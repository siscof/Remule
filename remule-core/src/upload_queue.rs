// SPDX-License-Identifier: GPL-2.0-or-later
//! The upload queue (`CUploadQueue`, UploadQueue.cpp, and the score of
//! `CUpDownClient::CalculateScoreInternal`), without IO.
//!
//! Peers that ask for a file wait in the queue; each gets a score: the
//! seconds it has waited, times its credit ratio, times a factor for the
//! file's upload priority. Whenever a slot is free (at most one new slot a
//! second) the best peer that can be reached gets it. With every slot
//! taken, a slot is given back after an hour or 10 MB, so others get their
//! turn, but only when someone is waiting.
//!
//! Peers are named by user hash, which outlives connections: a peer keeps
//! its place across reconnects. The application tells the queue who is
//! connected and turns its [`QueueAction`]s into packets
//! ([`UploadSession::accept`](ed2k_peer::upload::UploadSession::accept),
//! [`UploadSession::end_slot`](ed2k_peer::upload::UploadSession::end_slot)).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ed2k_formats::known_met::priority;
use ed2k_types::ed2k::{MAX_PURGEQUEUETIME, MAX_UP_CLIENTS_ALLOWED, MIN_UP_CLIENTS_ALLOWED};
use ed2k_types::Md4Hash;

/// Settings (`amule.conf`).
#[derive(Debug, Clone)]
pub struct UploadConfig {
    /// `MaxUpload`, KiB/s; 0 for no limit.
    pub max_upload_kbps: u32,
    /// `SlotAllocation`: KiB/s each slot should get.
    pub slot_allocation_kbps: u32,
    /// `QueueSizePref` × 100: peers kept waiting.
    pub queue_size: usize,
    /// A slot is given back after this long...
    pub slot_time: Duration,
    /// ...or this much data, when others wait.
    pub slot_bytes: u64,
    /// A waiting peer that has not asked again for this long is dropped.
    pub purge_after: Duration,
}

impl Default for UploadConfig {
    fn default() -> Self {
        UploadConfig {
            max_upload_kbps: 0,
            slot_allocation_kbps: 10,
            queue_size: 5000,
            slot_time: Duration::from_secs(3600),
            slot_bytes: 10 * 1024 * 1024,
            purge_after: MAX_PURGEQUEUETIME,
        }
    }
}

/// A peer asking for an upload.
#[derive(Debug, Clone, PartialEq)]
pub struct Asker {
    pub user_hash: Md4Hash,
    pub ip: IpAddr,
    /// It cannot be called back (`HasLowID`).
    pub low_id: bool,
    /// Its credit ratio, 1 to 10 (`GetScoreRatio`).
    pub score_ratio: f32,
    /// An eMule of version 0.19 or older (`m_byEmuleVersion <= 0x19`):
    /// half the score.
    pub old_emule: bool,
}

/// The answer to an upload request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Give it a slot now (`OP_ACCEPTUPLOADREQ`).
    Slot,
    /// It waits at this place (`OP_QUEUERANKING`).
    Queued(u16),
    /// Not taken: the queue is full, or its address has enough waiting.
    Refused,
}

/// Something for the application to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueAction {
    /// The peer is connected and has a slot: send the accept.
    GiveSlot(Md4Hash),
    /// The peer has a slot but is not connected: connect to it, then accept.
    CallBack(Md4Hash),
    /// Its slot is over (`SendOutOfPartReqsAndAddToWaitingQueue`): send
    /// `OP_OUTOFPARTREQS`; it waits again.
    TakeSlot(Md4Hash),
}

#[derive(Debug, Clone)]
struct Waiting {
    asker: Asker,
    file: Md4Hash,
    priority: u32,
    auto_priority: bool,
    wait_start: Instant,
    last_request: Instant,
    connected: bool,
    /// A LowID at the top: it gets a slot when it next connects
    /// (`m_bAddNextConnect`).
    add_next_connect: bool,
}

#[derive(Debug, Clone)]
struct Slot {
    asker: Asker,
    file: Md4Hash,
    priority: u32,
    started: Instant,
    sent: u64,
}

/// At most this many from one address wait at once (`IsWithinUploadScopeLimit`).
const MAX_WAITING_PER_ADDRESS: usize = 3;
/// Slots one address takes while others can use them (`MaxUploadSlotsPerScope`).
const MAX_SLOTS_PER_ADDRESS: usize = 2;
/// One new slot a second at most.
const START_INTERVAL: Duration = Duration::from_secs(1);

/// The queue.
#[derive(Debug, Default)]
pub struct UploadQueue {
    config: UploadConfig,
    waiting: Vec<Waiting>,
    slots: Vec<Slot>,
    last_start: Option<Instant>,
    /// All slots are taken and someone waits (`m_allowKicking`).
    allow_kicking: bool,
    /// Who is connected now.
    connected: HashMap<Md4Hash, bool>,
}

/// The file priority factor of the score.
fn priority_factor(p: u32) -> f32 {
    match p {
        priority::POWERSHARE => 250.0,
        priority::VERY_HIGH => 1.8,
        priority::HIGH => 0.9,
        priority::LOW => 0.6,
        priority::VERY_LOW => 0.2,
        _ => 0.7,
    }
}

impl UploadQueue {
    pub fn new(config: UploadConfig) -> Self {
        UploadQueue {
            config,
            ..Default::default()
        }
    }

    pub fn config(&self) -> &UploadConfig {
        &self.config
    }

    /// `GetMaxSlots`. `rate` is the upload rate now, in bytes/s. Without a
    /// limit: one slot per `SlotAllocation` of the rate, plus two, at least
    /// 20; with one: the limit over `SlotAllocation`, at least 2. At most 250.
    pub fn max_slots(&self, rate: u64) -> usize {
        let alloc = self.config.slot_allocation_kbps.max(1) as f32;
        let n = if self.config.max_upload_kbps == 0 {
            let by_speed = (rate as f32 / 1024.0 / alloc) as u32 + 2;
            by_speed.max(20)
        } else if self.config.max_upload_kbps >= 10 {
            ((self.config.max_upload_kbps as f32 / alloc + 0.5).floor() as u32)
                .max(MIN_UP_CLIENTS_ALLOWED)
        } else {
            MIN_UP_CLIENTS_ALLOWED
        };
        n.min(MAX_UP_CLIENTS_ALLOWED) as usize
    }

    /// `CalculateScoreInternal` for a waiting peer.
    fn score(w: &Waiting, now: Instant) -> u32 {
        let mut s = now.saturating_duration_since(w.wait_start).as_secs_f32();
        s *= w.asker.score_ratio;
        s *= priority_factor(if w.auto_priority {
            priority::HIGH
        } else {
            w.priority
        });
        if w.asker.old_emule {
            s *= 0.5;
        }
        s as u32
    }

    /// The waiting peers, best first.
    fn sort(&mut self, now: Instant) {
        // Stable: equal scores keep their order of arrival.
        self.waiting
            .sort_by_key(|w| std::cmp::Reverse(Self::score(w, now)));
    }

    fn rank_of(&self, hash: &Md4Hash) -> Option<u16> {
        self.waiting
            .iter()
            .position(|w| &w.asker.user_hash == hash)
            .map(|i| (i + 1).min(u16::MAX as usize) as u16)
    }

    /// Its place in the queue, 1 first.
    pub fn rank(&mut self, hash: &Md4Hash, now: Instant) -> Option<u16> {
        self.sort(now);
        self.rank_of(hash)
    }

    pub fn waiting_count(&self) -> usize {
        self.waiting.len()
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn has_slot(&self, hash: &Md4Hash) -> bool {
        self.slots.iter().any(|s| &s.asker.user_hash == hash)
    }

    /// The file a peer with a slot is downloading.
    pub fn slot_file(&self, hash: &Md4Hash) -> Option<Md4Hash> {
        self.slots
            .iter()
            .find(|s| &s.asker.user_hash == hash)
            .map(|s| s.file)
    }

    fn slots_at(&self, ip: &IpAddr) -> usize {
        self.slots.iter().filter(|s| &s.asker.ip == ip).count()
    }

    fn take_slot(&mut self, i: usize, now: Instant) -> Md4Hash {
        let w = self.waiting.remove(i);
        let hash = w.asker.user_hash;
        self.slots.push(Slot {
            asker: w.asker,
            file: w.file,
            priority: w.priority,
            started: now,
            sent: 0,
        });
        self.last_start = Some(now);
        hash
    }

    /// `AddClientToQueue`: a peer asked for `file` (`OP_STARTUPLOADREQ`).
    /// `priority` is the file's upload priority (`known_met::priority`), or
    /// `auto` for an automatic one. `rate` is the upload rate now.
    pub fn request(
        &mut self,
        asker: Asker,
        file: Md4Hash,
        file_priority: u32,
        auto: bool,
        rate: u64,
        now: Instant,
    ) -> Answer {
        let hash = asker.user_hash;
        self.connected.insert(hash, true);
        // Already uploading: it probably wants another file.
        if let Some(s) = self.slots.iter_mut().find(|s| s.asker.user_hash == hash) {
            s.file = file;
            return Answer::Slot;
        }
        let max = self.max_slots(rate);
        if let Some(i) = self.waiting.iter().position(|w| w.asker.user_hash == hash) {
            let w = &mut self.waiting[i];
            w.last_request = now;
            w.connected = true;
            w.file = file;
            w.priority = file_priority;
            w.auto_priority = auto;
            w.asker = asker;
            // A LowID whose turn came while it was away: the extra slot
            // (`TryTakeLowIdAlternationSlot`).
            if w.add_next_connect && self.slots.len() <= max {
                self.take_slot(i, now);
                return Answer::Slot;
            }
            self.sort(now);
            return Answer::Queued(self.rank_of(&hash).unwrap_or(1));
        }
        let same_address = self
            .waiting
            .iter()
            .filter(|w| w.asker.ip == asker.ip)
            .count();
        if same_address >= MAX_WAITING_PER_ADDRESS || self.waiting.len() >= self.config.queue_size {
            return Answer::Refused;
        }
        let ip = asker.ip;
        self.waiting.push(Waiting {
            asker,
            file,
            priority: file_priority,
            auto_priority: auto,
            wait_start: now,
            last_request: now,
            connected: true,
            add_next_connect: false,
        });
        // Nobody else waits and a slot is free: straight in.
        let started_recently = self
            .last_start
            .is_some_and(|t| now.saturating_duration_since(t) < START_INTERVAL);
        if self.waiting.len() == 1
            && !started_recently
            && self.slots.len() < max
            && self.slots_at(&ip) < 10
        {
            self.take_slot(0, now);
            return Answer::Slot;
        }
        self.sort(now);
        Answer::Queued(self.rank_of(&hash).unwrap_or(1))
    }

    /// `CUploadQueue::Process` / `SortGetBestClient`: drop peers that
    /// stopped asking, and fill a free slot with the best peer that can
    /// take it. `rate` is the upload rate now.
    pub fn process(&mut self, rate: u64, now: Instant) -> Vec<QueueAction> {
        let purge = self.config.purge_after;
        self.waiting
            .retain(|w| now.saturating_duration_since(w.last_request) <= purge);
        let mut out = Vec::new();
        let started_recently = self
            .last_start
            .is_some_and(|t| now.saturating_duration_since(t) < START_INTERVAL);
        if self.waiting.is_empty() || started_recently {
            self.allow_kicking = false;
            return out;
        }
        if self.slots.len() >= self.max_slots(rate) {
            self.allow_kicking = true;
            return out;
        }
        self.allow_kicking = false;
        self.sort(now);
        let mut pick = None;
        for i in 0..self.waiting.len() {
            let w = &self.waiting[i];
            if self.slots_at(&w.asker.ip) >= MAX_SLOTS_PER_ADDRESS {
                continue;
            }
            if w.asker.low_id && !w.connected {
                // Its turn: it gets the slot when it next connects.
                self.waiting[i].add_next_connect = true;
                continue;
            }
            pick = Some(i);
            break;
        }
        if let Some(i) = pick {
            let connected = self.waiting[i].connected;
            let hash = self.take_slot(i, now);
            out.push(if connected {
                QueueAction::GiveSlot(hash)
            } else {
                QueueAction::CallBack(hash)
            });
        }
        out
    }

    /// `CheckForTimeOver` after sending `bytes` to a peer with a slot: when
    /// others wait and the slot has had an hour or 10 MB, it goes back to
    /// waiting (one per round).
    pub fn sent(&mut self, hash: &Md4Hash, bytes: u64, now: Instant) -> Option<QueueAction> {
        let i = self.slots.iter().position(|s| &s.asker.user_hash == hash)?;
        let s = &mut self.slots[i];
        s.sent += bytes;
        if !self.allow_kicking || s.priority == priority::POWERSHARE {
            return None;
        }
        let over = now.saturating_duration_since(s.started) > self.config.slot_time
            || s.sent > self.config.slot_bytes;
        if !over {
            return None;
        }
        self.allow_kicking = false;
        let s = self.slots.remove(i);
        let connected = self.connected.get(hash).copied().unwrap_or(false);
        self.waiting.push(Waiting {
            asker: s.asker,
            file: s.file,
            priority: s.priority,
            auto_priority: false,
            wait_start: now,
            last_request: now,
            connected,
            add_next_connect: false,
        });
        Some(QueueAction::TakeSlot(*hash))
    }

    /// The slot ended (`RemoveFromUploadQueue`): the peer cancelled or
    /// finished, or its connection went. It is not put back in the queue.
    pub fn ended(&mut self, hash: &Md4Hash) -> bool {
        let before = self.slots.len();
        self.slots.retain(|s| &s.asker.user_hash != hash);
        self.slots.len() != before
    }

    /// Whether the peer is connected now. A waiting peer keeps its place
    /// either way; a slot ends with its connection.
    pub fn set_connected(&mut self, hash: &Md4Hash, connected: bool) {
        self.connected.insert(*hash, connected);
        for w in self
            .waiting
            .iter_mut()
            .filter(|w| &w.asker.user_hash == hash)
        {
            w.connected = connected;
        }
        if !connected {
            self.ended(hash);
        }
    }

    /// Leave the queue entirely (banned, or the file is no longer shared).
    pub fn remove(&mut self, hash: &Md4Hash) {
        self.ended(hash);
        self.waiting.retain(|w| &w.asker.user_hash != hash);
    }
}
