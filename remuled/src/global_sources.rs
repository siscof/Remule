// SPDX-License-Identifier: GPL-2.0-or-later
//! Asking the servers we are not logged into for sources over UDP
//! (`CDownloadQueue::SendGlobalSources`, `CGlobalSourceQueue`), without IO.
//!
//! Each server keeps its own queue of downloads to ask about. Lugdunum
//! 17.15 stops answering an IP for an hour or more once its requests cost
//! too much, so each server gets at most 35 hashes per
//! `UDPSERVERREASKTIME` (21 min 40 s) and, in the long run, one request a
//! minute (five at most in a burst). Downloads just added or resumed go
//! first, newest first, 15 s after the last request; the others are asked
//! in turn, in hash order from where the last request stopped, a minute
//! apart, none twice within `UDPSERVERREASKTIME`. Some of the budget is
//! kept for new downloads.
//!
//! Once a second, while logged into a server, the next server in the list
//! (not the one we are logged into) that has something to ask sends one
//! request: up to 31 files to a server with `SRV_UDPFLG_EXT_GETSOURCES`,
//! one to another; `OP_GLOBGETSOURCES2` with the sizes where the server
//! takes them; a large file only to a server that takes large files over
//! UDP. A download is asked about while it is ready or empty, not paused
//! or stopped, and has fewer sources than `GetMaxSourcePerFileUDP`.

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_formats::server_met::ServerInfo;
use ed2k_server::udp::{global_get_sources, MAX_FILES_PER_UDP_PACKET};
use ed2k_types::ed2k::server_udp::flags;
use ed2k_types::ed2k::OLD_MAX_FILE_SIZE;
use ed2k_types::Md4Hash;
use tracing::debug;

/// `UDPSERVERREASKTIME`.
pub const REASK: Duration = Duration::from_millis(1_300_000);
/// The hashes a server may be asked about per [`REASK`].
pub const HASHES: u32 = 35;
/// Requests in a burst, one more each minute.
pub const PACKETS: u32 = 5;
pub const PER_PACKET: Duration = Duration::from_secs(60);
/// Kept for downloads just added or resumed.
pub const RESERVE: u32 = 4;
pub const PACKET_RESERVE: u32 = 1;
/// Lugdunum drops a request sent a few seconds after another; a new
/// download may go sooner than the others.
pub const GAP: Duration = Duration::from_secs(60);
pub const NEW_GAP: Duration = Duration::from_secs(15);
pub const MAX_NEW: usize = 1000;

/// `GetMaxSourcePerFileUDP` for a `MaxSourcesPerFile`: three quarters, at
/// most 100.
pub fn max_sources_udp(max_sources_per_file: u32) -> u32 {
    ((max_sources_per_file as f64 * 0.75) as u32).min(100)
}

/// `CRefill`: a budget that refills one unit every `per`, up to `capacity`.
#[derive(Debug, Clone)]
struct Refill {
    capacity: u32,
    per: Duration,
    /// When it is back to capacity.
    full_at: Option<Instant>,
}

impl Refill {
    fn new(capacity: u32, per: Duration) -> Self {
        Refill {
            capacity,
            per,
            full_at: None,
        }
    }

    fn available(&self, now: Instant) -> u32 {
        let Some(full) = self.full_at.filter(|&f| f > now) else {
            return self.capacity;
        };
        let per = self.per.as_millis().max(1);
        let owed = (full - now).as_millis().div_ceil(per);
        if owed >= u128::from(self.capacity) {
            0
        } else {
            self.capacity - owed as u32
        }
    }

    fn spend(&mut self, now: Instant, units: u32) {
        let from = self.full_at.map_or(now, |f| f.max(now));
        self.full_at = Some(from + self.per * units);
    }
}

/// One server's queue (`CGlobalSourceQueue`).
#[derive(Debug, Clone)]
pub struct SourceQueue {
    new: VecDeque<Md4Hash>,
    /// Asked within [`REASK`], and when.
    recent: HashMap<Md4Hash, Instant>,
    /// The last download asked about in turn.
    cursor: Md4Hash,
    hashes: Refill,
    packets: Refill,
    last_request: Option<Instant>,
}

impl SourceQueue {
    pub fn new(start: Md4Hash) -> Self {
        SourceQueue {
            new: VecDeque::new(),
            recent: HashMap::new(),
            cursor: start,
            hashes: Refill::new(HASHES, REASK / HASHES),
            packets: Refill::new(PACKETS, PER_PACKET),
            last_request: None,
        }
    }

    /// A download was added or resumed.
    pub fn add(&mut self, hash: Md4Hash) {
        self.new.retain(|h| *h != hash);
        if self.new.len() >= MAX_NEW {
            self.new.pop_front();
        }
        self.new.push_back(hash);
    }

    /// The downloads to ask about now, at most `per_packet`; empty if none
    /// may be asked yet. Takes them out of the queue and spends the budget.
    /// `downloads` sorted; `wanted` says whether one may be asked about.
    pub fn next(
        &mut self,
        now: Instant,
        downloads: &[Md4Hash],
        wanted: &dyn Fn(&Md4Hash) -> bool,
        per_packet: usize,
    ) -> Vec<Md4Hash> {
        let mut asked: Vec<Md4Hash> = Vec::new();
        let budget = self.hashes.available(now) as usize;
        let packets = self.packets.available(now);
        let room = budget.min(per_packet);
        let since_last = self
            .last_request
            .map_or(Duration::MAX, |t| now.saturating_duration_since(t));

        if since_last >= NEW_GAP && packets > 0 {
            while asked.len() < room {
                let Some(hash) = self.new.pop_back() else {
                    break;
                };
                if wanted(&hash) {
                    asked.push(hash);
                }
            }
        }

        if (since_last >= GAP && packets > PACKET_RESERVE) || !asked.is_empty() {
            self.recent
                .retain(|_, t| now.saturating_duration_since(*t) < REASK);
            let reserve = RESERVE as usize;
            let unreserved = if budget > asked.len() + reserve {
                budget - asked.len() - reserve
            } else {
                0
            };
            let limit = room.min(asked.len() + unreserved);
            let after = downloads.partition_point(|h| h.0 <= self.cursor.0);
            for i in 0..downloads.len() {
                if asked.len() >= limit {
                    break;
                }
                let hash = downloads[(after + i) % downloads.len()];
                if !self.recent.contains_key(&hash) && !asked.contains(&hash) && wanted(&hash) {
                    asked.push(hash);
                    self.cursor = hash;
                }
            }
        }

        if !asked.is_empty() {
            self.last_request = Some(now);
            self.hashes.spend(now, asked.len() as u32);
            self.packets.spend(now, 1);
            for h in &asked {
                self.recent.insert(*h, now);
            }
        }
        asked
    }
}

/// A download that may be asked about: its hash and size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wanted {
    pub hash: Md4Hash,
    pub size: u64,
}

/// One request to send.
#[derive(Debug, Clone)]
pub struct Ask {
    pub server: ServerInfo,
    pub packet: Packet,
    pub files: Vec<Md4Hash>,
}

fn addr_of(s: &ServerInfo) -> Option<SocketAddrV4> {
    s.ip.map(|ip| SocketAddrV4::new(ip, s.port))
}

/// Every server's queue, and whose turn it is.
#[derive(Debug, Default)]
pub struct GlobalSources {
    queues: HashMap<SocketAddrV4, SourceQueue>,
    next_server: usize,
}

impl GlobalSources {
    /// `GlobalSources(server)`: each server starts its turn elsewhere, so
    /// the servers are asked about different downloads first.
    fn queue(&mut self, addr: SocketAddrV4) -> &mut SourceQueue {
        self.queues.entry(addr).or_insert_with(|| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            addr.hash(&mut h);
            let seed = h.finish().to_le_bytes();
            let mut start = [0u8; 16];
            for (i, b) in start.iter_mut().enumerate() {
                *b = seed[i % seed.len()];
            }
            SourceQueue::new(Md4Hash(start))
        })
    }

    /// `RequestGlobalSources`: a download was added or resumed; every
    /// listed server but the connected one asks about it first.
    pub fn request(
        &mut self,
        hash: Md4Hash,
        servers: &[ServerInfo],
        connected: Option<SocketAddrV4>,
    ) {
        for a in servers.iter().filter_map(addr_of) {
            if Some(a) != connected {
                self.queue(a).add(hash);
            }
        }
    }

    /// `StopUDPRequests`.
    pub fn stop(&mut self) {
        self.queues.clear();
    }

    /// `SendGlobalSources`: at most one request, to the next server in turn
    /// that has something to ask about. `downloads` are those that want
    /// sources (`WantsGlobalSources`).
    pub fn send(
        &mut self,
        now: Instant,
        downloads: &[Wanted],
        servers: &[ServerInfo],
        connected: Option<SocketAddrV4>,
    ) -> Option<Ask> {
        // Servers no longer listed are forgotten.
        self.queues
            .retain(|a, _| servers.iter().any(|s| addr_of(s) == Some(*a)));
        if downloads.is_empty() || servers.is_empty() {
            return None;
        }
        let mut sorted: Vec<Wanted> = downloads.to_vec();
        sorted.sort_by_key(|w| w.hash.0);
        let hashes: Vec<Md4Hash> = sorted.iter().map(|w| w.hash).collect();
        let find = |h: &Md4Hash| {
            sorted
                .binary_search_by(|w| w.hash.0.cmp(&h.0))
                .ok()
                .map(|i| sorted[i])
        };
        for i in 0..servers.len() {
            let idx = (self.next_server + i) % servers.len();
            let server = &servers[idx];
            let Some(addr) = addr_of(server) else {
                continue;
            };
            if Some(addr) == connected {
                continue;
            }
            let per_packet = if server.udp_flags & flags::EXT_GETSOURCES != 0 {
                MAX_FILES_PER_UDP_PACKET
            } else {
                1
            };
            let large_ok = server.udp_flags & flags::LARGEFILES != 0;
            let wanted = |h: &Md4Hash| {
                find(h).is_some_and(|w| {
                    let ok = w.size <= OLD_MAX_FILE_SIZE || large_ok;
                    if !ok {
                        debug!("UDP Request for sources on a large file ignored: server doesn't support it");
                    }
                    ok
                })
            };
            let asked = self.queue(addr).next(now, &hashes, &wanted, per_packet);
            if asked.is_empty() {
                continue;
            }
            let files: Vec<(Md4Hash, u64)> = asked
                .iter()
                .filter_map(|h| find(h).map(|w| (w.hash, w.size)))
                .collect();
            self.next_server = idx + 1;
            debug!("Asked {addr} for sources of {} downloads", asked.len());
            return Some(Ask {
                server: server.clone(),
                packet: global_get_sources(&files, server.udp_flags),
                files: asked,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn h(b: u8) -> Md4Hash {
        Md4Hash([b; 16])
    }

    fn server(last: u8, udp_flags: u32) -> ServerInfo {
        ServerInfo {
            ip: Some(Ipv4Addr::new(198, 51, 100, last)),
            port: 4661,
            udp_flags,
            ..Default::default()
        }
    }

    #[test]
    fn refill_spends_and_refills() {
        let t0 = Instant::now();
        let mut r = Refill::new(5, Duration::from_secs(60));
        assert_eq!(r.available(t0), 5);
        r.spend(t0, 2);
        assert_eq!(r.available(t0), 3);
        assert_eq!(r.available(t0 + Duration::from_secs(59)), 3);
        assert_eq!(r.available(t0 + Duration::from_secs(60)), 4);
        assert_eq!(r.available(t0 + Duration::from_secs(120)), 5);
        r.spend(t0, 10);
        assert_eq!(r.available(t0), 0);
    }

    /// A new download goes first, then the others in hash order after the
    /// cursor, a minute apart, none twice within `UDPSERVERREASKTIME`.
    #[test]
    fn a_queue_asks_new_downloads_first_then_the_others_in_turn() {
        let t0 = Instant::now();
        let mut q = SourceQueue::new(h(0));
        let downloads = [h(1), h(2), h(3)];
        let all = |_: &Md4Hash| true;
        q.add(h(3));
        // One per packet (a server without EXT_GETSOURCES).
        assert_eq!(q.next(t0, &downloads, &all, 1), vec![h(3)]);
        // Nothing within 15 s, or a minute for the others.
        assert!(q
            .next(t0 + Duration::from_secs(30), &downloads, &all, 1)
            .is_empty());
        let t = t0 + GAP;
        assert_eq!(q.next(t, &downloads, &all, 1), vec![h(1)]);
        let t = t + GAP;
        assert_eq!(q.next(t, &downloads, &all, 1), vec![h(2)]);
        // h(3) was asked at t0, h(1) a minute later: neither again yet.
        let t = t + GAP;
        assert!(q.next(t, &downloads, &all, 1).is_empty());
        // After UDPSERVERREASKTIME they come round again.
        let t = t0 + REASK + GAP;
        assert_eq!(q.next(t, &downloads, &all, 1), vec![h(3)]);
        // A new one goes 15 s after the last request.
        q.add(h(2));
        assert!(q
            .next(t + Duration::from_secs(5), &downloads, &all, 1)
            .is_empty());
        assert_eq!(q.next(t + NEW_GAP, &downloads, &all, 1), vec![h(2)]);
    }

    /// Many files in one request (EXT_GETSOURCES), with four hashes of
    /// the 35 kept for new downloads; the budget then lasts.
    #[test]
    fn a_queue_keeps_to_its_hash_budget() {
        let t0 = Instant::now();
        let mut q = SourceQueue::new(h(0));
        let downloads: Vec<Md4Hash> = (1..=60).map(h).collect();
        let all = |_: &Md4Hash| true;
        let first = q.next(t0, &downloads, &all, MAX_FILES_PER_UDP_PACKET);
        assert_eq!(first.len(), (HASHES - RESERVE) as usize);
        assert_eq!(first[0], h(1));
        // The budget is spent: a minute later, only what refilled beyond
        // the reserve (one hash), while a new download may use the reserve.
        let t = t0 + GAP;
        assert_eq!(
            q.next(t, &downloads, &all, MAX_FILES_PER_UDP_PACKET),
            vec![h(32)]
        );
        q.add(h(60));
        let t = t + NEW_GAP;
        assert_eq!(
            q.next(t, &downloads, &all, MAX_FILES_PER_UDP_PACKET),
            vec![h(60)]
        );
        // Downloads not wanted are passed over.
        let mut q = SourceQueue::new(h(0));
        let odd = |x: &Md4Hash| x.0[0] % 2 == 1;
        let got = q.next(t0, &downloads[..6], &odd, MAX_FILES_PER_UDP_PACKET);
        assert_eq!(got, vec![h(1), h(3), h(5)]);
    }

    /// Servers take turns, the connected one never asked; the request is
    /// the one each server takes; a large file only to a server that takes
    /// large files over UDP.
    #[test]
    fn servers_take_turns_with_the_request_they_read() {
        let t0 = Instant::now();
        let connected = server(1, 0);
        let plain = server(2, 0);
        let ext = server(
            3,
            flags::EXT_GETSOURCES | flags::EXT_GETSOURCES2 | flags::LARGEFILES,
        );
        let servers = [connected.clone(), plain.clone(), ext.clone()];
        let here = addr_of(&connected);
        let downloads = [
            Wanted {
                hash: h(1),
                size: 1000,
            },
            Wanted {
                hash: h(2),
                size: 5_000_000_000,
            },
        ];
        let mut g = GlobalSources::default();
        g.request(h(2), &servers, here);
        assert!(!g.queues.contains_key(&here.unwrap()));
        // The plain server: the large file is not for it; one file, hashes only.
        let a = g.send(t0, &downloads, &servers, here).unwrap();
        assert_eq!(a.server.ip, plain.ip);
        assert_eq!(a.packet.opcode, 0x9A);
        assert_eq!(a.files, vec![h(1)]);
        assert_eq!(a.packet.payload, vec![1u8; 16]);
        // Then the other: both files, with their sizes.
        let a = g.send(t0, &downloads, &servers, here).unwrap();
        assert_eq!(a.server.ip, ext.ip);
        assert_eq!(a.packet.opcode, 0x94);
        assert_eq!(a.files.len(), 2);
        assert_eq!(a.files[0], h(2), "the new one first");
        // Nothing more for a while.
        assert!(g
            .send(t0 + Duration::from_secs(1), &downloads, &servers, here)
            .is_none());
        // Nothing to ask about: nothing sent.
        assert!(g.send(t0 + GAP * 30, &[], &servers, here).is_none());
        // A server that leaves the list is forgotten.
        g.send(t0, &downloads, &servers[..2], here);
        assert!(!g.queues.contains_key(&addr_of(&ext).unwrap()));
        assert_eq!(max_sources_udp(300), 100);
        assert_eq!(max_sources_udp(40), 30);
    }
}
