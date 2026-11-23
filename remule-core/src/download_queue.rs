// SPDX-License-Identifier: GPL-2.0-or-later
//! The download queue (`CDownloadQueue`, the source half of `CPartFile`,
//! and `CUpDownClient`'s reask logic), without IO.
//!
//! It holds the part files and their sources, decides which sources to
//! connect to and when to ask again, runs one [`Session`] per connection,
//! and acts on what the sessions report: sources from source exchange,
//! AICH roots and recovery data, finished files. Everything that needs
//! the network comes out as an [`Action`]; what the network does comes
//! back in through [`DownloadQueue::connected`], [`DownloadQueue::packet`]
//! and [`DownloadQueue::closed`]. The [`downloader`](crate::downloader)
//! runs it on tokio.
//!
//! Sources come from servers, Kad and source exchange, all through
//! [`DownloadQueue::add_source`]. Only sources that can be connected to
//! directly are used: callbacks through a server or a Kad buddy are not
//! ported yet. A source whose queue we wait in is asked again over UDP
//! first ([`Action::SendUdp`], [`DownloadQueue::udp_packet`]).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_hash::aich::signing_key_v4;
use ed2k_peer::download::{CloseReason, Event, Output, Session, State};
use ed2k_peer::secident::{IdentConfig, IdentResult, Identity};
use ed2k_peer::sources::{source_request_allowed, ExchangedSource, SourceRequestInput};
use ed2k_peer::udp::UdpPacket;
use ed2k_peer::{Hello, PartStatus, PeerPacket};
use ed2k_types::ed2k::MAX_SOURCES_FILE_SOFT;
use ed2k_types::{AichHash, Md4Hash};

use crate::ip_filter::AddressFilter;
use crate::part_file::{Completion, FileEvent, PartFile, SourceView};

/// A connection, as the queue and the network layer name it.
pub type ConnId = u64;

/// Where a source came from (`ESourceFrom`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    Server,
    Kad,
    SourceExchange,
    /// Given by the user or a link.
    Manual,
}

/// Obfuscation flags as servers, Kad and source exchange give them
/// (`SetConnectOptions`): bit 0 supported, 1 requested, 2 required.
pub mod crypt {
    pub const SUPPORTED: u8 = 1;
    pub const REQUESTED: u8 = 2;
    pub const REQUIRED: u8 = 4;
}

/// How to reach a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: SocketAddrV4,
    /// Needed to connect obfuscated.
    pub user_hash: Option<Md4Hash>,
    /// [`crypt`] flags.
    pub crypt: u8,
    /// A firewalled Kad source: it is not connected to, its buddy is asked
    /// to have it connect to us.
    pub buddy: Option<BuddyRoute>,
    /// A Kad source that takes UDP but not TCP (type 6): asked over UDP,
    /// at this port, to connect to us (`OP_DIRECTCALLBACKREQ`).
    pub direct_udp: Option<u16>,
}

/// A firewalled source's Kad buddy (source types 3 and 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuddyRoute {
    /// Its IP and Kad port.
    pub kad: SocketAddrV4,
    /// The ID callbacks for the source go by (aMule's layout).
    pub id: ed2k_types::UInt128,
}

impl Endpoint {
    pub fn new(addr: SocketAddrV4) -> Self {
        Endpoint {
            addr,
            user_hash: None,
            crypt: 0,
            buddy: None,
            direct_udp: None,
        }
    }

    /// A source a server sent (`OP_FOUNDSOURCES(_OBFU)`); `None` for a
    /// LowID, which needs a callback through the server.
    pub fn from_server(s: &ed2k_server::packets::Source) -> Option<Endpoint> {
        if s.id < 0x0100_0000 {
            return None;
        }
        Some(Endpoint {
            addr: SocketAddrV4::new(ed2k_server::packets::id_to_ip(s.id), s.port),
            user_hash: s.user_hash,
            crypt: s.crypt_options.unwrap_or(0) & 0x07,
            buddy: None,
            direct_udp: None,
        })
    }

    /// A source a Kad search found; `None` unless it can be reached
    /// directly (types 1 and 4, with a TCP port).
    pub fn from_kad(s: &ed2k_kad::search::SourceResult) -> Option<Endpoint> {
        if s.tcp_port == 0 {
            return None;
        }
        let mut direct_udp = None;
        let buddy = match s.source_type {
            1 | 4 => None,
            // Direct callback: only with its flag set (0x08) and a UDP port.
            6 if s.crypt_options & 0x08 != 0 && s.udp_port != 0 => {
                direct_udp = Some(s.udp_port);
                None
            }
            // `KademliaSearchFile` for types 3 and 5: reached through its
            // buddy. Its IP only matches it when it calls.
            3 | 5 => match s.buddy_id {
                Some(id) if !s.buddy_ip.is_unspecified() && s.buddy_port != 0 => Some(BuddyRoute {
                    kad: SocketAddrV4::new(s.buddy_ip, s.buddy_port),
                    id,
                }),
                _ => return None,
            },
            _ => return None,
        };
        Some(Endpoint {
            addr: SocketAddrV4::new(s.ip, s.tcp_port),
            user_hash: Some(s.user_hash),
            crypt: s.crypt_options & 0x07,
            buddy,
            direct_udp,
        })
    }

    /// A source from source exchange; `None` for a LowID.
    pub fn from_exchange(s: &ExchangedSource) -> Option<Endpoint> {
        Some(Endpoint {
            addr: SocketAddrV4::new(s.ip()?, s.port),
            user_hash: s.user_hash,
            crypt: s.crypt_options.unwrap_or(0) & 0x07,
            buddy: None,
            direct_udp: None,
        })
    }
}

/// Settings.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Our hello: user hash, ID, port, name and capabilities.
    pub ours: Hello,
    /// Where finished files go.
    pub incoming: PathBuf,
    /// Connections at once.
    pub max_connections: usize,
    /// New connections per tick (aMule: `MAXCONPER5SEC` in five seconds).
    pub max_new_per_tick: usize,
    /// Sources kept per file (`GetMaxSourcePerFile`).
    pub max_sources_per_file: usize,
    /// Before asking a source again (`GetSourceReaskTime`, 15 minutes);
    /// twice that for one with nothing we need.
    pub reask: Duration,
    /// How long a source that failed is not taken back (`DeadSourceDelay`).
    pub dead_delay: Duration,
    /// Write buffered data and check parts at least this often.
    pub flush_every: Duration,
    /// Connect obfuscated whenever a source supports it.
    pub request_obfuscation: bool,
    /// Drop LAN and loopback addresses (`FilterLanIPs`).
    pub filter_lan: bool,
    /// Sources and incoming peers the IP filter blocks are dropped.
    pub ip_filter: Option<Arc<AddressFilter>>,
    /// Our key, for secure identification.
    pub identity: Option<Arc<Identity>>,
    pub our_public_ip: Option<Ipv4Addr>,
    /// Others can connect to us (`!IsFirewalled`): firewalled Kad sources
    /// can be asked, through their buddy, to connect.
    pub reachable: bool,
}

impl QueueConfig {
    pub fn new(ours: Hello, incoming: PathBuf) -> Self {
        QueueConfig {
            ours,
            incoming,
            max_connections: 50,
            max_new_per_tick: 10,
            max_sources_per_file: 300,
            reask: Duration::from_secs(15 * 60),
            dead_delay: Duration::from_secs(45 * 60),
            flush_every: Duration::from_secs(60),
            request_obfuscation: true,
            filter_lan: true,
            ip_filter: None,
            identity: None,
            our_public_ip: None,
            reachable: false,
        }
    }
}

/// Something for the network layer, or news for the application.
#[derive(Debug)]
pub enum Action {
    /// Open a TCP connection; obfuscated for this user hash if given.
    Connect {
        conn: ConnId,
        addr: SocketAddr,
        obfuscate_for: Option<Md4Hash>,
    },
    Send {
        conn: ConnId,
        packets: Vec<Packet>,
    },
    Close {
        conn: ConnId,
    },
    /// Send a datagram from our client UDP port.
    SendUdp(UdpOut),
    Report(Report),
}

/// A client UDP datagram to send ([`ed2k_peer::udp`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpOut {
    pub to: SocketAddrV4,
    /// The plain datagram, protocol byte first.
    pub payload: Vec<u8>,
    /// Obfuscate it for this user hash (`ShouldReceiveCryptUDPPackets`).
    pub obfuscate_for: Option<Md4Hash>,
}

/// What happened, for the application to show or log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    SourceAdded {
        file: Md4Hash,
        addr: SocketAddrV4,
        origin: Origin,
    },
    /// A source dropped: the reason in words.
    SourceDropped {
        file: Md4Hash,
        addr: SocketAddrV4,
        why: String,
    },
    Queued {
        file: Md4Hash,
        addr: SocketAddrV4,
        rank: Option<u32>,
    },
    DownloadStarted {
        file: Md4Hash,
        addr: SocketAddrV4,
    },
    PartVerified {
        file: Md4Hash,
        part: u16,
    },
    PartCorrupt {
        file: Md4Hash,
        part: u16,
    },
    AichRecovered {
        file: Md4Hash,
        part: u16,
        bytes: u64,
    },
    Identified {
        addr: SocketAddrV4,
        passed: bool,
    },
    /// The file is complete and at this path.
    Completed {
        file: Md4Hash,
        path: PathBuf,
    },
    /// The file failed its final check; the named parts are missing again.
    CompletionFailed {
        file: Md4Hash,
        corrupt: Vec<u16>,
    },
    FileError {
        file: Md4Hash,
        error: String,
    },
    /// A peer got an upload slot for a file of ours.
    UploadStarted {
        user: Md4Hash,
        file: Md4Hash,
    },
    /// `OP_KAD_FWTCPCHECK_ACK` came from a peer at `ip`: for Kad's firewall
    /// check (`ed2k_kad::Kad::firewall_ack`). The downloader reports it.
    KadFirewallAck {
        ip: Ipv4Addr,
    },
    /// A Kad buddy link is up ([`crate::buddy`]): ours (we are firewalled),
    /// or one we serve.
    BuddyLinked {
        addr: SocketAddrV4,
        /// Our buddy's Kad port (0 for one we serve).
        kad_port: u16,
        serving: bool,
    },
    /// A Kad buddy link ended.
    BuddyLost {
        addr: SocketAddrV4,
        serving: bool,
        why: String,
    },
}

/// Where a source stands (`EDownloadState`, simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    /// Not asked yet, or due to be asked again.
    Idle,
    Connecting,
    /// Connected; the session says the rest.
    Connected,
    /// In the source's upload queue (`DS_ONQUEUE`).
    OnQueue,
    /// It has nothing we need (`DS_NONEEDEDPARTS`).
    NoNeededParts,
}

#[derive(Debug)]
struct Source {
    file: Md4Hash,
    endpoint: Endpoint,
    origin: Origin,
    state: SourceState,
    conn: Option<ConnId>,
    last_asked: Option<Instant>,
    /// `m_lastPartAsked`
    last_part: Option<u16>,
    /// The parts counted in the file's frequencies.
    parts: Option<PartStatus>,
    /// Kept after a disconnect, for a callback (`accepted` with `queued`).
    queued_parts: Option<PartStatus>,
    complete: bool,
    aich_root: Option<AichHash>,
    last_source_answer: Option<Instant>,
    /// Its client UDP port and UDP version, from its hello.
    udp: Option<(u16, u8)>,
    /// Obfuscate datagrams to it (`ShouldReceiveCryptUDPPackets`).
    crypt_udp: bool,
    /// A callback through its buddy went unasked-for (no connection came):
    /// the next goes with the buddy ID in the other layout
    /// (`NextBuddyIdUsesAmuleLayout`).
    callback_unanswered: bool,
    callback_other_layout: bool,
    /// A UDP reask went out unanswered (`m_bUDPPending`).
    udp_pending: bool,
    /// It said its queue is full (`IsRemoteQueueFull`).
    remote_queue_full: bool,
}

/// A queued source is reasked over UDP this long before its TCP reask is
/// due, giving UDP a chance to answer first (`CPartFile::Process`).
pub const UDP_REASK_EARLY: Duration = Duration::from_secs(20);

#[derive(Debug)]
struct Conn {
    /// `None` for an incoming connection not matched to a source yet.
    source: Option<u64>,
    session: Option<Session>,
}

#[derive(Debug)]
struct FileEntry {
    file: PartFile,
    /// Sources were last asked for (`SetLastAnsweredTimeTimeout`).
    last_sources_asked: Option<Instant>,
    done: bool,
    /// `m_stopped`: no sources are kept or taken. A file loaded paused is
    /// stopped, as aMule loads it.
    stopped: bool,
}

/// One file's progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProgress {
    pub hash: Md4Hash,
    pub name: String,
    pub size: u64,
    /// Bytes present.
    pub completed: u64,
    pub sources: usize,
    /// Sources whose upload queue we are in.
    pub queued: usize,
    /// Sources connected now, and those sending data.
    pub connected: usize,
    pub downloading: usize,
    pub done: bool,
    pub paused: bool,
    /// `IsStopped`.
    pub stopped: bool,
    pub status: crate::part_file::Status,
    /// Bytes received for it, counting those thrown away (`GetTransferred`).
    pub transferred: u64,
    /// The `.part.met` file name, without `.met` (`NNN.part`).
    pub part_met_name: String,
    /// `PR_*`, and whether it is chosen automatically.
    pub priority: u32,
    pub auto_priority: bool,
    /// The upload priority, as shared while downloading.
    pub up_priority: u32,
    pub auto_up_priority: bool,
    pub category: u32,
    /// Unix time a complete source was last seen.
    pub last_seen_complete: u32,
    pub lost_to_corruption: u64,
    /// The missing ranges, inclusive.
    pub gaps: Vec<(u64, u64)>,
    /// The blocks being downloaded, inclusive.
    pub requested: Vec<(u64, u64)>,
    /// How many sources have each part.
    pub part_frequency: Vec<u16>,
}

/// Download statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStats {
    pub received: u64,
    pub connections: usize,
    pub sources: usize,
}

/// The queue.
#[derive(Debug)]
pub struct DownloadQueue {
    config: QueueConfig,
    files: HashMap<Md4Hash, FileEntry>,
    sources: HashMap<u64, Source>,
    conns: HashMap<ConnId, Conn>,
    /// Endpoints that failed, per file, and until when they stay out.
    dead: HashMap<(Md4Hash, SocketAddrV4), Instant>,
    next_id: u64,
    last_flush: Option<Instant>,
    rng: u64,
    received: u64,
}

/// `IsGoodIP`: no zero, broadcast or multicast address; with `filter_lan`,
/// no private or loopback one either.
pub fn is_good_ip(ip: Ipv4Addr, filter_lan: bool) -> bool {
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.octets()[0] == 0 {
        return false;
    }
    !(filter_lan && (ip.is_private() || ip.is_loopback() || ip.is_link_local()))
}

impl DownloadQueue {
    pub fn new(config: QueueConfig) -> Self {
        let seed = u64::from_le_bytes(config.ours.user_hash.0[..8].try_into().unwrap()) | 1;
        DownloadQueue {
            config,
            files: HashMap::new(),
            sources: HashMap::new(),
            conns: HashMap::new(),
            dead: HashMap::new(),
            next_id: 1,
            last_flush: None,
            rng: seed,
            received: 0,
        }
    }

    /// Whether the IP filter blocks this peer (`IsFiltered(ip, false)`).
    pub fn blocks(&self, ip: Ipv4Addr) -> bool {
        self.config
            .ip_filter
            .as_ref()
            .is_some_and(|f| f.blocks_client(ip))
    }

    pub fn config(&self) -> &QueueConfig {
        &self.config
    }

    /// A server login (`CServerConnect::SetClientID`): our ID, which is our
    /// address for a HighID, and the public address the server saw, for the
    /// connections made from now on. 0 and `None` when logged out.
    /// Whether others can connect to us now.
    pub fn set_reachable(&mut self, reachable: bool) {
        self.config.reachable = reachable;
    }

    pub fn set_our_id(&mut self, id: u32, public_ip: Option<Ipv4Addr>) {
        self.config.ours.id = id;
        self.config.our_public_ip = public_ip;
    }

    /// A connection id for another part of the client (the uploader's
    /// callbacks), from the same sequence as ours.
    pub fn new_conn_id(&mut self) -> ConnId {
        self.id()
    }

    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn random(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        (x >> 32) as u32
    }

    /// Start downloading a part file. False if it is already here.
    pub fn add_file(&mut self, file: PartFile) -> bool {
        let hash = file.hash();
        if self.files.contains_key(&hash) {
            return false;
        }
        self.files.insert(
            hash,
            FileEntry {
                file,
                last_sources_asked: None,
                done: false,
                stopped: false,
            },
        );
        let e = self.files.get_mut(&hash).unwrap();
        e.stopped = e.file.is_paused();
        true
    }

    /// `PauseFile`: nothing more is asked for the file, its connections
    /// are closed, and it is saved paused. Its sources are kept. False if
    /// the file is not here; a completing or complete one is left alone.
    pub fn pause(&mut self, hash: &Md4Hash, now: Instant, out: &mut Vec<Action>) -> bool {
        let Some(e) = self.files.get_mut(hash) else {
            return false;
        };
        if e.done
            || matches!(
                e.file.status(),
                crate::part_file::Status::Completing | crate::part_file::Status::Complete
            )
        {
            return true;
        }
        e.file.set_paused(true);
        let _ = e.file.save();
        self.close_file_conns(*hash, now, out);
        true
    }

    /// `StopFile`: paused, and every source dropped.
    pub fn stop(&mut self, hash: &Md4Hash, now: Instant, out: &mut Vec<Action>) -> bool {
        if !self.pause(hash, now, out) {
            return false;
        }
        let e = self.files.get_mut(hash).unwrap();
        if !e.done {
            e.stopped = true;
            self.forget_sources(hash);
        }
        true
    }

    /// `ResumeFile`: asked for again, sources taken again, saved.
    /// A download's priority or category, saved at once. False if the
    /// file is not here.
    pub fn set_file(&mut self, hash: &Md4Hash, f: impl FnOnce(&mut PartFile)) -> bool {
        let Some(e) = self.files.get_mut(hash) else {
            return false;
        };
        f(&mut e.file);
        if !e.done {
            let _ = e.file.save();
        }
        true
    }

    /// `ResetCatParts` after a category is deleted (`RemoveCategory`): its
    /// downloads go to the default category, those in a later one move
    /// down one; each changed file is saved.
    pub fn remove_category(&mut self, cat: u32) {
        for e in self.files.values_mut() {
            let now = e.file.info().category;
            let new = if now == cat {
                0
            } else if now > cat {
                now - 1
            } else {
                continue;
            };
            e.file.set_category(new);
            if !e.done {
                let _ = e.file.save();
            }
        }
    }

    pub fn resume(&mut self, hash: &Md4Hash) -> bool {
        let Some(e) = self.files.get_mut(hash) else {
            return false;
        };
        if e.done {
            return true;
        }
        e.file.set_paused(false);
        e.stopped = false;
        e.last_sources_asked = None;
        let _ = e.file.save();
        true
    }

    /// Take a download out of the queue: its connections closed and its
    /// sources dropped. The caller deletes it (`CPartFile::Delete`).
    pub fn remove(
        &mut self,
        hash: &Md4Hash,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> Option<PartFile> {
        if !self.files.contains_key(hash) {
            return None;
        }
        self.close_file_conns(*hash, now, out);
        self.forget_sources(hash);
        self.dead.retain(|(f, _), _| f != hash);
        self.files.remove(hash).map(|e| e.file)
    }

    /// Whether the file is stopped (`IsStopped`).
    pub fn is_stopped(&self, hash: &Md4Hash) -> bool {
        self.files.get(hash).is_some_and(|e| e.stopped)
    }

    /// `RemoveAllSources`: no dead-list entries, so they can come back.
    fn forget_sources(&mut self, hash: &Md4Hash) {
        let ids: Vec<u64> = self
            .sources
            .iter()
            .filter(|(_, s)| &s.file == hash && s.conn.is_none())
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            if let Some(s) = self.sources.remove(&id) {
                if let (Some(parts), Some(e)) = (&s.parts, self.files.get_mut(&s.file)) {
                    e.file.remove_source(parts);
                }
            }
        }
    }

    pub fn file(&self, hash: &Md4Hash) -> Option<&PartFile> {
        self.files.get(hash).map(|e| &e.file)
    }

    pub fn file_mut(&mut self, hash: &Md4Hash) -> Option<&mut PartFile> {
        self.files.get_mut(hash).map(|e| &mut e.file)
    }

    pub fn files(&self) -> impl Iterator<Item = &PartFile> {
        self.files.values().map(|e| &e.file)
    }

    /// Whether every file is complete.
    pub fn all_done(&self) -> bool {
        self.files.values().all(|e| e.done)
    }

    pub fn source_count(&self, file: &Md4Hash) -> usize {
        self.sources.values().filter(|s| &s.file == file).count()
    }

    /// The state of each source of a file.
    pub fn sources_of(&self, file: &Md4Hash) -> Vec<(SocketAddrV4, Origin, SourceState)> {
        let mut v: Vec<_> = self
            .sources
            .values()
            .filter(|s| &s.file == file)
            .map(|s| (s.endpoint.addr, s.origin, s.state))
            .collect();
        v.sort_by_key(|s| s.0);
        v
    }

    /// Where each file stands.
    pub fn progress(&self) -> Vec<FileProgress> {
        let mut v: Vec<FileProgress> = self
            .files
            .values()
            .map(|e| {
                let hash = e.file.hash();
                let mine = |c: &Conn| {
                    c.source
                        .and_then(|id| self.sources.get(&id))
                        .is_some_and(|s| s.file == hash)
                };
                FileProgress {
                    hash,
                    name: e.file.name().to_owned(),
                    size: e.file.size(),
                    completed: e.file.completed(),
                    sources: self.source_count(&hash),
                    queued: self
                        .sources
                        .values()
                        .filter(|s| s.file == hash && s.state == SourceState::OnQueue)
                        .count(),
                    connected: self.conns.values().filter(|c| mine(c)).count(),
                    downloading: self
                        .conns
                        .values()
                        .filter(|c| {
                            mine(c)
                                && c.session
                                    .as_ref()
                                    .is_some_and(|s| s.state() == State::Downloading)
                        })
                        .count(),
                    done: e.done,
                    paused: e.file.is_paused(),
                    stopped: e.stopped,
                    status: e.file.status(),
                    transferred: e.file.transferred(),
                    part_met_name: e
                        .file
                        .met_path()
                        .file_stem()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    priority: e.file.info().down_priority,
                    auto_priority: e.file.info().auto_down_priority,
                    up_priority: e.file.info().up_priority,
                    auto_up_priority: e.file.info().auto_up_priority,
                    category: e.file.info().category,
                    last_seen_complete: e.file.info().last_seen_complete,
                    lost_to_corruption: e.file.lost_to_corruption(),
                    gaps: e.file.gaps().iter().collect(),
                    requested: e.file.requested_inclusive().to_vec(),
                    part_frequency: e.file.part_frequency().to_vec(),
                }
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn stats(&self) -> QueueStats {
        QueueStats {
            received: self.received,
            connections: self.conns.len(),
            sources: self.sources.len(),
        }
    }

    /// `CanAddSource` / `CheckAndAddSource`: take a source of `file`.
    /// False for an unknown or finished file, a bad address, ourselves, a
    /// source already known (whose missing details are filled in), one
    /// that failed recently, or a full list.
    pub fn add_source(
        &mut self,
        file: Md4Hash,
        ep: Endpoint,
        origin: Origin,
        now: Instant,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        self.add_source_into(file, ep, origin, now, &mut out);
        out
    }

    fn add_source_into(
        &mut self,
        file: Md4Hash,
        ep: Endpoint,
        origin: Origin,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> bool {
        // `CheckAndAddSource`: none for a stopped file.
        match self.files.get(&file) {
            Some(e) if !e.done && !e.stopped => {}
            _ => return false,
        }
        if ep.addr.port() == 0 || !is_good_ip(*ep.addr.ip(), self.config.filter_lan) {
            return false;
        }
        if self.blocks(*ep.addr.ip()) {
            return false;
        }
        let our_ip = Ipv4Addr::from(self.config.ours.id.to_le_bytes());
        if (*ep.addr.ip() == our_ip && ep.addr.port() == self.config.ours.port)
            || ep.user_hash == Some(self.config.ours.user_hash)
        {
            return false;
        }
        if let Some(s) = self.sources.values_mut().find(|s| {
            s.file == file
                && (s.endpoint.addr == ep.addr
                    || (ep.user_hash.is_some() && s.endpoint.user_hash == ep.user_hash))
        }) {
            if s.endpoint.user_hash.is_none() {
                s.endpoint.user_hash = ep.user_hash;
            }
            s.endpoint.crypt |= ep.crypt;
            return false;
        }
        match self.dead.get(&(file, ep.addr)) {
            Some(&until) if until > now => return false,
            _ => {}
        }
        if self.source_count(&file) >= self.config.max_sources_per_file {
            return false;
        }
        let id = self.id();
        self.sources.insert(
            id,
            Source {
                file,
                endpoint: ep,
                origin,
                state: SourceState::Idle,
                conn: None,
                last_asked: None,
                last_part: None,
                parts: None,
                queued_parts: None,
                complete: false,
                aich_root: None,
                last_source_answer: None,
                udp: None,
                crypt_udp: false,
                callback_unanswered: false,
                callback_other_layout: false,
                udp_pending: false,
                remote_queue_full: false,
            },
        );
        out.push(Action::Report(Report::SourceAdded {
            file,
            addr: ep.addr,
            origin,
        }));
        true
    }

    fn drop_source(&mut self, id: u64, why: &str, now: Instant, out: &mut Vec<Action>) {
        let Some(s) = self.sources.remove(&id) else {
            return;
        };
        if let (Some(parts), Some(e)) = (&s.parts, self.files.get_mut(&s.file)) {
            e.file.remove_source(parts);
        }
        self.dead
            .insert((s.file, s.endpoint.addr), now + self.config.dead_delay);
        out.push(Action::Report(Report::SourceDropped {
            file: s.file,
            addr: s.endpoint.addr,
            why: why.to_owned(),
        }));
    }

    /// `CPartFile::Process` for `DS_ONQUEUE` and `UDPReaskForDownload`:
    /// a queued source with a UDP port is asked again over UDP shortly
    /// before its TCP reask is due; an answer puts the TCP reask off.
    /// Only while others can reach us (a HighID), with a UDP port of our
    /// own, and not when the source is to be asked for sources (that
    /// needs TCP).
    fn udp_reasks(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.config.ours.udp_port == 0 || self.config.ours.id < 0x0100_0000 {
            return;
        }
        let early = self.config.reask.saturating_sub(UDP_REASK_EARLY);
        let ids: Vec<u64> = self
            .sources
            .iter()
            .filter(|(_, s)| {
                s.state == SourceState::OnQueue
                    && s.conn.is_none()
                    && !s.udp_pending
                    && s.udp.is_some()
                    && s.last_asked
                        .is_some_and(|t| now.saturating_duration_since(t) > early)
            })
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            let s = &self.sources[&id];
            let Some(e) = self.files.get(&s.file) else {
                continue;
            };
            if e.done || e.file.is_stopped() {
                continue;
            }
            let count = self.source_count(&s.file);
            if wants_sources(&self.config, e, s, count, now) {
                continue;
            }
            let (port, version) = s.udp.unwrap_or_default();
            let complete = self
                .sources
                .values()
                .filter(|o| o.file == s.file && o.complete)
                .count();
            let ping = UdpPacket::ReaskFilePing {
                file: s.file,
                parts: Some(e.file.part_status()),
                complete_sources: Some(complete.min(u16::MAX as usize) as u16),
            };
            let to = SocketAddrV4::new(*s.endpoint.addr.ip(), port);
            let obfuscate_for = s.endpoint.user_hash.filter(|_| s.crypt_udp);
            out.push(Action::SendUdp(UdpOut {
                to,
                payload: ping.to_datagram(version),
                obfuscate_for,
            }));
            self.sources.get_mut(&id).unwrap().udp_pending = true;
        }
    }

    /// A client UDP datagram (decrypted) from `from` that answers a reask
    /// of ours (`OP_REASKACK`, `OP_QUEUEFULL`, `OP_FILENOTFOUND`): it goes
    /// to the source waiting for an answer at that address
    /// (`GetDownloadClientByIP_UDP`).
    pub fn udp_packet(&mut self, from: SocketAddrV4, datagram: &[u8], now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let Some((&id, s)) = self.sources.iter().find(|(_, s)| {
            s.udp_pending
                && s.endpoint.addr.ip() == from.ip()
                && s.udp.is_some_and(|(p, _)| p == from.port())
        }) else {
            return out;
        };
        let version = s.udp.map(|(_, v)| v);
        let (file, addr) = (s.file, s.endpoint.addr);
        match UdpPacket::parse(datagram, version) {
            // `UDPReaskACK`
            Ok(UdpPacket::ReaskAck { rank, .. }) => {
                let s = self.sources.get_mut(&id).unwrap();
                s.udp_pending = false;
                s.remote_queue_full = false;
                s.last_asked = Some(now);
                out.push(Action::Report(Report::Queued {
                    file,
                    addr,
                    rank: Some(u32::from(rank)),
                }));
            }
            Ok(UdpPacket::QueueFull) => {
                let s = self.sources.get_mut(&id).unwrap();
                s.udp_pending = false;
                s.remote_queue_full = true;
                s.last_asked = Some(now);
            }
            // `UDPReaskFNF`
            Ok(UdpPacket::FileNotFound) => {
                self.drop_source(id, "file not found (UDP)", now, &mut out);
            }
            _ => {}
        }
        out
    }

    /// Whether a source is due to be asked (`SourceRetryPolicy::IsDue`).
    fn due(&self, s: &Source, now: Instant) -> bool {
        if s.conn.is_some() {
            return false;
        }
        let wait = match s.state {
            SourceState::NoNeededParts => self.config.reask * 2,
            _ => self.config.reask,
        };
        s.last_asked
            .is_none_or(|t| now.saturating_duration_since(t) > wait)
    }

    /// The periodic work (`CDownloadQueue::Process`): time-outs, flushing
    /// the files, and connecting to the sources that are due.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        self.dead.retain(|_, until| *until > now);

        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in ids {
            self.with_session(conn, now, &mut out, |s, view, now| s.tick(view, now));
        }

        let flush_due = self
            .last_flush
            .is_none_or(|t| now.saturating_duration_since(t) >= self.config.flush_every);
        if flush_due {
            self.last_flush = Some(now);
            let hashes: Vec<Md4Hash> = self.files.keys().copied().collect();
            for h in hashes {
                let e = self.files.get_mut(&h).unwrap();
                if !e.done {
                    let _ = e.file.flush();
                }
                self.file_events(h, now, &mut out);
            }
        }

        self.udp_reasks(now, &mut out);

        // Connect to the sources that are due, the longest waiting first.
        let room = self.config.max_connections.saturating_sub(self.conns.len());
        let mut due: Vec<(Option<Instant>, u64)> = self
            .sources
            .iter()
            .filter(|(_, s)| {
                self.files
                    .get(&s.file)
                    .is_some_and(|e| !e.done && !e.file.is_stopped())
                    && self.due(s, now)
            })
            .map(|(&id, s)| (s.last_asked, id))
            .collect();
        due.sort();
        // One connection per peer, as aMule has one client object per peer
        // (asking it for several files over parallel connections confuses
        // it): a peer that is a source of several files is asked for one at
        // a time.
        let mut busy: Vec<SocketAddrV4> = self
            .sources
            .values()
            .filter(|s| s.conn.is_some())
            .map(|s| s.endpoint.addr)
            .collect();
        let mut started = 0;
        for (_, id) in due {
            if started == room.min(self.config.max_new_per_tick) {
                break;
            }
            let addr = self.sources[&id].endpoint.addr;
            if busy.contains(&addr) {
                continue;
            }
            busy.push(addr);
            started += 1;
            // A source that takes UDP only (`SupportsDirectUDPCallback`):
            // ask it to connect to us, if it can (we are reachable, and have
            // a UDP port to ask from). One packet, like a connection try.
            if let Some(udp) = self.sources[&id].endpoint.direct_udp {
                let ok = self.config.reachable && self.config.ours.udp_port != 0;
                let ours = &self.config.ours;
                let req = UdpPacket::DirectCallbackReq {
                    tcp_port: ours.port,
                    user_hash: ours.user_hash,
                    // GetMyConnectOptions(true, false)
                    connect_options: 0x03,
                };
                let s = self.sources.get_mut(&id).unwrap();
                s.last_asked = Some(now);
                if ok {
                    let ep = s.endpoint;
                    let obfuscate_for = ep.user_hash.filter(|_| {
                        ep.crypt & crypt::SUPPORTED != 0
                            && (self.config.request_obfuscation || ep.crypt & crypt::REQUESTED != 0)
                    });
                    out.push(Action::SendUdp(UdpOut {
                        to: SocketAddrV4::new(*ep.addr.ip(), udp),
                        payload: req.to_datagram(0),
                        obfuscate_for,
                    }));
                }
                continue;
            }
            // A firewalled source: ask its buddy to have it connect to us
            // (`DS_WAITCALLBACKKAD`), unless we cannot be reached either.
            if let Some(route) = self.sources[&id].endpoint.buddy {
                let reachable = self.config.reachable;
                let s = self.sources.get_mut(&id).unwrap();
                s.last_asked = Some(now);
                if !reachable {
                    continue;
                }
                if s.callback_unanswered {
                    s.callback_other_layout = !s.callback_other_layout;
                }
                s.callback_unanswered = true;
                let buddy_id = if s.callback_other_layout {
                    ed2k_kad::search::buddy_id_other_layout(route.id)
                } else {
                    route.id
                };
                let req = ed2k_kad::packets::KadPacket::CallbackReq {
                    buddy_id,
                    file: ed2k_types::UInt128::from_be_bytes(s.file.0),
                    tcp_port: self.config.ours.port,
                };
                // Unobfuscated: the buddy's Kad version is not known.
                out.push(Action::SendUdp(UdpOut {
                    to: route.kad,
                    payload: req.to_datagram(),
                    obfuscate_for: None,
                }));
                continue;
            }
            let conn = self.id();
            let s = self.sources.get_mut(&id).unwrap();
            s.conn = Some(conn);
            s.state = SourceState::Connecting;
            s.last_asked = Some(now);
            s.udp_pending = false;
            let ep = s.endpoint;
            let obfuscate_for = ep.user_hash.filter(|_| {
                ep.crypt & crypt::SUPPORTED != 0
                    && (self.config.request_obfuscation || ep.crypt & crypt::REQUIRED != 0)
            });
            self.conns.insert(
                conn,
                Conn {
                    source: Some(id),
                    session: None,
                },
            );
            out.push(Action::Connect {
                conn,
                addr: SocketAddr::V4(ep.addr),
                obfuscate_for,
            });
        }
        out
    }

    // ------------------------------------------------------ network in ---

    /// An outgoing connection is up: say hello.
    pub fn connected(&mut self, conn: ConnId, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(source) = self.conns.get(&conn).and_then(|c| c.source) else {
            return out;
        };
        if self.conns[&conn].session.is_some() {
            return out;
        }
        let ours = self.config.ours.clone();
        let Some(s) = self.sources.get_mut(&source) else {
            return out;
        };
        s.state = SourceState::Connected;
        let Some(e) = self.files.get_mut(&s.file) else {
            return out;
        };
        let view = SourceView {
            file: &mut e.file,
            last_part: &mut s.last_part,
            wants_sources: false,
        };
        match Session::connect(ours, &view, now) {
            Ok((session, hello)) => {
                self.conns.get_mut(&conn).unwrap().session = Some(session);
                out.push(Action::Send {
                    conn,
                    packets: vec![hello],
                });
            }
            Err(_) => {
                self.finish_conn(conn, None, now, &mut out);
                out.push(Action::Close { conn });
            }
        }
        out
    }

    /// Someone connected to us (a source calling back with a slot). The
    /// first packet must be its hello.
    pub fn incoming(&mut self) -> ConnId {
        let conn = self.id();
        self.conns.insert(
            conn,
            Conn {
                source: None,
                session: None,
            },
        );
        conn
    }

    /// A packet arrived on `conn`.
    pub fn packet(&mut self, conn: ConnId, packet: Packet, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(c) = self.conns.get(&conn) else {
            return out;
        };
        let Some(session) = &c.session else {
            if c.source.is_none() {
                match PeerPacket::parse(packet, Default::default()) {
                    Ok(PeerPacket::Hello(h)) => self.accept_incoming(conn, h, now, &mut out),
                    _ => {
                        self.conns.remove(&conn);
                        out.push(Action::Close { conn });
                    }
                }
            }
            return out;
        };
        match PeerPacket::parse(packet, session.parse_context()) {
            Ok(p) => self.with_session(conn, now, &mut out, |s, v, now| s.handle(p, v, now)),
            Err(e) => {
                self.close_conn(conn, now, &mut out);
                if let Some(id) = self.source_of(conn) {
                    self.drop_source(id, &e.to_string(), now, &mut out);
                }
            }
        }
        out
    }

    /// `conn` is gone: it closed, or could not be opened.
    pub fn closed(&mut self, conn: ConnId, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(c) = self.conns.get(&conn) else {
            return out;
        };
        if c.session.is_some() {
            self.with_session(conn, now, &mut out, |s, v, _| s.closed(v));
        }
        // Not connected (or no session to say so): finish here.
        if self.conns.contains_key(&conn) {
            self.finish_conn(conn, None, now, &mut out);
        }
        out
    }

    /// Hang up every connection and save every file.
    pub fn shutdown(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in ids {
            self.close_conn(conn, now, &mut out);
        }
        for e in self.files.values_mut() {
            if !e.done {
                let _ = e.file.save();
            }
        }
        out
    }

    /// Whether `conn` is an incoming connection not yet matched to a source.
    pub fn is_unmatched_incoming(&self, conn: ConnId) -> bool {
        self.conns
            .get(&conn)
            .is_some_and(|c| c.source.is_none() && c.session.is_none())
    }

    /// Whether a peer that connected to us with this hello is one of our
    /// sources calling back (by user hash, else by address).
    pub fn wants_incoming(&self, hello: &Hello) -> bool {
        let ip = Ipv4Addr::from(hello.id.to_le_bytes());
        self.sources.values().any(|s| {
            s.conn.is_none()
                && self.files.get(&s.file).is_some_and(|e| !e.done)
                && (s.endpoint.user_hash == Some(hello.user_hash) || *s.endpoint.addr.ip() == ip)
        })
    }

    /// Hand an unmatched incoming connection over to someone else (the
    /// uploader): the queue forgets it.
    pub fn forget(&mut self, conn: ConnId) {
        if self.is_unmatched_incoming(conn) {
            self.conns.remove(&conn);
        }
    }

    fn source_of(&self, conn: ConnId) -> Option<u64> {
        self.conns.get(&conn).and_then(|c| c.source)
    }

    /// Match a callback to a source (by user hash, else by address) and
    /// resume its session.
    fn accept_incoming(&mut self, conn: ConnId, hello: Hello, now: Instant, out: &mut Vec<Action>) {
        let ip = Ipv4Addr::from(hello.id.to_le_bytes());
        let found = self
            .sources
            .iter()
            .filter(|(_, s)| s.conn.is_none() && self.files.get(&s.file).is_some_and(|e| !e.done))
            .find(|(_, s)| {
                s.endpoint.user_hash == Some(hello.user_hash) || *s.endpoint.addr.ip() == ip
            })
            .map(|(&id, _)| id);
        let Some(id) = found else {
            // Nothing to download from it; uploads are not ported yet.
            self.conns.remove(&conn);
            out.push(Action::Close { conn });
            return;
        };
        let ours = self.config.ours.clone();
        let s = self.sources.get_mut(&id).unwrap();
        let queued = (s.state == SourceState::OnQueue)
            .then(|| s.queued_parts.clone())
            .flatten();
        s.conn = Some(conn);
        s.state = SourceState::Connected;
        s.last_asked = Some(now);
        s.callback_unanswered = false;
        s.endpoint.user_hash.get_or_insert(hello.user_hash);
        let e = self.files.get_mut(&s.file).unwrap();
        let view = SourceView {
            file: &mut e.file,
            last_part: &mut s.last_part,
            wants_sources: false,
        };
        match Session::accepted(ours, hello, &view, queued, now) {
            Ok((session, output)) => {
                let c = self.conns.get_mut(&conn).unwrap();
                c.source = Some(id);
                c.session = Some(session);
                self.handle_output(conn, output, now, out);
            }
            Err(_) => {
                self.conns.remove(&conn);
                out.push(Action::Close { conn });
                if let Some(s) = self.sources.get_mut(&id) {
                    s.conn = None;
                }
            }
        }
    }

    /// Run `f` on a connection's session with its file, then act on the
    /// output.
    fn with_session(
        &mut self,
        conn: ConnId,
        now: Instant,
        out: &mut Vec<Action>,
        f: impl FnOnce(&mut Session, &mut SourceView<'_>, Instant) -> Output,
    ) {
        let Some(source) = self.source_of(conn) else {
            return;
        };
        let Some(file) = self.sources.get(&source).map(|s| s.file) else {
            return;
        };
        let count = self.source_count(&file);
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        let Some(session) = c.session.as_mut() else {
            return;
        };
        let s = self.sources.get_mut(&source).unwrap();
        let Some(e) = self.files.get_mut(&file) else {
            return;
        };
        let wants = wants_sources(&self.config, e, s, count, now);
        let mut view = SourceView {
            file: &mut e.file,
            last_part: &mut s.last_part,
            wants_sources: wants,
        };
        let output = f(session, &mut view, now);
        self.handle_output(conn, output, now, out);
    }

    /// Act on what a session produced.
    fn handle_output(&mut self, conn: ConnId, output: Output, now: Instant, out: &mut Vec<Action>) {
        if !output.send.is_empty() {
            out.push(Action::Send {
                conn,
                packets: output.send,
            });
        }
        let Some(sid) = self.source_of(conn) else {
            return;
        };
        let Some((file, addr)) = self.sources.get(&sid).map(|s| (s.file, s.endpoint.addr)) else {
            return;
        };
        let mut start_ident = false;
        let mut closed = None;
        let mut nothing_needed = false;
        let mut aich_answered = false;
        let mut exchanged = Vec::new();
        for ev in output.events {
            let Some(s) = self.sources.get_mut(&sid) else {
                break;
            };
            let Some(e) = self.files.get_mut(&file) else {
                break;
            };
            match ev {
                Event::Handshake(h) => {
                    s.endpoint.user_hash.get_or_insert(h.user_hash);
                    start_ident = self.config.identity.is_some();
                    let udp_version = h.misc1.map_or(0, |m| m.udp_version);
                    s.udp =
                        (h.udp_port != 0 && udp_version != 0).then_some((h.udp_port, udp_version));
                    let theirs = h.misc2.unwrap_or_default();
                    s.crypt_udp = theirs.supports_crypt
                        && (theirs.requires_crypt
                            || theirs.requests_crypt
                            || self.config.request_obfuscation);
                }
                Event::PeerParts(p) => {
                    if let Some(old) = s.parts.take() {
                        e.file.remove_source(&old);
                    }
                    e.file.add_source(&p);
                    s.complete = match &p {
                        PartStatus::Complete => true,
                        PartStatus::Parts(v) => !v.is_empty() && v.iter().all(|&b| b),
                    };
                    s.queued_parts = Some(p.clone());
                    s.parts = Some(p);
                }
                Event::Queued { rank } => {
                    // Once on entering the queue, then with each rank.
                    if s.state != SourceState::OnQueue || rank.is_some() {
                        out.push(Action::Report(Report::Queued { file, addr, rank }));
                    }
                    s.state = SourceState::OnQueue;
                }
                Event::NoNeededParts => {
                    s.state = SourceState::NoNeededParts;
                    nothing_needed = true;
                }
                Event::DownloadStarted => {
                    s.state = SourceState::Connected;
                    out.push(Action::Report(Report::DownloadStarted { file, addr }));
                }
                Event::Received(r) => self.received += r.end - r.start,
                Event::SourcesRequested => e.last_sources_asked = Some(now),
                Event::Sources(list) => {
                    s.last_source_answer = Some(now);
                    exchanged.extend(list.iter().filter_map(Endpoint::from_exchange));
                }
                Event::AichFileHash(root) => {
                    s.aich_root = Some(root);
                    e.file
                        .aich_hash_received(root, signing_key_v4(*addr.ip()), false);
                }
                Event::AichRecovery(r) => {
                    aich_answered = true;
                    match e.file.aich_recovery_data(r.part, r.root, &r.data) {
                        Ok(Some(bytes)) => out.push(Action::Report(Report::AichRecovered {
                            file,
                            part: r.part,
                            bytes,
                        })),
                        _ => e.file.aich_recovery_failed(r.part),
                    }
                }
                Event::AichRecoveryFailed { part } => {
                    aich_answered = true;
                    e.file.aich_recovery_failed(part);
                }
                Event::Identified(r) => out.push(Action::Report(Report::Identified {
                    addr,
                    passed: matches!(r, IdentResult::Passed { .. }),
                })),
                Event::Closed(reason) => closed = Some(reason),
                Event::FileName(_)
                | Event::HashSetReceived
                | Event::BlockFailed(_)
                | Event::DownloadStopped
                | Event::SourcesRejected(_)
                | Event::Unhandled(_) => {}
            }
        }
        for ep in exchanged {
            self.add_source_into(file, ep, Origin::SourceExchange, now, out);
        }
        if let Some(reason) = closed {
            if reason != CloseReason::Disconnected {
                out.push(Action::Close { conn });
            }
            self.finish_conn(conn, Some(reason), now, out);
            self.file_events(file, now, out);
            return;
        }
        if start_ident {
            self.start_ident(conn, addr, now, out);
        }
        if nothing_needed {
            // Check what this source sent before hanging up: a corrupt part
            // can still ask it for AICH recovery data.
            if let Some(e) = self.files.get_mut(&file) {
                let _ = e.file.flush();
            }
        }
        self.file_events(file, now, out);
        if nothing_needed || aich_answered {
            let idle = self
                .conns
                .get(&conn)
                .and_then(|c| c.session.as_ref())
                .is_some_and(|s| s.state() == State::NoNeededParts && s.aich_pending().is_none());
            if idle {
                self.close_conn(conn, now, out);
            }
        }
    }

    fn start_ident(
        &mut self,
        conn: ConnId,
        addr: SocketAddrV4,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Some(ours) = self.config.identity.clone() else {
            return;
        };
        let cfg = IdentConfig {
            ours,
            stored_key: None,
            peer_ip: Some(*addr.ip()),
            our_id: self.config.ours.id,
            our_public_ip: self.config.our_public_ip,
        };
        let challenge = self.random();
        let Some(session) = self.conns.get_mut(&conn).and_then(|c| c.session.as_mut()) else {
            return;
        };
        let output = session.start_secure_ident(cfg, challenge);
        self.handle_output(conn, output, now, out);
    }

    /// We hang up `conn`: its blocks go back to the file.
    fn close_conn(&mut self, conn: ConnId, now: Instant, out: &mut Vec<Action>) {
        if !self.conns.contains_key(&conn) {
            return;
        }
        out.push(Action::Close { conn });
        self.with_session(conn, now, out, |s, v, _| s.closed(v));
        if self.conns.contains_key(&conn) {
            self.finish_conn(conn, None, now, out);
        }
    }

    /// Forget `conn`, and decide what happens to its source.
    fn finish_conn(
        &mut self,
        conn: ConnId,
        reason: Option<CloseReason>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Some(c) = self.conns.remove(&conn) else {
            return;
        };
        let Some(id) = c.source else {
            return;
        };
        let Some(s) = self.sources.get_mut(&id) else {
            return;
        };
        if s.conn != Some(conn) {
            return;
        }
        s.conn = None;
        if let Some(p) = s.parts.take() {
            if let Some(e) = self.files.get_mut(&s.file) {
                e.file.remove_source(&p);
            }
        }
        let never_connected = s.state == SourceState::Connecting;
        match reason {
            Some(CloseReason::NoSuchFile) => {
                self.drop_source(id, "does not have the file", now, out)
            }
            Some(CloseReason::Protocol(why)) => self.drop_source(id, &why, now, out),
            Some(CloseReason::HandshakeTimeout) => {
                self.drop_source(id, "no hello answer", now, out)
            }
            _ if never_connected => self.drop_source(id, "could not connect", now, out),
            _ => {
                // Ask again later; queued and needless sources keep their state.
                if s.state == SourceState::Connected {
                    s.state = SourceState::Idle;
                }
            }
        }
    }

    /// Act on what a part file reports.
    fn file_events(&mut self, file: Md4Hash, now: Instant, out: &mut Vec<Action>) {
        let Some(e) = self.files.get_mut(&file) else {
            return;
        };
        for ev in e.file.take_events() {
            match ev {
                FileEvent::PartVerified(part) => {
                    out.push(Action::Report(Report::PartVerified { file, part }))
                }
                FileEvent::PartCorrupt(part) => {
                    out.push(Action::Report(Report::PartCorrupt { file, part }))
                }
                FileEvent::AichRecoveryWanted { part, root } => {
                    self.ask_aich(file, part, root, out)
                }
                FileEvent::ReadyToComplete => self.complete_file(file, now, out),
                FileEvent::Error(error) => {
                    out.push(Action::Report(Report::FileError { file, error }));
                    self.close_file_conns(file, now, out);
                }
                FileEvent::HashSetNeeded => {}
            }
        }
    }

    /// `RequestAICHRecovery`: ask a connected source that reported the
    /// trusted root, else give up for now.
    fn ask_aich(&mut self, file: Md4Hash, part: u16, root: AichHash, out: &mut Vec<Action>) {
        let pick = self.conns.iter().find_map(|(&conn, c)| {
            let s = self.sources.get(&c.source?)?;
            let session = c.session.as_ref()?;
            (s.file == file
                && s.aich_root == Some(root)
                && session.peer_supports_aich()
                && session.aich_pending().is_none())
            .then_some(conn)
        });
        let request = pick.and_then(|conn| {
            let session = self.conns.get_mut(&conn)?.session.as_mut()?;
            Some((conn, session.request_aich(part, root)?))
        });
        match request {
            Some((conn, packet)) => out.push(Action::Send {
                conn,
                packets: vec![packet],
            }),
            None => {
                if let Some(e) = self.files.get_mut(&file) {
                    e.file.aich_recovery_failed(part);
                }
            }
        }
    }

    fn close_file_conns(&mut self, file: Md4Hash, now: Instant, out: &mut Vec<Action>) {
        let conns: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| {
                c.source
                    .and_then(|id| self.sources.get(&id))
                    .is_some_and(|s| s.file == file)
            })
            .map(|(&id, _)| id)
            .collect();
        for conn in conns {
            self.close_conn(conn, now, out);
        }
    }

    /// `CompleteFile`: hang up, check the whole file, move it to incoming.
    fn complete_file(&mut self, file: Md4Hash, now: Instant, out: &mut Vec<Action>) {
        self.close_file_conns(file, now, out);
        let incoming = self.config.incoming.clone();
        let Some(e) = self.files.get_mut(&file) else {
            return;
        };
        match e.file.complete(&incoming) {
            Ok(Completion::Done(path)) => {
                e.done = true;
                self.sources.retain(|_, s| s.file != file);
                out.push(Action::Report(Report::Completed { file, path }));
            }
            Ok(Completion::Corrupt(corrupt)) => {
                out.push(Action::Report(Report::CompletionFailed { file, corrupt }));
                self.file_events(file, now, out);
            }
            Ok(Completion::AwaitingHashSet) => {}
            Err(err) => out.push(Action::Report(Report::FileError {
                file,
                error: err.to_string(),
            })),
        }
    }
}

/// Whether to ask a source for more sources (the file's half of
/// `IsSourceRequestAllowed`; the session checks the peer's half).
fn wants_sources(
    config: &QueueConfig,
    e: &FileEntry,
    s: &Source,
    sources: usize,
    now: Instant,
) -> bool {
    source_request_allowed(SourceRequestInput {
        ext_protocol: true,
        peer_sx2: true,
        peer_sx1_version: 4,
        sources: sources as u32,
        valid_sources: sources as u32,
        max_sources_soft: (config.max_sources_per_file as u32).min(MAX_SOURCES_FILE_SOFT),
        peer_complete: s.complete,
        since_peer_answer: s
            .last_source_answer
            .map(|t| now.saturating_duration_since(t)),
        since_file_answer: e
            .last_sources_asked
            .map_or(Duration::MAX, |t| now.saturating_duration_since(t)),
    })
}
