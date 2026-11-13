// SPDX-License-Identifier: GPL-2.0-or-later
//! A Kad node without IO (`CKademlia`, `CKademliaUDPListener`): datagrams
//! and the clock go in, datagrams and events come out.
//!
//! It answers what keeps the network healthy (bootstrap, hello, routing
//! requests, pings), keeps its routing table alive with the small timer
//! (hello to the oldest contact of each bin every minute), the big timer
//! (a random lookup in a thin zone every 10 s) and a lookup of its own ID,
//! and runs keyword and source searches. It does not store or publish
//! nothing yet, but it stores what others publish to it ([`crate::index`])
//! when it is reachable, answers searches from that, and keeps flooders out
//! ([`crate::tracking`]).

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};

use ed2k_crypto::udp::{self, ClientKey, OwnKeys, VerifyKeys};
use ed2k_formats::nodes_dat;
use ed2k_server::search::{encode_kad_search, kad_words, QueryError, SearchParams};
use ed2k_types::kad::v2::Opcode;
use ed2k_types::{Md4Hash, Protocol, UInt128};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::contact::{is_good_ip_port, is_lan_ip, Contact, UdpKey};
use crate::index::{size_of, Entry, Index, KeyEntry};
use crate::packets::{ContactRecord, Hello, KadPacket, SearchAnswer, SizedTag};
use crate::routing::{RoutingTable, CONTACT_FILE_LIMIT};
use crate::search::{keyword_target, Action, Found, Search, SearchKind, SEARCH_TOLERANCE};
use crate::tracking::{Admission, InTracker};
use ed2k_codec::{Tag, TagName, TagValue};
use ed2k_types::kad::{
    KADEMLIAMAXNOTECOMMENTLEN, KADEMLIAMAXNOTENAMELEN, KADEMLIAMAXSOURCEEXTRABYTES,
    KADEMLIAMAXSOURCESTRLEN, KADEMLIAREPUBLISHTIMEK, KADEMLIAREPUBLISHTIMEN,
    KADEMLIAREPUBLISHTIMES,
};
use ed2k_types::tags::kad as tag;

/// `KADEMLIA_VERSION_DEFAULT` (0.49b).
pub const VERSION: u8 = ed2k_types::kad::version::DEFAULT;
/// Tracked requests are answerable this long (`PacketTracking`).
pub const TRACK_TIME: u64 = 180;
/// `KADEMLIADISCONNECTDELAY`: no packet for this long and we are offline.
pub const DISCONNECT_DELAY: u64 = 20 * 60;
/// `CLIENTBANTIME`: how long a flooder is ignored.
pub const BAN_TIME: u64 = 2 * 3600;
/// Answers per `KADEMLIA2_SEARCH_RES`.
pub const RESULTS_PER_PACKET: usize = 50;

/// Who we are.
#[derive(Debug, Clone)]
pub struct Config {
    pub kad_id: UInt128,
    /// `CryptoKadUDPKey`: the secret our verify keys come from.
    pub udp_key_secret: u32,
    /// Our user hash (what eD2k-keyed obfuscated packets to us use).
    pub user_hash: Md4Hash,
    pub tcp_port: u16,
    /// Say we cannot take TCP connections (nothing listens).
    pub tcp_firewalled: bool,
    /// Say we cannot take unsolicited UDP: other nodes then keep us out of
    /// their routing tables, which suits a short-lived node.
    pub udp_firewalled: bool,
}

/// A datagram to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub to: SocketAddrV4,
    pub bytes: Vec<u8>,
}

/// Something for the application.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The first packet from the network.
    Connected,
    Found {
        search: u32,
        found: Found,
    },
    SearchDone {
        search: u32,
        answers: u32,
        requests: u32,
    },
}

/// What a call produced.
#[derive(Debug, Default)]
pub struct Output {
    pub send: Vec<Datagram>,
    pub events: Vec<Event>,
}

/// Counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bad_packets: u64,
    pub unrequested: u64,
    /// Requests dropped by the flood protection.
    pub flood_drops: u64,
    pub bans: u64,
    /// Publish requests stored.
    pub publishes_stored: u64,
    /// Search requests answered with at least one result.
    pub searches_answered: u64,
}

/// The node.
#[derive(Debug)]
pub struct Kad {
    cfg: Config,
    pub routing: RoutingTable,
    searches: BTreeMap<u32, Search>,
    by_target: HashMap<UInt128, u32>,
    next_search: u32,
    tracked: Vec<(u32, u8, u64)>,
    last_contact: u64,
    next_self_lookup: u64,
    big_timer: u64,
    next_consolidate: u64,
    next_jump_start: u64,
    /// The UDP port others see us at (`KADEMLIA2_PONG`).
    pub external_port: Option<u16>,
    pub stats: Stats,
    /// What others published to us.
    pub index: Index,
    tracker: InTracker,
    banned: HashMap<u32, u64>,
    rng: StdRng,
}

/// aMule-order IP of an address.
fn ip_of(a: &SocketAddrV4) -> u32 {
    u32::from(*a.ip())
}

impl Kad {
    pub fn new(cfg: Config, now: u64) -> Self {
        let kad_id = cfg.kad_id;
        let routing = RoutingTable::new(kad_id, now);
        Kad {
            cfg,
            routing,
            searches: BTreeMap::new(),
            by_target: HashMap::new(),
            next_search: 1,
            tracked: Vec::new(),
            last_contact: 0,
            next_self_lookup: now + 3 * 60,
            big_timer: now,
            next_consolidate: now + 45 * 60,
            next_jump_start: now,
            external_port: None,
            stats: Stats::default(),
            index: Index::new(kad_id),
            tracker: InTracker::default(),
            banned: HashMap::new(),
            rng: StdRng::from_entropy(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// `IsConnected`: a packet came in lately.
    pub fn is_connected(&self, now: u64) -> bool {
        self.last_contact != 0 && now.saturating_sub(self.last_contact) < DISCONNECT_DELAY
    }

    pub fn searches(&self) -> impl Iterator<Item = &Search> {
        self.searches.values()
    }

    /// Our verify key for `ip` (`GetUDPVerifyKey`).
    fn verify_key(&self, ip: u32) -> u32 {
        udp::udp_verify_key(self.cfg.udp_key_secret, Ipv4Addr::from(ip))
    }

    // ------------------------------------------------------------ nodes.dat

    /// `ReadFile`: the contacts of a nodes.dat into the routing table.
    /// Returns how many were taken.
    pub fn load_nodes(&mut self, nodes: &nodes_dat::NodesDat, now: u64) -> usize {
        let all_verified = nodes.treat_all_as_verified();
        let mut n = 0;
        for c in &nodes.contacts {
            if c.version <= 1 {
                continue;
            }
            let key = c
                .udp_key
                .map(|k| UdpKey::new(k.key, k.ip))
                .unwrap_or_default();
            let mut verified = c.is_verified();
            if self.routing.add(
                c.id,
                u32::from(c.ip),
                c.udp_port,
                c.tcp_port,
                c.version,
                key,
                &mut verified,
                false,
                false,
                now,
            ) {
                n += 1;
            }
        }
        if all_verified {
            self.routing.set_all_verified();
        }
        n
    }

    /// `WriteFile`: a nodes.dat (version 2) of up to 200 contacts, or
    /// `None` with fewer than 25.
    pub fn nodes_to_save(&mut self) -> Option<nodes_dat::NodesDat> {
        let rng = &mut self.rng;
        let mut pick = || rng.gen::<usize>();
        let mut list = self.routing.bootstrap_contacts(200, &mut pick);
        list.truncate(CONTACT_FILE_LIMIT);
        if list.len() < 25 {
            return None;
        }
        let contacts: Vec<nodes_dat::Contact> = list
            .iter()
            .map(|c| nodes_dat::Contact {
                id: c.id,
                ip: Ipv4Addr::from(c.ip),
                udp_port: c.udp_port,
                tcp_port: c.tcp_port,
                version: c.version,
                udp_key: Some(nodes_dat::KadUdpKey {
                    key: c.udp_key.key,
                    ip: c.udp_key.ip,
                }),
                verified: Some(c.ip_verified as u8),
            })
            .collect();
        nodes_dat::NodesDat::for_writing(&contacts)
    }

    // ------------------------------------------------------------ sending

    fn track(&mut self, ip: u32, op: Opcode, now: u64) {
        self.tracked.push((ip, op.into(), now));
    }

    /// `IsOnOutTrackList` (and take it off).
    fn was_requested(&mut self, ip: u32, op: Opcode, now: u64) -> bool {
        let op: u8 = op.into();
        match self
            .tracked
            .iter()
            .position(|&(i, o, t)| i == ip && o == op && now.saturating_sub(t) < TRACK_TIME)
        {
            Some(p) => {
                self.tracked.remove(p);
                true
            }
            None => false,
        }
    }

    /// `SendPacket`: obfuscated with the receiver's Kad ID (or its key)
    /// when it is version 6 or later.
    fn packet(
        &mut self,
        p: &KadPacket,
        to: SocketAddrV4,
        version: u8,
        crypt_id: Option<UInt128>,
        key: UdpKey,
        now: u64,
    ) -> Datagram {
        let ip = ip_of(&to);
        // Responses are tracked to check what answers them.
        let tracked = match p {
            KadPacket::BootstrapReq => Some(Opcode::BootstrapReq),
            KadPacket::HelloReq(_) => Some(Opcode::HelloReq),
            KadPacket::HelloRes(_) => Some(Opcode::HelloRes),
            KadPacket::Req { .. } => Some(Opcode::Req),
            KadPacket::Ping => Some(Opcode::Ping),
            _ => None,
        };
        if let Some(op) = tracked {
            self.track(ip, op, now);
        }
        let plain = p.to_datagram();
        let receiver_key = key.value_for(self.routing.public_ip);
        let id = crypt_id.filter(|id| !id.is_zero() && version >= 6);
        let ckey = match (id, receiver_key) {
            (Some(id), _) => Some(ClientKey::KadId(id)),
            (None, k) if k != 0 => Some(ClientKey::KadVerifyKey(k)),
            _ => None,
        };
        let bytes = match ckey {
            Some(k) => udp::encrypt_client(
                &plain,
                &k,
                VerifyKeys {
                    receiver: receiver_key,
                    sender: self.verify_key(ip),
                },
                &mut self.rng,
            ),
            None => plain,
        };
        self.stats.packets_out += 1;
        Datagram { to, bytes }
    }

    /// Send any packet (tests play the parts the node does not have yet).
    #[cfg(test)]
    pub(crate) fn send_to_test(
        &mut self,
        p: &KadPacket,
        to: SocketAddrV4,
        version: u8,
        crypt_id: Option<UInt128>,
        now: u64,
    ) -> Datagram {
        self.packet(p, to, version, crypt_id, UdpKey::default(), now)
    }

    fn send_to_contact(&mut self, p: &KadPacket, c: &Contact, now: u64) -> Datagram {
        self.packet(p, c.addr(), c.version, Some(c.id), c.udp_key, now)
    }

    /// `SendMyDetails`
    fn my_details(&self, target_version: u8, request_ack: bool) -> Hello {
        let mut misc = 0;
        if target_version >= 8
            && (request_ack || self.cfg.tcp_firewalled || self.cfg.udp_firewalled)
        {
            misc = (request_ack as u8) << 2
                | (self.cfg.tcp_firewalled as u8) << 1
                | self.cfg.udp_firewalled as u8;
        }
        Hello {
            id: self.cfg.kad_id,
            tcp_port: self.cfg.tcp_port,
            version: VERSION,
            udp_port: None,
            misc_options: misc,
        }
    }

    fn action(&mut self, a: Action, search_target: UInt128, now: u64) -> Datagram {
        match a {
            Action::FindNodes { to, count } => self.send_to_contact(
                &KadPacket::Req {
                    count,
                    target: search_target,
                    receiver: to.id,
                },
                &to,
                now,
            ),
            Action::SearchKey { to, terms } => self.send_to_contact(
                &KadPacket::SearchKeyReq {
                    target: search_target,
                    start: 0,
                    terms: Some(terms),
                },
                &to,
                now,
            ),
            Action::SearchSource { to, size } => self.send_to_contact(
                &KadPacket::SearchSourceReq {
                    target: search_target,
                    start: 0,
                    size,
                },
                &to,
                now,
            ),
        }
    }

    /// Send `KADEMLIA2_BOOTSTRAP_REQ` to an address (unobfuscated: its ID is unknown).
    pub fn bootstrap(&mut self, to: SocketAddrV4, now: u64) -> Datagram {
        self.packet(
            &KadPacket::BootstrapReq,
            to,
            0,
            None,
            UdpKey::default(),
            now,
        )
    }

    // ------------------------------------------------------------ searches

    fn start(
        &mut self,
        kind: SearchKind,
        target: UInt128,
        now: u64,
    ) -> Option<(u32, Vec<Datagram>)> {
        if self.by_target.contains_key(&target) {
            return None;
        }
        let id = self.next_search;
        self.next_search += 1;
        let mut s = Search::new(id, kind, target, now);
        let actions = s.go(&self.routing);
        self.searches.insert(id, s);
        self.by_target.insert(target, id);
        let out = actions
            .into_iter()
            .map(|a| self.action(a, target, now))
            .collect();
        Some((id, out))
    }

    /// `FindNode`: a routing lookup.
    pub fn find_node(
        &mut self,
        target: UInt128,
        complete: bool,
        now: u64,
    ) -> Option<(u32, Vec<Datagram>)> {
        let kind = if complete {
            SearchKind::NodeComplete
        } else {
            SearchKind::Node
        };
        self.start(kind, target, now)
    }

    /// A keyword search (`PrepareFindKeywords`); returns the search ID, the
    /// keyword it looks up, and what to send.
    pub fn search_keyword(
        &mut self,
        params: &SearchParams,
        now: u64,
    ) -> Result<(u32, String, Vec<Datagram>), SearchError> {
        let (keyword, terms) = encode_kad_search(params)?;
        let word = kad_words(&keyword)
            .into_iter()
            .next()
            .ok_or(SearchError::Query(QueryError::NoKeyword))?;
        let target = keyword_target(&word);
        let (id, out) = self
            .start(SearchKind::Keyword { terms }, target, now)
            .ok_or(SearchError::AlreadySearching)?;
        Ok((id, word, out))
    }

    /// A source search for a file.
    pub fn search_sources(
        &mut self,
        hash: Md4Hash,
        size: u64,
        now: u64,
    ) -> Result<(u32, Vec<Datagram>), SearchError> {
        let target = UInt128::from_be_bytes(hash.0);
        self.start(SearchKind::Source { size }, target, now)
            .ok_or(SearchError::AlreadySearching)
    }

    // ------------------------------------------------------------ timers

    /// Run the timers; call it about once a second.
    pub fn tick(&mut self, now: u64) -> Output {
        let mut out = Output::default();
        self.tracked
            .retain(|&(_, _, t)| now.saturating_sub(t) < TRACK_TIME);

        if self.next_self_lookup <= now {
            self.next_self_lookup = now + 4 * 3600;
            if let Some((_, d)) = self.find_node(self.cfg.kad_id, true, now) {
                out.send.extend(d);
            }
        }
        if self.big_timer <= now {
            let random: u128 = self.rng.gen();
            let stale = self.last_contact != 0
                && now.saturating_sub(self.last_contact) > DISCONNECT_DELAY - 5 * 60;
            if let Some(target) = self.routing.big_timer(now, random, stale) {
                self.big_timer = now + 10;
                if let Some((_, d)) = self.find_node(target, false, now) {
                    out.send.extend(d);
                }
            }
        }
        for c in self.routing.small_timer(now) {
            let hello = KadPacket::HelloReq(self.my_details(c.version, false));
            let d = self.send_to_contact(&hello, &c, now);
            out.send.push(d);
        }
        if self.next_consolidate <= now {
            self.next_consolidate = now + 45 * 60;
            self.routing.consolidate(now);
        }
        if self.next_jump_start <= now {
            self.next_jump_start = now + 1;
            let ids: Vec<u32> = self.searches.keys().copied().collect();
            for id in ids {
                let Some(s) = self.searches.get_mut(&id) else {
                    continue;
                };
                let target = s.target;
                let (done, actions) = s.tick(now);
                if done {
                    let s = self.searches.remove(&id).expect("present");
                    self.by_target.remove(&s.target);
                    if matches!(
                        s.kind,
                        SearchKind::Keyword { .. } | SearchKind::Source { .. }
                    ) {
                        out.events.push(Event::SearchDone {
                            search: id,
                            answers: s.answers,
                            requests: s.requests,
                        });
                    }
                    continue;
                }
                for a in actions {
                    let d = self.action(a, target, now);
                    out.send.push(d);
                }
            }
        }
        out
    }

    // ------------------------------------------------------------ receiving

    /// Handle a datagram from `from`.
    pub fn handle(&mut self, from: SocketAddrV4, datagram: &[u8], now: u64) -> Output {
        let mut out = Output::default();
        let ip = ip_of(&from);
        let port = from.port();
        if self.banned.get(&ip).is_some_and(|&until| until > now) {
            return out;
        }
        // Decrypt (DecryptReceivedClient): our Kad ID, then our verify key for the sender.
        let (plain, valid_receiver_key, sender_key) = match datagram.first() {
            Some(&b) if b == Protocol::Kademlia as u8 || b == Protocol::KademliaPacked as u8 => {
                (datagram.to_vec(), false, UdpKey::default())
            }
            _ => {
                let own = OwnKeys {
                    user_hash: self.cfg.user_hash,
                    sender_ip: *from.ip(),
                    kad_id: Some(self.cfg.kad_id),
                    verify_key: Some(self.verify_key(ip)),
                };
                match udp::decrypt_client(datagram, &own) {
                    Some(d) if d.kad => (
                        d.payload,
                        d.verify.receiver == self.verify_key(ip),
                        UdpKey::new(d.verify.sender, self.routing.public_ip),
                    ),
                    _ => {
                        self.stats.bad_packets += 1;
                        return out;
                    }
                }
            }
        };
        // No unobfuscated packets from port 53 (DNS).
        if port == 53 && sender_key.is_empty() {
            return out;
        }
        let packet = match KadPacket::parse(&plain) {
            Ok(p) => p,
            Err(_) => {
                self.stats.bad_packets += 1;
                return out;
            }
        };
        self.stats.packets_in += 1;
        match self
            .tracker
            .admit(ip, packet.opcode(), valid_receiver_key, now * 1000)
        {
            Admission::Allowed => {}
            Admission::Drop => {
                self.stats.flood_drops += 1;
                return out;
            }
            Admission::MassiveFlood => {
                // Only keyed packets get here: the sender cannot be spoofed.
                self.stats.bans += 1;
                self.banned.insert(ip, now + BAN_TIME);
                if let Some(id) = self.routing.get_by_addr(ip, port, false).map(|c| c.id) {
                    if let Some(c) = self.routing.get_mut(id) {
                        c.kind = 4;
                        c.expires = 1;
                    }
                }
                return out;
            }
        }
        if self.last_contact == 0 {
            out.events.push(Event::Connected);
        }
        self.last_contact = now;
        self.dispatch(packet, from, valid_receiver_key, sender_key, now, &mut out);
        out
    }

    /// `AddContact2`: the sender of a hello, unless it is UDP-firewalled.
    fn add_hello_sender(
        &mut self,
        h: &Hello,
        ip: u32,
        port: &mut u16,
        key: UdpKey,
        verified: &mut bool,
        now: u64,
    ) -> bool {
        if let Some(p) = h.udp_port {
            *port = p;
        }
        if h.udp_firewalled() {
            return false;
        }
        self.routing.add(
            h.id, ip, *port, h.tcp_port, h.version, key, verified, true, true, now,
        )
    }

    fn dispatch(
        &mut self,
        packet: KadPacket,
        from: SocketAddrV4,
        valid_key: bool,
        sender_key: UdpKey,
        now: u64,
        out: &mut Output,
    ) {
        let ip = ip_of(&from);
        let mut port = from.port();
        match packet {
            KadPacket::BootstrapReq => {
                let rng = &mut self.rng;
                let mut pick = || rng.gen::<usize>();
                let contacts = self
                    .routing
                    .bootstrap_contacts(20, &mut pick)
                    .iter()
                    .map(|c| ContactRecord {
                        id: c.id,
                        ip: c.ip,
                        udp_port: c.udp_port,
                        tcp_port: c.tcp_port,
                        version: c.version,
                    })
                    .collect();
                let res = KadPacket::BootstrapRes {
                    id: self.cfg.kad_id,
                    tcp_port: self.cfg.tcp_port,
                    version: VERSION,
                    contacts,
                };
                let d = self.packet(&res, from, 0, None, sender_key, now);
                out.send.push(d);
            }
            KadPacket::BootstrapRes {
                id,
                tcp_port,
                version,
                contacts,
            } => {
                if !self.was_requested(ip, Opcode::BootstrapReq, now) {
                    self.stats.unrequested += 1;
                    return;
                }
                let assume_verified = self.routing.is_empty();
                let mut v = valid_key;
                self.routing.add(
                    id, ip, port, tcp_port, version, sender_key, &mut v, true, false, now,
                );
                for c in contacts {
                    let mut v = assume_verified;
                    self.routing.add(
                        c.id,
                        c.ip,
                        c.udp_port,
                        c.tcp_port,
                        c.version,
                        UdpKey::default(),
                        &mut v,
                        false,
                        false,
                        now,
                    );
                }
            }
            KadPacket::HelloReq(h) => {
                let mut verified = valid_key;
                let added =
                    self.add_hello_sender(&h, ip, &mut port, sender_key, &mut verified, now);
                let res = KadPacket::HelloRes(self.my_details(h.version, added && !valid_key));
                let to = SocketAddrV4::new(*from.ip(), port);
                let d = self.packet(&res, to, h.version, Some(h.id), sender_key, now);
                out.send.push(d);
            }
            KadPacket::HelloRes(h) => {
                if !self.was_requested(ip, Opcode::HelloReq, now) {
                    self.stats.unrequested += 1;
                    return;
                }
                let mut verified = valid_key;
                self.add_hello_sender(&h, ip, &mut port, sender_key, &mut verified, now);
                if h.wants_ack() && h.version >= 8 && !sender_key.is_empty() {
                    let ack = KadPacket::HelloResAck {
                        id: self.cfg.kad_id,
                    };
                    let to = SocketAddrV4::new(*from.ip(), port);
                    let d = self.packet(&ack, to, h.version, None, sender_key, now);
                    out.send.push(d);
                }
            }
            KadPacket::HelloResAck { id } => {
                if !self.was_requested(ip, Opcode::HelloRes, now) || !valid_key {
                    return;
                }
                self.routing.verify(id, ip);
            }
            KadPacket::Req {
                count,
                target,
                receiver,
            } => {
                if count == 0 || receiver != self.cfg.kad_id {
                    return;
                }
                let contacts = self
                    .routing
                    .closest_to(2, target, count as usize)
                    .values()
                    .map(|c| ContactRecord {
                        id: c.id,
                        ip: c.ip,
                        udp_port: c.udp_port,
                        tcp_port: c.tcp_port,
                        version: c.version,
                    })
                    .collect();
                let res = KadPacket::Res { target, contacts };
                let d = self.packet(&res, from, 0, None, sender_key, now);
                out.send.push(d);
            }
            KadPacket::Res { target, contacts } => {
                if !self.was_requested(ip, Opcode::Req, now) {
                    self.stats.unrequested += 1;
                    return;
                }
                let filter_lan = self.routing.filter_lan;
                let mut results = Vec::new();
                for c in contacts {
                    if c.version <= 1
                        || !is_good_ip_port(c.ip, c.udp_port, filter_lan)
                        || (c.udp_port == 53 && c.version <= 5)
                    {
                        continue;
                    }
                    let mut verified = false;
                    let added = self.routing.add_unfiltered(
                        c.id,
                        c.ip,
                        c.udp_port,
                        c.tcp_port,
                        c.version,
                        UdpKey::default(),
                        &mut verified,
                        false,
                        false,
                        now,
                    );
                    let contact = Contact::new(
                        c.id,
                        c.ip,
                        c.udp_port,
                        c.tcp_port,
                        c.version,
                        UdpKey::default(),
                        false,
                        now,
                    );
                    if added || self.routing.is_acceptable(&contact) {
                        results.push(contact);
                    }
                }
                let Some(&id) = self.by_target.get(&target) else {
                    return;
                };
                let Some(s) = self.searches.get_mut(&id) else {
                    return;
                };
                let actions = s.process_response(ip, port, sender_key, results, now);
                for a in actions {
                    let d = self.action(a, target, now);
                    out.send.push(d);
                }
            }
            KadPacket::SearchRes {
                target, results, ..
            } => {
                let Some(&id) = self.by_target.get(&target) else {
                    return;
                };
                let Some(s) = self.searches.get_mut(&id) else {
                    return;
                };
                for r in results {
                    if let Some(found) = s.process_result(r.answer, &r.tags, ip) {
                        out.events.push(Event::Found { search: id, found });
                    }
                }
            }
            KadPacket::Ping => {
                let pong = KadPacket::Pong { port };
                let d = self.packet(&pong, from, 0, None, sender_key, now);
                out.send.push(d);
            }
            KadPacket::Pong { port } => {
                if self.was_requested(ip, Opcode::Ping, now) {
                    self.external_port = Some(port);
                }
            }
            KadPacket::SearchKeyReq {
                target,
                start,
                terms,
            } => {
                let terms = match terms {
                    Some(t) => match crate::terms::parse(&t) {
                        Some(t) => Some(t),
                        None => return, // "Invalid search expression"
                    },
                    None => None,
                };
                let res = self
                    .index
                    .keyword_results(target, terms.as_ref(), start, now);
                self.send_results(target, res, from, sender_key, now, out);
            }
            KadPacket::SearchSourceReq {
                target,
                start,
                size,
            } => {
                let res = self.index.source_results(target, start, size, now);
                self.send_results(target, res, from, sender_key, now, out);
            }
            KadPacket::SearchNotesReq { target, size } => {
                let res = self.index.note_results(target, size, now);
                self.send_results(target, res, from, sender_key, now, out);
            }
            KadPacket::PublishKeyReq { key, files } => {
                if let Some(load) = self.publish_keys(key, files, ip, port, now) {
                    self.publish_res(key, load, from, sender_key, now, out);
                }
            }
            KadPacket::PublishSourceReq { file, source, tags } => {
                if let Some(load) = self.publish_source(file, source, tags, ip, port, now) {
                    self.publish_res(file, load, from, sender_key, now, out);
                }
            }
            KadPacket::PublishNotesReq { file, source, tags } => {
                if let Some(load) = self.publish_note(file, source, tags, ip, port, now) {
                    self.publish_res(file, load, from, sender_key, now, out);
                }
            }
            // We publish nothing yet.
            KadPacket::PublishRes { .. } | KadPacket::PublishResAck | KadPacket::Other { .. } => {}
        }
    }
}

fn int_tag(name: &[u8], v: u64) -> Tag {
    Tag::new(TagName::Str(name.to_vec()), TagValue::int(v))
}

impl Kad {
    fn publish_res(
        &mut self,
        target: UInt128,
        load: u8,
        to: SocketAddrV4,
        key: UdpKey,
        now: u64,
        out: &mut Output,
    ) {
        let res = KadPacket::PublishRes {
            target,
            load,
            options: None,
        };
        let d = self.packet(&res, to, 0, None, key, now);
        out.send.push(d);
    }

    /// The answers to a search request, 50 to a packet.
    fn send_results(
        &mut self,
        target: UInt128,
        results: Vec<SearchAnswer>,
        to: SocketAddrV4,
        key: UdpKey,
        now: u64,
        out: &mut Output,
    ) {
        if !results.is_empty() {
            self.stats.searches_answered += 1;
        }
        for chunk in results.chunks(RESULTS_PER_PACKET) {
            let res = KadPacket::SearchRes {
                sender: self.cfg.kad_id,
                target,
                results: chunk.to_vec(),
            };
            let d = self.packet(&res, to, 0, None, key, now);
            out.send.push(d);
        }
    }

    /// Whether a publish to `target` from `ip` is for us: we are reachable
    /// and close enough to it.
    fn takes_publish(&self, target: UInt128, ip: u32) -> bool {
        !self.cfg.udp_firewalled
            && ((self.cfg.kad_id ^ target).chunk(0) <= SEARCH_TOLERANCE || is_lan_ip(ip))
    }

    /// `Process2PublishKeyRequest`: the load to answer with, or `None` to stay silent.
    fn publish_keys(
        &mut self,
        key: UInt128,
        files: Vec<(UInt128, Vec<SizedTag>)>,
        ip: u32,
        port: u16,
        now: u64,
    ) -> Option<u8> {
        if !self.takes_publish(key, ip) {
            return None;
        }
        let mut load = 0;
        for (file, tags) in files {
            let mut e = KeyEntry::new(Entry {
                ip,
                udp_port: port,
                key_id: key,
                source_id: file,
                lifetime: now + KADEMLIAREPUBLISHTIMEK.as_secs(),
                ..Default::default()
            });
            for SizedTag { tag: t, .. } in tags {
                if t.name.is(tag::FILENAME) {
                    if e.entry.common_name().is_empty() {
                        e.entry.set_name(t.as_str().unwrap_or_default());
                    }
                } else if t.name.is(tag::FILESIZE) {
                    if e.entry.size == 0 {
                        e.entry.size = size_of(&t);
                    }
                } else if t.name.is(tag::KADAICHHASHPUB) {
                    if let TagValue::Bsob(b) = &t.value {
                        if let Ok(h) = <[u8; crate::aich::HASH_SIZE]>::try_from(&b[..]) {
                            if e.aich_count() == 0 {
                                e.set_published_aich(&h);
                            }
                        }
                    }
                } else {
                    e.entry.add_tag(t);
                }
            }
            let (stored, l) = self.index.add_keyword(key, file, e, now);
            load = l;
            if stored {
                self.stats.publishes_stored += 1;
            }
        }
        Some(load)
    }

    /// `Process2PublishSourceRequest`: answered only when stored.
    fn publish_source(
        &mut self,
        file: UInt128,
        source: UInt128,
        tags: Vec<SizedTag>,
        ip: u32,
        port: u16,
        now: u64,
    ) -> Option<u8> {
        if !self.takes_publish(file, ip) {
            return None;
        }
        let mut e = Entry {
            ip,
            udp_port: port,
            key_id: file,
            source_id: source,
            lifetime: now + KADEMLIAREPUBLISHTIMES.as_secs(),
            ..Default::default()
        };
        let mut udp_tag_pending = true;
        let (mut extra, mut extra_full) = (0u32, false);
        for SizedTag { tag: t, bytes } in tags {
            let n = &t.name;
            if n.is(tag::SOURCETYPE) {
                if !e.is_source {
                    e.add_tag(int_tag(tag::SOURCEIP, ip as u64));
                    e.add_tag(t);
                    e.is_source = true;
                }
            } else if n.is(tag::FILESIZE) {
                if e.size == 0 {
                    e.size = size_of(&t);
                }
            } else if n.is(tag::SOURCEPORT) {
                if e.tcp_port == 0 {
                    e.tcp_port = t.as_int().unwrap_or(0) as u16;
                    e.add_tag(t);
                }
            } else if n.is(tag::SOURCEUPORT) {
                if udp_tag_pending && t.as_int().is_some_and(|v| v != 0) {
                    e.udp_port = t.as_int().unwrap_or(0) as u16;
                    e.add_tag(t);
                    udp_tag_pending = false;
                }
            } else if n.is(tag::SERVERIP) || n.is(tag::SERVERPORT) || n.is(tag::ENCRYPTION) {
                if t.as_int().is_some() {
                    e.add_tag(t);
                }
            } else if n.is(tag::BUDDYHASH) || n.is(tag::IPV6) || n.is(tag::SERVINGBUDDYIPV6) {
                if t.as_str()
                    .is_some_and(|s| s.chars().count() <= KADEMLIAMAXSOURCESTRLEN)
                {
                    e.add_tag(t);
                }
            } else if !extra_full
                && extra + bytes <= KADEMLIAMAXSOURCEEXTRABYTES as u32
                && self.index.has_room_for_extra_tags(extra + bytes)
            {
                extra += bytes;
                e.add_tag(t);
            } else {
                extra_full = true;
            }
        }
        if udp_tag_pending {
            e.add_tag(int_tag(tag::SOURCEUPORT, e.udp_port as u64));
        }
        e.extra_tag_bytes = extra;
        if !e.is_source {
            return None;
        }
        let (stored, load) = self.index.add_source(file, source, e, now);
        if stored {
            self.stats.publishes_stored += 1;
        }
        stored.then_some(load)
    }

    /// `Process2PublishNotesRequest`: answered only when stored.
    fn publish_note(
        &mut self,
        file: UInt128,
        source: UInt128,
        tags: Vec<SizedTag>,
        ip: u32,
        port: u16,
        now: u64,
    ) -> Option<u8> {
        if !self.takes_publish(file, ip) {
            return None;
        }
        let mut e = Entry {
            ip,
            udp_port: port,
            key_id: file,
            source_id: source,
            lifetime: now + KADEMLIAREPUBLISHTIMEN.as_secs(),
            ..Default::default()
        };
        let mut valid = true;
        for SizedTag { tag: t, .. } in tags {
            let n = &t.name;
            if n.is(tag::FILENAME) {
                let s = t.as_str().unwrap_or_default();
                if s.chars().count() > KADEMLIAMAXNOTENAMELEN {
                    valid = false;
                } else if e.common_name().is_empty() {
                    e.set_name(s);
                }
            } else if n.is(tag::FILESIZE) {
                if e.size == 0 {
                    e.size = t.as_int().unwrap_or(0);
                }
            } else if n.is(tag::DESCRIPTION) {
                if t.as_str().unwrap_or_default().chars().count() > KADEMLIAMAXNOTECOMMENTLEN {
                    valid = false;
                } else {
                    e.add_tag(t);
                }
            } else if n.is(tag::FILERATING) && t.as_int().is_some() {
                e.add_tag(t);
            }
        }
        if !valid {
            return None;
        }
        let (stored, load) = self.index.add_note(file, source, e, now);
        if stored {
            self.stats.publishes_stored += 1;
        }
        stored.then_some(load)
    }
}

/// Why a search could not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SearchError {
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error("already searching for that")]
    AlreadySearching,
}
