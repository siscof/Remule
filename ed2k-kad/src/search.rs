// SPDX-License-Identifier: GPL-2.0-or-later
//! Iterative lookups and searches (`CSearch`, `CSearchManager`).
//!
//! A lookup starts from the 50 closest contacts we know, asks up to
//! [`ALPHA_QUERY`] of them for contacts closer to the target, and keeps
//! asking the best new ones; every second ("jump start") it asks the next
//! closest untried one. When a contact that answered comes up again, a
//! keyword or source search sends it the actual search request
//! (`StorePacket`) — if it is close enough ([`SEARCH_TOLERANCE`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use ed2k_codec::Tag;
use ed2k_types::kad::FindType;
use ed2k_types::tags::kad as tag;
use ed2k_types::{Md4Hash, UInt128};

use crate::contact::{is_lan_ip, Contact, UdpKey};
use crate::routing::RoutingTable;

/// `ALPHA_QUERY`: requests in flight.
pub const ALPHA_QUERY: usize = 5;
/// `SEARCHTOLERANCE`: how far (in the top 32 bits) a node may be from the
/// target and still be asked for results.
pub const SEARCH_TOLERANCE: u32 = 16_777_216;
/// `SEARCH*_LIFETIME` (seconds) of every kind here.
pub const LIFETIME: u64 = 45;
/// `SEARCHNODECOMP_LIFETIME`
pub const NODECOMP_LIFETIME: u64 = 10;
/// `SEARCHNODECOMP_TOTAL`
pub const NODECOMP_TOTAL: u32 = 10;
/// `SEARCHKEYWORD_TOTAL` / `SEARCHFILE_TOTAL`
pub const RESULTS_TOTAL: u32 = 300;

/// What is being looked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKind {
    /// `NODE`: a routing lookup; it ends with the first answer.
    Node,
    /// `NODECOMPLETE`: the lookup of our own ID.
    NodeComplete,
    /// Files for a keyword; `terms` narrow it (`SetSearchTermData`).
    Keyword { terms: Vec<u8> },
    /// Sources of a file of this size.
    Source { size: u64 },
}

impl SearchKind {
    fn request_count(&self) -> u8 {
        match self {
            SearchKind::Node | SearchKind::NodeComplete => FindType::FindNode.into(),
            SearchKind::Keyword { .. } | SearchKind::Source { .. } => FindType::FindValue.into(),
        }
    }
}

/// What a search wants sent.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// `KADEMLIA2_REQ` asking for `count` contacts close to the target.
    FindNodes { to: Contact, count: u8 },
    /// `KADEMLIA2_SEARCH_KEY_REQ`
    SearchKey { to: Contact, terms: Vec<u8> },
    /// `KADEMLIA2_SEARCH_SOURCE_REQ`
    SearchSource { to: Contact, size: u64 },
}

/// A file found by a keyword search (`ProcessResultKeyword`).
#[derive(Debug, Clone, PartialEq)]
pub struct KeywordResult {
    pub hash: Md4Hash,
    pub name: String,
    pub size: u64,
    pub file_type: String,
    pub format: String,
    pub artist: String,
    pub album: String,
    pub title: String,
    pub length: u32,
    pub bitrate: u32,
    pub codec: String,
    /// Sources (0 when the node says more than 65500).
    pub availability: u32,
    /// `TAG_PUBLISHINFO`: different names (8 bits), publishers (8), trust ×100 (16).
    pub publish_info: u32,
    /// The node that answered.
    pub from: Ipv4Addr,
}

/// A source found by a source search (`ProcessResultFile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceResult {
    /// The source's user hash.
    pub user_hash: Md4Hash,
    /// 1: high ID, 3: firewalled with a buddy, 4/5/6: newer kinds.
    pub source_type: u8,
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub buddy_ip: Ipv4Addr,
    pub buddy_port: u16,
    pub crypt_options: u8,
}

/// A result.
#[derive(Debug, Clone, PartialEq)]
pub enum Found {
    Keyword(Box<KeywordResult>),
    Source(SourceResult),
}

/// One lookup.
#[derive(Debug, Clone)]
pub struct Search {
    pub id: u32,
    pub kind: SearchKind,
    pub target: UInt128,
    possible: BTreeMap<UInt128, Contact>,
    tried: BTreeMap<UInt128, Contact>,
    best: BTreeMap<UInt128, Contact>,
    responded: BTreeMap<UInt128, bool>,
    requested_more: HashSet<UInt128>,
    pub answers: u32,
    /// Search requests sent.
    pub requests: u32,
    pub created: u64,
    last_response: u64,
    stopping: bool,
    /// The closest node asked for results.
    pub closest_found: Option<UInt128>,
}

impl Search {
    pub fn new(id: u32, kind: SearchKind, target: UInt128, now: u64) -> Self {
        Search {
            id,
            kind,
            target,
            possible: BTreeMap::new(),
            tried: BTreeMap::new(),
            best: BTreeMap::new(),
            responded: BTreeMap::new(),
            requested_more: HashSet::new(),
            answers: 0,
            requests: 0,
            created: now,
            last_response: 0,
            stopping: false,
            closest_found: None,
        }
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping
    }

    /// Contacts asked so far.
    pub fn tried(&self) -> usize {
        self.tried.len()
    }

    /// `Go`
    pub fn go(&mut self, routing: &RoutingTable) -> Vec<Action> {
        if self.possible.is_empty() {
            self.possible = routing.closest_to(3, self.target, 50);
        }
        let n = match self.kind {
            SearchKind::Node => 1,
            _ => ALPHA_QUERY.min(self.possible.len()),
        };
        let first: Vec<(UInt128, Contact)> = self
            .possible
            .iter()
            .take(n)
            .map(|(d, c)| (*d, c.clone()))
            .collect();
        let mut out = Vec::new();
        for (d, c) in first {
            self.tried.insert(d, c.clone());
            out.extend(self.find_value(&c, false));
        }
        out
    }

    /// `SendFindValue`
    fn find_value(&mut self, c: &Contact, more: bool) -> Option<Action> {
        if self.stopping || c.version < 2 {
            return None;
        }
        let mut count = self.kind.request_count();
        if more {
            self.requested_more.insert(c.id);
            count = FindType::FIND_VALUE_MORE.into();
        }
        Some(Action::FindNodes {
            to: c.clone(),
            count,
        })
    }

    /// `PrepareToStop`: no more requests; the search ends 15 s from `now`.
    pub fn stop_at(&mut self, now: u64) {
        if !self.stopping {
            self.created = (now + 15).saturating_sub(LIFETIME);
            self.stopping = true;
        }
    }

    /// `CSearchManager::JumpStart` for this search: whether it is over,
    /// and what to send.
    pub fn tick(&mut self, now: u64) -> (bool, Vec<Action>) {
        let age_end = self.created + LIFETIME;
        match self.kind {
            SearchKind::Node => {
                if age_end < now {
                    return (true, Vec::new());
                }
            }
            SearchKind::NodeComplete => {
                if age_end < now
                    || (self.created + NODECOMP_LIFETIME < now && self.answers > NODECOMP_TOTAL)
                {
                    return (true, Vec::new());
                }
            }
            SearchKind::Keyword { .. } | SearchKind::Source { .. } => {
                if age_end < now {
                    return (true, Vec::new());
                }
                if self.answers > RESULTS_TOTAL || age_end - 20 < now {
                    self.stop_at(now);
                    return (false, Vec::new());
                }
            }
        }
        (false, self.jump_start(now))
    }

    /// `JumpStart`
    fn jump_start(&mut self, now: u64) -> Vec<Action> {
        if self.last_response + 3 > now {
            return Vec::new();
        }
        if self.possible.is_empty() {
            self.stop_at(now);
            return Vec::new();
        }
        let find_value: u8 = FindType::FindValue.into();
        let fv = find_value as usize;
        // Nobody of the first ones answered: ask one that did for more contacts.
        if self.requested_more.is_empty()
            && self.kind.request_count() == find_value
            && self.tried.len() >= 3 * fv
            && !self
                .tried
                .keys()
                .take(fv)
                .any(|d| self.responded.contains_key(d))
        {
            let next = self
                .tried
                .iter()
                .skip(fv)
                .find(|(d, _)| self.responded.contains_key(*d))
                .map(|(_, c)| c.clone());
            if let Some(c) = next {
                return self.find_value(&c, true).into_iter().collect();
            }
        }
        let mut out = Vec::new();
        while let Some((&d, c)) = self.possible.iter().next() {
            let c = c.clone();
            if let std::collections::btree_map::Entry::Vacant(e) = self.tried.entry(d) {
                e.insert(c.clone());
                out.extend(self.find_value(&c, false));
                break;
            }
            if self.responded.contains_key(&d) {
                out.extend(self.store_packet(d, &c));
            }
            self.possible.remove(&d);
        }
        out
    }

    /// `StorePacket`: the search request to a close node that answered.
    fn store_packet(&mut self, d: UInt128, from: &Contact) -> Option<Action> {
        if self.closest_found.is_none_or(|c| d < c) {
            self.closest_found = Some(d);
        }
        if d.chunk(0) > SEARCH_TOLERANCE && !is_lan_ip(from.ip) {
            return None;
        }
        // Kad1 nodes (before version 3) are not asked.
        if from.version < 3 {
            return None;
        }
        let a = match &self.kind {
            SearchKind::Keyword { terms } => Action::SearchKey {
                to: from.clone(),
                terms: terms.clone(),
            },
            SearchKind::Source { size } => Action::SearchSource {
                to: from.clone(),
                size: *size,
            },
            _ => return None,
        };
        self.requests += 1;
        Some(a)
    }

    /// `ProcessResponse`: contacts from a `KADEMLIA2_RES` for this target.
    pub fn process_response(
        &mut self,
        from_ip: u32,
        from_port: u16,
        sender_key: UdpKey,
        results: Vec<Contact>,
        now: u64,
    ) -> Vec<Action> {
        self.last_response = now;
        let from = self
            .tried
            .iter()
            .find(|(_, c)| c.ip == from_ip && c.udp_port == from_port)
            .map(|(d, c)| (*d, c.id));
        let more = from.is_some_and(|(_, id)| self.requested_more.contains(&id));
        let limit = self.kind.request_count() as usize;
        let more_limit = u8::from(FindType::FIND_VALUE_MORE) as usize;
        if results.len() > limit && !(more && results.len() <= more_limit) {
            return Vec::new();
        }
        if let Some((d, _)) = from {
            if let Some(c) = self.tried.get_mut(&d) {
                if c.udp_key.is_empty() && !sender_key.is_empty() {
                    c.udp_key = sender_key;
                }
            }
        }
        if self.kind == SearchKind::Node {
            self.answers += 1;
            self.possible.clear();
            return Vec::new();
        }
        let Some((from_d, _)) = from else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut closer = false;
        let mut ips: HashSet<u32> = HashSet::from([from_ip]);
        let mut subnets: HashMap<u32, u32> = HashMap::from([(from_ip & 0xFFFF_FF00, 1)]);
        for c in results {
            let d = c.id ^ self.target;
            if d < from_d {
                closer = true;
            }
            if self.possible.contains_key(&d) || self.tried.contains_key(&d) {
                continue;
            }
            // At most one per IP and two per /24 from one answer.
            if !ips.insert(c.ip) {
                continue;
            }
            let sn = c.ip & 0xFFFF_FF00;
            if !is_lan_ip(c.ip) {
                let n = subnets.entry(sn).or_insert(0);
                if *n >= 2 {
                    continue;
                }
                *n += 1;
            } else {
                subnets.insert(sn, 1);
            }
            self.possible.insert(d, c.clone());
            if d < from_d {
                let top = if self.best.len() < ALPHA_QUERY {
                    true
                } else {
                    let worst = *self.best.keys().next_back().expect("not empty");
                    if d < worst {
                        self.best.remove(&worst);
                        true
                    } else {
                        false
                    }
                };
                if top {
                    self.best.insert(d, c.clone());
                    self.tried.insert(d, c.clone());
                    out.extend(self.find_value(&c, false));
                }
            }
        }
        self.responded.insert(from_d, closer);
        if self.kind == SearchKind::NodeComplete {
            self.answers += 1;
        }
        out
    }

    /// `ProcessResult`: one answer of a `KADEMLIA2_SEARCH_RES`.
    pub fn process_result(&mut self, answer: UInt128, tags: &[Tag], from_ip: u32) -> Option<Found> {
        let found = match self.kind {
            SearchKind::Keyword { .. } => {
                keyword_result(answer, tags, from_ip).map(|k| Found::Keyword(Box::new(k)))
            }
            SearchKind::Source { .. } => source_result(answer, tags).map(Found::Source),
            _ => None,
        };
        if found.is_some() {
            self.answers += 1;
        }
        found
    }
}

fn str_of(t: &Tag) -> String {
    t.as_str().unwrap_or_default().to_owned()
}

/// `ProcessResultKeyword`: `None` without a name and a size.
pub fn keyword_result(answer: UInt128, tags: &[Tag], from_ip: u32) -> Option<KeywordResult> {
    let mut r = KeywordResult {
        hash: Md4Hash(answer.to_be_bytes()),
        name: String::new(),
        size: 0,
        file_type: String::new(),
        format: String::new(),
        artist: String::new(),
        album: String::new(),
        title: String::new(),
        length: 0,
        bitrate: 0,
        codec: String::new(),
        availability: 0,
        publish_info: 0,
        from: Ipv4Addr::from(from_ip),
    };
    let mut has_size = false;
    for t in tags {
        let n = &t.name;
        let int = t.as_int().unwrap_or(0);
        if n.is(tag::FILENAME) {
            r.name = str_of(t);
        } else if n.is(tag::FILESIZE) {
            if let Some(b) = t.as_bytes().filter(|b| b.len() == 8) {
                r.size = u64::from_le_bytes(b.try_into().ok()?);
                has_size = true;
            } else if let Some(v) = t.as_int() {
                r.size = v;
                has_size = true;
            }
        } else if n.is(tag::FILETYPE) {
            r.file_type = str_of(t);
        } else if n.is(tag::FILEFORMAT) {
            r.format = str_of(t);
        } else if n.is(tag::MEDIA_ARTIST) {
            r.artist = str_of(t);
        } else if n.is(tag::MEDIA_ALBUM) {
            r.album = str_of(t);
        } else if n.is(tag::MEDIA_TITLE) {
            r.title = str_of(t);
        } else if n.is(tag::MEDIA_LENGTH) {
            r.length = int as u32;
        } else if n.is(tag::MEDIA_BITRATE) {
            r.bitrate = int as u32;
        } else if n.is(tag::MEDIA_CODEC) {
            r.codec = str_of(t);
        } else if n.is(tag::SOURCES) {
            r.availability = if int > 65500 { 0 } else { int as u32 };
        } else if n.is(tag::PUBLISHINFO) {
            r.publish_info = int as u32;
        }
    }
    (!r.name.is_empty() && has_size).then_some(r)
}

/// `ProcessResultFile`: `None` for a type aMule ignores (2, or unknown).
pub fn source_result(answer: UInt128, tags: &[Tag]) -> Option<SourceResult> {
    let mut r = SourceResult {
        user_hash: Md4Hash(answer.to_be_bytes()),
        source_type: 0,
        ip: Ipv4Addr::UNSPECIFIED,
        tcp_port: 0,
        udp_port: 0,
        buddy_ip: Ipv4Addr::UNSPECIFIED,
        buddy_port: 0,
        crypt_options: 0,
    };
    for t in tags {
        let n = &t.name;
        let int = t.as_int().unwrap_or(0);
        if n.is(tag::SOURCETYPE) {
            r.source_type = int as u8;
        } else if n.is(tag::SOURCEIP) {
            r.ip = Ipv4Addr::from(int as u32);
        } else if n.is(tag::SOURCEPORT) {
            r.tcp_port = int as u16;
        } else if n.is(tag::SOURCEUPORT) {
            r.udp_port = int as u16;
        } else if n.is(tag::SERVERIP) {
            r.buddy_ip = Ipv4Addr::from(int as u32);
        } else if n.is(tag::SERVERPORT) {
            r.buddy_port = int as u16;
        } else if n.is(tag::ENCRYPTION) {
            r.crypt_options = int as u8;
        }
    }
    matches!(r.source_type, 1 | 3 | 4 | 5 | 6).then_some(r)
}

/// `KadGetKeywordHash`: the target of a keyword, MD4 of its UTF-8.
pub fn keyword_target(word: &str) -> UInt128 {
    use md4::{Digest, Md4};
    UInt128::from_be_bytes(Md4::digest(word.as_bytes()).into())
}
