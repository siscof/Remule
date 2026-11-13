// SPDX-License-Identifier: GPL-2.0-or-later
//! What a Kad node stores for others (`CIndexed`, `CEntry`, `CKeyEntry`):
//! keyword entries (files under a keyword), sources (of a file), notes
//! (comments on a file) and the load of keywords we publish.
//!
//! A keyword entry remembers who published it (up to 100 publishers, by
//! IP) and gets a trust value from how spread out they are: 10 points per
//! publisher, divided by how many publishers in the whole index share its
//! /24. Searches get trusted entries (trust ≥ 1) first. Names compete by
//! popularity: a name published again by another publisher gains a point.
//!
//! All times are seconds of the Unix clock, as in the index files.

use std::collections::{BTreeMap, HashMap, VecDeque};

use ed2k_codec::io::{LenField, StrEncoding};
use ed2k_codec::tag::{read_kad_list, write_kad_list};
use ed2k_codec::{Reader, Tag, TagName, TagValue, Writer};
use ed2k_types::kad::{
    KADEMLIAMAXENTRIES, KADEMLIAMAXINDEX, KADEMLIAMAXNOTES, KADEMLIAMAXNOTESPERFILE,
    KADEMLIAMAXSOURCEPERFILE, KADEMLIAMAXSOURCES, KADEMLIAREPUBLISHTIMEK, KADEMLIAREPUBLISHTIMES,
};
use ed2k_types::tags::kad as tag;
use ed2k_types::UInt128;

use crate::aich::{AichHash, AichList, INVALID_INDEX};
use crate::packets::SearchAnswer;
use crate::terms::{self, Matchable, Term, SEARCH_BUDGET};

/// Most answers to one search request (`maxResults`).
pub const MAX_RESULTS: usize = 300;
/// Most notes in one answer.
pub const MAX_NOTE_RESULTS: usize = 150;
/// Most names kept for one keyword entry.
pub const MAX_FILENAMES: usize = 100;
/// Most publishers kept for one keyword entry.
pub const MAX_PUBLISHERS: usize = 100;
/// `PUBLISHPOINTSSPERSUBNET`
pub const POINTS_PER_SUBNET: f64 = 10.0;
/// How often a trust value is recomputed.
pub const TRUST_RECALC: u64 = 10 * 60;
/// How often the index is cleaned (`Clean`).
pub const CLEAN_INTERVAL: u64 = 30 * 60;

fn secs(d: std::time::Duration) -> u64 {
    d.as_secs()
}

fn str_tag(name: &[u8], s: &str) -> Tag {
    Tag::new(TagName::Str(name.to_vec()), TagValue::String(s.to_owned()))
}

fn int_tag(name: &[u8], v: u64) -> Tag {
    Tag::new(TagName::Str(name.to_vec()), TagValue::int(v))
}

/// A name and how many publishers gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    pub name: String,
    pub popularity: u32,
}

/// `CEntry`
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Entry {
    /// The publisher (aMule-order IP).
    pub ip: u32,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub key_id: UInt128,
    pub source_id: UInt128,
    pub size: u64,
    /// When it expires.
    pub lifetime: u64,
    /// `m_bSource`: a source entry carrying a `TAG_SOURCETYPE`.
    pub is_source: bool,
    /// Bytes of tags we keep without knowing them (sources only).
    pub extra_tag_bytes: u32,
    pub names: Vec<FileName>,
    pub tags: Vec<Tag>,
}

impl Entry {
    /// `AddTag`: result-only tags are not stored.
    pub fn add_tag(&mut self, t: Tag) {
        if t.name.is(tag::PUBLISHINFO) || t.name.is(tag::KADAICHHASHRESULT) {
            return;
        }
        self.tags.push(t);
    }

    /// `SetFileName`
    pub fn set_name(&mut self, name: &str) {
        if !name.is_empty() {
            self.names = vec![FileName {
                name: name.to_owned(),
                popularity: 1,
            }];
        }
    }

    /// `GetCommonFileName`: the most popular name (the first of equals).
    pub fn common_name(&self) -> &str {
        let mut best: Option<&FileName> = None;
        for n in &self.names {
            if best.is_none_or(|b| n.popularity > b.popularity) {
                best = Some(n);
            }
        }
        best.map(|n| n.name.as_str()).unwrap_or("")
    }

    /// `GetTagCount`: the tags, plus the name and the size.
    pub fn tag_count(&self) -> u32 {
        self.tags.len() as u32 + (self.size != 0) as u32 + (!self.common_name().is_empty()) as u32
    }

    /// `WriteTagListInc`: name, size and the tags, at most 255 in all with
    /// `extra` more to come.
    pub fn tag_list(&self, extra: u32) -> Vec<Tag> {
        let count = (self.tag_count() + extra).min(255);
        let mut budget = count.saturating_sub(extra) as usize;
        let mut out = Vec::new();
        let name = self.common_name();
        if !name.is_empty() && budget > 0 {
            out.push(str_tag(tag::FILENAME, name));
            budget -= 1;
        }
        if self.size != 0 && budget > 0 {
            out.push(int_tag(tag::FILESIZE, self.size));
            budget -= 1;
        }
        out.extend(self.tags.iter().take(budget).cloned());
        out
    }
}

impl Matchable for Entry {
    fn name(&self) -> &str {
        self.common_name()
    }

    /// `GetIntTagValue` with the virtual size tag.
    fn int_tag(&self, name: &[u8]) -> Option<u64> {
        self.tags
            .iter()
            .find(|t| t.as_int().is_some() && t.name.is(name))
            .and_then(Tag::as_int)
            .or_else(|| (name == tag::FILESIZE).then_some(self.size))
    }

    fn str_tag(&self, name: &[u8]) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.name.is(name) && t.as_str().is_some())
            .and_then(Tag::as_str)
    }

    fn tag_count(&self) -> usize {
        self.tags.len()
    }
}

/// A publisher of a keyword entry (`sPublishingIP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publisher {
    pub ip: u32,
    pub last_publish: u64,
    /// Its AICH hash's slot, or [`INVALID_INDEX`].
    pub aich: u16,
}

/// `CKeyEntry`
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KeyEntry {
    pub entry: Entry,
    /// `None` until merged into the index.
    publishers: Option<VecDeque<Publisher>>,
    aich: AichList,
    trust: f64,
    last_trust: Option<u64>,
}

/// Publishers per /24 across the index.
type Tracking = HashMap<u32, u32>;

fn track(map: &mut Tracking, ip: u32, up: bool) {
    let k = ip & 0xFFFF_FF00;
    let n = map.entry(k).or_insert(0);
    if up {
        *n += 1;
    } else {
        *n = n.saturating_sub(1);
    }
    if *n == 0 {
        map.remove(&k);
    }
}

impl KeyEntry {
    pub fn new(entry: Entry) -> Self {
        KeyEntry {
            entry,
            ..Default::default()
        }
    }

    /// `SetPublishedAICHHash`
    pub fn set_published_aich(&mut self, h: &AichHash) {
        self.aich.add_reference(h);
    }

    pub fn aich_count(&self) -> u16 {
        self.aich.slot_count()
    }

    pub fn publishers(&self) -> usize {
        self.publishers.as_ref().map_or(0, VecDeque::len)
    }

    /// The tracked publishers go away with the entry (the destructor).
    fn release(&mut self, map: &mut Tracking) {
        if let Some(p) = self.publishers.take() {
            for x in p {
                track(map, x.ip, false);
            }
        }
    }

    /// `ReCalculateTrustValue`
    fn recalc_trust(&mut self, map: &Tracking, now: u64) {
        self.last_trust = Some(now);
        self.trust = self
            .publishers
            .iter()
            .flatten()
            .filter_map(|p| map.get(&(p.ip & 0xFFFF_FF00)))
            .filter(|&&n| n > 0)
            .map(|&n| POINTS_PER_SUBNET / n as f64)
            .sum();
    }

    /// `GetTrustValue`
    pub fn trust(&mut self, map: &Tracking, now: u64) -> f64 {
        if self
            .last_trust
            .is_none_or(|t| now.saturating_sub(t) > TRUST_RECALC)
        {
            self.recalc_trust(map, now);
        }
        self.trust
    }

    /// `CleanUpTrackedPublishers`: those not heard from in 24 h go.
    fn clean_publishers(&mut self, map: &mut Tracking, now: u64) {
        let Some(list) = self.publishers.as_mut() else {
            return;
        };
        while let Some(p) = list.front() {
            if now.saturating_sub(p.last_publish) > secs(KADEMLIAREPUBLISHTIMEK) {
                track(map, p.ip, false);
                self.aich.drop_reference(p.aich);
                list.pop_front();
            } else {
                break;
            }
        }
    }

    /// `MergeIPsAndFilenames`: take over the publishers, names and AICH
    /// votes of the entry this one replaces (or start them).
    fn merge(&mut self, from: Option<&mut KeyEntry>, map: &mut Tracking, now: u64) {
        if self.publishers.is_some() {
            return;
        }
        let new_aich = self.aich.hash_at(0).copied();
        self.aich = AichList::default();
        let mut refresh = false;
        match from.filter(|f| f.publishers.is_some()) {
            None => self.publishers = Some(VecDeque::new()),
            Some(old) => {
                self.aich = std::mem::take(&mut old.aich);
                let mut list = old.publishers.take().expect("checked");
                let mut fast_refresh = false;
                if let Some(i) = list.iter().position(|p| p.ip == self.entry.ip) {
                    refresh = true;
                    let mut p = list.remove(i).expect("found");
                    // Refreshed sooner than expected: the name does not gain a point.
                    if now.saturating_sub(p.last_publish)
                        < secs(KADEMLIAREPUBLISHTIMES).saturating_sub(3600)
                    {
                        fast_refresh = true;
                    }
                    p.last_publish = now;
                    match new_aich {
                        Some(h) => {
                            if p.aich == INVALID_INDEX {
                                p.aich = self.aich.add_reference(&h);
                            } else if self.aich.hash_at(p.aich) != Some(&h) {
                                self.aich.drop_reference(p.aich);
                                p.aich = self.aich.add_reference(&h);
                            }
                        }
                        None => {
                            if p.aich != INVALID_INDEX {
                                self.aich.drop_reference(p.aich);
                                p.aich = INVALID_INDEX;
                            }
                        }
                    }
                    list.push_back(p);
                }
                self.publishers = Some(list);
                self.trust = old.trust;
                self.last_trust = old.last_trust;
                let current = if self.entry.names.is_empty() {
                    FileName {
                        name: String::new(),
                        popularity: 0,
                    }
                } else {
                    self.entry.names.remove(0)
                };
                let names = &mut self.entry.names;
                let push = |names: &mut Vec<FileName>, n: FileName| {
                    if names.len() < MAX_FILENAMES {
                        names.push(n);
                    } else if let Some(w) = names.iter_mut().min_by_key(|x| x.popularity) {
                        if n.popularity > w.popularity {
                            *w = n;
                        }
                    }
                };
                let mut duplicate = false;
                for mut n in std::mem::take(&mut old.entry.names) {
                    if n.name.is_empty() {
                        continue;
                    }
                    if n.name.to_lowercase() == current.name.to_lowercase() {
                        duplicate = true;
                        if !fast_refresh {
                            n.popularity += 1;
                        }
                    }
                    push(names, n);
                }
                if !duplicate && !current.name.is_empty() {
                    push(names, current);
                }
            }
        }
        let list = self.publishers.as_mut().expect("set above");
        if !refresh {
            let aich = match new_aich {
                Some(h) => self.aich.add_reference(&h),
                None => INVALID_INDEX,
            };
            list.push_back(Publisher {
                ip: self.entry.ip,
                last_publish: now,
                aich,
            });
            track(map, self.entry.ip, true);
            if list.len() > MAX_PUBLISHERS {
                let p = list.pop_front().expect("over 100");
                self.aich.drop_reference(p.aich);
                track(map, p.ip, false);
            }
            self.recalc_trust(map, now);
        }
        let remap = self.aich.compact();
        for p in self.publishers.iter_mut().flatten() {
            p.aich = remap.get(p.aich as usize).copied().unwrap_or(INVALID_INDEX);
        }
    }

    /// `WriteTagListWithPublishInfo`: the tags, `TAG_PUBLISHINFO` (names
    /// << 24 | publishers << 16 | trust × 100) and the AICH votes.
    fn result_tags(&mut self, map: &Tracking, now: u64) -> Vec<Tag> {
        let Some(n_pub) = self
            .publishers
            .as_ref()
            .map(VecDeque::len)
            .filter(|&n| n > 0)
        else {
            return self.entry.tag_list(0);
        };
        let aich = self.aich.encode_result_tag();
        let mut tags = self.entry.tag_list(if aich.is_empty() { 1 } else { 2 });
        // (uint16_t)(trust * 100): truncated as the C++ conversion does.
        let trust = (self.trust(map, now) * 100.0) as u32 as u16 as u32;
        let names = (self.entry.names.len() & 0xFF) as u32;
        let publishers = (n_pub & 0xFF) as u32;
        tags.push(int_tag(
            tag::PUBLISHINFO,
            ((names << 24) | (publishers << 16) | trust) as u64,
        ));
        if !aich.is_empty() {
            tags.push(Tag::new(
                TagName::Str(tag::KADAICHHASHRESULT.to_vec()),
                TagValue::Bsob(aich),
            ));
        }
        tags
    }
}

/// One source (or note) of a key: its ID and its entries, newest first.
#[derive(Debug, Clone, PartialEq)]
struct Slot {
    source_id: UInt128,
    entries: VecDeque<Entry>,
}

/// The counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IndexStats {
    pub keywords: u32,
    pub sources: u32,
    pub notes: u32,
    pub loads: u32,
    pub keyword_keys: usize,
    pub source_keys: usize,
}

/// The index.
#[derive(Debug, Clone, Default)]
pub struct Index {
    kad_id: UInt128,
    keywords: BTreeMap<UInt128, BTreeMap<UInt128, VecDeque<KeyEntry>>>,
    sources: BTreeMap<UInt128, VecDeque<Slot>>,
    notes: BTreeMap<UInt128, VecDeque<Slot>>,
    loads: BTreeMap<UInt128, u32>,
    tracking: Tracking,
    total_keywords: u32,
    total_sources: u32,
    total_notes: u32,
    total_loads: u32,
    extra_tag_bytes: u32,
    next_clean: u64,
}

impl Index {
    pub fn new(kad_id: UInt128) -> Self {
        Index {
            kad_id,
            ..Default::default()
        }
    }

    pub fn stats(&self) -> IndexStats {
        IndexStats {
            keywords: self.total_keywords,
            sources: self.total_sources,
            notes: self.total_notes,
            loads: self.total_loads,
            keyword_keys: self.keywords.len(),
            source_keys: self.sources.len(),
        }
    }

    /// `HasRoomForExtraTags`
    pub fn has_room_for_extra_tags(&self, bytes: u32) -> bool {
        self.extra_tag_bytes + bytes <= ed2k_types::kad::KADEMLIAMAXEXTRATAGBYTES as u32
    }

    // ------------------------------------------------------------ adding

    /// `AddKeyword`: whether it was stored, and the load to report (0..=100).
    pub fn add_keyword(
        &mut self,
        key: UInt128,
        source: UInt128,
        mut e: KeyEntry,
        now: u64,
    ) -> (bool, u8) {
        e.entry.key_id = key;
        e.entry.source_id = source;
        let reject = |s: &mut Self, mut e: KeyEntry, load: u8| {
            e.release(&mut s.tracking);
            (false, load)
        };
        if self.total_keywords > KADEMLIAMAXENTRIES {
            return reject(self, e, 100);
        }
        if e.entry.size == 0
            || e.entry.common_name().is_empty()
            || e.entry.tag_count() == 0
            || e.entry.lifetime < now
        {
            return reject(self, e, 0);
        }
        let max = KADEMLIAMAXINDEX as usize;
        let Some(by_source) = self.keywords.get_mut(&key) else {
            e.merge(None, &mut self.tracking, now);
            self.keywords
                .insert(key, BTreeMap::from([(source, VecDeque::from([e]))]));
            self.total_keywords += 1;
            return (true, 1);
        };
        let total = by_source.len();
        if total > max {
            return reject(self, e, 100);
        }
        let load = ((total * 100) / max) as u8;
        match by_source.get_mut(&source) {
            Some(list) if !list.is_empty() => {
                if total > max - 5000 {
                    return reject(self, e, 100);
                }
                // An entry of the same size is replaced (and merged).
                let mut old = list
                    .iter()
                    .position(|x| x.entry.size == e.entry.size)
                    .and_then(|i| list.remove(i));
                e.merge(old.as_mut(), &mut self.tracking, now);
                match old {
                    Some(mut o) => o.release(&mut self.tracking),
                    None => self.total_keywords += 1, // another size of the same file
                }
                list.push_front(e);
                (true, load)
            }
            Some(list) => {
                self.total_keywords += 1;
                e.merge(None, &mut self.tracking, now);
                list.push_front(e);
                (true, load)
            }
            None => {
                e.merge(None, &mut self.tracking, now);
                by_source.insert(source, VecDeque::from([e]));
                self.total_keywords += 1;
                (true, load)
            }
        }
    }

    /// `AddSources`
    pub fn add_source(
        &mut self,
        key: UInt128,
        source: UInt128,
        mut e: Entry,
        now: u64,
    ) -> (bool, u8) {
        e.key_id = key;
        e.source_id = source;
        if e.ip == 0 || e.tcp_port == 0 || e.udp_port == 0 || e.tag_count() == 0 || e.lifetime < now
        {
            return (false, 0);
        }
        let extra = e.extra_tag_bytes;
        let full = self.total_sources >= KADEMLIAMAXSOURCES;
        let r = add_slot(
            &mut self.sources,
            key,
            source,
            e,
            KADEMLIAMAXSOURCEPERFILE as usize,
            full,
            |old, new| {
                old.ip == new.ip && (old.tcp_port == new.tcp_port || old.udp_port == new.udp_port)
            },
        );
        if r.counted {
            self.total_sources += 1;
        }
        if r.stored {
            self.extra_tag_bytes += extra;
        }
        (r.stored, r.load)
    }

    /// `AddNotes`
    pub fn add_note(
        &mut self,
        key: UInt128,
        source: UInt128,
        mut e: Entry,
        now: u64,
    ) -> (bool, u8) {
        e.key_id = key;
        e.source_id = source;
        if e.ip == 0 || e.tag_count() == 0 || e.lifetime < now {
            return (false, 0);
        }
        let full = self.total_notes >= KADEMLIAMAXNOTES;
        let r = add_slot(
            &mut self.notes,
            key,
            source,
            e,
            KADEMLIAMAXNOTESPERFILE as usize,
            full,
            |old, new| old.ip == new.ip || old.source_id == new.source_id,
        );
        if r.counted {
            self.total_notes += 1;
        }
        (r.stored, r.load)
    }

    /// `AddLoad`
    pub fn add_load(&mut self, key: UInt128, time: u32, now: u64) -> bool {
        if now > time as u64 {
            return false;
        }
        if let Some(t) = self.loads.get_mut(&key) {
            *t = (*t).max(time);
            return false;
        }
        self.loads.insert(key, time);
        self.total_loads += 1;
        true
    }

    /// `SendStoreRequest`: may we publish to `key` again?
    pub fn may_store(&mut self, key: UInt128, now: u64) -> bool {
        match self.loads.get(&key) {
            Some(&t) if (t as u64) < now => {
                self.loads.remove(&key);
                self.total_loads -= 1;
                true
            }
            Some(_) => false,
            None => true,
        }
    }

    // ------------------------------------------------------------ expiry

    /// `Expire`: drop what expired, and recount.
    pub fn expire(&mut self, now: u64) {
        let mut k_total = 0;
        let tracking = &mut self.tracking;
        self.keywords.retain(|_, by_source| {
            by_source.retain(|_, list| {
                list.retain_mut(|e| {
                    if e.entry.lifetime < now {
                        e.release(tracking);
                        false
                    } else {
                        e.clean_publishers(tracking, now);
                        k_total += 1;
                        true
                    }
                });
                !list.is_empty()
            });
            !by_source.is_empty()
        });
        let mut extra = 0;
        let s_total = clean_slots(&mut self.sources, now, &mut extra);
        self.extra_tag_bytes = extra;
        let n_total = clean_slots(&mut self.notes, now, &mut extra);
        self.total_keywords = k_total;
        self.total_sources = s_total;
        self.total_notes = n_total;
    }

    /// `Clean`: [`Index::expire`] every 30 minutes.
    pub fn clean(&mut self, now: u64) {
        if self.next_clean > now {
            return;
        }
        self.expire(now);
        self.next_clean = now + CLEAN_INTERVAL;
    }

    // ------------------------------------------------------------ answers

    /// `SendValidKeywordResult`: up to 300 answers after skipping `start`,
    /// trusted entries first.
    pub fn keyword_results(
        &mut self,
        key: UInt128,
        terms: Option<&Term>,
        start: u16,
        now: u64,
    ) -> Vec<SearchAnswer> {
        let mut out = Vec::new();
        let tracking = &self.tracking;
        if let Some(by_source) = self.keywords.get_mut(&key) {
            let mut count = -(start as i64);
            let mut budget = SEARCH_BUDGET;
            'passes: for only_trusted in [true, false] {
                for list in by_source.values_mut() {
                    for e in list.iter_mut() {
                        if budget == 0 {
                            break;
                        }
                        let trusted = e.trust(tracking, now) >= 1.0;
                        if only_trusted != trusted {
                            continue;
                        }
                        if let Some(t) = terms {
                            if !terms::matches(t, &e.entry, &mut budget) {
                                continue;
                            }
                        }
                        if count < 0 {
                            count += 1;
                        } else if (count as usize) < MAX_RESULTS {
                            count += 1;
                            out.push(SearchAnswer {
                                answer: e.entry.source_id,
                                tags: e.result_tags(tracking, now),
                            });
                        } else {
                            break 'passes;
                        }
                    }
                }
            }
        }
        self.clean(now);
        out
    }

    /// `SendValidSourceResult`
    pub fn source_results(
        &mut self,
        key: UInt128,
        start: u16,
        size: u64,
        now: u64,
    ) -> Vec<SearchAnswer> {
        let out = slot_results(self.sources.get(&key), start, size, MAX_RESULTS);
        self.clean(now);
        out
    }

    /// `SendValidNoteResult`
    pub fn note_results(&mut self, key: UInt128, size: u64, now: u64) -> Vec<SearchAnswer> {
        let out = slot_results(self.notes.get(&key), 0, size, MAX_NOTE_RESULTS);
        self.clean(now);
        out
    }

    // ------------------------------------------------------------ files

    /// `load_index.dat`: `<1 4><now 4><count 4>(<key 16><time 4>)*`.
    pub fn write_load_file(&self, now: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(1).u32(now as u32).u32(self.loads.len() as u32);
        for (k, t) in &self.loads {
            w.uint128(*k).u32(*t);
        }
        w.into_bytes()
    }

    /// `src_index.dat`, version 2, valid for 5 hours.
    pub fn write_source_file(&self, now: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(2)
            .u32((now + secs(KADEMLIAREPUBLISHTIMES)) as u32)
            .u32(self.sources.len() as u32);
        for (k, slots) in &self.sources {
            w.uint128(*k).u32(slots.len() as u32);
            for s in slots {
                w.uint128(s.source_id).u32(s.entries.len() as u32);
                for e in &s.entries {
                    w.u32(e.lifetime as u32);
                    let _ = write_kad_list(&mut w, &e.tag_list(0));
                }
            }
        }
        w.into_bytes()
    }

    /// `key_index.dat`, version 4 (with AICH votes), valid for 24 hours.
    pub fn write_keyword_file(&self, now: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(4)
            .u32((now + secs(KADEMLIAREPUBLISHTIMEK)) as u32)
            .uint128(self.kad_id)
            .u32(self.keywords.len() as u32);
        for (k, by_source) in &self.keywords {
            w.uint128(*k).u32(by_source.len() as u32);
            for (src, list) in by_source {
                w.uint128(*src).u32(list.len() as u32);
                for e in list {
                    w.u32(e.entry.lifetime as u32);
                    write_tracking(&mut w, e);
                    let _ = write_kad_list(&mut w, &e.entry.tag_list(0));
                }
            }
        }
        w.into_bytes()
    }

    /// `ReadLoadFile`
    pub fn read_load_file(&mut self, bytes: &[u8], now: u64) -> Result<(), FileError> {
        let mut r = Reader::new(bytes);
        if r.u32()? >= 2 {
            return Err(FileError::Version);
        }
        r.u32()?;
        for _ in 0..r.u32()? {
            let k = r.uint128()?;
            let t = r.u32()?;
            self.add_load(k, t, now);
        }
        Ok(())
    }

    /// `ReadSourceFile`
    pub fn read_source_file(&mut self, bytes: &[u8], now: u64) -> Result<(), FileError> {
        let mut r = Reader::new(bytes);
        if r.u32()? >= 3 {
            return Err(FileError::Version);
        }
        if (r.u32()? as u64) <= now {
            return Ok(()); // out of date
        }
        for _ in 0..r.u32()? {
            let key = r.uint128()?;
            for _ in 0..r.u32()? {
                let source = r.uint128()?;
                for _ in 0..r.u32()? {
                    let mut e = Entry {
                        is_source: true,
                        lifetime: r.u32()? as u64,
                        key_id: key,
                        source_id: source,
                        ..Default::default()
                    };
                    for t in read_kad_list(&mut r, true)? {
                        address_tag(&mut e, &t);
                        e.add_tag(t);
                    }
                    self.add_source(key, source, e, now);
                }
            }
        }
        Ok(())
    }

    /// `ReadKeywordFile` (versions up to 4; another node's file is ignored).
    pub fn read_keyword_file(&mut self, bytes: &[u8], now: u64) -> Result<(), FileError> {
        let mut r = Reader::new(bytes);
        let version = r.u32()?;
        if version >= 5 {
            return Err(FileError::Version);
        }
        if (r.u32()? as u64) <= now || r.uint128()? != self.kad_id {
            return Ok(());
        }
        for _ in 0..r.u32()? {
            let key = r.uint128()?;
            for _ in 0..r.u32()? {
                let source = r.uint128()?;
                for _ in 0..r.u32()? {
                    let mut e = KeyEntry::new(Entry {
                        key_id: key,
                        source_id: source,
                        lifetime: r.u32()? as u64,
                        ..Default::default()
                    });
                    if version >= 3 {
                        read_tracking(&mut r, &mut e, version >= 4, &mut self.tracking, now)?;
                    }
                    for t in read_kad_list(&mut r, true)? {
                        if t.name.is(tag::FILENAME) {
                            if e.entry.common_name().is_empty() {
                                e.entry.set_name(t.as_str().unwrap_or_default());
                            }
                        } else if t.name.is(tag::FILESIZE) {
                            e.entry.size = size_of(&t);
                        } else {
                            address_tag(&mut e.entry, &t);
                            e.entry.add_tag(t);
                        }
                    }
                    self.add_keyword(key, source, e, now);
                }
            }
        }
        Ok(())
    }
}

/// A bad index file.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("unsupported index file version")]
    Version,
    #[error(transparent)]
    Data(#[from] ed2k_codec::Error),
    #[error(transparent)]
    Tag(#[from] ed2k_codec::TagError),
}

/// A `TAG_FILESIZE`: an integer, or 8 bytes in a BSOB.
pub fn size_of(t: &Tag) -> u64 {
    match &t.value {
        TagValue::Bsob(b) if b.len() == 8 => u64::from_le_bytes(b[..].try_into().expect("8")),
        _ => t.as_int().unwrap_or(0),
    }
}

/// `ReadAddressTag`
fn address_tag(e: &mut Entry, t: &Tag) {
    let v = t.as_int().unwrap_or(0);
    if t.name.is(tag::SOURCEIP) {
        e.ip = v as u32;
    } else if t.name.is(tag::SOURCEPORT) {
        e.tcp_port = v as u16;
    } else if t.name.is(tag::SOURCEUPORT) {
        e.udp_port = v as u16;
    }
}

fn write_tracking(w: &mut Writer, e: &KeyEntry) {
    let map = e.aich.compaction_map();
    w.u16(e.aich.referenced_count());
    for (h, _) in e.aich.referenced() {
        w.bytes(h);
    }
    w.u32(e.entry.names.len() as u32);
    for n in &e.entry.names {
        w.string(&n.name, StrEncoding::Utf8, LenField::U16)
            .u32(n.popularity);
    }
    let pubs = e.publishers.as_ref();
    w.u32(pubs.map_or(0, VecDeque::len) as u32);
    for p in pubs.into_iter().flatten() {
        let idx = map.get(p.aich as usize).copied().unwrap_or(INVALID_INDEX);
        w.u32(p.ip).u32(p.last_publish as u32).u16(idx);
    }
}

/// `ReadPublishTrackingDataFromFile`
fn read_tracking(
    r: &mut Reader<'_>,
    e: &mut KeyEntry,
    with_aich: bool,
    map: &mut Tracking,
    now: u64,
) -> Result<(), FileError> {
    let mut hashes = Vec::new();
    if with_aich {
        for _ in 0..r.u16()? {
            hashes.push(r.array::<20>()?);
        }
    }
    let n = r.u32()?;
    let mut names = Vec::with_capacity((n as usize).min(r.remaining() / 6));
    for _ in 0..n {
        let name = r.string(true, LenField::U16, false)?;
        let popularity = r.u32()?;
        names.push(FileName { name, popularity });
    }
    e.entry.names = names;
    let n = r.u32()?;
    let mut pubs = VecDeque::with_capacity((n as usize).min(r.remaining() / 8));
    for _ in 0..n {
        let ip = r.u32()?;
        let last_publish = r.u32()? as u64;
        let mut aich = INVALID_INDEX;
        if with_aich {
            let i = r.u16()?;
            if let Some(h) = hashes.get(i as usize) {
                aich = e.aich.add_reference(h);
            }
        }
        track(map, ip, true);
        pubs.push_back(Publisher {
            ip,
            last_publish,
            aich,
        });
    }
    e.publishers = Some(pubs);
    e.recalc_trust(map, now);
    Ok(())
}

struct SlotAdd {
    stored: bool,
    counted: bool,
    load: u8,
}

/// The common part of `AddSources` and `AddNotes`.
fn add_slot(
    map: &mut BTreeMap<UInt128, VecDeque<Slot>>,
    key: UInt128,
    source: UInt128,
    e: Entry,
    max_per_key: usize,
    full: bool,
    same: impl Fn(&Entry, &Entry) -> bool,
) -> SlotAdd {
    let Some(slots) = map.get_mut(&key) else {
        if full {
            return SlotAdd {
                stored: false,
                counted: false,
                load: 100,
            };
        }
        map.insert(
            key,
            VecDeque::from([Slot {
                source_id: source,
                entries: VecDeque::from([e]),
            }]),
        );
        return SlotAdd {
            stored: true,
            counted: true,
            load: 1,
        };
    };
    let size = slots.len();
    let load = ((size * 100) / max_per_key) as u8;
    for s in slots.iter_mut() {
        match s.entries.front() {
            Some(front) if same(front, &e) => {
                // The same publisher again: its entry is replaced.
                s.entries.pop_front();
                s.entries.push_front(e);
                return SlotAdd {
                    stored: true,
                    counted: false,
                    load,
                };
            }
            Some(_) => {}
            None => {
                s.entries.push_front(e);
                return SlotAdd {
                    stored: true,
                    counted: false,
                    load,
                };
            }
        }
    }
    if size > max_per_key {
        // Full: the oldest makes way.
        let mut s = slots.pop_back().expect("not empty");
        s.entries.pop_back();
        s.source_id = source;
        s.entries.push_front(e);
        slots.push_front(s);
        return SlotAdd {
            stored: true,
            counted: false,
            load: 100,
        };
    }
    if full {
        return SlotAdd {
            stored: false,
            counted: false,
            load: 100,
        };
    }
    slots.push_front(Slot {
        source_id: source,
        entries: VecDeque::from([e]),
    });
    SlotAdd {
        stored: true,
        counted: true,
        load,
    }
}

/// `CleanSources`: the entries left.
fn clean_slots(map: &mut BTreeMap<UInt128, VecDeque<Slot>>, now: u64, extra: &mut u32) -> u32 {
    let mut total = 0;
    map.retain(|_, slots| {
        slots.retain_mut(|s| {
            s.entries.retain(|e| {
                if e.lifetime < now {
                    false
                } else {
                    total += 1;
                    *extra += e.extra_tag_bytes;
                    true
                }
            });
            !s.entries.is_empty()
        });
        !slots.is_empty()
    });
    total
}

fn slot_results(
    slots: Option<&VecDeque<Slot>>,
    start: u16,
    size: u64,
    max: usize,
) -> Vec<SearchAnswer> {
    let mut out = Vec::new();
    let mut count = -(start as i64);
    for s in slots.into_iter().flatten() {
        let Some(e) = s.entries.front() else { continue };
        if count < 0 {
            count += 1;
        } else if (count as usize) < max {
            if size == 0 || e.size == 0 || e.size == size {
                out.push(SearchAnswer {
                    answer: e.source_id,
                    tags: e.tag_list(0),
                });
                count += 1;
            }
        } else {
            break;
        }
    }
    out
}
