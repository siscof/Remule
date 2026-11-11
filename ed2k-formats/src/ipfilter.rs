// SPDX-License-Identifier: GPL-2.0-or-later
//! IP filter lists: `ipfilter.dat`, `ipfilter_static.dat`, and the text
//! formats aMule's loader accepts in them.
//!
//! Port of `IPFilterScanner.l` (the line grammar), `CIPFilterTask` and
//! `CIPFilter` (IPFilter.cpp: precedence, threshold, lookup) and
//! `CIPFilterIPv6Ranges` (IPFilter.h).
//!
//! A line is one of:
//!
//! * PeerGuardian / eMule `.dat`: `<IPStart> - <IPEnd> , <level> , <description>`
//! * AntiP2P / `.p2p`: `<description> : <IPStart> - <IPEnd>` (level 0)
//! * native IPv6 CIDR: `<address>/<prefix> , <level> , <description>`
//! * a comment (`#`), a blank line, or a bad line (counted, then ignored).
//!
//! As in the flex scanner, a rule only wins if it covers the whole line, NUL
//! bytes read as `\x01`, and a line is cut at 64 KiB. A range whose level is
//! below the access-level threshold is blocked; where rules overlap, the one
//! loaded later wins (`ipfilter_static.dat` is loaded after `ipfilter.dat`).
//!
//! aMule never writes these files (apart from its placeholder comments), so
//! [`IpFilterFile`] keeps every line as read and [`IpFilterFile::write`] gives
//! the original bytes back.
//!
//! Not here: zip/gzip-packed lists (`UnpackArchive`, phase 10), and the
//! tunnelled-IPv4 check (6to4/Teredo) of `CIPFilter::IsFiltered`. The binary
//! `.p2b` format is not read by aMule either.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `kMaxLineLength`: bytes of a line the scanner looks at.
pub const MAX_LINE_LENGTH: usize = 64 * 1024;

/// Which syntax an IPv4 range came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    /// `start - end , level , description`
    PeerGuardian,
    /// `description : start - end`
    AntiP2P,
}

/// An IPv4 range rule. `start > end` is a valid line that aMule counts but
/// does not use (`AddIPRange` discards it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule4 {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub level: u8,
    /// As in the file, bytes decoded leniently; aMule uses it only in debug logs.
    pub description: String,
    pub syntax: Syntax,
}

/// An IPv6 CIDR rule; `network` already has its host bits cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule6 {
    pub network: Ipv6Addr,
    pub prefix: u8,
    pub level: u8,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineKind {
    Range4(Rule4),
    Range6(Rule6),
    Comment,
    /// Empty or whitespace only.
    Blank,
    /// Matches no rule, or has an out-of-range number (`yyip_Bad`).
    Bad,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The line as stored, without its `\n`.
    pub raw: Vec<u8>,
    pub kind: LineKind,
}

/// One filter file, line by line.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IpFilterFile {
    pub lines: Vec<Line>,
    /// Whether the last line ended with `\n`.
    pub final_newline: bool,
}

impl IpFilterFile {
    /// Read a filter file. Never fails: like aMule, unreadable lines are
    /// counted as bad and skipped.
    pub fn parse(bytes: &[u8]) -> IpFilterFile {
        let mut lines = Vec::new();
        let mut parts = bytes.split(|&b| b == b'\n').peekable();
        let final_newline = bytes.last() == Some(&b'\n');
        while let Some(raw) = parts.next() {
            let last = parts.peek().is_none();
            if last && final_newline {
                break; // the empty piece after the final '\n'
            }
            if last && raw.is_empty() {
                break; // empty file
            }
            let has_newline = !last;
            lines.push(Line {
                raw: raw.to_vec(),
                kind: classify(raw, has_newline),
            });
        }
        IpFilterFile {
            lines,
            final_newline,
        }
    }

    /// The original bytes.
    pub fn write(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, l) in self.lines.iter().enumerate() {
            out.extend_from_slice(&l.raw);
            if i + 1 < self.lines.len() || self.final_newline {
                out.push(b'\n');
            }
        }
        out
    }

    pub fn rules4(&self) -> impl Iterator<Item = &Rule4> {
        self.lines.iter().filter_map(|l| match &l.kind {
            LineKind::Range4(r) => Some(r),
            _ => None,
        })
    }

    pub fn rules6(&self) -> impl Iterator<Item = &Rule6> {
        self.lines.iter().filter_map(|l| match &l.kind {
            LineKind::Range6(r) => Some(r),
            _ => None,
        })
    }

    /// `yyip_Bad`: malformed lines, which aMule reports as discarded.
    pub fn bad_lines(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| l.kind == LineKind::Bad)
            .count()
    }

    /// The count aMule logs as "Loaded N IP-ranges": every range line.
    pub fn range_count(&self) -> usize {
        self.rules4().count() + self.rules6().count()
    }
}

// ---------------------------------------------------------------- scanner ---

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r')
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && is_ws(b[i]) {
        i += 1;
    }
    i
}

/// `{NO}`: 1-3 digits. The value is checked against 255 by the caller.
fn no(b: &[u8], i: usize) -> Option<(u32, usize)> {
    let mut j = i;
    let mut v = 0u32;
    while j < b.len() && j - i < 3 && b[j].is_ascii_digit() {
        v = v * 10 + u32::from(b[j] - b'0');
        j += 1;
    }
    (j > i).then_some((v, j))
}

/// `{IP}`: four `{NO}` joined by dots. The value is `None` if a part is over
/// 255 (`ScanIP` fails: a bad line).
fn ip(b: &[u8], mut i: usize) -> Option<(Option<u32>, usize)> {
    let mut v = 0u32;
    let mut ok = true;
    for part in 0..4 {
        if part > 0 {
            if b.get(i) != Some(&b'.') {
                return None;
            }
            i += 1;
        }
        let (n, j) = no(b, i)?;
        ok &= n <= 255;
        v = (v << 8) | (n & 0xFF);
        i = j;
    }
    Some((ok.then_some(v), i))
}

fn expect(b: &[u8], i: usize, c: u8) -> Option<usize> {
    (b.get(i) == Some(&c)).then_some(i + 1)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// What a syntactically matching rule line yields.
enum Match<T> {
    Rule(T),
    /// The line has the rule's shape but a number out of range.
    BadValue,
}

/// `{WS}{IP}{WS}-{WS}{IP}{WS},{WS}{NO}{WS},.*`
fn peerguardian(b: &[u8]) -> Option<Match<Rule4>> {
    let i = skip_ws(b, 0);
    let (start, i) = ip(b, i)?;
    let i = expect(b, skip_ws(b, i), b'-')?;
    let (end, i) = ip(b, skip_ws(b, i))?;
    let i = expect(b, skip_ws(b, i), b',')?;
    let (level, i) = no(b, skip_ws(b, i))?;
    let i = expect(b, skip_ws(b, i), b',')?;
    Some(match (start, end, level) {
        (Some(s), Some(e), l) if l <= 255 => Match::Rule(Rule4 {
            start: s.into(),
            end: e.into(),
            level: l as u8,
            description: text(&b[i..]),
            syntax: Syntax::PeerGuardian,
        }),
        _ => Match::BadValue,
    })
}

/// `^[^\n\x01]*:{WS}{IP}{WS}-{WS}{IP}{WS}`, matching the whole line.
fn antip2p(b: &[u8]) -> Option<Match<Rule4>> {
    // The IP part has no ':', so the description ends at the last one.
    let colon = b.iter().rposition(|&c| c == b':')?;
    let desc = &b[..colon];
    if desc.contains(&0x01) {
        return None;
    }
    let (start, i) = ip(b, skip_ws(b, colon + 1))?;
    let i = expect(b, skip_ws(b, i), b'-')?;
    let (end, i) = ip(b, skip_ws(b, i))?;
    if skip_ws(b, i) != b.len() {
        return None;
    }
    Some(match (start, end) {
        (Some(s), Some(e)) => Match::Rule(Rule4 {
            start: s.into(),
            end: e.into(),
            level: 0,
            description: text(desc),
            syntax: Syntax::AntiP2P,
        }),
        _ => Match::BadValue,
    })
}

/// `{WS}[0-9a-fA-F:]+"/"{NO}{WS},{WS}{NO}{WS},.*`
fn ipv6(b: &[u8]) -> Option<Match<Rule6>> {
    let a = skip_ws(b, 0);
    let mut i = a;
    while i < b.len() && (b[i].is_ascii_hexdigit() || b[i] == b':') {
        i += 1;
    }
    if i == a {
        return None;
    }
    let addr = &b[a..i];
    let i = expect(b, i, b'/')?;
    let (prefix, i) = no(b, i)?;
    let i = expect(b, skip_ws(b, i), b',')?;
    let (level, i) = no(b, skip_ws(b, i))?;
    let i = expect(b, skip_ws(b, i), b',')?;
    let parsed = std::str::from_utf8(addr)
        .ok()
        .and_then(|s| s.parse::<Ipv6Addr>().ok());
    Some(match parsed {
        Some(net) if net.to_ipv4_mapped().is_none() && prefix <= 128 && level <= 255 => {
            Match::Rule(Rule6 {
                network: truncate(net, prefix),
                prefix: prefix as u8,
                level: level as u8,
                description: text(&b[i..]),
            })
        }
        _ => Match::BadValue,
    })
}

/// Classify one line, as the flex rules do. `has_newline` matters only for a
/// whitespace-only last line, which `{WS}"\n"` cannot consume.
fn classify(raw: &[u8], has_newline: bool) -> LineKind {
    // ReadFilterInput: NUL reads as \x01, and a line is cut at 64 KiB.
    let b: Vec<u8> = raw
        .iter()
        .take(MAX_LINE_LENGTH)
        .map(|&c| if c == 0 { 0x01 } else { c })
        .collect();
    let b = &b[..];
    // Rule order breaks ties between rules that all cover the whole line.
    if let Some(m) = ipv6(b) {
        return match m {
            Match::Rule(r) => LineKind::Range6(r),
            Match::BadValue => LineKind::Bad,
        };
    }
    if let Some(m) = peerguardian(b) {
        return match m {
            Match::Rule(r) => LineKind::Range4(r),
            Match::BadValue => LineKind::Bad,
        };
    }
    if b.get(skip_ws(b, 0)) == Some(&b'#') {
        return LineKind::Comment;
    }
    if let Some(m) = antip2p(b) {
        return match m {
            Match::Rule(r) => LineKind::Range4(r),
            Match::BadValue => LineKind::Bad,
        };
    }
    if skip_ws(b, 0) == b.len() && (has_newline || b.is_empty()) {
        return LineKind::Blank;
    }
    LineKind::Bad
}

// ----------------------------------------------------------------- filter ---

fn truncate(a: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    let v = u128::from(a);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix.min(128))
    };
    Ipv6Addr::from(v & mask)
}

/// A resolved, disjoint range: the rule that wins over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range<T> {
    pub first: T,
    pub last: T,
    pub level: u8,
    pub description: String,
}

/// Resolve rules in load order into sorted, disjoint ranges where the newest
/// covering rule wins (CRangeMap's insert, `CIPFilterIPv6Ranges::Resolve`).
/// `rules` are (first, last, level, description) with first <= last.
fn resolve<T: Copy + Ord + Into<u128> + TryFrom<u128>>(
    rules: &[(T, T, u8, &str)],
    max: u128,
) -> Vec<Range<T>> {
    // Endpoints as u128, with an exclusive end one past `last`.
    let mut ends: Vec<(u128, usize, bool)> = Vec::with_capacity(rules.len() * 2);
    for (i, r) in rules.iter().enumerate() {
        ends.push((r.0.into(), i, true));
        let last: u128 = r.1.into();
        if last < max {
            ends.push((last + 1, i, false));
        }
    }
    ends.sort_by_key(|e| e.0);
    let mut active = BTreeSet::new();
    let mut out: Vec<Range<T>> = Vec::new();
    let mut i = 0;
    while i < ends.len() {
        let at = ends[i].0;
        while i < ends.len() && ends[i].0 == at {
            if ends[i].2 {
                active.insert(ends[i].1);
            } else {
                active.remove(&ends[i].1);
            }
            i += 1;
        }
        if let Some(&w) = active.iter().next_back() {
            let last = if i < ends.len() { ends[i].0 - 1 } else { max };
            let (Ok(first), Ok(last)) = (T::try_from(at), T::try_from(last)) else {
                continue;
            };
            let rule = &rules[w];
            // Merge with an adjacent range of the same level (CRangeMap merges equal entries).
            if let Some(prev) = out.last_mut() {
                if prev.level == rule.2 && prev.last.into().checked_add(1) == Some(at) {
                    prev.last = last;
                    continue;
                }
            }
            out.push(Range {
                first,
                last,
                level: rule.2,
                description: rule.3.to_owned(),
            });
        }
    }
    out
}

/// The loaded filter (`CIPFilter` after `CIPFilterTask`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpFilter {
    pub ranges4: Vec<Range<u32>>,
    pub ranges6: Vec<Range<u128>>,
    /// Input IPv6 rules per level (`m_levelCounts`), for [`IpFilter::ban_count`].
    levels6: Vec<u32>,
}

impl IpFilter {
    /// Build from files in load order: `ipfilter.dat` (or the system-wide
    /// one), then `ipfilter_static.dat`. Later rules win where they overlap.
    pub fn build(files: &[&IpFilterFile]) -> IpFilter {
        let rules4: Vec<_> = files
            .iter()
            .flat_map(|f| f.rules4())
            .filter(|r| r.start <= r.end) // AddIPRange discards reversed ranges
            .map(|r| {
                (
                    u32::from(r.start),
                    u32::from(r.end),
                    r.level,
                    r.description.as_str(),
                )
            })
            .collect();
        let mut levels6 = vec![0u32; 256];
        let rules6: Vec<_> = files
            .iter()
            .flat_map(|f| f.rules6())
            .map(|r| {
                levels6[usize::from(r.level)] += 1;
                let first = u128::from(r.network);
                let host = if r.prefix == 0 {
                    u128::MAX
                } else {
                    (1u128 << (128 - u32::from(r.prefix))).wrapping_sub(1)
                };
                (first, first | host, r.level, r.description.as_str())
            })
            .collect();
        IpFilter {
            ranges4: resolve(&rules4, u128::from(u32::MAX)),
            ranges6: resolve(&rules6, u128::MAX),
            levels6,
        }
    }

    fn find<T: Copy + Ord>(ranges: &[Range<T>], ip: T) -> Option<&Range<T>> {
        let i = ranges.partition_point(|r| r.first <= ip);
        let r = ranges.get(i.checked_sub(1)?)?;
        (ip <= r.last).then_some(r)
    }

    /// `IsFiltered(uint32)`: blocked if a range covering `ip` has a level
    /// below `access_level` (the `IPFilterLevel` preference).
    pub fn is_filtered_v4(&self, ip: Ipv4Addr, access_level: u32) -> bool {
        Self::find(&self.ranges4, u32::from(ip)).is_some_and(|r| u32::from(r.level) < access_level)
    }

    /// `CIPFilterIPv6Ranges::IsFiltered`. IPv4-mapped addresses are not IPv6
    /// here (use [`IpFilter::is_filtered`]), and the unspecified address `::`
    /// never matches.
    pub fn is_filtered_v6(&self, ip: Ipv6Addr, access_level: u32) -> bool {
        if ip.to_ipv4_mapped().is_some() || ip.is_unspecified() {
            return false;
        }
        Self::find(&self.ranges6, u128::from(ip)).is_some_and(|r| u32::from(r.level) < access_level)
    }

    /// `IsFiltered(CNetworkAddress)`: an IPv4-mapped IPv6 address is checked
    /// as IPv4.
    pub fn is_filtered(&self, ip: IpAddr, access_level: u32) -> bool {
        match ip {
            IpAddr::V4(v4) => self.is_filtered_v4(v4, access_level),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => self.is_filtered_v4(v4, access_level),
                None => self.is_filtered_v6(v6, access_level),
            },
        }
    }

    /// Blocked ranges at this access level: resolved IPv4 ranges plus input
    /// IPv6 rules (`BanCount`). aMule's IPv4 figure counts its compressed
    /// table entries, which can split a range; this counts whole ranges.
    pub fn ban_count(&self, access_level: u32) -> usize {
        let v4 = self
            .ranges4
            .iter()
            .filter(|r| u32::from(r.level) < access_level)
            .count();
        let v6: u32 = self
            .levels6
            .iter()
            .take(access_level.min(256) as usize)
            .sum();
        v4 + v6 as usize
    }
}

#[cfg(test)]
mod tests;
