// SPDX-License-Identifier: GPL-2.0-or-later
//! The statistics graphs' history (`CStatistics::RecordHistory`,
//! `GetHistoryForGui`), and the `EC_OP_GET_STATSGRAPHS` reply
//! (`GetStatsGraphs`) `amulegui` polls for its graphs.
//!
//! One record a second, kept in a fixed number of slots: the newest 1800
//! a second apart, the 1800 before 2 s apart, then 4 s, and so on over 7
//! ranges, so a long history costs memory in the log of its length. Each
//! second one slot is recycled: the one whose range is due, chosen by the
//! highest bit of a counter that just turned on.

use remule_ec::codes::*;
use remule_ec::{Packet, Tag};

/// `GetPointsPerRange`.
pub const POINTS_PER_RANGE: usize = 1800;
/// `nHistRanges`.
pub const RANGES: usize = 7;

/// `HistoryRecord`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Record {
    pub kbytes_sent: f64,
    pub kbytes_received: f64,
    pub kbps_up: f32,
    pub kbps_down: f32,
    /// Seconds of uptime.
    pub timestamp: f64,
    pub downloads: u16,
    pub uploads: u16,
    pub connections: u16,
    pub kad_nodes: u16,
    /// The Kad node counts of every record so far, added up.
    pub kad_nodes_total: u64,
}

/// `listHR` and its recycling positions.
#[derive(Debug, Clone)]
pub struct History {
    list: Vec<Record>,
    /// `aposRecycle`: where each range's next recycled slot is.
    recycle: [usize; RANGES],
    clock: u32,
    kad_nodes_total: u64,
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

impl History {
    /// `CStatistics()`: every slot an empty record.
    pub fn new() -> Self {
        let mut list = Vec::with_capacity(RANGES * POINTS_PER_RANGE);
        let mut recycle = [0; RANGES];
        for i in (0..RANGES).rev() {
            list.push(Record::default());
            recycle[i] = list.len() - 1;
            list.extend(std::iter::repeat_n(Record::default(), POINTS_PER_RANGE - 1));
        }
        History {
            list,
            recycle,
            clock: 0,
            kad_nodes_total: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The records, oldest first.
    pub fn records(&self) -> &[Record] {
        &self.list
    }

    /// Take the slot at `i` out, keeping the positions after it right;
    /// the index of what came after it.
    fn erase(&mut self, i: usize) -> usize {
        self.list.remove(i);
        for p in &mut self.recycle {
            if *p > i {
                *p -= 1;
            }
        }
        i
    }

    /// `RecordHistory`: recycle a slot to the newest end and fill it. The
    /// Kad total is kept here; `r.kad_nodes_total` is ignored.
    pub fn record(&mut self, mut r: Record) {
        let prev = self.clock;
        self.clock = self.clock.wrapping_add(1);
        let bits = (prev ^ self.clock) & self.clock;
        let mask = (1u32 << (RANGES - 1)) - 1;
        if bits <= mask {
            // The highest bit just turned on names the range.
            let k = (31 - bits.leading_zeros()) as usize;
            let at = self.recycle[k];
            self.list.push(self.list[at]);
            let next = self.erase(at);
            // Skip one, which moves it into the next range up.
            self.recycle[k] = next + 1;
        } else {
            // The oldest: there is no range above it.
            let at = self.recycle[RANGES - 1];
            self.list.push(self.list[at]);
            let next = self.erase(at);
            self.recycle[RANGES - 1] = next;
        }
        self.kad_nodes_total += u64::from(r.kad_nodes);
        r.kad_nodes_total = self.kad_nodes_total;
        *self.list.last_mut().expect("never empty") = r;
    }

    /// `GetHistoryForGui`: up to `points` records `step` seconds apart,
    /// newest first going back, stopping at `start` (the newest timestamp
    /// the client has; negative reads as 0) or at the start of time (then a
    /// `None` marks the gap). Returned oldest first, with the newest
    /// timestamp, the client's next `start`.
    pub fn for_gui(&self, points: usize, step: f64, start: f64) -> (Vec<Option<Record>>, f64) {
        let start = start.max(0.0);
        if step == 0.0 || points == 0 {
            return (Vec::new(), start);
        }
        let last = self.list.last().map_or(0.0, |r| r.timestamp);
        let mut target = last;
        let mut picked: Vec<Option<Record>> = Vec::new();
        let mut pos = self.list.len();
        while pos > 0 {
            let r = &self.list[pos - 1];
            if r.timestamp > target {
                pos -= 1;
                continue;
            }
            picked.push(Some(*r));
            if picked.len() == points || r.timestamp <= start {
                break;
            }
            target -= step;
            if target <= 0.0 {
                picked.push(None);
                break;
            }
        }
        picked.reverse();
        (picked, last)
    }
}

/// `GetStatsGraphs`: the points since the client's last, as network-order
/// words (download and upload bytes per second, connections, Kad nodes;
/// then uploads and downloads), with the session totals at the newest.
pub fn graphs_reply(req: &Packet, h: &History) -> Packet {
    let failed = |m: &str| Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, m));
    let detail = req
        .tag(EC_TAG_DETAIL_LEVEL)
        .map_or(EC_DETAIL_FULL, |t| t.as_int() as u8);
    if detail != EC_DETAIL_FULL && detail != EC_DETAIL_WEB {
        return failed("Your client is not configured for this detail level.");
    }
    let start = req.tag(EC_TAG_STATSGRAPH_LAST).map_or(0.0, Tag::as_double);
    let scale = req.tag(EC_TAG_STATSGRAPH_SCALE).map_or(0, Tag::as_int) as u16;
    let width = req.tag(EC_TAG_STATSGRAPH_WIDTH).map_or(0, Tag::as_int) as u16;
    let (points, last) = h.for_gui(width.into(), scale.into(), start);
    if points.is_empty() {
        return failed("No points for graph.");
    }
    let mut graph = Vec::with_capacity(points.len() * 16);
    let mut conn = Vec::with_capacity(points.len() * 8);
    for p in &points {
        let r = p.unwrap_or_default();
        for v in [
            (r.kbps_down * 1024.0) as u32,
            (r.kbps_up * 1024.0) as u32,
            u32::from(r.connections),
            u32::from(r.kad_nodes),
        ] {
            graph.extend_from_slice(&v.to_be_bytes());
        }
        for v in [u32::from(r.uploads), u32::from(r.downloads)] {
            conn.extend_from_slice(&v.to_be_bytes());
        }
    }
    // The newest record, never the gap marker.
    let newest = points.iter().rev().find_map(|p| *p).unwrap_or_default();
    Packet::new(EC_OP_STATSGRAPHS)
        .with(Tag::custom(EC_TAG_STATSGRAPH_DATA, graph))
        .with(Tag::custom(EC_TAG_STATSGRAPH_DATA_CONN, conn))
        .with(Tag::int(
            EC_TAG_STATSGRAPH_SESSION_DL,
            newest.kbytes_received as u64,
        ))
        .with(Tag::int(
            EC_TAG_STATSGRAPH_SESSION_UL,
            newest.kbytes_sent as u64,
        ))
        .with(Tag::int(
            EC_TAG_STATSGRAPH_SESSION_KAD,
            newest.kad_nodes_total,
        ))
        .with(Tag::double(
            EC_TAG_STATSGRAPH_SESSION_TIMESPAN,
            newest.timestamp,
        ))
        .with(Tag::int(EC_TAG_STATSGRAPH_DEPTH, POINTS_PER_RANGE as u64))
        .with(Tag::double(EC_TAG_STATSGRAPH_LAST, last))
}
