// SPDX-License-Identifier: GPL-2.0-or-later
//! The graphs' history: its ranges, what a client is given from it, and
//! the reply's encoding.

use remule_ec::codes::*;
use remule_ec::{Packet, Tag};

use crate::graphs::{graphs_reply, History, Record, POINTS_PER_RANGE, RANGES};

fn at(t: f64) -> Record {
    Record {
        timestamp: t,
        kbps_down: 2.0,
        kbps_up: 0.5,
        connections: 3,
        kad_nodes: 10,
        kbytes_received: t * 2.0,
        ..Default::default()
    }
}

#[test]
fn the_history_keeps_its_ranges() {
    let mut h = History::new();
    let slots = RANGES * POINTS_PER_RANGE;
    assert_eq!(h.len(), slots);
    for t in 1..=20_000 {
        h.record(at(t as f64));
        assert_eq!(h.len(), slots);
    }
    let ts: Vec<f64> = h
        .records()
        .iter()
        .map(|r| r.timestamp)
        .filter(|&t| t > 0.0)
        .collect();
    // Oldest to newest, never back.
    assert!(ts.windows(2).all(|w| w[0] < w[1]), "out of order");
    assert_eq!(*ts.last().unwrap(), 20_000.0);
    // The newest range a second apart.
    let tail = &ts[ts.len() - POINTS_PER_RANGE..];
    assert!(tail.windows(2).all(|w| w[1] - w[0] == 1.0));
    // Going back, spacings are powers of two and never shrink.
    let gaps: Vec<f64> = ts.windows(2).map(|w| w[1] - w[0]).rev().collect();
    assert!(gaps
        .iter()
        .all(|g| [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0].contains(g)));
    assert!(
        gaps.windows(2).all(|w| w[1] >= w[0]),
        "spacing shrinks going back"
    );
    assert_eq!(
        gaps.iter().filter(|&&g| g == 1.0).count(),
        POINTS_PER_RANGE - 1 + 1
    );
    assert!(gaps.contains(&2.0) && gaps.contains(&4.0));
    // It goes back further than one record per slot would.
    assert!(ts[0] < 20_000.0 - slots as f64, "{}", ts[0]);
    // The Kad nodes, added up record by record.
    assert_eq!(h.records().last().unwrap().kad_nodes_total, 10 * 20_000);
}

#[test]
fn a_client_gets_the_points_since_its_last() {
    let mut h = History::new();
    for t in 1..=100 {
        h.record(at(t as f64));
    }
    // Ten points a second apart: the newest ten, oldest first.
    let (p, last) = h.for_gui(10, 1.0, 0.0);
    assert_eq!(last, 100.0);
    let ts: Vec<f64> = p.iter().map(|r| r.unwrap().timestamp).collect();
    assert_eq!(ts, (91..=100).map(f64::from).collect::<Vec<_>>());
    // Since 97: 97 to 100 (the one it has, then what is new).
    let (p, _) = h.for_gui(10, 1.0, 97.0);
    let ts: Vec<f64> = p.iter().map(|r| r.unwrap().timestamp).collect();
    assert_eq!(ts, [97.0, 98.0, 99.0, 100.0]);
    // Every 30 s, more points than there is history: back to the start of
    // time, which is marked.
    let (p, _) = h.for_gui(10, 30.0, 0.0);
    assert_eq!(p.first(), Some(&None));
    let ts: Vec<f64> = p[1..].iter().map(|r| r.unwrap().timestamp).collect();
    assert_eq!(ts, [10.0, 40.0, 70.0, 100.0]);
    // Nothing asked: nothing.
    assert!(h.for_gui(0, 1.0, 0.0).0.is_empty());
    assert!(h.for_gui(5, 0.0, 0.0).0.is_empty());
}

fn ask(width: u64, scale: u64, last: Option<f64>) -> Packet {
    let mut p = Packet::new(EC_OP_GET_STATSGRAPHS)
        .with(Tag::int(EC_TAG_STATSGRAPH_WIDTH, width))
        .with(Tag::int(EC_TAG_STATSGRAPH_SCALE, scale));
    if let Some(l) = last {
        p = p.with(Tag::double(EC_TAG_STATSGRAPH_LAST, l));
    }
    p
}

#[test]
fn the_reply_is_network_order_words_and_the_session_totals() {
    let mut h = History::new();
    for t in 1..=5 {
        h.record(at(t as f64));
    }
    let r = graphs_reply(&ask(2, 1, None), &h);
    assert_eq!(r.opcode, EC_OP_STATSGRAPHS);
    let data = &r.tag(EC_TAG_STATSGRAPH_DATA).unwrap().data;
    assert_eq!(data.len(), 2 * 16);
    let word = |i: usize| u32::from_be_bytes(data[4 * i..4 * i + 4].try_into().unwrap());
    // Download 2 KiB/s, upload 0.5 KiB/s, 3 connections, 10 Kad nodes.
    assert_eq!((word(0), word(1), word(2), word(3)), (2048, 512, 3, 10));
    assert_eq!(
        r.tag(EC_TAG_STATSGRAPH_DATA_CONN).unwrap().data.len(),
        2 * 8
    );
    // The totals at the newest point.
    assert_eq!(r.tag(EC_TAG_STATSGRAPH_SESSION_DL).unwrap().as_int(), 10);
    assert_eq!(r.tag(EC_TAG_STATSGRAPH_SESSION_KAD).unwrap().as_int(), 50);
    assert_eq!(
        r.tag(EC_TAG_STATSGRAPH_SESSION_TIMESPAN)
            .unwrap()
            .as_double(),
        5.0
    );
    assert_eq!(r.tag(EC_TAG_STATSGRAPH_DEPTH).unwrap().as_int(), 1800);
    assert_eq!(r.tag(EC_TAG_STATSGRAPH_LAST).unwrap().as_double(), 5.0);
    // From the last one sent.
    let r = graphs_reply(&ask(100, 1, Some(4.0)), &h);
    assert_eq!(r.tag(EC_TAG_STATSGRAPH_DATA).unwrap().data.len(), 2 * 16);
    // Refused, with aMule's words.
    let r = graphs_reply(&ask(2, 1, None).with_detail(EC_DETAIL_CMD), &h);
    assert_eq!(
        r.message().unwrap(),
        "Your client is not configured for this detail level."
    );
    let r = graphs_reply(&ask(0, 1, None), &h);
    assert_eq!(r.message().unwrap(), "No points for graph.");
    // A double survives the trip.
    assert_eq!(Tag::double(1, 12_345.678_9).as_double(), 12_345.678_9);
}
