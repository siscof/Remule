// SPDX-License-Identifier: GPL-2.0-or-later
//! Tests: search terms, the AICH list, the index (trust, names, answers,
//! limits, expiry, files), flood protection, and publishing then
//! searching on a simulated network.

use std::net::Ipv4Addr;

use ed2k_codec::{Tag, TagName, TagValue};
use ed2k_server::search::{encode_kad_search, SearchParams};
use ed2k_types::tags::kad as tag;
use ed2k_types::tags::FileType;
use ed2k_types::UInt128;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::aich::{self, AichList, ResultHash};
use crate::index::{Entry, Index, KeyEntry};
use crate::node::Event;
use crate::packets::{KadPacket, SizedTag};
use crate::search::{keyword_target, Found};
use crate::terms::{self, Term, SEARCH_BUDGET};
use crate::tests::Net;
use crate::tracking::{Admission, InTracker};

const NOW: u64 = 1_700_000_000;

fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from(Ipv4Addr::new(a, b, c, d))
}

fn s(n: &[u8], v: &str) -> Tag {
    Tag::new(TagName::Str(n.to_vec()), TagValue::String(v.into()))
}

fn i(n: &[u8], v: u64) -> Tag {
    Tag::new(TagName::Str(n.to_vec()), TagValue::int(v))
}

fn key_entry(name: &str, size: u64, from: u32, extra: Vec<Tag>) -> KeyEntry {
    let mut e = Entry {
        ip: from,
        udp_port: 4672,
        size,
        lifetime: NOW + 24 * 3600,
        tags: extra,
        ..Default::default()
    };
    e.set_name(name);
    KeyEntry::new(e)
}

fn kad_terms(p: SearchParams) -> Term {
    let (_, data) = encode_kad_search(&p).unwrap();
    terms::parse(&data).expect("parses")
}

// ---------------------------------------------------------------- terms

#[test]
fn terms_from_real_requests_match_as_amule() {
    let e = |name: &str, size: u64, ty: &str| {
        let mut x = Entry {
            size,
            tags: vec![s(tag::FILETYPE, ty)],
            ..Default::default()
        };
        x.set_name(name);
        x
    };
    let iso = e("Ubuntu-24.04-Desktop.ISO", 6_000_000_000, "Pro");
    let pdf = e("ubuntu manual.pdf", 2_000_000, "Doc");
    let m = |t: &Term, x: &Entry| terms::matches(t, x, &mut SEARCH_BUDGET.clone());

    // "ubuntu iso": keyword ubuntu, the term "iso" (a word in the name, any case).
    let t = kad_terms(SearchParams::new("ubuntu iso"));
    assert!(m(&t, &iso) && !m(&t, &pdf));
    // Words are cut at the invalid characters: "24.04" is "24" and "04".
    let t = kad_terms(SearchParams::new("ubuntu 24.04"));
    assert!(m(&t, &iso) && !m(&t, &pdf));
    // OR, NOT.
    let t = kad_terms(SearchParams::new("ubuntu iso OR manual"));
    assert!(m(&t, &iso) && m(&t, &pdf));
    let t = kad_terms(SearchParams::new("ubuntu NOT manual"));
    assert!(m(&t, &iso) && !m(&t, &pdf));
    // Sizes, the extension, the type.
    let mut p = SearchParams::new("ubuntu");
    p.min_size = 1 << 30;
    let t = kad_terms(p);
    assert!(m(&t, &iso) && !m(&t, &pdf));
    let mut p = SearchParams::new("ubuntu");
    p.extension = "PDF".into();
    let t = kad_terms(p);
    assert!(!m(&t, &iso) && m(&t, &pdf));
    let mut p = SearchParams::new("ubuntu");
    p.file_type = Some(FileType::Document);
    let t = kad_terms(p);
    assert!(!m(&t, &iso) && m(&t, &pdf));
}

#[test]
fn terms_are_bounded() {
    // 25 nested ANDs is too deep.
    let mut deep = [0u8, 0].repeat(25);
    for _ in 0..26 {
        deep.extend([1, 1, 0, b'a']);
    }
    assert_eq!(terms::parse(&deep), None);
    // Unknown operators and truncation.
    assert_eq!(terms::parse(&[0, 7]), None);
    assert_eq!(terms::parse(&[1, 5, 0, b'a']), None);
    assert_eq!(terms::parse(&[3, 1, 0, 0, 0, 9, 1, 0, 2]), None);
    // A match that cannot be paid for does not match.
    let mut e = Entry::default();
    e.set_name(&"x".repeat(1000));
    let t = Term::Words(vec!["y".into()]);
    let mut budget = 100;
    assert!(!terms::matches(&t, &e, &mut budget));
    assert_eq!(budget, 0);
}

// ---------------------------------------------------------------- AICH

#[test]
fn aich_votes() {
    let (a, b) = ([1u8; 20], [2u8; 20]);
    let mut l = AichList::default();
    assert_eq!(l.add_reference(&a), 0);
    assert_eq!(l.add_reference(&b), 1);
    assert_eq!(l.add_reference(&a), 0);
    l.drop_reference(1);
    assert_eq!(l.referenced_count(), 1);
    let tag = l.encode_result_tag();
    assert_eq!(tag.len(), 1 + 21);
    assert_eq!(&tag[..2], [1, 2]);
    let back = aich::decode_result_tag(&tag).unwrap();
    assert_eq!(
        back,
        [ResultHash {
            popularity: 2,
            hash: a
        }]
    );
    assert_eq!(l.compact(), [0, aich::INVALID_INDEX]);
    // A candidate needs two publishers and a third of those known.
    assert!(aich::select_candidate(&back, 2).is_some());
    assert!(aich::select_candidate(&back, 6).is_some());
    assert!(aich::select_candidate(&back, 8).is_none());
    assert!(aich::decode_result_tag(&[12]).is_none());
}

// ---------------------------------------------------------------- index

#[test]
fn trust_names_and_publishers() {
    let mut x = Index::new(UInt128::new(1));
    let (key, file) = (UInt128::new(10), UInt128::new(20));
    // Three publishers in three /24s: trust 10 + 10 + 10.
    for (n, (who, name)) in [
        (ip(1, 1, 1, 1), "a.iso"),
        (ip(2, 2, 2, 2), "A.iso"),
        (ip(3, 3, 3, 3), "b.iso"),
    ]
    .into_iter()
    .enumerate()
    {
        let (ok, load) =
            x.add_keyword(key, file, key_entry(name, 100, who, vec![]), NOW + n as u64);
        assert!(ok);
        // 1 for a new keyword, then the share of KADEMLIAMAXINDEX.
        assert_eq!(load, if n == 0 { 1 } else { 0 });
    }
    let res = x.keyword_results(key, None, 0, NOW);
    assert_eq!(res.len(), 1);
    let names: Vec<_> = res[0]
        .tags
        .iter()
        .filter(|t| t.name.is(tag::FILENAME))
        .collect();
    // "a.iso" was published twice (any case): the most popular name.
    assert_eq!(names[0].as_str(), Some("a.iso"));
    let info = res[0]
        .tags
        .iter()
        .find(|t| t.name.is(tag::PUBLISHINFO))
        .unwrap()
        .as_int()
        .unwrap();
    assert_eq!(info >> 24, 2, "two names");
    assert_eq!((info >> 16) & 0xFF, 3, "three publishers");
    assert_eq!(info & 0xFFFF, 3000, "trust 30.00");
    // The same publisher again soon: refreshed, not counted again.
    x.add_keyword(
        key,
        file,
        key_entry("a.iso", 100, ip(1, 1, 1, 1), vec![]),
        NOW + 10,
    );
    let res = x.keyword_results(key, None, 0, NOW + 10);
    let info = res[0]
        .tags
        .iter()
        .find(|t| t.name.is(tag::PUBLISHINFO))
        .unwrap()
        .as_int()
        .unwrap();
    assert_eq!((info >> 16) & 0xFF, 3);
    assert_eq!(x.stats().keywords, 1);
}

#[test]
fn trusted_entries_come_first_and_start_skips() {
    let mut x = Index::new(UInt128::new(1));
    let key = UInt128::new(10);
    // Eleven files from one /24: each publisher's subnet has 11 → trust 10/11 < 1.
    for n in 0..11u8 {
        x.add_keyword(
            key,
            UInt128::new(100 + n as u128),
            key_entry("spam.exe", 5, ip(9, 9, 9, n + 1), vec![]),
            NOW,
        );
    }
    // One from elsewhere: trust 10.
    x.add_keyword(
        key,
        UInt128::new(999),
        key_entry("good.iso", 5, ip(8, 8, 8, 8), vec![]),
        NOW,
    );
    // Trust values are kept 10 minutes: the first spam entries still count
    // as trusted until they are recomputed with the full /24.
    let later = NOW + 11 * 60;
    let res = x.keyword_results(key, None, 0, later);
    assert_eq!(res.len(), 12);
    assert_eq!(res[0].answer, UInt128::new(999));
    // Skip the first 5.
    let res = x.keyword_results(key, None, 5, later);
    assert_eq!(res.len(), 7);
    // Terms filter.
    let t = Term::Words(vec!["good".into()]);
    assert_eq!(x.keyword_results(key, Some(&t), 0, later).len(), 1);
}

#[test]
fn keyword_validation_and_sizes() {
    let mut x = Index::new(UInt128::new(1));
    let (key, file) = (UInt128::new(10), UInt128::new(20));
    // No size, no name, expired: refused.
    assert!(
        !x.add_keyword(key, file, key_entry("a", 0, ip(1, 1, 1, 1), vec![]), NOW)
            .0
    );
    assert!(
        !x.add_keyword(key, file, key_entry("", 5, ip(1, 1, 1, 1), vec![]), NOW)
            .0
    );
    assert!(
        !x.add_keyword(
            key,
            file,
            key_entry("a", 5, ip(1, 1, 1, 1), vec![]),
            NOW + 25 * 3600
        )
        .0
    );
    // Two sizes of one file are two entries.
    assert!(
        x.add_keyword(key, file, key_entry("a", 5, ip(1, 1, 1, 1), vec![]), NOW)
            .0
    );
    assert!(
        x.add_keyword(key, file, key_entry("a", 6, ip(1, 1, 1, 1), vec![]), NOW)
            .0
    );
    assert_eq!(x.stats().keywords, 2);
    assert_eq!(x.keyword_results(key, None, 0, NOW).len(), 2);
}

fn source(from: u32, tcp: u16) -> Entry {
    Entry {
        ip: from,
        tcp_port: tcp,
        udp_port: 4672,
        is_source: true,
        lifetime: NOW + 5 * 3600,
        tags: vec![
            i(tag::SOURCEIP, from as u64),
            i(tag::SOURCETYPE, 1),
            i(tag::SOURCEPORT, tcp as u64),
            i(tag::SOURCEUPORT, 4672),
        ],
        ..Default::default()
    }
}

#[test]
fn sources_replace_and_evict() {
    let mut x = Index::new(UInt128::new(1));
    let file = UInt128::new(7);
    assert_eq!(
        x.add_source(file, UInt128::new(1), source(ip(1, 1, 1, 1), 4662), NOW),
        (true, 1)
    );
    // The same IP and port: replaced.
    assert!(
        x.add_source(file, UInt128::new(1), source(ip(1, 1, 1, 1), 4662), NOW)
            .0
    );
    assert_eq!(x.stats().sources, 1);
    // Up to 1001 sources, then the oldest makes way.
    for n in 0..1001u32 {
        x.add_source(
            file,
            UInt128::new(n as u128 + 2),
            source(ip(20, (n >> 8) as u8, n as u8, 1), 1),
            NOW,
        );
    }
    let (ok, load) = x.add_source(file, UInt128::new(5000), source(ip(30, 0, 0, 1), 1), NOW);
    assert!(ok && load == 100);
    let res = x.source_results(file, 0, 0, NOW);
    assert_eq!(res.len(), 300);
    assert_eq!(res[0].answer, UInt128::new(5000));
    // Missing ports: refused.
    assert!(
        !x.add_source(file, UInt128::new(1), source(ip(1, 1, 1, 1), 0), NOW)
            .0
    );
}

#[test]
fn expiry_and_trust_follow_the_publishers() {
    let mut x = Index::new(UInt128::new(1));
    let key = UInt128::new(10);
    x.add_keyword(
        key,
        UInt128::new(1),
        key_entry("a", 5, ip(1, 1, 1, 1), vec![]),
        NOW,
    );
    x.add_source(
        UInt128::new(3),
        UInt128::new(4),
        source(ip(1, 1, 1, 2), 9),
        NOW,
    );
    x.expire(NOW + 6 * 3600);
    assert_eq!((x.stats().keywords, x.stats().sources), (1, 0));
    x.expire(NOW + 25 * 3600);
    assert_eq!(x.stats().keywords, 0);
    assert!(x.keyword_results(key, None, 0, NOW + 25 * 3600).is_empty());
}

#[test]
fn index_files_round_trip() {
    let me = UInt128::new(77);
    let mut x = Index::new(me);
    let key = UInt128::new(10);
    let mut e = key_entry(
        "a.iso",
        1 << 33,
        ip(1, 1, 1, 1),
        vec![s(tag::FILETYPE, "Pro")],
    );
    e.set_published_aich(&[5; 20]);
    x.add_keyword(key, UInt128::new(1), e, NOW);
    x.add_keyword(
        key,
        UInt128::new(1),
        key_entry(
            "b.iso",
            1 << 33,
            ip(2, 2, 2, 2),
            vec![s(tag::FILETYPE, "Pro")],
        ),
        NOW,
    );
    x.add_source(
        UInt128::new(3),
        UInt128::new(4),
        source(ip(1, 1, 1, 2), 9),
        NOW,
    );
    x.add_load(UInt128::new(6), (NOW + 100) as u32, NOW);
    let (k, src, l) = (
        x.write_keyword_file(NOW),
        x.write_source_file(NOW),
        x.write_load_file(NOW),
    );

    let mut y = Index::new(me);
    y.read_keyword_file(&k, NOW + 1).unwrap();
    y.read_source_file(&src, NOW + 1).unwrap();
    y.read_load_file(&l, NOW + 1).unwrap();
    assert_eq!(y.stats(), x.stats());
    assert_eq!(
        y.keyword_results(key, None, 0, NOW + 1),
        x.keyword_results(key, None, 0, NOW + 1)
    );
    assert_eq!(
        y.source_results(UInt128::new(3), 0, 0, NOW + 1),
        x.source_results(UInt128::new(3), 0, 0, NOW + 1)
    );
    assert!(!y.may_store(UInt128::new(6), NOW + 1));
    // Another node's keyword file, or an old one, is ignored.
    let mut z = Index::new(UInt128::new(78));
    z.read_keyword_file(&k, NOW).unwrap();
    assert_eq!(z.stats().keywords, 0);
    let mut z = Index::new(me);
    z.read_keyword_file(&k, NOW + 25 * 3600).unwrap();
    assert_eq!(z.stats().keywords, 0);
    // A newer version is refused.
    let mut bad = k.clone();
    bad[0] = 5;
    assert!(Index::new(me).read_keyword_file(&bad, NOW).is_err());
}

// ---------------------------------------------------------------- flood protection

#[test]
fn flood_protection() {
    let mut t = InTracker::default();
    let hello: u8 = ed2k_types::kad::v2::Opcode::HelloReq.into();
    let a = ip(1, 2, 3, 4);
    // Three hellos a minute.
    for _ in 0..3 {
        assert_eq!(t.admit(a, hello, false, 1000), Admission::Allowed);
    }
    assert_eq!(t.admit(a, hello, false, 1000), Admission::Drop);
    // One drains every 20 s.
    assert_eq!(t.admit(a, hello, false, 1000 + 20_000), Admission::Drop);
    assert_eq!(t.admit(a, hello, false, 1000 + 80_000), Admission::Allowed);
    // Unlimited opcodes pass.
    assert_eq!(t.admit(a, 0x99, false, 0), Admission::Allowed);
    // Keyed floods beyond 5× the rate: banned.
    let b = ip(5, 6, 7, 8);
    let mut last = Admission::Allowed;
    for _ in 0..16 {
        last = t.admit(b, hello, true, 5000);
    }
    assert_eq!(last, Admission::MassiveFlood);
    // Unkeyed floods are only dropped.
    let c = ip(9, 9, 9, 9);
    for _ in 0..30 {
        last = t.admit(c, hello, false, 5000);
    }
    assert_eq!(last, Admission::Drop);
}

// ---------------------------------------------------------------- the network

#[test]
fn a_published_keyword_is_found_by_another_node() {
    let mut rng = StdRng::seed_from_u64(7);
    let target = keyword_target("remule");
    let mut ids: Vec<UInt128> = (0..40).map(|_| UInt128::new(rng.gen())).collect();
    ids[39] = target ^ UInt128::new(99); // the node for "remule"
    let mut net = Net::new(&ids, &mut rng);
    for a in 0..net.nodes.len() {
        for _ in 0..8 {
            let b = rng.gen_range(0..ids.len());
            if a == b {
                continue;
            }
            let addr = net.addrs[b];
            let mut v = true;
            net.nodes[a].routing.add(
                ids[b],
                u32::from(*addr.ip()),
                addr.port(),
                4662,
                8,
                Default::default(),
                &mut v,
                false,
                false,
                1000,
            );
        }
    }
    net.run(200);
    // Node 5 publishes a file under "remule" to node 39 (as aMule's store search would).
    let file = UInt128::from_be_bytes([0x42; 16]);
    let publish = KadPacket::PublishKeyReq {
        key: target,
        files: vec![(
            file,
            vec![
                SizedTag::new(s(tag::FILENAME, "remule-0.1.tar.gz")),
                SizedTag::new(i(tag::FILESIZE, 123_456)),
                SizedTag::new(s(tag::FILETYPE, "Arc")),
            ],
        )],
    };
    let now = net.now;
    let to39 = net.addrs[39];
    let d = net.nodes[5].send_to_test(&publish, to39, 8, Some(ids[39]), now);
    net.post(5, vec![d]);
    net.deliver();
    assert_eq!(net.nodes[39].stats.publishes_stored, 1);
    assert_eq!(net.nodes[39].index.stats().keywords, 1);

    // Node 0 searches; node 39 answers from its index.
    let (sid, _, out) = net.nodes[0]
        .search_keyword(&SearchParams::new("remule tar"), now)
        .unwrap();
    net.post(0, out);
    let mut events = net.deliver();
    events.extend(net.run(60));
    let found: Vec<_> = events
        .iter()
        .filter_map(|(n, e)| match e {
            Event::Found {
                search,
                found: Found::Keyword(k),
            } if *n == 0 && *search == sid => Some(k.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1, "{events:?}");
    let k = &found[0];
    assert_eq!(
        (k.name.as_str(), k.size, k.file_type.as_str()),
        ("remule-0.1.tar.gz", 123_456, "Arc")
    );
    // One publisher, one name, trust 10.
    assert_eq!(k.publish_info, (1 << 24) | (1 << 16) | 1000);
    assert!(net.nodes[39].stats.searches_answered >= 1);
}
