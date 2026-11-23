// SPDX-License-Identifier: GPL-2.0-or-later
//! Tests: contacts, the routing table's rules, packets, results, and a
//! simulated network of nodes exchanging real (obfuscated) datagrams.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};

use ed2k_codec::{Tag, TagName, TagValue};
use ed2k_crypto::udp::{self, OwnKeys};
use ed2k_server::search::SearchParams;
use ed2k_types::tags::kad as tag;
use ed2k_types::{Md4Hash, UInt128};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::contact::{is_good_ip_port, is_lan_ip, Contact, UdpKey};
use crate::node::{Config, Datagram, Event, Kad};
use crate::packets::{ContactRecord, Hello, KadPacket, SearchAnswer};
use crate::routing::{RoutingTable, K};
use crate::search::{keyword_result, keyword_target, source_result, Found};

fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from(Ipv4Addr::new(a, b, c, d))
}

// ---------------------------------------------------------------- contacts

#[test]
fn ip_rules_are_amules() {
    assert!(is_good_ip_port(ip(8, 8, 8, 8), 4672, true));
    assert!(!is_good_ip_port(ip(8, 8, 8, 8), 0, true));
    for bad in [
        ip(0, 1, 2, 3),
        ip(127, 0, 0, 1),
        ip(39, 1, 1, 1),
        ip(169, 254, 1, 1),
        ip(192, 0, 2, 7),
        ip(224, 0, 0, 1),
        ip(250, 1, 1, 1),
    ] {
        assert!(
            !is_good_ip_port(bad, 4672, false),
            "{}",
            Ipv4Addr::from(bad)
        );
    }
    // 14/8 and 24/8 are ordinary.
    assert!(is_good_ip_port(ip(14, 1, 1, 1), 1, true));
    assert!(
        is_lan_ip(ip(192, 168, 1, 1))
            && is_lan_ip(ip(172, 31, 0, 1))
            && !is_lan_ip(ip(172, 32, 0, 1))
    );
    assert!(!is_good_ip_port(ip(10, 0, 0, 1), 1, true));
    assert!(is_good_ip_port(ip(10, 0, 0, 1), 1, false));
}

#[test]
fn contact_types() {
    let mut c = Contact::new(
        UInt128::new(1),
        ip(8, 8, 8, 8),
        1,
        1,
        8,
        UdpKey::default(),
        true,
        1000,
    );
    assert_eq!(c.kind, 3);
    c.update_type(1000);
    assert_eq!((c.kind, c.expires), (2, 1000 + 3600));
    c.checking_type(1005); // within 10 s of the last change: no
    assert_eq!(c.kind, 2);
    c.checking_type(1020);
    assert_eq!((c.kind, c.expires), (3, 1020 + 120));
    c.update_type(1000 + 2 * 3600);
    assert_eq!((c.kind, c.expires), (0, 1000 + 4 * 3600));
}

// ---------------------------------------------------------------- routing

/// Contacts at distinct /24s, IDs at a given distance from `me`.
fn add_n(t: &mut RoutingTable, n: u32, dist: impl Fn(u32) -> u128, now: u64) -> usize {
    let mut added = 0;
    for i in 0..n {
        let id = UInt128::new(dist(i)) ^ t.me();
        let mut v = true;
        added += t.add(
            id,
            ip(20, (i >> 8) as u8, i as u8, 1),
            4672,
            4662,
            8,
            UdpKey::default(),
            &mut v,
            false,
            false,
            now,
        ) as usize;
    }
    added
}

/// Distances spread over all bits (a multiplicative hash of i).
fn spread(i: u32) -> u128 {
    (i as u128 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835)
}

#[test]
fn bins_split_near_us_and_fill_far_away() {
    let me = UInt128::new(0x1234_5678_9ABC_DEF0_1234_5678_9ABC_DEF0);
    let mut t = RoutingTable::new(me, 1000);
    // Far contacts (top bit set): the far half of the root holds K at
    // level 1, but splits go on down to KBASE.
    let added = add_n(&mut t, 200, |i| (1u128 << 127) | spread(i), 1000);
    assert!(added > K && added < 200, "{added}");
    // Near contacts: the near side keeps splitting.
    let near = add_n(&mut t, 200, |i| (i as u128 + 1) << 20, 1000);
    assert!(near > 3 * K, "{near}");
    assert_eq!(t.len(), added + near);
    assert!(t.depth() >= 4);
    // Closest-to is ordered by distance to the target and only verified ones.
    let target = me ^ UInt128::new(5 << 20);
    let c = t.closest_to(3, target, 5);
    assert_eq!(c.len(), 5);
    assert!(c.keys().zip(c.keys().skip(1)).all(|(a, b)| a < b));
    let closest = t.contacts().map(|x| x.id ^ target).min().unwrap();
    assert_eq!(*c.keys().next().unwrap(), closest);
}

#[test]
fn ip_and_subnet_limits() {
    let me = UInt128::new(7);
    let mut t = RoutingTable::new(me, 0);
    let mut v = true;
    let k = UdpKey::default();
    assert!(t.add(
        UInt128::new(1 << 120),
        ip(20, 1, 1, 1),
        1,
        1,
        8,
        k,
        &mut v,
        false,
        false,
        0
    ));
    // Same IP, another ID: one per IP.
    assert!(!t.add(
        UInt128::new(2 << 120),
        ip(20, 1, 1, 1),
        2,
        1,
        8,
        k,
        &mut v,
        false,
        false,
        0
    ));
    // Two per /24 in a bin.
    assert!(t.add(
        UInt128::new(3 << 120),
        ip(20, 1, 1, 2),
        1,
        1,
        8,
        k,
        &mut v,
        false,
        false,
        0
    ));
    assert!(!t.add(
        UInt128::new(4 << 120),
        ip(20, 1, 1, 3),
        1,
        1,
        8,
        k,
        &mut v,
        false,
        false,
        0
    ));
    // LAN addresses are exempt (when not filtered).
    t.filter_lan = false;
    for i in 0..4 {
        assert!(t.add(
            UInt128::new((10 + i) << 120),
            ip(192, 168, 0, 10 + i as u8),
            1,
            1,
            8,
            k,
            &mut v,
            false,
            false,
            0
        ));
    }
    // Ourselves never.
    assert!(!t.add(me, ip(30, 1, 1, 1), 1, 1, 8, k, &mut v, false, false, 0));
    // DNS port without obfuscation.
    assert!(!t.add(
        UInt128::new(99 << 120),
        ip(30, 1, 1, 1),
        53,
        1,
        5,
        k,
        &mut v,
        false,
        false,
        0
    ));
}

#[test]
fn updates_need_the_same_key() {
    let mut t = RoutingTable::new(UInt128::new(7), 0);
    let id = UInt128::new(1 << 120);
    let mut v = false;
    t.add(
        id,
        ip(20, 1, 1, 1),
        1,
        1,
        8,
        UdpKey::new(55, 0),
        &mut v,
        false,
        false,
        0,
    );
    // A wrong key: no update (not even its IP).
    assert!(!t.add(
        id,
        ip(20, 2, 2, 2),
        1,
        1,
        8,
        UdpKey::new(56, 0),
        &mut v,
        true,
        false,
        10
    ));
    assert_eq!(t.get(id).unwrap().ip, ip(20, 1, 1, 1));
    // The right key: updated, and alive.
    let mut v = true;
    assert!(t.add(
        id,
        ip(20, 2, 2, 2),
        7,
        1,
        8,
        UdpKey::new(55, 0),
        &mut v,
        true,
        false,
        10
    ));
    let c = t.get(id).unwrap();
    assert_eq!(
        (c.ip, c.udp_port, c.kind, c.ip_verified),
        (ip(20, 2, 2, 2), 7, 2, true)
    );
}

#[test]
fn small_timer_checks_the_oldest_and_drops_the_dead() {
    let mut t = RoutingTable::new(UInt128::new(7), 0);
    add_n(&mut t, 3, |i| (i as u128 + 1) << 125, 0);
    // First pass: expiries are set to now, nothing is due yet.
    assert!(t.small_timer(100).is_empty());
    // A minute on, the oldest gets a hello and is "being checked" (type 4).
    let hello = t.small_timer(160);
    assert_eq!(hello.len(), 1);
    assert_eq!(t.get(hello[0].id).unwrap().kind, 4);
    // It never answers: once its 2 minutes are up it is dropped.
    for now in [220, 280, 340] {
        t.small_timer(now);
    }
    assert!(t.get(hello[0].id).is_none());
    assert_eq!(t.len(), 2);
}

#[test]
fn big_timer_looks_up_inside_the_zone() {
    let me = UInt128::new(0xFF << 120);
    let mut t = RoutingTable::new(me, 0);
    add_n(&mut t, 60, |i| (i as u128 + 1) << 100, 0);
    let target = t.big_timer(100, rand::random(), false).unwrap();
    // Some zone wanted a lookup, and not again for an hour.
    let mut more = 0;
    while t.big_timer(100, rand::random(), false).is_some() {
        more += 1;
    }
    assert!(more > 0);
    assert!(t.big_timer(200, 0, false).is_none());
    assert_ne!(target, me);
    // Heard nothing for a while: a lookup at every call (every 10 s in the
    // node) until something answers, the zones' hours notwithstanding.
    for _ in 0..5 {
        assert!(t.big_timer(300, rand::random(), true).is_some());
    }
    assert!(t.big_timer(300, 0, false).is_none());
}

#[test]
fn small_timer_skips_the_hello_for_old_contacts() {
    let mut t = RoutingTable::new(UInt128::new(7), 0);
    let mut v = true;
    t.add(
        UInt128::new(1 << 125),
        ip(20, 0, 0, 1),
        4672,
        4662,
        5,
        UdpKey::default(),
        &mut v,
        false,
        false,
        0,
    );
    t.small_timer(100);
    assert!(t.small_timer(160).is_empty());
    assert_eq!(
        t.contacts().next().unwrap().kind,
        4,
        "aged out all the same"
    );
}

#[test]
fn consolidate_merges_thin_leaves() {
    let me = UInt128::new(0);
    let mut t = RoutingTable::new(me, 0);
    add_n(
        &mut t,
        11,
        |i| ((i % 2) as u128) << 127 | ((i as u128 + 1) << 90),
        0,
    );
    assert!(t.depth() >= 1);
    // Drop all but two by letting them die.
    for c in t.contacts().cloned().collect::<Vec<_>>().iter().skip(2) {
        t.get_mut(c.id).unwrap().kind = 4;
        t.get_mut(c.id).unwrap().expires = 1;
    }
    t.small_timer(10_000);
    let merged = t.consolidate(10_000);
    assert!(merged >= 1);
    assert_eq!(t.depth(), 0);
}

// ---------------------------------------------------------------- packets

#[test]
fn packets_round_trip() {
    let id = UInt128::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10);
    let c = ContactRecord {
        id,
        ip: ip(1, 2, 3, 4),
        udp_port: 4672,
        tcp_port: 4662,
        version: 8,
    };
    let hello = Hello {
        id,
        tcp_port: 4662,
        version: 8,
        udp_port: Some(4673),
        misc_options: 0x03,
    };
    let answer = SearchAnswer {
        answer: id,
        tags: vec![
            Tag::new(
                TagName::Str(tag::FILENAME.to_vec()),
                TagValue::String("a.iso".into()),
            ),
            Tag::new(TagName::Str(tag::FILESIZE.to_vec()), TagValue::int(1 << 33)),
        ],
    };
    for p in [
        KadPacket::BootstrapReq,
        KadPacket::BootstrapRes {
            id,
            tcp_port: 1,
            version: 8,
            contacts: vec![c; 3],
        },
        KadPacket::HelloReq(hello.clone()),
        KadPacket::HelloRes(Hello {
            misc_options: 0,
            udp_port: None,
            ..hello
        }),
        KadPacket::HelloResAck { id },
        KadPacket::Req {
            count: 2,
            target: id,
            receiver: UInt128::new(9),
        },
        KadPacket::Res {
            target: id,
            contacts: vec![c; 11],
        },
        KadPacket::SearchKeyReq {
            target: id,
            start: 0,
            terms: Some(vec![1, 3, 0, b'i', b's', b'o']),
        },
        KadPacket::SearchSourceReq {
            target: id,
            start: 0,
            size: 1234,
        },
        KadPacket::SearchRes {
            sender: id,
            target: id,
            results: vec![answer; 3],
        },
        KadPacket::Ping,
        KadPacket::Pong { port: 4672 },
        KadPacket::FirewalledReq { tcp_port: 4662 },
        KadPacket::Firewalled2Req {
            tcp_port: 4662,
            user_hash: id,
            connect_options: 3,
        },
        KadPacket::FirewalledRes { ip: ip(1, 2, 3, 4) },
        KadPacket::FirewalledAckRes,
    ] {
        let d = p.to_datagram();
        assert_eq!(KadPacket::parse(&d).unwrap(), p, "{p:?}");
    }
    // The firewall check's packets as aMule writes them.
    let d = KadPacket::Firewalled2Req {
        tcp_port: 4662,
        user_hash: id,
        connect_options: 3,
    }
    .to_datagram();
    assert_eq!(d.len(), 2 + 19);
    assert_eq!(&d[..4], [0xE4, 0x53, 0x36, 0x12]);
    assert_eq!(d[20], 3);
    assert_eq!(
        KadPacket::FirewalledRes { ip: ip(1, 2, 3, 4) }.to_datagram(),
        [0xE4, 0x58, 4, 3, 2, 1]
    );
    assert_eq!(KadPacket::FirewalledAckRes.to_datagram(), [0xE4, 0x59]);
    assert_eq!(
        KadPacket::FirewalledReq { tcp_port: 1 }.to_datagram(),
        [0xE4, 0x50, 1, 0]
    );
    // Kad 1 sizes are exact.
    assert!(KadPacket::parse(&[0xE4, 0x58, 4, 3, 2]).is_err());
    assert!(KadPacket::parse(&[0xE4, 0x59, 0]).is_err());
    // KADEMLIA2_REQ: <count><target as WriteUInt128><receiver>.
    let d = KadPacket::Req {
        count: 2,
        target: id,
        receiver: id,
    }
    .to_datagram();
    assert_eq!(&d[..4], [0xE4, 0x21, 0x02, 0x04]);
    assert_eq!(
        &d[3..7],
        [0x04, 0x03, 0x02, 0x01],
        "first word, little-endian"
    );
    // A big answer is packed.
    let big = KadPacket::Res {
        target: id,
        contacts: vec![c; 11],
    }
    .to_datagram();
    assert_eq!(big[0], 0xE5);
    // A wrong contact count is refused.
    let mut bad = KadPacket::Res {
        target: id,
        contacts: vec![c; 2],
    }
    .payload();
    bad[16] = 3;
    let mut dg = vec![0xE4, 0x29];
    dg.extend(bad);
    assert!(KadPacket::parse(&dg).is_err());
}

#[test]
fn keyword_hash() {
    // RFC 1320: MD4("abc").
    assert_eq!(
        keyword_target("abc").to_be_bytes(),
        *b"\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d"
    );
}

#[test]
fn results() {
    let s = |n: &[u8], v: &str| Tag::new(TagName::Str(n.to_vec()), TagValue::String(v.into()));
    let i = |n: &[u8], v: u64| Tag::new(TagName::Str(n.to_vec()), TagValue::int(v));
    let h = UInt128::from_be_bytes([0xAB; 16]);
    let r = keyword_result(
        h,
        &[
            s(tag::FILENAME, "x.avi"),
            i(tag::FILESIZE, 700),
            i(tag::SOURCES, 70000),
            s(tag::FILETYPE, "Video"),
        ],
        ip(1, 2, 3, 4),
    )
    .unwrap();
    assert_eq!(
        (
            r.name.as_str(),
            r.size,
            r.availability,
            r.file_type.as_str()
        ),
        ("x.avi", 700, 0, "Video")
    );
    assert_eq!(r.hash, Md4Hash([0xAB; 16]));
    // A 64-bit size as an 8-byte BSOB.
    let big = Tag::new(
        TagName::Str(tag::FILESIZE.to_vec()),
        TagValue::Bsob((5u64 << 32).to_le_bytes().to_vec()),
    );
    assert_eq!(
        keyword_result(h, &[s(tag::FILENAME, "y"), big], 0)
            .unwrap()
            .size,
        5 << 32
    );
    // No name or no size: nothing.
    assert!(keyword_result(h, &[i(tag::FILESIZE, 1)], 0).is_none());
    let src = source_result(
        h,
        &[
            i(tag::SOURCETYPE, 1),
            i(tag::SOURCEIP, ip(9, 8, 7, 6) as u64),
            i(tag::SOURCEPORT, 4662),
            i(tag::SOURCEUPORT, 4672),
            i(tag::ENCRYPTION, 3),
        ],
    )
    .unwrap();
    assert_eq!(
        (src.ip, src.tcp_port, src.crypt_options),
        (Ipv4Addr::new(9, 8, 7, 6), 4662, 3)
    );
    assert!(source_result(h, &[i(tag::SOURCETYPE, 2)]).is_none());
}

// ---------------------------------------------------------------- a network

pub(crate) struct Net {
    pub(crate) nodes: Vec<Kad>,
    pub(crate) addrs: Vec<SocketAddrV4>,
    queue: VecDeque<(SocketAddrV4, Datagram)>,
    pub(crate) now: u64,
    /// Search requests seen: (receiver index, packet).
    pub(crate) requests: Vec<(usize, KadPacket, SocketAddrV4)>,
}

impl Net {
    pub(crate) fn new(ids: &[UInt128], rng: &mut StdRng) -> Net {
        let now = 1000;
        let mut nodes = Vec::new();
        let mut addrs = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let cfg = Config {
                kad_id: *id,
                udp_key_secret: rng.gen(),
                user_hash: Md4Hash(rng.gen()),
                tcp_port: 4662,
                tcp_firewalled: false,
                udp_firewalled: false,
            };
            nodes.push(Kad::new(cfg, now));
            addrs.push(SocketAddrV4::new(
                Ipv4Addr::new(20, (i / 200) as u8, (i % 200) as u8, 1),
                4672,
            ));
        }
        Net {
            nodes,
            addrs,
            queue: VecDeque::new(),
            now,
            requests: Vec::new(),
        }
    }

    fn index(&self, a: SocketAddrV4) -> Option<usize> {
        self.addrs.iter().position(|x| *x == a)
    }

    pub(crate) fn post(&mut self, from: usize, ds: Vec<Datagram>) {
        for d in ds {
            self.queue.push_back((self.addrs[from], d));
        }
    }

    /// Peek at what a node receives (decrypting it as the node would).
    fn peek(&mut self, to: usize, from: SocketAddrV4, bytes: &[u8]) {
        let n = &self.nodes[to];
        let plain = if bytes[0] == 0xE4 || bytes[0] == 0xE5 {
            Some(bytes.to_vec())
        } else {
            let own = OwnKeys {
                user_hash: n.config().user_hash,
                sender_ip: *from.ip(),
                kad_id: Some(n.config().kad_id),
                verify_key: Some(udp::udp_verify_key(n.config().udp_key_secret, *from.ip())),
            };
            udp::decrypt_client(bytes, &own).map(|d| d.payload)
        };
        let p = KadPacket::parse(&plain.expect("decrypts")).expect("parses");
        if matches!(
            p,
            KadPacket::SearchKeyReq { .. } | KadPacket::SearchSourceReq { .. }
        ) {
            self.requests.push((to, p, from));
        }
    }

    pub(crate) fn deliver(&mut self) -> Vec<(usize, Event)> {
        let mut events = Vec::new();
        while let Some((from, d)) = self.queue.pop_front() {
            let Some(to) = self.index(d.to) else { continue };
            self.peek(to, from, &d.bytes);
            let out = self.nodes[to].handle(from, &d.bytes, self.now);
            events.extend(out.events.into_iter().map(|e| (to, e)));
            self.post(to, out.send);
        }
        events
    }

    pub(crate) fn run(&mut self, secs: u64) -> Vec<(usize, Event)> {
        let mut events = Vec::new();
        for _ in 0..secs {
            self.now += 1;
            for i in 0..self.nodes.len() {
                let out = self.nodes[i].tick(self.now);
                events.extend(out.events.into_iter().map(|e| (i, e)));
                self.post(i, out.send);
            }
            events.extend(self.deliver());
        }
        events
    }
}

#[test]
fn a_simulated_network_finds_the_keyword_node_and_reads_its_answer() {
    let mut rng = StdRng::seed_from_u64(42);
    let target = keyword_target("ubuntu");
    let mut ids: Vec<UInt128> = (0..60).map(|_| UInt128::new(rng.gen())).collect();
    // Node 59 holds the keyword: its ID is within the search tolerance.
    ids[59] = target ^ UInt128::new(12345);
    let mut net = Net::new(&ids, &mut rng);
    // Everyone knows a few others (verified, as from a nodes.dat).
    for i in 0..net.nodes.len() {
        for _ in 0..8 {
            let j = rng.gen_range(0..ids.len() - 1); // nobody knows node 59 directly
            if j == i {
                continue;
            }
            let a = net.addrs[j];
            let mut v = true;
            net.nodes[i].routing.add(
                ids[j],
                u32::from(*a.ip()),
                a.port(),
                4662,
                8,
                UdpKey::default(),
                &mut v,
                false,
                false,
                1000,
            );
        }
    }
    let mut v = true;
    let a59 = net.addrs[59];
    for k in [3, 17, 33] {
        net.nodes[k].routing.add(
            ids[59],
            u32::from(*a59.ip()),
            a59.port(),
            4662,
            8,
            UdpKey::default(),
            &mut v,
            false,
            false,
            1000,
        );
    }
    // Let the network get to know itself: contacts answer hellos (and
    // become type 2, which nodes hand out), lookups spread them.
    let before: usize = net.nodes.iter().map(|n| n.routing.len()).sum();
    let events = net.run(300);
    assert!(events.iter().any(|(_, e)| *e == Event::Connected));
    let after: usize = net.nodes.iter().map(|n| n.routing.len()).sum();
    assert!(
        after > before * 3 / 2,
        "routing tables grew: {before} -> {after}"
    );

    // Node 0 searches "ubuntu iso": keyword "ubuntu", terms "iso".
    let now = net.now;
    let (sid, word, out) = net.nodes[0]
        .search_keyword(&SearchParams::new("ubuntu iso"), now)
        .unwrap();
    assert_eq!(word, "ubuntu");
    net.post(0, out);
    net.deliver();
    net.run(10);
    let req = net.requests.iter().find(|(to, ..)| *to == 59).cloned();
    let (_, p, from) = req.expect("the keyword node was asked");
    let KadPacket::SearchKeyReq {
        target: t, terms, ..
    } = p
    else {
        unreachable!()
    };
    assert_eq!(t, target);
    assert_eq!(terms.unwrap()[..3], [1, 3, 0]);
    // Node 59 answers, obfuscated for node 0 with the key node 0 gave it.
    let res = KadPacket::SearchRes {
        sender: ids[59],
        target,
        results: vec![SearchAnswer {
            answer: UInt128::from_be_bytes([7; 16]),
            tags: vec![
                Tag::new(
                    TagName::Str(tag::FILENAME.to_vec()),
                    TagValue::String("ubuntu-24.04.iso".into()),
                ),
                Tag::new(
                    TagName::Str(tag::FILESIZE.to_vec()),
                    TagValue::int(6_000_000_000),
                ),
                Tag::new(TagName::Str(tag::SOURCES.to_vec()), TagValue::int(12)),
            ],
        }],
    };
    let d = net.nodes[59].send_to_test(&res, from, 8, Some(ids[0]), net.now);
    net.post(59, vec![d]);
    let events = net.deliver();
    let found = events.iter().find_map(|(i, e)| match e {
        Event::Found {
            search,
            found: Found::Keyword(k),
        } if *i == 0 && *search == sid => Some(k.clone()),
        _ => None,
    });
    let k = found.expect("node 0 got the result");
    assert_eq!(
        (k.name.as_str(), k.size, k.availability),
        ("ubuntu-24.04.iso", 6_000_000_000, 12)
    );
    // The search ends after its 45 s.
    let events = net.run(50);
    assert!(events.iter().any(|(i, e)| *i == 0
        && matches!(e, Event::SearchDone { search, answers: 1, .. } if *search == sid)));
}

#[test]
fn answers_hello_req_and_ping_and_ignores_the_unrequested() {
    let mut rng = StdRng::seed_from_u64(1);
    let ids = [UInt128::new(rng.gen()), UInt128::new(rng.gen())];
    let mut net = Net::new(&ids, &mut rng);
    let (a, b) = (net.addrs[0], net.addrs[1]);
    // Hello from 1 to 0 (unobfuscated: 0's ID unknown to it).
    let hello = KadPacket::HelloReq(Hello {
        id: ids[1],
        tcp_port: 4662,
        version: 8,
        udp_port: None,
        misc_options: 0,
    });
    let out = net.nodes[0].handle(b, &hello.to_datagram(), 1001);
    // The answer, and (a firewall check running) a check request.
    assert_eq!(out.send.len(), 2);
    assert!(matches!(
        KadPacket::parse(&out.send[1].bytes).unwrap(),
        KadPacket::Firewalled2Req { .. }
    ));
    assert!(net.nodes[0].routing.get(ids[1]).is_some());
    // Ping: pong with the port it came from.
    let out = net.nodes[0].handle(b, &KadPacket::Ping.to_datagram(), 1002);
    assert_eq!(
        KadPacket::parse(&out.send[0].bytes).unwrap(),
        KadPacket::Pong { port: 4672 }
    );
    // An answer nobody asked for is dropped.
    let res = KadPacket::Res {
        target: ids[0],
        contacts: vec![],
    };
    let out = net.nodes[0].handle(b, &res.to_datagram(), 1003);
    assert!(out.send.is_empty());
    assert_eq!(net.nodes[0].stats.unrequested, 1);
    // A UDP-firewalled sender is answered but not added.
    let fw = KadPacket::HelloReq(Hello {
        id: UInt128::new(5),
        tcp_port: 1,
        version: 8,
        udp_port: None,
        misc_options: 1,
    });
    let out = net.nodes[1].handle(a, &fw.to_datagram(), 1004);
    assert_eq!(out.send.len(), 2);
    assert!(net.nodes[1].routing.get(UInt128::new(5)).is_none());
}

/// With `trace_wire`, every datagram each way is recorded with its key:
/// a hello keyed on the receiver's Kad ID, answered keyed on ours and
/// carrying the verify key we gave, which we see as valid.
#[test]
fn the_wire_trace_tells_how_each_datagram_was_obfuscated() {
    use crate::node::{Wire, WireForm};
    use ed2k_types::kad::v2::Opcode;
    let mut rng = StdRng::seed_from_u64(7);
    let ids = [UInt128::new(rng.gen()), UInt128::new(rng.gen())];
    let mut net = Net::new(&ids, &mut rng);
    for n in &mut net.nodes {
        n.trace_wire = true;
    }
    let (a, b) = (net.addrs[0], net.addrs[1]);
    let hello = KadPacket::HelloReq(Hello {
        id: ids[1],
        tcp_port: 4662,
        version: 9,
        udp_port: None,
        misc_options: 0,
    });
    // Node 1 knows node 0's ID: keyed on it.
    let d = net.nodes[1].send_to_test(&hello, a, 9, Some(ids[0]), net.now);
    net.post(1, vec![d]);
    net.deliver();
    let w1 = net.nodes[1].take_wire();
    let w0 = net.nodes[0].take_wire();
    assert_eq!(
        w1[0],
        Wire {
            incoming: false,
            peer: a,
            opcode: Opcode::HelloReq as u8,
            form: WireForm::KadId,
            receiver_key_valid: false,
        }
    );
    // Node 0 had given node 1 no verify key yet.
    assert_eq!(
        w0[0],
        Wire {
            incoming: true,
            peer: b,
            opcode: Opcode::HelloReq as u8,
            form: WireForm::KadId,
            receiver_key_valid: false,
        }
    );
    // The answer, keyed on node 1's ID, with node 1's verify key in it.
    let res = w0
        .iter()
        .find(|w| !w.incoming && w.opcode == Opcode::HelloRes as u8)
        .expect("node 0 answered");
    assert_eq!((res.peer, res.form), (b, WireForm::KadId));
    let got = w1
        .iter()
        .find(|w| w.incoming && w.opcode == Opcode::HelloRes as u8)
        .expect("node 1 read the answer");
    assert_eq!(got.form, WireForm::KadId);
    assert!(got.receiver_key_valid);
    // The counters agree; the trace is drained.
    let s = &net.nodes[0].stats;
    assert_eq!(
        (s.obfuscated_in, s.obfuscated_out),
        (
            w0.iter()
                .filter(|w| w.incoming && w.form != WireForm::Plain)
                .count() as u64,
            w0.iter()
                .filter(|w| !w.incoming && w.form != WireForm::Plain)
                .count() as u64
        )
    );
    assert!(net.nodes[0].take_wire().is_empty());
    // Off by default.
    let mut quiet = Net::new(&ids, &mut rng);
    let d = quiet.nodes[1].send_to_test(&hello, quiet.addrs[0], 9, Some(ids[0]), 0);
    quiet.post(1, vec![d]);
    quiet.deliver();
    assert!(quiet.nodes[0].take_wire().is_empty());
    assert!(quiet.nodes[0].stats.obfuscated_in > 0);
}

/// A packet `to` receives from `from`, decrypted as it would.
fn read_as(to: &Kad, from: SocketAddrV4, bytes: &[u8]) -> KadPacket {
    let plain = if bytes[0] == 0xE4 || bytes[0] == 0xE5 {
        bytes.to_vec()
    } else {
        let own = OwnKeys {
            user_hash: to.config().user_hash,
            sender_ip: *from.ip(),
            kad_id: Some(to.config().kad_id),
            verify_key: Some(udp::udp_verify_key(to.config().udp_key_secret, *from.ip())),
        };
        udp::decrypt_client(bytes, &own).expect("decrypts").payload
    };
    KadPacket::parse(&plain).expect("parses")
}

/// Node `i` says hello to node 0; what node 0 sends back is delivered, and
/// node `i`'s answers to that too. The events of node `i`.
fn hello_to_0(net: &mut Net, i: usize) -> Vec<Event> {
    let hello = KadPacket::HelloReq(Hello {
        id: net.nodes[i].config().kad_id,
        tcp_port: 4662,
        version: 9,
        udp_port: None,
        misc_options: 0,
    });
    let d = net.nodes[i].send_to_test(&hello, net.addrs[0], 9, None, net.now);
    net.post(i, vec![d]);
    net.deliver()
        .into_iter()
        .filter(|(n, e)| *n == i && *e != Event::Connected)
        .map(|(_, e)| e)
        .collect()
}

/// The TCP firewall check (`CFirewallRecheck` through the UDP listener):
/// nodes that say hello are asked to check us and tell us our IP; two that
/// reach our TCP port make us open; each counts once; an hour later the
/// check runs again, and with nobody getting through we are firewalled
/// again.
#[test]
fn the_tcp_firewall_check() {
    use crate::firewall::GRACE;
    use ed2k_types::kad::KADEMLIAFIREWALLCHECKS;

    let mut rng = StdRng::seed_from_u64(7);
    let ids: Vec<UInt128> = (0..10).map(|_| UInt128::new(rng.gen())).collect();
    let mut net = Net::new(&ids, &mut rng);
    let us = net.addrs[0];
    let our_hash = net.nodes[0].config().user_hash;
    assert!(net.nodes[0].is_firewalled(net.now));

    // Node 1 says hello: it is asked, tells us our IP, and asks its
    // application to connect to our TCP port (crypt supported and requested).
    let ev = hello_to_0(&mut net, 1);
    assert_eq!(
        ev,
        [Event::FirewallCheck {
            tcp: SocketAddrV4::new(*us.ip(), 4662),
            user_hash: our_hash,
            connect_options: 0x03,
        }]
    );
    assert_eq!(net.nodes[0].public_ip(), u32::from(*us.ip()));
    assert!(net.nodes[0].is_firewalled(net.now));

    // Three more: the check has its answers.
    for i in 2..=KADEMLIAFIREWALLCHECKS as usize {
        assert_eq!(hello_to_0(&mut net, i).len(), 1);
    }
    // Once it has them, nobody else is asked.
    assert!(hello_to_0(&mut net, 5).is_empty());

    // Acks over TCP: an unasked node and a repeat count for nothing.
    let ip_of = |i: usize| *net.addrs[i].ip();
    let now = net.now;
    assert!(!net.nodes[0].firewall_ack(ip_of(6), now));
    assert!(net.nodes[0].firewall_ack(ip_of(1), now));
    assert!(!net.nodes[0].firewall_ack(ip_of(1), now));
    assert!(net.nodes[0].is_firewalled(now));
    assert!(net.nodes[0].tick(now).events.is_empty());
    assert!(net.nodes[0].firewall_ack(ip_of(2), now));
    assert!(!net.nodes[0].is_firewalled(now));
    assert_eq!(net.nodes[0].tick(now).events, [Event::Firewalled(false)]);

    // Our hellos now say we take TCP connections (misc options: UDP
    // firewalled only, as node 0 is not).
    let hello = KadPacket::HelloReq(Hello {
        id: ids[7],
        tcp_port: 4662,
        version: 9,
        udp_port: None,
        misc_options: 0,
    });
    let out = net.nodes[0].handle(net.addrs[7], &hello.to_datagram(), now);
    assert_eq!(out.send.len(), 1, "nobody is asked any more");
    match read_as(&net.nodes[7], us, &out.send[0].bytes) {
        KadPacket::HelloRes(h) => assert!(!h.tcp_firewalled()),
        p => panic!("{p:?}"),
    }

    // A late or unasked IP answer changes nothing.
    let res = KadPacket::FirewalledRes { ip: 0x0102_0304 };
    let before = net.nodes[0].stats.unrequested;
    net.nodes[0].handle(net.addrs[8], &res.to_datagram(), now);
    assert_eq!(net.nodes[0].public_ip(), u32::from(*us.ip()));
    assert_eq!(net.nodes[0].stats.unrequested, before);

    // An hour later: a recheck. Open until it has its answers, and firewalled
    // a grace period after them when nobody got through.
    net.now += crate::firewall::RECHECK_INTERVAL;
    assert!(net.nodes[0].tick(net.now).events.is_empty());
    for i in 1..=KADEMLIAFIREWALLCHECKS as usize {
        assert_eq!(hello_to_0(&mut net, i).len(), 1);
        assert!(!net.nodes[0].is_firewalled(net.now));
    }
    let answered = net.now;
    assert!(net.nodes[0].tick(answered + GRACE - 1).events.is_empty());
    assert_eq!(
        net.nodes[0].tick(answered + GRACE).events,
        [Event::Firewalled(true)]
    );
}

/// A node that takes no TCP connections neither asks nor answers.
#[test]
fn no_firewall_check_without_tcp() {
    let mut rng = StdRng::seed_from_u64(8);
    let ids: Vec<UInt128> = (0..2).map(|_| UInt128::new(rng.gen())).collect();
    let mut net = Net::new(&ids, &mut rng);
    for n in &mut net.nodes {
        *n = Kad::new(
            Config {
                tcp_firewalled: true,
                ..n.config().clone()
            },
            net.now,
        );
    }
    let hello = KadPacket::HelloReq(Hello {
        id: ids[1],
        tcp_port: 4662,
        version: 9,
        udp_port: None,
        misc_options: 0,
    });
    let out = net.nodes[0].handle(net.addrs[1], &hello.to_datagram(), net.now);
    assert_eq!(out.send.len(), 1);
    let ask = KadPacket::Firewalled2Req {
        tcp_port: 4662,
        user_hash: UInt128::new(1),
        connect_options: 0,
    };
    let out = net.nodes[0].handle(net.addrs[1], &ask.to_datagram(), net.now);
    assert!(out.send.is_empty() && out.events.is_empty());
    assert!(net.nodes[0].is_firewalled(net.now + 3600));
}

#[test]
fn nodes_dat_round_trip() {
    let mut rng = StdRng::seed_from_u64(9);
    let cfg = Config {
        kad_id: UInt128::new(rng.gen()),
        udp_key_secret: 1,
        user_hash: Md4Hash([0; 16]),
        tcp_port: 1,
        tcp_firewalled: true,
        udp_firewalled: true,
    };
    let mut kad = Kad::new(cfg.clone(), 1000);
    add_n(&mut kad.routing, 100, spread, 1000);
    let n = kad.routing.len();
    let file = kad.nodes_to_save().expect("enough contacts");
    let bytes = file.write();
    let back = ed2k_formats::nodes_dat::NodesDat::read(&bytes).unwrap();
    let mut kad2 = Kad::new(cfg, 1000);
    assert_eq!(kad2.load_nodes(&back, 1000), back.contacts.len());
    assert!(back.contacts.len() >= 25 && back.contacts.len() <= n);
}

/// `SendLegacyChallenge` / `IsLegacyChallenge`: a pre-v7 node saying hello
/// unproven is sent a plain `KADEMLIA2_REQ` for a random target; an answer
/// with another target proves nothing, the right one verifies it. One
/// challenge per IP while it waits; a v7 node gets a keyed ping instead.
#[test]
fn legacy_challenges_verify_old_nodes() {
    use crate::node::CHALLENGE_TIME;
    let mut rng = StdRng::seed_from_u64(9);
    let ids = [UInt128::new(rng.gen()), UInt128::new(rng.gen())];
    let mut net = Net::new(&ids, &mut rng);
    let b = net.addrs[1];
    let old = |version| {
        KadPacket::HelloReq(Hello {
            id: ids[1],
            tcp_port: 4662,
            version,
            udp_port: None,
            misc_options: 0,
        })
    };
    let out = net.nodes[0].handle(b, &old(6).to_datagram(), 1000);
    let challenges: Vec<(UInt128, UInt128, u8)> = out
        .send
        .iter()
        .filter_map(|d| match KadPacket::parse(&d.bytes) {
            Ok(KadPacket::Req {
                count,
                target,
                receiver,
            }) => Some((target, receiver, count)),
            _ => None,
        })
        .collect();
    // Plain (it parses as is), for the contact's ID, KADEMLIA_FIND_VALUE.
    assert_eq!(challenges.len(), 1);
    let (challenge, receiver, count) = challenges[0];
    assert_eq!((receiver, count), (ids[1], 0x02));
    assert!(!net.nodes[0].routing.get(ids[1]).unwrap().ip_verified);

    // A second hello while it waits: no second challenge.
    let out = net.nodes[0].handle(b, &old(6).to_datagram(), 1001);
    assert!(!out
        .send
        .iter()
        .any(|d| matches!(KadPacket::parse(&d.bytes), Ok(KadPacket::Req { .. }))));

    // The wrong target: nothing verified. It used up the request it
    // answered (`CHECK_TRACKED_PACKET`), as in aMule.
    let wrong = KadPacket::Res {
        target: UInt128::new(12345),
        contacts: vec![],
    };
    net.nodes[0].handle(b, &wrong.to_datagram(), 1002);
    assert!(!net.nodes[0].routing.get(ids[1]).unwrap().ip_verified);
    // Once that challenge expires, a new hello brings a new one, and the
    // right answer to it verifies the contact.
    let later = 1000 + CHALLENGE_TIME + 1;
    let out = net.nodes[0].handle(b, &old(6).to_datagram(), later);
    let (challenge2, ..) = out
        .send
        .iter()
        .find_map(|d| match KadPacket::parse(&d.bytes) {
            Ok(KadPacket::Req {
                target, receiver, ..
            }) => Some((target, receiver)),
            _ => None,
        })
        .expect("a new challenge once the first expired");
    assert_ne!(challenge2, challenge);
    let right = KadPacket::Res {
        target: challenge2,
        contacts: vec![],
    };
    net.nodes[0].handle(b, &right.to_datagram(), later + 1);
    assert!(net.nodes[0].routing.get(ids[1]).unwrap().ip_verified);

    // Version 7: a ping, no challenge.
    let mut net = Net::new(&ids, &mut rng);
    let out = net.nodes[0].handle(b, &old(7).to_datagram(), 1000);
    let parsed: Vec<KadPacket> = out
        .send
        .iter()
        .map(|d| read_as(&net.nodes[1], net.addrs[0], &d.bytes))
        .collect();
    assert!(parsed.contains(&KadPacket::Ping));
    assert!(!parsed.iter().any(|p| matches!(p, KadPacket::Req { .. })));
    // Version 8 proves itself with the ACK: neither.
    let mut net = Net::new(&ids, &mut rng);
    let out = net.nodes[0].handle(b, &old(8).to_datagram(), 1000);
    assert!(!out.send.iter().any(|d| matches!(
        read_as(&net.nodes[1], net.addrs[0], &d.bytes),
        KadPacket::Ping | KadPacket::Req { .. }
    )));
}

/// A pre-v7 node's answer to our hello is challenged too (it can be
/// spoofed by whoever knows we said hello).
#[test]
fn an_old_nodes_hello_answer_is_challenged() {
    let mut rng = StdRng::seed_from_u64(10);
    let ids = [UInt128::new(rng.gen()), UInt128::new(rng.gen())];
    let mut net = Net::new(&ids, &mut rng);
    let b = net.addrs[1];
    let hello = KadPacket::HelloReq(Hello {
        id: ids[0],
        tcp_port: 4662,
        version: 9,
        udp_port: None,
        misc_options: 0,
    });
    let _ = net.nodes[0].send_to_test(&hello, b, 6, None, 1000);
    let res = KadPacket::HelloRes(Hello {
        id: ids[1],
        tcp_port: 4662,
        version: 6,
        udp_port: None,
        misc_options: 0,
    });
    let out = net.nodes[0].handle(b, &res.to_datagram(), 1001);
    assert!(out.send.iter().any(|d| matches!(
        KadPacket::parse(&d.bytes),
        Ok(KadPacket::Req { receiver, .. }) if receiver == ids[1]
    )));
}

/// The buddy packets on the wire (`KADEMLIA_FINDBUDDY_REQ/RES`,
/// `KADEMLIA_CALLBACK_REQ`): Kad 1 opcodes under the Kad 2 header; an
/// offer's connect options only when present.
#[test]
fn buddy_packets_round_trip() {
    let a = UInt128::new(0x0123_4567_89AB_CDEF_0011_2233_4455_6677);
    let b = UInt128::new(42);
    for p in [
        KadPacket::FindBuddyReq {
            buddy_id: a,
            user_hash: b,
            tcp_port: 4662,
        },
        KadPacket::FindBuddyRes {
            buddy_id: a,
            user_hash: b,
            tcp_port: 4662,
            connect_options: Some(3),
        },
        KadPacket::FindBuddyRes {
            buddy_id: a,
            user_hash: b,
            tcp_port: 4662,
            connect_options: None,
        },
        KadPacket::CallbackReq {
            buddy_id: a,
            file: b,
            tcp_port: 4711,
        },
    ] {
        let d = p.to_datagram();
        assert_eq!(d[0], 0xE4);
        assert_eq!(KadPacket::parse(&d).unwrap(), p);
    }
    assert_eq!(
        KadPacket::FindBuddyReq {
            buddy_id: a,
            user_hash: b,
            tcp_port: 1
        }
        .to_datagram()[1],
        0x51
    );
    // Shorter than 34 bytes: refused.
    assert!(KadPacket::parse(&[0xE4, 0x52, 1, 2, 3]).is_err());
}

/// A firewalled node finds a buddy: five minutes after start it searches
/// toward its Kad ID with every bit flipped; the open node there offers
/// (and says so to its application), the firewalled one hears the offer.
/// A firewalled or already serving node does not offer; an offer for
/// another ID, or unasked, is not taken.
#[test]
fn a_firewalled_node_finds_a_buddy() {
    let mut rng = StdRng::seed_from_u64(77);
    let mut ids: Vec<UInt128> = (0..30).map(|_| UInt128::new(rng.gen())).collect();
    let target = UInt128::new(u128::MAX) ^ ids[0];
    // Node 5 is close to node 0's buddy target; node 6 too, but serving.
    ids[5] = target ^ UInt128::new(777);
    ids[6] = target ^ UInt128::new(999);
    let mut net = Net::new(&ids, &mut rng);
    let mut c = net.nodes[0].config().clone();
    c.tcp_firewalled = true;
    net.nodes[0] = Kad::new(c, net.now);
    net.nodes[6].serving_buddy = true;
    // Everyone but node 0 can be reached over TCP.
    for n in &mut net.nodes[1..] {
        n.set_tcp_open();
    }
    let addrs = net.addrs.clone();
    for i in 0..net.nodes.len() {
        for (j, &a) in addrs.iter().enumerate() {
            if i == j || (i + j) % 3 != 0 && j != 5 && j != 6 {
                continue;
            }
            let mut v = true;
            net.nodes[i].routing.add(
                ids[j],
                u32::from(*a.ip()),
                a.port(),
                4662,
                8,
                UdpKey::default(),
                &mut v,
                false,
                false,
                1000,
            );
        }
    }
    net.run(60);
    // Not before five minutes, nor with a buddy.
    assert!(net.nodes[0].buddy_search(false, net.now).is_none());
    net.run(250);
    assert!(net.nodes[0].buddy_search(true, net.now).is_none());
    let now = net.now;
    let (_, out) = net.nodes[0]
        .buddy_search(false, now)
        .expect("a buddy search");
    // Once: the next waits 20 minutes.
    assert!(net.nodes[0].buddy_search(false, now).is_none());
    // An open node that is not firewalled does not search.
    assert!(net.nodes[1].buddy_search(false, now).is_none());
    net.post(0, out);
    let mut events = net.deliver();
    events.extend(net.run(30));
    let offer = events.iter().find_map(|(i, e)| match e {
        Event::BuddyOffer { tcp, user_hash, .. } if *i == 0 => Some((*tcp, *user_hash)),
        _ => None,
    });
    let (tcp, user_hash) = offer.expect("an offer");
    assert_eq!(tcp, SocketAddrV4::new(*net.addrs[5].ip(), 4662));
    assert_eq!(user_hash, net.nodes[5].config().user_hash);
    let request = events.iter().find_map(|(i, e)| match e {
        Event::BuddyRequest {
            buddy_id,
            user_hash,
            tcp,
        } if *i == 5 => Some((*buddy_id, *user_hash, *tcp)),
        _ => None,
    });
    assert_eq!(
        request,
        Some((
            target,
            net.nodes[0].config().user_hash,
            SocketAddrV4::new(*net.addrs[0].ip(), 4662)
        ))
    );
    assert!(!events
        .iter()
        .any(|(i, e)| *i == 6 && matches!(e, Event::BuddyRequest { .. })));

    // An offer nobody asked for, or for someone else: ignored.
    let stray = KadPacket::FindBuddyRes {
        buddy_id: target,
        user_hash: UInt128::new(1),
        tcp_port: 1,
        connect_options: None,
    };
    let out = net.nodes[0].handle(net.addrs[9], &stray.to_datagram(), net.now);
    assert!(out.events.is_empty());
    // A firewalled node does not offer.
    let req = KadPacket::FindBuddyReq {
        buddy_id: UInt128::new(5),
        user_hash: UInt128::new(6),
        tcp_port: 7,
    };
    let out = net.nodes[0].handle(net.addrs[9], &req.to_datagram(), net.now);
    assert!(out.send.is_empty() && out.events.is_empty());
}

/// `KADEMLIA_CALLBACK_REQ` reaches the application with the asker's
/// address and TCP port.
#[test]
fn callback_requests_reach_the_application() {
    let mut rng = StdRng::seed_from_u64(78);
    let ids = [UInt128::new(rng.gen()), UInt128::new(rng.gen())];
    let mut net = Net::new(&ids, &mut rng);
    let req = KadPacket::CallbackReq {
        buddy_id: UInt128::new(99),
        file: UInt128::from_be_bytes([7; 16]),
        tcp_port: 4711,
    };
    let out = net.nodes[0].handle(net.addrs[1], &req.to_datagram(), 1000);
    // (The first packet also says Kad is connected.)
    let events: Vec<Event> = out
        .events
        .into_iter()
        .filter(|e| *e != Event::Connected)
        .collect();
    assert_eq!(
        events,
        vec![Event::CallbackRequest {
            buddy_id: UInt128::new(99),
            file: Md4Hash([7; 16]),
            from: SocketAddrV4::new(*net.addrs[1].ip(), 4711),
        }]
    );
}
