// SPDX-License-Identifier: GPL-2.0-or-later
//! Kad buddies, the TCP side ([`crate::buddy`]).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_peer::packets::{buddy_ping, buddy_pong, callback};
use ed2k_peer::{BuddyCallback, Hello, PeerPacket};
use ed2k_types::{Md4Hash, UInt128};

use crate::buddy::{other_layout, same_buddy_id, Buddies, CallBack, PING_INTERVAL};
use crate::download_queue::{Action, ConnId, Report};

fn ours() -> Hello {
    Hello::amule(Md4Hash([0x11; 16]), 0x0100_000A, 4662, "remule")
}

fn wire(p: Packet) -> Packet {
    Packet::parse_tcp(&p.to_tcp_bytes().unwrap()).unwrap()
}

fn sent(actions: &[Action]) -> Vec<PeerPacket> {
    actions
        .iter()
        .flat_map(|a| match a {
            Action::Send { packets, .. } => packets.clone(),
            _ => Vec::new(),
        })
        .map(|p| PeerPacket::parse(wire(p), Default::default()).unwrap())
        .collect()
}

fn reports(actions: &[Action]) -> Vec<Report> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Report(r) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn buddy_ids_match_in_either_layout() {
    let id = UInt128::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let emule = other_layout(id);
    assert_eq!(
        emule.to_be_bytes(),
        [4, 3, 2, 1, 8, 7, 6, 5, 12, 11, 10, 9, 16, 15, 14, 13]
    );
    assert_eq!(other_layout(emule), id);
    assert!(same_buddy_id(id, id) && same_buddy_id(emule, id));
    assert!(!same_buddy_id(UInt128::new(5), id));
}

/// We are firewalled: the first offer is taken (obfuscated when the node
/// supports it), hello, hello answer, the link is up; a ping every ten
/// minutes, a pong renews it; a callback for our buddy ID (either layout)
/// is for the upload side, another is not; silence ends it.
#[test]
fn our_buddy() {
    let t0 = Instant::now();
    let kad_id = UInt128::new(0x1234_5678);
    let our_buddy_id = UInt128::new(u128::MAX) ^ kad_id;
    let mut b = Buddies::new(ours());
    b.set_kad_id(Some(kad_id));
    let addr = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 4662);
    let theirs = Md4Hash([0x22; 16]);
    let conn: ConnId = 7;
    let a = b.offer(addr, 4672, theirs, 0x03, conn, t0);
    assert!(matches!(
        &a[..],
        [Action::Connect { conn: c, addr: SocketAddr::V4(to), obfuscate_for: Some(h) }]
            if *c == conn && *to == addr && *h == theirs
    ));
    assert!(b.has_own() && b.owns(conn) && b.own_buddy().is_none());
    // A second offer meanwhile: not taken.
    assert!(b.offer(addr, 4672, theirs, 0, 8, t0).is_empty());

    assert!(matches!(
        sent(&b.connected(conn, t0))[..],
        [PeerPacket::Hello(_)]
    ));
    let answer = Hello::amule(theirs, 0x0700_A8C0, 4662, "buddy");
    let (a, cb) = b.packet(conn, wire(answer.to_hello_answer().unwrap()), t0);
    assert!(cb.is_empty());
    assert_eq!(
        reports(&a),
        vec![Report::BuddyLinked {
            addr,
            kad_port: 4672,
            serving: false
        }]
    );
    assert_eq!(b.own_buddy(), Some(addr));

    // Pings every ten minutes.
    assert!(b
        .tick(t0 + PING_INTERVAL - Duration::from_secs(1))
        .is_empty());
    let t1 = t0 + PING_INTERVAL;
    assert!(matches!(sent(&b.tick(t1))[..], [PeerPacket::BuddyPing]));
    b.packet(conn, wire(buddy_pong()), t1);

    // Callbacks: ours in both layouts; a stranger's ID is dropped.
    let requester = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 4711);
    for id in [our_buddy_id, other_layout(our_buddy_id)] {
        let c = callback(&BuddyCallback {
            buddy_id: id,
            file: Md4Hash([7; 16]),
            ip: *requester.ip(),
            tcp_port: requester.port(),
        });
        let (_, cb) = b.packet(conn, wire(c), t1);
        assert_eq!(
            cb,
            vec![CallBack {
                addr: requester,
                file: Md4Hash([7; 16])
            }]
        );
    }
    let c = callback(&BuddyCallback {
        buddy_id: UInt128::new(9),
        file: Md4Hash([7; 16]),
        ip: *requester.ip(),
        tcp_port: requester.port(),
    });
    assert!(b.packet(conn, wire(c), t1).1.is_empty());

    // 25 minutes of silence: closed, lost, free for another offer.
    let a = b.tick(t1 + Duration::from_secs(25 * 60));
    assert!(a
        .iter()
        .any(|x| matches!(x, Action::Close { conn: c } if *c == conn)));
    assert!(matches!(
        &reports(&a)[..],
        [Report::BuddyLost { serving: false, .. }]
    ));
    assert!(!b.has_own());
    // An offer that never comes up is given up after two minutes.
    let t2 = t1 + Duration::from_secs(30 * 60);
    b.offer(addr, 4672, theirs, 0, 9, t2);
    assert!(b.tick(t2 + Duration::from_secs(119)).is_empty());
    let a = b.tick(t2 + Duration::from_secs(120));
    assert!(a.iter().any(|x| matches!(x, Action::Close { conn: 9 })));
    assert!(!b.has_own());
}

/// We serve: the node we offered to connects within two minutes and is
/// answered; pings are answered at most every three minutes; a callback
/// request for its ID (either layout) is passed on with the ID we know
/// it by and the asker's address; others are not.
#[test]
fn a_buddy_we_serve() {
    let t0 = Instant::now();
    let mut b = Buddies::new(ours());
    let fw_ip = Ipv4Addr::new(192, 0, 2, 50);
    let fw = Hello::amule(Md4Hash([0x33; 16]), 1234, 4662, "firewalled");
    let buddy_id = UInt128::new(0xABCD_EF01_2345_6789);
    b.expect(buddy_id, fw.user_hash, fw_ip, t0);
    assert!(!b.serving());
    // Someone else, or from elsewhere: not it.
    let other = Hello::amule(Md4Hash([0x44; 16]), 1, 4662, "other");
    assert!(!b.wants_incoming(&other, fw_ip, t0));
    assert!(!b.wants_incoming(&fw, Ipv4Addr::new(1, 2, 3, 4), t0));
    // Too late.
    assert!(!b.wants_incoming(&fw, fw_ip, t0 + Duration::from_secs(121)));
    assert!(b.wants_incoming(&fw, fw_ip, t0 + Duration::from_secs(30)));

    let conn: ConnId = 3;
    let a = b.accept(conn, &fw, fw_ip, t0);
    assert!(matches!(sent(&a)[..], [PeerPacket::HelloAnswer(_)]));
    assert_eq!(
        reports(&a),
        vec![Report::BuddyLinked {
            addr: SocketAddrV4::new(fw_ip, 4662),
            kad_port: 0,
            serving: true
        }]
    );
    assert!(b.serving() && b.owns(conn));

    let (a, _) = b.packet(conn, wire(buddy_ping()), t0);
    assert!(matches!(sent(&a)[..], [PeerPacket::BuddyPong]));
    let (a, _) = b.packet(conn, wire(buddy_ping()), t0 + Duration::from_secs(60));
    assert!(a.is_empty(), "a second ping within three minutes");
    let (a, _) = b.packet(conn, wire(buddy_ping()), t0 + Duration::from_secs(180));
    assert!(matches!(sent(&a)[..], [PeerPacket::BuddyPong]));

    let asker = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 4711);
    for id in [buddy_id, other_layout(buddy_id)] {
        let a = b.relay(id, Md4Hash([5; 16]), asker);
        assert_eq!(
            sent(&a),
            vec![PeerPacket::Callback(BuddyCallback {
                buddy_id,
                file: Md4Hash([5; 16]),
                ip: *asker.ip(),
                tcp_port: 4711,
            })]
        );
    }
    assert!(b.relay(UInt128::new(1), Md4Hash([5; 16]), asker).is_empty());

    let a = b.closed(conn);
    assert!(matches!(
        &reports(&a)[..],
        [Report::BuddyLost { serving: true, .. }]
    ));
    assert!(!b.serving());
}
