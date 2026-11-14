// SPDX-License-Identifier: GPL-2.0-or-later
//! Source exchange answers (aMule's `SourceExchangePacketTest.cpp`), when
//! to ask for sources, the secure ident and AICH packets, and secure ident
//! between two clients.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use ed2k_codec::Packet;
use ed2k_codec::Reader;
use ed2k_types::ed2k::{SOURCECLIENTREASKF, SOURCECLIENTREASKS};
use ed2k_types::{AichHash, Md4Hash, Protocol};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::packets::{self, AichRecovery, ParseContext, PeerPacket};
use crate::secident::{self, IdentConfig, IdentResult, Identity, Need, SecureIdent};
use crate::sources::{
    parse_answer, source_request_allowed, AnswerBuilder, ExchangedSource, SourceRequestInput,
};

const FILE: [u8; 16] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];

/// aMule's test source: ID, port, server address and port, hash, crypt.
const SOURCE: [u8; 29] = [
    0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0x21, 0x43, 0x65, 0x87, 0xf0, 0xde, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0x07,
];

/// The test source as we hold it, for an answer of `version`: the wire ID
/// 0x12345678 is an eD2k ID before v3 and a hybrid ID from v3.
fn test_source(version: u8) -> ExchangedSource {
    let mut hash = [0u8; 16];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = 16 + i as u8;
    }
    ExchangedSource {
        id: if version >= 3 {
            0x1234_5678u32.swap_bytes()
        } else {
            0x1234_5678
        },
        port: 0x9abc,
        server: SocketAddrV4::new(Ipv4Addr::from(0x8765_4321u32.to_le_bytes()), 0xdef0),
        user_hash: (version >= 2).then_some(Md4Hash(hash)),
        crypt_options: (version >= 4).then_some(7),
    }
}

fn check_reply(sx2: bool, sx1: u8, requested: u8, version: u8, expect_sx2: bool, len: usize) {
    let mut b = AnswerBuilder::new(Md4Hash(FILE), sx2, sx1, requested);
    assert_eq!(b.version(), version);
    b.add(&test_source(version));
    let p = b.finish().unwrap();
    assert_eq!(p.protocol, u8::from(Protocol::Emule));
    assert_eq!(p.opcode, if expect_sx2 { 0x84 } else { 0x82 });
    let mut expected = Vec::new();
    if expect_sx2 {
        expected.push(version);
    }
    expected.extend_from_slice(&FILE);
    expected.extend_from_slice(&[1, 0]);
    expected.extend_from_slice(&SOURCE[..len]);
    assert_eq!(p.payload, expected);

    // And it reads back.
    let body = &p.payload[if expect_sx2 { 17 } else { 16 }..];
    let back = parse_answer(body, expect_sx2, version).unwrap();
    assert_eq!(back, [test_source(version)]);
}

#[test]
fn legacy_versions_keep_their_wire_layout() {
    check_reply(false, 1, 0, 1, false, 12);
    check_reply(false, 2, 0, 2, false, 28);
    check_reply(false, 3, 0, 3, false, 28);
    check_reply(false, 4, 0, 4, false, 29);
}

#[test]
fn negotiates_sx2_without_using_the_sx1_version() {
    check_reply(true, 4, 1, 1, true, 12);
    check_reply(true, 1, 2, 2, true, 28);
    check_reply(true, 1, 3, 3, true, 28);
    check_reply(true, 1, 4, 4, true, 29);
    check_reply(true, 1, 255, 4, true, 29);
}

#[test]
fn uses_sx1_when_sx2_is_unavailable_or_not_requested() {
    check_reply(false, 2, 4, 2, false, 28);
    check_reply(true, 3, 0, 3, false, 28);
}

#[test]
fn does_not_send_empty_replies() {
    assert!(AnswerBuilder::new(Md4Hash(FILE), false, 2, 0)
        .finish()
        .is_none());
    assert!(AnswerBuilder::new(Md4Hash(FILE), true, 2, 4)
        .finish()
        .is_none());
}

#[test]
fn preserves_the_501_source_limit_and_count_offset() {
    for sx2 in [false, true] {
        let mut b = AnswerBuilder::new(Md4Hash(FILE), sx2, 4, 4);
        for _ in 0..501 {
            assert!(!b.is_full());
            b.add(&test_source(4));
        }
        assert!(b.is_full());
        let mut p = b.finish().unwrap();
        assert_eq!(p.protocol, u8::from(Protocol::Packed));
        p.unpack(1 << 20).unwrap();
        let mut r = Reader::new(&p.payload);
        if sx2 {
            assert_eq!(r.u8().unwrap(), 4);
        }
        assert_eq!(r.hash().unwrap(), Md4Hash(FILE));
        assert_eq!(r.u16().unwrap(), 501);
        assert_eq!(r.remaining(), 501 * 29);
    }
}

#[test]
fn compresses_only_above_354_bytes() {
    // SX1 v1: 18 + 28·12 = 354 bytes. SX2 adds a version byte.
    for sx2 in [false, true] {
        let mut b = AnswerBuilder::new(Md4Hash(FILE), sx2, 1, 1);
        for _ in 0..28 {
            b.add(&test_source(1));
        }
        let mut p = b.finish().unwrap();
        if sx2 {
            assert_eq!(p.protocol, u8::from(Protocol::Packed));
            p.unpack(1 << 20).unwrap();
            assert_eq!(p.payload.len(), 355);
        } else {
            assert_eq!(p.protocol, u8::from(Protocol::Emule));
            assert_eq!(p.payload.len(), 354);
        }
    }
}

#[test]
fn sx1_answers_must_fit_the_announced_version() {
    let body = |version: u8| {
        let mut b = AnswerBuilder::new(Md4Hash(FILE), false, version, 0);
        b.add(&test_source(version));
        b.add(&test_source(version));
        b.finish().unwrap().payload[16..].to_vec()
    };
    // The v2/v3 layout reads as v2 from a v2 peer, as v3 (hybrid) from v3+.
    assert_eq!(parse_answer(&body(2), false, 2).unwrap()[0].id, 0x1234_5678);
    let v3 = parse_answer(&body(2), false, 3).unwrap();
    assert_eq!(v3[0].id, 0x1234_5678u32.swap_bytes());
    // Layouts the peer did not announce.
    assert!(parse_answer(&body(1), false, 2).is_err());
    assert!(parse_answer(&body(2), false, 1).is_err());
    assert!(parse_answer(&body(4), false, 3).is_err());
    // A size that fits no layout.
    let mut odd = body(4);
    odd.push(0);
    assert!(parse_answer(&odd, false, 4).is_err());
    // SX2: the version must be known, the size exact.
    assert!(parse_answer(&body(4), true, 5).is_err());
    assert!(parse_answer(&body(4), true, 0).is_err());
    assert!(parse_answer(&body(4), true, 3).is_err());
    assert_eq!(parse_answer(&body(4), true, 4).unwrap().len(), 2);
}

#[test]
fn low_ids_are_not_swapped() {
    let low = ExchangedSource {
        id: 1234,
        ..test_source(4)
    };
    let mut b = AnswerBuilder::new(Md4Hash(FILE), true, 4, 4);
    b.add(&low);
    let p = b.finish().unwrap();
    assert_eq!(&p.payload[19..23], &1234u32.to_le_bytes());
    let back = parse_answer(&p.payload[17..], true, 4).unwrap();
    assert_eq!(back[0].id, 1234);
    assert!(back[0].is_low_id());
    assert_eq!(back[0].ip(), None);
    assert_eq!(
        test_source(2).ip(),
        Some(Ipv4Addr::from(0x1234_5678u32.to_le_bytes()))
    );
}

fn request_input() -> SourceRequestInput {
    SourceRequestInput {
        ext_protocol: true,
        peer_sx2: true,
        peer_sx1_version: 3,
        sources: 5,
        valid_sources: 5,
        max_sources_soft: 500,
        peer_complete: false,
        since_peer_answer: None,
        since_file_answer: Duration::ZERO,
    }
}

#[test]
fn sources_are_asked_when_the_file_needs_them() {
    let base = request_input();
    // A very rare file: ask any peer never asked.
    assert!(source_request_allowed(base));
    // Not a peer that cannot answer, nor when the file has enough.
    assert!(!source_request_allowed(SourceRequestInput {
        ext_protocol: false,
        ..base
    }));
    assert!(!source_request_allowed(SourceRequestInput {
        peer_sx2: false,
        peer_sx1_version: 1,
        ..base
    }));
    assert!(!source_request_allowed(SourceRequestInput {
        sources: 500,
        valid_sources: 500,
        ..base
    }));
    // Asked recently: wait SOURCECLIENTREASKS.
    let recent = SourceRequestInput {
        since_peer_answer: Some(Duration::from_secs(60)),
        ..base
    };
    assert!(!source_request_allowed(recent));
    assert!(source_request_allowed(SourceRequestInput {
        since_peer_answer: Some(SOURCECLIENTREASKS + Duration::from_secs(1)),
        ..base
    }));
    // A rare file (≤ 50 sources): also wait SOURCECLIENTREASKF per file.
    let rare = SourceRequestInput {
        sources: 40,
        valid_sources: 40,
        ..base
    };
    assert!(!source_request_allowed(rare));
    assert!(source_request_allowed(SourceRequestInput {
        since_file_answer: SOURCECLIENTREASKF + Duration::from_secs(1),
        ..rare
    }));
    // A common file (many sources, many of them not usable), or a
    // complete peer: four times as long. (With nearly all sources usable,
    // aMule counts the file as rare.)
    let common = SourceRequestInput {
        sources: 300,
        valid_sources: 200,
        since_file_answer: SOURCECLIENTREASKF + Duration::from_secs(1),
        ..base
    };
    assert!(!source_request_allowed(common));
    assert!(source_request_allowed(SourceRequestInput {
        since_file_answer: SOURCECLIENTREASKF * 4 + Duration::from_secs(1),
        ..common
    }));
    assert!(!source_request_allowed(SourceRequestInput {
        peer_complete: true,
        ..base
    }));
}

// ---- packets ----

fn round_trip(p: Packet) -> PeerPacket {
    let bytes = p.to_tcp_bytes().unwrap();
    PeerPacket::parse(Packet::parse_tcp(&bytes).unwrap(), ParseContext::default()).unwrap()
}

#[test]
fn source_request_packets() {
    let h = Md4Hash(FILE);
    assert_eq!(
        round_trip(packets::request_sources(h)),
        PeerPacket::RequestSources(h)
    );
    assert_eq!(
        round_trip(packets::request_sources2(h)),
        PeerPacket::RequestSources2 {
            version: 4,
            options: 0,
            hash: h
        }
    );
    let short = Packet::new(Protocol::Emule, 0x81u8, vec![0; 15]);
    assert!(PeerPacket::parse(short, ParseContext::default()).is_err());
    let long = Packet::new(Protocol::Emule, 0x83u8, vec![0; 20]);
    assert!(PeerPacket::parse(long, ParseContext::default()).is_err());
}

#[test]
fn secure_ident_packets() {
    assert_eq!(
        round_trip(secident::state_packet(Need::KeyAndSignature, 0xDEAD_BEEF)),
        PeerPacket::SecIdentState {
            need: Need::KeyAndSignature,
            challenge: 0xDEAD_BEEF
        }
    );
    assert_eq!(
        round_trip(secident::public_key_packet(&[1, 2, 3])),
        PeerPacket::PublicKey(vec![1, 2, 3])
    );
    assert_eq!(
        round_trip(secident::signature_packet(&[9; 48], None)),
        PeerPacket::Signature {
            signature: vec![9; 48],
            ip_kind: None
        }
    );
    assert_eq!(
        round_trip(secident::signature_packet(&[9; 48], Some(20))),
        PeerPacket::Signature {
            signature: vec![9; 48],
            ip_kind: Some(20)
        }
    );
    // Malformed ones are ignored, as aMule does.
    for (op, payload) in [
        (0x87u8, vec![1, 0, 0, 0]),
        (0x87, vec![3, 1, 2, 3, 4]),
        (0x85, vec![5, 1, 2]),
        (0x86, vec![2, 1, 2, 3, 4]),
        (0x86, vec![]),
    ] {
        let p = Packet::new(Protocol::Emule, op, payload);
        assert!(matches!(
            PeerPacket::parse(p, ParseContext::default()).unwrap(),
            PeerPacket::Other(_)
        ));
    }
}

#[test]
fn aich_recovery_packets() {
    let h = Md4Hash(FILE);
    let root = AichHash([3; 20]);
    assert_eq!(
        round_trip(packets::aich_request(h, 7, root)),
        PeerPacket::AichRequest {
            hash: h,
            part: 7,
            root
        }
    );
    let rec = AichRecovery {
        hash: h,
        part: 7,
        root,
        data: vec![1, 2, 3, 4],
    };
    assert_eq!(
        round_trip(packets::aich_answer(&rec)),
        PeerPacket::AichAnswer(Some(rec))
    );
    assert_eq!(
        round_trip(packets::aich_answer_failed(h)),
        PeerPacket::AichAnswer(None)
    );
    let bad = Packet::new(Protocol::Emule, 0x9Bu8, vec![0; 37]);
    assert!(PeerPacket::parse(bad, ParseContext::default()).is_err());
    let cut = Packet::new(Protocol::Emule, 0x9Cu8, vec![0; 20]);
    assert!(PeerPacket::parse(cut, ParseContext::default()).is_err());
}

// ---- secure ident between two clients ----

fn identity(seed: u64) -> Arc<Identity> {
    let ck =
        ed2k_formats::cryptkey_dat::CryptKey::generate(&mut StdRng::seed_from_u64(seed)).unwrap();
    Arc::new(Identity {
        key: ck.private_key().unwrap(),
        public: ck.public_key().unwrap(),
    })
}

fn config(ours: Arc<Identity>, peer_ip: [u8; 4], our_id: u32) -> IdentConfig {
    IdentConfig {
        ours,
        stored_key: None,
        peer_ip: Some(Ipv4Addr::from(peer_ip)),
        our_id,
        our_public_ip: None,
    }
}

/// Run both directions to the end; each side's verdict on the other.
fn exchange(
    a: &mut SecureIdent,
    b: &mut SecureIdent,
) -> (Option<IdentResult>, Option<IdentResult>) {
    let mut to_b: Vec<Packet> = a.start(11).into_iter().collect();
    let mut to_a: Vec<Packet> = b.start(22).into_iter().collect();
    let (mut va, mut vb) = (None, None);
    for _ in 0..4 {
        let deliver = |s: &mut SecureIdent, ps: Vec<Packet>, v: &mut Option<IdentResult>| {
            let mut out = Vec::new();
            for p in ps {
                match round_trip(p) {
                    PeerPacket::SecIdentState { need, challenge } => {
                        out.extend(s.on_state(need, challenge))
                    }
                    PeerPacket::PublicKey(k) => out.extend(s.on_public_key(k)),
                    PeerPacket::Signature { signature, ip_kind } => {
                        if let Some(r) = s.on_signature(&signature, ip_kind) {
                            *v = Some(r);
                        }
                    }
                    other => panic!("{other:?}"),
                }
            }
            out
        };
        let next_a = deliver(a, std::mem::take(&mut to_a), &mut va);
        let next_b = deliver(b, std::mem::take(&mut to_b), &mut vb);
        to_b = next_a;
        to_a = next_b;
    }
    (va, vb)
}

#[test]
fn two_clients_identify_each_other() {
    let (alice, bob) = (identity(1), identity(2));
    // Alice at 10.0.0.1 with a high ID, Bob at 10.0.0.2.
    let alice_id = u32::from_le_bytes([10, 0, 0, 1]);
    let bob_id = u32::from_le_bytes([10, 0, 0, 2]);
    let mut a = SecureIdent::new(config(alice.clone(), [10, 0, 0, 2], alice_id), 3);
    let mut b = SecureIdent::new(config(bob.clone(), [10, 0, 0, 1], bob_id), 3);
    let (va, vb) = exchange(&mut a, &mut b);
    assert_eq!(
        va,
        Some(IdentResult::Passed {
            key: bob.public.clone()
        })
    );
    assert_eq!(
        vb,
        Some(IdentResult::Passed {
            key: alice.public.clone()
        })
    );
    // A second signature is not considered.
    assert_eq!(a.on_signature(&[1; 48], None), None);
}

#[test]
fn v2_signatures_carry_an_address() {
    let (alice, bob) = (identity(1), identity(2));
    let alice_id = u32::from_le_bytes([10, 0, 0, 1]);
    let bob_id = u32::from_le_bytes([10, 0, 0, 2]);
    // Peers that announce v2 only.
    let mut a = SecureIdent::new(config(alice.clone(), [10, 0, 0, 2], alice_id), 2);
    let mut b = SecureIdent::new(config(bob.clone(), [10, 0, 0, 1], bob_id), 2);
    let (va, vb) = exchange(&mut a, &mut b);
    assert!(matches!(va, Some(IdentResult::Passed { .. })));
    assert!(matches!(vb, Some(IdentResult::Passed { .. })));

    // A v2 signature over the wrong address fails: Bob thinks Alice is
    // somewhere else.
    let mut a = SecureIdent::new(config(alice.clone(), [10, 0, 0, 2], alice_id), 2);
    let mut b = SecureIdent::new(config(bob, [10, 9, 9, 9], bob_id), 2);
    let (va, vb) = exchange(&mut a, &mut b);
    assert!(matches!(va, Some(IdentResult::Passed { .. })));
    assert_eq!(vb, Some(IdentResult::Failed));

    // Without the peer's IPv4 address, v2 is unusable.
    let no_ip = IdentConfig {
        peer_ip: None,
        ..config(alice, [0; 4], alice_id)
    };
    let mut c = SecureIdent::new(no_ip, 2);
    assert!(!c.usable());
    assert!(c.start(5).is_none());
}

#[test]
fn a_stored_key_is_not_replaced() {
    let (alice, bob, mallory) = (identity(1), identity(2), identity(3));
    let mut cfg = config(alice, [10, 0, 0, 2], 0x0100_000A);
    cfg.stored_key = Some(bob.public.clone());
    let mut a = SecureIdent::new(cfg, 3);
    // Only a signature is asked for.
    let PeerPacket::SecIdentState { need, .. } = round_trip(a.start(5).unwrap()) else {
        panic!()
    };
    assert_eq!(need, Need::Signature);
    assert!(a.on_public_key(mallory.public.clone()).is_empty());
}
