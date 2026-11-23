// SPDX-License-Identifier: GPL-2.0-or-later
//! Known answers from an independent Python reference written from the C++
//! (its RC4 checked against the RFC 6229 and "Key"/"Plaintext" vectors),
//! plus aMule's own unittests (RC4Test, ClientCreditsTest, SecIdentTest,
//! EncryptionRequirementTest, UdpObfuscationPolicyTest).

use std::net::Ipv4Addr;

use ed2k_types::{Md4Hash, UInt128};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::credits::{credit_ratio, score_ratio, IdentState};
use crate::ident::{self, ChallengeIp};
use crate::rc4::Rc4;
use crate::stream::{self, StreamCrypt, StreamError};
use crate::udp::{self, ClientKey, OwnKeys, SendForm, VerifyKeys};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn keystream(mut r: Rc4, n: usize) -> Vec<u8> {
    r.crypt(&vec![0; n])
}

// ---------------------------------------------------------------- RC4

#[test]
fn rc4_published_vectors() {
    assert_eq!(
        Rc4::new(b"Key").crypt(b"Plaintext"),
        hex("BBF316E8D940AF0AD3")
    );
    // RFC 6229, 40-bit key 0x0102030405, offset 0.
    assert_eq!(
        keystream(Rc4::new(&[1, 2, 3, 4, 5]), 16),
        hex("B2396305F03DC027CCC3524A0A1118A8")
    );
}

/// RC4Test: KnownAnswersWithAndWithoutDiscard (a zero MD5Sum key).
#[test]
fn rc4_amule_known_answers() {
    assert_eq!(
        keystream(Rc4::from_md5([0; 16], false), 16),
        hex("de188941a3375d3a8a061e67576e926d")
    );
    assert_eq!(
        keystream(Rc4::from_md5([0; 16], true), 16),
        hex("9a8898ebed25895336ae119ae503cad6")
    );
    assert_eq!(
        keystream(Rc4::from_md5_of(b"remule", true), 16),
        hex("B7DC8DE68F6EED3EDF1CD6E1E09642F2")
    );
}

/// RC4Test: ChunkingInPlaceAndDiscardPreserveStream.
#[test]
fn rc4_chunking_and_skip_preserve_the_stream() {
    for discard in [false, true] {
        let input: Vec<u8> = (0..8192).map(|i| (i * 31) as u8).collect();
        let whole = Rc4::from_md5_of(b"RC4 streaming regression", discard).crypt(&input);
        let mut c = Rc4::from_md5_of(b"RC4 streaming regression", discard);
        let mut actual = input.clone();
        let mut off = 0;
        for len in [1, 4, 255, 256, 257, 1300] {
            c.apply(&mut actual[off..off + len]);
            off += len;
        }
        c.skip(1024);
        off += 1024;
        c.apply(&mut actual[off..]);
        let skipped = off - 1024..off;
        for i in 0..actual.len() {
            if !skipped.contains(&i) {
                assert_eq!(actual[i], whole[i], "byte {i}");
            }
        }
    }
}

// ---------------------------------------------------------------- TCP

fn hash() -> Md4Hash {
    Md4Hash(std::array::from_fn(|i| i as u8))
}

#[test]
fn client_handshake_known_answer() {
    let (mut a, req) = StreamCrypt::client_with(&hash(), 0x42, 0x1234_5678, &[0xAA, 0xBB]);
    assert_eq!(req, hex("4278563412788CF755D47F7AC8B4"));
    assert!(!a.is_ready());
    assert_eq!(a.seal(b"x"), Err(StreamError::NotReady));

    let mut b = StreamCrypt::incoming_with(hash(), vec![0x01]);
    let r = b.receive(&req).unwrap();
    assert!(r.data.is_empty());
    assert_eq!(r.reply, hex("62934590690416"));
    assert!(b.is_obfuscated() && b.is_ready());
    assert_eq!(b.peer_methods(), Some((0, 0)));

    let r = a.receive(&r.reply).unwrap();
    assert!(r.data.is_empty() && r.reply.is_empty());
    assert!(a.is_ready());

    let hello = a.seal(b"hello").unwrap();
    assert_eq!(hello, hex("4009FF8E99"));
    assert_eq!(b.receive(&hello).unwrap().data, b"hello");
    let world = b.seal(b"world").unwrap();
    assert_eq!(world, hex("76AAB71B90"));
    assert_eq!(a.receive(&world).unwrap().data, b"world");
}

#[test]
fn client_handshake_one_byte_at_a_time_and_data_after_it() {
    let mut rng = StdRng::seed_from_u64(7);
    for _ in 0..20 {
        let (mut a, req) = StreamCrypt::client(&hash(), stream::DEFAULT_MAX_PADDING, &mut rng);
        assert!(!stream::is_protocol_byte(req[0]));
        let mut b = StreamCrypt::incoming(hash(), stream::DEFAULT_MAX_PADDING, &mut rng);
        let mut reply = Vec::new();
        for byte in &req {
            let r = b.receive(std::slice::from_ref(byte)).unwrap();
            assert!(r.data.is_empty());
            reply.extend(r.reply);
        }
        assert!(b.is_ready());
        // B's answer and its first packet arrive in one read.
        reply.extend(b.seal(b"\xE3first packet").unwrap());
        let r = a.receive(&reply).unwrap();
        assert_eq!(r.data, b"\xE3first packet");
        let x = a.seal(b"more").unwrap();
        assert_eq!(b.receive(&x).unwrap().data, b"more");
    }
}

#[test]
fn wrong_user_hash_fails_on_the_magic() {
    let (_, req) = StreamCrypt::client_with(&hash(), 0x42, 1, &[]);
    let mut b = StreamCrypt::incoming_with(Md4Hash([0xFF; 16]), vec![]);
    assert!(matches!(b.receive(&req), Err(StreamError::BadMagic(_))));
    assert_eq!(b.receive(b"more"), Err(StreamError::Failed));
}

#[test]
fn bad_method_is_refused() {
    let (mut a, _) = StreamCrypt::client_with(&hash(), 0x42, 9, &[]);
    let (_, mut b_send) = stream::client_keys(&hash(), 9);
    let mut answer = stream::MAGICVALUE_SYNC.to_le_bytes().to_vec();
    answer.extend([0x07, 0]);
    b_send.apply(&mut answer);
    assert_eq!(a.receive(&answer), Err(StreamError::BadMethod(7)));
}

#[test]
fn plain_incoming_connection_passes_through() {
    let mut b = StreamCrypt::incoming_with(hash(), vec![]);
    let r = b.receive(b"\xE3\x05\x00\x00\x00\x01abcd").unwrap();
    assert_eq!(r.data, b"\xE3\x05\x00\x00\x00\x01abcd");
    assert!(!b.is_obfuscated());
    assert_eq!(b.seal(b"\xC5x").unwrap(), b"\xC5x");
    // Nothing read yet and we write first: plain.
    let mut c = StreamCrypt::incoming_with(hash(), vec![]);
    assert_eq!(c.receive(b"").unwrap(), Default::default());
    assert_eq!(c.seal(b"q").unwrap(), b"q");
    assert_eq!(c.receive(b"\x01").unwrap().data, b"\x01");
}

const DH_B: &str = "783B52F4E16E1EC23D28872C9D51ABFFDC7AEB0EE65CD55851646B3A09E2583586DDFE22256ECBF049F2C1BD1EA081E60A932DB7EAFA74AF31FA8FF32B9EEB9F9D55CB3D35E44B9CD0BD4D357818FC11A4382A656EAD10B38238142715356834";

#[test]
fn diffie_hellman_known_answer() {
    let a: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
    let b: [u8; 16] = std::array::from_fn(|i| i as u8 + 0x11);
    assert_eq!(stream::dh_public(&a).to_vec(), hex("76B0A1B114C92A87A2C881DDEC997EAB0C495DB426627CA35C20A1185E0F88089D6063A761DCBFED3CC999DDE35D1BC20AF17066183771FB0E4B298F59CB5F9D3DD7F8CA1FE3E31F1811735DB5DFD79C8745B2EEACF477EA7A1D6472A453DB35"));
    assert_eq!(stream::dh_public(&b).to_vec(), hex(DH_B));
    let s = hex("510F309DFC329EFACE666F1C16AEB56D35AEEF543D2981E4C01BF24BF53CF2927B37FB780B971A33B4D21DE47CA2808B2CB72AA57F36F0B4700A26339B4E74FD19CD63FED40646153EE99DAEBAF42FDD942B05D44E65717E46E66ACEB957B16A");
    assert_eq!(stream::dh_shared(&stream::dh_public(&b), &a).to_vec(), s);
    assert_eq!(stream::dh_shared(&stream::dh_public(&a), &b).to_vec(), s);
}

#[test]
fn server_handshake_known_answer() {
    let a: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
    let (mut c, req) = StreamCrypt::server_with(0x21, &a, &[0x55; 3], vec![0x77]);
    let mut want = vec![0x21];
    want.extend(stream::dh_public(&a));
    want.extend([3, 0x55, 0x55, 0x55]);
    assert_eq!(req, want);

    let mut answer = hex(DH_B);
    answer.extend(hex("75468AF8B1155AC0"));
    // Split mid-prime and mid-magic.
    let r1 = c.receive(&answer[..50]).unwrap();
    let r2 = c.receive(&answer[50..99]).unwrap();
    let r3 = c.receive(&answer[99..]).unwrap();
    for r in [r1, r2, r3] {
        assert!(r.data.is_empty() && r.reply.is_empty());
    }
    assert!(c.is_ready());
    // Our answer waits for the first packet.
    assert_eq!(c.seal(b"ping").unwrap(), hex("644F7FDB4621052576042C"));
    assert!(c.take_pending().is_empty());
}

#[test]
fn server_handshake_random_parts() {
    let mut rng = StdRng::seed_from_u64(1);
    let (mut c, req) = StreamCrypt::server(&mut rng);
    assert!((98..=113).contains(&req.len()));
    assert_eq!(req.len(), 1 + 96 + 1 + req[97] as usize);
    // A fake server.
    let b = [9u8; 16];
    let shared = stream::dh_shared(&req[1..97].try_into().unwrap(), &b);
    let (mut s_recv, mut s_send) = stream::server_keys(&shared);
    let mut answer = stream::dh_public(&b).to_vec();
    let mut enc = stream::MAGICVALUE_SYNC.to_le_bytes().to_vec();
    enc.extend([0, 0, 0]);
    s_send.apply(&mut enc);
    answer.extend(enc);
    assert_eq!(c.receive(&answer).unwrap(), Default::default());
    let mut sent = c.take_pending();
    sent.extend(c.seal(b"login").unwrap());
    s_recv.apply(&mut sent);
    assert_eq!(&sent[..4], stream::MAGICVALUE_SYNC.to_le_bytes());
    assert_eq!(sent[4], stream::ENM_OBFUSCATION);
    let pad = sent[5] as usize;
    assert!(pad <= 15);
    assert_eq!(&sent[6 + pad..], b"login");
}

/// EncryptionRequirementTest.
#[test]
fn refusing_plain_connections() {
    use stream::must_refuse_plain_connection as refuse;
    assert!(!refuse(false, true, false));
    assert!(!refuse(true, true, false));
    assert!(refuse(false, false, false));
    assert!(!refuse(false, false, true));
    assert!(refuse(true, false, true));
}

// ---------------------------------------------------------------- UDP

fn kad_id() -> UInt128 {
    UInt128::from_wire_bytes(std::array::from_fn(|i| 0x30 + i as u8))
}

#[test]
fn udp_known_answers() {
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    let ed2k = ClientKey::Ed2k {
        receiver: hash(),
        sender_ip: ip,
    };
    let none = VerifyKeys::default();
    let p = udp::encrypt_client_with(b"\xC5\x01abc", &ed2k, none, 0x43, 0xBEEF);
    assert_eq!(p, hex("43EFBE5A43E2678D0BDC67DE33"));

    let v = VerifyKeys {
        receiver: 0x1122_3344,
        sender: 0x5566_7788,
    };
    let p = udp::encrypt_client_with(b"\xE4\x01abc", &ClientKey::KadId(kad_id()), v, 0x40, 0xBEEF);
    assert_eq!(p, hex("40EFBE1019AE7D9DA465A2F8A76EDAF47C9B71D22B"));

    let v2 = VerifyKeys {
        receiver: 0xCAFE_BABE,
        sender: 0x5566_7788,
    };
    let key = ClientKey::KadVerifyKey(0xCAFE_BABE);
    let p = udp::encrypt_client_with(b"\xE4\x01abc", &key, v2, 0x42, 0xBEEF);
    assert_eq!(p, hex("42EFBE09AEDC98A3795F59599875F91AAD57CEE300"));

    let p = udp::encrypt_server_with(b"\xE3\x96abc", 0xDEAD_BEEF, 0x50, 0x1234);
    assert_eq!(p, hex("503412F7B1B3465E0D34DF2029"));
    let from = hex("5034121C738EE1331FF97BBA57");
    assert_eq!(
        udp::encrypt_from_server(b"\xE3\x97abc", 0xDEAD_BEEF, 0x50, 0x1234),
        from
    );
    assert_eq!(
        udp::decrypt_server(&from, 0xDEAD_BEEF).unwrap(),
        b"\xE3\x97abc"
    );
    assert_eq!(udp::decrypt_server(&from, 0xDEAD_BEEE), None);
    assert_eq!(udp::decrypt_server(&from, 0), None);

    assert_eq!(
        udp::udp_verify_key(0x0102_0304, Ipv4Addr::new(10, 0, 0, 1)),
        0x21AD_A7BB
    );
}

#[test]
fn udp_client_round_trips_with_every_key() {
    let mut rng = StdRng::seed_from_u64(3);
    let sender_ip = Ipv4Addr::new(192, 0, 2, 9);
    let own = OwnKeys {
        user_hash: hash(),
        sender_ip,
        kad_id: Some(kad_id()),
        verify_key: Some(0xABCD_0001),
    };
    let v = VerifyKeys {
        receiver: 0xABCD_0001,
        sender: 77,
    };
    let keys = [
        ClientKey::Ed2k {
            receiver: hash(),
            sender_ip,
        },
        ClientKey::KadId(kad_id()),
        ClientKey::KadVerifyKey(0xABCD_0001),
    ];
    for _ in 0..50 {
        for key in &keys {
            let p = udp::encrypt_client(b"\xE4\x20payload", key, v, &mut rng);
            let m = p[0];
            assert!(![0xC5, 0xE5, 0xE4, 0xA3, 0xB2, 0xD4].contains(&m));
            let d = udp::decrypt_client(&p, &own).unwrap();
            assert_eq!(d.payload, b"\xE4\x20payload");
            let kad = !matches!(key, ClientKey::Ed2k { .. });
            assert_eq!(d.kad, kad);
            assert_eq!(d.key, key.kind());
            assert_eq!(d.verify, if kad { v } else { VerifyKeys::default() });
            // The marker is only a hint: any marker still decrypts.
            let mut q = p.clone();
            q[0] = 0x01;
            assert!(udp::decrypt_client(&q, &own).is_some());
        }
    }
    // Without Kad, only the eD2k key is tried.
    let ed2k_only = OwnKeys {
        kad_id: None,
        verify_key: None,
        ..own
    };
    let p = udp::encrypt_client(b"xx", &keys[1], v, &mut rng);
    assert_eq!(udp::decrypt_client(&p, &ed2k_only), None);
    let p = udp::encrypt_client(b"xx", &keys[0], v, &mut rng);
    assert!(udp::decrypt_client(&p, &ed2k_only).is_some());
}

#[test]
fn udp_plain_and_short_packets_are_not_decrypted() {
    let own = OwnKeys {
        user_hash: hash(),
        sender_ip: Ipv4Addr::LOCALHOST,
        kad_id: None,
        verify_key: None,
    };
    assert_eq!(udp::decrypt_client(b"\xC5\x01abcdefgh", &own), None);
    assert_eq!(udp::decrypt_client(b"\x01abcdefg", &own), None);
    assert_eq!(udp::decrypt_client(b"\x01abcdefghijk", &own), None);
    assert_eq!(udp::decrypt_server(b"\xE3abcdefghijk", 5), None);
    // A Kad packet too short for its verify keys.
    let key = ClientKey::KadVerifyKey(5);
    let p = udp::encrypt_client_with(b"", &key, VerifyKeys::default(), 0x42, 1);
    let kad = OwnKeys {
        verify_key: Some(5),
        ..own
    };
    assert_eq!(udp::decrypt_client(&p, &kad), None);
}

/// UdpObfuscationPolicyTest.
#[test]
fn udp_send_form() {
    let ip = 0x0100_007F;
    assert_eq!(udp::send_form(true, false, false, ip), SendForm::Obfuscated);
    assert_eq!(udp::send_form(true, true, false, ip), SendForm::Obfuscated);
    assert_eq!(udp::send_form(true, false, false, 0), SendForm::Plain);
    assert_eq!(udp::send_form(false, false, false, ip), SendForm::Plain);
    assert_eq!(udp::send_form(true, false, true, 0), SendForm::Obfuscated);
    assert_eq!(udp::send_form(true, true, false, 0), SendForm::Drop);
    assert_eq!(udp::send_form(false, true, false, ip), SendForm::Drop);
}

// ---------------------------------------------------------------- ident

fn keypair(seed: u64) -> (rsa::RsaPrivateKey, Vec<u8>) {
    let ck =
        ed2k_formats::cryptkey_dat::CryptKey::generate(&mut StdRng::seed_from_u64(seed)).unwrap();
    (ck.private_key().unwrap(), ck.public_key().unwrap())
}

/// `Debug_CheckCrypting`, plus what must make verification fail.
#[test]
fn secure_ident_signatures() {
    let (alice, alice_pub) = keypair(1);
    let (_, bob_pub) = keypair(2);
    assert_eq!(alice_pub.len(), 76);
    let ip = Some(ChallengeIp::LocalClient(Ipv4Addr::new(203, 0, 113, 7)));
    for ip in [None, ip, Some(ChallengeIp::None)] {
        // Alice proves herself to Bob, who sent challenge 0x1234.
        let sig = ident::sign(&alice, &bob_pub, 0x1234, ip).unwrap();
        assert_eq!(sig.len(), 48);
        assert!(ident::verify(&alice_pub, &bob_pub, 0x1234, ip, &sig).unwrap());
        assert!(!ident::verify(&alice_pub, &bob_pub, 0x1235, ip, &sig).unwrap());
        assert!(!ident::verify(&bob_pub, &bob_pub, 0x1234, ip, &sig).unwrap());
        assert!(!ident::verify(&alice_pub, &alice_pub, 0x1234, ip, &sig).unwrap());
        let mut bad = sig.clone();
        bad[5] ^= 1;
        assert!(!ident::verify(&alice_pub, &bob_pub, 0x1234, ip, &bad).unwrap());
    }
    let other_ip = Some(ChallengeIp::RemoteClient(Ipv4Addr::new(203, 0, 113, 7)));
    let sig = ident::sign(&alice, &bob_pub, 1, other_ip).unwrap();
    assert!(!ident::verify(&alice_pub, &bob_pub, 1, ip, &sig).unwrap());
    assert!(ident::verify(&[1, 2, 3], &bob_pub, 1, None, &sig).is_err());
    assert!(ident::sign(&alice, &[0; 81], 1, None).is_err());
}

#[test]
fn signed_message_layout() {
    let m = ident::signed_message(
        b"KEY",
        0x0403_0201,
        Some(ChallengeIp::RemoteClient(Ipv4Addr::new(192, 0, 2, 1))),
    );
    assert_eq!(m, b"KEY\x01\x02\x03\x04\xC0\x00\x02\x01\x0A");
}

/// SecIdentTest.
#[test]
fn secure_ident_versions() {
    use ident::{signature_version as sv, supported_versions as supp};
    assert_eq!(supp(false, false), 0);
    assert_eq!(supp(false, true), 0);
    assert_eq!(supp(true, false), 1);
    assert_eq!(supp(true, true), 3);
    assert_eq!(
        (sv(0, true), sv(1, true), sv(2, true), sv(3, true)),
        (0, 1, 2, 1)
    );
    assert_eq!(
        (sv(0, false), sv(1, false), sv(2, false), sv(3, false)),
        (0, 1, 0, 1)
    );
    assert_eq!((sv(0xfc, true), sv(0xfc, false)), (0, 0));
    assert_eq!(
        (sv(0xfd, false), sv(0xfe, true), sv(0xfe, false)),
        (1, 2, 0)
    );

    let (login, udp, high_id) = (0x0171_00cb, 0x0271_00cb, 0x0a71_00cb);
    let rc = ident::remote_client_challenge_ip;
    assert_eq!(rc(udp, login, login, true, 5), udp);
    assert_eq!(rc(0, login, login, true, 5), login);
    assert_eq!(rc(0, 0, login, true, 5), login);
    assert_eq!(rc(0, 0, login, false, high_id), high_id);
}

// ---------------------------------------------------------------- credits

/// ClientCreditsTest: CreditRatioClampsAtBothEnds and the identity gate.
#[test]
fn credit_ratios() {
    assert_eq!(credit_ratio(999_999, 0), 1.0);
    let leech = credit_ratio(10_485_760, 0); // sqrt(12)
    assert!(leech > 3.4 && leech < 3.5, "{leech}");
    assert_eq!(credit_ratio(4_000_000_000, 0), 10.0);
    assert_eq!(credit_ratio(2_000_000, 100_000_000), 1.0);
    // 2·down/up below the sqrt cap.
    assert_eq!(credit_ratio(100_000_000, 80_000_000), 2.5);

    let down = 100_000_000;
    assert_eq!(score_ratio(IdentState::Needed, true, down, 0), 1.0);
    assert_eq!(score_ratio(IdentState::Failed, true, down, 0), 1.0);
    assert_eq!(score_ratio(IdentState::BadGuy, true, down, 0), 1.0);
    let r = credit_ratio(down, 0);
    assert!(r > 1.0);
    assert_eq!(score_ratio(IdentState::Needed, false, down, 0), r);
    assert_eq!(score_ratio(IdentState::Identified, true, down, 0), r);
    assert_eq!(score_ratio(IdentState::NotAvailable, true, down, 0), r);
}
