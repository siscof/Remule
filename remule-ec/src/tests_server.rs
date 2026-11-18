// SPDX-License-Identifier: GPL-2.0-or-later
//! The daemon's side ([`crate::server`]) against this crate's client, over
//! real sockets: logins that pass, every refusal, the lockout, and the
//! framing rules after the keys.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::client::{Client, ConnectOptions};
use crate::codes::*;
use crate::server::{AuthLimiter, Credentials, Identity, Limits, Received, ServerConn};
use crate::srp::{self, Verifier};
use crate::tag::{Packet, Tag};
use crate::Error;

const DIGEST: &str = "5ebe2294ecd0e0f08eab7690d2a6ee69"; // md5("secret")

fn identity() -> Identity {
    Identity {
        version: "3.3.0-remule".into(),
        session_id: 0x1234_5678_9ABC_DEF0,
    }
}

/// Serve connections one after the other on a thread, answering requests
/// with `handler`, until `count` have come and gone.
fn daemon(
    creds: Credentials,
    limits: Limits,
    count: usize,
    now: Arc<Mutex<u64>>,
    handler: fn(&Packet) -> Packet,
) -> (u16, thread::JoinHandle<Vec<String>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        let mut limiter = AuthLimiter::new(limits);
        let mut log = Vec::new();
        for _ in 0..count {
            let (mut s, peer) = l.accept().unwrap();
            let mut conn = ServerConn::new(peer.ip());
            loop {
                let mut header = [0u8; 8];
                if s.read_exact(&mut header).is_err() {
                    break;
                }
                let (flags, len) = match conn.check_header(header) {
                    Ok(x) => x,
                    Err(e) => {
                        log.push(format!("closed: {e}"));
                        break;
                    }
                };
                let mut body = vec![0u8; len];
                if s.read_exact(&mut body).is_err() {
                    break;
                }
                let t = *now.lock().unwrap();
                match conn.receive(flags, body, &creds, &identity(), &mut limiter, t) {
                    Received::Reply(f) => {
                        if s.write_all(&f).is_err() {
                            break;
                        }
                    }
                    Received::Request(p) => {
                        let f = conn.frame(&handler(&p)).unwrap();
                        if s.write_all(&f).is_err() {
                            break;
                        }
                    }
                    Received::Close(why) => {
                        log.push(format!("closed: {why}"));
                        break;
                    }
                }
            }
            log.extend(conn.take_log());
        }
        log
    });
    (port, h)
}

fn echo(req: &Packet) -> Packet {
    match req.opcode {
        EC_OP_STAT_REQ => Packet::new(EC_OP_STATS).with(Tag::int(EC_TAG_STATS_UL_SPEED, 42)),
        // Large enough to be compressed.
        EC_OP_GET_DLOAD_QUEUE => {
            let mut p = Packet::new(EC_OP_DLOAD_QUEUE);
            for i in 0..300u64 {
                p = p.with(Tag::int(EC_TAG_PARTFILE, i).with(Tag::string(
                    EC_TAG_PARTFILE_NAME,
                    &format!("file number {i}.iso"),
                )));
            }
            p
        }
        _ => Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, "no")),
    }
}

fn connect(port: u16, digest: &str) -> Result<Client, Error> {
    Client::connect(&ConnectOptions::new("127.0.0.1", port, digest))
}

fn reason(e: &Error) -> Option<u8> {
    match e {
        Error::AuthFailed { reason, .. } => *reason,
        _ => None,
    }
}

#[test]
fn the_verifier_is_stored_as_amule_stores_it() {
    // unittests/tests/ECSRPVector.h: digest 0123…ef, salt 00..0f.
    let salt: [u8; 16] = std::array::from_fn(|i| i as u8);
    let v = Verifier::create("0123456789abcdef0123456789abcdef", salt).unwrap();
    let text = v.encode();
    assert!(text.starts_with("v1:15:8:1:000102030405060708090a0b0c0d0e0f:4acf9c3ef792b769"));
    assert_eq!(text.len(), 10 + 32 + 1 + 768);
    assert_eq!(Verifier::decode(&text).unwrap(), v);
    // Either case; nothing else.
    assert_eq!(
        Verifier::decode(&text.to_uppercase().replacen("V1", "v1", 1)).unwrap(),
        v
    );
    for bad in [
        text.replacen("v1:15", "v1:14", 1),
        format!("{text}0"),
        text.replacen(':', ";", 5),
        format!("v1:15:8:1:{}:{}", "00".repeat(16), "00".repeat(384)),
    ] {
        assert!(Verifier::decode(&bad).is_err(), "{bad:.40}");
    }
    assert!(v.matches("0123456789abcdef0123456789abcdef"));
    assert!(!v.matches(DIGEST));
    // The empty password has no verifier.
    assert!(Verifier::create(&srp::password_digest(""), salt).is_err());
}

#[test]
fn a_client_logs_in_and_is_answered() {
    let creds = Credentials::new(Some(Verifier::create_random(DIGEST).unwrap()));
    let (port, h) = daemon(creds, Limits::default(), 1, Arc::default(), echo);
    let mut c = connect(port, DIGEST).unwrap();
    assert_eq!(c.info().version, "3.3.0-remule");
    assert_eq!(c.info().session_id, 0x1234_5678_9ABC_DEF0);
    assert!(c.info().large_tag_count);
    let r = c
        .request(&Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_CMD))
        .unwrap();
    assert_eq!(r.tag(EC_TAG_STATS_UL_SPEED).unwrap().as_int(), 42);
    let r = c.request(&Packet::new(EC_OP_GET_DLOAD_QUEUE)).unwrap();
    assert_eq!(r.tags.len(), 300);
    assert_eq!(
        r.tags[299].child_str(EC_TAG_PARTFILE_NAME),
        "file number 299.iso"
    );
    drop(c);
    let log = h.join().unwrap();
    assert!(
        log.iter()
            .any(|l| l.starts_with("Connecting client: remule-gui ")),
        "{log:?}"
    );
    assert!(log.contains(&"Access granted.".to_string()), "{log:?}");
}

#[test]
fn wrong_passwords_are_refused_then_locked_out() {
    let creds = Credentials::new(Some(Verifier::create_random(DIGEST).unwrap()));
    let limits = Limits {
        window_seconds: 60,
        threshold: 3,
        lockout_seconds: 300,
    };
    let now = Arc::new(Mutex::new(1000u64));
    let (port, h) = daemon(creds, limits, 5, now.clone(), echo);
    let wrong = srp::password_digest("guess");
    // A good login clears the count: two typos, a success, two more typos.
    for _ in 0..2 {
        let e = connect(port, &wrong).err().unwrap();
        assert_eq!(reason(&e), Some(EC_AUTH_FAIL_REJECTED), "{e}");
    }
    drop(connect(port, DIGEST).unwrap());
    let e = connect(port, &wrong).err().unwrap();
    assert_eq!(reason(&e), Some(EC_AUTH_FAIL_REJECTED));
    // Two failures in the window are still under the threshold.
    *now.lock().unwrap() = 1010;
    let e = connect(port, &wrong).err().unwrap();
    assert_eq!(reason(&e), Some(EC_AUTH_FAIL_REJECTED));
    let log = h.join().unwrap();
    assert_eq!(
        log.iter()
            .filter(|l| *l == "Authentication failed: wrong password.")
            .count(),
        4,
        "{log:?}"
    );

    let mut limiter = AuthLimiter::new(limits);
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    for t in [0, 10, 20] {
        assert_eq!(limiter.check(ip, t), None);
        limiter.note_failure(ip, t);
    }
    assert_eq!(limiter.check(ip, 30), Some(290));
    assert_eq!(limiter.check(ip, 320), None);
    // A sliding window: stamps expire one by one.
    limiter.note_failure(ip, 400);
    limiter.note_failure(ip, 450);
    limiter.note_failure(ip, 455);
    assert_eq!(limiter.check(ip, 456), Some(299));
    let mut limiter = AuthLimiter::new(limits);
    limiter.note_failure(ip, 400);
    limiter.note_failure(ip, 450);
    limiter.note_failure(ip, 461);
    assert_eq!(limiter.check(ip, 462), None);
}

#[test]
fn a_locked_out_address_is_told_when_to_come_back() {
    let creds = Credentials::new(Some(Verifier::create_random(DIGEST).unwrap()));
    let limits = Limits {
        window_seconds: 60,
        threshold: 1,
        lockout_seconds: 300,
    };
    let now = Arc::new(Mutex::new(5000u64));
    let (port, h) = daemon(creds, limits, 2, now.clone(), echo);
    // With a threshold of one, the attempt that reaches it still finishes.
    drop(connect(port, DIGEST).unwrap());
    // ... and a success forgets it.
    let _ = connect(port, &srp::password_digest("x"));
    h.join().unwrap();

    let creds = Credentials::new(Some(Verifier::create_random(DIGEST).unwrap()));
    let (port, h) = daemon(creds, limits, 2, now.clone(), echo);
    let _ = connect(port, &srp::password_digest("x"));
    *now.lock().unwrap() = 5100;
    let e = connect(port, DIGEST).err().unwrap();
    match e {
        Error::AuthFailed {
            reason,
            retry_after,
            message,
        } => {
            assert_eq!(reason, Some(EC_AUTH_FAIL_RATE_LIMITED));
            assert_eq!(retry_after, Some(200));
            assert_eq!(
                message,
                "Too many failed connection attempts; try again in 200 seconds."
            );
        }
        e => panic!("{e}"),
    }
    h.join().unwrap();
}

#[test]
fn refusals_carry_amules_reasons() {
    // No EC password.
    let (port, h) = daemon(
        Credentials::new(None),
        Limits::default(),
        1,
        Arc::default(),
        echo,
    );
    let e = connect(port, DIGEST).err().unwrap();
    assert_eq!(reason(&e), Some(EC_AUTH_FAIL_NO_PASSWORD), "{e}");
    h.join().unwrap();

    // Hand-made requests: an old client, a wrong protocol, a snapshot, a
    // request before the login, a token credential.
    let creds = Credentials::new(Some(Verifier::create_random(DIGEST).unwrap()));
    let mut limiter = AuthLimiter::default();
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let id = identity();
    let mut ask = |p: Packet| {
        let mut conn = ServerConn::new(ip);
        let body = p.encode(crate::tag::WireOpts::default());
        let reply = match conn.receive(0x20, body, &creds, &id, &mut limiter, 0) {
            Received::Reply(f) => Packet::decode(
                &f[8..],
                crate::tag::WireOpts::from_flags(u32::from_be_bytes(f[0..4].try_into().unwrap())),
            )
            .unwrap(),
            r => panic!("{r:?}"),
        };
        assert!(conn.failed());
        // Anything more is dropped.
        let again = Packet::new(EC_OP_AUTH_REQ).encode(crate::tag::WireOpts::default());
        assert!(matches!(
            conn.receive(0x20, again, &creds, &id, &mut limiter, 0),
            Received::Close(_)
        ));
        (
            reply.opcode,
            reply.tag(EC_TAG_AUTH_FAIL_REASON).map(|t| t.as_int() as u8),
            reply.message().unwrap_or_default(),
        )
    };
    let old = Packet::new(EC_OP_AUTH_REQ).with(Tag::int(
        EC_TAG_PROTOCOL_VERSION,
        EC_CURRENT_PROTOCOL_VERSION.into(),
    ));
    assert_eq!(
        ask(old.clone()),
        (
            EC_OP_AUTH_FAIL,
            Some(EC_AUTH_FAIL_CLIENT_TOO_OLD),
            "An EC client of version 3.3.0 or later is required.".into()
        )
    );
    let with_a = |p: Packet| p.with(Tag::custom(EC_TAG_SRP_A, vec![1; srp::WIDTH]));
    let r = ask(with_a(
        Packet::new(EC_OP_AUTH_REQ).with(Tag::int(EC_TAG_PROTOCOL_VERSION, 0x0100)),
    ));
    assert_eq!(r.1, Some(EC_AUTH_FAIL_INCOMPATIBLE));
    assert!(
        r.2.starts_with("Invalid protocol version.( 0x0100 != "),
        "{}",
        r.2
    );
    let r = ask(with_a(Packet::new(EC_OP_AUTH_REQ)));
    assert_eq!(r.2, "Missing protocol version tag.");
    let r = ask(with_a(old.clone()).with(Tag::hash(EC_TAG_VERSION_ID, [0; 16])));
    assert!(
        r.2.starts_with("You cannot connect to a release version"),
        "{}",
        r.2
    );
    let r = ask(Packet::new(EC_OP_STAT_REQ));
    assert_eq!(
        r,
        (
            EC_OP_AUTH_FAIL,
            Some(EC_AUTH_FAIL_INCOMPATIBLE),
            "Invalid request, please authenticate first.".into()
        )
    );
    // No cipher offer: no handshake.
    let r = ask(with_a(old));
    assert_eq!(r.2, "Invalid SRP handshake or EC verifier.");
}

/// The bytes of one framed packet, as the client sends them.
fn raw_frame(flags: u32, body: &[u8]) -> Vec<u8> {
    let mut f = flags.to_be_bytes().to_vec();
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(body);
    f
}

#[test]
fn framing_is_checked_as_ecsocket_does() {
    let creds = Credentials::new(Some(Verifier::create_random(DIGEST).unwrap()));
    let mut limiter = AuthLimiter::default();
    let id = identity();
    let mut conn = ServerConn::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    // Before the login: 16 MiB at most.
    let mut h = [0u8; 8];
    h[0..4].copy_from_slice(&0x20u32.to_be_bytes());
    h[4..8].copy_from_slice(&(16u32 * 1024 * 1024 + 1).to_be_bytes());
    assert!(conn.check_header(h).is_err());
    h[4..8].copy_from_slice(&(16u32 * 1024 * 1024).to_be_bytes());
    assert!(conn.check_header(h).is_ok());
    // Bad flags, and a sealed packet before any keys.
    for flags in [0x40, 0x20 | 0x100, 0x20 | EC_FLAG_ENCRYPTED] {
        assert!(matches!(
            conn.receive(flags, vec![1, 0], &creds, &id, &mut limiter, 0),
            Received::Close(_)
        ));
    }
}

#[test]
fn a_clear_packet_after_the_keys_drops_the_connection() {
    let creds = Credentials::new(Some(Verifier::create_random(DIGEST).unwrap()));
    let (port, h) = daemon(creds, Limits::default(), 1, Arc::default(), echo);
    // Log in for real, then inject a clear packet on the same socket.
    let mut c = connect(port, DIGEST).unwrap();
    let mut s: TcpStream = c.take_stream_for_tests();
    let body = Packet::new(EC_OP_STAT_REQ).encode(crate::tag::WireOpts::default());
    s.write_all(&raw_frame(0x20, &body)).unwrap();
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).unwrap_or(0), 0, "the daemon hangs up");
    let log = h.join().unwrap();
    assert!(
        log.iter()
            .any(|l| l.contains("unencrypted packet after key setup")),
        "{log:?}"
    );
}
