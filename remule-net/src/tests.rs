// SPDX-License-Identifier: GPL-2.0-or-later
//! Unit tests; the buckets and limits run on tokio's paused clock.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use ed2k_codec::Packet;
use ed2k_crypto::stream as cs;
use ed2k_types::{Md4Hash, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::codec::{Decoder, Encoder};

use crate::codec::{CodecError, PacketCodec, MAX_PACKET_SIZE};
use crate::conn::{establish, ConnConfig, Handshake, NetError};
use crate::limits::{recommended_max_connections, ConnectionLimiter, ConnectionLimits};
use crate::throttle::{min_frag_size, send_size, Bandwidth, Priority, RateLimiter};

fn packet(op: u8, len: usize) -> Packet {
    Packet::new(Protocol::Edonkey, op, (0..len).map(|i| i as u8).collect())
}

// ---------------------------------------------------------------- codec

#[test]
fn codec_round_trip_in_any_pieces() {
    let mut c = PacketCodec::new();
    let mut wire = BytesMut::new();
    for (op, len) in [(0x01, 0), (0x02, 1), (0x58, 5000)] {
        c.encode(packet(op, len), &mut wire).unwrap();
    }
    assert_eq!(&wire[..6], [0xE3, 1, 0, 0, 0, 0x01]);
    let mut got = Vec::new();
    let mut buf = BytesMut::new();
    for b in wire.iter() {
        buf.extend_from_slice(&[*b]);
        while let Some(p) = c.decode(&mut buf).unwrap() {
            got.push(p);
        }
    }
    assert_eq!(got, [packet(0x01, 0), packet(0x02, 1), packet(0x58, 5000)]);
    assert!(buf.is_empty());
}

#[test]
fn codec_refuses_bad_and_huge_headers() {
    let mut c = PacketCodec::new();
    let mut zero = BytesMut::from(&[0xE3, 0, 0, 0, 0, 1][..]);
    assert!(matches!(c.decode(&mut zero), Err(CodecError::Header(_))));
    let len = (MAX_PACKET_SIZE + 2).to_le_bytes();
    let mut huge = BytesMut::from(&[0xE3, len[0], len[1], len[2], len[3], 1][..]);
    assert!(matches!(
        PacketCodec::new().decode(&mut huge),
        Err(CodecError::TooBig(n)) if n == MAX_PACKET_SIZE + 1
    ));
    // Exactly the limit is fine (and nothing is allocated before it arrives).
    let len = (MAX_PACKET_SIZE + 1).to_le_bytes();
    let mut max = BytesMut::from(&[0xE3, len[0], len[1], len[2], len[3], 1][..]);
    let mut c = PacketCodec::new();
    assert!(c.decode(&mut max).unwrap().is_none());
    assert_eq!(c.wanted(0), MAX_PACKET_SIZE as usize);
}

// ---------------------------------------------------------------- throttle

#[test]
fn fragment_sizes() {
    assert_eq!((min_frag_size(0), send_size(0)), (1300, 2600));
    assert_eq!((min_frag_size(6 * 1024), send_size(6 * 1024)), (1300, 2600));
    assert_eq!((min_frag_size(5 * 1024), send_size(5 * 1024)), (536, 536));
}

#[tokio::test(start_paused = true)]
async fn download_bucket_refills_per_tick_and_caps_at_two() {
    let l = RateLimiter::download(10 * 1024); // 3072 bytes per 300 ms tick
    let t0 = Instant::now();
    // Empty at first: the first tick's budget, partially.
    assert_eq!(l.acquire(10_000, Priority::Standard).await, 3072);
    assert_eq!(t0.elapsed(), Duration::from_millis(300));
    // A long quiet spell banks at most two ticks.
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(l.acquire(100_000, Priority::Standard).await, 6144);
    // Refunds come back at once.
    l.refund(1000);
    let t1 = Instant::now();
    assert_eq!(l.acquire(5000, Priority::Standard).await, 1000);
    assert_eq!(t1.elapsed(), Duration::ZERO);
    assert_eq!(l.used(), 3072 + 6144);
}

#[tokio::test(start_paused = true)]
async fn rates_hold_over_time() {
    for kbps in [1u64, 5, 50, 1000] {
        let rate = kbps * 1024;
        for l in [RateLimiter::download(rate), RateLimiter::upload(rate)] {
            let t0 = Instant::now();
            let mut got = 0u64;
            while t0.elapsed() < Duration::from_secs(20) {
                got += l.acquire(send_size(rate), Priority::Standard).await as u64;
            }
            let secs = t0.elapsed().as_secs_f64();
            // At most the rate, plus what the bucket held at the start (up
            // to two download ticks, or one upload send) and the last send,
            // which may go into debt.
            let max = rate as f64 * (secs + 0.6) + 2.0 * send_size(rate) as f64;
            assert!(
                got as f64 <= max && got as f64 >= rate as f64 * secs * 0.95,
                "{kbps} KiB/s: got {got} bytes in {secs} s"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn upload_goes_into_debt_and_waits_it_out() {
    let l = RateLimiter::upload(1000 * 1024); // 10240 per 10 ms tick
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Any budget lets a whole send through.
    assert_eq!(l.acquire(30_000, Priority::Standard).await, 30_000);
    let t = Instant::now();
    assert_eq!(l.acquire(1, Priority::Standard).await, 1);
    // 10240 - 30000 = -19760: two more ticks, then the one that crosses 0.
    assert_eq!(t.elapsed(), Duration::from_millis(20));
}

#[tokio::test(start_paused = true)]
async fn unlimited_never_waits() {
    let bw = Bandwidth::unlimited();
    let t = Instant::now();
    for _ in 0..1000 {
        assert_eq!(
            bw.upload.acquire(1 << 20, Priority::Standard).await,
            1 << 20
        );
        assert_eq!(
            bw.download.acquire(1 << 20, Priority::Standard).await,
            1 << 20
        );
    }
    assert_eq!(t.elapsed(), Duration::ZERO);
    // Limited later, it starts from an empty bucket.
    bw.set_limits(10, 0);
    assert_eq!(bw.upload.rate(), 10 * 1024);
    let t = Instant::now();
    bw.upload.acquire(1, Priority::Standard).await;
    assert_eq!(t.elapsed(), Duration::from_millis(10));
}

#[tokio::test(start_paused = true)]
async fn control_packets_go_before_file_data() {
    let l = Arc::new(RateLimiter::upload(100 * 1024));
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut tasks = Vec::new();
    // File data queues first, then control packets.
    for (i, prio) in [
        (0, Priority::Standard),
        (1, Priority::Standard),
        (2, Priority::Control),
        (3, Priority::Control),
    ] {
        let (l, order) = (l.clone(), order.clone());
        tasks.push(tokio::spawn(async move {
            l.acquire(5000, prio).await;
            order.lock().unwrap().push(i);
        }));
        tokio::task::yield_now().await;
    }
    for t in tasks {
        t.await.unwrap();
    }
    let order = order.lock().unwrap().clone();
    let pos = |i| order.iter().position(|&x| x == i).unwrap();
    assert!(pos(2) < pos(0) && pos(2) < pos(1), "{order:?}");
    assert!(pos(3) < pos(0) && pos(3) < pos(1), "{order:?}");
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_control_wait_does_not_block_file_data() {
    let l = RateLimiter::upload(1024);
    let _ = tokio::time::timeout(Duration::from_millis(1), l.acquire(10, Priority::Control)).await;
    let t = Instant::now();
    l.acquire(10, Priority::Standard).await;
    assert!(t.elapsed() <= Duration::from_millis(20));
}

// ---------------------------------------------------------------- limits

#[test]
fn recommended_connections() {
    let r = recommended_max_connections;
    assert_eq!(
        [
            r(None),
            r(Some(1024)),
            r(Some(520)),
            r(Some(256)),
            r(Some(19))
        ],
        [500, 500, 500, 246, 19]
    );
}

#[test]
fn too_many_sockets() {
    let mut l = ConnectionLimits::new(3, 50);
    for _ in 0..4 {
        assert!(!l.too_many(true));
        l.opened();
    }
    // Above MaxConnections, not at it.
    assert!(l.too_many(true));
    l.closed();
    assert!(!l.too_many(true));

    // The per-five limit shrinks with the spike over the average.
    let mut l = ConnectionLimits::new(1000, 4);
    assert_eq!(l.per_five_modifier(), 1.0);
    for _ in 0..4 {
        l.opened();
    }
    // Spike 4 over an average of 0, tolerance 10: 4 > 4 × 0.6.
    assert!((l.per_five_modifier() - 0.6).abs() < 1e-6);
    assert!(l.too_many(false));
    assert!(!l.too_many(true));
    l.reset_interval();
    assert!(!l.too_many(false));
    // The average follows the open count; at it, the modifier is 1 again.
    for _ in 0..200 {
        l.update_status();
    }
    assert!(l.average() > 3.0);
    l.closed();
    assert_eq!(l.per_five_modifier(), 1.0);
}

#[tokio::test(start_paused = true)]
async fn the_limiter_waits_for_the_next_interval_or_a_closed_slot() {
    let lim = ConnectionLimiter::new(1, 1000);
    let a = lim.try_open().unwrap();
    let b = lim.try_open().unwrap(); // 2 > 1 only after this one
    assert!(lim.try_open().is_none());
    let lim2 = lim.clone();
    let waiter = tokio::spawn(async move { lim2.open().await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!waiter.is_finished());
    drop(a);
    let c = waiter.await.unwrap();
    assert_eq!(lim.snapshot().open(), 2);
    drop((b, c));

    // The per-five counter: 3 in this interval, then wait for the next one.
    let lim = ConnectionLimiter::new(1000, 2);
    let mut permits = Vec::new();
    for _ in 0..3 {
        permits.push(lim.try_open().unwrap());
        drop(permits.pop());
    }
    assert!(lim.try_open().is_none());
    let t = Instant::now();
    let _p = lim.open().await;
    assert_eq!(t.elapsed(), Duration::from_secs(5));
}

// ---------------------------------------------------------------- connections

fn hash() -> Md4Hash {
    Md4Hash([0x5A; 16])
}

fn config() -> ConnConfig {
    ConnConfig::new(Arc::new(Bandwidth::unlimited()))
}

/// Connect A and B over a pipe, pass packets both ways; whether each
/// writer is obfuscated.
async fn exchange(a: Handshake, b: Handshake) -> (bool, bool) {
    let (x, y) = tokio::io::duplex(1 << 16);
    let big = packet(0x46, 100_000);
    let small = packet(0x01, 3);
    let side_a = async {
        let (mut ar, mut aw) = establish(x, a, config()).await.unwrap();
        aw.send(&small, Priority::Control).await.unwrap();
        aw.send(&big, Priority::Standard).await.unwrap();
        assert_eq!(ar.recv().await.unwrap(), Some(small.clone()));
        // A clean close between packets.
        aw.shutdown().await.unwrap();
        aw.is_obfuscated()
    };
    let side_b = async {
        let (mut br, mut bw) = establish(y, b, config()).await.unwrap();
        assert_eq!(br.recv().await.unwrap(), Some(small.clone()));
        assert_eq!(br.recv().await.unwrap(), Some(big.clone()));
        bw.send(&small, Priority::Control).await.unwrap();
        assert_eq!(br.recv().await.unwrap(), None);
        bw.is_obfuscated()
    };
    tokio::join!(side_a, side_b)
}

fn incoming(require: bool) -> Handshake {
    Handshake::Incoming {
        own_hash: hash(),
        max_padding: cs::DEFAULT_MAX_PADDING,
        require,
    }
}

#[tokio::test]
async fn plain_and_obfuscated_connections() {
    assert_eq!(
        exchange(Handshake::Plain, Handshake::Plain).await,
        (false, false)
    );
    assert_eq!(
        exchange(Handshake::Plain, incoming(false)).await,
        (false, false)
    );
    let client = Handshake::Client {
        target: hash(),
        max_padding: cs::DEFAULT_MAX_PADDING,
    };
    for _ in 0..10 {
        assert_eq!(exchange(client.clone(), incoming(true)).await, (true, true));
    }
}

#[tokio::test]
async fn required_obfuscation_refuses_plain() {
    let (x, y) = tokio::io::duplex(1 << 16);
    let (a, b) = tokio::join!(
        async {
            let (_r, mut w) = establish(x, Handshake::Plain, config()).await.unwrap();
            w.send(&packet(1, 1), Priority::Control).await.unwrap();
        },
        establish(y, incoming(true), config())
    );
    let () = a;
    assert!(matches!(b, Err(NetError::PlainRefused)));
}

#[tokio::test]
async fn wrong_user_hash_fails_the_handshake() {
    let (x, y) = tokio::io::duplex(1 << 16);
    let client = Handshake::Client {
        target: Md4Hash([1; 16]),
        max_padding: 0,
    };
    let (a, b) = tokio::join!(establish(x, client, config()), async {
        let r = establish(y, incoming(true), config()).await;
        drop(r);
    });
    let () = b;
    assert!(a.is_err());
}

/// Towards a fake server built from the ed2k-crypto primitives: our answer
/// goes out in front of the first packet.
#[tokio::test]
async fn server_handshake_over_a_pipe() {
    let (x, mut s) = tokio::io::duplex(1 << 16);
    let server = async move {
        let mut head = [0u8; 98];
        s.read_exact(&mut head).await.unwrap();
        let mut pad = vec![0u8; head[97] as usize];
        s.read_exact(&mut pad).await.unwrap();
        let b = [7u8; 16];
        let shared = cs::dh_shared(&head[1..97].try_into().unwrap(), &b);
        let (mut recv, mut send) = cs::server_keys(&shared);
        let mut answer = cs::dh_public(&b).to_vec();
        let mut enc = cs::MAGICVALUE_SYNC.to_le_bytes().to_vec();
        enc.extend([0, 0, 2, 0xAB, 0xCD]);
        send.apply(&mut enc);
        answer.extend(enc);
        s.write_all(&answer).await.unwrap();
        // Our answer: magic, method, padding length, padding; then the packet.
        let mut m = [0u8; 6];
        s.read_exact(&mut m).await.unwrap();
        recv.apply(&mut m);
        assert_eq!(&m[..4], cs::MAGICVALUE_SYNC.to_le_bytes());
        let mut pad = vec![0u8; m[5] as usize];
        s.read_exact(&mut pad).await.unwrap();
        recv.apply(&mut pad);
        let mut p = [0u8; 9];
        s.read_exact(&mut p).await.unwrap();
        recv.apply(&mut p);
        assert_eq!(p, [0xE3, 4, 0, 0, 0, 0x01, 0, 1, 2]);
        // And a packet back.
        let mut back = vec![0xE3, 1, 0, 0, 0, 0x34];
        send.apply(&mut back);
        s.write_all(&back).await.unwrap();
        s
    };
    let client = async {
        let (mut r, mut w) = establish(x, Handshake::Server, config()).await.unwrap();
        assert!(w.is_obfuscated());
        w.send(&packet(0x01, 3), Priority::Control).await.unwrap();
        r.recv().await.unwrap().unwrap()
    };
    let (_s, got) = tokio::join!(server, client);
    assert_eq!(got, packet(0x34, 0));
}

#[tokio::test]
async fn a_close_mid_packet_is_an_error() {
    let (x, mut y) = tokio::io::duplex(1024);
    let (mut r, _w) = establish(x, Handshake::Plain, config()).await.unwrap();
    y.write_all(&[0xE3, 10, 0, 0, 0, 1, 1, 2]).await.unwrap();
    drop(y);
    assert!(matches!(r.recv().await, Err(NetError::ClosedInPacket)));
}

#[tokio::test(start_paused = true)]
async fn reads_are_throttled_and_refunded() {
    let bw = Arc::new(Bandwidth::new(0, 10)); // 3072 bytes per tick
    let (x, mut y) = tokio::io::duplex(1 << 20);
    let (mut r, _w) = establish(x, Handshake::Plain, ConnConfig::new(bw.clone()))
        .await
        .unwrap();
    let mut wire = BytesMut::new();
    PacketCodec::new()
        .encode(packet(0x46, 30_000), &mut wire)
        .unwrap();
    y.write_all(&wire).await.unwrap();
    let t = Instant::now();
    assert_eq!(r.recv().await.unwrap(), Some(packet(0x46, 30_000)));
    // 30,006 bytes at 3072 per 300 ms: ten ticks.
    assert_eq!(t.elapsed(), Duration::from_millis(3000));
    assert_eq!(bw.download.used(), 30_006);
    assert_eq!(r.received(), 30_006);
    // Unthrottled sockets (servers, browsing) do not count.
    r.set_download_throttled(false);
    y.write_all(&wire).await.unwrap();
    r.recv().await.unwrap();
    assert_eq!(bw.download.used(), 30_006);
}
