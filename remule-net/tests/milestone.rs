// SPDX-License-Identifier: GPL-2.0-or-later
//! Phase 5 milestone: N real TCP connections on localhost stay within the
//! configured upload and download limits, and the listener keeps to the
//! connection limit.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_types::Protocol;
use remule_net::conn::DEFAULT_MAX_PADDING;
use remule_net::{
    establish, Bandwidth, ConnConfig, ConnectionLimiter, Handshake, Listener, Priority,
};
use tokio::net::TcpStream;

const CONNECTIONS: usize = 8;
const RUN: Duration = Duration::from_secs(3);
const LIMIT_KIB: u32 = 256;

fn incoming() -> Handshake {
    Handshake::Incoming {
        own_hash: ed2k_types::Md4Hash([3; 16]),
        max_padding: DEFAULT_MAX_PADDING,
        require: false,
    }
}

fn client() -> Handshake {
    Handshake::Client {
        target: ed2k_types::Md4Hash([3; 16]),
        max_padding: DEFAULT_MAX_PADDING,
    }
}

/// `CONNECTIONS` senders pushing file data for `RUN` through `send_bw` to a
/// listener reading through `recv_bw`; the bytes the listener read and the
/// time it took.
async fn run(send_bw: Arc<Bandwidth>, recv_bw: Arc<Bandwidth>) -> (u64, Duration) {
    let limiter = ConnectionLimiter::new(500, 1000);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), limiter)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let start = Instant::now();
    let deadline = start + RUN;

    let server = tokio::spawn(async move {
        let mut readers = Vec::new();
        for _ in 0..CONNECTIONS {
            let (stream, _, permit) = listener.accept().await.unwrap();
            let cfg = ConnConfig::new(recv_bw.clone());
            readers.push(tokio::spawn(async move {
                let _permit = permit;
                let (mut r, _w) = establish(stream, incoming(), cfg).await.unwrap();
                // Read until the deadline; what arrives after does not count.
                let _ = tokio::time::timeout_at(deadline.into(), async {
                    while let Ok(Some(_)) = r.recv().await {}
                })
                .await;
                r.received()
            }));
        }
        let mut total = 0;
        for r in readers {
            total += r.await.unwrap();
        }
        total
    });

    let mut senders = Vec::new();
    for i in 0..CONNECTIONS {
        let bw = send_bw.clone();
        // Half of them obfuscated.
        let hs = if i % 2 == 0 {
            client()
        } else {
            Handshake::Plain
        };
        senders.push(tokio::spawn(async move {
            sender(addr, bw, hs, deadline).await;
        }));
    }
    let total = server.await.unwrap();
    for s in senders {
        let _ = s.await;
    }
    (total, start.elapsed().min(RUN))
}

async fn sender(addr: SocketAddr, bw: Arc<Bandwidth>, hs: Handshake, deadline: Instant) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (_r, mut w) = establish(stream, hs, ConnConfig::new(bw)).await.unwrap();
    let data = Packet::new(Protocol::Emule, 0x40u8, vec![0x55; 10_000]);
    while Instant::now() < deadline {
        let send = w.send(&data, Priority::Standard);
        if tokio::time::timeout_at(deadline.into(), send)
            .await
            .is_err()
        {
            break;
        }
    }
}

fn check(what: &str, bytes: u64, elapsed: Duration) {
    let limit = LIMIT_KIB as f64 * 1024.0;
    let rate = bytes as f64 / elapsed.as_secs_f64();
    println!(
        "{what}: {bytes} bytes in {elapsed:?} = {:.1} KiB/s (limit {LIMIT_KIB})",
        rate / 1024.0
    );
    // Above: one bucket's burst and a send per connection. Below: shared CI
    // machines are slow, but not that slow.
    let burst = 0.6 * limit + (CONNECTIONS * 2600) as f64;
    assert!(
        bytes as f64 <= limit * elapsed.as_secs_f64() + burst,
        "{what}: {:.1} KiB/s over the limit",
        rate / 1024.0
    );
    assert!(
        rate >= 0.6 * limit,
        "{what}: only {:.1} KiB/s",
        rate / 1024.0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_limit_holds_across_connections() {
    let up = Arc::new(Bandwidth::new(LIMIT_KIB, 0));
    let (bytes, elapsed) = run(up.clone(), Arc::new(Bandwidth::unlimited())).await;
    check("upload", bytes, elapsed);
    // What the writers were allowed is what was sent.
    assert!(up.upload.used() >= bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn download_limit_holds_across_connections() {
    let down = Arc::new(Bandwidth::new(0, LIMIT_KIB));
    let (bytes, elapsed) = run(Arc::new(Bandwidth::unlimited()), down.clone()).await;
    check("download", bytes, elapsed);
    assert_eq!(down.download.used(), bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_keeps_to_max_connections() {
    // MaxConnections 3: a fourth is still taken (the limit is "above"), a fifth waits.
    let limiter = ConnectionLimiter::new(3, 1000);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), limiter.clone())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let mut clients = Vec::new();
    for _ in 0..5 {
        clients.push(TcpStream::connect(addr).await.unwrap());
    }
    let mut permits = Vec::new();
    for _ in 0..4 {
        let (_, _, p) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accepted")
            .unwrap();
        permits.push(p);
    }
    assert_eq!(limiter.snapshot().open(), 4);
    let fifth = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
    assert!(fifth.is_err(), "a fifth connection was accepted");
    // One closes: the fifth gets in.
    permits.pop();
    let (_, _, p) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accepted after a close")
        .unwrap();
    permits.push(p);
    assert_eq!(limiter.snapshot().open(), 4);
    // While a server connection is being made, the limit does not apply.
    clients.push(TcpStream::connect(addr).await.unwrap());
    listener.set_server_connecting(true);
    let (_, _, p) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accepted while connecting to a server")
        .unwrap();
    permits.push(p);
    assert_eq!(limiter.snapshot().open(), 5);
}
