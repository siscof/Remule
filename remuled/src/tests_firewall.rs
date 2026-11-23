// SPDX-License-Identifier: GPL-2.0-or-later
//! Kad's TCP firewall check in the running daemon, against scripted Kad
//! nodes on other loopback addresses (127.0.0.x: each node is its own IP,
//! as the check counts nodes by IP).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed2k_codec::Packet;
use ed2k_crypto::udp::{self, OwnKeys};
use ed2k_kad::packets::{Hello as KadHello, KadPacket};
use ed2k_peer::Hello;
use ed2k_types::ed2k::client_tcp::{Extended, Standard};
use ed2k_types::{Md4Hash, Protocol, UInt128};
use remule_net::{establish, Bandwidth, ConnConfig, Handshake, PacketReader, Priority};
use tokio::net::{TcpSocket, UdpSocket};

use crate::client::{self, ClientConfig, KadSettings};

/// A directory under the system's temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn lo(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, n)
}

/// A scripted Kad node at 127.0.0.`n`.
struct Node {
    sock: UdpSocket,
    id: UInt128,
    hash: Md4Hash,
}

impl Node {
    async fn new(n: u8) -> Node {
        Node {
            sock: UdpSocket::bind((lo(n), 0)).await.unwrap(),
            id: UInt128::new(0x1111_0000 + u128::from(n)),
            hash: Md4Hash([n; 16]),
        }
    }

    fn ip(&self) -> Ipv4Addr {
        match self.sock.local_addr().unwrap() {
            SocketAddr::V4(a) => *a.ip(),
            _ => unreachable!(),
        }
    }

    async fn send(&self, p: &KadPacket, to: SocketAddrV4) {
        self.sock.send_to(&p.to_datagram(), to).await.unwrap();
    }

    /// The next packet, decrypted with our Kad ID if need be; `None` after
    /// `wait`.
    async fn recv(&self, wait: Duration) -> Option<KadPacket> {
        let mut buf = vec![0u8; 4096];
        let (n, from) = tokio::time::timeout(wait, async {
            loop {
                // Windows reports ICMP port-unreachable as a recv error.
                if let Ok(r) = self.sock.recv_from(&mut buf).await {
                    return r;
                }
            }
        })
        .await
        .ok()?;
        let bytes = &buf[..n];
        let plain = if bytes[0] == 0xE4 || bytes[0] == 0xE5 {
            bytes.to_vec()
        } else {
            let SocketAddr::V4(from) = from else {
                return None;
            };
            let own = OwnKeys {
                user_hash: self.hash,
                sender_ip: *from.ip(),
                kad_id: Some(self.id),
                verify_key: None,
            };
            udp::decrypt_client(bytes, &own)?.payload
        };
        KadPacket::parse(&plain).ok()
    }

    fn hello(&self) -> KadPacket {
        KadPacket::HelloReq(KadHello {
            id: self.id,
            tcp_port: 4662,
            version: 9,
            udp_port: None,
            misc_options: 0,
        })
    }
}

/// Peer packets until one passes `want`, within 10 s.
async fn until<R>(r: &mut PacketReader<R>, want: impl Fn(&Packet) -> bool) -> Result<Packet, String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match r.recv().await {
                Ok(Some(p)) if want(&p) => return Ok(p),
                Ok(Some(_)) => {}
                Ok(None) => return Err("closed".to_owned()),
                Err(e) => return Err(e.to_string()),
            }
        }
    })
    .await
    .map_err(|_| "timed out".to_owned())?
}

fn is(p: &Packet, protocol: Protocol, opcode: u8) -> bool {
    p.protocol == u8::from(protocol) && p.opcode == opcode
}

fn cfg() -> ConnConfig {
    ConnConfig::new(Arc::new(Bandwidth::new(0, 0)))
}

/// Node `n` says hello and is asked to check the daemon: it tells the
/// daemon its IP, connects to its TCP port (obfuscated or not), exchanges
/// hellos and acks. Returns whether the daemon's hello answer said it was
/// TCP-firewalled.
async fn check_the_daemon(n: &Node, udp: SocketAddrV4, tcp_port: u16, daemon: Md4Hash) -> bool {
    // The first hello may come before the daemon's Kad listens: again, up
    // to three times (Kad takes three hellos a minute from an IP).
    let mut firewalled = None;
    let mut ask = None;
    for _ in 0..3 {
        n.send(&n.hello(), udp).await;
        while let Some(p) = n.recv(Duration::from_secs(2)).await {
            match p {
                KadPacket::HelloRes(h) => firewalled = Some(h.tcp_firewalled()),
                KadPacket::Firewalled2Req {
                    tcp_port,
                    user_hash,
                    connect_options,
                } => ask = Some((tcp_port, user_hash, connect_options)),
                _ => {}
            }
            if firewalled.is_some() && ask.is_some() {
                break;
            }
        }
        if ask.is_some() {
            break;
        }
    }
    let (port, user_hash, options) = ask.expect("asked to check the daemon");
    assert_eq!(port, tcp_port);
    assert_eq!(Md4Hash(user_hash.to_be_bytes()), daemon);
    assert_eq!(options & 0x03, 0x03, "crypt supported and requested");
    n.send(
        &KadPacket::FirewalledRes {
            ip: u32::from(Ipv4Addr::LOCALHOST),
        },
        udp,
    )
    .await;

    // Over TCP from our own address, obfuscated by one node, plain by the other.
    let s = TcpSocket::new_v4().unwrap();
    s.bind(SocketAddr::from((n.ip(), 0))).unwrap();
    let stream = s
        .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port)))
        .await
        .unwrap();
    let hs = if n.ip().octets()[3].is_multiple_of(2) {
        Handshake::Client {
            target: daemon,
            max_padding: 0,
        }
    } else {
        Handshake::Plain
    };
    let (mut r, mut w) = establish(stream, hs, cfg()).await.unwrap();
    let hello = Hello::amule(n.hash, 0, 4662, "checker").to_hello().unwrap();
    w.send(&hello, Priority::Control).await.unwrap();
    until(&mut r, |p| {
        is(p, Protocol::Edonkey, Standard::HelloAnswer.into())
    })
    .await
    .expect("the daemon's hello answer");
    let ack = Packet::new(Protocol::Emule, Extended::KadFwTcpCheckAck, Vec::new());
    w.send(&ack, Priority::Control).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    firewalled.expect("a hello answer")
}

/// Other nodes check the daemon's TCP port: after two got through, its Kad
/// hellos say it takes TCP connections. And a node that asks the daemon to
/// check its own port gets its IP back over UDP and, on its TCP port, the
/// daemon's hello then `OP_KAD_FWTCPCHECK_ACK`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_runs_the_kad_firewall_check() {
    let d = TempDir::new("firewall");
    let kad_dir = d.0.join("kad");
    std::fs::create_dir_all(&kad_dir).unwrap();
    // An empty nodes.dat (version 2, no contacts): the nodes come to it.
    std::fs::write(
        kad_dir.join("nodes.dat"),
        [0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    let tcp_port = free_tcp_port();
    let udp_port = free_udp_port();
    let user_hash = Md4Hash([0x44; 16]);
    let c = ClientConfig {
        temp: d.0.join("temp"),
        incoming: d.0.join("incoming"),
        config: d.0.join("config"),
        user_hash,
        identity: client::load_identity(&d.0.join("cryptkey.dat")).unwrap(),
        servers: Vec::new(),
        obfuscate_server: false,
        autoconnect: false,
        reconnect: false,
        kad: Some(KadSettings {
            dir: kad_dir,
            nodes: None,
            bootstrap: Vec::new(),
            warmup: crate::client::KAD_WARMUP,
        }),
        tcp_port,
        udp_port,
        nick: "daemon".into(),
        max_connections: 50,
        max_download: 0,
        max_upload: 0,
        upload: true,
        share: Vec::new(),
        reachable: false,
        allow_lan: true,
        reask: Duration::from_secs(900),
        ip_filter: None,
        stop_when_done: false,
        status_every: Duration::from_secs(3600),
        ec: None,
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(client::run(c, Vec::new(), Vec::new(), async {
        let _ = stop_rx.await;
    }));
    let udp = SocketAddrV4::new(Ipv4Addr::LOCALHOST, udp_port);

    // Two nodes check it; it says it is firewalled until they got through.
    for n in [2, 3] {
        let node = Node::new(n).await;
        assert!(
            check_the_daemon(&node, udp, tcp_port, user_hash).await,
            "firewalled before the acks"
        );
    }
    let mut open = false;
    for n in 4..10 {
        let node = Node::new(n).await;
        node.send(&node.hello(), udp).await;
        while let Some(p) = node.recv(Duration::from_secs(1)).await {
            if let KadPacket::HelloRes(h) = p {
                open = !h.tcp_firewalled();
                break;
            }
        }
        if open {
            break;
        }
    }
    assert!(
        open,
        "two acks got through, yet the daemon says it is firewalled"
    );

    // A node asks the daemon to check its port.
    let asker = Node::new(20).await;
    let listener = tokio::net::TcpListener::bind((asker.ip(), 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    asker
        .send(
            &KadPacket::Firewalled2Req {
                tcp_port: port,
                user_hash: UInt128::from_be_bytes(asker.hash.0),
                connect_options: 0x03,
            },
            udp,
        )
        .await;
    let mut told = None;
    while let Some(p) = asker.recv(Duration::from_secs(5)).await {
        if let KadPacket::FirewalledRes { ip } = p {
            told = Some(Ipv4Addr::from(ip));
            break;
        }
    }
    assert_eq!(told, Some(asker.ip()));
    let (stream, from) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the daemon connects back")
        .unwrap();
    assert_eq!(from.ip(), Ipv4Addr::LOCALHOST);
    let hs = Handshake::Incoming {
        own_hash: asker.hash,
        max_padding: 0,
        require: true,
    };
    let (mut r, mut w) = establish(stream, hs, cfg()).await.expect("obfuscated");
    let hello = until(&mut r, |p| is(p, Protocol::Edonkey, Standard::Hello.into()))
        .await
        .expect("the daemon's hello");
    assert_eq!(
        ed2k_peer::PeerPacket::parse(hello, Default::default())
            .ok()
            .and_then(|p| match p {
                ed2k_peer::PeerPacket::Hello(h) => Some(h.user_hash),
                _ => None,
            }),
        Some(user_hash)
    );
    let answer = Hello::amule(asker.hash, 0, port, "asker")
        .to_hello_answer()
        .unwrap();
    w.send(&answer, Priority::Control).await.unwrap();
    until(&mut r, |p| {
        is(p, Protocol::Emule, Extended::KadFwTcpCheckAck.into())
    })
    .await
    .expect("the ack");

    stop_tx.send(()).unwrap();
    daemon.await.unwrap().unwrap();
}
