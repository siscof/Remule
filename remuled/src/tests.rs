// SPDX-License-Identifier: GPL-2.0-or-later
//! The daemon: loading an aMule config directory, and running from one.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use ed2k_codec::{Tag, TagValue};
use ed2k_formats::preferences_dat;
use ed2k_formats::server_met::{ServerMet, ServerRecord};
use ed2k_types::tags::ServerTag;
use ed2k_types::Md4Hash;

use crate::client::{self, ClientConfig};
use crate::config;

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

fn server(ip: [u8; 4], port: u16, prio: Option<u8>) -> ServerRecord {
    ServerRecord {
        ip: Ipv4Addr::from(ip),
        port,
        tags: prio
            .map(|p| vec![Tag::new(ServerTag::Preference.value(), TagValue::U8(p))])
            .unwrap_or_default(),
    }
}

#[test]
fn the_user_hash_is_kept_or_made() {
    let d = TempDir::new("hash");
    // Missing: made, saved, with the eMule markers in memory only.
    let h = config::user_hash(&d.0).unwrap();
    assert_eq!((h.0[5], h.0[14]), (14, 111));
    let stored =
        preferences_dat::read(&std::fs::read(d.0.join("preferences.dat")).unwrap()).unwrap();
    assert!(!preferences_dat::is_bad(&stored));
    assert_eq!(preferences_dat::with_markers(stored), h);
    assert_eq!(config::user_hash(&d.0).unwrap(), h);
    // aMule's own file is read as it is.
    let theirs = Md4Hash([0x5A; 16]);
    std::fs::write(d.0.join("preferences.dat"), preferences_dat::write(&theirs)).unwrap();
    assert_eq!(
        config::user_hash(&d.0).unwrap(),
        preferences_dat::with_markers(theirs)
    );
    // A bad one is replaced.
    std::fs::write(
        d.0.join("preferences.dat"),
        preferences_dat::write(&Md4Hash([0; 16])),
    )
    .unwrap();
    let h = config::user_hash(&d.0).unwrap();
    assert!(!preferences_dat::is_bad(&h));
}

#[test]
fn servers_go_high_priority_first() {
    let met = ServerMet {
        version: 0x0E,
        servers: vec![
            server([1, 1, 1, 1], 4661, None),
            server([2, 2, 2, 2], 4662, Some(2)),
            server([3, 3, 3, 3], 4663, Some(1)),
            server([0, 0, 0, 0], 4664, Some(1)),
            server([5, 5, 5, 5], 4665, Some(0)),
        ],
        legacy_counts: false,
    };
    let got: Vec<String> = config::servers(&met)
        .iter()
        .map(|a| a.to_string())
        .collect();
    assert_eq!(
        got,
        [
            "3.3.3.3:4663",
            "1.1.1.1:4661",
            "5.5.5.5:4665",
            "2.2.2.2:4662"
        ]
    );
}

#[test]
fn an_amule_directory_loads() {
    let d = TempDir::new("load");
    let dir = &d.0;
    let shared = dir.join("files");
    std::fs::create_dir_all(shared.join("a/b")).unwrap();
    std::fs::create_dir_all(shared.join("c")).unwrap();
    std::fs::write(
        dir.join("amule.conf"),
        "[eMule]\nNick=tester\nPort=4999\nUDPPort=4998\nMaxUpload=40\nMaxDownload=0\n\
         MaxConnections=77\nTempDir=tmp\nFilterLanIPs=0\nConnectToKad=1\nConnectToED2K=1\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("shareddir-recursive.dat"),
        format!("{}\n", shared.display()),
    )
    .unwrap();
    let met = ServerMet {
        version: 0x0E,
        servers: vec![
            server([9, 9, 9, 9], 4242, None),
            server([8, 8, 8, 8], 4243, Some(1)),
        ],
        legacy_counts: false,
    };
    std::fs::write(dir.join("server.met"), met.write()).unwrap();

    let l = config::load(dir).unwrap();
    let c = &l.client;
    assert_eq!(c.nick, "tester");
    assert_eq!((c.tcp_port, c.udp_port), (4999, 4998));
    assert_eq!(
        (c.max_upload, c.max_download, c.max_connections),
        (40, 0, 77)
    );
    assert_eq!(c.temp, dir.join("tmp"));
    assert_eq!(c.incoming, dir.join("Incoming"));
    assert_eq!(c.config, *dir);
    assert!(c.allow_lan && c.upload && !c.stop_when_done);
    assert_eq!(
        c.servers,
        [
            "8.8.8.8:4243".parse::<SocketAddr>().unwrap(),
            "9.9.9.9:4242".parse().unwrap()
        ]
    );
    // Kad wants a nodes.dat.
    assert!(c.kad.is_none());
    assert!(
        l.notes.iter().any(|n| n.contains("nodes.dat")),
        "{:?}",
        l.notes
    );
    // Everything below the recursive folder.
    assert_eq!(
        c.share,
        [
            shared.clone(),
            shared.join("a"),
            shared.join("a/b"),
            shared.join("c")
        ]
    );
    assert!(dir.join("preferences.dat").is_file());
    assert!(dir.join("cryptkey.dat").is_file());

    // With a nodes.dat, Kad keeps its state in the directory.
    std::fs::write(dir.join("nodes.dat"), [0u8; 4]).unwrap();
    let l = config::load(dir).unwrap();
    assert_eq!(l.client.kad.unwrap().dir, *dir);
    // An empty directory: aMule's defaults.
    let e = TempDir::new("load-empty");
    let l = config::load(&e.0).unwrap();
    assert_eq!(
        (l.client.tcp_port, l.client.nick.as_str()),
        (4662, ed2k_formats::amule_conf::DEFAULT_NICK)
    );
    assert!(!l.client.allow_lan);
    assert_eq!(l.client.max_connections, config::DEFAULT_MAX_CONNECTIONS);
    assert!(config::load(&e.0.join("missing")).is_err());
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The daemon, run from an aMule config directory with a legacy
/// `shareddir.dat`, serves a file to another remule client on this
/// machine, then stops and leaves `known.met` and `clients.met` behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_shares_from_an_amule_directory() {
    let d = TempDir::new("serve");
    let amule = d.0.join("amule");
    let shared = d.0.join("shared");
    std::fs::create_dir_all(&amule).unwrap();
    std::fs::create_dir_all(&shared).unwrap();
    let content: Vec<u8> = (0..(9_728_000u64 + 54_321))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(shared.join("book.bin"), &content).unwrap();
    let port = free_port();
    std::fs::write(
        amule.join("amule.conf"),
        format!("[eMule]\nNick=daemon\nPort={port}\nConnectToKad=0\nConnectToED2K=0\n"),
    )
    .unwrap();
    // eMule style: a trailing separator.
    std::fs::write(
        amule.join("shareddir.dat"),
        format!("{}{}\n", shared.display(), std::path::MAIN_SEPARATOR),
    )
    .unwrap();

    let loaded = config::load(&amule).unwrap();
    assert_eq!(loaded.client.share, std::slice::from_ref(&shared));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(client::run(loaded.client, Vec::new(), Vec::new(), async {
        let _ = stop_rx.await;
    }));
    // Let it hash the file and listen.
    let mut tries = 0;
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        tries += 1;
        assert!(tries < 100, "the daemon never listened");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Another client downloads it, with the daemon as the source.
    let mut h = ed2k_hash::Hasher::new();
    h.update(&content);
    let h = h.finish();
    let getter = d.0.join("getter");
    let temp = getter.join("temp");
    std::fs::create_dir_all(&temp).unwrap();
    let pf = remule_core::PartFile::create(&temp, "book.bin", h.ed2k, h.size).unwrap();
    let c = ClientConfig {
        temp: temp.clone(),
        incoming: getter.join("incoming"),
        config: getter.join("config"),
        user_hash: Md4Hash([0x33; 16]),
        identity: client::load_identity(&getter.join("cryptkey.dat")).unwrap(),
        servers: Vec::new(),
        obfuscate_server: false,
        autoconnect: true,
        reconnect: true,
        kad: None,
        tcp_port: free_port(),
        udp_port: 0,
        nick: "getter".into(),
        max_connections: 10,
        max_download: 0,
        max_upload: 0,
        upload: false,
        share: Vec::new(),
        reachable: false,
        allow_lan: true,
        ip_filter: None,
        stop_when_done: true,
        status_every: Duration::from_secs(3600),
    };
    let source = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let s = tokio::time::timeout(
        Duration::from_secs(120),
        client::run(c, vec![pf], vec![(h.ed2k, source)], std::future::pending()),
    )
    .await
    .expect("the download timed out")
    .unwrap();
    assert_eq!(s.completed, 1);
    assert_eq!(
        std::fs::read(getter.join("incoming").join("book.bin")).unwrap(),
        content
    );

    stop_tx.send(()).unwrap();
    let s = daemon.await.unwrap().unwrap();
    assert!(s.uploaded >= content.len() as u64, "{}", s.uploaded);
    // aMule's files, in aMule's directory.
    for f in [
        "known.met",
        "known2_64.met",
        "clients.met",
        "preferences.dat",
        "cryptkey.dat",
    ] {
        assert!(amule.join(f).is_file(), "{f} missing");
    }
    assert!(amule.join("Incoming").is_dir() && amule.join("Temp").is_dir());
}

/// A scripted eD2k server for [`the_daemon_logs_in_again_when_the_server_drops_it`]:
/// each connection's login is answered with `OP_IDCHANGE`; what arrives is
/// reported as (connection number, opcode). The first connection is closed
/// once an `OP_OFFERFILES` came on it.
async fn dropping_server(
    listener: tokio::net::TcpListener,
    seen: tokio::sync::mpsc::UnboundedSender<(usize, u8)>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for n in 0.. {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        tokio::spawn(async move {
            loop {
                let mut head = [0u8; 5];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let len = u32::from_le_bytes(head[1..5].try_into().unwrap()) as usize;
                let mut body = vec![0u8; len];
                if len == 0 || s.read_exact(&mut body).await.is_err() {
                    return;
                }
                let _ = seen.send((n, body[0]));
                match body[0] {
                    // OP_LOGINREQUEST: a HighID, 127.0.0.1.
                    0x01 => {
                        let mut p = vec![0xE3, 5, 0, 0, 0, 0x40];
                        p.extend_from_slice(&[127, 0, 0, 1]);
                        if s.write_all(&p).await.is_err() {
                            return;
                        }
                    }
                    // OP_OFFERFILES on the first connection: hang up.
                    0x15 if n == 0 => return,
                    _ => {}
                }
            }
        });
    }
}

/// The server drops the daemon after its login and offer: it logs in again
/// at once (aMule's `Reconnect`) and offers its files on the new connection
/// too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_logs_in_again_when_the_server_drops_it() {
    let d = TempDir::new("reconnect");
    let amule = d.0.join("amule");
    std::fs::create_dir_all(amule.join("Incoming")).unwrap();
    std::fs::write(amule.join("Incoming").join("shared.bin"), vec![7u8; 5000]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    std::fs::write(
        amule.join("amule.conf"),
        format!(
            "[eMule]\nNick=daemon\nPort={}\nConnectToKad=0\nConnectToED2K=1\n",
            free_port()
        ),
    )
    .unwrap();
    let met = ServerMet {
        version: 0x0E,
        servers: vec![server([127, 0, 0, 1], server_port, None)],
        legacy_counts: false,
    };
    std::fs::write(amule.join("server.met"), met.write()).unwrap();
    let loaded = config::load(&amule).unwrap();
    assert!(loaded.client.autoconnect && loaded.client.reconnect);

    let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(dropping_server(listener, seen_tx));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(client::run(loaded.client, Vec::new(), Vec::new(), async {
        let _ = stop_rx.await;
    }));

    // A login and an offer on each of the two connections.
    let mut got = Vec::new();
    let want = [(0, 0x01), (0, 0x15), (1, 0x01), (1, 0x15)];
    tokio::time::timeout(Duration::from_secs(20), async {
        while !want.iter().all(|w| got.contains(w)) {
            got.push(seen.recv().await.unwrap());
        }
    })
    .await
    .unwrap_or_else(|_| panic!("got only {got:x?}"));

    stop_tx.send(()).unwrap();
    daemon.await.unwrap().unwrap();
}

/// The IP filter of an aMule directory: aMule's placeholders when missing,
/// `ipfilter_static.dat` winning over `ipfilter.dat`, `FilterLevel` and the
/// client/server switches, a packed list left unread.
#[test]
fn the_ip_filter_loads_as_amule_does() {
    use ed2k_formats::amule_conf::ConfFile;

    let d = TempDir::new("ipfilter");
    let dir = &d.0;
    let mut notes = Vec::new();
    let f = config::ip_filter(dir, &ConfFile::new(), &mut notes);
    assert_eq!(f.ban_count(), 0);
    let placeholder = std::fs::read_to_string(dir.join("ipfilter.dat")).unwrap();
    assert!(placeholder.starts_with("# This file is used by aMule to store ipfilter lists"));
    assert!(placeholder.ends_with("overwritten by aMule.\n\n"));
    let placeholder = std::fs::read_to_string(dir.join("ipfilter_static.dat")).unwrap();
    assert!(placeholder.ends_with("aMule will not change this file.\n"));

    // Two lists; the static one lifts part of a blocked range.
    std::fs::write(
        dir.join("ipfilter.dat"),
        "1.0.0.0 - 1.0.0.255 , 100 , blocked\n2.0.0.0 - 2.0.0.255 , 140 , mild\nnonsense\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("ipfilter_static.dat"),
        "1.0.0.128 - 1.0.0.255 , 200 , friends\n",
    )
    .unwrap();
    let mut notes = Vec::new();
    let f = config::ip_filter(dir, &ConfFile::new(), &mut notes);
    assert!(f.blocks_client(Ipv4Addr::new(1, 0, 0, 5)));
    assert!(!f.blocks_client(Ipv4Addr::new(1, 0, 0, 200)));
    // 140 is not below the default level, 127.
    assert!(!f.blocks_client(Ipv4Addr::new(2, 0, 0, 1)));
    assert!(f.blocks_server(Ipv4Addr::new(1, 0, 0, 5)));
    assert!(
        notes.iter().any(|n| n.starts_with("Loaded 2 IP-ranges")
            && n.ends_with("1 malformed lines were discarded.")),
        "{notes:?}"
    );

    // A higher level blocks more; clients unfiltered, servers still.
    let conf = ConfFile::parse(
        "[eMule]\nFilterLevel=150\n[ExternalConnect]\nIpFilterClients=0\nIpFilterServers=1\n",
    );
    let f = config::ip_filter(dir, &conf, &mut Vec::new());
    assert!(!f.blocks_client(Ipv4Addr::new(2, 0, 0, 1)));
    assert!(f.blocks_server(Ipv4Addr::new(2, 0, 0, 1)));

    // A zip is not read, and says so.
    std::fs::write(dir.join("ipfilter.dat"), b"PK\x03\x04rest of a zip").unwrap();
    let mut notes = Vec::new();
    let f = config::ip_filter(dir, &ConfFile::new(), &mut notes);
    assert!(!f.blocks_client(Ipv4Addr::new(1, 0, 0, 5)));
    assert!(notes.iter().any(|n| n.contains("packed list")), "{notes:?}");
}

/// With loopback blocked in `ipfilter_static.dat`, the daemon neither logs
/// into a server on 127.0.0.1 nor talks to a peer connecting from there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_keeps_away_from_filtered_addresses() {
    use tokio::io::AsyncReadExt;

    let d = TempDir::new("ipfilter-run");
    let amule = d.0.join("amule");
    std::fs::create_dir_all(&amule).unwrap();
    let srv = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = srv.local_addr().unwrap().port();
    let port = free_port();
    std::fs::write(
        amule.join("amule.conf"),
        format!("[eMule]\nNick=daemon\nPort={port}\nConnectToKad=0\nConnectToED2K=1\n"),
    )
    .unwrap();
    let met = ServerMet {
        version: 0x0E,
        servers: vec![server([127, 0, 0, 1], server_port, None)],
        legacy_counts: false,
    };
    std::fs::write(amule.join("server.met"), met.write()).unwrap();
    std::fs::write(
        amule.join("ipfilter_static.dat"),
        "127.0.0.0 - 127.255.255.255 , 0 , loopback\n",
    )
    .unwrap();
    let loaded = config::load(&amule).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let daemon = tokio::spawn(client::run(loaded.client, Vec::new(), Vec::new(), async {
        let _ = stop_rx.await;
    }));

    // A peer from 127.0.0.1: the connection is accepted, then closed with
    // nothing sent.
    let mut tries = 0;
    let mut peer = loop {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => break s,
            Err(_) => {
                tries += 1;
                assert!(tries < 100, "the daemon never listened");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut buf))
        .await
        .expect("the daemon kept a filtered peer")
        .unwrap_or(0);
    assert_eq!(n, 0);
    // The server on 127.0.0.1 is never tried.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), srv.accept())
            .await
            .is_err(),
        "the daemon connected to a filtered server"
    );

    stop_tx.send(()).unwrap();
    daemon.await.unwrap().unwrap();
}
