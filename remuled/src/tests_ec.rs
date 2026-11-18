// SPDX-License-Identifier: GPL-2.0-or-later
//! External connections: the EC password as aMule 3.3 loads and migrates
//! it, `[ExternalConnect]`, the replies, and an EC client driving a
//! running daemon.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use ed2k_formats::amule_conf::ConfFile;
use ed2k_types::UInt128;
use remule_ec::codes::*;
use remule_ec::srp::{password_digest, Verifier};
use remule_ec::{Client, ConnectOptions, Packet, Tag};

use crate::config;
use crate::ec::{self, Control, KadStatus, ServerStatus, Status};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-ec-{name}-{}", std::process::id()));
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

const SECRET: &str = "5ebe2294ecd0e0f08eab7690d2a6ee69"; // md5("secret")

fn conf_text(dir: &TempDir) -> String {
    std::fs::read_to_string(dir.0.join("amule.conf")).unwrap()
}

/// Write `text` as amule.conf and load the credential from it.
fn credential(dir: &TempDir, text: &str) -> (Result<Option<Verifier>, String>, Vec<String>) {
    std::fs::write(dir.0.join("amule.conf"), text).unwrap();
    let mut conf = ConfFile::parse(text);
    let mut notes = Vec::new();
    let r = config::ec_credential(&dir.0, &mut conf, &mut notes);
    (r, notes)
}

#[test]
fn the_ec_password_is_migrated_as_amule_does() {
    let d = TempDir::new("migrate");
    // A legacy digest: a verifier for it, saved, and the digest removed.
    let text = format!("[ExternalConnect]\nAcceptExternalConnections=1\nECPassword={SECRET}\n");
    let (v, notes) = credential(&d, &text);
    let v = v.unwrap().unwrap();
    assert!(v.matches(SECRET));
    assert!(notes.is_empty(), "{notes:?}");
    let saved = conf_text(&d);
    assert!(!saved.contains("ECPassword="), "{saved}");
    assert!(
        saved.contains(&format!("ECPasswordVerifier={}", v.encode())),
        "{saved}"
    );
    assert!(saved.contains("AcceptExternalConnections=1"), "{saved}");
    // Loaded again: the same verifier, the file untouched.
    let (again, _) = credential(&d, &saved);
    assert_eq!(again.unwrap().unwrap(), v);
    assert_eq!(conf_text(&d), saved);

    // A downgraded core left the key empty: cleaned, the verifier kept.
    let (r, _) = credential(&d, &format!("{saved}ECPassword=\n"));
    assert_eq!(r.unwrap().unwrap(), v);
    assert_eq!(conf_text(&d), saved);
    // ... or changed the password there: the newer one wins, with a note.
    let other = password_digest("other");
    let (r, notes) = credential(&d, &format!("{saved}ECPassword={other}\n"));
    let w = r.unwrap().unwrap();
    assert!(w.matches(&other) && !w.matches(SECRET));
    assert!(
        notes[0].starts_with("Migrating a changed legacy ECPassword"),
        "{notes:?}"
    );
    assert!(!conf_text(&d).contains("ECPassword="));
    // ... or kept the same one: nothing changes but the cleanup.
    let (r, notes) = credential(&d, &format!("{saved}ECPassword={SECRET}\n"));
    assert_eq!(r.unwrap().unwrap(), v);
    assert!(notes.is_empty());

    // No password at all.
    let (r, _) = credential(&d, "[ExternalConnect]\nAcceptExternalConnections=1\n");
    assert_eq!(r.unwrap(), None);
    // The empty password's digest, or junk, is refused and left alone.
    let empty = password_digest("");
    for bad in [empty.as_str(), "nothex"] {
        let text = format!("[ExternalConnect]\nECPassword={bad}\n");
        let (r, _) = credential(&d, &text);
        assert!(r.unwrap_err().starts_with("ECPassword contains an invalid"));
        assert_eq!(conf_text(&d), text);
    }
    // A bad verifier never falls back to the digest.
    let text = format!("[ExternalConnect]\nECPasswordVerifier=v1:junk\nECPassword={SECRET}\n");
    let (r, _) = credential(&d, &text);
    assert_eq!(
        r.unwrap_err(),
        "Invalid or unsupported ECPasswordVerifier; refusing external connections."
    );
    assert_eq!(conf_text(&d), text);
}

#[test]
fn external_connect_is_read_as_amule_reads_it() {
    let d = TempDir::new("settings");
    let load = |text: &str| {
        std::fs::write(
            d.0.join("amule.conf"),
            format!("[eMule]\nConnectToKad=0\nConnectToED2K=0\n{text}"),
        )
        .unwrap();
        config::load(&d.0).unwrap()
    };
    let l = load("");
    assert!(l.client.ec.is_none());
    assert!(l
        .info
        .contains(&"External connections disabled in config file".to_string()));
    let l = load("[ExternalConnect]\nAcceptExternalConnections=1\n");
    assert!(l.client.ec.is_none());
    assert!(l
        .notes
        .contains(&"External connections disabled due to empty password!".to_string()));
    let l = load(&format!(
        "[ExternalConnect]\nAcceptExternalConnections=1\nECAddress=\nECPort=4999\n\
         ECPassword={SECRET}\nAuthFailureThreshold=3\nAuthLockoutSeconds=60\n"
    ));
    let ec = l.client.ec.unwrap();
    assert_eq!(ec.addr, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 4999));
    assert_eq!(
        (
            ec.limits.window_seconds,
            ec.limits.threshold,
            ec.limits.lockout_seconds
        ),
        (60, 3, 60)
    );
    let v = ec.credentials.password.unwrap();
    assert!(v.matches(SECRET));
    // A verifier, at aMule's default address.
    let l = load(&format!(
        "[ExternalConnect]\nAcceptExternalConnections=1\nECPasswordVerifier={}\n",
        v.encode()
    ));
    assert_eq!(l.client.ec.as_ref().unwrap().credentials.password, Some(v));
    assert_eq!(
        l.client.ec.unwrap().addr,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4712)
    );
}

fn busy() -> Status {
    Status {
        ed2k_enabled: true,
        kad_enabled: true,
        server: Some(ServerStatus {
            addr: Some(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 4661)),
            name: "Big Server".into(),
            description: "the one".into(),
            version: String::new(),
            users: 1000,
            files: 50_000,
            tcp_flags: 0x19,
        }),
        connecting: false,
        ed2k_id: 2_241_576,
        ed2k_since: Some(1_700_000_000),
        kad: Some(KadStatus {
            connected: true,
            firewalled: true,
            id: UInt128::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
            public_ip: Ipv4Addr::new(5, 6, 7, 8),
            users: 123_456,
            nodes: 147,
            since: Some(1_700_000_010),
        }),
        ul_speed: 2048,
        dl_speed: 4096,
        ul_limit: 100 * 1024,
        dl_limit: 0,
        session_sent: 10,
        session_received: 20,
        total_sent: 2900,
        total_received: 20,
        uptime: 3600,
        shared_files: 7,
        connections: 3,
        sources: 9,
        upload_queue: 0,
        banned: 0,
    }
}

fn kids(t: &Tag) -> Vec<u16> {
    t.children.iter().map(|c| c.name).collect()
}

#[test]
fn the_connection_state_is_told_as_amule_tells_it() {
    let s = busy();
    let t = ec::connstate_tag(&s, EC_DETAIL_CMD);
    // eD2k connected, Kad connected, firewalled, running.
    assert_eq!(t.as_int(), 0x01 | 0x04 | 0x08 | 0x10);
    assert_eq!(
        kids(&t),
        [
            EC_TAG_NETWORKS_ENABLED,
            EC_TAG_SERVER,
            EC_TAG_ED2K_ID,
            EC_TAG_ED2K_CONNECTED_SINCE,
            EC_TAG_CLIENT_ID,
            EC_TAG_KAD_ID,
            EC_TAG_KAD_CONNECTED_SINCE
        ]
    );
    assert_eq!(t.child_int(EC_TAG_NETWORKS_ENABLED), 3);
    let server = t.child(EC_TAG_SERVER).unwrap();
    assert_eq!(server.as_ipv4(), Some(([1, 2, 3, 4], 4661)));
    // amulecmd's detail: the name only.
    assert_eq!(kids(server), [EC_TAG_SERVER_NAME]);
    assert_eq!(server.child_str(EC_TAG_SERVER_NAME), "Big Server");
    // Firewalled on Kad: the eD2k LowID is our ID.
    assert_eq!(t.child_int(EC_TAG_CLIENT_ID), 2_241_576);
    let kad_id = t.child(EC_TAG_KAD_ID).unwrap();
    assert_eq!(kad_id.ty, EC_TAGTYPE_UINT128);
    assert_eq!(kad_id.data[0..2], [0x01, 0x02]);
    // The GUI's detail: the whole server.
    let full = ec::connstate_tag(&s, EC_DETAIL_FULL);
    assert_eq!(
        kids(full.child(EC_TAG_SERVER).unwrap()),
        [
            EC_TAG_SERVER_DESC,
            EC_TAG_SERVER_USERS,
            EC_TAG_SERVER_FILES,
            EC_TAG_SERVER_TCP_FLAGS,
            EC_TAG_SERVER_NAME
        ]
    );

    // Reachable on Kad: Kad's IP is our ID.
    let mut open = busy();
    open.kad.as_mut().unwrap().firewalled = false;
    assert_eq!(open.client_id(), u32::from_le_bytes([5, 6, 7, 8]));
    // Only Kad, firewalled: 1. Nothing: 0, and while connecting the eD2k
    // ID says so.
    let mut kad_only = busy();
    kad_only.server = None;
    assert_eq!(kad_only.client_id(), 1);
    let idle = Status {
        connecting: true,
        ..Default::default()
    };
    let t = ec::connstate_tag(&idle, EC_DETAIL_CMD);
    assert_eq!(t.as_int(), 0x02);
    assert_eq!(t.child_int(EC_TAG_ED2K_ID), 0xFFFF_FFFF);
    assert_eq!(t.child_int(EC_TAG_CLIENT_ID), 0);
    assert!(!t.has(EC_TAG_KAD_ID));
}

#[test]
fn statistics_follow_the_detail_level() {
    let s = busy();
    let cmd = ec::stats_reply(&s, EC_DETAIL_CMD);
    assert_eq!(cmd.opcode, EC_OP_STATS);
    let get = |p: &Packet, n: u16| p.tag(n).map(Tag::as_int);
    assert_eq!(get(&cmd, EC_TAG_STATS_UL_SPEED), Some(2048));
    assert_eq!(get(&cmd, EC_TAG_STATS_DL_SPEED), Some(4096));
    assert_eq!(get(&cmd, EC_TAG_STATS_UL_SPEED_LIMIT), Some(100 * 1024));
    assert_eq!(get(&cmd, EC_TAG_STATS_ED2K_USERS), Some(1000));
    assert_eq!(get(&cmd, EC_TAG_STATS_KAD_USERS), Some(123_456));
    assert_eq!(get(&cmd, EC_TAG_STATS_KAD_NODES), Some(147));
    assert_eq!(
        get(&cmd, EC_TAG_STATS_KAD_IP_ADDRESS),
        Some(u32::from_le_bytes([5, 6, 7, 8]).into())
    );
    // The session and totals only at the GUI's levels.
    assert_eq!(get(&cmd, EC_TAG_STATS_UPTIME_SECONDS), None);
    let full = ec::stats_reply(&s, EC_DETAIL_FULL);
    assert_eq!(get(&full, EC_TAG_STATS_UPTIME_SECONDS), Some(3600));
    assert_eq!(get(&full, EC_TAG_STATS_TOTAL_SENT_BYTES), Some(2900));
    assert_eq!(get(&full, EC_TAG_STATS_SHARED_FILE_COUNT), Some(7));
    assert_eq!(get(&full, EC_TAG_STATS_UL_SPEED), Some(2048));
    // UPDATE: nothing but the connection state; it always comes last.
    let upd = ec::stats_reply(&s, EC_DETAIL_UPDATE);
    assert_eq!(upd.tags.len(), 1);
    for p in [cmd, full, upd] {
        assert_eq!(p.tags.last().unwrap().name, EC_TAG_CONNSTATE);
    }
    // Kad not connected: no Kad block.
    let mut off = busy();
    off.kad = None;
    let p = ec::stats_reply(&off, EC_DETAIL_CMD);
    assert_eq!(get(&p, EC_TAG_STATS_KAD_IP_ADDRESS), None);
}

#[test]
fn requests_are_answered_as_process_request2_does() {
    let s = busy();
    let (r, c) = ec::answer(&Packet::new(EC_OP_SHUTDOWN), &s, false);
    assert_eq!((r.opcode, c), (EC_OP_NOOP, Some(Control::Shutdown)));
    let (r, c) = ec::answer(&Packet::new(EC_OP_SHUTDOWN), &s, true);
    assert_eq!((r.opcode, c), (EC_OP_FAILED, None));
    assert_eq!(r.message().unwrap(), "Already shutting down.");
    // No detail level: FULL.
    let (r, _) = ec::answer(&Packet::new(EC_OP_STAT_REQ), &s, false);
    assert!(r.tag(EC_TAG_STATS_UPTIME_SECONDS).is_some());
    let (r, _) = ec::answer(
        &Packet::new(EC_OP_GET_CONNSTATE).with_detail(EC_DETAIL_CMD),
        &s,
        false,
    );
    assert_eq!(r.opcode, EC_OP_MISC_DATA);
    assert_eq!(r.tags[0].name, EC_TAG_CONNSTATE);
    let (r, _) = ec::answer(&Packet::new(EC_OP_GET_DLOAD_QUEUE), &s, false);
    assert_eq!(r.opcode, EC_OP_FAILED);
    assert_eq!(
        r.message().unwrap(),
        "Invalid opcode (wrong protocol version?)"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The daemon, run from an aMule config directory with a legacy EC
/// password: an EC client logs in, reads the statistics and the connection
/// state, and shuts it down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ec_client_drives_the_daemon() {
    let d = TempDir::new("drive");
    let (port, ec_port) = (free_port(), free_port());
    std::fs::write(
        d.0.join("amule.conf"),
        format!(
            "[eMule]\nPort={port}\nConnectToKad=0\nConnectToED2K=0\nMaxUpload=50\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\n\
             ECPassword={SECRET}\n"
        ),
    )
    .unwrap();
    let loaded = config::load(&d.0).unwrap();
    assert!(!conf_text(&d).contains("ECPassword="), "migrated");
    let daemon = tokio::spawn(crate::client::run(
        loaded.client,
        Vec::new(),
        Vec::new(),
        std::future::pending(),
    ));
    let mut tries = 0;
    while tokio::net::TcpStream::connect(("127.0.0.1", ec_port))
        .await
        .is_err()
    {
        tries += 1;
        assert!(tries < 100, "the daemon never listened for EC");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Let the first status refresh land.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let replies = tokio::task::spawn_blocking(move || {
        // The wrong password first.
        let wrong = Client::connect(&ConnectOptions::new(
            "127.0.0.1",
            ec_port,
            password_digest("nope"),
        ));
        assert!(wrong.is_err());
        let mut c = Client::connect(&ConnectOptions::new("127.0.0.1", ec_port, SECRET)).unwrap();
        assert!(c.info().version.starts_with("remuled "), "{:?}", c.info());
        let stats = c
            .request(&Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_FULL))
            .unwrap();
        let state = c
            .request(&Packet::new(EC_OP_GET_CONNSTATE).with_detail(EC_DETAIL_CMD))
            .unwrap();
        let bye = c.request(&Packet::new(EC_OP_SHUTDOWN)).unwrap();
        (stats, state, bye)
    })
    .await
    .unwrap();
    let (stats, state, bye) = replies;
    assert_eq!(stats.opcode, EC_OP_STATS);
    assert_eq!(
        stats.tag(EC_TAG_STATS_UL_SPEED_LIMIT).map(Tag::as_int),
        Some(50 * 1024)
    );
    assert!(stats.tag(EC_TAG_STATS_UPTIME_SECONDS).unwrap().as_int() >= 1);
    let cs = state.tag(EC_TAG_CONNSTATE).unwrap();
    // Neither network: nothing connected, nothing enabled.
    assert_eq!(cs.as_int(), 0);
    assert_eq!(cs.child_int(EC_TAG_NETWORKS_ENABLED), 0);
    assert_eq!(bye.opcode, EC_OP_NOOP);
    // The daemon stops, and saves as on any shutdown.
    let s = tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
    assert_eq!(s.completed, 0);
}
