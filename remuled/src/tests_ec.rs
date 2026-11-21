// SPDX-License-Identifier: GPL-2.0-or-later
//! External connections: the EC password as aMule 3.3 loads and migrates
//! it, `[ExternalConnect]`, the replies, and an EC client driving a
//! running daemon.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::Duration;

use ed2k_formats::amule_conf::ConfFile;
use ed2k_types::{Md4Hash, UInt128};
use remule_ec::codes::*;
use remule_ec::srp::{password_digest, Verifier};
use remule_ec::{Client, ConnectOptions, Packet, Tag};

use crate::config;
use crate::ec::{self, Control, Download, DownloadIds, KadStatus, ServerStatus, Status};

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
            ecid: 77,
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
        downloads: Vec::new(),
        applied: 0,
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

/// `answer` with a client that does what it is told: links are taken
/// unless they say "bad", file commands succeed unless they are for 0xEE..
async fn ask(req: Packet, s: &Status, shutting_down: bool) -> (Packet, bool, Vec<String>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let client = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Some(c) = rx.recv().await {
            match c {
                Control::Shutdown => seen.push("shutdown".to_string()),
                Control::AddLink { link, reply, .. } => {
                    let _ = reply.send(!link.contains("bad"));
                    seen.push(format!("link {link}"));
                }
                Control::File { file, op, reply } => {
                    let _ = reply.send(if file == Md4Hash([0xEE; 16]) {
                        Err("disk full".into())
                    } else {
                        Ok(())
                    });
                    seen.push(format!("{op:?} {file}"));
                }
                Control::Search { req, .. } => seen.push(format!("search {:#x}", req.opcode)),
                Control::Servers { request, reply } => {
                    let _ = reply.send(Packet::new(EC_OP_NOOP));
                    seen.push(format!("servers {:#x}", request.opcode));
                }
                Control::Shared(_) => seen.push("shared".to_string()),
                Control::Update(reply) => {
                    let _ = reply.send(Default::default());
                    seen.push("update".to_string());
                }
                Control::StatsTree(reply) => {
                    let _ = reply.send(Default::default());
                    seen.push("stats tree".to_string());
                }
                Control::IpFilterReload => seen.push("ipfilter reload".to_string()),
                Control::ClientHistory(reply) => {
                    let _ = reply.send(Vec::new());
                    seen.push("client history".to_string());
                }
                Control::Friend { req, reply } => {
                    let _ = reply.send(Packet::new(EC_OP_NOOP));
                    seen.push(format!("friend {:#x}", req.opcode));
                }
                Control::CategoryRemoved(c, done) => {
                    let _ = done.send(());
                    seen.push(format!("category removed {c}"));
                }
                Control::IpFilterUpdate(url) => seen.push(format!("ipfilter update {url}")),
            }
        }
        seen
    });
    let prefs = std::sync::Mutex::new(crate::prefs::PrefStore::default());
    let history = std::sync::Mutex::new(crate::graphs::History::new());
    let mut cv = ec::ConnView {
        log: crate::applog::global().cursor(),
        partial: false,
        search: Default::default(),
        update: Default::default(),
        prefs: &prefs,
        history: &history,
        version: "remuled test",
    };
    let (r, stops) = ec::answer(&req, s, shutting_down, &tx, &mut cv).await;
    drop(tx);
    (r, stops, client.await.unwrap())
}

#[tokio::test]
async fn requests_are_answered_as_process_request2_does() {
    let s = busy();
    let (r, stops, seen) = ask(Packet::new(EC_OP_SHUTDOWN), &s, false).await;
    assert_eq!((r.opcode, stops), (EC_OP_NOOP, true));
    assert_eq!(seen, ["shutdown"]);
    let (r, stops, seen) = ask(Packet::new(EC_OP_SHUTDOWN), &s, true).await;
    assert_eq!((r.opcode, stops), (EC_OP_FAILED, false));
    assert!(seen.is_empty());
    assert_eq!(r.message().unwrap(), "Already shutting down.");
    // No detail level: FULL.
    let (r, ..) = ask(Packet::new(EC_OP_STAT_REQ), &s, false).await;
    assert!(r.tag(EC_TAG_STATS_UPTIME_SECONDS).is_some());
    let (r, ..) = ask(
        Packet::new(EC_OP_GET_CONNSTATE).with_detail(EC_DETAIL_CMD),
        &s,
        false,
    )
    .await;
    assert_eq!(r.opcode, EC_OP_MISC_DATA);
    assert_eq!(r.tags[0].name, EC_TAG_CONNSTATE);
    // The Kad buddy counters, only when asked for.
    let (r, ..) = ask(Packet::new(EC_OP_STAT_REQ), &s, false).await;
    assert!(r.tag(EC_TAG_KAD_BUDDY).is_none());
    let (r, ..) = ask(
        Packet::new(EC_OP_STAT_REQ).with(Tag::empty(EC_TAG_KAD_BUDDY)),
        &s,
        false,
    )
    .await;
    assert_eq!(r.tag(EC_TAG_KAD_BUDDY).unwrap().children.len(), 41);
    // The IP filter: reloaded; updated from the URL given, or from the
    // configured one (none here: nothing to fetch).
    let (r, _, seen) = ask(Packet::new(EC_OP_IPFILTER_RELOAD), &s, false).await;
    assert_eq!(
        (r.opcode, seen),
        (EC_OP_NOOP, vec!["ipfilter reload".to_string()])
    );
    let (r, _, seen) = ask(
        Packet::new(EC_OP_IPFILTER_UPDATE)
            .with(Tag::string(EC_TAG_STRING, "http://x/ipfilter.dat")),
        &s,
        false,
    )
    .await;
    assert_eq!(r.opcode, EC_OP_NOOP);
    assert_eq!(seen, ["ipfilter update http://x/ipfilter.dat"]);
    let (_, _, seen) = ask(
        Packet::new(EC_OP_IPFILTER_UPDATE).with(Tag::string(EC_TAG_STRING, "")),
        &s,
        false,
    )
    .await;
    assert!(seen.is_empty());
    let (r, ..) = ask(Packet::new(EC_OP_GET_CHAT_SESSIONS), &s, false).await;
    assert_eq!(r.opcode, EC_OP_FAILED);
    assert_eq!(
        r.message().unwrap(),
        "Invalid opcode (wrong protocol version?)"
    );
}

fn download(ecid: u32, hash: u8, status: u8) -> Download {
    Download {
        ecid,
        hash: Md4Hash([hash; 16]),
        name: format!("file {hash}.iso"),
        size: 10_000_000,
        completed: 2_500_000,
        transferred: 2_600_000,
        sources: 5,
        transferring: 0,
        status,
        stopped: false,
        speed: 0,
        part_met_id: 7,
        dir: "/tmp/Temp".into(),
        priority: 11,
        up_priority: 12,
        category: 0,
        last_seen_complete: 0,
        lost_to_corruption: 0,
        gaps: Vec::new(),
        requested: Vec::new(),
        part_frequency: Vec::new(),
    }
}

#[test]
fn downloads_are_told_as_cec_partfile_tag_tells_them() {
    let d = download(3, 0xAB, ec::ps::EMPTY);
    let cmd = ec::partfile_tag(&d, EC_DETAIL_CMD);
    assert_eq!((cmd.name, cmd.as_int()), (EC_TAG_PARTFILE, 3));
    // What amulecmd's `show dl` reads.
    assert_eq!(
        cmd.child(EC_TAG_PARTFILE_HASH).unwrap().as_hash(),
        Some([0xAB; 16])
    );
    assert_eq!(cmd.child_str(EC_TAG_PARTFILE_NAME), "file 171.iso");
    assert_eq!(cmd.child_int(EC_TAG_PARTFILE_SIZE_FULL), 10_000_000);
    assert_eq!(cmd.child_int(EC_TAG_PARTFILE_SIZE_DONE), 2_500_000);
    assert_eq!(cmd.child_int(EC_TAG_PARTFILE_SIZE_XFER), 2_600_000);
    assert_eq!(cmd.child_int(EC_TAG_PARTFILE_SOURCE_COUNT), 5);
    assert_eq!(cmd.child_int(EC_TAG_PARTFILE_STATUS), 1);
    assert_eq!(cmd.child_int(EC_TAG_PARTFILE_PRIO), 11);
    assert_eq!(cmd.child_int(EC_TAG_KNOWNFILE_PRIO), 12);
    assert_eq!(cmd.child_int(EC_TAG_PARTFILE_PARTMETID), 7);
    assert_eq!(cmd.child_str(EC_TAG_KNOWNFILE_FILENAME), "007.part");
    assert_eq!(cmd.child_str(EC_TAG_KNOWNFILE_PATH), "/tmp/Temp");
    assert_eq!(
        cmd.child_str(EC_TAG_PARTFILE_ED2K_LINK),
        format!("ed2k://|file|file 171.iso|10000000|{}|/", "AB".repeat(16))
    );
    // UPDATE: no names, no sizes unless it is transferring, no met ID.
    let upd = ec::partfile_tag(&d, EC_DETAIL_UPDATE);
    for gone in [
        EC_TAG_PARTFILE_NAME,
        EC_TAG_PARTFILE_HASH,
        EC_TAG_PARTFILE_SIZE_DONE,
        EC_TAG_PARTFILE_PARTMETID,
    ] {
        assert!(!upd.has(gone), "{gone:#x}");
    }
    assert!(upd.has(EC_TAG_PARTFILE_STATUS));
    let busy = Download {
        transferring: 2,
        speed: 4096,
        ..d.clone()
    };
    let upd = ec::partfile_tag(&busy, EC_DETAIL_UPDATE);
    assert_eq!(upd.child_int(EC_TAG_PARTFILE_SPEED), 4096);

    // The queue: all of them, or those asked for by ECID.
    let s = Status {
        downloads: vec![download(1, 1, 0), download(2, 2, 0), download(3, 3, 0)],
        ..Default::default()
    };
    let all = ec::download_queue_reply(&Packet::new(EC_OP_GET_DLOAD_QUEUE), &s);
    assert_eq!((all.opcode, all.tags.len()), (EC_OP_DLOAD_QUEUE, 3));
    let some = ec::download_queue_reply(
        &Packet::new(EC_OP_GET_DLOAD_QUEUE)
            .with(Tag::int(EC_TAG_PARTFILE, 3))
            .with(Tag::int(EC_TAG_PARTFILE, 1)),
        &s,
    );
    let ids: Vec<u64> = some.tags.iter().map(Tag::as_int).collect();
    assert_eq!(ids, [1, 3]);
}

#[test]
fn download_ids_and_speeds_last_while_the_download_does() {
    use remule_core::download_queue::FileProgress;
    use remule_core::part_file::Status as S;
    let p = |hash: u8, transferred: u64, status: S, paused: bool, done: bool| FileProgress {
        hash: Md4Hash([hash; 16]),
        name: "x".into(),
        size: 100,
        completed: 0,
        sources: 0,
        queued: 0,
        connected: 0,
        downloading: 0,
        done,
        paused,
        stopped: paused,
        status,
        transferred,
        part_met_name: "012.part".into(),
        priority: 1,
        auto_priority: true,
        up_priority: 2,
        auto_up_priority: false,
        category: 0,
        last_seen_complete: 0,
        lost_to_corruption: 0,
        gaps: Vec::new(),
        requested: Vec::new(),
        part_frequency: Vec::new(),
    };
    let mut ids = DownloadIds::default();
    let temp = std::path::Path::new("T");
    let v = ids.view(
        &[
            p(1, 0, S::Empty, false, false),
            p(2, 50, S::Ready, true, false),
        ],
        temp,
    );
    // One counter for every ECID in the process: distinct, never 0.
    let (one, two) = (v[0].ecid, v[1].ecid);
    assert!(one != 0 && two != 0 && one != two);
    assert_eq!((v[0].status, v[1].status), (ec::ps::EMPTY, ec::ps::PAUSED));
    assert_eq!(
        (v[0].priority, v[0].up_priority, v[0].part_met_id),
        (11, 2, 12)
    );
    assert_eq!(v[1].speed, 0, "no speed on first sight");
    // A second later: the bytes since are the speed; IDs stay.
    let v = ids.view(
        &[
            p(1, 3000, S::Ready, false, false),
            p(2, 50, S::Ready, true, false),
        ],
        temp,
    );
    assert_eq!(
        (v[0].ecid, v[0].speed, v[0].status),
        (one, 3000, ec::ps::READY)
    );
    // Gone, and back: a new ID. Finished: complete.
    let v = ids.view(&[p(2, 50, S::Complete, false, true)], temp);
    assert_eq!((v[0].ecid, v[0].status), (two, ec::ps::COMPLETE));
    let v = ids.view(&[p(1, 0, S::Empty, false, false)], temp);
    assert!(v[0].ecid != one && v[0].ecid != two);
}

#[tokio::test]
async fn partfile_commands_check_their_targets() {
    let s = Status {
        downloads: vec![
            download(1, 1, ec::ps::EMPTY),
            download(2, 2, ec::ps::COMPLETE),
            download(3, 0xEE, ec::ps::READY),
        ],
        ..Default::default()
    };
    let cmd = |op: u8, tags: Vec<Tag>| {
        let mut p = Packet::new(op);
        p.tags = tags;
        p
    };
    let h = |b: u8| Tag::hash(EC_TAG_PARTFILE, [b; 16]);
    // Each named file, in order.
    let (r, _, seen) = ask(cmd(EC_OP_PARTFILE_PAUSE, vec![h(1)]), &s, false).await;
    assert_eq!(r.opcode, EC_OP_NOOP);
    assert_eq!(seen, [format!("Pause {}", "01".repeat(16))]);
    let (r, _, seen) = ask(cmd(EC_OP_PARTFILE_RESUME, vec![h(1), h(2)]), &s, false).await;
    assert_eq!(r.opcode, EC_OP_NOOP);
    assert_eq!(seen.len(), 2);
    // Not a hash, or an unknown one: stop there.
    let (r, _, seen) = ask(
        cmd(EC_OP_PARTFILE_STOP, vec![Tag::int(EC_TAG_PARTFILE, 1)]),
        &s,
        false,
    )
    .await;
    assert_eq!(r.message().unwrap(), "Invalid partfile command target.");
    assert!(seen.is_empty());
    let (r, _, seen) = ask(cmd(EC_OP_PARTFILE_STOP, vec![h(9), h(1)]), &s, false).await;
    assert_eq!(
        r.message().unwrap(),
        format!("FileHash not found: {}", "09".repeat(16))
    );
    assert!(seen.is_empty());
    // An ECID that does not match: the GUI's view is stale.
    let (r, ..) = ask(
        cmd(
            EC_OP_PARTFILE_PAUSE,
            vec![h(1).with(Tag::int(EC_TAG_ECID, 2))],
        ),
        &s,
        false,
    )
    .await;
    assert_eq!(
        r.message().unwrap(),
        "The selected download has changed. Refresh and try again."
    );
    // Cancelling: a finished one is skipped (and said), the rest go on.
    let (r, _, seen) = ask(cmd(EC_OP_PARTFILE_DELETE, vec![h(2), h(1)]), &s, false).await;
    assert_eq!(
        r.message().unwrap(),
        "Cannot cancel a hashing or finished download: file 2.iso"
    );
    assert_eq!(seen, [format!("Delete {}", "01".repeat(16))]);
    // ... with the name and folder the client saw, if it says them.
    let (r, _, seen) = ask(
        cmd(
            EC_OP_PARTFILE_DELETE,
            vec![h(1).with(Tag::string(EC_TAG_PARTFILE_NAME, "other.iso"))],
        ),
        &s,
        false,
    )
    .await;
    assert_eq!(
        r.message().unwrap(),
        "The selected download has changed or is completing. Refresh and try again."
    );
    assert!(seen.is_empty());
    // The client's own failure is the reply.
    let (r, ..) = ask(cmd(EC_OP_PARTFILE_PAUSE, vec![h(0xEE)]), &s, false).await;
    assert_eq!(r.message().unwrap(), "disk full");

    // Links: one reply for all.
    let link = |l: &str| Tag::string(EC_TAG_STRING, l);
    let (r, _, seen) = ask(
        cmd(EC_OP_ADD_LINK, vec![link("ed2k://a"), link("ed2k://b")]),
        &s,
        false,
    )
    .await;
    assert_eq!((r.opcode, seen.len()), (EC_OP_NOOP, 2));
    let (r, ..) = ask(cmd(EC_OP_ADD_LINK, vec![link("bad")]), &s, false).await;
    assert_eq!(r.message().unwrap(), "Invalid link or already on list.");
    let (r, ..) = ask(
        cmd(
            EC_OP_ADD_LINK,
            vec![link("ed2k://a"), link("bad"), link("bad 2")],
        ),
        &s,
        false,
    )
    .await;
    assert_eq!(
        r.message().unwrap(),
        "2 of 3 links failed (invalid or already on list)."
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

/// Downloads over EC, as `amulecmd` drives them: a link added, listed,
/// paused, resumed and cancelled, with the files on disk following.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ec_client_adds_pauses_and_cancels_a_download() {
    let d = TempDir::new("downloads");
    let (port, ec_port) = (free_port(), free_port());
    std::fs::write(
        d.0.join("amule.conf"),
        format!(
            "[eMule]\nPort={port}\nConnectToKad=0\nConnectToED2K=0\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\n\
             ECPassword={SECRET}\n"
        ),
    )
    .unwrap();
    let loaded = config::load(&d.0).unwrap();
    let temp = loaded.client.temp.clone();
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

    let hash = Md4Hash([0x4D; 16]);
    let temp2 = temp.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(&ConnectOptions::new("127.0.0.1", ec_port, SECRET)).unwrap();
        let mut ask = |p: Packet| c.request(&p).unwrap();
        // The queue as `show dl` asks for it, right after the change: a
        // change is answered once the view shows it.
        let queue_until = |ask: &mut dyn FnMut(Packet) -> Packet, ok: &dyn Fn(&Packet) -> bool| {
            for _ in 0..1 {
                let q = ask(Packet::new(EC_OP_GET_DLOAD_QUEUE));
                if ok(&q) {
                    return q;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            panic!("the queue never got there");
        };
        let link = format!("ed2k://|file|Some%20Film.mkv|123456789|{hash}|/");
        let add = |l: &str| Packet::new(EC_OP_ADD_LINK).with(Tag::string(EC_TAG_STRING, l));
        assert_eq!(ask(add(&link)).opcode, EC_OP_NOOP);
        let q = queue_until(&mut ask, &|q| q.tags.len() == 1);
        let f = &q.tags[0];
        assert_eq!(f.child_str(EC_TAG_PARTFILE_NAME), "Some Film.mkv");
        assert_eq!(f.child_int(EC_TAG_PARTFILE_SIZE_FULL), 123_456_789);
        assert_eq!(
            f.child_int(EC_TAG_PARTFILE_STATUS),
            u64::from(ec::ps::EMPTY)
        );
        assert_eq!(f.child_int(EC_TAG_PARTFILE_PARTMETID), 1);
        let met = temp2.join("001.part.met");
        assert!(met.is_file());
        // The same file again: taken (it is being downloaded), still one.
        // A link that is no link, and one in another protocol: refused.
        assert_eq!(ask(add(&link)).opcode, EC_OP_NOOP);
        let r = ask(add("ed2k://|file|broken|"));
        assert_eq!(r.message().unwrap(), "Invalid link or already on list.");
        let r = ask(add("http://example.org/x"));
        assert_eq!(r.opcode, EC_OP_FAILED);

        // Paused: so the queue says, and so the met says.
        let target = || Tag::hash(EC_TAG_PARTFILE, hash.0);
        assert_eq!(
            ask(Packet::new(EC_OP_PARTFILE_PAUSE).with(target())).opcode,
            EC_OP_NOOP
        );
        queue_until(&mut ask, &|q| {
            q.tags[0].child_int(EC_TAG_PARTFILE_STATUS) == u64::from(ec::ps::PAUSED)
        });
        assert!(remule_core::PartFile::open(&met).unwrap().is_paused());
        // Resumed.
        assert_eq!(
            ask(Packet::new(EC_OP_PARTFILE_RESUME).with(target())).opcode,
            EC_OP_NOOP
        );
        queue_until(&mut ask, &|q| {
            q.tags[0].child_int(EC_TAG_PARTFILE_STATUS) == u64::from(ec::ps::EMPTY)
        });
        assert!(!remule_core::PartFile::open(&met).unwrap().is_paused());
        // Priority high: shown at once, kept in the met.
        let prio = |v: u64| {
            Packet::new(EC_OP_PARTFILE_PRIO_SET)
                .with(target().with(Tag::int(EC_TAG_PARTFILE_PRIO, v)))
        };
        assert_eq!(ask(prio(2)).opcode, EC_OP_NOOP);
        queue_until(&mut ask, &|q| {
            q.tags[0].child_int(EC_TAG_PARTFILE_PRIO) == 2
        });
        assert_eq!(
            remule_core::PartFile::open(&met)
                .unwrap()
                .info()
                .down_priority,
            2
        );
        // Automatic: sent back as high plus 10.
        assert_eq!(ask(prio(5)).opcode, EC_OP_NOOP);
        queue_until(&mut ask, &|q| {
            q.tags[0].child_int(EC_TAG_PARTFILE_PRIO) == 12
        });
        // The one category there is, and one there is not.
        let cat = |v: u64| {
            Packet::new(EC_OP_PARTFILE_SET_CAT)
                .with(target().with(Tag::int(EC_TAG_PARTFILE_CAT, v)))
        };
        assert_eq!(ask(cat(0)).opcode, EC_OP_NOOP);
        assert_eq!(ask(cat(3)).message().unwrap(), "No such category: 3");
        // Cancelled: gone from the queue and the disk.
        assert_eq!(
            ask(Packet::new(EC_OP_PARTFILE_DELETE).with(target())).opcode,
            EC_OP_NOOP
        );
        queue_until(&mut ask, &|q| q.tags.is_empty());
        assert!(!met.exists());
        assert!(!temp2.join("001.part").exists());
        // A magnet with an ed2k hash, as amuleapi passes it on.
        let magnet = format!(
            "magnet:?xt=urn:ed2k:{}&xl=4096&dn=magnet%20file.bin",
            "AB".repeat(16)
        );
        assert_eq!(ask(add(&magnet)).opcode, EC_OP_NOOP);
        queue_until(&mut ask, &|q| {
            q.tags.len() == 1 && q.tags[0].child_str(EC_TAG_PARTFILE_NAME) == "magnet file.bin"
        });
        assert_eq!(
            ask(add("magnet:?xt=urn:btih:abc&xl=1")).message().unwrap(),
            "Invalid link or already on list."
        );
        // An unknown one now.
        let r = ask(Packet::new(EC_OP_PARTFILE_PAUSE).with(target()));
        assert_eq!(r.message().unwrap(), format!("FileHash not found: {hash}"));
        assert_eq!(ask(Packet::new(EC_OP_SHUTDOWN)).opcode, EC_OP_NOOP);
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
}

/// The log over EC: new lines on the GUI's stats poll, the whole log, the
/// last line, a reset; the server's messages.
#[tokio::test]
async fn the_log_is_read_as_amules_is() {
    let log = crate::applog::global();
    let s = busy();
    log.push(tracing::Level::INFO, "an EC log test line");
    // One connection's view: what is new, once.
    let prefs = std::sync::Mutex::new(crate::prefs::PrefStore::default());
    let history = std::sync::Mutex::new(crate::graphs::History::new());
    let mut cv = ec::ConnView {
        log: log.cursor(),
        partial: false,
        search: Default::default(),
        update: Default::default(),
        prefs: &prefs,
        history: &history,
        version: "remuled test",
    };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let stats = || Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_INC_UPDATE);
    let (r, _) = ec::answer(&stats(), &s, false, &tx, &mut cv).await;
    let lines = r.tag(EC_TAG_STATS_LOGGER_MESSAGE).expect("the new lines");
    assert!(lines
        .children
        .iter()
        .any(|l| l.as_str().ends_with("INFO  an EC log test line\n")));
    assert_eq!(
        r.tags[3].name, EC_TAG_STATS_LOGGER_MESSAGE,
        "after the banned count"
    );
    let (r, _) = ec::answer(&stats(), &s, false, &tx, &mut cv).await;
    assert!(r.tag(EC_TAG_STATS_LOGGER_MESSAGE).is_none(), "nothing new");
    // amulecmd's level gets none.
    log.push(tracing::Level::INFO, "another");
    let (r, _) = ec::answer(
        &Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_CMD),
        &s,
        false,
        &tx,
        &mut cv,
    )
    .await;
    assert!(r.tag(EC_TAG_STATS_LOGGER_MESSAGE).is_none());

    let (r, ..) = ask(Packet::new(EC_OP_GET_LOG), &s, false).await;
    assert_eq!(r.opcode, EC_OP_LOG);
    assert!(r.message().unwrap().contains("an EC log test line\n"));
    let (r, ..) = ask(Packet::new(EC_OP_GET_LAST_LOG_ENTRY), &s, false).await;
    assert!(r.message().unwrap().ends_with("INFO  another"), "{r:?}");
    let (r, ..) = ask(
        Packet::new(EC_OP_ADDLOGLINE)
            .with(Tag::string(EC_TAG_STRING, "from a client"))
            .with(Tag::empty(EC_TAG_LOG_TO_STATUS)),
        &s,
        false,
    )
    .await;
    assert_eq!(r.opcode, EC_OP_NOOP);
    assert!(log.text().contains("!") && log.text().contains("WARN  from a client"));

    log.server_message("hello from the server");
    let (r, ..) = ask(Packet::new(EC_OP_GET_SERVERINFO), &s, false).await;
    assert_eq!(r.opcode, EC_OP_SERVERINFO);
    assert!(r.message().unwrap().contains("hello from the server\n"));
    let (r, ..) = ask(Packet::new(EC_OP_CLEAR_SERVERINFO), &s, false).await;
    assert_eq!(r.opcode, EC_OP_NOOP);
    let (r, ..) = ask(Packet::new(EC_OP_GET_SERVERINFO), &s, false).await;
    assert_eq!(r.message().unwrap(), "");

    // A reset: the log starts over, and this connection with it.
    let (r, ..) = ask(Packet::new(EC_OP_RESET_LOG), &s, false).await;
    assert_eq!(r.opcode, EC_OP_NOOP);
    let (r, _) = ec::answer(&stats(), &s, false, &tx, &mut cv).await;
    let lines = r.tag(EC_TAG_STATS_LOGGER_MESSAGE).unwrap();
    assert!(lines.children[0].as_str().ends_with("Log has been reset\n"));
}
