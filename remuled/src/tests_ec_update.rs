// SPDX-License-Identifier: GPL-2.0-or-later
//! `amulegui`'s incremental updates and the preferences it reads: what
//! changed and only that, the bars as diffs a client decodes, and a daemon
//! asked for both over EC.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use ed2k_formats::server_met::ServerInfo;
use ed2k_types::Md4Hash;
use remule_ec::codes::*;
use remule_ec::rle::RleData;
use remule_ec::srp::password_digest;
use remule_ec::{Client, ConnectOptions, Packet, Tag};

use crate::ec::{self, Download, ServerStatus, Status};
use crate::ec_shared::SharedBase;
use crate::ec_update::{
    prefs_reply, DirPrefs, EcPrefs, GeoipPrefs, RemotePrefs, UpdateData, UpdateServer, UpdateState,
    ValueMap,
};

fn download(ecid: u32, gaps: Vec<(u64, u64)>) -> Download {
    Download {
        ecid,
        hash: Md4Hash([ecid as u8; 16]),
        name: format!("film {ecid}.mkv"),
        size: 30_000_000,
        completed: 30_000_000 - gaps.iter().map(|(s, e)| e - s + 1).sum::<u64>(),
        status: ec::ps::EMPTY,
        part_met_id: ecid as u16,
        dir: "/T".into(),
        priority: 1,
        gaps,
        part_frequency: vec![0, 2, 1],
        ..Default::default()
    }
}

fn shared(ecid: u32) -> SharedBase {
    SharedBase {
        ecid,
        hash: Md4Hash([0xC0 | ecid as u8; 16]),
        name: "book.pdf".into(),
        size: 1234,
        ..Default::default()
    }
}

fn server(ecid: u32) -> UpdateServer {
    UpdateServer {
        ecid,
        info: ServerInfo {
            ip: Some(Ipv4Addr::new(1, 2, 3, 4)),
            port: 4661,
            name: "a server".into(),
            users: 10,
            ..Default::default()
        },
        tcp_flags: 0x19,
    }
}

fn names(t: &Tag) -> Vec<u16> {
    t.children.iter().map(|c| c.name).collect()
}

#[test]
fn a_value_map_passes_on_only_what_changed() {
    let mut m = ValueMap::default();
    let t = |a: u64, b: &str| {
        Tag::int(EC_TAG_PARTFILE, 1)
            .with(Tag::int(EC_TAG_PARTFILE_SIZE_DONE, a))
            .with(Tag::string(EC_TAG_PARTFILE_NAME, b))
    };
    let first = m.filter(t(5, "x"));
    assert_eq!(
        names(&first),
        [EC_TAG_PARTFILE_SIZE_DONE, EC_TAG_PARTFILE_NAME]
    );
    assert!(m.filter(t(5, "x")).children.is_empty());
    let second = m.filter(t(6, "x"));
    assert_eq!(names(&second), [EC_TAG_PARTFILE_SIZE_DONE]);
    assert_eq!(second.child_int(EC_TAG_PARTFILE_SIZE_DONE), 6);
    // The tag itself (its ECID) always goes.
    assert_eq!(second.as_int(), 1);
}

/// A client's view of one download's bars, as amulegui keeps it.
struct Bars {
    gaps: RleData,
    parts: RleData,
}

impl Bars {
    fn new() -> Self {
        Bars {
            gaps: RleData::new(true),
            parts: RleData::new(true),
        }
    }

    fn apply(&mut self, t: &Tag) -> (Option<Vec<u64>>, Option<Vec<u8>>) {
        (
            t.child(EC_TAG_PARTFILE_GAP_STATUS)
                .map(|g| self.gaps.decode_u64(&g.data)),
            t.child(EC_TAG_PARTFILE_PART_STATUS)
                .map(|p| self.parts.decode(&p.data).to_vec()),
        )
    }
}

#[test]
fn updates_carry_changes_by_ecid_and_bars_as_diffs() {
    let mut st = UpdateState::default();
    let data = UpdateData {
        shared: vec![shared(3)],
        servers: vec![server(9)],
    };
    let mut dl = vec![
        download(5, vec![(0, 29_999_999)]),
        download(2, vec![(100, 199)]),
    ];
    let p = st.reply(&dl, &data, false);
    assert_eq!(p.opcode, EC_OP_SHARED_FILES);
    // Files in ECID order, then clients, servers and friends.
    let tops: Vec<(u16, u64)> = p.tags.iter().map(|t| (t.name, t.as_int())).collect();
    assert_eq!(
        tops[..3],
        [
            (EC_TAG_PARTFILE, 2),
            (EC_TAG_KNOWNFILE, 3),
            (EC_TAG_PARTFILE, 5)
        ]
    );
    assert_eq!(
        p.tags[3..].iter().map(|t| t.name).collect::<Vec<_>>(),
        [EC_TAG_CLIENT, EC_TAG_SERVER, EC_TAG_FRIEND]
    );
    // The first time: everything, names included, and the bars.
    let f5 = &p.tags[2];
    assert_eq!(f5.child_str(EC_TAG_PARTFILE_NAME), "film 5.mkv");
    assert_eq!(f5.child_int(EC_TAG_PARTFILE_SHARED), 0);
    let mut bars = Bars::new();
    assert_eq!(
        bars.apply(f5),
        (Some(vec![0, 29_999_999]), Some(vec![0, 2, 1]))
    );
    // No blocks requested, from none: RLE_Data sees no change, no tag.
    assert!(!f5.has(EC_TAG_PARTFILE_REQ_STATUS));
    let srv = &p.tags[4].children[0];
    assert_eq!(srv.as_int(), 9);
    assert_eq!(srv.child_str(EC_TAG_SERVER_NAME), "a server");
    assert_eq!(
        srv.child_int(EC_TAG_SERVER_IP),
        u64::from(u32::from_le_bytes([1, 2, 3, 4]))
    );
    assert_eq!(srv.child_int(EC_TAG_SERVER_TCP_FLAGS), 0x19);
    assert_eq!(p.tags[1].child_str(EC_TAG_PARTFILE_NAME), "book.pdf");

    // Nothing changed: bare ECIDs, still listed.
    let p = st.reply(&dl, &data, false);
    for t in &p.tags[..3] {
        assert!(t.children.is_empty(), "{t:?}");
    }
    assert!(p.tags[4].children[0].children.is_empty());

    // Some of file 5 arrived: its sizes and its gap bar, as a diff the
    // client's decoder turns into the new gaps.
    dl[0] = download(5, vec![(9_728_000, 29_999_999)]);
    dl[0].transferred = 9_728_000;
    let p = st.reply(&dl, &data, false);
    let f5 = p.tags.iter().find(|t| t.as_int() == 5).unwrap();
    assert!(f5.has(EC_TAG_PARTFILE_SIZE_DONE));
    assert!(!f5.has(EC_TAG_PARTFILE_NAME));
    assert!(
        !f5.has(EC_TAG_PARTFILE_PART_STATUS),
        "availability unchanged"
    );
    assert_eq!(bars.apply(f5).0, Some(vec![9_728_000, 29_999_999]));

    // File 2 gone, file 7 new: 7 goes out whole; 2 is simply absent.
    dl.retain(|d| d.ecid != 2);
    dl.push(download(7, vec![(0, 9)]));
    let p = st.reply(&dl, &data, false);
    assert!(p
        .tags
        .iter()
        .all(|t| t.as_int() != 2 || t.name != EC_TAG_PARTFILE));
    let f7 = p.tags.iter().find(|t| t.as_int() == 7).unwrap();
    assert!(f7.has(EC_TAG_PARTFILE_NAME));
    // ... and if 2 came back under the same ECID, from nothing again.
    dl.push(download(2, vec![(100, 199)]));
    let p = st.reply(&dl, &data, false);
    let f2 = p.tags.iter().find(|t| t.as_int() == 2).unwrap();
    assert!(f2.has(EC_TAG_PARTFILE_NAME));
    let mut fresh = Bars::new();
    assert_eq!(fresh.apply(f2).0, Some(vec![100, 199]));
}

#[test]
fn the_connection_state_names_the_server_by_ecid_when_incremental() {
    let s = Status {
        server: Some(ServerStatus {
            ecid: 41,
            name: "x".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let t = ec::connstate_tag(&s, EC_DETAIL_INC_UPDATE);
    let srv = t.child(EC_TAG_SERVER).unwrap();
    assert_eq!((srv.as_int(), srv.children.len()), (41, 0));
}

fn prefs() -> EcPrefs {
    EcPrefs {
        nick: "me".into(),
        user_hash: [7; 16],
        upload_capacity: 2500,
        download_capacity: 12500,
        max_upload: 50,
        tcp_port: 4662,
        udp_port: 4672,
        udp_enabled: false,
        max_connections: 500,
        autoconnect: true,
        ed2k: true,
        ..Default::default()
    }
}

#[test]
fn preferences_are_the_pages_asked_for() {
    let ask = |sel: u32| {
        prefs_reply(
            &Packet::new(EC_OP_GET_PREFERENCES)
                .with_detail(EC_DETAIL_UPDATE)
                .with(Tag::int(EC_TAG_SELECT_PREFS, sel.into())),
            &prefs(),
        )
    };
    let r = ask(EC_PREFS_GENERAL | EC_PREFS_CONNECTIONS | EC_PREFS_CATEGORIES);
    assert_eq!(r.opcode, EC_OP_SET_PREFERENCES);
    assert_eq!(
        r.tag(EC_TAG_DETAIL_LEVEL).unwrap().as_int(),
        u64::from(EC_DETAIL_UPDATE)
    );
    let g = r.tag(EC_TAG_PREFS_GENERAL).unwrap();
    assert_eq!(g.child_str(EC_TAG_USER_NICK), "me");
    assert_eq!(g.child(EC_TAG_USER_HASH).unwrap().as_hash(), Some([7; 16]));
    let c = r.tag(EC_TAG_PREFS_CONNECTIONS).unwrap();
    assert_eq!(c.child_int(EC_TAG_CONN_MAX_UL), 50);
    assert_eq!(c.child_int(EC_TAG_CONN_UDP_PORT), 4672);
    assert_eq!(c.child_int(EC_TAG_CONN_MAX_CONN), 500);
    // Flags are present-or-absent.
    assert!(c.has(EC_TAG_CONN_UDP_DISABLE));
    assert!(c.has(EC_TAG_CONN_AUTOCONNECT));
    assert!(!c.has(EC_TAG_CONN_RECONNECT));
    assert!(c.has(EC_TAG_NETWORK_ED2K) && !c.has(EC_TAG_NETWORK_KADEMLIA));
    // One category only, as with aMule's: none sent.
    assert!(r.tag(EC_TAG_PREFS_CATEGORIES).is_none());
    // Only what was asked.
    let r = ask(EC_PREFS_GENERAL);
    assert!(r.tag(EC_TAG_PREFS_CONNECTIONS).is_none());
    assert!(r.tag(EC_TAG_PREFS_GENERAL).is_some());
}

#[test]
fn the_remote_directories_and_geoip_pages() {
    let mut p = prefs();
    p.dirs = DirPrefs {
        incoming: "/in".into(),
        temp: "/tmp/t".into(),
        shared: vec!["/a".into(), "/b".into()],
        allowed_roots: vec!["/srv".into()],
    };
    p.remote = RemotePrefs {
        web_port: 4711,
        api_enabled: true,
        api_port: 4713,
        api_bind: "127.0.0.1".into(),
        ec_address: "127.0.0.1".into(),
        ec_port: 4712,
        ..Default::default()
    };
    p.geoip = GeoipPrefs {
        enabled: true,
        source: GeoipPrefs::source_of("maxmind"),
        ..Default::default()
    };
    let r = prefs_reply(
        &Packet::new(EC_OP_GET_PREFERENCES).with(Tag::int(
            EC_TAG_SELECT_PREFS,
            (EC_PREFS_REMOTECONTROLS | EC_PREFS_DIRECTORIES | EC_PREFS_IP2COUNTRY).into(),
        )),
        &p,
    );
    let rc = r.tag(EC_TAG_PREFS_REMOTECTRL).unwrap();
    assert_eq!(rc.child_int(EC_TAG_WEBSERVER_PORT), 4711);
    assert!(!rc.has(EC_TAG_WEBSERVER_AUTORUN) && rc.has(EC_TAG_AMULEAPI_AUTORUN));
    assert_eq!(rc.child_int(EC_TAG_AMULEAPI_PORT), 4713);
    assert_eq!(rc.child_int(EC_TAG_EXTERNALCONN_ENABLED), 1);
    assert_eq!(rc.child_int(EC_TAG_EXTERNALCONN_PORT), 4712);
    assert_eq!(rc.child_str(EC_TAG_EXTERNALCONN_ADDRESS), "127.0.0.1");
    assert_eq!(rc.child_int(EC_TAG_EXTERNALCONN_PASSWD_SET), 1);
    assert_eq!(rc.child_int(EC_TAG_EXTERNALCONN_REQUIRE_ENCRYPTION), 1);

    let d = r.tag(EC_TAG_PREFS_DIRECTORIES).unwrap();
    assert_eq!(d.child_str(EC_TAG_DIRECTORIES_INCOMING), "/in");
    assert_eq!(d.child_str(EC_TAG_DIRECTORIES_TEMP), "/tmp/t");
    // A count, with the folders as its children.
    let shared = d.child(EC_TAG_DIRECTORIES_SHARED).unwrap();
    assert_eq!(shared.as_int(), 2);
    let names: Vec<String> = shared.children.iter().map(Tag::as_str).collect();
    assert_eq!(names, ["/a", "/b"]);
    let roots = d.child(EC_TAG_DIRECTORIES_ALLOWED_ROOTS).unwrap();
    assert_eq!(
        (roots.as_int(), roots.children[0].as_str()),
        (1, "/srv".into())
    );
    assert!(!d.has(EC_TAG_DIRECTORIES_SHARE_HIDDEN));

    let g = r.tag(EC_TAG_PREFS_IP2COUNTRY).unwrap();
    assert_eq!(g.child_int(EC_TAG_IP2COUNTRY_SUPPORTED), 0);
    assert_eq!(g.child_int(EC_TAG_IP2COUNTRY_ENABLED), 1);
    assert_eq!(g.child_int(EC_TAG_IP2COUNTRY_SOURCE), 1);
    assert_eq!(GeoipPrefs::source_of("custom"), 2);
    assert_eq!(GeoipPrefs::source_of("anything"), 0);
    // Pages not asked for are left out.
    assert!(r.tag(EC_TAG_PREFS_GENERAL).is_none());
}

#[test]
fn the_kad_buddy_counters_are_sent_when_asked_for() {
    let t = crate::ec::kad_buddy_tag();
    assert_eq!(t.name, EC_TAG_KAD_BUDDY);
    assert_eq!(t.children.len(), 41);
    assert!(t.children.iter().all(|c| c.is_int() && c.as_int() == 0));
    assert!(t.has(EC_TAG_KAD_BUDDY_PENDING) && t.has(EC_TAG_KAD_BUDDY_OWN_MISSING_SECONDS));
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// What amulegui does once logged in: the preferences, then incremental
/// updates, against a running daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn amulegui_s_first_requests_are_answered() {
    let d = TempDir(std::env::temp_dir().join(format!("remuled-ec-upd-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&d.0);
    std::fs::create_dir_all(&d.0).unwrap();
    let (port, ec_port) = (free_port(), free_port());
    let digest = password_digest("gui");
    std::fs::write(
        d.0.join("amule.conf"),
        format!(
            "[eMule]\nNick=gui test\nPort={port}\nConnectToKad=0\nConnectToED2K=0\nMaxUpload=40\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\nECPassword={digest}\n"
        ),
    )
    .unwrap();
    let loaded = crate::config::load(&d.0).unwrap();
    let user_hash = loaded.client.user_hash;
    let daemon = tokio::spawn(crate::client::run(
        loaded.client,
        Vec::new(),
        Vec::new(),
        std::future::pending(),
    ));
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", ec_port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(&ConnectOptions::new("127.0.0.1", ec_port, digest)).unwrap();
        let prefs = c
            .request(
                &Packet::new(EC_OP_GET_PREFERENCES)
                    .with_detail(EC_DETAIL_UPDATE)
                    .with(Tag::int(
                        EC_TAG_SELECT_PREFS,
                        (EC_PREFS_GENERAL | EC_PREFS_CONNECTIONS).into(),
                    )),
            )
            .unwrap();
        let g = prefs.tag(EC_TAG_PREFS_GENERAL).unwrap();
        assert_eq!(g.child_str(EC_TAG_USER_NICK), "gui test");
        assert_eq!(
            g.child(EC_TAG_USER_HASH).unwrap().as_hash(),
            Some(user_hash.0)
        );
        assert_eq!(
            prefs
                .tag(EC_TAG_PREFS_CONNECTIONS)
                .unwrap()
                .child_int(EC_TAG_CONN_MAX_UL),
            40
        );
        // A download to see.
        let link = format!("ed2k://|file|gui.iso|5000000|{}|/", "AB".repeat(16));
        c.request(&Packet::new(EC_OP_ADD_LINK).with(Tag::string(EC_TAG_STRING, &link)))
            .unwrap();
        let update = Packet::new(EC_OP_GET_UPDATE).with_detail(EC_DETAIL_INC_UPDATE);
        let mut first = None;
        for _ in 0..50 {
            let u = c.request(&update).unwrap();
            if u.tags.iter().any(|t| t.name == EC_TAG_PARTFILE) {
                first = Some(u);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let first = first.expect("the download never showed up");
        let f = first.tag(EC_TAG_PARTFILE).unwrap();
        assert_eq!(f.child_str(EC_TAG_PARTFILE_NAME), "gui.iso");
        let mut gaps = RleData::new(true);
        assert_eq!(
            gaps.decode_u64(&f.child(EC_TAG_PARTFILE_GAP_STATUS).unwrap().data),
            [0, 4_999_999]
        );
        // The next one: the same file, nothing new about it.
        let next = c.request(&update).unwrap();
        let f = next.tag(EC_TAG_PARTFILE).unwrap();
        assert!(!f.has(EC_TAG_PARTFILE_NAME), "{f:?}");
        assert!(!f.has(EC_TAG_PARTFILE_GAP_STATUS));
        // Any other detail level: not answered, as aMule.
        let r = c.request(&Packet::new(EC_OP_GET_UPDATE)).unwrap();
        assert_eq!(r.opcode, EC_OP_FAILED);
        // A new connection starts from nothing.
        drop(c);
        let mut c2 = Client::connect(&ConnectOptions::new(
            "127.0.0.1",
            ec_port,
            password_digest("gui"),
        ))
        .unwrap();
        let again = c2.request(&update).unwrap();
        assert!(again
            .tag(EC_TAG_PARTFILE)
            .unwrap()
            .has(EC_TAG_PARTFILE_NAME));
        c2.request(&Packet::new(EC_OP_SHUTDOWN)).unwrap();
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
}

#[test]
fn the_partial_update_protocol_leaves_out_what_is_unchanged_and_names_what_is_gone() {
    let mut st = UpdateState::default();
    let data = UpdateData {
        shared: vec![shared(3)],
        servers: Vec::new(),
    };
    let mut dl = vec![download(5, vec![(0, 9)]), download(2, vec![(0, 9)])];
    let files = |p: &Packet| {
        p.tags
            .iter()
            .filter(|t| t.name == EC_TAG_PARTFILE || t.name == EC_TAG_KNOWNFILE)
            .map(|t| t.as_int())
            .collect::<Vec<_>>()
    };
    let removed = |p: &Packet| {
        p.tags
            .iter()
            .filter(|t| t.name == EC_TAG_FILE_REMOVED)
            .map(|t| t.as_int())
            .collect::<Vec<_>>()
    };
    let p = st.reply(&dl, &data, true);
    assert_eq!(files(&p), [2, 3, 5]);
    // Nothing new: nothing at all, not even bare ECIDs.
    let p = st.reply(&dl, &data, true);
    assert!(files(&p).is_empty() && removed(&p).is_empty(), "{p:?}");
    // A download cancelled and the shared file deleted: named, once.
    dl.retain(|d| d.ecid != 2);
    let gone = UpdateData::default();
    let p = st.reply(&dl, &gone, true);
    assert_eq!(removed(&p), [2, 3]);
    assert!(files(&p).is_empty());
    let p = st.reply(&dl, &gone, true);
    assert!(removed(&p).is_empty());
    // Without it, as before: bare ECIDs, and no removals.
    let mut legacy = UpdateState::default();
    legacy.reply(&dl, &data, false);
    let p = legacy.reply(&dl, &data, false);
    assert_eq!(files(&p), [3, 5]);
    let p = legacy.reply(&[], &UpdateData::default(), false);
    assert!(removed(&p).is_empty());
}

#[test]
fn allowed_remote_dirs_are_one_a_line() {
    let d = TempDir(std::env::temp_dir().join(format!("remuled-allowed-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&d.0);
    std::fs::create_dir_all(&d.0).unwrap();
    assert!(crate::config::allowed_remote_dirs(&d.0).is_empty());
    std::fs::write(
        d.0.join("allowed-remote-dirs.dat"),
        "# roots\n/srv/media\n\n  /tmp  \r\n",
    )
    .unwrap();
    assert_eq!(
        crate::config::allowed_remote_dirs(&d.0),
        ["/srv/media", "/tmp"]
    );
}
