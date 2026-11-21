// SPDX-License-Identifier: GPL-2.0-or-later
//! The preferences over external connections ([`crate::prefs`]): the pages
//! as aMule builds them, and changes applied, refused and saved.

use std::path::{Path, PathBuf};

use ed2k_formats::amule_conf::ConfFile;
use remule_ec::codes::*;
use remule_ec::{Packet, Tag};

use crate::prefs::{ul_dl_ratio, PrefStore, Runtime, DEFAULT_TCP_PORT};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-prefs-{name}-{}", std::process::id()));
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

fn conf(dir: &Path) -> ConfFile {
    ConfFile::from_bytes(&std::fs::read(dir.join("amule.conf")).unwrap_or_default())
}

fn store(dir: &Path, amule_conf: &str) -> PrefStore {
    std::fs::write(dir.join("amule.conf"), amule_conf).unwrap();
    PrefStore::load(
        dir,
        &conf(dir),
        &Runtime {
            user_hash: [7; 16],
            incoming: dir.join("in").display().to_string(),
            temp: dir.join("tmp").display().to_string(),
            shared: vec!["/a".into(), "/b".into()],
            max_connections: 500,
            listening: (0, 0),
        },
    )
}

fn get(s: &PrefStore, selection: u32) -> Packet {
    s.reply(
        &Packet::new(EC_OP_GET_PREFERENCES)
            .with_detail(EC_DETAIL_UPDATE)
            .with(Tag::int(EC_TAG_SELECT_PREFS, selection.into())),
    )
}

fn set(s: &mut PrefStore, page: Tag) -> Packet {
    s.apply(
        &Packet::new(EC_OP_SET_PREFERENCES)
            .with_detail(EC_DETAIL_FULL)
            .with(page),
    )
}

#[test]
fn the_pages_are_the_ones_asked_for_with_amule_conf_s_values() {
    let d = TempDir::new("pages");
    std::fs::write(d.0.join("allowed-remote-dirs.dat"), "# roots\n/srv\n").unwrap();
    std::fs::write(
        d.0.join("addresses.dat"),
        "http://one/server.met\nhttp://two/\n",
    )
    .unwrap();
    // The shared folders as their lists say now.
    std::fs::write(d.0.join("shareddir-explicit.dat"), "/a\n").unwrap();
    std::fs::write(d.0.join("shareddir-recursive.dat"), "/b\n").unwrap();
    let s = store(
        &d.0,
        "[eMule]\nNick=me\nMaxUpload=50\nUDPEnable=0\nReconnect=0\nFileBufferSizePref=2\n\
         GeoIPSource=maxmind\nSeeShare=0\n",
    );
    let r = get(&s, EC_PREFS_GENERAL | EC_PREFS_CONNECTIONS);
    assert_eq!(r.opcode, EC_OP_SET_PREFERENCES);
    let g = r.tag(EC_TAG_PREFS_GENERAL).unwrap();
    assert_eq!(g.child_str(EC_TAG_USER_NICK), "me");
    assert_eq!(g.child(EC_TAG_USER_HASH).unwrap().as_hash(), Some([7; 16]));
    assert_eq!(g.child_int(EC_TAG_GENERAL_VERSION_CHECK_AVAILABLE), 1);
    let c = r.tag(EC_TAG_PREFS_CONNECTIONS).unwrap();
    assert_eq!(c.child_int(EC_TAG_CONN_MAX_UL), 50);
    assert_eq!(c.child_int(EC_TAG_CONN_MAX_CONN), 500);
    // Flags present when on: UDP off is UDP_DISABLE on.
    assert!(c.has(EC_TAG_CONN_UDP_DISABLE));
    assert!(!c.has(EC_TAG_CONN_RECONNECT) && c.has(EC_TAG_CONN_AUTOCONNECT));
    // A password is never told.
    assert!(!c.has(EC_TAG_PROXY_PASSWORD));
    assert!(r.tag(EC_TAG_PREFS_FILES).is_none(), "only what was asked");

    let r = get(
        &s,
        EC_PREFS_DIRECTORIES
            | EC_PREFS_SERVERS
            | EC_PREFS_CORETWEAKS
            | EC_PREFS_IP2COUNTRY
            | EC_PREFS_SECURITY
            | EC_PREFS_REMOTECONTROLS
            | EC_PREFS_KADEMLIA,
    );
    let dirs = r.tag(EC_TAG_PREFS_DIRECTORIES).unwrap();
    assert_eq!(
        dirs.child_str(EC_TAG_DIRECTORIES_INCOMING),
        d.0.join("in").display().to_string()
    );
    let shared = dirs.child(EC_TAG_DIRECTORIES_SHARED).unwrap();
    assert_eq!(shared.as_int(), 2);
    assert_eq!(shared.children[1].as_str(), "/b");
    let roots = dirs.child(EC_TAG_DIRECTORIES_ALLOWED_ROOTS).unwrap();
    assert_eq!(
        (roots.as_int(), roots.children[0].as_str()),
        (1, "/srv".to_string())
    );
    let srv = r.tag(EC_TAG_PREFS_SERVERS).unwrap();
    assert_eq!(
        srv.child(EC_TAG_SERVERS_URL_LIST).unwrap().children.len(),
        2
    );
    assert_eq!(
        srv.child_str(EC_TAG_SERVERS_UPDATE_URL),
        "http://one/server.met"
    );
    // Stored in 15000-byte steps.
    let tw = r.tag(EC_TAG_PREFS_CORETWEAKS).unwrap();
    assert_eq!(tw.child_int(EC_TAG_CORETW_FILEBUFFER), 30000);
    assert_eq!(tw.child_int(EC_TAG_CORETW_SOURCE_REASK_MS), 15 * 60000);
    assert!(tw.has(EC_TAG_CORETW_WRITE_BUFFER_LIMIT_MIB));
    assert!(
        !tw.has(EC_TAG_CORETW_DEBUG_CATEGORIES),
        "no debug categories"
    );
    assert_eq!(
        r.tag(EC_TAG_PREFS_IP2COUNTRY)
            .unwrap()
            .child_int(EC_TAG_IP2COUNTRY_SOURCE),
        1
    );
    assert_eq!(
        r.tag(EC_TAG_PREFS_SECURITY)
            .unwrap()
            .child_int(EC_TAG_SECURITY_CAN_SEE_SHARES),
        0
    );
    let rc = r.tag(EC_TAG_PREFS_REMOTECTRL).unwrap();
    assert_eq!(rc.child_int(EC_TAG_EXTERNALCONN_PASSWD_SET), 1);
    assert_eq!(rc.child_int(EC_TAG_EXTERNALCONN_PORT), 4712);
    assert_eq!(
        r.tag(EC_TAG_PREFS_KADEMLIA)
            .unwrap()
            .child_int(EC_TAG_KADEMLIA_PROTOCOL10),
        1
    );
}

#[test]
fn a_change_is_applied_saved_and_read_back() {
    let d = TempDir::new("apply");
    let mut s = store(&d.0, "[eMule]\nNick=me\n");
    let r = set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_CONNECTIONS)
            .with(Tag::int(EC_TAG_CONN_MAX_UL, 42))
            // Flags by value at FULL.
            .with(Tag::int(EC_TAG_CONN_AUTOCONNECT, 0))
            .with(Tag::int(EC_TAG_CONN_UDP_DISABLE, 1))
            .with(Tag::string(EC_TAG_PROXY_PASSWORD, "s3cret")),
    );
    assert_eq!(r.opcode, EC_OP_NOOP);
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_CORETWEAKS)
            .with(Tag::int(EC_TAG_CORETW_FILEBUFFER, 45000))
            .with(Tag::int(EC_TAG_CORETW_KAD_REASK_MS, 31 * 60000)),
    );
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_IP2COUNTRY).with(Tag::int(EC_TAG_IP2COUNTRY_SOURCE, 2)),
    );
    let c = get(&s, EC_PREFS_CONNECTIONS);
    let c = c.tag(EC_TAG_PREFS_CONNECTIONS).unwrap();
    assert_eq!(c.child_int(EC_TAG_CONN_MAX_UL), 42);
    assert!(!c.has(EC_TAG_CONN_AUTOCONNECT) && c.has(EC_TAG_CONN_UDP_DISABLE));
    assert!(!c.has(EC_TAG_PROXY_PASSWORD));

    // In amule.conf as aMule keeps them.
    let f = conf(&d.0);
    assert_eq!(f.get("/eMule/MaxUpload"), Some("42"));
    assert_eq!(f.get("/eMule/Autoconnect"), Some("0"));
    assert_eq!(f.get("/eMule/UDPEnable"), Some("0"));
    assert_eq!(f.get("/eMule/FileBufferSizePref"), Some("3"));
    assert_eq!(f.get("/eMule/KadSourceReaskMinutes"), Some("31"));
    assert_eq!(f.get("/eMule/GeoIPSource"), Some("custom"));
    assert_eq!(f.get("/Proxy/ProxyPassword"), Some("s3cret"));
    assert_eq!(f.get("/eMule/Nick"), Some("me"), "the rest kept");

    // And read back so after a restart.
    let again = PrefStore::load(&d.0, &f, &Runtime::default());
    let t = get(&again, EC_PREFS_CORETWEAKS);
    let t = t.tag(EC_TAG_PREFS_CORETWEAKS).unwrap();
    assert_eq!(t.child_int(EC_TAG_CORETW_FILEBUFFER), 45000);
    assert_eq!(t.child_int(EC_TAG_CORETW_KAD_REASK_MS), 31 * 60000);
}

#[test]
fn read_only_and_daemon_local_settings_are_not_changed() {
    let d = TempDir::new("readonly");
    let mut s = store(&d.0, "");
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_REMOTECTRL)
            .with(Tag::int(EC_TAG_EXTERNALCONN_PORT, 1))
            .with(Tag::int(EC_TAG_WEBSERVER_REFRESH, 99)),
    );
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_ONLINESIG)
            .with(Tag::string(EC_TAG_ONLINESIG_DIRECTORY, "/elsewhere")),
    );
    let r = get(&s, EC_PREFS_REMOTECONTROLS | EC_PREFS_ONLINESIG);
    let rc = r.tag(EC_TAG_PREFS_REMOTECTRL).unwrap();
    assert_eq!(rc.child_int(EC_TAG_EXTERNALCONN_PORT), 4712);
    assert_eq!(rc.child_int(EC_TAG_WEBSERVER_REFRESH), 99);
    assert_eq!(
        r.tag(EC_TAG_PREFS_ONLINESIG)
            .unwrap()
            .child_str(EC_TAG_ONLINESIG_DIRECTORY),
        d.0.display().to_string()
    );
}

#[test]
fn a_flag_left_out_is_off_below_full_detail() {
    let d = TempDir::new("detail");
    let mut s = store(&d.0, "");
    s.apply(
        &Packet::new(EC_OP_SET_PREFERENCES)
            .with_detail(EC_DETAIL_WEB)
            .with(Tag::empty(EC_TAG_PREFS_FILES).with(Tag::empty(EC_TAG_FILES_NEW_PAUSED))),
    );
    let f = get(&s, EC_PREFS_FILES);
    let f = f.tag(EC_TAG_PREFS_FILES).unwrap();
    assert!(f.has(EC_TAG_FILES_NEW_PAUSED));
    // ICH is on by default, and was not in the request.
    assert!(!f.has(EC_TAG_FILES_ICH_ENABLED));
}

#[test]
fn amule_s_rules_for_ports_and_limits() {
    let d = TempDir::new("rules");
    let mut s = store(&d.0, "");
    let conn = |s: &PrefStore, tag: u16| {
        get(s, EC_PREFS_CONNECTIONS)
            .tag(EC_TAG_PREFS_CONNECTIONS)
            .unwrap()
            .child_int(tag)
    };
    // TCP+3 past 65535: the default port (here the one already set).
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_CONNECTIONS).with(Tag::int(EC_TAG_CONN_TCP_PORT, 65534)),
    );
    assert_eq!(conn(&s, EC_TAG_CONN_TCP_PORT), u64::from(DEFAULT_TCP_PORT));
    // A low upload limit caps the download limit.
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_CONNECTIONS)
            .with(Tag::int(EC_TAG_CONN_MAX_UL, 3))
            .with(Tag::int(EC_TAG_CONN_MAX_DL, 100)),
    );
    assert_eq!(conn(&s, EC_TAG_CONN_MAX_DL), 9);
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_CONNECTIONS).with(Tag::int(EC_TAG_CONN_SLOT_ALLOCATION, 0)),
    );
    assert_eq!(conn(&s, EC_TAG_CONN_SLOT_ALLOCATION), 1);

    assert_eq!(ul_dl_ratio(0, 0), 0);
    assert_eq!(ul_dl_ratio(3, 0), 9);
    assert_eq!(ul_dl_ratio(3, 5), 5);
    assert_eq!(ul_dl_ratio(5, 100), 20);
    assert_eq!(ul_dl_ratio(10, 100), 100);
}

#[test]
fn a_port_in_use_is_refused_and_the_rest_applied() {
    let d = TempDir::new("port");
    let mut s = store(&d.0, "[eMule]\nPort=4662\n");
    let held = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let r = set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_CONNECTIONS)
            .with(Tag::int(EC_TAG_CONN_TCP_PORT, port.into()))
            .with(Tag::int(EC_TAG_CONN_MAX_UL, 77)),
    );
    assert_eq!(r.opcode, EC_OP_FAILED);
    assert!(
        r.message().unwrap().contains(&format!("TCP port {port}")),
        "{r:?}"
    );
    let c = get(&s, EC_PREFS_CONNECTIONS);
    let c = c.tag(EC_TAG_PREFS_CONNECTIONS).unwrap();
    assert_eq!(c.child_int(EC_TAG_CONN_TCP_PORT), 4662);
    assert_eq!(c.child_int(EC_TAG_CONN_MAX_UL), 77);
    assert_eq!(conf(&d.0).get("/eMule/Port"), Some("4662"));

    // The port the daemon itself listens on is its own to go back to.
    let mut s = PrefStore::load(
        &d.0,
        &conf(&d.0),
        &Runtime {
            listening: (port, 0),
            ..Default::default()
        },
    );
    let r = set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_CONNECTIONS).with(Tag::int(EC_TAG_CONN_TCP_PORT, port.into())),
    );
    assert_eq!(r.opcode, EC_OP_NOOP, "{r:?}");
}

#[test]
fn folders_move_only_inside_the_allowed_roots() {
    let d = TempDir::new("dirs");
    let inside = d.0.join("root").join("downloads");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::write(
        d.0.join("allowed-remote-dirs.dat"),
        format!("{}\n", d.0.join("root").display()),
    )
    .unwrap();
    let mut s = store(&d.0, "");
    let current = d.0.join("in").display().to_string();
    let dirs = |s: &PrefStore| {
        get(s, EC_PREFS_DIRECTORIES | EC_PREFS_ONLINESIG)
            .tag(EC_TAG_PREFS_DIRECTORIES)
            .unwrap()
            .child_str(EC_TAG_DIRECTORIES_INCOMING)
    };
    // The current value passes, whatever the roots.
    let r = set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_DIRECTORIES)
            .with(Tag::string(EC_TAG_DIRECTORIES_INCOMING, &current)),
    );
    assert_eq!(r.opcode, EC_OP_NOOP);
    // Outside: refused, named with reason 3; the rest applied.
    let r = s.apply(
        &Packet::new(EC_OP_SET_PREFERENCES)
            .with_detail(EC_DETAIL_FULL)
            .with(
                Tag::empty(EC_TAG_PREFS_DIRECTORIES)
                    .with(Tag::string(EC_TAG_DIRECTORIES_INCOMING, "/outside")),
            )
            .with(Tag::empty(EC_TAG_PREFS_ONLINESIG).with(Tag::int(EC_TAG_ONLINESIG_UPDATE, 321))),
    );
    assert_eq!(r.opcode, EC_OP_FAILED);
    let rejected = r.tag(EC_TAG_SHAREDDIR_REJECTED).unwrap();
    assert_eq!(rejected.as_str(), "/outside");
    assert_eq!(rejected.child_int(EC_TAG_SHAREDDIR_ERROR), 3);
    assert_eq!(dirs(&s), current);
    assert_eq!(
        get(&s, EC_PREFS_ONLINESIG)
            .tag(EC_TAG_PREFS_ONLINESIG)
            .unwrap()
            .child_int(EC_TAG_ONLINESIG_UPDATE),
        321
    );
    // Inside: taken, as its canonical path.
    let r = set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_DIRECTORIES).with(Tag::string(
            EC_TAG_DIRECTORIES_INCOMING,
            &inside.display().to_string(),
        )),
    );
    assert_eq!(r.opcode, EC_OP_NOOP);
    assert_eq!(
        dirs(&s),
        crate::prefs::canonical(&inside).display().to_string()
    );
}

#[test]
fn server_list_urls_and_the_ip_filter_url_are_kept() {
    let d = TempDir::new("urls");
    let mut s = store(&d.0, "");
    set(
        &mut s,
        Tag::empty(EC_TAG_PREFS_SERVERS).with(
            Tag::int(EC_TAG_SERVERS_URL_LIST, 2)
                .with(Tag::string(EC_TAG_STRING, "http://a/"))
                .with(Tag::string(EC_TAG_STRING, "http://b/")),
        ),
    );
    assert_eq!(
        std::fs::read_to_string(d.0.join("addresses.dat")).unwrap(),
        "http://a/\nhttp://b/\n"
    );
    assert_eq!(
        s.ipfilter_url(),
        "https://upd.emule-security.org/ipfilter.zip",
        "aMule's default"
    );
    s.set_ipfilter_url("http://example/ipfilter.dat");
    assert_eq!(
        conf(&d.0).get("/eMule/IPFilterURL"),
        Some("http://example/ipfilter.dat")
    );
}

#[test]
fn containment_is_judged_as_amule_judges_it() {
    use crate::prefs::{canonical_for_containment, within_roots};
    let d = TempDir::new("contain");
    let root = d.0.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let roots = [root.display().to_string()];
    // Not made yet: its existing part resolved, the rest put back.
    let new = canonical_for_containment(&root.join("a").join("b")).unwrap();
    assert!(new.ends_with(Path::new("a").join("b")));
    assert!(within_roots(&new, &roots));
    // A `..` is refused, whatever it would resolve to.
    assert_eq!(
        canonical_for_containment(&root.join("..").join("root")),
        None
    );
    assert_eq!(
        canonical_for_containment(&root.join("x").join("..").join("..")),
        None
    );
    // Beside the root is outside it.
    let beside = canonical_for_containment(&d.0.join("rootless")).unwrap();
    assert!(!within_roots(&beside, &roots));
    // No roots, nothing inside.
    assert!(!within_roots(&new, &[]));
    #[cfg(unix)]
    {
        // A symlink inside a root that leads out of it.
        let out = d.0.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::os::unix::fs::symlink(&out, root.join("link")).unwrap();
        let through = canonical_for_containment(&root.join("link").join("x")).unwrap();
        assert!(!within_roots(&through, &roots));
    }
}
