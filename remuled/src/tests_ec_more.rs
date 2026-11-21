// SPDX-License-Identifier: GPL-2.0-or-later
//! Friends, categories, the shared folders' configuration and the client
//! history over external connections.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use ed2k_formats::clients_met::{ClientMeta, CreditRecord};
use ed2k_formats::emfriends_met::EmfriendsMet;
use ed2k_types::Md4Hash;
use remule_ec::codes::*;
use remule_ec::{Packet, Tag};

use crate::ec::{client_history_reply, format_client_version};
use crate::ec_shared::{set_shared_dirs, shareddir_err};
use crate::friends::FriendList;
use crate::prefs::{CategoryResult, PrefStore, Runtime};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-more-{name}-{}", std::process::id()));
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

fn add_friend(ip: [u8; 4], port: u16, name: &str) -> Packet {
    Packet::new(EC_OP_FRIEND).with(
        Tag::empty(EC_TAG_FRIEND_ADD)
            .with(Tag::hash(EC_TAG_FRIEND_HASH, [0; 16]))
            .with(Tag::int(EC_TAG_FRIEND_IP, u32::from_le_bytes(ip).into()))
            .with(Tag::int(EC_TAG_FRIEND_PORT, port.into()))
            .with(Tag::string(EC_TAG_FRIEND_NAME, name)),
    )
}

#[test]
fn friends_are_added_given_the_slot_removed_and_saved() {
    let d = TempDir::new("friends");
    let mut l = FriendList::load(&d.0);
    assert!(l.view().is_empty());
    assert_eq!(
        l.answer(&add_friend([203, 0, 113, 42], 4662, "one")).opcode,
        EC_OP_NOOP
    );
    assert_eq!(
        l.answer(&add_friend([10, 0, 0, 1], 4672, "two")).opcode,
        EC_OP_NOOP
    );
    let v = l.view();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].ip, u32::from_le_bytes([203, 0, 113, 42]));
    assert_eq!((v[0].port, v[0].name.as_str()), (4662, "one"));
    assert_ne!(v[0].ecid, v[1].ecid);
    // The tag: client 0, not connected, the slot.
    let t = crate::friends::friend_tag(&v[0]);
    assert_eq!((t.name, t.as_int()), (EC_TAG_FRIEND, u64::from(v[0].ecid)));
    assert_eq!(t.child_int(EC_TAG_FRIEND_CLIENT), 0);
    assert_eq!(t.child_int(EC_TAG_CLIENT_CONNECTED), 0);

    // One friend holds the slot at most.
    let slot = |ecid: u32, on: u64| {
        Packet::new(EC_OP_FRIEND)
            .with(Tag::int(EC_TAG_FRIEND_FRIENDSLOT, on).with(Tag::int(EC_TAG_FRIEND, ecid.into())))
    };
    assert_eq!(l.answer(&slot(v[0].ecid, 1)).opcode, EC_OP_NOOP);
    assert_eq!(l.answer(&slot(v[1].ecid, 1)).opcode, EC_OP_NOOP);
    let now = l.view();
    assert!(!now[0].friend_slot && now[1].friend_slot);
    assert_eq!(l.answer(&slot(999_999, 1)).opcode, EC_OP_FAILED);

    // Saved in emfriends.met, as aMule reads it.
    let met = EmfriendsMet::read(&std::fs::read(d.0.join("emfriends.met")).unwrap()).unwrap();
    assert_eq!(met.friends.len(), 2);
    assert_eq!(met.friends[0].ip, Ipv4Addr::new(203, 0, 113, 42));
    let again = FriendList::load(&d.0).view();
    assert_eq!(again[1].name, "two");
    assert!(again[1].friend_slot);

    // Removed; again, still fine.
    let remove = |ecid: u32| {
        Packet::new(EC_OP_FRIEND)
            .with(Tag::empty(EC_TAG_FRIEND_REMOVE).with(Tag::int(EC_TAG_FRIEND, ecid.into())))
    };
    assert_eq!(l.answer(&remove(v[0].ecid)).opcode, EC_OP_NOOP);
    assert_eq!(l.answer(&remove(v[0].ecid)).opcode, EC_OP_NOOP);
    assert_eq!(l.view().len(), 1);
    // A connected client, or browsing: no clients are kept yet.
    let r = l.answer(
        &Packet::new(EC_OP_FRIEND)
            .with(Tag::empty(EC_TAG_FRIEND_ADD).with(Tag::int(EC_TAG_CLIENT, 5))),
    );
    assert_eq!(r.opcode, EC_OP_FAILED);
    let r = l.answer(
        &Packet::new(EC_OP_FRIEND).with(
            Tag::empty(EC_TAG_FRIEND_SHARED)
                .with(Tag::int(EC_TAG_FRIEND, v[1].ecid.into()))
                .with(Tag::int(EC_TAG_SEARCH_REF, 77)),
        ),
    );
    assert_eq!(r.message().unwrap(), "Client not found.");
    assert_eq!(r.tag(EC_TAG_SEARCH_REF).unwrap().as_int(), 77);
}

fn store(dir: &Path) -> PrefStore {
    let incoming = dir.join("in");
    std::fs::create_dir_all(&incoming).unwrap();
    std::fs::write(
        dir.join("allowed-remote-dirs.dat"),
        format!("{}\n", dir.join("root").display()),
    )
    .unwrap();
    let conf = ed2k_formats::amule_conf::ConfFile::from_bytes(
        &std::fs::read(dir.join("amule.conf")).unwrap_or_default(),
    );
    PrefStore::load(
        dir,
        &conf,
        &Runtime {
            incoming: incoming.display().to_string(),
            ..Default::default()
        },
    )
}

fn category(index: u64, title: &str, path: &str) -> Tag {
    Tag::int(EC_TAG_CATEGORY, index)
        .with(Tag::string(EC_TAG_CATEGORY_PATH, path))
        .with(Tag::string(EC_TAG_CATEGORY_COMMENT, "note"))
        .with(Tag::int(EC_TAG_CATEGORY_COLOR, 0xff00))
        .with(Tag::int(EC_TAG_CATEGORY_PRIO, 2))
        .with(Tag::string(EC_TAG_CATEGORY_TITLE, title))
}

#[test]
fn categories_are_created_updated_deleted_and_saved() {
    let d = TempDir::new("cats");
    let mut s = store(&d.0);
    let page = |s: &PrefStore| {
        s.reply(
            &Packet::new(EC_OP_GET_PREFERENCES)
                .with(Tag::int(EC_TAG_SELECT_PREFS, EC_PREFS_CATEGORIES.into())),
        )
    };
    // Only the default one: nothing told.
    assert!(page(&s).tag(EC_TAG_PREFS_CATEGORIES).is_none());
    assert_eq!(s.category_count(), 1);

    // Inside the roots, made if missing, stored canonical.
    let music = d.0.join("root").join("music");
    assert_eq!(
        s.create_category(&category(0, "Music", &music.display().to_string())),
        CategoryResult::Done
    );
    assert!(music.is_dir());
    // No folder: the incoming one is kept, which a client reads as applied.
    match s.create_category(&category(0, "Other", "")) {
        CategoryResult::PathKept { index, path } => {
            assert_eq!((index, path), (2, d.0.join("in").display().to_string()))
        }
        r => panic!("{r:?}"),
    }
    // Outside the roots: refused, nothing created.
    assert!(matches!(
        s.create_category(&category(0, "Bad", "/elsewhere")),
        CategoryResult::Refused {
            folder: Some(_),
            ..
        }
    ));
    assert_eq!(s.category_count(), 3);
    let p = page(&s);
    let cats = p.tag(EC_TAG_PREFS_CATEGORIES).unwrap();
    assert_eq!(cats.children.len(), 3);
    let c1 = &cats.children[1];
    assert_eq!(
        (c1.as_int(), c1.child_str(EC_TAG_CATEGORY_TITLE)),
        (1, "Music".into())
    );
    assert_eq!(c1.child_int(EC_TAG_CATEGORY_COLOR), 0xff00);
    assert_eq!(
        c1.child_str(EC_TAG_CATEGORY_PATH),
        music.canonicalize().unwrap().display().to_string()
    );

    // Updated; an unknown one refused.
    let mut t = category(
        1,
        "Tunes",
        &music.canonicalize().unwrap().display().to_string(),
    );
    t.children[1] = Tag::string(EC_TAG_CATEGORY_COMMENT, "changed");
    assert_eq!(s.update_category_from(&t), CategoryResult::Done);
    assert!(matches!(
        s.update_category_from(&category(9, "x", "")),
        CategoryResult::Refused { index: Some(9), .. }
    ));

    // In amule.conf as aMule keeps them, and read back.
    let conf = ed2k_formats::amule_conf::ConfFile::from_bytes(
        &std::fs::read(d.0.join("amule.conf")).unwrap(),
    );
    assert_eq!(conf.get("/General/Count"), Some("2"));
    assert_eq!(conf.get("/Cat#1/Title"), Some("Tunes"));
    assert_eq!(conf.get("/Cat#1/Comment"), Some("changed"));
    assert_eq!(conf.get("/Cat#1/Color"), Some("65280"));
    assert_eq!(store(&d.0).category_count(), 3);

    // Deleted: never the default one; the groups after it gone.
    assert!(matches!(
        s.delete_category(0),
        CategoryResult::Refused { index: Some(0), .. }
    ));
    assert_eq!(s.delete_category(1), CategoryResult::Done);
    assert!(matches!(
        s.delete_category(5),
        CategoryResult::Refused { .. }
    ));
    let conf = ed2k_formats::amule_conf::ConfFile::from_bytes(
        &std::fs::read(d.0.join("amule.conf")).unwrap(),
    );
    assert_eq!(conf.get("/General/Count"), Some("1"));
    assert_eq!(conf.get("/Cat#1/Title"), Some("Other"));
    assert_eq!(conf.get("/Cat#2/Title"), None);
}

#[test]
fn shared_folders_are_set_as_amule_sets_them() {
    let d = TempDir::new("dirs");
    let root = d.0.join("root");
    let (a, b) = (root.join("a"), root.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let outside = d.0.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(
        d.0.join("allowed-remote-dirs.dat"),
        format!("{}\n", root.display()),
    )
    .unwrap();
    // Shared before the roots were set: kept as it is when sent again.
    std::fs::write(
        d.0.join("shareddir-explicit.dat"),
        format!("{}\n", outside.display()),
    )
    .unwrap();
    let s = |p: &Path| p.display().to_string();
    let refused = set_shared_dirs(
        &d.0,
        &[
            (s(&outside), false),
            (s(&a), false),
            (s(&b), true),
            (s(&root.join("missing")), false),
            ("/".into(), false),
        ],
    );
    assert_eq!(
        refused,
        [
            (s(&root.join("missing")), shareddir_err::MISSING),
            ("/".into(), shareddir_err::OUTSIDE_ROOTS),
        ]
    );
    let read = |name: &str| std::fs::read_to_string(d.0.join(name)).unwrap();
    let canon = |p: &Path| s(&p.canonicalize().unwrap());
    assert_eq!(
        read("shareddir-explicit.dat"),
        format!("{}\n{}\n", s(&outside), canon(&a))
    );
    assert_eq!(read("shareddir-recursive.dat"), format!("{}\n", canon(&b)));
    // Made recursive outside the roots: refused, kept as it was.
    let refused = set_shared_dirs(&d.0, &[(s(&outside), true)]);
    assert_eq!(refused, [(s(&outside), shareddir_err::OUTSIDE_ROOTS)]);
    assert_eq!(read("shareddir-explicit.dat"), format!("{}\n", s(&outside)));
    // Left out: no longer shared.
    assert!(set_shared_dirs(&d.0, &[]).is_empty());
    assert_eq!(read("shareddir-explicit.dat"), "");
}

#[test]
fn the_client_history_is_the_credits_with_their_metadata() {
    let mut known = CreditRecord::new(Md4Hash([1; 16]));
    known.uploaded = 5_000_000;
    known.downloaded = 2_000_000;
    known.last_seen = 1_700_000_000;
    let bare = CreditRecord::new(Md4Hash([2; 16]));
    let meta = ClientMeta {
        name: "peer".into(),
        first_seen: 1_600_000_000,
        sessions: 4,
        last_ip: u32::from_le_bytes([1, 2, 3, 4]),
        last_port: 4662,
        version: 2 * 100_000 + 3 * 1000 + 300,
        client_soft: 3,
        ..Default::default()
    };
    let p = client_history_reply(&[(known.clone(), Some(meta)), (bare, None)]);
    assert_eq!(p.opcode, EC_OP_CLIENT_HISTORY);
    assert_eq!(p.tags.len(), 2);
    let t = &p.tags[0];
    assert_eq!(t.as_hash(), Some([1; 16]));
    assert_eq!(t.child_int(EC_TAG_CLIENT_UPLOAD_TOTAL), 5_000_000);
    assert_eq!(t.child_int(EC_TAG_CLIENT_DOWNLOAD_TOTAL), 2_000_000);
    assert!(
        (t.child_double(EC_TAG_CLIENT_SCORE_RATIO) - f64::from(known.credit_ratio())).abs() < 1e-6
    );
    assert_eq!(t.child_int(EC_TAG_CLIENT_SESSIONS), 4);
    assert_eq!(t.child_str(EC_TAG_CLIENT_NAME), "peer");
    assert_eq!(t.child_str(EC_TAG_CLIENT_SOFT_VER_STR), "v2.3.3");
    // A record without metadata: the credits only.
    let b = &p.tags[1];
    assert!(b.child(EC_TAG_CLIENT_FIRST_SEEN).is_none() && b.child(EC_TAG_CLIENT_NAME).is_none());

    let v = |maj: u32, min: u32, upd: u32| maj * 100_000 + min * 1000 + upd * 100;
    assert_eq!(format_client_version(0, v(0, 70, 1)), "v0.70b");
    assert_eq!(format_client_version(0x32, v(1, 2, 0)), "v1.2");
    assert_eq!(format_client_version(0x32, v(1, 2, 1)), "v1.2.1");
    assert_eq!(format_client_version(0x14, v(4, 1, 2)), " v3.01c");
    assert_eq!(format_client_version(5, v(1, 0, 0)), "v1");
    assert_eq!(format_client_version(5, v(1, 2, 1)), "v1.2a");
}
