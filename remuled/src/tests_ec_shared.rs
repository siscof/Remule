// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared files over external connections: the shared-file tag, the
//! replies, the client's side (ECIDs, priorities, a reload), and an EC
//! client listing, prioritising and reloading a running daemon's shares.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed2k_formats::known_met::{priority, KnownFile, KnownMet};
use ed2k_types::Md4Hash;
use remule_core::shared::SharedFiles;
use remule_ec::codes::*;
use remule_ec::{Client, ConnectOptions, Packet, Tag};

use crate::config;
use crate::ec_shared::{
    self, next_ecid, ReloadDirs, SharedBase, SharedDirs, SharedRequest, SharedState,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-ecsh-{name}-{}", std::process::id()));
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

fn base() -> SharedBase {
    SharedBase {
        ecid: 42,
        hash: Md4Hash([0x5A; 16]),
        name: "book.pdf".into(),
        size: 1234,
        file_name: "/srv/share".into(),
        dir: "/srv/share".into(),
        up_priority: 12,
        requests_all: 7,
        accepts_all: 3,
        transferred_all: 99_999,
        aich: "AICHROOT".into(),
        last_upload: 1_700_000_000,
        shared_since: 1_600_000_000,
        verify: None,
        comment: "mine".into(),
        rating: 4,
    }
}

fn names(t: &Tag) -> Vec<u16> {
    t.children.iter().map(|c| c.name).collect()
}

#[test]
fn shared_files_are_told_as_cec_shared_file_tag_tells_them() {
    let b = base();
    let t = ec_shared::shared_tag(EC_TAG_KNOWNFILE, &b, EC_DETAIL_FULL);
    assert_eq!((t.name, t.as_int()), (EC_TAG_KNOWNFILE, 42));
    // aMule's order, the hashing count for a known file only.
    assert_eq!(
        names(&t),
        [
            EC_TAG_KNOWNFILE_REQ_COUNT,
            EC_TAG_KNOWNFILE_REQ_COUNT_ALL,
            EC_TAG_KNOWNFILE_ACCEPT_COUNT,
            EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL,
            EC_TAG_KNOWNFILE_XFERRED,
            EC_TAG_KNOWNFILE_XFERRED_ALL,
            EC_TAG_KNOWNFILE_AICH_MASTERHASH,
            EC_TAG_KNOWNFILE_PRIO,
            EC_TAG_KNOWNFILE_COMPLETE_SOURCES_LOW,
            EC_TAG_KNOWNFILE_COMPLETE_SOURCES_HIGH,
            EC_TAG_KNOWNFILE_COMPLETE_SOURCES,
            EC_TAG_KNOWNFILE_HASHED_PART_COUNT,
            EC_TAG_KNOWNFILE_ON_QUEUE,
            EC_TAG_KNOWNFILE_UPLOAD_SPEED,
            EC_TAG_KNOWNFILE_UPLOADING_COUNT,
            EC_TAG_KNOWNFILE_LAST_UPLOAD,
            EC_TAG_PARTFILE_COMMENTS,
            EC_TAG_PARTFILE_KAD_COMMENT_SEARCHING,
            EC_TAG_PARTFILE_NAME,
            EC_TAG_PARTFILE_HASH,
            EC_TAG_KNOWNFILE_FILENAME,
            EC_TAG_KNOWNFILE_PATH,
            EC_TAG_KNOWNFILE_SHARED_SINCE,
            EC_TAG_PARTFILE_SIZE_FULL,
            EC_TAG_PARTFILE_ED2K_LINK,
            EC_TAG_KNOWNFILE_COMMENT,
            EC_TAG_KNOWNFILE_RATING,
        ]
    );
    // What amulecmd's `show shared` prints: hash, folder and name,
    // priority, requests, accepts, bytes, ratio.
    assert_eq!(t.child_str(EC_TAG_KNOWNFILE_FILENAME), "/srv/share");
    assert_eq!(t.child_str(EC_TAG_PARTFILE_NAME), "book.pdf");
    assert_eq!(t.child_int(EC_TAG_KNOWNFILE_PRIO), 12);
    assert_eq!(t.child_int(EC_TAG_KNOWNFILE_REQ_COUNT_ALL), 7);
    assert_eq!(t.child_int(EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL), 3);
    assert_eq!(t.child_int(EC_TAG_KNOWNFILE_XFERRED_ALL), 99_999);
    assert_eq!(t.child_int(EC_TAG_PARTFILE_SIZE_FULL), 1234);
    assert_eq!(t.child_str(EC_TAG_KNOWNFILE_AICH_MASTERHASH), "AICHROOT");
    assert_eq!(
        t.child_str(EC_TAG_PARTFILE_ED2K_LINK),
        format!("ed2k://|file|book.pdf|1234|{}|/", "5A".repeat(16))
    );
    // UPDATE: no names; a verified file says when and what.
    let upd = ec_shared::shared_tag(EC_TAG_KNOWNFILE, &b, EC_DETAIL_UPDATE);
    assert!(!upd.has(EC_TAG_PARTFILE_NAME) && !upd.has(EC_TAG_PARTFILE_HASH));
    assert!(!upd.has(EC_TAG_KNOWNFILE_VERIFY_DATE));
    let v = SharedBase {
        verify: Some((5, "1,2".into(), String::new())),
        ..b.clone()
    };
    let t = ec_shared::shared_tag(EC_TAG_KNOWNFILE, &v, EC_DETAIL_UPDATE);
    assert_eq!(t.child_int(EC_TAG_KNOWNFILE_VERIFY_DATE), 5);
    assert_eq!(t.child_str(EC_TAG_KNOWNFILE_VERIFY_CORRUPT_MD4), "1,2");
    // A download's base: no hashing count.
    let p = ec_shared::shared_tag(EC_TAG_PARTFILE, &b, EC_DETAIL_FULL);
    assert!(!p.has(EC_TAG_KNOWNFILE_HASHED_PART_COUNT));

    // The reply: all, or those asked for by ECID.
    let files = vec![
        SharedBase { ecid: 1, ..base() },
        SharedBase { ecid: 2, ..base() },
    ];
    let all = ec_shared::shared_files_reply(&Packet::new(EC_OP_GET_SHARED_FILES), &files);
    assert_eq!((all.opcode, all.tags.len()), (EC_OP_SHARED_FILES, 2));
    let one = ec_shared::shared_files_reply(
        &Packet::new(EC_OP_GET_SHARED_FILES).with(Tag::int(EC_TAG_KNOWNFILE, 2)),
        &files,
    );
    assert_eq!(one.tags.len(), 1);
    assert_eq!(one.tags[0].as_int(), 2);

    // The folders: explicit ones plain, recursive roots marked.
    let d = ec_shared::shared_dirs_reply(&SharedDirs {
        explicit: vec!["/a".into()],
        recursive: vec!["/b".into()],
    });
    assert_eq!(d.opcode, EC_OP_GET_SHARED_DIRS);
    assert_eq!(d.tags[0].as_str(), "/a");
    assert!(d.tags[0].children.is_empty());
    assert_eq!(d.tags[1].as_str(), "/b");
    assert_eq!(d.tags[1].child_int(EC_TAG_SHAREDDIR_RECURSIVE), 1);
}

#[test]
fn ecids_are_one_counter_and_last_while_shared() {
    let (a, b) = (next_ecid(), next_ecid());
    assert!(a != 0 && b != 0 && a != b);

    let d = TempDir::new("ids");
    let share = d.0.join("share");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::write(share.join("a.bin"), b"aaaa").unwrap();
    std::fs::write(share.join("b.bin"), b"bbbbbb").unwrap();
    let shares = Mutex::new(SharedFiles::load(&d.0).unwrap());
    let dirs = ReloadDirs {
        dirs: vec![share.clone()],
        reserved: Vec::new(),
    };
    ec_shared::reload_now(&shares, &dirs);
    let mut st = SharedState::default();
    let first = st.list(&shares.lock().unwrap());
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].name, "a.bin");
    assert_eq!(first[0].dir, share.display().to_string());
    assert_eq!(
        first[0].file_name, first[0].dir,
        "a shared file's FILENAME is its folder"
    );
    // New files share at automatic priority.
    assert_eq!(first[0].up_priority, 11);
    let again = st.list(&shares.lock().unwrap());
    assert_eq!(
        first.iter().map(|f| f.ecid).collect::<Vec<_>>(),
        again.iter().map(|f| f.ecid).collect::<Vec<_>>()
    );
    // Gone and back: a new ID; the other keeps its own.
    std::fs::remove_file(share.join("a.bin")).unwrap();
    ec_shared::reload_now(&shares, &dirs);
    assert_eq!(st.list(&shares.lock().unwrap()).len(), 1);
    std::fs::write(share.join("a.bin"), b"aaaa").unwrap();
    ec_shared::reload_now(&shares, &dirs);
    let back = st.list(&shares.lock().unwrap());
    assert_ne!(back[0].ecid, first[0].ecid);
    assert_eq!(back[1].ecid, first[1].ecid);
}

#[tokio::test]
async fn priorities_are_set_as_amule_sets_them() {
    let d = TempDir::new("prio");
    let share = d.0.join("share");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::write(share.join("x.bin"), b"xyz").unwrap();
    let shares = Arc::new(Mutex::new(SharedFiles::load(&d.0).unwrap()));
    let dirs = ReloadDirs {
        dirs: vec![share.clone()],
        reserved: Vec::new(),
    };
    ec_shared::reload_now(&shares, &dirs);
    let hash = shares.lock().unwrap().files()[0].0.hash;
    let mut st = SharedState::default();
    let mut set = |prio: u8| {
        let (reply, _rx) = tokio::sync::oneshot::channel();
        st.handle(
            SharedRequest::SetPriority {
                // An unknown file is passed over.
                files: vec![(Md4Hash([1; 16]), 0), (hash, prio)],
                reply,
            },
            Some(&shares),
            &dirs,
            &d.0,
        );
        let s = shares.lock().unwrap();
        let f: KnownFile = s.get(&hash).unwrap().0.clone();
        (f.up_priority, f.auto_priority)
    };
    assert_eq!(set(priority::VERY_HIGH as u8), (priority::VERY_HIGH, false));
    assert_eq!(set(priority::LOW as u8), (priority::LOW, false));
    // Automatic: high, as for a file nobody is queued for.
    assert_eq!(set(priority::AUTO as u8), (priority::HIGH, true));
    // Kept in known.met.
    shares.lock().unwrap().save().unwrap();
    let met = KnownMet::read(&std::fs::read(d.0.join("known.met")).unwrap()).unwrap();
    let f = KnownFile::from_record(&met.records[0]).unwrap();
    assert_eq!((f.up_priority, f.auto_priority), (priority::HIGH, true));
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A daemon sharing a folder: an EC client lists the shared files, sets a
/// priority, reads the folders, adds a file and asks for a reload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ec_client_lists_prioritises_and_reloads_shared_files() {
    let d = TempDir::new("drive");
    let amule = d.0.join("amule");
    let share = d.0.join("share");
    std::fs::create_dir_all(&amule).unwrap();
    std::fs::create_dir_all(&share).unwrap();
    std::fs::write(share.join("first.txt"), b"the first shared file").unwrap();
    std::fs::write(
        amule.join("shareddir.dat"),
        format!("{}\n", share.display()),
    )
    .unwrap();
    let (port, ec_port) = (free_port(), free_port());
    std::fs::write(
        amule.join("amule.conf"),
        format!(
            "[eMule]\nPort={port}\nConnectToKad=0\nConnectToED2K=0\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\n\
             ECPassword={SECRET}\n"
        ),
    )
    .unwrap();
    let loaded = config::load(&amule).unwrap();
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

    let share2 = share.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(&ConnectOptions::new("127.0.0.1", ec_port, SECRET)).unwrap();
        // What `show shared` sends: no detail level, FULL.
        let list = |c: &mut Client| c.request(&Packet::new(EC_OP_GET_SHARED_FILES)).unwrap();
        let l = list(&mut c);
        assert_eq!(l.opcode, EC_OP_SHARED_FILES);
        // The incoming folder is shared too, and empty.
        assert_eq!(l.tags.len(), 1, "{l:?}");
        let f = &l.tags[0];
        assert_eq!(f.child_str(EC_TAG_PARTFILE_NAME), "first.txt");
        assert_eq!(f.child_int(EC_TAG_PARTFILE_SIZE_FULL), 21);
        assert_eq!(
            f.child_str(EC_TAG_KNOWNFILE_FILENAME),
            share2.display().to_string()
        );
        let hash = f.child(EC_TAG_PARTFILE_HASH).unwrap().as_hash().unwrap();
        let ecid = f.as_int();

        // Very high, by hash, as amulegui sends it.
        let r = c
            .request(
                &Packet::new(EC_OP_SHARED_SET_PRIO).with(
                    Tag::hash(EC_TAG_KNOWNFILE, hash).with(Tag::int(EC_TAG_KNOWNFILE_PRIO, 3)),
                ),
            )
            .unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        let l = list(&mut c);
        assert_eq!(l.tags[0].child_int(EC_TAG_KNOWNFILE_PRIO), 3);
        assert_eq!(l.tags[0].as_int(), ecid, "the same ECID");

        // The folders as configured.
        let dirs = c.request(&Packet::new(EC_OP_GET_SHARED_DIRS)).unwrap();
        assert_eq!(dirs.opcode, EC_OP_GET_SHARED_DIRS);
        assert_eq!(dirs.tags.len(), 1);
        assert_eq!(dirs.tags[0].as_str(), share2.display().to_string());

        // A new file, and a reload: answered at once, the file there soon.
        std::fs::write(share2.join("second.txt"), b"another one").unwrap();
        let r = c.request(&Packet::new(EC_OP_SHAREDFILES_RELOAD)).unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        let mut got = 0;
        for _ in 0..50 {
            got = list(&mut c).tags.len();
            if got == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(got, 2, "the reload never found the new file");
        let l = list(&mut c);
        assert_eq!(l.tags[1].child_str(EC_TAG_PARTFILE_NAME), "second.txt");
        // The first kept its ECID and priority through the reload.
        assert_eq!(l.tags[0].as_int(), ecid);
        assert_eq!(l.tags[0].child_int(EC_TAG_KNOWNFILE_PRIO), 3);

        // Deleting a complete file, as amuleapi asks it: only the one the
        // client saw (hash, ECID, folder, name).
        let second = &l.tags[1];
        let h2 = second
            .child(EC_TAG_PARTFILE_HASH)
            .unwrap()
            .as_hash()
            .unwrap();
        let id2 = second.as_int();
        let del = |hash: [u8; 16], ecid: u64, dir: &str, name: &str| {
            Packet::new(EC_OP_KNOWNFILE_DELETE)
                .with(Tag::hash(EC_TAG_KNOWNFILE, hash))
                .with(Tag::int(EC_TAG_ECID, ecid))
                .with(Tag::string(EC_TAG_KNOWNFILE_PATH, dir))
                .with(Tag::string(EC_TAG_PARTFILE_NAME, name))
        };
        let dir = share2.display().to_string();
        let changed = "The selected file has changed or is not a complete file.";
        for stale in [
            del(h2, id2 + 1000, &dir, "second.txt"),
            del(h2, id2, &dir, "other.txt"),
            del(h2, id2, "/elsewhere", "second.txt"),
        ] {
            let r = c.request(&stale).unwrap();
            assert_eq!(r.message().unwrap(), changed);
        }
        let r = c
            .request(&Packet::new(EC_OP_KNOWNFILE_DELETE).with(Tag::int(EC_TAG_ECID, id2)))
            .unwrap();
        assert_eq!(
            r.message().unwrap(),
            "Invalid complete-file deletion target."
        );
        assert!(share2.join("second.txt").exists());
        let r = c.request(&del(h2, id2, &dir, "second.txt")).unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        assert!(!share2.join("second.txt").exists(), "off the disk");
        let l = list(&mut c);
        assert_eq!(l.tags.len(), 1, "out of the list");
        assert_eq!(l.tags[0].child_str(EC_TAG_PARTFILE_NAME), "first.txt");

        // The user's comment and rating.
        let r = c
            .request(
                &Packet::new(EC_OP_SHARED_FILE_SET_COMMENT)
                    .with(Tag::hash(EC_TAG_KNOWNFILE, hash))
                    .with(Tag::string(EC_TAG_KNOWNFILE_COMMENT, "nice file"))
                    .with(Tag::int(EC_TAG_KNOWNFILE_RATING, 4)),
            )
            .unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        let l = list(&mut c);
        assert_eq!(l.tags[0].child_str(EC_TAG_KNOWNFILE_COMMENT), "nice file");
        assert_eq!(l.tags[0].child_int(EC_TAG_KNOWNFILE_RATING), 4);

        // Renamed in its folder; never out of it.
        let rename = |hash: [u8; 16], name: &str| {
            Packet::new(EC_OP_RENAME_FILE)
                .with(Tag::hash(EC_TAG_KNOWNFILE, hash))
                .with(Tag::string(EC_TAG_PARTFILE_NAME, name))
        };
        for (h, name, why) in [
            (hash, "../out.txt", "Unable to rename file."),
            (hash, "", "Invalid file name."),
            ([9; 16], "x.txt", "File not found."),
        ] {
            let r = c.request(&rename(h, name)).unwrap();
            assert_eq!(
                (r.opcode, r.message().unwrap().as_str()),
                (EC_OP_FAILED, why)
            );
        }
        let r = c.request(&rename(hash, "renamed.txt")).unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        assert!(share2.join("renamed.txt").exists() && !share2.join("first.txt").exists());
        let l = list(&mut c);
        assert_eq!(l.tags[0].child_str(EC_TAG_PARTFILE_NAME), "renamed.txt");
        assert_eq!(l.tags[0].as_int(), ecid, "the same file");

        // Verified: answered at once, the outcome in the log.
        let r = c
            .request(&Packet::new(EC_OP_VERIFY_LOCAL_DATA).with(Tag::hash(EC_TAG_KNOWNFILE, hash)))
            .unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        // Recorded once done, as the file's verify tags.
        let mut verified = None;
        for _ in 0..50 {
            let l = list(&mut c);
            if let Some(t) = l.tags[0].child(EC_TAG_KNOWNFILE_VERIFY_DATE) {
                verified = Some((
                    t.as_int(),
                    l.tags[0].child_str(EC_TAG_KNOWNFILE_VERIFY_CORRUPT_MD4),
                ));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let (date, md4) = verified.expect("the check was never recorded");
        assert!(date > 0);
        assert_eq!(md4, "", "nothing corrupt");

        assert_eq!(
            c.request(&Packet::new(EC_OP_SHUTDOWN)).unwrap().opcode,
            EC_OP_NOOP
        );
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
    // The priority set over EC is in known.met after the shutdown.
    let met = KnownMet::read(&std::fs::read(amule.join("known.met")).unwrap()).unwrap();
    let first = met
        .records
        .iter()
        .filter_map(|r| KnownFile::from_record(r).ok())
        .find(|f| f.name == "renamed.txt")
        .unwrap();
    assert_eq!(
        (first.up_priority, first.auto_priority),
        (priority::VERY_HIGH, false)
    );
    // The check is recorded, clean.
    assert_ne!(first.verify_date, 0);
    assert_eq!(first.verify_corrupt_md4, "");
    // The comment is in amule.conf, under the file's hash, as aMule keeps it.
    let conf = ed2k_formats::amule_conf::ConfFile::from_bytes(
        &std::fs::read(amule.join("amule.conf")).unwrap(),
    );
    assert_eq!(
        conf.get(&format!("/{}/Comment", first.hash)),
        Some("nice file")
    );
    assert_eq!(conf.get(&format!("/{}/Rate", first.hash)), Some("4"));
}

#[test]
fn comments_are_read_from_amule_conf() {
    let d = TempDir::new("comments");
    let share = d.0.join("share");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::write(share.join("c.bin"), b"commented").unwrap();
    let shares = Mutex::new(SharedFiles::load(&d.0).unwrap());
    let dirs = ReloadDirs {
        dirs: vec![share.clone()],
        reserved: Vec::new(),
    };
    ec_shared::reload_now(&shares, &dirs);
    let hash = shares.lock().unwrap().files()[0].0.hash;
    std::fs::write(
        d.0.join("amule.conf"),
        format!("[eMule]\nNick=x\n[{hash}]\nComment=hello\nRate=9\n"),
    )
    .unwrap();
    let mut st = SharedState::default();
    st.load_comments(&d.0);
    let f = &st.list(&shares.lock().unwrap())[0];
    // A rating past 5 is read as 5.
    assert_eq!((f.comment.as_str(), f.rating), ("hello", 5));
}
