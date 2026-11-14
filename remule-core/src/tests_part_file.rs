// SPDX-License-Identifier: GPL-2.0-or-later
//! Part files on disk: whole downloads through block reservation, buffered
//! writes, part hash checks, saving, resuming and completion.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use ed2k_formats::part_met::{PartFile as MetFile, PartMet, VERSION};
use ed2k_hash::{FileHashes, Hasher};
use ed2k_peer::PartStatus;
use ed2k_types::ed2k::{EMBLOCKSIZE, PARTSIZE};
use ed2k_types::Md4Hash;

use crate::part_file::{clean_file_name, completed_path};
use crate::{Completion, FileEvent, PartFile, SourceView, Status};

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "remule-core-{}-{}-{name}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(p.join("temp")).unwrap();
        fs::create_dir_all(p.join("incoming")).unwrap();
        TempDir(p)
    }

    pub(crate) fn temp(&self) -> PathBuf {
        self.0.join("temp")
    }

    pub(crate) fn incoming(&self) -> PathBuf {
        self.0.join("incoming")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn data(size: u64, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

pub(crate) fn hashes(d: &[u8]) -> FileHashes {
    let mut h = Hasher::new();
    h.update(d);
    h.finish()
}

/// A peer with only these parts.
pub(crate) fn parts(count: usize, have: &[usize]) -> PartStatus {
    PartStatus::Parts((0..count).map(|i| have.contains(&i)).collect())
}

/// Download everything `peer` has, as one source fetching three blocks at
/// a time. `corrupt` flips a byte in every block that starts inside it.
fn download(pf: &mut PartFile, d: &[u8], peer: &PartStatus, corrupt: Option<u16>) {
    let mut last = None;
    loop {
        let blocks = pf.reserve_blocks(&mut last, peer, 3);
        if blocks.is_empty() {
            break;
        }
        for b in blocks {
            assert!(b.end - b.start <= u64::from(EMBLOCKSIZE));
            assert_eq!(b.start / PARTSIZE, (b.end - 1) / PARTSIZE);
            let mut piece = d[b.start as usize..b.end as usize].to_vec();
            if corrupt == Some((b.start / PARTSIZE) as u16) {
                piece[0] ^= 0xFF;
            }
            pf.write(b.start, &piece).unwrap();
            pf.release_block(b);
        }
    }
}

fn read_met(path: &Path) -> (PartMet, MetFile) {
    let met = PartMet::read(&fs::read(path).unwrap()).unwrap();
    let file = MetFile::from_met(&met).unwrap();
    (met, file)
}

fn part_mtime(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

const MULTI: u64 = 2 * PARTSIZE + 12_345;

fn new_multi(dir: &TempDir) -> (PartFile, Vec<u8>, FileHashes) {
    let d = data(MULTI, 7);
    let h = hashes(&d);
    let pf = PartFile::create(&dir.temp(), "some file.iso", h.ed2k, MULTI).unwrap();
    (pf, d, h)
}

#[test]
fn create_writes_a_met_amule_can_read() {
    let dir = TempDir::new("create");
    let (pf, _, h) = new_multi(&dir);
    assert_eq!(pf.met_path(), dir.temp().join("001.part.met"));
    assert_eq!(pf.part_path(), dir.temp().join("001.part"));
    assert!(pf.part_path().exists());
    assert!(pf.hash_set_needed());
    assert_eq!(pf.status(), Status::Empty);

    let (met, file) = read_met(pf.met_path());
    assert_eq!(met.version, VERSION);
    assert_eq!(met.date, part_mtime(pf.part_path()));
    assert_eq!(file.hash, h.ed2k);
    assert_eq!(file.name, "some file.iso");
    assert_eq!(file.size, MULTI);
    assert_eq!(file.gaps, [(0, MULTI - 1)]);
    assert!(file.part_hashes.is_empty());
    // The met as stored is what aMule's own writer produces from it.
    assert_eq!(met.write(), file.to_met().write());

    // The next download takes the next number.
    let other = PartFile::create(&dir.temp(), "x", Md4Hash([1; 16]), 10).unwrap();
    assert_eq!(other.met_path(), dir.temp().join("002.part.met"));
    assert!(PartFile::create(&dir.temp(), "x", Md4Hash([1; 16]), 0).is_err());
}

#[test]
fn hash_sets_must_match_the_file_hash() {
    let dir = TempDir::new("hashset");
    let (mut pf, _, h) = new_multi(&dir);
    assert!(!pf.set_hash_set(h.part_hashes[..2].to_vec()));
    let mut bad = h.part_hashes.clone();
    bad[1] = Md4Hash([9; 16]);
    assert!(!pf.set_hash_set(bad));
    assert!(pf.hash_set_needed());
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    assert!(!pf.hash_set_needed());
    pf.flush().unwrap();
    assert_eq!(read_met(pf.met_path()).1.part_hashes, h.part_hashes);
}

#[test]
fn a_whole_download_is_verified_and_moved_to_incoming() {
    let dir = TempDir::new("whole");
    let (mut pf, d, h) = new_multi(&dir);
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    pf.add_source(&PartStatus::Complete);
    download(&mut pf, &d, &PartStatus::Complete, None);
    let events = pf.take_events();
    assert!(events.contains(&FileEvent::ReadyToComplete), "{events:?}");
    assert!(!events
        .iter()
        .any(|e| matches!(e, FileEvent::PartCorrupt(_))));
    assert_eq!(pf.status(), Status::Completing);
    assert!(pf.is_stopped());
    assert_eq!(pf.completed(), MULTI);
    assert_eq!(pf.transferred(), MULTI);
    assert_eq!(pf.part_status(), parts(3, &[0, 1, 2]));

    let met = pf.met_path().to_owned();
    let done = pf.complete(&dir.incoming()).unwrap();
    assert_eq!(done, Completion::Done(dir.incoming().join("some file.iso")));
    assert_eq!(pf.status(), Status::Complete);
    assert_eq!(fs::read(dir.incoming().join("some file.iso")).unwrap(), d);
    for ext in ["", ".bak", ".tmp", ".bak.tmp"] {
        let mut p = met.clone().into_os_string();
        p.push(ext);
        assert!(!Path::new(&p).exists(), "{p:?} left behind");
    }
    assert!(!dir.temp().join("001.part").exists());
}

#[test]
fn parts_are_verified_as_they_complete() {
    let dir = TempDir::new("verify");
    let (mut pf, d, h) = new_multi(&dir);
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    download(&mut pf, &d, &parts(3, &[1]), None);
    pf.flush().unwrap();
    assert_eq!(pf.take_events(), [FileEvent::PartVerified(1)]);
    assert_eq!(pf.status(), Status::Ready);
    assert_eq!(pf.part_status(), parts(3, &[1]));
}

#[test]
fn a_corrupt_part_is_missing_again_until_it_downloads_clean() {
    let dir = TempDir::new("corrupt");
    let (mut pf, d, h) = new_multi(&dir);
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    let peer = parts(3, &[0]);
    download(&mut pf, &d, &peer, Some(0));
    pf.flush().unwrap();
    assert_eq!(pf.take_events(), [FileEvent::PartCorrupt(0)]);
    assert_eq!(pf.corrupted_parts(), [0]);
    assert_eq!(pf.gaps().iter().collect::<Vec<_>>(), [(0, MULTI - 1)]);
    assert_eq!(pf.lost_to_corruption(), PARTSIZE);
    assert_eq!(read_met(pf.met_path()).1.corrupted_parts, [0]);

    download(&mut pf, &d, &peer, None);
    pf.flush().unwrap();
    assert_eq!(pf.take_events(), [FileEvent::PartVerified(0)]);
    assert!(pf.corrupted_parts().is_empty());
    assert!(read_met(pf.met_path()).1.corrupted_parts.is_empty());
}

#[test]
fn a_download_resumes_from_its_met() {
    let dir = TempDir::new("resume");
    let (mut pf, d, h) = new_multi(&dir);
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    download(&mut pf, &d, &parts(3, &[1, 2]), None);
    pf.flush().unwrap();
    let gaps: Vec<_> = pf.gaps().iter().collect();
    assert_eq!(gaps, [(0, PARTSIZE - 1)]);
    let met_path = pf.met_path().to_owned();
    drop(pf);

    // What aMule would load.
    let (met, file) = read_met(&met_path);
    assert_eq!(met.date, part_mtime(&dir.temp().join("001.part")));
    assert_eq!(file.gaps, gaps);
    assert_eq!(file.part_hashes, h.part_hashes);
    assert_eq!(file.transferred, PARTSIZE + 12_345);

    let mut pf = PartFile::open(&met_path).unwrap();
    assert_eq!(pf.gaps().iter().collect::<Vec<_>>(), gaps);
    assert_eq!(pf.status(), Status::Ready);
    assert!(!pf.hash_set_needed());
    assert_eq!(pf.name(), "some file.iso");
    assert!(pf.take_events().is_empty());

    download(&mut pf, &d, &PartStatus::Complete, None);
    let Completion::Done(path) = pf.complete(&dir.incoming()).unwrap() else {
        panic!("not completed");
    };
    assert_eq!(fs::read(path).unwrap(), d);
}

#[test]
fn a_part_file_changed_behind_our_back_is_rehashed() {
    let dir = TempDir::new("rehash");
    let (mut pf, d, h) = new_multi(&dir);
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    download(&mut pf, &d, &parts(3, &[0, 1]), None);
    pf.flush().unwrap();
    let met_path = pf.met_path().to_owned();
    let part_path = pf.part_path().to_owned();
    drop(pf);

    // Damage part 1 and move the mtime away from the met's date.
    let mut bytes = fs::read(&part_path).unwrap();
    bytes[PARTSIZE as usize + 100] ^= 1;
    fs::write(&part_path, &bytes).unwrap();
    let f = fs::OpenOptions::new().write(true).open(&part_path).unwrap();
    f.set_modified(UNIX_EPOCH + Duration::from_secs(1_000_000))
        .unwrap();
    drop(f);

    let mut pf = PartFile::open(&met_path).unwrap();
    assert_eq!(pf.take_events(), [FileEvent::PartCorrupt(1)]);
    assert!(pf.gaps().is_part_complete(0));
    assert!(!pf.gaps().is_part_complete(1));
    assert_eq!(pf.corrupted_parts(), [1]);
    // Saved, with the .part's new date.
    let (met, file) = read_met(&met_path);
    assert_eq!(met.date, 1_000_000);
    assert_eq!(file.corrupted_parts, [1]);
}

#[test]
fn a_short_part_file_reopens_the_missing_tail() {
    let dir = TempDir::new("short");
    let (mut pf, d, h) = new_multi(&dir);
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    download(&mut pf, &d, &parts(3, &[0, 1]), None);
    pf.flush().unwrap();
    let met_path = pf.met_path().to_owned();
    let part_path = pf.part_path().to_owned();
    drop(pf);
    let f = fs::OpenOptions::new().write(true).open(&part_path).unwrap();
    f.set_len(PARTSIZE + 10).unwrap();
    drop(f);

    let pf = PartFile::open(&met_path).unwrap();
    assert_eq!(
        pf.gaps().iter().collect::<Vec<_>>(),
        [(PARTSIZE + 10, MULTI - 1)]
    );
}

#[test]
fn a_broken_met_is_restored_from_its_backup() {
    let dir = TempDir::new("backup");
    let (mut pf, d, h) = new_multi(&dir);
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    pf.flush().unwrap();
    download(&mut pf, &d, &parts(3, &[2]), None);
    pf.flush().unwrap();
    let met_path = pf.met_path().to_owned();
    drop(pf);
    fs::write(&met_path, [0x55, 1, 2, 3]).unwrap();

    let pf = PartFile::open(&met_path).unwrap();
    assert_eq!(pf.part_hashes(), h.part_hashes);
    // The met is good again.
    assert_eq!(read_met(&met_path).1.part_hashes, h.part_hashes);
}

#[test]
fn sources_get_disjoint_blocks_they_have() {
    let dir = TempDir::new("reserve");
    let (mut pf, d, _) = new_multi(&dir);
    let all = PartStatus::Complete;
    let (mut a, mut b) = (None, None);
    let ba = pf.reserve_blocks(&mut a, &all, 3);
    let bb = pf.reserve_blocks(&mut b, &all, 3);
    assert_eq!((ba.len(), bb.len()), (3, 3));
    for x in &ba {
        for y in &bb {
            assert!(x.end <= y.start || y.end <= x.start, "{x:?} overlaps {y:?}");
        }
    }
    // A source's blocks follow each other while they are in one part. The
    // short last part ranks first: it counts as nearly complete.
    assert_eq!(ba[0], 2 * PARTSIZE..MULTI);
    for w in ba.windows(2).chain(bb.windows(2)) {
        if w[0].start / PARTSIZE == w[1].start / PARTSIZE {
            assert_eq!(w[0].end, w[1].start);
        }
    }
    assert_eq!(pf.requested_blocks().len(), 6);

    // Nothing for a peer without parts we need, or with an empty bitmap.
    let mut c = None;
    assert!(pf.reserve_blocks(&mut c, &parts(3, &[]), 3).is_empty());
    assert!(pf
        .reserve_blocks(&mut c, &PartStatus::Parts(vec![]), 3)
        .is_empty());

    // Data outside every reservation is dropped; so is a duplicate.
    let reserved = pf.requested_blocks();
    let free = (0..MULTI / 1000)
        .map(|i| i * 1000..i * 1000 + 10)
        .find(|r| {
            reserved
                .iter()
                .all(|b| r.end <= b.start || b.end <= r.start)
        })
        .unwrap();
    assert_eq!(
        pf.write(free.start, &d[free.start as usize..free.end as usize])
            .unwrap(),
        0
    );
    let blk = ba[0].clone();
    let piece = &d[blk.start as usize..blk.end as usize];
    assert_eq!(pf.write(blk.start, piece).unwrap(), piece.len() as u64);
    assert_eq!(pf.write(blk.start, piece).unwrap(), 0);
    assert_eq!(pf.buffered_bytes(), piece.len() as u64);

    // A released block that was not written is offered again.
    let unwritten = ba[1].clone();
    pf.release_block(unwritten.clone());
    let mut e = Some((unwritten.start / PARTSIZE) as u16);
    assert_eq!(pf.reserve_blocks(&mut e, &all, 1), [unwritten]);
}

#[test]
fn a_paused_file_reserves_nothing_and_saves_the_pause() {
    let dir = TempDir::new("pause");
    let (mut pf, _, _) = new_multi(&dir);
    pf.set_paused(true);
    assert!(pf.is_stopped());
    let mut l = None;
    assert!(pf
        .reserve_blocks(&mut l, &PartStatus::Complete, 3)
        .is_empty());
    pf.flush().unwrap();
    assert!(read_met(pf.met_path()).1.paused);
}

#[test]
fn a_one_part_file_needs_no_hash_set() {
    let dir = TempDir::new("one");
    let d = data(500_000, 3);
    let h = hashes(&d);
    let mut pf = PartFile::create(&dir.temp(), "small.bin", h.ed2k, 500_000).unwrap();
    assert!(!pf.hash_set_needed());
    download(&mut pf, &d, &PartStatus::Complete, None);
    assert_eq!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::Done(dir.incoming().join("small.bin"))
    );
}

#[test]
fn a_one_part_file_that_fails_its_hash_is_downloaded_again() {
    let dir = TempDir::new("one-bad");
    let d = data(500_000, 3);
    let h = hashes(&d);
    let mut pf = PartFile::create(&dir.temp(), "small.bin", h.ed2k, 500_000).unwrap();
    download(&mut pf, &d, &PartStatus::Complete, Some(0));
    assert_eq!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::Corrupt(vec![0])
    );
    assert_eq!(pf.status(), Status::Ready);
    assert_eq!(pf.gaps().gap_size(), 500_000);
    download(&mut pf, &d, &PartStatus::Complete, None);
    assert!(matches!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::Done(_)
    ));
}

#[test]
fn a_file_of_exactly_one_part_size() {
    let dir = TempDir::new("exact");
    let d = data(PARTSIZE, 5);
    let h = hashes(&d);
    assert_eq!(h.part_hashes.len(), 2);
    let mut pf = PartFile::create(&dir.temp(), "exact.bin", h.ed2k, PARTSIZE).unwrap();
    assert!(pf.hash_set_needed());
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    // Two eD2k parts, the second the empty one, always complete.
    assert_eq!(pf.part_status(), parts(2, &[1]));
    download(&mut pf, &d, &PartStatus::Complete, None);
    assert!(matches!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::Done(_)
    ));
}

#[test]
fn completion_without_a_hash_set_adopts_the_file_hashes() {
    let dir = TempDir::new("adopt");
    let (mut pf, d, h) = new_multi(&dir);
    download(&mut pf, &d, &PartStatus::Complete, None);
    assert!(pf.take_events().contains(&FileEvent::HashSetNeeded));
    assert!(matches!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::Done(_)
    ));
    assert_eq!(pf.part_hashes(), h.part_hashes);
}

#[test]
fn a_bad_file_without_a_hash_set_waits_for_one() {
    let dir = TempDir::new("await");
    let (mut pf, d, h) = new_multi(&dir);
    download(&mut pf, &d, &PartStatus::Complete, Some(1));
    assert_eq!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::AwaitingHashSet
    );
    assert!(pf.hash_set_needed());
    pf.take_events();
    assert!(pf.set_hash_set(h.part_hashes.clone()));
    assert_eq!(pf.take_events(), [FileEvent::ReadyToComplete]);
    assert_eq!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::Corrupt(vec![1])
    );
    download(&mut pf, &d, &PartStatus::Complete, None);
    assert!(matches!(
        pf.complete(&dir.incoming()).unwrap(),
        Completion::Done(_)
    ));
    assert_eq!(fs::read(dir.incoming().join("some file.iso")).unwrap(), d);
}

#[test]
fn completed_names_are_cleaned_and_never_overwrite() {
    let dir = TempDir::new("names");
    let inc = dir.incoming();
    assert_eq!(completed_path(&inc, "a.iso"), inc.join("a.iso"));
    fs::write(inc.join("a.iso"), b"x").unwrap();
    assert_eq!(completed_path(&inc, "a.iso"), inc.join("a(0).iso"));
    fs::write(inc.join("a(0).iso"), b"x").unwrap();
    assert_eq!(completed_path(&inc, "a.iso"), inc.join("a(1).iso"));
    fs::write(inc.join("noext"), b"x").unwrap();
    assert_eq!(completed_path(&inc, "noext"), inc.join("noext(0)"));
    assert_eq!(clean_file_name("a/b\u{1}c"), "abc");
    assert_eq!(clean_file_name("/"), "Unknown");
    if cfg!(windows) {
        assert_eq!(clean_file_name("what?<now>.txt"), "whatnow.txt");
    }
}

#[test]
fn the_session_view_reserves_writes_and_reports() {
    use ed2k_peer::download::PartFile as _;
    let dir = TempDir::new("view");
    let (mut pf, d, h) = new_multi(&dir);
    let mut last = None;
    let mut view = SourceView {
        file: &mut pf,
        last_part: &mut last,
        wants_sources: false,
    };
    assert!(view.hash_set_needed());
    assert!(view.set_hash_set(h.part_hashes.clone()));
    let blocks = view.reserve_blocks(&PartStatus::Complete, 3);
    assert_eq!(blocks.len(), 3);
    for b in &blocks {
        view.write(b.start, &d[b.start as usize..b.end as usize]);
        view.release_block(b.clone());
    }
    // The short last part came first and is complete.
    assert_eq!(blocks[0], 2 * PARTSIZE..MULTI);
    assert!(view.has_part(2) && !view.has_part(0));
    assert_eq!(view.status(), parts(3, &[2]));
    assert!(last.is_some());
    let fetched: u64 = blocks.iter().map(|b| b.end - b.start).sum();
    assert_eq!(pf.completed(), fetched);
}

#[test]
fn resuming_keeps_everything_amule_stores_in_the_met() {
    use ed2k_codec::{Tag, TagValue};
    use ed2k_formats::part_met::priority;

    let dir = TempDir::new("keep");
    let d = data(MULTI, 11);
    let h = hashes(&d);
    // A .part holding part 0, and a met as aMule's SavePartFile writes it.
    let part_path = dir.temp().join("007.part");
    fs::write(&part_path, &d[..PARTSIZE as usize]).unwrap();
    let original = MetFile {
        date: part_mtime(&part_path),
        hash: h.ed2k,
        part_hashes: h.part_hashes.clone(),
        name: "Sörvér ☃.mkv".into(),
        size: MULTI,
        transferred: PARTSIZE + 77,
        paused: true,
        down_priority: priority::HIGH,
        auto_down_priority: false,
        up_priority: priority::HIGH,
        auto_up_priority: true,
        category: 2,
        last_seen_complete: 1_699_000_000,
        kad_last_publish_src: 1_700_000_100,
        kad_last_publish_notes: 0,
        dl_active_time: 3600,
        corrupted_parts: vec![1],
        aich_hash: Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".into()),
        all_time_transferred: (3 << 32) + 99,
        all_time_requests: 5,
        all_time_accepts: 2,
        gaps: vec![(PARTSIZE, MULTI - 1)],
        other_tags: vec![Tag::new("Artist", TagValue::String("Someone".into()))],
    };
    let met_path = dir.temp().join("007.part.met");
    fs::write(&met_path, original.to_met().write()).unwrap();

    let mut pf = PartFile::open(&met_path).unwrap();
    assert_eq!(pf.status(), Status::Ready);
    assert!(pf.is_paused());
    assert_eq!(pf.corrupted_parts(), [1]);
    assert!(pf.take_events().is_empty());
    pf.set_paused(false);
    pf.save().unwrap();

    let (_, saved) = read_met(&met_path);
    let expected = MetFile {
        paused: false,
        date: part_mtime(&part_path),
        ..original
    };
    assert_eq!(saved, expected);
    // The previous met is the backup.
    let mut bak = met_path.clone().into_os_string();
    bak.push(".bak");
    assert!(read_met(Path::new(&bak)).1.paused);
}

#[test]
fn files_over_4_gb_get_the_large_file_met() {
    use ed2k_formats::part_met::VERSION_LARGE_FILE;
    let dir = TempDir::new("large");
    let size = 5 << 30;
    let pf = PartFile::create(&dir.temp(), "big.iso", Md4Hash([3; 16]), size).unwrap();
    let (met, file) = read_met(pf.met_path());
    assert_eq!(met.version, VERSION_LARGE_FILE);
    assert_eq!(file.size, size);
    assert_eq!(file.gaps, [(0, size - 1)]);
    drop(pf);
    let pf = PartFile::open(&dir.temp().join("001.part.met")).unwrap();
    assert_eq!(pf.size(), size);
    assert_eq!(pf.gaps().gap_size(), size);
}

// ---- AICH recovery ----

mod aich_recovery {
    use std::net::Ipv4Addr;

    use ed2k_hash::aich::{signing_key_v4, AichTree};
    use ed2k_types::AichHash;

    use super::*;
    use crate::AichStatus;

    /// Download what `peer` has, flipping a byte in the block that holds
    /// offset `bad`.
    fn download_with_bad_byte(pf: &mut PartFile, d: &[u8], peer: &PartStatus, bad: u64) {
        let mut last = None;
        loop {
            let blocks = pf.reserve_blocks(&mut last, peer, 3);
            if blocks.is_empty() {
                break;
            }
            for b in blocks {
                let mut piece = d[b.start as usize..b.end as usize].to_vec();
                if b.contains(&bad) {
                    piece[(bad - b.start) as usize] ^= 0xFF;
                }
                pf.write(b.start, &piece).unwrap();
                pf.release_block(b);
            }
        }
    }

    fn trust(pf: &mut PartFile, root: AichHash) {
        for i in 0..10 {
            pf.aich_hash_received(root, signing_key_v4(Ipv4Addr::new(10, i, 0, 1)), false);
        }
        assert_eq!(pf.aich_status(), AichStatus::Trusted);
        assert_eq!(pf.aich_root(), Some(root));
    }

    #[test]
    fn a_corrupt_part_keeps_its_good_blocks() {
        let dir = TempDir::new("aich");
        let (mut pf, d, h) = new_multi(&dir);
        let root = h.aich_root.unwrap();
        assert!(pf.set_hash_set(h.part_hashes.clone()));
        trust(&mut pf, root);

        let block = u64::from(EMBLOCKSIZE);
        let bad = PARTSIZE + 3 * block + 17;
        download_with_bad_byte(&mut pf, &d, &parts(3, &[1]), bad);
        pf.flush().unwrap();
        assert_eq!(
            pf.take_events(),
            [
                FileEvent::PartCorrupt(1),
                FileEvent::AichRecoveryWanted { part: 1, root }
            ]
        );
        assert_eq!(pf.aich_wanted(), [1]);

        // A peer with the whole file sends the part's recovery data.
        let mut full = AichTree::from_blocks(MULTI, &h.aich_blocks).unwrap();
        let data = full.part_recovery_data(PARTSIZE).unwrap();
        let kept = pf.aich_recovery_data(1, root, &data).unwrap();
        assert_eq!(kept, Some(PARTSIZE - block));
        assert_eq!(pf.recovered_by_aich(), PARTSIZE - block);
        assert!(pf.aich_wanted().is_empty());
        assert!(pf.corrupted_parts().is_empty());
        // Only the bad block is missing from part 1.
        let start = PARTSIZE + 3 * block;
        assert_eq!(
            pf.gaps().missing_in(PARTSIZE, 2 * PARTSIZE - 1),
            [(start, start + block - 1)]
        );

        // It is fetched again, and the part checks out.
        download_with_bad_byte(&mut pf, &d, &parts(3, &[1]), u64::MAX);
        pf.flush().unwrap();
        assert_eq!(pf.take_events(), [FileEvent::PartVerified(1)]);
        assert_eq!(pf.status(), Status::Ready);
    }

    #[test]
    fn recovery_data_under_another_root_is_refused() {
        let dir = TempDir::new("aich-root");
        let (mut pf, d, h) = new_multi(&dir);
        let root = h.aich_root.unwrap();
        assert!(pf.set_hash_set(h.part_hashes.clone()));
        trust(&mut pf, root);
        download_with_bad_byte(&mut pf, &d, &parts(3, &[0]), 5);
        pf.flush().unwrap();
        pf.take_events();

        let mut full = AichTree::from_blocks(MULTI, &h.aich_blocks).unwrap();
        let data = full.part_recovery_data(0).unwrap();
        // Data for another part, a root we do not trust, garbage.
        assert_eq!(
            pf.aich_recovery_data(0, AichHash([1; 20]), &data).unwrap(),
            None
        );
        assert_eq!(pf.aich_recovery_data(0, root, &data[..40]).unwrap(), None);
        assert_eq!(pf.gaps().part_gap_size(0), PARTSIZE);

        // A failed request lets the next corruption ask again.
        pf.aich_recovery_failed(0);
        assert!(pf.aich_wanted().is_empty());
    }

    #[test]
    fn an_untrusted_root_asks_for_nothing() {
        let dir = TempDir::new("aich-untrusted");
        let (mut pf, d, h) = new_multi(&dir);
        let root = h.aich_root.unwrap();
        assert!(pf.set_hash_set(h.part_hashes.clone()));
        pf.aich_hash_received(root, signing_key_v4(Ipv4Addr::new(10, 0, 0, 1)), false);
        assert_eq!(pf.aich_status(), AichStatus::Untrusted);
        download_with_bad_byte(&mut pf, &d, &parts(3, &[0]), 5);
        pf.flush().unwrap();
        assert_eq!(pf.take_events(), [FileEvent::PartCorrupt(0)]);
        // Nor is data taken under it.
        let mut full = AichTree::from_blocks(MULTI, &h.aich_blocks).unwrap();
        let data = full.part_recovery_data(0).unwrap();
        assert_eq!(pf.aich_recovery_data(0, root, &data).unwrap(), None);
    }

    #[test]
    fn a_root_from_a_link_is_saved_and_completion_records_the_files() {
        let dir = TempDir::new("aich-link");
        let (mut pf, d, h) = new_multi(&dir);
        let root = h.aich_root.unwrap();
        pf.set_aich_root(root);
        pf.save().unwrap();
        // Reports from peers do not move a verified root.
        pf.aich_hash_received(AichHash([1; 20]), 7, false);
        assert_eq!(pf.aich_root(), Some(root));
        let met_path = pf.met_path().to_owned();
        assert_eq!(read_met(&met_path).1.aich_hash, Some(root.to_string()));
        drop(pf);

        let mut pf = PartFile::open(&met_path).unwrap();
        assert_eq!(pf.aich_status(), AichStatus::Verified);
        assert_eq!(pf.aich_root(), Some(root));

        // Completion records the file's own root.
        download(&mut pf, &d, &PartStatus::Complete, None);
        assert!(matches!(
            pf.complete(&dir.incoming()).unwrap(),
            Completion::Done(_)
        ));
        assert_eq!(pf.aich_root(), Some(root));
        assert_eq!(pf.info().aich_hash, Some(root.to_string()));
    }

    #[test]
    fn the_session_view_passes_the_source_wish() {
        use ed2k_peer::download::PartFile as _;
        let dir = TempDir::new("aich-view");
        let (mut pf, _, _) = new_multi(&dir);
        let mut last = None;
        let view = SourceView {
            file: &mut pf,
            last_part: &mut last,
            wants_sources: true,
        };
        assert!(view.wants_sources());
    }
}
