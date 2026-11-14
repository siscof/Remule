// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared files: scanning, hashing, known.met and known2_64.met.

use std::fs;
use std::time::{Duration, UNIX_EPOCH};

use ed2k_formats::known2_met::Known2Met;
use ed2k_formats::known_met::{KnownFile, KnownMet, VERSION};
use ed2k_types::ed2k::PARTSIZE;

use crate::shared::{mtime, ScanOptions, SharedFiles, KNOWN2_MET, KNOWN_MET};
use crate::tests_part_file::{data, hashes, TempDir};

const NOW: u32 = 1_800_000_000;

fn hash_all(s: &mut SharedFiles, to_hash: &[std::path::PathBuf]) {
    for p in to_hash {
        let h = SharedFiles::hash(p).unwrap();
        let date = mtime(&fs::metadata(p).unwrap());
        s.add_hashed(p, &h, date, NOW);
    }
}

fn opts(dir: &TempDir) -> ScanOptions {
    ScanOptions {
        dirs: vec![dir.incoming()],
        reserved: vec![dir.temp()],
        hidden: false,
    }
}

#[test]
fn new_files_are_hashed_recorded_and_known_next_time() {
    let dir = TempDir::new("shared-new");
    let inc = dir.incoming();
    let big = data(PARTSIZE + 1000, 1);
    fs::write(inc.join("big.bin"), &big).unwrap();
    fs::write(inc.join("small.txt"), b"hello").unwrap();
    fs::write(inc.join("empty"), b"").unwrap();
    fs::write(inc.join(".hidden"), b"x").unwrap();
    let cfg = dir.0.join("config");

    let mut s = SharedFiles::load(&cfg).unwrap();
    assert_eq!(s.known_count(), 0);
    let r = s.scan(&opts(&dir), NOW);
    assert_eq!(r.known, 0);
    assert_eq!(r.to_hash, [inc.join("big.bin"), inc.join("small.txt")]);
    hash_all(&mut s, &r.to_hash);
    assert_eq!(s.shared_count(), 2);
    let h = hashes(&big);
    let (f, path) = s.get(&h.ed2k).unwrap();
    assert_eq!(path, inc.join("big.bin"));
    assert_eq!(f.name, "big.bin");
    assert_eq!(f.size, PARTSIZE + 1000);
    assert_eq!(f.part_hashes, h.part_hashes);
    assert_eq!(f.aich_hash, h.aich_root.map(|r| r.to_string()));
    assert_eq!(s.aich_set(&h.ed2k).unwrap().block_hashes, h.aich_blocks);
    s.save().unwrap();

    // What aMule would read.
    let met = KnownMet::read(&fs::read(cfg.join(KNOWN_MET)).unwrap()).unwrap();
    assert_eq!(met.version, VERSION);
    assert_eq!(met.records.len(), 2);
    let back: Vec<KnownFile> = met
        .records
        .iter()
        .map(|r| KnownFile::from_record(r).unwrap())
        .collect();
    assert!(back.iter().any(|k| k.name == "small.txt" && k.size == 5));
    let k2 = Known2Met::read(&fs::read(cfg.join(KNOWN2_MET)).unwrap()).unwrap();
    assert_eq!(k2.sets.len(), 2);

    // Next start: nothing to hash.
    let mut s = SharedFiles::load(&cfg).unwrap();
    assert_eq!(s.known_count(), 2);
    let r = s.scan(&opts(&dir), NOW + 10);
    assert_eq!(r.known, 2);
    assert!(r.to_hash.is_empty());
    assert_eq!(s.files().len(), 2);
    assert_eq!(s.get(&h.ed2k).unwrap().0.last_seen, NOW + 10);
}

#[test]
fn a_changed_file_is_hashed_again() {
    let dir = TempDir::new("shared-changed");
    let inc = dir.incoming();
    let p = inc.join("doc.txt");
    fs::write(&p, b"first version").unwrap();
    let mut s = SharedFiles::load(&dir.0.join("config")).unwrap();
    let r = s.scan(&opts(&dir), NOW);
    hash_all(&mut s, &r.to_hash);
    let old = SharedFiles::hash(&p).unwrap().ed2k;

    // Same size, another time: hashed again.
    fs::write(&p, b"first versioN").unwrap();
    let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_modified(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        .unwrap();
    drop(f);
    let r = s.scan(&opts(&dir), NOW);
    assert_eq!(r.to_hash, std::slice::from_ref(&p));
    hash_all(&mut s, &r.to_hash);
    let new = SharedFiles::hash(&p).unwrap().ed2k;
    assert_ne!(old, new);
    assert!(s.get(&new).is_some());
    assert!(s.get(&old).is_none());
    // The old record stays known.
    assert_eq!(s.known_count(), 2);
}

#[test]
fn a_renamed_file_keeps_its_statistics() {
    let dir = TempDir::new("shared-renamed");
    let inc = dir.incoming();
    fs::write(inc.join("a.txt"), b"same content").unwrap();
    let mut s = SharedFiles::load(&dir.0.join("config")).unwrap();
    let r = s.scan(&opts(&dir), NOW);
    hash_all(&mut s, &r.to_hash);
    let h = SharedFiles::hash(&inc.join("a.txt")).unwrap().ed2k;
    s.get_mut(&h).unwrap().all_time_transferred = 1234;

    fs::rename(inc.join("a.txt"), inc.join("b.txt")).unwrap();
    let r = s.scan(&opts(&dir), NOW);
    assert_eq!(r.to_hash, [inc.join("b.txt")]);
    hash_all(&mut s, &r.to_hash);
    let (f, path) = s.get(&h).unwrap();
    assert_eq!(f.name, "b.txt");
    assert_eq!(path, inc.join("b.txt"));
    assert_eq!(f.all_time_transferred, 1234);
    assert_eq!(s.known_count(), 1);
}

#[test]
fn the_first_copy_of_duplicate_content_is_shared() {
    let dir = TempDir::new("shared-dup");
    let other = dir.0.join("other");
    fs::create_dir_all(&other).unwrap();
    fs::write(dir.incoming().join("x.bin"), b"twins").unwrap();
    fs::write(other.join("x.bin"), b"twins").unwrap();
    let mut o = opts(&dir);
    o.dirs.push(other.clone());
    let mut s = SharedFiles::load(&dir.0.join("config")).unwrap();
    let r = s.scan(&o, NOW);
    hash_all(&mut s, &r.to_hash);
    assert_eq!(s.shared_count(), 1);
    let h = SharedFiles::hash(&other.join("x.bin")).unwrap().ed2k;
    // Directories are walked in sorted order: incoming before other.
    let first = if dir.incoming() < other {
        dir.incoming()
    } else {
        other
    };
    assert_eq!(s.get(&h).unwrap().1, first.join("x.bin"));
}

#[test]
fn reserved_and_missing_directories_are_not_shared() {
    let dir = TempDir::new("shared-reserved");
    fs::write(dir.temp().join("001.part"), b"partial").unwrap();
    let mut o = opts(&dir);
    o.dirs.push(dir.temp());
    o.dirs.push(dir.0.join("nowhere"));
    let mut s = SharedFiles::load(&dir.0.join("config")).unwrap();
    let r = s.scan(&o, NOW);
    assert!(r.to_hash.is_empty());
    assert_eq!(r.skipped.len(), 2);
    assert!(r
        .skipped
        .iter()
        .any(|(d, why)| *d == dir.temp() && why == "reserved directory"));
    // Hidden files, when asked.
    fs::write(dir.incoming().join(".dot"), b"x").unwrap();
    o.hidden = true;
    let r = s.scan(&o, NOW);
    assert_eq!(r.to_hash, [dir.incoming().join(".dot")]);
}

#[test]
fn a_damaged_known_met_keeps_what_it_can() {
    let dir = TempDir::new("shared-damaged");
    let cfg = dir.0.join("config");
    fs::write(dir.incoming().join("a"), b"aaa").unwrap();
    fs::write(dir.incoming().join("b"), b"bbb").unwrap();
    let mut s = SharedFiles::load(&cfg).unwrap();
    let r = s.scan(&opts(&dir), NOW);
    hash_all(&mut s, &r.to_hash);
    s.save().unwrap();
    // Cut the second record short.
    let mut b = fs::read(cfg.join(KNOWN_MET)).unwrap();
    b.truncate(b.len() - 10);
    fs::write(cfg.join(KNOWN_MET), &b).unwrap();
    let s = SharedFiles::load(&cfg).unwrap();
    assert_eq!(s.known_count(), 1);
    assert!(s.is_dirty());
}
