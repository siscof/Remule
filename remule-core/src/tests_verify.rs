// SPDX-License-Identifier: GPL-2.0-or-later
//! "Verify Local Data" ([`crate::verify`]).

use std::fs;
use std::io::Write;
use std::path::Path;

use ed2k_types::ed2k::{EMBLOCKSIZE, PARTSIZE};

use crate::tests_part_file::TempDir;
use crate::verify::*;

fn target(path: &Path) -> VerifyTarget {
    let h = ed2k_hash::hash_reader(fs::File::open(path).unwrap()).unwrap();
    VerifyTarget {
        path: path.to_owned(),
        size: h.size,
        file_hash: h.ed2k,
        part_hashes: h.part_hashes,
        aich_blocks: Some(h.aich_blocks),
    }
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

#[test]
fn an_intact_file_is_ok_on_md4_and_aich() {
    let dir = TempDir::new("verify-1");
    let p = dir.0.join("small.dat");
    fs::write(&p, data(1_000_000)).unwrap();
    let t = target(&p);
    let r = verify(&t);
    assert_eq!(
        r,
        VerifyOutcome::Checked {
            aich: true,
            md4: vec![],
            aich_blocks: vec![]
        }
    );
    let (critical, line) = r.report(&p);
    assert!(!critical);
    assert_eq!(
        line,
        format!(
            "Verify Local Data (MD4 & AICH): Result OK for {}",
            p.display()
        )
    );
    assert_eq!(r.record(), Some((String::new(), String::new())));

    // Without the AICH set only MD4 is checked.
    let r = verify(&VerifyTarget {
        aich_blocks: None,
        ..t
    });
    assert!(r
        .report(&p)
        .1
        .starts_with("Verify Local Data (MD4): Result OK"));
}

#[test]
fn a_damaged_block_is_found_by_part_and_block() {
    let dir = TempDir::new("verify-2");
    let p = dir.0.join("two-parts.dat");
    let len = PARTSIZE as usize + 500_000;
    fs::write(&p, data(len)).unwrap();
    let t = target(&p);
    assert_eq!(t.part_hashes.len(), 2);

    // One byte in part 1, block 2.
    let mut d = data(len);
    let at = PARTSIZE as usize + 2 * EMBLOCKSIZE as usize + 10;
    d[at] ^= 0xff;
    fs::write(&p, d).unwrap();
    let r = verify(&t);
    assert_eq!(
        r,
        VerifyOutcome::Checked {
            aich: true,
            md4: vec![1],
            aich_blocks: vec![(1, vec![2])]
        }
    );
    let (critical, line) = r.report(&p);
    assert!(critical);
    assert_eq!(
        line,
        format!(
            "Verify Local Data (MD4 & AICH): ERRORS FOUND! {} Failed blocks: MD4: 1. AICH: 1: (2)",
            p.display()
        )
    );
    assert_eq!(r.record(), Some(("1".into(), "1:2".into())));
}

#[test]
fn a_one_part_file_is_checked_against_its_file_hash() {
    let dir = TempDir::new("verify-3");
    let p = dir.0.join("one.dat");
    fs::write(&p, data(5000)).unwrap();
    let t = VerifyTarget {
        aich_blocks: None,
        ..target(&p)
    };
    assert!(t.part_hashes.is_empty());
    let mut d = data(5000);
    d[0] ^= 1;
    fs::write(&p, d).unwrap();
    assert_eq!(
        verify(&t),
        VerifyOutcome::Checked {
            aich: false,
            md4: vec![0],
            aich_blocks: vec![]
        }
    );
    assert_eq!(
        verify(&t).report(&p).1,
        format!(
            "Verify Local Data (MD4): ERRORS FOUND! {} Failed blocks: MD4: 0. ",
            p.display()
        )
    );
}

#[test]
fn a_changed_size_fails_every_part() {
    let dir = TempDir::new("verify-4");
    let p = dir.0.join("grown.dat");
    fs::write(&p, data(PARTSIZE as usize + 1)).unwrap();
    let t = target(&p);
    fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .unwrap()
        .write_all(b"x")
        .unwrap();
    let r = verify(&t);
    assert_eq!(
        r,
        VerifyOutcome::SizeChanged {
            on_disk: PARTSIZE + 2,
            expected: PARTSIZE + 1
        }
    );
    assert_eq!(
        r.report(&p),
        (
            true,
            format!(
                "Verify Local Data: ERRORS FOUND! {} Size on disk: {} bytes, expected: {} bytes.",
                p.display(),
                PARTSIZE + 2,
                PARTSIZE + 1
            )
        )
    );
    assert_eq!(r.record(), Some(("0,1".into(), String::new())));
}

#[test]
fn unreadable_and_empty_files_are_not_checked() {
    let dir = TempDir::new("verify-5");
    let p = dir.0.join("gone.dat");
    fs::write(&p, data(10)).unwrap();
    let t = target(&p);
    fs::remove_file(&p).unwrap();
    let r = verify(&t);
    assert!(matches!(r, VerifyOutcome::NotRead { .. }));
    assert_eq!(r.record(), None);
    assert_eq!(
        r.report(&p).1,
        format!(
            "Verify Local Data: could not read {}, so it was not checked.",
            p.display()
        )
    );

    fs::write(&p, b"").unwrap();
    let r = verify(&VerifyTarget { size: 0, ..t });
    assert_eq!(r, VerifyOutcome::Empty);
    assert_eq!(r.record(), None);
}

#[test]
fn the_encodings() {
    assert_eq!(encode_md4(&[0, 3, 12]), "0,3,12");
    let aich = vec![(1, vec![2, 5]), (4, vec![0])];
    assert_eq!(encode_aich(&aich), "1:2.5;4:0");
    assert_eq!(format_aich(&aich), "1: (2,5), 4: (0)");
}
