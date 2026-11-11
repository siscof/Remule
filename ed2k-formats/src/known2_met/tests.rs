// SPDX-License-Identifier: GPL-2.0-or-later
//! known2_64.met tests, from the rules in SHAHashSet.cpp and ThreadTasks.cpp
//! (aMule's own tests for this file are Python integration tests that need a
//! running daemon).

use super::*;

fn h(b: u8) -> AichHash {
    AichHash([b; HASH_LEN])
}

fn set(root: u8, blocks: usize) -> AichHashSet {
    AichHashSet {
        root: h(root),
        block_hashes: (0..blocks).map(|i| h(i as u8)).collect(),
    }
}

#[test]
fn base32_matches_the_known_encoding() {
    // SHA-1("abc"), as it appears in magnet links.
    let sha1_abc = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2,
        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];
    let a = AichHash(sha1_abc);
    assert_eq!(a.to_string(), "VGMT4NSHA2AWVOR6EVYXQUGCNSONBWE5");
    assert_eq!("VGMT4NSHA2AWVOR6EVYXQUGCNSONBWE5".parse(), Ok(a));
    assert_eq!(
        "vgmt4nsha2awvor6evyxqugcnsonbwe5".parse(),
        Ok(a),
        "DecodeBase32 accepts lower case"
    );
    assert_eq!(h(0).to_string(), "A".repeat(32));
    assert_eq!(h(0xFF).to_string(), "7".repeat(32));
    assert_eq!("A".repeat(31).parse::<AichHash>(), Err(ParseAichHashError));
    assert_eq!(
        format!("{}1", "A".repeat(31)).parse::<AichHash>(),
        Err(ParseAichHashError)
    );
    for b in [0u8, 1, 0x5A, 0xA5, 0xFF] {
        let x = AichHash(std::array::from_fn(|i| b.wrapping_mul(i as u8 + 3)));
        assert_eq!(x.to_string().parse(), Ok(x));
    }
}

#[test]
fn block_hash_counts() {
    let bs = u64::from(EMBLOCKSIZE);
    assert_eq!(block_hash_count(0), 0);
    assert_eq!(block_hash_count(1), 1);
    assert_eq!(block_hash_count(bs), 1);
    assert_eq!(block_hash_count(bs + 1), 2);
    // 9728000 / 184320 = 52.77: 53 blocks per part, the last one short.
    assert_eq!(block_hash_count(PARTSIZE), 53);
    assert_eq!(block_hash_count(PARTSIZE + 1), 54);
    assert_eq!(block_hash_count(2 * PARTSIZE), 106);
    assert!(set(1, 53).fits_size(PARTSIZE));
    assert!(!set(1, 52).fits_size(PARTSIZE));
}

#[test]
fn file_round_trips_byte_for_byte() {
    let m = Known2Met {
        sets: vec![set(1, 0), set(2, 53), set(3, 3)],
    };
    let bytes = m.write();
    assert_eq!(bytes[0], VERSION);
    assert_eq!(
        bytes.len(),
        1 + (20 + 4) * 3 + 20 * (53 + 3),
        "SaveHashSet's size check"
    );
    let back = Known2Met::read(&bytes).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.write(), bytes);
    // Appending an entry's bytes to the file is the same as writing the longer list.
    let mut appended = bytes.clone();
    appended.extend(Known2Met::entry_bytes(&set(4, 2)));
    let mut longer = m.clone();
    assert!(longer.append(set(4, 2)));
    assert_eq!(longer.write(), appended);
}

#[test]
fn layout_is_root_count_hashes() {
    let bytes = Known2Met {
        sets: vec![set(0xAB, 2)],
    }
    .write();
    assert_eq!(&bytes[1..21], &[0xAB; 20]);
    assert_eq!(&bytes[21..25], &2u32.to_le_bytes());
    assert_eq!(&bytes[25..45], &[0; 20]);
    assert_eq!(&bytes[45..65], &[1; 20]);
}

#[test]
fn empty_and_header_only_files() {
    assert_eq!(Known2Met::read(&[]).unwrap(), Known2Met::default());
    assert_eq!(Known2Met::read(&[VERSION]).unwrap(), Known2Met::default());
    assert_eq!(Known2Met::default().write(), vec![VERSION]);
}

#[test]
fn bad_header_is_truncated_to_nothing() {
    let err = Known2Met::read(&[0x01, 0, 0]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::BadVersion(0x01));
    assert_eq!(err.valid_len, 0);
    assert!(err.salvaged.is_empty());
}

#[test]
fn truncated_entry_keeps_the_complete_ones() {
    let m = Known2Met {
        sets: vec![set(1, 2), set(2, 5)],
    };
    let bytes = m.write();
    let first_end = 1 + 24 + 2 * 20;
    for cut in [bytes.len() - 1, first_end + 10, first_end + 23] {
        let err = Known2Met::read(&bytes[..cut]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Truncated, "cut at {cut}");
        assert_eq!(err.salvaged, vec![set(1, 2)]);
        assert_eq!(
            err.valid_len, first_end as u64,
            "aMule truncates after the last whole entry"
        );
    }
    // Damage inside the first entry: aMule's truncation point is still 0.
    let err = Known2Met::read(&bytes[..30]).unwrap_err();
    assert!(err.salvaged.is_empty());
    assert_eq!(err.valid_len, 0);
}

#[test]
fn hostile_count_does_not_allocate() {
    let mut w = Writer::new();
    w.u8(VERSION).bytes(&[7; 20]).u32(u32::MAX);
    let err = Known2Met::read(w.as_bytes()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
}

#[test]
fn find_append_and_prune() {
    let mut m = Known2Met {
        sets: vec![set(1, 1), set(2, 2)],
    };
    // A hand-edited file may repeat a root: the first wins.
    m.sets.push(AichHashSet {
        root: h(1),
        block_hashes: vec![h(9)],
    });
    assert_eq!(m.find(&h(1)).unwrap().block_hashes, vec![h(0)]);
    assert!(m.find(&h(7)).is_none());
    // SaveHashSet skips a root it already has.
    assert!(!m.append(set(2, 9)));
    assert!(m.append(set(3, 1)));
    assert_eq!(m.sets.len(), 4);

    // An empty live set prunes nothing.
    assert_eq!(m.prune_orphans(&HashSet::new()), 0);
    assert_eq!(m.sets.len(), 4);
    let live: HashSet<AichHash> = [h(1), h(3)].into();
    assert_eq!(m.prune_orphans(&live), 1);
    assert!(m.sets.iter().all(|s| live.contains(&s.root)));
}

/// The old format: no header, `u16` counts.
fn old_file(sets: &[AichHashSet]) -> Vec<u8> {
    let mut w = Writer::new();
    for s in sets {
        w.bytes(&s.root.0).u16(s.block_hashes.len() as u16);
        for b in &s.block_hashes {
            w.bytes(&b.0);
        }
    }
    w.into_bytes()
}

#[test]
fn old_known2_converts_every_entry() {
    let sets: Vec<AichHashSet> = (0..12).map(|i| set(i, 0)).collect();
    let old = old_file(&sets);
    // aMule's loop stops once 1 + new bytes (2 more per entry) reach the old
    // length: with twelve empty entries it would drop the last one.
    let converted = convert_old_known2(&old).unwrap();
    assert_eq!(converted.sets, sets);
    // The converted file is the new format.
    assert_eq!(Known2Met::read(&converted.write()).unwrap(), converted);

    let mixed = vec![set(1, 53), set(2, 3)];
    assert_eq!(convert_old_known2(&old_file(&mixed)).unwrap().sets, mixed);

    let damaged = old_file(&mixed);
    let err = convert_old_known2(&damaged[..damaged.len() - 5]).unwrap_err();
    assert_eq!(err.salvaged, vec![set(1, 53)]);
    assert_eq!(convert_old_known2(&[]).unwrap(), Known2Met::default());
}
