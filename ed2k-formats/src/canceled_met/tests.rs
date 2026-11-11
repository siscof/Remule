// SPDX-License-Identifier: GPL-2.0-or-later
//! canceled.met tests, from the rules in HashListFile.cpp (aMule has only
//! daemon-level integration tests for this file).

use super::*;

fn h(b: u8) -> Md4Hash {
    Md4Hash([b; 16])
}

fn file(version: u8, count: u32, hashes: &[Md4Hash]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(version).u32(count);
    for x in hashes {
        w.hash(*x);
    }
    w.into_bytes()
}

/// What `Save` writes: version, count, sorted hashes, and it reads back.
#[test]
fn amule_written_file_round_trips_byte_for_byte() {
    let set: BTreeSet<Md4Hash> = [h(3), h(1), h(0xFE)].into();
    let met = CanceledMet::from_set(&set);
    let bytes = met.write();
    assert_eq!(
        bytes,
        file(VERSION, 3, &[h(1), h(3), h(0xFE)]),
        "sorted, as std::set"
    );
    let back = CanceledMet::read(&bytes).unwrap();
    assert_eq!(back, met);
    assert_eq!(back.write(), bytes);
    assert_eq!(back.set(), set);
}

#[test]
fn empty_list() {
    let bytes = [VERSION, 0, 0, 0, 0];
    let met = CanceledMet::read(&bytes).unwrap();
    assert!(met.hashes.is_empty());
    assert_eq!(met.write(), bytes);
    assert_eq!(CanceledMet::from_set(&BTreeSet::new()).write(), bytes);
}

#[test]
fn load_drops_empty_hashes_and_duplicates_but_keeps_them_stored() {
    let bytes = file(VERSION, 4, &[h(2), Md4Hash::EMPTY, h(2), h(1)]);
    let met = CanceledMet::read(&bytes).unwrap();
    assert_eq!(met.hashes.len(), 4);
    assert_eq!(met.set(), [h(1), h(2)].into());
    assert_eq!(met.write(), bytes, "stored order and duplicates survive");
    assert!(met.contains(&h(2)));
    assert!(
        !met.contains(&Md4Hash::EMPTY),
        "the empty hash is never contained"
    );
    assert!(!met.contains(&h(9)));
}

#[test]
fn bad_version_is_refused() {
    let err = CanceledMet::read(&file(0x20, 1, &[h(1)])).unwrap_err();
    assert_eq!(err.kind, ErrorKind::BadVersion(0x20));
    assert!(err.salvaged.is_empty());
}

#[test]
fn truncation_keeps_the_hashes_before_it() {
    let full = file(VERSION, 3, &[h(1), h(2), h(3)]);
    let err = CanceledMet::read(&full[..full.len() - 1]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
    assert_eq!(err.salvaged, [h(1), h(2)].into());
    assert_eq!(
        CanceledMet::read(&[]).unwrap_err().kind,
        ErrorKind::Truncated
    );
    assert_eq!(
        CanceledMet::read(&[VERSION, 1, 0]).unwrap_err().kind,
        ErrorKind::Truncated
    );
}

#[test]
fn trailing_bytes_are_ignored_like_amule_and_kept() {
    let mut bytes = file(VERSION, 1, &[h(7)]);
    bytes.extend_from_slice(b"junk");
    let met = CanceledMet::read(&bytes).unwrap();
    assert_eq!(met.set(), [h(7)].into());
    assert_eq!(met.trailing, b"junk");
    assert_eq!(met.write(), bytes);
}

#[test]
fn hostile_count_does_not_allocate_or_panic() {
    let err = CanceledMet::read(&file(VERSION, u32::MAX, &[h(1)])).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
    assert_eq!(err.salvaged, [h(1)].into());
}
