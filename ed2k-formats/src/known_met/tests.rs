// SPDX-License-Identifier: GPL-2.0-or-later
//! known.met tests, from the rules in KnownFile.cpp / KnownFileList.cpp (aMule
//! has no unit test for this file).

use super::*;

/// RFC 1320 test vectors, so the MD4 used for hash sets is the real one.
#[test]
fn md4_matches_rfc_1320() {
    let md4 = |s: &[u8]| -> String { Md4::digest(s).iter().map(|b| format!("{b:02x}")).collect() };
    assert_eq!(md4(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(md4(b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
    assert_eq!(md4(b"message digest"), "d9130a8164549fe818874806e1c7014b");
}

#[test]
fn part_hash_counts() {
    assert_eq!(part_hash_count(0), 0);
    assert_eq!(
        part_hash_count(PARTSIZE - 1),
        0,
        "a single part needs no part hashes"
    );
    // The eD2k quirk: an exact multiple has an extra, empty last part.
    assert_eq!(part_hash_count(PARTSIZE), 2);
    assert_eq!(part_hash_count(PARTSIZE + 1), 2);
    assert_eq!(part_hash_count(3 * PARTSIZE), 4);
}

fn h(b: u8) -> Md4Hash {
    Md4Hash([b; 16])
}

/// A file of `parts` full parts plus a tail, with a consistent hash set.
fn sample(name: &str, size: u64) -> KnownFile {
    let part_hashes: Vec<Md4Hash> = (0..part_hash_count(size))
        .map(|i| h((i % 255) as u8 + 1))
        .collect();
    let hash = if part_hashes.is_empty() {
        h(0xAA)
    } else {
        hash_of_part_hashes(&part_hashes)
    };
    KnownFile {
        date: 1_700_000_000,
        hash,
        part_hashes,
        name: name.into(),
        size,
        all_time_transferred: (7 << 32) + 12345,
        all_time_requests: 40,
        all_time_accepts: 12,
        up_priority: priority::HIGH,
        auto_priority: true,
        aich_hash: Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".into()),
        kad_last_publish_src: 1_700_000_100,
        kad_last_publish_notes: 0,
        last_seen: 1_700_000_200,
        last_uploaded: 1_700_000_300,
        shared_since: 1_600_000_000,
        verify_date: 1_700_000_400,
        verify_corrupt_md4: "1,3".into(),
        verify_corrupt_aich: String::new(),
        other_tags: vec![
            Tag::new("Artist", TagValue::String("Someone".into())),
            Tag::new(0x7E, TagValue::U32(9)),
        ],
    }
}

fn met(files: &[KnownFile]) -> KnownMet {
    let mut m = KnownMet {
        version: VERSION,
        records: files.iter().map(KnownFile::to_record).collect(),
        skipped: vec![],
    };
    m.version = m.canonical_version();
    m
}

/// A file written the way `WriteToFile` writes it reads back to the same
/// files and writes back byte for byte.
#[test]
fn amule_written_file_round_trips_byte_for_byte() {
    let files = [
        sample("small.txt", 1000),
        sample("Sörvér – ünicode ☃.mkv", 3 * PARTSIZE + 17),
        sample("exact.bin", PARTSIZE),
    ];
    let m = met(&files);
    assert_eq!(m.version, VERSION, "no file over 4 GB");
    let bytes = m.write();
    let back = KnownMet::read(&bytes).unwrap();
    assert!(back.skipped.is_empty());
    assert_eq!(back.write(), bytes);
    for (rec, want) in back.records.iter().zip(&files) {
        assert_eq!(&KnownFile::from_record(rec).unwrap(), want);
    }
}

#[test]
fn large_files_use_a_u64_size_and_the_large_header() {
    let big = sample("big.iso", OLD_MAX_FILE_SIZE + 1);
    let m = met(std::slice::from_ref(&big));
    assert_eq!(m.version, VERSION_LARGE_FILES);
    let rec = &m.records[0];
    let size_tag = rec
        .tags
        .iter()
        .find(|t| t.name.is_id(FileTag::Filesize.value()))
        .unwrap();
    assert_eq!(size_tag.value, TagValue::U64(big.size));
    let back = KnownMet::read(&m.write()).unwrap();
    assert_eq!(
        KnownFile::from_record(&back.records[0]).unwrap().size,
        big.size
    );
}

#[test]
fn bad_records_are_skipped_and_loading_goes_on() {
    let good = sample("good", 2 * PARTSIZE);
    let mut wrong_hash = sample("wrong hash", 2 * PARTSIZE);
    wrong_hash.hash = h(0x55);
    let mut wrong_count = sample("wrong count", 2 * PARTSIZE);
    wrong_count.part_hashes.pop();
    wrong_count.hash = hash_of_part_hashes(&wrong_count.part_hashes);
    // A small file with a part hash it should not have.
    let mut extra = sample("extra", 10);
    extra.part_hashes = vec![h(1)];

    let m = KnownMet {
        version: VERSION,
        records: [&good, &wrong_hash, &wrong_count, &extra]
            .map(KnownFile::to_record)
            .to_vec(),
        skipped: vec![],
    };
    let back = KnownMet::read(&m.write()).unwrap();
    assert_eq!(back.records.len(), 1);
    assert_eq!(
        KnownFile::from_record(&back.records[0]).unwrap().name,
        "good"
    );
    assert_eq!(
        back.skipped,
        vec![
            (1, Invalid::HashsetMismatch),
            (
                2,
                Invalid::PartCount {
                    expected: 3,
                    found: 2
                }
            ),
            (
                3,
                Invalid::PartCount {
                    expected: 0,
                    found: 1
                }
            ),
        ]
    );
}

#[test]
fn damage_stops_the_load_but_keeps_earlier_files() {
    let m = met(&[sample("one", 100), sample("two", 200)]);
    let bytes = m.write();
    let err = KnownMet::read(&bytes[..bytes.len() - 3]).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Tag(_)));
    assert_eq!(err.salvaged.len(), 1);

    // A known tag with the wrong type: GetInt() throws in the C++.
    let mut rec = sample("typed", 100).to_record();
    rec.tags.push(Tag::new(
        FileTag::AtRequested.value(),
        TagValue::String("many".into()),
    ));
    let bad = KnownMet {
        version: VERSION,
        records: vec![sample("first", 1).to_record(), rec],
        skipped: vec![],
    };
    let err = KnownMet::read(&bad.write()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongType(FileTag::AtRequested));
    assert_eq!(err.salvaged.len(), 1);

    assert_eq!(
        KnownMet::read(&[0x0D, 0, 0, 0, 0]).unwrap_err().kind,
        ErrorKind::BadVersion(0x0D)
    );
}

#[test]
fn tag_rules_follow_load_tags_from_file() {
    let univ_bytes = "naïve.txt";
    let rec = KnownRecord {
        date: 5,
        hash: h(9),
        part_hashes: vec![],
        tags: vec![
            // The universal name is the UTF-8 bytes one per character.
            Tag::new(FileTag::Filename.value(), TagValue::String("first".into())),
            Tag::new(
                FileTag::Filename.value(),
                TagValue::String(univ_bytes.bytes().map(char::from).collect()),
            ),
            Tag::new(FileTag::Filesize.value(), TagValue::U32(10)),
            // eMule's high half of a large size is combined (aMule ignores it).
            Tag::new(FileTag::FilesizeHi.value(), TagValue::U32(1)),
            // An out-of-range priority becomes normal.
            Tag::new(FileTag::UlPriority.value(), TagValue::U8(9)),
            // A malformed AICH hash is ignored.
            Tag::new(FileTag::AichHash.value(), TagValue::String("nope".into())),
            // Old tags are purged; unknown ones kept.
            Tag::new(FileTag::Permissions.value(), TagValue::U32(1)),
            Tag::new(FileTag::KadLastPublishKey.value(), TagValue::U32(1)),
            Tag::new(
                FileTag::PartFilename.value(),
                TagValue::String("x.part".into()),
            ),
            Tag::new(0x7E, TagValue::Float(1.5)),
            // A corrupt list without a date is an orphan and dropped.
            Tag::new(
                FileTag::VerifyCorruptMd4.value(),
                TagValue::String("2".into()),
            ),
        ],
    };
    let f = KnownFile::from_record(&rec).unwrap();
    assert_eq!(f.name, "naïve.txt");
    assert_eq!(f.size, (1 << 32) | 10);
    assert_eq!((f.up_priority, f.auto_priority), (priority::NORMAL, false));
    assert_eq!(f.aich_hash, None);
    assert_eq!(f.other_tags, vec![Tag::new(0x7E, TagValue::Float(1.5))]);
    assert_eq!(f.verify_corrupt_md4, "");
    assert_eq!(f.last_seen, 5, "falls back to the date");
    // A float tag is not written back (old eMules mishandle them).
    assert!(f.to_record().tags.iter().all(|t| t.as_float().is_none()));

    // A universal name that does not decode leaves the first name.
    let mut rec2 = rec.clone();
    rec2.tags[1] = Tag::new(
        FileTag::Filename.value(),
        TagValue::String("\u{FF}\u{FE}".into()),
    );
    assert_eq!(KnownFile::from_record(&rec2).unwrap().name, "first");
}

#[test]
fn hostile_counts_do_not_allocate_or_panic() {
    let mut w = Writer::new();
    w.u8(VERSION).u32(1).u32(0).hash(h(1)).u16(u16::MAX);
    assert!(KnownMet::read(w.as_bytes()).is_err());
    let mut w = Writer::new();
    w.u8(VERSION).u32(1).u32(0).hash(h(1)).u16(0).u32(u32::MAX);
    assert!(KnownMet::read(w.as_bytes()).is_err());
    assert!(KnownMet::read(&[VERSION, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}
