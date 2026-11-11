// SPDX-License-Identifier: GPL-2.0-or-later
//! part.met tests: the format rules of LoadPartFile / SavePartFile, plus the
//! pure cases of aMule's `PartMetWriterTest.cpp` (header patch, save due).

use super::*;

fn h(b: u8) -> Md4Hash {
    Md4Hash([b; 16])
}

fn sample(name: &str, size: u64) -> PartFile {
    let part_hashes: Vec<Md4Hash> = (0..part_hash_count(size))
        .map(|i| h((i % 255) as u8 + 1))
        .collect();
    let hash = if part_hashes.is_empty() {
        h(0xAA)
    } else {
        hash_of_part_hashes(&part_hashes)
    };
    PartFile {
        date: 1_700_000_000,
        hash,
        part_hashes,
        name: name.into(),
        size,
        transferred: size / 3,
        paused: true,
        down_priority: priority::HIGH,
        auto_down_priority: false,
        // aMule loads an auto priority as HIGH.
        up_priority: priority::HIGH,
        auto_up_priority: true,
        category: 2,
        last_seen_complete: 1_699_000_000,
        kad_last_publish_src: 1_700_000_100,
        kad_last_publish_notes: 0,
        dl_active_time: 3600,
        corrupted_parts: if size > PARTSIZE { vec![1, 0] } else { vec![] },
        aich_hash: Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".into()),
        all_time_transferred: (3 << 32) + 99,
        all_time_requests: 5,
        all_time_accepts: 2,
        gaps: if size > 10 {
            vec![(0, 4), (size / 2, size - 1)]
        } else {
            vec![]
        },
        other_tags: vec![Tag::new("Artist", TagValue::String("Someone".into()))],
    }
}

/// A met written the way SavePartFile writes it reads back to the same
/// download and writes back byte for byte.
#[test]
fn amule_written_met_round_trips_byte_for_byte() {
    for f in [
        sample("Sörvér ☃.mkv", 3 * PARTSIZE + 17),
        sample("tiny.txt", 100),
        sample("exact.bin", PARTSIZE),
    ] {
        let met = f.to_met();
        assert_eq!(met.version, VERSION);
        let bytes = met.write();
        let back = PartMet::read(&bytes).unwrap();
        assert_eq!(back.layout, Layout::Amule);
        assert!(!back.truncated);
        assert_eq!(back.write(), bytes);
        assert_eq!(PartFile::from_met(&back).unwrap(), f);
    }
}

#[test]
fn large_files_use_64_bit_sizes_and_gaps() {
    let f = sample("big.iso", OLD_MAX_FILE_SIZE + 10);
    let met = f.to_met();
    assert_eq!(met.version, VERSION_LARGE_FILE);
    let gap_start = met
        .tags
        .iter()
        .find(|t| t.name == TagName::Str(vec![0x09, b'0']))
        .unwrap();
    assert_eq!(gap_start.value, TagValue::U64(0));
    let back = PartMet::read(&met.write()).unwrap();
    assert_eq!(PartFile::from_met(&back).unwrap(), f);
}

#[test]
fn gap_tags_are_named_and_exclusive_as_amule_writes_them() {
    let mut f = sample("g", 1000);
    f.gaps = vec![(10, 19), (100, 999)];
    let met = f.to_met();
    let gap_tags: Vec<_> = met
        .tags
        .iter()
        .filter(|t| matches!(&t.name, TagName::Str(s) if s.len() > 1 && (s[0] == 9 || s[0] == 10)))
        .collect();
    assert_eq!(gap_tags.len(), 4);
    assert_eq!(gap_tags[0].name, TagName::Str(b"\x090".to_vec()));
    assert_eq!(gap_tags[1].name, TagName::Str(b"\x0A0".to_vec()));
    assert_eq!(
        gap_tags[1].value,
        TagValue::U32(20),
        "the end is stored exclusive"
    );
    assert_eq!(gap_tags[3].name, TagName::Str(b"\x0A1".to_vec()));
    assert_eq!(f.missing(), 10 + 900);
    assert_eq!(f.completed(), 90);
}

#[test]
fn gaps_follow_the_load_rules() {
    let mut met = sample("g", 1000).to_met();
    met.tags.retain(|t| gap_key(&t.name).is_none());
    let gap = |mark: u8, idx: &str, v: u32| {
        let mut n = vec![mark];
        n.extend_from_slice(idx.as_bytes());
        Tag::new(TagName::Str(n), TagValue::U32(v))
    };
    met.tags.extend([
        // Overlapping and adjacent gaps merge.
        gap(9, "0", 10),
        gap(10, "0", 20),
        gap(9, "1", 20),
        gap(10, "1", 30),
        gap(9, "2", 25),
        gap(10, "2", 40),
        // A gap past the end is clipped; one starting past it is dropped.
        gap(9, "3", 900),
        gap(10, "3", 5000),
        gap(9, "4", 2000),
        gap(10, "4", 3000),
        // A start without an end is dropped.
        gap(9, "5", 500),
        // An end of 0 wraps to the "unset" value and the gap is dropped.
        gap(9, "6", 600),
        gap(10, "6", 0),
        // A name whose index is not a number is just another tag.
        gap(9, "x", 1),
    ]);
    let f = PartFile::from_met(&met).unwrap();
    assert_eq!(f.gaps, vec![(10, 39), (900, 999)]);
    assert!(f
        .other_tags
        .iter()
        .any(|t| t.name == TagName::Str(b"\x09x".to_vec())));
}

#[test]
fn hashset_rules() {
    let mut f = sample("h", 2 * PARTSIZE);
    assert!(f.has_hashset());
    // A part hash set that does not hash to the file hash is not used.
    f.hash = h(0x55);
    let back = PartFile::from_met(&PartMet::read(&f.to_met().write()).unwrap()).unwrap();
    assert!(back.part_hashes.is_empty());
    assert!(
        !back.has_hashset(),
        "aMule then asks peers for the hash set"
    );
}

#[test]
fn tag_rules() {
    let mut met = sample("t", 3 * PARTSIZE).to_met();
    met.tags.retain(|t| {
        !t.name.is_id(FileTag::DlPriority.value())
            && !t.name.is_id(FileTag::OldDlPriority.value())
            && !t.name.is_id(FileTag::CorruptedParts.value())
    });
    met.tags.insert(
        0,
        Tag::new(FileTag::Filename.value(), TagValue::String(String::new())),
    );
    met.tags
        .push(Tag::new(FileTag::DlPriority.value(), TagValue::U8(9)));
    met.tags.push(Tag::new(
        FileTag::CorruptedParts.value(),
        TagValue::String("2,,7,2,x,0".into()),
    ));
    met.tags.push(Tag::new(
        FileTag::Filetype.value(),
        TagValue::String("Video".into()),
    ));
    met.tags
        .push(Tag::new(FileTag::Permissions.value(), TagValue::U32(1)));
    met.tags.push(Tag::new(0x7E, TagValue::Float(1.0)));
    let f = PartFile::from_met(&met).unwrap();
    assert_eq!(f.name, "t", "an empty first name lets the next one in");
    assert_eq!(
        (f.down_priority, f.auto_down_priority),
        (priority::NORMAL, false)
    );
    assert_eq!(
        f.corrupted_parts,
        vec![2, 0],
        "deduplicated, in range, in order"
    );
    assert!(f
        .other_tags
        .iter()
        .all(|t| !t.name.is_id(FileTag::Filetype.value())
            && !t.name.is_id(FileTag::Permissions.value())));
    // Unlike known.met, part.met keeps float tags (CanWriteToFile admits them).
    assert!(f.other_tags.iter().any(|t| t.as_float().is_some()));

    let mut bad = met.clone();
    bad.tags.push(Tag::new(
        FileTag::Status.value(),
        TagValue::String("paused".into()),
    ));
    assert_eq!(
        PartMet::read(&bad.write()),
        Err(Error::WrongType(FileTag::Status))
    );
}

#[test]
fn truncated_met_is_recovered_once_the_size_is_known() {
    let f = sample("r", 2 * PARTSIZE);
    let bytes = f.to_met().write();
    let met = PartMet::read(&bytes[..bytes.len() - 3]).unwrap();
    assert!(met.truncated);
    assert_eq!(PartFile::from_met(&met).unwrap().size, f.size);
    // Cut before the size tag: nothing to recover.
    let header = 1 + 4 + 16 + 2 + 16 * f.part_hashes.len() + 4;
    assert_eq!(PartMet::read(&bytes[..header + 5]), Err(Error::Truncated));
}

#[test]
fn version_and_size_errors() {
    assert_eq!(PartMet::read(&[]), Err(Error::Empty));
    assert_eq!(
        PartMet::read(&[0x0E, 0, 0, 0]),
        Err(Error::BadVersion(0x0E))
    );
    // The eDonkey marker check reads offset 24..28 even on a short file.
    assert_eq!(PartMet::read(&[VERSION, 0, 0]), Err(Error::Truncated));
}

/// An eDonkey "splitted" met: version 0xE1, date and hash at offset 2, then
/// tags, then a byte and the part hashes.
#[test]
fn edonkey_splitted_layout_is_imported() {
    let parts: Vec<Md4Hash> = (1..=3).map(h).collect();
    let hash = hash_of_part_hashes(&parts);
    let size = 2 * PARTSIZE + 5;
    let mut w = Writer::new();
    w.u8(VERSION_SPLITTED).u8(0xFF).u32(1234).hash(hash).u32(3);
    Tag::new(
        FileTag::Filename.value(),
        TagValue::String("imp.avi".into()),
    )
    .write_ed2k(&mut w, ed2k_codec::StrEncoding::Utf8)
    .unwrap();
    Tag::new(FileTag::Filesize.value(), TagValue::U32(size as u32))
        .write_ed2k(&mut w, ed2k_codec::StrEncoding::Utf8)
        .unwrap();
    // Priorities are ignored for imports.
    Tag::new(FileTag::DlPriority.value(), TagValue::U32(priority::HIGH))
        .write_ed2k(&mut w, ed2k_codec::StrEncoding::Utf8)
        .unwrap();
    w.u8(0);
    for p in &parts {
        w.hash(*p);
    }
    w.u8(0); // the loop stops while 16 bytes or fewer are left
    let met = PartMet::read(w.as_bytes()).unwrap();
    assert_eq!(met.layout, Layout::Splitted);
    assert_eq!(met.date, 1234);
    let f = PartFile::from_met(&met).unwrap();
    assert_eq!(f.name, "imp.avi");
    assert_eq!(f.size, size);
    assert_eq!(f.down_priority, priority::NORMAL);
    assert_eq!(f.part_hashes, parts);
    // Written back in aMule's own layout.
    let out = PartMet::read(&met.write()).unwrap();
    assert_eq!(out.layout, Layout::Amule);
    assert_eq!(PartFile::from_met(&out).unwrap().part_hashes, parts);
}

#[test]
fn hostile_counts_do_not_allocate_or_panic() {
    let mut w = Writer::new();
    w.u8(VERSION).u32(0).hash(h(1)).u16(u16::MAX);
    w.bytes(&[0; 8]);
    assert!(PartMet::read(w.as_bytes()).is_err());
    let mut w = Writer::new();
    w.u8(VERSION)
        .u32(0)
        .hash(h(1))
        .u16(0)
        .u32(u32::MAX)
        .bytes(&[0; 8]);
    assert!(PartMet::read(w.as_bytes()).is_err());
}

// --- PartMetWriterTest.cpp: the format-level cases -------------------------

/// WritesThenKeepsTheOldOneAsBackup: the .part's mtime goes into bytes 1..5,
/// little-endian, and nothing else changes.
#[test]
fn mtime_is_patched_little_endian() {
    let mut content = vec![1, 0, 0, 0, 0, 0xAB];
    patch_mtime(&mut content, 0x0403_0201).unwrap();
    assert_eq!(content, [1, 1, 2, 3, 4, 0xAB]);
}

/// RejectsAnIncompleteHeader
#[test]
fn incomplete_header_is_rejected() {
    let mut content = vec![1, 0, 0, 0];
    assert_eq!(patch_mtime(&mut content, 7), Err(IncompleteHeader));
    assert_eq!(content, [1, 0, 0, 0]);
}

fn gen(met: u64, stats: u64) -> SaveGen {
    SaveGen { met, stats }
}

#[test]
fn stats_moving_after_a_save_do_not_keep_the_state_dirty() {
    assert!(!save_due(gen(1, 9), gen(1, 5), None, false));
    assert!(save_due(gen(1, 9), gen(1, 5), None, true));
}

#[test]
fn a_state_change_is_saved_unless_a_save_carries_it() {
    assert!(save_due(gen(2, 0), gen(1, 0), None, false));
    assert!(!save_due(gen(2, 7), gen(1, 0), Some(gen(2, 3)), false));
    assert!(save_due(gen(3, 0), gen(1, 0), Some(gen(2, 0)), false));
}

#[test]
fn stats_wait_for_the_heartbeat_and_for_no_save_on_its_way() {
    assert!(!save_due(gen(1, 5), gen(1, 4), None, false));
    assert!(save_due(gen(1, 5), gen(1, 4), None, true));
    assert!(!save_due(gen(1, 5), gen(1, 4), Some(gen(1, 4)), true));
}

#[test]
fn nothing_is_due_when_clean() {
    assert!(!save_due(gen(1, 4), gen(1, 4), None, true));
}
