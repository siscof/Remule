// SPDX-License-Identifier: GPL-2.0-or-later
//! Ported from aMule's `unittests/tests/ClientMetaTrailerTest.cpp`, plus the
//! LoadList / SaveList rules and the credit ratio.

use super::*;

/// `MakeEntry`
fn make_entry(seed: u8, name: &str) -> MetaEntry {
    let mut key = [0u8; 16];
    for (i, k) in key.iter_mut().enumerate() {
        *k = seed + i as u8;
    }
    MetaEntry {
        key: Md4Hash(key),
        meta: ClientMeta {
            name: name.into(),
            mod_version: if seed == 1 {
                "AI v1.6".into()
            } else {
                String::new()
            },
            first_seen: 0x1111_1111u32.wrapping_mul(u32::from(seed)),
            sessions: u32::from(seed) + 1,
            last_ip: 0x0100_007f + u32::from(seed),
            last_port: 4662 + u16::from(seed),
            kad_port: 4672 + u16::from(seed),
            version: 0x0003_0100 + u32::from(seed),
            client_soft: seed,
            source_from: seed + 2,
            obfuscation: seed + 3,
        },
    }
}

fn written(entries: &[MetaEntry]) -> Vec<u8> {
    let mut w = Writer::new();
    write_trailer(&mut w, entries);
    w.into_bytes()
}

#[test]
fn entries_survive_a_round_trip() {
    let saved = vec![make_entry(1, "peer"), make_entry(2, "péër")];
    assert_eq!(read_trailer(&written(&saved)), TrailerRead::Ok(saved));
}

#[test]
fn layout_matches_version_two() {
    let expected = concat!(
        "414d554c454d4431",                 // magic
        "02",                               // trailer version
        "01000000",                         // entry count
        "0102030405060708090a0b0c0d0e0f10", // key
        "11111111",                         // firstSeen
        "02000000",                         // sessions
        "80000001",                         // lastIP
        "3712",                             // lastPort 4663
        "4112",                             // kadPort 4673
        "01010300",                         // version
        "01",                               // clientSoft
        "03",                               // sourceFrom
        "04",                               // obfuscation
        "02006162",                         // name "ab"
        "070041492076312e36",               // mod "AI v1.6"
    );
    let hex: String = written(&[make_entry(1, "ab")])
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, expected);
}

#[test]
fn no_entries_write_nothing() {
    assert!(written(&[]).is_empty());
}

#[test]
fn long_names_and_mods_are_capped_in_characters() {
    let long: String = "é".repeat(100);
    let mut e = make_entry(1, &long);
    e.meta.mod_version = long.clone();
    let TrailerRead::Ok(loaded) = read_trailer(&written(&[e])) else {
        panic!("not ok")
    };
    let capped: String = long.chars().take(64).collect();
    assert_eq!(loaded[0].meta.name, capped);
    assert_eq!(loaded[0].meta.mod_version, capped);
}

#[test]
fn a_file_from_an_older_build_has_no_trailer() {
    assert_eq!(read_trailer(&[]), TrailerRead::Absent);
    assert_eq!(
        read_trailer(&[b'A'; 12]),
        TrailerRead::Absent,
        "shorter than magic, version and count"
    );
}

#[test]
fn other_trailing_data_is_not_a_block() {
    let mut tail = written(&[make_entry(1, "peer")]);
    tail[0] = b'X';
    assert_eq!(read_trailer(&tail), TrailerRead::Foreign);
}

#[test]
fn a_block_from_a_newer_version_is_left_alone() {
    let mut tail = written(&[make_entry(1, "peer")]);
    tail[8] = 3;
    let r = read_trailer(&tail);
    assert_eq!(r, TrailerRead::OtherVersion(3));
    assert!(r.entries().is_empty());
}

#[test]
fn a_truncated_block_keeps_the_complete_entries() {
    let saved = vec![make_entry(1, "first"), make_entry(2, "second")];
    let mut tail = written(&saved);
    tail.truncate(tail.len() - 3);
    assert_eq!(
        read_trailer(&tail),
        TrailerRead::Damaged(vec![saved[0].clone()])
    );
}

#[test]
fn reads_version_one_without_a_mod() {
    let mut tail = vec![
        b'A', b'M', b'U', b'L', b'E', b'M', b'D', b'1', 1, 2, 0, 0, 0,
    ];
    for i in 0..2u8 {
        // key (16), fixed fields (23), nickname length (2), nickname (2)
        let mut rec = vec![0u8; 43];
        rec[0] = i + 1;
        rec[39] = 2;
        rec[41] = b'a';
        rec[42] = b'b';
        tail.extend(rec);
    }
    let TrailerRead::Ok(loaded) = read_trailer(&tail) else {
        panic!("not ok")
    };
    assert_eq!(loaded.len(), 2);
    assert!(loaded
        .iter()
        .all(|e| e.meta.name == "ab" && e.meta.mod_version.is_empty()));
}

fn record(seed: u8, up: u64, down: u64, last_seen: u32) -> CreditRecord {
    let mut r = CreditRecord::new(Md4Hash([seed; 16]));
    r.uploaded = up;
    r.downloaded = down;
    r.last_seen = last_seen;
    r
}

#[test]
fn record_layout_is_119_bytes_and_splits_64_bit_totals() {
    let mut r = record(7, 0x1_0000_0002, 0x3_0000_0004, 0x0506_0708);
    r.reserved = 0x0A0B;
    r.key_size = 3;
    r.secure_ident[..3].copy_from_slice(&[9, 9, 9]);
    r.secure_ident[79] = 0xEE; // garbage past the key is kept
    let m = ClientsMet {
        records: vec![r.clone()],
        trailing: vec![],
    };
    let bytes = m.write();
    assert_eq!(RECORD_LEN, 119);
    assert_eq!(bytes.len(), 5 + 119);
    assert_eq!(&bytes[..5], [VERSION, 1, 0, 0, 0]);
    assert_eq!(&bytes[5..21], [7; 16]);
    // up lo, down lo, last seen, up hi, down hi
    assert_eq!(
        &bytes[21..41],
        [2, 0, 0, 0, 4, 0, 0, 0, 8, 7, 6, 5, 1, 0, 0, 0, 3, 0, 0, 0]
    );
    assert_eq!(&bytes[41..44], [0x0B, 0x0A, 3]);
    let back = ClientsMet::read(&bytes).unwrap();
    assert_eq!(back.records[0], r);
    assert_eq!(back.records[0].public_key(), [9, 9, 9]);
}

#[test]
fn file_with_trailer_round_trips_byte_for_byte() {
    let recs = vec![
        record(1, 100, 0, 1_700_000_000),
        record(2, 0, 5_000_000, 1_700_000_001),
    ];
    let meta = vec![MetaEntry {
        key: Md4Hash([1; 16]),
        ..make_entry(1, "peer")
    }];
    let saved = ClientsMet::save(&recs, &meta);
    let bytes = saved.write();
    let back = ClientsMet::read(&bytes).unwrap();
    assert_eq!(back.write(), bytes);
    assert_eq!(back.records, recs);
    assert_eq!(back.trailer().entries(), &meta[..]);
}

#[test]
fn save_writes_only_traffic_and_matching_populated_meta() {
    let recs = vec![record(1, 1, 0, 5), record(2, 0, 0, 5), record(3, 0, 1, 5)];
    let mut unpopulated = make_entry(3, "x");
    unpopulated.key = Md4Hash([3; 16]);
    unpopulated.meta.first_seen = 0;
    let meta = vec![
        MetaEntry {
            key: Md4Hash([1; 16]),
            ..make_entry(1, "kept")
        },
        MetaEntry {
            key: Md4Hash([2; 16]),
            ..make_entry(2, "no traffic, dropped")
        },
        unpopulated,
    ];
    let m = ClientsMet::save(&recs, &meta);
    assert_eq!(
        m.records.iter().map(|r| r.key.0[0]).collect::<Vec<_>>(),
        [1, 3]
    );
    let entries = m.trailer();
    assert_eq!(entries.entries().len(), 1);
    assert_eq!(entries.entries()[0].meta.name, "kept");
    // No populated metadata: no trailer at all.
    assert!(ClientsMet::save(&recs, &[]).trailing.is_empty());
}

#[test]
fn load_rules() {
    // Outdated version: nothing loaded.
    assert_eq!(
        ClientsMet::read(&[0x11, 0, 0, 0, 0]).unwrap_err().kind,
        ErrorKind::Outdated(0x11)
    );
    // A key size over 80 discards the whole file.
    let mut bad = record(1, 1, 1, 1);
    bad.key_size = 81;
    let bytes = ClientsMet {
        records: vec![record(2, 1, 1, 1), bad],
        trailing: vec![],
    }
    .write();
    let err = ClientsMet::read(&bytes).unwrap_err();
    assert_eq!(
        err.kind,
        ErrorKind::BadKeySize {
            record: 1,
            size: 81
        }
    );
    assert!(err.salvaged.is_empty());
    // Truncation keeps the complete records before it.
    let bytes = ClientsMet {
        records: vec![record(1, 1, 1, 1), record(2, 1, 1, 1)],
        trailing: vec![],
    }
    .write();
    let err = ClientsMet::read(&bytes[..bytes.len() - 10]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
    assert_eq!(err.salvaged.len(), 1);
    // A count larger than the file does not allocate or panic.
    assert_eq!(
        ClientsMet::read(&[VERSION, 0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap_err()
            .kind,
        ErrorKind::Truncated
    );
}

#[test]
fn expiry_is_150_days() {
    let now = 1_700_000_000;
    let m = ClientsMet {
        records: vec![
            record(1, 1, 1, now - EXPIRY_SECS - 1),
            record(2, 1, 1, now - EXPIRY_SECS),
            record(3, 1, 1, now),
        ],
        trailing: vec![],
    };
    assert_eq!(m.live(now).map(|r| r.key.0[0]).collect::<Vec<_>>(), [2, 3]);
}

#[test]
fn credit_ratio_follows_get_credit_ratio() {
    // Under 1 MB downloaded: 1.
    assert_eq!(record(1, 0, 999_999, 0).credit_ratio(), 1.0);
    // Nothing uploaded: 10, bounded by sqrt(MB + 2).
    let r = record(1, 0, 1_000_000, 0);
    assert_eq!(
        r.credit_ratio(),
        ((1_000_000f64 / 1_048_576.0) + 2.0).sqrt() as f32
    );
    assert_eq!(record(1, 0, 200 * 1_048_576, 0).credit_ratio(), 10.0);
    // 2 * down / up, when below the bound.
    assert_eq!(
        record(1, 100 * 1_048_576, 100 * 1_048_576, 0).credit_ratio(),
        2.0
    );
    // Never below 1.
    assert_eq!(record(1, 1 << 40, 2_000_000, 0).credit_ratio(), 1.0);
}
