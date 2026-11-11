// SPDX-License-Identifier: GPL-2.0-or-later
//! Ported from aMule's `unittests/tests/CTagTest.cpp` (same packets), plus
//! the eD2k writer and the error paths.

use super::*;
use ed2k_types::tags::{kad, FileTag};

fn read_list(packet: &[u8]) -> Vec<Tag> {
    let mut r = Reader::new(packet);
    let tags = read_kad_list(&mut r, true).unwrap();
    assert!(r.is_eof(), "the whole packet is consumed");
    tags
}

/// `test_taglist_serialization`: writing the list back gives the packet.
fn assert_round_trip(tags: &[Tag], packet: &[u8]) {
    let mut w = Writer::new();
    write_kad_list(&mut w, tags).unwrap();
    assert_eq!(w.as_bytes(), packet);
}

fn check(tag: &Tag, name: &[u8], value: TagValue) {
    assert!(tag.name.is(name), "name {:?} != {name:?}", tag.name);
    assert_eq!(tag.value, value);
}

#[test]
fn read_tag_list_1() {
    let mut p = vec![0x07, 0x02, 0x01, 0x00, 0x01, 0x22, 0x00];
    p.extend_from_slice("Gem Boy - Sarà perchè ti amo.mp3".as_bytes());
    p.extend_from_slice(&[0x03, 0x01, 0x00, 0x02, 0x1d, 0x6f, 0x1f, 0x00]);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0x15, 0x01]);
    p.extend_from_slice(&[
        0x02, 0x01, 0x00, 0x03, 0x05, 0x00, 0x41, 0x75, 0x64, 0x69, 0x6f,
    ]);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0xd3, 0x6b]);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0xd4, 0x9a]);
    p.extend_from_slice(&[0x03, 0x01, 0x00, 0x33, 0x2f, 0x00, 0x01, 0x01]);
    let t = read_list(&p);
    assert_eq!(t.len(), 7);
    check(
        &t[0],
        kad::FILENAME,
        TagValue::String("Gem Boy - Sarà perchè ti amo.mp3".into()),
    );
    check(&t[1], kad::FILESIZE, TagValue::U32(2_060_061));
    check(&t[2], kad::SOURCES, TagValue::U8(1));
    check(&t[3], kad::FILETYPE, TagValue::String("Audio".into()));
    check(&t[4], kad::MEDIA_LENGTH, TagValue::U8(107));
    check(&t[5], kad::MEDIA_BITRATE, TagValue::U8(154));
    check(&t[6], kad::PUBLISHINFO, TagValue::U32(16_842_799));
    assert_round_trip(&t, &p);
}

#[test]
fn read_tag_list_2() {
    let name = "Serialization Test File 1893-€€èéçàù§.txt";
    let mut p = vec![0x05, 0x02, 0x01, 0x00, 0x01, 0x33, 0x00];
    p.extend_from_slice(name.as_bytes());
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0x02, 0x0d]);
    p.extend_from_slice(&[0x09, 0x01, 0x00, 0x15, 0x00]);
    p.extend_from_slice(&[0x02, 0x01, 0x00, 0x03, 0x03, 0x00, 0x44, 0x6f, 0x63]);
    p.extend_from_slice(&[0x03, 0x01, 0x00, 0x33, 0xe8, 0x03, 0x01, 0x01]);
    assert_eq!(name.len(), 0x33);
    let t = read_list(&p);
    check(&t[0], kad::FILENAME, TagValue::String(name.into()));
    check(&t[1], kad::FILESIZE, TagValue::U8(13));
    check(&t[2], kad::SOURCES, TagValue::U8(0));
    check(&t[3], kad::FILETYPE, TagValue::String("Doc".into()));
    check(&t[4], kad::PUBLISHINFO, TagValue::U32(16_843_752));
    assert_round_trip(&t, &p);
}

#[test]
fn kad_float() {
    let p = [
        0x02, 0x04, 0x01, 0x00, 0xFF, 0x79, 0xe9, 0xf6, 0x42, 0x04, 0x01, 0x00, 0xFF, 0x79, 0xd9,
        0xd6, 0x42,
    ];
    let t = read_list(&p);
    check(&t[0], kad::SOURCETYPE, TagValue::Float(123.456));
    check(&t[1], kad::SOURCETYPE, TagValue::Float(107.424_75));
    assert_round_trip(&t, &p);
}

#[test]
fn kad_hash() {
    let mut p = vec![0x01, 0x01, 0x01, 0x00, 0xFF];
    p.extend(0u8..16);
    let t = read_list(&p);
    check(
        &t[0],
        kad::SOURCETYPE,
        TagValue::Hash("000102030405060708090A0B0C0D0E0F".parse().unwrap()),
    );
    assert_round_trip(&t, &p);
}

/// `check_single_kad_tag`: read one tag, then write it back byte for byte.
fn single(p: &[u8], name: &[u8], value: TagValue) {
    let mut r = Reader::new(p);
    let t = Tag::read_kad(&mut r, true).unwrap();
    check(&t, name, value);
    assert!(r.is_eof());
    let mut w = Writer::new();
    t.write_kad(&mut w).unwrap();
    assert_eq!(w.as_bytes(), p);
}

#[test]
fn kad_bsob_and_integers() {
    single(
        &[0x0A, 0x01, 0x00, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04],
        kad::FILESIZE,
        TagValue::Bsob(vec![1, 2, 3, 4]),
    );
    single(
        &[
            0x0b, 0x01, 0x00, 0x02, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
        ],
        kad::FILESIZE,
        TagValue::U64(0x2322_2120_1312_1110),
    );
    single(
        &[0x03, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78],
        kad::FILESIZE,
        TagValue::U32(0x7856_3412),
    );
    single(
        &[0x08, 0x01, 0x00, 0x02, 0x12, 0x34],
        kad::FILESIZE,
        TagValue::U16(0x3412),
    );
    single(
        &[0x09, 0x01, 0x00, 0x02, 0x12],
        kad::FILESIZE,
        TagValue::U8(0x12),
    );
}

#[test]
fn read_integers() {
    let one = [
        &[0x03, 0x01, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78][..],
        &[0x08, 0x01, 0x00, 0x02, 0x12, 0x34],
        &[0x09, 0x01, 0x00, 0x02, 0x12],
        &[
            0x0b, 0x01, 0x00, 0x02, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
        ],
    ]
    .concat();
    let p = [&[0x08][..], &one, &one].concat();
    let t = read_list(&p);
    let expect = [
        TagValue::U32(0x7856_3412),
        TagValue::U16(0x3412),
        TagValue::U8(0x12),
        TagValue::U64(0x2322_2120_1312_1110),
    ];
    for (i, tag) in t.iter().enumerate() {
        check(tag, kad::FILESIZE, expect[i % 4].clone());
    }
    assert_round_trip(&t, &p);
}

#[test]
fn kad_tag_names() {
    let mut names: Vec<&[u8]> = vec![
        kad::FILENAME,
        kad::FILESIZE,
        kad::FILESIZE_HI,
        kad::FILETYPE,
        kad::FILEFORMAT,
        kad::COLLECTION,
        kad::PART_PATH,
        kad::PART_HASH,
        kad::COPIED,
        kad::GAP_START,
        kad::GAP_END,
        kad::DESCRIPTION,
        kad::PING,
        kad::FAIL,
        kad::PREFERENCE,
        kad::PORT,
        kad::IP_ADDRESS,
        kad::VERSION,
        kad::TEMPFILE,
        kad::PRIORITY,
        kad::STATUS,
        kad::SOURCES,
        kad::AVAILABILITY,
        kad::PERMISSIONS,
        kad::QTIME,
        kad::PARTS,
        kad::PUBLISHINFO,
        kad::MEDIA_ARTIST,
        kad::MEDIA_ALBUM,
        kad::MEDIA_TITLE,
        kad::MEDIA_LENGTH,
        kad::MEDIA_BITRATE,
        kad::MEDIA_CODEC,
        kad::KADMISCOPTIONS,
        kad::ENCRYPTION,
        kad::FILERATING,
        kad::BUDDYHASH,
        kad::CLIENTLOWID,
        kad::SERVERPORT,
        kad::SERVERIP,
        kad::SOURCEUPORT,
        kad::SOURCEPORT,
        kad::SOURCEIP,
        kad::SOURCETYPE,
    ];
    // The C++ test keys a std::map by name, so aliases collapse and the order is sorted.
    names.sort();
    names.dedup();
    let mut p = vec![names.len() as u8];
    for (i, n) in names.iter().enumerate() {
        p.extend_from_slice(&[0x09, 0x01, 0x00, n[0], i as u8]);
    }
    let t = read_list(&p);
    for (i, n) in names.iter().enumerate() {
        check(&t[i], n, TagValue::U8(i as u8));
    }
    assert_round_trip(&t, &p);
}

#[test]
fn ed2k_tag_names() {
    let ids: Vec<u8> = FileTag::ALL.iter().map(|&t| t.into()).collect();
    let mut p = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        p.extend_from_slice(&[0x09 + 0x80, *id, i as u8]);
    }
    let mut r = Reader::new(&p);
    for (i, id) in ids.iter().enumerate() {
        let t = Tag::read_ed2k(&mut r, true, true).unwrap();
        assert_eq!(t.name, TagName::Id(*id));
        assert_eq!(
            t.value,
            TagValue::U32(i as u32),
            "uint8 is normalised to uint32"
        );
    }
    assert!(r.is_eof());
}

#[test]
fn ed2k_blob() {
    let p = [0x87, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
    let t = Tag::read_ed2k(&mut Reader::new(&p), true, true).unwrap();
    assert_eq!(t, Tag::new(0xFF, TagValue::Blob(vec![1, 2, 3, 4])));
    let p = [
        0x07, 0x02, 0x00, b'A', b'A', 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    ];
    let t = Tag::read_ed2k(&mut Reader::new(&p), true, true).unwrap();
    assert_eq!(t, Tag::new("AA", TagValue::Blob(vec![1, 2, 3, 4])));
    let mut w = Writer::new();
    t.write_ed2k(&mut w, StrEncoding::Latin1).unwrap();
    assert_eq!(w.as_bytes(), p);
}

/// `CheckSkippedTagCopy`: BOOL / BOOLARRAY payloads are consumed and
/// dropped, and such a tag cannot be written.
#[test]
fn skipped_bool_tags() {
    let mut w = Writer::new();
    w.u8(u8::from(TagType::Bool)).u16(1).u8(0xF0).u8(1);
    let p = w.into_bytes();
    let mut r = Reader::new(&p);
    let t = Tag::read_ed2k(&mut r, true, true).unwrap();
    assert!(r.is_eof());
    assert_eq!(t, Tag::new(0xF0, TagValue::Bool));

    let mut w = Writer::new();
    w.u8(u8::from(TagType::BoolArray))
        .string("skipped", StrEncoding::Latin1, LenField::U16)
        .u16(8)
        .u8(0x80)
        .u8(0);
    let p = w.into_bytes();
    let mut r = Reader::new(&p);
    let t2 = Tag::read_ed2k(&mut r, true, true).unwrap();
    assert!(r.is_eof(), "len / 8 + 1 bytes are skipped");
    assert_eq!(t2, Tag::new("skipped", TagValue::BoolArray));

    for t in [&t, &t2] {
        assert!(!t.can_write_to_file());
        let mut w = Writer::new();
        assert!(t.write_kad(&mut w).is_err());
        assert!(t.write_ed2k(&mut w, StrEncoding::Utf8).is_err());
        assert!(w.is_empty(), "nothing is written for an unwritable tag");
    }
}

#[test]
fn ed2k_writer_picks_short_strings_and_small_ints() {
    let size = FileTag::Filesize.value();
    let cases = [
        (Tag::int(size, 5), vec![0x89, 0x02, 0x05]),
        // Sized by value, not by the declared width.
        (
            Tag::new(size, TagValue::U64(300)),
            vec![0x88, 0x02, 0x2C, 0x01],
        ),
        (
            Tag::int(size, 0x1_0000),
            vec![0x83, 0x02, 0x00, 0x00, 0x01, 0x00],
        ),
        (
            Tag::int(size, 1 << 32),
            vec![0x8B, 0x02, 0, 0, 0, 0, 1, 0, 0, 0],
        ),
        // "abc" is STR3 (0x13): the type carries the length.
        (
            Tag::string(FileTag::Filename.value(), "abc"),
            vec![0x93, 0x01, b'a', b'b', b'c'],
        ),
        // A string name of length 1 is written as a string and read back as an id.
        (Tag::string("A", "x"), vec![0x11, 0x01, 0x00, b'A', b'x']),
    ];
    for (tag, bytes) in cases {
        let mut w = Writer::new();
        tag.write_ed2k(&mut w, StrEncoding::Utf8).unwrap();
        assert_eq!(w.as_bytes(), bytes, "{tag}");
        let back = Tag::read_ed2k(&mut Reader::new(&bytes), true, false).unwrap();
        assert_eq!(back.name.as_bytes(), tag.name.as_bytes());
        assert_eq!(back.as_int(), tag.as_int());
        assert_eq!(back.as_str(), tag.as_str());
    }
    // 16 bytes is still a short string, 17 is not.
    let mut w = Writer::new();
    Tag::string(1, "0123456789abcdef")
        .write_ed2k(&mut w, StrEncoding::Utf8)
        .unwrap();
    assert_eq!(w.as_bytes()[0], 0x80 | 0x20);
    let mut w = Writer::new();
    Tag::string(1, "0123456789abcdefg")
        .write_ed2k(&mut w, StrEncoding::Utf8)
        .unwrap();
    assert_eq!(&w.as_bytes()[..4], [0x82, 0x01, 17, 0]);
    // The short-string length is measured in the encoding written: "é" is
    // 1 byte in Latin-1, 2 in UTF-8, 5 with a BOM.
    for (enc, ty, opt_utf8) in [
        (StrEncoding::Latin1, 0x11, false),
        (StrEncoding::Utf8, 0x12, true),
        (StrEncoding::Utf8Bom, 0x15, true),
    ] {
        let mut w = Writer::new();
        Tag::string(1, "é").write_ed2k(&mut w, enc).unwrap();
        assert_eq!(w.as_bytes()[0], 0x80 | ty, "{enc:?}");
        let back = Tag::read_ed2k(&mut Reader::new(w.as_bytes()), opt_utf8, true).unwrap();
        assert_eq!(back.as_str(), Some("é"), "{enc:?}");
    }
}

#[test]
fn errors_not_panics() {
    // Unknown types: eD2k has no BSOB, Kad has no BLOB or short strings.
    let bsob = [0x8A, 0x01, 0x00];
    assert_eq!(
        Tag::read_ed2k(&mut Reader::new(&bsob), true, true),
        Err(TagError::UnknownType {
            codec: "eD2k",
            ty: 0x0A
        })
    );
    let blob = [0x07, 0x01, 0x00, 0x01, 0, 0, 0, 0];
    assert!(matches!(
        Tag::read_kad(&mut Reader::new(&blob), true),
        Err(TagError::UnknownType { .. })
    ));
    let str3 = [0x13, 0x01, 0x00, 0x01, b'a', b'b', b'c'];
    assert!(matches!(
        Tag::read_kad(&mut Reader::new(&str3), true),
        Err(TagError::UnknownType { .. })
    ));
    // A blob claiming more than is left.
    let big = [0x87, 0x01, 0xFF, 0xFF, 0xFF, 0x7F, 0x00];
    assert!(matches!(
        Tag::read_ed2k(&mut Reader::new(&big), true, true),
        Err(TagError::BlobTooLarge { .. })
    ));
    // Truncated input.
    assert!(matches!(
        Tag::read_kad(&mut Reader::new(&[0x03, 0x01, 0x00, 0x02, 0x12]), true),
        Err(TagError::Io(_))
    ));
    // Unwritable things write nothing.
    let mut w = Writer::new();
    assert_eq!(
        Tag::new("x", TagValue::Bsob(vec![0; 256])).write_kad(&mut w),
        Err(TagError::TooLong("bsob"))
    );
    assert!(Tag::new(1, TagValue::Bsob(vec![1]))
        .write_ed2k(&mut w, StrEncoding::Utf8)
        .is_err());
    let many: Vec<Tag> = (0..256).map(|i| Tag::int(1, i)).collect();
    assert_eq!(
        write_kad_list(&mut w, &many),
        Err(TagError::TooLong("tag list"))
    );
    assert!(w.is_empty());
}

#[test]
fn display_like_get_full_info() {
    assert_eq!(Tag::string(1, "x").to_string(), "0x01=\"x\"");
    assert_eq!(
        Tag::new("Artist", TagValue::U32(5)).to_string(),
        "\"Artist\"=(Int32)5"
    );
    assert_eq!(
        Tag::new(kad::FILESIZE, TagValue::Blob(vec![0; 3])).to_string(),
        "0x02=(Blob)3"
    );
}
