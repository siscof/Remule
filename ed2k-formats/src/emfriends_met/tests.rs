// SPDX-License-Identifier: GPL-2.0-or-later
//! emfriends.met tests, from the rules in Friend.cpp / FriendList.cpp (aMule
//! has no unit test for this file).

use super::*;

fn sample(n: u8, name: &str, slot: bool) -> Friend {
    Friend {
        user_hash: Md4Hash([n; 16]),
        ip: Some(Ipv4Addr::new(10, 0, 0, n)),
        port: 4662,
        last_seen: 1_700_000_000 + u32::from(n),
        last_chatted: 1_690_000_000,
        name: name.into(),
        friend_slot: slot,
    }
}

fn met(friends: &[Friend]) -> EmfriendsMet {
    EmfriendsMet {
        version: VERSION,
        friends: friends.iter().map(Friend::to_record).collect(),
    }
}

/// Bytes of one friend as `WriteToFile` writes it, built by hand.
#[test]
fn layout_matches_write_to_file() {
    let f = sample(1, "Bob", true);
    let mut w = Writer::new();
    f.to_record().write(&mut w);
    let mut want = vec![1u8; 16];
    want.extend_from_slice(&[10, 0, 0, 1]);
    want.extend_from_slice(&4662u16.to_le_bytes());
    want.extend_from_slice(&f.last_seen.to_le_bytes());
    want.extend_from_slice(&f.last_chatted.to_le_bytes());
    want.extend_from_slice(&3u32.to_le_bytes());
    for _ in 0..2 {
        // TAGTYPE_STRING, name length 1, FF_NAME, value length 3, "Bob"
        want.extend_from_slice(&[0x02, 0x01, 0x00, FF_NAME, 0x03, 0x00, b'B', b'o', b'b']);
    }
    // TAGTYPE_UINT8, name length 1, FF_FRIENDSLOT, 1
    want.extend_from_slice(&[0x09, 0x01, 0x00, FF_FRIENDSLOT, 0x01]);
    assert_eq!(w.as_bytes(), want);
}

#[test]
fn amule_written_file_round_trips_byte_for_byte() {
    let friends = [
        sample(1, "Bob", true),
        sample(2, "Zoë ☃", false),
        sample(3, "", false),
    ];
    let m = met(&friends);
    let bytes = m.write();
    assert_eq!(bytes[0], VERSION);
    let back = EmfriendsMet::read(&bytes).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.write(), bytes);
    for (rec, want) in back.friends.iter().zip(&friends) {
        assert_eq!(&Friend::from_record(rec).unwrap(), want);
    }
    // A friend without a name writes no tags.
    assert!(back.friends[2].tags.is_empty());
}

#[test]
fn tag_rules_follow_load_from_file() {
    let rec = FriendRecord {
        user_hash: Md4Hash([7; 16]),
        ip: Ipv4Addr::new(1, 2, 3, 4),
        port: 1,
        last_seen: 2,
        last_chatted: 3,
        tags: vec![
            // The first name wins.
            Tag::new(FF_NAME, TagValue::String("first".into())),
            Tag::new(FF_NAME, TagValue::String("second".into())),
            // Any non-zero integer width sets the slot.
            Tag::new(FF_FRIENDSLOT, TagValue::U32(7)),
            // Unknown tags are ignored.
            Tag::new(0x7F, TagValue::U32(1)),
            Tag::new("whatever", TagValue::String("x".into())),
        ],
    };
    let f = Friend::from_record(&rec).unwrap();
    assert_eq!(f.name, "first");
    assert!(f.friend_slot);
    // A zero slot tag clears it.
    let mut rec2 = rec.clone();
    rec2.tags[2] = Tag::new(FF_FRIENDSLOT, TagValue::U8(0));
    assert!(!Friend::from_record(&rec2).unwrap().friend_slot);
    // The raw record keeps the unknown tags and writes them back.
    let m = EmfriendsMet {
        version: VERSION,
        friends: vec![rec],
    };
    assert_eq!(EmfriendsMet::read(&m.write()).unwrap(), m);
}

#[test]
fn damage_stops_the_load_but_keeps_earlier_friends() {
    let m = met(&[sample(1, "one", false), sample(2, "two", true)]);
    let bytes = m.write();
    let err = EmfriendsMet::read(&bytes[..bytes.len() - 2]).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Tag(_)));
    assert_eq!(err.salvaged.len(), 1);

    // A name that is not a string: GetStr() throws in the C++.
    let mut bad = sample(3, "", false).to_record();
    bad.tags.push(Tag::new(FF_NAME, TagValue::U32(5)));
    let m = EmfriendsMet {
        version: VERSION,
        friends: vec![sample(1, "ok", false).to_record(), bad],
    };
    let err = EmfriendsMet::read(&m.write()).unwrap_err();
    assert_eq!(err.kind, ErrorKind::WrongType(FF_NAME));
    assert_eq!(err.salvaged.len(), 1);

    // A slot that is not an integer: GetInt() throws.
    let mut bad = sample(4, "", false).to_record();
    bad.tags
        .push(Tag::new(FF_FRIENDSLOT, TagValue::String("yes".into())));
    let m = EmfriendsMet {
        version: VERSION,
        friends: vec![bad],
    };
    assert_eq!(
        EmfriendsMet::read(&m.write()).unwrap_err().kind,
        ErrorKind::WrongType(FF_FRIENDSLOT)
    );
}

#[test]
fn bad_header_and_empty_files() {
    // aMule loads nothing from a file with another header.
    assert_eq!(
        EmfriendsMet::read(&[0x0F, 0, 0, 0, 0]).unwrap_err().kind,
        ErrorKind::BadVersion(0x0F)
    );
    assert!(EmfriendsMet::read(&[]).is_err());
    assert!(EmfriendsMet::read(&[VERSION]).is_err());
    let empty = EmfriendsMet::read(&[VERSION, 0, 0, 0, 0]).unwrap();
    assert!(empty.friends.is_empty());
    assert_eq!(empty.write(), [VERSION, 0, 0, 0, 0]);
}

#[test]
fn hostile_counts_do_not_allocate_or_panic() {
    // A friend claiming four billion tags, with no tag data behind it.
    let mut w = Writer::new();
    w.u8(VERSION)
        .u32(1)
        .hash(Md4Hash([1; 16]))
        .bytes(&[1, 2, 3, 4])
        .u16(1)
        .u32(0)
        .u32(0)
        .u32(u32::MAX);
    assert!(EmfriendsMet::read(w.as_bytes()).is_err());
    // A friend count far larger than the file.
    assert!(EmfriendsMet::read(&[VERSION, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}
