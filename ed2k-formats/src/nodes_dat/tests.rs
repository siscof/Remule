// SPDX-License-Identifier: GPL-2.0-or-later
//! nodes.dat tests, from the rules in RoutingZone.cpp (aMule has no unit
//! test for this file).

use super::*;

fn contact(n: u8, version: u8, udp_port: u16) -> Contact {
    Contact {
        id: UInt128::new(u128::from(n) << 120 | u128::from(n)),
        ip: Ipv4Addr::new(10, 0, 0, n),
        udp_port,
        tcp_port: 4662,
        version,
        udp_key: Some(KadUdpKey {
            key: 0x1234_5678 + u32::from(n),
            ip: 0x0A00_0001,
        }),
        verified: Some(n % 2),
    }
}

fn v1(c: Contact) -> Contact {
    Contact {
        udp_key: None,
        verified: None,
        ..c
    }
}

#[test]
fn record_layout_is_byte_exact() {
    let c = Contact {
        id: UInt128::from_be_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        ip: Ipv4Addr::new(1, 2, 3, 4),
        udp_port: 4672,
        tcp_port: 4662,
        version: 8,
        udp_key: Some(KadUdpKey {
            key: 0xAABB_CCDD,
            ip: 0x0102_0304,
        }),
        verified: Some(1),
    };
    let mut w = Writer::new();
    c.write(&mut w);
    let b = w.into_bytes();
    assert_eq!(b.len(), 34);
    // UInt128 in the wire layout: little-endian 32-bit chunks, most significant first.
    assert_eq!(
        &b[..16],
        [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]
    );
    // The IP is a host-order u32 stored little-endian.
    assert_eq!(&b[16..20], [4, 3, 2, 1]);
    assert_eq!(&b[20..25], [0x40, 0x12, 0x36, 0x12, 8]);
    assert_eq!(&b[25..34], [0xDD, 0xCC, 0xBB, 0xAA, 4, 3, 2, 1, 1]);
}

#[test]
fn amule_written_file_round_trips_byte_for_byte() {
    let contacts: Vec<Contact> = (1..=30).map(|n| contact(n, 8, 4672)).collect();
    let dat = NodesDat::for_writing(&contacts).unwrap();
    let bytes = dat.write();
    assert_eq!(&bytes[..12], [0, 0, 0, 0, 2, 0, 0, 0, 30, 0, 0, 0]);
    assert_eq!(bytes.len(), 12 + 30 * 34);
    let back = NodesDat::read(&bytes).unwrap();
    assert_eq!(back, dat);
    assert_eq!(back.write(), bytes);
}

#[test]
fn write_file_limits() {
    let few: Vec<Contact> = (1..=24).map(|n| contact(n, 8, 4672)).collect();
    assert!(
        NodesDat::for_writing(&few).is_none(),
        "fewer than 25 contacts: not written"
    );
    let many: Vec<Contact> = (0..600)
        .map(|n| contact((n % 250) as u8, 8, 4672))
        .collect();
    assert_eq!(
        NodesDat::for_writing(&many).unwrap().contacts.len(),
        CONTACT_FILE_LIMIT
    );
    // A v1 contact gets an empty key and verified 0 when written as v2.
    let mixed: Vec<Contact> = (1..=25).map(|n| v1(contact(n, 8, 4672))).collect();
    let d = NodesDat::for_writing(&mixed).unwrap();
    assert!(d
        .contacts
        .iter()
        .all(|c| c.udp_key == Some(KadUdpKey::default()) && c.verified == Some(0)));
    // Non-0/1 verified bytes are normalised as aMule writes them.
    let mut odd = contact(1, 8, 4672);
    odd.verified = Some(7);
    let d = NodesDat::for_writing(&vec![odd; 25]).unwrap();
    assert_eq!(d.contacts[0].verified, Some(1));
}

fn file(header: &[u32], contacts: &[Contact], trailing: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    for h in header {
        w.u32(*h);
    }
    for c in contacts {
        c.write(&mut w);
    }
    w.bytes(trailing);
    w.into_bytes()
}

#[test]
fn every_version_reads_and_round_trips() {
    let k2: Vec<Contact> = (1..=3).map(|n| contact(n, 8, 4672)).collect();
    let k1: Vec<Contact> = k2.iter().copied().map(v1).collect();
    let cases = [
        (file(&[3], &k1, &[]), Format::V0, &k1),
        (file(&[0, 1, 3], &k1, &[]), Format::V1, &k1),
        (file(&[0, 2, 3], &k2, &[]), Format::V2, &k2),
        (
            file(&[0, 3, 0, 3], &k2, &[]),
            Format::V3 { edition: 0 },
            &k2,
        ),
        (file(&[0, 3, 1, 3], &k1, &[]), Format::Bootstrap, &k1),
    ];
    for (bytes, format, want) in cases {
        let d = NodesDat::read(&bytes).unwrap();
        assert_eq!(d.format, format);
        assert_eq!(&d.contacts, want, "{format:?}");
        assert_eq!(d.write(), bytes, "{format:?}");
    }
}

#[test]
fn guard_and_unreadable_files_keep_their_bytes() {
    let k1: Vec<Contact> = (1..=2).map(|n| v1(contact(n, 8, 4672))).collect();
    let k2: Vec<Contact> = (1..=2).map(|n| contact(n, 8, 4672)).collect();
    let cases: Vec<(Vec<u8>, Format, usize)> = vec![
        // Count 0: nothing read.
        (file(&[0, 2, 0], &[], &[1, 2, 3]), Format::V2, 0),
        // A count larger than 25 bytes per contact allows: nothing read.
        (file(&[0, 2, 9], &k2, &[]), Format::V2, 0),
        // Trailing bytes after the contacts are ignored, and kept.
        (file(&[0, 2, 2], &k2, &[0xEE; 5]), Format::V2, 2),
        // A bootstrap list must fill the file exactly.
        (file(&[0, 3, 1, 2], &k1, &[0]), Format::Bootstrap, 0),
        // Unknown version, and a lone zero word.
        (file(&[0, 7, 2], &k2, &[]), Format::Unreadable, 0),
        (file(&[0], &[], &[]), Format::Unreadable, 0),
        (file(&[0], &[], &[1, 2, 3]), Format::Unreadable, 0),
    ];
    for (bytes, format, n) in cases {
        let d = NodesDat::read(&bytes).unwrap();
        assert_eq!((d.format, d.contacts.len()), (format, n), "{bytes:?}");
        assert_eq!(d.write(), bytes);
    }
}

#[test]
fn truncation_keeps_earlier_contacts() {
    let k2: Vec<Contact> = (1..=3).map(|n| contact(n, 8, 4672)).collect();
    let mut bytes = file(&[0, 2, 3], &k2, &[]);
    // Still passes the 25-bytes-per-contact guard (3 × 25 = 75 ≤ 90), but
    // the third v2 record is cut short.
    bytes.truncate(12 + 2 * 34 + 22);
    let err = NodesDat::read(&bytes).unwrap_err();
    assert_eq!(err.salvaged, k2[..2]);
}

#[test]
fn huge_counts_neither_wrap_nor_allocate() {
    // 0x0A3D70A4 × 25 wraps to 4 in 32 bits, which passes aMule's guard;
    // here the product is computed without overflow and nothing is read.
    let bytes = file(&[0, 2, 0x0A3D_70A4], &[], &[0; 40]);
    let d = NodesDat::read(&bytes).unwrap();
    assert!(d.contacts.is_empty());
    assert_eq!(d.write(), bytes);
    assert!(NodesDat::read(&[0, 0]).is_err());
}

#[test]
fn usable_contacts_follow_the_file_checks() {
    let contacts = vec![
        contact(1, 8, 4672),
        contact(2, 1, 4672), // Kad 1: ignored
        contact(3, 5, 53),   // DNS port without obfuscation: dropped
        contact(4, 6, 53),   // DNS port with obfuscation (v6+): fine
    ];
    let d = NodesDat {
        format: Format::V2,
        declared_count: 4,
        contacts: contacts.clone(),
        trailing: vec![],
    };
    let ids: Vec<u8> = d.usable().map(|c| c.ip.octets()[3]).collect();
    assert_eq!(ids, [1, 4]);
    // v0 files load nothing.
    let old = NodesDat {
        format: Format::V0,
        ..d.clone()
    };
    assert_eq!(old.usable().count(), 0);
    // Some verified contacts: nothing to force. None verified: all treated as verified.
    assert!(!d.treat_all_as_verified());
    let unverified = NodesDat {
        contacts: contacts
            .iter()
            .map(|c| Contact {
                verified: Some(0),
                ..*c
            })
            .collect(),
        ..d
    };
    assert!(unverified.treat_all_as_verified());
}

#[test]
fn bootstrap_pick_is_the_closest_fifty() {
    let me = UInt128::new(0);
    // Ids 1..=80 in reverse file order; the 50 closest to 0 are 1..=50.
    let contacts: Vec<Contact> = (1..=80u8)
        .rev()
        .map(|n| Contact {
            id: UInt128::new(u128::from(n)),
            ..v1(contact(n, 8, 4672))
        })
        .collect();
    let d = NodesDat {
        format: Format::Bootstrap,
        declared_count: 80,
        contacts,
        trailing: vec![],
    };
    let pick = d.bootstrap_pick(me);
    assert_eq!(pick.len(), BOOTSTRAP_PICK);
    assert_eq!(pick[0].id, UInt128::new(1));
    assert_eq!(pick[49].id, UInt128::new(50));
}

#[test]
fn udp_key_value() {
    let k = KadUdpKey { key: 7, ip: 99 };
    assert_eq!(k.value_for(99), 7);
    assert_eq!(k.value_for(98), 0);
    assert!(KadUdpKey { key: 0, ip: 1 }.is_empty());
    assert!(KadUdpKey { key: 1, ip: 0 }.is_empty());
}
