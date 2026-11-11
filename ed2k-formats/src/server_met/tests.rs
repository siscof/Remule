// SPDX-License-Identifier: GPL-2.0-or-later
//! Ported from aMule's `unittests/tests/ServerMetTest.cpp`, plus round trips
//! and the typed view.

use super::*;

// The C++ test's IP_A / IP_B are uint32s in aMule's in-memory order, written
// little-endian: these are the file bytes.
const IP_A: Ipv4Addr = Ipv4Addr::new(0x91, 0xEF, 0x02, 0x86);
const IP_B: Ipv4Addr = Ipv4Addr::new(0xC0, 0xA8, 0x00, 0x0A);

/// `WriteServer`: one record, optionally with the legacy (one too many) tag count.
fn write_server(w: &mut Writer, ip: Ipv4Addr, version: &str, legacy_count: bool) {
    let mut tags = vec![
        Tag::new(
            ServerTag::ServerName.value(),
            TagValue::String("server".into()),
        ),
        Tag::new(ServerTag::Fail.value(), TagValue::U32(0)),
        Tag::new("users", TagValue::U32(10)),
    ];
    if !version.is_empty() {
        tags.push(Tag::new(
            ServerTag::Version.value(),
            TagValue::String(version.into()),
        ));
        tags.push(Tag::new(
            ServerTag::Version.value(),
            TagValue::String(version.into()),
        ));
    }
    tags.push(Tag::new(ServerTag::LowIdUsers.value(), TagValue::U32(3)));
    let count = tags.len() as u32 + u32::from(legacy_count && version.is_empty());
    w.bytes(&ip.octets()).u16(4661).u32(count);
    for t in &tags {
        t.write_kad(w).unwrap();
    }
}

/// `Finish`: header byte, server count, records.
fn finish(servers: Writer, count: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(VERSION).u32(count).bytes(servers.as_bytes());
    w.into_bytes()
}

#[test]
fn correct_counts_read_as_declared() {
    let mut s = Writer::new();
    write_server(&mut s, IP_A, "", false);
    write_server(&mut s, IP_B, "17.15", false);
    let met = ServerMet::read(&finish(s, 2)).unwrap();
    assert!(!met.legacy_counts);
    assert_eq!(met.servers.len(), 2);
    assert_eq!(met.servers[0].tags.len(), 4);
    assert_eq!(met.servers[1].tags.len(), 6);
    assert_eq!(met.servers[1].ip, IP_B);
}

#[test]
fn legacy_count_before_another_server() {
    let mut s = Writer::new();
    write_server(&mut s, IP_B, "", true);
    write_server(&mut s, IP_A, "17.15", true);
    write_server(&mut s, IP_B, "17.15", true);
    let met = ServerMet::read(&finish(s, 3)).unwrap();
    assert!(met.legacy_counts);
    assert_eq!(met.servers.len(), 3);
    assert_eq!(met.servers[0].tags.len(), 4);
    assert_eq!(met.servers[1].ip, IP_A);
    assert_eq!(met.servers[1].port, 4661);
    assert_eq!(met.servers[1].tags.len(), 6);
}

#[test]
fn legacy_count_on_last_server() {
    let mut s = Writer::new();
    write_server(&mut s, IP_A, "17.15", true);
    write_server(&mut s, IP_B, "", true);
    let met = ServerMet::read(&finish(s, 2)).unwrap();
    assert!(met.legacy_counts);
    assert_eq!(met.servers[1].tags.len(), 4);
}

#[test]
fn legacy_count_on_every_server() {
    let mut s = Writer::new();
    write_server(&mut s, IP_B, "", true);
    write_server(&mut s, IP_A, "", true);
    write_server(&mut s, IP_B, "", true);
    let met = ServerMet::read(&finish(s, 3)).unwrap();
    assert!(met.legacy_counts);
    assert_eq!(met.servers.len(), 3);
    assert_eq!(met.servers[1].ip, IP_A);
}

#[test]
fn truncated_file_keeps_the_servers_before_it() {
    let mut s = Writer::new();
    write_server(&mut s, IP_A, "17.15", false);
    write_server(&mut s, IP_B, "17.15", false);
    let full = finish(s, 2);
    let err = ServerMet::read(&full[..full.len() - 5]).unwrap_err();
    assert!(matches!(err.kind, ErrorKind::Tag(_)));
    assert_eq!(err.salvaged.len(), 1);
    assert_eq!(err.salvaged[0].ip, IP_A);
}

#[test]
fn trailing_records_are_rejected_without_losing_salvageable_servers() {
    let mut s = Writer::new();
    write_server(&mut s, IP_A, "17.15", false);
    write_server(&mut s, IP_B, "17.15", false);
    let err = ServerMet::read(&finish(s, 1)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::TrailingData);
    assert_eq!(err.salvaged.len(), 1);
    assert_eq!(err.salvaged[0].ip, IP_A);
}

#[test]
fn trailing_data_after_empty_list_is_rejected() {
    let mut s = Writer::new();
    s.u8(0xff);
    let err = ServerMet::read(&finish(s, 0)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::TrailingData);
    assert!(err.salvaged.is_empty());
}

#[test]
fn bad_version_and_empty_file() {
    assert_eq!(
        ServerMet::read(&[0x0F, 0, 0, 0, 0]).unwrap_err().kind,
        ErrorKind::BadVersion(0x0F)
    );
    assert!(ServerMet::read(&[]).is_err());
    let empty = ServerMet::read(&[VERSION_MET_HEADER, 0, 0, 0, 0]).unwrap();
    assert_eq!(empty.version, VERSION_MET_HEADER);
    assert!(empty.servers.is_empty());
}

fn sample_info() -> ServerInfo {
    ServerInfo {
        ip: Some(IP_A),
        port: 4661,
        name: "eMule Sunrise".into(),
        description: "Sörvér ünicode".into(),
        dyn_ip: String::new(),
        version: "17.15".into(),
        aux_ports: String::new(),
        preference: PRIORITY_HIGH,
        failed: 2,
        ping: 61,
        last_ping: 1_762_000_000,
        users: 95_120,
        files: 18_220_333,
        max_users: 190_240,
        soft_files: 1000,
        hard_files: 1500,
        low_id_users: 4_000,
        udp_flags: 0x3B,
        udp_key: 0xDEAD_BEEF,
        udp_key_ip: 0x0100_007F,
        obfuscation_port_tcp: 4665,
        obfuscation_port_udp: 4666,
    }
}

/// A file written the way `SaveServerMet` writes it reads back to the same
/// servers and writes back byte for byte.
#[test]
fn amule_written_file_round_trips_byte_for_byte() {
    let info = sample_info();
    let mut other = sample_info();
    other.ip = Some(IP_B);
    other.version.clear();
    other.udp_key = 0;
    other.aux_ports = "5000,5001".into();
    let met = ServerMet {
        version: VERSION,
        servers: vec![info.to_record(), other.to_record()],
        legacy_counts: false,
    };
    let bytes = met.write();
    let back = ServerMet::read(&bytes).unwrap();
    assert_eq!(back, met);
    assert_eq!(back.write(), bytes);
    assert_eq!(ServerInfo::from_record(&back.servers[0]), info);
    let o = ServerInfo::from_record(&back.servers[1]);
    assert_eq!(o, other);
    assert_eq!(o.connect_port(), 5000);
    assert_eq!(o.port, 4661);
}

#[test]
fn from_record_follows_add_tag_from_file() {
    let rec = ServerRecord {
        ip: IP_B,
        port: 4242,
        tags: vec![
            // First name wins; a second, different one is ignored.
            Tag::new(
                ServerTag::ServerName.value(),
                TagValue::String("first".into()),
            ),
            Tag::new(
                ServerTag::ServerName.value(),
                TagValue::String("second".into()),
            ),
            // A known tag with the wrong type is skipped.
            Tag::new(ServerTag::Ping.value(), TagValue::String("fast".into())),
            // A numeric version is major.minor.
            Tag::new(ServerTag::Version.value(), TagValue::U32((17 << 16) | 15)),
            // Narrow integer widths read the same.
            Tag::new(ServerTag::MaxUsers.value(), TagValue::U16(500)),
            // An out-of-range preference becomes normal.
            Tag::new(ServerTag::Preference.value(), TagValue::U8(9)),
            // Unknown tags are skipped.
            Tag::new("whatever", TagValue::U32(1)),
            Tag::new(0x7F, TagValue::U32(1)),
        ],
    };
    let s = ServerInfo::from_record(&rec);
    assert_eq!(s.name, "first");
    assert_eq!(s.ping, 0);
    assert_eq!(s.version, "17.15");
    assert_eq!(s.max_users, 500);
    assert_eq!(s.preference, PRIORITY_NORMAL);
    // A nameless server is named after its address.
    let nameless = ServerRecord {
        ip: IP_B,
        port: 1,
        tags: vec![],
    };
    assert_eq!(
        ServerInfo::from_record(&nameless).name,
        "Server 192.168.0.10"
    );
}

#[test]
fn hostile_counts_do_not_allocate_or_panic() {
    // One server claiming four billion tags, with no tag data behind it.
    let mut w = Writer::new();
    w.u8(VERSION)
        .u32(1)
        .bytes(&[1, 2, 3, 4])
        .u16(1)
        .u32(u32::MAX);
    assert!(ServerMet::read(w.as_bytes()).is_err());
    // A server count far larger than the file.
    assert!(ServerMet::read(&[VERSION, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}
