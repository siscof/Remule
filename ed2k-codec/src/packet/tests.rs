// SPDX-License-Identifier: GPL-2.0-or-later
//! Ported from aMule's `unittests/tests/PacketTest.cpp`, plus framing round
//! trips and the Kad protocol switch.

use std::io::Write as _;

use super::*;

/// A received `OP_PACKEDPROT` packet whose payload inflates to `data`,
/// packed with real zlib settings (best compression), as a peer sends it.
fn received(data: &[u8]) -> Packet {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), Compression::best());
    e.write_all(data).unwrap();
    Packet {
        protocol: Protocol::Packed.into(),
        opcode: 0,
        payload: e.finish().unwrap(),
    }
}

/// Packs to a few times smaller, like a real file list.
fn file_list(n: usize) -> Vec<u8> {
    let mut s = String::new();
    let mut i = 0u64;
    while s.len() < n {
        s += &format!("file_{}.mp3|", i * 7919 % 100_000);
        i += 1;
    }
    s.truncate(n);
    s.into_bytes()
}

fn header(protocol: u8, length: u32) -> [u8; HEADER_LEN] {
    let l = length.to_le_bytes();
    [protocol, l[0], l[1], l[2], l[3], 0]
}

#[test]
fn unpacks_within_the_first_estimate() {
    let data = file_list(20_000);
    let mut p = received(&data);
    assert!(p.payload.len() * 10 + 300 >= data.len());
    p.unpack(CLIENT_UNPACK_LIMIT).unwrap();
    assert_eq!(p.protocol, u8::from(Protocol::Emule));
    assert_eq!(p.payload, data);
}

#[test]
fn unpacks_beyond_the_tenfold_estimate() {
    // Packs to well under a tenth of its size, yet fits the 50000-byte default.
    let data = vec![b'A'; 40_000];
    let mut p = received(&data);
    assert!(p.payload.len() * 10 + 300 < data.len());
    p.unpack(CLIENT_UNPACK_LIMIT).unwrap();
    assert_eq!(p.payload, data);
}

#[test]
fn rejects_payload_over_the_limit() {
    let mut p = received(&[b'A'; 60_000]);
    assert_eq!(
        p.unpack(CLIENT_UNPACK_LIMIT),
        Err(PacketError::OverLimit(CLIENT_UNPACK_LIMIT))
    );
}

#[test]
fn rejects_unrepresentable_payload() {
    // RejectsUnrepresentablePayloadBeforeAllocating / NumericConstructorRejects
    // WideLengthsBeforeNarrowing: checked on the length, without allocating.
    assert_eq!(checked_payload_len(MAX_PAYLOAD as usize), Ok(MAX_PAYLOAD));
    assert_eq!(
        checked_payload_len(MAX_PAYLOAD as usize + 1),
        Err(PacketError::TooLarge(MAX_PAYLOAD as usize + 1))
    );
    // 2^32 used to truncate to zero at the C++ constructor boundary.
    #[cfg(target_pointer_width = "64")]
    assert!(checked_payload_len(1usize << 32).is_err());
}

#[test]
fn rejects_header_length_underflow() {
    assert_eq!(
        Header::parse(&header(Protocol::Emule.into(), 0)),
        Err(PacketError::InvalidLength(0))
    );
    assert_eq!(Packet::parse_udp(&[0xE3]), Err(PacketError::Truncated));
    assert_eq!(
        Packet::parse_tcp(&[0xE3, 1, 0, 0, 0]),
        Err(PacketError::Truncated)
    );
}

#[test]
fn header_validation_distinguishes_empty_and_invalid_packets() {
    for length in [0u32, 0x7fff_fff0, 0xffff_ffff] {
        assert_eq!(
            Header::parse(&header(Protocol::Emule.into(), length)),
            Err(PacketError::InvalidLength(length)),
            "{length:#x}"
        );
    }
    let empty = Header::parse(&header(Protocol::Emule.into(), 1)).unwrap();
    assert_eq!(empty.payload_len, 0);
    assert_eq!(
        Packet::from_tcp(empty, Vec::new()).unwrap().payload.len(),
        0
    );
    // The largest legal payload is still accepted at the header.
    assert_eq!(
        Header::parse(&header(0, MAX_PAYLOAD + 1))
            .unwrap()
            .payload_len,
        MAX_PAYLOAD
    );
}

#[test]
fn valid_packet_serialises_header_then_payload() {
    let p = Packet::new(Protocol::Emule, 0x53u8, vec![1, 2, 3, 4]);
    let bytes = p.to_tcp_bytes().unwrap();
    assert_eq!(bytes[0], u8::from(Protocol::Emule));
    assert_eq!(bytes[1], 5, "four payload bytes plus the opcode");
    assert_eq!(bytes[5], 0x53);
    assert_eq!(&bytes[6..], [1, 2, 3, 4]);
    assert_eq!(Packet::parse_tcp(&bytes).unwrap(), p);
    let udp = p.to_udp_bytes();
    assert_eq!(udp, [0xC5, 0x53, 1, 2, 3, 4]);
    assert_eq!(Packet::parse_udp(&udp).unwrap(), p);
    // A payload that does not match the header's length is refused.
    let h = p.header().unwrap();
    assert!(Packet::from_tcp(h, vec![1, 2, 3]).is_err());
}

#[test]
fn zero_decompression_limit_leaves_packed_packet_intact() {
    let mut p = received(&[b'A'; 100]);
    let before = p.clone();
    assert!(p.unpack(0).is_err());
    assert_eq!(p, before, "a failed unpack changes nothing");
    p.unpack(100).unwrap();
    assert_eq!(p.payload, vec![b'A'; 100]);
}

#[test]
fn pack_round_trips_and_switches_the_protocol() {
    let data = file_list(5_000);
    let mut p = Packet::new(Protocol::Emule, 0x01u8, data.clone());
    assert!(p.pack());
    assert_eq!(p.protocol, u8::from(Protocol::Packed));
    assert!(p.payload.len() < data.len());
    p.unpack(CLIENT_UNPACK_LIMIT).unwrap();
    assert_eq!(p.protocol, u8::from(Protocol::Emule));
    assert_eq!(p.payload, data);

    // Kad packs to its own packed protocol and unpacks back to Kad.
    let mut k = Packet::new(Protocol::Kademlia, 0x21u8, data.clone());
    assert!(k.pack());
    assert_eq!(k.protocol, u8::from(Protocol::KademliaPacked));
    k.unpack(kad_unpack_limit(k.payload.len())).unwrap();
    assert_eq!(k.protocol, u8::from(Protocol::Kademlia));
    assert_eq!(k.payload, data);
}

#[test]
fn pack_keeps_the_packet_when_compression_does_not_help() {
    let mut p = Packet::new(Protocol::Emule, 0x01u8, vec![7]);
    assert!(!p.pack());
    assert_eq!(p, Packet::new(Protocol::Emule, 0x01u8, vec![7]));
}

#[test]
fn unpack_errors() {
    let mut plain = Packet::new(Protocol::Emule, 0x01u8, vec![1, 2, 3]);
    assert_eq!(plain.unpack(1000), Err(PacketError::NotPacked(0xC5)));
    let mut garbage = Packet {
        protocol: Protocol::Packed.into(),
        opcode: 0,
        payload: vec![1, 2, 3, 4],
    };
    assert_eq!(garbage.unpack(1000), Err(PacketError::Corrupt));
    // A truncated stream is corrupt, not silently short.
    let mut cut = received(&file_list(2_000));
    cut.payload.truncate(cut.payload.len() / 2);
    assert_eq!(cut.unpack(CLIENT_UNPACK_LIMIT), Err(PacketError::Corrupt));
    // Experimental ED2KV2 packing unpacks to the eMule protocol, as in aMule.
    let mut v2 = received(b"hello");
    v2.protocol = Protocol::Ed2kV2Packed.into();
    v2.unpack(100).unwrap();
    assert_eq!(v2.protocol, u8::from(Protocol::Emule));
}

#[test]
fn kad_limit_matches_the_cpp_arithmetic() {
    // newSize = packetLen * 10 + 300, with packetLen counting the 2 header
    // bytes, and the output starting 2 bytes in.
    assert_eq!(kad_unpack_limit(100), (100 + 2) * 10 + 300 - 2);
    assert_eq!(kad_unpack_limit(0), 318);
}
