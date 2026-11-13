// SPDX-License-Identifier: GPL-2.0-or-later
//! Vectors from aMule's `PartStatusWriterTest.cpp`, and frames built the way
//! aMule's Python integration peers build them (`DownloadDisplayRatesIntegrationTest.py`
//! `hello`, `ShortBlockPacketIntegrationTest.py`), which are independent of
//! the C++ writers.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddrV4};

use ed2k_codec::{Packet, Reader, Writer};
use ed2k_types::ed2k::client_tcp::{Extended, Standard};
use ed2k_types::{AichHash, Md4Hash, Protocol};

use crate::hello::{
    CryptSettings, EmuleInfo, HelloTrailer, MiscOptions1, MiscOptions2, OS_INFO_PROTOCOL,
};
use crate::packets::*;
use crate::part_status::{ed2k_part_count, part_count};
use crate::{Hello, MuleInfo, PartStatus};

const HASH: Md4Hash = Md4Hash([0xAB; 16]);

fn ctx(unicode: bool, ext: u8) -> ParseContext {
    ParseContext {
        unicode,
        extended_requests_version: ext,
    }
}

fn parse(p: Packet) -> PeerPacket {
    PeerPacket::parse(p, ctx(true, 2)).unwrap()
}

fn edonkey(op: Standard, payload: Vec<u8>) -> Packet {
    Packet::new(Protocol::Edonkey, op, payload)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

// ---------------------------------------------------------------- hello ---

/// `hello(name, address, port, version=..., mod=...)` from the Python test.
fn python_hello(name: &[u8], ip: [u8; 4], port: u16, version: u32, m: &[u8]) -> Vec<u8> {
    let tags = [
        cat(&[
            b"\x02\x01\x00\x01",
            &(name.len() as u16).to_le_bytes(),
            name,
        ]),
        cat(&[b"\x03\x01\x00\xfb", &version.to_le_bytes()]),
        cat(&[b"\x02\x01\x00\x55", &(m.len() as u16).to_le_bytes(), m]),
    ];
    cat(&[
        b"\x10",
        &HASH.0,
        &ip,
        &port.to_le_bytes(),
        &(tags.len() as u32).to_le_bytes(),
        &tags.concat(),
        &[0; 6],
    ])
}

#[test]
fn hello_from_the_python_peer() {
    let version = (3 << 24) | crate::hello::ed2k_version(2, 3, 1);
    let bytes = python_hello(b"peer", [10, 0, 0, 5], 4662, version, b"MyMod 1.0");
    let PeerPacket::Hello(h) = parse(edonkey(Standard::Hello, bytes)) else {
        panic!("not a hello");
    };
    assert_eq!(h.user_hash, HASH);
    assert_eq!(h.high_id_ip(), Some(Ipv4Addr::new(10, 0, 0, 5)));
    assert_eq!(h.port, 4662);
    assert_eq!(h.name.as_deref(), Some("peer"));
    assert!(h.is_emule());
    assert_eq!(h.compatible_client(), Some(3));
    assert_eq!(h.emule_version, Some(version));
    assert_eq!(h.mod_version.as_deref(), Some("MyMod 1.0"));
    assert_eq!(h.server, None);
    assert_eq!(h.trailer, HelloTrailer::None);
    assert!(h.other_tags.is_empty());
}

fn our_hello() -> Hello {
    let mut h = Hello::amule(HASH, 0x0500_000A, 4662, "remule ünicode");
    h.udp_port = 4672;
    h.kad_port = 4665;
    h.buddy = Some((0x0102_0304, 4665));
    h.misc2 = Some(MiscOptions2::amule(
        9,
        CryptSettings {
            supported: true,
            requested: true,
            required: false,
        },
    ));
    h.mod_misc_options = Some(0x05);
    h.mod_version = Some("remule".into());
    h.server = Some(SocketAddrV4::new(Ipv4Addr::new(176, 123, 5, 89), 4725));
    h
}

#[test]
fn hello_and_answer_round_trip() {
    let h = our_hello();
    let hello = h.to_hello().unwrap();
    assert_eq!((hello.protocol, hello.opcode), (0xE3, 0x01));
    assert_eq!(hello.payload[0], 16);
    assert_eq!(parse(hello.clone()), PeerPacket::Hello(h.clone()));

    let answer = h.to_hello_answer().unwrap();
    assert_eq!(answer.opcode, 0x4C);
    assert_eq!(answer.payload, hello.payload[1..]);
    assert_eq!(parse(answer), PeerPacket::HelloAnswer(h));
}

#[test]
fn hello_layout() {
    let h = Hello {
        user_hash: HASH,
        id: 7,
        port: 0x1234,
        name: Some("ab".into()),
        udp_port: 0x0102,
        kad_port: 0x0304,
        ..Default::default()
    };
    let p = h.to_hello_answer().unwrap().payload;
    let expected = cat(&[
        &HASH.0,
        &7u32.to_le_bytes(),
        &[0x34, 0x12],
        &2u32.to_le_bytes(),
        // CT_NAME: string, name length 1, id 1, "ab"
        b"\x02\x01\x00\x01\x02\x00ab",
        // CT_EMULE_UDPPORTS: uint32, Kad port high, UDP port low
        b"\x03\x01\x00\xf9\x02\x01\x04\x03",
        &[0; 6],
    ]);
    assert_eq!(p, expected);
}

#[test]
fn hello_quirks() {
    // CT_PORT overrides the port field; an integer mod version is "ModID=n".
    let mut w = Writer::new();
    w.hash(HASH).u32(0).u16(1).u32(2);
    w.bytes(b"\x03\x01\x00\x0f").u32(4711);
    w.bytes(b"\x03\x01\x00\x55").u32(42);
    w.u32(0).u16(0).u32(0x4b44_4c4d);
    let h = Hello::parse_hello_answer(w.as_bytes()).unwrap();
    assert_eq!(h.port, 4711);
    assert_eq!(h.mod_version.as_deref(), Some("ModID=42"));
    assert_eq!(h.trailer, HelloTrailer::MlDonkey);
    assert!(!h.is_emule());

    // Any other four bytes make a Hybrid; other lengths are ignored.
    let mut w = Writer::new();
    w.hash(HASH).u32(0).u16(1).u32(0).u32(0).u16(0).u32(9);
    let h = Hello::parse_hello_answer(w.as_bytes()).unwrap();
    assert_eq!(h.trailer, HelloTrailer::Hybrid(9));
    let mut w = Writer::new();
    w.hash(HASH).u32(0).u16(1).u32(0).u32(0).u16(0).u8(1).u8(2);
    let h = Hello::parse_hello_answer(w.as_bytes()).unwrap();
    assert_eq!(h.trailer, HelloTrailer::None);
}

#[test]
fn bad_hellos() {
    let good = our_hello().to_hello().unwrap().payload;
    let mut wrong_size = good.clone();
    wrong_size[0] = 15;
    assert!(Hello::parse_hello(&wrong_size).is_err());
    // Without the server address.
    assert!(Hello::parse_hello(&good[..good.len() - 6]).is_err());
    for n in 0..good.len() - 6 {
        assert!(Hello::parse_hello(&good[..n]).is_err(), "{n} bytes");
    }
}

#[test]
fn misc_options() {
    let m1 = MiscOptions1::amule();
    assert_eq!(m1.to_bits(), 0x3413_3212);
    assert_eq!(MiscOptions1::from_bits(0x3413_3212), m1);
    assert_eq!(MiscOptions1::from_bits(u32::MAX).to_bits(), 0xFFFF_FFFF);

    let crypt = CryptSettings {
        supported: true,
        requested: true,
        required: false,
    };
    let m2 = MiscOptions2::amule(9, crypt);
    assert_eq!(m2.to_bits(), 0xDB9);
    assert_eq!(MiscOptions2::from_bits(0xDB9), m2);
    // "Requires" without "requests", "requests" without "supports": ignored.
    let m = MiscOptions2::from_bits(1 << 9 | 1 << 8);
    assert!(!m.requires_crypt && !m.requests_crypt && !m.supports_crypt);
    let m = MiscOptions2::from_bits(1 << 9 | 1 << 7);
    assert!(!m.requires_crypt && m.supports_crypt);
}

#[test]
fn emule_info_round_trip() {
    let info = MuleInfo::Info(EmuleInfo::amule(4672, 3, Some("remule".into())));
    for answer in [false, true] {
        let p = info.to_packet(answer).unwrap();
        assert_eq!(p.protocol, 0xC5);
        assert_eq!(p.opcode, if answer { 0x02 } else { 0x01 });
        assert_eq!(&p.payload[..6], &[0x47, 0x01, 9, 0, 0, 0]);
        assert_eq!(
            parse(p),
            PeerPacket::MuleInfo {
                info: info.clone(),
                answer
            }
        );
    }
    let os = MuleInfo::OsInfo {
        version: 0x47,
        os: Some("Windows".into()),
    };
    let p = os.to_packet(false).unwrap();
    assert_eq!(p.payload[1], OS_INFO_PROTOCOL);
    assert_eq!(MuleInfo::parse(&p.payload).unwrap(), os);
}

#[test]
fn emule_info_from_old_emule() {
    // Version 0x2B reads as 0x22; protocol other than 1 or 0xFF is refused.
    let mut w = Writer::new();
    w.u8(0x2B).u8(1).u32(2);
    w.bytes(b"\x03\x01\x00\x20").u32(1);
    w.bytes(b"\x08\x01\x00\x21").u16(4672); // a uint16 tag
    let MuleInfo::Info(i) = MuleInfo::parse(w.as_bytes()).unwrap() else {
        panic!()
    };
    assert_eq!((i.version, i.compression, i.udp_port), (0x22, 1, 4672));
    assert!(MuleInfo::parse(&[0x30, 2, 0, 0, 0, 0]).is_err());
}

// ---------------------------------------------------------- part status ---

fn bitmap(bits: &[usize], count: usize) -> PartStatus {
    PartStatus::Parts((0..count).map(|i| bits.contains(&i)).collect())
}

fn write(s: &PartStatus) -> Vec<u8> {
    let mut w = Writer::new();
    s.write(&mut w);
    w.into_bytes()
}

#[test]
fn part_status_vectors() {
    // PartStatusWriterTest.cpp
    let cases = [
        (bitmap(&[0, 2, 9], 10), vec![10, 0, 0x05, 0x02]),
        (
            bitmap(&[0, 1, 2, 3, 4, 5, 6, 7, 8], 9),
            vec![9, 0, 0xFF, 0x01],
        ),
        (bitmap(&[0, 1, 2, 3, 4, 5, 6, 7], 8), vec![8, 0, 0xFF]),
        (PartStatus::Complete, vec![0, 0]),
        (bitmap(&[0, 2], 4), vec![4, 0, 0x05]),
        (bitmap(&[0, 2], 3), vec![3, 0, 0x05]),
    ];
    for (status, bytes) in cases {
        assert_eq!(write(&status), bytes);
        let mut r = Reader::new(&bytes);
        assert_eq!(PartStatus::read(&mut r).unwrap(), status);
        assert!(r.is_eof());
    }
    assert!(PartStatus::read(&mut Reader::new(&[9, 0, 0xFF])).is_err());
    let s = bitmap(&[1], 3);
    assert!(s.has(1) && !s.has(0) && !s.has(7));
    assert!(PartStatus::Complete.has(1000));
}

#[test]
fn part_counts() {
    use ed2k_types::ed2k::PARTSIZE;
    assert_eq!((part_count(0), ed2k_part_count(0)), (0, 1));
    assert_eq!((part_count(1), ed2k_part_count(1)), (1, 1));
    assert_eq!((part_count(PARTSIZE), ed2k_part_count(PARTSIZE)), (1, 2));
    assert_eq!(
        (part_count(PARTSIZE + 1), ed2k_part_count(PARTSIZE + 1)),
        (2, 2)
    );
}

// -------------------------------------------------------- file requests ---

#[test]
fn file_requests_as_the_python_source_answers_them() {
    let name = b"file.bin";
    let p = edonkey(
        Standard::ReqFilenameAnswer,
        cat(&[&HASH.0, &(name.len() as u16).to_le_bytes(), name]),
    );
    assert_eq!(
        parse(p.clone()),
        PeerPacket::FileName {
            hash: HASH,
            name: "file.bin".into()
        }
    );
    assert_eq!(file_name(HASH, "file.bin", true), p);

    let p = edonkey(Standard::FileStatus, cat(&[&HASH.0, &[0, 0]]));
    assert_eq!(
        parse(p.clone()),
        PeerPacket::FileStatus {
            hash: HASH,
            parts: PartStatus::Complete
        }
    );
    assert_eq!(file_status(HASH, &PartStatus::Complete), p);
    assert_eq!(
        parse(edonkey(Standard::AcceptUploadReq, vec![])),
        PeerPacket::AcceptUploadReq
    );
    assert_eq!(
        accept_upload_req(),
        edonkey(Standard::AcceptUploadReq, vec![])
    );
}

#[test]
fn file_name_encodings() {
    let latin1 = file_name(HASH, "café", false);
    assert_eq!(&latin1.payload[16..], b"\x04\x00caf\xe9");
    let utf8 = file_name(HASH, "café", true);
    assert_eq!(&utf8.payload[16..], b"\x05\x00caf\xc3\xa9");
    for p in [latin1, utf8] {
        let PeerPacket::FileName { name, .. } = parse(p) else {
            panic!()
        };
        assert_eq!(name, "café");
    }
}

#[test]
fn file_name_request_and_extended_info() {
    let ext = FileRequestExt {
        parts: bitmap(&[1], 3),
        complete_sources: Some(7),
    };
    let p = request_file_name(HASH, Some(&ext));
    assert_eq!(p.payload, cat(&[&HASH.0, &[3, 0, 0x02, 7, 0]]));
    assert_eq!(
        PeerPacket::parse(p.clone(), ctx(true, 2)).unwrap(),
        PeerPacket::RequestFileName {
            hash: HASH,
            ext: Some(ext.clone())
        }
    );
    // Version 1: no source count; version 0: nothing read.
    let PeerPacket::RequestFileName { ext: e1, .. } =
        PeerPacket::parse(p.clone(), ctx(true, 1)).unwrap()
    else {
        panic!()
    };
    assert_eq!(e1.unwrap().complete_sources, None);
    let PeerPacket::RequestFileName { ext: e0, .. } = PeerPacket::parse(p, ctx(true, 0)).unwrap()
    else {
        panic!()
    };
    assert_eq!(e0, None);
    // Advertised but missing: aMule drops the client.
    assert!(PeerPacket::parse(request_file_name(HASH, None), ctx(true, 1)).is_err());
    // Count 0 is not followed by a source count.
    let p = edonkey(Standard::RequestFilename, cat(&[&HASH.0, &[0, 0]]));
    let PeerPacket::RequestFileName { ext, .. } = PeerPacket::parse(p, ctx(true, 2)).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        ext,
        Some(FileRequestExt {
            parts: PartStatus::Complete,
            complete_sources: None
        })
    );
}

#[test]
fn hash_only_packets() {
    let cases: [(Packet, PeerPacket); 6] = [
        (set_req_file_id(HASH), PeerPacket::SetReqFileId(HASH)),
        (no_such_file(HASH), PeerPacket::NoSuchFile(HASH)),
        (hash_set_request(HASH), PeerPacket::HashSetRequest(HASH)),
        (start_upload_req(HASH), PeerPacket::StartUploadReq(HASH)),
        (end_of_download(HASH), PeerPacket::EndOfDownload(HASH)),
        (aich_file_hash_req(HASH), PeerPacket::AichFileHashReq(HASH)),
    ];
    for (p, want) in cases {
        assert_eq!(p.payload, HASH.0);
        assert_eq!(parse(p.clone()), want);
        let mut short = p.clone();
        short.payload.pop();
        let got = PeerPacket::parse(short, ctx(true, 2));
        // aMule ignores a short upload request or end of download.
        assert!(matches!(got, Err(_) | Ok(PeerPacket::Other(_))), "{got:?}");
    }
    assert!(PeerPacket::parse(
        edonkey(Standard::SetReqFileId, [0; 17].to_vec()),
        ctx(true, 2)
    )
    .is_err());
}

#[test]
fn hash_sets() {
    let parts = [Md4Hash([1; 16]), Md4Hash([2; 16]), Md4Hash([3; 16])];
    let p = hash_set_answer(HASH, &parts);
    assert_eq!(p.payload.len(), 16 + 2 + 48);
    assert_eq!(&p.payload[16..18], &[3, 0]);
    assert_eq!(
        parse(p.clone()),
        PeerPacket::HashSetAnswer {
            hash: HASH,
            parts: parts.to_vec()
        }
    );
    let mut short = p;
    short.payload.pop();
    assert!(PeerPacket::parse(short, ctx(true, 2)).is_err());
}

#[test]
fn queue_ranks() {
    assert_eq!(parse(queue_rank(1234)), PeerPacket::QueueRank(1234));
    let p = queue_ranking(77);
    assert_eq!(p.payload, [77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(parse(p), PeerPacket::QueueRanking(77));
    let short = Packet::new(Protocol::Emule, Extended::QueueRanking, vec![1, 0]);
    assert!(PeerPacket::parse(short, ctx(true, 2)).is_err());
}

#[test]
fn aich_file_hash() {
    let aich = AichHash([9; 20]);
    let p = aich_file_hash_ans(HASH, aich);
    assert_eq!(p.payload.len(), 36);
    assert_eq!(parse(p), PeerPacket::AichFileHashAns { hash: HASH, aich });
}

// ------------------------------------------------------------- transfers ---

#[test]
fn part_requests() {
    // As the Python source reads them: '<6I' after the hash, empty slots zero.
    let p = request_parts(HASH, &[0..184_320, 184_320..368_640]);
    assert_eq!(p.protocol, 0xE3);
    assert_eq!(p.opcode, 0x47);
    let mut r = Reader::new(&p.payload[16..]);
    let v: Vec<u32> = (0..6).map(|_| r.u32().unwrap()).collect();
    assert_eq!(v, [0, 184_320, 0, 184_320, 368_640, 0]);
    assert_eq!(
        parse(p),
        PeerPacket::RequestParts {
            hash: HASH,
            ranges: vec![0..184_320, 184_320..368_640]
        }
    );

    // Past 4 GiB: the eMule I64 form.
    let big = (1u64 << 32) - 10..(1u64 << 32) + 10;
    let p = request_parts(HASH, std::slice::from_ref(&big));
    assert_eq!((p.protocol, p.opcode), (0xC5, 0xA3));
    assert_eq!(p.payload.len(), 16 + 48);
    assert_eq!(
        parse(p),
        PeerPacket::RequestParts {
            hash: HASH,
            ranges: vec![big]
        }
    );
    // A block ending exactly at 4 GiB needs the I64 form too.
    let at_4gib = (1u64 << 32) - 10..1u64 << 32;
    let p = request_parts(HASH, std::slice::from_ref(&at_4gib));
    assert_eq!(p.opcode, 0xA3);

    // Ranges that do not end after they start are dropped, as aMule does.
    let mut w = Writer::new();
    w.hash(HASH).u32(10).u32(50).u32(0).u32(5).u32(40).u32(0);
    let p = edonkey(Standard::RequestParts, w.into_bytes());
    assert_eq!(
        parse(p),
        PeerPacket::RequestParts {
            hash: HASH,
            ranges: vec![]
        }
    );
}

/// `block(file_hash, first, packed, large)` from the Python test.
fn python_block(first: u64, packed: bool, large: bool) -> (Vec<u8>, Vec<u8>) {
    let content = vec![b'x'; 1024];
    let data = if packed {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&content).unwrap();
        z.finish().unwrap()
    } else {
        content
    };
    let offset = |v: u64| {
        if large {
            v.to_le_bytes().to_vec()
        } else {
            (v as u32).to_le_bytes().to_vec()
        }
    };
    let mut header = cat(&[&HASH.0, &offset(first)]);
    if packed {
        header.extend((data.len() as u32).to_le_bytes());
    } else {
        header.extend(offset(first + data.len() as u64));
    }
    (header, data)
}

#[test]
fn data_blocks_from_the_python_source() {
    for large in [false, true] {
        let first = if large { 5 << 30 } else { 368_640 };
        let (header, data) = python_block(first, false, large);
        let ours = sending_part(HASH, first, &data);
        assert_eq!(ours.payload, cat(&[&header, &data]));
        assert_eq!(
            (ours.protocol, ours.opcode),
            if large { (0xC5, 0xA2) } else { (0xE3, 0x46) }
        );
        let PeerPacket::SendingPart(b) = parse(ours) else {
            panic!()
        };
        assert_eq!((b.start, b.data.as_slice()), (first, data.as_slice()));
        assert_eq!(b.range(), first..first + 1024);

        let (header, packed) = python_block(first, true, large);
        let ours = compressed_part(HASH, first..first + 1024, packed.len() as u32, &packed);
        assert_eq!(ours.payload, cat(&[&header, &packed]));
        assert_eq!(ours.opcode, if large { 0xA1 } else { 0x40 });
        assert_eq!(
            parse(ours),
            PeerPacket::CompressedPart(CompressedBlock {
                hash: HASH,
                start: first,
                packed_size: packed.len() as u32,
                data: packed
            })
        );
    }
}

#[test]
fn bad_data_blocks() {
    // The Python test's wrong_length case: one byte more than the range.
    let (header, mut data) = python_block(0, false, false);
    data.push(b'x');
    let p = edonkey(Standard::SendingPart, cat(&[&header, &data]));
    assert!(PeerPacket::parse(p, ctx(true, 2)).is_err());
    // An empty range, a truncated header, a compressed piece with no data.
    let mut w = Writer::new();
    w.hash(HASH).u32(5).u32(5);
    assert!(
        PeerPacket::parse(edonkey(Standard::SendingPart, w.into_bytes()), ctx(true, 2)).is_err()
    );
    assert!(PeerPacket::parse(
        edonkey(Standard::SendingPart, HASH.0.to_vec()),
        ctx(true, 2)
    )
    .is_err());
    let p = compressed_part(HASH, 0..10, 10, &[]);
    assert!(PeerPacket::parse(p, ctx(true, 2)).is_err());
}

#[test]
fn session_control() {
    assert_eq!(parse(cancel_transfer()), PeerPacket::CancelTransfer);
    assert_eq!(parse(out_of_part_reqs()), PeerPacket::OutOfPartReqs);
    // An unknown opcode is passed on.
    let p = edonkey(Standard::Message, b"\x02\x00hi".to_vec());
    assert_eq!(parse(p.clone()), PeerPacket::Other(p));
}

// ---------------------------------------------------------- multipacket ---

#[test]
fn multipacket_as_amule_sends_it() {
    // SendFileRequest to an eMule with ext multipacket, ext requests 2,
    // source exchange 2 and AICH.
    let ext = FileRequestExt {
        parts: bitmap(&[0], 2),
        complete_sources: Some(3),
    };
    let requests = vec![
        MultiRequest::FileName(Some(ext)),
        MultiRequest::FileStatus,
        MultiRequest::Sources2 {
            version: 4,
            options: 0,
        },
        MultiRequest::AichFileHash,
    ];
    let p = multi_packet(HASH, Some(20_000_000), &requests);
    assert_eq!((p.protocol, p.opcode), (0xC5, 0xA4));
    let expected = cat(&[
        &HASH.0,
        &20_000_000u64.to_le_bytes(),
        &[0x58, 2, 0, 0x01, 3, 0],
        &[0x4F],
        &[0x83, 4, 0, 0],
        &[0x9E],
    ]);
    assert_eq!(p.payload, expected);
    assert_eq!(
        parse(p),
        PeerPacket::MultiPacket {
            hash: HASH,
            size: Some(20_000_000),
            requests
        }
    );

    let plain = multi_packet(
        HASH,
        None,
        &[MultiRequest::FileName(None), MultiRequest::Sources],
    );
    assert_eq!(plain.opcode, 0x92);
    assert_eq!(
        PeerPacket::parse(plain, ctx(true, 0)).unwrap(),
        PeerPacket::MultiPacket {
            hash: HASH,
            size: None,
            requests: vec![MultiRequest::FileName(None), MultiRequest::Sources]
        }
    );
}

#[test]
fn multipacket_answer() {
    let answers = vec![
        MultiAnswer::FileName("ünï.iso".into()),
        MultiAnswer::FileStatus(bitmap(&[0, 2], 3)),
        MultiAnswer::AichFileHash(AichHash([7; 20])),
    ];
    let p = multi_packet_answer(HASH, &answers, true);
    assert_eq!(p.opcode, 0x93);
    assert_eq!(
        parse(p.clone()),
        PeerPacket::MultiPacketAnswer {
            hash: HASH,
            answers: answers.clone()
        }
    );
    // Packed, as any eMule packet may be.
    let mut packed = p;
    packed.payload.extend([0u8; 200].iter().map(|_| 0x93));
    let unpacked = packed.clone();
    assert!(packed.pack());
    assert_eq!(packed.protocol, 0xD4);
    let PeerPacket::MultiPacketAnswer { answers: got, .. } = parse(packed) else {
        panic!()
    };
    assert_eq!(got[..3], answers[..]);
    assert_eq!(got.len(), 3 + 200, "{unpacked:?}");
    assert!(got[3..].iter().all(|a| *a == MultiAnswer::Unknown(0x93)));
}

#[test]
fn truncated_multipackets() {
    let p = multi_packet(
        HASH,
        Some(1),
        &[MultiRequest::Sources2 {
            version: 4,
            options: 0,
        }],
    );
    for n in 0..p.payload.len() {
        if n == 24 {
            continue; // hash and size, no requests: valid
        }
        let mut q = p.clone();
        q.payload.truncate(n);
        assert!(PeerPacket::parse(q, ctx(true, 2)).is_err(), "{n} bytes");
    }
}
