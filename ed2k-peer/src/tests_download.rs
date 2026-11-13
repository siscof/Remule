// SPDX-License-Identifier: GPL-2.0-or-later
//! The download session against a scripted peer. Every packet goes through
//! the real encoder and parser.

// The expected values are lists of byte ranges, often just one.
#![allow(clippy::single_range_in_vec_init)]

use std::io::Write as _;
use std::ops::Range;
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_types::ed2k::{DOWNLOADTIMEOUT, PARTSIZE};
use ed2k_types::{AichHash, Md4Hash};

use crate::download::{CloseReason, Event, PartFile, Session, State};
use crate::hello::{CryptSettings, Hello, MiscOptions1, MiscOptions2};
use crate::packets::{self, FileRequestExt, MultiAnswer, MultiRequest, ParseContext, PeerPacket};
use crate::part_status::PartStatus;

const FILE: Md4Hash = Md4Hash([0x11; 16]);
/// Three parts.
const SIZE: u64 = 2 * PARTSIZE + 1000;
const BLOCK: u64 = 1000;

fn byte_at(offset: u64) -> u8 {
    (offset % 251) as u8
}

fn content(r: Range<u64>) -> Vec<u8> {
    r.map(byte_at).collect()
}

/// A part file that hands out small blocks from the start of each part.
struct MockFile {
    size: u64,
    have: Vec<bool>,
    hash_set_needed: bool,
    good_hashes: Vec<Md4Hash>,
    stopped: bool,
    free: Vec<Range<u64>>,
    released: Vec<Range<u64>>,
    written: Vec<(u64, Vec<u8>)>,
}

impl MockFile {
    fn new(size: u64, have: Vec<bool>) -> Self {
        let parts = size.div_ceil(PARTSIZE);
        let mut free = Vec::new();
        for p in 0..parts {
            if !have[p as usize] {
                let s = p * PARTSIZE;
                free.extend((0..4).map(|i| s + i * BLOCK..s + (i + 1) * BLOCK));
            }
        }
        MockFile {
            size,
            have,
            hash_set_needed: false,
            good_hashes: vec![Md4Hash([1; 16]), Md4Hash([2; 16]), Md4Hash([3; 16])],
            stopped: false,
            free,
            released: Vec::new(),
            written: Vec::new(),
        }
    }

    fn written_bytes(&self) -> u64 {
        self.written.iter().map(|(_, d)| d.len() as u64).sum()
    }
}

impl PartFile for MockFile {
    fn hash(&self) -> Md4Hash {
        FILE
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn has_part(&self, i: u64) -> bool {
        self.have[i as usize]
    }
    fn hash_set_needed(&self) -> bool {
        self.hash_set_needed
    }
    fn status(&self) -> PartStatus {
        let mut p = self.have.clone();
        if self.size.is_multiple_of(PARTSIZE) {
            p.push(false);
        }
        PartStatus::Parts(p)
    }
    fn complete_sources(&self) -> u16 {
        2
    }
    fn is_stopped(&self) -> bool {
        self.stopped
    }
    fn set_hash_set(&mut self, parts: Vec<Md4Hash>) -> bool {
        let ok = parts == self.good_hashes;
        if ok {
            self.hash_set_needed = false;
        }
        ok
    }
    fn reserve_blocks(&mut self, peer: &PartStatus, max: usize) -> Vec<Range<u64>> {
        let mut out = Vec::new();
        self.free.retain(|b| {
            if out.len() < max && peer.has((b.start / PARTSIZE) as usize) {
                out.push(b.clone());
                false
            } else {
                true
            }
        });
        out
    }
    fn release_block(&mut self, block: Range<u64>) {
        self.released.push(block);
    }
    fn write(&mut self, start: u64, data: &[u8]) {
        assert_eq!(data, content(start..start + data.len() as u64));
        self.written.push((start, data.to_vec()));
    }
}

fn peer_hello(multi: bool) -> Hello {
    let mut h = Hello::amule(Md4Hash([0x22; 16]), 0x0100_007F, 4662, "peer");
    if !multi {
        h.misc1 = Some(MiscOptions1 {
            multi_packet: false,
            aich_version: 0,
            ..MiscOptions1::amule()
        });
        h.misc2 = Some(MiscOptions2::default());
    } else {
        h.misc2 = Some(MiscOptions2::amule(9, CryptSettings::default()));
    }
    h
}

fn ours() -> Hello {
    Hello::amule(Md4Hash([0x33; 16]), 0x0200_007F, 4663, "remule")
}

/// A session and its file, with packets going through bytes and back.
struct Rig {
    s: Session,
    f: MockFile,
    now: Instant,
    events: Vec<Event>,
    sent: Vec<PeerPacket>,
}

impl Rig {
    fn connect(f: MockFile) -> Self {
        let now = Instant::now();
        let (s, hello) = Session::connect(ours(), &f, now).unwrap();
        let mut rig = Rig {
            s,
            f,
            now,
            events: Vec::new(),
            sent: Vec::new(),
        };
        rig.take_sent(vec![hello]);
        rig
    }

    /// What we sent, parsed as the peer would (it knows our capabilities).
    fn take_sent(&mut self, packets: Vec<Packet>) {
        let ctx = ParseContext {
            unicode: true,
            extended_requests_version: 2,
        };
        for p in packets {
            let bytes = p.to_tcp_bytes().unwrap();
            let back = Packet::parse_tcp(&bytes).unwrap();
            self.sent.push(PeerPacket::parse(back, ctx).unwrap());
        }
    }

    fn deliver(&mut self, p: Packet) {
        let bytes = p.to_tcp_bytes().unwrap();
        let parsed =
            PeerPacket::parse(Packet::parse_tcp(&bytes).unwrap(), self.s.parse_context()).unwrap();
        let out = self.s.handle(parsed, &mut self.f, self.now);
        self.events.extend(out.events);
        self.take_sent(out.send);
    }

    fn tick(&mut self, after: Duration) {
        self.now += after;
        let out = self.s.tick(&mut self.f, self.now);
        self.events.extend(out.events);
        self.take_sent(out.send);
    }

    fn sent(&mut self) -> Vec<PeerPacket> {
        std::mem::take(&mut self.sent)
    }

    fn events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// The ranges in the part requests sent since the last call.
    fn requested(&mut self) -> Vec<Range<u64>> {
        self.sent()
            .into_iter()
            .flat_map(|p| match p {
                PeerPacket::RequestParts { hash, ranges } => {
                    assert_eq!(hash, FILE);
                    ranges
                }
                other => panic!("expected a part request, got {other:?}"),
            })
            .collect()
    }

    /// Hello answer, then the multipacket answer for a peer with `parts`.
    fn queue_up(&mut self, parts: PartStatus) {
        self.sent();
        self.deliver(peer_hello(true).to_hello_answer().unwrap());
        self.sent();
        self.deliver(packets::multi_packet_answer(
            FILE,
            &[
                MultiAnswer::FileName("file.iso".into()),
                MultiAnswer::FileStatus(parts),
            ],
            true,
        ));
        assert_eq!(self.s.state(), State::OnQueue);
        assert_eq!(self.sent(), [PeerPacket::StartUploadReq(FILE)]);
        self.events();
    }
}

fn three_parts(have: [bool; 3]) -> MockFile {
    MockFile::new(SIZE, have.to_vec())
}

#[test]
fn download_through_a_multipacket_peer() {
    let mut r = Rig::connect(three_parts([false, true, false]));
    let PeerPacket::Hello(h) = &r.sent()[0] else {
        panic!()
    };
    assert_eq!(h.name.as_deref(), Some("remule"));
    assert_eq!(r.s.state(), State::Handshake);

    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    assert!(matches!(r.events()[0], Event::Handshake(_)));
    assert_eq!(r.s.state(), State::Connected);
    assert_eq!(
        r.sent(),
        [PeerPacket::MultiPacket {
            hash: FILE,
            size: Some(SIZE),
            requests: vec![
                MultiRequest::FileName(Some(FileRequestExt {
                    parts: PartStatus::Parts(vec![false, true, false]),
                    complete_sources: Some(2),
                })),
                MultiRequest::FileStatus,
                MultiRequest::AichFileHash,
            ],
        }]
    );

    let aich = AichHash([5; 20]);
    r.deliver(packets::multi_packet_answer(
        FILE,
        &[
            MultiAnswer::FileName("file.iso".into()),
            MultiAnswer::FileStatus(PartStatus::Complete),
            MultiAnswer::AichFileHash(aich),
        ],
        true,
    ));
    assert_eq!(
        r.events(),
        [
            Event::FileName("file.iso".into()),
            Event::PeerParts(PartStatus::Complete),
            Event::Queued { rank: None },
            Event::AichFileHash(aich),
        ]
    );
    assert_eq!(r.sent(), [PeerPacket::StartUploadReq(FILE)]);
    assert_eq!(r.s.state(), State::OnQueue);

    r.deliver(packets::queue_ranking(5));
    assert_eq!(r.events(), [Event::Queued { rank: Some(5) }]);

    r.deliver(packets::accept_upload_req());
    assert_eq!(r.s.state(), State::Downloading);
    assert_eq!(r.events(), [Event::DownloadStarted]);
    let first = r.requested();
    assert_eq!(first, [0..1000, 1000..2000, 2000..3000]);

    // The first block in two pieces: the second completes it, and one more
    // block is asked for.
    r.deliver(packets::sending_part(FILE, 0, &content(0..400)));
    assert!(r.sent().is_empty());
    r.deliver(packets::sending_part(FILE, 400, &content(400..1000)));
    assert_eq!(r.requested(), [3000..4000]);
    assert_eq!(r.f.released, [0..1000]);

    // The second block compressed, in two pieces of one stream.
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&content(1000..2000)).unwrap();
    let stream = z.finish().unwrap();
    let (a, b) = stream.split_at(stream.len() / 2);
    let total = stream.len() as u32;
    r.deliver(packets::compressed_part(FILE, 1000..2000, total, a));
    r.deliver(packets::compressed_part(FILE, 1000..2000, total, b));
    assert_eq!(r.requested(), [2 * PARTSIZE..2 * PARTSIZE + 1000]);
    assert_eq!(r.f.written_bytes(), 2000);

    // Data nobody asked for is dropped.
    r.deliver(packets::sending_part(
        FILE,
        50_000,
        &content(50_000..50_100),
    ));
    assert_eq!(r.f.written_bytes(), 2000);

    // The peer ends the session: the rest goes back to the file.
    r.events();
    r.deliver(packets::out_of_part_reqs());
    assert_eq!(r.s.state(), State::OnQueue);
    assert_eq!(r.events(), [Event::DownloadStopped]);
    assert_eq!(
        r.f.released,
        [
            0..1000,
            1000..2000,
            2000..3000,
            3000..4000,
            2 * PARTSIZE..2 * PARTSIZE + 1000
        ]
    );
    assert_eq!(r.s.pending_blocks().count(), 0);
}

#[test]
fn old_peer_gets_separate_packets() {
    let mut r = Rig::connect(three_parts([false; 3]));
    r.sent();
    r.deliver(peer_hello(false).to_hello_answer().unwrap());
    assert_eq!(
        r.sent(),
        [
            PeerPacket::RequestFileName {
                hash: FILE,
                ext: Some(FileRequestExt {
                    parts: PartStatus::Parts(vec![false; 3]),
                    complete_sources: Some(2)
                })
            },
            PeerPacket::SetReqFileId(FILE),
        ]
    );
    r.deliver(packets::file_name(FILE, "f", true));
    assert_eq!(r.s.state(), State::Connected, "waits for the status");
    r.deliver(packets::file_status(
        FILE,
        &PartStatus::Parts(vec![true, false, false]),
    ));
    assert_eq!(r.sent(), [PeerPacket::StartUploadReq(FILE)]);
}

#[test]
fn a_one_part_file_needs_no_status() {
    let f = MockFile::new(5000, vec![false]);
    let mut r = Rig::connect(f);
    r.sent();
    r.deliver(peer_hello(false).to_hello_answer().unwrap());
    let sent = r.sent();
    assert_eq!(sent.len(), 1, "no OP_SETREQFILEID: {sent:?}");
    r.deliver(packets::file_name(FILE, "small", true));
    assert_eq!(r.s.state(), State::OnQueue);
    assert_eq!(r.s.peer_parts(), Some(&PartStatus::Complete));
}

#[test]
fn hash_set_first() {
    let mut f = three_parts([false; 3]);
    f.hash_set_needed = true;
    let mut r = Rig::connect(f);
    r.sent();
    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    r.sent();
    r.deliver(packets::file_status(FILE, &PartStatus::Complete));
    assert_eq!(r.s.state(), State::ReqHashSet);
    assert_eq!(r.sent(), [PeerPacket::HashSetRequest(FILE)]);

    let good = r.f.good_hashes.clone();
    r.deliver(packets::hash_set_answer(FILE, &good));
    assert_eq!(r.s.state(), State::OnQueue);
    assert!(r.events().contains(&Event::HashSetReceived));
    assert_eq!(r.sent(), [PeerPacket::StartUploadReq(FILE)]);

    // A second, unasked hash set breaks the protocol.
    r.deliver(packets::hash_set_answer(FILE, &good));
    assert_eq!(r.s.state(), State::Closed);
    assert!(matches!(
        r.events().last(),
        Some(Event::Closed(CloseReason::Protocol(_)))
    ));
}

#[test]
fn a_wrong_hash_set_closes() {
    let mut f = three_parts([false; 3]);
    f.hash_set_needed = true;
    let mut r = Rig::connect(f);
    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    r.deliver(packets::file_status(FILE, &PartStatus::Complete));
    r.deliver(packets::hash_set_answer(FILE, &[Md4Hash([9; 16])]));
    assert_eq!(r.s.state(), State::Closed);
}

#[test]
fn nothing_needed() {
    let mut r = Rig::connect(three_parts([true, false, true]));
    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    r.sent();
    r.deliver(packets::file_status(
        FILE,
        &PartStatus::Parts(vec![true, false, true]),
    ));
    assert_eq!(r.s.state(), State::NoNeededParts);
    assert!(r.sent().is_empty());
    assert!(r.events().contains(&Event::NoNeededParts));
}

#[test]
fn refusals_and_bad_answers() {
    let mut r = Rig::connect(three_parts([false; 3]));
    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    r.deliver(packets::no_such_file(FILE));
    assert_eq!(r.s.state(), State::Closed);
    assert_eq!(
        r.events().last(),
        Some(&Event::Closed(CloseReason::NoSuchFile))
    );

    // Four parts for a three-part file (two would be right for one of size PARTSIZE).
    let mut r = Rig::connect(three_parts([false; 3]));
    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    r.deliver(packets::file_status(
        FILE,
        &PartStatus::Parts(vec![true; 4]),
    ));
    assert_eq!(r.s.state(), State::Closed);

    // An answer about another file.
    let mut r = Rig::connect(three_parts([false; 3]));
    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    r.deliver(packets::file_name(Md4Hash([0x99; 16]), "x", true));
    assert_eq!(r.s.state(), State::Closed);
}

#[test]
fn exact_multiple_has_an_extra_part() {
    let f = MockFile::new(2 * PARTSIZE, vec![false, false]);
    let mut r = Rig::connect(f);
    r.deliver(peer_hello(true).to_hello_answer().unwrap());
    r.deliver(packets::file_status(
        FILE,
        &PartStatus::Parts(vec![true, true, false]),
    ));
    assert_eq!(r.s.state(), State::OnQueue);
}

#[test]
fn timeouts() {
    let mut r = Rig::connect(three_parts([false; 3]));
    r.tick(Duration::from_secs(39));
    assert_eq!(r.s.state(), State::Handshake);
    r.tick(Duration::from_secs(2));
    assert_eq!(r.s.state(), State::Closed);
    assert_eq!(r.events(), [Event::Closed(CloseReason::HandshakeTimeout)]);

    // A stalled transfer: cancel, back to the queue, blocks returned.
    let mut r = Rig::connect(three_parts([false; 3]));
    r.queue_up(PartStatus::Complete);
    r.deliver(packets::accept_upload_req());
    r.requested();
    r.tick(DOWNLOADTIMEOUT);
    assert_eq!(r.s.state(), State::Downloading);
    r.tick(Duration::from_secs(1));
    assert_eq!(r.s.state(), State::OnQueue);
    assert_eq!(r.sent(), [PeerPacket::CancelTransfer]);
    assert_eq!(r.f.released.len(), 3);
}

#[test]
fn stopped_file_refuses_the_slot() {
    let mut r = Rig::connect(three_parts([false; 3]));
    r.queue_up(PartStatus::Complete);
    r.f.stopped = true;
    r.deliver(packets::accept_upload_req());
    r.deliver(packets::accept_upload_req());
    assert_eq!(r.sent(), [PeerPacket::CancelTransfer], "cancel sent once");
    assert_eq!(r.s.state(), State::OnQueue);

    // Paused during the transfer.
    let mut r = Rig::connect(three_parts([false; 3]));
    r.queue_up(PartStatus::Complete);
    r.deliver(packets::accept_upload_req());
    r.requested();
    let out = r.s.stop(&mut r.f);
    assert_eq!(out.send, [packets::cancel_transfer()]);
    assert_eq!(r.s.state(), State::OnQueue);
    assert_eq!(r.f.released.len(), 3);
}

#[test]
fn corrupt_compressed_block() {
    let mut r = Rig::connect(three_parts([false; 3]));
    r.queue_up(PartStatus::Complete);
    r.deliver(packets::accept_upload_req());
    r.requested();
    r.events();
    r.deliver(packets::compressed_part(FILE, 0..1000, 10, &[0xFF; 10]));
    assert_eq!(r.events(), [Event::BlockFailed(0..1000)]);
    assert_eq!(r.f.released, [0..1000]);
    // The rest of the broken stream is ignored; the block keeps its slot.
    r.deliver(packets::compressed_part(FILE, 0..1000, 10, &[0x00; 10]));
    assert!(r.events().is_empty());
    assert_eq!(r.s.pending_blocks().count(), 3);
    // Closing does not give it back twice.
    r.s.closed(&mut r.f);
    assert_eq!(r.f.released.len(), 3);
}

#[test]
fn out_of_blocks_ends_the_transfer() {
    // Only the first part is wanted: four blocks.
    let mut r = Rig::connect(three_parts([false, true, true]));
    r.queue_up(PartStatus::Complete);
    r.deliver(packets::accept_upload_req());
    assert_eq!(r.requested(), [0..1000, 1000..2000, 2000..3000]);
    for b in [0..1000, 1000..2000, 2000..3000] {
        r.deliver(packets::sending_part(FILE, b.start, &content(b)));
    }
    assert_eq!(r.requested(), [3000..4000]);
    r.deliver(packets::sending_part(FILE, 3000, &content(3000..4000)));
    assert_eq!(r.sent(), [PeerPacket::CancelTransfer]);
    assert_eq!(r.s.state(), State::NoNeededParts);
    assert_eq!(r.f.written_bytes(), 4000);
}

#[test]
fn a_peer_calls_back_with_a_slot() {
    let f = three_parts([false; 3]);
    let now = Instant::now();
    // An eMule hash without CT_EMULE_VERSION: an old eMule, which wants
    // OP_EMULEINFO before the hello answer.
    let mut hello = peer_hello(true);
    hello.user_hash.0[5] = 14;
    hello.user_hash.0[14] = 111;
    hello.emule_version = None;
    let (mut s, out) =
        Session::accepted(ours(), hello, &f, Some(PartStatus::Complete), now).unwrap();
    assert_eq!(out.send.len(), 2);
    assert_eq!((out.send[0].protocol, out.send[0].opcode), (0xC5, 0x01));
    assert_eq!(out.send[1].opcode, 0x4C);
    assert_eq!(s.state(), State::OnQueue);

    let mut f = f;
    let out = s.handle(PeerPacket::AcceptUploadReq, &mut f, now);
    assert_eq!(s.state(), State::Downloading);
    assert_eq!(out.send.len(), 1);

    // Not queued: ask for the file at once.
    let f = three_parts([false; 3]);
    let (s, out) = Session::accepted(ours(), peer_hello(true), &f, None, now).unwrap();
    assert_eq!(s.state(), State::Connected);
    assert_eq!(out.send.len(), 2, "hello answer and multipacket");
    assert_eq!(out.send[1].opcode, 0xA4);
}

#[test]
fn old_emule_info_exchange() {
    let mut r = Rig::connect(three_parts([false; 3]));
    r.sent();
    let info = crate::hello::EmuleInfo::amule(4672, 3, None);
    r.deliver(crate::MuleInfo::Info(info).to_packet(false).unwrap());
    assert!(matches!(
        r.sent()[..],
        [PeerPacket::MuleInfo { answer: true, .. }]
    ));
    assert_eq!(r.s.parse_context().extended_requests_version, 2);
}
