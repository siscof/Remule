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
    wants_sources: bool,
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
            wants_sources: false,
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
    fn wants_sources(&self) -> bool {
        self.wants_sources
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

// ---- source exchange, secure ident and AICH through the session ----

mod sx_ident_aich {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::packets::AichRecovery;
    use crate::secident::{IdentConfig, IdentResult, Identity, Need, SecureIdent};
    use crate::sources::{AnswerBuilder, ExchangedSource};

    fn source(i: u8) -> ExchangedSource {
        ExchangedSource {
            id: u32::from_le_bytes([198, 51, 100, i]),
            port: 4662,
            server: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 4242),
            user_hash: Some(Md4Hash([i; 16])),
            crypt_options: Some(0x0D),
        }
    }

    fn wanting_sources() -> MockFile {
        let mut f = three_parts([false, false, false]);
        f.wants_sources = true;
        f
    }

    #[test]
    fn sources_are_asked_with_the_multipacket() {
        let mut r = Rig::connect(wanting_sources());
        r.sent();
        r.deliver(peer_hello(true).to_hello_answer().unwrap());
        let PeerPacket::MultiPacket { requests, .. } = &r.sent()[0] else {
            panic!()
        };
        assert!(requests.contains(&MultiRequest::Sources2 {
            version: 4,
            options: 0
        }));
        assert!(r.events().contains(&Event::SourcesRequested));

        let mut b = AnswerBuilder::new(FILE, true, 3, 4);
        b.add(&source(1));
        b.add(&source(2));
        r.deliver(b.finish().unwrap());
        assert_eq!(r.events(), [Event::Sources(vec![source(1), source(2)])]);

        // Another file's answer is not ours.
        let mut b = AnswerBuilder::new(Md4Hash([9; 16]), true, 3, 4);
        b.add(&source(3));
        r.deliver(b.finish().unwrap());
        assert!(matches!(r.events()[..], [Event::Unhandled(_)]));
    }

    #[test]
    fn an_old_peer_is_asked_with_its_own_packet() {
        let mut r = Rig::connect(wanting_sources());
        r.sent();
        r.deliver(peer_hello(false).to_hello_answer().unwrap());
        let sent = r.sent();
        assert!(sent.contains(&PeerPacket::RequestSources(FILE)), "{sent:?}");
        assert!(r.events().contains(&Event::SourcesRequested));

        // SX1 v3: hashes, hybrid IDs, no crypt byte.
        let mut b = AnswerBuilder::new(FILE, false, 3, 0);
        b.add(&source(1));
        r.deliver(b.finish().unwrap());
        let expected = ExchangedSource {
            crypt_options: None,
            ..source(1)
        };
        assert_eq!(r.events(), [Event::Sources(vec![expected])]);

        // A v4 layout from a v3 peer is dropped.
        let mut b = AnswerBuilder::new(FILE, false, 4, 0);
        b.add(&source(1));
        r.deliver(b.finish().unwrap());
        assert!(matches!(r.events()[..], [Event::SourcesRejected(_)]));
    }

    #[test]
    fn no_sources_are_asked_unless_wanted() {
        let mut r = Rig::connect(three_parts([false, false, false]));
        r.sent();
        r.deliver(peer_hello(true).to_hello_answer().unwrap());
        let PeerPacket::MultiPacket { requests, .. } = &r.sent()[0] else {
            panic!()
        };
        assert!(!requests
            .iter()
            .any(|q| matches!(q, MultiRequest::Sources | MultiRequest::Sources2 { .. })));
        assert!(!r.events().contains(&Event::SourcesRequested));
    }

    fn identity(seed: u64) -> Arc<Identity> {
        let ck = ed2k_formats::cryptkey_dat::CryptKey::generate(&mut StdRng::seed_from_u64(seed))
            .unwrap();
        Arc::new(Identity {
            key: ck.private_key().unwrap(),
            public: ck.public_key().unwrap(),
        })
    }

    fn cfg(ours: Arc<Identity>) -> IdentConfig {
        IdentConfig {
            ours,
            stored_key: None,
            peer_ip: Some(Ipv4Addr::new(127, 0, 0, 1)),
            our_id: 0x0200_007F,
            our_public_ip: None,
        }
    }

    /// Hand what the session sent to the peer's identification; return
    /// what the peer answers, and its verdict on us.
    fn to_peer(
        peer: &mut SecureIdent,
        sent: Vec<PeerPacket>,
    ) -> (Vec<Packet>, Option<IdentResult>) {
        let mut out = Vec::new();
        let mut verdict = None;
        for p in sent {
            match p {
                PeerPacket::SecIdentState { need, challenge } => {
                    out.extend(peer.on_state(need, challenge))
                }
                PeerPacket::PublicKey(k) => out.extend(peer.on_public_key(k)),
                PeerPacket::Signature { signature, ip_kind } => {
                    verdict = peer.on_signature(&signature, ip_kind)
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        (out, verdict)
    }

    fn handshaken() -> Rig {
        let mut r = Rig::connect(three_parts([false, false, false]));
        r.sent();
        r.deliver(peer_hello(true).to_hello_answer().unwrap());
        r.sent();
        r.events();
        r
    }

    #[test]
    fn both_sides_identify_through_the_session() {
        let (us, them) = (identity(1), identity(2));
        let mut r = handshaken();

        // The peer asks first, before the application started ours.
        let mut peer = SecureIdent::new(cfg(them.clone()), 3);
        r.deliver(peer.start(77).unwrap());
        assert!(r.sent().is_empty());

        let out = r.s.start_secure_ident(cfg(us.clone()), 1234);
        r.take_sent(out.send);
        // Our state, then our key for the peer's request; no signature
        // yet, as we do not have its key.
        let sent = r.sent();
        assert_eq!(
            sent[0],
            PeerPacket::SecIdentState {
                need: Need::KeyAndSignature,
                challenge: 1234
            }
        );
        assert_eq!(sent[1], PeerPacket::PublicKey(us.public.clone()));
        assert_eq!(sent.len(), 2);

        // The peer sends its key and, having ours, its signature.
        let (answer, verdict) = to_peer(&mut peer, sent);
        assert_eq!(verdict, None);
        for p in answer {
            r.deliver(p);
        }
        assert_eq!(
            r.events(),
            [Event::Identified(IdentResult::Passed {
                key: them.public.clone()
            })]
        );
        // Now we can sign for the peer.
        let (_, verdict) = to_peer(&mut peer, r.sent());
        assert_eq!(
            verdict,
            Some(IdentResult::Passed {
                key: us.public.clone()
            })
        );
    }

    #[test]
    fn a_signature_by_another_key_fails() {
        let (us, them, mallory) = (identity(1), identity(2), identity(3));
        let mut r = handshaken();
        // We know the peer's key from its credits; mallory signs instead.
        let mut c = cfg(us.clone());
        c.stored_key = Some(them.public.clone());
        let out = r.s.start_secure_ident(c, 99);
        r.take_sent(out.send);
        assert_eq!(
            r.sent(),
            [PeerPacket::SecIdentState {
                need: Need::Signature,
                challenge: 99
            }]
        );
        let mut fake = SecureIdent::new(cfg(mallory), 3);
        fake.on_public_key(us.public.clone());
        for p in fake.on_state(Need::Signature, 99) {
            r.deliver(p);
        }
        assert_eq!(r.events(), [Event::Identified(IdentResult::Failed)]);
    }

    fn recovery(part: u16) -> AichRecovery {
        AichRecovery {
            hash: FILE,
            part,
            root: AichHash([4; 20]),
            data: vec![1, 2, 3],
        }
    }

    #[test]
    fn aich_recovery_is_asked_once_and_answered() {
        let mut r = handshaken();
        let root = AichHash([4; 20]);
        let req = r.s.request_aich(1, root).unwrap();
        assert!(r.s.request_aich(2, root).is_none());
        assert_eq!(r.s.aich_pending(), Some(1));
        r.take_sent(vec![req]);
        assert_eq!(
            r.sent(),
            [PeerPacket::AichRequest {
                hash: FILE,
                part: 1,
                root
            }]
        );

        r.deliver(packets::aich_answer(&recovery(1)));
        assert_eq!(r.events(), [Event::AichRecovery(recovery(1))]);
        assert_eq!(r.s.aich_pending(), None);

        // A refusal, then an answer for another part.
        let req = r.s.request_aich(0, root).unwrap();
        r.take_sent(vec![req]);
        r.deliver(packets::aich_answer_failed(FILE));
        assert_eq!(r.events(), [Event::AichRecoveryFailed { part: 0 }]);
        let req = r.s.request_aich(0, root).unwrap();
        r.take_sent(vec![req]);
        r.deliver(packets::aich_answer(&recovery(2)));
        assert_eq!(r.events(), [Event::AichRecoveryFailed { part: 0 }]);

        // Unasked: aMule disconnects.
        r.deliver(packets::aich_answer(&recovery(1)));
        assert!(matches!(
            r.events()[..],
            [Event::Closed(CloseReason::Protocol(_))]
        ));
    }

    #[test]
    fn a_peer_without_aich_is_not_asked() {
        let mut r = Rig::connect(three_parts([false, false, false]));
        r.sent();
        r.deliver(peer_hello(false).to_hello_answer().unwrap());
        assert!(!r.s.peer_supports_aich());
        assert!(r.s.request_aich(0, AichHash([4; 20])).is_none());
    }
}
