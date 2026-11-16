// SPDX-License-Identifier: GPL-2.0-or-later
//! The upload session: against our own download session, every packet
//! through the real encoder and parser, and its checks one by one.

// The expected values are lists of byte ranges, often just one.
#![allow(clippy::single_range_in_vec_init)]

use std::ops::Range;
use std::time::Instant;

use ed2k_codec::Packet;
use ed2k_hash::{FileHashes, Hasher};
use ed2k_types::ed2k::{EMBLOCKSIZE, PARTSIZE};
use ed2k_types::Md4Hash;

use crate::download::{self, PartFile, Session, State};
use crate::hello::{CryptSettings, Hello, MiscOptions2};
use crate::packets::{self, MultiRequest, ParseContext, PeerPacket};
use crate::part_status::{part_count, PartStatus};
use crate::upload::{
    block_packets, compressible, Event, SharedInfo, Shares, UploadSession, UploadState,
};

const SIZE: u64 = 2 * PARTSIZE + 5_000;

fn hello(b: u8, id: u32) -> Hello {
    let mut h = Hello::amule(Md4Hash([b; 16]), id, 4662, "peer");
    h.misc2 = Some(MiscOptions2::amule(0, CryptSettings::default()));
    h
}

/// Text-like data: it compresses.
fn text(n: u64) -> Vec<u8> {
    let words = b"the quick brown fox jumps over the lazy dog ";
    (0..n)
        .map(|i| words[(i * 7 % 43) as usize] ^ ((i / 997) as u8 & 1))
        .collect()
}

fn hashes(d: &[u8]) -> FileHashes {
    let mut h = Hasher::new();
    h.update(d);
    h.finish()
}

fn shared(name: &str, d: &[u8], h: &FileHashes) -> SharedInfo {
    SharedInfo {
        hash: h.ed2k,
        name: name.into(),
        size: d.len() as u64,
        part_hashes: h.part_hashes.clone(),
        parts: PartStatus::Complete,
        aich_root: h.aich_root,
    }
}

/// The downloader's file: blocks handed out in order, bytes kept.
struct Sink {
    hash: Md4Hash,
    data: Vec<u8>,
    written: Vec<bool>,
    free: Vec<Range<u64>>,
    expected_hashes: Md4Hash,
    hash_set: bool,
    wants_sources: bool,
}

impl Sink {
    fn new(h: &FileHashes) -> Self {
        let mut free = Vec::new();
        let mut s = 0;
        while s < h.size {
            let part_end = ((s / PARTSIZE) + 1) * PARTSIZE;
            let e = (s + u64::from(EMBLOCKSIZE)).min(part_end).min(h.size);
            free.push(s..e);
            s = e;
        }
        Sink {
            hash: h.ed2k,
            data: vec![0; h.size as usize],
            written: vec![false; h.size as usize],
            free,
            expected_hashes: h.ed2k,
            hash_set: part_count(h.size) <= 1,
            wants_sources: false,
        }
    }

    fn done(&self) -> bool {
        self.written.iter().all(|&w| w)
    }
}

impl PartFile for Sink {
    fn hash(&self) -> Md4Hash {
        self.hash
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    fn has_part(&self, i: u64) -> bool {
        let s = (i * PARTSIZE) as usize;
        let e = ((i + 1) * PARTSIZE).min(self.size()) as usize;
        self.written[s..e].iter().all(|&w| w)
    }
    fn hash_set_needed(&self) -> bool {
        !self.hash_set
    }
    fn status(&self) -> PartStatus {
        PartStatus::Parts(
            (0..=self.size() / PARTSIZE)
                .map(|i| i < part_count(self.size()) && self.has_part(i))
                .collect(),
        )
    }
    fn complete_sources(&self) -> u16 {
        0
    }
    fn is_stopped(&self) -> bool {
        false
    }
    fn set_hash_set(&mut self, parts: Vec<Md4Hash>) -> bool {
        let ok = ed2k_hash::hash_of_part_hashes(&parts) == self.expected_hashes;
        self.hash_set |= ok;
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
        if !self.written[block.start as usize..block.end as usize]
            .iter()
            .all(|&w| w)
        {
            self.free.push(block);
        }
    }
    fn write(&mut self, start: u64, data: &[u8]) {
        let s = start as usize;
        self.data[s..s + data.len()].copy_from_slice(data);
        self.written[s..s + data.len()]
            .iter_mut()
            .for_each(|w| *w = true);
    }
    fn wants_sources(&self) -> bool {
        self.wants_sources
    }
}

fn wire(p: Packet, ctx: ParseContext) -> PeerPacket {
    let bytes = p.to_tcp_bytes().unwrap();
    PeerPacket::parse(Packet::parse_tcp(&bytes).unwrap(), ctx).unwrap()
}

/// A downloader (our download session) and an uploader (the upload
/// session under test) wired together.
struct Pair {
    down: Session,
    up: UploadSession,
    sink: Sink,
    shares: Vec<SharedInfo>,
    data: Vec<u8>,
    /// What to do on an upload request: queue at this rank, or accept.
    queue_at: Option<u16>,
    rate: u32,
    up_events: Vec<Event>,
    down_events: Vec<download::Event>,
    packets_sent: usize,
    packed_sent: usize,
}

impl Pair {
    fn new(name: &str, data: Vec<u8>, queue_at: Option<u16>, rate: u32) -> Pair {
        let h = hashes(&data);
        let sink = Sink::new(&h);
        let now = Instant::now();
        let (down, hello_pkt) = Session::connect(hello(0x11, 0x0100_000A), &sink, now).unwrap();
        let PeerPacket::Hello(peer) = wire(hello_pkt, ParseContext::default()) else {
            panic!("expected a hello")
        };
        let (up, out) = UploadSession::accepted(hello(0x22, 0x0200_000A), *Box::new(peer)).unwrap();
        let mut pair = Pair {
            down,
            up,
            sink,
            shares: vec![shared(name, &data, &h)],
            data,
            queue_at,
            rate,
            up_events: Vec::new(),
            down_events: Vec::new(),
            packets_sent: 0,
            packed_sent: 0,
        };
        pair.deliver_down(out.send);
        pair
    }

    fn deliver_down(&mut self, packets: Vec<Packet>) {
        for p in packets {
            let parsed = wire(p, self.down.parse_context());
            if matches!(
                parsed,
                PeerPacket::SendingPart(_) | PeerPacket::CompressedPart(_)
            ) {
                self.packets_sent += 1;
            }
            if matches!(parsed, PeerPacket::CompressedPart(_)) {
                self.packed_sent += 1;
            }
            let out = self.down.handle(parsed, &mut self.sink, Instant::now());
            self.down_events.extend(out.events);
            self.deliver_up(out.send);
        }
    }

    fn deliver_up(&mut self, packets: Vec<Packet>) {
        for p in packets {
            let parsed = wire(p, self.up.parse_context());
            let out = self.up.handle(parsed, &self.shares);
            let mut reply = out.send;
            for e in &out.events {
                match e {
                    Event::UploadRequested(_) => match self.queue_at {
                        Some(r) => reply.push(self.up.queue_rank(r)),
                        None => reply.push(self.up.accept()),
                    },
                    Event::BlocksRequested { blocks, .. } => {
                        for b in blocks {
                            let d = self.data[b.start as usize..b.end as usize].to_vec();
                            let name = self.shares[0].name.clone();
                            reply.extend(self.up.block_packets(b.clone(), &d, self.rate, &name));
                        }
                    }
                    _ => {}
                }
            }
            self.up_events.extend(out.events);
            self.deliver_down(reply);
        }
    }
}

#[test]
fn a_whole_file_goes_from_upload_to_download_packed() {
    let p = Pair::new("notes.txt", text(SIZE), None, 0);
    assert!(p.sink.done(), "not all received");
    assert_eq!(p.sink.data, p.data);
    assert!(p.packed_sent > 0, "text should go packed");
    assert!(p
        .up_events
        .iter()
        .any(|e| matches!(e, Event::FileRequested { parts: Some(_), .. })));
    assert!(p.down_events.contains(&download::Event::HashSetReceived));
    // The downloader runs out of blocks and ends the transfer.
    assert_eq!(p.down.state(), State::NoNeededParts);
    assert!(p.up_events.contains(&Event::UploadEnded));
    assert_eq!(p.up.state(), UploadState::Idle);
    assert!(p.up.pending_blocks().is_empty());
    assert!(p.packets_sent >= p.packed_sent);
}

#[test]
fn archives_and_fast_slots_go_unpacked() {
    let p = Pair::new("notes.zip", text(SIZE), None, 0);
    assert!(p.sink.done());
    assert_eq!(p.sink.data, p.data);
    assert_eq!(p.packed_sent, 0);
    // Text over a slot above 150 KiB/s.
    let p = Pair::new("small.txt", text(300_000), None, 200 * 1024);
    assert!(p.sink.done());
    assert_eq!(p.sink.data, p.data);
    assert_eq!(p.packed_sent, 0);
}

#[test]
fn a_queued_peer_waits_for_its_slot() {
    let mut p = Pair::new("a.txt", text(300_000), Some(4), 0);
    assert_eq!(p.up.state(), UploadState::Queued);
    assert!(p
        .down_events
        .contains(&download::Event::Queued { rank: Some(4) }));
    assert!(!p.sink.done());
    // A slot frees up.
    let accept = p.up.accept();
    p.deliver_down(vec![accept]);
    assert!(p.sink.done());
    assert_eq!(p.sink.data, p.data);
}

/// A queued peer whose connection went is called back when its turn
/// comes: our hello, its answer, then the slot (`US_CONNECTING`).
#[test]
fn a_waiting_peer_is_called_back_with_its_slot() {
    let mut p = Pair::new("a.txt", text(300_000), Some(2), 0);
    assert_eq!(p.up.state(), UploadState::Queued);
    let parts = p.down.peer_parts().cloned();
    assert!(parts.is_some());
    // The connection went; the downloader keeps what it knew.
    let _ = p.down.closed(&mut p.sink);
    let _ = p.up.closed();

    let (up, our_hello) = UploadSession::connect(hello(0x22, 0x0200_000A)).unwrap();
    assert_eq!(up.state(), UploadState::Handshake);
    p.up = up;
    let PeerPacket::Hello(h) = wire(our_hello, ParseContext::default()) else {
        panic!("expected a hello")
    };
    let (down, out) =
        Session::accepted(hello(0x11, 0x0100_000A), h, &p.sink, parts, Instant::now()).unwrap();
    assert_eq!(down.state(), State::OnQueue);
    p.down = down;
    p.up_events.clear();
    p.deliver_up(out.send);
    assert!(matches!(p.up_events[0], Event::Handshake(_)));
    assert!(p.up_events.contains(&Event::CalledBack));
    assert!(p.sink.done(), "not all received");
    assert_eq!(p.sink.data, p.data);
}

#[test]
fn a_callback_wants_a_hello_answer() {
    let shares: Vec<SharedInfo> = Vec::new();
    let (mut up, _) = UploadSession::connect(hello(0x22, 0x0200_000A)).unwrap();
    // An old eMule's capabilities may come first.
    let info = crate::hello::MuleInfo::Info(crate::hello::EmuleInfo::amule(4672, 0, None))
        .to_packet(false)
        .unwrap();
    let out = up.handle(wire(info, ParseContext::default()), &shares);
    assert!(out.events.is_empty());
    assert_eq!(up.state(), UploadState::Handshake);
    // Anything else is a protocol error.
    let out = up.handle(
        wire(packets::accept_upload_req(), ParseContext::default()),
        &shares,
    );
    assert!(matches!(out.events[..], [Event::Closed(_)]));
    assert_eq!(up.state(), UploadState::Closed);
}

#[test]
fn unknown_files_and_wrong_sizes_are_refused() {
    let data = text(1000);
    let h = hashes(&data);
    let shares = vec![shared("a.txt", &data, &h)];
    let (mut up, _) = UploadSession::accepted(hello(0x22, 1), hello(0x11, 2)).unwrap();
    let ctx = up.parse_context();
    let other = Md4Hash([9; 16]);
    let ask = |up: &mut UploadSession, p: Packet| up.handle(wire(p, ctx), &shares);

    let out = ask(
        &mut up,
        packets::multi_packet(other, None, &[MultiRequest::FileStatus]),
    );
    assert_eq!(out.send.len(), 1);
    assert!(matches!(wire(out.send[0].clone(), ctx), PeerPacket::NoSuchFile(h) if h == other));
    let out = ask(
        &mut up,
        packets::multi_packet(h.ed2k, Some(999), &[MultiRequest::FileStatus]),
    );
    assert!(matches!(
        wire(out.send[0].clone(), ctx),
        PeerPacket::NoSuchFile(_)
    ));
    let out = ask(&mut up, packets::set_req_file_id(other));
    assert!(matches!(
        wire(out.send[0].clone(), ctx),
        PeerPacket::NoSuchFile(_)
    ));
    // A name request for an unknown file gets no answer at all.
    let ext = crate::packets::FileRequestExt {
        parts: PartStatus::Complete,
        complete_sources: Some(0),
    };
    assert!(ask(&mut up, packets::request_file_name(other, Some(&ext)))
        .send
        .is_empty());
    // An upload request for an unknown file is ignored.
    assert!(ask(&mut up, packets::start_upload_req(other))
        .events
        .is_empty());
}

#[test]
fn block_requests_are_checked() {
    let data = text(2 * PARTSIZE);
    let h = hashes(&data);
    // We have part 0 only.
    let mut info = shared("a.txt", &data, &h);
    info.parts = PartStatus::Parts(vec![true, false, false]);
    let shares = vec![info];
    let (mut up, _) = UploadSession::accepted(hello(0x22, 1), hello(0x11, 2)).unwrap();
    let ctx = up.parse_context();
    let req = |up: &mut UploadSession, r: Vec<Range<u64>>| {
        up.handle(wire(packets::request_parts(h.ed2k, &r), ctx), &shares)
    };
    // Not in a slot: ignored.
    assert!(req(&mut up, vec![0..1000]).events.is_empty());
    up.accept();
    let max = 3 * u64::from(EMBLOCKSIZE);
    let out = req(&mut up, vec![0..1000, PARTSIZE..PARTSIZE + 10, 0..max + 1]);
    assert_eq!(
        out.events,
        [Event::BlocksRequested {
            hash: h.ed2k,
            blocks: vec![0..1000]
        }]
    );
    // Asked again: not twice.
    assert!(req(&mut up, vec![0..1000]).events.is_empty());
    // Past the end, or empty.
    assert!(req(&mut up, vec![2 * PARTSIZE - 10..2 * PARTSIZE + 10])
        .events
        .is_empty());
    // Sent, then asked again: still not twice.
    let pk = up.block_packets(0..1000, &data[..1000], 0, "a.txt");
    assert_eq!(pk.len(), 1);
    assert!(up.pending_blocks().is_empty());
    assert!(req(&mut up, vec![0..1000]).events.is_empty());
    // The peer gives up the slot.
    let out = up.handle(wire(packets::cancel_transfer(), ctx), &shares);
    assert_eq!(out.events, [Event::UploadEnded]);
    assert_eq!(up.state(), UploadState::Idle);
}

#[test]
fn hash_sets_and_aich_roots_are_answered() {
    let small = text(1000);
    let hs = hashes(&small);
    let big = text(PARTSIZE + 10);
    let hb = hashes(&big);
    let mut no_hashes = shared("b.txt", &big, &hb);
    no_hashes.part_hashes.clear();
    let (mut up, _) = UploadSession::accepted(hello(0x22, 1), hello(0x11, 2)).unwrap();
    let ctx = up.parse_context();
    // A one-part file: an answer without hashes.
    let shares = vec![shared("a.txt", &small, &hs)];
    let out = up.handle(wire(packets::hash_set_request(hs.ed2k), ctx), &shares);
    assert!(
        matches!(wire(out.send[0].clone(), ctx), PeerPacket::HashSetAnswer { parts, .. } if parts.is_empty())
    );
    // A multi-part file without its hashes: no answer.
    let shares = vec![no_hashes];
    assert!(up
        .handle(wire(packets::hash_set_request(hb.ed2k), ctx), &shares)
        .send
        .is_empty());
    // The AICH root, alone and in a multipacket.
    let shares = vec![shared("b.txt", &big, &hb)];
    let out = up.handle(wire(packets::aich_file_hash_req(hb.ed2k), ctx), &shares);
    assert_eq!(
        wire(out.send[0].clone(), ctx),
        PeerPacket::AichFileHashAns {
            hash: hb.ed2k,
            aich: hb.aich_root.unwrap()
        }
    );
    let out = up.handle(
        wire(
            packets::multi_packet(
                hb.ed2k,
                Some(hb.size),
                &[
                    MultiRequest::AichFileHash,
                    MultiRequest::Sources2 {
                        version: 4,
                        options: 0,
                    },
                ],
            ),
            ctx,
        ),
        &shares,
    );
    assert_eq!(
        out.events,
        [Event::SourcesRequested {
            hash: hb.ed2k,
            version: 4,
            options: 0
        }]
    );
    assert!(matches!(
        wire(out.send[0].clone(), ctx),
        PeerPacket::MultiPacketAnswer { .. }
    ));
}

#[test]
fn block_packets_follow_the_slot_speed() {
    let h = Md4Hash([1; 16]);
    let block = 0..u64::from(EMBLOCKSIZE);
    let d = vec![7u8; EMBLOCKSIZE as usize];
    // A new slot: 10 KiB packets.
    assert_eq!(block_packets(h, block.clone(), &d, 0, false).len(), 18);
    // 400 KiB/s: 50 KiB packets, the last one taking what is under twice that.
    assert_eq!(
        block_packets(h, block.clone(), &d, 400 * 1024, false).len(),
        3
    );
    // 1 MiB/s: the whole block is under two 128 KiB packets: one.
    assert_eq!(block_packets(h, block.clone(), &d, 1 << 20, false).len(), 1);
    // A small block goes whole.
    assert_eq!(block_packets(h, 0..12_000, &d[..12_000], 0, false).len(), 1);
    // Packed: one stream, its pieces naming the whole block.
    let packed = block_packets(h, block.clone(), &d, 0, true);
    assert_eq!(packed.len(), 1);
    let PeerPacket::CompressedPart(b) = wire(packed[0].clone(), ParseContext::default()) else {
        panic!()
    };
    assert_eq!(b.start, 0);
    // Data that does not shrink goes as it is.
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let noise: Vec<u8> = (0..20_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    let p = block_packets(h, 0..20_000, &noise, 0, true);
    assert!(matches!(
        wire(p[0].clone(), ParseContext::default()),
        PeerPacket::SendingPart(_)
    ));
}

#[test]
fn compressible_files() {
    for (name, yes) in [
        ("a.txt", true),
        ("a.TAR", true),
        ("README", true),
        ("a.zip", false),
        ("a.mp3", false),
        ("a.MKV", false),
        ("a.epub", false),
        ("a.iso", true),
    ] {
        assert_eq!(compressible(name), yes, "{name}");
    }
}

#[test]
fn queue_ranks_follow_the_protocol() {
    let (mut up, _) = UploadSession::accepted(hello(0x22, 1), hello(0x11, 2)).unwrap();
    assert!(matches!(
        wire(up.queue_rank(7), ParseContext::default()),
        PeerPacket::QueueRanking(7)
    ));
    // An eDonkey peer gets OP_QUEUERANK.
    let mut old = hello(0x11, 2);
    old.misc1 = None;
    old.misc2 = None;
    old.emule_version = None;
    let (mut up, _) = UploadSession::accepted(hello(0x22, 1), old).unwrap();
    assert!(matches!(
        wire(up.queue_rank(7), ParseContext::default()),
        PeerPacket::QueueRank(7)
    ));
    let _ = Shares::shared(&Vec::<SharedInfo>::new(), &Md4Hash([0; 16]));
}
