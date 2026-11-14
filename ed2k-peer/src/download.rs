// SPDX-License-Identifier: GPL-2.0-or-later
//! Downloading one file from one peer over one connection, as a state
//! machine without IO (`CUpDownClient`'s download half: `DownloadClient.cpp`,
//! `ConnectionEstablished`, and the handlers in `ClientTCPSocket.cpp`).
//!
//! ```text
//!            connect: OP_HELLO ─▶ OP_HELLOANSWER ─┐
//!  accepted (peer's OP_HELLO) ─▶ OP_HELLOANSWER ──┤
//!                                                 ▼
//!   Connected ── file request ──▶ name / status ──▶ ReqHashSet ─▶ hash set ─┐
//!                                       │                                   │
//!                                       ├──▶ NoNeededParts                  │
//!                                       ▼                                   │
//!                           OnQueue (OP_STARTUPLOADREQ sent) ◀──────────────┘
//!                                       │ OP_ACCEPTUPLOADREQ
//!                                       ▼
//!                                  Downloading ── out of parts / timeout ──▶ OnQueue
//! ```
//!
//! The file itself (what we have, which blocks to fetch next, where data
//! goes) is behind [`PartFile`], so many sessions can share one file. A
//! queued peer usually hangs up and calls back when it has a slot for us;
//! [`Session::accepted`] with `queued` set picks that up.

use std::ops::Range;
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_types::ed2k::{CONNECTION_TIMEOUT, DOWNLOADTIMEOUT, SOURCEEXCHANGE2_VERSION};
use ed2k_types::{AichHash, Md4Hash};
use flate2::{Decompress, FlushDecompress, Status};

use crate::hello::{EmuleInfo, Hello, MuleInfo};
use crate::packets::{
    self, AichRecovery, Block, CompressedBlock, FileRequestExt, MultiAnswer, MultiRequest,
    ParseContext, PeerPacket,
};
use crate::part_status::{ed2k_part_count, part_count, PartStatus};
use crate::secident::{IdentConfig, IdentResult, Need, SecureIdent};
use crate::sources::{self, ExchangedSource};

/// Blocks asked for at once: one `OP_REQUESTPARTS` holds three.
pub const PIPELINE: usize = 3;

/// The file being downloaded, as the session needs it. Implemented by the
/// part file (and by test doubles).
pub trait PartFile {
    fn hash(&self) -> Md4Hash;
    fn size(&self) -> u64;
    /// Whether part `i` is complete and verified.
    fn has_part(&self, i: u64) -> bool;
    /// Whether the part hashes are still missing (`IsHashSetNeeded`).
    fn hash_set_needed(&self) -> bool;
    /// Our part status, sent with an extended file request.
    fn status(&self) -> PartStatus;
    /// `m_nCompleteSourcesCount`
    fn complete_sources(&self) -> u16;
    /// Paused or stopped: refuse a slot, end a transfer.
    fn is_stopped(&self) -> bool;
    /// Take part hashes from a peer. False if they do not hash to the file
    /// hash (`LoadHashsetFromFile`).
    fn set_hash_set(&mut self, parts: Vec<Md4Hash>) -> bool;
    /// Reserve up to `max` blocks this peer has and nobody else is fetching
    /// (`GetNextRequestedBlock`). Each at most
    /// [`EMBLOCKSIZE`](ed2k_types::ed2k::EMBLOCKSIZE), within one part.
    fn reserve_blocks(&mut self, peer: &PartStatus, max: usize) -> Vec<Range<u64>>;
    /// Give a reserved block back, finished or not (`RemoveBlockFromList`).
    /// The file knows from its gaps what was written.
    fn release_block(&mut self, block: Range<u64>);
    /// Store data (`WriteToBuffer`). `start..start + data.len()` lies inside
    /// a block reserved by this session.
    fn write(&mut self, start: u64, data: &[u8]);
    /// Ask this peer for other sources with the file request. The download
    /// queue decides, with
    /// [`source_request_allowed`](crate::sources::source_request_allowed).
    fn wants_sources(&self) -> bool {
        false
    }
}

/// `DS_*`, those a connected download goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for the hello answer to our hello.
    Handshake,
    /// File requested; waiting for its name and status.
    Connected,
    /// `OP_HASHSETREQUEST` sent.
    ReqHashSet,
    /// `OP_STARTUPLOADREQ` sent, or waiting for a slot.
    OnQueue,
    /// The peer has nothing we need.
    NoNeededParts,
    Downloading,
    Closed,
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// No hello answer within [`CONNECTION_TIMEOUT`].
    HandshakeTimeout,
    /// The peer does not have the file (`OP_FILEREQANSNOFIL`).
    NoSuchFile,
    /// The peer broke the protocol; aMule disconnects.
    Protocol(String),
    /// The application ended it, or the connection went away.
    Disconnected,
}

/// Something for the application.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The peer's hello, once the handshake is done.
    Handshake(Box<Hello>),
    /// The name the peer has the file under.
    FileName(String),
    /// What the peer has of the file.
    PeerParts(PartStatus),
    HashSetReceived,
    /// We are in the peer's queue; the rank when it says.
    Queued {
        rank: Option<u32>,
    },
    NoNeededParts,
    /// We have a slot.
    DownloadStarted,
    /// Data stored in the file.
    Received(Range<u64>),
    /// A compressed block did not inflate; it was given back to the file.
    BlockFailed(Range<u64>),
    /// The transfer ended: the peer ran out of slots for us, or stalled.
    DownloadStopped,
    AichFileHash(AichHash),
    /// Sources were asked for with the file request (`SetLastAskedForSources`).
    SourcesRequested,
    /// Other sources of the file, from the peer (source exchange). They are
    /// not filtered: bad and banned addresses are the application's.
    Sources(Vec<ExchangedSource>),
    /// A source answer that does not fit its version; aMule drops it.
    SourcesRejected(String),
    /// The peer's secure identification ended.
    Identified(IdentResult),
    /// Recovery data for the part asked with [`Session::request_aich`].
    AichRecovery(AichRecovery),
    /// The peer could not, or did not, send it.
    AichRecoveryFailed {
        part: u16,
    },
    Closed(CloseReason),
    /// A packet this session does not handle (uploads, chat, sources, …).
    Unhandled(Box<PeerPacket>),
}

/// What handling something produced.
#[derive(Debug, Default)]
pub struct Output {
    pub events: Vec<Event>,
    pub send: Vec<Packet>,
}

impl Output {
    pub fn is_closed(&self) -> bool {
        self.events.iter().any(|e| matches!(e, Event::Closed(_)))
    }
}

/// A block we asked for (`Pending_Block_Struct`).
#[derive(Debug)]
struct Pending {
    block: Range<u64>,
    /// The inflater of a compressed block, created by its first piece.
    zstream: Option<Decompress>,
    /// The stream broke: the block was given back, and the rest of the
    /// stream is ignored (`fZStreamError`).
    failed: bool,
}

/// The peer's capabilities that change what we send, from its hello or
/// its `OP_EMULEINFO`.
#[derive(Debug, Clone, Copy, Default)]
struct PeerCaps {
    unicode: bool,
    extended_requests: u8,
    multi_packet: bool,
    ext_multi_packet: bool,
    aich: bool,
    large_files: bool,
    /// Speaks the eMule protocol (`ExtProtocolAvailable`).
    ext_protocol: bool,
    source_exchange1: u8,
    source_exchange2: bool,
    /// Secure ident versions (`m_bySupportSecIdent`).
    secure_ident: u8,
}

/// One connection to a peer, downloading one file.
#[derive(Debug)]
pub struct Session {
    ours: Hello,
    state: State,
    file: Md4Hash,
    size: u64,
    peer: Option<Hello>,
    caps: PeerCaps,
    peer_parts: Option<PartStatus>,
    hash_set_requested: bool,
    sent_cancel: bool,
    pending: Vec<Pending>,
    started: Instant,
    last_block: Instant,
    ident: Option<SecureIdent>,
    /// A state that came before [`Session::start_secure_ident`].
    early_ident_state: Option<(Need, u32)>,
    /// The AICH recovery asked for (`m_fAICHRequested`): part and root.
    aich_request: Option<(u16, AichHash)>,
}

/// `IsLowID`
fn is_low_id(id: u32) -> bool {
    id < 0x0100_0000
}

/// `GetHashType() == SO_EMULE`: eMule marks its user hashes.
fn emule_user_hash(h: Md4Hash) -> bool {
    h.0[5] == 14 && h.0[14] == 111
}

impl Session {
    fn new(ours: Hello, file: &dyn PartFile, state: State, now: Instant) -> Self {
        Session {
            ours,
            state,
            file: file.hash(),
            size: file.size(),
            peer: None,
            caps: PeerCaps::default(),
            peer_parts: None,
            hash_set_requested: false,
            sent_cancel: false,
            pending: Vec::new(),
            started: now,
            last_block: now,
            ident: None,
            early_ident_state: None,
            aich_request: None,
        }
    }

    /// We connected to the peer: send our hello, then the file request once
    /// it answers.
    pub fn connect(
        ours: Hello,
        file: &dyn PartFile,
        now: Instant,
    ) -> Result<(Session, Packet), ed2k_codec::TagError> {
        let hello = ours.to_hello()?;
        Ok((Session::new(ours, file, State::Handshake, now), hello))
    }

    /// The peer connected to us and sent `hello`, and the application
    /// matched it to a source of `file`. With `queued` (the part status it
    /// sent on the connection that queued us, which aMule keeps on the
    /// client), we wait for `OP_ACCEPTUPLOADREQ`; otherwise we ask for the
    /// file now (`ConnectionEstablished` for `DS_CONNECTING` and friends).
    pub fn accepted(
        ours: Hello,
        hello: Hello,
        file: &dyn PartFile,
        queued: Option<PartStatus>,
        now: Instant,
    ) -> Result<(Session, Output), ed2k_codec::TagError> {
        let mut s = Session::new(ours, file, State::Connected, now);
        let mut out = Output::default();
        // An eMule without CT_EMULE_VERSION expects the old capability packet.
        if emule_user_hash(hello.user_hash) && !hello.is_emule() {
            out.send
                .push(MuleInfo::Info(s.our_mule_info()).to_packet(false)?);
        }
        out.send.push(s.ours.to_hello_answer()?);
        s.peer_said_hello(hello, &mut out);
        if let Some(parts) = queued {
            s.peer_parts = Some(parts);
            s.state = State::OnQueue;
        } else {
            s.send_file_request(file, &mut out);
        }
        Ok((s, out))
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn peer(&self) -> Option<&Hello> {
        self.peer.as_ref()
    }

    pub fn peer_parts(&self) -> Option<&PartStatus> {
        self.peer_parts.as_ref()
    }

    /// The blocks requested and not finished.
    pub fn pending_blocks(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.pending.iter().map(|p| p.block.clone())
    }

    /// How to parse what this peer sends.
    pub fn parse_context(&self) -> ParseContext {
        ParseContext {
            unicode: self.caps.unicode,
            extended_requests_version: self.caps.extended_requests,
        }
    }

    fn our_mule_info(&self) -> EmuleInfo {
        let ident = self.ours.misc1.map_or(0, |m| u32::from(m.secure_ident));
        EmuleInfo::amule(self.ours.udp_port, ident, self.ours.mod_version.clone())
    }

    /// Record the peer's hello (`ProcessHelloTypePacket`).
    fn peer_said_hello(&mut self, hello: Hello, out: &mut Output) {
        let m1 = hello.misc1.unwrap_or_default();
        let m2 = hello.misc2.unwrap_or_default();
        self.caps = PeerCaps {
            unicode: m1.unicode,
            extended_requests: m1.extended_requests_version,
            multi_packet: m1.multi_packet,
            ext_multi_packet: m2.ext_multi_packet,
            aich: m1.aich_version & 1 == 1,
            large_files: m2.large_files,
            ext_protocol: hello.misc1.is_some() || hello.is_emule(),
            source_exchange1: m1.source_exchange1_version,
            source_exchange2: m2.source_exchange2,
            secure_ident: m1.secure_ident,
        };
        out.events.push(Event::Handshake(Box::new(hello.clone())));
        self.peer = Some(hello);
    }

    // --------------------------------------------------------- sending ---

    /// Whether the peer can be asked for sources (the protocol half of
    /// `IsSourceRequestAllowed`).
    fn can_exchange_sources(&self) -> bool {
        self.caps.ext_protocol && (self.caps.source_exchange2 || self.caps.source_exchange1 > 1)
    }

    /// `SendFileRequest`
    fn send_file_request(&mut self, file: &dyn PartFile, out: &mut Output) {
        self.state = State::Connected;
        let ask_sources = file.wants_sources() && self.can_exchange_sources();
        let ext = (self.caps.extended_requests > 0).then(|| FileRequestExt {
            parts: file.status(),
            complete_sources: (self.caps.extended_requests > 1).then(|| file.complete_sources()),
        });
        let several_parts = part_count(self.size) > 1;
        if self.caps.multi_packet {
            let mut reqs = vec![MultiRequest::FileName(ext)];
            if several_parts {
                reqs.push(MultiRequest::FileStatus);
            }
            if ask_sources {
                reqs.push(if self.caps.source_exchange2 {
                    MultiRequest::Sources2 {
                        version: SOURCEEXCHANGE2_VERSION,
                        options: 0,
                    }
                } else {
                    MultiRequest::Sources
                });
            }
            if self.caps.aich {
                reqs.push(MultiRequest::AichFileHash);
            }
            let size = self.caps.ext_multi_packet.then_some(self.size);
            out.send.push(packets::multi_packet(self.file, size, &reqs));
        } else {
            out.send
                .push(packets::request_file_name(self.file, ext.as_ref()));
            if several_parts {
                out.send.push(packets::set_req_file_id(self.file));
            }
            if ask_sources {
                out.send.push(if self.caps.source_exchange2 {
                    packets::request_sources2(self.file)
                } else {
                    packets::request_sources(self.file)
                });
            }
            if self.caps.aich {
                out.send.push(packets::aich_file_hash_req(self.file));
            }
        }
        if ask_sources {
            out.events.push(Event::SourcesRequested);
        }
    }

    /// Start secure identification (`InfoPacketsReceived`), once the
    /// handshake is done and the application has looked up the peer's
    /// credits. `challenge` should be random.
    pub fn start_secure_ident(&mut self, cfg: IdentConfig, challenge: u32) -> Output {
        let mut out = Output::default();
        let mut ident = SecureIdent::new(cfg, self.caps.secure_ident);
        out.send.extend(ident.start(challenge));
        if let Some((need, ch)) = self.early_ident_state.take() {
            out.send.extend(ident.on_state(need, ch));
        }
        self.ident = Some(ident);
        out
    }

    /// `SendAICHRequest`: ask for the recovery data of `part` under `root`.
    /// `None` if the peer does not do AICH or a request is pending.
    pub fn request_aich(&mut self, part: u16, root: AichHash) -> Option<Packet> {
        if !self.caps.aich || self.aich_request.is_some() || self.state == State::Closed {
            return None;
        }
        self.aich_request = Some((part, root));
        Some(packets::aich_request(self.file, part, root))
    }

    /// The AICH recovery asked for and not answered (`IsAICHReqPending`).
    pub fn aich_pending(&self) -> Option<u16> {
        self.aich_request.map(|(p, _)| p)
    }

    /// Whether the peer supports AICH (`IsSupportingAICH`).
    pub fn peer_supports_aich(&self) -> bool {
        self.caps.aich
    }

    fn send_hash_set_request(&mut self, out: &mut Output) {
        out.send.push(packets::hash_set_request(self.file));
        self.hash_set_requested = true;
        self.state = State::ReqHashSet;
    }

    fn send_start_upload_req(&mut self, out: &mut Output) {
        out.send.push(packets::start_upload_req(self.file));
        self.state = State::OnQueue;
        out.events.push(Event::Queued { rank: None });
    }

    /// `HasPartWeNeed`
    fn has_part_we_need(&self, file: &dyn PartFile) -> bool {
        let Some(parts) = &self.peer_parts else {
            return false;
        };
        (0..part_count(self.size)).any(|i| parts.has(i as usize) && !file.has_part(i))
    }

    /// After name and status: hash set, queue, or nothing to do.
    fn after_status(&mut self, file: &dyn PartFile, out: &mut Output) {
        if file.hash_set_needed() {
            self.send_hash_set_request(out);
        } else if self.has_part_we_need(file) {
            self.send_start_upload_req(out);
        } else {
            self.state = State::NoNeededParts;
            out.events.push(Event::NoNeededParts);
        }
    }

    /// `SendBlockRequests`: top the pipeline up to [`PIPELINE`] blocks.
    /// With nothing left to fetch from this peer, end the transfer.
    fn request_blocks(&mut self, file: &mut dyn PartFile, out: &mut Output) {
        let parts = self
            .peer_parts
            .clone()
            .unwrap_or(PartStatus::Parts(Vec::new()));
        let want = PIPELINE.saturating_sub(self.pending.len());
        let mut new = if want > 0 {
            file.reserve_blocks(&parts, want)
        } else {
            Vec::new()
        };
        new.truncate(want);
        // A peer without large-file support cannot be asked past 4 GiB.
        if !self.caps.large_files {
            let (ok, too_far): (Vec<_>, Vec<_>) =
                new.into_iter().partition(|b| b.end <= u64::from(u32::MAX));
            too_far.into_iter().for_each(|b| file.release_block(b));
            new = ok;
        }
        if new.is_empty() {
            if self.pending.is_empty() {
                self.send_cancel(out);
                self.state = State::NoNeededParts;
                out.events.push(Event::NoNeededParts);
            }
            return;
        }
        out.send.push(packets::request_parts(self.file, &new));
        self.pending.extend(new.into_iter().map(|block| Pending {
            block,
            zstream: None,
            failed: false,
        }));
    }

    fn send_cancel(&mut self, out: &mut Output) {
        if !self.sent_cancel {
            out.send.push(packets::cancel_transfer());
            self.sent_cancel = true;
        }
    }

    fn release_all(&mut self, file: &mut dyn PartFile) {
        for p in self.pending.drain(..) {
            if !p.failed {
                file.release_block(p.block);
            }
        }
    }

    /// Leave `Downloading` for `next` (`SetDownloadState` clearing the
    /// block requests).
    fn stop_downloading(&mut self, file: &mut dyn PartFile, next: State, out: &mut Output) {
        if self.state == State::Downloading {
            self.release_all(file);
            out.events.push(Event::DownloadStopped);
        }
        self.state = next;
    }

    fn close(&mut self, file: &mut dyn PartFile, why: CloseReason, out: &mut Output) {
        if self.state != State::Closed {
            self.release_all(file);
            self.state = State::Closed;
            out.events.push(Event::Closed(why));
        }
    }

    fn protocol_error(&mut self, file: &mut dyn PartFile, why: String, out: &mut Output) {
        self.close(file, CloseReason::Protocol(why), out);
    }

    // ------------------------------------------------------- receiving ---

    /// Handle a packet from the peer, parsed with [`Session::parse_context`].
    pub fn handle(&mut self, packet: PeerPacket, file: &mut dyn PartFile, now: Instant) -> Output {
        let mut out = Output::default();
        if self.state == State::Closed {
            return out;
        }
        if let Err(why) = self.dispatch(packet, file, now, &mut out) {
            self.protocol_error(file, why, &mut out);
        }
        out
    }

    fn wrong_file(&self, hash: Md4Hash, what: &str) -> Result<(), String> {
        if hash == self.file {
            Ok(())
        } else {
            Err(format!("{what} for another file ({hash})"))
        }
    }

    fn dispatch(
        &mut self,
        packet: PeerPacket,
        file: &mut dyn PartFile,
        now: Instant,
        out: &mut Output,
    ) -> Result<(), String> {
        let handshaking = self.state == State::Handshake;
        match packet {
            PeerPacket::HelloAnswer(hello) if handshaking => {
                self.peer_said_hello(hello, out);
                self.send_file_request(file, out);
            }
            // An old eMule sends its capabilities separately.
            PeerPacket::MuleInfo {
                info: MuleInfo::Info(info),
                answer,
            } => {
                self.caps.extended_requests = info.extended_requests;
                self.caps.ext_protocol = true;
                self.caps.secure_ident = (info.features & 3) as u8;
                self.caps.source_exchange1 = info.source_exchange;
                if info.compression == 0 {
                    self.caps.source_exchange1 = 0;
                    self.caps.extended_requests = 0;
                }
                // Implied by old versions.
                if info.version > 0x21 && info.version < 0x25 {
                    self.caps.source_exchange1 = 1;
                }
                if !answer {
                    let reply = MuleInfo::Info(self.our_mule_info())
                        .to_packet(true)
                        .map_err(|e| e.to_string())?;
                    out.send.push(reply);
                }
            }
            PeerPacket::MuleInfo { .. } => {}
            p if handshaking => {
                // CheckHandshakeFinished: aMule ignores or refuses these.
                out.events.push(Event::Unhandled(Box::new(p)));
            }
            PeerPacket::FileName { hash, name } => {
                self.wrong_file(hash, "file name")?;
                self.file_name(name, file, out);
            }
            PeerPacket::FileStatus { hash, parts } => {
                self.wrong_file(hash, "file status")?;
                self.file_status(parts, file, out)?;
            }
            PeerPacket::MultiPacketAnswer { hash, answers } => {
                self.wrong_file(hash, "multipacket answer")?;
                for a in answers {
                    match a {
                        MultiAnswer::FileName(name) => self.file_name(name, file, out),
                        MultiAnswer::FileStatus(parts) => self.file_status(parts, file, out)?,
                        MultiAnswer::AichFileHash(h) => out.events.push(Event::AichFileHash(h)),
                        MultiAnswer::Unknown(_) => {}
                    }
                }
            }
            PeerPacket::AichFileHashAns { hash, aich } => {
                self.wrong_file(hash, "AICH file hash")?;
                out.events.push(Event::AichFileHash(aich));
            }
            PeerPacket::NoSuchFile(hash) => {
                self.wrong_file(hash, "no such file")?;
                self.close(file, CloseReason::NoSuchFile, out);
            }
            PeerPacket::HashSetAnswer { hash, parts } => {
                self.wrong_file(hash, "hash set")?;
                if !self.hash_set_requested {
                    return Err("unsolicited hash set".into());
                }
                self.hash_set_requested = false;
                if !file.set_hash_set(parts) {
                    return Err("hash set does not match the file hash".into());
                }
                out.events.push(Event::HashSetReceived);
                if self.has_part_we_need(file) {
                    self.send_start_upload_req(out);
                } else {
                    self.state = State::NoNeededParts;
                    out.events.push(Event::NoNeededParts);
                }
            }
            PeerPacket::QueueRanking(rank) => out.events.push(Event::Queued {
                rank: Some(rank.into()),
            }),
            PeerPacket::QueueRank(rank) => out.events.push(Event::Queued { rank: Some(rank) }),
            PeerPacket::AcceptUploadReq => self.accept(file, now, out),
            PeerPacket::SendingPart(b) => self.data(b, file, now, out),
            PeerPacket::CompressedPart(b) => self.compressed(b, file, now, out),
            PeerPacket::OutOfPartReqs => {
                if self.state == State::Downloading {
                    self.stop_downloading(file, State::OnQueue, out);
                }
            }
            PeerPacket::AnswerSources { hash, body } if hash == self.file => {
                self.sources(
                    sources::parse_answer(&body, false, self.caps.source_exchange1),
                    out,
                );
            }
            PeerPacket::AnswerSources2 {
                version,
                hash,
                body,
            } if hash == self.file => {
                self.sources(sources::parse_answer(&body, true, version), out);
            }
            PeerPacket::SecIdentState { need, challenge } => match &mut self.ident {
                Some(ident) => out.send.extend(ident.on_state(need, challenge)),
                None => self.early_ident_state = Some((need, challenge)),
            },
            PeerPacket::PublicKey(key) if self.ident.is_some() => {
                let ident = self.ident.as_mut().unwrap();
                out.send.extend(ident.on_public_key(key));
            }
            PeerPacket::Signature { signature, ip_kind } if self.ident.is_some() => {
                let ident = self.ident.as_mut().unwrap();
                if let Some(r) = ident.on_signature(&signature, ip_kind) {
                    out.events.push(Event::Identified(r));
                }
            }
            PeerPacket::AichAnswer(answer) => {
                let Some((part, _)) = self.aich_request.take() else {
                    return Err("unrequested AICH answer".into());
                };
                match answer {
                    Some(r) if r.hash == self.file && r.part == part => {
                        out.events.push(Event::AichRecovery(r))
                    }
                    _ => out.events.push(Event::AichRecoveryFailed { part }),
                }
            }
            p => out.events.push(Event::Unhandled(Box::new(p))),
        }
        Ok(())
    }

    fn sources(
        &mut self,
        parsed: Result<Vec<ExchangedSource>, sources::BadAnswer>,
        out: &mut Output,
    ) {
        match parsed {
            Ok(v) => out.events.push(Event::Sources(v)),
            Err(e) => out.events.push(Event::SourcesRejected(e.0)),
        }
    }

    /// `ProcessFileInfo`: a file of one part is complete at the peer.
    fn file_name(&mut self, name: String, file: &dyn PartFile, out: &mut Output) {
        out.events.push(Event::FileName(name));
        if part_count(self.size) <= 1 && self.state == State::Connected {
            self.peer_parts = Some(PartStatus::Complete);
            out.events.push(Event::PeerParts(PartStatus::Complete));
            self.after_status(file, out);
        }
    }

    /// `ProcessFileStatus`
    fn file_status(
        &mut self,
        parts: PartStatus,
        file: &dyn PartFile,
        out: &mut Output,
    ) -> Result<(), String> {
        let expected = ed2k_part_count(self.size);
        if parts.wire_count() != 0 && parts.wire_count() as u64 != expected {
            return Err(format!(
                "file status with {} parts, expected {expected}",
                parts.wire_count()
            ));
        }
        self.peer_parts = Some(parts.clone());
        out.events.push(Event::PeerParts(parts));
        if self.state == State::Connected {
            self.after_status(file, out);
        }
        Ok(())
    }

    /// `OP_ACCEPTUPLOADREQ`
    fn accept(&mut self, file: &mut dyn PartFile, now: Instant, out: &mut Output) {
        if file.is_stopped() {
            self.send_cancel(out);
            self.state = State::OnQueue;
            return;
        }
        if self.state != State::OnQueue {
            return;
        }
        self.state = State::Downloading;
        self.sent_cancel = false;
        self.last_block = now;
        out.events.push(Event::DownloadStarted);
        self.request_blocks(file, out);
    }

    fn pending_at(&self, hash: Md4Hash, start: u64) -> Option<usize> {
        if hash != self.file {
            return None;
        }
        self.pending
            .iter()
            .position(|p| p.block.start <= start && start < p.block.end)
    }

    /// The pending block `i` was written up to `end`: done if that is its end.
    fn written(&mut self, i: usize, end: u64, file: &mut dyn PartFile, out: &mut Output) {
        if end >= self.pending[i].block.end {
            let p = self.pending.remove(i);
            file.release_block(p.block);
            self.request_blocks(file, out);
        }
    }

    /// Data while not downloading is refused as aMule does: cancel, unless
    /// the file is fine and we just are not in the transfer state.
    fn not_receiving(&mut self, file: &dyn PartFile, out: &mut Output) -> bool {
        if self.state != State::Downloading {
            return true;
        }
        if file.is_stopped() {
            self.send_cancel(out);
            self.state = State::OnQueue;
            return true;
        }
        false
    }

    /// `ProcessBlockPacket`, plain.
    fn data(&mut self, b: Block, file: &mut dyn PartFile, now: Instant, out: &mut Output) {
        if self.not_receiving(file, out) {
            return;
        }
        self.last_block = now;
        let Some(i) = self.pending_at(b.hash, b.start) else {
            return; // not asked for: dropped, as aMule does
        };
        let block = self.pending[i].block.clone();
        // Never write past what was reserved.
        let end = b.range().end.min(block.end);
        let data = &b.data[..(end - b.start) as usize];
        file.write(b.start, data);
        out.events.push(Event::Received(b.start..end));
        self.written(i, end, file, out);
    }

    /// `ProcessBlockPacket`, packed: inflate the piece into the block.
    fn compressed(
        &mut self,
        b: CompressedBlock,
        file: &mut dyn PartFile,
        now: Instant,
        out: &mut Output,
    ) {
        if self.not_receiving(file, out) {
            return;
        }
        self.last_block = now;
        let Some(i) = self.pending_at(b.hash, b.start) else {
            return;
        };
        let p = &mut self.pending[i];
        if p.failed || p.block.start != b.start {
            return;
        }
        let z = p.zstream.get_or_insert_with(|| Decompress::new(true));
        let len = (p.block.end - p.block.start) as usize;
        let before = z.total_out() as usize;
        // Room for the rest of the block and one byte to notice overflow.
        let mut buf = Vec::with_capacity(len - before.min(len) + 1);
        let ok = match z.decompress_vec(&b.data, &mut buf, FlushDecompress::None) {
            Ok(Status::Ok | Status::StreamEnd) => before + buf.len() <= len,
            // Not enough input for any output yet.
            Ok(Status::BufError) => buf.is_empty(),
            Err(_) => false,
        };
        if !ok {
            p.failed = true;
            p.zstream = None;
            let block = p.block.clone();
            file.release_block(block.clone());
            out.events.push(Event::BlockFailed(block));
            return;
        }
        if buf.is_empty() {
            return;
        }
        let start = p.block.start + before as u64;
        let end = start + buf.len() as u64;
        file.write(start, &buf);
        out.events.push(Event::Received(start..end));
        self.written(i, end, file, out);
    }

    // ---------------------------------------------------------- timers ---

    /// Time-outs: the handshake, and a transfer with no data for
    /// [`DOWNLOADTIMEOUT`] (`CPartFile::Process`).
    pub fn tick(&mut self, file: &mut dyn PartFile, now: Instant) -> Output {
        let mut out = Output::default();
        let since = |t: Instant| now.saturating_duration_since(t);
        match self.state {
            State::Handshake if since(self.started) > CONNECTION_TIMEOUT => {
                self.close(file, CloseReason::HandshakeTimeout, &mut out);
            }
            State::Downloading if since(self.last_block) > DOWNLOADTIMEOUT => {
                self.send_cancel(&mut out);
                self.stop_downloading(file, State::OnQueue, &mut out);
            }
            _ => {}
        }
        out
    }

    /// The file was paused or stopped: end a transfer (`OP_CANCELTRANSFER`).
    pub fn stop(&mut self, file: &mut dyn PartFile) -> Output {
        let mut out = Output::default();
        if self.state == State::Downloading {
            self.send_cancel(&mut out);
            self.stop_downloading(file, State::OnQueue, &mut out);
        }
        out
    }

    /// The connection is gone, or the application hangs up. Reserved blocks
    /// go back to the file.
    pub fn closed(&mut self, file: &mut dyn PartFile) -> Output {
        let mut out = Output::default();
        self.close(file, CloseReason::Disconnected, &mut out);
        out
    }

    /// Whether the peer's ID is a LowID (it cannot be called back directly).
    pub fn peer_is_low_id(&self) -> Option<bool> {
        self.peer.as_ref().map(|h| is_low_id(h.id))
    }

    /// How long the session has existed.
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.started)
    }
}
