// SPDX-License-Identifier: GPL-2.0-or-later
//! Uploading to one peer over one connection, as a state machine without
//! IO: the upload half of `CUpDownClient` (`UploadClient.cpp`), the upload
//! handlers of `ClientTCPSocket.cpp`, and `UploadPacketBuilder.cpp`.
//!
//! ```text
//!  peer's OP_HELLO ─▶ OP_HELLOANSWER ─▶ Idle
//!     file requests (name, status, hash set, AICH root) answered here
//!     OP_STARTUPLOADREQ ─▶ Event::UploadRequested
//!         application: queue_rank() ─▶ Queued    accept() ─▶ Uploading
//!     Uploading: OP_REQUESTPARTS ─▶ Event::BlocksRequested
//!         application reads each block: block_packets() ─▶ data packets
//!     OP_CANCELTRANSFER / OP_END_OF_DOWNLOAD ─▶ Event::UploadEnded
//! ```
//!
//! What is shared, and the decisions (who gets a slot, which sources and
//! recovery data to send), belong to the application: it describes its
//! files through [`Shares`], and answers [`Event::SourcesRequested`] and
//! [`Event::AichRequested`] with the builders in
//! [`sources`](crate::sources) and [`packets`].

use std::ops::Range;
use std::sync::Arc;

use ed2k_codec::Packet;
use ed2k_types::ed2k::{EMBLOCKSIZE, OLD_MAX_FILE_SIZE};
use ed2k_types::{AichHash, Md4Hash};
use flate2::{Compress, Compression, FlushCompress};

use crate::download::CloseReason;
use crate::hello::{EmuleInfo, Hello, MuleInfo};
use crate::packets::{self, FileRequestExt, MultiAnswer, MultiRequest, ParseContext, PeerPacket};
use crate::part_status::{ed2k_part_count, PartStatus};
use crate::secident::{IdentConfig, IdentResult, Need, SecureIdent};

/// The most a peer may ask for in one block (`AddReqBlock`).
pub const MAX_BLOCK: u64 = 3 * EMBLOCKSIZE as u64;

/// A shared file as the session needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedInfo {
    pub hash: Md4Hash,
    pub name: String,
    pub size: u64,
    /// The part hashes (`known.met`'s: none for a file of one part).
    pub part_hashes: Vec<Md4Hash>,
    /// What we have: [`PartStatus::Complete`] for a complete file.
    pub parts: PartStatus,
    /// The AICH root, when the whole hash set is known.
    pub aich_root: Option<AichHash>,
}

impl SharedInfo {
    /// Whether every byte of `range` is ours to send.
    pub fn has_range(&self, range: &Range<u64>) -> bool {
        if range.is_empty() || range.end > self.size {
            return false;
        }
        let p = ed2k_types::ed2k::PARTSIZE;
        (range.start / p..=(range.end - 1) / p).all(|i| self.parts.has(i as usize))
    }
}

/// What we share, as the session sees it.
pub trait Shares {
    /// A shared file (complete, or a download with parts to give).
    fn shared(&self, hash: &Md4Hash) -> Option<SharedInfo>;
}

/// Where the upload stands (`EUploadState`, simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadState {
    /// Waiting for the peer's hello.
    Handshake,
    /// Talking about files; not asked for an upload, or the slot ended.
    Idle,
    /// In our upload queue (`US_ONUPLOADQUEUE`).
    Queued,
    /// Has a slot (`US_UPLOADING`).
    Uploading,
    Closed,
}

/// Something for the application.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The peer's hello, once answered.
    Handshake(Box<Hello>),
    /// It asked about a file, with what it has of it when it said
    /// (extended requests; `None` otherwise).
    FileRequested {
        hash: Md4Hash,
        parts: Option<PartStatus>,
        complete_sources: Option<u16>,
    },
    /// `OP_STARTUPLOADREQ` for a shared file: put it in the queue
    /// ([`UploadSession::queue_rank`]) or give it a slot
    /// ([`UploadSession::accept`]).
    UploadRequested(Md4Hash),
    /// New blocks to send, each checked: inside the file, ours, at most
    /// [`MAX_BLOCK`], not asked before. Read them and pass each to
    /// [`UploadSession::block_packets`].
    BlocksRequested {
        hash: Md4Hash,
        blocks: Vec<Range<u64>>,
    },
    /// The peer ended the transfer (`OP_CANCELTRANSFER`, `OP_END_OF_DOWNLOAD`).
    UploadEnded,
    /// It wants other sources of this file (version 0: SX1).
    SourcesRequested {
        hash: Md4Hash,
        version: u8,
        options: u16,
    },
    /// It wants AICH recovery data for a part, under this root.
    AichRequested {
        hash: Md4Hash,
        part: u16,
        root: AichHash,
    },
    /// A peer we called back answered our hello and was given its slot
    /// ([`UploadSession::connect`]).
    CalledBack,
    /// Its secure identification ended.
    Identified(IdentResult),
    Closed(CloseReason),
    /// Anything else (a download of ours on the same connection, chat, ...).
    Unhandled(Box<PeerPacket>),
}

/// What handling something produced.
#[derive(Debug, Default)]
pub struct Output {
    pub events: Vec<Event>,
    pub send: Vec<Packet>,
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerCaps {
    unicode: bool,
    extended_requests: u8,
    aich: bool,
    large_files: bool,
    data_compression: u8,
    ext_protocol: bool,
    secure_ident: u8,
}

/// One connection to a peer that downloads from us.
#[derive(Debug)]
pub struct UploadSession {
    ours: Hello,
    state: UploadState,
    peer: Option<Hello>,
    caps: PeerCaps,
    /// The file it asked about last (`m_requpfileid`).
    file: Option<Md4Hash>,
    /// Blocks asked for and not sent yet, then those sent.
    pending: Vec<Range<u64>>,
    done: Vec<Range<u64>>,
    ident: Option<SecureIdent>,
    early_ident_state: Option<(Need, u32)>,
    /// Compression turned off for this session (a fast slot).
    no_compression: bool,
}

/// `IsUploadCompressible`: formats compressed by design, video and
/// archives (but tar) are sent as they are.
pub fn compressible(name: &str) -> bool {
    const COMPRESSED: &[&str] = &[
        "aa", "aac", "aax", "ac3", "amr", "ape", "dts", "flac", "m1a", "m2a", "m4a", "m4b", "mka",
        "mp1", "mp2", "mp3", "mpa", "mpc", "mpp", "oga", "ogg", "opus", "ra", "weba", "wma", "wv",
        "apng", "avif", "gif", "heic", "heif", "j2k", "jfif", "jp2", "jpe", "jpeg", "jpg", "jxl",
        "png", "webp", "wmp", "chm", "djvu", "docm", "docx", "dotx", "epub", "key", "numbers",
        "odp", "ods", "odt", "otp", "ots", "ott", "oxps", "pages", "potx", "ppsx", "pptm", "pptx",
        "stc", "sti", "stw", "sxc", "sxi", "sxw", "xlsm", "xlsx", "xltx", "xps", "apk", "appx",
        "deb", "jar", "msix", "rpm", "snap", "xpi", "daa", "dmg", "isz", "wim",
    ];
    const VIDEO: &[&str] = &[
        "3g2", "3gp", "3gp2", "3gpp", "asf", "amv", "avi", "bik", "divx", "f4v", "flc", "fli",
        "flic", "flv", "h264", "h265", "hdmov", "hevc", "ifo", "m1v", "m2t", "m2ts", "m2v", "m4v",
        "mkv", "mov", "movie", "mp1v", "mp2v", "mp4", "mpe", "mpeg", "mpg", "mps", "mpv", "mpv1",
        "mpv2", "mts", "mxf", "ogm", "ogv", "pva", "qt", "ram", "ratdvd", "rm", "rmm", "rmvb",
        "rv", "rv9", "smil", "smk", "swf", "tp", "ts", "vid", "video", "vivo", "vob", "vp6",
        "webm", "wm", "wmv", "xvid",
    ];
    const ARCHIVE: &[&str] = &[
        "7z", "ace", "alz", "arc", "arj", "bz2", "cab", "cb7", "cba", "cbr", "cbt", "cbz", "gz",
        "hqx", "lha", "lz", "lz4", "lzh", "lzma", "pak", "par", "par2", "rar", "sea", "sit",
        "sitx", "tar", "tbz2", "tgz", "tlz", "txz", "uc2", "xz", "z", "zip", "zoo", "zst",
    ];
    let Some((_, ext)) = name.rsplit_once('.') else {
        return true;
    };
    let ext = ext.to_ascii_lowercase();
    if COMPRESSED.contains(&ext.as_str()) || VIDEO.contains(&ext.as_str()) {
        return false;
    }
    if ARCHIVE.contains(&ext.as_str()) {
        return ext == "tar";
    }
    true
}

/// `UploadPacketBuilder::Standard` / `Packed`: the packets that carry
/// `block` (whose data is `data`). Packets are about 125 ms of the slot's
/// `rate` (bytes/s), at least 10 KiB and at most [`EMBLOCKSIZE`]; a last
/// piece under twice that joins the one before. Packed with zlib level 1
/// when asked and when that makes it smaller.
pub fn block_packets(
    hash: Md4Hash,
    block: Range<u64>,
    data: &[u8],
    rate: u32,
    pack: bool,
) -> Vec<Packet> {
    debug_assert_eq!(data.len() as u64, block.end - block.start);
    let chunk = (rate / 8).clamp(10_240, EMBLOCKSIZE) as usize;
    let packed = if pack {
        deflate(data).filter(|p| p.len() < data.len())
    } else {
        None
    };
    let payload: &[u8] = packed.as_deref().unwrap_or(data);
    let size = payload.len();
    let mut out = Vec::new();
    let mut remaining = size;
    let mut piece = if remaining <= chunk + 2600 {
        remaining
    } else {
        chunk
    };
    while remaining > 0 {
        if remaining < piece * 2 {
            piece = remaining;
        }
        let pos = size - remaining;
        remaining -= piece;
        let bytes = &payload[pos..pos + piece];
        out.push(match &packed {
            Some(p) => packets::compressed_part(hash, block.clone(), p.len() as u32, bytes),
            None => packets::sending_part(hash, block.start + pos as u64, bytes),
        });
    }
    out
}

/// `compress2(level 1)`.
fn deflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut c = Compress::new(Compression::new(1), true);
    let mut out = Vec::with_capacity(data.len() + 300);
    match c.compress_vec(data, &mut out, FlushCompress::Finish) {
        Ok(flate2::Status::StreamEnd) => Some(out),
        _ => None,
    }
}

impl UploadSession {
    /// A peer connected to us and sent `hello`: answer it.
    pub fn accepted(
        ours: Hello,
        hello: Hello,
    ) -> Result<(UploadSession, Output), ed2k_codec::TagError> {
        let mut s = UploadSession {
            ours,
            state: UploadState::Idle,
            peer: None,
            caps: PeerCaps::default(),
            file: None,
            pending: Vec::new(),
            done: Vec::new(),
            ident: None,
            early_ident_state: None,
            no_compression: false,
        };
        let mut out = Output::default();
        // An eMule without CT_EMULE_VERSION expects the old capability packet.
        if hello.user_hash.0[5] == 14 && hello.user_hash.0[14] == 111 && !hello.is_emule() {
            out.send
                .push(MuleInfo::Info(s.our_mule_info()).to_packet(false)?);
        }
        out.send.push(s.ours.to_hello_answer()?);
        s.peer_said_hello(hello, &mut out);
        Ok((s, out))
    }

    /// We call back a waiting peer whose turn came (`US_CONNECTING`): send
    /// the returned hello once connected. When its hello answer arrives
    /// the slot is given (`OP_ACCEPTUPLOADREQ`, as `ConnectionEstablished`
    /// does), with [`Event::Handshake`] then [`Event::CalledBack`].
    pub fn connect(ours: Hello) -> Result<(UploadSession, Packet), ed2k_codec::TagError> {
        let hello = ours.to_hello()?;
        let s = UploadSession {
            ours,
            state: UploadState::Handshake,
            peer: None,
            caps: PeerCaps::default(),
            file: None,
            pending: Vec::new(),
            done: Vec::new(),
            ident: None,
            early_ident_state: None,
            no_compression: false,
        };
        Ok((s, hello))
    }

    pub fn state(&self) -> UploadState {
        self.state
    }

    pub fn peer(&self) -> Option<&Hello> {
        self.peer.as_ref()
    }

    /// The file the peer asked about last.
    pub fn file(&self) -> Option<Md4Hash> {
        self.file
    }

    /// Blocks asked for and not sent yet.
    pub fn pending_blocks(&self) -> &[Range<u64>] {
        &self.pending
    }

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

    fn peer_said_hello(&mut self, hello: Hello, out: &mut Output) {
        let m1 = hello.misc1.unwrap_or_default();
        let m2 = hello.misc2.unwrap_or_default();
        self.caps = PeerCaps {
            unicode: m1.unicode,
            extended_requests: m1.extended_requests_version,
            aich: m1.aich_version & 1 == 1,
            large_files: m2.large_files,
            data_compression: m1.data_comp_version,
            ext_protocol: hello.misc1.is_some() || hello.is_emule(),
            secure_ident: m1.secure_ident,
        };
        out.events.push(Event::Handshake(Box::new(hello.clone())));
        self.peer = Some(hello);
    }

    // ------------------------------------------------- the application ---

    /// Put the peer in the queue at `rank` (`SendRankingInfo`): an eMule
    /// rank for a peer that speaks the eMule protocol, else eDonkey's.
    pub fn queue_rank(&mut self, rank: u16) -> Packet {
        if self.state != UploadState::Uploading {
            self.state = UploadState::Queued;
        }
        if self.caps.ext_protocol {
            packets::queue_ranking(rank)
        } else {
            packets::queue_rank(u32::from(rank))
        }
    }

    /// Give the peer a slot (`OP_ACCEPTUPLOADREQ`).
    pub fn accept(&mut self) -> Packet {
        self.state = UploadState::Uploading;
        self.pending.clear();
        self.done.clear();
        packets::accept_upload_req()
    }

    /// Take the slot back (`SendOutOfPartReqsAndAddToWaitingQueue`): the
    /// peer goes back to waiting.
    pub fn end_slot(&mut self) -> Packet {
        self.state = UploadState::Queued;
        self.pending.clear();
        packets::out_of_part_reqs()
    }

    /// The packets that send `block`, read as `data`; the block is then
    /// done. `rate` is the slot's speed in bytes/s. Compressed for a peer
    /// that takes it, unless the file does not compress, or the slot is
    /// above 150 KiB/s (then for the rest of the session, as aMule does).
    pub fn block_packets(
        &mut self,
        block: Range<u64>,
        data: &[u8],
        rate: u32,
        name: &str,
    ) -> Vec<Packet> {
        let Some(hash) = self.file else {
            return Vec::new();
        };
        if let Some(i) = self.pending.iter().position(|b| *b == block) {
            self.pending.remove(i);
        }
        self.done.push(block.clone());
        if rate > 150 * 1024 {
            self.no_compression = true;
        }
        let pack = !self.no_compression && self.caps.data_compression == 1 && compressible(name);
        block_packets(hash, block, data, rate, pack)
    }

    /// Start secure identification (as [`crate::download::Session::start_secure_ident`]).
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

    /// The connection is gone.
    pub fn closed(&mut self) -> Output {
        let mut out = Output::default();
        if self.state != UploadState::Closed {
            self.state = UploadState::Closed;
            out.events.push(Event::Closed(CloseReason::Disconnected));
        }
        out
    }

    // ------------------------------------------------------- receiving ---

    /// Handle a packet from the peer, parsed with [`UploadSession::parse_context`].
    pub fn handle(&mut self, packet: PeerPacket, shares: &dyn Shares) -> Output {
        let mut out = Output::default();
        if self.state == UploadState::Closed {
            return out;
        }
        if let Err(why) = self.dispatch(packet, shares, &mut out) {
            self.state = UploadState::Closed;
            out.events.push(Event::Closed(CloseReason::Protocol(why)));
        }
        out
    }

    /// The file a request names, if we share it and the peer can take it.
    fn lookup(&self, hash: Md4Hash, size: Option<u64>, shares: &dyn Shares) -> Option<SharedInfo> {
        let f = shares.shared(&hash)?;
        if f.size > OLD_MAX_FILE_SIZE && !self.caps.large_files {
            return None;
        }
        if size.is_some_and(|s| s != 0 && s != f.size) {
            return None;
        }
        Some(f)
    }

    fn set_file(&mut self, hash: Md4Hash) {
        if self.file != Some(hash) {
            self.file = Some(hash);
            self.pending.clear();
            self.done.clear();
        }
    }

    fn file_requested(&self, hash: Md4Hash, ext: Option<FileRequestExt>, out: &mut Output) {
        let (parts, complete_sources) = match ext {
            Some(e) => (Some(e.parts), e.complete_sources),
            None => (None, None),
        };
        out.events.push(Event::FileRequested {
            hash,
            parts,
            complete_sources,
        });
    }

    fn dispatch(
        &mut self,
        packet: PeerPacket,
        shares: &dyn Shares,
        out: &mut Output,
    ) -> Result<(), String> {
        if self.state == UploadState::Handshake {
            // Calling back: only the hello answer (or an old eMule's
            // capabilities first) is expected.
            return match packet {
                PeerPacket::HelloAnswer(hello) => {
                    self.peer_said_hello(hello, out);
                    out.send.push(self.accept());
                    out.events.push(Event::CalledBack);
                    Ok(())
                }
                p @ PeerPacket::MuleInfo { .. } => {
                    self.state = UploadState::Idle;
                    let r = self.dispatch(p, shares, out);
                    self.state = UploadState::Handshake;
                    r
                }
                _ => Err("no hello answer to our callback".into()),
            };
        }
        match packet {
            // An old eMule sends its capabilities separately.
            PeerPacket::MuleInfo {
                info: MuleInfo::Info(info),
                answer,
            } => {
                self.caps.extended_requests = info.extended_requests;
                self.caps.data_compression = info.compression;
                self.caps.secure_ident = (info.features & 3) as u8;
                self.caps.ext_protocol = true;
                if !answer {
                    let reply = MuleInfo::Info(self.our_mule_info())
                        .to_packet(true)
                        .map_err(|e| e.to_string())?;
                    out.send.push(reply);
                }
            }
            // OP_REQUESTFILENAME: unknown files get no answer.
            PeerPacket::RequestFileName { hash, ext } => {
                if let Some(f) = self.lookup(hash, None, shares) {
                    self.set_file(hash);
                    out.send
                        .push(packets::file_name(hash, &f.name, self.caps.unicode));
                    self.file_requested(hash, ext, out);
                }
            }
            PeerPacket::SetReqFileId(hash) => match self.lookup(hash, None, shares) {
                Some(f) => {
                    self.set_file(hash);
                    out.send.push(packets::file_status(hash, &f.parts));
                }
                None => out.send.push(packets::no_such_file(hash)),
            },
            PeerPacket::MultiPacket {
                hash,
                size,
                requests,
            } => {
                let Some(f) = self.lookup(hash, size, shares) else {
                    out.send.push(packets::no_such_file(hash));
                    return Ok(());
                };
                self.set_file(hash);
                let mut answers = Vec::new();
                for r in requests {
                    match r {
                        MultiRequest::FileName(ext) => {
                            answers.push(MultiAnswer::FileName(f.name.clone()));
                            self.file_requested(hash, ext, out);
                        }
                        MultiRequest::FileStatus => {
                            answers.push(MultiAnswer::FileStatus(f.parts.clone()))
                        }
                        MultiRequest::AichFileHash => {
                            if let (true, Some(root)) = (self.caps.aich, f.aich_root) {
                                answers.push(MultiAnswer::AichFileHash(root));
                            }
                        }
                        MultiRequest::Sources => out.events.push(Event::SourcesRequested {
                            hash,
                            version: 0,
                            options: 0,
                        }),
                        MultiRequest::Sources2 { version, options } => {
                            out.events.push(Event::SourcesRequested {
                                hash,
                                version,
                                options,
                            })
                        }
                        MultiRequest::Unknown(_) => {}
                    }
                }
                if !answers.is_empty() {
                    out.send.push(packets::multi_packet_answer(
                        hash,
                        &answers,
                        self.caps.unicode,
                    ));
                }
            }
            PeerPacket::HashSetRequest(hash) => {
                // A file of several parts needs its part hashes to answer; one
                // of a single part answers with none.
                if let Some(f) = shares.shared(&hash) {
                    let needed = ed2k_part_count(f.size) > 1;
                    if !needed || !f.part_hashes.is_empty() {
                        out.send
                            .push(packets::hash_set_answer(hash, &f.part_hashes));
                    }
                }
            }
            PeerPacket::StartUploadReq(hash) => {
                if self.lookup(hash, None, shares).is_some() {
                    self.set_file(hash);
                    out.events.push(Event::UploadRequested(hash));
                }
            }
            PeerPacket::RequestParts { hash, ranges } => {
                // AddReqBlock: only in a slot, only what we have.
                if self.state != UploadState::Uploading {
                    return Ok(());
                }
                let Some(f) = shares.shared(&hash) else {
                    return Ok(());
                };
                self.set_file(hash);
                let mut new = Vec::new();
                for r in ranges {
                    if r.end - r.start > MAX_BLOCK
                        || !f.has_range(&r)
                        || self.pending.contains(&r)
                        || self.done.contains(&r)
                    {
                        continue;
                    }
                    self.pending.push(r.clone());
                    new.push(r);
                }
                if !new.is_empty() {
                    out.events
                        .push(Event::BlocksRequested { hash, blocks: new });
                }
            }
            PeerPacket::CancelTransfer => {
                if matches!(self.state, UploadState::Uploading | UploadState::Queued) {
                    self.state = UploadState::Idle;
                    self.pending.clear();
                    out.events.push(Event::UploadEnded);
                }
            }
            PeerPacket::EndOfDownload(hash) => {
                if self.file == Some(hash) && self.state != UploadState::Idle {
                    self.state = UploadState::Idle;
                    self.pending.clear();
                    out.events.push(Event::UploadEnded);
                }
            }
            PeerPacket::AichFileHashReq(hash) => {
                if let Some(f) = shares.shared(&hash) {
                    if let (true, Some(root)) = (self.caps.aich, f.aich_root) {
                        out.send.push(packets::aich_file_hash_ans(hash, root));
                    }
                }
            }
            PeerPacket::AichRequest { hash, part, root } => {
                out.events.push(Event::AichRequested { hash, part, root })
            }
            PeerPacket::RequestSources(hash) => out.events.push(Event::SourcesRequested {
                hash,
                version: 0,
                options: 0,
            }),
            PeerPacket::RequestSources2 {
                version,
                options,
                hash,
            } => out.events.push(Event::SourcesRequested {
                hash,
                version,
                options,
            }),
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
            p => out.events.push(Event::Unhandled(Box::new(p))),
        }
        Ok(())
    }
}

/// The answer to a source request, ready to fill (`CSourceExchangePacket`
/// for this peer).
pub fn source_answer_for(
    session: &UploadSession,
    hash: Md4Hash,
    requested_version: u8,
) -> crate::sources::AnswerBuilder {
    let (m1, m2) = session
        .peer
        .as_ref()
        .map(|h| (h.misc1.unwrap_or_default(), h.misc2.unwrap_or_default()))
        .unwrap_or_default();
    crate::sources::AnswerBuilder::new(
        hash,
        m2.source_exchange2,
        m1.source_exchange1_version,
        requested_version,
    )
}

/// Shares held in a list (tests, simple callers).
impl Shares for Vec<SharedInfo> {
    fn shared(&self, hash: &Md4Hash) -> Option<SharedInfo> {
        self.iter().find(|f| f.hash == *hash).cloned()
    }
}

impl<T: Shares + ?Sized> Shares for Arc<T> {
    fn shared(&self, hash: &Md4Hash) -> Option<SharedInfo> {
        (**self).shared(hash)
    }
}
