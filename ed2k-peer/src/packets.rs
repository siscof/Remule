// SPDX-License-Identifier: GPL-2.0-or-later
//! Client-to-client TCP packets (`CClientTCPSocket::ProcessPacket`,
//! `ProcessExtPacket`; the senders in `DownloadClient.cpp`,
//! `UploadClient.cpp` and `UploadPacketBuilder.cpp`).
//!
//! A download goes: hello, file request (`OP_REQUESTFILENAME` and
//! `OP_SETREQFILEID`, or both inside one `OP_MULTIPACKET`), the hash set if
//! the file has several parts, `OP_STARTUPLOADREQ`, then queue ranks until
//! `OP_ACCEPTUPLOADREQ`, then `OP_REQUESTPARTS` and the data blocks.
//!
//! Byte ranges are half-open (`start..end`) everywhere, as on the wire.
//! aMule keeps inclusive ends internally.

use std::ops::Range;

use ed2k_codec::packet::CLIENT_UNPACK_LIMIT;
use ed2k_codec::{LenField, Packet, Reader, StrEncoding, Writer};
use ed2k_types::ed2k::client_tcp::{Extended, Standard};
use ed2k_types::ed2k::SOURCEEXCHANGE2_VERSION;
use ed2k_types::{AichHash, Md4Hash, Protocol};

use crate::hello::{Hello, MuleInfo};
use crate::part_status::PartStatus;
use crate::secident::Need;

/// A malformed packet from a peer. aMule drops the connection for these.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("bad {what} from peer: {why}")]
pub struct BadPacket {
    pub what: &'static str,
    pub why: String,
}

impl BadPacket {
    pub fn new(what: &'static str, why: impl Into<String>) -> Self {
        BadPacket {
            what,
            why: why.into(),
        }
    }

    pub(crate) fn io(what: &'static str) -> impl Fn(ed2k_codec::Error) -> BadPacket {
        move |e| BadPacket::new(what, e.to_string())
    }

    pub(crate) fn tag(what: &'static str) -> impl Fn(ed2k_codec::TagError) -> BadPacket {
        move |e| BadPacket::new(what, e.to_string())
    }
}

/// What the parser needs to know about the peer, from its hello.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseContext {
    /// Strings are UTF-8 (`GetUnicodeSupport`); otherwise Latin-1.
    pub unicode: bool,
    /// `m_byExtendedRequestsVer`: whether file requests carry the
    /// requester's part status (1) and complete-source count (2).
    pub extended_requests_version: u8,
}

/// The extended part of a file request (`ProcessExtendedInfo`): what the
/// requester has of the file.
///
/// A requester downloading the file sends its bitmap. A wire count of 0,
/// read as [`PartStatus::Complete`], is taken by aMule as "no parts" here,
/// and is then not followed by the complete-source count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRequestExt {
    pub parts: PartStatus,
    /// Extended requests version 2: how many complete sources the
    /// requester knows.
    pub complete_sources: Option<u16>,
}

impl FileRequestExt {
    fn write(&self, w: &mut Writer) {
        self.parts.write(w);
        if let Some(n) = self.complete_sources {
            w.u16(n);
        }
    }

    fn read(r: &mut Reader<'_>, version: u8) -> Result<Option<Self>, ed2k_codec::Error> {
        if version == 0 {
            return Ok(None);
        }
        let parts = PartStatus::read(r)?;
        let complete_sources = if version > 1 && parts != PartStatus::Complete {
            Some(r.u16()?)
        } else {
            None
        };
        Ok(Some(FileRequestExt {
            parts,
            complete_sources,
        }))
    }
}

/// `OP_SENDINGPART(_I64)`: plain file data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub hash: Md4Hash,
    /// Where `data` goes in the file.
    pub start: u64,
    pub data: Vec<u8>,
}

impl Block {
    pub fn range(&self) -> Range<u64> {
        self.start..self.start + self.data.len() as u64
    }
}

/// `OP_COMPRESSEDPART(_I64)`: a piece of one zlib stream that inflates to
/// a requested block. Every piece of the stream repeats the block's start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedBlock {
    pub hash: Md4Hash,
    /// The start of the block the stream inflates to.
    pub start: u64,
    /// The size of the whole compressed stream.
    pub packed_size: u32,
    /// This piece of it.
    pub data: Vec<u8>,
}

/// A request inside `OP_MULTIPACKET(_EXT)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiRequest {
    /// `OP_REQUESTFILENAME`
    FileName(Option<FileRequestExt>),
    /// `OP_SETREQFILEID`: asks for the file status.
    FileStatus,
    /// `OP_REQUESTSOURCES`
    Sources,
    /// `OP_REQUESTSOURCES2`
    Sources2 { version: u8, options: u16 },
    /// `OP_AICHFILEHASHREQ`
    AichFileHash,
    /// An opcode aMule does not know. aMule skips the byte and reads on, so
    /// what follows is guesswork.
    Unknown(u8),
}

/// An answer inside `OP_MULTIPACKETANSWER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiAnswer {
    /// `OP_REQFILENAMEANSWER`
    FileName(String),
    /// `OP_FILESTATUS`
    FileStatus(PartStatus),
    /// `OP_AICHFILEHASHANS`
    AichFileHash(AichHash),
    /// As for [`MultiRequest::Unknown`].
    Unknown(u8),
}

/// Everything a peer can send that this crate understands, parsed.
#[derive(Debug, Clone, PartialEq)]
pub enum PeerPacket {
    Hello(Hello),
    HelloAnswer(Hello),
    MuleInfo {
        info: MuleInfo,
        answer: bool,
    },
    /// `OP_REQUESTFILENAME`
    RequestFileName {
        hash: Md4Hash,
        ext: Option<FileRequestExt>,
    },
    /// `OP_REQFILENAMEANSWER`: the peer has the file, under this name.
    FileName {
        hash: Md4Hash,
        name: String,
    },
    /// `OP_SETREQFILEID`: asks for the file status.
    SetReqFileId(Md4Hash),
    /// `OP_FILESTATUS`
    FileStatus {
        hash: Md4Hash,
        parts: PartStatus,
    },
    /// `OP_FILEREQANSNOFIL`: the peer does not have the file.
    NoSuchFile(Md4Hash),
    /// `OP_HASHSETREQUEST`
    HashSetRequest(Md4Hash),
    /// `OP_HASHSETANSWER`: the part hashes.
    HashSetAnswer {
        hash: Md4Hash,
        parts: Vec<Md4Hash>,
    },
    /// `OP_STARTUPLOADREQ`: put me in your upload queue for this file.
    StartUploadReq(Md4Hash),
    /// `OP_ACCEPTUPLOADREQ`: you have an upload slot.
    AcceptUploadReq,
    /// `OP_QUEUERANK` (eDonkey)
    QueueRank(u32),
    /// `OP_QUEUERANKING` (eMule)
    QueueRanking(u16),
    /// `OP_REQUESTPARTS(_I64)`: up to three ranges; empty slots dropped.
    RequestParts {
        hash: Md4Hash,
        ranges: Vec<Range<u64>>,
    },
    SendingPart(Block),
    CompressedPart(CompressedBlock),
    /// `OP_CANCELTRANSFER`: the downloader gives up its slot.
    CancelTransfer,
    /// `OP_OUTOFPARTREQS`: the uploader ends the session.
    OutOfPartReqs,
    /// `OP_END_OF_DOWNLOAD`
    EndOfDownload(Md4Hash),
    /// `OP_MULTIPACKET` (`size: None`) or `OP_MULTIPACKET_EXT`.
    MultiPacket {
        hash: Md4Hash,
        size: Option<u64>,
        requests: Vec<MultiRequest>,
    },
    MultiPacketAnswer {
        hash: Md4Hash,
        answers: Vec<MultiAnswer>,
    },
    /// `OP_AICHFILEHASHREQ`
    AichFileHashReq(Md4Hash),
    /// `OP_AICHFILEHASHANS`
    AichFileHashAns {
        hash: Md4Hash,
        aich: AichHash,
    },
    /// `OP_REQUESTSOURCES`: send me other sources of this file (SX1).
    RequestSources(Md4Hash),
    /// `OP_REQUESTSOURCES2`
    RequestSources2 {
        version: u8,
        options: u16,
        hash: Md4Hash,
    },
    /// `OP_ANSWERSOURCES`: the body is read with
    /// [`sources::parse_answer`](crate::sources::parse_answer), which
    /// needs the peer's SX1 version.
    AnswerSources {
        hash: Md4Hash,
        body: Vec<u8>,
    },
    /// `OP_ANSWERSOURCES2`
    AnswerSources2 {
        version: u8,
        hash: Md4Hash,
        body: Vec<u8>,
    },
    /// `OP_SECIDENTSTATE`
    SecIdentState {
        need: Need,
        challenge: u32,
    },
    /// `OP_PUBLICKEY`
    PublicKey(Vec<u8>),
    /// `OP_SIGNATURE`; `ip_kind` follows the signature in v2.
    Signature {
        signature: Vec<u8>,
        ip_kind: Option<u8>,
    },
    /// `OP_AICHREQUEST`: recovery data for a part, under this root.
    AichRequest {
        hash: Md4Hash,
        part: u16,
        root: AichHash,
    },
    /// `OP_AICHANSWER`; `None` when the peer could not answer (a packet of
    /// at most 16 bytes).
    AichAnswer(Option<AichRecovery>),
    /// Anything else, for the caller to handle or ignore.
    Other(Packet),
}

/// The recovery data in an `OP_AICHANSWER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AichRecovery {
    pub hash: Md4Hash,
    pub part: u16,
    pub root: AichHash,
    /// Read with `AichTree::read_recovery_data` (ed2k-hash).
    pub data: Vec<u8>,
}

fn edonkey(op: Standard, payload: Vec<u8>) -> Packet {
    Packet::new(Protocol::Edonkey, op, payload)
}

fn emule(op: Extended, payload: Vec<u8>) -> Packet {
    Packet::new(Protocol::Emule, op, payload)
}

fn hash_only(op: Standard, hash: Md4Hash) -> Packet {
    edonkey(op, hash.0.to_vec())
}

fn encoding(unicode: bool) -> StrEncoding {
    if unicode {
        StrEncoding::Utf8
    } else {
        StrEncoding::Latin1
    }
}

fn read_aich(r: &mut Reader<'_>) -> Result<AichHash, ed2k_codec::Error> {
    Ok(AichHash(r.array()?))
}

const U32_MAX: u64 = u32::MAX as u64;

// ------------------------------------------------------------- builders ---

/// `OP_REQUESTFILENAME`, with the extended part when the peer's extended
/// requests version is above 0.
pub fn request_file_name(hash: Md4Hash, ext: Option<&FileRequestExt>) -> Packet {
    let mut w = Writer::new();
    w.hash(hash);
    if let Some(e) = ext {
        e.write(&mut w);
    }
    edonkey(Standard::RequestFilename, w.into_bytes())
}

/// `OP_REQFILENAMEANSWER`, the name in UTF-8 for a Unicode peer.
pub fn file_name(hash: Md4Hash, name: &str, unicode: bool) -> Packet {
    let mut w = Writer::new();
    w.hash(hash).string(name, encoding(unicode), LenField::U16);
    edonkey(Standard::ReqFilenameAnswer, w.into_bytes())
}

/// `OP_SETREQFILEID`
pub fn set_req_file_id(hash: Md4Hash) -> Packet {
    hash_only(Standard::SetReqFileId, hash)
}

/// `OP_FILESTATUS`
pub fn file_status(hash: Md4Hash, parts: &PartStatus) -> Packet {
    let mut w = Writer::new();
    w.hash(hash);
    parts.write(&mut w);
    edonkey(Standard::FileStatus, w.into_bytes())
}

/// `OP_FILEREQANSNOFIL`
pub fn no_such_file(hash: Md4Hash) -> Packet {
    hash_only(Standard::FileReqAnsNoFil, hash)
}

/// `OP_HASHSETREQUEST`
pub fn hash_set_request(hash: Md4Hash) -> Packet {
    hash_only(Standard::HashsetRequest, hash)
}

/// `OP_HASHSETANSWER`. Panics past 65,535 part hashes.
pub fn hash_set_answer(hash: Md4Hash, parts: &[Md4Hash]) -> Packet {
    let mut w = Writer::with_capacity(18 + 16 * parts.len());
    let count = u16::try_from(parts.len()).expect("over 65,535 part hashes");
    w.hash(hash).u16(count);
    for p in parts {
        w.hash(*p);
    }
    edonkey(Standard::HashsetAnswer, w.into_bytes())
}

/// `OP_STARTUPLOADREQ`
pub fn start_upload_req(hash: Md4Hash) -> Packet {
    hash_only(Standard::StartUploadReq, hash)
}

/// `OP_ACCEPTUPLOADREQ`
pub fn accept_upload_req() -> Packet {
    edonkey(Standard::AcceptUploadReq, Vec::new())
}

/// `OP_QUEUERANK`
pub fn queue_rank(rank: u32) -> Packet {
    edonkey(Standard::QueueRank, rank.to_le_bytes().to_vec())
}

/// `OP_QUEUERANKING` (`SendRankingInfo`): the rank and ten zero bytes.
pub fn queue_ranking(rank: u16) -> Packet {
    let mut p = vec![0u8; 12];
    p[..2].copy_from_slice(&rank.to_le_bytes());
    emule(Extended::QueueRanking, p)
}

/// `OP_REQUESTPARTS`, or `OP_REQUESTPARTS_I64` when any offset needs 64
/// bits: three starts, then three ends, unused slots zero.
///
/// aMule picks the 64-bit form from its inclusive ends, so for a block
/// ending exactly at 4 GiB it writes an end of 0; this decides on the
/// half-open end and does not.
///
/// Panics with more than three ranges.
pub fn request_parts(hash: Md4Hash, ranges: &[Range<u64>]) -> Packet {
    assert!(ranges.len() <= 3, "at most 3 ranges per OP_REQUESTPARTS");
    let large = ranges.iter().any(|r| r.start > U32_MAX || r.end > U32_MAX);
    let slot = |i: usize| ranges.get(i).cloned().unwrap_or(0..0);
    let mut w = Writer::with_capacity(16 + 48);
    w.hash(hash);
    let mut put = |v: u64| {
        if large {
            w.u64(v);
        } else {
            w.u32(v as u32);
        }
    };
    (0..3).for_each(|i| put(slot(i).start));
    (0..3).for_each(|i| put(slot(i).end));
    if large {
        emule(Extended::RequestPartsI64, w.into_bytes())
    } else {
        edonkey(Standard::RequestParts, w.into_bytes())
    }
}

/// `OP_SENDINGPART`, or `OP_SENDINGPART_I64` past 4 GiB.
pub fn sending_part(hash: Md4Hash, start: u64, data: &[u8]) -> Packet {
    let end = start + data.len() as u64;
    let large = start > U32_MAX || end > U32_MAX;
    let mut w = Writer::with_capacity(32 + data.len());
    w.hash(hash);
    if large {
        w.u64(start).u64(end);
    } else {
        w.u32(start as u32).u32(end as u32);
    }
    w.bytes(data);
    if large {
        emule(Extended::SendingPartI64, w.into_bytes())
    } else {
        edonkey(Standard::SendingPart, w.into_bytes())
    }
}

/// `OP_COMPRESSEDPART(_I64)`: one piece of the compressed stream of the
/// block `block`, which is `packed_size` bytes long in all. The 64-bit form
/// is used when the block reaches past 4 GiB.
pub fn compressed_part(hash: Md4Hash, block: Range<u64>, packed_size: u32, piece: &[u8]) -> Packet {
    let large = block.start > U32_MAX || block.end > U32_MAX;
    let mut w = Writer::with_capacity(28 + piece.len());
    w.hash(hash);
    if large {
        w.u64(block.start);
    } else {
        w.u32(block.start as u32);
    }
    w.u32(packed_size).bytes(piece);
    let op = if large {
        Extended::CompressedPartI64
    } else {
        Extended::CompressedPart
    };
    emule(op, w.into_bytes())
}

/// `OP_CANCELTRANSFER`
pub fn cancel_transfer() -> Packet {
    edonkey(Standard::CancelTransfer, Vec::new())
}

/// `OP_OUTOFPARTREQS`
pub fn out_of_part_reqs() -> Packet {
    edonkey(Standard::OutOfPartReqs, Vec::new())
}

/// `OP_END_OF_DOWNLOAD`
pub fn end_of_download(hash: Md4Hash) -> Packet {
    hash_only(Standard::EndOfDownload, hash)
}

/// `OP_MULTIPACKET`, or `OP_MULTIPACKET_EXT` with the file size for a peer
/// that supports it (`SendFileRequest`).
pub fn multi_packet(hash: Md4Hash, size: Option<u64>, requests: &[MultiRequest]) -> Packet {
    let mut w = Writer::new();
    w.hash(hash);
    if let Some(s) = size {
        w.u64(s);
    }
    for r in requests {
        match r {
            MultiRequest::FileName(ext) => {
                w.u8(Standard::RequestFilename.into());
                if let Some(e) = ext {
                    e.write(&mut w);
                }
            }
            MultiRequest::FileStatus => {
                w.u8(Standard::SetReqFileId.into());
            }
            MultiRequest::Sources => {
                w.u8(Extended::RequestSources.into());
            }
            MultiRequest::Sources2 { version, options } => {
                w.u8(Extended::RequestSources2.into())
                    .u8(*version)
                    .u16(*options);
            }
            MultiRequest::AichFileHash => {
                w.u8(Extended::AichFileHashReq.into());
            }
            MultiRequest::Unknown(op) => {
                w.u8(*op);
            }
        }
    }
    let op = if size.is_some() {
        Extended::MultiPacketExt
    } else {
        Extended::MultiPacket
    };
    emule(op, w.into_bytes())
}

/// `OP_MULTIPACKETANSWER`
pub fn multi_packet_answer(hash: Md4Hash, answers: &[MultiAnswer], unicode: bool) -> Packet {
    let mut w = Writer::new();
    w.hash(hash);
    for a in answers {
        match a {
            MultiAnswer::FileName(name) => {
                w.u8(Standard::ReqFilenameAnswer.into()).string(
                    name,
                    encoding(unicode),
                    LenField::U16,
                );
            }
            MultiAnswer::FileStatus(parts) => {
                w.u8(Standard::FileStatus.into());
                parts.write(&mut w);
            }
            MultiAnswer::AichFileHash(aich) => {
                w.u8(Extended::AichFileHashAns.into()).bytes(&aich.0);
            }
            MultiAnswer::Unknown(op) => {
                w.u8(*op);
            }
        }
    }
    emule(Extended::MultiPacketAnswer, w.into_bytes())
}

/// `OP_REQUESTSOURCES`
pub fn request_sources(hash: Md4Hash) -> Packet {
    emule(Extended::RequestSources, hash.0.to_vec())
}

/// `OP_REQUESTSOURCES2` at our version, without options.
pub fn request_sources2(hash: Md4Hash) -> Packet {
    let mut w = Writer::new();
    w.u8(SOURCEEXCHANGE2_VERSION).u16(0).hash(hash);
    emule(Extended::RequestSources2, w.into_bytes())
}

/// `OP_AICHREQUEST`
pub fn aich_request(hash: Md4Hash, part: u16, root: AichHash) -> Packet {
    let mut w = Writer::new();
    w.hash(hash).u16(part).bytes(&root.0);
    emule(Extended::AichRequest, w.into_bytes())
}

/// `OP_AICHANSWER` with recovery data.
pub fn aich_answer(r: &AichRecovery) -> Packet {
    let mut w = Writer::new();
    w.hash(r.hash).u16(r.part).bytes(&r.root.0).bytes(&r.data);
    emule(Extended::AichAnswer, w.into_bytes())
}

/// `OP_AICHANSWER` saying no: just the file hash.
pub fn aich_answer_failed(hash: Md4Hash) -> Packet {
    emule(Extended::AichAnswer, hash.0.to_vec())
}

/// `OP_AICHFILEHASHREQ`
pub fn aich_file_hash_req(hash: Md4Hash) -> Packet {
    emule(Extended::AichFileHashReq, hash.0.to_vec())
}

/// `OP_AICHFILEHASHANS`
pub fn aich_file_hash_ans(hash: Md4Hash, aich: AichHash) -> Packet {
    let mut w = Writer::with_capacity(36);
    w.hash(hash).bytes(&aich.0);
    emule(Extended::AichFileHashAns, w.into_bytes())
}

// --------------------------------------------------------------- parser ---

fn exactly_hash(what: &'static str, p: &[u8]) -> Result<Md4Hash, BadPacket> {
    let h: [u8; 16] = p
        .try_into()
        .map_err(|_| BadPacket::new(what, format!("{} bytes, not 16", p.len())))?;
    Ok(Md4Hash(h))
}

fn read_offset(r: &mut Reader<'_>, large: bool) -> Result<u64, ed2k_codec::Error> {
    if large {
        r.u64()
    } else {
        r.u32().map(u64::from)
    }
}

/// A data block's header: hash, start, then the end (plain) or the packed
/// size, each offset 4 or 8 bytes (`ProcessBlockPacket`).
fn parse_block(p: &[u8], packed: bool, large: bool) -> Result<PeerPacket, BadPacket> {
    let what = if packed {
        "compressed block"
    } else {
        "data block"
    };
    let io = BadPacket::io(what);
    let mut r = Reader::new(p);
    let hash = r.hash().map_err(&io)?;
    let start = read_offset(&mut r, large).map_err(&io)?;
    if packed {
        let packed_size = r.u32().map_err(&io)?;
        if r.is_eof() {
            return Err(BadPacket::new(what, "no data"));
        }
        return Ok(PeerPacket::CompressedPart(CompressedBlock {
            hash,
            start,
            packed_size,
            data: r.rest().to_vec(),
        }));
    }
    let end = read_offset(&mut r, large).map_err(&io)?;
    let data = r.rest();
    if end <= start || end - start != data.len() as u64 {
        return Err(BadPacket::new(
            what,
            format!("range {start}..{end} with {} bytes", data.len()),
        ));
    }
    Ok(PeerPacket::SendingPart(Block {
        hash,
        start,
        data: data.to_vec(),
    }))
}

fn parse_request_parts(p: &[u8], large: bool) -> Result<PeerPacket, BadPacket> {
    let io = BadPacket::io("part request");
    let mut r = Reader::new(p);
    let hash = r.hash().map_err(&io)?;
    let mut v = [0u64; 6];
    for x in &mut v {
        *x = read_offset(&mut r, large).map_err(&io)?;
    }
    // aMule skips a range that does not end after it starts; zeros are the
    // padding of fewer than three requests.
    let ranges = (0..3)
        .map(|i| v[i]..v[i + 3])
        .filter(|r| r.end > r.start)
        .collect();
    Ok(PeerPacket::RequestParts { hash, ranges })
}

fn parse_multi_packet(p: &[u8], ext: bool, ctx: ParseContext) -> Result<PeerPacket, BadPacket> {
    let io = BadPacket::io("multipacket");
    let mut r = Reader::new(p);
    let hash = r.hash().map_err(&io)?;
    let size = if ext {
        Some(r.u64().map_err(&io)?)
    } else {
        None
    };
    let mut requests = Vec::new();
    while !r.is_eof() {
        let op = r.u8().map_err(&io)?;
        let req = if op == u8::from(Standard::RequestFilename) {
            MultiRequest::FileName(
                FileRequestExt::read(&mut r, ctx.extended_requests_version).map_err(&io)?,
            )
        } else if op == u8::from(Standard::SetReqFileId) {
            MultiRequest::FileStatus
        } else if op == u8::from(Extended::RequestSources) {
            MultiRequest::Sources
        } else if op == u8::from(Extended::RequestSources2) {
            MultiRequest::Sources2 {
                version: r.u8().map_err(&io)?,
                options: r.u16().map_err(&io)?,
            }
        } else if op == u8::from(Extended::AichFileHashReq) {
            MultiRequest::AichFileHash
        } else {
            MultiRequest::Unknown(op)
        };
        requests.push(req);
    }
    Ok(PeerPacket::MultiPacket {
        hash,
        size,
        requests,
    })
}

fn parse_multi_answer(p: &[u8], ctx: ParseContext) -> Result<PeerPacket, BadPacket> {
    let io = BadPacket::io("multipacket answer");
    let mut r = Reader::new(p);
    let hash = r.hash().map_err(&io)?;
    let mut answers = Vec::new();
    while !r.is_eof() {
        let op = r.u8().map_err(&io)?;
        let a = if op == u8::from(Standard::ReqFilenameAnswer) {
            MultiAnswer::FileName(r.string(ctx.unicode, LenField::U16, false).map_err(&io)?)
        } else if op == u8::from(Standard::FileStatus) {
            MultiAnswer::FileStatus(PartStatus::read(&mut r).map_err(&io)?)
        } else if op == u8::from(Extended::AichFileHashAns) {
            MultiAnswer::AichFileHash(read_aich(&mut r).map_err(&io)?)
        } else {
            MultiAnswer::Unknown(op)
        };
        answers.push(a);
    }
    Ok(PeerPacket::MultiPacketAnswer { hash, answers })
}

impl PeerPacket {
    /// Parse a packet from a peer, inflating it first if it is packed
    /// (which makes it an eMule packet, as in aMule).
    pub fn parse(mut packet: Packet, ctx: ParseContext) -> Result<PeerPacket, BadPacket> {
        if packet.protocol == u8::from(Protocol::Packed) {
            packet
                .unpack(CLIENT_UNPACK_LIMIT)
                .map_err(|e| BadPacket::new("packed packet", e.to_string()))?;
        }
        match Protocol::try_from(packet.protocol) {
            Ok(Protocol::Edonkey) => match Standard::try_from(packet.opcode) {
                Ok(op) => Self::parse_standard(op, packet, ctx),
                Err(_) => Ok(PeerPacket::Other(packet)),
            },
            Ok(Protocol::Emule) => match Extended::try_from(packet.opcode) {
                Ok(op) => Self::parse_extended(op, packet, ctx),
                Err(_) => Ok(PeerPacket::Other(packet)),
            },
            _ => Ok(PeerPacket::Other(packet)),
        }
    }

    fn parse_standard(op: Standard, packet: Packet, ctx: ParseContext) -> Result<Self, BadPacket> {
        let p = packet.payload.as_slice();
        let mut r = Reader::new(p);
        Ok(match op {
            Standard::Hello => PeerPacket::Hello(Hello::parse_hello(p)?),
            Standard::HelloAnswer => PeerPacket::HelloAnswer(Hello::parse_hello_answer(p)?),
            Standard::RequestFilename => {
                let io = BadPacket::io("file name request");
                let hash = r.hash().map_err(&io)?;
                // A peer that advertises extended requests must send them.
                if ctx.extended_requests_version > 0 && r.is_eof() {
                    return Err(BadPacket::new(
                        "file name request",
                        "extended requests advertised but not sent",
                    ));
                }
                let ext =
                    FileRequestExt::read(&mut r, ctx.extended_requests_version).map_err(&io)?;
                PeerPacket::RequestFileName { hash, ext }
            }
            Standard::ReqFilenameAnswer => {
                let io = BadPacket::io("file name");
                PeerPacket::FileName {
                    hash: r.hash().map_err(&io)?,
                    name: r.string(ctx.unicode, LenField::U16, false).map_err(&io)?,
                }
            }
            Standard::SetReqFileId => {
                PeerPacket::SetReqFileId(exactly_hash("file status request", p)?)
            }
            Standard::FileStatus => {
                let io = BadPacket::io("file status");
                PeerPacket::FileStatus {
                    hash: r.hash().map_err(&io)?,
                    parts: PartStatus::read(&mut r).map_err(&io)?,
                }
            }
            Standard::FileReqAnsNoFil => PeerPacket::NoSuchFile(exactly_hash("no such file", p)?),
            Standard::HashsetRequest => {
                PeerPacket::HashSetRequest(exactly_hash("hash set request", p)?)
            }
            Standard::HashsetAnswer => {
                let io = BadPacket::io("hash set");
                let hash = r.hash().map_err(&io)?;
                let count = r.u16().map_err(&io)?;
                let parts = (0..count)
                    .map(|_| r.hash())
                    .collect::<Result<_, _>>()
                    .map_err(&io)?;
                PeerPacket::HashSetAnswer { hash, parts }
            }
            // aMule ignores an upload request of the wrong size.
            Standard::StartUploadReq => match exactly_hash("upload request", p) {
                Ok(h) => PeerPacket::StartUploadReq(h),
                Err(_) => PeerPacket::Other(packet),
            },
            Standard::AcceptUploadReq => PeerPacket::AcceptUploadReq,
            Standard::QueueRank => {
                PeerPacket::QueueRank(r.u32().map_err(BadPacket::io("queue rank"))?)
            }
            Standard::RequestParts => parse_request_parts(p, false)?,
            Standard::SendingPart => parse_block(p, false, false)?,
            Standard::CancelTransfer => PeerPacket::CancelTransfer,
            Standard::OutOfPartReqs => PeerPacket::OutOfPartReqs,
            // aMule reads the first 16 bytes and ignores a shorter packet.
            Standard::EndOfDownload => match p.get(..16) {
                Some(h) => PeerPacket::EndOfDownload(exactly_hash("end of download", h)?),
                None => PeerPacket::Other(packet),
            },
            _ => PeerPacket::Other(packet),
        })
    }

    fn parse_extended(op: Extended, packet: Packet, ctx: ParseContext) -> Result<Self, BadPacket> {
        let p = packet.payload.as_slice();
        Ok(match op {
            Extended::EmuleInfo | Extended::EmuleInfoAnswer => PeerPacket::MuleInfo {
                info: MuleInfo::parse(p)?,
                answer: op == Extended::EmuleInfoAnswer,
            },
            Extended::QueueRanking => {
                if p.len() != 12 {
                    return Err(BadPacket::new(
                        "queue ranking",
                        format!("{} bytes, not 12", p.len()),
                    ));
                }
                PeerPacket::QueueRanking(u16::from_le_bytes([p[0], p[1]]))
            }
            Extended::RequestPartsI64 => parse_request_parts(p, true)?,
            Extended::SendingPartI64 => parse_block(p, false, true)?,
            Extended::CompressedPart => parse_block(p, true, false)?,
            Extended::CompressedPartI64 => parse_block(p, true, true)?,
            Extended::MultiPacket => parse_multi_packet(p, false, ctx)?,
            Extended::MultiPacketExt => parse_multi_packet(p, true, ctx)?,
            Extended::MultiPacketAnswer => parse_multi_answer(p, ctx)?,
            // aMule reads the hash and ignores anything after it.
            Extended::AichFileHashReq => PeerPacket::AichFileHashReq(
                Reader::new(p)
                    .hash()
                    .map_err(BadPacket::io("AICH file hash request"))?,
            ),
            Extended::AichFileHashAns => {
                let io = BadPacket::io("AICH file hash");
                let mut r = Reader::new(p);
                PeerPacket::AichFileHashAns {
                    hash: r.hash().map_err(&io)?,
                    aich: read_aich(&mut r).map_err(&io)?,
                }
            }
            Extended::RequestSources => {
                if p.len() != 16 {
                    return Err(BadPacket::new("source request", "invalid size"));
                }
                PeerPacket::RequestSources(exactly_hash("source request", p)?)
            }
            Extended::RequestSources2 => {
                if p.len() != 19 {
                    return Err(BadPacket::new("source request", "invalid size"));
                }
                let mut r = Reader::new(p);
                let io = BadPacket::io("source request");
                PeerPacket::RequestSources2 {
                    version: r.u8().map_err(&io)?,
                    options: r.u16().map_err(&io)?,
                    hash: r.hash().map_err(&io)?,
                }
            }
            Extended::AnswerSources => {
                let hash = Reader::new(p)
                    .hash()
                    .map_err(BadPacket::io("source answer"))?;
                PeerPacket::AnswerSources {
                    hash,
                    body: p[16..].to_vec(),
                }
            }
            Extended::AnswerSources2 => {
                let mut r = Reader::new(p);
                let io = BadPacket::io("source answer");
                let version = r.u8().map_err(&io)?;
                let hash = r.hash().map_err(&io)?;
                PeerPacket::AnswerSources2 {
                    version,
                    hash,
                    body: p[17..].to_vec(),
                }
            }
            // aMule ignores a malformed state, key or signature.
            Extended::SecIdentState => {
                match (p.len(), p.first().and_then(|&v| Need::from_value(v))) {
                    (5, Some(need)) => PeerPacket::SecIdentState {
                        need,
                        challenge: u32::from_le_bytes([p[1], p[2], p[3], p[4]]),
                    },
                    _ => PeerPacket::Other(packet),
                }
            }
            Extended::PublicKey => match p.split_first() {
                Some((&n, key)) if usize::from(n) == key.len() && p.len() <= 250 => {
                    PeerPacket::PublicKey(key.to_vec())
                }
                _ => PeerPacket::Other(packet),
            },
            Extended::Signature => match p.split_first() {
                Some((&n, rest)) if p.len() <= 250 && usize::from(n) == rest.len() => {
                    PeerPacket::Signature {
                        signature: rest.to_vec(),
                        ip_kind: None,
                    }
                }
                Some((&n, rest)) if p.len() <= 250 && usize::from(n) + 1 == rest.len() => {
                    PeerPacket::Signature {
                        signature: rest[..rest.len() - 1].to_vec(),
                        ip_kind: rest.last().copied(),
                    }
                }
                _ => PeerPacket::Other(packet),
            },
            Extended::AichRequest => {
                if p.len() != 16 + 2 + 20 {
                    return Err(BadPacket::new("AICH request", "wrong size"));
                }
                let mut r = Reader::new(p);
                let io = BadPacket::io("AICH request");
                PeerPacket::AichRequest {
                    hash: r.hash().map_err(&io)?,
                    part: r.u16().map_err(&io)?,
                    root: read_aich(&mut r).map_err(&io)?,
                }
            }
            Extended::AichAnswer => {
                if p.len() <= 16 {
                    PeerPacket::AichAnswer(None)
                } else {
                    let mut r = Reader::new(p);
                    let io = BadPacket::io("AICH answer");
                    let hash = r.hash().map_err(&io)?;
                    let part = r.u16().map_err(&io)?;
                    let root = read_aich(&mut r).map_err(&io)?;
                    PeerPacket::AichAnswer(Some(AichRecovery {
                        hash,
                        part,
                        root,
                        data: p[38..].to_vec(),
                    }))
                }
            }
            _ => PeerPacket::Other(packet),
        })
    }
}
