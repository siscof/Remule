// SPDX-License-Identifier: GPL-2.0-or-later
//! Source exchange: asking a peer for other sources of a file and reading
//! its answer (`CPartFile::AddClientSources`), building an answer
//! (`CSourceExchangePacket`, SourceExchangePacket.h), and when to ask
//! (`CUpDownClient::IsSourceRequestAllowed`).
//!
//! Versions: SX1 is negotiated in the hello (`source_exchange1_version`),
//! SX2 carries its version in each packet. Per source, a version adds:
//!
//! ```text
//! v1: <id 4><port 2><server ip 4><server port 2>
//! v2: ... <user hash 16>
//! v3: as v2, the ID in "hybrid" form (a high ID byte-swapped)
//! v4: ... <crypt options 1>
//! ```

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use ed2k_codec::{Packet, Reader, Writer};
use ed2k_types::ed2k::client_tcp::Extended;
use ed2k_types::ed2k::{
    MINCOMMONPENALTY, RARE_FILE, SOURCECLIENTREASKF, SOURCECLIENTREASKS, SOURCEEXCHANGE2_VERSION,
};
use ed2k_types::{Md4Hash, Protocol};

/// Answers are packed when bigger than this (`CreatePacket`).
const PACK_ABOVE: usize = 354;

/// A builder stops after 501 sources, as aMule's callers did.
pub const MAX_SOURCES_PER_ANSWER: usize = 501;

/// `IsLowID`
fn is_low_id(id: u32) -> bool {
    id < 0x0100_0000
}

/// One source from an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangedSource {
    /// The eD2k ID: a high ID is the IPv4 address, low byte first.
    pub id: u32,
    pub port: u16,
    pub server: SocketAddrV4,
    /// From v2.
    pub user_hash: Option<Md4Hash>,
    /// From v4: the obfuscation flags (`SetConnectOptions`).
    pub crypt_options: Option<u8>,
}

impl ExchangedSource {
    pub fn is_low_id(&self) -> bool {
        is_low_id(self.id)
    }

    /// The address of a high-ID source.
    pub fn ip(&self) -> Option<Ipv4Addr> {
        (!self.is_low_id()).then(|| Ipv4Addr::from(self.id.to_le_bytes()))
    }
}

fn entry_size(version: u8) -> usize {
    match version {
        1 => 12,
        2 | 3 => 28,
        _ => 29,
    }
}

/// Why an answer was dropped (aMule logs and ignores it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadAnswer(pub String);

/// `AddClientSources`: the sources in an answer's body, after the file hash
/// (and, for SX2, after the version byte, which is `version`).
///
/// SX1 (`sx2 == false`): the layout is told by the size, then must agree
/// with the SX1 version the peer announced (`peer_sx1_version`). SX2: the
/// version must be known and the size must match it exactly.
pub fn parse_answer(
    body: &[u8],
    sx2: bool,
    version: u8,
) -> Result<Vec<ExchangedSource>, BadAnswer> {
    let mut r = Reader::new(body);
    let count = r.u16().map_err(|_| BadAnswer("no source count".into()))? as usize;
    let size = r.remaining();
    let packet_version = if !sx2 {
        if count * 12 == size {
            if version != 1 {
                return Err(BadAnswer(format!("v1 layout from an SX1 v{version} peer")));
            }
            1
        } else if count * 28 == size {
            match version {
                2 => 2,
                v if v > 2 => 3,
                _ => return Err(BadAnswer("v2 layout from an SX1 v1 peer".into())),
            }
        } else if count * 29 == size {
            if version != 4 {
                return Err(BadAnswer(format!("v4 layout from an SX1 v{version} peer")));
            }
            4
        } else {
            return Err(BadAnswer(format!(
                "{size} bytes for {count} sources (SX1 v{version})"
            )));
        }
    } else {
        if version == 0 || version > SOURCEEXCHANGE2_VERSION {
            return Err(BadAnswer(format!("unknown SX2 version {version}")));
        }
        if count * entry_size(version) != size {
            return Err(BadAnswer(format!(
                "{size} bytes for {count} sources (SX2 v{version})"
            )));
        }
        version
    };
    let io = |_| BadAnswer("truncated".into());
    (0..count)
        .map(|_| {
            let raw = r.u32().map_err(io)?;
            let port = r.u16().map_err(io)?;
            let server_ip = r.u32().map_err(io)?;
            let server_port = r.u16().map_err(io)?;
            let user_hash = if packet_version > 1 {
                Some(r.hash().map_err(io)?)
            } else {
                None
            };
            let crypt_options = if packet_version >= 4 {
                Some(r.u8().map_err(io)?)
            } else {
                None
            };
            // v3+ send the hybrid ID: a high ID swapped, a low ID as is.
            let id = if packet_version >= 3 && !is_low_id(raw) {
                raw.swap_bytes()
            } else {
                raw
            };
            Ok(ExchangedSource {
                id,
                port,
                server: SocketAddrV4::new(Ipv4Addr::from(server_ip.to_le_bytes()), server_port),
                user_hash,
                crypt_options,
            })
        })
        .collect()
}

/// `CSourceExchangePacket`: an answer to a source request.
#[derive(Debug, Clone)]
pub struct AnswerBuilder {
    sx2: bool,
    version: u8,
    hash: Md4Hash,
    data: Writer,
    count: usize,
}

impl AnswerBuilder {
    /// Answer a peer that supports SX2 (`peer_sx2`) or not, announced SX1
    /// `peer_sx1_version`, and asked with SX2 `requested_version` (0 for an
    /// SX1 request). SX2 is answered at most at our version.
    pub fn new(hash: Md4Hash, peer_sx2: bool, peer_sx1_version: u8, requested_version: u8) -> Self {
        let sx2 = peer_sx2 && requested_version > 0;
        let version = if sx2 {
            requested_version.min(SOURCEEXCHANGE2_VERSION)
        } else {
            peer_sx1_version
        };
        AnswerBuilder {
            sx2,
            version,
            hash,
            data: Writer::new(),
            count: 0,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// `IsFull`: 501 sources.
    pub fn is_full(&self) -> bool {
        self.count >= MAX_SOURCES_PER_ANSWER
    }

    /// `AddSource`. `id` is the eD2k ID; aMule only sends high IDs.
    pub fn add(&mut self, s: &ExchangedSource) {
        // v3+ hybrid, else the eD2k ID (aMule swaps the hybrid back).
        let id = if self.version >= 3 && !s.is_low_id() {
            s.id.swap_bytes()
        } else {
            s.id
        };
        self.data
            .u32(id)
            .u16(s.port)
            .u32(u32::from_le_bytes(s.server.ip().octets()))
            .u16(s.server.port());
        if self.version >= 2 {
            self.data.hash(s.user_hash.unwrap_or(Md4Hash([0; 16])));
        }
        if self.version >= 4 {
            self.data.u8(s.crypt_options.unwrap_or(0));
        }
        self.count += 1;
    }

    /// `CreatePacket`: `OP_ANSWERSOURCES(2)`, packed above 354 bytes;
    /// `None` without sources, which is not sent.
    pub fn finish(self) -> Option<Packet> {
        if self.count == 0 {
            return None;
        }
        let mut w = Writer::new();
        if self.sx2 {
            w.u8(self.version);
        }
        w.hash(self.hash).u16(self.count as u16);
        let mut payload = w.into_bytes();
        payload.extend_from_slice(&self.data.into_bytes());
        let op = if self.sx2 {
            Extended::AnswerSources2
        } else {
            Extended::AnswerSources
        };
        let mut p = Packet::new(Protocol::Emule, op, payload);
        if p.payload.len() > PACK_ABOVE {
            p.pack();
        }
        Some(p)
    }
}

/// What [`source_request_allowed`] weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRequestInput {
    /// The peer speaks the eMule protocol (`ExtProtocolAvailable`).
    pub ext_protocol: bool,
    pub peer_sx2: bool,
    pub peer_sx1_version: u8,
    /// Sources the file has (`GetSourceCount`) and how many are usable
    /// (`GetValidSourcesCount`).
    pub sources: u32,
    pub valid_sources: u32,
    /// `GetMaxSourcePerFileSoft`
    pub max_sources_soft: u32,
    /// The peer has the whole file (`m_bCompleteSource`).
    pub peer_complete: bool,
    /// Since this peer last answered a source request (`None`: never asked).
    pub since_peer_answer: Option<Duration>,
    /// Since any peer last answered one for this file.
    pub since_file_answer: Duration,
}

/// `IsSourceRequestAllowed`. The times include aMule's
/// [`CONNECTION_LATENCY`](ed2k_types::ed2k::CONNECTION_LATENCY) allowance
/// already, if the caller wants it.
pub fn source_request_allowed(i: SourceRequestInput) -> bool {
    let never = i.since_peer_answer.is_none();
    let peer = i.since_peer_answer.unwrap_or(Duration::MAX);
    let rare = RARE_FILE;
    let penalty = MINCOMMONPENALTY;
    i.ext_protocol
        && (i.peer_sx2 || i.peer_sx1_version > 1)
        && i.max_sources_soft > i.sources
        && ((!i.peer_complete && (never || peer > SOURCECLIENTREASKS) && i.sources <= rare / 5)
            || (!i.peer_complete
                && (never || peer > SOURCECLIENTREASKS)
                && (i.sources <= rare || i.sources - i.valid_sources.min(i.sources) <= rare / 2)
                && i.since_file_answer > SOURCECLIENTREASKF)
            || ((never || peer > SOURCECLIENTREASKS * penalty)
                && i.since_file_answer > SOURCECLIENTREASKF * penalty))
}
