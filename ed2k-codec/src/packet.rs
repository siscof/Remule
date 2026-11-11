// SPDX-License-Identifier: GPL-2.0-or-later
//! eD2k/Kad packet framing and zlib packing. Port of `Packet.{h,cpp}`
//! (`CPacket`).
//!
//! * **TCP** frames start with a 6-byte header (`Header_Struct`): the
//!   protocol byte, a `u32` little-endian length that counts the opcode plus
//!   the payload, then the opcode.
//! * **UDP** datagrams start with just the protocol byte and the opcode
//!   (`UDP_Header_Struct`).
//! * **Packing** zlib-compresses the payload when that makes it smaller and
//!   switches the protocol byte to its packed variant; unpacking reverses it,
//!   refusing to inflate beyond a caller-given limit.
//!
//! Not ported: the "split" packets, which are raw slices of a large outgoing
//! packet cut up by the socket layer for throttling (phase 5), and the
//! `Copy*ToDataBuffer` helpers (the payload here is a plain `Vec`).
//! The protocol byte is kept raw, as the C++ does: a frame with an unknown
//! protocol still parses, and [`Packet::kind`] says what it is.

use std::fmt;

use ed2k_types::{Protocol, Unknown};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

/// Size of a TCP header (`sizeof(Header_Struct)`).
pub const HEADER_LEN: usize = 6;
/// Size of a UDP header (`sizeof(UDP_Header_Struct)`).
pub const UDP_HEADER_LEN: usize = 2;
/// The largest payload a header may announce (`MaxPacketPayload`), which
/// leaves room for allocation overhead under 2 GiB.
pub const MAX_PAYLOAD: u32 = 0x7fff_ffee;

/// Unpack limit for packets from clients (`UnPackPacket`'s default).
pub const CLIENT_UNPACK_LIMIT: u32 = 50_000;
/// Unpack limit for packets from a server (`CServerSocket::PacketReceived`).
pub const SERVER_UNPACK_LIMIT: u32 = 250_000;

/// The unpack limit aMule uses for a packed Kad datagram with this payload
/// size (`CClientUDPSocket`): ten times the datagram, plus 300, less the
/// two header bytes.
pub const fn kad_unpack_limit(payload_len: usize) -> u32 {
    let datagram = payload_len as u64 + UDP_HEADER_LEN as u64;
    let limit = datagram * 10 + 300 - UDP_HEADER_LEN as u64;
    if limit > u32::MAX as u64 {
        u32::MAX
    } else {
        limit as u32
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PacketError {
    /// A header announcing a length of 0 (no room for the opcode) or a
    /// payload over [`MAX_PAYLOAD`] (`CInvalidPacket`).
    InvalidLength(u32),
    /// A payload too large to frame.
    TooLarge(usize),
    /// A datagram shorter than the UDP header.
    Truncated,
    /// Unpacking a packet whose protocol is not a packed one.
    NotPacked(u8),
    /// The payload is not a complete zlib stream.
    Corrupt,
    /// The payload inflates past the limit.
    OverLimit(u32),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::InvalidLength(n) => write!(f, "invalid packet length {n}"),
            PacketError::TooLarge(n) => write!(f, "packet payload of {n} bytes is too large"),
            PacketError::Truncated => f.write_str("datagram shorter than its header"),
            PacketError::NotPacked(p) => write!(f, "protocol {p:#04x} is not a packed protocol"),
            PacketError::Corrupt => f.write_str("packed payload is not a valid zlib stream"),
            PacketError::OverLimit(n) => write!(f, "packed payload inflates past {n} bytes"),
        }
    }
}

impl std::error::Error for PacketError {}

/// `CheckedPayloadSize`: a payload length that a header can announce.
fn checked_payload_len(n: usize) -> Result<u32, PacketError> {
    u32::try_from(n)
        .ok()
        .filter(|&n| n <= MAX_PAYLOAD)
        .ok_or(PacketError::TooLarge(n))
}

/// A parsed TCP header (`GetPacketSizeFromHeader` and the receiving
/// constructor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub protocol: u8,
    pub opcode: u8,
    /// Bytes that follow the header.
    pub payload_len: u32,
}

impl Header {
    /// Validate a received header. The length must count at least the opcode
    /// and announce no more than [`MAX_PAYLOAD`].
    pub fn parse(h: &[u8; HEADER_LEN]) -> Result<Header, PacketError> {
        let length = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
        if length == 0 || length - 1 > MAX_PAYLOAD {
            return Err(PacketError::InvalidLength(length));
        }
        Ok(Header {
            protocol: h[0],
            opcode: h[5],
            payload_len: length - 1,
        })
    }

    /// `GetHeader`
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let len = (self.payload_len + 1).to_le_bytes();
        [self.protocol, len[0], len[1], len[2], len[3], self.opcode]
    }
}

/// One eD2k or Kad packet (`CPacket`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The protocol byte; see [`Packet::kind`].
    pub protocol: u8,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl Packet {
    /// A packet to send (`CPacket(const CMemFile&, ...)` and friends).
    pub fn new(protocol: Protocol, opcode: impl Into<u8>, payload: Vec<u8>) -> Self {
        Packet {
            protocol: protocol.into(),
            opcode: opcode.into(),
            payload,
        }
    }

    /// The protocol byte as a [`Protocol`], if it is a known one.
    pub fn kind(&self) -> Result<Protocol, Unknown<u8>> {
        Protocol::try_from(self.protocol)
    }

    /// A received TCP packet from its header and the payload read after it
    /// (`CPacket(header, buf)`).
    pub fn from_tcp(header: Header, payload: Vec<u8>) -> Result<Self, PacketError> {
        if payload.len() != header.payload_len as usize {
            return Err(PacketError::InvalidLength(payload.len() as u32 + 1));
        }
        Ok(Packet {
            protocol: header.protocol,
            opcode: header.opcode,
            payload,
        })
    }

    /// Parse a whole TCP frame held in memory: header plus exactly its payload.
    pub fn parse_tcp(frame: &[u8]) -> Result<Self, PacketError> {
        let head: &[u8; HEADER_LEN] = frame
            .get(..HEADER_LEN)
            .and_then(|h| h.try_into().ok())
            .ok_or(PacketError::Truncated)?;
        let header = Header::parse(head)?;
        Packet::from_tcp(header, frame[HEADER_LEN..].to_vec())
    }

    /// Parse a UDP datagram: protocol byte, opcode, payload.
    pub fn parse_udp(datagram: &[u8]) -> Result<Self, PacketError> {
        match datagram {
            [protocol, opcode, payload @ ..] => Ok(Packet {
                protocol: *protocol,
                opcode: *opcode,
                payload: payload.to_vec(),
            }),
            _ => Err(PacketError::Truncated),
        }
    }

    /// The TCP header for this packet.
    pub fn header(&self) -> Result<Header, PacketError> {
        let len = checked_payload_len(self.payload.len())?;
        Ok(Header {
            protocol: self.protocol,
            opcode: self.opcode,
            payload_len: len,
        })
    }

    /// The whole TCP frame (`GetPacket` / `DetachPacket`).
    pub fn to_tcp_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.header()?.to_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// The UDP datagram (`GetUDPHeader` followed by the payload).
    pub fn to_udp_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(UDP_HEADER_LEN + self.payload.len());
        out.push(self.protocol);
        out.push(self.opcode);
        out.extend_from_slice(&self.payload);
        out
    }

    /// `PackPacket`: compress the payload at the best level, but only keep
    /// the result if it is smaller. A Kad packet becomes
    /// [`Protocol::KademliaPacked`], anything else [`Protocol::Packed`].
    /// Returns whether the packet was packed.
    ///
    /// The compressed bytes are a standard zlib stream but not byte-identical
    /// to what zlib itself would produce; peers inflate them the same way.
    pub fn pack(&mut self) -> bool {
        let mut c = Compress::new(Compression::best(), true);
        let mut out = Vec::with_capacity(self.payload.len() + 300);
        let done = matches!(
            c.compress_vec(&self.payload, &mut out, FlushCompress::Finish),
            Ok(Status::StreamEnd)
        );
        if !done || out.len() >= self.payload.len() {
            return false;
        }
        self.protocol = if self.protocol == u8::from(Protocol::Kademlia) {
            Protocol::KademliaPacked.into()
        } else {
            Protocol::Packed.into()
        };
        self.payload = out;
        true
    }

    /// `UnPackPacket`: inflate a packed payload of at most `max` bytes and
    /// restore the protocol: [`Protocol::Packed`] and
    /// [`Protocol::Ed2kV2Packed`] become [`Protocol::Emule`], as in aMule, and
    /// [`Protocol::KademliaPacked`] becomes [`Protocol::Kademlia`] (as
    /// `CClientUDPSocket` does for Kad). On failure the packet is unchanged.
    ///
    /// Limits aMule uses: [`CLIENT_UNPACK_LIMIT`], [`SERVER_UNPACK_LIMIT`],
    /// [`kad_unpack_limit`].
    pub fn unpack(&mut self, max: u32) -> Result<(), PacketError> {
        let unpacked = match Protocol::try_from(self.protocol) {
            Ok(Protocol::Packed | Protocol::Ed2kV2Packed) => Protocol::Emule,
            Ok(Protocol::KademliaPacked) => Protocol::Kademlia,
            _ => return Err(PacketError::NotPacked(self.protocol)),
        };
        let mut d = Decompress::new(true);
        // One byte of headroom tells "exactly max" from "more than max".
        let mut out = Vec::with_capacity(max as usize + 1);
        let status = d.decompress_vec(&self.payload, &mut out, FlushDecompress::Finish);
        match status {
            Ok(Status::StreamEnd) if out.len() <= max as usize => {}
            Ok(_) if out.len() > max as usize => return Err(PacketError::OverLimit(max)),
            _ => return Err(PacketError::Corrupt),
        }
        self.payload = out;
        self.protocol = unpacked.into();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
