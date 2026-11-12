// SPDX-License-Identifier: GPL-2.0-or-later
//! eD2k TCP framing for `tokio_util::codec` (`CEMSocket::OnReceive` and
//! `SendPacket`, EMSocket.cpp): a 6-byte header `<protocol 1><length 4><opcode 1>`,
//! the length counting the opcode, then the payload.

use bytes::{Buf, BufMut, BytesMut};
use ed2k_codec::packet::HEADER_LEN;
use ed2k_codec::{Header, Packet, PacketError};
use tokio_util::codec::{Decoder, Encoder};

/// `MAX_PACKET_SIZE`: the largest payload `CEMSocket` accepts (`ERR_TOOBIG`).
pub const MAX_PACKET_SIZE: u32 = 2_000_000;

/// Framing errors.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// `ERR_WRONGHEADER`
    #[error("bad packet header: {0}")]
    Header(PacketError),
    /// `ERR_TOOBIG`
    #[error("packet of {0} bytes is too big (max {MAX_PACKET_SIZE})")]
    TooBig(u32),
    #[error("packet cannot be framed: {0}")]
    Encode(PacketError),
}

/// The codec. It never allocates more than the bytes that have arrived:
/// the announced length is only trusted up to [`PacketCodec::max_payload`].
#[derive(Debug, Clone)]
pub struct PacketCodec {
    max_payload: u32,
    header: Option<Header>,
}

impl Default for PacketCodec {
    fn default() -> Self {
        PacketCodec {
            max_payload: MAX_PACKET_SIZE,
            header: None,
        }
    }
}

impl PacketCodec {
    pub fn new() -> Self {
        Self::default()
    }

    /// A codec with another payload limit.
    pub fn with_max_payload(max_payload: u32) -> Self {
        PacketCodec {
            max_payload,
            header: None,
        }
    }

    pub fn max_payload(&self) -> u32 {
        self.max_payload
    }

    /// How many more bytes the packet being read needs (what `CEMSocket`
    /// reads at most, so a read never crosses a packet boundary).
    pub fn wanted(&self, buffered: usize) -> usize {
        match self.header {
            None => HEADER_LEN.saturating_sub(buffered),
            Some(h) => (h.payload_len as usize).saturating_sub(buffered),
        }
    }
}

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Packet>, CodecError> {
        if self.header.is_none() {
            if src.len() < HEADER_LEN {
                return Ok(None);
            }
            let mut raw = [0u8; HEADER_LEN];
            raw.copy_from_slice(&src[..HEADER_LEN]);
            let h = Header::parse(&raw).map_err(CodecError::Header)?;
            if h.payload_len > self.max_payload {
                return Err(CodecError::TooBig(h.payload_len));
            }
            src.advance(HEADER_LEN);
            self.header = Some(h);
        }
        let Some(h) = self.header else {
            return Ok(None);
        };
        let n = h.payload_len as usize;
        if src.len() < n {
            return Ok(None);
        }
        let payload = src.split_to(n).to_vec();
        self.header = None;
        Packet::from_tcp(h, payload)
            .map(Some)
            .map_err(CodecError::Header)
    }
}

impl Encoder<Packet> for PacketCodec {
    type Error = CodecError;

    fn encode(&mut self, p: Packet, dst: &mut BytesMut) -> Result<(), CodecError> {
        self.encode(&p, dst)
    }
}

impl Encoder<&Packet> for PacketCodec {
    type Error = CodecError;

    fn encode(&mut self, p: &Packet, dst: &mut BytesMut) -> Result<(), CodecError> {
        let h = p.header().map_err(CodecError::Encode)?;
        dst.reserve(HEADER_LEN + p.payload.len());
        dst.put_slice(&h.to_bytes());
        dst.put_slice(&p.payload);
        Ok(())
    }
}
