// SPDX-License-Identifier: GPL-2.0-or-later
//! Client to client over UDP (`CClientUDPSocket::ProcessPacket`,
//! `CUpDownClient::UDPReaskForDownload`): a downloader waiting in a queue
//! asks again without a TCP connection, and the uploader answers with its
//! queue rank, that its queue is full, or that it has no such file.
//!
//! A datagram is the protocol byte [`Protocol::Emule`], the opcode, then
//! the payload. What a ping and its answer carry depends on the UDP version
//! the *other* side announced in its hello (`CT_EMULE_MISCOPTIONS1`):
//!
//! | packet | UDP version 1-2 | 3 | 4 and up |
//! |---|---|---|---|
//! | `OP_REASKFILEPING` | hash | hash, complete sources | hash, part status, complete sources |
//! | `OP_REASKACK` | rank | rank | part status, rank |
//!
//! The ping's layout follows the uploader's version (the downloader writes
//! for it), the answer's the downloader's (the uploader writes for it).
//! The buddy relays (`OP_REASKCALLBACKUDP`, `OP_DIRECTCALLBACKREQ`) and the
//! NAT traversal opcodes are not here.

use ed2k_codec::{Reader, Writer};
use ed2k_types::ed2k::client_udp::Opcode;
use ed2k_types::{Md4Hash, Protocol};

use crate::PartStatus;

/// A client UDP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpPacket {
    /// `OP_REASKFILEPING`: still waiting for `file`?
    ReaskFilePing {
        file: Md4Hash,
        /// The asker's parts (UDP version 4 and up).
        parts: Option<PartStatus>,
        /// Complete sources the asker knows of (UDP version 3 and up).
        complete_sources: Option<u16>,
    },
    /// `OP_REASKACK`: yes, at this rank (0: about to get a slot).
    ReaskAck {
        /// The uploader's parts (UDP version 4 and up).
        parts: Option<PartStatus>,
        rank: u16,
    },
    /// `OP_FILENOTFOUND`: the uploader does not share the file (any more).
    FileNotFound,
    /// `OP_QUEUEFULL`: the uploader does not know the asker, and its queue
    /// is (nearly) full.
    QueueFull,
    /// `OP_REASKCALLBACKUDP`: a reask for a firewalled source, sent to its
    /// Kad buddy to pass on: `<buddy ID 16>` (raw, as the source published
    /// it) then what an `OP_REASKFILEPING` carries, laid out for the
    /// source's UDP version.
    ReaskCallbackUdp {
        buddy_id: [u8; 16],
        /// The `OP_REASKFILEPING` payload: file hash first.
        ping: Vec<u8>,
    },
}

/// Why a datagram is not a client UDP packet we read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BadUdpPacket {
    #[error("not an eMule protocol datagram")]
    NotEmule,
    #[error("opcode {0:#04x} not handled")]
    Unhandled(u8),
    #[error("truncated or malformed: {0}")]
    Malformed(String),
}

impl UdpPacket {
    /// The datagram, laid out for a peer of `udp_version`: the uploader's
    /// for a ping, the downloader's for an answer.
    pub fn to_datagram(&self, udp_version: u8) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(Protocol::Emule as u8);
        match self {
            UdpPacket::ReaskFilePing {
                file,
                parts,
                complete_sources,
            } => {
                w.u8(Opcode::ReaskFilePing as u8);
                w.hash(*file);
                if udp_version > 3 {
                    // A complete file is written as no parts (aMule's
                    // `WriteUInt16(0)` for a shared file).
                    parts.clone().unwrap_or(PartStatus::Complete).write(&mut w);
                }
                if udp_version > 2 {
                    w.u16(complete_sources.unwrap_or(0));
                }
            }
            UdpPacket::ReaskAck { parts, rank } => {
                w.u8(Opcode::ReaskAck as u8);
                if udp_version > 3 {
                    parts.clone().unwrap_or(PartStatus::Complete).write(&mut w);
                }
                w.u16(*rank);
            }
            UdpPacket::FileNotFound => {
                w.u8(Opcode::FileNotFound as u8);
            }
            UdpPacket::QueueFull => {
                w.u8(Opcode::QueueFull as u8);
            }
            UdpPacket::ReaskCallbackUdp { buddy_id, ping } => {
                w.u8(Opcode::ReaskCallbackUdp as u8);
                w.bytes(buddy_id);
                w.bytes(ping);
            }
        }
        w.into_bytes()
    }

    /// Read a datagram (already decrypted) from a peer of `udp_version`:
    /// the downloader's for a ping, the uploader's for an answer. `None`
    /// when the sender is unknown: a ping is read as far as its hash (what
    /// aMule needs to say the file is not shared, or the queue full).
    pub fn parse(datagram: &[u8], udp_version: Option<u8>) -> Result<UdpPacket, BadUdpPacket> {
        let bad = |e: ed2k_codec::Error| BadUdpPacket::Malformed(e.to_string());
        let (&proto, rest) = datagram.split_first().ok_or(BadUdpPacket::NotEmule)?;
        if proto != Protocol::Emule as u8 {
            return Err(BadUdpPacket::NotEmule);
        }
        let (&op, payload) = rest
            .split_first()
            .ok_or_else(|| BadUdpPacket::Malformed("no opcode".into()))?;
        let mut r = Reader::new(payload);
        let v = udp_version.unwrap_or(0);
        match Opcode::try_from(op) {
            Ok(Opcode::ReaskFilePing) => {
                let file = r.hash().map_err(bad)?;
                let mut parts = None;
                let mut complete_sources = None;
                if v > 3 {
                    parts = Some(PartStatus::read(&mut r).map_err(bad)?);
                    complete_sources = Some(r.u16().map_err(bad)?);
                } else if v > 2 {
                    complete_sources = Some(r.u16().map_err(bad)?);
                }
                Ok(UdpPacket::ReaskFilePing {
                    file,
                    parts,
                    complete_sources,
                })
            }
            Ok(Opcode::ReaskAck) => {
                let parts = if v > 3 {
                    Some(PartStatus::read(&mut r).map_err(bad)?)
                } else {
                    None
                };
                let rank = r.u16().map_err(bad)?;
                Ok(UdpPacket::ReaskAck { parts, rank })
            }
            Ok(Opcode::ReaskCallbackUdp) => {
                // The buddy ID, then at least the file hash (`size < 17`
                // is malformed for aMule; it reads the hash later).
                if payload.len() < 32 {
                    return Err(BadUdpPacket::Malformed("callback reask too short".into()));
                }
                let mut buddy_id = [0u8; 16];
                buddy_id.copy_from_slice(&payload[..16]);
                Ok(UdpPacket::ReaskCallbackUdp {
                    buddy_id,
                    ping: payload[16..].to_vec(),
                })
            }
            Ok(Opcode::FileNotFound) => Ok(UdpPacket::FileNotFound),
            Ok(Opcode::QueueFull) => Ok(UdpPacket::QueueFull),
            _ => Err(BadUdpPacket::Unhandled(op)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Md4Hash {
        Md4Hash([b; 16])
    }

    #[test]
    fn layouts_by_udp_version() {
        let parts = PartStatus::Parts(vec![true, false, true]);
        let ping = UdpPacket::ReaskFilePing {
            file: h(7),
            parts: Some(parts.clone()),
            complete_sources: Some(5),
        };
        // Version 4: hash, part status (count 3, bits 101), complete sources.
        let mut want = vec![0xC5, 0x90];
        want.extend([7; 16]);
        want.extend([3, 0, 0b101, 5, 0]);
        assert_eq!(ping.to_datagram(4), want);
        assert_eq!(UdpPacket::parse(&want, Some(4)).unwrap(), ping);
        // Version 3: hash, complete sources.
        let v3 = ping.to_datagram(3);
        assert_eq!(v3.len(), 2 + 16 + 2);
        assert_eq!(
            UdpPacket::parse(&v3, Some(3)).unwrap(),
            UdpPacket::ReaskFilePing {
                file: h(7),
                parts: None,
                complete_sources: Some(5)
            }
        );
        // Version 2: the hash alone; an unknown sender is read that far.
        let v2 = ping.to_datagram(2);
        assert_eq!(v2.len(), 2 + 16);
        for v in [Some(2), None] {
            assert_eq!(
                UdpPacket::parse(&v2, v).unwrap(),
                UdpPacket::ReaskFilePing {
                    file: h(7),
                    parts: None,
                    complete_sources: None
                }
            );
        }
        // A shared (complete) file's ping: no parts.
        let full = UdpPacket::ReaskFilePing {
            file: h(1),
            parts: None,
            complete_sources: Some(0),
        };
        assert_eq!(&full.to_datagram(4)[18..], &[0, 0, 0, 0]);

        let ack = UdpPacket::ReaskAck {
            parts: Some(parts),
            rank: 300,
        };
        let b = ack.to_datagram(4);
        assert_eq!(b, vec![0xC5, 0x91, 3, 0, 0b101, 0x2C, 0x01]);
        assert_eq!(UdpPacket::parse(&b, Some(4)).unwrap(), ack);
        let b = ack.to_datagram(3);
        assert_eq!(b, vec![0xC5, 0x91, 0x2C, 0x01]);
        assert_eq!(
            UdpPacket::parse(&b, Some(3)).unwrap(),
            UdpPacket::ReaskAck {
                parts: None,
                rank: 300
            }
        );
        for p in [UdpPacket::FileNotFound, UdpPacket::QueueFull] {
            let b = p.to_datagram(4);
            assert_eq!(b.len(), 2);
            assert_eq!(UdpPacket::parse(&b, None).unwrap(), p);
        }
    }

    #[test]
    fn bad_datagrams() {
        assert_eq!(UdpPacket::parse(&[], None), Err(BadUdpPacket::NotEmule));
        assert_eq!(
            UdpPacket::parse(&[0xE4, 0x90], None),
            Err(BadUdpPacket::NotEmule)
        );
        assert!(matches!(
            UdpPacket::parse(&[0xC5], None),
            Err(BadUdpPacket::Malformed(_))
        ));
        // A ping shorter than its hash, an ack without its rank.
        assert!(matches!(
            UdpPacket::parse(&[0xC5, 0x90, 1, 2, 3], None),
            Err(BadUdpPacket::Malformed(_))
        ));
        assert!(matches!(
            UdpPacket::parse(&[0xC5, 0x91, 1], Some(3)),
            Err(BadUdpPacket::Malformed(_))
        ));
        assert_eq!(
            UdpPacket::parse(&[0xC5, 0x95], None),
            Err(BadUdpPacket::Unhandled(0x95))
        );
    }
}
