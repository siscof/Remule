// SPDX-License-Identifier: GPL-2.0-or-later
//! The protocol byte that starts every eD2k/Kad packet.
//! Port of `include/protocol/Protocols.h`.

wire_enum! {
    /// First byte of a TCP or UDP packet (`enum Protocols`).
    pub enum Protocol: u8 {
        /// `OP_EDONKEYHEADER` / `OP_EDONKEYPROT`: plain eDonkey.
        Edonkey = 0xE3,
        /// `OP_PACKEDPROT`: zlib-packed eMule-extended packet.
        Packed = 0xD4,
        /// `OP_EMULEPROT`: eMule-extended packet.
        Emule = 0xC5,
        /// `OP_UDPRESERVEDPROT1`: reserved for later UDP headers
        /// (matters to the obfuscation layer, EncryptedDatagramSocket).
        UdpReserved1 = 0xA3,
        /// `OP_UDPRESERVEDPROT2`: a frame-type byte follows instead of an
        /// eD2k opcode; see [`ReservedProt2Frame`].
        UdpReserved2 = 0xB2,
        /// `OP_KADEMLIAHEADER`: Kademlia 1/2.
        Kademlia = 0xE4,
        /// `OP_KADEMLIAPACKEDPROT`: zlib-packed Kademlia.
        KademliaPacked = 0xE5,
        /// `OP_ED2KV2HEADER`: experimental ("Kry tests").
        Ed2kV2 = 0xF4,
        /// `OP_ED2KV2PACKEDPROT`: experimental, packed.
        Ed2kV2Packed = 0xF5,
        /// `OP_MLDONKEYPROT`.
        MlDonkey = 0x00,
    }
}

impl Protocol {
    /// `OP_EDONKEYPROT`, an alias of `OP_EDONKEYHEADER`.
    pub const EDONKEY_PROT: Protocol = Protocol::Edonkey;
}

/// `EMULE_PROTOCOL`: protocol version in the old (deprecated) MuleInfo packet.
pub const EMULE_PROTOCOL: u8 = 0x01;

wire_enum! {
    /// Frame type after an [`Protocol::UdpReserved2`] byte
    /// (`enum ReservedProt2FrameTypes`). These are eMuleAI's NAT traversal
    /// frames. aMule implements none of the transports behind them; it
    /// recognises them so they are dropped as known-but-unserved rather than
    /// as malformed. A separate namespace from [`Protocol`]: `0x00` here is
    /// not `OP_MLDONKEYPROT`.
    pub enum ReservedProt2Frame: u8 {
        /// `OP_NATT_FRAME_UTP`: legacy uTP NAT-T frame.
        Utp = 0x00,
        /// `OP_NATT_FRAME_QUIC`: QUIC NAT-T frame.
        Quic = 0x01,
        /// `OP_NATT_FRAME_CAPS`: direct peer NAT-T capability negotiation.
        Caps = 0x02,
        /// `OP_NATT_FRAME_CAPS_ACK`: its acknowledgement.
        CapsAck = 0x03,
        /// `OP_NATT_FRAME_KEY`: NAT-T key frame.
        Key = 0xFF,
    }
}

/// Opcodes of the server-coordinated NAT traversal extension. aMule only
/// compiles these with `ENABLE_NATT_SERVER_COORDINATION`; each lives in its
/// own transport namespace.
pub mod natt {
    wire_enum! {
        /// `NatServerTcp::Opcode`: client <-> ed2k-server over TCP.
        pub enum ServerTcp: u8 {
            /// `OP_LOWID_HOLEPUNCH_REQUEST`
            LowIdHolepunchRequest = 0x60,
            /// `OP_LOWID_HOLEPUNCH_INFO`
            LowIdHolepunchInfo = 0x61,
            /// `OP_LOWID_HOLEPUNCH_FAIL`
            LowIdHolepunchFail = 0x62,
        }
    }

    /// `NatServerUdp::OP_NATT_KEEPALIVE`.
    pub const SERVER_UDP_KEEPALIVE: u8 = 0x9F;

    /// `NatPeerUdp::OP_NATT_HOLEPUNCH`: a raw UDP protocol byte between peers.
    /// Not the TCP buddy request that shares the value.
    pub const PEER_UDP_HOLEPUNCH: u8 = 0xB3;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_protocols_h() {
        assert_eq!(u8::from(Protocol::Edonkey), 0xE3);
        assert_eq!(Protocol::EDONKEY_PROT, Protocol::Edonkey);
        assert_eq!(Protocol::try_from(0xC5), Ok(Protocol::Emule));
        assert_eq!(Protocol::try_from(0xE5), Ok(Protocol::KademliaPacked));
        assert_eq!(
            ReservedProt2Frame::try_from(0xFF),
            Ok(ReservedProt2Frame::Key)
        );
        assert!(ReservedProt2Frame::try_from(0x04).is_err());
    }
}
