// SPDX-License-Identifier: GPL-2.0-or-later
//! Kademlia opcodes, versions and limits.
//!
//! Port of `include/protocol/kad/**` and `include/protocol/kad2/**`. Kad 1 and
//! Kad 2 opcodes share one namespace, protocol byte
//! [`crate::Protocol::Kademlia`] (or [`crate::Protocol::KademliaPacked`]), and
//! their values do not overlap; [`Opcode`] reads either.
//!
//! The Kad2 opcodes that travel as eMule-extended packets live with them:
//! [`crate::ed2k::client_tcp::Extended::FwCheckUdpReq`] and
//! [`crate::ed2k::client_udp::Opcode::DirectCallbackReq`].

use std::time::Duration;

const fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}
const fn hours(h: u64) -> Duration {
    Duration::from_secs(h * 3600)
}

// ------------------------------------------------------------ Constants.h ---

/// `KADEMLIAASKTIME`
pub const KADEMLIAASKTIME: Duration = secs(1);
/// `KADEMLIAPUBLISHTIME`
pub const KADEMLIAPUBLISHTIME: Duration = secs(2);
/// `KADEMLIATOTALSTORENOTES`: hashes to store notes on.
pub const KADEMLIATOTALSTORENOTES: u32 = 1;
/// `KADEMLIATOTALSTORESRC`: hashes to store sources on.
pub const KADEMLIATOTALSTORESRC: u32 = 3;
/// `KADEMLIATOTALSTOREKEY`: hashes to store keywords on.
pub const KADEMLIATOTALSTOREKEY: u32 = 2;
/// `KADEMLIAREPUBLISHTIMES`: source republish interval.
pub const KADEMLIAREPUBLISHTIMES: Duration = hours(5);
/// `KADEMLIAREPUBLISHTIMEN`: notes republish interval.
pub const KADEMLIAREPUBLISHTIMEN: Duration = hours(24);
/// `KADEMLIAREPUBLISHTIMEK`: keyword republish interval.
pub const KADEMLIAREPUBLISHTIMEK: Duration = hours(24);
/// `KADEMLIADISCONNECTDELAY`
pub const KADEMLIADISCONNECTDELAY: Duration = secs(20 * 60);
/// `KADEMLIAMAXINDEX`: keyword indexes in total.
pub const KADEMLIAMAXINDEX: u32 = 50_000;
/// `KADEMLIAMAXENTRIES`: keyword entries in total.
pub const KADEMLIAMAXENTRIES: u32 = 60_000;
/// `KADEMLIAMAXSOURCEPERFILE`: sources per file in the index.
pub const KADEMLIAMAXSOURCEPERFILE: u32 = 1_000;
/// `KADEMLIAMAXNOTESPERFILE`: notes per entry in the index.
pub const KADEMLIAMAXNOTESPERFILE: u32 = 150;
/// `KADEMLIAMAXSOURCES`: source entries in the index (~820 bytes each).
pub const KADEMLIAMAXSOURCES: u32 = 100_000;
/// `KADEMLIAMAXNOTES`: note entries in the index (up to ~2.2 KB each).
pub const KADEMLIAMAXNOTES: u32 = 20_000;
/// `KADEMLIAMAXSOURCESTRLEN`: characters in a known string tag of a source.
pub const KADEMLIAMAXSOURCESTRLEN: usize = 64;
/// `KADEMLIAMAXSOURCEEXTRABYTES`: unknown tag bytes kept per source, as sent.
pub const KADEMLIAMAXSOURCEEXTRABYTES: usize = 2048;
/// `KADEMLIAMAXEXTRATAGBYTES`: unknown source tag bytes kept index-wide.
pub const KADEMLIAMAXEXTRATAGBYTES: usize = 8 * 1024 * 1024;
/// `KADEMLIAMAXNOTENAMELEN`: characters in a published note's file name.
pub const KADEMLIAMAXNOTENAMELEN: usize = 255;
/// `KADEMLIAMAXNOTECOMMENTLEN`: characters in a published note's comment.
pub const KADEMLIAMAXNOTECOMMENTLEN: usize = 128;
/// `KADEMLIAFIREWALLCHECKS`: firewall check requests at a time.
pub const KADEMLIAFIREWALLCHECKS: u32 = 4;

wire_enum! {
    /// The request type byte of `KADEMLIA2_REQ` (`KADEMLIA_FIND_*`): how many
    /// contacts the asker wants back.
    pub enum FindType: u8 {
        /// `KADEMLIA_FIND_VALUE`
        FindValue = 0x02,
        /// `KADEMLIA_STORE`
        Store = 0x04,
        /// `KADEMLIA_FIND_NODE`, also `KADEMLIA_FIND_VALUE_MORE`
        FindNode = 0x0B,
    }
}

impl FindType {
    /// `KADEMLIA_FIND_VALUE_MORE`, an alias of `KADEMLIA_FIND_NODE`.
    pub const FIND_VALUE_MORE: FindType = FindType::FindNode;
}

// ------------------------------------------------------- kad2/Constants.h ---

/// Kad protocol versions, the version byte of every Kad2 contact record
/// (`KADEMLIA_VERSION*`). A peer at one version must not be sent features of
/// a later one.
pub mod version {
    /// `KADEMLIA_VERSION1_46c`: eMule 0.45b - 0.46c.
    pub const V1_46C: u8 = 0x01;
    /// `KADEMLIA_VERSION2_47a`
    pub const V2_47A: u8 = 0x02;
    /// `KADEMLIA_VERSION3_47b`
    pub const V3_47B: u8 = 0x03;
    /// `KADEMLIA_VERSION4_47c`
    pub const V4_47C: u8 = 0x04;
    /// `KADEMLIA_VERSION5_48a`
    pub const V5_48A: u8 = 0x05;
    /// `KADEMLIA_VERSION6_49aBETA`: `OP_FWCHECKUDPREQ`, obfuscation, direct
    /// callbacks, source type 6, UDP firewall check.
    pub const V6_49A_BETA: u8 = 0x06;
    /// `KADEMLIA_VERSION7_49a`: `OP_KAD_FWTCPCHECK_ACK`, `KADEMLIA_FIREWALLED2_REQ`.
    pub const V7_49A: u8 = 0x07;
    /// `KADEMLIA_VERSION8_49b`: `TAG_KADMISCOPTIONS`, `KADEMLIA2_HELLO_RES_ACK`.
    pub const V8_49B: u8 = 0x08;
    /// `KADEMLIA_VERSION9_50a`: AICH hashes on keyword storage.
    pub const V9_50A: u8 = 0x09;
    /// `KADEMLIA_VERSION_DEFAULT`: what aMule advertises by default (0.49b),
    /// for the widest compatibility.
    pub const DEFAULT: u8 = V8_49B;
    /// `KADEMLIA_VERSION_PROTOCOL10`: advertised when the `KadProtocol10`
    /// preference is on (what eMule/eMuleAI advertise). Adds no wire element
    /// beyond 0x09. `CT_EMULE_MISCOPTIONS2` only has four bits for the Kad
    /// version, so 0x0F is the ceiling.
    pub const PROTOCOL10: u8 = 0x0a;

    // CT_EMULE_MISCOPTIONS2 has four bits for the Kad version.
    const _: () = assert!(PROTOCOL10 < 0x10 && DEFAULT < 0x10);
}

// ----------------------------------------------- kad/Client2Client/UDP.h ---

/// Kad 1 opcodes. Most are deprecated; the search/publish ones are still
/// answered for old peers.
pub mod v1 {
    wire_enum! {
        /// `enum KademliaV1OPcodes`.
        pub enum Opcode: u8 {
            /// `KADEMLIA_BOOTSTRAP_REQ_DEPRECATED`: `<PEER (sender) [25]>`
            BootstrapReq = 0x00,
            /// `KADEMLIA_BOOTSTRAP_RES_DEPRECATED`: `<CNT [2]> <PEER [25]>*(CNT)`
            BootstrapRes = 0x08,
            /// `KADEMLIA_HELLO_REQ_DEPRECATED`: `<PEER (sender) [25]>`
            HelloReq = 0x10,
            /// `KADEMLIA_HELLO_RES_DEPRECATED`: `<PEER (receiver) [25]>`
            HelloRes = 0x18,
            /// `KADEMLIA_REQ_DEPRECATED`: `<TYPE [1]> <HASH (target) [16]> <HASH (receiver) 16>`
            Req = 0x20,
            /// `KADEMLIA_RES_DEPRECATED`: `<HASH (target) [16]> <CNT> <PEER [25]>*(CNT)`
            Res = 0x28,
            /// `KADEMLIA_SEARCH_REQ`: `<HASH (key) [16]> <ext 0/1 [1]> <SEARCH_TREE>[ext]`
            SearchReq = 0x30,
            /// `KADEMLIA_SEARCH_NOTES_REQ`: `<HASH (key) [16]>`
            SearchNotesReq = 0x32,
            /// `KADEMLIA_SEARCH_RES`:
            /// `<HASH (key) [16]> <CNT1 [2]> (<HASH (answer) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)`
            SearchRes = 0x38,
            /// `KADEMLIA_SEARCH_NOTES_RES`: as `KADEMLIA_SEARCH_RES`
            SearchNotesRes = 0x3A,
            /// `KADEMLIA_PUBLISH_REQ`:
            /// `<HASH (key) [16]> <CNT1 [2]> (<HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)`
            PublishReq = 0x40,
            /// `KADEMLIA_PUBLISH_NOTES_REQ_DEPRECATED`:
            /// `<HASH (key) [16]> <HASH (target) [16]> <CNT2 [2]> <META>*(CNT2))*(CNT1)`
            PublishNotesReq = 0x42,
            /// `KADEMLIA_PUBLISH_RES`: `<HASH (key) [16]>`
            PublishRes = 0x48,
            /// `KADEMLIA_PUBLISH_NOTES_RES_DEPRECATED`: `<HASH (key) [16]>`
            PublishNotesRes = 0x4A,
            /// `KADEMLIA_FIREWALLED_REQ`: `<TCPPORT (sender) [2]>`
            FirewalledReq = 0x50,
            /// `KADEMLIA_FINDBUDDY_REQ`: `<TCPPORT (sender) [2]>`
            FindBuddyReq = 0x51,
            /// `KADEMLIA_CALLBACK_REQ`: `<TCPPORT (sender) [2]>`
            CallbackReq = 0x52,
            /// `KADEMLIA_FIREWALLED_RES`: `<IP (sender) [4]>`
            FirewalledRes = 0x58,
            /// `KADEMLIA_FIREWALLED_ACK_RES`: (null)
            FirewalledAckRes = 0x59,
            /// `KADEMLIA_FINDBUDDY_RES`: `<TCPPORT (sender) [2]>`
            FindBuddyRes = 0x5A,
        }
    }
}

// ---------------------------------------------- kad2/Client2Client/UDP.h ---

/// Kad 2 opcodes.
pub mod v2 {
    wire_enum! {
        /// `enum Kademlia2Opcodes`.
        pub enum Opcode: u8 {
            /// `KADEMLIA2_BOOTSTRAP_REQ`
            BootstrapReq = 0x01,
            /// `KADEMLIA2_BOOTSTRAP_RES`
            BootstrapRes = 0x09,
            /// `KADEMLIA2_HELLO_REQ`
            HelloReq = 0x11,
            /// `KADEMLIA2_HELLO_RES`
            HelloRes = 0x19,
            /// `KADEMLIA2_REQ`
            Req = 0x21,
            /// `KADEMLIA2_HELLO_RES_ACK`: `<NodeID><uint8 tags>`
            HelloResAck = 0x22,
            /// `KADEMLIA2_RES`
            Res = 0x29,
            /// `KADEMLIA2_SEARCH_KEY_REQ`
            SearchKeyReq = 0x33,
            /// `KADEMLIA2_SEARCH_SOURCE_REQ`
            SearchSourceReq = 0x34,
            /// `KADEMLIA2_SEARCH_NOTES_REQ`
            SearchNotesReq = 0x35,
            /// `KADEMLIA2_SEARCH_RES`
            SearchRes = 0x3B,
            /// `KADEMLIA2_PUBLISH_KEY_REQ`
            PublishKeyReq = 0x43,
            /// `KADEMLIA2_PUBLISH_SOURCE_REQ`
            PublishSourceReq = 0x44,
            /// `KADEMLIA2_PUBLISH_NOTES_REQ`
            PublishNotesReq = 0x45,
            /// `KADEMLIA2_PUBLISH_RES`
            PublishRes = 0x4B,
            /// `KADEMLIA2_PUBLISH_RES_ACK`: (null)
            PublishResAck = 0x4C,
            /// `KADEMLIA_FIREWALLED2_REQ`: `<TCPPORT (sender) [2]><userhash><connectoptions 1>`
            Firewalled2Req = 0x53,
            /// `KADEMLIA2_PING`: (null)
            Ping = 0x60,
            /// `KADEMLIA2_PONG`: (null)
            Pong = 0x61,
            /// `KADEMLIA2_FIREWALLUDP`: `<errorcode [1]><UDPPort_Used [2]>`
            FirewallUdp = 0x62,
        }
    }
}

/// Any opcode after a Kad protocol byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Opcode {
    V1(v1::Opcode),
    V2(v2::Opcode),
}

impl TryFrom<u8> for Opcode {
    type Error = crate::Unknown<u8>;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        v2::Opcode::try_from(v)
            .map(Opcode::V2)
            .or_else(|_| v1::Opcode::try_from(v).map(Opcode::V1))
            .map_err(|_| crate::Unknown {
                kind: "kad::Opcode",
                value: v,
            })
    }
}

impl From<Opcode> for u8 {
    fn from(o: Opcode) -> u8 {
        match o {
            Opcode::V1(o) => o.into(),
            Opcode::V2(o) => o.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kad1_and_kad2_opcodes_do_not_overlap() {
        for a in v1::Opcode::ALL {
            assert!(
                v2::Opcode::try_from(u8::from(*a)).is_err(),
                "{a:?} collides with a Kad2 opcode"
            );
        }
    }

    #[test]
    fn combined_opcode_reads_both_versions() {
        assert_eq!(
            Opcode::try_from(0x30),
            Ok(Opcode::V1(v1::Opcode::SearchReq))
        );
        assert_eq!(Opcode::try_from(0x60), Ok(Opcode::V2(v2::Opcode::Ping)));
        assert_eq!(u8::from(Opcode::V2(v2::Opcode::FirewallUdp)), 0x62);
        assert_eq!(
            Opcode::try_from(0x31).unwrap_err().to_string(),
            "unknown kad::Opcode 0x31"
        );
    }

    #[test]
    fn versions_and_find_types() {
        assert_eq!(version::DEFAULT, 0x08);
        assert_eq!(FindType::FIND_VALUE_MORE.value(), 0x0B);
    }
}
