// SPDX-License-Identifier: GPL-2.0-or-later
//! UDP server pings (`CServerList` pings, `CServerUDPSocket`).
//!
//! A server listens for UDP on its TCP port + 4. `OP_GLOBSERVSTATREQ`
//! carries a challenge, `0x55AA0000` plus 16 random bits, which the answer
//! `OP_GLOBSERVSTATRES` repeats, followed by as many counters as the server
//! knows. (The obfuscated ping, to port + 12, is not done yet.)

use ed2k_codec::{Packet, Reader};
use ed2k_types::ed2k::server_udp::Opcode;
use ed2k_types::Protocol;
use rand::Rng;

use crate::packets::BadPacket;

/// Where a server's UDP port is, from its TCP port.
pub const UDP_PORT_OFFSET: u16 = 4;

/// A ping challenge, as aMule picks it.
pub fn ping_challenge<R: rand::RngCore + ?Sized>(rng: &mut R) -> u32 {
    0x55AA_0000 + rng.gen::<u16>() as u32
}

/// `OP_GLOBSERVSTATREQ`
pub fn ping(challenge: u32) -> Packet {
    Packet::new(
        Protocol::Edonkey,
        Opcode::GlobServStatReq,
        challenge.to_le_bytes().to_vec(),
    )
}

/// `OP_GLOBSERVSTATRES`; fields a server did not send are 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpStatus {
    pub challenge: u32,
    pub users: u32,
    pub files: u32,
    pub max_users: u32,
    pub soft_files: u32,
    pub hard_files: u32,
    /// `SRV_UDPFLG_*`
    pub udp_flags: u32,
    pub low_id_users: u32,
    pub udp_obfuscation_port: u16,
    pub tcp_obfuscation_port: u16,
    /// The key for obfuscated UDP to this server.
    pub udp_key: u32,
}

/// Parse a ping answer (the packet's payload).
pub fn parse_status(payload: &[u8]) -> Result<UdpStatus, BadPacket> {
    let n = payload.len();
    if n < 12 {
        return Err(BadPacket {
            what: "server status (UDP)",
            why: format!("{n} bytes"),
        });
    }
    let mut r = Reader::new(payload);
    // The length checks make these reads infallible.
    let mut u32_ = || r.u32().unwrap_or(0);
    let mut s = UdpStatus {
        challenge: u32_(),
        users: u32_(),
        files: u32_(),
        ..Default::default()
    };
    if n >= 16 {
        s.max_users = u32_();
    }
    if n >= 24 {
        s.soft_files = u32_();
        s.hard_files = u32_();
    }
    if n >= 28 {
        s.udp_flags = u32_();
    }
    if n >= 32 {
        s.low_id_users = u32_();
    }
    if n >= 40 {
        s.udp_obfuscation_port = r.u16().unwrap_or(0);
        s.tcp_obfuscation_port = r.u16().unwrap_or(0);
        s.udp_key = r.u32().unwrap_or(0);
    }
    Ok(s)
}

/// Whether a datagram is a ping answer, and to which challenge.
pub fn parse_ping_answer(datagram: &[u8]) -> Option<UdpStatus> {
    let p = Packet::parse_udp(datagram).ok()?;
    if p.protocol != Protocol::Edonkey as u8 || p.opcode != u8::from(Opcode::GlobServStatRes) {
        return None;
    }
    parse_status(&p.payload).ok()
}
