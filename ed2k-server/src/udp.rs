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

// ------------------------------------------------- obfuscated ping (port + 12)

/// Where a server takes the obfuscated ping, from its TCP port.
pub const CRYPT_PING_PORT_OFFSET: u16 = 12;

/// The obfuscated ping (`CServerList::ServerStats`): a raw datagram of the
/// challenge (never 0) and up to 15 random bytes, to the server's port + 12.
/// Its answer comes obfuscated with the challenge as the key
/// ([`parse_crypt_ping_answer`]).
pub fn crypt_ping<R: rand::RngCore + ?Sized>(challenge: u32, rng: &mut R) -> Vec<u8> {
    let len = 4 + (rng.gen::<u8>() % 16) as usize;
    let mut b = challenge.to_le_bytes().to_vec();
    b.extend((4..len).map(|_| rng.gen::<u8>()));
    b
}

/// The answer to an obfuscated ping: decrypted with the challenge, it must
/// be a status answer repeating it.
pub fn parse_crypt_ping_answer(datagram: &[u8], challenge: u32) -> Option<UdpStatus> {
    let plain = ed2k_crypto::udp::decrypt_server(datagram, challenge)?;
    parse_ping_answer(&plain).filter(|s| s.challenge == challenge)
}

/// Obfuscate a datagram for a server that supports it
/// (`SRV_UDPFLG_UDPOBFUSCATION`, with the key its status gave): sent to its
/// UDP obfuscation port.
pub fn obfuscate<R: rand::RngCore + ?Sized>(
    datagram: &[u8],
    server_key: u32,
    rng: &mut R,
) -> Vec<u8> {
    ed2k_crypto::udp::encrypt_server(datagram, server_key, rng)
}

/// A datagram from a server: decrypted with its key when it is obfuscated,
/// as it is.
pub fn deobfuscate(datagram: &[u8], server_key: u32) -> Vec<u8> {
    if server_key != 0 {
        if let Some(p) = ed2k_crypto::udp::decrypt_server(datagram, server_key) {
            return p;
        }
    }
    datagram.to_vec()
}

// ---------------------------------------------------------- global search

/// The global search request for one server (`OnGlobalSearchTimer`), made
/// from a search request's payload ([`crate::search::encode_search`]):
/// `OP_GLOBSEARCHREQ3` (with the large files capability) to a server that
/// takes large files and extended requests, `OP_GLOBSEARCHREQ2` to one with
/// extended requests, else `OP_GLOBSEARCHREQ`. `None` when the search holds
/// a 64-bit size and the server cannot read it.
pub fn global_search(payload: &[u8], uses_64bit: bool, udp_flags: u32) -> Option<Packet> {
    use ed2k_types::ed2k::server_udp::flags;
    let large = udp_flags & flags::LARGEFILES != 0;
    let ext = udp_flags & flags::EXT_GETFILES != 0;
    if large && ext {
        // <tag count 4> CT_SERVER_UDPSEARCH_FLAGS = SRVCAP_UDP_NEWTAGS_LARGEFILES
        // as a new-style uint8 tag, then the search.
        let mut p = 1u32.to_le_bytes().to_vec();
        p.extend_from_slice(&[0x89, 0x0E, 0x01]);
        p.extend_from_slice(payload);
        return Some(Packet::new(Protocol::Edonkey, Opcode::GlobSearchReq3, p));
    }
    if uses_64bit && !large {
        return None;
    }
    let op = if ext {
        Opcode::GlobSearchReq2
    } else {
        Opcode::GlobSearchReq
    };
    Some(Packet::new(Protocol::Edonkey, op, payload.to_vec()))
}

/// `OP_GLOBSEARCHRES` (decrypted): one result, then maybe another
/// `OP_GLOBSEARCHRES` header and result, and so on (servers pack several in
/// one datagram). `None` for another kind of datagram.
pub fn parse_global_search_results(datagram: &[u8]) -> Option<Vec<crate::search::SearchResult>> {
    let head = [Protocol::Edonkey as u8, u8::from(Opcode::GlobSearchRes)];
    if datagram.len() < 2 || datagram[..2] != head {
        return None;
    }
    let mut r = Reader::new(&datagram[2..]);
    let mut out = Vec::new();
    while let Ok(res) = crate::search::SearchResult::read(&mut r) {
        out.push(res);
        // Another packed answer?
        let rest = r.rest();
        if rest.len() > 2 && rest[..2] == head {
            r = Reader::new(&rest[2..]);
        } else {
            break;
        }
    }
    Some(out)
}

// ------------------------------------------------------ global sources

/// `MAX_FILES_PER_UDP_PACKET`: at most this many files in one source
/// request (to a server with `SRV_UDPFLG_EXT_GETSOURCES`).
pub const MAX_FILES_PER_UDP_PACKET: usize = 31;

/// The source request for some downloads (hash and size) to one server
/// (`WriteGlobalSourceRequest`, `SendGlobGetSourcesUDPPacket`):
/// `OP_GLOBGETSOURCES2` with each size (a large file's as 0 then 64 bits)
/// to a server with `SRV_UDPFLG_EXT_GETSOURCES2`, else `OP_GLOBGETSOURCES`
/// with the hashes only.
pub fn global_get_sources(files: &[(ed2k_types::Md4Hash, u64)], udp_flags: u32) -> Packet {
    use ed2k_types::ed2k::{server_udp::flags, OLD_MAX_FILE_SIZE};
    let with_size = udp_flags & flags::EXT_GETSOURCES2 != 0;
    let mut w = ed2k_codec::Writer::new();
    for &(hash, size) in files {
        w.hash(hash);
        if with_size {
            if size > OLD_MAX_FILE_SIZE {
                w.u32(0).u64(size);
            } else {
                w.u32(size as u32);
            }
        }
    }
    let op = if with_size {
        Opcode::GlobGetSources2
    } else {
        Opcode::GlobGetSources
    };
    Packet::new(Protocol::Edonkey, op, w.into_bytes())
}

/// `OP_GLOBFOUNDSOURCES` (decrypted): a file's hash and its sources
/// (`<count 1>(<ID 4><port 2>)*`), maybe followed by more such answers
/// packed in the datagram. What could be read before anything broken;
/// `None` for another kind of datagram.
pub fn parse_global_found_sources(
    datagram: &[u8],
) -> Option<Vec<(ed2k_types::Md4Hash, Vec<crate::packets::Source>)>> {
    let head = [Protocol::Edonkey as u8, u8::from(Opcode::GlobFoundSources)];
    if datagram.len() < 2 || datagram[..2] != head {
        return None;
    }
    let mut r = Reader::new(&datagram[2..]);
    let mut out = Vec::new();
    loop {
        let read = (|| -> Result<_, ed2k_codec::io::Error> {
            let hash = r.hash()?;
            let count = r.u8()?;
            let mut sources = Vec::with_capacity(count.into());
            for _ in 0..count {
                sources.push(crate::packets::Source {
                    id: r.u32()?,
                    port: r.u16()?,
                    crypt_options: None,
                    user_hash: None,
                });
            }
            Ok((hash, sources))
        })();
        let Ok(found) = read else { break };
        out.push(found);
        // Another packed answer?
        let rest = r.rest();
        if rest.len() > 2 && rest[..2] == head {
            r = Reader::new(&rest[2..]);
        } else {
            break;
        }
    }
    Some(out)
}

// --------------------------------------------------- server descriptions

/// `INV_SERV_DESC_LEN`: the low half of a description challenge, an
/// impossible string length, so an old-style answer cannot be mistaken
/// for a new one.
pub const INV_SERV_DESC_LEN: u32 = 0xF0FF;

/// A description challenge, as aMule picks it.
pub fn desc_challenge<R: rand::RngCore + ?Sized>(rng: &mut R) -> u32 {
    ((rng.gen::<u16>() as u32) << 16) + INV_SERV_DESC_LEN
}

/// `OP_SERVER_DESC_REQ` with a challenge (eserver 16.45 and later answer
/// with tags).
pub fn desc_request(challenge: u32) -> Packet {
    Packet::new(
        Protocol::Edonkey,
        Opcode::ServerDescReq,
        challenge.to_le_bytes().to_vec(),
    )
}

/// What `OP_SERVER_DESC_RES` says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerDescription {
    pub name: Option<String>,
    pub description: Option<String>,
    pub dyn_ip: Option<String>,
    pub version: Option<String>,
}

/// `OP_SERVER_DESC_RES` (decrypted), old (two strings, read as aMule and
/// eMule read them: the description, then the name) or new
/// (`<challenge 4><tags>`, the challenge ours).
pub fn parse_desc_answer(datagram: &[u8], challenge: u32) -> Option<ServerDescription> {
    use ed2k_codec::Tag;
    use ed2k_types::tags::ServerTag;
    let p = Packet::parse_udp(datagram).ok()?;
    if p.protocol != Protocol::Edonkey as u8 || p.opcode != u8::from(Opcode::ServerDescRes) {
        return None;
    }
    let mut r = Reader::new(&p.payload);
    let len = u16::from_le_bytes([*p.payload.first()?, *p.payload.get(1)?]);
    let mut d = ServerDescription::default();
    if p.payload.len() >= 8 && u32::from(len) == INV_SERV_DESC_LEN {
        if r.u32().ok()? != challenge {
            return None;
        }
        let n = r.u32().ok()?;
        for _ in 0..n {
            // Strings as UTF-8, whatever the server says (aMule #831).
            let t = Tag::read_ed2k(&mut r, true, false).ok()?;
            let id = match t.name {
                ed2k_codec::TagName::Id(id) => ServerTag::try_from(id).ok(),
                _ => None,
            };
            let text = t.as_str().map(str::to_owned);
            match id {
                Some(ServerTag::ServerName) => d.name = text,
                Some(ServerTag::Description) => d.description = text,
                Some(ServerTag::DynIp) => d.dyn_ip = text,
                Some(ServerTag::Version) => {
                    d.version =
                        text.or_else(|| t.as_int().map(|v| format!("{}.{}", v >> 16, v & 0xFFFF)))
                }
                _ => {}
            }
        }
    } else {
        let mut s = || -> Option<String> {
            let n = r.u16().ok()? as usize;
            Some(String::from_utf8_lossy(r.bytes(n).ok()?).into_owned())
        };
        d.description = s();
        d.name = s();
    }
    Some(d)
}
