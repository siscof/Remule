// SPDX-License-Identifier: GPL-2.0-or-later
//! Client-to-server TCP packets (`CServerConnect`, `CServerSocket::ProcessPacket`).

use std::net::{Ipv4Addr, SocketAddrV4};

use ed2k_codec::packet::SERVER_UNPACK_LIMIT;
use ed2k_codec::{Packet, Reader, Tag, TagValue, Writer};
use ed2k_types::ed2k::server_tcp::Opcode;
use ed2k_types::tags::{server_caps, ClientTag, ServerTag};
use ed2k_types::{Md4Hash, Protocol};

use crate::search::{parse_search_answer, SearchResult};

/// `EDONKEYVERSION`: sent at login, meaningless today.
pub const EDONKEY_VERSION: u32 = 0x3C;
/// `SO_AMULE`
pub const SO_AMULE: u32 = 3;

/// `make_full_ed2k_version`
pub const fn ed2k_version(major: u32, minor: u32, update: u32) -> u32 {
    (major << 17) | (minor << 10) | (update << 7)
}

/// Whether an ID is a LowID (`IsLowID`): below 16,777,216.
pub const fn is_low_id(id: u32) -> bool {
    id < 0x0100_0000
}

/// A HighID is the client's IPv4 address, first octet in the low byte.
pub fn id_to_ip(id: u32) -> Ipv4Addr {
    Ipv4Addr::from(id.to_le_bytes())
}

/// `thePrefs::CreateUserHash`: random, with eMule's two marker bytes.
pub fn new_user_hash<R: rand::RngCore + ?Sized>(rng: &mut R) -> Md4Hash {
    let mut h = [0u8; 16];
    rng.fill_bytes(&mut h);
    h[5] = 14;
    h[14] = 111;
    Md4Hash(h)
}

/// What we say about ourselves at login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginInfo {
    pub user_hash: Md4Hash,
    /// Our TCP port, which the server will test.
    pub port: u16,
    pub nick: String,
    /// Obfuscation: supported, requested, required (`SRVCAP_*CRYPT`).
    pub crypt_supported: bool,
    pub crypt_requested: bool,
    pub crypt_required: bool,
    /// Our version, as `CT_EMULE_VERSION` (`ed2k_version`).
    pub version: u32,
}

impl LoginInfo {
    pub fn new(user_hash: Md4Hash, port: u16, nick: impl Into<String>) -> Self {
        LoginInfo {
            user_hash,
            port,
            nick: nick.into(),
            crypt_supported: true,
            crypt_requested: false,
            crypt_required: false,
            version: ed2k_version(3, 2, 0),
        }
    }

    /// The flags of `CT_SERVER_FLAGS`.
    pub fn server_flags(&self) -> u32 {
        let mut f = server_caps::ZLIB
            | server_caps::AUXPORT
            | server_caps::NEWTAGS
            | server_caps::UNICODE
            | server_caps::LARGEFILES;
        if self.crypt_supported {
            f |= server_caps::SUPPORTCRYPT;
        }
        if self.crypt_requested {
            f |= server_caps::REQUESTCRYPT;
        }
        if self.crypt_required {
            f |= server_caps::REQUIRECRYPT;
        }
        f
    }
}

fn edonkey(op: Opcode, payload: Vec<u8>) -> Packet {
    Packet::new(Protocol::Edonkey, op, payload)
}

/// `OP_LOGINREQUEST`: `<hash 16><ID 4 (0)><port 2><tag count 4>` and the
/// name, version, flags and eMule-version tags.
pub fn login(info: &LoginInfo) -> Result<Packet, ed2k_codec::TagError> {
    let mut w = Writer::new();
    w.hash(info.user_hash).u32(0).u16(info.port).u32(4);
    let int = |id: ClientTag, v: u32| Tag::new(id as u8, TagValue::U32(v));
    let tags = [
        Tag::string(ClientTag::Name as u8, info.nick.clone()),
        int(ClientTag::Version, EDONKEY_VERSION),
        int(ClientTag::ServerFlags, info.server_flags()),
        int(ClientTag::EmuleVersion, (SO_AMULE << 24) | info.version),
    ];
    for t in &tags {
        // WriteTagToFile: CTagInt32 stays 32 bits, the name is <1 u16><id>.
        t.write_kad(&mut w)?;
    }
    Ok(edonkey(Opcode::LoginRequest, w.into_bytes()))
}

/// `OP_GETSERVERLIST`
pub fn get_server_list() -> Packet {
    edonkey(Opcode::GetServerList, Vec::new())
}

/// `OP_SEARCHREQUEST` with a payload from [`crate::search::encode_search`].
pub fn search_request(payload: Vec<u8>) -> Packet {
    edonkey(Opcode::SearchRequest, payload)
}

/// `OP_QUERY_MORE_RESULT`
pub fn query_more_results() -> Packet {
    edonkey(Opcode::QueryMoreResult, Vec::new())
}

/// `OP_GETSOURCES` / `OP_GETSOURCES_OBFU`: `<hash 16><size 4>`, or for a
/// file over 4 GiB `<hash 16><0 4><size 8>`.
pub fn get_sources(hash: Md4Hash, size: u64, obfuscated: bool) -> Packet {
    let mut w = Writer::new();
    w.hash(hash);
    if size > u32::MAX as u64 {
        w.u32(0).u64(size);
    } else {
        w.u32(size as u32);
    }
    let op = if obfuscated {
        Opcode::GetSourcesObfu
    } else {
        Opcode::GetSources
    };
    edonkey(op, w.into_bytes())
}

/// `OP_CALLBACKREQUEST`: ask a LowID client (by its ID) to connect to us.
pub fn callback_request(id: u32) -> Packet {
    edonkey(Opcode::CallbackRequest, id.to_le_bytes().to_vec())
}

/// `OP_OFFERFILES` with no files.
pub fn offer_no_files() -> Packet {
    edonkey(Opcode::OfferFiles, 0u32.to_le_bytes().to_vec())
}

/// A source from `OP_FOUNDSOURCES(_OBFU)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// The client's ID: a HighID is its IP ([`id_to_ip`]).
    pub id: u32,
    pub port: u16,
    /// `_OBFU` only: bit 0 supported, 1 requested, 2 required, 7 a user hash follows.
    pub crypt_options: Option<u8>,
    pub user_hash: Option<Md4Hash>,
}

/// `OP_IDCHANGE`, whichever fields the server sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdChange {
    pub id: u32,
    /// `SRV_TCPFLG_*`
    pub tcp_flags: u32,
    pub aux_port: Option<u32>,
    /// Our IP as the server sees it (ignored when LowID-shaped).
    pub reported_ip: Option<u32>,
    pub obfuscation_port: Option<u32>,
}

/// Everything a server can send, parsed.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerPacket {
    /// `OP_SERVERMESSAGE`, split into lines.
    Message(Vec<String>),
    IdChange(IdChange),
    SearchResults {
        results: Vec<SearchResult>,
        more: Option<bool>,
    },
    FoundSources {
        hash: Md4Hash,
        sources: Vec<Source>,
    },
    Status {
        users: u32,
        files: u32,
    },
    Ident {
        hash: Md4Hash,
        ip: u32,
        port: u16,
        name: Option<String>,
        description: Option<String>,
        tags: Vec<Tag>,
    },
    ServerList(Vec<SocketAddrV4>),
    /// `OP_CALLBACKREQUESTED`: a LowID wants us to connect to it.
    CallbackRequested {
        ip: Ipv4Addr,
        port: u16,
        crypt_options: Option<u8>,
        user_hash: Option<Md4Hash>,
    },
    CallbackFail,
    Reject,
    /// Anything else (logged and ignored by aMule).
    Other(Packet),
}

/// A packet the server sent that is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("bad {what} from server: {why}")]
pub struct BadPacket {
    pub what: &'static str,
    pub why: String,
}

fn bad(what: &'static str) -> impl Fn(ed2k_codec::Error) -> BadPacket {
    move |e| BadPacket {
        what,
        why: e.to_string(),
    }
}

/// Parse a packet from a server, unpacking it first if it is packed.
pub fn parse(mut packet: Packet) -> Result<ServerPacket, BadPacket> {
    // Unpacking makes it an eMule packet, but CServerSocket handles it as
    // a server packet all the same.
    let packed = packet.protocol == Protocol::Packed as u8;
    if packed {
        packet.unpack(SERVER_UNPACK_LIMIT).map_err(|e| BadPacket {
            what: "packed packet",
            why: e.to_string(),
        })?;
    }
    if !packed && packet.protocol != Protocol::Edonkey as u8 {
        return Ok(ServerPacket::Other(packet));
    }
    let Ok(op) = Opcode::try_from(packet.opcode) else {
        return Ok(ServerPacket::Other(packet));
    };
    let p = &packet.payload;
    let mut r = Reader::new(p);
    Ok(match op {
        Opcode::ServerMessage => {
            if p.len() < 3 {
                return Err(BadPacket {
                    what: "server message",
                    why: "too short".into(),
                });
            }
            // aMule ignores the length field and takes the rest, up to a NUL.
            let text = &p[2..];
            let text = text.split(|&b| b == 0).next().unwrap_or_default();
            let lines = String::from_utf8_lossy(text)
                .split(['\r', '\n'])
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect();
            ServerPacket::Message(lines)
        }
        Opcode::IdChange => {
            let e = bad("ID change");
            let mut c = IdChange {
                id: r.u32().map_err(&e)?,
                ..Default::default()
            };
            if p.len() >= 8 {
                c.tcp_flags = r.u32().map_err(&e)?;
            }
            if p.len() >= 12 {
                c.aux_port = Some(r.u32().map_err(&e)?);
            }
            if p.len() >= 20 {
                let ip = r.u32().map_err(&e)?;
                c.reported_ip = (!is_low_id(ip)).then_some(ip);
                c.obfuscation_port = Some(r.u32().map_err(&e)?);
            }
            ServerPacket::IdChange(c)
        }
        Opcode::SearchResult => {
            let (results, more) = parse_search_answer(p).map_err(|e| BadPacket {
                what: "search result",
                why: e.to_string(),
            })?;
            ServerPacket::SearchResults { results, more }
        }
        Opcode::FoundSources | Opcode::FoundSourcesObfu => {
            let e = bad("found sources");
            let obfu = op == Opcode::FoundSourcesObfu;
            let hash = r.hash().map_err(&e)?;
            let count = r.u8().map_err(&e)?;
            let mut sources = Vec::with_capacity(count.into());
            for _ in 0..count {
                let id = r.u32().map_err(&e)?;
                let port = r.u16().map_err(&e)?;
                let (mut crypt_options, mut user_hash) = (None, None);
                if obfu {
                    let c = r.u8().map_err(&e)?;
                    crypt_options = Some(c);
                    if c & 0x80 != 0 {
                        user_hash = Some(r.hash().map_err(&e)?);
                    }
                }
                sources.push(Source {
                    id,
                    port,
                    crypt_options,
                    user_hash,
                });
            }
            ServerPacket::FoundSources { hash, sources }
        }
        Opcode::ServerStatus => {
            let e = bad("server status");
            ServerPacket::Status {
                users: r.u32().map_err(&e)?,
                files: r.u32().map_err(&e)?,
            }
        }
        Opcode::ServerIdent => {
            let e = bad("server ident");
            let hash = r.hash().map_err(&e)?;
            let ip = r.u32().map_err(&e)?;
            let port = r.u16().map_err(&e)?;
            let count = r.u32().map_err(&e)?;
            let (mut name, mut description, mut tags) = (None, None, Vec::new());
            for _ in 0..count {
                let t = Tag::read_ed2k(&mut r, true, false).map_err(|x| BadPacket {
                    what: "server ident",
                    why: x.to_string(),
                })?;
                if t.name.is_id(ServerTag::ServerName as u8) {
                    name = t.as_str().map(str::to_owned);
                } else if t.name.is_id(ServerTag::Description as u8) {
                    description = t.as_str().map(str::to_owned);
                }
                tags.push(t);
            }
            ServerPacket::Ident {
                hash,
                ip,
                port,
                name,
                description,
                tags,
            }
        }
        Opcode::ServerList => {
            let e = bad("server list");
            let mut count = r.u8().map_err(&e)? as usize;
            if count * 6 + 1 > p.len() {
                count = 0;
            }
            let mut list = Vec::with_capacity(count);
            for _ in 0..count {
                let ip = r.array::<4>().map_err(&e)?;
                let port = r.u16().map_err(&e)?;
                list.push(SocketAddrV4::new(Ipv4Addr::from(ip), port));
            }
            ServerPacket::ServerList(list)
        }
        Opcode::CallbackRequested => {
            let e = bad("callback request");
            let ip = Ipv4Addr::from(r.array::<4>().map_err(&e)?);
            let port = r.u16().map_err(&e)?;
            let (mut crypt_options, mut user_hash) = (None, None);
            if r.remaining() >= 1 {
                let c = r.u8().map_err(&e)?;
                crypt_options = Some(c);
                if r.remaining() >= 16 {
                    user_hash = Some(r.hash().map_err(&e)?);
                }
            }
            ServerPacket::CallbackRequested {
                ip,
                port,
                crypt_options,
                user_hash,
            }
        }
        Opcode::CallbackFail => ServerPacket::CallbackFail,
        Opcode::Reject => ServerPacket::Reject,
        _ => ServerPacket::Other(packet),
    })
}
