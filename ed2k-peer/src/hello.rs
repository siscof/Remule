// SPDX-License-Identifier: GPL-2.0-or-later
//! The handshake: `OP_HELLO` / `OP_HELLOANSWER` (`CUpDownClient::SendHelloTypePacket`,
//! `ProcessHelloTypePacket`) and the old `OP_EMULEINFO` / `OP_EMULEINFOANSWER`
//! (`SendMuleInfoPacket`, `ProcessMuleInfoPacket`).
//!
//! The hello carries the user hash, ID and port, then tags that advertise
//! what the client supports, then the server it is connected to. eMule and
//! aMule pack most capabilities into two bit fields, [`MiscOptions1`] and
//! [`MiscOptions2`]. A client that sends `CT_EMULE_VERSION` speaks the eMule
//! extended protocol; older eMules announce it with `OP_EMULEINFO` instead.

use std::net::{Ipv4Addr, SocketAddrV4};

use ed2k_codec::{Packet, Reader, Tag, TagError, TagName, TagValue, Writer};
use ed2k_types::ed2k::client_tcp::{Extended, Standard};
use ed2k_types::protocol::EMULE_PROTOCOL;
use ed2k_types::tags::{ClientTag, MuleInfoTag};
use ed2k_types::{Md4Hash, Protocol};

use crate::packets::BadPacket;

/// `EDONKEYVERSION`, sent as `CT_VERSION`.
pub const EDONKEY_VERSION: u32 = 0x3C;
/// `SO_AMULE`, the compatible-client byte of `CT_EMULE_VERSION`.
pub const SO_AMULE: u32 = 3;
/// `CURRENT_VERSION_SHORT`: the version byte of `OP_EMULEINFO`.
pub const CURRENT_VERSION_SHORT: u8 = 0x47;
/// The protocol byte of an `OP_EMULEINFO` that carries only the OS
/// (aMule and Hydranode).
pub const OS_INFO_PROTOCOL: u8 = 0xFF;
/// The four bytes some MLdonkeys append to their hello: "KDLM" read as a
/// little-endian `u32`.
const MLDONKEY_MARK: u32 = 0x4b44_4c4d;

/// `make_full_ed2k_version`
pub const fn ed2k_version(major: u32, minor: u32, update: u32) -> u32 {
    (major << 17) | (minor << 10) | (update << 7)
}

/// `CT_EMULE_MISCOPTIONS1`. From the top: 3 bits AICH version, 1 Unicode,
/// then 4 bits each of UDP version, data compression, secure ident, source
/// exchange, extended requests and comments, then single bits for
/// PeerCache, "no view shared files", multipacket and preview.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MiscOptions1 {
    pub aich_version: u8,
    pub unicode: bool,
    pub udp_version: u8,
    pub data_comp_version: u8,
    pub secure_ident: u8,
    pub source_exchange1_version: u8,
    pub extended_requests_version: u8,
    pub accept_comment_version: u8,
    pub peer_cache: bool,
    pub no_view_shared_files: bool,
    pub multi_packet: bool,
    pub preview: bool,
}

impl MiscOptions1 {
    /// What aMule sends: AICH 1, Unicode, UDP 4, compression 1, secure
    /// ident v1+v2, source exchange 3, extended requests 2, comments 1,
    /// multipacket.
    pub fn amule() -> Self {
        MiscOptions1 {
            aich_version: 1,
            unicode: true,
            udp_version: 4,
            data_comp_version: 1,
            secure_ident: 3,
            source_exchange1_version: 3,
            extended_requests_version: 2,
            accept_comment_version: 1,
            peer_cache: false,
            no_view_shared_files: false,
            multi_packet: true,
            preview: false,
        }
    }

    pub fn from_bits(f: u32) -> Self {
        let nibble = |n: u32| ((f >> (4 * n)) & 0x0f) as u8;
        let bit = |n: u32| (f >> n) & 1 == 1;
        MiscOptions1 {
            aich_version: ((f >> 29) & 0x07) as u8,
            unicode: bit(28),
            udp_version: nibble(6),
            data_comp_version: nibble(5),
            secure_ident: nibble(4),
            source_exchange1_version: nibble(3),
            extended_requests_version: nibble(2),
            accept_comment_version: nibble(1),
            peer_cache: bit(3),
            no_view_shared_files: bit(2),
            multi_packet: bit(1),
            preview: bit(0),
        }
    }

    pub fn to_bits(self) -> u32 {
        let nibble = |v: u8, n: u32| u32::from(v & 0x0f) << (4 * n);
        let bit = |v: bool, n: u32| u32::from(v) << n;
        (u32::from(self.aich_version & 0x07) << 29)
            | bit(self.unicode, 28)
            | nibble(self.udp_version, 6)
            | nibble(self.data_comp_version, 5)
            | nibble(self.secure_ident, 4)
            | nibble(self.source_exchange1_version, 3)
            | nibble(self.extended_requests_version, 2)
            | nibble(self.accept_comment_version, 1)
            | bit(self.peer_cache, 3)
            | bit(self.no_view_shared_files, 2)
            | bit(self.multi_packet, 1)
            | bit(self.preview, 0)
    }
}

/// `CT_EMULE_MISCOPTIONS2`. From bit 12 down: direct UDP callback, chat
/// captchas, source exchange 2, requires / requests / supports obfuscation,
/// a reserved mod bit, extended multipacket, large files, then 4 bits of Kad
/// version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MiscOptions2 {
    pub direct_udp_callback: bool,
    pub captcha: bool,
    pub source_exchange2: bool,
    pub requires_crypt: bool,
    pub requests_crypt: bool,
    pub supports_crypt: bool,
    pub mod_bit: bool,
    pub ext_multi_packet: bool,
    pub large_files: bool,
    pub kad_version: u8,
}

impl MiscOptions2 {
    /// What aMule sends, given its Kad version and obfuscation settings.
    pub fn amule(kad_version: u8, crypt: CryptSettings) -> Self {
        MiscOptions2 {
            direct_udp_callback: false,
            captcha: true,
            source_exchange2: true,
            requires_crypt: crypt.required,
            requests_crypt: crypt.requested,
            supports_crypt: crypt.supported,
            mod_bit: false,
            ext_multi_packet: true,
            large_files: true,
            kad_version,
        }
    }

    /// Decode, then as aMule does: "requests" only counts with "supports",
    /// "requires" only with "requests".
    pub fn from_bits(f: u32) -> Self {
        let bit = |n: u32| (f >> n) & 1 == 1;
        let supports_crypt = bit(7);
        let requests_crypt = bit(8) && supports_crypt;
        MiscOptions2 {
            direct_udp_callback: bit(12),
            captcha: bit(11),
            source_exchange2: bit(10),
            requires_crypt: bit(9) && requests_crypt,
            requests_crypt,
            supports_crypt,
            mod_bit: bit(6),
            ext_multi_packet: bit(5),
            large_files: bit(4),
            kad_version: (f & 0x0f) as u8,
        }
    }

    pub fn to_bits(self) -> u32 {
        let bit = |v: bool, n: u32| u32::from(v) << n;
        bit(self.direct_udp_callback, 12)
            | bit(self.captcha, 11)
            | bit(self.source_exchange2, 10)
            | bit(self.requires_crypt, 9)
            | bit(self.requests_crypt, 8)
            | bit(self.supports_crypt, 7)
            | bit(self.mod_bit, 6)
            | bit(self.ext_multi_packet, 5)
            | bit(self.large_files, 4)
            | u32::from(self.kad_version & 0x0f)
    }
}

/// Obfuscation preferences (`IsClientCryptLayer{Supported,Requested,Required}`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CryptSettings {
    pub supported: bool,
    pub requested: bool,
    pub required: bool,
}

/// What follows the server address in some hellos.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HelloTrailer {
    #[default]
    None,
    /// "KDLM": an MLdonkey.
    MlDonkey,
    /// Any other four bytes: an eDonkey Hybrid.
    Hybrid(u32),
}

/// An `OP_HELLO` or `OP_HELLOANSWER`.
///
/// Fields map to tags; an absent tag is `None` (or 0 for the UDP ports,
/// which aMule always sends). Tags this type does not model are kept in
/// [`Hello::other_tags`] and written back after the known ones.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Hello {
    pub user_hash: Md4Hash,
    /// A HighID is the IP, first octet in the low byte; below 16,777,216 a
    /// LowID; 0 when not connected to a server.
    pub id: u32,
    /// The TCP port. `CT_PORT`, when present, overrides it on parsing.
    pub port: u16,
    /// `CT_NAME`
    pub name: Option<String>,
    /// `CT_VERSION`
    pub version: Option<u32>,
    /// `CT_EMULE_UDPPORTS`: the client UDP port (low half)…
    pub udp_port: u16,
    /// …and the Kad port (high half).
    pub kad_port: u16,
    /// `CT_EMULE_BUDDYIP` and `CT_EMULE_BUDDYUDP`: a firewalled client's Kad
    /// buddy, IP in the same byte order as [`Hello::id`].
    pub buddy: Option<(u32, u16)>,
    /// `CT_EMULE_VERSION`: compatible client in the top byte, the version
    /// ([`ed2k_version`]) below. Its presence makes this an eMule client.
    pub emule_version: Option<u32>,
    pub misc1: Option<MiscOptions1>,
    pub misc2: Option<MiscOptions2>,
    /// `CT_EMULECOMPAT_OPTIONS`: bit 0, `OP_EMULEINFO` with OS info.
    pub compat_options: Option<u32>,
    /// `CT_MOD_MISCOPTIONS` (eMuleAI capabilities).
    pub mod_misc_options: Option<u32>,
    /// `ET_MOD_VERSION`: a string, or `ModID=<n>` for an integer.
    pub mod_version: Option<String>,
    /// The server the client is connected to, if any.
    pub server: Option<SocketAddrV4>,
    pub trailer: HelloTrailer,
    pub other_tags: Vec<Tag>,
}

/// `ET_MOD_VERSION` as aMule reads it.
fn mod_version(t: &Tag) -> String {
    match (&t.value, t.as_int()) {
        (TagValue::String(s), _) => s.clone(),
        (_, Some(n)) => format!("ModID={n}"),
        _ => "ModID=<Unknown>".to_owned(),
    }
}

fn id_of(t: &Tag) -> Option<u8> {
    match t.name {
        TagName::Id(id) => Some(id),
        _ => None,
    }
}

fn int32(id: u8, v: u32) -> Tag {
    Tag::new(id, TagValue::U32(v))
}

impl Hello {
    /// A hello as aMule fills it, before the caller sets the ports, server,
    /// buddy and capabilities that depend on its state.
    pub fn amule(user_hash: Md4Hash, id: u32, port: u16, name: impl Into<String>) -> Self {
        Hello {
            user_hash,
            id,
            port,
            name: Some(name.into()),
            version: Some(EDONKEY_VERSION),
            emule_version: Some((SO_AMULE << 24) | ed2k_version(3, 2, 0)),
            misc1: Some(MiscOptions1::amule()),
            misc2: Some(MiscOptions2::amule(0, CryptSettings::default())),
            compat_options: Some(1),
            ..Default::default()
        }
    }

    /// Whether the client speaks the eMule extended protocol.
    pub fn is_emule(&self) -> bool {
        self.emule_version.is_some()
    }

    /// The compatible-client byte of `CT_EMULE_VERSION`.
    pub fn compatible_client(&self) -> Option<u8> {
        self.emule_version.map(|v| (v >> 24) as u8)
    }

    /// The client's IPv4 address, if its ID is a HighID.
    pub fn high_id_ip(&self) -> Option<Ipv4Addr> {
        (self.id >= 0x0100_0000).then(|| Ipv4Addr::from(self.id.to_le_bytes()))
    }

    /// The tags, in the order aMule writes them.
    fn tags(&self) -> Vec<Tag> {
        let mut t = Vec::new();
        if let Some(name) = &self.name {
            t.push(Tag::string(ClientTag::Name as u8, name.clone()));
        }
        if let Some(v) = self.version {
            t.push(int32(ClientTag::Version as u8, v));
        }
        let ports = (u32::from(self.kad_port) << 16) | u32::from(self.udp_port);
        t.push(int32(ClientTag::EmuleUdpPorts as u8, ports));
        if let Some((ip, port)) = self.buddy {
            t.push(int32(ClientTag::EmuleBuddyIp as u8, ip));
            t.push(int32(ClientTag::EmuleBuddyUdp as u8, port.into()));
        }
        if let Some(v) = self.emule_version {
            t.push(int32(ClientTag::EmuleVersion as u8, v));
        }
        if let Some(m) = self.misc1 {
            t.push(int32(ClientTag::EmuleMiscOptions1 as u8, m.to_bits()));
        }
        if let Some(m) = self.misc2 {
            t.push(int32(ClientTag::EmuleMiscOptions2 as u8, m.to_bits()));
        }
        if let Some(v) = self.compat_options {
            t.push(int32(ClientTag::EmuleCompatOptions as u8, v));
        }
        if let Some(v) = self.mod_misc_options {
            t.push(int32(ClientTag::ModMiscOptions as u8, v));
        }
        if let Some(m) = &self.mod_version {
            t.push(Tag::string(MuleInfoTag::ModVersion as u8, m.clone()));
        }
        t.extend(self.other_tags.iter().cloned());
        t
    }

    /// The payload shared by both packets (`SendHelloTypePacket`).
    fn write_body(&self, w: &mut Writer) -> Result<(), TagError> {
        let tags = self.tags();
        w.hash(self.user_hash).u32(self.id).u16(self.port);
        w.u32(tags.len() as u32);
        for t in &tags {
            // WriteTagToFile: the eD2k "old" form, integers at full width.
            t.write_kad(w)?;
        }
        let (ip, port) = self
            .server
            .map(|s| (u32::from_le_bytes(s.ip().octets()), s.port()))
            .unwrap_or_default();
        w.u32(ip).u16(port);
        match self.trailer {
            HelloTrailer::None => {}
            HelloTrailer::MlDonkey => {
                w.u32(MLDONKEY_MARK);
            }
            HelloTrailer::Hybrid(v) => {
                w.u32(v);
            }
        }
        Ok(())
    }

    /// `OP_HELLO`: the body after a hash-size byte of 16.
    pub fn to_hello(&self) -> Result<Packet, TagError> {
        let mut w = Writer::new();
        w.u8(16);
        self.write_body(&mut w)?;
        Ok(Packet::new(
            Protocol::Edonkey,
            Standard::Hello,
            w.into_bytes(),
        ))
    }

    /// `OP_HELLOANSWER`: the same body, without the hash-size byte.
    pub fn to_hello_answer(&self) -> Result<Packet, TagError> {
        let mut w = Writer::new();
        self.write_body(&mut w)?;
        Ok(Packet::new(
            Protocol::Edonkey,
            Standard::HelloAnswer,
            w.into_bytes(),
        ))
    }

    /// Parse an `OP_HELLO` payload (`ProcessHelloPacket`).
    pub fn parse_hello(payload: &[u8]) -> Result<Hello, BadPacket> {
        let mut r = Reader::new(payload);
        let size = r.u8().map_err(BadPacket::io("hello"))?;
        if size != 16 {
            return Err(BadPacket::new(
                "hello",
                format!("user hash size {size}, not 16"),
            ));
        }
        Self::read_body(&mut r)
    }

    /// Parse an `OP_HELLOANSWER` payload (`ProcessHelloAnswer`).
    pub fn parse_hello_answer(payload: &[u8]) -> Result<Hello, BadPacket> {
        Self::read_body(&mut Reader::new(payload))
    }

    /// `ProcessHelloTypePacket`, without the side effects on the client.
    fn read_body(r: &mut Reader<'_>) -> Result<Hello, BadPacket> {
        let io = BadPacket::io("hello");
        let mut h = Hello {
            user_hash: r.hash().map_err(&io)?,
            id: r.u32().map_err(&io)?,
            port: r.u16().map_err(&io)?,
            ..Default::default()
        };
        let count = r.u32().map_err(&io)?;
        let mut buddy_ip = None;
        let mut buddy_port = None;
        for _ in 0..count {
            let t = Tag::read_ed2k(r, true, true).map_err(BadPacket::tag("hello"))?;
            let int = t.as_int().map(|v| v as u32);
            match (id_of(&t).and_then(|id| ClientTag::try_from(id).ok()), int) {
                (Some(ClientTag::Name), _) if t.as_str().is_some() => {
                    h.name = t.as_str().map(str::to_owned);
                }
                (Some(ClientTag::Version), Some(v)) => h.version = Some(v),
                (Some(ClientTag::Port), Some(v)) => h.port = v as u16,
                (Some(ClientTag::EmuleUdpPorts), Some(v)) => {
                    h.kad_port = (v >> 16) as u16;
                    h.udp_port = v as u16;
                }
                (Some(ClientTag::EmuleBuddyIp), Some(v)) => buddy_ip = Some(v),
                (Some(ClientTag::EmuleBuddyUdp), Some(v)) => buddy_port = Some(v as u16),
                (Some(ClientTag::EmuleMiscOptions1), Some(v)) => {
                    h.misc1 = Some(MiscOptions1::from_bits(v));
                }
                (Some(ClientTag::EmuleMiscOptions2), Some(v)) => {
                    h.misc2 = Some(MiscOptions2::from_bits(v));
                }
                (Some(ClientTag::EmuleCompatOptions), Some(v)) => h.compat_options = Some(v),
                (Some(ClientTag::EmuleVersion), Some(v)) => h.emule_version = Some(v),
                (Some(ClientTag::ModMiscOptions), Some(v)) => h.mod_misc_options = Some(v),
                _ if id_of(&t) == Some(MuleInfoTag::ModVersion as u8) => {
                    h.mod_version = Some(mod_version(&t));
                }
                _ => h.other_tags.push(t),
            }
        }
        // aMule keeps the two buddy fields apart; together they make a buddy.
        h.buddy = buddy_ip.map(|ip| (ip, buddy_port.unwrap_or(0)));
        let ip = r.u32().map_err(&io)?;
        let port = r.u16().map_err(&io)?;
        if ip != 0 || port != 0 {
            h.server = Some(SocketAddrV4::new(Ipv4Addr::from(ip.to_le_bytes()), port));
        }
        // Hybrids add four bytes, MLdonkeys "KDLM"; anything else is ignored.
        if r.remaining() == 4 {
            h.trailer = match r.u32().map_err(&io)? {
                MLDONKEY_MARK => HelloTrailer::MlDonkey,
                v => HelloTrailer::Hybrid(v),
            };
        }
        Ok(h)
    }
}

/// The fields of an old `OP_EMULEINFO` (`enum MuleInfo_tags`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmuleInfo {
    /// The eMule version byte (`m_byEmuleVersion`).
    pub version: u8,
    pub compression: u8,
    pub udp_port: u16,
    pub udp_version: u8,
    pub source_exchange: u8,
    pub comments: u8,
    pub extended_requests: u8,
    pub compatible_client: u8,
    /// `ET_FEATURES`: bits 0-1 secure ident, bit 7 preview.
    pub features: u32,
    pub mod_version: Option<String>,
    pub other_tags: Vec<Tag>,
}

impl EmuleInfo {
    /// What aMule sends (`SendMuleInfoPacket` without OS info).
    pub fn amule(udp_port: u16, secure_ident: u32, mod_version: Option<String>) -> Self {
        EmuleInfo {
            version: CURRENT_VERSION_SHORT,
            compression: 1,
            udp_port,
            udp_version: 4,
            source_exchange: 3,
            comments: 1,
            extended_requests: 2,
            compatible_client: SO_AMULE as u8,
            features: secure_ident,
            mod_version,
            other_tags: Vec::new(),
        }
    }
}

/// `OP_EMULEINFO` / `OP_EMULEINFOANSWER`.
#[derive(Debug, Clone, PartialEq)]
pub enum MuleInfo {
    /// The old eMule capability exchange.
    Info(EmuleInfo),
    /// aMule's recycled form (protocol byte 0xFF) with only `ET_OS_INFO`.
    OsInfo { version: u8, os: Option<String> },
}

impl MuleInfo {
    pub fn to_packet(&self, answer: bool) -> Result<Packet, TagError> {
        let mut w = Writer::new();
        let int = |id: MuleInfoTag, v: u32| int32(id as u8, v);
        match self {
            MuleInfo::OsInfo { version, os } => {
                w.u8(*version).u8(OS_INFO_PROTOCOL);
                let tags: Vec<Tag> = os
                    .iter()
                    .map(|s| Tag::string(MuleInfoTag::OsInfo as u8, s.clone()))
                    .collect();
                w.u32(tags.len() as u32);
                for t in &tags {
                    t.write_kad(&mut w)?;
                }
            }
            MuleInfo::Info(i) => {
                w.u8(i.version).u8(EMULE_PROTOCOL);
                let mut tags = vec![
                    int(MuleInfoTag::Compression, i.compression.into()),
                    int(MuleInfoTag::UdpVer, i.udp_version.into()),
                    int(MuleInfoTag::UdpPort, i.udp_port.into()),
                    int(MuleInfoTag::SourceExchange, i.source_exchange.into()),
                    int(MuleInfoTag::Comments, i.comments.into()),
                    int(MuleInfoTag::ExtendedRequest, i.extended_requests.into()),
                    int(MuleInfoTag::Features, i.features),
                    int(MuleInfoTag::CompatibleClient, i.compatible_client.into()),
                ];
                if let Some(m) = &i.mod_version {
                    tags.push(Tag::string(MuleInfoTag::ModVersion as u8, m.clone()));
                }
                tags.extend(i.other_tags.iter().cloned());
                w.u32(tags.len() as u32);
                for t in &tags {
                    t.write_kad(&mut w)?;
                }
            }
        }
        let op = if answer {
            Extended::EmuleInfoAnswer
        } else {
            Extended::EmuleInfo
        };
        Ok(Packet::new(Protocol::Emule, op, w.into_bytes()))
    }

    /// `ProcessMuleInfoPacket`, without the version-implied capabilities
    /// aMule adds afterwards.
    pub fn parse(payload: &[u8]) -> Result<MuleInfo, BadPacket> {
        let io = BadPacket::io("eMule info");
        let tag = BadPacket::tag("eMule info");
        let mut r = Reader::new(payload);
        let version = r.u8().map_err(&io)?;
        let protocol = r.u8().map_err(&io)?;
        let count = r.u32().map_err(&io)?;
        if protocol == OS_INFO_PROTOCOL {
            let mut os = None;
            for _ in 0..count {
                let t = Tag::read_ed2k(&mut r, true, true).map_err(&tag)?;
                if id_of(&t) == Some(MuleInfoTag::OsInfo as u8) {
                    os = t.as_str().map(str::to_owned);
                }
            }
            return Ok(MuleInfo::OsInfo { version, os });
        }
        if protocol != EMULE_PROTOCOL {
            return Err(BadPacket::new(
                "eMule info",
                format!("protocol {protocol:#x}, not eMule"),
            ));
        }
        // aMule maps the version byte 0x2B to 0x22.
        let mut i = EmuleInfo {
            version: if version == 0x2B { 0x22 } else { version },
            ..Default::default()
        };
        for _ in 0..count {
            let t = Tag::read_ed2k(&mut r, false, true).map_err(&tag)?;
            let v = t.as_int().unwrap_or_default() as u32;
            match id_of(&t).and_then(|id| MuleInfoTag::try_from(id).ok()) {
                Some(MuleInfoTag::Compression) => i.compression = v as u8,
                Some(MuleInfoTag::UdpPort) => i.udp_port = v as u16,
                Some(MuleInfoTag::UdpVer) => i.udp_version = v as u8,
                Some(MuleInfoTag::SourceExchange) => i.source_exchange = v as u8,
                Some(MuleInfoTag::Comments) => i.comments = v as u8,
                Some(MuleInfoTag::ExtendedRequest) => i.extended_requests = v as u8,
                Some(MuleInfoTag::CompatibleClient) => i.compatible_client = v as u8,
                Some(MuleInfoTag::Features) => i.features = v,
                Some(MuleInfoTag::ModVersion) => i.mod_version = Some(mod_version(&t)),
                _ => i.other_tags.push(t),
            }
        }
        Ok(MuleInfo::Info(i))
    }
}
