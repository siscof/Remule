// SPDX-License-Identifier: GPL-2.0-or-later
//! `server.met`: the list of known eD2k servers.
//!
//! Port of `ServerMet.{h,cpp}` (`ReadServerMetRecords`),
//! `CServerList::LoadServerMet` / `SaveServerMet` and
//! `CServer::AddTagFromFile`.
//!
//! Layout: a version byte (`0xE0`, or `MET_HEADER` `0x0E`), a `u32` server
//! count, then per server its IPv4 address (4 bytes, network order), its
//! TCP port (`u16` LE), a `u32` tag count and that many eD2k tags.
//!
//! [`ServerMet`] keeps the records exactly as stored, integer widths
//! included, so a file written by aMule is written back byte for byte.
//! [`ServerInfo`] is the typed view aMule builds from the tags.
//!
//! Not here: unpacking a server list that comes as a zip/gzip archive
//! (`UnpackArchive`), which belongs with the HTTP download (phase 10).

use std::fmt;
use std::net::Ipv4Addr;

use ed2k_codec::{Reader, Tag, TagError, TagName, TagValue, Writer};
use ed2k_types::tags::ServerTag;

/// The version byte aMule writes.
pub const VERSION: u8 = 0xE0;
/// The other version byte aMule accepts (`MET_HEADER`).
pub const VERSION_MET_HEADER: u8 = 0x0E;

/// One server as stored (`ServerMetRecord`).
#[derive(Clone, Debug, PartialEq)]
pub struct ServerRecord {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub tags: Vec<Tag>,
}

/// A whole `server.met`.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerMet {
    pub version: u8,
    pub servers: Vec<ServerRecord>,
    /// The file was read with the legacy tag counts: older aMule versions
    /// declared one tag too many for a server without a version tag.
    pub legacy_counts: bool,
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    /// The version byte is neither `0xE0` nor `0x0E`.
    BadVersion(u8),
    /// A record or tag could not be read.
    Tag(TagError),
    /// Bytes after the last declared server.
    TrailingData,
}

/// A `server.met` that does not read to its end either way. Like aMule,
/// it keeps the servers read before the problem, which startup salvages.
#[derive(Debug, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub salvaged: Vec<ServerRecord>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::BadVersion(v) => {
                write!(f, "server.met has an invalid version byte {v:#04x}")?
            }
            ErrorKind::Tag(e) => write!(f, "server.met is corrupt: {e}")?,
            ErrorKind::TrailingData => f.write_str("unexpected trailing data in server.met")?,
        }
        write!(f, " ({} servers salvaged)", self.salvaged.len())
    }
}

impl std::error::Error for Error {}

/// Read records with declared or legacy counts (`ReadRecords`). On error,
/// `out` holds the servers read so far.
fn read_records(
    r: &mut Reader<'_>,
    legacy: bool,
    out: &mut Vec<ServerRecord>,
) -> Result<(), TagError> {
    out.clear();
    let count = r.u32()?;
    for _ in 0..count {
        let ip = Ipv4Addr::from(r.array::<4>()?);
        let port = r.u16()?;
        let tag_count = r.u32()?;
        // Capacity from the data left, not from a count the file claims.
        let mut tags = Vec::with_capacity((tag_count as usize).min(r.remaining() / 4));
        for t in 0..tag_count {
            if legacy
                && t + 1 == tag_count
                && !tags
                    .iter()
                    .any(|tag: &Tag| tag.name.is_id(ServerTag::Version.value()))
            {
                break;
            }
            // Integer widths are kept so that the file can be written back as it was.
            tags.push(Tag::read_ed2k(r, true, false)?);
        }
        out.push(ServerRecord { ip, port, tags });
    }
    Ok(())
}

impl ServerMet {
    /// Parse a whole file (`LoadServerMet` + `ReadServerMetRecords`).
    /// `LoadServerMet` on a downloaded list: unpacked first when it is a
    /// zip, gzip or tar (`UnpackArchive` for `server.met`), then read; `None`
    /// when what is left is not a `.met` ("unknown format encountered").
    pub fn read_packed(bytes: &[u8]) -> Option<Result<ServerMet, Error>> {
        use crate::archive::{unpack, FileType};
        match unpack(bytes, &["server.met"]) {
            Some((plain, FileType::Met)) => Some(ServerMet::read(&plain)),
            _ => None,
        }
    }

    pub fn read(bytes: &[u8]) -> Result<ServerMet, Error> {
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|e| Error {
            kind: ErrorKind::Tag(e.into()),
            salvaged: Vec::new(),
        })?;
        if version != VERSION && version != VERSION_MET_HEADER {
            return Err(Error {
                kind: ErrorKind::BadVersion(version),
                salvaged: Vec::new(),
            });
        }
        let start = r.position();
        let mut records = Vec::new();

        // Read as declared; failing that, with the legacy counts.
        for legacy in [false, true] {
            let mut attempt = r.clone();
            if read_records(&mut attempt, legacy, &mut records).is_ok() && attempt.is_eof() {
                return Ok(ServerMet {
                    version,
                    servers: records,
                    legacy_counts: legacy,
                });
            }
        }
        // Neither way works: read as declared again, so the caller gets the
        // servers before the error, and the error.
        let mut again = Reader::new(bytes);
        again.seek(ed2k_codec::SeekFrom::Start(start as u64)).ok();
        let kind = match read_records(&mut again, false, &mut records) {
            Err(e) => ErrorKind::Tag(e),
            Ok(()) => ErrorKind::TrailingData,
        };
        Err(Error {
            kind,
            salvaged: records,
        })
    }

    /// Serialise. Tags are written as aMule's `.met` writer writes them
    /// (`WriteTagToFile`); tags that cannot be stored in a file (a skipped
    /// BOOL) are left out and not counted.
    pub fn write(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version).u32(self.servers.len() as u32);
        for s in &self.servers {
            let mut tags = Writer::new();
            let mut count = 0u32;
            for t in s.tags.iter().filter(|t| t.can_write_to_file()) {
                let mut one = Writer::new();
                if t.write_kad(&mut one).is_ok() {
                    tags.bytes(one.as_bytes());
                    count += 1;
                }
            }
            w.bytes(&s.ip.octets())
                .u16(s.port)
                .u32(count)
                .bytes(tags.as_bytes());
        }
        w.into_bytes()
    }
}

/// Server preference (`SRV_PR_*`), stored as `ST_PREFERENCE`.
pub const PRIORITY_NORMAL: u32 = 0;
pub const PRIORITY_HIGH: u32 = 1;
pub const PRIORITY_LOW: u32 = 2;

/// What aMule knows about a server from its record (`CServer` after
/// `AddTagFromFile`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerInfo {
    pub ip: Option<Ipv4Addr>,
    /// The port in the record; the server listens here.
    pub port: u16,
    pub name: String,
    pub description: String,
    pub dyn_ip: String,
    pub version: String,
    /// `ST_AUXPORTSLIST`: comma-separated alternative ports. When present and
    /// non-empty, aMule connects to the first of them ([`ServerInfo::connect_port`]).
    pub aux_ports: String,
    pub preference: u32,
    pub failed: u32,
    pub ping: u32,
    /// `ST_LASTPING`, seconds since the epoch. Older aMule wrote
    /// milliseconds since boot here; aMule ignores values in the future.
    pub last_ping: u64,
    pub users: u32,
    pub files: u32,
    pub max_users: u32,
    pub soft_files: u32,
    pub hard_files: u32,
    pub low_id_users: u32,
    pub udp_flags: u32,
    pub udp_key: u32,
    pub udp_key_ip: u32,
    pub obfuscation_port_tcp: u16,
    pub obfuscation_port_udp: u16,
}

impl ServerInfo {
    /// `AddTagFromFile` for every tag. A known tag with a value of the wrong
    /// type is skipped, as is any unknown tag.
    pub fn from_record(rec: &ServerRecord) -> ServerInfo {
        let mut s = ServerInfo {
            ip: Some(rec.ip),
            port: rec.port,
            ..Default::default()
        };
        for t in &rec.tags {
            s.add_tag(t);
        }
        // LoadServerMet: an out-of-range preference becomes normal, and a
        // nameless server is named after its address.
        if s.preference > PRIORITY_LOW {
            s.preference = PRIORITY_NORMAL;
        }
        if s.name.is_empty() {
            s.name = format!("Server {}", rec.ip);
        }
        s
    }

    fn add_tag(&mut self, t: &Tag) {
        let int = || t.as_int().map(|v| v as u32);
        let first_str = |field: &mut String| {
            if let (true, Some(v)) = (field.is_empty(), t.as_str()) {
                *field = v.to_owned();
            }
        };
        let id = match &t.name {
            TagName::Id(id) => Some(*id),
            TagName::Str(s) if s.len() == 1 => Some(s[0]),
            TagName::Str(_) => None,
        };
        match id.and_then(|id| ServerTag::try_from(id).ok()) {
            Some(ServerTag::ServerName) => first_str(&mut self.name),
            Some(ServerTag::Description) => first_str(&mut self.description),
            Some(ServerTag::DynIp) => first_str(&mut self.dyn_ip),
            Some(ServerTag::Preference) => self.preference = int().unwrap_or(self.preference),
            Some(ServerTag::Ping) => self.ping = int().unwrap_or(self.ping),
            Some(ServerTag::Fail) => self.failed = int().unwrap_or(self.failed),
            Some(ServerTag::LastPing) => self.last_ping = t.as_int().unwrap_or(self.last_ping),
            Some(ServerTag::MaxUsers) => self.max_users = int().unwrap_or(self.max_users),
            Some(ServerTag::SoftFiles) => self.soft_files = int().unwrap_or(self.soft_files),
            Some(ServerTag::HardFiles) => self.hard_files = int().unwrap_or(self.hard_files),
            Some(ServerTag::Version) => {
                if let Some(v) = t.as_str() {
                    // First writer wins: the version is stored twice.
                    if self.version.is_empty() {
                        self.version = v.to_owned();
                    }
                } else if let Some(v) = t.as_int() {
                    self.version = format!("{}.{}", v >> 16, v & 0xFFFF);
                }
            }
            Some(ServerTag::UdpFlags) => self.udp_flags = int().unwrap_or(self.udp_flags),
            Some(ServerTag::AuxPortsList) => {
                if let Some(v) = t.as_str() {
                    self.aux_ports = v.to_owned();
                }
            }
            Some(ServerTag::LowIdUsers) => self.low_id_users = int().unwrap_or(self.low_id_users),
            Some(ServerTag::UdpKey) => self.udp_key = int().unwrap_or(self.udp_key),
            Some(ServerTag::UdpKeyIp) => self.udp_key_ip = int().unwrap_or(self.udp_key_ip),
            Some(ServerTag::TcpPortObfuscation) => {
                self.obfuscation_port_tcp =
                    t.as_int().map_or(self.obfuscation_port_tcp, |v| v as u16)
            }
            Some(ServerTag::UdpPortObfuscation) => {
                self.obfuscation_port_udp =
                    t.as_int().map_or(self.obfuscation_port_udp, |v| v as u16)
            }
            _ if t.name.is(b"files") => self.files = int().unwrap_or(self.files),
            _ if t.name.is(b"users") => self.users = int().unwrap_or(self.users),
            // server.met also comes from URLs: unknown tags are skipped, as eMule does.
            _ => {}
        }
    }

    /// The port aMule connects to: the first aux port if there is a
    /// non-empty `ST_AUXPORTSLIST`, else the record's port.
    pub fn connect_port(&self) -> u16 {
        if self.aux_ports.is_empty() {
            return self.port;
        }
        // StrToULong of the text before the first comma; 0 when unparseable.
        self.aux_ports
            .split(',')
            .next()
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or(0)
    }

    /// The record `SaveServerMet` writes for this server, tag for tag.
    pub fn to_record(&self) -> ServerRecord {
        let id = |t: ServerTag| TagName::Id(t.value());
        let s = |t: ServerTag, v: &str| Tag::new(id(t), TagValue::String(v.to_owned()));
        let u32t = |t: ServerTag, v: u32| Tag::new(id(t), TagValue::U32(v));
        let u16t = |t: ServerTag, v: u16| Tag::new(id(t), TagValue::U16(v));
        let mut tags = Vec::new();
        // Each string twice: aMule meant one copy with a BOM "for eMule
        // compatibility", but its file writer ignores the encoding, so both
        // copies are the same plain UTF-8.
        for (t, v) in [
            (ServerTag::ServerName, &self.name),
            (ServerTag::DynIp, &self.dyn_ip),
            (ServerTag::Description, &self.description),
        ] {
            if !v.is_empty() {
                tags.push(s(t, v));
                tags.push(s(t, v));
            }
        }
        if self.connect_port() != self.port {
            tags.push(s(ServerTag::AuxPortsList, &self.aux_ports));
        }
        tags.push(u32t(ServerTag::Fail, self.failed));
        tags.push(u32t(ServerTag::Preference, self.preference));
        tags.push(Tag::new("users", TagValue::U32(self.users)));
        tags.push(Tag::new("files", TagValue::U32(self.files)));
        tags.push(u32t(ServerTag::Ping, self.ping));
        tags.push(u32t(ServerTag::LastPing, self.last_ping as u32));
        tags.push(u32t(ServerTag::MaxUsers, self.max_users));
        tags.push(u32t(ServerTag::SoftFiles, self.soft_files));
        tags.push(u32t(ServerTag::HardFiles, self.hard_files));
        if !self.version.is_empty() {
            tags.push(s(ServerTag::Version, &self.version));
            tags.push(s(ServerTag::Version, &self.version));
        }
        tags.push(u32t(ServerTag::UdpFlags, self.udp_flags));
        tags.push(u32t(ServerTag::LowIdUsers, self.low_id_users));
        if self.udp_key != 0 {
            tags.push(u32t(ServerTag::UdpKey, self.udp_key));
        }
        if self.udp_key_ip != 0 {
            tags.push(u32t(ServerTag::UdpKeyIp, self.udp_key_ip));
        }
        if self.obfuscation_port_tcp != 0 {
            tags.push(u16t(
                ServerTag::TcpPortObfuscation,
                self.obfuscation_port_tcp,
            ));
        }
        if self.obfuscation_port_udp != 0 {
            tags.push(u16t(
                ServerTag::UdpPortObfuscation,
                self.obfuscation_port_udp,
            ));
        }
        ServerRecord {
            ip: self.ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            port: self.port,
            tags,
        }
    }
}

#[cfg(test)]
mod tests;
