// SPDX-License-Identifier: GPL-2.0-or-later
//! `clients.met`: credits for other clients, and what aMule remembers about
//! them.
//!
//! Port of `CClientCreditsList::LoadList` / `SaveList`
//! (ClientCreditsList.cpp), `CreditStruct` and `CClientCredits::GetCreditRatio`
//! (ClientCredits.{h,cpp}) and the metadata trailer (ClientMetaTrailer.cpp).
//!
//! Layout: the version byte `CREDITFILE_VERSION` (0x12), a `u32` count, then
//! that many fixed 119-byte records (shared with eMule):
//!
//! ```text
//! MD4 key | u32 up lo | u32 down lo | u32 last seen | u32 up hi | u32 down hi
//!         | u16 reserved | u8 key size | 80 bytes secure-ident public key
//! ```
//!
//! After the records, aMule may append a metadata block (magic `AMULEMD1`,
//! version 1 or 2) that older readers never look at. Everything after the
//! records is kept as raw bytes, so a file writes back byte for byte;
//! [`ClientsMet::trailer`] parses it the way aMule does.

use std::fmt;

use ed2k_codec::{LenField, Reader, StrEncoding, Writer};
use ed2k_types::Md4Hash;

/// `CREDITFILE_VERSION`
pub const VERSION: u8 = 0x12;
/// `MAXPUBKEYSIZE`: room for the secure-ident public key in each record.
pub const MAX_PUBKEY_SIZE: usize = 80;
/// Size of one record on disk.
pub const RECORD_LEN: usize = 16 + 4 * 5 + 2 + 1 + MAX_PUBKEY_SIZE;
/// Records not seen for this long are dropped when the file is loaded
/// (`time(NULL) - 12960000`, 150 days).
pub const EXPIRY_SECS: u32 = 12_960_000;

/// `kMetaMagic`
pub const META_MAGIC: [u8; 8] = *b"AMULEMD1";
/// `kMetaVersion`: the trailer version aMule writes (1 is still read).
pub const META_VERSION: u8 = 2;
/// `kMetaMaxNameChars`: names and mod strings are cut to this many characters on write.
pub const META_MAX_NAME_CHARS: usize = 64;

/// One client's credits (`CreditStruct`), exactly as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditRecord {
    pub key: Md4Hash,
    /// Bytes uploaded to this client.
    pub uploaded: u64,
    /// Bytes downloaded from this client.
    pub downloaded: u64,
    /// Seconds since the epoch.
    pub last_seen: u32,
    /// `nReserved3`, kept as stored.
    pub reserved: u16,
    pub key_size: u8,
    /// The whole 80-byte area; only the first `key_size` bytes are the key.
    /// aMule writes whatever is in the unused tail, so it is kept as well.
    pub secure_ident: [u8; MAX_PUBKEY_SIZE],
}

impl CreditRecord {
    /// A record with no public key, as `CreditStruct()` starts out.
    pub fn new(key: Md4Hash) -> Self {
        CreditRecord {
            key,
            uploaded: 0,
            downloaded: 0,
            last_seen: 0,
            reserved: 0,
            key_size: 0,
            secure_ident: [0; MAX_PUBKEY_SIZE],
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, ed2k_codec::Error> {
        let key = r.hash()?;
        let up_lo = r.u32()?;
        let down_lo = r.u32()?;
        let last_seen = r.u32()?;
        let up_hi = r.u32()?;
        let down_hi = r.u32()?;
        let reserved = r.u16()?;
        let key_size = r.u8()?;
        let secure_ident = r.array()?;
        Ok(CreditRecord {
            key,
            uploaded: u64::from(up_lo) | (u64::from(up_hi) << 32),
            downloaded: u64::from(down_lo) | (u64::from(down_hi) << 32),
            last_seen,
            reserved,
            key_size,
            secure_ident,
        })
    }

    fn write(&self, w: &mut Writer) {
        w.hash(self.key)
            .u32(self.uploaded as u32)
            .u32(self.downloaded as u32)
            .u32(self.last_seen)
            .u32((self.uploaded >> 32) as u32)
            .u32((self.downloaded >> 32) as u32)
            .u16(self.reserved)
            .u8(self.key_size)
            .bytes(&self.secure_ident);
    }

    /// The client's secure-ident public key (empty if none).
    pub fn public_key(&self) -> &[u8] {
        &self.secure_ident[..usize::from(self.key_size).min(MAX_PUBKEY_SIZE)]
    }

    /// Dropped on load: last seen more than 150 days before `now`.
    pub fn is_expired(&self, now: u32) -> bool {
        self.last_seen < now.wrapping_sub(EXPIRY_SECS)
    }

    /// Written by `SaveList` only if there was traffic either way.
    pub fn has_traffic(&self) -> bool {
        self.uploaded != 0 || self.downloaded != 0
    }

    /// `GetCreditRatio`: how much this client's upload queue score is
    /// multiplied by, between 1 and 10. In the C++ the first ratio is a
    /// `float` and the square-root bound a `double`, compared as doubles;
    /// this reproduces that.
    pub fn credit_ratio(&self) -> f32 {
        if self.downloaded < 1_000_000 {
            return 1.0;
        }
        let mut result: f32 = if self.uploaded == 0 {
            10.0
        } else {
            (self.downloaded as f32 * 2.0) / self.uploaded as f32
        };
        let result2: f64 = ((self.downloaded as f64 / 1_048_576.0) + 2.0).sqrt();
        if f64::from(result) > result2 {
            result = result2 as f32;
        }
        result.clamp(1.0, 10.0)
    }
}

/// What aMule remembers about a peer beyond its credits (`ClientMetaStruct`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientMeta {
    pub name: String,
    /// Self-declared mod identity (trailer version 2).
    pub mod_version: String,
    pub first_seen: u32,
    pub sessions: u32,
    /// Last address, a `u32` in aMule's in-memory order.
    pub last_ip: u32,
    pub last_port: u16,
    pub kad_port: u16,
    pub version: u32,
    pub client_soft: u8,
    pub source_from: u8,
    pub obfuscation: u8,
}

impl ClientMeta {
    /// `IsPopulated`: nothing worth persisting until the peer was met once.
    pub fn is_populated(&self) -> bool {
        self.first_seen != 0
    }
}

/// One trailer entry (`ClientMetaTrailer::Entry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaEntry {
    pub key: Md4Hash,
    pub meta: ClientMeta,
}

/// The outcome of reading the trailer (`ClientMetaTrailer::ReadResult`).
/// Metadata is best-effort: none of these affects the credits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrailerRead {
    /// Every entry read.
    Ok(Vec<MetaEntry>),
    /// Nothing after the records, or too little to be a block.
    Absent,
    /// Trailing data without the magic.
    Foreign,
    /// A block from a newer aMule; left alone.
    OtherVersion(u8),
    /// The block ends early or is malformed; the complete entries before the
    /// damage are kept, as aMule keeps them.
    Damaged(Vec<MetaEntry>),
}

impl TrailerRead {
    /// The entries aMule applies, whatever the outcome.
    pub fn entries(&self) -> &[MetaEntry] {
        match self {
            TrailerRead::Ok(e) | TrailerRead::Damaged(e) => e,
            _ => &[],
        }
    }
}

/// `ClientMetaTrailer::Read`, on the bytes after the records.
pub fn read_trailer(bytes: &[u8]) -> TrailerRead {
    if bytes.len() < META_MAGIC.len() + 1 + 4 {
        return TrailerRead::Absent;
    }
    if bytes[..META_MAGIC.len()] != META_MAGIC {
        return TrailerRead::Foreign;
    }
    let mut r = Reader::new(&bytes[META_MAGIC.len()..]);
    let version = r.u8().unwrap_or_default();
    if version != 1 && version != META_VERSION {
        return TrailerRead::OtherVersion(version);
    }
    let Ok(count) = r.u32() else {
        return TrailerRead::Damaged(Vec::new());
    };
    // Each entry takes at least 41 bytes: no allocation beyond what the data can hold.
    let mut entries = Vec::with_capacity((count as usize).min(r.remaining() / 41));
    for _ in 0..count {
        match read_entry(&mut r, version) {
            Ok(e) => entries.push(e),
            Err(_) => return TrailerRead::Damaged(entries),
        }
    }
    TrailerRead::Ok(entries)
}

fn read_entry(r: &mut Reader<'_>, version: u8) -> Result<MetaEntry, ed2k_codec::Error> {
    let key = r.hash()?;
    let mut m = ClientMeta {
        first_seen: r.u32()?,
        sessions: r.u32()?,
        last_ip: r.u32()?,
        last_port: r.u16()?,
        kad_port: r.u16()?,
        version: r.u32()?,
        client_soft: r.u8()?,
        source_from: r.u8()?,
        obfuscation: r.u8()?,
        ..Default::default()
    };
    m.name = r.string(true, LenField::U16, false)?;
    if version >= 2 {
        m.mod_version = r.string(true, LenField::U16, false)?;
    }
    Ok(MetaEntry { key, meta: m })
}

/// `ClientMetaTrailer::Write`: nothing at all for no entries, so a file with
/// no metadata stays identical to what an older aMule writes.
pub fn write_trailer(w: &mut Writer, entries: &[MetaEntry]) {
    if entries.is_empty() {
        return;
    }
    let cap = |s: &str| -> String { s.chars().take(META_MAX_NAME_CHARS).collect() };
    w.bytes(&META_MAGIC)
        .u8(META_VERSION)
        .u32(entries.len() as u32);
    for e in entries {
        let m = &e.meta;
        w.hash(e.key)
            .u32(m.first_seen)
            .u32(m.sessions)
            .u32(m.last_ip)
            .u16(m.last_port)
            .u16(m.kad_port)
            .u32(m.version)
            .u8(m.client_soft)
            .u8(m.source_from)
            .u8(m.obfuscation)
            .string(&cap(&m.name), StrEncoding::Utf8, LenField::U16)
            .string(&cap(&m.mod_version), StrEncoding::Utf8, LenField::U16);
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    /// Not `CREDITFILE_VERSION`: aMule treats the file as outdated, loads
    /// nothing, and replaces it on the next save.
    Outdated(u8),
    /// A record claims a key longer than 80 bytes. aMule takes the whole
    /// file for corrupt and discards every record.
    BadKeySize { record: usize, size: u8 },
    /// The file ends inside a record.
    Truncated,
}

/// A `clients.met` that could not be read in full.
#[derive(Debug, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    /// Records read before a truncation. aMule keeps those (its IO error
    /// handler leaves them loaded); for the other kinds this is empty.
    pub salvaged: Vec<CreditRecord>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Outdated(v) => write!(f, "clients.met version {v:#04x} is outdated"),
            ErrorKind::BadKeySize { record, size } => {
                write!(
                    f,
                    "clients.met record {record} has a {size}-byte key; the file is corrupt"
                )
            }
            ErrorKind::Truncated => {
                write!(
                    f,
                    "clients.met is truncated ({} records salvaged)",
                    self.salvaged.len()
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// A whole `clients.met`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientsMet {
    pub records: Vec<CreditRecord>,
    /// Everything after the records, as stored (normally empty or a metadata block).
    pub trailing: Vec<u8>,
}

impl ClientsMet {
    /// Parse a whole file. All records are returned, expired ones included;
    /// see [`ClientsMet::live`] for what aMule keeps.
    pub fn read(bytes: &[u8]) -> Result<ClientsMet, Error> {
        let mut r = Reader::new(bytes);
        let fail = |kind, salvaged| Err(Error { kind, salvaged });
        let Ok(version) = r.u8() else {
            return fail(ErrorKind::Truncated, Vec::new());
        };
        if version != VERSION {
            return fail(ErrorKind::Outdated(version), Vec::new());
        }
        let Ok(count) = r.u32() else {
            return fail(ErrorKind::Truncated, Vec::new());
        };
        let mut records = Vec::with_capacity((count as usize).min(r.remaining() / RECORD_LEN));
        for i in 0..count as usize {
            let Ok(rec) = CreditRecord::read(&mut r) else {
                return fail(ErrorKind::Truncated, records);
            };
            if usize::from(rec.key_size) > MAX_PUBKEY_SIZE {
                return fail(
                    ErrorKind::BadKeySize {
                        record: i,
                        size: rec.key_size,
                    },
                    Vec::new(),
                );
            }
            records.push(rec);
        }
        Ok(ClientsMet {
            records,
            trailing: r.rest().to_vec(),
        })
    }

    /// Serialise exactly what was read.
    pub fn write(&self) -> Vec<u8> {
        let mut w =
            Writer::with_capacity(5 + self.records.len() * RECORD_LEN + self.trailing.len());
        w.u8(VERSION).u32(self.records.len() as u32);
        for rec in &self.records {
            rec.write(&mut w);
        }
        w.bytes(&self.trailing);
        w.into_bytes()
    }

    /// The metadata block after the records.
    pub fn trailer(&self) -> TrailerRead {
        read_trailer(&self.trailing)
    }

    /// The records aMule keeps when loading at time `now`: not expired.
    pub fn live(&self, now: u32) -> impl Iterator<Item = &CreditRecord> {
        self.records.iter().filter(move |r| !r.is_expired(now))
    }

    /// `SaveList`: only records with traffic, then the metadata of those
    /// records whose metadata is populated.
    pub fn save(records: &[CreditRecord], meta: &[MetaEntry]) -> ClientsMet {
        let written: Vec<CreditRecord> = records
            .iter()
            .filter(|r| r.has_traffic())
            .cloned()
            .collect();
        let entries: Vec<MetaEntry> = meta
            .iter()
            .filter(|e| e.meta.is_populated() && written.iter().any(|r| r.key == e.key))
            .cloned()
            .collect();
        let mut w = Writer::new();
        write_trailer(&mut w, &entries);
        ClientsMet {
            records: written,
            trailing: w.into_bytes(),
        }
    }
}

#[cfg(test)]
mod tests;
