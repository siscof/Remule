// SPDX-License-Identifier: GPL-2.0-or-later
//! `emfriends.met`: the friends list.
//!
//! Port of `CFriendList::LoadList` / `SaveList` (FriendList.cpp) and
//! `CFriend::LoadFromFile` / `WriteToFile` (Friend.cpp).
//!
//! Layout: a version byte (`MET_HEADER` `0x0E`), a `u32` friend count, then
//! per friend:
//!
//! ```text
//! MD4 user hash | IPv4 (4 bytes, network order) | u16 port | u32 last seen
//! | u32 last chatted | u32 m | m × eD2k tag
//! ```
//!
//! The tags are `FF_NAME` (string) and `FF_FRIENDSLOT` (integer).
//!
//! [`EmfriendsMet`] keeps records exactly as stored, so a file aMule wrote is
//! written back byte for byte; [`Friend`] is the typed view.
//!
//! aMule loads nothing, silently, from a file whose header is not `0x0E`;
//! here that is [`ErrorKind::BadVersion`], for the caller to treat as an
//! empty list. Damage that stops the read keeps the friends before it, as
//! aMule does.

use std::fmt;
use std::net::Ipv4Addr;

use ed2k_codec::{Reader, Tag, TagError, TagName, TagValue, Writer};
use ed2k_types::Md4Hash;

/// `MET_HEADER`, the only version aMule reads and writes.
pub const VERSION: u8 = 0x0E;

/// `FF_NAME`: the friend's user name.
pub const FF_NAME: u8 = 0x01;
/// `FF_FRIENDSLOT`: non-zero if the friend has a reserved upload slot.
pub const FF_FRIENDSLOT: u8 = 0x02;

/// One friend as stored.
#[derive(Clone, Debug, PartialEq)]
pub struct FriendRecord {
    pub user_hash: Md4Hash,
    /// `m_dwLastUsedIP`
    pub ip: Ipv4Addr,
    /// `m_nLastUsedPort`
    pub port: u16,
    /// `m_dwLastSeen`, seconds since the epoch.
    pub last_seen: u32,
    /// `m_dwLastChatted`, seconds since the epoch.
    pub last_chatted: u32,
    pub tags: Vec<Tag>,
}

/// A whole `emfriends.met`.
#[derive(Clone, Debug, PartialEq)]
pub struct EmfriendsMet {
    pub version: u8,
    pub friends: Vec<FriendRecord>,
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    /// Not `0x0E`. aMule then loads no friends.
    BadVersion(u8),
    /// A record could not be read.
    Tag(TagError),
    /// `FF_NAME` is not a string, or `FF_FRIENDSLOT` not an integer
    /// (`CInvalidPacket` from `GetStr`/`GetInt`).
    WrongType(u8),
}

/// An `emfriends.met` that cannot be read to its end. Like aMule, the
/// friends read before the problem are kept.
#[derive(Debug, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub salvaged: Vec<FriendRecord>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::BadVersion(v) => write!(f, "emfriends.met has an invalid header {v:#04x}")?,
            ErrorKind::Tag(e) => write!(f, "emfriends.met is corrupt: {e}")?,
            ErrorKind::WrongType(t) => write!(f, "emfriends.met tag {t:#04x} has the wrong type")?,
        }
        write!(f, " ({} friends salvaged)", self.salvaged.len())
    }
}

impl std::error::Error for Error {}

impl FriendRecord {
    /// `CFriend::LoadFromFile`, keeping every tag and its integer width.
    pub fn read(r: &mut Reader<'_>) -> Result<FriendRecord, TagError> {
        let user_hash = r.hash()?;
        let ip = Ipv4Addr::from(r.array::<4>()?);
        let port = r.u16()?;
        let last_seen = r.u32()?;
        let last_chatted = r.u32()?;
        let m = r.u32()?;
        // Capacity from the data left, not from a count the file claims.
        let mut tags = Vec::with_capacity((m as usize).min(r.remaining() / 4));
        for _ in 0..m {
            tags.push(Tag::read_ed2k(r, true, false)?);
        }
        Ok(FriendRecord {
            user_hash,
            ip,
            port,
            last_seen,
            last_chatted,
            tags,
        })
    }

    /// Serialise. Tags that cannot be stored in a file (a skipped BOOL) are
    /// left out and not counted.
    pub fn write(&self, w: &mut Writer) {
        w.hash(self.user_hash)
            .bytes(&self.ip.octets())
            .u16(self.port)
            .u32(self.last_seen)
            .u32(self.last_chatted);
        let tags: Vec<&Tag> = self.tags.iter().filter(|t| t.can_write_to_file()).collect();
        w.u32(tags.len() as u32);
        for t in tags {
            // can_write_to_file() admits only what write_kad can write.
            t.write_kad(w).expect("a file tag is writable");
        }
    }
}

impl EmfriendsMet {
    /// Parse a whole file (`CFriendList::LoadList`).
    pub fn read(bytes: &[u8]) -> Result<EmfriendsMet, Error> {
        let mut r = Reader::new(bytes);
        let fail = |kind, salvaged| Error { kind, salvaged };
        let version = r
            .u8()
            .map_err(|e| fail(ErrorKind::Tag(e.into()), Vec::new()))?;
        if version != VERSION {
            return Err(fail(ErrorKind::BadVersion(version), Vec::new()));
        }
        let count = r
            .u32()
            .map_err(|e| fail(ErrorKind::Tag(e.into()), Vec::new()))?;
        let mut friends = Vec::new();
        for _ in 0..count {
            let rec = match FriendRecord::read(&mut r) {
                Ok(rec) => rec,
                Err(e) => return Err(fail(ErrorKind::Tag(e), friends)),
            };
            // The C++ interprets the tags while reading; a wrong type throws
            // before the friend is added.
            if let Err(id) = Friend::from_record(&rec) {
                return Err(fail(ErrorKind::WrongType(id), friends));
            }
            friends.push(rec);
        }
        Ok(EmfriendsMet { version, friends })
    }

    /// Serialise with the stored version byte (`SaveList`).
    pub fn write(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version).u32(self.friends.len() as u32);
        for f in &self.friends {
            f.write(&mut w);
        }
        w.into_bytes()
    }
}

/// What aMule knows about a friend from its record (`CFriend` after
/// `LoadFromFile`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Friend {
    pub user_hash: Md4Hash,
    pub ip: Option<Ipv4Addr>,
    pub port: u16,
    pub last_seen: u32,
    pub last_chatted: u32,
    /// The first `FF_NAME`; empty if there is none.
    pub name: String,
    pub friend_slot: bool,
}

fn tag_id(t: &Tag) -> Option<u8> {
    match &t.name {
        TagName::Id(id) => Some(*id),
        TagName::Str(s) if s.len() == 1 => Some(s[0]),
        TagName::Str(_) => None,
    }
}

impl Friend {
    /// The tag rules of `LoadFromFile`: the first name wins, a non-zero slot
    /// tag sets the friend slot, other tags are ignored. A wrong-typed known
    /// tag is an error with its id, as the C++ `GetStr`/`GetInt` throw.
    pub fn from_record(rec: &FriendRecord) -> Result<Friend, u8> {
        let mut f = Friend {
            user_hash: rec.user_hash,
            ip: Some(rec.ip),
            port: rec.port,
            last_seen: rec.last_seen,
            last_chatted: rec.last_chatted,
            ..Default::default()
        };
        for t in &rec.tags {
            match tag_id(t) {
                Some(FF_NAME) => {
                    let s = t.as_str().ok_or(FF_NAME)?;
                    if f.name.is_empty() {
                        f.name = s.to_owned();
                    }
                }
                Some(FF_FRIENDSLOT) => f.friend_slot = t.as_int().ok_or(FF_FRIENDSLOT)? != 0,
                _ => {}
            }
        }
        Ok(f)
    }

    /// The record `WriteToFile` writes, tag for tag: the name twice (aMule
    /// meant one copy with a BOM, but its file writer ignores the encoding,
    /// so both are plain UTF-8), then a `uint8` slot tag of 1 if set.
    pub fn to_record(&self) -> FriendRecord {
        let mut tags = Vec::new();
        if !self.name.is_empty() {
            for _ in 0..2 {
                tags.push(Tag::new(FF_NAME, TagValue::String(self.name.clone())));
            }
        }
        if self.friend_slot {
            tags.push(Tag::new(FF_FRIENDSLOT, TagValue::U8(1)));
        }
        FriendRecord {
            user_hash: self.user_hash,
            ip: self.ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            port: self.port,
            last_seen: self.last_seen,
            last_chatted: self.last_chatted,
            tags,
        }
    }
}

#[cfg(test)]
mod tests;
