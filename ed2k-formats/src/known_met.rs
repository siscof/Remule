// SPDX-License-Identifier: GPL-2.0-or-later
//! `known.met`: every file aMule has hashed, with its part hashes and
//! sharing statistics.
//!
//! Port of `CKnownFileList::Init` / `Save` and `CKnownFile::LoadFromFile` /
//! `WriteToFile` (KnownFileList.cpp, KnownFile.cpp).
//!
//! Layout: a version byte (`MET_HEADER` `0x0E`, or
//! `MET_HEADER_WITH_LARGEFILES` `0x0F` when any file is over 4 GB), a `u32`
//! record count, then per file:
//!
//! ```text
//! u32 date (mtime) | MD4 file hash | u16 n | n × MD4 part hash | u32 m | m × eD2k tag
//! ```
//!
//! A record is kept only if its part hashes check out (`LoadHashsetFromFile`
//! and the final count check of `LoadFromFile`); a bad record is skipped and
//! loading goes on. Damage that makes the rest unreadable (a short file, a
//! known tag of the wrong type) stops the load, keeping the files before it,
//! as aMule does.
//!
//! [`KnownMet`] keeps records exactly as stored, so a file aMule wrote is
//! written back byte for byte; [`KnownFile`] is the typed view.

use std::fmt;

use ed2k_codec::{Reader, Tag, TagError, TagName, TagValue, Writer};
use ed2k_types::ed2k::{OLD_MAX_FILE_SIZE, PARTSIZE};
use ed2k_types::tags::FileTag;
use ed2k_types::Md4Hash;
use md4::{Digest, Md4};

/// `MET_HEADER`
pub const VERSION: u8 = 0x0E;
/// `MET_HEADER_WITH_LARGEFILES`, written when any file is over 4 GB.
pub const VERSION_LARGE_FILES: u8 = 0x0F;

/// One file as stored.
#[derive(Clone, Debug, PartialEq)]
pub struct KnownRecord {
    /// When the file was last changed on disk (`m_lastDateChanged`), seconds since the epoch.
    pub date: u32,
    pub hash: Md4Hash,
    pub part_hashes: Vec<Md4Hash>,
    pub tags: Vec<Tag>,
}

/// Why a record was skipped (`LoadFromFile` returning false).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The MD4 of the part hashes is not the file hash.
    HashsetMismatch,
    /// The file size needs this many part hashes, but the record has another number.
    PartCount { expected: usize, found: usize },
}

/// A whole `known.met`.
#[derive(Clone, Debug, PartialEq)]
pub struct KnownMet {
    pub version: u8,
    pub records: Vec<KnownRecord>,
    /// Records that were read but skipped, by their position in the file.
    pub skipped: Vec<(usize, Invalid)>,
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    /// Neither `0x0E` nor `0x0F`.
    BadVersion(u8),
    /// A record could not be read.
    Tag(TagError),
    /// A known tag holds a value of the wrong type (`CInvalidPacket` from
    /// `GetInt`/`GetStr`).
    WrongType(FileTag),
}

/// A `known.met` that cannot be read to its end. Like aMule, the files read
/// before the problem are kept.
#[derive(Debug, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub salvaged: Vec<KnownRecord>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::BadVersion(v) => write!(f, "known.met has an invalid header {v:#04x}")?,
            ErrorKind::Tag(e) => write!(f, "known.met is corrupt: {e}")?,
            ErrorKind::WrongType(t) => write!(f, "known.met tag {t:?} has the wrong type")?,
        }
        write!(f, " ({} files salvaged)", self.salvaged.len())
    }
}

impl std::error::Error for Error {}

/// How many part hashes a file of `size` bytes has (`m_iED2KPartHashCount`):
/// none below one part, and one more than the full parts otherwise. The
/// extra one is eD2k's hash of the empty last part of an exact multiple.
pub const fn part_hash_count(size: u64) -> usize {
    let n = size / PARTSIZE;
    if n == 0 {
        0
    } else {
        n as usize + 1
    }
}

/// `CreateHashFromHashlist`: the file hash is the MD4 of the concatenated part hashes.
pub fn hash_of_part_hashes(parts: &[Md4Hash]) -> Md4Hash {
    let mut h = Md4::new();
    for p in parts {
        h.update(p.0);
    }
    Md4Hash(h.finalize().into())
}

impl KnownRecord {
    /// `LoadDateFromFile` + `LoadHashsetFromFile` + the tag list. Integer
    /// widths are kept so the record can be written back as it was.
    pub fn read(r: &mut Reader<'_>) -> Result<KnownRecord, TagError> {
        let date = r.u32()?;
        let hash = r.hash()?;
        let n = r.u16()?;
        let mut part_hashes = Vec::with_capacity(usize::from(n).min(r.remaining() / 16));
        for _ in 0..n {
            part_hashes.push(r.hash()?);
        }
        let m = r.u32()?;
        let mut tags = Vec::with_capacity((m as usize).min(r.remaining() / 4));
        for _ in 0..m {
            tags.push(Tag::read_ed2k(r, true, false)?);
        }
        Ok(KnownRecord {
            date,
            hash,
            part_hashes,
            tags,
        })
    }

    pub fn write(&self, w: &mut Writer) {
        w.u32(self.date)
            .hash(self.hash)
            .u16(self.part_hashes.len() as u16);
        for p in &self.part_hashes {
            w.hash(*p);
        }
        let tags: Vec<&Tag> = self.tags.iter().filter(|t| t.can_write_to_file()).collect();
        w.u32(tags.len() as u32);
        for t in tags {
            // can_write_to_file() admits only what write_kad can write.
            t.write_kad(w).expect("a file tag is writable");
        }
    }

    /// The checks of `LoadFromFile`, given the file size from the tags.
    pub fn check(&self, size: u64) -> Result<(), Invalid> {
        if self.part_hashes.len() > 1 && hash_of_part_hashes(&self.part_hashes) != self.hash {
            return Err(Invalid::HashsetMismatch);
        }
        let expected = part_hash_count(size);
        if self.part_hashes.len() != expected {
            return Err(Invalid::PartCount {
                expected,
                found: self.part_hashes.len(),
            });
        }
        Ok(())
    }
}

impl KnownMet {
    /// Parse a whole file (`CKnownFileList::Init`).
    pub fn read(bytes: &[u8]) -> Result<KnownMet, Error> {
        let mut r = Reader::new(bytes);
        let fail = |kind, salvaged| Error { kind, salvaged };
        let version = r
            .u8()
            .map_err(|e| fail(ErrorKind::Tag(e.into()), Vec::new()))?;
        if version != VERSION && version != VERSION_LARGE_FILES {
            return Err(fail(ErrorKind::BadVersion(version), Vec::new()));
        }
        let count = r
            .u32()
            .map_err(|e| fail(ErrorKind::Tag(e.into()), Vec::new()))?;
        let mut records = Vec::new();
        let mut skipped = Vec::new();
        for i in 0..count as usize {
            let rec = match KnownRecord::read(&mut r) {
                Ok(rec) => rec,
                Err(e) => return Err(fail(ErrorKind::Tag(e), records)),
            };
            let file = match KnownFile::from_record(&rec) {
                Ok(f) => f,
                Err(t) => return Err(fail(ErrorKind::WrongType(t), records)),
            };
            match rec.check(file.size) {
                Ok(()) => records.push(rec),
                Err(why) => skipped.push((i, why)),
            }
        }
        Ok(KnownMet {
            version,
            records,
            skipped,
        })
    }

    /// Serialise with the stored version byte.
    pub fn write(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.version).u32(self.records.len() as u32);
        for rec in &self.records {
            rec.write(&mut w);
        }
        w.into_bytes()
    }

    /// The version byte aMule would write: 0x0F if any file is over 4 GB.
    pub fn canonical_version(&self) -> u8 {
        let large = self
            .records
            .iter()
            .any(|r| KnownFile::from_record(r).is_ok_and(|f| f.size > OLD_MAX_FILE_SIZE));
        if large {
            VERSION_LARGE_FILES
        } else {
            VERSION
        }
    }
}

/// Upload priority (`PR_*`), as stored in `FT_ULPRIORITY`.
pub mod priority {
    pub const LOW: u32 = 0;
    pub const NORMAL: u32 = 1;
    pub const HIGH: u32 = 2;
    pub const VERY_HIGH: u32 = 3;
    pub const VERY_LOW: u32 = 4;
    pub const AUTO: u32 = 5;
    pub const POWERSHARE: u32 = 6;
}

/// What aMule knows about a file from its record (`CKnownFile` after
/// `LoadFromFile`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KnownFile {
    pub date: u32,
    pub hash: Md4Hash,
    pub part_hashes: Vec<Md4Hash>,
    /// The file name. aMule stores it twice and prefers the second copy, a
    /// "universal" form of the on-disk bytes (see [`KnownFile::from_record`]).
    pub name: String,
    pub size: u64,
    pub all_time_transferred: u64,
    pub all_time_requests: u32,
    pub all_time_accepts: u32,
    /// One of [`priority`], never [`priority::AUTO`]: that is [`KnownFile::auto_priority`].
    pub up_priority: u32,
    pub auto_priority: bool,
    /// The AICH root hash, base32, when the record has a valid one.
    pub aich_hash: Option<String>,
    pub kad_last_publish_src: u32,
    pub kad_last_publish_notes: u32,
    /// When the file was last seen on disk; records from before this tag
    /// fall back to [`KnownFile::date`].
    pub last_seen: u32,
    pub last_uploaded: u32,
    pub shared_since: u32,
    /// Last "verify local data" run, and its corrupt parts / AICH blocks.
    pub verify_date: u32,
    pub verify_corrupt_md4: String,
    pub verify_corrupt_aich: String,
    /// Tags aMule does not interpret, kept and written back.
    pub other_tags: Vec<Tag>,
}

/// The universal name (`CPath::FromUniv`): each character is a byte of the
/// on-disk name, which is decoded as UTF-8. `None` when that fails.
fn from_univ(s: &str) -> Option<String> {
    let bytes: Option<Vec<u8>> = s.chars().map(|c| u8::try_from(u32::from(c)).ok()).collect();
    String::from_utf8(bytes?).ok().filter(|n| !n.is_empty())
}

/// `CPath::ToUniv`: the name's UTF-8 bytes, one character per byte.
fn to_univ(name: &str) -> String {
    name.bytes().map(char::from).collect()
}

/// An AICH root hash in base32 is 32 characters of A-Z and 2-7 (20 bytes).
fn is_aich_base32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
}

impl KnownFile {
    /// `LoadTagsFromFile` and the rest of `LoadFromFile`. A known tag with a
    /// value of the wrong type is an error, as the C++ `GetInt`/`GetStr` throw.
    ///
    /// One deliberate difference: `FT_FILESIZE_HI`, eMule's high half of a
    /// large file's size, is combined with `FT_FILESIZE`. aMule ignores it,
    /// so it reads such a file's size modulo 4 GiB and drops the record.
    pub fn from_record(rec: &KnownRecord) -> Result<KnownFile, FileTag> {
        let mut f = KnownFile {
            date: rec.date,
            hash: rec.hash,
            part_hashes: rec.part_hashes.clone(),
            up_priority: priority::NORMAL,
            ..Default::default()
        };
        let mut size_hi = 0u64;
        let mut first_name: Option<String> = None;
        for t in &rec.tags {
            let id = match &t.name {
                TagName::Id(id) => FileTag::try_from(*id).ok(),
                TagName::Str(s) if s.len() == 1 => FileTag::try_from(s[0]).ok(),
                TagName::Str(_) => None,
            };
            let Some(id) = id else {
                f.other_tags.push(t.clone());
                continue;
            };
            let int = || t.as_int().ok_or(id);
            let int32 = || int().map(|v| v as u32);
            let string = || t.as_str().map(str::to_owned).ok_or(id);
            match id {
                FileTag::Filename => {
                    let s = string()?;
                    match first_name {
                        // The second name is the universal one; it wins if it decodes.
                        Some(_) => {
                            if let Some(n) = from_univ(&s) {
                                f.name = n;
                            }
                        }
                        None => {
                            f.name = s.clone();
                            first_name = Some(s);
                        }
                    }
                }
                FileTag::Filesize => f.size = int()?,
                FileTag::FilesizeHi => size_hi = int()?,
                FileTag::AtTransferred => f.all_time_transferred += int()?,
                FileTag::AtTransferredHi => f.all_time_transferred += int()? << 32,
                FileTag::AtRequested => f.all_time_requests = int32()?,
                FileTag::AtAccepted => f.all_time_accepts = int32()?,
                FileTag::UlPriority => {
                    let p = int32()?;
                    if p == priority::AUTO {
                        f.up_priority = priority::HIGH;
                        f.auto_priority = true;
                    } else {
                        f.up_priority = if p <= priority::POWERSHARE {
                            p
                        } else {
                            priority::NORMAL
                        };
                        f.auto_priority = false;
                    }
                }
                // Old tags aMule no longer uses: purged.
                FileTag::Permissions | FileTag::KadLastPublishKey | FileTag::PartFilename => {}
                FileTag::AichHash => {
                    let s = string()?;
                    if is_aich_base32(&s) {
                        f.aich_hash = Some(s);
                    }
                }
                FileTag::KadLastPublishSrc => f.kad_last_publish_src = int32()?,
                FileTag::KadLastPublishNotes => f.kad_last_publish_notes = int32()?,
                FileTag::LastSeen => f.last_seen = int32()?,
                FileTag::LastUploaded => f.last_uploaded = int32()?,
                FileTag::SharedSince => f.shared_since = int32()?,
                FileTag::VerifyDate => f.verify_date = int32()?,
                FileTag::VerifyCorruptMd4 => f.verify_corrupt_md4 = string()?,
                FileTag::VerifyCorruptAich => f.verify_corrupt_aich = string()?,
                _ => f.other_tags.push(t.clone()),
            }
        }
        f.size |= size_hi << 32;
        if f.last_seen == 0 {
            f.last_seen = f.date;
        }
        // Corrupt lists without a date are orphans of a damaged record.
        if f.verify_date == 0 {
            f.verify_corrupt_md4.clear();
            f.verify_corrupt_aich.clear();
        }
        Ok(f)
    }

    /// The record `WriteToFile` writes for this file, tag for tag.
    pub fn to_record(&self) -> KnownRecord {
        let id = |t: FileTag| TagName::Id(t.value());
        let u32t = |t: FileTag, v: u32| Tag::new(id(t), TagValue::U32(v));
        let mut tags = vec![
            // Written twice: the name, then its universal form. aMule meant
            // the first to carry a BOM, but its file writer ignores that.
            Tag::new(id(FileTag::Filename), TagValue::String(self.name.clone())),
            Tag::new(id(FileTag::Filename), TagValue::String(to_univ(&self.name))),
            Tag::new(
                id(FileTag::Filesize),
                if self.size > OLD_MAX_FILE_SIZE {
                    TagValue::U64(self.size)
                } else {
                    TagValue::U32(self.size as u32)
                },
            ),
            u32t(FileTag::AtTransferred, self.all_time_transferred as u32),
            u32t(
                FileTag::AtTransferredHi,
                (self.all_time_transferred >> 32) as u32,
            ),
            u32t(FileTag::AtRequested, self.all_time_requests),
            u32t(FileTag::AtAccepted, self.all_time_accepts),
            u32t(
                FileTag::UlPriority,
                if self.auto_priority {
                    priority::AUTO
                } else {
                    self.up_priority
                },
            ),
            u32t(FileTag::LastSeen, self.last_seen),
        ];
        if let Some(a) = &self.aich_hash {
            tags.push(Tag::new(id(FileTag::AichHash), TagValue::String(a.clone())));
        }
        for (t, v) in [
            (FileTag::KadLastPublishSrc, self.kad_last_publish_src),
            (FileTag::KadLastPublishNotes, self.kad_last_publish_notes),
            (FileTag::LastUploaded, self.last_uploaded),
            (FileTag::SharedSince, self.shared_since),
        ] {
            if v != 0 {
                tags.push(u32t(t, v));
            }
        }
        if self.verify_date != 0 {
            tags.push(u32t(FileTag::VerifyDate, self.verify_date));
            for (t, v) in [
                (FileTag::VerifyCorruptMd4, &self.verify_corrupt_md4),
                (FileTag::VerifyCorruptAich, &self.verify_corrupt_aich),
            ] {
                if !v.is_empty() {
                    tags.push(Tag::new(id(t), TagValue::String(v.clone())));
                }
            }
        }
        // Other tags: integers and strings only (floats are left out for old eMules).
        tags.extend(
            self.other_tags
                .iter()
                .filter(|t| t.as_int().is_some() || t.as_str().is_some())
                .cloned(),
        );
        KnownRecord {
            date: self.date,
            hash: self.hash,
            part_hashes: self.part_hashes.clone(),
            tags,
        }
    }
}

#[cfg(test)]
mod tests;
