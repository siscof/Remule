// SPDX-License-Identifier: GPL-2.0-or-later
//! `.part.met`: the state of a download in progress (and its `.part.met.bak`
//! backup, which has the same format).
//!
//! Port of `CPartFile::LoadPartFile` / `SavePartFile` (PartFile.cpp) and the
//! pure parts of `PartMetWriter.{h,cpp}`: the `.part` mtime patched into the
//! header ([`patch_mtime`]) and when a save is due ([`save_due`]). Writing
//! the file (`.tmp`, `.bak`, atomic install) and the writer thread are
//! runtime I/O and belong to the daemon.
//!
//! aMule's own layout, which it always writes:
//!
//! ```text
//! u8 version (0xE0, or 0xE2 for files over 4 GB) | u32 date (the .part's mtime)
//! | MD4 file hash | u16 n | n × MD4 part hash | u32 m | m × eD2k tag
//! ```
//!
//! Gaps (missing ranges) are tags named `0x09<n>` (start) and `0x0A<n>`
//! (end, exclusive) with `<n>` a decimal index. Two import layouts are also
//! read: eDonkey's (version `0xE1`, or `0xE0` with `00 00 02 01` at offset
//! 24), whose part hashes follow the tags.
//!
//! [`PartMet`] keeps the file as stored, so a file aMule wrote is written back
//! byte for byte; [`PartFile`] is the typed view `LoadPartFile` builds.

use std::fmt;

use ed2k_codec::{Reader, SeekFrom, Tag, TagError, TagName, TagValue, Writer};
use ed2k_types::ed2k::{OLD_MAX_FILE_SIZE, PARTSIZE};
use ed2k_types::tags::FileTag;
use ed2k_types::Md4Hash;

use crate::known_met::{hash_of_part_hashes, part_hash_count};

/// `PARTFILE_VERSION`
pub const VERSION: u8 = 0xE0;
/// `PARTFILE_SPLITTEDVERSION`: eDonkey part files, for importing.
pub const VERSION_SPLITTED: u8 = 0xE1;
/// `PARTFILE_VERSION_LARGEFILE`: written when the file is over 4 GB.
pub const VERSION_LARGE_FILE: u8 = 0xE2;

/// Which layout the file was read in (`PMT_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `PMT_DEFAULTOLD`: aMule's and eMule's own.
    Amule,
    /// `PMT_NEWOLD`: version 0xE0 with eDonkey's "old part style" marker.
    EdonkeyOld,
    /// `PMT_SPLITTED`: version 0xE1.
    Splitted,
}

/// A whole `.part.met` as stored.
#[derive(Clone, Debug, PartialEq)]
pub struct PartMet {
    pub version: u8,
    pub layout: Layout,
    /// The `.part` file's mtime when the met was written.
    pub date: u32,
    pub hash: Md4Hash,
    /// The part hashes in the header (empty for eDonkey layouts, except the
    /// 0.48 variant).
    pub part_hashes: Vec<Md4Hash>,
    pub tags: Vec<Tag>,
    /// eDonkey layouts: the part hashes after the tags, when present.
    pub trailing_hashes: Option<Vec<Md4Hash>>,
    /// The file ended early, after the size was known, and was recovered as
    /// far as it was read (aMule's "wrong tagcount" recovery).
    pub truncated: bool,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// A 0-byte file.
    Empty,
    /// Not one of the three part.met versions.
    BadVersion(u8),
    /// A tag aMule cannot read ("bad tags").
    Tag(TagError),
    /// A known tag of the wrong type (`GetInt`/`GetStr` throw).
    WrongType(FileTag),
    /// The file ends before its size is known, so nothing can be recovered.
    Truncated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Empty => f.write_str("part.met file is 0 size"),
            Error::BadVersion(v) => write!(f, "invalid part.met file version {v:#04x}"),
            Error::Tag(e) => write!(f, "part.met is corrupt (bad tags: {e})"),
            Error::WrongType(t) => write!(f, "part.met tag {t:?} has the wrong type"),
            Error::Truncated => {
                f.write_str("part.met is corrupt (wrong tagcount), unable to load file")
            }
        }
    }
}

impl std::error::Error for Error {}

fn is_eof(e: &TagError) -> bool {
    matches!(e, TagError::Io(ed2k_codec::Error::Eof { .. }))
}

fn read_hashes(r: &mut Reader<'_>, n: usize) -> Result<Vec<Md4Hash>, ed2k_codec::Error> {
    let mut v = Vec::with_capacity(n.min(r.remaining() / 16));
    for _ in 0..n {
        v.push(r.hash()?);
    }
    Ok(v)
}

/// Parts in a file (`GetPartCount`): none for an empty file, else full parts
/// plus a last, partial one, which an exact multiple does not have.
pub const fn part_count(size: u64) -> u64 {
    if size == 0 {
        0
    } else {
        size.div_ceil(PARTSIZE)
    }
}

impl PartMet {
    /// `LoadPartFile`, as far as the met file goes.
    pub fn read(bytes: &[u8]) -> Result<PartMet, Error> {
        if bytes.is_empty() {
            return Err(Error::Empty);
        }
        let mut r = Reader::new(bytes);
        let version = r.u8().map_err(|_| Error::Empty)?;
        if version != VERSION && version != VERSION_SPLITTED && version != VERSION_LARGE_FILE {
            return Err(Error::BadVersion(version));
        }
        let mut layout = if version == VERSION_SPLITTED {
            Layout::Splitted
        } else {
            Layout::Amule
        };
        if version == VERSION {
            // eDonkey's "old part style": 00 00 02 01 at offset 24. The C++
            // reads it unconditionally, so a file shorter than 28 bytes fails.
            match bytes.get(24..28) {
                Some([0, 0, 2, 1]) => layout = Layout::EdonkeyOld,
                Some(_) => {}
                None => return Err(Error::Truncated),
            }
        }
        let new_style = layout != Layout::Amule;
        let header =
            |r: &mut Reader<'_>| -> Result<(u32, Md4Hash, Vec<Md4Hash>), ed2k_codec::Error> {
                if new_style {
                    let temp = r.u32()?;
                    if temp == 0 {
                        // 0.48 part.mets: a hash set follows the zero date.
                        let hash = r.hash()?;
                        let n = r.u16()?;
                        Ok((0, hash, read_hashes(r, n.into())?))
                    } else {
                        r.seek(SeekFrom::Start(2))?;
                        let date = r.u32()?;
                        Ok((date, r.hash()?, Vec::new()))
                    }
                } else {
                    let date = r.u32()?;
                    let hash = r.hash()?;
                    let n = r.u16()?;
                    Ok((date, hash, read_hashes(r, n.into())?))
                }
            };
        let (date, hash, part_hashes) = header(&mut r).map_err(|_| Error::Truncated)?;
        let mut met = PartMet {
            version,
            layout,
            date,
            hash,
            part_hashes,
            tags: Vec::new(),
            trailing_hashes: None,
            truncated: false,
        };

        let tag_count = match r.u32() {
            Ok(n) => n,
            Err(_) => return Err(Error::Truncated),
        };
        for _ in 0..tag_count {
            match Tag::read_ed2k(&mut r, true, false) {
                Ok(t) => met.tags.push(t),
                Err(e) if is_eof(&e) => {
                    // Recover what was read, if the size is known.
                    let file = PartFile::from_met(&met).map_err(Error::WrongType)?;
                    if file.size == 0 {
                        return Err(Error::Truncated);
                    }
                    met.truncated = true;
                    return Ok(met);
                }
                Err(e) => return Err(Error::Tag(e)),
            }
        }
        // Reject wrong-typed tags now, as the C++ does while reading them.
        let file = PartFile::from_met(&met).map_err(Error::WrongType)?;

        if new_style && !r.is_eof() {
            // One byte, then up to one hash per part while more than 16 bytes are left.
            r.seek(SeekFrom::Current(1)).ok();
            let parts = part_count(file.size) as u16;
            let mut hashes = Vec::new();
            for _ in 0..parts {
                if r.position() + 16 >= r.len() {
                    break;
                }
                match r.hash() {
                    Ok(h) => hashes.push(h),
                    Err(_) => break,
                }
            }
            met.trailing_hashes = Some(hashes);
        }
        Ok(met)
    }

    /// Serialise. aMule's layout is written as stored, byte for byte; an
    /// imported eDonkey file is written in aMule's layout, as aMule's next
    /// save would.
    pub fn write(&self) -> Vec<u8> {
        if self.layout != Layout::Amule {
            return match PartFile::from_met(self) {
                Ok(f) => f.to_met().write(),
                Err(_) => Vec::new(),
            };
        }
        let mut w = Writer::new();
        w.u8(self.version)
            .u32(self.date)
            .hash(self.hash)
            .u16(self.part_hashes.len() as u16);
        for h in &self.part_hashes {
            w.hash(*h);
        }
        let tags: Vec<&Tag> = self.tags.iter().filter(|t| t.can_write_to_file()).collect();
        w.u32(tags.len() as u32);
        for t in tags {
            t.write_kad(&mut w).expect("a file tag is writable");
        }
        w.into_bytes()
    }
}

/// Download and upload priorities (`PR_*`).
pub mod priority {
    pub const LOW: u32 = 0;
    pub const NORMAL: u32 = 1;
    pub const HIGH: u32 = 2;
    pub const AUTO: u32 = 5;
}

/// What aMule knows about a download from its met (`CPartFile` after `LoadPartFile`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PartFile {
    pub date: u32,
    pub hash: Md4Hash,
    /// The part hashes aMule accepts; empty if they do not check out. If
    /// there are fewer than [`part_hash_count`] needs, aMule asks peers for them.
    pub part_hashes: Vec<Md4Hash>,
    pub name: String,
    pub size: u64,
    /// Bytes downloaded, as counted by aMule (compressed transfers and
    /// corruption make it differ from what the gaps say).
    pub transferred: u64,
    pub paused: bool,
    /// `LOW`, `NORMAL` or `HIGH`; [`PartFile::auto_down_priority`] for auto.
    pub down_priority: u32,
    pub auto_down_priority: bool,
    pub up_priority: u32,
    pub auto_up_priority: bool,
    /// As stored. aMule resets it to 0 if no such category exists.
    pub category: u32,
    pub last_seen_complete: u32,
    pub kad_last_publish_src: u32,
    pub kad_last_publish_notes: u32,
    pub dl_active_time: u32,
    pub corrupted_parts: Vec<u16>,
    pub aich_hash: Option<String>,
    pub all_time_transferred: u64,
    pub all_time_requests: u32,
    pub all_time_accepts: u32,
    /// Missing byte ranges, inclusive, sorted and merged.
    pub gaps: Vec<(u64, u64)>,
    /// Tags aMule keeps without interpreting.
    pub other_tags: Vec<Tag>,
}

fn is_aich_base32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
}

/// A gap tag's kind and index: a name of `0x09` or `0x0A` followed by a
/// decimal number (`newtag.GetName().Mid(1).ToULong`). The index is kept to
/// 16 bits, as aMule's gap map does.
fn gap_key(name: &TagName) -> Option<(u8, u16)> {
    let TagName::Str(s) = name else { return None };
    let (&mark, digits) = s.split_first()?;
    if (mark != FileTag::GapStart.value() && mark != FileTag::GapEnd.value()) || digits.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(digits).ok()?;
    let n: u64 = text.trim_start().parse().ok()?;
    Some((mark, n as u16))
}

/// Merge gaps the way `CGapList::AddGap` does: overlapping and adjacent
/// ranges join.
fn merge_gaps(mut gaps: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    gaps.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(gaps.len());
    for (s, e) in gaps {
        match out.last_mut() {
            Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

impl PartFile {
    /// `LoadPartFile`'s tag handling. A known tag aMule reads with the wrong
    /// type is an error, as the C++ `GetInt`/`GetStr` throw.
    ///
    /// One deliberate difference, as in `known_met`: eMule's
    /// `FT_FILESIZE_HI` is combined with `FT_FILESIZE`; aMule ignores it.
    pub fn from_met(met: &PartMet) -> Result<PartFile, FileTag> {
        let new_style = met.layout != Layout::Amule;
        let mut f = PartFile {
            date: met.date,
            hash: met.hash,
            down_priority: priority::NORMAL,
            up_priority: priority::NORMAL,
            ..Default::default()
        };
        let mut size_hi = 0u64;
        let mut gap_map: std::collections::BTreeMap<u16, (u64, u64)> = Default::default();
        let mut corrupted_text: Option<String> = None;
        for t in &met.tags {
            let id = match &t.name {
                TagName::Id(id) => FileTag::try_from(*id).ok(),
                TagName::Str(s) if s.len() == 1 => FileTag::try_from(s[0]).ok(),
                TagName::Str(_) => None,
            };
            let int = |id| t.as_int().ok_or(id);
            let string = |id| t.as_str().map(str::to_owned).ok_or(id);
            match id {
                Some(FileTag::Filename) => {
                    // The first non-empty name wins.
                    if f.name.is_empty() {
                        f.name = string(FileTag::Filename)?;
                    }
                }
                Some(FileTag::LastSeenComplete) => {
                    f.last_seen_complete = int(FileTag::LastSeenComplete)? as u32
                }
                Some(FileTag::Filesize) => f.size = int(FileTag::Filesize)?,
                Some(FileTag::FilesizeHi) => size_hi = int(FileTag::FilesizeHi)?,
                Some(FileTag::Transferred) => f.transferred = int(FileTag::Transferred)?,
                Some(FileTag::Filetype) => {}
                Some(FileTag::Category) => f.category = int(FileTag::Category)? as u32,
                Some(tag @ (FileTag::OldDlPriority | FileTag::DlPriority)) => {
                    if !new_style {
                        let p = int(tag)? as u32;
                        if p == priority::AUTO {
                            f.down_priority = priority::HIGH;
                            f.auto_down_priority = true;
                        } else {
                            f.down_priority = if p <= priority::HIGH {
                                p
                            } else {
                                priority::NORMAL
                            };
                            f.auto_down_priority = false;
                        }
                    }
                }
                Some(FileTag::Status) => f.paused = int(FileTag::Status)? == 1,
                Some(tag @ (FileTag::OldUlPriority | FileTag::UlPriority)) => {
                    if !new_style {
                        let p = int(tag)? as u32;
                        if p == priority::AUTO {
                            f.up_priority = priority::HIGH;
                            f.auto_up_priority = true;
                        } else {
                            f.up_priority = p;
                            f.auto_up_priority = false;
                        }
                    }
                }
                Some(FileTag::KadLastPublishSrc) => {
                    f.kad_last_publish_src = int(FileTag::KadLastPublishSrc)? as u32
                }
                Some(FileTag::KadLastPublishNotes) => {
                    f.kad_last_publish_notes = int(FileTag::KadLastPublishNotes)? as u32
                }
                // Old tags: purged.
                Some(FileTag::Permissions | FileTag::KadLastPublishKey | FileTag::PartFilename) => {
                }
                Some(FileTag::DlActiveTime) => {
                    if let Some(v) = t.as_int() {
                        f.dl_active_time = v as u32;
                    }
                }
                Some(FileTag::CorruptedParts) => {
                    corrupted_text = Some(string(FileTag::CorruptedParts)?)
                }
                Some(FileTag::AichHash) => {
                    let s = string(FileTag::AichHash)?;
                    if is_aich_base32(&s) {
                        f.aich_hash = Some(s);
                    }
                }
                Some(FileTag::AtTransferred) => {
                    f.all_time_transferred += int(FileTag::AtTransferred)?
                }
                Some(FileTag::AtTransferredHi) => {
                    f.all_time_transferred += int(FileTag::AtTransferredHi)? << 32
                }
                Some(FileTag::AtRequested) => {
                    f.all_time_requests = int(FileTag::AtRequested)? as u32
                }
                Some(FileTag::AtAccepted) => f.all_time_accepts = int(FileTag::AtAccepted)? as u32,
                _ => match (gap_key(&t.name), t.as_int()) {
                    (Some((mark, key)), Some(v)) => {
                        let g = gap_map.entry(key).or_insert((u64::MAX, u64::MAX));
                        if mark == FileTag::GapStart.value() {
                            g.0 = v;
                        } else {
                            g.1 = v.wrapping_sub(1);
                        }
                    }
                    _ => {
                        if t.can_write_to_file() {
                            f.other_tags.push(t.clone());
                        }
                    }
                },
            }
        }
        f.size |= size_hi << 32;

        let parts = part_count(f.size);
        if let Some(text) = corrupted_text {
            for token in text.split(',').filter(|s| !s.is_empty()) {
                if let Ok(p) = token.trim_start().parse::<u64>() {
                    if p < parts && !f.corrupted_parts.contains(&(p as u16)) {
                        f.corrupted_parts.push(p as u16);
                    }
                }
            }
        }

        // Gaps: complete pairs inside the file, clipped to its end.
        let mut gaps = Vec::new();
        for (_, (start, mut end)) in gap_map {
            if start != u64::MAX && end != u64::MAX && start <= end && start < f.size {
                if end >= f.size {
                    end = f.size - 1;
                }
                gaps.push((start, end));
            }
        }
        f.gaps = merge_gaps(gaps);

        // Hash sets (LoadHashsetFromFile, then the eDonkey trailing block).
        let header_ok =
            met.part_hashes.len() <= 1 || hash_of_part_hashes(&met.part_hashes) == met.hash;
        let mut hashes = if header_ok {
            met.part_hashes.clone()
        } else {
            Vec::new()
        };
        if let Some(trailing) = &met.trailing_hashes {
            hashes.extend_from_slice(trailing);
            let check = if hashes.is_empty() {
                Md4Hash::EMPTY
            } else {
                hash_of_part_hashes(&hashes)
            };
            if check != met.hash {
                hashes.clear();
            }
        }
        f.part_hashes = hashes;
        Ok(f)
    }

    /// Bytes still missing.
    pub fn missing(&self) -> u64 {
        self.gaps.iter().map(|(s, e)| e - s + 1).sum()
    }

    /// Bytes present (`completedsize`).
    pub fn completed(&self) -> u64 {
        self.size - self.missing().min(self.size)
    }

    /// Whether every part hash is known (else aMule asks peers: `m_hashsetneeded`).
    pub fn has_hashset(&self) -> bool {
        self.part_hashes.len() == part_hash_count(self.size)
    }

    pub fn is_large(&self) -> bool {
        self.size > OLD_MAX_FILE_SIZE
    }

    /// The met `SavePartFile` writes, tag for tag.
    pub fn to_met(&self) -> PartMet {
        let large = self.is_large();
        let id = |t: FileTag| TagName::Id(t.value());
        let u32t = |t: FileTag, v: u32| Tag::new(id(t), TagValue::U32(v));
        let sized = |v: u64| {
            if large {
                TagValue::U64(v)
            } else {
                TagValue::U32(v as u32)
            }
        };
        let down = if self.auto_down_priority {
            priority::AUTO
        } else {
            self.down_priority
        };
        let up = if self.auto_up_priority {
            priority::AUTO
        } else {
            self.up_priority
        };
        let mut tags = vec![
            // Written twice; aMule meant the first with a BOM, but its file
            // writer ignores the encoding.
            Tag::new(id(FileTag::Filename), TagValue::String(self.name.clone())),
            Tag::new(id(FileTag::Filename), TagValue::String(self.name.clone())),
            Tag::new(id(FileTag::Filesize), sized(self.size)),
            Tag::new(id(FileTag::Transferred), sized(self.transferred)),
            u32t(FileTag::Status, u32::from(self.paused)),
            u32t(FileTag::DlPriority, down),
            u32t(FileTag::OldDlPriority, down),
            u32t(FileTag::LastSeenComplete, self.last_seen_complete),
            u32t(FileTag::UlPriority, up),
            u32t(FileTag::OldUlPriority, up),
            u32t(FileTag::Category, self.category),
            u32t(FileTag::AtTransferred, self.all_time_transferred as u32),
            u32t(
                FileTag::AtTransferredHi,
                (self.all_time_transferred >> 32) as u32,
            ),
            u32t(FileTag::AtRequested, self.all_time_requests),
            u32t(FileTag::AtAccepted, self.all_time_accepts),
        ];
        if !self.corrupted_parts.is_empty() {
            let s = self
                .corrupted_parts
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            tags.push(Tag::new(id(FileTag::CorruptedParts), TagValue::String(s)));
        }
        if let Some(a) = &self.aich_hash {
            tags.push(Tag::new(id(FileTag::AichHash), TagValue::String(a.clone())));
        }
        for (t, v) in [
            (FileTag::KadLastPublishSrc, self.kad_last_publish_src),
            (FileTag::KadLastPublishNotes, self.kad_last_publish_notes),
            (FileTag::DlActiveTime, self.dl_active_time),
        ] {
            if v != 0 {
                tags.push(u32t(t, v));
            }
        }
        tags.extend(
            self.other_tags
                .iter()
                .filter(|t| t.can_write_to_file())
                .cloned(),
        );
        for (i, &(start, end)) in self.gaps.iter().enumerate() {
            let name = |mark: FileTag| {
                let mut n = vec![mark.value()];
                n.extend_from_slice(i.to_string().as_bytes());
                TagName::Str(n)
            };
            tags.push(Tag::new(name(FileTag::GapStart), sized(start)));
            tags.push(Tag::new(name(FileTag::GapEnd), sized(end + 1)));
        }
        PartMet {
            version: if large { VERSION_LARGE_FILE } else { VERSION },
            layout: Layout::Amule,
            date: self.date,
            hash: self.hash,
            part_hashes: self.part_hashes.clone(),
            tags,
            trailing_hashes: None,
            truncated: false,
        }
    }
}

/// `WritePartMet`'s header patch: the `.part`'s mtime, little-endian, goes
/// into bytes 1..5 of a serialised met. Fails on content shorter than 5
/// bytes ("Incomplete part.met header").
pub fn patch_mtime(content: &mut [u8], mtime: u32) -> Result<(), IncompleteHeader> {
    let slot = content.get_mut(1..5).ok_or(IncompleteHeader)?;
    slot.copy_from_slice(&mtime.to_le_bytes());
    Ok(())
}

/// A met shorter than its 5-byte header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncompleteHeader;

/// The change counts a save was serialised at (`CPartMetGen`): changes to
/// the download's state and to its upload statistics are counted apart, so a
/// save clears only what it carried.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SaveGen {
    pub met: u64,
    pub stats: u64,
}

/// `PartMetSaveDue`: a state change is saved unless a save carrying it is on
/// its way; statistics alone wait for the heartbeat and for no save to be on
/// its way, as every save carries them.
pub fn save_due(
    current: SaveGen,
    saved: SaveGen,
    pending: Option<SaveGen>,
    heartbeat_due: bool,
) -> bool {
    if current.met != saved.met {
        return pending.is_none_or(|p| p.met != current.met);
    }
    current.stats != saved.stats && heartbeat_due && pending.is_none()
}

#[cfg(test)]
mod tests;
