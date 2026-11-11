// SPDX-License-Identifier: GPL-2.0-or-later
//! `known2_64.met`: stored AICH hash sets (a root hash and its block hashes).
//!
//! Port of `CAICHHashSet::SaveHashSet` / `LoadHashSet` /
//! `LoadRootHashCacheLocked` (SHAHashSet.cpp), `CAICHSyncTask::Entry` and
//! `ConvertToKnown2ToKnown264` (ThreadTasks.cpp), and the orphan prune fed by
//! `CKnownFileList::CollectLiveAICHRoots`.
//!
//! Layout: a version byte (`KNOWN2_MET_VERSION`, `0x02`), then entries, to the
//! end of the file:
//!
//! ```text
//! 20-byte AICH root hash | u32 n | n × 20-byte block hash
//! ```
//!
//! The block hashes are the lowest level of the AICH tree, left to right, one
//! per 180 KB block (`EMBLOCKSIZE`); their count follows from the file size
//! ([`block_hash_count`]). There are no tags, so the stored structure is the
//! typed view and every readable file writes back byte for byte.
//!
//! aMule appends one entry per newly hashed file, skipping a root hash already
//! present ([`Known2Met::append`]); a lookup takes the first entry with the root
//! ([`Known2Met::find`]). At startup an entry running past the end of the file
//! makes aMule truncate the file after the last complete entry
//! ([`Error::valid_len`]), and entries whose root no `known.met` record still
//! names are pruned ([`Known2Met::prune_orphans`]).
//!
//! Not here: checking that the block hashes rebuild the root hash, which needs
//! the AICH tree (phase 3).
//!
//! Deliberate differences from aMule, both where it loses data:
//! * [`convert_old_known2`] reads the old `known2.met` to its end. aMule's
//!   loop compares the *new* file's position with the *old* file's length; each
//!   converted entry is 2 bytes longer, so trailing entries can be dropped.
//! * Positions are `u64`. aMule keeps the recovery truncation point in a
//!   `uint32`, which wraps for a file over 4 GiB.

use std::collections::HashSet;
use std::fmt;

use ed2k_codec::{Reader, Writer};
use ed2k_types::ed2k::{EMBLOCKSIZE, PARTSIZE};

/// `KNOWN2_MET_FILENAME`
pub const FILE_NAME: &str = "known2_64.met";
/// `OLD_KNOWN2_MET_FILENAME`: the pre-large-file format, see [`convert_old_known2`].
pub const OLD_FILE_NAME: &str = "known2.met";
/// `KNOWN2_MET_VERSION`
pub const VERSION: u8 = 0x02;
/// `CAICHHash::HASHSIZE`: an AICH hash is a SHA-1 digest.
pub use ed2k_types::aich::HASH_LEN;

pub use ed2k_types::aich::{AichHash, ParseAichHashError};

/// How many block hashes a file of `size` bytes has (the `nHashCount` of
/// `SaveHashSet` / `LoadHashSet`): ⌈PARTSIZE / EMBLOCKSIZE⌉ = 53 per full
/// part, plus one per started block of the last part.
pub const fn block_hash_count(size: u64) -> u64 {
    let bs = EMBLOCKSIZE as u64;
    let per_part = PARTSIZE.div_ceil(bs);
    per_part * (size / PARTSIZE) + (size % PARTSIZE).div_ceil(bs)
}

/// One stored hash set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AichHashSet {
    pub root: AichHash,
    /// The lowest-level hashes of the AICH tree, left to right.
    pub block_hashes: Vec<AichHash>,
}

impl AichHashSet {
    /// `LoadHashSet`'s count check: the set has as many block hashes as a
    /// file of `size` bytes needs.
    pub fn fits_size(&self, size: u64) -> bool {
        self.block_hashes.len() as u64 == block_hash_count(size)
    }
}

/// A whole `known2_64.met`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Known2Met {
    /// In file order. A root hash may appear more than once in a file that
    /// was edited by hand; [`Known2Met::find`] takes the first, as aMule does.
    pub sets: Vec<AichHashSet>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The first byte is not [`VERSION`]. aMule's startup sync truncates
    /// such a file to nothing.
    BadVersion(u8),
    /// An entry runs past the end of the file.
    Truncated,
}

/// A file that does not read to its end.
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// The complete entries before the problem.
    pub salvaged: Vec<AichHashSet>,
    /// Where aMule's startup sync cuts the file: after the last complete
    /// entry, or 0 (header included) when there is none.
    pub valid_len: u64,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::BadVersion(v) => write!(f, "known2_64.met has an invalid header {v:#04x}")?,
            ErrorKind::Truncated => f.write_str("known2_64.met ends inside an entry")?,
        }
        write!(
            f,
            " ({} hash sets salvaged, valid up to byte {})",
            self.salvaged.len(),
            self.valid_len
        )
    }
}

impl std::error::Error for Error {}

/// Read entries of root, count (`u16` or `u32`) and block hashes until the
/// data ends. The count is checked against the data left before anything is
/// allocated for it.
fn read_entries(
    r: &mut Reader<'_>,
    wide_count: bool,
    valid_len: &mut u64,
) -> Result<Vec<AichHashSet>, Vec<AichHashSet>> {
    let mut sets = Vec::new();
    while !r.is_eof() {
        let Ok(root) = r.array::<HASH_LEN>() else {
            return Err(sets);
        };
        let count = if wide_count {
            r.u32().map(u64::from)
        } else {
            r.u16().map(u64::from)
        };
        let Ok(count) = count else { return Err(sets) };
        if count * HASH_LEN as u64 > r.remaining() as u64 {
            return Err(sets);
        }
        let mut block_hashes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            // Cannot fail: the length was checked above.
            let Ok(h) = r.array::<HASH_LEN>() else {
                return Err(sets);
            };
            block_hashes.push(AichHash(h));
        }
        sets.push(AichHashSet {
            root: AichHash(root),
            block_hashes,
        });
        *valid_len = r.position() as u64;
    }
    Ok(sets)
}

impl Known2Met {
    /// Parse a whole file, as the startup sync walks it. An empty file is an
    /// empty list (aMule writes the header on its first append).
    pub fn read(bytes: &[u8]) -> Result<Known2Met, Error> {
        if bytes.is_empty() {
            return Ok(Known2Met::default());
        }
        if bytes[0] != VERSION {
            return Err(Error {
                kind: ErrorKind::BadVersion(bytes[0]),
                salvaged: Vec::new(),
                valid_len: 0,
            });
        }
        let mut r = Reader::new(&bytes[1..]);
        let mut valid = 0u64;
        match read_entries(&mut r, true, &mut valid) {
            Ok(sets) => Ok(Known2Met { sets }),
            Err(salvaged) => Err(Error {
                kind: ErrorKind::Truncated,
                // `valid` counts from after the header; aMule leaves its
                // truncation point at 0 until an entry has been verified.
                valid_len: if salvaged.is_empty() { 0 } else { valid + 1 },
                salvaged,
            }),
        }
    }

    /// Serialise: the version byte, then every entry.
    pub fn write(&self) -> Vec<u8> {
        let n: usize = self
            .sets
            .iter()
            .map(|s| HASH_LEN + 4 + s.block_hashes.len() * HASH_LEN)
            .sum();
        let mut w = Writer::with_capacity(1 + n);
        w.u8(VERSION);
        for s in &self.sets {
            write_entry(&mut w, s);
        }
        w.into_bytes()
    }

    /// The first entry with this root hash (`LoadHashSet`'s scan, and the
    /// first-wins offset cache).
    pub fn find(&self, root: &AichHash) -> Option<&AichHashSet> {
        self.sets.iter().find(|s| s.root == *root)
    }

    /// `SaveHashSet`: append unless the root hash is already stored. Returns
    /// whether it was appended.
    pub fn append(&mut self, set: AichHashSet) -> bool {
        if self.find(&set.root).is_some() {
            return false;
        }
        self.sets.push(set);
        true
    }

    /// The bytes `SaveHashSet` appends for one entry (it never rewrites the
    /// file to add one).
    pub fn entry_bytes(set: &AichHashSet) -> Vec<u8> {
        let mut w = Writer::with_capacity(HASH_LEN + 4 + set.block_hashes.len() * HASH_LEN);
        write_entry(&mut w, set);
        w.into_bytes()
    }

    /// The startup orphan prune: drop entries whose root is not in `live`
    /// (the AICH roots of `known.met`, `CollectLiveAICHRoots`). An empty set
    /// prunes nothing, so a file is never wiped before the known files are
    /// loaded. Returns how many entries were dropped.
    pub fn prune_orphans(&mut self, live: &HashSet<AichHash>) -> usize {
        if live.is_empty() {
            return 0;
        }
        let before = self.sets.len();
        self.sets.retain(|s| live.contains(&s.root));
        before - self.sets.len()
    }
}

fn write_entry(w: &mut Writer, s: &AichHashSet) {
    w.bytes(&s.root.0).u32(s.block_hashes.len() as u32);
    for h in &s.block_hashes {
        w.bytes(&h.0);
    }
}

/// `ConvertToKnown2ToKnown264`: read the old `known2.met` (no version byte,
/// `u16` counts) into the current format. Unlike aMule, every entry is
/// converted (see the module docs). On damage, the error holds the entries
/// before it, which aMule has already written to the new file by then.
pub fn convert_old_known2(bytes: &[u8]) -> Result<Known2Met, Error> {
    let mut r = Reader::new(bytes);
    let mut valid = 0u64;
    match read_entries(&mut r, false, &mut valid) {
        Ok(sets) => Ok(Known2Met { sets }),
        Err(salvaged) => Err(Error {
            kind: ErrorKind::Truncated,
            salvaged,
            valid_len: valid,
        }),
    }
}

#[cfg(test)]
mod tests;
