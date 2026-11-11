// SPDX-License-Identifier: GPL-2.0-or-later
//! `canceled.met`: the hashes of downloads the user cancelled, so search
//! results can mark them. The same format holds `knownhistory.met`, the
//! hashes of files `known.met` no longer remembers.
//!
//! Port of `CHashListFile` (HashListFile.{h,cpp}), which serves both files.
//!
//! Layout: a version byte (`CANCELEDFILE_VERSION` `0x21`), a `u32` count,
//! then that many 16-byte MD4 hashes. aMule keeps the hashes in a
//! `std::set`, so it writes them sorted and without duplicates, and it drops
//! all-zero hashes when loading.
//!
//! [`CanceledMet`] keeps the hashes exactly as stored (order, duplicates and
//! empty hashes included), so any file writes back byte for byte;
//! [`CanceledMet::set`] is the set aMule builds from it.

use std::collections::BTreeSet;
use std::fmt;

use ed2k_codec::{Reader, Writer};
use ed2k_types::Md4Hash;

/// `CANCELEDFILE_VERSION`
pub const VERSION: u8 = 0x21;

/// The file name of the cancelled-downloads list.
pub const FILE_NAME: &str = "canceled.met";
/// The file name of the known-file history, which uses the same format.
pub const HISTORY_FILE_NAME: &str = "knownhistory.met";

/// A whole `canceled.met` (or `knownhistory.met`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanceledMet {
    pub version: u8,
    /// The hashes in file order, as stored.
    pub hashes: Vec<Md4Hash>,
    /// Bytes after the declared hashes. aMule ignores them; they are kept so
    /// the file writes back unchanged.
    pub trailing: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The version byte is not `0x21` (aMule: "might be corrupted").
    BadVersion(u8),
    /// The file ends before its header or before the declared hashes.
    Truncated,
}

/// A file that cannot be read in full. Like aMule, which inserts each hash
/// as it reads it, the non-empty hashes read before the problem are kept.
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub salvaged: BTreeSet<Md4Hash>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::BadVersion(v) => write!(f, "hash list has an invalid version {v:#04x}")?,
            ErrorKind::Truncated => f.write_str("hash list is truncated")?,
        }
        write!(f, " ({} hashes salvaged)", self.salvaged.len())
    }
}

impl std::error::Error for Error {}

impl CanceledMet {
    /// Parse a whole file (`CHashListFile::Init`).
    pub fn read(bytes: &[u8]) -> Result<CanceledMet, Error> {
        let mut r = Reader::new(bytes);
        let truncated = |salvaged| Error {
            kind: ErrorKind::Truncated,
            salvaged,
        };
        let version = r.u8().map_err(|_| truncated(BTreeSet::new()))?;
        if version != VERSION {
            return Err(Error {
                kind: ErrorKind::BadVersion(version),
                salvaged: BTreeSet::new(),
            });
        }
        let count = r.u32().map_err(|_| truncated(BTreeSet::new()))?;
        // Capacity from the data present, never from the declared count.
        let mut hashes = Vec::with_capacity((count as usize).min(r.remaining() / Md4Hash::LEN));
        for _ in 0..count {
            match r.hash() {
                Ok(h) => hashes.push(h),
                Err(_) => return Err(truncated(to_set(&hashes))),
            }
        }
        Ok(CanceledMet {
            version,
            hashes,
            trailing: r.rest().to_vec(),
        })
    }

    /// Serialise exactly what is stored (`Save` writes the same layout).
    pub fn write(&self) -> Vec<u8> {
        let mut w =
            Writer::with_capacity(5 + self.hashes.len() * Md4Hash::LEN + self.trailing.len());
        w.u8(self.version).u32(self.hashes.len() as u32);
        for h in &self.hashes {
            w.hash(*h);
        }
        w.bytes(&self.trailing);
        w.into_bytes()
    }

    /// The set aMule loads: every hash except the all-zero one, deduplicated.
    pub fn set(&self) -> BTreeSet<Md4Hash> {
        to_set(&self.hashes)
    }

    /// The file `CHashListFile::Save` writes for a set: version `0x21`, the
    /// hashes in sorted order (the order of `std::set<CMD4Hash>`, which is
    /// byte-wise, as `Md4Hash`'s `Ord`).
    pub fn from_set(set: &BTreeSet<Md4Hash>) -> CanceledMet {
        CanceledMet {
            version: VERSION,
            hashes: set.iter().copied().collect(),
            trailing: Vec::new(),
        }
    }

    /// `Contains`: the empty hash is never contained.
    pub fn contains(&self, hash: &Md4Hash) -> bool {
        !hash.is_empty() && self.hashes.contains(hash)
    }
}

fn to_set(hashes: &[Md4Hash]) -> BTreeSet<Md4Hash> {
    hashes.iter().filter(|h| !h.is_empty()).copied().collect()
}

#[cfg(test)]
mod tests;
