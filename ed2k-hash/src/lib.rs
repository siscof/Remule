// SPDX-License-Identifier: GPL-2.0-or-later
//! eD2k file hashing (MIGRATION_PLAN.md, phase 3).
//!
//! Port of `CHashingTask::CreateNextPartHash` and the hash-list rules of
//! `CHashingTask::Entry` (ThreadTasks.cpp), `CKnownFile::CreateHashFromInput`
//! (KnownFile.cpp) and `CAICHHashTree` (SHAHashSet.cpp).
//!
//! * **eD2k**: MD4 per part of `PARTSIZE` (9,728,000) bytes. A file of one
//!   part is named by that part's hash; a longer file by the MD4 of its part
//!   hashes. When the last part is exactly full, eD2k counts one more, empty
//!   part, whose hash is the MD4 of nothing (`31D6CFE0…`).
//! * **AICH**: SHA-1 per block of `EMBLOCKSIZE` (184,320) bytes, the blocks
//!   restarting at every part, combined in eMule's tree (see [`aich_root`]).
//!
//! [`Hasher`] streams: feed it the file in any chunks, it never holds more
//! than the running digests and the hash lists.

pub mod aich;

use std::fmt;
use std::io::{self, Read};

use ed2k_types::ed2k::{EMBLOCKSIZE, PARTSIZE};
use ed2k_types::{AichHash, Md4Hash};
use md4::{Digest, Md4};
use sha1::Sha1;

const BLOCK: u64 = EMBLOCKSIZE as u64;

/// AICH blocks in a full part: ⌈PARTSIZE / EMBLOCKSIZE⌉ = 53, the last one short.
pub const BLOCKS_PER_PART: u64 = PARTSIZE.div_ceil(BLOCK);

/// `g_emptyMD4Hash`: the MD4 of no data, the hash of the empty extra part.
pub const EMPTY_MD4: Md4Hash = Md4Hash([
    0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0,
]);

/// Everything hashing a file produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHashes {
    pub size: u64,
    /// The eD2k file hash.
    pub ed2k: Md4Hash,
    /// The part hashes as `known.met` stores them: none for a file of one
    /// part, otherwise one per part plus the empty one for an exact multiple.
    pub part_hashes: Vec<Md4Hash>,
    /// The AICH root (master hash). `None` for an empty file, which aMule
    /// does not share.
    pub aich_root: Option<AichHash>,
    /// The AICH block hashes, left to right, as `known2_64.met` stores them.
    pub aich_blocks: Vec<AichHash>,
}

impl FileHashes {
    /// The ed2k link (`CreateED2kLink`, without sources):
    /// `ed2k://|file|NAME|SIZE|HASH|h=AICH|/`, the name cleaned as
    /// `CPath::Cleanup(false)` does.
    pub fn ed2k_link(&self, name: &str) -> String {
        let mut s = format!(
            "ed2k://|file|{}|{}|{}|",
            cleanup_name(name),
            self.size,
            self.ed2k
        );
        if let Some(root) = self.aich_root {
            s += &format!("h={root}|");
        }
        s.push('/');
        s
    }
}

/// `CPath::Cleanup(keepSpaces = false)`: drop `/` and control characters,
/// write spaces as `%20`. (`|` and the other characters FAT32 refuses are kept.)
pub fn cleanup_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '/' => {}
            ' ' => out.push_str("%20"),
            c if u32::from(c) < 32 => {}
            c => out.push(c),
        }
    }
    out
}

/// Streaming eD2k + AICH hasher.
pub struct Hasher {
    size: u64,
    part: Md4,
    part_len: u64,
    block: Sha1,
    block_len: u64,
    part_hashes: Vec<Md4Hash>,
    blocks: Vec<AichHash>,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Hasher {
            size: 0,
            part: Md4::new(),
            part_len: 0,
            block: Sha1::new(),
            block_len: 0,
            part_hashes: Vec::new(),
            blocks: Vec::new(),
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let part_left = PARTSIZE - self.part_len;
            let block_left = (BLOCK - self.block_len).min(part_left);
            let n = (data.len() as u64).min(block_left) as usize;
            self.part.update(&data[..n]);
            self.block.update(&data[..n]);
            self.part_len += n as u64;
            self.block_len += n as u64;
            self.size += n as u64;
            data = &data[n..];
            // A block ends at EMBLOCKSIZE or at the end of its part.
            if self.block_len == BLOCK || self.part_len == PARTSIZE {
                self.end_block();
            }
            if self.part_len == PARTSIZE {
                self.end_part();
            }
        }
    }

    fn end_block(&mut self) {
        let h = std::mem::replace(&mut self.block, Sha1::new()).finalize();
        self.blocks.push(AichHash(h.into()));
        self.block_len = 0;
    }

    fn end_part(&mut self) {
        let h = std::mem::replace(&mut self.part, Md4::new()).finalize();
        self.part_hashes.push(Md4Hash(h.into()));
        self.part_len = 0;
    }

    pub fn finish(mut self) -> FileHashes {
        if self.size == 0 {
            return FileHashes {
                size: 0,
                ed2k: EMPTY_MD4,
                part_hashes: Vec::new(),
                aich_root: None,
                aich_blocks: Vec::new(),
            };
        }
        if self.block_len > 0 {
            self.end_block();
        }
        if self.part_len > 0 {
            self.end_part();
        } else {
            // The last part ended exactly full: eD2k adds an empty part.
            self.part_hashes.push(EMPTY_MD4);
        }
        let (ed2k, part_hashes) = if self.part_hashes.len() == 1 {
            (self.part_hashes[0], Vec::new())
        } else {
            (hash_of_part_hashes(&self.part_hashes), self.part_hashes)
        };
        let aich_root = aich_root(self.size, &self.blocks);
        FileHashes {
            size: self.size,
            ed2k,
            part_hashes,
            aich_root,
            aich_blocks: self.blocks,
        }
    }
}

/// `CreateHashFromHashlist`: the file hash of a file of several parts.
pub fn hash_of_part_hashes(parts: &[Md4Hash]) -> Md4Hash {
    let mut h = Md4::new();
    for p in parts {
        h.update(p.0);
    }
    Md4Hash(h.finalize().into())
}

/// Hash everything a reader yields.
pub fn hash_reader<R: Read>(mut r: R) -> io::Result<FileHashes> {
    let mut h = Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(h.finish()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
    }
}

/// How many AICH block hashes a file of `size` bytes has.
pub const fn aich_block_count(size: u64) -> u64 {
    let full = size / PARTSIZE;
    let rest = size % PARTSIZE;
    full * BLOCKS_PER_PART + rest.div_ceil(BLOCK)
}

/// The AICH root of a file of `size` bytes from its block hashes, left to
/// right; `None` if `size` is 0 or the number of blocks does not fit.
///
/// The tree is `CAICHHashTree`: the root covers the file and is a left
/// branch; a node above part size splits in whole parts, a node of at most
/// one part in blocks. With `n` units, a left branch gives its left child
/// ⌈n/2⌉ units and a right branch ⌊n/2⌋, the rest going right; a node's
/// hash is the SHA-1 of its children's hashes, a block's the SHA-1 of its data.
pub fn aich_root(size: u64, blocks: &[AichHash]) -> Option<AichHash> {
    if size == 0 || blocks.len() as u64 != aich_block_count(size) {
        return None;
    }
    let base = if size <= PARTSIZE { BLOCK } else { PARTSIZE };
    Some(node(0, size, true, base, blocks))
}

fn node(start: u64, size: u64, left: bool, base: u64, blocks: &[AichHash]) -> AichHash {
    if size <= BLOCK {
        // A leaf: blocks restart at every part.
        let idx = start / PARTSIZE * BLOCKS_PER_PART + start % PARTSIZE / BLOCK;
        return blocks[idx as usize];
    }
    let units = size.div_ceil(base);
    let left_size = (if left { units + 1 } else { units }) / 2 * base;
    let child_base = |n: u64| if n <= PARTSIZE { BLOCK } else { PARTSIZE };
    let l = node(start, left_size, true, child_base(left_size), blocks);
    let right_size = size - left_size;
    let r = node(
        start + left_size,
        right_size,
        false,
        child_base(right_size),
        blocks,
    );
    let mut h = Sha1::new();
    h.update(l.0);
    h.update(r.0);
    AichHash(h.finalize().into())
}

impl fmt::Display for FileHashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed2k {} ({} bytes", self.ed2k, self.size)?;
        if let Some(r) = self.aich_root {
            write!(f, ", AICH {r}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_aich;
