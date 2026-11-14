// SPDX-License-Identifier: GPL-2.0-or-later
//! The AICH hash tree as aMule keeps it for recovery (`CAICHHashTree`,
//! `CAICHHashSet`, SHAHashSet.cpp), and the trust in a root hash that peers
//! report (`CAICHHashSet::HashReceived`).
//!
//! A part that fails its MD4 check is not thrown away whole: a peer with
//! the complete file sends the part's block hashes and, up to the root, the
//! sibling hash at every level ("recovery data"). If they hash up to the
//! root we trust, each block whose SHA-1 matches is kept.
//!
//! The tree's shape is that of [`aich_root`](crate::aich_root). A node is
//! named by its path from the root (the "hash ident"): a leading 1 for the
//! root, then one bit per level, 1 for a left child and 0 for a right one.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use ed2k_types::ed2k::{EMBLOCKSIZE, OLD_MAX_FILE_SIZE, PARTSIZE};
use ed2k_types::AichHash;
use sha1::{Digest, Sha1};

const BLOCK: u64 = EMBLOCKSIZE as u64;
const HASH_LEN: usize = 20;

/// The deepest a path can go (`FindHash`'s sanity limit).
const MAX_LEVEL: u8 = 22;

/// The largest 32-bit ident `ReadRecoveryData` accepts.
const MAX_IDENT32: u32 = 0x40_0000;

fn sha1_pair(l: &AichHash, r: &AichHash) -> AichHash {
    let mut h = Sha1::new();
    h.update(l.0);
    h.update(r.0);
    AichHash(h.finalize().into())
}

/// The SHA-1 of each [`EMBLOCKSIZE`] block of `part` (the data of one part).
pub fn block_hashes(part: &[u8]) -> Vec<AichHash> {
    part.chunks(EMBLOCKSIZE as usize)
        .map(|b| AichHash(Sha1::digest(b).into()))
        .collect()
}

fn base_for(size: u64) -> u64 {
    if size <= PARTSIZE {
        BLOCK
    } else {
        PARTSIZE
    }
}

#[derive(Debug, Clone)]
struct Node {
    size: u64,
    left_branch: bool,
    base: u64,
    hash: Option<AichHash>,
    left: Option<usize>,
    right: Option<usize>,
}

impl Node {
    fn new(size: u64, left_branch: bool) -> Node {
        Node {
            size,
            left_branch,
            base: base_for(size),
            hash: None,
            left: None,
            right: None,
        }
    }

    /// The sizes of the two children: a left branch gives its left child
    /// the larger half of its units.
    fn split(&self) -> (u64, u64) {
        let units = self.size.div_ceil(self.base);
        let left = (if self.left_branch { units + 1 } else { units }) / 2 * self.base;
        (left, self.size - left)
    }

    fn is_leaf_level(&self) -> bool {
        self.size <= self.base
    }
}

/// A partial AICH tree over a file. Nodes are created as paths are
/// walked; a node without a hash is unknown.
#[derive(Debug, Clone)]
pub struct AichTree {
    nodes: Vec<Node>,
}

impl AichTree {
    /// An empty tree over a file of `size` bytes (`SetFileSize`).
    pub fn new(size: u64) -> AichTree {
        AichTree {
            nodes: vec![Node::new(size, true)],
        }
    }

    /// A tree with only the root hash (`SetMasterHash`).
    pub fn with_root(size: u64, root: AichHash) -> AichTree {
        let mut t = AichTree::new(size);
        t.nodes[0].hash = Some(root);
        t
    }

    /// The complete tree of a file, from its block hashes left to right as
    /// [`Hasher`](crate::Hasher) gives them. `None` if the count is wrong.
    pub fn from_blocks(size: u64, blocks: &[AichHash]) -> Option<AichTree> {
        if size == 0 || blocks.len() as u64 != crate::aich_block_count(size) {
            return None;
        }
        let mut t = AichTree::new(size);
        let mut it = blocks.iter();
        t.load_lowest(0, &mut it);
        t.recalculate(0, false);
        Some(t)
    }

    pub fn size(&self) -> u64 {
        self.nodes[0].size
    }

    pub fn root(&self) -> Option<AichHash> {
        self.nodes[0].hash
    }

    /// `LoadLowestLevelHashs`
    fn load_lowest<'a>(&mut self, n: usize, it: &mut impl Iterator<Item = &'a AichHash>) {
        if self.nodes[n].is_leaf_level() {
            self.nodes[n].hash = it.next().copied();
            return;
        }
        let l = self.child(n, true);
        let r = self.child(n, false);
        self.load_lowest(l, it);
        self.load_lowest(r, it);
    }

    /// The left or right child of `n`, created if missing.
    fn child(&mut self, n: usize, left: bool) -> usize {
        let existing = if left {
            self.nodes[n].left
        } else {
            self.nodes[n].right
        };
        if let Some(c) = existing {
            return c;
        }
        let (ls, rs) = self.nodes[n].split();
        let c = self.nodes.len();
        self.nodes.push(Node::new(if left { ls } else { rs }, left));
        if left {
            self.nodes[n].left = Some(c);
        } else {
            self.nodes[n].right = Some(c);
        }
        c
    }

    /// `FindHash`: the node covering exactly `start..start + size`,
    /// creating the path to it, and its level (the root is level 1).
    fn find(&mut self, mut start: u64, size: u64) -> Option<(usize, u8)> {
        let mut n = 0;
        let mut level = 0u8;
        loop {
            level += 1;
            let node = &self.nodes[n];
            if level > MAX_LEVEL || start + size > node.size || size > node.size {
                return None;
            }
            if start == 0 && size == node.size {
                return Some((n, level));
            }
            if node.is_leaf_level() {
                return None;
            }
            let (ls, _) = node.split();
            if start < ls {
                if start + size > ls {
                    return None;
                }
                n = self.child(n, true);
            } else {
                start -= ls;
                n = self.child(n, false);
            }
        }
    }

    /// `FindExistingHash`: as [`find`](Self::find), but only along nodes
    /// that have hashes, and creating nothing.
    fn find_existing(&self, mut start: u64, size: u64) -> Option<usize> {
        let mut n = 0;
        for _ in 0..MAX_LEVEL {
            let node = &self.nodes[n];
            if start + size > node.size || size > node.size {
                return None;
            }
            if start == 0 && size == node.size {
                return node.hash.map(|_| n);
            }
            if node.is_leaf_level() {
                return None;
            }
            let (ls, _) = node.split();
            let next = if start < ls {
                if start + size > ls {
                    return None;
                }
                node.left
            } else {
                start -= ls;
                node.right
            };
            match next {
                Some(c) if self.nodes[c].hash.is_some() => n = c,
                _ => return None,
            }
        }
        None
    }

    /// `ReCalculateHash`: fill in hashes from the children's. False if a
    /// node has only one child.
    fn recalculate(&mut self, n: usize, dont_replace: bool) -> bool {
        match (self.nodes[n].left, self.nodes[n].right) {
            (Some(l), Some(r)) => {
                if !self.recalculate(l, dont_replace) || !self.recalculate(r, dont_replace) {
                    return false;
                }
                if dont_replace && self.nodes[n].hash.is_some() {
                    return true;
                }
                match (self.nodes[l].hash, self.nodes[r].hash) {
                    (Some(lh), Some(rh)) => {
                        self.nodes[n].hash = Some(sha1_pair(&lh, &rh));
                        true
                    }
                    _ => self.nodes[n].hash.is_some(),
                }
            }
            (None, None) => true,
            _ => false,
        }
    }

    fn drop_children(&mut self, n: usize) {
        self.nodes[n].left = None;
        self.nodes[n].right = None;
    }

    /// `VerifyHashTree`: every hash below `n` must agree with the one
    /// above it. With `delete_bad`, branches that do not, or that cannot be
    /// checked, are dropped.
    fn verify(&mut self, n: usize, delete_bad: bool) -> bool {
        let Some(own) = self.nodes[n].hash else {
            if delete_bad {
                self.drop_children(n);
            }
            return false;
        };
        let (l, r) = (self.nodes[n].left, self.nodes[n].right);
        for c in [l, r].into_iter().flatten() {
            if self.nodes[c].hash.is_none() {
                self.recalculate(c, true);
            }
        }
        let lh = l.and_then(|c| self.nodes[c].hash);
        let rh = r.and_then(|c| self.nodes[c].hash);
        match (lh, rh) {
            (Some(lh), Some(rh)) => {
                if sha1_pair(&lh, &rh) != own {
                    if delete_bad {
                        self.drop_children(n);
                    }
                    return false;
                }
                // Both are checked, as aMule's && does: the right only if
                // the left passed.
                self.verify(l.unwrap(), delete_bad) && self.verify(r.unwrap(), delete_bad)
            }
            (None, None) => {
                // The last hash on this branch. Children without hashes may
                // still hold unchecked hashes further down: drop them.
                if delete_bad {
                    if l.is_some() {
                        self.nodes[n].left = None;
                    }
                    if r.is_some() {
                        self.nodes[n].right = None;
                    }
                }
                true
            }
            _ => {
                // One branch can never be checked.
                if delete_bad {
                    self.drop_children(n);
                }
                false
            }
        }
    }

    /// `SetHash`: put a hash at the node `ident` names. An existing hash is
    /// kept (the data is still consumed).
    fn set_hash(&mut self, ident: u32, hash: AichHash) -> bool {
        if ident == 0 {
            return false;
        }
        let mut level = 31 - ident.leading_zeros();
        let mut ident = ident << ident.leading_zeros();
        let mut n = 0;
        while level > 0 {
            if self.nodes[n].is_leaf_level() {
                return false;
            }
            ident <<= 1;
            level -= 1;
            n = self.child(n, ident & 0x8000_0000 != 0);
        }
        if self.nodes[n].hash.is_none() {
            self.nodes[n].hash = Some(hash);
        }
        true
    }

    fn part_range(&self, part_start: u64) -> Option<u64> {
        let size = self.size();
        if part_start >= size || !part_start.is_multiple_of(PARTSIZE) {
            return None;
        }
        Some(PARTSIZE.min(size - part_start))
    }

    /// The number of hashes recovery data for the part at `part_start`
    /// carries: a sibling per level above the part, then its blocks.
    fn hashes_for_part(&mut self, part_start: u64, part_size: u64) -> Option<u16> {
        let (_, level) = self.find(part_start, part_size)?;
        Some(u16::from(level - 1) + part_size.div_ceil(BLOCK) as u16)
    }

    /// `CAICHHashSet::CreatePartRecoveryData`: the recovery data for the
    /// part starting at `part_start`, from a complete tree. Files over
    /// 4 GB use 32-bit idents, after an empty 16-bit section; others end
    /// with an empty 32-bit section. `None` for a file of one block, a
    /// bad offset, or a tree missing a hash on the way.
    pub fn part_recovery_data(&mut self, part_start: u64) -> Option<Vec<u8>> {
        let part_size = self.part_range(part_start)?;
        if self.size() <= BLOCK {
            return None;
        }
        let count = self.hashes_for_part(part_start, part_size)?;
        let wide = self.size() > OLD_MAX_FILE_SIZE;
        let mut out = Vec::new();
        if wide {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        out.extend_from_slice(&count.to_le_bytes());
        let before = out.len();
        if !self.write_part_path(0, part_start, part_size, 0, wide, &mut out) {
            return None;
        }
        let each = HASH_LEN + if wide { 4 } else { 2 };
        if out.len() - before != usize::from(count) * each {
            return None;
        }
        if !wide {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        Some(out)
    }

    fn write_ident(out: &mut Vec<u8>, ident: u32, wide: bool) {
        if wide {
            out.extend_from_slice(&ident.to_le_bytes());
        } else {
            out.extend_from_slice(&(ident as u16).to_le_bytes());
        }
    }

    /// `CAICHHashTree::CreatePartRecoveryData`
    fn write_part_path(
        &self,
        n: usize,
        mut start: u64,
        size: u64,
        ident: u32,
        wide: bool,
        out: &mut Vec<u8>,
    ) -> bool {
        let node = &self.nodes[n];
        if start == 0 && size == node.size {
            return self.write_lowest(n, ident, wide, out);
        }
        if node.is_leaf_level() {
            return false;
        }
        let ident = ident << 1 | u32::from(node.left_branch);
        let (Some(l), Some(r)) = (node.left, node.right) else {
            return false;
        };
        let (ls, rs) = node.split();
        let (sibling, next) = if start < ls {
            if start + size > ls {
                return false;
            }
            (r, l)
        } else {
            start -= ls;
            if start + size > rs {
                return false;
            }
            (l, r)
        };
        let Some(h) = self.nodes[sibling].hash else {
            return false;
        };
        Self::write_ident(
            out,
            ident << 1 | u32::from(self.nodes[sibling].left_branch),
            wide,
        );
        out.extend_from_slice(&h.0);
        self.write_part_path(next, start, size, ident, wide, out)
    }

    /// `WriteLowestLevelHashs`, with idents.
    fn write_lowest(&self, n: usize, ident: u32, wide: bool, out: &mut Vec<u8>) -> bool {
        let node = &self.nodes[n];
        let ident = ident << 1 | u32::from(node.left_branch);
        match (node.left, node.right) {
            (None, None) => match node.hash {
                Some(h) if node.is_leaf_level() => {
                    Self::write_ident(out, ident, wide);
                    out.extend_from_slice(&h.0);
                    true
                }
                _ => false,
            },
            (Some(l), Some(r)) => {
                self.write_lowest(l, ident, wide, out) && self.write_lowest(r, ident, wide, out)
            }
            _ => false,
        }
    }

    /// `CAICHHashSet::ReadRecoveryData`: take recovery data for the part at
    /// `part_start` into the tree. True if every block hash of the part is
    /// now known and hashes up to the root; on failure, what does not
    /// check out is dropped. The root must be set (and trusted).
    pub fn read_recovery_data(&mut self, part_start: u64, data: &[u8]) -> bool {
        if self.root().is_none() {
            return false;
        }
        let Some(part_size) = self.part_range(part_start) else {
            return false;
        };
        let Some(want) = self.hashes_for_part(part_start, part_size) else {
            return false;
        };
        let want = usize::from(want);
        let mut r = data;
        let mut take = |n: usize| -> Option<&[u8]> {
            if r.len() < n {
                return None;
            }
            let (a, b) = r.split_at(n);
            r = b;
            Some(a)
        };
        let u16_at = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);

        let Some(c) = take(2) else { return false };
        let mut available = usize::from(u16_at(c));
        // Checked against what is left after the count, as aMule does.
        let left = data.len() - 2;
        if left < want * (HASH_LEN + 2) || (want != available && available != 0) {
            return false;
        }
        for _ in 0..available {
            let (Some(i), Some(h)) = (take(2), take(HASH_LEN)) else {
                return false;
            };
            let ident = u32::from(u16_at(i));
            let hash = AichHash(h.try_into().unwrap());
            // The root is never overwritten.
            if ident == 1 || !self.set_hash(ident, hash) {
                self.verify(0, true);
                return false;
            }
        }
        if available == 0 {
            if let Some(c) = take(2) {
                available = usize::from(u16_at(c));
                let left = data.len() - 4;
                if left < want * (HASH_LEN + 4) || want != available {
                    return false;
                }
                for _ in 0..available {
                    let (Some(i), Some(h)) = (take(4), take(HASH_LEN)) else {
                        return false;
                    };
                    let ident = u32::from_le_bytes(i.try_into().unwrap());
                    let hash = AichHash(h.try_into().unwrap());
                    if ident == 1 || ident > MAX_IDENT32 || !self.set_hash(ident, hash) {
                        self.verify(0, true);
                        return false;
                    }
                }
            }
        }
        if available == 0 {
            return false;
        }
        if !self.verify(0, true) {
            return false;
        }
        self.verified_block_hashes(part_start).is_some()
    }

    /// The block hashes of the part at `part_start`, if all are known and
    /// linked to the root.
    pub fn verified_block_hashes(&self, part_start: u64) -> Option<Vec<AichHash>> {
        let part_size = self.part_range(part_start)?;
        (0..part_size)
            .step_by(EMBLOCKSIZE as usize)
            .map(|pos| {
                let n = self.find_existing(part_start + pos, BLOCK.min(part_size - pos))?;
                self.nodes[n].hash
            })
            .collect()
    }
}

/// `CAICHUntrustedHash::SigningSubnet`: an IPv4 source vouches for its /20.
pub fn signing_key_v4(ip: Ipv4Addr) -> u32 {
    u32::from_le_bytes(ip.octets()) & 0x00F0_FFFF
}

/// `kIPv6KeyBit`: set in every IPv6 key, never in an IPv4 one.
pub const IPV6_KEY_BIT: u32 = 0x8000_0000;

/// `CAICHUntrustedHash::SigningKey` for IPv6: one key per /48, an FNV-1a
/// of its six octets.
pub fn signing_key_v6(ip: Ipv6Addr) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for &o in &ip.octets()[..6] {
        h = (h ^ u32::from(o)).wrapping_mul(16_777_619);
    }
    h | IPV6_KEY_BIT
}

/// `MINUNIQUEIPS_TOTRUST`
pub const MIN_KEYS_TO_TRUST: usize = 10;
/// `MINPERCENTAGE_TOTRUST`
pub const MIN_PERCENT_TO_TRUST: usize = 92;

#[derive(Debug, Clone)]
struct Vote {
    hash: AichHash,
    keys: BTreeSet<u32>,
    /// Keys backed only by a Kad search result.
    kad: BTreeSet<u32>,
}

/// The best root so far, and whether it is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootTrust {
    Untrusted(AichHash),
    Trusted(AichHash),
}

impl RootTrust {
    pub fn hash(self) -> AichHash {
        match self {
            RootTrust::Untrusted(h) | RootTrust::Trusted(h) => h,
        }
    }
}

/// The roots peers have reported for one file (`m_aUntrustedHashs`). A root
/// is trusted once at least [`MIN_KEYS_TO_TRUST`] subnets report it and
/// they are at least [`MIN_PERCENT_TO_TRUST`] percent of all that reported.
#[derive(Debug, Clone, Default)]
pub struct RootVotes {
    votes: Vec<Vote>,
    /// `IsTrustingEveryHash`: trust whatever is reported most.
    pub trust_every_hash: bool,
}

impl RootVotes {
    /// `HashReceived`: `key` (a [`signing_key_v4`] or [`signing_key_v6`])
    /// reports `hash`. A key may back one root only; a contradicting report
    /// is ignored (`None`), unless the earlier one came from Kad alone and
    /// this one from a source. Returns the best root after the vote.
    pub fn received(&mut self, hash: AichHash, key: u32, from_kad: bool) -> Option<RootTrust> {
        if let Some(i) = self
            .votes
            .iter()
            .position(|v| v.hash != hash && v.keys.contains(&key))
        {
            let held = &mut self.votes[i];
            if from_kad || !held.kad.contains(&key) {
                return None;
            }
            held.keys.remove(&key);
            held.kad.remove(&key);
            if held.keys.is_empty() {
                self.votes.remove(i);
            }
        }
        match self.votes.iter_mut().find(|v| v.hash == hash) {
            Some(v) => {
                let added = v.keys.insert(key);
                if !from_kad {
                    v.kad.remove(&key);
                } else if added {
                    v.kad.insert(key);
                }
            }
            None => self.votes.push(Vote {
                hash,
                keys: BTreeSet::from([key]),
                kad: if from_kad {
                    BTreeSet::from([key])
                } else {
                    BTreeSet::new()
                },
            }),
        }
        let total: usize = self.votes.iter().map(|v| v.keys.len()).sum();
        // The first of equals wins, as aMule's strict > does.
        let best = self.votes.iter().fold(None::<&Vote>, |b, v| match b {
            Some(b) if b.keys.len() >= v.keys.len() => Some(b),
            _ => Some(v),
        })?;
        let n = best.keys.len();
        Some(
            if self.trust_every_hash
                || (n >= MIN_KEYS_TO_TRUST && 100 * n / total >= MIN_PERCENT_TO_TRUST)
            {
                RootTrust::Trusted(best.hash)
            } else {
                RootTrust::Untrusted(best.hash)
            },
        )
    }
}
