// SPDX-License-Identifier: GPL-2.0-or-later
//! The AICH hashes publishers gave for a keyword entry, with how many
//! publishers gave each (`CKadAICHHashList`, kademlia/AICHHashList.cpp).

/// `KAD_AICH_HASH_SIZE`
pub const HASH_SIZE: usize = 20;
/// An AICH root hash.
pub type AichHash = [u8; HASH_SIZE];
/// `INVALID_INDEX`
pub const INVALID_INDEX: u16 = 0xFFFF;
/// `MAX_RESULT_HASHES`: what fits a result tag (1 + 21 × 11 = 232 bytes).
pub const MAX_RESULT_HASHES: u8 = 11;
/// `MAX_SLOTS`
pub const MAX_SLOTS: usize = 1024;

/// One hash and its popularity, as a result tag carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultHash {
    pub popularity: u8,
    pub hash: AichHash,
}

/// The list: slots of hashes with a reference count each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AichList {
    hashes: Vec<AichHash>,
    popularity: Vec<u8>,
}

impl AichList {
    pub fn slot_count(&self) -> u16 {
        self.hashes.len() as u16
    }

    /// `AddReference`: the slot of `hash` (a new one if needed), or
    /// [`INVALID_INDEX`] when all [`MAX_SLOTS`] are used.
    pub fn add_reference(&mut self, hash: &AichHash) -> u16 {
        if let Some(i) = self.hashes.iter().position(|h| h == hash) {
            self.popularity[i] = self.popularity[i].saturating_add(1);
            return i as u16;
        }
        if self.hashes.len() >= MAX_SLOTS {
            return INVALID_INDEX;
        }
        self.hashes.push(*hash);
        self.popularity.push(1);
        (self.hashes.len() - 1) as u16
    }

    /// `DropReferenceAt` (an invalid index is ignored).
    pub fn drop_reference(&mut self, index: u16) {
        if let Some(p) = self.popularity.get_mut(index as usize) {
            *p = p.saturating_sub(1);
        }
    }

    pub fn referenced_count(&self) -> u16 {
        self.popularity.iter().filter(|&&p| p > 0).count() as u16
    }

    pub fn hash_at(&self, index: u16) -> Option<&AichHash> {
        self.hashes.get(index as usize)
    }

    /// `BuildCompactionMap`: each slot's index once unreferenced slots go.
    pub fn compaction_map(&self) -> Vec<u16> {
        let mut next = 0;
        self.popularity
            .iter()
            .map(|&p| {
                if p > 0 {
                    next += 1;
                    next - 1
                } else {
                    INVALID_INDEX
                }
            })
            .collect()
    }

    /// `Compact`: drop unreferenced slots; returns the old-to-new map.
    pub fn compact(&mut self) -> Vec<u16> {
        let map = self.compaction_map();
        let mut i = 0;
        self.hashes.retain(|_| {
            i += 1;
            map[i - 1] != INVALID_INDEX
        });
        self.popularity.retain(|&p| p > 0);
        map
    }

    /// The referenced hashes, in slot order.
    pub fn referenced(&self) -> impl Iterator<Item = (&AichHash, u8)> {
        self.hashes
            .iter()
            .zip(self.popularity.iter().copied())
            .filter(|(_, p)| *p > 0)
    }

    /// `EncodeResultTag`: `<count 1>(<popularity 1><hash 20>)*`, empty
    /// when no hash is referenced.
    pub fn encode_result_tag(&self) -> Vec<u8> {
        let list: Vec<_> = self.referenced().take(MAX_RESULT_HASHES as usize).collect();
        if list.is_empty() {
            return Vec::new();
        }
        let mut v = vec![list.len() as u8];
        for (h, p) in list {
            v.push(p);
            v.extend_from_slice(h);
        }
        v
    }
}

/// `DecodeResultTag`: `None` when malformed; hashes of popularity 0 are skipped.
pub fn decode_result_tag(data: &[u8]) -> Option<Vec<ResultHash>> {
    let (&count, rest) = data.split_first()?;
    if count > MAX_RESULT_HASHES || rest.len() < count as usize * (1 + HASH_SIZE) {
        return None;
    }
    Some(
        rest.as_chunks::<{ 1 + HASH_SIZE }>()
            .0
            .iter()
            .take(count as usize)
            .filter(|c| c[0] > 0)
            .map(|c| ResultHash {
                popularity: c[0],
                hash: std::array::from_fn(|i| c[1 + i]),
            })
            .collect(),
    )
}

/// `PeerSupportsAICHKeywordStorage`: Kad version 9 (0.50a) and later.
pub fn peer_supports_aich(version: u8) -> bool {
    version >= ed2k_types::kad::version::V9_50A
}

/// `SelectCandidate`: the one hash a searcher may trust, if any: there
/// must be exactly one, from at least two publishers, and from at least a
/// third of the publishers known.
pub fn select_candidate(hashes: &[ResultHash], publishers_known: u32) -> Option<&ResultHash> {
    let [h] = hashes else { return None };
    let p = h.popularity as u32;
    if p == 0 || publishers_known == 0 || publishers_known / p > 3 || publishers_known < 2 || p < 2
    {
        return None;
    }
    Some(h)
}
