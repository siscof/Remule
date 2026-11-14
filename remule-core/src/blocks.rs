// SPDX-License-Identifier: GPL-2.0-or-later
//! Choosing what to download next (`BlockReservation.h` and the chunk
//! ranking of `CPartFile::GetNextRequestedBlock`).
//!
//! Ranges here are inclusive `(start, end)` pairs, as in aMule.

/// `FindUnreservedBlock`: the first run of `candidate` that no reservation
/// covers. Reservations may be in any order, overlap, or be malformed
/// (start after end, which is ignored). A block partly reserved by another
/// peer still yields its free part.
pub fn find_unreserved_block(
    candidate: (u64, u64),
    reservations: &[(u64, u64)],
) -> Option<(u64, u64)> {
    let (mut start, cand_end) = candidate;
    if start > cand_end {
        return None;
    }
    'restart: loop {
        let mut end = cand_end;
        for &(rs, re) in reservations {
            if rs > re || re < start || rs > cand_end {
                continue;
            }
            if rs <= start {
                if re >= cand_end {
                    return None;
                }
                start = re + 1;
                // An earlier reservation may cover the new start.
                continue 'restart;
            }
            end = end.min(rs - 1);
        }
        return Some((start, end));
    }
}

/// `FindNextDownloadBlock`: the next free block within `part`, on the
/// part-relative grid of `block_size` bytes. `gaps` must be ordered and
/// disjoint, as a [`GapList`](crate::GapList) gives them.
pub fn find_next_download_block(
    part: (u64, u64),
    block_size: u64,
    gaps: impl IntoIterator<Item = (u64, u64)>,
    reservations: &[(u64, u64)],
) -> Option<(u64, u64)> {
    for (gs, ge) in gaps {
        if ge < part.0 {
            continue;
        }
        if gs > part.1 {
            break;
        }
        let mut start = part.0.max(gs);
        let limit = part.1.min(ge);
        loop {
            // Subtraction first keeps the inclusive end safe at u64::MAX.
            let remaining = block_size - 1 - (start - part.0) % block_size;
            let end = start + remaining.min(limit - start);
            if let Some(free) = find_unreserved_block((start, end), reservations) {
                return Some(free);
            }
            if end == limit {
                break;
            }
            start = end + 1;
        }
    }
    None
}

/// What chunk ranking needs to know about one part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkInfo {
    /// Sources that have the part (`m_SrcpartFrequency`).
    pub frequency: u16,
    /// The part is the first or last of a previewable file (criterion 2).
    pub preview: bool,
    /// Some block of the part is being downloaded (criterion 3).
    pub requested: bool,
    /// Percent of the part present, of a full [`PARTSIZE`](ed2k_types::ed2k::PARTSIZE)
    /// (criterion 4; this favours a short last part, as aMule does).
    pub completion: u16,
}

/// The rare-chunk bounds for a file with `sources` sources: very rare at or
/// below the first, rare at or below the second.
pub fn rarity_bounds(sources: u32) -> (u32, u32) {
    let modif = if sources > 800 {
        2
    } else if sources > 200 {
        5
    } else {
        10
    };
    // aMule computes this in 16 bits.
    let limit = ((modif * sources / 100) as u16).max(1);
    (u32::from(limit), 2 * u32::from(limit))
}

/// A chunk's priority; lower goes first. See `GetNextRequestedBlock`:
///
/// ```text
/// 0..xxxx       unrequested and requested very rare chunks
/// 10000..1xxxx  unrequested rare chunks + unrequested preview chunks
/// 20000..2xxxx  unrequested common chunks (the most complete first)
/// 30000..3xxxx  requested rare chunks + requested preview chunks
/// 40000..4xxxx  requested common chunks (the least complete first)
/// ```
///
/// Computed in 32 bits; aMule's 16-bit rank would wrap for parts with
/// thousands of sources.
pub fn chunk_rank(c: ChunkInfo, (very_rare, rare): (u32, u32)) -> u32 {
    let freq = u32::from(c.frequency);
    let completion = u32::from(c.completion.min(100));
    // Criterion 3 counts only above the very rare zone.
    let requested = freq > very_rare && c.requested;
    if freq <= very_rare {
        25 * freq + u32::from(!c.preview) + (100 - completion)
    } else if c.preview {
        (if requested { 30000 } else { 10000 }) + (100 - completion)
    } else if freq <= rare {
        25 * freq + (if requested { 30101 } else { 10101 }) + (100 - completion)
    } else if !requested {
        20000 + (100 - completion)
    } else {
        // Inverted, to spread new sources over the completing chunks.
        40000 + completion
    }
}

/// Which of the `count` best-ranked chunks to take, given a random number:
/// `1 + rand * (count - 1)` in aMule, so the last of several tied chunks is
/// never chosen. Returns a 0-based index among the tied chunks.
pub fn pick_tied(count: usize, random: u32) -> usize {
    if count <= 1 {
        0
    } else {
        random as usize % (count - 1)
    }
}
