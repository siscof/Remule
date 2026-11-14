// SPDX-License-Identifier: GPL-2.0-or-later
//! Gap list and block selection. The block cases are aMule's
//! `BlockReservationTest.cpp`.

use ed2k_types::ed2k::PARTSIZE;

use crate::blocks::{
    chunk_rank, find_next_download_block, find_unreserved_block, pick_tied, rarity_bounds,
    ChunkInfo,
};
use crate::GapList;

fn gaps(g: &GapList) -> Vec<(u64, u64)> {
    g.iter().collect()
}

#[test]
fn gap_list_starts_empty_or_complete() {
    let g = GapList::new(1000, true);
    assert_eq!(gaps(&g), [(0, 999)]);
    assert_eq!(g.gap_size(), 1000);
    assert!(GapList::new(1000, false).is_complete());
    assert!(GapList::new(0, true).is_complete());
}

#[test]
fn adding_joins_overlapping_and_adjacent_gaps() {
    let mut g = GapList::new(1000, false);
    g.add(10, 19);
    g.add(30, 39);
    assert_eq!(gaps(&g), [(10, 19), (30, 39)]);
    // Adjacent on both sides.
    g.add(20, 29);
    assert_eq!(gaps(&g), [(10, 39)]);
    // Inside an existing gap: no change.
    g.add(15, 16);
    assert_eq!(gaps(&g), [(10, 39)]);
    // Covering several.
    g.add(50, 59);
    g.add(70, 79);
    g.add(45, 75);
    assert_eq!(gaps(&g), [(10, 39), (45, 79)]);
    // Touching the start.
    g.add(0, 9);
    assert_eq!(gaps(&g), [(0, 39), (45, 79)]);
    // Clipped to the file; inverted ranges ignored.
    g.add(990, 5000);
    g.add(500, 400);
    assert_eq!(gaps(&g), [(0, 39), (45, 79), (990, 999)]);
}

#[test]
fn filling_shrinks_and_splits_gaps() {
    let mut g = GapList::new(1000, true);
    g.fill(0, 99);
    assert_eq!(gaps(&g), [(100, 999)]);
    g.fill(200, 299);
    assert_eq!(gaps(&g), [(100, 199), (300, 999)]);
    g.fill(150, 349);
    assert_eq!(gaps(&g), [(100, 149), (350, 999)]);
    g.fill(0, 5000);
    assert!(g.is_complete());
}

#[test]
fn completeness_of_ranges_and_parts() {
    let size = 2 * PARTSIZE + 100;
    let mut g = GapList::new(size, false);
    g.add(PARTSIZE + 5, PARTSIZE + 5);
    assert!(g.is_part_complete(0));
    assert!(!g.is_part_complete(1));
    assert!(g.is_part_complete(2));
    assert!(!g.is_part_complete(3));
    assert!(g.is_range_complete(0, PARTSIZE + 4));
    assert!(!g.is_range_complete(PARTSIZE + 5, PARTSIZE + 5));
    assert!(!g.is_range_complete(0, size));
    assert_eq!(g.part_gap_size(1), 1);
    assert_eq!(g.part_gap_size(0), 0);

    let mut g = GapList::new(size, true);
    g.fill_part(1);
    assert_eq!(gaps(&g), [(0, PARTSIZE - 1), (2 * PARTSIZE, size - 1)]);
    assert_eq!(g.part_gap_size(2), 100);
    g.add_part(1);
    assert_eq!(gaps(&g), [(0, size - 1)]);
}

#[test]
fn the_extra_ed2k_part_of_an_exact_multiple_is_complete() {
    let g = GapList::new(2 * PARTSIZE, true);
    assert_eq!(g.part_count(), 2);
    assert!(!g.is_part_complete(1));
    assert!(g.is_part_complete(2));
    assert!(!g.is_part_complete(3));
    assert!(!GapList::new(PARTSIZE + 1, true).is_part_complete(2));
}

#[test]
fn part_gap_size_sums_partial_gaps() {
    let mut g = GapList::new(3 * PARTSIZE, false);
    g.add(PARTSIZE - 10, PARTSIZE + 9);
    g.add(PARTSIZE + 100, PARTSIZE + 199);
    g.add(2 * PARTSIZE - 5, 2 * PARTSIZE + 5);
    assert_eq!(g.part_gap_size(0), 10);
    assert_eq!(g.part_gap_size(1), 10 + 100 + 5);
    assert_eq!(g.part_gap_size(2), 6);
    assert_eq!(g.gap_size(), 20 + 100 + 11);
}

#[test]
fn missing_in_clips_to_the_range() {
    let mut g = GapList::new(100, false);
    g.add(10, 19);
    g.add(30, 39);
    assert_eq!(g.missing_in(15, 35), [(15, 19), (30, 35)]);
    assert!(g.missing_in(20, 29).is_empty());
}

// ---- BlockReservationTest ----

fn find(candidate: (u64, u64), reservations: &[(u64, u64)]) -> Option<(u64, u64)> {
    find_unreserved_block(candidate, reservations)
}

#[test]
fn partial_reservation_does_not_hide_the_rest_of_the_block() {
    assert_eq!(find((0, 99), &[(0, 19)]), Some((20, 99)));
    assert_eq!(find((0, 99), &[(20, 39)]), Some((0, 19)));
}

#[test]
fn unordered_overlapping_reservations_are_clipped() {
    assert_eq!(
        find((10, 99), &[(40, 59), (15, 29), (0, 19), (25, 34)]),
        Some((35, 39))
    );
    assert_eq!(find((10, 99), &[(50, 99), (0, 59)]), None);
}

#[test]
fn inclusive_boundaries_cannot_overflow() {
    let max = u64::MAX;
    assert_eq!(find((max, max), &[(max, max)]), None);
    assert_eq!(
        find((max - 1, max), &[(max - 1, max - 1)]),
        Some((max, max))
    );
    assert_eq!(find((0, 1), &[(1, 1)]), Some((0, 0)));
    assert_eq!(find((1, 0), &[]), None);
}

#[test]
fn allocates_every_free_byte_exactly_once_regardless_of_reservation_order() {
    for mask in 0u32..256 {
        let mut res: Vec<(u64, u64)> = (0..8)
            .filter(|b| mask & (1 << b) != 0)
            .map(|b| (b, b))
            .collect();
        res.reverse();
        let mut allocated = mask;
        while let Some((s, e)) = find((0, 7), &res) {
            assert!(s <= e && e < 8);
            for byte in s..=e {
                assert_eq!(allocated & (1 << byte), 0);
                allocated |= 1 << byte;
            }
            res.push((s, e));
        }
        assert_eq!(allocated, 255);
    }
}

#[test]
fn ignores_malformed_and_unrelated_reservations() {
    assert_eq!(find((10, 19), &[(9, 1), (0, 9), (20, 99)]), Some((10, 19)));
}

#[test]
fn overlapping_intervals_match_first_free_run_oracle() {
    for base in [0u64, u64::MAX - 7] {
        let mut ranges = Vec::new();
        for s in 0..8u64 {
            for e in s..8 {
                ranges.push((base + s, base + e));
            }
        }
        for &cand in &ranges {
            for &a in &ranges {
                for &b in &ranges {
                    let reserved = |byte: u64| {
                        let o = base + byte;
                        (a.0 <= o && o <= a.1) || (b.0 <= o && o <= b.1)
                    };
                    let mut start = cand.0 - base;
                    let limit = cand.1 - base;
                    while start <= limit && reserved(start) {
                        start += 1;
                    }
                    let mut end = start;
                    while end < limit && !reserved(end + 1) {
                        end += 1;
                    }
                    let got = find(cand, &[a, b]);
                    assert_eq!(got.is_some(), start <= limit);
                    if let Some(r) = got {
                        assert_eq!(r, (base + start, base + end));
                    }
                }
            }
        }
    }
}

fn select(
    part: (u64, u64),
    block: u64,
    gaps: &[(u64, u64)],
    res: &[(u64, u64)],
) -> Option<(u64, u64)> {
    find_next_download_block(part, block, gaps.iter().copied(), res)
}

#[test]
fn selection_clips_gaps_to_part_and_block_grid() {
    assert_eq!(
        select((100, 126), 10, &[(0, 99), (103, 199)], &[]),
        Some((103, 109))
    );
    assert_eq!(
        select((100, 126), 10, &[(103, 199)], &[(100, 119)]),
        Some((120, 126))
    );
}

#[test]
fn selection_skips_reserved_blocks_and_preserves_holes() {
    assert_eq!(
        select(
            (0, 29),
            10,
            &[(2, 14), (18, 29)],
            &[(18, 19), (0, 9), (10, 12)]
        ),
        Some((13, 14))
    );
    assert_eq!(select((0, 29), 10, &[(2, 14), (18, 29)], &[(0, 29)]), None);
    assert_eq!(select((0, 29), 10, &[], &[]), None);
}

#[test]
fn selection_matches_byte_oracle_across_gaps_and_reservations() {
    for missing in 0u32..256 {
        let mut gaps: Vec<(u64, u64)> = Vec::new();
        for bit in 0..8u64 {
            if missing & (1 << bit) != 0 {
                match gaps.last_mut() {
                    Some(g) if g.1 + 1 == bit => g.1 = bit,
                    _ => gaps.push((bit, bit)),
                }
            }
        }
        for busy in 0u32..256 {
            let mut res: Vec<(u64, u64)> = (0..8u64)
                .filter(|b| busy & (1 << b) != 0)
                .map(|b| (b, b))
                .collect();
            res.reverse();
            let got = select((1, 6), 3, &gaps, &res);
            let free = |bit: u64| missing & !busy & (1 << bit) != 0;
            let mut start = 1;
            while start <= 6 && !free(start) {
                start += 1;
            }
            assert_eq!(got.is_some(), start <= 6);
            if let Some(r) = got {
                let mut end = start;
                while end < 6 && (end - 1) / 3 == end / 3 && free(end + 1) {
                    end += 1;
                }
                assert_eq!(r, (start, end));
            }
        }
    }
}

// ---- chunk ranking ----

#[test]
fn rarity_bounds_follow_the_source_count() {
    assert_eq!(rarity_bounds(0), (1, 2));
    assert_eq!(rarity_bounds(50), (5, 10));
    assert_eq!(rarity_bounds(200), (20, 40));
    assert_eq!(rarity_bounds(201), (10, 20));
    assert_eq!(rarity_bounds(1000), (20, 40));
}

#[test]
fn chunk_ranks_fall_in_their_zones() {
    let bounds = (5, 10);
    let c = |frequency, preview, requested, completion| ChunkInfo {
        frequency,
        preview,
        requested,
        completion,
    };
    // Very rare: frequency, preview, completion; requests do not count.
    assert_eq!(chunk_rank(c(2, false, true, 30), bounds), 50 + 1 + 70);
    assert_eq!(chunk_rank(c(2, true, false, 30), bounds), 50 + 70);
    // Preview.
    assert_eq!(chunk_rank(c(8, true, false, 0), bounds), 10100);
    assert_eq!(chunk_rank(c(8, true, true, 100), bounds), 30000);
    // Rare.
    assert_eq!(chunk_rank(c(8, false, false, 50), bounds), 200 + 10101 + 50);
    assert_eq!(chunk_rank(c(8, false, true, 50), bounds), 200 + 30101 + 50);
    // Common: the most complete first, unless requested, then the least.
    assert_eq!(chunk_rank(c(20, false, false, 90), bounds), 20010);
    assert_eq!(chunk_rank(c(20, false, true, 90), bounds), 40090);
    assert!(
        chunk_rank(c(20, false, true, 10), bounds) < chunk_rank(c(20, false, true, 90), bounds)
    );
}

#[test]
fn ties_never_pick_the_last_of_several() {
    assert_eq!(pick_tied(1, 12345), 0);
    for r in 0..100 {
        assert!(pick_tied(3, r) < 2);
    }
}
