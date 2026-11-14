// SPDX-License-Identifier: GPL-2.0-or-later
//! The missing ranges of a download (`CGapList`, GapList.cpp).
//!
//! Ranges are inclusive, as aMule keeps them and as `.part.met` stores them
//! (with the end written plus one). Overlapping and adjacent gaps join.

use std::collections::BTreeMap;

use ed2k_types::ed2k::PARTSIZE;

/// Missing byte ranges of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapList {
    /// Keyed by end, the value is the start, as in aMule: the first gap
    /// ending at or after an offset is one range query away.
    gaps: BTreeMap<u64, u64>,
    size: u64,
}

impl GapList {
    /// `Init`: a list for a file of `size` bytes, either all missing
    /// (`empty`) or complete.
    pub fn new(size: u64, empty: bool) -> GapList {
        let mut g = GapList {
            gaps: BTreeMap::new(),
            size,
        };
        if empty && size > 0 {
            g.gaps.insert(size - 1, 0);
        }
        g
    }

    /// A list with the given inclusive gaps (as loaded from a `.part.met`).
    pub fn with_gaps(size: u64, gaps: &[(u64, u64)]) -> GapList {
        let mut g = GapList::new(size, false);
        for &(s, e) in gaps {
            g.add(s, e);
        }
        g
    }

    pub fn file_size(&self) -> u64 {
        self.size
    }

    /// `GetPartCount`: parts that hold data.
    pub fn part_count(&self) -> u16 {
        self.size.div_ceil(PARTSIZE) as u16
    }

    /// The range of part `part`, inclusive.
    pub fn part_range(&self, part: u16) -> (u64, u64) {
        let start = u64::from(part) * PARTSIZE;
        let end = (start + PARTSIZE).min(self.size) - 1;
        (start, end)
    }

    /// `ArgCheck`: `None` for an inverted range or an empty file, the end
    /// clipped to the file.
    fn clip(&self, start: u64, end: u64) -> Option<(u64, u64)> {
        if end < start || self.size == 0 || start >= self.size {
            return None;
        }
        Some((start, end.min(self.size - 1)))
    }

    /// `AddGap`: mark `start..=end` missing.
    pub fn add(&mut self, start: u64, end: u64) {
        let Some((mut start, mut end)) = self.clip(start, end) else {
            return;
        };
        // Every gap overlapping or touching the new one joins it.
        let joined: Vec<(u64, u64)> = self
            .gaps
            .range(start.saturating_sub(1)..)
            .take_while(|(_, &s)| s <= end.saturating_add(1))
            .map(|(&e, &s)| (s, e))
            .collect();
        for (s, e) in joined {
            self.gaps.remove(&e);
            start = start.min(s);
            end = end.max(e);
        }
        self.gaps.insert(end, start);
    }

    /// `AddGap(part)`
    pub fn add_part(&mut self, part: u16) {
        if part < self.part_count() {
            let (s, e) = self.part_range(part);
            self.add(s, e);
        }
    }

    /// `FillGap`: mark `start..=end` present.
    pub fn fill(&mut self, start: u64, end: u64) {
        let Some((start, end)) = self.clip(start, end) else {
            return;
        };
        let hit: Vec<(u64, u64)> = self
            .gaps
            .range(start..)
            .take_while(|(_, &s)| s <= end)
            .map(|(&e, &s)| (s, e))
            .collect();
        for (s, e) in hit {
            self.gaps.remove(&e);
            if s < start {
                self.gaps.insert(start - 1, s);
            }
            if e > end {
                self.gaps.insert(e, end + 1);
            }
        }
    }

    /// `FillGap(part)`
    pub fn fill_part(&mut self, part: u16) {
        if part < self.part_count() {
            let (s, e) = self.part_range(part);
            self.fill(s, e);
        }
    }

    /// `IsComplete(start, end)`: nothing in the range is missing. False for
    /// an invalid range.
    pub fn is_range_complete(&self, start: u64, end: u64) -> bool {
        let Some((start, end)) = self.clip(start, end) else {
            return false;
        };
        match self.gaps.range(start..).next() {
            Some((_, &s)) => s > end,
            None => true,
        }
    }

    /// `IsComplete(part)`. The extra empty part eD2k counts for a file that
    /// is an exact multiple of [`PARTSIZE`] is always complete, so it is never
    /// asked for; any other part past the end is not.
    pub fn is_part_complete(&self, part: u16) -> bool {
        let count = self.part_count();
        if part == count && self.size.is_multiple_of(PARTSIZE) && self.size > 0 {
            return true;
        }
        if part >= count {
            return false;
        }
        let (s, e) = self.part_range(part);
        self.is_range_complete(s, e)
    }

    /// Whether nothing is missing.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Number of gaps.
    pub fn len(&self) -> usize {
        self.gaps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.gaps.is_empty()
    }

    /// `GetGapSize()`: bytes missing.
    pub fn gap_size(&self) -> u64 {
        self.gaps.iter().map(|(&e, &s)| e - s + 1).sum()
    }

    /// `GetGapSize(part)`: bytes missing in one part.
    pub fn part_gap_size(&self, part: u16) -> u64 {
        if part >= self.part_count() {
            return 0;
        }
        let (start, end) = self.part_range(part);
        self.gaps
            .range(start..)
            .take_while(|(_, &s)| s <= end)
            .map(|(&e, &s)| e.min(end) - s.max(start) + 1)
            .sum()
    }

    /// The gaps in order, inclusive.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.gaps.iter().map(|(&e, &s)| (s, e))
    }

    /// The gaps overlapping `start..=end`, clipped to it.
    pub fn missing_in(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        self.gaps
            .range(start..)
            .take_while(|(_, &s)| s <= end)
            .map(|(&e, &s)| (s.max(start), e.min(end)))
            .collect()
    }
}
