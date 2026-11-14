// SPDX-License-Identifier: GPL-2.0-or-later
//! remule's client core (MIGRATION_PLAN.md, phase 8 onwards).
//!
//! * [`gap_list`]: the missing ranges of a download (`CGapList`).
//! * [`blocks`]: what to download next: block reservation and chunk
//!   ranking (`BlockReservation.h`, `GetNextRequestedBlock`).
//! * [`part_file`]: a download on disk, `.part` and `.part.met`, resumable
//!   by aMule (`CPartFile`).

pub mod blocks;
pub mod gap_list;
pub mod part_file;

pub use gap_list::GapList;
pub use part_file::{Completion, FileEvent, OpenError, PartFile, SourceView, Status};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_part_file;
