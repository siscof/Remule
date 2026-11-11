// SPDX-License-Identifier: GPL-2.0-or-later
//! aMule/eMule on-disk formats (MIGRATION_PLAN.md, phase 2).
//!
//! Each module reads a file into a structure that keeps what is stored, so
//! that a file aMule wrote is written back byte for byte, and offers the
//! typed view aMule builds from it.
//!
//! * [`server_met`]: `server.met`, the eD2k server list.
//! * [`known_met`]: `known.met`, the hashed files and their statistics.
//! * [`canceled_met`]: `canceled.met` (and `knownhistory.met`), lists of file hashes.
//! * [`emfriends_met`]: `emfriends.met`, the friends list.

pub mod canceled_met;
pub mod emfriends_met;
pub mod known_met;
pub mod server_met;
