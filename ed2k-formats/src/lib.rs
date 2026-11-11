// SPDX-License-Identifier: GPL-2.0-or-later
//! aMule/eMule on-disk formats (MIGRATION_PLAN.md, phase 2).
//!
//! Each module reads a file into a structure that keeps what is stored, so
//! that a file aMule wrote is written back byte for byte, and offers the
//! typed view aMule builds from it.
//!
//! * [`server_met`]: `server.met`, the eD2k server list.
//! * [`known_met`]: `known.met`, the hashed files and their statistics.
//! * [`nodes_dat`]: `nodes.dat`, saved Kad contacts (v0-v3 and bootstrap lists).

pub mod known_met;
pub mod nodes_dat;
pub mod server_met;
