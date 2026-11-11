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
//! * [`nodes_dat`]: `nodes.dat`, saved Kad contacts (v0-v3 and bootstrap lists).

pub mod canceled_met;
//! * [`emfriends_met`]: `emfriends.met`, the friends list.

pub mod emfriends_met;
//! * [`clients_met`]: `clients.met`, credits and metadata of other clients.

pub mod clients_met;
//! * [`known2_met`]: `known2_64.met`, the stored AICH hash sets.

pub mod known2_met;
//! * [`cryptkey_dat`]: `cryptkey.dat`, our RSA key for secure identification.

pub mod cryptkey_dat;
pub mod known_met;
pub mod nodes_dat;
pub mod server_met;
