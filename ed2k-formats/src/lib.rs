// SPDX-License-Identifier: GPL-2.0-or-later
//! aMule/eMule on-disk formats (MIGRATION_PLAN.md, phase 2).
//!
//! Each module reads a file into a structure that keeps what is stored, so
//! that a file aMule wrote is written back byte for byte, and offers the
//! typed view aMule builds from it.
//!
//! * [`server_met`]: `server.met`, the eD2k server list.
//! * [`known_met`]: `known.met`, the hashed files and their statistics.
//! * [`part_met`]: `.part.met`, the state of each download.
//! * [`known2_met`]: `known2_64.met`, the stored AICH hash sets.
//! * [`clients_met`]: `clients.met`, credits and metadata of other clients.
//! * [`cryptkey_dat`]: `cryptkey.dat`, our RSA key for secure identification.
//! * [`nodes_dat`]: `nodes.dat`, saved Kad contacts (v0-v3 and bootstrap lists).
//! * [`ipfilter`]: `ipfilter.dat` / `ipfilter_static.dat` IP filter lists.
//! * [`addresses_dat`]: `addresses.dat` (server.met update URLs) and
//!   `staticservers.dat` (servers marked static).
//! * [`canceled_met`]: `canceled.met` (and `knownhistory.met`), lists of file hashes.
//! * [`emfriends_met`]: `emfriends.met`, the friends list.
//! * [`amule_conf`]: `amule.conf`, the preferences (a wxFileConfig INI file).
//! * [`preferences_dat`]: `preferences.dat`, our user hash.
//! * [`shareddir_dat`]: `shareddir.dat` and its successors, the shared folders.

pub mod addresses_dat;
pub mod amule_conf;
pub mod canceled_met;
pub mod clients_met;
pub mod cryptkey_dat;
pub mod emfriends_met;
pub mod ipfilter;
pub mod known2_met;
pub mod known_met;
pub mod nodes_dat;
pub mod part_met;
pub mod preferences_dat;
pub mod server_met;
pub mod shareddir_dat;
