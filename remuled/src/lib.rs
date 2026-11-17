// SPDX-License-Identifier: GPL-2.0-or-later
//! `remuled`, the remule daemon (MIGRATION_PLAN.md, phase 10): the client
//! run from an aMule config directory, as `amuled` runs.
//!
//! * [`config`]: an aMule config directory turned into a client's settings.
//! * [`client`]: the running client (also behind `remule download`).
//! * [`kad`]: a Kad node started from, and saved to, aMule's files.
//! * [`bootstrap`]: `nodes.dat` and server lists fetched over HTTP at start.
//! * [`http`]: one file over HTTP(S).
//! * [`server_conn`]: which eD2k server to log into next, and when.
//! * [`stats`]: the transfer statistics in `statistics.dat` and in the log.

pub mod bootstrap;
pub mod client;
pub mod config;
pub mod http;
pub mod kad;
pub mod server_conn;
pub mod stats;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bootstrap;
#[cfg(test)]
mod tests_server_conn;
