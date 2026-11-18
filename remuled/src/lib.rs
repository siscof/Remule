// SPDX-License-Identifier: GPL-2.0-or-later
//! `remuled`, the remule daemon (MIGRATION_PLAN.md, phase 10): the client
//! run from an aMule config directory, as `amuled` runs.
//!
//! * [`config`]: an aMule config directory turned into a client's settings.
//! * [`client`]: the running client (also behind `remule download`).
//! * [`kad`]: a Kad node started from, and saved to, aMule's files.
//! * [`firewall`]: whether others can reach us; answering Kad's firewall
//!   checks over TCP.
//! * [`bootstrap`]: `nodes.dat` and server lists fetched over HTTP at start.
//! * [`http`]: one file over HTTP(S).
//! * [`server_conn`]: which eD2k server to log into next, and when.
//! * [`stats`]: the transfer statistics in `statistics.dat` and in the log.
//! * [`ec`]: external connections, for `amulecmd` and `amulegui`.
//! * [`ec_shared`]: shared files over external connections.

pub mod bootstrap;
pub mod client;
pub mod config;
pub mod ec;
pub mod ec_shared;
pub mod firewall;
pub mod http;
pub mod kad;
pub mod server_conn;
pub mod stats;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_bootstrap;
#[cfg(test)]
mod tests_ec;
#[cfg(test)]
mod tests_ec_shared;
#[cfg(test)]
mod tests_firewall;
#[cfg(test)]
mod tests_server_conn;
