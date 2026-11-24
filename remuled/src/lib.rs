// SPDX-License-Identifier: GPL-2.0-or-later
//! `remuled`, the remule daemon (MIGRATION_PLAN.md, phase 10): the client
//! run from an aMule config directory, as `amuled` runs.
//!
//! * [`config`]: an aMule config directory turned into a client's settings.
//! * [`client`]: the running client (also behind `remule download`).
//! * [`kad`]: a Kad node started from, and saved to, aMule's files.
//! * [`friends`]: the friend list, `emfriends.met`.
//! * [`firewall`]: whether others can reach us; answering Kad's firewall
//!   checks over TCP.
//! * [`applog`]: the log as External Connections read it.
//! * [`bootstrap`]: `nodes.dat` and server lists fetched over HTTP at start.
//! * [`http`]: one file over HTTP(S).
//! * [`server_conn`]: which eD2k server to log into next, and when.
//! * [`stats`]: the transfer statistics in `statistics.dat` and in the log.
//! * [`graphs`]: the history the statistics graphs are drawn from.
//! * [`ec`]: external connections, for `amulecmd` and `amulegui`.
//! * [`ec_search`]: searches over external connections.
//! * [`ec_servers`]: the server list and the networks over them.
//! * [`ec_shared`]: shared files over external connections.
//! * [`ec_stats`]: the statistics tree.
//! * [`ec_update`]: `amulegui`'s incremental updates, and the preferences.
//! * [`prefs`]: the preferences over external connections, kept in
//!   `amule.conf`.
//! * [`version_check`]: whether a newer release is out.

pub mod applog;
pub mod bootstrap;
pub mod client;
pub mod config;
pub mod disk;
pub mod ec;
pub mod ec_search;
pub mod ec_servers;
pub mod ec_shared;
pub mod ec_stats;
pub mod ec_update;
pub mod firewall;
pub mod friends;
pub mod graphs;
pub mod http;
pub mod kad;
pub mod prefs;
pub mod server_conn;
pub mod server_stats;
pub mod server_udp;
pub mod stats;
pub mod udp_port;
pub mod version_check;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_applog;
#[cfg(test)]
mod tests_bootstrap;
#[cfg(test)]
mod tests_ec;
#[cfg(test)]
mod tests_ec_more;
#[cfg(test)]
mod tests_ec_search;
#[cfg(test)]
mod tests_ec_servers;
#[cfg(test)]
mod tests_ec_shared;
#[cfg(test)]
mod tests_ec_stats;
#[cfg(test)]
mod tests_ec_update;
#[cfg(test)]
mod tests_firewall;
#[cfg(test)]
mod tests_graphs;
#[cfg(test)]
mod tests_prefs;
#[cfg(test)]
mod tests_server_conn;
