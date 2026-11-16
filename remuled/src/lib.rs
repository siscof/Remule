// SPDX-License-Identifier: GPL-2.0-or-later
//! `remuled`, the remule daemon (MIGRATION_PLAN.md, phase 10): the client
//! run from an aMule config directory, as `amuled` runs.
//!
//! * [`config`]: an aMule config directory turned into a client's settings.
//! * [`client`]: the running client (also behind `remule download`).
//! * [`kad`]: a Kad node started from, and saved to, aMule's files.

pub mod client;
pub mod config;
pub mod kad;

#[cfg(test)]
mod tests;
