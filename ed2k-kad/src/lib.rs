// SPDX-License-Identifier: GPL-2.0-or-later
//! Kademlia, Kad2 (MIGRATION_PLAN.md, phase 7, part 1): the routing table,
//! the packets, lookups, keyword and source searches, and answering the
//! requests that keep the network healthy. Storing and publishing come later.
//!
//! * [`contact`], [`routing`]: contacts and the routing table (an arena tree).
//! * [`packets`]: Kad2 packets.
//! * [`search`]: the lookup state machine and its results.
//! * [`node`]: the node without IO.
//! * [`driver`]: the node on a tokio UDP socket.
//! * [`prefs`]: the `preferencesKad.dat` file.

pub mod contact;
pub mod driver;
pub mod node;
pub mod packets;
pub mod prefs;
pub mod routing;
pub mod search;

pub use node::{Config, Event, Kad};

#[cfg(test)]
mod tests;
