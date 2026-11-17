// SPDX-License-Identifier: GPL-2.0-or-later
//! Kademlia, Kad2 (MIGRATION_PLAN.md, phase 7, part 1): the routing table,
//! the packets, lookups, keyword and source searches, and answering the
//! requests that keep the network healthy, storing what others publish and
//! answering their searches, flood protection; publishing our own files
//! (phase 9) and the TCP firewall check (phase 10).
//!
//! * [`contact`], [`routing`]: contacts and the routing table (an arena tree).
//! * [`firewall`]: the TCP firewall check's bookkeeping and our public IP.
//! * [`packets`]: Kad2 packets.
//! * [`search`]: the lookup state machine and its results.
//! * [`node`]: the node without IO.
//! * [`driver`]: the node on a tokio UDP socket.
//! * [`prefs`]: the `preferencesKad.dat` file.
//! * [`index`], [`terms`], [`aich`]: what we store for others, and the
//!   search terms matched against it.
//! * [`tracking`]: flood protection.

pub mod aich;
pub mod contact;
pub mod driver;
pub mod firewall;
pub mod index;
pub mod node;
pub mod packets;
pub mod prefs;
pub mod routing;
pub mod search;
pub mod terms;
pub mod tracking;

pub use node::{Config, Event, Kad};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_index;
