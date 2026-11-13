// SPDX-License-Identifier: GPL-2.0-or-later
//! The eD2k client-to-server protocol (MIGRATION_PLAN.md, phase 6).
//!
//! * [`search`]: the query language, search requests and answers.
//! * [`packets`]: the TCP packets, built and parsed.
//! * [`session`]: the connection as a state machine, without IO.
//! * [`udp`]: UDP pings.
//! * [`client`]: an async connection on `remule-net`.

pub mod client;
pub mod packets;
pub mod search;
pub mod session;
pub mod udp;

pub use client::{ClientError, ConnectOptions, Login, ServerClient};
pub use packets::{LoginInfo, ServerPacket};
pub use search::{SearchParams, SearchResult};
pub use session::{Event, Session, SessionOptions};

#[cfg(test)]
mod tests;
