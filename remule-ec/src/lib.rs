// SPDX-License-Identifier: GPL-2.0-or-later
//! aMule's External Connection (EC) protocol, both sides.
//!
//! EC is how `amulegui`, `amulecmd` and the web UI drive the `amuled`
//! daemon. This crate speaks the 3.3 protocol of the aMule-org fork: SRP-6a
//! login over a mandatory X25519 + AEAD channel (`docs/EC_SRP.md`,
//! `docs/EC_Protocol.md`).
//!
//! * [`tag`]: packets and tags, and their wire encoding (sans-IO).
//! * [`crypt`], [`srp`]: the transport keys and the login proofs (sans-IO).
//! * [`client`]: a blocking TCP connection that logs in and sends requests.
//! * [`server`]: the daemon's side of a connection (framing, login,
//!   lockout), sans IO.
//! * [`model`]: typed views of the replies a GUI needs.

pub mod client;
pub mod codes;
pub mod crypt;
#[cfg(any(test, feature = "fake-daemon"))]
pub mod fake;
pub mod model;
pub mod server;
pub mod srp;
pub mod tag;

#[cfg(test)]
mod tests_server;

pub use client::{Client, ConnectOptions, ServerInfo};
pub use tag::{Packet, Tag};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("network error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the daemon closed the connection")]
    Closed,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("access denied: {message}")]
    AuthFailed {
        reason: Option<u8>,
        message: String,
        retry_after: Option<u64>,
    },
    #[error("{0}")]
    Failed(String),
}

impl Error {
    /// True when the connection is unusable and must be re-established.
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Error::Failed(_))
    }
}
