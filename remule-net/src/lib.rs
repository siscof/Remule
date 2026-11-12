// SPDX-License-Identifier: GPL-2.0-or-later
//! remule's async networking runtime (MIGRATION_PLAN.md, phase 5), on tokio.
//!
//! * [`codec`]: eD2k TCP framing for `tokio_util::codec`.
//! * [`conn`]: a connection: obfuscation handshake, then a packet reader and
//!   writer that run apart, both throttled.
//! * [`throttle`]: the global upload and download buckets.
//! * [`limits`]: connection limits and a listener that honours them.
//! * [`udp`]: a throttled UDP socket.

pub mod codec;
pub mod conn;
pub mod limits;
pub mod throttle;
pub mod udp;

pub use codec::{CodecError, PacketCodec};
pub use conn::{establish, ConnConfig, Handshake, NetError, PacketReader, PacketWriter};
pub use limits::{ConnectionLimiter, ConnectionLimits, Listener, Permit};
pub use throttle::{Bandwidth, Priority, RateLimiter};
pub use udp::UdpEndpoint;

#[cfg(test)]
mod tests;
