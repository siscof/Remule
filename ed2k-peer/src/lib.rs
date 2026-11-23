// SPDX-License-Identifier: GPL-2.0-or-later
//! The eD2k client-to-client protocol (MIGRATION_PLAN.md, phase 8).
//!
//! * [`hello`]: `OP_HELLO`/`OP_HELLOANSWER` and the old `OP_EMULEINFO`, the
//!   handshake that tells each side what the other supports.
//! * [`part_status`]: the part bitmap of `OP_FILESTATUS` and file requests.
//! * [`packets`]: file requests, hash sets, upload requests, block requests
//!   and the data blocks themselves, built and parsed.
//! * [`sources`]: source exchange (SX1 and SX2) answers, and when to ask.
//! * [`secident`]: secure user identification between two clients.
//!
//! * [`download`]: downloading a file from one peer, as a state machine.
//! * [`upload`]: uploading to one peer, as a state machine.
//!
//! Everything here is sans-IO: bytes in, values out.

pub mod download;
pub mod hello;
pub mod packets;
pub mod part_status;
pub mod secident;
pub mod sources;
pub mod udp;
pub mod upload;

pub use hello::{Hello, MiscOptions1, MiscOptions2, MuleInfo};
pub use packets::{BadPacket, Block, ParseContext, PeerPacket};
pub use part_status::PartStatus;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_download;
#[cfg(test)]
mod tests_sx;
#[cfg(test)]
mod tests_upload;
