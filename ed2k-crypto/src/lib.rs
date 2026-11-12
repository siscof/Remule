// SPDX-License-Identifier: GPL-2.0-or-later
//! eMule protocol crypto (MIGRATION_PLAN.md, phase 4), sans IO.
//!
//! * [`rc4`]: the RC4 of `CRC4EncryptableBuffer`.
//! * [`stream`]: TCP obfuscation, client ↔ client and client → server (DH).
//! * [`udp`]: UDP obfuscation, eD2k and Kad keys, client ↔ server.
//! * [`ident`]: secure user identification, RSA signatures (`rsa` replaces Crypto++).
//! * [`credits`]: the upload credit ratio.
//!
//! None of this is real encryption: the obfuscation keys come from public
//! values, and only make traffic harder to classify.

pub mod credits;
pub mod ident;
pub mod rc4;
pub mod stream;
pub mod udp;

pub use rc4::Rc4;
pub use stream::{Received, StreamCrypt, StreamError};

#[cfg(test)]
mod tests;
