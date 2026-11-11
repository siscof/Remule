// SPDX-License-Identifier: GPL-2.0-or-later
//! eD2k byte codec (MIGRATION_PLAN.md, phase 1).
//!
//! * [`io`]: little-endian values and strings over byte buffers, the port of
//!   `SafeFile.{h,cpp}` (step 1.3).
//!
//! * [`tag`]: tags in their eD2k and Kad encodings, the port of `Tag.{h,cpp}`
//!   (step 1.4).
//!
//! Packets (`Packet.cpp`, step 1.5) build on these. Sans-IO: everything
//! works on in-memory buffers.

pub mod io;
pub mod tag;

pub use io::{Error, LenField, Reader, SeekFrom, StrEncoding, Writer};
pub use tag::{Tag, TagError, TagName, TagValue};
