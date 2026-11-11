// SPDX-License-Identifier: GPL-2.0-or-later
//! eD2k byte codec (MIGRATION_PLAN.md, phase 1).
//!
//! * [`io`]: little-endian values and strings over byte buffers, the port of
//!   `SafeFile.{h,cpp}` (step 1.3).
//!
//! Tags (`Tag.cpp`, step 1.4) and packets (`Packet.cpp`, step 1.5) build on
//! it. Sans-IO: everything works on in-memory buffers.

pub mod io;

pub use io::{Error, LenField, Reader, SeekFrom, StrEncoding, Writer};
