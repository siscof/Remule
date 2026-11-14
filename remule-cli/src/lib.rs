// SPDX-License-Identifier: GPL-2.0-or-later
//! The `remule` command-line tool. Each subcommand is a module, so it can be
//! tested without spawning the binary.

pub mod download;
pub mod inspect;
pub mod kad;
pub mod link;
pub mod server;
pub mod share;
