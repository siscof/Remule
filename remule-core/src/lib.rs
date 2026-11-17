// SPDX-License-Identifier: GPL-2.0-or-later
//! remule's client core (MIGRATION_PLAN.md, phase 8 onwards).
//!
//! * [`gap_list`]: the missing ranges of a download (`CGapList`).
//! * [`blocks`]: what to download next: block reservation and chunk
//!   ranking (`BlockReservation.h`, `GetNextRequestedBlock`).
//! * [`part_file`]: a download on disk, `.part` and `.part.met`, resumable
//!   by aMule (`CPartFile`).
//! * [`download_queue`]: the files, their sources and one session per
//!   connection (`CDownloadQueue`), without IO.
//! * [`shared`]: the shared files, `known.met` and `known2_64.met`
//!   (`CSharedFileList`, `CKnownFileList`).
//! * [`upload_queue`]: who gets an upload slot (`CUploadQueue`), without IO.
//! * [`uploader`]: the upload side of a running client, without IO.
//! * [`credits`]: upload and download credits, `clients.met`.
//! * [`ip_filter`]: the IP filter as peers and servers are checked against it.
//! * [`publish`]: what to offer to the server and publish on Kad, and when.
//! * [`downloader`]: the queue on tokio, with peer connections on
//!   `remule-net`.

pub mod blocks;
pub mod credits;
pub mod download_queue;
pub mod downloader;
pub mod gap_list;
pub mod ip_filter;
pub mod part_file;
pub mod publish;
pub mod shared;
pub mod upload_queue;
pub mod uploader;

pub use gap_list::GapList;
pub use part_file::{AichStatus, Completion, FileEvent, OpenError, PartFile, SourceView, Status};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_part_file;
#[cfg(test)]
mod tests_publish;
#[cfg(test)]
mod tests_queue;
#[cfg(test)]
mod tests_shared;
#[cfg(test)]
mod tests_upload_queue;
