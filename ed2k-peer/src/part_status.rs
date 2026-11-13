// SPDX-License-Identifier: GPL-2.0-or-later
//! The part bitmap (`PartStatusWriter.h`, `CUpDownClient::ProcessFileStatus`).
//!
//! On the wire: a `u16` part count, then one bit per part, least significant
//! bit first, the last byte padded with zeros. A count of 0 means "every
//! part": the sender has the whole file.
//!
//! The count is the eD2k part count (`GetED2KPartCount`), which has one more
//! part than the file has when its size is an exact multiple of
//! [`PARTSIZE`](ed2k_types::ed2k::PARTSIZE).

use ed2k_codec::{Reader, Writer};

/// Which parts a peer has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartStatus {
    /// Count 0: the whole file.
    Complete,
    /// One flag per eD2k part.
    Parts(Vec<bool>),
}

impl PartStatus {
    /// Whether the peer has part `i`. Out of range is false, except for a
    /// complete file.
    pub fn has(&self, i: usize) -> bool {
        match self {
            PartStatus::Complete => true,
            PartStatus::Parts(p) => p.get(i).copied().unwrap_or(false),
        }
    }

    /// The part count on the wire (0 for [`PartStatus::Complete`]).
    pub fn wire_count(&self) -> usize {
        match self {
            PartStatus::Complete => 0,
            PartStatus::Parts(p) => p.len(),
        }
    }

    /// `WritePartBitmap`. Panics past 65,535 parts, which no file under
    /// [`MAX_FILE_SIZE`](ed2k_types::ed2k::MAX_FILE_SIZE) reaches.
    pub fn write(&self, w: &mut Writer) {
        match self {
            PartStatus::Complete => {
                w.u16(0);
            }
            PartStatus::Parts(parts) => {
                let count = u16::try_from(parts.len()).expect("over 65,535 parts");
                w.u16(count);
                for chunk in parts.chunks(8) {
                    let byte = chunk
                        .iter()
                        .enumerate()
                        .fold(0u8, |b, (i, &has)| b | (u8::from(has) << i));
                    w.u8(byte);
                }
            }
        }
    }

    /// Read a bitmap. Unlike aMule, which reads as many bits as the file has
    /// parts (`GetPartCount`) and leaves the padding byte of an exact
    /// multiple unread, this reads every byte the count says was written.
    /// Comparing the count against the file is the caller's job.
    pub fn read(r: &mut Reader<'_>) -> Result<PartStatus, ed2k_codec::Error> {
        let count = usize::from(r.u16()?);
        if count == 0 {
            return Ok(PartStatus::Complete);
        }
        let bytes = r.bytes(count.div_ceil(8))?;
        let parts = (0..count)
            .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
            .collect();
        Ok(PartStatus::Parts(parts))
    }
}

/// `GetED2KPartCount`: parts of a file of `size` bytes as eD2k counts them,
/// with an extra empty part when the size is an exact multiple of
/// [`PARTSIZE`](ed2k_types::ed2k::PARTSIZE).
pub fn ed2k_part_count(size: u64) -> u64 {
    size / ed2k_types::ed2k::PARTSIZE + 1
}

/// `GetPartCount`: parts that hold data.
pub fn part_count(size: u64) -> u64 {
    size.div_ceil(ed2k_types::ed2k::PARTSIZE)
}
