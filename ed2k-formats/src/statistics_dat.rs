// SPDX-License-Identifier: GPL-2.0-or-later
//! `statistics.dat`: the bytes sent and received over every session, the
//! cumulative totals aMule's statistics show next to the session's.
//!
//! Port of `CStatistics::Load` and `CStatistics::Save` (Statistics.cpp).
//!
//! Layout: a version byte (0), then the total sent and the total received,
//! each a little-endian `u64`: 17 bytes. On reading, another version leaves
//! both totals at zero. A file cut short is an error aMule logs, keeping
//! what it read before the end (the sent total when only the received one
//! is missing).
//!
//! aMule 2.3.3 also moved the totals of older versions out of `amule.conf`
//! (`[Statistics]` `TotalUploadedBytes` and `TotalDownloadedBytes`, added
//! to the file's and deleted from the config) on its first run; the aMule
//! this port follows no longer reads them, and neither does this module.

/// The file name in the config directory.
pub const FILE_NAME: &str = "statistics.dat";

/// The only version aMule writes and reads.
pub const VERSION: u8 = 0;

/// The cumulative totals, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// `s_totalSent`: file data uploaded.
    pub sent: u64,
    /// `s_totalReceived`: file data downloaded.
    pub received: u64,
}

/// A file cut short; `kept` holds what was read before the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated {
    pub kept: Totals,
}

impl std::fmt::Display for Truncated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("statistics.dat is cut short")
    }
}

impl std::error::Error for Truncated {}

/// The totals in a `statistics.dat` as aMule reads them.
pub fn read(bytes: &[u8]) -> Result<Totals, Truncated> {
    let mut t = Totals::default();
    let Some((&version, rest)) = bytes.split_first() else {
        return Err(Truncated { kept: t });
    };
    if version != VERSION {
        return Ok(t);
    }
    let u64_at = |at: usize| -> Option<u64> {
        rest.get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
    };
    t.sent = u64_at(0).ok_or(Truncated { kept: t })?;
    t.received = u64_at(8).ok_or(Truncated { kept: t })?;
    Ok(t)
}

/// The file aMule writes for `t`.
pub fn write(t: &Totals) -> Vec<u8> {
    let mut v = Vec::with_capacity(17);
    v.push(VERSION);
    v.extend_from_slice(&t.sent.to_le_bytes());
    v.extend_from_slice(&t.received.to_le_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_is_amules() {
        let t = Totals {
            sent: 0x0102_0304_0506_0708,
            received: 0x1112_1314_1516_1718,
        };
        let b = write(&t);
        assert_eq!(
            b,
            [0, 8, 7, 6, 5, 4, 3, 2, 1, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]
        );
        assert_eq!(read(&b), Ok(t));
        assert_eq!(write(&Totals::default()), [0u8; 17]);
        // Trailing bytes are not read.
        let mut longer = b.clone();
        longer.push(0xFF);
        assert_eq!(read(&longer), Ok(t));
    }

    #[test]
    fn other_versions_and_short_files() {
        let b = write(&Totals {
            sent: 5,
            received: 9,
        });
        let mut v1 = b.clone();
        v1[0] = 1;
        assert_eq!(read(&v1), Ok(Totals::default()));
        assert_eq!(
            read(&[]),
            Err(Truncated {
                kept: Totals::default()
            })
        );
        assert_eq!(
            read(&b[..5]),
            Err(Truncated {
                kept: Totals::default()
            })
        );
        // The sent total read before the end is kept.
        assert_eq!(
            read(&b[..12]),
            Err(Truncated {
                kept: Totals {
                    sent: 5,
                    received: 0
                }
            })
        );
        // Another version is not read past its first byte, short or not.
        assert_eq!(read(&[7]), Ok(Totals::default()));
    }
}
