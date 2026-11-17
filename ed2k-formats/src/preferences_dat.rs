// SPDX-License-Identifier: GPL-2.0-or-later
//! `preferences.dat`: our user hash, the identity other clients know us by.
//!
//! Port of `WriteUserHashFile` and the reading in `CPreferences`'s
//! constructor (Preferences.cpp), with `IsBadUserHash` and
//! `CreateUserHash` (UserHash.cpp).
//!
//! Layout: a version byte (`PREFFILE_VERSION` `0x14`, not checked on
//! reading), then the 16-byte hash. Everything else moved to `amule.conf`
//! long ago. A hash of zeros (the two eMule marker bytes aside) is bad: aMule
//! makes a new random one and writes the file again. The markers (byte 5 =
//! 14, byte 14 = 111, which make the hash an eMule one) are set on the hash
//! in memory, not in the file.

use ed2k_codec::Reader;
use ed2k_types::Md4Hash;

/// `PREFFILE_VERSION`
pub const VERSION: u8 = 0x14;

/// The file name in the config directory.
pub const FILE_NAME: &str = "preferences.dat";

/// `USERHASH_MARKER_POS_1`, `USERHASH_MARKER_POS_2` and their values.
const MARKERS: [(usize, u8); 2] = [(5, 14), (14, 111)];

/// The hash stored in a `preferences.dat`, if it has one: a short file has
/// none (aMule logs the error and makes a new hash).
pub fn read(bytes: &[u8]) -> Option<Md4Hash> {
    let mut r = Reader::new(bytes);
    r.u8().ok()?;
    r.hash().ok()
}

/// The file aMule writes for `hash`.
pub fn write(hash: &Md4Hash) -> Vec<u8> {
    let mut v = Vec::with_capacity(17);
    v.push(VERSION);
    v.extend_from_slice(&hash.0);
    v
}

/// `IsBadUserHash`: zeros everywhere but the marker positions.
pub fn is_bad(hash: &Md4Hash) -> bool {
    hash.0
        .iter()
        .enumerate()
        .all(|(i, &b)| b == 0 || MARKERS.iter().any(|&(p, _)| p == i))
}

/// The hash as aMule uses it: with the eMule markers set.
pub fn with_markers(mut hash: Md4Hash) -> Md4Hash {
    for (p, v) in MARKERS {
        hash.0[p] = v;
    }
    hash
}

/// `CreateUserHash`: random bytes from `fill` until the hash is good.
pub fn create(mut fill: impl FnMut(&mut [u8; 16])) -> Md4Hash {
    let mut h = Md4Hash([0; 16]);
    while is_bad(&h) {
        fill(&mut h.0);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ignores_the_version() {
        let h = Md4Hash([0xAB; 16]);
        let b = write(&h);
        assert_eq!(b.len(), 17);
        assert_eq!(b[0], 0x14);
        assert_eq!(read(&b), Some(h));
        let mut other = b.clone();
        other[0] = 0x01;
        assert_eq!(read(&other), Some(h));
        assert_eq!(read(&b[..10]), None);
        assert_eq!(read(&[]), None);
    }

    #[test]
    fn bad_hashes_and_markers() {
        assert!(is_bad(&Md4Hash([0; 16])));
        assert!(is_bad(&with_markers(Md4Hash([0; 16]))));
        let mut h = [0u8; 16];
        h[3] = 1;
        assert!(!is_bad(&Md4Hash(h)));
        let m = with_markers(Md4Hash([0xFF; 16]));
        assert_eq!((m.0[5], m.0[14]), (14, 111));
        assert_eq!(m.0[0], 0xFF);
        // A filler that first gives zeros is asked again.
        let mut calls = 0;
        let h = create(|b| {
            calls += 1;
            *b = if calls == 1 { [0; 16] } else { [7; 16] };
        });
        assert_eq!((calls, h), (2, Md4Hash([7; 16])));
    }
}
