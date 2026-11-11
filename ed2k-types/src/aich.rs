// SPDX-License-Identifier: GPL-2.0-or-later
//! The 20-byte AICH hash (SHA-1), shown in base32. Port of `CAICHHash`
//! (SHAHashSet.h) and aMule's `EncodeBase32` / `DecodeBase32`.

use std::fmt::{self, Write as _};
use std::str::FromStr;

/// `HASHSIZE`: an AICH hash is a SHA-1.
pub const HASH_LEN: usize = 20;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// An AICH hash (`CAICHHash`): 20 bytes, shown in base32 as aMule and
/// eMule do (`GetString`, `EncodeBase32`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct AichHash(pub [u8; HASH_LEN]);

impl fmt::Display for AichHash {
    /// RFC 4648 base32, upper case, no padding: 32 characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut acc: u32 = 0;
        let mut bits = 0;
        for &b in &self.0 {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                f.write_char(char::from(BASE32[((acc >> bits) & 0x1F) as usize]))?;
            }
        }
        // 160 bits is a multiple of 5: nothing is left over.
        Ok(())
    }
}

impl fmt::Debug for AichHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AichHash({self})")
    }
}

/// A string that is not 32 base32 characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseAichHashError;

impl fmt::Display for ParseAichHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an AICH hash is 32 base32 characters")
    }
}

impl std::error::Error for ParseAichHashError {}

/// `DecodeBase32` into a 20-byte hash: exactly 32 characters, either case.
impl FromStr for AichHash {
    type Err = ParseAichHashError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 {
            return Err(ParseAichHashError);
        }
        let mut out = [0u8; HASH_LEN];
        let mut acc: u32 = 0;
        let mut bits = 0;
        let mut i = 0;
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a',
                b'2'..=b'7' => c - b'2' + 26,
                _ => return Err(ParseAichHashError),
            };
            acc = (acc << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out[i] = (acc >> bits) as u8;
                i += 1;
            }
        }
        Ok(AichHash(out))
    }
}
