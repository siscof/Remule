// SPDX-License-Identifier: GPL-2.0-or-later
//! The 16-byte MD4 hash that names files and users. Port of `MD4Hash.h`.

use std::fmt;
use std::str::FromStr;

/// `CMD4Hash`: 16 bytes, no terminator. Ordered byte by byte, as the C++
/// `operator<`, so it can key a `BTreeMap`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Md4Hash(pub [u8; Md4Hash::LEN]);

impl Md4Hash {
    /// `MD4HASH_LENGTH`
    pub const LEN: usize = 16;
    /// The all-zero hash that `CMD4Hash()` and `Clear()` produce.
    pub const EMPTY: Md4Hash = Md4Hash([0; Md4Hash::LEN]);

    /// `IsEmpty`: every byte zero.
    pub fn is_empty(&self) -> bool {
        self.0 == [0; Self::LEN]
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// From a slice that must be exactly 16 bytes long.
    pub fn from_slice(b: &[u8]) -> Option<Md4Hash> {
        b.try_into().ok().map(Md4Hash)
    }
}

impl From<[u8; Md4Hash::LEN]> for Md4Hash {
    fn from(b: [u8; Md4Hash::LEN]) -> Self {
        Md4Hash(b)
    }
}

impl From<Md4Hash> for [u8; Md4Hash::LEN] {
    fn from(h: Md4Hash) -> Self {
        h.0
    }
}

impl AsRef<[u8]> for Md4Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// `EncodeSTL`: 32 uppercase hex digits.
impl fmt::Display for Md4Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Md4Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Md4Hash({self})")
    }
}

/// A string that is not 32 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseHashError;

impl fmt::Display for ParseHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an MD4 hash is 32 hexadecimal digits")
    }
}

impl std::error::Error for ParseHashError {}

/// `Decode`: exactly 32 hex digits, either case.
impl FromStr for Md4Hash {
    type Err = ParseHashError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.as_bytes();
        if s.len() != 2 * Self::LEN {
            return Err(ParseHashError);
        }
        let nibble = |c: u8| (c as char).to_digit(16).ok_or(ParseHashError);
        let mut out = [0u8; Self::LEN];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (nibble(s[2 * i])? << 4 | nibble(s[2 * i + 1])?) as u8;
        }
        Ok(Md4Hash(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQ: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    fn encode_is_uppercase_and_decode_takes_either_case() {
        let h = Md4Hash(SEQ);
        assert_eq!(h.to_string(), "000102030405060708090A0B0C0D0E0F");
        assert_eq!("000102030405060708090a0b0c0d0e0f".parse(), Ok(h));
        assert_eq!(h.to_string().parse(), Ok(h));
        assert_eq!(
            format!("{h:?}"),
            "Md4Hash(000102030405060708090A0B0C0D0E0F)"
        );
    }

    #[test]
    fn decode_rejects_what_cmd4hash_rejects() {
        assert_eq!("".parse::<Md4Hash>(), Err(ParseHashError));
        assert_eq!(
            "000102030405060708090A0B0C0D0E0".parse::<Md4Hash>(),
            Err(ParseHashError)
        );
        assert_eq!(
            "000102030405060708090A0B0C0D0E0F0".parse::<Md4Hash>(),
            Err(ParseHashError)
        );
        assert_eq!(
            "000102030405060708090A0B0C0D0E0G".parse::<Md4Hash>(),
            Err(ParseHashError)
        );
        assert_eq!(
            "+00102030405060708090A0B0C0D0E0F".parse::<Md4Hash>(),
            Err(ParseHashError)
        );
        // Multi-byte UTF-8 of the right byte length is still not hex.
        assert_eq!("ééééééééééééééee".parse::<Md4Hash>(), Err(ParseHashError));
    }

    #[test]
    fn empty_and_ordering() {
        assert!(Md4Hash::EMPTY.is_empty());
        assert!(Md4Hash::default().is_empty());
        assert!(!Md4Hash(SEQ).is_empty());
        // Byte-wise, like CMD4Hash::operator<: the first byte decides.
        let mut a = [0u8; 16];
        a[0] = 1;
        let mut b = [0xFFu8; 16];
        b[0] = 0;
        assert!(Md4Hash(b) < Md4Hash(a));
        assert_eq!(Md4Hash::from_slice(&SEQ), Some(Md4Hash(SEQ)));
        assert_eq!(Md4Hash::from_slice(&SEQ[1..]), None);
    }
}
