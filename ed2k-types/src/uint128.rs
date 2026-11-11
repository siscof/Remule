// SPDX-License-Identifier: GPL-2.0-or-later
//! The 128-bit Kad id. Port of `kademlia/utils/UInt128.{h,cpp}`.
//!
//! `CUInt128` implements 128-bit arithmetic by hand over four 32-bit words.
//! Here it is a native `u128`, so arithmetic and comparison are plain integer
//! operations. What remains are the conventions Kad depends on:
//!
//! * **Bit levels** count from the most significant bit (level 0), which is
//!   how the routing tree walks an id.
//! * **32-bit chunks** count from the most significant chunk (chunk 0).
//! * **Two byte layouts**: big-endian ([`UInt128::from_be_bytes`], as built
//!   from an MD4 hash), and eMule's wire layout of four little-endian 32-bit
//!   chunks, most significant chunk first ([`UInt128::to_wire_bytes`], as
//!   `CFileDataIO::WriteUInt128` and `StoreCryptValue` write it).
//!
//! Like the C++, out-of-range bit or chunk indices read as 0 and writes to
//! them are ignored.

use std::fmt;
use std::ops::{Add, AddAssign, BitXor, BitXorAssign, Shl, ShlAssign, Sub, SubAssign};

use crate::hash::Md4Hash;

/// `Kademlia::CUInt128`. Ordered numerically, as `CompareTo`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct UInt128(u128);

impl UInt128 {
    /// `CUInt128()` / `CUInt128(false)`
    pub const ZERO: UInt128 = UInt128(0);
    /// `CUInt128(true)`: every bit set.
    pub const MAX: UInt128 = UInt128(u128::MAX);

    pub const fn new(v: u128) -> Self {
        UInt128(v)
    }

    pub const fn value(self) -> u128 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// `CUInt128(const uint8_t *valueBE)` / `SetValueBE`.
    pub const fn from_be_bytes(b: [u8; 16]) -> Self {
        UInt128(u128::from_be_bytes(b))
    }

    /// `ToByteArray`.
    pub const fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// `CFileDataIO::ReadUInt128`: four little-endian 32-bit chunks, most
    /// significant chunk first.
    pub fn from_wire_bytes(b: [u8; 16]) -> Self {
        let mut v = UInt128::ZERO;
        for i in 0..4 {
            v.set_chunk(
                i,
                u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]),
            );
        }
        v
    }

    /// `CFileDataIO::WriteUInt128`, and `StoreCryptValue` (the same layout,
    /// which eMule's obfuscation keys are derived from).
    pub fn to_wire_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.chunk(i).to_le_bytes());
        }
        out
    }

    /// `Get32BitChunk`: chunk 0 is the most significant; past 3 reads 0.
    pub const fn chunk(self, i: usize) -> u32 {
        if i < 4 {
            (self.0 >> (32 * (3 - i))) as u32
        } else {
            0
        }
    }

    /// `Set32BitChunk`: ignored past chunk 3.
    pub fn set_chunk(&mut self, i: usize, v: u32) {
        if i < 4 {
            let shift = 32 * (3 - i);
            self.0 = (self.0 & !(u128::from(u32::MAX) << shift)) | (u128::from(v) << shift);
        }
    }

    /// `GetBitNumber`: level 0 is the most significant bit; past 127 reads 0.
    pub const fn bit(self, level: usize) -> bool {
        level <= 127 && (self.0 >> (127 - level)) & 1 == 1
    }

    /// `SetBitNumber`: ignored past level 127.
    pub fn set_bit(&mut self, level: usize, on: bool) {
        if level <= 127 {
            let m = 1u128 << (127 - level);
            if on {
                self.0 |= m;
            } else {
                self.0 &= !m;
            }
        }
    }

    /// `CUInt128(value, numBits)`: keep the `bits` most significant bits of
    /// `self`, take the rest from `random`. The C++ draws them from `rand()`;
    /// here the caller supplies them, which keeps this crate free of I/O and
    /// makes the result testable.
    pub const fn with_prefix_bits(self, bits: u32, random: u128) -> Self {
        if bits >= 128 {
            return self;
        }
        if bits == 0 {
            return UInt128(random);
        }
        let keep = u128::MAX << (128 - bits);
        UInt128((self.0 & keep) | (random & !keep))
    }

    /// The Kad XOR metric: the distance between two ids.
    pub const fn distance(self, other: UInt128) -> UInt128 {
        UInt128(self.0 ^ other.0)
    }

    /// `ToBinaryString`: 128 digits, or with `trim` no leading zeros ("0" for zero).
    pub fn to_binary_string(self, trim: bool) -> String {
        if trim {
            format!("{:b}", self.0)
        } else {
            format!("{:0128b}", self.0)
        }
    }
}

impl From<u32> for UInt128 {
    /// `CUInt128(uint32_t)`
    fn from(v: u32) -> Self {
        UInt128(u128::from(v))
    }
}

impl From<u128> for UInt128 {
    fn from(v: u128) -> Self {
        UInt128(v)
    }
}

impl From<UInt128> for u128 {
    fn from(v: UInt128) -> Self {
        v.0
    }
}

/// A Kad id from an MD4 hash, read big-endian as aMule does
/// (`CUInt128(hash.GetHash())`).
impl From<Md4Hash> for UInt128 {
    fn from(h: Md4Hash) -> Self {
        UInt128::from_be_bytes(h.0)
    }
}

/// `ToHexString`: 32 uppercase hex digits.
impl fmt::Display for UInt128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032X}", self.0)
    }
}

impl fmt::Debug for UInt128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UInt128({self})")
    }
}

// Arithmetic wraps, as the C++ word-by-word carry does.

impl Add for UInt128 {
    type Output = UInt128;
    fn add(self, o: UInt128) -> UInt128 {
        UInt128(self.0.wrapping_add(o.0))
    }
}

impl Sub for UInt128 {
    type Output = UInt128;
    fn sub(self, o: UInt128) -> UInt128 {
        UInt128(self.0.wrapping_sub(o.0))
    }
}

impl BitXor for UInt128 {
    type Output = UInt128;
    fn bitxor(self, o: UInt128) -> UInt128 {
        UInt128(self.0 ^ o.0)
    }
}

/// `operator<<`: shifting by 128 or more gives zero (a plain `u128` shift
/// would overflow).
impl Shl<u32> for UInt128 {
    type Output = UInt128;
    fn shl(self, bits: u32) -> UInt128 {
        UInt128(self.0.checked_shl(bits).unwrap_or(0))
    }
}

impl AddAssign for UInt128 {
    fn add_assign(&mut self, o: UInt128) {
        *self = *self + o;
    }
}

impl SubAssign for UInt128 {
    fn sub_assign(&mut self, o: UInt128) {
        *self = *self - o;
    }
}

impl BitXorAssign for UInt128 {
    fn bitxor_assign(&mut self, o: UInt128) {
        *self = *self ^ o;
    }
}

impl ShlAssign<u32> for UInt128 {
    fn shl_assign(&mut self, bits: u32) {
        *self = *self << bits;
    }
}

/// Ported from aMule's `unittests/tests/CUInt128Test.cpp` (the cases about
/// representation; the operator cases are native `u128` arithmetic here).
#[cfg(test)]
mod tests {
    use super::*;

    const SEQUENCE: [u8; 16] = [
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    ];
    const ONE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const MINUS_ONE: [u8; 16] = [0xff; 16];
    const UINT_VALUE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78];

    fn be(b: [u8; 16]) -> UInt128 {
        UInt128::from_be_bytes(b)
    }

    #[test]
    fn constructor_and_to_byte_array() {
        assert_eq!(be(SEQUENCE).to_be_bytes(), SEQUENCE);
    }

    #[test]
    fn to_hex_string() {
        assert_eq!(be(SEQUENCE).to_string(), "000102030405060708090A0B0C0D0E0F");
    }

    #[test]
    fn to_binary_string() {
        let t = be(SEQUENCE);
        assert_eq!(
            t.to_binary_string(false),
            "00000000000000010000001000000011000001000000010100000110000001110000100000001001000010\
             100000101100001100000011010000111000001111"
        );
        assert_eq!(
            t.to_binary_string(true),
            "10000001000000011000001000000010100000110000001110000100000001001000010100000101100001\
             100000011010000111000001111"
        );
        assert_eq!(UInt128::ZERO.to_binary_string(true), "0");
    }

    #[test]
    fn get_32_bit_chunk() {
        let t = be(SEQUENCE);
        assert_eq!(t.chunk(0), 0x0001_0203);
        assert_eq!(t.chunk(1), 0x0405_0607);
        assert_eq!(t.chunk(2), 0x0809_0a0b);
        assert_eq!(t.chunk(3), 0x0c0d_0e0f);
        assert_eq!(t.chunk(4), 0);
    }

    #[test]
    fn construct_with_bits() {
        let a = be(SEQUENCE);
        let b = be(MINUS_ONE);
        // The test checks only the kept bits, so any random fill must pass.
        for random in [0, u128::MAX, 0x5555_aaaa_5555_aaaa_5555_aaaa_5555_aaaa] {
            assert_eq!(a.with_prefix_bits(1, random).chunk(0) & 0x8000_0000, 0);
            assert_eq!(
                b.with_prefix_bits(1, random).chunk(0) & 0x8000_0000,
                0x8000_0000
            );
            assert_eq!(a.with_prefix_bits(2, random).chunk(0) & 0xc000_0000, 0);
            assert_eq!(
                b.with_prefix_bits(2, random).chunk(0) & 0xc000_0000,
                0xc000_0000
            );
            assert_eq!(a.with_prefix_bits(8, random).chunk(0) & 0xff00_0000, 0);
            assert_eq!(
                b.with_prefix_bits(8, random).chunk(0) & 0xff00_0000,
                0xff00_0000
            );
            assert_eq!(
                a.with_prefix_bits(31, random).chunk(0) & 0xffff_fffe,
                0x0001_0202
            );
            assert_eq!(
                b.with_prefix_bits(31, random).chunk(0) & 0xffff_fffe,
                0xffff_fffe
            );
            assert_eq!(a.with_prefix_bits(32, random).chunk(0), 0x0001_0203);
            assert_eq!(b.with_prefix_bits(32, random).chunk(0), 0xffff_ffff);
            assert_eq!(a.with_prefix_bits(33, random).chunk(1) & 0x8000_0000, 0);
            assert_eq!(
                b.with_prefix_bits(33, random).chunk(1) & 0x8000_0000,
                0x8000_0000
            );
            assert_eq!(a.with_prefix_bits(128, random), a);
            assert_eq!(b.with_prefix_bits(128, random), b);
        }
        assert_eq!(a.with_prefix_bits(0, 7), UInt128::new(7));
        // And the rest really does come from `random`.
        assert_eq!(a.with_prefix_bits(32, 0).chunk(1), 0);
        assert_eq!(a.with_prefix_bits(32, u128::MAX).chunk(1), u32::MAX);
    }

    #[test]
    fn assign_uint32() {
        assert_eq!(UInt128::from(0x1234_5678u32), be(UINT_VALUE));
    }

    #[test]
    fn set_32_bit_chunk() {
        let mut t = UInt128::ZERO;
        t.set_chunk(3, 0x1234_5678);
        assert_eq!(t, be(UINT_VALUE));
        t.set_chunk(0, 0x0001_0203);
        t.set_chunk(1, 0x0405_0607);
        t.set_chunk(2, 0x0809_0a0b);
        t.set_chunk(3, 0x0c0d_0e0f);
        assert_eq!(t, be(SEQUENCE));
        t.set_chunk(4, 0);
        assert_eq!(t, be(SEQUENCE), "out of range is ignored");
    }

    #[test]
    fn set_value_be() {
        let a = be(SEQUENCE);
        assert_eq!(UInt128::from_be_bytes(a.to_be_bytes()), a);
    }

    #[test]
    fn store_crypt_value() {
        let reference = [
            0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4, 0xb, 0xa, 0x9, 0x8, 0xf, 0xe, 0xd, 0xc,
        ];
        assert_eq!(be(SEQUENCE).to_wire_bytes(), reference);
        assert_eq!(UInt128::from_wire_bytes(reference), be(SEQUENCE));
    }

    #[test]
    fn shift_left_assign() {
        let mut t = be(ONE);
        let r1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let r2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        let r3 = [0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let r4 = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        t <<= 0;
        assert_eq!(t, be(ONE));
        t <<= 1;
        assert_eq!(t, be(r1));
        t <<= 32;
        assert_eq!(t, be(r2));
        t <<= 58;
        assert_eq!(t, be(r3));
        assert_eq!(be(ONE) << 127, be(r4));
        assert_eq!(be(ONE) << 128, UInt128::ZERO);
        assert_eq!(be(ONE) << 1000, UInt128::ZERO);
    }

    #[test]
    fn get_bit_number() {
        let mut t = UInt128::from(1u32);
        assert!(!t.bit(0));
        assert!(t.bit(127));
        t <<= 127;
        assert!(t.bit(0));
        assert!(!t.bit(127));
        assert!(!UInt128::MAX.bit(128));
    }

    #[test]
    fn set_bit_number() {
        let mut t = UInt128::ZERO;
        t.set_bit(127, true);
        assert_eq!(t, UInt128::from(1u32));
        t.set_bit(126, true);
        assert_eq!(t, UInt128::from(3u32));
        t.set_bit(127, false);
        assert_eq!(t, UInt128::from(2u32));
        t.set_bit(0, true);
        assert_eq!(t.chunk(0), 0x8000_0000);
        let mut s = be(SEQUENCE);
        s.set_bit(128, true);
        assert_eq!(s, be(SEQUENCE), "out of range is ignored");
    }

    #[test]
    fn arithmetic_wraps_like_the_word_carry() {
        assert_eq!(UInt128::MAX + UInt128::from(1u32), UInt128::ZERO);
        assert_eq!(UInt128::ZERO - UInt128::from(1u32), UInt128::MAX);
        // A carry across every 32-bit word.
        let x = UInt128::new(0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff);
        assert_eq!(
            x + UInt128::from(1u32),
            UInt128::new(0x0000_0001_0000_0000_0000_0000_0000_0000)
        );
        assert_eq!(be(SEQUENCE) ^ be(SEQUENCE), UInt128::ZERO);
    }

    #[test]
    fn ordering_and_distance() {
        assert!(UInt128::from(1u32) < be(SEQUENCE));
        assert!(UInt128::MAX > be(SEQUENCE));
        let (a, b) = (be(SEQUENCE), be(MINUS_ONE));
        assert_eq!(a.distance(b), b.distance(a));
        assert_eq!(a.distance(a), UInt128::ZERO);
        assert_eq!(a.distance(b), a ^ b);
    }

    /// Property check over many values: both byte layouts round-trip, and
    /// chunks, bits and bytes describe the same number.
    #[test]
    fn layouts_and_accessors_agree_for_many_values() {
        let mut x: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C834;
        for _ in 0..10_000 {
            // xorshift128
            x ^= x << 23;
            x ^= x >> 17;
            x ^= x << 26;
            let v = UInt128::new(x);
            assert_eq!(UInt128::from_be_bytes(v.to_be_bytes()), v);
            assert_eq!(UInt128::from_wire_bytes(v.to_wire_bytes()), v);
            let w = v.to_wire_bytes();
            let b = v.to_be_bytes();
            for i in 0..4 {
                // Wire chunk i is BE chunk i with its bytes reversed.
                let mut c = [b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]];
                c.reverse();
                assert_eq!(&w[4 * i..4 * i + 4], &c);
                assert_eq!(
                    v.chunk(i),
                    u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
                );
            }
            for level in [0usize, 1, 31, 32, 63, 64, 100, 127] {
                assert_eq!(v.bit(level), b[level / 8] & (0x80 >> (level % 8)) != 0);
                let mut t = v;
                t.set_bit(level, !v.bit(level));
                assert_eq!(t.distance(v), UInt128::new(1u128 << (127 - level)));
            }
        }
    }

    #[test]
    fn kad_id_from_md4_hash_is_big_endian() {
        assert_eq!(UInt128::from(Md4Hash(SEQUENCE)), be(SEQUENCE));
    }
}
