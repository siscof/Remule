// SPDX-License-Identifier: GPL-2.0-or-later
//! Little-endian reading and writing of eD2k values. Port of
//! `SafeFile.{h,cpp}` (`CFileDataIO`).
//!
//! The C++ class sits over a file or a memory buffer and throws on a short
//! read. Here [`Reader`] works over a byte slice and returns
//! [`Error::Eof`] instead, and [`Writer`] appends to a `Vec<u8>`. Files are
//! read into memory first: a `.met` file is small, and packets arrive whole.
//! Nothing here panics on malformed input.

use std::fmt;

use ed2k_types::{Md4Hash, UInt128};

/// A read that ran past the end of the data (`CEOFException`), or a seek
/// to an impossible position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Wanted `wanted` bytes at `at`, but only `available` were left.
    Eof {
        at: usize,
        wanted: usize,
        available: usize,
    },
    /// A seek before the start, or past the end, of the data.
    Seek { to: i128, len: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Eof {
                at,
                wanted,
                available,
            } => {
                write!(
                    f,
                    "read past end: wanted {wanted} bytes at offset {at}, {available} left"
                )
            }
            Error::Seek { to, len } => write!(f, "seek to {to} outside 0..={len}"),
        }
    }
}

impl std::error::Error for Error {}

/// Width of a string's length field (`lenBytes` in the C++).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LenField {
    /// No length field; the caller knows the length (`lenBytes == 0`).
    None,
    /// A `u16` length, the default.
    U16,
    /// A `u32` length.
    U32,
}

/// How a string is written (`EUtf8Str`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrEncoding {
    /// `utf8strNone`: Latin-1. A string with characters beyond U+00FF cannot be
    /// represented and is written empty, as wx's conversion yields nothing.
    Latin1,
    /// `utf8strOptBOM`: UTF-8 after a byte order mark; the length counts it.
    Utf8Bom,
    /// `utf8strRaw`: UTF-8 without a BOM.
    Utf8,
}

/// `BOMHeader`
pub const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Where to seek from (`wxSeekMode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekFrom {
    Start(u64),
    Current(i64),
    End(i64),
}

/// Reads values from a byte slice (`CFileDataIO`'s read side, over a `CMemFile`).
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// `GetPosition`
    pub fn position(&self) -> usize {
        self.pos
    }

    /// `GetLength`
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Bytes left after the position.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// `Eof`: at or past the end.
    pub fn is_eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The bytes not read yet.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// `Seek`. Unlike a file, a slice cannot grow, so seeking past the end
    /// is an error as well as seeking before the start.
    pub fn seek(&mut self, from: SeekFrom) -> Result<usize, Error> {
        let to: i128 = match from {
            SeekFrom::Start(o) => i128::from(o),
            SeekFrom::Current(o) => self.pos as i128 + i128::from(o),
            SeekFrom::End(o) => self.buf.len() as i128 + i128::from(o),
        };
        if to < 0 || to > self.buf.len() as i128 {
            return Err(Error::Seek {
                to,
                len: self.buf.len(),
            });
        }
        self.pos = to as usize;
        Ok(self.pos)
    }

    /// `Read`: exactly `n` bytes, or [`Error::Eof`] with the position unchanged.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining() {
            return Err(Error::Eof {
                at: self.pos,
                wanted: n,
                available: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let b = self.bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }

    /// `ReadUInt8`
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    /// `ReadUInt16`
    pub fn u16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_le_bytes)
    }

    /// `ReadUInt32`
    pub fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_le_bytes)
    }

    /// `ReadUInt64`
    pub fn u64(&mut self) -> Result<u64, Error> {
        self.array().map(u64::from_le_bytes)
    }

    /// `ReadUInt128`: four little-endian `u32` chunks, most significant first.
    pub fn uint128(&mut self) -> Result<UInt128, Error> {
        self.array().map(UInt128::from_wire_bytes)
    }

    /// `ReadHash`
    pub fn hash(&mut self) -> Result<Md4Hash, Error> {
        self.array().map(Md4Hash)
    }

    /// `ReadFloat`: an IEEE 754 single, little-endian.
    pub fn f32(&mut self) -> Result<f32, Error> {
        self.array().map(f32::from_le_bytes)
    }

    /// `ReadBsob`: a byte string with a `u8` length.
    pub fn bsob(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u8()?;
        self.bytes(usize::from(n))
    }

    /// `ReadString`: a length field, then the string (see [`Reader::string_of_len`]).
    ///
    /// With `crop`, the C++ `SafeRead`, a length longer than the data left is
    /// cut to what is left instead of failing.
    ///
    /// Deliberately unlike the C++: a `u32` length above 65535 is read in
    /// full. `ReadOnlyString` takes a `uint16`, so aMule silently truncates
    /// such a length and misreads everything after the string.
    pub fn string(&mut self, opt_utf8: bool, len: LenField, crop: bool) -> Result<String, Error> {
        let start = self.pos;
        let mut n = match len {
            LenField::None => 0,
            LenField::U16 => usize::from(self.u16()?),
            LenField::U32 => self.u32()? as usize,
        };
        if crop {
            n = n.min(self.remaining());
        }
        self.string_of_len(opt_utf8, n)
            .inspect_err(|_| self.pos = start)
    }

    /// `ReadOnlyString`: `len` bytes, decoded as aMule does:
    ///
    /// 1. after a UTF-8 BOM, as UTF-8 (invalid UTF-8 gives an empty string);
    /// 2. else with `opt_utf8`, as UTF-8, falling back to Latin-1 when the
    ///    bytes are not valid UTF-8 or decode to nothing;
    /// 3. else as Latin-1.
    ///
    /// The UTF-8 paths stop at the first NUL byte (the C++ decodes a C
    /// string); the Latin-1 path keeps every byte.
    pub fn string_of_len(&mut self, opt_utf8: bool, len: usize) -> Result<String, Error> {
        let raw = self.bytes(len)?;
        Ok(decode_string(raw, opt_utf8))
    }
}

fn until_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| char::from(c)).collect()
}

/// The decoding of `ReadOnlyString`; see [`Reader::string_of_len`].
pub fn decode_string(raw: &[u8], opt_utf8: bool) -> String {
    if let Some(rest) = raw.strip_prefix(&UTF8_BOM) {
        return std::str::from_utf8(until_nul(rest))
            .map(str::to_owned)
            .unwrap_or_default();
    }
    if opt_utf8 {
        match std::str::from_utf8(until_nul(raw)) {
            Ok(s) if !s.is_empty() => return s.to_owned(),
            _ => {}
        }
    }
    latin1(raw)
}

/// A string's bytes as [`Writer::string`] writes them, without BOM or length
/// field: Latin-1 (empty if not representable) or UTF-8, cut at the first NUL.
fn encode_string_body(s: &str, enc: StrEncoding) -> Vec<u8> {
    let mut encoded: Vec<u8> = match enc {
        StrEncoding::Latin1 => {
            if s.chars().all(|c| u32::from(c) <= 0xFF) {
                s.chars().map(|c| u32::from(c) as u8).collect()
            } else {
                Vec::new()
            }
        }
        StrEncoding::Utf8 | StrEncoding::Utf8Bom => s.as_bytes().to_vec(),
    };
    let n = until_nul(&encoded).len();
    encoded.truncate(n);
    encoded
}

/// How many bytes [`Writer::string`] writes for `s` without a length field,
/// BOM included (`GetRawSize`, but measured in the encoding actually written:
/// the C++ measures Latin-1 strings in the locale's charset, which can
/// disagree with the bytes it then writes).
pub fn encoded_len(s: &str, enc: StrEncoding) -> usize {
    let bom = if enc == StrEncoding::Utf8Bom {
        UTF8_BOM.len()
    } else {
        0
    };
    bom + encode_string_body(s, enc).len()
}

/// Writes values to a growing buffer (`CFileDataIO`'s write side, over a
/// `CMemFile`).
#[derive(Clone, Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// `Write`
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// `WriteUInt8`
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    /// `WriteUInt16`
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    /// `WriteUInt32`
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    /// `WriteUInt64`
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    /// `WriteUInt128`
    pub fn uint128(&mut self, v: UInt128) -> &mut Self {
        self.bytes(&v.to_wire_bytes())
    }

    /// `WriteHash`
    pub fn hash(&mut self, h: Md4Hash) -> &mut Self {
        self.bytes(&h.0)
    }

    /// `WriteFloat`
    pub fn f32(&mut self, v: f32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    /// `WriteBsob`. The length is a `u8`, so at most 255 bytes are written;
    /// the C++ caller passes a `uint8` size and cannot ask for more.
    pub fn bsob(&mut self, b: &[u8]) -> &mut Self {
        let n = b.len().min(255);
        self.u8(n as u8).bytes(&b[..n])
    }

    /// `WriteString`. The string ends at its first NUL (the C++ measures it
    /// with `strlen`). With a `u16` length field, the bytes, BOM included,
    /// are capped at 0xFFFF; this can cut a UTF-8 character in half, as in
    /// aMule, so that a peer cannot make us emit an inconsistent length.
    pub fn string(&mut self, s: &str, enc: StrEncoding, len: LenField) -> &mut Self {
        let encoded = encode_string_body(s, enc);
        let mut body = &encoded[..];
        let bom = if enc == StrEncoding::Utf8Bom {
            UTF8_BOM.len()
        } else {
            0
        };
        let mut real_len = body.len() + bom;
        match len {
            LenField::None => {}
            LenField::U16 => {
                if real_len > 0xFFFF {
                    real_len = 0xFFFF;
                    body = &body[..real_len - bom];
                }
                self.u16(real_len as u16);
            }
            LenField::U32 => {
                self.u32(real_len as u32);
            }
        }
        if bom > 0 {
            self.bytes(&UTF8_BOM);
        }
        self.bytes(body)
    }
}

/// Ported from aMule's `unittests/tests/FileDataIOTest.cpp`.
#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LENGTH: usize = 512;

    fn predef() -> Vec<u8> {
        (0..TEST_LENGTH).map(|j| j as u8).collect()
    }

    // The value each type has at offset j of the predefined data (genValue).
    fn u16_at(j: usize) -> u16 {
        ((((j + 1) & 0xff) << 8) | (j & 0xff)) as u16
    }
    fn u32_at(j: usize) -> u32 {
        ((((j + 3) & 0xff) << 24) | (((j + 2) & 0xff) << 16) | (((j + 1) & 0xff) << 8) | (j & 0xff))
            as u32
    }
    fn hash_at(j: usize) -> Md4Hash {
        let mut h = [0u8; 16];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (j + i) as u8;
        }
        Md4Hash(h)
    }
    fn uint128_at(j: usize) -> UInt128 {
        let mut v = UInt128::ZERO;
        for y in (0..16).step_by(4) {
            v.set_chunk(
                y >> 2,
                ((j + y) & 0xff) as u32
                    | (((j + y + 1) & 0xff) as u32) << 8
                    | (((j + y + 2) & 0xff) as u32) << 16
                    | (((j + y + 3) & 0xff) as u32) << 24,
            );
        }
        v
    }

    /// ReadTest: every offset reads the generated value, and the last
    /// partial value is an EOF with the position unchanged.
    #[test]
    fn read_test_every_type_at_every_offset() {
        let data = predef();
        for j in 0..=TEST_LENGTH {
            let mut r = Reader::new(&data);
            r.seek(SeekFrom::Start(j as u64)).unwrap();
            let left = TEST_LENGTH - j;
            assert_eq!(r.clone().u8().ok(), (left >= 1).then_some(j as u8));
            assert_eq!(r.clone().u16().ok(), (left >= 2).then(|| u16_at(j)));
            assert_eq!(r.clone().u32().ok(), (left >= 4).then(|| u32_at(j)));
            assert_eq!(r.clone().hash().ok(), (left >= 16).then(|| hash_at(j)));
            assert_eq!(
                r.clone().uint128().ok(),
                (left >= 16).then(|| uint128_at(j))
            );
            let mut short = r.clone();
            if left < 16 {
                assert_eq!(
                    short.hash(),
                    Err(Error::Eof {
                        at: j,
                        wanted: 16,
                        available: left
                    })
                );
                assert_eq!(short.position(), j, "a failed read leaves the position");
            }
        }
    }

    /// WriteTest: writing the generated values reproduces the predefined data.
    #[test]
    fn write_test_every_type() {
        let data = predef();
        let mut w = Writer::new();
        for j in (0..TEST_LENGTH).step_by(2) {
            w.u16(u16_at(j));
        }
        assert_eq!(w.as_bytes(), &data[..]);
        let mut w = Writer::new();
        for j in (0..TEST_LENGTH).step_by(4) {
            w.u32(u32_at(j));
        }
        assert_eq!(w.as_bytes(), &data[..]);
        let mut w = Writer::new();
        for j in (0..TEST_LENGTH).step_by(16) {
            w.hash(hash_at(j));
        }
        assert_eq!(w.as_bytes(), &data[..]);
        let mut w = Writer::new();
        for j in (0..TEST_LENGTH).step_by(16) {
            w.uint128(uint128_at(j));
        }
        assert_eq!(w.as_bytes(), &data[..]);
    }

    /// StringTest: lengths per encoding, the BOM header, and round trips with
    /// both length widths.
    #[test]
    fn string_test() {
        // (string, Latin-1 length, UTF-8 length)
        let data = [
            ("0123456789abcdef", 16, 16),
            ("", 0, 0),
            ("abc ø def æ ghi å", 17, 20),
            ("aáeéuúó", 7, 11),
            ("uüoöÿeëaäyÿ", 11, 17),
        ];
        for (s, latin_len, utf8_len) in data {
            for enc in [StrEncoding::Latin1, StrEncoding::Utf8Bom, StrEncoding::Utf8] {
                let str_len = if enc == StrEncoding::Latin1 {
                    latin_len
                } else {
                    utf8_len
                };
                let head: &[u8] = if enc == StrEncoding::Utf8Bom {
                    &UTF8_BOM
                } else {
                    &[]
                };
                // ReadString(encodings[enc].id, ...) passes the enum as bOptUTF8.
                let opt_utf8 = enc != StrEncoding::Latin1;
                for (len, width) in [(LenField::U16, 2), (LenField::U32, 4)] {
                    let mut w = Writer::new();
                    w.string(s, enc, len);
                    let out = w.into_bytes();
                    assert_eq!(out.len(), str_len + width + head.len(), "{s:?} {enc:?}");
                    let mut r = Reader::new(&out);
                    let n = if width == 2 {
                        usize::from(r.u16().unwrap())
                    } else {
                        r.u32().unwrap() as usize
                    };
                    assert_eq!(n, str_len + head.len());
                    assert_eq!(r.bytes(head.len()).unwrap(), head);
                    assert_eq!(
                        Reader::new(&out).string(opt_utf8, len, false).unwrap(),
                        s,
                        "{enc:?}"
                    );
                }
            }
        }
    }

    /// StringTest, "poisoning": a string whose UTF-8 form overflows the u16
    /// length is cut to 0xFFFF bytes, so the next field still lines up.
    #[test]
    fn string_poisoning_is_guarded() {
        let raw_len = (usize::from(u16::MAX) * 3) / 4;
        let bad: String = std::iter::repeat_n('\u{fe}', raw_len).collect();
        for enc in [StrEncoding::Latin1, StrEncoding::Utf8Bom, StrEncoding::Utf8] {
            let mut w = Writer::new();
            w.string(&bad, enc, LenField::U16).u16(0x7913);
            let out = w.into_bytes();
            let mut r = Reader::new(&out);
            r.string(true, LenField::U16, false).unwrap();
            assert_eq!(r.u16().unwrap(), 0x7913, "{enc:?}");
        }
    }

    #[test]
    fn decoding_rules() {
        // BOM wins, even without opt_utf8.
        assert_eq!(decode_string(b"\xEF\xBB\xBFh\xC3\xA9", false), "hé");
        // Invalid UTF-8 after a BOM gives nothing (no Latin-1 fallback there).
        assert_eq!(decode_string(b"\xEF\xBB\xBF\xFF", true), "");
        // opt_utf8 falls back to Latin-1 for invalid UTF-8.
        assert_eq!(decode_string(b"caf\xE9", true), "café");
        assert_eq!(decode_string(b"caf\xC3\xA9", true), "café");
        // Without opt_utf8 it is Latin-1, UTF-8 or not.
        assert_eq!(decode_string(b"caf\xC3\xA9", false), "cafÃ©");
        // UTF-8 stops at a NUL; Latin-1 keeps it.
        assert_eq!(decode_string(b"ab\0cd", true), "ab");
        assert_eq!(decode_string(b"ab\0cd", false), "ab\0cd");
        // A UTF-8 string that is empty up to its NUL falls back to Latin-1.
        assert_eq!(decode_string(b"\0x", true), "\0x");
    }

    #[test]
    fn writing_rules() {
        let mut w = Writer::new();
        w.string("snow ☃", StrEncoding::Latin1, LenField::U16);
        assert_eq!(
            w.as_bytes(),
            [0, 0],
            "not representable in Latin-1: written empty"
        );
        let mut w = Writer::new();
        w.string("ab\0cd", StrEncoding::Utf8, LenField::U16);
        assert_eq!(
            w.as_bytes(),
            [2, 0, b'a', b'b'],
            "ends at the NUL, like strlen"
        );
        let mut w = Writer::new();
        w.string("abc", StrEncoding::Utf8, LenField::None);
        assert_eq!(w.as_bytes(), b"abc");
        let mut w = Writer::new();
        w.string("", StrEncoding::Utf8Bom, LenField::U16);
        assert_eq!(
            w.as_bytes(),
            [3, 0, 0xEF, 0xBB, 0xBF],
            "the BOM is written even when empty"
        );
    }

    #[test]
    fn long_u32_strings_are_read_in_full() {
        let s = "x".repeat(70_000);
        let mut w = Writer::new();
        w.string(&s, StrEncoding::Utf8, LenField::U32).u8(0xAA);
        let out = w.into_bytes();
        let mut r = Reader::new(&out);
        assert_eq!(r.string(true, LenField::U32, false).unwrap().len(), 70_000);
        assert_eq!(r.u8().unwrap(), 0xAA);
    }

    #[test]
    fn crop_and_failed_string_reads() {
        // Length says 10, only 3 bytes follow.
        let data = [10u8, 0, b'a', b'b', b'c'];
        assert_eq!(
            Reader::new(&data)
                .string(true, LenField::U16, true)
                .unwrap(),
            "abc"
        );
        let mut r = Reader::new(&data);
        assert!(matches!(
            r.string(true, LenField::U16, false),
            Err(Error::Eof { .. })
        ));
        assert_eq!(
            r.position(),
            0,
            "a failed string read rewinds past its length field"
        );
    }

    #[test]
    fn bsob_float_and_seek() {
        let mut w = Writer::new();
        w.bsob(&[1, 2, 3]).f32(1.5).bsob(&[7u8; 300]);
        let out = w.into_bytes();
        assert_eq!(&out[..4], [3, 1, 2, 3]);
        assert_eq!(&out[4..8], 1.5f32.to_le_bytes());
        let mut r = Reader::new(&out);
        assert_eq!(r.bsob().unwrap(), [1, 2, 3]);
        assert_eq!(r.f32().unwrap(), 1.5);
        assert_eq!(
            r.bsob().unwrap().len(),
            255,
            "a bsob holds at most 255 bytes"
        );
        assert!(r.is_eof());
        assert_eq!(r.seek(SeekFrom::End(-4)).unwrap(), out.len() - 4);
        assert_eq!(r.seek(SeekFrom::Current(-1)).unwrap(), out.len() - 5);
        assert!(r.seek(SeekFrom::Current(-10_000)).is_err());
        assert!(r.seek(SeekFrom::End(1)).is_err());
        assert_eq!(
            r.position(),
            out.len() - 5,
            "a failed seek leaves the position"
        );
    }
}
