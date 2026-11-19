// SPDX-License-Identifier: GPL-2.0-or-later
//! `RLE_Data` (`RLE.cpp`): how EC sends a download's bars (gaps, requested
//! blocks, part availability) in incremental updates. Each side keeps the
//! last state; what goes over is the XOR with it, run-length encoded: a
//! byte that repeats is written twice and followed by the run length
//! (at most 255), any other byte as itself.
//!
//! The encoder and decoder must start from the same state: one per object
//! per connection, reset when either side starts over.

/// One stream's state, encoder or decoder side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RleData {
    /// The last data (encoder) or the decoded data (decoder).
    buff: Vec<u8>,
    /// XOR with the last data before encoding (`m_use_diff`).
    use_diff: bool,
}

impl RleData {
    /// `RLE_Data(0, use_diff)`.
    pub fn new(use_diff: bool) -> Self {
        RleData {
            buff: Vec::new(),
            use_diff,
        }
    }

    /// `ResetEncoder`: start over from nothing.
    pub fn reset(&mut self) {
        self.buff.clear();
    }

    /// The decoded (or last encoded) bytes.
    pub fn buffer(&self) -> &[u8] {
        &self.buff
    }

    /// `Realloc`: keep the common prefix, zero-fill the rest. True if the
    /// size changed.
    fn realloc(&mut self, size: usize) -> bool {
        if size == self.buff.len() {
            return false;
        }
        self.buff.resize(size, 0);
        true
    }

    /// `Encode(const uint8 *, ...)`: the encoded bytes, and whether
    /// anything changed (size, or any byte when diffing).
    pub fn encode_bytes(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let mut changed = self.realloc(data.len());
        if self.buff.is_empty() {
            return (Vec::new(), changed);
        }
        if self.use_diff {
            for (b, d) in self.buff.iter_mut().zip(data) {
                *b ^= d;
                if *b != 0 {
                    changed = true;
                }
            }
        } else {
            self.buff.copy_from_slice(data);
            changed = true;
        }
        let mut out = Vec::with_capacity(self.buff.len() * 3 / 2 + 1);
        let mut i = 0;
        while i < self.buff.len() {
            let v = self.buff[i];
            let start = i;
            while i < self.buff.len() && self.buff[i] == v && i - start < 0xFF {
                i += 1;
            }
            if i - start > 1 {
                out.extend_from_slice(&[v, v, (i - start) as u8]);
            } else {
                out.push(v);
            }
        }
        if self.use_diff {
            self.buff.copy_from_slice(data);
        }
        (out, changed)
    }

    /// `Encode(const ArrayOfUInts16 &, ...)`: each value capped at 255.
    pub fn encode_u16(&mut self, data: &[u16]) -> (Vec<u8>, bool) {
        let bytes: Vec<u8> = data.iter().map(|&v| v.min(0xFF) as u8).collect();
        self.encode_bytes(&bytes)
    }

    /// `Encode(const ArrayOfUInts64 &, ...)`: all the low bytes first, then
    /// all the second bytes, and so on, so equal high bytes make runs.
    pub fn encode_u64(&mut self, data: &[u64]) -> (Vec<u8>, bool) {
        let n = data.len();
        let mut bytes = vec![0u8; n * 8];
        for (i, &v) in data.iter().enumerate() {
            for j in 0..8 {
                bytes[i + j * n] = (v >> (8 * j)) as u8;
            }
        }
        self.encode_bytes(&bytes)
    }

    /// `Decode(const uint8 *, int)`: apply one encoded update and return
    /// the current data. The size follows what the update decodes to.
    pub fn decode(&mut self, enc: &[u8]) -> &[u8] {
        let mut dec = Vec::new();
        let mut i = 0;
        while i < enc.len() {
            if i + 2 < enc.len() && enc[i + 1] == enc[i] {
                dec.extend(std::iter::repeat_n(enc[i], usize::from(enc[i + 2])));
                i += 3;
            } else {
                dec.push(enc[i]);
                i += 1;
            }
        }
        self.realloc(dec.len());
        if self.use_diff {
            for (b, d) in self.buff.iter_mut().zip(&dec) {
                *b ^= d;
            }
        } else {
            self.buff.copy_from_slice(&dec);
        }
        &self.buff
    }

    /// `Decode(..., ArrayOfUInts64 &)`.
    pub fn decode_u64(&mut self, enc: &[u8]) -> Vec<u64> {
        let b = self.decode(enc);
        let n = b.len() / 8;
        (0..n)
            .map(|i| {
                (0..8)
                    .rev()
                    .fold(0u64, |u, j| (u << 8) | u64::from(b[i + j * n]))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_are_written_twice_with_their_length() {
        let mut e = RleData::new(false);
        let (out, changed) = e.encode_bytes(&[7, 7, 7, 1, 2, 2]);
        assert!(changed);
        assert_eq!(out, [7, 7, 3, 1, 2, 2, 2]);
        // A run longer than 255 is cut.
        let (out, _) = e.encode_bytes(&[0u8; 300]);
        assert_eq!(out, [0, 0, 255, 0, 0, 45]);
        let mut d = RleData::new(false);
        assert_eq!(d.decode(&out), &[0u8; 300][..]);
    }

    #[test]
    fn the_diff_only_says_what_changed() {
        let mut e = RleData::new(true);
        let mut d = RleData::new(true);
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let (out, changed) = e.encode_bytes(&a);
        assert!(changed);
        assert_eq!(d.decode(&out), &a);
        // The same again: all zeros, not changed.
        let (out, changed) = e.encode_bytes(&a);
        assert!(!changed);
        assert_eq!(out, [0, 0, 8]);
        assert_eq!(d.decode(&out), &a);
        // One byte different.
        let b = [1u8, 2, 3, 9, 5, 6, 7, 8];
        let (out, changed) = e.encode_bytes(&b);
        assert!(changed);
        assert_eq!(out, [0, 0, 3, 4 ^ 9, 0, 0, 4]);
        assert_eq!(d.decode(&out), &b);
        // Longer: the new tail against zeros; shorter: the prefix kept.
        let c = [1u8, 2, 3, 9, 5, 6, 7, 8, 10, 11];
        let (out, changed) = e.encode_bytes(&c);
        assert!(changed);
        assert_eq!(d.decode(&out), &c);
        let (out, changed) = e.encode_bytes(&c[..4]);
        assert!(changed, "a size change is a change");
        assert_eq!(d.decode(&out), &c[..4]);
        // Nothing: empty.
        let (out, changed) = e.encode_bytes(&[]);
        assert!(changed && out.is_empty());
        e.reset();
        let (out, _) = e.encode_bytes(&a);
        let mut fresh = RleData::new(true);
        assert_eq!(fresh.decode(&out), &a, "after a reset, from nothing");
    }

    #[test]
    fn u64_values_go_by_byte_planes() {
        // RLE.cpp's own example.
        let mut e = RleData::new(false);
        let (out, _) = e.encode_u64(&[0x0000_0304_5A6A_7A8A, 0x0000_0304_5B6B_7B8B]);
        let mut d = RleData::new(false);
        assert_eq!(
            d.decode(&out),
            &[0x8A, 0x8B, 0x7A, 0x7B, 0x6A, 0x6B, 0x5A, 0x5B, 0x04, 0x04, 0x03, 0x03, 0, 0, 0, 0]
        );
        let gaps = [0u64, 9_728_000, 12_000_000, 21_000_000];
        let mut e = RleData::new(true);
        let mut d = RleData::new(true);
        let (out, _) = e.encode_u64(&gaps);
        assert_eq!(d.decode_u64(&out), gaps);
        let (out, _) = e.encode_u64(&gaps[2..]);
        assert_eq!(d.decode_u64(&out), &gaps[2..]);
        // Part frequencies: capped at 255.
        let mut e = RleData::new(true);
        let (out, _) = e.encode_u16(&[1, 300, 0]);
        let mut d = RleData::new(true);
        assert_eq!(d.decode(&out), &[1, 255, 0]);
    }

    #[test]
    fn a_dangling_pair_reads_as_single_bytes() {
        // Two equal bytes at the very end have no length: two single bytes.
        let mut d = RleData::new(false);
        assert_eq!(d.decode(&[5, 9, 9]), &[5, 9, 9]);
    }
}
