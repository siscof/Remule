// SPDX-License-Identifier: GPL-2.0-or-later
//! RC4, as `CRC4EncryptableBuffer` (RC4Encrypt.cpp) uses it.

use md5::{Digest, Md5};

/// An RC4 stream. Encrypting and decrypting are the same operation.
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    x: u8,
    y: u8,
}

impl std::fmt::Debug for Rc4 {
    /// Never prints the state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rc4")
    }
}

/// The keystream bytes eMule drops after keying a TCP stream.
pub const TCP_DISCARD: usize = 1024;

impl Rc4 {
    /// `RC4CreateKey(key, len, bSkipDiscard = true)`: plain RC4, nothing
    /// discarded. An empty key is treated as one zero byte.
    pub fn new(key: &[u8]) -> Self {
        let key = if key.is_empty() { &[0u8][..] } else { key };
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(key[i % key.len()]).wrapping_add(s[i]);
            s.swap(i, j as usize);
        }
        Rc4 { s, x: 0, y: 0 }
    }

    /// `SetKey(md5, bSkipDiscard)`: keyed with an MD5 digest; TCP streams
    /// (`discard`) drop the first [`TCP_DISCARD`] bytes, UDP packets do not.
    pub fn from_md5(digest: [u8; 16], discard: bool) -> Self {
        let mut r = Rc4::new(&digest);
        if discard {
            r.skip(TCP_DISCARD);
        }
        r
    }

    /// The key MD5(`data`).
    pub fn from_md5_of(data: &[u8], discard: bool) -> Self {
        Rc4::from_md5(Md5::digest(data).into(), discard)
    }

    #[inline]
    fn next(&mut self) -> u8 {
        self.x = self.x.wrapping_add(1);
        let a = self.s[self.x as usize];
        self.y = self.y.wrapping_add(a);
        let b = self.s[self.y as usize];
        self.s[self.x as usize] = b;
        self.s[self.y as usize] = a;
        self.s[a.wrapping_add(b) as usize]
    }

    /// XOR `data` with the keystream, in place.
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            *b ^= self.next();
        }
    }

    /// `data`, encrypted (or decrypted).
    pub fn crypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        self.apply(&mut v);
        v
    }

    /// Advance the stream by `n` bytes (`RC4Crypt(NULL, NULL, n)`).
    pub fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.next();
        }
    }
}
