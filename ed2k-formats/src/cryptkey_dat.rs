// SPDX-License-Identifier: GPL-2.0-or-later
//! `cryptkey.dat`: our RSA private key for secure user identification.
//!
//! Port of `CClientCreditsList::CreateKeyPair` / `InitalizeCrypting`
//! (ClientCreditsList.cpp).
//!
//! The file is Crypto++'s `Base64Encoder` output of the DER-encoded private
//! key, as `InvertibleRSAFunction::DEREncode` writes it: a **PKCS#8**
//! `PrivateKeyInfo` wrapping a PKCS#1 `RSAPrivateKey`. aMule makes a
//! 384-bit key (`RSAKEYSIZE`) with Crypto++'s default public exponent, 17.
//!
//! Base64 as Crypto++ writes it: standard alphabet with `=` padding, a `\n`
//! after every 72 characters and one `\n` at the end. As Crypto++ reads it:
//! every character outside the alphabet (newlines, `\r`, `=`) is skipped and
//! trailing bits that do not make a whole byte are dropped.
//!
//! What aMule derives from the key, and what peers see, is the public key as
//! an X.509 `SubjectPublicKeyInfo` (76 bytes for a 384-bit key), sent in
//! `OP_PUBLICKEY` and stored in other clients' `clients.met`.
//!
//! [`CryptKey`] keeps the file bytes exactly, so [`CryptKey::write`] returns
//! them unchanged.

use std::fmt;

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{BigUint, RsaPrivateKey};

/// `CRYPTKEY_FILENAME`
pub const FILE_NAME: &str = "cryptkey.dat";
/// `RSAKEYSIZE`, in bits.
pub const KEY_BITS: usize = 384;
/// Crypto++'s default public exponent for `InvertibleRSAFunction::Initialize`.
pub const PUBLIC_EXPONENT: u32 = 17;
/// `Base64Encoder`'s default line length.
pub const LINE_LEN: usize = 72;
/// aMule keeps its public key in an 80-byte buffer (`m_abyMyPublicKey`).
pub const MAX_PUBLIC_KEY_LEN: usize = 80;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// An empty file. aMule makes a new key pair in that case.
    Empty,
    /// The base64 does not hold a PKCS#8 RSA private key.
    BadKey(String),
    /// The public key does not fit aMule's 80-byte buffer (aMule would
    /// announce a truncated key).
    PublicKeyTooLong(usize),
    /// Key generation failed.
    Generate(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Empty => f.write_str("cryptkey.dat is empty"),
            Error::BadKey(e) => write!(f, "cryptkey.dat does not hold an RSA private key: {e}"),
            Error::PublicKeyTooLong(n) => write!(
                f,
                "public key of {n} bytes does not fit in {MAX_PUBLIC_KEY_LEN}"
            ),
            Error::Generate(e) => write!(f, "cannot create an RSA key pair: {e}"),
        }
    }
}

impl std::error::Error for Error {}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Crypto++ `Base64Encoder` with its defaults: `=` padding, a `\n` every
/// [`LINE_LEN`] characters, and a final `\n`.
pub fn encode_base64(data: &[u8]) -> String {
    let mut plain = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                plain.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                plain.push('=');
            }
        }
    }
    let mut out = String::with_capacity(plain.len() + plain.len() / LINE_LEN + 1);
    for (i, c) in plain.chars().enumerate() {
        // Grouper: the separator goes before a group, never after the last one.
        if i > 0 && i % LINE_LEN == 0 {
            out.push('\n');
        }
        out.push(c);
    }
    out.push('\n');
    out
}

/// Crypto++ `Base64Decoder`: characters outside the alphabet are skipped,
/// and bits that do not make a whole byte at the end are dropped.
pub fn decode_base64(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in text {
        let Some(v) = ALPHABET.iter().position(|&a| a == c) else {
            continue;
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// A `cryptkey.dat`.
#[derive(Clone, PartialEq, Eq)]
pub struct CryptKey {
    raw: Vec<u8>,
    der: Vec<u8>,
}

impl fmt::Debug for CryptKey {
    /// Never prints the key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptKey({} bytes of DER)", self.der.len())
    }
}

impl CryptKey {
    /// Read a file. Only the base64 is decoded here; [`CryptKey::private_key`]
    /// parses it. aMule makes a new key for an empty file ([`Error::Empty`]).
    pub fn read(bytes: &[u8]) -> Result<CryptKey, Error> {
        if bytes.is_empty() {
            return Err(Error::Empty);
        }
        Ok(CryptKey {
            raw: bytes.to_vec(),
            der: decode_base64(bytes),
        })
    }

    /// The file aMule writes for this DER-encoded private key.
    pub fn from_der(der: &[u8]) -> CryptKey {
        CryptKey {
            raw: encode_base64(der).into_bytes(),
            der: der.to_vec(),
        }
    }

    /// `CreateKeyPair`: a new 384-bit key with exponent 17, as a file.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Result<CryptKey, Error> {
        let key = RsaPrivateKey::new_with_exp(rng, KEY_BITS, &BigUint::from(PUBLIC_EXPONENT))
            .map_err(|e| Error::Generate(e.to_string()))?;
        let der = key
            .to_pkcs8_der()
            .map_err(|e| Error::Generate(e.to_string()))?;
        Ok(CryptKey::from_der(der.as_bytes()))
    }

    /// The file bytes, unchanged from what was read.
    pub fn write(&self) -> Vec<u8> {
        self.raw.clone()
    }

    /// The decoded DER: a PKCS#8 `PrivateKeyInfo`.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The private key (`RSASSA_PKCS1v15_SHA_Signer` built from the file).
    pub fn private_key(&self) -> Result<RsaPrivateKey, Error> {
        RsaPrivateKey::from_pkcs8_der(&self.der).map_err(|e| Error::BadKey(e.to_string()))
    }

    /// The public key as aMule exports it (`GetMaterial().Save`): an X.509
    /// `SubjectPublicKeyInfo`, 76 bytes for a 384-bit key.
    pub fn public_key(&self) -> Result<Vec<u8>, Error> {
        let spki = self
            .private_key()?
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| Error::BadKey(e.to_string()))?
            .into_vec();
        if spki.len() > MAX_PUBLIC_KEY_LEN {
            return Err(Error::PublicKeyTooLong(spki.len()));
        }
        Ok(spki)
    }
}

#[cfg(test)]
mod tests;
