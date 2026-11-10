// SPDX-License-Identifier: GPL-2.0-or-later
//! EC transport encryption. Port of `libs/ec/cpp/ECCrypt.cpp`.
//!
//! Keys come from an ephemeral X25519 exchange, split per direction by
//! HKDF-SHA256 over the handshake transcript. Each sealed packet uses a
//! 12-byte nonce: a 4-byte derived prefix and a 64-bit big-endian counter
//! that is implicit (never sent). See `docs/EC_Protocol.md` §1.3.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const NONCE_TAG_LEN: usize = 32;
pub const X25519_KEY_LEN: usize = 32;
pub const AEAD_TAG_LEN: usize = 16;

pub const CIPHER_AES128_GCM: u8 = 1;
pub const CIPHER_CHACHA20_POLY1305: u8 = 2;

/// What we offer, in preference order. The C++ client puts AES first only
/// when it can detect AES instructions; ChaCha20 is constant-time in software
/// everywhere, so we always prefer it and the daemon honours that.
pub const OFFERED_CIPHERS: [u8; 2] = [CIPHER_CHACHA20_POLY1305, CIPHER_AES128_GCM];

pub fn cipher_name(c: u8) -> &'static str {
    match c {
        CIPHER_AES128_GCM => "AES-128-GCM",
        CIPHER_CHACHA20_POLY1305 => "ChaCha20-Poly1305",
        _ => "unknown",
    }
}

fn key_len(cipher: u8) -> Option<usize> {
    match cipher {
        CIPHER_AES128_GCM => Some(16),
        CIPHER_CHACHA20_POLY1305 => Some(32),
        _ => None,
    }
}

/// `ECCrypt::BuildTranscript`: the handshake bytes both sides bind into the
/// key derivation and the SRP proofs.
pub fn build_transcript(
    offered: &[u8],
    chosen: u8,
    client_nonce: &[u8],
    server_nonce: &[u8],
    client_pub: &[u8],
    server_pub: &[u8],
) -> Vec<u8> {
    let n = offered.len().min(255);
    let mut out = Vec::with_capacity(
        2 + n + client_nonce.len() + server_nonce.len() + client_pub.len() + server_pub.len(),
    );
    out.push(n as u8);
    out.extend_from_slice(&offered[..n]);
    out.push(chosen);
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(server_nonce);
    out.extend_from_slice(client_pub);
    out.extend_from_slice(server_pub);
    out
}

enum Aead2 {
    Aes(Box<Aes128Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Aead2 {
    fn new(cipher: u8, key: &[u8]) -> Option<Self> {
        match cipher {
            CIPHER_AES128_GCM => Aes128Gcm::new_from_slice(key)
                .ok()
                .map(|c| Aead2::Aes(Box::new(c))),
            CIPHER_CHACHA20_POLY1305 => ChaCha20Poly1305::new_from_slice(key)
                .ok()
                .map(|c| Aead2::ChaCha(Box::new(c))),
            _ => None,
        }
    }

    fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Option<Vec<u8>> {
        match self {
            Aead2::Aes(c) => c.encrypt(nonce.into(), plain).ok(),
            Aead2::ChaCha(c) => c.encrypt(nonce.into(), plain).ok(),
        }
    }

    fn open(&self, nonce: &[u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
        match self {
            Aead2::Aes(c) => c.decrypt(nonce.into(), sealed).ok(),
            Aead2::ChaCha(c) => c.decrypt(nonce.into(), sealed).ok(),
        }
    }
}

/// One connection's sealing state, client side.
pub struct Session {
    cipher: u8,
    tx: Aead2,
    rx: Aead2,
    tx_prefix: [u8; 4],
    rx_prefix: [u8; 4],
    tx_counter: u64,
    rx_counter: u64,
}

impl Session {
    /// `ECCrypt::Session::Init` with `isServer == false`.
    pub fn new_client(
        cipher: u8,
        ikm: &[u8],
        server_nonce: &[u8],
        client_nonce: &[u8],
        transcript: &[u8],
    ) -> Option<Self> {
        Self::new(cipher, ikm, server_nonce, client_nonce, transcript, false)
    }

    /// The daemon's side; only the test fake daemon needs it.
    #[cfg(any(test, feature = "fake-daemon"))]
    pub(crate) fn new_server(
        cipher: u8,
        ikm: &[u8],
        server_nonce: &[u8],
        client_nonce: &[u8],
        transcript: &[u8],
    ) -> Option<Self> {
        Self::new(cipher, ikm, server_nonce, client_nonce, transcript, true)
    }

    fn new(
        cipher: u8,
        ikm: &[u8],
        server_nonce: &[u8],
        client_nonce: &[u8],
        transcript: &[u8],
        is_server: bool,
    ) -> Option<Self> {
        let klen = key_len(cipher)?;
        if server_nonce.len() != NONCE_TAG_LEN || client_nonce.len() != NONCE_TAG_LEN {
            return None;
        }
        let mut salt = Vec::with_capacity(2 * NONCE_TAG_LEN);
        salt.extend_from_slice(server_nonce);
        salt.extend_from_slice(client_nonce);
        let mut info = b"aMule EC AEAD v1".to_vec();
        info.push(cipher);
        info.extend_from_slice(transcript);

        let mut okm = Zeroizing::new(vec![0u8; 2 * klen + 8]);
        Hkdf::<Sha256>::new(Some(&salt), ikm)
            .expand(&info, &mut okm)
            .ok()?;
        let (c2s_key, rest) = okm.split_at(klen);
        let (s2c_key, prefixes) = rest.split_at(klen);
        let c2s_prefix: [u8; 4] = prefixes[0..4].try_into().ok()?;
        let s2c_prefix: [u8; 4] = prefixes[4..8].try_into().ok()?;

        let (tx_key, rx_key, tx_prefix, rx_prefix) = if is_server {
            (s2c_key, c2s_key, s2c_prefix, c2s_prefix)
        } else {
            (c2s_key, s2c_key, c2s_prefix, s2c_prefix)
        };
        Some(Session {
            cipher,
            tx: Aead2::new(cipher, tx_key)?,
            rx: Aead2::new(cipher, rx_key)?,
            tx_prefix,
            rx_prefix,
            tx_counter: 0,
            rx_counter: 0,
        })
    }

    pub fn cipher(&self) -> u8 {
        self.cipher
    }

    fn nonce(prefix: &[u8; 4], counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(prefix);
        n[4..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    /// Seal one packet body: ciphertext followed by the 16-byte tag.
    pub fn seal(&mut self, plain: &[u8]) -> Option<Vec<u8>> {
        let out = self
            .tx
            .seal(&Self::nonce(&self.tx_prefix, self.tx_counter), plain)?;
        self.tx_counter += 1;
        Some(out)
    }

    /// Open one packet body. A failure is the tamper signal; the counter
    /// does not advance and the caller must drop the connection.
    pub fn open(&mut self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < AEAD_TAG_LEN {
            return None;
        }
        let out = self
            .rx
            .open(&Self::nonce(&self.rx_prefix, self.rx_counter), sealed)?;
        self.rx_counter += 1;
        Some(out)
    }
}

/// Our half of the ephemeral key exchange.
pub struct Ephemeral {
    secret: x25519_dalek::EphemeralSecret,
    pub public: [u8; 32],
}

impl Ephemeral {
    pub fn generate() -> Self {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Ephemeral { secret, public }
    }

    /// `ECCrypt::X25519Agree`: consumes the secret, refuses a non-contributory
    /// (all-zero) result that a low-order peer key would force.
    pub fn agree(self, peer: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        let peer: [u8; 32] = peer.try_into().ok()?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        if !shared.was_contributory() {
            return None;
        }
        Some(Zeroizing::new(shared.to_bytes()))
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn wipe(v: &mut Vec<u8>) {
    v.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ECCryptTest.cpp: BuildTranscriptMatchesGoldenVector.
    #[test]
    fn transcript_matches_golden_vector() {
        let t = build_transcript(
            &[1, 2, 3],
            2,
            &[0xA0, 0xA1, 0xA2, 0xA3],
            &[0xB0, 0xB1, 0xB2, 0xB3],
            &[0xC0, 0xC1, 0xC2],
            &[0xD0, 0xD1, 0xD2],
        );
        assert_eq!(
            t,
            [
                0x03, 0x01, 0x02, 0x03, 0x02, 0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3, 0xC0,
                0xC1, 0xC2, 0xD0, 0xD1, 0xD2
            ]
        );
    }

    #[test]
    fn transcript_caps_cipher_list_at_255() {
        let t = build_transcript(&[1; 300], 1, &[], &[], &[], &[]);
        assert_eq!(t[0], 255);
        assert_eq!(t.len(), 1 + 255 + 1);
    }

    /// RFC 5869 test case 1, through the same HKDF call the session uses.
    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .unwrap();
        let expected =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        let got: String = okm.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expected);
    }

    fn pair(cipher: u8) -> (Session, Session) {
        let ikm = [5u8; 32];
        let (sn, cn) = ([1u8; 32], [2u8; 32]);
        let t = build_transcript(&OFFERED_CIPHERS, cipher, &cn, &sn, &[3; 32], &[4; 32]);
        (
            Session::new(cipher, &ikm, &sn, &cn, &t, false).unwrap(),
            Session::new(cipher, &ikm, &sn, &cn, &t, true).unwrap(),
        )
    }

    #[test]
    fn both_ciphers_round_trip_in_both_directions() {
        for cipher in OFFERED_CIPHERS {
            let (mut client, mut server) = pair(cipher);
            for i in 0..5u8 {
                let msg = vec![i; i as usize * 100];
                let sealed = client.seal(&msg).unwrap();
                assert_eq!(sealed.len(), msg.len() + AEAD_TAG_LEN);
                assert_eq!(server.open(&sealed).unwrap(), msg);
                let back = server.seal(&msg).unwrap();
                assert_eq!(client.open(&back).unwrap(), msg);
            }
        }
    }

    #[test]
    fn counter_advances_and_tampering_is_caught() {
        let (mut client, mut server) = pair(CIPHER_CHACHA20_POLY1305);
        let a = client.seal(b"same").unwrap();
        let b = client.seal(b"same").unwrap();
        assert_ne!(a, b, "identical plaintexts must seal differently");
        let mut bad = a.clone();
        bad[0] ^= 1;
        assert!(server.open(&bad).is_none());
        // A failed open holds the counter, so the genuine packet still opens.
        assert_eq!(server.open(&a).unwrap(), b"same");
        assert!(server.open(&b[..10]).is_none());
    }

    #[test]
    fn x25519_agreement_matches_on_both_sides() {
        let a = Ephemeral::generate();
        let b = Ephemeral::generate();
        let (apub, bpub) = (a.public, b.public);
        assert_eq!(*a.agree(&bpub).unwrap(), *b.agree(&apub).unwrap());
        assert!(
            Ephemeral::generate().agree(&[0u8; 32]).is_none(),
            "low-order point must be refused"
        );
    }
}
