// SPDX-License-Identifier: GPL-2.0-or-later
//! Secure user identification (`CClientCreditsList::CreateSignature` and
//! `VerifyIdent`, ClientCreditsList.cpp; `SecIdentPolicy.h`).
//!
//! Each client has an RSA key (384 bits, `cryptkey.dat`) and sends its public
//! key (an X.509 `SubjectPublicKeyInfo`, at most [`MAX_PUBLIC_KEY_LEN`] bytes)
//! and a random 32-bit challenge. The other side proves its identity by
//! signing, with RSASSA-PKCS1-v1.5 over SHA-1:
//!
//! ```text
//! v1: <the challenger's public key><challenge 4>
//! v2: <the challenger's public key><challenge 4><ChallengeIP 4><ChaIPKind 1>
//! ```
//!
//! `ChallengeIP` is an IPv4 address in network order, written as aMule's
//! `PokeUInt32` does, i.e. as its four octets.

use std::net::Ipv4Addr;

use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest, Sha1};

/// `MAXPUBKEYSIZE`
pub const MAX_PUBLIC_KEY_LEN: usize = 80;

/// `CRYPT_CIP_*`: whose IP a v2 signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeIp {
    /// `CRYPT_CIP_REMOTECLIENT` (10): the signer's IP as the challenger sees it.
    RemoteClient(Ipv4Addr),
    /// `CRYPT_CIP_LOCALCLIENT` (20): the challenger's own IP.
    LocalClient(Ipv4Addr),
    /// `CRYPT_CIP_NONECLIENT` (30): no IP (signed as 0).
    None,
}

impl ChallengeIp {
    pub const REMOTE_CLIENT: u8 = 10;
    pub const LOCAL_CLIENT: u8 = 20;
    pub const NONE_CLIENT: u8 = 30;

    fn bytes(self) -> [u8; 5] {
        let (ip, kind) = match self {
            ChallengeIp::RemoteClient(ip) => (ip, Self::REMOTE_CLIENT),
            ChallengeIp::LocalClient(ip) => (ip, Self::LOCAL_CLIENT),
            ChallengeIp::None => (Ipv4Addr::UNSPECIFIED, Self::NONE_CLIENT),
        };
        let o = ip.octets();
        [o[0], o[1], o[2], o[3], kind]
    }
}

/// What is signed: the challenger's key, the challenge, and for v2 the IP.
pub fn signed_message(challenger_key: &[u8], challenge: u32, ip: Option<ChallengeIp>) -> Vec<u8> {
    let mut m = Vec::with_capacity(challenger_key.len() + 9);
    m.extend_from_slice(challenger_key);
    m.extend_from_slice(&challenge.to_le_bytes());
    if let Some(ip) = ip {
        m.extend_from_slice(&ip.bytes());
    }
    m
}

/// What can go wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentError {
    #[error("public key of {0} bytes (at most 80)")]
    KeyTooLong(usize),
    #[error("bad public key: {0}")]
    BadKey(String),
    #[error("signing failed: {0}")]
    Sign(String),
}

/// `CreateSignature`: prove our identity to the client whose public key is
/// `challenger_key` and that sent `challenge`.
pub fn sign(
    key: &RsaPrivateKey,
    challenger_key: &[u8],
    challenge: u32,
    ip: Option<ChallengeIp>,
) -> Result<Vec<u8>, IdentError> {
    if challenger_key.len() > MAX_PUBLIC_KEY_LEN {
        return Err(IdentError::KeyTooLong(challenger_key.len()));
    }
    let digest = Sha1::digest(signed_message(challenger_key, challenge, ip));
    key.sign(Pkcs1v15Sign::new::<Sha1>(), &digest)
        .map_err(|e| IdentError::Sign(e.to_string()))
}

/// `VerifyIdent`: check that the owner of `signer_key` signed `our_key`
/// with the `challenge` we sent it.
pub fn verify(
    signer_key: &[u8],
    our_key: &[u8],
    challenge: u32,
    ip: Option<ChallengeIp>,
    signature: &[u8],
) -> Result<bool, IdentError> {
    if signer_key.len() > MAX_PUBLIC_KEY_LEN {
        return Err(IdentError::KeyTooLong(signer_key.len()));
    }
    let public = RsaPublicKey::from_public_key_der(signer_key)
        .map_err(|e| IdentError::BadKey(e.to_string()))?;
    let digest = Sha1::digest(signed_message(our_key, challenge, ip));
    Ok(public
        .verify(Pkcs1v15Sign::new::<Sha1>(), &digest, signature)
        .is_ok())
}

/// `SecIdent::Version` bits a client advertises.
pub mod version {
    pub const V1: u8 = 1;
    pub const V2: u8 = 2;
}

/// `SecIdent::SupportedVersions`: v2 needs the peer's IPv4.
pub fn supported_versions(crypto_available: bool, has_peer_ipv4: bool) -> u8 {
    match (crypto_available, has_peer_ipv4) {
        (false, _) => 0,
        (true, true) => version::V1 | version::V2,
        (true, false) => version::V1,
    }
}

/// `SecIdent::SignatureVersion`: v1 when the peer can, as aMule always has.
pub fn signature_version(peer_versions: u8, has_peer_ipv4: bool) -> u8 {
    if peer_versions & version::V1 != 0 {
        version::V1
    } else if has_peer_ipv4 && peer_versions & version::V2 != 0 {
        version::V2
    } else {
        0
    }
}

/// `SecIdent::RemoteClientChallengeIP`: the IP a `CRYPT_CIP_REMOTECLIENT`
/// signer used, i.e. ours as it sees us. `own_ip_as_seen` is that address
/// when known (behind a TCP/UDP-split NAT), else 0; without a verified
/// public IP a HighID falls back to its ID, a LowID to its public IP.
pub fn remote_client_challenge_ip(
    own_ip_as_seen: u32,
    verified_public_ip: u32,
    public_ip: u32,
    low_id: bool,
    ed2k_id: u32,
) -> u32 {
    if own_ip_as_seen != 0 {
        own_ip_as_seen
    } else if verified_public_ip == 0 {
        if low_id {
            public_ip
        } else {
            ed2k_id
        }
    } else {
        public_ip
    }
}
