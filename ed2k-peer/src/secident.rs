// SPDX-License-Identifier: GPL-2.0-or-later
//! Secure user identification between two clients (BaseClient.cpp:
//! `SendSecIdentStatePacket`, `ProcessSecIdentStatePacket`,
//! `SendPublicKeyPacket`, `ProcessPublicKeyPacket`, `SendSignaturePacket`,
//! `ProcessSignaturePacket`), sans-IO.
//!
//! After the hello, each side that wants proof sends `OP_SECIDENTSTATE`:
//! whether it needs the other's public key, and a random challenge. The
//! other answers with `OP_PUBLICKEY` if asked, then `OP_SIGNATURE`: our
//! public key and the challenge, signed with its key
//! ([`ed2k_crypto::ident`]). Both directions run at once.
//!
//! The credits (which key a user hash had before, `clients.met`) are the
//! application's: it gives the stored key, and stores a key that passed.

use std::net::Ipv4Addr;
use std::sync::Arc;

use ed2k_codec::Packet;
use ed2k_crypto::ident::{self, version, ChallengeIp, MAX_PUBLIC_KEY_LEN};
use ed2k_types::ed2k::client_tcp::Extended;
use ed2k_types::Protocol;
use rsa::RsaPrivateKey;

/// The largest public key or signature packet aMule accepts.
const MAX_PACKET: usize = 250;

/// `IS_*`: what the peer asked of us in its `OP_SECIDENTSTATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// `IS_UNAVAILABLE` (0)
    Nothing,
    /// `IS_SIGNATURENEEDED` (1)
    Signature,
    /// `IS_KEYANDSIGNEEDED` (2)
    KeyAndSignature,
}

impl Need {
    pub fn value(self) -> u8 {
        match self {
            Need::Nothing => 0,
            Need::Signature => 1,
            Need::KeyAndSignature => 2,
        }
    }

    pub fn from_value(v: u8) -> Option<Need> {
        match v {
            0 => Some(Need::Nothing),
            1 => Some(Need::Signature),
            2 => Some(Need::KeyAndSignature),
            _ => None,
        }
    }
}

/// Our key pair (`cryptkey.dat`).
#[derive(Debug, Clone)]
pub struct Identity {
    pub key: RsaPrivateKey,
    /// The public key as sent: an X.509 `SubjectPublicKeyInfo`.
    pub public: Vec<u8>,
}

/// What the application knows when identification starts.
#[derive(Debug, Clone)]
pub struct IdentConfig {
    pub ours: Arc<Identity>,
    /// The key this user hash proved before (from its credits), if any. A
    /// stored key is never replaced by one the peer sends.
    pub stored_key: Option<Vec<u8>>,
    /// The peer's IPv4 address, if it is reached over IPv4 (v2 needs it).
    pub peer_ip: Option<Ipv4Addr>,
    /// Our eD2k ID: with a high ID, v2 signatures carry our address.
    pub our_id: u32,
    /// Our public IPv4 address, to check a v2 signature over it.
    pub our_public_ip: Option<Ipv4Addr>,
}

/// How a peer's identification ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentResult {
    /// It signed our challenge with this key (`IS_IDENTIFIED`).
    Passed { key: Vec<u8> },
    /// The signature did not verify (`IS_IDFAILED`).
    Failed,
}

/// One connection's identification, both ways.
#[derive(Debug, Clone)]
pub struct SecureIdent {
    cfg: IdentConfig,
    /// The versions the peer announced (`m_bySupportSecIdent`).
    peer_versions: u8,
    peer_key: Option<Vec<u8>>,
    /// The challenge we sent (`m_dwCryptRndChallengeFor`).
    challenge_for: u32,
    /// The challenge the peer sent (`m_dwCryptRndChallengeFrom`).
    challenge_from: u32,
    /// What the peer still wants from us (`m_SecureIdentState`).
    need: Option<Need>,
    signature_received: bool,
}

/// `OP_SECIDENTSTATE`
pub fn state_packet(need: Need, challenge: u32) -> Packet {
    let mut p = vec![need.value()];
    p.extend_from_slice(&challenge.to_le_bytes());
    Packet::new(Protocol::Emule, Extended::SecIdentState, p)
}

/// `OP_PUBLICKEY`
pub fn public_key_packet(key: &[u8]) -> Packet {
    let mut p = vec![key.len() as u8];
    p.extend_from_slice(key);
    Packet::new(Protocol::Emule, Extended::PublicKey, p)
}

/// `OP_SIGNATURE`, with the challenge IP kind for v2.
pub fn signature_packet(signature: &[u8], ip_kind: Option<u8>) -> Packet {
    let mut p = vec![signature.len() as u8];
    p.extend_from_slice(signature);
    p.extend(ip_kind);
    Packet::new(Protocol::Emule, Extended::Signature, p)
}

/// The eD2k ID of a high-ID client is its address, low byte first.
fn id_ip(id: u32) -> Ipv4Addr {
    Ipv4Addr::from(id.to_le_bytes())
}

impl SecureIdent {
    /// Identification with a peer that announced `peer_versions`.
    pub fn new(cfg: IdentConfig, peer_versions: u8) -> SecureIdent {
        SecureIdent {
            peer_key: cfg.stored_key.clone(),
            cfg,
            peer_versions,
            challenge_for: 0,
            challenge_from: 0,
            need: None,
            signature_received: false,
        }
    }

    /// Whether a signature version is usable with this peer
    /// (`SecIdent::SignatureVersion != Unavailable`).
    pub fn usable(&self) -> bool {
        ident::signature_version(self.peer_versions, self.cfg.peer_ip.is_some()) != 0
    }

    /// `SendSecIdentStatePacket`: ask for the key (if we have none) and a
    /// signature over `challenge` (any non-zero value; aMule's is random).
    /// `None` when there is nothing to ask or no usable version.
    pub fn start(&mut self, challenge: u32) -> Option<Packet> {
        if !self.usable() {
            return None;
        }
        let need = if self.peer_key.is_none() {
            Need::KeyAndSignature
        } else if !self.signature_received {
            Need::Signature
        } else {
            return None;
        };
        self.challenge_for = challenge.max(1);
        Some(state_packet(need, self.challenge_for))
    }

    /// `ProcessSecIdentStatePacket`, then what aMule's socket does with
    /// it: send the key if asked, and the signature.
    pub fn on_state(&mut self, need: Need, challenge: u32) -> Vec<Packet> {
        self.need = Some(need);
        self.challenge_from = challenge;
        let mut out = Vec::new();
        match need {
            Need::Nothing => {}
            Need::Signature => out.extend(self.signature()),
            Need::KeyAndSignature => {
                out.push(public_key_packet(&self.cfg.ours.public));
                self.need = Some(Need::Signature);
                out.extend(self.signature());
            }
        }
        out
    }

    /// `ProcessPublicKeyPacket`: the peer's key, unless one is stored. If
    /// the peer is waiting for our signature, it can be sent now.
    pub fn on_public_key(&mut self, key: Vec<u8>) -> Vec<Packet> {
        if key.is_empty() || key.len() > MAX_PUBLIC_KEY_LEN || self.cfg.stored_key.is_some() {
            return Vec::new();
        }
        self.peer_key = Some(key);
        if self.need == Some(Need::Signature) {
            self.signature().into_iter().collect()
        } else {
            Vec::new()
        }
    }

    /// `SendSignaturePacket`: sign the peer's key and its challenge. Not
    /// before both are known.
    fn signature(&mut self) -> Option<Packet> {
        let key = self.peer_key.as_ref()?;
        if self.challenge_from == 0 {
            return None;
        }
        let v = ident::signature_version(self.peer_versions, self.cfg.peer_ip.is_some());
        let ip = match v {
            version::V1 => None,
            version::V2 => Some(if self.cfg.our_id < 0x0100_0000 {
                // We do not know our address for sure: sign the peer's.
                ChallengeIp::RemoteClient(self.cfg.peer_ip?)
            } else {
                ChallengeIp::LocalClient(id_ip(self.cfg.our_id))
            }),
            _ => return None,
        };
        let sig = ident::sign(&self.cfg.ours.key, key, self.challenge_from, ip).ok()?;
        self.need = None;
        let kind = ip.map(|ip| match ip {
            ChallengeIp::RemoteClient(_) => ChallengeIp::REMOTE_CLIENT,
            ChallengeIp::LocalClient(_) => ChallengeIp::LOCAL_CLIENT,
            ChallengeIp::None => ChallengeIp::NONE_CLIENT,
        });
        Some(signature_packet(&sig, kind))
    }

    /// `ProcessSignaturePacket` and `VerifyIdent`. `None` when the
    /// signature is not considered at all: a second one, no key yet, no
    /// challenge sent, or a v2 kind the peer cannot use.
    pub fn on_signature(&mut self, signature: &[u8], ip_kind: Option<u8>) -> Option<IdentResult> {
        if signature.is_empty() || signature.len() > MAX_PACKET {
            return None;
        }
        if ip_kind.is_some()
            && (self.peer_versions & version::V2 == 0 || self.cfg.peer_ip.is_none())
        {
            return None;
        }
        if self.signature_received {
            return None;
        }
        let key = self.peer_key.clone()?;
        if self.challenge_for == 0 {
            return None;
        }
        self.signature_received = true;
        let ip = match ip_kind {
            None => None,
            Some(ChallengeIp::LOCAL_CLIENT) => Some(ChallengeIp::LocalClient(self.cfg.peer_ip?)),
            Some(ChallengeIp::REMOTE_CLIENT) => Some(ChallengeIp::RemoteClient(
                self.cfg
                    .our_public_ip
                    .unwrap_or_else(|| id_ip(self.cfg.our_id)),
            )),
            Some(ChallengeIp::NONE_CLIENT) => Some(ChallengeIp::None),
            Some(_) => return Some(IdentResult::Failed),
        };
        let ok = ident::verify(
            &key,
            &self.cfg.ours.public,
            self.challenge_for,
            ip,
            signature,
        )
        .unwrap_or(false);
        Some(if ok {
            IdentResult::Passed { key }
        } else {
            IdentResult::Failed
        })
    }
}
