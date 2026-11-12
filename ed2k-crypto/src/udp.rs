// SPDX-License-Identifier: GPL-2.0-or-later
//! UDP obfuscation (`CEncryptedDatagramSocket`, EncryptedDatagramSocket.cpp).
//!
//! Every packet carries its own key part; RC4 drops nothing (unlike TCP).
//!
//! ```text
//! client ↔ client, eD2k:  key MD5(<UserHashReceiver 16><IPSender 4><91><RandomKeyPart 2>)
//! client ↔ client, Kad:   key MD5(<KadIDReceiver 16><RandomKeyPart 2>)
//!                      or MD5(<ReceiverVerifyKey 4><RandomKeyPart 2>)
//! client → server:        key MD5(<BaseKey 4><0x6B><RandomKeyPart 2>)
//! server → client:        key MD5(<BaseKey 4><0xA5><RandomKeyPart 2>)
//!
//! packet: <Marker 1><RandomKeyPart 2> then encrypted
//!         <Magic 4><PaddingLen 1><Padding>[<ReceiverVerifyKey 4><SenderVerifyKey 4>]<payload>
//! ```
//!
//! The verify keys are there for Kad only. The marker's low bits say which
//! key to try first (eD2k: bit 0 set; Kad ID: `..00`; Kad verify key: `..10`)
//! but are only a hint. Senders never pad.

use std::net::Ipv4Addr;

use ed2k_types::protocol::Protocol;
use ed2k_types::{Md4Hash, UInt128};
use md5::{Digest, Md5};
use rand::{Rng, RngCore};

use crate::rc4::Rc4;

/// `CRYPT_HEADER_WITHOUTPADDING`
pub const HEADER_LEN: usize = 8;
/// `MAGICVALUE_UDP`
pub const MAGICVALUE_UDP: u8 = 91;
/// `MAGICVALUE_UDP_SYNC_CLIENT`
pub const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F_2EC1;
/// `MAGICVALUE_UDP_SYNC_SERVER`
pub const MAGICVALUE_UDP_SYNC_SERVER: u32 = 0x13EF_24D5;
/// `MAGICVALUE_UDP_SERVERCLIENT`
pub const MAGICVALUE_UDP_SERVERCLIENT: u8 = 0xA5;
/// `MAGICVALUE_UDP_CLIENTSERVER`
pub const MAGICVALUE_UDP_CLIENTSERVER: u8 = 0x6B;

/// The first bytes of plain client UDP packets, which no marker may be.
fn is_client_protocol_byte(b: u8) -> bool {
    [
        Protocol::Emule,
        Protocol::KademliaPacked,
        Protocol::Kademlia,
        Protocol::UdpReserved1,
        Protocol::UdpReserved2,
        Protocol::Packed,
    ]
    .iter()
    .any(|p| *p as u8 == b)
}

/// Which key a client packet is encrypted with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKey {
    /// eD2k: the receiver's user hash and the sender's public IP.
    Ed2k {
        receiver: Md4Hash,
        sender_ip: Ipv4Addr,
    },
    /// Kad: the receiver's Kad ID.
    KadId(UInt128),
    /// Kad: the receiver's verify key for us (when its Kad ID is unknown).
    KadVerifyKey(u32),
}

impl ClientKey {
    fn rc4(&self, random_key_part: [u8; 2]) -> Rc4 {
        let mut h = Md5::new();
        match self {
            ClientKey::Ed2k {
                receiver,
                sender_ip,
            } => {
                h.update(receiver.0);
                h.update(sender_ip.octets());
                h.update([MAGICVALUE_UDP]);
            }
            ClientKey::KadId(id) => h.update(id.to_wire_bytes()),
            ClientKey::KadVerifyKey(k) => h.update(k.to_le_bytes()),
        }
        h.update(random_key_part);
        Rc4::from_md5(h.finalize().into(), false)
    }

    fn is_kad(&self) -> bool {
        !matches!(self, ClientKey::Ed2k { .. })
    }

    /// The marker bits for this key, set into `random`.
    fn marker(&self, random: u8) -> u8 {
        match self {
            ClientKey::Ed2k { .. } => random | 0x01,
            ClientKey::KadId(_) => random & 0xFC,
            ClientKey::KadVerifyKey(_) => (random & 0xFC) | 0x02,
        }
    }
}

/// The Kad verify keys a packet carries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyKeys {
    pub receiver: u32,
    pub sender: u32,
}

/// `EncryptSendClient`, randomness drawn from `rng`. `verify` is used for Kad keys only.
pub fn encrypt_client<R: RngCore + ?Sized>(
    payload: &[u8],
    key: &ClientKey,
    verify: VerifyKeys,
    rng: &mut R,
) -> Vec<u8> {
    let random_key_part: u16 = rng.gen();
    let mut marker = 0x01;
    for _ in 0..128 {
        let m = key.marker(rng.gen());
        if !is_client_protocol_byte(m) {
            marker = m;
            break;
        }
    }
    encrypt_client_with(payload, key, verify, marker, random_key_part)
}

/// [`encrypt_client`] with the marker (used as given) and key part given.
pub fn encrypt_client_with(
    payload: &[u8],
    key: &ClientKey,
    verify: VerifyKeys,
    marker: u8,
    random_key_part: u16,
) -> Vec<u8> {
    let kp = random_key_part.to_le_bytes();
    let mut rc4 = key.rc4(kp);
    let mut out = vec![marker, kp[0], kp[1]];
    let start = out.len();
    out.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes());
    out.push(0); // no padding
    if key.is_kad() {
        out.extend_from_slice(&verify.receiver.to_le_bytes());
        out.extend_from_slice(&verify.sender.to_le_bytes());
    }
    out.extend_from_slice(payload);
    rc4.apply(&mut out[start..]);
    out
}

/// What we can decrypt incoming client packets with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnKeys {
    /// Our user hash.
    pub user_hash: Md4Hash,
    /// The sender's IP as we see it; an eD2k sender keys with its own public IP.
    pub sender_ip: Ipv4Addr,
    /// Our Kad ID, if Kad has run.
    pub kad_id: Option<UInt128>,
    /// Our verify key for the sender ([`udp_verify_key`]), if Kad has run.
    pub verify_key: Option<u32>,
}

/// A decrypted client packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    pub payload: Vec<u8>,
    /// Whether a Kad key opened it.
    pub kad: bool,
    /// The verify keys of a Kad packet (zero for eD2k).
    pub verify: VerifyKeys,
}

/// `DecryptReceivedClient`. `None` means "not an obfuscated packet": aMule
/// then hands the packet on as it is.
pub fn decrypt_client(packet: &[u8], own: &OwnKeys) -> Option<Decrypted> {
    if packet.len() <= HEADER_LEN || is_client_protocol_byte(packet[0]) {
        return None;
    }
    let kp = [packet[1], packet[2]];
    // Try in the order the marker hints: 0 Kad ID, 1 eD2k, 2 Kad verify key.
    let first = match packet[0] & 0x03 {
        3 => 1,
        n => n,
    };
    let kad_ran = own.kad_id.is_some() || own.verify_key.is_some();
    let tries = if kad_ran { 3 } else { 1 };
    let mut try_ = if kad_ran { first } else { 1 };
    for _ in 0..tries {
        let key = match try_ {
            0 => own.kad_id.map(ClientKey::KadId),
            1 => Some(ClientKey::Ed2k {
                receiver: own.user_hash,
                sender_ip: own.sender_ip,
            }),
            _ => own.verify_key.map(ClientKey::KadVerifyKey),
        };
        try_ = (try_ + 1) % 3;
        let Some(key) = key else { continue };
        let mut rc4 = key.rc4(kp);
        let mut magic = [packet[3], packet[4], packet[5], packet[6]];
        rc4.apply(&mut magic);
        if u32::from_le_bytes(magic) != MAGICVALUE_UDP_SYNC_CLIENT {
            continue;
        }
        let mut pad = [packet[7]];
        rc4.apply(&mut pad);
        let pad = pad[0] as usize;
        let mut rest = &packet[HEADER_LEN..];
        if rest.len() <= pad {
            return None;
        }
        rc4.skip(pad);
        rest = &rest[pad..];
        let mut verify = VerifyKeys::default();
        if key.is_kad() {
            if rest.len() <= 8 {
                return None;
            }
            let mut v = [0u8; 8];
            v.copy_from_slice(&rest[..8]);
            rc4.apply(&mut v);
            verify.receiver = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
            verify.sender = u32::from_le_bytes([v[4], v[5], v[6], v[7]]);
            rest = &rest[8..];
        }
        return Some(Decrypted {
            payload: rc4.crypt(rest),
            kad: key.is_kad(),
            verify,
        });
    }
    None
}

fn server_rc4(base_key: u32, magic: u8, kp: [u8; 2]) -> Rc4 {
    let mut d = [0u8; 7];
    d[..4].copy_from_slice(&base_key.to_le_bytes());
    d[4] = magic;
    d[5..].copy_from_slice(&kp);
    Rc4::from_md5_of(&d, false)
}

/// `EncryptSendServer`: a packet to a server whose UDP key is `base_key`.
pub fn encrypt_server<R: RngCore + ?Sized>(payload: &[u8], base_key: u32, rng: &mut R) -> Vec<u8> {
    let random_key_part: u16 = rng.gen();
    let mut marker = 0x01;
    for _ in 0..128 {
        let m: u8 = rng.gen();
        if m != Protocol::Edonkey as u8 {
            marker = m;
            break;
        }
    }
    encrypt_server_with(payload, base_key, marker, random_key_part)
}

/// [`encrypt_server`] with the marker and key part given.
pub fn encrypt_server_with(
    payload: &[u8],
    base_key: u32,
    marker: u8,
    random_key_part: u16,
) -> Vec<u8> {
    let kp = random_key_part.to_le_bytes();
    seal_server(
        payload,
        server_rc4(base_key, MAGICVALUE_UDP_CLIENTSERVER, kp),
        marker,
        kp,
    )
}

fn seal_server(payload: &[u8], mut rc4: Rc4, marker: u8, kp: [u8; 2]) -> Vec<u8> {
    let mut out = vec![marker, kp[0], kp[1]];
    out.extend_from_slice(&MAGICVALUE_UDP_SYNC_SERVER.to_le_bytes());
    out.push(0);
    out.extend_from_slice(payload);
    rc4.apply(&mut out[3..]);
    out
}

/// What a server sends: [`encrypt_server_with`] in the other direction
/// (for tests and fakes; clients never send it).
pub fn encrypt_from_server(
    payload: &[u8],
    base_key: u32,
    marker: u8,
    random_key_part: u16,
) -> Vec<u8> {
    let kp = random_key_part.to_le_bytes();
    seal_server(
        payload,
        server_rc4(base_key, MAGICVALUE_UDP_SERVERCLIENT, kp),
        marker,
        kp,
    )
}

/// `DecryptReceivedServer`: `None` when the packet is not obfuscated (or
/// `base_key` is 0, the server having none).
pub fn decrypt_server(packet: &[u8], base_key: u32) -> Option<Vec<u8>> {
    if packet.len() <= HEADER_LEN || base_key == 0 || packet[0] == Protocol::Edonkey as u8 {
        return None;
    }
    let kp = [packet[1], packet[2]];
    let mut rc4 = server_rc4(base_key, MAGICVALUE_UDP_SERVERCLIENT, kp);
    let mut head = [packet[3], packet[4], packet[5], packet[6], packet[7]];
    rc4.apply(&mut head);
    if u32::from_le_bytes([head[0], head[1], head[2], head[3]]) != MAGICVALUE_UDP_SYNC_SERVER {
        return None;
    }
    let pad = (head[4] & 15) as usize;
    let rest = &packet[HEADER_LEN..];
    if rest.len() <= pad {
        return None;
    }
    rc4.skip(pad);
    Some(rc4.crypt(&rest[pad..]))
}

/// `Kademlia::CPrefs::GetUDPVerifyKey`: our verify key for `ip`, from our
/// secret Kad UDP key. Never 0.
pub fn udp_verify_key(kad_udp_key: u32, ip: Ipv4Addr) -> u32 {
    // MD5 of the 64-bit (key << 32 | ip) as it lies in memory (little-endian),
    // aMule's IP being in network order: the octets, then the key.
    let mut h = Md5::new();
    h.update(ip.octets());
    h.update(kad_udp_key.to_le_bytes());
    let d = h.finalize();
    let w = |i: usize| u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
    (w(0) ^ w(4) ^ w(8) ^ w(12)) % 0xFFFF_FFFE + 1
}

/// `EUdpSendForm`: how a queued packet leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendForm {
    Plain,
    Obfuscated,
    Drop,
}

/// `DecideUdpSendForm`: eD2k client obfuscation needs our public IP, so an
/// ordinary packet falls back to plain without one; a packet that must be
/// obfuscated (it carries our user hash) is dropped instead.
pub fn send_form(encrypt: bool, require_obfuscation: bool, kad: bool, public_ip: u32) -> SendForm {
    if encrypt && (public_ip != 0 || kad) {
        SendForm::Obfuscated
    } else if require_obfuscation {
        SendForm::Drop
    } else {
        SendForm::Plain
    }
}
