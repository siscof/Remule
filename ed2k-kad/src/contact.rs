// SPDX-License-Identifier: GPL-2.0-or-later
//! A Kad contact (`Kademlia::CContact`, routing/Contact.cpp).
//!
//! IPs are kept as aMule's Kad code keeps them: a `u32` whose most
//! significant byte is the first octet (`Ipv4Addr::from(u32)`).
//!
//! A contact's *type* says how sure we are it is alive: 3 for one just
//! learned, 2, 1 and 0 as it stays alive one, two, more hours (and its
//! expiry moves out: 1 h, 1.5 h, 2 h), up to 4 while it fails to answer;
//! a type-4 contact past its expiry is dropped.

use std::net::{Ipv4Addr, SocketAddrV4};

use ed2k_types::UInt128;

/// `CKadUDPKey`: a peer's verify key, valid for the IP of ours it was given to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpKey {
    pub key: u32,
    /// Our public IP when the peer gave it (aMule order).
    pub ip: u32,
}

impl UdpKey {
    pub fn new(key: u32, ip: u32) -> Self {
        UdpKey { key, ip }
    }

    /// `GetKeyValue`: the key, if it was given to the IP we have now.
    pub fn value_for(&self, my_ip: u32) -> u32 {
        if my_ip == self.ip {
            self.key
        } else {
            0
        }
    }

    pub fn is_empty(&self) -> bool {
        self.key == 0 || self.ip == 0
    }
}

/// One contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub id: UInt128,
    /// aMule order (first octet in the top byte).
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
    pub udp_key: UdpKey,
    pub ip_verified: bool,
    pub received_hello: bool,
    /// 0..=4, see the module docs.
    pub kind: u8,
    last_type_set: u64,
    /// When it is due for a check (0: not set yet).
    pub expires: u64,
    created: u64,
}

impl Contact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: UInt128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        udp_key: UdpKey,
        ip_verified: bool,
        now: u64,
    ) -> Self {
        Contact {
            id,
            ip,
            udp_port,
            tcp_port,
            version,
            udp_key,
            ip_verified,
            received_hello: false,
            kind: 3,
            last_type_set: now,
            expires: 0,
            created: now,
        }
    }

    pub fn addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(self.ip), self.udp_port)
    }

    /// The XOR distance to `target`.
    pub fn distance(&self, target: UInt128) -> UInt128 {
        self.id ^ target
    }

    /// `CheckingType`: it is being asked whether it is alive.
    pub fn checking_type(&mut self, now: u64) {
        if now.saturating_sub(self.last_type_set) < 10 || self.kind == 4 {
            return;
        }
        self.last_type_set = now;
        self.expires = now + 2 * 60;
        self.kind += 1;
    }

    /// `UpdateType`: it answered.
    pub fn update_type(&mut self, now: u64) {
        let hours = now.saturating_sub(self.created) / 3600;
        let (kind, after) = match hours {
            0 => (2, 3600),
            1 => (1, 90 * 60),
            _ => (0, 2 * 3600),
        };
        self.kind = kind;
        self.expires = now + after;
    }
}

/// (first octets, prefix length) of a range.
type Range = ([u8; 4], u32);

/// `reserved_ranges` (NetworkFunctions.cpp), from RFC 3330.
const RESERVED: [Range; 13] = [
    // (14/8 and 24/8 are ordinary addresses, per RFC 3330.)
    ([0, 0, 0, 0], 8),
    ([39, 0, 0, 0], 8),
    ([127, 0, 0, 0], 8),
    ([128, 0, 0, 0], 16),
    ([169, 254, 0, 0], 16),
    ([191, 255, 0, 0], 16),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 88, 99, 0], 24),
    ([198, 18, 0, 0], 15),
    ([223, 255, 255, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

/// `lan_ranges`: the RFC 1918 private networks.
const LAN: [Range; 3] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
];

fn in_range(ip: u32, (net, bits): Range) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    ip & mask == u32::from_be_bytes(net) & mask
}

/// `::IsLanIP` on an aMule-order IP.
pub fn is_lan_ip(ip: u32) -> bool {
    LAN.iter().any(|&r| in_range(ip, r))
}

/// `::IsGoodIPPort`: not reserved, not LAN when filtering, and a port.
pub fn is_good_ip_port(ip: u32, port: u16, filter_lan: bool) -> bool {
    port != 0 && !RESERVED.iter().any(|&r| in_range(ip, r)) && !(filter_lan && is_lan_ip(ip))
}
