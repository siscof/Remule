// SPDX-License-Identifier: GPL-2.0-or-later
//! `nodes.dat`: saved Kad contacts, used to rejoin the network.
//!
//! Port of `CRoutingZone::ReadFile` / `ReadBootstrapNodesDat` / `WriteFile`
//! (kademlia/routing/RoutingZone.cpp) and `CKadUDPKey` (KadUDPKey.h).
//!
//! Layouts, all integers little-endian:
//!
//! ```text
//! v0:        u32 count (≠ 0) | count × contact25           (aMule refuses it)
//! v1:        u32 0 | u32 1 | u32 count | count × contact25
//! v2:        u32 0 | u32 2 | u32 count | count × contact34
//! v3:        u32 0 | u32 3 | u32 edition (≠ 1) | u32 count | count × contact34
//! bootstrap: u32 0 | u32 3 | u32 1 | u32 count | count × contact25
//!
//! contact25: UInt128 id (wire layout) | u32 IP | u16 UDP port | u16 TCP port | u8 Kad version
//! contact34: contact25 | u32 UDP key | u32 key IP | u8 verified
//! ```
//!
//! The IP is a `u32` holding the address in host order (1.2.3.4 is
//! `0x01020304`), stored little-endian.
//!
//! aMule reads contacts only when the count is non-zero and the data left
//! holds at least 25 bytes per contact (exactly 25 for a bootstrap list);
//! otherwise it reads none. Bytes after the contacts are ignored. [`NodesDat`]
//! keeps all of it, so any file writes back byte for byte.
//!
//! One deliberate difference: aMule computes `count * 25` in 32 bits, so a
//! huge count can wrap past the guard and be read until the data runs out.
//! Here the product cannot overflow, and such a count reads no contacts.

use std::fmt;
use std::net::Ipv4Addr;

use ed2k_codec::{Reader, Writer};
use ed2k_types::UInt128;

/// `CONTACT_FILE_LIMIT`: the most contacts aMule writes.
pub const CONTACT_FILE_LIMIT: usize = 500;
/// aMule does not write a `nodes.dat` with fewer contacts than this.
pub const MIN_CONTACTS_TO_WRITE: usize = 25;
/// How many contacts aMule picks from a bootstrap list: those closest to its own id.
pub const BOOTSTRAP_PICK: usize = 50;
/// The smallest record (v0, v1, bootstrap); the count guard uses it for every version.
const MIN_RECORD: u64 = 25;

/// `CKadUDPKey`: the UDP verify key a contact gave us, valid for the IP we
/// had when it was issued.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct KadUdpKey {
    pub key: u32,
    /// Our IP the key belongs to, in the same host-order `u32` as contact IPs.
    pub ip: u32,
}

impl KadUdpKey {
    /// `IsEmpty`
    pub fn is_empty(&self) -> bool {
        self.key == 0 || self.ip == 0
    }

    /// `GetKeyValue`: the key if `my_ip` is the IP it was issued for, else 0.
    pub fn value_for(&self, my_ip: u32) -> u32 {
        if my_ip == self.ip {
            self.key
        } else {
            0
        }
    }
}

/// One saved contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    pub id: UInt128,
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub tcp_port: u16,
    /// The contact's Kad version (`ed2k_types::kad::version`).
    pub version: u8,
    /// v2 and v3 records only.
    pub udp_key: Option<KadUdpKey>,
    /// v2 and v3 records only: the stored byte, non-zero meaning verified.
    pub verified: Option<u8>,
}

impl Contact {
    pub fn is_verified(&self) -> bool {
        self.verified.is_some_and(|v| v != 0)
    }

    /// The checks of `ReadFile` that depend only on the record: a Kad 2
    /// contact (version above 1) that is not on UDP port 53 without
    /// obfuscation (version 5 or less). aMule also drops bad or LAN IPs
    /// (`IsGoodIPPort`) and IP-filtered addresses, which need policy and the
    /// IP filter and are not part of the file format.
    pub fn passes_file_checks(&self) -> bool {
        self.version > 1 && !(self.udp_port == 53 && self.version <= 5)
    }

    fn read(r: &mut Reader<'_>, with_key: bool) -> Result<Contact, ed2k_codec::Error> {
        let id = r.uint128()?;
        let ip = Ipv4Addr::from(r.u32()?);
        let udp_port = r.u16()?;
        let tcp_port = r.u16()?;
        let version = r.u8()?;
        let (udp_key, verified) = if with_key {
            let key = r.u32()?;
            let ip = r.u32()?;
            (Some(KadUdpKey { key, ip }), Some(r.u8()?))
        } else {
            (None, None)
        };
        Ok(Contact {
            id,
            ip,
            udp_port,
            tcp_port,
            version,
            udp_key,
            verified,
        })
    }

    fn write(&self, w: &mut Writer) {
        w.uint128(self.id)
            .u32(u32::from(self.ip))
            .u16(self.udp_port)
            .u16(self.tcp_port)
            .u8(self.version);
        if let Some(k) = self.udp_key {
            w.u32(k.key).u32(k.ip).u8(self.verified.unwrap_or(0));
        }
    }
}

/// Which layout a file has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// The first word is the count. aMule refuses these: they do not say
    /// which Kad version their contacts speak.
    V0,
    V1,
    V2,
    /// Version 3 with a bootstrap edition other than 1: records as v2.
    V3 {
        edition: u32,
    },
    /// Version 3, edition 1: a large list of contacts only to send bootstrap
    /// requests to, never added to the routing table.
    Bootstrap,
    /// A first word of 0 with fewer than 8 bytes, or an unknown version:
    /// aMule reads no contacts.
    Unreadable,
}

/// A whole `nodes.dat`, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodesDat {
    pub format: Format,
    /// The count the file declares (0 for [`Format::Unreadable`]).
    pub declared_count: u32,
    /// The contacts aMule reads, in file order: empty when the count fails
    /// aMule's guard.
    pub contacts: Vec<Contact>,
    /// Everything after the last contact read, which aMule ignores. For an
    /// unreadable file, everything after the first word.
    pub trailing: Vec<u8>,
}

/// A file that runs out in the middle of a contact. Like aMule, which adds
/// each contact as it reads it, the ones before are kept.
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub cause: ed2k_codec::Error,
    pub salvaged: Vec<Contact>,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "nodes.dat is truncated: {} ({} contacts salvaged)",
            self.cause,
            self.salvaged.len()
        )
    }
}

impl std::error::Error for Error {}

impl NodesDat {
    /// Parse a whole file, following `ReadFile` / `ReadBootstrapNodesDat`.
    pub fn read(bytes: &[u8]) -> Result<NodesDat, Error> {
        let fail = |cause, salvaged| Error { cause, salvaged };
        let mut r = Reader::new(bytes);
        let first = r.u32().map_err(|e| fail(e, Vec::new()))?;

        let (format, count) = if first != 0 {
            (Format::V0, first)
        } else if bytes.len() < 8 {
            (Format::Unreadable, 0)
        } else {
            let mut look = r.clone();
            let version = look.u32().map_err(|e| fail(e, Vec::new()))?;
            match version {
                1 | 2 => {
                    let count = look.u32().map_err(|e| fail(e, Vec::new()))?;
                    r = look;
                    (if version == 1 { Format::V1 } else { Format::V2 }, count)
                }
                3 => {
                    let edition = look.u32().map_err(|e| fail(e, Vec::new()))?;
                    let count = look.u32().map_err(|e| fail(e, Vec::new()))?;
                    r = look;
                    (
                        if edition == 1 {
                            Format::Bootstrap
                        } else {
                            Format::V3 { edition }
                        },
                        count,
                    )
                }
                _ => (Format::Unreadable, 0),
            }
        };

        let with_key = matches!(format, Format::V2 | Format::V3 { .. });
        let need = u64::from(count) * MIN_RECORD;
        let left = r.remaining() as u64;
        let readable = match format {
            Format::Unreadable => false,
            Format::Bootstrap => count != 0 && need == left,
            _ => count != 0 && need <= left,
        };

        let mut contacts = Vec::new();
        if readable {
            // The guard bounds the count by the data, so this cannot over-allocate.
            contacts.reserve(count as usize);
            for _ in 0..count {
                match Contact::read(&mut r, with_key) {
                    Ok(c) => contacts.push(c),
                    Err(e) => return Err(fail(e, contacts)),
                }
            }
        }
        Ok(NodesDat {
            format,
            declared_count: count,
            contacts,
            trailing: r.rest().to_vec(),
        })
    }

    /// Serialise exactly as read.
    pub fn write(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self.format {
            Format::V0 => {
                w.u32(self.declared_count);
            }
            Format::V1 => {
                w.u32(0).u32(1).u32(self.declared_count);
            }
            Format::V2 => {
                w.u32(0).u32(2).u32(self.declared_count);
            }
            Format::V3 { edition } => {
                w.u32(0).u32(3).u32(edition).u32(self.declared_count);
            }
            Format::Bootstrap => {
                w.u32(0).u32(3).u32(1).u32(self.declared_count);
            }
            Format::Unreadable => {
                w.u32(0);
            }
        }
        for c in &self.contacts {
            c.write(&mut w);
        }
        w.bytes(&self.trailing);
        w.into_bytes()
    }

    /// The file `WriteFile` writes: version 2, every contact with its UDP
    /// key and a verified flag of 0 or 1. aMule writes nothing for fewer
    /// than [`MIN_CONTACTS_TO_WRITE`] contacts and at most
    /// [`CONTACT_FILE_LIMIT`]; `None` and truncation follow that.
    pub fn for_writing(contacts: &[Contact]) -> Option<NodesDat> {
        let n = contacts.len().min(CONTACT_FILE_LIMIT);
        if n < MIN_CONTACTS_TO_WRITE {
            return None;
        }
        let contacts = contacts[..n]
            .iter()
            .map(|c| Contact {
                udp_key: Some(c.udp_key.unwrap_or_default()),
                verified: Some(u8::from(c.is_verified())),
                ..*c
            })
            .collect();
        Some(NodesDat {
            format: Format::V2,
            declared_count: n as u32,
            contacts,
            trailing: Vec::new(),
        })
    }

    /// The contacts aMule would add to its routing table (normal files) or
    /// consider for bootstrapping (bootstrap files), as far as the file
    /// itself decides; see [`Contact::passes_file_checks`]. None for v0.
    pub fn usable(&self) -> impl Iterator<Item = &Contact> {
        let ok = !matches!(self.format, Format::V0 | Format::Unreadable);
        self.contacts
            .iter()
            .filter(move |c| ok && c.passes_file_checks())
    }

    /// aMule marks every contact verified when a file has none marked, so
    /// that an old file still bootstraps quickly.
    pub fn treat_all_as_verified(&self) -> bool {
        !self.contacts.iter().any(Contact::is_verified)
    }

    /// For a bootstrap list: the [`BOOTSTRAP_PICK`] usable contacts closest to
    /// `me` by Kad distance, nearest first; ties keep file order, as aMule's
    /// insertion does.
    pub fn bootstrap_pick(&self, me: UInt128) -> Vec<&Contact> {
        let mut picks: Vec<&Contact> = self.usable().collect();
        picks.sort_by_key(|c| c.id.distance(me));
        picks.truncate(BOOTSTRAP_PICK);
        picks
    }
}

#[cfg(test)]
mod tests;
