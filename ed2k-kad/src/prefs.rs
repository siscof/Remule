// SPDX-License-Identifier: GPL-2.0-or-later
//! `preferencesKad.dat` (`Kademlia::CPrefs::ReadFile` / `WriteFile`):
//! `<public IP 4><0 2><Kad ID 16><tag count 1 (0)>`.

use std::net::Ipv4Addr;

use ed2k_codec::{Reader, Writer};
use ed2k_types::UInt128;

pub const FILE_NAME: &str = "preferencesKad.dat";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KadPrefs {
    /// Our public IP as last seen (aMule order).
    pub public_ip: u32,
    pub kad_id: UInt128,
}

impl KadPrefs {
    /// Read a file; `None` if it is short. A zero ID (stored by old
    /// versions) reads as `None` too: aMule then makes a new one.
    pub fn read(bytes: &[u8]) -> Option<KadPrefs> {
        let mut r = Reader::new(bytes);
        let public_ip = r.u32().ok()?;
        r.u16().ok()?;
        let kad_id = r.uint128().ok()?;
        (!kad_id.is_zero()).then_some(KadPrefs { public_ip, kad_id })
    }

    pub fn write(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.public_ip).u16(0).uint128(self.kad_id).u8(0);
        w.into_bytes()
    }

    pub fn public_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.public_ip)
    }
}
