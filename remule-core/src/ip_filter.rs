// SPDX-License-Identifier: GPL-2.0-or-later
//! The IP filter as the client applies it: `CIPFilter::IsFiltered` with the
//! `FilterLevel`, `IpFilterClients` and `IpFilterServers` preferences.
//!
//! The lists themselves (`ipfilter.dat`, `ipfilter_static.dat`) are read and
//! resolved by [`ed2k_formats::ipfilter`].

use std::net::Ipv4Addr;
use std::sync::RwLock;

use ed2k_formats::ipfilter::IpFilter;

/// aMule's default `FilterLevel`: ranges below 127 are blocked.
pub const DEFAULT_LEVEL: u32 = 127;

/// A loaded filter and how to apply it. Shared by everything that checks
/// addresses, and reloaded in place ([`AddressFilter::replace`]).
#[derive(Debug)]
pub struct AddressFilter {
    inner: RwLock<Inner>,
}

#[derive(Debug, Clone)]
struct Inner {
    filter: IpFilter,
    level: u32,
    clients: bool,
    servers: bool,
}

impl Clone for AddressFilter {
    fn clone(&self) -> Self {
        AddressFilter {
            inner: RwLock::new(self.read().clone()),
        }
    }
}

impl AddressFilter {
    /// `level`: a range is blocked when its level is below this
    /// (`FilterLevel`); `clients` and `servers`: whether peers and servers
    /// are filtered at all (`IpFilterClients`, `IpFilterServers`).
    pub fn new(filter: IpFilter, level: u32, clients: bool, servers: bool) -> Self {
        AddressFilter {
            inner: RwLock::new(Inner {
                filter,
                level,
                clients,
                servers,
            }),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    /// A reloaded filter in place of this one (`OnIPFilterEvent`), for
    /// everything that shares it.
    pub fn replace(&self, other: AddressFilter) {
        let new = other.read().clone();
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = new;
    }

    /// `IsFiltered(ip, false)`: a peer, as a source or connecting to us.
    pub fn blocks_client(&self, ip: Ipv4Addr) -> bool {
        let f = self.read();
        f.clients && f.filter.is_filtered_v4(ip, f.level)
    }

    /// `IsFiltered(ip, true)`: a server.
    pub fn blocks_server(&self, ip: Ipv4Addr) -> bool {
        let f = self.read();
        f.servers && f.filter.is_filtered_v4(ip, f.level)
    }

    /// Ranges blocked at this level (`BanCount`).
    pub fn ban_count(&self) -> usize {
        let f = self.read();
        f.filter.ban_count(f.level)
    }
}
