// SPDX-License-Identifier: GPL-2.0-or-later
//! The IP filter as the client applies it: `CIPFilter::IsFiltered` with the
//! `FilterLevel`, `IpFilterClients` and `IpFilterServers` preferences.
//!
//! The lists themselves (`ipfilter.dat`, `ipfilter_static.dat`) are read and
//! resolved by [`ed2k_formats::ipfilter`].

use std::net::Ipv4Addr;

use ed2k_formats::ipfilter::IpFilter;

/// aMule's default `FilterLevel`: ranges below 127 are blocked.
pub const DEFAULT_LEVEL: u32 = 127;

/// A loaded filter and how to apply it.
#[derive(Debug, Clone)]
pub struct AddressFilter {
    filter: IpFilter,
    level: u32,
    clients: bool,
    servers: bool,
}

impl AddressFilter {
    /// `level`: a range is blocked when its level is below this
    /// (`FilterLevel`); `clients` and `servers`: whether peers and servers
    /// are filtered at all (`IpFilterClients`, `IpFilterServers`).
    pub fn new(filter: IpFilter, level: u32, clients: bool, servers: bool) -> Self {
        AddressFilter {
            filter,
            level,
            clients,
            servers,
        }
    }

    /// `IsFiltered(ip, false)`: a peer, as a source or connecting to us.
    pub fn blocks_client(&self, ip: Ipv4Addr) -> bool {
        self.clients && self.filter.is_filtered_v4(ip, self.level)
    }

    /// `IsFiltered(ip, true)`: a server.
    pub fn blocks_server(&self, ip: Ipv4Addr) -> bool {
        self.servers && self.filter.is_filtered_v4(ip, self.level)
    }

    /// Ranges blocked at this level (`BanCount`).
    pub fn ban_count(&self) -> usize {
        self.filter.ban_count(self.level)
    }
}
