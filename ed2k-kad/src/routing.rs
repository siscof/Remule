// SPDX-License-Identifier: GPL-2.0-or-later
//! The routing table (`CRoutingZone`, `CRoutingBin`).
//!
//! A binary tree of zones over the XOR distance from our ID. A leaf holds
//! a bin of at most [`K`] contacts; a full leaf splits while it is near us
//! (its index, the path from the root read as a number, below [`KK`]) or
//! near the root (level below [`KBASE`]). The tree is an arena: zones are
//! indices into a vector, a parent knows its two children.
//!
//! Anti-flooding: at most one contact per IP and ten per /24 in the whole
//! table, two per /24 in one bin (LAN addresses are exempt from the /24 rules).

use std::collections::{BTreeMap, HashMap};

use ed2k_types::UInt128;

use crate::contact::{is_good_ip_port, is_lan_ip, Contact, UdpKey};

/// Contacts per bin.
pub const K: usize = 10;
/// Levels near the root that always split.
pub const KBASE: u32 = 4;
/// Zone indices (near us) that always split.
pub const KK: u128 = 5;
/// `MAX_CONTACTS_IP`
pub const MAX_CONTACTS_IP: u32 = 1;
/// `MAX_CONTACTS_SUBNET`
pub const MAX_CONTACTS_SUBNET: u32 = 10;
/// `LOG_BASE_EXPONENT`: depth of the bootstrap contact sample.
pub const LOG_BASE_EXPONENT: u32 = 5;
/// `CONTACT_FILE_LIMIT`
pub const CONTACT_FILE_LIMIT: usize = 500;

#[derive(Debug, Clone)]
enum Node {
    Leaf(Vec<Contact>),
    Split([usize; 2]),
}

#[derive(Debug, Clone)]
struct Zone {
    level: u32,
    index: UInt128,
    node: Node,
    next_big_timer: u64,
    next_small_timer: u64,
}

/// What a lookup should go and find (`RandomLookup`).
pub type LookupTarget = UInt128;

/// The application's IP filter (`CIPFilter::IsFiltered`): true for an
/// address (aMule order) that is to be left alone.
#[derive(Clone)]
pub struct AddressCheck(pub std::sync::Arc<dyn Fn(u32) -> bool + Send + Sync>);

impl std::fmt::Debug for AddressCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AddressCheck")
    }
}

/// The table.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    /// Contacts the IP filter blocks are not taken (`CRoutingZone::Add`).
    pub ip_filter: Option<AddressCheck>,
    me: UInt128,
    zones: Vec<Option<Zone>>,
    free: Vec<usize>,
    ips: HashMap<u32, u32>,
    subnets: HashMap<u32, u32>,
    /// Our public IP (aMule order), for comparing UDP keys.
    pub public_ip: u32,
    /// `thePrefs::FilterLanIPs`
    pub filter_lan: bool,
}

const ROOT: usize = 0;

fn subnet(ip: u32) -> u32 {
    ip & 0xFFFF_FF00
}

impl RoutingTable {
    pub fn new(me: UInt128, now: u64) -> Self {
        let mut t = RoutingTable {
            ip_filter: None,
            me,
            zones: Vec::new(),
            free: Vec::new(),
            ips: HashMap::new(),
            subnets: HashMap::new(),
            public_ip: 0,
            filter_lan: true,
        };
        t.new_zone(0, UInt128::ZERO, now);
        t
    }

    pub fn me(&self) -> UInt128 {
        self.me
    }

    fn new_zone(&mut self, level: u32, index: UInt128, now: u64) -> usize {
        let z = Zone {
            level,
            index,
            node: Node::Leaf(Vec::new()),
            next_big_timer: now + 10,
            // Zones closer to the root are processed earlier.
            next_small_timer: now + index.chunk(3) as u64,
        };
        match self.free.pop() {
            Some(i) => {
                self.zones[i] = Some(z);
                i
            }
            None => {
                self.zones.push(Some(z));
                self.zones.len() - 1
            }
        }
    }

    fn zone(&self, i: usize) -> &Zone {
        self.zones[i].as_ref().expect("live zone")
    }

    fn zone_mut(&mut self, i: usize) -> &mut Zone {
        self.zones[i].as_mut().expect("live zone")
    }

    /// The leaf the ID `id` belongs to.
    fn leaf_for(&self, id: UInt128) -> usize {
        let d = id ^ self.me;
        let mut z = ROOT;
        loop {
            match &self.zone(z).node {
                Node::Leaf(_) => return z,
                Node::Split(c) => z = c[d.bit(self.zone(z).level as usize) as usize],
            }
        }
    }

    fn bin(&self, z: usize) -> &Vec<Contact> {
        match &self.zone(z).node {
            Node::Leaf(b) => b,
            Node::Split(_) => unreachable!("not a leaf"),
        }
    }

    fn bin_mut(&mut self, z: usize) -> &mut Vec<Contact> {
        match &mut self.zone_mut(z).node {
            Node::Leaf(b) => b,
            Node::Split(_) => unreachable!("not a leaf"),
        }
    }

    fn leaves(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![ROOT];
        while let Some(z) = stack.pop() {
            match &self.zone(z).node {
                Node::Leaf(_) => out.push(z),
                Node::Split([a, b]) => {
                    stack.push(*b);
                    stack.push(*a);
                }
            }
        }
        out
    }

    // ------------------------------------------------------------ tracking

    fn track(&mut self, ip: u32, up: bool) {
        for (map, key) in [(&mut self.ips, ip), (&mut self.subnets, subnet(ip))] {
            let n = map.entry(key).or_insert(0);
            if up {
                *n += 1;
            } else {
                *n = n.saturating_sub(1);
            }
            if *n == 0 {
                map.remove(&key);
            }
        }
    }

    /// Whether the IP filter blocks `ip` (aMule order).
    pub fn filtered(&self, ip: u32) -> bool {
        self.ip_filter.as_ref().is_some_and(|f| (f.0)(ip))
    }

    /// `CheckGlobalIPLimits`
    pub fn within_global_limits(&self, ip: u32) -> bool {
        if self.ips.get(&ip).copied().unwrap_or(0) >= MAX_CONTACTS_IP {
            return false;
        }
        !(self.subnets.get(&subnet(ip)).copied().unwrap_or(0) >= MAX_CONTACTS_SUBNET
            && !is_lan_ip(ip))
    }

    /// `CRoutingBin::AddContact`
    fn bin_add(&mut self, z: usize, c: Contact) -> bool {
        let bin = self.bin(z);
        if bin.iter().any(|x| x.id == c.id) {
            return false;
        }
        let same_subnet = bin.iter().filter(|x| subnet(x.ip) == subnet(c.ip)).count();
        if !self.within_global_limits(c.ip) {
            return false;
        }
        if same_subnet >= 2 && !is_lan_ip(c.ip) {
            return false;
        }
        if self.bin(z).len() < K {
            self.track(c.ip, true);
            self.bin_mut(z).push(c);
            return true;
        }
        false
    }

    // ------------------------------------------------------------ adding

    /// `CRoutingZone::Add`: filter the address, then [`Self::add_unfiltered`].
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        id: UInt128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        key: UdpKey,
        ip_verified: &mut bool,
        update: bool,
        from_hello: bool,
        now: u64,
    ) -> bool {
        if !is_good_ip_port(ip, udp_port, self.filter_lan)
            || self.filtered(ip)
            || (udp_port == 53 && version <= 5)
        {
            return false;
        }
        self.add_unfiltered(
            id,
            ip,
            udp_port,
            tcp_port,
            version,
            key,
            ip_verified,
            update,
            from_hello,
            now,
        )
    }

    /// `AddUnfiltered`: whether the contact was added, or (with `update`)
    /// updated. `ip_verified` comes back as the stored contact's.
    #[allow(clippy::too_many_arguments)]
    pub fn add_unfiltered(
        &mut self,
        id: UInt128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        key: UdpKey,
        ip_verified: &mut bool,
        mut update: bool,
        from_hello: bool,
        now: u64,
    ) -> bool {
        if id == self.me {
            return false;
        }
        let mut c = Contact::new(id, ip, udp_port, tcp_port, version, key, *ip_verified, now);
        c.received_hello = from_hello;
        if self.add_contact(c, &mut update, ip_verified, now) {
            true
        } else {
            update
        }
    }

    fn add_contact(
        &mut self,
        c: Contact,
        update: &mut bool,
        out_verified: &mut bool,
        now: u64,
    ) -> bool {
        let z = self.leaf_for(c.id);
        if let Some(pos) = self.bin(z).iter().position(|x| x.id == c.id) {
            if *update {
                self.update_existing(z, pos, c, update, out_verified, now);
            }
            return false;
        }
        if self.bin(z).len() < K {
            *update = false;
            return self.bin_add(z, c);
        }
        if self.can_split(z) {
            self.split(z, now);
            return self.add_contact(c, update, out_verified, now);
        }
        *update = false;
        false
    }

    fn update_existing(
        &mut self,
        z: usize,
        pos: usize,
        c: Contact,
        update: &mut bool,
        out_verified: &mut bool,
        now: u64,
    ) {
        let pub_ip = self.public_ip;
        let old = &self.bin(z)[pos];
        let old_key = old.udp_key.value_for(pub_ip);
        if old_key != 0 && old_key != c.udp_key.value_for(pub_ip) {
            // An update without the key the contact gave us before.
            *update = false;
        } else if (1..6).contains(&old.version) && old.received_hello {
            // Legacy nodes without keys: only a refresh of the same details.
            if old.ip == c.ip
                && old.tcp_port == c.tcp_port
                && old.version == c.version
                && old.udp_port == c.udp_port
            {
                *out_verified = old.ip_verified;
                self.set_alive(z, pos, now);
            } else {
                *update = false;
            }
        } else if self.change_ip(z, pos, c.ip) && c.version >= self.bin(z)[pos].version {
            let e = &mut self.bin_mut(z)[pos];
            e.udp_port = c.udp_port;
            e.tcp_port = c.tcp_port;
            e.version = c.version;
            e.udp_key = c.udp_key;
            if !e.ip_verified {
                e.ip_verified = c.ip_verified;
            }
            *out_verified = e.ip_verified;
            if c.received_hello {
                e.received_hello = true;
            }
            self.set_alive(z, pos, now);
        } else {
            *update = false;
        }
    }

    /// `ChangeContactIPAddress`
    fn change_ip(&mut self, z: usize, pos: usize, new_ip: u32) -> bool {
        let old_ip = self.bin(z)[pos].ip;
        if old_ip == new_ip {
            return true;
        }
        if self.ips.get(&new_ip).copied().unwrap_or(0) >= MAX_CONTACTS_IP {
            return false;
        }
        if subnet(old_ip) != subnet(new_ip) {
            if self.subnets.get(&subnet(new_ip)).copied().unwrap_or(0) >= MAX_CONTACTS_SUBNET
                && !is_lan_ip(new_ip)
            {
                return false;
            }
            let same = self
                .bin(z)
                .iter()
                .filter(|x| subnet(x.ip) == subnet(new_ip))
                .count();
            if same >= 2 && !is_lan_ip(new_ip) {
                return false;
            }
        }
        self.track(old_ip, false);
        self.bin_mut(z)[pos].ip = new_ip;
        self.track(new_ip, true);
        true
    }

    /// `SetAlive`: update its type and move it to the end of its bin.
    fn set_alive(&mut self, z: usize, pos: usize, now: u64) {
        let bin = self.bin_mut(z);
        let mut c = bin.remove(pos);
        c.update_type(now);
        bin.push(c);
    }

    fn can_split(&self, z: usize) -> bool {
        let zone = self.zone(z);
        zone.level < 127
            && (zone.index < UInt128::new(KK) || zone.level < KBASE)
            && self.bin(z).len() == K
    }

    fn split(&mut self, z: usize, now: u64) {
        let (level, index) = (self.zone(z).level, self.zone(z).index);
        let entries = std::mem::take(self.bin_mut(z));
        for c in &entries {
            self.track(c.ip, false);
        }
        let a = self.new_zone(level + 1, index << 1, now);
        let b = self.new_zone(level + 1, (index << 1) + UInt128::new(1), now);
        self.zone_mut(z).node = Node::Split([a, b]);
        for c in entries {
            let side = (c.id ^ self.me).bit(level as usize) as usize;
            self.bin_add([a, b][side], c);
        }
    }

    /// `Consolidate`: merge sibling leaves holding fewer than K/2 together.
    /// Returns how many merges there were.
    pub fn consolidate(&mut self, now: u64) -> u32 {
        self.consolidate_zone(ROOT, now)
    }

    fn consolidate_zone(&mut self, z: usize, now: u64) -> u32 {
        let Node::Split([a, b]) = self.zone(z).node else {
            return 0;
        };
        let mut merged = self.consolidate_zone(a, now) + self.consolidate_zone(b, now);
        let leaf = |t: &Self, i: usize| matches!(t.zone(i).node, Node::Leaf(_));
        if leaf(self, a) && leaf(self, b) && self.bin(a).len() + self.bin(b).len() < K / 2 {
            let mut entries = std::mem::take(self.bin_mut(a));
            entries.append(self.bin_mut(b));
            for c in &entries {
                self.track(c.ip, false);
            }
            self.zones[a] = None;
            self.zones[b] = None;
            self.free.extend([a, b]);
            let zone = self.zone_mut(z);
            zone.node = Node::Leaf(Vec::new());
            zone.next_big_timer = now + 10;
            for c in entries {
                self.bin_add(z, c);
            }
            merged += 1;
        }
        merged
    }

    // ------------------------------------------------------------ queries

    pub fn get(&self, id: UInt128) -> Option<&Contact> {
        self.bin(self.leaf_for(id)).iter().find(|c| c.id == id)
    }

    pub fn get_mut(&mut self, id: UInt128) -> Option<&mut Contact> {
        let z = self.leaf_for(id);
        self.bin_mut(z).iter_mut().find(|c| c.id == id)
    }

    /// `GetContact(ip, port, tcpPort)`; a port of 0 matches any.
    pub fn get_by_addr(&self, ip: u32, port: u16, tcp: bool) -> Option<&Contact> {
        self.contacts().find(|c| {
            c.ip == ip && (port == 0 || (!tcp && port == c.udp_port) || (tcp && port == c.tcp_port))
        })
    }

    /// Every contact, leaf by leaf (`GetAllEntries`).
    pub fn contacts(&self) -> impl Iterator<Item = &Contact> {
        self.leaves()
            .into_iter()
            .flat_map(move |z| self.bin(z).iter())
    }

    pub fn len(&self) -> usize {
        self.leaves().iter().map(|&z| self.bin(z).len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Verified contacts of type at most `max_type`, closest to `target`
    /// first, at most `max` (`GetClosestTo`).
    pub fn closest_to(
        &self,
        max_type: u8,
        target: UInt128,
        max: usize,
    ) -> BTreeMap<UInt128, Contact> {
        let mut out = BTreeMap::new();
        self.closest_in(ROOT, max_type, target, target ^ self.me, max, &mut out);
        out
    }

    fn closest_in(
        &self,
        z: usize,
        max_type: u8,
        target: UInt128,
        distance: UInt128,
        max: usize,
        out: &mut BTreeMap<UInt128, Contact>,
    ) {
        match &self.zone(z).node {
            Node::Leaf(bin) => {
                for c in bin {
                    if c.kind <= max_type && c.ip_verified {
                        out.insert(c.id ^ target, c.clone());
                    }
                }
                while out.len() > max {
                    out.pop_last();
                }
            }
            Node::Split(ch) => {
                let closer = distance.bit(self.zone(z).level as usize) as usize;
                self.closest_in(ch[closer], max_type, target, distance, max, out);
                if out.len() < max {
                    self.closest_in(ch[1 - closer], max_type, target, distance, max, out);
                }
            }
        }
    }

    /// `GetBootstrapContacts`: contacts down to depth [`LOG_BASE_EXPONENT`]
    /// (below it, one random bin per branch). `pick` chooses a branch (0 or 1).
    pub fn bootstrap_contacts(&self, max: usize, pick: &mut impl FnMut() -> usize) -> Vec<Contact> {
        let mut out = Vec::new();
        self.top_depth(ROOT, LOG_BASE_EXPONENT as i32, &mut out, pick);
        out.truncate(max);
        out
    }

    fn top_depth(
        &self,
        z: usize,
        depth: i32,
        out: &mut Vec<Contact>,
        pick: &mut impl FnMut() -> usize,
    ) {
        match &self.zone(z).node {
            Node::Leaf(bin) => out.extend(bin.iter().cloned()),
            Node::Split(ch) if depth <= 0 => {
                // RandomBin
                let mut z = ch[pick() & 1];
                loop {
                    match &self.zone(z).node {
                        Node::Leaf(bin) => {
                            out.extend(bin.iter().cloned());
                            break;
                        }
                        Node::Split(ch) => z = ch[pick() & 1],
                    }
                }
            }
            Node::Split([a, b]) => {
                self.top_depth(*a, depth - 1, out, pick);
                self.top_depth(*b, depth - 1, out, pick);
            }
        }
    }

    /// `GetRandomContact`
    pub fn random_contact(
        &self,
        max_type: u8,
        min_version: u8,
        rnd: &mut impl FnMut() -> usize,
    ) -> Option<&Contact> {
        let fits: Vec<&Contact> = self
            .contacts()
            .filter(|c| c.kind <= max_type && c.version >= min_version)
            .collect();
        if fits.is_empty() {
            None
        } else {
            Some(fits[rnd() % fits.len()])
        }
    }

    /// `VerifyContact`: the contact proved it owns its IP.
    pub fn verify(&mut self, id: UInt128, ip: u32) -> bool {
        match self.get_mut(id) {
            Some(c) if c.ip == ip => {
                c.ip_verified = true;
                true
            }
            _ => false,
        }
    }

    /// `SetAllContactsVerified` (a nodes.dat without verified flags).
    pub fn set_all_verified(&mut self) {
        for z in self.leaves() {
            for c in self.bin_mut(z) {
                c.ip_verified = true;
            }
        }
    }

    /// `IsAcceptableContact`: may a contact from a lookup answer be queried?
    pub fn is_acceptable(&self, c: &Contact) -> bool {
        if c.version <= 1 {
            return false;
        }
        if let Some(d) = self.get(c.id) {
            return !((d.ip_verified && d.ip != c.ip) || d.udp_port != c.udp_port);
        }
        self.within_global_limits(c.ip)
    }

    /// Leaves and their depth, for statistics.
    pub fn depth(&self) -> u32 {
        self.leaves()
            .iter()
            .map(|&z| self.zone(z).level)
            .max()
            .unwrap_or(0)
    }

    /// `EstimateCount` of the zone holding the most (a guess of the network
    /// size, without the firewalled-ratio adjustments).
    pub fn estimate_users(&self) -> u32 {
        let mut best = 0u32;
        for z in self.leaves() {
            let zone = self.zone(z);
            let est = if zone.level < KBASE {
                2f64.powi(zone.level as i32) * K as f64
            } else {
                // The zone three levels up, counted.
                let mut up = zone.index;
                let lvl = zone.level - 3;
                up = UInt128::new(up.value() >> 3);
                let n = self.count_under(lvl, up) as f64;
                2f64.powi(zone.level as i32 - 2) * K as f64 * (n / (K * 2) as f64) * 1.20
            };
            best = best.max(est as u32);
        }
        best
    }

    fn count_under(&self, level: u32, index: UInt128) -> usize {
        self.leaves()
            .into_iter()
            .filter(|&z| {
                let zone = self.zone(z);
                zone.level >= level
                    && UInt128::new(zone.index.value() >> (zone.level - level)) == index
            })
            .map(|z| self.bin(z).len())
            .sum()
    }

    // ------------------------------------------------------------ timers

    /// `OnSmallTimer` of every leaf that is due: drop dead contacts, and
    /// return those to send a `KADEMLIA2_HELLO_REQ` to (one per leaf: its
    /// oldest, if its time has come).
    pub fn small_timer(&mut self, now: u64) -> Vec<Contact> {
        let mut hello = Vec::new();
        for z in self.leaves() {
            if self.zone(z).next_small_timer > now {
                continue;
            }
            self.zone_mut(z).next_small_timer = now + 60;
            let dead: Vec<usize> = self
                .bin(z)
                .iter()
                .enumerate()
                .filter(|(_, c)| c.kind == 4 && c.expires > 0 && c.expires <= now)
                .map(|(i, _)| i)
                .collect();
            for i in dead.into_iter().rev() {
                let c = self.bin_mut(z).remove(i);
                self.track(c.ip, false);
            }
            for c in self.bin_mut(z) {
                if c.expires == 0 {
                    c.expires = now;
                }
            }
            let Some(oldest) = self.bin(z).first() else {
                continue;
            };
            if oldest.expires >= now || oldest.kind == 4 {
                let bin = self.bin_mut(z);
                let c = bin.remove(0);
                bin.push(c);
                continue;
            }
            let c = &mut self.bin_mut(z)[0];
            c.checking_type(now);
            // Older contacts are aged out without a hello, as in aMule.
            if c.version >= 6 {
                hello.push(c.clone());
            }
        }
        hello
    }

    /// The big timer (every 10 s): the first due leaf that wants it gets a
    /// random lookup in its range (`OnBigTimer` / `RandomLookup`).
    /// `random` supplies the bits below the zone's prefix.
    ///
    /// With `stale` (nothing heard for most of the disconnect delay), every
    /// leaf is due, not only those whose hour is up: `CKademlia::Process`
    /// keeps a node that nobody contacts, such as one behind a NAT, talking
    /// this way.
    pub fn big_timer(&mut self, now: u64, random: u128, stale: bool) -> Option<LookupTarget> {
        for z in self.leaves() {
            let zone = self.zone(z);
            if zone.next_big_timer > now && !stale {
                continue;
            }
            let wants = zone.index < UInt128::new(KK)
                || zone.level < KBASE
                || K - self.bin(z).len() >= (K * 8).div_ceil(10);
            if !wants {
                continue;
            }
            let (level, index) = (zone.level, zone.index);
            self.zone_mut(z).next_big_timer = now + 3600;
            let prefix = if level == 0 {
                UInt128::ZERO
            } else {
                UInt128::new(index.value() << (128 - level))
            };
            return Some(prefix.with_prefix_bits(level, random) ^ self.me);
        }
        None
    }
}
