// SPDX-License-Identifier: GPL-2.0-or-later
//! Servers and networks over external connections: what `amulecmd`'s
//! `show servers`, `connect`, `disconnect`, `add` and `remove` (and
//! `amulegui`'s server list) send.
//!
//! * `EC_OP_GET_SERVER_LIST`: every server, as `CEC_Server_Tag`.
//! * `EC_OP_SERVER_CONNECT` (one server, or any), `EC_OP_SERVER_DISCONNECT`,
//!   `EC_OP_SERVER_ADD`, `EC_OP_SERVER_REMOVE` (`Get_EC_Response_Server`,
//!   `Get_EC_Response_Server_Add`).
//! * `EC_OP_CONNECT`, `EC_OP_DISCONNECT`: both networks;
//!   `EC_OP_KAD_START`, `EC_OP_KAD_STOP`, `EC_OP_KAD_BOOTSTRAP_FROM_IP`.
//! * `EC_OP_SERVER_UPDATE_FROM_URL`: `server.met` fetched from a URL, or
//!   from each of `addresses.dat`'s, and merged into the list
//!   (`UpdateServerMetFromURL`, `LoadServerMet`).
//!
//! The client loop owns the list and the [`Connector`]; [`handle`] answers
//! a request from them without IO and says what the loop must then do
//! ([`Effect`]). The list is written back to `server.met` on shutdown when
//! it changed, as `~CServerList` writes it.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::Path;
use std::time::Instant;

use ed2k_formats::server_met::{ServerInfo, ServerMet, VERSION};
use remule_core::download_queue::is_good_ip;
use remule_core::ip_filter::AddressFilter;
use remule_ec::codes::*;
use remule_ec::{Packet, Tag};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::ec::Control;
use crate::server_conn::{Connector, Next};

/// The requests this module answers.
pub fn is_server_request(opcode: u8) -> bool {
    matches!(
        opcode,
        EC_OP_GET_SERVER_LIST
            | EC_OP_SERVER_CONNECT
            | EC_OP_SERVER_DISCONNECT
            | EC_OP_SERVER_ADD
            | EC_OP_SERVER_REMOVE
            | EC_OP_CONNECT
            | EC_OP_DISCONNECT
            | EC_OP_KAD_START
            | EC_OP_KAD_STOP
            | EC_OP_KAD_BOOTSTRAP_FROM_IP
            | EC_OP_SERVER_UPDATE_FROM_URL
            | EC_OP_SERVER_SET_STATIC_PRIO
    )
}

/// Hand a server request to the client loop and wait for its answer.
pub async fn ask(req: &Packet, control: &mpsc::UnboundedSender<Control>) -> Packet {
    let (reply, rx) = oneshot::channel();
    if control
        .send(Control::Servers {
            request: req.clone(),
            reply,
        })
        .is_err()
    {
        return failed("Already shutting down.");
    }
    rx.await
        .unwrap_or_else(|_| failed("Already shutting down."))
}

fn failed(message: &str) -> Packet {
    Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, message))
}

/// The servers as the user sees them (`CServerList`): what `server.met`
/// says of each, in the order they are tried.
#[derive(Debug, Clone, Default)]
pub struct ServerList {
    entries: Vec<ServerInfo>,
    changed: bool,
    /// Those `staticservers.dat` keeps (`IsStaticMember`), by [`key`].
    statics: std::collections::HashSet<(String, u16)>,
}

/// A server as `GetServerByAddress` knows it: its host name when it has a
/// dynamic IP (case aside), else its IP; and its port.
pub fn key(e: &ServerInfo) -> (String, u16) {
    let addr = if e.dyn_ip.is_empty() {
        e.ip.map(|ip| ip.to_string()).unwrap_or_default()
    } else {
        e.dyn_ip.to_lowercase()
    };
    (addr, e.port)
}

/// Whether an address is a host name, not an IP (`HasDynIP`).
fn is_host_name(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>().is_err()
}

/// A line of `staticservers.dat`: `host:port,priority,name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticServer {
    /// An IP, or a host name (a dynamic-IP server).
    pub host: String,
    pub port: u16,
    pub preference: u32,
    pub name: String,
}

impl StaticServer {
    /// Its address, when it is given by IP.
    pub fn addr(&self) -> Option<SocketAddrV4> {
        self.host
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .map(|ip| SocketAddrV4::new(ip, self.port))
    }

    fn key(&self) -> (String, u16) {
        (self.host.to_lowercase(), self.port)
    }
}

/// `LoadStaticServers`: one server a line, `host:port,priority,name`;
/// blank lines and those starting with `#` or `/` skipped, as are lines
/// without exactly three fields. A priority out of range is normal; a
/// missing name is the address. A host name makes a dynamic-IP server.
pub fn read_static_servers(dir: &Path) -> Vec<StaticServer> {
    use ed2k_formats::server_met::{PRIORITY_LOW, PRIORITY_NORMAL};
    let text = std::fs::read(dir.join("staticservers.dat"))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with('/') {
            continue;
        }
        // wxStringTokenizer: empty fields count, but not a trailing one.
        let mut fields: Vec<&str> = line.split(',').collect();
        if fields.last() == Some(&"") {
            fields.pop();
        }
        if fields.len() != 3 {
            continue;
        }
        let (addy, prio, name) = (fields[0].trim(), fields[1].trim(), fields[2].trim());
        let (host, port) = addy.split_once(':').unwrap_or((addy, ""));
        if host.is_empty() {
            continue;
        }
        // StrToLong: the leading digits.
        let num = |t: &str| -> i64 {
            let d: String = t.chars().take_while(char::is_ascii_digit).collect();
            d.parse().unwrap_or(0)
        };
        let port = num(port);
        if port <= 0 || port > i64::from(u16::MAX) {
            continue;
        }
        let p = num(prio);
        let preference = if (0..=i64::from(PRIORITY_LOW)).contains(&p) {
            p as u32
        } else {
            PRIORITY_NORMAL
        };
        out.push(StaticServer {
            host: host.to_owned(),
            port: port as u16,
            preference,
            name: if name.is_empty() {
                addy.to_owned()
            } else {
                name.to_owned()
            },
        });
    }
    out
}

fn v4(a: SocketAddr) -> Option<SocketAddrV4> {
    match a {
        SocketAddr::V4(a) => Some(a),
        SocketAddr::V6(_) => None,
    }
}

impl ServerList {
    /// The servers to try, with what `met` says of them.
    pub fn new(addrs: &[SocketAddr], met: Option<&ServerMet>) -> Self {
        let known: Vec<ServerInfo> = met
            .map(|m| m.servers.iter().map(ServerInfo::from_record).collect())
            .unwrap_or_default();
        let entries = addrs
            .iter()
            .filter_map(|a| v4(*a))
            .map(|a| {
                known
                    .iter()
                    .find(|s| s.ip == Some(*a.ip()) && s.port == a.port())
                    .cloned()
                    .unwrap_or_else(|| ServerInfo {
                        ip: Some(*a.ip()),
                        port: a.port(),
                        ..Default::default()
                    })
            })
            .collect();
        ServerList {
            entries,
            changed: false,
            statics: Default::default(),
        }
    }

    /// With `dir/server.met`, if there is one, and `dir/staticservers.dat`'s
    /// servers marked static, named and given their priority.
    pub fn load(dir: &Path, addrs: &[SocketAddr]) -> Self {
        let met = std::fs::read(dir.join("server.met"))
            .ok()
            .and_then(|b| ServerMet::read(&b).ok());
        let mut list = Self::new(addrs, met.as_ref());
        // Servers known by host name and not yet by IP: kept, to be
        // resolved ([`ServerList::unresolved`]).
        if let Some(m) = &met {
            for s in m.servers.iter().map(ServerInfo::from_record) {
                let unresolved = s.ip.is_none_or(|ip| ip.is_unspecified());
                if !s.dyn_ip.is_empty() && unresolved && s.port != 0 {
                    list.push_dyn(s);
                }
            }
        }
        list.apply_statics(&read_static_servers(dir));
        list
    }

    /// A dynamic-IP server added unresolved, unless listed already.
    fn push_dyn(&mut self, mut s: ServerInfo) -> bool {
        s.ip = None;
        let k = key(&s);
        if self.entries.iter().any(|e| key(e) == k) {
            return false;
        }
        self.entries.push(s);
        true
    }

    /// The static servers: listed ones marked (those `addrs` let through),
    /// and those known by host name added if they are not listed.
    pub fn apply_statics(&mut self, statics: &[StaticServer]) {
        for st in statics {
            if st.addr().is_none() {
                self.push_dyn(ServerInfo {
                    dyn_ip: st.host.clone(),
                    port: st.port,
                    ..Default::default()
                });
            }
            let k = st.key();
            if let Some(e) = self.entries.iter_mut().find(|e| key(e) == k) {
                e.name = st.name.clone();
                e.preference = st.preference;
                self.statics.insert(k);
            }
        }
    }

    /// `IsStaticMember`.
    pub fn is_static(&self, a: SocketAddrV4) -> bool {
        self.find(a).is_some_and(|e| self.statics.contains(&key(e)))
    }

    /// `SetStaticServer`: marked or not, and `staticservers.dat` written.
    pub fn set_static(&mut self, a: SocketAddrV4, is_static: bool, dir: &Path) {
        let Some(k) = self.find(a).map(key) else {
            return;
        };
        if is_static {
            self.statics.insert(k);
        } else {
            self.statics.remove(&k);
        }
        self.save_statics(dir);
    }

    /// The dynamic-IP servers, by host name and port.
    pub fn dyn_servers(&self) -> Vec<(String, u16)> {
        self.entries
            .iter()
            .filter(|e| !e.dyn_ip.is_empty())
            .map(|e| (e.dyn_ip.clone(), e.port))
            .collect()
    }

    /// Those not resolved yet.
    pub fn unresolved(&self) -> Vec<(String, u16)> {
        self.entries
            .iter()
            .filter(|e| !e.dyn_ip.is_empty() && e.ip.is_none())
            .map(|e| (e.dyn_ip.clone(), e.port))
            .collect()
    }

    /// A host name resolved (`SetID` after the lookup): the server's IP
    /// set. `Some(the address it had)` when it changed.
    pub fn resolved(
        &mut self,
        host: &str,
        port: u16,
        ip: std::net::Ipv4Addr,
    ) -> Option<Option<SocketAddrV4>> {
        let k = (host.to_lowercase(), port);
        let e = self
            .entries
            .iter_mut()
            .find(|e| !e.dyn_ip.is_empty() && key(e) == k)?;
        if e.ip == Some(ip) {
            return None;
        }
        let old = e.ip.map(|o| SocketAddrV4::new(o, port));
        e.ip = Some(ip);
        self.changed = true;
        Some(old)
    }

    /// `SetServerPrio`.
    pub fn set_priority(&mut self, a: SocketAddrV4, preference: u32) {
        if let Some(e) = self.find_mut(a) {
            e.preference = preference;
            self.changed = true;
        }
    }

    /// `SaveStaticServers`: `address:port,priority,name`, one a line, the
    /// address a host name for a dynamic-IP server.
    pub fn save_statics(&self, dir: &Path) {
        let mut text = String::new();
        for e in &self.entries {
            if !self.statics.contains(&key(e)) {
                continue;
            }
            let addr = if e.dyn_ip.is_empty() {
                e.ip.map(|ip| ip.to_string()).unwrap_or_default()
            } else {
                e.dyn_ip.clone()
            };
            text.push_str(&format!("{addr}:{},{},{}\n", e.port, e.preference, e.name));
        }
        let path = dir.join("staticservers.dat");
        if let Err(e) = std::fs::write(&path, text) {
            warn!("Failed to open '{}': {e}", path.display());
        }
    }

    pub fn entries(&self) -> &[ServerInfo] {
        &self.entries
    }

    /// For what is learnt of the servers as we run (pings); call
    /// [`ServerList::mark_changed`] after.
    pub fn entries_mut(&mut self) -> &mut [ServerInfo] {
        &mut self.entries
    }

    /// `server.met` is to be written again.
    pub fn mark_changed(&mut self) {
        self.changed = true;
    }

    /// `RemoveServer`.
    pub fn remove(&mut self, a: SocketAddrV4) {
        self.entries
            .retain(|s| !(s.ip == Some(*a.ip()) && s.port == a.port()));
        self.changed = true;
    }

    /// `RemoveServer(server, fromUser = true)`: a static server is written
    /// out of `staticservers.dat` too, or it comes back at the next start.
    pub fn remove_by_user(&mut self, a: SocketAddrV4, dir: &Path) {
        let k = self.find(a).map(key);
        self.remove(a);
        if k.is_some_and(|k| self.statics.remove(&k)) {
            self.save_statics(dir);
        }
    }

    /// Whether servers were added or removed, or what is known of them
    /// changed (pings).
    pub fn changed(&self) -> bool {
        self.changed
    }

    /// `GetServerByIPTCP`.
    pub fn find(&self, a: SocketAddrV4) -> Option<&ServerInfo> {
        self.entries
            .iter()
            .find(|s| s.ip == Some(*a.ip()) && s.port == a.port())
    }

    fn find_mut(&mut self, a: SocketAddrV4) -> Option<&mut ServerInfo> {
        self.entries
            .iter_mut()
            .find(|s| s.ip == Some(*a.ip()) && s.port == a.port())
    }

    /// `SaveServerMet`, when servers were added or removed.
    pub fn save_if_changed(&mut self, dir: &Path) {
        if !self.changed {
            return;
        }
        let met = ServerMet {
            version: VERSION,
            servers: self.entries.iter().map(ServerInfo::to_record).collect(),
            legacy_counts: false,
        };
        let path = dir.join("server.met");
        match std::fs::write(&path, met.write()) {
            Ok(()) => {
                self.changed = false;
                info!("wrote {} ({} servers)", path.display(), self.entries.len());
            }
            Err(e) => warn!("Failed to save server.met! ({}: {e})", path.display()),
        }
    }
}

/// What the client loop does after a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Drop the attempt in progress (`StopConnectionTry`).
    CancelAttempt,
    /// Hang up on the server we are logged into (`Disconnect`).
    Disconnect,
    /// Do what the connector says next.
    Follow(Next),
    /// Fetch `server.met` from these URLs in turn, merging each
    /// (`UpdateServerMetFromURL`).
    UpdateServerMet(Vec<String>),
    /// Start Kad if it is not running, and bootstrap from this node
    /// (`BootstrapKad`).
    BootstrapKad(SocketAddrV4),
    /// Look up a dynamic-IP server's host name.
    Resolve(String, u16),
    StartKad,
    StopKad,
}

/// What [`handle`] works on.
pub struct Ctx<'a> {
    pub list: &'a mut ServerList,
    pub connector: &'a mut Connector,
    /// `GetNetworkED2K`, `GetNetworkKademlia`.
    pub ed2k: bool,
    pub kad: bool,
    pub kad_running: bool,
    pub kad_connected: bool,
    /// What the server we are logged into said of itself.
    pub live: Option<&'a ed2k_server::session::ServerInfo>,
    pub ip_filter: Option<&'a AddressFilter>,
    pub filter_lan: bool,
    pub now: Instant,
    /// The config directory (`addresses.dat`).
    pub config: &'a Path,
    /// A server list download is under way.
    pub server_met_busy: bool,
    /// The server an ECID names.
    pub ecid: &'a dyn Fn(u32) -> Option<SocketAddrV4>,
}

/// `ServerListSources::IsValid`: an http or https URL naming a host, with
/// no white space or control characters.
pub fn valid_list_url(url: &str) -> bool {
    if url.contains(['\n', '\r', '\0', ' ', '\t']) {
        return false;
    }
    reqwest::Url::parse(url).is_ok_and(|u| {
        matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty())
    })
}

/// `GetServerListURLs`: `addresses.dat`, read afresh, one URL a line; the
/// valid ones, each once.
pub fn list_sources(config: &Path) -> Vec<String> {
    let text = std::fs::read(config.join("addresses.dat"))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for line in text.split(['\r', '\n']) {
        let url = line.trim();
        if valid_list_url(url) && !out.iter().any(|u| u == url) {
            out.push(url.to_owned());
        }
    }
    out
}

/// `LoadServerMet` merging a downloaded list: each server added as
/// `AddServer` adds one (a usable, unfiltered address not listed yet), a
/// listed one renamed and its description taken when it has one. The
/// number added.
pub fn merge_met(
    list: &mut ServerList,
    met: &ServerMet,
    connector: &mut Connector,
    ip_filter: Option<&AddressFilter>,
    filter_lan: bool,
) -> usize {
    let mut added = 0;
    for rec in &met.servers {
        let s = ServerInfo::from_record(rec);
        // A dynamic-IP server: by its host name; resolved later.
        if !s.dyn_ip.is_empty() {
            let k = key(&s);
            if let Some(e) = list.entries.iter_mut().find(|e| key(e) == k) {
                e.name = s.name.clone();
                if !s.description.is_empty() {
                    e.description = s.description.clone();
                }
                list.changed = true;
            } else if s.port != 0 && list.push_dyn(s) {
                list.changed = true;
                added += 1;
            }
            continue;
        }
        let Some(ip) = s.ip else { continue };
        let addr = SocketAddrV4::new(ip, s.port);
        if let Some(e) = list.find_mut(addr) {
            e.name = s.name.clone();
            if !s.description.is_empty() {
                e.description = s.description.clone();
            }
            list.changed = true;
            continue;
        }
        if s.port == 0
            || !is_good_ip(ip, filter_lan)
            || ip_filter.is_some_and(|f| f.blocks_server(ip))
        {
            continue;
        }
        list.entries.push(s);
        list.changed = true;
        connector.add(SocketAddr::V4(addr));
        added += 1;
    }
    info!("{added} servers added");
    added
}

/// `CEC_Server_Tag(server, detail_level)`.
pub fn server_tag(s: &ServerInfo, is_static: bool, tcp_flags: u32, detail: u8) -> Tag {
    let ip = s.ip.map_or([0; 4], |ip| ip.octets());
    let mut t = Tag::ipv4(EC_TAG_SERVER, ip, s.port);
    let mut add = |c: Tag| t.children.push(c);
    let nonzero = |name: u16, v: u32| (v != 0).then(|| Tag::int(name, v.into()));
    let text = |name: u16, v: &str| (!v.is_empty()).then(|| Tag::string(name, v));
    match detail {
        EC_DETAIL_UPDATE => {
            for c in [
                nonzero(EC_TAG_SERVER_PING, s.ping),
                nonzero(EC_TAG_SERVER_FAILED, s.failed & 0xFF),
            ]
            .into_iter()
            .flatten()
            {
                add(c);
            }
        }
        EC_DETAIL_WEB | EC_DETAIL_FULL | EC_DETAIL_CMD => {
            if detail != EC_DETAIL_CMD {
                for c in [
                    nonzero(EC_TAG_SERVER_PING, s.ping),
                    nonzero(EC_TAG_SERVER_PRIO, s.preference & 0xFF),
                    nonzero(EC_TAG_SERVER_FAILED, s.failed & 0xFF),
                    nonzero(EC_TAG_SERVER_STATIC, u32::from(is_static)),
                    text(EC_TAG_SERVER_VERSION, &s.version),
                    text(EC_TAG_SERVER_DESC, &s.description),
                    nonzero(EC_TAG_SERVER_USERS, s.users),
                    nonzero(EC_TAG_SERVER_USERS_MAX, s.max_users),
                    nonzero(EC_TAG_SERVER_FILES, s.files),
                    nonzero(EC_TAG_SERVER_FILES_SOFT, s.soft_files),
                    nonzero(EC_TAG_SERVER_FILES_HARD, s.hard_files),
                    nonzero(EC_TAG_SERVER_TCP_FLAGS, tcp_flags),
                    nonzero(EC_TAG_SERVER_UDP_FLAGS, s.udp_flags),
                ]
                .into_iter()
                .flatten()
                {
                    add(c);
                }
            }
            if let Some(c) = text(EC_TAG_SERVER_NAME, &s.name) {
                add(c);
            }
        }
        // `EC_DETAIL_INC_UPDATE` "should not get here".
        _ => {}
    }
    t
}

/// `ConnectToAnyServer`.
fn connect_any(ctx: &mut Ctx<'_>, out: &mut Vec<Effect>) {
    ctx.connector.stop();
    out.push(Effect::CancelAttempt);
    if ctx.connector.disconnect() {
        out.push(Effect::Disconnect);
    }
    let next = ctx.connector.start(ctx.now);
    if next == Next::Idle {
        warn!("No valid servers to which to connect found in server list");
    }
    out.push(Effect::Follow(next));
}

/// `ConnectToServer`.
fn connect_to(ctx: &mut Ctx<'_>, addr: SocketAddrV4, out: &mut Vec<Effect>) {
    ctx.connector.stop();
    out.push(Effect::CancelAttempt);
    if ctx.connector.disconnect() {
        out.push(Effect::Disconnect);
    }
    out.push(Effect::Follow(
        ctx.connector.connect_to(SocketAddr::V4(addr)),
    ));
}

/// The server we are logged into.
fn current(ctx: &Ctx<'_>) -> Option<SocketAddrV4> {
    ctx.connector.connected().and_then(|a| v4(a.addr))
}

/// Answer one request, and say what the client must do.
pub fn handle(req: &Packet, ctx: &mut Ctx<'_>) -> (Packet, Vec<Effect>) {
    let mut out = Vec::new();
    // What the server we are on says of itself goes into its entry.
    if let (Some(a), Some(live)) = (current(ctx), ctx.live) {
        if let Some(e) = ctx.list.find_mut(a) {
            if let Some(n) = live.name.as_ref().filter(|n| !n.is_empty()) {
                e.name = n.clone();
            }
            if let Some(d) = live.description.as_ref().filter(|d| !d.is_empty()) {
                e.description = d.clone();
            }
            if let Some(v) = live.version.as_ref().filter(|v| !v.is_empty()) {
                e.version = v.clone();
            }
            if live.users != 0 || live.files != 0 {
                e.users = live.users;
                e.files = live.files;
            }
        }
    }
    let reply = match req.opcode {
        EC_OP_GET_SERVER_LIST => {
            let mut p = Packet::new(EC_OP_SERVER_LIST);
            // Kad only: an empty list.
            if ctx.ed2k {
                let detail = req
                    .tag(EC_TAG_DETAIL_LEVEL)
                    .map_or(EC_DETAIL_FULL, |t| t.as_int() as u8);
                let on = current(ctx);
                for s in ctx.list.entries() {
                    let here = on.is_some_and(|a| s.ip == Some(*a.ip()) && s.port == a.port());
                    let flags = if here {
                        ctx.live.map_or(0, |l| l.tcp_flags)
                    } else {
                        0
                    };
                    let st =
                        s.ip.is_some_and(|ip| ctx.list.is_static(SocketAddrV4::new(ip, s.port)));
                    p = p.with(server_tag(s, st, flags, detail));
                }
            }
            p
        }
        EC_OP_SERVER_ADD => server_add(req, ctx, &mut out),
        EC_OP_SERVER_CONNECT | EC_OP_SERVER_DISCONNECT | EC_OP_SERVER_REMOVE => {
            server_cmd(req, ctx, &mut out)
        }
        EC_OP_KAD_START => {
            if ctx.kad {
                if !ctx.kad_running {
                    out.push(Effect::StartKad);
                }
                Packet::new(EC_OP_NOOP)
            } else {
                failed("Kad is disabled in preferences.")
            }
        }
        EC_OP_SERVER_UPDATE_FROM_URL => server_update(req, ctx, &mut out),
        // The server by its ECID; static, priority or both.
        EC_OP_SERVER_SET_STATIC_PRIO => {
            let ecid = req.tag(EC_TAG_SERVER).map_or(0, Tag::as_int) as u32;
            if let Some(a) = (ctx.ecid)(ecid).filter(|a| ctx.list.find(*a).is_some()) {
                if let Some(t) = req.tag(EC_TAG_SERVER_STATIC) {
                    let on = t.as_int() > 0;
                    ctx.list.set_static(a, on, ctx.config);
                    ctx.connector.set_static(SocketAddr::V4(a), on);
                }
                if let Some(t) = req.tag(EC_TAG_SERVER_PRIO) {
                    ctx.list.set_priority(a, t.as_int() as u32);
                }
            }
            Packet::new(EC_OP_NOOP)
        }
        EC_OP_KAD_BOOTSTRAP_FROM_IP => {
            if ctx.kad {
                let ip = req.tag(EC_TAG_BOOTSTRAP_IP).map_or(0, Tag::as_int) as u32;
                let port = req.tag(EC_TAG_BOOTSTRAP_PORT).map_or(0, Tag::as_int) as u16;
                // Kad's order: the most significant byte first.
                out.push(Effect::BootstrapKad(SocketAddrV4::new(ip.into(), port)));
                Packet::new(EC_OP_NOOP)
            } else {
                failed("Kad is disabled in preferences.")
            }
        }
        EC_OP_KAD_STOP => {
            if ctx.kad_running {
                out.push(Effect::StopKad);
            }
            Packet::new(EC_OP_NOOP)
        }
        EC_OP_CONNECT => {
            let mut r: Option<Packet> = None;
            if ctx.ed2k {
                let p = Packet::new(EC_OP_STRINGS);
                r = Some(if current(ctx).is_some() {
                    p.with(Tag::string(EC_TAG_STRING, "Already connected to eD2k."))
                } else {
                    connect_any(ctx, &mut out);
                    p.with(Tag::string(EC_TAG_STRING, "Connecting to eD2k..."))
                });
            }
            if ctx.kad {
                let p = r.take().unwrap_or_else(|| Packet::new(EC_OP_STRINGS));
                r = Some(if ctx.kad_connected {
                    p.with(Tag::string(EC_TAG_STRING, "Already connected to Kad."))
                } else {
                    if !ctx.kad_running {
                        out.push(Effect::StartKad);
                    }
                    p.with(Tag::string(EC_TAG_STRING, "Connecting to Kad..."))
                });
            }
            r.unwrap_or_else(|| failed("All networks are disabled."))
        }
        EC_OP_DISCONNECT => {
            let ed2k = current(ctx).is_some();
            if ed2k || ctx.kad_connected {
                let mut p = Packet::new(EC_OP_STRINGS);
                if ed2k {
                    ctx.connector.disconnect();
                    out.push(Effect::Disconnect);
                    p = p.with(Tag::string(EC_TAG_STRING, "Disconnected from eD2k."));
                }
                if ctx.kad_connected {
                    out.push(Effect::StopKad);
                    p = p.with(Tag::string(EC_TAG_STRING, "Disconnected from Kad."));
                }
                p
            } else {
                Packet::new(EC_OP_NOOP)
            }
        }
        _ => failed("OOPS! OpCode processing error!"),
    };
    (reply, out)
}

/// `Get_EC_Response_Server_Add` and `CServerList::AddServer`.
fn server_add(req: &Packet, ctx: &mut Ctx<'_>, out: &mut Vec<Effect>) -> Packet {
    let text = |name: u16| req.tag(name).map(Tag::as_str).unwrap_or_default();
    let full = text(EC_TAG_SERVER_ADDRESS);
    let name = text(EC_TAG_SERVER_NAME);
    let (host, port) = match full.find(':') {
        Some(i) => (&full[..i], &full[i + 1..]),
        None => (full.as_str(), full.as_str()),
    };
    // StrToULong: the leading digits, 0 when there are none.
    let digits: String = port.chars().take_while(char::is_ascii_digit).collect();
    let port = digits.parse::<u64>().map_or(0, |p| p as u16);
    let refused = || failed("Server not added");
    if port == 0 {
        warn!("Server not added: [{host}:{port}] does not specify a valid port.");
        return refused();
    }
    // A host name: a dynamic-IP server, looked up once added.
    if is_host_name(host) {
        let list_name = if name.is_empty() { full.clone() } else { name };
        let s = ServerInfo {
            dyn_ip: host.to_owned(),
            port,
            name: list_name.clone(),
            ..Default::default()
        };
        if !ctx.list.push_dyn(s) {
            warn!("Server not added: Server with matching IP:Port [{host}:{port}] found in list.");
            return refused();
        }
        info!("Server added: Server at [{host}:{port}] using the name '{list_name}'.");
        ctx.list.changed = true;
        out.push(Effect::Resolve(host.to_owned(), port));
        return Packet::new(EC_OP_NOOP);
    }
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return refused();
    };
    if !is_good_ip(ip, ctx.filter_lan) || ctx.ip_filter.is_some_and(|f| f.blocks_server(ip)) {
        warn!("Server not added: The IP of [{host}:{port}] is filtered or invalid.");
        return refused();
    }
    let addr = SocketAddrV4::new(ip, port);
    if ctx.list.find(addr).is_some() {
        warn!("Server not added: Server with matching IP:Port [{host}:{port}] found in list.");
        if let Some(e) = ctx.list.find_mut(addr) {
            e.failed = 0;
        }
        return refused();
    }
    let list_name = if name.is_empty() { full.clone() } else { name };
    info!("Server added: Server at [{host}:{port}] using the name '{list_name}'.");
    ctx.list.entries.push(ServerInfo {
        ip: Some(ip),
        port,
        name: list_name,
        ..Default::default()
    });
    ctx.list.changed = true;
    ctx.connector.add(SocketAddr::V4(addr));
    Packet::new(EC_OP_NOOP)
}

/// `EC_OP_SERVER_UPDATE_FROM_URL`: one URL, or none for `addresses.dat`'s.
/// The download runs on; a refusal says why, and whether a download is
/// already under way.
fn server_update(req: &Packet, ctx: &mut Ctx<'_>, out: &mut Vec<Effect>) -> Packet {
    if req.tags.len() > 1
        || req
            .tags
            .first()
            .is_some_and(|t| t.ty != remule_ec::codes::EC_TAGTYPE_STRING)
    {
        return failed("Invalid URL");
    }
    let url = req.tags.first().map(Tag::as_str).unwrap_or_default();
    let refuse = |reason: &str| {
        info!("{reason}");
        let p = failed(reason);
        if ctx.server_met_busy {
            p.with(Tag::int(EC_TAG_SERVER_UPDATE_BUSY, 1))
        } else {
            p
        }
    };
    if ctx.server_met_busy {
        return refuse("A server list download is already in progress.");
    }
    let sources = if url.is_empty() {
        list_sources(ctx.config)
    } else if valid_list_url(&url) {
        vec![url]
    } else {
        return refuse("Invalid URL");
    };
    if sources.is_empty() {
        return refuse("No server list sources configured");
    }
    out.push(Effect::UpdateServerMet(sources));
    Packet::new(EC_OP_NOOP)
}

/// `Get_EC_Response_Server`.
fn server_cmd(req: &Packet, ctx: &mut Ctx<'_>, out: &mut Vec<Effect>) -> Packet {
    let mut srv: Option<SocketAddrV4> = None;
    if let Some(t) = req.tag(EC_TAG_SERVER) {
        let (ip, port) = t.as_ipv4().unwrap_or(([0; 4], 0));
        let a = SocketAddrV4::new(ip.into(), port);
        if ctx.list.find(a).is_none() {
            return failed(&format!("server not found: [{a}]"));
        }
        srv = Some(a);
    }
    match req.opcode {
        EC_OP_SERVER_DISCONNECT => {
            if ctx.connector.disconnect() {
                out.push(Effect::Disconnect);
            }
            Packet::new(EC_OP_NOOP)
        }
        EC_OP_SERVER_REMOVE => match srv {
            // RemoveServer refuses the server we are logged into.
            Some(a) if current(ctx) == Some(a) => failed(
                "You are connected to the server you are trying to delete. please disconnect first.",
            ),
            Some(a) => {
                ctx.list.remove_by_user(a, ctx.config);
                ctx.connector.remove(SocketAddr::V4(a));
                Packet::new(EC_OP_NOOP)
            }
            None => failed("need to define server to be removed"),
        },
        _ => {
            if !ctx.ed2k {
                return failed("eD2k is disabled in preferences.");
            }
            match srv {
                Some(a) => connect_to(ctx, a, out),
                None => connect_any(ctx, out),
            }
            Packet::new(EC_OP_NOOP)
        }
    }
}
