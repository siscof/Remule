// SPDX-License-Identifier: GPL-2.0-or-later
//! External connections (`ExternalConn.cpp`): what `amulecmd` and
//! `amulegui` log into.
//!
//! A listener on `ECAddress:ECPort`; per connection, the login of
//! [`remule_ec::server`] and then requests, answered from a [`Status`] the
//! client refreshes every second. Served so far: `EC_OP_STAT_REQ`,
//! `EC_OP_GET_CONNSTATE`, `EC_OP_GET_DLOAD_QUEUE`, `EC_OP_ADD_LINK`, the
//! partfile pause, resume, stop and delete commands, the search requests
//! ([`crate::ec_search`]), and `EC_OP_SHUTDOWN`; anything else is answered `EC_OP_FAILED`, as aMule
//! answers an opcode it does not know.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ed2k_types::{Md4Hash, UInt128};
use remule_core::downloader::FileOp;
use remule_ec::codes::*;
use remule_ec::server::{AuthLimiter, Credentials, Identity, Limits, Received, ServerConn};
use remule_ec::{Packet, Tag};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};

/// How external connections are accepted (`[ExternalConnect]`).
#[derive(Clone, Debug)]
pub struct EcSettings {
    pub addr: SocketAddrV4,
    pub credentials: Credentials,
    pub limits: Limits,
    /// `ConnectToED2K` and `ConnectToKad`, which the server and network
    /// requests check.
    pub ed2k: bool,
    pub kad: bool,
    /// The preferences ([`crate::prefs`]).
    pub prefs: crate::prefs::PrefStore,
}

/// The connected server, as the EC server tag tells it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerStatus {
    /// Its ECID, as the incremental updates name it.
    pub ecid: u32,
    pub addr: Option<SocketAddrV4>,
    pub name: String,
    pub description: String,
    pub version: String,
    pub users: u32,
    pub files: u32,
    pub tcp_flags: u32,
}

/// Kad, as the connection state and statistics tell it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KadStatus {
    pub connected: bool,
    /// The TCP firewall check's answer.
    pub firewalled: bool,
    pub id: UInt128,
    /// Our IP as nodes tell it (unspecified if unknown).
    pub public_ip: Ipv4Addr,
    /// Estimated users on the network.
    pub users: u32,
    /// Contacts in the routing table.
    pub nodes: u32,
    /// Unix time it connected.
    pub since: Option<u32>,
}

impl Default for KadStatus {
    fn default() -> Self {
        KadStatus {
            connected: false,
            firewalled: false,
            id: UInt128::ZERO,
            public_ip: Ipv4Addr::UNSPECIFIED,
            users: 0,
            nodes: 0,
            since: None,
        }
    }
}

/// What the client is doing, as the EC replies need it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub ed2k_enabled: bool,
    pub kad_enabled: bool,
    pub server: Option<ServerStatus>,
    pub connecting: bool,
    /// Our ID from the server's login, 0 when not logged in.
    pub ed2k_id: u32,
    /// Unix time of the login.
    pub ed2k_since: Option<u32>,
    pub kad: Option<KadStatus>,
    /// Bytes per second over the last second.
    pub ul_speed: u64,
    pub dl_speed: u64,
    /// Bytes per second, 0 for no limit.
    pub ul_limit: u32,
    pub dl_limit: u32,
    pub session_sent: u64,
    pub session_received: u64,
    pub total_sent: u64,
    pub total_received: u64,
    pub uptime: u64,
    pub shared_files: u32,
    pub connections: u32,
    pub sources: u32,
    pub upload_queue: u32,
    pub banned: u32,
    /// The download queue, in the client's order.
    pub downloads: Vec<Download>,
    /// How many changes to the downloads the client had applied when it
    /// took this view ([`DownloadChanges`]).
    pub applied: u64,
}

/// Changes to the downloads the client has applied, counted as it applies
/// them; each view carries the count it was taken at. A connection that
/// made a change answers once a view at least that recent is out, so what
/// its client asks next sees the change (a view published between its
/// request and the change does not count).
pub type DownloadChanges = std::sync::atomic::AtomicU64;

/// `PS_*`, as EC reports a download's state.
pub mod ps {
    pub const READY: u8 = 0;
    pub const EMPTY: u8 = 1;
    pub const ERROR: u8 = 4;
    pub const PAUSED: u8 = 7;
    pub const COMPLETING: u8 = 8;
    pub const COMPLETE: u8 = 9;
}

/// One download, as `CEC_PartFile_Tag` tells it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Download {
    /// Its ID for this daemon process.
    pub ecid: u32,
    pub hash: Md4Hash,
    pub name: String,
    pub size: u64,
    pub completed: u64,
    pub transferred: u64,
    pub sources: u32,
    /// Sources sending data.
    pub transferring: u32,
    /// `GetStatus()`: [`ps`].
    pub status: u8,
    pub stopped: bool,
    /// Bytes per second over the last second.
    pub speed: u64,
    /// `NNN.part.met`'s number.
    pub part_met_id: u16,
    /// The temp directory.
    pub dir: String,
    /// `EC_TAG_PARTFILE_PRIO`: `PR_*`, plus 10 when automatic.
    pub priority: u8,
    /// `EC_TAG_KNOWNFILE_PRIO`, the same way.
    pub up_priority: u8,
    pub category: u32,
    pub last_seen_complete: u32,
    pub lost_to_corruption: u64,
    /// The missing ranges, inclusive (the gap bar).
    pub gaps: Vec<(u64, u64)>,
    /// The blocks being downloaded, inclusive.
    pub requested: Vec<(u64, u64)>,
    /// How many sources have each part.
    pub part_frequency: Vec<u16>,
}

/// ECIDs for the downloads, and their speeds.
#[derive(Debug, Default)]
pub struct DownloadIds {
    ids: std::collections::HashMap<Md4Hash, u32>,
    last: std::collections::HashMap<Md4Hash, u64>,
}

impl DownloadIds {
    /// The downloads as EC tells them; called once a second, so the
    /// difference in bytes transferred is the speed.
    pub fn view(
        &mut self,
        files: &[remule_core::download_queue::FileProgress],
        temp: &std::path::Path,
    ) -> Vec<Download> {
        use remule_core::part_file::Status as S;
        let mut last = std::collections::HashMap::new();
        let out = files
            .iter()
            .map(|f| {
                let ecid = *self
                    .ids
                    .entry(f.hash)
                    .or_insert_with(crate::ec_shared::next_ecid);
                let speed = f
                    .transferred
                    .saturating_sub(*self.last.get(&f.hash).unwrap_or(&f.transferred));
                last.insert(f.hash, f.transferred);
                let status = match f.status {
                    _ if f.done => ps::COMPLETE,
                    S::Error => ps::ERROR,
                    S::Completing => ps::COMPLETING,
                    S::Complete => ps::COMPLETE,
                    _ if f.paused => ps::PAUSED,
                    S::Ready => ps::READY,
                    S::Empty => ps::EMPTY,
                };
                let prio = |p: u32, auto: bool| (p as u8).saturating_add(if auto { 10 } else { 0 });
                Download {
                    ecid,
                    hash: f.hash,
                    name: f.name.clone(),
                    size: f.size,
                    completed: f.completed,
                    transferred: f.transferred,
                    sources: f.sources as u32,
                    transferring: f.downloading as u32,
                    status,
                    stopped: f.stopped,
                    speed,
                    part_met_id: f
                        .part_met_name
                        .strip_suffix(".part")
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0),
                    dir: temp.display().to_string(),
                    priority: prio(f.priority, f.auto_priority),
                    up_priority: prio(f.up_priority, f.auto_up_priority),
                    category: f.category,
                    last_seen_complete: f.last_seen_complete,
                    lost_to_corruption: f.lost_to_corruption,
                    gaps: f.gaps.clone(),
                    requested: f.requested.clone(),
                    part_frequency: f.part_frequency.clone(),
                }
            })
            .collect();
        self.ids.retain(|h, _| last.contains_key(h));
        self.last = last;
        out
    }
}

impl Status {
    /// `CamuleApp::GetID`: Kad is trusted above eD2k.
    pub fn client_id(&self) -> u32 {
        match &self.kad {
            Some(k) if k.connected && !k.firewalled => u32::from_le_bytes(k.public_ip.octets()),
            _ if self.server.is_some() => self.ed2k_id,
            Some(k) if k.connected => 1,
            _ => 0,
        }
    }
}

/// What a request asks of the client.
#[derive(Debug)]
pub enum Control {
    Shutdown,
    /// `CDownloadQueue::AddLink`, one link: true when it was taken.
    AddLink {
        link: String,
        category: u32,
        reply: oneshot::Sender<bool>,
    },
    /// Shared files ([`crate::ec_shared`]).
    Shared(crate::ec_shared::SharedRequest),
    /// One partfile command on one download.
    File {
        file: Md4Hash,
        op: FileOp,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// A search request, answered by the client, which holds the search
    /// ([`crate::ec_search`]).
    Search {
        req: Packet,
        ctx: crate::ec_search::Ctx,
        /// The reply, and the ID of a search it started.
        reply: oneshot::Sender<(Packet, Option<u32>)>,
    },
    /// A server or network request ([`crate::ec_servers`]), answered by
    /// the client loop.
    Servers {
        request: Packet,
        reply: oneshot::Sender<Packet>,
    },
    /// The shared files and servers for an incremental update
    /// ([`crate::ec_update`]).
    Update(oneshot::Sender<crate::ec_update::UpdateData>),
    /// The statistics tree's data ([`crate::ec_stats`]).
    StatsTree(oneshot::Sender<crate::ec_stats::TreeData>),
    /// `EC_OP_FRIEND`, answered by the client loop, which keeps the
    /// friends ([`crate::friends`]).
    Friend {
        req: Packet,
        reply: oneshot::Sender<Packet>,
    },
    /// The credit history (`EC_OP_GET_CLIENT_HISTORY`).
    ClientHistory(oneshot::Sender<Vec<remule_core::credits::HistoryEntry>>),
    /// `ResetCatParts`: a category was deleted; answered once applied.
    CategoryRemoved(u32, oneshot::Sender<()>),
    /// `NotifyAlways_IPFilter_Reload`: the IP filter read again.
    IpFilterReload,
    /// `CIPFilter::Update`: `ipfilter.dat` fetched from this URL, then
    /// the filter read again.
    IpFilterUpdate(String),
}

fn detail(req: &Packet) -> u8 {
    req.tag(EC_TAG_DETAIL_LEVEL)
        .map_or(EC_DETAIL_FULL, |t| t.as_int() as u8)
}

/// `CEC_Server_Tag(server, detail_level)`.
fn server_tag(s: &ServerStatus, detail: u8) -> Tag {
    let (ip, port) = s.addr.map_or(([0; 4], 0), |a| (a.ip().octets(), a.port()));
    let mut t = Tag::ipv4(EC_TAG_SERVER, ip, port);
    let mut add = |c: Tag| t.children.push(c);
    if detail == EC_DETAIL_WEB || detail == EC_DETAIL_FULL {
        // Ping, priority, failures and the static flag are not kept yet:
        // their defaults are what aMule leaves out.
        if !s.version.is_empty() {
            add(Tag::string(EC_TAG_SERVER_VERSION, &s.version));
        }
        if !s.description.is_empty() {
            add(Tag::string(EC_TAG_SERVER_DESC, &s.description));
        }
        if s.users != 0 {
            add(Tag::int(EC_TAG_SERVER_USERS, s.users.into()));
        }
        if s.files != 0 {
            add(Tag::int(EC_TAG_SERVER_FILES, s.files.into()));
        }
        if s.tcp_flags != 0 {
            add(Tag::int(EC_TAG_SERVER_TCP_FLAGS, s.tcp_flags.into()));
        }
    }
    if detail != EC_DETAIL_UPDATE && !s.name.is_empty() {
        add(Tag::string(EC_TAG_SERVER_NAME, &s.name));
    }
    t
}

/// `CEC_ConnState_Tag`.
pub fn connstate_tag(s: &Status, detail: u8) -> Tag {
    let kad = s.kad.as_ref();
    let bits = u64::from(s.server.is_some())
        | if s.connecting { 0x02 } else { 0 }
        | if kad.is_some_and(|k| k.connected) {
            0x04
        } else {
            0
        }
        | if kad.is_some_and(|k| k.firewalled) {
            0x08
        } else {
            0
        }
        | if kad.is_some() { 0x10 } else { 0 };
    let mut t = Tag::int(EC_TAG_CONNSTATE, bits).with(Tag::int(
        EC_TAG_NETWORKS_ENABLED,
        u64::from(s.ed2k_enabled) | if s.kad_enabled { 0x02 } else { 0 },
    ));
    if let Some(server) = &s.server {
        if detail == EC_DETAIL_INC_UPDATE {
            // Just the connected server's ECID.
            t = t.with(Tag::int(EC_TAG_SERVER, server.ecid.into()));
        } else {
            t = t.with(server_tag(server, detail));
        }
        t = t.with(Tag::int(EC_TAG_ED2K_ID, s.ed2k_id.into()));
        if let Some(since) = s.ed2k_since {
            t = t.with(Tag::int(EC_TAG_ED2K_CONNECTED_SINCE, since.into()));
        }
    } else if s.connecting {
        t = t.with(Tag::int(EC_TAG_ED2K_ID, 0xFFFF_FFFF));
    }
    t = t.with(Tag::int(EC_TAG_CLIENT_ID, s.client_id().into()));
    if let Some(k) = kad {
        t = t.with(Tag {
            name: EC_TAG_KAD_ID,
            ty: EC_TAGTYPE_UINT128,
            data: k.id.to_be_bytes().to_vec(),
            children: Vec::new(),
        });
        if let (true, Some(since)) = (k.connected, k.since) {
            t = t.with(Tag::int(EC_TAG_KAD_CONNECTED_SINCE, since.into()));
        }
    }
    t
}

/// `Get_EC_Response_StatRequest`, with the connection state.
pub fn stats_reply(s: &Status, detail: u8) -> Packet {
    let mut p = Packet::new(EC_OP_STATS);
    let int = |name: u16, v: u64| Tag::int(name, v);
    if detail == EC_DETAIL_FULL || detail == EC_DETAIL_INC_UPDATE {
        // Overhead is not measured yet: 0, as an idle aMule says.
        p = p
            .with(int(EC_TAG_STATS_UP_OVERHEAD, 0))
            .with(int(EC_TAG_STATS_DOWN_OVERHEAD, 0))
            .with(int(EC_TAG_STATS_BANNED_COUNT, s.banned.into()))
            .with(int(EC_TAG_STATS_SESSION_SENT_BYTES, s.session_sent))
            .with(int(EC_TAG_STATS_SESSION_RECEIVED_BYTES, s.session_received))
            .with(int(EC_TAG_STATS_ACTIVE_CONNECTIONS, s.connections.into()))
            .with(int(EC_TAG_STATS_UPTIME_SECONDS, s.uptime))
            .with(int(EC_TAG_STATS_TOTAL_SENT_BYTES, s.total_sent))
            .with(int(EC_TAG_STATS_TOTAL_RECEIVED_BYTES, s.total_received))
            .with(int(EC_TAG_STATS_SHARED_FILE_COUNT, s.shared_files.into()));
        // The version check's outcome, once one has finished.
        if let Some(v) = crate::version_check::global().result() {
            p = p
                .with(Tag::string(EC_TAG_GENERAL_VERSION_CHECK_LATEST, &v.latest))
                .with(int(EC_TAG_GENERAL_VERSION_CHECK_TIMESTAMP, v.at));
            if v.outdated {
                p = p.with(Tag::empty(EC_TAG_GENERAL_VERSION_CHECK_OUTDATED));
            }
        }
    }
    if detail != EC_DETAIL_UPDATE {
        let (ed2k_users, ed2k_files) = s.server.as_ref().map_or((0, 0), |sv| (sv.users, sv.files));
        let kad = s.kad.as_ref();
        p = p
            .with(int(EC_TAG_STATS_UL_SPEED, s.ul_speed))
            .with(int(EC_TAG_STATS_DL_SPEED, s.dl_speed))
            .with(int(EC_TAG_STATS_UL_SPEED_LIMIT, s.ul_limit.into()))
            .with(int(EC_TAG_STATS_DL_SPEED_LIMIT, s.dl_limit.into()))
            .with(int(EC_TAG_STATS_UL_QUEUE_LEN, s.upload_queue.into()))
            .with(int(EC_TAG_STATS_TOTAL_SRC_COUNT, s.sources.into()))
            .with(int(EC_TAG_STATS_ED2K_USERS, ed2k_users.into()))
            .with(int(
                EC_TAG_STATS_KAD_USERS,
                kad.map_or(0, |k| k.users).into(),
            ))
            .with(int(EC_TAG_STATS_ED2K_FILES, ed2k_files.into()))
            .with(int(EC_TAG_STATS_KAD_FILES, 0))
            .with(int(
                EC_TAG_STATS_KAD_NODES,
                kad.map_or(0, |k| k.nodes).into(),
            ));
        if let Some(k) = kad.filter(|k| k.connected) {
            // UDP firewalled is not tested yet; the buddy is not kept.
            p = p
                .with(int(EC_TAG_STATS_KAD_FIREWALLED_UDP, 0))
                .with(int(
                    EC_TAG_STATS_KAD_IP_ADDRESS,
                    u32::from_le_bytes(k.public_ip.octets()).into(),
                ))
                .with(int(EC_TAG_STATS_KAD_IN_LAN_MODE, 0))
                .with(int(EC_TAG_STATS_BUDDY_STATUS, 0))
                .with(int(EC_TAG_STATS_BUDDY_IP, 0))
                .with(int(EC_TAG_STATS_BUDDY_PORT, 0))
                .with(int(EC_TAG_STATS_BUDDY_SERVED, 0))
                .with(int(EC_TAG_STATS_BUDDY_SERVED_LIMIT, 0));
        }
    }
    p.with(connstate_tag(s, detail))
}

/// `MakeKadBuddyTag`: the buddy counters, serving and own, in aMule's order.
pub fn kad_buddy_tag() -> Tag {
    let mut t = Tag::empty(EC_TAG_KAD_BUDDY);
    t.children = [
        EC_TAG_KAD_BUDDY_PENDING,
        EC_TAG_KAD_BUDDY_SERVING_REQUESTS,
        EC_TAG_KAD_BUDDY_SERVING_OFFERED,
        EC_TAG_KAD_BUDDY_SERVING_REFUSED_FIREWALLED,
        EC_TAG_KAD_BUDDY_SERVING_REFUSED_FULL,
        EC_TAG_KAD_BUDDY_SERVING_REFUSED_CONFLICT,
        EC_TAG_KAD_BUDDY_SERVING_RATE_LIMITED,
        EC_TAG_KAD_BUDDY_SERVING_OFFERS_EXPIRED,
        EC_TAG_KAD_BUDDY_SERVING_OFFERS_SUPERSEDED,
        EC_TAG_KAD_BUDDY_SERVING_OFFERS_DUPLICATE,
        EC_TAG_KAD_BUDDY_SERVING_STARTED,
        EC_TAG_KAD_BUDDY_SERVING_RELEASED_EXTRA,
        EC_TAG_KAD_BUDDY_SERVING_ENDED,
        EC_TAG_KAD_BUDDY_SERVING_TIMED_OUT,
        EC_TAG_KAD_BUDDY_SERVING_SECONDS,
        EC_TAG_KAD_BUDDY_SERVING_CALLBACKS,
        EC_TAG_KAD_BUDDY_SERVING_CALLBACK_BYTES,
        EC_TAG_KAD_BUDDY_SERVING_CALLBACKS_NO_BUDDY,
        EC_TAG_KAD_BUDDY_SERVING_CALLBACKS_MISMATCHED,
        EC_TAG_KAD_BUDDY_SERVING_CALLBACKS_RATE_LIMITED,
        EC_TAG_KAD_BUDDY_SERVING_REASKS,
        EC_TAG_KAD_BUDDY_SERVING_REASK_BYTES,
        EC_TAG_KAD_BUDDY_SERVING_REASKS_NO_BUDDY,
        EC_TAG_KAD_BUDDY_SERVING_REASKS_MISMATCHED,
        EC_TAG_KAD_BUDDY_SERVING_REASKS_MALFORMED,
        EC_TAG_KAD_BUDDY_SERVING_RELAY_BYTES_PEAK,
        EC_TAG_KAD_BUDDY_SERVING_CALLBACK_REQUESTS_PEAK,
        EC_TAG_KAD_BUDDY_OWN_SEARCHES,
        EC_TAG_KAD_BUDDY_OWN_REQUESTS,
        EC_TAG_KAD_BUDDY_OWN_REQUESTS_SKIPPED,
        EC_TAG_KAD_BUDDY_OWN_OFFERS,
        EC_TAG_KAD_BUDDY_OWN_CONNECT_ATTEMPTS,
        EC_TAG_KAD_BUDDY_OWN_CONNECT_FAILURES,
        EC_TAG_KAD_BUDDY_OWN_CONNECTED,
        EC_TAG_KAD_BUDDY_OWN_ENDED,
        EC_TAG_KAD_BUDDY_OWN_TIMED_OUT,
        EC_TAG_KAD_BUDDY_OWN_SECONDS,
        EC_TAG_KAD_BUDDY_OWN_CALLBACKS,
        EC_TAG_KAD_BUDDY_OWN_REASKS,
        EC_TAG_KAD_BUDDY_OWN_NEEDED_SECONDS,
        EC_TAG_KAD_BUDDY_OWN_MISSING_SECONDS,
    ]
    .into_iter()
    .map(|n| Tag::int(n, 0))
    .collect();
    t
}

/// `FormatPackedClientVersion`: `major * 100000 + minor * 1000 + update *
/// 100`, written as each client family writes its version.
pub fn format_client_version(soft: u8, packed: u32) -> String {
    let (major, minor, update) = (
        packed / 100_000,
        (packed % 100_000) / 1000,
        (packed % 1000) / 100,
    );
    let letter = |n: u32| char::from_u32(u32::from(b'a') + n).unwrap_or('?');
    match soft {
        // aMule, lxMule, Hydranode and the MLDonkeys: three numbers.
        3 | 2 | 6 | 0x34 | 0x98 | 0x0a => format!("v{major}.{minor}.{update}"),
        // eDonkeyHybrid drops a zero update.
        0x32 if update == 0 => format!("v{major}.{minor}"),
        0x32 => format!("v{major}.{minor}.{update}"),
        // lphant: the major one lower, the minor two digits, the update a letter.
        0x14 => format!(" v{}.{minor:02}{}", major.saturating_sub(1), letter(update)),
        // eMule Plus: trailing zeros left out, 'a' meaning 1.
        5 => {
            let mut out = format!("v{major}");
            if minor != 0 {
                out += &format!(".{minor}");
            }
            if update != 0 {
                out.push(letter(update - 1));
            }
            out
        }
        // eMule and its kind: the update a letter, 'a' meaning 0.
        _ => format!("v{major}.{minor}{}", letter(update)),
    }
}

/// `Get_EC_Response_ClientHistory`: one tag per peer with credits, its
/// totals, ratio and last-seen date, and what the metadata block remembers
/// of it when it has any.
pub fn client_history_reply(entries: &[remule_core::credits::HistoryEntry]) -> Packet {
    let mut p = Packet::new(EC_OP_CLIENT_HISTORY);
    for (r, meta) in entries {
        let mut t = Tag::hash(EC_TAG_CLIENT, r.key.0)
            .with(Tag::int(EC_TAG_CLIENT_UPLOAD_TOTAL, r.uploaded))
            .with(Tag::int(EC_TAG_CLIENT_DOWNLOAD_TOTAL, r.downloaded))
            .with(Tag::double(
                EC_TAG_CLIENT_SCORE_RATIO,
                r.credit_ratio().into(),
            ))
            .with(Tag::int(EC_TAG_CLIENT_LAST_SEEN, r.last_seen.into()));
        if let Some(m) = meta {
            t = t
                .with(Tag::int(EC_TAG_CLIENT_FIRST_SEEN, m.first_seen.into()))
                .with(Tag::int(EC_TAG_CLIENT_SESSIONS, m.sessions.into()));
            if !m.name.is_empty() {
                t = t.with(Tag::string(EC_TAG_CLIENT_NAME, &m.name));
            }
            t = t
                .with(Tag::int(EC_TAG_CLIENT_USER_IP, m.last_ip.into()))
                .with(Tag::int(EC_TAG_CLIENT_USER_PORT, m.last_port.into()))
                .with(Tag::int(EC_TAG_CLIENT_KAD_PORT, m.kad_port.into()))
                .with(Tag::int(EC_TAG_CLIENT_SOFTWARE, m.client_soft.into()));
            if !m.mod_version.is_empty() {
                t = t.with(Tag::string(EC_TAG_CLIENT_MOD_VERSION, &m.mod_version));
            }
            t = t
                .with(Tag::string(
                    EC_TAG_CLIENT_SOFT_VER_STR,
                    &format_client_version(m.client_soft, m.version),
                ))
                .with(Tag::int(EC_TAG_CLIENT_FROM, m.source_from.into()))
                .with(Tag::int(
                    EC_TAG_CLIENT_OBFUSCATION_STATUS,
                    m.obfuscation.into(),
                ));
        }
        p = p.with(t);
    }
    p
}

/// A category command's answer: a kept folder with its category and
/// path (which clients read as applied), a refusal with its category or
/// the folder refused (reason 3, outside the allowed roots).
fn category_reply(r: crate::prefs::CategoryResult) -> Packet {
    use crate::prefs::CategoryResult;
    match r {
        CategoryResult::Done => Packet::new(EC_OP_NOOP),
        CategoryResult::PathKept { index, path } => Packet::new(EC_OP_FAILED)
            .with(Tag::int(EC_TAG_CATEGORY, index.into()))
            .with(Tag::string(EC_TAG_CATEGORY_PATH, &path)),
        CategoryResult::Refused {
            index,
            folder,
            message,
        } => {
            let mut p = Packet::new(EC_OP_FAILED);
            if let Some(dir) = folder {
                p = p.with(Tag::string(EC_TAG_SHAREDDIR_REJECTED, &dir).with(Tag::int(
                    EC_TAG_SHAREDDIR_ERROR,
                    crate::prefs::SHAREDDIR_ERR_OUTSIDE_ROOTS,
                )));
            }
            if let Some(i) = index {
                p = p.with(Tag::int(EC_TAG_CATEGORY, i.into()));
            }
            p.with(Tag::string(EC_TAG_STRING, message))
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn failed(message: &str) -> Packet {
    Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, message))
}

/// `CEC_PartFile_Tag(file, detail_level)`, and its `CEC_SharedFile_Tag`
/// base. Upload statistics, comments and media data are not kept yet:
/// their zeros and blanks are sent, as for a file nobody asked for.
pub fn partfile_tag(d: &Download, detail: u8) -> Tag {
    let int = |name: u16, v: u64| Tag::int(name, v);
    let base = crate::ec_shared::SharedBase {
        ecid: d.ecid,
        hash: d.hash,
        name: d.name.clone(),
        size: d.size,
        file_name: format!("{:03}.part", d.part_met_id),
        dir: d.dir.clone(),
        up_priority: d.up_priority,
        ..Default::default()
    };
    let mut t = crate::ec_shared::shared_tag(EC_TAG_PARTFILE, &base, detail);
    let mut add = |c: Tag| t.children.push(c);
    // CEC_PartFile_Tag.
    add(int(EC_TAG_PARTFILE_STATUS, d.status.into()));
    add(int(EC_TAG_PARTFILE_STOPPED, d.stopped.into()));
    add(int(EC_TAG_PARTFILE_SOURCE_COUNT, d.sources.into()));
    add(int(EC_TAG_PARTFILE_SOURCE_COUNT_NOT_CURRENT, 0));
    add(int(
        EC_TAG_PARTFILE_SOURCE_COUNT_XFER,
        d.transferring.into(),
    ));
    add(int(EC_TAG_PARTFILE_SOURCE_COUNT_A4AF, 0));
    if d.transferring > 0 || detail != EC_DETAIL_UPDATE {
        add(int(EC_TAG_PARTFILE_SIZE_XFER, d.transferred));
        add(int(EC_TAG_PARTFILE_SIZE_DONE, d.completed));
        add(int(EC_TAG_PARTFILE_SPEED, d.speed));
    }
    add(int(EC_TAG_PARTFILE_PRIO, d.priority.into()));
    add(int(EC_TAG_PARTFILE_CAT, d.category.into()));
    add(int(
        EC_TAG_PARTFILE_LAST_SEEN_COMP,
        d.last_seen_complete.into(),
    ));
    add(int(EC_TAG_PARTFILE_LOST_CORRUPTION, d.lost_to_corruption));
    add(int(EC_TAG_PARTFILE_GAINED_COMPRESSION, 0));
    add(int(EC_TAG_PARTFILE_SAVED_ICH, 0));
    add(int(EC_TAG_PARTFILE_A4AFAUTO, 0));
    if detail != EC_DETAIL_UPDATE {
        add(int(EC_TAG_PARTFILE_PARTMETID, d.part_met_id.into()));
        add(Tag::empty(EC_TAG_PARTFILE_A4AF_SOURCES));
    }
    t
}

/// `CreateED2kLink(file, false)`: `ed2k://|file|NAME|SIZE|HASH|/`.
pub fn ed2k_link(d: &Download) -> String {
    crate::ec_shared::ed2k_link(&d.name, d.size, &d.hash)
}

/// `Get_EC_Response_GetDownloadQueue`: every download, or those asked for
/// by ECID.
pub fn download_queue_reply(req: &Packet, s: &Status) -> Packet {
    let detail = detail(req);
    let asked: Vec<u64> = req.tags_named(EC_TAG_PARTFILE).map(Tag::as_int).collect();
    let mut p = Packet::new(EC_OP_DLOAD_QUEUE);
    for d in &s.downloads {
        if asked.is_empty() || asked.contains(&u64::from(d.ecid)) {
            p = p.with(partfile_tag(d, detail));
        }
    }
    p
}

/// `EC_OP_ADD_LINK`: each tag a link; one reply for all of them.
async fn add_links(req: &Packet, control: &mpsc::UnboundedSender<Control>) -> Packet {
    let (mut ok, mut failed_count) = (0, 0);
    for t in &req.tags {
        let link = t.as_str();
        let category = t
            .child(EC_TAG_PARTFILE_CAT)
            .map_or(0, |c| c.as_int() as u32);
        info!("ExternalConn: adding link '{link}'.");
        let (reply, rx) = oneshot::channel();
        let taken = control
            .send(Control::AddLink {
                link,
                category,
                reply,
            })
            .is_ok()
            && rx.await.unwrap_or(false);
        if taken {
            ok += 1;
        } else {
            failed_count += 1;
        }
    }
    if failed_count == 0 {
        Packet::new(EC_OP_NOOP)
    } else if ok == 0 {
        failed("Invalid link or already on list.")
    } else {
        failed(&format!(
            "{failed_count} of {} links failed (invalid or already on list).",
            failed_count + ok
        ))
    }
}

/// `Get_EC_Response_PartFile_Cmd`: the command on each download named, in
/// order, stopping at the first that is not one.
async fn partfile_cmd(
    req: &Packet,
    s: &Status,
    categories: u32,
    control: &mpsc::UnboundedSender<Control>,
) -> Packet {
    let mut response: Option<Packet> = None;
    for t in &req.tags {
        // The priority or category is the target's first child.
        let first = || t.children.first().map_or(0, Tag::as_int);
        let op = match req.opcode {
            EC_OP_PARTFILE_PAUSE => FileOp::Pause,
            EC_OP_PARTFILE_RESUME => FileOp::Resume,
            EC_OP_PARTFILE_STOP => FileOp::Stop,
            EC_OP_PARTFILE_PRIO_SET => match first() as u32 {
                // PR_AUTO: automatic, starting high.
                5 => FileOp::Priority {
                    prio: 2,
                    auto: true,
                },
                p => FileOp::Priority {
                    prio: p,
                    auto: false,
                },
            },
            EC_OP_PARTFILE_SET_CAT => FileOp::Category(first() as u32),
            _ => FileOp::Delete,
        };
        if t.name != EC_TAG_PARTFILE || t.ty != EC_TAGTYPE_HASH16 {
            return failed("Invalid partfile command target.");
        }
        let Some(hash) = t.as_hash().map(Md4Hash) else {
            return failed("Invalid partfile command target.");
        };
        let Some(d) = s.downloads.iter().find(|d| d.hash == hash) else {
            info!("Remote PartFile command failed: FileHash not found: {hash}");
            return failed(&format!("FileHash not found: {hash}"));
        };
        // An older client addresses files by hash only; a GUI adds the ECID
        // it saw, so a replacement is not acted on.
        if let Some(id) = t.child(EC_TAG_ECID) {
            if !id.is_int() || id.as_int() != u64::from(d.ecid) {
                return failed("The selected download has changed. Refresh and try again.");
            }
        }
        if let FileOp::Category(c) = op {
            if c >= categories {
                response.get_or_insert_with(|| failed(&format!("No such category: {c}")));
                continue;
            }
        }
        if op == FileOp::Delete {
            // Finished (or finishing) downloads are skipped, the rest
            // cancelled.
            if matches!(d.status, ps::COMPLETING | ps::COMPLETE) {
                response.get_or_insert_with(|| {
                    failed(&format!(
                        "Cannot cancel a hashing or finished download: {}",
                        d.name
                    ))
                });
                continue;
            }
            let name_differs = t
                .child(EC_TAG_PARTFILE_NAME)
                .is_some_and(|n| n.ty != EC_TAGTYPE_STRING || n.as_str() != d.name);
            let dir_differs = t
                .child(EC_TAG_KNOWNFILE_PATH)
                .is_some_and(|n| n.ty != EC_TAGTYPE_STRING || n.as_str() != d.dir);
            if name_differs || dir_differs {
                return failed(
                    "The selected download has changed or is completing. Refresh and try again.",
                );
            }
        }
        let (reply, rx) = oneshot::channel();
        if control
            .send(Control::File {
                file: hash,
                op,
                reply,
            })
            .is_err()
        {
            return failed("Already shutting down.");
        }
        if let Ok(Err(e)) = rx.await {
            return failed(&e);
        }
    }
    response.unwrap_or_else(|| Packet::new(EC_OP_NOOP))
}

/// What came of a request: the reply, and whether it shut the daemon down.
pub async fn answer(
    req: &Packet,
    s: &Status,
    shutting_down: bool,
    control: &mpsc::UnboundedSender<Control>,
    conn: &mut ConnView<'_>,
) -> (Packet, bool) {
    match req.opcode {
        // Only incremental: aMule has no other answer for it.
        EC_OP_GET_UPDATE if detail(req) == EC_DETAIL_INC_UPDATE => {
            let (reply, rx) = oneshot::channel();
            let data = match control.send(Control::Update(reply)) {
                Ok(()) => rx.await.unwrap_or_default(),
                Err(_) => Default::default(),
            };
            (conn.update.reply(&s.downloads, &data, conn.partial), false)
        }
        EC_OP_GET_PREFERENCES => (lock(conn.prefs).reply(req), false),
        EC_OP_SET_PREFERENCES => (lock(conn.prefs).apply(req), false),
        EC_OP_GET_STATSTREE => {
            let (reply, rx) = oneshot::channel();
            let data = match control.send(Control::StatsTree(reply)) {
                Ok(()) => rx.await.unwrap_or_default(),
                Err(_) => Default::default(),
            };
            (
                crate::ec_stats::tree_reply(req, &data, conn.version, &lock(conn.prefs).nick()),
                false,
            )
        }
        EC_OP_GET_STATSGRAPHS => {
            let h = conn.history.lock().unwrap_or_else(|e| e.into_inner());
            (crate::graphs::graphs_reply(req, &h), false)
        }
        // amuleapi's `POST /version/check`: started, or throttled.
        EC_OP_VERSION_CHECK => (
            if crate::version_check::global().start() {
                Packet::new(EC_OP_NOOP)
            } else {
                failed("Version check throttled; try again shortly.")
            },
            false,
        ),
        EC_OP_FRIEND => {
            let (reply, rx) = oneshot::channel();
            let p = match control.send(Control::Friend {
                req: req.clone(),
                reply,
            }) {
                Ok(()) => rx
                    .await
                    .unwrap_or_else(|_| failed("Already shutting down.")),
                Err(_) => failed("Already shutting down."),
            };
            (p, false)
        }
        EC_OP_GET_CLIENT_HISTORY => {
            let (reply, rx) = oneshot::channel();
            let entries = match control.send(Control::ClientHistory(reply)) {
                Ok(()) => rx.await.unwrap_or_default(),
                Err(_) => Vec::new(),
            };
            (client_history_reply(&entries), false)
        }
        EC_OP_IPFILTER_RELOAD => {
            let _ = control.send(Control::IpFilterReload);
            (Packet::new(EC_OP_NOOP), false)
        }
        EC_OP_IPFILTER_UPDATE => {
            // The URL given, remembered; none, the configured one.
            let given = req.tags.first().map(Tag::as_str).unwrap_or_default();
            let url = {
                let mut p = lock(conn.prefs);
                if given.is_empty() {
                    p.ipfilter_url()
                } else {
                    p.set_ipfilter_url(&given);
                    given
                }
            };
            if !url.is_empty() {
                let _ = control.send(Control::IpFilterUpdate(url));
            }
            (Packet::new(EC_OP_NOOP), false)
        }
        EC_OP_SHUTDOWN if shutting_down => (failed("Already shutting down."), false),
        EC_OP_SHUTDOWN => {
            let _ = control.send(Control::Shutdown);
            (Packet::new(EC_OP_NOOP), true)
        }
        EC_OP_STAT_REQ => {
            let d = detail(req);
            let mut p = stats_reply(s, d);
            // `MakeKadBuddyTag`, when asked for: no buddy is kept or
            // served yet, so every counter is 0.
            if d != EC_DETAIL_UPDATE && req.tag(EC_TAG_KAD_BUDDY).is_some() {
                let at = p.tags.len().saturating_sub(1);
                p.tags.insert(at, kad_buddy_tag());
            }
            // `AddLoggerTag`: the lines this connection has not seen, after
            // the banned count, at the GUI's levels.
            if d == EC_DETAIL_FULL || d == EC_DETAIL_INC_UPDATE {
                let lines = crate::applog::global().read(&mut conn.log, LOG_LINES_PER_MESSAGE);
                if !lines.is_empty() {
                    let mut t = Tag::empty(EC_TAG_STATS_LOGGER_MESSAGE);
                    t.children = lines
                        .iter()
                        .map(|l| Tag::string(EC_TAG_STRING, l))
                        .collect();
                    p.tags.insert(3.min(p.tags.len()), t);
                }
            }
            (p, false)
        }
        EC_OP_GET_LOG => (
            Packet::new(EC_OP_LOG)
                .with(Tag::string(EC_TAG_STRING, &crate::applog::global().text())),
            false,
        ),
        EC_OP_RESET_LOG => {
            crate::applog::global().reset();
            (Packet::new(EC_OP_NOOP), false)
        }
        EC_OP_GET_LAST_LOG_ENTRY => {
            let text = crate::applog::global().text();
            let last = text
                .strip_suffix('\n')
                .unwrap_or(&text)
                .rsplit('\n')
                .next()
                .unwrap_or("")
                .to_owned();
            (
                Packet::new(EC_OP_LOG).with(Tag::string(EC_TAG_STRING, &last)),
                false,
            )
        }
        EC_OP_GET_SERVERINFO => (
            Packet::new(EC_OP_SERVERINFO).with(Tag::string(
                EC_TAG_STRING,
                &crate::applog::global().server_text(false),
            )),
            false,
        ),
        EC_OP_CLEAR_SERVERINFO => {
            crate::applog::global().server_text(true);
            (Packet::new(EC_OP_NOOP), false)
        }
        EC_OP_ADDLOGLINE => {
            let level = if req.tag(EC_TAG_LOG_TO_STATUS).is_some() {
                tracing::Level::WARN
            } else {
                tracing::Level::INFO
            };
            let line = req.tag(EC_TAG_STRING).map(Tag::as_str).unwrap_or_default();
            crate::applog::global().push(level, &line);
            (Packet::new(EC_OP_NOOP), false)
        }
        EC_OP_GET_CONNSTATE => (
            Packet::new(EC_OP_MISC_DATA).with(connstate_tag(s, detail(req))),
            false,
        ),
        // amulegui's incremental updates come with the update protocol.
        EC_OP_GET_DLOAD_QUEUE if detail(req) == EC_DETAIL_INC_UPDATE => {
            (failed("Invalid opcode (wrong protocol version?)"), false)
        }
        EC_OP_GET_DLOAD_QUEUE => (download_queue_reply(req, s), false),
        EC_OP_ADD_LINK => (add_links(req, control).await, false),
        op if crate::ec_search::is_search(op) => {
            let (p, started) = crate::ec_search::forward(req, conn.search, control).await;
            if let Some(id) = started {
                conn.search.current = id;
            }
            (p, false)
        }
        EC_OP_PARTFILE_PAUSE
        | EC_OP_PARTFILE_RESUME
        | EC_OP_PARTFILE_STOP
        | EC_OP_PARTFILE_DELETE
        | EC_OP_PARTFILE_PRIO_SET
        | EC_OP_PARTFILE_SET_CAT => {
            let categories = lock(conn.prefs).category_count();
            (partfile_cmd(req, s, categories, control).await, false)
        }
        EC_OP_CREATE_CATEGORY | EC_OP_UPDATE_CATEGORY => {
            // One category, or nothing to do.
            if req.tags.len() != 1 {
                return (Packet::new(EC_OP_NOOP), false);
            }
            let mut p = lock(conn.prefs);
            let r = if req.opcode == EC_OP_CREATE_CATEGORY {
                p.create_category(&req.tags[0])
            } else {
                p.update_category_from(&req.tags[0])
            };
            (category_reply(r), false)
        }
        EC_OP_DELETE_CATEGORY => {
            if req.tags.len() != 1 {
                return (failed("Malformed category request."), false);
            }
            let index = req.tags[0].as_int();
            let r = lock(conn.prefs).delete_category(index);
            if r == crate::prefs::CategoryResult::Done {
                let (done, applied) = oneshot::channel();
                if control
                    .send(Control::CategoryRemoved(index as u32, done))
                    .is_ok()
                {
                    let _ = applied.await;
                }
            }
            (category_reply(r), false)
        }
        op if crate::ec_servers::is_server_request(op) => {
            (crate::ec_servers::ask(req, control).await, false)
        }
        EC_OP_GET_SHARED_FILES
        | EC_OP_SHAREDFILES_RELOAD
        | EC_OP_SHARED_SET_PRIO
        | EC_OP_GET_SHARED_DIRS
        | EC_OP_SET_SHARED_DIRS
        | EC_OP_KNOWNFILE_DELETE
        | EC_OP_VERIFY_LOCAL_DATA
        | EC_OP_SHARED_FILE_SET_COMMENT
        | EC_OP_RENAME_FILE => match crate::ec_shared::answer(req, control).await {
            Some(p) => (p, false),
            None => (failed("Invalid opcode (wrong protocol version?)"), false),
        },
        op => {
            info!("External Connection: invalid opcode received: {op:#x}");
            (failed("Invalid opcode (wrong protocol version?)"), false)
        }
    }
}

/// `ExternalConn`: bind `ECAddress:ECPort`, logging as aMule does.
pub async fn listen(settings: &EcSettings) -> Option<TcpListener> {
    let a = settings.addr;
    match TcpListener::bind(a).await {
        Ok(l) => {
            info!(
                "*** TCP socket (ECServer) listening on {}:{}",
                a.ip(),
                a.port()
            );
            Some(l)
        }
        Err(e) => {
            warn!(
                "Could not listen for external connections at {}:{}! ({e})",
                a.ip(),
                a.port()
            );
            None
        }
    }
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Accept connections until the listener fails; each runs on its own.
pub async fn serve(
    listener: TcpListener,
    settings: EcSettings,
    identity: Identity,
    status: watch::Receiver<Status>,
    control: mpsc::UnboundedSender<Control>,
    history: Arc<Mutex<crate::graphs::History>>,
    applied: Arc<DownloadChanges>,
) {
    let limiter = Arc::new(Mutex::new(AuthLimiter::new(settings.limits)));
    let creds = Arc::new(settings.credentials);
    let prefs = Arc::new(Mutex::new(settings.prefs));
    // The daily version check, on while the preference is.
    {
        let prefs = prefs.clone();
        tokio::spawn(crate::version_check::run_daily(
            crate::version_check::global(),
            move || lock(&prefs).check_new_version(),
        ));
    }
    let identity = Arc::new(identity);
    // `IsOnShutDown`: one shutdown, whichever connection asks.
    let shutting_down = Arc::new(AtomicBool::new(false));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("ERROR: couldn't accept a new external connection ({e})");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        info!("New external connection accepted");
        let prefs = prefs.clone();
        let history = history.clone();
        let applied = applied.clone();
        let (limiter, creds, identity, status, control, down) = (
            limiter.clone(),
            creds.clone(),
            identity.clone(),
            status.clone(),
            control.clone(),
            shutting_down.clone(),
        );
        tokio::spawn(async move {
            let shared = Shared {
                creds: &creds,
                identity: &identity,
                limiter: &limiter,
                shutting_down: &down,
                prefs: &prefs,
                history: &history,
                applied: &applied,
            };
            let why = connection(stream, peer.ip(), shared, status, control).await;
            debug!("EC {peer}: {why}");
            info!("External connection closed.");
        });
    }
}

/// Requests that change the download queue; the client refreshes its view
/// at once after each.
fn changes_downloads(opcode: u8) -> bool {
    matches!(
        opcode,
        EC_OP_ADD_LINK
            | EC_OP_PARTFILE_PAUSE
            | EC_OP_PARTFILE_RESUME
            | EC_OP_PARTFILE_STOP
            | EC_OP_PARTFILE_DELETE
            | EC_OP_PARTFILE_PRIO_SET
            | EC_OP_PARTFILE_SET_CAT
            | EC_OP_DELETE_CATEGORY
            | EC_OP_DOWNLOAD_SEARCH_RESULT
    )
}

/// What every connection shares.
struct Shared<'a> {
    creds: &'a Credentials,
    identity: &'a Identity,
    limiter: &'a Mutex<AuthLimiter>,
    shutting_down: &'a AtomicBool,
    prefs: &'a Mutex<crate::prefs::PrefStore>,
    history: &'a Mutex<crate::graphs::History>,
    applied: &'a DownloadChanges,
}

/// `EC_LOG_LINES_PER_MESSAGE`: a big backlog goes over a few polls.
pub const LOG_LINES_PER_MESSAGE: usize = 5000;

/// What one connection keeps between its requests.
pub struct ConnView<'a> {
    /// What it has read of the log.
    pub log: crate::applog::Cursor,
    /// It speaks the partial-update protocol.
    pub partial: bool,
    /// How it searches, and the last search it started.
    pub search: crate::ec_search::Ctx,
    /// What it was sent of each object, for incremental updates.
    pub update: crate::ec_update::UpdateState,
    pub prefs: &'a Mutex<crate::prefs::PrefStore>,
    /// The statistics graphs' history.
    pub history: &'a Mutex<crate::graphs::History>,
    /// The daemon's version, as `EC_OP_AUTH_OK` gives it.
    pub version: &'a str,
}

/// One connection, until it closes; returns why.
async fn connection(
    mut s: TcpStream,
    peer: std::net::IpAddr,
    sh: Shared<'_>,
    mut status: watch::Receiver<Status>,
    control: mpsc::UnboundedSender<Control>,
) -> String {
    let mut conn = ServerConn::new(peer);
    let mut cv = ConnView {
        log: crate::applog::global().cursor(),
        partial: false,
        search: Default::default(),
        update: Default::default(),
        prefs: sh.prefs,
        history: sh.history,
        version: &sh.identity.version,
    };
    loop {
        let mut header = [0u8; 8];
        if let Err(e) = s.read_exact(&mut header).await {
            return e.to_string();
        }
        let (flags, len) = match conn.check_header(header) {
            Ok(x) => x,
            Err(e) => return e,
        };
        let mut body = vec![0u8; len];
        if let Err(e) = s.read_exact(&mut body).await {
            return e.to_string();
        }
        let received = {
            let mut l = sh.limiter.lock().unwrap_or_else(|e| e.into_inner());
            conn.receive(flags, body, sh.creds, sh.identity, &mut l, unix_now())
        };
        for line in conn.take_log() {
            info!("{line}");
        }
        let frame = match received {
            Received::Reply(f) => f,
            Received::Close(why) => return why,
            Received::Request(req) => {
                let down = sh.shutting_down.load(Ordering::SeqCst);
                let view = status.borrow_and_update().clone();
                cv.partial = conn.partial_update();
                cv.search.multi = conn.multi_search();
                cv.search.union = conn.progress_union();
                let (reply, stops) = answer(&req, &view, down, &control, &mut cv).await;
                // A change to the downloads is answered once the view shows
                // it, as aMule's are: what the client asks next sees it.
                if changes_downloads(req.opcode) && reply.opcode != EC_OP_FAILED {
                    let target = sh.applied.load(Ordering::SeqCst);
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                        while status.borrow_and_update().applied < target {
                            if status.changed().await.is_err() {
                                break;
                            }
                        }
                    })
                    .await;
                }
                if stops {
                    info!("External Connection: shutdown requested");
                    sh.shutting_down.store(true, Ordering::SeqCst);
                }
                match conn.frame(&reply) {
                    Ok(f) => f,
                    Err(e) => return e,
                }
            }
        };
        if let Err(e) = s.write_all(&frame).await {
            return e.to_string();
        }
    }
}
