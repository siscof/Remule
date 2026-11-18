// SPDX-License-Identifier: GPL-2.0-or-later
//! External connections (`ExternalConn.cpp`): what `amulecmd` and
//! `amulegui` log into.
//!
//! A listener on `ECAddress:ECPort`; per connection, the login of
//! [`remule_ec::server`] and then requests, answered from a [`Status`] the
//! client refreshes every second. Served so far: `EC_OP_STAT_REQ`,
//! `EC_OP_GET_CONNSTATE`, `EC_OP_GET_DLOAD_QUEUE`, `EC_OP_ADD_LINK`, the
//! partfile pause, resume, stop and delete commands, and
//! `EC_OP_SHUTDOWN`; anything else is answered `EC_OP_FAILED`, as aMule
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
}

/// The connected server, as the EC server tag tells it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerStatus {
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
}

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
            // The ECID of the connected server: none are given out yet.
            t = t.with(Tag::int(EC_TAG_SERVER, 0));
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
    control: &mpsc::UnboundedSender<Control>,
) -> Packet {
    let op = match req.opcode {
        EC_OP_PARTFILE_PAUSE => FileOp::Pause,
        EC_OP_PARTFILE_RESUME => FileOp::Resume,
        EC_OP_PARTFILE_STOP => FileOp::Stop,
        _ => FileOp::Delete,
    };
    let mut response: Option<Packet> = None;
    for t in &req.tags {
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
) -> (Packet, bool) {
    match req.opcode {
        EC_OP_SHUTDOWN if shutting_down => (failed("Already shutting down."), false),
        EC_OP_SHUTDOWN => {
            let _ = control.send(Control::Shutdown);
            (Packet::new(EC_OP_NOOP), true)
        }
        EC_OP_STAT_REQ => (stats_reply(s, detail(req)), false),
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
        EC_OP_PARTFILE_PAUSE
        | EC_OP_PARTFILE_RESUME
        | EC_OP_PARTFILE_STOP
        | EC_OP_PARTFILE_DELETE => (partfile_cmd(req, s, control).await, false),
        EC_OP_GET_SHARED_FILES
        | EC_OP_SHAREDFILES_RELOAD
        | EC_OP_SHARED_SET_PRIO
        | EC_OP_GET_SHARED_DIRS => match crate::ec_shared::answer(req, control).await {
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
) {
    let limiter = Arc::new(Mutex::new(AuthLimiter::new(settings.limits)));
    let creds = Arc::new(settings.credentials);
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
            };
            let why = connection(stream, peer.ip(), shared, status, control).await;
            debug!("EC {peer}: {why}");
            info!("External connection closed.");
        });
    }
}

/// What every connection shares.
struct Shared<'a> {
    creds: &'a Credentials,
    identity: &'a Identity,
    limiter: &'a Mutex<AuthLimiter>,
    shutting_down: &'a AtomicBool,
}

/// One connection, until it closes; returns why.
async fn connection(
    mut s: TcpStream,
    peer: std::net::IpAddr,
    sh: Shared<'_>,
    status: watch::Receiver<Status>,
    control: mpsc::UnboundedSender<Control>,
) -> String {
    let mut conn = ServerConn::new(peer);
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
                let view = status.borrow().clone();
                let (reply, stops) = answer(&req, &view, down, &control).await;
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
