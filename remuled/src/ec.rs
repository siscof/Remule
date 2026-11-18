// SPDX-License-Identifier: GPL-2.0-or-later
//! External connections (`ExternalConn.cpp`): what `amulecmd` and
//! `amulegui` log into.
//!
//! A listener on `ECAddress:ECPort`; per connection, the login of
//! [`remule_ec::server`] and then requests, answered from a [`Status`] the
//! client refreshes every second. Served so far: `EC_OP_STAT_REQ`,
//! `EC_OP_GET_CONNSTATE` and `EC_OP_SHUTDOWN`; anything else is answered
//! `EC_OP_FAILED`, as aMule answers an opcode it does not know.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ed2k_types::UInt128;
use remule_ec::codes::*;
use remule_ec::server::{AuthLimiter, Credentials, Identity, Limits, Received, ServerConn};
use remule_ec::{Packet, Tag};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Shutdown,
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

/// `ProcessRequest2`, for what is served so far.
pub fn answer(req: &Packet, s: &Status, shutting_down: bool) -> (Packet, Option<Control>) {
    match req.opcode {
        EC_OP_SHUTDOWN if shutting_down => (failed("Already shutting down."), None),
        EC_OP_SHUTDOWN => (Packet::new(EC_OP_NOOP), Some(Control::Shutdown)),
        EC_OP_STAT_REQ => (stats_reply(s, detail(req)), None),
        EC_OP_GET_CONNSTATE => (
            Packet::new(EC_OP_MISC_DATA).with(connstate_tag(s, detail(req))),
            None,
        ),
        op => {
            info!("External Connection: invalid opcode received: {op:#x}");
            (failed("Invalid opcode (wrong protocol version?)"), None)
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
                let (reply, ctl) = answer(&req, &status.borrow(), down);
                if let Some(c) = ctl {
                    info!("External Connection: shutdown requested");
                    sh.shutting_down.store(true, Ordering::SeqCst);
                    let _ = control.send(c);
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
