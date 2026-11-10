// SPDX-License-Identifier: GPL-2.0-or-later
//! Typed views of the EC replies a GUI needs, and builders for its requests.
//!
//! Tag layouts follow `ECSpecialCoreTags.cpp` (what the daemon writes) and
//! `ECSpecialTags.h` (what amulegui reads). Every field is optional on the
//! wire; a missing one reads as zero or empty, as in the C++ accessors.

use crate::client::Client;
use crate::codes::*;
use crate::tag::{Packet, Tag};
use crate::Error;

pub type Hash = [u8; 16];

pub fn hash_hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02X}")).collect()
}

fn ip_string(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// `EC_TAG_CONNSTATE` bits.
#[derive(Clone, Debug, Default)]
pub struct ConnState {
    pub bits: u8,
    pub ed2k_enabled: bool,
    pub kad_enabled: bool,
    pub server: Option<Server>,
    pub ed2k_id: u32,
    pub client_id: u32,
    pub kad_id: Option<String>,
}

impl ConnState {
    pub fn ed2k_connected(&self) -> bool {
        self.bits & 0x01 != 0
    }
    pub fn ed2k_connecting(&self) -> bool {
        self.bits & 0x02 != 0
    }
    pub fn kad_connected(&self) -> bool {
        self.bits & 0x04 != 0
    }
    pub fn kad_firewalled(&self) -> bool {
        self.bits & 0x08 != 0
    }
    pub fn kad_running(&self) -> bool {
        self.bits & 0x10 != 0
    }
    /// eD2k "low ID": an ID below 16777216 means we are firewalled.
    pub fn low_id(&self) -> bool {
        self.ed2k_connected() && self.ed2k_id < 0x0100_0000
    }

    fn from_tag(t: &Tag) -> Self {
        let nets = t.child(EC_TAG_NETWORKS_ENABLED).map(Tag::as_int);
        ConnState {
            bits: t.as_int() as u8,
            // Absent on older daemons: assume both, as amulegui does.
            ed2k_enabled: nets.is_none_or(|n| n & 1 != 0),
            kad_enabled: nets.is_none_or(|n| n & 2 != 0),
            server: t.child(EC_TAG_SERVER).map(Server::from_tag),
            ed2k_id: t.child_int(EC_TAG_ED2K_ID) as u32,
            client_id: t.child_int(EC_TAG_CLIENT_ID) as u32,
            kad_id: t
                .child(EC_TAG_KAD_ID)
                .map(|k| k.data.iter().map(|b| format!("{b:02X}")).collect()),
        }
    }
}

/// `EC_OP_STATS`, requested at `EC_DETAIL_FULL`.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub ul_speed: u64,
    pub dl_speed: u64,
    pub ul_limit: u64,
    pub dl_limit: u64,
    pub ul_overhead: u64,
    pub dl_overhead: u64,
    pub queue_len: u64,
    pub total_sources: u64,
    pub banned: u64,
    pub ed2k_users: u64,
    pub ed2k_files: u64,
    pub kad_users: u64,
    pub kad_files: u64,
    pub kad_nodes: u64,
    pub session_sent: u64,
    pub session_received: u64,
    pub total_sent: u64,
    pub total_received: u64,
    pub shared_files: u64,
    pub uptime_secs: u64,
    pub active_connections: u64,
    pub temp_free: Option<u64>,
    pub incoming_free: Option<u64>,
    pub conn: ConnState,
    /// New log lines since the previous FULL stats request on this
    /// connection. The daemon keeps the cursor per connection.
    pub new_log_lines: Vec<String>,
}

impl Stats {
    fn from_packet(p: &Packet) -> Self {
        let g = |n| p.tag(n).map_or(0, Tag::as_int);
        Stats {
            ul_speed: g(EC_TAG_STATS_UL_SPEED),
            dl_speed: g(EC_TAG_STATS_DL_SPEED),
            ul_limit: g(EC_TAG_STATS_UL_SPEED_LIMIT),
            dl_limit: g(EC_TAG_STATS_DL_SPEED_LIMIT),
            ul_overhead: g(EC_TAG_STATS_UP_OVERHEAD),
            dl_overhead: g(EC_TAG_STATS_DOWN_OVERHEAD),
            queue_len: g(EC_TAG_STATS_UL_QUEUE_LEN),
            total_sources: g(EC_TAG_STATS_TOTAL_SRC_COUNT),
            banned: g(EC_TAG_STATS_BANNED_COUNT),
            ed2k_users: g(EC_TAG_STATS_ED2K_USERS),
            ed2k_files: g(EC_TAG_STATS_ED2K_FILES),
            kad_users: g(EC_TAG_STATS_KAD_USERS),
            kad_files: g(EC_TAG_STATS_KAD_FILES),
            kad_nodes: g(EC_TAG_STATS_KAD_NODES),
            session_sent: g(EC_TAG_STATS_SESSION_SENT_BYTES),
            session_received: g(EC_TAG_STATS_SESSION_RECEIVED_BYTES),
            total_sent: g(EC_TAG_STATS_TOTAL_SENT_BYTES),
            total_received: g(EC_TAG_STATS_TOTAL_RECEIVED_BYTES),
            shared_files: g(EC_TAG_STATS_SHARED_FILE_COUNT),
            uptime_secs: g(EC_TAG_STATS_UPTIME_SECONDS),
            active_connections: g(EC_TAG_STATS_ACTIVE_CONNECTIONS),
            temp_free: p.tag(EC_TAG_STATS_TEMP_FREE_SPACE).map(Tag::as_int),
            incoming_free: p.tag(EC_TAG_STATS_INCOMING_FREE_SPACE).map(Tag::as_int),
            conn: p
                .tag(EC_TAG_CONNSTATE)
                .map(ConnState::from_tag)
                .unwrap_or_default(),
            new_log_lines: p
                .tag(EC_TAG_STATS_LOGGER_MESSAGE)
                .map(|t| {
                    t.children
                        .iter()
                        .filter(|c| c.name == EC_TAG_STRING)
                        .map(Tag::as_str)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// Part file status (`PS_*` in Constants.h).
pub fn part_status_text(status: u64, stopped: bool, sources_xfer: u64) -> &'static str {
    if stopped {
        return "Stopped";
    }
    match status {
        0 | 1 if sources_xfer > 0 => "Downloading",
        0 | 1 => "Waiting",
        2 => "Waiting for hash",
        3 => "Hashing",
        4 => "Error",
        5 => "Insufficient disk space",
        6 => "Unknown",
        7 => "Paused",
        8 => "Completing",
        9 => "Complete",
        10 => "Allocating",
        _ => "?",
    }
}

pub const PS_PAUSED: u64 = 7;
pub const PS_COMPLETE: u64 = 9;

/// Download priority (`PR_*`); the daemon adds 10 when it is automatic.
pub fn priority_text(prio: u64) -> &'static str {
    let auto = prio >= 10;
    match (prio % 10, auto) {
        (0, false) => "Low",
        (1, false) => "Normal",
        (2, false) => "High",
        (3, false) => "Very high",
        (4, false) => "Very low",
        (0, true) => "Auto (Low)",
        (1, true) => "Auto (Normal)",
        (2, true) => "Auto (High)",
        (5, _) => "Auto",
        (6, _) => "Release",
        _ => "?",
    }
}

pub const PR_LOW: u8 = 0;
pub const PR_NORMAL: u8 = 1;
pub const PR_HIGH: u8 = 2;
pub const PR_AUTO: u8 = 5;

/// A download (`CEC_PartFile_Tag`).
#[derive(Clone, Debug, Default)]
pub struct PartFile {
    pub ecid: u32,
    pub hash: Hash,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub transferred: u64,
    pub completed: u64,
    pub speed: u64,
    pub status: u64,
    pub stopped: bool,
    pub priority: u64,
    pub category: u64,
    pub sources: u64,
    pub sources_not_current: u64,
    pub sources_xfer: u64,
    pub sources_a4af: u64,
    pub available_parts: u64,
    pub last_seen_complete: u64,
    pub last_received: u64,
    pub ed2k_link: String,
}

impl PartFile {
    fn from_tag(t: &Tag) -> Self {
        PartFile {
            ecid: t.as_int() as u32,
            hash: t
                .child(EC_TAG_PARTFILE_HASH)
                .and_then(Tag::as_hash)
                .unwrap_or_default(),
            name: t.child_str(EC_TAG_PARTFILE_NAME),
            path: t.child_str(EC_TAG_KNOWNFILE_PATH),
            size: t.child_int(EC_TAG_PARTFILE_SIZE_FULL),
            transferred: t.child_int(EC_TAG_PARTFILE_SIZE_XFER),
            completed: t.child_int(EC_TAG_PARTFILE_SIZE_DONE),
            speed: t.child_int(EC_TAG_PARTFILE_SPEED),
            status: t.child_int(EC_TAG_PARTFILE_STATUS),
            stopped: t.child_int(EC_TAG_PARTFILE_STOPPED) != 0,
            priority: t.child_int(EC_TAG_PARTFILE_PRIO),
            category: t.child_int(EC_TAG_PARTFILE_CAT),
            sources: t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT),
            sources_not_current: t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_NOT_CURRENT),
            sources_xfer: t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER),
            sources_a4af: t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_A4AF),
            available_parts: t.child_int(EC_TAG_PARTFILE_AVAILABLE_PARTS),
            last_seen_complete: t.child_int(EC_TAG_PARTFILE_LAST_SEEN_COMP),
            last_received: t.child_int(EC_TAG_PARTFILE_LAST_RECV),
            ed2k_link: t.child_str(EC_TAG_PARTFILE_ED2K_LINK),
        }
    }

    pub fn progress(&self) -> f32 {
        if self.size == 0 {
            0.0
        } else {
            (self.completed as f64 / self.size as f64).clamp(0.0, 1.0) as f32
        }
    }

    pub fn status_text(&self) -> &'static str {
        part_status_text(self.status, self.stopped, self.sources_xfer)
    }

    pub fn is_complete(&self) -> bool {
        self.status == PS_COMPLETE
    }
}

/// A shared file (`CEC_SharedFile_Tag`).
#[derive(Clone, Debug, Default)]
pub struct SharedFile {
    pub ecid: u32,
    pub hash: Hash,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub transferred: u64,
    pub transferred_all: u64,
    pub requests: u64,
    pub requests_all: u64,
    pub accepts: u64,
    pub accepts_all: u64,
    pub priority: u64,
    pub complete_sources: u64,
    pub on_queue: u64,
    pub upload_speed: u64,
    pub ed2k_link: String,
}

impl SharedFile {
    fn from_tag(t: &Tag) -> Self {
        SharedFile {
            ecid: t.as_int() as u32,
            hash: t
                .child(EC_TAG_PARTFILE_HASH)
                .and_then(Tag::as_hash)
                .unwrap_or_default(),
            name: t.child_str(EC_TAG_PARTFILE_NAME),
            path: t.child_str(EC_TAG_KNOWNFILE_PATH),
            size: t.child_int(EC_TAG_PARTFILE_SIZE_FULL),
            transferred: t.child_int(EC_TAG_KNOWNFILE_XFERRED),
            transferred_all: t.child_int(EC_TAG_KNOWNFILE_XFERRED_ALL),
            requests: t.child_int(EC_TAG_KNOWNFILE_REQ_COUNT),
            requests_all: t.child_int(EC_TAG_KNOWNFILE_REQ_COUNT_ALL),
            accepts: t.child_int(EC_TAG_KNOWNFILE_ACCEPT_COUNT),
            accepts_all: t.child_int(EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL),
            priority: t.child_int(EC_TAG_KNOWNFILE_PRIO),
            complete_sources: t.child_int(EC_TAG_KNOWNFILE_COMPLETE_SOURCES),
            on_queue: t.child_int(EC_TAG_KNOWNFILE_ON_QUEUE),
            upload_speed: t.child_int(EC_TAG_KNOWNFILE_UPLOAD_SPEED),
            ed2k_link: t.child_str(EC_TAG_PARTFILE_ED2K_LINK),
        }
    }
}

/// An ed2k server (`CEC_Server_Tag`, non-incremental form: the tag value is
/// the address).
#[derive(Clone, Debug, Default)]
pub struct Server {
    pub ip: [u8; 4],
    pub port: u16,
    pub name: String,
    pub description: String,
    pub version: String,
    pub users: u64,
    pub max_users: u64,
    pub files: u64,
    pub ping: u64,
    pub priority: u64,
    pub failed: u64,
    pub is_static: bool,
}

impl Server {
    fn from_tag(t: &Tag) -> Self {
        let (ip, port) = t.as_ipv4().unwrap_or(([0; 4], 0));
        Server {
            ip,
            port,
            name: t.child_str(EC_TAG_SERVER_NAME),
            description: t.child_str(EC_TAG_SERVER_DESC),
            version: t.child_str(EC_TAG_SERVER_VERSION),
            users: t.child_int(EC_TAG_SERVER_USERS),
            max_users: t.child_int(EC_TAG_SERVER_USERS_MAX),
            files: t.child_int(EC_TAG_SERVER_FILES),
            ping: t.child_int(EC_TAG_SERVER_PING),
            priority: t.child_int(EC_TAG_SERVER_PRIO),
            failed: t.child_int(EC_TAG_SERVER_FAILED),
            is_static: t.child_int(EC_TAG_SERVER_STATIC) != 0,
        }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", ip_string(self.ip), self.port)
    }

    pub fn priority_text(&self) -> &'static str {
        // SRV_PR_* in Server.h: 0 normal, 1 high, 2 low.
        match self.priority {
            0 => "Normal",
            1 => "High",
            2 => "Low",
            _ => "?",
        }
    }
}

/// A search hit (`CEC_SearchFile_Tag`).
#[derive(Clone, Debug, Default)]
pub struct SearchResult {
    pub ecid: u32,
    pub hash: Hash,
    pub name: String,
    pub size: u64,
    pub sources: u64,
    pub complete_sources: u64,
    /// `CSearchFile::DownloadStatus`; see [`SearchResult::status_text`].
    pub status: u64,
    pub parent: Option<u32>,
}

impl SearchResult {
    fn from_tag(t: &Tag) -> Self {
        SearchResult {
            ecid: t.as_int() as u32,
            hash: t
                .child(EC_TAG_PARTFILE_HASH)
                .and_then(Tag::as_hash)
                .unwrap_or_default(),
            name: t.child_str(EC_TAG_PARTFILE_NAME),
            size: t.child_int(EC_TAG_PARTFILE_SIZE_FULL),
            sources: t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT),
            complete_sources: t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER),
            status: t.child_int(EC_TAG_PARTFILE_STATUS),
            parent: t.child(EC_TAG_SEARCH_PARENT).map(|p| p.as_int() as u32),
        }
    }

    pub fn status_text(&self) -> &'static str {
        // CSearchFile::DownloadStatus in SearchFile.h.
        match self.status {
            1 => "Known / shared",
            2 => "Downloading",
            3 => "Canceled",
            4 => "Downloading (was canceled)",
            _ => "",
        }
    }
}

/// `EC_SEARCH_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchKind {
    Local,
    Global,
    Kad,
    All,
}

impl SearchKind {
    pub const ALL: [SearchKind; 4] = [
        SearchKind::Local,
        SearchKind::Global,
        SearchKind::Kad,
        SearchKind::All,
    ];

    fn code(self) -> u8 {
        match self {
            SearchKind::Local => EC_SEARCH_LOCAL,
            SearchKind::Global => EC_SEARCH_GLOBAL,
            SearchKind::Kad => EC_SEARCH_KAD,
            SearchKind::All => EC_SEARCH_ALL,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SearchKind::Local => "Local (server)",
            SearchKind::Global => "Global (servers)",
            SearchKind::Kad => "Kad",
            SearchKind::All => "eD2k + Kad",
        }
    }
}

/// Parameters for [`Client::search_start`] (see `CEC_Search_Tag`).
#[derive(Clone, Debug, Default)]
pub struct SearchParams {
    pub text: String,
    /// "" for any, or an `ED2KFTSTR_*` value: Audio, Video, Image, Doc, Pro, Arc, Iso.
    pub file_type: String,
    pub extension: String,
    pub min_size: u64,
    pub max_size: u64,
    pub availability: u32,
}

pub const FILE_TYPES: [(&str, &str); 8] = [
    ("Any", ""),
    ("Archive", "Arc"),
    ("Audio", "Audio"),
    ("CD image", "Iso"),
    ("Document", "Doc"),
    ("Image", "Image"),
    ("Program", "Pro"),
    ("Video", "Video"),
];

/// `EC_OP_SEARCH_PROGRESS` for the single (legacy) search.
#[derive(Clone, Debug, Default)]
pub struct SearchProgress {
    pub percent: Option<u8>,
    pub result_count: u64,
    pub finished: bool,
}

/// The `EC_OP_FAILED` text, or `Ok` for anything else.
fn check(reply: Packet) -> Result<Packet, Error> {
    if reply.opcode == EC_OP_FAILED {
        Err(Error::Failed(
            reply.message().unwrap_or_else(|| "request failed".into()),
        ))
    } else {
        Ok(reply)
    }
}

/// Address a download by hash, guarded by its ECID so a stale selection
/// cannot hit a replacement file (see Get_EC_Response_PartFile_Cmd).
fn partfile_target(hash: Hash, ecid: u32) -> Tag {
    Tag::hash(EC_TAG_PARTFILE, hash).with(Tag::int(EC_TAG_ECID, u64::from(ecid)))
}

/// The C++ `EC_OP_PARTFILE_*` commands that need only a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartFileCmd {
    Pause,
    Resume,
    Stop,
    Cancel,
}

impl Client {
    pub fn stats(&mut self) -> Result<Stats, Error> {
        let reply = check(self.request(&Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_FULL))?)?;
        Ok(Stats::from_packet(&reply))
    }

    pub fn download_queue(&mut self) -> Result<Vec<PartFile>, Error> {
        let reply =
            check(self.request(&Packet::new(EC_OP_GET_DLOAD_QUEUE).with_detail(EC_DETAIL_FULL))?)?;
        Ok(reply
            .tags_named(EC_TAG_PARTFILE)
            .map(PartFile::from_tag)
            .collect())
    }

    pub fn shared_files(&mut self) -> Result<Vec<SharedFile>, Error> {
        let reply =
            check(self.request(&Packet::new(EC_OP_GET_SHARED_FILES).with_detail(EC_DETAIL_FULL))?)?;
        Ok(reply
            .tags_named(EC_TAG_KNOWNFILE)
            .map(SharedFile::from_tag)
            .collect())
    }

    pub fn servers(&mut self) -> Result<Vec<Server>, Error> {
        let reply =
            check(self.request(&Packet::new(EC_OP_GET_SERVER_LIST).with_detail(EC_DETAIL_FULL))?)?;
        Ok(reply
            .tags_named(EC_TAG_SERVER)
            .map(Server::from_tag)
            .collect())
    }

    /// The whole daemon log (`EC_OP_GET_LOG`), one string.
    pub fn log(&mut self) -> Result<String, Error> {
        let reply = check(self.request(&Packet::new(EC_OP_GET_LOG))?)?;
        Ok(reply.message().unwrap_or_default())
    }

    pub fn add_links(&mut self, links: &[String]) -> Result<(), Error> {
        let mut p = Packet::new(EC_OP_ADD_LINK);
        for l in links {
            p = p.with(Tag::string(EC_TAG_STRING, l.trim()));
        }
        check(self.request(&p)?).map(drop)
    }

    pub fn partfile_cmd(&mut self, cmd: PartFileCmd, files: &[(Hash, u32)]) -> Result<(), Error> {
        let op = match cmd {
            PartFileCmd::Pause => EC_OP_PARTFILE_PAUSE,
            PartFileCmd::Resume => EC_OP_PARTFILE_RESUME,
            PartFileCmd::Stop => EC_OP_PARTFILE_STOP,
            PartFileCmd::Cancel => EC_OP_PARTFILE_DELETE,
        };
        let mut p = Packet::new(op);
        for &(h, id) in files {
            p = p.with(partfile_target(h, id));
        }
        check(self.request(&p)?).map(drop)
    }

    /// `prio` is `PR_LOW`, `PR_NORMAL`, `PR_HIGH` or `PR_AUTO`. The daemon
    /// reads the value as the target's first child.
    pub fn set_download_priority(&mut self, files: &[(Hash, u32)], prio: u8) -> Result<(), Error> {
        let mut p = Packet::new(EC_OP_PARTFILE_PRIO_SET);
        for &(h, _) in files {
            p = p.with(
                Tag::hash(EC_TAG_PARTFILE, h).with(Tag::int(EC_TAG_PARTFILE_PRIO, u64::from(prio))),
            );
        }
        check(self.request(&p)?).map(drop)
    }

    pub fn clear_completed(&mut self, ecids: &[u32]) -> Result<(), Error> {
        let mut p = Packet::new(EC_OP_CLEAR_COMPLETED);
        for &id in ecids {
            p = p.with(Tag::int(EC_TAG_ECID, u64::from(id)));
        }
        check(self.request(&p)?).map(drop)
    }

    /// Upload priority for shared files (same values as downloads).
    pub fn set_shared_priority(&mut self, files: &[Hash], prio: u8) -> Result<(), Error> {
        let mut p = Packet::new(EC_OP_SHARED_SET_PRIO);
        for &h in files {
            p = p.with(
                Tag::hash(EC_TAG_PARTFILE, h).with(Tag::int(EC_TAG_PARTFILE_PRIO, u64::from(prio))),
            );
        }
        check(self.request(&p)?).map(drop)
    }

    pub fn shared_reload(&mut self) -> Result<(), Error> {
        check(self.request(&Packet::new(EC_OP_SHAREDFILES_RELOAD))?).map(drop)
    }

    /// Connect to one server, or to any when `server` is `None`.
    pub fn server_connect(&mut self, server: Option<([u8; 4], u16)>) -> Result<(), Error> {
        let mut p = Packet::new(EC_OP_SERVER_CONNECT);
        if let Some((ip, port)) = server {
            p = p.with(Tag::ipv4(EC_TAG_SERVER, ip, port));
        }
        check(self.request(&p)?).map(drop)
    }

    pub fn server_disconnect(&mut self) -> Result<(), Error> {
        check(self.request(&Packet::new(EC_OP_SERVER_DISCONNECT))?).map(drop)
    }

    pub fn server_remove(&mut self, ip: [u8; 4], port: u16) -> Result<(), Error> {
        check(
            self.request(&Packet::new(EC_OP_SERVER_REMOVE).with(Tag::ipv4(
                EC_TAG_SERVER,
                ip,
                port,
            )))?,
        )
        .map(drop)
    }

    /// `address` is "host:port".
    pub fn server_add(&mut self, address: &str, name: &str) -> Result<(), Error> {
        let p = Packet::new(EC_OP_SERVER_ADD)
            .with(Tag::string(EC_TAG_SERVER_ADDRESS, address))
            .with(Tag::string(EC_TAG_SERVER_NAME, name));
        check(self.request(&p)?).map(drop)
    }

    /// Connect every enabled network (`EC_OP_CONNECT`).
    pub fn connect_all(&mut self) -> Result<(), Error> {
        check(self.request(&Packet::new(EC_OP_CONNECT))?).map(drop)
    }

    pub fn disconnect_all(&mut self) -> Result<(), Error> {
        check(self.request(&Packet::new(EC_OP_DISCONNECT))?).map(drop)
    }

    pub fn kad_start(&mut self) -> Result<(), Error> {
        check(self.request(&Packet::new(EC_OP_KAD_START))?).map(drop)
    }

    pub fn kad_stop(&mut self) -> Result<(), Error> {
        check(self.request(&Packet::new(EC_OP_KAD_STOP))?).map(drop)
    }

    /// Start a search, replacing the previous one. Returns the daemon's note.
    pub fn search_start(
        &mut self,
        kind: SearchKind,
        params: &SearchParams,
    ) -> Result<String, Error> {
        let mut t = Tag::int(EC_TAG_SEARCH_TYPE, u64::from(kind.code()))
            .with(Tag::string(EC_TAG_SEARCH_NAME, params.text.trim()))
            .with(Tag::string(EC_TAG_SEARCH_FILE_TYPE, &params.file_type));
        if !params.extension.is_empty() {
            t = t.with(Tag::string(EC_TAG_SEARCH_EXTENSION, &params.extension));
        }
        if params.availability != 0 {
            t = t.with(Tag::int(
                EC_TAG_SEARCH_AVAILABILITY,
                u64::from(params.availability),
            ));
        }
        if params.min_size != 0 {
            t = t.with(Tag::int(EC_TAG_SEARCH_MIN_SIZE, params.min_size));
        }
        if params.max_size != 0 {
            t = t.with(Tag::int(EC_TAG_SEARCH_MAX_SIZE, params.max_size));
        }
        let reply = check(self.request(&Packet::new(EC_OP_SEARCH_START).with(t))?)?;
        Ok(reply.message().unwrap_or_default())
    }

    pub fn search_stop(&mut self) -> Result<(), Error> {
        check(self.request(&Packet::new(EC_OP_SEARCH_STOP))?).map(drop)
    }

    pub fn search_results(&mut self) -> Result<Vec<SearchResult>, Error> {
        let reply =
            check(self.request(&Packet::new(EC_OP_SEARCH_RESULTS).with_detail(EC_DETAIL_FULL))?)?;
        Ok(reply
            .tags_named(EC_TAG_SEARCHFILE)
            .map(SearchResult::from_tag)
            .collect())
    }

    pub fn search_progress(&mut self) -> Result<SearchProgress, Error> {
        let reply = check(self.request(&Packet::new(EC_OP_SEARCH_PROGRESS))?)?;
        let state = reply.tag(EC_TAG_SEARCH_LIFECYCLE_STATE).map(Tag::as_int);
        Ok(SearchProgress {
            percent: reply
                .tag(EC_TAG_SEARCH_LIFECYCLE_PERCENT)
                .map(|t| t.as_int().min(100) as u8),
            result_count: reply.tag(EC_TAG_SEARCH_RESULT_COUNT).map_or(0, Tag::as_int),
            // SearchLifecycleState: 0 idle, 1 running, 2 finished.
            finished: state.is_some_and(|s| s != 1),
        })
    }

    pub fn download_search_results(&mut self, hashes: &[Hash], category: u8) -> Result<(), Error> {
        let mut p = Packet::new(EC_OP_DOWNLOAD_SEARCH_RESULT);
        for &h in hashes {
            p = p.with(
                Tag::hash(EC_TAG_PARTFILE, h)
                    .with(Tag::int(EC_TAG_PARTFILE_CAT, u64::from(category))),
            );
        }
        check(self.request(&p)?).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partfile_reads_the_tags_the_daemon_writes() {
        let t = Tag::int(EC_TAG_PARTFILE, 42)
            .with(Tag::int(EC_TAG_PARTFILE_STATUS, 0))
            .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER, 3))
            .with(Tag::int(EC_TAG_PARTFILE_SIZE_DONE, 50))
            .with(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, 200))
            .with(Tag::int(EC_TAG_PARTFILE_PRIO, 11))
            .with(Tag::string(EC_TAG_PARTFILE_NAME, "a.iso"))
            .with(Tag::hash(EC_TAG_PARTFILE_HASH, [0xAB; 16]));
        let f = PartFile::from_tag(&t);
        assert_eq!(f.ecid, 42);
        assert_eq!(f.name, "a.iso");
        assert_eq!(f.progress(), 0.25);
        assert_eq!(f.status_text(), "Downloading");
        assert_eq!(priority_text(f.priority), "Auto (Normal)");
        assert_eq!(hash_hex(&f.hash), "AB".repeat(16));
    }

    #[test]
    fn connstate_bits_and_server() {
        let t = Tag::int(EC_TAG_CONNSTATE, 0x01 | 0x04 | 0x10)
            .with(Tag::int(EC_TAG_NETWORKS_ENABLED, 3))
            .with(
                Tag::ipv4(EC_TAG_SERVER, [10, 0, 0, 1], 4661)
                    .with(Tag::string(EC_TAG_SERVER_NAME, "srv")),
            )
            .with(Tag::int(EC_TAG_ED2K_ID, 1234));
        let c = ConnState::from_tag(&t);
        assert!(c.ed2k_connected() && c.kad_connected() && c.kad_running());
        assert!(!c.kad_firewalled());
        assert!(c.low_id());
        let s = c.server.unwrap();
        assert_eq!(
            (s.address(), s.name.as_str()),
            ("10.0.0.1:4661".to_string(), "srv")
        );
    }
}
