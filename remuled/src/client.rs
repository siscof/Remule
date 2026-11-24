// SPDX-License-Identifier: GPL-2.0-or-later
//! A running client: downloads with sources from a server, Kad and links,
//! uploads to those who ask, shared files offered to the server and
//! published on Kad. Both `remuled` and `remule download` run this.
//!
//! What happens is logged with [`tracing`] at `info`, each line prefixed
//! with the seconds since start.
//!
//! With [`ClientConfig::ec`], external connections are accepted too
//! ([`crate::ec`]): the client refreshes their view of it every second, and
//! stops when one asks it to.
//!
//! With `REMULE_TRACE` set, every peer packet's protocol, opcode and size
//! is printed to stderr, and every Kad datagram with how it was obfuscated.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed2k_formats::cryptkey_dat::CryptKey;
use ed2k_kad::node::Event as KadEvent;
use ed2k_kad::search::Found;
use ed2k_peer::hello::{CryptSettings, MiscOptions2};
use ed2k_peer::secident::Identity;
use ed2k_peer::Hello;
use ed2k_server::session::Event as ServerEvent;
use ed2k_server::{ConnectOptions, Login, LoginInfo, ServerClient};
use ed2k_types::ed2k::SERVERREASKTIME;
use ed2k_types::Md4Hash;
use remule_core::credits::Credits;
use remule_core::download_queue::{DownloadQueue, Endpoint, Origin, QueueConfig, Report};
use remule_core::downloader::{self, Command, DownloaderConfig, FileOp};
use remule_core::ip_filter::AddressFilter;
use remule_core::publish::{KadPublish, Publisher};
use remule_core::shared::{mtime, ScanOptions, SharedFiles};
use remule_core::statistics::{Statistics, Totals};
use remule_core::upload_queue::{UploadConfig, UploadQueue};
use remule_core::uploader::Uploader;
use remule_core::PartFile;
use remule_net::Bandwidth;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::ec::{self, Control, DownloadIds, EcSettings, KadStatus, ServerStatus, Status};
use crate::ec_search;
use crate::ec_servers::{Effect, ServerList};
use crate::firewall::{self, Reachability, MAX_CONNECT_BACKS};
use crate::kad::{self, KadStart};
use crate::server_conn::{Attempt, Connector, Next, ATTEMPT_TIMEOUT, RETRY_AFTER};
use crate::udp_port::UdpPort;
use remule_core::download_queue::UdpOut;
use remule_core::publish::SourceRoute;
use remule_core::udp_check::CheckRequest;

/// Kad source searches are repeated this often (`GetKadSourceReaskTime`).
const KAD_REASK: Duration = Duration::from_secs(30 * 60);
/// Seconds after Kad connects before searching, so the table fills.
pub const KAD_WARMUP: u64 = 20;
/// Shared files are offered to the server this often (new ones as they come).
const OFFER_EVERY: Duration = Duration::from_secs(60);

/// Where Kad keeps its state.
#[derive(Debug, Clone)]
pub struct KadSettings {
    /// `nodes.dat`, `preferencesKad.dat` and the index files.
    pub dir: PathBuf,
    /// The `nodes.dat` to start from (default: the one in `dir`).
    pub nodes: Option<PathBuf>,
    /// Nodes to bootstrap from as well.
    pub bootstrap: Vec<SocketAddrV4>,
    /// Seconds after Kad connects before the first source searches.
    pub warmup: u64,
}

/// How to run.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The `.part` / `.part.met` files.
    pub temp: PathBuf,
    /// Where finished files go (shared too).
    pub incoming: PathBuf,
    /// Where `known.met`, `known2_64.met` and `clients.met` are kept.
    pub config: PathBuf,
    pub user_hash: Md4Hash,
    pub identity: Arc<Identity>,
    /// Servers to try in turn; the first that logs in is used.
    pub servers: Vec<SocketAddr>,
    pub obfuscate_server: bool,
    /// Log into a server at start (aMule's `Autoconnect`).
    pub autoconnect: bool,
    /// Log in again when the server connection is lost, and try the list
    /// again 30 s after every server failed (aMule's `Reconnect`).
    pub reconnect: bool,
    /// `DeadServerRetry` when `RemoveDeadServer` is on: servers whose status
    /// pings failed this often are dropped.
    pub dead_server_retries: Option<u32>,
    pub kad: Option<KadSettings>,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub nick: String,
    pub max_connections: usize,
    /// KiB/s, 0 for no limit.
    pub max_download: u32,
    pub max_upload: u32,
    /// Share the incoming directory and [`ClientConfig::share`], and upload
    /// to those who ask.
    pub upload: bool,
    /// More directories to share.
    pub share: Vec<PathBuf>,
    /// Assume others can connect to our TCP port (publish sources on Kad)
    /// before anything says so: a HighID login or Kad's firewall check
    /// tell while running.
    pub reachable: bool,
    /// Take sources on LAN and loopback addresses (aMule's FilterLanIPs off).
    pub allow_lan: bool,
    /// Before asking a source again (`SourceReaskMinutes`); a queued one is
    /// asked over UDP 20 s before that.
    pub reask: Duration,
    /// Peers and servers it blocks are left alone (`ipfilter.dat`).
    pub ip_filter: Option<Arc<AddressFilter>>,
    /// Stop once every download is complete (ignored when sharing).
    pub stop_when_done: bool,
    /// Between progress lines.
    pub status_every: Duration,
    /// Accept external connections (`amulecmd`, `amulegui`).
    pub ec: Option<EcSettings>,
}

/// How a run ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub completed: usize,
    pub received: u64,
    pub uploaded: u64,
    /// The bytes of every session, this one's included (`statistics.dat`).
    pub totals: Totals,
}

pub fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Our RSA key for secure identification from a `cryptkey.dat`, made and
/// saved there if missing or unreadable, as aMule does.
pub fn load_identity(path: &Path) -> Result<Arc<Identity>, String> {
    let key = match std::fs::read(path)
        .ok()
        .and_then(|b| CryptKey::read(&b).ok())
    {
        Some(k) => k,
        None => {
            let k = CryptKey::generate(&mut rand::rngs::OsRng).map_err(|e| e.to_string())?;
            std::fs::write(path, k.write()).map_err(|e| format!("{}: {e}", path.display()))?;
            k
        }
    };
    Ok(Arc::new(Identity {
        key: key.private_key().map_err(|e| e.to_string())?,
        public: key.public_key().map_err(|e| e.to_string())?,
    }))
}

/// Open every `*.part.met` in `temp`.
pub fn existing_downloads(temp: &Path) -> Result<Vec<PartFile>, String> {
    let mut v = Vec::new();
    let entries = std::fs::read_dir(temp).map_err(|e| format!("{}: {e}", temp.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().ends_with(".part.met"))
        .collect();
    paths.sort();
    for p in paths {
        match PartFile::open(&p) {
            Ok(f) => v.push(f),
            Err(e) => warn!("{}: {e} (skipped)", p.display()),
        }
    }
    Ok(v)
}

fn log_report(t: Duration, r: &Report, names: &HashMap<Md4Hash, String>) {
    let name = |h: &Md4Hash| names.get(h).cloned().unwrap_or_else(|| h.to_string());
    let line = match r {
        Report::SourceAdded { .. }
        | Report::SourceDropped { .. }
        | Report::Queued { rank: None, .. }
        | Report::KadFirewallAck { .. }
        | Report::UdpCheckEnded { .. }
        | Report::UdpCheckRequested { .. } => return,
        Report::Queued {
            addr,
            rank: Some(n),
            ..
        } => format!("{addr}: queue rank {n}"),
        Report::DownloadStarted { file, addr } => format!("{addr}: sending {}", name(file)),
        Report::BuddyLinked {
            addr,
            serving: false,
            ..
        } => format!("Kad: {addr} is our buddy"),
        Report::BuddyLinked {
            addr,
            serving: true,
            ..
        } => format!("Kad: we are {addr}'s buddy"),
        Report::BuddyLost { addr, why, .. } => format!("Kad: buddy {addr} lost ({why})"),
        Report::PartVerified { file, part } => format!("{}: part {part} verified", name(file)),
        Report::PartCorrupt { file, part } => format!("{}: part {part} CORRUPT", name(file)),
        Report::AichRecovered { file, part, bytes } => {
            format!(
                "{}: AICH recovered {} of part {part}",
                name(file),
                human(*bytes)
            )
        }
        Report::Identified { addr, passed } => format!(
            "{addr}: secure ident {}",
            if *passed { "passed" } else { "FAILED" }
        ),
        Report::Completed { file, path } => {
            format!("{}: COMPLETE -> {}", name(file), path.display())
        }
        Report::CompletionFailed { file, corrupt } => {
            format!(
                "{}: final check failed, parts {corrupt:?} again",
                name(file)
            )
        }
        Report::FileError { file, error } => format!("{}: ERROR {error}", name(file)),
        Report::UploadStarted { user, file } => {
            format!("uploading {} to {user}", name(file))
        }
    };
    info!("[{:>5}s] {line}", t.as_secs());
}

/// Say so when whether others can reach us changed.
fn log_reach(t: Duration, was: Reachability, now: Reachability) {
    if was.reachable() != now.reachable() {
        info!("[{:>5}s] {}", t.as_secs(), now.describe());
    }
}

/// A server connection attempt under way: connect and log in.
type Attempting = Pin<Box<dyn Future<Output = Result<(ServerClient, Login), String>> + Send>>;

/// Connect to and log into `a.addr`, within [`ATTEMPT_TIMEOUT`].
fn attempt(a: Attempt, c: &ClientConfig) -> Attempting {
    let mut login = LoginInfo::new(c.user_hash, c.tcp_port, c.nick.clone());
    login.crypt_requested = a.obfuscated;
    let mut opts = ConnectOptions::new(login);
    opts.obfuscate = a.obfuscated;
    opts.session.ask_server_list = false;
    Box::pin(async move {
        match tokio::time::timeout(ATTEMPT_TIMEOUT, ServerClient::connect(a.addr, opts)).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err(format!("no login within {} s", ATTEMPT_TIMEOUT.as_secs())),
        }
    })
}

/// Start what the connector says to do next.
fn follow(next: Next, c: &ClientConfig, attempting: &mut Option<Attempting>, t: Duration) {
    match next {
        Next::Connect(a) => {
            info!(
                "[{:>5}s] server {}: connecting{}",
                t.as_secs(),
                a.addr,
                if a.obfuscated { " (obfuscated)" } else { "" }
            );
            *attempting = Some(attempt(a, c));
        }
        Next::RetryAt(_) => info!(
            "[{:>5}s] could not log into any server; trying again in {} s",
            t.as_secs(),
            RETRY_AFTER.as_secs()
        ),
        Next::Idle => {}
    }
}

/// What the EC view is made from.
struct EcInputs<'a> {
    c: &'a ClientConfig,
    server: Option<(&'a ServerClient, Option<(SocketAddr, u32)>)>,
    connecting: bool,
    our_id: u32,
    kad: Option<(
        Option<ed2k_kad::driver::Snapshot>,
        ed2k_types::UInt128,
        Option<u32>,
    )>,
    statistics: &'a Statistics,
    /// Bytes in the last second.
    rates: Totals,
    queue: Option<(
        Vec<remule_core::download_queue::FileProgress>,
        remule_core::download_queue::QueueStats,
    )>,
    shared: usize,
    now: Instant,
    download_ids: &'a mut DownloadIds,
    /// The connected server as `server.met` lists it.
    listed: Option<&'a ed2k_formats::server_met::ServerInfo>,
    /// The connected server's ECID.
    server_ecid: u32,
}

/// The client as the EC replies tell it.
fn ec_status(i: EcInputs<'_>) -> Status {
    let session = i.statistics.session();
    let totals = i.statistics.totals();
    let server = i.server.map(|(s, since)| {
        let info = s.info();
        ServerStatus {
            ecid: i.server_ecid,
            addr: match since {
                Some((SocketAddr::V4(a), _)) => Some(a),
                _ => None,
            },
            // `GetListName`: what the server calls itself, else the list's name.
            name: info
                .name
                .filter(|n| !n.is_empty())
                .or_else(|| i.listed.map(|l| l.name.clone()))
                .unwrap_or_default(),
            description: info
                .description
                .filter(|d| !d.is_empty())
                .or_else(|| i.listed.map(|l| l.description.clone()))
                .unwrap_or_default(),
            version: info.version.unwrap_or_default(),
            users: info.users,
            files: info.files,
            tcp_flags: info.tcp_flags,
        }
    });
    let ed2k_since = i.server.and_then(|(_, s)| s).map(|(_, t)| t);
    let kad = i.kad.map(|(snap, id, since)| match snap {
        Some(snap) => KadStatus {
            connected: snap.connected,
            firewalled: snap.firewalled,
            id,
            public_ip: snap.public_ip,
            users: snap.estimated_users,
            nodes: snap.contacts as u32,
            since: since.filter(|_| snap.connected),
        },
        None => KadStatus {
            id,
            ..Default::default()
        },
    });
    let (files, q) = i.queue.unwrap_or_default();
    let downloads = i.download_ids.view(&files, &i.c.temp);
    Status {
        ed2k_enabled: !i.c.servers.is_empty(),
        kad_enabled: i.c.kad.is_some(),
        server,
        connecting: i.connecting,
        ed2k_id: i.our_id,
        ed2k_since,
        kad,
        ul_speed: i.rates.sent,
        dl_speed: i.rates.received,
        ul_limit: i.c.max_upload.saturating_mul(1024),
        dl_limit: i.c.max_download.saturating_mul(1024),
        session_sent: session.sent,
        session_received: session.received,
        total_sent: totals.sent,
        total_received: totals.received,
        uptime: i.statistics.uptime(i.now).as_secs(),
        shared_files: i.shared as u32,
        connections: q.connections as u32,
        sources: q.sources as u32,
        upload_queue: 0,
        banned: 0,
        downloads,
        // Set by the caller, which counts the changes.
        applied: 0,
        temp_free: crate::disk::free_space(&i.c.temp),
        incoming_free: crate::disk::free_space(&i.c.incoming),
    }
}

/// ECIDs for the servers in the list (`CECID`), kept while each is listed.
#[derive(Debug, Default)]
struct ServerIds(HashMap<SocketAddrV4, u32>);

impl ServerIds {
    fn id(&mut self, a: SocketAddrV4) -> u32 {
        *self.0.entry(a).or_insert_with(crate::ec_shared::next_ecid)
    }

    /// Forget the servers no longer listed.
    fn keep(&mut self, list: &[ed2k_formats::server_met::ServerInfo]) {
        self.0.retain(|a, _| {
            list.iter()
                .any(|s| s.ip == Some(*a.ip()) && s.port == a.port())
        });
    }
}

/// What a link added: a new download (or none when it is already being
/// downloaded), and its sources.
struct Added {
    hash: Md4Hash,
    size: u64,
    file: Option<PartFile>,
    sources: Vec<Endpoint>,
    origin: Origin,
}

/// What a new download changes in the client loop.
struct Starting<'a> {
    names: &'a mut HashMap<Md4Hash, String>,
    paused: &'a mut HashSet<Md4Hash>,
    wanted: &'a mut Vec<(Md4Hash, u64)>,
    kad_searches: &'a mut HashMap<u32, Md4Hash>,
    cmd: &'a mpsc::UnboundedSender<Command>,
    server: Option<&'a ServerClient>,
    /// Kad, when connected.
    kad: Option<&'a ed2k_kad::driver::KadHandle>,
}

/// Start what [`new_download`] made: the file to the downloader, its
/// sources, and sources asked for it at once from the server and Kad.
async fn take_download(add: Added, s: Starting<'_>) {
    let (hash, size) = (add.hash, add.size);
    if let Some(f) = add.file {
        s.names.insert(hash, f.name().to_owned());
        if f.is_paused() {
            s.paused.insert(hash);
        }
        let _ = s.cmd.send(Command::AddFile(Box::new(f)));
        s.wanted.push((hash, size));
    }
    if !add.sources.is_empty() {
        let _ = s.cmd.send(Command::AddSources {
            file: hash,
            sources: add.sources,
            origin: add.origin,
        });
    }
    if let Some(server) = s.server {
        let _ = server.get_sources(hash, size).await;
    }
    if let Some(k) = s.kad {
        match k.search_sources(hash, size).await {
            Ok(id) => {
                s.kad_searches.insert(id, hash);
            }
            Err(e) => warn!("Kad source search: {e}"),
        }
    }
}

/// `CDownloadQueue::AddLink` for an ed2k file link: a new download in the
/// temp directory, or more sources for one already there. `None` (with the
/// reason logged as aMule logs it) when the link is not taken.
fn add_link(
    link: &str,
    c: &ClientConfig,
    wanted: &[(Md4Hash, u64)],
    shares: Option<&Arc<Mutex<SharedFiles>>>,
) -> Option<Added> {
    // `AddLink`: a magnet with an ed2k hash is taken as its ed2k link.
    let converted;
    let link = if remule_core::link::is_magnet(link) {
        match remule_core::link::magnet_to_ed2k(link) {
            Some(l) => {
                converted = l;
                converted.as_str()
            }
            None => {
                warn!("Cannot convert magnet link to eD2k: {link}");
                return None;
            }
        }
    } else {
        link
    };
    if !link
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("ed2k://"))
    {
        warn!("Unknown protocol of link: {link}");
        return None;
    }
    let mut uri = link.to_owned();
    if !uri.ends_with('/') {
        uri.push('/');
    }
    let l = match remule_core::link::parse(&uri) {
        Ok(l) => l,
        Err(e) => {
            warn!("Invalid eD2k link! ERROR: {e}");
            return None;
        }
    };
    let sources = l.sources.iter().map(|a| Endpoint::new(*a)).collect();
    // A link's sources are taken for a download already there.
    new_download(
        c,
        wanted,
        shares,
        NewDownload {
            name: &l.name,
            hash: l.hash,
            size: l.size,
            aich: l.aich,
            sources,
            origin: Origin::Manual,
            sources_if_downloading: true,
        },
    )
}

/// A download to start, from a link or a search result.
struct NewDownload<'a> {
    name: &'a str,
    hash: Md4Hash,
    size: u64,
    aich: Option<ed2k_types::AichHash>,
    sources: Vec<Endpoint>,
    origin: Origin,
    /// Hand the sources on when the file is already being downloaded
    /// (`AddED2KLink` does, `AddSearchToDownload` does not).
    sources_if_downloading: bool,
}

/// `IsFileExisting`, then a new download in the temp directory. `None`
/// (logged as aMule logs it) when nothing is to be done.
fn new_download(
    c: &ClientConfig,
    wanted: &[(Md4Hash, u64)],
    shares: Option<&Arc<Mutex<SharedFiles>>>,
    d: NewDownload<'_>,
) -> Option<Added> {
    if wanted.iter().any(|(h, _)| *h == d.hash) {
        warn!("You are already trying to download the file '{}'", d.name);
        return d.sources_if_downloading.then_some(Added {
            hash: d.hash,
            size: d.size,
            file: None,
            sources: d.sources,
            origin: d.origin,
        });
    }
    if let Some(sh) = shares {
        let sh = sh.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((f, _)) = sh.files().into_iter().find(|(f, _)| f.hash == d.hash) {
            if d.name != f.name {
                warn!(
                    "You already have the file '{}' (requested as '{}')",
                    f.name, d.name
                );
            } else {
                warn!("You already have the file '{}'", f.name);
            }
            return None;
        }
    }
    let mut f = match PartFile::create(&c.temp, d.name, d.hash, d.size) {
        Ok(f) => f,
        Err(e) => {
            warn!("{}: {e}", d.name);
            return None;
        }
    };
    if let Some(root) = d.aich {
        f.set_aich_root(root);
    }
    info!(
        "new download {} ({}, {})",
        d.name,
        human(d.size),
        f.met_path().display()
    );
    Some(Added {
        hash: d.hash,
        size: d.size,
        file: Some(f),
        sources: d.sources,
        origin: d.origin,
    })
}

/// What the status pings want done: sent, or a dead server dropped.
async fn stats_out(
    u: &crate::server_udp::ServerUdp,
    o: crate::server_stats::Out,
    list: &mut ServerList,
    connector: &mut Connector,
    public_ip: Option<std::net::Ipv4Addr>,
) {
    use crate::server_stats::Out;
    match o {
        Out::Raw { to, bytes } => u.send_raw(to, &bytes).await,
        Out::Packet { server, packet } => u.send(&packet, &server, public_ip).await,
        Out::Remove(a) => {
            info!("Removed dead server {a}");
            list.remove(a);
            connector.remove(SocketAddr::V4(a));
        }
    }
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

/// Scan the shared directories (and incoming), hashing what known.met does
/// not know, as aMule does at start-up.
fn share_files(c: &ClientConfig) -> Result<Arc<Mutex<SharedFiles>>, String> {
    let mut s = SharedFiles::load(&c.config).map_err(|e| format!("{}: {e}", c.config.display()))?;
    let mut dirs = c.share.clone();
    dirs.push(c.incoming.clone());
    let r = s.scan(
        &ScanOptions {
            dirs,
            reserved: vec![c.temp.clone(), c.config.clone()],
            hidden: false,
        },
        unix_now(),
    );
    for (d, why) in &r.skipped {
        warn!("{}: not shared ({why})", d.display());
    }
    for p in &r.to_hash {
        let date = match std::fs::metadata(p) {
            Ok(m) => mtime(&m),
            Err(_) => continue,
        };
        match SharedFiles::hash(p) {
            Ok(h) => {
                s.add_hashed(p, &h, date, unix_now());
                info!("hashed {}", p.display());
            }
            Err(e) => warn!("{}: {e}", p.display()),
        }
    }
    s.save()
        .map_err(|e| format!("{}: {e}", c.config.display()))?;
    info!("sharing {} files", s.shared_count());
    Ok(Arc::new(Mutex::new(s)))
}

/// Run with `files` to download (and these sources for them) until
/// `shutdown` completes, or every download is done when `stop_when_done`
/// and nothing is shared. Everything is saved before returning.
pub async fn run(
    c: ClientConfig,
    files: Vec<PartFile>,
    link_sources: Vec<(Md4Hash, SocketAddrV4)>,
    shutdown: impl Future<Output = ()>,
) -> Result<Summary, String> {
    for d in [&c.temp, &c.incoming, &c.config] {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    // What we share: the shared directories and the incoming one.
    let shares = if c.upload {
        Some(share_files(&c)?)
    } else {
        None
    };
    let mut wanted: Vec<(Md4Hash, u64)> = files.iter().map(|f| (f.hash(), f.size())).collect();
    // Paused or stopped downloads: no sources are asked for them.
    let mut paused: HashSet<Md4Hash> = files
        .iter()
        .filter(|f| f.is_paused())
        .map(|f| f.hash())
        .collect();
    let mut names: HashMap<Md4Hash, String> = files
        .iter()
        .map(|f| (f.hash(), f.name().to_owned()))
        .collect();
    if let Some(s) = &shares {
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        names.extend(s.files().into_iter().map(|(f, _)| (f.hash, f.name.clone())));
    }

    // The server connection: our ID comes from its login, and changes with
    // each new one.
    let mut server: Option<ServerClient> = None;
    let mut our_id = 0u32;
    // Servers the IP filter blocks are not tried (`CServerList::AddServer`).
    let servers: Vec<SocketAddr> = c
        .servers
        .iter()
        .copied()
        .filter(|a| {
            let blocked = match (a, &c.ip_filter) {
                (SocketAddr::V4(v4), Some(f)) => f.blocks_server(*v4.ip()),
                _ => false,
            };
            if blocked {
                info!("server {a}: blocked by the IP filter");
            }
            !blocked
        })
        .collect();
    // What is known of each, for the EC server list.
    let mut server_list = ServerList::load(&c.config, &servers);
    let mut connector = Connector::new(servers, c.obfuscate_server, c.reconnect);
    let mut attempting: Option<Attempting> = None;
    // Whether others can connect to us: found out as we run.
    let mut reach = Reachability {
        assumed: c.reachable,
        ..Default::default()
    };
    // Connections answering other Kad nodes' firewall checks.
    let mut connect_backs: JoinSet<()> = JoinSet::new();

    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", c.tcp_port)).await {
        Ok(l) => Some(l),
        Err(e) => {
            warn!("TCP port {}: {e} (no callbacks)", c.tcp_port);
            None
        }
    };
    let listening = listener.is_some();

    // The client UDP port, Kad's too (`CClientUDPSocket`): reasks come and
    // go there.
    let (ed2k_udp_tx, mut ed2k_udp_rx) = mpsc::unbounded_channel();
    let udp_port = if c.udp_port == 0 {
        None
    } else {
        match UdpPort::bind(c.udp_port, c.user_hash, ed2k_udp_tx).await {
            Ok(p) => Some(p),
            Err(e) => {
                warn!("UDP port {}: {e} (no UDP reasks, no Kad)", c.udp_port);
                None
            }
        }
    };
    let (udp_out_tx, mut udp_out_rx) = mpsc::unbounded_channel::<UdpOut>();
    // The server UDP port (TCP + 3): global searches over the other servers.
    let (server_udp_tx, mut server_udp_rx) = mpsc::unbounded_channel();
    let server_udp =
        match crate::server_udp::ServerUdp::bind(c.tcp_port.saturating_add(3), server_udp_tx).await
        {
            Ok(s) => Some(s),
            Err(e) => {
                warn!("Server UDP: {e} (global searches ask the connected server only)");
                None
            }
        };
    // The servers' status pings.
    let mut server_stats = crate::server_stats::ServerStats::default();
    // Sources asked of the other servers over UDP, and the downloads seen
    // wanting sources (the new ones go first).
    let mut global_sources = crate::global_sources::GlobalSources::default();
    let mut seen_wanted: HashSet<Md4Hash> = HashSet::new();
    // The global search timer's resolution.
    let mut sweep_tick = tokio::time::interval(Duration::from_millis(250));
    sweep_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Our public IP as the server tells it: obfuscated datagrams are keyed with it.
    let mut public_ip: Option<std::net::Ipv4Addr> = None;

    let mut ours = Hello::amule(c.user_hash, our_id, c.tcp_port, c.nick.clone());
    ours.udp_port = udp_port.as_ref().map_or(0, |p| p.port);
    ours.misc2 = Some(MiscOptions2::amule(
        0,
        CryptSettings {
            supported: true,
            requested: true,
            required: false,
        },
    ));
    let mut qc = QueueConfig::new(ours, c.incoming.clone());
    qc.max_connections = c.max_connections;
    qc.identity = Some(c.identity.clone());
    qc.filter_lan = !c.allow_lan;
    qc.reask = c.reask;
    qc.ip_filter = c.ip_filter.clone();
    let ours_for_upload = qc.ours.clone();
    let ours_for_checks = qc.ours.clone();
    let queue = DownloadQueue::new(qc);
    let mut dc = DownloaderConfig::new(Arc::new(Bandwidth::new(c.max_upload, c.max_download)));
    dc.stop_when_done = c.stop_when_done;
    dc.udp = udp_port.as_ref().map(|_| udp_out_tx);
    let (cmd, cmd_rx) = mpsc::unbounded_channel();
    let (rep_tx, mut reports) = mpsc::unbounded_channel();
    let uploader = match &shares {
        Some(s) => {
            let credits = Credits::load(&c.config, unix_now())
                .map_err(|e| format!("{}: {e}", c.config.display()))?;
            Some(Uploader::new(
                ours_for_upload,
                Some(c.identity.clone()),
                s.clone(),
                UploadQueue::new(UploadConfig {
                    max_upload_kbps: c.max_upload,
                    ..Default::default()
                }),
                Some(credits),
            ))
        }
        None => None,
    };
    let mut dl = tokio::spawn(downloader::run_with(
        queue, uploader, dc, listener, cmd_rx, rep_tx,
    ));
    let mut publisher = Publisher::new();
    if let Some(s) = &shares {
        publisher.update_keywords(&s.lock().unwrap_or_else(|e| e.into_inner()));
    }
    let mut next_offer = Instant::now();
    for f in files {
        let _ = cmd.send(Command::AddFile(Box::new(f)));
    }
    for (file, addr) in link_sources {
        let _ = cmd.send(Command::AddSources {
            file,
            sources: vec![Endpoint::new(addr)],
            origin: Origin::Manual,
        });
    }

    let mut kad_node = match &c.kad {
        Some(k) => Some(
            start_kad(
                udp_port.as_ref(),
                &KadStart {
                    dir: k.dir.clone(),
                    nodes: k.nodes.clone(),
                    bootstrap: k.bootstrap.clone(),
                    udp_port: c.udp_port,
                    tcp_port: c.tcp_port,
                    user_hash: c.user_hash,
                    reachable: c.reachable,
                    listening,
                    allow_lan: c.allow_lan,
                    trace_wire: kad::trace_from_env(),
                    ip_filter: c.ip_filter.clone(),
                },
            )
            .await?,
        ),
        None => None,
    };
    // Buddy callbacks are checked against our Kad ID.
    if let Some(k) = &kad_node {
        let _ = cmd.send(Command::SetKadId(Some(k.prefs.kad_id)));
    }
    // Our Kad buddy, once up (we are firewalled): its IP and Kad port.
    let mut own_buddy: Option<SocketAddrV4> = None;
    // What the downloader was last told of whether others reach us.
    let mut told_reachable: Option<bool> = None;

    // External connections: a view of the client, refreshed every second,
    // and what they ask of it.
    let mut ec_view: Option<watch::Sender<Status>> = None;
    // What the statistics graphs show, a record a second.
    let history = Arc::new(Mutex::new(crate::graphs::History::new()));
    // Changes to the downloads applied, for the views EC answers from.
    let download_changes = Arc::new(ec::DownloadChanges::new(0));
    let mut ec_control: Option<mpsc::UnboundedReceiver<Control>> = None;
    if let Some(e) = &c.ec {
        if let Some(l) = ec::listen(e).await {
            let (tx, rx) = watch::channel(Status::default());
            let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
            let identity = remule_ec::server::Identity {
                version: concat!("remuled ", env!("CARGO_PKG_VERSION")).into(),
                session_id: rand::random(),
            };
            tokio::spawn(ec::serve(
                l,
                e.clone(),
                identity,
                rx,
                ctl_tx,
                history.clone(),
                download_changes.clone(),
            ));
            ec_view = Some(tx);
            ec_control = Some(ctl_rx);
        }
    }
    // For the EC view: the server logged into and since when, when Kad
    // connected, and the traffic a second ago.
    let mut server_since: Option<(SocketAddr, u32)> = None;
    let mut kad_since: Option<u32> = None;
    let mut last_traffic = Totals::default();
    let mut download_ids = DownloadIds::default();
    // The search external connections run.
    let mut searches = ec_search::Searches::default();
    let mut shared_state = crate::ec_shared::SharedState::default();
    shared_state.load_comments(&c.config);
    let mut friends = crate::friends::FriendList::load(&c.config);
    // The servers' ECIDs, kept while they are listed.
    let mut server_ids = ServerIds::default();
    // What the statistics tree shows that is not kept elsewhere.
    let mut tree_track = crate::ec_stats::TreeTrack::default();
    let reload_dirs = crate::ec_shared::ReloadDirs {
        dirs: c.share.iter().chain([&c.incoming]).cloned().collect(),
        reserved: vec![c.temp.clone(), c.config.clone()],
        incoming: Some((c.config.clone(), c.incoming.clone())),
    };

    let start = Instant::now();
    // The totals of earlier sessions, which this one adds to.
    let (before, note) = crate::stats::load(&c.config);
    if let Some(n) = note {
        warn!("{n}");
    }
    let mut statistics = Statistics::new(before, start);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut next_status = Duration::ZERO;
    let mut next_server_ask = Instant::now();
    let mut kad_connected: Option<Instant> = None;
    let mut next_kad_ask: Option<Instant> = None;
    let mut kad_searches: HashMap<u32, Md4Hash> = HashMap::new();
    let mut done = 0usize;
    let mut last_received = 0u64;
    let mut last_status = Instant::now();
    tokio::pin!(shutdown);
    let mut finished = None;
    if c.autoconnect {
        let next = connector.start(Instant::now());
        follow(next, &c, &mut attempting, Duration::ZERO);
    }

    loop {
        tokio::select! {
            r = async { match &mut attempting { Some(f) => f.await, None => std::future::pending().await } } => {
                attempting = None;
                let now = Instant::now();
                let t = start.elapsed();
                let addr = connector.connecting().map(|a| a.addr.to_string()).unwrap_or_default();
                match r {
                    Ok((s, li)) => {
                        connector.logged_in();
                        // ConnectionEstablished: its failures are forgotten.
                        if let Some(SocketAddr::V4(a)) = connector.connected().map(|c| c.addr) {
                            if let Some(e) = server_list.entries_mut().iter_mut().find(|e| e.ip == Some(*a.ip()) && e.port == a.port()) {
                                e.failed = 0;
                            }
                        }
                        info!(
                            "[{:>5}s] server {addr}: logged in, {} {}",
                            t.as_secs(),
                            if li.low_id { "LowID" } else { "HighID" },
                            li.id
                        );
                        our_id = li.id;
                        tree_track.logins += 1;
                        server_since = connector.connected().map(|a| (a.addr, unix_now()));
                        // `GetPublicIP`: a HighID is our IP.
                        let before = public_ip;
                        public_ip = li.public_ip.or_else(|| {
                            (!li.low_id).then(|| ed2k_server::packets::id_to_ip(li.id))
                        });
                        // SetPublicIP: keys given for another IP are recovered.
                        if let Some(ip) = public_ip.filter(|ip| before != Some(*ip)) {
                            server_stats.public_ip_changed(ip, u64::from(unix_now()), &mut server_list);
                        }
                        let _ = cmd.send(Command::SetOurId { id: li.id, public_ip: li.public_ip });
                        let was = reach;
                        reach.high_id = !li.low_id;
                        log_reach(t, was, reach);
                        // A new server: offer everything, and ask it for sources.
                        publisher.server_connected();
                        next_offer = now;
                        next_server_ask = now;
                        server = Some(s);
                    }
                    Err(e) => {
                        warn!("[{:>5}s] server {addr}: {e}", t.as_secs());
                        let next = connector.failed(now);
                        follow(next, &c, &mut attempting, t);
                    }
                }
            }
            // Client UDP out (obfuscated when the peer wants it and our IP
            // is known), and in (to the downloader).
            d = async { match &udp_port { Some(_) => udp_out_rx.recv().await, None => std::future::pending().await } } => {
                if let (Some(d), Some(p)) = (d, &udp_port) {
                    p.send_ed2k(&d, public_ip).await;
                }
            }
            // A global search asks one more server, now and then.
            _ = sweep_tick.tick() => {
                let connected = match server_since {
                    Some((SocketAddr::V4(a), _)) if server.is_some() => Some(a),
                    _ => None,
                };
                if let Some(ask) = searches.sweep(Instant::now(), server_list.entries(), connected) {
                    if let Some(u) = &server_udp {
                        u.send(&ask.packet, &ask.server, public_ip).await;
                    }
                }
            }
            // Server UDP in: status and description answers, global search
            // answers.
            d = server_udp_rx.recv() => {
                if let Some((from, datagram)) = d {
                    if let Some(u) = &server_udp {
                        if u.trace() {
                            let plain = crate::server_udp::decode(&datagram, from, server_list.entries(), public_ip);
                            eprintln!(
                                "server udp <- {from} {:#04x} {}",
                                plain.get(1).copied().unwrap_or(0),
                                if plain != datagram { "obfuscated" } else { "plain" }
                            );
                        }
                    }
                    let inc = server_stats.datagram(
                        from, &datagram, Instant::now(), u64::from(unix_now()), &mut server_list, public_ip,
                        &mut rand::thread_rng(),
                    );
                    if let Some(results) = inc.results {
                        searches.udp_results(*from.ip(), results);
                    }
                    // AddSources(SF_REMOTE_SERVER): LowIDs cannot be called
                    // back through a server we are not logged into.
                    for (hash, sources) in inc.sources.unwrap_or_default() {
                        if !wanted.iter().any(|(h, _)| *h == hash) {
                            debug!("Sources received for unknown file");
                            continue;
                        }
                        let eps: Vec<Endpoint> = sources.iter().filter_map(Endpoint::from_server).collect();
                        info!("[{:>5}s] server {from} (UDP): {} sources ({} reachable) for {}",
                            start.elapsed().as_secs(), sources.len(), eps.len(),
                            names.get(&hash).map(String::as_str).unwrap_or("?"));
                        if !eps.is_empty() {
                            let _ = cmd.send(Command::AddSources { file: hash, sources: eps, origin: Origin::Server });
                        }
                    }
                    if let Some(u) = &server_udp {
                        for o in inc.out {
                            stats_out(u, o, &mut server_list, &mut connector, public_ip).await;
                        }
                    }
                }
            }
            d = async { match &udp_port { Some(_) => ed2k_udp_rx.recv().await, None => std::future::pending().await } } => {
                if let Some(d) = d {
                    let _ = cmd.send(Command::Udp { from: d.from, datagram: d.payload });
                }
            }
            r = reports.recv() => {
                let Some(r) = r else { continue };
                if let (Report::KadFirewallAck { ip }, Some(k)) = (&r, &kad_node) {
                    k.handle.firewall_ack(*ip).await;
                }
                if matches!(r, Report::Completed { .. }) {
                    done += 1;
                }
                // The UDP firewall test's TCP half: its end, and others'
                // requests, are Kad's to act on.
                match (&r, &kad_node) {
                    (Report::UdpCheckEnded { ip, cancelled }, Some(k)) => {
                        k.handle.udp_check_ended(*ip, *cancelled).await;
                    }
                    (Report::UdpCheckRequested { ip, internal, external, key, known }, Some(k)) => {
                        k.handle.answer_udp_check(*ip, *internal, *external, *key, *known).await;
                    }
                    _ => {}
                }
                // The buddy links: ours stops the buddy search, one we serve
                // stops Kad's offers.
                match (&r, &kad_node) {
                    (Report::BuddyLinked { serving: false, addr, kad_port }, _) => {
                        own_buddy = Some(SocketAddrV4::new(*addr.ip(), *kad_port));
                    }
                    (Report::BuddyLost { serving: false, .. }, _) => own_buddy = None,
                    (Report::BuddyLinked { serving: true, .. }, Some(k)) => k.handle.set_serving_buddy(true).await,
                    (Report::BuddyLost { serving: true, .. }, Some(k)) => k.handle.set_serving_buddy(false).await,
                    _ => {}
                }
                log_report(start.elapsed(), &r, &names);
            }
            ev = async { match &mut server { Some(s) => s.next_event().await, None => std::future::pending().await } } => {
                match ev {
                    Some(ServerEvent::SearchResults { results, .. }) => searches.server_results(results),
                    Some(ServerEvent::Message(m)) => crate::applog::global().server_message(&m),
                    Some(ServerEvent::FoundSources { hash, sources }) => {
                        let eps: Vec<Endpoint> = sources.iter().filter_map(Endpoint::from_server).collect();
                        info!("[{:>5}s] server: {} sources ({} reachable) for {}",
                            start.elapsed().as_secs(), sources.len(), eps.len(),
                            names.get(&hash).map(String::as_str).unwrap_or("?"));
                        let _ = cmd.send(Command::AddSources { file: hash, sources: eps, origin: Origin::Server });
                    }
                    Some(ServerEvent::Closed(_)) | None => {
                        let t = start.elapsed();
                        match &ev {
                            Some(ServerEvent::Closed(why)) => warn!("[{:>5}s] server connection lost: {why:?}", t.as_secs()),
                            _ => warn!("[{:>5}s] server connection lost", t.as_secs()),
                        }
                        server = None;
                        server_since = None;
                        our_id = 0;
                        public_ip = None;
                        let _ = cmd.send(Command::SetOurId { id: 0, public_ip: None });
                        let was = reach;
                        reach.high_id = false;
                        log_reach(t, was, reach);
                        let next = connector.lost(Instant::now());
                        follow(next, &c, &mut attempting, t);
                    }
                    _ => {}
                }
            }
            ev = async { match &mut kad_node { Some(k) => k.handle.events.recv().await, None => std::future::pending().await } } => {
                match ev {
                    Some(KadEvent::Connected) => {
                        info!("[{:>5}s] Kad connected", start.elapsed().as_secs());
                        kad_connected = Some(Instant::now());
                        kad_since = Some(unix_now());
                        let warmup = c.kad.as_ref().map_or(KAD_WARMUP, |k| k.warmup);
                        next_kad_ask = Some(Instant::now() + Duration::from_secs(warmup));
                    }
                    Some(KadEvent::Found { search, found: Found::Source(s) }) => {
                        if let (Some(&file), Some(ep)) = (kad_searches.get(&search), Endpoint::from_kad(&s)) {
                            let _ = cmd.send(Command::AddSources { file, sources: vec![ep], origin: Origin::Kad });
                        }
                    }
                    Some(KadEvent::Found { search, found: Found::Keyword(k) }) => searches.kad_result(search, *k),
                    Some(KadEvent::SearchDone { search, answers, .. }) => {
                        searches.kad_done(search);
                        if let Some(file) = kad_searches.remove(&search) {
                            info!("[{:>5}s] Kad: {answers} source answers for {}", start.elapsed().as_secs(),
                                names.get(&file).map(String::as_str).unwrap_or("?"));
                        }
                    }
                    Some(KadEvent::Firewalled(f)) => {
                        let was = reach;
                        reach.kad_open = !f;
                        info!("[{:>5}s] Kad: {}", start.elapsed().as_secs(),
                            if f { "firewalled" } else { "nodes reach our TCP port" });
                        log_reach(start.elapsed(), was, reach);
                    }
                    // Another node's firewall check: connect back, unless the
                    // IP filter blocks it or enough are running already.
                    Some(KadEvent::FirewallCheck { tcp, user_hash, connect_options }) => {
                        while connect_backs.try_join_next().is_some() {}
                        let blocked = c.ip_filter.as_ref().is_some_and(|f| f.blocks_client(*tcp.ip()));
                        if !blocked && connect_backs.len() < MAX_CONNECT_BACKS {
                            let mut hello = ours_for_checks.clone();
                            hello.id = our_id;
                            connect_backs.spawn(async move {
                                if let Err(e) = firewall::connect_back(tcp, user_hash, connect_options, hello).await {
                                    debug!("Kad firewall check for {tcp}: {e}");
                                }
                            });
                        }
                    }
                    Some(KadEvent::Wire(w)) => eprintln!("{}", kad::wire_line(&w)),
                    // Buddies: the TCP side is the downloader's.
                    Some(KadEvent::BuddyOffer { tcp, kad_port, user_hash, connect_options }) => {
                        info!("[{:>5}s] Kad: buddy offer from {tcp}", start.elapsed().as_secs());
                        let _ = cmd.send(Command::BuddyOffer { tcp, kad_port, user_hash, connect_options });
                    }
                    Some(KadEvent::BuddyRequest { buddy_id, user_hash, tcp }) => {
                        info!("[{:>5}s] Kad: buddy request from {tcp}, offered", start.elapsed().as_secs());
                        let _ = cmd.send(Command::BuddyRequest { buddy_id, user_hash, tcp });
                    }
                    // The UDP firewall test: ask this node over TCP.
                    Some(KadEvent::UdpFirewallCheck { tcp }) => {
                        if let Some(k) = &kad_node {
                            if let Some((internal, external, key)) = k.handle.udp_check_request(*tcp.ip()).await {
                                let request = CheckRequest { internal, external, key };
                                let _ = cmd.send(Command::UdpFirewallCheck { tcp, request });
                            }
                        }
                    }
                    Some(KadEvent::UdpFirewalled(f)) => {
                        info!("[{:>5}s] Kad: UDP {}", start.elapsed().as_secs(),
                            if f { "firewalled" } else { "open: others reach our UDP port" });
                    }
                    Some(KadEvent::CallbackRequest { buddy_id, file, from }) => {
                        debug!("[{:>5}s] Kad: callback request from {from}", start.elapsed().as_secs());
                        let _ = cmd.send(Command::BuddyCallback { buddy_id, file, from });
                    }
                    None => kad_node = None,
                }
            }
            r = &mut dl => {
                finished = Some(r.map_err(|e| e.to_string())?);
                break;
            }
            _ = &mut shutdown => break,
            ctl = async { match &mut ec_control { Some(r) => r.recv().await, None => std::future::pending().await } } => {
                match ctl {
                    Some(Control::Shutdown) => {
                        info!("[{:>5}s] shutdown requested over an external connection: saving", start.elapsed().as_secs());
                        break;
                    }
                    Some(Control::AddLink { link, category: _, reply }) => {
                        let added = add_link(&link, &c, &wanted, shares.as_ref());
                        let taken = added.is_some();
                        if let Some(add) = added {
                            take_download(add, Starting {
                                names: &mut names, paused: &mut paused, wanted: &mut wanted,
                                kad_searches: &mut kad_searches, cmd: &cmd, server: server.as_ref(),
                                kad: kad_node.as_ref().filter(|_| kad_connected.is_some()).map(|k| &k.handle),
                            }).await;
                        }
                        download_changes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = reply.send(taken);
                        // The EC view shows it at once.
                        tick.reset_immediately();
                    }
                    Some(Control::File { file, op, reply }) => {
                        let (tx, rx) = oneshot::channel();
                        let r = match cmd.send(Command::File { file, op, reply: tx }) {
                            Ok(()) => rx.await.unwrap_or_else(|_| Err("Already shutting down.".into())),
                            Err(_) => Err("Already shutting down.".into()),
                        };
                        if r.is_ok() {
                            let name = names.get(&file).cloned().unwrap_or_else(|| file.to_string());
                            let t = start.elapsed().as_secs();
                            match op {
                                FileOp::Pause => { paused.insert(file); info!("[{t:>5}s] {name}: paused"); }
                                FileOp::Stop => { paused.insert(file); info!("[{t:>5}s] {name}: stopped"); }
                                FileOp::Resume => { paused.remove(&file); info!("[{t:>5}s] {name}: resumed"); }
                                FileOp::Delete => {
                                    paused.remove(&file);
                                    wanted.retain(|(h, _)| *h != file);
                                    info!("[{t:>5}s] {name}: cancelled");
                                }
                                FileOp::Priority { .. } | FileOp::Category(_) => {}
                            }
                        }
                        download_changes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = reply.send(r);
                        tick.reset_immediately();
                    }
                    Some(Control::Search { req, ctx, reply }) => {
                        let net = ec_search::Net { server: server.as_ref(), kad: kad_node.as_ref().map(|k| &k.handle) };
                        let status = |h: &Md4Hash| {
                            if wanted.iter().any(|(w, _)| w == h) {
                                ec_search::download_status::QUEUED
                            } else if shares.as_ref().is_some_and(|s| s.lock().unwrap_or_else(|e| e.into_inner()).files().iter().any(|(f, _)| f.hash == *h)) {
                                ec_search::download_status::DOWNLOADED
                            } else {
                                ec_search::download_status::NEW
                            }
                        };
                        let (packet, todo, started_id) = ec_search::serve(&req, &mut searches, ctx, net, &status).await;
                        let started = !todo.is_empty();
                        for d in todo {
                            let add = new_download(&c, &wanted, shares.as_ref(), NewDownload {
                                name: &d.name, hash: d.hash, size: d.size, aich: None,
                                sources: d.sources.into_iter().map(Endpoint::new).collect(),
                                origin: Origin::Server, sources_if_downloading: false,
                            });
                            if let Some(add) = add {
                                take_download(add, Starting {
                                    names: &mut names, paused: &mut paused, wanted: &mut wanted,
                                    kad_searches: &mut kad_searches, cmd: &cmd, server: server.as_ref(),
                                    kad: kad_node.as_ref().filter(|_| kad_connected.is_some()).map(|k| &k.handle),
                                }).await;
                            }
                        }
                        download_changes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = reply.send((packet, started_id));
                        if started {
                            tick.reset_immediately();
                        }
                    }
                    Some(Control::Servers { request, reply }) => {
                        let t = start.elapsed();
                        let live = server.as_ref().map(|s| s.info());
                        let (packet, effects) = crate::ec_servers::handle(&request, &mut crate::ec_servers::Ctx {
                            list: &mut server_list,
                            connector: &mut connector,
                            ed2k: c.ec.as_ref().is_some_and(|e| e.ed2k),
                            kad: c.ec.as_ref().is_some_and(|e| e.kad),
                            kad_running: kad_node.is_some(),
                            kad_connected: kad_node.is_some() && kad_connected.is_some(),
                            live: live.as_ref(),
                            ip_filter: c.ip_filter.as_deref(),
                            filter_lan: !c.allow_lan,
                            now: Instant::now(),
                        });
                        let _ = reply.send(packet);
                        for e in effects {
                            match e {
                                Effect::CancelAttempt => attempting = None,
                                Effect::Disconnect => {
                                    info!("[{:>5}s] disconnected from the server", t.as_secs());
                                    server = None;
                                    server_since = None;
                                    our_id = 0;
                                    let _ = cmd.send(Command::SetOurId { id: 0, public_ip: None });
                                    let was = reach;
                                    reach.high_id = false;
                                    log_reach(t, was, reach);
                                }
                                Effect::Follow(next) => follow(next, &c, &mut attempting, t),
                                Effect::StopKad => {
                                    if let Some(k) = kad_node.take() {
                                        if let Err(e) = k.save().await {
                                            warn!("Kad: {e}");
                                        }
                                        info!("[{:>5}s] Kad stopped", t.as_secs());
                                    }
                                    kad_connected = None;
                                    kad_since = None;
                                    next_kad_ask = None;
                                    kad_searches.clear();
                                    let was = reach;
                                    reach.kad_open = false;
                                    log_reach(t, was, reach);
                                }
                                Effect::StartKad => {
                                    let k = c.kad.clone().unwrap_or_else(|| KadSettings { dir: c.config.clone(), nodes: None, bootstrap: Vec::new(), warmup: KAD_WARMUP });
                                    // The stopped node's socket may still be closing.
                                    let mut started = Err(String::new());
                                    for _ in 0..20 {
                                        started = start_kad(udp_port.as_ref(), &KadStart {
                                            dir: k.dir.clone(),
                                            nodes: k.nodes.clone(),
                                            bootstrap: Vec::new(),
                                            udp_port: c.udp_port,
                                            tcp_port: c.tcp_port,
                                            user_hash: c.user_hash,
                                            reachable: c.reachable,
                                            listening,
                                            allow_lan: c.allow_lan,
                                            trace_wire: kad::trace_from_env(),
                                            ip_filter: c.ip_filter.clone(),
                                        }).await;
                                        if started.is_ok() {
                                            break;
                                        }
                                        tokio::time::sleep(Duration::from_millis(50)).await;
                                    }
                                    match started {
                                        Ok(n) => {
                                            info!("[{:>5}s] Kad started", t.as_secs());
                                            let _ = cmd.send(Command::SetKadId(Some(n.prefs.kad_id)));
                                            kad_node = Some(n);
                                        }
                                        Err(e) => warn!("Kad: {e}"),
                                    }
                                }
                            }
                        }
                        tick.reset_immediately();
                    }
                    Some(Control::ClientHistory(reply)) => {
                        let (tx, rx) = oneshot::channel();
                        if cmd.send(Command::CreditHistory(tx)).is_ok() {
                            tokio::spawn(async move {
                                let _ = reply.send(rx.await.unwrap_or_default());
                            });
                        }
                    }
                    Some(Control::Friend { req, reply }) => {
                        let _ = reply.send(friends.answer(&req));
                    }
                    Some(Control::CategoryRemoved(cat, done)) => {
                        let _ = cmd.send(Command::RemoveCategory(cat));
                        download_changes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let _ = done.send(());
                        tick.reset_immediately();
                    }
                    Some(Control::IpFilterReload) => {
                        if let Some(f) = c.ip_filter.clone() {
                            let dir = c.config.clone();
                            tokio::task::spawn_blocking(move || crate::config::reload_ip_filter(&dir, &f));
                        }
                    }
                    Some(Control::IpFilterUpdate(url)) => {
                        if let Some(f) = c.ip_filter.clone() {
                            tokio::spawn(update_ip_filter(c.config.clone(), url, f));
                        }
                    }
                    Some(Control::Shared(req)) => {
                        shared_state.handle(req, shares.as_ref(), &reload_dirs, &c.config);
                    }
                    Some(Control::StatsTree(reply)) => {
                        let now_i = Instant::now();
                        let session = statistics.session();
                        let totals = statistics.totals();
                        let view = ec_view.as_ref().map(|v| v.borrow().clone()).unwrap_or_default();
                        let (shared_count, shared_size) = match &shares {
                            Some(s) => {
                                let s = s.lock().unwrap_or_else(|e| e.into_inner());
                                let files = s.files();
                                (files.len() as u64, files.iter().map(|(f, _)| f.size).sum())
                            }
                            None => (0, 0),
                        };
                        let moment = crate::ec_stats::Moment {
                            uptime: statistics.uptime(now_i).as_secs(),
                            session_sent: session.sent,
                            session_received: session.received,
                            total_sent: totals.sent,
                            total_received: totals.received,
                            connected_since: server_since
                                .filter(|_| server.is_some())
                                .map(|(_, t)| u64::from(unix_now().saturating_sub(t))),
                            connections: view.connections.into(),
                            active_uploads: 0,
                            waiting_uploads: view.upload_queue.into(),
                            found_sources: view.sources.into(),
                            active_downloads: view.downloads.iter().map(|d| u64::from(d.transferring)).sum(),
                            servers: server_list.entries().to_vec(),
                            shared_count,
                            shared_size,
                        };
                        let _ = reply.send(tree_track.data(moment));
                    }
                    Some(Control::Update(reply)) => {
                        let shared = match &shares {
                            Some(s) => shared_state.list(&s.lock().unwrap_or_else(|e| e.into_inner())),
                            None => Vec::new(),
                        };
                        let live = server.as_ref().map(|s| s.info());
                        let connected = match server_since {
                            Some((SocketAddr::V4(a), _)) if server.is_some() => Some(a),
                            _ => None,
                        };
                        server_ids.keep(server_list.entries());
                        let servers = server_list.entries().iter().filter_map(|e| {
                            let addr = SocketAddrV4::new(e.ip?, e.port);
                            let mut info = e.clone();
                            let mut tcp_flags = 0;
                            // The connected one, as it told us of itself.
                            if let (Some(l), true) = (&live, connected == Some(addr)) {
                                if let Some(n) = l.name.as_ref().filter(|n| !n.is_empty()) { info.name = n.clone(); }
                                if let Some(d) = l.description.as_ref().filter(|d| !d.is_empty()) { info.description = d.clone(); }
                                if let Some(v) = l.version.as_ref().filter(|v| !v.is_empty()) { info.version = v.clone(); }
                                info.users = l.users;
                                info.files = l.files;
                                tcp_flags = l.tcp_flags;
                            }
                            Some(crate::ec_update::UpdateServer { ecid: server_ids.id(addr), info, tcp_flags })
                        }).collect();
                        let _ = reply.send(crate::ec_update::UpdateData { shared, servers, friends: friends.view() });
                    }
                    None => ec_control = None,
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let t = start.elapsed();
                // The session's bytes into the statistics, saved once a minute.
                let (tx, rx) = oneshot::channel();
                if cmd.send(Command::Traffic(tx)).is_ok() {
                    if let Ok(traffic) = rx.await {
                        statistics.update(traffic, now);
                        if let Some(view) = &ec_view {
                            let rates = Totals {
                                sent: traffic.sent.saturating_sub(last_traffic.sent),
                                received: traffic.received.saturating_sub(last_traffic.received),
                            };
                            let mut status = ec_status(EcInputs {
                                c: &c,
                                server: server.as_ref().map(|s| (s, server_since)),
                                connecting: attempting.is_some(),
                                our_id,
                                kad: match &kad_node {
                                    Some(k) => Some((k.handle.snapshot().await, k.prefs.kad_id, kad_since)),
                                    None => None,
                                },
                                statistics: &statistics,
                                rates,
                                queue: {
                                    let (tx, rx) = oneshot::channel();
                                    match cmd.send(Command::Progress(tx)) {
                                        Ok(()) => rx.await.ok(),
                                        Err(_) => None,
                                    }
                                },
                                download_ids: &mut download_ids,
                                listed: match server_since {
                                    Some((SocketAddr::V4(a), _)) => server_list.find(a),
                                    _ => None,
                                },
                                server_ecid: match server_since {
                                    Some((SocketAddr::V4(a), _)) => server_ids.id(a),
                                    _ => 0,
                                },
                                shared: shares.as_ref().map_or(0, |s| s.lock().unwrap_or_else(|e| e.into_inner()).shared_count()),
                                now,
                            });
                            tree_track.sample(
                                statistics.uptime(now).as_secs(),
                                status.dl_speed,
                                status.ul_speed,
                                status.session_sent + status.session_received > 0,
                                status.connections.into(),
                            );
                            history.lock().unwrap_or_else(|e| e.into_inner()).record(crate::graphs::Record {
                                kbytes_sent: status.session_sent as f64 / 1024.0,
                                kbytes_received: status.session_received as f64 / 1024.0,
                                kbps_up: status.ul_speed as f32 / 1024.0,
                                kbps_down: status.dl_speed as f32 / 1024.0,
                                timestamp: statistics.uptime(now).as_secs_f64(),
                                downloads: status.downloads.iter().map(|d| d.transferring).sum::<u32>().min(u16::MAX.into()) as u16,
                                // Uploads are not counted per second yet.
                                uploads: 0,
                                connections: status.connections.min(u16::MAX.into()) as u16,
                                kad_nodes: status.kad.as_ref().map_or(0, |k| k.nodes).min(u16::MAX.into()) as u16,
                                kad_nodes_total: 0,
                            });
                            // Taken after every change handled so far: this
                            // loop handles changes and ticks in turn.
                            status.applied = download_changes.load(std::sync::atomic::Ordering::SeqCst);
                            view.send_replace(status);
                        }
                        last_traffic = traffic;
                    }
                }
                if let Some(totals) = statistics.save_due(now) {
                    crate::stats::save_logged(&c.config, &mut statistics, &totals);
                }
                // Every server failed a while ago: a new sweep.
                searches.poll(now);
                // Downloads added or resumed are asked about first
                // (`RequestGlobalSources`).
                let connected_addr = match server_since {
                    Some((SocketAddr::V4(a), _)) if server.is_some() => Some(a),
                    _ => None,
                };
                let now_wanted: HashSet<Md4Hash> = wanted.iter().map(|(h, _)| *h).filter(|h| !paused.contains(h)).collect();
                for h in now_wanted.difference(&seen_wanted) {
                    global_sources.request(*h, server_list.entries(), connected_addr);
                }
                seen_wanted = now_wanted;
                // One source request to another server (`SendGlobalSources`),
                // while logged in.
                if let (Some(u), Some(_)) = (&server_udp, &server) {
                    if !wanted.is_empty() {
                        let (tx, rx) = oneshot::channel();
                        if cmd.send(Command::Progress(tx)).is_ok() {
                            if let Ok((files, _)) = rx.await {
                                let max_udp = crate::global_sources::max_sources_udp(300);
                                let downloads: Vec<crate::global_sources::Wanted> = files.iter()
                                    .filter(|f| matches!(f.status, remule_core::part_file::Status::Ready | remule_core::part_file::Status::Empty)
                                        && !f.paused && !f.stopped && !f.done
                                        && (f.sources as u32) < max_udp)
                                    .map(|f| crate::global_sources::Wanted { hash: f.hash, size: f.size })
                                    .collect();
                                if let Some(ask) = global_sources.send(now, &downloads, server_list.entries(), connected_addr) {
                                    u.send(&ask.packet, &ask.server, public_ip).await;
                                }
                            }
                        }
                    }
                }
                // One server's status ping (`ServerStats`), while logged in.
                if let (Some(u), Some(_)) = (&server_udp, &server) {
                    let o = server_stats.tick(
                        now, u64::from(unix_now()), &mut server_list, public_ip, c.dead_server_retries,
                        &mut rand::thread_rng(),
                    );
                    if let Some(o) = o {
                        stats_out(u, o, &mut server_list, &mut connector, public_ip).await;
                    }
                }
                if let Some(next) = connector.poll(now) {
                    follow(next, &c, &mut attempting, t);
                }
                // Offer what we share (new files as they come).
                if let (Some(s), Some(sh)) = (&server, &shares) {
                    if now >= next_offer {
                        next_offer = now + OFFER_EVERY;
                        let files = {
                            let sh = sh.lock().unwrap_or_else(|e| e.into_inner());
                            publisher.server_offer(&sh, s.info().tcp_flags, 0, 0)
                        };
                        if !files.is_empty() {
                            info!("[{:>5}s] offering {} files to the server", t.as_secs(), files.len());
                            let _ = s.offer_files(&files, our_id, c.tcp_port).await;
                        }
                    }
                }
                // Publish on Kad, when others can reach us.
                if let (Some(k), Some(sh), true) = (&kad_node, &shares, kad_connected.is_some()) {
                    let running = k.handle.store_counts().await;
                    // `DecideKadSourcePublish`: open, else a direct UDP
                    // callback, else through our buddy, else nothing.
                    let route = if reach.reachable() {
                        Some(SourceRoute::Open)
                    } else if let Some(udp_port) = k.handle.direct_callback().await {
                        Some(SourceRoute::DirectCallback { udp_port })
                    } else {
                        own_buddy.map(|at| SourceRoute::Buddy {
                            at,
                            id: ed2k_types::UInt128::new(u128::MAX) ^ k.prefs.kad_id,
                        })
                    };
                    let publishes = {
                        let mut sh = sh.lock().unwrap_or_else(|e| e.into_inner());
                        publisher.update_keywords(&sh);
                        publisher.kad_publish(
                            &mut sh,
                            running,
                            route,
                            c.tcp_port,
                            0x03,
                            unix_now().into(),
                        )
                    };
                    for p in publishes {
                        let r = match p {
                            KadPublish::Keyword { word, target, files } => {
                                info!("[{:>5}s] Kad: publishing {} files under {word:?}", t.as_secs(), files.len());
                                k.handle.store_keyword(target, files).await
                            }
                            KadPublish::Source { hash, size, tags } => k.handle.store_source(hash, size, tags).await,
                        };
                        if let Err(e) = r {
                            warn!("Kad publish: {e}");
                        }
                    }
                }
                if let Some(s) = &server {
                    if now >= next_server_ask {
                        next_server_ask = now + SERVERREASKTIME;
                        for (h, size) in wanted.iter().filter(|(h, _)| !paused.contains(h)) {
                            let _ = s.get_sources(*h, *size).await;
                        }
                    }
                }
                // Firewalled sources are asked for callbacks only while
                // others can reach us.
                if told_reachable != Some(reach.reachable()) {
                    told_reachable = Some(reach.reachable());
                    let _ = cmd.send(Command::SetReachable(reach.reachable()));
                }
                // Firewalled with no buddy: look for one when it is time.
                if let (Some(k), Some(_)) = (&kad_node, kad_connected) {
                    if k.handle.buddy_search(own_buddy.is_some()).await.is_some() {
                        info!("[{:>5}s] Kad: looking for a buddy", t.as_secs());
                    }
                }
                if let (Some(k), Some(at)) = (&kad_node, next_kad_ask) {
                    if now >= at && kad_connected.is_some() {
                        next_kad_ask = Some(now + KAD_REASK);
                        for (h, size) in wanted.iter().filter(|(h, _)| !paused.contains(h)) {
                            match k.handle.search_sources(*h, *size).await {
                                Ok(id) => { kad_searches.insert(id, *h); }
                                Err(e) => warn!("Kad source search: {e}"),
                            }
                        }
                    }
                }
                if t >= next_status {
                    next_status = t + c.status_every;
                    let (tx, rx) = oneshot::channel();
                    if cmd.send(Command::Progress(tx)).is_ok() {
                        if let Ok((files, stats)) = rx.await {
                            let secs = last_status.elapsed().as_secs_f64().max(0.001);
                            let rate = (stats.received - last_received) as f64 / secs;
                            last_received = stats.received;
                            last_status = Instant::now();
                            for f in files {
                                info!(
                                    "[{:>5}s] {:5.1}% {} of {} {}: {} sources, {} queued, {} connected, {} sending",
                                    t.as_secs(),
                                    100.0 * f.completed as f64 / f.size.max(1) as f64,
                                    human(f.completed), human(f.size), f.name,
                                    f.sources, f.queued, f.connected, f.downloading,
                                );
                            }
                            info!("[{:>5}s] {}/s, {} received, {} connections",
                                t.as_secs(), human(rate as u64), human(stats.received), stats.connections);
                        }
                    }
                    info!("[{:>5}s] {}", t.as_secs(), crate::stats::line(&statistics));
                }
            }
        }
    }

    let (queue, uploader) = match finished {
        Some(q) => q,
        None => {
            let _ = cmd.send(Command::Shutdown);
            dl.await.map_err(|e| e.to_string())?
        }
    };
    let mut summary = Summary::default();
    if let Some(up) = &uploader {
        summary.uploaded = up.sent_total();
        info!(
            "uploaded {}, {} waiting in the upload queue",
            human(up.sent_total()),
            up.queue().waiting_count()
        );
    }
    while let Ok(r) = reports.try_recv() {
        if matches!(r, Report::Completed { .. }) {
            done += 1;
        }
        log_report(start.elapsed(), &r, &names);
    }
    if let Some(k) = kad_node {
        k.save().await?;
    }
    server_list.save_if_changed(&c.config);
    for f in queue.progress() {
        info!(
            "{}: {} of {}{}",
            f.name,
            human(f.completed),
            human(f.size),
            if f.done { " (complete)" } else { "" }
        );
    }
    summary.completed = done;
    summary.received = queue.stats().received;
    info!(
        "{done} file(s) completed, {} received",
        human(summary.received)
    );
    // The statistics, with the last bytes counted, saved as aMule does on
    // shutdown.
    let now = Instant::now();
    statistics.update(
        Totals {
            sent: summary.uploaded,
            received: summary.received,
        },
        now,
    );
    if let Some(totals) = statistics.unsaved() {
        crate::stats::save_logged(&c.config, &mut statistics, &totals);
    }
    summary.totals = statistics.totals();
    info!("{}", crate::stats::summary(&statistics, now));
    Ok(summary)
}

/// `CIPFilter::Update` and `DownloadFinished`: `ipfilter.dat` fetched to
/// `ipfilter.download`, put in place, and the filter read again.
async fn update_ip_filter(dir: PathBuf, url: String, filter: Arc<AddressFilter>) {
    let body = match crate::http::fetch(&url).await {
        Ok(b) => b,
        Err(e) => {
            debug!("ipfilter.dat from {url}: {e}");
            warn!("Failed to download ipfilter.dat from {url}");
            return;
        }
    };
    // Unlike aMule, which replaces the file first and only then finds it
    // unreadable, a download that unpacks to no list keeps the filter there
    // is: an update must not lift the blocks of a working one.
    if !matches!(
        ed2k_formats::archive::unpack(&body, crate::config::IPFILTER_MEMBERS),
        Some((_, ed2k_formats::archive::FileType::Text))
    ) {
        warn!("Failed to load ipfilter.dat from {url}, unknown format encountered; the current filter is kept");
        return;
    }
    let (download, dat) = (dir.join("ipfilter.download"), dir.join("ipfilter.dat"));
    if let Err(e) = std::fs::write(&download, &body).and_then(|_| std::fs::rename(&download, &dat))
    {
        warn!("Failed to replace ipfilter.dat file, aborting update: {e}");
        return;
    }
    info!("Successfully updated ipfilter.dat");
    let _ =
        tokio::task::spawn_blocking(move || crate::config::reload_ip_filter(&dir, &filter)).await;
}

/// Kad on the client UDP port when there is one (shared, as in aMule),
/// else on a socket of its own.
async fn start_kad(port: Option<&UdpPort>, a: &KadStart) -> Result<kad::KadNode, String> {
    match port {
        Some(p) => kad::start_on(a, p).await,
        None => kad::start(a).await,
    }
}
