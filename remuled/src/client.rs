// SPDX-License-Identifier: GPL-2.0-or-later
//! A running client: downloads with sources from a server, Kad and links,
//! uploads to those who ask, shared files offered to the server and
//! published on Kad. Both `remuled` and `remule download` run this.
//!
//! What happens is logged with [`tracing`] at `info`, each line prefixed
//! with the seconds since start.
//!
//! With `REMULE_TRACE` set, every peer packet's protocol, opcode and size
//! is printed to stderr.

use std::collections::HashMap;
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
use remule_core::downloader::{self, Command, DownloaderConfig};
use remule_core::ip_filter::AddressFilter;
use remule_core::publish::{KadPublish, Publisher};
use remule_core::shared::{mtime, ScanOptions, SharedFiles};
use remule_core::statistics::{Statistics, Totals};
use remule_core::upload_queue::{UploadConfig, UploadQueue};
use remule_core::uploader::Uploader;
use remule_core::PartFile;
use remule_net::Bandwidth;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::kad::{self, KadStart};
use crate::server_conn::{Attempt, Connector, Next, ATTEMPT_TIMEOUT, RETRY_AFTER};

/// Kad source searches are repeated this often (`GetKadSourceReaskTime`).
const KAD_REASK: Duration = Duration::from_secs(30 * 60);
/// Seconds after Kad connects before searching, so the table fills.
const KAD_WARMUP: u64 = 20;
/// Shared files are offered to the server this often (new ones as they come).
const OFFER_EVERY: Duration = Duration::from_secs(60);

/// Where Kad keeps its state.
#[derive(Debug, Clone)]
pub struct KadSettings {
    /// `nodes.dat`, `preferencesKad.dat` and the index files.
    pub dir: PathBuf,
    /// The `nodes.dat` to start from (default: the one in `dir`).
    pub nodes: Option<PathBuf>,
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
    /// Others can connect to our TCP port: publish sources on Kad.
    pub reachable: bool,
    /// Take sources on LAN and loopback addresses (aMule's FilterLanIPs off).
    pub allow_lan: bool,
    /// Peers and servers it blocks are left alone (`ipfilter.dat`).
    pub ip_filter: Option<Arc<AddressFilter>>,
    /// Stop once every download is complete (ignored when sharing).
    pub stop_when_done: bool,
    /// Between progress lines.
    pub status_every: Duration,
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
        | Report::Queued { rank: None, .. } => return,
        Report::Queued {
            addr,
            rank: Some(n),
            ..
        } => format!("{addr}: queue rank {n}"),
        Report::DownloadStarted { file, addr } => format!("{addr}: sending {}", name(file)),
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
    let wanted: Vec<(Md4Hash, u64)> = files.iter().map(|f| (f.hash(), f.size())).collect();
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
    let mut connector = Connector::new(servers, c.obfuscate_server, c.reconnect);
    let mut attempting: Option<Attempting> = None;

    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", c.tcp_port)).await {
        Ok(l) => Some(l),
        Err(e) => {
            warn!("TCP port {}: {e} (no callbacks)", c.tcp_port);
            None
        }
    };

    let mut ours = Hello::amule(c.user_hash, our_id, c.tcp_port, c.nick.clone());
    ours.udp_port = 0;
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
    qc.ip_filter = c.ip_filter.clone();
    let ours_for_upload = qc.ours.clone();
    let queue = DownloadQueue::new(qc);
    let mut dc = DownloaderConfig::new(Arc::new(Bandwidth::new(c.max_upload, c.max_download)));
    dc.stop_when_done = c.stop_when_done;
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
            kad::start(&KadStart {
                dir: k.dir.clone(),
                nodes: k.nodes.clone(),
                bootstrap: Vec::new(),
                udp_port: c.udp_port,
                tcp_port: c.tcp_port,
                user_hash: c.user_hash,
                reachable: c.reachable,
            })
            .await?,
        ),
        None => None,
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
                        info!(
                            "[{:>5}s] server {addr}: logged in, {} {}",
                            t.as_secs(),
                            if li.low_id { "LowID" } else { "HighID" },
                            li.id
                        );
                        our_id = li.id;
                        let _ = cmd.send(Command::SetOurId { id: li.id, public_ip: li.public_ip });
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
            r = reports.recv() => {
                let Some(r) = r else { continue };
                if matches!(r, Report::Completed { .. }) {
                    done += 1;
                }
                log_report(start.elapsed(), &r, &names);
            }
            ev = async { match &mut server { Some(s) => s.next_event().await, None => std::future::pending().await } } => {
                match ev {
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
                        our_id = 0;
                        let _ = cmd.send(Command::SetOurId { id: 0, public_ip: None });
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
                        next_kad_ask = Some(Instant::now() + Duration::from_secs(KAD_WARMUP));
                    }
                    Some(KadEvent::Found { search, found: Found::Source(s) }) => {
                        if let (Some(&file), Some(ep)) = (kad_searches.get(&search), Endpoint::from_kad(&s)) {
                            let _ = cmd.send(Command::AddSources { file, sources: vec![ep], origin: Origin::Kad });
                        }
                    }
                    Some(KadEvent::SearchDone { search, answers, .. }) => {
                        if let Some(file) = kad_searches.remove(&search) {
                            info!("[{:>5}s] Kad: {answers} source answers for {}", start.elapsed().as_secs(),
                                names.get(&file).map(String::as_str).unwrap_or("?"));
                        }
                    }
                    Some(_) => {}
                    None => kad_node = None,
                }
            }
            r = &mut dl => {
                finished = Some(r.map_err(|e| e.to_string())?);
                break;
            }
            _ = &mut shutdown => break,
            _ = tick.tick() => {
                let now = Instant::now();
                let t = start.elapsed();
                // The session's bytes into the statistics, saved once a minute.
                let (tx, rx) = oneshot::channel();
                if cmd.send(Command::Traffic(tx)).is_ok() {
                    if let Ok(traffic) = rx.await {
                        statistics.update(traffic, now);
                    }
                }
                if let Some(totals) = statistics.save_due(now) {
                    crate::stats::save_logged(&c.config, &mut statistics, &totals);
                }
                // Every server failed a while ago: a new sweep.
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
                    let publishes = {
                        let mut sh = sh.lock().unwrap_or_else(|e| e.into_inner());
                        publisher.update_keywords(&sh);
                        publisher.kad_publish(&mut sh, running, c.reachable, c.tcp_port, 0x03, unix_now().into())
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
                        for (h, size) in &wanted {
                            let _ = s.get_sources(*h, *size).await;
                        }
                    }
                }
                if let (Some(k), Some(at)) = (&kad_node, next_kad_ask) {
                    if now >= at && kad_connected.is_some() {
                        next_kad_ask = Some(now + KAD_REASK);
                        for (h, size) in &wanted {
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
