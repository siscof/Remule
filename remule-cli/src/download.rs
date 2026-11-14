// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule download`: download files from ed2k links, finding sources on
//! eD2k servers and Kad, and resume the downloads in the temp directory,
//! including aMule's.
//!
//! The temp directory holds `NNN.part` / `NNN.part.met` pairs in aMule's
//! format: point it at aMule's `Temp` directory (with aMule closed) and
//! remule carries on aMule's downloads; aMule resumes remule's the same way.
//!
//! With `REMULE_TRACE` set, every peer packet's protocol, opcode and size
//! is printed to stderr.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed2k_formats::cryptkey_dat::CryptKey;
use ed2k_kad::node::Event as KadEvent;
use ed2k_kad::search::Found;
use ed2k_peer::hello::{CryptSettings, MiscOptions2};
use ed2k_peer::secident::Identity;
use ed2k_peer::Hello;
use ed2k_server::session::Event as ServerEvent;
use ed2k_server::{ConnectOptions, LoginInfo, ServerClient};
use ed2k_types::ed2k::SERVERREASKTIME;
use ed2k_types::Md4Hash;
use remule_core::download_queue::{DownloadQueue, Endpoint, Origin, QueueConfig, Report};
use remule_core::downloader::{self, Command, DownloaderConfig};
use remule_core::PartFile;
use remule_net::Bandwidth;
use tokio::sync::{mpsc, oneshot};

use crate::kad::{self, KadStart};
use crate::link;

/// Kad source searches are repeated this often (`GetKadSourceReaskTime`).
const KAD_REASK: Duration = Duration::from_secs(30 * 60);
/// Seconds after Kad connects before searching, so the table fills.
const KAD_WARMUP: u64 = 20;

/// What `remule download` was asked.
#[derive(Debug, Clone)]
pub struct DownloadArgs {
    pub links: Vec<String>,
    pub temp: PathBuf,
    pub incoming: PathBuf,
    pub servers: Vec<SocketAddr>,
    pub obfuscate_server: bool,
    /// Find sources on Kad, keeping its state here.
    pub kad: Option<PathBuf>,
    pub kad_nodes: Option<PathBuf>,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub nick: String,
    /// Seconds to run (0: until every file is done).
    pub duration: u64,
    pub status_every: u64,
    pub max_connections: usize,
    /// KiB/s, 0 for no limit.
    pub max_download: u32,
    pub max_upload: u32,
}

fn human(n: u64) -> String {
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

/// Our user hash, kept in the temp directory so peers recognise us.
fn user_hash(temp: &Path) -> Md4Hash {
    let path = temp.join("remule.userhash");
    if let Some(h) = std::fs::read(&path)
        .ok()
        .and_then(|b| Md4Hash::from_slice(&b))
    {
        return h;
    }
    let h = ed2k_server::packets::new_user_hash(&mut rand::thread_rng());
    let _ = std::fs::write(&path, h.0);
    h
}

/// Our RSA key for secure identification, kept in the temp directory as
/// aMule keeps `cryptkey.dat`.
fn identity(temp: &Path) -> Result<Arc<Identity>, String> {
    let path = temp.join("cryptkey.dat");
    let key = match std::fs::read(&path)
        .ok()
        .and_then(|b| CryptKey::read(&b).ok())
    {
        Some(k) => k,
        None => {
            let k = CryptKey::generate(&mut rand::rngs::OsRng).map_err(|e| e.to_string())?;
            std::fs::write(&path, k.write()).map_err(|e| format!("{}: {e}", path.display()))?;
            k
        }
    };
    Ok(Arc::new(Identity {
        key: key.private_key().map_err(|e| e.to_string())?,
        public: key.public_key().map_err(|e| e.to_string())?,
    }))
}

/// Open every `*.part.met` in `temp`.
fn existing_downloads(temp: &Path) -> Result<Vec<PartFile>, String> {
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
            Err(e) => println!("{}: {e} (skipped)", p.display()),
        }
    }
    Ok(v)
}

fn print_report(t: Duration, r: &Report, names: &HashMap<Md4Hash, String>) {
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
    };
    println!("[{:>5}s] {line}", t.as_secs());
}

/// Run.
pub async fn run(a: DownloadArgs) -> Result<(), String> {
    for d in [&a.temp, &a.incoming] {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let mut files = existing_downloads(&a.temp)?;
    for f in &files {
        println!(
            "resuming {} ({} of {}, {})",
            f.name(),
            human(f.completed()),
            human(f.size()),
            f.met_path().display()
        );
    }
    let mut link_sources: Vec<(Md4Hash, SocketAddrV4)> = Vec::new();
    for l in &a.links {
        let l = link::parse(l)?;
        link_sources.extend(l.sources.iter().map(|s| (l.hash, *s)));
        if files.iter().any(|f| f.hash() == l.hash) {
            continue;
        }
        let mut f = PartFile::create(&a.temp, &l.name, l.hash, l.size)
            .map_err(|e| format!("{}: {e}", l.name))?;
        if let Some(root) = l.aich {
            f.set_aich_root(root);
        }
        println!(
            "new download {} ({}, {})",
            l.name,
            human(l.size),
            f.met_path().display()
        );
        files.push(f);
    }
    if files.is_empty() {
        return Err(
            "nothing to download: give ed2k links, or a temp directory with downloads".into(),
        );
    }
    if a.servers.is_empty() && a.kad.is_none() && link_sources.is_empty() {
        return Err("no way to find sources: give --server, --kad or links with sources".into());
    }
    let wanted: Vec<(Md4Hash, u64)> = files.iter().map(|f| (f.hash(), f.size())).collect();
    let names: HashMap<Md4Hash, String> = files
        .iter()
        .map(|f| (f.hash(), f.name().to_owned()))
        .collect();
    let our_hash = user_hash(&a.temp);

    // A server first: it gives us our ID.
    let mut server: Option<ServerClient> = None;
    let mut our_id = 0u32;
    let mut public_ip = None;
    for addr in &a.servers {
        let mut login = LoginInfo::new(our_hash, a.tcp_port, a.nick.clone());
        login.crypt_requested = a.obfuscate_server;
        let mut opts = ConnectOptions::new(login);
        opts.obfuscate = a.obfuscate_server;
        opts.session.ask_server_list = false;
        match ServerClient::connect(*addr, opts).await {
            Ok((c, li)) => {
                println!(
                    "server {addr}: logged in, {} {}",
                    if li.low_id { "LowID" } else { "HighID" },
                    li.id
                );
                our_id = li.id;
                public_ip = li.public_ip;
                server = Some(c);
                break;
            }
            Err(e) => println!("server {addr}: {e}"),
        }
    }

    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", a.tcp_port)).await {
        Ok(l) => Some(l),
        Err(e) => {
            println!("TCP port {}: {e} (no callbacks)", a.tcp_port);
            None
        }
    };

    let mut ours = Hello::amule(our_hash, our_id, a.tcp_port, a.nick.clone());
    ours.udp_port = 0;
    ours.misc2 = Some(MiscOptions2::amule(
        0,
        CryptSettings {
            supported: true,
            requested: true,
            required: false,
        },
    ));
    let mut qc = QueueConfig::new(ours, a.incoming.clone());
    qc.max_connections = a.max_connections;
    qc.our_public_ip = public_ip;
    qc.identity = Some(identity(&a.temp)?);
    let queue = DownloadQueue::new(qc);
    let mut dc = DownloaderConfig::new(Arc::new(Bandwidth::new(a.max_upload, a.max_download)));
    dc.stop_when_done = true;
    let (cmd, cmd_rx) = mpsc::unbounded_channel();
    let (rep_tx, mut reports) = mpsc::unbounded_channel();
    let mut dl = tokio::spawn(downloader::run(queue, dc, listener, cmd_rx, rep_tx));
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

    let mut kad_node = match &a.kad {
        Some(dir) => Some(
            kad::start(&KadStart {
                dir: dir.clone(),
                nodes: a.kad_nodes.clone(),
                bootstrap: Vec::new(),
                udp_port: a.udp_port,
                tcp_port: a.tcp_port,
                user_hash: our_hash,
                reachable: false,
            })
            .await?,
        ),
        None => None,
    };

    let start = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut next_status = 0u64;
    let mut next_server_ask = Instant::now();
    let mut kad_connected: Option<Instant> = None;
    let mut next_kad_ask: Option<Instant> = None;
    let mut kad_searches: HashMap<u32, Md4Hash> = HashMap::new();
    let mut done = 0usize;
    let mut last_received = 0u64;
    let mut last_status = Instant::now();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut finished = None;

    loop {
        tokio::select! {
            r = reports.recv() => {
                let Some(r) = r else { continue };
                if matches!(r, Report::Completed { .. }) {
                    done += 1;
                }
                print_report(start.elapsed(), &r, &names);
            }
            ev = async { match &mut server { Some(s) => s.next_event().await, None => std::future::pending().await } } => {
                match ev {
                    Some(ServerEvent::FoundSources { hash, sources }) => {
                        let eps: Vec<Endpoint> = sources.iter().filter_map(Endpoint::from_server).collect();
                        println!("[{:>5}s] server: {} sources ({} reachable) for {}",
                            start.elapsed().as_secs(), sources.len(), eps.len(),
                            names.get(&hash).map(String::as_str).unwrap_or("?"));
                        let _ = cmd.send(Command::AddSources { file: hash, sources: eps, origin: Origin::Server });
                    }
                    Some(ServerEvent::Closed(why)) => {
                        println!("[{:>5}s] server connection closed: {why:?}", start.elapsed().as_secs());
                        server = None;
                    }
                    None => {
                        println!("[{:>5}s] server connection closed", start.elapsed().as_secs());
                        server = None;
                    }
                    _ => {}
                }
            }
            ev = async { match &mut kad_node { Some(k) => k.handle.events.recv().await, None => std::future::pending().await } } => {
                match ev {
                    Some(KadEvent::Connected) => {
                        println!("[{:>5}s] Kad connected", start.elapsed().as_secs());
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
                            println!("[{:>5}s] Kad: {answers} source answers for {}", start.elapsed().as_secs(),
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
            _ = &mut ctrl_c => {
                println!("interrupted: saving");
                break;
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let t = start.elapsed();
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
                                Err(e) => println!("Kad source search: {e}"),
                            }
                        }
                    }
                }
                if t.as_secs() >= next_status {
                    next_status = t.as_secs() + a.status_every;
                    let (tx, rx) = oneshot::channel();
                    if cmd.send(Command::Progress(tx)).is_ok() {
                        if let Ok((files, stats)) = rx.await {
                            let secs = last_status.elapsed().as_secs_f64().max(0.001);
                            let rate = (stats.received - last_received) as f64 / secs;
                            last_received = stats.received;
                            last_status = Instant::now();
                            for f in files {
                                println!(
                                    "[{:>5}s] {:5.1}% {} of {} {}: {} sources, {} queued, {} connected, {} sending",
                                    t.as_secs(),
                                    100.0 * f.completed as f64 / f.size.max(1) as f64,
                                    human(f.completed), human(f.size), f.name,
                                    f.sources, f.queued, f.connected, f.downloading,
                                );
                            }
                            println!("[{:>5}s] {}/s, {} received, {} connections",
                                t.as_secs(), human(rate as u64), human(stats.received), stats.connections);
                        }
                    }
                }
                if a.duration > 0 && t.as_secs() >= a.duration {
                    println!("time is up: saving");
                    break;
                }
            }
        }
    }

    let queue = match finished {
        Some(q) => q,
        None => {
            let _ = cmd.send(Command::Shutdown);
            dl.await.map_err(|e| e.to_string())?
        }
    };
    while let Ok(r) = reports.try_recv() {
        if matches!(r, Report::Completed { .. }) {
            done += 1;
        }
        print_report(start.elapsed(), &r, &names);
    }
    if let Some(k) = kad_node {
        k.save().await?;
    }
    for f in queue.progress() {
        println!(
            "{}: {} of {}{}",
            f.name,
            human(f.completed),
            human(f.size),
            if f.done { " (complete)" } else { "" }
        );
    }
    println!(
        "{done} file(s) completed, {} received",
        human(queue.stats().received)
    );
    Ok(())
}
