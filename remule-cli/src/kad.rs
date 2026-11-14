// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule kad`: join Kad from a nodes.dat, keep the routing table alive,
//! search keywords and sources.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ed2k_formats::nodes_dat::NodesDat;
use ed2k_kad::driver::{self, KadHandle, Snapshot};
use ed2k_kad::node::{Config, Event};
use ed2k_kad::prefs::{self, KadPrefs};
use ed2k_kad::search::{Found, KeywordResult, SourceResult};
use ed2k_kad::Kad;
use ed2k_server::SearchParams;
use ed2k_types::{Md4Hash, UInt128};
use rand::Rng;

/// The files a keyword search found, by hash: the result and how many nodes gave it.
type FilesFound = HashMap<Md4Hash, (KeywordResult, u32)>;

/// What `remule kad` was asked.
#[derive(Debug, Clone)]
pub struct KadArgs {
    pub nodes: Option<PathBuf>,
    pub dir: PathBuf,
    pub port: u16,
    pub bootstrap: Vec<SocketAddrV4>,
    pub searches: Vec<String>,
    pub sources: Vec<(Md4Hash, u64)>,
    /// Seconds to stay up (0: until the searches are done).
    pub duration: u64,
    pub status_every: u64,
    pub warmup: u64,
    pub limit: usize,
    /// Print ed2k links.
    pub verbose: bool,
    /// Say we take unsolicited UDP: others then publish to us and we
    /// store and serve it (the port must be reachable from outside).
    pub reachable: bool,
}

/// The index files in the state directory.
const INDEX_FILES: [&str; 3] = ["load_index.dat", "key_index.dat", "src_index.dat"];

/// `HASH:SIZE` for `--source`.
pub fn parse_source(s: &str) -> Result<(Md4Hash, u64), String> {
    let (h, size) = s
        .split_once(':')
        .ok_or_else(|| format!("{s:?}: expected HASH:SIZE"))?;
    let hash: Md4Hash = h.parse().map_err(|_| format!("{h:?} is not an MD4 hash"))?;
    let size = size
        .parse()
        .map_err(|_| format!("{size:?} is not a size in bytes"))?;
    Ok((hash, size))
}

fn status(t: Duration, s: &Snapshot) -> String {
    let mut extra = String::new();
    let i = &s.index;
    if i.keywords + i.sources + i.notes > 0 || s.stats.publishes_stored > 0 {
        extra += &format!(
            ", index {} keywords / {} sources / {} notes ({} publishes, {} searches answered)",
            i.keywords, i.sources, i.notes, s.stats.publishes_stored, s.stats.searches_answered
        );
    }
    if s.stats.flood_drops + s.stats.bans > 0 {
        extra += &format!(
            ", {} flood drops, {} bans",
            s.stats.flood_drops, s.stats.bans
        );
    }
    format!(
        "[{:>5}s] {} contacts ({} verified; by type {:?}), depth {}, ~{} users, in {} / out {} packets{}{}{extra}",
        t.as_secs(),
        s.contacts,
        s.verified,
        s.by_type,
        s.depth,
        s.estimated_users,
        s.stats.packets_in,
        s.stats.packets_out,
        if s.connected { "" } else { ", not connected" },
        s.external_port
            .map(|p| format!(", seen at UDP port {p}"))
            .unwrap_or_default(),
    )
}

fn human(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[u])
    }
}

fn print_keyword_results(query: &str, found: &FilesFound, limit: usize, verbose: bool) {
    let mut v: Vec<&(KeywordResult, u32)> = found.values().collect();
    v.sort_by(|a, b| {
        b.0.availability
            .cmp(&a.0.availability)
            .then(a.0.name.cmp(&b.0.name))
    });
    println!("{} files for {query:?}", v.len());
    println!("{:>7} {:>5} {:>10}  name", "sources", "nodes", "size");
    for (r, nodes) in v.iter().take(limit) {
        println!(
            "{:>7} {:>5} {:>10}  {}",
            r.availability,
            nodes,
            human(r.size),
            r.name
        );
        if verbose {
            println!(
                "{:>25}  ed2k://|file|{}|{}|{}|/",
                "",
                ed2k_hash::cleanup_name(&r.name),
                r.size,
                r.hash
            );
        }
    }
    if v.len() > limit {
        println!("... and {} more (--limit)", v.len() - limit);
    }
}

fn print_sources(hash: &Md4Hash, found: &[SourceResult]) {
    println!("{} sources for {hash}", found.len());
    for s in found {
        println!(
            "  type {} {}:{} (UDP {}), crypt {:#04x}{}",
            s.source_type,
            s.ip,
            s.tcp_port,
            s.udp_port,
            s.crypt_options,
            if s.buddy_port != 0 {
                format!(", buddy {}:{}", s.buddy_ip, s.buddy_port)
            } else {
                String::new()
            }
        );
    }
}

fn load_or_make_prefs(dir: &std::path::Path) -> KadPrefs {
    let path = dir.join(prefs::FILE_NAME);
    if let Some(p) = std::fs::read(&path).ok().and_then(|b| KadPrefs::read(&b)) {
        return p;
    }
    KadPrefs {
        public_ip: 0,
        kad_id: UInt128::new(rand::thread_rng().gen()),
    }
}

/// A running Kad node and where its state is kept.
pub struct KadNode {
    pub handle: KadHandle,
    prefs: KadPrefs,
    dir: PathBuf,
}

/// How to start a Kad node.
#[derive(Debug, Clone)]
pub struct KadStart {
    /// Where nodes.dat, preferencesKad.dat and the index files are kept.
    pub dir: PathBuf,
    /// The nodes.dat to start from (default: DIR/nodes.dat).
    pub nodes: Option<PathBuf>,
    pub bootstrap: Vec<SocketAddrV4>,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub user_hash: Md4Hash,
    pub reachable: bool,
}

/// Load the state, bind the UDP port and start the node.
pub async fn start(a: &KadStart) -> Result<KadNode, String> {
    std::fs::create_dir_all(&a.dir).map_err(|e| format!("{}: {e}", a.dir.display()))?;
    let prefs = load_or_make_prefs(&a.dir);
    let nodes_path = a.nodes.clone().unwrap_or_else(|| a.dir.join("nodes.dat"));
    let nodes = match std::fs::read(&nodes_path) {
        Ok(b) => Some(NodesDat::read(&b).map_err(|e| format!("{}: {e}", nodes_path.display()))?),
        Err(e) if a.bootstrap.is_empty() => {
            return Err(format!(
                "{}: {e} (give a nodes.dat with --nodes, or --bootstrap IP:PORT)",
                nodes_path.display()
            ))
        }
        Err(_) => None,
    };
    let cfg = Config {
        kad_id: prefs.kad_id,
        udp_key_secret: rand::thread_rng().gen(),
        user_hash: a.user_hash,
        tcp_port: a.tcp_port,
        tcp_firewalled: true,
        udp_firewalled: !a.reachable,
    };
    let now = driver::unix_now();
    let mut kad = Kad::new(cfg, now);
    for (i, name) in INDEX_FILES.iter().enumerate() {
        let Ok(b) = std::fs::read(a.dir.join(name)) else {
            continue;
        };
        let r = match i {
            0 => kad.index.read_load_file(&b, now),
            1 => kad.index.read_keyword_file(&b, now),
            _ => kad.index.read_source_file(&b, now),
        };
        if let Err(e) = r {
            println!("{name}: {e} (ignored)");
        }
    }
    let st = kad.index.stats();
    if st.keywords + st.sources + st.loads > 0 {
        println!(
            "index: {} keyword entries, {} sources, {} loads",
            st.keywords, st.sources, st.loads
        );
    }
    if let Some(n) = &nodes {
        let taken = kad.load_nodes(n, now);
        println!(
            "{}: {} contacts, {} taken into the routing table",
            nodes_path.display(),
            n.contacts.len(),
            taken
        );
    }
    println!(
        "Kad ID {}",
        prefs
            .kad_id
            .to_be_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    );
    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", a.udp_port))
        .await
        .map_err(|e| format!("UDP port {}: {e}", a.udp_port))?;
    let handle: KadHandle = driver::spawn(kad, socket);
    for b in &a.bootstrap {
        handle.bootstrap(*b).await;
    }
    Ok(KadNode {
        handle,
        prefs,
        dir: a.dir.clone(),
    })
}

impl KadNode {
    /// Save what was learned, as aMule does on exit.
    pub async fn save(&self) -> Result<(), String> {
        match self.handle.nodes().await {
            Some(n) => {
                let path = self.dir.join("nodes.dat");
                std::fs::write(&path, n.write()).map_err(|e| format!("{}: {e}", path.display()))?;
                println!("wrote {} ({} contacts)", path.display(), n.contacts.len());
            }
            None => println!("fewer than 25 contacts: nodes.dat not written"),
        }
        if let Some(f) = self.handle.index_files().await {
            for (name, bytes) in INDEX_FILES.iter().zip([f.load, f.keywords, f.sources]) {
                let path = self.dir.join(name);
                std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
            }
        }
        let path = self.dir.join(prefs::FILE_NAME);
        std::fs::write(&path, self.prefs.write()).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Run.
pub async fn run(a: KadArgs) -> Result<(), String> {
    let node = start(&KadStart {
        dir: a.dir.clone(),
        nodes: a.nodes.clone(),
        bootstrap: a.bootstrap.clone(),
        udp_port: a.port,
        tcp_port: a.port,
        user_hash: ed2k_server::packets::new_user_hash(&mut rand::thread_rng()),
        reachable: a.reachable,
    })
    .await?;
    let mut h = node.handle;
    let start = Instant::now();
    let mut next_status = 0;
    let mut pending: Vec<SearchParams> = a.searches.iter().map(SearchParams::new).collect();
    let mut pending_sources = a.sources.clone();
    let mut keyword_ids: HashMap<u32, (String, FilesFound)> = HashMap::new();
    let mut source_ids: HashMap<u32, (Md4Hash, Vec<SourceResult>)> = HashMap::new();
    let mut connected_at: Option<u64> = None;
    let mut started_any = false;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            e = h.events.recv() => {
                let Some(e) = e else { break };
                match e {
                    Event::Connected => {
                        println!("[{:>5}s] connected", start.elapsed().as_secs());
                        connected_at = Some(start.elapsed().as_secs());
                    }
                    Event::Found { search, found: Found::Keyword(k) } => {
                        if let Some((_, m)) = keyword_ids.get_mut(&search) {
                            m.entry(k.hash).and_modify(|(old, n)| {
                                *n += 1;
                                if k.availability > old.availability { old.availability = k.availability; }
                            }).or_insert((*k, 1));
                        }
                    }
                    Event::Found { search, found: Found::Source(s) } => {
                        if let Some((_, v)) = source_ids.get_mut(&search) {
                            if !v.contains(&s) { v.push(s); }
                        }
                    }
                    Event::SearchDone { search, answers, requests } => {
                        if let Some((q, m)) = keyword_ids.remove(&search) {
                            println!("[{:>5}s] search {q:?} done: {answers} answers from {requests} nodes asked", start.elapsed().as_secs());
                            print_keyword_results(&q, &m, a.limit, a.verbose);
                        }
                        if let Some((hash, v)) = source_ids.remove(&search) {
                            println!("[{:>5}s] source search done: {answers} answers from {requests} nodes asked", start.elapsed().as_secs());
                            print_sources(&hash, &v);
                        }
                    }
                }
            }
            _ = tick.tick() => {
                let t = start.elapsed();
                if t.as_secs() >= next_status {
                    next_status = t.as_secs() + a.status_every;
                    if let Some(s) = h.snapshot().await {
                        println!("{}", status(t, &s));
                    }
                }
                // Searches start once the routing table has warmed up.
                if connected_at.is_some_and(|c| t.as_secs() >= c + a.warmup) {
                    for p in pending.drain(..) {
                        match h.search_keyword(p.clone()).await {
                            Ok((id, word)) => {
                                println!("[{:>5}s] searching {:?} (keyword {word:?})", t.as_secs(), p.query);
                                keyword_ids.insert(id, (p.query.clone(), HashMap::new()));
                                started_any = true;
                            }
                            Err(e) => println!("search {:?}: {e}", p.query),
                        }
                    }
                    for (hash, size) in pending_sources.drain(..) {
                        match h.search_sources(hash, size).await {
                            Ok(id) => {
                                println!("[{:>5}s] searching sources of {hash}", t.as_secs());
                                source_ids.insert(id, (hash, Vec::new()));
                                started_any = true;
                            }
                            Err(e) => println!("sources of {hash}: {e}"),
                        }
                    }
                }
                let searches_over = started_any && keyword_ids.is_empty() && source_ids.is_empty();
                let nothing_to_search = a.searches.is_empty() && a.sources.is_empty();
                let out_of_time = a.duration > 0 && t.as_secs() >= a.duration;
                if out_of_time || (a.duration == 0 && (searches_over || nothing_to_search)) {
                    break;
                }
            }
        }
    }
    if let Some(s) = h.snapshot().await {
        println!("{}", status(start.elapsed(), &s));
    }
    KadNode {
        handle: h,
        prefs: node.prefs,
        dir: node.dir,
    }
    .save()
    .await
}
