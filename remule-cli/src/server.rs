// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule search` and `remule ping`: talk to an eD2k server.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ed2k_server::session::Event;
use ed2k_server::{udp, ConnectOptions, LoginInfo, SearchParams, SearchResult, ServerClient};
use ed2k_types::tags::FileType;

/// What `remule search` was asked.
#[derive(Debug, Clone)]
pub struct SearchArgs {
    pub server: SocketAddr,
    pub query: String,
    pub obfuscate: bool,
    pub nick: String,
    pub port: u16,
    pub file_type: Option<FileType>,
    pub min_size: u64,
    pub max_size: u64,
    pub extension: String,
    pub more: usize,
    pub limit: usize,
    pub verbose: bool,
}

/// Parse a size: bytes, or with K, M, G (powers of 1024).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') => (&s[..s.len() - 1], 1 << 20),
        Some('G') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| format!("bad size {s:?} (bytes, or a number with K, M or G)"))
}

/// A file type by the names aMule's search dialog uses.
pub fn parse_file_type(s: &str) -> Result<FileType, String> {
    let l = s.to_ascii_lowercase();
    FileType::ALL
        .into_iter()
        .find(|t| {
            let name = format!("{t:?}").to_ascii_lowercase();
            l == name || l == t.as_str().to_ascii_lowercase()
        })
        .ok_or_else(|| {
            let names: Vec<String> = FileType::ALL.iter().map(|t| format!("{t:?}")).collect();
            format!("unknown file type {s:?} (one of {})", names.join(", "))
        })
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

fn print_results(results: &mut [SearchResult], limit: usize, verbose: bool) {
    // Most sources first, as aMule's list sorts by default.
    results.sort_by(|a, b| b.sources.cmp(&a.sources).then(a.name.cmp(&b.name)));
    println!("{:>7} {:>10}  name", "sources", "size");
    for r in results.iter().take(limit) {
        println!("{:>7} {:>10}  {}", r.sources, human(r.size), r.name);
        if verbose {
            println!(
                "{:>18}  ed2k://|file|{}|{}|{}|/",
                "",
                ed2k_hash::cleanup_name(&r.name),
                r.size,
                r.hash
            );
        }
    }
    if results.len() > limit {
        println!("... and {} more (--limit)", results.len() - limit);
    }
}

fn print_event(e: &Event) {
    match e {
        Event::Message(m) => println!("server: {m}"),
        Event::Error(m) => println!("server ERROR: {m}"),
        Event::Warning(m) => println!("server WARNING: {m}"),
        _ => {}
    }
}

/// Log in, search, print. Returns whether it worked.
pub async fn search(a: SearchArgs) -> Result<(), String> {
    let hash = ed2k_server::packets::new_user_hash(&mut rand::thread_rng());
    let mut login = LoginInfo::new(hash, a.port, a.nick.clone());
    login.crypt_requested = a.obfuscate;
    let mut opts = ConnectOptions::new(login);
    opts.obfuscate = a.obfuscate;
    // Not a client that keeps a server list.
    opts.session.ask_server_list = false;

    let t = Instant::now();
    println!(
        "connecting to {}{} ...",
        a.server,
        if a.obfuscate { " (obfuscated)" } else { "" }
    );
    let (mut client, li) = ServerClient::connect(a.server, opts)
        .await
        .map_err(|e| format!("{}: {e}", a.server))?;
    for e in client.drain_events() {
        print_event(&e);
    }
    let info = client.info();
    println!(
        "logged in after {:.1}s: {} ID {}{}",
        t.elapsed().as_secs_f64(),
        if li.low_id { "LowID" } else { "HighID" },
        li.id,
        info.version
            .as_deref()
            .map(|v| format!(", server version {v}"))
            .unwrap_or_default()
    );

    let mut params = SearchParams::new(a.query.clone());
    params.file_type = a.file_type;
    params.min_size = a.min_size;
    params.max_size = a.max_size;
    params.extension = a.extension.clone();
    let mut results = client
        .search(&params, Duration::from_secs(30), a.more + 1)
        .await
        .map_err(|e| format!("search: {e}"))?;
    for e in client.drain_events() {
        print_event(&e);
    }
    let info = client.info();
    if let Some(name) = &info.name {
        println!("server name: {name}");
    }
    if info.users > 0 {
        println!("server: {} users, {} files", info.users, info.files);
    }
    println!("{} results for {:?}", results.len(), a.query);
    print_results(&mut results, a.limit, a.verbose);
    Ok(())
}

/// One UDP status ping (to the server's TCP port + 4).
pub async fn ping(server: SocketAddr, wait: Duration) -> Result<(), String> {
    let sock = tokio::net::UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(|e| e.to_string())?;
    let mut to = server;
    to.set_port(server.port().wrapping_add(udp::UDP_PORT_OFFSET));
    let challenge = udp::ping_challenge(&mut rand::thread_rng());
    let t = Instant::now();
    sock.send_to(&udp::ping(challenge).to_udp_bytes(), to)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 2048];
    let answer = tokio::time::timeout(wait, async {
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if from.ip() != to.ip() {
                continue;
            }
            if let Some(s) = udp::parse_ping_answer(&buf[..n]) {
                if s.challenge == challenge {
                    return Ok::<_, std::io::Error>(s);
                }
            }
        }
    })
    .await
    .map_err(|_| format!("no answer from {to} within {wait:?}"))?
    .map_err(|e| e.to_string())?;
    println!(
        "{to}: {} ms, {} users ({} LowID, max {}), {} files (soft {} / hard {})",
        t.elapsed().as_millis(),
        answer.users,
        answer.low_id_users,
        answer.max_users,
        answer.files,
        answer.soft_files,
        answer.hard_files
    );
    println!(
        "  UDP flags {:#x}, obfuscation ports TCP {} / UDP {}",
        answer.udp_flags, answer.tcp_obfuscation_port, answer.udp_obfuscation_port
    );
    Ok(())
}
