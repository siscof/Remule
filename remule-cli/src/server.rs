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
    /// Other servers to ask over UDP (a global search).
    pub global: Vec<SocketAddr>,
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
    if !a.global.is_empty() {
        let more = global_search(&a.global, &params, a.obfuscate).await?;
        // The same file from several servers: one line, the most sources.
        for r in more {
            match results.iter_mut().find(|x| x.hash == r.hash) {
                Some(x) => x.sources = x.sources.max(r.sources),
                None => results.push(r),
            }
        }
        println!("{} results with the other servers'", results.len());
    }
    print_results(&mut results, a.limit, a.verbose);
    Ok(())
}

/// The UDP half of a global search (`CSearchList::OnGlobalSearchTimer`):
/// each server pinged for its UDP flags and key, then sent the request
/// that suits it, 750 ms apart; answers gathered until a few seconds after
/// the last.
async fn global_search(
    servers: &[SocketAddr],
    params: &SearchParams,
    obfuscate: bool,
) -> Result<Vec<SearchResult>, String> {
    let (payload, uses_64bit) =
        ed2k_server::search::encode_search(params, true).map_err(|e| e.to_string())?;
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    let mut keys: Vec<(std::net::IpAddr, u32)> = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut out = Vec::new();
    for &server in servers {
        let status = match status_of(&sock, server, Duration::from_secs(3)).await {
            Ok(s) => s,
            Err(e) => {
                println!("  {server}: {e}");
                continue;
            }
        };
        let Some(req) = udp::global_search(&payload, uses_64bit, status.udp_flags) else {
            println!("  {server}: no large files over UDP, not asked");
            continue;
        };
        let bytes = req.to_udp_bytes();
        use ed2k_types::ed2k::server_udp::flags;
        let crypt = obfuscate
            && status.udp_flags & flags::UDPOBFUSCATION != 0
            && status.udp_key != 0
            && status.udp_obfuscation_port != 0;
        let (to, wire) = if crypt {
            keys.push((server.ip(), status.udp_key));
            let mut to = server;
            to.set_port(status.udp_obfuscation_port);
            (
                to,
                udp::obfuscate(&bytes, status.udp_key, &mut rand::thread_rng()),
            )
        } else {
            let mut to = server;
            to.set_port(server.port().wrapping_add(udp::UDP_PORT_OFFSET));
            (to, bytes)
        };
        println!(
            "  {server}: asking with {:#04x}{}",
            req.opcode,
            if crypt { ", obfuscated" } else { "" }
        );
        sock.send_to(&wire, to).await.map_err(|e| e.to_string())?;
        // 750 ms to the next, reading what comes meanwhile.
        let until = tokio::time::Instant::now() + Duration::from_millis(750);
        while let Ok(Ok((n, from))) = tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await
        {
            take_results(&buf[..n], from, &keys, &mut out);
        }
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await {
        take_results(&buf[..n], from, &keys, &mut out);
    }
    Ok(out)
}

/// Global search answers in a datagram (decrypted with the server's key
/// when it was asked obfuscated).
fn take_results(
    datagram: &[u8],
    from: SocketAddr,
    keys: &[(std::net::IpAddr, u32)],
    out: &mut Vec<SearchResult>,
) {
    let key = keys
        .iter()
        .find(|(ip, _)| *ip == from.ip())
        .map_or(0, |k| k.1);
    let plain = udp::deobfuscate(datagram, key);
    if let Some(r) = udp::parse_global_search_results(&plain) {
        println!("  {from}: {} results", r.len());
        out.extend(r);
    }
}

/// A server's UDP status (the plain ping), for its flags and key.
async fn status_of(
    sock: &tokio::net::UdpSocket,
    server: SocketAddr,
    wait: Duration,
) -> Result<udp::UdpStatus, String> {
    let mut to = server;
    to.set_port(server.port().wrapping_add(udp::UDP_PORT_OFFSET));
    let challenge = udp::ping_challenge(&mut rand::thread_rng());
    sock.send_to(&udp::ping(challenge).to_udp_bytes(), to)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 2048];
    tokio::time::timeout(wait, async {
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
    .map_err(|_| format!("no status answer within {wait:?}"))?
    .map_err(|e| e.to_string())
}

/// One UDP status ping: plain to the server's TCP port + 4, or obfuscated
/// to its port + 12.
pub async fn ping(server: SocketAddr, wait: Duration, obfuscated: bool) -> Result<(), String> {
    let sock = tokio::net::UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(|e| e.to_string())?;
    let mut to = server;
    let offset = if obfuscated {
        udp::CRYPT_PING_PORT_OFFSET
    } else {
        udp::UDP_PORT_OFFSET
    };
    to.set_port(server.port().wrapping_add(offset));
    let mut rng = rand::thread_rng();
    let (challenge, wire) = if obfuscated {
        let c = rand::Rng::gen::<u32>(&mut rng).max(1);
        (c, udp::crypt_ping(c, &mut rng))
    } else {
        let c = udp::ping_challenge(&mut rng);
        (c, udp::ping(c).to_udp_bytes())
    };
    let t = Instant::now();
    sock.send_to(&wire, to).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 2048];
    let answer = tokio::time::timeout(wait, async {
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if from.ip() != to.ip() {
                continue;
            }
            let s = if obfuscated {
                udp::parse_crypt_ping_answer(&buf[..n], challenge)
            } else {
                udp::parse_ping_answer(&buf[..n]).filter(|s| s.challenge == challenge)
            };
            if let Some(s) = s {
                return Ok::<_, std::io::Error>(s);
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
