// SPDX-License-Identifier: GPL-2.0-or-later
//! A scripted stand-in for `amuled`, so the GUI can be worked on without a
//! daemon. It speaks the real EC login (SRP + AEAD) and answers the requests
//! remule-gui sends with made-up but self-consistent data: downloads that
//! progress, a server list, Kad state, search results and a log.
//!
//!     cargo run -p remule-ec --features fake-daemon --example fake_amuled -- [port] [password]
//!
//! Defaults: port 4712, password "secret". Listens on 127.0.0.1 only.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use remule_ec::codes::*;
use remule_ec::{fake, srp, Packet, Tag};

const PART: u64 = 9_728_000;

struct File {
    ecid: u32,
    hash: [u8; 16],
    name: String,
    size: u64,
    done: f64,
    speed: u64,
    paused: bool,
    prio: u64,
    sources: u64,
}

struct Server {
    ip: [u8; 4],
    port: u16,
    name: &'static str,
    users: u64,
    files: u64,
    ping: u64,
}

struct State {
    started: Instant,
    last_tick: Instant,
    next_ecid: u32,
    files: Vec<File>,
    servers: Vec<Server>,
    connected_server: Option<usize>,
    kad: bool,
    log: Vec<String>,
    search: Option<(String, Instant)>,
}

fn hash_of(s: &str) -> [u8; 16] {
    let d = srp::password_digest(s); // any stable 16 bytes will do
    let mut h = [0u8; 16];
    for (i, b) in h.iter_mut().enumerate() {
        *b = u8::from_str_radix(&d[2 * i..2 * i + 2], 16).unwrap();
    }
    h
}

impl State {
    fn new() -> Self {
        let mut s = State {
            started: Instant::now(),
            last_tick: Instant::now(),
            next_ecid: 1,
            files: Vec::new(),
            servers: vec![
                Server {
                    ip: [176, 123, 5, 89],
                    port: 4725,
                    name: "eMule Security",
                    users: 214_332,
                    files: 41_870_101,
                    ping: 48,
                },
                Server {
                    ip: [45, 82, 80, 155],
                    port: 5687,
                    name: "eMule Sunrise",
                    users: 95_120,
                    files: 18_220_333,
                    ping: 61,
                },
                Server {
                    ip: [91, 208, 184, 143],
                    port: 4232,
                    name: "Astra-2",
                    users: 12_004,
                    files: 3_120_771,
                    ping: 102,
                },
            ],
            connected_server: Some(0),
            kad: true,
            log: vec![
                "aMule 3.3.0-fake is up".into(),
                "Connected to eMule Security (176.123.5.89:4725) with High ID".into(),
            ],
            // A finished search, so the Searches page has something to show.
            search: Some((
                "ubuntu".into(),
                Instant::now() - std::time::Duration::from_secs(60),
            )),
        };
        for (name, size, done, speed, sources) in [
            (
                "debian-13.1.0-amd64-netinst.iso",
                754_974_720u64,
                0.62,
                184_000u64,
                41u64,
            ),
            (
                "Big Buck Bunny (2008) 1080p.mkv",
                928_670_754,
                0.18,
                412_000,
                87,
            ),
            (
                "archlinux-2026.11.01-x86_64.iso",
                1_288_490_188,
                1.0,
                0,
                120,
            ),
            ("Free Software Song - Stallman.ogg", 4_350_112, 0.05, 0, 2),
        ] {
            s.add_file(name, size, done, speed, sources);
        }
        s.files[3].paused = true;
        s
    }

    fn add_file(&mut self, name: &str, size: u64, done: f64, speed: u64, sources: u64) {
        let ecid = self.next_ecid;
        self.next_ecid += 1;
        self.files.push(File {
            ecid,
            hash: hash_of(name),
            name: name.into(),
            size,
            done,
            speed,
            paused: false,
            prio: 11,
            sources,
        });
    }

    /// Advance the simulation to now.
    fn tick(&mut self) {
        let dt = self.last_tick.elapsed().as_secs_f64();
        self.last_tick = Instant::now();
        let t = self.started.elapsed().as_secs_f64();
        let mut finished = Vec::new();
        for (i, f) in self.files.iter_mut().enumerate() {
            if f.paused || f.done >= 1.0 {
                f.speed = 0;
                continue;
            }
            // Wobbling, plausible rates.
            let base = 60_000.0 + 40_000.0 * (i as f64 + 1.0);
            f.speed = (base * (1.0 + 0.4 * (t / 7.0 + i as f64).sin())) as u64;
            f.done = (f.done + f.speed as f64 * dt / f.size as f64).min(1.0);
            if f.done >= 1.0 {
                finished.push(f.name.clone());
            }
        }
        for n in finished {
            self.log.push(format!("Completed download of {n}"));
        }
    }

    /// `log_cursor` is per connection, like the daemon's CLoggerAccess.
    fn stats(&mut self, log_cursor: &mut usize) -> Packet {
        self.tick();
        let dl: u64 = self.files.iter().map(|f| f.speed).sum();
        let t = self.started.elapsed().as_secs_f64();
        let ul = (30_000.0 * (1.2 + (t / 11.0).sin())) as u64;
        let mut bits = 0u64;
        let mut conn = Tag::int(EC_TAG_CONNSTATE, 0);
        if let Some(i) = self.connected_server {
            bits |= 0x01;
            let s = &self.servers[i];
            conn = conn
                .with(server_tag(s))
                .with(Tag::int(EC_TAG_ED2K_ID, 0x5D1A_2B3C));
        }
        if self.kad {
            bits |= 0x04 | 0x10;
            conn = conn.with(Tag::custom(EC_TAG_KAD_ID, hash_of("kad").to_vec()));
        }
        conn.data = vec![bits as u8];
        conn = conn
            .with(Tag::int(EC_TAG_NETWORKS_ENABLED, 3))
            .with(Tag::int(EC_TAG_CLIENT_ID, 0x5D1A_2B3C));

        let mut p = Packet::new(EC_OP_STATS)
            .with(Tag::int(EC_TAG_STATS_DL_SPEED, dl))
            .with(Tag::int(EC_TAG_STATS_UL_SPEED, ul))
            .with(Tag::int(EC_TAG_STATS_DL_SPEED_LIMIT, 0))
            .with(Tag::int(EC_TAG_STATS_UL_SPEED_LIMIT, 100 * 1024))
            .with(Tag::int(EC_TAG_STATS_UP_OVERHEAD, 1_200))
            .with(Tag::int(EC_TAG_STATS_DOWN_OVERHEAD, 2_100))
            .with(Tag::int(EC_TAG_STATS_UL_QUEUE_LEN, 312))
            .with(Tag::int(
                EC_TAG_STATS_TOTAL_SRC_COUNT,
                self.files.iter().map(|f| f.sources).sum(),
            ))
            .with(Tag::int(EC_TAG_STATS_BANNED_COUNT, 3))
            .with(Tag::int(
                EC_TAG_STATS_ED2K_USERS,
                self.connected_server.map_or(0, |i| self.servers[i].users),
            ))
            .with(Tag::int(
                EC_TAG_STATS_ED2K_FILES,
                self.connected_server.map_or(0, |i| self.servers[i].files),
            ))
            .with(Tag::int(
                EC_TAG_STATS_KAD_USERS,
                if self.kad { 3_412_000 } else { 0 },
            ))
            .with(Tag::int(
                EC_TAG_STATS_KAD_FILES,
                if self.kad { 512_400_000 } else { 0 },
            ))
            .with(Tag::int(
                EC_TAG_STATS_KAD_NODES,
                if self.kad { 1_874 } else { 0 },
            ))
            .with(Tag::int(
                EC_TAG_STATS_SESSION_RECEIVED_BYTES,
                (t * 250_000.0) as u64,
            ))
            .with(Tag::int(
                EC_TAG_STATS_SESSION_SENT_BYTES,
                (t * 35_000.0) as u64,
            ))
            .with(Tag::int(
                EC_TAG_STATS_TOTAL_RECEIVED_BYTES,
                412_000_000_000 + (t * 250_000.0) as u64,
            ))
            .with(Tag::int(
                EC_TAG_STATS_TOTAL_SENT_BYTES,
                98_000_000_000 + (t * 35_000.0) as u64,
            ))
            .with(Tag::int(EC_TAG_STATS_SHARED_FILE_COUNT, 3))
            .with(Tag::int(EC_TAG_STATS_UPTIME_SECONDS, 86_400 * 3 + t as u64))
            .with(Tag::int(EC_TAG_STATS_ACTIVE_CONNECTIONS, 57))
            .with(Tag::int(EC_TAG_STATS_TEMP_FREE_SPACE, 212_000_000_000))
            .with(Tag::int(EC_TAG_STATS_INCOMING_FREE_SPACE, 212_000_000_000))
            .with(conn);
        if *log_cursor < self.log.len() {
            let mut lt = Tag::empty(EC_TAG_STATS_LOGGER_MESSAGE);
            for l in &self.log[*log_cursor..] {
                lt = lt.with(Tag::string(EC_TAG_STRING, l));
            }
            *log_cursor = self.log.len();
            p = p.with(lt);
        }
        p
    }

    fn file_mut(&mut self, hash: Option<[u8; 16]>) -> Option<&mut File> {
        let h = hash?;
        self.files.iter_mut().find(|f| f.hash == h)
    }

    fn handle(&mut self, req: &Packet, log_cursor: &mut usize) -> Packet {
        let ok = Packet::new(EC_OP_NOOP);
        match req.opcode {
            EC_OP_STAT_REQ => self.stats(log_cursor),
            EC_OP_GET_DLOAD_QUEUE => {
                self.tick();
                let mut p = Packet::new(EC_OP_DLOAD_QUEUE);
                for f in &self.files {
                    let complete = f.done >= 1.0;
                    let status = if complete {
                        9
                    } else if f.paused {
                        7
                    } else {
                        0
                    };
                    let xfer = if f.speed > 0 {
                        (f.sources / 6).max(1)
                    } else {
                        0
                    };
                    let done = (f.done * f.size as f64) as u64;
                    p = p.with(
                        Tag::int(EC_TAG_PARTFILE, u64::from(f.ecid))
                            .with(Tag::string(EC_TAG_PARTFILE_NAME, &f.name))
                            .with(Tag::hash(EC_TAG_PARTFILE_HASH, f.hash))
                            .with(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, f.size))
                            .with(Tag::int(EC_TAG_PARTFILE_SIZE_DONE, done))
                            .with(Tag::int(EC_TAG_PARTFILE_SIZE_XFER, done))
                            .with(Tag::int(EC_TAG_PARTFILE_SPEED, f.speed))
                            .with(Tag::int(EC_TAG_PARTFILE_STATUS, status))
                            .with(Tag::int(EC_TAG_PARTFILE_PRIO, f.prio))
                            .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT, f.sources))
                            .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER, xfer))
                            .with(Tag::int(
                                EC_TAG_PARTFILE_AVAILABLE_PARTS,
                                f.size.div_ceil(PART),
                            ))
                            .with(Tag::string(
                                EC_TAG_PARTFILE_ED2K_LINK,
                                &format!("ed2k://|file|{}|{}|{}|/", f.name, f.size, hex(&f.hash)),
                            )),
                    );
                }
                p
            }
            EC_OP_GET_SHARED_FILES => {
                let mut p = Packet::new(EC_OP_SHARED_FILES);
                for (i, f) in self.files.iter().filter(|f| f.done >= 1.0).enumerate() {
                    p = p.with(
                        Tag::int(EC_TAG_KNOWNFILE, u64::from(f.ecid))
                            .with(Tag::string(EC_TAG_PARTFILE_NAME, &f.name))
                            .with(Tag::hash(EC_TAG_PARTFILE_HASH, f.hash))
                            .with(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, f.size))
                            .with(Tag::string(
                                EC_TAG_KNOWNFILE_PATH,
                                "/home/amule/.aMule/Incoming",
                            ))
                            .with(Tag::int(
                                EC_TAG_KNOWNFILE_XFERRED,
                                40_000_000 * (i as u64 + 1),
                            ))
                            .with(Tag::int(
                                EC_TAG_KNOWNFILE_XFERRED_ALL,
                                900_000_000 * (i as u64 + 1),
                            ))
                            .with(Tag::int(EC_TAG_KNOWNFILE_REQ_COUNT, 12))
                            .with(Tag::int(EC_TAG_KNOWNFILE_REQ_COUNT_ALL, 340))
                            .with(Tag::int(EC_TAG_KNOWNFILE_ACCEPT_COUNT, 5))
                            .with(Tag::int(EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL, 120))
                            .with(Tag::int(EC_TAG_KNOWNFILE_PRIO, 11))
                            .with(Tag::int(EC_TAG_KNOWNFILE_COMPLETE_SOURCES, f.sources))
                            .with(Tag::string(
                                EC_TAG_PARTFILE_ED2K_LINK,
                                &format!("ed2k://|file|{}|{}|{}|/", f.name, f.size, hex(&f.hash)),
                            )),
                    );
                }
                p
            }
            EC_OP_GET_SERVER_LIST => {
                let mut p = Packet::new(EC_OP_SERVER_LIST);
                for s in &self.servers {
                    p = p.with(server_tag(s));
                }
                p
            }
            EC_OP_SERVER_CONNECT => {
                let want = req.tag(EC_TAG_SERVER).and_then(Tag::as_ipv4);
                let idx = match want {
                    Some((ip, port)) => self
                        .servers
                        .iter()
                        .position(|s| s.ip == ip && s.port == port),
                    None => Some(0),
                };
                match idx {
                    Some(i) => {
                        self.connected_server = Some(i);
                        self.log.push(format!(
                            "Connected to {} with High ID",
                            self.servers[i].name
                        ));
                        ok
                    }
                    None => failed("server not found"),
                }
            }
            EC_OP_SERVER_DISCONNECT => {
                self.connected_server = None;
                self.log.push("Disconnected from eD2k server".into());
                ok
            }
            EC_OP_SERVER_REMOVE => {
                let Some((ip, port)) = req.tag(EC_TAG_SERVER).and_then(Tag::as_ipv4) else {
                    return failed("need to define server to be removed");
                };
                match self.servers.iter().position(|s| s.ip == ip && s.port == port) {
                    Some(i) if self.connected_server == Some(i) => failed("You are connected to the server you are trying to delete. please disconnect first."),
                    Some(i) => {
                        self.servers.remove(i);
                        if let Some(c) = self.connected_server.as_mut() {
                            if *c > i {
                                *c -= 1;
                            }
                        }
                        ok
                    }
                    None => failed("server not found"),
                }
            }
            EC_OP_SERVER_ADD => {
                let addr = req
                    .tag(EC_TAG_SERVER_ADDRESS)
                    .map(Tag::as_str)
                    .unwrap_or_default();
                let Some((host, port)) = addr.rsplit_once(':') else {
                    return failed("Server not added");
                };
                let ip: Vec<u8> = host.split('.').filter_map(|x| x.parse().ok()).collect();
                let (Ok(port), &[a, b, c, d]) = (port.parse(), &ip[..]) else {
                    return failed("Server not added");
                };
                self.servers.push(Server {
                    ip: [a, b, c, d],
                    port,
                    name: "Added server",
                    users: 0,
                    files: 0,
                    ping: 0,
                });
                ok
            }
            EC_OP_CONNECT => {
                self.connected_server = Some(0);
                self.kad = true;
                ok
            }
            EC_OP_DISCONNECT => {
                self.connected_server = None;
                self.kad = false;
                ok
            }
            EC_OP_KAD_START => {
                self.kad = true;
                ok
            }
            EC_OP_KAD_STOP => {
                self.kad = false;
                ok
            }
            EC_OP_ADD_LINK => {
                for t in &req.tags {
                    let link = t.as_str();
                    // ed2k://|file|NAME|SIZE|HASH|/
                    let parts: Vec<&str> = link.split('|').collect();
                    if parts.len() >= 5 && parts[1] == "file" {
                        let size = parts[3].parse().unwrap_or(0);
                        self.add_file(parts[2], size, 0.0, 0, 1);
                        self.log
                            .push(format!("ExternalConn: adding link '{link}'."));
                    } else {
                        return failed("Invalid link or already on list.");
                    }
                }
                ok
            }
            EC_OP_PARTFILE_PAUSE | EC_OP_PARTFILE_STOP | EC_OP_PARTFILE_RESUME => {
                for t in &req.tags {
                    let Some(f) = self.file_mut(t.as_hash()) else {
                        return failed("FileHash not found");
                    };
                    f.paused = req.opcode != EC_OP_PARTFILE_RESUME;
                }
                ok
            }
            EC_OP_PARTFILE_PRIO_SET => {
                for t in &req.tags {
                    let prio = t.children.first().map_or(1, Tag::as_int);
                    if let Some(f) = self.file_mut(t.as_hash()) {
                        f.prio = if prio == 5 { 11 } else { prio };
                    }
                }
                ok
            }
            EC_OP_PARTFILE_DELETE => {
                let hashes: Vec<_> = req.tags.iter().filter_map(Tag::as_hash).collect();
                self.files.retain(|f| !hashes.contains(&f.hash));
                ok
            }
            EC_OP_CLEAR_COMPLETED => {
                let ids: Vec<u64> = req.tags.iter().map(Tag::as_int).collect();
                self.files
                    .retain(|f| !(f.done >= 1.0 && ids.contains(&u64::from(f.ecid))));
                ok
            }
            EC_OP_SEARCH_START => {
                let text = req
                    .tags
                    .first()
                    .map(|t| t.child_str(EC_TAG_SEARCH_NAME))
                    .unwrap_or_default();
                self.search = Some((text, Instant::now()));
                Packet::new(EC_OP_STRINGS).with(Tag::string(
                    EC_TAG_STRING,
                    "Search in progress. Refetch results in a moment!",
                ))
            }
            EC_OP_SEARCH_STOP => {
                if let Some((_, t)) = &mut self.search {
                    *t = Instant::now() - std::time::Duration::from_secs(60);
                }
                Packet::new(EC_OP_MISC_DATA)
            }
            EC_OP_SEARCH_PROGRESS => {
                let (state, pct) = match &self.search {
                    None => (0, 0),
                    Some((_, t)) => {
                        let p = (t.elapsed().as_secs_f64() / 8.0 * 100.0).min(100.0) as u64;
                        (if p >= 100 { 2 } else { 1 }, p)
                    }
                };
                Packet::new(EC_OP_SEARCH_PROGRESS)
                    .with(Tag::int(EC_TAG_SEARCH_LIFECYCLE_STATE, state))
                    .with(Tag::int(EC_TAG_SEARCH_LIFECYCLE_PERCENT, pct))
            }
            EC_OP_SEARCH_RESULTS => {
                let mut p = Packet::new(EC_OP_SEARCH_RESULTS);
                let Some((text, t)) = &self.search else {
                    return p;
                };
                // Results trickle in over the search's 8 seconds.
                let n = ((t.elapsed().as_secs_f64() / 8.0).min(1.0) * 24.0) as u64;
                for i in 0..n {
                    let name = result_name(text, i);
                    let hash = hash_of(&name);
                    let status = if self.files.iter().any(|f| f.hash == hash) {
                        2
                    } else {
                        0
                    };
                    p = p.with(
                        Tag::int(EC_TAG_SEARCHFILE, 10_000 + i)
                            .with(Tag::string(EC_TAG_PARTFILE_NAME, &name))
                            .with(Tag::hash(EC_TAG_PARTFILE_HASH, hash))
                            .with(Tag::int(
                                EC_TAG_PARTFILE_SIZE_FULL,
                                1_000_000 + i * 37_000_000,
                            ))
                            .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT, 1 + (i * 7) % 53))
                            .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER, (i * 3) % 11))
                            .with(Tag::int(EC_TAG_PARTFILE_STATUS, status)),
                    );
                }
                p
            }
            EC_OP_DOWNLOAD_SEARCH_RESULT => {
                let Some((text, _)) = self.search.clone() else {
                    return failed("No open search holds this result.");
                };
                for t in &req.tags {
                    let Some(h) = t.as_hash() else { continue };
                    let name = (0..24u64)
                        .map(|i| result_name(&text, i))
                        .find(|n| hash_of(n) == h);
                    if let Some(n) = name {
                        self.add_file(&n, 700_000_000, 0.0, 0, 9);
                    }
                }
                Packet::new(EC_OP_STRINGS)
            }
            EC_OP_SHARED_SET_PRIO | EC_OP_SHAREDFILES_RELOAD => ok,
            EC_OP_GET_LOG => {
                Packet::new(EC_OP_LOG).with(Tag::string(EC_TAG_STRING, &self.log.join("\n")))
            }
            op => failed(&format!("fake_amuled does not implement opcode {op:#04x}")),
        }
    }
}

/// The fake search's i-th result name.
fn result_name(query: &str, i: u64) -> String {
    let tag = ["", " remastered", " final", " v2", " complete"][i as usize % 5];
    let ext = ["iso", "mkv", "avi", "zip", "pdf", "mp3"][i as usize % 6];
    format!("{query}{tag} [{}].{ext}", 2000 + i * 3 % 26)
}

fn server_tag(s: &Server) -> Tag {
    Tag::ipv4(EC_TAG_SERVER, s.ip, s.port)
        .with(Tag::string(EC_TAG_SERVER_NAME, s.name))
        .with(Tag::string(EC_TAG_SERVER_DESC, "simulated by fake_amuled"))
        .with(Tag::int(EC_TAG_SERVER_USERS, s.users))
        .with(Tag::int(EC_TAG_SERVER_USERS_MAX, s.users * 2))
        .with(Tag::int(EC_TAG_SERVER_FILES, s.files))
        .with(Tag::int(EC_TAG_SERVER_PING, s.ping))
        .with(Tag::string(EC_TAG_SERVER_VERSION, "17.15"))
}

fn failed(msg: &str) -> Packet {
    Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, msg))
}

fn hex(h: &[u8; 16]) -> String {
    h.iter().map(|b| format!("{b:02X}")).collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(4712);
    let password = args.next().unwrap_or_else(|| "secret".into());
    let login = fake::Login {
        digest: srp::password_digest(&password),
        version: "3.3.0-fake".into(),
        tamper_m2: false,
    };
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    eprintln!("fake_amuled: EC on 127.0.0.1:{port}, password {password:?}");
    let state = Arc::new(Mutex::new(State::new()));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let (login, state) = (login.clone(), state.clone());
        thread::spawn(move || match fake::accept(stream, &login) {
            Ok(Some(conn)) => {
                eprintln!("fake_amuled: client logged in");
                let mut log_cursor = 0;
                let r = conn.serve(|req| state.lock().unwrap().handle(req, &mut log_cursor));
                eprintln!("fake_amuled: client left ({r:?})");
            }
            Ok(None) => eprintln!("fake_amuled: login refused"),
            Err(e) => eprintln!("fake_amuled: handshake error: {e}"),
        });
    }
}
