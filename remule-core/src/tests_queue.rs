// SPDX-License-Identifier: GPL-2.0-or-later
//! The download queue against scripted seeders: first without IO, every
//! packet through the real encoder and parser; then on tokio over real
//! TCP connections, obfuscated and plain.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_hash::aich::AichTree;
use ed2k_hash::FileHashes;
use ed2k_peer::hello::{CryptSettings, MiscOptions2};
use ed2k_peer::packets::{self, AichRecovery, MultiAnswer, MultiRequest, ParseContext};
use ed2k_peer::sources::{AnswerBuilder, ExchangedSource};
use ed2k_peer::udp::UdpPacket;
use ed2k_peer::{Hello, PartStatus, PeerPacket};
use ed2k_types::ed2k::{EMBLOCKSIZE, PARTSIZE};
use ed2k_types::Md4Hash;

use crate::download_queue::{
    crypt, Action, ConnId, DownloadQueue, Endpoint, Origin, QueueConfig, Report, SourceState,
    UdpOut,
};
use crate::tests_part_file::{data, hashes, parts, TempDir};
use crate::PartFile;

const SIZE: u64 = 2 * PARTSIZE + 12_345;

fn ip_id(ip: Ipv4Addr) -> u32 {
    u32::from_le_bytes(ip.octets())
}

/// An uploader as far as a download needs one.
#[derive(Clone)]
struct Seeder {
    hello: Hello,
    data: Arc<Vec<u8>>,
    hashes: Arc<FileHashes>,
    name: String,
    parts: PartStatus,
    /// Sources to give when asked.
    exchange: Vec<ExchangedSource>,
    /// Queue the downloader instead of giving it a slot.
    queue_first: bool,
    /// Answer the file request with "no such file".
    no_file: bool,
    /// Flip a byte at these offsets, once each.
    corrupt: Arc<Mutex<HashSet<u64>>>,
}

impl Seeder {
    fn new(ip: Ipv4Addr, port: u16, d: Arc<Vec<u8>>, h: Arc<FileHashes>, have: PartStatus) -> Self {
        // A user hash of its own: address and port.
        let mut uh = [0u8; 16];
        uh[..4].copy_from_slice(&ip.octets());
        uh[4..6].copy_from_slice(&port.to_le_bytes());
        uh[15] = 0x5E;
        let mut hello = Hello::amule(Md4Hash(uh), ip_id(ip), port, "seeder");
        hello.misc2 = Some(MiscOptions2::amule(
            0,
            CryptSettings {
                supported: true,
                requested: false,
                required: false,
            },
        ));
        Seeder {
            hello,
            data: d,
            hashes: h,
            name: "test file.bin".into(),
            parts: have,
            exchange: Vec::new(),
            queue_first: false,
            no_file: false,
            corrupt: Arc::default(),
        }
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint {
            addr: SocketAddrV4::new(Ipv4Addr::from(self.hello.id.to_le_bytes()), self.hello.port),
            user_hash: Some(self.hello.user_hash),
            crypt: crypt::SUPPORTED,
            buddy: None,
            direct_udp: None,
        }
    }

    fn file(&self) -> Md4Hash {
        self.hashes.ed2k
    }

    /// What the seeder answers to one packet from the downloader.
    fn answer(&self, p: Packet) -> Vec<Packet> {
        let ctx = ParseContext {
            unicode: true,
            extended_requests_version: 2,
        };
        let file = self.file();
        match PeerPacket::parse(p, ctx).unwrap() {
            PeerPacket::Hello(_) => vec![self.hello.to_hello_answer().unwrap()],
            PeerPacket::MultiPacket { hash, requests, .. } => {
                assert_eq!(hash, file);
                if self.no_file {
                    return vec![packets::no_such_file(hash)];
                }
                let mut answers = Vec::new();
                let mut out = Vec::new();
                for r in requests {
                    match r {
                        MultiRequest::FileName(_) => {
                            answers.push(MultiAnswer::FileName(self.name.clone()))
                        }
                        MultiRequest::FileStatus => {
                            answers.push(MultiAnswer::FileStatus(self.parts.clone()))
                        }
                        MultiRequest::AichFileHash => {
                            answers.push(MultiAnswer::AichFileHash(self.hashes.aich_root.unwrap()))
                        }
                        MultiRequest::Sources2 { version, .. } => {
                            let mut b = AnswerBuilder::new(hash, true, 3, version);
                            self.exchange.iter().for_each(|s| b.add(s));
                            out.extend(b.finish());
                        }
                        _ => {}
                    }
                }
                let mut v = vec![packets::multi_packet_answer(hash, &answers, true)];
                v.extend(out);
                v
            }
            PeerPacket::HashSetRequest(h) => {
                vec![packets::hash_set_answer(h, &self.hashes.part_hashes)]
            }
            PeerPacket::StartUploadReq(_) => {
                if self.queue_first {
                    vec![packets::queue_ranking(3)]
                } else {
                    vec![packets::accept_upload_req()]
                }
            }
            PeerPacket::RequestParts { hash, ranges } => ranges
                .into_iter()
                .map(|r| {
                    assert!(self.parts.has((r.start / PARTSIZE) as usize));
                    let mut piece = self.data[r.start as usize..r.end as usize].to_vec();
                    let mut bad = self.corrupt.lock().unwrap();
                    for off in bad.clone() {
                        if r.contains(&off) {
                            piece[(off - r.start) as usize] ^= 0xFF;
                            bad.remove(&off);
                        }
                    }
                    packets::sending_part(hash, r.start, &piece)
                })
                .collect(),
            PeerPacket::AichRequest { hash, part, root } => {
                let mut tree = AichTree::from_blocks(SIZE, &self.hashes.aich_blocks).unwrap();
                let data = tree.part_recovery_data(u64::from(part) * PARTSIZE).unwrap();
                vec![packets::aich_answer(&AichRecovery {
                    hash,
                    part,
                    root,
                    data,
                })]
            }
            _ => Vec::new(),
        }
    }
}

fn ours() -> Hello {
    let mut h = Hello::amule(
        Md4Hash([0x77; 16]),
        ip_id(Ipv4Addr::new(10, 99, 0, 1)),
        4662,
        "remule",
    );
    h.misc2 = Some(MiscOptions2::amule(0, CryptSettings::default()));
    h
}

fn config(dir: &TempDir) -> QueueConfig {
    let mut c = QueueConfig::new(ours(), dir.incoming());
    c.filter_lan = false;
    c.reask = Duration::from_secs(5);
    c.flush_every = Duration::from_secs(2);
    c
}

/// Bytes on the wire and back, as the network would deliver them.
fn wire(p: Packet) -> Packet {
    Packet::parse_tcp(&p.to_tcp_bytes().unwrap()).unwrap()
}

/// The queue and its scripted peers, no network.
struct World {
    q: DownloadQueue,
    seeders: HashMap<SocketAddr, Seeder>,
    conns: HashMap<ConnId, SocketAddr>,
    reports: Vec<Report>,
    now: Instant,
    /// Addresses that refuse connections.
    unreachable: HashSet<SocketAddr>,
    /// Datagrams sent.
    udp: Vec<UdpOut>,
}

impl World {
    fn new(q: DownloadQueue) -> Self {
        World {
            q,
            seeders: HashMap::new(),
            conns: HashMap::new(),
            reports: Vec::new(),
            now: Instant::now(),
            unreachable: HashSet::new(),
            udp: Vec::new(),
        }
    }

    fn add_seeder(&mut self, s: Seeder) {
        self.seeders.insert(SocketAddr::V4(s.endpoint().addr), s);
    }

    fn run(&mut self, mut work: VecDeque<Action>) {
        while let Some(a) = work.pop_front() {
            match a {
                Action::Connect { conn, addr, .. } => {
                    if self.unreachable.contains(&addr) || !self.seeders.contains_key(&addr) {
                        work.extend(self.q.closed(conn, self.now));
                    } else {
                        self.conns.insert(conn, addr);
                        work.extend(self.q.connected(conn, self.now));
                    }
                }
                Action::Send { conn, packets } => {
                    let Some(addr) = self.conns.get(&conn) else {
                        continue;
                    };
                    let seeder = self.seeders[addr].clone();
                    for p in packets {
                        for reply in seeder.answer(wire(p)) {
                            work.extend(self.q.packet(conn, wire(reply), self.now));
                        }
                    }
                }
                Action::Close { conn } => {
                    self.conns.remove(&conn);
                }
                Action::SendUdp(d) => self.udp.push(d),
                Action::Report(r) => self.reports.push(r),
            }
        }
    }

    fn tick(&mut self) {
        self.now += Duration::from_secs(1);
        let a = self.q.tick(self.now);
        self.run(a.into());
    }

    fn add_source(&mut self, file: Md4Hash, ep: Endpoint) {
        let a = self.q.add_source(file, ep, Origin::Manual, self.now);
        self.run(a.into());
    }

    /// Tick until `done` holds, at most `n` times.
    fn tick_until(&mut self, n: usize, done: impl Fn(&World) -> bool) {
        for _ in 0..n {
            if done(self) {
                return;
            }
            self.tick();
        }
        assert!(done(self), "not done after {n} ticks: {:#?}", self.reports);
    }

    fn completed(&self) -> bool {
        self.reports
            .iter()
            .any(|r| matches!(r, Report::Completed { .. }))
    }
}

fn setup(name: &str) -> (TempDir, Arc<Vec<u8>>, Arc<FileHashes>, DownloadQueue) {
    let dir = TempDir::new(name);
    let d = Arc::new(data(SIZE, 21));
    let h = Arc::new(hashes(&d));
    let mut q = DownloadQueue::new(config(&dir));
    let pf = PartFile::create(&dir.temp(), "test file.bin", h.ed2k, SIZE).unwrap();
    assert!(q.add_file(pf));
    (dir, d, h, q)
}

fn seeder_at(last: u8, d: &Arc<Vec<u8>>, h: &Arc<FileHashes>, have: PartStatus) -> Seeder {
    Seeder::new(
        Ipv4Addr::new(10, last, 0, 2),
        4662,
        d.clone(),
        h.clone(),
        have,
    )
}

#[test]
fn a_file_downloads_from_one_seeder() {
    let (dir, d, h, q) = setup("q-one");
    let mut w = World::new(q);
    let s = seeder_at(1, &d, &h, PartStatus::Complete);
    let ep = s.endpoint();
    w.add_seeder(s);
    w.add_source(h.ed2k, ep);
    w.tick_until(10, World::completed);

    let path = dir.incoming().join("test file.bin");
    assert!(w.reports.contains(&Report::Completed {
        file: h.ed2k,
        path: path.clone()
    }));
    assert_eq!(std::fs::read(path).unwrap(), *d);
    assert!(w.q.all_done());
    assert_eq!(w.q.stats().received, SIZE);
    assert!(w.reports.contains(&Report::DownloadStarted {
        file: h.ed2k,
        addr: ep.addr
    }));
    // Hung up once done.
    assert!(w.conns.is_empty());
    assert_eq!(w.q.stats().connections, 0);
}

#[test]
fn source_exchange_finds_the_rest() {
    let (_dir, d, h, q) = setup("q-sx");
    let mut w = World::new(q);
    let full = seeder_at(2, &d, &h, PartStatus::Complete);
    let mut partial = seeder_at(1, &d, &h, parts(3, &[0]));
    let fe = full.endpoint();
    partial.exchange.push(ExchangedSource {
        id: ip_id(*fe.addr.ip()),
        port: fe.addr.port(),
        server: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        user_hash: fe.user_hash,
        crypt_options: Some(crypt::SUPPORTED),
    });
    let pe = partial.endpoint();
    w.add_seeder(partial);
    w.add_seeder(full);
    // Only the partial seeder is known.
    w.add_source(h.ed2k, pe);
    w.tick_until(20, World::completed);
    assert!(w.reports.contains(&Report::SourceAdded {
        file: h.ed2k,
        addr: fe.addr,
        origin: Origin::SourceExchange
    }));
}

#[test]
fn a_queued_source_calls_back_with_a_slot() {
    let (_dir, d, h, q) = setup("q-callback");
    let mut w = World::new(q);
    let mut s = seeder_at(1, &d, &h, PartStatus::Complete);
    s.queue_first = true;
    let ep = s.endpoint();
    let addr = SocketAddr::V4(ep.addr);
    w.add_seeder(s.clone());
    w.add_source(h.ed2k, ep);
    w.tick();
    assert!(w.reports.contains(&Report::Queued {
        file: h.ed2k,
        addr: ep.addr,
        rank: Some(3)
    }));
    // The seeder hangs up; we stay in its queue.
    let (&conn, _) = w.conns.iter().next().unwrap();
    w.conns.remove(&conn);
    let a = w.q.closed(conn, w.now);
    w.run(a.into());
    assert_eq!(w.q.sources_of(&h.ed2k)[0].2, SourceState::OnQueue);

    // Later it connects to us with a slot: hello, then the accept.
    let conn = w.q.incoming();
    w.conns.insert(conn, addr);
    s.queue_first = false;
    w.seeders.insert(addr, s.clone());
    let mut hello = s.hello.clone();
    hello.misc2 = s.hello.misc2;
    let a = w.q.packet(conn, wire(hello.to_hello().unwrap()), w.now);
    w.run(a.into());
    let a = w.q.packet(conn, wire(packets::accept_upload_req()), w.now);
    w.run(a.into());
    w.tick_until(10, World::completed);
}

#[test]
fn sources_that_fail_are_dropped_for_a_while() {
    let (_dir, d, h, q) = setup("q-dead");
    let mut w = World::new(q);
    let mut nofile = seeder_at(1, &d, &h, PartStatus::Complete);
    nofile.no_file = true;
    let a = nofile.endpoint();
    let b = seeder_at(2, &d, &h, PartStatus::Complete).endpoint();
    w.add_seeder(nofile);
    w.unreachable.insert(SocketAddr::V4(b.addr));
    w.add_source(h.ed2k, a);
    w.add_source(h.ed2k, b);
    w.tick();
    let dropped: Vec<_> = w
        .reports
        .iter()
        .filter_map(|r| match r {
            Report::SourceDropped { addr, why, .. } => Some((*addr, why.clone())),
            _ => None,
        })
        .collect();
    assert!(
        dropped.contains(&(a.addr, "does not have the file".into())),
        "{dropped:?}"
    );
    assert!(
        dropped.contains(&(b.addr, "could not connect".into())),
        "{dropped:?}"
    );
    assert_eq!(w.q.source_count(&h.ed2k), 0);
    // Not taken back until the dead delay is over.
    assert!(w.q.add_source(h.ed2k, b, Origin::Kad, w.now).is_empty());
    let later = w.now + w.q.config().dead_delay + Duration::from_secs(1);
    w.q.tick(later);
    assert!(!w.q.add_source(h.ed2k, b, Origin::Kad, later).is_empty());
}

#[test]
fn bad_and_duplicate_sources_are_refused() {
    let (dir, _d, h, mut q) = setup("q-filter");
    let now = Instant::now();
    let ep = |a: [u8; 4], port| Endpoint::new(SocketAddrV4::new(Ipv4Addr::from(a), port));
    assert!(q
        .add_source(h.ed2k, ep([0, 0, 0, 0], 4662), Origin::Kad, now)
        .is_empty());
    assert!(q
        .add_source(h.ed2k, ep([1, 2, 3, 4], 0), Origin::Kad, now)
        .is_empty());
    assert!(q
        .add_source(h.ed2k, ep([224, 0, 0, 1], 4662), Origin::Kad, now)
        .is_empty());
    assert!(q
        .add_source(Md4Hash([1; 16]), ep([1, 2, 3, 4], 4662), Origin::Kad, now)
        .is_empty());
    // Ourselves.
    assert!(q
        .add_source(h.ed2k, ep([10, 99, 0, 1], 4662), Origin::Kad, now)
        .is_empty());
    assert_eq!(
        q.add_source(h.ed2k, ep([1, 2, 3, 4], 4662), Origin::Kad, now)
            .len(),
        1
    );
    assert!(q
        .add_source(h.ed2k, ep([1, 2, 3, 4], 4662), Origin::Server, now)
        .is_empty());
    assert_eq!(q.source_count(&h.ed2k), 1);

    // LAN addresses, when filtered.
    let mut c = config(&dir);
    c.filter_lan = true;
    let mut q = DownloadQueue::new(c);
    q.add_file(PartFile::create(&dir.temp(), "x", Md4Hash([5; 16]), 100).unwrap());
    assert!(q
        .add_source(
            Md4Hash([5; 16]),
            ep([192, 168, 1, 2], 4662),
            Origin::Kad,
            now
        )
        .is_empty());
    assert!(q
        .add_source(Md4Hash([5; 16]), ep([127, 0, 0, 1], 4662), Origin::Kad, now)
        .is_empty());
}

#[test]
fn sources_the_ip_filter_blocks_are_refused() {
    use crate::ip_filter::AddressFilter;
    use ed2k_formats::ipfilter::{IpFilter, IpFilterFile};

    let dir = TempDir::new("q-ipfilter");
    let now = Instant::now();
    let ep = |a: [u8; 4]| Endpoint::new(SocketAddrV4::new(Ipv4Addr::from(a), 4662));
    // Level 100 is blocked at the default 127; level 200 is not.
    let list = IpFilterFile::parse(
        b"1.2.3.0 - 1.2.3.255 , 100 , blocked\n5.6.7.0 - 5.6.7.255 , 200 , allowed\n",
    );
    let filter = |clients| {
        let mut c = config(&dir);
        c.ip_filter = Some(Arc::new(AddressFilter::new(
            IpFilter::build(&[&list]),
            127,
            clients,
            true,
        )));
        let mut q = DownloadQueue::new(c);
        q.add_file(PartFile::create(&dir.temp(), "x", Md4Hash([5; 16]), 100).unwrap());
        q
    };
    let mut q = filter(true);
    assert!(q.blocks(Ipv4Addr::new(1, 2, 3, 4)));
    assert!(q
        .add_source(Md4Hash([5; 16]), ep([1, 2, 3, 4]), Origin::Server, now)
        .is_empty());
    assert_eq!(
        q.add_source(Md4Hash([5; 16]), ep([5, 6, 7, 8]), Origin::Server, now)
            .len(),
        1
    );
    assert_eq!(
        q.add_source(Md4Hash([5; 16]), ep([1, 2, 4, 1]), Origin::Kad, now)
            .len(),
        1
    );
    assert_eq!(q.source_count(&Md4Hash([5; 16])), 2);
    // With IpFilterClients off, nothing is blocked.
    let mut q = filter(false);
    assert!(!q.blocks(Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(
        q.add_source(Md4Hash([5; 16]), ep([1, 2, 3, 4]), Origin::Server, now)
            .len(),
        1
    );
}

#[test]
fn connections_respect_the_limits() {
    let (dir, _d, h, _) = setup("q-limits");
    let mut c = config(&dir);
    c.max_connections = 4;
    c.max_new_per_tick = 3;
    let mut q = DownloadQueue::new(c);
    q.add_file(PartFile::create(&dir.temp(), "y", h.ed2k, SIZE).unwrap());
    let now = Instant::now();
    for i in 1..=10u8 {
        let mut ep = Endpoint::new(SocketAddrV4::new(Ipv4Addr::new(20, 0, 0, i), 4662));
        if i == 1 {
            ep.user_hash = Some(Md4Hash([i; 16]));
            ep.crypt = crypt::SUPPORTED;
        }
        q.add_source(h.ed2k, ep, Origin::Kad, now);
    }
    let connects = |a: &[Action]| {
        a.iter()
            .filter_map(|a| match a {
                Action::Connect { obfuscate_for, .. } => Some(*obfuscate_for),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let first = connects(&q.tick(now));
    assert_eq!(first.len(), 3);
    // The one with a user hash that supports obfuscation gets it.
    assert_eq!(first.iter().filter(|o| o.is_some()).count(), 1);
    assert_eq!(connects(&q.tick(now + Duration::from_secs(1))).len(), 1);
    assert!(connects(&q.tick(now + Duration::from_secs(2))).is_empty());
    assert_eq!(q.stats().connections, 4);
}

#[test]
fn a_corrupt_part_is_recovered_through_aich() {
    let (_dir, d, h, mut q) = setup("q-aich");
    q.file_mut(&h.ed2k).unwrap().set_trust_every_aich_hash(true);
    let mut w = World::new(q);
    // The first seeder has parts 0 and 1 and spoils one byte of part 0.
    let first = seeder_at(1, &d, &h, parts(3, &[0, 1]));
    first.corrupt.lock().unwrap().insert(5);
    let fe = first.endpoint();
    w.add_seeder(first);
    w.add_source(h.ed2k, fe);
    w.tick_until(20, |w| {
        w.reports
            .iter()
            .any(|r| matches!(r, Report::AichRecovered { .. }))
    });
    assert!(w.reports.contains(&Report::PartCorrupt {
        file: h.ed2k,
        part: 0
    }));
    assert!(w.reports.contains(&Report::AichRecovered {
        file: h.ed2k,
        part: 0,
        bytes: PARTSIZE - u64::from(EMBLOCKSIZE)
    }));
    // A second seeder has the last part; the bad block is fetched again.
    let full = seeder_at(2, &d, &h, PartStatus::Complete);
    let full_ep = full.endpoint();
    w.add_seeder(full);
    w.add_source(h.ed2k, full_ep);
    w.tick_until(40, World::completed);
    assert!(w.reports.contains(&Report::PartVerified {
        file: h.ed2k,
        part: 0
    }));
}

// ---- over TCP ----

/// Serve `seeder` on a local port until the test ends.
async fn serve(seeder: Seeder, listener: tokio::net::TcpListener) {
    use remule_net::{establish, Bandwidth, ConnConfig, Handshake, Priority};
    let bw = Arc::new(Bandwidth::unlimited());
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let s = seeder.clone();
        let cfg = ConnConfig::new(bw.clone());
        tokio::spawn(async move {
            let hs = Handshake::Incoming {
                own_hash: s.hello.user_hash,
                max_padding: 16,
                require: false,
            };
            let Ok((mut r, mut w)) = establish(stream, hs, cfg).await else {
                return;
            };
            while let Ok(Some(p)) = r.recv().await {
                for reply in s.answer(p) {
                    if w.send(&reply, Priority::Standard).await.is_err() {
                        return;
                    }
                }
            }
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_downloader_fetches_a_file_over_tcp() {
    use tokio::sync::mpsc;

    use crate::downloader::{run, Command, DownloaderConfig};

    let dir = TempDir::new("q-tcp");
    let d = Arc::new(data(SIZE, 33));
    let h = Arc::new(hashes(&d));

    // Two seeders on 127.0.0.1: the first has part 0 and passes on the
    // second, which has everything. The first is reached obfuscated.
    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (p1, p2) = (
        l1.local_addr().unwrap().port(),
        l2.local_addr().unwrap().port(),
    );
    let localhost = Ipv4Addr::LOCALHOST;
    let mut s1 = Seeder::new(localhost, p1, d.clone(), h.clone(), parts(3, &[0]));
    s1.hello.user_hash = Md4Hash([0x51; 16]);
    let mut s2 = Seeder::new(localhost, p2, d.clone(), h.clone(), PartStatus::Complete);
    s2.hello.user_hash = Md4Hash([0x52; 16]);
    s1.exchange.push(ExchangedSource {
        id: ip_id(localhost),
        port: p2,
        server: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        user_hash: None,
        crypt_options: Some(0),
    });
    let first = s1.endpoint();
    tokio::spawn(serve(s1, l1));
    tokio::spawn(serve(s2, l2));

    let mut cfg = config(&dir);
    cfg.ours.id = ip_id(Ipv4Addr::new(10, 99, 0, 1));
    let queue = DownloadQueue::new(cfg);
    let mut dl = DownloaderConfig::new(Arc::new(remule_net::Bandwidth::unlimited()));
    dl.tick = Duration::from_millis(50);
    dl.stop_when_done = true;
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (rep_tx, mut rep_rx) = mpsc::unbounded_channel();
    let pf = PartFile::create(&dir.temp(), "test file.bin", h.ed2k, SIZE).unwrap();
    cmd_tx.send(Command::AddFile(Box::new(pf))).unwrap();
    cmd_tx
        .send(Command::AddSources {
            file: h.ed2k,
            sources: vec![first],
            origin: Origin::Manual,
        })
        .unwrap();

    let queue = tokio::time::timeout(
        Duration::from_secs(120),
        run(queue, dl, None, cmd_rx, rep_tx),
    )
    .await
    .expect("download timed out");
    assert!(queue.all_done());
    let mut reports = Vec::new();
    while let Ok(r) = rep_rx.try_recv() {
        reports.push(r);
    }
    assert!(reports.iter().any(|r| matches!(
        r,
        Report::SourceAdded {
            origin: Origin::SourceExchange,
            ..
        }
    )));
    let path = dir.incoming().join("test file.bin");
    assert!(reports.contains(&Report::Completed {
        file: h.ed2k,
        path: path.clone()
    }));
    assert_eq!(std::fs::read(path).unwrap(), *d);
}

#[test]
fn a_peer_with_two_files_gets_one_connection() {
    let (dir, _d, h, _) = setup("q-onepeer");
    let mut q = DownloadQueue::new(config(&dir));
    let other = Md4Hash([0x42; 16]);
    q.add_file(PartFile::create(&dir.temp(), "a", h.ed2k, SIZE).unwrap());
    q.add_file(PartFile::create(&dir.temp(), "b", other, 1000).unwrap());
    let now = Instant::now();
    let ep = Endpoint::new(SocketAddrV4::new(Ipv4Addr::new(20, 0, 0, 1), 4662));
    q.add_source(h.ed2k, ep, Origin::Kad, now);
    q.add_source(other, ep, Origin::Kad, now);
    let connects = |a: Vec<Action>| {
        a.iter()
            .filter(|a| matches!(a, Action::Connect { .. }))
            .count()
    };
    assert_eq!(connects(q.tick(now)), 1);
    assert_eq!(connects(q.tick(now + Duration::from_secs(1))), 0);
}

/// Two remule clients over TCP: one shares a file from disk, the other
/// downloads it from the first. Uploads, the upload queue and secure
/// ident on one side, the download queue on the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_remule_downloads_from_another() {
    use std::sync::Mutex;

    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use tokio::sync::mpsc;

    use crate::downloader::{run, run_with, Command, DownloaderConfig};
    use crate::shared::{mtime, ScanOptions, SharedFiles};
    use crate::upload_queue::{UploadConfig, UploadQueue};
    use crate::uploader::Uploader;

    let dir = TempDir::new("q-share");
    let content = data(SIZE, 55);
    let share_dir = dir.0.join("share");
    std::fs::create_dir_all(&share_dir).unwrap();
    std::fs::write(share_dir.join("shared.bin"), &content).unwrap();

    // The sharing client.
    let mut shares = SharedFiles::load(&dir.0.join("config-a")).unwrap();
    let r = shares.scan(
        &ScanOptions {
            dirs: vec![share_dir.clone()],
            ..Default::default()
        },
        1,
    );
    for p in &r.to_hash {
        let h = SharedFiles::hash(p).unwrap();
        shares.add_hashed(p, &h, mtime(&std::fs::metadata(p).unwrap()), 1);
    }
    let h = hashes(&content);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut a_hello = Hello::amule(
        Md4Hash([0xA1; 16]),
        ip_id(Ipv4Addr::LOCALHOST),
        port,
        "sharer",
    );
    a_hello.misc2 = Some(MiscOptions2::amule(0, CryptSettings::default()));
    let ck = ed2k_formats::cryptkey_dat::CryptKey::generate(&mut StdRng::seed_from_u64(1)).unwrap();
    let identity = Arc::new(ed2k_peer::secident::Identity {
        key: ck.private_key().unwrap(),
        public: ck.public_key().unwrap(),
    });
    let uploader = Uploader::new(
        a_hello.clone(),
        Some(identity),
        Arc::new(Mutex::new(shares)),
        UploadQueue::new(UploadConfig::default()),
        Some(crate::credits::Credits::load(&dir.0.join("config-a"), 1).unwrap()),
    );
    let mut a_cfg = QueueConfig::new(a_hello, dir.0.join("incoming-a"));
    a_cfg.filter_lan = false;
    let mut a_dl = DownloaderConfig::new(Arc::new(remule_net::Bandwidth::unlimited()));
    a_dl.tick = Duration::from_millis(50);
    let (a_cmd, a_cmd_rx) = mpsc::unbounded_channel();
    let (a_rep, mut a_reports) = mpsc::unbounded_channel();
    let sharer = tokio::spawn(run_with(
        DownloadQueue::new(a_cfg),
        Some(uploader),
        a_dl,
        Some(listener),
        a_cmd_rx,
        a_rep,
    ));

    // The downloading client.
    let mut cfg = config(&dir);
    cfg.ours.id = ip_id(Ipv4Addr::new(10, 99, 0, 1));
    let mut dl = DownloaderConfig::new(Arc::new(remule_net::Bandwidth::unlimited()));
    dl.tick = Duration::from_millis(50);
    dl.stop_when_done = true;
    let (cmd, cmd_rx) = mpsc::unbounded_channel();
    let (rep, mut reports) = mpsc::unbounded_channel();
    let pf = PartFile::create(&dir.temp(), "shared.bin", h.ed2k, SIZE).unwrap();
    cmd.send(Command::AddFile(Box::new(pf))).unwrap();
    cmd.send(Command::AddSources {
        file: h.ed2k,
        sources: vec![Endpoint::new(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))],
        origin: Origin::Manual,
    })
    .unwrap();
    let queue = tokio::time::timeout(
        Duration::from_secs(120),
        run(DownloadQueue::new(cfg), dl, None, cmd_rx, rep),
    )
    .await
    .expect("download timed out");
    assert!(queue.all_done());
    let path = dir.incoming().join("shared.bin");
    let mut got = Vec::new();
    while let Ok(r) = reports.try_recv() {
        got.push(r);
    }
    assert!(got.contains(&Report::Completed {
        file: h.ed2k,
        path: path.clone()
    }));
    assert_eq!(std::fs::read(path).unwrap(), content);

    // The sharer gave a slot, and keeps the credit in clients.met.
    a_cmd.send(Command::Shutdown).unwrap();
    let (_, up) = sharer.await.unwrap();
    let up = up.unwrap();
    assert!(up.sent_total() >= SIZE, "{}", up.sent_total());
    let mut started = false;
    while let Ok(r) = a_reports.try_recv() {
        started |= matches!(r, Report::UploadStarted { file, .. } if file == h.ed2k);
    }
    assert!(started);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let credits = crate::credits::Credits::load(&dir.0.join("config-a"), now).unwrap();
    assert!(credits
        .get(&Md4Hash([0x77; 16]))
        .is_some_and(|c| c.uploaded >= SIZE));
}

/// `PauseFile`, `StopFile`, `ResumeFile` and cancelling, as the EC
/// partfile commands use them.
#[test]
fn downloads_pause_stop_resume_and_go() {
    let (dir, d, h, q) = setup("q-pause");
    let mut w = World::new(q);
    // A seeder that queues us keeps its connection open.
    let mut s = seeder_at(1, &d, &h, PartStatus::Complete);
    s.queue_first = true;
    let ep = s.endpoint();
    w.add_seeder(s);
    w.add_source(h.ed2k, ep);
    w.tick();
    assert_eq!(w.q.stats().connections, 1);

    // Paused: hung up, saved paused, nothing more asked; the source kept.
    let mut out = Vec::new();
    assert!(w.q.pause(&h.ed2k, w.now, &mut out));
    assert!(out.iter().any(|a| matches!(a, Action::Close { .. })));
    w.run(out.into());
    assert_eq!(w.q.stats().connections, 0);
    assert_eq!(w.q.source_count(&h.ed2k), 1);
    let met = w.q.file(&h.ed2k).unwrap().met_path().to_owned();
    assert!(PartFile::open(&met).unwrap().is_paused());
    for _ in 0..10 {
        w.tick();
    }
    assert_eq!(w.q.stats().connections, 0);
    let p = &w.q.progress()[0];
    assert!(p.paused && !p.stopped);

    // Resumed: asked again, saved unpaused.
    assert!(w.q.resume(&h.ed2k));
    assert!(!PartFile::open(&met).unwrap().is_paused());
    w.tick_until(10, |w| w.q.stats().connections == 1);

    // Stopped: paused, and its sources gone; new ones are refused.
    let mut out = Vec::new();
    assert!(w.q.stop(&h.ed2k, w.now, &mut out));
    w.run(out.into());
    assert_eq!(w.q.source_count(&h.ed2k), 0);
    assert!(w.q.is_stopped(&h.ed2k));
    w.add_source(h.ed2k, ep);
    assert_eq!(w.q.source_count(&h.ed2k), 0);
    // Resumed, it takes sources again, at once (no dead-list wait).
    assert!(w.q.resume(&h.ed2k));
    w.add_source(h.ed2k, ep);
    assert_eq!(w.q.source_count(&h.ed2k), 1);

    // A file loaded paused is stopped, as aMule loads it.
    let mut out = Vec::new();
    w.q.pause(&h.ed2k, w.now, &mut out);
    let mut q2 = DownloadQueue::new(config(&dir));
    assert!(q2.add_file(PartFile::open(&met).unwrap()));
    assert!(q2.is_stopped(&h.ed2k));

    // Cancelled: out of the queue, its sources and connections gone.
    assert!(w.q.resume(&h.ed2k));
    w.tick_until(10, |w| w.q.stats().connections == 1);
    let mut out = Vec::new();
    let f = w.q.remove(&h.ed2k, w.now, &mut out).unwrap();
    w.run(out.into());
    assert_eq!(f.hash(), h.ed2k);
    assert!(w.q.file(&h.ed2k).is_none());
    assert_eq!((w.q.stats().connections, w.q.stats().sources), (0, 0));
    f.delete().unwrap();
    assert!(!met.exists());
    // Unknown files.
    let other = Md4Hash([9; 16]);
    let mut out = Vec::new();
    assert!(!w.q.pause(&other, w.now, &mut out));
    assert!(!w.q.stop(&other, w.now, &mut out));
    assert!(!w.q.resume(&other));
    assert!(w.q.remove(&other, w.now, &mut out).is_none());
}

#[test]
fn a_reloaded_ip_filter_is_seen_by_everything_sharing_it() {
    use crate::ip_filter::AddressFilter;
    use ed2k_formats::ipfilter::{IpFilter, IpFilterFile};
    let list = |text: &str| {
        let f = IpFilterFile::parse(text.as_bytes());
        IpFilter::build(&[&f])
    };
    let shared = Arc::new(AddressFilter::new(list(""), 127, true, true));
    let other = shared.clone();
    let ip = std::net::Ipv4Addr::new(10, 1, 2, 3);
    assert!(!other.blocks_client(ip));
    shared.replace(AddressFilter::new(
        list("10.0.0.0 - 10.255.255.255 , 0 , test\n"),
        127,
        true,
        false,
    ));
    assert!(other.blocks_client(ip), "the same filter, reloaded");
    assert!(!other.blocks_server(ip), "servers not filtered now");
    assert_eq!(other.ban_count(), 1);
}

#[test]
fn a_deleted_category_moves_its_downloads_to_the_default_one() {
    let dir = TempDir::new("queue-category");
    let mut q = DownloadQueue::new(config(&dir));
    for (h, cat) in [(1u8, 0u32), (2, 1), (3, 2), (4, 3)] {
        let mut f = PartFile::create(&dir.temp(), "x", Md4Hash([h; 16]), 100).unwrap();
        f.set_category(cat);
        q.add_file(f);
    }
    q.remove_category(2);
    let cat = |h: u8| {
        q.files()
            .find(|f| f.hash() == Md4Hash([h; 16]))
            .unwrap()
            .info()
            .category
    };
    assert_eq!((cat(1), cat(2), cat(3), cat(4)), (0, 1, 0, 2));
}

/// `CPartFile::Process` for a queued source, `UDPReaskForDownload` and the
/// answers to it: the reask goes out over UDP (obfuscated, laid out for the
/// source's UDP version) 20 s before the TCP one is due, once; an answer
/// with a rank puts the TCP reask off; unanswered, TCP asks; "file not
/// found" drops the source.
#[test]
fn a_queued_source_is_reasked_over_udp_first() {
    let dir = TempDir::new("q-udp-reask");
    let d = Arc::new(data(SIZE, 21));
    let h = Arc::new(hashes(&d));
    let mut c = config(&dir);
    c.reask = Duration::from_secs(60);
    c.ours.udp_port = 4672;
    let mut q = DownloadQueue::new(c);
    let pf = PartFile::create(&dir.temp(), "test file.bin", h.ed2k, SIZE).unwrap();
    assert!(q.add_file(pf));
    let mut w = World::new(q);
    let mut s = seeder_at(1, &d, &h, PartStatus::Complete);
    s.queue_first = true;
    s.hello.udp_port = 4672;
    let ep = s.endpoint();
    let udp_addr = SocketAddrV4::new(*ep.addr.ip(), 4672);
    w.add_seeder(s.clone());
    w.add_source(h.ed2k, ep);
    w.tick();
    // Queued; the seeder hangs up.
    let (&conn, _) = w.conns.iter().next().unwrap();
    w.conns.remove(&conn);
    let a = w.q.closed(conn, w.now);
    w.run(a.into());
    let asked = w.now;
    let connects = |w: &World| w.conns.len();

    // Nothing until 40 s (60 - 20) have passed, then one ping.
    while w.now < asked + Duration::from_secs(40) {
        w.tick();
        assert!(w.udp.is_empty(), "too early");
    }
    w.tick();
    assert_eq!(w.udp.len(), 1);
    let ping = w.udp[0].clone();
    assert_eq!(ping.to, udp_addr);
    assert_eq!(ping.obfuscate_for, Some(s.hello.user_hash));
    // aMule's UDP version 4: our parts and the complete sources it knows.
    assert_eq!(
        UdpPacket::parse(&ping.payload, Some(4)).unwrap(),
        UdpPacket::ReaskFilePing {
            file: h.ed2k,
            parts: Some(parts(3, &[])),
            complete_sources: Some(1),
        }
    );
    // Once only while it is unanswered.
    for _ in 0..5 {
        w.tick();
    }
    assert_eq!(w.udp.len(), 1);

    // The answer, rank 2: no TCP reask at 60 s, the clock starts again.
    let ack = UdpPacket::ReaskAck {
        parts: Some(PartStatus::Complete),
        rank: 2,
    };
    let a = w.q.udp_packet(udp_addr, &ack.to_datagram(4), w.now);
    w.run(a.into());
    assert!(w.reports.contains(&Report::Queued {
        file: h.ed2k,
        addr: ep.addr,
        rank: Some(2)
    }));
    let acked = w.now;
    // From another port, or unasked: ignored.
    let a = w.q.udp_packet(udp_addr, &ack.to_datagram(4), w.now);
    assert!(a.is_empty());
    while w.now < asked + Duration::from_secs(65) {
        w.tick();
        assert_eq!(connects(&w), 0, "TCP reask despite the UDP answer");
    }
    // The next ping 40 s after the answer, left unanswered: TCP at 60 s.
    while w.udp.len() < 2 {
        w.tick();
    }
    assert!(w.now >= acked + Duration::from_secs(40));
    while connects(&w) == 0 {
        w.tick();
        assert!(w.now <= acked + Duration::from_secs(62), "no TCP reask");
    }
    assert!(w.now > acked + Duration::from_secs(60));
    let (&conn, _) = w.conns.iter().next().unwrap();
    w.conns.remove(&conn);
    let a = w.q.closed(conn, w.now);
    w.run(a.into());

    // Next time the file is gone: the source is dropped.
    while w.udp.len() < 3 {
        w.tick();
    }
    let a =
        w.q.udp_packet(udp_addr, &UdpPacket::FileNotFound.to_datagram(4), w.now);
    w.run(a.into());
    assert!(w.q.sources_of(&h.ed2k).is_empty());
    assert!(w.reports.iter().any(|r| matches!(r,
        Report::SourceDropped { why, .. } if why.contains("not found"))));
}

/// No UDP reask without a UDP port of ours, or as a LowID (others cannot
/// answer what they cannot reach).
#[test]
fn no_udp_reask_without_a_port_or_as_a_low_id() {
    for (udp_port, id) in [(0u16, None), (4672, Some(5000u32))] {
        let dir = TempDir::new("q-udp-none");
        let d = Arc::new(data(SIZE, 21));
        let h = Arc::new(hashes(&d));
        let mut c = config(&dir);
        c.reask = Duration::from_secs(60);
        c.ours.udp_port = udp_port;
        if let Some(id) = id {
            c.ours.id = id;
        }
        let mut q = DownloadQueue::new(c);
        let pf = PartFile::create(&dir.temp(), "test file.bin", h.ed2k, SIZE).unwrap();
        assert!(q.add_file(pf));
        let mut w = World::new(q);
        let mut s = seeder_at(1, &d, &h, PartStatus::Complete);
        s.queue_first = true;
        s.hello.udp_port = 4672;
        let ep = s.endpoint();
        w.add_seeder(s);
        w.add_source(h.ed2k, ep);
        w.tick();
        let (&conn, _) = w.conns.iter().next().unwrap();
        w.conns.remove(&conn);
        let a = w.q.closed(conn, w.now);
        w.run(a.into());
        for _ in 0..70 {
            w.tick();
        }
        assert!(w.udp.is_empty());
    }
}

/// A firewalled Kad source (type 3): not connected to; its buddy is asked
/// over Kad to have it connect (`KADEMLIA_CALLBACK_REQ`, unobfuscated),
/// only while others can reach us; an unanswered request makes the next
/// carry the buddy ID in the other layout; when the source connects, it
/// is downloaded from.
#[test]
fn a_firewalled_source_is_asked_through_its_buddy() {
    use crate::download_queue::BuddyRoute;
    use ed2k_kad::packets::KadPacket;
    use ed2k_kad::search::buddy_id_other_layout;
    use ed2k_types::UInt128;
    let (_dir, d, h, q) = setup("q-buddy-source");
    let mut w = World::new(q);
    let s = seeder_at(1, &d, &h, PartStatus::Complete);
    let route = BuddyRoute {
        kad: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 4672),
        id: UInt128::new(0x0102_0304_0506_0708),
    };
    let mut ep = s.endpoint();
    ep.buddy = Some(route);
    w.add_seeder(s.clone());
    // Not reachable: nothing asked, no connection.
    w.add_source(h.ed2k, ep);
    w.tick();
    assert!(w.udp.is_empty() && w.conns.is_empty());
    // Reachable: at the next reask, the buddy is asked.
    w.q.set_reachable(true);
    w.tick_until(10, |w| !w.udp.is_empty());
    assert!(
        w.conns.is_empty(),
        "a firewalled source is not connected to"
    );
    let req = w.udp[0].clone();
    assert_eq!((req.to, req.obfuscate_for), (route.kad, None));
    assert_eq!(
        KadPacket::parse(&req.payload).unwrap(),
        KadPacket::CallbackReq {
            buddy_id: route.id,
            file: UInt128::from_be_bytes(h.ed2k.0),
            tcp_port: 4662,
        }
    );
    // Unanswered: the next one tries the other layout.
    w.tick_until(10, |w| w.udp.len() >= 2);
    let KadPacket::CallbackReq { buddy_id, .. } = KadPacket::parse(&w.udp[1].payload).unwrap()
    else {
        panic!()
    };
    assert_eq!(buddy_id, buddy_id_other_layout(route.id));
    // The source connects to us: downloaded from as any callback.
    let conn = w.q.incoming();
    let addr = SocketAddr::V4(ep.addr);
    w.conns.insert(conn, addr);
    let a = w.q.packet(conn, wire(s.hello.to_hello().unwrap()), w.now);
    w.run(a.into());
    w.tick_until(20, World::completed);
}

/// A Kad source that takes UDP but not TCP (type 6, direct callback flag
/// set): not connected to; asked over UDP to connect to us
/// (`OP_DIRECTCALLBACKREQ`: our TCP port, user hash, connect options),
/// only while we can be reached. Without the flag it is not taken.
#[test]
fn a_udp_only_source_is_asked_to_call_back() {
    use ed2k_kad::search::SourceResult;
    let kad = |crypt| SourceResult {
        user_hash: Md4Hash([0x66; 16]),
        source_type: 6,
        ip: Ipv4Addr::new(10, 1, 0, 2),
        tcp_port: 4662,
        udp_port: 4672,
        buddy_ip: Ipv4Addr::UNSPECIFIED,
        buddy_port: 0,
        buddy_id: None,
        crypt_options: crypt,
    };
    assert!(Endpoint::from_kad(&kad(0x01)).is_none());
    let ep = Endpoint::from_kad(&kad(0x09)).unwrap();
    assert_eq!(ep.direct_udp, Some(4672));

    let (_dir, _d, h, q) = setup("q-direct-callback");
    let mut w = World::new(q);
    w.add_source(h.ed2k, ep);
    w.tick();
    assert!(
        w.udp.is_empty() && w.conns.is_empty(),
        "not reachable: nothing"
    );
    // Reachable, but without a UDP port of ours (0 here): nothing either.
    w.q.set_reachable(true);
    assert_eq!(w.q.config().ours.udp_port, 0);
    for _ in 0..10 {
        w.tick();
    }
    assert!(w.udp.is_empty() && w.conns.is_empty());
}

#[test]
fn a_udp_only_source_gets_the_request() {
    use ed2k_kad::search::SourceResult;
    let dir = TempDir::new("q-direct-callback-2");
    let d = Arc::new(data(SIZE, 21));
    let h = Arc::new(hashes(&d));
    let mut c = config(&dir);
    c.ours.udp_port = 4672;
    c.reachable = true;
    let mut q = DownloadQueue::new(c);
    let pf = PartFile::create(&dir.temp(), "test file.bin", h.ed2k, SIZE).unwrap();
    assert!(q.add_file(pf));
    let mut w = World::new(q);
    let ep = Endpoint::from_kad(&SourceResult {
        user_hash: Md4Hash([0x66; 16]),
        source_type: 6,
        ip: Ipv4Addr::new(10, 1, 0, 2),
        tcp_port: 4662,
        udp_port: 4673,
        buddy_ip: Ipv4Addr::UNSPECIFIED,
        buddy_port: 0,
        buddy_id: None,
        crypt_options: 0x09,
    })
    .unwrap();
    w.add_source(h.ed2k, ep);
    w.tick();
    assert!(w.conns.is_empty());
    assert_eq!(w.udp.len(), 1);
    let u = &w.udp[0];
    assert_eq!(u.to, SocketAddrV4::new(Ipv4Addr::new(10, 1, 0, 2), 4673));
    assert_eq!(u.obfuscate_for, Some(Md4Hash([0x66; 16])));
    assert_eq!(
        UdpPacket::parse(&u.payload, None).unwrap(),
        UdpPacket::DirectCallbackReq {
            tcp_port: 4662,
            user_hash: w.q.config().ours.user_hash,
            connect_options: 0x03,
        }
    );
}

/// A firewalled source we wait in the queue of is reasked through its Kad
/// buddy (`OP_REASKCALLBACKUDP`: the buddy ID raw, then the ping),
/// unobfuscated, even as a LowID; its answer comes straight from it.
#[test]
fn a_firewalled_source_is_reasked_through_its_buddy() {
    use crate::download_queue::BuddyRoute;
    use ed2k_types::UInt128;
    let dir = TempDir::new("q-buddy-reask");
    let d = Arc::new(data(SIZE, 21));
    let h = Arc::new(hashes(&d));
    let mut c = config(&dir);
    c.reask = Duration::from_secs(60);
    c.ours.udp_port = 4672;
    c.ours.id = 5000; // a LowID
    let mut q = DownloadQueue::new(c);
    let pf = PartFile::create(&dir.temp(), "test file.bin", h.ed2k, SIZE).unwrap();
    assert!(q.add_file(pf));
    let mut w = World::new(q);
    let mut s = seeder_at(1, &d, &h, PartStatus::Complete);
    s.queue_first = true;
    s.hello.udp_port = 4672;
    let route = BuddyRoute {
        kad: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 4672),
        id: UInt128::new(0xABCD),
    };
    let mut ep = s.endpoint();
    ep.buddy = Some(route);
    w.add_seeder(s.clone());
    // As if it had called back and queued us: it connects to us.
    w.add_source(h.ed2k, ep);
    let conn = w.q.incoming();
    let addr = SocketAddr::V4(ep.addr);
    w.conns.insert(conn, addr);
    let a = w.q.packet(conn, wire(s.hello.to_hello().unwrap()), w.now);
    w.run(a.into());
    w.conns.remove(&conn);
    let a = w.q.closed(conn, w.now);
    w.run(a.into());
    assert_eq!(w.q.sources_of(&h.ed2k)[0].2, SourceState::OnQueue);
    let udp_before = w.udp.len();
    for _ in 0..45 {
        w.tick();
    }
    let relayed: Vec<_> = w.udp[udp_before..]
        .iter()
        .filter(|u| u.to == route.kad && u.payload.get(1) == Some(&0x94))
        .collect();
    assert_eq!(relayed.len(), 1, "{:?}", &w.udp[udp_before..]);
    assert_eq!(relayed[0].obfuscate_for, None);
    let UdpPacket::ReaskCallbackUdp { buddy_id, ping } =
        UdpPacket::parse(&relayed[0].payload, None).unwrap()
    else {
        panic!()
    };
    assert_eq!(buddy_id, route.id.to_be_bytes());
    assert_eq!(&ping[..16], &h.ed2k.0);
    // Its answer, from its own address and UDP port.
    let from = SocketAddrV4::new(*ep.addr.ip(), 4672);
    let ack = UdpPacket::ReaskAck {
        parts: Some(PartStatus::Complete),
        rank: 4,
    };
    let a = w.q.udp_packet(from, &ack.to_datagram(4), w.now);
    w.run(a.into());
    assert!(w.reports.contains(&Report::Queued {
        file: h.ed2k,
        addr: ep.addr,
        rank: Some(4)
    }));
}
