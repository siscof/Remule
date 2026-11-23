// SPDX-License-Identifier: GPL-2.0-or-later
//! The upload queue, credits, and a whole upload from shared files on disk
//! into a part file on disk.

use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use ed2k_crypto::credits::IdentState;
use ed2k_formats::known_met::priority;
use ed2k_types::Md4Hash;

use crate::credits::Credits;
use crate::tests_part_file::{data, TempDir};
use crate::upload_queue::{Answer, Asker, QueueAction, UdpReask, UploadConfig, UploadQueue};

fn asker(n: u8) -> Asker {
    Asker {
        user_hash: Md4Hash([n; 16]),
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)),
        low_id: false,
        score_ratio: 1.0,
        old_emule: false,
        udp_port: 4672,
        udp_version: 4,
        crypt_udp: false,
    }
}

const FILE: Md4Hash = Md4Hash([0xF1; 16]);

/// Two slots: 20 KiB/s at 10 KiB/s each.
fn two_slots() -> UploadQueue {
    UploadQueue::new(UploadConfig {
        max_upload_kbps: 20,
        ..Default::default()
    })
}

fn ask(q: &mut UploadQueue, a: Asker, now: Instant) -> Answer {
    q.request(a, FILE, priority::NORMAL, false, 0, now)
}

#[test]
fn slot_counts_follow_the_limit() {
    let q = UploadQueue::new(UploadConfig::default());
    assert_eq!(q.max_slots(0), 20);
    assert_eq!(q.max_slots(1024 * 1024), 1024 / 10 + 2);
    assert_eq!(q.max_slots(100 << 20), 250);
    let limited = |kbps| {
        UploadQueue::new(UploadConfig {
            max_upload_kbps: kbps,
            ..Default::default()
        })
        .max_slots(0)
    };
    assert_eq!(limited(100), 10);
    assert_eq!(limited(15), 2);
    assert_eq!(limited(5), 2);
}

#[test]
fn the_first_gets_a_slot_the_others_wait_their_turn() {
    let mut q = two_slots();
    let t = Instant::now();
    assert_eq!(ask(&mut q, asker(1), t), Answer::Slot);
    // Within the second, the next one waits even with a slot free.
    assert_eq!(ask(&mut q, asker(2), t), Answer::Queued(1));
    assert_eq!(ask(&mut q, asker(3), t), Answer::Queued(2));
    assert!(q.process(0, t).is_empty());
    // A second later the free slot goes to the one that waited longest.
    let t1 = t + Duration::from_secs(2);
    assert_eq!(q.process(0, t1), [QueueAction::GiveSlot(Md4Hash([2; 16]))]);
    assert_eq!(q.slot_count(), 2);
    // Full: nobody else.
    assert!(q.process(0, t1 + Duration::from_secs(5)).is_empty());
    // Asking again keeps the place.
    assert_eq!(ask(&mut q, asker(3), t1), Answer::Queued(1));
    assert_eq!(ask(&mut q, asker(1), t1), Answer::Slot);
}

#[test]
fn scores_weigh_waiting_credits_and_priority() {
    let mut q = UploadQueue::new(UploadConfig {
        max_upload_kbps: 10,
        ..Default::default()
    });
    let t = Instant::now();
    ask(&mut q, asker(9), t); // takes a slot
    ask(&mut q, asker(9), t);
    let _ = q.process(0, t);
    // 1 waits 100 s; 2 waits 60 s with credits worth 2.
    let mut a1 = asker(1);
    a1.score_ratio = 1.0;
    q.request(a1, FILE, priority::NORMAL, false, 0, t);
    let mut a2 = asker(2);
    a2.score_ratio = 2.0;
    q.request(
        a2,
        FILE,
        priority::NORMAL,
        false,
        0,
        t + Duration::from_secs(40),
    );
    let now = t + Duration::from_secs(100);
    assert_eq!(q.rank(&Md4Hash([2; 16]), now), Some(1));
    // A file of very high priority beats a long wait.
    q.request(
        asker(3),
        FILE,
        priority::VERY_HIGH,
        false,
        0,
        t + Duration::from_secs(60),
    );
    assert_eq!(q.rank(&Md4Hash([3; 16]), now), Some(2));
    q.request(
        asker(4),
        FILE,
        priority::POWERSHARE,
        false,
        0,
        now - Duration::from_secs(1),
    );
    assert_eq!(q.rank(&Md4Hash([4; 16]), now), Some(1));
    // An old eMule counts half.
    let mut old = asker(5);
    old.old_emule = true;
    q.request(old, FILE, priority::NORMAL, false, 0, t);
    assert!(q.rank(&Md4Hash([5; 16]), now).unwrap() > q.rank(&Md4Hash([1; 16]), now).unwrap());
}

#[test]
fn full_slots_rotate_after_ten_megabytes() {
    let mut q = two_slots();
    let t = Instant::now();
    ask(&mut q, asker(1), t);
    ask(&mut q, asker(2), t);
    let t = t + Duration::from_secs(2);
    q.process(0, t);
    assert_eq!(q.slot_count(), 2);
    // Nobody waits: no rotation, whatever was sent.
    assert_eq!(q.sent(&Md4Hash([1; 16]), 11 << 20, t), None);
    ask(&mut q, asker(3), t);
    q.process(0, t + Duration::from_secs(2));
    let h1 = Md4Hash([1; 16]);
    assert_eq!(q.sent(&h1, 1, t), Some(QueueAction::TakeSlot(h1)));
    assert!(!q.has_slot(&h1));
    // One per round; the waiting peer gets the slot next.
    assert_eq!(q.sent(&Md4Hash([2; 16]), 11 << 20, t), None);
    let actions = q.process(0, t + Duration::from_secs(4));
    assert_eq!(actions, [QueueAction::GiveSlot(Md4Hash([3; 16]))]);
}

#[test]
fn unreachable_peers_wait_for_their_turn() {
    let mut q = two_slots();
    let t = Instant::now();
    ask(&mut q, asker(1), t);
    // A LowID and a HighID wait, both gone.
    let mut low = asker(2);
    low.low_id = true;
    q.request(low.clone(), FILE, priority::NORMAL, false, 0, t);
    q.request(
        asker(3),
        FILE,
        priority::NORMAL,
        false,
        0,
        t + Duration::from_secs(1),
    );
    q.set_connected(&low.user_hash, false);
    q.set_connected(&Md4Hash([3; 16]), false);
    // The LowID is first but cannot be reached: the HighID is called back.
    let actions = q.process(0, t + Duration::from_secs(3));
    assert_eq!(actions, [QueueAction::CallBack(Md4Hash([3; 16]))]);
    // When the LowID connects again it gets its turn, one over the count.
    assert_eq!(
        q.request(
            low,
            FILE,
            priority::NORMAL,
            false,
            0,
            t + Duration::from_secs(4)
        ),
        Answer::Slot
    );
    assert_eq!(q.slot_count(), 3);
}

#[test]
fn limits_on_addresses_and_queue_size() {
    let mut q = UploadQueue::new(UploadConfig {
        max_upload_kbps: 10,
        queue_size: 6,
        ..Default::default()
    });
    let t = Instant::now();
    ask(&mut q, asker(1), t);
    // Three waiting from one address, not a fourth.
    for i in 0..4u8 {
        let mut a = asker(50 + i);
        a.ip = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
        let ans = ask(&mut q, a, t);
        assert_eq!(ans == Answer::Refused, i == 3, "{i}");
    }
    ask(&mut q, asker(2), t);
    ask(&mut q, asker(3), t);
    ask(&mut q, asker(4), t);
    assert_eq!(q.waiting_count(), 6);
    assert_eq!(ask(&mut q, asker(5), t), Answer::Refused);
    // Peers that stop asking are dropped after an hour.
    q.process(0, t + Duration::from_secs(3601));
    assert_eq!(q.waiting_count(), 0);
}

#[test]
fn a_slot_ends_with_its_connection() {
    let mut q = two_slots();
    let t = Instant::now();
    ask(&mut q, asker(1), t);
    let h = Md4Hash([1; 16]);
    assert_eq!(q.slot_file(&h), Some(FILE));
    q.set_connected(&h, false);
    assert!(!q.has_slot(&h));
    ask(&mut q, asker(2), t + Duration::from_secs(5));
    assert!(q.ended(&Md4Hash([2; 16])));
    assert!(!q.ended(&Md4Hash([2; 16])));
}

#[test]
fn credits_are_kept_in_clients_met() {
    let dir = TempDir::new("credits");
    let cfg = dir.0.join("config");
    let now = 1_800_000_000;
    let mut c = Credits::load(&cfg, now).unwrap();
    assert!(c.is_empty());
    let (a, b, idle) = (Md4Hash([1; 16]), Md4Hash([2; 16]), Md4Hash([3; 16]));
    c.add_downloaded(&a, 5 << 20, now);
    c.add_uploaded(&a, 1 << 20, now);
    c.add_uploaded(&b, 100, now - 200 * 86_400);
    assert!(c.set_public_key(&a, &[7; 76], now));
    assert!(!c.set_public_key(&a, &[8; 76], now));
    assert!(c.public_key(&idle).is_none());
    let _ = c.score_ratio(&idle, IdentState::NotAvailable, true);
    c.save().unwrap();

    // Loaded again: b is too old and is dropped.
    let c = Credits::load(&cfg, now).unwrap();
    assert_eq!(c.len(), 1);
    let r = c.get(&a).unwrap();
    assert_eq!((r.downloaded, r.uploaded), (5 << 20, 1 << 20));
    assert_eq!(c.public_key(&a), Some(vec![7; 76]));
    // 5 MiB down against 1 up: min(10, sqrt(5 + 2)) ≈ 2.6.
    let ratio = c.score_ratio(&a, IdentState::Identified, true);
    assert!((ratio - 7f32.sqrt()).abs() < 0.01, "{ratio}");
    // Not identified while we could check: no credit.
    assert_eq!(c.score_ratio(&a, IdentState::Failed, true), 1.0);
}

/// A remule download fetching a file a remule upload session shares, both
/// on disk, the queue deciding the slot, every packet through the codec.
#[test]
fn a_shared_file_uploads_into_a_part_file() {
    use ed2k_codec::Packet;
    use ed2k_peer::download::{Event as DownEvent, Session};
    use ed2k_peer::hello::{CryptSettings, MiscOptions2};
    use ed2k_peer::upload::{Event as UpEvent, UploadSession};
    use ed2k_peer::{Hello, PeerPacket};
    use ed2k_types::ed2k::PARTSIZE;

    use crate::shared::{mtime, ScanOptions, SharedFiles};
    use crate::{Completion, PartFile, SourceView};

    let dir = TempDir::new("upload-e2e");
    let size = 2 * PARTSIZE + 77_777;
    let content = data(size, 99);
    let src = dir.0.join("share");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("book.txt"), &content).unwrap();
    let mut shares = SharedFiles::load(&dir.0.join("config")).unwrap();
    let r = shares.scan(
        &ScanOptions {
            dirs: vec![src.clone()],
            ..Default::default()
        },
        1,
    );
    let p = &r.to_hash[0];
    let h = SharedFiles::hash(p).unwrap();
    shares.add_hashed(p, &h, mtime(&fs::metadata(p).unwrap()), 1);

    let mut queue = two_slots();
    let mut pf = PartFile::create(&dir.temp(), "book.txt", h.ed2k, size).unwrap();
    let hello = |b: u8, id: u32| {
        let mut x = Hello::amule(Md4Hash([b; 16]), id, 4662, "peer");
        x.misc2 = Some(MiscOptions2::amule(0, CryptSettings::default()));
        x
    };
    let wire = |p: Packet, ctx| {
        PeerPacket::parse(Packet::parse_tcp(&p.to_tcp_bytes().unwrap()).unwrap(), ctx).unwrap()
    };
    let now = Instant::now();
    let mut last = None;
    let (mut down, first) = {
        let view = SourceView {
            file: &mut pf,
            last_part: &mut last,
            wants_sources: false,
        };
        Session::connect(hello(0x11, 0x0100_000A), &view, now).unwrap()
    };
    let PeerPacket::Hello(peer_hello) = wire(first, Default::default()) else {
        panic!()
    };
    let downloader = Asker {
        user_hash: peer_hello.user_hash,
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        low_id: false,
        score_ratio: 1.0,
        old_emule: false,
        udp_port: 0,
        udp_version: 0,
        crypt_udp: false,
    };
    let (mut up, out) = UploadSession::accepted(hello(0x22, 0x0200_000A), peer_hello).unwrap();
    let mut to_down: VecDeque<Packet> = out.send.into();
    let mut uploaded = 0u64;
    let mut done = false;
    while let Some(p) = to_down.pop_front() {
        let mut view = SourceView {
            file: &mut pf,
            last_part: &mut last,
            wants_sources: false,
        };
        let out = down.handle(wire(p, down.parse_context()), &mut view, now);
        done |= out.events.contains(&DownEvent::NoNeededParts);
        for p in out.send {
            let out = up.handle(wire(p, up.parse_context()), &shares);
            to_down.extend(out.send);
            for e in out.events {
                match e {
                    UpEvent::UploadRequested(file) => {
                        match queue.request(
                            downloader.clone(),
                            file,
                            priority::NORMAL,
                            true,
                            0,
                            now,
                        ) {
                            Answer::Slot => to_down.push_back(up.accept()),
                            Answer::Queued(r) => to_down.push_back(up.queue_rank(r)),
                            Answer::Refused => {}
                        }
                    }
                    UpEvent::BlocksRequested { hash, blocks } => {
                        for b in blocks {
                            let bytes = shares.read_block(&hash, b.clone()).unwrap();
                            uploaded += bytes.len() as u64;
                            let _ = queue.sent(&downloader.user_hash, bytes.len() as u64, now);
                            to_down.extend(up.block_packets(b, &bytes, 0, "book.txt"));
                        }
                    }
                    UpEvent::UploadEnded => {
                        queue.ended(&downloader.user_hash);
                    }
                    _ => {}
                }
            }
        }
    }
    assert!(done, "the download did not finish");
    assert!(uploaded >= size);
    assert_eq!(queue.slot_count(), 0);
    let incoming = dir.incoming();
    let Completion::Done(path) = pf.complete(&incoming).unwrap() else {
        panic!("not complete");
    };
    assert_eq!(fs::read(path).unwrap(), content);
}

/// A peer that downloads from an [`Uploader`](crate::uploader::Uploader):
/// our download session on a part file, packets through the codec.
struct Downloader {
    pf: crate::PartFile,
    last: Option<u16>,
    session: Option<ed2k_peer::download::Session>,
    queued: bool,
}

impl Downloader {
    fn view(&mut self) -> crate::SourceView<'_> {
        crate::SourceView {
            file: &mut self.pf,
            last_part: &mut self.last,
            wants_sources: false,
        }
    }

    /// Hand `actions` for `conn` to the session, its answers back to the
    /// uploader, until both are quiet. Returns the other actions.
    fn pump(
        &mut self,
        up: &mut crate::uploader::Uploader,
        conn: u64,
        actions: Vec<crate::download_queue::Action>,
        now: Instant,
    ) -> Vec<crate::download_queue::Action> {
        use crate::download_queue::Action;
        use ed2k_codec::Packet;
        use ed2k_peer::download::Event as DownEvent;
        use ed2k_peer::PeerPacket;
        let mut todo: VecDeque<Action> = actions.into();
        let mut rest = Vec::new();
        while let Some(a) = todo.pop_front() {
            match a {
                Action::Send { conn: c, packets } if c == conn => {
                    for p in packets {
                        let mut session = self.session.take().expect("a session");
                        let p = Packet::parse_tcp(&p.to_tcp_bytes().unwrap()).unwrap();
                        let p = PeerPacket::parse(p, session.parse_context()).unwrap();
                        let out = session.handle(p, &mut self.view(), now);
                        self.queued |= out
                            .events
                            .iter()
                            .any(|e| matches!(e, DownEvent::Queued { .. }));
                        self.session = Some(session);
                        for p in out.send {
                            let p = Packet::parse_tcp(&p.to_tcp_bytes().unwrap()).unwrap();
                            todo.extend(up.packet(conn, p, now));
                        }
                    }
                }
                a => rest.push(a),
            }
        }
        rest
    }
}

/// Our uploader with two slots, both taken, sharing one file; and a
/// downloader for it.
fn callback_setup(dir: &TempDir) -> (crate::uploader::Uploader, Downloader, Vec<u8>, Instant) {
    use std::sync::{Arc, Mutex};

    use ed2k_peer::hello::{CryptSettings, MiscOptions2};
    use ed2k_peer::Hello;
    use ed2k_types::ed2k::PARTSIZE;

    use crate::shared::{mtime, ScanOptions, SharedFiles};

    let size = 2 * PARTSIZE + 4_321;
    let content = data(size, 31);
    let src = dir.0.join("share");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("book.txt"), &content).unwrap();
    let mut shares = SharedFiles::load(&dir.0.join("config")).unwrap();
    let r = shares.scan(
        &ScanOptions {
            dirs: vec![src.clone()],
            ..Default::default()
        },
        1,
    );
    let p = &r.to_hash[0];
    let h = SharedFiles::hash(p).unwrap();
    shares.add_hashed(p, &h, mtime(&fs::metadata(p).unwrap()), 1);

    let t0 = Instant::now();
    let mut queue = two_slots();
    assert_eq!(ask(&mut queue, asker(1), t0), Answer::Slot);
    assert_eq!(
        ask(&mut queue, asker(2), t0 + Duration::from_secs(2)),
        Answer::Slot
    );
    let mut ours = Hello::amule(Md4Hash([0x22; 16]), 0x0200_000A, 4662, "sharer");
    ours.misc2 = Some(MiscOptions2::amule(0, CryptSettings::default()));
    let up = crate::uploader::Uploader::new(ours, None, Arc::new(Mutex::new(shares)), queue, None);
    let pf = crate::PartFile::create(&dir.temp(), "book.txt", h.ed2k, size).unwrap();
    let d = Downloader {
        pf,
        last: None,
        session: None,
        queued: false,
    };
    (up, d, content, t0 + Duration::from_secs(4))
}

fn downloader_hello() -> ed2k_peer::Hello {
    use ed2k_peer::hello::{CryptSettings, MiscOptions2};
    // A HighID at 10.0.0.9, listening on 4711.
    let mut h = ed2k_peer::Hello::amule(Md4Hash([0x11; 16]), 0x0900_000A, 4711, "getter");
    h.misc2 = Some(MiscOptions2::amule(0, CryptSettings::default()));
    h
}

/// The downloader asks, waits in the queue, and its connection goes idle.
fn queue_then_go_idle(up: &mut crate::uploader::Uploader, d: &mut Downloader, now: Instant) {
    use crate::download_queue::Action;
    use ed2k_codec::Packet;
    use ed2k_peer::download::Session;
    use ed2k_peer::PeerPacket;

    let (session, hello) = {
        let view = d.view();
        Session::connect(downloader_hello(), &view, now).unwrap()
    };
    d.session = Some(session);
    let p = Packet::parse_tcp(&hello.to_tcp_bytes().unwrap()).unwrap();
    let PeerPacket::Hello(h) = PeerPacket::parse(p, Default::default()).unwrap() else {
        panic!()
    };
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let actions = up.accept(1, h, ip, now);
    let rest = d.pump(up, 1, actions, now);
    assert!(rest.is_empty(), "{rest:?}");
    assert!(d.queued, "not queued");
    assert_eq!(up.queue().waiting_count(), 1);

    // Nothing for CONNECTION_TIMEOUT: closed, its place kept.
    assert!(up
        .tick(now + Duration::from_secs(30), &mut || 99)
        .is_empty());
    let a = up.tick(now + Duration::from_secs(41), &mut || 99);
    assert!(matches!(a[..], [Action::Close { conn: 1 }]), "{a:?}");
    assert!(!up.owns(1));
    let mut s = d.session.take().unwrap();
    let _ = s.closed(&mut d.view());
    d.session = Some(s);
    assert_eq!(up.queue().waiting_count(), 1);
}

#[test]
fn a_waiting_peer_is_called_back_when_a_slot_frees() {
    use crate::download_queue::{Action, Report};
    use crate::Completion;
    use ed2k_codec::Packet;
    use ed2k_peer::download::Session;
    use ed2k_peer::PeerPacket;
    use std::net::SocketAddr;

    let dir = TempDir::new("upload-callback");
    let (mut up, mut d, content, now) = callback_setup(&dir);
    queue_then_go_idle(&mut up, &mut d, now);
    let parts = d.session.as_ref().unwrap().peer_parts().cloned();

    // A slot frees: we dial the peer where it said it listens.
    up.queue_mut().ended(&Md4Hash([1; 16]));
    let now = now + Duration::from_secs(45);
    let a = up.tick(now, &mut || 7);
    let [Action::Connect {
        conn: 7,
        addr,
        obfuscate_for: None,
    }] = a[..]
    else {
        panic!("{a:?}")
    };
    assert_eq!(addr, "10.0.0.9:4711".parse::<SocketAddr>().unwrap());
    assert!(up.owns(7));
    assert_eq!(up.queue().slot_count(), 2);

    // Connected: our hello; it takes us for the source it waits on.
    let a = up.connected(7, now);
    let [Action::Send {
        conn: 7,
        ref packets,
    }] = a[..]
    else {
        panic!("{a:?}")
    };
    let p = Packet::parse_tcp(&packets[0].to_tcp_bytes().unwrap()).unwrap();
    let PeerPacket::Hello(h) = PeerPacket::parse(p, Default::default()).unwrap() else {
        panic!()
    };
    let (session, out) = {
        let view = d.view();
        Session::accepted(downloader_hello(), h, &view, parts, now).unwrap()
    };
    d.session = Some(session);
    let mut actions = Vec::new();
    for p in out.send {
        let p = Packet::parse_tcp(&p.to_tcp_bytes().unwrap()).unwrap();
        actions.extend(up.packet(7, p, now));
    }
    // The hello answer gives it the slot, and the file goes over.
    let rest = d.pump(&mut up, 7, actions, now);
    let file = d.pf.hash();
    assert!(
        rest.iter().any(|a| matches!(
            a,
            Action::Report(Report::UploadStarted { user, file: f })
                if *user == Md4Hash([0x11; 16]) && *f == file
        )),
        "{rest:?}"
    );
    assert!(up.sent_total() >= content.len() as u64);
    assert_eq!(up.queue().waiting_count(), 0);
    let Completion::Done(path) = d.pf.complete(&dir.incoming()).unwrap() else {
        panic!("not complete");
    };
    assert_eq!(fs::read(path).unwrap(), content);
}

#[test]
fn an_unreachable_peer_loses_its_slot() {
    use crate::download_queue::Action;

    let dir = TempDir::new("upload-callback-fail");
    let (mut up, mut d, _, now) = callback_setup(&dir);
    queue_then_go_idle(&mut up, &mut d, now);
    up.queue_mut().ended(&Md4Hash([1; 16]));
    let now = now + Duration::from_secs(45);
    let a = up.tick(now, &mut || 7);
    assert!(matches!(a[..], [Action::Connect { conn: 7, .. }]));
    // The connection fails.
    up.closed(7);
    assert!(!up.owns(7));
    assert_eq!(up.queue().slot_count(), 1);
    assert_eq!(up.queue().waiting_count(), 0);

    // A dial that connects but never answers our hello times out.
    let dir = TempDir::new("upload-callback-mute");
    let (mut up, mut d, _, now) = callback_setup(&dir);
    queue_then_go_idle(&mut up, &mut d, now);
    up.queue_mut().ended(&Md4Hash([1; 16]));
    let now = now + Duration::from_secs(45);
    let _ = up.tick(now, &mut || 7);
    let _ = up.connected(7, now);
    let a = up.tick(now + Duration::from_secs(41), &mut || 8);
    assert!(
        a.iter().any(|a| matches!(a, Action::Close { conn: 7 })),
        "{a:?}"
    );
    assert_eq!(up.queue().slot_count(), 1);
}

#[test]
fn the_credit_history_carries_the_metadata_block() {
    use ed2k_formats::clients_met::{ClientMeta, ClientsMet, CreditRecord, MetaEntry};
    let dir = crate::tests_part_file::TempDir::new("credit-history");
    let now = 1_800_000_000;
    let mut a = CreditRecord::new(Md4Hash([1; 16]));
    a.uploaded = 10;
    a.last_seen = now;
    let mut b = CreditRecord::new(Md4Hash([2; 16]));
    b.downloaded = 20;
    b.last_seen = now;
    let meta = MetaEntry {
        key: a.key,
        meta: ClientMeta {
            name: "a".into(),
            first_seen: now - 100,
            sessions: 3,
            ..Default::default()
        },
    };
    let met = ClientsMet::save(&[a.clone(), b.clone()], &[meta]);
    std::fs::write(dir.0.join("clients.met"), met.write()).unwrap();
    let credits = crate::credits::Credits::load(&dir.0, now).unwrap();
    let h = credits.history();
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].0.key, a.key);
    assert_eq!(h[0].1.as_ref().unwrap().sessions, 3);
    assert_eq!((h[1].0.downloaded, h[1].1.is_none()), (20, true));
}

/// `OP_REASKFILEPING` as `CClientUDPSocket::ProcessPacket` takes it: the
/// waiting peer found by IP and UDP port (or IP alone when it is the only
/// one there), its place kept and its rank given; another file gets no
/// answer; a stranger hears the queue is full only when it nearly is.
#[test]
fn udp_reasks_find_the_waiting_peer() {
    let t0 = Instant::now();
    let mut q = UploadQueue::new(UploadConfig {
        max_upload_kbps: 20,
        queue_size: 100,
        purge_after: Duration::from_secs(3600),
        ..Default::default()
    });
    // Two slots taken, then 3 and 4 wait.
    for n in 1..=4 {
        ask(&mut q, asker(n), t0 + Duration::from_secs(u64::from(n) * 2));
    }
    assert_eq!(q.waiting_count(), 2);
    let ip = |n| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n));
    let t = t0 + Duration::from_secs(60);
    assert_eq!(
        q.udp_reask(ip(4), 4672, FILE, t),
        UdpReask::Waiting {
            user: Md4Hash([4; 16]),
            rank: 2,
            udp_version: 4,
            crypt_udp: false
        }
    );
    // From another port of a lone waiter's IP: still it, the port updated.
    assert!(matches!(
        q.udp_reask(ip(3), 5000, FILE, t),
        UdpReask::Waiting { rank: 1, .. }
    ));
    assert!(matches!(
        q.udp_reask(ip(3), 5000, FILE, t),
        UdpReask::Waiting { rank: 1, .. }
    ));
    assert_eq!(
        q.udp_reask(ip(3), 5000, Md4Hash([9; 16]), t),
        UdpReask::OtherFile {
            user: Md4Hash([3; 16]),
            crypt_udp: false
        }
    );
    // Strangers: room enough, then 50 or fewer places left.
    assert_eq!(
        q.udp_reask(ip(9), 4672, FILE, t),
        UdpReask::Unknown { queue_full: false }
    );
    q = UploadQueue::new(UploadConfig {
        max_upload_kbps: 20,
        queue_size: 49,
        ..Default::default()
    });
    assert_eq!(
        q.udp_reask(ip(9), 4672, FILE, t),
        UdpReask::Unknown { queue_full: true }
    );
    // Two waiting from one address, asking from a third port.
    let mut q = UploadQueue::new(UploadConfig {
        max_upload_kbps: 20,
        queue_size: 100,
        ..Default::default()
    });
    for n in 1..=2 {
        ask(&mut q, asker(n), t0);
    }
    for (n, port) in [(5u8, 1000u16), (6, 2000)] {
        let mut a = asker(n);
        a.ip = ip(7);
        a.udp_port = port;
        ask(&mut q, a, t0);
    }
    assert_eq!(q.udp_reask(ip(7), 3000, FILE, t), UdpReask::Ambiguous);
    assert!(matches!(
        q.udp_reask(ip(7), 2000, FILE, t),
        UdpReask::Waiting { user, .. } if user == Md4Hash([6; 16])
    ));
}
