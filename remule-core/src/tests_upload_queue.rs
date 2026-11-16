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
use crate::upload_queue::{Answer, Asker, QueueAction, UploadConfig, UploadQueue};

fn asker(n: u8) -> Asker {
    Asker {
        user_hash: Md4Hash([n; 16]),
        ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)),
        low_id: false,
        score_ratio: 1.0,
        old_emule: false,
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
