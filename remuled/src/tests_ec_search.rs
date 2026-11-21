// SPDX-License-Identifier: GPL-2.0-or-later
//! Searches over external connections: what may start and what it sends,
//! results merged as `CSearchList::AddToList` merges them, the progress
//! reported, and an EC client searching a scripted server through a
//! running daemon and downloading a result.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ed2k_formats::server_met::{ServerMet, ServerRecord};
use ed2k_kad::search::KeywordResult;
use ed2k_server::{SearchParams, SearchResult};
use ed2k_types::Md4Hash;
use remule_ec::codes::*;
use remule_ec::{Client, ConnectOptions, Packet, Tag};

use crate::config;
use crate::ec_search::{download_status, Kind, Lifecycle, Networks, SearchList};

const ED2K: Networks = Networks {
    ed2k_connected: true,
    large_files: true,
    kad_running: false,
};
const KAD: Networks = Networks {
    ed2k_connected: false,
    large_files: false,
    kad_running: true,
};
const NONE: Networks = Networks {
    ed2k_connected: false,
    large_files: false,
    kad_running: false,
};

fn result(hash: u8, name: &str, size: u64, sources: u32, complete: u32) -> SearchResult {
    SearchResult {
        hash: Md4Hash([hash; 16]),
        client_id: u32::from_le_bytes([10, 0, 0, hash]),
        client_port: 4662,
        name: name.into(),
        size,
        sources,
        complete_sources: complete,
        file_type: None,
        rating: 0,
        tags: Vec::new(),
    }
}

fn keyword(hash: u8, name: &str, availability: u32) -> KeywordResult {
    KeywordResult {
        hash: Md4Hash([hash; 16]),
        name: name.into(),
        size: 1000,
        file_type: String::new(),
        format: String::new(),
        artist: String::new(),
        album: String::new(),
        title: String::new(),
        length: 0,
        bitrate: 0,
        codec: String::new(),
        availability,
        publish_info: 0,
        from: Ipv4Addr::LOCALHOST,
    }
}

/// A local search started, as `serve` starts it.
fn local(list: &mut SearchList, now: Instant) {
    let plan = list
        .plan(Kind::Local, &SearchParams::new("ubuntu"), ED2K)
        .unwrap();
    list.begin(&plan, None, now);
}

#[test]
fn a_search_starts_only_where_it_can() {
    let list = SearchList::default();
    let p = SearchParams::new("ubuntu iso");
    let err = |k, n| list.plan(k, &p, n).unwrap_err();
    assert_eq!(
        err(Kind::Local, KAD),
        "eD2k search can't be done if eD2k is not connected"
    );
    assert_eq!(
        err(Kind::Global, NONE),
        "eD2k search can't be done if eD2k is not connected"
    );
    assert_eq!(
        err(Kind::Kad, ED2K),
        "Kad search can't be done if Kad is not running"
    );
    assert_eq!(
        err(Kind::All, NONE),
        "All search can't be done if neither eD2k nor Kad is available"
    );
    // Kad needs a word of three letters.
    let short = SearchParams::new("ab");
    assert_eq!(
        list.plan(Kind::Kad, &short, KAD).unwrap_err(),
        "No keyword for Kad search - aborting"
    );
    // ... which an all search can do without, with eD2k.
    let both = Networks {
        kad_running: true,
        ..ED2K
    };
    let plan = list.plan(Kind::All, &short, both).unwrap();
    assert!(plan.server.is_some() && plan.kad.is_none());
    // The query's syntax errors, one per line.
    let bad = SearchParams::new("ubuntu AND");
    assert!(list
        .plan(Kind::Local, &bad, ED2K)
        .unwrap_err()
        .ends_with('\n'));
    // What each kind sends.
    let plan = list.plan(Kind::Local, &p, ED2K).unwrap();
    assert!(plan.server.is_some() && plan.kad.is_none());
    let plan = list.plan(Kind::Kad, &p, KAD).unwrap();
    assert!(plan.server.is_none() && plan.kad == Some(p.clone()));
    let plan = list.plan(Kind::All, &p, KAD).unwrap();
    assert!(plan.server.is_none() && plan.kad.is_some());
}

#[test]
fn results_merge_as_add_to_list_merges_them() {
    let mut list = SearchList::default();
    local(&mut list, Instant::now());
    list.server_results(vec![
        result(1, "film.mkv", 1000, 3, 1),
        // The same file under the same name: one result, counts added.
        result(1, "film.mkv", 1000, 2, 1),
        // No size, or too large: dropped.
        result(2, "empty", 0, 9, 9),
        result(3, "huge", 0x40_0000_0001, 9, 9),
        result(4, "other.iso", 5000, 1, 0),
    ]);
    let r = list.results();
    assert_eq!(r.len(), 2);
    assert_eq!((r[0].sources.total(), r[0].complete.total()), (5, 2));
    assert!(r[0].children.is_empty());
    assert_eq!(
        r[0].clients,
        [SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4662)]
    );

    // Another name for it: a group, the first child being the first result;
    // the parent takes the name with the most sources.
    let mut list = SearchList::default();
    local(&mut list, Instant::now());
    list.server_results(vec![
        result(1, "a.mkv", 1000, 2, 0),
        result(1, "b.mkv", 1000, 7, 0),
        result(1, "a.mkv", 1000, 1, 0),
    ]);
    let p = &list.results()[0];
    let names: Vec<&str> = p.children.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["a.mkv", "b.mkv"]);
    assert_eq!(p.children[0].sources.total(), 3);
    assert_eq!((p.name.as_str(), p.sources.total()), ("b.mkv", 10));
    let mut ids: Vec<u32> = p.children.iter().map(|c| c.ecid).collect();
    ids.push(p.ecid);
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3, "every result its own ECID");
    assert!(p.children.iter().all(|c| c.parent == Some(p.ecid)));

    // Kad's counts: the largest seen, not a sum.
    let mut list = SearchList::default();
    let plan = list
        .plan(Kind::Kad, &SearchParams::new("film"), KAD)
        .unwrap();
    list.begin(&plan, Some(7), Instant::now());
    list.kad_result(7, keyword(5, "film.avi", 4));
    list.kad_result(7, keyword(5, "film.avi", 9));
    list.kad_result(7, keyword(5, "film.avi", 2));
    // Another lookup's results are not this search's.
    list.kad_result(8, keyword(6, "x.avi", 1));
    assert_eq!(list.results().len(), 1);
    assert_eq!(list.results()[0].sources.kad, 9);
}

#[test]
fn progress_is_told_as_get_search_progress_tells_it() {
    let t0 = Instant::now();
    let mut list = SearchList::default();
    assert_eq!(list.lifecycle(), Lifecycle::Idle);
    assert_eq!(list.progress(t0), 0);

    // Local: 0xffff until the server answers, then finished.
    local(&mut list, t0);
    assert_eq!(
        (list.lifecycle(), list.progress(t0), list.percent(t0)),
        (Lifecycle::Running, 0xffff, 0)
    );
    list.server_results(vec![result(1, "a", 10, 1, 0)]);
    assert_eq!(
        (list.lifecycle(), list.progress(t0), list.percent(t0)),
        (Lifecycle::Finished, 0, 100)
    );
    // A late answer adds nothing.
    list.server_results(vec![result(2, "b", 10, 1, 0)]);
    assert_eq!(list.results().len(), 1);

    // No answer within 12 s: over all the same.
    local(&mut list, t0);
    list.poll(t0 + Duration::from_secs(11));
    assert_eq!(list.lifecycle(), Lifecycle::Running);
    list.poll(t0 + Duration::from_secs(12));
    assert_eq!(list.lifecycle(), Lifecycle::Finished);

    // Kad: 0 while it runs, a ramp over 45 s capped at 99, 0xfffe at its end.
    let mut list = SearchList::default();
    let plan = list
        .plan(Kind::Kad, &SearchParams::new("film"), KAD)
        .unwrap();
    list.begin(&plan, Some(3), t0);
    assert_eq!(list.progress(t0), 0);
    assert_eq!(list.percent(t0 + Duration::from_secs(9)), 20);
    assert_eq!(list.percent(t0 + Duration::from_secs(90)), 99);
    list.kad_done(4);
    assert_eq!(list.lifecycle(), Lifecycle::Running);
    list.kad_done(3);
    assert_eq!(
        (list.lifecycle(), list.progress(t0), list.percent(t0)),
        (Lifecycle::Finished, 0xfffe, 100)
    );

    // Stopped: idle, the results kept.
    let mut list = SearchList::default();
    local(&mut list, t0);
    list.server_results(vec![result(1, "a", 10, 1, 0)]);
    list.stop();
    assert_eq!(list.lifecycle(), Lifecycle::Idle);
    assert_eq!(list.results().len(), 1);
    let p = list.progress_reply(t0);
    assert_eq!(p.tag(EC_TAG_SEARCH_RESULT_COUNT).unwrap().as_int(), 0);
    assert_eq!(p.tag(EC_TAG_SEARCH_LIFECYCLE_STATE).unwrap().as_int(), 0);
    // A new search empties the bucket.
    list.remove_results();
    assert!(list.results().is_empty());

    // All: running while either part runs.
    let mut list = SearchList::default();
    let both = Networks {
        kad_running: true,
        ..ED2K
    };
    let plan = list
        .plan(Kind::All, &SearchParams::new("film"), both)
        .unwrap();
    list.begin(&plan, Some(9), t0);
    list.server_results(Vec::new());
    assert_eq!(list.lifecycle(), Lifecycle::Running);
    list.kad_done(9);
    assert_eq!(
        (list.lifecycle(), list.progress(t0)),
        (Lifecycle::Finished, 0xfffe)
    );
    let p = list.progress_reply(t0);
    assert_eq!(p.tag(EC_TAG_SEARCH_LIFECYCLE_KIND).unwrap().as_int(), 5);
}

#[test]
fn results_are_told_as_cec_searchfile_tag_tells_them() {
    let mut list = SearchList::default();
    local(&mut list, Instant::now());
    list.server_results(vec![
        result(1, "a.mkv", 1000, 2, 1),
        result(1, "b.mkv", 1000, 7, 0),
        result(2, "c.iso", 5000, 1, 0),
    ]);
    let status = |h: &Md4Hash| {
        if h.0[0] == 2 {
            download_status::QUEUED
        } else {
            download_status::NEW
        }
    };
    // Parents only, unless the request asks for the groups.
    let full = Packet::new(EC_OP_SEARCH_RESULTS).with_detail(EC_DETAIL_FULL);
    let r = list.results_reply(&full, &status);
    assert_eq!((r.opcode, r.tags.len()), (EC_OP_SEARCH_RESULTS, 2));
    let t = &r.tags[0];
    assert_eq!(t.name, EC_TAG_SEARCHFILE);
    assert_eq!(t.child_str(EC_TAG_PARTFILE_NAME), "b.mkv");
    assert_eq!(t.child_int(EC_TAG_PARTFILE_SIZE_FULL), 1000);
    assert_eq!(
        t.child(EC_TAG_PARTFILE_HASH).unwrap().as_hash(),
        Some([1; 16])
    );
    assert_eq!(t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT), 9);
    assert_eq!(t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER), 1);
    assert_eq!(t.child_int(EC_TAG_SEARCHFILE_ED2K_SOURCES), 9);
    assert!(!t.has(EC_TAG_SEARCH_PARENT));
    assert_eq!(r.tags[1].child_int(EC_TAG_PARTFILE_STATUS), 2);
    let grouped = full.clone().with(Tag::empty(EC_TAG_SEARCH_PARENT));
    let r = list.results_reply(&grouped, &status);
    assert_eq!(r.tags.len(), 4);
    let parent = r.tags[0].as_int();
    assert_eq!(r.tags[1].child_int(EC_TAG_SEARCH_PARENT), parent);
    // Asked for by ECID; UPDATE without names.
    let one = Packet::new(EC_OP_SEARCH_RESULTS)
        .with_detail(EC_DETAIL_UPDATE)
        .with(Tag::int(EC_TAG_SEARCHFILE, list.results()[1].ecid.into()));
    let r = list.results_reply(&one, &status);
    assert_eq!(r.tags.len(), 1);
    assert!(!r.tags[0].has(EC_TAG_PARTFILE_NAME));
    assert!(r.tags[0].has(EC_TAG_PARTFILE_SOURCE_COUNT));

    // What a download finds: a parent by hash, any result by ECID.
    let child = list.results()[0].children[0].ecid;
    assert_eq!(
        list.find_for_download(Some(child), None).unwrap().name,
        "a.mkv"
    );
    assert_eq!(
        list.find_for_download(None, Some(Md4Hash([2; 16])))
            .unwrap()
            .name,
        "c.iso"
    );
    assert!(list
        .find_for_download(None, Some(Md4Hash([9; 16])))
        .is_none());
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-search-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One search result as a server sends it.
fn result_bytes(w: &mut ed2k_codec::Writer, hash: u8, name: &str, size: u32, sources: u32) {
    use ed2k_codec::{Tag, TagValue};
    use ed2k_types::tags::FileTag;
    w.hash(Md4Hash([hash; 16]))
        .u32(u32::from_le_bytes([10, 1, 2, hash]))
        .u16(4662);
    let tags = [
        Tag::string(FileTag::Filename as u8, name),
        Tag::new(FileTag::Filesize as u8, TagValue::U32(size)),
        Tag::new(FileTag::Sources as u8, TagValue::U32(sources)),
    ];
    w.u32(tags.len() as u32);
    for t in &tags {
        t.write_ed2k(w, ed2k_codec::io::StrEncoding::Utf8).unwrap();
    }
}

/// A scripted server: a HighID login, and each `OP_SEARCHREQUEST`
/// answered with three results, two of them one file under two names.
async fn searching_server(listener: tokio::net::TcpListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            loop {
                let mut head = [0u8; 5];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                let len = u32::from_le_bytes(head[1..5].try_into().unwrap()) as usize;
                let mut body = vec![0u8; len];
                if len == 0 || s.read_exact(&mut body).await.is_err() {
                    return;
                }
                let reply = match body[0] {
                    0x01 => {
                        let mut p = vec![0xE3, 5, 0, 0, 0, 0x40];
                        p.extend_from_slice(&[127, 0, 0, 1]);
                        p
                    }
                    // OP_SEARCHREQUEST
                    0x16 => {
                        let mut w = ed2k_codec::Writer::new();
                        w.u32(3);
                        result_bytes(&mut w, 1, "ubuntu-24.04.iso", 6_000_000, 120);
                        result_bytes(&mut w, 2, "Ubuntu Book.pdf", 77_000, 3);
                        result_bytes(&mut w, 2, "ubuntu-book.pdf", 77_000, 1);
                        let payload = w.into_bytes();
                        let mut p = vec![0xE3];
                        p.extend_from_slice(&((payload.len() + 1) as u32).to_le_bytes());
                        // OP_SEARCHRESULT
                        p.push(0x33);
                        p.extend_from_slice(&payload);
                        p
                    }
                    _ => continue,
                };
                if s.write_all(&reply).await.is_err() {
                    return;
                }
            }
        });
    }
}

const SECRET: &str = "5ebe2294ecd0e0f08eab7690d2a6ee69"; // md5("secret")

/// A daemon logged into a scripted server, with EC on: its config
/// directory, EC port and task.
async fn searching_daemon(
    name: &str,
) -> (
    TempDir,
    u16,
    tokio::task::JoinHandle<Result<crate::client::Summary, String>>,
) {
    let d = TempDir::new(name);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    tokio::spawn(searching_server(listener));
    let (port, ec_port) = (free_port(), free_port());
    std::fs::write(
        d.0.join("amule.conf"),
        format!(
            "[eMule]\nPort={port}\nConnectToKad=0\nConnectToED2K=1\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\n\
             ECPassword={SECRET}\n"
        ),
    )
    .unwrap();
    let met = ServerMet {
        version: 0x0E,
        servers: vec![ServerRecord {
            ip: Ipv4Addr::LOCALHOST,
            port: server_port,
            tags: Vec::new(),
        }],
        legacy_counts: false,
    };
    std::fs::write(d.0.join("server.met"), met.write()).unwrap();
    let loaded = config::load(&d.0).unwrap();
    let daemon = tokio::spawn(crate::client::run(
        loaded.client,
        Vec::new(),
        Vec::new(),
        std::future::pending(),
    ));
    let mut tries = 0;
    while tokio::net::TcpStream::connect(("127.0.0.1", ec_port))
        .await
        .is_err()
    {
        tries += 1;
        assert!(tries < 100, "the daemon never listened for EC");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    (d, ec_port, daemon)
}

/// A daemon logged into a scripted server: an EC client searches it,
/// reads the results and the progress as `amulecmd` does, downloads one,
/// and finds it in the download queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ec_client_searches_and_downloads_a_result() {
    let d = TempDir::new("e2e");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();
    tokio::spawn(searching_server(listener));
    let (port, ec_port) = (free_port(), free_port());
    std::fs::write(
        d.0.join("amule.conf"),
        format!(
            "[eMule]\nPort={port}\nConnectToKad=0\nConnectToED2K=1\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\n\
             ECPassword={SECRET}\n"
        ),
    )
    .unwrap();
    let met = ServerMet {
        version: 0x0E,
        servers: vec![ServerRecord {
            ip: Ipv4Addr::LOCALHOST,
            port: server_port,
            tags: Vec::new(),
        }],
        legacy_counts: false,
    };
    std::fs::write(d.0.join("server.met"), met.write()).unwrap();
    let loaded = config::load(&d.0).unwrap();
    let daemon = tokio::spawn(crate::client::run(
        loaded.client,
        Vec::new(),
        Vec::new(),
        std::future::pending(),
    ));
    let mut tries = 0;
    while tokio::net::TcpStream::connect(("127.0.0.1", ec_port))
        .await
        .is_err()
    {
        tries += 1;
        assert!(tries < 100, "the daemon never listened for EC");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(&ConnectOptions::new("127.0.0.1", ec_port, SECRET)).unwrap();
        let mut ask = |p: Packet| c.request(&p).unwrap();
        let until =
            |ask: &mut dyn FnMut(Packet) -> Packet, p: Packet, ok: &dyn Fn(&Packet) -> bool| {
                for _ in 0..100 {
                    let r = ask(p.clone());
                    if ok(&r) {
                        return r;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                panic!("never got there: {:?}", ask(p.clone()));
            };
        let search = |ty: u8, words: &str| {
            Packet::new(EC_OP_SEARCH_START).with(
                Tag::int(EC_TAG_SEARCH_TYPE, ty.into())
                    .with(Tag::string(EC_TAG_SEARCH_NAME, words))
                    .with(Tag::string(EC_TAG_SEARCH_FILE_TYPE, "")),
            )
        };
        let hashed = |r: &Packet, h: u8| {
            r.tags
                .iter()
                .find(|t| t.child(EC_TAG_PARTFILE_HASH).unwrap().as_hash() == Some([h; 16]))
                .cloned()
                .unwrap()
        };
        // Logged in first.
        until(
            &mut ask,
            Packet::new(EC_OP_GET_CONNSTATE).with_detail(EC_DETAIL_CMD),
            &|r| r.tags[0].as_int() & 1 == 1,
        );
        // Kad is off here.
        let r = ask(search(EC_SEARCH_KAD, "ubuntu"));
        assert_eq!(r.opcode, EC_OP_FAILED);
        assert_eq!(
            r.message().unwrap(),
            "Kad search can't be done if Kad is not running"
        );
        let r = ask(search(EC_SEARCH_WEB, "ubuntu"));
        assert_eq!(
            r.message().unwrap(),
            "WebSearch from remote interface makes no sense."
        );
        let r = ask(search(EC_SEARCH_LOCAL, "ubuntu"));
        assert_eq!(r.opcode, EC_OP_STRINGS);
        assert_eq!(
            r.message().unwrap(),
            "Search in progress. Refetch results in a moment!"
        );
        // `progress` until done, then `results`.
        let p = until(&mut ask, Packet::new(EC_OP_SEARCH_PROGRESS), &|r| {
            r.tag(EC_TAG_SEARCH_LIFECYCLE_STATE).map(Tag::as_int)
                == Some(Lifecycle::Finished as u64)
        });
        assert_eq!(p.tag(EC_TAG_SEARCH_RESULT_COUNT).unwrap().as_int(), 2);
        assert_eq!(
            p.tag(EC_TAG_SEARCH_LIFECYCLE_PERCENT).unwrap().as_int(),
            100
        );
        let r = ask(Packet::new(EC_OP_SEARCH_RESULTS).with_detail(EC_DETAIL_FULL));
        assert_eq!(r.tags.len(), 2);
        let book = hashed(&r, 2);
        assert_eq!(book.child_str(EC_TAG_PARTFILE_NAME), "Ubuntu Book.pdf");
        assert_eq!(book.child_int(EC_TAG_PARTFILE_SOURCE_COUNT), 4);
        assert_eq!(
            book.child_int(EC_TAG_PARTFILE_STATUS),
            u64::from(download_status::NEW)
        );

        // `download`: as amulecmd sends it, by hash with a category.
        let dl = Packet::new(EC_OP_DOWNLOAD_SEARCH_RESULT)
            .with(Tag::hash(EC_TAG_PARTFILE, [2; 16]).with(Tag::int(EC_TAG_PARTFILE_CAT, 0)));
        assert_eq!(ask(dl).opcode, EC_OP_STRINGS);
        let q = until(&mut ask, Packet::new(EC_OP_GET_DLOAD_QUEUE), &|q| {
            q.tags.len() == 1
        });
        assert_eq!(q.tags[0].child_str(EC_TAG_PARTFILE_NAME), "Ubuntu Book.pdf");
        assert_eq!(q.tags[0].child_int(EC_TAG_PARTFILE_SIZE_FULL), 77_000);
        let r = ask(Packet::new(EC_OP_SEARCH_RESULTS));
        assert_eq!(
            hashed(&r, 2).child_int(EC_TAG_PARTFILE_STATUS),
            u64::from(download_status::QUEUED)
        );
        // A result no search holds.
        let dl =
            Packet::new(EC_OP_DOWNLOAD_SEARCH_RESULT).with(Tag::hash(EC_TAG_PARTFILE, [9; 16]));
        let r = ask(dl);
        assert_eq!(r.message().unwrap(), "No open search holds this result.");

        // Stopped: idle, the results kept.
        assert_eq!(ask(Packet::new(EC_OP_SEARCH_STOP)).opcode, EC_OP_MISC_DATA);
        let p = ask(Packet::new(EC_OP_SEARCH_PROGRESS));
        assert_eq!(p.tag(EC_TAG_SEARCH_LIFECYCLE_STATE).unwrap().as_int(), 0);
        assert_eq!(ask(Packet::new(EC_OP_SEARCH_RESULTS)).tags.len(), 2);
        // A legacy client has no searches to list.
        let l = ask(Packet::new(EC_OP_SEARCH_LIST));
        assert_eq!((l.opcode, l.tags.len()), (EC_OP_SEARCH_LIST, 0));
        assert_eq!(ask(Packet::new(EC_OP_SHUTDOWN)).opcode, EC_OP_NOOP);
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
}

/// What amuleapi does, speaking multi-search: two searches by ID, each
/// polled, listed, its results read and one downloaded; one stopped, one
/// closed, and an ID no search has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_search_client_runs_searches_by_id() {
    let (_d, ec_port, daemon) = searching_daemon("multi").await;
    tokio::task::spawn_blocking(move || {
        let mut opts = ConnectOptions::new("127.0.0.1", ec_port, SECRET);
        opts.capabilities = vec![EC_TAG_CAN_MULTI_SEARCH, EC_TAG_CAN_SEARCH_PROGRESS_UNION];
        let mut c = Client::connect(&opts).unwrap();
        let mut ask = |p: Packet| c.request(&p).unwrap();
        for _ in 0..100 {
            let r = ask(Packet::new(EC_OP_GET_CONNSTATE).with_detail(EC_DETAIL_CMD));
            if r.tags[0].as_int() & 1 == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let search = |words: &str, r: u64| {
            Packet::new(EC_OP_SEARCH_START)
                .with(
                    Tag::int(EC_TAG_SEARCH_TYPE, EC_SEARCH_LOCAL.into())
                        .with(Tag::string(EC_TAG_SEARCH_NAME, words))
                        .with(Tag::string(EC_TAG_SEARCH_FILE_TYPE, "")),
                )
                .with(Tag::int(EC_TAG_SEARCH_REF, r))
        };
        // A refusal echoes the client's token.
        let r = ask(Packet::new(EC_OP_SEARCH_START)
            .with(
                Tag::int(EC_TAG_SEARCH_TYPE, EC_SEARCH_KAD.into())
                    .with(Tag::string(EC_TAG_SEARCH_NAME, "x")),
            )
            .with(Tag::int(EC_TAG_SEARCH_REF, 5)));
        assert_eq!(r.opcode, EC_OP_FAILED);
        assert_eq!(r.tag(EC_TAG_SEARCH_REF).unwrap().as_int(), 5);
        assert!(r.tag(EC_TAG_SEARCH_ID).is_none());

        let r = ask(search("ubuntu", 7));
        assert_eq!(r.opcode, EC_OP_STRINGS);
        let first = r.tag(EC_TAG_SEARCH_ID).unwrap().as_int();
        assert_eq!(r.tag(EC_TAG_SEARCH_REF).unwrap().as_int(), 7);
        assert_eq!(r.tag(EC_TAG_SEARCH_ED2K_ACTIVE).unwrap().as_int(), 1);
        assert_eq!(r.tag(EC_TAG_SEARCH_KAD_ACTIVE).unwrap().as_int(), 0);
        // Its progress, by ID, until done.
        // With the union form, naming an ID narrows the union: its entry.
        let progress = |ask: &mut dyn FnMut(Packet) -> Packet, id: u64| {
            let u = ask(Packet::new(EC_OP_SEARCH_PROGRESS).with(Tag::int(EC_TAG_SEARCH_ID, id)));
            let mut p = Packet::new(EC_OP_SEARCH_PROGRESS);
            if let Some(e) = u.tags.iter().find(|t| t.as_int() == id) {
                p.tags = e.children.clone();
            }
            p
        };
        let mut done = None;
        for _ in 0..100 {
            let p = progress(&mut ask, first);
            if p.tag(EC_TAG_SEARCH_LIFECYCLE_STATE).unwrap().as_int() == Lifecycle::Finished as u64
            {
                done = Some(p);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let p = done.expect("the search never finished");
        assert_eq!(p.tag(EC_TAG_SEARCH_ID).unwrap().as_int(), first);
        assert_eq!(p.tag(EC_TAG_SEARCH_NAME).unwrap().as_str(), "ubuntu");
        assert_eq!(p.tag(EC_TAG_SEARCH_RESULT_COUNT).unwrap().as_int(), 2);
        assert_eq!(p.tag(EC_TAG_SEARCH_STATUS).unwrap().as_int(), 0xffff);

        // A second one: its own ID and results.
        let r = ask(search("linux", 8));
        let second = r.tag(EC_TAG_SEARCH_ID).unwrap().as_int();
        assert_ne!(first, second);
        let results = |ask: &mut dyn FnMut(Packet) -> Packet, id: u64| {
            ask(Packet::new(EC_OP_SEARCH_RESULTS)
                .with_detail(EC_DETAIL_FULL)
                .with(Tag::int(EC_TAG_SEARCH_ID, id)))
        };
        assert_eq!(results(&mut ask, first).tags.len(), 2);
        // Listed in ID order, each with its query.
        let l = ask(Packet::new(EC_OP_SEARCH_LIST));
        let ids: Vec<u64> = l.tags.iter().map(Tag::as_int).collect();
        assert_eq!(ids, [first, second]);
        assert_eq!(l.tags[0].child_str(EC_TAG_SEARCH_NAME), "ubuntu");
        assert_eq!(l.tags[0].child_int(EC_TAG_SEARCH_RESULT_COUNT), 2);
        // The union form: every search, one child each.
        let u = ask(Packet::new(EC_OP_SEARCH_PROGRESS));
        assert_eq!(u.tags.len(), 2);
        assert!(u.tags.iter().all(
            |t| t.name == EC_TAG_SEARCH_ID && t.child(EC_TAG_SEARCH_LIFECYCLE_STATE).is_some()
        ));

        // A result downloaded by its ECID.
        let r = results(&mut ask, first);
        let ecid = r.tags[0].as_int();
        let dl = Packet::new(EC_OP_DOWNLOAD_SEARCH_RESULT).with(
            Tag::hash(EC_TAG_PARTFILE, [0; 16])
                .with(Tag::int(EC_TAG_PARTFILE_CAT, 0))
                .with(Tag::int(EC_TAG_SEARCHFILE, ecid)),
        );
        assert_eq!(ask(dl).opcode, EC_OP_STRINGS);

        // Stopped: results kept. Closed: gone, and an ID no search has
        // is expired.
        let stop = |id: u64, close: bool| {
            let mut p = Packet::new(EC_OP_SEARCH_STOP).with(Tag::int(EC_TAG_SEARCH_ID, id));
            if close {
                p = p.with(Tag::empty(EC_TAG_SEARCH_CLOSE));
            }
            p
        };
        assert_eq!(ask(stop(second, false)).opcode, EC_OP_MISC_DATA);
        assert_eq!(ask(stop(first, true)).opcode, EC_OP_MISC_DATA);
        let r = results(&mut ask, first);
        assert!(r.tag(EC_TAG_SEARCH_EXPIRED).is_some());
        // Left out of the union: how a union client learns it expired.
        let u = ask(Packet::new(EC_OP_SEARCH_PROGRESS).with(Tag::int(EC_TAG_SEARCH_ID, first)));
        assert!(u.tags.is_empty());
        assert_eq!(ask(Packet::new(EC_OP_SEARCH_LIST)).tags.len(), 1);
        // Re-asking Kad is not done: nothing to widen, the ID echoed.
        let m =
            ask(Packet::new(EC_OP_SEARCH_REQUEST_MORE).with(Tag::int(EC_TAG_SEARCH_ID, second)));
        assert_eq!(m.tag(EC_TAG_SEARCH_MORE_REASKABLE).unwrap().as_int(), 0);
        assert_eq!(m.tag(EC_TAG_SEARCH_ID).unwrap().as_int(), second);
        assert_eq!(ask(Packet::new(EC_OP_SHUTDOWN)).opcode, EC_OP_NOOP);
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
}

#[test]
fn only_one_search_waits_for_the_server() {
    use crate::ec_search::Searches;
    let mut s = Searches::default();
    let now = Instant::now();
    local(&mut s.legacy, now);
    assert!(s.legacy.ed2k_running());
    s.server_results(vec![result(1, "a.iso", 1000, 1, 0)]);
    assert_eq!(s.legacy.results().len(), 1);
    assert!(!s.legacy.ed2k_running(), "the answer ends it");
    // An answer nobody waits for goes nowhere.
    s.server_results(vec![result(2, "b.iso", 1000, 1, 0)]);
    assert_eq!(s.legacy.results().len(), 1);
}
