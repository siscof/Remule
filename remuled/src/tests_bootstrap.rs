// SPDX-License-Identifier: GPL-2.0-or-later
//! What is fetched at start, and how: the plan from amule.conf and the
//! files present, the server.met merge, and the fetches against a local
//! HTTP server.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ed2k_codec::{Tag, TagValue};
use ed2k_formats::amule_conf::ConfFile;
use ed2k_formats::nodes_dat::{Contact, Format, KadUdpKey, NodesDat};
use ed2k_formats::server_met::{ServerInfo, ServerMet, ServerRecord, VERSION};
use ed2k_types::tags::ServerTag;
use ed2k_types::UInt128;

use crate::bootstrap::{self, Plan, DEFAULT_NODES_DAT_URL, DEFAULT_SERVER_MET_URL};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-boot-{name}-{}", std::process::id()));
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

fn record(ip: [u8; 4], port: u16, name: &str, description: &str) -> ServerRecord {
    let mut tags = vec![Tag::new(
        ServerTag::ServerName.value(),
        TagValue::String(name.into()),
    )];
    if !description.is_empty() {
        tags.push(Tag::new(
            ServerTag::Description.value(),
            TagValue::String(description.into()),
        ));
    }
    ServerRecord {
        ip: Ipv4Addr::from(ip),
        port,
        tags,
    }
}

fn met(servers: Vec<ServerRecord>) -> ServerMet {
    ServerMet {
        version: VERSION,
        servers,
        legacy_counts: false,
    }
}

fn names(m: &ServerMet) -> Vec<(String, u16, String, String)> {
    m.servers
        .iter()
        .map(ServerInfo::from_record)
        .map(|s| (s.ip.unwrap().to_string(), s.port, s.name, s.description))
        .collect()
}

fn nodes() -> Vec<u8> {
    NodesDat {
        format: Format::V2,
        declared_count: 1,
        contacts: vec![Contact {
            id: UInt128::new(0x1234),
            ip: Ipv4Addr::new(1, 2, 3, 4),
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: Some(KadUdpKey { key: 0, ip: 0 }),
            verified: Some(1),
        }],
        trailing: Vec::new(),
    }
    .write()
}

#[test]
fn the_plan_follows_amuleds_rules() {
    let d = TempDir::new("plan");
    let dir = &d.0;
    let mut notes = Vec::new();
    // Nothing there: a new addresses.dat with aMule's default, and both files.
    let p = bootstrap::plan(dir, &ConfFile::new(), &mut notes);
    assert_eq!(
        p,
        Plan {
            server_met: vec![DEFAULT_SERVER_MET_URL.into()],
            nodes_dat: Some(DEFAULT_NODES_DAT_URL.into()),
        }
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("addresses.dat")).unwrap(),
        format!("{DEFAULT_SERVER_MET_URL}\n")
    );
    // With servers and a nodes.dat: nothing, unless Serverlist asks for the list.
    std::fs::write(
        dir.join("server.met"),
        met(vec![record([1, 1, 1, 1], 4661, "a", "")]).write(),
    )
    .unwrap();
    std::fs::write(dir.join("nodes.dat"), nodes()).unwrap();
    assert_eq!(
        bootstrap::plan(dir, &ConfFile::new(), &mut notes),
        Plan::default()
    );
    let conf = ConfFile::parse("[eMule]\nServerlist=1\n");
    assert_eq!(
        bootstrap::plan(dir, &conf, &mut notes).server_met,
        [DEFAULT_SERVER_MET_URL]
    );
    // Networks off: nothing for them.
    std::fs::remove_file(dir.join("nodes.dat")).unwrap();
    let conf = ConfFile::parse("[eMule]\nServerlist=1\nConnectToED2K=0\nConnectToKad=0\n");
    assert_eq!(bootstrap::plan(dir, &conf, &mut notes), Plan::default());
    // KadNodesUrl, and the legacy Ed2kServersUrl for a new addresses.dat.
    let e = TempDir::new("plan-legacy");
    let conf = ConfFile::parse(
        "[eMule]\nKadNodesUrl=http://example.org/n.dat\nEd2kServersUrl=http://example.org/s.met\n",
    );
    assert_eq!(
        bootstrap::plan(&e.0, &conf, &mut notes),
        Plan {
            server_met: vec!["http://example.org/s.met".into()],
            nodes_dat: Some("http://example.org/n.dat".into()),
        }
    );
    assert!(notes.is_empty(), "{notes:?}");
}

#[test]
fn a_downloaded_list_is_merged_as_load_server_met_does() {
    let current = met(vec![
        record([1, 1, 1, 1], 4661, "old name", "kept"),
        record([2, 2, 2, 2], 4661, "two", ""),
    ]);
    let downloaded = met(vec![
        // Known: the new name; an empty description leaves the old one.
        record([1, 1, 1, 1], 4661, "new name", ""),
        // Same address, other port: another server.
        record([2, 2, 2, 2], 4662, "two bis", "desc"),
        // Unusable.
        record([0, 0, 0, 0], 4661, "zero", ""),
        record([3, 3, 3, 3], 0, "no port", ""),
    ]);
    let (merged, added) = bootstrap::merge_server_met(Some(&current), &downloaded);
    assert_eq!(added, 1);
    assert_eq!(
        names(&merged),
        [
            ("1.1.1.1".into(), 4661, "new name".into(), "kept".into()),
            ("2.2.2.2".into(), 4661, "two".into(), String::new()),
            ("2.2.2.2".into(), 4662, "two bis".into(), "desc".into()),
        ]
    );
    // From nothing: everything usable.
    let (merged, added) = bootstrap::merge_server_met(None, &downloaded);
    assert_eq!((merged.servers.len(), added), (2, 2));
    assert_eq!(merged.version, VERSION);
}

/// A tiny HTTP/1.1 server: path -> (status line, extra header, body).
async fn http_server(routes: Vec<(&'static str, &'static str, String, Vec<u8>)>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&req);
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                let (status, header, body) = routes
                    .iter()
                    .find(|r| r.0 == path)
                    .map(|r| (r.1, r.2.clone(), r.3.clone()))
                    .unwrap_or(("404 Not Found", String::new(), b"no".to_vec()));
                let head = format!(
                    "HTTP/1.1 {status}\r\n{header}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
            });
        }
    });
    base
}

#[tokio::test]
async fn server_lists_and_nodes_dat_are_fetched_and_kept() {
    let list = met(vec![
        record([1, 1, 1, 1], 4661, "renamed", ""),
        record([5, 5, 5, 5], 4242, "new", "from the web"),
    ]);
    let base = http_server(vec![
        ("/server.met", "200 OK", String::new(), list.write()),
        (
            "/moved",
            "302 Found",
            "Location: /server.met\r\n".into(),
            Vec::new(),
        ),
        ("/nodes.dat", "200 OK", String::new(), nodes()),
        (
            "/page",
            "200 OK",
            String::new(),
            b"<html>not a file</html>".to_vec(),
        ),
    ])
    .await;

    let d = TempDir::new("run");
    let dir = &d.0;
    std::fs::write(
        dir.join("server.met"),
        met(vec![record([1, 1, 1, 1], 4661, "old", "")]).write(),
    )
    .unwrap();
    // A redirect, a 404 and a page that is no server.met: only the first counts.
    let plan = Plan {
        server_met: vec![
            format!("{base}/moved"),
            format!("{base}/missing"),
            format!("{base}/page"),
        ],
        nodes_dat: Some(format!("{base}/nodes.dat")),
    };
    bootstrap::run(dir, &plan).await;
    let got = ServerMet::read(&std::fs::read(dir.join("server.met")).unwrap()).unwrap();
    assert_eq!(
        names(&got),
        [
            ("1.1.1.1".into(), 4661, "renamed".into(), String::new()),
            ("5.5.5.5".into(), 4242, "new".into(), "from the web".into()),
        ]
    );
    assert_eq!(std::fs::read(dir.join("nodes.dat")).unwrap(), nodes());
    for f in ["server.met.download", "nodes.dat.download"] {
        assert!(!dir.join(f).exists(), "{f} left behind");
    }

    // A nodes.dat that is not one is not kept; nor is a failed download.
    let e = TempDir::new("run-bad");
    for url in [format!("{base}/page"), format!("{base}/missing")] {
        bootstrap::run(
            &e.0,
            &Plan {
                server_met: Vec::new(),
                nodes_dat: Some(url),
            },
        )
        .await;
        assert!(!e.0.join("nodes.dat").exists());
        assert!(!e.0.join("nodes.dat.download").exists());
    }
}
