// SPDX-License-Identifier: GPL-2.0-or-later
//! Servers and networks over EC: the server tags, every reply of the
//! server and network requests and what the client loop is told to do,
//! the list saved to `server.met`, and EC clients driving a running daemon
//! against scripted servers and a Kad node.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ed2k_codec::TagValue;
use ed2k_formats::server_met::{ServerInfo, ServerMet, ServerRecord};
use ed2k_types::tags::ServerTag;
use remule_ec::codes::*;
use remule_ec::{Client, ConnectOptions, Packet, Tag};

use crate::config;
use crate::ec_servers::{self, Ctx, Effect, ServerList};
use crate::server_conn::{Attempt, Connector, Next};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remuled-ecsrv-{name}-{}", std::process::id()));
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

const SECRET: &str = "5ebe2294ecd0e0f08eab7690d2a6ee69"; // md5("secret")

fn a(n: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, n], 4661))
}

fn info(n: u8) -> ServerInfo {
    ServerInfo {
        ip: Some(Ipv4Addr::new(10, 0, 0, n)),
        port: 4661,
        name: format!("server {n}"),
        description: "a test".into(),
        version: "17.15".into(),
        users: 1000,
        files: 2000,
        max_users: 5000,
        ping: 30,
        preference: 1,
        failed: 2,
        udp_flags: 0x3FB,
        ..Default::default()
    }
}

fn met(servers: &[ServerInfo]) -> ServerMet {
    ServerMet {
        version: 0xE0,
        servers: servers.iter().map(ServerInfo::to_record).collect(),
        legacy_counts: false,
    }
}

fn kids(t: &Tag) -> Vec<u16> {
    t.children.iter().map(|c| c.name).collect()
}

#[test]
fn servers_are_told_as_cec_server_tag_tells_them() {
    let s = info(1);
    // amulecmd: the address and the name.
    let cmd = ec_servers::server_tag(&s, 0x19, EC_DETAIL_CMD);
    assert_eq!(cmd.as_ipv4(), Some(([10, 0, 0, 1], 4661)));
    assert_eq!(kids(&cmd), [EC_TAG_SERVER_NAME]);
    // The GUI: everything that is not zero or empty, the name last.
    let full = ec_servers::server_tag(&s, 0x19, EC_DETAIL_FULL);
    assert_eq!(
        kids(&full),
        [
            EC_TAG_SERVER_PING,
            EC_TAG_SERVER_PRIO,
            EC_TAG_SERVER_FAILED,
            EC_TAG_SERVER_VERSION,
            EC_TAG_SERVER_DESC,
            EC_TAG_SERVER_USERS,
            EC_TAG_SERVER_USERS_MAX,
            EC_TAG_SERVER_FILES,
            EC_TAG_SERVER_TCP_FLAGS,
            EC_TAG_SERVER_UDP_FLAGS,
            EC_TAG_SERVER_NAME,
        ]
    );
    assert_eq!(full.child_int(EC_TAG_SERVER_USERS_MAX), 5000);
    assert_eq!(full.child_int(EC_TAG_SERVER_TCP_FLAGS), 0x19);
    // Updates: ping and failures only.
    let upd = ec_servers::server_tag(&s, 0x19, EC_DETAIL_UPDATE);
    assert_eq!(kids(&upd), [EC_TAG_SERVER_PING, EC_TAG_SERVER_FAILED]);
    // Normal priority, no failures, no name: left out.
    let bare = ServerInfo {
        ip: Some(Ipv4Addr::new(10, 0, 0, 9)),
        port: 4242,
        ..Default::default()
    };
    assert!(ec_servers::server_tag(&bare, 0, EC_DETAIL_FULL)
        .children
        .is_empty());
}

/// The handler's world: three servers known, the second one logged into.
struct World {
    list: ServerList,
    connector: Connector,
    ed2k: bool,
    kad: bool,
    kad_running: bool,
    kad_connected: bool,
    live: Option<ed2k_server::session::ServerInfo>,
}

impl World {
    fn new() -> World {
        let addrs = [a(1), a(2), a(3)];
        let list = ServerList::new(&addrs, Some(&met(&[info(1), info(2), info(3)])));
        let mut connector = Connector::new(addrs.to_vec(), false, true);
        connector.connect_to(a(2));
        connector.logged_in();
        World {
            list,
            connector,
            ed2k: true,
            kad: true,
            kad_running: true,
            kad_connected: true,
            live: Some(ed2k_server::session::ServerInfo {
                name: Some("Live Name".into()),
                users: 77,
                files: 88,
                tcp_flags: 0x19,
                ..Default::default()
            }),
        }
    }

    fn ask(&mut self, req: Packet) -> (Packet, Vec<Effect>) {
        ec_servers::handle(
            &req,
            &mut Ctx {
                list: &mut self.list,
                connector: &mut self.connector,
                ed2k: self.ed2k,
                kad: self.kad,
                kad_running: self.kad_running,
                kad_connected: self.kad_connected,
                live: self.live.as_ref(),
                ip_filter: None,
                filter_lan: true,
                now: Instant::now(),
            },
        )
    }
}

fn message(p: &Packet) -> String {
    p.message().unwrap_or_default()
}

fn srv(n: u8) -> Tag {
    Tag::ipv4(EC_TAG_SERVER, [10, 0, 0, n], 4661)
}

#[test]
fn the_server_list_is_every_server_with_the_live_one_updated() {
    let mut w = World::new();
    let (r, e) = w.ask(Packet::new(EC_OP_GET_SERVER_LIST).with_detail(EC_DETAIL_FULL));
    assert!(e.is_empty());
    assert_eq!(r.opcode, EC_OP_SERVER_LIST);
    let names: Vec<String> = r
        .tags
        .iter()
        .map(|t| t.child_str(EC_TAG_SERVER_NAME))
        .collect();
    assert_eq!(names, ["server 1", "Live Name", "server 3"]);
    // What the logged-in server says of itself: its counts and flags.
    assert_eq!(r.tags[1].child_int(EC_TAG_SERVER_USERS), 77);
    assert_eq!(r.tags[1].child_int(EC_TAG_SERVER_TCP_FLAGS), 0x19);
    assert!(!r.tags[0].has(EC_TAG_SERVER_TCP_FLAGS));
    // Kad only: empty.
    w.ed2k = false;
    let (r, _) = w.ask(Packet::new(EC_OP_GET_SERVER_LIST));
    assert!(r.tags.is_empty());
}

#[test]
fn servers_are_added_and_removed_as_the_server_list_does_it() {
    let mut w = World::new();
    let add = |addr: &str, name: &str| {
        Packet::new(EC_OP_SERVER_ADD)
            .with(Tag::string(EC_TAG_SERVER_ADDRESS, addr))
            .with(Tag::string(EC_TAG_SERVER_NAME, name))
    };
    // Refused: no port, a LAN or invalid address (LAN addresses
    // filtered), a host name, one already in the list.
    for bad in [
        "8.8.8.8:0",
        "8.8.8.8:x",
        "192.168.1.1:4661",
        "0.0.0.0:4661",
        "example.org:4661",
        "10.0.0.1:4661",
    ] {
        let (r, e) = w.ask(add(bad, "x"));
        assert_eq!(
            (r.opcode, message(&r)),
            (EC_OP_FAILED, "Server not added".into()),
            "{bad}"
        );
        assert!(e.is_empty());
    }
    assert!(!w.list.changed());
    // No colon: StrToULong of the whole text, so 8.8.8.8 is on port 8, as
    // aMule reads it.
    let (r, _) = w.ask(add("8.8.8.8", "eight"));
    assert_eq!(r.opcode, EC_OP_NOOP);
    assert_eq!(w.list.entries().last().unwrap().port, 8);
    let (r, _) = w.ask(add("8.8.4.4:4242", ""));
    assert_eq!(r.opcode, EC_OP_NOOP);
    // No name given: the address is its name; it goes last, and is tried.
    let last = w.list.entries().last().unwrap();
    assert_eq!((last.name.as_str(), last.port), ("8.8.4.4:4242", 4242));
    assert!(w.list.changed());
    assert_eq!(
        w.connector.servers().last(),
        Some(&SocketAddr::from(([8, 8, 4, 4], 4242)))
    );

    // Removing: it must be named and known, and not the one we are on.
    let (r, _) = w.ask(Packet::new(EC_OP_SERVER_REMOVE));
    assert_eq!(message(&r), "need to define server to be removed");
    let (r, _) = w.ask(Packet::new(EC_OP_SERVER_REMOVE).with(srv(9)));
    assert_eq!(message(&r), "server not found: [10.0.0.9:4661]");
    let (r, _) = w.ask(Packet::new(EC_OP_SERVER_REMOVE).with(srv(2)));
    assert_eq!(
        message(&r),
        "You are connected to the server you are trying to delete. please disconnect first."
    );
    let (r, e) = w.ask(Packet::new(EC_OP_SERVER_REMOVE).with(srv(3)));
    assert_eq!((r.opcode, e), (EC_OP_NOOP, vec![]));
    assert!(w
        .list
        .find(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 4661))
        .is_none());
    assert!(!w.connector.servers().contains(&a(3)));
}

#[test]
fn connecting_and_disconnecting_tell_the_client_what_to_do() {
    let mut w = World::new();
    // Disconnect: hang up, nothing follows.
    let (r, e) = w.ask(Packet::new(EC_OP_SERVER_DISCONNECT));
    assert_eq!((r.opcode, e), (EC_OP_NOOP, vec![Effect::Disconnect]));
    let (_, e) = w.ask(Packet::new(EC_OP_SERVER_DISCONNECT));
    assert!(e.is_empty());
    // One server: that one alone.
    let (r, e) = w.ask(Packet::new(EC_OP_SERVER_CONNECT).with(srv(3)));
    assert_eq!(r.opcode, EC_OP_NOOP);
    let to3 = Next::Connect(Attempt {
        addr: a(3),
        obfuscated: false,
    });
    assert_eq!(e, [Effect::CancelAttempt, Effect::Follow(to3)]);
    let (r, _) = w.ask(Packet::new(EC_OP_SERVER_CONNECT).with(srv(7)));
    assert_eq!(message(&r), "server not found: [10.0.0.7:4661]");
    // Any: a sweep from the top, hanging up on the one we are on first.
    w.connector.logged_in();
    let (_, e) = w.ask(Packet::new(EC_OP_SERVER_CONNECT));
    let to1 = Next::Connect(Attempt {
        addr: a(1),
        obfuscated: false,
    });
    assert_eq!(
        e,
        [
            Effect::CancelAttempt,
            Effect::Disconnect,
            Effect::Follow(to1)
        ]
    );
    w.ed2k = false;
    let (r, e) = w.ask(Packet::new(EC_OP_SERVER_CONNECT));
    assert_eq!(message(&r), "eD2k is disabled in preferences.");
    assert!(e.is_empty());
}

#[test]
fn both_networks_answer_in_words() {
    let strings = |p: &Packet| -> Vec<String> { p.tags.iter().map(Tag::as_str).collect() };
    // Connected to both: already.
    let mut w = World::new();
    let (r, e) = w.ask(Packet::new(EC_OP_CONNECT));
    assert_eq!(r.opcode, EC_OP_STRINGS);
    assert_eq!(
        strings(&r),
        ["Already connected to eD2k.", "Already connected to Kad."]
    );
    assert!(e.is_empty());
    // Disconnected from both, then nothing to do.
    let (r, e) = w.ask(Packet::new(EC_OP_DISCONNECT));
    assert_eq!(
        strings(&r),
        ["Disconnected from eD2k.", "Disconnected from Kad."]
    );
    assert_eq!(e, [Effect::Disconnect, Effect::StopKad]);
    w.kad_running = false;
    w.kad_connected = false;
    let (r, e) = w.ask(Packet::new(EC_OP_DISCONNECT));
    assert_eq!((r.opcode, e), (EC_OP_NOOP, vec![]));
    // Connecting both.
    let (r, e) = w.ask(Packet::new(EC_OP_CONNECT));
    assert_eq!(
        strings(&r),
        ["Connecting to eD2k...", "Connecting to Kad..."]
    );
    assert_eq!(e.last(), Some(&Effect::StartKad));
    assert!(e.contains(&Effect::Follow(Next::Connect(Attempt {
        addr: a(1),
        obfuscated: false
    }))));
    // Neither enabled.
    w.ed2k = false;
    w.kad = false;
    let (r, _) = w.ask(Packet::new(EC_OP_CONNECT));
    assert_eq!(message(&r), "All networks are disabled.");
    // Kad alone.
    let (r, _) = w.ask(Packet::new(EC_OP_KAD_START));
    assert_eq!(message(&r), "Kad is disabled in preferences.");
    w.kad = true;
    let (r, e) = w.ask(Packet::new(EC_OP_KAD_START));
    assert_eq!((r.opcode, e), (EC_OP_NOOP, vec![Effect::StartKad]));
    let (r, e) = w.ask(Packet::new(EC_OP_KAD_STOP));
    assert_eq!((r.opcode, e), (EC_OP_NOOP, vec![]));
    w.kad_running = true;
    let (_, e) = w.ask(Packet::new(EC_OP_KAD_START));
    assert!(e.is_empty(), "already running");
    let (_, e) = w.ask(Packet::new(EC_OP_KAD_STOP));
    assert_eq!(e, [Effect::StopKad]);
    // An empty list: nothing to connect to.
    let mut empty = World::new();
    empty.list = ServerList::default();
    empty.connector = Connector::new(Vec::new(), false, true);
    let (_, e) = empty.ask(Packet::new(EC_OP_SERVER_CONNECT));
    assert_eq!(e, [Effect::CancelAttempt, Effect::Follow(Next::Idle)]);
}

#[test]
fn a_changed_list_is_saved_and_an_unchanged_one_left_alone() {
    let d = TempDir::new("save");
    let file = d.0.join("server.met");
    std::fs::write(&file, met(&[info(1), info(2)]).write()).unwrap();
    let before = std::fs::read(&file).unwrap();
    let mut list = ServerList::load(&d.0, &[a(2), a(1)]);
    // In the order they are tried, with what server.met says.
    assert_eq!(list.entries()[0].name, "server 2");
    list.save_if_changed(&d.0);
    assert_eq!(std::fs::read(&file).unwrap(), before);

    let mut w = World::new();
    w.list = list;
    let (r, _) = w.ask(
        Packet::new(EC_OP_SERVER_ADD)
            .with(Tag::string(EC_TAG_SERVER_ADDRESS, "8.8.8.8:4661"))
            .with(Tag::string(EC_TAG_SERVER_NAME, "Google")),
    );
    assert_eq!(r.opcode, EC_OP_NOOP);
    w.list.save_if_changed(&d.0);
    let saved = ServerMet::read(&std::fs::read(&file).unwrap()).unwrap();
    let got: Vec<(String, u32)> = saved
        .servers
        .iter()
        .map(ServerInfo::from_record)
        .map(|s| (s.name, s.users))
        .collect();
    // server 2 is the one logged into: its live counts went in.
    assert_eq!(
        got,
        [
            ("Live Name".to_string(), 77),
            ("server 1".to_string(), 1000),
            ("Google".to_string(), 0)
        ]
    );
    assert!(!w.list.changed());

    // A removal alone is a change too.
    let mut w = World::new();
    let (r, _) = w.ask(Packet::new(EC_OP_SERVER_REMOVE).with(srv(3)));
    assert_eq!(r.opcode, EC_OP_NOOP);
    assert!(w.list.changed());
    w.list.save_if_changed(&d.0);
    let saved = ServerMet::read(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(saved.servers.len(), 2);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A scripted eD2k server: each login is answered with a HighID; the
/// connection stays up until the client hangs up.
async fn server(listener: tokio::net::TcpListener) {
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
                if body[0] == 0x01 {
                    let mut p = vec![0xE3, 5, 0, 0, 0, 0x40];
                    p.extend_from_slice(&[127, 0, 0, 1]);
                    if s.write_all(&p).await.is_err() {
                        return;
                    }
                }
            }
        });
    }
}

fn record(port: u16, name: &str) -> ServerRecord {
    ServerRecord {
        ip: Ipv4Addr::LOCALHOST,
        port,
        tags: vec![ed2k_codec::Tag::new(
            ServerTag::ServerName.value(),
            TagValue::String(name.into()),
        )],
    }
}

/// Ask for the connection state until its eD2k bits and server port say
/// what `want` wants.
fn state_until(c: &mut Client, want: impl Fn(u64, Option<u16>) -> bool) {
    for _ in 0..100 {
        let r = c
            .request(&Packet::new(EC_OP_GET_CONNSTATE).with_detail(EC_DETAIL_CMD))
            .unwrap();
        let cs = r.tag(EC_TAG_CONNSTATE).unwrap();
        let port = cs
            .child(EC_TAG_SERVER)
            .and_then(Tag::as_ipv4)
            .map(|(_, p)| p);
        if want(cs.as_int() & 0x03, port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the connection state never got there");
}

async fn wait_for_ec(port: u16) {
    let mut tries = 0;
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_err()
    {
        tries += 1;
        assert!(tries < 100, "the daemon never listened for EC");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `amulecmd` against a daemon with two servers known and one added: the
/// list shown, a server picked, refused removal while on it, disconnect,
/// remove, connect to any, the network commands, and `server.met` saved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ec_client_drives_the_servers() {
    let d = TempDir::new("drive");
    let mut ports = Vec::new();
    for _ in 0..3 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        ports.push(l.local_addr().unwrap().port());
        tokio::spawn(server(l));
    }
    let (alpha, beta, gamma) = (ports[0], ports[1], ports[2]);
    let ec_port = free_port();
    std::fs::write(
        d.0.join("amule.conf"),
        format!(
            "[eMule]\nPort={}\nConnectToKad=0\nConnectToED2K=1\nAutoconnect=0\nFilterLanIPs=0\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\nECPassword={SECRET}\n",
            free_port()
        ),
    )
    .unwrap();
    let met = ServerMet {
        version: 0xE0,
        servers: vec![record(alpha, "Alpha"), record(beta, "Beta")],
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
    wait_for_ec(ec_port).await;

    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(&ConnectOptions::new("127.0.0.1", ec_port, SECRET)).unwrap();
        let names = |c: &mut Client| -> Vec<String> {
            let r = c
                .request(&Packet::new(EC_OP_GET_SERVER_LIST).with_detail(EC_DETAIL_CMD))
                .unwrap();
            assert_eq!(r.opcode, EC_OP_SERVER_LIST);
            r.tags
                .iter()
                .map(|t| t.child_str(EC_TAG_SERVER_NAME))
                .collect()
        };
        let at = |p: u16| Tag::ipv4(EC_TAG_SERVER, [127, 0, 0, 1], p);
        assert_eq!(names(&mut c), ["Alpha", "Beta"]);
        // Not connected (Autoconnect off).
        state_until(&mut c, |bits, _| bits == 0);

        let add = Packet::new(EC_OP_SERVER_ADD)
            .with(Tag::string(
                EC_TAG_SERVER_ADDRESS,
                &format!("127.0.0.1:{gamma}"),
            ))
            .with(Tag::string(EC_TAG_SERVER_NAME, "Gamma"));
        assert_eq!(c.request(&add).unwrap().opcode, EC_OP_NOOP);
        let again = c.request(&add).unwrap();
        assert_eq!(again.message().unwrap(), "Server not added");
        assert_eq!(names(&mut c), ["Alpha", "Beta", "Gamma"]);

        // Beta picked: logged in there.
        let r = c
            .request(&Packet::new(EC_OP_SERVER_CONNECT).with(at(beta)))
            .unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        state_until(&mut c, |bits, p| bits == 1 && p == Some(beta));
        let r = c
            .request(&Packet::new(EC_OP_SERVER_REMOVE).with(at(beta)))
            .unwrap();
        assert!(r
            .message()
            .unwrap()
            .starts_with("You are connected to the server"));
        // Disconnected, and it stays so; then removed.
        let r = c.request(&Packet::new(EC_OP_SERVER_DISCONNECT)).unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        state_until(&mut c, |bits, _| bits == 0);
        std::thread::sleep(Duration::from_millis(1500));
        state_until(&mut c, |bits, _| bits == 0);
        let r = c
            .request(&Packet::new(EC_OP_SERVER_REMOVE).with(at(beta)))
            .unwrap();
        assert_eq!(r.opcode, EC_OP_NOOP);
        assert_eq!(names(&mut c), ["Alpha", "Gamma"]);

        // amulecmd's connect: any server, the first that logs in.
        let r = c.request(&Packet::new(EC_OP_CONNECT)).unwrap();
        assert_eq!(r.opcode, EC_OP_STRINGS);
        assert_eq!(r.message().unwrap(), "Connecting to eD2k...");
        state_until(&mut c, |bits, p| bits == 1 && p == Some(alpha));
        let r = c.request(&Packet::new(EC_OP_CONNECT)).unwrap();
        assert_eq!(r.message().unwrap(), "Already connected to eD2k.");
        let r = c.request(&Packet::new(EC_OP_DISCONNECT)).unwrap();
        assert_eq!(r.message().unwrap(), "Disconnected from eD2k.");
        state_until(&mut c, |bits, _| bits == 0);
        assert_eq!(
            c.request(&Packet::new(EC_OP_DISCONNECT)).unwrap().opcode,
            EC_OP_NOOP
        );
        let r = c.request(&Packet::new(EC_OP_KAD_START)).unwrap();
        assert_eq!(r.message().unwrap(), "Kad is disabled in preferences.");
        let r = c
            .request(&Packet::new(EC_OP_SERVER_CONNECT).with(Tag::ipv4(
                EC_TAG_SERVER,
                [1, 2, 3, 4],
                5,
            )))
            .unwrap();
        assert_eq!(r.message().unwrap(), "server not found: [1.2.3.4:5]");
        assert_eq!(
            c.request(&Packet::new(EC_OP_SHUTDOWN)).unwrap().opcode,
            EC_OP_NOOP
        );
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
    // Changed, so saved: Beta gone, Gamma added.
    let saved = ServerMet::read(&std::fs::read(d.0.join("server.met")).unwrap()).unwrap();
    let got: Vec<(String, u16)> = saved
        .servers
        .iter()
        .map(ServerInfo::from_record)
        .map(|s| (s.name, s.port))
        .collect();
    assert_eq!(
        got,
        [("Alpha".to_string(), alpha), ("Gamma".to_string(), gamma)]
    );
}

/// Kad stopped and started again over EC: the connection state follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ec_client_stops_and_starts_kad() {
    use ed2k_formats::nodes_dat::{Contact, Format, KadUdpKey, NodesDat};
    let d = TempDir::new("kad");
    let ec_port = free_port();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        d.0.join("amule.conf"),
        format!(
            "[eMule]\nPort={}\nUDPPort={udp}\nConnectToKad=1\nConnectToED2K=0\n\
             [ExternalConnect]\nAcceptExternalConnections=1\nECPort={ec_port}\nECPassword={SECRET}\n",
            free_port()
        ),
    )
    .unwrap();
    let nodes = NodesDat {
        format: Format::V2,
        declared_count: 1,
        contacts: vec![Contact {
            id: ed2k_types::UInt128::new(0x1234),
            ip: Ipv4Addr::new(127, 0, 0, 1),
            udp_port: 1,
            tcp_port: 1,
            version: 8,
            udp_key: Some(KadUdpKey { key: 0, ip: 0 }),
            verified: Some(1),
        }],
        trailing: Vec::new(),
    };
    std::fs::write(d.0.join("nodes.dat"), nodes.write()).unwrap();
    let loaded = config::load(&d.0).unwrap();
    assert!(loaded.client.kad.is_some());
    let daemon = tokio::spawn(crate::client::run(
        loaded.client,
        Vec::new(),
        Vec::new(),
        std::future::pending(),
    ));
    wait_for_ec(ec_port).await;
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(&ConnectOptions::new("127.0.0.1", ec_port, SECRET)).unwrap();
        // Kad running: bit 0x10, and our Kad ID.
        let running_until = |c: &mut Client, on: bool| {
            for _ in 0..100 {
                let r = c
                    .request(&Packet::new(EC_OP_GET_CONNSTATE).with_detail(EC_DETAIL_CMD))
                    .unwrap();
                let cs = r.tag(EC_TAG_CONNSTATE).unwrap();
                if (cs.as_int() & 0x10 != 0) == on && cs.has(EC_TAG_KAD_ID) == on {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            panic!("Kad never got to running={on}");
        };
        running_until(&mut c, true);
        let stop = Packet::new(EC_OP_KAD_STOP);
        assert_eq!(c.request(&stop).unwrap().opcode, EC_OP_NOOP);
        running_until(&mut c, false);
        assert_eq!(c.request(&stop).unwrap().opcode, EC_OP_NOOP);
        let start = Packet::new(EC_OP_KAD_START);
        assert_eq!(c.request(&start).unwrap().opcode, EC_OP_NOOP);
        running_until(&mut c, true);
        // eD2k off, Kad running but not connected: Kad is told to connect.
        let r = c.request(&Packet::new(EC_OP_CONNECT)).unwrap();
        assert_eq!(r.message().unwrap(), "Connecting to Kad...");
        let bye = Packet::new(EC_OP_SHUTDOWN);
        assert_eq!(c.request(&bye).unwrap().opcode, EC_OP_NOOP);
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), daemon)
        .await
        .expect("the daemon did not stop")
        .unwrap()
        .unwrap();
    // Kad's state was saved when it stopped.
    assert!(d.0.join("preferencesKad.dat").is_file());
}
