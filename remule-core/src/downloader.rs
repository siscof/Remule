// SPDX-License-Identifier: GPL-2.0-or-later
//! The download queue on tokio: one task per peer connection on
//! [`remule_net`], and a loop that hands the queue what the network does
//! and the network what the queue wants.
//!
//! The queue, and so every part file, lives in the loop's task: sessions
//! only ever touch a file from there, and connection tasks only move
//! packets. File writes and hash checks run in that task too (a later step
//! can move them to blocking threads).
//!
//! ```text
//!  commands ──▶ ┌───────────┐ ──▶ reports
//!  listener ──▶ │ run loop  │
//!   ticks   ──▶ │  (queue)  │ ──▶ Connect / Send / Close
//!  net events ▶ └───────────┘         │
//!        ▲                            ▼
//!        └──── connection tasks (establish, read, write)
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_types::ed2k::client_tcp::Extended;
use ed2k_types::ed2k::CONNECTION_TIMEOUT;
use ed2k_types::{Md4Hash, Protocol};
use remule_net::{establish, Bandwidth, ConnConfig, Handshake, Priority};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::buddy::{Buddies, ForUploader};
use crate::download_queue::{
    Action, ConnId, DownloadQueue, Endpoint, FileProgress, Origin, QueueStats, Report, UdpOut,
};
use crate::part_file::PartFile;
use crate::uploader::Uploader;
use ed2k_peer::PeerPacket;
use ed2k_types::ed2k::client_udp::Opcode as UdpOpcode;

/// What the application can tell a running downloader.
#[derive(Debug)]
pub enum Command {
    AddFile(Box<PartFile>),
    AddSources {
        file: Md4Hash,
        sources: Vec<Endpoint>,
        origin: Origin,
    },
    /// Where each file stands, and the bytes received so far.
    Progress(tokio::sync::oneshot::Sender<(Vec<FileProgress>, QueueStats)>),
    /// The file data received and sent so far: the session's counts for
    /// the statistics.
    Traffic(tokio::sync::oneshot::Sender<crate::statistics::Totals>),
    /// A server login gave us this ID (0 when logged out) and public
    /// address: the hellos of connections from now on carry them.
    SetOurId {
        id: u32,
        public_ip: Option<std::net::Ipv4Addr>,
    },
    /// Pause, stop, resume or cancel a download; the reply is false when
    /// it is not in the queue (or could not be deleted).
    File {
        file: Md4Hash,
        op: FileOp,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// The credit history ([`crate::credits::Credits::history`]); empty
    /// without an uploader.
    CreditHistory(tokio::sync::oneshot::Sender<Vec<crate::credits::HistoryEntry>>),
    /// A category was deleted: the downloads in it, or after it, moved
    /// ([`DownloadQueue::remove_category`]).
    RemoveCategory(u32),
    /// A client UDP datagram (eMule protocol, decrypted) came to our UDP
    /// port: a reask for the uploader, or an answer to one of ours.
    Udp {
        from: SocketAddrV4,
        datagram: Vec<u8>,
    },
    /// Kad runs with this ID (buddy callbacks are checked against it).
    SetKadId(Option<ed2k_types::UInt128>),
    /// Kad found a node offering to be our buddy
    /// (`ed2k_kad::Event::BuddyOffer`).
    BuddyOffer {
        tcp: SocketAddrV4,
        kad_port: u16,
        user_hash: Md4Hash,
        connect_options: u8,
    },
    /// Whether others can connect to us now (a HighID, Kad's firewall
    /// check, or told so).
    SetReachable(bool),
    /// Kad offered to serve a firewalled node (`ed2k_kad::Event::BuddyRequest`).
    BuddyRequest {
        buddy_id: ed2k_types::UInt128,
        user_hash: Md4Hash,
        tcp: SocketAddrV4,
    },
    /// A callback request for a buddy came over Kad
    /// (`ed2k_kad::Event::CallbackRequest`).
    BuddyCallback {
        buddy_id: ed2k_types::UInt128,
        file: Md4Hash,
        from: SocketAddrV4,
    },
    /// Hang up, save the files, and return the queue.
    Shutdown,
}

/// What [`Command::File`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    /// `PauseFile`.
    Pause,
    /// `StopFile`.
    Stop,
    /// `ResumeFile`.
    Resume,
    /// `Delete`: out of the queue, the `.part` and its met removed.
    Delete,
    /// `SetDownPriority` (`PR_*`), or automatic.
    Priority { prio: u32, auto: bool },
    /// `SetCategory`.
    Category(u32),
}

/// Settings for [`run`].
#[derive(Debug, Clone)]
pub struct DownloaderConfig {
    pub bandwidth: Arc<Bandwidth>,
    /// How often the queue ticks.
    pub tick: Duration,
    /// Stop by itself once every file is complete.
    pub stop_when_done: bool,
    /// Accept obfuscated callbacks, padded up to this much.
    pub max_padding: u8,
    /// Where client UDP datagrams go out ([`Action::SendUdp`]): the
    /// application owns the UDP port (shared with Kad, as in aMule).
    /// Without it, nothing is sent over UDP.
    pub udp: Option<mpsc::UnboundedSender<UdpOut>>,
}

impl DownloaderConfig {
    pub fn new(bandwidth: Arc<Bandwidth>) -> Self {
        DownloaderConfig {
            bandwidth,
            tick: Duration::from_secs(1),
            stop_when_done: false,
            max_padding: remule_net::conn::DEFAULT_MAX_PADDING,
            udp: None,
        }
    }
}

/// What a connection task reports.
#[derive(Debug)]
enum NetEvent {
    Connected(ConnId),
    Packet(ConnId, Packet),
    Closed(ConnId),
}

struct ConnHandle {
    tx: mpsc::UnboundedSender<Packet>,
    task: JoinHandle<()>,
}

enum How {
    Outgoing(SocketAddr, Handshake),
    Incoming(TcpStream, Handshake),
}

async fn conn_task(
    conn: ConnId,
    how: How,
    mut rx: mpsc::UnboundedReceiver<Packet>,
    events: mpsc::UnboundedSender<NetEvent>,
    cfg: ConnConfig,
) {
    let how_addr = match &how {
        How::Outgoing(a, _) => Some(*a),
        How::Incoming(s, _) => s.peer_addr().ok(),
    };
    let (stream, handshake, outgoing) = match how {
        How::Outgoing(addr, hs) => {
            match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => (s, hs, true),
                _ => {
                    let _ = events.send(NetEvent::Closed(conn));
                    return;
                }
            }
        }
        How::Incoming(s, hs) => (s, hs, false),
    };
    let _ = stream.set_nodelay(true);
    let established =
        tokio::time::timeout(CONNECTION_TIMEOUT, establish(stream, handshake, cfg)).await;
    // REMULE_TRACE: each connection made or accepted and whether it is
    // obfuscated, and each packet's protocol, opcode and size; =2 also the
    // payload of packets up to 64 bytes, in hex.
    let trace_level = std::env::var("REMULE_TRACE").map_or(0, |v| if v == "2" { 2 } else { 1 });
    let trace = trace_level > 0;
    let way = if outgoing { "connected" } else { "accepted" };
    let Ok(Ok((mut reader, mut writer))) = established else {
        if let (true, Some(a)) = (trace, &how_addr) {
            eprintln!("{a} handshake failed ({way})");
        }
        let _ = events.send(NetEvent::Closed(conn));
        return;
    };
    if let (true, Some(a)) = (trace, &how_addr) {
        let kind = if writer.is_obfuscated() {
            "obfuscated"
        } else {
            "plain"
        };
        eprintln!("{a} {way}, {kind}");
    }
    if outgoing {
        let _ = events.send(NetEvent::Connected(conn));
    }
    let hex = |p: &Packet| -> String {
        if trace_level < 2 || p.payload.len() > 64 {
            return String::new();
        }
        let h: String = p.payload.iter().map(|b| format!("{b:02x}")).collect();
        format!(" {h}")
    };
    let peer = match &how_addr {
        Some(a) => a.to_string(),
        None => format!("conn {conn}"),
    };
    let write = async {
        while let Some(p) = rx.recv().await {
            if trace {
                eprintln!(
                    "{peer} <- {:#04x}/{:#04x} {} bytes{}",
                    p.protocol,
                    p.opcode,
                    p.payload.len(),
                    hex(&p)
                );
            }
            if writer.send(&p, Priority::Control).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    };
    let read = async {
        loop {
            let p = match reader.recv().await {
                Ok(Some(p)) => p,
                Ok(None) => {
                    if trace {
                        eprintln!("{peer} closed");
                    }
                    break;
                }
                Err(e) => {
                    if trace {
                        eprintln!("{peer} error: {e}");
                    }
                    break;
                }
            };
            if trace {
                eprintln!(
                    "{peer} -> {:#04x}/{:#04x} {} bytes{}",
                    p.protocol,
                    p.opcode,
                    p.payload.len(),
                    hex(&p)
                );
            }
            if events.send(NetEvent::Packet(conn, p)).is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = write => {}
        _ = read => {}
    }
    let _ = events.send(NetEvent::Closed(conn));
}

/// Run `queue` until [`Command::Shutdown`], the command channel closing,
/// or (with `stop_when_done`) every file completing. Reports go to
/// `reports` as they happen. Returns the queue, files saved.
pub async fn run(
    queue: DownloadQueue,
    config: DownloaderConfig,
    listener: Option<TcpListener>,
    commands: mpsc::UnboundedReceiver<Command>,
    reports: mpsc::UnboundedSender<Report>,
) -> DownloadQueue {
    run_with(queue, None, config, listener, commands, reports)
        .await
        .0
}

/// [`run`], uploading too: peers that connect to us and are not sources of
/// ours calling back are served by `uploader`, and finished downloads are
/// shared. With an uploader, `stop_when_done` is ignored: sharing goes on.
pub async fn run_with(
    mut queue: DownloadQueue,
    mut uploader: Option<Uploader>,
    config: DownloaderConfig,
    listener: Option<TcpListener>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    reports: mpsc::UnboundedSender<Report>,
) -> (DownloadQueue, Option<Uploader>) {
    // Where each connection goes (or came from).
    let mut peer_addrs: HashMap<ConnId, SocketAddr> = HashMap::new();
    let (net_tx, mut net_rx) = mpsc::unbounded_channel();
    let mut conns: HashMap<ConnId, ConnHandle> = HashMap::new();
    let conn_cfg = ConnConfig::new(config.bandwidth.clone());
    let own_hash = queue.config().ours.user_hash;
    let mut buddies = Buddies::new(queue.config().ours.clone());
    let mut ticker = tokio::time::interval(config.tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let spawn = |conn: ConnId, how: How, conns: &mut HashMap<ConnId, ConnHandle>| {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(conn_task(conn, how, rx, net_tx.clone(), conn_cfg.clone()));
        conns.insert(conn, ConnHandle { tx, task });
    };

    loop {
        let actions = tokio::select! {
            _ = ticker.tick() => {
                let now = Instant::now();
                let mut a = queue.tick(now);
                if let Some(up) = uploader.as_mut() {
                    a.extend(up.tick(now, &mut || queue.new_conn_id()));
                }
                a.extend(buddies.tick(now));
                a
            }
            Some(ev) = net_rx.recv() => {
                let now = Instant::now();
                match ev {
                    NetEvent::Connected(c) if buddies.owns(c) => buddies.connected(c, now),
                    NetEvent::Connected(c) => match uploader.as_mut() {
                        // A waiting peer we call back.
                        Some(up) if up.owns(c) => up.connected(c, now),
                        _ => queue.connected(c, now),
                    },
                    // `OP_KAD_FWTCPCHECK_ACK`: a Kad node we asked to check our
                    // firewall got through. Kad's business, on any connection.
                    NetEvent::Packet(c, p) if is_kad_firewall_ack(&p) => {
                        if let Some(SocketAddr::V4(a)) = peer_addrs.get(&c) {
                            let _ = reports.send(Report::KadFirewallAck { ip: *a.ip() });
                        }
                        Vec::new()
                    }
                    // A Kad buddy link; callbacks through it are answered by
                    // the upload side.
                    NetEvent::Packet(c, p) if buddies.owns(c) => {
                        let (mut a, work) = buddies.packet(c, p, now);
                        if let Some(up) = uploader.as_mut() {
                            for w in work {
                                a.extend(match w {
                                    ForUploader::CallBack { addr, file } => {
                                        up.answer_callback(addr, file, now, &mut || queue.new_conn_id())
                                    }
                                    ForUploader::Reask { from, datagram } => up.udp_reask(from, &datagram, now),
                                });
                            }
                        }
                        a
                    }
                    // The firewalled node we offered to serve, connecting.
                    NetEvent::Packet(c, p) if queue.is_unmatched_incoming(c) && is_expected_buddy(&buddies, &p, peer_addrs.get(&c), now) => {
                        let Ok(PeerPacket::Hello(h)) = PeerPacket::parse(p, Default::default()) else {
                            unreachable!()
                        };
                        let Some(SocketAddr::V4(a)) = peer_addrs.get(&c) else {
                            unreachable!()
                        };
                        queue.forget(c);
                        buddies.accept(c, &h, *a.ip(), now)
                    }
                    NetEvent::Packet(c, p) => match uploader.as_mut() {
                        Some(up) if up.owns(c) => up.packet(c, p, now),
                        Some(up) if queue.is_unmatched_incoming(c) => {
                            // The first packet of a peer that connected to us: a
                            // source of ours calling back, or someone to serve.
                            match PeerPacket::parse(p.clone(), Default::default()) {
                                Ok(PeerPacket::Hello(h)) if !queue.wants_incoming(&h) => {
                                    queue.forget(c);
                                    let ip = peer_addrs
                                        .get(&c)
                                        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |a| a.ip());
                                    up.accept(c, h, ip, now)
                                }
                                _ => queue.packet(c, p, now),
                            }
                        }
                        _ => queue.packet(c, p, now),
                    },
                    NetEvent::Closed(c) => {
                        conns.remove(&c);
                        peer_addrs.remove(&c);
                        if buddies.owns(c) {
                            buddies.closed(c)
                        } else { match uploader.as_mut() {
                            Some(up) if up.owns(c) => {
                                up.closed(c);
                                Vec::new()
                            }
                            _ => queue.closed(c, now),
                        } }
                    }
                }
            }
            accepted = accept(listener.as_ref()) => match accepted {
                // `CListenSocket::OnAccept`: a peer the IP filter blocks is
                // hung up on before anything is read.
                Some(stream) if matches!(stream.peer_addr(), Ok(std::net::SocketAddr::V4(a)) if queue.blocks(*a.ip())) => {
                    drop(stream);
                    Vec::new()
                }
                Some(stream) => {
                    let conn = queue.incoming();
                    if let Ok(a) = stream.peer_addr() {
                        peer_addrs.insert(conn, a);
                    }
                    let hs = Handshake::Incoming {
                        own_hash,
                        max_padding: config.max_padding,
                        require: false,
                    };
                    spawn(conn, How::Incoming(stream, hs), &mut conns);
                    Vec::new()
                }
                None => Vec::new(),
            },
            cmd = commands.recv() => {
                let now = Instant::now();
                match cmd {
                    Some(Command::AddFile(f)) => {
                        queue.add_file(*f);
                        Vec::new()
                    }
                    Some(Command::AddSources { file, sources, origin }) => sources
                        .into_iter()
                        .flat_map(|ep| queue.add_source(file, ep, origin, now))
                        .collect(),
                    Some(Command::Progress(reply)) => {
                        let _ = reply.send((queue.progress(), queue.stats()));
                        Vec::new()
                    }
                    Some(Command::Traffic(reply)) => {
                        let _ = reply.send(crate::statistics::Totals {
                            received: queue.stats().received,
                            sent: uploader.as_ref().map_or(0, |u| u.sent_total()),
                        });
                        Vec::new()
                    }
                    Some(Command::SetOurId { id, public_ip }) => {
                        queue.set_our_id(id, public_ip);
                        if let Some(up) = uploader.as_mut() {
                            up.set_our_id(id);
                        }
                        buddies.set_ours(queue.config().ours.clone());
                        Vec::new()
                    }
                    Some(Command::CreditHistory(reply)) => {
                        let h = uploader
                            .as_ref()
                            .and_then(|u| u.credits())
                            .map(|c| c.history())
                            .unwrap_or_default();
                        let _ = reply.send(h);
                        Vec::new()
                    }
                    Some(Command::RemoveCategory(cat)) => {
                        queue.remove_category(cat);
                        Vec::new()
                    }
                    Some(Command::SetKadId(id)) => {
                        buddies.set_kad_id(id);
                        Vec::new()
                    }
                    Some(Command::BuddyOffer { tcp, kad_port, user_hash, connect_options }) => {
                        let conn = queue.new_conn_id();
                        buddies.offer(tcp, kad_port, user_hash, connect_options, conn, now)
                    }
                    Some(Command::SetReachable(r)) => {
                        queue.set_reachable(r);
                        Vec::new()
                    }
                    Some(Command::BuddyRequest { buddy_id, user_hash, tcp }) => {
                        buddies.expect(buddy_id, user_hash, *tcp.ip(), now);
                        Vec::new()
                    }
                    Some(Command::BuddyCallback { buddy_id, file, from }) => {
                        buddies.relay(buddy_id, file, from)
                    }
                    Some(Command::Udp { from, datagram }) => {
                        if datagram.get(1) == Some(&(UdpOpcode::ReaskCallbackUdp as u8)) {
                            // For the firewalled node we serve as its buddy.
                            match ed2k_peer::udp::UdpPacket::parse(&datagram, None) {
                                Ok(ed2k_peer::udp::UdpPacket::ReaskCallbackUdp { buddy_id, ping }) => {
                                    buddies.relay_reask(from, buddy_id, &ping)
                                }
                                _ => Vec::new(),
                            }
                        } else if datagram.get(1) == Some(&(UdpOpcode::ReaskFilePing as u8)) {
                            match uploader.as_mut() {
                                Some(up) => up.udp_reask(from, &datagram, now),
                                None => Vec::new(),
                            }
                        } else {
                            queue.udp_packet(from, &datagram, now)
                        }
                    }
                    Some(Command::File { file, op, reply }) => {
                        let mut out = Vec::new();
                        let missing = || Err(format!("FileHash not found: {file}"));
                        let found = |ok: bool| if ok { Ok(()) } else { missing() };
                        let r = match op {
                            FileOp::Pause => found(queue.pause(&file, now, &mut out)),
                            FileOp::Stop => found(queue.stop(&file, now, &mut out)),
                            FileOp::Resume => found(queue.resume(&file)),
                            FileOp::Priority { prio, auto } => {
                                found(queue.set_file(&file, |f| f.set_down_priority(prio, auto)))
                            }
                            FileOp::Category(c) => found(queue.set_file(&file, |f| f.set_category(c))),
                            FileOp::Delete => match queue.remove(&file, now, &mut out) {
                                Some(f) => f.delete().map_err(|e| e.to_string()),
                                None => missing(),
                            },
                        };
                        let _ = reply.send(r);
                        out
                    }
                    Some(Command::Shutdown) | None => break,
                }
            }
        };
        for a in actions {
            match a {
                Action::Connect {
                    conn,
                    addr,
                    obfuscate_for,
                } => {
                    let hs = match obfuscate_for {
                        Some(target) => Handshake::Client {
                            target,
                            max_padding: config.max_padding,
                        },
                        None => Handshake::Plain,
                    };
                    peer_addrs.insert(conn, addr);
                    spawn(conn, How::Outgoing(addr, hs), &mut conns);
                }
                Action::Send { conn, packets } => {
                    if let Some(h) = conns.get(&conn) {
                        for p in packets {
                            let _ = h.tx.send(p);
                        }
                    }
                }
                Action::Close { conn } => {
                    if let Some(h) = conns.remove(&conn) {
                        // Let the writer drain what was queued, then hang up.
                        drop(h.tx);
                        let task = h.task;
                        tokio::spawn(async move {
                            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
                        });
                    }
                }
                Action::SendUdp(d) => {
                    if let Some(tx) = &config.udp {
                        let _ = tx.send(d);
                    }
                }
                Action::Report(r) => {
                    // A finished download is shared at once.
                    if let (Report::Completed { path, .. }, Some(up)) = (&r, uploader.as_mut()) {
                        let _ = up.share_completed(path);
                    }
                    let _ = reports.send(r);
                }
            }
        }
        if uploader.is_none()
            && config.stop_when_done
            && queue.files().next().is_some()
            && queue.all_done()
        {
            break;
        }
    }
    if let Some(up) = uploader.as_mut() {
        let _ = up.save();
    }

    for a in queue.shutdown(Instant::now()) {
        if let Action::Report(r) = a {
            let _ = reports.send(r);
        }
    }
    for (_, h) in conns.drain() {
        h.task.abort();
    }
    (queue, uploader)
}

/// `OP_KAD_FWTCPCHECK_ACK` (eMule protocol, no payload).
/// Whether the first packet of an incoming connection is the hello of the
/// firewalled node we offered to serve as its Kad buddy.
fn is_expected_buddy(
    buddies: &Buddies,
    p: &Packet,
    from: Option<&SocketAddr>,
    now: Instant,
) -> bool {
    let Some(SocketAddr::V4(a)) = from else {
        return false;
    };
    match PeerPacket::parse(p.clone(), Default::default()) {
        Ok(PeerPacket::Hello(h)) => buddies.wants_incoming(&h, *a.ip(), now),
        _ => false,
    }
}

fn is_kad_firewall_ack(p: &Packet) -> bool {
    p.protocol == u8::from(Protocol::Emule) && p.opcode == u8::from(Extended::KadFwTcpCheckAck)
}

/// The next incoming connection, or never without a listener.
async fn accept(listener: Option<&TcpListener>) -> Option<TcpStream> {
    match listener {
        Some(l) => l.accept().await.ok().map(|(s, _)| s),
        None => std::future::pending().await,
    }
}
