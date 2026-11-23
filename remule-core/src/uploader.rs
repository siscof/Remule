// SPDX-License-Identifier: GPL-2.0-or-later
//! The upload side of a running client, without IO: one
//! [`UploadSession`] per peer that connects to download from us, the
//! [`UploadQueue`] deciding who gets a slot, the shared files the data
//! comes from, and the credits. It speaks the same [`Action`]s as the
//! [`DownloadQueue`](crate::download_queue::DownloadQueue), so the
//! [`downloader`](crate::downloader) runs both.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed2k_codec::Packet;
use ed2k_crypto::credits::IdentState;
use ed2k_hash::aich::AichTree;
use ed2k_peer::packets::{self, AichRecovery};
use ed2k_peer::secident::{IdentConfig, IdentResult, Identity};
use ed2k_peer::udp::UdpPacket;
use ed2k_peer::upload::Shares;
use ed2k_peer::upload::{Event, Output, UploadSession, UploadState};
use ed2k_peer::{Hello, PartStatus, PeerPacket};
use ed2k_types::ed2k::{CONNECTION_TIMEOUT, PARTSIZE};
use ed2k_types::Md4Hash;

use crate::credits::Credits;
use crate::download_queue::{Action, ConnId, Report, UdpOut};
use crate::shared::SharedFiles;
use crate::upload_queue::{Answer, Asker, QueueAction, UdpReask, UploadQueue};

struct Peer {
    session: UploadSession,
    user_hash: Md4Hash,
    ip: IpAddr,
    ident: IdentState,
    /// The last packet from it, or when the connection began.
    last_seen: Instant,
    /// Our hello, to send once a callback connects.
    hello: Option<Packet>,
}

/// Where a waiting peer can be called back.
#[derive(Debug, Clone, Copy)]
struct Callback {
    addr: SocketAddr,
    obfuscate: bool,
}

/// A secure ident challenge: anything but zero.
fn challenge(now: Instant, user: &Md4Hash) -> u32 {
    (now.elapsed().subsec_nanos() ^ u32::from(user.0[0])) | 1
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

/// The upload side.
pub struct Uploader {
    ours: Hello,
    identity: Option<Arc<Identity>>,
    shares: Arc<Mutex<SharedFiles>>,
    queue: UploadQueue,
    credits: Option<Credits>,
    peers: HashMap<ConnId, Peer>,
    /// HighID peers by user hash, for calling them back.
    callbacks: HashMap<Md4Hash, Callback>,
    /// A connection with no slot and nothing heard for this long is
    /// closed (`CClientTCPSocket::CheckTimeOut`); the peer keeps its place.
    idle_timeout: Duration,
    /// Bytes sent, and over the last rate window.
    sent_total: u64,
    window: (Instant, u64),
    rate: u64,
}

impl std::fmt::Debug for Uploader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Uploader")
            .field("peers", &self.peers.len())
            .field("sent_total", &self.sent_total)
            .finish()
    }
}

impl Uploader {
    /// `ours` is our hello (as the download queue's); `credits` the loaded
    /// `clients.met`, if kept.
    pub fn new(
        ours: Hello,
        identity: Option<Arc<Identity>>,
        shares: Arc<Mutex<SharedFiles>>,
        queue: UploadQueue,
        credits: Option<Credits>,
    ) -> Self {
        Uploader {
            ours,
            identity,
            shares,
            queue,
            credits,
            peers: HashMap::new(),
            callbacks: HashMap::new(),
            idle_timeout: CONNECTION_TIMEOUT,
            sent_total: 0,
            window: (Instant::now(), 0),
            rate: 0,
        }
    }

    pub fn shares(&self) -> &Arc<Mutex<SharedFiles>> {
        &self.shares
    }

    pub fn queue(&self) -> &UploadQueue {
        &self.queue
    }

    pub fn queue_mut(&mut self) -> &mut UploadQueue {
        &mut self.queue
    }

    /// How long a connection without a slot may stay silent
    /// ([`CONNECTION_TIMEOUT`] by default).
    pub fn set_idle_timeout(&mut self, t: Duration) {
        self.idle_timeout = t;
    }

    pub fn credits(&self) -> Option<&Credits> {
        self.credits.as_ref()
    }

    pub fn credits_mut(&mut self) -> Option<&mut Credits> {
        self.credits.as_mut()
    }

    /// A server login gave us this ID: the hellos of upload connections from
    /// now on carry it.
    pub fn set_our_id(&mut self, id: u32) {
        self.ours.id = id;
    }

    /// Bytes uploaded since start.
    pub fn sent_total(&self) -> u64 {
        self.sent_total
    }

    /// Whether `conn` is one of ours.
    pub fn owns(&self, conn: ConnId) -> bool {
        self.peers.contains_key(&conn)
    }

    /// A peer connected to us and said hello, and it is not a source of
    /// ours calling back: answer it and serve it.
    pub fn accept(&mut self, conn: ConnId, hello: Hello, ip: IpAddr, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let user_hash = hello.user_hash;
        let Ok((mut session, output)) = UploadSession::accepted(self.ours.clone(), hello) else {
            out.push(Action::Close { conn });
            return out;
        };
        let mut send = output.send;
        if let Some(peer) = session.peer().cloned() {
            self.remember_callback(&peer, ip);
        }
        if let Some(cfg) = self.ident_config(&user_hash, ip) {
            send.extend(
                session
                    .start_secure_ident(cfg, challenge(now, &user_hash))
                    .send,
            );
        }
        self.peers.insert(
            conn,
            Peer {
                session,
                user_hash,
                ip,
                ident: IdentState::NotAvailable,
                last_seen: now,
                hello: None,
            },
        );
        self.queue.set_connected(&user_hash, true);
        if !send.is_empty() {
            out.push(Action::Send {
                conn,
                packets: send,
            });
        }
        out
    }

    /// What secure identification needs, when we have a key.
    fn ident_config(&self, user_hash: &Md4Hash, ip: IpAddr) -> Option<IdentConfig> {
        Some(IdentConfig {
            ours: self.identity.clone()?,
            stored_key: self.credits.as_ref().and_then(|c| c.public_key(user_hash)),
            peer_ip: match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            },
            our_id: self.ours.id,
            our_public_ip: None,
        })
    }

    /// Note where a HighID peer listens, to call it back when its turn
    /// comes; obfuscated when it supports it and either side asks for it.
    fn remember_callback(&mut self, hello: &Hello, ip: IpAddr) {
        if hello.id < 0x0100_0000 || hello.port == 0 || ip.is_unspecified() {
            return;
        }
        let obfuscate = self.obfuscate_for(hello);
        self.callbacks.insert(
            hello.user_hash,
            Callback {
                addr: SocketAddr::new(ip, hello.port),
                obfuscate,
            },
        );
    }

    /// Whether to obfuscate what we send this peer, over TCP or UDP: it
    /// supports it and either side asks for it.
    fn obfuscate_for(&self, hello: &Hello) -> bool {
        let theirs = hello.misc2.unwrap_or_default();
        let ours = self.ours.misc2.unwrap_or_default();
        theirs.supports_crypt
            && (theirs.requires_crypt || theirs.requests_crypt || ours.requests_crypt)
    }

    /// A callback connection of ours is up: say hello.
    pub fn connected(&mut self, conn: ConnId, now: Instant) -> Vec<Action> {
        let Some(p) = self.peers.get_mut(&conn) else {
            return Vec::new();
        };
        p.last_seen = now;
        match p.hello.take() {
            Some(hello) => vec![Action::Send {
                conn,
                packets: vec![hello],
            }],
            None => Vec::new(),
        }
    }

    /// A packet from one of our peers.
    pub fn packet(&mut self, conn: ConnId, packet: Packet, now: Instant) -> Vec<Action> {
        let Some(p) = self.peers.get_mut(&conn) else {
            return Vec::new();
        };
        p.last_seen = now;
        let parsed = match PeerPacket::parse(packet, p.session.parse_context()) {
            Ok(x) => x,
            Err(_) => return self.drop_peer(conn, true),
        };
        let shares = self.shares.clone();
        let output = {
            let s = shares.lock().unwrap_or_else(|e| e.into_inner());
            p.session.handle(parsed, &*s)
        };
        self.handle_output(conn, output, now)
    }

    /// `OP_REASKFILEPING` from `from` (decrypted), as
    /// `CClientUDPSocket::ProcessPacket` answers it: `OP_FILENOTFOUND` for a
    /// file we do not share, `OP_REASKACK` with its rank to a peer waiting
    /// for that file, `OP_QUEUEFULL` to a stranger when the queue nearly is.
    /// Answers to a peer we know go obfuscated when it wants that.
    pub fn udp_reask(&mut self, from: SocketAddrV4, datagram: &[u8], now: Instant) -> Vec<Action> {
        let Ok(UdpPacket::ReaskFilePing { file, .. }) = UdpPacket::parse(datagram, None) else {
            return Vec::new();
        };
        let ip = IpAddr::V4(*from.ip());
        let info = {
            let s = self.shares.lock().unwrap_or_else(|e| e.into_inner());
            s.shared(&file)
        };
        let send = |packet: UdpPacket, version: u8, crypt: Option<Md4Hash>| {
            vec![Action::SendUdp(UdpOut {
                to: from,
                payload: packet.to_datagram(version),
                obfuscate_for: crypt,
            })]
        };
        let Some(info) = info else {
            let crypt = match self.queue.udp_reask(ip, from.port(), file, now) {
                UdpReask::OtherFile { user, crypt_udp } => crypt_udp.then_some(user),
                _ => None,
            };
            return send(UdpPacket::FileNotFound, 0, crypt);
        };
        match self.queue.udp_reask(ip, from.port(), file, now) {
            UdpReask::Waiting {
                user,
                rank,
                udp_version,
                crypt_udp,
            } => {
                // The rest of the ping (its parts, its complete sources)
                // feeds aMule's statistics only; it is read to check it.
                if UdpPacket::parse(datagram, Some(udp_version)).is_err() {
                    return Vec::new();
                }
                let parts = match info.parts {
                    PartStatus::Complete => None,
                    p => Some(p),
                };
                send(
                    UdpPacket::ReaskAck { parts, rank },
                    udp_version,
                    crypt_udp.then_some(user),
                )
            }
            UdpReask::Unknown { queue_full: true } => send(UdpPacket::QueueFull, 0, None),
            UdpReask::Unknown { queue_full: false }
            | UdpReask::OtherFile { .. }
            | UdpReask::Ambiguous => Vec::new(),
        }
    }

    fn handle_output(&mut self, conn: ConnId, output: Output, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let mut send = output.send;
        let mut close = false;
        for e in output.events {
            let Some(p) = self.peers.get_mut(&conn) else {
                break;
            };
            match e {
                Event::UploadRequested(file) => {
                    let (prio, auto) = {
                        let s = self.shares.lock().unwrap_or_else(|e| e.into_inner());
                        s.get(&file)
                            .map_or((1, true), |(f, _)| (f.up_priority, f.auto_priority))
                    };
                    let crypto = self.identity.is_some();
                    let ratio = self
                        .credits
                        .as_ref()
                        .map_or(1.0, |c| c.score_ratio(&p.user_hash, p.ident, crypto));
                    let hello = p.session.peer().cloned();
                    let crypt_udp = hello.as_ref().is_some_and(|h| self.obfuscate_for(h));
                    let Some(p) = self.peers.get_mut(&conn) else {
                        break;
                    };
                    let asker = Asker {
                        user_hash: p.user_hash,
                        ip: p.ip,
                        low_id: hello.as_ref().is_some_and(|h| h.id < 0x0100_0000),
                        score_ratio: ratio,
                        old_emule: false,
                        udp_port: hello.as_ref().map_or(0, |h| h.udp_port),
                        udp_version: hello
                            .as_ref()
                            .and_then(|h| h.misc1)
                            .map_or(0, |m| m.udp_version),
                        crypt_udp,
                    };
                    match self.queue.request(asker, file, prio, auto, self.rate, now) {
                        Answer::Slot => {
                            send.push(p.session.accept());
                            out.push(Action::Report(Report::UploadStarted {
                                user: p.user_hash,
                                file,
                            }));
                        }
                        Answer::Queued(r) => send.push(p.session.queue_rank(r)),
                        Answer::Refused => {}
                    }
                }
                Event::BlocksRequested { hash, blocks } => {
                    let shares = self.shares.clone();
                    let s = shares.lock().unwrap_or_else(|e| e.into_inner());
                    let name = s
                        .get(&hash)
                        .map(|(f, _)| f.name.clone())
                        .unwrap_or_default();
                    for b in blocks {
                        let Ok(data) = s.read_block(&hash, b.clone()) else {
                            // A read error ends the slot (`m_bIOError`).
                            close = true;
                            break;
                        };
                        let n = data.len() as u64;
                        send.extend(p.session.block_packets(b, &data, self.rate as u32, &name));
                        self.sent_total += n;
                        self.window.1 += n;
                        if let Some(c) = self.credits.as_mut() {
                            c.add_uploaded(&p.user_hash, n, unix_now());
                        }
                        if let Some(QueueAction::TakeSlot(_)) =
                            self.queue.sent(&p.user_hash, n, now)
                        {
                            send.push(p.session.end_slot());
                            break;
                        }
                    }
                }
                Event::UploadEnded => {
                    self.queue.ended(&p.user_hash);
                }
                Event::AichRequested { hash, part, root } => {
                    send.push(self.aich_answer(hash, part, root));
                }
                Event::Identified(r) => {
                    let p = self.peers.get_mut(&conn).unwrap();
                    p.ident = match &r {
                        IdentResult::Passed { key } => {
                            let ok = self
                                .credits
                                .as_mut()
                                .is_none_or(|c| c.set_public_key(&p.user_hash, key, unix_now()));
                            if ok {
                                IdentState::Identified
                            } else {
                                IdentState::BadGuy
                            }
                        }
                        IdentResult::Failed => IdentState::Failed,
                    };
                }
                Event::CalledBack => {
                    let (user, ip) = (p.user_hash, p.ip);
                    let file = self.queue.slot_file(&user).unwrap_or(Md4Hash([0; 16]));
                    self.queue.set_connected(&user, true);
                    if let Some(cfg) = self.ident_config(&user, ip) {
                        let p = self.peers.get_mut(&conn).unwrap();
                        send.extend(
                            p.session
                                .start_secure_ident(cfg, challenge(now, &user))
                                .send,
                        );
                    }
                    out.push(Action::Report(Report::UploadStarted { user, file }));
                }
                Event::Closed(_) => close = true,
                // A peer we connected to on request: now we know who it is.
                Event::Handshake(h) => {
                    if p.user_hash == Md4Hash([0; 16]) {
                        p.user_hash = h.user_hash;
                        let ip = p.ip;
                        self.remember_callback(&h, ip);
                    }
                }
                Event::FileRequested { .. }
                | Event::SourcesRequested { .. }
                | Event::Unhandled(_) => {}
            }
        }
        if !send.is_empty() {
            out.push(Action::Send {
                conn,
                packets: send,
            });
        }
        if close {
            out.extend(self.drop_peer(conn, true));
        }
        out
    }

    /// `OP_AICHANSWER`: recovery data from the shared file's hash set, or
    /// a refusal.
    fn aich_answer(&self, hash: Md4Hash, part: u16, root: ed2k_types::AichHash) -> Packet {
        let s = self.shares.lock().unwrap_or_else(|e| e.into_inner());
        let data = s.get(&hash).and_then(|(f, _)| {
            let set = s.aich_set(&hash)?;
            if set.root != root {
                return None;
            }
            AichTree::from_blocks(f.size, &set.block_hashes)?
                .part_recovery_data(u64::from(part) * PARTSIZE)
        });
        match data {
            Some(data) => packets::aich_answer(&AichRecovery {
                hash,
                part,
                root,
                data,
            }),
            None => packets::aich_answer_failed(hash),
        }
    }

    fn drop_peer(&mut self, conn: ConnId, close: bool) -> Vec<Action> {
        if let Some(p) = self.peers.remove(&conn) {
            // It may have another connection (it called while we dialled).
            if !self.peers.values().any(|o| o.user_hash == p.user_hash) {
                self.queue.set_connected(&p.user_hash, false);
            }
        }
        if close {
            vec![Action::Close { conn }]
        } else {
            Vec::new()
        }
    }

    /// The connection went.
    pub fn closed(&mut self, conn: ConnId) {
        self.drop_peer(conn, false);
    }

    /// The periodic work: the upload rate, idle connections closed, and
    /// free slots filled, calling back waiting peers that are not
    /// connected. `new_conn` names a new connection.
    pub fn tick(&mut self, now: Instant, new_conn: &mut dyn FnMut() -> ConnId) -> Vec<Action> {
        let secs = now.saturating_duration_since(self.window.0).as_secs_f64();
        if secs >= 10.0 {
            self.rate = (self.window.1 as f64 / secs) as u64;
            self.window = (now, 0);
        }
        let mut out = Vec::new();
        let idle: Vec<ConnId> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                p.session.state() != UploadState::Uploading
                    && now.saturating_duration_since(p.last_seen) > self.idle_timeout
            })
            .map(|(&c, _)| c)
            .collect();
        for conn in idle {
            out.extend(self.drop_peer(conn, true));
        }
        for a in self.queue.process(self.rate, now) {
            match a {
                QueueAction::GiveSlot(user) => {
                    let found = self.peers.iter_mut().find(|(_, p)| {
                        p.user_hash == user && p.session.state() != UploadState::Closed
                    });
                    match found {
                        Some((&conn, p)) => {
                            let file = p.session.file().unwrap_or(Md4Hash([0; 16]));
                            out.push(Action::Send {
                                conn,
                                packets: vec![p.session.accept()],
                            });
                            out.push(Action::Report(Report::UploadStarted { user, file }));
                        }
                        None => {
                            self.queue.ended(&user);
                        }
                    }
                }
                QueueAction::CallBack(user) => out.extend(self.call_back(user, now, new_conn)),
                QueueAction::TakeSlot(user) => {
                    self.queue.ended(&user);
                }
            }
        }
        out
    }

    /// `OP_CALLBACK` through our Kad buddy: someone at `addr` wants `file`
    /// and cannot reach us; connect to it (plain: its user hash is not
    /// known), and serve it as if it had connected. Nothing for a file we
    /// do not share.
    pub fn answer_callback(
        &mut self,
        addr: SocketAddrV4,
        file: Md4Hash,
        now: Instant,
        new_conn: &mut dyn FnMut() -> ConnId,
    ) -> Vec<Action> {
        let shared = {
            let s = self.shares.lock().unwrap_or_else(|e| e.into_inner());
            s.shared(&file).is_some()
        };
        if !shared {
            return Vec::new();
        }
        let Ok((session, hello)) = UploadSession::connect_on_request(self.ours.clone()) else {
            return Vec::new();
        };
        let conn = new_conn();
        self.peers.insert(
            conn,
            Peer {
                session,
                // Known once it answers.
                user_hash: Md4Hash([0; 16]),
                ip: IpAddr::V4(*addr.ip()),
                ident: IdentState::NotAvailable,
                last_seen: now,
                hello: Some(hello),
            },
        );
        vec![Action::Connect {
            conn,
            addr: SocketAddr::V4(addr),
            obfuscate_for: None,
        }]
    }

    /// `OP_DIRECTCALLBACKREQ` (we are firewalled, but take UDP): the peer at
    /// `addr` wants us to connect; do, obfuscated when it supports that,
    /// and serve it as if it had connected.
    pub fn answer_direct_callback(
        &mut self,
        addr: SocketAddrV4,
        user_hash: Md4Hash,
        connect_options: u8,
        now: Instant,
        new_conn: &mut dyn FnMut() -> ConnId,
    ) -> Vec<Action> {
        let Ok((session, hello)) = UploadSession::connect_on_request(self.ours.clone()) else {
            return Vec::new();
        };
        let conn = new_conn();
        self.peers.insert(
            conn,
            Peer {
                session,
                user_hash,
                ip: IpAddr::V4(*addr.ip()),
                ident: IdentState::NotAvailable,
                last_seen: now,
                hello: Some(hello),
            },
        );
        vec![Action::Connect {
            conn,
            addr: SocketAddr::V4(addr),
            obfuscate_for: (connect_options & 0x01 != 0).then_some(user_hash),
        }]
    }

    /// `AddUpNextClient` for a peer that is not connected: connect to it;
    /// the slot is given when it answers our hello. If it cannot be
    /// reached, the slot ends and it leaves the queue (`AddDeadSource`).
    fn call_back(
        &mut self,
        user: Md4Hash,
        now: Instant,
        new_conn: &mut dyn FnMut() -> ConnId,
    ) -> Vec<Action> {
        let Some(cb) = self.callbacks.get(&user).copied() else {
            self.queue.ended(&user);
            return Vec::new();
        };
        let Ok((session, hello)) = UploadSession::connect(self.ours.clone()) else {
            self.queue.ended(&user);
            return Vec::new();
        };
        let conn = new_conn();
        self.peers.insert(
            conn,
            Peer {
                session,
                user_hash: user,
                ip: cb.addr.ip(),
                ident: IdentState::NotAvailable,
                last_seen: now,
                hello: Some(hello),
            },
        );
        vec![Action::Connect {
            conn,
            addr: cb.addr,
            obfuscate_for: cb.obfuscate.then_some(user),
        }]
    }

    /// Share a file that just completed (hashed here; blocking).
    pub fn share_completed(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let h = SharedFiles::hash(path)?;
        let date = crate::shared::mtime(&std::fs::metadata(path)?);
        let mut s = self.shares.lock().unwrap_or_else(|e| e.into_inner());
        s.add_hashed(path, &h, date, unix_now());
        s.save()
    }

    /// Save `known.met` and `clients.met`.
    pub fn save(&mut self) -> std::io::Result<()> {
        if let Some(c) = self.credits.as_mut() {
            c.save()?;
        }
        let mut s = self.shares.lock().unwrap_or_else(|e| e.into_inner());
        if s.is_dirty() {
            s.save()?;
        }
        Ok(())
    }
}
