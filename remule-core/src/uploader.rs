// SPDX-License-Identifier: GPL-2.0-or-later
//! The upload side of a running client, without IO: one
//! [`UploadSession`] per peer that connects to download from us, the
//! [`UploadQueue`] deciding who gets a slot, the shared files the data
//! comes from, and the credits. It speaks the same [`Action`]s as the
//! [`DownloadQueue`](crate::download_queue::DownloadQueue), so the
//! [`downloader`](crate::downloader) runs both.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed2k_codec::Packet;
use ed2k_crypto::credits::IdentState;
use ed2k_hash::aich::AichTree;
use ed2k_peer::packets::{self, AichRecovery};
use ed2k_peer::secident::{IdentConfig, IdentResult, Identity};
use ed2k_peer::upload::{Event, Output, UploadSession, UploadState};
use ed2k_peer::{Hello, PeerPacket};
use ed2k_types::ed2k::PARTSIZE;
use ed2k_types::Md4Hash;

use crate::credits::Credits;
use crate::download_queue::{Action, ConnId, Report};
use crate::shared::SharedFiles;
use crate::upload_queue::{Answer, Asker, QueueAction, UploadQueue};

struct Peer {
    session: UploadSession,
    user_hash: Md4Hash,
    ip: IpAddr,
    ident: IdentState,
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

    pub fn credits_mut(&mut self) -> Option<&mut Credits> {
        self.credits.as_mut()
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
        if let Some(ours) = self.identity.clone() {
            let cfg = IdentConfig {
                ours,
                stored_key: self.credits.as_ref().and_then(|c| c.public_key(&user_hash)),
                peer_ip: match ip {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(_) => None,
                },
                our_id: self.ours.id,
                our_public_ip: None,
            };
            let challenge = (now.elapsed().subsec_nanos() ^ user_hash.0[0] as u32) | 1;
            send.extend(session.start_secure_ident(cfg, challenge).send);
        }
        self.peers.insert(
            conn,
            Peer {
                session,
                user_hash,
                ip,
                ident: IdentState::NotAvailable,
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

    /// A packet from one of our peers.
    pub fn packet(&mut self, conn: ConnId, packet: Packet, now: Instant) -> Vec<Action> {
        let Some(p) = self.peers.get_mut(&conn) else {
            return Vec::new();
        };
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
                    let hello = p.session.peer();
                    let asker = Asker {
                        user_hash: p.user_hash,
                        ip: p.ip,
                        low_id: hello.is_some_and(|h| h.id < 0x0100_0000),
                        score_ratio: ratio,
                        old_emule: false,
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
                Event::Closed(_) => close = true,
                Event::Handshake(_)
                | Event::FileRequested { .. }
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
            self.queue.set_connected(&p.user_hash, false);
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

    /// The periodic work: the upload rate, and free slots filled.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let secs = now.saturating_duration_since(self.window.0).as_secs_f64();
        if secs >= 10.0 {
            self.rate = (self.window.1 as f64 / secs) as u64;
            self.window = (now, 0);
        }
        let mut out = Vec::new();
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
                // Calling a peer back is not ported: its turn passes.
                QueueAction::CallBack(user) | QueueAction::TakeSlot(user) => {
                    self.queue.ended(&user);
                }
            }
        }
        out
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
