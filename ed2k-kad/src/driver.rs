// SPDX-License-Identifier: GPL-2.0-or-later
//! The [`Kad`] node on a tokio UDP socket: one task owns the node and the
//! socket; the application talks to it through a [`KadHandle`].

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use ed2k_formats::nodes_dat::NodesDat;
use ed2k_server::search::SearchParams;
use ed2k_types::Md4Hash;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::node::{Datagram, Event, Kad, SearchError, Stats};

/// A picture of the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub contacts: usize,
    pub verified: usize,
    /// By type: 0 (alive for hours) to 4 (not answering).
    pub by_type: [usize; 5],
    pub depth: u32,
    pub estimated_users: u32,
    pub connected: bool,
    pub searches: usize,
    pub external_port: Option<u16>,
    pub stats: Stats,
}

enum Command {
    Keyword(
        SearchParams,
        oneshot::Sender<Result<(u32, String), SearchError>>,
    ),
    Sources(Md4Hash, u64, oneshot::Sender<Result<u32, SearchError>>),
    Bootstrap(SocketAddrV4),
    Snapshot(oneshot::Sender<Snapshot>),
    Nodes(oneshot::Sender<Option<NodesDat>>),
}

/// The application's side.
#[derive(Debug)]
pub struct KadHandle {
    cmd: mpsc::Sender<Command>,
    pub events: mpsc::Receiver<Event>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Command")
    }
}

impl Drop for KadHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Run the node on `socket`.
pub fn spawn(kad: Kad, socket: UdpSocket) -> KadHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (ev_tx, ev_rx) = mpsc::channel(1024);
    let task = tokio::spawn(run(kad, socket, cmd_rx, ev_tx));
    KadHandle {
        cmd: cmd_tx,
        events: ev_rx,
        task,
    }
}

impl KadHandle {
    async fn ask<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Command) -> Option<T> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(make(tx)).await.ok()?;
        rx.await.ok()
    }

    /// Start a keyword search: its ID and the keyword it looks up.
    pub async fn search_keyword(&self, params: SearchParams) -> Result<(u32, String), SearchError> {
        self.ask(|tx| Command::Keyword(params, tx))
            .await
            .unwrap_or(Err(SearchError::AlreadySearching))
    }

    /// Start a source search.
    pub async fn search_sources(&self, hash: Md4Hash, size: u64) -> Result<u32, SearchError> {
        self.ask(|tx| Command::Sources(hash, size, tx))
            .await
            .unwrap_or(Err(SearchError::AlreadySearching))
    }

    pub async fn bootstrap(&self, to: SocketAddrV4) {
        let _ = self.cmd.send(Command::Bootstrap(to)).await;
    }

    pub async fn snapshot(&self) -> Option<Snapshot> {
        self.ask(Command::Snapshot).await
    }

    /// The nodes.dat to save (`None` below 25 contacts).
    pub async fn nodes(&self) -> Option<NodesDat> {
        self.ask(Command::Nodes).await.flatten()
    }
}

fn snapshot(kad: &Kad, now: u64) -> Snapshot {
    let mut by_type = [0; 5];
    let mut verified = 0;
    let mut contacts = 0;
    for c in kad.routing.contacts() {
        contacts += 1;
        by_type[c.kind.min(4) as usize] += 1;
        verified += c.ip_verified as usize;
    }
    Snapshot {
        contacts,
        verified,
        by_type,
        depth: kad.routing.depth(),
        estimated_users: kad.routing.estimate_users(),
        connected: kad.is_connected(now),
        searches: kad.searches().count(),
        external_port: kad.external_port,
        stats: kad.stats.clone(),
    }
}

async fn send_all(socket: &UdpSocket, out: Vec<Datagram>) {
    for d in out {
        // A failed send to one peer (unreachable, ...) is not fatal.
        let _ = socket.send_to(&d.bytes, d.to).await;
    }
}

async fn run(
    mut kad: Kad,
    socket: UdpSocket,
    mut cmds: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    let start = Instant::now();
    // Seconds on a clock that starts well above 0 (0 means "never" in places).
    let now = || 1_000 + start.elapsed().as_secs();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                let (n, from) = match r {
                    Ok(x) => x,
                    // Windows reports ICMP port-unreachable as a recv error: ignore.
                    Err(_) => continue,
                };
                let SocketAddr::V4(from) = from else { continue };
                let out = kad.handle(from, &buf[..n], now());
                send_all(&socket, out.send).await;
                for e in out.events {
                    let _ = events.send(e).await;
                }
            }
            _ = tick.tick() => {
                let out = kad.tick(now());
                send_all(&socket, out.send).await;
                for e in out.events {
                    let _ = events.send(e).await;
                }
            }
            c = cmds.recv() => {
                let Some(c) = c else { return };
                let t = now();
                match c {
                    Command::Keyword(p, tx) => {
                        match kad.search_keyword(&p, t) {
                            Ok((id, word, out)) => {
                                send_all(&socket, out).await;
                                let _ = tx.send(Ok((id, word)));
                            }
                            Err(e) => { let _ = tx.send(Err(e)); }
                        }
                    }
                    Command::Sources(h, size, tx) => match kad.search_sources(h, size, t) {
                        Ok((id, out)) => {
                            send_all(&socket, out).await;
                            let _ = tx.send(Ok(id));
                        }
                        Err(e) => { let _ = tx.send(Err(e)); }
                    },
                    Command::Bootstrap(to) => {
                        let d = kad.bootstrap(to, t);
                        send_all(&socket, vec![d]).await;
                    }
                    Command::Snapshot(tx) => { let _ = tx.send(snapshot(&kad, t)); }
                    Command::Nodes(tx) => { let _ = tx.send(kad.nodes_to_save()); }
                }
            }
        }
    }
}
