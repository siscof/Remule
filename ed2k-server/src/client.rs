// SPDX-License-Identifier: GPL-2.0-or-later
//! An async server connection on `remule-net`: a reader task runs the
//! [`Session`] and sends its events down a channel; a writer task sends
//! what is queued for the server.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed2k_codec::Packet;
use ed2k_types::Md4Hash;
use remule_net::{establish, Bandwidth, ConnConfig, Handshake, NetError, Priority};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::packets::{self, LoginInfo};
use crate::search::{encode_search, QueryError, SearchParams, SearchResult};
use crate::session::{CloseReason, Event, ServerInfo, Session, SessionOptions, LOGIN_TIMEOUT};

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Net(#[from] NetError),
    #[error("{0} timed out")]
    Timeout(&'static str),
    /// The server would not have us; its messages say why.
    #[error("the server refused the login{}", fmt_reasons(.0))]
    Refused(Vec<String>),
    #[error("the server closed the connection{}", fmt_reasons(.0))]
    Closed(Vec<String>),
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error("bad login data: {0}")]
    Login(ed2k_codec::TagError),
}

fn fmt_reasons(r: &[String]) -> String {
    if r.is_empty() {
        String::new()
    } else {
        format!(": {}", r.join(" / "))
    }
}

/// How to connect.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub login: LoginInfo,
    pub session: SessionOptions,
    /// Use the obfuscated handshake (the server's obfuscation port, if it
    /// has one, is what to connect to).
    pub obfuscate: bool,
    pub bandwidth: Arc<Bandwidth>,
    pub connect_timeout: Duration,
}

impl ConnectOptions {
    pub fn new(login: LoginInfo) -> Self {
        ConnectOptions {
            login,
            session: SessionOptions::default(),
            obfuscate: false,
            bandwidth: Arc::new(Bandwidth::unlimited()),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// A logged-in server connection.
#[derive(Debug)]
pub struct ServerClient {
    session: Arc<Mutex<Session>>,
    out: mpsc::Sender<Packet>,
    events: mpsc::Receiver<Event>,
    pending: VecDeque<Event>,
    id: u32,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for ServerClient {
    /// Stop reading; the writer then sends what is queued and closes.
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// The outcome of the login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub id: u32,
    pub low_id: bool,
    pub public_ip: Option<std::net::Ipv4Addr>,
}

fn lock(s: &Mutex<Session>) -> std::sync::MutexGuard<'_, Session> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

impl ServerClient {
    /// Connect to `addr` and log in.
    pub async fn connect(
        addr: SocketAddr,
        options: ConnectOptions,
    ) -> Result<(ServerClient, Login), ClientError> {
        let stream = timeout(options.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| ClientError::Timeout("connecting"))??;
        let _ = stream.set_nodelay(true);
        let handshake = if options.obfuscate {
            Handshake::Server
        } else {
            Handshake::Plain
        };
        let mut cfg = ConnConfig::new(options.bandwidth.clone());
        // aMule does not count server traffic against the download limit.
        cfg.download_throttled = false;
        let (mut reader, mut writer) =
            timeout(options.connect_timeout, establish(stream, handshake, cfg))
                .await
                .map_err(|_| ClientError::Timeout("the obfuscation handshake"))??;

        let mut session = Session::new(options.login, options.session);
        let login = session.start().map_err(ClientError::Login)?;
        let session = Arc::new(Mutex::new(session));
        let (out_tx, mut out_rx) = mpsc::channel::<Packet>(64);
        let (ev_tx, ev_rx) = mpsc::channel::<Event>(256);

        // Writer: everything queued, in order.
        tokio::spawn(async move {
            while let Some(p) = out_rx.recv().await {
                if writer.send(&p, Priority::Control).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
        // Reader: packets through the session. It holds the queue weakly,
        // so dropping the client closes the writer.
        let reader = {
            let session = session.clone();
            let out_tx = out_tx.downgrade();
            tokio::spawn(async move {
                loop {
                    let p = match reader.recv().await {
                        Ok(Some(p)) => p,
                        _ => break,
                    };
                    let output = match packets::parse(p) {
                        Ok(sp) => lock(&session).handle(sp),
                        // aMule logs bogus packets and goes on.
                        Err(e) => {
                            let _ = ev_tx.send(Event::Message(format!("({e})"))).await;
                            continue;
                        }
                    };
                    if let Some(out_tx) = out_tx.upgrade() {
                        for p in output.send {
                            let _ = out_tx.send(p).await;
                        }
                    }
                    let mut refused = false;
                    for e in output.events {
                        refused |= matches!(e, Event::Closed(CloseReason::Refused));
                        if ev_tx.send(e).await.is_err() {
                            return;
                        }
                    }
                    if refused {
                        return;
                    }
                }
                let ev = lock(&session).closed();
                let _ = ev_tx.send(ev).await;
            })
        };

        out_tx
            .send(login)
            .await
            .map_err(|_| ClientError::Closed(vec![]))?;
        let mut client = ServerClient {
            session,
            out: out_tx,
            events: ev_rx,
            pending: VecDeque::new(),
            id: 0,
            reader,
        };
        let login = client.wait_login().await?;
        client.id = login.id;
        Ok((client, login))
    }

    async fn wait_login(&mut self) -> Result<Login, ClientError> {
        let mut reasons = Vec::new();
        let wait = async {
            loop {
                match self.events.recv().await {
                    Some(Event::LoggedIn {
                        id,
                        low_id,
                        public_ip,
                    }) => {
                        return Ok(Login {
                            id,
                            low_id,
                            public_ip,
                        })
                    }
                    Some(Event::Closed(CloseReason::Refused)) => {
                        return Err(ClientError::Refused(std::mem::take(&mut reasons)))
                    }
                    Some(Event::Closed(_)) | None => {
                        return Err(ClientError::Closed(std::mem::take(&mut reasons)))
                    }
                    Some(e) => {
                        if let Event::Error(m) | Event::Warning(m) = &e {
                            reasons.push(m.clone());
                        }
                        self.pending.push_back(e);
                    }
                }
            }
        };
        timeout(LOGIN_TIMEOUT, wait)
            .await
            .map_err(|_| ClientError::Timeout("the login"))?
    }

    /// Our ID on this server.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// What we know about the server.
    pub fn info(&self) -> ServerInfo {
        lock(&self.session).info().clone()
    }

    /// The next event (those that came while waiting for something else first).
    pub async fn next_event(&mut self) -> Option<Event> {
        if let Some(e) = self.pending.pop_front() {
            return Some(e);
        }
        self.events.recv().await
    }

    /// Events already here, without waiting.
    pub fn drain_events(&mut self) -> Vec<Event> {
        let mut v: Vec<Event> = self.pending.drain(..).collect();
        while let Ok(e) = self.events.try_recv() {
            v.push(e);
        }
        v
    }

    /// Queue a packet for the server.
    pub async fn send(&self, p: Packet) -> Result<(), ClientError> {
        self.out
            .send(p)
            .await
            .map_err(|_| ClientError::Closed(vec![]))
    }

    /// Run a search and wait for its answer (other events are kept for
    /// [`ServerClient::next_event`]). With `more`, ask for more results
    /// while the server says there are, up to `max_rounds` answers.
    pub async fn search(
        &mut self,
        params: &SearchParams,
        wait: Duration,
        max_rounds: usize,
    ) -> Result<Vec<SearchResult>, ClientError> {
        let large = lock(&self.session).supports_large_files();
        let (payload, _) = encode_search(params, large)?;
        self.send(packets::search_request(payload)).await?;
        let mut all = Vec::new();
        for round in 0..max_rounds.max(1) {
            let (results, more) = self.wait_results(wait).await?;
            all.extend(results);
            if more != Some(true) || round + 1 == max_rounds.max(1) {
                break;
            }
            self.send(packets::query_more_results()).await?;
        }
        Ok(all)
    }

    async fn wait_results(
        &mut self,
        wait: Duration,
    ) -> Result<(Vec<SearchResult>, Option<bool>), ClientError> {
        let fut = async {
            loop {
                match self.events.recv().await {
                    Some(Event::SearchResults { results, more }) => return Ok((results, more)),
                    Some(Event::Closed(_)) | None => return Err(ClientError::Closed(vec![])),
                    Some(e) => self.pending.push_back(e),
                }
            }
        };
        timeout(wait, fut)
            .await
            .map_err(|_| ClientError::Timeout("the search"))?
    }

    /// Ask for sources of a file (the answer is an [`Event::FoundSources`]).
    pub async fn get_sources(&self, hash: Md4Hash, size: u64) -> Result<(), ClientError> {
        let obfu = lock(&self.session).info().tcp_flags
            & ed2k_types::ed2k::server_tcp::flags::TCPOBFUSCATION
            != 0;
        self.send(packets::get_sources(hash, size, obfu)).await
    }
}
