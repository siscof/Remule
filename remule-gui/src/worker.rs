// SPDX-License-Identifier: GPL-2.0-or-later
//! The EC worker thread.
//!
//! amulegui drives `CRemoteConnect` from wx timers on the GUI thread. Here
//! one thread owns the blocking [`Client`]: it polls the daemon on a schedule
//! that favours the page on screen, runs the commands the UI queues, and
//! sends everything back as [`Update`]s. The UI never blocks on the network.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use remule_ec::model::{
    PartFile, SearchKind, SearchParams, SearchProgress, SearchResult, Server, SharedFile, Stats,
};
use remule_ec::{Client, ConnectOptions, Error, ServerInfo};

/// The pages, as the buttons of aMule's main toolbar (amuleDlg.cpp).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Page {
    Networks = 0,
    Searches = 1,
    Transfers = 2,
    Shared = 3,
    Statistics = 4,
}

impl Page {
    fn from_u8(v: u8) -> Page {
        match v {
            0 => Page::Networks,
            1 => Page::Searches,
            3 => Page::Shared,
            4 => Page::Statistics,
            _ => Page::Transfers,
        }
    }
}

pub enum Update {
    Connected(ServerInfo),
    ConnectFailed(String),
    /// The connection died after login.
    Lost(String),
    Stats(Box<Stats>),
    Downloads(Vec<PartFile>),
    Shared(Vec<SharedFile>),
    Servers(Vec<Server>),
    Search(Vec<SearchResult>, SearchProgress),
    /// The outcome of a user command, for the notice area.
    Notice {
        ok: bool,
        text: String,
    },
}

/// A command to run against the daemon. Returns the text to show on success.
pub type Job = Box<dyn FnOnce(&mut Client) -> Result<String, Error> + Send>;

enum Cmd {
    Connect(ConnectOptions),
    Disconnect,
    Job(Job),
    Search(SearchKind, SearchParams),
    SearchStop,
    RefreshShared,
}

pub struct Worker {
    tx: Sender<Cmd>,
    pub rx: Receiver<Update>,
    page: Arc<AtomicU8>,
}

impl Worker {
    pub fn spawn(ctx: eframe::egui::Context) -> Worker {
        let (tx, cmd_rx) = mpsc::channel();
        let (up_tx, rx) = mpsc::channel();
        let page = Arc::new(AtomicU8::new(Page::Transfers as u8));
        let page2 = page.clone();
        thread::Builder::new()
            .name("ec-worker".into())
            .spawn(move || Loop::new(cmd_rx, up_tx, page2, ctx).run())
            .expect("spawn EC worker");
        Worker { tx, rx, page }
    }

    pub fn set_page(&self, p: Page) {
        self.page.store(p as u8, Ordering::Relaxed);
    }

    pub fn connect(&self, o: ConnectOptions) {
        let _ = self.tx.send(Cmd::Connect(o));
    }

    pub fn disconnect(&self) {
        let _ = self.tx.send(Cmd::Disconnect);
    }

    pub fn job(&self, f: impl FnOnce(&mut Client) -> Result<String, Error> + Send + 'static) {
        let _ = self.tx.send(Cmd::Job(Box::new(f)));
    }

    pub fn search(&self, kind: SearchKind, params: SearchParams) {
        let _ = self.tx.send(Cmd::Search(kind, params));
    }

    pub fn search_stop(&self) {
        let _ = self.tx.send(Cmd::SearchStop);
    }

    pub fn refresh_shared(&self) {
        let _ = self.tx.send(Cmd::RefreshShared);
    }
}

/// When each kind of data was last fetched.
#[derive(Default)]
struct Due {
    stats: Option<Instant>,
    downloads: Option<Instant>,
    servers: Option<Instant>,
    shared: Option<Instant>,
    search: Option<Instant>,
}

fn stale(last: Option<Instant>, every: Duration) -> bool {
    last.is_none_or(|t| t.elapsed() >= every)
}

struct Loop {
    cmds: Receiver<Cmd>,
    out: Sender<Update>,
    page: Arc<AtomicU8>,
    ctx: eframe::egui::Context,
    client: Option<Client>,
    due: Due,
    /// Poll search results while a search runs, and once more after.
    search_active: bool,
}

impl Loop {
    fn new(
        cmds: Receiver<Cmd>,
        out: Sender<Update>,
        page: Arc<AtomicU8>,
        ctx: eframe::egui::Context,
    ) -> Self {
        Loop {
            cmds,
            out,
            page,
            ctx,
            client: None,
            due: Due::default(),
            search_active: false,
        }
    }

    fn send(&self, u: Update) {
        let _ = self.out.send(u);
        self.ctx.request_repaint();
    }

    fn run(mut self) {
        loop {
            match self.cmds.recv_timeout(Duration::from_millis(200)) {
                Ok(cmd) => self.handle(cmd),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return, // UI closed
            }
            if self.client.is_some() {
                if let Err(e) = self.poll() {
                    self.lose(e);
                }
            }
        }
    }

    fn lose(&mut self, e: Error) {
        self.client = None;
        self.search_active = false;
        self.send(Update::Lost(e.to_string()));
    }

    /// Run `f` on the client; a fatal error drops the connection.
    fn with_client<T>(
        &mut self,
        f: impl FnOnce(&mut Client) -> Result<T, Error>,
    ) -> Option<Result<T, Error>> {
        let c = self.client.as_mut()?;
        let r = f(c);
        match r {
            Err(e) if e.is_fatal() => {
                self.lose(e);
                None
            }
            r => Some(r),
        }
    }

    fn notice(&self, r: Result<String, Error>) {
        match r {
            Ok(text) if text.is_empty() => {}
            Ok(text) => self.send(Update::Notice { ok: true, text }),
            Err(e) => self.send(Update::Notice {
                ok: false,
                text: e.to_string(),
            }),
        }
    }

    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Connect(o) => {
                self.client = None;
                match Client::connect(&o) {
                    Ok(c) => {
                        let info = c.info().clone();
                        self.client = Some(c);
                        self.due = Due::default();
                        self.send(Update::Connected(info));
                    }
                    Err(e) => self.send(Update::ConnectFailed(e.to_string())),
                }
            }
            Cmd::Disconnect => {
                self.client = None;
                self.search_active = false;
            }
            Cmd::Job(f) => {
                if let Some(r) = self.with_client(f) {
                    self.notice(r);
                    // Show the effect of the command at once.
                    self.due.downloads = None;
                    self.due.servers = None;
                    self.due.stats = None;
                }
            }
            Cmd::Search(kind, params) => {
                if let Some(r) = self.with_client(|c| c.search_start(kind, &params)) {
                    self.search_active = r.is_ok();
                    self.due.search = None;
                    self.notice(r);
                }
            }
            Cmd::SearchStop => {
                if let Some(r) = self.with_client(Client::search_stop) {
                    self.notice(r.map(|()| String::new()));
                    self.due.search = None;
                }
            }
            Cmd::RefreshShared => self.due.shared = None,
        }
    }

    fn poll(&mut self) -> Result<(), Error> {
        let page = Page::from_u8(self.page.load(Ordering::Relaxed));
        let secs = Duration::from_secs;
        let c = self.client.as_mut().expect("connected");

        if stale(self.due.stats, secs(1)) {
            let s = c.stats()?;
            self.due.stats = Some(Instant::now());
            let _ = self.out.send(Update::Stats(Box::new(s)));
        }
        let dl_every = if page == Page::Transfers {
            secs(1)
        } else {
            secs(4)
        };
        if stale(self.due.downloads, dl_every) {
            let d = c.download_queue()?;
            self.due.downloads = Some(Instant::now());
            let _ = self.out.send(Update::Downloads(d));
        }
        let srv_every = if page == Page::Networks {
            secs(5)
        } else {
            secs(60)
        };
        if stale(self.due.servers, srv_every) {
            let s = c.servers()?;
            self.due.servers = Some(Instant::now());
            let _ = self.out.send(Update::Servers(s));
        }
        // The shared list can be large; fetch it only for its own page.
        if page == Page::Shared && stale(self.due.shared, secs(10)) {
            let s = c.shared_files()?;
            self.due.shared = Some(Instant::now());
            let _ = self.out.send(Update::Shared(s));
        }
        let search_every = if page == Page::Searches {
            secs(1)
        } else {
            secs(5)
        };
        if (self.search_active || self.due.search.is_none()) && stale(self.due.search, search_every)
        {
            let progress = c.search_progress()?;
            let results = c.search_results()?;
            self.due.search = Some(Instant::now());
            if progress.finished {
                self.search_active = false;
            }
            let _ = self.out.send(Update::Search(results, progress));
        }
        self.ctx.request_repaint();
        Ok(())
    }
}
