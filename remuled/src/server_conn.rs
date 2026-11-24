// SPDX-License-Identifier: GPL-2.0-or-later
//! Which eD2k server to log into next, and when (`CServerConnect`), without
//! IO: the client loop makes the attempts and reports how they went.
//!
//! As aMule with "safe connect" on: one attempt at a time, the servers in
//! list order (high priority first). When obfuscation is asked for, a pass
//! over every server obfuscated, then one in plain (aMule's "Making another
//! pass without obfuscation"). Each attempt gets [`ATTEMPT_TIMEOUT`]. When
//! every server has failed, a new sweep [`RETRY_AFTER`] later. A connection
//! that was up and is lost starts a new sweep at once. With `Reconnect` off,
//! neither happens.
//!
//! A connection to one server the user picked (`ConnectToServer`) is tried
//! obfuscated, then plain, and nothing else when it fails. The user can
//! disconnect, and add or remove servers while it runs.
//!
//! With `AutoConnectStaticOnly`, a sweep tries the static servers only,
//! and none starts when there are none.
//!
//! Not ported: two attempts at a time.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// `CONSERVTIMEOUT`: how long one attempt (connect and login) may take.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(25_000);
/// `CS_RETRYCONNECTTIME`: the wait after every server has failed.
pub const RETRY_AFTER: Duration = Duration::from_secs(30);

/// One connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    pub addr: SocketAddr,
    pub obfuscated: bool,
}

/// What the client should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Try this server.
    Connect(Attempt),
    /// Every server failed: [`Connector::poll`] starts again at this time.
    RetryAt(Instant),
    /// Nothing more (no servers, or `Reconnect` off).
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Connecting(Attempt),
    Connected(Attempt),
    Waiting(Instant),
}

/// The server connection's state (`CServerConnect`).
#[derive(Debug)]
pub struct Connector {
    servers: Vec<SocketAddr>,
    obfuscate: bool,
    reconnect: bool,
    /// The next server of the sweep.
    pos: usize,
    /// Whether this pass is the obfuscated one.
    obfuscated_pass: bool,
    state: State,
    /// `singleconnecting`: one server picked, no sweep.
    single: bool,
    /// The static servers, and whether only they are tried.
    statics: std::collections::HashSet<SocketAddr>,
    static_only: bool,
}

impl Connector {
    /// `servers` in the order to try them; `obfuscate` asks for the
    /// obfuscated pass first; `reconnect` is aMule's `Reconnect`.
    pub fn new(servers: Vec<SocketAddr>, obfuscate: bool, reconnect: bool) -> Self {
        Connector {
            servers,
            obfuscate,
            reconnect,
            pos: 0,
            obfuscated_pass: obfuscate,
            state: State::Idle,
            single: false,
            statics: Default::default(),
            static_only: false,
        }
    }

    /// `AutoConnectStaticOnly`.
    pub fn set_static_only(&mut self, on: bool) {
        self.static_only = on;
    }

    /// A server marked static or not (`IsStaticMember`).
    pub fn set_static(&mut self, addr: SocketAddr, on: bool) {
        if on {
            self.statics.insert(addr);
        } else {
            self.statics.remove(&addr);
        }
    }

    /// Whether a sweep may try this server.
    fn may_try(&self, addr: &SocketAddr) -> bool {
        !self.static_only || self.statics.contains(addr)
    }

    /// The servers, in the order they are tried.
    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// A server added at the end of the list (`CServerList::AddServer`).
    pub fn add(&mut self, addr: SocketAddr) {
        if !self.servers.contains(&addr) {
            self.servers.push(addr);
        }
    }

    /// A server taken out of the list; a sweep under way goes on with the
    /// one after it (`RemoveServer` moving `m_serverpos` on).
    pub fn remove(&mut self, addr: SocketAddr) {
        if let Some(i) = self.servers.iter().position(|a| *a == addr) {
            self.servers.remove(i);
            if i < self.pos {
                self.pos -= 1;
            }
        }
    }

    /// `ConnectToAnyServer`: a sweep from the top of the list.
    pub fn start(&mut self, now: Instant) -> Next {
        self.single = false;
        self.pos = 0;
        self.obfuscated_pass = self.obfuscate;
        // "No valid servers to which to connect found in server list"
        if !self.servers.iter().any(|a| self.may_try(a)) {
            self.state = State::Idle;
            return Next::Idle;
        }
        self.try_next(now)
    }

    /// `TryAnotherConnectionrequest`.
    fn try_next(&mut self, now: Instant) -> Next {
        while self.servers.get(self.pos).is_some_and(|a| !self.may_try(a)) {
            self.pos += 1;
        }
        if let Some(&addr) = self.servers.get(self.pos) {
            self.pos += 1;
            let a = Attempt {
                addr,
                obfuscated: self.obfuscated_pass,
            };
            self.state = State::Connecting(a);
            return Next::Connect(a);
        }
        if self.obfuscated_pass {
            // "Failed to connect to all obfuscated servers listed. Making
            // another pass without obfuscation."
            self.obfuscated_pass = false;
            self.pos = 0;
            return self.try_next(now);
        }
        // "Failed to connect to all servers listed."
        if self.reconnect {
            let at = now + RETRY_AFTER;
            self.state = State::Waiting(at);
            Next::RetryAt(at)
        } else {
            self.state = State::Idle;
            Next::Idle
        }
    }

    /// The attempt in progress failed or took longer than
    /// [`ATTEMPT_TIMEOUT`]: the next server.
    pub fn failed(&mut self, now: Instant) -> Next {
        match self.state {
            // One server picked: plain after obfuscated, then nothing.
            State::Connecting(a) if self.single => {
                if a.obfuscated {
                    let a = Attempt {
                        obfuscated: false,
                        ..a
                    };
                    self.state = State::Connecting(a);
                    Next::Connect(a)
                } else {
                    self.stop();
                    Next::Idle
                }
            }
            State::Connecting(_) => self.try_next(now),
            _ => Next::Idle,
        }
    }

    /// `ConnectToServer`: this server alone, obfuscated first when asked.
    pub fn connect_to(&mut self, addr: SocketAddr) -> Next {
        self.single = true;
        let a = Attempt {
            addr,
            obfuscated: self.obfuscate,
        };
        self.state = State::Connecting(a);
        Next::Connect(a)
    }

    /// `StopConnectionTry`: no attempt, no sweep waiting; a connection
    /// that is up stays up.
    pub fn stop(&mut self) {
        self.single = false;
        if !matches!(self.state, State::Connected(_)) {
            self.state = State::Idle;
        }
    }

    /// `Disconnect`: the user hung up. True if a connection was up; nothing
    /// follows it, unlike a lost one.
    pub fn disconnect(&mut self) -> bool {
        if matches!(self.state, State::Connected(_)) {
            self.state = State::Idle;
            true
        } else {
            false
        }
    }

    /// The attempt in progress logged in.
    pub fn logged_in(&mut self) {
        if let State::Connecting(a) = self.state {
            self.state = State::Connected(a);
            self.single = false;
        }
    }

    /// The server we were logged into closed the connection: a new sweep
    /// at once when reconnecting.
    pub fn lost(&mut self, now: Instant) -> Next {
        if !matches!(self.state, State::Connected(_)) {
            return Next::Idle;
        }
        if self.reconnect {
            self.start(now)
        } else {
            self.state = State::Idle;
            Next::Idle
        }
    }

    /// The new sweep, once a wait after every server failing is over.
    pub fn poll(&mut self, now: Instant) -> Option<Next> {
        match self.state {
            State::Waiting(at) if now >= at => Some(self.start(now)),
            _ => None,
        }
    }

    /// The server we are logged into.
    pub fn connected(&self) -> Option<Attempt> {
        match self.state {
            State::Connected(a) => Some(a),
            _ => None,
        }
    }

    /// The attempt in progress.
    pub fn connecting(&self) -> Option<Attempt> {
        match self.state {
            State::Connecting(a) => Some(a),
            _ => None,
        }
    }
}
