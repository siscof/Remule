// SPDX-License-Identifier: GPL-2.0-or-later
//! Connection limits (`CListenSocket::TooManySockets`, ListenSocket.cpp).
//!
//! Two limits: the open sockets (`MaxConnections`, exceeded only when the
//! count is *above* it) and the connections opened in the current five
//! seconds (`MaxConnectionsPerFiveSeconds`). The second shrinks while the
//! open count spikes above its running average: by `1 − spike / (2.5 ×
//! per-five)`, to nothing at 2.5 × per-five above it.
//!
//! While the limit is reached, the listener stops accepting and leaves
//! connections in the kernel backlog, as aMule does; it accepts anyway while
//! a server connection is being made (a refused callback would mean a LowID).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time::Instant;

/// `MAXCONPER5SEC`, the default `MaxConnectionsPerFiveSeconds`.
pub const DEFAULT_MAX_PER_FIVE: u32 = 50;
/// How often the per-five counter restarts (`CListenSocket::Process`).
pub const INTERVAL: Duration = Duration::from_secs(5);
/// How often the running average is updated (`UpdateConnectionsStatus`).
pub const STATUS_PERIOD: Duration = Duration::from_secs(1);

/// `GetRecommendedMaxConnections` from the OS limit on open sockets
/// (`None`: unknown).
pub fn recommended_max_connections(os_limit: Option<u32>) -> u32 {
    match os_limit {
        None => 500,
        Some(n) if n > 520 => 500,
        Some(n) if n < 20 => n,
        Some(n) if n <= 256 => n - 10,
        Some(n) => n - 20,
    }
}

/// The counters and the rule, without the clock.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionLimits {
    pub max_connections: u32,
    pub max_per_five: u32,
    open: u32,
    interval: u32,
    average: f32,
    checks: u32,
}

impl ConnectionLimits {
    pub fn new(max_connections: u32, max_per_five: u32) -> Self {
        ConnectionLimits {
            max_connections,
            max_per_five,
            open: 0,
            interval: 0,
            average: 0.0,
            checks: 0,
        }
    }

    /// Open sockets (`GetOpenSockets`).
    pub fn open(&self) -> u32 {
        self.open
    }

    /// Connections opened in this five-second interval.
    pub fn opened_in_interval(&self) -> u32 {
        self.interval
    }

    /// The running average of open sockets.
    pub fn average(&self) -> f32 {
        self.average
    }

    /// `AddSocket` + `AddConnection`.
    pub fn opened(&mut self) {
        self.open += 1;
        self.interval += 1;
    }

    /// `RemoveSocket`.
    pub fn closed(&mut self) {
        self.open = self.open.saturating_sub(1);
    }

    /// `Process`: every five seconds.
    pub fn reset_interval(&mut self) {
        self.interval = 0;
    }

    /// `UpdateConnectionsStatus`: every second, while connected to a network.
    pub fn update_status(&mut self) {
        self.checks = self.checks.saturating_add(1);
        let percent = ((self.checks - 1) as f32 / self.checks as f32).min(0.99);
        self.average = self.average * percent + self.open as f32 * (1.0 - percent);
    }

    /// `GetMaxConperFiveModifier`
    pub fn per_five_modifier(&self) -> f32 {
        let spike = self.open as f32 - self.average;
        if spike < 1.0 {
            return 1.0;
        }
        let tolerance = 2.5 * self.max_per_five as f32;
        if spike > tolerance {
            return 0.0;
        }
        1.0 - spike / tolerance
    }

    /// `TooManySockets(bIgnoreInterval)`
    pub fn too_many(&self, ignore_interval: bool) -> bool {
        self.open > self.max_connections
            || (!ignore_interval
                && self.interval as f32 > self.max_per_five as f32 * self.per_five_modifier())
    }
}

#[derive(Debug)]
struct Clocked {
    limits: ConnectionLimits,
    last_reset: Instant,
    last_status: Instant,
}

impl Clocked {
    fn tick(&mut self, now: Instant, connected: bool) {
        while now.saturating_duration_since(self.last_reset) >= INTERVAL {
            self.last_reset += INTERVAL;
            self.limits.reset_interval();
        }
        let mut n = 0;
        while now.saturating_duration_since(self.last_status) >= STATUS_PERIOD {
            self.last_status += STATUS_PERIOD;
            // Bound the catch-up after a long idle spell.
            if connected && n < 3600 {
                self.limits.update_status();
                n += 1;
            }
        }
    }
}

/// The limits on a clock, shared by every connection (`Arc<ConnectionLimiter>`).
#[derive(Debug)]
pub struct ConnectionLimiter {
    state: Mutex<Clocked>,
    notify: Notify,
    connected: AtomicBool,
}

/// One open connection; dropping it closes the slot.
#[derive(Debug)]
pub struct Permit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.limiter.lock().limits.closed();
        self.limiter.notify.notify_waiters();
    }
}

impl ConnectionLimiter {
    pub fn new(max_connections: u32, max_per_five: u32) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(ConnectionLimiter {
            state: Mutex::new(Clocked {
                limits: ConnectionLimits::new(max_connections, max_per_five),
                last_reset: now,
                last_status: now,
            }),
            notify: Notify::new(),
            connected: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Clocked> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether we are connected to a network (the average only moves then).
    pub fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::Relaxed);
    }

    /// A copy of the counters, brought up to date.
    pub fn snapshot(&self) -> ConnectionLimits {
        let mut s = self.lock();
        s.tick(Instant::now(), self.connected.load(Ordering::Relaxed));
        s.limits.clone()
    }

    pub fn set_limits(&self, max_connections: u32, max_per_five: u32) {
        let mut s = self.lock();
        s.limits.max_connections = max_connections;
        s.limits.max_per_five = max_per_five;
        drop(s);
        self.notify.notify_waiters();
    }

    /// Whether `TooManySockets` holds now.
    pub fn too_many(&self, ignore_interval: bool) -> bool {
        let mut s = self.lock();
        s.tick(Instant::now(), self.connected.load(Ordering::Relaxed));
        s.limits.too_many(ignore_interval)
    }

    /// Open a connection if the limits allow it.
    pub fn try_open(self: &Arc<Self>) -> Option<Permit> {
        let mut s = self.lock();
        s.tick(Instant::now(), self.connected.load(Ordering::Relaxed));
        if s.limits.too_many(false) {
            return None;
        }
        s.limits.opened();
        Some(Permit {
            limiter: self.clone(),
        })
    }

    /// Open a connection whatever the limits say (it still counts).
    pub fn open_anyway(self: &Arc<Self>) -> Permit {
        let mut s = self.lock();
        s.tick(Instant::now(), self.connected.load(Ordering::Relaxed));
        s.limits.opened();
        Permit {
            limiter: self.clone(),
        }
    }

    /// Wait until the limits allow another connection (a slot closes or the
    /// five-second interval restarts).
    pub async fn admissible(&self) {
        loop {
            let notified = self.notify.notified();
            let wait = {
                let mut s = self.lock();
                let now = Instant::now();
                s.tick(now, self.connected.load(Ordering::Relaxed));
                if !s.limits.too_many(false) {
                    return;
                }
                (s.last_reset + INTERVAL).saturating_duration_since(now)
            };
            tokio::select! {
                _ = tokio::time::sleep(wait.max(Duration::from_millis(1))) => {}
                _ = notified => {}
            }
        }
    }

    /// Wait for, and take, a connection slot.
    pub async fn open(self: &Arc<Self>) -> Permit {
        loop {
            self.admissible().await;
            if let Some(p) = self.try_open() {
                return p;
            }
        }
    }
}

/// A TCP listener that honours the limits (`CListenSocket::OnAccept`).
#[derive(Debug)]
pub struct Listener {
    tcp: TcpListener,
    limiter: Arc<ConnectionLimiter>,
    /// `serverconnect->IsConnecting()`: accept past the limits.
    bypass: AtomicBool,
}

impl Listener {
    pub async fn bind(addr: SocketAddr, limiter: Arc<ConnectionLimiter>) -> std::io::Result<Self> {
        Ok(Listener {
            tcp: TcpListener::bind(addr).await?,
            limiter,
            bypass: AtomicBool::new(false),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    pub fn limiter(&self) -> &Arc<ConnectionLimiter> {
        &self.limiter
    }

    /// Accept past the limits while a server connection is being made.
    pub fn set_server_connecting(&self, connecting: bool) {
        self.bypass.store(connecting, Ordering::Relaxed);
        self.limiter.notify.notify_waiters();
    }

    /// The next connection, once the limits allow one.
    pub async fn accept(&self) -> std::io::Result<(TcpStream, SocketAddr, Permit)> {
        loop {
            if !self.bypass.load(Ordering::Relaxed) {
                // Leave it in the backlog until there is room, but look again
                // when the server connection starts.
                tokio::select! {
                    _ = self.limiter.admissible() => {}
                    _ = self.limiter.notify.notified() => continue,
                }
            }
            let (stream, addr) = self.tcp.accept().await?;
            return Ok((stream, addr, self.limiter.open_anyway()));
        }
    }
}
