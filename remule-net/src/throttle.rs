// SPDX-License-Identifier: GPL-2.0-or-later
//! Global bandwidth throttling: token buckets shared by every connection
//! (`CDownloadBandwidthThrottler`, `UploadBandwidthThrottler`).
//!
//! **Download** (`RefillBudget` / `Reserve` / `Refund`): every tick
//! (`CORE_TIMER_PERIOD`, 300 ms in the daemon) the bucket gains
//! `rate × tick`, keeping what is left from the last tick but never more than
//! two ticks' worth; debt is forgiven. A read reserves up to what it wants,
//! gets what is there (maybe less), and gives back what it did not read.
//!
//! **Upload**: bytes are earned continuously. Control packets go before file
//! data; a sender with any budget left sends a whole fragment, which may put
//! the bucket into debt that the next sends wait out. Fragments are 1300
//! bytes, sent two at a time so they share an ACK, or 536 bytes below 6 KiB/s.
//!
//! A rate of 0 is unlimited, as aMule's `MaxDownload=0` / `MaxUpload=0`.
//!
//! The refill is computed on demand from the time elapsed, so no task has to
//! drive it; waiting is a sleep until the next refill.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// `CORE_TIMER_PERIOD` of amuled: the download refill tick.
pub const DOWNLOAD_TICK: Duration = Duration::from_millis(300);
/// How often upload budget is earned (aMule earns per millisecond of loop).
pub const UPLOAD_TICK: Duration = Duration::from_millis(10);

/// The upload fragment size (`minFragSize`) for a rate in bytes/s.
pub fn min_frag_size(rate: u64) -> usize {
    if rate != 0 && rate < 6 * 1024 {
        536
    } else {
        1300
    }
}

/// How much one upload send may take at once (`doubleSendSize`).
pub fn send_size(rate: u64) -> usize {
    if rate != 0 && rate < 6 * 1024 {
        536
    } else {
        2 * 1300
    }
}

/// Who is asking for upload budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Control packets (and UDP): served first.
    Control,
    /// File data (upload slots).
    Standard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Download,
    Upload,
}

#[derive(Debug)]
struct State {
    /// Bytes per second; 0 is unlimited.
    rate: u64,
    available: i64,
    last: Instant,
    control_waiting: usize,
}

/// One direction's bucket.
#[derive(Debug)]
pub struct RateLimiter {
    kind: Kind,
    tick: Duration,
    state: Mutex<State>,
    notify: Notify,
    /// Bytes granted and not refunded.
    used: AtomicU64,
}

impl RateLimiter {
    fn new(kind: Kind, tick: Duration, rate: u64) -> Self {
        RateLimiter {
            kind,
            tick,
            state: Mutex::new(State {
                rate,
                available: 0,
                last: Instant::now(),
                control_waiting: 0,
            }),
            notify: Notify::new(),
            used: AtomicU64::new(0),
        }
    }

    /// A download bucket of `rate` bytes/s.
    pub fn download(rate: u64) -> Self {
        RateLimiter::new(Kind::Download, DOWNLOAD_TICK, rate)
    }

    /// An upload bucket of `rate` bytes/s.
    pub fn upload(rate: u64) -> Self {
        RateLimiter::new(Kind::Upload, UPLOAD_TICK, rate)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding this lock leaves plain numbers behind; carry on.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The rate in bytes/s (0: unlimited).
    pub fn rate(&self) -> u64 {
        self.lock().rate
    }

    /// Change the rate (0: unlimited).
    pub fn set_rate(&self, rate: u64) {
        let now = Instant::now();
        let mut s = self.lock();
        self.refill(&mut s, now);
        if s.rate == 0 && rate != 0 {
            s.last = now;
            s.available = 0;
        }
        s.rate = rate;
        let cap = self.cap(rate);
        s.available = s.available.min(cap);
        drop(s);
        self.notify.notify_waiters();
    }

    /// Bytes granted so far, net of refunds.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    fn budget(&self, rate: u64) -> i64 {
        (rate as u128 * self.tick.as_millis() / 1000) as i64
    }

    /// The most the bucket holds: two ticks' worth, and at least one send
    /// for uploads.
    fn cap(&self, rate: u64) -> i64 {
        let two_ticks = 2 * self.budget(rate);
        match self.kind {
            Kind::Download => two_ticks,
            Kind::Upload => two_ticks.max(send_size(rate) as i64),
        }
    }

    fn refill(&self, s: &mut State, now: Instant) {
        let elapsed = now.saturating_duration_since(s.last);
        let ticks = (elapsed.as_nanos() / self.tick.as_nanos()) as u64;
        if ticks == 0 || s.rate == 0 {
            if s.rate == 0 {
                s.last = now;
            }
            return;
        }
        s.last += self.tick * ticks.min(u32::MAX as u64) as u32;
        if self.kind == Kind::Download && s.available < 0 {
            s.available = 0;
        }
        let gained = self.budget(s.rate).saturating_mul(ticks as i64);
        s.available = s.available.saturating_add(gained).min(self.cap(s.rate));
    }

    /// Ask for up to `want` bytes; waits until there are any. A download
    /// gets what is there, at most `want`; an upload gets all of `want`
    /// (send at most [`send_size`] at a time).
    pub async fn acquire(&self, want: usize, priority: Priority) -> usize {
        if want == 0 {
            return 0;
        }
        let mut guard = ControlGuard {
            limiter: self,
            registered: false,
        };
        loop {
            let notified = self.notify.notified();
            let now = Instant::now();
            let wait = {
                let mut s = self.lock();
                self.refill(&mut s, now);
                if s.rate == 0 {
                    self.used.fetch_add(want as u64, Ordering::Relaxed);
                    return want;
                }
                let blocked = priority == Priority::Standard && s.control_waiting > 0;
                if !blocked && s.available > 0 {
                    let grant = match self.kind {
                        Kind::Download => want.min(s.available as usize),
                        Kind::Upload => want,
                    };
                    s.available -= grant as i64;
                    guard.release(&mut s);
                    self.used.fetch_add(grant as u64, Ordering::Relaxed);
                    return grant;
                }
                if priority == Priority::Control && !guard.registered {
                    s.control_waiting += 1;
                    guard.registered = true;
                }
                // Until the refill that brings the bucket above zero.
                let missing = (1 - s.available).max(1) as u128;
                let per_tick = self.budget(s.rate).max(1) as u128;
                let ticks = missing.div_ceil(per_tick).max(1) as u32;
                (s.last + self.tick * ticks).saturating_duration_since(now)
            };
            tokio::select! {
                _ = tokio::time::sleep(wait.max(Duration::from_millis(1))) => {}
                _ = notified => {}
            }
        }
    }

    /// Give back reserved bytes that were not used (`Refund`).
    pub fn refund(&self, n: usize) {
        if n == 0 {
            return;
        }
        let mut s = self.lock();
        if s.rate != 0 {
            s.available = s.available.saturating_add(n as i64);
        }
        drop(s);
        self.used.fetch_sub(n as u64, Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}

/// Keeps `control_waiting` right when a control acquire is cancelled.
struct ControlGuard<'a> {
    limiter: &'a RateLimiter,
    registered: bool,
}

impl ControlGuard<'_> {
    fn release(&mut self, s: &mut State) {
        if self.registered {
            s.control_waiting -= 1;
            self.registered = false;
            self.limiter.notify.notify_waiters();
        }
    }
}

impl Drop for ControlGuard<'_> {
    fn drop(&mut self) {
        if self.registered {
            let mut s = self.limiter.lock();
            s.control_waiting -= 1;
            drop(s);
            self.limiter.notify.notify_waiters();
        }
    }
}

/// Both directions, shared by every connection (`Arc<Bandwidth>`).
#[derive(Debug)]
pub struct Bandwidth {
    pub upload: RateLimiter,
    pub download: RateLimiter,
}

impl Bandwidth {
    /// Limits in KiB/s, as amule.conf's `MaxUpload` / `MaxDownload` (0: unlimited).
    pub fn new(max_upload_kbps: u32, max_download_kbps: u32) -> Self {
        Bandwidth {
            upload: RateLimiter::upload(max_upload_kbps as u64 * 1024),
            download: RateLimiter::download(max_download_kbps as u64 * 1024),
        }
    }

    pub fn unlimited() -> Self {
        Bandwidth::new(0, 0)
    }

    /// Change the limits, in KiB/s.
    pub fn set_limits(&self, max_upload_kbps: u32, max_download_kbps: u32) {
        self.upload.set_rate(max_upload_kbps as u64 * 1024);
        self.download.set_rate(max_download_kbps as u64 * 1024);
    }
}
