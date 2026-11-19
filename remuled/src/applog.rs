// SPDX-License-Identifier: GPL-2.0-or-later
//! The log as External Connections read it (`CLogger`, `CLoggerAccess`,
//! `GetLog`, `GetServerLog`).
//!
//! Every `tracing` event at info level and above is kept, as the line
//! aMule's logfile replays over EC: a marker (`' '`, or `'!'` for what
//! aMule also puts in the status bar: warnings and errors here), the record
//! header (`2026-11-19T18:30:09.123+00:00 INFO  `) and the message. Each
//! connection reads what it has not seen yet with its own [`Cursor`].
//! Beside it, the server's messages (`server_msg`).

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Lines kept; older ones go, as a rotated logfile's would.
pub const MAX_LINES: usize = 10_000;

#[derive(Debug, Default)]
struct Inner {
    lines: VecDeque<String>,
    /// The number of the first line kept, counting from the last reset.
    first: u64,
    /// Bumped by a reset: every cursor starts over.
    generation: u64,
    server: String,
}

/// The daemon's log.
#[derive(Debug, Default)]
pub struct AppLog {
    inner: Mutex<Inner>,
}

/// Where one reader is (`CLoggerAccess`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    generation: u64,
    next: u64,
}

/// The process's log, which the `tracing` layer fills.
pub fn global() -> &'static AppLog {
    static LOG: OnceLock<AppLog> = OnceLock::new();
    LOG.get_or_init(AppLog::default)
}

/// `FormatLogPrefix` for a moment in UTC, to the millisecond.
pub fn header(unix_ms: u64, level: Level) -> String {
    let secs = unix_ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let name = match level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN ",
        Level::INFO => "INFO ",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}+00:00 {name} ",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        unix_ms % 1000
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl AppLog {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One record: a line per line of `message`, each with the header.
    pub fn push_at(&self, unix_ms: u64, level: Level, message: &str) {
        let marker = if level <= Level::WARN { '!' } else { ' ' };
        let head = header(unix_ms, level);
        let text = message.replace("\r\n", "\n").replace('\r', "\n");
        let text = text.trim_end();
        let mut inner = self.lock();
        let parts: Vec<&str> = if text.is_empty() {
            vec![""]
        } else {
            text.split('\n').collect()
        };
        for part in parts {
            inner.lines.push_back(format!("{marker}{head}{part}\n"));
            if inner.lines.len() > MAX_LINES {
                inner.lines.pop_front();
                inner.first += 1;
            }
        }
    }

    pub fn push(&self, level: Level, message: &str) {
        self.push_at(now_ms(), level, message);
    }

    /// A reader at the start.
    pub fn cursor(&self) -> Cursor {
        Cursor {
            generation: self.lock().generation,
            next: 0,
        }
    }

    /// `CLoggerAccess::GetString`, up to `max` times: the lines `cursor`
    /// has not seen (those dropped since are skipped).
    pub fn read(&self, cursor: &mut Cursor, max: usize) -> Vec<String> {
        let inner = self.lock();
        if cursor.generation != inner.generation {
            *cursor = Cursor {
                generation: inner.generation,
                next: 0,
            };
        }
        let from = cursor.next.max(inner.first);
        let skip = (from - inner.first) as usize;
        let out: Vec<String> = inner.lines.iter().skip(skip).take(max).cloned().collect();
        cursor.next = from + out.len() as u64;
        out
    }

    /// `GetLog(false)`: every line kept.
    pub fn text(&self) -> String {
        self.lock().lines.iter().map(String::as_str).collect()
    }

    /// `GetLog(true)`: the log started over, every reader with it.
    pub fn reset(&self) {
        {
            let mut inner = self.lock();
            inner.lines.clear();
            inner.first = 0;
            inner.generation += 1;
        }
        self.push(Level::INFO, "Log has been reset");
    }

    /// `AddServerMessageLine`: kept, and logged.
    pub fn server_message(&self, msg: &str) {
        self.lock().server.push_str(&format!("{msg}\n"));
        self.push(Level::INFO, &format!("ServerMessage: {msg}"));
    }

    /// `GetServerLog`, emptied when `reset`.
    pub fn server_text(&self, reset: bool) -> String {
        let mut inner = self.lock();
        if reset {
            std::mem::take(&mut inner.server)
        } else {
            inner.server.clone()
        }
    }
}

/// The `tracing` layer that fills [`global`].
pub struct EcLogLayer;

struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_owned();
        }
    }
}

impl<S: Subscriber> Layer<S> for EcLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        if level > Level::INFO {
            return;
        }
        let mut m = Message(String::new());
        event.record(&mut m);
        global().push(level, &m.0);
    }
}
