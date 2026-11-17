// SPDX-License-Identifier: GPL-2.0-or-later
//! The transfer statistics of a running client on disk and in the log:
//! the totals of earlier sessions read from `statistics.dat` in the config
//! directory at start, written back there once a minute when they changed
//! and on shutdown (`CStatistics::Load`, `CStatistics::Save`); the counting
//! itself is [`remule_core::statistics`].
//!
//! aMule keeps these totals in `statistics.dat` only: `amule.conf` is
//! neither read nor written for them.

use std::path::Path;
use std::time::{Duration, Instant};

use ed2k_formats::statistics_dat::{self, FILE_NAME};
use remule_core::statistics::{Statistics, Totals};
use tracing::warn;

use crate::client::human;

/// The totals of earlier sessions in `dir`, and what went wrong reading
/// them: none when there is no file yet; what was read before the end of a
/// file cut short, as aMule keeps it.
pub fn load(dir: &Path) -> (Totals, Option<String>) {
    let path = dir.join(FILE_NAME);
    match std::fs::read(&path) {
        Ok(b) => match statistics_dat::read(&b) {
            Ok(t) => (t, None),
            Err(e) => (e.kept, Some(format!("{}: {e}", path.display()))),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Totals::default(), None),
        Err(e) => (Totals::default(), Some(format!("{}: {e}", path.display()))),
    }
}

/// Write `t` to `statistics.dat` in `dir`, through a temporary file.
pub fn save(dir: &Path, t: &Totals) -> Result<(), String> {
    let path = dir.join(FILE_NAME);
    let tmp = dir.join(format!("{FILE_NAME}.new"));
    std::fs::write(&tmp, statistics_dat::write(t))
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Save `t` and tell `s` so; on failure, warn and leave them due for the
/// next try, as aMule does.
pub fn save_logged(dir: &Path, s: &mut Statistics, t: &Totals) {
    match save(dir, t) {
        Ok(()) => s.saved(),
        Err(e) => warn!("saving statistics: {e}"),
    }
}

/// `1h 02m 03s`, `4m 05s`, `6s`.
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    let (h, m, s) = (s / 3600, s / 60 % 60, s % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m {s:02}s"),
        _ => format!("{h}h {m:02}m {s:02}s"),
    }
}

/// The transfer line of the periodic status: each way, the session then
/// the total (aMule's "Session (Total)"), and the UL:DL ratios.
pub fn line(s: &Statistics) -> String {
    let (now, all) = (s.session(), s.totals());
    let (ratio, total_ratio) = s.ratios();
    let na = || "n/a".to_owned();
    format!(
        "downloaded {} ({}), uploaded {} ({}), UL:DL {} ({})",
        human(now.received),
        human(all.received),
        human(now.sent),
        human(all.sent),
        ratio.unwrap_or_else(na),
        total_ratio.unwrap_or_else(na),
    )
}

/// The session's statistics on shutdown: [`line()`], then uptime, average
/// rates and the time since the first transfer.
pub fn summary(s: &Statistics, now: Instant) -> String {
    let (down, up) = s.average_rates(now);
    let mut out = format!(
        "{}; uptime {}, average {}/s down, {}/s up",
        line(s),
        duration(s.uptime(now)),
        human(down),
        human(up)
    );
    if let Some(d) = s.since_first_transfer(now) {
        out += &format!(", first transfer {} ago", duration(d));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_and_saved_in_the_config_directory() {
        let d = std::env::temp_dir().join(format!("remuled-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // None yet: zeros, nothing to say.
        assert_eq!(load(&d), (Totals::default(), None));
        let t = Totals {
            sent: 123_456_789_012,
            received: 42,
        };
        save(&d, &t).unwrap();
        assert_eq!(load(&d), (t, None));
        assert_eq!(std::fs::read(d.join(FILE_NAME)).unwrap().len(), 17);
        assert!(!d.join("statistics.dat.new").exists());
        // Cut short: what was read, and a note.
        std::fs::write(d.join(FILE_NAME), &statistics_dat::write(&t)[..12]).unwrap();
        let (kept, note) = load(&d);
        assert_eq!(
            kept,
            Totals {
                sent: t.sent,
                received: 0
            }
        );
        assert!(note.unwrap().contains("cut short"));
        // Saving marks the statistics saved; a failure leaves them due.
        let now = Instant::now();
        let mut s = Statistics::new(Totals::default(), now);
        s.update(t, now);
        save_logged(&d.join("missing"), &mut s, &t);
        assert_eq!(s.unsaved(), Some(t));
        save_logged(&d, &mut s, &t);
        assert_eq!(s.unsaved(), None);
        assert_eq!(load(&d), (t, None));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn durations_and_lines() {
        assert_eq!(duration(Duration::from_secs(6)), "6s");
        assert_eq!(duration(Duration::from_secs(245)), "4m 05s");
        assert_eq!(duration(Duration::from_secs(3723)), "1h 02m 03s");
        assert_eq!(duration(Duration::from_secs(90_000)), "25h 00m 00s");
        let t0 = Instant::now();
        let mut s = Statistics::new(
            Totals {
                sent: 2048,
                received: 1024,
            },
            t0,
        );
        assert_eq!(
            line(&s),
            "downloaded 0 B (1.0 KiB), uploaded 0 B (2.0 KiB), UL:DL n/a (2.00 : 1)"
        );
        s.update(
            Totals {
                sent: 0,
                received: 3072,
            },
            t0 + Duration::from_secs(1),
        );
        assert_eq!(
            summary(&s, t0 + Duration::from_secs(3)),
            "downloaded 3.0 KiB (4.0 KiB), uploaded 0 B (2.0 KiB), UL:DL n/a (1 : 2.00); \
             uptime 3s, average 1.0 KiB/s down, 0 B/s up, first transfer 2s ago"
        );
    }
}
