// SPDX-License-Identifier: GPL-2.0-or-later
//! Checking for a newer release (`CamuleApp::StartVersionCheck`,
//! `CheckNewVersion`; `CompareLatestReleaseVersion`, OtherFunctions.cpp).
//!
//! With `/eMule/NewVersionCheck` on, the latest release is asked of GitHub
//! at start, again once a day, and when an external connection asks
//! (`EC_OP_VERSION_CHECK`, amuleapi's `POST /version/check`). Attempts are
//! at least a minute apart: one asked for sooner is refused, as aMule
//! throttles it against GitHub's unauthenticated rate limit. The outcome is
//! logged and relayed with the statistics (`EC_TAG_GENERAL_VERSION_CHECK_*`).
//!
//! remuled compares its own version with remule's releases, not aMule's.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tracing::{debug, info, warn};

/// Where the latest release is described.
pub const LATEST_URL: &str = "https://api.github.com/repos/siscof/Remule/releases/latest";
/// Where it can be downloaded.
pub const RELEASES_URL: &str = "https://github.com/siscof/Remule/releases/latest";
/// `kMinInterval`: attempts at least this far apart.
pub const MIN_INTERVAL: u64 = 60;
/// The periodic check: once a day.
pub const PERIOD: u64 = 24 * 60 * 60;

/// A finished check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// `MAJOR.MINOR.UPDATE`.
    pub latest: String,
    /// A newer release exists.
    pub outdated: bool,
    /// When it finished, Unix seconds.
    pub at: u64,
}

/// What the daemon knows of its checks.
#[derive(Debug, Default)]
pub struct VersionCheck {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// When the last one started, 0 for never.
    last_attempt: u64,
    result: Option<Outcome>,
}

/// The daemon's one.
pub fn global() -> &'static VersionCheck {
    static G: OnceLock<VersionCheck> = OnceLock::new();
    G.get_or_init(VersionCheck::default)
}

impl VersionCheck {
    /// Whether an attempt may start at `now`; if so it is stamped.
    pub fn try_start(&self, now: u64) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.last_attempt != 0 && now.saturating_sub(s.last_attempt) < MIN_INTERVAL {
            return false;
        }
        s.last_attempt = now;
        true
    }

    /// Whether the periodic check is due at `now`: never tried, or a day
    /// since.
    pub fn due(&self, now: u64) -> bool {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.last_attempt == 0 || now.saturating_sub(s.last_attempt) >= PERIOD
    }

    /// The last check that finished, if any.
    pub fn result(&self) -> Option<Outcome> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .result
            .clone()
    }

    /// `CheckNewVersion`: what GitHub answered, compared with `current`.
    pub fn finished(&self, body: Result<Vec<u8>, String>, current: &str, now: u64) {
        let body = match body {
            Ok(b) => b,
            Err(e) => {
                debug!("version check: {e}");
                warn!("Failed to download the version check file");
                return;
            }
        };
        let Some((latest, outdated)) = compare_latest(&String::from_utf8_lossy(&body), current)
        else {
            warn!("Corrupted version check file");
            return;
        };
        debug!("Running: {current}, Version check: {latest}");
        if outdated {
            warn!("You are using an outdated version of remuled!");
            info!("Your remuled version is {current} and the latest version is {latest}");
            info!("The latest version can always be found at {RELEASES_URL}");
        }
        self.state.lock().unwrap_or_else(|e| e.into_inner()).result = Some(Outcome {
            latest,
            outdated,
            at: now,
        });
    }

    /// `StartVersionCheck`: false when throttled; otherwise the fetch runs
    /// on its own and its outcome is recorded.
    pub fn start(&'static self) -> bool {
        if !self.try_start(crate::ec::unix_now()) {
            return false;
        }
        tokio::spawn(async move {
            let body = crate::http::fetch(LATEST_URL).await;
            self.finished(body, env!("CARGO_PKG_VERSION"), crate::ec::unix_now());
        });
        true
    }
}

/// The periodic check, for as long as the daemon runs: at once, then a
/// day after the last attempt, whatever started it; each time only while
/// `enabled` says the preference is on (aMule's timer reads it each time,
/// so turning it on or off over EC takes effect without a restart).
pub async fn run_daily(check: &'static VersionCheck, enabled: impl Fn() -> bool) {
    loop {
        if enabled() && check.due(crate::ec::unix_now()) {
            check.start();
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// `MAJOR.MINOR.UPDATE` from a version string: an optional leading `v`,
/// any `-`/`+` suffix dropped, missing fields 0.
fn parse_version(v: &str) -> Option<[u64; 3]> {
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    let v = v.split(['-', '+']).next().unwrap_or_default();
    if v.is_empty() {
        return None;
    }
    let mut out = [0; 3];
    for (i, f) in v.split('.').take(3).enumerate() {
        out[i] = f.parse().ok()?;
    }
    Some(out)
}

/// `CompareLatestReleaseVersion`: the `tag_name` of GitHub's
/// `/releases/latest` answer as `MAJOR.MINOR.UPDATE`, and whether it is
/// newer than `current`. `None` when there is no tag or it is not a version.
pub fn compare_latest(json: &str, current: &str) -> Option<(String, bool)> {
    // The one well-known field, as aMule's regex finds it.
    let at = json.find("\"tag_name\"")? + "\"tag_name\"".len();
    let rest = json[at..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let tag = &rest[..rest.find('"')?];
    let latest = parse_version(tag)?;
    let mine = parse_version(current).unwrap_or_default();
    Some((
        format!("{}.{}.{}", latest[0], latest[1], latest[2]),
        mine < latest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_latest_tag_against_ours() {
        let json = |tag: &str| {
            format!("{{\"url\": \"x\",\n  \"tag_name\" :  \"{tag}\", \"name\": \"y\"}}")
        };
        assert_eq!(
            compare_latest(&json("0.2.0"), "0.1.0"),
            Some(("0.2.0".into(), true))
        );
        assert_eq!(
            compare_latest(&json("v0.1.0"), "0.1.0"),
            Some(("0.1.0".into(), false))
        );
        assert_eq!(
            compare_latest(&json("0.1"), "0.1.0"),
            Some(("0.1.0".into(), false))
        );
        assert_eq!(
            compare_latest(&json("1.0.0-rc1"), "0.9.9"),
            Some(("1.0.0".into(), true))
        );
        assert_eq!(
            compare_latest(&json("0.0.9"), "0.1.0"),
            Some(("0.0.9".into(), false))
        );
        assert_eq!(compare_latest(&json(""), "0.1.0"), None);
        assert_eq!(compare_latest(&json("latest"), "0.1.0"), None);
        assert_eq!(
            compare_latest("{\"message\": \"Not Found\"}", "0.1.0"),
            None
        );
    }

    #[test]
    fn attempts_are_a_minute_apart() {
        let c = VersionCheck::default();
        assert!(c.due(1000));
        assert!(c.try_start(1000));
        assert!(!c.try_start(1000));
        assert!(!c.try_start(1059));
        assert!(!c.due(1059));
        assert!(c.try_start(1060));
        assert!(!c.due(1060 + PERIOD - 1));
        assert!(c.due(1060 + PERIOD));
    }

    #[test]
    fn a_finished_check_is_kept_and_a_failed_one_is_not() {
        let c = VersionCheck::default();
        c.finished(Err("offline".into()), "0.1.0", 5);
        assert_eq!(c.result(), None);
        c.finished(Ok(b"garbage".to_vec()), "0.1.0", 6);
        assert_eq!(c.result(), None);
        c.finished(Ok(br#"{"tag_name":"0.3.1"}"#.to_vec()), "0.1.0", 7);
        assert_eq!(
            c.result(),
            Some(Outcome {
                latest: "0.3.1".into(),
                outdated: true,
                at: 7
            })
        );
    }
}
