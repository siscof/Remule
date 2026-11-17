// SPDX-License-Identifier: GPL-2.0-or-later
//! The transfer statistics of a running client, without IO: the session's
//! bytes, the cumulative totals of every session (kept in
//! `statistics.dat`), and when to save those.
//!
//! Port of the counting in `CStatistics` (Statistics.h/.cpp:
//! `AddReceivedBytes`, `AddSentBytes`, `GetTotalSentBytes`, `Save` as
//! `CamuleApp::OnCoreTimer` calls it) and of the items of the statistics
//! tree made from them (`CStatTreeItemUlDlCounter`, `CStatTreeItemRatio`,
//! `CStatTreeItemAverageSpeed`, the uptime and "time since first transfer"
//! timers).
//!
//! As in aMule, the totals grow with the session: every byte added to the
//! session is added to them, and they are written out once a minute when
//! something changed, and on shutdown. The session ratio is shown with the
//! total one after it; aMule adds the session's bytes to the totals once
//! more there (they already hold them), this does not.

use std::time::{Duration, Instant};

pub use ed2k_formats::statistics_dat::Totals;

/// How often the totals are saved when they changed (`OnCoreTimer`).
pub const SAVE_EVERY: Duration = Duration::from_secs(60);

/// A session's statistics.
#[derive(Debug, Clone)]
pub struct Statistics {
    start: Instant,
    /// The totals loaded at start.
    before: Totals,
    session: Totals,
    first_transfer: Option<Instant>,
    /// `s_statsNeedSave`
    needs_save: bool,
    next_save: Instant,
}

impl Statistics {
    /// A session starting at `now`, with the totals of the sessions before.
    pub fn new(before: Totals, now: Instant) -> Self {
        Statistics {
            start: now,
            before,
            session: Totals::default(),
            first_transfer: None,
            needs_save: false,
            next_save: now + SAVE_EVERY,
        }
    }

    /// The session's file data so far, as the running client counts it
    /// (counters that only grow): what came since the last call is added
    /// to the totals (`AddReceivedBytes`, `AddSentBytes`).
    pub fn update(&mut self, session: Totals, now: Instant) {
        let sent = session.sent.max(self.session.sent);
        let received = session.received.max(self.session.received);
        if (sent, received) != (self.session.sent, self.session.received) {
            self.session = Totals { sent, received };
            self.needs_save = true;
            self.first_transfer.get_or_insert(now);
        }
    }

    /// This session's bytes.
    pub fn session(&self) -> Totals {
        self.session
    }

    /// Every session's bytes, this one's included (`GetTotalSentBytes`,
    /// `GetTotalReceivedBytes`).
    pub fn totals(&self) -> Totals {
        Totals {
            sent: self.before.sent.saturating_add(self.session.sent),
            received: self.before.received.saturating_add(self.session.received),
        }
    }

    /// Since the session started ("Uptime").
    pub fn uptime(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.start)
    }

    /// Since the first byte went either way ("Time Since First Transfer",
    /// hidden while there is none).
    pub fn since_first_transfer(&self, now: Instant) -> Option<Duration> {
        self.first_transfer
            .map(|t| now.saturating_duration_since(t))
    }

    /// The session's average download and upload rates in bytes per second:
    /// its bytes over its whole seconds of uptime, 0 in the first second
    /// (`CStatTreeItemAverageSpeed`).
    pub fn average_rates(&self, now: Instant) -> (u64, u64) {
        match self.uptime(now).as_secs() {
            0 => (0, 0),
            s => (self.session.received / s, self.session.sent / s),
        }
    }

    /// "Session UL:DL Ratio (Total)": the session's ratio, then the total
    /// one in brackets; `None` for either while nothing went one of the
    /// ways ("Not available").
    pub fn ratios(&self) -> (Option<String>, Option<String>) {
        (ratio(self.session), ratio(self.totals()))
    }

    /// The totals to save now, once a minute when they changed. After
    /// writing them, call [`Statistics::saved`]; when that failed, they are
    /// due again on the next minute.
    pub fn save_due(&mut self, now: Instant) -> Option<Totals> {
        if now < self.next_save {
            return None;
        }
        self.next_save = now + SAVE_EVERY;
        self.unsaved()
    }

    /// The totals, if they changed since they were last saved (on
    /// shutdown, `CStatistics::Save`).
    pub fn unsaved(&self) -> Option<Totals> {
        self.needs_save.then(|| self.totals())
    }

    /// The totals were written.
    pub fn saved(&mut self) {
        self.needs_save = false;
    }
}

/// `CStatTreeItemRatio::GetString`, uploaded to downloaded: the larger
/// over the smaller to two places, as `x : 1` or `1 : x`.
pub fn ratio(t: Totals) -> Option<String> {
    let (up, down) = (t.sent as f64, t.received as f64);
    if up <= 0.0 || down <= 0.0 {
        return None;
    }
    Some(if down < up {
        format!("{:.2} : 1", up / down)
    } else {
        format!("1 : {:.2}", down / up)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(sent: u64, received: u64) -> Totals {
        Totals { sent, received }
    }

    #[test]
    fn the_session_adds_to_the_totals() {
        let t0 = Instant::now();
        let mut s = Statistics::new(t(1000, 50), t0);
        assert_eq!(s.totals(), t(1000, 50));
        assert_eq!(s.unsaved(), None);
        assert_eq!(s.since_first_transfer(t0 + Duration::from_secs(9)), None);
        s.update(t(0, 0), t0 + Duration::from_secs(1));
        assert_eq!(s.unsaved(), None, "nothing moved");
        s.update(t(0, 300), t0 + Duration::from_secs(2));
        s.update(t(40, 300), t0 + Duration::from_secs(5));
        assert_eq!(s.session(), t(40, 300));
        assert_eq!(s.totals(), t(1040, 350));
        assert_eq!(s.unsaved(), Some(t(1040, 350)));
        assert_eq!(
            s.since_first_transfer(t0 + Duration::from_secs(10)),
            Some(Duration::from_secs(8))
        );
        // The counters only grow: a smaller value adds nothing.
        s.update(t(10, 10), t0 + Duration::from_secs(6));
        assert_eq!(s.session(), t(40, 300));
        // Over whole seconds of uptime, as aMule's timer counts them.
        assert_eq!(s.uptime(t0 + Duration::from_secs(10)).as_secs(), 10);
        assert_eq!(s.average_rates(t0 + Duration::from_secs(10)), (30, 4));
        assert_eq!(s.average_rates(t0 + Duration::from_millis(999)), (0, 0));
        // No overflow from a damaged file.
        let mut big = Statistics::new(t(u64::MAX, 0), t0);
        big.update(t(5, 0), t0);
        assert_eq!(big.totals().sent, u64::MAX);
    }

    #[test]
    fn saved_once_a_minute_when_changed() {
        let t0 = Instant::now();
        let mut s = Statistics::new(t(0, 0), t0);
        let at = |secs| t0 + Duration::from_secs(secs);
        assert_eq!(s.save_due(at(59)), None);
        // A minute with nothing moved: nothing to write.
        assert_eq!(s.save_due(at(60)), None);
        s.update(t(5, 0), at(61));
        assert_eq!(s.save_due(at(62)), None, "not before the next minute");
        assert_eq!(s.save_due(at(120)), Some(t(5, 0)));
        // Writing failed: due again a minute later, not at once.
        assert_eq!(s.save_due(at(121)), None);
        assert_eq!(s.save_due(at(180)), Some(t(5, 0)));
        s.saved();
        assert_eq!(s.save_due(at(240)), None);
        assert_eq!(s.unsaved(), None);
        s.update(t(5, 7), at(250));
        assert_eq!(s.unsaved(), Some(t(5, 7)));
        assert_eq!(s.save_due(at(300)), Some(t(5, 7)));
    }

    #[test]
    fn ratios_as_amule_shows_them() {
        assert_eq!(ratio(t(0, 0)), None);
        assert_eq!(ratio(t(10, 0)), None);
        assert_eq!(ratio(t(0, 10)), None);
        assert_eq!(ratio(t(300, 100)).as_deref(), Some("3.00 : 1"));
        assert_eq!(ratio(t(100, 250)).as_deref(), Some("1 : 2.50"));
        assert_eq!(ratio(t(7, 7)).as_deref(), Some("1 : 1.00"));
        let t0 = Instant::now();
        let mut s = Statistics::new(t(100, 900), t0);
        assert_eq!(s.ratios(), (None, Some("1 : 9.00".to_owned())));
        s.update(t(100, 100), t0);
        // The total holds the session once.
        assert_eq!(
            s.ratios(),
            (Some("1 : 1.00".to_owned()), Some("1 : 5.00".to_owned()))
        );
    }
}
