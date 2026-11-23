// SPDX-License-Identifier: GPL-2.0-or-later
//! Whether others can reach our UDP port (`CUDPFirewallTester`,
//! `CUDPVerificationExpiry`, the external port of `CPrefs`), without IO.
//!
//! A lookup for a random target turns up nodes that do not know us yet;
//! two of them in turn are asked over TCP (`OP_FWCHECKUDPREQ`, the
//! application's part) to send a `KADEMLIA2_FIREWALLUDP` to our ports. One
//! that arrives means open; two tests that end without one, firewalled; no
//! answer at all for six minutes, firewalled too. The answer is verified
//! until two rounds in a row end without a result, or it gets older than
//! two hours and six minutes; the check runs again every hour.
//!
//! Before testing, the external port is found: nodes are pinged and the
//! port in their pongs is taken once two of three agree.

use std::collections::VecDeque;

use crate::contact::Contact;

/// `UDP_FIREWALLTEST_CLIENTSTOASK`
pub const CLIENTS_TO_ASK: u8 = 2;
/// `kRoundTimeoutMs`: seconds.
pub const ROUND_TIMEOUT: u64 = 6 * 60;
/// `kFailedRoundsToExpire`
pub const FAILED_ROUNDS_TO_EXPIRE: u32 = 2;
/// `kRecheckIntervalMs`: seconds.
pub const RECHECK_INTERVAL: u64 = 60 * 60;
/// `kMaxVerificationAgeMs`: seconds.
pub const MAX_VERIFICATION_AGE: u64 =
    FAILED_ROUNDS_TO_EXPIRE as u64 * RECHECK_INTERVAL + ROUND_TIMEOUT;
/// `EXTERNAL_PORT_ASKIPS`
pub const EXTERNAL_PORT_ASK_IPS: usize = 3;

/// `CUDPVerificationExpiry`
#[derive(Debug, Clone, Default)]
struct Expiry {
    started_at: u64,
    verified_at: u64,
    has_result: bool,
    failed_rounds: u32,
    running: bool,
    counted: bool,
}

impl Expiry {
    fn start(&mut self, now: u64) {
        self.started_at = now;
        self.running = true;
        self.counted = false;
    }

    fn should_expire(&mut self, now: u64) -> bool {
        if self.running
            && !self.counted
            && now >= self.started_at
            && now - self.started_at > ROUND_TIMEOUT
        {
            self.counted = true;
            if self.failed_rounds < FAILED_ROUNDS_TO_EXPIRE {
                self.failed_rounds += 1;
            }
        }
        self.failed_rounds >= FAILED_ROUNDS_TO_EXPIRE
            || (self.has_result
                && now >= self.verified_at
                && now - self.verified_at >= MAX_VERIFICATION_AGE)
    }

    fn record_result(&mut self, now: u64) {
        self.running = false;
        self.failed_rounds = 0;
        self.verified_at = now;
        self.has_result = true;
    }
}

#[derive(Debug, Clone)]
struct Used {
    ip: u32,
    answered: bool,
    /// Retired entries stay, so their IPs are not asked again.
    current_round: bool,
}

/// The external port (`CPrefs::SetExternKadPort`, `FindExternKadPort`).
#[derive(Debug, Clone, Default)]
pub struct ExternalPort {
    ips: Vec<u32>,
    ports: Vec<u16>,
    port: Option<u16>,
}

impl ExternalPort {
    /// `FindExternKadPort(reset)`: still looking? (`reset` starts over.)
    pub fn finding(&mut self, reset: bool) -> bool {
        if reset {
            self.ips.clear();
            self.ports.clear();
        }
        self.ips.len() < EXTERNAL_PORT_ASK_IPS
    }

    /// `SetExternKadPort`: a port a node saw us at (`KADEMLIA2_PONG`); two
    /// alike out of three IPs settle it.
    pub fn vote(&mut self, port: u16, from_ip: u32) {
        if !self.finding(false) || self.ips.contains(&from_ip) {
            return;
        }
        self.ips.push(from_ip);
        if self.ports.contains(&port) {
            self.port = Some(port);
            while self.ips.len() < EXTERNAL_PORT_ASK_IPS {
                self.ips.push(0);
            }
            return;
        }
        self.ports.push(port);
    }

    /// `GetExternalKadPort` (none while unknown or unreliable).
    pub fn get(&self) -> Option<u16> {
        self.port
    }
}

/// `CUDPFirewallTester`
#[derive(Debug, Clone, Default)]
pub struct UdpFirewallTester {
    expiry: Expiry,
    firewalled: bool,
    last_state: bool,
    verified: bool,
    node_search_started: bool,
    timed_out: bool,
    running: u8,
    finished: u8,
    test_start: Option<u64>,
    last_succeeded: u64,
    possible: VecDeque<Contact>,
    used: Vec<Used>,
    /// The external port answered on, when it was not the internal one
    /// (`m_useExternKadPort`).
    pub use_external_port: bool,
}

impl UdpFirewallTester {
    /// `IsFWCheckUDPRunning`
    pub fn is_running(&self) -> bool {
        self.finished < CLIENTS_TO_ASK
    }

    fn clients_needed(&self) -> bool {
        self.running + self.finished < CLIENTS_TO_ASK
    }

    fn check_expiry(&mut self, now: u64) {
        if self.expiry.should_expire(now) && self.verified {
            self.verified = false;
        }
    }

    /// The answer as it stands (firewalled, verified), without the timers.
    pub fn peek(&self) -> (bool, bool) {
        (
            self.firewalled || (self.timed_out && self.is_running()),
            self.verified,
        )
    }

    /// `IsVerified`: there is an answer, fresh enough.
    pub fn is_verified(&mut self, now: u64) -> bool {
        self.check_expiry(now);
        self.verified
    }

    /// `IsFirewalledUDP`: open until a test says otherwise; while testing,
    /// the last answer when `last_state_if_testing`. With the TCP check
    /// saying firewalled and no answer for six minutes: firewalled.
    pub fn is_firewalled(
        &mut self,
        last_state_if_testing: bool,
        tcp_firewalled: bool,
        now: u64,
    ) -> bool {
        self.check_expiry(now);
        if !self.timed_out && self.is_running() {
            if !self.firewalled
                && tcp_firewalled
                && self
                    .test_start
                    .is_some_and(|t| now.saturating_sub(t) > ROUND_TIMEOUT)
                && !self.verified
            {
                self.timed_out = true;
            }
        } else if self.timed_out && self.is_running() {
            return true;
        }
        if last_state_if_testing && self.is_running() {
            self.last_state
        } else {
            self.firewalled
        }
    }

    /// `Connected`: Kad is up; the first round starts (a node lookup for
    /// test contacts: true when one should start now).
    pub fn connected(&mut self, now: u64) -> bool {
        if !self.node_search_started && self.is_running() {
            self.node_search_started = true;
            self.test_start = Some(now);
            self.expiry.start(now);
            self.timed_out = false;
            return true;
        }
        false
    }

    /// `ReCheckFirewallUDP`: a new round (the hourly recheck). True: start
    /// a node lookup for test contacts, and look for the external port again.
    pub fn recheck(&mut self, set_unverified: bool, now: u64) -> bool {
        self.check_expiry(now);
        for u in &mut self.used {
            u.current_round = false;
        }
        if set_unverified {
            self.expiry = Expiry::default();
        }
        self.expiry.start(now);
        self.running = 0;
        self.finished = 0;
        self.test_start = Some(now);
        self.timed_out = false;
        self.last_state = self.firewalled;
        self.verified = self.verified && !set_unverified;
        self.node_search_started = true;
        true
    }

    /// `AddPossibleTestContact`: a node the lookup found.
    pub fn add_possible(&mut self, c: Contact) {
        if self.is_running() {
            self.possible.push_front(c);
        }
    }

    /// `QueryNextClient`: the next node to ask, once the external port is
    /// settled. Not one of ours (`ours`), not one asked before, not one in
    /// our routing table (`known`): its answer would prove nothing.
    pub fn next_client(
        &mut self,
        external_port_known: bool,
        ours: impl Fn(&Contact) -> bool,
        known: impl Fn(u32) -> bool,
    ) -> Option<Contact> {
        if !self.is_running() || !self.clients_needed() || !external_port_known {
            return None;
        }
        while let Some(c) = self.possible.pop_front() {
            if c.version <= 5 || ours(&c) {
                continue;
            }
            if self.used.iter().any(|u| u.ip == c.ip) || known(c.ip) {
                continue;
            }
            self.used.insert(
                0,
                Used {
                    ip: c.ip,
                    answered: false,
                    current_round: true,
                },
            );
            self.running += 1;
            return Some(c);
        }
        None
    }

    /// `SetUDPFWCheckResult`: a test from `from_ip` ended. `succeeded`: its
    /// `KADEMLIA2_FIREWALLUDP` came, on `incoming_port`. `cancelled`: it
    /// proved nothing either way. True when the answer changed.
    pub fn result(
        &mut self,
        succeeded: bool,
        cancelled: bool,
        from_ip: u32,
        incoming_port: u16,
        internal_port: u16,
        now: u64,
    ) -> bool {
        let Some(u) = self
            .used
            .iter_mut()
            .find(|u| u.ip == from_ip && u.current_round)
        else {
            return false;
        };
        if u.answered {
            return false;
        }
        u.answered = true;
        if !self.is_running() || self.running == 0 {
            return false;
        }
        self.running -= 1;
        if cancelled {
            return false;
        }
        self.finished += 1;
        let was = (self.firewalled, self.verified);
        if succeeded {
            // One open answer is enough: no more tests this round.
            self.last_succeeded = now;
            self.test_start = None;
            self.firewalled = false;
            self.verified = true;
            self.expiry.record_result(now);
            self.timed_out = false;
            self.finished = CLIENTS_TO_ASK;
            self.running = 0;
            self.possible.clear();
            self.use_external_port = incoming_port != internal_port;
        } else if self.finished >= CLIENTS_TO_ASK {
            self.test_start = None;
            self.firewalled = true;
            self.verified = true;
            self.expiry.record_result(now);
            self.timed_out = false;
            self.possible.clear();
        }
        was != (self.firewalled, self.verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::UdpKey;
    use ed2k_types::UInt128;

    fn contact(n: u8, version: u8) -> Contact {
        let mut c = Contact::new(
            UInt128::new(u128::from(n)),
            u32::from(std::net::Ipv4Addr::new(20, 0, 0, n)),
            4672,
            4662,
            version,
            UdpKey::default(),
            true,
            0,
        );
        c.version = version;
        c
    }

    fn ip(n: u8) -> u32 {
        u32::from(std::net::Ipv4Addr::new(20, 0, 0, n))
    }

    #[test]
    fn the_external_port_takes_two_of_three() {
        let mut e = ExternalPort::default();
        assert!(e.finding(false));
        e.vote(5000, ip(1));
        e.vote(5000, ip(1)); // the same IP counts once
        assert_eq!(e.get(), None);
        e.vote(6000, ip(2));
        assert_eq!(e.get(), None);
        e.vote(5000, ip(3));
        assert_eq!(e.get(), Some(5000));
        assert!(!e.finding(false));
        // Three disagreeing: done, unknown.
        let mut e = ExternalPort::default();
        for (p, n) in [(1, 1), (2, 2), (3, 3)] {
            e.vote(p, ip(n));
        }
        assert!(!e.finding(false));
        assert_eq!(e.get(), None);
        assert!(e.finding(true));
    }

    #[test]
    fn one_open_answer_is_enough() {
        let mut t = UdpFirewallTester::default();
        assert!(t.connected(100));
        assert!(!t.connected(101));
        for n in 1..=4 {
            t.add_possible(contact(n, 8));
        }
        t.add_possible(contact(9, 5)); // too old to ask
                                       // Not before the external port is known.
        assert!(t.next_client(false, |_| false, |_| false).is_none());
        let a = t.next_client(true, |_| false, |_| false).unwrap();
        let b = t.next_client(true, |_| false, |_| false).unwrap();
        // Two at a time.
        assert!(t.next_client(true, |_| false, |_| false).is_none());
        assert!(!t.is_firewalled(false, false, 110));
        assert!(!t.is_verified(110));
        // Unasked: ignored.
        assert!(!t.result(true, false, ip(7), 4672, 4672, 110));
        assert!(t.result(true, false, a.ip, 4672, 4672, 120));
        assert!(t.is_verified(120) && !t.is_firewalled(false, false, 120));
        assert!(!t.use_external_port);
        assert!(!t.is_running());
        // The other's late answer changes nothing.
        assert!(!t.result(false, false, b.ip, 0, 4672, 121));
    }

    #[test]
    fn two_failed_tests_say_firewalled() {
        let mut t = UdpFirewallTester::default();
        t.connected(100);
        for n in 1..=3 {
            t.add_possible(contact(n, 8));
        }
        // One in our routing table is not asked.
        let a = t.next_client(true, |_| false, |i| i == ip(3)).unwrap();
        let b = t.next_client(true, |_| false, |i| i == ip(3)).unwrap();
        // A cancelled test frees its place.
        assert!(!t.result(false, true, a.ip, 0, 4672, 110));
        assert!(
            t.next_client(true, |_| false, |_| false).is_none(),
            "no third contact left"
        );
        assert!(!t.result(false, false, b.ip, 0, 4672, 110));
        t.add_possible(contact(4, 8));
        let c = t.next_client(true, |_| false, |_| false).unwrap();
        assert!(t.result(false, false, c.ip, 0, 4672, 130));
        assert!(t.is_verified(130) && t.is_firewalled(false, true, 130));
    }

    #[test]
    fn no_answer_in_six_minutes_says_firewalled_then_it_expires() {
        let mut t = UdpFirewallTester::default();
        t.connected(0);
        assert!(!t.is_firewalled(false, true, ROUND_TIMEOUT));
        // Only with TCP firewalled too.
        assert!(!t.is_firewalled(false, false, ROUND_TIMEOUT + 1));
        // As in aMule, the call that notices the timeout still gives the
        // old answer; from then on, firewalled.
        assert!(!t.is_firewalled(false, true, ROUND_TIMEOUT + 1));
        assert!(t.is_firewalled(false, true, ROUND_TIMEOUT + 2));
        // A verified answer lapses after two rounds without a result.
        let mut t = UdpFirewallTester::default();
        t.connected(0);
        t.add_possible(contact(1, 8));
        let a = t.next_client(true, |_| false, |_| false).unwrap();
        t.result(true, false, a.ip, 4672, 4672, 10);
        assert!(t.is_verified(10));
        t.recheck(false, RECHECK_INTERVAL);
        assert!(t.is_verified(RECHECK_INTERVAL + ROUND_TIMEOUT + 1));
        t.recheck(false, 2 * RECHECK_INTERVAL);
        assert!(!t.is_verified(2 * RECHECK_INTERVAL + ROUND_TIMEOUT + 1));
    }
}
