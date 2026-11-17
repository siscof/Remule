// SPDX-License-Identifier: GPL-2.0-or-later
//! Kad's TCP firewall check, the bookkeeping without IO
//! (`kademlia/kademlia/FirewallRecheck.h`, `FirewallCheckRequests.h`,
//! `PublicIPVote.h`).
//!
//! While a check runs, every node that says hello is asked
//! (`KADEMLIA_FIREWALLED2_REQ`) to tell us our IP over UDP
//! (`KADEMLIA_FIREWALLED_RES`) and to connect to our TCP port; when it got
//! through it says so on that connection (`OP_KAD_FWTCPCHECK_ACK`). Two such
//! confirmations and we are reachable. A check runs from the start and again
//! every hour.
//!
//! Times are seconds (aMule keeps the request lifetime in milliseconds).

use ed2k_types::kad::KADEMLIAFIREWALLCHECKS;

/// `CFirewallRecheck::kConfirmations`: peers that must reach us over TCP
/// before we count as open.
pub const CONFIRMATIONS: u32 = 2;
/// `CFirewallRecheck::kGraceSeconds`: how long the confirmations may take
/// after the last IP answer.
pub const GRACE: u64 = 60;
/// `CUDPVerificationExpiry::kRecheckIntervalMs`: between two checks.
pub const RECHECK_INTERVAL: u64 = 3600;
/// `CFirewallCheckRequests::kLifetimeMs`: how long a request is answerable.
pub const REQUEST_LIFETIME: u64 = 180;

/// `CFirewallRecheck`: our TCP firewall state across a recheck.
///
/// The IP answers alone do not end a recheck: confirmations come over TCP
/// and take longer, and ending on the last IP answer would show us
/// firewalled for a moment every hour.
#[derive(Debug, Clone)]
pub struct Recheck {
    answers: u32,
    confirmations: u32,
    answered_at: u64,
    last_state: bool,
}

impl Default for Recheck {
    /// Firewalled, and waiting for answers (the first check).
    fn default() -> Self {
        Recheck {
            answers: 0,
            confirmations: 0,
            answered_at: 0,
            last_state: true,
        }
    }
}

impl Recheck {
    /// `Start`: a new recheck, keeping the current state until it ends.
    pub fn start(&mut self, now: u64) {
        self.last_state = self.is_firewalled(now);
        self.answers = 0;
        self.confirmations = 0;
        self.answered_at = 0;
    }

    /// `AddAnswer`: a node told us our IP.
    pub fn add_answer(&mut self, now: u64) {
        self.answers += 1;
        if self.answers == KADEMLIAFIREWALLCHECKS {
            self.answered_at = now;
        }
    }

    /// `AddConfirmation`: a node reached our TCP port.
    pub fn add_confirmation(&mut self) {
        self.confirmations += 1;
    }

    /// `AwaitingAnswers`: nodes that say hello are asked while this holds.
    pub fn awaiting_answers(&self) -> bool {
        self.answers < KADEMLIAFIREWALLCHECKS
    }

    /// `IsFirewalled`
    pub fn is_firewalled(&self, now: u64) -> bool {
        if self.confirmations >= CONFIRMATIONS {
            return false;
        }
        if self.awaiting_answers() || now < self.answered_at + GRACE {
            return self.last_state;
        }
        true
    }
}

/// Which reply a peer gave to our request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// `KADEMLIA_FIREWALLED_RES`
    PublicIp,
    /// `KADEMLIA_FIREWALLED_ACK_RES` or `OP_KAD_FWTCPCHECK_ACK`
    Reachable,
}

#[derive(Debug, Clone)]
struct Request {
    ip: u32,
    sent: u64,
    public_ip_taken: bool,
    reachable_taken: bool,
}

/// `CFirewallCheckRequests`: the peers we asked, for
/// [`REQUEST_LIFETIME`] each. Each may give each kind of reply once, so
/// one peer cannot settle our IP or make us reachable by repeating itself.
#[derive(Debug, Clone, Default)]
pub struct Requests {
    /// Newest first.
    list: Vec<Request>,
}

impl Requests {
    /// `Add`: a peer already asked keeps its request (asking again buys no
    /// more replies).
    pub fn add(&mut self, ip: u32, now: u64) {
        while self
            .list
            .last()
            .is_some_and(|r| now.saturating_sub(r.sent) > REQUEST_LIFETIME)
        {
            self.list.pop();
        }
        if !self.contains(ip, now) {
            self.list.insert(
                0,
                Request {
                    ip,
                    sent: now,
                    public_ip_taken: false,
                    reachable_taken: false,
                },
            );
        }
    }

    /// `Contains`: a check with this peer is running.
    pub fn contains(&self, ip: u32, now: u64) -> bool {
        self.list
            .iter()
            .any(|r| r.ip == ip && now.saturating_sub(r.sent) < REQUEST_LIFETIME)
    }

    /// `Take`: accept `reply` from `ip` if a live request to it has not had
    /// that reply yet.
    pub fn take(&mut self, ip: u32, reply: Reply, now: u64) -> bool {
        for r in &mut self.list {
            if r.ip != ip || now.saturating_sub(r.sent) >= REQUEST_LIFETIME {
                continue;
            }
            let taken = match reply {
                Reply::PublicIp => &mut r.public_ip_taken,
                Reply::Reachable => &mut r.reachable_taken,
            };
            if !*taken {
                *taken = true;
                return true;
            }
        }
        false
    }
}

/// `CPublicIPVote`: our public IP as Kad peers report it. The first report
/// is taken as is; after that a new value needs a second, equal report from
/// another /24.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicIpVote {
    ip: u32,
    last: u32,
    last_reporter: u32,
}

impl PublicIpVote {
    pub fn get(&self) -> u32 {
        self.ip
    }

    /// `Load`: the IP saved with the Kad preferences; nobody's report.
    pub fn load(&mut self, ip: u32) {
        self.ip = ip;
    }

    /// `Report`: `reporter` told us we are at `ip` (both aMule order).
    pub fn report(&mut self, ip: u32, reporter: u32) {
        if ip == 0 || self.last == 0 {
            self.ip = ip;
            self.last = ip;
            self.last_reporter = reporter;
        } else if ip != self.last {
            self.last = ip;
            self.last_reporter = reporter;
        } else if (reporter ^ self.last_reporter) & 0xFFFF_FF00 != 0 {
            self.ip = ip;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KadFirewallRecheckTest.cpp
    const START: u64 = 1_000_000;

    fn open_node() -> Recheck {
        let mut fw = Recheck::default();
        fw.add_confirmation();
        fw.add_confirmation();
        fw
    }

    fn add_all_answers(fw: &mut Recheck, now: u64) {
        for _ in 0..KADEMLIAFIREWALLCHECKS {
            fw.add_answer(now);
        }
    }

    #[test]
    fn starts_firewalled_until_confirmed() {
        let mut fw = Recheck::default();
        assert!(fw.is_firewalled(START));
        assert!(fw.awaiting_answers());
        add_all_answers(&mut fw, START);
        assert!(fw.is_firewalled(START + 1));
        fw.add_confirmation();
        fw.add_confirmation();
        assert!(!fw.is_firewalled(START + 2));
    }

    #[test]
    fn answers_before_confirmations_keep_open_state() {
        let mut fw = open_node();
        fw.start(START);
        assert!(!fw.is_firewalled(START));
        add_all_answers(&mut fw, START + 1);
        assert!(!fw.awaiting_answers());
        assert!(!fw.is_firewalled(START + 1));
        fw.add_confirmation();
        assert!(!fw.is_firewalled(START + 2));
        fw.add_confirmation();
        assert!(!fw.is_firewalled(START + 2));
    }

    #[test]
    fn confirmations_before_answers_keep_open_state() {
        let mut fw = open_node();
        fw.start(START);
        fw.add_confirmation();
        fw.add_confirmation();
        assert!(!fw.is_firewalled(START + 1));
        add_all_answers(&mut fw, START + 2);
        assert!(!fw.is_firewalled(START + 2));
    }

    #[test]
    fn no_confirmation_turns_firewalled_after_grace() {
        let mut fw = open_node();
        fw.start(START);
        add_all_answers(&mut fw, START + 1);
        assert!(!fw.is_firewalled(START + GRACE));
        assert!(fw.is_firewalled(START + 1 + GRACE));
        // One confirmation is not enough.
        fw.add_confirmation();
        assert!(fw.is_firewalled(START + 2 + GRACE));
    }

    #[test]
    fn restart_during_recheck_keeps_shown_state() {
        let mut fw = open_node();
        fw.start(START);
        fw.start(START + 5);
        assert!(!fw.is_firewalled(START + 5));
    }

    #[test]
    fn late_answers_do_not_extend_grace() {
        let mut fw = open_node();
        fw.start(START);
        add_all_answers(&mut fw, START);
        fw.add_answer(START + 50);
        assert!(fw.is_firewalled(START + GRACE));
    }

    // KadFirewallCheckRequestsTest.cpp
    const PEER: u32 = 0x0A00_0001;
    const OTHER: u32 = 0x0A00_0002;

    #[test]
    fn unasked_peer_gets_nothing() {
        let mut r = Requests::default();
        r.add(PEER, START);
        assert!(!r.contains(OTHER, START));
        assert!(!r.take(OTHER, Reply::PublicIp, START));
        assert!(!r.take(OTHER, Reply::Reachable, START));
    }

    #[test]
    fn each_reply_kind_once_per_request() {
        let mut r = Requests::default();
        r.add(PEER, START);
        assert!(r.take(PEER, Reply::PublicIp, START + 1));
        assert!(!r.take(PEER, Reply::PublicIp, START + 2));
        assert!(r.take(PEER, Reply::Reachable, START + 3));
        assert!(!r.take(PEER, Reply::Reachable, START + 4));
        assert!(r.contains(PEER, START + 5));
    }

    #[test]
    fn asking_again_buys_no_second_reply() {
        let mut r = Requests::default();
        r.add(PEER, START);
        r.add(PEER, START + 10);
        assert!(r.take(PEER, Reply::Reachable, START + 20));
        assert!(!r.take(PEER, Reply::Reachable, START + 21));
        assert!(r.take(PEER, Reply::PublicIp, START + 22));
        assert!(!r.take(PEER, Reply::PublicIp, START + 23));
    }

    #[test]
    fn requests_expire() {
        let mut r = Requests::default();
        r.add(PEER, START);
        let expired = START + REQUEST_LIFETIME;
        assert!(!r.contains(PEER, expired));
        assert!(!r.take(PEER, Reply::PublicIp, expired));
        // Adding later drops the stale request, so a new one is the only one left.
        r.add(OTHER, expired + 1);
        r.add(PEER, expired + 2);
        assert!(r.take(PEER, Reply::PublicIp, expired + 3));
        assert!(!r.take(PEER, Reply::PublicIp, expired + 4));
    }

    // KadPublicIPVoteTest.cpp
    const OUR_IP: u32 = 0x5D00_0001;
    const FAKE_IP: u32 = 0x0102_0304;
    const PEER_A: u32 = 0x0A00_0001;
    const PEER_A_SAME_NET: u32 = 0x0A00_00FE;
    const PEER_B: u32 = 0x0B00_0001;

    #[test]
    fn first_report_is_taken() {
        let mut v = PublicIpVote::default();
        v.report(OUR_IP, PEER_A);
        assert_eq!(v.get(), OUR_IP);
    }

    #[test]
    fn change_needs_two_reporters_from_different_subnets() {
        let mut v = PublicIpVote::default();
        v.report(OUR_IP, PEER_A);
        v.report(FAKE_IP, PEER_A);
        v.report(FAKE_IP, PEER_A);
        v.report(FAKE_IP, PEER_A_SAME_NET);
        assert_eq!(v.get(), OUR_IP);
        v.report(FAKE_IP, PEER_B);
        assert_eq!(v.get(), FAKE_IP);
    }

    #[test]
    fn mismatch_restarts_the_vote() {
        let mut v = PublicIpVote::default();
        v.report(OUR_IP, PEER_A);
        v.report(FAKE_IP, PEER_A);
        v.report(OUR_IP + 1, PEER_B);
        v.report(FAKE_IP, PEER_B);
        assert_eq!(v.get(), OUR_IP);
    }

    #[test]
    fn loaded_ip_is_nobodys_report() {
        let mut v = PublicIpVote::default();
        v.load(OUR_IP);
        assert_eq!(v.get(), OUR_IP);
        v.report(FAKE_IP, PEER_A);
        assert_eq!(v.get(), FAKE_IP);
    }
}
