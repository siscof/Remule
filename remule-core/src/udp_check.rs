// SPDX-License-Identifier: GPL-2.0-or-later
//! The TCP half of Kad's UDP firewall test (`DoRequestFirewallCheckUDP`,
//! `SendFirewallCheckUDPRequest`, the `KS_*FWCHECK_UDP` states), without IO.
//!
//! Kad picks a node that does not know us ([`ed2k_kad::Event::UdpFirewallCheck`]);
//! we connect to it (plainly: its user hash is not known), say hello, and
//! once it has answered send `OP_FWCHECKUDPREQ` with our Kad ports and our
//! verify key for it. It then sends `KADEMLIA2_FIREWALLUDP` to those ports,
//! which Kad itself reads. The connection is kept until it times out; when
//! it ends, Kad is told: a test whose request went out and whose answer did
//! not come failed, one that never got that far was cancelled.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_peer::packets::fw_check_udp_req;
use ed2k_peer::{Hello, PeerPacket};
use ed2k_types::ed2k::CONNECTION_TIMEOUT;

use crate::download_queue::{Action, ConnId, Report};

/// What `OP_FWCHECKUDPREQ` carries: our internal and external Kad ports,
/// our verify key for the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckRequest {
    pub internal: u16,
    pub external: u16,
    pub key: u32,
}

#[derive(Debug, Clone)]
struct Test {
    addr: SocketAddrV4,
    request: CheckRequest,
    /// The request went out (`KS_FWCHECK_UDP`).
    sent: bool,
    since: Instant,
}

/// The tests under way.
#[derive(Debug)]
pub struct UdpChecks {
    ours: Hello,
    tests: HashMap<ConnId, Test>,
    timeout: Duration,
}

impl UdpChecks {
    pub fn new(ours: Hello) -> Self {
        UdpChecks {
            ours,
            tests: HashMap::new(),
            timeout: CONNECTION_TIMEOUT,
        }
    }

    /// Our hello changed (a new ID from the server).
    pub fn set_ours(&mut self, ours: Hello) {
        self.ours = ours;
    }

    pub fn owns(&self, conn: ConnId) -> bool {
        self.tests.contains_key(&conn)
    }

    /// Kad wants the node at `addr` (its TCP port) asked.
    pub fn start(
        &mut self,
        addr: SocketAddrV4,
        request: CheckRequest,
        conn: ConnId,
        now: Instant,
    ) -> Vec<Action> {
        self.tests.insert(
            conn,
            Test {
                addr,
                request,
                sent: false,
                since: now,
            },
        );
        vec![Action::Connect {
            conn,
            addr: SocketAddr::V4(addr),
            obfuscate_for: None,
        }]
    }

    /// Connected: say hello.
    pub fn connected(&mut self, conn: ConnId, now: Instant) -> Vec<Action> {
        let Some(t) = self.tests.get_mut(&conn) else {
            return Vec::new();
        };
        t.since = now;
        match self.ours.to_hello() {
            Ok(p) => vec![Action::Send {
                conn,
                packets: vec![p],
            }],
            Err(_) => Vec::new(),
        }
    }

    /// A packet on a test connection: the hello answer is the cue for the
    /// request; the rest is of no interest.
    pub fn packet(&mut self, conn: ConnId, packet: Packet, now: Instant) -> Vec<Action> {
        let Some(t) = self.tests.get_mut(&conn) else {
            return Vec::new();
        };
        if !t.sent {
            if let Ok(PeerPacket::HelloAnswer(_)) = PeerPacket::parse(packet, Default::default()) {
                t.sent = true;
                t.since = now;
                let r = t.request;
                return vec![Action::Send {
                    conn,
                    packets: vec![fw_check_udp_req(r.internal, r.external, r.key)],
                }];
            }
        }
        Vec::new()
    }

    /// A test connection ended: tell Kad how far it got.
    pub fn closed(&mut self, conn: ConnId) -> Vec<Action> {
        match self.tests.remove(&conn) {
            Some(t) => vec![Action::Report(Report::UdpCheckEnded {
                ip: *t.addr.ip(),
                cancelled: !t.sent,
            })],
            None => Vec::new(),
        }
    }

    /// Connections that have waited long enough (`CONNECTION_TIMEOUT`):
    /// for the hello answer, or after the request for nothing more.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let due: Vec<ConnId> = self
            .tests
            .iter()
            .filter(|(_, t)| now.saturating_duration_since(t.since) >= self.timeout)
            .map(|(&c, _)| c)
            .collect();
        let mut out = Vec::new();
        for conn in due {
            out.push(Action::Close { conn });
            out.extend(self.closed(conn));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed2k_peer::packets::parse_fw_check_udp_req;
    use ed2k_types::Md4Hash;
    use std::net::Ipv4Addr;

    fn wire(p: Packet) -> Packet {
        Packet::parse_tcp(&p.to_tcp_bytes().unwrap()).unwrap()
    }

    #[test]
    fn a_test_over_tcp() {
        let t0 = Instant::now();
        let ours = Hello::amule(Md4Hash([1; 16]), 0x0100_000A, 4662, "remule");
        let mut u = UdpChecks::new(ours);
        let addr = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 4662);
        let req = CheckRequest {
            internal: 4672,
            external: 4672,
            key: 77,
        };
        let a = u.start(addr, req, 5, t0);
        assert!(matches!(
            &a[..],
            [Action::Connect {
                conn: 5,
                obfuscate_for: None,
                ..
            }]
        ));
        assert!(u.owns(5));
        let a = u.connected(5, t0);
        assert!(matches!(&a[..], [Action::Send { conn: 5, .. }]));
        // Its hello answer: the request goes out.
        let theirs = Hello::amule(Md4Hash([2; 16]), 0x0700_A8C0, 4662, "node");
        let a = u.packet(5, wire(theirs.to_hello_answer().unwrap()), t0);
        let Action::Send { packets, .. } = &a[0] else {
            panic!()
        };
        assert_eq!(parse_fw_check_udp_req(&packets[0]), Some((4672, 4672, 77)));
        // Only once.
        assert!(u
            .packet(5, wire(theirs.to_hello_answer().unwrap()), t0)
            .is_empty());
        // It times out: closed, and the test failed (not cancelled).
        assert!(u.tick(t0 + Duration::from_secs(1)).is_empty());
        let a = u.tick(t0 + u.timeout);
        assert!(a.iter().any(|x| matches!(x, Action::Close { conn: 5 })));
        assert!(a.iter().any(|x| matches!(
            x,
            Action::Report(Report::UdpCheckEnded { cancelled: false, ip }) if *ip == *addr.ip()
        )));
        assert!(!u.owns(5));
        // One that never got its request out is cancelled.
        u.start(addr, req, 6, t0);
        let a = u.closed(6);
        assert!(matches!(
            &a[..],
            [Action::Report(Report::UdpCheckEnded {
                cancelled: true,
                ..
            })]
        ));
    }
}
