// SPDX-License-Identifier: GPL-2.0-or-later
//! Kad buddies, the TCP side (`CClientList`'s buddy, the `KS_*_BUDDY`
//! states, `CBuddyLiveness`, `OP_CALLBACK`, `OP_BUDDYPING`), without IO.
//!
//! A firewalled client cannot be connected to, so it keeps a TCP
//! connection open to a node that can be (its buddy), found through Kad
//! ([`ed2k_kad::Event::BuddyOffer`]). Someone who wants it to connect asks
//! the buddy over Kad (`KADEMLIA_CALLBACK_REQ`); the buddy passes that on
//! (`OP_CALLBACK`) and the firewalled client connects to the asker.
//!
//! Both halves are here: our own buddy when we are firewalled (one at a
//! time: the first offer is taken), and the one we serve when we are open
//! (one at a time too: Kad offers only while we serve none). Either link
//! stays up while packets come: the firewalled side pings every ten
//! minutes, the buddy answers (at most every three), and 25 minutes of
//! silence end it. A link that has not come up two minutes after the offer
//! or the request is given up.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_peer::packets::{buddy_ping, buddy_pong, callback};
use ed2k_peer::{BuddyCallback, Hello, PeerPacket};
use ed2k_types::{Md4Hash, UInt128};

use crate::download_queue::{Action, ConnId, Report};

/// `CBuddyLiveness::RequestTimeout`: a link that has not come up.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// `PingInterval`
pub const PING_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// `IncomingPingInterval`: pings answered at most this often.
pub const INCOMING_PING_INTERVAL: Duration = Duration::from_secs(3 * 60);
/// `ReceiveTimeout`: silence that ends a link.
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(25 * 60);

/// `ConvertBuddyIdLayout`: eMule writes a buddy ID with each 4-byte group
/// reversed against aMule's (`ToByteArray`); the change is its own inverse.
pub fn other_layout(id: UInt128) -> UInt128 {
    let b = id.to_be_bytes();
    let mut o = [0u8; 16];
    for g in 0..4 {
        for i in 0..4 {
            o[g * 4 + i] = b[g * 4 + (3 - i)];
        }
    }
    UInt128::from_be_bytes(o)
}

/// `MatchesBuddyIdEitherLayout`
pub fn same_buddy_id(received: UInt128, expected: UInt128) -> bool {
    received == expected || received == other_layout(expected)
}

#[derive(Debug, Clone)]
struct Link {
    conn: ConnId,
    addr: SocketAddrV4,
    user_hash: Md4Hash,
    /// The hellos are done (`KS_CONNECTED_BUDDY`).
    up: bool,
    since: Instant,
    last_received: Instant,
    next_ping: Instant,
    last_incoming_ping: Option<Instant>,
}

impl Link {
    fn new(conn: ConnId, addr: SocketAddrV4, user_hash: Md4Hash, now: Instant) -> Self {
        Link {
            conn,
            addr,
            user_hash,
            up: false,
            since: now,
            last_received: now,
            next_ping: now + PING_INTERVAL,
            last_incoming_ping: None,
        }
    }

    fn renew(&mut self, now: Instant) {
        self.last_received = now;
        self.next_ping = now + PING_INTERVAL;
    }
}

/// A firewalled node we offered to serve, not connected yet
/// (`KS_INCOMING_BUDDY`).
#[derive(Debug, Clone)]
struct Expected {
    buddy_id: UInt128,
    user_hash: Md4Hash,
    ip: Ipv4Addr,
    until: Instant,
}

/// What a callback asks of the upload side: connect to `addr`, who wants
/// `file` from us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallBack {
    pub addr: SocketAddrV4,
    pub file: Md4Hash,
}

/// Both halves of the buddy business.
#[derive(Debug)]
pub struct Buddies {
    ours: Hello,
    /// Our Kad ID: our buddy ID is it with every bit flipped.
    kad_id: Option<UInt128>,
    own: Option<Link>,
    served: Option<(Link, UInt128)>,
    expected: Vec<Expected>,
}

impl Buddies {
    pub fn new(ours: Hello) -> Self {
        Buddies {
            ours,
            kad_id: None,
            own: None,
            served: None,
            expected: Vec::new(),
        }
    }

    /// Our hello changed (a new ID from the server).
    pub fn set_ours(&mut self, ours: Hello) {
        self.ours = ours;
    }

    /// Kad runs with this ID (callbacks are checked against it).
    pub fn set_kad_id(&mut self, id: Option<UInt128>) {
        self.kad_id = id;
    }

    /// We have a buddy, or are connecting to one (`m_nBuddyStatus !=
    /// Disconnected`): no buddy search.
    pub fn has_own(&self) -> bool {
        self.own.is_some()
    }

    /// Our buddy, once the link is up.
    pub fn own_buddy(&self) -> Option<SocketAddrV4> {
        self.own.as_ref().filter(|l| l.up).map(|l| l.addr)
    }

    /// We serve a buddy: Kad makes no more offers.
    pub fn serving(&self) -> bool {
        self.served.is_some()
    }

    /// Whether a connection is one of ours.
    pub fn owns(&self, conn: ConnId) -> bool {
        self.own.as_ref().is_some_and(|l| l.conn == conn)
            || self.served.as_ref().is_some_and(|(l, _)| l.conn == conn)
    }

    /// `RequestBuddy`: an offer, for when we are firewalled. Taken if we
    /// have no buddy and are not connecting to one: connect to it
    /// (obfuscated when it says it supports that).
    pub fn offer(
        &mut self,
        tcp: SocketAddrV4,
        user_hash: Md4Hash,
        connect_options: u8,
        conn: ConnId,
        now: Instant,
    ) -> Vec<Action> {
        if self.own.is_some() {
            return Vec::new();
        }
        self.own = Some(Link::new(conn, tcp, user_hash, now));
        vec![Action::Connect {
            conn,
            addr: SocketAddr::V4(tcp),
            obfuscate_for: (connect_options & 0x01 != 0).then_some(user_hash),
        }]
    }

    /// Our connection to the buddy is up: say hello.
    pub fn connected(&mut self, conn: ConnId, now: Instant) -> Vec<Action> {
        match &mut self.own {
            Some(l) if l.conn == conn => {
                l.last_received = now;
                match self.ours.to_hello() {
                    Ok(p) => vec![Action::Send {
                        conn,
                        packets: vec![p],
                    }],
                    Err(_) => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }

    /// `IncomingBuddy`: Kad offered to serve a firewalled node; it should
    /// connect within two minutes.
    pub fn expect(&mut self, buddy_id: UInt128, user_hash: Md4Hash, ip: Ipv4Addr, now: Instant) {
        self.expected
            .retain(|e| e.user_hash != user_hash && e.until > now);
        self.expected.push(Expected {
            buddy_id,
            user_hash,
            ip,
            until: now + REQUEST_TIMEOUT,
        });
    }

    /// Whether an incoming connection's hello is from the node we expect.
    pub fn wants_incoming(&self, hello: &Hello, ip: Ipv4Addr, now: Instant) -> bool {
        self.served.is_none()
            && self
                .expected
                .iter()
                .any(|e| e.user_hash == hello.user_hash && e.ip == ip && e.until > now)
    }

    /// The node we expected connected (`KS_INCOMING_BUDDY` to
    /// `KS_CONNECTED_BUDDY`): answer its hello; we serve it now.
    pub fn accept(
        &mut self,
        conn: ConnId,
        hello: &Hello,
        ip: Ipv4Addr,
        now: Instant,
    ) -> Vec<Action> {
        let Some(i) = self
            .expected
            .iter()
            .position(|e| e.user_hash == hello.user_hash && e.ip == ip)
        else {
            return Vec::new();
        };
        let e = self.expected.remove(i);
        let addr = SocketAddrV4::new(ip, hello.port);
        let mut link = Link::new(conn, addr, e.user_hash, now);
        link.up = true;
        self.served = Some((link, e.buddy_id));
        let mut out = Vec::new();
        if let Ok(p) = self.ours.to_hello_answer() {
            out.push(Action::Send {
                conn,
                packets: vec![p],
            });
        }
        out.push(Action::Report(Report::BuddyLinked {
            addr,
            serving: true,
        }));
        out
    }

    /// A packet on one of our links. Callbacks for the upload side come
    /// back separately.
    pub fn packet(
        &mut self,
        conn: ConnId,
        packet: Packet,
        now: Instant,
    ) -> (Vec<Action>, Vec<CallBack>) {
        let mut out = Vec::new();
        let mut callbacks = Vec::new();
        let parsed = PeerPacket::parse(packet, Default::default());
        if let Some(l) = self.own.as_mut().filter(|l| l.conn == conn) {
            l.last_received = now;
            match parsed {
                Ok(PeerPacket::HelloAnswer(h)) if !l.up => {
                    l.up = true;
                    l.user_hash = h.user_hash;
                    l.renew(now);
                    out.push(Action::Report(Report::BuddyLinked {
                        addr: l.addr,
                        serving: false,
                    }));
                }
                Ok(PeerPacket::BuddyPong) => l.renew(now),
                // Ours is the inverse of our Kad ID, in either layout.
                Ok(PeerPacket::Callback(c)) => {
                    let ours = self.kad_id.map(|id| UInt128::new(u128::MAX) ^ id);
                    if ours.is_some_and(|b| same_buddy_id(c.buddy_id, b)) {
                        callbacks.push(CallBack {
                            addr: SocketAddrV4::new(c.ip, c.tcp_port),
                            file: c.file,
                        });
                    }
                }
                _ => {}
            }
        } else if let Some((l, _)) = self.served.as_mut().filter(|(l, _)| l.conn == conn) {
            l.last_received = now;
            if let Ok(PeerPacket::BuddyPing) = parsed {
                let allowed = l
                    .last_incoming_ping
                    .is_none_or(|t| now.saturating_duration_since(t) >= INCOMING_PING_INTERVAL);
                if allowed {
                    l.last_incoming_ping = Some(now);
                    l.renew(now);
                    out.push(Action::Send {
                        conn,
                        packets: vec![buddy_pong()],
                    });
                }
            }
        }
        (out, callbacks)
    }

    /// `ProcessCallbackRequest` and `BuildBuddyCallback`: a callback request
    /// came over Kad for `buddy_id`; if we serve that buddy (either
    /// layout), pass it on with the ID we know it by.
    pub fn relay(&mut self, buddy_id: UInt128, file: Md4Hash, from: SocketAddrV4) -> Vec<Action> {
        match &self.served {
            Some((l, id)) if l.up && same_buddy_id(buddy_id, *id) => vec![Action::Send {
                conn: l.conn,
                packets: vec![callback(&BuddyCallback {
                    buddy_id: *id,
                    file,
                    ip: *from.ip(),
                    tcp_port: from.port(),
                })],
            }],
            _ => Vec::new(),
        }
    }

    /// One of our connections closed.
    pub fn closed(&mut self, conn: ConnId) -> Vec<Action> {
        self.drop_link(conn, "connection closed")
    }

    fn drop_link(&mut self, conn: ConnId, why: &str) -> Vec<Action> {
        if self.own.as_ref().is_some_and(|l| l.conn == conn) {
            let l = self.own.take().unwrap();
            return vec![Action::Report(Report::BuddyLost {
                addr: l.addr,
                serving: false,
                why: why.to_owned(),
            })];
        }
        if self.served.as_ref().is_some_and(|(l, _)| l.conn == conn) {
            let (l, _) = self.served.take().unwrap();
            return vec![Action::Report(Report::BuddyLost {
                addr: l.addr,
                serving: true,
                why: why.to_owned(),
            })];
        }
        Vec::new()
    }

    /// The timers: our ping, links that went quiet or never came up,
    /// expected nodes that never came.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        self.expected.retain(|e| e.until > now);
        let mut dead = Vec::new();
        if let Some(l) = self.own.as_mut() {
            if !l.up && now.saturating_duration_since(l.since) >= REQUEST_TIMEOUT {
                dead.push((l.conn, "did not come up in time"));
            } else if l.up && now.saturating_duration_since(l.last_received) >= RECEIVE_TIMEOUT {
                dead.push((l.conn, "silent for 25 minutes"));
            } else if l.up && now >= l.next_ping {
                l.next_ping = now + PING_INTERVAL;
                out.push(Action::Send {
                    conn: l.conn,
                    packets: vec![buddy_ping()],
                });
            }
        }
        if let Some((l, _)) = &self.served {
            if now.saturating_duration_since(l.last_received) >= RECEIVE_TIMEOUT {
                dead.push((l.conn, "silent for 25 minutes"));
            }
        }
        for (conn, why) in dead {
            out.push(Action::Close { conn });
            out.extend(self.drop_link(conn, why));
        }
        out
    }
}
