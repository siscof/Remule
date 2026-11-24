// SPDX-License-Identifier: GPL-2.0-or-later
//! The servers' UDP status pings (`CServerList::ServerStats` and the
//! answers `CServerUDPSocket::ProcessPacket` takes), without IO.
//!
//! While logged into a server, every 5 s the next server of the list whose
//! last ping is 4.5 hours old (`UDPSERVSTATREASKTIME`; the time is kept in
//! `server.met`) is pinged: obfuscated first when our public IP is known (a
//! raw challenge to its TCP port + 12, the answer keyed with it), and when
//! that has not been answered within 20 s, plainly (`OP_GLOBSERVSTATREQ`,
//! obfuscated with the server's key where it has one for our IP). A plain
//! ping counts as a failure until something comes back from the server;
//! with `RemoveDeadServer` on, a server that has failed `DeadServerRetry`
//! times is dropped when its turn comes.
//!
//! The answer (`OP_GLOBSERVSTATRES`, its challenge ours) tells the server's
//! users and files, its limits, UDP flags, obfuscation ports and UDP key
//! (for our IP); the ping time is measured. Every other answer is followed
//! by a description request (`OP_SERVER_DESC_REQ` with a challenge), whose
//! answer names and describes the server.
//!
//! A server's UDP key is given for our public IP. When that changes
//! (`SetPublicIP`, `CheckForExpiredUDPKeys`), the servers holding a key
//! for another IP are pinged again as soon as they may be: at once, or 20
//! minutes after their last ping (`UDPSERVSTATMINREASKTIME`).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use ed2k_codec::Packet;
use ed2k_formats::server_met::ServerInfo;
use ed2k_server::udp;
use ed2k_server::SearchResult;
use ed2k_types::ed2k::server_udp::{flags, Opcode};
use ed2k_types::Protocol;
use rand::Rng;
use tracing::debug;

use crate::ec_servers::ServerList;
use crate::server_udp::{key_for, sender};

/// `UDPSERVERSTATTIME`: one server pinged this often.
pub const STAT_EVERY: Duration = Duration::from_secs(5);
/// `UDPSERVSTATREASKTIME`: a server is pinged again after 4.5 hours.
pub const REASK_SECS: u64 = 16_200;
/// How long the obfuscated ping waits for its answer.
pub const CRYPT_ANSWER_SECS: u64 = 20;
/// `UDPSERVSTATMINREASKTIME`: no server is pinged twice within 20 minutes
/// to recover its key.
pub const MIN_REASK_SECS: u64 = 1200;

/// What is kept of a server while running, not in `server.met`.
#[derive(Debug, Default, Clone)]
struct Pinging {
    /// The challenge of the ping in flight, 0 for none.
    challenge: u32,
    /// The obfuscated ping went out and was not answered yet.
    crypt_pending: bool,
    /// When the last ping went out (`GetLastPinged`), for the ping time.
    sent: Option<Instant>,
    desc_challenge: u32,
    /// Status answers since the last description request (`lastdescpingedcout`).
    desc_count: u8,
    /// When it was last pinged, in seconds since the epoch
    /// (`GetRealLastPingedTime`; `ST_LASTPING` is moved about).
    real_pinged: u64,
}

/// Something to do for the pings.
#[derive(Debug, Clone)]
pub enum Out {
    /// A raw datagram (the obfuscated ping).
    Raw { to: SocketAddrV4, bytes: Vec<u8> },
    /// A packet for the server, obfuscated where its key allows
    /// ([`crate::server_udp::ServerUdp::send`]).
    Packet { server: ServerInfo, packet: Packet },
    /// A dead server, to be dropped from the list and the connector.
    Remove(SocketAddrV4),
}

/// A server datagram, taken.
#[derive(Debug, Default)]
pub struct Incoming {
    /// A global search answer, for the searches to take.
    pub results: Option<Vec<SearchResult>>,
    /// Sources a server we asked over UDP found, by file.
    pub sources: Option<Vec<(ed2k_types::Md4Hash, Vec<ed2k_server::packets::Source>)>>,
    pub out: Vec<Out>,
}

/// The pings.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// `m_statserverpos`.
    pos: usize,
    state: HashMap<SocketAddrV4, Pinging>,
    next: Option<Instant>,
}

fn addr_of(s: &ServerInfo) -> Option<SocketAddrV4> {
    s.ip.map(|ip| SocketAddrV4::new(ip, s.port))
}

/// aMule's in-memory order of an address, as `ST_UDPKEYIP` keeps it.
fn amule_ip(ip: Option<Ipv4Addr>) -> u32 {
    ip.map_or(0, |ip| u32::from_le_bytes(ip.octets()))
}

impl ServerStats {
    /// `GetNextStatServer`.
    fn next_index(&mut self, n: usize) -> usize {
        if self.pos >= n {
            self.pos = 0;
        }
        let i = self.pos;
        self.pos += 1;
        i
    }

    /// `ServerStats`, called while logged into a server: at most one ping
    /// (or one removal) every [`STAT_EVERY`]. `unix` is the time in seconds
    /// since the epoch; `dead_retries` is `DeadServerRetry` when
    /// `RemoveDeadServer` is on.
    pub fn tick<R: Rng + ?Sized>(
        &mut self,
        now: Instant,
        unix: u64,
        list: &mut ServerList,
        public_ip: Option<Ipv4Addr>,
        dead_retries: Option<u32>,
        rng: &mut R,
    ) -> Option<Out> {
        if self.next.is_some_and(|t| now < t) {
            return None;
        }
        self.next = Some(now + STAT_EVERY);
        let n = list.entries().len();
        if n == 0 {
            return None;
        }
        let mut i = self.next_index(n);
        let first = i;
        loop {
            let last = list.entries()[i].last_ping;
            if last == 0 || unix >= last + REASK_SECS {
                break;
            }
            i = self.next_index(n);
            if i == first {
                return None;
            }
        }
        let e = &list.entries()[i];
        let addr = addr_of(e)?;
        // IsPastDeadThreshold: a static server is never dropped.
        let is_static = list.is_static(addr);
        let e = &mut list.entries_mut()[i];
        if let Some(retries) = dead_retries.filter(|_| !is_static) {
            if e.failed >= retries.max(1) {
                debug!("Removing dead server {addr} ({} failures)", e.failed);
                self.state.remove(&addr);
                return Some(Out::Remove(addr));
            }
        }
        let st = self.state.entry(addr).or_default();
        st.sent = Some(now);
        st.real_pinged = unix;
        if !st.crypt_pending && public_ip.is_some() {
            // Obfuscated first; no answer within 20 s is no failure, the
            // plain ping follows.
            st.crypt_pending = true;
            let c = rng.gen::<u32>().max(1);
            st.challenge = c;
            e.last_ping = (unix + CRYPT_ANSWER_SECS).saturating_sub(REASK_SECS);
            debug!("Sending the obfuscated status ping to server {addr}");
            let to = SocketAddrV4::new(
                *addr.ip(),
                addr.port().wrapping_add(udp::CRYPT_PING_PORT_OFFSET),
            );
            list.mark_changed();
            return Some(Out::Raw {
                to,
                bytes: udp::crypt_ping(c, rng),
            });
        }
        if st.crypt_pending {
            debug!("CryptPing failed for server {addr}");
        }
        st.crypt_pending = false;
        let c = udp::ping_challenge(rng);
        st.challenge = c;
        e.last_ping = unix.saturating_sub(rng.gen_range(0..3600));
        e.failed += 1;
        let server = e.clone();
        list.mark_changed();
        Some(Out::Packet {
            server,
            packet: udp::ping(c),
        })
    }

    /// `CheckForExpiredUDPKeys`, our public IP now `ip`: a server holding
    /// a key given for another IP is pinged again at its next turn, or once
    /// 20 minutes have passed since its last ping.
    pub fn public_ip_changed(&mut self, ip: Ipv4Addr, unix: u64, list: &mut ServerList) {
        let ours = amule_ip(Some(ip));
        let mut expired = 0;
        for e in list.entries_mut() {
            if e.udp_flags & flags::UDPOBFUSCATION == 0 || e.udp_key == 0 || e.udp_key_ip == ours {
                continue;
            }
            expired += 1;
            let real = addr_of(e)
                .and_then(|a| self.state.get(&a))
                .map_or(0, |st| st.real_pinged);
            e.last_ping = if real != 0 && unix < real + MIN_REASK_SECS {
                // Now + (the least delay - what has passed).
                (unix + MIN_REASK_SECS - (unix - real)).saturating_sub(REASK_SECS)
            } else {
                0
            };
        }
        if expired > 0 {
            debug!("Our public IP is {ip}: {expired} servers' UDP keys to recover");
            list.mark_changed();
        }
    }

    /// The key a datagram from this server is read with: the challenge of
    /// an obfuscated ping waiting for its answer, else the server's own.
    fn key(&self, s: &ServerInfo, public_ip: Option<Ipv4Addr>) -> u32 {
        let st = addr_of(s).and_then(|a| self.state.get(&a));
        match st {
            Some(st) if st.crypt_pending && st.challenge != 0 => st.challenge,
            _ => key_for(s, public_ip),
        }
    }

    /// `OnPacketReceived` and `ProcessPacket`: a datagram on the server UDP
    /// port, decrypted and taken. Anything from a listed server resets its
    /// failures.
    #[allow(clippy::too_many_arguments)]
    pub fn datagram<R: Rng + ?Sized>(
        &mut self,
        from: SocketAddrV4,
        datagram: &[u8],
        now: Instant,
        unix: u64,
        list: &mut ServerList,
        public_ip: Option<Ipv4Addr>,
        rng: &mut R,
    ) -> Incoming {
        let mut inc = Incoming::default();
        let idx = sender(list.entries(), from)
            .and_then(addr_of)
            .and_then(|a| list.entries().iter().position(|s| addr_of(s) == Some(a)));
        let key = idx.map_or(0, |i| self.key(&list.entries()[i], public_ip));
        let plain = udp::deobfuscate(datagram, key);
        if plain.len() < 2 || plain[0] != Protocol::Edonkey as u8 {
            debug!("Received an invalid server UDP packet from {from}");
            return inc;
        }
        match Opcode::try_from(plain[1]) {
            Ok(Opcode::GlobSearchRes) => {
                inc.results = udp::parse_global_search_results(&plain);
            }
            Ok(Opcode::GlobFoundSources) => {
                // From a listed server (its obfuscation port, or any port
                // of a server at that IP).
                if idx.is_some() || list.entries().iter().any(|s| s.ip == Some(*from.ip())) {
                    inc.sources = udp::parse_global_found_sources(&plain);
                } else {
                    debug!("OP_GLOBFOUNDSOURCES packet from unknown server {from}");
                }
            }
            Ok(Opcode::GlobServStatRes) => match idx {
                Some(i) => self.status(i, &plain, now, unix, list, public_ip, rng, &mut inc),
                None => debug!("Unknown server on a OP_GLOBSERVSTATRES packet ({from})"),
            },
            Ok(Opcode::ServerDescRes) => match idx {
                Some(i) => self.description(i, &plain, list),
                None => debug!("Received OP_SERVER_DESC_RES from an unknown server"),
            },
            _ => debug!("Unknown Server UDP opcode {:x}", plain[1]),
        }
        if let Some(i) = idx {
            list.entries_mut()[i].failed = 0;
        }
        inc
    }

    #[allow(clippy::too_many_arguments)]
    fn status<R: Rng + ?Sized>(
        &mut self,
        i: usize,
        plain: &[u8],
        now: Instant,
        unix: u64,
        list: &mut ServerList,
        public_ip: Option<Ipv4Addr>,
        rng: &mut R,
        inc: &mut Incoming,
    ) {
        let e = &mut list.entries_mut()[i];
        let Some(addr) = addr_of(e) else { return };
        let st = self.state.entry(addr).or_default();
        let Some(s) = udp::parse_ping_answer(plain) else {
            debug!("Invalid OP_GLOBSERVSTATRES packet from {addr}");
            return;
        };
        if s.challenge != st.challenge {
            debug!(
                "Invalid challenge on OP_GLOBSERVSTATRES packet ({:#x} != {:#x})",
                s.challenge, st.challenge
            );
            return;
        }
        st.challenge = 0;
        st.crypt_pending = false;
        e.last_ping = unix.saturating_sub(rng.gen_range(0..3600));
        if let Some(t) = st.sent {
            e.ping = now.saturating_duration_since(t).as_millis() as u32;
        }
        e.users = s.users;
        e.files = s.files;
        e.max_users = s.max_users;
        e.soft_files = s.soft_files;
        e.hard_files = s.hard_files;
        e.udp_flags = s.udp_flags;
        e.low_id_users = s.low_id_users;
        // SetServerKeyUDP: the key is for our current public IP.
        e.udp_key = s.udp_key;
        e.udp_key_ip = amule_ip(public_ip);
        e.obfuscation_port_tcp = s.tcp_obfuscation_port;
        e.obfuscation_port_udp = s.udp_obfuscation_port;
        // A description every other answer.
        st.desc_count += 1;
        if st.desc_count < 2 {
            let c = udp::desc_challenge(rng);
            st.desc_challenge = c;
            inc.out.push(Out::Packet {
                server: e.clone(),
                packet: udp::desc_request(c),
            });
        } else {
            st.desc_count = 0;
        }
        list.mark_changed();
    }

    fn description(&mut self, i: usize, plain: &[u8], list: &mut ServerList) {
        let e = &mut list.entries_mut()[i];
        let Some(addr) = addr_of(e) else { return };
        let st = self.state.entry(addr).or_default();
        let Some(d) = udp::parse_desc_answer(plain, st.desc_challenge) else {
            // A new-style answer we did not ask for (several servers on one
            // machine answer twice), or garbage.
            return;
        };
        st.desc_challenge = 0;
        if let Some(n) = d.name {
            e.name = n;
        }
        if let Some(t) = d.description {
            e.description = t;
        }
        if let Some(t) = d.dyn_ip {
            e.dyn_ip = t;
        }
        if let Some(t) = d.version {
            e.version = t;
        }
        list.mark_changed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed2k_codec::Writer;
    use std::net::SocketAddr;

    const OURS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const UNIX: u64 = 1_800_000_000;

    fn list() -> (ServerList, SocketAddrV4, SocketAddrV4) {
        let a = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 4661);
        let b = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 4242);
        (
            ServerList::new(&[SocketAddr::V4(a), SocketAddr::V4(b)], None),
            a,
            b,
        )
    }

    fn entry(l: &ServerList, a: SocketAddrV4) -> &ServerInfo {
        l.find(a).unwrap()
    }

    /// `OP_GLOBSERVSTATRES` with every field.
    fn status(challenge: u32, key: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(0xE3).u8(0x97).u32(challenge);
        for v in [1000u32, 50_000, 5000, 10_000, 20_000] {
            w.u32(v);
        }
        w.u32(0x3FB).u32(77).u16(4669).u16(4670).u32(key);
        w.into_bytes()
    }

    /// Pinged in turn every 5 s, obfuscated first; the answer to the
    /// obfuscated ping, keyed with its challenge, fills in the server and
    /// asks for its description; a ping not answered within 20 s is
    /// followed by a plain one, which counts as a failure until the server
    /// answers.
    #[test]
    fn servers_are_pinged_in_turn_and_their_answers_taken() {
        let mut rng = rand::thread_rng();
        let (mut l, a, b) = list();
        let mut s = ServerStats::default();
        let t0 = Instant::now();
        let Some(Out::Raw { to, bytes }) = s.tick(t0, UNIX, &mut l, Some(OURS), Some(3), &mut rng)
        else {
            panic!("an obfuscated ping")
        };
        assert_eq!(to, SocketAddrV4::new(*a.ip(), 4661 + 12));
        let challenge = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(entry(&l, a).last_ping, UNIX + 20 - REASK_SECS);
        assert_eq!(entry(&l, a).failed, 0);
        // 5 s apart.
        let t = t0 + Duration::from_secs(1);
        assert!(s
            .tick(t, UNIX, &mut l, Some(OURS), Some(3), &mut rng)
            .is_none());
        let t = t0 + STAT_EVERY;
        let Some(Out::Raw { to, .. }) = s.tick(t, UNIX + 5, &mut l, Some(OURS), Some(3), &mut rng)
        else {
            panic!()
        };
        assert_eq!(*to.ip(), *b.ip());
        // Both pinged lately: nothing.
        let t = t + STAT_EVERY;
        assert!(s
            .tick(t, UNIX + 10, &mut l, Some(OURS), Some(3), &mut rng)
            .is_none());

        // A answers the obfuscated ping from its obfuscation port.
        let wire =
            ed2k_crypto::udp::encrypt_from_server(&status(challenge, 0xABCD), challenge, 0x5A, 7);
        let inc = s.datagram(
            SocketAddrV4::new(*a.ip(), 4661 + 12),
            &wire,
            t0 + Duration::from_millis(80),
            UNIX + 12,
            &mut l,
            Some(OURS),
            &mut rng,
        );
        let e = entry(&l, a);
        assert_eq!((e.users, e.files, e.max_users), (1000, 50_000, 5000));
        assert_eq!(
            (e.soft_files, e.hard_files, e.low_id_users),
            (10_000, 20_000, 77)
        );
        assert_eq!(e.udp_flags, 0x3FB);
        assert_eq!(
            (e.obfuscation_port_udp, e.obfuscation_port_tcp),
            (4669, 4670)
        );
        assert_eq!(e.udp_key, 0xABCD);
        assert_eq!(e.udp_key_ip, u32::from_le_bytes(OURS.octets()));
        assert_eq!(e.ping, 80);
        assert!(e.last_ping <= UNIX + 12 && e.last_ping + 3600 > UNIX + 12);
        assert!(l.changed());
        // Its key is for our IP now.
        assert_eq!(key_for(e, Some(OURS)), 0xABCD);
        // Then its description is asked for (sent obfuscated with that key).
        let [Out::Packet { server, packet }] = &inc.out[..] else {
            panic!("{:?}", inc.out)
        };
        assert_eq!(server.udp_key, 0xABCD);
        assert_eq!(packet.opcode, u8::from(Opcode::ServerDescReq));
        let desc_challenge = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
        assert_eq!(desc_challenge & 0xFFFF, udp::INV_SERV_DESC_LEN);
        // The new-style answer, obfuscated with the server's key.
        let mut w = Writer::new();
        w.u8(0xE3).u8(0xA3).u32(desc_challenge).u32(2);
        for (id, text) in [(0x01u8, "Big Server"), (0x0B, "the description")] {
            ed2k_codec::Tag::string(id, text)
                .write_ed2k(&mut w, ed2k_codec::io::StrEncoding::Utf8)
                .unwrap();
        }
        let wire = ed2k_crypto::udp::encrypt_from_server(&w.into_bytes(), 0xABCD, 0x5A, 9);
        s.datagram(
            SocketAddrV4::new(*a.ip(), 4669),
            &wire,
            t0,
            UNIX,
            &mut l,
            Some(OURS),
            &mut rng,
        );
        let e = entry(&l, a);
        assert_eq!(
            (e.name.as_str(), e.description.as_str()),
            ("Big Server", "the description")
        );

        // B never answers: 20 s on, a plain ping, a failure.
        let t = t0 + Duration::from_secs(30);
        let Some(Out::Packet { server, packet }) =
            s.tick(t, UNIX + 30, &mut l, Some(OURS), Some(3), &mut rng)
        else {
            panic!()
        };
        assert_eq!(server.ip, Some(*b.ip()));
        assert_eq!(packet.opcode, u8::from(Opcode::GlobServStatReq));
        let plain_challenge = u32::from_le_bytes(packet.payload[..4].try_into().unwrap());
        assert_eq!(plain_challenge >> 16, 0x55AA);
        assert_eq!(entry(&l, b).failed, 1);
        // A wrong challenge is not taken, but anything from it resets the
        // failures.
        let from_b = SocketAddrV4::new(*b.ip(), 4242 + 4);
        s.datagram(
            from_b,
            &status(plain_challenge ^ 1, 0),
            t,
            UNIX + 31,
            &mut l,
            Some(OURS),
            &mut rng,
        );
        assert_eq!(entry(&l, b).users, 0);
        assert_eq!(entry(&l, b).failed, 0);
        // The right one: taken, a description asked for; the next answer
        // asks for none (every other one).
        let inc = s.datagram(
            from_b,
            &status(plain_challenge, 0),
            t,
            UNIX + 31,
            &mut l,
            Some(OURS),
            &mut rng,
        );
        assert_eq!(entry(&l, b).users, 1000);
        assert_eq!(inc.out.len(), 1);
        s.state.get_mut(&b).unwrap().challenge = 5;
        let inc = s.datagram(
            from_b,
            &status(5, 0),
            t,
            UNIX + 31,
            &mut l,
            Some(OURS),
            &mut rng,
        );
        assert!(inc.out.is_empty());
        // An old-style description: the description, then the name.
        let mut w = Writer::new();
        w.u8(0xE3).u8(0xA3).u16(2).bytes(b"dd").u16(2).bytes(b"nn");
        s.datagram(
            from_b,
            &w.into_bytes(),
            t,
            UNIX,
            &mut l,
            Some(OURS),
            &mut rng,
        );
        assert_eq!(
            (
                entry(&l, b).name.as_str(),
                entry(&l, b).description.as_str()
            ),
            ("nn", "dd")
        );
        // A global search answer is handed on.
        let inc = s.datagram(from_b, &[0xE3, 0x99], t, UNIX, &mut l, Some(OURS), &mut rng);
        assert!(inc.results.is_some());
    }

    /// Without our public IP the ping is plain from the start; a server
    /// that failed `DeadServerRetry` times is dropped at its turn, unless
    /// dead servers are kept; one pinged within 4.5 hours waits.
    #[test]
    fn plain_without_our_ip_and_dead_servers_dropped() {
        let mut rng = rand::thread_rng();
        let (mut l, a, b) = list();
        let mut s = ServerStats::default();
        let t0 = Instant::now();
        let Some(Out::Packet { server, .. }) = s.tick(t0, UNIX, &mut l, None, Some(3), &mut rng)
        else {
            panic!()
        };
        assert_eq!(server.ip, Some(*a.ip()));
        l.entries_mut()[1].failed = 3;
        let t = t0 + STAT_EVERY;
        let mut kept = ServerStats {
            pos: 1,
            ..Default::default()
        };
        let mut l2 = l.clone();
        assert!(matches!(
            kept.tick(t, UNIX, &mut l2, None, None, &mut rng),
            Some(Out::Packet { .. })
        ));
        assert!(matches!(
            s.tick(t, UNIX, &mut l, None, Some(3), &mut rng),
            Some(Out::Remove(x)) if x == b
        ));
        l.entries_mut()[1].last_ping = UNIX - REASK_SECS + 1;
        l.entries_mut()[1].failed = 0;
        let t = t + STAT_EVERY;
        assert!(s.tick(t, UNIX, &mut l, None, Some(3), &mut rng).is_none());
        let t = t + STAT_EVERY;
        assert!(matches!(
            s.tick(t, UNIX + 1, &mut l, None, Some(3), &mut rng),
            Some(Out::Packet { server, .. }) if server.ip == Some(*b.ip())
        ));
    }

    /// Our public IP changes: servers holding a key for another IP are
    /// pinged again (obfuscated first) at their next turn, or 20 minutes
    /// after their last ping; keys for the new IP, and servers without
    /// obfuscation, are left alone.
    #[test]
    fn keys_for_another_ip_are_recovered() {
        let mut rng = rand::thread_rng();
        let old = Ipv4Addr::new(192, 0, 2, 1);
        let addrs: Vec<SocketAddr> = (1..=4)
            .map(|i| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, i), 4661)))
            .collect();
        let mut l = ServerList::new(&addrs, None);
        for (i, e) in l.entries_mut().iter_mut().enumerate() {
            e.udp_flags = if i == 3 { 0 } else { flags::UDPOBFUSCATION };
            e.udp_key = 0x1234;
            e.udp_key_ip = amule_ip(Some(if i == 2 { OURS } else { old }));
            e.obfuscation_port_udp = 4669;
            e.last_ping = UNIX - 60;
        }
        let mut s = ServerStats::default();
        // The first was pinged (by us) 5 minutes ago.
        let a = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 4661);
        s.state.entry(a).or_default().real_pinged = UNIX - 300;
        s.public_ip_changed(OURS, UNIX, &mut l);
        let last: Vec<u64> = l.entries().iter().map(|e| e.last_ping).collect();
        assert_eq!(last, vec![UNIX + 900 - REASK_SECS, 0, UNIX - 60, UNIX - 60]);
        // The second is pinged at once, the first 15 minutes on.
        let t0 = Instant::now();
        let Some(Out::Raw { to, .. }) = s.tick(t0, UNIX, &mut l, Some(OURS), None, &mut rng) else {
            panic!()
        };
        assert_eq!(to.ip().octets()[3], 2);
        let t = t0 + STAT_EVERY;
        // (Meanwhile the second's obfuscated ping went unanswered: plain.)
        let Some(Out::Packet { server, .. }) =
            s.tick(t, UNIX + 899, &mut l, Some(OURS), None, &mut rng)
        else {
            panic!()
        };
        assert_eq!(server.ip.unwrap().octets()[3], 2);
        let t = t + STAT_EVERY;
        let Some(Out::Raw { to, .. }) = s.tick(t, UNIX + 900, &mut l, Some(OURS), None, &mut rng)
        else {
            panic!()
        };
        assert_eq!(to.ip().octets()[3], 1);
        // Nothing changes when no key is for another IP.
        let mut l2 = ServerList::new(&addrs[2..3], None);
        s.public_ip_changed(OURS, UNIX, &mut l2);
        assert!(!l2.changed());
    }

    /// IsPastDeadThreshold: a static server is pinged, never dropped.
    #[test]
    fn a_static_server_is_never_dropped() {
        let mut rng = rand::thread_rng();
        let (mut l, a, _) = list();
        l.apply_statics(&[crate::ec_servers::StaticServer {
            addr: a,
            preference: 0,
            name: "static".into(),
        }]);
        l.entries_mut()[0].failed = 9;
        let mut s = ServerStats::default();
        assert!(matches!(
            s.tick(Instant::now(), UNIX, &mut l, None, Some(3), &mut rng),
            Some(Out::Packet { server, .. }) if server.ip == Some(*a.ip())
        ));
    }
}
