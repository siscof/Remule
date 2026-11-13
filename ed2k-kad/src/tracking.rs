// SPDX-License-Identifier: GPL-2.0-or-later
//! Flood protection for incoming requests (`CPacketTracking::InTrack*`,
//! net/PacketTracking.cpp).
//!
//! Each request opcode has a rate per IP (requests per minute). A request
//! is counted in a leaky bucket that drains one request per `60 / rate`
//! seconds: above the rate requests are dropped; above five times the rate
//! *with a valid receiver key* (so the sender cannot be spoofed) it is a
//! massive flood, and the sender is banned.

use std::collections::HashMap;

use ed2k_types::kad::v1::Opcode as V1;
use ed2k_types::kad::v2::Opcode;

/// `MAX_TRACKED_IPS`
pub const MAX_TRACKED_IPS: usize = 10_000;
/// How often old trackers are swept.
const CLEANUP_MS: u64 = 12 * 60 * 1000;

/// `IncomingPacket`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    Drop,
    MassiveFlood,
}

/// `InTrackListAllowedPerMinute` (0: not limited).
pub fn allowed_per_minute(opcode: u8) -> u32 {
    match Opcode::try_from(opcode) {
        Ok(Opcode::BootstrapReq) => 2,
        Ok(Opcode::HelloReq) => 3,
        Ok(Opcode::Req) => 10,
        Ok(Opcode::SearchNotesReq) => 3,
        Ok(Opcode::SearchKeyReq) => 3,
        Ok(Opcode::SearchSourceReq) => 3,
        Ok(Opcode::PublishKeyReq) => 3,
        Ok(Opcode::PublishSourceReq) => 2,
        Ok(Opcode::PublishNotesReq) => 2,
        Ok(Opcode::Firewalled2Req) => 2,
        Ok(Opcode::Ping) => 2,
        _ => match V1::try_from(opcode) {
            Ok(V1::FirewalledReq) | Ok(V1::FindBuddyReq) => 2,
            Ok(V1::CallbackReq) => 1,
            _ => 0,
        },
    }
}

/// Both firewall requests count as one.
fn tracked_opcode(opcode: u8) -> u8 {
    if opcode == u8::from(Opcode::Firewalled2Req) {
        V1::FirewalledReq.into()
    } else {
        opcode
    }
}

#[derive(Debug, Clone)]
struct Request {
    opcode: u8,
    first: u64,
    count: u32,
    verified_first: u64,
    verified_count: u32,
}

#[derive(Debug, Clone, Default)]
struct PerIp {
    requests: Vec<Request>,
    last_expire: u64,
}

/// The tracker. Times are milliseconds.
#[derive(Debug, Clone, Default)]
pub struct InTracker {
    ips: HashMap<u32, PerIp>,
    last_cleanup: u64,
}

/// One leaky bucket step: drain, then add this request (capped).
fn charge(count: &mut u32, first: &mut u64, now: u64, interval: u64, flood: u32) {
    let drained = now.saturating_sub(*first) / interval;
    if drained >= *count as u64 {
        *count = 0;
        *first = now;
    } else {
        *count -= drained as u32;
        *first += drained * interval;
    }
    *count = (*count + 1).min(flood + 1);
}

impl InTracker {
    pub fn tracked_ips(&self) -> usize {
        self.ips.len()
    }

    /// `InTrackListIsAllowedPacket`
    pub fn admit(&mut self, ip: u32, opcode: u8, valid_receiver_key: bool, now: u64) -> Admission {
        let per_minute = allowed_per_minute(opcode);
        if per_minute == 0 {
            return Admission::Allowed;
        }
        let opcode = tracked_opcode(opcode);
        let interval = 60_000 / per_minute as u64;
        let flood = per_minute * 5;
        if now.saturating_sub(self.last_cleanup) > CLEANUP_MS {
            self.cleanup(now);
        }
        if !self.ips.contains_key(&ip) {
            if self.ips.len() >= MAX_TRACKED_IPS && now.saturating_sub(self.last_cleanup) > 60_000 {
                self.cleanup(now);
            }
            if self.ips.len() >= MAX_TRACKED_IPS {
                return Admission::Drop;
            }
        }
        let t = self.ips.entry(ip).or_default();
        if let Some(r) = t.requests.iter_mut().find(|r| r.opcode == opcode) {
            charge(&mut r.count, &mut r.first, now, interval, flood);
            if valid_receiver_key {
                charge(
                    &mut r.verified_count,
                    &mut r.verified_first,
                    now,
                    interval,
                    flood,
                );
            }
            t.last_expire = t.last_expire.max(now + interval * r.count as u64);
            if valid_receiver_key && r.verified_count > flood {
                return Admission::MassiveFlood;
            }
            if r.count > per_minute {
                return Admission::Drop;
            }
            return Admission::Allowed;
        }
        t.requests.push(Request {
            opcode,
            first: now,
            count: 1,
            verified_first: now,
            verified_count: valid_receiver_key as u32,
        });
        t.last_expire = t.last_expire.max(now + interval);
        Admission::Allowed
    }

    /// `InTrackListCleanup`
    fn cleanup(&mut self, now: u64) {
        self.last_cleanup = now;
        self.ips.retain(|_, t| t.last_expire >= now);
    }
}
