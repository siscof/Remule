// SPDX-License-Identifier: GPL-2.0-or-later
//! The daemon's side of an EC connection, sans IO: framing as
//! `CECSocket` reads and writes it, the login as
//! `CECServerSocket::Authenticate` runs it (EC_SRP.md, "Four messages"),
//! and the failed-login lockout of `CRateLimiter`.
//!
//! The caller reads an 8-byte header, checks it with
//! [`ServerConn::check_header`], reads the body and hands both to
//! [`ServerConn::receive`]. Until the login is done that answers by itself;
//! afterwards it returns each request, and the caller sends its reply
//! through [`ServerConn::frame`].

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::IpAddr;

use crate::client::field;
use crate::codes::*;
use crate::crypt::{self, Ephemeral, Session};
use crate::srp::{self, Verifier};
use crate::tag::{Packet, Tag, WireOpts};

/// `ReadHeader`'s bound before the login.
pub const MAX_PACKET_PRE_AUTH: usize = 16 * 1024 * 1024;
/// And after it.
pub const MAX_PACKET: usize = 256 * 1024 * 1024;
/// `EC_MAX_UNCOMPRESSED`: larger replies are compressed when the client can
/// inflate them.
pub const MAX_UNCOMPRESSED: usize = 1024;
/// A zlib body is not inflated past this.
const MAX_INFLATED: u64 = 1024 * 1024 * 1024;

/// `CRateLimiter::Config` with `ExternalConn`'s defaults (ten failures a
/// minute, then five minutes out).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub window_seconds: u64,
    pub threshold: usize,
    pub lockout_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            window_seconds: 60,
            threshold: 10,
            lockout_seconds: 300,
        }
    }
}

#[derive(Debug, Default)]
struct Bucket {
    /// One stamp per failure, each expiring on its own (a sliding window).
    failures: VecDeque<u64>,
    lockout_until: u64,
}

/// `CRateLimiter`, per peer address. Times are in seconds.
#[derive(Debug, Default)]
pub struct AuthLimiter {
    limits: Limits,
    buckets: HashMap<IpAddr, Bucket>,
}

impl AuthLimiter {
    pub fn new(limits: Limits) -> Self {
        AuthLimiter {
            limits,
            buckets: HashMap::new(),
        }
    }

    /// `Check`: `Some(seconds to wait)` while `ip` is locked out.
    pub fn check(&mut self, ip: IpAddr, now: u64) -> Option<u64> {
        let b = self.buckets.get_mut(&ip)?;
        if b.lockout_until > now {
            return Some(b.lockout_until - now);
        }
        if b.lockout_until != 0 {
            b.lockout_until = 0;
            b.failures.clear();
        }
        let window = self.limits.window_seconds;
        while b.failures.front().is_some_and(|&t| now - t > window) {
            b.failures.pop_front();
        }
        None
    }

    /// `NoteFailure`: counted when a challenge is handed out, so abandoned
    /// handshakes count too.
    pub fn note_failure(&mut self, ip: IpAddr, now: u64) {
        let window = self.limits.window_seconds;
        let b = self.buckets.entry(ip).or_default();
        while b.failures.front().is_some_and(|&t| now - t > window) {
            b.failures.pop_front();
        }
        b.failures.push_back(now);
        if b.failures.len() >= self.limits.threshold {
            b.lockout_until = now + self.limits.lockout_seconds;
        }
    }

    /// `NoteSuccess`: a good login forgets earlier typos.
    pub fn note_success(&mut self, ip: IpAddr) {
        self.buckets.remove(&ip);
    }
}

/// What the logins are checked against.
#[derive(Clone, Debug)]
pub struct Credentials {
    /// `ECPasswordVerifier`; `None` when the daemon has no EC password.
    pub password: Option<Verifier>,
    /// Checked for the API and amuleweb token credentials, which this
    /// daemon does not issue: they fail as a wrong password does.
    pub dummy: Verifier,
}

impl Credentials {
    pub fn new(password: Option<Verifier>) -> Self {
        Credentials {
            password,
            dummy: Verifier::dummy(),
        }
    }
}

/// Who the daemon says it is in `EC_OP_AUTH_OK`.
#[derive(Clone, Debug)]
pub struct Identity {
    /// `EC_TAG_SERVER_VERSION`.
    pub version: String,
    /// `EC_TAG_SESSION_ID`: one per daemon process.
    pub session_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Init,
    SaltSent,
    Established,
    Failed,
}

/// What came of a packet.
#[derive(Debug)]
pub enum Received {
    /// A login step: send this frame. After a refusal, [`ServerConn::failed`]
    /// is true and the client is expected to hang up.
    Reply(Vec<u8>),
    /// A request on the established connection, for the caller to answer.
    Request(Packet),
    /// Drop the connection (the reason is for the log).
    Close(String),
}

/// One accepted EC connection.
pub struct ServerConn {
    peer: IpAddr,
    state: State,
    /// `m_my_flags`: what the client said it can read.
    my_flags: u32,
    /// The client is on this machine or the LAN (`EC_TAG_PREFER_NO_ZLIB`).
    local_peer: bool,
    /// Keys exist (`m_crypt_ready`).
    session: Option<Session>,
    /// Replies are sealed (`m_crypt_enabled`): from the one after AUTH_SALT.
    sealing: bool,
    seal_after_next: bool,
    srp: Option<(srp::Server, u8)>,
    notify: bool,
    /// `m_partialUpdateActive`.
    partial_update: bool,
    client: Option<(String, String)>,
    log: Vec<String>,
}

/// `AuthFailure`.
fn auth_failure(reason: u8, message: &str) -> Packet {
    Packet::new(EC_OP_AUTH_FAIL)
        .with(Tag::string(EC_TAG_STRING, message))
        .with(Tag::int(EC_TAG_AUTH_FAIL_REASON, u64::from(reason)))
}

const INVALID_HANDSHAKE: &str = "Invalid SRP handshake or EC verifier.";

/// The transport half of the login (`NegotiateAEAD`): cipher, server nonce,
/// our key and the shared secret. `None` when the offer is unusable.
struct Negotiated {
    cipher: u8,
    server_nonce: [u8; 32],
    client_nonce: Vec<u8>,
    server_pub: [u8; 32],
    shared: zeroize::Zeroizing<[u8; 32]>,
    transcript: Vec<u8>,
}

fn negotiate(req: &Packet) -> Option<Negotiated> {
    let offer = req.tag(EC_TAG_CAN_AEAD)?;
    let nonce = req.tag(EC_TAG_AEAD_CLIENT_NONCE)?;
    if offer.ty != EC_TAGTYPE_CUSTOM || nonce.ty != EC_TAGTYPE_CUSTOM {
        return None;
    }
    if nonce.data.len() != crypt::NONCE_TAG_LEN {
        return None;
    }
    let client_pub = req.tag(EC_TAG_AEAD_CLIENT_PUBKEY)?;
    if client_pub.ty != EC_TAGTYPE_CUSTOM || client_pub.data.len() != crypt::X25519_KEY_LEN {
        return None;
    }
    let offered = &offer.data;
    // A ChaCha20-first offer is honoured; otherwise our order (AES first).
    let cipher = if offered.first() == Some(&crypt::CIPHER_CHACHA20_POLY1305) {
        crypt::CIPHER_CHACHA20_POLY1305
    } else {
        [crypt::CIPHER_AES128_GCM, crypt::CIPHER_CHACHA20_POLY1305]
            .into_iter()
            .find(|c| offered.contains(c))?
    };
    let server_nonce: [u8; 32] = crypt::random_bytes();
    let eph = Ephemeral::generate();
    let server_pub = eph.public;
    let shared = eph.agree(&client_pub.data)?;
    let transcript = crypt::build_transcript(
        offered,
        cipher,
        &nonce.data,
        &server_nonce,
        &client_pub.data,
        &server_pub,
    );
    Some(Negotiated {
        cipher,
        server_nonce,
        client_nonce: nonce.data.clone(),
        server_pub,
        shared,
        transcript,
    })
}

impl ServerConn {
    pub fn new(peer: IpAddr) -> Self {
        ServerConn {
            peer,
            state: State::Init,
            my_flags: 0x20,
            local_peer: false,
            session: None,
            sealing: false,
            seal_after_next: false,
            srp: None,
            notify: false,
            partial_update: false,
            client: None,
            log: Vec::new(),
        }
    }

    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    pub fn established(&self) -> bool {
        self.state == State::Established
    }

    pub fn failed(&self) -> bool {
        self.state == State::Failed
    }

    /// The client's name and version, once it said them.
    pub fn client(&self) -> Option<&(String, String)> {
        self.client.as_ref()
    }

    /// Whether the client speaks the partial-update protocol
    /// (`EC_TAG_CAN_PARTIAL_UPDATE`): unchanged files are left out of
    /// incremental updates, and removed ones named.
    pub fn partial_update(&self) -> bool {
        self.partial_update
    }

    /// Whether the client asked for push notifications (`EC_TAG_CAN_NOTIFY`).
    pub fn wants_notifications(&self) -> bool {
        self.notify
    }

    /// The lines aMule logs for the login so far, taken.
    pub fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }

    /// `ReadHeader`: `Err` closes the connection.
    pub fn check_header(&self, header: [u8; 8]) -> Result<(u32, usize), String> {
        let flags = u32::from_be_bytes(header[0..4].try_into().unwrap());
        let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        let max = if self.established() {
            MAX_PACKET
        } else {
            MAX_PACKET_PRE_AUTH
        };
        if len > max {
            return Err(format!("packet too big: {len}"));
        }
        Ok((flags, len))
    }

    /// `ReadPacket` and `OnPacketReceived`.
    pub fn receive(
        &mut self,
        flags: u32,
        mut body: Vec<u8>,
        creds: &Credentials,
        id: &Identity,
        limiter: &mut AuthLimiter,
        now: u64,
    ) -> Received {
        if flags & 0x60 != 0x20 || flags & EC_FLAG_UNKNOWN_MASK != 0 {
            return Received::Close(format!("packet has invalid flags {flags:#x}"));
        }
        let encrypted = flags & EC_FLAG_ENCRYPTED != 0;
        match (&mut self.session, encrypted) {
            (Some(_), false) => {
                return Received::Close("EC received an unencrypted packet after key setup".into())
            }
            (None, true) => return Received::Close("encrypted packet before key setup".into()),
            (Some(s), true) => match s.open(&body) {
                Some(b) => body = b,
                None => return Received::Close("EC packet failed authentication".into()),
            },
            (None, false) => {}
        }
        if flags & EC_FLAG_ZLIB != 0 {
            let mut out = Vec::new();
            if flate2::read::ZlibDecoder::new(&body[..])
                .take(MAX_INFLATED)
                .read_to_end(&mut out)
                .is_err()
            {
                return Received::Close("zlib error".into());
            }
            body = out;
        }
        let packet = match Packet::decode(&body, WireOpts::from_flags(flags)) {
            Ok(p) => p,
            Err(e) => return Received::Close(format!("error in packet read: {e}")),
        };
        match self.state {
            State::Failed => {
                Received::Close("Client sent packet after authentication failed.".into())
            }
            State::Established => Received::Request(packet),
            State::Init | State::SaltSent => {
                let reply = self.authenticate(&packet, creds, id, limiter, now);
                match self.frame(&reply) {
                    Ok(f) => Received::Reply(f),
                    Err(e) => Received::Close(e),
                }
            }
        }
    }

    /// `Authenticate`: the answer to a login step.
    fn authenticate(
        &mut self,
        req: &Packet,
        creds: &Credentials,
        id: &Identity,
        limiter: &mut AuthLimiter,
        now: u64,
    ) -> Packet {
        let response = if creds.password.is_none() {
            self.log
                .push("External connection refused due to empty password in preferences!".into());
            auth_failure(
                EC_AUTH_FAIL_NO_PASSWORD,
                "External connection refused due to empty password in preferences!",
            )
        } else if self.state == State::Init && req.opcode == EC_OP_AUTH_REQ {
            self.auth_req(req, creds, limiter, now)
        } else if self.state == State::SaltSent && req.opcode == EC_OP_AUTH_PASSWD {
            self.auth_passwd(req, id, limiter)
        } else {
            auth_failure(
                EC_AUTH_FAIL_INCOMPATIBLE,
                "Invalid request, please authenticate first.",
            )
        };
        if response.opcode == EC_OP_AUTH_OK {
            self.state = State::Established;
            self.log.push("Access granted.".into());
        } else if response.opcode == EC_OP_AUTH_FAIL {
            if let Some(m) = response.message() {
                self.log
                    .push(format!("Sent error message \"{m}\" to client."));
            }
            self.log.push(format!(
                "Unauthorized access attempt from {}. Connection closed.",
                self.peer
            ));
            self.state = State::Failed;
            self.srp = None;
        }
        response
    }

    fn auth_req(
        &mut self,
        req: &Packet,
        creds: &Credentials,
        limiter: &mut AuthLimiter,
        now: u64,
    ) -> Packet {
        if let Some(wait) = limiter.check(self.peer, now) {
            let msg = format!("Too many failed connection attempts; try again in {wait} seconds.");
            self.log.push(format!("{msg} {}", self.peer));
            return auth_failure(EC_AUTH_FAIL_RATE_LIMITED, &msg)
                .with(Tag::int(EC_TAG_AUTH_RETRY_AFTER, wait.min(u32::MAX.into())));
        }
        let text = |name: u16, unknown: &str| {
            req.tag(name)
                .filter(|t| t.ty == EC_TAGTYPE_STRING)
                .map_or_else(|| unknown.to_owned(), Tag::as_str)
        };
        let client = (
            text(EC_TAG_CLIENT_NAME, "Unknown"),
            text(EC_TAG_CLIENT_VERSION, "Unknown version"),
        );
        self.log
            .push(format!("Connecting client: {} {}", client.0, client.1));
        self.client = Some(client);
        if req.tag(EC_TAG_SRP_A).is_none() {
            return auth_failure(
                EC_AUTH_FAIL_CLIENT_TOO_OLD,
                "An EC client of version 3.3.0 or later is required.",
            );
        }
        if req.tag(EC_TAG_VERSION_ID).is_some() {
            return auth_failure(
                EC_AUTH_FAIL_INCOMPATIBLE,
                "You cannot connect to a release version from an arbitrary development \
                 snapshot! *sigh* possible crash prevented",
            );
        }
        let Some(proto) = req.tag(EC_TAG_PROTOCOL_VERSION).filter(|t| t.is_int()) else {
            return auth_failure(EC_AUTH_FAIL_INCOMPATIBLE, "Missing protocol version tag.");
        };
        let proto = proto.as_int() as u16;
        if proto != EC_CURRENT_PROTOCOL_VERSION {
            return auth_failure(
                EC_AUTH_FAIL_INCOMPATIBLE,
                &format!(
                    "Invalid protocol version.( {proto:#06x} != {EC_CURRENT_PROTOCOL_VERSION:#06x} )"
                ),
            );
        }
        let response = match self.challenge(req, creds, limiter, now) {
            Some(r) => r,
            None => return auth_failure(EC_AUTH_FAIL_INCOMPATIBLE, INVALID_HANDSHAKE),
        };
        self.state = State::SaltSent;
        // What the client can read.
        if req.tag(EC_TAG_CAN_ZLIB).is_some() {
            self.my_flags |= EC_FLAG_ZLIB;
        }
        if req.tag(EC_TAG_PREFER_NO_ZLIB).is_some() {
            self.local_peer = true;
        }
        if req.tag(EC_TAG_CAN_UTF8_NUMBERS).is_some() {
            self.my_flags |= EC_FLAG_UTF8_NUMBERS;
        }
        if req.tag(EC_TAG_CAN_LARGE_TAG_COUNT).is_some() {
            self.my_flags |= EC_FLAG_LARGE_TAG_COUNT;
        }
        self.notify = req.tag(EC_TAG_CAN_NOTIFY).is_some();
        self.partial_update = req.tag(EC_TAG_CAN_PARTIAL_UPDATE).is_some();
        response
    }

    /// The `try` block of `Authenticate`: AUTH_SALT, or `None` for a
    /// malformed or incompatible handshake.
    fn challenge(
        &mut self,
        req: &Packet,
        creds: &Credentials,
        limiter: &mut AuthLimiter,
        now: u64,
    ) -> Option<Packet> {
        let offer_len = req.tag(EC_TAG_CAN_AEAD)?.data.len();
        if offer_len == 0 || offer_len > 2 {
            return None;
        }
        field(req, EC_TAG_CAN_AEAD, offer_len).ok()?;
        field(req, EC_TAG_AEAD_CLIENT_NONCE, crypt::NONCE_TAG_LEN).ok()?;
        field(req, EC_TAG_AEAD_CLIENT_PUBKEY, crypt::X25519_KEY_LEN).ok()?;
        // A compatible handshake counts against the lockout before any
        // expensive work.
        limiter.note_failure(self.peer, now);
        let aead = negotiate(req);
        let a_pub = field(req, EC_TAG_SRP_A, srp::WIDTH).ok()?;
        let credential = *field(req, EC_TAG_SRP_CREDENTIAL, 1).ok()?.first()?;
        let aead = aead?;
        let verifier = if credential == srp::Credential::Password as u8 {
            creds.password.as_ref()?
        } else {
            &creds.dummy
        };
        let server = srp::Server::start(verifier, credential, &a_pub, &aead.transcript).ok()?;
        let salt = Packet::new(EC_OP_AUTH_SALT)
            .with(Tag::int(EC_TAG_AEAD_CIPHER, u64::from(aead.cipher)))
            .with(Tag::custom(
                EC_TAG_AEAD_SERVER_NONCE,
                aead.server_nonce.to_vec(),
            ))
            .with(Tag::custom(
                EC_TAG_AEAD_SERVER_PUBKEY,
                aead.server_pub.to_vec(),
            ))
            .with(Tag::custom(EC_TAG_SRP_B, server.public().to_vec()))
            .with(Tag::custom(EC_TAG_SRP_SALT, server.salt().to_vec()))
            .with(Tag::custom(EC_TAG_SRP_PROFILE, srp::PROFILE_BYTES.to_vec()));
        // ActivateAEAD: keyed from the ephemeral exchange alone; AUTH_SALT
        // goes out in clear, everything after it sealed.
        let session = Session::new_server(
            aead.cipher,
            &aead.shared[..],
            &aead.server_nonce,
            &aead.client_nonce,
            &aead.transcript,
        )?;
        self.session = Some(session);
        self.seal_after_next = true;
        self.srp = Some((server, credential));
        Some(salt)
    }

    fn auth_passwd(&mut self, req: &Packet, id: &Identity, limiter: &mut AuthLimiter) -> Packet {
        let proof = field(req, EC_TAG_SRP_M1, 32).ok();
        let present = req.tag(EC_TAG_SRP_M1).is_some();
        // Every packet after the keys is sealed, so this one was.
        let m2 = match (self.srp.take(), &proof) {
            (Some((server, _)), Some(m1)) => server.verify(m1),
            _ => None,
        };
        if let Some(m2) = m2 {
            limiter.note_success(self.peer);
            let mut ok = Packet::new(EC_OP_AUTH_OK)
                .with(Tag::string(EC_TAG_SERVER_VERSION, &id.version))
                .with(Tag::custom(EC_TAG_SRP_M2, m2.to_vec()));
            if self.my_flags & EC_FLAG_LARGE_TAG_COUNT != 0 {
                ok = ok.with(Tag::empty(EC_TAG_CAN_LARGE_TAG_COUNT));
            }
            ok = ok.with(Tag::int(EC_TAG_SESSION_ID, id.session_id));
            if self.partial_update {
                // Confirmed, so the client stops reading absence as removal.
                ok = ok.with(Tag::empty(EC_TAG_CAN_PARTIAL_UPDATE));
            }
            // Served unconditionally: the client history, deleting
            // complete files, and the shared folders' configuration. The
            // other capabilities that advertise requests (multi-search,
            // chat, search list, Kad lookups, search-all, metadata) are
            // echoed once those requests are served: a client that sees one
            // sends them.
            return ok
                .with(Tag::empty(EC_TAG_CAN_CLIENT_HISTORY))
                .with(Tag::empty(EC_TAG_CAN_DELETE_COMPLETE))
                .with(Tag::empty(EC_TAG_CAN_SHAREDDIRS_CONFIG));
        }
        if present && proof.is_none() {
            return auth_failure(EC_AUTH_FAIL_INCOMPATIBLE, INVALID_HANDSHAKE);
        }
        let err = if present {
            "Authentication failed: wrong password."
        } else {
            "Authentication failed: missing password."
        };
        self.log.push(err.into());
        auth_failure(EC_AUTH_FAIL_REJECTED, err)
    }

    /// `WritePacket`: the frame for `p`, compressed when large and the
    /// client inflates (not for a local client, below 256 MiB), sealed once
    /// the keys are on.
    pub fn frame(&mut self, p: &Packet) -> Result<Vec<u8>, String> {
        let plain_len = p
            .encode(WireOpts {
                utf8_numbers: false,
                large_tag_count: self.my_flags & EC_FLAG_LARGE_TAG_COUNT != 0,
            })
            .len();
        let local_bypass = self.local_peer && plain_len <= MAX_PACKET;
        let mut flags = 0x20;
        if plain_len > MAX_UNCOMPRESSED && self.my_flags & EC_FLAG_ZLIB != 0 && !local_bypass {
            flags |= EC_FLAG_ZLIB;
        } else {
            flags |= EC_FLAG_UTF8_NUMBERS;
        }
        flags |= EC_FLAG_LARGE_TAG_COUNT;
        flags &= self.my_flags | 0x20;
        let mut body = p.encode(WireOpts::from_flags(flags));
        if flags & EC_FLAG_ZLIB != 0 {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&body).map_err(|e| e.to_string())?;
            body = e.finish().map_err(|e| e.to_string())?;
        }
        if self.sealing {
            let s = self.session.as_mut().ok_or("sealing without keys")?;
            body = s.seal(&body).ok_or("sealing failed")?;
            flags |= EC_FLAG_ENCRYPTED;
        }
        // SendPacket: armed after the write, so AUTH_SALT is the last clear one.
        if self.seal_after_next {
            self.seal_after_next = false;
            self.sealing = self.session.is_some();
        }
        let mut frame = Vec::with_capacity(8 + body.len());
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }
}
