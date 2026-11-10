// SPDX-License-Identifier: GPL-2.0-or-later
//! A blocking EC client connection: framing, login, and request/reply.
//!
//! Port of the client half of `ECSocket.cpp` (framing, sealing, zlib) and
//! `RemoteConnect.cpp` (the login handshake). EC is strictly request/reply in
//! FIFO order when the client does not advertise `EC_TAG_CAN_NOTIFY`, so a
//! plain blocking socket is enough: one `request` is one write and one read.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::codes::*;
use crate::crypt::{self, Ephemeral, Session};
use crate::srp::{self, Credential};
use crate::tag::{Packet, Tag, WireOpts};
use crate::Error;

const HEADER_LEN: usize = 8;
/// ReadHeader's post-auth bound on one packet.
const MAX_PACKET: usize = 256 * 1024 * 1024;
/// Bound on a zlib body once inflated, so a tiny bomb cannot exhaust memory.
const MAX_INFLATED: u64 = 1024 * 1024 * 1024;

/// How to reach and identify ourselves to the daemon.
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    /// MD5 hex of the EC password, as aMule clients store it. Use
    /// [`srp::password_digest`] to make one from the plaintext.
    pub password_digest: String,
    pub client_name: String,
    pub client_version: String,
    pub connect_timeout: Duration,
    /// Per-reply read timeout. Generous: a daemon serialising a huge shared
    /// list can take a while to answer.
    pub io_timeout: Duration,
}

impl ConnectOptions {
    pub fn new(host: impl Into<String>, port: u16, password_digest: impl Into<String>) -> Self {
        ConnectOptions {
            host: host.into(),
            port,
            password_digest: password_digest.into(),
            client_name: "remule-gui".into(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(60),
        }
    }
}

/// What the daemon told us in `EC_OP_AUTH_OK`.
#[derive(Clone, Debug, Default)]
pub struct ServerInfo {
    pub version: String,
    pub cipher: &'static str,
    pub session_id: u64,
    pub large_tag_count: bool,
    pub can_search_all: bool,
}

/// An authenticated EC connection.
pub struct Client {
    stream: TcpStream,
    session: Option<Session>,
    sealing: bool,
    rx_sealed_seen: bool,
    tx_large_count: bool,
    info: ServerInfo,
}

/// A refusal's machine-readable reason (`EC_AUTH_FAIL_REASON`).
pub fn auth_fail_text(reason: u8) -> &'static str {
    match reason {
        EC_AUTH_FAIL_CLIENT_TOO_OLD => "client too old",
        EC_AUTH_FAIL_NO_PASSWORD => "the daemon has no EC password set",
        EC_AUTH_FAIL_RATE_LIMITED => "too many attempts; rate limited",
        EC_AUTH_FAIL_INCOMPATIBLE => "incompatible daemon or malformed handshake",
        EC_AUTH_FAIL_REJECTED => "wrong password",
        _ => "unknown reason",
    }
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// `ECSRP::Field`: exactly one custom tag of that name, `size` bytes, no children.
pub(crate) fn field(p: &Packet, name: u16, size: usize) -> Result<Vec<u8>, Error> {
    let mut found = p.tags_named(name);
    let t = found
        .next()
        .ok_or_else(|| Error::Auth(format!("handshake field 0x{name:04x} missing")))?;
    if found.next().is_some() {
        return Err(Error::Auth(format!(
            "duplicate handshake field 0x{name:04x}"
        )));
    }
    if t.ty != EC_TAGTYPE_CUSTOM || t.data.len() != size || !t.children.is_empty() {
        return Err(Error::Auth(format!(
            "malformed handshake field 0x{name:04x}"
        )));
    }
    Ok(t.data.clone())
}

fn auth_failure(p: &Packet) -> Error {
    Error::AuthFailed {
        reason: p.tag(EC_TAG_AUTH_FAIL_REASON).map(|t| t.as_int() as u8),
        message: p.message().unwrap_or_else(|| "handshake failed".into()),
        retry_after: p.tag(EC_TAG_AUTH_RETRY_AFTER).map(Tag::as_int),
    }
}

impl Client {
    /// Connect, log in, and verify the daemon's proof.
    pub fn connect(opts: &ConnectOptions) -> Result<Client, Error> {
        if !srp::is_password_digest(&opts.password_digest) {
            return Err(Error::Auth("you must specify a non-empty password".into()));
        }
        // aMule's EC listens on IPv4 only.
        let addrs: Vec<SocketAddr> = (opts.host.as_str(), opts.port).to_socket_addrs()?.collect();
        let addr = addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.first())
            .copied()
            .ok_or_else(|| Error::Protocol(format!("could not resolve {}", opts.host)))?;
        let stream = TcpStream::connect_timeout(&addr, opts.connect_timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(opts.io_timeout))?;
        stream.set_write_timeout(Some(opts.io_timeout))?;

        let mut c = Client {
            stream,
            session: None,
            sealing: false,
            rx_sealed_seen: false,
            tx_large_count: false,
            info: ServerInfo::default(),
        };
        c.login(opts, is_local(addr.ip()))?;
        Ok(c)
    }

    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    fn login(&mut self, opts: &ConnectOptions, local: bool) -> Result<(), Error> {
        let mut srp = srp::Client::start();
        let eph = Ephemeral::generate();
        let client_nonce: [u8; crypt::NONCE_TAG_LEN] = crypt::random_bytes();
        let client_pub = eph.public;

        // Capabilities, as CECLoginPacket. Deliberately not advertised:
        // CAN_NOTIFY (we never read unsolicited packets), CAN_PARTIAL_UPDATE /
        // CAN_PARTIAL_SEARCH (every FULL reply is then the complete state) and
        // CAN_MULTI_SEARCH (one search at a time, on the legacy sentinel id).
        let mut req = Packet::new(EC_OP_AUTH_REQ)
            .with(Tag::string(EC_TAG_CLIENT_NAME, &opts.client_name))
            .with(Tag::string(EC_TAG_CLIENT_VERSION, &opts.client_version))
            .with(Tag::int(
                EC_TAG_PROTOCOL_VERSION,
                u64::from(EC_CURRENT_PROTOCOL_VERSION),
            ))
            .with(Tag::empty(EC_TAG_CAN_ZLIB))
            .with(Tag::empty(EC_TAG_CAN_UTF8_NUMBERS))
            .with(Tag::empty(EC_TAG_CAN_LARGE_TAG_COUNT));
        if local {
            req = req.with(Tag::empty(EC_TAG_PREFER_NO_ZLIB));
        }
        req = req
            .with(Tag::custom(
                EC_TAG_CAN_AEAD,
                crypt::OFFERED_CIPHERS.to_vec(),
            ))
            .with(Tag::custom(EC_TAG_AEAD_CLIENT_NONCE, client_nonce.to_vec()))
            .with(Tag::custom(EC_TAG_AEAD_CLIENT_PUBKEY, client_pub.to_vec()))
            .with(Tag::custom(EC_TAG_SRP_A, srp.public().to_vec()))
            .with(Tag::custom(
                EC_TAG_SRP_CREDENTIAL,
                vec![Credential::Password as u8],
            ));
        self.send(&req)?;

        // AUTH_SALT arrives in clear.
        let salt_reply = self.recv()?;
        if salt_reply.opcode != EC_OP_AUTH_SALT {
            return Err(auth_failure(&salt_reply));
        }
        let b_pub = field(&salt_reply, EC_TAG_SRP_B, srp::WIDTH).map_err(|_| {
            Error::Auth("an EC daemon of version 3.3.0 or later is required".into())
        })?;
        let salt = field(&salt_reply, EC_TAG_SRP_SALT, srp::SALT_LEN)?;
        if field(&salt_reply, EC_TAG_SRP_PROFILE, 4)? != srp::PROFILE_BYTES {
            return Err(Error::Auth("unsupported SRP profile".into()));
        }

        // Transport keys (RemoteConnect::SetupAEADFromSalt). No fallback to clear.
        let mut ciphers = salt_reply.tags_named(EC_TAG_AEAD_CIPHER);
        let cipher_tag = ciphers
            .next()
            .ok_or_else(|| Error::Auth("the daemon offered no encryption".into()))?;
        if ciphers.next().is_some() || !cipher_tag.is_int() || cipher_tag.as_int() > 255 {
            return Err(Error::Auth("invalid AEAD cipher choice".into()));
        }
        let cipher = cipher_tag.as_int() as u8;
        if !crypt::OFFERED_CIPHERS.contains(&cipher) {
            return Err(Error::Auth(
                "the daemon chose a cipher we did not offer".into(),
            ));
        }
        let server_nonce = field(&salt_reply, EC_TAG_AEAD_SERVER_NONCE, crypt::NONCE_TAG_LEN)?;
        let server_pub = field(
            &salt_reply,
            EC_TAG_AEAD_SERVER_PUBKEY,
            crypt::X25519_KEY_LEN,
        )?;
        let shared = eph
            .agree(&server_pub)
            .ok_or_else(|| Error::Auth("bad daemon public key".into()))?;
        let transcript = crypt::build_transcript(
            &crypt::OFFERED_CIPHERS,
            cipher,
            &client_nonce,
            &server_nonce,
            &client_pub,
            &server_pub,
        );
        let session = Session::new_client(
            cipher,
            &shared[..],
            &server_nonce,
            &client_nonce,
            &transcript,
        )
        .ok_or_else(|| Error::Auth("key derivation failed".into()))?;
        self.session = Some(session);
        self.sealing = true;

        // SRP proof, sealed.
        let m1 = srp.respond(
            &opts.password_digest,
            Credential::Password,
            &salt,
            &b_pub,
            &transcript,
        )?;
        self.send(&Packet::new(EC_OP_AUTH_PASSWD).with(Tag::custom(EC_TAG_SRP_M1, m1.to_vec())))?;

        let ok = self.recv()?;
        if ok.opcode != EC_OP_AUTH_OK {
            return Err(auth_failure(&ok));
        }
        // recv() already refused a clear packet once keys exist, so reaching
        // here means AUTH_OK arrived sealed. Now the daemon must prove it holds
        // the credential over this exact handshake.
        let m2 = field(&ok, EC_TAG_SRP_M2, 32).unwrap_or_default();
        if !srp.verify(&m2) {
            return Err(Error::Auth(
                "the daemon failed to prove it knows the password".into(),
            ));
        }

        self.tx_large_count = ok.tag(EC_TAG_CAN_LARGE_TAG_COUNT).is_some();
        self.info = ServerInfo {
            version: ok
                .tag(EC_TAG_SERVER_VERSION)
                .map(Tag::as_str)
                .unwrap_or_default(),
            cipher: crypt::cipher_name(cipher),
            session_id: ok.tag(EC_TAG_SESSION_ID).map_or(0, Tag::as_int),
            large_tag_count: self.tx_large_count,
            can_search_all: ok.tag(EC_TAG_CAN_SEARCH_ALL).is_some(),
        };
        Ok(())
    }

    /// Send one request and read its reply.
    pub fn request(&mut self, p: &Packet) -> Result<Packet, Error> {
        self.send(p)?;
        self.recv()
    }

    fn send(&mut self, p: &Packet) -> Result<(), Error> {
        let opts = WireOpts {
            utf8_numbers: true,
            large_tag_count: self.tx_large_count,
        };
        let mut flags = 0x20 | EC_FLAG_UTF8_NUMBERS;
        if opts.large_tag_count {
            flags |= EC_FLAG_LARGE_TAG_COUNT;
        }
        let mut body = p.encode(opts);
        if self.sealing {
            let s = self
                .session
                .as_mut()
                .ok_or_else(|| Error::Protocol("sealing without keys".into()))?;
            let sealed = s
                .seal(&body)
                .ok_or_else(|| Error::Protocol("sealing failed".into()))?;
            crypt::wipe(&mut body);
            body = sealed;
            flags |= EC_FLAG_ENCRYPTED;
        }
        let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
        frame.extend_from_slice(&flags.to_be_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        self.stream.write_all(&frame)?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Packet, Error> {
        let mut header = [0u8; HEADER_LEN];
        read_exact(&mut self.stream, &mut header)?;
        let flags = u32::from_be_bytes(header[0..4].try_into().unwrap());
        let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        if flags & 0x60 != 0x20 || flags & EC_FLAG_UNKNOWN_MASK != 0 {
            return Err(Error::Protocol(format!(
                "packet has invalid flags {flags:#x}"
            )));
        }
        if len > MAX_PACKET {
            return Err(Error::Protocol(format!("packet too big: {len} bytes")));
        }
        let mut body = vec![0u8; len];
        read_exact(&mut self.stream, &mut body)?;

        let encrypted = flags & EC_FLAG_ENCRYPTED != 0;
        if let Some(session) = self.session.as_mut() {
            if !encrypted {
                return Err(Error::Protocol(
                    "unencrypted packet after key setup; dropping the connection".into(),
                ));
            }
            body = session.open(&body).ok_or_else(|| {
                Error::Protocol("EC packet failed authentication; dropping the connection".into())
            })?;
            self.rx_sealed_seen = true;
        } else if encrypted {
            return Err(Error::Protocol("encrypted packet before key setup".into()));
        }

        if flags & EC_FLAG_ZLIB != 0 {
            let mut out = Vec::new();
            flate2::read::ZlibDecoder::new(&body[..])
                .take(MAX_INFLATED)
                .read_to_end(&mut out)
                .map_err(|e| Error::Protocol(format!("zlib: {e}")))?;
            body = out;
        }
        Packet::decode(&body, WireOpts::from_flags(flags))
    }
}

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> Result<(), Error> {
    s.read_exact(buf).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => Error::Closed,
        _ => Error::Io(e),
    })
}

/// End-to-end tests against the in-process fake daemon (`crate::fake`),
/// which implements the server half of the login from the spec.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake;
    use crate::model::{PartFileCmd, SearchKind, SearchParams};
    use std::net::TcpListener;
    use std::thread;

    const DIGEST: &str = "5ebe2294ecd0e0f08eab7690d2a6ee69"; // md5("secret")

    fn daemon(tamper_m2: bool) -> (u16, thread::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let login = fake::Login {
            digest: DIGEST.into(),
            version: "3.3.0-fake".into(),
            tamper_m2,
        };
        let h = thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let Some(conn) = fake::accept(s, &login).unwrap() else {
                return;
            };
            conn.serve(|req| match req.opcode {
                EC_OP_STAT_REQ => Packet::new(EC_OP_STATS)
                    .with(Tag::int(EC_TAG_STATS_DL_SPEED, 123_456))
                    .with(Tag::int(EC_TAG_STATS_UL_SPEED, 7))
                    .with(
                        Tag::empty(EC_TAG_STATS_LOGGER_MESSAGE)
                            .with(Tag::string(EC_TAG_STRING, "line one"))
                            .with(Tag::string(EC_TAG_STRING, "line two")),
                    )
                    .with(Tag::int(EC_TAG_CONNSTATE, 0x14).with(Tag::int(EC_TAG_CLIENT_ID, 0))),
                EC_OP_SEARCH_START => {
                    let t = &req.tags[0];
                    assert_eq!(t.name, EC_TAG_SEARCH_TYPE);
                    assert_eq!(t.as_int(), u64::from(EC_SEARCH_KAD));
                    assert_eq!(t.child_str(EC_TAG_SEARCH_NAME), "ubuntu iso");
                    Packet::new(EC_OP_STRINGS)
                        .with(Tag::string(EC_TAG_STRING, "Search in progress."))
                }
                // Big enough that the fake daemon compresses it.
                EC_OP_GET_DLOAD_QUEUE => {
                    let mut p = Packet::new(EC_OP_DLOAD_QUEUE);
                    for i in 0..200u64 {
                        p = p.with(
                            Tag::int(EC_TAG_PARTFILE, i)
                                .with(Tag::string(EC_TAG_PARTFILE_NAME, &format!("file {i}"))),
                        );
                    }
                    p
                }
                EC_OP_PARTFILE_PAUSE => {
                    Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, "FileHash not found"))
                }
                _ => Packet::new(EC_OP_NOOP),
            })
            .unwrap();
        });
        (port, h)
    }

    fn opts(port: u16, password: &str) -> ConnectOptions {
        ConnectOptions::new("127.0.0.1", port, srp::password_digest(password))
    }

    #[test]
    fn logs_in_and_runs_requests_over_the_sealed_channel() {
        assert_eq!(srp::password_digest("secret"), DIGEST);
        let (port, daemon) = daemon(false);

        let mut c = Client::connect(&opts(port, "secret")).expect("login");
        assert_eq!(c.info().version, "3.3.0-fake");
        assert_eq!(c.info().cipher, "ChaCha20-Poly1305");
        assert!(c.info().large_tag_count);

        let stats = c.stats().unwrap();
        assert_eq!((stats.dl_speed, stats.ul_speed), (123_456, 7));
        assert_eq!(stats.new_log_lines, ["line one", "line two"]);
        assert!(stats.conn.kad_connected() && stats.conn.kad_running());

        let params = SearchParams {
            text: " ubuntu iso ".into(),
            ..Default::default()
        };
        assert_eq!(
            c.search_start(SearchKind::Kad, &params).unwrap(),
            "Search in progress."
        );

        let q = c.download_queue().unwrap();
        assert_eq!(q.len(), 200);
        assert_eq!(q[199].name, "file 199");

        // EC_OP_FAILED is a recoverable error carrying the daemon's message.
        let err = c
            .partfile_cmd(PartFileCmd::Pause, &[([1; 16], 9)])
            .unwrap_err();
        assert!(!err.is_fatal());
        assert_eq!(err.to_string(), "FileHash not found");

        c.kad_start().unwrap();
        drop(c);
        daemon.join().unwrap();
    }

    #[test]
    fn wrong_password_is_reported_with_its_reason() {
        let (port, daemon) = daemon(false);
        match Client::connect(&opts(port, "not the password")) {
            Err(Error::AuthFailed {
                reason, message, ..
            }) => {
                assert_eq!(reason, Some(EC_AUTH_FAIL_REJECTED));
                assert!(message.contains("wrong password"));
            }
            Err(e) => panic!("unexpected error {e}"),
            Ok(_) => panic!("login must fail"),
        }
        daemon.join().unwrap();
    }

    #[test]
    fn a_daemon_that_cannot_prove_the_password_is_refused() {
        let (port, daemon) = daemon(true);
        let err = Client::connect(&opts(port, "secret"))
            .err()
            .expect("must refuse");
        assert!(err.to_string().contains("failed to prove"), "{err}");
        daemon.join().unwrap();
    }

    #[test]
    fn empty_password_is_refused_locally() {
        let err = Client::connect(&opts(1, "")).err().unwrap();
        assert!(matches!(err, Error::Auth(_)));
    }
}
