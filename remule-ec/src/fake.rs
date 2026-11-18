// SPDX-License-Identifier: GPL-2.0-or-later
//! A stand-in for `amuled`'s EC listener: the server half of the 3.3 login
//! (EC_SRP.md, "Four messages") over a real socket, then a caller-supplied
//! request handler.
//!
//! It exists for tests and for working on the GUI without a daemon (see
//! `examples/fake_amuled.rs`). It is not a daemon and implements no P2P.
//! Available under `cfg(test)` or the `fake-daemon` feature.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::client::field;
use crate::codes::*;
use crate::crypt::{self, Ephemeral, Session};
use crate::srp;
use crate::tag::{Packet, Tag, WireOpts};

/// One accepted connection, after or during login.
pub struct Conn {
    stream: TcpStream,
    session: Option<Session>,
    seal: bool,
}

type R<T> = Result<T, String>;

impl Conn {
    pub fn recv(&mut self) -> R<Packet> {
        let mut h = [0u8; 8];
        self.stream.read_exact(&mut h).map_err(|e| e.to_string())?;
        let flags = u32::from_be_bytes(h[0..4].try_into().unwrap());
        let len = u32::from_be_bytes(h[4..8].try_into().unwrap()) as usize;
        if len > 16 * 1024 * 1024 {
            return Err("request too big".into());
        }
        let mut body = vec![0u8; len];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| e.to_string())?;
        if flags & EC_FLAG_ENCRYPTED != 0 {
            let s = self
                .session
                .as_mut()
                .ok_or("sealed packet before key setup")?;
            body = s.open(&body).ok_or("client packet failed authentication")?;
        } else if self.session.is_some() {
            return Err("client sent a clear packet after key setup".into());
        }
        Packet::decode(&body, WireOpts::from_flags(flags)).map_err(|e| e.to_string())
    }

    /// Send a reply; `zlib` compresses it as the daemon does large ones.
    pub fn send(&mut self, p: &Packet, zlib: bool) -> R<()> {
        let opts = WireOpts {
            utf8_numbers: !zlib,
            large_tag_count: true,
        };
        let mut flags = 0x20
            | EC_FLAG_LARGE_TAG_COUNT
            | if zlib {
                EC_FLAG_ZLIB
            } else {
                EC_FLAG_UTF8_NUMBERS
            };
        let mut body = p.encode(opts);
        if zlib {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&body).map_err(|e| e.to_string())?;
            body = e.finish().map_err(|e| e.to_string())?;
        }
        if self.seal {
            body = self
                .session
                .as_mut()
                .ok_or("no keys")?
                .seal(&body)
                .ok_or("seal failed")?;
            flags |= EC_FLAG_ENCRYPTED;
        }
        let mut frame = flags.to_be_bytes().to_vec();
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        self.stream.write_all(&frame).map_err(|e| e.to_string())
    }

    /// Serve requests until the client hangs up.
    pub fn serve(mut self, mut handler: impl FnMut(&Packet) -> Packet) -> R<()> {
        loop {
            let req = match self.recv() {
                Ok(r) => r,
                Err(_) => return Ok(()), // hung up
            };
            let reply = handler(&req);
            let big = reply.encode(WireOpts::default()).len() > 1024;
            self.send(&reply, big)?;
        }
    }
}

/// How the fake daemon behaves during login.
#[derive(Clone, Debug)]
pub struct Login {
    /// MD5 hex of the EC password it accepts.
    pub digest: String,
    pub version: String,
    /// Send a wrong M2, as an impostor that relayed the exchange would.
    pub tamper_m2: bool,
}

/// Run the server half of the login. `Ok(None)` means the client was
/// refused (wrong password, or the test asked for a bad M2).
pub fn accept(stream: TcpStream, login: &Login) -> R<Option<Conn>> {
    let mut c = Conn {
        stream,
        session: None,
        seal: false,
    };

    let req = c.recv()?;
    if req.opcode != EC_OP_AUTH_REQ {
        return Err(format!("expected AUTH_REQ, got {:#x}", req.opcode));
    }
    if req.tag(EC_TAG_PROTOCOL_VERSION).map(Tag::as_int)
        != Some(u64::from(EC_CURRENT_PROTOCOL_VERSION))
    {
        return Err("wrong protocol version".into());
    }
    if req.tag(EC_TAG_VERSION_ID).is_some() {
        return Err("a release daemon refuses snapshot clients (EC_TAG_VERSION_ID sent)".into());
    }
    let e = |x: crate::Error| x.to_string();
    let offer_len = req.tag(EC_TAG_CAN_AEAD).map_or(0, |t| t.data.len());
    let offered = field(&req, EC_TAG_CAN_AEAD, offer_len).map_err(e)?;
    let client_nonce = field(&req, EC_TAG_AEAD_CLIENT_NONCE, 32).map_err(e)?;
    let client_pub = field(&req, EC_TAG_AEAD_CLIENT_PUBKEY, 32).map_err(e)?;
    let a_pub = field(&req, EC_TAG_SRP_A, srp::WIDTH).map_err(e)?;
    if field(&req, EC_TAG_SRP_CREDENTIAL, 1).map_err(e)? != [0] {
        return Err("expected the password credential".into());
    }

    // NegotiateAEAD honours a ChaCha20-first offer, else picks AES.
    let cipher = if offered.first() == Some(&crypt::CIPHER_CHACHA20_POLY1305) {
        crypt::CIPHER_CHACHA20_POLY1305
    } else if offered.contains(&crypt::CIPHER_AES128_GCM) {
        crypt::CIPHER_AES128_GCM
    } else {
        return Err("no cipher in common".into());
    };
    let server_nonce: [u8; 32] = crypt::random_bytes();
    let eph = Ephemeral::generate();
    let server_pub = eph.public;
    let shared = eph.agree(&client_pub).ok_or("bad client key")?;
    let transcript = crypt::build_transcript(
        &offered,
        cipher,
        &client_nonce,
        &server_nonce,
        &client_pub,
        &server_pub,
    );
    let salt: [u8; 16] = crypt::random_bytes();
    let challenge = srp::server::challenge(&login.digest, &salt, &a_pub, &transcript);

    let salt_pkt = Packet::new(EC_OP_AUTH_SALT)
        .with(Tag::int(EC_TAG_AEAD_CIPHER, u64::from(cipher)))
        .with(Tag::custom(EC_TAG_AEAD_SERVER_NONCE, server_nonce.to_vec()))
        .with(Tag::custom(EC_TAG_AEAD_SERVER_PUBKEY, server_pub.to_vec()))
        .with(Tag::custom(EC_TAG_SRP_B, challenge.b_pub.clone()))
        .with(Tag::custom(EC_TAG_SRP_SALT, salt.to_vec()))
        .with(Tag::custom(EC_TAG_SRP_PROFILE, srp::PROFILE_BYTES.to_vec()));
    c.send(&salt_pkt, false)?;
    // EnableAEADAfterNextWrite: everything after the salt is sealed.
    c.session = Some(
        Session::new_server(
            cipher,
            &shared[..],
            &server_nonce,
            &client_nonce,
            &transcript,
        )
        .ok_or("key setup")?,
    );
    c.seal = true;

    let passwd = c.recv()?;
    if passwd.opcode != EC_OP_AUTH_PASSWD {
        return Err("expected AUTH_PASSWD".into());
    }
    let m1 = field(&passwd, EC_TAG_SRP_M1, 32).map_err(e)?;
    let Some(mut m2) = challenge.verify(&m1) else {
        let fail = Packet::new(EC_OP_AUTH_FAIL)
            .with(Tag::string(
                EC_TAG_STRING,
                "Authentication failed: wrong password.",
            ))
            .with(Tag::int(
                EC_TAG_AUTH_FAIL_REASON,
                u64::from(EC_AUTH_FAIL_REJECTED),
            ));
        c.send(&fail, false)?;
        return Ok(None);
    };
    if login.tamper_m2 {
        m2[0] ^= 1;
    }
    let ok = Packet::new(EC_OP_AUTH_OK)
        .with(Tag::string(EC_TAG_SERVER_VERSION, &login.version))
        .with(Tag::custom(EC_TAG_SRP_M2, m2.to_vec()))
        .with(Tag::empty(EC_TAG_CAN_LARGE_TAG_COUNT))
        .with(Tag::int(EC_TAG_SESSION_ID, 0xDEAD_BEEF_0000_0001))
        .with(Tag::empty(EC_TAG_CAN_SEARCH_ALL));
    c.send(&ok, false)?;
    Ok((!login.tamper_m2).then_some(c))
}
