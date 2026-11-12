// SPDX-License-Identifier: GPL-2.0-or-later
//! TCP obfuscation (`CEncryptedStreamSocket`, EncryptedStreamSocket.cpp), sans IO.
//!
//! **Client ↔ client.** The connecting client A knows B's user hash:
//!
//! ```text
//! keys:  A send = B recv = RC4(MD5(<UserHashB 16><34><RandomKeyPartA 4>)), 1024 bytes dropped
//!        A recv = B send = the same with 203
//! A → B: <Marker 1><RandomKeyPartA 4> then encrypted
//!        <MAGICVALUE_SYNC 4><MethodsSupported 1><MethodPreferred 1><PaddingLen 1><Padding>
//! B → A: encrypted <MAGICVALUE_SYNC 4><MethodSelected 1><PaddingLen 1><Padding>
//! ```
//!
//! **Client → server.** Diffie-Hellman, g = 2, over the 768-bit prime
//! [`DH768_P`], with a 128-bit secret; the shared S (96 bytes, big-endian)
//! keys the streams as `MD5(<S 96><34>)` (client send) and `MD5(<S><203>)`:
//!
//! ```text
//! C → S: <Marker 1><g^a mod p 96><PaddingLen 1><Padding>          all plain
//! S → C: <g^b mod p 96> then encrypted
//!        <MAGICVALUE_SYNC 4><MethodsSupported 1><MethodPreferred 1><PaddingLen 1><Padding>
//! C → S: encrypted <MAGICVALUE_SYNC 4><MethodSelected 1><PaddingLen 1><Padding>,
//!        held back and sent in front of the client's first packet
//! ```
//!
//! The marker is any byte but the three protocol bytes (0xE3, 0xD4, 0xC5),
//! which is how the receiving side tells an obfuscated stream from a plain one.
//!
//! Deviation: when the peer's first packet arrives in the same read as the
//! end of its handshake, aMule hands those bytes on undecrypted
//! (`ECS_NEGOTIATING` in `Read`); this decrypts them, as eMule does.

use ed2k_types::protocol::Protocol;
use ed2k_types::Md4Hash;
use num_bigint::BigUint;
use rand::{Rng, RngCore};

use crate::rc4::Rc4;

/// `MAGICVALUE_REQUESTER`: appended to the key data for the connecting side's sends.
pub const MAGICVALUE_REQUESTER: u8 = 34;
/// `MAGICVALUE_SERVER`: appended to the key data for the accepting side's sends.
pub const MAGICVALUE_SERVER: u8 = 203;
/// `MAGICVALUE_SYNC`: what each side's encrypted part starts with.
pub const MAGICVALUE_SYNC: u32 = 0x835E_6FC4;
/// `ENM_OBFUSCATION`: the only encryption method there is.
pub const ENM_OBFUSCATION: u8 = 0x00;
/// `DHAGREEMENT_A_BITS`: the size of the client's DH secret.
pub const DH_SECRET_BYTES: usize = 128 / 8;
/// `PRIMESIZE_BYTES`
pub const PRIME_BYTES: usize = 96;
/// `GetCryptTCPPaddingLength`'s default and maximum.
pub const DEFAULT_MAX_PADDING: u8 = 254;
/// Padding towards a server is `rand % 16`.
pub const SERVER_MAX_PADDING: u8 = 15;

/// `dh768_p`, the fixed prime of the client-server key agreement.
pub const DH768_P: [u8; PRIME_BYTES] = [
    0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36, 0xE8, 0x86, 0xEB, 0x3C,
    0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D, 0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7,
    0x21, 0xFC, 0x28, 0x63, 0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
    0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4, 0x5A, 0xD5, 0xE0, 0x74,
    0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34, 0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91,
    0x42, 0xFB, 0x42, 0x68, 0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
];

/// Whether `b` starts a plain eD2k/eMule TCP packet.
pub fn is_protocol_byte(b: u8) -> bool {
    b == Protocol::Edonkey as u8 || b == Protocol::Packed as u8 || b == Protocol::Emule as u8
}

/// `GetSemiRandomNotProtocolMarker`.
pub fn random_marker<R: RngCore + ?Sized>(rng: &mut R) -> u8 {
    for _ in 0..128 {
        let b: u8 = rng.gen();
        if !is_protocol_byte(b) {
            return b;
        }
    }
    0x01
}

fn random_padding<R: RngCore + ?Sized>(rng: &mut R, max: u8) -> Vec<u8> {
    // aMule: GetRandomUint8() % (max + 1).
    let len = rng.gen::<u8>() as usize % (max as usize + 1);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

/// The client-client keys: (`MAGICVALUE_REQUESTER` stream, `MAGICVALUE_SERVER`
/// stream) for the accepting side's user hash and the connecting side's
/// random key part. The connecting side sends with the first.
pub fn client_keys(hash: &Md4Hash, random_key_part: u32) -> (Rc4, Rc4) {
    let mut d = [0u8; 21];
    d[..16].copy_from_slice(&hash.0);
    d[17..].copy_from_slice(&random_key_part.to_le_bytes());
    d[16] = MAGICVALUE_REQUESTER;
    let requester = Rc4::from_md5_of(&d, true);
    d[16] = MAGICVALUE_SERVER;
    (requester, Rc4::from_md5_of(&d, true))
}

/// The client-server keys from the shared secret: (client send, client receive).
pub fn server_keys(shared: &[u8; PRIME_BYTES]) -> (Rc4, Rc4) {
    let mut d = [0u8; PRIME_BYTES + 1];
    d[..PRIME_BYTES].copy_from_slice(shared);
    d[PRIME_BYTES] = MAGICVALUE_REQUESTER;
    let send = Rc4::from_md5_of(&d, true);
    d[PRIME_BYTES] = MAGICVALUE_SERVER;
    (send, Rc4::from_md5_of(&d, true))
}

fn encode_96(n: &BigUint) -> [u8; PRIME_BYTES] {
    let b = n.to_bytes_be();
    let mut out = [0u8; PRIME_BYTES];
    // Always fits: n < p < 2^768.
    out[PRIME_BYTES - b.len()..].copy_from_slice(&b);
    out
}

/// `g^secret mod p`, 96 bytes big-endian.
pub fn dh_public(secret: &[u8]) -> [u8; PRIME_BYTES] {
    let p = BigUint::from_bytes_be(&DH768_P);
    encode_96(&BigUint::from(2u8).modpow(&BigUint::from_bytes_be(secret), &p))
}

/// `other^secret mod p`, 96 bytes big-endian.
pub fn dh_shared(other: &[u8; PRIME_BYTES], secret: &[u8]) -> [u8; PRIME_BYTES] {
    let p = BigUint::from_bytes_be(&DH768_P);
    let o = BigUint::from_bytes_be(other);
    encode_96(&o.modpow(&BigUint::from_bytes_be(secret), &p))
}

/// What can go wrong in a handshake.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    #[error("obfuscation handshake: bad magic value {0:#010x}")]
    BadMagic(u32),
    #[error("obfuscation handshake: unsupported method {0:#04x}")]
    BadMethod(u8),
    #[error("obfuscation handshake still in progress")]
    NotReady,
    #[error("obfuscation handshake failed earlier")]
    Failed,
}

/// What [`StreamCrypt::receive`] produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Received {
    /// Decrypted stream data for the packet layer.
    pub data: Vec<u8>,
    /// Handshake bytes to send to the peer now.
    pub reply: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    // Accepting a client (`ONS_BASIC_CLIENTA_*`).
    ARandomPart,
    AMagic,
    AMethodsPadLen,
    APadding,
    // Connected to a client (`ONS_BASIC_CLIENTB_*`).
    BMagic,
    BMethodPadLen,
    BPadding,
    // Connected to a server (`ONS_BASIC_SERVER_*`).
    SDhAnswer,
    SMagic,
    SMethodsPadLen,
    SPadding,
}

impl Step {
    /// The steps whose bytes are sent before any key exists.
    fn is_plain(self) -> bool {
        matches!(self, Step::ARandomPart | Step::SDhAnswer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `ECS_UNKNOWN`: an incoming connection, nothing read yet.
    Unknown,
    /// `ECS_NONE`
    Plain,
    /// `ECS_NEGOTIATING`
    Negotiating(Step),
    /// `ECS_ENCRYPTING`
    Encrypting,
    Failed,
}

/// One side of an obfuscated (or plain) TCP connection.
#[derive(Debug)]
pub struct StreamCrypt {
    state: State,
    send: Option<Rc4>,
    recv: Option<Rc4>,
    buf: Vec<u8>,
    want: usize,
    /// Accepting side: our user hash, the key of incoming handshakes.
    own_hash: Md4Hash,
    /// Towards a server: our DH secret.
    dh_secret: Vec<u8>,
    /// The padding of the answer we will send.
    reply_padding: Vec<u8>,
    /// Handshake bytes held back for the front of the next send.
    pending: Vec<u8>,
    /// What the peer said it supports and prefers (`m_dbgbyEncryption*`).
    peer_methods: Option<(u8, u8)>,
}

impl StreamCrypt {
    fn new(state: State) -> Self {
        StreamCrypt {
            state,
            send: None,
            recv: None,
            buf: Vec::new(),
            want: 0,
            own_hash: Md4Hash::default(),
            dh_secret: Vec::new(),
            reply_padding: Vec::new(),
            pending: Vec::new(),
            peer_methods: None,
        }
    }

    /// A connection without obfuscation.
    pub fn plain() -> Self {
        StreamCrypt::new(State::Plain)
    }

    /// An incoming connection: obfuscated if the first byte is not a protocol
    /// byte. `max_padding` bounds our answer's padding (aMule uses
    /// [`SERVER_MAX_PADDING`] when the server is testing our port).
    pub fn incoming<R: RngCore + ?Sized>(own_hash: Md4Hash, max_padding: u8, rng: &mut R) -> Self {
        StreamCrypt::incoming_with(own_hash, random_padding(rng, max_padding))
    }

    /// [`StreamCrypt::incoming`] with the answer's padding given.
    pub fn incoming_with(own_hash: Md4Hash, reply_padding: Vec<u8>) -> Self {
        let mut s = StreamCrypt::new(State::Unknown);
        s.own_hash = own_hash;
        s.reply_padding = reply_padding;
        s
    }

    /// Connect to a client whose user hash is `target`: the connection and
    /// the bytes to send first.
    pub fn client<R: RngCore + ?Sized>(
        target: &Md4Hash,
        max_padding: u8,
        rng: &mut R,
    ) -> (Self, Vec<u8>) {
        let marker = random_marker(rng);
        let key_part = rng.next_u32();
        let padding = random_padding(rng, max_padding);
        StreamCrypt::client_with(target, marker, key_part, &padding)
    }

    /// [`StreamCrypt::client`] with the random parts given.
    pub fn client_with(
        target: &Md4Hash,
        marker: u8,
        random_key_part: u32,
        padding: &[u8],
    ) -> (Self, Vec<u8>) {
        let (mut send, recv) = client_keys(target, random_key_part);
        let mut out = vec![marker];
        out.extend_from_slice(&random_key_part.to_le_bytes());
        let mut enc = MAGICVALUE_SYNC.to_le_bytes().to_vec();
        enc.extend_from_slice(&[ENM_OBFUSCATION, ENM_OBFUSCATION, padding.len() as u8]);
        enc.extend_from_slice(padding);
        send.apply(&mut enc);
        out.extend_from_slice(&enc);
        let mut s = StreamCrypt::new(State::Negotiating(Step::BMagic));
        s.send = Some(send);
        s.recv = Some(recv);
        s.want = 4;
        (s, out)
    }

    /// Connect to a server: the connection and the bytes to send first.
    pub fn server<R: RngCore + ?Sized>(rng: &mut R) -> (Self, Vec<u8>) {
        let marker = random_marker(rng);
        let mut secret = [0u8; DH_SECRET_BYTES];
        rng.fill_bytes(&mut secret);
        let padding = random_padding(rng, SERVER_MAX_PADDING);
        let reply_padding = random_padding(rng, SERVER_MAX_PADDING);
        StreamCrypt::server_with(marker, &secret, &padding, reply_padding)
    }

    /// [`StreamCrypt::server`] with the random parts given.
    pub fn server_with(
        marker: u8,
        secret: &[u8; DH_SECRET_BYTES],
        padding: &[u8],
        reply_padding: Vec<u8>,
    ) -> (Self, Vec<u8>) {
        let mut out = vec![marker];
        out.extend_from_slice(&dh_public(secret));
        out.push(padding.len() as u8);
        out.extend_from_slice(padding);
        let mut s = StreamCrypt::new(State::Negotiating(Step::SDhAnswer));
        s.dh_secret = secret.to_vec();
        s.reply_padding = reply_padding;
        s.want = PRIME_BYTES;
        (s, out)
    }

    /// Whether the handshake is over (or there was none) and data can be sent.
    pub fn is_ready(&self) -> bool {
        matches!(
            self.state,
            State::Plain | State::Encrypting | State::Unknown
        )
    }

    /// Whether the stream is obfuscated (known once the handshake starts).
    pub fn is_obfuscated(&self) -> bool {
        matches!(self.state, State::Negotiating(_) | State::Encrypting)
    }

    /// The methods the connecting peer offered: (supported, preferred).
    pub fn peer_methods(&self) -> Option<(u8, u8)> {
        self.peer_methods
    }

    /// Handshake bytes held back for the next [`StreamCrypt::seal`]
    /// (towards a server). Taking them sends them on their own.
    pub fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    /// Prepare stream data for sending: held-back handshake bytes, then
    /// `data`, encrypted if the stream is.
    pub fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, StreamError> {
        match self.state {
            State::Unknown | State::Plain => {
                // Writing before the peer said anything settles it: plain.
                self.state = State::Plain;
                Ok(data.to_vec())
            }
            State::Encrypting => {
                let mut out = std::mem::take(&mut self.pending);
                let start = out.len();
                out.extend_from_slice(data);
                if let Some(send) = &mut self.send {
                    send.apply(&mut out[start..]);
                }
                Ok(out)
            }
            State::Negotiating(_) => Err(StreamError::NotReady),
            State::Failed => Err(StreamError::Failed),
        }
    }

    /// Split a connection whose handshake is over into its two directions,
    /// for a reader and a writer that run apart. Fails while negotiating.
    pub fn split(self) -> Result<(SendHalf, RecvHalf), StreamError> {
        match self.state {
            State::Plain | State::Unknown => Ok((
                SendHalf {
                    rc4: None,
                    pending: Vec::new(),
                },
                RecvHalf { rc4: None },
            )),
            State::Encrypting => Ok((
                SendHalf {
                    rc4: self.send,
                    pending: self.pending,
                },
                RecvHalf { rc4: self.recv },
            )),
            State::Negotiating(_) => Err(StreamError::NotReady),
            State::Failed => Err(StreamError::Failed),
        }
    }

    /// Feed bytes read from the socket.
    pub fn receive(&mut self, mut input: &[u8]) -> Result<Received, StreamError> {
        let mut out = Received::default();
        match self.state {
            State::Failed => return Err(StreamError::Failed),
            State::Plain => {
                out.data = input.to_vec();
                return Ok(out);
            }
            State::Encrypting => {
                out.data = self.decrypt(input);
                return Ok(out);
            }
            State::Unknown => {
                let Some(&first) = input.first() else {
                    return Ok(out);
                };
                if is_protocol_byte(first) {
                    self.state = State::Plain;
                    out.data = input.to_vec();
                    return Ok(out);
                }
                input = &input[1..];
                self.state = State::Negotiating(Step::ARandomPart);
                self.want = 4;
            }
            State::Negotiating(_) => {}
        }
        while let State::Negotiating(step) = self.state {
            if input.is_empty() {
                break;
            }
            let n = (self.want - self.buf.len()).min(input.len());
            self.buf.extend_from_slice(&input[..n]);
            input = &input[n..];
            if self.buf.len() < self.want {
                break;
            }
            let mut chunk = std::mem::take(&mut self.buf);
            if !step.is_plain() {
                if let Some(recv) = &mut self.recv {
                    recv.apply(&mut chunk);
                }
            }
            if let Err(e) = self.advance(step, &chunk, &mut out.reply) {
                self.state = State::Failed;
                return Err(e);
            }
        }
        if self.state == State::Encrypting && !input.is_empty() {
            out.data = self.decrypt(input);
        }
        Ok(out)
    }

    fn decrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        if let Some(recv) = &mut self.recv {
            recv.apply(&mut v);
        }
        v
    }

    fn expect(&mut self, step: Step, want: usize) {
        self.state = State::Negotiating(step);
        self.want = want;
    }

    /// The answer of the accepted or the server side.
    fn answer(&mut self) -> Vec<u8> {
        let mut v = MAGICVALUE_SYNC.to_le_bytes().to_vec();
        v.push(ENM_OBFUSCATION);
        v.push(self.reply_padding.len() as u8);
        v.extend_from_slice(&std::mem::take(&mut self.reply_padding));
        if let Some(send) = &mut self.send {
            send.apply(&mut v);
        }
        v
    }

    fn advance(&mut self, step: Step, c: &[u8], reply: &mut Vec<u8>) -> Result<(), StreamError> {
        let magic = |c: &[u8]| {
            let v = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            if v == MAGICVALUE_SYNC {
                Ok(())
            } else {
                Err(StreamError::BadMagic(v))
            }
        };
        match step {
            Step::ARandomPart => {
                let part = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                let (recv, send) = client_keys(&self.own_hash, part);
                self.recv = Some(recv);
                self.send = Some(send);
                self.expect(Step::AMagic, 4);
            }
            Step::AMagic | Step::SMagic => {
                magic(c)?;
                let next = if step == Step::AMagic {
                    Step::AMethodsPadLen
                } else {
                    Step::SMethodsPadLen
                };
                self.expect(next, 3);
            }
            Step::AMethodsPadLen | Step::SMethodsPadLen => {
                // The preferred method is not checked: there is only one.
                self.peer_methods = Some((c[0], c[1]));
                let (pad_step, done_step) = if step == Step::AMethodsPadLen {
                    (Step::APadding, Step::APadding)
                } else {
                    (Step::SPadding, Step::SPadding)
                };
                if c[2] > 0 {
                    self.expect(pad_step, c[2] as usize);
                } else {
                    return self.advance(done_step, &[], reply);
                }
            }
            Step::APadding => {
                *reply = self.answer();
                self.state = State::Encrypting;
            }
            Step::SPadding => {
                // Held back until the first packet (`ONS_BASIC_SERVER_DELAYEDSENDING`).
                self.pending = self.answer();
                self.state = State::Encrypting;
            }
            Step::BMagic => {
                magic(c)?;
                self.expect(Step::BMethodPadLen, 2);
            }
            Step::BMethodPadLen => {
                if c[0] != ENM_OBFUSCATION {
                    return Err(StreamError::BadMethod(c[0]));
                }
                if c[1] > 0 {
                    self.expect(Step::BPadding, c[1] as usize);
                } else {
                    self.state = State::Encrypting;
                }
            }
            Step::BPadding => self.state = State::Encrypting,
            Step::SDhAnswer => {
                let mut other = [0u8; PRIME_BYTES];
                other.copy_from_slice(c);
                let shared = dh_shared(&other, &self.dh_secret);
                self.dh_secret.clear();
                let (send, recv) = server_keys(&shared);
                self.send = Some(send);
                self.recv = Some(recv);
                self.expect(Step::SMagic, 4);
            }
        }
        Ok(())
    }
}

/// `EncryptionRequirement::MustRefusePlainConnection`: whether an incoming
/// plain connection must be refused while obfuscation is required. A
/// transport that obfuscates by itself satisfies the requirement; a server or
/// Kad firewall test connection is exempt unless `strict`.
pub const fn must_refuse_plain_connection(
    strict: bool,
    transport_obfuscates: bool,
    is_test_connection: bool,
) -> bool {
    !transport_obfuscates && (strict || !is_test_connection)
}

/// The sending direction of an established connection ([`StreamCrypt::split`]).
#[derive(Debug)]
pub struct SendHalf {
    rc4: Option<Rc4>,
    pending: Vec<u8>,
}

impl SendHalf {
    /// Whether the stream is obfuscated.
    pub fn is_obfuscated(&self) -> bool {
        self.rc4.is_some()
    }

    /// Held-back handshake bytes, then `data`, encrypted if the stream is.
    pub fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.pending);
        let start = out.len();
        out.extend_from_slice(data);
        if let Some(rc4) = &mut self.rc4 {
            rc4.apply(&mut out[start..]);
        }
        out
    }
}

/// The receiving direction of an established connection ([`StreamCrypt::split`]).
#[derive(Debug)]
pub struct RecvHalf {
    rc4: Option<Rc4>,
}

impl RecvHalf {
    /// Decrypt bytes read from the socket, in place.
    pub fn open(&mut self, data: &mut [u8]) {
        if let Some(rc4) = &mut self.rc4 {
            rc4.apply(data);
        }
    }
}
