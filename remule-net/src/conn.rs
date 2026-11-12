// SPDX-License-Identifier: GPL-2.0-or-later
//! A framed, optionally obfuscated, throttled eD2k TCP connection
//! (`CEMSocket` on top of `CEncryptedStreamSocket`).
//!
//! [`establish`] runs the obfuscation handshake, if any, and splits the
//! connection into a [`PacketReader`] and a [`PacketWriter`], which can run
//! in separate tasks. Reads take from the download bucket (when
//! [`PacketReader::set_download_throttled`] says so: aMule throttles only
//! sockets it downloads over), writes from the upload bucket, in fragments.

use std::sync::Arc;

use bytes::BytesMut;
use ed2k_codec::Packet;
use ed2k_crypto::stream::{self, RecvHalf, SendHalf, StreamCrypt, StreamError};
use ed2k_types::Md4Hash;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_util::codec::{Decoder, Encoder};

use crate::codec::{CodecError, PacketCodec};
use crate::throttle::{send_size, Bandwidth, Priority, RateLimiter};

/// The most read at once (aMule reads up to the end of the current packet).
pub const READ_CHUNK: usize = 64 * 1024;
const HANDSHAKE_CHUNK: usize = 512;

/// Connection errors.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    Crypt(#[from] StreamError),
    #[error("connection closed during the obfuscation handshake")]
    ClosedInHandshake,
    #[error("connection closed in the middle of a packet")]
    ClosedInPacket,
    /// `ERR_ENCRYPTION_NOTALLOWED`
    #[error("plain connection refused: obfuscation is required")]
    PlainRefused,
}

/// How to start a connection.
#[derive(Debug, Clone)]
pub enum Handshake {
    /// No obfuscation.
    Plain,
    /// We connect to a client with this user hash, obfuscated.
    Client { target: Md4Hash, max_padding: u8 },
    /// We connect to a server, obfuscated.
    Server,
    /// Someone connected to us: obfuscated or not, the first byte says.
    /// With `require`, a plain one is refused (`must_refuse_plain_connection`
    /// decides the exemptions; pass its result).
    Incoming {
        own_hash: Md4Hash,
        max_padding: u8,
        require: bool,
    },
}

/// Settings shared by the two halves.
#[derive(Debug, Clone)]
pub struct ConnConfig {
    pub bandwidth: Arc<Bandwidth>,
    /// Count reads against the download bucket.
    pub download_throttled: bool,
    pub max_payload: u32,
}

impl ConnConfig {
    pub fn new(bandwidth: Arc<Bandwidth>) -> Self {
        ConnConfig {
            bandwidth,
            download_throttled: true,
            max_payload: crate::codec::MAX_PACKET_SIZE,
        }
    }
}

/// Run the handshake on `io` and split it.
pub async fn establish<S>(
    mut io: S,
    handshake: Handshake,
    config: ConnConfig,
) -> Result<(PacketReader<ReadHalf<S>>, PacketWriter<WriteHalf<S>>), NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // StdRng, not thread_rng: the future must stay Send.
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_entropy();
    let mut early = BytesMut::new();
    let crypt = match handshake {
        Handshake::Plain => StreamCrypt::plain(),
        Handshake::Client {
            target,
            max_padding,
        } => {
            let (c, hello) = StreamCrypt::client(&target, max_padding, &mut rng);
            write_all(&mut io, &hello).await?;
            negotiate(&mut io, c, &mut early).await?
        }
        Handshake::Server => {
            let (c, hello) = StreamCrypt::server(&mut rng);
            write_all(&mut io, &hello).await?;
            negotiate(&mut io, c, &mut early).await?
        }
        Handshake::Incoming {
            own_hash,
            max_padding,
            require,
        } => {
            let c = StreamCrypt::incoming(own_hash, max_padding, &mut rng);
            let c = negotiate(&mut io, c, &mut early).await?;
            if require && !c.is_obfuscated() {
                return Err(NetError::PlainRefused);
            }
            c
        }
    };
    let (send, recv) = crypt.split()?;
    let (r, w) = tokio::io::split(io);
    let reader = PacketReader {
        io: r,
        crypt: recv,
        codec: PacketCodec::with_max_payload(config.max_payload),
        buf: early,
        bandwidth: config.bandwidth.clone(),
        throttled: config.download_throttled,
        received: 0,
    };
    let writer = PacketWriter {
        io: w,
        crypt: send,
        codec: PacketCodec::new(),
        bandwidth: config.bandwidth,
        sent: 0,
    };
    Ok((reader, writer))
}

async fn write_all<S: AsyncWrite + Unpin>(io: &mut S, data: &[u8]) -> std::io::Result<()> {
    io.write_all(data).await?;
    io.flush().await
}

/// Read until the handshake is over (or, incoming, until the first bytes
/// say whether there is one). Stream data that came with it goes to `early`.
async fn negotiate<S>(
    io: &mut S,
    mut crypt: StreamCrypt,
    early: &mut BytesMut,
) -> Result<StreamCrypt, NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let incoming_unknown = |c: &StreamCrypt| c.is_ready() && !c.is_obfuscated();
    let mut first = incoming_unknown(&crypt);
    let mut buf = [0u8; HANDSHAKE_CHUNK];
    while first || !crypt.is_ready() {
        let n = io.read(&mut buf).await?;
        if n == 0 {
            return Err(NetError::ClosedInHandshake);
        }
        let r = crypt.receive(&buf[..n])?;
        if !r.reply.is_empty() {
            write_all(io, &r.reply).await?;
        }
        early.extend_from_slice(&r.data);
        first = false;
    }
    Ok(crypt)
}

/// Gives a reservation back unless it is used (so a cancelled read loses nothing).
struct Reservation<'a> {
    limiter: Option<&'a RateLimiter>,
    n: usize,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if let Some(l) = self.limiter {
            l.refund(self.n);
        }
    }
}

/// The receiving half.
#[derive(Debug)]
pub struct PacketReader<R> {
    io: R,
    crypt: RecvHalf,
    codec: PacketCodec,
    buf: BytesMut,
    bandwidth: Arc<Bandwidth>,
    throttled: bool,
    received: u64,
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    /// `IsDownloadThrottled`: count reads against the download bucket.
    pub fn set_download_throttled(&mut self, on: bool) {
        self.throttled = on;
    }

    /// Bytes read from the socket so far.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// The next packet; `None` when the peer closed between packets.
    /// Cancel-safe: a dropped call loses no data and no budget.
    pub async fn recv(&mut self) -> Result<Option<Packet>, NetError> {
        loop {
            if let Some(p) = self.codec.decode(&mut self.buf)? {
                return Ok(Some(p));
            }
            let want = self.codec.wanted(self.buf.len()).clamp(1, READ_CHUNK);
            let mut res = Reservation {
                limiter: None,
                n: want,
            };
            if self.throttled {
                let l = &self.bandwidth.download;
                res.n = l.acquire(want, Priority::Standard).await;
                res.limiter = Some(l);
            }
            let start = self.buf.len();
            // read_buf appends only what arrived, so cancelling here is harmless.
            let n = (&mut self.io)
                .take(res.n as u64)
                .read_buf(&mut self.buf)
                .await?;
            res.n -= n; // the rest is refunded
            if n == 0 {
                return if self.buf.is_empty()
                    && self.codec.wanted(0) == ed2k_codec::packet::HEADER_LEN
                {
                    Ok(None)
                } else {
                    Err(NetError::ClosedInPacket)
                };
            }
            self.received += n as u64;
            self.crypt.open(&mut self.buf[start..]);
        }
    }
}

/// The sending half.
#[derive(Debug)]
pub struct PacketWriter<W> {
    io: W,
    crypt: SendHalf,
    codec: PacketCodec,
    bandwidth: Arc<Bandwidth>,
    sent: u64,
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    /// Whether the connection is obfuscated.
    pub fn is_obfuscated(&self) -> bool {
        self.crypt.is_obfuscated()
    }

    /// Bytes written to the socket so far.
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Send a packet: control packets go before file data in the upload
    /// bucket. Not cancel-safe: a dropped call may leave half a packet sent.
    pub async fn send(&mut self, packet: &Packet, priority: Priority) -> Result<(), NetError> {
        let mut frame = BytesMut::new();
        self.codec.encode(packet, &mut frame)?;
        let data = self.crypt.seal(&frame);
        let limiter = &self.bandwidth.upload;
        let mut rest = &data[..];
        while !rest.is_empty() {
            let n = rest.len().min(send_size(limiter.rate()));
            limiter.acquire(n, priority).await;
            self.io.write_all(&rest[..n]).await?;
            self.sent += n as u64;
            rest = &rest[n..];
        }
        self.io.flush().await?;
        Ok(())
    }

    /// Close the sending direction.
    pub async fn shutdown(&mut self) -> Result<(), NetError> {
        self.io.shutdown().await?;
        Ok(())
    }
}

/// Re-exported for [`Handshake`]'s padding fields.
pub use stream::DEFAULT_MAX_PADDING;
