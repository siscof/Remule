// SPDX-License-Identifier: GPL-2.0-or-later
//! UDP (`CMuleUDPSocket`): datagrams go out through the upload bucket as
//! control traffic; incoming ones are not throttled. Obfuscation is the
//! caller's ([`ed2k_crypto::udp`]), since the key depends on the peer.

use std::net::SocketAddr;
use std::sync::Arc;

use ed2k_codec::Packet;
use tokio::net::UdpSocket;

use crate::throttle::{Bandwidth, Priority};

/// `UDP_BUFFER_SIZE`: the largest datagram read.
pub const UDP_BUFFER_SIZE: usize = 16384;

/// A throttled UDP socket.
#[derive(Debug)]
pub struct UdpEndpoint {
    socket: UdpSocket,
    bandwidth: Arc<Bandwidth>,
}

impl UdpEndpoint {
    pub async fn bind(addr: SocketAddr, bandwidth: Arc<Bandwidth>) -> std::io::Result<Self> {
        Ok(UdpEndpoint {
            socket: UdpSocket::bind(addr).await?,
            bandwidth,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send a datagram once the upload bucket allows it.
    pub async fn send_to(&self, datagram: &[u8], to: SocketAddr) -> std::io::Result<()> {
        self.bandwidth
            .upload
            .acquire(datagram.len(), Priority::Control)
            .await;
        self.socket.send_to(datagram, to).await?;
        Ok(())
    }

    /// Send a packet, unobfuscated.
    pub async fn send_packet(&self, packet: &Packet, to: SocketAddr) -> std::io::Result<()> {
        self.send_to(&packet.to_udp_bytes(), to).await
    }

    /// The next datagram (at most [`UDP_BUFFER_SIZE`] bytes).
    pub async fn recv_from(&self) -> std::io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((buf, from))
    }
}
