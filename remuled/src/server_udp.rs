// SPDX-License-Identifier: GPL-2.0-or-later
//! The server UDP port (`CServerUDPSocket`): bound on the TCP port + 3, as
//! aMule binds it. Global search requests go out of it to the servers of
//! the list, plain to their TCP port + 4, or obfuscated to their UDP
//! obfuscation port when they support that and their key was given for our
//! public IP (`SendPacket`); their answers come back to it, decrypted with
//! that key (`OnPacketReceived`).
//!
//! With `REMULE_TRACE` set, every datagram each way is printed to stderr.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use ed2k_codec::Packet;
use ed2k_formats::server_met::ServerInfo;
use ed2k_server::udp;
use ed2k_types::ed2k::server_udp::flags;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

/// The bound port.
pub struct ServerUdp {
    socket: Arc<UdpSocket>,
    trace: bool,
    task: JoinHandle<()>,
    pub port: u16,
}

impl Drop for ServerUdp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `GetServerKeyUDP`, and whether it may be used (`SupportsObfuscationUDP`):
/// the server's key when it was given for our public IP, else 0.
pub fn key_for(server: &ServerInfo, public_ip: Option<Ipv4Addr>) -> u32 {
    let ours = public_ip.map_or(0, |ip| u32::from_le_bytes(ip.octets()));
    let usable = server.udp_key != 0
        && ours != 0
        && server.udp_key_ip == ours
        && server.udp_flags & flags::UDPOBFUSCATION != 0
        && server.obfuscation_port_udp != 0;
    if usable {
        server.udp_key
    } else {
        0
    }
}

/// Where a packet for `server` goes and what is sent: obfuscated to its UDP
/// obfuscation port when [`key_for`] gives a key, else plain to its TCP
/// port + 4. `true` when obfuscated.
pub fn encode(
    packet: &Packet,
    server: &ServerInfo,
    public_ip: Option<Ipv4Addr>,
) -> Option<(SocketAddrV4, Vec<u8>, bool)> {
    let ip = server.ip?;
    let bytes = packet.to_udp_bytes();
    match key_for(server, public_ip) {
        0 => Some((
            SocketAddrV4::new(ip, server.port.wrapping_add(udp::UDP_PORT_OFFSET)),
            bytes,
            false,
        )),
        key => Some((
            SocketAddrV4::new(ip, server.obfuscation_port_udp),
            udp::obfuscate(&bytes, key, &mut rand::thread_rng()),
            true,
        )),
    }
}

/// `GetServerByIPUDP(ip, port, true)`: the server a datagram came from, by
/// its TCP port + 4, its UDP obfuscation port or its TCP port + 12.
pub fn sender(servers: &[ServerInfo], from: SocketAddrV4) -> Option<&ServerInfo> {
    let p = from.port();
    servers.iter().find(|s| {
        s.ip == Some(*from.ip())
            && (s.port.wrapping_add(udp::UDP_PORT_OFFSET) == p
                || (s.obfuscation_port_udp != 0 && s.obfuscation_port_udp == p)
                || s.port.wrapping_add(udp::CRYPT_PING_PORT_OFFSET) == p)
    })
}

/// A datagram from `from` as plain bytes: decrypted with its server's key
/// when it has one (an unencrypted one is taken as it is).
pub fn decode(
    datagram: &[u8],
    from: SocketAddrV4,
    servers: &[ServerInfo],
    public_ip: Option<Ipv4Addr>,
) -> Vec<u8> {
    let key = sender(servers, from).map_or(0, |s| key_for(s, public_ip));
    udp::deobfuscate(datagram, key)
}

impl ServerUdp {
    /// Bind `port` (the TCP port + 3); when it is taken, any port, so
    /// answers still come back.
    pub async fn bind(
        port: u16,
        incoming: mpsc::UnboundedSender<(SocketAddrV4, Vec<u8>)>,
    ) -> std::io::Result<ServerUdp> {
        let socket = match UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Server UDP port {port}: {e}; using another");
                UdpSocket::bind(("0.0.0.0", 0)).await?
            }
        };
        let socket = Arc::new(socket);
        let port = socket.local_addr()?.port();
        let trace = crate::kad::trace_from_env();
        let task = tokio::spawn(receive(socket.clone(), incoming));
        Ok(ServerUdp {
            socket,
            trace,
            task,
            port,
        })
    }

    /// Send `packet` to `server`.
    pub async fn send(&self, packet: &Packet, server: &ServerInfo, public_ip: Option<Ipv4Addr>) {
        let Some((to, bytes, obfuscated)) = encode(packet, server, public_ip) else {
            return;
        };
        if self.trace {
            eprintln!(
                "server udp -> {to} {:#04x} {}",
                packet.opcode,
                if obfuscated { "obfuscated" } else { "plain" }
            );
        }
        let _ = self.socket.send_to(&bytes, to).await;
    }

    /// Send a raw datagram (the obfuscated ping).
    pub async fn send_raw(&self, to: SocketAddrV4, bytes: &[u8]) {
        if self.trace {
            eprintln!("server udp -> {to} crypt ping");
        }
        let _ = self.socket.send_to(bytes, to).await;
    }

    pub fn trace(&self) -> bool {
        self.trace
    }
}

async fn receive(socket: Arc<UdpSocket>, incoming: mpsc::UnboundedSender<(SocketAddrV4, Vec<u8>)>) {
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            // Windows reports ICMP port-unreachable as a recv error: ignore.
            Err(_) => continue,
        };
        let SocketAddr::V4(from) = from else { continue };
        if incoming.send((from, buf[..n].to_vec())).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed2k_types::ed2k::server_udp::Opcode;
    use ed2k_types::Protocol;

    fn server(key: u32, key_ip: Ipv4Addr) -> ServerInfo {
        ServerInfo {
            ip: Some(Ipv4Addr::new(198, 51, 100, 4)),
            port: 4242,
            udp_flags: flags::UDPOBFUSCATION | flags::EXT_GETFILES,
            udp_key: key,
            udp_key_ip: u32::from_le_bytes(key_ip.octets()),
            obfuscation_port_udp: 5555,
            ..Default::default()
        }
    }

    /// A server whose key was given for our IP gets the request obfuscated
    /// on its obfuscation port, and what it sends back from there is read
    /// with that key; with no key (or one for another IP), plain to port + 4.
    #[test]
    fn obfuscated_when_the_key_is_for_our_ip() {
        let ours = Ipv4Addr::new(203, 0, 113, 9);
        let s = server(0x1234_5678, ours);
        let p = Packet::new(Protocol::Edonkey, Opcode::GlobSearchReq2, vec![1, 2, 3]);
        let (to, bytes, obf) = encode(&p, &s, Some(ours)).unwrap();
        assert!(obf);
        assert_eq!(to.port(), 5555);
        assert_ne!(bytes, p.to_udp_bytes());

        let answer = [0xE3, 0x99, 7, 7];
        let wire = ed2k_crypto::udp::encrypt_from_server(&answer, s.udp_key, 0x5A, 0x0102);
        let servers = [s.clone()];
        assert_eq!(decode(&wire, to, &servers, Some(ours)), answer);
        // Plain from port + 4 stays plain.
        let from4 = SocketAddrV4::new(s.ip.unwrap(), 4246);
        assert_eq!(decode(&answer, from4, &servers, Some(ours)), answer);

        for (srv, ip) in [
            (server(0x1234_5678, Ipv4Addr::new(1, 2, 3, 4)), Some(ours)),
            (server(0, ours), Some(ours)),
            (s.clone(), None),
        ] {
            let (to, bytes, obf) = encode(&p, &srv, ip).unwrap();
            assert!(!obf);
            assert_eq!(to, SocketAddrV4::new(srv.ip.unwrap(), 4246));
            assert_eq!(bytes, p.to_udp_bytes());
        }
    }
}
