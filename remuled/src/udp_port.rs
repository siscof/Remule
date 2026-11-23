// SPDX-License-Identifier: GPL-2.0-or-later
//! The client UDP port (`CClientUDPSocket`, `CMuleUDPSocket`): one socket
//! for Kad and for eD2k client packets, as in aMule.
//!
//! Each datagram that comes in goes one way: an eMule protocol packet,
//! plain or obfuscated with the key made from our user hash
//! (`DecryptReceivedClient`), to the client; anything else to Kad, which
//! tries its own keys. What either sends goes out of the same socket;
//! eD2k packets obfuscated for the receiver's user hash when it wants that
//! and our public IP (part of the key) is known.
//!
//! With `REMULE_TRACE` set, every eD2k datagram each way is printed to
//! stderr with its opcode and whether it was obfuscated.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use ed2k_crypto::udp::{self, ClientKey, OwnKeys, SendForm, VerifyKeys};
use ed2k_kad::node::Datagram;
use ed2k_types::ed2k::client_udp::Opcode;
use ed2k_types::{Md4Hash, Protocol};
use remule_core::download_queue::UdpOut;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// An eD2k client datagram that came in, decrypted.
#[derive(Debug, Clone)]
pub struct Ed2kDatagram {
    pub from: SocketAddrV4,
    /// Protocol byte first.
    pub payload: Vec<u8>,
    pub obfuscated: bool,
}

type KadIn = Arc<Mutex<Option<mpsc::Sender<(SocketAddrV4, Vec<u8>)>>>>;

/// The bound port.
pub struct UdpPort {
    socket: Arc<UdpSocket>,
    kad_in: KadIn,
    trace: bool,
    task: JoinHandle<()>,
    pub port: u16,
}

impl Drop for UdpPort {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn opcode_name(op: u8) -> String {
    Opcode::try_from(op)
        .map(|o| format!("{o:?}"))
        .unwrap_or_else(|_| format!("{op:#04x}"))
}

/// Sort one datagram: an eD2k client packet (decrypted) or not.
pub fn classify(datagram: &[u8], from: SocketAddrV4, user_hash: Md4Hash) -> Option<Ed2kDatagram> {
    match datagram.first() {
        Some(&b) if b == Protocol::Emule as u8 => {
            return Some(Ed2kDatagram {
                from,
                payload: datagram.to_vec(),
                obfuscated: false,
            })
        }
        Some(&b) if b == Protocol::Kademlia as u8 || b == Protocol::KademliaPacked as u8 => {
            return None
        }
        _ => {}
    }
    let own = OwnKeys {
        user_hash,
        sender_ip: *from.ip(),
        kad_id: None,
        verify_key: None,
    };
    let d = udp::decrypt_client(datagram, &own)?;
    (!d.kad && d.payload.first() == Some(&(Protocol::Emule as u8))).then_some(Ed2kDatagram {
        from,
        payload: d.payload,
        obfuscated: true,
    })
}

/// The datagram to send for `d`: obfuscated for its user hash when asked
/// and our public IP is known (`EncryptSendClient` keys with it), plain
/// otherwise. `true` when obfuscated.
pub fn encode(d: &UdpOut, public_ip: Option<Ipv4Addr>) -> (Vec<u8>, bool) {
    let ip = public_ip.map_or(0, u32::from);
    match (
        d.obfuscate_for,
        udp::send_form(d.obfuscate_for.is_some(), false, false, ip),
    ) {
        (Some(receiver), SendForm::Obfuscated) => {
            let key = ClientKey::Ed2k {
                receiver,
                sender_ip: public_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            };
            let bytes = udp::encrypt_client(
                &d.payload,
                &key,
                VerifyKeys::default(),
                &mut rand::thread_rng(),
            );
            (bytes, true)
        }
        _ => (d.payload.clone(), false),
    }
}

impl UdpPort {
    /// Bind `port` on every address; eD2k datagrams go to `ed2k`.
    pub async fn bind(
        port: u16,
        user_hash: Md4Hash,
        ed2k: mpsc::UnboundedSender<Ed2kDatagram>,
    ) -> std::io::Result<UdpPort> {
        let socket = Arc::new(UdpSocket::bind(("0.0.0.0", port)).await?);
        let port = socket.local_addr()?.port();
        let kad_in: KadIn = Arc::default();
        let trace = crate::kad::trace_from_env();
        let task = tokio::spawn(receive(
            socket.clone(),
            user_hash,
            ed2k,
            kad_in.clone(),
            trace,
        ));
        Ok(UdpPort {
            socket,
            kad_in,
            trace,
            task,
            port,
        })
    }

    /// The channels a Kad node runs on ([`ed2k_kad::driver::spawn_on`]):
    /// from now on, what is not eD2k goes to it. A new call replaces the
    /// node before.
    pub fn kad_transport(
        &self,
    ) -> (
        mpsc::Receiver<(SocketAddrV4, Vec<u8>)>,
        mpsc::UnboundedSender<Datagram>,
    ) {
        let (in_tx, in_rx) = mpsc::channel(1024);
        *self.kad_in.lock().unwrap_or_else(|e| e.into_inner()) = Some(in_tx);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Datagram>();
        let socket = self.socket.clone();
        tokio::spawn(async move {
            while let Some(d) = out_rx.recv().await {
                // A failed send to one peer is not fatal.
                let _ = socket.send_to(&d.bytes, d.to).await;
            }
        });
        (in_rx, out_tx)
    }

    /// Send an eD2k client datagram.
    pub async fn send_ed2k(&self, d: &UdpOut, public_ip: Option<Ipv4Addr>) {
        let (bytes, obfuscated) = encode(d, public_ip);
        if self.trace {
            eprintln!(
                "udp -> {} {} {}",
                d.to,
                opcode_name(d.payload.get(1).copied().unwrap_or(0)),
                if obfuscated { "obfuscated" } else { "plain" }
            );
        }
        let _ = self.socket.send_to(&bytes, d.to).await;
    }
}

async fn receive(
    socket: Arc<UdpSocket>,
    user_hash: Md4Hash,
    ed2k: mpsc::UnboundedSender<Ed2kDatagram>,
    kad_in: KadIn,
    trace: bool,
) {
    let mut buf = vec![0u8; 16384];
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            // Windows reports ICMP port-unreachable as a recv error: ignore.
            Err(_) => continue,
        };
        let SocketAddr::V4(from) = from else { continue };
        let datagram = &buf[..n];
        match classify(datagram, from, user_hash) {
            Some(d) => {
                if trace {
                    eprintln!(
                        "udp <- {} {} {}",
                        d.from,
                        opcode_name(d.payload.get(1).copied().unwrap_or(0)),
                        if d.obfuscated { "obfuscated" } else { "plain" }
                    );
                }
                let _ = ed2k.send(d);
            }
            None => {
                let kad = kad_in.lock().unwrap_or_else(|e| e.into_inner()).clone();
                if let Some(tx) = kad {
                    let _ = tx.try_send((from, datagram.to_vec()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What one client obfuscates for another's user hash, keyed with its
    /// public IP, the other reads as the same packet from that IP; Kad
    /// packets and other keys are not taken for eD2k.
    #[test]
    fn obfuscated_both_ways() {
        let theirs = Md4Hash([0x42; 16]);
        let ours_ip = Ipv4Addr::new(203, 0, 113, 9);
        let ping = vec![
            0xC5, 0x90, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ];
        let out = UdpOut {
            to: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 4672),
            payload: ping.clone(),
            obfuscate_for: Some(theirs),
        };
        let (bytes, obfuscated) = encode(&out, Some(ours_ip));
        assert!(obfuscated);
        assert_ne!(bytes[0], 0xC5);
        let from = SocketAddrV4::new(ours_ip, 4672);
        let d = classify(&bytes, from, theirs).expect("eD2k");
        assert!(d.obfuscated);
        assert_eq!(d.payload, ping);
        // The wrong receiver, or the wrong sender IP: not ours.
        assert!(classify(&bytes, from, Md4Hash([1; 16])).is_none());
        assert!(classify(
            &bytes,
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1),
            theirs
        )
        .is_none());
        // Without our public IP, plain.
        let (bytes, obfuscated) = encode(&out, None);
        assert!(!obfuscated);
        assert_eq!(bytes, ping);
        let d = classify(&bytes, from, theirs).unwrap();
        assert!(!d.obfuscated);
        // Kad, plain: not eD2k.
        assert!(classify(&[0xE4, 0x01], from, theirs).is_none());
    }
}
