// SPDX-License-Identifier: GPL-2.0-or-later
//! Whether others can reach us, and the TCP side of Kad's firewall check.
//!
//! * [`Reachability`]: `CamuleApp::IsFirewalled`, the other way round: a
//!   HighID from the server, or Kad's TCP firewall check open.
//! * [`connect_back`]: a Kad node asked us to check its TCP port
//!   (`KADEMLIA_FIREWALLED2_REQ`): connect, exchange hellos, send
//!   `OP_KAD_FWTCPCHECK_ACK` (`CClientList::RequestTCP`, then the
//!   `KS_CONNECTED_FWCHECK` case of `CClientList::Process`).
//!
//! Our own check is `ed2k_kad`'s ([`ed2k_kad::firewall`]); the acks other
//! nodes send us come in on peer connections and are handed to it.

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use ed2k_codec::Packet;
use ed2k_peer::Hello;
use ed2k_types::ed2k::client_tcp::{Extended, Standard};
use ed2k_types::ed2k::CONNECTION_TIMEOUT;
use ed2k_types::{Md4Hash, Protocol};
use remule_net::{establish, Bandwidth, ConnConfig, Handshake, Priority};
use tokio::net::TcpStream;

/// Connect-backs for others' checks running at a time (ours; aMule relies
/// on Kad's flood protection alone).
pub const MAX_CONNECT_BACKS: usize = 16;

/// Whether others can connect to our TCP port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reachability {
    /// The user says so (`remule download --reachable`).
    pub assumed: bool,
    /// Logged into a server with a HighID: it connected to our port
    /// (`!CServerConnect::IsLowID`).
    pub high_id: bool,
    /// Kad's TCP firewall check says other nodes got through
    /// (`!CKademlia::IsFirewalled`).
    pub kad_open: bool,
}

impl Reachability {
    /// `!CamuleApp::IsFirewalled()`: then we publish ourselves as a source
    /// on Kad.
    pub fn reachable(&self) -> bool {
        self.assumed || self.high_id || self.kad_open
    }

    /// The answer, for the log.
    pub fn describe(&self) -> &'static str {
        if self.high_id {
            "reachable: the server gave us a HighID"
        } else if self.kad_open {
            "reachable: Kad nodes got through to our TCP port"
        } else if self.assumed {
            "reachable (assumed)"
        } else {
            "firewalled: no HighID, and Kad's firewall check did not get through"
        }
    }
}

/// Answer a Kad node's firewall check: connect to it at `to` (obfuscated
/// when its `connect_options` say it supports that and its user hash is
/// known, as `TryToConnect` decides for us, who request obfuscation), send
/// `ours` as our hello, and once its answer comes, `OP_KAD_FWTCPCHECK_ACK`.
pub async fn connect_back(
    to: SocketAddrV4,
    user_hash: Md4Hash,
    connect_options: u8,
    ours: Hello,
) -> Result<(), String> {
    let within =
        |what: &'static str| move |_| format!("{to}: no {what} within {CONNECTION_TIMEOUT:?}");
    let stream = tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(to))
        .await
        .map_err(within("connection"))?
        .map_err(|e| format!("{to}: {e}"))?;
    let _ = stream.set_nodelay(true);
    let handshake = if connect_options & 0x01 != 0 && user_hash != Md4Hash::default() {
        Handshake::Client {
            target: user_hash,
            max_padding: remule_net::conn::DEFAULT_MAX_PADDING,
        }
    } else {
        Handshake::Plain
    };
    let cfg = ConnConfig::new(Arc::new(Bandwidth::new(0, 0)));
    let (mut reader, mut writer) =
        tokio::time::timeout(CONNECTION_TIMEOUT, establish(stream, handshake, cfg))
            .await
            .map_err(within("handshake"))?
            .map_err(|e| format!("{to}: {e}"))?;
    let hello = ours.to_hello().map_err(|e| e.to_string())?;
    writer
        .send(&hello, Priority::Control)
        .await
        .map_err(|e| format!("{to}: {e}"))?;
    // `ConnectionEstablished` comes with its hello answer.
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        loop {
            match reader.recv().await {
                Ok(Some(p))
                    if p.protocol == u8::from(Protocol::Edonkey)
                        && p.opcode == u8::from(Standard::HelloAnswer) =>
                {
                    return Ok(());
                }
                Ok(Some(_)) => {}
                Ok(None) => return Err(format!("{to}: closed before its hello answer")),
                Err(e) => return Err(format!("{to}: {e}")),
            }
        }
    })
    .await
    .map_err(within("hello answer"))??;
    let ack = Packet::new(Protocol::Emule, Extended::KadFwTcpCheckAck, Vec::new());
    writer
        .send(&ack, Priority::Control)
        .await
        .map_err(|e| format!("{to}: {e}"))?;
    // aMule leaves the connection to time out; a moment for the peer to
    // read the ack is enough here.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = writer.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Reachability;

    /// `CamuleApp::IsFirewalled`: a HighID or an open Kad check is enough.
    #[test]
    fn reachable_by_server_or_kad() {
        let mut r = Reachability::default();
        assert!(!r.reachable());
        r.high_id = true;
        assert!(r.reachable());
        r.high_id = false;
        r.kad_open = true;
        assert!(r.reachable());
        r.kad_open = false;
        r.assumed = true;
        assert!(r.reachable());
    }
}
