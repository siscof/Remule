// SPDX-License-Identifier: GPL-2.0-or-later
//! Starting a Kad node from the files aMule keeps for it (`nodes.dat`,
//! `preferencesKad.dat`, the index files), and saving them again.

use std::net::SocketAddrV4;
use std::path::PathBuf;

use ed2k_formats::nodes_dat::NodesDat;
use ed2k_kad::driver::{self, KadHandle};
use ed2k_kad::node::{Config, Wire, WireForm};
use ed2k_kad::prefs::{self, KadPrefs};
use ed2k_kad::Kad;
use ed2k_types::kad::v2::Opcode;
use ed2k_types::{Md4Hash, UInt128};
use rand::Rng;
use tracing::info;

/// Whether `REMULE_TRACE` asks for every datagram.
pub fn trace_from_env() -> bool {
    std::env::var_os("REMULE_TRACE").is_some()
}

/// A traced datagram as one line: direction, peer, opcode and how it was
/// obfuscated, e.g. `kad <- 10.0.0.2:4672 HelloRes obfuscated (Kad ID), receiver key valid`.
pub fn wire_line(w: &Wire) -> String {
    let op = Opcode::try_from(w.opcode)
        .map(|o| format!("{o:?}"))
        .unwrap_or_else(|_| format!("{:#04x}", w.opcode));
    let form = match w.form {
        WireForm::Plain => "plain",
        WireForm::KadId => "obfuscated (Kad ID)",
        WireForm::KadVerifyKey => "obfuscated (verify key)",
        WireForm::Ed2k => "obfuscated (user hash)",
    };
    format!(
        "kad {} {} {op} {form}{}",
        if w.incoming { "<-" } else { "->" },
        w.peer,
        if w.receiver_key_valid {
            ", receiver key valid"
        } else {
            ""
        }
    )
}

/// The index files in the state directory.
pub const INDEX_FILES: [&str; 3] = ["load_index.dat", "key_index.dat", "src_index.dat"];

fn load_or_make_prefs(dir: &std::path::Path) -> KadPrefs {
    let path = dir.join(prefs::FILE_NAME);
    if let Some(p) = std::fs::read(&path).ok().and_then(|b| KadPrefs::read(&b)) {
        return p;
    }
    KadPrefs {
        public_ip: 0,
        kad_id: UInt128::new(rand::thread_rng().gen()),
    }
}

/// A running Kad node and where its state is kept.
pub struct KadNode {
    pub handle: KadHandle,
    pub prefs: KadPrefs,
    /// Where its state is kept.
    pub dir: PathBuf,
}

/// How to start a Kad node.
#[derive(Debug, Clone)]
pub struct KadStart {
    /// Where nodes.dat, preferencesKad.dat and the index files are kept.
    pub dir: PathBuf,
    /// The nodes.dat to start from (default: DIR/nodes.dat).
    pub nodes: Option<PathBuf>,
    pub bootstrap: Vec<SocketAddrV4>,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub user_hash: Md4Hash,
    /// Others can reach our UDP port: store what they publish.
    pub reachable: bool,
    /// Something listens on `tcp_port`, and will hand the node the firewall
    /// check acks that come there and connect back when it is asked to:
    /// the TCP firewall check runs.
    pub listening: bool,
    /// Take contacts on LAN addresses (aMule's `FilterLanIPs` off).
    pub allow_lan: bool,
    /// Hand every datagram to the application as an `Event::Wire`.
    pub trace_wire: bool,
}

/// Load the state, bind the UDP port and start the node.
pub async fn start(a: &KadStart) -> Result<KadNode, String> {
    std::fs::create_dir_all(&a.dir).map_err(|e| format!("{}: {e}", a.dir.display()))?;
    let prefs = load_or_make_prefs(&a.dir);
    let nodes_path = a.nodes.clone().unwrap_or_else(|| a.dir.join("nodes.dat"));
    let nodes = match std::fs::read(&nodes_path) {
        Ok(b) => Some(NodesDat::read(&b).map_err(|e| format!("{}: {e}", nodes_path.display()))?),
        Err(e) if a.bootstrap.is_empty() => {
            return Err(format!(
                "{}: {e} (give a nodes.dat with --nodes, or --bootstrap IP:PORT)",
                nodes_path.display()
            ))
        }
        Err(_) => None,
    };
    let cfg = Config {
        kad_id: prefs.kad_id,
        udp_key_secret: rand::thread_rng().gen(),
        user_hash: a.user_hash,
        tcp_port: a.tcp_port,
        tcp_firewalled: !a.listening,
        udp_firewalled: !a.reachable,
    };
    let now = driver::unix_now();
    let mut kad = Kad::new(cfg, now);
    kad.load_public_ip(prefs.public_ip);
    kad.routing.filter_lan = !a.allow_lan;
    kad.trace_wire = a.trace_wire;
    for (i, name) in INDEX_FILES.iter().enumerate() {
        let Ok(b) = std::fs::read(a.dir.join(name)) else {
            continue;
        };
        let r = match i {
            0 => kad.index.read_load_file(&b, now),
            1 => kad.index.read_keyword_file(&b, now),
            _ => kad.index.read_source_file(&b, now),
        };
        if let Err(e) = r {
            info!("{name}: {e} (ignored)");
        }
    }
    let st = kad.index.stats();
    if st.keywords + st.sources + st.loads > 0 {
        info!(
            "index: {} keyword entries, {} sources, {} loads",
            st.keywords, st.sources, st.loads
        );
    }
    if let Some(n) = &nodes {
        let taken = kad.load_nodes(n, now);
        info!(
            "{}: {} contacts, {} taken into the routing table",
            nodes_path.display(),
            n.contacts.len(),
            taken
        );
    }
    info!(
        "Kad ID {}",
        prefs
            .kad_id
            .to_be_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    );
    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", a.udp_port))
        .await
        .map_err(|e| format!("UDP port {}: {e}", a.udp_port))?;
    let handle: KadHandle = driver::spawn(kad, socket);
    for b in &a.bootstrap {
        handle.bootstrap(*b).await;
    }
    Ok(KadNode {
        handle,
        prefs,
        dir: a.dir.clone(),
    })
}

impl KadNode {
    /// Save what was learned, as aMule does on exit.
    pub async fn save(&self) -> Result<(), String> {
        match self.handle.nodes().await {
            Some(n) => {
                let path = self.dir.join("nodes.dat");
                std::fs::write(&path, n.write()).map_err(|e| format!("{}: {e}", path.display()))?;
                info!("wrote {} ({} contacts)", path.display(), n.contacts.len());
            }
            None => info!("fewer than 25 contacts: nodes.dat not written"),
        }
        if let Some(f) = self.handle.index_files().await {
            for (name, bytes) in INDEX_FILES.iter().zip([f.load, f.keywords, f.sources]) {
                let path = self.dir.join(name);
                std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
            }
        }
        // With our public IP as nodes last told it.
        let mut p = self.prefs;
        if let Some(s) = self.handle.snapshot().await {
            if !s.public_ip.is_unspecified() {
                p.public_ip = u32::from(s.public_ip);
            }
        }
        let path = self.dir.join(prefs::FILE_NAME);
        std::fs::write(&path, p.write()).map_err(|e| format!("{}: {e}", path.display()))
    }
}
