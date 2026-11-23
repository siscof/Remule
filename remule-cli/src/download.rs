// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule download`: download files from ed2k links, finding sources on
//! eD2k servers and Kad, and resume the downloads in the temp directory,
//! including aMule's. The client itself is [`remuled::client`].
//!
//! The temp directory holds `NNN.part` / `NNN.part.met` pairs in aMule's
//! format: point it at aMule's `Temp` directory (with aMule closed) and
//! remule carries on aMule's downloads; aMule resumes remule's the same way.
//!
//! With `REMULE_TRACE` set, every peer packet's protocol, opcode and size
//! is printed to stderr.

use std::net::{SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ed2k_types::Md4Hash;
use remule_core::PartFile;
use remuled::client::{self, existing_downloads, human, ClientConfig, KadSettings};

use remule_core::link;

/// What `remule download` was asked.
#[derive(Debug, Clone)]
pub struct DownloadArgs {
    pub links: Vec<String>,
    pub temp: PathBuf,
    pub incoming: PathBuf,
    pub servers: Vec<SocketAddr>,
    pub obfuscate_server: bool,
    /// Find sources on Kad, keeping its state here.
    pub kad: Option<PathBuf>,
    pub kad_nodes: Option<PathBuf>,
    /// Kad nodes to bootstrap from as well.
    pub kad_bootstrap: Vec<std::net::SocketAddrV4>,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub nick: String,
    /// Seconds to run (0: until every file is done).
    pub duration: u64,
    pub status_every: u64,
    pub max_connections: usize,
    /// KiB/s, 0 for no limit.
    pub max_download: u32,
    pub max_upload: u32,
    /// Directories to share; finished downloads are shared too.
    pub share: Vec<PathBuf>,
    /// Where known.met, known2_64.met and clients.met are kept.
    pub config: PathBuf,
    /// Others can connect to our TCP port: publish sources on Kad.
    pub reachable: bool,
    /// Take sources on LAN and loopback addresses (aMule's FilterLanIPs off).
    pub allow_lan: bool,
    /// Seconds before asking a source again.
    pub reask: u64,
}

/// Our user hash, kept in the temp directory so peers recognise us.
fn user_hash(temp: &Path) -> Md4Hash {
    let path = temp.join("remule.userhash");
    if let Some(h) = std::fs::read(&path)
        .ok()
        .and_then(|b| Md4Hash::from_slice(&b))
    {
        return h;
    }
    let h = ed2k_server::packets::new_user_hash(&mut rand::thread_rng());
    let _ = std::fs::write(&path, h.0);
    h
}

/// Ctrl-C, or the time limit.
async fn stopped(duration: u64) {
    let limit = async {
        if duration > 0 {
            tokio::time::sleep(Duration::from_secs(duration)).await;
            println!("time is up: saving");
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => println!("interrupted: saving"),
        _ = limit => {}
    }
}

/// Run.
pub async fn run(a: DownloadArgs) -> Result<(), String> {
    for d in [&a.temp, &a.incoming] {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let mut files = existing_downloads(&a.temp)?;
    for f in &files {
        println!(
            "resuming {} ({} of {}, {})",
            f.name(),
            human(f.completed()),
            human(f.size()),
            f.met_path().display()
        );
    }
    let mut link_sources: Vec<(Md4Hash, SocketAddrV4)> = Vec::new();
    for l in &a.links {
        let l = link::parse(l)?;
        link_sources.extend(l.sources.iter().map(|s| (l.hash, *s)));
        if files.iter().any(|f| f.hash() == l.hash) {
            continue;
        }
        let mut f = PartFile::create(&a.temp, &l.name, l.hash, l.size)
            .map_err(|e| format!("{}: {e}", l.name))?;
        if let Some(root) = l.aich {
            f.set_aich_root(root);
        }
        println!(
            "new download {} ({}, {})",
            l.name,
            human(l.size),
            f.met_path().display()
        );
        files.push(f);
    }
    let sharing = !a.share.is_empty();
    if files.is_empty() && !sharing {
        return Err(
            "nothing to do: give ed2k links, a temp directory with downloads, or --share".into(),
        );
    }
    if !files.is_empty() && a.servers.is_empty() && a.kad.is_none() && link_sources.is_empty() {
        return Err("no way to find sources: give --server, --kad or links with sources".into());
    }
    let c = ClientConfig {
        temp: a.temp.clone(),
        incoming: a.incoming.clone(),
        config: a.config.clone(),
        user_hash: user_hash(&a.temp),
        identity: client::load_identity(&a.temp.join("cryptkey.dat"))?,
        servers: a.servers.clone(),
        obfuscate_server: a.obfuscate_server,
        autoconnect: true,
        reconnect: true,
        kad: a.kad.clone().map(|dir| KadSettings {
            dir,
            nodes: a.kad_nodes.clone(),
            bootstrap: a.kad_bootstrap.clone(),
        }),
        tcp_port: a.tcp_port,
        udp_port: a.udp_port,
        nick: a.nick.clone(),
        max_connections: a.max_connections,
        max_download: a.max_download,
        max_upload: a.max_upload,
        upload: sharing,
        share: a.share.clone(),
        reachable: a.reachable,
        allow_lan: a.allow_lan,
        reask: Duration::from_secs(a.reask.max(1)),
        ip_filter: None,
        stop_when_done: true,
        status_every: Duration::from_secs(a.status_every.max(1)),
        ec: None,
    };
    client::run(c, files, link_sources, stopped(a.duration)).await?;
    Ok(())
}
