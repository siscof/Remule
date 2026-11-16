// SPDX-License-Identifier: GPL-2.0-or-later
//! Running from an aMule config directory (`~/.aMule`): what `amuled`
//! reads at start-up, turned into a [`ClientConfig`].
//!
//! * `amule.conf`: nick, ports, limits, the temp and incoming directories,
//!   whether to connect to eD2k and Kad, `FilterLanIPs`.
//! * `preferences.dat`: the user hash; made (and written) when missing or
//!   bad, as aMule does.
//! * `cryptkey.dat`: the secure-ident key; made when missing.
//! * `shareddir-explicit.dat` and `shareddir-recursive.dat`, else
//!   `shareddir.dat`: the shared folders. Recursive ones are expanded to
//!   every folder below them.
//! * `server.met`: the servers, high priority first.
//! * `nodes.dat`, `preferencesKad.dat` and the Kad index files, kept in
//!   the directory itself.
//! * `known.met`, `known2_64.met`, `clients.met`: as the client keeps them.
//!
//! Nothing aMule owns is rewritten except what aMule itself writes as it
//! runs. aMule must not run on the same directory at the same time.

use std::path::{Path, PathBuf};
use std::time::Duration;

use ed2k_formats::amule_conf::{ConfFile, Preferences};
use ed2k_formats::server_met::{
    ServerInfo, ServerMet, PRIORITY_HIGH, PRIORITY_LOW, PRIORITY_NORMAL,
};
use ed2k_formats::{preferences_dat, shareddir_dat};
use ed2k_types::Md4Hash;
use rand::RngCore;

use crate::client::{load_identity, ClientConfig, KadSettings};

/// Peer connections when `amule.conf` does not say
/// (`GetRecommendedMaxConnections` on a system without a lower limit).
pub const DEFAULT_MAX_CONNECTIONS: usize = 500;

/// A loaded config directory.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub client: ClientConfig,
    pub prefs: Preferences,
    /// Things worth telling the user (missing files, features off).
    pub notes: Vec<String>,
}

fn read_opt(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// A path from `amule.conf`, relative ones taken from the config directory.
fn conf_path(dir: &Path, p: Option<&str>, default: &str) -> PathBuf {
    match p {
        Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
        Some(p) => dir.join(p),
        None => dir.join(default),
    }
}

/// The user hash from `preferences.dat`, made and saved if it is missing or
/// bad (`CPreferences::CPreferences`); with the eMule markers.
pub fn user_hash(dir: &Path) -> Result<Md4Hash, String> {
    let path = dir.join(preferences_dat::FILE_NAME);
    let stored = read_opt(&path).and_then(|b| preferences_dat::read(&b));
    let h = match stored {
        Some(h) if !preferences_dat::is_bad(&h) => h,
        _ => {
            let h = preferences_dat::create(|b| rand::rngs::OsRng.fill_bytes(b));
            std::fs::write(&path, preferences_dat::write(&h))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            h
        }
    };
    Ok(preferences_dat::with_markers(h))
}

/// Every folder at and below `root`, in a stable order. Unreadable ones
/// are left out.
fn expand_recursive(root: &Path, out: &mut Vec<PathBuf>) {
    out.push(root.to_path_buf());
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut subs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    subs.sort();
    for s in subs {
        expand_recursive(&s, out);
    }
}

/// The shared folders of a config directory, recursive ones expanded.
pub fn shared_dirs(dir: &Path) -> Vec<PathBuf> {
    let d = shareddir_dat::intents(
        read_opt(&dir.join(shareddir_dat::EXPLICIT_FILE_NAME)).as_deref(),
        read_opt(&dir.join(shareddir_dat::RECURSIVE_FILE_NAME)).as_deref(),
        read_opt(&dir.join(shareddir_dat::LEGACY_FILE_NAME)).as_deref(),
    );
    let mut out: Vec<PathBuf> = d.explicit.iter().map(PathBuf::from).collect();
    for r in &d.recursive {
        expand_recursive(Path::new(r), &mut out);
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(p.clone()));
    out
}

/// The servers of a `server.met`, high priority first, then normal, then
/// low, each in file order. Servers known only by name are left out.
pub fn servers(met: &ServerMet) -> Vec<std::net::SocketAddr> {
    let rank = |p: u32| match p {
        PRIORITY_HIGH => 0,
        PRIORITY_NORMAL => 1,
        PRIORITY_LOW => 2,
        _ => 1,
    };
    let mut v: Vec<(u32, std::net::SocketAddr)> = met
        .servers
        .iter()
        .map(ServerInfo::from_record)
        .filter_map(|s| {
            let ip = s.ip.filter(|ip| !ip.is_unspecified())?;
            (s.port != 0).then(|| (rank(s.preference), (ip, s.port).into()))
        })
        .collect();
    v.sort_by_key(|(r, _)| *r);
    v.into_iter().map(|(_, a)| a).collect()
}

/// Load `dir` as `amuled` would.
pub fn load(dir: &Path) -> Result<Loaded, String> {
    if !dir.is_dir() {
        return Err(format!("{}: not a directory", dir.display()));
    }
    let mut notes = Vec::new();
    let conf = match read_opt(&dir.join("amule.conf")) {
        Some(b) => ConfFile::from_bytes(&b),
        None => {
            notes.push("no amule.conf: aMule's defaults".to_owned());
            ConfFile::new()
        }
    };
    let prefs = Preferences::read(&conf);
    let filter_lan = conf
        .get("/eMule/FilterLanIPs")
        .and_then(ed2k_formats::amule_conf::parse_long)
        .is_none_or(|v| v != 0);

    let servers = if prefs.connect_to_ed2k {
        match read_opt(&dir.join("server.met")) {
            Some(b) => match ServerMet::read(&b) {
                Ok(m) => servers(&m),
                Err(e) => {
                    notes.push(format!("server.met: {e}"));
                    servers(&ServerMet {
                        version: 0,
                        servers: e.salvaged,
                        legacy_counts: false,
                    })
                }
            },
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    if prefs.connect_to_ed2k && servers.is_empty() {
        notes.push("no servers in server.met: eD2k off".to_owned());
    }
    let kad = if prefs.connect_to_kad {
        if dir.join("nodes.dat").is_file() {
            Some(KadSettings {
                dir: dir.to_path_buf(),
                nodes: None,
            })
        } else {
            notes.push("no nodes.dat: Kad off (fetching one is not ported yet)".to_owned());
            None
        }
    } else {
        None
    };

    let client = ClientConfig {
        temp: conf_path(dir, prefs.temp_dir.as_deref(), "Temp"),
        incoming: conf_path(dir, prefs.incoming_dir.as_deref(), "Incoming"),
        config: dir.to_path_buf(),
        user_hash: user_hash(dir)?,
        identity: load_identity(&dir.join("cryptkey.dat"))?,
        servers,
        obfuscate_server: false,
        kad,
        tcp_port: prefs.tcp_port,
        udp_port: prefs.udp_port,
        nick: prefs.nick.clone(),
        max_connections: prefs
            .max_connections
            .map_or(DEFAULT_MAX_CONNECTIONS, usize::from),
        max_download: prefs.max_download,
        max_upload: prefs.max_upload,
        upload: true,
        share: shared_dirs(dir),
        // Unknown until a firewall check, which is not ported: assume not.
        reachable: false,
        allow_lan: !filter_lan,
        stop_when_done: false,
        status_every: Duration::from_secs(60),
    };
    Ok(Loaded {
        client,
        prefs,
        notes,
    })
}
