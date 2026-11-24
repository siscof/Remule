// SPDX-License-Identifier: GPL-2.0-or-later
//! Running from an aMule config directory (`~/.aMule`): what `amuled`
//! reads at start-up, turned into a [`ClientConfig`].
//!
//! * `amule.conf`: nick, ports, limits, the temp and incoming directories,
//!   whether to connect to eD2k and Kad, `FilterLanIPs`, `UDPDisable`.
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
//! * `ipfilter.dat`, then `ipfilter_static.dat`: the IP filter, applied
//!   with `FilterLevel`, `IpFilterClients` and `IpFilterServers`. Missing
//!   ones are made with aMule's placeholder comments.
//! * `[ExternalConnect]` in `amule.conf`: whether, where and with what
//!   password external connections are accepted. A legacy `ECPassword` is
//!   migrated to `ECPasswordVerifier` in `amule.conf`, as aMule 3.3 does.
//!
//! Nothing aMule owns is rewritten except what aMule itself writes as it
//! runs. aMule must not run on the same directory at the same time.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ed2k_formats::amule_conf::{keys, ConfFile, Preferences};
use ed2k_formats::ipfilter::{IpFilter, IpFilterFile};
use ed2k_formats::server_met::{
    ServerInfo, ServerMet, PRIORITY_HIGH, PRIORITY_LOW, PRIORITY_NORMAL,
};
use ed2k_formats::{preferences_dat, shareddir_dat};
use ed2k_types::Md4Hash;
use rand::RngCore;
use remule_core::ip_filter::{AddressFilter, DEFAULT_LEVEL};
use remule_ec::server::{Credentials, Limits};
use remule_ec::srp::{is_password_digest, Verifier};

use crate::client::{load_identity, ClientConfig, KadSettings};
use crate::ec::EcSettings;

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
    /// What was loaded, as aMule logs it.
    pub info: Vec<String>,
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
    let d = shared_dir_intents(dir);
    let mut out: Vec<PathBuf> = d.explicit.iter().map(PathBuf::from).collect();
    for r in &d.recursive {
        expand_recursive(Path::new(r), &mut out);
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(p.clone()));
    out
}

/// The shared folders as configured (`LoadSharedFolderIntents`): the
/// explicit ones and the recursive roots, unexpanded.
pub fn shared_dir_intents(dir: &Path) -> shareddir_dat::SharedDirs {
    shareddir_dat::intents(
        read_opt(&dir.join(shareddir_dat::EXPLICIT_FILE_NAME)).as_deref(),
        read_opt(&dir.join(shareddir_dat::RECURSIVE_FILE_NAME)).as_deref(),
        read_opt(&dir.join(shareddir_dat::LEGACY_FILE_NAME)).as_deref(),
    )
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

/// `CIPFilter`'s placeholder for `ipfilter.dat` (written with a final
/// newline by `CTextFile::WriteLine`).
const IPFILTER_PLACEHOLDER: &str = concat!(
    "# This file is used by aMule to store ipfilter lists downloaded\n",
    "# through the auto-update functionality. Do not save ipfilter-\n",
    "# ranges here that should not be overwritten by aMule.\n",
    "\n",
);
/// And for `ipfilter_static.dat`.
const IPFILTER_STATIC_PLACEHOLDER: &str = concat!(
    "# This file is used to store ipfilter-ranges that should\n",
    "# not be overwritten by aMule. If you wish to keep a custom\n",
    "# set of ipfilter-ranges that take precedence over ipfilter-\n",
    "# ranges acquired through the auto-update functionality, then\n",
    "# place them in this file. aMule will not change this file.\n",
);

/// The names an IP filter archive's list goes by (`ipfilter_files`).
pub const IPFILTER_MEMBERS: &[&str] = &["ipfilter.dat", "guardian.p2p", "guarding.p2p"];

/// One IP filter list, as `CIPFilterTask::LoadFromFile` reads it: missing
/// or empty is no ranges; a zip, gzip or tar one is unpacked in place
/// first (`UnpackArchive`), and one that is not text then is not read.
fn load_filter_list(
    path: &Path,
    notes: &mut Vec<String>,
    info: &mut Vec<String>,
) -> Option<IpFilterFile> {
    use ed2k_formats::archive::{self, FileType};
    let mut bytes = read_opt(path).filter(|b| !b.is_empty())?;
    let packed = matches!(
        archive::guess(&bytes),
        FileType::Zip | FileType::GZip | FileType::Tar
    );
    match archive::unpack(&bytes, IPFILTER_MEMBERS) {
        Some((plain, FileType::Text)) => {
            if packed {
                // As aMule: the archive is replaced by what it held.
                let _ = std::fs::write(path, &plain);
            }
            bytes = plain;
        }
        _ => {
            notes.push(format!(
                "Failed to load ipfilter.dat file '{}', unknown format encountered.",
                path.display()
            ));
            return None;
        }
    }
    let f = IpFilterFile::parse(&bytes);
    let mut msg = format!(
        "Loaded {} IP-ranges from '{}'.",
        f.range_count(),
        path.display()
    );
    if f.bad_lines() > 0 {
        msg.push_str(&format!(
            " {} malformed lines were discarded.",
            f.bad_lines()
        ));
    }
    info.push(msg);
    Some(f)
}

/// The IP filter of a config directory (`CIPFilter`, `CIPFilterTask`):
/// `ipfilter.dat` then `ipfilter_static.dat`, the later winning where they
/// overlap; missing files are made with aMule's placeholders.
pub fn ip_filter(
    dir: &Path,
    conf: &ConfFile,
    notes: &mut Vec<String>,
    info: &mut Vec<String>,
) -> Arc<AddressFilter> {
    for (name, text) in [
        ("ipfilter.dat", IPFILTER_PLACEHOLDER),
        ("ipfilter_static.dat", IPFILTER_STATIC_PLACEHOLDER),
    ] {
        let p = dir.join(name);
        if !p.exists() {
            if let Err(e) = std::fs::write(&p, text) {
                notes.push(format!("{}: {e}", p.display()));
            }
        }
    }
    let int = |key: &str| conf.get(key).and_then(ed2k_formats::amule_conf::parse_long);
    let mut lists: Vec<IpFilterFile> = Vec::new();
    let own = load_filter_list(&dir.join("ipfilter.dat"), notes, info);
    // `IPFilterSystem`: with no ranges of its own, the system-wide list.
    let none_own = own.as_ref().is_none_or(|f| f.range_count() == 0);
    lists.extend(own);
    if none_own && int("/eMule/IPFilterSystem").is_some_and(|v| v != 0) {
        lists.extend(load_filter_list(&system_ip_filter(), notes, info));
    }
    lists.extend(load_filter_list(
        &dir.join("ipfilter_static.dat"),
        notes,
        info,
    ));
    let refs: Vec<&IpFilterFile> = lists.iter().collect();
    let flag = |key: &str| int(key).is_none_or(|v| v != 0);
    let level = int("/eMule/FilterLevel").map_or(DEFAULT_LEVEL, |v| v.clamp(0, 255) as u32);
    Arc::new(AddressFilter::new(
        IpFilter::build(&refs),
        level,
        flag("/ExternalConnect/IpFilterClients"),
        flag("/ExternalConnect/IpFilterServers"),
    ))
}

/// The system-wide IP filter (`IPFilterSystem`): `ipfilter.dat` in the
/// shared data folder, `/usr/share/amule` (next to the program on Windows).
pub fn system_ip_filter() -> PathBuf {
    if cfg!(windows) {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("ipfilter.dat")))
            .unwrap_or_else(|| PathBuf::from("ipfilter.dat"))
    } else {
        PathBuf::from("/usr/share/amule/ipfilter.dat")
    }
}

/// `CIPFilter::Reload`: the lists and `amule.conf`'s filter settings read
/// again into `target`, which everything checking addresses shares.
pub fn reload_ip_filter(dir: &Path, target: &AddressFilter) {
    let conf = read_opt(&dir.join("amule.conf"))
        .map(|b| ConfFile::from_bytes(&b))
        .unwrap_or_default();
    let (mut notes, mut info) = (Vec::new(), Vec::new());
    let fresh = ip_filter(dir, &conf, &mut notes, &mut info);
    for line in info {
        tracing::info!("{line}");
    }
    for line in notes {
        tracing::warn!("{line}");
    }
    target.replace((*fresh).clone());
    tracing::info!("IP filter is ready");
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
    // `UDPDisable`: no client UDP port, so no UDP reasks and no Kad ("Kad
    // makes no sense without the Client-UDP socket", `StartKad`).
    let udp_disabled = conf
        .get("/eMule/UDPDisable")
        .and_then(ed2k_formats::amule_conf::parse_long)
        .is_some_and(|v| v != 0);

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
    let mut info = Vec::new();
    let mut conf = conf;
    let ec = ec_settings(dir, &mut conf, &prefs, &mut notes, &mut info);
    let ip_filter = ip_filter(dir, &conf, &mut notes, &mut info);
    let kad = if prefs.connect_to_kad && !udp_disabled {
        if dir.join("nodes.dat").is_file() {
            Some(KadSettings {
                dir: dir.to_path_buf(),
                nodes: None,
                bootstrap: Vec::new(),
                warmup: crate::client::KAD_WARMUP,
            })
        } else {
            notes.push("no nodes.dat (none could be fetched): Kad off".to_owned());
            None
        }
    } else {
        None
    };

    let mut client = ClientConfig {
        temp: conf_path(dir, prefs.temp_dir.as_deref(), "Temp"),
        incoming: conf_path(dir, prefs.incoming_dir.as_deref(), "Incoming"),
        config: dir.to_path_buf(),
        user_hash: user_hash(dir)?,
        identity: load_identity(&dir.join("cryptkey.dat"))?,
        servers,
        obfuscate_server: false,
        autoconnect: prefs.autoconnect,
        reconnect: prefs.reconnect,
        // RemoveDeadServer (on by default), DeadServerRetry (3).
        dead_server_retries: (conf
            .get("/eMule/RemoveDeadServer")
            .and_then(ed2k_formats::amule_conf::parse_long)
            .unwrap_or(1)
            != 0)
            .then(|| {
                conf.get("/eMule/DeadServerRetry")
                    .and_then(ed2k_formats::amule_conf::parse_long)
                    .map_or(3, |n| n.clamp(0, i64::from(u32::MAX)) as u32)
            }),
        kad,
        tcp_port: prefs.tcp_port,
        udp_port: if udp_disabled { 0 } else { prefs.udp_port },
        nick: prefs.nick.clone(),
        max_connections: prefs
            .max_connections
            .map_or(DEFAULT_MAX_CONNECTIONS, usize::from),
        max_download: prefs.max_download,
        max_upload: prefs.max_upload,
        upload: true,
        share: shared_dirs(dir),
        // Not assumed: a HighID login or Kad's firewall check tell as it runs.
        reachable: false,
        allow_lan: !filter_lan,
        reask: Duration::from_secs(
            60 * conf
                .get("/eMule/SourceReaskMinutes")
                .and_then(ed2k_formats::amule_conf::parse_long)
                .map_or(15, |m| m.clamp(15, 60)) as u64,
        ),
        ip_filter: Some(ip_filter),
        stop_when_done: false,
        status_every: Duration::from_secs(60),
        ec,
    };
    if let Some(e) = client.ec.as_mut() {
        e.prefs = crate::prefs::PrefStore::load(
            dir,
            &conf,
            &crate::prefs::Runtime {
                user_hash: client.user_hash.0,
                incoming: client.incoming.display().to_string(),
                temp: client.temp.display().to_string(),
                shared: client
                    .share
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect(),
                max_connections: client.max_connections.min(usize::from(u16::MAX)) as u16,
                listening: (client.tcp_port, client.udp_port),
            },
        );
    }
    Ok(Loaded {
        client,
        prefs,
        notes,
        info,
    })
}

/// `amule.conf` read again, changed by `f` and written back: for what the
/// daemon itself changes while it runs.
pub fn update_conf(dir: &Path, f: impl FnOnce(&mut ConfFile)) -> Result<(), String> {
    let mut conf = match std::fs::read(dir.join("amule.conf")) {
        Ok(b) => ConfFile::from_bytes(&b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfFile::new(),
        Err(e) => return Err(format!("{}: {e}", dir.join("amule.conf").display())),
    };
    f(&mut conf);
    save_conf(dir, &conf)
}

/// `amule.conf` written back, through a temporary file as wxFileConfig does.
fn save_conf(dir: &Path, conf: &ConfFile) -> Result<(), String> {
    let path = dir.join("amule.conf");
    let tmp = dir.join("amule.conf.tmp");
    std::fs::write(&tmp, conf.to_bytes())
        .and_then(|_| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// What `ECSRP::LoadCredential` makes of the two EC password keys: the
/// verifier (`None`: no EC password), or why external connections are off.
/// A legacy `ECPassword` digest becomes a verifier with a fresh salt,
/// written to `amule.conf`, and the legacy key is removed; a verifier left
/// behind by a downgrade that changed the password is replaced the same way.
pub fn ec_credential(
    dir: &Path,
    conf: &mut ConfFile,
    notes: &mut Vec<String>,
) -> Result<Option<Verifier>, String> {
    let legacy = conf
        .get(keys::EC_PASSWORD_LEGACY)
        .unwrap_or_default()
        .to_owned();
    if !legacy.is_empty() && !is_password_digest(&legacy) {
        return Err(concat!(
            "ECPassword contains an invalid or empty-password digest. ",
            "Run amuled --ec-config to set a new EC password."
        )
        .into());
    }
    let has_legacy = conf.get(keys::EC_PASSWORD_LEGACY).is_some();
    // Remove the legacy key (Cleanup), saying so if that cannot be saved.
    let cleanup = |conf: &mut ConfFile, notes: &mut Vec<String>| {
        if conf.remove(keys::EC_PASSWORD_LEGACY) && save_conf(dir, conf).is_err() {
            notes.push(
                "Could not remove legacy ECPassword; cleanup will be retried on restart.".into(),
            );
        }
    };
    // A new verifier for the legacy digest (Migrate).
    let migrate = |conf: &mut ConfFile, notes: &mut Vec<String>| -> Result<Verifier, String> {
        let v = Verifier::create_random(&legacy).map_err(|_| {
            "Could not generate ECPasswordVerifier; external connections are disabled.".to_owned()
        })?;
        conf.set(keys::EC_PASSWORD_VERIFIER, &v.encode());
        if save_conf(dir, conf).is_ok() {
            cleanup(conf, notes);
        } else {
            notes.push(
                concat!(
                    "Could not persist ECPasswordVerifier; using the legacy ECPassword in ",
                    "memory for this run. Migration will be retried on restart."
                )
                .into(),
            );
        }
        Ok(v)
    };
    let Some(stored) = conf.get(keys::EC_PASSWORD_VERIFIER).map(str::to_owned) else {
        return if legacy.is_empty() {
            Ok(None)
        } else {
            migrate(conf, notes).map(Some)
        };
    };
    let verifier = if stored.is_empty() {
        None
    } else {
        Some(Verifier::decode(&stored).map_err(|_| {
            "Invalid or unsupported ECPasswordVerifier; refusing external connections.".to_owned()
        })?)
    };
    if has_legacy {
        // A downgraded core recreates an empty key on any save; only a
        // non-empty digest can carry a newer password.
        let matches = match &verifier {
            _ if legacy.is_empty() => true,
            Some(v) => v.matches(&legacy),
            None => false,
        };
        if !matches {
            let v = migrate(conf, notes)?;
            notes.push(
                concat!(
                    "Migrating a changed legacy ECPassword after downgrade; ",
                    "the previous verifier no longer authenticates this run."
                )
                .into(),
            );
            return Ok(Some(v));
        }
    }
    cleanup(conf, notes);
    Ok(verifier)
}

/// `[ExternalConnect]`: `None` when external connections are off, with the
/// reason noted as aMule logs it.
fn ec_settings(
    dir: &Path,
    conf: &mut ConfFile,
    prefs: &Preferences,
    notes: &mut Vec<String>,
    info: &mut Vec<String>,
) -> Option<EcSettings> {
    // The credential is loaded (and migrated) with the preferences, whether
    // or not external connections are on.
    let credential = ec_credential(dir, conf, notes);
    if !prefs.accept_external_connections {
        info.push("External connections disabled in config file".into());
        return None;
    }
    let verifier = match credential {
        Ok(Some(v)) => v,
        Ok(None) => {
            notes.push("External connections disabled due to empty password!".into());
            return None;
        }
        Err(e) => {
            notes.push(e);
            return None;
        }
    };
    let ip = if prefs.ec_address.is_empty() {
        Ipv4Addr::UNSPECIFIED
    } else {
        let found = prefs.ec_address.parse().ok().or_else(|| {
            (prefs.ec_address.as_str(), 0)
                .to_socket_addrs()
                .ok()?
                .find_map(|a| match a {
                    SocketAddr::V4(v4) => Some(*v4.ip()),
                    SocketAddr::V6(_) => None,
                })
        });
        found.unwrap_or_else(|| {
            notes.push(format!(
                "External connection: could not bind to '{}', listening on 127.0.0.1 only.",
                prefs.ec_address
            ));
            Ipv4Addr::LOCALHOST
        })
    };
    let limit = |key: &str, default: u64| {
        conf.get(key)
            .and_then(ed2k_formats::amule_conf::parse_long)
            .map_or(default, |v| u64::from(v as u32))
    };
    Some(EcSettings {
        addr: SocketAddrV4::new(ip, prefs.ec_port as u16),
        credentials: Credentials::new(Some(verifier)),
        limits: Limits {
            window_seconds: limit("/ExternalConnect/AuthFailureWindowSeconds", 60),
            threshold: limit("/ExternalConnect/AuthFailureThreshold", 10) as usize,
            lockout_seconds: limit("/ExternalConnect/AuthLockoutSeconds", 300),
        },
        ed2k: prefs.connect_to_ed2k,
        kad: prefs.connect_to_kad,
        // Read with the client, which supplies what amule.conf does not.
        prefs: Default::default(),
    })
}
