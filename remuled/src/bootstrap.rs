// SPDX-License-Identifier: GPL-2.0-or-later
//! What `amuled` fetches over HTTP at start, before the networks start
//! (`CamuleApp::OnInit`): a `nodes.dat` when Kad is on and there is none
//! (`UpdateNotesDat` from `KadNodesUrl`), and a `server.met` from each URL
//! in `addresses.dat` when eD2k is on and no server is known, or at every
//! start with `Serverlist` (`UpdateServerMetFromURL`). A missing
//! `addresses.dat` is made first, as `LoadPreferences` does.
//!
//! A downloaded server list is merged into `server.met` as `LoadServerMet`
//! merges: new servers are added, known ones (same address and port) take
//! the downloaded name and description. Files are written to `*.download`
//! first and only then replace the real ones.
//!
//! Not here: zip or gzip lists (unpacking is not ported), conditional
//! requests (aMule asks only for the IP filter), the IP filter update.

use std::path::Path;

use ed2k_formats::addresses_dat::AddressesDat;
use ed2k_formats::amule_conf::{parse_long, ConfFile};
use ed2k_formats::nodes_dat::NodesDat;
use ed2k_formats::server_met::{ServerInfo, ServerMet, VERSION};
use tracing::{info, warn};

use crate::http;

/// The server list `LoadPreferences` puts in a new `addresses.dat`.
pub const DEFAULT_SERVER_MET_URL: &str = "https://upd.emule-security.org/server.met";
/// `KadNodesUrl`'s default.
pub const DEFAULT_NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";

/// What to fetch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Server lists to merge into `server.met`, each in turn.
    pub server_met: Vec<String>,
    /// Where to get a `nodes.dat`.
    pub nodes_dat: Option<String>,
}

/// The server list URLs of `addresses.dat`, making the file when missing
/// (with the legacy `Ed2kServersUrl` if valid, else aMule's default).
pub fn server_list_urls(dir: &Path, conf: &ConfFile, notes: &mut Vec<String>) -> Vec<String> {
    let path = dir.join("addresses.dat");
    if let Ok(b) = std::fs::read(&path) {
        return AddressesDat::from_bytes(b).urls().unwrap_or_else(|e| {
            notes.push(format!("{}: {e:?}", path.display()));
            Vec::new()
        });
    }
    let legacy = conf
        .get("/eMule/Ed2kServersUrl")
        .filter(|u| ed2k_formats::addresses_dat::is_valid_url(u));
    let urls = vec![legacy.unwrap_or(DEFAULT_SERVER_MET_URL).to_owned()];
    match AddressesDat::from_urls(&urls) {
        Ok(a) => {
            if let Err(e) = std::fs::write(&path, a.as_bytes()) {
                notes.push(format!("{}: {e}", path.display()));
            }
        }
        Err(e) => notes.push(e.to_string()),
    }
    urls
}

/// What `amuled` would fetch for this directory.
pub fn plan(dir: &Path, conf: &ConfFile, notes: &mut Vec<String>) -> Plan {
    let int = |k: &str| conf.get(k).and_then(parse_long);
    let flag = |k: &str, default: bool| int(k).map_or(default, |v| v != 0);
    let mut p = Plan::default();
    if flag("/eMule/ConnectToED2K", true) {
        let known = std::fs::read(dir.join("server.met"))
            .ok()
            .and_then(|b| ServerMet::read(&b).ok())
            .is_some_and(|m| !m.servers.is_empty());
        if !known || flag("/eMule/Serverlist", false) {
            p.server_met = server_list_urls(dir, conf, notes);
        }
    }
    if flag("/eMule/ConnectToKad", true) && !dir.join("nodes.dat").exists() {
        let url = conf
            .get("/eMule/KadNodesUrl")
            .filter(|u| !u.is_empty())
            .unwrap_or(DEFAULT_NODES_DAT_URL);
        p.nodes_dat = Some(url.to_owned());
    }
    p
}

/// `LoadServerMet` merging `downloaded` into `current`: the merged list
/// and how many servers were added.
pub fn merge_server_met(current: Option<&ServerMet>, downloaded: &ServerMet) -> (ServerMet, usize) {
    let mut list: Vec<ServerInfo> = current
        .map(|m| m.servers.iter().map(ServerInfo::from_record).collect())
        .unwrap_or_default();
    let address = |s: &ServerInfo| {
        let host = if s.dyn_ip.is_empty() {
            s.ip.map(|ip| ip.to_string()).unwrap_or_default()
        } else {
            s.dyn_ip.to_lowercase()
        };
        (host, s.port)
    };
    let mut added = 0;
    for rec in &downloaded.servers {
        let new = ServerInfo::from_record(rec);
        // CServerList::AddServer: no unusable addresses.
        if new.port == 0 || (new.dyn_ip.is_empty() && new.ip.is_none_or(|ip| ip.is_unspecified())) {
            continue;
        }
        match list.iter_mut().find(|s| address(s) == address(&new)) {
            Some(known) => {
                known.name = new.name;
                if !new.description.is_empty() {
                    known.description = new.description;
                }
            }
            None => {
                list.push(new);
                added += 1;
            }
        }
    }
    let met = ServerMet {
        version: VERSION,
        servers: list.iter().map(ServerInfo::to_record).collect(),
        legacy_counts: false,
    };
    (met, added)
}

/// Download `url` to `<dir>/<name>.download`.
async fn download(
    dir: &Path,
    name: &str,
    url: &str,
) -> Result<(Vec<u8>, std::path::PathBuf), String> {
    let body = http::fetch(url).await?;
    let tmp = dir.join(format!("{name}.download"));
    std::fs::write(&tmp, &body).map_err(|e| format!("{}: {e}", tmp.display()))?;
    Ok((body, tmp))
}

/// Merge the server list at `url` into `<dir>/server.met`.
async fn fetch_server_met(dir: &Path, url: &str) -> Result<usize, String> {
    let (body, tmp) = download(dir, "server.met", url).await?;
    let _ = std::fs::remove_file(&tmp);
    let downloaded = ServerMet::read_packed(&body)
        .ok_or_else(|| "unknown format encountered".to_owned())?
        .map_err(|e| format!("not a server.met: {e}"))?;
    let path = dir.join("server.met");
    let current = std::fs::read(&path)
        .ok()
        .map(|b| match ServerMet::read(&b) {
            Ok(m) => m,
            Err(e) => ServerMet {
                version: VERSION,
                servers: e.salvaged,
                legacy_counts: false,
            },
        });
    let (merged, added) = merge_server_met(current.as_ref(), &downloaded);
    // Written aside, then moved over the old file.
    std::fs::write(&tmp, merged.write()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(added)
}

/// Fetch `<dir>/nodes.dat` from `url`. Unlike aMule, which takes whatever
/// came, a file with no contacts it can read is not kept.
async fn fetch_nodes_dat(dir: &Path, url: &str) -> Result<usize, String> {
    let (body, tmp) = download(dir, "nodes.dat", url).await?;
    let contacts = NodesDat::read(&body).map(|n| n.contacts.len()).unwrap_or(0);
    if contacts == 0 {
        let _ = std::fs::remove_file(&tmp);
        return Err("no contacts in it".to_owned());
    }
    let path = dir.join("nodes.dat");
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(contacts)
}

/// Fetch what `plan` says, logging as aMule does. Failures are logged and
/// leave the files as they were.
pub async fn run(dir: &Path, plan: &Plan) {
    for url in &plan.server_met {
        info!("Start downloading server list from {url}");
        match fetch_server_met(dir, url).await {
            Ok(added) => {
                info!("Finished downloading the server list from {url}: {added} servers added")
            }
            Err(e) => warn!("Failed to download server.met from {url}: {e}"),
        }
    }
    if let Some(url) = &plan.nodes_dat {
        info!("Downloading nodes.dat from {url}");
        match fetch_nodes_dat(dir, url).await {
            Ok(n) => info!("nodes.dat downloaded: {n} contacts"),
            Err(e) => warn!("Failed to download the nodes list from {url}: {e}"),
        }
    }
}
