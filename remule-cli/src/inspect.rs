// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule inspect`: read every file of an aMule config directory, summarise
//! it, and check that remule writes it back byte for byte
//! (MIGRATION_PLAN.md, the phase 2 milestone).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed2k_formats::{
    addresses_dat, amule_conf, canceled_met, clients_met, cryptkey_dat, emfriends_met, ipfilter,
    known2_met, known_met, nodes_dat, part_met, server_met,
};

/// How a file fared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Read, and written back byte for byte.
    Identical,
    /// Read, but written back differently, for a reason the format knows
    /// (for example records aMule itself would drop on its next save).
    Differs(String),
    /// Could not be read.
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileReport {
    /// The file name, relative to the config directory (or the temp dir for part files).
    pub name: String,
    pub path: PathBuf,
    pub summary: String,
    /// One line per entry, with `verbose`.
    pub details: Vec<String>,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Default)]
pub struct Options {
    /// List entries, not just counts.
    pub verbose: bool,
    /// Where the `.part.met` files are; default: amule.conf's TempDir, else `<dir>/Temp`.
    pub temp_dir: Option<PathBuf>,
    /// Write remule's re-encoding of every readable file here, under its own name.
    pub write_to: Option<PathBuf>,
}

/// What reading one file produced.
struct Parsed {
    summary: String,
    details: Vec<String>,
    rewritten: Vec<u8>,
    /// Why the rewrite may legitimately differ, if it does.
    expected_difference: Option<String>,
}

type Handler = fn(&[u8], bool) -> Result<Parsed, String>;

/// The files of a config directory, in the order they are reported.
const FILES: &[(&str, Handler)] = &[
    ("amule.conf", conf),
    ("server.met", server),
    ("known.met", known),
    (known2_met::FILE_NAME, known2),
    ("clients.met", clients),
    (cryptkey_dat::FILE_NAME, cryptkey),
    ("nodes.dat", nodes),
    ("ipfilter.dat", ipfilter),
    ("ipfilter_static.dat", ipfilter),
    ("addresses.dat", addresses),
    ("staticservers.dat", static_servers),
    (canceled_met::FILE_NAME, hash_list),
    (canceled_met::HISTORY_FILE_NAME, hash_list),
    ("emfriends.met", friends),
];

fn plain(summary: String, details: Vec<String>, rewritten: Vec<u8>) -> Parsed {
    Parsed {
        summary,
        details,
        rewritten,
        expected_difference: None,
    }
}

fn conf(b: &[u8], _verbose: bool) -> Result<Parsed, String> {
    let c = amule_conf::ConfFile::from_bytes(b);
    let p = amule_conf::Preferences::read(&c);
    let summary = format!(
        "{} settings; nick {:?}, TCP {} / UDP {}, temp dir {}",
        c.entries().len(),
        p.nick,
        p.tcp_port,
        p.udp_port,
        p.temp_dir.as_deref().unwrap_or("(default)")
    );
    let mut details: Vec<String> = c
        .warnings()
        .iter()
        .map(|w| format!("warning: {w:?}"))
        .collect();
    details.sort();
    Ok(plain(summary, details, c.to_bytes()))
}

fn server(b: &[u8], verbose: bool) -> Result<Parsed, String> {
    let m = server_met::ServerMet::read(b).map_err(|e| e.to_string())?;
    let details = if verbose {
        m.servers
            .iter()
            .map(|r| {
                let s = server_met::ServerInfo::from_record(r);
                format!("{}:{}  users {}  {}", r.ip, s.port, s.users, s.name)
            })
            .collect()
    } else {
        Vec::new()
    };
    let legacy = if m.legacy_counts {
        ", legacy tag counts"
    } else {
        ""
    };
    let mut p = plain(
        format!("{} servers{legacy}", m.servers.len()),
        details,
        m.write(),
    );
    if m.legacy_counts {
        p.expected_difference = Some("written with the corrected tag counts".into());
    }
    Ok(p)
}

fn known(b: &[u8], verbose: bool) -> Result<Parsed, String> {
    let m = known_met::KnownMet::read(b).map_err(|e| e.to_string())?;
    let total: u64 = m
        .records
        .iter()
        .filter_map(|r| known_met::KnownFile::from_record(r).ok())
        .map(|f| f.size)
        .sum();
    let mut details: Vec<String> = m
        .skipped
        .iter()
        .map(|(i, why)| format!("skipped record #{i}: {why:?}"))
        .collect();
    if verbose {
        details.extend(
            m.records
                .iter()
                .filter_map(|r| known_met::KnownFile::from_record(r).ok())
                .map(|f| format!("{}  {:>14}  {}", f.hash, f.size, f.name)),
        );
    }
    let mut p = plain(
        format!(
            "{} files, {} bytes, {} skipped",
            m.records.len(),
            total,
            m.skipped.len()
        ),
        details,
        m.write(),
    );
    if !m.skipped.is_empty() {
        p.expected_difference =
            Some("records with bad hash sets are dropped, as aMule's next save drops them".into());
    }
    Ok(p)
}

fn known2(b: &[u8], _verbose: bool) -> Result<Parsed, String> {
    let m = known2_met::Known2Met::read(b).map_err(|e| e.to_string())?;
    let blocks: usize = m.sets.iter().map(|s| s.block_hashes.len()).sum();
    Ok(plain(
        format!("{} AICH hash sets, {blocks} block hashes", m.sets.len()),
        Vec::new(),
        m.write(),
    ))
}

fn clients(b: &[u8], _verbose: bool) -> Result<Parsed, String> {
    let m = clients_met::ClientsMet::read(b).map_err(|e| e.to_string())?;
    let with_key = m
        .records
        .iter()
        .filter(|r| !r.public_key().is_empty())
        .count();
    Ok(plain(
        format!(
            "{} clients, {with_key} with a secure-ident key",
            m.records.len()
        ),
        Vec::new(),
        m.write(),
    ))
}

fn cryptkey(b: &[u8], _verbose: bool) -> Result<Parsed, String> {
    let k = cryptkey_dat::CryptKey::read(b).map_err(|e| e.to_string())?;
    // Never print the private key: only that it parses and how big the public half is.
    let summary = match k.public_key() {
        Ok(pk) => format!("RSA key, public key {} bytes", pk.len()),
        Err(e) => format!("RSA key that does not parse: {e}"),
    };
    Ok(plain(summary, Vec::new(), k.write()))
}

fn nodes(b: &[u8], verbose: bool) -> Result<Parsed, String> {
    let n = nodes_dat::NodesDat::read(b).map_err(|e| e.to_string())?;
    let details = if verbose {
        n.contacts.iter().map(|c| format!("{c:?}")).collect()
    } else {
        Vec::new()
    };
    Ok(plain(
        format!(
            "{:?}, {} contacts ({} usable)",
            n.format,
            n.contacts.len(),
            n.usable().count()
        ),
        details,
        n.write(),
    ))
}

fn ipfilter(b: &[u8], _verbose: bool) -> Result<Parsed, String> {
    let f = ipfilter::IpFilterFile::parse(b);
    Ok(plain(
        format!(
            "{} ranges ({} IPv6), {} bad lines",
            f.range_count(),
            f.rules6().count(),
            f.bad_lines()
        ),
        Vec::new(),
        f.write(),
    ))
}

fn addresses(b: &[u8], verbose: bool) -> Result<Parsed, String> {
    let a = addresses_dat::AddressesDat::from_bytes(b.to_vec());
    let urls = a
        .urls()
        .map_err(|_| "text encoding not recognised".to_string())?;
    let details = if verbose { urls.clone() } else { Vec::new() };
    Ok(plain(
        format!("{} server.met URLs", urls.len()),
        details,
        a.as_bytes().to_vec(),
    ))
}

fn static_servers(b: &[u8], verbose: bool) -> Result<Parsed, String> {
    let servers = addresses_dat::read_static_servers(b)
        .map_err(|_| "text encoding not recognised".to_string())?;
    let eol = if b.windows(2).any(|w| w == b"\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let details = if verbose {
        servers.iter().map(|s| format!("{s:?}")).collect()
    } else {
        Vec::new()
    };
    let mut p = plain(
        format!("{} static servers", servers.len()),
        details,
        addresses_dat::write_static_servers(&servers, eol),
    );
    p.expected_difference =
        Some("aMule rewrites this file in its own layout (comments and bad lines dropped)".into());
    Ok(p)
}

fn hash_list(b: &[u8], _verbose: bool) -> Result<Parsed, String> {
    let m = canceled_met::CanceledMet::read(b).map_err(|e| e.to_string())?;
    Ok(plain(
        format!("{} hashes ({} distinct)", m.hashes.len(), m.set().len()),
        Vec::new(),
        m.write(),
    ))
}

fn friends(b: &[u8], verbose: bool) -> Result<Parsed, String> {
    let m = emfriends_met::EmfriendsMet::read(b).map_err(|e| e.to_string())?;
    let details = if verbose {
        m.friends
            .iter()
            .filter_map(|r| emfriends_met::Friend::from_record(r).ok())
            .map(|f| format!("{}  {}", f.user_hash, f.name))
            .collect()
    } else {
        Vec::new()
    };
    Ok(plain(
        format!("{} friends", m.friends.len()),
        details,
        m.write(),
    ))
}

fn part(b: &[u8], _verbose: bool) -> Result<Parsed, String> {
    let m = part_met::PartMet::read(b).map_err(|e| e.to_string())?;
    let summary = match part_met::PartFile::from_met(&m) {
        Ok(f) => {
            let pct = if f.size == 0 {
                100.0
            } else {
                f.completed() as f64 * 100.0 / f.size as f64
            };
            format!(
                "{:.1}% of {} bytes{}  {}",
                pct,
                f.size,
                if f.paused { ", paused" } else { "" },
                f.name
            )
        }
        Err(t) => format!("tag {t:?} has the wrong type"),
    };
    let mut p = plain(summary, Vec::new(), m.write());
    if !matches!(m.layout, part_met::Layout::Amule) {
        p.expected_difference =
            Some("an imported eDonkey file is written in aMule's layout".into());
    }
    Ok(p)
}

fn check(name: String, path: PathBuf, handler: Handler, opts: &Options) -> io::Result<FileReport> {
    let bytes = fs::read(&path)?;
    let report = match handler(&bytes, opts.verbose) {
        Err(e) => FileReport {
            name,
            path,
            summary: String::new(),
            details: Vec::new(),
            outcome: Outcome::Failed(e),
        },
        Ok(p) => {
            if let Some(dir) = &opts.write_to {
                let out = dir.join(&name);
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(out, &p.rewritten)?;
            }
            let outcome = if p.rewritten == bytes {
                Outcome::Identical
            } else {
                let at = p
                    .rewritten
                    .iter()
                    .zip(&bytes)
                    .position(|(a, b)| a != b)
                    .unwrap_or(p.rewritten.len().min(bytes.len()));
                let why = p.expected_difference.unwrap_or_else(|| "unexpected".into());
                Outcome::Differs(format!(
                    "first difference at byte {at} ({} → {} bytes): {why}",
                    bytes.len(),
                    p.rewritten.len()
                ))
            };
            FileReport {
                name,
                path,
                summary: p.summary,
                details: p.details,
                outcome,
            }
        }
    };
    Ok(report)
}

/// The temp directory for part files: the option, else amule.conf's
/// TempDir, else `<dir>/Temp`.
fn temp_dir(dir: &Path, opts: &Options) -> PathBuf {
    if let Some(t) = &opts.temp_dir {
        return t.clone();
    }
    fs::read(dir.join("amule.conf"))
        .ok()
        .and_then(|b| amule_conf::Preferences::read(&amule_conf::ConfFile::from_bytes(&b)).temp_dir)
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| dir.join("Temp"))
}

/// Inspect a config directory. Files that are not there are not reported.
pub fn inspect(dir: &Path, opts: &Options) -> io::Result<Vec<FileReport>> {
    if !dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not a directory", dir.display()),
        ));
    }
    let mut reports = Vec::new();
    for (name, handler) in FILES {
        let path = dir.join(name);
        if path.is_file() {
            reports.push(check(name.to_string(), path, *handler, opts)?);
        }
    }
    let temp = temp_dir(dir, opts);
    if let Ok(entries) = fs::read_dir(&temp) {
        let mut parts: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .filter(|p| {
                let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                n.ends_with(".part.met") || n.ends_with(".part.met.bak")
            })
            .collect();
        parts.sort();
        for path in parts {
            let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            reports.push(check(format!("Temp/{file}"), path.clone(), part, opts)?);
        }
    }
    Ok(reports)
}
