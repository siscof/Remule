// SPDX-License-Identifier: GPL-2.0-or-later
//! Upload and download credits per user hash, in `clients.met`
//! (`CClientCreditsList`, ClientCreditsList.cpp).
//!
//! What each peer uploaded to us and downloaded from us decides its credit
//! ratio, which multiplies its upload queue score. A peer that proved its
//! identity with secure ident keeps its public key here, so another client
//! cannot take its credits. Records unseen for 150 days are dropped on
//! load; only records with traffic are written, as aMule does.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed2k_crypto::credits::{score_ratio, IdentState};
use ed2k_formats::clients_met::{ClientsMet, CreditRecord};
use ed2k_types::Md4Hash;

/// `clients.met`
pub const CLIENTS_MET: &str = "clients.met";

/// The credits.
#[derive(Debug)]
pub struct Credits {
    path: PathBuf,
    records: HashMap<Md4Hash, CreditRecord>,
    /// The metadata block after the records, kept as stored.
    trailing: Vec<u8>,
    dirty: bool,
}

impl Credits {
    /// Load `clients.met` from the config directory `dir`, dropping
    /// records unseen for 150 days. A missing file is empty; from a damaged
    /// one, what could be read is kept.
    pub fn load(dir: &Path, now: u32) -> io::Result<Credits> {
        let path = dir.join(CLIENTS_MET);
        let (records, trailing) = match fs::read(&path) {
            Ok(b) => match ClientsMet::read(&b) {
                Ok(m) => (m.records, m.trailing),
                Err(e) => (e.salvaged, Vec::new()),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Vec::new(), Vec::new()),
            Err(e) => return Err(e),
        };
        let before = records.len();
        let records: HashMap<Md4Hash, CreditRecord> = records
            .into_iter()
            .filter(|r| !r.is_expired(now))
            .map(|r| (r.key, r))
            .collect();
        Ok(Credits {
            path,
            dirty: records.len() != before,
            records,
            trailing,
        })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, hash: &Md4Hash) -> Option<&CreditRecord> {
        self.records.get(hash)
    }

    fn entry(&mut self, hash: &Md4Hash, now: u32) -> &mut CreditRecord {
        self.dirty = true;
        let r = self
            .records
            .entry(*hash)
            .or_insert_with(|| CreditRecord::new(*hash));
        r.last_seen = now;
        r
    }

    /// Bytes we sent the peer (`AddUploaded`).
    pub fn add_uploaded(&mut self, hash: &Md4Hash, bytes: u64, now: u32) {
        self.entry(hash, now).uploaded += bytes;
    }

    /// Bytes the peer sent us (`AddDownloaded`).
    pub fn add_downloaded(&mut self, hash: &Md4Hash, bytes: u64, now: u32) {
        self.entry(hash, now).downloaded += bytes;
    }

    /// The public key the peer proved before, for secure ident.
    pub fn public_key(&self, hash: &Md4Hash) -> Option<Vec<u8>> {
        self.records
            .get(hash)
            .map(|r| r.public_key().to_vec())
            .filter(|k| !k.is_empty())
    }

    /// Keep the key a peer just proved (`SetSecureIdent`, `Verified`). A
    /// key already stored is never replaced.
    pub fn set_public_key(&mut self, hash: &Md4Hash, key: &[u8], now: u32) -> bool {
        if key.is_empty() || key.len() > 80 {
            return false;
        }
        let r = self.entry(hash, now);
        if r.key_size != 0 {
            return r.public_key() == key;
        }
        r.secure_ident[..key.len()].copy_from_slice(key);
        r.key_size = key.len() as u8;
        true
    }

    /// `GetScoreRatio` for the peer, given how its identification stands.
    pub fn score_ratio(&self, hash: &Md4Hash, ident: IdentState, crypto_available: bool) -> f32 {
        let (down, up) = self
            .records
            .get(hash)
            .map_or((0, 0), |r| (r.downloaded, r.uploaded));
        score_ratio(ident, crypto_available, down, up)
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// `SaveList`: the records with traffic, through a temporary file.
    pub fn save(&mut self) -> io::Result<()> {
        let mut records: Vec<CreditRecord> = self
            .records
            .values()
            .filter(|r| r.has_traffic())
            .cloned()
            .collect();
        records.sort_by_key(|r| r.key.0);
        let met = ClientsMet {
            records,
            trailing: self.trailing.clone(),
        };
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".new");
        fs::write(&tmp, met.write())?;
        fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }
}
