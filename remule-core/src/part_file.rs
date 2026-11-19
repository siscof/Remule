// SPDX-License-Identifier: GPL-2.0-or-later
//! A download in progress on disk (`CPartFile`, PartFile.cpp): the `.part`
//! data file and its `.part.met` state, kept the way aMule keeps them so
//! either program can resume the other's downloads.
//!
//! What is ported:
//!
//! * creation (`CreatePartFile`: the lowest free `NNN.part.met`) and loading
//!   (`LoadPartFile`, with the `.bak` fallback, the size checks and the
//!   rehash when the `.part` changed behind aMule's back);
//! * block reservation (`GetNextRequestedBlock`: chunk ranking, then blocks
//!   on the part grid that no other source is fetching);
//! * buffered writes (`WriteToBuffer`, `FlushBuffer`): data fills the gaps
//!   when it arrives and reaches the disk at the next flush;
//! * part hash checks (`HashSinglePart`, `OnAsyncHashComplete`): a corrupt
//!   part becomes a gap again and is listed in the met;
//! * saving (`SavePartFile`, `WritePartMet`, `InstallPartMet`): `.tmp`, then
//!   the old met to `.bak`, then the new one in place;
//! * completion (`CHashingTask`, `PartFileHashFinished`, `CCompletionTask`):
//!   the whole file is hashed again, then moved to the incoming directory.
//!
//! * AICH recovery (`RequestAICHRecovery`, `AICHRecoveryDataAvailable`):
//!   the root hash peers report is voted on; once one is trusted, a corrupt
//!   part asks for recovery data, and the blocks that match it are kept.
//!
//! aMule writes and hashes on worker threads; here it is all synchronous,
//! and the daemon decides where to run it. Not yet ported: ICH, the
//! corruption black box, sparse or preallocated files, the free-space
//! checks.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use ed2k_formats::known_met::{hash_of_part_hashes, part_hash_count};
use ed2k_formats::part_met::{self, Layout, PartMet};
use ed2k_hash::aich::{self, AichTree, RootTrust, RootVotes};
use ed2k_hash::FileHashes;
use ed2k_peer::part_status::ed2k_part_count;
use ed2k_peer::PartStatus;
use ed2k_types::ed2k::{EMBLOCKSIZE, MAX_FILE_SIZE, PARTSIZE};
use ed2k_types::{AichHash, Md4Hash};
use md4::{Digest, Md4};

use crate::blocks::{self, ChunkInfo};
use crate::GapList;

/// Flush after this many buffered writes, however small (aMule's count
/// threshold, which bounds the bookkeeping for tiny packets).
const FLUSH_WRITES: usize = 4096;

/// Flush once this much data is buffered. aMule shares one budget among
/// all downloads (`WriteBufferBudget`); here each file has its own.
pub const DEFAULT_BUFFER_LIMIT: u64 = 1 << 20;

/// The other files a `.part.met` may have beside it, removed on completion.
const MET_SIDE_FILES: [&str; 5] = ["", ".bak", ".seeds", ".tmp", ".bak.tmp"];

/// `PS_*`, those a part file goes through here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No part verified yet (`PS_EMPTY`).
    Empty,
    /// At least one part verified, so it can be shared (`PS_READY`).
    Ready,
    /// Every byte is present; [`PartFile::complete`] is due (`PS_COMPLETING`).
    Completing,
    /// Moved to the incoming directory (`PS_COMPLETE`).
    Complete,
    /// A disk error stopped the download (`PS_ERROR`).
    Error,
}

/// Something the application should know, from [`PartFile::take_events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEvent {
    /// A part passed its hash check.
    PartVerified(u16),
    /// A part failed its hash check and is missing again.
    PartCorrupt(u16),
    /// A part is complete but the part hashes are unknown: ask a peer.
    HashSetNeeded,
    /// Every byte is present: call [`PartFile::complete`].
    ReadyToComplete,
    /// A corrupt part could be recovered: ask a peer that reported this
    /// AICH root for the part's recovery data (`RequestAICHRecovery`), and
    /// give it to [`PartFile::aich_recovery_data`].
    AichRecoveryWanted { part: u16, root: AichHash },
    /// A disk error; the file is now [`Status::Error`].
    Error(String),
}

/// `EAICHStatus`, as far as a download goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AichStatus {
    /// No root known (`AICH_EMPTY`).
    Empty,
    /// Peers reported a root, not enough of them agree (`AICH_UNTRUSTED`).
    Untrusted,
    /// Enough peers agree (`AICH_TRUSTED`).
    Trusted,
    /// From the met or an ed2k link: saved with the download (`AICH_VERIFIED`).
    Verified,
    /// Recovery data contradicted the part hashes (`AICH_ERROR`).
    Error,
}

/// What [`PartFile::complete`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Completion {
    /// The file checked out and is now at this path.
    Done(PathBuf),
    /// These parts did not match their hashes and are missing again.
    Corrupt(Vec<u16>),
    /// The file does not match its hash and, without the part hashes, the
    /// bad part cannot be found. Completion resumes when a peer sends them.
    AwaitingHashSet,
}

/// Why a `.part.met` could not be loaded.
#[derive(Debug)]
pub enum OpenError {
    Io(io::Error),
    Met(part_met::Error),
    /// The met says the file is empty or larger than eD2k allows.
    BadSize(u64),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Io(e) => write!(f, "{e}"),
            OpenError::Met(e) => write!(f, "{e}"),
            OpenError::BadSize(s) => write!(f, "part.met gives an invalid file size ({s})"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

/// A download in progress.
#[derive(Debug)]
pub struct PartFile {
    met_path: PathBuf,
    part_path: PathBuf,
    /// The `.part`, open while the download is.
    file: Option<File>,
    /// What the met stores. Its `gaps` stay empty: [`GapList`] has them.
    info: part_met::PartFile,
    gaps: GapList,
    /// Blocks being downloaded, inclusive (`m_requestedblocks_list`).
    requested: Vec<(u64, u64)>,
    /// Data not yet on disk, by start offset. The ranges are disjoint: each
    /// filled its gap when it was buffered.
    buffered: std::collections::BTreeMap<u64, Vec<u8>>,
    buffered_bytes: u64,
    buffered_writes: usize,
    buffer_limit: u64,
    /// Parts written since their last hash check (`m_aChangedPart`).
    changed: Vec<bool>,
    hash_set_needed: bool,
    /// Completion found a bad file and no part hashes to find the bad part.
    awaiting_hash_set: bool,
    status: Status,
    /// The met differs from what is on disk.
    dirty: bool,
    /// Sources that have each part (`m_SrcpartFrequency`).
    frequency: Vec<u16>,
    sources: u32,
    complete_sources: u16,
    /// Rank the first and last parts higher (`GetPreviewPrio` for an
    /// archive or a video).
    preview_priority: bool,
    rng: u64,
    events: Vec<FileEvent>,
    /// Bytes thrown away by failed hash checks (`m_iLostDueToCorruption`).
    lost_to_corruption: u64,
    aich_status: AichStatus,
    aich_root: Option<AichHash>,
    aich_votes: RootVotes,
    /// The tree recovery data builds up, under `aich_root`.
    aich_tree: Option<AichTree>,
    /// Parts whose recovery data was asked for (`IsClientRequestPending`).
    aich_wanted: Vec<u16>,
    /// Bytes saved by AICH recovery.
    recovered_by_aich: u64,
}

/// The `.part`'s mtime as aMule stores it: seconds since 1970, 32 bits.
fn mtime(meta: &fs::Metadata) -> u32 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as u32)
}

fn with_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(ext);
    PathBuf::from(s)
}

/// `CPath::Cleanup(keepSpaces = true, isFAT32)`: drop `/` and control
/// characters; on Windows also the characters its file systems refuse.
pub fn clean_file_name(name: &str) -> String {
    let fat = cfg!(windows);
    let s: String = name
        .chars()
        .filter(|&c| {
            !(c == '/'
                || u32::from(c) < 32
                || (fat && matches!(c, '"' | '*' | '<' | '>' | '?' | '|' | '\\' | ':')))
        })
        .collect();
    if s.is_empty() {
        "Unknown".to_owned()
    } else {
        s
    }
}

/// `CPath::AddPostfix`: `name.ext` → `name(n).ext`.
fn add_postfix(name: &str, n: u32) -> String {
    match name.rfind('.') {
        Some(dot) if dot > 0 => format!("{}({n}){}", &name[..dot], &name[dot..]),
        _ => format!("{name}({n})"),
    }
}

/// Where a completed file goes: `dir/name`, or `dir/name(0).ext`,
/// `dir/name(1).ext`, ... if that exists (`CCompletionTask::Entry`).
pub fn completed_path(dir: &Path, name: &str) -> PathBuf {
    let clean = clean_file_name(name);
    let mut path = dir.join(&clean);
    let mut n = 0;
    while path.exists() {
        path = dir.join(add_postfix(&clean, n));
        n += 1;
    }
    path
}

impl PartFile {
    /// `CreatePartFile`: a new download in `dir`, as the lowest free
    /// `NNN.part` / `NNN.part.met`. The met is written at once, which
    /// reserves the number.
    pub fn create(dir: &Path, name: &str, hash: Md4Hash, size: u64) -> io::Result<PartFile> {
        if size == 0 || size > MAX_FILE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid file size {size}"),
            ));
        }
        let mut n = 1u32;
        let met_path = loop {
            let p = dir.join(format!("{n:03}.part.met"));
            if !p.exists() {
                break p;
            }
            n += 1;
        };
        let part_path = met_path.with_extension("");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part_path)?;
        let info = part_met::PartFile {
            hash,
            name: name.to_owned(),
            size,
            down_priority: part_met::priority::NORMAL,
            up_priority: part_met::priority::NORMAL,
            ..Default::default()
        };
        let mut pf = PartFile::new(met_path, part_path, file, info, GapList::new(size, true));
        pf.hash_set_needed = part_hash_count(size) > 0;
        pf.save()?;
        Ok(pf)
    }

    fn new(
        met_path: PathBuf,
        part_path: PathBuf,
        file: File,
        info: part_met::PartFile,
        gaps: GapList,
    ) -> PartFile {
        let parts = usize::from(gaps.part_count());
        // Seeded from the file hash: different files spread differently,
        // and a test run is repeatable.
        let seed = u64::from_le_bytes(info.hash.0[..8].try_into().unwrap()) | 1;
        // A root in the met was verified (`FT_AICH_HASH`).
        let aich_root = info.aich_hash.as_deref().and_then(|s| s.parse().ok());
        PartFile {
            met_path,
            part_path,
            file: Some(file),
            info,
            gaps,
            requested: Vec::new(),
            buffered: Default::default(),
            buffered_bytes: 0,
            buffered_writes: 0,
            buffer_limit: DEFAULT_BUFFER_LIMIT,
            changed: vec![false; parts],
            hash_set_needed: false,
            awaiting_hash_set: false,
            status: Status::Empty,
            dirty: false,
            frequency: vec![0; parts],
            sources: 0,
            complete_sources: 0,
            preview_priority: false,
            rng: seed,
            events: Vec::new(),
            lost_to_corruption: 0,
            aich_status: if aich_root.is_some() {
                AichStatus::Verified
            } else {
                AichStatus::Empty
            },
            aich_root,
            aich_votes: RootVotes::default(),
            aich_tree: None,
            aich_wanted: Vec::new(),
            recovered_by_aich: 0,
        }
    }

    /// `LoadPartFile`: resume the download whose met is at `met_path`
    /// (`.../NNN.part.met`; the data is `.../NNN.part`). If the met cannot
    /// be read, its `.bak` is tried and, if that loads, saved as the met.
    pub fn open(met_path: &Path) -> Result<PartFile, OpenError> {
        let load = |p: &Path| -> Result<PartMet, OpenError> {
            let bytes = fs::read(p)?;
            PartMet::read(&bytes).map_err(OpenError::Met)
        };
        let (met, from_backup) = match load(met_path) {
            Ok(m) => (m, false),
            Err(e) => match load(&with_ext(met_path, ".bak")) {
                Ok(m) => (m, true),
                Err(_) => return Err(e),
            },
        };
        let mut info = part_met::PartFile::from_met(&met)
            .map_err(|t| OpenError::Met(part_met::Error::WrongType(t)))?;
        if info.size == 0 || info.size > MAX_FILE_SIZE {
            return Err(OpenError::BadSize(info.size));
        }
        let gaps = GapList::with_gaps(info.size, &info.gaps);
        info.gaps.clear();
        let imported = met.layout != Layout::Amule;

        let part_path = met_path.with_extension("");
        let file = OpenOptions::new().read(true).write(true).open(&part_path)?;
        let size = info.size;
        let date = info.date;
        let mut pf = PartFile::new(met_path.to_owned(), part_path, file, info, gaps);

        // SafeHash: whatever the .part lacks is missing; it is never longer
        // than the file.
        let len = pf.handle()?.metadata()?.len();
        if len < size {
            pf.gaps.add(len, size - 1);
        } else if len > size {
            pf.handle()?.set_len(size)?;
        }

        pf.hash_set_needed = pf.info.part_hashes.len() != part_hash_count(size);
        if !pf.hash_set_needed && (0..pf.gaps.part_count()).any(|p| pf.gaps.is_part_complete(p)) {
            pf.status = Status::Ready;
        }

        if pf.gaps.is_complete() {
            pf.status = Status::Completing;
            pf.events.push(FileEvent::ReadyToComplete);
        } else if !imported && !pf.hash_set_needed {
            // The .part changed since the met was written: check every part.
            let meta = pf.handle()?.metadata()?;
            if mtime(&meta) != date && meta.len() > 0 {
                let result = pf.hash_whole_file()?;
                pf.apply_rehash(&result);
            }
        }
        if from_backup || pf.dirty {
            pf.save()?;
        }
        Ok(pf)
    }

    fn handle(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("the part file is closed"))
    }

    // ---- accessors ----

    pub fn hash(&self) -> Md4Hash {
        self.info.hash
    }

    pub fn size(&self) -> u64 {
        self.info.size
    }

    pub fn name(&self) -> &str {
        &self.info.name
    }

    pub fn met_path(&self) -> &Path {
        &self.met_path
    }

    pub fn part_path(&self) -> &Path {
        &self.part_path
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// What the met stores, apart from the gaps.
    pub fn info(&self) -> &part_met::PartFile {
        &self.info
    }

    pub fn gaps(&self) -> &GapList {
        &self.gaps
    }

    /// Bytes present (`completedsize`), buffered data included.
    pub fn completed(&self) -> u64 {
        self.size() - self.gaps.gap_size()
    }

    /// Bytes received, as aMule counts them (duplicates and corrupt data
    /// included).
    pub fn transferred(&self) -> u64 {
        self.info.transferred
    }

    pub fn lost_to_corruption(&self) -> u64 {
        self.lost_to_corruption
    }

    pub fn hash_set_needed(&self) -> bool {
        self.hash_set_needed
    }

    pub fn part_hashes(&self) -> &[Md4Hash] {
        &self.info.part_hashes
    }

    pub fn corrupted_parts(&self) -> &[u16] {
        &self.info.corrupted_parts
    }

    pub fn is_paused(&self) -> bool {
        self.info.paused
    }

    /// Paused, or past downloading.
    pub fn is_stopped(&self) -> bool {
        self.info.paused
            || matches!(
                self.status,
                Status::Completing | Status::Complete | Status::Error
            )
    }

    /// Blocks being downloaded, inclusive, as aMule keeps them.
    pub fn requested_inclusive(&self) -> &[(u64, u64)] {
        &self.requested
    }

    /// How many known sources have each part (`m_SrcpartFrequency`).
    pub fn part_frequency(&self) -> &[u16] {
        &self.frequency
    }

    /// Blocks being downloaded, half-open.
    pub fn requested_blocks(&self) -> Vec<Range<u64>> {
        self.requested.iter().map(|&(s, e)| s..e + 1).collect()
    }

    pub fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }

    pub fn complete_sources(&self) -> u16 {
        self.complete_sources
    }

    pub fn aich_status(&self) -> AichStatus {
        self.aich_status
    }

    pub fn aich_root(&self) -> Option<AichHash> {
        self.aich_root
    }

    /// Bytes of corrupt parts kept thanks to AICH recovery.
    pub fn recovered_by_aich(&self) -> u64 {
        self.recovered_by_aich
    }

    /// Parts whose recovery data is wanted and not yet received.
    pub fn aich_wanted(&self) -> &[u16] {
        &self.aich_wanted
    }

    // ---- settings ----

    pub fn set_paused(&mut self, paused: bool) {
        if self.info.paused != paused {
            self.info.paused = paused;
            self.dirty = true;
        }
    }

    /// The AICH root from an ed2k link (`h=`): verified, and saved with
    /// the download.
    pub fn set_aich_root(&mut self, root: AichHash) {
        self.aich_status = AichStatus::Verified;
        if self.aich_root != Some(root) {
            self.aich_tree = None;
        }
        self.aich_root = Some(root);
        self.info.aich_hash = Some(root.to_string());
        self.dirty = true;
    }

    /// `UntrustedHashReceived`: a source reported this AICH root. `key` is
    /// its subnet ([`aich::signing_key_v4`] or [`aich::signing_key_v6`]);
    /// `from_kad` for a root from a Kad search result. A verified root is
    /// never replaced.
    pub fn aich_hash_received(&mut self, root: AichHash, key: u32, from_kad: bool) {
        if !matches!(
            self.aich_status,
            AichStatus::Empty | AichStatus::Untrusted | AichStatus::Trusted
        ) {
            return;
        }
        let Some(trust) = self.aich_votes.received(root, key, from_kad) else {
            return;
        };
        self.aich_status = match trust {
            RootTrust::Trusted(_) => AichStatus::Trusted,
            RootTrust::Untrusted(_) => AichStatus::Untrusted,
        };
        if self.aich_root != Some(trust.hash()) {
            self.aich_root = Some(trust.hash());
            self.aich_tree = None;
        }
    }

    /// Trust whatever root is reported most (`IsTrustingEveryHash`).
    pub fn set_trust_every_aich_hash(&mut self, on: bool) {
        self.aich_votes.trust_every_hash = on;
    }

    /// `RequestAICHRecovery`, as far as the file goes: with a trusted root,
    /// a part bigger than one block, and no request out for it.
    fn want_aich_recovery(&mut self, part: u16) {
        let Some(root) = self.aich_root else { return };
        if !matches!(self.aich_status, AichStatus::Trusted | AichStatus::Verified)
            || self.aich_wanted.contains(&part)
        {
            return;
        }
        let (s, e) = self.gaps.part_range(part);
        if e - s < u64::from(EMBLOCKSIZE) {
            return;
        }
        self.aich_wanted.push(part);
        self.events
            .push(FileEvent::AichRecoveryWanted { part, root });
    }

    /// No peer could send the recovery data for `part`
    /// (`ClientAICHRequestFailed`): it may be asked for again.
    pub fn aich_recovery_failed(&mut self, part: u16) {
        self.aich_wanted.retain(|&p| p != part);
    }

    /// `ReadRecoveryData` and `AICHRecoveryDataAvailable`: recovery data
    /// for `part` under `root` arrived. If it hashes up to our trusted
    /// root, every block of the part whose SHA-1 matches is kept; the rest
    /// stays missing. Returns the bytes kept, or `None` if the data was
    /// not usable.
    pub fn aich_recovery_data(
        &mut self,
        part: u16,
        root: AichHash,
        data: &[u8],
    ) -> io::Result<Option<u64>> {
        self.aich_wanted.retain(|&p| p != part);
        if !matches!(self.aich_status, AichStatus::Trusted | AichStatus::Verified)
            || self.aich_root != Some(root)
            || part >= self.gaps.part_count()
        {
            return Ok(None);
        }
        let size = self.size();
        let start = u64::from(part) * PARTSIZE;
        let tree = self
            .aich_tree
            .get_or_insert_with(|| AichTree::with_root(size, root));
        if !tree.read_recovery_data(start, data) {
            return Ok(None);
        }
        let Some(verified) = tree.verified_block_hashes(start) else {
            return Ok(None);
        };
        self.flush()?;
        if self.gaps.is_part_complete(part) {
            return Ok(Some(0));
        }
        let (s, e) = self.gaps.part_range(part);
        let len = (e - s + 1) as usize;
        let mut buf = vec![0u8; len];
        let have = self
            .handle()?
            .metadata()?
            .len()
            .saturating_sub(s)
            .min(len as u64) as usize;
        {
            let f = self.handle()?;
            f.seek(SeekFrom::Start(s))?;
            f.read_exact(&mut buf[..have])?;
        }
        let ours = aich::block_hashes(&buf);
        let mut recovered = 0;
        for (i, (o, v)) in ours.iter().zip(&verified).enumerate() {
            if o != v {
                continue;
            }
            let bs = s + i as u64 * u64::from(EMBLOCKSIZE);
            let be = (bs + u64::from(EMBLOCKSIZE)).min(e + 1) - 1;
            if bs >= s + have as u64 {
                continue;
            }
            self.gaps.fill(bs, be);
            self.requested.retain(|&(rs, re)| !(rs >= bs && re <= be));
            recovered += be - bs + 1;
        }
        self.recovered_by_aich += recovered;
        if self.gaps.is_part_complete(part) {
            if self.verify_part(part)? {
                if self.status == Status::Empty && !self.hash_set_needed {
                    self.status = Status::Ready;
                }
                self.events.push(FileEvent::PartVerified(part));
                if self.gaps.is_complete() {
                    self.status = Status::Completing;
                    self.events.push(FileEvent::ReadyToComplete);
                }
            } else {
                // The recovery data and the part hash disagree.
                self.aich_status = AichStatus::Error;
                self.info.aich_hash = None;
                self.gaps.add_part(part);
                self.recovered_by_aich -= recovered;
                recovered = 0;
            }
        }
        // Done what can be done: no longer listed as corrupt.
        self.info.corrupted_parts.retain(|&p| p != part);
        self.dirty = true;
        self.save_met()?;
        Ok(Some(recovered))
    }

    pub fn set_complete_sources(&mut self, n: u16) {
        self.complete_sources = n;
    }

    pub fn set_preview_priority(&mut self, on: bool) {
        self.preview_priority = on;
    }

    pub fn set_buffer_limit(&mut self, bytes: u64) {
        self.buffer_limit = bytes;
    }

    /// Reseed the chunk choice among equals.
    pub fn set_seed(&mut self, seed: u64) {
        self.rng = seed | 1;
    }

    pub fn take_events(&mut self) -> Vec<FileEvent> {
        std::mem::take(&mut self.events)
    }

    fn random(&mut self) -> u32 {
        // xorshift64
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        (x >> 32) as u32
    }

    // ---- sources ----

    /// `UpdatePartsFrequency(client, true)`: a source with these parts
    /// joined. Also counts it for the rarity bounds (`GetSourceCount`).
    pub fn add_source(&mut self, parts: &PartStatus) {
        self.sources += 1;
        for (i, f) in self.frequency.iter_mut().enumerate() {
            if parts.has(i) {
                *f = f.saturating_add(1);
            }
        }
    }

    /// `UpdatePartsFrequency(client, false)`
    pub fn remove_source(&mut self, parts: &PartStatus) {
        self.sources = self.sources.saturating_sub(1);
        for (i, f) in self.frequency.iter_mut().enumerate() {
            if parts.has(i) {
                *f = f.saturating_sub(1);
            }
        }
    }

    /// Our part status (`WritePartStatus`): one bit per eD2k part, set for
    /// parts with no gap.
    pub fn part_status(&self) -> PartStatus {
        let n = ed2k_part_count(self.size()) as u16;
        PartStatus::Parts((0..n).map(|p| self.gaps.is_part_complete(p)).collect())
    }

    /// `LoadHashsetFromFile(checkhash = true)`: take part hashes from a peer.
    /// False if there are not as many as the file needs or they do not hash
    /// to the file hash; the stored ones are then kept.
    ///
    /// Parts completed while the hashes were unknown passed unchecked; they
    /// are checked at the next flush. (aMule leaves them to the final hash.)
    pub fn set_hash_set(&mut self, parts: Vec<Md4Hash>) -> bool {
        if parts.len() != part_hash_count(self.size()) {
            return false;
        }
        if !parts.is_empty() && hash_of_part_hashes(&parts) != self.hash() {
            return false;
        }
        let had = self.info.part_hashes == parts;
        self.info.part_hashes = parts;
        self.hash_set_needed = false;
        if !had {
            self.dirty = true;
            for p in 0..self.gaps.part_count() {
                if self.gaps.is_part_complete(p) {
                    self.changed[usize::from(p)] = true;
                }
            }
        }
        // HashsetReceived
        if self.awaiting_hash_set {
            self.awaiting_hash_set = false;
            if self.gaps.is_complete() {
                self.status = Status::Completing;
                self.events.push(FileEvent::ReadyToComplete);
            }
        }
        true
    }

    // ---- block reservation ----

    /// `GetNextEmptyBlockInPart`
    fn next_empty_block(&self, part: u16) -> Option<(u64, u64)> {
        if part >= self.gaps.part_count() {
            return None;
        }
        blocks::find_next_download_block(
            self.gaps.part_range(part),
            u64::from(EMBLOCKSIZE),
            self.gaps.iter(),
            &self.requested,
        )
    }

    /// `IsAlreadyRequested`
    fn is_requested(&self, (start, end): (u64, u64)) -> bool {
        self.requested.iter().any(|&(s, e)| start <= e && end >= s)
    }

    /// The parts `peer` has that still have blocks free, ranked.
    fn rank_chunks(&self, peer: &PartStatus) -> Vec<(u16, u32)> {
        let count = self.gaps.part_count();
        let bounds = blocks::rarity_bounds(self.sources);
        (0..count)
            .filter(|&p| peer.has(usize::from(p)) && self.next_empty_block(p).is_some())
            .map(|p| {
                let range = self.gaps.part_range(p);
                let preview = self.preview_priority
                    && (p == 0
                        || p == count - 1
                        || (p + 2 == count && self.size() - range.1 < PARTSIZE / 3));
                let present = PARTSIZE - self.gaps.part_gap_size(p);
                let info = ChunkInfo {
                    frequency: self.frequency[usize::from(p)],
                    preview,
                    requested: self.is_requested(range),
                    completion: (present / (PARTSIZE / 100)) as u16,
                };
                (p, blocks::chunk_rank(info, bounds))
            })
            .collect()
    }

    /// `GetNextRequestedBlock`: reserve up to `count` blocks `peer` has and
    /// nobody is fetching, each at most [`EMBLOCKSIZE`] and within one part.
    /// `last_part` is the source's current part (`m_lastPartAsked`): blocks
    /// come from it while it has free ones, then the best-ranked part is
    /// chosen, at random among equals.
    pub fn reserve_blocks(
        &mut self,
        last_part: &mut Option<u16>,
        peer: &PartStatus,
        count: usize,
    ) -> Vec<Range<u64>> {
        let mut out = Vec::new();
        if matches!(peer, PartStatus::Parts(p) if p.is_empty()) || self.is_stopped() {
            return out;
        }
        let mut chunks: Vec<(u16, u32)> = Vec::new();
        while out.len() < count {
            if let Some(part) = *last_part {
                if let Some(block) = self.next_empty_block(part) {
                    self.requested.push(block);
                    out.push(block.0..block.1 + 1);
                    continue;
                }
                *last_part = None;
            }
            if chunks.is_empty() {
                chunks = self.rank_chunks(peer);
                if chunks.is_empty() {
                    break;
                }
            }
            let best = chunks.iter().map(|c| c.1).min().unwrap();
            let tied = chunks.iter().filter(|c| c.1 == best).count();
            let pick = blocks::pick_tied(tied, self.random());
            let idx = chunks
                .iter()
                .enumerate()
                .filter(|(_, c)| c.1 == best)
                .nth(pick)
                .map(|(i, _)| i)
                .unwrap();
            *last_part = Some(chunks.remove(idx).0);
        }
        out
    }

    /// `RemoveBlockFromList`: drop the reservations covering `block`,
    /// finished or not. The gaps say what was written.
    pub fn release_block(&mut self, block: Range<u64>) {
        if block.is_empty() {
            return;
        }
        let (s, e) = (block.start, block.end - 1);
        self.requested.retain(|&(rs, re)| !(rs <= s && re >= e));
    }

    // ---- writing ----

    /// `WriteToBuffer`: take data received for `start..start + data.len()`.
    /// It must lie in a reserved block. Data already present, data touching
    /// a complete part and data outside every reservation are dropped (a
    /// duplicate packet, a cancelled block). Returns the bytes kept; they
    /// fill their gaps at once and reach the disk at the next flush, which
    /// happens here when enough is buffered or the file is complete.
    pub fn write(&mut self, start: u64, data: &[u8]) -> io::Result<u64> {
        if data.is_empty() || matches!(self.status, Status::Complete | Status::Error) {
            return Ok(0);
        }
        self.info.transferred += data.len() as u64;
        let end = start + data.len() as u64 - 1;
        if end >= self.size() || self.gaps.is_range_complete(start, end) {
            return Ok(0);
        }
        let (first, last) = ((start / PARTSIZE) as u16, (end / PARTSIZE) as u16);
        if self.gaps.is_part_complete(first) || self.gaps.is_part_complete(last) {
            return Ok(0);
        }
        if !self.requested.iter().any(|&(s, e)| s <= start && end <= e) {
            return Ok(0);
        }
        let mut kept = 0;
        for (fs, fe) in self.gaps.missing_in(start, end) {
            let piece = &data[(fs - start) as usize..=(fe - start) as usize];
            self.buffered.insert(fs, piece.to_vec());
            self.gaps.fill(fs, fe);
            kept += fe - fs + 1;
            self.buffered_writes += 1;
        }
        self.buffered_bytes += kept;
        self.dirty = true;
        if self.gaps.is_complete()
            || self.buffered_writes >= FLUSH_WRITES
            || self.buffered_bytes >= self.buffer_limit
        {
            self.flush()?;
        }
        Ok(kept)
    }

    /// Put buffered data on disk. On failure, what did not land is a gap
    /// again, so the met never claims data the `.part` lacks.
    fn write_buffers(&mut self) -> io::Result<()> {
        if self.buffered.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.buffered);
        self.buffered_bytes = 0;
        self.buffered_writes = 0;
        let mut result = Ok(());
        for (start, data) in pending {
            let end = start + data.len() as u64 - 1;
            if result.is_ok() {
                result = self.handle().and_then(|f| {
                    f.seek(SeekFrom::Start(start))?;
                    f.write_all(&data)
                });
            }
            if result.is_ok() {
                for p in start / PARTSIZE..=end / PARTSIZE {
                    self.changed[p as usize] = true;
                }
            } else {
                self.gaps.add(start, end);
            }
        }
        result
    }

    fn fail(&mut self, e: &io::Error) {
        self.status = Status::Error;
        self.events.push(FileEvent::Error(e.to_string()));
    }

    /// `FlushBuffer`: write what is buffered, check the hash of every part
    /// that is complete and was written to, and save the met if anything
    /// changed. Call it now and then (aMule: about every minute) besides
    /// the flushes [`write`](Self::write) makes.
    pub fn flush(&mut self) -> io::Result<()> {
        if matches!(self.status, Status::Complete | Status::Error) {
            return Ok(());
        }
        let r = self.flush_inner();
        if let Err(e) = &r {
            self.fail(e);
        }
        r
    }

    fn flush_inner(&mut self) -> io::Result<()> {
        self.write_buffers()?;
        let size = self.size();
        if self.handle()?.metadata()?.len() > size {
            self.handle()?.set_len(size)?;
        }
        if self.gaps.is_complete() {
            // The final hash covers every part.
            self.changed.fill(false);
            if matches!(self.status, Status::Empty | Status::Ready) && !self.awaiting_hash_set {
                self.status = Status::Completing;
                self.events.push(FileEvent::ReadyToComplete);
            }
        } else {
            for p in 0..self.gaps.part_count() {
                if !std::mem::take(&mut self.changed[usize::from(p)]) {
                    continue;
                }
                // A part with gaps left is checked when its last write lands.
                if self.gaps.is_part_complete(p) {
                    let ok = self.verify_part(p)?;
                    self.on_part_hashed(p, ok);
                }
            }
        }
        if self.dirty {
            self.save_met()?;
        }
        Ok(())
    }

    fn hash_range(&mut self, start: u64, len: u64) -> io::Result<Md4Hash> {
        let f = self.handle()?;
        f.seek(SeekFrom::Start(start))?;
        let mut h = Md4::new();
        let mut left = len;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let n = (buf.len() as u64).min(left) as usize;
            f.read_exact(&mut buf[..n])?;
            h.update(&buf[..n]);
            left -= n as u64;
        }
        Ok(Md4Hash(h.finalize().into()))
    }

    /// `HashSinglePart`. Without part hashes a part of a multi-part file
    /// cannot be checked: it passes, and a peer is asked for them.
    ///
    /// One difference: aMule compares the only part of a one-part file with
    /// the file hash even when part hashes exist, which fails for a file of
    /// exactly [`PARTSIZE`] bytes (two part hashes, the second empty). Here
    /// a known part hash always wins.
    fn verify_part(&mut self, part: u16) -> io::Result<bool> {
        let (start, end) = self.gaps.part_range(part);
        let len = end - start + 1;
        let expected = match self.info.part_hashes.get(usize::from(part)) {
            Some(&h) => h,
            None if self.gaps.part_count() == 1 => self.hash(),
            None => {
                if !self.hash_set_needed {
                    self.hash_set_needed = true;
                }
                self.events.push(FileEvent::HashSetNeeded);
                return Ok(true);
            }
        };
        // Drift defence: a part the met calls complete but the .part does
        // not hold (a lost write, a truncated file) is fetched again.
        if self.handle()?.metadata()?.len() < end + 1 {
            self.gaps.add(start, end);
            self.dirty = true;
            return Ok(false);
        }
        Ok(self.hash_range(start, len)? == expected)
    }

    /// `OnAsyncHashComplete`, without AICH recovery and ICH.
    fn on_part_hashed(&mut self, part: u16, ok: bool) {
        if !self.gaps.is_part_complete(part) {
            return;
        }
        if !ok {
            let (s, e) = self.gaps.part_range(part);
            self.gaps.add_part(part);
            if !self.info.corrupted_parts.contains(&part) {
                self.info.corrupted_parts.push(part);
            }
            self.lost_to_corruption += e - s + 1;
            self.dirty = true;
            self.events.push(FileEvent::PartCorrupt(part));
            self.want_aich_recovery(part);
            return;
        }
        if let Some(i) = self.info.corrupted_parts.iter().position(|&p| p == part) {
            self.info.corrupted_parts.remove(i);
            self.dirty = true;
        }
        if !self.hash_set_needed {
            if self.status == Status::Empty {
                self.status = Status::Ready;
                self.dirty = true;
            }
            self.events.push(FileEvent::PartVerified(part));
        }
    }

    fn hash_whole_file(&mut self) -> io::Result<FileHashes> {
        let size = self.size();
        let f = self.handle()?;
        f.seek(SeekFrom::Start(0))?;
        ed2k_hash::hash_reader(f.take(size))
    }

    /// `PartFileHashFinished`: compare a hash of the whole `.part` with
    /// what the file should be. Bad parts become gaps (and are listed as
    /// corrupt); good parts the met thought missing are filled.
    fn apply_rehash(&mut self, result: &FileHashes) -> Rehash {
        let size = self.size();
        let wanted = part_hash_count(size);
        let mut corrupt = Vec::new();
        if wanted == 0 {
            if self.gaps.is_range_complete(0, size - 1) && result.ed2k != self.hash() {
                self.gaps.add(0, size - 1);
                corrupt.push(0);
            }
        } else if self.info.part_hashes.len() != wanted {
            if self.gaps.is_range_complete(0, size - 1) {
                // The file hash binds the data: adopt the part hashes.
                if result.ed2k == self.hash() && result.part_hashes.len() == wanted {
                    self.info.part_hashes = result.part_hashes.clone();
                    self.hash_set_needed = false;
                    self.dirty = true;
                } else {
                    self.hash_set_needed = true;
                    self.awaiting_hash_set = true;
                    self.events.push(FileEvent::HashSetNeeded);
                    return Rehash::AwaitingHashSet;
                }
            }
        } else {
            for i in 0..wanted {
                let part = i as u16;
                let good = result.part_hashes.get(i) == Some(&self.info.part_hashes[i]);
                if !good {
                    if self.gaps.is_part_complete(part) && part < self.gaps.part_count() {
                        self.gaps.add_part(part);
                        if !self.info.corrupted_parts.contains(&part) {
                            self.info.corrupted_parts.push(part);
                        }
                        corrupt.push(part);
                    }
                } else if !self.gaps.is_part_complete(part) {
                    let (s, e) = self.gaps.part_range(part);
                    self.gaps.fill_part(part);
                    self.requested.retain(|&(rs, re)| !(rs >= s && re <= e));
                }
            }
        }
        if corrupt.is_empty() {
            Rehash::Ok
        } else {
            self.dirty = true;
            for &p in &corrupt {
                let (s, e) = self.gaps.part_range(p);
                self.lost_to_corruption += e - s + 1;
                self.events.push(FileEvent::PartCorrupt(p));
                self.want_aich_recovery(p);
            }
            Rehash::Corrupt(corrupt)
        }
    }

    // ---- saving ----

    /// `SavePartFile`: write the met now, buffered data first.
    pub fn save(&mut self) -> io::Result<()> {
        self.write_buffers()?;
        self.save_met()
    }

    fn save_met(&mut self) -> io::Result<()> {
        let mtime = mtime(&self.handle()?.metadata()?);
        self.info.date = mtime;
        let mut info = self.info.clone();
        info.gaps = self.gaps.iter().collect();
        let content = info.to_met().write();

        // WritePartMet: a stale .tmp may be a link to the live met; unlink it.
        let tmp = with_ext(&self.met_path, ".tmp");
        if tmp.exists() {
            fs::remove_file(&tmp)?;
        }
        fs::write(&tmp, &content)?;
        if fs::metadata(&tmp)?.len() != content.len() as u64 {
            let _ = fs::remove_file(&tmp);
            return Err(io::Error::other("incomplete part.met.tmp file"));
        }
        // InstallPartMet: back up the live met through a staged copy, so the
        // old backup is replaced whole and the met never goes missing.
        if self.met_path.exists() {
            let staged = with_ext(&self.met_path, ".bak.tmp");
            if staged.exists() {
                fs::remove_file(&staged)?;
            }
            fs::copy(&self.met_path, &staged)?;
            fs::rename(&staged, with_ext(&self.met_path, ".bak"))?;
        }
        fs::rename(&tmp, &self.met_path)?;
        self.dirty = false;
        Ok(())
    }

    // ---- completion ----

    /// `CompleteFile`: hash the whole file again (`CHashingTask`) and, if
    /// it checks out, move it to `incoming` under its name
    /// (`CCompletionTask`) and remove the met and its side files.
    ///
    /// Fails if bytes are still missing.
    pub fn complete(&mut self, incoming: &Path) -> io::Result<Completion> {
        self.flush()?;
        if !self.gaps.is_complete() {
            return Err(io::Error::other("the download is not complete"));
        }
        let result = match self.hash_whole_file() {
            Ok(r) => r,
            Err(e) => {
                self.fail(&e);
                return Err(e);
            }
        };
        match self.apply_rehash(&result) {
            Rehash::Ok => {}
            Rehash::AwaitingHashSet => {
                self.status = Status::Empty;
                self.save()?;
                return Ok(Completion::AwaitingHashSet);
            }
            Rehash::Corrupt(parts) => {
                self.status = Status::Ready;
                self.save()?;
                return Ok(Completion::Corrupt(parts));
            }
        }
        // The file's own AICH root, now that it is known.
        if let Some(root) = result.aich_root {
            self.aich_root = Some(root);
            self.aich_status = AichStatus::Verified;
            self.info.aich_hash = Some(root.to_string());
        }
        if self.dirty {
            self.save()?;
        }

        // Windows cannot move an open file.
        drop(self.file.take());
        let target = completed_path(incoming, &self.info.name);
        let moved = fs::rename(&self.part_path, &target).or_else(|_| {
            fs::copy(&self.part_path, &target)?;
            let _ = fs::remove_file(&self.part_path);
            Ok(())
        });
        if let Err(e) = moved {
            self.info.paused = true;
            self.fail(&e);
            self.file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.part_path)
                .ok();
            return Err(e);
        }
        for ext in MET_SIDE_FILES {
            let p = with_ext(&self.met_path, ext);
            if p.exists() {
                let _ = fs::remove_file(p);
            }
        }
        self.status = Status::Complete;
        self.requested.clear();
        Ok(Completion::Done(target))
    }

    /// Cancel the download: remove the `.part`, the met and its side files.
    pub fn delete(mut self) -> io::Result<()> {
        drop(self.file.take());
        if self.part_path.exists() {
            fs::remove_file(&self.part_path)?;
        }
        for ext in MET_SIDE_FILES {
            let p = with_ext(&self.met_path, ext);
            if p.exists() {
                fs::remove_file(p)?;
            }
        }
        Ok(())
    }
}

enum Rehash {
    Ok,
    Corrupt(Vec<u16>),
    AwaitingHashSet,
}

/// A part file as one download session sees it: the file, and which part
/// the session's source is being asked for (`m_lastPartAsked`).
pub struct SourceView<'a> {
    pub file: &'a mut PartFile,
    pub last_part: &'a mut Option<u16>,
    /// Ask this source for other sources with the file request.
    pub wants_sources: bool,
}

impl ed2k_peer::download::PartFile for SourceView<'_> {
    fn hash(&self) -> Md4Hash {
        self.file.hash()
    }

    fn size(&self) -> u64 {
        self.file.size()
    }

    fn has_part(&self, i: u64) -> bool {
        u16::try_from(i).is_ok_and(|p| self.file.gaps.is_part_complete(p))
    }

    fn hash_set_needed(&self) -> bool {
        self.file.hash_set_needed
    }

    fn status(&self) -> PartStatus {
        self.file.part_status()
    }

    fn complete_sources(&self) -> u16 {
        self.file.complete_sources
    }

    fn is_stopped(&self) -> bool {
        self.file.is_stopped()
    }

    fn set_hash_set(&mut self, parts: Vec<Md4Hash>) -> bool {
        self.file.set_hash_set(parts)
    }

    fn reserve_blocks(&mut self, peer: &PartStatus, max: usize) -> Vec<Range<u64>> {
        self.file.reserve_blocks(self.last_part, peer, max)
    }

    fn release_block(&mut self, block: Range<u64>) {
        self.file.release_block(block)
    }

    fn write(&mut self, start: u64, data: &[u8]) {
        // A disk error puts the file in Status::Error, with an event.
        let _ = self.file.write(start, data);
    }

    fn wants_sources(&self) -> bool {
        self.wants_sources
    }
}
