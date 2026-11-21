// SPDX-License-Identifier: GPL-2.0-or-later
//! The shared files and what is known about them (`CSharedFileList`,
//! `CKnownFileList`; SharedFileList.cpp, KnownFileList.cpp).
//!
//! `known.met` remembers every file ever hashed, under its name, size and
//! modification time; `known2_64.met` keeps their AICH hash sets. A scan of
//! the shared directories matches each file against `known.met` (name, size
//! and time must all agree) and lists the ones to hash; once hashed, a file
//! is recorded in both and shared. Both files are written as aMule writes
//! them, so remule and aMule can use the same config directory in turn.
//!
//! As in aMule: directories are not walked recursively (each shared
//! directory is listed), empty files are not shared, the temp, config and
//! home directories are never shared, and when the same content is found
//! twice the first path wins. Hashing is left to the caller
//! ([`SharedFiles::hash`] is blocking), so it can run off the main task.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use ed2k_formats::known2_met::{AichHashSet, Known2Met};
use ed2k_formats::known_met::{priority, KnownFile, KnownMet, VERSION};
use ed2k_hash::FileHashes;
use ed2k_types::Md4Hash;

/// `known.met`
pub const KNOWN_MET: &str = "known.met";
/// `known2_64.met`
pub const KNOWN2_MET: &str = "known2_64.met";

/// A file's modification time as aMule stores it: seconds, 32 bits.
pub fn mtime(meta: &fs::Metadata) -> u32 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as u32)
}

/// What to share.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// The shared directories, the incoming directory among them.
    pub dirs: Vec<PathBuf>,
    /// Never shared, whatever `dirs` says (`IsReservedDir`): the temp
    /// directory, the config directory, the home directory.
    pub reserved: Vec<PathBuf>,
    /// Share files whose names start with a dot (`ShareHiddenFiles`).
    pub hidden: bool,
}

/// What a scan found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanResult {
    /// Files known from `known.met`, now shared.
    pub known: usize,
    /// Files to hash, then give to [`SharedFiles::add_hashed`].
    pub to_hash: Vec<PathBuf>,
    /// Directories left out, and why.
    pub skipped: Vec<(PathBuf, String)>,
}

/// The shared files.
#[derive(Debug)]
pub struct SharedFiles {
    dir: PathBuf,
    /// Every known file, in `known.met` order.
    records: Vec<KnownFile>,
    /// The record that answers for each hash: the last one, as aMule's map
    /// keeps the last record loaded.
    by_hash: HashMap<Md4Hash, usize>,
    known2: Known2Met,
    /// Shared files: where each is.
    shared: HashMap<Md4Hash, PathBuf>,
    dirty: bool,
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Why a rename was refused.
#[derive(Debug)]
pub enum RenameError {
    /// The new name has a folder in it, or is none (`IsBareFileName`).
    NotBare,
    NotShared,
    Io(io::Error),
}

/// `CPath::IsBareFileName`: one path component, not `.` or `..`.
pub fn is_bare_file_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

/// Write `data` to `path` through a temporary file (`CFile::write_safe`).
fn write_safe(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)
}

impl SharedFiles {
    /// Load `known.met` and `known2_64.met` from the config directory
    /// `dir`. Missing files are empty; from a damaged file, what could be
    /// read is kept, as aMule does.
    pub fn load(dir: &Path) -> io::Result<SharedFiles> {
        let mut s = SharedFiles {
            dir: dir.to_owned(),
            records: Vec::new(),
            by_hash: HashMap::new(),
            known2: Known2Met::default(),
            shared: HashMap::new(),
            dirty: false,
        };
        match fs::read(dir.join(KNOWN_MET)) {
            Ok(b) => {
                let records = match KnownMet::read(&b) {
                    Ok(m) => m.records,
                    Err(e) => {
                        s.dirty = true;
                        e.salvaged
                    }
                };
                for rec in records {
                    if let Ok(f) = KnownFile::from_record(&rec) {
                        s.push(f);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        match fs::read(dir.join(KNOWN2_MET)) {
            Ok(b) => {
                s.known2 = match Known2Met::read(&b) {
                    Ok(k) => k,
                    Err(e) => Known2Met { sets: e.salvaged },
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(s)
    }

    fn push(&mut self, f: KnownFile) {
        self.by_hash.insert(f.hash, self.records.len());
        self.records.push(f);
    }

    /// How many files `known.met` holds.
    pub fn known_count(&self) -> usize {
        self.records.len()
    }

    /// `FindKnownFile`: the record for a file of this name, time and size.
    pub fn find_known(&self, name: &str, date: u32, size: u64) -> Option<&KnownFile> {
        self.records
            .iter()
            .rev()
            .find(|f| f.date == date && f.size == size && f.name == name)
    }

    /// `FindSharedFiles` / `AddFilesFromDirectory`: list the shared
    /// directories again. Files known from `known.met` are shared at once;
    /// the rest are returned to hash.
    pub fn scan(&mut self, opts: &ScanOptions, now: u32) -> ScanResult {
        self.shared.clear();
        let mut result = ScanResult::default();
        let mut dirs = opts.dirs.clone();
        dirs.sort();
        dirs.dedup();
        for dir in dirs {
            if opts.reserved.iter().any(|r| same_dir(r, &dir)) {
                result.skipped.push((dir, "reserved directory".into()));
                continue;
            }
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    result.skipped.push((dir, e.to_string()));
                    continue;
                }
            };
            let mut paths: Vec<PathBuf> =
                entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            paths.sort();
            for path in paths {
                let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned)
                else {
                    continue;
                };
                if !opts.hidden && name.starts_with('.') {
                    continue;
                }
                // Follows links, as a stat does; a broken link fails here.
                let Ok(meta) = fs::metadata(&path) else {
                    continue;
                };
                if !meta.is_file() || meta.len() == 0 {
                    continue;
                }
                let date = mtime(&meta);
                match self.find_known(&name, date, meta.len()).map(|f| f.hash) {
                    Some(hash) => {
                        if let Some(i) = self.by_hash.get(&hash).copied() {
                            self.records[i].last_seen = now;
                        }
                        // The first copy found stays.
                        self.shared.entry(hash).or_insert(path);
                        result.known += 1;
                    }
                    None => result.to_hash.push(path),
                }
            }
        }
        self.dirty |= result.known > 0;
        result
    }

    /// Hash a file (`CHashingTask`). Blocking.
    pub fn hash(path: &Path) -> io::Result<FileHashes> {
        let f = fs::File::open(path)?;
        ed2k_hash::hash_reader(io::BufReader::with_capacity(1 << 20, f))
    }

    /// A file was hashed (`SafeAddKFile` after `CHashingTask`): record it
    /// in `known.met` and `known2_64.met`, and share it. `date` is its
    /// modification time when hashing started. A file known under another
    /// name or time takes over the record, keeping its statistics.
    pub fn add_hashed(&mut self, path: &Path, hashes: &FileHashes, date: u32, now: u32) -> Md4Hash {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let aich = hashes.aich_root.map(|r| r.to_string());
        match self.by_hash.get(&hashes.ed2k).copied() {
            Some(i) => {
                let f = &mut self.records[i];
                f.name = name;
                f.date = date;
                f.size = hashes.size;
                f.part_hashes = hashes.part_hashes.clone();
                f.last_seen = now;
                if aich.is_some() {
                    f.aich_hash = aich;
                }
            }
            None => self.push(KnownFile {
                date,
                hash: hashes.ed2k,
                part_hashes: hashes.part_hashes.clone(),
                name,
                size: hashes.size,
                up_priority: priority::NORMAL,
                auto_priority: true,
                aich_hash: aich,
                last_seen: now,
                shared_since: now,
                ..Default::default()
            }),
        }
        if let Some(root) = hashes.aich_root {
            self.known2.append(AichHashSet {
                root,
                block_hashes: hashes.aich_blocks.clone(),
            });
        }
        self.shared
            .entry(hashes.ed2k)
            .or_insert_with(|| path.to_owned());
        self.dirty = true;
        hashes.ed2k
    }

    /// Stop sharing a file (it was deleted or its directory unshared). It
    /// stays in `known.met`.
    pub fn unshare(&mut self, hash: &Md4Hash) -> bool {
        self.shared.remove(hash).is_some()
    }

    /// `CSharedFileList::RenameFile` for a complete file: renamed on disk
    /// in its own folder, then in `known.met`. `new_name` must be a plain
    /// file name, and nothing may be there under it already.
    pub fn rename(&mut self, hash: &Md4Hash, new_name: &str) -> Result<PathBuf, RenameError> {
        if !is_bare_file_name(new_name) {
            return Err(RenameError::NotBare);
        }
        let old = self.shared.get(hash).ok_or(RenameError::NotShared)?.clone();
        let new = old.with_file_name(new_name);
        if new == old {
            return Ok(new);
        }
        if fs::symlink_metadata(&new).is_ok() {
            return Err(RenameError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a file of that name is already there",
            )));
        }
        fs::rename(&old, &new).map_err(RenameError::Io)?;
        if let Some(f) = self.get_mut(hash) {
            f.name = new_name.to_owned();
        }
        self.shared.insert(*hash, new.clone());
        Ok(new)
    }

    /// A shared file: what is known about it and where it is.
    pub fn get(&self, hash: &Md4Hash) -> Option<(&KnownFile, &Path)> {
        let path = self.shared.get(hash)?;
        let i = *self.by_hash.get(hash)?;
        Some((&self.records[i], path))
    }

    pub fn get_mut(&mut self, hash: &Md4Hash) -> Option<&mut KnownFile> {
        if !self.shared.contains_key(hash) {
            return None;
        }
        let i = *self.by_hash.get(hash)?;
        self.dirty = true;
        Some(&mut self.records[i])
    }

    /// The shared files, by name.
    pub fn files(&self) -> Vec<(&KnownFile, &Path)> {
        let mut v: Vec<_> = self.shared.keys().filter_map(|h| self.get(h)).collect();
        v.sort_by(|a, b| a.0.name.cmp(&b.0.name).then(a.1.cmp(b.1)));
        v
    }

    pub fn shared_count(&self) -> usize {
        self.shared.len()
    }

    /// The AICH hash set of a shared file, from `known2_64.met`.
    pub fn aich_set(&self, hash: &Md4Hash) -> Option<&AichHashSet> {
        let (f, _) = self.get(hash)?;
        let root = f.aich_hash.as_deref()?.parse().ok()?;
        self.known2.find(&root).filter(|s| s.fits_size(f.size))
    }

    /// What "Verify Local Data" checks a shared file against: where it is
    /// and the hashes it was shared under.
    pub fn verify_target(&self, hash: &Md4Hash) -> Option<crate::verify::VerifyTarget> {
        let (f, path) = self.get(hash)?;
        Some(crate::verify::VerifyTarget {
            path: path.to_owned(),
            size: f.size,
            file_hash: f.hash,
            part_hashes: f.part_hashes.clone(),
            aich_blocks: self.aich_set(hash).map(|s| s.block_hashes.clone()),
        })
    }

    /// Record a finished check (`CVerifyLocalDataEvent`): only on the file
    /// it was made on, still shared from `path` at `size`. False when it
    /// is no longer that file.
    pub fn record_verify(
        &mut self,
        hash: &Md4Hash,
        path: &Path,
        size: u64,
        date: u32,
        (md4, aich): (String, String),
    ) -> bool {
        match self.get(hash) {
            Some((f, p)) if p == path && f.size == size => {}
            _ => return false,
        }
        let Some(f) = self.get_mut(hash) else {
            return false;
        };
        f.verify_date = date;
        f.verify_corrupt_md4 = md4;
        f.verify_corrupt_aich = aich;
        true
    }

    /// Whether `known.met` needs writing.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// `CKnownFileList::Save` and the AICH hash sets: write both files,
    /// each through a temporary file.
    pub fn save(&mut self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut met = KnownMet {
            version: VERSION,
            records: self.records.iter().map(KnownFile::to_record).collect(),
            skipped: Vec::new(),
        };
        met.version = met.canonical_version();
        write_safe(&self.dir.join(KNOWN_MET), &met.write())?;
        write_safe(&self.dir.join(KNOWN2_MET), &self.known2.write())?;
        self.dirty = false;
        Ok(())
    }
}

impl SharedFiles {
    /// What the upload session needs to know about a shared file.
    pub fn shared_info(&self, hash: &Md4Hash) -> Option<ed2k_peer::upload::SharedInfo> {
        let (f, _) = self.get(hash)?;
        Some(ed2k_peer::upload::SharedInfo {
            hash: f.hash,
            name: f.name.clone(),
            size: f.size,
            part_hashes: f.part_hashes.clone(),
            parts: ed2k_peer::PartStatus::Complete,
            aich_root: f.aich_hash.as_deref().and_then(|s| s.parse().ok()),
        })
    }

    /// Read `range` of a shared file, for an upload (`CUploadDiskIOThread`).
    /// Blocking.
    pub fn read_block(&self, hash: &Md4Hash, range: std::ops::Range<u64>) -> io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let Some((f, path)) = self.get(hash) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "not shared"));
        };
        if range.start > range.end || range.end > f.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outside the file",
            ));
        }
        let mut file = fs::File::open(path)?;
        file.seek(SeekFrom::Start(range.start))?;
        let mut buf = vec![0u8; (range.end - range.start) as usize];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl ed2k_peer::upload::Shares for SharedFiles {
    fn shared(&self, hash: &Md4Hash) -> Option<ed2k_peer::upload::SharedInfo> {
        self.shared_info(hash)
    }
}
