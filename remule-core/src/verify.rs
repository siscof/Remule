// SPDX-License-Identifier: GPL-2.0-or-later
//! "Verify Local Data": a shared file read back and checked against the
//! hashes it was shared under (`CVerifyLocalDataTask`, ThreadTasks.cpp;
//! `CVerifyLocalDataResult`, VerifyLocalDataResult.h).
//!
//! Each part's MD4 is compared with the stored part hash (a file of one
//! part with the file hash), and, when the file's AICH hash set is known,
//! each block's AICH hash with the stored one. A file whose size on disk is
//! not the one it was hashed at fails as a whole. The outcome is reported as
//! aMule logs it and recorded as `known.met` keeps it
//! (`FT_VERIFY_DATE`, `FT_VERIFY_CORRUPTMD4`, `FT_VERIFY_CORRUPTAICH`).

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use ed2k_hash::BLOCKS_PER_PART;
use ed2k_types::ed2k::PARTSIZE;
use ed2k_types::{AichHash, Md4Hash};

/// `MAX_FILE_SIZE`: the largest file eD2k can name (256 GiB).
const MAX_FILE_SIZE: u64 = 0x40_0000_0000;

/// What a check is made against: a shared file as it was hashed.
#[derive(Clone, Debug)]
pub struct VerifyTarget {
    pub path: PathBuf,
    pub size: u64,
    pub file_hash: Md4Hash,
    /// As `known.met` stores them: none for a file of one part.
    pub part_hashes: Vec<Md4Hash>,
    /// The AICH block hashes from `known2_64.met`, when the file's hash
    /// set is there and complete.
    pub aich_blocks: Option<Vec<AichHash>>,
}

/// How a check ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The file could not be opened or read.
    NotRead {
        error: String,
    },
    /// Its size on disk is not the one it was hashed at: every part is
    /// corrupt.
    SizeChanged {
        on_disk: u64,
        expected: u64,
    },
    TooLarge,
    Empty,
    /// A file of several parts without a hash for each.
    MissingHashes,
    /// Read to the end: the corrupt parts, and per part the corrupt AICH
    /// blocks. `aich` tells whether the AICH hashes were checked.
    Checked {
        aich: bool,
        md4: Vec<u16>,
        aich_blocks: Vec<(u16, Vec<u8>)>,
    },
}

/// `(size + PARTSIZE - 1) / PARTSIZE`: the data parts, without the empty
/// extra one.
fn part_count(size: u64) -> u64 {
    size.div_ceil(PARTSIZE)
}

/// `CVerifyLocalDataTask::Entry`, blocking.
pub fn verify(t: &VerifyTarget) -> VerifyOutcome {
    let not_read = |e: io::Error| VerifyOutcome::NotRead {
        error: e.to_string(),
    };
    let file = match fs::File::open(&t.path) {
        Ok(f) => f,
        Err(e) => return not_read(e),
    };
    let on_disk = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => return not_read(e),
    };
    if on_disk != t.size {
        return VerifyOutcome::SizeChanged {
            on_disk,
            expected: t.size,
        };
    } else if on_disk > MAX_FILE_SIZE {
        return VerifyOutcome::TooLarge;
    } else if on_disk == 0 {
        return VerifyOutcome::Empty;
    }
    let parts = part_count(t.size);
    if t.size >= PARTSIZE && (t.part_hashes.len() as u64) < parts {
        return VerifyOutcome::MissingHashes;
    }
    let aich = t
        .aich_blocks
        .as_ref()
        .filter(|b| b.len() as u64 == ed2k_hash::aich_block_count(t.size));

    // One read through the file: the same hashes sharing made.
    let mut hasher = ed2k_hash::Hasher::new();
    let mut r = io::BufReader::with_capacity(1 << 20, file);
    let mut buf = vec![0u8; 1 << 20];
    let mut left = t.size;
    while left > 0 {
        let want = buf.len().min(left as usize);
        match r.read(&mut buf[..want]) {
            Ok(0) => {
                return VerifyOutcome::NotRead {
                    error: "the file ended early".into(),
                }
            }
            Ok(n) => {
                hasher.update(&buf[..n]);
                left -= n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return not_read(e),
        }
    }
    let now = hasher.finish();

    let mut md4 = Vec::new();
    let mut aich_blocks: Vec<(u16, Vec<u8>)> = Vec::new();
    for part in 0..parts {
        let stored = if t.part_hashes.is_empty() {
            Some(&t.file_hash)
        } else {
            t.part_hashes.get(part as usize)
        };
        let found = if t.part_hashes.is_empty() {
            Some(&now.ed2k)
        } else {
            now.part_hashes.get(part as usize)
        };
        if stored != found {
            md4.push(part as u16);
        }
        if let Some(stored) = aich {
            let first = part * BLOCKS_PER_PART;
            let last = (first + BLOCKS_PER_PART).min(stored.len() as u64);
            let bad: Vec<u8> = (first..last)
                .filter(|&i| now.aich_blocks.get(i as usize) != stored.get(i as usize))
                .map(|i| (i - first) as u8)
                .collect();
            if !bad.is_empty() {
                aich_blocks.push((part as u16, bad));
            }
        }
        if t.part_hashes.is_empty() {
            break;
        }
    }
    VerifyOutcome::Checked {
        aich: aich.is_some(),
        md4,
        aich_blocks,
    }
}

/// `FT_VERIFY_CORRUPTMD4`: `p,p,p`.
pub fn encode_md4(parts: &[u16]) -> String {
    parts
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// `FT_VERIFY_CORRUPTAICH`: `p:b.b;p:b`.
pub fn encode_aich(parts: &[(u16, Vec<u8>)]) -> String {
    parts
        .iter()
        .map(|(p, blocks)| {
            let b: Vec<String> = blocks.iter().map(u8::to_string).collect();
            format!("{p}:{}", b.join("."))
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// `FormatCorruptedAICH`, the log's notation: `p: (b,b), p: (b)`.
pub fn format_aich(parts: &[(u16, Vec<u8>)]) -> String {
    parts
        .iter()
        .map(|(p, blocks)| {
            let b: Vec<String> = blocks.iter().map(u8::to_string).collect();
            format!("{p}: ({})", b.join(","))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl VerifyOutcome {
    /// The log line aMule writes for it, and whether it is one it shows as
    /// critical (`AddLogLineC`).
    pub fn report(&self, path: &Path) -> (bool, String) {
        let path = path.display();
        match self {
            VerifyOutcome::NotRead { .. } => (
                true,
                format!("Verify Local Data: could not read {path}, so it was not checked."),
            ),
            VerifyOutcome::SizeChanged { on_disk, expected } => (
                true,
                format!(
                    "Verify Local Data: ERRORS FOUND! {path} Size on disk: {on_disk} bytes, \
                     expected: {expected} bytes."
                ),
            ),
            VerifyOutcome::TooLarge => (
                true,
                format!(
                    "Verify Local Data: {path} is larger than aMule supports, so it was not \
                     checked."
                ),
            ),
            VerifyOutcome::Empty => (
                false,
                format!("Verify Local Data: {path} is empty, so there is nothing to check."),
            ),
            VerifyOutcome::MissingHashes => (
                false,
                format!("Verify Local Data: missing MD4 hashes for {path}, so it was not checked."),
            ),
            VerifyOutcome::Checked {
                aich,
                md4,
                aich_blocks,
            } => {
                let scope = if *aich { "MD4 & AICH" } else { "MD4" };
                if md4.is_empty() && aich_blocks.is_empty() {
                    (
                        false,
                        format!("Verify Local Data ({scope}): Result OK for {path}"),
                    )
                } else {
                    (
                        true,
                        format!(
                            "Verify Local Data ({scope}): ERRORS FOUND! {path} Failed blocks: \
                             MD4: {}. {}{}",
                            encode_md4(md4),
                            if *aich { "AICH: " } else { "" },
                            if *aich {
                                format_aich(aich_blocks)
                            } else {
                                String::new()
                            }
                        ),
                    )
                }
            }
        }
    }

    /// What `known.met` records of it (`PublishResult`): the corrupt parts
    /// and AICH blocks, encoded. `None` for a check that did not finish.
    pub fn record(&self) -> Option<(String, String)> {
        match self {
            VerifyOutcome::SizeChanged { expected, .. } => {
                let all: Vec<u16> = (0..part_count(*expected)).map(|p| p as u16).collect();
                Some((encode_md4(&all), String::new()))
            }
            VerifyOutcome::Checked {
                md4, aich_blocks, ..
            } => Some((encode_md4(md4), encode_aich(aich_blocks))),
            _ => None,
        }
    }
}
