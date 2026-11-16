// SPDX-License-Identifier: GPL-2.0-or-later
//! What to publish, and when: shared files offered to the eD2k server
//! (`CSharedFileList::SendListToServer`) and published on Kad, under the
//! keywords of their names and with ourselves as a source
//! (`CSharedFileList::Publish`, `CPublishKeywordList`).
//!
//! The publisher only decides; the application sends: the files to offer
//! go into [`ed2k_server::packets::offer_files`], the Kad publishes into
//! [`ed2k_kad::Kad::store_keyword`] and [`ed2k_kad::Kad::store_source`].

use std::collections::{BTreeMap, HashSet};

use ed2k_kad::node::{keyword_publish_tags, source_publish_tags};
use ed2k_kad::search::keyword_target;
use ed2k_server::packets::{offer_limit, OfferedFile};
use ed2k_server::search::kad_words;
use ed2k_types::ed2k::server_tcp::flags;
use ed2k_types::tags::FileType;
use ed2k_types::{Md4Hash, UInt128};

use ed2k_codec::Tag;
use ed2k_formats::known_met::priority;

use crate::shared::SharedFiles;

/// `KADEMLIAPUBLISHTIME`: seconds between two keyword (or two source)
/// publishes started.
pub const PUBLISH_INTERVAL: u64 = 2;
/// `KADEMLIAREPUBLISHTIMEK`: a keyword is published again after 24 hours.
pub const KEYWORD_REPUBLISH: u64 = 24 * 3600;
/// `KADEMLIAREPUBLISHTIMES`: a source after 5 hours.
pub const SOURCE_REPUBLISH: u64 = 5 * 3600;
/// `KADEMLIATOTALSTOREKEY`, `KADEMLIATOTALSTORESRC`: publishes running at once.
pub const MAX_KEYWORD_STORES: usize = 2;
pub const MAX_SOURCE_STORES: usize = 3;
/// Files per keyword publish (the rest rotate in next time).
pub const FILES_PER_KEYWORD: usize = 150;

/// `GuessAndRemoveExt`: the name without what looks like its extension, so
/// that "avi" is not published as a keyword.
fn strip_extension(name: &str) -> &str {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return name;
    };
    if ext == "gz" || ext == "bz2" {
        return match stem.rsplit_once('.') {
            Some((s, "tar")) => s,
            _ => stem,
        };
    }
    if ext.len() == 3 || matches!(ext, "7z" | "rm" | "jpeg" | "mpeg") {
        stem
    } else {
        name
    }
}

/// The Kad keywords of a file name (`CKnownFile::SetFileName`): its words
/// of three bytes or more, lower-cased, once each, the extension left out.
pub fn file_keywords(name: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for w in kad_words(strip_extension(name)) {
        // GetWords without duplicates keeps the last place of each word.
        words.retain(|x| x != &w);
        words.push(w);
    }
    words
}

/// A Kad publish to start.
#[derive(Debug, Clone, PartialEq)]
pub enum KadPublish {
    /// Publish these files under the keyword `word`.
    Keyword {
        word: String,
        target: UInt128,
        files: Vec<(UInt128, Vec<Tag>)>,
    },
    /// Publish ourselves as a source of the file.
    Source {
        hash: Md4Hash,
        size: u64,
        tags: Vec<Tag>,
    },
}

#[derive(Debug, Clone)]
struct Keyword {
    files: Vec<Md4Hash>,
    next_publish: u64,
}

/// What has been published, and what is next.
#[derive(Debug, Default)]
pub struct Publisher {
    /// Offered to the server on this connection (`GetPublishedED2K`).
    offered: HashSet<Md4Hash>,
    /// The keywords of the shared files.
    keywords: BTreeMap<String, Keyword>,
    keyword_cursor: Option<String>,
    next_keyword_time: u64,
    source_cursor: Option<Md4Hash>,
    next_source_time: u64,
}

/// `GetRealPrio`: upload priorities in their real order, lowest first.
fn real_priority(p: u32) -> u8 {
    match p {
        priority::VERY_LOW => 0,
        priority::LOW => 1,
        priority::NORMAL => 2,
        priority::HIGH => 3,
        priority::VERY_HIGH => 4,
        _ => 2,
    }
}

impl Publisher {
    pub fn new() -> Self {
        Publisher::default()
    }

    /// A new server connection: everything is offered again.
    pub fn server_connected(&mut self) {
        self.offered.clear();
    }

    /// `SendListToServer`: the files not yet offered on this connection,
    /// as many as the server takes in one packet (`soft` and `hard`, its
    /// file limits, 0 when not known); files over 4 GB only to a server
    /// that supports them. Ordered by upload priority as aMule's sort
    /// leaves them (lowest first). They count as offered from here on.
    pub fn server_offer(
        &mut self,
        shared: &SharedFiles,
        tcp_flags: u32,
        soft: u32,
        hard: u32,
    ) -> Vec<OfferedFile> {
        let large_ok = tcp_flags & flags::LARGEFILES != 0;
        let mut candidates: Vec<_> = shared
            .files()
            .into_iter()
            .map(|(f, _)| f)
            .filter(|f| !self.offered.contains(&f.hash))
            .filter(|f| large_ok || f.size <= u64::from(u32::MAX))
            .collect();
        candidates.sort_by_key(|f| {
            real_priority(if f.auto_priority {
                priority::HIGH
            } else {
                f.up_priority
            })
        });
        let limit = offer_limit(soft, hard) as usize;
        candidates
            .into_iter()
            .take(limit)
            .map(|f| {
                self.offered.insert(f.hash);
                OfferedFile {
                    hash: f.hash,
                    name: f.name.clone(),
                    size: f.size,
                    complete: true,
                    file_type: FileType::of_name(&f.name),
                }
            })
            .collect()
    }

    /// Rebuild the keyword list from the shared files (`AddKeywords`,
    /// `PurgeUnreferencedKeywords`); when a keyword was published stays.
    pub fn update_keywords(&mut self, shared: &SharedFiles) {
        let mut fresh: BTreeMap<String, Keyword> = BTreeMap::new();
        for (f, _) in shared.files() {
            for w in file_keywords(&f.name) {
                fresh
                    .entry(w)
                    .or_insert_with(|| Keyword {
                        files: Vec::new(),
                        next_publish: 0,
                    })
                    .files
                    .push(f.hash);
            }
        }
        for (w, k) in fresh.iter_mut() {
            if let Some(old) = self.keywords.get(w) {
                k.next_publish = old.next_publish;
            }
        }
        self.keywords = fresh;
    }

    pub fn keyword_count(&self) -> usize {
        self.keywords.len()
    }

    /// The next keyword after the cursor, round the list.
    fn next_keyword(&mut self) -> Option<String> {
        let next = match &self.keyword_cursor {
            Some(c) => self
                .keywords
                .range::<String, _>((
                    std::ops::Bound::Excluded(c.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .or_else(|| self.keywords.iter().next()),
            None => self.keywords.iter().next(),
        }
        .map(|(w, _)| w.clone());
        self.keyword_cursor = next.clone();
        next
    }

    /// `CSharedFileList::Publish`: the Kad publishes to start now.
    /// `running` are the keyword and source publishes still going
    /// (`Kad::store_counts`); `reachable` says whether others can connect
    /// to us on `tcp_port` (a firewalled client needs a buddy, not ported,
    /// and publishes nothing). Keyword and source publishes each start at
    /// most every two seconds, one keyword in turn every 24 hours, one file
    /// as a source in turn every 5 hours (kept in `known.met`).
    pub fn kad_publish(
        &mut self,
        shared: &mut SharedFiles,
        running: (usize, usize),
        reachable: bool,
        tcp_port: u16,
        crypt_options: u8,
        now: u64,
    ) -> Vec<KadPublish> {
        let mut out = Vec::new();
        if !reachable || shared.shared_count() == 0 {
            return out;
        }
        if running.0 < MAX_KEYWORD_STORES && now >= self.next_keyword_time {
            self.next_keyword_time = now + PUBLISH_INTERVAL;
            if let Some(word) = self.next_keyword() {
                let k = self.keywords.get_mut(&word).unwrap();
                if now >= k.next_publish {
                    // Rotate, so the next publish starts after these.
                    let n = k.files.len().min(FILES_PER_KEYWORD);
                    let files: Vec<Md4Hash> = k.files.iter().take(n).copied().collect();
                    let len = k.files.len().max(1);
                    k.files.rotate_left(n % len);
                    k.next_publish = now + KEYWORD_REPUBLISH;
                    let files: Vec<(UInt128, Vec<Tag>)> = files
                        .iter()
                        .filter_map(|h| shared.get(h))
                        .map(|(f, _)| {
                            (
                                UInt128::from_be_bytes(f.hash.0),
                                keyword_publish_tags(&f.name, f.size, 1),
                            )
                        })
                        .collect();
                    if !files.is_empty() {
                        out.push(KadPublish::Keyword {
                            target: keyword_target(&word),
                            word,
                            files,
                        });
                    }
                }
            }
        }
        if running.1 < MAX_SOURCE_STORES && now >= self.next_source_time {
            self.next_source_time = now + PUBLISH_INTERVAL;
            let hashes: Vec<Md4Hash> = shared.files().iter().map(|(f, _)| f.hash).collect();
            let start = self
                .source_cursor
                .and_then(|c| hashes.iter().position(|h| *h == c))
                .map_or(0, |i| i + 1);
            if let Some(&hash) = hashes.get(start % hashes.len().max(1)) {
                self.source_cursor = Some(hash);
                if let Some(f) = shared.get_mut(&hash) {
                    // `PublishSrc` / `CanPublishSource`.
                    if u64::from(f.kad_last_publish_src) <= now {
                        f.kad_last_publish_src = (now + SOURCE_REPUBLISH) as u32;
                        out.push(KadPublish::Source {
                            hash,
                            size: f.size,
                            tags: source_publish_tags(f.size, tcp_port, crypt_options),
                        });
                    }
                }
            }
        }
        out
    }
}
