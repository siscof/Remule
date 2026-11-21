// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared files over external connections: what `amulecmd`'s `show
//! shared` and `reload shared` use, and the shared-file tag downloads are
//! built on.
//!
//! * `EC_OP_GET_SHARED_FILES`: one `EC_TAG_KNOWNFILE` per shared file
//!   (`Get_EC_Response_GetSharedFiles`, `CEC_SharedFile_Tag`), or those
//!   asked for by ECID.
//! * `EC_OP_SHAREDFILES_RELOAD`: the shared folders listed again, new files
//!   hashed (`CSharedFileList::Reload`); answered at once, as aMule
//!   schedules it.
//! * `EC_OP_SHARED_SET_PRIO`: a file's upload priority, or automatic.
//! * `EC_OP_SHARED_FILE_SET_COMMENT`: the user's comment and rating of a
//!   file, kept in `amule.conf` as aMule keeps them.
//! * `EC_OP_RENAME_FILE`: a complete shared file renamed on disk, in its
//!   own folder.
//! * `EC_OP_VERIFY_LOCAL_DATA`: a shared file checked against its hashes
//!   (`CVerifyLocalDataTask`), answered at once; the outcome is logged.
//! * `EC_OP_GET_SHARED_DIRS`: the shared folders as configured
//!   (`Get_EC_Response_GetSharedDirs`).
//!
//! The list is read when asked for, from the client's [`SharedFiles`], not
//! kept in the per-second view: a library can hold tens of thousands of
//! files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ed2k_formats::amule_conf::ConfFile;
use ed2k_formats::known_met::{priority, KnownFile};
use ed2k_types::Md4Hash;
use remule_core::shared::{mtime, ScanOptions, SharedFiles};
use remule_ec::codes::*;
use remule_ec::{Packet, Tag};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::ec::Control;

/// `CECID`: one counter for every object EC names, whatever its kind, for
/// the life of the process. Never 0.
pub fn next_ecid() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed).wrapping_add(1).max(1)
}

/// What `CEC_SharedFile_Tag` tells of a file, downloads and shared files
/// alike.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedBase {
    pub ecid: u32,
    pub hash: Md4Hash,
    pub name: String,
    pub size: u64,
    /// `EC_TAG_KNOWNFILE_FILENAME`: `NNN.part` for a download, the folder
    /// for a shared file.
    pub file_name: String,
    /// `EC_TAG_KNOWNFILE_PATH`: the folder it is in.
    pub dir: String,
    /// `PR_*`, plus 10 when automatic.
    pub up_priority: u8,
    pub requests_all: u32,
    pub accepts_all: u32,
    pub transferred_all: u64,
    /// Base32, empty when unknown.
    pub aich: String,
    pub last_upload: u32,
    pub shared_since: u32,
    /// The last "verify local data": date and the two corrupt lists.
    pub verify: Option<(u32, String, String)>,
    /// The user's own comment and rating (0 to 5, 0 for none).
    pub comment: String,
    pub rating: u8,
}

/// `CreateED2kLink(file, false)`: `ed2k://|file|NAME|SIZE|HASH|/`.
pub fn ed2k_link(name: &str, size: u64, hash: &Md4Hash) -> String {
    format!(
        "ed2k://|file|{}|{}|{}|/",
        remule_core::part_file::clean_file_name(name),
        size,
        hash
    )
}

/// `CEC_SharedFile_Tag(file, detail_level, NULL, name)`: a tag named
/// `name` (`EC_TAG_KNOWNFILE`, or `EC_TAG_PARTFILE` for a download, which
/// adds its own after). Session upload statistics, complete-source counts,
/// upload activity, others' comments and media data are not kept yet: their zeros
/// and blanks are sent, as for a file nobody asked for.
pub fn shared_tag(name: u16, b: &SharedBase, detail: u8) -> Tag {
    let int = |n: u16, v: u64| Tag::int(n, v);
    let mut t = Tag::int(name, b.ecid.into());
    let mut add = |c: Tag| t.children.push(c);
    add(int(EC_TAG_KNOWNFILE_REQ_COUNT, 0));
    add(int(EC_TAG_KNOWNFILE_REQ_COUNT_ALL, b.requests_all.into()));
    add(int(EC_TAG_KNOWNFILE_ACCEPT_COUNT, 0));
    add(int(EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL, b.accepts_all.into()));
    add(int(EC_TAG_KNOWNFILE_XFERRED, 0));
    add(int(EC_TAG_KNOWNFILE_XFERRED_ALL, b.transferred_all));
    add(Tag::string(EC_TAG_KNOWNFILE_AICH_MASTERHASH, &b.aich));
    add(int(EC_TAG_KNOWNFILE_PRIO, b.up_priority.into()));
    for n in [
        EC_TAG_KNOWNFILE_COMPLETE_SOURCES_LOW,
        EC_TAG_KNOWNFILE_COMPLETE_SOURCES_HIGH,
        EC_TAG_KNOWNFILE_COMPLETE_SOURCES,
    ] {
        add(int(n, 0));
    }
    if name == EC_TAG_KNOWNFILE {
        // Hashing is done before a file is listed.
        add(int(EC_TAG_KNOWNFILE_HASHED_PART_COUNT, 0));
    }
    for n in [
        EC_TAG_KNOWNFILE_ON_QUEUE,
        EC_TAG_KNOWNFILE_UPLOAD_SPEED,
        EC_TAG_KNOWNFILE_UPLOADING_COUNT,
    ] {
        add(int(n, 0));
    }
    add(int(EC_TAG_KNOWNFILE_LAST_UPLOAD, b.last_upload.into()));
    // Only for a file verified once.
    if let Some((date, md4, aich)) = &b.verify {
        add(int(EC_TAG_KNOWNFILE_VERIFY_DATE, (*date).into()));
        add(Tag::string(EC_TAG_KNOWNFILE_VERIFY_CORRUPT_MD4, md4));
        add(Tag::string(EC_TAG_KNOWNFILE_VERIFY_CORRUPT_AICH, aich));
    }
    add(Tag::empty(EC_TAG_PARTFILE_COMMENTS));
    add(int(EC_TAG_PARTFILE_KAD_COMMENT_SEARCHING, 0));
    if detail != EC_DETAIL_UPDATE {
        add(Tag::string(EC_TAG_PARTFILE_NAME, &b.name));
        add(Tag::hash(EC_TAG_PARTFILE_HASH, b.hash.0));
        add(Tag::string(EC_TAG_KNOWNFILE_FILENAME, &b.file_name));
        add(Tag::string(EC_TAG_KNOWNFILE_PATH, &b.dir));
        add(int(EC_TAG_KNOWNFILE_SHARED_SINCE, b.shared_since.into()));
        add(int(EC_TAG_PARTFILE_SIZE_FULL, b.size));
        add(Tag::string(
            EC_TAG_PARTFILE_ED2K_LINK,
            &ed2k_link(&b.name, b.size, &b.hash),
        ));
        add(Tag::string(EC_TAG_KNOWNFILE_COMMENT, &b.comment));
        add(int(EC_TAG_KNOWNFILE_RATING, b.rating.into()));
    }
    t
}

/// `PR_*` as EC sends it: plus 10 when automatic.
pub fn ec_priority(p: u32, auto: bool) -> u8 {
    (p as u8).saturating_add(if auto { 10 } else { 0 })
}

/// A shared file's base, from its `known.met` record and where it is.
pub fn shared_base(ecid: u32, f: &KnownFile, path: &Path) -> SharedBase {
    let dir = path
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    SharedBase {
        ecid,
        hash: f.hash,
        name: f.name.clone(),
        size: f.size,
        file_name: dir.clone(),
        dir,
        up_priority: ec_priority(f.up_priority, f.auto_priority),
        requests_all: f.all_time_requests,
        accepts_all: f.all_time_accepts,
        transferred_all: f.all_time_transferred,
        aich: f.aich_hash.clone().unwrap_or_default(),
        last_upload: f.last_uploaded,
        shared_since: f.shared_since,
        verify: (f.verify_date != 0).then(|| {
            (
                f.verify_date,
                f.verify_corrupt_md4.clone(),
                f.verify_corrupt_aich.clone(),
            )
        }),
        comment: String::new(),
        rating: 0,
    }
}

/// The shared folders as configured: explicit, and recursive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedDirs {
    pub explicit: Vec<String>,
    pub recursive: Vec<String>,
}

/// What a shared-file request asks of the client.
#[derive(Debug)]
pub enum SharedRequest {
    /// Every shared file.
    List(oneshot::Sender<Vec<SharedBase>>),
    /// `RequestReload`.
    Reload,
    /// Upload priorities (`PR_AUTO` for automatic) by hash.
    SetPriority {
        files: Vec<(Md4Hash, u8)>,
        reply: oneshot::Sender<()>,
    },
    /// The configured folders.
    Dirs(oneshot::Sender<SharedDirs>),
    /// `DeleteFileFromDisk`: a complete shared file off the disk and out
    /// of the list, if it is still the one the client saw.
    Delete {
        hash: Md4Hash,
        ecid: u32,
        dir: String,
        name: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// `SetFileCommentRating`: the user's comment and rating of a shared
    /// file, kept in `amule.conf`.
    SetComment {
        hash: Md4Hash,
        comment: String,
        rating: u8,
        reply: oneshot::Sender<()>,
    },
    /// `RenameFile`: a complete shared file renamed on disk.
    Rename {
        hash: Md4Hash,
        name: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// `VerifyLocalData`: a shared file read back and checked against its
    /// hashes, off the client's loop; the outcome is logged.
    Verify(Md4Hash),
}

/// Ask the client; `None` when it is gone.
async fn ask<T>(
    control: &mpsc::UnboundedSender<Control>,
    make: impl FnOnce(oneshot::Sender<T>) -> SharedRequest,
) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    control.send(Control::Shared(make(tx))).ok()?;
    rx.await.ok()
}

fn detail(req: &Packet) -> u8 {
    req.tag(EC_TAG_DETAIL_LEVEL)
        .map_or(EC_DETAIL_FULL, |t| t.as_int() as u8)
}

/// `EC_OP_SHARED_FILES`: the files asked for by ECID, else all.
pub fn shared_files_reply(req: &Packet, files: &[SharedBase]) -> Packet {
    let detail = detail(req);
    let asked: Vec<u64> = req.tags_named(EC_TAG_KNOWNFILE).map(Tag::as_int).collect();
    let mut p = Packet::new(EC_OP_SHARED_FILES);
    for f in files {
        if asked.is_empty() || asked.contains(&u64::from(f.ecid)) {
            p = p.with(shared_tag(EC_TAG_KNOWNFILE, f, detail));
        }
    }
    p
}

/// `Get_EC_Response_GetSharedDirs`.
pub fn shared_dirs_reply(d: &SharedDirs) -> Packet {
    let mut p = Packet::new(EC_OP_GET_SHARED_DIRS);
    for dir in &d.explicit {
        p = p.with(Tag::string(EC_TAG_SHAREDDIR, dir));
    }
    for dir in &d.recursive {
        p = p
            .with(Tag::string(EC_TAG_SHAREDDIR, dir).with(Tag::int(EC_TAG_SHAREDDIR_RECURSIVE, 1)));
    }
    p
}

/// The shared-file requests (`ProcessRequest2`'s cases for them); `None`
/// for any other opcode.
pub async fn answer(req: &Packet, control: &mpsc::UnboundedSender<Control>) -> Option<Packet> {
    let gone =
        || Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, "Already shutting down."));
    Some(match req.opcode {
        // amulegui's incremental updates come with the update protocol.
        EC_OP_GET_SHARED_FILES if detail(req) == EC_DETAIL_INC_UPDATE => {
            return None;
        }
        EC_OP_GET_SHARED_FILES => match ask(control, SharedRequest::List).await {
            Some(files) => shared_files_reply(req, &files),
            None => gone(),
        },
        EC_OP_SHAREDFILES_RELOAD => {
            let _ = control.send(Control::Shared(SharedRequest::Reload));
            Packet::new(EC_OP_NOOP)
        }
        EC_OP_SHARED_SET_PRIO => {
            // Each tag a hash, its first child the priority; anything else
            // is passed over.
            let files = req
                .tags
                .iter()
                .filter_map(|t| {
                    let hash = Md4Hash(t.as_hash()?);
                    Some((hash, t.children.first()?.as_int() as u8))
                })
                .collect();
            match ask(control, |reply| SharedRequest::SetPriority { files, reply }).await {
                Some(()) => Packet::new(EC_OP_NOOP),
                None => gone(),
            }
        }
        EC_OP_GET_SHARED_DIRS => match ask(control, SharedRequest::Dirs).await {
            Some(d) => shared_dirs_reply(&d),
            None => gone(),
        },
        EC_OP_SHARED_FILE_SET_COMMENT => {
            let hash = req
                .tag(EC_TAG_KNOWNFILE)
                .filter(|t| t.ty == EC_TAGTYPE_HASH16)
                .and_then(Tag::as_hash);
            // aMule reads both safely: missing, they are empty and 0.
            let comment = req
                .tag(EC_TAG_KNOWNFILE_COMMENT)
                .map(Tag::as_str)
                .unwrap_or_default();
            let rating = req.tag(EC_TAG_KNOWNFILE_RATING).map_or(0, Tag::as_int) as u8;
            if let Some(hash) = hash {
                let r = ask(control, |reply| SharedRequest::SetComment {
                    hash: Md4Hash(hash),
                    comment,
                    rating,
                    reply,
                })
                .await;
                if r.is_none() {
                    return Some(gone());
                }
            }
            Packet::new(EC_OP_NOOP)
        }
        EC_OP_RENAME_FILE => {
            let failed = |m: &str| Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, m));
            let Some(hash) = req
                .tag(EC_TAG_KNOWNFILE)
                .filter(|t| t.ty == EC_TAGTYPE_HASH16)
                .and_then(Tag::as_hash)
            else {
                return Some(failed("File not found."));
            };
            let name = req
                .tag(EC_TAG_PARTFILE_NAME)
                .map(Tag::as_str)
                .unwrap_or_default();
            let r = ask(control, |reply| SharedRequest::Rename {
                hash: Md4Hash(hash),
                name,
                reply,
            })
            .await;
            match r {
                Some(Ok(())) => Packet::new(EC_OP_NOOP),
                Some(Err(e)) => failed(&e),
                None => gone(),
            }
        }
        EC_OP_VERIFY_LOCAL_DATA => {
            // Answered at once whatever it names, as aMule queues the task.
            if let Some(hash) = req
                .tag(EC_TAG_KNOWNFILE)
                .filter(|t| t.ty == EC_TAGTYPE_HASH16)
                .and_then(Tag::as_hash)
            {
                let _ = control.send(Control::Shared(SharedRequest::Verify(Md4Hash(hash))));
            }
            Packet::new(EC_OP_NOOP)
        }
        EC_OP_KNOWNFILE_DELETE => {
            let failed = |m: &str| Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, m));
            let hash = req
                .tag(EC_TAG_KNOWNFILE)
                .filter(|t| t.ty == EC_TAGTYPE_HASH16)
                .and_then(Tag::as_hash);
            let ecid = req
                .tag(EC_TAG_ECID)
                .filter(|t| t.is_int())
                .map(Tag::as_int)
                .filter(|&e| e != 0 && e <= u64::from(u32::MAX));
            let text = |name: u16| {
                req.tag(name)
                    .filter(|t| t.ty == EC_TAGTYPE_STRING)
                    .map(Tag::as_str)
            };
            let (Some(hash), Some(ecid), Some(dir), Some(name)) = (
                hash,
                ecid,
                text(EC_TAG_KNOWNFILE_PATH),
                text(EC_TAG_PARTFILE_NAME),
            ) else {
                return Some(failed("Invalid complete-file deletion target."));
            };
            let r = ask(control, |reply| SharedRequest::Delete {
                hash: Md4Hash(hash),
                ecid: ecid as u32,
                dir,
                name,
                reply,
            })
            .await;
            match r {
                Some(Ok(())) => Packet::new(EC_OP_NOOP),
                Some(Err(e)) => failed(&e),
                None => gone(),
            }
        }
        _ => return None,
    })
}

/// The client's side: the shared files, their ECIDs, a reload under way.
#[derive(Debug, Default)]
pub struct SharedState {
    ids: HashMap<Md4Hash, u32>,
    reloading: Arc<AtomicBool>,
    /// A reload asked for while one runs: one more walk after it.
    again: Arc<AtomicBool>,
    /// The user's comments and ratings, by file (`amule.conf`'s groups
    /// named by hash).
    comments: HashMap<Md4Hash, (String, u8)>,
}

/// Where a reload looks.
#[derive(Debug, Clone)]
pub struct ReloadDirs {
    pub dirs: Vec<PathBuf>,
    pub reserved: Vec<PathBuf>,
}

impl SharedState {
    /// Answer `req` from `shares` (`None` when nothing is shared), with the
    /// configured folders read from `config`.
    pub fn handle(
        &mut self,
        req: SharedRequest,
        shares: Option<&Arc<Mutex<SharedFiles>>>,
        reload: &ReloadDirs,
        config: &Path,
    ) {
        match req {
            SharedRequest::List(reply) => {
                let files = match shares {
                    Some(s) => self.list(&s.lock().unwrap_or_else(|e| e.into_inner())),
                    None => Vec::new(),
                };
                let _ = reply.send(files);
            }
            SharedRequest::Reload => {
                if let Some(s) = shares {
                    self.reload(s.clone(), reload.clone());
                }
            }
            SharedRequest::SetPriority { files, reply } => {
                if let Some(s) = shares {
                    let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
                    for (hash, prio) in files {
                        if let Some(f) = s.get_mut(&hash) {
                            set_priority(f, prio);
                        }
                    }
                }
                let _ = reply.send(());
            }
            SharedRequest::Delete {
                hash,
                ecid,
                dir,
                name,
                reply,
            } => {
                let r = match shares {
                    Some(s) => self.delete(s, hash, ecid, &dir, &name),
                    None => Err(CHANGED.into()),
                };
                let _ = reply.send(r);
            }
            SharedRequest::SetComment {
                hash,
                comment,
                rating,
                reply,
            } => {
                if shares.is_some_and(|s| {
                    s.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&hash)
                        .is_some()
                }) {
                    self.set_comment(config, hash, comment, rating);
                }
                let _ = reply.send(());
            }
            SharedRequest::Rename { hash, name, reply } => {
                let r = match shares {
                    Some(s) => rename(s, &hash, &name),
                    None => Err("File not found.".into()),
                };
                let _ = reply.send(r);
            }
            SharedRequest::Verify(hash) => {
                if let Some(s) = shares {
                    verify_local_data(s.clone(), hash);
                }
            }
            SharedRequest::Dirs(reply) => {
                let d = crate::config::shared_dir_intents(config);
                let _ = reply.send(SharedDirs {
                    explicit: d.explicit,
                    recursive: d.recursive,
                });
            }
        }
    }

    /// The comments and ratings `amule.conf` keeps (`CKnownFile::LoadComment`):
    /// a group per file, named by its hash, with `Comment` and `Rate`.
    pub fn load_comments(&mut self, config: &Path) {
        let Ok(bytes) = std::fs::read(config.join("amule.conf")) else {
            return;
        };
        let conf = ConfFile::from_bytes(&bytes);
        for (path, _) in conf.entries() {
            let Some(group) = path.strip_prefix('/').and_then(|p| p.split_once('/')) else {
                continue;
            };
            let Ok(hash) = group.0.parse::<Md4Hash>() else {
                continue;
            };
            if group.1 != "Comment" && group.1 != "Rate" {
                continue;
            }
            let get = |k: &str| conf.get(&format!("/{}/{k}", group.0));
            let comment = get("Comment").unwrap_or_default().to_owned();
            let rating = get("Rate")
                .and_then(ed2k_formats::amule_conf::parse_long)
                .map_or(0, |r| r.clamp(0, 5) as u8);
            self.comments.insert(hash, (comment, rating));
        }
    }

    /// `SetFileCommentRating`: kept, and written to `amule.conf`; neither
    /// a comment nor a rating removes the file's entries.
    fn set_comment(&mut self, config: &Path, hash: Md4Hash, comment: String, rating: u8) {
        if self
            .comments
            .get(&hash)
            .map_or(("", 0), |(c, r)| (c.as_str(), *r))
            == (comment.as_str(), rating)
        {
            return;
        }
        let group = format!("/{hash}/");
        let r = crate::config::update_conf(config, |conf| {
            if comment.is_empty() && rating == 0 {
                conf.remove(&format!("{group}Comment"));
                conf.remove(&format!("{group}Rate"));
            } else {
                conf.set(&format!("{group}Comment"), &comment);
                conf.set(&format!("{group}Rate"), &rating.to_string());
            }
        });
        if let Err(e) = r {
            warn!("{e}");
        }
        if comment.is_empty() && rating == 0 {
            self.comments.remove(&hash);
        } else {
            self.comments.insert(hash, (comment, rating));
        }
    }

    /// `DeleteFileFromDisk`: only the file the client saw (its hash, ECID,
    /// folder and name), and only once it is gone from the disk is it
    /// taken out of the list.
    fn delete(
        &mut self,
        shares: &Mutex<SharedFiles>,
        hash: Md4Hash,
        ecid: u32,
        dir: &str,
        name: &str,
    ) -> Result<(), String> {
        let mut s = shares.lock().unwrap_or_else(|e| e.into_inner());
        let path = match s.get(&hash) {
            Some((f, path))
                if self.ids.get(&hash) == Some(&ecid)
                    && f.name == name
                    && path.parent().map(|p| p.display().to_string()).as_deref() == Some(dir) =>
            {
                path.to_path_buf()
            }
            _ => {
                warn!("{CHANGED}");
                return Err(CHANGED.into());
            }
        };
        if let Err(e) = std::fs::remove_file(&path) {
            // A failed removal is no proof the file is still there.
            if path.exists() || e.kind() != std::io::ErrorKind::NotFound {
                let msg = format!("Could not delete '{}' from disk.", path.display());
                warn!("{msg}");
                return Err(msg);
            }
        }
        s.unshare(&hash);
        self.ids.remove(&hash);
        info!("Deleted '{}' from disk.", path.display());
        Ok(())
    }

    /// The shared files as EC tells them, each with its ECID (kept while
    /// it stays shared).
    pub fn list(&mut self, s: &SharedFiles) -> Vec<SharedBase> {
        let files = s.files();
        let mut ids = HashMap::with_capacity(files.len());
        let out = files
            .iter()
            .map(|(f, path)| {
                let ecid = *ids
                    .entry(f.hash)
                    .or_insert_with(|| self.ids.get(&f.hash).copied().unwrap_or_else(next_ecid));
                let mut b = shared_base(ecid, f, path);
                if let Some((comment, rating)) = self.comments.get(&f.hash) {
                    b.comment = comment.clone();
                    b.rating = *rating;
                }
                b
            })
            .collect();
        self.ids = ids;
        out
    }

    /// `CSharedFileList::Reload`, off the client's loop: the folders
    /// listed again, then the new files hashed one by one without holding
    /// the list. One at a time; asked for again meanwhile, it walks again.
    fn reload(&self, shares: Arc<Mutex<SharedFiles>>, dirs: ReloadDirs) {
        if self.reloading.swap(true, Ordering::SeqCst) {
            self.again.store(true, Ordering::SeqCst);
            return;
        }
        let (reloading, again) = (self.reloading.clone(), self.again.clone());
        tokio::task::spawn_blocking(move || {
            loop {
                again.store(false, Ordering::SeqCst);
                reload_now(&shares, &dirs);
                if !again.load(Ordering::SeqCst) {
                    break;
                }
            }
            reloading.store(false, Ordering::SeqCst);
        });
    }
}

/// `CSharedFileList::RenameFile` for a complete shared file: on disk,
/// then in `known.met`.
fn rename(shares: &Mutex<SharedFiles>, hash: &Md4Hash, name: &str) -> Result<(), String> {
    use remule_core::shared::RenameError;
    let mut s = shares.lock().unwrap_or_else(|e| e.into_inner());
    let old = match s.get(hash) {
        Some((f, _)) => f.name.clone(),
        None => return Err("File not found.".into()),
    };
    if name.is_empty() {
        return Err("Invalid file name.".into());
    }
    match s.rename(hash, name) {
        Ok(path) => {
            info!("Renamed '{old}' to '{}'.", path.display());
            if let Err(e) = s.save() {
                warn!("known.met: {e}");
            }
            Ok(())
        }
        Err(RenameError::NotBare) => {
            warn!(
                "Refused to rename '{old}' to '{name}': the new name must be a plain file name, \
                 not a path."
            );
            Err("Unable to rename file.".into())
        }
        Err(RenameError::NotShared) => Err("File not found.".into()),
        Err(RenameError::Io(e)) => {
            warn!("Could not rename '{old}' to '{name}': {e}");
            Err("Unable to rename file.".into())
        }
    }
}

/// `CKnownFile::VerifyLocalData` and `CVerifyLocalDataTask`: the check
/// runs off the client's loop, its outcome is logged as aMule logs it and
/// recorded in `known.met` if the file is still the one checked.
pub fn verify_local_data(shares: Arc<Mutex<SharedFiles>>, hash: Md4Hash) {
    let Some(target) = shares
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .verify_target(&hash)
    else {
        return;
    };
    tokio::task::spawn_blocking(move || {
        let outcome = remule_core::verify::verify(&target);
        let (critical, line) = outcome.report(&target.path);
        if critical {
            warn!("{line}");
        } else {
            info!("{line}");
        }
        let Some(record) = outcome.record() else {
            return;
        };
        let mut s = shares.lock().unwrap_or_else(|e| e.into_inner());
        if s.record_verify(&hash, &target.path, target.size, unix_now(), record) {
            if let Err(e) = s.save() {
                warn!("known.met: {e}");
            }
        }
    });
}

const CHANGED: &str = "The selected file has changed or is not a complete file.";

/// `SetAutoUpPriority` / `SetUpPriority`. Automatic starts as
/// `UpdateAutoUpPriority` puts a file nobody is queued for: high.
fn set_priority(f: &mut KnownFile, prio: u8) {
    if u32::from(prio) == priority::AUTO {
        f.auto_priority = true;
        f.up_priority = priority::HIGH;
    } else {
        f.auto_priority = false;
        f.up_priority = prio.into();
    }
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

/// One walk: blocking.
pub fn reload_now(shares: &Mutex<SharedFiles>, dirs: &ReloadDirs) {
    info!("Reloading shared files...");
    let opts = ScanOptions {
        dirs: dirs.dirs.clone(),
        reserved: dirs.reserved.clone(),
        hidden: false,
    };
    let (before, to_hash) = {
        let mut s = shares.lock().unwrap_or_else(|e| e.into_inner());
        let before = s.shared_count();
        let r = s.scan(&opts, unix_now());
        for (d, why) in &r.skipped {
            warn!("{}: not shared ({why})", d.display());
        }
        (before, r.to_hash)
    };
    let mut new = 0usize;
    for p in &to_hash {
        let Ok(date) = std::fs::metadata(p).map(|m| mtime(&m)) else {
            continue;
        };
        match SharedFiles::hash(p) {
            Ok(h) => {
                shares.lock().unwrap_or_else(|e| e.into_inner()).add_hashed(
                    p,
                    &h,
                    date,
                    unix_now(),
                );
                info!("hashed {}", p.display());
                new += 1;
            }
            Err(e) => warn!("{}: {e}", p.display()),
        }
    }
    let mut s = shares.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(e) = s.save() {
        warn!("known.met: {e}");
    }
    if new > 0 {
        info!(
            "Discovered {new} new shared file{}",
            if new == 1 { "" } else { "s" }
        );
    }
    info!("sharing {} files (was {before})", s.shared_count());
}
