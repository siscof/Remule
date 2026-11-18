// SPDX-License-Identifier: GPL-2.0-or-later
//! Searches over external connections (`CSearchList` and the search
//! requests of `ExternalConn.cpp`), for clients that do not speak
//! multi-search: one search at a time, its results in the legacy
//! `0xffffffff` bucket.
//!
//! [`SearchList`] keeps the search and its results without IO: what may be
//! started, the results merged as `CSearchList::AddToList` merges them, and
//! the progress EC reports. [`serve`] answers a request with it, starting
//! the server and Kad parts on the client's connections; the client feeds
//! it the server's answer and Kad's results as they come.
//!
//! Not yet: the global sweep over other servers by UDP (a global search
//! asks the connected server, as a local one does), filtering results by
//! file type, stopping a running Kad lookup (its later results are ignored).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use ed2k_kad::driver::KadHandle;
use ed2k_kad::search::KeywordResult;
use ed2k_server::search::{encode_kad_search, encode_search, kad_words, SearchParams};
use ed2k_server::{SearchResult, ServerClient};
use ed2k_types::ed2k::server_tcp::flags::LARGEFILES;
use ed2k_types::ed2k::MAX_FILE_SIZE;
use ed2k_types::tags::FileType;
use ed2k_types::Md4Hash;
use remule_ec::codes::*;
use remule_ec::{Packet, Tag};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::ec::Control;

/// `SERVER_ANSWER_TIMEOUT_MS`: how long the server may take to answer.
pub const SERVER_ANSWER_TIMEOUT: Duration = Duration::from_secs(12);
/// `SEARCHKEYWORD_LIFETIME`: what the Kad progress ramp is measured against.
pub const KEYWORD_LIFETIME: Duration = Duration::from_secs(45);
/// `SEARCH_MAX_MIN_BITRATE_KBPS`, `SEARCH_MAX_MIN_DURATION_SECONDS`.
pub const MAX_MIN_BITRATE: u64 = 1_000_000;
pub const MAX_MIN_LENGTH: u64 = 86_400;

/// `SearchType`: its numbers are `EC_SEARCH_TYPE`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    #[default]
    Local = 0,
    Global = 1,
    Kad = 2,
    All = 5,
}

/// `SearchLifecycleState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Idle = 0,
    Running = 1,
    Finished = 2,
}

/// `CSearchFile::DownloadStatus`, as EC sends it.
pub mod download_status {
    pub const NEW: u8 = 0;
    pub const DOWNLOADED: u8 = 1;
    pub const QUEUED: u8 = 2;
}

/// `CSearchSourceCount`: the eD2k counts add up, Kad's is the largest seen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Count {
    pub ed2k: u32,
    pub kad: u32,
}

impl Count {
    fn merge(&mut self, o: Count) {
        self.ed2k = self.ed2k.saturating_add(o.ed2k);
        self.kad = self.kad.max(o.kad);
    }

    pub fn total(self) -> u32 {
        self.ed2k.max(self.kad)
    }
}

/// One result (`CSearchFile`): a parent, or one of its differently named
/// children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchFile {
    pub ecid: u32,
    pub hash: Md4Hash,
    pub name: String,
    pub size: u64,
    pub sources: Count,
    pub complete: Count,
    /// 0 when unrated.
    pub rating: u8,
    /// Clients that have it, as the server said (HighIDs only).
    pub clients: Vec<SocketAddrV4>,
    pub children: Vec<SearchFile>,
    /// A child's parent's ECID.
    pub parent: Option<u32>,
}

impl SearchFile {
    /// `MergeResults`.
    fn merge(&mut self, o: &SearchFile) {
        self.sources.merge(o.sources);
        self.complete.merge(o.complete);
        self.rating = match (self.rating, o.rating) {
            (0, r) => r,
            (r, 0) => r,
            (a, b) => ((u16::from(a) + u16::from(b)) / 2) as u8,
        };
        for c in &o.clients {
            if !self.clients.contains(c) {
                self.clients.push(*c);
            }
        }
    }

    /// `UpdateParent`: the counts of every child, the name of the one with
    /// the most sources.
    fn update_parent(&mut self) {
        let mut sources = Count::default();
        let mut complete = Count::default();
        let mut best = 0;
        let (mut rated, mut rating_total) = (0u32, 0u32);
        for (i, c) in self.children.iter().enumerate() {
            if c.sources.total() > self.children[best].sources.total() {
                best = i;
            }
            sources.merge(c.sources);
            complete.merge(c.complete);
            if c.rating != 0 {
                rated += 1;
                rating_total += u32::from(c.rating);
            }
            for a in &c.clients {
                if !self.clients.contains(a) {
                    self.clients.push(*a);
                }
            }
        }
        self.sources = sources;
        self.complete = complete;
        self.rating = rating_total.checked_div(rated).unwrap_or(0) as u8;
        self.name = self.children[best].name.clone();
    }

    /// `CEC_SearchFile_Tag(file, detail_level)`.
    pub fn tag(&self, detail: u8, status: u8) -> Tag {
        let mut t = Tag::int(EC_TAG_SEARCHFILE, self.ecid.into());
        let mut add = |c: Tag| t.children.push(c);
        add(Tag::int(
            EC_TAG_PARTFILE_SOURCE_COUNT,
            self.sources.total().into(),
        ));
        add(Tag::int(
            EC_TAG_PARTFILE_SOURCE_COUNT_XFER,
            self.complete.total().into(),
        ));
        add(Tag::int(
            EC_TAG_SEARCHFILE_ED2K_SOURCES,
            self.sources.ed2k.into(),
        ));
        add(Tag::int(
            EC_TAG_SEARCHFILE_KAD_SOURCES,
            self.sources.kad.into(),
        ));
        add(Tag::int(EC_TAG_PARTFILE_STATUS, status.into()));
        add(Tag::int(EC_TAG_PARTFILE_KAD_COMMENT_SEARCHING, 0));
        if detail != EC_DETAIL_UPDATE {
            add(Tag::string(EC_TAG_PARTFILE_NAME, &self.name));
            add(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, self.size));
            add(Tag::hash(EC_TAG_PARTFILE_HASH, self.hash.0));
            if let Some(p) = self.parent {
                add(Tag::int(EC_TAG_SEARCH_PARENT, p.into()));
            }
            if self.rating != 0 {
                add(Tag::int(EC_TAG_KNOWNFILE_RATING, self.rating.into()));
            }
        }
        t
    }
}

/// What the client's connections allow (`StartNewSearch`'s checks).
#[derive(Debug, Clone, Copy, Default)]
pub struct Networks {
    pub ed2k_connected: bool,
    /// The server takes 64-bit sizes.
    pub large_files: bool,
    pub kad_running: bool,
}

/// What a start needs done on the networks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub kind: Kind,
    /// The search request's payload, for the connected server.
    pub server: Option<Vec<u8>>,
    /// The Kad keyword search to start.
    pub kad: Option<SearchParams>,
}

/// The search and its results.
#[derive(Debug, Default)]
pub struct SearchList {
    results: Vec<SearchFile>,
    next_ecid: u32,
    /// `m_searchType`.
    kind: Kind,
    /// `m_currentSearch != -1`.
    current: bool,
    /// `m_searchInProgress`: the eD2k part runs.
    ed2k_running: bool,
    ed2k_finished: bool,
    /// While waiting for the server's answer: until when.
    answer_due: Option<Instant>,
    /// The Kad lookup that feeds this search, while it runs.
    kad_id: Option<u32>,
    kad_finished: bool,
    started: Option<Instant>,
}

/// `CreateSearchData`'s parser errors, one per line.
fn parser_error(e: impl std::fmt::Display) -> String {
    format!("{e}\n")
}

impl SearchList {
    fn ecid(&mut self) -> u32 {
        self.next_ecid += 1;
        self.next_ecid
    }

    pub fn results(&self) -> &[SearchFile] {
        &self.results
    }

    /// `RemoveResults(0xffffffff)`: the bucket emptied, and the Kad lookup
    /// that fed it no longer counts.
    pub fn remove_results(&mut self) {
        self.results.clear();
        if self.kad_id.take().is_some() && self.kind == Kind::Kad {
            self.kad_finished = true;
        }
    }

    /// `StartNewSearch`'s checks and `CreateSearchData`: what to start, or
    /// why not. Nothing changes until [`SearchList::begin`].
    pub fn plan(&self, kind: Kind, params: &SearchParams, net: Networks) -> Result<Plan, String> {
        match kind {
            Kind::All if !net.ed2k_connected && !net.kad_running => {
                return Err("All search can't be done if neither eD2k nor Kad is available".into())
            }
            Kind::Kad if !net.kad_running => {
                return Err("Kad search can't be done if Kad is not running".into())
            }
            Kind::Local | Kind::Global if !net.ed2k_connected => {
                return Err("eD2k search can't be done if eD2k is not connected".into())
            }
            _ => {}
        }
        let mut start_kad = kind == Kind::Kad || (kind == Kind::All && net.kad_running);
        if start_kad && kad_words(&params.query).is_empty() {
            if kind == Kind::All && net.ed2k_connected {
                start_kad = false;
                info!("All search: no usable Kad keyword; continuing with eD2k.");
            } else {
                return Err("No keyword for Kad search - aborting".into());
            }
        }
        let server = if kind == Kind::Kad {
            None
        } else {
            Some(
                encode_search(params, net.large_files)
                    .map_err(parser_error)?
                    .0,
            )
        };
        if start_kad {
            encode_kad_search(params).map_err(parser_error)?;
        }
        Ok(Plan {
            kind,
            server: server.filter(|_| net.ed2k_connected),
            kad: start_kad.then(|| params.clone()),
        })
    }

    /// The search started: its Kad lookup's ID, if one runs.
    pub fn begin(&mut self, plan: &Plan, kad_id: Option<u32>, now: Instant) {
        // A Kad search beside a running eD2k one does not take over the
        // eD2k part's place.
        let keep_ed2k = plan.kind == Kind::Kad && self.ed2k_running;
        if !keep_ed2k {
            self.kind = plan.kind;
            self.current = true;
        }
        if plan.kind == Kind::Kad {
            self.kad_finished = false;
        } else {
            // StopInFlightEd2kSearch, then the new one.
            self.ed2k_running = plan.server.is_some();
            self.ed2k_finished = !self.ed2k_running;
            self.answer_due = self.ed2k_running.then(|| now + SERVER_ANSWER_TIMEOUT);
        }
        if kad_id.is_some() {
            self.kad_id = kad_id;
        }
        self.started = Some(now);
    }

    fn add(&mut self, mut f: SearchFile) {
        if f.size == 0 || f.size > MAX_FILE_SIZE {
            debug!("Dropped result with filesize {}: {}", f.size, f.name);
            return;
        }
        let Some(i) = self
            .results
            .iter()
            .position(|r| r.hash == f.hash && r.size == f.size)
        else {
            self.results.push(f);
            return;
        };
        // AddChild: the same name merges; another name makes the group,
        // whose first child is the result received first.
        if self.results[i].children.is_empty() {
            if f.name == self.results[i].name {
                self.results[i].merge(&f);
                return;
            }
            let id = self.ecid();
            let parent = &mut self.results[i];
            let mut first = parent.clone();
            first.ecid = id;
            first.parent = Some(parent.ecid);
            parent.children.push(first);
        }
        let parent = &mut self.results[i];
        f.parent = Some(parent.ecid);
        match parent.children.iter_mut().find(|c| c.name == f.name) {
            Some(c) => c.merge(&f),
            None => parent.children.push(f),
        }
        parent.update_parent();
    }

    /// The server's `OP_SEARCHRESULT`, then `LocalSearchEnd`. Without the
    /// UDP sweep, a global search ends with it too.
    pub fn server_results(&mut self, results: Vec<SearchResult>) {
        if !self.ed2k_running {
            return;
        }
        for r in results {
            let ecid = self.ecid();
            let ip = Ipv4Addr::from(r.client_id.to_le_bytes());
            let clients = if r.client_port != 0 && !ed2k_server::packets::is_low_id(r.client_id) {
                vec![SocketAddrV4::new(ip, r.client_port)]
            } else {
                Vec::new()
            };
            self.add(SearchFile {
                ecid,
                hash: r.hash,
                name: r.name,
                size: r.size,
                sources: Count {
                    ed2k: r.sources,
                    kad: 0,
                },
                complete: Count {
                    ed2k: r.complete_sources,
                    kad: 0,
                },
                rating: r.rating,
                clients,
                children: Vec::new(),
                parent: None,
            });
        }
        if self.answer_due.take().is_some() {
            self.finish_ed2k();
        }
    }

    /// A Kad keyword result, if it is for this search.
    pub fn kad_result(&mut self, search: u32, k: KeywordResult) {
        if self.kad_id != Some(search) {
            return;
        }
        let ecid = self.ecid();
        self.add(SearchFile {
            ecid,
            hash: k.hash,
            name: k.name,
            size: k.size,
            sources: Count {
                ed2k: 0,
                kad: k.availability,
            },
            complete: Count::default(),
            rating: 0,
            clients: Vec::new(),
            children: Vec::new(),
            parent: None,
        });
    }

    /// A Kad lookup ended.
    pub fn kad_done(&mut self, search: u32) {
        if self.kad_id == Some(search) {
            self.kad_id = None;
            if self.kind == Kind::Kad {
                self.kad_finished = true;
            }
        }
    }

    /// `FinalizeLocalSearch` / `FinalizeGlobalSearch`.
    fn finish_ed2k(&mut self) {
        self.answer_due = None;
        self.ed2k_running = false;
        self.ed2k_finished = true;
    }

    /// The server's answer is overdue.
    pub fn poll(&mut self, now: Instant) {
        if self.ed2k_running && self.answer_due.is_some_and(|t| now >= t) {
            if self.kind == Kind::Local {
                info!("Search timed out: the server did not answer.");
            } else {
                debug!("The server did not answer the search, asking the other servers");
            }
            self.finish_ed2k();
        }
    }

    /// `StopSearch()`: no more results, the results kept.
    pub fn stop(&mut self) {
        match self.kind {
            Kind::Global | Kind::All | Kind::Local => {
                self.finish_ed2k();
                if self.kind == Kind::All {
                    self.kad_id = None;
                }
                self.current = false;
            }
            Kind::Kad => {
                self.kad_id = None;
                self.kad_finished = true;
                self.current = false;
            }
        }
    }

    /// `GetSearchProgress`: 0xffff a local search running, 0xfffe a Kad
    /// (or all) search over, else a percent.
    pub fn progress(&self, now: Instant) -> u32 {
        match self.kind {
            Kind::All => {
                let kad = self.kad_id.is_some();
                if !self.ed2k_running && !kad {
                    return 0xfffe;
                }
                // The sweep never runs, so a running eD2k part is at 0.
                let sweep = if self.ed2k_running { 0 } else { 100 };
                let ramp = if kad { self.ramp(now).min(99) } else { 100 };
                sweep.min(ramp)
            }
            Kind::Kad if self.kad_finished => 0xfffe,
            Kind::Kad => 0,
            _ if !self.ed2k_running => 0,
            Kind::Local => 0xffff,
            Kind::Global => 0,
        }
    }

    fn ramp(&self, now: Instant) -> u32 {
        let elapsed = self
            .started
            .map_or(0, |t| now.saturating_duration_since(t).as_secs());
        (elapsed * 100 / KEYWORD_LIFETIME.as_secs()) as u32
    }

    /// `GetSearchLifecycleState`.
    pub fn lifecycle(&self) -> Lifecycle {
        if !self.current {
            return Lifecycle::Idle;
        }
        match self.kind {
            Kind::Kad if self.kad_finished => Lifecycle::Finished,
            Kind::Kad => Lifecycle::Running,
            Kind::All if self.kad_id.is_some() => Lifecycle::Running,
            _ if self.ed2k_finished => Lifecycle::Finished,
            _ => Lifecycle::Running,
        }
    }

    /// `GetSearchLifecyclePercent`.
    pub fn percent(&self, now: Instant) -> u8 {
        match self.lifecycle() {
            Lifecycle::Idle => 0,
            Lifecycle::Finished => 100,
            Lifecycle::Running => match self.kind {
                Kind::Kad => self.ramp(now).min(99) as u8,
                Kind::Global | Kind::All => self.progress(now).min(100) as u8,
                Kind::Local => 0,
            },
        }
    }

    /// The legacy `EC_OP_SEARCH_PROGRESS` reply.
    pub fn progress_reply(&self, now: Instant) -> Packet {
        let count = if self.current { self.results.len() } else { 0 };
        Packet::new(EC_OP_SEARCH_PROGRESS)
            .with(Tag::int(EC_TAG_SEARCH_STATUS, self.progress(now).into()))
            .with(Tag::int(
                EC_TAG_SEARCH_LIFECYCLE_STATE,
                self.lifecycle() as u64,
            ))
            .with(Tag::int(EC_TAG_SEARCH_LIFECYCLE_KIND, self.kind as u64))
            .with(Tag::int(EC_TAG_SEARCH_RESULT_COUNT, count as u64))
            .with(Tag::int(
                EC_TAG_SEARCH_LIFECYCLE_PERCENT,
                self.percent(now).into(),
            ))
    }

    /// `Get_EC_Response_Search_Results`: the parents, their children too
    /// when the request carries `EC_TAG_SEARCH_PARENT`, or those asked for
    /// by ECID.
    pub fn results_reply(&self, req: &Packet, status: &dyn Fn(&Md4Hash) -> u8) -> Packet {
        let detail = req
            .tag(EC_TAG_DETAIL_LEVEL)
            .map_or(EC_DETAIL_FULL, |t| t.as_int() as u8);
        let asked: Vec<u64> = req.tags_named(EC_TAG_SEARCHFILE).map(Tag::as_int).collect();
        let children = req.tag(EC_TAG_SEARCH_PARENT).is_some();
        let mut p = Packet::new(EC_OP_SEARCH_RESULTS);
        for f in &self.results {
            if !asked.is_empty() && !asked.contains(&u64::from(f.ecid)) {
                continue;
            }
            p = p.with(f.tag(detail, status(&f.hash)));
            if children {
                for c in &f.children {
                    p = p.with(c.tag(detail, status(&c.hash)));
                }
            }
        }
        p
    }

    /// `AddFileToDownloadByEcid` (parents and children), or
    /// `AddFileToDownloadByHash` (the first parent with that hash).
    pub fn find_for_download(
        &self,
        ecid: Option<u32>,
        hash: Option<Md4Hash>,
    ) -> Option<&SearchFile> {
        match ecid {
            Some(id) => self.results.iter().find_map(|f| {
                if f.ecid == id {
                    Some(f)
                } else {
                    f.children.iter().find(|c| c.ecid == id)
                }
            }),
            None => self.results.iter().find(|f| Some(f.hash) == hash),
        }
    }
}

/// A result to download, for the client to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToDownload {
    pub hash: Md4Hash,
    pub name: String,
    pub size: u64,
    pub sources: Vec<SocketAddrV4>,
}

/// `EC_TAG_SEARCH_FILE_TYPE` to a server file type; "Any" or nothing is
/// none.
fn file_type(s: &str) -> Option<FileType> {
    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("any") {
        return None;
    }
    let long = [
        ("Document", FileType::Document),
        ("Program", FileType::Program),
        ("Archive", FileType::Archive),
        ("CD-Image", FileType::CdImage),
        ("CDImage", FileType::CdImage),
    ];
    FileType::ALL
        .into_iter()
        .find(|t| t.as_str().eq_ignore_ascii_case(s))
        .or_else(|| {
            long.iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(s))
                .map(|(_, t)| *t)
        })
}

/// `CEC_Search_Tag`'s fields, as `Get_EC_Response_Search` reads them.
pub fn search_params(t: &Tag) -> (u8, SearchParams) {
    let params = SearchParams {
        query: t.child_str(EC_TAG_SEARCH_NAME),
        file_type: file_type(&t.child_str(EC_TAG_SEARCH_FILE_TYPE)),
        min_size: t.child_int(EC_TAG_SEARCH_MIN_SIZE),
        max_size: t.child_int(EC_TAG_SEARCH_MAX_SIZE),
        availability: t.child_int(EC_TAG_SEARCH_AVAILABILITY),
        extension: t.child_str(EC_TAG_SEARCH_EXTENSION),
        min_bitrate: t.child_int(EC_TAG_SEARCH_MIN_BITRATE),
        min_length: t.child_int(EC_TAG_SEARCH_MIN_LENGTH),
        codec: t.child_str(EC_TAG_SEARCH_CODEC),
        title: t.child_str(EC_TAG_SEARCH_TITLE),
        album: t.child_str(EC_TAG_SEARCH_ALBUM),
        artist: t.child_str(EC_TAG_SEARCH_ARTIST),
    };
    (t.as_int() as u8, params)
}

/// The client's connections a search runs on.
pub struct Net<'a> {
    pub server: Option<&'a ServerClient>,
    pub kad: Option<&'a KadHandle>,
}

fn reply(op: u8, message: &str) -> Packet {
    Packet::new(op).with(Tag::string(EC_TAG_STRING, message))
}

/// `Get_EC_Response_Search` on the legacy sentinel: the bucket emptied,
/// then the search started (or why not).
async fn start(req: &Packet, list: &mut SearchList, net: &Net<'_>) -> Packet {
    let empty = Tag::empty(EC_TAG_SEARCH_TYPE);
    let (ty, params) = search_params(req.tags.first().unwrap_or(&empty));
    let kind = match ty {
        EC_SEARCH_WEB => {
            return reply(
                EC_OP_FAILED,
                "WebSearch from remote interface makes no sense.",
            )
        }
        _ if params.min_bitrate > MAX_MIN_BITRATE || params.min_length > MAX_MIN_LENGTH => {
            return reply(EC_OP_FAILED, "Invalid media search filter.")
        }
        EC_SEARCH_BROWSE => {
            return reply(
                EC_OP_FAILED,
                "A browse is not a search that can be started.",
            )
        }
        EC_SEARCH_GLOBAL => Kind::Global,
        EC_SEARCH_KAD => Kind::Kad,
        EC_SEARCH_ALL => Kind::All,
        _ => Kind::Local,
    };
    list.remove_results();
    let networks = Networks {
        ed2k_connected: net.server.is_some(),
        large_files: net
            .server
            .is_some_and(|s| s.info().tcp_flags & LARGEFILES != 0),
        kad_running: net.kad.is_some(),
    };
    let mut plan = match list.plan(kind, &params, networks) {
        Ok(p) => p,
        Err(e) => return reply(EC_OP_FAILED, &e),
    };
    let mut kad_id = None;
    if let (Some(p), Some(k)) = (plan.kad.clone(), net.kad) {
        match k.search_keyword(p).await {
            Ok((id, keyword)) => {
                debug!("Kad keyword search {id} for {keyword:?}");
                kad_id = Some(id);
            }
            Err(e) if kind == Kind::All && plan.server.is_some() => {
                info!("All search: Kad component could not start: {e}");
                plan.kad = None;
            }
            Err(e) => {
                return reply(
                    EC_OP_FAILED,
                    &format!("Unexpected error while attempting Kad search: {e}"),
                )
            }
        }
    }
    list.begin(&plan, kad_id, Instant::now());
    if let (Some(payload), Some(s)) = (plan.server.clone(), net.server) {
        if let Err(e) = s.send(ed2k_server::packets::search_request(payload)).await {
            warn!("search request to the server: {e}");
        }
    }
    reply(
        EC_OP_STRINGS,
        "Search in progress. Refetch results in a moment!",
    )
}

/// `Get_EC_Response_Search_Results_Download`.
fn downloads(req: &Packet, list: &SearchList) -> (Packet, Vec<ToDownload>) {
    let mut out = Vec::new();
    let mut all_found = true;
    for t in &req.tags {
        let found = match t.child(EC_TAG_SEARCHFILE) {
            Some(id) => list.find_for_download(Some(id.as_int() as u32), None),
            None => list.find_for_download(None, t.as_hash().map(Md4Hash)),
        };
        match found {
            Some(f) => out.push(ToDownload {
                hash: f.hash,
                name: f.name.clone(),
                size: f.size,
                sources: f.clients.clone(),
            }),
            None => all_found = false,
        }
    }
    if all_found {
        (Packet::new(EC_OP_STRINGS), out)
    } else {
        (
            reply(EC_OP_FAILED, "No open search holds this result."),
            out,
        )
    }
}

/// A search request: the reply, and the results to start downloading.
/// `status` says what became of a file (`download_status`).
pub async fn serve(
    req: &Packet,
    list: &mut SearchList,
    net: Net<'_>,
    status: &(dyn Fn(&Md4Hash) -> u8 + Sync),
) -> (Packet, Vec<ToDownload>) {
    let now = Instant::now();
    match req.opcode {
        EC_OP_SEARCH_START => (start(req, list, &net).await, Vec::new()),
        EC_OP_SEARCH_STOP => {
            list.stop();
            (Packet::new(EC_OP_MISC_DATA), Vec::new())
        }
        EC_OP_SEARCH_RESULTS => (list.results_reply(req, status), Vec::new()),
        EC_OP_SEARCH_PROGRESS => (list.progress_reply(now), Vec::new()),
        EC_OP_DOWNLOAD_SEARCH_RESULT => downloads(req, list),
        EC_OP_SEARCH_REQUEST_MORE => {
            // Only multi-search has searches to widen.
            let mut p =
                Packet::new(EC_OP_MISC_DATA).with(Tag::int(EC_TAG_SEARCH_MORE_REASKABLE, 0));
            if let Some(id) = req.tag(EC_TAG_SEARCH_ID) {
                p = p.with(Tag::int(EC_TAG_SEARCH_ID, id.as_int()));
            }
            (p, Vec::new())
        }
        // A legacy client has the one search, nothing to list.
        _ => (Packet::new(EC_OP_SEARCH_LIST), Vec::new()),
    }
}

/// The search opcodes.
pub fn is_search(op: u8) -> bool {
    matches!(
        op,
        EC_OP_SEARCH_START
            | EC_OP_SEARCH_STOP
            | EC_OP_SEARCH_RESULTS
            | EC_OP_SEARCH_PROGRESS
            | EC_OP_DOWNLOAD_SEARCH_RESULT
            | EC_OP_SEARCH_REQUEST_MORE
            | EC_OP_SEARCH_LIST
    )
}

/// Hand a search request to the client, which holds the search.
pub async fn forward(req: &Packet, control: &mpsc::UnboundedSender<Control>) -> Packet {
    let (tx, rx) = oneshot::channel();
    if control
        .send(Control::Search {
            req: req.clone(),
            reply: tx,
        })
        .is_err()
    {
        return reply(EC_OP_FAILED, "Already shutting down.");
    }
    rx.await
        .unwrap_or_else(|_| reply(EC_OP_FAILED, "Already shutting down."))
}
