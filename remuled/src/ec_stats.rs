// SPDX-License-Identifier: GPL-2.0-or-later
//! The statistics tree (`CStatistics::InitStatsTree`, `UpdateStatsTree`,
//! `CStatTreeItem*::CreateECTag`): what `EC_OP_GET_STATSTREE` answers,
//! for `amulegui`'s statistics page and `amulecmd`'s `statistics`.
//!
//! Each node is its label, an untranslated format string ("Uptime: %s"),
//! with its ID and key, its values (typed so the client can format them),
//! and its visible children. The nodes, their order, IDs, keys and value
//! types are aMule's; what remuled does not count yet (overheads, upload
//! sessions, client types, Kad buddies) reads as zero, as on an aMule that
//! has seen none.

use remule_ec::codes::*;
use remule_ec::{Packet, Tag};

/// What the tree's values come from.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TreeData {
    pub uptime: u64,
    pub session_sent: u64,
    pub session_received: u64,
    /// Every session's, this one's included.
    pub total_sent: u64,
    pub total_received: u64,
    /// Seconds since the first byte went either way, if one has.
    pub since_first_transfer: Option<u64>,
    /// Seconds since the server login, if logged in.
    pub connected_since: Option<u64>,
    /// Server logins this session.
    pub logins: u64,
    /// Bytes per second, the highest 30-second average this session.
    pub max_download_rate: u32,
    pub max_upload_rate: u32,
    pub connections: u64,
    pub peak_connections: u64,
    pub average_connections: f64,
    pub active_uploads: u64,
    pub waiting_uploads: u64,
    pub found_sources: u64,
    /// Sources sending us data.
    pub active_downloads: u64,
    pub servers_total: u64,
    pub servers_failed: u64,
    pub users_on_working: u64,
    pub files_on_working: u64,
    pub total_users: u64,
    pub total_files: u64,
    /// Percent of the working servers' capacity in use.
    pub server_occupation: f64,
    pub shared_count: u64,
    pub shared_size: u64,
}

/// One node, being built.
struct Node {
    label: &'static str,
    id: u32,
    key: Option<&'static str>,
    values: Vec<Tag>,
    visible: bool,
    children: Vec<Node>,
}

impl Node {
    fn tag(&self) -> Option<Tag> {
        if !self.visible {
            return None;
        }
        let mut t = Tag::string(EC_TAG_STATTREE_NODE, self.label)
            .with(Tag::int(EC_TAG_STATTREE_NODEID, self.id.into()));
        if let Some(k) = self.key {
            t = t.with(Tag::string(EC_TAG_STAT_NODE_KEY, k));
        }
        t.children.extend(self.values.iter().cloned());
        t.children
            .extend(self.children.iter().filter_map(Node::tag));
        Some(t)
    }
}

/// `NewStatTreeItemId`: IDs in the order aMule makes the nodes.
struct Ids(u32);

impl Ids {
    fn next(&mut self) -> u32 {
        self.0 += 1;
        self.0
    }

    fn node(&mut self, label: &'static str, key: Option<&'static str>, values: Vec<Tag>) -> Node {
        Node {
            label,
            id: self.next(),
            key,
            values,
            visible: true,
            children: Vec::new(),
        }
    }
}

fn value(v: u64) -> Tag {
    Tag::int(EC_TAG_STAT_NODE_VALUE, v)
}

fn typed(v: u64, ty: u8) -> Tag {
    value(v).with(Tag::int(EC_TAG_STAT_VALUE_TYPE, ty.into()))
}

fn text(s: &str) -> Tag {
    Tag::string(EC_TAG_STAT_NODE_VALUE, s)
        .with(Tag::int(EC_TAG_STAT_VALUE_TYPE, EC_VALUE_STRING.into()))
}

fn double(v: f64) -> Tag {
    Tag::double(EC_TAG_STAT_NODE_VALUE, v)
        .with(Tag::int(EC_TAG_STAT_VALUE_TYPE, EC_VALUE_DOUBLE.into()))
}

/// A `CStatTreeItemCounter` / `NativeCounter` shown as a number.
fn counter(v: u64) -> Vec<Tag> {
    vec![typed(v, EC_VALUE_ISTRING)]
}

/// `CStatTreeItemPackets` / `PacketTotals`: bytes, with the packet count.
fn packets(bytes: u64, count: u64) -> Vec<Tag> {
    vec![typed(bytes, EC_VALUE_BYTES).with(typed(count, EC_VALUE_ISHORT))]
}

/// `CStatTreeItemUlDlCounter`: the session's bytes, with every session's.
fn ul_dl(session: u64, total: u64) -> Vec<Tag> {
    vec![typed(session, EC_VALUE_BYTES).with(typed(total, EC_VALUE_BYTES))]
}

/// `CStatTreeItemTimer`: seconds, 0 while not started.
fn timer(secs: Option<u64>) -> Vec<Tag> {
    vec![typed(secs.unwrap_or(0).min(u32::MAX.into()), EC_VALUE_TIME)]
}

/// `CStatTreeItemRatio::GetString(true)` and its raw ratios: C-locale
/// numbers to two places, English text.
fn ratio(sent: u64, received: u64, total_sent: u64, total_received: u64) -> Vec<Tag> {
    let (v1, v2) = (sent as f64, received as f64);
    let mut s = if v1 > 0.0 && v2 > 0.0 {
        if v2 < v1 {
            format!("{:.2} : 1", v1 / v2)
        } else {
            format!("1 : {:.2}", v2 / v1)
        }
    } else {
        "Not available".to_owned()
    };
    // As aMule: the cumulative figures already hold the session's, and
    // the session's are added again.
    let (t1, t2) = (total_sent as f64 + v1, total_received as f64 + v2);
    if t1 > 0.0 && t2 > 0.0 {
        s += &if t2 < t1 {
            format!(" ({:.2} : 1)", t1 / t2)
        } else {
            format!(" (1 : {:.2})", t2 / t1)
        };
    }
    let mut v = text(&s);
    if !(v1 > 0.0 && v2 > 0.0) {
        v = v.with(Tag::string(EC_TAG_STAT_VALUE_ENUM, "not_available"));
    }
    let mut out = vec![v];
    if v1 > 0.0 && v2 > 0.0 {
        out.push(Tag::double(EC_TAG_STAT_NODE_RATIO, v2 / v1));
    }
    if t1 > 0.0 && t2 > 0.0 {
        out.push(Tag::double(EC_TAG_STAT_NODE_RATIO_TOTAL, t2 / t1));
    }
    out
}

/// `CStatTreeItemAverageSpeed`: bytes over the uptime, per second.
fn average_speed(bytes: u64, uptime: u64) -> Vec<Tag> {
    let v = bytes.checked_div(uptime).unwrap_or(0);
    vec![typed(v.min(u32::MAX.into()), EC_VALUE_SPEED)]
}

/// The whole tree, as `CreateECTag` makes it from the root.
pub fn tree(d: &TreeData) -> Tag {
    let mut ids = Ids(0);
    let mut root = ids.node("Statistics", Some("statistics"), Vec::new());
    root.children
        .push(ids.node("Uptime: %s", Some("uptime"), timer(Some(d.uptime))));

    // Transfer: its children sorted by their IDs, highest first.
    let mut transfer = ids.node("Transfer", Some("transfer"), Vec::new());
    let mut uploads = ids.node("Uploads", Some("uploads"), Vec::new());
    let up = [
        (
            "Uploaded Data (Session (Total)): %s",
            "upload_data",
            ul_dl(d.session_sent, d.total_sent),
        ),
        (
            "Total Overhead (Packets): %s",
            "upload_total_overhead",
            packets(0, 0),
        ),
        (
            "File Request Overhead (Packets): %s",
            "upload_filereq_overhead",
            packets(0, 0),
        ),
        (
            "Source Exchange Overhead (Packets): %s",
            "upload_srcexch_overhead",
            packets(0, 0),
        ),
        (
            "Server Overhead (Packets): %s",
            "upload_server_overhead",
            packets(0, 0),
        ),
        (
            "Kad Overhead (Packets): %s",
            "upload_kad_overhead",
            packets(0, 0),
        ),
        (
            "Crypt overhead (UDP): %s",
            "upload_crypt_overhead",
            vec![typed(0, EC_VALUE_BYTES)],
        ),
        (
            "Active Uploads: %s",
            "active_uploads",
            counter(d.active_uploads),
        ),
        (
            "Waiting Uploads: %s",
            "waiting_uploads",
            counter(d.waiting_uploads),
        ),
        (
            "Total successful upload sessions: %s",
            "upload_sessions_success",
            counter(0),
        ),
        (
            "Total failed upload sessions: %s",
            "upload_sessions_failed",
            counter(0),
        ),
    ];
    for (label, key, values) in up {
        uploads.children.push(ids.node(label, Some(key), values));
    }
    // The total upload time, a counter outside the tree, takes an ID.
    ids.next();
    // Averaged over no successful session: hidden.
    let mut avg = ids.node(
        "Average upload time: %s",
        Some("upload_avg_time"),
        Vec::new(),
    );
    avg.visible = false;
    uploads.children.push(avg);

    let mut downloads = ids.node("Downloads", Some("downloads"), Vec::new());
    let down = [
        (
            "Downloaded Data (Session (Total)): %s",
            "download_data",
            ul_dl(d.session_received, d.total_received),
        ),
        (
            "Total Overhead (Packets): %s",
            "download_total_overhead",
            packets(0, 0),
        ),
        (
            "File Request Overhead (Packets): %s",
            "download_filereq_overhead",
            packets(0, 0),
        ),
        (
            "Source Exchange Overhead (Packets): %s",
            "download_srcexch_overhead",
            packets(0, 0),
        ),
        (
            "Server Overhead (Packets): %s",
            "download_server_overhead",
            packets(0, 0),
        ),
        (
            "Kad Overhead (Packets): %s",
            "download_kad_overhead",
            packets(0, 0),
        ),
        (
            "Crypt overhead (UDP): %s",
            "download_crypt_overhead",
            vec![typed(0, EC_VALUE_BYTES)],
        ),
        (
            "Found Sources: %s",
            "found_sources",
            counter(d.found_sources),
        ),
        (
            "Active Downloads (chunks): %s",
            "active_downloads",
            counter(d.active_downloads),
        ),
    ];
    for (label, key, values) in down {
        downloads.children.push(ids.node(label, Some(key), values));
    }
    let ratio_node = ids.node(
        "Session UL:DL Ratio (Total): %s",
        Some("ul_dl_ratio"),
        ratio(
            d.session_sent,
            d.session_received,
            d.total_sent,
            d.total_received,
        ),
    );
    // Sort IDs 3, 2, 1.
    transfer.children = vec![ratio_node, uploads, downloads];
    root.children.push(transfer);

    let mut conn = ids.node("Connection", Some("connection"), Vec::new());
    let items = [
        (
            "Average download rate (Session): %s",
            "avg_download_rate",
            average_speed(d.session_received, d.uptime),
        ),
        (
            "Average upload rate (Session): %s",
            "avg_upload_rate",
            average_speed(d.session_sent, d.uptime),
        ),
        (
            "Max download rate (Session): %s",
            "max_download_rate",
            vec![typed(d.max_download_rate.into(), EC_VALUE_SPEED)],
        ),
        (
            "Max upload rate (Session): %s",
            "max_upload_rate",
            vec![typed(d.max_upload_rate.into(), EC_VALUE_SPEED)],
        ),
        // The first login is not a reconnect.
        (
            "Reconnects: %i",
            "reconnects",
            vec![value(d.logins.saturating_sub(1))],
        ),
        (
            "Time Since First Transfer: %s",
            "since_first_transfer",
            timer(d.since_first_transfer),
        ),
        (
            "Connected To Server Since: %s",
            "connected_since",
            timer(d.connected_since),
        ),
        (
            "Active Connections (estimate): %i",
            "active_connections",
            vec![value(d.connections)],
        ),
        (
            "Max Connection Limit Reached: %s",
            "max_conn_limit_reached",
            vec![text("Never").with(Tag::string(EC_TAG_STAT_VALUE_ENUM, "never"))],
        ),
        (
            "Average Connections (estimate): %g",
            "avg_connections",
            vec![double(d.average_connections)],
        ),
        (
            "Peak Connections (estimate): %i",
            "peak_connections",
            vec![value(d.peak_connections)],
        ),
    ];
    for (label, key, values) in items {
        let mut n = ids.node(label, Some(key), values);
        if key == "since_first_transfer" {
            // stHideIfZero: until the first byte.
            n.visible = d.since_first_transfer.is_some();
        }
        conn.children.push(n);
    }
    root.children.push(conn);

    // Clients: sorted by ID, highest first; "Total" comes last in the
    // making but first in the list.
    let mut clients = ids.node("Clients", Some("clients"), Vec::new());
    let unknown = ids.node("Unknown: %s", Some("clients_unknown"), counter(0));
    let filtered = ids.node("Filtered: %s", Some("clients_filtered"), counter(0));
    let banned = ids.node("Banned: %s", Some("clients_banned"), counter(0));
    let mut keys = ids.node("Kad receiver keys", Some("kad_receiver_keys"), Vec::new());
    for (name, valid, missing) in [
        (
            "Keyword publish",
            "kad_recv_key_keyword_publish_valid",
            "kad_recv_key_keyword_publish_missing",
        ),
        (
            "Source publish",
            "kad_recv_key_source_publish_valid",
            "kad_recv_key_source_publish_missing",
        ),
        (
            "Notes publish",
            "kad_recv_key_notes_publish_valid",
            "kad_recv_key_notes_publish_missing",
        ),
        (
            "Firewall check",
            "kad_recv_key_firewall_check_valid",
            "kad_recv_key_firewall_check_missing",
        ),
        (
            "Firewall check 2",
            "kad_recv_key_firewall_check2_valid",
            "kad_recv_key_firewall_check2_missing",
        ),
        (
            "Find buddy",
            "kad_recv_key_find_buddy_valid",
            "kad_recv_key_find_buddy_missing",
        ),
        (
            "Callback",
            "kad_recv_key_callback_valid",
            "kad_recv_key_callback_missing",
        ),
    ] {
        let mut h = ids.node(name, None, Vec::new());
        h.children
            .push(ids.node("Keys valid: %s", Some(valid), counter(0)));
        h.children
            .push(ids.node("Keys missing: %s", Some(missing), counter(0)));
        keys.children.push(h);
    }
    let total = ids.node(
        "Total: %i Known: %i",
        Some("clients_total"),
        vec![value(0), value(0)],
    );
    clients.children = vec![total, unknown, filtered, banned];
    root.children.push(clients);
    root.children.push(keys);

    let mut servers = ids.node("Servers", Some("servers"), Vec::new());
    let s = [
        (
            "Working Servers: %i",
            "servers_working",
            vec![value(d.servers_total.saturating_sub(d.servers_failed))],
        ),
        (
            "Failed Servers: %i",
            "servers_failed",
            vec![value(d.servers_failed)],
        ),
        ("Total: %s", "servers_total", counter(d.servers_total)),
        ("Deleted Servers: %s", "servers_deleted", counter(0)),
        ("Filtered Servers: %s", "servers_filtered", counter(0)),
        (
            "Users on Working Servers: %llu",
            "servers_users_working",
            vec![value(d.users_on_working)],
        ),
        (
            "Files on Working Servers: %llu",
            "servers_files_working",
            vec![value(d.files_on_working)],
        ),
        (
            "Total Users: %llu",
            "servers_total_users",
            vec![value(d.total_users)],
        ),
        (
            "Total Files: %llu",
            "servers_total_files",
            vec![value(d.total_files)],
        ),
        (
            "Server Occupation: %.2f%%",
            "servers_occupation",
            vec![double(d.server_occupation)],
        ),
    ];
    for (label, key, values) in s {
        servers.children.push(ids.node(label, Some(key), values));
    }
    root.children.push(servers);

    let mut shared = ids.node("Shared Files", Some("shared_files"), Vec::new());
    shared.children.push(ids.node(
        "Number of Shared Files: %s",
        Some("shared_count"),
        counter(d.shared_count),
    ));
    shared.children.push(ids.node(
        "Total size of Shared Files: %s",
        Some("shared_size"),
        vec![typed(d.shared_size, EC_VALUE_BYTES)],
    ));
    let mut avg = ids.node(
        "Average file size: %s",
        Some("shared_avg_size"),
        vec![typed(
            d.shared_size.checked_div(d.shared_count).unwrap_or(0),
            EC_VALUE_BYTES,
        )],
    );
    // Averaged over no file: hidden.
    avg.visible = d.shared_count != 0;
    shared.children.push(avg);
    root.children.push(shared);

    let mut buddies = ids.node("Kad Buddies", Some("kad_buddies"), Vec::new());
    let mut serving = ids.node(
        "Serving Firewalled Nodes",
        Some("kad_buddies_serving"),
        Vec::new(),
    );
    let mut own = ids.node("Our Own Buddy", Some("kad_buddies_own"), Vec::new());
    // `kadBuddyRows`: none of this is kept yet; zero, in its display mode.
    const PLAIN: u8 = 0;
    const TIME: u8 = 1;
    const BYTES: u8 = 2;
    let rows: [(bool, &str, &str, u8); 25] = [
        (true, "kad_buddies_served", "Served Now: %llu", PLAIN),
        (
            true,
            "kad_buddies_requests_received",
            "Buddy Requests Received: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_offers_sent",
            "Buddy Offers Sent: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_requests_refused",
            "Buddy Requests Refused: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_requests_rate_limited",
            "Buddy Requests Over the Rate Limit: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_offers_unused",
            "Unused Buddy Offers: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_served_started",
            "Buddies Served: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_served_timed_out",
            "Served Buddies Timed Out: %llu",
            PLAIN,
        ),
        (true, "kad_buddies_time_served", "Time Served: %s", TIME),
        (
            true,
            "kad_buddies_callbacks_relayed",
            "Callbacks Relayed: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_reasks_relayed",
            "Reasks Relayed: %llu",
            PLAIN,
        ),
        (true, "kad_buddies_relayed_data", "Data Relayed: %s", BYTES),
        (
            true,
            "kad_buddies_callbacks_dropped",
            "Callbacks Dropped: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_reasks_dropped",
            "Reasks Dropped: %llu",
            PLAIN,
        ),
        (
            true,
            "kad_buddies_busiest_minute",
            "Busiest Minute to One Buddy: %s",
            BYTES,
        ),
        (
            false,
            "kad_buddies_own_searches",
            "Buddy Searches: %llu",
            PLAIN,
        ),
        (
            false,
            "kad_buddies_own_requests_sent",
            "Buddy Requests Sent: %llu",
            PLAIN,
        ),
        (
            false,
            "kad_buddies_own_offers_received",
            "Buddy Offers Received: %llu",
            PLAIN,
        ),
        (
            false,
            "kad_buddies_own_connect_failures",
            "Failed Buddy Connections: %llu",
            PLAIN,
        ),
        (
            false,
            "kad_buddies_own_connected",
            "Buddies Connected: %llu",
            PLAIN,
        ),
        (
            false,
            "kad_buddies_own_timed_out",
            "Buddies Timed Out: %llu",
            PLAIN,
        ),
        (
            false,
            "kad_buddies_own_needed",
            "Time a Buddy Was Needed: %s",
            TIME,
        ),
        (
            false,
            "kad_buddies_own_missing",
            "Time Without a Buddy: %s",
            TIME,
        ),
        (
            false,
            "kad_buddies_own_callbacks",
            "Callbacks Received: %llu",
            PLAIN,
        ),
        (
            false,
            "kad_buddies_own_reasks",
            "Reasks Received: %llu",
            PLAIN,
        ),
    ];
    for (is_serving, key, label, mode) in rows {
        let v = match mode {
            TIME => typed(0, EC_VALUE_TIME),
            BYTES => typed(0, EC_VALUE_BYTES),
            _ => value(0),
        };
        let n = ids.node(label, Some(key), vec![v]);
        if is_serving {
            serving.children.push(n);
        } else {
            own.children.push(n);
        }
    }
    buddies.children = vec![serving, own];
    root.children.push(buddies);

    root.tag().expect("the root is visible")
}

/// `EC_OP_GET_STATSTREE`: the tree; for the web interface also the
/// daemon's version and nick. Capping only limits nodes that list peers,
/// which are not kept yet.
pub fn tree_reply(req: &Packet, d: &TreeData, version: &str, nick: &str) -> Packet {
    let mut p = Packet::new(EC_OP_STATSTREE).with(tree(d));
    let detail = req
        .tag(EC_TAG_DETAIL_LEVEL)
        .map_or(EC_DETAIL_FULL, |t| t.as_int() as u8);
    if detail == EC_DETAIL_WEB {
        p = p
            .with(Tag::string(EC_TAG_SERVER_VERSION, version))
            .with(Tag::string(EC_TAG_USER_NICK, nick));
    }
    p
}

/// What the tree shows that the client does not keep: followed a second
/// at a time.
#[derive(Debug, Default)]
pub struct TreeTrack {
    /// Uptime (s) of the first second anything was transferred.
    first_transfer: Option<u64>,
    /// The last 30 seconds' rates, down and up (`CPreciseRateCounter(30000)`).
    window: std::collections::VecDeque<(u64, u64)>,
    max_down: u32,
    max_up: u32,
    peak_connections: u64,
    connection_samples: u64,
    connection_sum: u64,
    /// Server logins this session.
    pub logins: u64,
}

impl TreeTrack {
    /// One second: the rates of the last second, the connections now.
    pub fn sample(&mut self, uptime: u64, down: u64, up: u64, transferred: bool, connections: u64) {
        if transferred && self.first_transfer.is_none() {
            self.first_transfer = Some(uptime);
        }
        self.window.push_back((down, up));
        if self.window.len() > 30 {
            self.window.pop_front();
        }
        let n = self.window.len() as u64;
        let (d, u) = self
            .window
            .iter()
            .fold((0u64, 0u64), |(a, b), (x, y)| (a + x, b + y));
        self.max_down = self.max_down.max((d / n).min(u32::MAX.into()) as u32);
        self.max_up = self.max_up.max((u / n).min(u32::MAX.into()) as u32);
        self.peak_connections = self.peak_connections.max(connections);
        self.connection_samples += 1;
        self.connection_sum += connections;
    }

    /// The tree's data, with what the client gives of the moment.
    pub fn data(&self, now: Moment) -> TreeData {
        TreeData {
            since_first_transfer: self.first_transfer.map(|t| now.uptime.saturating_sub(t)),
            logins: self.logins,
            max_download_rate: self.max_down,
            max_upload_rate: self.max_up,
            peak_connections: self.peak_connections,
            average_connections: if self.connection_samples == 0 {
                0.0
            } else {
                self.connection_sum as f64 / self.connection_samples as f64
            },
            uptime: now.uptime,
            session_sent: now.session_sent,
            session_received: now.session_received,
            total_sent: now.total_sent,
            total_received: now.total_received,
            connected_since: now.connected_since,
            connections: now.connections,
            active_uploads: now.active_uploads,
            waiting_uploads: now.waiting_uploads,
            found_sources: now.found_sources,
            active_downloads: now.active_downloads,
            servers_total: now.servers.len() as u64,
            servers_failed: now.servers.iter().filter(|s| s.failed > 0).count() as u64,
            users_on_working: now
                .servers
                .iter()
                .filter(|s| s.failed == 0)
                .map(|s| u64::from(s.users))
                .sum(),
            files_on_working: now
                .servers
                .iter()
                .filter(|s| s.failed == 0)
                .map(|s| u64::from(s.files))
                .sum(),
            total_users: now.servers.iter().map(|s| u64::from(s.users)).sum(),
            total_files: now.servers.iter().map(|s| u64::from(s.files)).sum(),
            server_occupation: occupation(&now.servers),
            shared_count: now.shared_count,
            shared_size: now.shared_size,
        }
    }
}

/// `CServerList::GetStatus`'s occupation: the users of the servers that
/// say their capacity, over that capacity, in percent.
fn occupation(servers: &[ed2k_formats::server_met::ServerInfo]) -> f64 {
    let (users, max) = servers
        .iter()
        .filter(|s| s.max_users > 0)
        .fold((0u64, 0u64), |(u, m), s| {
            (u + u64::from(s.users), m + u64::from(s.max_users))
        });
    if max == 0 {
        0.0
    } else {
        users as f64 * 100.0 / max as f64
    }
}

/// What the client gives of the moment a tree is asked for.
#[derive(Debug, Default)]
pub struct Moment {
    pub uptime: u64,
    pub session_sent: u64,
    pub session_received: u64,
    pub total_sent: u64,
    pub total_received: u64,
    pub connected_since: Option<u64>,
    pub connections: u64,
    pub active_uploads: u64,
    pub waiting_uploads: u64,
    pub found_sources: u64,
    pub active_downloads: u64,
    pub servers: Vec<ed2k_formats::server_met::ServerInfo>,
    pub shared_count: u64,
    pub shared_size: u64,
}
