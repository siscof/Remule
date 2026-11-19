// SPDX-License-Identifier: GPL-2.0-or-later
//! The statistics tree: aMule's nodes in aMule's order with aMule's IDs,
//! the values and their types, what is hidden when, and what is followed
//! a second at a time.

use ed2k_formats::server_met::ServerInfo;
use remule_ec::codes::*;
use remule_ec::{Packet, Tag};

use crate::ec_stats::{tree, tree_reply, Moment, TreeData, TreeTrack};

fn find<'a>(t: &'a Tag, key: &str) -> Option<&'a Tag> {
    if t.child(EC_TAG_STAT_NODE_KEY).map(Tag::as_str).as_deref() == Some(key) {
        return Some(t);
    }
    t.children
        .iter()
        .filter(|c| c.name == EC_TAG_STATTREE_NODE)
        .find_map(|c| find(c, key))
}

fn nodes(t: &Tag) -> Vec<&Tag> {
    t.children
        .iter()
        .filter(|c| c.name == EC_TAG_STATTREE_NODE)
        .collect()
}

fn labels(t: &Tag) -> Vec<String> {
    nodes(t).iter().map(|n| n.as_str()).collect()
}

fn id(t: &Tag) -> u64 {
    t.child_int(EC_TAG_STATTREE_NODEID)
}

fn val(t: &Tag) -> &Tag {
    t.child(EC_TAG_STAT_NODE_VALUE).expect("a value")
}

#[test]
fn the_tree_is_amules_nodes_in_amules_order() {
    let t = tree(&TreeData::default());
    assert_eq!(
        (t.name, t.as_str()),
        (EC_TAG_STATTREE_NODE, "Statistics".into())
    );
    assert_eq!(id(&t), 1);
    assert_eq!(
        labels(&t),
        [
            "Uptime: %s",
            "Transfer",
            "Connection",
            "Clients",
            "Kad receiver keys",
            "Servers",
            "Shared Files",
            "Kad Buddies"
        ]
    );
    // Transfer's children by their sort IDs, highest first.
    let transfer = find(&t, "transfer").unwrap();
    assert_eq!(
        labels(transfer),
        ["Session UL:DL Ratio (Total): %s", "Uploads", "Downloads"]
    );
    // IDs as aMule hands them out, in the order it makes the nodes (the
    // total upload time, outside the tree, takes 16).
    for (key, want) in [
        ("uptime", 2),
        ("uploads", 4),
        ("upload_data", 5),
        ("upload_sessions_failed", 15),
        ("downloads", 18),
        ("active_downloads", 27),
        ("ul_dl_ratio", 28),
        ("connection", 29),
        ("peak_connections", 40),
        ("clients", 41),
        ("clients_banned", 44),
        ("kad_receiver_keys", 45),
        ("kad_recv_key_callback_missing", 66),
        ("clients_total", 67),
        ("servers", 68),
        ("servers_occupation", 78),
        ("shared_size", 81),
        ("kad_buddies", 83),
        ("kad_buddies_own_reasks", 110),
    ] {
        assert_eq!(
            id(find(&t, key).unwrap_or_else(|| panic!("{key}"))),
            want,
            "{key}"
        );
    }
    let clients = find(&t, "clients").unwrap();
    assert_eq!(
        labels(clients),
        [
            "Total: %i Known: %i",
            "Unknown: %s",
            "Filtered: %s",
            "Banned: %s"
        ]
    );
    assert_eq!(nodes(find(&t, "kad_receiver_keys").unwrap()).len(), 7);
    assert_eq!(nodes(find(&t, "kad_buddies_serving").unwrap()).len(), 15);
    assert_eq!(nodes(find(&t, "kad_buddies_own").unwrap()).len(), 10);
    // Averages over nothing, and the time since a first transfer that
    // never happened, are hidden.
    for hidden in ["upload_avg_time", "since_first_transfer", "shared_avg_size"] {
        assert!(find(&t, hidden).is_none(), "{hidden}");
    }
}

fn typ(v: &Tag) -> Option<u64> {
    v.child(EC_TAG_STAT_VALUE_TYPE).map(Tag::as_int)
}

#[test]
fn values_carry_their_types() {
    let d = TreeData {
        uptime: 100,
        session_sent: 1_000,
        session_received: 3_000,
        total_sent: 1_000,
        total_received: 3_000,
        since_first_transfer: Some(40),
        connected_since: Some(90),
        logins: 3,
        max_download_rate: 2048,
        connections: 7,
        peak_connections: 9,
        average_connections: 4.5,
        servers_total: 4,
        servers_failed: 1,
        users_on_working: 500,
        server_occupation: 12.5,
        shared_count: 2,
        shared_size: 3_000,
        ..Default::default()
    };
    let t = tree(&d);
    let v = val(find(&t, "uptime").unwrap());
    assert_eq!((v.as_int(), typ(v)), (100, Some(EC_VALUE_TIME.into())));
    // Session bytes, with every session's beside them.
    let v = val(find(&t, "download_data").unwrap());
    assert_eq!((v.as_int(), typ(v)), (3_000, Some(EC_VALUE_BYTES.into())));
    assert_eq!(v.child(EC_TAG_STAT_NODE_VALUE).unwrap().as_int(), 3_000);
    // Packets: bytes, with the count as a short number.
    let v = val(find(&t, "upload_total_overhead").unwrap());
    assert_eq!(
        typ(v.child(EC_TAG_STAT_NODE_VALUE).unwrap()),
        Some(EC_VALUE_ISHORT.into())
    );
    // The ratio: text, and the raw numbers.
    let r = find(&t, "ul_dl_ratio").unwrap();
    assert_eq!(val(r).as_str(), "1 : 3.00 (1 : 3.00)");
    assert_eq!(r.child(EC_TAG_STAT_NODE_RATIO).unwrap().as_double(), 3.0);
    assert_eq!(
        r.child(EC_TAG_STAT_NODE_RATIO_TOTAL).unwrap().as_double(),
        3.0
    );
    // Speeds: the session average, and the highest.
    let v = val(find(&t, "avg_download_rate").unwrap());
    assert_eq!((v.as_int(), typ(v)), (30, Some(EC_VALUE_SPEED.into())));
    assert_eq!(val(find(&t, "max_download_rate").unwrap()).as_int(), 2048);
    // The first login is not a reconnect.
    let v = val(find(&t, "reconnects").unwrap());
    assert_eq!((v.as_int(), typ(v)), (2, None));
    assert_eq!(val(find(&t, "since_first_transfer").unwrap()).as_int(), 40);
    assert_eq!(val(find(&t, "connected_since").unwrap()).as_int(), 90);
    let v = val(find(&t, "max_conn_limit_reached").unwrap());
    assert_eq!(v.as_str(), "Never");
    assert_eq!(v.child_str(EC_TAG_STAT_VALUE_ENUM), "never");
    let v = val(find(&t, "avg_connections").unwrap());
    assert_eq!((v.as_double(), typ(v)), (4.5, Some(EC_VALUE_DOUBLE.into())));
    assert_eq!(val(find(&t, "servers_working").unwrap()).as_int(), 3);
    assert_eq!(val(find(&t, "servers_failed").unwrap()).as_int(), 1);
    let v = val(find(&t, "servers_total").unwrap());
    assert_eq!((v.as_int(), typ(v)), (4, Some(EC_VALUE_ISTRING.into())));
    assert_eq!(
        val(find(&t, "servers_occupation").unwrap()).as_double(),
        12.5
    );
    let v = val(find(&t, "shared_avg_size").unwrap());
    assert_eq!((v.as_int(), typ(v)), (1_500, Some(EC_VALUE_BYTES.into())));
    // Two plain values: total, known.
    let total = find(&t, "clients_total").unwrap();
    assert_eq!(
        total
            .children
            .iter()
            .filter(|c| c.name == EC_TAG_STAT_NODE_VALUE)
            .count(),
        2
    );
    let v = val(find(&t, "kad_buddies_time_served").unwrap());
    assert_eq!(typ(v), Some(EC_VALUE_TIME.into()));

    // Nothing transferred: no ratio, said so.
    let t = tree(&TreeData::default());
    let r = find(&t, "ul_dl_ratio").unwrap();
    assert_eq!(val(r).as_str(), "Not available");
    assert_eq!(val(r).child_str(EC_TAG_STAT_VALUE_ENUM), "not_available");
    assert!(r.child(EC_TAG_STAT_NODE_RATIO).is_none());
    // Uploading more than downloading.
    let t = tree(&TreeData {
        session_sent: 500,
        session_received: 100,
        ..Default::default()
    });
    assert_eq!(
        val(find(&t, "ul_dl_ratio").unwrap()).as_str(),
        "5.00 : 1 (5.00 : 1)"
    );
}

#[test]
fn the_tracker_follows_rates_connections_and_the_first_transfer() {
    let mut tr = TreeTrack::default();
    tr.sample(1, 0, 0, false, 2);
    // A burst of one second: its 30-second average is what counts.
    tr.sample(2, 3_000, 0, true, 6);
    for s in 3..=31 {
        tr.sample(s, 0, 0, true, 4);
    }
    tr.logins = 1;
    let servers = vec![
        ServerInfo {
            users: 100,
            max_users: 400,
            files: 10,
            ..Default::default()
        },
        ServerInfo {
            users: 50,
            failed: 2,
            files: 5,
            ..Default::default()
        },
        // Failed, but its capacity still counts.
        ServerInfo {
            users: 100,
            max_users: 100,
            failed: 1,
            ..Default::default()
        },
    ];
    let d = tr.data(Moment {
        uptime: 31,
        servers,
        ..Default::default()
    });
    assert_eq!(d.max_download_rate, 3_000 / 2);
    assert_eq!(d.since_first_transfer, Some(29));
    assert_eq!(d.peak_connections, 6);
    assert_eq!(d.average_connections, (2 + 6 + 29 * 4) as f64 / 31.0);
    assert_eq!(d.logins, 1);
    assert_eq!((d.servers_total, d.servers_failed), (3, 2));
    assert_eq!((d.users_on_working, d.total_users), (100, 250));
    assert_eq!((d.files_on_working, d.total_files), (10, 15));
    // The servers that say their capacity count, failed or not.
    assert_eq!(d.server_occupation, 40.0);
}

#[test]
fn the_web_detail_adds_the_version_and_nick() {
    let req = Packet::new(EC_OP_GET_STATSTREE).with(Tag::int(EC_TAG_STATTREE_CAPPING, 5));
    let r = tree_reply(&req, &TreeData::default(), "remuled 1", "me");
    assert_eq!(r.opcode, EC_OP_STATSTREE);
    assert_eq!(r.tags.len(), 1);
    let r = tree_reply(
        &req.clone().with_detail(EC_DETAIL_WEB),
        &TreeData::default(),
        "remuled 1",
        "me",
    );
    assert_eq!(r.tag(EC_TAG_SERVER_VERSION).unwrap().as_str(), "remuled 1");
    assert_eq!(r.tag(EC_TAG_USER_NICK).unwrap().as_str(), "me");
}
