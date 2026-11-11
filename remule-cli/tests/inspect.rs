// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule inspect` on a generated aMule config directory.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use ed2k_formats::{canceled_met, emfriends_met, known_met, server_met};
use ed2k_types::Md4Hash;
use remule_cli::inspect::{inspect, Options, Outcome};

/// A fresh, empty directory under the target dir (no temp-file crate needed).
fn fresh_dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

const AMULE_CONF: &str = "[eMule]\nNick=remule tester\nPort=4662\nUDPPort=4672\nMaxUpload=100\n\n[ExternalConnect]\nAcceptExternalConnections=1\nECPort=4712\n";

fn write_config(dir: &Path) {
    fs::write(dir.join("amule.conf"), AMULE_CONF).unwrap();

    let srv = server_met::ServerInfo {
        ip: Some(Ipv4Addr::new(176, 123, 5, 89)),
        port: 4725,
        name: "eMule Sunrise".into(),
        version: "17.15".into(),
        users: 54_902,
        ..Default::default()
    };
    let met = server_met::ServerMet {
        version: server_met::VERSION,
        servers: vec![srv.to_record()],
        legacy_counts: false,
    };
    fs::write(dir.join("server.met"), met.write()).unwrap();

    let file = known_met::KnownFile {
        date: 1_700_000_000,
        hash: Md4Hash([7; 16]),
        name: "a small file.txt".into(),
        size: 1234,
        up_priority: known_met::priority::NORMAL,
        last_seen: 1_700_000_000,
        ..Default::default()
    };
    let known = known_met::KnownMet {
        version: known_met::VERSION,
        records: vec![file.to_record()],
        skipped: vec![],
    };
    fs::write(dir.join("known.met"), known.write()).unwrap();

    let canceled =
        canceled_met::CanceledMet::from_set(&BTreeSet::from([Md4Hash([1; 16]), Md4Hash([2; 16])]));
    fs::write(dir.join("canceled.met"), canceled.write()).unwrap();

    let friend = emfriends_met::Friend {
        user_hash: Md4Hash([9; 16]),
        name: "a friend".into(),
        ..Default::default()
    };
    let friends = emfriends_met::EmfriendsMet {
        version: emfriends_met::VERSION,
        friends: vec![friend.to_record()],
    };
    fs::write(dir.join("emfriends.met"), friends.write()).unwrap();

    fs::write(
        dir.join("ipfilter.dat"),
        "1.2.3.0 - 1.2.3.255 , 100 , some range\n# a comment\nnot a rule\n",
    )
    .unwrap();
    fs::write(
        dir.join("addresses.dat"),
        "https://upd.emule-security.org/server.met\n",
    )
    .unwrap();
}

#[test]
fn every_file_of_an_amule_config_reads_and_writes_back_identically() {
    let dir = fresh_dir("inspect-ok");
    write_config(&dir);
    let out = fresh_dir("inspect-ok-out");
    let opts = Options {
        verbose: true,
        temp_dir: None,
        write_to: Some(out.clone()),
    };
    let reports = inspect(&dir, &opts).unwrap();

    let names: Vec<&str> = reports.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "amule.conf",
            "server.met",
            "known.met",
            "ipfilter.dat",
            "addresses.dat",
            "canceled.met",
            "emfriends.met"
        ]
    );
    for r in &reports {
        assert_eq!(r.outcome, Outcome::Identical, "{}: {}", r.name, r.summary);
        // --write produced the same bytes.
        assert_eq!(
            fs::read(out.join(&r.name)).unwrap(),
            fs::read(&r.path).unwrap(),
            "{}",
            r.name
        );
    }
    let by_name = |n: &str| reports.iter().find(|r| r.name == n).unwrap();
    assert!(by_name("amule.conf").summary.contains("\"remule tester\""));
    assert!(by_name("amule.conf")
        .summary
        .contains("TCP 4662 / UDP 4672"));
    assert_eq!(by_name("server.met").summary, "1 servers");
    assert!(by_name("server.met").details[0].contains("eMule Sunrise"));
    assert!(by_name("known.met")
        .summary
        .starts_with("1 files, 1234 bytes"));
    assert_eq!(by_name("canceled.met").summary, "2 hashes (2 distinct)");
    assert!(by_name("ipfilter.dat").summary.contains("1 bad lines"));
}

#[test]
fn a_corrupt_file_is_reported_and_the_others_still_are() {
    let dir = fresh_dir("inspect-corrupt");
    write_config(&dir);
    // A server.met with a version byte aMule refuses.
    fs::write(dir.join("server.met"), [0x42, 0, 0, 0, 0]).unwrap();
    let reports = inspect(&dir, &Options::default()).unwrap();
    let srv = reports.iter().find(|r| r.name == "server.met").unwrap();
    assert!(
        matches!(&srv.outcome, Outcome::Failed(e) if e.contains("0x42")),
        "{:?}",
        srv.outcome
    );
    assert_eq!(
        reports
            .iter()
            .filter(|r| r.outcome == Outcome::Identical)
            .count(),
        reports.len() - 1
    );
}

#[test]
fn missing_files_are_skipped_and_a_missing_dir_is_an_error() {
    let dir = fresh_dir("inspect-empty");
    assert!(inspect(&dir, &Options::default()).unwrap().is_empty());
    assert!(inspect(&dir.join("nope"), &Options::default()).is_err());
}
