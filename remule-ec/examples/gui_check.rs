// SPDX-License-Identifier: GPL-2.0-or-later
//! MIGRATION_PLAN.md 13.M: what remule-gui's EC worker asks of a daemon,
//! through the same `remule_ec::model` calls, against any running daemon,
//! `amuled` or `remuled`, logged into `scripts/interop/fake_ed2k_server.py`.
//!
//!     cargo run -p remule-ec --example gui_check -- HOST PORT PASSWORD INCOMING_DIR [--shutdown]
//!
//! The status bar's connection and HighID, the server list, a local search
//! to its end and its result downloaded, a link added, paused, resumed, set
//! to high and cancelled, a file put in the incoming folder found after a
//! reload and its priority set, the log; with `--shutdown`, the daemon
//! stopped. Each reply is read as the GUI reads it. Prints a line a step;
//! exits with 1 at the first step that fails.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use remule_ec::codes::*;
use remule_ec::model::{priority_text, PartFileCmd, SearchKind, SearchParams};
use remule_ec::{srp, Client, ConnectOptions, Packet};

/// What `fake_ed2k_server.py` finds for every search.
const RESULT_NAME: &str = "remule interop result.iso";
const RESULT_SIZE: u64 = 7_340_032;
const LINK_NAME: &str = "GUI Check.iso";

type R<T> = Result<T, String>;

fn e(err: remule_ec::Error) -> String {
    err.to_string()
}

/// Ask until `ok` holds, at most `secs` seconds.
fn until(c: &mut Client, secs: u64, what: &str, ok: &dyn Fn(&mut Client) -> R<bool>) -> R<()> {
    for _ in 0..secs * 4 {
        if ok(c)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("never: {what}"))
}

fn check(cond: bool, what: impl Into<String>) -> R<()> {
    if cond {
        Ok(())
    } else {
        Err(what.into())
    }
}

fn run(host: &str, port: u16, password: &str, incoming: &Path, shutdown: bool) -> R<()> {
    // As the GUI connects: its own name, nothing more advertised.
    let mut opts = ConnectOptions::new(host, port, srp::password_digest(password));
    opts.client_name = "remule-gui".into();
    let mut c = Client::connect(&opts).map_err(e)?;
    println!("ok: logged in to {}", c.info().version);

    // The status bar: connected to the server, with a HighID.
    until(&mut c, 60, "connected to the server", &|c| {
        Ok(c.stats().map_err(e)?.conn.ed2k_connected())
    })?;
    let s = c.stats().map_err(e)?;
    check(!s.conn.low_id(), "a LowID")?;
    let server = s.conn.server.clone().ok_or("no server in the status")?;
    check(
        server.ip == [127, 0, 0, 1],
        format!("server {:?}", server.ip),
    )?;
    // The free space the Downloads and Shared panels show.
    check(
        s.temp_free.is_some() && s.incoming_free.is_some(),
        "no free disk space in the statistics",
    )?;
    println!("ok: connected to {} with a HighID", server.address());

    // Networks: the server list.
    let servers = c.servers().map_err(e)?;
    check(servers.len() == 1, format!("{} servers", servers.len()))?;
    check(servers[0].ip == [127, 0, 0, 1], "the server's address")?;
    println!("ok: the server list: {}", servers[0].name);

    // Searches: a local search, its progress until done, its result.
    let note = c
        .search_start(
            SearchKind::Local,
            &SearchParams {
                text: "interop".into(),
                ..Default::default()
            },
        )
        .map_err(e)?;
    println!("ok: search started: {note}");
    until(&mut c, 30, "the search finished", &|c| {
        Ok(c.search_progress().map_err(e)?.finished)
    })?;
    let p = c.search_progress().map_err(e)?;
    check(
        p.percent == Some(100) && p.result_count == 1,
        format!("progress {:?}, {} results", p.percent, p.result_count),
    )?;
    let results = c.search_results().map_err(e)?;
    let found = results
        .iter()
        .find(|r| r.name == RESULT_NAME)
        .ok_or_else(|| format!("no {RESULT_NAME} in {} results", results.len()))?
        .clone();
    check(
        found.size == RESULT_SIZE,
        format!("result size {}", found.size),
    )?;
    // Nothing shown for a file not had yet, as in aMule's list.
    check(found.status_text().is_empty(), found.status_text())?;
    println!("ok: the search finished with {RESULT_NAME}");

    // Downloaded: in the transfers list, and the result says so.
    c.download_search_results(&[found.hash], 0).map_err(e)?;
    until(&mut c, 10, "the result in the queue", &|c| {
        Ok(c.download_queue()
            .map_err(e)?
            .iter()
            .any(|f| f.name == RESULT_NAME))
    })?;
    until(&mut c, 10, "the result marked as downloading", &|c| {
        Ok(c.search_results()
            .map_err(e)?
            .iter()
            .any(|r| r.hash == found.hash && r.status_text() == "Downloading"))
    })?;
    println!("ok: the result is downloading");

    // Transfers: a link added, paused, resumed, set to high and cancelled.
    let link = format!(
        "ed2k://|file|{}|5000000|{}|/",
        LINK_NAME.replace(' ', "%20"),
        "AB".repeat(16)
    );
    c.add_links(&[link]).map_err(e)?;
    let file = |c: &mut Client| -> R<Option<remule_ec::model::PartFile>> {
        Ok(c.download_queue()
            .map_err(e)?
            .into_iter()
            .find(|f| f.name == LINK_NAME))
    };
    until(&mut c, 10, "the link in the queue", &|c| {
        Ok(file(c)?.is_some())
    })?;
    let f = file(&mut c)?.unwrap();
    check(f.size == 5_000_000, format!("link size {}", f.size))?;
    check(
        f.ed2k_link.contains("GUI%20Check.iso"),
        format!("its link: {}", f.ed2k_link),
    )?;
    let target = [(f.hash, f.ecid)];
    c.partfile_cmd(PartFileCmd::Pause, &target).map_err(e)?;
    until(&mut c, 10, "paused", &|c| {
        Ok(file(c)?.is_some_and(|f| f.status_text() == "Paused"))
    })?;
    c.partfile_cmd(PartFileCmd::Resume, &target).map_err(e)?;
    until(&mut c, 10, "resumed", &|c| {
        Ok(file(c)?.is_some_and(|f| f.status_text() != "Paused"))
    })?;
    c.set_download_priority(&target, 2).map_err(e)?;
    until(&mut c, 10, "high priority", &|c| {
        Ok(file(c)?.is_some_and(|f| priority_text(f.priority) == "High"))
    })?;
    c.partfile_cmd(PartFileCmd::Cancel, &target).map_err(e)?;
    until(&mut c, 10, "cancelled", &|c| Ok(file(c)?.is_none()))?;
    println!("ok: a link added, paused, resumed, set to high and cancelled");

    // Shared files: a file in the incoming folder, after a reload.
    let name = "gui check shared.bin";
    std::fs::write(incoming.join(name), vec![7u8; 4096])
        .map_err(|err| format!("writing into {}: {err}", incoming.display()))?;
    c.shared_reload().map_err(e)?;
    let shared = |c: &mut Client| -> R<Option<remule_ec::model::SharedFile>> {
        Ok(c.shared_files()
            .map_err(e)?
            .into_iter()
            .find(|f| f.name == name))
    };
    until(&mut c, 60, "the new file shared", &|c| {
        Ok(shared(c)?.is_some())
    })?;
    let sf = shared(&mut c)?.unwrap();
    check(sf.size == 4096, format!("shared size {}", sf.size))?;
    c.set_shared_priority(&[sf.hash], 3).map_err(e)?;
    until(&mut c, 10, "the shared file's priority", &|c| {
        Ok(shared(c)?.is_some_and(|f| f.priority == 3))
    })?;
    println!("ok: a new file shared after a reload, its priority set");

    // The log, as the Networks page asks for it.
    let log = c.log().map_err(e)?;
    check(!log.trim().is_empty(), "an empty log")?;
    println!("ok: the log ({} lines)", log.lines().count());

    if shutdown {
        let reply = c.request(&Packet::new(EC_OP_SHUTDOWN)).map_err(e)?;
        check(
            reply.opcode == EC_OP_NOOP,
            format!("shutdown: {:#x}", reply.opcode),
        )?;
        println!("ok: shutdown acknowledged");
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (host, port, password, incoming) = match args.as_slice() {
        [h, p, pw, dir, ..] => match p.parse::<u16>() {
            Ok(p) => (h.as_str(), p, pw.as_str(), Path::new(dir)),
            Err(_) => {
                eprintln!("bad port {p}");
                return ExitCode::from(2);
            }
        },
        _ => {
            eprintln!("usage: gui_check HOST PORT PASSWORD INCOMING_DIR [--shutdown]");
            return ExitCode::from(2);
        }
    };
    let shutdown = args.iter().any(|a| a == "--shutdown");
    match run(host, port, password, incoming, shutdown) {
        Ok(()) => {
            println!("PASS: remule-gui's requests against {host}:{port}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!("FAIL: {err}");
            ExitCode::FAILURE
        }
    }
}
