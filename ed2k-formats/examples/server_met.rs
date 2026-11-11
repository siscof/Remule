// SPDX-License-Identifier: GPL-2.0-or-later
//! Dump a server.met and check that it writes back byte for byte.
//!
//!     cargo run -p ed2k-formats --example server_met -- path/to/server.met

use ed2k_formats::server_met::{ServerInfo, ServerMet};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: server_met <server.met>");
        std::process::exit(2);
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    let met = match ServerMet::read(&bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "version {:#04x}, {} servers{}",
        met.version,
        met.servers.len(),
        if met.legacy_counts {
            " (legacy tag counts)"
        } else {
            ""
        }
    );
    for rec in &met.servers {
        let s = ServerInfo::from_record(rec);
        println!(
            "{:>15}:{:<5}  users {:>7}  files {:>9}  {:<7} {} ",
            rec.ip.to_string(),
            s.port,
            s.users,
            s.files,
            s.version,
            s.name
        );
    }
    let out = met.write();
    if out == bytes {
        println!("round trip: identical ({} bytes)", out.len());
    } else {
        let at = out
            .iter()
            .zip(&bytes)
            .position(|(a, b)| a != b)
            .unwrap_or(out.len().min(bytes.len()));
        println!(
            "round trip: differs at byte {at} (read {} bytes, wrote {})",
            bytes.len(),
            out.len()
        );
        // Semantically the same? Re-read what was written.
        let again = ServerMet::read(&out).expect("our own output reads back");
        let same = again
            .servers
            .iter()
            .zip(&met.servers)
            .all(|(a, b)| ServerInfo::from_record(a) == ServerInfo::from_record(b));
        println!(
            "re-read: {} servers, same information: {same}",
            again.servers.len()
        );
    }
}
