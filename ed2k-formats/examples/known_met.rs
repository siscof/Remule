// SPDX-License-Identifier: GPL-2.0-or-later
//! Dump a known.met and check that it writes back byte for byte.
//!
//!     cargo run -p ed2k-formats --example known_met -- ~/.aMule/known.met

use ed2k_formats::known_met::{KnownFile, KnownMet};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: known_met <known.met>");
        std::process::exit(2);
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    let met = match KnownMet::read(&bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "version {:#04x}, {} files, {} skipped",
        met.version,
        met.records.len(),
        met.skipped.len()
    );
    for (i, why) in &met.skipped {
        println!("  skipped record #{i}: {why:?}");
    }
    for rec in &met.records {
        match KnownFile::from_record(rec) {
            Ok(f) => println!(
                "{}  {:>14}  up {:>14}  req {:>5}  acc {:>5}  {}",
                f.hash,
                f.size,
                f.all_time_transferred,
                f.all_time_requests,
                f.all_time_accepts,
                f.name
            ),
            Err(t) => println!("{}  (tag {t:?} has the wrong type)", rec.hash),
        }
    }
    let out = met.write();
    if out == bytes {
        println!("round trip: identical ({} bytes)", out.len());
    } else {
        // Skipped records are dropped, as aMule drops them on its next save.
        println!(
            "round trip: differs (read {} bytes, wrote {}){}",
            bytes.len(),
            out.len(),
            if met.skipped.is_empty() {
                ""
            } else {
                "; skipped records are not written back"
            }
        );
    }
}
