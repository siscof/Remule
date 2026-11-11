// SPDX-License-Identifier: GPL-2.0-or-later
//! Dump a nodes.dat and check that it writes back byte for byte.
//!
//!     cargo run -p ed2k-formats --example nodes_dat -- path/to/nodes.dat

use ed2k_formats::nodes_dat::NodesDat;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: nodes_dat <nodes.dat>");
        std::process::exit(2);
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    let dat = match NodesDat::read(&bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "{:?}: {} declared, {} read, {} usable, {} verified, {} trailing bytes",
        dat.format,
        dat.declared_count,
        dat.contacts.len(),
        dat.usable().count(),
        dat.contacts.iter().filter(|c| c.is_verified()).count(),
        dat.trailing.len()
    );
    for c in dat.contacts.iter().take(5) {
        println!(
            "  {} {}:{} tcp {} kad v{}",
            c.id, c.ip, c.udp_port, c.tcp_port, c.version
        );
    }
    let out = dat.write();
    println!(
        "round trip: {}",
        if out == bytes { "identical" } else { "DIFFERS" }
    );
}
