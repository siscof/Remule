// SPDX-License-Identifier: GPL-2.0-or-later
//! `remuled`: run the client from an aMule config directory until stopped
//! (Ctrl-C, or SIGTERM on Unix), then save everything.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tracing::{error, info, warn};

/// The remule daemon: an aMule-compatible eD2k/Kad client run from an
/// aMule config directory. Stop aMule first: both must not use the same
/// directory at once.
#[derive(Parser, Debug)]
#[command(name = "remuled", version)]
struct Args {
    /// The aMule config directory (default: ~/.aMule, or %APPDATA%\aMule
    /// on Windows)
    #[arg(short = 'c', long = "config-dir")]
    config_dir: Option<PathBuf>,
    /// Stop after this many seconds (0: run until stopped)
    #[arg(long, default_value_t = 0)]
    duration: u64,
}

fn default_config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("aMule"))
    } else {
        std::env::var_os("HOME").map(|d| PathBuf::from(d).join(".aMule"))
    }
}

/// Ctrl-C, SIGTERM on Unix, or the time limit.
async fn stopped(duration: u64) {
    let limit = async {
        if duration > 0 {
            tokio::time::sleep(Duration::from_secs(duration)).await;
            info!("time is up: saving");
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
                info!("terminated: saving");
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("interrupted: saving"),
        _ = term => {}
        _ = limit => {}
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
    let args = Args::parse();
    let Some(dir) = args.config_dir.or_else(default_config_dir) else {
        error!("no config directory: give --config-dir");
        return std::process::ExitCode::from(2);
    };
    // What amuled fetches before the networks start: a nodes.dat, server lists.
    if dir.is_dir() {
        let conf = std::fs::read(dir.join("amule.conf"))
            .map(|b| ed2k_formats::amule_conf::ConfFile::from_bytes(&b))
            .unwrap_or_else(|_| ed2k_formats::amule_conf::ConfFile::new());
        let mut notes = Vec::new();
        let plan = remuled::bootstrap::plan(&dir, &conf, &mut notes);
        for n in &notes {
            warn!("{n}");
        }
        remuled::bootstrap::run(&dir, &plan).await;
    }
    let loaded = match remuled::config::load(&dir) {
        Ok(l) => l,
        Err(e) => {
            error!("{e}");
            return std::process::ExitCode::from(2);
        }
    };
    for n in &loaded.info {
        info!("{n}");
    }
    for n in &loaded.notes {
        warn!("{n}");
    }
    let c = &loaded.client;
    info!(
        "{}: {} as {}, TCP {}, {} servers, Kad {}, {} shared folders",
        dir.display(),
        c.nick,
        c.user_hash,
        c.tcp_port,
        c.servers.len(),
        if c.kad.is_some() { "on" } else { "off" },
        c.share.len()
    );
    let files = if loaded.client.temp.is_dir() {
        match remuled::client::existing_downloads(&loaded.client.temp) {
            Ok(f) => f,
            Err(e) => {
                error!("{e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };
    for f in &files {
        info!(
            "resuming {} ({} of {})",
            f.name(),
            remuled::client::human(f.completed()),
            remuled::client::human(f.size())
        );
    }
    match remuled::client::run(loaded.client, files, Vec::new(), stopped(args.duration)).await {
        Ok(_) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
