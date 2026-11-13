// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule`: command-line tools for the Rust port of aMule.
//!
//!     remule inspect [DIR] [-v] [--temp-dir DIR] [--write OUT]
//!     remule hash FILE... [-v]
//!     remule search TERMS --server IP:PORT [--obfuscate] [--type T] [--min-size S] ...
//!     remule ping IP:PORT

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ed2k_types::tags::FileType;
use remule_cli::inspect::{self, Outcome};
use remule_cli::server;

#[derive(Parser)]
#[command(
    name = "remule",
    version,
    about = "Command-line tools for remule, a Rust port of aMule"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read every file of an aMule config directory and check that remule
    /// writes each one back byte for byte.
    Inspect {
        /// The config directory (default: ~/.aMule).
        dir: Option<PathBuf>,
        /// List entries, not just counts.
        #[arg(short, long)]
        verbose: bool,
        /// Where the .part.met files are (default: amule.conf's TempDir, else DIR/Temp).
        #[arg(long)]
        temp_dir: Option<PathBuf>,
        /// Write remule's re-encoding of each file into this directory, to diff.
        #[arg(long, value_name = "OUT")]
        write: Option<PathBuf>,
    },
    /// Hash files as aMule does and print their ed2k links (with the AICH root).
    Hash {
        /// The files to hash.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Also list the part hashes.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Log into an eD2k server, search it and print the results.
    Search {
        /// What to look for: words, AND / OR / NOT, (groups), "quoted words".
        query: String,
        /// The server, IP:PORT (with --obfuscate, its obfuscation port if it has one).
        #[arg(long, short)]
        server: SocketAddr,
        /// Use the obfuscated (DH + RC4) handshake.
        #[arg(long)]
        obfuscate: bool,
        /// File type: Audio, Video, Image, Document, Program, Archive, CdImage.
        #[arg(long = "type", value_parser = server::parse_file_type)]
        file_type: Option<FileType>,
        /// Smallest size: bytes, or with K, M, G.
        #[arg(long, value_parser = server::parse_size, default_value = "0")]
        min_size: u64,
        /// Largest size.
        #[arg(long, value_parser = server::parse_size, default_value = "0")]
        max_size: u64,
        /// File extension, without the dot.
        #[arg(long, default_value = "")]
        ext: String,
        /// Ask for more results up to this many times, while the server has more.
        #[arg(long, default_value_t = 0)]
        more: usize,
        /// Print at most this many results.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// The nick to log in with.
        #[arg(long, default_value = "remule")]
        nick: String,
        /// The TCP port to tell the server (nothing listens on it: expect a LowID).
        #[arg(long, default_value_t = 4662)]
        port: u16,
        /// Also print each result's ed2k link.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Ping an eD2k server over UDP (its TCP port + 4) for its user and file counts.
    Ping {
        /// The server, IP:PORT (its TCP port).
        server: SocketAddr,
        /// Seconds to wait for the answer.
        #[arg(long, default_value_t = 5)]
        wait: u64,
    },
}

fn run_async(f: impl std::future::Future<Output = Result<(), String>>) -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("remule: {e}");
            return ExitCode::from(2);
        }
    };
    match rt.block_on(f) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("remule: {e}");
            ExitCode::from(1)
        }
    }
}

fn hash_files(files: &[PathBuf], verbose: bool) -> ExitCode {
    let mut failed = false;
    for path in files {
        let start = std::time::Instant::now();
        let result = std::fs::File::open(path)
            .and_then(|f| ed2k_hash::hash_reader(std::io::BufReader::new(f)));
        let h = match result {
            Ok(h) => h,
            Err(e) => {
                eprintln!("remule: {}: {e}", path.display());
                failed = true;
                continue;
            }
        };
        let secs = start.elapsed().as_secs_f64();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        println!("{}", h.ed2k_link(&name));
        println!("  size {}  ed2k {}", h.size, h.ed2k);
        if let Some(root) = h.aich_root {
            println!("  AICH {root} ({} blocks)", h.aich_blocks.len());
        }
        if secs > 0.0 && h.size > 0 {
            println!(
                "  hashed in {:.2}s, {:.1} MB/s",
                secs,
                h.size as f64 / secs / 1e6
            );
        }
        if verbose {
            for (i, p) in h.part_hashes.iter().enumerate() {
                println!("  part {i:>4}  {p}");
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn default_config_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".aMule"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Hash { files, verbose } => hash_files(&files, verbose),
        Command::Search {
            query,
            server,
            obfuscate,
            file_type,
            min_size,
            max_size,
            ext,
            more,
            limit,
            nick,
            port,
            verbose,
        } => run_async(server::search(server::SearchArgs {
            server,
            query,
            obfuscate,
            nick,
            port,
            file_type,
            min_size,
            max_size,
            extension: ext,
            more,
            limit,
            verbose,
        })),
        Command::Ping { server, wait } => {
            run_async(server::ping(server, Duration::from_secs(wait)))
        }
        Command::Inspect {
            dir,
            verbose,
            temp_dir,
            write,
        } => {
            let Some(dir) = dir.or_else(default_config_dir) else {
                eprintln!("remule: no config directory given and no home directory found");
                return ExitCode::from(2);
            };
            let opts = inspect::Options {
                verbose,
                temp_dir,
                write_to: write,
            };
            let reports = match inspect::inspect(&dir, &opts) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("remule: {e}");
                    return ExitCode::from(2);
                }
            };
            if reports.is_empty() {
                println!("{}: no aMule files found", dir.display());
                return ExitCode::from(1);
            }
            let (mut same, mut differ, mut failed) = (0, 0, 0);
            for r in &reports {
                let mark = match &r.outcome {
                    Outcome::Identical => {
                        same += 1;
                        "ok  "
                    }
                    Outcome::Differs(_) => {
                        differ += 1;
                        "diff"
                    }
                    Outcome::Failed(_) => {
                        failed += 1;
                        "FAIL"
                    }
                };
                println!("[{mark}] {:<24} {}", r.name, r.summary);
                match &r.outcome {
                    Outcome::Differs(why) => println!("       {why}"),
                    Outcome::Failed(e) => println!("       {e}"),
                    Outcome::Identical => {}
                }
                for d in &r.details {
                    println!("       {d}");
                }
            }
            println!(
                "{} files: {same} identical, {differ} different, {failed} unreadable",
                reports.len()
            );
            if failed > 0 || differ > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}
