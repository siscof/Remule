// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule`: command-line tools for the Rust port of aMule.
//!
//!     remule inspect [DIR] [-v] [--temp-dir DIR] [--write OUT]
//!     remule hash FILE... [-v]
//!     remule search TERMS --server IP:PORT [--obfuscate] [--type T] [--min-size S] ...
//!     remule ping IP:PORT
//!     remule kad [--nodes nodes.dat] [--search TERMS]... [--source HASH:SIZE]... [--duration S]
//!     remule share DIR... [--config DIR] [--links]
//!     remule download [LINK]... --temp DIR --incoming DIR [--server IP:PORT]... [--kad DIR] [--share DIR]...

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ed2k_types::tags::FileType;
use remule_cli::inspect::{self, Outcome};
use remule_cli::{download, kad, server, share};

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
    /// Join Kad from a nodes.dat, keep a routing table, run keyword and source searches.
    Kad {
        /// The nodes.dat to start from (default: DIR/nodes.dat).
        #[arg(long)]
        nodes: Option<PathBuf>,
        /// Where to keep nodes.dat and preferencesKad.dat between runs.
        #[arg(long, default_value = "remule-kad")]
        dir: PathBuf,
        /// The UDP port to use.
        #[arg(long, default_value_t = 4672)]
        port: u16,
        /// Also bootstrap from this node (IP:PORT).
        #[arg(long)]
        bootstrap: Vec<std::net::SocketAddrV4>,
        /// Search for these words (the first word of 3+ letters, or a longer one, is the keyword).
        #[arg(long = "search")]
        searches: Vec<String>,
        /// Look for sources of a file: HASH:SIZE.
        #[arg(long = "source", value_parser = kad::parse_source)]
        sources: Vec<(ed2k_types::Md4Hash, u64)>,
        /// Seconds to stay up (default: until the searches are done).
        #[arg(long, default_value_t = 0)]
        duration: u64,
        /// Seconds between status lines.
        #[arg(long, default_value_t = 30)]
        status_every: u64,
        /// Seconds after connecting before searching.
        #[arg(long, default_value_t = 20)]
        warmup: u64,
        /// Print at most this many results per search.
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// Also print each result's ed2k link.
        #[arg(short, long)]
        verbose: bool,
        /// The UDP port is reachable from outside: store what others publish.
        #[arg(long)]
        reachable: bool,
        /// Take contacts on LAN addresses (aMule's FilterLanIPs off).
        #[arg(long)]
        allow_lan: bool,
    },
    /// Download files from ed2k links, with sources from servers and Kad. Downloads
    /// already in the temp directory (remule's or aMule's) are resumed.
    Download {
        /// ed2k://|file|NAME|SIZE|HASH|/ links (none: just resume the temp directory).
        links: Vec<String>,
        /// Where the .part / .part.met files are (aMule's Temp directory works too).
        #[arg(long, default_value = "remule-temp")]
        temp: PathBuf,
        /// Where finished files go.
        #[arg(long, default_value = "remule-incoming")]
        incoming: PathBuf,
        /// An eD2k server to ask for sources (the first that logs in is used).
        #[arg(long = "server", short)]
        servers: Vec<SocketAddr>,
        /// Connect to the server obfuscated.
        #[arg(long)]
        obfuscate: bool,
        /// Also find sources on Kad, keeping its state in this directory.
        #[arg(long)]
        kad: Option<PathBuf>,
        /// The nodes.dat to join Kad from (default: the --kad directory's).
        #[arg(long)]
        nodes: Option<PathBuf>,
        /// Also bootstrap Kad from this node (IP:PORT).
        #[arg(long)]
        kad_bootstrap: Vec<std::net::SocketAddrV4>,
        /// TCP port: told to peers and servers, and listened on for callbacks.
        #[arg(long, default_value_t = 4662)]
        port: u16,
        /// Kad's UDP port.
        #[arg(long, default_value_t = 4672)]
        udp_port: u16,
        #[arg(long, default_value = "remule")]
        nick: String,
        /// Seconds to run (default: until every file is complete).
        #[arg(long, default_value_t = 0)]
        duration: u64,
        /// Seconds between progress lines.
        #[arg(long, default_value_t = 30)]
        status_every: u64,
        /// Peer connections at once.
        #[arg(long, default_value_t = 50)]
        max_connections: usize,
        /// Download limit in KiB/s (0: none).
        #[arg(long, default_value_t = 0)]
        max_download: u32,
        /// Upload limit in KiB/s (0: none).
        #[arg(long, default_value_t = 0)]
        max_upload: u32,
        /// Share this directory (repeat for more); finished downloads are shared too,
        /// and the client keeps running for others to download.
        #[arg(long)]
        share: Vec<PathBuf>,
        /// Where known.met, known2_64.met and clients.met are kept.
        #[arg(long, default_value = "remule-config")]
        config: PathBuf,
        /// Others can connect to the TCP port: publish sources on Kad from
        /// the start (otherwise once a HighID or the Kad firewall check says so).
        #[arg(long)]
        reachable: bool,
        /// Take sources on LAN and loopback addresses.
        #[arg(long)]
        allow_lan: bool,
        /// Seconds before asking a source again (aMule's SourceReaskMinutes,
        /// 15 minutes); a queued source is asked over UDP 20 s before.
        /// Peers ban a client that asks within about 10 minutes.
        #[arg(long, default_value_t = 900)]
        reask: u64,
    },
    /// Share directories as aMule does: hash new files into known.met and
    /// known2_64.met, and list the shared files.
    Share {
        /// The directories to share (not recursive, as in aMule).
        #[arg(required = true)]
        dirs: Vec<PathBuf>,
        /// The config directory with known.met (aMule's works, with aMule closed).
        #[arg(long, default_value = "remule-config")]
        config: PathBuf,
        /// A directory never to share (aMule's Temp, say).
        #[arg(long)]
        reserved: Vec<PathBuf>,
        /// Share files whose names start with a dot.
        #[arg(long)]
        hidden: bool,
        /// Print each file's ed2k link.
        #[arg(long)]
        links: bool,
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
    // The client and Kad log through `tracing`: print their lines as the
    // tool always has, bare on stdout.
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_level(false)
        .with_writer(std::io::stdout)
        .init();
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
        Command::Kad {
            nodes,
            dir,
            port,
            bootstrap,
            searches,
            sources,
            duration,
            status_every,
            warmup,
            limit,
            verbose,
            reachable,
            allow_lan,
        } => run_async(kad::run(kad::KadArgs {
            nodes,
            dir,
            port,
            bootstrap,
            searches,
            sources,
            duration,
            status_every: status_every.max(1),
            warmup,
            limit,
            verbose,
            reachable,
            allow_lan,
        })),
        Command::Download {
            links,
            temp,
            incoming,
            servers,
            obfuscate,
            kad,
            nodes,
            kad_bootstrap,
            port,
            udp_port,
            nick,
            duration,
            status_every,
            max_connections,
            max_download,
            max_upload,
            share,
            config,
            reachable,
            allow_lan,
            reask,
        } => run_async(download::run(download::DownloadArgs {
            links,
            temp,
            incoming,
            servers,
            obfuscate_server: obfuscate,
            kad,
            kad_nodes: nodes,
            kad_bootstrap,
            tcp_port: port,
            udp_port,
            nick,
            duration,
            status_every: status_every.max(1),
            max_connections,
            max_download,
            max_upload,
            share,
            config,
            reachable,
            allow_lan,
            reask,
        })),
        Command::Share {
            dirs,
            config,
            reserved,
            hidden,
            links,
        } => match share::run(share::ShareArgs {
            config,
            dirs,
            reserved,
            hidden,
            links,
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("remule: {e}");
                ExitCode::from(1)
            }
        },
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
