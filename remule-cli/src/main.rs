// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule`: command-line tools for the Rust port of aMule.
//!
//!     remule inspect [DIR] [-v] [--temp-dir DIR] [--write OUT]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use remule_cli::inspect::{self, Outcome};

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
}

fn default_config_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".aMule"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
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
