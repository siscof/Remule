// SPDX-License-Identifier: GPL-2.0-or-later
//! `remule share`: scan shared directories as aMule does, hash what
//! `known.met` does not know, save `known.met` / `known2_64.met`, and list
//! the shared files with their ed2k links.

use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use remule_core::shared::{mtime, ScanOptions, SharedFiles};

/// What `remule share` was asked.
#[derive(Debug, Clone)]
pub struct ShareArgs {
    /// The config directory holding known.met (aMule's works).
    pub config: PathBuf,
    pub dirs: Vec<PathBuf>,
    /// Never shared (aMule's Temp directory, say).
    pub reserved: Vec<PathBuf>,
    pub hidden: bool,
    /// Print each file's ed2k link.
    pub links: bool,
}

pub fn run(a: ShareArgs) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32);
    let mut s = SharedFiles::load(&a.config).map_err(|e| format!("{}: {e}", a.config.display()))?;
    println!("{}: {} known files", a.config.display(), s.known_count());
    let mut reserved = a.reserved.clone();
    reserved.push(a.config.clone());
    let r = s.scan(
        &ScanOptions {
            dirs: a.dirs.clone(),
            reserved,
            hidden: a.hidden,
        },
        now,
    );
    for (d, why) in &r.skipped {
        println!("{}: not shared ({why})", d.display());
    }
    println!("{} known, {} to hash", r.known, r.to_hash.len());
    for p in &r.to_hash {
        let t = Instant::now();
        let date = match std::fs::metadata(p) {
            Ok(m) => mtime(&m),
            Err(e) => {
                println!("{}: {e}", p.display());
                continue;
            }
        };
        match SharedFiles::hash(p) {
            Ok(h) => {
                s.add_hashed(p, &h, date, now);
                println!(
                    "hashed {} in {:.1}s",
                    p.display(),
                    t.elapsed().as_secs_f64()
                );
            }
            Err(e) => println!("{}: {e}", p.display()),
        }
    }
    s.save()
        .map_err(|e| format!("{}: {e}", a.config.display()))?;
    for (f, path) in s.files() {
        println!("{:>12}  {}  {}", f.size, f.hash, path.display());
        if a.links {
            let mut link = format!(
                "ed2k://|file|{}|{}|{}|",
                ed2k_hash::cleanup_name(&f.name),
                f.size,
                f.hash
            );
            if let Some(root) = &f.aich_hash {
                link += &format!("h={root}|");
            }
            println!("              {link}/");
        }
    }
    println!(
        "{} files shared, {} known",
        s.shared_count(),
        s.known_count()
    );
    Ok(())
}
