// SPDX-License-Identifier: GPL-2.0-or-later
//! ed2k file links (`CED2KFileLink`, ED2KLink.cpp):
//!
//! ```text
//! ed2k://|file|NAME|SIZE|HASH|[h=AICH|][p=PARTHASH:...|][/|sources,IP:PORT,...|]/
//! ```
//!
//! The name is URL-encoded (`%20` and friends); optional fields after the
//! hash may come in any order and unknown ones are skipped.

use std::net::SocketAddrV4;

use ed2k_types::ed2k::MAX_FILE_SIZE;
use ed2k_types::{AichHash, Md4Hash};

/// A parsed file link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLink {
    pub name: String,
    pub size: u64,
    pub hash: Md4Hash,
    pub aich: Option<AichHash>,
    /// Sources given with the link (`|sources,IP:PORT,...|`).
    pub sources: Vec<SocketAddrV4>,
}

/// `%XX` decoding, as `UnescapeHTML` (bytes, then UTF-8, Latin-1 if not).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out.clone()).unwrap_or_else(|_| out.iter().map(|&c| char::from(c)).collect())
}

/// Parse an `ed2k://|file|...` link.
pub fn parse(link: &str) -> Result<FileLink, String> {
    let bad = |why: &str| format!("{link:?}: {why}");
    let rest = link
        .trim()
        .strip_prefix("ed2k://")
        .ok_or_else(|| bad("not an ed2k:// link"))?;
    let fields: Vec<&str> = rest.split('|').collect();
    if fields.len() < 5 || !fields[0].is_empty() || !fields[1].eq_ignore_ascii_case("file") {
        return Err(bad("not a file link (ed2k://|file|NAME|SIZE|HASH|/)"));
    }
    let name = unescape(fields[2]);
    if name.is_empty() {
        return Err(bad("empty name"));
    }
    let size: u64 = fields[3].parse().map_err(|_| bad("bad size"))?;
    if size == 0 || size > MAX_FILE_SIZE {
        return Err(bad("size out of range"));
    }
    let hash: Md4Hash = fields[4].parse().map_err(|_| bad("bad hash"))?;
    let mut aich = None;
    let mut sources = Vec::new();
    for f in &fields[5..] {
        if let Some(h) = f.strip_prefix("h=") {
            aich = Some(h.parse().map_err(|_| bad("bad AICH hash"))?);
        } else if let Some(list) = f.strip_prefix("sources,") {
            sources.extend(
                list.split(',')
                    .filter_map(|s| s.parse::<SocketAddrV4>().ok()),
            );
        }
    }
    Ok(FileLink {
        name,
        size,
        hash,
        aich,
        sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_parse() {
        let l = parse("ed2k://|file|My%20File.iso|9728000|31D6CFE0D16AE931B73C59D7E0C089C0|h=LOUTZHNQZ74T6UVVEHLUEDSD63W2E6CP|/").unwrap();
        assert_eq!(l.name, "My File.iso");
        assert_eq!(l.size, 9_728_000);
        assert_eq!(l.hash.to_string(), "31D6CFE0D16AE931B73C59D7E0C089C0");
        assert_eq!(
            l.aich.unwrap().to_string(),
            "LOUTZHNQZ74T6UVVEHLUEDSD63W2E6CP"
        );
        let l = parse(
            "ed2k://|file|a.txt|5|31d6cfe0d16ae931b73c59d7e0c089c0|/|sources,1.2.3.4:4662,bad|/",
        )
        .unwrap();
        assert_eq!(l.sources, ["1.2.3.4:4662".parse().unwrap()]);
        assert_eq!(
            parse("ed2k://|file|%C3%A9t%C3%A9.mp3|1|31D6CFE0D16AE931B73C59D7E0C089C0|/")
                .unwrap()
                .name,
            "été.mp3"
        );
        for bad in [
            "http://x",
            "ed2k://|server|1.2.3.4|4661|/",
            "ed2k://|file|x|0|31D6CFE0D16AE931B73C59D7E0C089C0|/",
            "ed2k://|file|x|10|nothex|/",
            "ed2k://|file||10|31D6CFE0D16AE931B73C59D7E0C089C0|/",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
