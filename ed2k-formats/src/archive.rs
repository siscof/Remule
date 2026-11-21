// SPDX-License-Identifier: GPL-2.0-or-later
//! Packed downloads (`UnpackArchive`, `GuessFiletype` in aMule's
//! `FileFunctions.cpp`): an IP filter (or other list) fetched as a zip, a
//! gzip or a tar is unpacked to the member it should hold, nested archives
//! too, up to three levels and 256 MiB, so a small archive can neither fill
//! the disk nor unpack to itself forever.

use std::io::Read;

/// `MAX_UNPACKED_SIZE`.
pub const MAX_UNPACKED: usize = 256 * 1024 * 1024;
/// `MAX_UNPACK_DEPTH`.
pub const MAX_DEPTH: usize = 3;

/// `EFileType`, as `GuessFiletype` tells it from the first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Zip,
    GZip,
    Tar,
    /// A `.met` file (`0xE0` or `0x0E` first).
    Met,
    /// Printable, the first ten bytes at least.
    Text,
    /// Anything else, or empty.
    Unknown,
}

/// `GuessFiletype`.
pub fn guess(b: &[u8]) -> FileType {
    const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
    let head = &b[..b.len().min(10)];
    if head.is_empty() {
        return FileType::Unknown;
    }
    if head.starts_with(b"PK") {
        return FileType::Zip;
    }
    if head.starts_with(&[0x1F, 0x8B]) {
        return FileType::GZip;
    }
    if head[0] == 0xE0 || head[0] == 0x0E {
        return FileType::Met;
    }
    // Tar has no magic at the start; "ustar" at 257, POSIX and GNU alike.
    if b.get(257..262) == Some(b"ustar") {
        return FileType::Tar;
    }
    let printable = |c: u8| {
        (0x20..0x7F).contains(&c) || matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
    };
    if head
        .iter()
        .enumerate()
        .all(|(i, &c)| printable(c) || (i < 3 && c == BOM[i]))
    {
        FileType::Text
    } else {
        FileType::Unknown
    }
}

/// `IsWantedMember`: the member's name without its folder, in any case,
/// against the wanted names (`*` and `?` wildcards).
fn wanted(member: &str, names: &[&str]) -> bool {
    let name = member.rsplit('/').next().unwrap_or(member).to_lowercase();
    names.iter().any(|p| wild(&p.to_lowercase(), &name))
}

fn wild(p: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Read all of `r`, refusing more than [`MAX_UNPACKED`].
fn read_capped(r: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    r.take(MAX_UNPACKED as u64 + 1).read_to_end(&mut out).ok()?;
    (out.len() <= MAX_UNPACKED).then_some(out)
}

fn u16_at(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?).into())
}

fn u32_at(b: &[u8], i: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize)
}

/// `UnpackZipFile`: the first wanted member (stored or deflated), found
/// through the central directory, so sizes a data descriptor gives after
/// the data are known too.
fn unzip(b: &[u8], names: &[&str]) -> Option<Vec<u8>> {
    // End of central directory: its signature, searched from the end
    // (past at most a 64 KiB comment).
    let lo = b.len().saturating_sub(22 + 0xFFFF);
    let eocd = (lo..b.len().saturating_sub(21))
        .rev()
        .find(|&i| b[i..].starts_with(b"PK\x05\x06"))?;
    let count = u16_at(b, eocd + 10)?;
    let mut at = u32_at(b, eocd + 16)?;
    for _ in 0..count {
        if !b.get(at..)?.starts_with(b"PK\x01\x02") {
            return None;
        }
        let method = u16_at(b, at + 10)?;
        let csize = u32_at(b, at + 20)?;
        let (nlen, xlen, clen) = (
            u16_at(b, at + 28)?,
            u16_at(b, at + 30)?,
            u16_at(b, at + 32)?,
        );
        let local = u32_at(b, at + 42)?;
        let name = String::from_utf8_lossy(b.get(at + 46..at + 46 + nlen)?).into_owned();
        at += 46 + nlen + xlen + clen;
        if name.ends_with('/') || !wanted(&name, names) {
            continue;
        }
        if !b.get(local..)?.starts_with(b"PK\x03\x04") {
            return None;
        }
        let start = local + 30 + u16_at(b, local + 26)? + u16_at(b, local + 28)?;
        let data = b.get(start..start.checked_add(csize)?)?;
        let out = match method {
            0 => (data.len() <= MAX_UNPACKED).then(|| data.to_vec())?,
            8 => read_capped(flate2::read::DeflateDecoder::new(data))?,
            // An unsupported method: this download failed.
            _ => return None,
        };
        return (!out.is_empty()).then_some(out);
    }
    None
}

/// `UnpackGZipFile`.
fn gunzip(b: &[u8]) -> Option<Vec<u8>> {
    read_capped(flate2::read::MultiGzDecoder::new(b))
}

/// `UnpackTarFile`: the first wanted member, whole (a truncated one is
/// nothing).
fn untar(b: &[u8], names: &[&str]) -> Option<Vec<u8>> {
    let mut at = 0;
    while at + 512 <= b.len() {
        let h = &b[at..at + 512];
        if h.iter().all(|&c| c == 0) {
            return None;
        }
        let field = |r: std::ops::Range<usize>| {
            let f = &h[r];
            let end = f.iter().position(|&c| c == 0).unwrap_or(f.len());
            String::from_utf8_lossy(&f[..end]).trim().to_owned()
        };
        let mut name = field(0..100);
        let prefix = field(345..500);
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let size = usize::from_str_radix(&field(124..136), 8).ok()?;
        let kind = h[156];
        let data = at + 512;
        if (kind == b'0' || kind == 0) && wanted(&name, names) {
            if size == 0 || size > MAX_UNPACKED {
                return None;
            }
            return b.get(data..data + size).map(<[u8]>::to_vec);
        }
        at = data + size.div_ceil(512) * 512;
    }
    None
}

/// `UnpackArchive`: `b` unpacked to the wanted member, as deep as the
/// nesting goes (at most [`MAX_DEPTH`] levels), with the type of what is
/// left; `None` when an archive could not be unpacked.
pub fn unpack(b: &[u8], names: &[&str]) -> Option<(Vec<u8>, FileType)> {
    let mut cur = b.to_vec();
    for _ in 0..MAX_DEPTH {
        let ty = guess(&cur);
        let next = match ty {
            FileType::Zip => unzip(&cur, names),
            FileType::GZip => gunzip(&cur),
            FileType::Tar => untar(&cur, names),
            _ => return Some((cur, ty)),
        };
        cur = next?;
    }
    // Still an archive past the deepest level: refused.
    match guess(&cur) {
        FileType::Zip | FileType::GZip | FileType::Tar => None,
        ty => Some((cur, ty)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const NAMES: &[&str] = &["ipfilter.dat", "guardian.p2p", "guarding.p2p"];
    const LIST: &[u8] = b"1.2.3.0 - 1.2.3.255 , 0 , test\n";

    fn gz(b: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    /// A zip with these members; deflated or stored; sizes in the local
    /// header or, with `descriptor`, after the data.
    fn zip(members: &[(&str, &[u8])], deflate: bool, descriptor: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in members {
            let body = if deflate {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            } else {
                data.to_vec()
            };
            let method: u16 = if deflate { 8 } else { 0 };
            let flags: u16 = if descriptor { 8 } else { 0 };
            let offset = out.len() as u32;
            let (cs, us) = if descriptor {
                (0, 0)
            } else {
                (body.len() as u32, data.len() as u32)
            };
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 8]); // time, date, crc
            out.extend_from_slice(&cs.to_le_bytes());
            out.extend_from_slice(&us.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
            if descriptor {
                out.extend_from_slice(b"PK\x07\x08");
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&(body.len() as u32).to_le_bytes());
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            }
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&[20, 0, 20, 0]);
            central.extend_from_slice(&flags.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 8]);
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]); // extra, comment, disk, attrs
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn tar(name: &str, data: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", data.len());
        h[124..136].copy_from_slice(size.as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        let mut out = h;
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512 + 1024, 0);
        out
    }

    #[test]
    fn types_are_told_from_the_first_bytes() {
        assert_eq!(guess(b"PK\x03\x04..."), FileType::Zip);
        assert_eq!(guess(&[0x1F, 0x8B, 8]), FileType::GZip);
        assert_eq!(guess(&[0xE0, 1, 2]), FileType::Met);
        assert_eq!(guess(LIST), FileType::Text);
        assert_eq!(guess(b"\xEF\xBB\xBF# with a BOM\n"), FileType::Text);
        assert_eq!(guess(&[0, 1, 2, 3]), FileType::Unknown);
        assert_eq!(guess(b""), FileType::Unknown);
        assert_eq!(guess(&tar("ipfilter.dat", LIST)), FileType::Tar);
    }

    #[test]
    fn archives_unpack_to_the_list_they_hold() {
        // A zip, deflated, the list after an nfo the archive also holds.
        let z = zip(
            &[("readme.nfo", b"hi"), ("lists/IPFilter.DAT", LIST)],
            true,
            false,
        );
        assert_eq!(unpack(&z, NAMES), Some((LIST.to_vec(), FileType::Text)));
        // Stored, with the sizes after the data.
        let z = zip(&[("guarding.p2p", LIST)], false, true);
        assert_eq!(unpack(&z, NAMES).unwrap().0, LIST);
        // gzip, tar, and a tar in a gzip.
        assert_eq!(unpack(&gz(LIST), NAMES).unwrap().0, LIST);
        assert_eq!(unpack(&tar("x/ipfilter.dat", LIST), NAMES).unwrap().0, LIST);
        assert_eq!(
            unpack(&gz(&tar("ipfilter.dat", LIST)), NAMES).unwrap().0,
            LIST
        );
        // Plain text stays as it is.
        assert_eq!(unpack(LIST, NAMES), Some((LIST.to_vec(), FileType::Text)));
    }

    #[test]
    fn what_cannot_be_unpacked_is_refused() {
        // No wanted member, or a broken archive.
        assert_eq!(
            unpack(&zip(&[("readme.nfo", b"hi")], true, false), NAMES),
            None
        );
        assert_eq!(unpack(b"PK\x03\x04 broken", NAMES), None);
        assert_eq!(unpack(&[0x1F, 0x8B, 0, 0, 0], NAMES), None);
        // Nested deeper than three levels.
        let deep = gz(&gz(&gz(&gz(LIST))));
        assert_eq!(unpack(&deep, NAMES), None);
        assert!(unpack(&gz(&gz(&gz(LIST))), NAMES).is_some());
        // Binary that is no archive: unpacked to nothing, and not text.
        assert_eq!(unpack(&[0, 1, 2], NAMES).unwrap().1, FileType::Unknown);
    }

    #[test]
    fn member_names_match_as_amule_matches_them() {
        assert!(wanted("a/b/IPFILTER.dat", NAMES));
        assert!(!wanted("ipfilter.dat.bak", NAMES));
        assert!(wild("*.p2p", "guarding.p2p"));
        assert!(wild("ip?ilter.dat", "ipfilter.dat"));
        assert!(!wild("*.p2p", "guarding.dat"));
    }
}
