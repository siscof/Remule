// SPDX-License-Identifier: GPL-2.0-or-later
//! `addresses.dat` and `staticservers.dat`: two small text files in the
//! config directory.
//!
//! * `addresses.dat` lists the URLs `server.met` is updated from, one per
//!   line. Port of `ServerListSources.h` (`Read`, `IsValid`) and
//!   `CPreferences::SetServerListURLs`.
//! * `staticservers.dat` lists the servers the user marked static, one
//!   `host:port,priority,name` per line. Port of
//!   `CServerList::LoadStaticServers` / `SaveStaticServers`.
//!
//! aMule only reads `addresses.dat` (it never rewrites it on load), so a
//! file is kept as its bytes and the URL list is derived from them; writing
//! a list back produces aMule's format. The one-time migration of the old
//! `/eMule/Ed2kServersUrl` preference into this file is preferences logic
//! and is not here.

use std::fmt;

/// The source aMule adds when there is no `addresses.dat` yet.
pub const DEFAULT_URL: &str = "https://upd.emule-security.org/server.met";

/// The file is not valid in the encoding its byte order mark names
/// (`wxFFile::ReadAll` failing): aMule then treats it as unreadable, which
/// is not the same as empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Undecodable;

impl fmt::Display for Undecodable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("text file is not valid in the encoding its byte order mark names")
    }
}

impl std::error::Error for Undecodable {}

/// Decode a text file as `wxConvAuto` does: a UTF-32, UTF-16 or UTF-8 byte
/// order mark selects that encoding; without one, UTF-8, falling back to
/// Latin-1. (wx falls back to Windows-1252 on Windows; Latin-1 elsewhere.)
pub fn decode_text(bytes: &[u8]) -> Result<String, Undecodable> {
    fn units<const N: usize>(b: &[u8], f: fn([u8; N]) -> u32) -> Result<Vec<u32>, Undecodable> {
        let (chunks, rest) = b.as_chunks::<N>();
        if !rest.is_empty() {
            return Err(Undecodable);
        }
        Ok(chunks.iter().map(|c| f(*c)).collect())
    }
    fn utf32(v: Vec<u32>) -> Result<String, Undecodable> {
        v.into_iter()
            .map(|u| char::from_u32(u).ok_or(Undecodable))
            .collect()
    }
    fn utf16(v: Vec<u32>) -> Result<String, Undecodable> {
        char::decode_utf16(v.into_iter().map(|u| u as u16))
            .map(|c| c.map_err(|_| Undecodable))
            .collect()
    }
    match bytes {
        [0x00, 0x00, 0xFE, 0xFF, rest @ ..] => utf32(units(rest, u32::from_be_bytes)?),
        [0xFF, 0xFE, 0x00, 0x00, rest @ ..] => utf32(units(rest, u32::from_le_bytes)?),
        [0xFE, 0xFF, rest @ ..] => {
            utf16(units(rest, |b: [u8; 2]| u32::from(u16::from_be_bytes(b)))?)
        }
        [0xFF, 0xFE, rest @ ..] => {
            utf16(units(rest, |b: [u8; 2]| u32::from(u16::from_le_bytes(b)))?)
        }
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8(rest.to_vec()).map_err(|_| Undecodable),
        _ => Ok(match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => bytes.iter().map(|&b| char::from(b)).collect(),
        }),
    }
}

/// `wxString::Trim` both ends: the C whitespace set.
fn trim_ws(s: &str) -> &str {
    s.trim_matches(C_WHITESPACE)
}

/// The C `isspace` set that wx trims.
const C_WHITESPACE: [char; 6] = [' ', '\t', '\n', '\x0B', '\x0C', '\r'];

/// `ServerListSources::IsValid`: an `http`/`https` URL (scheme in any case)
/// with a non-empty host and no whitespace, line breaks or NUL.
///
/// The URL syntax follows `wxURI` closely enough for this check: a scheme,
/// `//`, then an authority whose host part (after any `userinfo@`, before
/// any `:port`, or inside `[...]` for IPv6) must be non-empty.
pub fn is_valid_url(url: &str) -> bool {
    if url.contains(['\n', '\r', '\0', ' ', '\t']) {
        return false;
    }
    let Some((scheme, rest)) = url.split_once(':') else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let Some(rest) = rest.strip_prefix("//") else {
        return false;
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let server = if let Some(v6) = host.strip_prefix('[') {
        v6.split_once(']').map_or("", |(inside, _)| inside)
    } else {
        // A reg-name or IPv4: unreserved, pct-encoded and sub-delims.
        let end = host
            .find(|c: char| !(c.is_ascii_alphanumeric() || "-._~%!$&'()*+,;=".contains(c)))
            .unwrap_or(host.len());
        &host[..end]
    };
    !server.is_empty()
}

/// `addresses.dat`: the `server.met` update URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressesDat {
    raw: Vec<u8>,
}

/// A URL that cannot go into `addresses.dat` (`SetServerListURLs` refusing the list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidUrl(pub String);

impl fmt::Display for InvalidUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a valid server list URL: {:?}", self.0)
    }
}

impl std::error::Error for InvalidUrl {}

impl AddressesDat {
    /// The file as read. Nothing is lost: [`AddressesDat::as_bytes`] gives it back.
    pub fn from_bytes(raw: Vec<u8>) -> Self {
        AddressesDat { raw }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// `ServerListSources::Read`: every line, trimmed, that is a valid URL,
    /// without duplicates, in file order. Anything else (comments, blank
    /// lines, other schemes) is skipped but stays in the file.
    pub fn urls(&self) -> Result<Vec<String>, Undecodable> {
        let text = decode_text(&self.raw)?;
        let mut out: Vec<String> = Vec::new();
        for line in text.split(['\r', '\n']).filter(|l| !l.is_empty()) {
            let url = trim_ws(line);
            if is_valid_url(url) && !out.iter().any(|u| u == url) {
                out.push(url.to_owned());
            }
        }
        Ok(out)
    }

    /// `SetServerListURLs`: every URL must be valid; duplicates are dropped;
    /// each is written as UTF-8 followed by `\n`. One invalid URL rejects the
    /// whole list, as in aMule.
    pub fn from_urls<S: AsRef<str>>(urls: &[S]) -> Result<Self, InvalidUrl> {
        let mut unique: Vec<&str> = Vec::new();
        for u in urls {
            let u = u.as_ref();
            if !is_valid_url(u) {
                return Err(InvalidUrl(u.to_owned()));
            }
            if !unique.contains(&u) {
                unique.push(u);
            }
        }
        let mut raw = Vec::new();
        for u in unique {
            raw.extend_from_slice(u.as_bytes());
            raw.push(b'\n');
        }
        Ok(AddressesDat { raw })
    }
}

/// Server preference as `staticservers.dat` stores it (`SRV_PR_*`).
pub const PRIORITY_NORMAL: u32 = 0;
pub const PRIORITY_HIGH: u32 = 1;
pub const PRIORITY_LOW: u32 = 2;

/// One line of `staticservers.dat`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticServer {
    /// Host name or IP, as written before the `:`.
    pub host: String,
    pub port: u16,
    /// [`PRIORITY_NORMAL`], [`PRIORITY_HIGH`] or [`PRIORITY_LOW`].
    pub priority: u32,
    pub name: String,
}

/// `wxString::ToLong` as `StrToLong` uses it: the whole string must be a
/// base-10 number (leading whitespace and a sign allowed, as `strtol`);
/// anything else, or an overflow, is 0.
fn str_to_long(s: &str) -> i64 {
    let t = s.trim_start_matches(C_WHITESPACE);
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    // A 64-bit `long`, as on Linux.
    t.parse::<i64>().unwrap_or(0)
}

/// `LoadStaticServers`. Lines that are empty or start with `#` or `/` are
/// comments; a line needs exactly three comma-separated fields
/// (`host:port,priority,name`), each trimmed. An out-of-range priority
/// becomes normal; an empty name becomes the `host:port` text.
///
/// As in aMule, a name containing a comma makes its line unreadable: the
/// format has no escaping, so `SaveStaticServers` writes such a line and the
/// next load skips it.
pub fn read_static_servers(bytes: &[u8]) -> Result<Vec<StaticServer>, Undecodable> {
    let text = decode_text(bytes)?;
    let mut out = Vec::new();
    // wxTextInputStream::ReadLine ends lines at \n, \r\n or \r.
    for line in text.split('\n').flat_map(|l| l.split('\r')) {
        if line.is_empty() || line.starts_with('#') || line.starts_with('/') {
            continue;
        }
        // wxStringTokenizer(line, ","): empty fields in the middle count, a
        // trailing comma does not add one.
        let body = line.strip_suffix(',').unwrap_or(line);
        let fields: Vec<&str> = body.split(',').collect();
        if fields.len() != 3 {
            continue;
        }
        let addy = trim_ws(fields[0]);
        let prio = trim_ws(fields[1]);
        let name = trim_ws(fields[2]);
        let (host, port) = addy.split_once(':').unwrap_or((addy, ""));
        let mut priority = str_to_long(prio);
        if !(i64::from(PRIORITY_NORMAL)..=i64::from(PRIORITY_LOW)).contains(&priority) {
            priority = i64::from(PRIORITY_NORMAL);
        }
        out.push(StaticServer {
            host: host.to_owned(),
            // CServer takes a uint16: the long is truncated.
            port: str_to_long(port) as u16,
            priority: priority as u32,
            name: if name.is_empty() {
                addy.to_owned()
            } else {
                name.to_owned()
            },
        });
    }
    Ok(out)
}

/// `SaveStaticServers`: one `host:port,priority,name` line per server,
/// separated by `eol` with no line break after the last one (`CTextFile`
/// puts the end-of-line before every line but the first). aMule uses the
/// platform's end of line: `"\n"`, or `"\r\n"` on Windows.
pub fn write_static_servers(servers: &[StaticServer], eol: &str) -> Vec<u8> {
    servers
        .iter()
        .map(|s| format!("{}:{},{},{}", s.host, s.port, s.priority, s.name))
        .collect::<Vec<_>>()
        .join(eol)
        .into_bytes()
}

#[cfg(test)]
mod tests;
