// SPDX-License-Identifier: GPL-2.0-or-later
//! `amule.conf`: aMule's preferences, a wxFileConfig INI file.
//!
//! Two layers:
//!
//! * [`ConfFile`]: a lossless model of the file as wxFileConfig parses it
//!   (`wx/src/common/fileconf.cpp`, as aMule's `CECFileConfig` uses it:
//!   escapes on, case-insensitive names). An unchanged file writes back
//!   byte for byte; setting a value rewrites only its line, or inserts one
//!   where wxFileConfig would; setting a value to what it already holds
//!   leaves the line alone, as `wxFileConfigEntry::SetValue` does.
//! * [`Preferences`]: a typed view of a core subset of the keys in
//!   `Preferences.cpp`, read with aMule's defaults and wxConfig's number
//!   parsing. Every other key stays reachable through [`ConfFile::get`].
//!
//! Format, as wxFileConfig reads it: lines are split at `\n`, `\r\n` or
//! `\r`; leading whitespace is skipped; blank lines and lines starting with
//! `;` or `#` are comments; `[a/b]` opens the group `/a/b` (an absolute
//! path); `key = value` is an entry of the current group (entries before any
//! group belong to the root). In names, `\` escapes the next character. In
//! values, `\n \r \t \\ \"` are escapes, any other escaped character is
//! dropped, and a value starting with `"` is quoted. A repeated key: the
//! last one wins.
//!
//! Deliberate differences from wxFileConfig, all to avoid changing what the
//! user did not change:
//!
//! * Each line keeps its own end-of-line; wxFileConfig rewrites the whole
//!   file with the platform's. New lines use the file's first end-of-line.
//! * A Latin-1 file stays Latin-1 (wxConvAuto would save it as UTF-8),
//!   unless a value that Latin-1 cannot hold is set; then it becomes UTF-8.
//! * Values are not environment-expanded: wxConfig's `Read` expands `$VAR`
//!   and `${VAR}` by default; that is left to the caller.

use std::fmt;

/// `wxCONFIG_PATH_SEPARATOR`
const SEP: char = '/';

/// How the file's bytes were encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// UTF-8, optionally with a byte order mark.
    Utf8 { bom: bool },
    /// Not valid UTF-8: read as Latin-1 (wxConvAuto's fallback).
    Latin1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    /// Blank, comment, or a line wxFileConfig could not parse (kept as is).
    Other,
    /// A group header; the group's normalised path without the leading `/`.
    Group(String),
    /// An entry: its group, its name, and its decoded value.
    Entry {
        group: String,
        key: String,
        value: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Line {
    text: String,
    eol: &'static str,
    kind: Kind,
}

/// Something wxFileConfig would warn about while parsing; the line is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// 1-based line number.
    pub line: usize,
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

/// A lossless wxFileConfig file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfFile {
    lines: Vec<Line>,
    encoding: Encoding,
    /// For new lines: the file's first end-of-line, or `\n`.
    eol: &'static str,
    warnings: Vec<Warning>,
}

/// Names compare case-insensitively (`wxCONFIG_CASE_SENSITIVE` is 0).
fn same_name(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.chars()
            .zip(b.chars())
            .all(|(x, y)| x.to_lowercase().eq(y.to_lowercase()))
}

/// `FilterInEntryName`: drop each `\`, keeping the character after it.
fn filter_in_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n) => out.push(n),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `FilterOutEntryName`: escape everything but alphanumerics, `@_/-!.*%()`
/// and non-ASCII characters.
fn filter_out_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_alphanumeric() && !"@_/-!.*%()".contains(c) && c.is_ascii() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `FilterInValue`.
fn filter_in_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let quoted = s.starts_with('"');
    let body = if quoted { &s[1..] } else { s };
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                // Any other escaped character is dropped, as in wx.
                Some(_) => {}
                // A trailing backslash is ignored.
                None => break,
            }
        } else if c != '"' || !quoted {
            out.push(c);
        }
        // else: a quote inside a quoted value (wx warns) or the closing one: dropped.
    }
    out
}

/// `FilterOutValue`: quote a value that starts with whitespace or `"`, and
/// escape newlines, tabs, backslashes (and quotes, when quoting).
fn filter_out_value(s: &str) -> String {
    let Some(first) = s.chars().next() else {
        return String::new();
    };
    let quote = first.is_whitespace() || first == '"';
    let mut out = String::with_capacity(s.len() + 2);
    if quote {
        out.push('"');
    }
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            '"' if quote => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    if quote {
        out.push('"');
    }
    out
}

/// Normalise a group path like `wxSplitPath`: drop empty and `.` parts,
/// resolve `..`. Returns it without the leading `/` ("" is the root).
fn normalise(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for p in path.split(SEP) {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

fn parent(group: &str) -> Option<&str> {
    if group.is_empty() {
        None
    } else {
        Some(group.rsplit_once(SEP).map_or("", |(p, _)| p))
    }
}

/// Split "/eMule/Nick" into ("eMule", "Nick"). The group is normalised.
fn split_key(path: &str) -> (String, String) {
    match path.rsplit_once(SEP) {
        Some((g, k)) => (normalise(g), k.to_owned()),
        None => (String::new(), path.to_owned()),
    }
}

/// Split text into lines with their ends, as wxTextFile does.
fn split_lines(text: &str) -> Vec<(&str, &'static str)> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        match rest.find(['\n', '\r']) {
            Some(i) => {
                let eol = if rest[i..].starts_with("\r\n") {
                    "\r\n"
                } else if rest.as_bytes()[i] == b'\r' {
                    "\r"
                } else {
                    "\n"
                };
                out.push((&rest[..i], eol));
                rest = &rest[i + eol.len()..];
            }
            None => {
                out.push((rest, ""));
                break;
            }
        }
    }
    out
}

impl ConfFile {
    /// An empty file.
    pub fn new() -> Self {
        ConfFile {
            lines: Vec::new(),
            encoding: Encoding::Utf8 { bom: false },
            eol: "\n",
            warnings: Vec::new(),
        }
    }

    /// Read a file's bytes: UTF-8 (with or without a BOM), else Latin-1.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let (text, encoding) = match bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
            Some(rest) => match std::str::from_utf8(rest) {
                Ok(s) => (s.to_owned(), Encoding::Utf8 { bom: true }),
                Err(_) => (
                    rest.iter().map(|&b| char::from(b)).collect(),
                    Encoding::Latin1,
                ),
            },
            None => match std::str::from_utf8(bytes) {
                Ok(s) => (s.to_owned(), Encoding::Utf8 { bom: false }),
                Err(_) => (
                    bytes.iter().map(|&b| char::from(b)).collect(),
                    Encoding::Latin1,
                ),
            },
        };
        let mut f = ConfFile::parse(&text);
        f.encoding = encoding;
        f
    }

    /// The file's bytes, in its encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let text = self.to_text();
        match self.encoding {
            Encoding::Utf8 { bom } => {
                let mut out = if bom {
                    vec![0xEF, 0xBB, 0xBF]
                } else {
                    Vec::new()
                };
                out.extend_from_slice(text.as_bytes());
                out
            }
            Encoding::Latin1 => text.chars().map(|c| c as u8).collect(),
        }
    }

    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// What wxFileConfig would have warned about.
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Parse text (`wxFileConfig::Parse`).
    pub fn parse(text: &str) -> Self {
        let mut f = ConfFile::new();
        let mut group = String::new();
        let raw = split_lines(text);
        if let Some(&(_, eol)) = raw.iter().find(|(_, e)| !e.is_empty()) {
            f.eol = eol;
        }
        for (n, (text, eol)) in raw.into_iter().enumerate() {
            let kind = f.parse_line(n + 1, text, &mut group);
            f.lines.push(Line {
                text: text.to_owned(),
                eol,
                kind,
            });
        }
        f
    }

    fn warn(&mut self, line: usize, message: String) {
        self.warnings.push(Warning { line, message });
    }

    fn parse_line(&mut self, n: usize, text: &str, group: &mut String) -> Kind {
        let s = text.trim_start();
        if s.is_empty() || s.starts_with(';') || s.starts_with('#') {
            return Kind::Other;
        }
        if let Some(body) = s.strip_prefix('[') {
            // Find the closing ']', honouring escapes.
            let mut end = None;
            let mut chars = body.char_indices();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        chars.next();
                    }
                    ']' => {
                        end = Some(i);
                        break;
                    }
                    _ => {}
                }
            }
            let Some(end) = end else {
                self.warn(n, "unterminated group header".into());
                return Kind::Other;
            };
            *group = normalise(&filter_in_name(&body[..end]));
            // Only whitespace or a comment may follow.
            if let Some(c) = body[end + 1..]
                .trim_start_matches([' ', '\t'])
                .chars()
                .next()
            {
                if c != '#' && c != ';' {
                    self.warn(n, "text ignored after group header".into());
                }
            }
            return Kind::Group(group.clone());
        }
        // A key: up to '=', with '\' escaping the next character.
        let mut end = s.len();
        let mut chars = s.char_indices();
        while let Some((i, c)) = chars.next() {
            if c == '\\' {
                if chars.next().is_none() {
                    break;
                }
            } else if c == '=' {
                end = i;
                break;
            }
        }
        if end == s.len() {
            self.warn(n, "'=' expected".into());
            return Kind::Other;
        }
        let key = filter_in_name(s[..end].trim_end());
        let value = filter_in_value(s[end + 1..].trim_start());
        if self.find(group, &key).is_some() {
            self.warn(
                n,
                format!("key '{key}' appears more than once; the last one wins"),
            );
        }
        Kind::Entry {
            group: group.clone(),
            key,
            value,
        }
    }

    /// Index of the line holding `key` in `group` (the last one, if repeated).
    fn find(&self, group: &str, key: &str) -> Option<usize> {
        self.lines.iter().rposition(|l| matches!(&l.kind, Kind::Entry { group: g, key: k, .. } if same_name(g, group) && same_name(k, key)))
    }

    fn group_line(&self, group: &str) -> Option<usize> {
        self.lines
            .iter()
            .rposition(|l| matches!(&l.kind, Kind::Group(g) if same_name(g, group)))
    }

    /// The value of `path` ("/Group/Key"), if present.
    pub fn get(&self, path: &str) -> Option<&str> {
        let (group, key) = split_key(path);
        self.find(&group, &key).map(|i| match &self.lines[i].kind {
            Kind::Entry { value, .. } => value.as_str(),
            _ => unreachable!("find returns entry lines"),
        })
    }

    /// Every entry as (path, value), in file order; repeated keys appear once,
    /// with the value that wins.
    pub fn entries(&self) -> Vec<(String, &str)> {
        let mut out: Vec<(String, &str)> = Vec::new();
        for (i, l) in self.lines.iter().enumerate() {
            if let Kind::Entry { group, key, value } = &l.kind {
                if self.find(group, key) == Some(i) {
                    let path = if group.is_empty() {
                        format!("/{key}")
                    } else {
                        format!("/{group}/{key}")
                    };
                    out.push((path, value));
                }
            }
        }
        out
    }

    /// Last entry line of `group`, or its header line if it has none
    /// (`GetLastEntryLine`).
    fn last_entry_line(&self, group: &str) -> Option<usize> {
        self.lines
            .iter()
            .rposition(|l| matches!(&l.kind, Kind::Entry { group: g, .. } if same_name(g, group)))
            .or_else(|| {
                if group.is_empty() {
                    None
                } else {
                    self.group_line(group)
                }
            })
    }

    /// Where a new subgroup of `group` goes: after its last subgroup's last
    /// line, or after its own last entry (`GetLastGroupLine`).
    fn last_group_line(&self, group: &str) -> Option<usize> {
        let last_sub = self
            .lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| match &l.kind {
                Kind::Group(g) if parent(g).is_some_and(|p| same_name(p, group)) => {
                    Some((i, g.clone()))
                }
                _ => None,
            })
            .max_by_key(|(i, _)| *i);
        match last_sub {
            Some((_, sub)) => self.last_group_line(&sub),
            None => self.last_entry_line(group),
        }
    }

    fn insert_after(&mut self, at: Option<usize>, text: String, kind: Kind) -> usize {
        let i = at.map_or(0, |i| i + 1);
        // The line before the new one must end, or the two would merge.
        if i > 0 && self.lines[i - 1].eol.is_empty() {
            self.lines[i - 1].eol = self.eol;
        }
        self.lines.insert(
            i,
            Line {
                text,
                eol: self.eol,
                kind,
            },
        );
        i
    }

    /// Make sure `group` has a header line, creating its parents' first (`GetGroupLine`).
    fn ensure_group_line(&mut self, group: &str) {
        if group.is_empty() || self.group_line(group).is_some() {
            return;
        }
        let p = parent(group).unwrap_or("").to_owned();
        self.ensure_group_line(&p);
        let at = self.last_group_line(&p);
        self.insert_after(
            at,
            format!("[{}]", filter_out_name(group)),
            Kind::Group(group.to_owned()),
        );
    }

    /// Set `path` ("/Group/Key") to `value`. An existing entry keeps its line
    /// (rewritten only if the value differs); a new one goes after its
    /// group's last entry, creating the group's header if needed.
    pub fn set(&mut self, path: &str, value: &str) {
        let (group, key) = split_key(path);
        if self.encoding == Encoding::Latin1 && value.chars().any(|c| u32::from(c) > 0xFF) {
            self.encoding = Encoding::Utf8 { bom: false };
        }
        let text = format!("{}={}", filter_out_name(&key), filter_out_value(value));
        if let Some(i) = self.find(&group, &key) {
            if let Kind::Entry { value: old, .. } = &mut self.lines[i].kind {
                if old == value {
                    return;
                }
                *old = value.to_owned();
            }
            self.lines[i].text = text;
            return;
        }
        self.ensure_group_line(&group);
        let at = self.last_entry_line(&group);
        self.insert_after(
            at,
            text,
            Kind::Entry {
                group,
                key,
                value: value.to_owned(),
            },
        );
    }

    /// Remove `path`'s entry (every line of it, if repeated). Returns whether
    /// there was one. The group header stays, as wxFileConfig keeps it until
    /// the group is deleted.
    pub fn remove(&mut self, path: &str) -> bool {
        let (group, key) = split_key(path);
        let before = self.lines.len();
        self.lines.retain(|l| !matches!(&l.kind, Kind::Entry { group: g, key: k, .. } if same_name(g, &group) && same_name(k, &key)));
        self.lines.len() != before
    }

    fn to_text(&self) -> String {
        let mut out = String::new();
        for l in &self.lines {
            out.push_str(&l.text);
            out.push_str(l.eol);
        }
        out
    }
}

impl Default for ConfFile {
    fn default() -> Self {
        ConfFile::new()
    }
}

/// wxConfig's number parsing (`wxFileConfig::DoReadLong`): the value with
/// trailing whitespace trimmed, then `wxString::ToLong`, i.e. `strtol` in
/// base 10 that must consume everything and not overflow. Leading
/// whitespace and a sign are allowed.
pub fn parse_long(value: &str) -> Option<i64> {
    let s = value.trim_end().trim_start();
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

/// `CPath::FromUniv`: each character is a byte of the on-disk path, decoded
/// as UTF-8. A path that does not decode becomes empty, as in aMule.
fn from_univ(s: &str) -> String {
    let bytes: Option<Vec<u8>> = s.chars().map(|c| u8::try_from(u32::from(c)).ok()).collect();
    bytes
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

/// `CPath::ToUniv`
fn to_univ(path: &str) -> String {
    path.bytes().map(char::from).collect()
}

/// Key paths of the [`Preferences`] fields (from `Preferences.cpp`).
pub mod keys {
    pub const NICK: &str = "/eMule/Nick";
    pub const PORT: &str = "/eMule/Port";
    pub const UDP_PORT: &str = "/eMule/UDPPort";
    pub const UDP_ENABLE: &str = "/eMule/UDPEnable";
    pub const MAX_UPLOAD: &str = "/eMule/MaxUpload";
    pub const MAX_DOWNLOAD: &str = "/eMule/MaxDownload";
    pub const SLOT_ALLOCATION: &str = "/eMule/SlotAllocation";
    pub const MAX_CONNECTIONS: &str = "/eMule/MaxConnections";
    pub const MAX_CONNECTIONS_PER_FIVE_SECONDS: &str = "/eMule/MaxConnectionsPerFiveSeconds";
    pub const MAX_SOURCES_PER_FILE: &str = "/eMule/MaxSourcesPerFile";
    pub const TEMP_DIR: &str = "/eMule/TempDir";
    pub const INCOMING_DIR: &str = "/eMule/IncomingDir";
    pub const CONNECT_TO_ED2K: &str = "/eMule/ConnectToED2K";
    pub const CONNECT_TO_KAD: &str = "/eMule/ConnectToKad";
    pub const AUTOCONNECT: &str = "/eMule/Autoconnect";
    pub const RECONNECT: &str = "/eMule/Reconnect";
    pub const ACCEPT_EXTERNAL_CONNECTIONS: &str = "/ExternalConnect/AcceptExternalConnections";
    pub const EC_ADDRESS: &str = "/ExternalConnect/ECAddress";
    pub const EC_PORT: &str = "/ExternalConnect/ECPort";
    /// `v1:15:8:1:<salt>:<verifier>`, see `ECSRPConfig.cpp`.
    pub const EC_PASSWORD_VERIFIER: &str = "/ExternalConnect/ECPasswordVerifier";
    /// The legacy MD5 digest, migrated to the verifier at startup.
    pub const EC_PASSWORD_LEGACY: &str = "/ExternalConnect/ECPassword";
}

/// aMule's defaults (`Preferences.cpp`).
pub const DEFAULT_NICK: &str = "https://amule-org.github.io";
pub const DEFAULT_TCP_PORT: u16 = 4662;
pub const DEFAULT_UDP_PORT: u16 = 4672;
pub const DEFAULT_EC_PORT: u32 = 4712;
pub const DEFAULT_EC_ADDRESS: &str = "127.0.0.1";

/// A core subset of aMule's preferences, read as `CPreferences` reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preferences {
    pub nick: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub udp_enabled: bool,
    /// kB/s, 0 = unlimited.
    pub max_upload: u32,
    /// kB/s, 0 = unlimited.
    pub max_download: u32,
    pub slot_allocation: u32,
    /// `None`: not set; aMule then uses a value recommended for the system.
    pub max_connections: Option<u16>,
    pub max_connections_per_five_seconds: u16,
    pub max_sources_per_file: u16,
    /// `None`: not set or empty; aMule uses `<config dir>/Temp`.
    pub temp_dir: Option<String>,
    /// `None`: not set or empty; aMule uses its default incoming directory.
    pub incoming_dir: Option<String>,
    pub connect_to_ed2k: bool,
    pub connect_to_kad: bool,
    /// Log into a server at start-up.
    pub autoconnect: bool,
    /// Log into a server again when the connection is lost, and try the
    /// list again after every server failed.
    pub reconnect: bool,
    pub accept_external_connections: bool,
    pub ec_address: String,
    pub ec_port: u32,
    /// Stored verbatim; `ECSRP::LoadCredential` validates and migrates it.
    pub ec_password_verifier: Option<String>,
    pub ec_password_legacy: Option<String>,
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences::read(&ConfFile::new())
    }
}

impl Preferences {
    /// Read with aMule's defaults. Numbers that do not parse fall back to the
    /// default and are cast to the field's width as the C++ casts them
    /// (`(TYPE)long`), so 70000 in a `u16` port reads as 4464.
    pub fn read(conf: &ConfFile) -> Preferences {
        let long = |k: &str| conf.get(k).and_then(parse_long);
        let int = |k: &str, d: i64| long(k).unwrap_or(d);
        let flag = |k: &str, d: bool| long(k).map_or(d, |v| v != 0);
        let string = |k: &str, d: &str| conf.get(k).map_or_else(|| d.to_owned(), str::to_owned);
        // Cfg_Path with defaultIfEmpty: missing or empty means the default.
        let path = |k: &str| conf.get(k).filter(|v| !v.is_empty()).map(from_univ);
        Preferences {
            nick: string(keys::NICK, DEFAULT_NICK),
            tcp_port: int(keys::PORT, DEFAULT_TCP_PORT.into()) as u16,
            udp_port: int(keys::UDP_PORT, DEFAULT_UDP_PORT.into()) as u16,
            udp_enabled: flag(keys::UDP_ENABLE, true),
            max_upload: int(keys::MAX_UPLOAD, 0) as u32,
            max_download: int(keys::MAX_DOWNLOAD, 0) as u32,
            slot_allocation: int(keys::SLOT_ALLOCATION, 10) as u32,
            max_connections: long(keys::MAX_CONNECTIONS).map(|v| v as u16),
            max_connections_per_five_seconds: int(keys::MAX_CONNECTIONS_PER_FIVE_SECONDS, 50)
                as u16,
            max_sources_per_file: int(keys::MAX_SOURCES_PER_FILE, 300) as u16,
            temp_dir: path(keys::TEMP_DIR),
            incoming_dir: path(keys::INCOMING_DIR),
            connect_to_ed2k: flag(keys::CONNECT_TO_ED2K, true),
            connect_to_kad: flag(keys::CONNECT_TO_KAD, true),
            autoconnect: flag(keys::AUTOCONNECT, true),
            reconnect: flag(keys::RECONNECT, true),
            accept_external_connections: flag(keys::ACCEPT_EXTERNAL_CONNECTIONS, false),
            ec_address: string(keys::EC_ADDRESS, DEFAULT_EC_ADDRESS),
            ec_port: int(keys::EC_PORT, DEFAULT_EC_PORT.into()) as u32,
            ec_password_verifier: conf.get(keys::EC_PASSWORD_VERIFIER).map(str::to_owned),
            ec_password_legacy: conf.get(keys::EC_PASSWORD_LEGACY).map(str::to_owned),
        }
    }

    /// Write the fields back as aMule's `SaveToFile` does (numbers in
    /// decimal, booleans as 1/0, paths in their universal form). Unchanged
    /// values leave their lines alone. The EC password keys are not written:
    /// `Cfg_ECPassword::SaveToFile` does nothing, `ECSRPConfig` owns them.
    /// Optional fields that are `None` are left as they are.
    pub fn write(&self, conf: &mut ConfFile) {
        let b = |v: bool| if v { "1" } else { "0" };
        conf.set(keys::NICK, &self.nick);
        conf.set(keys::PORT, &self.tcp_port.to_string());
        conf.set(keys::UDP_PORT, &self.udp_port.to_string());
        conf.set(keys::UDP_ENABLE, b(self.udp_enabled));
        conf.set(keys::MAX_UPLOAD, &self.max_upload.to_string());
        conf.set(keys::MAX_DOWNLOAD, &self.max_download.to_string());
        conf.set(keys::SLOT_ALLOCATION, &self.slot_allocation.to_string());
        if let Some(v) = self.max_connections {
            conf.set(keys::MAX_CONNECTIONS, &v.to_string());
        }
        conf.set(
            keys::MAX_CONNECTIONS_PER_FIVE_SECONDS,
            &self.max_connections_per_five_seconds.to_string(),
        );
        conf.set(
            keys::MAX_SOURCES_PER_FILE,
            &self.max_sources_per_file.to_string(),
        );
        if let Some(p) = &self.temp_dir {
            conf.set(keys::TEMP_DIR, &to_univ(p));
        }
        if let Some(p) = &self.incoming_dir {
            conf.set(keys::INCOMING_DIR, &to_univ(p));
        }
        conf.set(keys::CONNECT_TO_ED2K, b(self.connect_to_ed2k));
        conf.set(keys::CONNECT_TO_KAD, b(self.connect_to_kad));
        conf.set(keys::AUTOCONNECT, b(self.autoconnect));
        conf.set(keys::RECONNECT, b(self.reconnect));
        conf.set(
            keys::ACCEPT_EXTERNAL_CONNECTIONS,
            b(self.accept_external_connections),
        );
        conf.set(keys::EC_ADDRESS, &self.ec_address);
        conf.set(keys::EC_PORT, &self.ec_port.to_string());
    }
}

#[cfg(test)]
mod tests;
