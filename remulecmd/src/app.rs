// SPDX-License-Identifier: GPL-2.0-or-later
//! What amulecmd does with a typed line: the requests it sends
//! (`CamulecmdApp::ProcessCommand`), how it prints the replies
//! (`CamulecmdApp::Process_Answer_v2`) and how errors read
//! (`CaMuleExternalConnector::Parse_Command`).

use std::net::ToSocketAddrs;

use remule_ec::codes::*;
use remule_ec::{Error, Packet, Tag};

use crate::commands::{command_set, id, Command};
use crate::commands::{
    CMD_ERR_INCOMPLETE, CMD_ERR_INVALID_ARG, CMD_ERR_MUST_HAVE_PARAM, CMD_ERR_NO_PARAM,
    CMD_ERR_PROCESS_CMD, CMD_ERR_SYNTAX, CMD_ID_HELP, CMD_ID_QUIT, CMD_OK,
};
use crate::format;

/// The daemon, as the commands see it.
pub trait Link {
    fn request(&mut self, p: &Packet) -> Result<Packet, Error>;
    /// Whether the daemon echoed this `EC_TAG_CAN_*` at login.
    fn echoed(&self, capability: u16) -> bool;
    /// Whether the connection is still up.
    fn connected(&self) -> bool;
}

const SEARCH_MAX_MIN_BITRATE_KBPS: u64 = 1_000_000;
const SEARCH_MAX_MIN_DURATION_SECONDS: u64 = 86_400;

/// One search result, as `download <n>` addresses it (`SearchFile`).
#[derive(Clone, Debug)]
struct SearchFile {
    name: String,
    size: u64,
    hash: [u8; 16],
    sources: u32,
}

impl SearchFile {
    fn from_tag(t: &Tag) -> Self {
        SearchFile {
            name: t.child_str(EC_TAG_PARTFILE_NAME),
            size: t.child_int(EC_TAG_PARTFILE_SIZE_FULL),
            hash: hash_of(t),
            sources: t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT) as u32,
        }
    }
}

fn hash_of(t: &Tag) -> [u8; 16] {
    t.child(EC_TAG_PARTFILE_HASH)
        .and_then(Tag::as_hash)
        .unwrap_or_default()
}

fn hash_hex(h: &[u8; 16]) -> String {
    h.iter().map(|b| format!("{b:02X}")).collect()
}

/// `CMD4Hash::Decode`: exactly 32 hex digits, either case.
fn decode_hash(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 || !b.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut h = [0u8; 16];
    for (i, out) in h.iter_mut().enumerate() {
        *out = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(h)
}

/// `wxString::ToULong`: optional leading blanks and '+', then only digits.
fn to_ulong(s: &str) -> Option<u64> {
    let s = s.trim_start();
    let s = s.strip_prefix('+').unwrap_or(s);
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

const DELIMS: &[char] = &[' ', '\t', '\r', '\n'];

/// `wxStringTokenizer` in its whitespace mode: empty tokens are skipped,
/// and what is left starts just past the delimiter that ended a token.
struct Tokens {
    s: String,
    pos: usize,
}

impl Tokens {
    fn new(s: &str) -> Self {
        Tokens {
            s: s.to_string(),
            pos: 0,
        }
    }

    fn has_more(&self) -> bool {
        self.s[self.pos..].contains(|c: char| !DELIMS.contains(&c))
    }

    fn next_token(&mut self) -> String {
        loop {
            let rest = &self.s[self.pos..];
            let (token, used) = match rest.find(DELIMS) {
                Some(i) => (rest[..i].to_string(), i + 1),
                None => (rest.to_string(), rest.len()),
            };
            self.pos += used;
            if !token.is_empty() || !self.has_more() {
                return token;
            }
        }
    }

    fn rest(&self) -> &str {
        &self.s[self.pos..]
    }

    fn set(&mut self, s: &str) {
        self.s = s.to_string();
        self.pos = 0;
    }
}

/// `ParseSizeWithSuffix`: bytes, or K, M, G (binary) or B after the number.
fn parse_size(s: &str) -> Option<u64> {
    let last = s.chars().last()?;
    let (digits, multiplier) = if last.is_ascii_digit() {
        (s, 1u64)
    } else {
        let m = match last.to_ascii_lowercase() {
            'k' => 1024,
            'm' => 1024 * 1024,
            'g' => 1024 * 1024 * 1024,
            'b' => 1,
            _ => return None,
        };
        (&s[..s.len() - last.len_utf8()], m)
    };
    Some(to_ulong(digits)?.wrapping_mul(multiplier))
}

/// `ParseSearchNumber`: decimal digits only, at most `maximum`.
fn parse_search_number(text: &str, maximum: u64) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().filter(|&v| v <= maximum)
}

/// `ReadSearchText`: a media filter's value, quoted to keep its spaces.
fn read_search_text(tokens: &mut Tokens) -> Option<String> {
    let tail = tokens.rest().trim_start_matches(DELIMS).to_string();
    if tail.is_empty() || tail.starts_with("--") {
        return None;
    }
    let first = tail.chars().next()?;
    if first == '"' || first == '\'' {
        let end = 1 + tail[1..].find(first)?;
        let after = &tail[end + 1..];
        if after.chars().next().is_some_and(|c| !c.is_whitespace()) {
            return None;
        }
        let value = tail[1..end].to_string();
        tokens.set(after);
        Some(value)
    } else {
        Some(tokens.next_token())
    }
}

#[derive(Default)]
struct SearchFilters {
    query: String,
    file_type: String,
    extension: String,
    avail: u32,
    min_size: u64,
    max_size: u64,
    min_bitrate: u64,
    min_length: u64,
    codec: String,
    title: String,
    album: String,
    artist: String,
}

impl SearchFilters {
    fn has_metadata(&self) -> bool {
        self.min_bitrate != 0
            || self.min_length != 0
            || !self.codec.is_empty()
            || !self.title.is_empty()
            || !self.album.is_empty()
            || !self.artist.is_empty()
    }
}

/// `ParseSearchFilters`: the flags out, the keywords left in order.
fn parse_search_filters(args: &str) -> Option<SearchFilters> {
    let mut f = SearchFilters::default();
    let mut remaining: Vec<String> = Vec::new();
    let mut tok = Tokens::new(args);
    let mut in_phrase = false;
    while tok.has_more() {
        let t = tok.next_token();
        if in_phrase || t.contains('"') {
            in_phrase ^= t.matches('"').count() % 2 == 1;
            remaining.push(t);
            continue;
        }
        match t.as_str() {
            "--type" => f.file_type = value(&mut tok)?,
            "--extension" | "--ext" => f.extension = value(&mut tok)?,
            "--avail" | "--availability" => f.avail = to_ulong(&value(&mut tok)?)? as u32,
            "--min-size" => f.min_size = parse_size(&value(&mut tok)?)?,
            "--max-size" => f.max_size = parse_size(&value(&mut tok)?)?,
            "--min-bitrate" => {
                f.min_bitrate = parse_search_number(&value(&mut tok)?, SEARCH_MAX_MIN_BITRATE_KBPS)?
            }
            "--min-duration" => {
                f.min_length =
                    parse_search_number(&value(&mut tok)?, SEARCH_MAX_MIN_DURATION_SECONDS)?
            }
            "--codec" => f.codec = read_search_text(&mut tok)?,
            "--title" => f.title = read_search_text(&mut tok)?,
            "--album" => f.album = read_search_text(&mut tok)?,
            "--artist" => f.artist = read_search_text(&mut tok)?,
            _ => remaining.push(t),
        }
    }
    f.query = remaining.join(" ");
    Some(f)
}

fn value(tok: &mut Tokens) -> Option<String> {
    tok.has_more().then(|| tok.next_token())
}

/// `sscanf("%3d.%3d.%3d.%3d:%5d")`: how many of the five it read.
fn scan_address(s: &str) -> (usize, [u32; 4], u32) {
    let b = s.as_bytes();
    let mut pos = 0;
    let mut nums = [0u32; 5];
    let widths = [3, 3, 3, 3, 5];
    let seps = *b"...:";
    for i in 0..5 {
        while pos < b.len() && b[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let start = pos;
        let mut neg = false;
        if pos < b.len() && (b[pos] == b'-' || b[pos] == b'+') {
            neg = b[pos] == b'-';
            pos += 1;
        }
        let digits_start = pos;
        while pos < b.len() && pos - start < widths[i] && b[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == digits_start {
            return (i, [nums[0], nums[1], nums[2], nums[3]], nums[4]);
        }
        let v: i64 = s[digits_start..pos].parse().unwrap_or(0);
        nums[i] = (if neg { -v } else { v }) as u32;
        if i < 4 {
            if pos < b.len() && b[pos] == seps[i] {
                pos += 1;
            } else {
                return (i + 1, [nums[0], nums[1], nums[2], nums[3]], nums[4]);
            }
        }
    }
    (5, [nums[0], nums[1], nums[2], nums[3]], nums[4])
}

/// `wxString::SubString(0, last)`: the first `last + 1` characters.
fn head(s: &str, last: usize) -> String {
    s.chars().take(last + 1).collect()
}

/// A float ratio as C's printf writes it, NaN and infinity included.
fn c_float(v: f64, decimals: usize) -> String {
    if v.is_nan() {
        "-nan".into()
    } else if v.is_infinite() {
        if v > 0.0 { "inf" } else { "-inf" }.into()
    } else {
        format!("{v:.decimals$}")
    }
}

/// amulecmd's state between lines.
pub struct App<L: Link> {
    link: Option<L>,
    commands: Command,
    /// `--space-separated`: list fields apart by spaces, as before tabs.
    pub space_separated: bool,
    out: String,
    cmdargs: String,
    rawcmdargs: String,
    lastcmdstr: String,
    last_cmd_id: i32,
    results: Vec<SearchFile>,
}

impl<L: Link> App<L> {
    pub fn new(link: Option<L>) -> Self {
        App {
            link,
            commands: command_set(),
            space_separated: false,
            out: String::new(),
            cmdargs: String::new(),
            rawcmdargs: String::new(),
            lastcmdstr: String::new(),
            last_cmd_id: 0,
            results: Vec::new(),
        }
    }

    /// What the commands have printed since last asked.
    pub fn take_output(&mut self) -> String {
        std::mem::take(&mut self.out)
    }

    pub fn connected(&self) -> bool {
        self.link.as_ref().is_some_and(Link::connected)
    }

    fn show(&mut self, s: &str) {
        self.out.push_str(s);
    }

    fn sep(&self, legacy: &'static str) -> &'static str {
        if self.space_separated {
            legacy
        } else {
            "\t"
        }
    }

    fn field(&self, value: &str) -> String {
        let out = value.replace("\r\n", " ").replace(['\n', '\r'], " ");
        if self.space_separated {
            out
        } else {
            out.replace('\t', " ")
        }
    }

    fn send(&mut self, p: &Packet) -> Option<Packet> {
        self.link.as_mut()?.request(p).ok()
    }

    fn echoed(&self, capability: u16) -> bool {
        self.link.as_ref().is_some_and(|l| l.echoed(capability))
    }

    /// `Parse_Command`: true when the line asks to quit.
    pub fn parse_command(&mut self, buffer: &str) -> bool {
        let cmd = buffer
            .split(DELIMS)
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if cmd.is_empty() {
            return false;
        }
        let found = self.commands.find(&cmd);
        if let Some(text) = &found.deprecation {
            self.show(&format!("\n{text}\n"));
        }
        self.cmdargs = found.args;
        self.lastcmdstr = found.path;
        let mut raw = Tokens::new(buffer);
        for _ in 0..self.lastcmdstr.split(' ').filter(|w| !w.is_empty()).count() {
            if !raw.has_more() {
                break;
            }
            raw.next_token();
        }
        self.rawcmdargs = raw.rest().to_string();
        let mut cmd_id = found.id;
        if cmd_id >= 0 {
            cmd_id = self.process_command(cmd_id);
        }
        let error = match cmd_id {
            CMD_ID_HELP => {
                let help = self.commands.help(&self.cmdargs);
                self.show(&help);
                ""
            }
            CMD_ERR_SYNTAX => "Syntax error!",
            CMD_ERR_PROCESS_CMD => {
                self.show("Error processing command - should never happen! Report bug, please\n");
                ""
            }
            CMD_ERR_NO_PARAM => "This command should not have any parameters.",
            CMD_ERR_MUST_HAVE_PARAM => "This command must have a parameter.",
            CMD_ERR_INVALID_ARG => "Invalid argument.",
            CMD_ERR_INCOMPLETE => "This is an incomplete command.",
            _ => "",
        };
        if !error.is_empty() {
            let mut help = String::from("help");
            if !self.lastcmdstr.is_empty() {
                help = format!("help {}", self.lastcmdstr);
            }
            self.show(&format!("{error}\nType '{help}' to get more help.\n"));
        }
        cmd_id == CMD_ID_QUIT
    }

    /// `Process_Answer`: each non-empty line of a reply after " > ".
    fn process_answer(&mut self, answer: &str) {
        for line in answer.split('\n').filter(|l| !l.is_empty()) {
            self.show(&format!(" > {line}\n"));
        }
    }

    fn prefs_request(section: u32) -> Packet {
        Packet::new(EC_OP_GET_PREFERENCES).with(Tag::int(EC_TAG_SELECT_PREFS, section.into()))
    }

    /// `CamulecmdApp::ProcessCommand`.
    fn process_command(&mut self, mut cmd_id: i32) -> i32 {
        let args = self.cmdargs.clone();
        let mut requests: Vec<Packet> = Vec::new();
        let mut search_type = EC_SEARCH_KAD;

        // The deprecated 'SetIPFilter'.
        if cmd_id == id::SET_IPFILTER {
            cmd_id = if args.is_empty() {
                id::GET_IPFILTER_STATE
            } else if args.eq_ignore_ascii_case("on") {
                id::SET_IPFILTER_ON
            } else if args.eq_ignore_ascii_case("off") {
                id::SET_IPFILTER_OFF
            } else {
                return CMD_ERR_INVALID_ARG;
            };
        }

        match cmd_id {
            id::STATUS => {
                requests.push(Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_CMD));
            }
            id::SHUTDOWN => requests.push(Packet::new(EC_OP_SHUTDOWN)),
            id::CONNECT => {
                if args.is_empty() {
                    requests.push(Packet::new(EC_OP_CONNECT));
                } else {
                    let Some((ip, port)) = Self::server_address(&args) else {
                        self.show("Invalid IP format. Use xxx.xxx.xxx.xxx:xxxx\n");
                        return CMD_OK;
                    };
                    requests.push(Packet::new(EC_OP_SERVER_CONNECT).with(Tag::ipv4(
                        EC_TAG_SERVER,
                        ip,
                        port,
                    )));
                }
            }
            id::CONNECT_ED2K => requests.push(Packet::new(EC_OP_SERVER_CONNECT)),
            id::CONNECT_KAD => requests.push(Packet::new(EC_OP_KAD_START)),
            id::DISCONNECT => requests.push(Packet::new(EC_OP_DISCONNECT)),
            id::DISCONNECT_ED2K => requests.push(Packet::new(EC_OP_SERVER_DISCONNECT)),
            id::DISCONNECT_KAD => requests.push(Packet::new(EC_OP_KAD_STOP)),
            id::RELOAD_SHARED => requests.push(Packet::new(EC_OP_SHAREDFILES_RELOAD)),
            id::RELOAD_IPFILTER_LOCAL => requests.push(Packet::new(EC_OP_IPFILTER_RELOAD)),
            id::RELOAD_IPFILTER_NET => requests
                .push(Packet::new(EC_OP_IPFILTER_UPDATE).with(Tag::string(EC_TAG_STRING, &args))),
            id::SET_IPFILTER_ON
            | id::SET_IPFILTER_CLIENTS_ON
            | id::SET_IPFILTER_SERVERS_ON
            | id::SET_IPFILTER_OFF
            | id::SET_IPFILTER_CLIENTS_OFF
            | id::SET_IPFILTER_SERVERS_OFF => {
                let on = matches!(
                    cmd_id,
                    id::SET_IPFILTER_ON | id::SET_IPFILTER_CLIENTS_ON | id::SET_IPFILTER_SERVERS_ON
                );
                cmd_id = match cmd_id {
                    id::SET_IPFILTER_CLIENTS_ON | id::SET_IPFILTER_CLIENTS_OFF => {
                        id::GET_IPFILTER_STATE_CLIENTS
                    }
                    id::SET_IPFILTER_SERVERS_ON | id::SET_IPFILTER_SERVERS_OFF => {
                        id::GET_IPFILTER_STATE_SERVERS
                    }
                    _ => id::GET_IPFILTER_STATE,
                };
                let mut prefs = Tag::empty(EC_TAG_PREFS_SECURITY);
                if cmd_id != id::GET_IPFILTER_STATE_SERVERS {
                    prefs = prefs.with(Tag::int(EC_TAG_IPFILTER_CLIENTS, on.into()));
                }
                if cmd_id != id::GET_IPFILTER_STATE_CLIENTS {
                    prefs = prefs.with(Tag::int(EC_TAG_IPFILTER_SERVERS, on.into()));
                }
                requests.push(Packet::new(EC_OP_SET_PREFERENCES).with(prefs));
                requests.push(Self::prefs_request(EC_PREFS_SECURITY));
            }
            id::GET_IPFILTER
            | id::GET_IPFILTER_STATE
            | id::GET_IPFILTER_STATE_CLIENTS
            | id::GET_IPFILTER_STATE_SERVERS
            | id::GET_IPFILTER_LEVEL => requests.push(Self::prefs_request(EC_PREFS_SECURITY)),
            id::SET_IPFILTER_LEVEL => {
                // Without an argument, the deprecated 'IPLevel' only reads it.
                if !args.is_empty() {
                    match to_ulong(&args) {
                        Some(level) if level < 256 => requests.push(
                            Packet::new(EC_OP_SET_PREFERENCES).with(
                                Tag::empty(EC_TAG_PREFS_SECURITY)
                                    .with(Tag::int(EC_TAG_IPFILTER_LEVEL, level)),
                            ),
                        ),
                        _ => return CMD_ERR_INVALID_ARG,
                    }
                }
                cmd_id = id::GET_IPFILTER_LEVEL;
                requests.push(Self::prefs_request(EC_PREFS_SECURITY));
            }
            id::PAUSE | id::CANCEL | id::RESUME => {
                if args.is_empty() {
                    self.show("This command requires an argument. Valid arguments: 'all', filename, or a number.\n");
                    return CMD_OK;
                }
                let all = Packet::new(EC_OP_GET_DLOAD_QUEUE).with_detail(EC_DETAIL_CMD);
                if let Some(queue) = self.send(&all) {
                    let mut request = Packet::new(match cmd_id {
                        id::PAUSE => EC_OP_PARTFILE_PAUSE,
                        id::CANCEL => EC_OP_PARTFILE_DELETE,
                        _ => EC_OP_PARTFILE_RESUME,
                    });
                    let mut tokens = Tokens::new(&args);
                    while tokens.has_more() {
                        let token = tokens.next_token();
                        if token == "all" {
                            for t in &queue.tags {
                                request = request.with(Tag::hash(EC_TAG_PARTFILE, hash_of(t)));
                            }
                            break;
                        } else if let Some(hash) = decode_hash(token.trim()) {
                            if hash != [0; 16] {
                                self.show(&format!("Processing by hash: {token}\n"));
                                request = request.with(Tag::hash(EC_TAG_PARTFILE, hash));
                            }
                        } else {
                            for t in &queue.tags {
                                let met = Self::part_met_name(t);
                                // The name, XXX.part.met, XXX.part or XXX.
                                let matches = t.child_str(EC_TAG_PARTFILE_NAME) == token
                                    || met == token
                                    || (met.len() >= 4 && met[..met.len() - 4] == token)
                                    || (met.len() >= 9 && met[..met.len() - 9] == token);
                                if matches {
                                    self.show(&format!("Processing by filename: {token}\n"));
                                    request = request.with(Tag::hash(EC_TAG_PARTFILE, hash_of(t)));
                                }
                            }
                        }
                    }
                    requests.push(request);
                }
            }
            id::PRIORITY_LOW | id::PRIORITY_NORMAL | id::PRIORITY_HIGH | id::PRIORITY_AUTO => {
                if args.is_empty() {
                    self.show("This command requires an argument. Valid arguments: a file hash.\n");
                    return CMD_OK;
                }
                match decode_hash(args.trim()) {
                    None => {
                        self.show("Not a valid hash (length should be exactly 32 chars)\n");
                        return CMD_OK;
                    }
                    Some(h) if h == [0; 16] => {
                        self.show("Not a valid number\n");
                        return CMD_OK;
                    }
                    Some(hash) => {
                        let prio = match cmd_id {
                            id::PRIORITY_LOW => format::PR_LOW,
                            id::PRIORITY_NORMAL => format::PR_NORMAL,
                            id::PRIORITY_HIGH => format::PR_HIGH,
                            _ => format::PR_AUTO,
                        };
                        requests.push(
                            Packet::new(EC_OP_PARTFILE_PRIO_SET).with(
                                Tag::hash(EC_TAG_PARTFILE, hash)
                                    .with(Tag::int(EC_TAG_PARTFILE_PRIO, prio.into())),
                            ),
                        );
                    }
                }
            }
            id::SHOW_UL => requests.push(Packet::new(EC_OP_GET_ULOAD_QUEUE)),
            id::SHOW_DL => requests.push(Packet::new(EC_OP_GET_DLOAD_QUEUE)),
            id::SHOW_LOG => requests.push(Packet::new(EC_OP_GET_LOG)),
            id::SHOW_SERVERS => {
                requests.push(Packet::new(EC_OP_GET_SERVER_LIST).with_detail(EC_DETAIL_CMD))
            }
            id::SHOW_SHARED => requests.push(Packet::new(EC_OP_GET_SHARED_FILES)),
            id::RESET_LOG => requests.push(Packet::new(EC_OP_RESET_LOG)),
            id::ADDLINK => {
                let mut link = args.clone();
                if link
                    .get(..7)
                    .is_some_and(|p| p.eq_ignore_ascii_case("ed2k://"))
                {
                    // aMule wants AICH hashes after |/|.
                    if link.contains("|h=") && !link.contains("|/|h=") {
                        link = link.replace("|h=", "|/|h=");
                    }
                    link = restore_encoded_pipes(&link);
                }
                requests.push(Packet::new(EC_OP_ADD_LINK).with(Tag::string(EC_TAG_STRING, &link)));
            }
            id::SET_BWLIMIT_UP | id::SET_BWLIMIT_DOWN => {
                let name = if cmd_id == id::SET_BWLIMIT_UP {
                    EC_TAG_CONN_MAX_UL
                } else {
                    EC_TAG_CONN_MAX_DL
                };
                match to_ulong(&args) {
                    Some(limit) if limit <= u64::from(u32::MAX) => requests
                        .push(Packet::new(EC_OP_SET_PREFERENCES).with(
                            Tag::empty(EC_TAG_PREFS_CONNECTIONS).with(Tag::int(name, limit)),
                        )),
                    _ => return CMD_ERR_INVALID_ARG,
                }
                requests.push(Self::prefs_request(EC_PREFS_CONNECTIONS));
            }
            id::GET_BWLIMITS => requests.push(Self::prefs_request(EC_PREFS_CONNECTIONS)),
            id::SET_ENDGAME => {
                let val = if args.eq_ignore_ascii_case("on") || args == "1" {
                    1
                } else if args.eq_ignore_ascii_case("off") || args == "0" {
                    0
                } else {
                    return CMD_ERR_INVALID_ARG;
                };
                requests.push(Packet::new(EC_OP_SET_PREFERENCES).with(
                    Tag::empty(EC_TAG_PREFS_FILES).with(Tag::int(EC_TAG_FILES_ENDGAME, val)),
                ));
            }
            id::GET_ENDGAME => requests.push(Self::prefs_request(EC_PREFS_FILES)),
            id::STATTREE => {
                let mut request = Packet::new(EC_OP_GET_STATSTREE);
                if !args.is_empty() {
                    match to_ulong(&args) {
                        Some(max) if max < 256 => {
                            request = request.with(Tag::int(EC_TAG_STATTREE_CAPPING, max))
                        }
                        _ => return CMD_ERR_INVALID_ARG,
                    }
                }
                requests.push(request);
            }
            id::SEARCH_ALL | id::SEARCH_GLOBAL | id::SEARCH_LOCAL | id::SEARCH_KAD => {
                if cmd_id == id::SEARCH_ALL {
                    if !self.echoed(EC_TAG_CAN_SEARCH_ALL) {
                        self.show("The connected daemon does not support All searches.\n");
                        return CMD_ERR_INVALID_ARG;
                    }
                    search_type = EC_SEARCH_ALL;
                } else if cmd_id == id::SEARCH_GLOBAL {
                    search_type = EC_SEARCH_GLOBAL;
                } else if cmd_id == id::SEARCH_LOCAL {
                    search_type = EC_SEARCH_LOCAL;
                }
                if !args.is_empty() {
                    let Some(f) = parse_search_filters(&self.rawcmdargs.clone()) else {
                        self.show(
                            "Invalid search filter syntax.\nType 'help search' to get more help.\n",
                        );
                        return CMD_ERR_INVALID_ARG;
                    };
                    if f.query.is_empty() {
                        self.show(
                            "No search keyword provided.\nType 'help search' to get more help.\n",
                        );
                        return CMD_ERR_INVALID_ARG;
                    }
                    if f.has_metadata() && !self.echoed(EC_TAG_CAN_SEARCH_METADATA) {
                        self.show("The connected daemon does not support media search filters.\n");
                        return CMD_ERR_INVALID_ARG;
                    }
                    requests
                        .push(Packet::new(EC_OP_SEARCH_START).with(search_tag(&f, search_type)));
                }
            }
            id::SEARCH => {
                self.show("No search type defined.\nType 'help search' to get more help.\n");
            }
            id::SEARCH_LIST | id::SEARCH_STOP | id::SEARCH_MORE => {
                if !(self.echoed(EC_TAG_CAN_MULTI_SEARCH) && self.echoed(EC_TAG_CAN_SEARCH_LIST)) {
                    self.show("The connected daemon does not support search management.\n");
                    return CMD_ERR_INVALID_ARG;
                }
                let mut sid = 0;
                if cmd_id != id::SEARCH_LIST {
                    match parse_search_number(&args, u64::from(u32::MAX)) {
                        Some(v) if v != 0 => sid = v,
                        _ => {
                            self.show("A search ID from 'search list' is required.\n");
                            return CMD_ERR_INVALID_ARG;
                        }
                    }
                }
                let mut request = Packet::new(match cmd_id {
                    id::SEARCH_LIST => EC_OP_SEARCH_LIST,
                    id::SEARCH_STOP => EC_OP_SEARCH_STOP,
                    _ => EC_OP_SEARCH_REQUEST_MORE,
                });
                if cmd_id != id::SEARCH_LIST {
                    request = request.with(Tag::int(EC_TAG_SEARCH_ID, sid));
                }
                requests.push(request);
            }
            id::SEARCH_RESULTS | id::SEARCH_PROGRESS => {
                let mut request = Packet::new(if cmd_id == id::SEARCH_RESULTS {
                    EC_OP_SEARCH_RESULTS
                } else {
                    EC_OP_SEARCH_PROGRESS
                });
                if let Some(sid) = to_ulong(args.trim_end()) {
                    request = request.with(Tag::int(EC_TAG_SEARCH_ID, u64::from(sid as u32)));
                }
                requests.push(request);
            }
            id::DOWNLOAD => {
                let mut tokens = Tokens::new(&args);
                let Some(n) = to_ulong(&tokens.next_token()) else {
                    return CMD_ERR_INVALID_ARG;
                };
                let has_search_id = tokens.has_more();
                let mut sid = 0;
                if has_search_id {
                    match to_ulong(&tokens.next_token()) {
                        Some(v) => sid = v,
                        None => return CMD_ERR_INVALID_ARG,
                    }
                }
                // Fetch first: a one-shot run has listed nothing, and an id may
                // name a search not listed.
                if has_search_id || self.results.is_empty() {
                    let mut request = Packet::new(EC_OP_SEARCH_RESULTS);
                    if has_search_id {
                        request = request.with(Tag::int(EC_TAG_SEARCH_ID, u64::from(sid as u32)));
                    }
                    let Some(reply) = self.send(&request) else {
                        return CMD_ERR_PROCESS_CMD;
                    };
                    if reply.tag(EC_TAG_SEARCH_EXPIRED).is_some() {
                        self.show("Search expired or unknown ID. Start a new search.\n");
                        return CMD_OK;
                    }
                    self.store_results(&reply);
                }
                let Some(file) = usize::try_from(n)
                    .ok()
                    .and_then(|n| self.results.get(n))
                    .cloned()
                else {
                    return CMD_ERR_INVALID_ARG;
                };
                self.show(&format!("Download File: {n} {}\n", file.name));
                requests.push(Packet::new(EC_OP_DOWNLOAD_SEARCH_RESULT).with(
                    Tag::hash(EC_TAG_PARTFILE, file.hash).with(Tag::int(EC_TAG_PARTFILE_CAT, 0)),
                ));
            }
            _ => return CMD_ERR_PROCESS_CMD,
        }

        self.last_cmd_id = cmd_id;

        for request in requests {
            if request.opcode == EC_OP_SHUTDOWN {
                // Wait for the daemon to acknowledge or close: leaving at once
                // could reset the connection before the request arrives.
                let _ = self.send(&request);
                return CMD_ID_QUIT;
            }
            if let Some(reply) = self.send(&request) {
                self.process_answer_v2(&reply);
            }
        }
        CMD_OK
    }

    /// A dotted address and port, or a name to look up.
    fn server_address(args: &str) -> Option<([u8; 4], u16)> {
        let (read, ip, port) = scan_address(args);
        if read == 5 {
            return Some((ip.map(|b| b as u8), port as u16));
        }
        let (name, port) = args.split_once(':').unwrap_or((args, ""));
        let port = port.parse::<i64>().ok()?;
        if name.is_empty() {
            return None;
        }
        let addr = (name, port as u16)
            .to_socket_addrs()
            .ok()?
            .find_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(v4),
                _ => None,
            })?;
        Some((addr.ip().octets(), port as u16))
    }

    fn part_met_name(t: &Tag) -> String {
        match t.child_int(EC_TAG_PARTFILE_PARTMETID) as u16 {
            0 => String::new(),
            id => format!("{id:03}.part.met"),
        }
    }

    fn store_results(&mut self, reply: &Packet) {
        self.results = reply.tags.iter().map(SearchFile::from_tag).collect();
    }

    /// `ShowResults`: printed as it comes, before the reply's summary line.
    fn show_results(&mut self) {
        const NAME_MAX: usize = 80;
        const MB_MAX: usize = 5;
        const NR_MAX: usize = 5;
        let mut out = String::from(
            "Nr.    Filename:                                                                        Size(MiB):  Sources: \n",
        );
        out += &"-".repeat(107);
        out += "\n";
        for (n, file) in self.results.iter().enumerate() {
            let line = head(&format!("{n}.      "), NR_MAX) + &file.name + &" ".repeat(NAME_MAX);
            let mb = format!("     {}", file.size / 1024 / 1024);
            let kb = format!(".{:03}", file.size / 1024 % 1024);
            let line = head(&line, NR_MAX + NAME_MAX + MB_MAX - mb.chars().count()) + &mb + &kb;
            out += &format!("{line}     {}\n", file.sources as i32);
        }
        self.out.push_str(&out);
    }

    /// `CamulecmdApp::Process_Answer_v2`.
    fn process_answer_v2(&mut self, reply: &Packet) {
        let mut s = String::new();
        match reply.opcode {
            EC_OP_NOOP => s += "Operation was successful.",
            EC_OP_FAILED => match reply.tags.first() {
                Some(t) if t.ty == EC_TAGTYPE_STRING => {
                    s += &format!("Request failed with the following error: {}", t.as_str())
                }
                _ => s += "Request failed with an unknown error.",
            },
            EC_OP_SET_PREFERENCES => {
                let empty = Tag::empty(0);
                let security = reply.tag(EC_TAG_PREFS_SECURITY).unwrap_or(&empty);
                if let Some(level) = security.child(EC_TAG_IPFILTER_LEVEL) {
                    let on_off = |name| if security.has(name) { "ON" } else { "OFF" };
                    let last = self.last_cmd_id;
                    if matches!(
                        last,
                        id::GET_IPFILTER | id::GET_IPFILTER_STATE | id::GET_IPFILTER_STATE_CLIENTS
                    ) {
                        s += &format!(
                            "IP filtering for clients is {}.\n",
                            on_off(EC_TAG_IPFILTER_CLIENTS)
                        );
                    }
                    if matches!(
                        last,
                        id::GET_IPFILTER | id::GET_IPFILTER_STATE | id::GET_IPFILTER_STATE_SERVERS
                    ) {
                        s += &format!(
                            "IP filtering for servers is {}.\n",
                            on_off(EC_TAG_IPFILTER_SERVERS)
                        );
                    }
                    if matches!(last, id::GET_IPFILTER | id::GET_IPFILTER_LEVEL) {
                        s += &format!("Current IPFilter Level is {}.\n", level.as_int() as i64);
                    }
                }
                let conn = reply.tag(EC_TAG_PREFS_CONNECTIONS).unwrap_or(&empty);
                if let (Some(up), Some(down)) = (
                    conn.child(EC_TAG_CONN_MAX_UL),
                    conn.child(EC_TAG_CONN_MAX_DL),
                ) {
                    s += &format!(
                        "Bandwidth limits: Up: {} KiB/s, Down: {} KiB/s.\n",
                        up.as_int() as u32,
                        down.as_int() as u32
                    );
                }
                let files = reply.tag(EC_TAG_PREFS_FILES).unwrap_or(&empty);
                s += &format!(
                    "Endgame source rotation is {}.\n",
                    if files.has(EC_TAG_FILES_ENDGAME) {
                        "ON"
                    } else {
                        "OFF"
                    }
                );
            }
            EC_OP_STRINGS => {
                for t in &reply.tags {
                    if t.name == EC_TAG_SEARCH_ID {
                        s += &format!("Search started (id {}).\n", t.as_int() as u32);
                    } else if t.ty == EC_TAGTYPE_STRING {
                        s += &t.as_str();
                        s += "\n";
                    }
                }
            }
            EC_OP_STATS => s += &stats_text(reply),
            EC_OP_DLOAD_QUEUE => {
                for t in &reply.tags {
                    s += &self.download_row(t);
                }
            }
            EC_OP_ULOAD_QUEUE => {
                for t in &reply.tags {
                    let (Some(client), Some(file), Some(xfer), Some(speed)) = (
                        t.child(EC_TAG_CLIENT_NAME),
                        t.child(EC_TAG_PARTFILE_NAME),
                        t.child(EC_TAG_PARTFILE_SIZE_XFER),
                        t.child(EC_TAG_CLIENT_UP_SPEED),
                    ) else {
                        continue;
                    };
                    s += &format!(
                        "\n{:10}{}{}{}{}{}{}{}{}",
                        t.as_int() as u32,
                        self.sep(" "),
                        self.field(&client.as_str()),
                        self.sep(" "),
                        self.field(&file.as_str()),
                        self.sep(" "),
                        format::xbytes(xfer.as_int()),
                        self.sep(" "),
                        format::speed(speed.as_int() as u32)
                    );
                }
            }
            EC_OP_LOG => {
                // Log records start with their time stamp, without the reply's " > ".
                for t in &reply.tags {
                    let text = format::log_text(&t.as_str());
                    self.show(&text);
                }
                return;
            }
            EC_OP_SERVER_LIST => {
                for t in &reply.tags {
                    let Some(name) = t.child(EC_TAG_SERVER_NAME) else {
                        continue;
                    };
                    let (ip, port) = t.as_ipv4().unwrap_or_default();
                    let mut addr = format!("[{}.{}.{}.{}:{port}]", ip[0], ip[1], ip[2], ip[3]);
                    if self.space_separated {
                        // The column padding was the separator.
                        while addr.len() < 24 {
                            addr.push(' ');
                        }
                    } else {
                        addr.push('\t');
                    }
                    s += &addr;
                    s += &self.field(&name.as_str());
                    if let Some(country) = t.child(EC_TAG_SERVER_COUNTRY) {
                        let country = country.as_str();
                        if !country.is_empty() {
                            s += &format!("{}[{country}]", self.sep(" "));
                        }
                    }
                    s += "\n";
                }
            }
            EC_OP_SHARED_FILES => {
                for t in &reply.tags {
                    s += &self.shared_row(t);
                }
            }
            EC_OP_STATSTREE => s += &format::stat_tree(reply.tag(EC_TAG_STATTREE_NODE), 0),
            EC_OP_SEARCH_LIST => {
                if reply.tags.is_empty() {
                    s += "No retained searches.\n";
                }
                for t in reply.tags_named(EC_TAG_SEARCH_ID) {
                    s += &format!(
                        "{}{}{}\n",
                        t.as_int() as u32,
                        self.sep(" "),
                        self.field(&t.child_str(EC_TAG_SEARCH_NAME))
                    );
                }
            }
            EC_OP_MISC_DATA => {
                if self.last_cmd_id == id::SEARCH_MORE {
                    s += match reply.tag(EC_TAG_SEARCH_MORE_REASKABLE) {
                        None => "More-results request processed; availability is unknown.\n",
                        Some(t) if t.as_int() != 0 => {
                            "More-results request processed; further requests remain possible.\n"
                        }
                        Some(_) => "No further results can be requested for this search.\n",
                    };
                } else if self.last_cmd_id == id::SEARCH_STOP {
                    // The daemon acknowledges unknown IDs too.
                    s += "Search stop request processed; retained results were not removed.\n";
                }
            }
            EC_OP_SEARCH_RESULTS => {
                if reply.tag(EC_TAG_SEARCH_EXPIRED).is_some() {
                    s += "Search expired or unknown ID. Start a new search.\n";
                } else {
                    self.store_results(reply);
                    s += &format!("Number of search results: {}\n", reply.tags.len());
                    self.show_results();
                }
            }
            EC_OP_SEARCH_PROGRESS => s += &format::search_progress(reply),
            op => s += &format!("Received an unknown reply from the server, OpCode = {op:#x}."),
        }
        self.process_answer(&s);
    }

    /// One `show dl` record: two lines, the second after a tab.
    fn download_row(&self, t: &Tag) -> String {
        let size = t.child_int(EC_TAG_PARTFILE_SIZE_FULL);
        let done = t.child_int(EC_TAG_PARTFILE_SIZE_DONE);
        let sources = t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT) as u16;
        let not_current = t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_NOT_CURRENT) as u16;
        let xfer = t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER) as u16;
        let a4af = t.child_int(EC_TAG_PARTFILE_SOURCE_COUNT_A4AF) as u16;
        let prio = t.child_int(EC_TAG_PARTFILE_PRIO) as u8;
        let percent = f64::from(done as f32 / size as f32) * 100.0;
        let mut s = format!(
            "{}{}{}\n\t [{}%]{}{:4}/{:4}{}",
            hash_hex(&hash_of(t)),
            self.sep(" "),
            self.field(&t.child_str(EC_TAG_PARTFILE_NAME)),
            c_float(percent, 1),
            self.sep(" "),
            i32::from(sources) - i32::from(not_current),
            sources,
            self.sep(" ")
        );
        if a4af != 0 {
            s += &format!("+{a4af:02}{}", self.sep(" "));
        } else {
            s += self.sep("    ");
        }
        if xfer != 0 {
            s += &format!("({xfer:02}){}", self.sep(" - "));
        } else {
            s += self.sep("     - ");
        }
        s += format::file_status(
            t.child_int(EC_TAG_PARTFILE_STATUS) as u8,
            t.child_int(EC_TAG_PARTFILE_STOPPED) != 0,
            xfer,
        );
        s += self.sep(" - ");
        s += &Self::part_met_name(t);
        s += self.sep(" - ");
        s += if prio < 10 {
            format::priority(prio, false)
        } else {
            format::priority(prio - 10, true)
        };
        if xfer > 0 {
            s += self.sep(" - ");
            s += &format::speed(t.child_int(EC_TAG_PARTFILE_SPEED) as u32);
        }
        s += "\n";
        s
    }

    /// One `show shared` record.
    fn shared_row(&self, t: &Tag) -> String {
        let mut s = format!("{}{}", hash_hex(&hash_of(t)), self.sep(" "));
        let path = t.child_str(EC_TAG_KNOWNFILE_FILENAME);
        let is_part = path
            .strip_suffix(".part")
            .is_some_and(|stem| stem.chars().all(|c| c.is_ascii_digit()));
        if is_part {
            s += "[PartFile]";
            s += self.sep(" ");
        } else {
            s += &self.field(&path);
            s.push(std::path::MAIN_SEPARATOR);
        }
        let up = t.child_int(EC_TAG_KNOWNFILE_PRIO) as u8;
        let xferred_all = t.child_int(EC_TAG_KNOWNFILE_XFERRED_ALL);
        let size = t.child_int(EC_TAG_PARTFILE_SIZE_FULL);
        s += &format!(
            "{}\n\t{}{}{}({}){}{}({}){}{} ({}){}{}\n",
            self.field(&t.child_str(EC_TAG_PARTFILE_NAME)),
            format::priority(up % 10, up >= 10),
            self.sep(" - "),
            t.child_int(EC_TAG_KNOWNFILE_REQ_COUNT) as u16,
            t.child_int(EC_TAG_KNOWNFILE_REQ_COUNT_ALL) as u32 as i32,
            self.sep(" / "),
            t.child_int(EC_TAG_KNOWNFILE_ACCEPT_COUNT) as u16,
            t.child_int(EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL) as u32 as i32,
            self.sep(" - "),
            format::xbytes(t.child_int(EC_TAG_KNOWNFILE_XFERRED)),
            format::xbytes(xferred_all),
            self.sep(" - "),
            c_float(f64::from(xferred_all as f32 / size as f32), 2)
        );
        s
    }
}

/// `status`: the networks, then the rates.
fn stats_text(reply: &Packet) -> String {
    let mut s = String::new();
    if let Some(conn) = reply.tag(EC_TAG_CONNSTATE) {
        let bits = conn.as_int();
        s += "eD2k: ";
        if bits & 0x01 != 0 {
            if let Some(server) = conn.child(EC_TAG_SERVER) {
                if let Some(name) = server.child(EC_TAG_SERVER_NAME) {
                    let (ip, port) = server.as_ipv4().unwrap_or_default();
                    let low_id = (conn.child_int(EC_TAG_ED2K_ID) as u32) < 0x0100_0000;
                    s += &format!(
                        "Connected to {} [{}.{}.{}.{}:{port}] {}",
                        name.as_str(),
                        ip[0],
                        ip[1],
                        ip[2],
                        ip[3],
                        if low_id { "with LowID" } else { "with HighID" }
                    );
                }
            }
        } else if bits & 0x02 != 0 {
            s += "Now connecting";
        } else {
            s += "Not connected";
        }
        s += "\nKad: ";
        if bits & 0x10 != 0 {
            if bits & 0x04 != 0 {
                s += if bits & 0x08 != 0 {
                    "Connected (firewalled)"
                } else {
                    "Connected (ok)"
                };
            } else {
                s += "Not connected";
            }
        } else {
            s += "Not running";
        }
        s += "\n";
    }
    if let Some(t) = reply.tag(EC_TAG_STATS_DL_SPEED) {
        s += &format!("\nDownload:\t{}", format::speed(t.as_int() as u32));
    }
    if let Some(t) = reply.tag(EC_TAG_STATS_UL_SPEED) {
        s += &format!("\nUpload:\t{}", format::speed(t.as_int() as u32));
    }
    if let Some(t) = reply.tag(EC_TAG_STATS_UL_QUEUE_LEN) {
        s += &format!("\nClients in queue:\t{}\n", t.as_int() as i32);
    }
    if let Some(t) = reply.tag(EC_TAG_STATS_TOTAL_SRC_COUNT) {
        s += &format!("\nTotal sources:\t{}\n", t.as_int() as i32);
    }
    s
}

/// `CEC_Search_Tag`.
fn search_tag(f: &SearchFilters, search_type: u8) -> Tag {
    let mut t = Tag::int(EC_TAG_SEARCH_TYPE, search_type.into())
        .with(Tag::string(EC_TAG_SEARCH_NAME, &f.query))
        .with(Tag::string(EC_TAG_SEARCH_FILE_TYPE, &f.file_type));
    if !f.extension.is_empty() {
        t = t.with(Tag::string(EC_TAG_SEARCH_EXTENSION, &f.extension));
    }
    if f.avail != 0 {
        t = t.with(Tag::int(EC_TAG_SEARCH_AVAILABILITY, f.avail.into()));
    }
    if f.min_size != 0 {
        t = t.with(Tag::int(EC_TAG_SEARCH_MIN_SIZE, f.min_size));
    }
    if f.max_size != 0 {
        t = t.with(Tag::int(EC_TAG_SEARCH_MAX_SIZE, f.max_size));
    }
    if f.min_bitrate != 0 {
        t = t.with(Tag::int(EC_TAG_SEARCH_MIN_BITRATE, f.min_bitrate));
    }
    if f.min_length != 0 {
        t = t.with(Tag::int(EC_TAG_SEARCH_MIN_LENGTH, f.min_length));
    }
    for (name, value) in [
        (EC_TAG_SEARCH_CODEC, &f.codec),
        (EC_TAG_SEARCH_TITLE, &f.title),
        (EC_TAG_SEARCH_ALBUM, &f.album),
        (EC_TAG_SEARCH_ARTIST, &f.artist),
    ] {
        if !value.is_empty() {
            t = t.with(Tag::string(name, value));
        }
    }
    t
}

/// `RestoreEncodedPipes`: `%7C` (either case) back to `|`, for daemons that
/// do not do it themselves.
fn restore_encoded_pipes(link: &str) -> String {
    let mut out = String::with_capacity(link.len());
    let mut rest = link;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        if rest[i..].len() >= 3 && rest[i + 1..i + 3].eq_ignore_ascii_case("7c") {
            out.push('|');
            rest = &rest[i + 3..];
        } else {
            out.push('%');
            rest = &rest[i + 1..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
#[path = "tests_app.rs"]
mod tests;
