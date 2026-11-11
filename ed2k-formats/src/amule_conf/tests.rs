// SPDX-License-Identifier: GPL-2.0-or-later
//! amule.conf tests. aMule has no unit test for its config file, so these
//! follow wxFileConfig's parser/writer and Preferences.cpp.

use super::*;

/// A realistic amule.conf as aMule writes it (abridged), with a comment and
/// a CRLF line thrown in.
const SAMPLE: &str = "[eMule]\n\
AppVersion=3.3.0\n\
Nick=https://amule-org.github.io\n\
QueueSizePref=50\n\
MaxUpload=120\n\
MaxDownload=0\n\
SlotAllocation=10\n\
Port=4662\n\
UDPPort=4672\n\
UDPEnable=1\n\
Address=\n\
MaxSourcesPerFile=300\n\
MaxConnections=500\n\
MaxConnectionsPerFiveSeconds=50\n\
ConnectToKad=1\n\
ConnectToED2K=0\n\
TempDir=/home/amule/.aMule/Temp\n\
IncomingDir=/home/amule/.aMule/Incoming\n\
; a comment the user added\r\n\
[ExternalConnect]\n\
UseSrcSeeds=0\n\
AcceptExternalConnections=1\n\
ECAddress=\n\
ECPort=4712\n\
ECPasswordVerifier=v1:15:8:1:00112233445566778899aabbccddeeff:abcd\n\
[WebServer]\n\
Enabled=0\n\
Password=\n\
Template=default\n";

#[test]
fn unchanged_file_round_trips_byte_for_byte() {
    let f = ConfFile::from_bytes(SAMPLE.as_bytes());
    assert!(f.warnings().is_empty(), "{:?}", f.warnings());
    assert_eq!(f.to_bytes(), SAMPLE.as_bytes());
    // Also with a BOM, no final newline, and as Latin-1.
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(b"[eMule]\nNick=x");
    assert_eq!(ConfFile::from_bytes(&bom).to_bytes(), bom);
    let latin1 = b"[eMule]\nNick=caf\xE9\n".to_vec();
    let f = ConfFile::from_bytes(&latin1);
    assert_eq!(f.encoding(), Encoding::Latin1);
    assert_eq!(f.get("/eMule/Nick"), Some("café"));
    assert_eq!(f.to_bytes(), latin1);
}

#[test]
fn preferences_read_with_amule_rules() {
    let p = Preferences::read(&ConfFile::parse(SAMPLE));
    assert_eq!(p.nick, "https://amule-org.github.io");
    assert_eq!((p.tcp_port, p.udp_port, p.udp_enabled), (4662, 4672, true));
    assert_eq!(
        (p.max_upload, p.max_download, p.slot_allocation),
        (120, 0, 10)
    );
    assert_eq!(p.max_connections, Some(500));
    assert_eq!((p.connect_to_kad, p.connect_to_ed2k), (true, false));
    assert_eq!(p.temp_dir.as_deref(), Some("/home/amule/.aMule/Temp"));
    assert!(p.accept_external_connections);
    // An empty ECAddress is read as empty, not as the default: Cfg_Str
    // only uses the default when the key is missing.
    assert_eq!(p.ec_address, "");
    assert_eq!(p.ec_port, 4712);
    assert_eq!(
        p.ec_password_verifier.as_deref(),
        Some("v1:15:8:1:00112233445566778899aabbccddeeff:abcd")
    );
    assert_eq!(p.ec_password_legacy, None);
}

#[test]
fn defaults_when_keys_are_missing() {
    let p = Preferences::default();
    assert_eq!(p.nick, DEFAULT_NICK);
    assert_eq!((p.tcp_port, p.udp_port, p.ec_port), (4662, 4672, 4712));
    assert_eq!(p.ec_address, "127.0.0.1");
    assert_eq!(
        (
            p.max_sources_per_file,
            p.max_connections_per_five_seconds,
            p.slot_allocation
        ),
        (300, 50, 10)
    );
    assert_eq!(p.max_connections, None);
    assert_eq!((p.temp_dir, p.incoming_dir), (None, None));
    assert!(
        p.connect_to_ed2k && p.connect_to_kad && p.udp_enabled && !p.accept_external_connections
    );
}

#[test]
fn numbers_parse_like_wxconfig() {
    assert_eq!(parse_long("42"), Some(42));
    assert_eq!(
        parse_long("  42  "),
        Some(42),
        "leading spaces (strtol) and trailing (Trim)"
    );
    assert_eq!(parse_long("+7"), Some(7));
    assert_eq!(parse_long("-1"), Some(-1));
    assert_eq!(parse_long(""), None);
    assert_eq!(parse_long("0x10"), None, "base 10 only");
    assert_eq!(parse_long("12abc"), None, "must consume everything");
    assert_eq!(parse_long("99999999999999999999"), None, "overflow");
    // Unparseable -> default; out of range -> the C++ cast truncates.
    let f = ConfFile::parse("[eMule]\nPort=nope\nUDPPort=70000\nUDPEnable=yes\nConnectToKad=2\n");
    let p = Preferences::read(&f);
    assert_eq!(p.tcp_port, 4662);
    assert_eq!(p.udp_port, 70000u32 as u16);
    assert!(
        p.udp_enabled,
        "'yes' is not a number: the default (true) is kept"
    );
    assert!(p.connect_to_kad, "any non-zero number is true");
    // Empty paths mean the default; universal paths are decoded.
    let f = ConfFile::parse("[eMule]\nTempDir=\nIncomingDir=/data/m\u{c3}\u{bc}sic\n");
    let p = Preferences::read(&f);
    assert_eq!(p.temp_dir, None);
    assert_eq!(p.incoming_dir.as_deref(), Some("/data/müsic"));
}

#[test]
fn values_unescape_and_quote_like_wx() {
    let f = ConfFile::parse(
        "[g]\n\
         a = spaced\n\
         b=\"  leading\"\n\
         c=tab\\there\\nline\\\\back\n\
         d=drop\\x\n\
         e=\"say \\\"hi\\\"\"\n\
         f=trailing\\\n\
         \\ weird\\=key=1\n",
    );
    assert_eq!(
        f.get("/g/a"),
        Some("spaced"),
        "whitespace around '=' is skipped"
    );
    assert_eq!(f.get("/g/b"), Some("  leading"));
    assert_eq!(f.get("/g/c"), Some("tab\there\nline\\back"));
    assert_eq!(f.get("/g/d"), Some("drop"), "unknown escapes are dropped");
    assert_eq!(f.get("/g/e"), Some("say \"hi\""));
    assert_eq!(f.get("/g/f"), Some("trailing"));
    assert_eq!(f.get("/g/ weird=key"), Some("1"), "escaped name characters");
    // Writing escapes back so the value reads the same.
    for v in ["  leading", "\"quoted", "a\tb\nc\\d", "plain", "", "x\"y"] {
        let mut f = ConfFile::new();
        f.set("/g/k", v);
        let back = ConfFile::from_bytes(&f.to_bytes());
        assert_eq!(back.get("/g/k"), Some(v), "{v:?}");
    }
    let mut f = ConfFile::new();
    f.set("/g/k", "  x");
    assert_eq!(f.to_bytes(), b"[g]\nk=\"  x\"\n");
}

#[test]
fn names_are_case_insensitive_and_last_duplicate_wins() {
    let f = ConfFile::parse("[eMule]\nNick=first\nnick=second\n[EMULE]\nNICK=third\n");
    assert_eq!(f.get("/emule/nick"), Some("third"));
    assert_eq!(f.warnings().len(), 2);
    assert_eq!(f.entries(), vec![("/EMULE/NICK".to_string(), "third")]);
}

#[test]
fn changing_a_value_rewrites_only_its_line() {
    let mut f = ConfFile::parse(SAMPLE);
    f.set("/eMule/MaxUpload", "200");
    let out = String::from_utf8(f.to_bytes()).unwrap();
    assert_eq!(out, SAMPLE.replace("MaxUpload=120", "MaxUpload=200"));
    // Setting the same value leaves an oddly formatted line alone.
    let mut f = ConfFile::parse("[eMule]\n  Port =  4662\n");
    f.set("/eMule/Port", "4662");
    assert_eq!(f.to_bytes(), b"[eMule]\n  Port =  4662\n");
    // Writing the typed view back unchanged changes nothing.
    let mut f = ConfFile::parse(SAMPLE);
    Preferences::read(&f).write(&mut f);
    assert_eq!(f.to_bytes(), SAMPLE.as_bytes());
}

#[test]
fn new_keys_and_groups_go_where_wxfileconfig_puts_them() {
    let mut f = ConfFile::parse("top=1\n[a]\nx=1\n[b]\ny=2\n; tail comment\n");
    // After the group's last entry.
    f.set("/a/z", "3");
    // A new group: after the last group's last line, before trailing comments.
    f.set("/c/w", "4");
    // A subgroup of an existing group: after that group's entries.
    f.set("/a/sub/q", "5");
    // A root entry: after the last root entry.
    f.set("/top2", "6");
    assert_eq!(
        String::from_utf8(f.to_bytes()).unwrap(),
        "top=1\ntop2=6\n[a]\nx=1\nz=3\n[a/sub]\nq=5\n[b]\ny=2\n[c]\nw=4\n; tail comment\n"
    );
    // A new key in an empty file, and names that need escaping.
    let mut f = ConfFile::new();
    f.set("/My Group/a key", "v");
    assert_eq!(f.to_bytes(), b"[My\\ Group]\na\\ key=v\n");
    assert_eq!(
        ConfFile::from_bytes(&f.to_bytes()).get("/My Group/a key"),
        Some("v")
    );
}

#[test]
fn new_lines_follow_the_file_line_endings() {
    let mut f = ConfFile::parse("[eMule]\r\nPort=1\r\n");
    f.set("/eMule/UDPPort", "2");
    assert_eq!(f.to_bytes(), b"[eMule]\r\nPort=1\r\nUDPPort=2\r\n");
    // A last line without an end gets one before a new line follows it.
    let mut f = ConfFile::parse("[eMule]\nPort=1");
    f.set("/eMule/UDPPort", "2");
    assert_eq!(f.to_bytes(), b"[eMule]\nPort=1\nUDPPort=2\n");
}

#[test]
fn latin1_file_becomes_utf8_only_when_it_must() {
    let mut f = ConfFile::from_bytes(b"[eMule]\nNick=caf\xE9\n");
    f.set("/eMule/Nick", "naïve");
    assert_eq!(f.encoding(), Encoding::Latin1);
    assert_eq!(f.to_bytes(), b"[eMule]\nNick=na\xEFve\n");
    f.set("/eMule/Nick", "snow ☃");
    assert_eq!(f.encoding(), Encoding::Utf8 { bom: false });
    assert_eq!(f.to_bytes(), "[eMule]\nNick=snow ☃\n".as_bytes());
}

#[test]
fn remove_and_ec_keys_are_not_written() {
    let mut f = ConfFile::parse(SAMPLE);
    assert!(f.remove("/WebServer/Password"));
    assert!(!f.remove("/WebServer/Password"));
    assert_eq!(f.get("/WebServer/Password"), None);
    // The typed view never writes the EC password keys.
    let mut p = Preferences::read(&f);
    p.ec_password_verifier = Some("changed".into());
    p.ec_password_legacy = Some("x".into());
    p.write(&mut f);
    assert_eq!(
        f.get(keys::EC_PASSWORD_VERIFIER),
        Some("v1:15:8:1:00112233445566778899aabbccddeeff:abcd")
    );
    assert_eq!(f.get(keys::EC_PASSWORD_LEGACY), None);
}

#[test]
fn malformed_lines_are_kept_and_reported() {
    let text = "[eMule\nno equals here\n[ok] junk\nPort=1\n\u{0}\n";
    let f = ConfFile::parse(text);
    assert_eq!(f.to_bytes(), text.as_bytes());
    assert_eq!(f.warnings().len(), 4);
    assert_eq!(f.get("/ok/Port"), Some("1"));
    // Arbitrary bytes never panic.
    let junk: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let f = ConfFile::from_bytes(&junk);
    assert_eq!(f.to_bytes(), junk);
    let _ = Preferences::read(&f);
}
