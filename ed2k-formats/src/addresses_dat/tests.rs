// SPDX-License-Identifier: GPL-2.0-or-later
//! Ported from aMule's `unittests/tests/ServerListSourcesTest.cpp`, plus
//! `SetServerListURLs` and `staticservers.dat`.

use super::*;

fn urls(text: &[u8]) -> Vec<String> {
    AddressesDat::from_bytes(text.to_vec()).urls().unwrap()
}

#[test]
fn filters_comments_invalid_schemes_and_duplicates_in_order() {
    let text = b" # preserved comment\r\n  https://one.example/server.met \r\n\r\n\
ftp://unsupported.example/server.met\nnot a URL\nhttp:///missing-host\n\
http://two.example/list\nhttps://one.example/server.met\n";
    let file = AddressesDat::from_bytes(text.to_vec());
    assert_eq!(
        file.urls().unwrap(),
        ["https://one.example/server.met", "http://two.example/list"]
    );
    // Reading never changes the file: the comment is still there.
    assert_eq!(file.as_bytes(), text);
}

#[test]
fn reloads_edits_and_does_not_limit_sources_to_255() {
    let text: String = (0..300)
        .map(|i| format!("https://source.example/{i}\n"))
        .collect();
    assert_eq!(urls(text.as_bytes()).len(), 300);
    assert_eq!(
        urls(b"https://changed.example/list\n"),
        ["https://changed.example/list"]
    );
    assert!(urls(b"").is_empty());
}

#[test]
fn rejects_line_injection_and_whitespace() {
    assert!(!is_valid_url(
        "https://example.com/list\nhttp://injected/list"
    ));
    assert!(!is_valid_url("https://example.com/list\r"));
    assert!(!is_valid_url("https://example.com/a b"));
    assert!(!is_valid_url("https://example.com/\t"));
    assert!(is_valid_url("HTTPS://example.com/a%20b?token=value"));
    // More of wxURI's rules.
    assert!(!is_valid_url("http:///missing-host"));
    assert!(!is_valid_url("https:example.com/no-slashes"));
    assert!(!is_valid_url("example.com/server.met"));
    assert!(!is_valid_url("http://user@:80/"));
    assert!(is_valid_url("http://user:pw@host.example:8080/x"));
    assert!(is_valid_url("http://[2001:db8::1]/server.met"));
    assert!(!is_valid_url("http://[]/server.met"));
    assert!(!is_valid_url("https://exa\0mple.com/"));
}

#[test]
fn legacy_comment_encoding_does_not_hide_valid_urls() {
    // Invalid UTF-8 falls back to Latin-1 for the whole file.
    assert_eq!(
        urls(b"# caf\xe9\nhttps://example.com/list\n"),
        ["https://example.com/list"]
    );
}

#[test]
fn reads_utf8_bom() {
    assert_eq!(
        urls(b"\xef\xbb\xbfhttps://example.com/list\n"),
        ["https://example.com/list"]
    );
}

#[test]
fn reads_utf16_and_utf32_boms_and_rejects_broken_ones() {
    let mut le = vec![0xFF, 0xFE];
    le.extend(
        "https://example.com/16\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes),
    );
    assert_eq!(urls(&le), ["https://example.com/16"]);
    let mut be = vec![0xFE, 0xFF];
    be.extend(
        "https://example.com/16be\n"
            .encode_utf16()
            .flat_map(u16::to_be_bytes),
    );
    assert_eq!(urls(&be), ["https://example.com/16be"]);
    let mut le32 = vec![0xFF, 0xFE, 0x00, 0x00];
    le32.extend(
        "http://x.example/32\n"
            .chars()
            .flat_map(|c| u32::from(c).to_le_bytes()),
    );
    assert_eq!(urls(&le32), ["http://x.example/32"]);
    // ReadStatusDistinguishesEmptyFromUnreadable: an unreadable file is an
    // error, not an empty list.
    assert_eq!(
        AddressesDat::from_bytes(vec![0xFF, 0xFE, 0x41]).urls(),
        Err(Undecodable)
    );
    assert_eq!(
        AddressesDat::from_bytes(b"\xef\xbb\xbf\xff".to_vec()).urls(),
        Err(Undecodable)
    );
    assert_eq!(AddressesDat::from_bytes(Vec::new()).urls(), Ok(vec![]));
}

#[test]
fn set_server_list_urls_writes_valid_unique_lines() {
    let f =
        AddressesDat::from_urls(&[DEFAULT_URL, "http://two.example/list", DEFAULT_URL]).unwrap();
    assert_eq!(
        f.as_bytes(),
        b"https://upd.emule-security.org/server.met\nhttp://two.example/list\n"
    );
    assert_eq!(f.urls().unwrap(), [DEFAULT_URL, "http://two.example/list"]);
    // Written then read gives the same bytes back.
    let again = AddressesDat::from_urls(&f.urls().unwrap()).unwrap();
    assert_eq!(again.as_bytes(), f.as_bytes());
    // One invalid URL rejects the whole list.
    assert_eq!(
        AddressesDat::from_urls(&["http://ok.example/", "ftp://no.example/"]),
        Err(InvalidUrl("ftp://no.example/".into()))
    );
    assert_eq!(
        AddressesDat::from_urls::<&str>(&[]).unwrap().as_bytes(),
        b""
    );
}

fn server(host: &str, port: u16, priority: u32, name: &str) -> StaticServer {
    StaticServer {
        host: host.into(),
        port,
        priority,
        name: name.into(),
    }
}

#[test]
fn static_servers_round_trip_as_amule_writes_them() {
    let list = [
        server("176.123.5.89", 4725, PRIORITY_HIGH, "eMule Sunrise"),
        server("ed2k.example.org", 4661, PRIORITY_LOW, "Ünicode sërver"),
        server("10.0.0.1", 4242, PRIORITY_NORMAL, "Local"),
    ];
    for eol in ["\n", "\r\n"] {
        let bytes = write_static_servers(&list, eol);
        assert!(
            !bytes.ends_with(eol.as_bytes()),
            "no line break after the last line"
        );
        let back = read_static_servers(&bytes).unwrap();
        assert_eq!(back, list);
        assert_eq!(write_static_servers(&back, eol), bytes);
    }
    assert_eq!(
        write_static_servers(&list[..1], "\n"),
        b"176.123.5.89:4725,1,eMule Sunrise".to_vec()
    );
}

#[test]
fn static_servers_follow_load_static_servers() {
    let text = b"# comment\n/ also a comment\n\n\
  host.example : 4661 , 1 , Spaced  \r\n\
noname.example:1234,0,   \n\
noname2.example:1,0,\n\
badprio.example:1,9,Bad priority\n\
notanumber.example:abc,x,Zero port\n\
too,many,fields,here\n\
two:1,fields\n\
comma.example:1,0,Name, with comma\n\
trailing.example:5,2,Trailing,\r\
last.example:6,1,No newline";
    let got = read_static_servers(text).unwrap();
    assert_eq!(
        got,
        [
            // Fields are trimmed; the host:port text is not split on spaces.
            server("host.example ", 4661, 1, "Spaced"),
            // A blank name becomes the address text. A trailing comma with
            // nothing after it is not a field at all, so noname2 is skipped.
            server("noname.example", 1234, 0, "noname.example:1234"),
            // An out-of-range priority becomes normal.
            server("badprio.example", 1, 0, "Bad priority"),
            // StrToLong of something that is not a number is 0.
            server("notanumber.example", 0, 0, "Zero port"),
            // A trailing comma does not add a field; a lone \r ends a line.
            server("trailing.example", 5, 2, "Trailing"),
            server("last.example", 6, 1, "No newline"),
        ]
    );
}

#[test]
fn str_to_long_is_strict() {
    assert_eq!(str_to_long("4661"), 4661);
    assert_eq!(str_to_long(" 12"), 12, "strtol skips leading whitespace");
    assert_eq!(str_to_long("-3"), -3);
    assert_eq!(str_to_long("12a"), 0);
    assert_eq!(str_to_long(""), 0);
    assert_eq!(str_to_long("99999999999999999999999"), 0, "overflow");
    // A port beyond u16 is truncated, as CServer's uint16 parameter does.
    assert_eq!(
        read_static_servers(b"h:70000,0,n").unwrap()[0].port,
        70000u32 as u16
    );
}

#[test]
fn hostile_input_is_not_a_panic() {
    let junk: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let _ = AddressesDat::from_bytes(junk.clone()).urls();
    let _ = read_static_servers(&junk);
    assert!(read_static_servers(&[0xFE, 0xFF, 0x00]).is_err());
}
