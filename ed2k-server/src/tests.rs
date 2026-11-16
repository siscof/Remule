// SPDX-License-Identifier: GPL-2.0-or-later
//! Tests: the query grammar against Parser.y's rules, request bytes worked
//! out from `WriteSearchPacket`, packet parsing, the session, and a fake
//! server for the async client.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed2k_codec::{Packet, Tag, TagValue, Writer};
use ed2k_types::ed2k::server_tcp::Opcode;
use ed2k_types::tags::{FileTag, FileType};
use ed2k_types::{Md4Hash, Protocol};

use crate::packets::{self, IdChange, LoginInfo, ServerPacket};
use crate::search::{encode_search, parse_query, QueryError, SearchParams, Term};
use crate::session::{CloseReason, Event, Session, SessionOptions, State};
use crate::udp;

fn w(s: &str) -> Term {
    Term::Word(s.into())
}

// ---------------------------------------------------------------- grammar

#[test]
fn words_side_by_side_become_one_string() {
    assert_eq!(parse_query("ubuntu").unwrap(), [w("ubuntu")]);
    assert_eq!(parse_query("  ubuntu   iso ").unwrap(), [w("ubuntu iso")]);
    assert_eq!(parse_query("a AND b c").unwrap(), [w("a b c")]);
    // Lower-case operators are words.
    assert_eq!(parse_query("this or that").unwrap(), [w("this or that")]);
    // A quoted word keeps its spaces and escapes.
    assert_eq!(
        parse_query(r#""a b" "c\"d\tq\x41""#).unwrap(),
        [w("a b c\"d\tqA")]
    );
}

#[test]
fn operators_bind_not_and_or() {
    use Term::{And, Not, Or};
    assert_eq!(parse_query("a OR b").unwrap(), [Or, w("a"), w("b")]);
    // NOT binds tighter than OR, AND tighter than OR.
    assert_eq!(
        parse_query("a OR b NOT c").unwrap(),
        [Or, w("a"), Not, w("b"), w("c")]
    );
    assert_eq!(
        parse_query("a b OR c").unwrap(),
        [Or, And, w("a"), w("b"), w("c")]
    );
    assert_eq!(
        parse_query("a AND b OR c AND d").unwrap(),
        [Or, And, w("a"), w("b"), And, w("c"), w("d")]
    );
    // Left-associative.
    assert_eq!(
        parse_query("a OR b OR c").unwrap(),
        [Or, Or, w("a"), w("b"), w("c")]
    );
    assert_eq!(
        parse_query("(a OR b) NOT c").unwrap(),
        [Not, Or, w("a"), w("b"), w("c")]
    );
    assert_eq!(
        parse_query("a NOT (b OR c)").unwrap(),
        [Not, w("a"), Or, w("b"), w("c")]
    );
}

#[test]
fn bad_queries() {
    assert_eq!(parse_query(""), Err(QueryError::Empty));
    assert_eq!(parse_query("   "), Err(QueryError::Empty));
    assert_eq!(
        parse_query("OR a"),
        Err(QueryError::MissingLeftOperand("OR"))
    );
    assert_eq!(
        parse_query("a OR"),
        Err(QueryError::MissingRightOperand("OR"))
    );
    assert_eq!(
        parse_query("a NOT"),
        Err(QueryError::MissingRightOperand("NOT"))
    );
    assert_eq!(
        parse_query("(a OR b"),
        Err(QueryError::MissingClosingParenthesis)
    );
    assert_eq!(parse_query("\"open"), Err(QueryError::UnterminatedString));
    // Parser.y has no rule for a word after a group, or a group after words.
    assert!(matches!(
        parse_query("(a) b"),
        Err(QueryError::Unexpected(_))
    ));
    assert!(matches!(
        parse_query("a (b)"),
        Err(QueryError::Unexpected(_))
    ));
    assert!(matches!(parse_query("a)"), Err(QueryError::Unexpected(_))));
    // Eleven operators is too many; ten is fine.
    let ten = (0..11)
        .map(|i| format!("w{i}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    assert!(parse_query(&ten).is_ok());
    let eleven = format!("{ten} OR w11");
    assert_eq!(parse_query(&eleven), Err(QueryError::TooComplex));
}

#[test]
fn ed2k_hash_searches() {
    let h = "ed2k::0123456789abcdef0123456789ABCDEF";
    assert_eq!(parse_query(h).unwrap(), [w(h)]);
    // Only alone; one digit more and it is a word.
    assert_eq!(
        parse_query(&format!("{h}0")).unwrap(),
        [w(&format!("{h}0"))]
    );
    assert!(parse_query(&format!("{h} x")).is_err());
}

// ---------------------------------------------------------------- requests

/// `<1><len 2><utf-8>`
fn word(s: &str) -> Vec<u8> {
    let mut v = vec![1];
    v.extend((s.len() as u16).to_le_bytes());
    v.extend(s.as_bytes());
    v
}

const AND: [u8; 2] = [0, 0];

#[test]
fn simple_search_bytes() {
    let (b, large) = encode_search(&SearchParams::new("ubuntu iso"), true).unwrap();
    assert_eq!(b, word("ubuntu iso"));
    assert!(!large);
    let (b, _) = encode_search(&SearchParams::new("a OR b"), true).unwrap();
    let mut want = vec![0, 1];
    want.extend(word("a"));
    want.extend(word("b"));
    assert_eq!(b, want);
}

#[test]
fn filters_are_anded_as_wire_search_packet_does() {
    let mut p = SearchParams::new("linux");
    p.file_type = Some(FileType::Archive); // sent as "Pro" for a simple search
    p.min_size = 1000;
    p.max_size = 5_000_000_000; // over 32 bits
    p.extension = "iso".into();
    let (b, large) = encode_search(&p, true).unwrap();
    assert!(large);
    // Simple search: AND word AND type AND min AND max ext.
    let mut want = AND.to_vec();
    want.extend(word("linux"));
    want.extend(AND);
    want.extend([2, 3, 0, b'P', b'r', b'o', 1, 0, FileTag::Filetype.into()]);
    want.extend(AND);
    want.extend([3]);
    want.extend(1000u32.to_le_bytes());
    want.extend([1, 1, 0, FileTag::Filesize.into()]);
    want.extend(AND);
    want.extend([8]);
    want.extend(5_000_000_000u64.to_le_bytes());
    want.extend([2, 1, 0, FileTag::Filesize.into()]);
    want.extend([2, 3, 0, b'i', b's', b'o', 1, 0, FileTag::Fileformat.into()]);
    assert_eq!(b, want);

    // Without large-file support the size is cut to 32 bits.
    let (b, large) = encode_search(&p, false).unwrap();
    assert!(!large);
    assert!(b.windows(5).any(|x| x == [3, 0xFF, 0xFF, 0xFF, 0xFF]));

    // A boolean expression: all the ANDs first, then the terms.
    let mut p = SearchParams::new("a OR b");
    p.file_type = Some(FileType::Archive); // kept as "Arc" here
    p.availability = 5;
    let (b, _) = encode_search(&p, true).unwrap();
    let mut want = [AND, AND].concat();
    want.extend([0, 1]);
    want.extend(word("a"));
    want.extend(word("b"));
    want.extend([2, 3, 0, b'A', b'r', b'c', 1, 0, FileTag::Filetype.into()]);
    want.extend([3]);
    want.extend(5u32.to_le_bytes());
    want.extend([1, 1, 0, FileTag::Sources.into()]);
    assert_eq!(b, want);
}

// ---------------------------------------------------------------- packets

#[test]
fn login_packet() {
    let mut info = LoginInfo::new(Md4Hash([7; 16]), 4662, "remule");
    info.crypt_requested = true;
    let p = packets::login(&info).unwrap();
    assert_eq!((p.protocol, p.opcode), (0xE3, 0x01));
    let mut want = Writer::new();
    want.hash(Md4Hash([7; 16])).u32(0).u16(4662).u32(4);
    // <type><1 u16><id><value>
    want.bytes(&[2, 1, 0, 0x01]).u16(6).bytes(b"remule");
    want.bytes(&[3, 1, 0, 0x11]).u32(0x3C);
    want.bytes(&[3, 1, 0, 0x20])
        .u32(0x0001 | 0x0004 | 0x0008 | 0x0010 | 0x0100 | 0x0200 | 0x0400);
    want.bytes(&[3, 1, 0, 0xFB])
        .u32((3 << 24) | (3 << 17) | (2 << 10));
    assert_eq!(p.payload, want.into_bytes());
    assert_eq!(packets::ed2k_version(3, 2, 0), 0x6_0800);
}

#[test]
fn user_hash_markers() {
    let h = packets::new_user_hash(&mut rand::thread_rng());
    assert_eq!((h.0[5], h.0[14]), (14, 111));
}

#[test]
fn source_requests() {
    let h = Md4Hash([1; 16]);
    let p = packets::get_sources(h, 1234, false);
    assert_eq!(p.opcode, 0x19);
    assert_eq!(p.payload[16..], 1234u32.to_le_bytes());
    let p = packets::get_sources(h, 5_000_000_000, true);
    assert_eq!(p.opcode, 0x23);
    assert_eq!(p.payload[16..20], [0; 4]);
    assert_eq!(p.payload[20..], 5_000_000_000u64.to_le_bytes());
}

fn server(op: Opcode, payload: Vec<u8>) -> Packet {
    Packet::new(Protocol::Edonkey, op, payload)
}

fn result_bytes(w: &mut Writer, hash: u8, name: &str, size: u64, sources: u32) {
    w.hash(Md4Hash([hash; 16])).u32(0x0A0B0C0D).u16(4662);
    let mut tags = vec![
        Tag::string(FileTag::Filename as u8, name),
        Tag::new(FileTag::Filesize as u8, TagValue::U32(size as u32)),
        Tag::new(FileTag::Sources as u8, TagValue::U32(sources)),
        Tag::new(FileTag::FileRating as u8, TagValue::U32(4 * 51)),
    ];
    if size > u32::MAX as u64 {
        tags.push(Tag::new(
            FileTag::FilesizeHi as u8,
            TagValue::U32((size >> 32) as u32),
        ));
    }
    w.u32(tags.len() as u32);
    for t in &tags {
        t.write_ed2k(w, ed2k_codec::io::StrEncoding::Utf8).unwrap();
    }
}

#[test]
fn search_answers() {
    let mut wr = Writer::new();
    wr.u32(2);
    result_bytes(&mut wr, 1, "ubuntu-24.04.iso", 6_000_000_000, 120);
    result_bytes(&mut wr, 2, "ümlaut ☃.txt", 77, 1);
    wr.u8(1);
    let p = packets::parse(server(Opcode::SearchResult, wr.into_bytes())).unwrap();
    let ServerPacket::SearchResults { results, more } = p else {
        panic!("{p:?}")
    };
    assert_eq!(more, Some(true));
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].name, "ubuntu-24.04.iso");
    assert_eq!(results[0].size, 6_000_000_000);
    assert_eq!(results[0].sources, 120);
    assert_eq!(results[0].rating, 4);
    assert_eq!(results[1].name, "ümlaut ☃.txt");
    assert_eq!(results[1].client_id, 0x0A0B0C0D);

    // A count far beyond the data is an error, not an allocation.
    let mut wr = Writer::new();
    wr.u32(u32::MAX);
    result_bytes(&mut wr, 1, "x", 1, 1);
    assert!(packets::parse(server(Opcode::SearchResult, wr.into_bytes())).is_err());
}

#[test]
fn packed_packets_are_unpacked() {
    // Enough alike results for zlib to shrink them (pack() declines otherwise).
    let mut wr = Writer::new();
    wr.u32(20);
    for _ in 0..20 {
        result_bytes(&mut wr, 3, "packed.bin", 10, 2);
    }
    let mut p = server(Opcode::SearchResult, wr.into_bytes());
    assert!(p.pack());
    assert_eq!(p.protocol, 0xD4);
    let ServerPacket::SearchResults { results, more } = packets::parse(p).unwrap() else {
        panic!()
    };
    assert_eq!(results.len(), 20);
    assert_eq!((results[0].name.as_str(), more), ("packed.bin", None));
}

#[test]
fn other_server_packets() {
    let id = |payload: Vec<u8>| packets::parse(server(Opcode::IdChange, payload)).unwrap();
    assert_eq!(
        id(5u32.to_le_bytes().to_vec()),
        ServerPacket::IdChange(IdChange {
            id: 5,
            ..Default::default()
        })
    );
    let mut full = Writer::new();
    full.u32(7).u32(0x0501).u32(4661).u32(0x0403_0201).u32(4665);
    assert_eq!(
        id(full.into_bytes()),
        ServerPacket::IdChange(IdChange {
            id: 7,
            tcp_flags: 0x0501,
            aux_port: Some(4661),
            reported_ip: Some(0x0403_0201),
            obfuscation_port: Some(4665),
        })
    );
    assert!(packets::parse(server(Opcode::IdChange, vec![1, 2])).is_err());

    let mut m = vec![0, 0];
    m.extend(b"server version 17.15\r\nWARNING : low id\nhello\0junk");
    assert_eq!(
        packets::parse(server(Opcode::ServerMessage, m)).unwrap(),
        ServerPacket::Message(vec![
            "server version 17.15".into(),
            "WARNING : low id".into(),
            "hello".into()
        ])
    );

    let mut s = Writer::new();
    s.hash(Md4Hash([9; 16])).u8(2);
    s.u32(0x0100_007F).u16(4662).u8(0x81).hash(Md4Hash([3; 16]));
    s.u32(1234).u16(4663).u8(0x01);
    let ServerPacket::FoundSources { hash, sources } =
        packets::parse(server(Opcode::FoundSourcesObfu, s.into_bytes())).unwrap()
    else {
        panic!()
    };
    assert_eq!(hash, Md4Hash([9; 16]));
    assert_eq!(sources[0].user_hash, Some(Md4Hash([3; 16])));
    assert_eq!(
        packets::id_to_ip(sources[0].id),
        Ipv4Addr::new(127, 0, 0, 1)
    );
    assert!(packets::is_low_id(sources[1].id));
    assert_eq!(sources[1].crypt_options, Some(1));

    let mut l = Writer::new();
    l.u8(2)
        .bytes(&[1, 2, 3, 4])
        .u16(4661)
        .bytes(&[5, 6, 7, 8])
        .u16(4242);
    assert_eq!(
        packets::parse(server(Opcode::ServerList, l.into_bytes())).unwrap(),
        ServerPacket::ServerList(vec![
            "1.2.3.4:4661".parse().unwrap(),
            "5.6.7.8:4242".parse().unwrap()
        ])
    );
    // A count the data cannot hold reads as none (as aMule).
    assert_eq!(
        packets::parse(server(Opcode::ServerList, vec![9, 1, 2])).unwrap(),
        ServerPacket::ServerList(vec![])
    );
}

// ---------------------------------------------------------------- session

fn session() -> Session {
    Session::new(
        LoginInfo::new(Md4Hash([1; 16]), 4662, "t"),
        SessionOptions::default(),
    )
}

#[test]
fn session_login_and_refusal() {
    let mut s = session();
    assert_eq!(*s.state(), State::Connecting);
    s.start().unwrap();
    assert_eq!(*s.state(), State::WaitingForLogin);
    let out = s.handle(ServerPacket::Message(vec![
        "server version 17.15 (lugdunum)".into(),
        "ERROR : bad nick".into(),
        "[emDynIP: srv.example.org]".into(),
    ]));
    assert_eq!(s.info().version.as_deref(), Some("17.15 (lugdunum)"));
    assert_eq!(s.info().dyn_ip.as_deref(), Some("srv.example.org"));
    assert_eq!(out.events[1], Event::Error("bad nick".into()));
    let out = s.handle(ServerPacket::IdChange(IdChange::default()));
    assert_eq!(out.events, [Event::Closed(CloseReason::Refused)]);
    assert_eq!(*s.state(), State::Closed(CloseReason::Refused));

    let mut s = session();
    s.start().unwrap();
    let out = s.handle(ServerPacket::IdChange(IdChange {
        id: 1234,
        tcp_flags: 0x0100,
        reported_ip: Some(0x0403_0201),
        ..Default::default()
    }));
    assert_eq!(
        out.events,
        [Event::LoggedIn {
            id: 1234,
            low_id: true,
            public_ip: Some(Ipv4Addr::new(1, 2, 3, 4))
        }]
    );
    // Once logged in, ask for servers.
    assert_eq!(out.send, [packets::get_server_list()]);
    assert!(s.supports_large_files());
    let out = s.handle(ServerPacket::IdChange(IdChange {
        id: 0x0403_0201,
        ..Default::default()
    }));
    assert_eq!(out.events, [Event::IdChanged { id: 0x0403_0201 }]);
    assert_eq!(s.id(), Some(0x0403_0201));
}

// ---------------------------------------------------------------- UDP

#[test]
fn udp_ping() {
    let c = udp::ping_challenge(&mut rand::thread_rng());
    assert_eq!(c >> 16, 0x55AA);
    let p = udp::ping(c);
    assert_eq!(p.to_udp_bytes()[..2], [0xE3, 0x96]);
    let mut a = Writer::new();
    a.bytes(&[0xE3, 0x97]).u32(c).u32(100).u32(200).u32(300);
    let s = udp::parse_ping_answer(a.as_bytes()).unwrap();
    assert_eq!(
        (s.challenge, s.users, s.files, s.max_users),
        (c, 100, 200, 300)
    );
    a.u32(1)
        .u32(2)
        .u32(0x0200)
        .u32(9)
        .u16(4665)
        .u16(4666)
        .u32(0xDEAD);
    let s = udp::parse_ping_answer(a.as_bytes()).unwrap();
    assert_eq!(
        (
            s.udp_flags,
            s.low_id_users,
            s.udp_obfuscation_port,
            s.tcp_obfuscation_port,
            s.udp_key
        ),
        (0x0200, 9, 4665, 4666, 0xDEAD)
    );
    assert!(udp::parse_ping_answer(&[0xE3, 0x97, 1, 2]).is_none());
}

// ---------------------------------------------------------------- client

/// A fake server: answers the login and one search.
async fn fake_server(listener: tokio::net::TcpListener, id: u32) {
    use remule_net::{establish, Bandwidth, ConnConfig, Handshake, Priority};
    let (stream, _) = listener.accept().await.unwrap();
    let hs = Handshake::Plain;
    let (mut r, mut w) = establish(
        stream,
        hs,
        ConnConfig::new(std::sync::Arc::new(Bandwidth::unlimited())),
    )
    .await
    .unwrap();
    let login = r.recv().await.unwrap().unwrap();
    assert_eq!(login.opcode, 0x01);
    let mut m = vec![0, 0];
    m.extend(b"server version 17.15\r\nWelcome to the fake server");
    w.send(&server(Opcode::ServerMessage, m), Priority::Control)
        .await
        .unwrap();
    if id == 0 {
        let mut m = vec![0, 0];
        m.extend(b"ERROR : you are banned");
        w.send(&server(Opcode::ServerMessage, m), Priority::Control)
            .await
            .unwrap();
    }
    let mut c = Writer::new();
    c.u32(id).u32(0x0100);
    w.send(&server(Opcode::IdChange, c.into_bytes()), Priority::Control)
        .await
        .unwrap();
    if id == 0 {
        return;
    }
    // OP_GETSERVERLIST, then the search.
    assert_eq!(r.recv().await.unwrap().unwrap().opcode, 0x14);
    let search = r.recv().await.unwrap().unwrap();
    assert_eq!(search.opcode, 0x16);
    assert_eq!(search.payload, word("fake query"));
    let mut wr = Writer::new();
    wr.u32(1);
    result_bytes(&mut wr, 4, "fake result.avi", 700_000_000, 42);
    w.send(
        &server(Opcode::SearchResult, wr.into_bytes()),
        Priority::Control,
    )
    .await
    .unwrap();
    // Hold the connection until the client goes.
    let _ = r.recv().await;
}

async fn listen() -> (tokio::net::TcpListener, SocketAddr) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

#[tokio::test]
async fn client_logs_in_and_searches() {
    let (l, addr) = listen().await;
    let srv = tokio::spawn(fake_server(l, 1234));
    let opts = crate::ConnectOptions::new(LoginInfo::new(Md4Hash([2; 16]), 4662, "remule"));
    let (mut c, login) = crate::ServerClient::connect(addr, opts).await.unwrap();
    assert_eq!((login.id, login.low_id), (1234, true));
    assert_eq!(c.info().version.as_deref(), Some("17.15"));
    let res = c
        .search(&SearchParams::new("fake query"), Duration::from_secs(5), 1)
        .await
        .unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].name, "fake result.avi");
    let early = c.drain_events();
    assert!(early.contains(&Event::Message("Welcome to the fake server".into())));
    drop(c);
    srv.await.unwrap();
}

#[tokio::test]
async fn refused_login_reports_the_reason() {
    let (l, addr) = listen().await;
    let srv = tokio::spawn(fake_server(l, 0));
    let opts = crate::ConnectOptions::new(LoginInfo::new(Md4Hash([2; 16]), 4662, "remule"));
    let err = crate::ServerClient::connect(addr, opts).await.unwrap_err();
    assert!(
        matches!(&err, crate::ClientError::Refused(r) if r == &["you are banned"]),
        "{err}"
    );
    srv.await.unwrap();
}

// ---------------------------------------------------------------- Kad keywords

#[test]
fn kad_words_and_keywords() {
    use crate::search::{encode_kad_search, kad_words};
    assert_eq!(kad_words("Ubuntu iso, a/b-cd ÄÖ"), ["ubuntu", "iso", "äö"]);
    let kad = |q: &str| encode_kad_search(&SearchParams::new(q));
    // The keyword alone: nothing more to send.
    assert_eq!(kad("ubuntu").unwrap(), ("ubuntu".into(), vec![]));
    // The keyword leaves the ANDed words.
    assert_eq!(kad("ubuntu iso").unwrap(), ("ubuntu".into(), word("iso")));
    // A longer word takes over as the keyword.
    assert_eq!(kad("iso ubuntu").unwrap(), ("ubuntu".into(), word("iso")));
    // The keyword is lower-cased, the terms are not: "Ubuntu" stays a term (as aMule).
    assert_eq!(kad("Ubuntu").unwrap(), ("ubuntu".into(), word("Ubuntu")));
    // With OR or NOT the whole expression goes along.
    let (k, d) = kad("abc OR ubuntu").unwrap();
    assert_eq!(k, "abc");
    let mut want = vec![0, 1];
    want.extend(word("abc"));
    want.extend(word("ubuntu"));
    assert_eq!(d, want);
    assert_eq!(kad("ab cd"), Err(QueryError::NoKeyword));
    // Filters alone still go out.
    let mut p = SearchParams::new("ubuntu");
    p.min_size = 10;
    let (_, d) = encode_kad_search(&p).unwrap();
    let mut want = vec![3];
    want.extend(10u32.to_le_bytes());
    want.extend([1, 1, 0, FileTag::Filesize.into()]);
    assert_eq!(d, want);
}

// ---- OP_OFFERFILES ----

/// Read an offer back: (hash, id, port, tags) per file.
fn read_offer(p: &Packet) -> Vec<(Md4Hash, u32, u16, Vec<Tag>)> {
    let mut p = p.clone();
    if p.protocol == u8::from(Protocol::Packed) {
        p.unpack(1 << 20).unwrap();
    }
    assert_eq!(p.opcode, u8::from(Opcode::OfferFiles));
    let mut r = ed2k_codec::Reader::new(&p.payload);
    let n = r.u32().unwrap();
    (0..n)
        .map(|_| {
            let h = r.hash().unwrap();
            let id = r.u32().unwrap();
            let port = r.u16().unwrap();
            let tc = r.u32().unwrap();
            let tags = (0..tc)
                .map(|_| Tag::read_ed2k(&mut r, true, true).unwrap())
                .collect();
            (h, id, port, tags)
        })
        .collect()
}

fn offered(n: u8, name: &str, size: u64, complete: bool) -> packets::OfferedFile {
    packets::OfferedFile {
        hash: Md4Hash([n; 16]),
        name: name.into(),
        size,
        complete,
        file_type: FileType::of_name(name),
    }
}

#[test]
fn offers_follow_the_server_dialect() {
    use ed2k_types::ed2k::server_tcp::flags;
    let files = [
        offered(1, "a book.epub", 1000, true),
        offered(2, "disc.iso", 5_000_000_000, false),
    ];
    // A modern server: markers, new tags, integer types, large files, packed.
    let modern = flags::COMPRESSION
        | flags::NEWTAGS
        | flags::UNICODE
        | flags::TYPETAGINTEGER
        | flags::LARGEFILES;
    let back = read_offer(&packets::offer_files(&files, modern, 0x0A00_0001, 4662));
    assert_eq!(back.len(), 2);
    assert_eq!((back[0].1, back[0].2), (0xFBFB_FBFB, 0xFBFB));
    assert_eq!((back[1].1, back[1].2), (0xFCFC_FCFC, 0xFCFC));
    let tag = |tags: &[Tag], t: FileTag| {
        tags.iter()
            .find(|x| x.name == ed2k_codec::TagName::Id(t.value()))
            .cloned()
    };
    assert_eq!(
        tag(&back[0].3, FileTag::Filename).unwrap().as_str(),
        Some("a book.epub")
    );
    assert_eq!(
        tag(&back[0].3, FileTag::Filesize).unwrap().as_int(),
        Some(1000)
    );
    assert_eq!(
        tag(&back[0].3, FileTag::Filetype).unwrap().as_int(),
        Some(5)
    );
    // Over 4 GB: the low and high halves; a disc image goes as a program.
    assert_eq!(
        tag(&back[1].3, FileTag::Filesize).unwrap().as_int(),
        Some(5_000_000_000 & 0xFFFF_FFFF)
    );
    assert_eq!(
        tag(&back[1].3, FileTag::FilesizeHi).unwrap().as_int(),
        Some(1)
    );
    assert_eq!(
        tag(&back[1].3, FileTag::Filetype).unwrap().as_int(),
        Some(4)
    );

    // An old server: our address (or zero for a LowID), string types, no large files.
    let back = read_offer(&packets::offer_files(&files, 0, 0x0A00_0001, 4662));
    assert_eq!(back.len(), 1);
    assert_eq!((back[0].1, back[0].2), (0x0A00_0001, 4662));
    assert_eq!(
        tag(&back[0].3, FileTag::Filetype).unwrap().as_str(),
        Some("Doc")
    );
    let back = read_offer(&packets::offer_files(&files, 0, 1234, 4662));
    assert_eq!((back[0].1, back[0].2), (0, 0));

    assert_eq!(packets::offer_limit(0, 0), 200);
    assert_eq!(packets::offer_limit(1000, 0), 200);
    assert_eq!(packets::offer_limit(100, 0), 100);
    assert_eq!(packets::offer_limit(100, 50), 49);
}
