// SPDX-License-Identifier: GPL-2.0-or-later
//! amulecmd's lines against a scripted daemon: the requests each command
//! sends and how the replies print.

use std::collections::VecDeque;

use super::*;

#[derive(Default)]
struct Fake {
    sent: Vec<Packet>,
    replies: VecDeque<Packet>,
    caps: Vec<u16>,
}

impl Link for Fake {
    fn request(&mut self, p: &Packet) -> Result<Packet, Error> {
        self.sent.push(p.clone());
        Ok(self
            .replies
            .pop_front()
            .unwrap_or_else(|| Packet::new(EC_OP_NOOP)))
    }
    fn echoed(&self, capability: u16) -> bool {
        self.caps.contains(&capability)
    }
    fn connected(&self) -> bool {
        true
    }
}

fn app(replies: Vec<Packet>) -> App<Fake> {
    App::new(Some(Fake {
        replies: replies.into(),
        caps: vec![
            EC_TAG_CAN_SEARCH_ALL,
            EC_TAG_CAN_MULTI_SEARCH,
            EC_TAG_CAN_SEARCH_LIST,
            EC_TAG_CAN_SEARCH_METADATA,
        ],
        ..Fake::default()
    }))
}

fn run(a: &mut App<Fake>, line: &str) -> String {
    a.parse_command(line);
    a.take_output()
}

fn sent(a: &App<Fake>) -> &[Packet] {
    &a.link.as_ref().unwrap().sent
}

const HASH: [u8; 16] = [0xAB; 16];
const HASH_HEX: &str = "ABABABABABABABABABABABABABABABAB";

fn part(name: &str, met: u64) -> Tag {
    Tag::int(EC_TAG_PARTFILE, 1)
        .with(Tag::hash(EC_TAG_PARTFILE_HASH, HASH))
        .with(Tag::string(EC_TAG_PARTFILE_NAME, name))
        .with(Tag::int(EC_TAG_PARTFILE_PARTMETID, met))
}

#[test]
fn errors_point_at_the_commands_help() {
    let mut a = app(vec![]);
    assert_eq!(
        run(&mut a, "frobnicate"),
        "Syntax error!\nType 'help' to get more help.\n"
    );
    assert_eq!(
        run(&mut a, "status now"),
        "This command should not have any parameters.\nType 'help status' to get more help.\n"
    );
    assert_eq!(
        run(&mut a, "show"),
        "This command must have a parameter.\nType 'help show' to get more help.\n"
    );
    assert_eq!(
        run(&mut a, "set ipfilter level 300"),
        "Invalid argument.\nType 'help set ipfilter level' to get more help.\n"
    );
    assert!(sent(&a).is_empty());
    assert!(a.parse_command("quit"));
    assert!(!a.parse_command("   "));
}

#[test]
fn status_prints_networks_and_rates() {
    let stats = Packet::new(EC_OP_STATS)
        .with(
            Tag::int(EC_TAG_CONNSTATE, 0x01 | 0x10 | 0x04)
                .with(
                    Tag::ipv4(EC_TAG_SERVER, [10, 0, 0, 1], 4242)
                        .with(Tag::string(EC_TAG_SERVER_NAME, "test server")),
                )
                .with(Tag::int(EC_TAG_ED2K_ID, 0x0200_0000)),
        )
        .with(Tag::int(EC_TAG_STATS_DL_SPEED, 1536))
        .with(Tag::int(EC_TAG_STATS_UL_SPEED, 0))
        .with(Tag::int(EC_TAG_STATS_UL_QUEUE_LEN, 3))
        .with(Tag::int(EC_TAG_STATS_TOTAL_SRC_COUNT, 7));
    let mut a = app(vec![stats]);
    assert_eq!(
        run(&mut a, "status"),
        " > eD2k: Connected to test server [10.0.0.1:4242] with HighID\n > Kad: Connected (ok)\n > Download:\t1.50 KiB/s\n > Upload:\t0 bytes/sec\n > Clients in queue:\t3\n > Total sources:\t7\n"
    );
    assert_eq!(sent(&a)[0].opcode, EC_OP_STAT_REQ);
    assert_eq!(
        sent(&a)[0].tag(EC_TAG_DETAIL_LEVEL).map(Tag::as_int),
        Some(EC_DETAIL_CMD.into())
    );
}

#[test]
fn deprecated_command_says_so_then_runs() {
    let mut a = app(vec![Packet::new(EC_OP_SERVER_LIST)]);
    let out = run(&mut a, "Servers");
    assert!(out.starts_with("\nThis is a deprecated command"));
    assert_eq!(sent(&a)[0].opcode, EC_OP_GET_SERVER_LIST);
}

#[test]
fn show_dl_rows_in_tabs_and_spaces() {
    let file = part("a\tb.iso", 3)
        .with(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, 1000))
        .with(Tag::int(EC_TAG_PARTFILE_SIZE_DONE, 250))
        .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT, 5))
        .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT_NOT_CURRENT, 1))
        .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT_XFER, 2))
        .with(Tag::int(EC_TAG_PARTFILE_SPEED, 2048))
        .with(Tag::int(EC_TAG_PARTFILE_PRIO, 11));
    let reply = Packet::new(EC_OP_DLOAD_QUEUE).with(file);
    let mut a = app(vec![reply.clone()]);
    assert_eq!(
        run(&mut a, "show dl"),
        format!(" > {HASH_HEX}\ta b.iso\n > \t [25.0%]\t   4/   5\t\t(02)\tDownloading\t003.part.met\tAuto [No]\t2.00 KiB/s\n")
    );
    let mut a = app(vec![reply]);
    a.space_separated = true;
    assert_eq!(
        run(&mut a, "show dl"),
        format!(" > {HASH_HEX} a\tb.iso\n > \t [25.0%]    4/   5     (02) - Downloading - 003.part.met - Auto [No] - 2.00 KiB/s\n")
    );
}

#[test]
fn show_shared_and_servers() {
    let shared = Packet::new(EC_OP_SHARED_FILES).with(
        Tag::int(EC_TAG_KNOWNFILE, 1)
            .with(Tag::hash(EC_TAG_PARTFILE_HASH, HASH))
            .with(Tag::string(EC_TAG_PARTFILE_NAME, "f.bin"))
            .with(Tag::string(EC_TAG_KNOWNFILE_FILENAME, "/share"))
            .with(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, 300_000))
            .with(Tag::int(EC_TAG_KNOWNFILE_PRIO, 1))
            .with(Tag::int(EC_TAG_KNOWNFILE_REQ_COUNT, 2))
            .with(Tag::int(EC_TAG_KNOWNFILE_REQ_COUNT_ALL, 4))
            .with(Tag::int(EC_TAG_KNOWNFILE_XFERRED_ALL, 150_000)),
    );
    let servers = Packet::new(EC_OP_SERVER_LIST).with(
        Tag::ipv4(EC_TAG_SERVER, [127, 0, 0, 1], 4242)
            .with(Tag::string(EC_TAG_SERVER_NAME, "local"))
            .with(Tag::string(EC_TAG_SERVER_COUNTRY, "DE")),
    );
    let mut a = app(vec![shared, servers]);
    let sep = std::path::MAIN_SEPARATOR;
    assert_eq!(
        run(&mut a, "show shared"),
        format!(
            " > {HASH_HEX}\t/share{sep}f.bin\n > \tNormal\t2(4)\t0(0)\t0 bytes (146 KiB)\t0.50\n"
        )
    );
    assert_eq!(
        run(&mut a, "show servers"),
        " > [127.0.0.1:4242]\tlocal\t[DE]\n"
    );
}

#[test]
fn pause_by_name_part_met_hash_or_all() {
    let queue = || {
        Packet::new(EC_OP_DLOAD_QUEUE)
            .with(part("one.iso", 1))
            .with(part("two.iso", 2))
    };
    let mut a = app(vec![queue(), Packet::new(EC_OP_NOOP)]);
    assert_eq!(
        run(&mut a, "pause two.iso"),
        "Processing by filename: two.iso\n > Operation was successful.\n"
    );
    assert_eq!(sent(&a)[1].opcode, EC_OP_PARTFILE_PAUSE);
    assert_eq!(sent(&a)[1].tags.len(), 1);

    for name in ["001.part.met", "001.part", "001"] {
        let mut a = app(vec![queue()]);
        assert!(run(&mut a, &format!("resume {name}")).starts_with("Processing by filename"));
        assert_eq!(sent(&a)[1].opcode, EC_OP_PARTFILE_RESUME);
        assert_eq!(sent(&a)[1].tags.len(), 1);
    }

    let mut a = app(vec![queue()]);
    run(&mut a, "cancel all");
    assert_eq!(sent(&a)[1].opcode, EC_OP_PARTFILE_DELETE);
    assert_eq!(sent(&a)[1].tags.len(), 2);

    let mut a = app(vec![queue()]);
    assert!(run(&mut a, &format!("pause {}", HASH_HEX.to_lowercase()))
        .starts_with("Processing by hash"));
    assert_eq!(sent(&a)[1].tags[0].as_hash(), Some(HASH));

    let mut a = app(vec![]);
    assert_eq!(
        run(&mut a, "pause"),
        "This command must have a parameter.\nType 'help pause' to get more help.\n"
    );
}

#[test]
fn priority_wants_a_hash() {
    let mut a = app(vec![]);
    assert_eq!(
        run(&mut a, "priority high 123"),
        "Not a valid hash (length should be exactly 32 chars)\n"
    );
    run(&mut a, &format!("priority auto {HASH_HEX}"));
    let t = &sent(&a)[0].tags[0];
    assert_eq!(
        t.child_int(EC_TAG_PARTFILE_PRIO),
        u64::from(format::PR_AUTO)
    );
}

#[test]
fn ipfilter_and_bandwidth_preferences() {
    let security = Packet::new(EC_OP_SET_PREFERENCES).with(
        Tag::empty(EC_TAG_PREFS_SECURITY)
            .with(Tag::empty(EC_TAG_IPFILTER_CLIENTS))
            .with(Tag::int(EC_TAG_IPFILTER_LEVEL, 127)),
    );
    let mut a = app(vec![security.clone()]);
    assert_eq!(
        run(&mut a, "get ipfilter"),
        " > IP filtering for clients is ON.\n > IP filtering for servers is OFF.\n > Current IPFilter Level is 127.\n > Endgame source rotation is OFF.\n"
    );
    let mut a = app(vec![Packet::new(EC_OP_NOOP), security]);
    assert_eq!(
        run(&mut a, "set ipfilter servers off"),
        " > Operation was successful.\n > IP filtering for servers is OFF.\n > Endgame source rotation is OFF.\n"
    );
    let set = &sent(&a)[0];
    let prefs = set.tag(EC_TAG_PREFS_SECURITY).unwrap();
    assert!(prefs.has(EC_TAG_IPFILTER_SERVERS) && !prefs.has(EC_TAG_IPFILTER_CLIENTS));

    let conn = Packet::new(EC_OP_SET_PREFERENCES).with(
        Tag::empty(EC_TAG_PREFS_CONNECTIONS)
            .with(Tag::int(EC_TAG_CONN_MAX_UL, 20))
            .with(Tag::int(EC_TAG_CONN_MAX_DL, 0)),
    );
    let mut a = app(vec![Packet::new(EC_OP_NOOP), conn]);
    assert_eq!(
        run(&mut a, "set bwlimit up 20"),
        " > Operation was successful.\n > Bandwidth limits: Up: 20 KiB/s, Down: 0 KiB/s.\n > Endgame source rotation is OFF.\n"
    );
    assert_eq!(
        sent(&a)[0]
            .tag(EC_TAG_PREFS_CONNECTIONS)
            .unwrap()
            .child_int(EC_TAG_CONN_MAX_UL),
        20
    );
}

#[test]
fn search_filters_go_into_the_search_tag() {
    let mut a = app(vec![
        Packet::new(EC_OP_STRINGS).with(Tag::int(EC_TAG_SEARCH_ID, 7))
    ]);
    assert_eq!(
        run(
            &mut a,
            "search kad linux --type Iso --min-size 100M iso --artist 'Some One' --min-bitrate 128"
        ),
        " > Search started (id 7).\n"
    );
    let t = &sent(&a)[0].tags[0];
    assert_eq!(t.as_int(), u64::from(EC_SEARCH_KAD));
    assert_eq!(t.child_str(EC_TAG_SEARCH_NAME), "linux iso");
    assert_eq!(t.child_str(EC_TAG_SEARCH_FILE_TYPE), "Iso");
    assert_eq!(t.child_int(EC_TAG_SEARCH_MIN_SIZE), 100 * 1024 * 1024);
    assert_eq!(t.child_str(EC_TAG_SEARCH_ARTIST), "Some One");
    assert_eq!(t.child_int(EC_TAG_SEARCH_MIN_BITRATE), 128);
    assert!(t.child(EC_TAG_SEARCH_EXTENSION).is_none());

    // A quoted phrase belongs to the query, flags inside it included.
    let mut a = app(vec![]);
    run(&mut a, "search global \"a --type b\" c");
    let t = &sent(&a)[0].tags[0];
    assert_eq!(t.child_str(EC_TAG_SEARCH_NAME), "\"a --type b\" c");
    assert_eq!(t.as_int(), u64::from(EC_SEARCH_GLOBAL));

    let mut a = app(vec![]);
    assert_eq!(
        run(&mut a, "search local --min-size"),
        "Invalid search filter syntax.\nType 'help search' to get more help.\nInvalid argument.\nType 'help search local' to get more help.\n"
    );
    assert_eq!(
        run(&mut a, "search local --type Iso"),
        "No search keyword provided.\nType 'help search' to get more help.\nInvalid argument.\nType 'help search local' to get more help.\n"
    );
    assert_eq!(
        run(&mut a, "search linux"),
        "No search type defined.\nType 'help search' to get more help.\n"
    );
    assert!(sent(&a).is_empty());
}

#[test]
fn search_needs_what_the_daemon_supports() {
    let mut a: App<Fake> = App::new(Some(Fake::default()));
    assert_eq!(
        run(&mut a, "search all x"),
        "The connected daemon does not support All searches.\nInvalid argument.\nType 'help search all' to get more help.\n"
    );
    assert!(run(&mut a, "search kad x --title y")
        .starts_with("The connected daemon does not support media search filters.\n"));
    assert!(run(&mut a, "search list")
        .starts_with("The connected daemon does not support search management.\n"));
}

#[test]
fn results_then_download_by_number() {
    let result = |name: &str, size: u64, sources: u64| {
        Tag::int(EC_TAG_SEARCHFILE, 1)
            .with(Tag::hash(EC_TAG_PARTFILE_HASH, HASH))
            .with(Tag::string(EC_TAG_PARTFILE_NAME, name))
            .with(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, size))
            .with(Tag::int(EC_TAG_PARTFILE_SOURCE_COUNT, sources))
    };
    let results = Packet::new(EC_OP_SEARCH_RESULTS)
        .with(result("linux.iso", 5 * 1024 * 1024 + 300 * 1024, 12))
        .with(result("other.iso", 2048, 1));
    let mut a = app(vec![results]);
    let out = run(&mut a, "results 3");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        "Nr.    Filename:                                                                        Size(MiB):  Sources: "
    );
    assert_eq!(lines[1], "-".repeat(107));
    assert_eq!(
        lines[2],
        format!("0.    linux.iso{}     5.300     12", " ".repeat(70))
    );
    assert_eq!(
        lines[3],
        format!("1.    other.iso{}     0.002     1", " ".repeat(70))
    );
    assert_eq!(lines[4], " > Number of search results: 2");
    assert_eq!(sent(&a)[0].tag(EC_TAG_SEARCH_ID).map(Tag::as_int), Some(3));

    assert_eq!(
        run(&mut a, "download 1"),
        "Download File: 1 other.iso\n > Operation was successful.\n"
    );
    let d = &sent(&a)[1];
    assert_eq!(d.opcode, EC_OP_DOWNLOAD_SEARCH_RESULT);
    assert_eq!(d.tags[0].as_hash(), Some(HASH));
    assert_eq!(
        run(&mut a, "download 9"),
        "Invalid argument.\nType 'help download' to get more help.\n"
    );
}

#[test]
fn download_with_an_expired_search() {
    let mut a = app(vec![
        Packet::new(EC_OP_SEARCH_RESULTS).with(Tag::empty(EC_TAG_SEARCH_EXPIRED))
    ]);
    assert_eq!(
        run(&mut a, "download 0 5"),
        "Search expired or unknown ID. Start a new search.\n"
    );
}

#[test]
fn log_lines_print_bare() {
    let mut a = app(vec![Packet::new(EC_OP_LOG)
        .with(Tag::string(
            EC_TAG_STRING,
            " 2026-11-21 10:00:00: started\n",
        ))
        .with(Tag::string(EC_TAG_STRING, "!2026-11-21 10:00:01: error\n"))]);
    assert_eq!(
        run(&mut a, "show log"),
        "2026-11-21 10:00:00: started\n2026-11-21 10:00:01: error\n"
    );
}

#[test]
fn failures_and_unknown_replies() {
    let mut a = app(vec![
        Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, "Invalid link")),
        Packet::new(EC_OP_FAILED),
        Packet::new(0x7e),
    ]);
    assert_eq!(
        run(&mut a, "add nothing"),
        " > Request failed with the following error: Invalid link\n"
    );
    assert_eq!(
        run(&mut a, "reload shared"),
        " > Request failed with an unknown error.\n"
    );
    assert_eq!(
        run(&mut a, "reset"),
        " > Received an unknown reply from the server, OpCode = 0x7e.\n"
    );
}

#[test]
fn add_repairs_ed2k_links() {
    let mut a = app(vec![]);
    run(
        &mut a,
        "add ed2k://%7Cfile%7Ca.iso%7C10%7CABABABABABABABABABABABABABABABAB%7Ch=XYZ%7C/",
    );
    assert_eq!(
        sent(&a)[0].tags[0].as_str(),
        "ed2k://|file|a.iso|10|ABABABABABABABABABABABABABABABAB|h=XYZ|/"
    );
    let mut a = app(vec![]);
    run(&mut a, "add ed2k://|file|a.iso|10|AB|h=XYZ|/");
    assert_eq!(
        sent(&a)[0].tags[0].as_str(),
        "ed2k://|file|a.iso|10|AB|/|h=XYZ|/"
    );
}

#[test]
fn connect_to_an_address_or_everything() {
    let mut a = app(vec![]);
    run(&mut a, "connect 10.1.2.3:4661");
    assert_eq!(sent(&a)[0].opcode, EC_OP_SERVER_CONNECT);
    assert_eq!(sent(&a)[0].tags[0].as_ipv4(), Some(([10, 1, 2, 3], 4661)));
    run(&mut a, "connect");
    assert_eq!(sent(&a)[1].opcode, EC_OP_CONNECT);
    assert_eq!(
        run(&mut a, "connect :4661"),
        "Invalid IP format. Use xxx.xxx.xxx.xxx:xxxx\n"
    );
}

#[test]
fn search_list_stop_and_more() {
    let mut a = app(vec![
        Packet::new(EC_OP_SEARCH_LIST)
            .with(Tag::int(EC_TAG_SEARCH_ID, 2).with(Tag::string(EC_TAG_SEARCH_NAME, "linux"))),
        Packet::new(EC_OP_MISC_DATA),
        Packet::new(EC_OP_MISC_DATA).with(Tag::int(EC_TAG_SEARCH_MORE_REASKABLE, 0)),
        Packet::new(EC_OP_SEARCH_LIST),
    ]);
    assert_eq!(run(&mut a, "search list"), " > 2\tlinux\n");
    assert_eq!(
        run(&mut a, "search stop 2"),
        " > Search stop request processed; retained results were not removed.\n"
    );
    assert_eq!(
        run(&mut a, "search more 2"),
        " > No further results can be requested for this search.\n"
    );
    assert_eq!(run(&mut a, "search list"), " > No retained searches.\n");
    assert!(
        run(&mut a, "search stop 0").starts_with("A search ID from 'search list' is required.\n")
    );
}

#[test]
fn shutdown_quits() {
    let mut a = app(vec![]);
    assert!(a.parse_command("shutdown"));
    assert_eq!(sent(&a)[0].opcode, EC_OP_SHUTDOWN);
}

#[test]
fn help_needs_no_daemon() {
    let mut a: App<Fake> = App::new(None);
    let out = run(&mut a, "help get ipfilter");
    assert!(out.starts_with("GET IPFILTER: Get IP filtering preferences.\n"));
    assert!(out.contains("Available extensions:\nLevel    Get IP filtering level.\nState    "));
}
