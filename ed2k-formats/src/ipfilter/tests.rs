// SPDX-License-Identifier: GPL-2.0-or-later
//! Ported from aMule's `unittests/tests/IPFilterIPv6Test.cpp` (scanner and
//! IPv6 range cases), plus IPv4 precedence and thresholds from IPFilter.cpp.

use super::*;

fn a6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn a4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

/// The range lines of a file, as the scanner returns them.
fn scan(text: &[u8]) -> (Vec<LineKind>, usize) {
    let f = IpFilterFile::parse(text);
    let rules = f
        .lines
        .iter()
        .filter(|l| matches!(l.kind, LineKind::Range4(_) | LineKind::Range6(_)))
        .map(|l| l.kind.clone())
        .collect();
    (rules, f.bad_lines())
}

fn filter(rules6: &[(&str, u8, u8)]) -> IpFilter {
    let text: String = rules6
        .iter()
        .map(|(n, p, l)| format!("{n}/{p},{l},x\n"))
        .collect();
    let f = IpFilterFile::parse(text.as_bytes());
    assert_eq!(f.bad_lines(), 0, "{text}");
    IpFilter::build(&[&f])
}

#[test]
fn mixed_input_preserves_legacy_ranges_and_descriptions() {
    let (e, bad) = scan(
        b"# comment\n\
          1.2.3.4 - 1.2.3.5,100,Duh:2.3.4.5-2.3.4.6\n\
          old list: 192.0.2.1-192.0.2.9\n \t2001:db8::1234/64 , 99 ,description:with,commas\r\n\
          2001:db8::2/128,0,no final newline",
    );
    assert_eq!(e.len(), 4);
    assert_eq!(bad, 0);
    let LineKind::Range4(r) = &e[0] else { panic!() };
    assert_eq!(
        (u32::from(r.start), u32::from(r.end), r.level),
        (0x0102_0304, 0x0102_0305, 100)
    );
    assert_eq!(r.description, "Duh:2.3.4.5-2.3.4.6");
    assert_eq!(r.syntax, Syntax::PeerGuardian);
    let LineKind::Range4(r) = &e[1] else { panic!() };
    assert_eq!(
        (u32::from(r.start), u32::from(r.end), r.level),
        (0xc000_0201, 0xc000_0209, 0)
    );
    assert_eq!(
        (r.description.as_str(), r.syntax),
        ("old list", Syntax::AntiP2P)
    );
    let LineKind::Range6(r) = &e[2] else { panic!() };
    assert_eq!((r.network, r.prefix, r.level), (a6("2001:db8::"), 64, 99));
    let LineKind::Range6(r) = &e[3] else { panic!() };
    assert_eq!(r.prefix, 128);
}

#[test]
fn invalid_cidrs_do_not_become_rules() {
    for line in [
        "2001:db8::/129,0,bad",
        "2001:db8::/64,256,bad",
        "2001:::1/64,0,bad",
        "::ffff:c000:201/128,0,mapped",
        "::ffff:192.0.2.1/128,0,mapped",
        "fe80::1%3/64,0,scoped",
        "[2001:db8::]/64,0,brackets",
        "2001:db8::/-1,0,negative",
        "2001:db8::/64x,0,junk",
        "2001:db8::/64,0",
    ] {
        let (e, bad) = scan(format!("{line}\n2001:db8::1/128,0,valid\n").as_bytes());
        assert_eq!(e.len(), 1, "{line}");
        assert_eq!(bad, 1, "{line}");
        assert!(matches!(e[0], LineKind::Range6(_)));
    }
}

#[test]
fn bad_lines_are_consumed_whole() {
    let (e, bad) =
        scan(b"garbage line\nOrg:1.2.3.4-1.2.3.5 trailing text\n2001:db8::/32,0,valid\n");
    assert_eq!(e.len(), 1);
    assert_eq!(bad, 2);
    assert!(matches!(e[0], LineKind::Range6(_)));
}

#[test]
fn prefix_boundaries_and_family_separation() {
    let f = filter(&[("2001:db8::ffff", 65, 99)]);
    assert!(f.is_filtered_v6(a6("2001:db8::"), 100));
    assert!(f.is_filtered_v6(a6("2001:db8::7fff:ffff:ffff:ffff"), 100));
    assert!(!f.is_filtered_v6(a6("2001:db8:0:0:8000::"), 100));
    assert!(!f.is_filtered_v6(a6("2001:db8::1"), 99));
    assert!(!f.is_filtered("192.0.2.1".parse().unwrap(), 100));
    assert!(!f.is_filtered("::ffff:192.0.2.1".parse().unwrap(), 100));
}

#[test]
fn resolved_ranges_preserve_gaps_fragments_and_thresholds() {
    let mut rules = vec![
        ("2001:db8::", 120, 10),
        ("2001:db8::80", 125, 200),
        ("2001:db8::83", 128, 20),
    ];
    let f = filter(&rules);
    for host in 0u128..256 {
        let addr = Ipv6Addr::from(u128::from(a6("2001:db8::")) | host);
        let expected = if host == 131 {
            20
        } else if (128..=135).contains(&host) {
            200
        } else {
            10
        };
        assert!(!f.is_filtered_v6(addr, expected), "{addr}");
        assert!(f.is_filtered_v6(addr, expected + 1), "{addr}");
    }
    assert!(!f.is_filtered_v6(a6("2001:db8::100"), 256));
    assert!(!f.is_filtered_v6(a6("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"), 256));
    // A later wider prefix replaces all fragments, irrespective of specificity.
    rules.push(("2001:db8::", 119, 255));
    let f = filter(&rules);
    assert!(!f.is_filtered_v6(a6("2001:db8::83"), 255));
    assert!(f.is_filtered_v6(a6("2001:db8::1ff"), 256));
    assert!(!f.is_filtered_v6(a6("2001:db8::200"), 256));
}

#[test]
fn full_width_endpoints_and_security_prefix_policy() {
    let mut rules = vec![("::", 0, 0)];
    let f = filter(&rules);
    assert!(
        !f.is_filtered_v6(a6("::"), 1),
        "the unspecified address never matches"
    );
    assert!(f.is_filtered_v6(a6("::1"), 1));
    rules.push(("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128, 200));
    let f = filter(&rules);
    assert!(!f.is_filtered_v6(a6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 100));
    assert!(f.is_filtered_v6(a6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), 100));
    rules.push(("::", 128, 200));
    let f = filter(&rules);
    assert!(f.is_filtered_v6(a6("::1"), 100));
    rules.push(("::", 0, 255));
    let f = filter(&rules);
    assert!(!f.is_filtered_v6(a6("::1"), 255));
    assert!(f.is_filtered_v6(a6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 256));
}

#[test]
fn later_static_rules_override() {
    let dat = IpFilterFile::parse(b"::/0,0,all\n2001:db8::/32,200,exception\n");
    let stat = IpFilterFile::parse(b"2001:db8::1/128,0,static\n");
    let f = IpFilter::build(&[&dat, &stat]);
    assert!(f.is_filtered_v6(a6("2001:db9::1"), 127));
    assert!(!f.is_filtered_v6(a6("2001:db8::2"), 127));
    assert!(f.is_filtered_v6(a6("2001:db8::1"), 127));
    assert_eq!(f.ban_count(127), 2);
    assert_eq!(f.ban_count(0), 0);
    assert!(!IpFilter::build(&[]).is_filtered_v6(a6("2001:db8::1"), 127));
}

#[test]
fn nul_bytes_in_antip2p_lines_are_bad_lines() {
    let text = b"0.0.0.0-0.255.255.255,0,bogon\n\0:1.2.3.4-1.2.3.5\nx:abcdefgh\0:1.2.3.4-1.2.3.5\na:b\0:1.2.3.4-1.2.3.5\nOrg:5.6.7.8-5.6.7.9\n";
    let (e, bad) = scan(text);
    assert_eq!(e.len(), 2);
    assert_eq!(bad, 3);
    let (LineKind::Range4(a), LineKind::Range4(b)) = (&e[0], &e[1]) else {
        panic!()
    };
    assert_eq!(a.description, "bogon");
    assert_eq!(b.description, "Org");
    assert_eq!(u32::from(b.start), 0x0506_0708);
}

#[test]
fn nul_is_read_as_an_ordinary_byte() {
    let (e, _) = scan(b"1.2.3.4-1.2.3.5,0,ab\0cd\n");
    let LineKind::Range4(r) = &e[0] else { panic!() };
    assert_eq!(r.description, "ab\x01cd");
}

#[test]
fn overlong_lines_are_cut() {
    let mut text = vec![b'x'; 70_000];
    text.extend_from_slice(b":1.2.3.4-1.2.3.5\nOrg:5.6.7.8-5.6.7.9\n");
    let (e, bad) = scan(&text);
    assert_eq!(e.len(), 1);
    assert_eq!(bad, 1);
    let LineKind::Range4(r) = &e[0] else { panic!() };
    assert_eq!(r.description, "Org");
}

#[test]
fn ipv4_precedence_threshold_and_bounds() {
    let dat = IpFilterFile::parse(
        b"# eMule ipfilter.dat\n\
          010.000.000.000 - 010.255.255.255 , 000 , private\n\
          010.001.000.000 - 010.001.255.255 , 200 , allowed hole\n\
          1.2.3.4 - 1.2.3.5 , 256 , level too high\n\
          1.2.3.4 - 1.2.3.256 , 0 , ip too high\n\
          9.9.9.9 - 9.9.9.1 , 0 , reversed\n\
          Some Org:255.255.255.0-255.255.255.255\n\
          \n   \n",
    );
    assert_eq!(dat.bad_lines(), 2);
    assert_eq!(
        dat.range_count(),
        4,
        "the reversed range is counted, as aMule logs it"
    );
    let stat = IpFilterFile::parse(b"10.1.2.3 - 10.1.2.3 , 0 , static block\n");
    let f = IpFilter::build(&[&dat, &stat]);
    // Default IPFilterLevel is 127.
    assert!(f.is_filtered_v4(a4("10.0.0.1"), 127));
    assert!(
        !f.is_filtered_v4(a4("10.1.0.1"), 127),
        "the later higher-level rule wins"
    );
    assert!(f.is_filtered_v4(a4("10.1.0.1"), 201));
    assert!(
        f.is_filtered_v4(a4("10.1.2.3"), 127),
        "ipfilter_static.dat wins last"
    );
    assert!(
        !f.is_filtered_v4(a4("9.9.9.5"), 255),
        "reversed ranges are discarded"
    );
    assert!(f.is_filtered_v4(a4("255.255.255.255"), 1));
    assert!(!f.is_filtered_v4(a4("11.0.0.0"), 255));
    assert!(
        !f.is_filtered_v4(a4("10.0.0.1"), 0),
        "level 0 blocks nothing"
    );
    assert!(
        f.is_filtered("::ffff:10.0.0.1".parse().unwrap(), 127),
        "mapped addresses are IPv4"
    );
    // Ranges come out sorted and disjoint.
    assert!(f.ranges4.windows(2).all(|w| w[0].last < w[1].first));
}

#[test]
fn files_write_back_byte_for_byte() {
    for text in [
        &b"# c\r\n1.2.3.4-1.2.3.5,0,x\r\n\r\ngarbage\nOrg:1.1.1.1-1.1.1.2"[..],
        b"",
        b"\n",
        b"only\n",
        b"  \t",
    ] {
        assert_eq!(IpFilterFile::parse(text).write(), text);
    }
    // A whitespace-only last line without a newline is a bad line, as in the scanner.
    assert_eq!(
        IpFilterFile::parse(b"1.2.3.4-1.2.3.5,0,x\n  ").bad_lines(),
        1
    );
    assert_eq!(
        IpFilterFile::parse(b"1.2.3.4-1.2.3.5,0,x\n  \n").bad_lines(),
        0
    );
}
