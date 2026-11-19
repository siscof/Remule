// SPDX-License-Identifier: GPL-2.0-or-later
//! The log as External Connections read it.

use tracing::Level;

use crate::applog::{header, AppLog, MAX_LINES};

// 2026-11-19T18:30:09.123Z
const T: u64 = 1_795_113_009_123;

#[test]
fn lines_are_written_as_amules_logfile_replays_them() {
    assert_eq!(
        header(T, Level::INFO),
        "2026-11-19T18:30:09.123+00:00 INFO  "
    );
    assert_eq!(
        header(0, Level::ERROR),
        "1970-01-01T00:00:00.000+00:00 ERROR "
    );
    assert_eq!(
        header(951_782_400_000, Level::WARN),
        "2000-02-29T00:00:00.000+00:00 WARN  ",
        "a leap day"
    );
    let log = AppLog::default();
    log.push_at(T, Level::INFO, "hello");
    // Warnings and errors are marked as aMule marks what it shows in the
    // status bar.
    log.push_at(T, Level::WARN, "careful\r\nsecond line\n");
    assert_eq!(
        log.text(),
        concat!(
            " 2026-11-19T18:30:09.123+00:00 INFO  hello\n",
            "!2026-11-19T18:30:09.123+00:00 WARN  careful\n",
            "!2026-11-19T18:30:09.123+00:00 WARN  second line\n",
        )
    );
}

#[test]
fn each_reader_gets_what_it_has_not_seen() {
    let log = AppLog::default();
    let mut a = log.cursor();
    for i in 0..5 {
        log.push_at(T, Level::INFO, &format!("line {i}"));
    }
    // At most so many at a time, then the rest.
    let first = log.read(&mut a, 3);
    assert_eq!(first.len(), 3);
    assert!(first[0].ends_with("line 0\n"));
    let rest = log.read(&mut a, 100);
    assert_eq!(rest.len(), 2);
    assert!(log.read(&mut a, 100).is_empty());
    // A new reader starts at the start.
    let mut b = log.cursor();
    assert_eq!(log.read(&mut b, 100).len(), 5);
    // After a reset everyone starts over, from the reset's own line.
    log.reset();
    let after = log.read(&mut a, 100);
    assert_eq!(after.len(), 1);
    assert!(after[0].ends_with("Log has been reset\n"));
    assert_eq!(log.text().lines().count(), 1);
}

#[test]
fn old_lines_go_and_readers_skip_them() {
    let log = AppLog::default();
    let mut c = log.cursor();
    for i in 0..MAX_LINES + 10 {
        log.push_at(T, Level::INFO, &format!("{i}"));
    }
    assert_eq!(log.text().lines().count(), MAX_LINES);
    let got = log.read(&mut c, usize::MAX);
    assert_eq!(got.len(), MAX_LINES);
    assert!(got[0].ends_with(" 10\n"), "{}", got[0]);
}

#[test]
fn server_messages_are_kept_and_logged() {
    let log = AppLog::default();
    log.server_message("welcome");
    log.server_message("be nice");
    assert_eq!(log.server_text(false), "welcome\nbe nice\n");
    assert!(log.text().contains("ServerMessage: welcome"));
    assert_eq!(log.server_text(true), "welcome\nbe nice\n");
    assert_eq!(log.server_text(false), "");
}
