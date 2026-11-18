// SPDX-License-Identifier: GPL-2.0-or-later
//! The server connector's sweeps, passes, waits and reconnects.

use std::net::SocketAddr;
use std::time::Instant;

use crate::server_conn::{Attempt, Connector, Next, RETRY_AFTER};

fn addr(n: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, n], 4661))
}

fn connect(n: u8, obfuscated: bool) -> Next {
    Next::Connect(Attempt {
        addr: addr(n),
        obfuscated,
    })
}

#[test]
fn servers_are_tried_in_order_then_retried_after_a_wait() {
    let t = Instant::now();
    let mut c = Connector::new(vec![addr(1), addr(2)], false, true);
    assert_eq!(c.start(t), connect(1, false));
    assert_eq!(c.failed(t), connect(2, false));
    assert_eq!(c.failed(t), Next::RetryAt(t + RETRY_AFTER));
    // Nothing before the wait is over, then a sweep from the top.
    assert_eq!(c.poll(t + RETRY_AFTER / 2), None);
    assert_eq!(c.poll(t + RETRY_AFTER), Some(connect(1, false)));
}

#[test]
fn an_obfuscated_pass_comes_before_a_plain_one() {
    let t = Instant::now();
    let mut c = Connector::new(vec![addr(1), addr(2)], true, true);
    assert_eq!(c.start(t), connect(1, true));
    assert_eq!(c.failed(t), connect(2, true));
    assert_eq!(c.failed(t), connect(1, false));
    assert_eq!(c.failed(t), connect(2, false));
    assert_eq!(c.failed(t), Next::RetryAt(t + RETRY_AFTER));
    // The next sweep is obfuscated again.
    assert_eq!(c.poll(t + RETRY_AFTER), Some(connect(1, true)));
}

#[test]
fn a_lost_connection_starts_a_sweep_at_once() {
    let t = Instant::now();
    let mut c = Connector::new(vec![addr(1), addr(2)], false, true);
    c.start(t);
    assert_eq!(c.failed(t), connect(2, false));
    c.logged_in();
    assert_eq!(
        c.connected(),
        Some(Attempt {
            addr: addr(2),
            obfuscated: false
        })
    );
    // From the top of the list, not after the server just lost.
    assert_eq!(c.lost(t), connect(1, false));
    assert_eq!(c.connected(), None);
    assert!(c.connecting().is_some());
}

#[test]
fn without_reconnect_it_stops() {
    let t = Instant::now();
    let mut c = Connector::new(vec![addr(1)], false, false);
    assert_eq!(c.start(t), connect(1, false));
    assert_eq!(c.failed(t), Next::Idle);
    assert_eq!(c.poll(t + RETRY_AFTER * 10), None);

    let mut c = Connector::new(vec![addr(1)], false, false);
    c.start(t);
    c.logged_in();
    assert_eq!(c.lost(t), Next::Idle);
    assert_eq!(c.connected(), None);
}

#[test]
fn no_servers_means_idle() {
    let t = Instant::now();
    let mut c = Connector::new(Vec::new(), true, true);
    assert_eq!(c.start(t), Next::Idle);
    assert_eq!(c.poll(t + RETRY_AFTER), None);
}

#[test]
fn reports_out_of_turn_are_ignored() {
    let t = Instant::now();
    let mut c = Connector::new(vec![addr(1)], false, true);
    // Nothing in progress: neither a failure nor a loss changes anything.
    assert_eq!(c.failed(t), Next::Idle);
    assert_eq!(c.lost(t), Next::Idle);
    c.logged_in();
    assert_eq!(c.connected(), None);
    // A loss while still connecting is a failure, not a loss.
    c.start(t);
    assert_eq!(c.lost(t), Next::Idle);
    assert!(c.connecting().is_some());
}

#[test]
fn one_picked_server_is_tried_obfuscated_then_plain_then_left() {
    let t = Instant::now();
    let mut c = Connector::new(vec![addr(1), addr(2)], true, true);
    assert_eq!(c.connect_to(addr(2)), connect(2, true));
    assert_eq!(c.failed(t), connect(2, false));
    // No sweep, no wait: `singleconnecting`.
    assert_eq!(c.failed(t), Next::Idle);
    assert_eq!(c.connecting(), None);
    assert_eq!(c.poll(t + RETRY_AFTER), None);
    // Logged in to it: a later loss starts a sweep, as any other.
    assert_eq!(c.connect_to(addr(2)), connect(2, true));
    c.logged_in();
    assert_eq!(c.connected().map(|a| a.addr), Some(addr(2)));
    assert_eq!(c.lost(t), connect(1, true));
}

#[test]
fn the_user_disconnects_stops_and_changes_the_list() {
    let t = Instant::now();
    let mut c = Connector::new(vec![addr(1), addr(2), addr(3)], false, true);
    assert_eq!(c.start(t), connect(1, false));
    // Stopping leaves no attempt and no sweep; a disconnect needs a connection.
    c.stop();
    assert_eq!(c.connecting(), None);
    assert!(!c.disconnect());
    assert_eq!(c.start(t), connect(1, false));
    c.logged_in();
    // Stop keeps a connection that is up; disconnect ends it, and nothing follows.
    c.stop();
    assert!(c.connected().is_some());
    assert!(c.disconnect());
    assert_eq!(c.connected(), None);
    assert_eq!(c.lost(t), Next::Idle);
    assert_eq!(c.poll(t + RETRY_AFTER), None);

    // A server removed behind the sweep's position moves it back one, so
    // the next one is not skipped; one added goes last.
    assert_eq!(c.start(t), connect(1, false));
    assert_eq!(c.failed(t), connect(2, false));
    c.remove(addr(1));
    assert_eq!(c.failed(t), connect(3, false));
    c.add(addr(4));
    c.add(addr(4));
    assert_eq!(c.servers(), [addr(2), addr(3), addr(4)]);
    assert_eq!(c.failed(t), connect(4, false));
}
