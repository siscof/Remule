// SPDX-License-Identifier: GPL-2.0-or-later
//! The AICH recovery tree and root votes.

use std::net::{Ipv4Addr, Ipv6Addr};

use ed2k_types::ed2k::{EMBLOCKSIZE, PARTSIZE};
use ed2k_types::AichHash;

use crate::aich::{
    block_hashes, signing_key_v4, signing_key_v6, AichTree, RootTrust, RootVotes, IPV6_KEY_BIT,
};
use crate::{aich_block_count, aich_root, Hasher};

const BLOCK: u64 = EMBLOCKSIZE as u64;

fn data(n: u64, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Made-up block hashes for sizes too big to hash.
fn fake_blocks(size: u64) -> Vec<AichHash> {
    (0..aich_block_count(size))
        .map(|i| {
            let mut h = [0u8; 20];
            h[..8].copy_from_slice(&i.to_le_bytes());
            h[19] = 0xA5;
            AichHash(h)
        })
        .collect()
}

#[test]
fn a_full_tree_has_the_root_aich_root_computes() {
    for size in [
        1,
        BLOCK,
        BLOCK + 1,
        PARTSIZE,
        PARTSIZE + 1,
        3 * PARTSIZE + 777_777,
        5 * PARTSIZE,
    ] {
        let blocks = fake_blocks(size);
        let tree = AichTree::from_blocks(size, &blocks).unwrap();
        assert_eq!(tree.root(), aich_root(size, &blocks), "size {size}");
    }
    assert!(AichTree::from_blocks(PARTSIZE, &fake_blocks(PARTSIZE)[1..]).is_none());
}

#[test]
fn recovery_data_round_trips_for_every_part() {
    let size = 3 * PARTSIZE + 500_000;
    let d = data(size, 3);
    let mut h = Hasher::new();
    h.update(&d);
    let hashes = h.finish();
    let root = hashes.aich_root.unwrap();
    let mut full = AichTree::from_blocks(size, &hashes.aich_blocks).unwrap();
    assert_eq!(full.root(), Some(root));

    for part in 0..4u64 {
        let start = part * PARTSIZE;
        let rec = full.part_recovery_data(start).unwrap();
        // count, then (ident 2 + hash 20) per hash, then an empty 32-bit section.
        let count = u16::from_le_bytes([rec[0], rec[1]]) as usize;
        assert_eq!(rec.len(), 2 + count * 22 + 2);
        let end = (start + PARTSIZE).min(size) as usize;
        let blocks = block_hashes(&d[start as usize..end]);
        assert!(count > blocks.len());

        let mut ours = AichTree::with_root(size, root);
        assert!(ours.read_recovery_data(start, &rec), "part {part}");
        assert_eq!(ours.verified_block_hashes(start).unwrap(), blocks);
    }
}

#[test]
fn recovery_data_must_hash_to_the_root() {
    let size = 2 * PARTSIZE + 1000;
    let blocks = fake_blocks(size);
    let mut full = AichTree::from_blocks(size, &blocks).unwrap();
    let root = full.root().unwrap();
    let good = full.part_recovery_data(PARTSIZE).unwrap();

    // One flipped bit in a block hash.
    let mut bad = good.clone();
    bad[2 + 22 * 3 + 5] ^= 1;
    let mut ours = AichTree::with_root(size, root);
    assert!(!ours.read_recovery_data(PARTSIZE, &bad));
    assert!(ours.verified_block_hashes(PARTSIZE).is_none());
    // The bad hashes were dropped; the good data is taken afterwards.
    assert!(ours.read_recovery_data(PARTSIZE, &good));
    assert!(ours.verified_block_hashes(PARTSIZE).is_some());

    // Under another root nothing checks out.
    let mut other = AichTree::with_root(size, AichHash([7; 20]));
    assert!(!other.read_recovery_data(PARTSIZE, &good));
    // Without a root, nothing is read.
    assert!(!AichTree::new(size).read_recovery_data(PARTSIZE, &good));
}

#[test]
fn malformed_recovery_data_is_refused() {
    let size = 2 * PARTSIZE + 1000;
    let mut full = AichTree::from_blocks(size, &fake_blocks(size)).unwrap();
    let root = full.root().unwrap();
    let good = full.part_recovery_data(0).unwrap();
    let fresh = || AichTree::with_root(size, root);

    // Too few hashes announced, or the data cut short.
    let mut wrong_count = good.clone();
    wrong_count[0] -= 1;
    assert!(!fresh().read_recovery_data(0, &wrong_count));
    assert!(!fresh().read_recovery_data(0, &good[..good.len() - 30]));
    // The root's ident (1) may not be sent.
    let mut root_ident = good.clone();
    root_ident[2..4].copy_from_slice(&1u16.to_le_bytes());
    assert!(!fresh().read_recovery_data(0, &root_ident));
    // Not a part boundary, or past the end.
    assert!(!fresh().read_recovery_data(5, &good));
    assert!(!fresh().read_recovery_data(3 * PARTSIZE, &good));
    // Data for part 0 does not recover part 1.
    assert!(!fresh().read_recovery_data(PARTSIZE, &good));
}

#[test]
fn files_over_4_gb_use_32_bit_idents() {
    let size = 5 << 30;
    let blocks = fake_blocks(size);
    let mut full = AichTree::from_blocks(size, &blocks).unwrap();
    let root = full.root().unwrap();
    let part = 400u64;
    let rec = full.part_recovery_data(part * PARTSIZE).unwrap();
    // An empty 16-bit section, then the 32-bit one.
    assert_eq!(&rec[..2], &[0, 0]);
    let count = u16::from_le_bytes([rec[2], rec[3]]) as usize;
    assert_eq!(rec.len(), 4 + count * 24);

    let mut ours = AichTree::with_root(size, root);
    assert!(ours.read_recovery_data(part * PARTSIZE, &rec));
    let first = (part * 53) as usize;
    assert_eq!(
        ours.verified_block_hashes(part * PARTSIZE).unwrap(),
        &blocks[first..first + 53]
    );
}

#[test]
fn a_one_block_file_has_no_recovery_data() {
    let mut t = AichTree::from_blocks(1000, &fake_blocks(1000)).unwrap();
    assert!(t.part_recovery_data(0).is_none());
}

#[test]
fn block_hashes_restart_with_each_block() {
    let d = data(BLOCK * 2 + 10, 1);
    let h = block_hashes(&d);
    assert_eq!(h.len(), 3);
    assert_eq!(h[2], block_hashes(&d[2 * BLOCK as usize..])[0]);
}

// ---- votes ----

fn root(b: u8) -> AichHash {
    AichHash([b; 20])
}

fn key(i: u8) -> u32 {
    signing_key_v4(Ipv4Addr::new(10, i, 0, 1))
}

#[test]
fn ten_agreeing_subnets_make_a_root_trusted() {
    let mut v = RootVotes::default();
    for i in 0..9 {
        assert_eq!(
            v.received(root(1), key(i), false),
            Some(RootTrust::Untrusted(root(1)))
        );
    }
    // The same subnet again does not count.
    assert_eq!(
        v.received(root(1), key(0), false),
        Some(RootTrust::Untrusted(root(1)))
    );
    assert_eq!(
        v.received(root(1), key(9), false),
        Some(RootTrust::Trusted(root(1)))
    );
}

#[test]
fn trust_needs_92_percent() {
    let mut v = RootVotes::default();
    v.received(root(2), key(200), false);
    for i in 0..10 {
        v.received(root(1), key(i), false);
    }
    // 11 of 12 is 91%; 12 of 13 is 92%.
    assert_eq!(
        v.received(root(1), key(10), false),
        Some(RootTrust::Untrusted(root(1)))
    );
    assert_eq!(
        v.received(root(1), key(11), false),
        Some(RootTrust::Trusted(root(1)))
    );
}

#[test]
fn a_subnet_backs_one_root_only() {
    let mut v = RootVotes::default();
    v.received(root(1), key(1), false);
    assert_eq!(v.received(root(2), key(1), false), None);
    // A Kad report gives way to a source.
    let mut v = RootVotes::default();
    v.received(root(1), key(1), true);
    assert_eq!(v.received(root(2), key(1), true), None);
    assert_eq!(
        v.received(root(2), key(1), false),
        Some(RootTrust::Untrusted(root(2)))
    );
}

#[test]
fn signing_keys_cover_a_subnet() {
    assert_eq!(
        signing_key_v4(Ipv4Addr::new(192, 168, 16, 1)),
        signing_key_v4(Ipv4Addr::new(192, 168, 31, 200))
    );
    assert_ne!(
        signing_key_v4(Ipv4Addr::new(192, 168, 16, 1)),
        signing_key_v4(Ipv4Addr::new(192, 168, 32, 1))
    );
    let a: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let b: Ipv6Addr = "2001:db8:1:ffff::2".parse().unwrap();
    let c: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
    assert_eq!(signing_key_v6(a), signing_key_v6(b));
    assert_ne!(signing_key_v6(a), signing_key_v6(c));
    assert_ne!(signing_key_v6(a) & IPV6_KEY_BIT, 0);
}
