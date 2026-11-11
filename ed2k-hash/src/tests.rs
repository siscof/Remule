// SPDX-License-Identifier: GPL-2.0-or-later
//! Known answers from an independent Python reference (pure-Python MD4
//! checked against RFC 1320, hashlib SHA-1, and the AICH tree written from
//! the C++ split rule), plus the published eD2k hash of one part of zeros.

use super::*;

/// The test data: byte i = (i * 7 + i / 9973) mod 256 (as in the reference).
fn data(n: u64) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + i / 9973) & 0xFF) as u8).collect()
}

/// (size, ed2k hash, AICH root) from the Python reference.
const VECTORS: &[(u64, &str, Option<&str>)] = &[
    (0, "31D6CFE0D16AE931B73C59D7E0C089C0", None),
    (
        1,
        "47C61A0FA8738BA77308A8A600F88E4B",
        Some("LOUTZHNQZ74T6UVVEHLUEDSD63W2E6CP"),
    ),
    (
        184_320,
        "08D3E396BBA762691FC4771333436816",
        Some("QZOR2B2OFAFDETJZDK2O3INR4UTNGAGK"),
    ),
    (
        184_321,
        "0BEB5B02178307360966118ACF9DB1AB",
        Some("JUKR5GMO4OOR3BLLRBMDWWMIAVPNXX3A"),
    ),
    (
        9_727_999,
        "B7834418010764279E270FB9F80AEDD7",
        Some("B5ITBMW2KPCZKISZ3Z7B6GFFHMVM6EYI"),
    ),
    (
        9_728_000,
        "9F46AE2FB0B546FF3C19BFE2A7DF18BB",
        Some("OEPKUOSDWTFADWYURNBBWUDMD2KCQ3HE"),
    ),
    (
        9_728_001,
        "1DDFE58A447664A6519EC2A5F63BE995",
        Some("DBYLPD7OT42HWNNQ5GPM45UDSXVH4AVY"),
    ),
    (
        19_456_000,
        "412378B66664F7FF9BA9DEB4D73A8606",
        Some("V7ZIHIJMBUWUJ2ILNMBJZXJDR5YPG3ZZ"),
    ),
    (
        20_462_087,
        "BD6F80B8810B803C9FA4F338FB3A0E90",
        Some("U44EZEMEQGTODZV6N3A3TFOSPWKB4IUU"),
    ),
    (
        29_184_001,
        "62D28623DCD139AC86A5DC2FE4DC4E74",
        Some("AAUIVIMMCCSZHMJPHKJPPW5XUEGOLXQD"),
    ),
];

fn hash_all(d: &[u8]) -> FileHashes {
    let mut h = Hasher::new();
    h.update(d);
    h.finish()
}

#[test]
fn matches_the_independent_reference() {
    for &(size, ed2k, aich) in VECTORS {
        let r = hash_all(&data(size));
        assert_eq!(r.size, size);
        assert_eq!(r.ed2k.to_string(), ed2k, "ed2k of {size} bytes");
        assert_eq!(
            r.aich_root.map(|h| h.to_string()).as_deref(),
            aich,
            "AICH of {size} bytes"
        );
        assert_eq!(r.aich_blocks.len() as u64, aich_block_count(size), "{size}");
        // known.met's part hash list: none for one part, else parts (+1 for an exact multiple).
        assert_eq!(
            r.part_hashes.len(),
            ed2k_types_part_hash_count(size),
            "{size}"
        );
    }
}

/// `m_iED2KPartHashCount`, as known_met::part_hash_count computes it.
fn ed2k_types_part_hash_count(size: u64) -> usize {
    match size / PARTSIZE {
        0 => 0,
        n => n as usize + 1,
    }
}

/// The eD2k hash of 9,728,000 zero bytes is published (it is the case where
/// eMule hashes an extra, empty part): FC21D9AF828F92A8DF64BEAC3357425D. The
/// variant without the empty part would be D7DEF262A127CD79096A108E7A9FC138.
#[test]
fn one_part_of_zeros_has_the_published_hash() {
    let r = hash_all(&vec![0u8; PARTSIZE as usize]);
    assert_eq!(r.ed2k.to_string(), "FC21D9AF828F92A8DF64BEAC3357425D");
    assert_eq!(r.part_hashes.len(), 2);
    assert_eq!(r.part_hashes[1], EMPTY_MD4);
    assert_eq!(
        r.aich_root.unwrap().to_string(),
        "5D3N4HQHIUMQ7IU7A5QLPLI6RHSWOR7B"
    );
}

#[test]
fn chunking_does_not_matter() {
    let d = data(20_462_087);
    let whole = hash_all(&d);
    for chunk in [1usize << 20, 184_320, 9_728_000, 65_536 + 7, 333_333] {
        let mut h = Hasher::new();
        for c in d.chunks(chunk) {
            h.update(c);
        }
        assert_eq!(h.finish(), whole, "chunk {chunk}");
    }
    assert_eq!(hash_reader(&d[..]).unwrap(), whole);
}

#[test]
fn aich_root_from_stored_blocks() {
    let r = hash_all(&data(19_456_000));
    // What known2_64.met stores is enough to rebuild the root.
    assert_eq!(aich_root(r.size, &r.aich_blocks), r.aich_root);
    // The wrong number of blocks, or no data, gives nothing.
    assert_eq!(aich_root(r.size, &r.aich_blocks[1..]), None);
    assert_eq!(aich_root(0, &[]), None);
    assert_eq!(BLOCKS_PER_PART, 53);
    assert_eq!(aich_block_count(PARTSIZE), 53);
    assert_eq!(aich_block_count(PARTSIZE + 1), 54);
    assert_eq!(aich_block_count(1), 1);
}

#[test]
fn ed2k_link_like_create_ed2k_link() {
    let r = hash_all(&data(1));
    assert_eq!(
        r.ed2k_link("my file/v2.txt"),
        "ed2k://|file|my%20filev2.txt|1|47C61A0FA8738BA77308A8A600F88E4B|h=LOUTZHNQZ74T6UVVEHLUEDSD63W2E6CP|/"
    );
    // No AICH root for an empty file, so no h= field.
    assert_eq!(
        hash_all(&[]).ed2k_link("e"),
        "ed2k://|file|e|0|31D6CFE0D16AE931B73C59D7E0C089C0|/"
    );
    // Control characters go, '|' stays (it is only dropped for FAT32).
    assert_eq!(cleanup_name("a\tb|c"), "ab|c");
}
