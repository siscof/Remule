// SPDX-License-Identifier: GPL-2.0-or-later
//! What to offer to servers and publish on Kad, and when.

use std::fs;

use ed2k_hash::FileHashes;
use ed2k_types::ed2k::server_tcp::flags;
use ed2k_types::tags::FileType;
use ed2k_types::Md4Hash;

use crate::publish::{file_keywords, KadPublish, Publisher, KEYWORD_REPUBLISH, SOURCE_REPUBLISH};
use crate::shared::SharedFiles;
use crate::tests_part_file::TempDir;

#[test]
fn keywords_come_from_the_name_without_its_extension() {
    assert_eq!(
        file_keywords("My Great Movie (2009).avi"),
        ["great", "movie", "2009"]
    );
    assert_eq!(file_keywords("remule-0.1.tar.gz"), ["remule"]);
    assert_eq!(file_keywords("clip.mpeg"), ["clip"]);
    // Not an extension aMule knows the shape of: kept.
    assert_eq!(file_keywords("notes.markdown"), ["notes", "markdown"]);
    // Each word once, in the place of its last occurrence.
    assert_eq!(
        file_keywords("the end of the road.txt"),
        ["end", "the", "road"]
    );
}

/// Shared files with made-up hashes: what the publisher sees is the record.
fn shares(dir: &TempDir, files: &[(&str, u64)]) -> SharedFiles {
    let mut s = SharedFiles::load(&dir.0.join("config")).unwrap();
    for (i, (name, size)) in files.iter().enumerate() {
        let p = dir.incoming().join(name);
        fs::write(&p, b"x").unwrap();
        let h = FileHashes {
            size: *size,
            ed2k: Md4Hash([i as u8 + 1; 16]),
            part_hashes: Vec::new(),
            aich_root: None,
            aich_blocks: Vec::new(),
        };
        s.add_hashed(&p, &h, 1, 1);
    }
    s
}

#[test]
fn server_offers_go_in_batches_within_the_limits() {
    let dir = TempDir::new("publish-server");
    let s = shares(
        &dir,
        &[("a.txt", 10), ("b.iso", 20), ("big.mkv", 5_000_000_000)],
    );
    let mut p = Publisher::new();
    // A server without large files, taking two at a time.
    let first = p.server_offer(&s, flags::COMPRESSION, 2, 0);
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|f| f.size < 5_000_000_000 && f.complete));
    assert_eq!(
        first.iter().find(|f| f.name == "b.iso").unwrap().file_type,
        Some(FileType::CdImage)
    );
    // Nothing left for it.
    assert!(p.server_offer(&s, flags::COMPRESSION, 2, 0).is_empty());
    // A server with large files gets the rest.
    let rest = p.server_offer(&s, flags::LARGEFILES, 2, 0);
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].name, "big.mkv");
    // A new connection: everything again.
    p.server_connected();
    assert_eq!(p.server_offer(&s, flags::LARGEFILES, 0, 0).len(), 3);
}

#[test]
fn kad_publishes_go_in_turn() {
    let dir = TempDir::new("publish-kad");
    let mut s = shares(&dir, &[("alpha beta.txt", 10), ("beta gamma.txt", 20)]);
    let mut p = Publisher::new();
    p.update_keywords(&s);
    assert_eq!(p.keyword_count(), 3);
    let t = 1_000_000;
    // Firewalled: nothing.
    assert!(p.kad_publish(&mut s, (0, 0), false, 4662, 1, t).is_empty());

    let first = p.kad_publish(&mut s, (0, 0), true, 4662, 1, t);
    assert_eq!(first.len(), 2, "{first:?}");
    let KadPublish::Keyword { word, files, .. } = &first[0] else {
        panic!("{first:?}")
    };
    assert_eq!(word, "alpha");
    assert_eq!(files.len(), 1);
    assert!(matches!(first[1], KadPublish::Source { size: 10, .. }));
    // Two seconds between starts.
    assert!(p
        .kad_publish(&mut s, (0, 0), true, 4662, 1, t + 1)
        .is_empty());
    let next = p.kad_publish(&mut s, (0, 0), true, 4662, 1, t + 2);
    let KadPublish::Keyword { word, files, .. } = &next[0] else {
        panic!("{next:?}")
    };
    assert_eq!((word.as_str(), files.len()), ("beta", 2));
    assert!(matches!(next[1], KadPublish::Source { size: 20, .. }));
    // Too many publishes running: none started.
    assert!(p
        .kad_publish(&mut s, (2, 3), true, 4662, 1, t + 4)
        .is_empty());
    let third = p.kad_publish(&mut s, (0, 0), true, 4662, 1, t + 6);
    assert!(matches!(&third[0], KadPublish::Keyword { word, .. } if word == "gamma"));
    // Every file is a source for the next five hours, every keyword for a day.
    assert_eq!(third.len(), 1, "{third:?}");
    let mut later = Vec::new();
    for i in 0..10 {
        later.extend(p.kad_publish(&mut s, (0, 0), true, 4662, 1, t + 8 + 2 * i));
    }
    assert!(later.is_empty(), "{later:?}");
    // The source time is kept in known.met.
    let (f, _) = s.get(&Md4Hash([1; 16])).unwrap();
    assert_eq!(u64::from(f.kad_last_publish_src), t + SOURCE_REPUBLISH);
    let again = p.kad_publish(&mut s, (0, 0), true, 4662, 1, t + SOURCE_REPUBLISH + 10);
    assert!(again.iter().any(|x| matches!(x, KadPublish::Source { .. })));
    let again = p.kad_publish(&mut s, (0, 0), true, 4662, 1, t + KEYWORD_REPUBLISH + 10);
    assert!(again
        .iter()
        .any(|x| matches!(x, KadPublish::Keyword { .. })));
}
