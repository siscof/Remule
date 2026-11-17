// SPDX-License-Identifier: GPL-2.0-or-later
//! The shared-folder lists: `shareddir.dat` (aMule 2.3 and eMule), and
//! `shareddir-explicit.dat` / `shareddir-recursive.dat` (aMule-org, which
//! reads `shareddir.dat` only while neither new file exists).
//!
//! Port of `LoadDirListFile`, `LoadLegacySharedDirFile` and
//! `LoadSharedFolderIntents` (Preferences.cpp).
//!
//! One folder per line. aMule writes UTF-8; eMule writes UTF-16LE behind a
//! byte-order mark. Lines are trimmed, and empty lines and `#` comments are
//! skipped. eMule ends every folder in the legacy file with a separator,
//! which is stripped (a root such as `/` or `C:\` keeps its own).

/// The legacy list.
pub const LEGACY_FILE_NAME: &str = "shareddir.dat";
/// Folders shared on their own.
pub const EXPLICIT_FILE_NAME: &str = "shareddir-explicit.dat";
/// Folders shared with everything below them.
pub const RECURSIVE_FILE_NAME: &str = "shareddir-recursive.dat";

/// The folders in one list file, or `None` when it cannot be decoded
/// (aMule: an unreadable file, not an empty one).
pub fn read(bytes: &[u8]) -> Option<Vec<String>> {
    let text = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        if rest.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&units).ok()?
    } else {
        let s = std::str::from_utf8(bytes).ok()?;
        s.strip_prefix('\u{FEFF}').unwrap_or(s).to_owned()
    };
    Some(
        text.split(['\n', '\0'])
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect(),
    )
}

/// `WithoutTrailingSeparator`, for the legacy file's folders.
pub fn without_trailing_separator(dir: &str) -> &str {
    let mut d = dir;
    while d.len() > 1 && d.ends_with(['/', '\\']) && !(d.len() == 3 && d.as_bytes()[1] == b':') {
        d = &d[..d.len() - 1];
    }
    d
}

/// The shared folders of a config directory, as aMule-org decides them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedDirs {
    pub explicit: Vec<String>,
    pub recursive: Vec<String>,
    /// They came from `shareddir.dat`.
    pub legacy: bool,
}

/// `LoadSharedFolderIntents` over the contents of the three files (`None`
/// for one that is missing or unreadable).
pub fn intents(
    explicit: Option<&[u8]>,
    recursive: Option<&[u8]>,
    legacy: Option<&[u8]>,
) -> SharedDirs {
    let e = explicit.and_then(read);
    let r = recursive.and_then(read);
    if e.is_none() && r.is_none() {
        if let Some(l) = legacy.and_then(read) {
            return SharedDirs {
                explicit: l
                    .iter()
                    .map(|d| without_trailing_separator(d).to_owned())
                    .collect(),
                recursive: Vec::new(),
                legacy: true,
            };
        }
    }
    SharedDirs {
        explicit: e.unwrap_or_default(),
        recursive: r.unwrap_or_default(),
        legacy: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_and_utf16_lists() {
        let a = read(b"\xEF\xBB\xBF/home/a\n\n  /home/b  \r\n# not this\n").unwrap();
        assert_eq!(a, ["/home/a", "/home/b"]);
        let mut u = vec![0xFF, 0xFE];
        for c in "C:\\Shared\\\r\nD:\\M\u{fc}sica\\\r\n".encode_utf16() {
            u.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(read(&u).unwrap(), ["C:\\Shared\\", "D:\\M\u{fc}sica\\"]);
        assert_eq!(read(&[0xFF, 0xFE, 0x41]), None);
        assert_eq!(read(b"\xFF\x00bad"), None);
        assert_eq!(read(b"").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn trailing_separators() {
        assert_eq!(without_trailing_separator("C:\\Shared\\"), "C:\\Shared");
        assert_eq!(without_trailing_separator("/srv/x//"), "/srv/x");
        assert_eq!(without_trailing_separator("C:\\"), "C:\\");
        assert_eq!(without_trailing_separator("/"), "/");
    }

    #[test]
    fn the_new_files_win_over_the_legacy_one() {
        let legacy = b"C:\\Old\\\n".as_slice();
        let d = intents(None, None, Some(legacy));
        assert_eq!((d.explicit, d.legacy), (vec!["C:\\Old".to_owned()], true));
        let d = intents(None, Some(b"/r\n"), Some(legacy));
        assert_eq!(d.explicit, Vec::<String>::new());
        assert_eq!(d.recursive, ["/r"]);
        assert!(!d.legacy);
        assert_eq!(intents(None, None, None), SharedDirs::default());
    }
}
