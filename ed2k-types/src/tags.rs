// SPDX-License-Identifier: GPL-2.0-or-later
//! Tag types and tag ids: files, clients and servers.
//!
//! Port of `include/tags/**`. A tag is a name (an id byte, or a string for
//! Kad and some eD2k metadata), a type, and a value; the codec itself is step
//! 1.4 (`Tag.cpp`).

use std::fmt;
use std::str::FromStr;

// ------------------------------------------------------------- TagTypes.h ---

/// A tag's value type (`enum Tag_Types`).
///
/// `TAGTYPE_STR1`..`TAGTYPE_STR16` are short strings whose length is in the
/// type byte itself: [`TagType::Str`] holds that length, 1..=16.
/// `TAGTYPE_STR17`..`TAGTYPE_STR22` have names in aMule but are refused when
/// read (`CTag` throws "Unknown tag type"), so they are not accepted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TagType {
    /// `TAGTYPE_HASH16`
    Hash16,
    /// `TAGTYPE_STRING`: length-prefixed string.
    String,
    /// `TAGTYPE_UINT32`
    Uint32,
    /// `TAGTYPE_FLOAT32`
    Float32,
    /// `TAGTYPE_BOOL`
    Bool,
    /// `TAGTYPE_BOOLARRAY`
    BoolArray,
    /// `TAGTYPE_BLOB`
    Blob,
    /// `TAGTYPE_UINT16`
    Uint16,
    /// `TAGTYPE_UINT8`
    Uint8,
    /// `TAGTYPE_BSOB`: byte string, 1-byte length.
    Bsob,
    /// `TAGTYPE_UINT64`
    Uint64,
    /// `TAGTYPE_STR1`..`TAGTYPE_STR16`: a string of exactly this many bytes.
    Str(u8),
}

impl TagType {
    /// `TAGTYPE_STR1`.
    pub const STR1: u8 = 0x11;
    /// `TAGTYPE_STR16`, the last short string type a reader accepts.
    pub const STR16: u8 = 0x20;
    /// The longest string a short-string type can carry.
    pub const MAX_SHORT_STR: usize = 16;

    /// The short-string type for a string of `len` bytes, if there is one.
    pub fn short_str(len: usize) -> Option<TagType> {
        (1..=Self::MAX_SHORT_STR)
            .contains(&len)
            .then_some(TagType::Str(len as u8))
    }
}

impl From<TagType> for u8 {
    fn from(t: TagType) -> u8 {
        match t {
            TagType::Hash16 => 0x01,
            TagType::String => 0x02,
            TagType::Uint32 => 0x03,
            TagType::Float32 => 0x04,
            TagType::Bool => 0x05,
            TagType::BoolArray => 0x06,
            TagType::Blob => 0x07,
            TagType::Uint16 => 0x08,
            TagType::Uint8 => 0x09,
            TagType::Bsob => 0x0A,
            TagType::Uint64 => 0x0B,
            TagType::Str(len) => TagType::STR1 - 1 + len,
        }
    }
}

impl TryFrom<u8> for TagType {
    type Error = crate::Unknown<u8>;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0x01 => TagType::Hash16,
            0x02 => TagType::String,
            0x03 => TagType::Uint32,
            0x04 => TagType::Float32,
            0x05 => TagType::Bool,
            0x06 => TagType::BoolArray,
            0x07 => TagType::Blob,
            0x08 => TagType::Uint16,
            0x09 => TagType::Uint8,
            0x0A => TagType::Bsob,
            0x0B => TagType::Uint64,
            TagType::STR1..=TagType::STR16 => TagType::Str(v - TagType::STR1 + 1),
            _ => {
                return Err(crate::Unknown {
                    kind: "TagType",
                    value: v,
                })
            }
        })
    }
}

// ------------------------------------------------------------- FileTags.h ---

wire_enum! {
    /// File tag ids (`FT_*`): ed2k search results, `known.met`, `.part.met`.
    pub enum FileTag: u8 {
        /// `FT_FILENAME`: string
        Filename = 0x01,
        /// `FT_FILESIZE`: uint32 (low half for large files)
        Filesize = 0x02,
        /// `FT_FILETYPE`: string or uint32
        Filetype = 0x03,
        /// `FT_FILEFORMAT`: string
        Fileformat = 0x04,
        /// `FT_LASTSEENCOMPLETE`: uint32
        LastSeenComplete = 0x05,
        /// `FT_TRANSFERRED`: uint32
        Transferred = 0x08,
        /// `FT_GAPSTART`: uint32
        GapStart = 0x09,
        /// `FT_GAPEND`: uint32
        GapEnd = 0x0A,
        /// `FT_PARTFILENAME`: string
        PartFilename = 0x12,
        /// `FT_OLDDLPRIORITY`: no longer used
        OldDlPriority = 0x13,
        /// `FT_STATUS`: uint32
        Status = 0x14,
        /// `FT_SOURCES`: uint32
        Sources = 0x15,
        /// `FT_PERMISSIONS`: uint32
        Permissions = 0x16,
        /// `FT_OLDULPRIORITY`: no longer used
        OldUlPriority = 0x17,
        /// `FT_DLPRIORITY` (was 0x13)
        DlPriority = 0x18,
        /// `FT_ULPRIORITY` (was 0x17)
        UlPriority = 0x19,
        /// `FT_KADLASTPUBLISHKEY`: uint32
        KadLastPublishKey = 0x20,
        /// `FT_KADLASTPUBLISHSRC`: uint32
        KadLastPublishSrc = 0x21,
        /// `FT_FLAGS`: uint32
        Flags = 0x22,
        /// `FT_DL_ACTIVE_TIME`: uint32
        DlActiveTime = 0x23,
        /// `FT_CORRUPTEDPARTS`: string
        CorruptedParts = 0x24,
        /// `FT_DL_PREVIEW`
        DlPreview = 0x25,
        /// `FT_KADLASTPUBLISHNOTES`: uint32
        KadLastPublishNotes = 0x26,
        /// `FT_AICH_HASH`
        AichHash = 0x27,
        /// `FT_LASTSEEN`: uint32. aMule-internal: when the file was last seen
        /// on disk, so `known.met` entries can expire. eMule ignores it.
        LastSeen = 0x28,
        /// `FT_COMPLETE_SOURCES`: sources sharing the complete file (eserver 16.46+)
        CompleteSources = 0x30,
        /// `FT_PUBLISHINFO`: uint32
        PublishInfo = 0x33,
        /// `FT_FILESIZE_HI`: uint32, high half of a large file's size
        FilesizeHi = 0x3A,
        /// `FT_ATTRANSFERRED`: uint32, all-time transferred (low half)
        AtTransferred = 0x50,
        /// `FT_ATREQUESTED`: uint32
        AtRequested = 0x51,
        /// `FT_ATACCEPTED`: uint32
        AtAccepted = 0x52,
        /// `FT_CATEGORY`: uint32
        Category = 0x53,
        /// `FT_ATTRANSFERREDHI`: uint32, all-time transferred (high half)
        AtTransferredHi = 0x54,
        /// `FT_LASTUPLOADED`: uint32, last time data was uploaded for this file
        LastUploaded = 0x55,
        /// `FT_SHAREDSINCE`: uint32, when the file was completed / first shared
        SharedSince = 0x56,
        /// `FT_MEDIA_PROBE_FAILED`: uint32, aMule-internal, never published.
        /// 1: legacy ffprobe failure (one retry); 2: probed, nothing usable.
        MediaProbeFailed = 0x57,
        /// `FT_VERIFY_DATE`: uint32, aMule-internal, last Verify Local Data run
        VerifyDate = 0x58,
        /// `FT_VERIFY_CORRUPTMD4`: string, "p,p,p" corrupt parts
        VerifyCorruptMd4 = 0x59,
        /// `FT_VERIFY_CORRUPTAICH`: string, "p:b.b;p:b" corrupt AICH blocks per part
        VerifyCorruptAich = 0x5A,
        /// `FT_MEDIA_ARTIST`: string
        MediaArtist = 0xD0,
        /// `FT_MEDIA_ALBUM`: string
        MediaAlbum = 0xD1,
        /// `FT_MEDIA_TITLE`: string
        MediaTitle = 0xD2,
        /// `FT_MEDIA_LENGTH`: uint32
        MediaLength = 0xD3,
        /// `FT_MEDIA_BITRATE`: uint32
        MediaBitrate = 0xD4,
        /// `FT_MEDIA_CODEC`: string
        MediaCodec = 0xD5,
        /// `FT_FILERATING`: uint8
        FileRating = 0xF7,
    }
}

/// Kad tag names (`TAG_*`). On Kad, tags are named by strings; these are the
/// one-byte names, plus eMuleAI's multi-character ones. Several ids mirror
/// the [`FileTag`] ones.
pub mod kad {
    /// `TAG_FILENAME`: string
    pub const FILENAME: &[u8] = b"\x01";
    /// `TAG_FILESIZE`: uint32
    pub const FILESIZE: &[u8] = b"\x02";
    /// `TAG_FILESIZE_HI`: uint32
    pub const FILESIZE_HI: &[u8] = b"\x3A";
    /// `TAG_FILETYPE`: string
    pub const FILETYPE: &[u8] = b"\x03";
    /// `TAG_FILEFORMAT`: string
    pub const FILEFORMAT: &[u8] = b"\x04";
    /// `TAG_COLLECTION`
    pub const COLLECTION: &[u8] = b"\x05";
    /// `TAG_PART_PATH`: string
    pub const PART_PATH: &[u8] = b"\x06";
    /// `TAG_PART_HASH`
    pub const PART_HASH: &[u8] = b"\x07";
    /// `TAG_COPIED`: uint32
    pub const COPIED: &[u8] = b"\x08";
    /// `TAG_GAP_START`: uint32
    pub const GAP_START: &[u8] = b"\x09";
    /// `TAG_GAP_END`: uint32
    pub const GAP_END: &[u8] = b"\x0A";
    /// `TAG_DESCRIPTION`: string
    pub const DESCRIPTION: &[u8] = b"\x0B";
    /// `TAG_PING`
    pub const PING: &[u8] = b"\x0C";
    /// `TAG_FAIL`
    pub const FAIL: &[u8] = b"\x0D";
    /// `TAG_PREFERENCE`
    pub const PREFERENCE: &[u8] = b"\x0E";
    /// `TAG_PORT`
    pub const PORT: &[u8] = b"\x0F";
    /// `TAG_IP_ADDRESS`
    pub const IP_ADDRESS: &[u8] = b"\x10";
    /// `TAG_VERSION`: string
    pub const VERSION: &[u8] = b"\x11";
    /// `TAG_TEMPFILE`: string
    pub const TEMPFILE: &[u8] = b"\x12";
    /// `TAG_PRIORITY`: uint32
    pub const PRIORITY: &[u8] = b"\x13";
    /// `TAG_STATUS`: uint32
    pub const STATUS: &[u8] = b"\x14";
    /// `TAG_SOURCES`: uint32. Same name as [`AVAILABILITY`].
    pub const SOURCES: &[u8] = b"\x15";
    /// `TAG_AVAILABILITY`: uint32. Same name as [`SOURCES`].
    pub const AVAILABILITY: &[u8] = b"\x15";
    /// `TAG_PERMISSIONS`. Same name as [`QTIME`].
    pub const PERMISSIONS: &[u8] = b"\x16";
    /// `TAG_QTIME`. Same name as [`PERMISSIONS`].
    pub const QTIME: &[u8] = b"\x16";
    /// `TAG_PARTS`
    pub const PARTS: &[u8] = b"\x17";
    /// `TAG_AICHHASH`: string (base32). Not a Kad wire tag: the AICH root a
    /// Kad search agreed on, handed to the search list. Shares `FT_AICH_HASH`'s id.
    pub const AICHHASH: &[u8] = b"\x27";
    /// `TAG_PUBLISHINFO`: uint32
    pub const PUBLISHINFO: &[u8] = b"\x33";
    /// `TAG_KADAICHHASHPUB`: BSOB, a 20-byte AICH hash. Only sent to peers at
    /// Kad version >= [`crate::kad::version::V9_50A`].
    pub const KADAICHHASHPUB: &[u8] = b"\x36";
    /// `TAG_KADAICHHASHRESULT`: BSOB, `<Count 1>{<Publishers 1><AICH Hash 20>}*Count`.
    /// Only honoured from senders at Kad version >= 0x09.
    pub const KADAICHHASHRESULT: &[u8] = b"\x37";
    /// `TAG_MEDIA_ARTIST`: string
    pub const MEDIA_ARTIST: &[u8] = b"\xD0";
    /// `TAG_MEDIA_ALBUM`: string
    pub const MEDIA_ALBUM: &[u8] = b"\xD1";
    /// `TAG_MEDIA_TITLE`: string
    pub const MEDIA_TITLE: &[u8] = b"\xD2";
    /// `TAG_MEDIA_LENGTH`: uint32
    pub const MEDIA_LENGTH: &[u8] = b"\xD3";
    /// `TAG_MEDIA_BITRATE`: uint32
    pub const MEDIA_BITRATE: &[u8] = b"\xD4";
    /// `TAG_MEDIA_CODEC`: string
    pub const MEDIA_CODEC: &[u8] = b"\xD5";
    /// `TAG_KADMISCOPTIONS`: uint8
    pub const KADMISCOPTIONS: &[u8] = b"\xF2";
    /// `TAG_ENCRYPTION`: uint8
    pub const ENCRYPTION: &[u8] = b"\xF3";
    /// `TAG_FILERATING`: uint8
    pub const FILERATING: &[u8] = b"\xF7";
    /// `TAG_BUDDYHASH`: string
    pub const BUDDYHASH: &[u8] = b"\xF8";
    /// `TAG_CLIENTLOWID`: uint32
    pub const CLIENTLOWID: &[u8] = b"\xF9";
    /// `TAG_SERVERPORT`: uint16
    pub const SERVERPORT: &[u8] = b"\xFA";
    /// `TAG_SERVERIP`: uint32
    pub const SERVERIP: &[u8] = b"\xFB";
    /// `TAG_SOURCEUPORT`: uint16
    pub const SOURCEUPORT: &[u8] = b"\xFC";
    /// `TAG_SOURCEPORT`: uint16
    pub const SOURCEPORT: &[u8] = b"\xFD";
    /// `TAG_SOURCEIP`: uint32
    pub const SOURCEIP: &[u8] = b"\xFE";
    /// `TAG_SOURCETYPE`: uint8
    pub const SOURCETYPE: &[u8] = b"\xFF";
    /// `TAG_IPV6`: string, an unfirewalled IPv6 address as exactly 32 hex
    /// characters, most significant byte first (eMuleAI vendor tag).
    pub const IPV6: &[u8] = b"ip6";
    /// `TAG_SERVINGBUDDYIPV6`: string, the serving buddy's IPv6, same format
    /// (eMuleAI vendor tag; unused by aMule).
    pub const SERVINGBUDDYIPV6: &[u8] = b"bi6";
}

/// eDonkeyHybrid media tags, named by strings in eD2k search results. Note the
/// mixed case, which is as on the wire.
pub mod ed2k_media {
    /// `FT_ED2K_MEDIA_ARTIST`: string
    pub const ARTIST: &str = "Artist";
    /// `FT_ED2K_MEDIA_ALBUM`: string
    pub const ALBUM: &str = "Album";
    /// `FT_ED2K_MEDIA_TITLE`: string
    pub const TITLE: &str = "Title";
    /// `FT_ED2K_MEDIA_LENGTH`: string (not a number)
    pub const LENGTH: &str = "length";
    /// `FT_ED2K_MEDIA_BITRATE`: uint32
    pub const BITRATE: &str = "bitrate";
    /// `FT_ED2K_MEDIA_CODEC`: string
    pub const CODEC: &str = "codec";
}

/// A value of [`FileTag::Filetype`] (`ED2KFTSTR_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileType {
    /// `ED2KFTSTR_AUDIO`
    Audio,
    /// `ED2KFTSTR_VIDEO`
    Video,
    /// `ED2KFTSTR_IMAGE`
    Image,
    /// `ED2KFTSTR_DOCUMENT`
    Document,
    /// `ED2KFTSTR_PROGRAM`
    Program,
    /// `ED2KFTSTR_ARCHIVE`: *Mule internal use only.
    Archive,
    /// `ED2KFTSTR_CDIMAGE`: *Mule internal use only.
    CdImage,
}

impl FileType {
    pub const ALL: [FileType; 7] = [
        FileType::Audio,
        FileType::Video,
        FileType::Image,
        FileType::Document,
        FileType::Program,
        FileType::Archive,
        FileType::CdImage,
    ];

    /// The string sent on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            FileType::Audio => "Audio",
            FileType::Video => "Video",
            FileType::Image => "Image",
            FileType::Document => "Doc",
            FileType::Program => "Pro",
            FileType::Archive => "Arc",
            FileType::CdImage => "Iso",
        }
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A string that is not one of the `ED2KFTSTR_*` values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownFileType(pub String);

impl fmt::Display for UnknownFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown file type {:?}", self.0)
    }
}

impl std::error::Error for UnknownFileType {}

impl FromStr for FileType {
    type Err = UnknownFileType;
    /// Case-sensitive: the wire values are exactly the `ED2KFTSTR_*` strings.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FileType::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| UnknownFileType(s.to_owned()))
    }
}

/// `ED2KFileTypesMap` (OtherFunctions.cpp): extension (lower case, without
/// the dot) to file type, sorted for a binary search.
const EXTENSIONS: &[(&str, FileType)] = &[
    ("3g2", FileType::Video),
    ("3gp", FileType::Video),
    ("3gp2", FileType::Video),
    ("3gpp", FileType::Video),
    ("669", FileType::Audio),
    ("7z", FileType::Archive),
    ("aa", FileType::Audio),
    ("aac", FileType::Audio),
    ("aax", FileType::Audio),
    ("ac3", FileType::Audio),
    ("ace", FileType::Archive),
    ("aif", FileType::Audio),
    ("aifc", FileType::Audio),
    ("aiff", FileType::Audio),
    ("alz", FileType::Archive),
    ("amf", FileType::Audio),
    ("amr", FileType::Audio),
    ("ams", FileType::Audio),
    ("amv", FileType::Video),
    ("ape", FileType::Audio),
    ("apk", FileType::Program),
    ("apng", FileType::Image),
    ("app", FileType::Program),
    ("appimage", FileType::Program),
    ("appx", FileType::Program),
    ("arc", FileType::Archive),
    ("arj", FileType::Archive),
    ("arw", FileType::Image),
    ("asf", FileType::Video),
    ("au", FileType::Audio),
    ("aud", FileType::Audio),
    ("audio", FileType::Audio),
    ("avi", FileType::Video),
    ("avif", FileType::Image),
    ("azw", FileType::Document),
    ("azw3", FileType::Document),
    ("b5t", FileType::CdImage),
    ("b6t", FileType::CdImage),
    ("bat", FileType::Program),
    ("bik", FileType::Video),
    ("bin", FileType::CdImage),
    ("bmp", FileType::Image),
    ("bwa", FileType::CdImage),
    ("bwi", FileType::CdImage),
    ("bws", FileType::CdImage),
    ("bwt", FileType::CdImage),
    ("bz2", FileType::Archive),
    ("cab", FileType::Archive),
    ("caf", FileType::Audio),
    ("cb7", FileType::Archive),
    ("cba", FileType::Archive),
    ("cbr", FileType::Archive),
    ("cbt", FileType::Archive),
    ("cbz", FileType::Archive),
    ("ccd", FileType::CdImage),
    ("cda", FileType::Audio),
    ("cdi", FileType::CdImage),
    ("chm", FileType::Document),
    ("cmd", FileType::Program),
    ("com", FileType::Program),
    ("cpl", FileType::Program),
    ("cr2", FileType::Image),
    ("cr3", FileType::Image),
    ("css", FileType::Document),
    ("csv", FileType::Document),
    ("cue", FileType::CdImage),
    ("daa", FileType::CdImage),
    ("dbm", FileType::Audio),
    ("dcx", FileType::Image),
    ("deb", FileType::Program),
    ("dff", FileType::Audio),
    ("divx", FileType::Video),
    ("diz", FileType::Document),
    ("djvu", FileType::Document),
    ("dmf", FileType::Audio),
    ("dmg", FileType::CdImage),
    ("dng", FileType::Image),
    ("doc", FileType::Document),
    ("docx", FileType::Document),
    ("dot", FileType::Document),
    ("dotx", FileType::Document),
    ("dsf", FileType::Audio),
    ("dsm", FileType::Audio),
    ("dts", FileType::Audio),
    ("emf", FileType::Image),
    ("epub", FileType::Document),
    ("exe", FileType::Program),
    ("f4v", FileType::Video),
    ("far", FileType::Audio),
    ("fb2", FileType::Document),
    ("flac", FileType::Audio),
    ("flatpak", FileType::Program),
    ("flc", FileType::Video),
    ("fli", FileType::Video),
    ("flic", FileType::Video),
    ("flv", FileType::Video),
    ("gif", FileType::Image),
    ("gz", FileType::Archive),
    ("h264", FileType::Video),
    ("h265", FileType::Video),
    ("hdmov", FileType::Video),
    ("heic", FileType::Image),
    ("heif", FileType::Image),
    ("hevc", FileType::Video),
    ("hlp", FileType::Document),
    ("hqx", FileType::Archive),
    ("hta", FileType::Program),
    ("htm", FileType::Document),
    ("html", FileType::Document),
    ("ico", FileType::Image),
    ("ifo", FileType::Video),
    ("img", FileType::CdImage),
    ("iso", FileType::CdImage),
    ("isz", FileType::CdImage),
    ("it", FileType::Audio),
    ("j2k", FileType::Image),
    ("jfif", FileType::Image),
    ("jp2", FileType::Image),
    ("jpe", FileType::Image),
    ("jpeg", FileType::Image),
    ("jpg", FileType::Image),
    ("js", FileType::Program),
    ("jse", FileType::Program),
    ("json", FileType::Document),
    ("jxl", FileType::Image),
    ("key", FileType::Document),
    ("kfx", FileType::Document),
    ("lha", FileType::Archive),
    ("lz", FileType::Archive),
    ("lz4", FileType::Archive),
    ("lzh", FileType::Archive),
    ("lzma", FileType::Archive),
    ("m1a", FileType::Audio),
    ("m1v", FileType::Video),
    ("m2a", FileType::Audio),
    ("m2t", FileType::Video),
    ("m2ts", FileType::Video),
    ("m2v", FileType::Video),
    ("m4a", FileType::Audio),
    ("m4v", FileType::Video),
    ("markdown", FileType::Document),
    ("md", FileType::Document),
    ("mdf", FileType::CdImage),
    ("mdl", FileType::Audio),
    ("mds", FileType::CdImage),
    ("mdx", FileType::CdImage),
    ("med", FileType::Audio),
    ("mid", FileType::Audio),
    ("midi", FileType::Audio),
    ("mka", FileType::Audio),
    ("mkv", FileType::Video),
    ("mobi", FileType::Document),
    ("mod", FileType::Audio),
    ("mol", FileType::Audio),
    ("mov", FileType::Video),
    ("movie", FileType::Video),
    ("mp1", FileType::Audio),
    ("mp1v", FileType::Video),
    ("mp2", FileType::Audio),
    ("mp2v", FileType::Video),
    ("mp3", FileType::Audio),
    ("mp4", FileType::Video),
    ("mpa", FileType::Audio),
    ("mpc", FileType::Audio),
    ("mpe", FileType::Video),
    ("mpeg", FileType::Video),
    ("mpg", FileType::Video),
    ("mpp", FileType::Audio),
    ("mps", FileType::Video),
    ("mpv", FileType::Video),
    ("mpv1", FileType::Video),
    ("mpv2", FileType::Video),
    ("msc", FileType::Program),
    ("msi", FileType::Program),
    ("msix", FileType::Program),
    ("mtm", FileType::Audio),
    ("mts", FileType::Video),
    ("mxf", FileType::Video),
    ("nef", FileType::Image),
    ("nfo", FileType::Document),
    ("nrg", FileType::CdImage),
    ("nst", FileType::Audio),
    ("numbers", FileType::Document),
    ("odp", FileType::Document),
    ("ods", FileType::Document),
    ("odt", FileType::Document),
    ("oga", FileType::Audio),
    ("ogg", FileType::Audio),
    ("ogm", FileType::Video),
    ("ogv", FileType::Video),
    ("okt", FileType::Audio),
    ("opus", FileType::Audio),
    ("orf", FileType::Image),
    ("ott", FileType::Document),
    ("oxps", FileType::Document),
    ("pages", FileType::Document),
    ("pak", FileType::Archive),
    ("par", FileType::Archive),
    ("par2", FileType::Archive),
    ("pct", FileType::Image),
    ("pcx", FileType::Image),
    ("pdf", FileType::Document),
    ("pic", FileType::Image),
    ("pict", FileType::Image),
    ("png", FileType::Image),
    ("pps", FileType::Document),
    ("ppt", FileType::Document),
    ("ps", FileType::Document),
    ("ps1", FileType::Program),
    ("psd", FileType::Image),
    ("psd1", FileType::Program),
    ("psm", FileType::Audio),
    ("psm1", FileType::Program),
    ("psp", FileType::Image),
    ("ptm", FileType::Audio),
    ("pva", FileType::Video),
    ("qcow2", FileType::CdImage),
    ("qt", FileType::Video),
    ("ra", FileType::Audio),
    ("raf", FileType::Image),
    ("ram", FileType::Video),
    ("rar", FileType::Archive),
    ("ratdvd", FileType::Video),
    ("rm", FileType::Video),
    ("rmi", FileType::Audio),
    ("rmm", FileType::Video),
    ("rmvb", FileType::Video),
    ("rpm", FileType::Program),
    ("rtf", FileType::Document),
    ("rv", FileType::Video),
    ("rv9", FileType::Video),
    ("rw2", FileType::Image),
    ("s3m", FileType::Audio),
    ("scr", FileType::Program),
    ("sea", FileType::Archive),
    ("sh", FileType::Program),
    ("sit", FileType::Archive),
    ("sitx", FileType::Archive),
    ("smil", FileType::Video),
    ("smk", FileType::Video),
    ("snap", FileType::Program),
    ("snd", FileType::Audio),
    ("stm", FileType::Audio),
    ("sub", FileType::CdImage),
    ("svg", FileType::Image),
    ("swf", FileType::Video),
    ("sxc", FileType::Document),
    ("sxi", FileType::Document),
    ("sxw", FileType::Document),
    ("tar", FileType::Archive),
    ("tbz2", FileType::Archive),
    ("tex", FileType::Document),
    ("text", FileType::Document),
    ("tga", FileType::Image),
    ("tgz", FileType::Archive),
    ("tif", FileType::Image),
    ("tiff", FileType::Image),
    ("tlz", FileType::Archive),
    ("toast", FileType::CdImage),
    ("tp", FileType::Video),
    ("ts", FileType::Video),
    ("txt", FileType::Document),
    ("txz", FileType::Archive),
    ("uc2", FileType::Archive),
    ("uif", FileType::CdImage),
    ("ult", FileType::Audio),
    ("umx", FileType::Audio),
    ("vbe", FileType::Program),
    ("vbs", FileType::Program),
    ("vcd", FileType::CdImage),
    ("vdi", FileType::CdImage),
    ("vhd", FileType::CdImage),
    ("vhdx", FileType::CdImage),
    ("vid", FileType::Video),
    ("video", FileType::Video),
    ("vivo", FileType::Video),
    ("vmdk", FileType::CdImage),
    ("vob", FileType::Video),
    ("vp6", FileType::Video),
    ("wav", FileType::Audio),
    ("weba", FileType::Audio),
    ("webm", FileType::Video),
    ("webp", FileType::Image),
    ("wim", FileType::CdImage),
    ("wm", FileType::Video),
    ("wma", FileType::Audio),
    ("wmf", FileType::Image),
    ("wmp", FileType::Image),
    ("wmv", FileType::Video),
    ("wow", FileType::Audio),
    ("wri", FileType::Document),
    ("wsf", FileType::Program),
    ("wsh", FileType::Program),
    ("wv", FileType::Audio),
    ("xcf", FileType::Image),
    ("xls", FileType::Document),
    ("xlt", FileType::Document),
    ("xm", FileType::Audio),
    ("xml", FileType::Document),
    ("xpi", FileType::Program),
    ("xpm", FileType::Image),
    ("xps", FileType::Document),
    ("xvid", FileType::Video),
    ("xz", FileType::Archive),
    ("yaml", FileType::Document),
    ("yml", FileType::Document),
    ("z", FileType::Archive),
    ("zip", FileType::Archive),
    ("zoo", FileType::Archive),
    ("zst", FileType::Archive),
];

impl FileType {
    /// `GetED2KFileTypeID`: the type of a file by its extension; `None`
    /// for no extension or an unknown one (`ED2KFT_ANY`).
    pub fn of_name(name: &str) -> Option<FileType> {
        let (_, ext) = name.rsplit_once('.')?;
        let ext = ext.to_ascii_lowercase();
        EXTENSIONS
            .binary_search_by(|(e, _)| (*e).cmp(ext.as_str()))
            .ok()
            .map(|i| EXTENSIONS[i].1)
    }

    /// `GetED2KFileTypeSearchID`: archives and disc images are published
    /// and searched as programs.
    pub const fn published(self) -> FileType {
        match self {
            FileType::Archive | FileType::CdImage => FileType::Program,
            t => t,
        }
    }

    /// `EED2KFileType`: the integer servers with `SRV_TCPFLG_TYPETAGINTEGER`
    /// take in `FT_FILETYPE`.
    pub const fn id(self) -> u32 {
        match self {
            FileType::Audio => 1,
            FileType::Video => 2,
            FileType::Image => 3,
            FileType::Program => 4,
            FileType::Document => 5,
            FileType::Archive => 6,
            FileType::CdImage => 7,
        }
    }
}

// ----------------------------------------------------------- ClientTags.h ---

wire_enum! {
    /// Hello tag ids (`enum client_tags`).
    pub enum ClientTag: u8 {
        /// `CT_NAME`
        Name = 0x01,
        /// `CT_SERVER_UDPSEARCH_FLAGS`: see [`server_udp_caps`]
        ServerUdpSearchFlags = 0x0E,
        /// `CT_PORT`
        Port = 0x0F,
        /// `CT_VERSION`
        Version = 0x11,
        /// `CT_SERVER_FLAGS`: tells a server our features, see [`server_caps`]
        ServerFlags = 0x20,
        /// `CT_EMULE_SERVINGBUDDYIPV6`: hash, the serving buddy's IPv6 (eMuleAI)
        EmuleServingBuddyIpv6 = 0xA0,
        /// `CT_MOD_MISCOPTIONS`: uint32 capability bitfield (eMuleAI)
        ModMiscOptions = 0xAA,
        /// `CT_MOD_YOUR_IP`: hash, the address the peer saw us arrive from (eMuleAI)
        ModYourIp = 0xAD,
        /// `CT_MOD_IP_V6`: hash, the client's IPv6 address (eMuleAI)
        ModIpV6 = 0xAE,
        /// `CT_EMULECOMPAT_OPTIONS`
        EmuleCompatOptions = 0xEF,
        /// `CT_EMULE_RESERVED1`
        EmuleReserved1 = 0xF0,
        /// `CT_EMULE_RESERVED2`
        EmuleReserved2 = 0xF1,
        /// `CT_EMULE_RESERVED3`
        EmuleReserved3 = 0xF2,
        /// `CT_EMULE_RESERVED4`
        EmuleReserved4 = 0xF3,
        /// `CT_EMULE_RESERVED5`
        EmuleReserved5 = 0xF4,
        /// `CT_EMULE_RESERVED6`
        EmuleReserved6 = 0xF5,
        /// `CT_EMULE_RESERVED7`
        EmuleReserved7 = 0xF6,
        /// `CT_EMULE_RESERVED8`
        EmuleReserved8 = 0xF7,
        /// `CT_EMULE_RESERVED9`
        EmuleReserved9 = 0xF8,
        /// `CT_EMULE_UDPPORTS`
        EmuleUdpPorts = 0xF9,
        /// `CT_EMULE_MISCOPTIONS1`
        EmuleMiscOptions1 = 0xFA,
        /// `CT_EMULE_VERSION`
        EmuleVersion = 0xFB,
        /// `CT_EMULE_BUDDYIP`
        EmuleBuddyIp = 0xFC,
        /// `CT_EMULE_BUDDYUDP`
        EmuleBuddyUdp = 0xFD,
        /// `CT_EMULE_MISCOPTIONS2`
        EmuleMiscOptions2 = 0xFE,
        /// `CT_EMULE_RESERVED13`
        EmuleReserved13 = 0xFF,
    }
}

wire_enum! {
    /// Tags of the old `OP_EMULEINFO` packet (`enum MuleInfo_tags`).
    pub enum MuleInfoTag: u8 {
        /// `ET_COMPRESSION`
        Compression = 0x20,
        /// `ET_UDPPORT`
        UdpPort = 0x21,
        /// `ET_UDPVER`
        UdpVer = 0x22,
        /// `ET_SOURCEEXCHANGE`
        SourceExchange = 0x23,
        /// `ET_COMMENTS`
        Comments = 0x24,
        /// `ET_EXTENDEDREQUEST`
        ExtendedRequest = 0x25,
        /// `ET_COMPATIBLECLIENT`
        CompatibleClient = 0x26,
        /// `ET_FEATURES`: bit 0 SecIdent v1, bit 1 SecIdent v2
        Features = 0x27,
        /// `ET_MOD_VERSION`
        ModVersion = 0x55,
        /// `ET_OS_INFO`: a reused random tag (MOD_OXY)
        OsInfo = 0x94,
    }
}

/// Our capabilities, sent to a server in [`ClientTag::ServerFlags`]
/// (`enum ServerCapabilites`).
pub mod server_caps {
    /// `SRVCAP_ZLIB` (aMule's old name: `CAPABLE_ZLIB`)
    pub const ZLIB: u32 = 0x0001;
    /// `SRVCAP_IP_IN_LOGIN` (`CAPABLE_IP_IN_LOGIN_FRAME`)
    pub const IP_IN_LOGIN: u32 = 0x0002;
    /// `SRVCAP_AUXPORT` (`CAPABLE_AUXPORT`)
    pub const AUXPORT: u32 = 0x0004;
    /// `SRVCAP_NEWTAGS` (`CAPABLE_NEWTAGS`)
    pub const NEWTAGS: u32 = 0x0008;
    /// `SRVCAP_UNICODE` (`CAPABLE_UNICODE`)
    pub const UNICODE: u32 = 0x0010;
    /// `SRVCAP_LARGEFILES` (`CAPABLE_LARGEFILES`)
    pub const LARGEFILES: u32 = 0x0100;
    /// `SRVCAP_SUPPORTCRYPT`
    pub const SUPPORTCRYPT: u32 = 0x0200;
    /// `SRVCAP_REQUESTCRYPT`
    pub const REQUESTCRYPT: u32 = 0x0400;
    /// `SRVCAP_REQUIRECRYPT`
    pub const REQUIRECRYPT: u32 = 0x0800;
    /// `SRVCAP_NATTRAVERSAL`: opt in to Lugdunum's NAT callback (odd LowIDs,
    /// forwarded callbacks). aMule sends it only with `ENABLE_NATT_SERVER_COORDINATION`.
    pub const NATTRAVERSAL: u32 = 0x1000;
    /// `SRVCAP_HOLEPUNCH_EXTENSION`: always sent together with [`NATTRAVERSAL`].
    pub const HOLEPUNCH_EXTENSION: u32 = 0x10_0000;
}

/// Values of [`ClientTag::ServerUdpSearchFlags`] (`enum ServerUDPCapabilities`).
pub mod server_udp_caps {
    /// `SRVCAP_UDP_NEWTAGS_LARGEFILES`
    pub const NEWTAGS_LARGEFILES: u32 = 0x01;
}

// ----------------------------------------------------------- ServerTags.h ---

wire_enum! {
    /// `server.met` and server status tag ids (`enum Server_tags`).
    pub enum ServerTag: u8 {
        /// `ST_SERVERNAME`: string
        ServerName = 0x01,
        /// `ST_DESCRIPTION`: string
        Description = 0x0B,
        /// `ST_PING`: uint32
        Ping = 0x0C,
        /// `ST_FAIL`: uint32
        Fail = 0x0D,
        /// `ST_PREFERENCE`: uint32
        Preference = 0x0E,
        /// `ST_DYNIP`
        DynIp = 0x85,
        /// `ST_LASTPING_DEPRECATED`: uint32, use [`ServerTag::LastPing`]
        LastPingDeprecated = 0x86,
        /// `ST_MAXUSERS`
        MaxUsers = 0x87,
        /// `ST_SOFTFILES`
        SoftFiles = 0x88,
        /// `ST_HARDFILES`
        HardFiles = 0x89,
        /// `ST_LASTPING`: uint32
        LastPing = 0x90,
        /// `ST_VERSION`: string
        Version = 0x91,
        /// `ST_UDPFLAGS`: uint32
        UdpFlags = 0x92,
        /// `ST_AUXPORTSLIST`: string
        AuxPortsList = 0x93,
        /// `ST_LOWIDUSERS`: uint32
        LowIdUsers = 0x94,
        /// `ST_UDPKEY`: uint32
        UdpKey = 0x95,
        /// `ST_UDPKEYIP`: uint32
        UdpKeyIp = 0x96,
        /// `ST_TCPPORTOBFUSCATION`: uint16
        TcpPortObfuscation = 0x97,
        /// `ST_UDPPORTOBFUSCATION`: uint16
        UdpPortObfuscation = 0x98,
        /// `ST_NATT_PROOF`: uint32; 1 means ed2k-server takes a proof 0x9F instead of the token
        NattProof = 0xA9,
        /// `ST_IPV6_STATUS`: uint8 bit field, held | reachable | probed
        Ipv6Status = 0xAB,
        /// `ST_NATT_TOKEN`: hash16, ed2k-server NAT-T session token
        NattToken = 0xAC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_types_round_trip_including_short_strings() {
        for v in 0u8..=0xFF {
            if let Ok(t) = TagType::try_from(v) {
                assert_eq!(u8::from(t), v);
            }
        }
        assert_eq!(TagType::try_from(0x11), Ok(TagType::Str(1)));
        assert_eq!(TagType::try_from(0x20), Ok(TagType::Str(16)));
        assert_eq!(TagType::short_str(16), Some(TagType::Str(16)));
        assert_eq!(TagType::short_str(0), None);
        assert_eq!(TagType::short_str(17), None);
    }

    #[test]
    fn str17_to_str22_are_refused_like_ctag_does() {
        for v in 0x21..=0x26 {
            assert!(TagType::try_from(v).is_err(), "{v:#x}");
        }
        assert!(TagType::try_from(0x00).is_err());
        assert!(TagType::try_from(0x0C).is_err());
    }

    #[test]
    fn spot_values() {
        assert_eq!(u8::from(FileTag::FilesizeHi), 0x3A);
        assert_eq!(FileTag::try_from(0xF7), Ok(FileTag::FileRating));
        assert_eq!(u8::from(ClientTag::EmuleMiscOptions2), 0xFE);
        assert_eq!(MuleInfoTag::try_from(0x94), Ok(MuleInfoTag::OsInfo));
        assert_eq!(ServerTag::try_from(0xAC), Ok(ServerTag::NattToken));
        assert!(ServerTag::try_from(0x02).is_err(), "0x02-0x0A are unused");
        // Kad names that mirror the eD2k file tag ids.
        assert_eq!(kad::FILESIZE_HI, [u8::from(FileTag::FilesizeHi)]);
        assert_eq!(kad::AICHHASH, [u8::from(FileTag::AichHash)]);
        assert_eq!(kad::SOURCES, kad::AVAILABILITY);
    }

    #[test]
    fn file_types() {
        for t in FileType::ALL {
            assert_eq!(t.as_str().parse::<FileType>(), Ok(t));
        }
        assert_eq!(FileType::Document.to_string(), "Doc");
        assert_eq!(
            "audio".parse::<FileType>(),
            Err(UnknownFileType("audio".into()))
        );
    }
}

#[cfg(test)]
mod file_type_tests {
    use super::FileType;

    #[test]
    fn file_types_by_name() {
        for (name, t) in [
            ("song.MP3", Some(FileType::Audio)),
            ("film.mkv", Some(FileType::Video)),
            ("disc.iso", Some(FileType::CdImage)),
            ("src.tar.gz", Some(FileType::Archive)),
            ("book.epub", Some(FileType::Document)),
            ("setup.exe", Some(FileType::Program)),
            ("photo.jpeg", Some(FileType::Image)),
            ("README", None),
            ("data.unknownext", None),
        ] {
            assert_eq!(FileType::of_name(name), t, "{name}");
        }
        assert_eq!(FileType::Archive.published(), FileType::Program);
        assert_eq!(FileType::CdImage.published(), FileType::Program);
        assert_eq!(FileType::Video.published(), FileType::Video);
        assert_eq!(FileType::Document.id(), 5);
    }
}
