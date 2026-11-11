// SPDX-License-Identifier: GPL-2.0-or-later
//! Tags: named, typed values in packets and `.met` files. Port of
//! `Tag.{h,cpp}` (`CTag`) and the tag functions of `SafeFile.cpp`.
//!
//! aMule has two codecs for the same structure:
//!
//! * **eD2k** ([`Tag::read_ed2k`], [`Tag::write_ed2k`]: `CTag(CFileDataIO&)`
//!   and `WriteNewEd2kTag`), used by eD2k packets and `.met` files. A type
//!   byte with bit 0x80 set is followed by a one-byte name id; otherwise a
//!   `u16` name length follows, and a length of 1 also means a name id. The
//!   writer picks the smallest integer type and writes strings of 1..=16
//!   bytes as the short-string types `TAGTYPE_STR1..16`. The reader
//!   normalises `uint8`/`uint16` to `uint32` unless told not to.
//! * **Kad** ([`Tag::read_kad`], [`Tag::write_kad`]: `ReadTag` and
//!   `WriteTag`). The name is always a `u16`-length string, integers keep
//!   their exact width, strings are always written as UTF-8, and BSOBs are
//!   allowed. Tag lists have a `u8` count ([`read_kad_list`]).
//!
//! Unlike the C++, writing a tag that cannot be written (a skipped BOOL, a
//! BSOB on eD2k, a BSOB over 255 bytes, more than 255 tags in a list) is an
//! error before any byte is written; aMule writes a partial, corrupt tag.

use std::fmt;

use ed2k_types::tags::TagType;
use ed2k_types::Md4Hash;

use crate::io::{self, encoded_len, LenField, Reader, StrEncoding, Writer};

/// A tag's name: a one-byte id, or a byte string (Kad, and some eD2k
/// metadata such as "Artist"). Names are kept as raw bytes, exactly as on
/// the wire.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TagName {
    Id(u8),
    Str(Vec<u8>),
}

impl TagName {
    /// The name as it is compared: an id is the one-byte string of itself,
    /// which is also how both codecs write it.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            TagName::Id(id) => std::slice::from_ref(id),
            TagName::Str(s) => s,
        }
    }

    /// True if this is the name `name`, in either form (Kad names like
    /// `ed2k_types::tags::kad::FILENAME` are one-byte strings).
    pub fn is(&self, name: &[u8]) -> bool {
        self.as_bytes() == name
    }

    /// True if this is the one-byte name `id`, in either form.
    pub fn is_id(&self, id: u8) -> bool {
        self.as_bytes() == [id]
    }
}

impl From<u8> for TagName {
    fn from(id: u8) -> Self {
        TagName::Id(id)
    }
}

impl From<&[u8]> for TagName {
    fn from(s: &[u8]) -> Self {
        TagName::Str(s.to_vec())
    }
}

impl From<&str> for TagName {
    fn from(s: &str) -> Self {
        TagName::Str(s.as_bytes().to_vec())
    }
}

/// A tag's value. Integers keep the width they were read or built with,
/// because Kad writes them back with exactly that type.
#[derive(Clone, Debug, PartialEq)]
pub enum TagValue {
    Hash(Md4Hash),
    String(String),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Float(f32),
    /// A `TAGTYPE_BOOL` tag. Its byte is read and dropped, as in aMule, so it
    /// cannot be written again.
    Bool,
    /// A `TAGTYPE_BOOLARRAY` tag, payload skipped like [`TagValue::Bool`].
    BoolArray,
    Blob(Vec<u8>),
    /// A byte string of at most 255 bytes (Kad only).
    Bsob(Vec<u8>),
}

impl TagValue {
    /// The smallest integer type that holds `v` (`CTagVarInt`).
    pub fn int(v: u64) -> TagValue {
        if let Ok(v) = u8::try_from(v) {
            TagValue::U8(v)
        } else if let Ok(v) = u16::try_from(v) {
            TagValue::U16(v)
        } else if let Ok(v) = u32::try_from(v) {
            TagValue::U32(v)
        } else {
            TagValue::U64(v)
        }
    }

    /// The wire type this value is stored as (`GetType`).
    pub fn tag_type(&self) -> TagType {
        match self {
            TagValue::Hash(_) => TagType::Hash16,
            TagValue::String(_) => TagType::String,
            TagValue::U8(_) => TagType::Uint8,
            TagValue::U16(_) => TagType::Uint16,
            TagValue::U32(_) => TagType::Uint32,
            TagValue::U64(_) => TagType::Uint64,
            TagValue::Float(_) => TagType::Float32,
            TagValue::Bool => TagType::Bool,
            TagValue::BoolArray => TagType::BoolArray,
            TagValue::Blob(_) => TagType::Blob,
            TagValue::Bsob(_) => TagType::Bsob,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TagError {
    Io(io::Error),
    /// A type this codec cannot read; the tag's length is unknown, so
    /// reading has to stop (`CInvalidPacket`).
    UnknownType {
        codec: &'static str,
        ty: u8,
    },
    /// A blob longer than the data left.
    BlobTooLarge {
        len: u32,
        available: usize,
    },
    /// A value this codec cannot write.
    NotWritable {
        codec: &'static str,
        ty: TagType,
    },
    /// A BSOB over 255 bytes, a name over 65535 bytes, or a list of more
    /// than 255 tags.
    TooLong(&'static str),
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagError::Io(e) => e.fmt(f),
            TagError::UnknownType { codec, ty } => write!(f, "unknown {codec} tag type {ty:#04x}"),
            TagError::BlobTooLarge { len, available } => {
                write!(f, "malformed tag: blob of {len} bytes, {available} left")
            }
            TagError::NotWritable { codec, ty } => {
                write!(f, "cannot write a {ty:?} tag as {codec}")
            }
            TagError::TooLong(what) => write!(f, "{what} too long"),
        }
    }
}

impl std::error::Error for TagError {}

impl From<io::Error> for TagError {
    fn from(e: io::Error) -> Self {
        TagError::Io(e)
    }
}

/// A named, typed value (`CTag`).
#[derive(Clone, Debug, PartialEq)]
pub struct Tag {
    pub name: TagName,
    pub value: TagValue,
}

const ID_FLAG: u8 = 0x80;

impl Tag {
    pub fn new(name: impl Into<TagName>, value: TagValue) -> Self {
        Tag {
            name: name.into(),
            value,
        }
    }

    /// An integer tag of the smallest type that holds `v` (`CTagVarInt`).
    pub fn int(name: impl Into<TagName>, v: u64) -> Self {
        Tag::new(name, TagValue::int(v))
    }

    pub fn string(name: impl Into<TagName>, s: impl Into<String>) -> Self {
        Tag::new(name, TagValue::String(s.into()))
    }

    /// `GetInt`: any integer width.
    pub fn as_int(&self) -> Option<u64> {
        match self.value {
            TagValue::U8(v) => Some(v.into()),
            TagValue::U16(v) => Some(v.into()),
            TagValue::U32(v) => Some(v.into()),
            TagValue::U64(v) => Some(v),
            _ => None,
        }
    }

    /// `GetStr`
    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            TagValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// `GetFloat`
    pub fn as_float(&self) -> Option<f32> {
        match self.value {
            TagValue::Float(v) => Some(v),
            _ => None,
        }
    }

    /// `GetHash`
    pub fn as_hash(&self) -> Option<Md4Hash> {
        match self.value {
            TagValue::Hash(h) => Some(h),
            _ => None,
        }
    }

    /// `GetBlob` / `GetBsob`
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.value {
            TagValue::Blob(b) | TagValue::Bsob(b) => Some(b),
            _ => None,
        }
    }

    /// `CanWriteToFile`: what a `.met` writer may write, and what its tag
    /// count must count.
    pub fn can_write_to_file(&self) -> bool {
        self.as_int().is_some()
            || matches!(
                self.value,
                TagValue::String(_) | TagValue::Float(_) | TagValue::Blob(_)
            )
    }

    /// `CTag(const CFileDataIO&, bOptUTF8, normalizeIntTypes)`.
    ///
    /// With `normalize_ints` (aMule's default), `uint8` and `uint16` values
    /// are stored as `uint32`; short strings are always stored as strings.
    pub fn read_ed2k(
        r: &mut Reader<'_>,
        opt_utf8: bool,
        normalize_ints: bool,
    ) -> Result<Tag, TagError> {
        let mut ty = r.u8()?;
        let name = if ty & ID_FLAG != 0 {
            ty &= !ID_FLAG;
            TagName::Id(r.u8()?)
        } else {
            match r.u16()? {
                1 => TagName::Id(r.u8()?),
                n => TagName::Str(r.bytes(usize::from(n))?.to_vec()),
            }
        };
        let unknown = TagError::UnknownType { codec: "eD2k", ty };
        // Every tag must be read in full, even unused ones: tags come in lists.
        let value = match TagType::try_from(ty).map_err(|_| unknown)? {
            TagType::String => TagValue::String(r.string(opt_utf8, LenField::U16, false)?),
            TagType::Uint32 => TagValue::U32(r.u32()?),
            TagType::Uint64 => TagValue::U64(r.u64()?),
            TagType::Uint16 => {
                let v = r.u16()?;
                if normalize_ints {
                    TagValue::U32(v.into())
                } else {
                    TagValue::U16(v)
                }
            }
            TagType::Uint8 => {
                let v = r.u8()?;
                if normalize_ints {
                    TagValue::U32(v.into())
                } else {
                    TagValue::U8(v)
                }
            }
            TagType::Float32 => TagValue::Float(r.f32()?),
            TagType::Hash16 => TagValue::Hash(r.hash()?),
            TagType::Bool => {
                r.u8()?;
                TagValue::Bool
            }
            TagType::BoolArray => {
                // eMule before 0.42e.29 used (len + 7) / 8; aMule keeps
                // len / 8 + 1, one byte more for a multiple of 8.
                let bits = r.u16()?;
                r.bytes(usize::from(bits / 8) + 1)?;
                TagValue::BoolArray
            }
            TagType::Blob => {
                let len = r.u32()?;
                if len as usize > r.remaining() {
                    return Err(TagError::BlobTooLarge {
                        len,
                        available: r.remaining(),
                    });
                }
                TagValue::Blob(r.bytes(len as usize)?.to_vec())
            }
            TagType::Str(n) => TagValue::String(r.string_of_len(opt_utf8, n.into())?),
            TagType::Bsob => return Err(TagError::UnknownType { codec: "eD2k", ty }),
        };
        Ok(Tag { name, value })
    }

    /// `WriteNewEd2kTag`: integers in their smallest type, strings of 1..=16
    /// bytes (in `enc`) as short strings.
    pub fn write_ed2k(&self, w: &mut Writer, enc: StrEncoding) -> Result<(), TagError> {
        let ty = match &self.value {
            // Sized by value, not by the declared width.
            TagValue::U8(_) | TagValue::U16(_) | TagValue::U32(_) | TagValue::U64(_) => {
                TagValue::int(self.as_int().unwrap_or_default()).tag_type()
            }
            TagValue::String(s) => {
                TagType::short_str(encoded_len(s, enc)).unwrap_or(TagType::String)
            }
            TagValue::Bool | TagValue::BoolArray | TagValue::Bsob(_) => {
                return Err(TagError::NotWritable {
                    codec: "eD2k",
                    ty: self.value.tag_type(),
                })
            }
            v => v.tag_type(),
        };
        let ty_byte = u8::from(ty);
        match &self.name {
            TagName::Str(n) if !n.is_empty() => {
                let len = u16::try_from(n.len()).map_err(|_| TagError::TooLong("tag name"))?;
                w.u8(ty_byte).u16(len).bytes(n);
            }
            // An empty string name has no id; aMule writes id 0.
            TagName::Str(_) => {
                w.u8(ty_byte | ID_FLAG).u8(0);
            }
            TagName::Id(id) => {
                w.u8(ty_byte | ID_FLAG).u8(*id);
            }
        }
        match (&self.value, ty) {
            (TagValue::String(s), TagType::Str(_)) => {
                w.string(s, enc, LenField::None);
            }
            (TagValue::String(s), _) => {
                w.string(s, enc, LenField::U16);
            }
            (TagValue::Float(v), _) => {
                w.f32(*v);
            }
            (TagValue::Hash(h), _) => {
                w.hash(*h);
            }
            (TagValue::Blob(b), _) => {
                let len = u32::try_from(b.len()).map_err(|_| TagError::TooLong("blob"))?;
                w.u32(len).bytes(b);
            }
            (_, TagType::Uint8) => {
                w.u8(self.as_int().unwrap_or_default() as u8);
            }
            (_, TagType::Uint16) => {
                w.u16(self.as_int().unwrap_or_default() as u16);
            }
            (_, TagType::Uint32) => {
                w.u32(self.as_int().unwrap_or_default() as u32);
            }
            _ => {
                w.u64(self.as_int().unwrap_or_default());
            }
        }
        Ok(())
    }

    /// `CFileDataIO::ReadTag`: a Kad tag.
    pub fn read_kad(r: &mut Reader<'_>, opt_utf8: bool) -> Result<Tag, TagError> {
        let ty = r.u8()?;
        let n = r.u16()?;
        let name = TagName::Str(r.bytes(usize::from(n))?.to_vec());
        let value = match TagType::try_from(ty) {
            Ok(TagType::Hash16) => TagValue::Hash(r.hash()?),
            Ok(TagType::String) => TagValue::String(r.string(opt_utf8, LenField::U16, false)?),
            Ok(TagType::Uint64) => TagValue::U64(r.u64()?),
            Ok(TagType::Uint32) => TagValue::U32(r.u32()?),
            Ok(TagType::Uint16) => TagValue::U16(r.u16()?),
            Ok(TagType::Uint8) => TagValue::U8(r.u8()?),
            Ok(TagType::Float32) => TagValue::Float(r.f32()?),
            Ok(TagType::Bsob) => TagValue::Bsob(r.bsob()?.to_vec()),
            _ => return Err(TagError::UnknownType { codec: "Kad", ty }),
        };
        Ok(Tag { name, value })
    }

    /// `CFileDataIO::WriteTag`: a Kad tag (also aMule's `.met` writer,
    /// `WriteTagToFile`). Strings are always written as UTF-8.
    pub fn write_kad(&self, w: &mut Writer) -> Result<(), TagError> {
        let ty = self.value.tag_type();
        if matches!(self.value, TagValue::Bool | TagValue::BoolArray) {
            return Err(TagError::NotWritable { codec: "Kad", ty });
        }
        if let TagValue::Bsob(b) = &self.value {
            if b.len() > 255 {
                return Err(TagError::TooLong("bsob"));
            }
        }
        if let TagValue::Blob(b) = &self.value {
            u32::try_from(b.len()).map_err(|_| TagError::TooLong("blob"))?;
        }
        let name = match &self.name {
            TagName::Str(n) if !n.is_empty() => n.as_slice(),
            TagName::Str(_) => &[0],
            TagName::Id(id) => std::slice::from_ref(id),
        };
        let len = u16::try_from(name.len()).map_err(|_| TagError::TooLong("tag name"))?;
        w.u8(ty.into()).u16(len).bytes(name);
        match &self.value {
            TagValue::Hash(h) => {
                w.hash(*h);
            }
            TagValue::String(s) => {
                w.string(s, StrEncoding::Utf8, LenField::U16);
            }
            TagValue::U64(v) => {
                w.u64(*v);
            }
            TagValue::U32(v) => {
                w.u32(*v);
            }
            TagValue::U16(v) => {
                w.u16(*v);
            }
            TagValue::U8(v) => {
                w.u8(*v);
            }
            TagValue::Float(v) => {
                w.f32(*v);
            }
            TagValue::Bsob(b) => {
                w.bsob(b);
            }
            TagValue::Blob(b) => {
                w.u32(b.len() as u32).bytes(b);
            }
            TagValue::Bool | TagValue::BoolArray => unreachable!("rejected above"),
        }
        Ok(())
    }
}

/// `ReadTagPtrList`: a `u8` count, then Kad tags.
pub fn read_kad_list(r: &mut Reader<'_>, opt_utf8: bool) -> Result<Vec<Tag>, TagError> {
    let n = r.u8()?;
    (0..n).map(|_| Tag::read_kad(r, opt_utf8)).collect()
}

/// `WriteTagPtrList`. Nothing is written if the list cannot be.
pub fn write_kad_list(w: &mut Writer, tags: &[Tag]) -> Result<(), TagError> {
    let n = u8::try_from(tags.len()).map_err(|_| TagError::TooLong("tag list"))?;
    let mut tmp = Writer::new();
    tmp.u8(n);
    for t in tags {
        t.write_kad(&mut tmp)?;
    }
    w.bytes(tmp.as_bytes());
    Ok(())
}

/// `GetFullInfo`, for logs: `0x01="name"`, `"Artist"=(Int32)5`, ...
impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            TagName::Id(id) => write!(f, "0x{id:02X}")?,
            TagName::Str(s) if s.len() == 1 => write!(f, "0x{:02X}", s[0])?,
            TagName::Str(s) => write!(
                f,
                "\"{}\"",
                s.iter().map(|&c| char::from(c)).collect::<String>()
            )?,
        }
        f.write_str("=")?;
        match &self.value {
            TagValue::String(s) => write!(f, "\"{s}\""),
            TagValue::U64(v) => write!(f, "(Int64){v}"),
            TagValue::U32(v) => write!(f, "(Int32){v}"),
            TagValue::U16(v) => write!(f, "(Int16){v}"),
            TagValue::U8(v) => write!(f, "(Int8){v}"),
            TagValue::Float(v) => write!(f, "(Float32){v:.6}"),
            TagValue::Blob(b) => write!(f, "(Blob){}", b.len()),
            TagValue::Bsob(b) => write!(f, "(Bsob){}", b.len()),
            TagValue::Hash(h) => write!(f, "(Hash){h}"),
            v => write!(f, "Type={}", u8::from(v.tag_type())),
        }
    }
}

#[cfg(test)]
mod tests;
