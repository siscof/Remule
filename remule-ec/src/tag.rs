// SPDX-License-Identifier: GPL-2.0-or-later
//! EC packets and tags, and their wire encoding.
//!
//! Port of `libs/ec/cpp/ECTag.cpp` and `ECPacket.cpp`. The encoding is
//! described in `docs/EC_Protocol.md` §1.2. Two details matter:
//!
//! * With `EC_FLAG_UTF8_NUMBERS` the structural numbers (opcode, tag name,
//!   type, length, child count) are written like UTF-8 code points, but
//!   `TAGLEN` still counts every header as if it had its fixed width.
//! * A tag's own data comes *after* its children, and its length is what is
//!   left of `TAGLEN` once the children have been parsed.

use crate::codes::*;
use crate::Error;

/// Deepest nesting a received packet may use (`MAX_READ_DEPTH` in ECTag.cpp).
const MAX_READ_DEPTH: usize = 64;

/// Wire options for one packet, from its `FLAGS` header field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireOpts {
    pub utf8_numbers: bool,
    pub large_tag_count: bool,
}

impl WireOpts {
    pub fn from_flags(flags: u32) -> Self {
        WireOpts {
            utf8_numbers: flags & EC_FLAG_UTF8_NUMBERS != 0,
            large_tag_count: flags & EC_FLAG_LARGE_TAG_COUNT != 0,
        }
    }
}

/// One EC tag. Kept close to the wire: a type byte and the raw data bytes,
/// with typed constructors and accessors on top.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub name: u16,
    pub ty: u8,
    pub data: Vec<u8>,
    pub children: Vec<Tag>,
}

impl Tag {
    /// A tag with no data (`CECEmptyTag`). Its presence is the information.
    pub fn empty(name: u16) -> Self {
        Self::custom(name, Vec::new())
    }

    /// Raw bytes (`EC_TAGTYPE_CUSTOM`).
    pub fn custom(name: u16, data: Vec<u8>) -> Self {
        Tag {
            name,
            ty: EC_TAGTYPE_CUSTOM,
            data,
            children: Vec::new(),
        }
    }

    /// An unsigned integer in the smallest type that holds it, as
    /// `CECTag::InitInt` does.
    pub fn int(name: u16, v: u64) -> Self {
        let (ty, data) = if v <= 0xFF {
            (EC_TAGTYPE_UINT8, vec![v as u8])
        } else if v <= 0xFFFF {
            (EC_TAGTYPE_UINT16, (v as u16).to_be_bytes().to_vec())
        } else if v <= 0xFFFF_FFFF {
            (EC_TAGTYPE_UINT32, (v as u32).to_be_bytes().to_vec())
        } else {
            (EC_TAGTYPE_UINT64, v.to_be_bytes().to_vec())
        };
        Tag {
            name,
            ty,
            data,
            children: Vec::new(),
        }
    }

    /// A UTF-8 string with its trailing NUL.
    pub fn string(name: u16, s: &str) -> Self {
        // A NUL inside the string would end it early on the C++ side.
        let mut data: Vec<u8> = s.bytes().take_while(|&b| b != 0).collect();
        data.push(0);
        Tag {
            name,
            ty: EC_TAGTYPE_STRING,
            data,
            children: Vec::new(),
        }
    }

    /// A 16-byte MD4 hash, network order.
    pub fn hash(name: u16, h: [u8; 16]) -> Self {
        Tag {
            name,
            ty: EC_TAGTYPE_HASH16,
            data: h.to_vec(),
            children: Vec::new(),
        }
    }

    /// An IPv4 endpoint: 4 address bytes as stored, port big-endian.
    pub fn ipv4(name: u16, ip: [u8; 4], port: u16) -> Self {
        let mut data = ip.to_vec();
        data.extend_from_slice(&port.to_be_bytes());
        Tag {
            name,
            ty: EC_TAGTYPE_IPV4,
            data,
            children: Vec::new(),
        }
    }

    /// Builder: append a child.
    pub fn with(mut self, child: Tag) -> Self {
        self.children.push(child);
        self
    }

    // --- accessors (lenient, like the C++ ones: wrong type reads as empty) ---

    pub fn is_int(&self) -> bool {
        matches!(
            self.ty,
            EC_TAGTYPE_UINT8 | EC_TAGTYPE_UINT16 | EC_TAGTYPE_UINT32 | EC_TAGTYPE_UINT64
        )
    }

    /// Any unsigned integer type, widened. 0 for an empty or non-integer tag.
    pub fn as_int(&self) -> u64 {
        if !self.is_int() || self.data.is_empty() {
            return 0;
        }
        self.data
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    }

    /// String data without the trailing NUL; empty for other types.
    pub fn as_str(&self) -> String {
        if self.ty != EC_TAGTYPE_STRING {
            return String::new();
        }
        let end = self
            .data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len());
        String::from_utf8_lossy(&self.data[..end]).into_owned()
    }

    /// Doubles travel as decimal strings (`EC_TAGTYPE_DOUBLE`).
    pub fn as_double(&self) -> f64 {
        if self.ty != EC_TAGTYPE_DOUBLE {
            return 0.0;
        }
        let end = self
            .data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len());
        std::str::from_utf8(&self.data[..end])
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0.0)
    }

    pub fn as_hash(&self) -> Option<[u8; 16]> {
        if self.ty == EC_TAGTYPE_HASH16 {
            self.data.as_slice().try_into().ok()
        } else {
            None
        }
    }

    pub fn as_ipv4(&self) -> Option<([u8; 4], u16)> {
        if self.ty == EC_TAGTYPE_IPV4 && self.data.len() == 6 {
            let ip = [self.data[0], self.data[1], self.data[2], self.data[3]];
            Some((ip, u16::from_be_bytes([self.data[4], self.data[5]])))
        } else {
            None
        }
    }

    /// First child with this name.
    pub fn child(&self, name: u16) -> Option<&Tag> {
        self.children.iter().find(|t| t.name == name)
    }

    pub fn child_int(&self, name: u16) -> u64 {
        self.child(name).map_or(0, Tag::as_int)
    }

    pub fn child_str(&self, name: u16) -> String {
        self.child(name).map(Tag::as_str).unwrap_or_default()
    }

    pub fn child_double(&self, name: u16) -> f64 {
        self.child(name).map_or(0.0, Tag::as_double)
    }

    pub fn has(&self, name: u16) -> bool {
        self.child(name).is_some()
    }

    /// `TAGLEN` for this tag: own data plus each child's full logical size
    /// (`CECTag::GetTagLen`).
    fn tag_len(&self, large: bool) -> u64 {
        let take = if large {
            self.children.len()
        } else {
            self.children.len().min(0xFFFE)
        };
        let mut len = self.data.len() as u64;
        for c in &self.children[..take] {
            len += c.tag_len(large) + 7;
            if !c.children.is_empty() {
                len += 2;
                if large && c.children.len() >= 0xFFFF {
                    len += 4;
                }
            }
        }
        len
    }
}

/// An EC packet: an opcode and its top-level tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub opcode: u8,
    pub tags: Vec<Tag>,
}

impl Packet {
    pub fn new(opcode: u8) -> Self {
        Packet {
            opcode,
            tags: Vec::new(),
        }
    }

    pub fn with(mut self, tag: Tag) -> Self {
        self.tags.push(tag);
        self
    }

    /// A request carrying `EC_TAG_DETAIL_LEVEL`.
    pub fn with_detail(self, level: u8) -> Self {
        self.with(Tag::int(EC_TAG_DETAIL_LEVEL, u64::from(level)))
    }

    pub fn tag(&self, name: u16) -> Option<&Tag> {
        self.tags.iter().find(|t| t.name == name)
    }

    pub fn tags_named(&self, name: u16) -> impl Iterator<Item = &Tag> {
        self.tags.iter().filter(move |t| t.name == name)
    }

    /// `EC_TAG_STRING`, the human-readable message most replies carry.
    pub fn message(&self) -> Option<String> {
        self.tag(EC_TAG_STRING).map(Tag::as_str)
    }

    /// Serialise the packet body (opcode, count, tags). No framing.
    pub fn encode(&self, opts: WireOpts) -> Vec<u8> {
        let mut w = Writer {
            out: Vec::new(),
            opts,
        };
        w.number(u32::from(self.opcode), 1);
        w.children(&self.tags);
        w.out
    }

    /// Parse a packet body. Trailing bytes are an error: they mean the two
    /// ends disagree about the format.
    pub fn decode(buf: &[u8], opts: WireOpts) -> Result<Self, Error> {
        let mut r = Reader { buf, pos: 0, opts };
        let opcode = r.number(1)? as u8;
        let tags = r.children(0)?;
        if r.pos != buf.len() {
            return Err(Error::Protocol(format!(
                "{} trailing bytes after packet",
                buf.len() - r.pos
            )));
        }
        Ok(Packet { opcode, tags })
    }
}

struct Writer {
    out: Vec<u8>,
    opts: WireOpts,
}

impl Writer {
    /// One structural number of `width` bytes (`CECSocket::WriteNumber`).
    fn number(&mut self, v: u32, width: usize) {
        if self.opts.utf8_numbers {
            utf8_encode(v, &mut self.out);
        } else {
            self.out.extend_from_slice(&v.to_be_bytes()[4 - width..]);
        }
    }

    fn children(&mut self, tags: &[Tag]) {
        let large = self.opts.large_tag_count;
        let count = if large {
            tags.len()
        } else {
            tags.len().min(0xFFFE)
        };
        if large && count >= 0xFFFF {
            self.number(0xFFFF, 2);
            self.number(count as u32, 4);
        } else {
            self.number(count as u32, 2);
        }
        for t in &tags[..count] {
            self.tag(t);
        }
    }

    fn tag(&mut self, t: &Tag) {
        let has_children = !t.children.is_empty();
        self.number((u32::from(t.name) << 1) | u32::from(has_children), 2);
        self.number(u32::from(t.ty), 1);
        self.number(t.tag_len(self.opts.large_tag_count) as u32, 4);
        if has_children {
            self.children(&t.children);
        }
        self.out.extend_from_slice(&t.data);
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    opts: WireOpts,
}

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Result<&[u8], Error> {
        if self.buf.len() - self.pos < n {
            return Err(Error::Protocol("packet truncated".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// `CECSocket::ReadNumber`: a UTF-8 style number truncated to `width`,
    /// or `width` big-endian bytes.
    fn number(&mut self, width: usize) -> Result<u32, Error> {
        if self.opts.utf8_numbers {
            let (v, used) = utf8_decode(&self.buf[self.pos..])?;
            self.pos += used;
            Ok(match width {
                1 => v & 0xFF,
                2 => v & 0xFFFF,
                _ => v,
            })
        } else {
            let b = self.bytes(width)?;
            Ok(b.iter().fold(0u32, |acc, &x| (acc << 8) | u32::from(x)))
        }
    }

    fn children(&mut self, depth: usize) -> Result<Vec<Tag>, Error> {
        if depth >= MAX_READ_DEPTH {
            return Err(Error::Protocol("tags nested too deeply".into()));
        }
        let mut count = self.number(2)?;
        if self.opts.large_tag_count && count == 0xFFFF {
            count = self.number(4)?;
        }
        // Each tag takes at least 3 bytes even compressed, so a count the
        // remaining bytes cannot hold is a lie; don't pre-allocate for it.
        let cap = (count as usize).min((self.buf.len() - self.pos) / 3);
        let mut tags = Vec::with_capacity(cap);
        for _ in 0..count {
            tags.push(self.tag(depth)?);
        }
        Ok(tags)
    }

    fn tag(&mut self, depth: usize) -> Result<Tag, Error> {
        let raw_name = self.number(2)?;
        let ty = self.number(1)? as u8;
        let len = u64::from(self.number(4)?);
        let mut tag = Tag {
            name: (raw_name >> 1) as u16,
            ty,
            data: Vec::new(),
            children: Vec::new(),
        };
        if raw_name & 1 != 0 {
            tag.children = self.children(depth + 1)?;
        }
        let children_len = tag.tag_len(self.opts.large_tag_count); // data is still empty
        let data_len = len
            .checked_sub(children_len)
            .ok_or_else(|| Error::Protocol("tag length smaller than its children".into()))?;
        let data_len =
            usize::try_from(data_len).map_err(|_| Error::Protocol("tag too large".into()))?;
        if data_len > 0 {
            if !data_len_fits_type(ty, data_len) {
                return Err(Error::Protocol(format!(
                    "tag 0x{:04x}: {data_len} bytes for type {ty}",
                    tag.name
                )));
            }
            tag.data = self.bytes(data_len)?.to_vec();
        }
        Ok(tag)
    }
}

fn data_len_fits_type(ty: u8, len: usize) -> bool {
    match ty {
        EC_TAGTYPE_UINT8 => len == 1,
        EC_TAGTYPE_UINT16 => len == 2,
        EC_TAGTYPE_UINT32 => len == 4,
        EC_TAGTYPE_UINT64 => len == 8,
        EC_TAGTYPE_IPV4 => len == 6,
        EC_TAGTYPE_HASH16 | EC_TAGTYPE_UINT128 => len == 16,
        _ => true,
    }
}

/// The 1..6-byte UTF-8 style encoding of `utf8_wctomb` in ECSocket.cpp.
fn utf8_encode(v: u32, out: &mut Vec<u8>) {
    const LIMITS: [(u32, u8); 6] = [
        (0x7F, 0x00),
        (0x7FF, 0xC0),
        (0xFFFF, 0xE0),
        (0x1F_FFFF, 0xF0),
        (0x3FF_FFFF, 0xF8),
        (0x7FFF_FFFF, 0xFC),
    ];
    // Values above 0x7FFFFFFF cannot be expressed; the C++ fails the write.
    // Nothing structural gets that big (packets are capped at 256 MB).
    let v = v.min(0x7FFF_FFFF);
    for (n, &(limit, lead)) in LIMITS.iter().enumerate() {
        if v <= limit {
            let shift = 6 * n as u32;
            out.push(lead | (v >> shift) as u8);
            for i in (0..n as u32).rev() {
                out.push(0x80 | ((v >> (6 * i)) & 0x3F) as u8);
            }
            return;
        }
    }
}

/// `utf8_mbtowc`: decode one number, rejecting malformed and overlong forms.
fn utf8_decode(s: &[u8]) -> Result<(u32, usize), Error> {
    const TABLE: [(u8, u8, u32, u32); 6] = [
        (0x80, 0x00, 0x7F, 0),
        (0xE0, 0xC0, 0x7FF, 0x80),
        (0xF0, 0xE0, 0xFFFF, 0x800),
        (0xF8, 0xF0, 0x1F_FFFF, 0x1_0000),
        (0xFC, 0xF8, 0x3FF_FFFF, 0x20_0000),
        (0xFE, 0xFC, 0x7FFF_FFFF, 0x400_0000),
    ];
    let bad = || Error::Protocol("invalid compressed number".into());
    let c0 = *s
        .first()
        .ok_or_else(|| Error::Protocol("packet truncated".into()))?;
    let mut l = u32::from(c0);
    for (i, &(cmask, cval, lmask, lval)) in TABLE.iter().enumerate() {
        if c0 & cmask == cval {
            l &= lmask;
            if l < lval {
                return Err(bad());
            }
            return Ok((l, i + 1));
        }
        let c = *s
            .get(i + 1)
            .ok_or_else(|| Error::Protocol("packet truncated".into()))?
            ^ 0x80;
        if c & 0xC0 != 0 {
            return Err(bad());
        }
        l = (l << 6) | u32::from(c);
    }
    Err(bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// EC_Protocol.md, Example 2: the plain stats request.
    #[test]
    fn stats_request_matches_doc_example_2() {
        let p = Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_CMD);
        assert_eq!(
            p.encode(WireOpts::default()),
            hex("0a 0001 0008 02 00000001 00")
        );
    }

    /// EC_Protocol.md, Example 3: the same request with compressed numbers.
    #[test]
    fn stats_request_matches_doc_example_3() {
        let p = Packet::new(EC_OP_STAT_REQ).with_detail(EC_DETAIL_CMD);
        let opts = WireOpts {
            utf8_numbers: true,
            large_tag_count: true,
        };
        assert_eq!(p.encode(opts), hex("0a 01 08 02 01 00"));
    }

    /// EC_Protocol.md, Example 2/3: CONNSTATE with one child counts the child
    /// header as 7 bytes in TAGLEN even when it is compressed to 4.
    #[test]
    fn nested_tag_len_counts_uncompressed_headers() {
        let conn = Tag::int(EC_TAG_CONNSTATE, 8).with(Tag::int(EC_TAG_CLIENT_ID, 0));
        let p = Packet::new(EC_OP_STATS).with(conn);
        let opts = WireOpts {
            utf8_numbers: true,
            large_tag_count: false,
        };
        let enc = p.encode(opts);
        assert_eq!(&enc[2..], &hex("0b 02 09 01 14 02 01 00 08")[..]);
        assert_eq!(Packet::decode(&enc, opts).unwrap(), p);

        let plain = p.encode(WireOpts::default());
        assert_eq!(
            &plain[3..],
            &hex("000b 02 00000009 0001 0014 02 00000001 00 08")[..]
        );
        assert_eq!(Packet::decode(&plain, WireOpts::default()).unwrap(), p);
    }

    #[test]
    fn utf8_numbers_round_trip_at_every_width_boundary() {
        for v in [
            0,
            0x7F,
            0x80,
            0x7FF,
            0x800,
            0xFFFF,
            0x1_0000,
            0x1F_FFFF,
            0x20_0000,
            0x3FF_FFFF,
            0x400_0000,
            0x7FFF_FFFF,
        ] {
            let mut out = Vec::new();
            utf8_encode(v, &mut out);
            assert_eq!(utf8_decode(&out).unwrap(), (v, out.len()), "value {v:#x}");
        }
        let mut out = Vec::new();
        utf8_encode(0x0200, &mut out);
        assert_eq!(out, [0xC8, 0x80], "doc: tag name 0x0200 becomes c8 80");
    }

    #[test]
    fn overlong_numbers_are_rejected() {
        assert!(utf8_decode(&[0xC0, 0x80]).is_err());
        assert!(utf8_decode(&[0xE0, 0x80, 0x80]).is_err());
        assert!(utf8_decode(&[0xC8]).is_err());
    }

    #[test]
    fn every_value_kind_round_trips() {
        let p = Packet::new(EC_OP_MISC_DATA)
            .with(Tag::int(EC_TAG_PARTFILE_SIZE_FULL, 0x1_2345_6789))
            .with(Tag::string(EC_TAG_PARTFILE_NAME, "ünïcode.avi"))
            .with(Tag::hash(EC_TAG_PARTFILE_HASH, [7; 16]))
            .with(Tag::ipv4(EC_TAG_SERVER, [1, 2, 3, 4], 4661))
            .with(Tag::empty(EC_TAG_CAN_ZLIB))
            .with(Tag::custom(EC_TAG_SRP_A, vec![9; 384]));
        for opts in [
            WireOpts::default(),
            WireOpts {
                utf8_numbers: true,
                large_tag_count: true,
            },
        ] {
            let back = Packet::decode(&p.encode(opts), opts).unwrap();
            assert_eq!(back, p);
            assert_eq!(back.tags[0].as_int(), 0x1_2345_6789);
            assert_eq!(back.tags[1].as_str(), "ünïcode.avi");
            assert_eq!(back.tags[3].as_ipv4(), Some(([1, 2, 3, 4], 4661)));
        }
    }

    #[test]
    fn large_child_count_uses_the_sentinel() {
        let mut parent = Tag::empty(EC_TAG_STATS_LOGGER_MESSAGE);
        parent.children = (0..70_000u64).map(|i| Tag::int(EC_TAG_ECID, i)).collect();
        let p = Packet::new(EC_OP_MISC_DATA).with(parent);
        let opts = WireOpts {
            utf8_numbers: true,
            large_tag_count: true,
        };
        assert_eq!(Packet::decode(&p.encode(opts), opts).unwrap(), p);
        // Without the flag the count is capped at 0xFFFE, as the C++ does.
        let capped = Packet::decode(&p.encode(WireOpts::default()), WireOpts::default()).unwrap();
        assert_eq!(capped.tags[0].children.len(), 0xFFFE);
    }

    #[test]
    fn hostile_input_is_an_error_not_a_panic() {
        let opts = WireOpts::default();
        // Tag claims fewer bytes than its child needs.
        assert!(Packet::decode(
            &hex("0c 0001 000b 02 00000001 0001 0014 02 00000001 00"),
            opts
        )
        .is_err());
        // uint32 tag with 1 byte of data.
        assert!(Packet::decode(&hex("0c 0001 0014 04 00000001 00"), opts).is_err());
        // Huge child count, no data.
        assert!(Packet::decode(&hex("0c fffe"), opts).is_err());
        // Trailing garbage.
        assert!(Packet::decode(&hex("0c 0000 ff"), opts).is_err());
        // Nesting beyond the limit.
        let mut deep = hex("0c 0001");
        for _ in 0..70 {
            deep.extend(hex("0015 02 00000000 0001"));
        }
        assert!(Packet::decode(&deep, opts).is_err());
    }
}
