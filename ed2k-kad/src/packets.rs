// SPDX-License-Identifier: GPL-2.0-or-later
//! Kad2 packets (`CKademliaUDPListener`): built and parsed.
//!
//! IDs go on the wire as `WriteUInt128` writes them (four little-endian
//! 32-bit words, most significant first); IPs as aMule-order `u32`s.

use ed2k_codec::packet::kad_unpack_limit;
use ed2k_codec::tag::{read_kad_list, write_kad_list};
use ed2k_codec::{Packet, Reader, Tag, TagName, TagValue, Writer};
use ed2k_types::kad::v2::Opcode;
use ed2k_types::kad::FindType;
use ed2k_types::tags::kad as tag;
use ed2k_types::{Protocol, UInt128};

/// A contact as packets carry it: `<id 16><ip 4><udp 2><tcp 2><version 1>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactRecord {
    pub id: UInt128,
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
}

/// `KADEMLIA2_HELLO_REQ` / `_RES`: `<id 16><tcp port 2><version 1><tag count 1><tags>`.
#[derive(Debug, Clone, PartialEq)]
pub struct Hello {
    pub id: UInt128,
    pub tcp_port: u16,
    pub version: u8,
    /// `TAG_SOURCEUPORT`: the sender's own (internal) UDP port.
    pub udp_port: Option<u16>,
    /// `TAG_KADMISCOPTIONS`: bit 0 UDP firewalled, 1 TCP firewalled, 2 wants an ACK.
    pub misc_options: u8,
}

impl Hello {
    pub fn udp_firewalled(&self) -> bool {
        self.misc_options & 0x01 != 0
    }
    pub fn tcp_firewalled(&self) -> bool {
        self.misc_options & 0x02 != 0
    }
    pub fn wants_ack(&self) -> bool {
        self.misc_options & 0x04 != 0
    }
}

/// One answer of a `KADEMLIA2_SEARCH_RES`.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchAnswer {
    pub answer: UInt128,
    pub tags: Vec<Tag>,
}

/// A tag of a publish request and the bytes it took.
#[derive(Debug, Clone, PartialEq)]
pub struct SizedTag {
    pub tag: Tag,
    pub bytes: u32,
}

impl SizedTag {
    pub fn new(tag: Tag) -> Self {
        let mut w = Writer::new();
        let _ = tag.write_kad(&mut w);
        SizedTag {
            tag,
            bytes: w.len() as u32,
        }
    }
}

fn read_sized_tags(r: &mut Reader<'_>) -> Result<Vec<SizedTag>, String> {
    let n = r.u8().map_err(|e| e.to_string())?;
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let start = r.position();
        let tag = Tag::read_kad(r, true).map_err(|e| e.to_string())?;
        v.push(SizedTag {
            tag,
            bytes: (r.position() - start) as u32,
        });
    }
    Ok(v)
}

fn write_sized_tags(w: &mut Writer, tags: &[SizedTag]) {
    w.u8(tags.len().min(255) as u8);
    for t in tags.iter().take(255) {
        let _ = t.tag.write_kad(w);
    }
}

/// The Kad2 packets this crate speaks.
#[derive(Debug, Clone, PartialEq)]
pub enum KadPacket {
    BootstrapReq,
    BootstrapRes {
        id: UInt128,
        tcp_port: u16,
        version: u8,
        contacts: Vec<ContactRecord>,
    },
    HelloReq(Hello),
    HelloRes(Hello),
    HelloResAck {
        id: UInt128,
    },
    /// `KADEMLIA2_REQ`: `<type 1><target 16><receiver id 16>`; the type
    /// (low 5 bits) is how many contacts are wanted.
    Req {
        count: u8,
        target: UInt128,
        receiver: UInt128,
    },
    Res {
        target: UInt128,
        contacts: Vec<ContactRecord>,
    },
    /// `<target 16><start 2 (bit 15: terms follow)>[terms]`
    SearchKeyReq {
        target: UInt128,
        start: u16,
        terms: Option<Vec<u8>>,
    },
    /// `<target 16><start 2><file size 8>`
    SearchSourceReq {
        target: UInt128,
        start: u16,
        size: u64,
    },
    /// `<sender id 16><target 16><count 2>(<answer 16><tag list>)*`
    SearchRes {
        sender: UInt128,
        target: UInt128,
        results: Vec<SearchAnswer>,
    },
    /// `<target 16><file size 8>`
    SearchNotesReq {
        target: UInt128,
        size: u64,
    },
    /// `<keyword 16><count 2>(<file 16><tags>)*`
    PublishKeyReq {
        key: UInt128,
        files: Vec<(UInt128, Vec<SizedTag>)>,
    },
    /// `<file 16><source 16><tags>`
    PublishSourceReq {
        file: UInt128,
        source: UInt128,
        tags: Vec<SizedTag>,
    },
    /// `<file 16><source 16><tags>`
    PublishNotesReq {
        file: UInt128,
        source: UInt128,
        tags: Vec<SizedTag>,
    },
    /// `<target 16><load 1>[<options 1>]`
    PublishRes {
        target: UInt128,
        load: u8,
        options: Option<u8>,
    },
    PublishResAck,
    Ping,
    /// `<the port the pinger was seen from 2>`
    Pong {
        port: u16,
    },
    /// Anything else (or older): the opcode and payload.
    Other {
        opcode: u8,
        payload: Vec<u8>,
    },
}

/// A malformed packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("bad Kad packet {opcode:#04x}: {why}")]
pub struct BadPacket {
    pub opcode: u8,
    pub why: String,
}

fn contacts(w: &mut Writer, list: &[ContactRecord]) {
    for c in list {
        w.uint128(c.id)
            .u32(c.ip)
            .u16(c.udp_port)
            .u16(c.tcp_port)
            .u8(c.version);
    }
}

fn read_contacts(r: &mut Reader<'_>, n: usize) -> Result<Vec<ContactRecord>, ed2k_codec::Error> {
    // 25 bytes each: never more than the data holds.
    let mut v = Vec::with_capacity(n.min(r.remaining() / 25));
    for _ in 0..n {
        v.push(ContactRecord {
            id: r.uint128()?,
            ip: r.u32()?,
            udp_port: r.u16()?,
            tcp_port: r.u16()?,
            version: r.u8()?,
        });
    }
    Ok(v)
}

fn hello_bytes(w: &mut Writer, h: &Hello) {
    w.uint128(h.id).u16(h.tcp_port).u8(h.version);
    let mut tags = Vec::new();
    if let Some(p) = h.udp_port {
        tags.push(Tag::new(
            TagName::Str(tag::SOURCEUPORT.to_vec()),
            TagValue::int(p.into()),
        ));
    }
    // The sender leaves it out for receivers before version 8.
    if h.misc_options != 0 {
        tags.push(Tag::new(
            TagName::Str(tag::KADMISCOPTIONS.to_vec()),
            TagValue::int(h.misc_options.into()),
        ));
    }
    // Plain integers and at most two tags: this cannot fail.
    let _ = write_kad_list(w, &tags);
}

fn read_hello(r: &mut Reader<'_>) -> Result<Hello, String> {
    let e = |x: &dyn std::fmt::Display| x.to_string();
    let id = r.uint128().map_err(|x| e(&x))?;
    let tcp_port = r.u16().map_err(|x| e(&x))?;
    let version = r.u8().map_err(|x| e(&x))?;
    let tags = read_kad_list(r, true).map_err(|x| e(&x))?;
    let mut h = Hello {
        id,
        tcp_port,
        version,
        udp_port: None,
        misc_options: 0,
    };
    for t in tags {
        let v = t.as_int().unwrap_or(0);
        if t.name.is(tag::SOURCEUPORT) && v as u16 > 0 {
            h.udp_port = Some(v as u16);
        } else if t.name.is(tag::KADMISCOPTIONS) {
            h.misc_options = v as u8;
        }
    }
    Ok(h)
}

impl KadPacket {
    pub fn opcode(&self) -> u8 {
        let op = match self {
            KadPacket::BootstrapReq => Opcode::BootstrapReq,
            KadPacket::BootstrapRes { .. } => Opcode::BootstrapRes,
            KadPacket::HelloReq(_) => Opcode::HelloReq,
            KadPacket::HelloRes(_) => Opcode::HelloRes,
            KadPacket::HelloResAck { .. } => Opcode::HelloResAck,
            KadPacket::Req { .. } => Opcode::Req,
            KadPacket::Res { .. } => Opcode::Res,
            KadPacket::SearchKeyReq { .. } => Opcode::SearchKeyReq,
            KadPacket::SearchSourceReq { .. } => Opcode::SearchSourceReq,
            KadPacket::SearchRes { .. } => Opcode::SearchRes,
            KadPacket::SearchNotesReq { .. } => Opcode::SearchNotesReq,
            KadPacket::PublishKeyReq { .. } => Opcode::PublishKeyReq,
            KadPacket::PublishSourceReq { .. } => Opcode::PublishSourceReq,
            KadPacket::PublishNotesReq { .. } => Opcode::PublishNotesReq,
            KadPacket::PublishRes { .. } => Opcode::PublishRes,
            KadPacket::PublishResAck => Opcode::PublishResAck,
            KadPacket::Ping => Opcode::Ping,
            KadPacket::Pong { .. } => Opcode::Pong,
            KadPacket::Other { opcode, .. } => return *opcode,
        };
        op.into()
    }

    /// The payload.
    pub fn payload(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            KadPacket::BootstrapReq | KadPacket::Ping | KadPacket::PublishResAck => {}
            KadPacket::SearchNotesReq { target, size } => {
                w.uint128(*target).u64(*size);
            }
            KadPacket::PublishKeyReq { key, files } => {
                w.uint128(*key).u16(files.len() as u16);
                for (f, tags) in files {
                    w.uint128(*f);
                    write_sized_tags(&mut w, tags);
                }
            }
            KadPacket::PublishSourceReq { file, source, tags }
            | KadPacket::PublishNotesReq { file, source, tags } => {
                w.uint128(*file).uint128(*source);
                write_sized_tags(&mut w, tags);
            }
            KadPacket::PublishRes {
                target,
                load,
                options,
            } => {
                w.uint128(*target).u8(*load);
                if let Some(o) = options {
                    w.u8(*o);
                }
            }
            KadPacket::BootstrapRes {
                id,
                tcp_port,
                version,
                contacts: list,
            } => {
                w.uint128(*id)
                    .u16(*tcp_port)
                    .u8(*version)
                    .u16(list.len() as u16);
                contacts(&mut w, list);
            }
            KadPacket::HelloReq(h) | KadPacket::HelloRes(h) => hello_bytes(&mut w, h),
            KadPacket::HelloResAck { id } => {
                w.uint128(*id).u8(0);
            }
            KadPacket::Req {
                count,
                target,
                receiver,
            } => {
                w.u8(*count).uint128(*target).uint128(*receiver);
            }
            KadPacket::Res {
                target,
                contacts: list,
            } => {
                w.uint128(*target).u8(list.len() as u8);
                contacts(&mut w, list);
            }
            KadPacket::SearchKeyReq {
                target,
                start,
                terms,
            } => {
                w.uint128(*target);
                match terms {
                    Some(t) if !t.is_empty() => {
                        w.u16(start | 0x8000).bytes(t);
                    }
                    _ => {
                        w.u16(start & 0x7FFF);
                    }
                }
            }
            KadPacket::SearchSourceReq {
                target,
                start,
                size,
            } => {
                w.uint128(*target).u16(*start).u64(*size);
            }
            KadPacket::SearchRes {
                sender,
                target,
                results,
            } => {
                w.uint128(*sender)
                    .uint128(*target)
                    .u16(results.len() as u16);
                for r in results {
                    w.uint128(r.answer);
                    let _ = write_kad_list(&mut w, &r.tags);
                }
            }
            KadPacket::Pong { port } => {
                w.u16(*port);
            }
            KadPacket::Other { payload, .. } => {
                w.bytes(payload);
            }
        }
        w.into_bytes()
    }

    /// The datagram: packed when over 200 bytes, as aMule does.
    pub fn to_datagram(&self) -> Vec<u8> {
        let mut p = Packet::new(Protocol::Kademlia, self.opcode(), self.payload());
        if p.payload.len() > 200 {
            p.pack();
        }
        p.to_udp_bytes()
    }

    /// Parse a (decrypted) datagram.
    pub fn parse(datagram: &[u8]) -> Result<KadPacket, BadPacket> {
        let mut p = Packet::parse_udp(datagram).map_err(|e| BadPacket {
            opcode: 0,
            why: e.to_string(),
        })?;
        let opcode = p.opcode;
        let bad = |why: String| BadPacket { opcode, why };
        if p.protocol == Protocol::KademliaPacked as u8 {
            p.unpack(kad_unpack_limit(p.payload.len()))
                .map_err(|e| bad(e.to_string()))?;
        } else if p.protocol != Protocol::Kademlia as u8 {
            return Err(bad(format!("protocol {:#04x}", p.protocol)));
        }
        let mut r = Reader::new(&p.payload);
        let e = |x: ed2k_codec::Error| bad(x.to_string());
        let Ok(op) = Opcode::try_from(opcode) else {
            return Ok(KadPacket::Other {
                opcode,
                payload: p.payload,
            });
        };
        Ok(match op {
            Opcode::BootstrapReq => KadPacket::BootstrapReq,
            Opcode::BootstrapRes => {
                let id = r.uint128().map_err(e)?;
                let tcp_port = r.u16().map_err(e)?;
                let version = r.u8().map_err(e)?;
                let n = r.u16().map_err(e)? as usize;
                if n > 25 {
                    return Err(bad(format!("{n} contacts")));
                }
                KadPacket::BootstrapRes {
                    id,
                    tcp_port,
                    version,
                    contacts: read_contacts(&mut r, n).map_err(e)?,
                }
            }
            Opcode::HelloReq => KadPacket::HelloReq(read_hello(&mut r).map_err(bad)?),
            Opcode::HelloRes => KadPacket::HelloRes(read_hello(&mut r).map_err(bad)?),
            Opcode::HelloResAck => {
                if p.payload.len() < 17 {
                    return Err(bad("short".into()));
                }
                KadPacket::HelloResAck {
                    id: r.uint128().map_err(e)?,
                }
            }
            Opcode::Req => KadPacket::Req {
                count: r.u8().map_err(e)? & 0x1F,
                target: r.uint128().map_err(e)?,
                receiver: r.uint128().map_err(e)?,
            },
            Opcode::Res => {
                let target = r.uint128().map_err(e)?;
                let n = r.u8().map_err(e)? as usize;
                // CHECK_PACKET_EXACT_SIZE
                if p.payload.len() != 17 + 25 * n {
                    return Err(bad(format!("{n} contacts in {} bytes", p.payload.len())));
                }
                KadPacket::Res {
                    target,
                    contacts: read_contacts(&mut r, n).map_err(e)?,
                }
            }
            Opcode::SearchKeyReq => {
                let target = r.uint128().map_err(e)?;
                let start = r.u16().map_err(e)?;
                let terms = (start & 0x8000 != 0).then(|| r.rest().to_vec());
                KadPacket::SearchKeyReq {
                    target,
                    start: start & 0x7FFF,
                    terms,
                }
            }
            Opcode::SearchSourceReq => KadPacket::SearchSourceReq {
                target: r.uint128().map_err(e)?,
                start: r.u16().map_err(e)? & 0x7FFF,
                size: r.u64().map_err(e)?,
            },
            Opcode::SearchRes => {
                let sender = r.uint128().map_err(e)?;
                let target = r.uint128().map_err(e)?;
                let n = r.u16().map_err(e)? as usize;
                // Each answer takes at least 17 bytes.
                let mut results = Vec::with_capacity(n.min(r.remaining() / 17));
                for _ in 0..n {
                    let answer = r.uint128().map_err(e)?;
                    let tags = read_kad_list(&mut r, true).map_err(|x| bad(x.to_string()))?;
                    results.push(SearchAnswer { answer, tags });
                }
                KadPacket::SearchRes {
                    sender,
                    target,
                    results,
                }
            }
            Opcode::SearchNotesReq => KadPacket::SearchNotesReq {
                target: r.uint128().map_err(e)?,
                size: r.u64().map_err(e)?,
            },
            Opcode::PublishKeyReq => {
                let key = r.uint128().map_err(e)?;
                let n = r.u16().map_err(e)? as usize;
                // CheckTagRecords: at least 17 bytes a record.
                if n * 17 > r.remaining() {
                    return Err(bad(format!("{n} records")));
                }
                let mut files = Vec::with_capacity(n);
                for _ in 0..n {
                    let f = r.uint128().map_err(e)?;
                    files.push((f, read_sized_tags(&mut r).map_err(bad)?));
                }
                KadPacket::PublishKeyReq { key, files }
            }
            Opcode::PublishSourceReq | Opcode::PublishNotesReq => {
                let file = r.uint128().map_err(e)?;
                let source = r.uint128().map_err(e)?;
                let tags = read_sized_tags(&mut r).map_err(bad)?;
                if op == Opcode::PublishSourceReq {
                    KadPacket::PublishSourceReq { file, source, tags }
                } else {
                    KadPacket::PublishNotesReq { file, source, tags }
                }
            }
            Opcode::PublishRes => KadPacket::PublishRes {
                target: r.uint128().map_err(e)?,
                load: r.u8().map_err(e)?,
                options: r.u8().ok(),
            },
            Opcode::PublishResAck => KadPacket::PublishResAck,
            Opcode::Ping => KadPacket::Ping,
            Opcode::Pong => KadPacket::Pong {
                port: r.u16().map_err(e)?,
            },
            _ => KadPacket::Other {
                opcode,
                payload: p.payload,
            },
        })
    }
}

/// `KADEMLIA_FIND_*` counts.
pub fn find_count(t: FindType) -> u8 {
    t.into()
}
