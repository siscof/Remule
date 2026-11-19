// SPDX-License-Identifier: GPL-2.0-or-later
//! What `amulegui` polls with: `EC_OP_GET_UPDATE` at `EC_DETAIL_INC_UPDATE`
//! (`Get_EC_Response_GetUpdate`), and the preferences it asks for once
//! logged in (`EC_OP_GET_PREFERENCES`, `CEC_Prefs_Packet`).
//!
//! An incremental update sends each object by its ECID with only the tags
//! whose values changed since this connection last saw it (`CValueMap`),
//! and a download's bars as a diff against what this connection last
//! decoded (`CPartFile_Encoder`, [`remule_ec::rle`]). Both live with the
//! connection: a new one starts from nothing.

use std::collections::HashMap;

use ed2k_formats::server_met::ServerInfo;
use remule_ec::codes::*;
use remule_ec::rle::RleData;
use remule_ec::{Packet, Tag};

use crate::ec::Download;
use crate::ec_shared::SharedBase;

/// `CValueMap`: the last value sent of each tag of one object.
#[derive(Debug, Default)]
pub struct ValueMap {
    last: HashMap<u16, Tag>,
}

impl ValueMap {
    /// `t` with only the children whose value differs from the last sent
    /// (all of them the first time); those are remembered.
    pub fn filter(&mut self, mut t: Tag) -> Tag {
        let children = std::mem::take(&mut t.children);
        for c in children {
            if self.last.get(&c.name) != Some(&c) {
                self.last.insert(c.name, c.clone());
                t.children.push(c);
            }
        }
        t
    }
}

/// `CPartFile_Encoder` / `CKnownFile_Encoder`: one object's bars as this
/// connection last decoded them.
#[derive(Debug)]
pub struct FileEncoder {
    parts: RleData,
    gaps: RleData,
    reqs: RleData,
}

impl Default for FileEncoder {
    fn default() -> Self {
        FileEncoder {
            parts: RleData::new(true),
            gaps: RleData::new(true),
            reqs: RleData::new(true),
        }
    }
}

impl FileEncoder {
    /// `CPartFile_Encoder::Encode`: part availability (once known), the
    /// gaps and the requested blocks, each only when it changed. Source
    /// names are not kept yet.
    pub fn encode_download(&mut self, d: &Download, parent: &mut Tag) {
        if !d.part_frequency.is_empty() {
            let (enc, changed) = self.parts.encode_u16(&d.part_frequency);
            if changed {
                parent
                    .children
                    .push(Tag::custom(EC_TAG_PARTFILE_PART_STATUS, enc));
            }
        }
        let flat = |r: &[(u64, u64)]| r.iter().flat_map(|&(s, e)| [s, e]).collect::<Vec<u64>>();
        let (enc, changed) = self.gaps.encode_u64(&flat(&d.gaps));
        if changed {
            parent
                .children
                .push(Tag::custom(EC_TAG_PARTFILE_GAP_STATUS, enc));
        }
        let (enc, changed) = self.reqs.encode_u64(&flat(&d.requested));
        if changed {
            parent
                .children
                .push(Tag::custom(EC_TAG_PARTFILE_REQ_STATUS, enc));
        }
    }
}

/// A server as the update tells it: its ECID, its record, and the flags
/// it gave us when logged in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateServer {
    pub ecid: u32,
    pub info: ServerInfo,
    pub tcp_flags: u32,
}

/// What the client gives for one update.
#[derive(Clone, Debug, Default)]
pub struct UpdateData {
    pub shared: Vec<SharedBase>,
    pub servers: Vec<UpdateServer>,
}

/// One connection's view: what it was sent of each object.
#[derive(Debug, Default)]
pub struct UpdateState {
    maps: HashMap<u32, ValueMap>,
    encoders: HashMap<u32, FileEncoder>,
    /// The files alive at the last update (`m_lastSentFileIds`), for the
    /// partial-update protocol's removals.
    last_sent: Vec<u32>,
}

/// `CEC_Server_Tag(server, valuemap)`: every field, by ECID.
fn server_tag(s: &UpdateServer) -> Tag {
    let i = &s.info;
    let int = |n: u16, v: u64| Tag::int(n, v);
    let ip = i.ip.map_or(0, |ip| u32::from_le_bytes(ip.octets()));
    Tag::int(EC_TAG_SERVER, s.ecid.into())
        .with(Tag::string(EC_TAG_SERVER_NAME, &i.name))
        .with(Tag::string(EC_TAG_SERVER_DESC, &i.description))
        .with(Tag::string(EC_TAG_SERVER_VERSION, &i.version))
        .with(int(EC_TAG_SERVER_IP, ip.into()))
        .with(int(EC_TAG_SERVER_PORT, i.port.into()))
        .with(int(EC_TAG_SERVER_PING, i.ping.into()))
        .with(int(EC_TAG_SERVER_PRIO, i.preference.into()))
        .with(int(EC_TAG_SERVER_FAILED, i.failed.into()))
        // Static servers (`staticservers.dat`) are not kept: none is.
        .with(int(EC_TAG_SERVER_STATIC, 0))
        .with(int(EC_TAG_SERVER_USERS, i.users.into()))
        .with(int(EC_TAG_SERVER_USERS_MAX, i.max_users.into()))
        .with(int(EC_TAG_SERVER_FILES, i.files.into()))
        .with(int(EC_TAG_SERVER_FILES_SOFT, i.soft_files.into()))
        .with(int(EC_TAG_SERVER_FILES_HARD, i.hard_files.into()))
        .with(int(EC_TAG_SERVER_TCP_FLAGS, s.tcp_flags.into()))
        .with(int(EC_TAG_SERVER_UDP_FLAGS, i.udp_flags.into()))
}

impl UpdateState {
    /// `Get_EC_Response_GetUpdate`: every download and shared file in ECID
    /// order with what changed (a file with nothing new is a bare ECID,
    /// which a client that infers removal from absence reads as "still
    /// there"), then the clients (none are tracked yet), the servers and
    /// the friends (none). A file seen for the first time starts from
    /// nothing; one gone is forgotten.
    ///
    /// With the partial-update protocol (`partial`), a file with nothing new
    /// is left out instead, and each file of the last update that is gone
    /// is named with `EC_TAG_FILE_REMOVED`.
    pub fn reply(&mut self, downloads: &[Download], data: &UpdateData, partial: bool) -> Packet {
        enum Obj<'a> {
            Download(&'a Download),
            Shared(&'a SharedBase),
        }
        let mut files: Vec<(u32, Obj)> = downloads
            .iter()
            .map(|d| (d.ecid, Obj::Download(d)))
            .chain(data.shared.iter().map(|s| (s.ecid, Obj::Shared(s))))
            .collect();
        files.sort_by_key(|(id, _)| *id);
        files.dedup_by_key(|(id, _)| *id);

        // `UpdateEncoders`: encoders follow the files; a fresh one drops
        // the value map, so the file goes out in full.
        self.encoders
            .retain(|id, _| files.iter().any(|(f, _)| f == id));
        for (id, _) in &files {
            if !self.encoders.contains_key(id) {
                self.encoders.insert(*id, FileEncoder::default());
                self.maps.remove(id);
            }
        }

        let mut p = Packet::new(EC_OP_SHARED_FILES);
        for (id, obj) in &files {
            let map = self.maps.entry(*id).or_default();
            let t = match obj {
                Obj::Download(d) => {
                    let full = crate::ec::partfile_tag(d, EC_DETAIL_INC_UPDATE)
                        // Partial downloads are not shared yet.
                        .with(Tag::int(EC_TAG_PARTFILE_SHARED, 0));
                    let mut t = map.filter(full);
                    self.encoders
                        .get_mut(id)
                        .expect("made above")
                        .encode_download(d, &mut t);
                    t
                }
                // A shared file's availability comes from the peers that
                // ask for it, which is not kept yet: no bar.
                Obj::Shared(s) => map.filter(crate::ec_shared::shared_tag(
                    EC_TAG_KNOWNFILE,
                    s,
                    EC_DETAIL_INC_UPDATE,
                )),
            };
            if partial && t.children.is_empty() {
                continue;
            }
            p = p.with(t);
        }
        if partial {
            let current: Vec<u32> = files.iter().map(|(id, _)| *id).collect();
            for gone in self.last_sent.iter().filter(|id| !current.contains(id)) {
                p = p.with(Tag::int(EC_TAG_FILE_REMOVED, (*gone).into()));
            }
            self.last_sent = current;
        }
        p = p.with(Tag::empty(EC_TAG_CLIENT));
        let mut servers = Tag::empty(EC_TAG_SERVER);
        for s in &data.servers {
            let map = self.maps.entry(s.ecid).or_default();
            servers.children.push(map.filter(server_tag(s)));
        }
        p.with(servers).with(Tag::empty(EC_TAG_FRIEND))
    }
}

/// The preferences `remuled` can tell, as `amule.conf` gives them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EcPrefs {
    pub nick: String,
    pub user_hash: [u8; 16],
    /// kB/s, for the graphs.
    pub upload_capacity: u32,
    pub download_capacity: u32,
    /// kB/s, 0 for no limit.
    pub max_upload: u32,
    pub max_download: u32,
    pub slot_allocation: u32,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub udp_enabled: bool,
    pub max_sources_per_file: u16,
    pub max_connections: u16,
    pub autoconnect: bool,
    pub reconnect: bool,
    pub ed2k: bool,
    pub kad: bool,
    pub bind_address: String,
    pub bind_interface: String,
    pub upnp_enabled: bool,
    pub upnp_tcp_port: u16,
}

/// `CEC_Prefs_Packet(selection, EC_DETAIL_UPDATE, ...)`: the general and
/// connection pages of the selection. The other pages are not kept yet
/// and are left out, which a client reads as "keep your own".
pub fn prefs_reply(req: &Packet, p: &EcPrefs) -> Packet {
    let selection = req.tag(EC_TAG_SELECT_PREFS).map_or(0, Tag::as_int) as u32;
    let mut out = Packet::new(EC_OP_SET_PREFERENCES)
        .with(Tag::int(EC_TAG_DETAIL_LEVEL, EC_DETAIL_UPDATE.into()));
    let int = |n: u16, v: u64| Tag::int(n, v);
    let flag = |n: u16, on: bool| on.then(|| Tag::empty(n));
    if selection & EC_PREFS_GENERAL != 0 {
        out = out.with(
            Tag::empty(EC_TAG_PREFS_GENERAL)
                .with(Tag::string(EC_TAG_USER_NICK, &p.nick))
                .with(Tag::hash(EC_TAG_USER_HASH, p.user_hash))
                .with(Tag::string(EC_TAG_USER_HOST, ""))
                .with(int(EC_TAG_GENERAL_CHECK_NEW_VERSION, 0))
                // No version check, no UPnP in this build.
                .with(int(EC_TAG_GENERAL_VERSION_CHECK_AVAILABLE, 0))
                .with(int(EC_TAG_GENERAL_UPNP_AVAILABLE, 0)),
        );
    }
    if selection & EC_PREFS_CONNECTIONS != 0 {
        let mut c = Tag::empty(EC_TAG_PREFS_CONNECTIONS)
            .with(int(EC_TAG_CONN_UL_CAP, p.upload_capacity.into()))
            .with(int(EC_TAG_CONN_DL_CAP, p.download_capacity.into()))
            .with(int(EC_TAG_CONN_MAX_UL, p.max_upload.into()))
            .with(int(EC_TAG_CONN_MAX_DL, p.max_download.into()))
            .with(int(EC_TAG_CONN_SLOT_ALLOCATION, p.slot_allocation.into()))
            .with(int(EC_TAG_CONN_TCP_PORT, p.tcp_port.into()))
            .with(int(EC_TAG_CONN_UDP_PORT, p.udp_port.into()));
        let push = |c: &mut Tag, t: Option<Tag>| c.children.extend(t);
        push(&mut c, flag(EC_TAG_CONN_UDP_DISABLE, !p.udp_enabled));
        c = c
            .with(int(
                EC_TAG_CONN_MAX_FILE_SOURCES,
                p.max_sources_per_file.into(),
            ))
            .with(int(EC_TAG_CONN_MAX_CONN, p.max_connections.into()));
        push(&mut c, flag(EC_TAG_CONN_AUTOCONNECT, p.autoconnect));
        push(&mut c, flag(EC_TAG_CONN_RECONNECT, p.reconnect));
        push(&mut c, flag(EC_TAG_NETWORK_ED2K, p.ed2k));
        push(&mut c, flag(EC_TAG_NETWORK_KADEMLIA, p.kad));
        c = c
            .with(Tag::string(EC_TAG_CONN_BIND_ADDRESS, &p.bind_address))
            .with(Tag::string(EC_TAG_CONN_BIND_INTERFACE, &p.bind_interface))
            // No proxy is used.
            .with(int(EC_TAG_PROXY_ENABLE, 0))
            .with(int(EC_TAG_PROXY_TYPE, 0))
            .with(Tag::string(EC_TAG_PROXY_HOST, ""))
            .with(int(EC_TAG_PROXY_PORT, 0))
            .with(int(EC_TAG_PROXY_AUTH, 0))
            .with(Tag::string(EC_TAG_PROXY_USER, ""))
            .with(Tag::string(EC_TAG_PROXY_PASSWORD, ""))
            .with(int(EC_TAG_CONN_UPNP_ENABLED, p.upnp_enabled.into()))
            .with(int(EC_TAG_CONN_UPNP_TCP_PORT, p.upnp_tcp_port.into()));
        out = out.with(c);
    }
    out
}
