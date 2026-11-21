// SPDX-License-Identifier: GPL-2.0-or-later
//! The friend list (`CFriendList`, FriendList.cpp; `CFriend`, Friend.cpp)
//! and its requests over external connections (`Get_EC_Response_Friend`,
//! ExternalConn.cpp; `CEC_Friend_Tag`, ECSpecialCoreTags.cpp).
//!
//! Friends are kept in `emfriends.met`, read at start and written after each
//! change. `EC_OP_FRIEND` adds one by its address, hash and name, removes one,
//! or gives one the friend slot (only one friend holds it). Each friend has an
//! ECID for the life of the process, and is told in the incremental updates.
//!
//! Not yet: friends are not linked to the peers remuled talks to, so none is
//! ever connected; adding a connected client as a friend and browsing a
//! friend's files are refused, as for a client that is gone.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use ed2k_formats::emfriends_met::{EmfriendsMet, Friend, VERSION};
use ed2k_types::Md4Hash;
use remule_ec::codes::*;
use remule_ec::{Packet, Tag};
use tracing::{debug, info, warn};

/// `emfriends.met`.
pub const FILE_NAME: &str = "emfriends.met";

/// The friends, in the order they were added.
#[derive(Debug, Default)]
pub struct FriendList {
    path: PathBuf,
    friends: Vec<(u32, Friend)>,
}

/// A friend as the update tells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriendView {
    pub ecid: u32,
    pub name: String,
    pub user_hash: [u8; 16],
    /// Low byte first, as EC carries addresses.
    pub ip: u32,
    pub port: u16,
    pub friend_slot: bool,
}

/// `CEC_Friend_Tag(friend, valuemap)`: every field, by ECID. No friend is
/// linked to a client yet: client 0, not connected.
pub fn friend_tag(f: &FriendView) -> Tag {
    Tag::int(EC_TAG_FRIEND, f.ecid.into())
        .with(Tag::string(EC_TAG_FRIEND_NAME, &f.name))
        .with(Tag::hash(EC_TAG_FRIEND_HASH, f.user_hash))
        .with(Tag::int(EC_TAG_FRIEND_IP, f.ip.into()))
        .with(Tag::int(EC_TAG_FRIEND_PORT, f.port.into()))
        .with(Tag::int(EC_TAG_FRIEND_CLIENT, 0))
        .with(Tag::int(EC_TAG_CLIENT_CONNECTED, 0))
        .with(Tag::int(EC_TAG_FRIEND_FRIENDSLOT, f.friend_slot.into()))
}

fn failed(message: &str) -> Packet {
    Packet::new(EC_OP_FAILED).with(Tag::string(EC_TAG_STRING, message))
}

impl FriendList {
    /// `LoadList`: `emfriends.met` from the config directory; none, no
    /// friends. From a damaged file, the friends that could be read.
    pub fn load(config: &Path) -> FriendList {
        let path = config.join(FILE_NAME);
        let mut list = FriendList {
            path: path.clone(),
            friends: Vec::new(),
        };
        let Ok(bytes) = std::fs::read(&path) else {
            return list;
        };
        let records = match EmfriendsMet::read(&bytes) {
            Ok(m) => m.friends,
            Err(e) => {
                debug!("{FILE_NAME}: {:?}", e.kind);
                e.salvaged
            }
        };
        for r in &records {
            match Friend::from_record(r) {
                Ok(f) => list.push(f),
                Err(tag) => debug!("{FILE_NAME}: a friend with a bad tag {tag:#x}"),
            }
        }
        list
    }

    fn push(&mut self, f: Friend) {
        self.friends.push((crate::ec_shared::next_ecid(), f));
    }

    /// `SaveList`.
    fn save(&self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let met = EmfriendsMet {
            version: VERSION,
            friends: self.friends.iter().map(|(_, f)| f.to_record()).collect(),
        };
        if let Err(e) = std::fs::write(&self.path, met.write()) {
            warn!("Failed to open friend list file '{FILE_NAME}' for writing! ({e})");
        }
    }

    /// The friends as the update tells them.
    pub fn view(&self) -> Vec<FriendView> {
        self.friends
            .iter()
            .map(|(ecid, f)| FriendView {
                ecid: *ecid,
                name: f.name.clone(),
                user_hash: f.user_hash.0,
                ip: f.ip.map_or(0, |ip| u32::from_le_bytes(ip.octets())),
                port: f.port,
                friend_slot: f.friend_slot,
            })
            .collect()
    }

    fn find(&mut self, ecid: u64) -> Option<usize> {
        self.friends
            .iter()
            .position(|(id, _)| u64::from(*id) == ecid)
    }

    /// `Get_EC_Response_Friend`.
    pub fn answer(&mut self, req: &Packet) -> Packet {
        let oops = || failed("OOPS! OpCode processing error!");
        if let Some(add) = req.tag(EC_TAG_FRIEND_ADD) {
            // A connected client: none is tracked yet.
            if add.child(EC_TAG_CLIENT).is_some() {
                return oops();
            }
            let (Some(hash), Some(ip), Some(port), Some(name)) = (
                add.child(EC_TAG_FRIEND_HASH),
                add.child(EC_TAG_FRIEND_IP),
                add.child(EC_TAG_FRIEND_PORT),
                add.child(EC_TAG_FRIEND_NAME),
            ) else {
                return oops();
            };
            let ip = Ipv4Addr::from((ip.as_int() as u32).to_le_bytes());
            let f = Friend {
                user_hash: Md4Hash(hash.as_hash().unwrap_or_default()),
                ip: Some(ip),
                port: port.as_int() as u16,
                name: name.as_str(),
                ..Default::default()
            };
            info!("Added friend {} ({ip}:{})", f.name, f.port);
            self.push(f);
            self.save();
            return Packet::new(EC_OP_NOOP);
        }
        if let Some(remove) = req.tag(EC_TAG_FRIEND_REMOVE) {
            let Some(id) = remove.child(EC_TAG_FRIEND) else {
                return oops();
            };
            // Idempotent: gone already is the end asked for.
            if let Some(i) = self.find(id.as_int()) {
                self.friends.remove(i);
                self.save();
            }
            return Packet::new(EC_OP_NOOP);
        }
        if let Some(slot) = req.tag(EC_TAG_FRIEND_FRIENDSLOT) {
            let Some(i) = slot
                .child(EC_TAG_FRIEND)
                .and_then(|id| self.find(id.as_int()))
            else {
                return oops();
            };
            // `SetFriendSlot`: one friend holds it at most.
            let on = slot.as_int() != 0;
            for (j, (_, f)) in self.friends.iter_mut().enumerate() {
                if j == i {
                    f.friend_slot = on;
                } else if on {
                    f.friend_slot = false;
                }
            }
            self.save();
            return Packet::new(EC_OP_NOOP);
        }
        if let Some(shared) = req.tag(EC_TAG_FRIEND_SHARED) {
            // Browsing needs the friend's client, which is not kept yet.
            let mut p = failed("Client not found.");
            if let Some(r) = shared.child(EC_TAG_SEARCH_REF) {
                p = p.with(Tag::int(EC_TAG_SEARCH_REF, r.as_int()));
            }
            return p;
        }
        oops()
    }
}
