// SPDX-License-Identifier: GPL-2.0-or-later
//! The server connection as a state machine, without IO
//! (`CServerSocket` connection states and `ProcessPacket`).
//!
//! ```text
//! Connecting --start()--> WaitingForLogin --OP_IDCHANGE(id != 0)--> Connected { id }
//!                                \--OP_IDCHANGE(0)--> Closed(Refused)
//! ```
//!
//! A server says why it refuses a login in `OP_SERVERMESSAGE` lines
//! starting with `ERROR` or `WARNING`, before it sends an ID of 0 or hangs up.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use ed2k_codec::Packet;
use ed2k_types::Md4Hash;

use crate::packets::{self, is_low_id, IdChange, LoginInfo, ServerPacket, Source};
use crate::search::SearchResult;

/// `CONSERVTIMEOUT`: how long a login may take.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(25);

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// The server gave ID 0: it will not have us.
    Refused,
    /// The connection went away.
    Closed,
}

/// `CS_*`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Connecting,
    WaitingForLogin,
    Connected { id: u32 },
    Closed(CloseReason),
}

/// What we learned about the server (`CServer`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerInfo {
    pub name: Option<String>,
    pub description: Option<String>,
    /// From the "server version" message.
    pub version: Option<String>,
    pub tcp_flags: u32,
    pub aux_port: Option<u32>,
    pub obfuscation_port: Option<u32>,
    pub users: u32,
    pub files: u32,
    /// From an `[emDynIP: ...]` message.
    pub dyn_ip: Option<String>,
}

/// Something for the application.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    LoggedIn {
        id: u32,
        low_id: bool,
        /// Our IP as the server saw it (sent to LowIDs by newer servers).
        public_ip: Option<Ipv4Addr>,
    },
    /// Another `OP_IDCHANGE` after login.
    IdChanged {
        id: u32,
    },
    Message(String),
    /// A message starting with `ERROR`, the prefix stripped.
    Error(String),
    /// A message starting with `WARNING`.
    Warning(String),
    Status {
        users: u32,
        files: u32,
    },
    Ident,
    SearchResults {
        results: Vec<SearchResult>,
        more: Option<bool>,
    },
    FoundSources {
        hash: Md4Hash,
        sources: Vec<Source>,
    },
    ServerList(Vec<SocketAddrV4>),
    CallbackRequested {
        ip: Ipv4Addr,
        port: u16,
        crypt_options: Option<u8>,
        user_hash: Option<Md4Hash>,
    },
    CallbackFail,
    /// `OP_REJECT`: "Server rejected last command".
    Rejected,
    Closed(CloseReason),
    /// A packet this does not handle.
    Unhandled(Packet),
}

/// Options for what is sent on our behalf.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// `AddServersFromServer`: ask for the server list once logged in.
    pub ask_server_list: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            ask_server_list: true,
        }
    }
}

/// One server connection.
#[derive(Debug)]
pub struct Session {
    state: State,
    login: LoginInfo,
    options: SessionOptions,
    info: ServerInfo,
}

/// What handling a packet produced.
#[derive(Debug, Default)]
pub struct Output {
    pub events: Vec<Event>,
    pub send: Vec<Packet>,
}

impl Session {
    pub fn new(login: LoginInfo, options: SessionOptions) -> Self {
        Session {
            state: State::Connecting,
            login,
            options,
            info: ServerInfo::default(),
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Our ID, once logged in.
    pub fn id(&self) -> Option<u32> {
        match self.state {
            State::Connected { id } => Some(id),
            _ => None,
        }
    }

    /// Whether the server takes 64-bit sizes (`SRV_TCPFLG_LARGEFILES`).
    pub fn supports_large_files(&self) -> bool {
        self.info.tcp_flags & ed2k_types::ed2k::server_tcp::flags::LARGEFILES != 0
    }

    /// The TCP connection is up: the login to send.
    pub fn start(&mut self) -> Result<Packet, ed2k_codec::TagError> {
        let p = packets::login(&self.login)?;
        self.state = State::WaitingForLogin;
        Ok(p)
    }

    /// The connection went away.
    pub fn closed(&mut self) -> Event {
        if !matches!(self.state, State::Closed(_)) {
            self.state = State::Closed(CloseReason::Closed);
        }
        Event::Closed(CloseReason::Closed)
    }

    /// Handle a packet from the server.
    pub fn handle(&mut self, packet: ServerPacket) -> Output {
        let mut out = Output::default();
        match packet {
            ServerPacket::Message(lines) => {
                for line in lines {
                    self.message(line, &mut out.events);
                }
            }
            ServerPacket::IdChange(c) => self.id_change(c, &mut out),
            ServerPacket::SearchResults { results, more } => {
                out.events.push(Event::SearchResults { results, more })
            }
            ServerPacket::FoundSources { hash, sources } => {
                out.events.push(Event::FoundSources { hash, sources })
            }
            ServerPacket::Status { users, files } => {
                self.info.users = users;
                self.info.files = files;
                out.events.push(Event::Status { users, files });
            }
            ServerPacket::Ident {
                name, description, ..
            } => {
                if name.is_some() {
                    self.info.name = name;
                }
                if description.is_some() {
                    self.info.description = description;
                }
                out.events.push(Event::Ident);
            }
            ServerPacket::ServerList(list) => out.events.push(Event::ServerList(list)),
            ServerPacket::CallbackRequested {
                ip,
                port,
                crypt_options,
                user_hash,
            } => out.events.push(Event::CallbackRequested {
                ip,
                port,
                crypt_options,
                user_hash,
            }),
            ServerPacket::CallbackFail => out.events.push(Event::CallbackFail),
            ServerPacket::Reject => out.events.push(Event::Rejected),
            ServerPacket::Other(p) => out.events.push(Event::Unhandled(p)),
        }
        out
    }

    fn message(&mut self, line: String, events: &mut Vec<Event>) {
        if let Some(v) = line.strip_prefix("server version") {
            // Mid(15, 64): skip the separator, at most 64 characters.
            let v: String = v.chars().skip(1).take(64).collect();
            self.info.version = Some(v.trim().to_owned());
        }
        if let (Some(a), Some(b)) = (line.find("[emDynIP: "), line.find(']')) {
            if a < b {
                let ip = line[a + 10..b].trim_matches(' ');
                if !ip.is_empty() && ip.len() < 51 {
                    self.info.dyn_ip = Some(ip.to_owned());
                }
            }
        }
        let strip = |s: &str| s.get(5..).unwrap_or("").trim_matches([' ', ':']).to_owned();
        events.push(if line.starts_with("ERROR") {
            Event::Error(strip(&line))
        } else if line.starts_with("WARNING") {
            // aMule cuts five characters here as for ERROR, which leaves
            // "NG: ..." in its log; this cuts the whole word.
            Event::Warning(
                line.get(7..)
                    .unwrap_or("")
                    .trim_matches([' ', ':'])
                    .to_owned(),
            )
        } else {
            Event::Message(line)
        });
    }

    fn id_change(&mut self, c: IdChange, out: &mut Output) {
        self.info.tcp_flags = c.tcp_flags;
        if c.aux_port.is_some() {
            self.info.aux_port = c.aux_port;
        }
        if let Some(p) = c.obfuscation_port.filter(|&p| p != 0) {
            self.info.obfuscation_port = Some(p);
        }
        if c.id == 0 {
            self.state = State::Closed(CloseReason::Refused);
            out.events.push(Event::Closed(CloseReason::Refused));
            return;
        }
        let first = !matches!(self.state, State::Connected { .. });
        self.state = State::Connected { id: c.id };
        if first {
            let public_ip = c
                .reported_ip
                .filter(|_| is_low_id(c.id))
                .map(packets::id_to_ip);
            out.events.push(Event::LoggedIn {
                id: c.id,
                low_id: is_low_id(c.id),
                public_ip,
            });
            if self.options.ask_server_list {
                out.send.push(packets::get_server_list());
            }
        } else {
            out.events.push(Event::IdChanged { id: c.id });
        }
    }
}
