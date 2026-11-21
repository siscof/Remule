// SPDX-License-Identifier: GPL-2.0-or-later
//! amulecmd's command set (`CamulecmdApp::OnInitCommandSet`) and how a
//! typed line finds its command (`CCommandTree`): words matched case
//! insensitively down the tree, what is left over is the argument.

pub const CMD_OK: i32 = 0;
pub const CMD_ID_QUIT: i32 = -1;
pub const CMD_ID_HELP: i32 = -2;
pub const CMD_ERR_SYNTAX: i32 = -3;
pub const CMD_ERR_PROCESS_CMD: i32 = -4;
pub const CMD_ERR_NO_PARAM: i32 = -5;
pub const CMD_ERR_MUST_HAVE_PARAM: i32 = -6;
pub const CMD_ERR_INVALID_ARG: i32 = -7;
pub const CMD_ERR_INCOMPLETE: i32 = -8;
const CMD_DEPRECATED: i32 = 0x1000;

/// The command IDs, in TextClient.cpp's order.
#[allow(dead_code)]
pub mod id {
    pub const STATUS: i32 = 0;
    pub const RESUME: i32 = 1;
    pub const PAUSE: i32 = 2;
    pub const PRIORITY_LOW: i32 = 3;
    pub const PRIORITY_NORMAL: i32 = 4;
    pub const PRIORITY_HIGH: i32 = 5;
    pub const PRIORITY_AUTO: i32 = 6;
    pub const CANCEL: i32 = 7;
    pub const CONNECT: i32 = 8;
    pub const CONNECT_ED2K: i32 = 9;
    pub const CONNECT_KAD: i32 = 10;
    pub const DISCONNECT: i32 = 11;
    pub const DISCONNECT_ED2K: i32 = 12;
    pub const DISCONNECT_KAD: i32 = 13;
    pub const RELOAD_SHARED: i32 = 14;
    pub const RELOAD_IPFILTER_LOCAL: i32 = 15;
    pub const RELOAD_IPFILTER_NET: i32 = 16;
    pub const SET_IPFILTER_ON: i32 = 17;
    pub const SET_IPFILTER_OFF: i32 = 18;
    pub const SET_IPFILTER_CLIENTS_ON: i32 = 19;
    pub const SET_IPFILTER_CLIENTS_OFF: i32 = 20;
    pub const SET_IPFILTER_SERVERS_ON: i32 = 21;
    pub const SET_IPFILTER_SERVERS_OFF: i32 = 22;
    pub const SET_IPFILTER_LEVEL: i32 = 23;
    pub const GET_IPFILTER: i32 = 24;
    pub const GET_IPFILTER_STATE: i32 = 25;
    pub const GET_IPFILTER_STATE_CLIENTS: i32 = 26;
    pub const GET_IPFILTER_STATE_SERVERS: i32 = 27;
    pub const GET_IPFILTER_LEVEL: i32 = 28;
    pub const SHOW_UL: i32 = 29;
    pub const SHOW_DL: i32 = 30;
    pub const SHOW_LOG: i32 = 31;
    pub const SHOW_SERVERS: i32 = 32;
    pub const SHOW_SHARED: i32 = 33;
    pub const RESET_LOG: i32 = 34;
    pub const SHUTDOWN: i32 = 35;
    pub const ADDLINK: i32 = 36;
    pub const SET_BWLIMIT_UP: i32 = 37;
    pub const SET_BWLIMIT_DOWN: i32 = 38;
    pub const GET_BWLIMITS: i32 = 39;
    pub const SET_ENDGAME: i32 = 40;
    pub const GET_ENDGAME: i32 = 41;
    pub const STATTREE: i32 = 42;
    pub const SEARCH: i32 = 43;
    pub const SEARCH_ALL: i32 = 44;
    pub const SEARCH_GLOBAL: i32 = 45;
    pub const SEARCH_LOCAL: i32 = 46;
    pub const SEARCH_KAD: i32 = 47;
    pub const SEARCH_RESULTS: i32 = 48;
    pub const SEARCH_PROGRESS: i32 = 49;
    pub const SEARCH_LIST: i32 = 50;
    pub const SEARCH_STOP: i32 = 51;
    pub const SEARCH_MORE: i32 = 52;
    pub const DOWNLOAD: i32 = 53;
    pub const SET_IPFILTER: i32 = 54;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Params {
    Never,
    Optional,
    Always,
}

/// One node of the tree; the root has no name.
pub struct Command {
    name: String,
    id: i32,
    short: String,
    verbose: String,
    params: Params,
    children: Vec<Command>,
}

/// What a typed line resolved to.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub id: i32,
    /// What followed the command's words.
    pub args: String,
    /// The command's full name, lower case ("show dl").
    pub path: String,
    /// The long help of a deprecated command, shown when it is used.
    pub deprecation: Option<String>,
}

impl Command {
    fn root() -> Self {
        Command {
            name: String::new(),
            id: CMD_ERR_SYNTAX,
            short: String::new(),
            verbose: String::new(),
            params: Params::Optional,
            children: Vec::new(),
        }
    }

    /// `AddCommand`: kept sorted by name, a new name before the first
    /// greater one.
    fn add(
        &mut self,
        name: &str,
        id: i32,
        short: &str,
        verbose: &str,
        params: Params,
    ) -> &mut Self {
        let at = self
            .children
            .iter()
            .position(|c| c.name.as_str() > name)
            .unwrap_or(self.children.len());
        self.children.insert(
            at,
            Command {
                name: name.into(),
                id,
                short: short.into(),
                verbose: verbose.into(),
                params,
                children: Vec::new(),
            },
        );
        &mut self.children[at]
    }

    fn child(&self, word: &str) -> Option<&Command> {
        let word = word.to_lowercase();
        self.children.iter().find(|c| c.name.to_lowercase() == word)
    }

    /// `CCommandTree::FindCommandId`. `line` has its words single spaced.
    pub fn find(&self, line: &str) -> Found {
        let mut node = self;
        let mut path: Vec<&str> = Vec::new();
        let mut rest = line;
        // The root's own args are whatever the last command left; nothing
        // reads them, since the root takes any.
        let mut args = String::new();
        loop {
            let word = rest.split(' ').next().unwrap_or("");
            match node.child(word) {
                Some(next) => {
                    rest = rest.split_once(' ').map_or("", |(_, r)| r).trim_start();
                    args = rest.to_string();
                    path.push(&next.name);
                    node = next;
                }
                None => break,
            }
        }
        let path = path.join(" ").to_lowercase();
        let id = if node.params == Params::Always && args.is_empty() {
            CMD_ERR_MUST_HAVE_PARAM
        } else if node.params == Params::Never && !args.is_empty() {
            CMD_ERR_NO_PARAM
        } else {
            node.id
        };
        let deprecated = id >= 0 && id & CMD_DEPRECATED != 0;
        Found {
            id: if deprecated { id & !CMD_DEPRECATED } else { id },
            args,
            path,
            deprecation: deprecated.then(|| node.verbose.clone()),
        }
    }

    fn full_name(path: &[&str]) -> String {
        path.join(" ")
    }

    /// `CCommandTree::PrintHelpFor`.
    pub fn help(&self, topic: &str) -> String {
        self.help_at(topic, &mut Vec::new())
    }

    fn help_at<'a>(&'a self, topic: &str, path: &mut Vec<&'a str>) -> String {
        let is_root = path.is_empty() && self.name.is_empty();
        let word = topic.split(' ').next().unwrap_or("").to_lowercase();
        let mut out = String::new();
        if !word.is_empty() {
            if let Some(next) = self.child(&word) {
                let rest = topic.split_once(' ').map_or("", |(_, r)| r).trim_start();
                path.push(&next.name);
                return next.help_at(rest, path);
            }
            if is_root {
                out += &format!("Unknown command '{topic}'.\n");
            } else {
                out += &format!(
                    "Unknown extension '{topic}' for the '{}' command.\n",
                    Self::full_name(path)
                );
            }
        } else {
            let full = Self::full_name(path);
            if !full.is_empty() {
                out += &format!("{}: {}\n", full.to_uppercase(), self.short);
                if !self.verbose.is_empty() {
                    out += "\n";
                    out += &self.verbose;
                }
            }
            match self.params {
                Params::Never => out += "\nThis command cannot have an argument.\n",
                Params::Always => out += "\nThis command must have an argument.\n",
                Params::Optional => {}
            }
            if self.id == CMD_ERR_INCOMPLETE {
                out += "\nThis command is incomplete, you must use one of the extensions below.\n";
            }
            if !self.children.is_empty() {
                let listed = |c: &&Command| !is_root || !(c.id >= 0 && c.id & CMD_DEPRECATED != 0);
                let width = self
                    .children
                    .iter()
                    .filter(listed)
                    .map(|c| c.name.chars().count())
                    .max()
                    .unwrap_or(0)
                    + 4;
                out += if is_root {
                    "Available commands:\n"
                } else {
                    "\nAvailable extensions:\n"
                };
                for c in self.children.iter().filter(listed) {
                    out += &format!("{:<width$}{}\n", c.name, c.short);
                }
                if is_root {
                    out += "\nAll commands are case insensitive.\nType 'help <command>' to get detailed info on <command>.\n";
                }
            }
        }
        out += "\n";
        out
    }
}

/// `CaMuleExternalConnector::OnInitCommandSet` and
/// `CamulecmdApp::OnInitCommandSet`.
pub fn command_set() -> Command {
    use Params::*;
    let mut root = Command::root();
    let r = &mut root;
    r.add(
        "Quit",
        CMD_ID_QUIT,
        "Exits from the application.",
        "",
        Optional,
    );
    r.add(
        "Exit",
        CMD_ID_QUIT,
        "Exits from the application.",
        "",
        Optional,
    );
    r.add(
        "Help",
        CMD_ID_HELP,
        "Show help.",
        "To get help on a command, type 'help <command>'.\nTo get the full command list type 'help'.\n",
        Optional,
    );

    r.add(
        "Status",
        id::STATUS,
        "Show short status information.",
        "Show connection status, current up/download speeds, etc.\n",
        Never,
    );
    r.add(
        "Statistics",
        id::STATTREE,
        "Show full statistics tree.",
        "Optionally, a number in the range 0-255 can be passed as an argument to this\ncommand, which tells how many entries of the client version subtrees should be\nshown. Passing 0 or omitting it means 'unlimited'.\n\nExample: 'statistics 5' will show only the top 5 versions for each client type.\n",
        Optional,
    );
    r.add(
        "Shutdown",
        id::SHUTDOWN,
        "Shut down aMule.",
        "Shut down the remote running core (amule/amuled).\nThis will also shut down the text client, since it is unusable without a\nrunning core.\n",
        Never,
    );

    let reload = r.add(
        "Reload",
        CMD_ERR_INCOMPLETE,
        "Reload the given object.",
        "",
        Never,
    );
    reload.add(
        "Shared",
        id::RELOAD_SHARED,
        "Reload shared files list.",
        "",
        Never,
    );
    let ipf = reload.add(
        "IPFilter",
        id::RELOAD_IPFILTER_LOCAL,
        "Reload IP filtering table.",
        "",
        Optional,
    );
    ipf.add(
        "File",
        id::RELOAD_IPFILTER_LOCAL,
        "Reload current IP filtering table.",
        "",
        Never,
    );
    ipf.add(
        "Net",
        id::RELOAD_IPFILTER_NET,
        "Update IP filtering table from URL.",
        "If URL is omitted the URL from the preferences is used.",
        Optional,
    );

    let connect = r.add(
        "Connect",
        id::CONNECT,
        "Connect to the network.",
        "This will connect to all networks that are enabled in Preferences.\nYou may also optionally specify a server address in IP:Port form, to connect to\nthat server only. The IP must be a dotted decimal IPv4 address,\nor a resolvable DNS name.",
        Optional,
    );
    connect.add("ED2K", id::CONNECT_ED2K, "Connect to eD2k only.", "", Never);
    connect.add("Kad", id::CONNECT_KAD, "Connect to Kad only.", "", Never);

    let disconnect = r.add(
        "Disconnect",
        id::DISCONNECT,
        "Disconnect from the network.",
        "This will disconnect from all networks that are currently connected.\n",
        Never,
    );
    disconnect.add(
        "ED2K",
        id::DISCONNECT_ED2K,
        "Disconnect from eD2k only.",
        "",
        Never,
    );
    disconnect.add(
        "Kad",
        id::DISCONNECT_KAD,
        "Disconnect from Kad only.",
        "",
        Never,
    );

    r.add(
        "Add",
        id::ADDLINK,
        "Add an eD2k or magnet link to core.",
        "The eD2k link to be added can be:\n*) a file link (ed2k://|file|...), it will be added to the download queue,\n*) a server link (ed2k://|server|...), it will be added to the server list,\n*) or a serverlist link, in which case all servers in the list will be added to the\n   server list.\n\nThe magnet link must contain the eD2k hash and file length.\n",
        Always,
    );

    let set = r.add(
        "Set",
        CMD_ERR_INCOMPLETE,
        "Set a preference value.",
        "",
        Never,
    );
    let ipf = set.add(
        "IPFilter",
        CMD_ERR_INCOMPLETE,
        "Set IP filtering preferences.",
        "",
        Never,
    );
    ipf.add(
        "On",
        id::SET_IPFILTER_ON,
        "Turn IP filtering on for both clients and servers.",
        "",
        Never,
    );
    ipf.add(
        "Off",
        id::SET_IPFILTER_OFF,
        "Turn IP filtering off for both clients and servers.",
        "",
        Never,
    );
    let clients = ipf.add(
        "Clients",
        CMD_ERR_INCOMPLETE,
        "Enable/Disable IP filtering for clients.",
        "",
        Never,
    );
    clients.add(
        "On",
        id::SET_IPFILTER_CLIENTS_ON,
        "Turn IP filtering on for clients.",
        "",
        Never,
    );
    clients.add(
        "Off",
        id::SET_IPFILTER_CLIENTS_OFF,
        "Turn IP filtering off for clients.",
        "",
        Never,
    );
    let servers = ipf.add(
        "Servers",
        CMD_ERR_INCOMPLETE,
        "Enable/Disable IP filtering for servers.",
        "",
        Never,
    );
    servers.add(
        "On",
        id::SET_IPFILTER_SERVERS_ON,
        "Turn IP filtering on for servers.",
        "",
        Never,
    );
    servers.add(
        "Off",
        id::SET_IPFILTER_SERVERS_OFF,
        "Turn IP filtering off for servers.",
        "",
        Never,
    );
    ipf.add(
        "Level",
        id::SET_IPFILTER_LEVEL,
        "Select IP filtering level.",
        "Valid filtering levels are in the range 0-255, and it's default (initial)\nvalue is 127.\n",
        Always,
    );
    let bw = set.add(
        "BwLimit",
        CMD_ERR_INCOMPLETE,
        "Set bandwidth limits.",
        "The value given to these commands has to be in kilobytes/sec.\n",
        Never,
    );
    bw.add(
        "Up",
        id::SET_BWLIMIT_UP,
        "Set upload bandwidth limit.",
        "The given value must be in kilobytes/sec.\n",
        Always,
    );
    bw.add(
        "Down",
        id::SET_BWLIMIT_DOWN,
        "Set download bandwidth limit.",
        "The given value must be in kilobytes/sec.\n",
        Always,
    );
    set.add(
        "Endgame",
        id::SET_ENDGAME,
        "Enable or disable endgame source rotation.",
        "The given value must be 1/ON (enable) or 0/OFF (disable).\n",
        Always,
    );

    let get = r.add(
        "Get",
        CMD_ERR_INCOMPLETE,
        "Get and display a preference value.",
        "",
        Never,
    );
    let ipf = get.add(
        "IPFilter",
        id::GET_IPFILTER,
        "Get IP filtering preferences.",
        "",
        Never,
    );
    let state = ipf.add(
        "State",
        id::GET_IPFILTER_STATE,
        "Get IP filtering state for both clients and servers.",
        "",
        Never,
    );
    state.add(
        "Clients",
        id::GET_IPFILTER_STATE_CLIENTS,
        "Get IP filtering state for clients only.",
        "",
        Never,
    );
    state.add(
        "Servers",
        id::GET_IPFILTER_STATE_SERVERS,
        "Get IP filtering state for servers only.",
        "",
        Never,
    );
    ipf.add(
        "Level",
        id::GET_IPFILTER_LEVEL,
        "Get IP filtering level.",
        "",
        Never,
    );
    get.add(
        "BwLimits",
        id::GET_BWLIMITS,
        "Get bandwidth limits.",
        "",
        Never,
    );
    get.add(
        "Endgame",
        id::GET_ENDGAME,
        "Get endgame source rotation state.",
        "",
        Never,
    );

    let search = r.add(
        "Search",
        id::SEARCH,
        "Execute a search.",
        "A search type has to be specified by giving the type:\n    GLOBAL\n    LOCAL\n    KAD\n    ALL: All networks (requires daemon support)\nExample: 'search kad file' will execute a kad search for \"file\".\n\nOptional filters can be added before, after, or interleaved with\nthe search keyword(s):\n    --type <Audio|Video|Image|Doc|Pro|Arc|Iso>\n    --extension <ext>      (alias: --ext)\n    --avail <N>            minimum number of sources\n    --min-size <N[KMG]>    smallest file size; K=1024, M=K*1024, G=M*1024\n    --max-size <N[KMG]>    largest file size; same suffixes\n    --min-bitrate <kbps>   whole number, 0-1000000\n    --min-duration <sec>   whole number, 0-86400\n    --codec <text> --title <text> --album <text> --artist <text>\nQuote media text values containing spaces.\nKad applies media filters; eD2k servers may ignore them.\nExample: 'search global linux iso --type Iso --min-size 100M' returns\nresults for \"linux iso\" of file-type Iso at least 100 MiB.\n",
        Always,
    );
    search.add(
        "global",
        id::SEARCH_GLOBAL,
        "Execute a global search.",
        "",
        Always,
    );
    search.add(
        "local",
        id::SEARCH_LOCAL,
        "Execute a local search",
        "",
        Always,
    );
    search.add("kad", id::SEARCH_KAD, "Execute a kad search", "", Always);
    search.add(
        "all",
        id::SEARCH_ALL,
        "Execute an eD2k and Kad search",
        "",
        Always,
    );
    search.add(
        "list",
        id::SEARCH_LIST,
        "List retained search IDs and queries.",
        "",
        Never,
    );
    search.add(
        "stop",
        id::SEARCH_STOP,
        "Stop a search, keeping its results.",
        "Requires a search ID from 'search list'.",
        Always,
    );
    search.add(
        "more",
        id::SEARCH_MORE,
        "Request more Kad search results.",
        "Requires a search ID from 'search list'. Further results are not guaranteed.",
        Always,
    );

    r.add(
        "Results",
        id::SEARCH_RESULTS,
        "Show the results of a search.",
        "Return the results of a search.\nOptionally takes a search id (from 'search ...'); with no id, returns the results of the most recently started search.\n",
        Optional,
    );
    r.add(
        "Progress",
        id::SEARCH_PROGRESS,
        "Show the progress of a search.",
        "Show the progress of a search.\nOptionally takes a search id; with no id, shows the progress of the most recently started search.\n",
        Optional,
    );
    r.add(
        "Download",
        id::DOWNLOAD,
        "Start downloading a file",
        "Give the number of a file as listed by 'results', optionally followed by a search id.\nWithout an id, the number refers to the last 'results' output, or to the most recently started search if nothing was listed yet.\nExample: 'download 12' downloads file 12 of the last results; 'download 12 3' downloads file 12 of search 3.\n",
        Always,
    );

    r.add("Pause", id::PAUSE, "Pause download.", "", Always);
    r.add("Resume", id::RESUME, "Resume download.", "", Always);
    r.add("Cancel", id::CANCEL, "Cancel download.", "", Always);

    let prio = r.add(
        "Priority",
        CMD_ERR_INCOMPLETE,
        "Set download priority.",
        "Set priority of a download to Low, Normal, High or Auto.\n",
        Always,
    );
    prio.add("Low", id::PRIORITY_LOW, "Set priority to low.", "", Always);
    prio.add(
        "Normal",
        id::PRIORITY_NORMAL,
        "Set priority to normal.",
        "",
        Always,
    );
    prio.add(
        "High",
        id::PRIORITY_HIGH,
        "Set priority to high.",
        "",
        Always,
    );
    prio.add(
        "Auto",
        id::PRIORITY_AUTO,
        "Set priority to auto.",
        "",
        Always,
    );

    let show = r.add(
        "Show",
        CMD_ERR_INCOMPLETE,
        "Show queues/lists.",
        "Show upload/download queue, server list or shared files list.\n",
        Always,
    );
    show.add("UL", id::SHOW_UL, "Show upload queue.", "", Never);
    show.add("DL", id::SHOW_DL, "Show download queue.", "", Never);
    show.add("Log", id::SHOW_LOG, "Show log.", "", Never);
    show.add("Servers", id::SHOW_SERVERS, "Show servers list.", "", Never);
    show.add(
        "Shared",
        id::SHOW_SHARED,
        "Show shared files list.",
        "",
        Never,
    );

    r.add("Reset", id::RESET_LOG, "Reset log.", "", Never);

    // Deprecated commands, kept for backwards compatibility only.
    let mut deprecated = |old: &str, id: i32, new: &str, params: Params| {
        r.add(
            old,
            id | CMD_DEPRECATED,
            &format!("Deprecated command, use '{new}' instead."),
            &format!(
                "This is a deprecated command, and may be removed in the future.\nUse '{new}' instead.\n"
            ),
            params,
        );
    };
    deprecated("Stats", id::STATUS, "Status", Never);
    deprecated("SetIPFilter", id::SET_IPFILTER, "Set IPFilter", Optional);
    deprecated(
        "GetIPLevel",
        id::GET_IPFILTER_LEVEL,
        "Get IPFilter Level",
        Never,
    );
    deprecated(
        "SetIPLevel",
        id::SET_IPFILTER_LEVEL,
        "Set IPFilter Level",
        Always,
    );
    deprecated(
        "IPLevel",
        id::SET_IPFILTER_LEVEL,
        "Get/Set IPFilter Level",
        Optional,
    );
    deprecated("Servers", id::SHOW_SERVERS, "Show Servers", Never);
    deprecated("GetBWLimits", id::GET_BWLIMITS, "Get BwLimits", Never);
    deprecated("SetUpBWLimit", id::SET_BWLIMIT_UP, "Set BwLimit Up", Always);
    deprecated(
        "SetDownBWLimit",
        id::SET_BWLIMIT_DOWN,
        "Set BwLimit Down",
        Always,
    );
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(line: &str) -> (i32, String, String) {
        let f = command_set().find(line);
        (f.id, f.args, f.path)
    }

    #[test]
    fn words_match_down_the_tree_case_insensitively() {
        assert_eq!(find("show dl"), (id::SHOW_DL, "".into(), "show dl".into()));
        assert_eq!(find("SHOW Dl"), (id::SHOW_DL, "".into(), "show dl".into()));
        assert_eq!(
            find("search kad linux iso"),
            (id::SEARCH_KAD, "linux iso".into(), "search kad".into())
        );
        assert_eq!(
            find("set ipfilter clients on"),
            (
                id::SET_IPFILTER_CLIENTS_ON,
                "".into(),
                "set ipfilter clients on".into()
            )
        );
        assert_eq!(find("help search").0, CMD_ID_HELP);
        assert_eq!(find("help search").1, "search");
    }

    #[test]
    fn arguments_are_checked_against_the_command() {
        assert_eq!(find("show").0, CMD_ERR_MUST_HAVE_PARAM);
        assert_eq!(find("show foo").0, CMD_ERR_INCOMPLETE);
        assert_eq!(find("status now").0, CMD_ERR_NO_PARAM);
        assert_eq!(find("search foo").0, id::SEARCH);
        assert_eq!(find("frobnicate").0, CMD_ERR_SYNTAX);
        assert_eq!(find("frobnicate").2, "");
        assert_eq!(find("get").0, CMD_ERR_INCOMPLETE);
    }

    #[test]
    fn deprecated_commands_run_the_new_one_and_say_so() {
        let f = command_set().find("servers");
        assert_eq!(f.id, id::SHOW_SERVERS);
        assert!(f
            .deprecation
            .unwrap()
            .contains("Use 'Show Servers' instead."));
        assert_eq!(command_set().find("iplevel").id, id::SET_IPFILTER_LEVEL);
    }

    #[test]
    fn help_lists_commands_in_name_order_without_deprecated_ones() {
        let h = command_set().help("");
        assert!(h.starts_with("Available commands:\nAdd           Add an eD2k"));
        assert!(!h.contains("GetBWLimits"));
        let names: Vec<&str> = h
            .lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(' ').next().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(h.ends_with("Type 'help <command>' to get detailed info on <command>.\n\n"));
    }

    #[test]
    fn help_for_a_command_and_its_extensions() {
        let h = command_set().help("show");
        assert_eq!(
            h,
            "SHOW: Show queues/lists.\n\nShow upload/download queue, server list or shared files list.\n\nThis command must have an argument.\n\nThis command is incomplete, you must use one of the extensions below.\n\nAvailable extensions:\nDL         Show download queue.\nLog        Show log.\nServers    Show servers list.\nShared     Show shared files list.\nUL         Show upload queue.\n\n"
        );
        assert_eq!(
            command_set().help("show xyz"),
            "Unknown extension 'xyz' for the 'Show' command.\n\n"
        );
        assert_eq!(command_set().help("xyz"), "Unknown command 'xyz'.\n\n");
    }
}
