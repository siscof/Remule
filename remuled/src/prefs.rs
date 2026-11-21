// SPDX-License-Identifier: GPL-2.0-or-later
//! The preferences over external connections (`CEC_Prefs_Packet`,
//! ECSpecialMuleTags.cpp; the `EC_OP_SET_PREFERENCES` case of
//! ExternalConn.cpp; the keys and defaults of Preferences.cpp).
//!
//! One table names every preference a client can read: its page, its EC tag,
//! how it is encoded (a flag present when on, or a value), the `amule.conf`
//! key and default it is kept under, and whether a client may change it.
//! `EC_OP_GET_PREFERENCES` is answered from it, page by page, as aMule
//! answers; `EC_OP_SET_PREFERENCES` changes what it carries and writes it to
//! `amule.conf`, with aMule's rules: a TCP port past 65532 falls back to
//! 4662, a low upload limit caps the download limit (`CheckUlDlRatio`), a
//! new P2P port must be free, and the incoming and temp folders may only move
//! inside the roots of `allowed-remote-dirs.dat`. Daemon-local settings (the
//! online signature folder, following symlinks) are shown but not changed,
//! and the EC listener's are read-only.
//!
//! What a change does to the running daemon: the nick, the speed limits,
//! the ports, the folders and the rest are saved for the next start;
//! remuled does not yet apply them while it runs, and many (the message
//! filter, the server list options, the core tweaks) are kept for aMule's
//! sake, remuled not having those features yet.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use remule_ec::codes::*;
use remule_ec::{Packet, Tag};
use tracing::{info, warn};

/// How a preference travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Enc {
    /// An empty tag present when on; set by value at `EC_DETAIL_FULL`.
    Flag,
    /// A number, booleans as 0 and 1.
    Int,
    Str,
}

/// How the value in `amule.conf` relates to the one EC carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conv {
    Plain,
    /// A flag stored as its opposite (`UDPEnable` for `CONN_UDP_DISABLE`).
    Invert,
    /// EC carries the stored value times this (minutes as milliseconds,
    /// `FileBufferSizePref` in 15000-byte steps).
    Scale(u64),
    /// `GeoIPSource`: stored by name, carried as its number.
    GeoipSource,
}

/// Who may change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Rw,
    /// Told, never changed over EC.
    Ro,
    /// Daemon-local: told, a change ignored (aMule's `Apply` ignores it).
    Local,
    /// Set, never told (a password).
    WriteOnly,
}

#[derive(Clone, Copy, Debug)]
enum Def {
    I(u64),
    S(&'static str),
}

/// One preference.
#[derive(Clone, Copy, Debug)]
struct Row {
    page: u16,
    tag: u16,
    enc: Enc,
    /// The `amule.conf` key; empty for a value the daemon supplies.
    key: &'static str,
    def: Def,
    conv: Conv,
    access: Access,
}

const fn row(page: u16, tag: u16, enc: Enc, key: &'static str, def: Def, access: Access) -> Row {
    Row {
        page,
        tag,
        enc,
        key,
        def,
        conv: Conv::Plain,
        access,
    }
}

const fn conv(mut r: Row, c: Conv) -> Row {
    r.conv = c;
    r
}

use Access::{Local, Ro, Rw, WriteOnly};
use Def::{I, S};
use Enc::{Flag, Int, Str};

const GENERAL: u16 = EC_TAG_PREFS_GENERAL;
const CONN: u16 = EC_TAG_PREFS_CONNECTIONS;
const MSG: u16 = EC_TAG_PREFS_MESSAGEFILTER;
const REMOTE: u16 = EC_TAG_PREFS_REMOTECTRL;
const OSIG: u16 = EC_TAG_PREFS_ONLINESIG;
const SERVERS: u16 = EC_TAG_PREFS_SERVERS;
const FILES: u16 = EC_TAG_PREFS_FILES;
const DIRS: u16 = EC_TAG_PREFS_DIRECTORIES;
const SECURITY: u16 = EC_TAG_PREFS_SECURITY;
const TWEAKS: u16 = EC_TAG_PREFS_CORETWEAKS;
const KAD: u16 = EC_TAG_PREFS_KADEMLIA;
const GEOIP: u16 = EC_TAG_PREFS_IP2COUNTRY;

/// `DEFAULT_TCP_PORT`.
pub const DEFAULT_TCP_PORT: u16 = 4662;

/// Every preference, page by page in `CEC_Prefs_Packet`'s order, each page
/// in the order aMule adds its tags.
const ROWS: &[Row] = &[
    // General.
    row(
        GENERAL,
        EC_TAG_USER_NICK,
        Str,
        "/eMule/Nick",
        S("https://amule-org.github.io"),
        Rw,
    ),
    row(
        GENERAL,
        EC_TAG_USER_HOST,
        Str,
        "/eMule/YourHostname",
        S(""),
        Rw,
    ),
    row(
        GENERAL,
        EC_TAG_GENERAL_CHECK_NEW_VERSION,
        Int,
        "/eMule/NewVersionCheck",
        I(1),
        Rw,
    ),
    // Built in: the version check; not built in: UPnP.
    row(
        GENERAL,
        EC_TAG_GENERAL_VERSION_CHECK_AVAILABLE,
        Int,
        "",
        I(1),
        Ro,
    ),
    row(GENERAL, EC_TAG_GENERAL_UPNP_AVAILABLE, Int, "", I(0), Ro),
    // Connections.
    row(
        CONN,
        EC_TAG_CONN_UL_CAP,
        Int,
        "/eMule/UploadCapacity",
        I(2500),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_DL_CAP,
        Int,
        "/eMule/DownloadCapacity",
        I(12500),
        Rw,
    ),
    row(CONN, EC_TAG_CONN_MAX_UL, Int, "/eMule/MaxUpload", I(0), Rw),
    row(
        CONN,
        EC_TAG_CONN_MAX_DL,
        Int,
        "/eMule/MaxDownload",
        I(0),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_SLOT_ALLOCATION,
        Int,
        "/eMule/SlotAllocation",
        I(10),
        Rw,
    ),
    row(CONN, EC_TAG_CONN_TCP_PORT, Int, "/eMule/Port", I(4662), Rw),
    row(
        CONN,
        EC_TAG_CONN_UDP_PORT,
        Int,
        "/eMule/UDPPort",
        I(4672),
        Rw,
    ),
    conv(
        row(
            CONN,
            EC_TAG_CONN_UDP_DISABLE,
            Flag,
            "/eMule/UDPEnable",
            I(1),
            Rw,
        ),
        Conv::Invert,
    ),
    row(
        CONN,
        EC_TAG_CONN_MAX_FILE_SOURCES,
        Int,
        "/eMule/MaxSourcesPerFile",
        I(300),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_MAX_CONN,
        Int,
        "/eMule/MaxConnections",
        I(500),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_AUTOCONNECT,
        Flag,
        "/eMule/Autoconnect",
        I(1),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_RECONNECT,
        Flag,
        "/eMule/Reconnect",
        I(1),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_NETWORK_ED2K,
        Flag,
        "/eMule/ConnectToED2K",
        I(1),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_NETWORK_KADEMLIA,
        Flag,
        "/eMule/ConnectToKad",
        I(1),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_BIND_ADDRESS,
        Str,
        "/eMule/Address",
        S(""),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_BIND_INTERFACE,
        Str,
        "/eMule/NetworkInterface",
        S(""),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_PROXY_ENABLE,
        Int,
        "/Proxy/ProxyEnableProxy",
        I(0),
        Rw,
    ),
    row(CONN, EC_TAG_PROXY_TYPE, Int, "/Proxy/ProxyType", I(0), Rw),
    row(CONN, EC_TAG_PROXY_HOST, Str, "/Proxy/ProxyName", S(""), Rw),
    row(
        CONN,
        EC_TAG_PROXY_PORT,
        Int,
        "/Proxy/ProxyPort",
        I(1080),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_PROXY_AUTH,
        Int,
        "/Proxy/ProxyEnablePassword",
        I(0),
        Rw,
    ),
    row(CONN, EC_TAG_PROXY_USER, Str, "/Proxy/ProxyUser", S(""), Rw),
    row(
        CONN,
        EC_TAG_PROXY_PASSWORD,
        Str,
        "/Proxy/ProxyPassword",
        S(""),
        WriteOnly,
    ),
    row(
        CONN,
        EC_TAG_CONN_UPNP_ENABLED,
        Int,
        "/eMule/UPnPEnabled",
        I(0),
        Rw,
    ),
    row(
        CONN,
        EC_TAG_CONN_UPNP_TCP_PORT,
        Int,
        "/eMule/UPnPTCPPort",
        I(50000),
        Rw,
    ),
    // Message filter.
    row(
        MSG,
        EC_TAG_MSGFILTER_ENABLED,
        Flag,
        "/eMule/FilterMessages",
        I(1),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_ALL,
        Flag,
        "/eMule/FilterAllMessages",
        I(0),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_FRIENDS,
        Flag,
        "/eMule/MessagesFromFriendsOnly",
        I(0),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_SECURE,
        Flag,
        "/eMule/MessageFromValidSourcesOnly",
        I(1),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_BY_KEYWORD,
        Flag,
        "/eMule/FilterWordMessages",
        I(0),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_KEYWORDS,
        Str,
        "/eMule/MessageFilter",
        S(""),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_SHOW_IN_LOG,
        Flag,
        "/eMule/ShowMessagesInLog",
        I(1),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_FILTER_COMMENTS,
        Flag,
        "/eMule/FilterComments",
        I(0),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_COMMENT_KEYWORDS,
        Str,
        "/eMule/CommentFilter",
        S(""),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_ADVANCED,
        Int,
        "/eMule/AdvancedSpamFilter",
        I(1),
        Rw,
    ),
    row(
        MSG,
        EC_TAG_MSGFILTER_CAPTCHA,
        Int,
        "/eMule/MessageUseCaptchas",
        I(1),
        Rw,
    ),
    // Remote controls: the web server's and amuleapi's settings, then the
    // EC listener, read-only (it takes them only at a restart).
    row(
        REMOTE,
        EC_TAG_WEBSERVER_PORT,
        Int,
        "/WebServer/Port",
        I(4711),
        Rw,
    ),
    row(
        REMOTE,
        EC_TAG_WEBSERVER_AUTORUN,
        Flag,
        "/WebServer/Enabled",
        I(0),
        Rw,
    ),
    row(
        REMOTE,
        EC_TAG_WEBSERVER_USEGZIP,
        Flag,
        "/WebServer/UseGzip",
        I(1),
        Rw,
    ),
    row(
        REMOTE,
        EC_TAG_WEBSERVER_REFRESH,
        Int,
        "/WebServer/PageRefreshTime",
        I(120),
        Rw,
    ),
    row(
        REMOTE,
        EC_TAG_WEBSERVER_TEMPLATE,
        Str,
        "/WebServer/Template",
        S(""),
        Rw,
    ),
    row(
        REMOTE,
        EC_TAG_AMULEAPI_PORT,
        Int,
        "/AmuleApi/HttpPort",
        I(4713),
        Rw,
    ),
    row(
        REMOTE,
        EC_TAG_AMULEAPI_AUTORUN,
        Flag,
        "/AmuleApi/Enabled",
        I(0),
        Rw,
    ),
    row(
        REMOTE,
        EC_TAG_AMULEAPI_BIND,
        Str,
        "/AmuleApi/BindAddress",
        S("127.0.0.1"),
        Rw,
    ),
    row(REMOTE, EC_TAG_EXTERNALCONN_ENABLED, Int, "", I(1), Ro),
    row(
        REMOTE,
        EC_TAG_EXTERNALCONN_ADDRESS,
        Str,
        "/ExternalConnect/ECAddress",
        S("127.0.0.1"),
        Ro,
    ),
    row(
        REMOTE,
        EC_TAG_EXTERNALCONN_INTERFACE,
        Str,
        "/ExternalConnect/ECNetworkInterface",
        S(""),
        Ro,
    ),
    row(
        REMOTE,
        EC_TAG_EXTERNALCONN_PORT,
        Int,
        "/ExternalConnect/ECPort",
        I(4712),
        Ro,
    ),
    row(
        REMOTE,
        EC_TAG_EXTERNALCONN_UPNP,
        Int,
        "/ExternalConnect/UPnPECEnabled",
        I(0),
        Ro,
    ),
    row(
        REMOTE,
        EC_TAG_EXTERNALCONN_REQUIRE_ENCRYPTION,
        Int,
        "",
        I(1),
        Ro,
    ),
    row(REMOTE, EC_TAG_EXTERNALCONN_PASSWD_SET, Int, "", I(1), Ro),
    // Online signature.
    row(
        OSIG,
        EC_TAG_ONLINESIG_ENABLED,
        Flag,
        "/eMule/OnlineSignature",
        I(0),
        Rw,
    ),
    row(
        OSIG,
        EC_TAG_ONLINESIG_DIRECTORY,
        Str,
        "/eMule/OSDirectory",
        S(""),
        Local,
    ),
    row(
        OSIG,
        EC_TAG_ONLINESIG_UPDATE,
        Int,
        "/eMule/OnlineSignatureUpdate",
        I(5),
        Rw,
    ),
    // Servers (the URL list is `addresses.dat`, told apart).
    row(
        SERVERS,
        EC_TAG_SERVERS_REMOVE_DEAD,
        Flag,
        "/eMule/RemoveDeadServer",
        I(1),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_DEAD_SERVER_RETRIES,
        Int,
        "/eMule/DeadServerRetry",
        I(3),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_AUTO_UPDATE,
        Flag,
        "/eMule/Serverlist",
        I(0),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_ADD_FROM_SERVER,
        Flag,
        "/eMule/AddServerListFromServer",
        I(0),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_ADD_FROM_CLIENT,
        Flag,
        "/eMule/AddServerListFromClient",
        I(0),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_USE_SCORE_SYSTEM,
        Flag,
        "/eMule/Scoresystem",
        I(1),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_SMART_ID_CHECK,
        Flag,
        "/eMule/SmartIdCheck",
        I(1),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_SAFE_SERVER_CONNECT,
        Flag,
        "/eMule/SafeServerConnect",
        I(0),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_AUTOCONN_STATIC_ONLY,
        Flag,
        "/eMule/AutoConnectStaticOnly",
        I(0),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_MANUAL_HIGH_PRIO,
        Flag,
        "/eMule/ManualHighPrio",
        I(0),
        Rw,
    ),
    row(
        SERVERS,
        EC_TAG_SERVERS_ED2K_ACCELERATED_PUBLICATION,
        Int,
        "/eMule/ED2KAcceleratedPublication",
        I(1),
        Rw,
    ),
    // Files. No mmap: its capability tag is left out, so it cannot be set.
    row(
        FILES,
        EC_TAG_FILES_ICH_ENABLED,
        Flag,
        "/eMule/ICH",
        I(1),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_AICH_TRUST,
        Flag,
        "/eMule/AICHTrust",
        I(0),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_NEW_PAUSED,
        Flag,
        "/eMule/AddNewFilesPaused",
        I(0),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_NEW_AUTO_DL_PRIO,
        Flag,
        "/eMule/DAPPref",
        I(1),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_PREVIEW_PRIO,
        Flag,
        "/eMule/PreviewPrio",
        I(0),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_ENDGAME,
        Flag,
        "/eMule/Endgame",
        I(1),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_NEW_AUTO_UL_PRIO,
        Flag,
        "/eMule/UAPPref",
        I(1),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_START_NEXT_PAUSED,
        Flag,
        "/eMule/StartNextFile",
        I(0),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_RESUME_SAME_CAT,
        Flag,
        "/eMule/StartNextFileSameCat",
        I(0),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_SAVE_SOURCES,
        Flag,
        "/ExternalConnect/UseSrcSeeds",
        I(0),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_ALLOC_FULL_SIZE,
        Flag,
        "/eMule/AllocateFullFile",
        I(0),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_CHECK_FREE_SPACE,
        Flag,
        "/eMule/CheckDiskspace",
        I(1),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_MIN_FREE_SPACE,
        Int,
        "/eMule/MinFreeDiskSpace",
        I(500),
        Rw,
    ),
    row(
        FILES,
        EC_TAG_FILES_SHARED_REVERIFY_DAYS,
        Int,
        "/eMule/SharedFileReverifyDays",
        I(0),
        Rw,
    ),
    conv(
        row(
            FILES,
            EC_TAG_FILES_CREATE_NORMAL,
            Flag,
            "/eMule/CreateSparseFiles",
            I(1),
            Rw,
        ),
        Conv::Invert,
    ),
    row(
        FILES,
        EC_TAG_FILES_MEDIA_METADATA_ENABLED,
        Flag,
        "/MediaMetadata/Enabled",
        I(1),
        Rw,
    ),
    // No media probe is built in.
    row(
        FILES,
        EC_TAG_FILES_MEDIA_METADATA_AVAILABLE,
        Int,
        "",
        I(0),
        Ro,
    ),
    row(
        FILES,
        EC_TAG_FILES_START_NEXT_ALPHA,
        Flag,
        "/eMule/StartNextFileAlpha",
        I(0),
        Rw,
    ),
    // Directories (the folder lists are told apart).
    row(
        DIRS,
        EC_TAG_DIRECTORIES_INCOMING,
        Str,
        "/eMule/IncomingDir",
        S(""),
        Rw,
    ),
    row(
        DIRS,
        EC_TAG_DIRECTORIES_TEMP,
        Str,
        "/eMule/TempDir",
        S(""),
        Rw,
    ),
    row(
        DIRS,
        EC_TAG_DIRECTORIES_SHARE_HIDDEN,
        Flag,
        "/eMule/ShareHiddenFiles",
        I(0),
        Rw,
    ),
    row(
        DIRS,
        EC_TAG_DIRECTORIES_AUTO_RESCAN,
        Flag,
        "/eMule/AutoRescanSharedDirs",
        I(1),
        Rw,
    ),
    row(
        DIRS,
        EC_TAG_DIRECTORIES_FOLLOW_SYMLINKS,
        Flag,
        "/eMule/FollowSymlinksInShares",
        I(1),
        Local,
    ),
    row(
        DIRS,
        EC_TAG_DIRECTORIES_EXCLUDE_PATTERNS,
        Str,
        "/eMule/ExcludeSharePatterns",
        S(EXCLUDE_DEFAULT),
        Rw,
    ),
    row(
        DIRS,
        EC_TAG_DIRECTORIES_EXCLUDE_REGEX,
        Int,
        "/eMule/ExcludeSharePatternsUseRegex",
        I(0),
        Rw,
    ),
    // Security.
    row(
        SECURITY,
        EC_TAG_SECURITY_CAN_SEE_SHARES,
        Int,
        "/eMule/SeeShare",
        I(2),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_CLIENTS,
        Flag,
        "/ExternalConnect/IpFilterClients",
        I(1),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_SERVERS,
        Flag,
        "/ExternalConnect/IpFilterServers",
        I(1),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_AUTO_UPDATE,
        Flag,
        "/eMule/IPFilterAutoLoad",
        I(0),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_UPDATE_URL,
        Str,
        "/eMule/IPFilterURL",
        S("https://upd.emule-security.org/ipfilter.zip"),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_LEVEL,
        Int,
        "/eMule/FilterLevel",
        I(127),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_FILTER_LAN,
        Flag,
        "/eMule/FilterLanIPs",
        I(1),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_SECURITY_USE_SECIDENT,
        Flag,
        "/ExternalConnect/UseSecIdent",
        I(1),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_SECURITY_OBFUSCATION_SUPPORTED,
        Flag,
        "/Obfuscation/IsClientCryptLayerSupported",
        I(1),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_SECURITY_OBFUSCATION_REQUESTED,
        Flag,
        "/Obfuscation/IsCryptLayerRequested",
        I(1),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_SECURITY_OBFUSCATION_REQUIRED,
        Flag,
        "/Obfuscation/IsClientCryptLayerRequired",
        I(0),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_PARANOID,
        Flag,
        "/eMule/ParanoidFiltering",
        I(1),
        Rw,
    ),
    row(
        SECURITY,
        EC_TAG_IPFILTER_SYSTEM,
        Flag,
        "/eMule/IPFilterSystem",
        I(0),
        Rw,
    ),
    // Core tweaks. No debug categories: their tags are left out.
    row(
        TWEAKS,
        EC_TAG_CORETW_MAX_CONN_PER_FIVE,
        Int,
        "/eMule/MaxConnectionsPerFiveSeconds",
        I(50),
        Rw,
    ),
    row(
        TWEAKS,
        EC_TAG_CORETW_VERBOSE,
        Flag,
        "/eMule/VerboseDebug",
        I(0),
        Rw,
    ),
    conv(
        row(
            TWEAKS,
            EC_TAG_CORETW_FILEBUFFER,
            Int,
            "/eMule/FileBufferSizePref",
            I(16),
            Rw,
        ),
        Conv::Scale(15000),
    ),
    row(
        TWEAKS,
        EC_TAG_CORETW_WRITE_BUFFER_LIMIT_MIB,
        Int,
        "/eMule/WriteBufferLimitMiB",
        I(128),
        Rw,
    ),
    conv(
        row(
            TWEAKS,
            EC_TAG_CORETW_UL_QUEUE,
            Int,
            "/eMule/QueueSizePref",
            I(50),
            Rw,
        ),
        Conv::Scale(100),
    ),
    conv(
        row(
            TWEAKS,
            EC_TAG_CORETW_SRV_KEEPALIVE_TIMEOUT,
            Int,
            "/eMule/ServerKeepAliveTimeout",
            I(0),
            Rw,
        ),
        Conv::Scale(60000),
    ),
    row(
        TWEAKS,
        EC_TAG_CORETW_KAD_MAX_SEARCHES,
        Int,
        "/eMule/KadMaxSourceSearches",
        I(30),
        Rw,
    ),
    conv(
        row(
            TWEAKS,
            EC_TAG_CORETW_KAD_REASK_MS,
            Int,
            "/eMule/KadSourceReaskMinutes",
            I(30),
            Rw,
        ),
        Conv::Scale(60000),
    ),
    conv(
        row(
            TWEAKS,
            EC_TAG_CORETW_SOURCE_REASK_MS,
            Int,
            "/eMule/SourceReaskMinutes",
            I(15),
            Rw,
        ),
        Conv::Scale(60000),
    ),
    // Kademlia.
    row(
        KAD,
        EC_TAG_KADEMLIA_UPDATE_URL,
        Str,
        "/eMule/KadNodesUrl",
        S("https://upd.emule-security.org/nodes.dat"),
        Rw,
    ),
    row(
        KAD,
        EC_TAG_KADEMLIA_PROTOCOL10,
        Int,
        "/eMule/KadProtocol10",
        I(1),
        Rw,
    ),
    row(
        KAD,
        EC_TAG_KADEMLIA_STRICT_AICH_PUBLISHERS,
        Int,
        "/eMule/KadStrictAichPublishers",
        I(0),
        Rw,
    ),
    // GeoIP: the settings; no resolver is built in.
    row(GEOIP, EC_TAG_IP2COUNTRY_SUPPORTED, Int, "", I(0), Ro),
    row(
        GEOIP,
        EC_TAG_IP2COUNTRY_ENABLED,
        Int,
        "/eMule/GeoIPEnabled",
        I(1),
        Rw,
    ),
    conv(
        row(
            GEOIP,
            EC_TAG_IP2COUNTRY_SOURCE,
            Int,
            "/eMule/GeoIPSource",
            S("dbip"),
            Rw,
        ),
        Conv::GeoipSource,
    ),
    row(
        GEOIP,
        EC_TAG_IP2COUNTRY_CUSTOM_URL,
        Str,
        "/eMule/GeoIPCustomUrl",
        S(""),
        Rw,
    ),
    row(
        GEOIP,
        EC_TAG_IP2COUNTRY_MAXMIND_LICENSE,
        Str,
        "/eMule/GeoIPMaxMindLicense",
        S(""),
        Rw,
    ),
    row(
        GEOIP,
        EC_TAG_IP2COUNTRY_AUTO_UPDATE,
        Int,
        "/eMule/GeoIPAutoUpdate",
        I(1),
        Rw,
    ),
];

/// `ShareExclude::kDefaultPatterns`.
const EXCLUDE_DEFAULT: &str = ".DS_Store|._*|.Spotlight-V100|.Trashes|.fseventsd|\
    .DocumentRevisions-V100|.TemporaryItems|.apdisk|Thumbs.db|ehthumbs.db|desktop.ini|.directory|\
    *.doc|*.docx|*.docm|*.dot|*.dotx|*.dotm|*.xls|*.xlsx|*.xlsm|*.xlsb|*.xlt|*.xltx|*.xltm|*.xlam|\
    *.ppt|*.pptx|*.pptm|*.pot|*.potx|*.potm|*.pps|*.ppsx|*.ppsm|\
    *.odt|*.ott|*.ods|*.ots|*.odp|*.otp|*.odg|*.otg|*.odf|*.odb|*.rtf|*.csv|*.tsv";

/// The pages, as `EC_PREFS_*` selects them, in `CEC_Prefs_Packet`'s order.
const PAGES: &[(u32, u16)] = &[
    (EC_PREFS_GENERAL, GENERAL),
    (EC_PREFS_CONNECTIONS, CONN),
    (EC_PREFS_MESSAGEFILTER, MSG),
    (EC_PREFS_REMOTECONTROLS, REMOTE),
    (EC_PREFS_ONLINESIG, OSIG),
    (EC_PREFS_SERVERS, SERVERS),
    (EC_PREFS_FILES, FILES),
    (EC_PREFS_DIRECTORIES, DIRS),
    (EC_PREFS_SECURITY, SECURITY),
    (EC_PREFS_CORETWEAKS, TWEAKS),
    (EC_PREFS_KADEMLIA, KAD),
    (EC_PREFS_IP2COUNTRY, GEOIP),
];

/// A preference's value: numbers and flags as numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Val {
    I(u64),
    S(String),
}

/// What the daemon supplies rather than `amule.conf`.
#[derive(Clone, Debug, Default)]
pub struct Runtime {
    pub user_hash: [u8; 16],
    /// The folders in use, as defaults when `amule.conf` names none.
    pub incoming: String,
    pub temp: String,
    /// The shared folders, the incoming folder not among them.
    pub shared: Vec<String>,
    /// The default connection limit when `amule.conf` names none.
    pub max_connections: u16,
    /// The P2P ports the daemon listens on: free for it to go back to.
    pub listening: (u16, u16),
}

/// The preferences, as the daemon keeps them.
#[derive(Clone, Debug, Default)]
pub struct PrefStore {
    config: PathBuf,
    values: HashMap<u16, Val>,
    user_hash: [u8; 16],
    shared: Vec<String>,
    /// `allowed-remote-dirs.dat`.
    allowed_roots: Vec<String>,
    /// `addresses.dat`: where server lists are fetched from.
    server_urls: Vec<String>,
    /// The P2P ports in use (TCP, UDP).
    listening: (u16, u16),
}

fn rows_of(page: u16) -> impl Iterator<Item = &'static Row> {
    ROWS.iter().filter(move |r| r.page == page)
}

fn find(tag: u16) -> Option<&'static Row> {
    ROWS.iter().find(|r| r.tag == tag)
}

/// `GetGeoIPSource`.
fn geoip_source(name: &str) -> u64 {
    match name {
        "maxmind" => 1,
        "custom" => 2,
        _ => 0,
    }
}

fn geoip_name(n: u64) -> &'static str {
    match n {
        1 => "maxmind",
        2 => "custom",
        _ => "dbip",
    }
}

/// Non-empty lines, trimmed, `#` comments left out.
fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

impl PrefStore {
    /// Read from `amule.conf` (`conf`) and the config directory's lists.
    pub fn load(
        config: &Path,
        conf: &ed2k_formats::amule_conf::ConfFile,
        runtime: &Runtime,
    ) -> PrefStore {
        let mut values = HashMap::new();
        for r in ROWS {
            let stored = (!r.key.is_empty()).then(|| conf.get(r.key)).flatten();
            let v = match (r.conv, r.def) {
                (Conv::GeoipSource, S(d)) => Val::I(geoip_source(stored.unwrap_or(d))),
                (_, S(d)) => Val::S(stored.unwrap_or(d).to_owned()),
                (c, I(d)) => {
                    let n = stored
                        .and_then(ed2k_formats::amule_conf::parse_long)
                        .map_or(d, |v| v as u64);
                    Val::I(match c {
                        Conv::Invert => u64::from(n == 0),
                        Conv::Scale(k) => n.saturating_mul(k),
                        _ => n,
                    })
                }
            };
            values.insert(r.tag, v);
        }
        let mut s = PrefStore {
            config: config.to_owned(),
            values,
            user_hash: runtime.user_hash,
            shared: runtime.shared.clone(),
            allowed_roots: read_lines(&config.join("allowed-remote-dirs.dat")),
            server_urls: read_lines(&config.join("addresses.dat")),
            listening: runtime.listening,
        };
        // What is in use where amule.conf says nothing.
        let fill = |s: &mut PrefStore, tag: u16, key: &str, v: Val| {
            if conf.get(key).is_none() {
                s.values.insert(tag, v);
            }
        };
        fill(
            &mut s,
            EC_TAG_DIRECTORIES_INCOMING,
            "/eMule/IncomingDir",
            Val::S(runtime.incoming.clone()),
        );
        fill(
            &mut s,
            EC_TAG_DIRECTORIES_TEMP,
            "/eMule/TempDir",
            Val::S(runtime.temp.clone()),
        );
        fill(
            &mut s,
            EC_TAG_ONLINESIG_DIRECTORY,
            "/eMule/OSDirectory",
            Val::S(config.display().to_string()),
        );
        if runtime.max_connections != 0 {
            fill(
                &mut s,
                EC_TAG_CONN_MAX_CONN,
                "/eMule/MaxConnections",
                Val::I(runtime.max_connections.into()),
            );
        }
        s
    }

    fn int(&self, tag: u16) -> u64 {
        match self.values.get(&tag) {
            Some(Val::I(n)) => *n,
            _ => 0,
        }
    }

    fn text(&self, tag: u16) -> String {
        match self.values.get(&tag) {
            Some(Val::S(s)) => s.clone(),
            _ => String::new(),
        }
    }

    /// `IPFilterURL`.
    pub fn ipfilter_url(&self) -> String {
        self.text(EC_TAG_IPFILTER_UPDATE_URL)
    }

    /// `SetIPFilterURL`: an update's URL is remembered (`CIPFilter::Update`).
    pub fn set_ipfilter_url(&mut self, url: &str) {
        if self.text(EC_TAG_IPFILTER_UPDATE_URL) != url {
            self.values
                .insert(EC_TAG_IPFILTER_UPDATE_URL, Val::S(url.to_owned()));
            self.save(&[EC_TAG_IPFILTER_UPDATE_URL]);
        }
    }

    pub fn nick(&self) -> String {
        self.text(EC_TAG_USER_NICK)
    }

    pub fn check_new_version(&self) -> bool {
        self.int(EC_TAG_GENERAL_CHECK_NEW_VERSION) != 0
    }

    /// `/eMule/UploadCapacity` and `DownloadCapacity`, kB/s, for the graphs.
    pub fn capacities(&self) -> (u64, u64) {
        (self.int(EC_TAG_CONN_UL_CAP), self.int(EC_TAG_CONN_DL_CAP))
    }

    /// A page as `CEC_Prefs_Packet` builds it.
    fn page(&self, page: u16) -> Tag {
        let mut t = Tag::empty(page);
        for r in rows_of(page) {
            if r.access == WriteOnly {
                continue;
            }
            let tag = match (r.enc, self.values.get(&r.tag)) {
                (Flag, Some(Val::I(n))) => (*n != 0).then(|| Tag::empty(r.tag)),
                (Int, Some(Val::I(n))) => Some(Tag::int(r.tag, *n)),
                (Str, Some(Val::S(s))) => Some(Tag::string(r.tag, s)),
                _ => None,
            };
            t.children.extend(tag);
            // What aMule adds after a row.
            match r.tag {
                EC_TAG_USER_NICK => t.children.push(Tag::hash(EC_TAG_USER_HASH, self.user_hash)),
                EC_TAG_DIRECTORIES_TEMP => t
                    .children
                    .push(counted(EC_TAG_DIRECTORIES_SHARED, &self.shared)),
                EC_TAG_SERVERS_AUTO_UPDATE => {
                    let mut l = Tag::empty(EC_TAG_SERVERS_URL_LIST);
                    l.children = self
                        .server_urls
                        .iter()
                        .map(|u| Tag::string(EC_TAG_STRING, u))
                        .collect();
                    t.children.push(l);
                }
                EC_TAG_SERVERS_MANUAL_HIGH_PRIO => t.children.push(Tag::string(
                    EC_TAG_SERVERS_UPDATE_URL,
                    self.server_urls.first().map_or("", String::as_str),
                )),
                EC_TAG_DIRECTORIES_EXCLUDE_REGEX => t.children.push(counted(
                    EC_TAG_DIRECTORIES_ALLOWED_ROOTS,
                    &self.allowed_roots,
                )),
                _ => {}
            }
        }
        t
    }

    /// `EC_OP_GET_PREFERENCES`: the pages `EC_TAG_SELECT_PREFS` asks for. A
    /// single category is not told, as aMule tells none until there are two.
    pub fn reply(&self, req: &Packet) -> Packet {
        let selection = req.tag(EC_TAG_SELECT_PREFS).map_or(0, Tag::as_int) as u32;
        let mut out = Packet::new(EC_OP_SET_PREFERENCES).with_detail(EC_DETAIL_UPDATE);
        for &(bit, page) in PAGES {
            if selection & bit != 0 {
                out = out.with(self.page(page));
            }
        }
        out
    }

    /// `EC_OP_SET_PREFERENCES`: what the request carries applied and saved,
    /// as `CEC_Prefs_Packet::Apply` and the handler around it do. `NOOP`, or
    /// `FAILED` with what was refused; the rest is applied either way.
    pub fn apply(&mut self, req: &Packet) -> Packet {
        // amulegui and amuleapi send FULL: every flag carried by value.
        let full = req
            .tag(EC_TAG_DETAIL_LEVEL)
            .is_none_or(|t| t.as_int() == u64::from(EC_DETAIL_FULL));
        let old_tcp = self.int(EC_TAG_CONN_TCP_PORT);
        let old_udp = self.int(EC_TAG_CONN_UDP_PORT);
        let mut changed: Vec<u16> = Vec::new();
        let mut refused: Vec<String> = Vec::new();

        for page in &req.tags {
            if !PAGES.iter().any(|&(_, p)| p == page.name) {
                continue;
            }
            if page.name == SERVERS {
                if let Some(list) = page.child(EC_TAG_SERVERS_URL_LIST) {
                    let urls: Vec<String> = list
                        .children
                        .iter()
                        .filter(|t| t.name == EC_TAG_STRING)
                        .map(Tag::as_str)
                        .collect();
                    self.set_server_urls(urls);
                } else if let Some(url) = page.child(EC_TAG_SERVERS_UPDATE_URL) {
                    self.set_server_urls(vec![url.as_str()]);
                }
            }
            for r in rows_of(page.name) {
                if !matches!(r.access, Rw | WriteOnly) {
                    continue;
                }
                let v = match (r.enc, page.child(r.tag)) {
                    // A value when sent by value, else its presence.
                    (Flag, Some(t)) => Val::I(u64::from(!t.is_int() || t.as_int() != 0)),
                    (Flag, None) if !full => Val::I(0),
                    (Int, Some(t)) => Val::I(t.as_int()),
                    (Str, Some(t)) => Val::S(t.as_str()),
                    _ => continue,
                };
                let v = match (r.tag, v) {
                    // `SetPort`: the server UDP socket is TCP+3.
                    (EC_TAG_CONN_TCP_PORT, Val::I(p)) if p + 3 > 65535 => {
                        warn!("TCP port can't be higher than 65532 due to server UDP socket being TCP+3");
                        info!("Default port will be used ({DEFAULT_TCP_PORT})");
                        Val::I(DEFAULT_TCP_PORT.into())
                    }
                    (EC_TAG_CONN_SLOT_ALLOCATION, Val::I(n)) => Val::I(n.max(1)),
                    (EC_TAG_DIRECTORIES_INCOMING | EC_TAG_DIRECTORIES_TEMP, Val::S(dir)) => {
                        let current = self.text(r.tag);
                        if same_dir(&dir, &current) {
                            continue;
                        }
                        match self.allowed(&dir) {
                            Some(canonical) => Val::S(canonical),
                            None => {
                                refused.push(dir);
                                continue;
                            }
                        }
                    }
                    (_, v) => v,
                };
                if self.values.get(&r.tag) != Some(&v) {
                    self.values.insert(r.tag, v);
                    changed.push(r.tag);
                }
            }
        }
        // `CheckUlDlRatio`: a low upload limit caps the download limit.
        if changed.contains(&EC_TAG_CONN_MAX_UL) || changed.contains(&EC_TAG_CONN_MAX_DL) {
            let (up, down) = (self.int(EC_TAG_CONN_MAX_UL), self.int(EC_TAG_CONN_MAX_DL));
            let capped = ul_dl_ratio(up, down);
            if capped != down {
                self.values.insert(EC_TAG_CONN_MAX_DL, Val::I(capped));
                changed.push(EC_TAG_CONN_MAX_DL);
            }
        }
        // The new P2P ports must be free (`RebindP2PSockets`); if not, the
        // old ones are kept and the rest stays applied.
        let mut network_message = String::new();
        let (tcp, udp) = (
            self.int(EC_TAG_CONN_TCP_PORT),
            self.int(EC_TAG_CONN_UDP_PORT),
        );
        if tcp != old_tcp || udp != old_udp {
            // The ports the daemon holds are its own to keep.
            let (tcp_in_use, udp_in_use) = self.listening;
            let check_tcp = tcp != old_tcp && tcp != u64::from(tcp_in_use);
            let check_udp = udp != old_udp && udp != u64::from(udp_in_use);
            if let Err(e) = ports_free(tcp as u16, udp as u16, check_tcp, check_udp) {
                self.values.insert(EC_TAG_CONN_TCP_PORT, Val::I(old_tcp));
                self.values.insert(EC_TAG_CONN_UDP_PORT, Val::I(old_udp));
                changed.retain(|&t| t != EC_TAG_CONN_TCP_PORT && t != EC_TAG_CONN_UDP_PORT);
                warn!("{e}");
                network_message = e;
            }
        }
        self.save(&changed);

        let failed = !network_message.is_empty() || !refused.is_empty();
        let mut out = Packet::new(if failed { EC_OP_FAILED } else { EC_OP_NOOP });
        let mut message = network_message;
        if !refused.is_empty() {
            for dir in &refused {
                out = out.with(Tag::string(EC_TAG_SHAREDDIR_REJECTED, dir).with(Tag::int(
                    EC_TAG_SHAREDDIR_ERROR,
                    SHAREDDIR_ERR_OUTSIDE_ROOTS,
                )));
            }
            if !message.is_empty() {
                message.push('\n');
            }
            message.push_str(
                "One or more folders were outside the allowed remote directories and were left \
                 unchanged.",
            );
        }
        if !message.is_empty() {
            out = out.with(Tag::string(EC_TAG_STRING, &message));
        }
        out
    }

    /// `IsRemoteDirChangeAllowed`: inside one of the allowed roots, as its
    /// canonical path. None allowed when no roots are configured.
    fn allowed(&self, dir: &str) -> Option<String> {
        let canonical = canonical(Path::new(dir));
        self.allowed_roots
            .iter()
            .any(|root| canonical.starts_with(self::canonical(Path::new(root))))
            .then(|| canonical.display().to_string())
    }

    fn set_server_urls(&mut self, urls: Vec<String>) {
        if urls == self.server_urls {
            return;
        }
        let mut text = urls.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        match std::fs::write(self.config.join("addresses.dat"), text) {
            Ok(()) => self.server_urls = urls,
            Err(e) => warn!("addresses.dat: {e}"),
        }
    }

    /// The changed preferences written to `amule.conf`.
    fn save(&self, changed: &[u16]) {
        // A store not read from a config directory keeps its changes.
        if changed.is_empty() || self.config.as_os_str().is_empty() {
            return;
        }
        let r = crate::config::update_conf(&self.config, |conf| {
            for &tag in changed {
                let Some(r) = find(tag) else { continue };
                if r.key.is_empty() {
                    continue;
                }
                let text = match (r.conv, self.values.get(&tag)) {
                    (Conv::GeoipSource, Some(Val::I(n))) => geoip_name(*n).to_owned(),
                    (Conv::Invert, Some(Val::I(n))) => u64::from(*n == 0).to_string(),
                    (Conv::Scale(k), Some(Val::I(n))) => (n / k).to_string(),
                    (_, Some(Val::I(n))) => n.to_string(),
                    (_, Some(Val::S(s))) => s.clone(),
                    (_, None) => continue,
                };
                conf.set(r.key, &text);
            }
        });
        if let Err(e) = r {
            warn!("{e}");
        }
    }
}

/// `EC_SHAREDDIR_ERR_OUTSIDE_ROOTS`.
pub const SHAREDDIR_ERR_OUTSIDE_ROOTS: u64 = 3;

/// `CheckUlDlRatio`: below 4 kB/s up, at most 3 times as much down; below
/// 10, 4 times. 0 is no limit.
pub fn ul_dl_ratio(up: u64, down: u64) -> u64 {
    if up == 0 {
        down
    } else if up < 4 && (up * 3 < down || down == 0) {
        up * 3
    } else if (4..10).contains(&up) && (up * 4 < down || down == 0) {
        up * 4
    } else {
        down
    }
}

/// Whether the P2P sockets could listen on these ports: TCP, the client
/// UDP port and the server UDP port (TCP+3).
fn ports_free(tcp: u16, udp: u16, tcp_changed: bool, udp_changed: bool) -> Result<(), String> {
    if tcp_changed {
        std::net::TcpListener::bind(("0.0.0.0", tcp))
            .map_err(|e| format!("Could not listen on TCP port {tcp}: {e}"))?;
        let server_udp = tcp.saturating_add(3);
        std::net::UdpSocket::bind(("0.0.0.0", server_udp))
            .map_err(|e| format!("Could not listen on UDP port {server_udp}: {e}"))?;
    }
    if udp_changed && udp != 0 {
        std::net::UdpSocket::bind(("0.0.0.0", udp))
            .map_err(|e| format!("Could not listen on UDP port {udp}: {e}"))?;
    }
    Ok(())
}

/// A count with each item as a string child (`EC_TAG_DIRECTORIES_SHARED`).
fn counted(name: u16, items: &[String]) -> Tag {
    let mut t = Tag::int(name, items.len() as u64);
    t.children = items
        .iter()
        .map(|s| Tag::string(EC_TAG_STRING, s))
        .collect();
    t
}

fn canonical(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_owned())
}

/// `CPath::IsSameDir`.
fn same_dir(a: &str, b: &str) -> bool {
    a == b || canonical(Path::new(a)) == canonical(Path::new(b))
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read(path)
        .map(|b| lines(&String::from_utf8_lossy(&b)))
        .unwrap_or_default()
}

/// `allowed-remote-dirs.dat` (`LoadAllowedRemoteDirRoots`): one folder a
/// line, blank lines and `#` comments left out.
pub fn allowed_remote_dirs(dir: &Path) -> Vec<String> {
    read_lines(&dir.join("allowed-remote-dirs.dat"))
}
