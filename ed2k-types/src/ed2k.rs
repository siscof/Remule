// SPDX-License-Identifier: GPL-2.0-or-later
//! eD2k opcodes, flags and limits.
//!
//! Port of `include/protocol/ed2k/**`. Wire layouts in the variant docs are
//! aMule's own notes, kept verbatim where they say something.

use std::time::Duration;

const fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}
const fn mins(m: u64) -> Duration {
    Duration::from_secs(m * 60)
}
const fn hours(h: u64) -> Duration {
    Duration::from_secs(h * 3600)
}

// ------------------------------------------------------------ Constants.h ---

/// `PARTSIZE`: an eD2k part, the unit of the MD4 part hash.
pub const PARTSIZE: u64 = 9_728_000;
/// `BLOCKSIZE`: a transfer block, the unit of AICH hashing and requests.
pub const BLOCKSIZE: u32 = 184_320;
/// `EMBLOCKSIZE`: the same block size, as eMule names it.
pub const EMBLOCKSIZE: u32 = 184_320;
/// `OLD_MAX_FILE_SIZE`: `(2^32 - 1) / PARTSIZE * PARTSIZE`, ~4 GB, the limit
/// before large-file support.
pub const OLD_MAX_FILE_SIZE: u64 = 4_290_048_000;
/// `MAX_FILE_SIZE`: 2^38 bytes, 256 GB.
pub const MAX_FILE_SIZE: u64 = 0x40_0000_0000;

/// `RSAKEYSIZE`, in bits, for secure user identification.
pub const RSAKEYSIZE: u32 = 384;
/// `MAX_SOURCES_FILE_SOFT`
pub const MAX_SOURCES_FILE_SOFT: u32 = 500;
/// `MAX_SOURCES_FILE_UDP`
pub const MAX_SOURCES_FILE_UDP: u32 = 50;
/// `MAXFILECOMMENTLEN`
pub const MAXFILECOMMENTLEN: usize = 50;
/// `MIN_UP_CLIENTS_ALLOWED`: upload slots granted regardless of rate.
pub const MIN_UP_CLIENTS_ALLOWED: u32 = 2;
/// `MAX_UP_CLIENTS_ALLOWED`
pub const MAX_UP_CLIENTS_ALLOWED: u32 = 250;
/// `SOURCEEXCHANGE2_VERSION`: replaces the version sent in the SX1 MISC_OPTIONS flag.
pub const SOURCEEXCHANGE2_VERSION: u8 = 4;
/// `MAXCONPER5SEC`
pub const MAXCONPER5SEC: u32 = 50;
/// `RARE_FILE`: fewer sources than this makes a file rare.
pub const RARE_FILE: u32 = 50;
/// `MINCOMMONPENALTY`: for file source reasks.
pub const MINCOMMONPENALTY: u32 = 4;
/// `LOCALSERVER_SOURCE_REQUESTS`: source requests sent to the connected
/// server at once. Lugdunum 17.15 answers at most 7 per 28 s per IP.
pub const LOCALSERVER_SOURCE_REQUESTS: u32 = 5;
/// `LOCALSERVER_MS_PER_SOURCE_REQUEST`: then one per this interval.
pub const LOCALSERVER_SOURCE_REQUEST_INTERVAL: Duration = secs(20);
/// `INV_SERV_DESC_LEN`: an "invalid" string length for
/// `OP_SERVER_DESC_REQ`/`RES`.
pub const INV_SERV_DESC_LEN: u16 = 0xF0FF;
/// `OP_INCOMPLETE_SHARED_FILES`: the pseudo directory for shared part files
/// in `OP_ASKSHAREDDIRS` and friends (from eDonkeyHybrid, part of the protocol).
pub const INCOMPLETE_SHARED_FILES: &str = "!Incomplete Files";

/// `CONNECTION_TIMEOUT`
pub const CONNECTION_TIMEOUT: Duration = secs(40);
/// `SERVERREASKTIME`
pub const SERVERREASKTIME: Duration = Duration::from_millis(800_000);
/// `UDPSERVERREASKTIME`
pub const UDPSERVERREASKTIME: Duration = Duration::from_millis(1_300_000);
/// `SOURCECLIENTREASKS`
pub const SOURCECLIENTREASKS: Duration = mins(40);
/// `SOURCECLIENTREASKF`
pub const SOURCECLIENTREASKF: Duration = mins(5);
/// `UDPSERVERSTATTIME`
pub const UDPSERVERSTATTIME: Duration = secs(5);
/// `UDPSERVSTATREASKTIME`: 4.5 h. Stored in server.met as seconds since the epoch.
pub const UDPSERVSTATREASKTIME: Duration = secs(16_200);
/// `UDPSERVSTATMINREASKTIME`
pub const UDPSERVSTATMINREASKTIME: Duration = mins(20);
/// `ED2KREPUBLISHTIME`
pub const ED2KREPUBLISHTIME: Duration = mins(1);
/// `UDPMAXQUEUETIME`
pub const UDPMAXQUEUETIME: Duration = secs(30);
/// `DOWNLOADTIMEOUT`
pub const DOWNLOADTIMEOUT: Duration = secs(100);
/// `CONSERVTIMEOUT`: age limit for pending connection attempts.
pub const CONSERVTIMEOUT: Duration = secs(25);
/// `MIN_REQUESTTIME`
pub const MIN_REQUESTTIME: Duration = secs(590);
/// `MAX_PURGEQUEUETIME`
pub const MAX_PURGEQUEUETIME: Duration = hours(1);
/// `PURGESOURCESWAPSTOP`: how long swapping a source to a given file is forbidden.
pub const PURGESOURCESWAPSTOP: Duration = mins(15);
/// `CONNECTION_LATENCY`: latency allowed for responses.
pub const CONNECTION_LATENCY: Duration = Duration::from_millis(22_050);
/// `CLIENTBANTIME`
pub const CLIENTBANTIME: Duration = hours(2);
/// `TRACKED_CLEANUP_TIME`
pub const TRACKED_CLEANUP_TIME: Duration = hours(1);
/// `KEEPTRACK_TIME`: how long clients once in the upload queue are tracked.
pub const KEEPTRACK_TIME: Duration = hours(2);
/// `CLIENTLIST_CLEANUP_TIME`
pub const CLIENTLIST_CLEANUP_TIME: Duration = mins(34);

wire_enum! {
    /// Comparison operators in ed2k (and, since eMule 0.47a, Kad) search
    /// expressions (`enum ed2k_search_compare`).
    pub enum SearchCompare: u8 {
        /// `ED2K_SEARCH_OP_EQUAL` (eserver 16.45+)
        Equal = 0,
        /// `ED2K_SEARCH_OP_GREATER` (dserver)
        Greater = 1,
        /// `ED2K_SEARCH_OP_LESS` (dserver)
        Less = 2,
        /// `ED2K_SEARCH_OP_GREATER_EQUAL` (eserver 16.45+)
        GreaterEqual = 3,
        /// `ED2K_SEARCH_OP_LESS_EQUAL` (eserver 16.45+)
        LessEqual = 4,
        /// `ED2K_SEARCH_OP_NOTEQUAL`
        NotEqual = 5,
    }
}

// ------------------------------------------------------- ClientSoftware.h ---

wire_enum! {
    /// Client software as identified from its hello (`enum EClientSoftware`).
    pub enum ClientSoftware: u8 {
        /// `SO_EMULE`
        Emule = 0,
        /// `SO_CDONKEY`
        CDonkey = 1,
        /// `SO_LXMULE`
        LxMule = 2,
        /// `SO_AMULE`
        AMule = 3,
        /// `SO_SHAREAZA`
        Shareaza = 4,
        /// `SO_EMULEPLUS`
        EmulePlus = 5,
        /// `SO_HYDRANODE`
        Hydranode = 6,
        /// `SO_NEW2_MLDONKEY`
        New2MlDonkey = 0x0a,
        /// `SO_LPHANT`
        Lphant = 0x14,
        /// `SO_NEW2_SHAREAZA`
        New2Shareaza = 0x28,
        /// `SO_EDONKEYHYBRID`
        EdonkeyHybrid = 0x32,
        /// `SO_EDONKEY`
        Edonkey = 0x33,
        /// `SO_MLDONKEY`
        MlDonkey = 0x34,
        /// `SO_OLDEMULE`
        OldEmule = 0x35,
        /// `SO_UNKNOWN`
        Unknown = 0x36,
        /// `SO_NEW_SHAREAZA`
        NewShareaza = 0x44,
        /// `SO_NEW_MLDONKEY`
        NewMlDonkey = 0x98,
        /// `SO_COMPAT_UNK`
        CompatUnknown = 0xFF,
    }
}

// --------------------------------------------------- Client2Server/TCP.h ---

/// Client <-> server over TCP, protocol byte [`crate::Protocol::Edonkey`].
pub mod server_tcp {
    wire_enum! {
        /// `enum OP_ClientToServerTCP` (both directions).
        pub enum Opcode: u8 {
            /// `OP_LOGINREQUEST`: `<HASH 16><ID 4><PORT 2><1 Tag_set>`
            LoginRequest = 0x01,
            /// `OP_REJECT`: (null)
            Reject = 0x05,
            /// `OP_GETSERVERLIST`: (null), client -> server
            GetServerList = 0x14,
            /// `OP_OFFERFILES`: `<count 4>(<HASH 16><ID 4><PORT 2><1 Tag_set>)[count]`
            OfferFiles = 0x15,
            /// `OP_SEARCHREQUEST`: `<Query_Tree>`
            SearchRequest = 0x16,
            /// `OP_DISCONNECT` (not verified)
            Disconnect = 0x18,
            /// `OP_GETSOURCES`: `<HASH 16>`; v2 `<HASH 16><SIZE 4>` (17.3, mandatory
            /// on 17.8); v2large `<HASH 16><FILESIZE 4(0)><FILESIZE 8>` (17.9)
            GetSources = 0x19,
            /// `OP_SEARCH_USER`: `<Query_Tree>`
            SearchUser = 0x1A,
            /// `OP_CALLBACKREQUEST`: `<ID 4>`
            CallbackRequest = 0x1C,
            /// `OP_QUERY_MORE_RESULT`: (null)
            QueryMoreResult = 0x21,
            /// `OP_GETSOURCES_OBFU`
            GetSourcesObfu = 0x23,
            /// `OP_SERVERLIST`: `<count 1>(<IP 4><PORT 2>)[count]`, server -> client
            ServerList = 0x32,
            /// `OP_SEARCHRESULT`: `<count 4>(<HASH 16><ID 4><PORT 2><1 Tag_set>)[count]`
            SearchResult = 0x33,
            /// `OP_SERVERSTATUS`: `<USER 4><FILES 4>`
            ServerStatus = 0x34,
            /// `OP_CALLBACKREQUESTED`: `<IP 4><PORT 2>`
            CallbackRequested = 0x35,
            /// `OP_CALLBACK_FAIL`: (null, not verified)
            CallbackFail = 0x36,
            /// `OP_NAT_CALLBACKREQUESTED`: Lugdunum NAT callback forwarded over TCP,
            /// `<Seen IP 4><Seen UDP Port 2><Requester ID 4>[<obfuscation 17>]`
            NatCallbackRequested = 0x37,
            /// `OP_SERVERMESSAGE`: `<len 2><Message len>`
            ServerMessage = 0x38,
            /// `OP_IDCHANGE`: `<NEW_ID 4>`
            IdChange = 0x40,
            /// `OP_SERVERIDENT`: `<HASH 16><IP 4><PORT 2>{1 TAG_SET}`
            ServerIdent = 0x41,
            /// `OP_FOUNDSOURCES`: `<HASH 16><count 1>(<ID 4><PORT 2>)[count]`
            FoundSources = 0x42,
            /// `OP_USERS_LIST`: `<count 4>(<HASH 16><ID 4><PORT 2><1 Tag_set>)[count]`
            UsersList = 0x43,
            /// `OP_FOUNDSOURCES_OBFU`:
            /// `<HASH 16><count 1>(<ID 4><PORT 2><obf settings 1>(UserHash16 if obf&0x80))[count]`
            FoundSourcesObfu = 0x44,
            /// `OP_IPV6_UPDATE`: `<ipv6 address 16>`, all zeros withdraws. Sent only on a
            /// connection that received [`flags::IPV6_UPDATE`]. No reply.
            Ipv6Update = 0x63,
        }
    }

    /// Server TCP flags (`SRV_TCPFLG_*`), from `OP_SERVERIDENT` / the server list.
    pub mod flags {
        /// `SRV_TCPFLG_COMPRESSION`
        pub const COMPRESSION: u32 = 0x0000_0001;
        /// `SRV_TCPFLG_NEWTAGS`
        pub const NEWTAGS: u32 = 0x0000_0008;
        /// `SRV_TCPFLG_UNICODE`
        pub const UNICODE: u32 = 0x0000_0010;
        /// `SRV_TCPFLG_RELATEDSEARCH`
        pub const RELATEDSEARCH: u32 = 0x0000_0040;
        /// `SRV_TCPFLG_TYPETAGINTEGER`
        pub const TYPETAGINTEGER: u32 = 0x0000_0080;
        /// `SRV_TCPFLG_LARGEFILES`
        pub const LARGEFILES: u32 = 0x0000_0100;
        /// `SRV_TCPFLG_TCPOBFUSCATION`
        pub const TCPOBFUSCATION: u32 = 0x0000_0400;
        /// `SRV_TCPFLG_NATTRAVERSAL`: Lugdunum's NAT callback (eserver 17.15+).
        pub const NATTRAVERSAL: u32 = 0x0000_1000;
        /// `SRV_TCPFLG_IPV6`: speaks the IPv6 source extension.
        pub const IPV6: u32 = 0x0000_4000;
        /// `SRV_TCPFLG_IPV6_UPDATE`: accepts `OP_IPV6_UPDATE`; trusted only with [`IPV6`].
        pub const IPV6_UPDATE: u32 = 0x0000_8000;
        /// `SRV_TCPFLG_LOWID_HOLEPUNCH`: accepts `OP_LOWID_HOLEPUNCH_REQUEST` (ed2k-server 0.9.84+).
        pub const LOWID_HOLEPUNCH: u32 = 0x0002_0000;
        /// `SRV_TCPFLG_HOLEPUNCH_EXTENSION`: runs the hole-punch extension (ed2k-server 0.9.85).
        pub const HOLEPUNCH_EXTENSION: u32 = 0x0010_0000;
        /// `SRV_TCPFLG_IPV6_PROBE`: dials an address back before publishing it (0.9.86+).
        pub const IPV6_PROBE: u32 = 0x0040_0000;
    }
}

// --------------------------------------------------- Client2Server/UDP.h ---

/// Client <-> server over UDP, protocol byte [`crate::Protocol::Edonkey`].
pub mod server_udp {
    wire_enum! {
        /// `enum OP_ClientToServerUDP`.
        pub enum Opcode: u8 {
            /// `OP_GLOBSEARCHREQ3`: `<1 tag set><search_tree>`
            GlobSearchReq3 = 0x90,
            /// `OP_GLOBSEARCHREQ2`: `<search_tree>`
            GlobSearchReq2 = 0x92,
            /// `OP_GLOBGETSOURCES2`: `<HASH 16><FILESIZE 4>`; large files only:
            /// `<HASH 16><FILESIZE 4(0)><FILESIZE 8>` (17.8)
            GlobGetSources2 = 0x94,
            /// `OP_GLOBSERVSTATREQ`: (null)
            GlobServStatReq = 0x96,
            /// `OP_GLOBSERVSTATRES`: `<USER 4><FILES 4>`
            GlobServStatRes = 0x97,
            /// `OP_GLOBSEARCHREQ`: `<search_tree>`
            GlobSearchReq = 0x98,
            /// `OP_GLOBSEARCHRES`
            GlobSearchRes = 0x99,
            /// `OP_GLOBGETSOURCES`: `<HASH 16>`
            GlobGetSources = 0x9A,
            /// `OP_GLOBFOUNDSOURCES`
            GlobFoundSources = 0x9B,
            /// `OP_GLOBCALLBACKREQ`: `<IP 4><PORT 2><client_ID 4>`
            GlobCallbackReq = 0x9C,
            /// `OP_INVALID_LOWID`: `<ID 4>`
            InvalidLowId = 0x9E,
            /// `OP_SERVER_LIST_REQ`: `<IP 4><PORT 2>`
            ServerListReq = 0xA0,
            /// `OP_SERVER_LIST_RES`: `<count 1> (<ip 4><port 2>)[count]`
            ServerListRes = 0xA1,
            /// `OP_SERVER_DESC_REQ`: (null)
            ServerDescReq = 0xA2,
            /// `OP_SERVER_DESC_RES`: `<name_len 2><name name_len><desc_len 2 desc_en>`
            ServerDescRes = 0xA3,
            /// `OP_SERVER_LIST_REQ2`: (null)
            ServerListReq2 = 0xA4,
            /// `OP_NAT_CALLBACKREQUEST`: `<Target ID 4><Requester ID 4>`, client -> server
            NatCallbackRequest = 0xA6,
            /// `OP_NAT_CALLBACKREQUESTED_UDP`:
            /// `<Seen IP 4><Seen UDP Port 2><Requester ID 4>[<obfuscation 17>]`
            NatCallbackRequestedUdp = 0xA7,
        }
    }

    /// Server UDP flags (`SRV_UDPFLG_*`).
    pub mod flags {
        /// `SRV_UDPFLG_EXT_GETSOURCES`
        pub const EXT_GETSOURCES: u32 = 0x0000_0001;
        /// `SRV_UDPFLG_EXT_GETFILES`
        pub const EXT_GETFILES: u32 = 0x0000_0002;
        /// `SRV_UDPFLG_NEWTAGS`
        pub const NEWTAGS: u32 = 0x0000_0008;
        /// `SRV_UDPFLG_UNICODE`
        pub const UNICODE: u32 = 0x0000_0010;
        /// `SRV_UDPFLG_EXT_GETSOURCES2`
        pub const EXT_GETSOURCES2: u32 = 0x0000_0020;
        /// `SRV_UDPFLG_LARGEFILES`
        pub const LARGEFILES: u32 = 0x0000_0100;
        /// `SRV_UDPFLG_UDPOBFUSCATION`
        pub const UDPOBFUSCATION: u32 = 0x0000_0200;
        /// `SRV_UDPFLG_TCPOBFUSCATION`
        pub const TCPOBFUSCATION: u32 = 0x0000_0400;
        /// `SRV_UDPFLG_FOREIGN_NAT_CALLBACK`: takes a NAT callback request from a
        /// client logged in to another server (ed2k-server 0.9.86).
        pub const FOREIGN_NAT_CALLBACK: u32 = 0x0010_0000;
    }
}

// --------------------------------------------------- Client2Client/TCP.h ---

/// Client <-> client over TCP.
pub mod client_tcp {
    wire_enum! {
        /// Protocol byte [`crate::Protocol::Edonkey`] (`enum ED2KStandardClientTCP`).
        pub enum Standard: u8 {
            /// `OP_HELLO`: `0x10<HASH 16><ID 4><PORT 2><1 Tag_set>`
            Hello = 0x01,
            /// `OP_SENDINGPART`: `<HASH 16><start 4><end 4><Data len:(end-start)>`
            SendingPart = 0x46,
            /// `OP_REQUESTPARTS`: `<HASH 16><start[3] 4*3><end[3] 4*3>`
            RequestParts = 0x47,
            /// `OP_FILEREQANSNOFIL`: `<HASH 16>`
            FileReqAnsNoFil = 0x48,
            /// `OP_END_OF_DOWNLOAD`: `<HASH 16>` (not sent by aMule)
            EndOfDownload = 0x49,
            /// `OP_ASKSHAREDFILES`: (null)
            AskSharedFiles = 0x4A,
            /// `OP_ASKSHAREDFILESANSWER`: `<count 4>(<HASH 16><ID 4><PORT 2><1 Tag_set>)[count]`
            AskSharedFilesAnswer = 0x4B,
            /// `OP_HELLOANSWER`: `<HASH 16><ID 4><PORT 2><1 Tag_set><SERVER_IP 4><SERVER_PORT 2>`
            HelloAnswer = 0x4C,
            /// `OP_CHANGE_CLIENT_ID`: `<ID_old 4><ID_new 4>` (not sent by aMule)
            ChangeClientId = 0x4D,
            /// `OP_MESSAGE`: `<len 2><Message len>`
            Message = 0x4E,
            /// `OP_SETREQFILEID`: `<HASH 16>`
            SetReqFileId = 0x4F,
            /// `OP_FILESTATUS`: `<HASH 16><count 2><status(bit array) len:((count+7)/8)>`
            FileStatus = 0x50,
            /// `OP_HASHSETREQUEST`: `<HASH 16>`
            HashsetRequest = 0x51,
            /// `OP_HASHSETANSWER`: `<count 2><HASH[count] 16*count>`
            HashsetAnswer = 0x52,
            /// `OP_STARTUPLOADREQ`: `<HASH 16>`
            StartUploadReq = 0x54,
            /// `OP_ACCEPTUPLOADREQ`: (null)
            AcceptUploadReq = 0x55,
            /// `OP_CANCELTRANSFER`: (null)
            CancelTransfer = 0x56,
            /// `OP_OUTOFPARTREQS`: (null)
            OutOfPartReqs = 0x57,
            /// `OP_REQUESTFILENAME`: `<HASH 16>`
            RequestFilename = 0x58,
            /// `OP_REQFILENAMEANSWER`: `<HASH 16><len 4><NAME len>`
            ReqFilenameAnswer = 0x59,
            /// `OP_CHANGE_SLOT`: `<HASH 16>` (not sent by aMule)
            ChangeSlot = 0x5B,
            /// `OP_QUEUERANK`: `<value 4>` (not sent by aMule)
            QueueRank = 0x5C,
            /// `OP_ASKSHAREDDIRS`: (null)
            AskSharedDirs = 0x5D,
            /// `OP_ASKSHAREDFILESDIR`: `<len 2><Directory len>`
            AskSharedFilesDir = 0x5E,
            /// `OP_ASKSHAREDDIRSANS`: `<count 4>(<len 2><Directory len>)[count]`
            AskSharedDirsAns = 0x5F,
            /// `OP_ASKSHAREDFILESDIRANS`: `<len 2><Directory len><count 4>(<HASH 16><ID 4><PORT 2><1 Tag_set>)[count]`
            AskSharedFilesDirAns = 0x60,
            /// `OP_ASKSHAREDDENIEDANS`: (null)
            AskSharedDeniedAns = 0x61,
            /// `OP_CHANGE_CLIENT_IP`: `<new IPv6 16>`
            ChangeClientIp = 0xAC,
        }
    }

    wire_enum! {
        /// Protocol byte [`crate::Protocol::Emule`] or [`crate::Protocol::Packed`]
        /// (`enum ED2KExtendedClientTCP`, plus `enum Ed2kTCPOpcodesForKademliaV2`
        /// from `kad2/Client2Client/TCP.h`, which shares the namespace).
        pub enum Extended: u8 {
            /// `OP_EMULEINFO`
            EmuleInfo = 0x01,
            /// `OP_EMULEINFOANSWER`
            EmuleInfoAnswer = 0x02,
            /// `OP_COMPRESSEDPART`
            CompressedPart = 0x40,
            /// `OP_QUEUERANKING`: `<RANK 2>`
            QueueRanking = 0x60,
            /// `OP_FILEDESC`: `<len 2><NAME len>`
            FileDesc = 0x61,
            /// `OP_VERIFYUPSREQ` (never used)
            VerifyUpsReq = 0x71,
            /// `OP_VERIFYUPSANSWER` (never used)
            VerifyUpsAnswer = 0x72,
            /// `OP_UDPVERIFYUPREQ` (never used)
            UdpVerifyUpReq = 0x73,
            /// `OP_UDPVERIFYUPA` (never used)
            UdpVerifyUpA = 0x74,
            /// `OP_REQUESTSOURCES`: `<HASH 16>`
            RequestSources = 0x81,
            /// `OP_ANSWERSOURCES`
            AnswerSources = 0x82,
            /// `OP_REQUESTSOURCES2`: `<HASH 16>`
            RequestSources2 = 0x83,
            /// `OP_ANSWERSOURCES2`
            AnswerSources2 = 0x84,
            /// `OP_PUBLICKEY`: `<len 1><pubkey len>`
            PublicKey = 0x85,
            /// `OP_SIGNATURE`: v1 `<len 1><signature len>`; v2 `<len 1><signature len><sigIPused 1>`
            Signature = 0x86,
            /// `OP_SECIDENTSTATE`: `<state 1><rndchallenge 4>`
            SecIdentState = 0x87,
            /// `OP_REQUESTPREVIEW`: `<HASH 16>` (not sent by aMule)
            RequestPreview = 0x90,
            /// `OP_PREVIEWANSWER`: `<HASH 16><frames 1>{frames * <len 4><frame len>}` (not sent by aMule)
            PreviewAnswer = 0x91,
            /// `OP_MULTIPACKET`
            MultiPacket = 0x92,
            /// `OP_MULTIPACKETANSWER`
            MultiPacketAnswer = 0x93,
            /// `OP_PUBLICIP_REQ`
            PublicIpReq = 0x97,
            /// `OP_PUBLICIP_ANSWER`
            PublicIpAnswer = 0x98,
            /// `OP_CALLBACK`: `<HASH 16><HASH 16><uint 16>`
            Callback = 0x99,
            /// `OP_REASKCALLBACKTCP`
            ReaskCallbackTcp = 0x9A,
            /// `OP_AICHREQUEST`: `<HASH 16><uint16><HASH aichhashlen>`
            AichRequest = 0x9B,
            /// `OP_AICHANSWER`: `<HASH 16><uint16><HASH aichhashlen> <data>`
            AichAnswer = 0x9C,
            /// `OP_AICHFILEHASHANS`
            AichFileHashAns = 0x9D,
            /// `OP_AICHFILEHASHREQ`
            AichFileHashReq = 0x9E,
            /// `OP_BUDDYPING`
            BuddyPing = 0x9F,
            /// `OP_BUDDYPONG`
            BuddyPong = 0xA0,
            /// `OP_COMPRESSEDPART_I64`: `<HASH 16><start 8><size 4><Data len:size>`
            CompressedPartI64 = 0xA1,
            /// `OP_SENDINGPART_I64`: `<HASH 16><start 8><end 8><Data len:(end-start)>`
            SendingPartI64 = 0xA2,
            /// `OP_REQUESTPARTS_I64`: `<HASH 16><start[3] 8*3><end[3] 8*3>`
            RequestPartsI64 = 0xA3,
            /// `OP_MULTIPACKET_EXT`
            MultiPacketExt = 0xA4,
            /// `OP_CHATCAPTCHAREQ`
            ChatCaptchaReq = 0xA5,
            /// `OP_CHATCAPTCHARES`
            ChatCaptchaRes = 0xA6,
            /// `OP_FWCHECKUDPREQ`: `<Inter_Port 2><Extern_Port 2><KadUDPKey 4>`
            /// (Kad version >= 6)
            FwCheckUdpReq = 0xA7,
            /// `OP_KAD_FWTCPCHECK_ACK`: (null/reserved), replaces
            /// `KADEMLIA_FIREWALLED_ACK_RES` (Kad version >= 7)
            KadFwTcpCheckAck = 0xA8,
        }
    }
}

// --------------------------------------------------- Client2Client/UDP.h ---

/// Client <-> client over UDP, protocol byte [`crate::Protocol::Emule`].
pub mod client_udp {
    wire_enum! {
        /// `enum ED2KExtendedClientUDP`, plus `OP_DIRECTCALLBACKREQ` from
        /// `kad2/Client2Client/UDP.h`, which shares the namespace.
        pub enum Opcode: u8 {
            /// `OP_REASKFILEPING`: `<HASH 16>`
            ReaskFilePing = 0x90,
            /// `OP_REASKACK`: `<RANK 2>`
            ReaskAck = 0x91,
            /// `OP_FILENOTFOUND`: (null)
            FileNotFound = 0x92,
            /// `OP_QUEUEFULL`: (null)
            QueueFull = 0x93,
            /// `OP_REASKCALLBACKUDP`
            ReaskCallbackUdp = 0x94,
            /// `OP_DIRECTCALLBACKREQ`: `<TCPPort 2><Userhash 16><ConnectionOptions 1>`
            DirectCallbackReq = 0x95,
            /// `OP_HOLEPUNCH`: (null). An empty peer punch; the recipient dials uTP back.
            /// Only in aMule builds with `ENABLE_NATT_SERVER_COORDINATION`.
            HolePunch = 0xA1,
            /// `OP_NATT_SOURCE_ECHO`: `<IP 4><PORT 2>`, to a punched peer whose datagram
            /// no key decoded. Only in aMule builds with uTP or QUIC transport.
            NattSourceEcho = 0xAB,
            /// `OP_PORTTEST`: connection test.
            PortTest = 0xFE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(
            OLD_MAX_FILE_SIZE,
            (u64::from(u32::MAX) / PARTSIZE) * PARTSIZE
        );
        assert_eq!(MAX_FILE_SIZE, 1 << 38);
        // 53 AICH blocks per part, the last one short.
        assert_eq!(PARTSIZE.div_ceil(u64::from(BLOCKSIZE)), 53);
        assert_eq!(UDPSERVSTATREASKTIME, Duration::from_secs_f64(4.5 * 3600.0));
    }

    #[test]
    fn spot_values() {
        assert_eq!(
            server_tcp::Opcode::try_from(0x01),
            Ok(server_tcp::Opcode::LoginRequest)
        );
        assert_eq!(u8::from(server_tcp::Opcode::FoundSourcesObfu), 0x44);
        assert_eq!(u8::from(server_udp::Opcode::NatCallbackRequestedUdp), 0xA7);
        assert_eq!(
            client_tcp::Standard::try_from(0xAC),
            Ok(client_tcp::Standard::ChangeClientIp)
        );
        assert_eq!(
            client_tcp::Extended::try_from(0xA8),
            Ok(client_tcp::Extended::KadFwTcpCheckAck)
        );
        assert_eq!(u8::from(client_udp::Opcode::PortTest), 0xFE);
        assert_eq!(
            ClientSoftware::try_from(0x98),
            Ok(ClientSoftware::NewMlDonkey)
        );
        assert!(client_tcp::Standard::try_from(0x53).is_err());
    }
}
