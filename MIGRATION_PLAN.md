# aMule → Rust migration plan (remule)

Status: **draft** · Started: 2026-11-10 · Source of truth for the C++ side: `C:\workspace\amule` (aMule-org, `688c51eb7`)

## 1. Where we start

### aMule (C++, the reference)

About 1,100 C++ files, roughly 220k lines in `src/` (not counting the bundled web assets). Five executables are built from it (`src/CMakeLists.txt`):

| Binary | What it is |
|---|---|
| `amuled` | Headless daemon: the whole P2P core, no GUI |
| `amule` | Monolithic wxWidgets GUI + core |
| `amulegui` | Remote GUI that talks to `amuled` over **EC** (External Connection protocol) |
| `amulecmd` | CLI client over EC |
| `ed2k` | ed2k:// link handler |

Main areas, roughly by size:

| Area | Where | Notes |
|---|---|---|
| Core client logic | `src/*.cpp` (BaseClient, PartFile, DownloadQueue, UploadQueue, SharedFileList, KnownFile, ServerConnect, …) | Biggest and most entangled part; mixed with wx types |
| GUI | `src/*Dlg.cpp`, `*Ctrl.cpp`, `*Wnd.cpp`, … | wxWidgets. **Not migrated** (see §2) |
| Kademlia | `src/kademlia/{kademlia,net,routing,utils}` | ~16k lines, fairly self-contained |
| EC protocol | `src/libs/ec/cpp`, `ExternalConn.cpp` (5.4k) | Lets GUIs and CLIs drive the daemon |
| Common libs | `src/libs/common` | Paths, formatting, MD5, rate limiting |
| Web | `src/webapi` (backend + static JS), `src/webserver`, `src/libwebcommon` | |
| Protocol constants | `src/include/protocol/{ed2k,kad,kad2}`, `src/include/tags` | Port these first, mechanically |
| Extras | `extern/libutp`, QUIC transport, `mediaprobe`, `geoip`, `utils/*` (wxCas, aLinkCreator, fileview) | Later or never |
| Tests | `unittests/tests` (~350 files: muleunit C++ + Python integration), `curl-tests`, `browser-tests` | A source of test vectors |

### remule (Rust, today)

A fresh Cargo-only workspace (history restarted on 2026-11-10; no code inherited from earlier projects), licensed GPLv2+ like aMule:

| Crate | Contents |
|---|---|
| `ed2k-types` | eD2k/Kad protocol constants: opcodes, tag ids, flags, limits (step 1.1); `Md4Hash` and the Kad id `UInt128` (step 1.2) |
| `remule-cli` | The `remule` command-line tool: `remule inspect`, `remule hash` |
| `ed2k-formats` | On-disk formats (phase 2): `server.met`, `known.met`, `.part.met`, `known2_64.met`, `clients.met`, `cryptkey.dat`, `nodes.dat`, IP filter, `addresses.dat`/`staticservers.dat`, `canceled.met`, `emfriends.met`, `amule.conf` |
| `ed2k-hash` | eD2k MD4 and AICH hashing, streaming (phase 3) |
| `ed2k-crypto` | RC4 obfuscation (TCP, UDP), secure ident (RSA), credits, sans IO (phase 4) |
| `remule-net` | tokio runtime: framed TCP with obfuscation, UDP, bandwidth throttling, connection limits (phase 5) |
| `ed2k-server` | client↔server protocol: login, search, sources, server list, UDP ping; sans-IO session and async client (phase 6) |
| `ed2k-kad` | Kademlia (Kad2): routing table (arena tree), packets, lookups, keyword and source searches; sans-IO node and tokio driver (phase 7) |
| `ed2k-peer` | client↔client protocol (phase 8): hello and eMule info handshake, file requests and multipackets, part status, hash sets, upload requests, block requests and data blocks; sans-IO packets and the download session |
| `remule-core` | client core (phase 8 onwards): gap lists, block reservation and chunk ranking, part files on disk (`.part` / `.part.met`, buffered writes, part hash checks, completion); later the download and upload queues |
| `ed2k-codec` | Little-endian reader/writer and eD2k strings (step 1.3); tags in eD2k and Kad encodings (step 1.4); packet framing and zlib packing (step 1.5) |
| `remule-ec` | Client side of the EC protocol: codec, SRP-6a login, X25519 + AEAD transport, blocking client, typed replies; `fake-daemon` feature for tests |
| `remule-gui` | egui remote GUI, a port of `amulegui` (Phase 13) |

Toolchain present: rustc/cargo 1.99.1.

## 2. Strategy

**Rewrite the headless core (`amuled`) in Rust module by module, with aMule as the reference oracle. Do not try to link Rust into the C++ binary.**

Why not an incremental FFI port (cxx/bindgen inside aMule)? aMule's core is threaded through wxWidgets types (`wxString`, events, sockets, threads), global singletons (`theApp`), and raw cross-object pointers. Every FFI seam would need wrappers on both sides, and the C++ build would become far more complex. aMule's real boundaries are **wire protocols and on-disk files**, and those are exactly where a separate Rust program can stay compatible.

Compatibility contract, which every phase must keep:

1. **On-disk formats**: remule reads and writes aMule/eMule config and metadata (`known.met`, `*.part.met`, `server.met`, `nodes.dat`, `cryptkey.dat`, `preferences`, …) byte-compatibly. A user can point remule at an existing aMule config dir.
2. **Network protocols**: remule interoperates with real eMule/aMule peers, ed2k servers, and the Kad network.
3. **EC protocol** (the strangler step): once remule speaks EC, the existing `amulegui`, `amulecmd` and web UI can drive `remuled` in place of `amuled`. The C++ frontends keep working while the core underneath is replaced.

Out of scope, at least at first: porting the wxWidgets code itself, libutp/QUIC transports, mediaprobe, geoip, wxCas/aLinkCreator, AppImage/autostart integration. The GUI is instead rebuilt natively in Rust (egui) on top of EC; it was brought forward from Phase 13 on 2026-11-10 (see Phase 13).

## 3. How each step works

Every step is small enough to review in one sitting:

1. **Pick** one C++ unit (for example `Tag.cpp` + `Tag.h`) and list its responsibilities and dependencies.
2. **Collect test vectors** first: matching aMule unittests, real files from an aMule config dir, packet captures.
3. **Write the Rust module** with idiomatic types (enums over int codes, `Result` over error flags, no globals). Don't transliterate C++.
4. **Test**: unit tests, golden-file round trips (`parse → write → identical bytes`), `proptest` for encoders/decoders, `cargo fuzz` for every parser that reads network input.
5. **Verify against aMule** where possible: same input, same output (differential testing).
6. **Record** the step in the tracking table (§6) and commit.

Rules:
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test` pass on every commit.
- No `unsafe` outside clearly marked, justified spots. Parsers never panic on bad input.
- Each crate has a narrow purpose. Protocol/format crates are sync, pure, and I/O-free ("sans-IO"). Only the daemon layer touches sockets and the async runtime.

## 4. Target crate layout

```
remule/
  crates/
    ed2k-types/      MD4 hash, UInt128, file/part sizes, client IDs, constants (from include/protocol, include/tags)
    ed2k-codec/      SafeFile-style readers/writers, Tag, Packet framing, zlib packing
    ed2k-formats/    .met/.dat file formats
    ed2k-hash/       ed2k MD4 part hashing, AICH (SHA-1 tree), hashsets
    ed2k-crypto/     RC4 protocol obfuscation, RSA secure ident, client credits
    ed2k-server/     client↔server protocol (sans-IO state machine)
    ed2k-peer/       client↔client protocol: hello, file requests, source exchange
    kad/             Kademlia: routing, contacts, searches, publishing
    remule-core/     download queue, part files, shared files, upload queue, credits, ip filter, stats
    remule-ec/       EC protocol (server side first, then client)
    remule-net/      tokio runtime: framed TCP, UDP, throttling, connection limits
    remuled/         daemon binary: config, runtime, wiring
    remulecmd/       CLI over EC
```

## 5. Phases

Each phase ends with a **milestone** you can demonstrate. The "Rust skills" column notes which language concepts each phase leans on, since this is also a Rust learning project.

### Phase 0: Workspace hygiene
- Make sure the current workspace builds and tests pass on Windows (`cargo build`, `cargo test`).
- **Decide on one async runtime: tokio** (async-std is discontinued).
- ~~Drop Bazel and Nix, go Cargo-only.~~ Done.
- ~~Add a LICENSE (GPLv2+, same as aMule).~~ Done: `LICENSE.md`, `license = "GPL-2.0-or-later"` in `[workspace.package]`.
- Add CI (GitHub Actions: fmt, clippy, test on Linux and Windows).
- Move to the `crates/` layout above.
- **Milestone:** green CI on a clean tree.
- Rust skills: Cargo workspaces, features, clippy.

### Phase 1: Foundation types and codec
Source: `include/protocol/**`, `include/tags/**`, `MD4Hash.h`, `kademlia/utils/UInt128.*`, `SafeFile.*`, `Tag.*`, `Packet.*`
- Protocol opcodes and tag names as Rust enums (`#[repr(u8)]` + `TryFrom`).
- `Md4Hash`, `UInt128` with XOR distance and ordering.
- Byte reader/writer (little-endian, ed2k strings with UTF-8 / legacy handling, optional zlib).
- `Tag` (all tag types, including the short-tag encodings) and `Packet` (protocol byte, size, opcode, packed/unpacked).
- **Milestone:** every tag type round-trips. Packets captured from aMule decode and re-encode byte-identically.
- Rust skills: ownership of buffers, `&[u8]` vs `Vec<u8>` vs `bytes::Bytes`, enums, `TryFrom`, error types (`thiserror`).

### Phase 2: File formats
Source: `KnownFileList`, `PartMetWriter`, `ServerMet`, `ClientCreditsList`, `Preferences`, `IPFilter`
- `known.met`, `*.part.met` (+ `.bak`), `server.met`, `clients.met`, `nodes.dat` (v0/v1/v2), `cryptkey.dat`, `ipfilter.dat`, `addresses.dat`, `amule.conf`.
- **Milestone:** `remule inspect <aMule config dir>` dumps everything in it, and writes bit-identical copies.
- Rust skills: traits for `Read`/`Write`, `serde`, iterators, golden tests.

### Phase 3: Hashing
Source: `SHAHashSet.*`, `KnownFile.cpp` (hashing), `PartFileHashThread.*`, `AICHHashList`
- ed2k hash (MD4 over 9,728,000-byte parts, including the edge case of exact multiples), AICH tree (180 KB blocks, SHA-1), recovery data verification.
- **Milestone:** `remule hash <file>` prints the same ed2k link and AICH root as aMule for a set of test files (empty, 1 part, exactly N parts, large).
- Rust skills: streaming I/O, trait objects vs generics, benchmarks (`criterion`), maybe `rayon`.

### Phase 4: Crypto
Source: `RC4Encrypt.*`, `EncryptedStreamSocket.*`, `EncryptedDatagramSocket.*`, `ClientCredits.*`, `CryptoPP_Inc.h` usages
- RC4 obfuscation handshake (TCP and UDP, including the Kad UDP key variants), RSA secure user identification (replaces Crypto++ with the `rsa` crate), credit computation.
- **Milestone:** handshake test vectors from aMule pass, and an obfuscated TCP handshake with a real aMule instance succeeds.
- Rust skills: crate ecosystem choices, constant-time concerns, sans-IO state machines.

### Phase 5: Async networking runtime
Source: `EMSocket.*`, `ThrottledSocket.h`, `UploadBandwidthThrottler.*`, `DownloadBandwidthThrottler.*`, `ListenSocket.*`, `MuleUDPSocket.*`
- tokio-based framed TCP (`tokio_util::codec`) using the Phase 1 codec, UDP sockets, global bandwidth throttling (token bucket), connection limits.
- **Milestone:** a test harness opens N connections and stays within the configured upload/download limits.
- Rust skills: async/await, `Send`/`Sync`, channels, `select!`, cancellation.

### Phase 6: Server protocol
Source: `ServerConnect.*`, `ServerSocket.*`, `ServerUDPSocket.*`, `Server.*`, `ServerList.*`, `SearchPacket*`, `SearchList.*` (ed2k part)
- Login (including obfuscation and low ID), server list, keyword search, source requests (`GETSOURCES`), UDP server pings.
- **Milestone:** `remule search "<terms>" --server <ip:port>` logs into a real ed2k server and prints results.
- Rust skills: protocol state machines as enums, async tasks talking via channels.

### Phase 7: Kademlia
Source: `src/kademlia/**`, `src/include/protocol/kad*`
- Routing zone/bins (k-buckets), contact management and `nodes.dat` persistence, bootstrap, firewall check, node/keyword/source searches, publishing, Kad2 packet obfuscation, flood protection.
- **Milestone:** `remule kad` bootstraps from `nodes.dat`, keeps a healthy routing table for an hour, and runs keyword and source searches whose results match aMule's.
- Rust skills: tree data structures without `Rc<RefCell>` spaghetti (arena/index-based), timers, larger async systems.

### Phase 8: Peer protocol and downloading
Source: `BaseClient.cpp` (4.3k), `DownloadClient.cpp`, `UploadClient.cpp`, `ClientTCPSocket.*`, `ClientUDPSocket.*`, `PartFile.cpp` (5k), `DownloadQueue.*`, `SourceExchangePacket.h`, `ClientList.*`
- Hello/eMule info handshake, file request/status/hashset, block requests (compressed and uncompressed), source exchange, part file storage (gaps, buffered writes, completion, AICH-based corruption recovery).
- **Milestone (the big one):** remule downloads a real file from the network and completes it, and aMule can resume a `.part` that remule started (and the other way round).
- Rust skills: splitting a god-object (`CUpDownClient`) into per-concern components, file I/O off the async runtime.

### Phase 9: Sharing and uploading
Source: `SharedFileList.*`, `KnownFile.*`, `UploadQueue.*`, `UploadDiskIOThread.*`, `UploadPacketBuilder.*`, `ClientCreditsList.*`
- Shared dir scanning and rehash scheduling, publishing to server and Kad, upload queue with scoring and credits, upload slots.
- **Milestone:** a stock aMule instance downloads a file from remule.

### Phase 10: The daemon (`remuled`)
Source: `amuled.cpp`, `amule.cpp` (core parts), `Preferences.*`, `Statistics.*`, `IPFilter.*`, `ServerList` auto-update, `HTTPDownload.*`
- Config loading from an aMule config dir, lifecycle and graceful shutdown, statistics, IP filter, server.met/nodes.dat updates over HTTP, structured logging (`tracing`).
- **Milestone:** `remuled` runs unattended for 24h on a real network, using an existing aMule config.

### Phase 11: EC protocol (strangler step)
Source: `libs/ec/cpp/**` (packets, tags, SRP auth, crypt), `ExternalConn.cpp` (5.4k), `ECSpecialCoreTags.cpp`
- EC packet/tag codec, SRP authentication, the request handlers `ExternalConn.cpp` implements.
- **Milestone:** the **unmodified C++ `amulegui` and `amulecmd`** connect to `remuled` and can search, download, and show stats.
- Then: port `amulecmd` to Rust (`remulecmd`).

### Phase 12: Web API
Source: `src/webapi`, `src/libwebcommon`, `src/webserver`
- Re-implement the backend (axum) and serve the existing static frontend unchanged.
- **Milestone:** the existing web UI works against `remuled`, and `unittests/curl-tests/amuleapi` pass against it.

### Phase 13: Native GUI (brought forward, started 2026-11-10)
Source: `amule-remote-gui.cpp` (the EC glue), `amuleDlg.cpp`, `ServerWnd`/`ServerListCtrl`, `SearchDlg`/`SearchListCtrl`, `TransferWnd`/`DownloadListCtrl`, `SharedFilesWnd`/`SharedFilesCtrl`, `StatisticsDlg`; EC client side of `libs/ec/cpp` (`ECSocket`, `ECTag`, `ECCrypt`, `ECSRP`, `RemoteConnect`)
- Toolkit: **egui/eframe**. The GUI talks to the core only over EC, like `amulegui`, so it drives a stock `amuled` (3.3+, SRP + AEAD login) today and `remuled` after Phase 11 without changes.
- This pulls the *client* half of Phase 11 forward: `remule-ec` (codec, SRP-6a, X25519/HKDF/AEAD transport, blocking client, typed replies). The server half stays in Phase 11.
- `remule-gui`: Networks (servers, Kad, log), Searches, Transfers, Shared files, Statistics. A worker thread owns the EC connection and polls; the UI never blocks.
- `remule-ec --features fake-daemon --example fake_amuled`: a scripted stand-in daemon that speaks the real login, for GUI work and tests without `amuled`.
- Not yet: preferences dialog, categories, per-file details/sources (`EC_OP_GET_ULOAD_QUEUE`, client lists), chat/messages, friends, statistics tree, multi-search tabs, incremental (`EC_DETAIL_INC_UPDATE`) updates for very large lists, tray icon.
- **Milestone:** logs in to a real `amuled` and can search, download, pause/resume/cancel, and show stats. *Verified so far only against `fake_amuled` and aMule's own test vectors; not yet against a real daemon.*

### Later or never
libutp and QUIC transports, NAT hole punching via server, mediaprobe, geoip, `ed2k` link handler, fileview, wxCas, aLinkCreator.

## 6. Tracking

Update this table as steps land.

| # | Step | C++ source | Rust module | Status |
|---|---|---|---|---|
| 0.1 | Workspace builds + tests on Windows | — | workspace | done (CI runs Windows and Linux) |
| 0.3 | CI | — | `.github/workflows/ci.yml` | done: fmt, clippy -D warnings, tests, docs on Linux + Windows |
| 0.4 | GPLv2+ license, Cargo-only build | — | workspace | done |
| 1.1 | Protocol constants | `include/protocol/**`, `include/tags/**` | `ed2k-types` | done (369 values cross-checked against the headers) |
| 1.2 | `Md4Hash`, `UInt128` | `MD4Hash.h`, `UInt128.*` | `ed2k-types` | done (CUInt128Test cases ported) |
| 1.3 | Byte reader/writer | `SafeFile.*` | `ed2k-codec` | done (FileDataIOTest cases ported; u32 string lengths read in full, unlike the C++) |
| 1.4 | Tags | `Tag.*` | `ed2k-codec` | done (CTagTest.cpp packets ported; unwritable tags are errors, not corrupt output) |
| 1.5 | Packets | `Packet.*` | `ed2k-codec` | done (PacketTest.cpp ported; split packets left to phase 5). Phase 1 milestone: every tag type round-trips; byte-identical re-encoding verified on aMule's test packets, not yet on live captures |
| 2.1 | `server.met` | `ServerMet.*`, `ServerList.cpp` (load/save), `CServer::AddTagFromFile` | `ed2k-formats::server_met` | done (ServerMetTest.cpp ported; a public server.met from emule-security.org reads and writes back byte for byte) |
| 2.2 | `known.met` | `KnownFileList.cpp` (Init/Save), `CKnownFile::LoadFromFile`/`WriteToFile` | `ed2k-formats::known_met` | done (rules-based tests; aMule has no unit test for it; FT_FILESIZE_HI combined, unlike aMule) |
| 2.3 | `.part.met` | `CPartFile::LoadPartFile`/`SavePartFile`, `PartMetWriter` (format parts) | `ed2k-formats::part_met` | done (PartMetWriterTest format cases ported; eDonkey import layouts read) |
| 2.4 | `clients.met` | `ClientCreditsList.cpp`, `ClientCredits.*`, `ClientMetaTrailer.*` | `ed2k-formats::clients_met` | done (ClientMetaTrailerTest ported; credit ratio as aMule computes it) |
| 2.5 | `nodes.dat` | `CRoutingZone::ReadFile`/`WriteFile`, `CKadUDPKey` | `ed2k-formats::nodes_dat` | done (v0-v3 + bootstrap; a public nodes.dat round-trips byte for byte) |
| 2.6 | `cryptkey.dat` | `CClientCreditsList::CreateKeyPair`/`InitalizeCrypting` | `ed2k-formats::cryptkey_dat` | done (Crypto++ base64 of PKCS#8; not yet checked against an aMule-made key) |
| 2.7 | IP filter | `IPFilterScanner.l`, `IPFilter.cpp`, `CIPFilterIPv6Ranges` | `ed2k-formats::ipfilter` | done (IPFilterIPv6Test ported; zip lists and 6to4/Teredo check left out) |
| 2.8 | `addresses.dat`, `staticservers.dat` | `ServerListSources.h`, `CServerList::Load/SaveStaticServers` | `ed2k-formats::addresses_dat` | done (ServerListSourcesTest ported) |
| 2.9 | `amule.conf` | `Preferences.cpp`, `ECSRPConfig.cpp`, wxFileConfig rules | `ed2k-formats::amule_conf` | done (lossless INI + typed core subset) |
| 2.10 | `known2_64.met` | `SHAHashSet.cpp`, `CAICHSyncTask`, `ConvertToKnown2ToKnown264` | `ed2k-formats::known2_met` | done (root verification waits for phase 3 AICH) |
| 2.11 | `canceled.met`, `knownhistory.met` | `HashListFile.*` | `ed2k-formats::canceled_met` | done |
| 2.12 | `emfriends.met` | `FriendList.cpp`, `Friend.cpp` | `ed2k-formats::emfriends_met` | done |
| 2.M | Phase 2 milestone: `remule inspect <aMule config dir>` | — | `remule-cli` | done: summarises every file and checks the byte-for-byte rewrite (`--write OUT` saves the copies); a public server.met and nodes.dat pass |
| 3.1 | eD2k hash: MD4 parts, file hash, empty extra part | `ThreadTasks.cpp` (`CreateNextPartHash`), `KnownFile.cpp` | `ed2k-hash` | done (independent Python reference; one part of zeros gives the published FC21D9AF828F92A8DF64BEAC3357425D) |
| 3.2 | AICH tree (SHA-1, 184,320-byte blocks) | `SHAHashSet.cpp` (`CAICHHashTree`) | `ed2k-hash` | done (same reference; root rebuilt from stored block hashes) |
| 3.M | Phase 3 milestone: `remule hash <file>` | — | `remule-cli` | done (ed2k link with h=AICH as aMule writes it; ~840 MB/s release). Not yet compared with aMule on the same files |
| 4.1 | RC4 and TCP obfuscation: client↔client, client→server (DH768), sans-IO state machine | `RC4Encrypt.cpp`, `EncryptedStreamSocket.cpp`, `EncryptionRequirement.h` | `ed2k-crypto` | done (independent Python reference; aMule RC4Test vectors; the server handshake works against a real eD2k server). Client↔client not yet tried against a real aMule |
| 4.2 | UDP obfuscation: eD2k, Kad ID and Kad verify-key variants, client↔server | `EncryptedDatagramSocket.cpp`, `kademlia/Prefs.cpp` (`GetUDPVerifyKey`), `UdpObfuscationPolicy.h` | `ed2k-crypto` | done (same reference) |
| 4.3 | Secure ident: RSA PKCS#1 v1.5 / SHA-1 signatures, v1 and v2 (challenge IP) | `ClientCreditsList.cpp`, `SecIdentPolicy.h` | `ed2k-crypto` | done (sign/verify round trips and tampering; SecIdentTest ported). Not yet checked against an aMule-made signature |
| 4.4 | Credit ratio and the identity gate on scoring | `ClientCredits.cpp` | `ed2k-crypto` | done (ClientCreditsTest ratio cases ported) |
| 4.M | Phase 4 milestone: an obfuscated handshake with a real aMule | — | — | open |
| 5.1 | Framed TCP (`tokio_util::codec`, 2 MB packet limit) with the obfuscation handshake, split into reader and writer | `EMSocket.cpp`, `EncryptedStreamSocket.cpp` | `remule-net` | done (plain, client, server and incoming handshakes over pipes) |
| 5.2 | Bandwidth throttling: download bucket (300 ms ticks, 2-tick cap, refunds), upload (control first, fragments, debt) | `DownloadBandwidthThrottler.cpp`, `UploadBandwidthThrottler.cpp` | `remule-net` | done (paused-clock tests). Upload slots and their trickle/round-robin come with the upload queue |
| 5.3 | Connection limits (`TooManySockets`, per-five-seconds with spike modifier), limit-aware listener | `ListenSocket.cpp`, `Preferences.cpp` | `remule-net` | done |
| 5.4 | UDP socket, sent as control traffic | `MuleUDPSocket.cpp` | `remule-net` | done (no send queue yet) |
| 5.M | Phase 5 milestone: N connections stay within the limits | — | `remule-net` | done (8 localhost connections, half obfuscated: 254.6 / 256.0 KiB/s against 256) |
| 6.1 | Login (`OP_LOGINREQUEST`, capability flags), `OP_IDCHANGE`, LowID, server messages, refusal | `ServerConnect.cpp`, `ServerSocket.cpp` | `ed2k-server` | done (plain and obfuscated logins to a real server) |
| 6.2 | Search query language and request | `Parser.y`, `Scanner.l`, `SearchPacket.cpp`, `SearchPacketWriter.h` | `ed2k-server` | done (grammar and bytes from the C++ rules; boolean query with filters against a real server) |
| 6.3 | Search answers, found sources (incl. `_OBFU`), server list, ident, status, callbacks, packed packets | `SearchList.cpp`, `SearchFile.cpp`, `PartFile.cpp` (`AddSources`), `ServerSocket.cpp` | `ed2k-server` | done |
| 6.4 | Source requests (`OP_GETSOURCES`, `_OBFU`, large files) | `DownloadQueue.cpp` | `ed2k-server` | done (packet only; used with the download queue) |
| 6.5 | UDP server ping (`OP_GLOBSERVSTATREQ/RES`) | `ServerList.cpp`, `ServerUDPSocket.cpp` | `ed2k-server` | done (real server). Obfuscated ping, UDP global search and server descriptions not yet |
| 6.M | Phase 6 milestone: `remule search` against a real server | — | `remule-cli` | done (eMule Sunrise: 153 results for "ubuntu", plain and obfuscated) |
| 7.1 | Contacts and the routing table: bins, zone splits and merges, IP/subnet limits, small and big timers, nodes.dat and preferencesKad.dat | `routing/*`, `kademlia/Prefs.cpp` | `ed2k-kad` | done (arena tree; rules tested; nodes.dat written back) |
| 7.2 | Kad2 packets and their obfuscation (Kad ID and verify keys), request tracking | `net/KademliaUDPListener.cpp`, `net/PacketTracking.cpp` (tracking only) | `ed2k-kad` | done (real network) |
| 7.3 | Lookups: node, self, keyword and source searches; keyword choice and search terms | `kademlia/Search.cpp`, `SearchManager.cpp`, `SearchList.cpp`, `SearchPacket.cpp` | `ed2k-kad`, `ed2k-server` | done (simulated network; real network: "ubuntu" 539 files, 11 sources for an ISO it listed with 10) |
| 7.4 | Answering bootstrap, hello (with ACK), routing requests, pings | `net/KademliaUDPListener.cpp` | `ed2k-kad` | done |
| 7.5 | Indexing: storing published keywords (publishers, trust, names, AICH votes), sources and notes; answering searches (terms, trusted first); expiry; key/src/load_index.dat | `kademlia/Indexed.cpp`, `Entry.cpp`, `AICHHashList.cpp`, `net/SearchExpression.cpp`, publish handlers | `ed2k-kad` | done (unit tests; publish then search on a simulated network). Publishing our own files comes with sharing (phase 9) |
| 7.6 | Flood protection and bans; firewall checks, buddies, legacy (pre-v7) challenges, node protection | `net/PacketTracking.cpp`, `UDPFirewallTester.cpp`, `net/SafeKad.cpp` | `ed2k-kad` | flood protection done; firewall checks and buddies need the TCP side (phase 8); legacy challenges and SafeKad open |
| 7.M | Phase 7 milestone: `remule kad` bootstraps, keeps a healthy table for an hour, searches | — | `remule-cli` | done. Searches work on the live network (no local aMule to compare with side by side; server results agree). Hour run (2026-11-13) failed: traffic stopped after ~20 min and the node read "not connected" from 55 min. Fixed by porting the keep-alive from `CKademlia::Process` (big timer runs early when the last packet is over 15 min old) and the version-6 check on small-timer hellos. Rerun (2026-11-14) passed: 461 contacts, all verified, after 60 min; connected throughout; the keep-alive lookup came 15 min after the last packet; "linux" search returned 550 files at 30 min |
| 8.1 | Peer packets: hello/hello answer (capability bit fields), `OP_EMULEINFO`, file name/status requests, multipacket (+ext) and answers, part status bitmap, hash sets, upload request/accept, queue ranks, `OP_REQUESTPARTS(_I64)`, plain and compressed blocks (+I64), cancel/end, AICH file hash | `BaseClient.cpp` (hello, mule info), `ClientTCPSocket.cpp`, `DownloadClient.cpp`, `UploadClient.cpp`, `UploadPacketBuilder.cpp`, `PartStatusWriter.h` | `ed2k-peer` | done (PartStatusWriterTest vectors; hellos and blocks as aMule's Python integration peers build them). Not yet against a real peer |
| 8.2 | Download session state machine: handshake, file request, hash set, queue, block requests, timeouts (sans-IO) | `DownloadClient.cpp`, `BaseClient.cpp` (`ConnectionEstablished`, `TryToConnect`) | `ed2k-peer::download` | done (scripted peer through the real codec: multipacket and old-style requests, one-part files, hash sets, queue, plain and compressed blocks, corrupt streams, timeouts, callback with a slot). The part file is a trait until 8.3; no source exchange yet |
| 8.3 | Part file storage: gaps, block reservation, buffered writes, part hash checks, completion; `.part`/`.part.met` resumable by aMule | `PartFile.cpp`, `GapList.*`, `BlockReservation*` | `remule-core` | done (BlockReservationTest cases and oracles; whole downloads in a temp dir: verified parts, corrupt parts fetched again, resume from the met, rehash when the `.part` changed, short `.part`, `.bak` fallback, one-part and exact-multiple files, completion with and without part hashes, met fields kept on save). Synchronous; no AICH recovery yet (8.4). Resuming in a real aMule is checked at 8.M |
| 8.4 | Source exchange (SX1/SX2), secure ident in the handshake, AICH recovery | `SourceExchangePacket.h`, `PartFile::CreateSrcInfoPacket`, `ClientCreditsList.cpp`, `SHAHashSet.cpp` | `ed2k-peer`, `ed2k-hash::aich`, `remule-core` | done (SourceExchangePacketTest layouts; SX1 size detection and SX2 checks; `IsSourceRequestAllowed`; both directions of secure ident, v1 and v2, through the session; AICH recovery data built and read back for every part, 32-bit idents over 4 GB, tampered data dropped; root votes at 10 subnets and 92%; a corrupt part keeping all but its bad block). Answering source and AICH requests is left to the upload side (phase 9); storing proved keys in `clients.met` to the daemon; no ICH |
| 8.5 | Async peer connection on `remule-net` and a download queue driving sessions from server and Kad sources | `ClientTCPSocket.cpp`, `DownloadQueue.cpp`, `ClientList.cpp` | `remule-core` | done (sans-IO queue against scripted seeders through the real codec: one seeder, source exchange, queue then callback with a slot, sources dropped for no file or no connection and kept out for the dead delay, address filters, connection limits, a corrupt part recovered through AICH; the tokio driver downloading over real TCP from two local seeders, one obfuscated, one found by source exchange). Only directly reachable sources: no server or Kad buddy callbacks, no UDP reasks yet; file IO runs in the queue's task |
| 8.M | Phase 8 milestone: download a real file; aMule resumes remule's `.part` and the other way round | — | `remule-cli` | partly done. `remule download` (2026-11-14, Kad sources only): a public-domain Project Gutenberg epub downloaded from a live peer, checked against its ed2k hash; the unfinished downloads resumed from their `.part.met` in a second run; secure ident passed both ways with two live peers. Found and fixed: parallel connections to one peer for two files (now one per peer). Open: aMule resuming remule's `.part` and the other way round (no aMule on the test machine); a multi-part file from the live network |
| 9.1 | Shared files: scan the shared directories, match `known.met` (name, size, time), hash new files, record AICH hash sets in `known2_64.met`, save both as aMule does | `SharedFileList.cpp` (`FindSharedFiles`, `AddPathToShares`), `KnownFileList.cpp`, `ThreadTasks.cpp` (`CHashingTask`) | `remule-core::shared`, `remule-cli` | done (new, known, changed, renamed and duplicate files; reserved, missing and hidden; a damaged known.met; `remule share` on real files, its known.met and known2_64.met read back byte for byte by `remule inspect`). No directory watcher, exclusion filters or known.met pruning yet |
| 9.2 | Upload side of the peer protocol (sans-IO): answer file requests, status, hash sets, AICH and source requests; queue ranks; send requested blocks, packed when it pays | `UploadClient.cpp`, `UploadPacketBuilder.cpp`, `ClientTCPSocket.cpp` (upload handlers) | `ed2k-peer::upload` | done (our download session against it through the real codec: whole multi-part files, packed and plain, a queued peer then a slot; refusals of unknown files and wrong sizes; block request checks; hash sets and AICH roots; packet sizes by slot speed; `IsUploadCompressible`). Queue, slots and disk reads are 9.3; source and AICH answers are the application's |
| 9.3 | Upload queue: scores (credits, waiting time, file priority), slots, credits in `clients.met`, reading blocks off disk | `UploadQueue.cpp`, `UploadDiskIOThread.cpp`, `ClientCreditsList.cpp` | `remule-core` | done, without IO (scores by waiting time, credits and file priority; slot count from the limit; one new slot a second; rotation after an hour or 10 MB when others wait; LowID turns and callbacks; per-address and queue size limits; purge after an hour; `clients.met` with expiry, keys and score ratio; a shared file on disk uploaded into a part file on disk through both sessions and the queue). The network side, with the download queue on one connection, comes with 9.M |
| 9.4 | Publishing: offer files to the server (`OP_OFFERFILES`), publish keywords and sources to Kad | `SharedFileList.cpp` (`SendListToServer`, `Publish`), `kademlia/Search.cpp` (publish) | `ed2k-server`, `ed2k-kad`, `remule-core::publish` | done (offers in each server dialect: complete/incomplete markers, new tags, integer types, large files; limits; Kad store-keyword and store-source searches on the simulated network, found afterwards by keyword and source searches; keywords from names as aMule makes them; keyword and source publishing in turn, 2 s apart, 24 h and 5 h apart per item, the source time kept in `known.met`). Firewalled publishing through a buddy, notes and the AICH tag in keyword publishes are not ported. Sending them from a running client comes with 9.M |
| 9.M | Phase 9 milestone: a stock aMule downloads a file from remule | — | `remule-cli` | done. One client runs downloads and uploads together (`remule-core::uploader`, `downloader::run_with`): an incoming peer that is not a source calling back is served by the upload queue, finished downloads are shared, credits kept in `clients.met`. `remule download --share DIR` shares, offers to the server and publishes on Kad when `--reachable`. Two remule clients over TCP: a test (19 MB file, byte for byte) and two processes on this machine (2026-11-16: a Gutenberg epub, secure ident passed, uploaded at once). Waiting peers called back (2026-11-16): a connection with no slot closes after `CONNECTION_TIMEOUT` of silence, the peer keeping its place; when its turn comes a HighID is dialled where its hello said it listens (obfuscated when either side asks), our hello sent, and the slot given on its hello answer (`AddUpNextClient`, `US_CONNECTING`); an unreachable or mute peer loses the slot (session and uploader tests through the codec, a whole file downloaded after the callback; not yet over real TCP or with a real aMule). Offering to a live server (2026-11-16): `remule download --share` logged into eMule Sunrise (LowID) and offered a 300,000-byte file with a unique name; a second `remule search` on that server found it with 1 source and the same ed2k hash. A stock aMule downloads from remule (2026-11-17, CI job `amule-interop`, `scripts/interop/amule-downloads-from-remule.sh`): upstream's aMule 3.2.0 static build in a Fedora container, logged into a scripted eD2k server for a HighID, finishes a 24 MB three-part file from remule byte for byte (24 s); a control job with a second aMule as the source takes as long. Ubuntu's aMule 2.3.3 is not used: it stops reading a peer socket for good when bytes land before its edge-triggered read wait is re-armed (`async_read_some(null_buffers())`, fixed in 3.x by amule-org/amule `ee5289884`), and stalled at random points with a 2.3.3 source as well as with remule |
| 10.1 | `remuled`: the client run from an aMule config directory (amule.conf, preferences.dat, cryptkey.dat, shared folder lists, server.met, Kad files, known/clients.met), stopped by Ctrl-C or SIGTERM with everything saved; `tracing` logs | `amuled.cpp`, `amule.cpp` (`OnInit`, `ShutDown`), `Preferences.cpp` (user hash, `LoadSharedFolderIntents`), `UserHash.cpp`, `ServerList.cpp` (priority order) | `remuled`, `ed2k-formats::{preferences_dat, shareddir_dat}` | done (format tests; a whole directory loaded; the daemon serves a file from an aMule directory to a second client over TCP and leaves known.met, known2_64.met and clients.met there). The client loop moved from `remule download` into `remuled::client`, which the CLI now runs. |
| 10.2 | Server connection kept up: log in at start (`Autoconnect`), again at once when the connection is lost, and the whole list again 30 s after every server failed (`Reconnect`); our ID follows each login | `ServerConnect.cpp` (`ConnectToAnyServer`, `TryAnotherConnectionrequest`, `ConnectionFailed`, `CheckForTimeout`), `amule.cpp` (`GetID`) | `remuled::server_conn`, `remule-core::downloader` (`Command::SetOurId`) | done (the connector as a state machine: list order, an obfuscated pass before a plain one, 25 s per attempt, the 30 s wait, a sweep from the top after a loss, nothing more with `Reconnect` off; the daemon from an aMule directory dropped by a scripted server after its login and offer logs in again at once and offers its files on the new connection, a test that fails with reconnecting off). Attempts are made in the client loop, so downloads and Kad start without waiting for a server. As aMule with safe connect: one attempt at a time. Not ported: failure counts and dropping dead servers, static-only connecting, the keep-alive (`ServerKeepAliveTimeout`, off by default), the server's obfuscation port |
| 10.3 | IP filter in the running client: `ipfilter.dat` then `ipfilter_static.dat` from the config directory (aMule's placeholders made when missing), applied with `FilterLevel`, `IpFilterClients` and `IpFilterServers` to sources, incoming peers and servers | `IPFilter.cpp` (`CIPFilter`, `CIPFilterTask::LoadFromFile`), `ListenSocket.cpp` (`OnAccept`), `DownloadQueue.cpp`/`PartFile.cpp` (sources), `ServerList.cpp` (`AddServer`) | `remule-core::ip_filter`, `remuled::config`; the lists themselves in `ed2k-formats::ipfilter` (phase 4) | done (loading: placeholders with aMule's text, the static list winning, the level and switches, malformed lines counted, a zip or gzip list reported and left unread; the queue refusing blocked sources; the daemon hanging up on a blocked peer before reading anything and never trying a blocked server, a test that fails with either check removed). Not yet: unpacking zip/gzip lists, the system-wide list (`IPFilterSystem`), the update from `IPFilterURL` (needs unpacking: its default is a zip), Kad contacts (sources found on Kad are filtered), and reloading while running |
| 10.4 | Fetched over HTTP at start, as `amuled`: a `nodes.dat` from `KadNodesUrl` when Kad is on and there is none; a server list from each URL of `addresses.dat` when eD2k is on and no server is known, or at every start with `Serverlist`, merged into `server.met`; a missing `addresses.dat` made with aMule's default (or the legacy `Ed2kServersUrl`) | `amule.cpp` (`OnInit`, `UpdateNotesDat`, `OnFinishedHTTPDownload`), `ServerList.cpp` (`UpdateServerMetFromURL`, `DownloadFinished`, `LoadServerMet` merging), `HTTPDownload.cpp`, `Preferences.cpp` (`LoadPreferences`, `GetServerListURLs`) | `remuled::{bootstrap, http}` (reqwest with rustls) | done (the plan from amule.conf and the files present; the merge: new servers added, known ones renamed, unusable ones skipped; fetches from a local HTTP server: a redirect followed, a 404 and a page that is not a server.met skipped, files written through `*.download`, a `nodes.dat` with no contacts not kept). Live (2026-11-17): `remuled` on an empty config directory fetched 19 servers and 192 Kad contacts from upd.emule-security.org, connected to Kad and logged into a server within 10 s. Unlike aMule, a downloaded `nodes.dat` is kept only if it has contacts. Not yet: zip/gzip lists, the IP filter update, conditional requests, fetching again while running |
| 10.5 | Transfer statistics: the session's file data each way added to the totals of every session, read from `statistics.dat` at start and written back once a minute when they changed and on shutdown, as `amuled` keeps them (`amule.conf` neither read nor written for them); a statistics line in the periodic status (session and total each way, UL:DL ratios) and on shutdown (with uptime, average rates, time since the first transfer) | `Statistics.cpp/.h` (`Load`, `Save`, `AddReceivedBytes`, `AddSentBytes`), `StatTree.cpp` (`CStatTreeItemUlDlCounter`, `CStatTreeItemRatio`, `CStatTreeItemAverageSpeed`), `amule.cpp` (`OnCoreTimer`, `ShutDown`) | `ed2k-formats::statistics_dat`, `remule-core::statistics`, `remuled::stats`, `remule-core::downloader` (`Command::Traffic`) | done (the file's layout, other versions and files cut short; counting, the once-a-minute save and a failed save left due, ratios as aMule prints them; the daemon from an aMule directory with earlier totals adds what it uploaded to `statistics.dat` and leaves `amule.conf` byte for byte, the downloading client's first session writes what it received; a test that fails with the shutdown save removed). Counted as remule counts them: file bytes received and sent, where aMule counts block payloads on the wire (packed blocks at their packed size). Unlike aMule's tree, the total ratio does not count the session twice. Not yet: the statistics tree and graphs for the GUI and EC (phase 11), overhead, rates over a window and their maxima, connection, source, client and server counts, per-client-software breakdowns, the move of 2.3.3's `[Statistics]` totals out of `amule.conf` (dropped by today's aMule) |
| 10.6 | Whether others can reach us, found out while running as aMule's `IsFirewalled` does: a HighID login, or Kad's TCP firewall check (while a check wants answers, nodes that say hello are asked with `KADEMLIA_FIREWALLED2_REQ` to tell us our IP and to connect to our TCP port; two `OP_KAD_FWTCPCHECK_ACK`s and we are open; again every hour). Kad source and keyword publishing and the TCP bit of our Kad hellos follow it. Others' checks answered: their IP over UDP, then a connection to their port, hellos and the ack. Our public IP voted from the answers and kept in `preferencesKad.dat` | `amule.cpp` (`IsFirewalled`, `IsFirewalledKad`), `kademlia/kademlia/{FirewallRecheck,FirewallCheckRequests,PublicIPVote}.h`, `Kademlia.cpp` (`RecheckFirewalled`), `KademliaUDPListener.cpp` (`FirewalledCheck`, `ProcessFirewalled2Request`, `ProcessFirewalledResponse`, `ProcessFirewalledAckResponse`), `ClientList.cpp` (`RequestTCP`, the `KS_CONNECTED_FWCHECK` case of `Process`), `ClientTCPSocket.cpp` (`OP_KAD_FWTCPCHECK_ACK`), `SharedFileList.cpp` (`CurrentKadPublishFacts`) | `ed2k-kad::{firewall, node, packets}`, `remule-core::downloader`, `remuled::{firewall, client, kad}` | done (aMule's `KadFirewallRecheckTest`, `KadFirewallCheckRequestsTest` and `KadPublicIPVoteTest` cases; the check between nodes without IO: asked only while answers are wanted, each node's IP answer and ack counted once, open on the second ack, firewalled again a grace minute after the hourly recheck's answers when nobody got through, nothing asked or answered without TCP; the packets byte for byte; the daemon checked by scripted Kad nodes on other loopback addresses, one obfuscated: its hellos say TCP-firewalled until their acks, then not; and it connects back, obfuscated, to a node that asks, with its hello then the ack; a test that fails with the ack dropped on either side). A HighID making us reachable is tested on its own, not in a running daemon. Not yet: the UDP firewall test (`CUDPFirewallTester`, `KADEMLIA2_FIREWALLUDP`: the daemon says it is UDP-firewalled, so it does not store what others publish), buddies and callbacks for firewalled clients, answering Kad 1 checks (`KADEMLIA_FIREWALLED_REQ`, acked over UDP; Kad 1 acks to our checks are counted), Kad counting as firewalled once it has lost its contacts, LAN mode, UPnP and NAT traversal |
| 11.1 | EC server, first step: `remuled` listens on `ECAddress:ECPort` when `AcceptExternalConnections` is on and an EC password is set, and runs the daemon's half of the 3.3 login: X25519 + AEAD keys (ChaCha20 when the client asks first, else AES-GCM), the SRP-6a challenge from `ECPasswordVerifier`, every `EC_OP_AUTH_FAIL` reason and text, the per-address lockout (`AuthFailureWindowSeconds`, `AuthFailureThreshold`, `AuthLockoutSeconds`), and `ECSocket`'s framing (16 MiB before login, zlib for large replies unless the client is local, nothing in clear after the keys). A legacy `ECPassword` is migrated to `ECPasswordVerifier` in `amule.conf` as `ECSRP::LoadCredential` does. Served: `EC_OP_STAT_REQ` and `EC_OP_GET_CONNSTATE` at every detail level, from a view the client refreshes every second, and `EC_OP_SHUTDOWN`, which stops and saves; anything else gets aMule's "Invalid opcode" `EC_OP_FAILED` | `ExternalConn.cpp` (`ExternalConn`, `Authenticate`, `NegotiateAEAD`, `ActivateAEAD`, `OnPacketReceived`, `Get_EC_Response_StatRequest`, `ProcessRequest2`), `ECSpecialCoreTags.cpp` (`CEC_ConnState_Tag`, `CEC_Server_Tag`), `libs/ec/cpp/{ECSRP,ECSRPConfig,ECSocket}.cpp`, `libs/common/RateLimiter.*`, `amule.cpp` (`GetID`, the EC address) | `remule-ec::{server, srp}`, `remuled::{ec, config, client}` | done (the verifier of aMule's SRP test vector, encoded and decoded as `ECPasswordVerifier`; this crate's client logs in over a socket, is refused with each reason, locked out and told when to come back, and dropped for a clear packet after the keys; the migration cases of EC_SRP.md: legacy digest, empty key left by a downgrade, password changed by a downgrade, bad digest, bad verifier; the replies' tags by detail level; a running daemon from an aMule directory with a legacy password, logged into, asked for stats and state, and shut down over EC). Not yet checked with the C++ `amulecmd` or `amulegui`. Not yet: the download queue, shared files, servers, searches, logs, preferences and every other request; push notifications (`EC_TAG_CAN_NOTIFY`); the capability echoes that announce those requests; API and amuleweb tokens (they fail as a wrong password); `amuled --ec-config`; overhead, banned, UDP-firewalled and buddy values (sent as 0) |
| 11.2 | Downloads over EC, as `amulecmd`'s `show dl`, `add`, `pause`, `resume` and `cancel` use them: `EC_OP_GET_DLOAD_QUEUE` (every download, or those asked for by ECID; `CEC_PartFile_Tag` with its `CEC_SharedFile_Tag` base at each detail level, ECIDs per daemon process, speeds from the bytes of the last second, finished downloads kept until cleared); `EC_OP_ADD_LINK` (ed2k file links: a new download in the temp directory, or the link's sources for one already there; a file already shared or a link that is not one refused, logged as aMule logs it; one reply for all the links, with aMule's counts); `EC_OP_PARTFILE_PAUSE`, `_RESUME`, `_STOP` and `_DELETE` (each target an MD4 tag, in order; aMule's guards: unknown hash, a stale ECID, a finished download skipped from a cancel, a changed name or folder). In the core: `PauseFile` (connections closed, saved paused, sources kept), `StopFile` (sources dropped, none taken), `ResumeFile`, and cancelling (out of the queue, `.part` and met removed); a file loaded paused is stopped; no sources asked for paused downloads. The ed2k link parser moved to `remule-core` | `ExternalConn.cpp` (`Get_EC_Response_GetDownloadQueue`, `Get_EC_Response_PartFile_Cmd`, `EC_OP_ADD_LINK`), `ECSpecialCoreTags.cpp` (`CEC_PartFile_Tag`, `CEC_SharedFile_Tag`), `DownloadQueue.cpp` (`AddLink`, `AddED2KLink`, `IsFileExisting`), `PartFile.cpp` (`PauseFile`, `StopFile`, `ResumeFile`, `GetStatus`), `amuleAppCommon.cpp` (`CreateED2kLink`), `TextClient.cpp` | `remule-core::{download_queue, downloader, link}`, `remuled::{ec, client}` | done (the queue paused, resumed, stopped and cancelled against a scripted seeder; the partfile tag's fields by detail level; ECIDs and speeds over refreshes; every partfile-command guard and the link replies; a running daemon driven over EC: a link added and listed, added again, refused when broken, paused, resumed and cancelled, with the `.part.met` following each step). Not yet: the gap, requested-block and source-name encodings (`CPartFile_Encoder`: amulegui's progress bars), `EC_DETAIL_INC_UPDATE` and `EC_OP_GET_UPDATE`, priorities and categories (`EC_OP_PARTFILE_PRIO_SET`, `_SET_CAT`), A4AF, `AddNewFilesPaused`, server, server-list and magnet links, and refreshing the view before the next second (a command right after a link may not see it yet) |
| 11.3 | Servers and networks over EC, as `amulecmd`'s `show servers`, `connect`, `disconnect`, `add` and `remove` use them: `EC_OP_GET_SERVER_LIST` (every server as `CEC_Server_Tag` at the request's detail level, what `server.met` says of each with what the logged-in server says of itself; empty with eD2k off); `EC_OP_SERVER_CONNECT` (one server: obfuscated, then plain, then nothing, as `ConnectToServer`; or any: a new sweep), `EC_OP_SERVER_DISCONNECT` (hung up, no reconnect), `EC_OP_SERVER_ADD` (`CServerList::AddServer`'s checks and log lines: no port, filtered or invalid IP, already listed; the address as the name when none is given; tried last) and `EC_OP_SERVER_REMOVE` (refused for the server we are on), with `Get_EC_Response_Server`'s replies; `EC_OP_CONNECT` and `EC_OP_DISCONNECT` for both networks, in aMule's words; `EC_OP_KAD_START` and `EC_OP_KAD_STOP` (the node saved and stopped, and started again from its files). A changed list is written to `server.met` on shutdown, as `~CServerList` writes it. The connection state now names the logged-in server (the login used to record the attempt after it had become the connection) | `ExternalConn.cpp` (`Get_EC_Response_Server`, `Get_EC_Response_Server_Add`, `EC_OP_GET_SERVER_LIST`, `EC_OP_CONNECT`, `EC_OP_DISCONNECT`, `EC_OP_KAD_START`, `EC_OP_KAD_STOP`), `ECSpecialCoreTags.cpp` (`CEC_Server_Tag`), `ServerConnect.cpp` (`ConnectToAnyServer`, `ConnectToServer`, `StopConnectionTry`, `Disconnect`, `ConnectionFailed`), `ServerList.cpp` (`AddServer`, `RemoveServer`, `SaveServerMet`), `TextClient.cpp` | `remuled::{ec_servers, server_conn, client, ec, config}` | done (the server tag's fields by detail level; every reply and the effects each request has on the loop, against a connector and a list without IO; the connector's single-server attempts, stop, disconnect and list changes under a sweep; the list saved only when changed, with the live server's counts; a running daemon driven over EC against scripted servers: listed, added, refused twice, one picked and logged into, its removal refused, disconnected and staying so, removed, any server connected, the network commands, `server.met` written on shutdown; and Kad stopped and started over EC). Not yet: dynamic-IP (host name) servers, static servers (`staticservers.dat`, `EC_OP_SERVER_SET_STATIC_PRIO`), `EC_OP_SERVER_UPDATE_FROM_URL`, `EC_OP_KAD_UPDATE_FROM_URL`, `EC_OP_KAD_BOOTSTRAP_FROM_IP`, `EC_OP_GET_SERVERINFO`, server pings, failure counts and dead-server removal; the list is written only when it changed, not on every shutdown |
| 11.4 | Shared files over EC, as `amulecmd`'s `show shared` and `reload shared` and amulegui's shared-files panel use them: `EC_OP_GET_SHARED_FILES` (one `EC_TAG_KNOWNFILE` per shared file, or those asked for by ECID, at each detail level; `CEC_SharedFile_Tag` with all-time requests, accepts and bytes, AICH root, upload priority, last upload, shared since and the last verify from `known.met`, the folder as `EC_TAG_KNOWNFILE_FILENAME`), `EC_OP_SHAREDFILES_RELOAD` (answered at once, as aMule schedules it; the folders listed again and new files hashed off the client's loop, one walk at a time, one more if asked again meanwhile), `EC_OP_SHARED_SET_PRIO` (a priority by hash, `PR_AUTO` starting at high as `UpdateAutoUpPriority` does for a file nobody is queued for; kept in `known.met`), `EC_OP_GET_SHARED_DIRS` (the explicit folders and the recursive roots as configured). The list is read when asked for, not kept in the per-second view. The shared-file tag is now the base of the downloads' tag, and every ECID comes from one counter for the process, as `CECID` does | `ExternalConn.cpp` (`Get_EC_Response_GetSharedFiles`, `Get_EC_Response_Set_SharedFile_Prio`, `Get_EC_Response_GetSharedDirs`, `EC_OP_SHAREDFILES_RELOAD`), `ECSpecialCoreTags.cpp` (`CEC_SharedFile_Tag`), `SharedFileList.cpp` (`Reload`), `KnownFile.cpp` (`UpdateAutoUpPriority`), `TextClient.cpp` | `remuled::{ec_shared, ec, client, config}` | done (the tag's fields and order by detail level, the verify fields only once verified; the replies by ECID; ECIDs kept while a file stays shared, new ones after it comes back; priorities set, automatic, and saved; a running daemon sharing a folder driven over EC: listed, given a priority, its folders read, a new file found by a reload, the priority in `known.met` after shutdown). Not yet: session request/accept/transfer counts, complete-source counts and upload activity (sent as 0), the part availability encoding (`CKnownFile_Encoder`), partial downloads in the shared list, `EC_DETAIL_INC_UPDATE`, automatic priorities following the upload queue, `EC_OP_SET_SHARED_DIRS` (and so the `EC_TAG_CAN_SHAREDDIRS_CONFIG` echo), renaming, deleting, comments and ratings |
| 11.5 | Searches over EC, as `amulecmd`'s `search local|global|kad`, `results`, `progress`, `stop` and `download` use them on the legacy single search (`0xffffffff`; multi-search is not echoed): `EC_OP_SEARCH_START` (the `CEC_Search_Tag` fields: name, type, extension, sizes, availability, media filters; aMule's refusals for web, browse and out-of-range media filters; `StartNewSearch`'s checks and texts for eD2k not connected, Kad not running, no Kad keyword, query syntax errors; the results emptied first; the request sent to the connected server, the keyword lookup started on Kad, both for an all search), `EC_OP_SEARCH_RESULTS` (`CEC_SearchFile_Tag` by detail level, parents or with their groups on `EC_TAG_SEARCH_PARENT`, or by ECID; download status from the queue and the shared files), `EC_OP_SEARCH_PROGRESS` (`EC_TAG_SEARCH_STATUS` with its 0xffff/0xfffe sentinels, lifecycle state, kind, result count and percent, Kad's 45 s ramp), `EC_OP_SEARCH_STOP`, `EC_OP_DOWNLOAD_SEARCH_RESULT` (by hash or ECID, a new download with the result's clients as sources, "No open search holds this result."), and the legacy answers of `_REQUEST_MORE` and `_SEARCH_LIST`. Results merge as `AddToList` and `AddChild` merge them: size 0 or too large dropped, the same name added up, other names a group named after the child with the most sources (eD2k counts summed, Kad's the largest); the server's answer ends a local search, or 12 s without one | `ExternalConn.cpp` (`Get_EC_Response_Search`, `_Search_Stop`, `_Search_Results`, `_Search_Results_Download`, `_Search_Request_More`, `EC_OP_SEARCH_PROGRESS`), `ECSpecialCoreTags.cpp` (`CEC_SearchFile_Tag`), `SearchList.cpp` (`StartNewSearch`, `AddToList`, `GetSearchProgress`, `GetSearchLifecycleState`, `GetSearchLifecyclePercent`, `StopSearch`, `AddFileToDownloadByHash`/`ByEcid`, `OnGlobalSearchTimer`), `SearchFile.cpp` (`AddChild`, `MergeResults`, `UpdateParent`), `DownloadQueue.cpp` (`AddSearchToDownload`), `TextClient.cpp` | `remuled::{ec_search, ec, client}` | done (the start checks and texts; merging and groups with their ECIDs; progress, lifecycle and percent for local, Kad and all searches, the answer timeout, stopping; the result tags by detail level, groups and ECIDs; a running daemon logged into a scripted server: refused searches, a local search answered with a group, `progress` and `results` as amulecmd reads them, a result downloaded into the queue and shown as queued, stop and list). Not yet: the global sweep over other servers by UDP (a global search asks the connected server only), multi-search and its capability echoes, `EC_DETAIL_INC_UPDATE` value maps (full tags are sent), result filtering by file type, stopping a running Kad lookup (later results are ignored), asking the server for more results, media metadata in results, Kad notes |
| 13.1 | EC client: codec, SRP-6a, AEAD transport, login | `libs/ec/cpp/{ECTag,ECPacket,ECSocket,ECCrypt,ECSRP,RemoteConnect}.*`, `ECCodes.abstract` | `remule-ec` | done (vs. aMule test vectors + fake daemon) |
| 13.2 | Remote GUI: Networks, Searches, Transfers, Shared, Statistics | `amule-remote-gui.cpp`, `amuleDlg.cpp`, `*Wnd`/`*Ctrl` | `remule-gui` | first version; needs testing against real `amuled` |
| … | (add rows as phases are broken down) | | | |

## 7. Open decisions

1. ~~**License.**~~ Decided: GPLv2+, same as aMule. The repository was restarted without any inherited code, so there is no third-party code to clear.
2. ~~**Build systems.**~~ Decided: Cargo-only.
3. **Async runtime.** tokio is recommended; async-std is discontinued.
4. **Crypto crates.** RustCrypto (`md4`, `sha1`, `rc4`, `rsa`) vs `ring`/`aws-lc-rs`. RustCrypto covers the legacy algorithms ed2k needs.
5. **Upstream relationship.** Should remule track aMule-org changes after the port starts (pin a commit and review diffs periodically), or freeze at `688c51eb7`?

## 8. Risks

- **Undocumented protocol behaviour.** Much of ed2k is defined by what eMule and aMule actually do. Mitigation: differential tests and captures from real peers, and reading the C++ before guessing.
- **God objects.** `CUpDownClient`, `CPartFile` and `CamuleApp` hold most of the state. Rust's borrow checker will reject a direct translation. Mitigation: redesign around message passing (one task owns each piece of state) instead of shared pointers.
- **Scale.** About 100k lines of non-GUI core. Mitigation: strict phase milestones, and the EC strangler step so the result is usable before it is complete.
- **Hostile input.** Every network parser faces untrusted peers. Mitigation: fuzz every parser and never panic on bad input.
