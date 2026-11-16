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
| 9.M | Phase 9 milestone: a stock aMule downloads a file from remule | — | `remule-cli` | partly done. One client runs downloads and uploads together (`remule-core::uploader`, `downloader::run_with`): an incoming peer that is not a source calling back is served by the upload queue, finished downloads are shared, credits kept in `clients.met`. `remule download --share DIR` shares, offers to the server and publishes on Kad when `--reachable`. Two remule clients over TCP: a test (19 MB file, byte for byte) and two processes on this machine (2026-11-16: a Gutenberg epub, secure ident passed, uploaded at once). Open: a stock aMule downloading from remule (no aMule on the test machine); offering to a live server; callbacks to queued peers |
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
