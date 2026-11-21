# remule

A Rust port of aMule, in progress. See [MIGRATION_PLAN.md](MIGRATION_PLAN.md).

## remule inspect: check an aMule config directory

    cargo run -p remule-cli -- inspect ~/.aMule

Reads every aMule file in the directory (amule.conf, server.met, known.met, the .part.met files in the temp dir, nodes.dat, clients.met, ...), prints a summary of each, and checks that remule writes it back byte for byte. `-v` lists entries; `--write OUT` saves remule's copies to diff. Nothing in the directory is modified, and the private key in cryptkey.dat is never printed.

## remule hash: ed2k links

    cargo run --release -p remule-cli -- hash FILE...

Hashes files as aMule does (MD4 per 9,728,000-byte part, the AICH tree over 184,320-byte blocks) and prints each file's ed2k link with its AICH root: `ed2k://|file|NAME|SIZE|HASH|h=AICH|/`. `-v` lists the part hashes.

## remule search: search an eD2k server

    cargo run --release -p remule-cli -- search "ubuntu iso NOT desktop" --server 176.123.5.89:4725 [--obfuscate] [--type Video] [--min-size 1G] [--more 2] [-v]

Logs into a server, as a LowID since nothing listens for its callback, and runs a keyword search. The query is aMule's search syntax: words, `AND` / `OR` / `NOT`, parentheses, `"quoted words"`. `--obfuscate` uses the obfuscated handshake (DH + RC4). `-v` prints each result's ed2k link.

    cargo run --release -p remule-cli -- ping 176.123.5.89:4725

Pings a server over UDP (its TCP port + 4) for its user and file counts.

## remule kad: Kademlia

    cargo run --release -p remule-cli -- kad --nodes nodes.dat [--search "ubuntu iso"]... [--source HASH:SIZE]... [--duration SECS] [-v]

Joins Kad from a nodes.dat, keeps a routing table and runs keyword and source searches. Within one search it merges the answers for the same file, then prints them. The node says it is firewalled, so other nodes keep it out of their routing tables. It keeps its Kad ID, the contacts it learned and its index in `--dir` (default `remule-kad`) for the next run. With `--reachable` (when its UDP port can be reached from outside) it stores what others publish to it and answers their searches, as aMule does. It does not publish anything of its own yet.

## remuled: the daemon

Runs the client from an aMule config directory, as `amuled` does:
- downloads in its `Temp` directory are resumed;
- the shared folders and `Incoming` are shared and uploaded. Shared folders come from `shareddir.dat`, or from aMule-org's `shareddir-explicit.dat` / `shareddir-recursive.dat`;
- the first server in `server.met` that logs in is used, high priority first, and it logs in again when the connection is lost;
- Kad starts from the `nodes.dat` there;
- a missing `nodes.dat`, and server lists from `addresses.dat`, are fetched over HTTP at start;
- `ipfilter.dat` and `ipfilter_static.dat` keep it away from filtered peers and servers;
- transfer totals are kept in `statistics.dat`;
- with `AcceptExternalConnections` and an EC password, it accepts External Connections on `ECPort` (aMule 3.3's SRP login). So far they can ask for statistics and the connection state; list, add (ed2k links), pause, resume and cancel downloads; list, add, remove, connect to and disconnect from servers, and start and stop Kad; list the shared files, reload them and set their upload priority; search the server and Kad and download results; read the general and connection preferences; get `amulegui`'s incremental updates; read the statistics graphs and tree; and shut it down. `scripts/interop/amulecmd-drives-remuled.sh` (run in CI) checks this with aMule's own `amulecmd`.

Nick, ports, limits and directories come from `amule.conf`, the user hash from `preferences.dat`, and the secure-ident key from `cryptkey.dat` (both made if missing). A legacy `ECPassword` in `amule.conf` is replaced by an `ECPasswordVerifier`, as aMule 3.3 does. On Ctrl-C (or SIGTERM) it saves `known.met`, `clients.met`, the part files, the statistics and the Kad state, in aMule's formats and places.

    cargo run --release -p remuled -- [-c ~/.aMule] [--duration SECS]

Stop aMule first: the two must not use one directory at once.

Not yet supported: the rest of External Connections (changing preferences, logs, categories, the upload queue, and the peers in `amulegui`'s updates).

## Windows: one zip to share

    powershell -File scripts\package-windows.ps1

builds `dist\remule-<version>-windows-x64.zip`: `Remule.exe` (the `remule-app` launcher), `remuled.exe`, `remule-gui.exe`, a README for whoever it is shared with, and the license. The C runtime is linked in, so nothing else needs installing. `Remule.exe` keeps its own config folder, `%APPDATA%\remule\daemon`, and never touches an aMule install. The first time, it sets that folder up with an External Connections password and a free local port. It then starts `remuled` with no console window and opens `remule-gui` connected to it. When the window is closed, it asks `remuled` over EC to save and stop.

## remulecmd: amulecmd in Rust

A port of `amulecmd`, the text client for a running daemon (`amuled` 3.3+ or `remuled`). Same options, same `remote.conf`, same commands, and the same output, so scripts written for amulecmd keep working:

    cargo run --release -p remulecmd -- -h 127.0.0.1 -p 4712 -P PASSWORD -c "show dl"

Without `-c` it opens amulecmd's shell (`help` lists the commands). CI runs about a hundred commands through both `amulecmd` and `remulecmd` against `remuled` and compares what they print.

## remule-gui: remote GUI for amuled

A native (egui) port of `amulegui`. It connects to an aMule daemon over External Connections (aMule 3.3+, SRP login over an encrypted channel), like `amulegui` does.

    cargo run --release -p remule-gui -- [-h HOST] [-p PORT] [-P PASSWORD]

Without options it opens a connect dialog (default `localhost:4712`). The daemon needs External Connections enabled and a password set (`amuled --ec-config`).

To try it without a daemon, run the scripted stand-in, which speaks the real EC login and serves made-up downloads, servers and search results:

    cargo run -p remule-ec --features fake-daemon --example fake_amuled -- 4712 secret
    cargo run -p remule-gui -- -h 127.0.0.1 -p 4712 -P secret

Crates: `remule-cli` (the `remule` command), `ed2k-types` (eD2k/Kad protocol constants, `Md4Hash`, `UInt128`), `ed2k-codec` (byte reader/writer, tags, packets), `ed2k-hash` (eD2k and AICH hashing), `ed2k-formats` (aMule's on-disk formats: `server.met`, `known.met`, `.part.met`, `nodes.dat`, `clients.met`, `amule.conf` and more), `remule-ec` (EC protocol: client, and the daemon's side), `remule-gui` (the GUI), `remulecmd` (the text client) and `remuled` (the daemon, and the client `remule download` runs). `remule-ec/src/codes.rs` is generated from aMule's `ECCodes.abstract` by `remule-ec/gen_codes.py`.

## License

GPL-2.0-or-later, like aMule. See [LICENSE.md](LICENSE.md).
