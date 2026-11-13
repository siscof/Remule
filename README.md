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

## remule-gui: remote GUI for amuled

A native (egui) port of `amulegui`. It connects to an aMule daemon over External Connections (aMule 3.3+, SRP login over an encrypted channel), like `amulegui` does.

    cargo run --release -p remule-gui -- [-h HOST] [-p PORT] [-P PASSWORD]

Without options it opens a connect dialog (default `localhost:4712`). The daemon needs External Connections enabled and a password set (`amuled --ec-config`).

To try it without a daemon, run the scripted stand-in, which speaks the real EC login and serves made-up downloads, servers and search results:

    cargo run -p remule-ec --features fake-daemon --example fake_amuled -- 4712 secret
    cargo run -p remule-gui -- -h 127.0.0.1 -p 4712 -P secret

Crates: `remule-cli` (the `remule` command), `ed2k-types` (eD2k/Kad protocol constants, `Md4Hash`, `UInt128`), `ed2k-codec` (byte reader/writer, tags, packets), `ed2k-hash` (eD2k and AICH hashing), `ed2k-formats` (aMule's on-disk formats: `server.met`, `known.met`, `.part.met`, `nodes.dat`, `clients.met`, `amule.conf` and more), `remule-ec` (EC protocol client) and `remule-gui` (the GUI). `remule-ec/src/codes.rs` is generated from aMule's `ECCodes.abstract` by `remule-ec/gen_codes.py`.

## License

GPL-2.0-or-later, like aMule. See [LICENSE.md](LICENSE.md).
