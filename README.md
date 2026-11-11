# remule

A Rust port of aMule, in progress. See [MIGRATION_PLAN.md](MIGRATION_PLAN.md).

## remule-gui: remote GUI for amuled

A native (egui) port of `amulegui`. It connects to an aMule daemon over External Connections (aMule 3.3+, SRP login over an encrypted channel), like `amulegui` does.

    cargo run --release -p remule-gui -- [-h HOST] [-p PORT] [-P PASSWORD]

Without options it opens a connect dialog (default `localhost:4712`). The daemon needs External Connections enabled and a password set (`amuled --ec-config`).

To try it without a daemon, run the scripted stand-in, which speaks the real EC login and serves made-up downloads, servers and search results:

    cargo run -p remule-ec --features fake-daemon --example fake_amuled -- 4712 secret
    cargo run -p remule-gui -- -h 127.0.0.1 -p 4712 -P secret

Crates: `ed2k-types` (eD2k/Kad protocol constants, `Md4Hash`, `UInt128`), `ed2k-codec` (byte reader/writer, tags, packets), `ed2k-formats` (on-disk formats: `server.met`), `remule-ec` (EC protocol client) and `remule-gui` (the GUI). `remule-ec/src/codes.rs` is generated from aMule's `ECCodes.abstract` by `remule-ec/gen_codes.py`.

## License

GPL-2.0-or-later, like aMule. See [LICENSE.md](LICENSE.md).
