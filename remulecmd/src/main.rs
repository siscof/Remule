// SPDX-License-Identifier: GPL-2.0-or-later
//! `remulecmd`: amulecmd ported to Rust. A text client for a running
//! `amuled` (3.3 or later) or `remuled`, over External Connections.
//!
//!     remulecmd [-h HOST] [-p PORT] [-P PASSWORD] [-c COMMAND] ...
//!
//! It reads the same `remote.conf` amulecmd reads (in `~/.aMule`, or
//! `%APPDATA%\aMule` on Windows), takes the same options and commands and
//! prints what amulecmd prints, so scripts written for amulecmd keep
//! working. Not ported: translations (`--locale` is accepted and ignored)
//! and line editing.

mod app;
mod commands;
mod format;

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ed2k_formats::amule_conf::{parse_long, ConfFile};
use remule_ec::codes::*;
use remule_ec::{srp, Client, ConnectOptions, Error, Packet};

use app::{App, Link};

const NAME: &str = "remulecmd";
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// What amulecmd says it is in its greeting.
const GREETING: &str = "remule text client";
/// MD5 of the empty string: no password.
const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

const USAGE: &str = "\
Usage: remulecmd [--help] [-h <str>] [-p <num>] [-P <str>] [-f <str>] [-q] [-v] [-l <str>] [-w] [--create-config-from <str>] [--version] [--force-zlib] [-c <str>] [--space-separated]
  --help                      Show this help text.
  -h, --host=<str>            Host where aMule is running. (default: 127.0.0.1)
  -p, --port=<num>            aMule's port for External Connection. (default: 4712)
  -P, --password=<str>        External Connection password.
  -f, --config-file=<str>     Read configuration from file.
  -q, --quiet                 Do not print any output to stdout.
  -v, --verbose               Be verbose - show also debug messages.
  -l, --locale=<str>          Sets program locale (language).
  -w, --write-config          Write command line options to config file.
  --create-config-from=<str>  Creates config file based on aMule's config file.
  --version                   Print program version.
  --force-zlib                Force ZLIB compression regardless of dialed-IP locality (useful when the server is reachable over a VPN tunnel that resolves to a LAN IP).
  -c, --command=<str>         Execute <str> and exit.
  --space-separated           Separate list fields with spaces, as before, instead of tabs.
";

/// The command line, as wxCmdLineParser reads amulecmd's.
#[derive(Default, Debug)]
struct Options {
    help: bool,
    host: Option<String>,
    port: Option<String>,
    password: Option<String>,
    config_file: Option<String>,
    quiet: bool,
    write_config: bool,
    create_config_from: Option<String>,
    version: bool,
    force_zlib: bool,
    command: Option<String>,
    space_separated: bool,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        let (name, inline) = if let Some(long) = arg.strip_prefix("--") {
            match long.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (long.to_string(), None),
            }
        } else if let Some(short) = arg.strip_prefix('-').filter(|s| !s.is_empty()) {
            let (c, rest) = short.split_at(short.chars().next().unwrap().len_utf8());
            let long = match c {
                "h" => "host",
                "p" => "port",
                "P" => "password",
                "f" => "config-file",
                "q" => "quiet",
                "v" => "verbose",
                "l" => "locale",
                "w" => "write-config",
                "c" => "command",
                _ => return Err(format!("Unknown option '{arg}'")),
            };
            let rest = rest.strip_prefix('=').unwrap_or(rest);
            (
                long.to_string(),
                (!rest.is_empty()).then(|| rest.to_string()),
            )
        } else {
            return Err(format!("Unexpected parameter '{arg}'"));
        };
        let mut value = || -> Result<String, String> {
            if let Some(v) = &inline {
                return Ok(v.clone());
            }
            let v = args
                .get(i)
                .cloned()
                .ok_or_else(|| format!("Option '{name}' requires a value."))?;
            i += 1;
            Ok(v)
        };
        match name.as_str() {
            "help" => o.help = true,
            "host" => o.host = Some(value()?),
            "port" => o.port = Some(value()?),
            "password" => o.password = Some(value()?),
            "config-file" => o.config_file = Some(value()?),
            "quiet" => o.quiet = true,
            "verbose" => {}
            "locale" => drop(value()?),
            "write-config" => o.write_config = true,
            "create-config-from" => o.create_config_from = Some(value()?),
            "version" => o.version = true,
            "force-zlib" => o.force_zlib = true,
            "command" => o.command = Some(value()?),
            "space-separated" => o.space_separated = true,
            _ => return Err(format!("Unknown long option '{name}'")),
        }
    }
    Ok(o)
}

/// aMule's user data directory.
fn user_config_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map_or_else(PathBuf::new, |d| PathBuf::from(d).join("aMule"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map_or_else(PathBuf::new, |d| {
            PathBuf::from(d).join("Library/Application Support/aMule")
        })
    } else {
        std::env::var_os("HOME").map_or_else(PathBuf::new, |d| PathBuf::from(d).join(".aMule"))
    }
}

/// `GetConfigDir`: `./config` when it holds the file ("portable aMule").
fn config_dir(probe: &str) -> PathBuf {
    let portable = std::env::current_dir().unwrap_or_default().join("config");
    if portable.join(probe).is_file() {
        portable
    } else {
        user_config_dir()
    }
}

/// `FinalizeFilename`: `~/` expanded, a bare name put in the config dir.
fn finalize_filename(name: &str, dir: &Path) -> PathBuf {
    if let Some(rest) = name.strip_prefix("~/").or_else(|| name.strip_prefix("~\\")) {
        if let Some(home) = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }) {
            return PathBuf::from(home).join(rest);
        }
    }
    if cfg!(windows)
        && name.len() >= 2
        && name.as_bytes()[1] == b':'
        && name.as_bytes()[0].is_ascii_alphabetic()
    {
        return PathBuf::from(name);
    }
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    if !name.contains(separators) {
        return dir.join(name);
    }
    PathBuf::from(name)
}

/// `CECFileConfig::ReadHash`: a 32-digit MD5 or nothing.
fn read_hash(conf: &ConfFile, path: &str) -> String {
    match conf.get(path) {
        Some(v) if srp::is_password_digest(v) => v.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// The settings the connection is made with.
struct Settings {
    host: String,
    port: i64,
    /// MD5 hex of the password, lower case; empty for none.
    password: String,
    zlib: bool,
    force_zlib: bool,
    locale: String,
}

impl Settings {
    /// `LoadConfigFile`.
    fn load(conf: &ConfFile) -> Self {
        Settings {
            host: conf.get("/EC/Host").unwrap_or("127.0.0.1").to_string(),
            port: conf.get("/EC/Port").and_then(parse_long).unwrap_or(4712),
            password: read_hash(conf, "/EC/Password"),
            zlib: conf.get("/EC/ZLIB").and_then(parse_long).unwrap_or(1) != 0,
            force_zlib: conf.get("/EC/ForceZLIB").and_then(parse_long).unwrap_or(0) != 0,
            locale: conf.get("/Locale").unwrap_or("").to_string(),
        }
    }

    /// `LoadAmuleConfig`: the daemon's own settings, for `--create-config-from`.
    fn load_amule(&mut self, amule: &ConfFile) {
        self.host = "127.0.0.1".into();
        self.port = amule
            .get("/ExternalConnect/ECPort")
            .and_then(parse_long)
            .unwrap_or(4712);
        // A daemon that keeps only a verifier cannot tell us the password.
        if amule.get("/ExternalConnect/ECPasswordVerifier").is_none() {
            self.password = read_hash(amule, "/ExternalConnect/ECPassword");
        }
        self.locale = amule.get("/eMule/Language").unwrap_or("").to_string();
    }

    /// `SaveConfigFile`.
    fn save(&self, conf: &mut ConfFile) {
        conf.set("/Locale", &self.locale);
        conf.set("/EC/Host", &self.host);
        conf.set("/EC/Port", &self.port.to_string());
        conf.set("/EC/Password", &self.password.to_ascii_uppercase());
        conf.set("/EC/ZLIB", if self.zlib { "1" } else { "0" });
        conf.set("/EC/ForceZLIB", if self.force_zlib { "1" } else { "0" });
        conf.remove("/EC/Encryption");
    }
}

/// `FlushConfigFile`: written, readable by its owner only.
fn write_config(path: &Path, conf: &ConfFile) -> bool {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if std::fs::create_dir_all(parent).is_err() {
            return false;
        }
    }
    let written = std::fs::write(path, conf.to_bytes()).is_ok();
    #[cfg(unix)]
    if written {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    written
}

/// Output, unless `--quiet`.
struct Out {
    quiet: bool,
}

impl Out {
    fn show(&self, s: &str) {
        if !self.quiet && !s.is_empty() {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(s.as_bytes());
            let _ = stdout.flush();
        }
    }
}

/// `GetPassword`: asked for on the terminal.
fn ask_password() -> String {
    let mut stdout = std::io::stdout();
    let _ = write!(stdout, "Enter password for mule connection: ");
    let _ = stdout.flush();
    let mut line = String::new();
    if std::io::stdin().is_terminal() {
        hidden_read_line(&mut line);
        println!();
    } else {
        let _ = std::io::stdin().lock().read_line(&mut line);
    }
    let plain = line.trim_end_matches(['\r', '\n']);
    srp::password_digest(plain)
}

/// One line from the terminal without echoing it.
#[cfg(unix)]
fn hidden_read_line(line: &mut String) {
    let echo_off = std::process::Command::new("stty")
        .arg("-echo")
        .stdin(std::process::Stdio::inherit())
        .status()
        .is_ok_and(|s| s.success());
    let _ = std::io::stdin().lock().read_line(line);
    if echo_off {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();
    }
}

#[cfg(windows)]
fn hidden_read_line(line: &mut String) {
    type Handle = *mut core::ffi::c_void;
    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(console: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(console: Handle, mode: u32) -> i32;
    }
    // SAFETY: plain Win32 console calls on this process's own input handle.
    unsafe {
        let input = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        let got = GetConsoleMode(input, &mut mode) != 0;
        if got {
            SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT);
        }
        let _ = std::io::stdin().lock().read_line(line);
        if got {
            SetConsoleMode(input, mode);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn hidden_read_line(line: &mut String) {
    let _ = std::io::stdin().lock().read_line(line);
}

/// The logged-in client.
struct Conn {
    client: Client,
    alive: bool,
}

impl Link for Conn {
    fn request(&mut self, p: &Packet) -> Result<Packet, Error> {
        let r = self.client.request(p);
        if let Err(e) = &r {
            if e.is_fatal() {
                self.alive = false;
            }
        }
        r
    }

    fn echoed(&self, capability: u16) -> bool {
        self.client.info().echoed(capability)
    }

    fn connected(&self) -> bool {
        self.alive
    }
}

/// `CRemoteConnect`'s explanation of a failed login.
fn server_reply(e: &Error) -> String {
    match e {
        Error::AuthFailed { message, .. } => {
            format!("External Connection: Access denied because: {message}")
        }
        Error::Auth(message) => format!("External Connection: {message}."),
        _ => String::new(),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_options(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    // `-c help...` answers without a daemon.
    if let Some(cmd) = &opts.command {
        if cmd.to_lowercase().starts_with("help") {
            println!("{NAME} {VERSION}");
            let mut app: App<Conn> = App::new(None);
            app.parse_command(cmd);
            print!("{}", app.take_output());
            return ExitCode::SUCCESS;
        }
    }
    if opts.version {
        println!("{NAME} {VERSION}");
        return ExitCode::SUCCESS;
    }

    let dir = config_dir("remote.conf");
    let config_path = finalize_filename(opts.config_file.as_deref().unwrap_or("remote.conf"), &dir);
    let mut conf = std::fs::read(&config_path)
        .map(|b| ConfFile::from_bytes(&b))
        .unwrap_or_default();
    let mut settings = Settings::load(&conf);

    if let Some(amule_conf) = &opts.create_config_from {
        let path = finalize_filename(amule_conf, &user_config_dir());
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("FATAL ERROR: File does not exist: {}", path.display());
            return ExitCode::FAILURE;
        };
        settings.load_amule(&ConfFile::from_bytes(&bytes));
    }
    if let Some(plain) = &opts.password {
        settings.password = if plain.is_empty() {
            String::new()
        } else {
            srp::password_digest(plain)
        };
    }
    if opts.create_config_from.is_some() {
        if settings.password.is_empty() {
            println!(
                "The daemon verifier cannot supply a client password. Use -P or the password prompt."
            );
        }
        settings.save(&mut conf);
        return if write_config(&config_path, &conf) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    if let Some(host) = &opts.host {
        settings.host = host.clone();
    }
    if let Some(port) = &opts.port {
        match parse_long(port) {
            Some(p) => settings.port = p,
            None => {
                eprintln!("'{port}' is not a correct numeric value for option 'port'.\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }
    if opts.force_zlib {
        settings.force_zlib = true;
    }
    if opts.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if opts.write_config {
        settings.save(&mut conf);
        return if write_config(&config_path, &conf) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let out = Out { quiet: opts.quiet };
    let interactive = opts.command.is_none();
    out.show(&format!("This is {NAME} {VERSION}\n"));

    if settings.password.is_empty() {
        settings.password = ask_password();
        if settings.password == EMPTY_MD5 {
            settings.password.clear();
        }
    }
    if settings.password.is_empty() {
        out.show("Cannot connect with an empty password.\nYou must specify a password either in config file\nor on command-line, or enter one when asked.\n\nExiting...\n");
        return ExitCode::SUCCESS;
    }

    out.show("\nCreating client...\n");
    let Ok(port) = u16::try_from(settings.port) else {
        out.show(&format!(
            "Connection Failed. Unable to connect to {}:{}\n",
            settings.host, settings.port
        ));
        return ExitCode::SUCCESS;
    };
    let mut connect = ConnectOptions::new(settings.host.clone(), port, settings.password.clone());
    connect.client_name = NAME.into();
    connect.client_version = VERSION.into();
    connect.connect_timeout = Duration::from_secs(15);
    connect.capabilities = vec![
        EC_TAG_CAN_PARTIAL_UPDATE,
        EC_TAG_CAN_PARTIAL_SEARCH,
        EC_TAG_CAN_SHAREDDIRS_CONFIG,
        EC_TAG_CAN_SEARCH_LIST,
        EC_TAG_CAN_KAD_LOOKUPS,
        // Searches are addressed by the ID the daemon hands out, so several
        // can be kept at once; `progress` without an ID shows the latest one,
        // so not the union.
        EC_TAG_CAN_MULTI_SEARCH,
    ];
    let client = match Client::connect(&connect) {
        Ok(c) => c,
        Err(e) => {
            let reply = server_reply(&e);
            if !reply.is_empty() {
                out.show(&format!("{reply}\n"));
            }
            out.show(&format!(
                "Connection Failed. Unable to connect to {}:{}\n",
                settings.host, settings.port
            ));
            return ExitCode::SUCCESS;
        }
    };
    let version = client.info().version.clone();
    out.show(&if version.is_empty() {
        "Succeeded! Connection established.\n".to_string()
    } else {
        format!("Succeeded! Connection established to aMule {version}\n")
    });

    let mut app = App::new(Some(Conn {
        client,
        alive: true,
    }));
    app.space_separated = opts.space_separated;

    if let Some(cmd) = &opts.command {
        app.parse_command(cmd);
        out.show(&app.take_output());
        return ExitCode::SUCCESS;
    }

    if interactive {
        let rule = "-".repeat(22 + GREETING.chars().count());
        out.show(&format!(
            "\n{rule}\n|{pad}{GREETING}{pad}|\n{rule}\n\nUse 'Help' for command list\n\n",
            pad = " ".repeat(10)
        ));
    }
    let stdin = std::io::stdin();
    let mut lines = stdin.lock();
    loop {
        out.show(&format!("{NAME}$ "));
        let mut line = String::new();
        let line = match lines.read_line(&mut line) {
            Ok(0) | Err(_) => "quit".to_string(),
            Ok(_) => line,
        };
        let quit = app.parse_command(&line);
        out.show(&app.take_output());
        if quit || !app.connected() {
            break;
        }
    }
    out.show(&format!("\nOk, exiting {NAME}...\n"));
    ExitCode::SUCCESS
}
