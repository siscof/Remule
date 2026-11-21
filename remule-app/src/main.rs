// SPDX-License-Identifier: GPL-2.0-or-later
//! Remule for Windows, the one program to double-click.
//!
//! It keeps its own config folder (`%APPDATA%\remule\daemon`, never
//! aMule's; `remule-gui` keeps its window state beside it, in `data`), so
//! it can sit beside an aMule install. The first time, it makes that
//! folder an External Connections password and a free local port (kept in
//! `launcher.conf`; `remuled` stores only a verifier of the password in
//! `amule.conf`). Then it starts `remuled` (no console window, its output
//! in `remuled.log`), opens `remule-gui` connected to it, and when the
//! window is closed asks `remuled` to stop and save over EC.
//!
//! `remuled.exe` and `remule-gui.exe` are looked for beside this program.
//! A `remuled` already running on the port (started by an earlier launch)
//! is used as it is, and left running.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed2k_formats::amule_conf::{keys, ConfFile};
use rand::Rng;

/// The EC port tried first: aMule's.
const DEFAULT_EC_PORT: u16 = 4712;
/// How long `remuled` gets to open its EC port.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long it gets to save and stop.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

/// What the launcher keeps: where `remuled` listens and the password.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Launch {
    port: u16,
    password: String,
}

impl Launch {
    fn parse(text: &str) -> Option<Launch> {
        let conf = ConfFile::parse(text);
        Some(Launch {
            port: conf.get("/Launcher/Port")?.parse().ok()?,
            password: conf.get("/Launcher/Password")?.to_owned(),
        })
    }

    fn write(&self) -> String {
        format!(
            "# Made by Remule.exe: how it reaches the remuled it starts.\n\
             [Launcher]\nPort={}\nPassword={}\n",
            self.port, self.password
        )
    }
}

/// A port nothing listens on, aMule's if it is free.
fn free_port() -> Result<u16, String> {
    if TcpListener::bind(("127.0.0.1", DEFAULT_EC_PORT)).is_ok() {
        return Ok(DEFAULT_EC_PORT);
    }
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("no free local port: {e}"))
}

fn random_password() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::rngs::OsRng;
    (0..24)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// The config folder ready for this launch: the launcher's settings made
/// the first time, and `amule.conf` taking external connections on
/// them. A new password is set as aMule's legacy `ECPassword` digest,
/// which `remuled` turns into a verifier at start.
fn prepare(dir: &Path) -> Result<Launch, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let state = dir.join("launcher.conf");
    let conf_path = dir.join("amule.conf");
    let mut conf = match std::fs::read(&conf_path) {
        Ok(b) => ConfFile::from_bytes(&b),
        Err(_) => ConfFile::new(),
    };
    let existing = std::fs::read_to_string(&state)
        .ok()
        .and_then(|t| Launch::parse(&t));
    let launch = match existing {
        Some(l) => l,
        None => {
            let l = Launch {
                port: free_port()?,
                password: random_password(),
            };
            conf.remove(keys::EC_PASSWORD_VERIFIER);
            conf.set(
                keys::EC_PASSWORD_LEGACY,
                &remule_ec::srp::password_digest(&l.password),
            );
            std::fs::write(&state, l.write()).map_err(|e| format!("{}: {e}", state.display()))?;
            l
        }
    };
    // Only from this PC, on the launcher's port.
    conf.set(keys::ACCEPT_EXTERNAL_CONNECTIONS, "1");
    conf.set(keys::EC_ADDRESS, "127.0.0.1");
    conf.set(keys::EC_PORT, &launch.port.to_string());
    std::fs::write(&conf_path, conf.to_bytes())
        .map_err(|e| format!("{}: {e}", conf_path.display()))?;
    Ok(launch)
}

fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(300),
    )
    .is_ok()
}

/// No console window for a child.
fn hidden(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

fn tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// Start `remuled` on `dir`, its output appended to `remuled.log`, and
/// wait for its EC port.
fn start_daemon(exe: &Path, dir: &Path, port: u16) -> Result<Child, String> {
    let log_path = dir.join("remuled.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("{}: {e}", log_path.display()))?;
    let err = log.try_clone().map_err(|e| e.to_string())?;
    let mut child = hidden(
        Command::new(exe)
            .arg("--config-dir")
            .arg(dir)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(err),
    )
    .spawn()
    .map_err(|e| format!("could not start {}: {e}", exe.display()))?;
    let start = Instant::now();
    while start.elapsed() < START_TIMEOUT {
        if listening(port) {
            return Ok(child);
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "remuled stopped at start ({status}). The end of {}:\n\n{}",
                log_path.display(),
                tail(&log_path, 15)
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = child.kill();
    Err(format!(
        "remuled did not open its port {port} in {} s. The end of {}:\n\n{}",
        START_TIMEOUT.as_secs(),
        log_path.display(),
        tail(&log_path, 15)
    ))
}

/// Ask `remuled` to save and stop over EC, as `amulecmd shutdown` does;
/// if that fails or it does not stop in time, end it.
fn stop_daemon(mut child: Child, launch: &Launch) {
    let mut opts = remule_ec::ConnectOptions::new(
        "127.0.0.1",
        launch.port,
        remule_ec::srp::password_digest(&launch.password),
    );
    opts.client_name = "Remule.exe".into();
    if let Ok(mut c) = remule_ec::Client::connect(&opts) {
        let _ = c.request(&remule_ec::Packet::new(remule_ec::codes::EC_OP_SHUTDOWN));
    }
    let start = Instant::now();
    while start.elapsed() < STOP_TIMEOUT {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = child.kill();
}

fn run() -> Result<(), String> {
    let here = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let (daemon, gui) = (here.join("remuled.exe"), here.join("remule-gui.exe"));
    for f in [&daemon, &gui] {
        if !f.is_file() {
            return Err(format!(
                "{} is missing: keep the files of the zip together.",
                f.display()
            ));
        }
    }
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .ok_or("APPDATA is not set")?;
    let dir = base.join("remule").join("daemon");
    let launch = prepare(&dir)?;
    // One started by an earlier launch keeps running.
    let child = if listening(launch.port) {
        None
    } else {
        Some(start_daemon(&daemon, &dir, launch.port)?)
    };
    let status = Command::new(&gui)
        .args(["-h", "127.0.0.1", "-p"])
        .arg(launch.port.to_string())
        .arg("-P")
        .arg(&launch.password)
        .status()
        .map_err(|e| format!("could not start {}: {e}", gui.display()));
    if let Some(c) = child {
        stop_daemon(c, &launch);
    }
    status.map(|_| ())
}

#[cfg(windows)]
fn show_error(text: &str) {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: *mut u8, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (t, c) = (wide(text), wide("Remule"));
    // MB_ICONERROR
    unsafe {
        MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), 0x10);
    }
}

#[cfg(not(windows))]
fn show_error(text: &str) {
    eprintln!("Remule: {text}");
}

fn main() {
    if let Err(e) = run() {
        show_error(&e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp(name: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!("remule-app-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        TempDir(p)
    }

    #[test]
    fn the_first_launch_sets_up_external_connections_once() {
        let d = temp("first");
        let l = prepare(&d.0).unwrap();
        assert_eq!(l.password.len(), 24);
        let conf = ConfFile::parse(&std::fs::read_to_string(d.0.join("amule.conf")).unwrap());
        assert_eq!(conf.get(keys::ACCEPT_EXTERNAL_CONNECTIONS), Some("1"));
        assert_eq!(conf.get(keys::EC_ADDRESS), Some("127.0.0.1"));
        assert_eq!(conf.get(keys::EC_PORT), Some(l.port.to_string().as_str()));
        let digest = remule_ec::srp::password_digest(&l.password);
        assert_eq!(conf.get(keys::EC_PASSWORD_LEGACY), Some(digest.as_str()));
        // remuled has since migrated the password: the next launch keeps
        // its settings and the verifier.
        let mut migrated = conf.clone();
        migrated.remove(keys::EC_PASSWORD_LEGACY);
        migrated.set(keys::EC_PASSWORD_VERIFIER, "v1:kept");
        migrated.set("/eMule/Nick", "a friend");
        std::fs::write(d.0.join("amule.conf"), migrated.to_bytes()).unwrap();
        assert_eq!(prepare(&d.0).unwrap(), l);
        let conf = ConfFile::parse(&std::fs::read_to_string(d.0.join("amule.conf")).unwrap());
        assert_eq!(conf.get(keys::EC_PASSWORD_VERIFIER), Some("v1:kept"));
        assert_eq!(conf.get(keys::EC_PASSWORD_LEGACY), None);
        assert_eq!(conf.get("/eMule/Nick"), Some("a friend"));
    }

    #[test]
    fn a_lost_launcher_file_sets_a_new_password() {
        let d = temp("lost");
        let first = prepare(&d.0).unwrap();
        std::fs::remove_file(d.0.join("launcher.conf")).unwrap();
        let second = prepare(&d.0).unwrap();
        assert_ne!(first.password, second.password);
        let conf = ConfFile::parse(&std::fs::read_to_string(d.0.join("amule.conf")).unwrap());
        assert_eq!(
            conf.get(keys::EC_PASSWORD_LEGACY),
            Some(remule_ec::srp::password_digest(&second.password).as_str())
        );
        assert_eq!(conf.get(keys::EC_PASSWORD_VERIFIER), None);
    }

    #[test]
    fn the_launcher_file_reads_back() {
        let l = Launch {
            port: 4799,
            password: "abc".into(),
        };
        assert_eq!(Launch::parse(&l.write()), Some(l));
        assert_eq!(Launch::parse("[Launcher]\nPort=x\n"), None);
    }
}
