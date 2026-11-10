// SPDX-License-Identifier: GPL-2.0-or-later
//! The main window: toolbar, pages, status bar, and the connect dialog.
//!
//! Layout follows aMule's `CamuleDlg` (amuleDlg.cpp): a toolbar that switches
//! between Networks / Searches / Transfers / Shared files / Statistics, and a
//! status bar with the last log line, user/file counts, speeds and the eD2k /
//! Kad connection state. The connect dialog stands in for amulegui's
//! `CEConnectDlg`.

use std::collections::VecDeque;
use std::time::Instant;

use eframe::egui::{self, Color32, RichText};
use remule_ec::model::{
    PartFile, SearchKind, SearchProgress, SearchResult, Server, SharedFile, Stats,
};
use remule_ec::{srp, ConnectOptions, ServerInfo};

use crate::table::TableState;
use crate::worker::{Page, Update, Worker};

/// What survives a restart (eframe storage).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub remember_password: bool,
    /// MD5 hex of the EC password, only when `remember_password`. It is a
    /// login credential, the same thing amulegui keeps in remote.conf.
    pub password_digest: Option<String>,
    pub page: Page,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            host: "localhost".into(),
            port: 4712,
            remember_password: false,
            password_digest: None,
            page: Page::Transfers,
        }
    }
}

pub enum Conn {
    Disconnected { error: Option<String> },
    Connecting,
    Connected(ServerInfo),
}

/// Speed history for the statistics graph: (seconds since start, down, up).
pub const HISTORY_LEN: usize = 600;

pub struct App {
    pub settings: Settings,
    pub worker: Worker,
    pub conn: Conn,
    pub password: String,
    pub started: Instant,

    pub stats: Option<Stats>,
    pub history: VecDeque<(f64, f64, f64)>,
    pub log: VecDeque<String>,
    pub notices: VecDeque<(Instant, bool, String)>,

    pub downloads: Vec<PartFile>,
    pub downloads_table: TableState,
    pub link_input: String,
    pub confirm_cancel: Option<Vec<(remule_ec::model::Hash, u32, String)>>,

    pub shared: Vec<SharedFile>,
    pub shared_table: TableState,

    pub servers: Vec<Server>,
    pub servers_table: TableState,
    pub new_server_addr: String,
    pub new_server_name: String,

    pub search_results: Vec<SearchResult>,
    pub search_progress: SearchProgress,
    pub search_table: TableState,
    pub search: SearchForm,
}

pub struct SearchForm {
    pub text: String,
    pub kind: SearchKind,
    pub file_type: usize,
    pub extension: String,
    pub min_mb: String,
    pub max_mb: String,
    pub availability: String,
    pub running: bool,
}

const MAX_LOG: usize = 5000;

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, args: crate::Args) -> Self {
        let mut settings: Settings = cc
            .storage
            .and_then(|s| eframe::get_value(s, eframe::APP_KEY))
            .unwrap_or_default();
        if let Some(h) = args.host {
            settings.host = h;
        }
        if let Some(p) = args.port {
            settings.port = p;
        }
        if let Some(p) = args.page {
            settings.page = p;
        }
        let worker = Worker::spawn(cc.egui_ctx.clone());
        worker.set_page(settings.page);
        let mut app = App {
            settings,
            worker,
            conn: Conn::Disconnected { error: None },
            password: String::new(),
            started: Instant::now(),
            stats: None,
            history: VecDeque::with_capacity(HISTORY_LEN),
            log: VecDeque::new(),
            notices: VecDeque::new(),
            downloads: Vec::new(),
            downloads_table: TableState::sorted_by(0, false),
            link_input: String::new(),
            confirm_cancel: None,
            shared: Vec::new(),
            shared_table: TableState::sorted_by(0, false),
            servers: Vec::new(),
            servers_table: TableState::sorted_by(2, true),
            new_server_addr: String::new(),
            new_server_name: String::new(),
            search_results: Vec::new(),
            search_progress: SearchProgress::default(),
            search_table: TableState::sorted_by(2, true),
            search: SearchForm {
                text: String::new(),
                kind: SearchKind::All,
                file_type: 0,
                extension: String::new(),
                min_mb: String::new(),
                max_mb: String::new(),
                availability: String::new(),
                running: false,
            },
        };
        // Like amulegui with a saved or given password: connect straight away.
        if let Some(pw) = args.password {
            app.password = pw;
            app.connect();
        } else if app.settings.remember_password && app.settings.password_digest.is_some() {
            app.connect();
        }
        app
    }

    fn connect(&mut self) {
        let digest = if self.password.is_empty() {
            match &self.settings.password_digest {
                Some(d) => d.clone(),
                None => srp::password_digest(""),
            }
        } else {
            srp::password_digest(&self.password)
        };
        self.settings.password_digest = self.settings.remember_password.then(|| digest.clone());
        self.password.clear();
        self.conn = Conn::Connecting;
        self.worker.connect(ConnectOptions::new(
            self.settings.host.trim(),
            self.settings.port,
            digest,
        ));
    }

    pub fn notify(&mut self, ok: bool, text: impl Into<String>) {
        self.notices.push_back((Instant::now(), ok, text.into()));
        while self.notices.len() > 4 {
            self.notices.pop_front();
        }
    }

    fn drain_updates(&mut self) {
        while let Ok(u) = self.worker.rx.try_recv() {
            match u {
                Update::Connected(info) => {
                    self.log.push_back(format!(
                        "Connected to aMule {} ({})",
                        info.version, info.cipher
                    ));
                    self.conn = Conn::Connected(info);
                }
                Update::ConnectFailed(e) => self.conn = Conn::Disconnected { error: Some(e) },
                Update::Lost(e) => {
                    self.conn = Conn::Disconnected {
                        error: Some(format!("Connection lost: {e}")),
                    };
                    self.stats = None;
                }
                Update::Stats(s) => {
                    let t = self.started.elapsed().as_secs_f64();
                    self.history.push_back((
                        t,
                        s.dl_speed as f64 / 1024.0,
                        s.ul_speed as f64 / 1024.0,
                    ));
                    while self.history.len() > HISTORY_LEN {
                        self.history.pop_front();
                    }
                    for l in &s.new_log_lines {
                        self.log.extend(l.lines().map(str::to_owned));
                    }
                    while self.log.len() > MAX_LOG {
                        self.log.pop_front();
                    }
                    self.stats = Some(*s);
                }
                Update::Downloads(d) => {
                    self.downloads_table
                        .retain(|id| d.iter().any(|f| u64::from(f.ecid) == id));
                    self.downloads = d;
                }
                Update::Shared(s) => {
                    self.shared_table
                        .retain(|id| s.iter().any(|f| u64::from(f.ecid) == id));
                    self.shared = s;
                }
                Update::Servers(s) => {
                    self.servers_table
                        .retain(|id| s.iter().any(|x| crate::pages::server_id(x) == id));
                    self.servers = s;
                }
                Update::Search(r, p) => {
                    self.search.running = !p.finished && self.search.running;
                    self.search_table
                        .retain(|id| r.iter().any(|x| u64::from(x.ecid) == id));
                    self.search_results = r;
                    self.search_progress = p;
                }
                Update::Notice { ok, text } => self.notify(ok, text),
            }
        }
    }

    pub fn connected(&self) -> bool {
        matches!(self.conn, Conn::Connected(_))
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().button_padding = egui::vec2(10.0, 6.0);
            let conn = self
                .stats
                .as_ref()
                .map(|s| s.conn.clone())
                .unwrap_or_default();
            let online = conn.ed2k_connected() || conn.ed2k_connecting() || conn.kad_running();
            ui.add_enabled_ui(self.connected(), |ui| {
                if online {
                    if ui
                        .button(RichText::new("⏹ Disconnect").size(15.0))
                        .on_hover_text("Disconnect from eD2k and Kad")
                        .clicked()
                    {
                        self.worker
                            .job(|c| c.disconnect_all().map(|()| String::new()));
                    }
                } else if ui
                    .button(RichText::new("▶ Connect").size(15.0))
                    .on_hover_text("Connect to eD2k and Kad")
                    .clicked()
                {
                    self.worker.job(|c| c.connect_all().map(|()| String::new()));
                }
            });
            ui.separator();
            for (page, label) in [
                (Page::Networks, "🌐 Networks"),
                (Page::Searches, "🔍 Searches"),
                (Page::Transfers, "⬇ Transfers"),
                (Page::Shared, "📂 Shared files"),
                (Page::Statistics, "📊 Statistics"),
            ] {
                if ui
                    .selectable_label(self.settings.page == page, RichText::new(label).size(15.0))
                    .clicked()
                {
                    self.settings.page = page;
                    self.worker.set_page(page);
                    if page == Page::Shared {
                        self.worker.refresh_shared();
                    }
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Conn::Connected(info) = &self.conn {
                    let detail = format!(
                        "Daemon {}:{}, aMule {}\nEncrypted with {} (X25519 key exchange, SRP login)",
                        self.settings.host, self.settings.port, info.version, info.cipher
                    );
                    if ui.small_button("⏏ Daemon").on_hover_text(format!("{detail}\n\nClick to disconnect from the daemon")).clicked() {
                        self.worker.disconnect();
                        self.conn = Conn::Disconnected { error: None };
                        self.stats = None;
                        return;
                    }
                    ui.label(RichText::new(format!("🔒 {}", self.settings.host)).weak()).on_hover_text(detail);
                }
            });
        });
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let Some(s) = &self.stats else {
                ui.label("Not connected to a daemon");
                return;
            };
            let dot = |ui: &mut egui::Ui, on: bool, warn: bool, label: &str| {
                let c = if !on {
                    Color32::from_rgb(200, 60, 60)
                } else if warn {
                    Color32::from_rgb(220, 170, 40)
                } else {
                    Color32::from_rgb(60, 170, 80)
                };
                // Right-to-left layout: the label first puts the dot before it.
                ui.label(label);
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.5, c);
            };
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let c = &s.conn;
                let kad = if !c.kad_enabled {
                    "Kad: disabled"
                } else if c.kad_connected() {
                    if c.kad_firewalled() {
                        "Kad: firewalled"
                    } else {
                        "Kad: connected"
                    }
                } else if c.kad_running() {
                    "Kad: connecting"
                } else {
                    "Kad: off"
                };
                dot(ui, c.kad_connected(), c.kad_firewalled(), kad);
                ui.separator();
                let ed2k = if !c.ed2k_enabled {
                    "eD2k: disabled".to_owned()
                } else if c.ed2k_connected() {
                    let name = c
                        .server
                        .as_ref()
                        .map(|s| s.name.clone())
                        .unwrap_or_default();
                    format!(
                        "eD2k: {} {name}",
                        if c.low_id() { "low ID" } else { "high ID" }
                    )
                } else if c.ed2k_connecting() {
                    "eD2k: connecting".into()
                } else {
                    "eD2k: not connected".into()
                };
                dot(ui, c.ed2k_connected(), c.low_id(), &ed2k);
                ui.separator();
                ui.label(format!(
                    "Up: {}  Down: {}",
                    crate::fmt::speed(s.ul_speed),
                    crate::fmt::speed(s.dl_speed)
                ));
                ui.separator();
                ui.label(format!(
                    "Users: {}  Files: {}",
                    s.ed2k_users + s.kad_users,
                    s.ed2k_files + s.kad_files
                ));
                ui.separator();
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    if let Some(l) = self.log.back() {
                        ui.add(egui::Label::new(l.as_str()).truncate());
                    }
                });
            });
        });
    }

    fn connect_dialog(&mut self, ctx: &egui::Context) {
        let connecting = matches!(self.conn, Conn::Connecting);
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.15);
                ui.heading("remule");
                ui.label("Connect to an aMule daemon (amuled) over External Connections");
                ui.add_space(16.0);
            });
            const FORM_WIDTH: f32 = 420.0;
            let margin = ((ui.available_width() - FORM_WIDTH) / 2.0).max(0.0);
            ui.horizontal(|ui| {
            ui.add_space(margin);
            ui.vertical(|ui| {
            egui::Frame::group(ui.style()).inner_margin(16.0).show(ui, |ui| {
                ui.set_width(FORM_WIDTH - 32.0);
                egui::Grid::new("connect").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label("Host");
                    ui.add_enabled(!connecting, egui::TextEdit::singleline(&mut self.settings.host).desired_width(240.0));
                    ui.end_row();
                    ui.label("Port");
                    ui.add_enabled(!connecting, egui::DragValue::new(&mut self.settings.port).range(1..=65535));
                    ui.end_row();
                    ui.label("Password");
                    let hint = if self.settings.password_digest.is_some() { "(saved)" } else { "" };
                    let pw = ui.add_enabled(
                        !connecting,
                        egui::TextEdit::singleline(&mut self.password).password(true).hint_text(hint).desired_width(240.0),
                    );
                    if pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !connecting {
                        self.connect();
                    }
                    ui.end_row();
                    ui.label("");
                    ui.checkbox(&mut self.settings.remember_password, "Remember password")
                        .on_hover_text("Stores the password's MD5 digest, which is enough to log in, in remule's settings.");
                    ui.end_row();
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if connecting {
                        ui.spinner();
                        ui.label("Connecting and authenticating…");
                    } else if ui.button(RichText::new("Connect").size(15.0)).clicked() {
                        self.connect();
                    }
                });
                if let Conn::Disconnected { error: Some(e) } = &self.conn {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::from_rgb(210, 70, 70), e);
                }
            });
            ui.add_space(8.0);
            ui.label(
                RichText::new("Needs aMule 3.3 or later with External Connections enabled (amuled --ec-config).")
                    .weak()
                    .small(),
            );
            });
            });
        });
    }

    fn notices(&mut self, ctx: &egui::Context) {
        self.notices.retain(|(t, _, _)| t.elapsed().as_secs() < 6);
        if self.notices.is_empty() {
            return;
        }
        egui::Area::new(egui::Id::new("notices"))
            .anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -36.0])
            .show(ctx, |ui| {
                for (_, ok, text) in &self.notices {
                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                        ui.set_max_width(360.0);
                        let c = if *ok {
                            ui.visuals().text_color()
                        } else {
                            Color32::from_rgb(220, 80, 80)
                        };
                        ui.colored_label(c, text);
                    });
                }
            });
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_updates();
        if !self.connected() {
            self.connect_dialog(ctx);
            return;
        }
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            self.toolbar(ui);
            ui.add_space(2.0);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));
        egui::CentralPanel::default().show(ctx, |ui| match self.settings.page {
            Page::Networks => self.networks_page(ui),
            Page::Searches => self.search_page(ui),
            Page::Transfers => self.transfers_page(ui),
            Page::Shared => self.shared_page(ui),
            Page::Statistics => self.statistics_page(ui),
        });
        self.cancel_dialog(ctx);
        self.notices(ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if !self.settings.remember_password {
            self.settings.password_digest = None;
        }
        eframe::set_value(storage, eframe::APP_KEY, &self.settings);
    }
}
