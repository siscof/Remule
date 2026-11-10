// SPDX-License-Identifier: GPL-2.0-or-later
//! The five pages of the main window. Each one corresponds to an aMule window:
//!
//! | Page        | aMule                                                  |
//! |-------------|--------------------------------------------------------|
//! | Networks    | `ServerWnd` + `ServerListCtrl`, Kad panel, log          |
//! | Searches    | `SearchDlg` + `SearchListCtrl`                          |
//! | Transfers   | `TransferWnd` + `DownloadListCtrl`, fast ed2k links     |
//! | Shared      | `SharedFilesWnd` + `SharedFilesCtrl`                    |
//! | Statistics  | `StatisticsDlg` (speed graphs + counters)               |

use eframe::egui::{self, Color32, RichText, Ui};
use egui_extras::Column;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use remule_ec::model::{
    self, PartFile, PartFileCmd, SearchKind, SearchParams, SearchResult, Server, SharedFile,
    FILE_TYPES,
};

use crate::app::App;
use crate::fmt;
use crate::table::{self, by_name, right, Col};

pub fn server_id(s: &Server) -> u64 {
    (u64::from(u32::from_be_bytes(s.ip)) << 16) | u64::from(s.port)
}

fn selected<'a, T>(
    items: &'a [T],
    sel: &std::collections::BTreeSet<u64>,
    id: fn(&T) -> u64,
) -> Vec<&'a T> {
    items.iter().filter(|x| sel.contains(&id(x))).collect()
}

fn copy(ui: &Ui, text: String) {
    ui.output_mut(|o| o.copied_text = text);
}

// ------------------------------------------------------------- Transfers ---

fn pf_id(f: &PartFile) -> u64 {
    u64::from(f.ecid)
}

fn download_cols() -> Vec<Col<PartFile>> {
    vec![
        Col {
            title: "File name",
            width: Column::remainder().at_least(200.0).clip(true),
            cmp: |a, b| by_name(&a.name, &b.name),
            show: |ui, f| {
                ui.label(&f.name).on_hover_text(&f.name);
            },
        },
        Col {
            title: "Size",
            width: Column::initial(80.0),
            cmp: |a, b| a.size.cmp(&b.size),
            show: |ui, f| right(ui, fmt::bytes(f.size)),
        },
        Col {
            title: "Completed",
            width: Column::initial(80.0),
            cmp: |a, b| a.completed.cmp(&b.completed),
            show: |ui, f| right(ui, fmt::bytes(f.completed)),
        },
        Col {
            title: "Speed",
            width: Column::initial(80.0),
            cmp: |a, b| a.speed.cmp(&b.speed),
            show: |ui, f| {
                right(
                    ui,
                    if f.speed > 0 {
                        fmt::speed(f.speed)
                    } else {
                        String::new()
                    },
                )
            },
        },
        Col {
            title: "Progress",
            width: Column::initial(150.0),
            cmp: |a, b| a.progress().total_cmp(&b.progress()),
            show: |ui, f| {
                let color = if f.stopped || f.status == model::PS_PAUSED {
                    Color32::GRAY
                } else {
                    Color32::from_rgb(70, 140, 220)
                };
                ui.add(
                    egui::ProgressBar::new(f.progress())
                        .fill(color)
                        .text(format!("{:.1}%", f.progress() * 100.0)),
                );
            },
        },
        Col {
            title: "Sources",
            width: Column::initial(80.0),
            cmp: |a, b| a.sources.cmp(&b.sources),
            show: |ui, f| {
                let mut s = format!("{}", f.sources.saturating_sub(f.sources_not_current));
                if f.sources_not_current > 0 {
                    s += &format!("/{}", f.sources);
                }
                if f.sources_xfer > 0 {
                    s += &format!(" ({})", f.sources_xfer);
                }
                if f.sources_a4af > 0 {
                    s += &format!(" +{}", f.sources_a4af);
                }
                right(ui, s)
            },
        },
        Col {
            title: "Priority",
            width: Column::initial(90.0),
            cmp: |a, b| a.priority.cmp(&b.priority),
            show: |ui, f| {
                ui.label(model::priority_text(f.priority));
            },
        },
        Col {
            title: "Status",
            width: Column::initial(100.0),
            cmp: |a, b| a.status_text().cmp(b.status_text()),
            show: |ui, f| {
                ui.label(f.status_text());
            },
        },
        Col {
            title: "Time left",
            width: Column::initial(80.0),
            cmp: |a, b| {
                let left = |f: &PartFile| {
                    f.size
                        .saturating_sub(f.completed)
                        .checked_div(f.speed)
                        .unwrap_or(u64::MAX)
                };
                left(a).cmp(&left(b))
            },
            show: |ui, f| right(ui, fmt::eta(f.size.saturating_sub(f.completed), f.speed)),
        },
    ]
}

impl App {
    pub fn transfers_page(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("ed2k link:");
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.link_input)
                    .hint_text(
                        "ed2k://|file|…|/   (several links: one per line or space-separated)",
                    )
                    .desired_width(ui.available_width() - 70.0),
            );
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (ui.button("Add").clicked() || enter) && !self.link_input.trim().is_empty() {
                let links: Vec<String> = self
                    .link_input
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect();
                let n = links.len();
                self.worker
                    .job(move |c| c.add_links(&links).map(|()| format!("Added {n} link(s)")));
                self.link_input.clear();
            }
        });
        ui.add_space(2.0);

        let sel: Vec<(model::Hash, u32, String)> =
            selected(&self.downloads, &self.downloads_table.selected, pf_id)
                .into_iter()
                .map(|f| (f.hash, f.ecid, f.name.clone()))
                .collect();
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!sel.is_empty(), |ui| {
                self.partfile_buttons(ui, &sel);
            });
            ui.separator();
            let done: Vec<u32> = self
                .downloads
                .iter()
                .filter(|f| f.is_complete())
                .map(|f| f.ecid)
                .collect();
            if ui
                .add_enabled(!done.is_empty(), egui::Button::new("Clear completed"))
                .clicked()
            {
                self.worker
                    .job(move |c| c.clear_completed(&done).map(|()| String::new()));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let total: u64 = self.downloads.iter().map(|f| f.speed).sum();
                ui.label(format!(
                    "{} downloads · {}",
                    self.downloads.len(),
                    fmt::speed(total)
                ));
                if let Some(free) = self.stats.as_ref().and_then(|s| s.temp_free) {
                    ui.label(RichText::new(format!("Temp free: {}  ·", fmt::bytes(free))).weak());
                }
            });
        });
        ui.separator();

        let cols = download_cols();
        let mut action: Option<(PartFileCmd, Vec<(model::Hash, u32)>)> = None;
        let mut prio: Option<u8> = None;
        let mut cancel = false;
        let mut copy_links: Option<String> = None;
        let downloads = &self.downloads;
        let dbl = table::show(
            ui,
            "downloads",
            &mut self.downloads_table,
            downloads,
            pf_id,
            &cols,
            |ui, _f, sel| {
                let targets: Vec<(model::Hash, u32)> = downloads
                    .iter()
                    .filter(|f| sel.contains(&pf_id(f)))
                    .map(|f| (f.hash, f.ecid))
                    .collect();
                for (label, cmd) in [
                    ("Pause", PartFileCmd::Pause),
                    ("Resume", PartFileCmd::Resume),
                    ("Stop", PartFileCmd::Stop),
                ] {
                    if ui.button(label).clicked() {
                        action = Some((cmd, targets.clone()));
                        ui.close_menu();
                    }
                }
                ui.menu_button("Priority", |ui| {
                    for (label, p) in [
                        ("Low", model::PR_LOW),
                        ("Normal", model::PR_NORMAL),
                        ("High", model::PR_HIGH),
                        ("Auto", model::PR_AUTO),
                    ] {
                        if ui.button(label).clicked() {
                            prio = Some(p);
                            ui.close_menu();
                        }
                    }
                });
                ui.separator();
                if ui.button("Copy ed2k link").clicked() {
                    copy_links = Some(
                        downloads
                            .iter()
                            .filter(|f| sel.contains(&pf_id(f)))
                            .map(|f| f.ed2k_link.clone())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Cancel…").clicked() {
                    cancel = true;
                    ui.close_menu();
                }
            },
        );
        if let Some(i) = dbl {
            // Double-click toggles pause, like the download list's default action.
            let f = &self.downloads[i];
            let cmd = if f.status == model::PS_PAUSED || f.stopped {
                PartFileCmd::Resume
            } else {
                PartFileCmd::Pause
            };
            action = Some((cmd, vec![(f.hash, f.ecid)]));
        }
        if let Some((cmd, t)) = action {
            self.worker
                .job(move |c| c.partfile_cmd(cmd, &t).map(|()| String::new()));
        }
        if let Some(p) = prio {
            let t: Vec<_> = sel.iter().map(|(h, id, _)| (*h, *id)).collect();
            self.worker
                .job(move |c| c.set_download_priority(&t, p).map(|()| String::new()));
        }
        if cancel {
            self.confirm_cancel = Some(sel);
        }
        if let Some(text) = copy_links {
            copy(ui, text);
            self.notify(true, "ed2k link copied");
        }
    }

    fn partfile_buttons(&mut self, ui: &mut Ui, sel: &[(model::Hash, u32, String)]) {
        let targets: Vec<(model::Hash, u32)> = sel.iter().map(|(h, id, _)| (*h, *id)).collect();
        for (label, cmd) in [
            ("⏸ Pause", PartFileCmd::Pause),
            ("▶ Resume", PartFileCmd::Resume),
            ("⏹ Stop", PartFileCmd::Stop),
        ] {
            if ui.button(label).clicked() {
                let t = targets.clone();
                self.worker
                    .job(move |c| c.partfile_cmd(cmd, &t).map(|()| String::new()));
            }
        }
        if ui.button("✖ Cancel").clicked() {
            self.confirm_cancel = Some(sel.to_vec());
        }
        egui::ComboBox::from_id_salt("prio")
            .selected_text("Priority")
            .show_ui(ui, |ui| {
                for (label, p) in [
                    ("Low", model::PR_LOW),
                    ("Normal", model::PR_NORMAL),
                    ("High", model::PR_HIGH),
                    ("Auto", model::PR_AUTO),
                ] {
                    if ui.selectable_label(false, label).clicked() {
                        let t = targets.clone();
                        self.worker
                            .job(move |c| c.set_download_priority(&t, p).map(|()| String::new()));
                    }
                }
            });
    }

    /// aMule asks before cancelling: the partial data is deleted.
    pub fn cancel_dialog(&mut self, ctx: &egui::Context) {
        let Some(files) = &self.confirm_cancel else {
            return;
        };
        let mut close = false;
        egui::Window::new("Cancel downloads?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!(
                    "Cancel {} download(s) and delete what was downloaded so far?",
                    files.len()
                ));
                for (_, _, name) in files.iter().take(8) {
                    ui.label(RichText::new(name).weak());
                }
                if files.len() > 8 {
                    ui.label(RichText::new(format!("… and {} more", files.len() - 8)).weak());
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .button(
                            RichText::new("Cancel downloads").color(Color32::from_rgb(220, 80, 80)),
                        )
                        .clicked()
                    {
                        let t: Vec<_> = files.iter().map(|(h, id, _)| (*h, *id)).collect();
                        self.worker.job(move |c| {
                            c.partfile_cmd(PartFileCmd::Cancel, &t)
                                .map(|()| String::new())
                        });
                        close = true;
                    }
                    if ui.button("Keep them").clicked() {
                        close = true;
                    }
                });
            });
        if close {
            self.confirm_cancel = None;
        }
    }

    // --------------------------------------------------------- Shared ---

    pub fn shared_page(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui
                .button("⟳ Reload")
                .on_hover_text("Rescan the shared folders on the daemon")
                .clicked()
            {
                self.worker.job(|c| {
                    c.shared_reload()
                        .map(|()| "Reloading shared files".to_owned())
                });
                self.worker.refresh_shared();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let total: u64 = self.shared.iter().map(|f| f.size).sum();
                ui.label(format!(
                    "{} files · {}",
                    self.shared.len(),
                    fmt::bytes(total)
                ));
            });
        });
        ui.separator();
        fn sf_id(f: &SharedFile) -> u64 {
            u64::from(f.ecid)
        }
        let cols: Vec<Col<SharedFile>> = vec![
            Col {
                title: "File name",
                width: Column::remainder().at_least(200.0).clip(true),
                cmp: |a, b| by_name(&a.name, &b.name),
                show: |ui, f| {
                    ui.label(&f.name).on_hover_text(&f.path);
                },
            },
            Col {
                title: "Size",
                width: Column::initial(80.0),
                cmp: |a, b| a.size.cmp(&b.size),
                show: |ui, f| right(ui, fmt::bytes(f.size)),
            },
            Col {
                title: "Transferred",
                width: Column::initial(130.0),
                cmp: |a, b| a.transferred_all.cmp(&b.transferred_all),
                show: |ui, f| {
                    right(
                        ui,
                        format!(
                            "{} ({})",
                            fmt::bytes(f.transferred),
                            fmt::bytes(f.transferred_all)
                        ),
                    )
                },
            },
            Col {
                title: "Requests",
                width: Column::initial(80.0),
                cmp: |a, b| a.requests_all.cmp(&b.requests_all),
                show: |ui, f| right(ui, format!("{} ({})", f.requests, f.requests_all)),
            },
            Col {
                title: "Accepted",
                width: Column::initial(80.0),
                cmp: |a, b| a.accepts_all.cmp(&b.accepts_all),
                show: |ui, f| right(ui, format!("{} ({})", f.accepts, f.accepts_all)),
            },
            Col {
                title: "Priority",
                width: Column::initial(90.0),
                cmp: |a, b| a.priority.cmp(&b.priority),
                show: |ui, f| {
                    ui.label(model::priority_text(f.priority));
                },
            },
            Col {
                title: "Sources",
                width: Column::initial(60.0),
                cmp: |a, b| a.complete_sources.cmp(&b.complete_sources),
                show: |ui, f| right(ui, f.complete_sources.to_string()),
            },
            Col {
                title: "Folder",
                width: Column::initial(220.0).clip(true),
                cmp: |a, b| a.path.cmp(&b.path),
                show: |ui, f| {
                    ui.label(RichText::new(&f.path).weak());
                },
            },
        ];
        let mut copy_links = None;
        let mut prio = None;
        let shared = &self.shared;
        table::show(
            ui,
            "shared",
            &mut self.shared_table,
            shared,
            sf_id,
            &cols,
            |ui, _f, sel| {
                if ui.button("Copy ed2k link").clicked() {
                    copy_links = Some(
                        shared
                            .iter()
                            .filter(|f| sel.contains(&sf_id(f)))
                            .map(|f| f.ed2k_link.clone())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                    ui.close_menu();
                }
                ui.menu_button("Priority", |ui| {
                    for (label, p) in [
                        ("Low", model::PR_LOW),
                        ("Normal", model::PR_NORMAL),
                        ("High", model::PR_HIGH),
                        ("Auto", model::PR_AUTO),
                    ] {
                        if ui.button(label).clicked() {
                            prio = Some((
                                p,
                                shared
                                    .iter()
                                    .filter(|f| sel.contains(&sf_id(f)))
                                    .map(|f| f.hash)
                                    .collect::<Vec<_>>(),
                            ));
                            ui.close_menu();
                        }
                    }
                });
            },
        );
        if let Some(text) = copy_links {
            copy(ui, text);
            self.notify(true, "ed2k link copied");
        }
        if let Some((p, hashes)) = prio {
            self.worker
                .job(move |c| c.set_shared_priority(&hashes, p).map(|()| String::new()));
            self.worker.refresh_shared();
        }
    }

    // ------------------------------------------------------- Networks ---

    pub fn networks_page(&mut self, ui: &mut Ui) {
        let conn = self
            .stats
            .as_ref()
            .map(|s| s.conn.clone())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.strong("eD2k servers");
            ui.separator();
            if ui.button("Connect to any server").clicked() {
                self.worker
                    .job(|c| c.server_connect(None).map(|()| String::new()));
            }
            if ui
                .add_enabled(
                    conn.ed2k_connected() || conn.ed2k_connecting(),
                    egui::Button::new("Disconnect"),
                )
                .clicked()
            {
                self.worker
                    .job(|c| c.server_disconnect().map(|()| String::new()));
            }
            ui.separator();
            ui.label("Add:");
            ui.add(
                egui::TextEdit::singleline(&mut self.new_server_addr)
                    .hint_text("host:port")
                    .desired_width(150.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.new_server_name)
                    .hint_text("name (optional)")
                    .desired_width(130.0),
            );
            if ui
                .add_enabled(
                    self.new_server_addr.contains(':'),
                    egui::Button::new("Add server"),
                )
                .clicked()
            {
                let (addr, name) = (
                    self.new_server_addr.trim().to_owned(),
                    self.new_server_name.trim().to_owned(),
                );
                self.worker.job(move |c| {
                    c.server_add(&addr, &name)
                        .map(|()| format!("Added server {addr}"))
                });
                self.new_server_addr.clear();
                self.new_server_name.clear();
            }
        });
        ui.separator();

        let current = conn
            .server
            .as_ref()
            .filter(|_| conn.ed2k_connected())
            .map(server_id);
        let cols: Vec<Col<Server>> = vec![
            Col {
                title: "Server name",
                width: Column::remainder().at_least(160.0).clip(true),
                cmp: |a, b| by_name(&a.name, &b.name),
                show: |ui, s| {
                    ui.label(&s.name).on_hover_text(&s.description);
                },
            },
            Col {
                title: "Address",
                width: Column::initial(150.0),
                cmp: |a, b| server_id(a).cmp(&server_id(b)),
                show: |ui, s| {
                    ui.label(s.address());
                },
            },
            Col {
                title: "Users",
                width: Column::initial(80.0),
                cmp: |a, b| a.users.cmp(&b.users),
                show: |ui, s| right(ui, s.users.to_string()),
            },
            Col {
                title: "Max users",
                width: Column::initial(80.0),
                cmp: |a, b| a.max_users.cmp(&b.max_users),
                show: |ui, s| right(ui, s.max_users.to_string()),
            },
            Col {
                title: "Files",
                width: Column::initial(90.0),
                cmp: |a, b| a.files.cmp(&b.files),
                show: |ui, s| right(ui, s.files.to_string()),
            },
            Col {
                title: "Ping",
                width: Column::initial(60.0),
                cmp: |a, b| a.ping.cmp(&b.ping),
                show: |ui, s| {
                    right(
                        ui,
                        if s.ping > 0 {
                            s.ping.to_string()
                        } else {
                            String::new()
                        },
                    )
                },
            },
            Col {
                title: "Priority",
                width: Column::initial(70.0),
                cmp: |a, b| a.priority.cmp(&b.priority),
                show: |ui, s| {
                    ui.label(s.priority_text());
                },
            },
            Col {
                title: "Failed",
                width: Column::initial(50.0),
                cmp: |a, b| a.failed.cmp(&b.failed),
                show: |ui, s| right(ui, s.failed.to_string()),
            },
            Col {
                title: "Version",
                width: Column::initial(80.0),
                cmp: |a, b| a.version.cmp(&b.version),
                show: |ui, s| {
                    ui.label(&s.version);
                },
            },
        ];

        let log_height = (ui.available_height() * 0.35).max(120.0);
        let table_height = ui.available_height() - log_height - 40.0;
        let mut connect_to = None;
        let mut remove = None;
        let servers = &self.servers;
        ui.allocate_ui(egui::vec2(ui.available_width(), table_height), |ui| {
            if let Some(cur) = current {
                if let Some(s) = servers.iter().find(|s| server_id(s) == cur) {
                    ui.label(
                        RichText::new(format!("Connected to {} ({})", s.name, s.address()))
                            .color(Color32::from_rgb(60, 170, 80)),
                    );
                }
            }
            let dbl = table::show(
                ui,
                "servers",
                &mut self.servers_table,
                servers,
                server_id,
                &cols,
                |ui, s, _sel| {
                    if ui.button("Connect to this server").clicked() {
                        connect_to = Some((s.ip, s.port));
                        ui.close_menu();
                    }
                    if ui.button("Copy ed2k link").clicked() {
                        copy(
                            ui,
                            format!(
                                "ed2k://|server|{}|{}|/",
                                s.address().split(':').next().unwrap_or(""),
                                s.port
                            ),
                        );
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Remove server").clicked() {
                        remove = Some((s.ip, s.port));
                        ui.close_menu();
                    }
                },
            );
            if let Some(i) = dbl {
                connect_to = Some((servers[i].ip, servers[i].port));
            }
        });
        if let Some(target) = connect_to {
            self.worker.job(move |c| {
                c.server_connect(Some(target))
                    .map(|()| "Connecting…".to_owned())
            });
        }
        if let Some((ip, port)) = remove {
            self.worker
                .job(move |c| c.server_remove(ip, port).map(|()| String::new()));
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.strong("Kad");
            ui.separator();
            let state = if !conn.kad_enabled {
                "disabled in the daemon's preferences"
            } else if conn.kad_connected() {
                if conn.kad_firewalled() {
                    "connected (firewalled)"
                } else {
                    "connected"
                }
            } else if conn.kad_running() {
                "connecting"
            } else {
                "not running"
            };
            ui.label(state);
            if let Some(s) = &self.stats {
                if s.kad_nodes > 0 {
                    ui.label(
                        RichText::new(format!(
                            "· {} nodes · {} users · {} files",
                            s.kad_nodes, s.kad_users, s.kad_files
                        ))
                        .weak(),
                    );
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if conn.kad_running() {
                    if ui.button("Stop Kad").clicked() {
                        self.worker.job(|c| c.kad_stop().map(|()| String::new()));
                    }
                } else if ui
                    .add_enabled(conn.kad_enabled, egui::Button::new("Start Kad"))
                    .clicked()
                {
                    self.worker.job(|c| c.kad_start().map(|()| String::new()));
                }
            });
        });
        ui.separator();
        ui.strong("aMule log");
        egui::ScrollArea::vertical()
            .id_salt("log")
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for l in &self.log {
                    ui.label(RichText::new(l).monospace().size(12.0));
                }
            });
    }

    // ------------------------------------------------------- Searches ---

    pub fn search_page(&mut self, ui: &mut Ui) {
        let mut start = false;
        ui.horizontal(|ui| {
            ui.label("Name:");
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.search.text)
                    .hint_text("search terms")
                    .desired_width(260.0),
            );
            start |= edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            egui::ComboBox::from_id_salt("kind")
                .selected_text(self.search.kind.label())
                .show_ui(ui, |ui| {
                    for k in SearchKind::ALL {
                        ui.selectable_value(&mut self.search.kind, k, k.label());
                    }
                });
            egui::ComboBox::from_id_salt("ftype")
                .selected_text(FILE_TYPES[self.search.file_type].0)
                .show_ui(ui, |ui| {
                    for (i, (label, _)) in FILE_TYPES.iter().enumerate() {
                        ui.selectable_value(&mut self.search.file_type, i, *label);
                    }
                });
            if self.search.running {
                ui.spinner();
                if ui.button("⏹ Stop").clicked() {
                    self.worker.search_stop();
                    self.search.running = false;
                }
            } else {
                start |= ui
                    .add_enabled(
                        !self.search.text.trim().is_empty(),
                        egui::Button::new("🔍 Start"),
                    )
                    .clicked();
            }
        });
        ui.collapsing("Filters", |ui| {
            ui.horizontal(|ui| {
                ui.label("Extension:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search.extension)
                        .hint_text("avi")
                        .desired_width(60.0),
                );
                ui.label("Min size (MB):");
                ui.add(egui::TextEdit::singleline(&mut self.search.min_mb).desired_width(60.0));
                ui.label("Max size (MB):");
                ui.add(egui::TextEdit::singleline(&mut self.search.max_mb).desired_width(60.0));
                ui.label("Min. sources:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search.availability).desired_width(40.0),
                );
            });
        });
        if start && !self.search.text.trim().is_empty() {
            match (
                fmt::parse_mb(&self.search.min_mb),
                fmt::parse_mb(&self.search.max_mb),
                self.search.availability.trim().parse::<u32>().or_else(|e| {
                    if self.search.availability.trim().is_empty() {
                        Ok(0)
                    } else {
                        Err(e)
                    }
                }),
            ) {
                (Some(min_size), Some(max_size), Ok(availability)) => {
                    let params = SearchParams {
                        text: self.search.text.clone(),
                        file_type: FILE_TYPES[self.search.file_type].1.to_owned(),
                        extension: self
                            .search
                            .extension
                            .trim()
                            .trim_start_matches('.')
                            .to_owned(),
                        min_size,
                        max_size,
                        availability,
                    };
                    self.search_results.clear();
                    self.search.running = true;
                    self.worker.search(self.search.kind, params);
                }
                _ => self.notify(false, "Sizes and sources must be numbers"),
            }
        }

        let percent = self.search_progress.percent;
        ui.horizontal(|ui| {
            let frac = percent.map_or(0.0, |v| f32::from(v) / 100.0);
            let label = if self.search.running {
                format!("Searching… {} results", self.search_results.len())
            } else {
                format!("{} results", self.search_results.len())
            };
            ui.add(
                egui::ProgressBar::new(if self.search.running { frac } else { 1.0 })
                    .text(label)
                    .desired_width(300.0),
            );
            let sel: Vec<model::Hash> =
                selected(&self.search_results, &self.search_table.selected, sr_id)
                    .into_iter()
                    .map(|r| r.hash)
                    .collect();
            if ui
                .add_enabled(
                    !sel.is_empty(),
                    egui::Button::new(format!("⬇ Download ({})", sel.len())),
                )
                .clicked()
            {
                self.download(sel);
            }
        });
        ui.separator();

        fn sr_id(r: &SearchResult) -> u64 {
            u64::from(r.ecid)
        }
        let cols: Vec<Col<SearchResult>> = vec![
            Col {
                title: "File name",
                width: Column::remainder().at_least(240.0).clip(true),
                cmp: |a, b| by_name(&a.name, &b.name),
                show: |ui, r| {
                    let mut t = RichText::new(&r.name);
                    if r.status != 0 {
                        // aMule colours known and downloading results.
                        t = t.color(if r.status == 3 {
                            Color32::from_rgb(200, 70, 70)
                        } else {
                            Color32::from_rgb(70, 140, 220)
                        });
                    }
                    if r.parent.is_some() {
                        t = t.italics();
                    }
                    ui.label(t).on_hover_text(&r.name);
                },
            },
            Col {
                title: "Size",
                width: Column::initial(90.0),
                cmp: |a, b| a.size.cmp(&b.size),
                show: |ui, r| right(ui, fmt::bytes(r.size)),
            },
            Col {
                title: "Sources",
                width: Column::initial(90.0),
                cmp: |a, b| a.sources.cmp(&b.sources),
                show: |ui, r| right(ui, format!("{} ({})", r.sources, r.complete_sources)),
            },
            Col {
                title: "Status",
                width: Column::initial(140.0),
                cmp: |a, b| a.status.cmp(&b.status),
                show: |ui, r| {
                    ui.label(r.status_text());
                },
            },
            Col {
                title: "Hash",
                width: Column::initial(260.0).clip(true),
                cmp: |a, b| a.hash.cmp(&b.hash),
                show: |ui, r| {
                    ui.label(
                        RichText::new(model::hash_hex(&r.hash))
                            .monospace()
                            .weak()
                            .size(11.0),
                    );
                },
            },
        ];
        let mut dl = None;
        let mut copy_links = None;
        let results = &self.search_results;
        let dbl = table::show(
            ui,
            "results",
            &mut self.search_table,
            results,
            sr_id,
            &cols,
            |ui, _r, sel| {
                let chosen: Vec<&SearchResult> =
                    results.iter().filter(|r| sel.contains(&sr_id(r))).collect();
                if ui.button("Download").clicked() {
                    dl = Some(chosen.iter().map(|r| r.hash).collect::<Vec<_>>());
                    ui.close_menu();
                }
                if ui.button("Copy ed2k link").clicked() {
                    copy_links = Some(
                        chosen
                            .iter()
                            .map(|r| {
                                format!(
                                    "ed2k://|file|{}|{}|{}|/",
                                    r.name.replace('|', "_"),
                                    r.size,
                                    model::hash_hex(&r.hash)
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                    ui.close_menu();
                }
            },
        );
        if let Some(i) = dbl {
            dl = Some(vec![self.search_results[i].hash]);
        }
        if let Some(h) = dl {
            self.download(h);
        }
        if let Some(text) = copy_links {
            copy(ui, text);
            self.notify(true, "ed2k link copied");
        }
    }

    fn download(&mut self, hashes: Vec<model::Hash>) {
        let n = hashes.len();
        self.worker.job(move |c| {
            c.download_search_results(&hashes, 0)
                .map(|()| format!("Queued {n} download(s)"))
        });
    }

    // ----------------------------------------------------- Statistics ---

    pub fn statistics_page(&mut self, ui: &mut Ui) {
        let Some(s) = self.stats.clone() else {
            ui.label("Waiting for statistics…");
            return;
        };
        let graph_h = (ui.available_height() * 0.5).max(180.0);
        ui.strong("Transfer rates (last 10 minutes)");
        let down: PlotPoints = self.history.iter().map(|&(t, d, _)| [t, d]).collect();
        let up: PlotPoints = self.history.iter().map(|&(t, _, u)| [t, u]).collect();
        Plot::new("speeds")
            .height(graph_h)
            .legend(Legend::default())
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .include_y(0.0)
            .y_axis_label("kB/s")
            .x_axis_formatter(|m, _| {
                let s = m.value.max(0.0) as u64;
                format!("{}:{:02}", s / 60, s % 60)
            })
            .show(ui, |p| {
                p.line(
                    Line::new(down)
                        .name("Download")
                        .color(Color32::from_rgb(70, 140, 220))
                        .width(2.0_f32),
                );
                p.line(
                    Line::new(up)
                        .name("Upload")
                        .color(Color32::from_rgb(220, 120, 50))
                        .width(2.0_f32),
                );
            });
        ui.add_space(8.0);

        let row = |ui: &mut Ui, k: &str, v: String| {
            ui.label(k);
            right(ui, v);
            ui.end_row();
        };
        ui.columns(3, |cols| {
            cols[0].strong("Transfer");
            egui::Grid::new("st_xfer")
                .striped(true)
                .num_columns(2)
                .show(&mut cols[0], |ui| {
                    row(
                        ui,
                        "Download speed",
                        format!("{} (limit {})", fmt::speed(s.dl_speed), limit(s.dl_limit)),
                    );
                    row(
                        ui,
                        "Upload speed",
                        format!("{} (limit {})", fmt::speed(s.ul_speed), limit(s.ul_limit)),
                    );
                    row(
                        ui,
                        "Overhead down / up",
                        format!(
                            "{} / {}",
                            fmt::speed(s.dl_overhead),
                            fmt::speed(s.ul_overhead)
                        ),
                    );
                    row(ui, "Session received", fmt::bytes(s.session_received));
                    row(ui, "Session sent", fmt::bytes(s.session_sent));
                    row(ui, "Total received", fmt::bytes(s.total_received));
                    row(ui, "Total sent", fmt::bytes(s.total_sent));
                });
            cols[1].strong("Connection");
            egui::Grid::new("st_conn")
                .striped(true)
                .num_columns(2)
                .show(&mut cols[1], |ui| {
                    row(ui, "Uptime", fmt::duration(s.uptime_secs));
                    row(ui, "Active connections", s.active_connections.to_string());
                    row(ui, "Upload queue", s.queue_len.to_string());
                    row(ui, "Found sources", s.total_sources.to_string());
                    row(ui, "Banned clients", s.banned.to_string());
                    row(
                        ui,
                        "eD2k ID",
                        if s.conn.ed2k_connected() {
                            s.conn.ed2k_id.to_string()
                        } else {
                            "—".into()
                        },
                    );
                    row(
                        ui,
                        "Kad ID",
                        s.conn.kad_id.clone().unwrap_or_else(|| "—".into()),
                    );
                });
            cols[2].strong("Networks");
            egui::Grid::new("st_net")
                .striped(true)
                .num_columns(2)
                .show(&mut cols[2], |ui| {
                    row(
                        ui,
                        "eD2k users / files",
                        format!("{} / {}", s.ed2k_users, s.ed2k_files),
                    );
                    row(
                        ui,
                        "Kad users / files",
                        format!("{} / {}", s.kad_users, s.kad_files),
                    );
                    row(ui, "Kad nodes", s.kad_nodes.to_string());
                    row(ui, "Shared files", s.shared_files.to_string());
                    row(
                        ui,
                        "Temp free space",
                        s.temp_free.map_or("—".into(), fmt::bytes),
                    );
                    row(
                        ui,
                        "Incoming free space",
                        s.incoming_free.map_or("—".into(), fmt::bytes),
                    );
                });
        });
    }
}

fn limit(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        "none".into()
    } else {
        fmt::speed(bytes_per_sec)
    }
}
