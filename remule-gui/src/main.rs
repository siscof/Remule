// SPDX-License-Identifier: GPL-2.0-or-later
//! remule-gui: a remote GUI for an aMule daemon, ported from amulegui.
//!
//! It connects to `amuled` over External Connections (EC), the same way
//! `amulegui` does, so it works with an existing daemon today and with
//! `remuled` once that speaks EC (MIGRATION_PLAN.md, Phase 11).
//!
//!     remule-gui [-h|--host HOST] [-p|--port PORT] [-P|--password PASSWORD] [--page PAGE]
//!
//! The options are the ones aMule's EC tools take (ExternalConnector.cpp).
//! Given a password, the GUI connects straight away.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod fmt;
mod pages;
mod table;
mod worker;

/// Command-line overrides for the saved connection settings.
#[derive(Default)]
pub struct Args {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub password: Option<String>,
    pub page: Option<worker::Page>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
            None => (arg.clone(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or(format!("{key} needs a value"))
        };
        match key.as_str() {
            "-h" | "--host" => a.host = Some(value()?),
            "-p" | "--port" => {
                a.port = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--port must be a number".to_owned())?,
                )
            }
            "-P" | "--password" => a.password = Some(value()?),
            "--page" => {
                a.page =
                    Some(match value()?.as_str() {
                        "networks" => worker::Page::Networks,
                        "searches" => worker::Page::Searches,
                        "transfers" => worker::Page::Transfers,
                        "shared" => worker::Page::Shared,
                        "statistics" => worker::Page::Statistics,
                        _ => return Err(
                            "--page is one of networks, searches, transfers, shared, statistics"
                                .into(),
                        ),
                    })
            }
            "--help" => {
                return Err(
                    "usage: remule-gui [-h HOST] [-p PORT] [-P PASSWORD] [--page PAGE]".into(),
                )
            }
            other => return Err(format!("unknown option {other}; try --help")),
        }
    }
    Ok(a)
}

fn main() -> eframe::Result {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("remule")
            .with_inner_size([1180.0, 720.0])
            .with_min_inner_size([760.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "remule",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, args)))),
    )
}
