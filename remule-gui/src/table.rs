// SPDX-License-Identifier: GPL-2.0-or-later
//! A sortable, multi-select list: the role of aMule's `CMuleListCtrl`
//! (click a header to sort, click again to reverse; Ctrl-click to extend the
//! selection; right-click for the row menu; double-click for the default
//! action).

use std::cmp::Ordering;
use std::collections::BTreeSet;

use eframe::egui::{self, Align, Layout, RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};

pub struct Col<T> {
    pub title: &'static str,
    pub width: Column,
    pub cmp: fn(&T, &T) -> Ordering,
    pub show: fn(&mut Ui, &T),
}

#[derive(Default)]
pub struct TableState {
    pub sort_col: usize,
    pub descending: bool,
    pub selected: BTreeSet<u64>,
}

impl TableState {
    pub fn sorted_by(col: usize, descending: bool) -> Self {
        TableState {
            sort_col: col,
            descending,
            selected: BTreeSet::new(),
        }
    }

    /// Forget selected rows that no longer exist.
    pub fn retain(&mut self, alive: impl Fn(u64) -> bool) {
        self.selected.retain(|&id| alive(id));
    }
}

/// Draw the table. Returns the index into `items` of a double-clicked row.
pub fn show<T>(
    ui: &mut Ui,
    salt: &str,
    state: &mut TableState,
    items: &[T],
    id_of: fn(&T) -> u64,
    cols: &[Col<T>],
    mut menu: impl FnMut(&mut Ui, &T, &BTreeSet<u64>),
) -> Option<usize> {
    let mut order: Vec<usize> = (0..items.len()).collect();
    if let Some(c) = cols.get(state.sort_col) {
        order.sort_by(|&a, &b| {
            let o = (c.cmp)(&items[a], &items[b]);
            if state.descending {
                o.reverse()
            } else {
                o
            }
        });
    }
    let ctrl = ui.input(|i| i.modifiers.command);
    let mut double = None;

    ui.push_id(salt, |ui| {
        let mut tb = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .auto_shrink([false, false])
            .min_scrolled_height(0.0)
            .max_scroll_height(f32::INFINITY);
        for c in cols {
            tb = tb.column(c.width);
        }
        tb.header(22.0, |mut header| {
            for (i, c) in cols.iter().enumerate() {
                header.col(|ui| {
                    let arrow = match (state.sort_col == i, state.descending) {
                        (true, false) => " ⏶",
                        (true, true) => " ⏷",
                        _ => "",
                    };
                    let b =
                        egui::Button::new(RichText::new(format!("{}{arrow}", c.title)).strong())
                            .frame(false);
                    if ui.add(b).clicked() {
                        if state.sort_col == i {
                            state.descending = !state.descending;
                        } else {
                            state.sort_col = i;
                            state.descending = false;
                        }
                    }
                });
            }
        })
        .body(|body| {
            body.rows(20.0, order.len(), |mut row| {
                let idx = order[row.index()];
                let item = &items[idx];
                let id = id_of(item);
                row.set_selected(state.selected.contains(&id));
                for c in cols {
                    row.col(|ui| (c.show)(ui, item));
                }
                let resp = row.response();
                if resp.clicked() {
                    if ctrl {
                        if !state.selected.remove(&id) {
                            state.selected.insert(id);
                        }
                    } else {
                        state.selected.clear();
                        state.selected.insert(id);
                    }
                }
                if resp.secondary_clicked() && !state.selected.contains(&id) {
                    state.selected.clear();
                    state.selected.insert(id);
                }
                if resp.double_clicked() {
                    double = Some(idx);
                }
                resp.context_menu(|ui| menu(ui, item, &state.selected));
            });
        });
    });
    double
}

/// A right-aligned cell, for numbers.
pub fn right(ui: &mut Ui, text: impl Into<egui::WidgetText>) {
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.label(text);
    });
}

/// Case-insensitive name order, as the aMule lists sort names.
pub fn by_name(a: &str, b: &str) -> Ordering {
    a.to_lowercase().cmp(&b.to_lowercase())
}
