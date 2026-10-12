//! The list column and the detail column (ADR 0026 §1).
//!
//! The list column has a toolbar with the title, a count, and "+", then the rows of the
//! place. The detail column has a toolbar on top and a scrolling body in a reading
//! column. Both toolbars hold the title bar of the window, so a drag on them moves it.
//! A place draws its own rows and its own body ([`super::items`], [`super::agents`],
//! [`super::decisions`]); this module has their frame.

use std::hash::Hash;

use eframe::egui::{self, Align, Layout, Margin, Pos2, Rect, ScrollArea, Sense, Ui, Vec2};

use super::kit::{self, Font, Icon};
use crate::desktop::{DesktopApp, Place};

/// The reading width of the detail body.
pub(super) const DETAIL_WIDTH: f32 = 640.0;

/// How the sidebar shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SidebarMode {
    Full,
    /// Icons only.
    Rail,
    /// A rail, with the full sidebar over the list (a narrow window).
    Float,
}

/// The widths of the window for this frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Columns {
    pub(super) sidebar: SidebarMode,
    pub(super) narrow: bool,
    pub(super) list_width: f32,
}

impl Columns {
    /// Below [`kit::NARROW_WINDOW`] the sidebar is a rail; the owner opens it over the
    /// list. Wider, it is full unless the owner collapsed it.
    pub(super) fn of(app: &DesktopApp, window_width: f32) -> Self {
        let narrow = window_width < kit::NARROW_WINDOW;
        let sidebar = match (narrow, app.ui.sidebar_float, app.ui.sidebar_hidden) {
            (true, true, _) => SidebarMode::Float,
            (true, false, _) | (false, _, true) => SidebarMode::Rail,
            (false, _, false) => SidebarMode::Full,
        };
        let list_width = if window_width < kit::WIDE_LIST_WINDOW {
            kit::LIST_WIDTH_NARROW
        } else {
            kit::LIST_WIDTH
        };
        Self {
            sidebar,
            narrow,
            list_width,
        }
    }

    /// The width of the sidebar panel: the rail stays under a floating sidebar.
    pub(super) fn sidebar_width(self) -> f32 {
        match self.sidebar {
            SidebarMode::Full => kit::SIDEBAR_WIDTH,
            SidebarMode::Rail | SidebarMode::Float => kit::RAIL_WIDTH,
        }
    }
}

/// The toolbar of a list column: the title and the line under it, and the buttons at
/// the right.
pub(super) fn list_toolbar(
    ui: &mut Ui,
    title: &str,
    subtitle: &str,
    trailing: impl FnOnce(&mut Ui),
) {
    let full = ui.max_rect();
    let rect = Rect::from_min_size(full.min, Vec2::new(full.width(), kit::TOOLBAR));
    kit::window_drag_region(ui, rect);
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(Rect::from_min_max(
                Pos2::new(rect.left() + 16.0, rect.top()),
                Pos2::new(rect.right() - 10.0, rect.bottom()),
            ))
            .layout(Layout::left_to_right(Align::Center)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let right = ui.max_rect().right();
            // The buttons first, from the right, so the title takes what they leave.
            let buttons = ui
                .scope_builder(
                    egui::UiBuilder::new()
                        .max_rect(ui.max_rect())
                        .layout(Layout::right_to_left(Align::Center)),
                    |ui| {
                        trailing(ui);
                        ui.min_rect().width()
                    },
                )
                .inner;
            let title_rect = Rect::from_min_max(
                ui.max_rect().min,
                Pos2::new(right - buttons - 6.0, ui.max_rect().bottom()),
            );
            ui.scope_builder(
                egui::UiBuilder::new()
                    .max_rect(title_rect)
                    .layout(Layout::left_to_right(Align::Center)),
                |ui| kit::toolbar_title(ui, title, subtitle),
            );
        },
    );
    ui.allocate_rect(rect, Sense::hover());
}

/// The toolbar of a detail column: its buttons at the right.
pub(super) fn detail_toolbar(ui: &mut Ui, trailing: impl FnOnce(&mut Ui)) {
    let full = ui.max_rect();
    let rect = Rect::from_min_size(full.min, Vec2::new(full.width(), kit::TOOLBAR));
    kit::window_drag_region(ui, rect);
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(Rect::from_min_max(
                rect.min,
                Pos2::new(rect.right() - 12.0, rect.bottom()),
            ))
            .layout(Layout::right_to_left(Align::Center)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            trailing(ui);
        },
    );
    ui.allocate_rect(rect, Sense::hover());
}

/// A margin of 12 points at the sides of a list column, for the search field.
pub(super) fn list_inset<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::NONE
        .inner_margin(Margin {
            left: 12,
            right: 12,
            top: 0,
            bottom: 8,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// One group of rows in a list column.
pub(super) struct Group<T> {
    pub(super) title: String,
    pub(super) rows: Vec<T>,
}

/// The rows of a list column in groups, in a scroll area. With `headers`, each group has
/// a header, and the header of the group at the top stays pinned while its rows
/// scroll under it. `after` draws below the last group.
pub(super) fn grouped_rows<T>(
    ui: &mut Ui,
    salt: impl Hash + std::fmt::Debug,
    groups: &[Group<T>],
    headers: bool,
    mut row: impl FnMut(&mut Ui, &T),
    after: impl FnOnce(&mut Ui),
) {
    ScrollArea::vertical()
        .id_salt(salt)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Frame::NONE
                .inner_margin(Margin {
                    left: 8,
                    right: 8,
                    top: 0,
                    bottom: 12,
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let clip = ui.clip_rect();
                    let width = ui.available_width();
                    let mut spans = Vec::new();
                    for group in groups {
                        let header = headers.then(|| {
                            let (rect, _) = ui.allocate_exact_size(
                                Vec2::new(width, kit::GROUP_HEADER),
                                Sense::hover(),
                            );
                            kit::paint_group_header(ui, rect, &group.title, Some(group.rows.len()));
                            rect
                        });
                        for item in &group.rows {
                            row(ui, item);
                        }
                        if let Some(rect) = header {
                            spans.push((group, rect, ui.cursor().top()));
                        }
                    }
                    // The header of the group that runs under the top edge stays there,
                    // until the next header pushes it up.
                    for (group, rect, bottom) in spans {
                        if rect.top() < clip.top() && bottom > clip.top() {
                            let top = clip.top().min(bottom - kit::GROUP_HEADER);
                            let pinned = Rect::from_min_size(
                                Pos2::new(rect.left(), top),
                                Vec2::new(rect.width(), kit::GROUP_HEADER),
                            );
                            kit::paint_group_header(
                                ui,
                                pinned,
                                &group.title,
                                Some(group.rows.len()),
                            );
                        }
                    }
                    ui.spacing_mut().item_spacing.y = 6.0;
                    after(ui);
                });
            kit::follow_focus(ui);
            kit::keyboard_scroll(ui);
        });
}

/// A short note in a list column, for an empty list.
pub(super) fn list_note(ui: &mut Ui, message: &str) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| {
        ui.add(egui::Label::new(kit::text(message, Font::Callout).color(kit::SECONDARY)).wrap());
    });
}

/// The scrolling body of a detail column: a reading column, the keyboard scroll, and
/// the scroll to the focus. `salt` keeps a scroll position for each credential or agent.
pub(super) fn detail_body(
    ui: &mut Ui,
    salt: impl Hash + std::fmt::Debug,
    add: impl FnOnce(&mut Ui),
) {
    ScrollArea::vertical()
        .id_salt(salt)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(6.0);
            kit::column(ui, DETAIL_WIDTH, add);
            kit::follow_focus(ui);
            kit::keyboard_scroll(ui);
        });
}

/// The detail of a place with nothing selected.
pub(super) fn nothing_selected(ui: &mut Ui, icon: Icon, title: &str, message: &str) {
    kit::empty_state(ui, icon, title, message, None);
}

/// The title of a place, for the list toolbar and the window.
pub(super) fn place_title(app: &DesktopApp) -> String {
    match &app.place {
        Place::Folder(None) => "All credentials".to_owned(),
        #[cfg(feature = "vault")]
        Place::Folder(Some(uuid)) => super::folders::FolderTree::load(app)
            .name(uuid)
            .unwrap_or_else(|| "Folder".to_owned()),
        #[cfg(not(feature = "vault"))]
        Place::Folder(Some(_)) => "Folder".to_owned(),
        Place::Shared(uuid) => super::sidebar::shared_vault(app, uuid).name,
        Place::Decisions => "Decisions".to_owned(),
        Place::Agents => "Agents".to_owned(),
    }
}

/// "1 item", "3 items".
pub(super) fn count_label(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}
