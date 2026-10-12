//! Settings in its own window (ADR 0026 §3): ⌘, and the gear at the bottom of the
//! sidebar open it, ⌘W, Esc, and its close button close it.
//!
//! The window is an egui viewport of the app. A toolbar of four tabs (General, Devices,
//! Security, Advanced) stays at the top; the sections of the selected tab scroll below
//! it ([`super::settings::draw`]). A sheet or an owner check that opens in the Settings
//! window shows there; the others show in the main window. A backend without a second
//! window (the headless tests) shows Settings in place of the main window instead, with
//! "Done" to go back.

use eframe::egui::{self, Frame, ScrollArea, ViewportBuilder, ViewportCommand};

use super::kit::{self, Style};
use crate::desktop::{DesktopApp, StatusKind};

/// The reading width of the Settings content.
const WIDTH: f32 = 640.0;
/// The size of the window when it opens.
const DEFAULT_SIZE: egui::Vec2 = egui::vec2(720.0, 640.0);
/// The smallest size of the window. Each tab draws in it.
pub(super) const MIN_SIZE: egui::Vec2 = egui::vec2(560.0, 420.0);

fn viewport_id() -> egui::ViewportId {
    egui::ViewportId::from_hash_of("apassy-settings")
}

/// Settings replaces the main window: it is open, and the backend has no second window.
pub(super) fn in_place(app: &DesktopApp, ctx: &egui::Context) -> bool {
    app.settings_open && ctx.embed_viewports()
}

/// The owner check is in the Settings window, so the main window does not draw it.
#[cfg(feature = "vault")]
pub(super) fn owns_check(app: &DesktopApp, ctx: &egui::Context) -> bool {
    app.settings_open && app.ui.settings_check && !ctx.embed_viewports()
}

/// The Settings content: the tab bar, and the sections of the tab in a scrolling
/// reading column.
pub(super) fn content(app: &mut DesktopApp, ui: &mut egui::Ui) {
    #[cfg(feature = "vault")]
    {
        ui.add_space(8.0);
        super::settings::tab_bar(app, ui);
        ui.add_space(6.0);
        let width = ui.available_width();
        let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 1.0), egui::Sense::hover());
        ui.painter()
            .hline(rect.x_range(), rect.center().y, (1.0, kit::SEPARATOR));
    }
    ScrollArea::vertical()
        .id_salt("settings-window")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(14.0);
            kit::column(ui, WIDTH, |ui| {
                #[cfg(feature = "vault")]
                super::settings::draw(app, ui);
                #[cfg(not(feature = "vault"))]
                super::demo::draw_settings(app, ui);
            });
            kit::follow_focus(ui);
            kit::keyboard_scroll(ui);
        });
}

/// ⌘W or the close button of the window.
fn closes(ctx: &egui::Context) -> bool {
    ctx.input(|input| input.viewport().close_requested())
        || kit::shortcut(ctx, egui::Modifiers::COMMAND, egui::Key::W)
}

/// Esc closes Settings when nothing else takes it: no sheet, owner check, menu, or error
/// message, and no text field with the focus. It is read before the frame draws, so a
/// sheet or a field that this Esc closes still counts.
fn escape_closes(app: &DesktopApp, ctx: &egui::Context) -> bool {
    let error_shown = app.status_kind == StatusKind::Error
        && !app.status_text.is_empty()
        && app.ui.toast_closed != app.status_seq;
    #[cfg(feature = "vault")]
    let checking = app.owner.check.is_some();
    #[cfg(not(feature = "vault"))]
    let checking = false;
    ctx.input(|input| input.key_pressed(egui::Key::Escape))
        && app.ui.sheet.is_none()
        && !checking
        && !error_shown
        && ctx.memory(|memory| memory.top_modal_layer()).is_none()
        && !egui::Popup::is_any_open(ctx)
        && !ctx.text_edit_focused()
}

/// The Settings window, when it is open.
pub(super) fn show(app: &mut DesktopApp, ctx: &egui::Context) {
    if !app.settings_open {
        app.ui.settings_sheet = false;
        app.ui.settings_check = false;
        app.ui.raise_settings = false;
        return;
    }
    let builder = ViewportBuilder::default()
        .with_title("Settings")
        .with_inner_size(DEFAULT_SIZE)
        .with_min_inner_size(MIN_SIZE);
    let raise = std::mem::take(&mut app.ui.raise_settings);
    ctx.show_viewport_immediate(viewport_id(), builder, |ui, _class| {
        let ctx = ui.ctx().clone();
        if raise {
            ctx.send_viewport_cmd(ViewportCommand::Focus);
        }
        let escape = escape_closes(app, &ctx);
        let had_sheet = app.ui.sheet.is_some();
        #[cfg(feature = "vault")]
        let had_check = app.owner.check.is_some();
        egui::CentralPanel::default()
            .frame(Frame::NONE.fill(kit::WINDOW))
            .show(ui, |ui| content(app, ui));
        if !had_sheet && app.ui.sheet.is_some() {
            app.ui.settings_sheet = true;
        }
        if app.ui.settings_sheet {
            super::shell::sheets(app, &ctx);
        }
        #[cfg(feature = "vault")]
        {
            if !had_check && app.owner.check.is_some() {
                app.ui.settings_check = true;
            }
            if app.ui.settings_check {
                super::owner_check_view::draw(app, &ctx);
            }
        }
        super::draw_toast(app, &ctx);
        let modal = ctx.memory(|memory| memory.top_modal_layer()).is_some();
        if (closes(&ctx) && !modal) || escape {
            app.settings_open = false;
        }
    });
    if app.ui.sheet.is_none() {
        app.ui.settings_sheet = false;
    }
    #[cfg(feature = "vault")]
    if app.owner.check.is_none() {
        app.ui.settings_check = false;
    }
}

/// Settings in place of the main window: a toolbar with the title and "Done", the
/// banners of the main window, and the content. Its sheets show over it.
pub(super) fn draw_in_place(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let escape = escape_closes(app, ui.ctx());
    super::shell::shortcuts(app, &ui.ctx().clone());
    egui::CentralPanel::default()
        .frame(Frame::NONE.fill(kit::WINDOW))
        .show(ui, |ui| {
            super::columns::detail_toolbar(ui, |ui| {
                if kit::button(ui, "Done", Style::Bordered)
                    .on_hover_text("Close Settings  ⌘W")
                    .clicked()
                {
                    app.settings_open = false;
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add_space(16.0);
                    kit::toolbar_title(ui, "Settings", "");
                });
            });
            #[cfg(feature = "vault")]
            kit::column_with_bottom_space(ui, WIDTH, 0.0, |ui| {
                ui.scope(|ui| super::updates::banner(app, ui));
                ui.scope(|ui| super::sync::banner(app, ui));
            });
            content(app, ui);
        });
    let ctx = ui.ctx().clone();
    super::shell::sheets(app, &ctx);
    if (closes(&ctx) && ctx.memory(|memory| memory.top_modal_layer()).is_none()) || escape {
        app.settings_open = false;
    }
}
