//! Settings in its own window (ADR 0026 §3): ⌘, and the gear at the bottom of the
//! sidebar open it, ⌘W and its close button close it.
//!
//! The window is an egui viewport of the app. It draws the Settings view as it was
//! ([`super::settings::draw`]); the tabs of ADR 0026 come later. A sheet or an owner
//! check that opens in the Settings window shows there; the others show in the main
//! window. A backend without a second window (the headless tests) shows Settings in
//! place of the main window instead, with "Done" to go back.

use eframe::egui::{self, Frame, ScrollArea, ViewportBuilder, ViewportCommand};

use super::kit::{self, Style};
use crate::desktop::DesktopApp;

/// The reading width of the Settings content.
const WIDTH: f32 = 640.0;

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

/// The Settings content: the view, in a scrolling reading column.
fn content(app: &mut DesktopApp, ui: &mut egui::Ui) {
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
        .with_inner_size([720.0, 640.0])
        .with_min_inner_size([560.0, 420.0]);
    let raise = std::mem::take(&mut app.ui.raise_settings);
    ctx.show_viewport_immediate(viewport_id(), builder, |ui, _class| {
        let ctx = ui.ctx().clone();
        if raise {
            ctx.send_viewport_cmd(ViewportCommand::Focus);
        }
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
        if closes(&ctx) && !modal {
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

/// Settings in place of the main window: a toolbar with "Done", the banners of the main
/// window, and the content. Its sheets show over it.
pub(super) fn draw_in_place(app: &mut DesktopApp, ui: &mut egui::Ui) {
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
    if closes(&ctx) && ctx.memory(|memory| memory.top_modal_layer()).is_none() {
        app.settings_open = false;
    }
}
