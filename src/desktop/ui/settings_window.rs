//! Settings in its own window (ADR 0026 §3): ⌘, and the gear at the bottom of the
//! sidebar open it, ⌘W, Esc, "Done", and its close button close it.
//!
//! The window is an egui viewport of the app, 600 points wide as the sheet of the
//! mockup, with the title bar hidden: the four tabs (General, Devices, Security,
//! Advanced) sit at the top, the groups of the selected tab below them
//! ([`super::settings::draw`]), and "Done" at the bottom right. The window takes the
//! height of the tab, as a macOS settings window does, and scrolls only past the height
//! of the screen. A sheet or an owner check that opens in the Settings window shows
//! there; the others show in the main window.
//!
//! A backend without a second window (the headless tests, and the screenshot tour that
//! clicks in it) draws the same window in the main one: [`draw_in_place`].

use eframe::egui::{self, Color32, Frame, Rect, ScrollArea, ViewportBuilder, ViewportCommand};

use super::kit::{self, Style};
use crate::desktop::{DesktopApp, StatusKind};

/// The width of the window, as the sheet of the mockup.
pub(super) const WIDTH: f32 = 600.0;
/// The padding of the window around its groups and "Done".
const PAD: f32 = 20.0;
/// The space above the tabs.
const TABS_TOP: f32 = 14.0;
/// The height of the tab bar.
const TABS: f32 = 50.0;
/// The space under the tabs.
const TABS_BOTTOM: f32 = 6.0;
/// The bar of "Done": its space above, the button, and the padding under it.
const DONE_BAR: f32 = 18.0 + 28.0 + PAD;
/// The window height before the first frame measures the tab.
const FIRST_HEIGHT: f32 = 460.0;
/// The smallest and the largest height of the window.
const MIN_HEIGHT: f32 = 300.0;
const MAX_HEIGHT: f32 = 760.0;
/// The smallest height while a sheet or an owner check shows in the window.
const SHEET_HEIGHT: f32 = 600.0;
/// The smallest size of the window. Each tab draws in it, and scrolls.
pub(super) const MIN_SIZE: egui::Vec2 = egui::vec2(WIDTH, MIN_HEIGHT);

fn viewport_id() -> egui::ViewportId {
    egui::ViewportId::from_hash_of("apassy-settings")
}

/// The height that the open tab wants, from its last frame.
fn wanted_height_id() -> egui::Id {
    egui::Id::new("apassy-settings-height")
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

/// The Settings content in the rect of `ui`: the tab bar at the top, the groups of the
/// tab in a scroll area, and "Done" at the bottom right. Returns the height that shows
/// the whole tab without a scroll bar.
pub(super) fn content(app: &mut DesktopApp, ui: &mut egui::Ui) -> f32 {
    let full = ui.max_rect();
    // The spaces are explicit, as in the mockup.
    ui.spacing_mut().item_spacing.y = 0.0;
    ui.add_space(TABS_TOP);
    #[cfg(feature = "vault")]
    super::settings::tab_bar(app, ui);
    #[cfg(not(feature = "vault"))]
    ui.add_space(TABS);
    ui.add_space(TABS_BOTTOM);
    let body = (full.bottom() - DONE_BAR - ui.cursor().top()).max(0.0);
    let scroll = ScrollArea::vertical()
        .id_salt("settings-window")
        .max_height(body)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            Frame::NONE
                .inner_margin(egui::Margin::symmetric(PAD as i8, 0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    #[cfg(feature = "vault")]
                    super::settings::draw(app, ui);
                    #[cfg(not(feature = "vault"))]
                    super::demo::draw_settings(app, ui);
                });
            kit::follow_focus(ui);
            kit::keyboard_scroll(ui);
        });
    // "Done" at the bottom right, as in the mockup.
    let bar = Rect::from_min_max(
        egui::pos2(full.left() + PAD, full.bottom() - DONE_BAR + 18.0),
        egui::pos2(full.right() - PAD, full.bottom() - PAD),
    );
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(bar)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
        |ui| {
            if kit::button(ui, "Done", Style::Prominent)
                .on_hover_text("Close Settings  ⌘W")
                .clicked()
            {
                app.settings_open = false;
            }
        },
    );
    TABS_TOP + TABS + TABS_BOTTOM + scroll.content_size.y + DONE_BAR
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

/// The height of the window for `wanted`, within the screen.
fn window_height(ctx: &egui::Context, wanted: f32) -> f32 {
    let screen = ctx
        .input(|input| input.viewport().monitor_size)
        .map_or(MAX_HEIGHT, |size| size.y - 120.0);
    wanted.clamp(MIN_HEIGHT, MAX_HEIGHT.min(screen.max(MIN_HEIGHT)))
}

/// The Settings window, when it is open.
pub(super) fn show(app: &mut DesktopApp, ctx: &egui::Context) {
    if !app.settings_open {
        app.ui.settings_sheet = false;
        app.ui.settings_check = false;
        app.ui.raise_settings = false;
        return;
    }
    // Without a second window, the next frame draws Settings in place. A command to
    // this "window" would go to the main one.
    if ctx.embed_viewports() {
        return;
    }
    let first = ctx
        .data(|data| data.get_temp::<f32>(wanted_height_id()))
        .unwrap_or(FIRST_HEIGHT);
    let builder = ViewportBuilder::default()
        .with_title("Settings")
        .with_inner_size(egui::vec2(WIDTH, window_height(ctx, first)))
        .with_min_inner_size(MIN_SIZE)
        .with_resizable(false)
        .with_maximize_button(false)
        .with_fullsize_content_view(true)
        .with_titlebar_shown(false)
        .with_title_shown(false);
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
        let wanted = egui::CentralPanel::default()
            .frame(Frame::NONE.fill(kit::DETAIL))
            .show(ui, |ui| {
                // The top strip moves the window, as a title bar does. The tabs on it
                // take their clicks first.
                let strip = Rect::from_min_size(
                    ui.max_rect().min,
                    egui::vec2(ui.max_rect().width(), kit::TITLE_BAR),
                );
                kit::window_drag_region(ui, strip);
                content(app, ui)
            })
            .inner;
        // The window takes the height of the tab, and room for a sheet or an owner
        // check that shows in it.
        let over = app.ui.settings_sheet || app.ui.settings_check;
        let height = window_height(
            &ctx,
            if over {
                wanted.max(SHEET_HEIGHT)
            } else {
                wanted
            },
        );
        let now = ctx.input(|input| input.viewport().inner_rect.map(|rect| rect.height()));
        if now.is_some_and(|now| (now - height).abs() > 1.0) {
            ctx.send_viewport_cmd(ViewportCommand::InnerSize(egui::vec2(WIDTH, height)));
        }
        ctx.data_mut(|data| data.insert_temp(wanted_height_id(), wanted));
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

/// The backdrop behind the window when it is drawn in place.
const BACKDROP: Color32 = Color32::from_rgb(207, 208, 213);
/// The space above the window drawn in place, as the sheet of the mockup.
const IN_PLACE_TOP: f32 = 50.0;
/// The traffic lights of a macOS window: their centers in points from the top left of
/// the window, their radius, and their fill and edge colors.
const LIGHTS: [f32; 3] = [16.0, 39.0, 62.0];
const LIGHTS_Y: f32 = 15.5;
const LIGHT_RADIUS: f32 = 7.0;
const LIGHT_COLORS: [(Color32, Color32); 3] = [
    (
        Color32::from_rgb(0xf9, 0x7b, 0x75),
        Color32::from_rgb(0xe9, 0x5e, 0x56),
    ),
    (
        Color32::from_rgb(0xfe, 0xc7, 0x36),
        Color32::from_rgb(0xe0, 0xa2, 0x20),
    ),
    (
        Color32::from_rgb(0x81, 0xd5, 0x5a),
        Color32::from_rgb(0x5e, 0xb1, 0x3b),
    ),
];

/// Settings in place of the main window: the same window as the real one, at its size,
/// centered over a plain backdrop, with painted traffic lights. Its sheets show over it.
pub(super) fn draw_in_place(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let escape = escape_closes(app, ui.ctx());
    super::shell::shortcuts(app, &ui.ctx().clone());
    egui::CentralPanel::default()
        .frame(Frame::NONE.fill(BACKDROP))
        .show(ui, |ui| {
            let area = ui.max_rect();
            let wanted = ui
                .ctx()
                .data(|data| data.get_temp::<f32>(wanted_height_id()))
                .unwrap_or(FIRST_HEIGHT);
            // As tall as the tab, within the main window (the screen of the real one).
            let size = egui::vec2(
                WIDTH.min(area.width()),
                wanted
                    .max(MIN_HEIGHT)
                    .min(area.height() - 2.0 * IN_PLACE_TOP)
                    .max(0.0),
            );
            // At a fixed place near the top, so the tabs stay where the tour clicks.
            let top = area.top() + ((area.height() - size.y) / 2.0).clamp(0.0, IN_PLACE_TOP);
            let window = Rect::from_min_size(
                egui::pos2(area.center().x - size.x / 2.0, top).round(),
                size,
            );
            let painter = ui.painter();
            painter.add(
                egui::Shadow {
                    offset: [0, 16],
                    blur: 48,
                    spread: 0,
                    color: Color32::from_black_alpha(70),
                }
                .as_shape(window, 10),
            );
            painter.rect(
                window,
                10,
                kit::DETAIL,
                egui::Stroke::new(0.5, Color32::from_black_alpha(60)),
                egui::StrokeKind::Outside,
            );
            for (x, (fill, edge)) in LIGHTS.into_iter().zip(LIGHT_COLORS) {
                let center = egui::pos2(window.left() + x, window.top() + LIGHTS_Y);
                painter.circle_filled(center, LIGHT_RADIUS, edge);
                painter.circle_filled(center, LIGHT_RADIUS - 0.5, fill);
            }
            let wanted = ui
                .scope_builder(
                    egui::UiBuilder::new()
                        .max_rect(window)
                        .layout(egui::Layout::top_down(egui::Align::Min)),
                    |ui| {
                        ui.set_clip_rect(window);
                        content(app, ui)
                    },
                )
                .inner;
            ui.ctx()
                .data_mut(|data| data.insert_temp(wanted_height_id(), wanted));
        });
    let ctx = ui.ctx().clone();
    super::shell::sheets(app, &ctx);
    if (closes(&ctx) && ctx.memory(|memory| memory.top_modal_layer()).is_none()) || escape {
        app.settings_open = false;
    }
}
