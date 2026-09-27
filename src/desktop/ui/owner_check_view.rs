//! The owner check sheet (goal item A4). It shows the action, runs Touch ID, and takes
//! the passphrase when Touch ID is not available.

use eframe::egui::{self, Key};

use super::kit::{self, Font, Icon, Size, Style, Tone};
use super::{OWNER_CHECK_FIELD, PASSPHRASE_CAPACITY, secure_input};
use crate::broker::approvals::{CheckMethod, OwnerCheck};
use crate::desktop::DesktopApp;

pub(super) fn draw(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(dialog) = app.owner.check.as_ref() else {
        return;
    };
    let action = dialog.request.describe();
    let running = dialog.running.as_ref().map(|(method, _)| *method);
    let message = dialog.message.clone();
    let note = app.owner.touch_id_note();
    let has_helper = app.owner.helper.is_some();
    let mut touch_id = false;
    let mut passphrase = false;
    let mut cancel = false;

    let response = kit::sheet(ctx, "owner-check", 440.0, |ui| {
        ui.horizontal(|ui| {
            kit::icon_tile_sized(ui, Icon::Lock, kit::ACCENT, 32.0);
            ui.add_space(2.0);
            ui.label(kit::text("Confirm that it is you", Font::Title3).color(kit::LABEL));
        });
        ui.add_space(8.0);
        kit::paragraph(ui, action, Font::Body, kit::LABEL);
        ui.add_space(4.0);
        kit::note(
            ui,
            "Apassy asks for Touch ID or the passphrase for each reveal, approval, access change, rule change, and token rotation. A notification or \"Mark as seen\" is never an approval.",
        );
        ui.add_space(10.0);
        match running {
            Some(CheckMethod::TouchId) => kit::tone_note(
                ui,
                "Waiting for Touch ID. Touch the sensor, or cancel the macOS prompt.",
                Tone::Warning,
            ),
            Some(CheckMethod::Passphrase) => {
                kit::tone_note(ui, "Apassy is checking the passphrase.", Tone::Accent);
            }
            None => {}
        }
        if let Some(message) = &message {
            kit::tone_note(ui, message, Tone::Critical);
        }
        ui.add_enabled_ui(running.is_none(), |ui| {
            kit::section(ui, None, note.as_deref(), |s| {
                if let Some(dialog) = app.owner.check.as_mut() {
                    let field = s.field("Passphrase", |ui| {
                        secure_input(
                            ui,
                            OWNER_CHECK_FIELD,
                            &mut dialog.passphrase,
                            PASSPHRASE_CAPACITY,
                            "Required",
                        )
                    });
                    if running.is_none() && !field.has_focus() && !field.lost_focus() {
                        let focused = field.ctx.memory(|memory| memory.focused());
                        if focused.is_none() {
                            field.request_focus();
                        }
                    }
                    if field.lost_focus() && field.ctx.input(|input| input.key_pressed(Key::Enter))
                    {
                        passphrase = true;
                    }
                }
            });
        });
        let idle = running.is_none();
        kit::sheet_buttons(
            ui,
            |ui| {
                if has_helper
                    && ui
                        .add_enabled_ui(idle, |ui| {
                            kit::button_with(ui, None, "Use Touch ID", Style::Link, Size::Regular)
                        })
                        .inner
                        .clicked()
                {
                    touch_id = true;
                }
            },
            |ui| {
                passphrase |= ui
                    .add_enabled_ui(idle, |ui| kit::button(ui, "Confirm", Style::Prominent))
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });

    if cancel || (response.escape && running.is_none()) {
        app.close_owner_check(Some(ctx));
        app.set_note("The owner check is cancelled. Apassy did nothing.");
    } else if touch_id {
        app.start_owner_check(OwnerCheck::TouchId, Some(ctx.clone()));
    } else if passphrase {
        app.start_passphrase_check(ctx);
    }
}
