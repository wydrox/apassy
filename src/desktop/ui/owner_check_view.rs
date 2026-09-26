//! The owner check dialog (goal item A4). It shows the action, runs Touch ID, and
//! takes the passphrase when Touch ID is not available.

use eframe::egui::{self, Modal, RichText};

use super::{
    ASK, DENY, INK, INK_MUTED, OWNER_CHECK_FIELD, PASSPHRASE_CAPACITY, accent_button, password_line,
};
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

    Modal::new(egui::Id::new("apassy-owner-check")).show(ctx, |ui| {
        ui.set_max_width(480.0);
        ui.label(
            RichText::new("Confirm that it is you")
                .size(18.0)
                .strong()
                .color(INK),
        );
        ui.label(RichText::new(action).color(INK));
        ui.label(
            RichText::new(
                "Apassy asks for Touch ID or the passphrase for each reveal, approval, access change, rule change, and token rotation. A notification or \"Mark as seen\" is never an approval.",
            )
            .color(INK_MUTED),
        );
        match running {
            Some(CheckMethod::TouchId) => {
                ui.label(
                    RichText::new("Waiting for Touch ID. Touch the sensor, or cancel the macOS prompt.")
                        .color(ASK),
                );
            }
            Some(CheckMethod::Passphrase) => {
                ui.label(RichText::new("Apassy is checking the passphrase.").color(ASK));
            }
            None => {}
        }
        if let Some(note) = &note {
            ui.label(RichText::new(note).color(ASK));
        }
        if let Some(message) = &message {
            ui.label(RichText::new(message).color(DENY));
        }
        ui.add_enabled_ui(running.is_none(), |ui| {
            ui.add_enabled_ui(has_helper, |ui| {
                if ui.button("Use Touch ID").clicked() {
                    touch_id = true;
                }
            });
            if let Some(dialog) = app.owner.check.as_mut() {
                let field = password_line(
                    ui,
                    OWNER_CHECK_FIELD,
                    "Passphrase",
                    &mut dialog.passphrase,
                    PASSPHRASE_CAPACITY,
                );
                if field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                    passphrase = true;
                }
            }
            if accent_button(ui, "Confirm with passphrase").clicked() {
                passphrase = true;
            }
        });
        if ui.button("Cancel").clicked() {
            cancel = true;
        }
    });

    if cancel {
        app.close_owner_check(Some(ctx));
        app.set_ok("The owner check is cancelled. Apassy did nothing.");
    } else if touch_id {
        app.start_owner_check(OwnerCheck::TouchId, Some(ctx.clone()));
    } else if passphrase {
        app.start_passphrase_check(ctx);
    }
}
