//! The unlock method: passphrase or Touch ID (goal items A2, A3).

use eframe::egui::{self, RichText};

use super::{
    ASK, INK, INK_MUTED, PASSPHRASE_CAPACITY, TOUCH_ID_SETUP_FIELD, accent_button, card_frame,
    password_line,
};
use crate::desktop::DesktopApp;
use crate::desktop::unlock::UnlockMethod;

/// Touch ID unlock in the Vault file card. It shows only for a locked vault file.
pub(super) fn draw_touch_id_unlock(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let session = &app.owner_ui.session;
    if !session.has_file() || !session.is_locked() {
        return;
    }
    let unlock = &app.owner.unlock;
    if unlock.reading.is_some() {
        ui.label(RichText::new("Apassy is checking the Touch ID unlock setting.").color(INK_MUTED));
        return;
    }
    let Some(setting) = unlock.setting.clone() else {
        return;
    };
    if let Some(note) = &setting.note {
        ui.label(RichText::new(note).color(ASK));
    }
    if setting.method != UnlockMethod::TouchId {
        return;
    }
    if unlock.unlocking.is_some() {
        ui.label(
            RichText::new("Waiting for Touch ID. Touch the sensor, or cancel the macOS prompt.")
                .color(ASK),
        );
        return;
    }
    ui.horizontal_wrapped(|ui| {
        if accent_button(ui, "Unlock with Touch ID").clicked() {
            let ctx = ui.ctx().clone();
            app.start_touch_id_unlock(&ctx);
        }
        ui.label(RichText::new("You can also type the passphrase.").color(INK_MUTED));
    });
}

/// The unlock method card for an unlocked vault.
pub(super) fn draw_unlock_method_card(app: &mut DesktopApp, ui: &mut egui::Ui) {
    card_frame().show(ui, |ui| {
        ui.label(RichText::new("Unlock method").size(16.0).strong().color(INK));
        ui.label(
            RichText::new(
                "Unlock is your choice: the passphrase or Touch ID. The passphrase stays the root key. Touch ID setup, backup restore, and recovery need the passphrase. Apassy reads this setting from the keychain before unlock, without a prompt. A fingerprint change turns Touch ID unlock off.",
            )
            .color(INK_MUTED),
        );
        let touch_id_for_checks = app.owner.touch_id_note().map_or_else(
            || "Touch ID for owner checks: available.".to_owned(),
            |note| format!("Touch ID for owner checks: {note}"),
        );
        ui.label(RichText::new(touch_id_for_checks).color(INK_MUTED));

        let unlock = &app.owner.unlock;
        if unlock.reading.is_some() || unlock.changing.is_some() {
            ui.label(RichText::new("Apassy is reading or changing the Touch ID unlock setting.").color(INK_MUTED));
            return;
        }
        let Some(setting) = unlock.setting.clone() else {
            ui.label(RichText::new("Current: passphrase.").color(INK));
            return;
        };
        if let Some(note) = &setting.note {
            ui.label(RichText::new(note).color(ASK));
        }
        let ctx = ui.ctx().clone();
        match setting.method {
            UnlockMethod::TouchId => {
                ui.label(RichText::new("Current: Touch ID. The passphrase still works.").color(INK));
                if ui.button("Turn off Touch ID unlock").clicked() {
                    app.start_touch_id_off(
                        Some(&ctx),
                        "Touch ID unlock is off. Apassy deleted the unlock key from the keychain.",
                    );
                }
            }
            UnlockMethod::Passphrase => {
                ui.label(RichText::new("Current: passphrase.").color(INK));
                if !setting.can_set_up {
                    return;
                }
                password_line(
                    ui,
                    TOUCH_ID_SETUP_FIELD,
                    "Passphrase (needed to turn on Touch ID unlock)",
                    &mut app.owner.unlock.setup_passphrase,
                    PASSPHRASE_CAPACITY,
                );
                if accent_button(ui, "Turn on Touch ID unlock").clicked() {
                    app.start_touch_id_setup(&ctx);
                }
            }
        }
    });
}
