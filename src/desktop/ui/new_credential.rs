//! "New Credential" (ADR 0026 §4): "+" in a list and ⌘N open it.
//!
//! The decision: the owner pastes a key, a `.env` file, a database URL, or an
//! `otpauth://` link, and Add saves what Apassy detects, in the selected folder. Until
//! the detection lands, this sheet leads to the kind picker of the add form, so the
//! owner can still add a credential.

use eframe::egui;

use super::kit::{self, Style};
use super::{close_sheet, save_pressed};
use crate::desktop::DesktopApp;

/// The sheet. Returns true on Escape.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut choose = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "new-credential", 480.0, |ui| {
        kit::sheet_title(
            ui,
            "New Credential",
            Some("Choose the kind of the credential, then fill in its fields."),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                choose = kit::button(ui, "Choose Kind…", Style::Prominent).clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if choose || save_pressed(app, ctx) {
        // The add form replaces this sheet.
        super::items::open_add(app);
    } else if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}
