//! Settings > Devices > Wi-Fi Pairing: the iPhone listener and the paired Wi-Fi iPhones
//! (ADR 0020), in the notice state of ADR 0028 stage 3 (plan S2–S3, unit W1 in N7).
//!
//! The group shows only while a Wi-Fi iPhone is paired. It has the warning line "Wi-Fi
//! pairing ends in two versions." with its help, "Listen on This Network" (the listener
//! switch, "Allow the iPhone app on this network" before), each iPhone with Remove…, and
//! Reset Pairing…. New pairing is no longer possible: there is no "Pair an iPhone" and no
//! pairing code here. When the last iPhone goes, the group goes and the listener stops.
//! The once-only notice is in [`super::devices`].
//!
//! The QR code drawing below stays for the device links of relay sync.

use eframe::egui::{self, Color32, Rect, Response, Sense, Ui, Vec2, WidgetInfo, WidgetType};

use super::devices::{self, Action, WifiDevice, WifiEnd, WifiView};
use super::kit::{self, Style};
use super::{Sheet, close_sheet};
use crate::companion::pairing::PairingView;
use crate::desktop::DesktopApp;
use crate::desktop::companion::{Listener, QUIET_ZONE, QrModules, now};

/// The Wi-Fi Pairing group of the open vault now, or `None` without a paired iPhone.
pub(super) fn wifi_view(app: &DesktopApp) -> Option<WifiView> {
    let devices = app.owner_ui.session.companion_devices().unwrap_or_default();
    if devices.is_empty() {
        return None;
    }
    let enabled = app
        .owner_ui
        .session
        .companion_status()
        .is_ok_and(|(setting, _)| setting.enabled);
    let failed = match &app.companion.listener {
        Listener::Failed { message, .. } => Some(message.clone()),
        _ => None,
    };
    Some(WifiView {
        listening: enabled,
        starting: enabled && matches!(app.companion.listener, Listener::Off),
        failed,
        devices: devices
            .into_iter()
            .map(|device| WifiDevice {
                id: device.device_id,
                name: device.name,
                paired_at: device.paired_at,
                last_seen_at: device.last_seen_at,
            })
            .collect(),
        end: WifiEnd::NOW,
    })
}

/// Settings > Devices > Wi-Fi Pairing. Without a paired iPhone there is no group, and a
/// listener that is still on stops, unless a pairing window of the listener is open.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut Ui) {
    let Some(view) = wifi_view(app) else {
        let enabled = app
            .owner_ui
            .session
            .companion_status()
            .is_ok_and(|(setting, _)| setting.enabled);
        let pairing = app.companion.opening_window()
            || app
                .companion_controller()
                .is_some_and(|controller| !matches!(controller.view(), PairingView::Closed));
        if enabled && !pairing {
            app.set_companion_on(false);
        }
        return;
    };
    let action = devices::wifi_group(ui, &view, now());
    match action {
        Some(Action::Listen(on)) => app.set_companion_on(on),
        Some(Action::RetryWifi) => app.retry_companion(),
        Some(Action::RemoveWifi(id, name)) => {
            app.remove_companion_device(&id, &name);
            // The last iPhone went: the group goes, and the listener stops.
            if view.devices.len() == 1 {
                app.set_companion_on(false);
            }
        }
        Some(Action::ResetWifi) => app.ui.sheet = Some(Sheet::ResetCompanion),
        _ => {}
    }
}

/// Draw the QR code black on white with a quiet zone of 4 modules. The modules are whole
/// points, so the code is about `size` points wide and stays sharp. A run of dark
/// modules in a row is one rectangle, so no seam shows between two modules. `label` names
/// the image for VoiceOver. The pairing QR code here and the link of "Add a device…" in
/// Settings > Vault > Sync use it.
pub(super) fn draw_qr(ui: &mut Ui, qr: &QrModules, size: f32, label: &str) -> Response {
    let total = qr.width() + 2 * QUIET_ZONE;
    let unit = (size / total as f32).floor().max(1.0);
    let side = unit * total as f32;
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Image, true, label));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect, 0, Color32::WHITE);
        for y in 0..qr.width() {
            let top = rect.top() + (y + QUIET_ZONE) as f32 * unit;
            let mut x = 0;
            while x < qr.width() {
                if !qr.is_dark(x, y) {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < qr.width() && qr.is_dark(x, y) {
                    x += 1;
                }
                let left = rect.left() + (start + QUIET_ZONE) as f32 * unit;
                let run = Rect::from_min_size(
                    egui::pos2(left, top),
                    Vec2::new((x - start) as f32 * unit, unit),
                );
                painter.rect_filled(run, 0, Color32::BLACK);
            }
        }
    }
    response
}

/// The confirmation of "Reset pairing". A reset only takes authority away, so it needs no
/// owner check.
pub(super) fn reset_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut reset = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "reset-companion", 420.0, |ui| {
        kit::sheet_title(
            ui,
            "Reset Pairing?",
            Some(
                "Apassy removes every paired iPhone and makes a new certificate. Each iPhone must pair again, and an iPhone that pinned the old certificate cannot connect.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                reset = kit::button(ui, "Reset Pairing", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if reset {
        app.ui.sheet = None;
        app.reset_companion();
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}
