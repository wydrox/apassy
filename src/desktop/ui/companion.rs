//! Settings > Devices > iPhone app: the iPhone listener, the pairing QR code, the code the owner
//! types, and the paired iPhones (ADR 0020).
//!
//! The Mac never shows the 6-digit code: only the iPhone does, and the owner types it
//! here. The QR code is drawn from its modules. The link is never a text on the screen
//! and never on the pasteboard, because an agent can read the pasteboard.

use eframe::egui::{self, Color32, Key, Rect, Response, Sense, Ui, Vec2, WidgetInfo, WidgetType};

use super::kit::{self, Font, Style, Tone};
use super::settings::rows;
use super::timeline::relative_time;
use super::{Sheet, close_sheet};
use crate::companion::pairing::PairingView;
use crate::desktop::DesktopApp;
use crate::desktop::companion::{Listener, QUIET_ZONE, QrModules, now};
use crate::desktop::owner_store::format_utc;

/// The width of the QR code in points, about. The modules are whole points.
const QR_POINTS: f32 = 200.0;
/// A code is 6 digits. The field ignores spaces, wherever they stand (`348 942`,
/// `3 4 8 9 4 2`), so the cap counts digits and not spaces.
const CODE_DIGITS: usize = 6;
/// A bound on the whole text, so that a paste of spaces does not fill the field.
const CODE_MAX_CHARS: usize = 32;

/// Settings > Devices > iPhone app: the listener with its state and "Pair…", the
/// pairing code while a pairing runs, and the paired iPhones.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut Ui) {
    listener_section(app, ui);
    if app.companion_controller().is_some() {
        pairing_section(app, ui);
    }
    devices_section(app, ui);
}

fn listener_section(app: &mut DesktopApp, ui: &mut Ui) {
    let enabled = app
        .owner_ui
        .session
        .companion_status()
        .is_ok_and(|(setting, _)| setting.enabled);
    let mut on = enabled;
    let mut retry = false;
    let mut pair = false;
    // "Pair…" is a row here while no pairing runs.
    let closed = app
        .companion_controller()
        .map(|controller| matches!(controller.view(), PairingView::Closed));
    let opening = app.companion.opening_window();
    rows::section(
        ui,
        Some("iPhone app"),
        Some(
            "The iPhone app approves runs that wait for you with Face ID, on this network or through Tailscale. It never shows a secret value or changes a setting.",
        ),
        |g| {
            g.toggle("Allow the iPhone app on this network", None, &mut on);
            match &app.companion.listener {
                Listener::Running { handle, .. } => g.line(
                    "Status",
                    Some(
                        kit::text(format!("Listening on port {}", handle.port()), Font::Body)
                            .color(Tone::Good.text()),
                    ),
                    |_| {},
                ),
                Listener::Failed { message, .. } => g.line_note(
                    "Status",
                    None,
                    Some(kit::text(message, Font::Callout).color(Tone::Critical.text())),
                    |ui| {
                        retry = kit::small_button(ui, "Try again", Style::Bordered).clicked();
                    },
                ),
                Listener::Off => g.line(
                    "Status",
                    Some(rows::value(if enabled {
                        "Starting"
                    } else {
                        "Off. Nothing listens on the network."
                    })),
                    |_| {},
                ),
            }
            if closed == Some(true) {
                g.row(|ui| {
                    rows::one_line(
                        ui,
                        rows::label_text("Pair an iPhone").into(),
                        opening.then(|| rows::value("Apassy is making the pairing code.")),
                        |ui| {
                            if !opening {
                                pair = kit::small_button(ui, "Pair…", Style::Bordered)
                                    .on_hover_text(
                                        "Open the Apassy app on the iPhone and scan the code. Then type the 6-digit code that the iPhone shows.",
                                    )
                                    .clicked();
                            }
                        },
                    );
                    if !opening {
                        ui.add(egui::Label::new(rows::note(
                            "Open the Apassy app on the iPhone and scan the code. Then type the 6-digit code that the iPhone shows.",
                        ))
                        .wrap());
                    }
                    notice(app, ui);
                });
            }
        },
    );
    if on != enabled {
        app.set_companion_on(on);
    }
    if retry {
        app.retry_companion();
    }
    if pair {
        let ctx = ui.ctx().clone();
        app.open_pairing(&ctx);
    }
}

/// "4:32" for 272 seconds.
pub(super) fn countdown(seconds: u64) -> String {
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

fn pairing_section(app: &mut DesktopApp, ui: &mut Ui) {
    let Some(controller) = app.companion_controller() else {
        return;
    };
    let view = controller.view();
    let mac_name = app.companion.mac_name().unwrap_or_default().to_owned();
    let check_open = app.owner.check.is_some();
    let mut cancel = false;
    let mut submit = false;
    let footer = match &view {
        PairingView::Closed => "",
        PairingView::Open { .. } => {
            "Do not photograph or share this code. Nothing pairs until you type the code that only the iPhone shows and confirm with Touch ID or your passphrase."
        }
        PairingView::Waiting { .. } => {
            "Apassy never shows this code on the Mac. A wrong code pairs nothing, and the third closes the window."
        }
    };
    // The main control of a new pairing step takes the focus (for a keyboard user):
    // Cancel while the code shows, and the code field when the iPhone asks.
    let step = match &view {
        PairingView::Closed => 0u8,
        PairingView::Open { .. } => 1,
        PairingView::Waiting { .. } => 2,
    };
    let step_key = egui::Id::new("apassy-pairing-step");
    let started = ui.ctx().data(|data| data.get_temp::<u8>(step_key)) != Some(step)
        && step != 0
        && kit::keyboard_mode(ui.ctx());
    ui.ctx().data_mut(|data| data.insert_temp(step_key, step));
    // While no pairing runs, "Pair…" is a row of the iPhone app.
    if matches!(view, PairingView::Closed) {
        return;
    }
    rows::section(ui, Some("Pair an iPhone"), Some(footer), |s| match &view {
        PairingView::Closed => {}
        PairingView::Open { expires_at } => {
            s.row(|ui| match &app.companion.invite {
                Some(qr) => {
                    ui.vertical_centered(|ui| {
                        draw_qr(ui, qr, QR_POINTS, "Pairing QR code");
                    });
                }
                None => kit::note(ui, "Apassy is making the pairing code."),
            });
            s.labeled("Mac name", rows::value(&mac_name));
            let left = expires_at.saturating_sub(now());
            s.row(|ui| {
                rows::one_line(
                    ui,
                    rows::label_text("Code works for").into(),
                    Some(kit::text(countdown(left), Font::Mono).color(kit::SECONDARY)),
                    |ui| {
                        let button = kit::small_button(ui, "Cancel", Style::Bordered);
                        if started {
                            button.request_focus();
                        }
                        cancel = button.clicked();
                    },
                );
                notice(app, ui);
            });
        }
        PairingView::Waiting {
            device_name,
            wrong_codes,
            ..
        } => {
            s.row(|ui| {
                kit::paragraph(
                    ui,
                    format!(
                        "\"{device_name}\" wants to pair. Type the 6-digit code that the iPhone shows."
                    ),
                    Font::Body,
                    kit::LABEL,
                );
                if *wrong_codes > 0 {
                    kit::tone_note(
                        ui,
                        format!("Wrong codes so far: {wrong_codes} of 3."),
                        Tone::Warning,
                    );
                }
            });
            s.field("Code", |ui| {
                let field = kit::mono_input(
                    ui,
                    &mut app.companion.code,
                    "companion-code",
                    "6 digits, spaces are ignored",
                );
                keep_code_characters(&mut app.companion.code);
                if started {
                    field.request_focus();
                }
                if !check_open
                    && field.lost_focus()
                    && field.ctx.input(|input| input.key_pressed(Key::Enter))
                {
                    submit = true;
                }
                field
            });
            s.row(|ui| {
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!check_open, |ui| {
                        submit |= kit::small_button(ui, "Pair", Style::Prominent).clicked();
                    });
                    cancel = kit::small_button(ui, "Cancel", Style::Bordered).clicked();
                });
                notice(app, ui);
            });
        }
    });
    if cancel {
        app.cancel_pairing();
    }
    if submit {
        let ctx = ui.ctx().clone();
        app.submit_pairing_code(&ctx);
    }
}

/// The line under the pairing controls, if there is one.
fn notice(app: &DesktopApp, ui: &mut Ui) {
    if let Some(notice) = &app.companion.notice {
        let tone = if notice.error {
            Tone::Critical
        } else {
            Tone::Neutral
        };
        kit::tone_note(ui, &notice.text, tone);
    }
}

/// Keep digits and spaces, and stop after the sixth digit. Any other character goes.
pub(super) fn keep_code_characters(code: &mut String) {
    let mut digits = 0;
    let mut kept = String::new();
    for c in code.chars().filter(|c| c.is_ascii_digit() || *c == ' ') {
        if kept.len() >= CODE_MAX_CHARS || (c.is_ascii_digit() && digits >= CODE_DIGITS) {
            break;
        }
        // Spaces after the last digit are not kept: they cannot be part of the code.
        if c == ' ' && digits >= CODE_DIGITS {
            break;
        }
        digits += usize::from(c.is_ascii_digit());
        kept.push(c);
    }
    if kept != *code {
        *code = kept;
    }
}

/// Draw the QR code black on white with a quiet zone of 4 modules. The modules are whole
/// points, so the code is about `size` points wide and stays sharp. A run of dark
/// modules in a row is one rectangle, so no seam shows between two modules. `label` names
/// the image for VoiceOver. The pairing QR code here and the link of "Add a device…" in
/// Settings > Devices > Sync use it.
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

fn devices_section(app: &mut DesktopApp, ui: &mut Ui) {
    let devices = app.owner_ui.session.companion_devices().unwrap_or_default();
    let now = now();
    let mut remove = None;
    let mut reset = false;
    rows::section(
        ui,
        Some("Paired iPhones"),
        Some("Removing an iPhone takes effect at once. \"Reset pairing\" removes every iPhone."),
        |s| {
            if devices.is_empty() {
                s.note_row("No iPhone is paired.");
            }
            for device in &devices {
                let date = format_utc(device.paired_at);
                let paired = date.split(' ').next().unwrap_or_default();
                let seen = device
                    .last_seen_at
                    .map_or_else(|| "never".to_owned(), |at| relative_time(at, now));
                s.line_note(
                    &device.name,
                    None,
                    Some(rows::note(&format!("Paired {paired}. Last seen {seen}."))),
                    |ui| {
                        let button = kit::small_button(ui, "Remove", Style::Destructive);
                        let name = format!("Remove {}", device.name);
                        ui.ctx()
                            .accesskit_node_builder(button.id, |node| node.set_label(name));
                        if button.clicked() {
                            remove = Some((device.device_id.clone(), device.name.clone()));
                        }
                    },
                );
            }
            reset = s
                .clickable_row("Reset pairing…", |ui| {
                    ui.label(kit::text("Reset pairing…", Font::Body).color(Tone::Critical.text()));
                })
                .on_hover_text(
                    "Removes every iPhone and makes a new certificate, so an iPhone that pinned the old one cannot connect.",
                )
                .clicked();
        },
    );
    if let Some((id, name)) = remove {
        app.remove_companion_device(&id, &name);
    }
    if reset {
        app.ui.sheet = Some(Sheet::ResetCompanion);
    }
}

/// The confirmation of "Reset pairing". A reset only takes authority away, so it needs no
/// owner check.
pub(super) fn reset_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut reset = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "reset-companion", 420.0, |ui| {
        kit::sheet_title(
            ui,
            "Reset pairing?",
            Some(
                "Apassy removes every paired iPhone and makes a new certificate. Each iPhone must pair again, and an iPhone that pinned the old certificate cannot connect.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                reset = kit::button(ui, "Reset pairing", Style::DestructiveProminent).clicked();
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
