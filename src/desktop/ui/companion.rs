//! Settings > Notifications > iPhone companion: the iPhone listener, the pairing QR code, the code the owner
//! types, and the paired iPhones (ADR 0020).
//!
//! The Mac never shows the 6-digit code: only the iPhone does, and the owner types it
//! here. The QR code is drawn from its modules. The link is never a text on the screen
//! and never on the pasteboard, because an agent can read the pasteboard.

use eframe::egui::{self, Color32, Key, Rect, Response, Sense, Ui, Vec2, WidgetInfo, WidgetType};

use super::kit::{self, Font, Icon, Style, Tone};
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
    kit::section(
        ui,
        Some("iPhone companion"),
        Some(
            "The iPhone app shows the runs that wait for you and approves them with Face ID. It never shows a secret value, and it cannot change a grant, a rule, or a setting. It reaches this Mac only on the same network.",
        ),
        |s| {
            s.toggle(
                "Allow the iPhone app on this network",
                Some(
                    "Paired iPhones can approve or deny runs that wait for you. This works only while the vault is unlocked.",
                ),
                &mut on,
            );
            match &app.companion.listener {
                Listener::Running { handle, .. } => s.labeled(
                    "Status",
                    kit::text(
                        format!("Listening on port {}", handle.port()),
                        Font::Callout,
                    )
                    .color(Tone::Good.text()),
                ),
                Listener::Failed { message, .. } => s.row(|ui| {
                    kit::tone_note(ui, message, Tone::Critical);
                    retry = kit::small_button(ui, "Try again", Style::Bordered).clicked();
                }),
                Listener::Off => s.labeled(
                    "Status",
                    kit::text(
                        if enabled {
                            "Starting"
                        } else {
                            "Off. Nothing listens on the network."
                        },
                        Font::Callout,
                    )
                    .color(kit::SECONDARY),
                ),
            }
        },
    );
    if on != enabled {
        app.set_companion_on(on);
    }
    if retry {
        app.retry_companion();
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
    let opening = app.companion.opening_window();
    let mac_name = app.companion.mac_name().unwrap_or_default().to_owned();
    let check_open = app.owner.check.is_some();
    let mut open = false;
    let mut cancel = false;
    let mut submit = false;
    let footer = match &view {
        PairingView::Closed => Some(
            "Open the Apassy app on the iPhone and scan the code. Then type the 6-digit code that the iPhone shows.",
        ),
        PairingView::Open { .. } => Some(
            "Do not photograph or share this code. Anyone who scans it can ask to pair, but nothing is paired until you type the code that only the iPhone shows and confirm with Touch ID or your passphrase.",
        ),
        PairingView::Waiting { .. } => Some(
            "Apassy never shows this code on the Mac. A wrong code pairs nothing, and the third wrong code closes the window.",
        ),
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
    kit::section(ui, Some("Pair an iPhone"), footer, |s| match &view {
        PairingView::Closed => s.row(|ui| {
            if opening {
                kit::note(ui, "Apassy is making the pairing code.");
            } else {
                ui.horizontal(|ui| {
                    kit::icon_tile(ui, Icon::Phone, kit::ACCENT);
                    ui.add_space(4.0);
                    open = kit::button(ui, "Pair an iPhone", Style::Prominent).clicked();
                });
            }
            notice(app, ui);
        }),
        PairingView::Open { expires_at } => {
            s.row(|ui| match &app.companion.invite {
                Some(qr) => {
                    ui.vertical_centered(|ui| {
                        draw_qr(ui, qr, QR_POINTS);
                    });
                }
                None => kit::note(ui, "Apassy is making the pairing code."),
            });
            s.labeled(
                "Mac name",
                kit::text(&mac_name, Font::Body).color(kit::SECONDARY),
            );
            let left = expires_at.saturating_sub(now());
            s.labeled(
                "Code works for",
                kit::text(countdown(left), Font::Mono).color(kit::SECONDARY),
            );
            s.row(|ui| {
                let button = kit::button(ui, "Cancel", Style::Bordered);
                if started {
                    button.request_focus();
                }
                cancel = button.clicked();
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
                        submit |= kit::button(ui, "Pair", Style::Prominent).clicked();
                    });
                    cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
                });
                notice(app, ui);
            });
        }
    });
    if open {
        let ctx = ui.ctx().clone();
        app.open_pairing(&ctx);
    }
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
/// modules in a row is one rectangle, so no seam shows between two modules.
pub(super) fn draw_qr(ui: &mut Ui, qr: &QrModules, size: f32) -> Response {
    let total = qr.width() + 2 * QUIET_ZONE;
    let unit = (size / total as f32).floor().max(1.0);
    let side = unit * total as f32;
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Image, true, "Pairing QR code"));
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
    kit::section(
        ui,
        Some("Paired iPhones"),
        Some(
            "Removing an iPhone takes effect at once. \"Reset pairing\" removes every iPhone and makes a new certificate, so an iPhone that pinned the old one cannot connect.",
        ),
        |s| {
            if devices.is_empty() {
                s.row(|ui| kit::note(ui, "No iPhone is paired."));
            }
            for device in &devices {
                s.row(|ui| {
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            ui.vertical(|ui| {
                                ui.label(kit::text(&device.name, Font::Body).color(kit::LABEL));
                                let date = format_utc(device.paired_at);
                                let paired = date.split(' ').next().unwrap_or_default();
                                let seen = device.last_seen_at.map_or_else(
                                    || "never".to_owned(),
                                    |at| relative_time(at, now),
                                );
                                kit::note(ui, format!("Paired {paired}. Last seen {seen}."));
                            });
                        },
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
                });
            }
            reset = s
                .clickable_row("Reset pairing…", |ui| {
                    ui.label(kit::text("Reset pairing…", Font::Body).color(Tone::Critical.text()));
                })
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
