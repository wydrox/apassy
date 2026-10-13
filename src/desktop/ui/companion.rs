//! Settings > Devices > "Pair on this network" (L3): the iPhone listener, the pairing QR
//! code, and the code the owner types (ADR 0020). The paired iPhones show in the list of
//! devices of the hub (`super::devices`), as "Approves on this Wi-Fi only".
//!
//! The Mac never shows the 6-digit code: only the iPhone does, and the owner types it
//! here. The QR code is drawn from its modules. The link is never a text on the screen
//! and never on the pasteboard, because an agent can read the pasteboard.

use eframe::egui::{self, Color32, Key, Rect, Response, Sense, Ui, Vec2, WidgetInfo, WidgetType};

use super::kit::{self, Font, Style, Tone};
use super::settings::rows;
use super::{Sheet, close_sheet};
use crate::companion::pairing::PairingView;
use crate::desktop::DesktopApp;
use crate::desktop::companion::{Listener, QUIET_ZONE, QrModules, now};

/// The width of the QR code in points, about. The modules are whole points.
const QR_POINTS: f32 = 200.0;
/// A code is 6 digits. The field ignores spaces, wherever they stand (`348 942`,
/// `3 4 8 9 4 2`), so the cap counts digits and not spaces.
const CODE_DIGITS: usize = 6;
/// A bound on the whole text, so that a paste of spaces does not fill the field.
const CODE_MAX_CHARS: usize = 32;

/// "Pair on this network": the listener switch, "Pair…", and "Reset pairing…" in one
/// group, and the pairing code below it while a pairing runs.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut Ui) {
    listener_group(app, ui);
    if app.companion_controller().is_some() {
        pairing_section(app, ui);
    }
}

fn listener_group(app: &mut DesktopApp, ui: &mut Ui) {
    let enabled = app
        .owner_ui
        .session
        .companion_status()
        .is_ok_and(|(setting, _)| setting.enabled);
    let paired = app
        .owner_ui
        .session
        .companion_devices()
        .is_ok_and(|devices| !devices.is_empty());
    let mut on = enabled;
    let mut retry = false;
    let mut pair = false;
    let mut reset = false;
    // "Pair…" is a row here while no pairing runs and the listener did not fail.
    let pairing = app
        .companion_controller()
        .is_some_and(|controller| !matches!(controller.view(), PairingView::Closed));
    let failed = matches!(app.companion.listener, Listener::Failed { .. });
    let opening = app.companion.opening_window();
    rows::section(
        ui,
        None,
        Some(
            "Without Apassy Connect: an iPhone on the same Wi-Fi as this Mac approves with Face ID. It never shows a secret value.",
        ),
        |g| {
            // The state of the listener only when it is not plainly on or off.
            let subtitle = match &app.companion.listener {
                Listener::Off if enabled => Some("Starting"),
                _ => None,
            };
            g.toggle("Allow the iPhone app on this network", subtitle, &mut on);
            if let Listener::Failed { message, .. } = &app.companion.listener {
                g.line_note(
                    "Listener",
                    None,
                    Some(kit::text(message, Font::Callout).color(Tone::Critical.text())),
                    |ui| {
                        retry = kit::small_button(ui, "Try again", Style::Bordered).clicked();
                    },
                );
            }
            if !pairing && !failed {
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
                    notice(app, ui);
                });
            }
            if paired {
                reset = g
                    .clickable_row("Reset pairing…", |ui| {
                        ui.label(
                            kit::text("Reset pairing…", Font::Body).color(Tone::Critical.text()),
                        );
                    })
                    .on_hover_text(
                        "Removes every iPhone and makes a new certificate, so an iPhone that pinned the old one cannot connect.",
                    )
                    .clicked();
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
        super::settings::add_an_iphone(app, &ctx);
    }
    if reset {
        app.ui.sheet = Some(Sheet::ResetCompanion);
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
    // While no pairing runs, "Pair…" is a row of the iPhone group.
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

/// The name of the iPhone that asks to pair on this network and the wrong codes so far,
/// while one asks.
pub(super) fn asking_to_pair(app: &DesktopApp) -> Option<(String, u32)> {
    match app.companion_controller()?.view() {
        PairingView::Waiting {
            device_name,
            wrong_codes,
            ..
        } => Some((device_name, wrong_codes)),
        _ => None,
    }
}

/// The 6-digit code field of a pairing on this network and "Pair", for the sheet of
/// "Add a device" when the iPhone fell back to this network. Returns whether the owner
/// submitted the code.
pub(super) fn code_entry(app: &mut DesktopApp, ui: &mut Ui, device_name: &str, wrong: u32) -> bool {
    let check_open = app.owner.check.is_some();
    let mut submit = false;
    kit::paragraph(
        ui,
        format!(
            "“{device_name}” wants to pair on this network. Type the 6-digit code that it shows."
        ),
        Font::Body,
        kit::LABEL,
    );
    if wrong > 0 {
        kit::tone_note(
            ui,
            format!("Wrong codes so far: {wrong} of 3."),
            Tone::Warning,
        );
    }
    ui.horizontal(|ui| {
        let field = kit::mono_input(
            ui,
            &mut app.companion.code,
            "companion-code-sheet",
            "6 digits",
        );
        keep_code_characters(&mut app.companion.code);
        if !check_open
            && field.lost_focus()
            && field.ctx.input(|input| input.key_pressed(Key::Enter))
        {
            submit = true;
        }
        ui.add_enabled_ui(!check_open, |ui| {
            submit |= kit::small_button(ui, "Pair", Style::Prominent).clicked();
        });
    });
    notice(app, ui);
    submit
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
