//! Settings: the vault file, security, backup, agents, notifications, and the broker.
//! Each change that is rare or risky opens a sheet.

use std::path::PathBuf;

use eframe::egui;

use super::kit::{self, Font, Icon, Style, Tone};
use super::{
    CHANGE_FIELDS, PASSPHRASE_CAPACITY, Sheet, TOUCH_ID_SETUP_FIELD, close_sheet,
    forget_secret_field, secure_input, start,
};
use crate::desktop::notify::{self, Delivery};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::Ephemeral;
use crate::desktop::unlock::UnlockMethod;
use crate::desktop::{BrokerState, DesktopApp};
use crate::vault::DEFAULT_TOKEN_LIFETIME_DAYS;

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::page_header(ui, "Settings", None, |_| {});
    vault_section(app, ui);
    security_section(app, ui);
    backup_section(app, ui);
    agents_section(app, ui);
    notifications_section(app, ui);
    super::companion::draw(app, ui);
    broker_section(app, ui);
    shortcuts_section(ui);
    kit::section(ui, Some("About"), None, |s| {
        s.labeled(
            "Version",
            kit::text(env!("CARGO_PKG_VERSION"), Font::Body).color(kit::SECONDARY),
        );
        s.labeled(
            "Contract",
            kit::text(crate::contracts::CONTRACT_VERSION.to_string(), Font::Body)
                .color(kit::SECONDARY),
        );
    });
}

fn vault_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let path = app
        .owner_ui
        .session
        .location()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let mut lock = false;
    kit::section(
        ui,
        Some("Vault"),
        Some(
            "A lock ends every run that waits for you. The broker refuses all agent requests while the vault is locked.",
        ),
        |s| {
            s.labeled(
                "File",
                kit::text(path, Font::MonoSmall).color(kit::SECONDARY),
            );
            lock = s
                .clickable_row(|ui| {
                    ui.label(kit::text("Lock now", Font::Body).color(kit::ACCENT_TEXT));
                })
                .clicked();
        },
    );
    if lock {
        let ctx = ui.ctx().clone();
        app.lock_vault(Some(&ctx));
    }
}

fn security_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let touch_id_for_checks = app.owner.touch_id_note().map_or_else(
        || "Touch ID for owner checks: available.".to_owned(),
        |note| format!("Touch ID for owner checks: {note}"),
    );
    let mut change = false;
    kit::section(ui, Some("Security"), Some(&touch_id_for_checks), |s| {
        let gray = egui::Color32::from_rgb(99, 99, 104);
        change = s
            .nav(
                Some((Icon::Lock, gray)),
                "Change passphrase",
                Some("Old backups still need the old passphrase."),
                None,
            )
            .clicked();
        s.row(|ui| unlock_method(app, ui));
    });
    if change {
        app.ui.sheet = Some(Sheet::ChangePassphrase);
    }
}

/// The unlock method: passphrase or Touch ID (goal items A2, A3). The passphrase stays
/// the root key.
fn unlock_method(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let unlock = &app.owner.unlock;
    let busy = unlock.reading.is_some() || unlock.changing.is_some();
    let setting = unlock.setting.clone();
    let current = match &setting {
        Some(setting) if setting.method == UnlockMethod::TouchId => {
            "Touch ID. The passphrase still works."
        }
        _ => "Passphrase",
    };
    egui::Sides::new().show(
        ui,
        |ui| ui.label(kit::text("Unlock method", Font::Body).color(kit::LABEL)),
        |ui| ui.label(kit::text(current, Font::Body).color(kit::SECONDARY)),
    );
    if busy {
        kit::note(
            ui,
            "Apassy is reading or changing the Touch ID unlock setting.",
        );
        return;
    }
    let Some(setting) = setting else {
        return;
    };
    if let Some(note) = &setting.note {
        kit::tone_note(ui, note, Tone::Warning);
    }
    let ctx = ui.ctx().clone();
    match setting.method {
        UnlockMethod::TouchId => {
            if kit::small_button(ui, "Turn off Touch ID unlock", Style::Bordered).clicked() {
                app.start_touch_id_off(
                    Some(&ctx),
                    "Touch ID unlock is off. Apassy deleted the unlock key from the keychain.",
                );
            }
        }
        UnlockMethod::Passphrase if setting.can_set_up => {
            kit::note(
                ui,
                "Touch ID setup, backup restore, and recovery need the passphrase. A fingerprint change turns Touch ID unlock off.",
            );
            ui.horizontal(|ui| {
                ui.scope(|ui| {
                    ui.set_max_width(220.0);
                    secure_input(
                        ui,
                        TOUCH_ID_SETUP_FIELD,
                        &mut app.owner.unlock.setup_passphrase,
                        PASSPHRASE_CAPACITY,
                        "Passphrase",
                    );
                });
                if kit::small_button(ui, "Turn on Touch ID unlock", Style::Bordered).clicked() {
                    app.start_touch_id_setup(&ctx);
                }
            });
        }
        UnlockMethod::Passphrase => {}
    }
}

fn backup_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut open = None;
    kit::section(
        ui,
        Some("Backup"),
        Some(
            "A backup is an encrypted copy of the vault file. Keep it in a safe place, for example on an external disk.",
        ),
        |s| {
            let green = egui::Color32::from_rgb(52, 170, 90);
            if s.nav(
                Some((Icon::Folder, green)),
                "Back up now",
                Some("The vault locks after the backup."),
                None,
            )
            .clicked()
            {
                open = Some(Sheet::Backup);
            }
            let orange = egui::Color32::from_rgb(255, 149, 0);
            if s.nav(
                Some((Icon::Clock, orange)),
                "Restore from a backup",
                Some("Agents are revoked, and each credential waits for your review."),
                None,
            )
            .clicked()
            {
                open = Some(Sheet::Restore);
            }
        },
    );
    if open.is_some() {
        app.ui.sheet = open;
    }
}

/// Token lifetime for every agent (goal item P1).
fn agents_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let current = app.owner_ui.session.token_lifetime_days().ok();
    let footer = format!(
        "{}A token works for this number of days after Apassy issues it. Then the agent gets token_expired, and you rotate the token. The default is {DEFAULT_TOKEN_LIFETIME_DAYS} days. A change applies to every active token from its issue time.",
        current.map_or_else(String::new, |days| format!(
            "Current lifetime: {days} days. "
        ))
    );
    let mut save = false;
    kit::section(ui, Some("Agents"), Some(&footer), |s| {
        s.field("Token lifetime", |ui| {
            let placeholder = current.map_or_else(String::new, |days| days.to_string());
            let field = kit::number_input(
                ui,
                &mut app.owner_ui.token_lifetime_input,
                "token-lifetime",
                &placeholder,
            );
            ui.label(kit::text("days (1 to 365)", Font::Body).color(kit::SECONDARY));
            save = kit::small_button(ui, "Save", Style::Bordered).clicked();
            field
        });
    });
    if save {
        let days = app.owner_ui.token_lifetime_input.clone();
        match crate::desktop::owner_store::parse_lifetime_days(&days) {
            Ok(_) => {
                let ctx = ui.ctx().clone();
                app.ask_owner(OwnerRequest::SetTokenLifetime { days }, Some(&ctx));
            }
            Err(err) => app.set_err(err.message),
        }
    }
}

/// The real notification channel (goal items N1 to N4).
fn notifications_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::section(
        ui,
        Some("Notifications"),
        Some(
            "A waiting approval or a blocked request causes a macOS notification. The notification shows only the agent name and the event type. You decide in this app.",
        ),
        |s| {
            let Some(center) = &app.owner.notifications else {
                s.row(|ui| {
                    kit::tone_note(
                        ui,
                        "Notifications: not running. The notification center starts with the Apassy window and the broker. Events stay in the inbox.",
                        Tone::Warning,
                    );
                });
                return;
            };
            let view = center.view();
            let tone = if view.channel.can_deliver() {
                Tone::Good
            } else {
                Tone::Warning
            };
            s.labeled(
                "Status",
                kit::text(view.channel.summary(), Font::Callout).color(tone.text()),
            );
            let failed = view
                .deliveries
                .values()
                .filter(|delivery| matches!(delivery, Delivery::Failed(_)))
                .count();
            if failed > 0 {
                s.row(|ui| {
                    kit::tone_note(
                        ui,
                        format!("{failed} notification(s) failed. The events stay in the inbox."),
                        Tone::Critical,
                    );
                });
            }
            s.row(|ui| {
                ui.horizontal_wrapped(|ui| {
                    if kit::small_button(ui, "Check again", Style::Bordered).clicked() {
                        center.refresh_status();
                    }
                    // The notifier (Contents/Helpers/ApassyNotify.app, display name
                    // "Apassy") asks macOS. The button hides while the prompt shows.
                    if view.channel.needs_permission()
                        && kit::small_button(ui, "Allow notifications", Style::Prominent)
                            .on_hover_text(
                                "macOS shows a prompt for \"Apassy\" at the top right of the screen. Select \"Allow\".",
                            )
                            .clicked()
                    {
                        center.request_permission();
                    }
                    // After a denial, macOS shows no new prompt. Only System Settings helps.
                    if view.channel.needs_settings()
                        && kit::small_button(ui, "Open System Settings", Style::Prominent)
                            .on_hover_text(
                                "System Settings > Notifications > Apassy. Turn on \"Allow notifications\" and select \"Banners\".",
                            )
                            .clicked()
                    {
                        match notify::open_notification_settings() {
                            Ok(()) => center.refresh_status(),
                            Err(err) => center.report_problem(format!(
                                "Apassy cannot open System Settings ({err}). Open System Settings > Notifications > Apassy."
                            )),
                        }
                    }
                });
            });
        },
    );
}

/// The keyboard shortcuts of the window.
fn shortcuts_section(ui: &mut egui::Ui) {
    kit::section(
        ui,
        Some("Keyboard shortcuts"),
        Some(
            "⌘H is the macOS shortcut for \"Hide Apassy\". The app menu takes it before the window, so showing values uses ⌘⇧H.",
        ),
        |s| {
            for (keys, action) in [
                ("⌘N", "New credential"),
                ("⌘F", "Search credentials"),
                ("⌘S", "Save the open sheet"),
                (
                    "⌘⇧H",
                    "Show or hide the secret values of the open credential",
                ),
                ("Tab, ⇧Tab", "Move to the next or the previous control"),
                (
                    "Space",
                    "Press the control, or select the next option of a picker",
                ),
                ("← →", "Select the previous or the next option of a picker"),
                ("Return", "Confirm a passphrase field"),
                ("Esc", "Close the sheet"),
            ] {
                s.labeled(action, kit::text(keys, Font::Mono).color(kit::SECONDARY));
            }
        },
    );
}

fn broker_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::section(
        ui,
        Some("Broker and bouncer"),
        Some(
            "A locked vault refuses all agent requests. Destinations use https://, or http:// on this computer only. The broker does not follow redirects.",
        ),
        |s| match &app.broker {
            BrokerState::Running(handle) => {
                s.labeled(
                    "Broker",
                    kit::text("Accepts agent requests", Font::Callout).color(Tone::Good.text()),
                );
                let bouncer = handle.bouncer_url().map_or_else(
                    || {
                        kit::text("Not set. Every run waits for you.", Font::Callout)
                            .color(Tone::Warning.text())
                    },
                    |url| kit::text(url, Font::Callout).color(kit::SECONDARY),
                );
                s.labeled("Bouncer", bouncer);
                s.labeled(
                    "Socket",
                    kit::text(handle.socket_path().display().to_string(), Font::MonoSmall)
                        .color(kit::SECONDARY),
                );
                if handle.bouncer_url().is_some() {
                    s.row(|ui| {
                        kit::note(
                            ui,
                            "A Jev-compatible bouncer, for example Laya. If it does not answer, every run waits for you.",
                        );
                    });
                }
            }
            BrokerState::Failed(message) => {
                s.labeled(
                    "Broker",
                    kit::text(message, Font::Callout).color(Tone::Critical.text()),
                );
            }
            BrokerState::NotStarted => {
                s.labeled(
                    "Broker",
                    kit::text("Starts with the desktop window", Font::Callout)
                        .color(kit::SECONDARY),
                );
            }
        },
    );
}

// ---- Sheets. ----

/// Change the master passphrase (goal item V5). The new passphrase is typed two times.
pub(super) fn passphrase_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut change = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "change-passphrase", 500.0, |ui| {
        passphrase_form(app, ui);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                change = kit::button(ui, "Change passphrase", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    change |= super::save_pressed(app, ctx);
    if change {
        change_passphrase(app, ctx);
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

pub(super) fn passphrase_form(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::sheet_title(
        ui,
        "Change passphrase",
        Some(
            "Apassy encrypts the vault file again with the new passphrase and keeps the SQLCipher key settings. Old backups still need the old passphrase. Agent runs that wait for you end.",
        ),
    );
    kit::section(
        ui,
        None,
        Some("The new passphrase needs 12 or more characters. Type it two times."),
        |s| {
            let fields = [
                (
                    CHANGE_FIELDS[0],
                    "Current passphrase",
                    &mut app.owner_ui.passphrase_current,
                ),
                (
                    CHANGE_FIELDS[1],
                    "New passphrase",
                    &mut app.owner_ui.passphrase_new,
                ),
                (
                    CHANGE_FIELDS[2],
                    "Repeat the new one",
                    &mut app.owner_ui.passphrase_repeat,
                ),
            ];
            for (salt, label, value) in fields {
                s.field(label, |ui| {
                    secure_input(ui, salt, value, PASSPHRASE_CAPACITY, "")
                });
            }
        },
    );
}

fn change_passphrase(app: &mut DesktopApp, ctx: &egui::Context) {
    let current = Ephemeral::take(&mut app.owner_ui.passphrase_current);
    let new = Ephemeral::take(&mut app.owner_ui.passphrase_new);
    let repeat = Ephemeral::take(&mut app.owner_ui.passphrase_repeat);
    for field in CHANGE_FIELDS {
        forget_secret_field(ctx, field);
    }
    let result =
        app.owner_ui
            .session
            .change_passphrase(current.expose(), new.expose(), repeat.expose());
    drop((current, new, repeat));
    if app
        .apply(
            result,
            "The passphrase is changed. Unlock with the new passphrase from now on. Old backups still need the old passphrase.",
        )
        .is_some()
    {
        // The Touch ID unlock key holds the old passphrase (goal item A3).
        app.after_passphrase_change(ctx);
        app.ui.sheet = None;
    }
    app.end_waiting_runs();
}

pub(super) fn backup_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut backup = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "backup", 500.0, |ui| {
        kit::sheet_title(
            ui,
            "Back up the vault",
            Some(
                "Apassy writes an encrypted copy. A restore needs the passphrase that the vault has now. The vault locks after the backup.",
            ),
        );
        kit::section(
            ui,
            None,
            Some("Keep the backup in a safe place, for example on an external disk."),
            |s| {
                let field = s.field("Backup file", |ui| {
                    kit::text_input(
                        ui,
                        &mut app.owner_ui.backup_path,
                        "vault-backup-path",
                        "/Volumes/Backup/apassy.backup",
                    )
                });
                backup = field.lost_focus()
                    && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
            },
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                backup |= kit::button(ui, "Back up", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    backup |= super::save_pressed(app, ctx);
    if backup {
        let path = PathBuf::from(app.owner_ui.backup_path.trim());
        let result = app.owner_ui.session.backup(&path);
        if app
            .apply(result, "The backup is written. The vault is locked.")
            .is_some()
        {
            app.pending_delete = false;
            app.ui.sheet = None;
        }
        // Backup locks the vault, also when it fails.
        app.end_waiting_runs();
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

pub(super) fn restore_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut restore = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "restore", 520.0, |ui| {
        kit::sheet_title(
            ui,
            "Restore from a backup",
            Some(
                "Apassy copies the backup to a new vault file and opens it locked. Agents are revoked, and each credential waits for your review before agents can use it.",
            ),
        );
        restore = start::restore_form(app, ui);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                restore |= kit::button(ui, "Restore", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    restore |= super::save_pressed(app, ctx);
    if restore {
        start::restore_now(app, ctx);
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}
