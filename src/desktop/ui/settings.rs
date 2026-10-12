//! Settings in four tabs (ADR 0026 §3), as the toolbar of a macOS settings window:
//! General (the vaults, import, and the browser extension), Devices (each device that
//! gets the questions, ADR 0025 §3e: this Mac, the other Macs through sync, the iPhones,
//! and the relay), Security (unlock, the passphrase, and backup), and Advanced (the
//! bouncer, calibration and learning, the command line, updates, and the keyboard
//! shortcuts). Each change that is rare or risky opens a sheet.
//!
//! Settings of single agents are gone (ADR 0025 §3f): the agent screen shows, it does
//! not configure.

use std::path::PathBuf;

use eframe::egui::{self, Pos2, Rect, Sense, Stroke, Vec2, WidgetInfo, WidgetType};

use super::kit::{self, Font, Icon, Style, Tone};
use super::{
    CHANGE_FIELDS, PASSPHRASE_CAPACITY, Sheet, TOUCH_ID_SETUP_FIELD, close_sheet,
    forget_secret_field, secure_input, start,
};
use crate::broker::model_server::{
    AgentConflict, BouncerSettings, FETCH_LABEL, FETCH_SCRIPT, IDLE_CHOICES, InstallState, Problem,
    ServerState, StartMode, Status, UV_MISSING, shell_word,
};
use crate::desktop::notify::{self, Delivery};
use crate::desktop::owner_store::Ephemeral;
use crate::desktop::unlock::UnlockMethod;
use crate::desktop::{BrokerState, DesktopApp};
use crate::relay::membership::{QuestionsAvailability, questions_availability};

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;

/// The tab of the Settings window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum SettingsTab {
    /// The vaults, import, and the browser extension.
    #[default]
    General,
    /// This Mac, the other Macs, the iPhones, and the relay.
    Devices,
    /// Unlock, the passphrase, and backups.
    Security,
    /// The bouncer, calibration and learning, the command line, updates, and the
    /// keyboard shortcuts.
    Advanced,
}

/// The old Notifications tab, for the Activity view that still opens it ("Open
/// Settings" when macOS notifications are off). Its sections are in Devices now. Remove
/// with the Activity view (ADR 0026 §2).
#[allow(non_upper_case_globals)]
impl SettingsTab {
    pub(crate) const Notifications: Self = Self::Devices;
}

impl SettingsTab {
    /// The tabs in the order of the toolbar.
    pub(crate) const ALL: [Self; 4] =
        [Self::General, Self::Devices, Self::Security, Self::Advanced];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Devices => "Devices",
            Self::Security => "Security",
            Self::Advanced => "Advanced",
        }
    }
}

/// Show Settings with the given tab.
pub(crate) fn open(app: &mut DesktopApp, tab: SettingsTab) {
    app.open_settings_window();
    app.ui.settings_tab = tab;
}

/// One tab of the toolbar: an icon above its label.
const TAB_SIZE: Vec2 = Vec2::new(80.0, 50.0);
const TAB_GAP: f32 = 4.0;
/// The width of the four tabs, for the minimum size of the window.
pub(super) const TAB_BAR_WIDTH: f32 = 4.0 * TAB_SIZE.x + 3.0 * TAB_GAP;

/// The toolbar of the Settings window: the four tabs, centered. The selected tab has a
/// gray fill and the accent color.
pub(super) fn tab_bar(app: &mut DesktopApp, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = TAB_GAP;
        ui.add_space(((ui.available_width() - TAB_BAR_WIDTH) / 2.0).max(0.0));
        for tab in SettingsTab::ALL {
            if tab_button(ui, tab, app.ui.settings_tab == tab).clicked() {
                app.ui.settings_tab = tab;
            }
        }
    });
}

fn tab_button(ui: &mut egui::Ui, tab: SettingsTab, selected: bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(TAB_SIZE, Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| {
        WidgetInfo::selected(WidgetType::SelectableLabel, enabled, selected, tab.label())
    });
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, 7, kit::FILL_HOVER);
    } else if response.hovered() {
        painter.rect_filled(rect, 7, kit::FILL);
    }
    let color = if selected {
        kit::ACCENT
    } else {
        kit::SECONDARY
    };
    let icon = Rect::from_center_size(
        Pos2::new(rect.center().x, rect.top() + 18.0),
        Vec2::splat(22.0),
    );
    paint_tab_icon(painter, icon, tab, color);
    let label = kit::galley(ui, kit::text(tab.label(), Font::Footnote));
    painter.galley(
        Pos2::new(rect.center().x - label.size().x / 2.0, icon.bottom() + 3.0),
        label,
        color,
    );
    if response.has_focus() {
        kit::focus_ring(painter, rect, 7);
    }
    response
}

/// The icon of a tab: a gear, a laptop, a lock, and sliders, as in the mockup.
fn paint_tab_icon(painter: &egui::Painter, rect: Rect, tab: SettingsTab, color: egui::Color32) {
    let size = rect.width();
    let p = |x: f32, y: f32| rect.min + Vec2::new(x * size, y * size);
    let stroke = Stroke::new((size / 11.0).clamp(1.0, 2.6), color);
    match tab {
        SettingsTab::General => kit::paint_icon(painter, rect, Icon::Gearshape, color),
        SettingsTab::Security => kit::paint_icon(painter, rect, Icon::Lock, color),
        SettingsTab::Devices => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.18, 0.2), p(0.82, 0.66)),
                size * 0.08,
                stroke,
                egui::StrokeKind::Middle,
            );
            painter.line_segment([p(0.06, 0.8), p(0.94, 0.8)], stroke);
        }
        SettingsTab::Advanced => {
            let radius = 0.1;
            for (y, knob) in [(0.24, 0.32), (0.5, 0.66), (0.76, 0.44)] {
                painter.line_segment([p(0.08, y), p(knob - radius, y)], stroke);
                painter.line_segment([p(knob + radius, y), p(0.92, y)], stroke);
                painter.circle_stroke(p(knob, y), radius * size, stroke);
            }
        }
    }
}

/// The sections of the selected tab. The tab bar is above them, in the window.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let tab = app.ui.settings_tab;
    // Each tab has its own IDs, so the focus of one tab never moves to another.
    ui.push_id(tab, |ui| match tab {
        SettingsTab::General => {
            super::vaults::settings_section(app, ui);
            super::import::section(app, ui);
            super::browser_settings::section(app, ui);
        }
        SettingsTab::Devices => {
            devices_section(app, ui);
            super::sync::settings_section(app, ui);
            notifications_section(app, ui);
            super::companion::draw(app, ui);
        }
        SettingsTab::Security => {
            security_section(app, ui);
            backup_section(app, ui);
        }
        SettingsTab::Advanced => {
            broker_section(app, ui);
            crate::desktop::learning_ui::settings_panel(app, ui);
            command_line_section(app, ui);
            super::updates::section(app, ui);
            shortcuts_section(ui);
            kit::section(ui, Some("About"), None, |s| {
                s.labeled(
                    "Contract",
                    kit::text(crate::contracts::CONTRACT_VERSION.to_string(), Font::Body)
                        .color(kit::SECONDARY),
                );
            });
        }
    });
}

/// The words of the relay row (ADR 0025 §3e, contract relay-questions-v1). Off by
/// default: only a relay membership with the purpose `questions` turns it on.
pub(super) const RELAY_QUESTIONS: &str = "Send questions through the relay";
pub(super) const RELAY_QUESTIONS_ON: &str = "On. Each question also goes, end-to-end encrypted, to your other devices of this vault. The relay sees no command and no credential.";
pub(super) const RELAY_QUESTIONS_OFF: &str =
    "Off. Turn it on to answer on your other Macs and iPhones away from this network.";
pub(super) const RELAY_QUESTIONS_NEW_TEAM: &str = "Off. This vault does not sync through the relay: turning it on makes a team on the relay for its questions only, with a team code from the operator.";
pub(super) const RELAY_QUESTIONS_LOCKED: &str = "Unlock the vault to change it.";
pub(super) const RELAY_QUESTIONS_JOIN: &str = "Off. This vault already has a questions team on the relay: turning it on joins that team with a link from a Mac that has it on.";
pub(super) const RELAY_QUESTIONS_REMOVED: &str = "Off. This Mac was removed from the questions of this vault. Turning it on again needs a new key: a link from a Mac that has it on, and your confirmation there.";
/// The button that removes a device from the questions, after its confirmation.
pub(super) const REMOVE_DEVICE: &str = "Remove…";
/// The button that links an iPhone or another Mac to the questions team.
pub(super) const ADD_IPHONE: &str = "Add an iPhone or a Mac…";

/// What the relay row shows: the availability of the open, unlocked vault, or `None`.
fn relay_questions_state(app: &DesktopApp) -> Option<QuestionsAvailability> {
    let vault = app.owner_ui.session.shared_vault();
    let guard = vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .as_ref()
        .filter(|vault| !vault.is_locked())
        .and_then(|vault| questions_availability(vault).ok())
}

/// Turn "Send questions through the relay" on or off for the open vault on this Mac. On
/// is a new channel that can approve runs: the owner check first, for the relay sync team
/// of the vault, or the sheet of a notifications-only team. Off needs no check and takes
/// the purpose `questions` away; relay sync never changes.
pub(super) fn set_relay_questions(app: &mut DesktopApp, on: bool, ctx: Option<&egui::Context>) {
    if on {
        app.questions_turn_on(ctx);
    } else {
        app.questions_turn_off();
    }
}

/// Settings > Devices: each device that gets the questions of the bouncer (ADR 0025
/// §3e), the relay, and "Add a Device…". The sync of the vaults, macOS notifications,
/// and the iPhone companion follow, each in its own section.
fn devices_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let others = super::sync::other_macs(app);
    let iphones = app
        .owner_ui
        .session
        .companion_devices()
        .map_or(0, |devices| devices.len());
    let this_mac = match &app.owner.notifications {
        Some(center) => center.view().channel.summary(),
        None => "Notifications are not running".to_owned(),
    };
    let mut list = None;
    let relay_state = relay_questions_state(app);
    let relay_devices = if matches!(relay_state, Some(QuestionsAvailability::On { .. })) {
        app.questions_devices()
    } else {
        Vec::new()
    };
    // The problem of the questions waiter: a relay without the questions, or this Mac
    // removed from them.
    let relay_problem = app
        .owner
        .questions
        .as_ref()
        .map(|questions| questions.view())
        .filter(|view| view.unsupported)
        .and_then(|view| view.problem);
    let mut switch_relay = None;
    let mut add_relay_iphone = false;
    let mut remove_device = None;
    kit::section(
        ui,
        Some("Questions go to every device"),
        Some(
            "A run that waits for you shows on this Mac and on each paired iPhone. The first answer counts. Other Macs get the vault through sync.",
        ),
        |s| {
            s.labeled(
                "This Mac",
                kit::text(this_mac, Font::Body).color(kit::SECONDARY),
            );
            s.row(|ui| {
                egui::Sides::new().shrink_left().truncate().show(
                    ui,
                    |ui| ui.label(kit::text("Other Macs", Font::Body).color(kit::LABEL)),
                    |ui| {
                        if let Some(id) = &others.relay
                            && kit::small_button(ui, "Devices…", Style::Bordered).clicked()
                        {
                            list = Some(id.clone());
                        }
                        ui.label(kit::text(&others.words, Font::Body).color(kit::SECONDARY));
                    },
                );
            });
            let phones = match iphones {
                0 => "None paired".to_owned(),
                1 => "1 paired".to_owned(),
                count => format!("{count} paired"),
            };
            s.labeled(
                "iPhones",
                kit::text(phones, Font::Body).color(kit::SECONDARY),
            );
            // Off by default; on only with a relay membership for the questions.
            let (mut on, enabled, note) = match &relay_state {
                Some(QuestionsAvailability::On { .. }) => (true, true, RELAY_QUESTIONS_ON),
                Some(QuestionsAvailability::CanTurnOn { .. }) => (false, true, RELAY_QUESTIONS_OFF),
                Some(QuestionsAvailability::NeedsTeam) => (false, true, RELAY_QUESTIONS_NEW_TEAM),
                Some(QuestionsAvailability::JoinTeam { .. }) => (false, true, RELAY_QUESTIONS_JOIN),
                Some(QuestionsAvailability::Removed { sync: false, .. }) => {
                    (false, true, RELAY_QUESTIONS_REMOVED)
                }
                Some(QuestionsAvailability::Removed { sync: true, .. }) => {
                    (false, false, super::sync::questions::REMOVED_SYNC)
                }
                None => (false, false, RELAY_QUESTIONS_LOCKED),
            };
            let was = on;
            s.row(|ui| {
                egui::Sides::new()
                    .shrink_left()
                    .wrap_mode(egui::TextWrapMode::Wrap)
                    .show(
                        ui,
                        |ui| {
                            ui.vertical(|ui| {
                                ui.label(kit::text(RELAY_QUESTIONS, Font::Body).color(kit::LABEL));
                                kit::note(ui, note);
                            });
                        },
                        |ui| {
                            ui.add_enabled_ui(enabled, |ui| {
                                kit::toggle(ui, &mut on, RELAY_QUESTIONS)
                            });
                        },
                    );
            });
            if on != was {
                switch_relay = Some(on);
            }
            // A relay that predates the questions, and other problems of the relay.
            if let Some(problem) = &relay_problem {
                s.row(|ui| kit::tone_note(ui, problem, Tone::Critical));
            }
            // The devices that get the questions through the relay, "Remove…" for each
            // other device, and a new device.
            for device in &relay_devices {
                s.row(|ui| {
                    egui::Sides::new().shrink_left().truncate().show(
                        ui,
                        |ui| {
                            ui.vertical(|ui| {
                                ui.label(kit::text(&device.name, Font::Body).color(kit::LABEL));
                                kit::note(ui, &device.words);
                            });
                        },
                        |ui| {
                            if device.removable
                                && kit::small_button(ui, REMOVE_DEVICE, Style::Destructive)
                                    .clicked()
                            {
                                remove_device = Some(device.uuid.clone());
                            }
                        },
                    );
                });
            }
            if was {
                s.row(|ui| {
                    egui::Sides::new().shrink_left().truncate().show(
                        ui,
                        |ui| {
                            kit::note(
                                ui,
                                "An iPhone answers the questions with Face ID, also away from this network.",
                            )
                        },
                        |ui| {
                            add_relay_iphone =
                                kit::small_button(ui, ADD_IPHONE, Style::Bordered).clicked();
                        },
                    );
                });
            }
        },
    );
    let mut add_mac = false;
    let mut add_iphone = false;
    ui.horizontal(|ui| {
        let add = kit::button(ui, "Add a Device…", Style::Bordered);
        egui::Popup::menu(&add).show(|ui| {
            ui.set_min_width(200.0);
            add_mac = ui
                .add_enabled(
                    others.relay.is_some(),
                    egui::Button::selectable(false, "Another Mac…"),
                )
                .on_disabled_hover_text(
                    "First sync this vault through the Apassy relay in Sync below.",
                )
                .clicked();
            add_iphone = ui.selectable_label(false, "iPhone…").clicked();
        });
    });
    ui.add_space(20.0);
    let ctx = ui.ctx().clone();
    if let Some(on) = switch_relay {
        set_relay_questions(app, on, Some(&ctx));
    }
    if let Some(uuid) = remove_device {
        app.questions_ask_remove(&uuid, Some(&ctx));
    } else if add_relay_iphone {
        app.questions_add_iphone(Some(&ctx));
    } else if let Some(id) = list {
        app.sync_open_sheet(super::sync::SyncSheet::Devices { id }, Some(&ctx));
    } else if add_mac && let Some(id) = others.relay {
        app.sync_open_sheet(super::sync::SyncSheet::AddMac { id }, Some(&ctx));
    } else if add_iphone {
        add_an_iphone(app, &ctx);
    }
}

/// "Add a Device…" > "iPhone…": the iPhone listener goes on, and the pairing code of
/// "Pair an iPhone" shows below.
fn add_an_iphone(app: &mut DesktopApp, ctx: &egui::Context) {
    let on = app
        .owner_ui
        .session
        .companion_status()
        .is_ok_and(|(setting, _)| setting.enabled);
    if !on {
        app.set_companion_on(true);
    }
    if app.companion_controller().is_some() {
        app.open_pairing(ctx);
    }
}

fn security_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let touch_id_for_checks = app.owner.touch_id_note().map_or_else(
        || "Touch ID for owner checks: available.".to_owned(),
        |note| format!("Touch ID for owner checks: {note}"),
    );
    let mut change = false;
    kit::section(ui, Some("Unlock"), Some(&touch_id_for_checks), |s| {
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
                let field = ui
                    .scope(|ui| {
                        ui.set_max_width(220.0);
                        secure_input(
                            ui,
                            TOUCH_ID_SETUP_FIELD,
                            &mut app.owner.unlock.setup_passphrase,
                            PASSPHRASE_CAPACITY,
                            "Passphrase",
                        )
                    })
                    .inner;
                ctx.accesskit_node_builder(field.id, |node| {
                    node.set_label("Passphrase for Touch ID unlock");
                });
                let submit =
                    field.lost_focus() && ctx.input(|input| input.key_pressed(egui::Key::Enter));
                if kit::small_button(ui, "Turn on Touch ID unlock", Style::Bordered).clicked()
                    || submit
                {
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
                        "Notifications: not running. The notification center starts with the Apassy window and the broker. Questions still wait in Decisions.",
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
                        format!("{failed} notification(s) failed. Questions still wait in Decisions, and the other events are in the activity log (apassy activity)."),
                        Tone::Critical,
                    );
                });
            }
            // The actions sit at the trailing edge, as "Check now" in Settings > Advanced.
            // The layout runs right to left: the main action comes first, so it is the
            // rightmost button.
            s.row(|ui| {
                // One control high: in the page scroll area the free height is unbounded.
                let size = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
                let layout = egui::Layout::right_to_left(egui::Align::Center);
                ui.allocate_ui_with_layout(size, layout, |ui| {
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
                    if kit::small_button(ui, "Check again", Style::Bordered).clicked() {
                        center.refresh_status();
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
            "⌘H is the macOS shortcut for \"Hide Apassy\". The app menu takes it before the window, so showing values uses ⌘⇧H. The page scrolls to the focused control, and a closed sheet gives the focus back to the control that opened it.",
        ),
        |s| {
            for (keys, action) in [
                ("⌘1 ⌘2 ⌘3", "All credentials, Decisions, Agents"),
                ("⌘,", "Settings"),
                ("⌘W, Esc", "Close Settings"),
                ("⌘[", "Back to the list"),
                ("⌘N", "New credential"),
                ("⌘F", "Search credentials"),
                ("⌘L", "Lock the vault"),
                ("⌃⌘S", "Hide or show the sidebar"),
                ("Return, ⌘S", "The default action of the open sheet"),
                (
                    "⌘⇧H",
                    "Show or hide the secret values of the open credential",
                ),
                ("Tab, ⇧Tab", "Move to the next or the previous control"),
                ("← → ↑ ↓", "Move to the nearest control"),
                (
                    "Space",
                    "Press the control, or select the next option of a picker",
                ),
                ("← → on a picker", "Select the previous or the next option"),
                (
                    "Page Up, Page Down, Home, End",
                    "Scroll the page or the sheet",
                ),
                ("Esc", "Close the sheet, a menu, or an error message"),
            ] {
                s.labeled(action, kit::text(keys, Font::Mono).color(kit::SECONDARY));
            }
        },
    );
}

/// "Asked you": how often a run waited for the owner in the last 7 days.
fn asked_words(asked: u32) -> String {
    match asked {
        0 => "Not this week".to_owned(),
        1 => "1 time this week".to_owned(),
        count => format!("{count} times this week"),
    }
}

/// The broker, the bouncer, and its model server (ADR 0024), with how often the bouncer
/// asked you this week.
fn broker_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let server = app.model_server.clone();
    let status = server.as_ref().map(|server| server.status());
    let asked = crate::desktop::learning_ui::asked_this_week(app);
    let mut action = None;
    kit::section(
        ui,
        Some("Broker and bouncer"),
        Some(
            "A locked vault refuses all agent requests. Destinations use https://, or http:// on this computer only. The broker does not follow redirects.",
        ),
        |s| {
            match &app.broker {
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
            }
            if let Some(asked) = asked {
                s.labeled(
                    "Asked you",
                    kit::text(asked_words(asked), Font::Callout).color(kit::SECONDARY),
                );
            }
            if let Some(status) = &status {
                action = model_server_rows(s, status);
            }
        },
    );
    let Some(server) = server else {
        return;
    };
    // The supervisor changes its state on its own thread. The page reads it each frame.
    let starting = status.as_ref().is_some_and(|status| {
        matches!(status.state, ServerState::Starting { .. })
            || matches!(status.install, InstallState::Installing { .. })
    });
    ui.ctx().request_repaint_after(if starting {
        std::time::Duration::from_millis(500)
    } else {
        std::time::Duration::from_secs(5)
    });
    match action {
        Some(ModelAction::Settings(settings)) => {
            let off = settings.start == StartMode::Off;
            match server.set_settings(settings) {
                Ok(()) if off => app.set_note("The bouncer is off. Every run waits for you."),
                Ok(()) => {}
                Err(err) => app.set_err(format!("Apassy cannot save the bouncer setting: {err}")),
            }
        }
        Some(ModelAction::Start) => server.start_now(),
        Some(ModelAction::Stop) => server.stop(),
        Some(ModelAction::Install) => {
            if let Err(err) = server.install() {
                app.set_err(err);
            }
        }
        Some(ModelAction::CancelInstall) => {
            server.cancel_install();
            app.set_note("The install stopped. \"Install the model\" starts it again.");
        }
        Some(ModelAction::OpenLog(log)) => {
            if !log.is_file() {
                app.set_note(
                    "There is no log yet. Apassy writes it when it starts the model server.",
                );
            } else if let Err(err) = open_file(&log) {
                app.set_err(format!("Apassy cannot open {} ({err}).", log.display()));
            }
        }
        None => {}
    }
}

/// What the owner chose in the rows of the model server.
enum ModelAction {
    Settings(BouncerSettings),
    Start,
    Stop,
    OpenLog(PathBuf),
    Install,
    CancelInstall,
}

/// The state in words, its tone, and a note.
fn model_server_words(status: &Status) -> (String, Tone, Option<String>) {
    let url = &status.url;
    let zero_shot = status.settings.start.managed()
        && status
            .preflight
            .as_ref()
            .is_ok_and(|ready| ready.checkpoint.is_none());
    let model_note = |model: &Option<String>| {
        let mut note = model
            .as_ref()
            .map_or_else(String::new, |model| format!("Model: {model}."));
        if zero_shot {
            if !note.is_empty() {
                note.push(' ');
            }
            note.push_str("Zero-shot model: there is no apassy-base-v1 checkpoint.");
        }
        (!note.is_empty()).then_some(note)
    };
    match &status.state {
        ServerState::Off => (
            "Off".to_owned(),
            Tone::Warning,
            Some("The broker asks no model. Every run waits for you.".to_owned()),
        ),
        ServerState::External { up: None, .. } => (
            "Checking".to_owned(),
            Tone::Neutral,
            Some(format!(
                "Apassy does not start or stop the model. It asks {url}."
            )),
        ),
        ServerState::External {
            up: Some(true),
            model,
        } => (
            "Answers".to_owned(),
            Tone::Good,
            Some(model.as_ref().map_or_else(
                || format!("The model at {url} answers."),
                |model| format!("Model: {model} at {url}."),
            )),
        ),
        ServerState::External {
            up: Some(false), ..
        } => (
            "No answer".to_owned(),
            Tone::Warning,
            Some(format!(
                "Nothing answers at {url}. Until it answers, every run waits for you."
            )),
        ),
        // A start would fail: say so here, not "the next run starts it". The note
        // under the rows names what is missing.
        ServerState::Stopped if status.settings.start.managed() && status.preflight.is_err() => (
            "Cannot start".to_owned(),
            Tone::Warning,
            Some(
                "Something that the model needs is missing. Until then, every run waits for you."
                    .to_owned(),
            ),
        ),
        ServerState::Stopped => (
            "Stopped".to_owned(),
            Tone::Neutral,
            Some(if status.settings.start == StartMode::WhenNeeded {
                "The next run that needs the model starts it.".to_owned()
            } else {
                "Until it runs, every run waits for you.".to_owned()
            }),
        ),
        // The base weights are not in the Hugging Face cache, so this start downloads
        // them (about 800 MB).
        ServerState::Starting { .. } if !status.weights_cached => (
            "Starting (downloading the model weights, first start only)".to_owned(),
            Tone::Neutral,
            Some(
                "The model server downloads the Laya base weights from Hugging Face. This can take several minutes. Until it answers, every run waits for you."
                    .to_owned(),
            ),
        ),
        ServerState::Starting { since } => (
            format!("Starting ({} s)", since.elapsed().as_secs()),
            Tone::Neutral,
            Some("The first start loads the model. This can take a minute.".to_owned()),
        ),
        ServerState::Running { model, outside } => (
            if *outside {
                "Running (started outside Apassy)".to_owned()
            } else {
                "Running".to_owned()
            },
            Tone::Good,
            model_note(model),
        ),
        ServerState::Failed { problem, .. } => (
            "Not running".to_owned(),
            Tone::Warning,
            Some(format!(
                "{} Until it runs, every run waits for you.",
                problem.text()
            )),
        ),
    }
}

/// The install commands of `docs/operations/bouncer.md` section 1, with the paths of
/// this Mac.
fn install_commands(status: &Status) -> String {
    let dir = shell_word(&status.laya_dir.to_string_lossy());
    let mut commands =
        format!("D={dir}\nmkdir -p \"$D\" && chmod 700 \"$(dirname \"$D\")\" && cd \"$D\"");
    // The same `uv venv` as "Install the model": none with a Python, `--clear` for a
    // `.venv` without one.
    if let Some(args) = status.venv_args {
        commands.push_str("\nuv ");
        commands.push_str(&args.join(" "));
    }
    commands.push_str("\nuv pip install --python .venv/bin/python \"laya[serve]==0.3.20\"");
    if let Some(tools) = &status.script_dir {
        let requirements = tools.join("requirements.txt");
        commands.push_str(&format!(
            "\nuv pip install --python .venv/bin/python -r {}",
            shell_word(&requirements.to_string_lossy())
        ));
        // The base weights, as the last step of "Install the model".
        commands.push('\n');
        commands.push_str(&fetch_command(tools));
    }
    commands
}

/// The command that downloads the base weights, in the Laya folder. `-B`: no
/// `__pycache__` in the app bundle, so its code signature stays valid.
fn fetch_command(tools: &std::path::Path) -> String {
    format!(
        ".venv/bin/python -B {}",
        shell_word(&tools.join(FETCH_SCRIPT).to_string_lossy())
    )
}

/// "Start the model", "Stop after", the status, the install note, and the buttons.
fn model_server_rows(s: &mut kit::Section<'_>, status: &Status) -> Option<ModelAction> {
    let mut action = None;
    let current = status.settings.start;
    s.field("Start the model", |ui| {
        let mut mode = current;
        let options: Vec<(StartMode, String)> = StartMode::ALL
            .iter()
            .map(|mode| (*mode, mode.label().to_owned()))
            .collect();
        let response = kit::picker(
            ui,
            "bouncer-start",
            &mut mode,
            &options,
            current.label(),
            220.0,
        );
        if mode != current {
            action = Some(ModelAction::Settings(BouncerSettings {
                start: mode,
                ..status.settings.clone()
            }));
        }
        response
    });
    if current == StartMode::WhenNeeded {
        let minutes = status.settings.idle_minutes;
        s.field("Stop after", |ui| {
            let mut chosen = minutes;
            let options: Vec<(u32, String)> = IDLE_CHOICES
                .iter()
                .map(|minutes| (*minutes, format!("{minutes} minutes without a run")))
                .collect();
            let label = format!("{minutes} minutes without a run");
            let response = kit::picker(ui, "bouncer-idle", &mut chosen, &options, label, 220.0);
            if chosen != minutes {
                action = Some(ModelAction::Settings(BouncerSettings {
                    idle_minutes: chosen,
                    ..status.settings.clone()
                }));
            }
            response
        });
    }
    let (words, tone, note) = model_server_words(status);
    s.status(
        "Status",
        note.as_deref(),
        kit::text(words, Font::Callout).color(tone.text()),
    );
    if let ServerState::Failed { log_tail, .. } = &status.state
        && !log_tail.is_empty()
    {
        s.row(|ui| {
            kit::note(ui, "The last lines of the log:");
            kit::code_block(ui, &log_tail.join("\n"), log_tail.len());
        });
    }
    if status.url_from_env {
        s.row(|ui| {
            kit::note(
                ui,
                "APASSY_BOUNCER_URL sets the address. It wins over the setting.",
            )
        });
    }
    if let Some(next) = install_rows(s, status) {
        action = Some(next);
    }
    launch_agent_rows(s, status);
    // The actions sit at the trailing edge, as in Notifications.
    s.row(|ui| {
        let size = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
        let layout = egui::Layout::right_to_left(egui::Align::Center);
        ui.allocate_ui_with_layout(size, layout, |ui| {
            if current.managed() {
                let active = matches!(
                    status.state,
                    ServerState::Starting { .. } | ServerState::Running { .. }
                );
                // A start would fail while the preflight fails, so there is no
                // "Start now". The status and the install rows name what is missing.
                if status.owned {
                    if kit::small_button(ui, "Stop", Style::Bordered).clicked() {
                        action = Some(ModelAction::Stop);
                    }
                } else if !active
                    && status.preflight.is_ok()
                    && kit::small_button(ui, "Start now", Style::Prominent).clicked()
                {
                    action = Some(ModelAction::Start);
                }
            }
            if kit::small_button(ui, "Open log", Style::Bordered)
                .on_hover_text(status.log.display().to_string())
                .clicked()
            {
                action = Some(ModelAction::OpenLog(status.log.clone()));
            }
        });
    });
    action
}

/// The install of the Laya environment: the progress with "Cancel install", the result,
/// and, in a managed mode with a missing environment, "Install the model".
fn install_rows(s: &mut kit::Section<'_>, status: &Status) -> Option<ModelAction> {
    let mut action = None;
    let installing = matches!(status.install, InstallState::Installing { .. });
    match &status.install {
        InstallState::Installing {
            step,
            of,
            label,
            since,
        } => {
            s.row(|ui| {
                let seconds = since.elapsed().as_secs();
                let progress = if *of == 0 {
                    format!("Installing the model: preparing ({seconds} s).")
                } else {
                    format!("Installing the model: step {step} of {of}, {label} ({seconds} s).")
                };
                kit::note(ui, progress);
                let what = if *label == FETCH_LABEL {
                    "The Python of the environment downloads the Laya base weights (about 800 MB) into the Hugging Face cache."
                } else {
                    "uv downloads Python packages."
                };
                kit::note(
                    ui,
                    format!(
                        "{what} This can take several minutes. The output goes to {}.",
                        status.install_log.display()
                    ),
                );
                if kit::small_button(ui, "Cancel install", Style::Bordered).clicked() {
                    action = Some(ModelAction::CancelInstall);
                }
            });
        }
        InstallState::Failed { reason, log_tail } => {
            s.row(|ui| {
                kit::tone_note(ui, format!("The install failed. {reason}"), Tone::Warning);
                if !log_tail.is_empty() {
                    kit::note(ui, "The last lines of the install log:");
                    kit::code_block(ui, &log_tail.join("\n"), log_tail.len());
                }
                if kit::small_button(ui, "Open install log", Style::Bordered)
                    .on_hover_text(status.install_log.display().to_string())
                    .clicked()
                {
                    action = Some(ModelAction::OpenLog(status.install_log.clone()));
                }
            });
        }
        InstallState::Done if status.venv_ready => {
            s.row(|ui| {
                kit::tone_note(
                    ui,
                    format!("The model is installed in {}.", status.laya_dir.display()),
                    Tone::Good,
                );
            });
        }
        InstallState::Done | InstallState::Idle => {}
    }
    let problem = status
        .preflight
        .as_ref()
        .err()
        .filter(|problem| matches!(problem, Problem::NoScript | Problem::NoVenv { .. }));
    // Only the download of the weights failed: the server can start and downloads
    // them, and "Install the model" tries the download again.
    let weights_retry = problem.is_none()
        && status.venv_ready
        && !status.weights_cached
        && matches!(status.install, InstallState::Failed { .. });
    if !status.settings.start.managed()
        || installing
        || (problem.is_none() && status.venv_ready && !weights_retry)
    {
        return action;
    }
    if weights_retry {
        s.row(|ui| {
            kit::note(
                ui,
                "The model weights are not in the Hugging Face cache yet. The first start of the model server downloads them (about 800 MB).",
            );
            match &status.uv {
                Some(_) => {
                    if kit::small_button(ui, "Install the model", Style::Prominent)
                        .on_hover_text("Download the model weights again")
                        .clicked()
                    {
                        action = Some(ModelAction::Install);
                    }
                }
                None => kit::tone_note(ui, UV_MISSING, Tone::Warning),
            }
            if let Some(tools) = &status.script_dir {
                kit::note(ui, "Or download them with this command in Terminal:");
                let command = format!(
                    "cd {} && {}",
                    shell_word(&status.laya_dir.to_string_lossy()),
                    fetch_command(tools)
                );
                kit::code_block(ui, &command, 1);
            }
        });
        return action;
    }
    s.row(|ui| {
        if let Some(problem) = problem {
            kit::tone_note(ui, problem.text(), Tone::Warning);
            if matches!(problem, Problem::NoScript) {
                kit::note(
                    ui,
                    "Build the app with scripts/build-app.sh, or run Apassy from the repository. The script is in tools/basemodel.",
                );
            }
        }
        if !status.venv_ready {
            match &status.uv {
                Some(uv) => {
                    kit::note(
                        ui,
                        format!(
                            "\"Install the model\" installs the Laya environment in {} with {}. It downloads Python packages and can take several minutes.",
                            status.laya_dir.display(),
                            uv.display()
                        ),
                    );
                    if kit::small_button(ui, "Install the model", Style::Prominent).clicked() {
                        action = Some(ModelAction::Install);
                    }
                }
                None => kit::tone_note(ui, UV_MISSING, Tone::Warning),
            }
            kit::note(
                ui,
                "Or install the Laya environment with these commands in Terminal:",
            );
            kit::code_block(ui, &install_commands(status), 6);
        }
        kit::note(ui, "Until then, every run waits for you.");
    });
    action
}

/// A note for each LaunchAgent that runs `start.sh` with a missing model, or in a mode
/// where Apassy starts the server itself. Apassy never changes the LaunchAgent.
fn launch_agent_rows(s: &mut kit::Section<'_>, status: &Status) {
    for agent in &status.launch_agents {
        let Some(conflict) = agent.conflict(status.settings.start) else {
            continue;
        };
        let text = match conflict {
            AgentConflict::MissingModel(model) => format!(
                "The LaunchAgent {} starts the bouncer with APASSY_BASE_MODEL {}. That file does not exist, so the start fails.",
                agent.label,
                model.display()
            ),
            AgentConflict::Mode(mode) => format!(
                "The LaunchAgent {} also starts the bouncer. With \"{}\", Apassy starts and stops the model itself.",
                agent.label,
                mode.label()
            ),
        };
        s.row(|ui| {
            kit::tone_note(ui, text, Tone::Warning);
            kit::note(
                ui,
                "To remove it, run these commands in Terminal. Apassy does not change it.",
            );
            kit::code_block(ui, &agent.remove_commands(), 2);
        });
    }
}

/// Open a file in its app with `/usr/bin/open`. A thread waits for `open`, so no
/// finished process stays.
fn open_file(path: &std::path::Path) -> std::io::Result<()> {
    let mut child = std::process::Command::new("/usr/bin/open")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// The owner command line (ADR 0017).
fn command_line_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let open = app.cli_sessions_open();
    let mut end = false;
    let mut install = false;
    kit::section(
        ui,
        Some("Command line"),
        Some(
            "The apassy command talks to this window. apassy login asks you here first. Commands never show a secret value. Approvals, new tokens, and changes that give access ask you here each time. Agents need no grant: the bouncer decides each use.",
        ),
        |s| {
            s.row(|ui| {
                install = kit::button(ui, "Install CLI tools", Style::Bordered).clicked();
            });
            s.row(|ui| {
                kit::note(ui, "Install links in ~/.local/bin. Existing commands are not replaced. Then run these commands in Terminal:");
                kit::code_block(ui, "export PATH=\"$HOME/.local/bin:$PATH\"\neval \"$(apassy login)\"\napassy doctor", 3);
                kit::note(ui, "The PATH command applies to this terminal session. Add it to ~/.zshrc to use the tools in each new terminal.");
            });
            match (app.cli.socket_path(), app.cli.problem.as_deref()) {
                (Some(path), _) => s.labeled(
                    "Socket",
                    kit::text(path.display().to_string(), Font::MonoSmall).color(kit::SECONDARY),
                ),
                (None, Some(problem)) => s.labeled(
                    "Socket",
                    kit::text(problem, Font::Callout).color(Tone::Critical.text()),
                ),
                (None, None) => s.labeled(
                    "Socket",
                    kit::text("Starts with the desktop window", Font::Callout)
                        .color(kit::SECONDARY),
                ),
            }
            let sessions = match open {
                0 => "None open".to_owned(),
                1 => "1 open".to_owned(),
                count => format!("{count} open"),
            };
            s.labeled(
                "Sessions",
                kit::text(sessions, Font::Callout).color(kit::SECONDARY),
            );
            if open > 0 {
                s.row(|ui| {
                    end = kit::small_button(ui, "End all sessions", Style::Bordered).clicked();
                });
            }
        },
    );
    if install {
        match super::cli_tools::install() {
            Ok(()) => app.set_ok(
                "CLI tools are installed in ~/.local/bin. Run the commands below in Terminal.",
            ),
            Err(error) => app.set_err(error),
        }
    }
    if end {
        app.end_cli_sessions();
        app.set_ok("Every command-line session ended.");
    }
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
                    super::files::path_input(
                        ui,
                        &mut app.files,
                        &mut app.owner_ui.backup_path,
                        "vault-backup-path",
                        "/Volumes/Backup/apassy.backup",
                        super::files::DialogKind::SaveBackup,
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
