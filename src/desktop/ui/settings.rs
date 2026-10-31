//! The sections of Settings (ADR 0026 §3), as the detail column of the Settings view
//! ([`super::settings_view`]) draws them:
//!
//! - Vault: the open vault, its sync, its backups, and import.
//! - Security: Touch ID and the passphrase.
//! - Devices: this Mac, the iPhones, the other Macs, and the relay for the questions
//!   (ADR 0025 §3e).
//! - Bouncer: the model with its actions, and calibration and learning.
//! - Tools: the command line and the browser extension.
//! - Updates: the updater, the version, and the keyboard shortcuts.
//!
//! Each section is a list of groups of rows ([`rows`]): the label on the left, the value
//! or the control on the right, and at most one short note for each group. A status that
//! needs nothing from the owner does not show. Each change that is rare or risky opens a
//! sheet.
//!
//! Settings of single agents are gone (ADR 0025 §3f): the agent screen shows, it does
//! not configure.

use std::path::PathBuf;

use eframe::egui;

use super::kit::{self, Font, Icon, Style, Tone};
use super::settings_view::SettingsSection;
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
use crate::desktop::unlock::{HELPER_MISSING_NOTE, UnlockMethod};
use crate::desktop::{BrokerState, DesktopApp};
use crate::relay::membership::{QuestionsAvailability, questions_availability};
use crate::vault::{CompanionDevice, TrustedDevice, TrustedDeviceKind};

#[path = "settings_rows.rs"]
pub(crate) mod rows;

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;

/// The groups of a section, under its header.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui, section: SettingsSection) {
    match section {
        SettingsSection::Vault => {
            super::vaults::settings_section(app, ui);
            super::sync::settings_section(app, ui);
            backup_section(app, ui);
            super::import::section(app, ui);
        }
        SettingsSection::Security => security_section(app, ui),
        SettingsSection::Devices => devices_section(app, ui),
        SettingsSection::Bouncer => broker_section(app, ui),
        SettingsSection::Tools => {
            command_line_section(app, ui);
            super::browser_settings::section(app, ui);
        }
        SettingsSection::Updates => {
            super::updates::section(app, ui);
            shortcuts_section(ui);
        }
    }
}

/// The status line of a section in the list of Settings: what the owner most likely
/// wants to know, in a few words.
pub(super) fn status_line(app: &DesktopApp, section: SettingsSection) -> String {
    match section {
        SettingsSection::Vault => {
            let Some(entry) = app.current_vault() else {
                return "No vault is open".to_owned();
            };
            if app.sync.offered {
                format!("{} · {}", entry.name, super::sync::method_words(app, entry))
            } else {
                entry.name.clone()
            }
        }
        SettingsSection::Security => {
            let touch_id = app
                .owner
                .unlock
                .setting
                .as_ref()
                .is_some_and(|setting| setting.method == UnlockMethod::TouchId);
            if touch_id {
                "Unlock with Touch ID".to_owned()
            } else {
                "Unlock with the passphrase".to_owned()
            }
        }
        SettingsSection::Devices => {
            let mut parts = Vec::new();
            let broken = app
                .owner
                .notifications
                .as_ref()
                .is_some_and(|center| !center.view().channel.can_deliver());
            if broken {
                parts.push("Notifications off".to_owned());
            }
            let companions = app.owner_ui.session.companion_devices().unwrap_or_default();
            let (relay_on, relay_iphones) = relay_iphones(app);
            parts.push(iphones_words(iphone_count(&companions, &relay_iphones)));
            if relay_on {
                parts.push("Relay on".to_owned());
            }
            parts.join(" · ")
        }
        SettingsSection::Bouncer => app.model_server.as_ref().map_or_else(
            || "Every run waits for you".to_owned(),
            |server| format!("Model: {}", model_server_words(&server.status()).0),
        ),
        SettingsSection::Tools => {
            if super::cli_tools::installed() {
                "Command line installed".to_owned()
            } else {
                "Command line not installed".to_owned()
            }
        }
        SettingsSection::Updates => format!("Version {}", app.updates.build().label()),
    }
}

/// Whether the questions of the open, unlocked vault go through the relay, and then the
/// live iPhones of its trusted devices: the iPhones that answer them there.
fn relay_iphones(app: &DesktopApp) -> (bool, Vec<TrustedDevice>) {
    let vault = app.owner_ui.session.shared_vault();
    let guard = vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(vault) = guard.as_ref().filter(|vault| !vault.is_locked()) else {
        return (false, Vec::new());
    };
    if !matches!(
        questions_availability(vault),
        Ok(QuestionsAvailability::On { .. })
    ) {
        return (false, Vec::new());
    }
    let iphones = vault
        .trusted_devices()
        .unwrap_or_default()
        .into_iter()
        .filter(|device| device.kind == TrustedDeviceKind::Iphone)
        .collect();
    (true, iphones)
}

/// How many iPhones this Mac works with: the paired iPhones of this network and the
/// iPhones of the relay. The two lists share no ID, so an iPhone of the relay with the
/// name of a paired iPhone is that iPhone, once for each paired iPhone of that name.
pub(super) fn iphone_count(companions: &[CompanionDevice], relay: &[TrustedDevice]) -> usize {
    let mut unmatched: Vec<&str> = companions.iter().map(|device| device.name.trim()).collect();
    let mut count = companions.len();
    for device in relay {
        let name = device.name.trim();
        match unmatched.iter().position(|paired| *paired == name) {
            Some(at) => {
                unmatched.swap_remove(at);
            }
            None => count += 1,
        }
    }
    count
}

/// "No iPhone", "1 iPhone", "2 iPhones".
pub(super) fn iphones_words(count: usize) -> String {
    match count {
        0 => "No iPhone".to_owned(),
        1 => "1 iPhone".to_owned(),
        count => format!("{count} iPhones"),
    }
}

/// A row that shows more rows below it: "Show" and "Hide". The state stays in the
/// memory of egui.
fn shows_more(ui: &egui::Ui, key: &str) -> (egui::Id, bool) {
    let id = egui::Id::new(("apassy-settings-more", key));
    (
        id,
        ui.ctx()
            .data(|data| data.get_temp::<bool>(id))
            .unwrap_or(false),
    )
}

fn show_more_button(ui: &mut egui::Ui, id: egui::Id, open: bool, name: &str) {
    let label = if open { "Hide" } else { "Show" };
    let button = kit::small_button(ui, label, Style::Bordered);
    let spoken = format!("{label} {name}");
    ui.ctx()
        .accesskit_node_builder(button.id, |node| node.set_label(spoken));
    if button.clicked() {
        ui.ctx().data_mut(|data| data.insert_temp(id, !open));
    }
}

/// The words of the relay row (ADR 0025 §3e, contract relay-questions-v1). Off by
/// default: only a relay membership with the purpose `questions` turns it on.
/// `RELAY_QUESTIONS` names its switch for VoiceOver.
pub(super) const RELAY_QUESTIONS: &str = "Send questions through the relay";
/// The label of the relay row.
pub(super) const RELAY_ROW: &str = "Questions through the relay";
pub(super) const RELAY_QUESTIONS_ON: &str = "Questions also go to your other devices of this vault. The relay sees no command and no credential.";
pub(super) const RELAY_QUESTIONS_OFF: &str =
    "Off. Turn it on to answer on your other devices away from this network.";
pub(super) const RELAY_QUESTIONS_NEW_TEAM: &str = "Off. Turning it on makes a relay team for the questions only, with a team code from the operator.";
pub(super) const RELAY_QUESTIONS_LOCKED: &str = "Unlock the vault to change it.";
pub(super) const RELAY_QUESTIONS_JOIN: &str = "Off. Turning it on joins the questions team of this vault, with a link from a Mac that has it on.";
pub(super) const RELAY_QUESTIONS_REMOVED: &str =
    "Off. This Mac was removed. Turning it on again needs a link from a Mac that has it on.";
/// The switch of the feed of the agents for the iPhone (relay-feed-v1 section 8). On by
/// default; `ui.json` keeps it.
pub(super) const SHOW_AGENTS: &str = "Show agents on the iPhone";
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

/// Turn "Show agents on the iPhone" on or off. Off: the questions waiter deletes the feed
/// of this Mac from the relay on its own thread, and takes no action from the iPhone.
pub(super) fn set_feed_shown(app: &mut DesktopApp, on: bool) {
    app.ui.set_feed_off(!on);
    if let Some(questions) = &app.owner.questions {
        questions.set_feed(on);
    }
}

/// What the owner chose for the macOS notifications of this Mac.
enum NotifyAction {
    Allow,
    OpenSettings,
    Check,
}

/// Settings > Devices: each device that gets the questions of the bouncer (ADR 0025
/// §3e). This Mac with its macOS notifications, the iPhone app, the other Macs of a
/// synced vault, and the relay that brings the questions to them away from this network.
fn devices_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    this_mac_group(app, ui);
    super::companion::draw(app, ui);
    other_macs_group(app, ui);
    relay_group(app, ui);
}

/// "This Mac": the macOS notifications. The buttons and the note show only while they
/// do not work (goal items N1 to N4).
fn this_mac_group(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let notifications = app.owner.notifications.as_ref().map(|center| center.view());
    let mut notify_action = None;
    rows::group(ui, Some("This Mac"), |g| {
        let Some(view) = &notifications else {
            g.line_note(
                "Notifications",
                Some(rows::value("Not running")),
                Some(rows::note(
                    "They start with the broker. Questions still wait in Decisions.",
                )),
                |_| {},
            );
            return;
        };
        let channel = &view.channel;
        let words = if channel.can_deliver() {
            "On"
        } else if channel.needs_permission() {
            "Not allowed yet"
        } else {
            "Off"
        };
        let failed = view
            .deliveries
            .values()
            .filter(|delivery| matches!(delivery, Delivery::Failed(_)))
            .count();
        g.row(|ui| {
            rows::one_line(
                ui,
                rows::label_text("Notifications").into(),
                Some(rows::value(words)),
                |ui| {
            if channel.needs_permission()
                && kit::small_button(ui, "Allow…", Style::Prominent)
                    .on_hover_text(
                        "macOS shows a prompt for \"Apassy\" at the top right of the screen. Select \"Allow\".",
                    )
                    .clicked()
            {
                notify_action = Some(NotifyAction::Allow);
            }
            if channel.needs_settings()
                && kit::small_button(ui, "Open System Settings…", Style::Bordered)
                    .on_hover_text(
                        "System Settings > Notifications > Apassy. Turn on \"Allow notifications\" and select \"Banners\".",
                    )
                    .clicked()
            {
                notify_action = Some(NotifyAction::OpenSettings);
            }
            if !channel.can_deliver()
                && kit::small_button(ui, "Check again", Style::Bordered).clicked()
            {
                notify_action = Some(NotifyAction::Check);
            }
                },
            );
            // What to do, only while notifications do not work.
            if !channel.can_deliver() {
                ui.add(egui::Label::new(rows::note(&channel.summary())).wrap());
            }
            if failed > 0 {
                ui.add(
                    egui::Label::new(
                        kit::text(
                            format!(
                                "{failed} {} failed. Questions still wait in Decisions.",
                                if failed == 1 {
                                    "notification"
                                } else {
                                    "notifications"
                                }
                            ),
                            Font::Callout,
                        )
                        .color(Tone::Critical.text()),
                    )
                    .wrap(),
                );
            }
        });
    });
    if let Some(action) = notify_action
        && let Some(center) = &app.owner.notifications
    {
        match action {
            // The notifier (Contents/Helpers/ApassyNotify.app, display name "Apassy")
            // asks macOS. After a denial, macOS shows no new prompt.
            NotifyAction::Allow => center.request_permission(),
            NotifyAction::OpenSettings => match notify::open_notification_settings() {
                Ok(()) => center.refresh_status(),
                Err(err) => center.report_problem(format!(
                    "Apassy cannot open System Settings ({err}). Open System Settings > Notifications > Apassy."
                )),
            },
            NotifyAction::Check => center.refresh_status(),
        }
    }
}

/// "Other Macs": only while the open vault syncs. Through the relay, "Add a Mac…" and
/// "Devices…" list and link them.
fn other_macs_group(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let synced = app
        .current_vault()
        .is_some_and(|entry| entry.sync.is_some() && entry.sync_state().is_some());
    if !synced {
        return;
    }
    let others = super::sync::other_macs(app);
    let mut sheet = None;
    rows::group(ui, Some("Other Macs"), |g| {
        g.line("Sync", Some(rows::value(&others.words)), |ui| {
            if let Some(id) = &others.relay {
                if kit::small_button(ui, "Devices…", Style::Bordered).clicked() {
                    sheet = Some(super::sync::SyncSheet::Devices { id: id.clone() });
                }
                if kit::small_button(ui, "Add a Mac…", Style::Bordered).clicked() {
                    sheet = Some(super::sync::SyncSheet::AddMac { id: id.clone() });
                }
            }
        });
    });
    if let Some(sheet) = sheet {
        let ctx = ui.ctx().clone();
        app.sync_open_sheet(sheet, Some(&ctx));
    }
}

/// "Relay": the switch that sends the questions through the relay, the devices that get
/// them, and a new device.
fn relay_group(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let relay_state = relay_questions_state(app);
    let relay_devices = if matches!(relay_state, Some(QuestionsAvailability::On { .. })) {
        app.questions_devices()
    } else {
        Vec::new()
    };
    // The problem of the questions waiter: a relay without the questions, or this Mac
    // removed from them.
    let questions_view = app
        .owner
        .questions
        .as_ref()
        .map(|questions| questions.view());
    let relay_problem = questions_view
        .clone()
        .filter(|view| view.unsupported)
        .and_then(|view| view.problem);
    // "Show agents on the iPhone", with the problem of the feed under it while it is on.
    let mut feed_shown = !app.ui.feed_off;
    let feed_problem = questions_view
        .and_then(|view| view.feed_problem)
        .filter(|_| feed_shown);
    let mut switch_feed = None;
    let mut switch_relay = None;
    let mut add_relay_iphone = false;
    let mut remove_device = None;
    rows::section(
        ui,
        Some("Relay"),
        Some("Questions reach every device."),
        |g| {
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
            let value = was.then(|| rows::value("End-to-end encrypted"));
            g.line_note(RELAY_ROW, value, Some(rows::note(note)), |ui| {
                ui.add_enabled_ui(enabled, |ui| kit::toggle(ui, &mut on, RELAY_QUESTIONS));
            });
            if on != was {
                switch_relay = Some(on);
            }
            // A relay that predates the questions, and other problems of the relay.
            if let Some(problem) = &relay_problem {
                g.tone_row(problem, Tone::Critical.text());
            }
            if was {
                // As the relay row above: the switch on the line of its label, and the
                // problem of the feed under them, in the warning tone (the questions go
                // on without the feed).
                let before = feed_shown;
                let problem = feed_problem
                    .as_deref()
                    .map(|problem| kit::text(problem, Font::Callout).color(Tone::Warning.text()));
                g.line_note(SHOW_AGENTS, None, problem, |ui| {
                    kit::toggle(ui, &mut feed_shown, SHOW_AGENTS);
                });
                if feed_shown != before {
                    switch_feed = Some(feed_shown);
                }
            }
            // The devices that get the questions through the relay, "Remove…" for each
            // other device, and a new device.
            for device in &relay_devices {
                g.line_note(
                    device.name.as_str(),
                    None,
                    Some(rows::note(&device.words)),
                    |ui| {
                        // Its text ends where the switches above end.
                        if device.removable
                            && kit::trailing_small_button(ui, REMOVE_DEVICE, Style::Destructive)
                                .clicked()
                        {
                            remove_device = Some(device.uuid.clone());
                        }
                    },
                );
            }
            if was {
                add_relay_iphone = g
                    .link(ADD_IPHONE)
                    .on_hover_text(
                        "An iPhone answers the questions with Face ID, also away from this network.",
                    )
                    .clicked();
            }
        },
    );
    let ctx = ui.ctx().clone();
    if let Some(on) = switch_relay {
        set_relay_questions(app, on, Some(&ctx));
    }
    if let Some(on) = switch_feed {
        set_feed_shown(app, on);
    }
    if let Some(uuid) = remove_device {
        app.questions_ask_remove(&uuid, Some(&ctx));
    } else if add_relay_iphone {
        app.questions_add_iphone(Some(&ctx));
    }
}

/// "Pair…" of the iPhone app: the iPhone listener goes on, and the pairing code shows
/// below.
pub(super) fn add_an_iphone(app: &mut DesktopApp, ctx: &egui::Context) {
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

/// Settings > Security > Unlock: Touch ID, with how owner checks confirm in its note,
/// and the passphrase.
fn security_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut change = false;
    let ctx = ui.ctx().clone();
    let setup_id = egui::Id::new("apassy-touch-id-setup");
    let mut setup = ctx
        .data(|data| data.get_temp::<bool>(setup_id))
        .unwrap_or(false);
    let mut action = None;
    rows::group(ui, Some("Unlock"), |g| {
        action = touch_id_rows(app, g, &mut setup);
        g.line("Passphrase", None, |ui| {
            change = kit::small_button(ui, "Change passphrase…", Style::Bordered)
                .on_hover_text("Old backups still need the old passphrase.")
                .clicked();
        });
    });
    ctx.data_mut(|data| data.insert_temp(setup_id, setup));
    match action {
        Some(TouchIdAction::Off) => app.start_touch_id_off(
            Some(&ctx),
            "Touch ID unlock is off. Apassy deleted the unlock key from the keychain.",
        ),
        Some(TouchIdAction::On) => app.start_touch_id_setup(&ctx),
        None => {}
    }
    if change {
        app.ui.sheet = Some(Sheet::ChangePassphrase);
    }
}

enum TouchIdAction {
    On,
    Off,
}

/// The Touch ID switch (goal items A2, A3). The passphrase stays the root key. "On"
/// first asks for the passphrase in a row below; "Off" acts at once. Its note says how
/// owner checks confirm, and why Touch ID unlock is not available.
fn touch_id_rows(
    app: &mut DesktopApp,
    g: &mut rows::Group<'_>,
    setup: &mut bool,
) -> Option<TouchIdAction> {
    let unlock = &app.owner.unlock;
    let busy = unlock.reading.is_some() || unlock.changing.is_some();
    let setting = unlock.setting.clone();
    let touch_id = setting
        .as_ref()
        .is_some_and(|setting| setting.method == UnlockMethod::TouchId);
    let can_set_up = setting
        .as_ref()
        .is_some_and(|setting| setting.method == UnlockMethod::Passphrase && setting.can_set_up);
    *setup &= can_set_up && !busy;
    let shown = touch_id || *setup;
    let mut on = shown;
    // Owner checks use Touch ID apart from the unlock setting.
    let checks_note = app.owner.touch_id_note();
    let checks = if checks_note.is_none() {
        "Owner checks use Touch ID."
    } else {
        "Owner checks use the passphrase."
    };
    let warning = setting.as_ref().and_then(|setting| setting.note.as_deref());
    let note = if busy {
        rows::note("Apassy is reading or changing the Touch ID unlock setting.")
    } else {
        match warning {
            // A source build: one line for both.
            Some(HELPER_MISSING_NOTE) if checks_note.is_some() => kit::text(
                "Touch ID works only in Apassy.app. Unlock and owner checks use the passphrase.",
                Font::Callout,
            )
            .color(Tone::Warning.text()),
            Some(warning) => {
                kit::text(format!("{warning} {checks}"), Font::Callout).color(Tone::Warning.text())
            }
            None => rows::note(checks),
        }
    };
    let note = Some(note);
    let value = touch_id.then(|| rows::value("The passphrase still works"));
    g.line_note("Touch ID", value, note, |ui| {
        ui.add_enabled_ui(!busy && (touch_id || can_set_up), |ui| {
            kit::toggle(ui, &mut on, "Touch ID unlock")
        });
    });
    let mut action = None;
    if on != shown {
        if touch_id {
            action = Some(TouchIdAction::Off);
        } else {
            *setup = on;
        }
    }
    if *setup {
        g.line_note(
            "Passphrase",
            None,
            Some(rows::note(
                "Touch ID setup, a restore, and recovery need the passphrase. A fingerprint change turns Touch ID unlock off.",
            )),
            |ui| {
                let ctx = ui.ctx().clone();
                if kit::small_button(ui, "Turn on", Style::Prominent).clicked() {
                    action = Some(TouchIdAction::On);
                }
                let field = ui
                    .scope(|ui| {
                        ui.set_max_width(200.0);
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
                if field.lost_focus() && ctx.input(|input| input.key_pressed(egui::Key::Enter)) {
                    action = Some(TouchIdAction::On);
                }
            },
        );
    }
    action
}

/// Settings > Vault > Backup.
fn backup_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut open = None;
    rows::section(
        ui,
        Some("Backup"),
        Some("The vault locks after a backup."),
        |g| {
            g.line("Encrypted copy of the vault", None, |ui| {
                if kit::small_button(ui, "Back up now…", Style::Bordered)
                    .on_hover_text("The vault locks after the backup.")
                    .clicked()
                {
                    open = Some(Sheet::Backup);
                }
            });
            g.line("Restore from a backup", None, |ui| {
                if kit::small_button(ui, "Restore…", Style::Bordered)
                    .on_hover_text("Agents are revoked, and each credential waits for your review.")
                    .clicked()
                {
                    open = Some(Sheet::Restore);
                }
            });
        },
    );
    if open.is_some() {
        app.ui.sheet = open;
    }
}

/// The keyboard shortcuts of the window.
const SHORTCUTS: [(&str, &str); 15] = [
    ("⌘1 ⌘2 ⌘3", "All credentials, Decisions, Agents"),
    ("⌘,", "Settings"),
    ("⌘[", "Back to the list"),
    ("⌘N", "New credential"),
    ("⌘F", "Search credentials"),
    ("⌘L", "Lock the vault"),
    ("⌃⌘S", "Hide or show the sidebar"),
    ("Return, ⌘S", "The default action of the open sheet"),
    ("⌘⇧H", "Show or hide the secret values"),
    ("Tab, ⇧Tab", "Next or previous control"),
    ("← → ↑ ↓", "Nearest control"),
    ("Space", "Press the control, or the next option"),
    ("← → on a picker", "Previous or next option"),
    (
        "Page Up, Page Down, Home, End",
        "Scroll the page or the sheet",
    ),
    ("Esc", "Close the sheet, a menu, or an error"),
];

/// Settings > Updates > Keyboard shortcuts, behind "Show".
fn shortcuts_section(ui: &mut egui::Ui) {
    let (id, open) = shows_more(ui, "shortcuts");
    rows::group(ui, Some("Keyboard shortcuts"), |g| {
        g.line("All shortcuts", None, |ui| {
            show_more_button(ui, id, open, "keyboard shortcuts");
        });
        if open {
            for (keys, action) in SHORTCUTS {
                g.line(
                    action,
                    Some(kit::text(keys, Font::Mono).color(kit::SECONDARY)),
                    |_| {},
                );
            }
            g.note_row(
                "⌘H stays the macOS shortcut for \"Hide Apassy\", so showing values uses ⌘⇧H.",
            );
        }
    });
}

/// Only states established by a successful inference warm-up are ready.
fn model_ready(state: &ServerState) -> bool {
    matches!(
        state,
        ServerState::Running { .. } | ServerState::External { up: Some(true), .. }
    )
}

/// UTC bounds of the owner's calendar day. Resolve both boundaries in the system
/// timezone: subtracting today's offset or adding 24 hours fails on DST days.
fn local_day_bounds(now: u64) -> Option<(u64, u64)> {
    local_day_bounds_with(now, |at| time::UtcOffset::local_offset_at(at).ok())
}

fn local_day_bounds_with(
    now: u64,
    offset_at: impl Fn(time::OffsetDateTime) -> Option<time::UtcOffset>,
) -> Option<(u64, u64)> {
    let now = time::OffsetDateTime::from_unix_timestamp(now.try_into().ok()?).ok()?;
    let date = now.to_offset(offset_at(now)?).date();
    let boundary = |date: time::Date| -> Option<u64> {
        let nominal = date.midnight().assume_utc().unix_timestamp();
        let (mut low, mut high) = (nominal - 172_800, nominal + 172_800);
        // Search calendar dates rather than assuming that local midnight exists
        // or has the same UTC offset as noon (some zones change at midnight).
        while low < high {
            let mid = low + (high - low) / 2;
            let at = time::OffsetDateTime::from_unix_timestamp(mid).ok()?;
            if at.to_offset(offset_at(at)?).date() < date {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low.try_into().ok()
    };
    Some((boundary(date)?, boundary(date.next_day()?)?))
}

/// Settings > Bouncer: the model server (ADR 0024) in one row with its state and its
/// action, how it starts, a broker that does not take agent requests, and calibration
/// and learning.
fn broker_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let server = app.model_server.clone();
    let status = server.as_ref().map(|server| server.status());
    let mut action = None;
    rows::group(ui, Some("Model"), |g| {
        if let Some(status) = &status {
            action = model_server_rows(g, status);
        }
        broker_rows(app, g);
        let ready = status
            .as_ref()
            .is_some_and(|status| model_ready(&status.state));
        g.line(
            "Bouncer",
            Some(kit::text(
                if ready {
                    "Model ready"
                } else {
                    "Model not ready"
                },
                Font::Body,
            )),
            |_| {},
        );
        let shared = app.owner_ui.session.shared_vault();
        let guard = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(vault) = guard.as_ref().filter(|vault| !vault.is_locked()) {
            let counts = local_day_bounds(crate::broker::learning::now())
                .and_then(|(start, end)| vault.bouncer_counts(start, end).ok());
            match counts {
                Some(counts) => {
                    g.line(
                        "Today",
                        Some(kit::text(
                            format!(
                                "{} decided by the bouncer · {} asked you · {} failed",
                                counts.by_model, counts.asked, counts.failed
                            ),
                            Font::Body,
                        )),
                        |_| {},
                    );
                    g.note_row("Failed: model or readiness errors, or questions left unanswered. These can also count as asked.");
                }
                None => g.tone_row(
                    "Today's bouncer counts are unavailable.",
                    Tone::Warning.text(),
                ),
            }
        }
    });
    crate::desktop::learning_ui::settings_panel(app, ui);
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
            app.set_note("The install stopped. \"Install…\" starts it again.");
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
        Some(ModelAction::Copy(text)) => {
            ui.ctx().copy_text(text);
            app.set_ok("The commands are copied. Paste them in Terminal.");
        }
        None => {}
    }
}

/// The broker, only when something is wrong: it failed to start, or it has no address
/// of the bouncer. A broker that accepts agent requests needs no row.
fn broker_rows(app: &DesktopApp, g: &mut rows::Group<'_>) {
    match &app.broker {
        BrokerState::Running(handle) if handle.bouncer_url().is_none() => g.tone_row(
            "The broker has no bouncer address. Every run waits for you.",
            Tone::Warning.text(),
        ),
        BrokerState::Failed(message) => g.tone_row(
            format!("The broker does not take agent requests. {message}"),
            Tone::Critical.text(),
        ),
        BrokerState::Running(_) | BrokerState::NotStarted => {}
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
    /// Commands for Terminal, to the pasteboard. They hold no secret.
    Copy(String),
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
            "Ready".to_owned(),
            Tone::Good,
            Some(model.as_ref().map_or_else(
                || format!("The model at {url} answers."),
                |model| format!("Model: {model} at {url}."),
            )),
        ),
        ServerState::External {
            up: Some(false), ..
        } => (
            "Not running".to_owned(),
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
            "Not running".to_owned(),
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
            "Ready".to_owned(),
            Tone::Good,
            if *outside {
                Some(format!("Started outside Apassy. {}", model_note(model).unwrap_or_default()))
            } else {
                model_note(model)
            },
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
/// this Mac. The menu of the "Model" row copies them.
pub(super) fn install_commands(status: &Status) -> String {
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

/// The "Model" row, how the model starts, and the notes of an install or a problem.
fn model_server_rows(g: &mut rows::Group<'_>, status: &Status) -> Option<ModelAction> {
    let mut action = None;
    let current = status.settings.start;
    let (words, tone, status_note) = model_server_words(status);
    let install = install_offer(status);
    let note = install.note.clone().or(status_note);
    let active = matches!(
        status.state,
        ServerState::Starting { .. } | ServerState::Running { .. }
    );
    g.line_note(
        "Model",
        Some(kit::text(words, Font::Body).color(tone.text())),
        note.as_deref().map(rows::note),
        |ui| {
            // The rare actions: the logs and the Terminal commands.
            let more = kit::icon_button(ui, Icon::More, "More bouncer actions", kit::Size::Small);
            egui::Popup::menu(&more).show(|ui| {
                ui.set_min_width(220.0);
                if ui
                    .selectable_label(false, "Open log")
                    .on_hover_text(status.log.display().to_string())
                    .clicked()
                {
                    action = Some(ModelAction::OpenLog(status.log.clone()));
                }
                if ui
                    .selectable_label(false, "Open install log")
                    .on_hover_text(status.install_log.display().to_string())
                    .clicked()
                {
                    action = Some(ModelAction::OpenLog(status.install_log.clone()));
                }
                if let Some((label, commands)) = &install.commands
                    && ui.selectable_label(false, *label).clicked()
                {
                    action = Some(ModelAction::Copy(commands.clone()));
                }
            });
            if install.installing {
                if kit::small_button(ui, "Cancel install", Style::Bordered).clicked() {
                    action = Some(ModelAction::CancelInstall);
                }
            } else if let Some(hover) = &install.button {
                if kit::small_button(ui, "Install…", Style::Prominent)
                    .on_hover_text(hover)
                    .clicked()
                {
                    action = Some(ModelAction::Install);
                }
            } else if current.managed() {
                // A start would fail while the preflight fails, so there is no
                // "Start now". The note names what is missing.
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
        },
    );
    for (text, tone) in &install.warnings {
        g.tone_row(text, tone.text());
    }
    if status.url_from_env {
        g.note_row("APASSY_BOUNCER_URL sets the address. It wins over the setting.");
    }
    g.field("Start the model", |ui| {
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
            200.0,
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
        g.field("Stop after", |ui| {
            let mut chosen = minutes;
            let options: Vec<(u32, String)> = IDLE_CHOICES
                .iter()
                .map(|minutes| (*minutes, format!("{minutes} minutes without a run")))
                .collect();
            let label = format!("{minutes} minutes without a run");
            let response = kit::picker(ui, "bouncer-idle", &mut chosen, &options, label, 200.0);
            if chosen != minutes {
                action = Some(ModelAction::Settings(BouncerSettings {
                    idle_minutes: chosen,
                    ..status.settings.clone()
                }));
            }
            response
        });
    }
    if let Some(next) = launch_agent_rows(g, status) {
        action = Some(next);
    }
    action
}

/// What the "Model" row offers for the install of the Laya environment.
#[derive(Default)]
struct InstallOffer {
    /// The install runs: "Cancel install".
    installing: bool,
    /// "Install…" with its hover text.
    button: Option<String>,
    /// The short note of the row, in place of the note of the state.
    note: Option<String>,
    /// The Terminal commands in the menu of the row: its label and the commands.
    commands: Option<(&'static str, String)>,
    /// Rows in a status color: a failed install, or a missing `uv`.
    warnings: Vec<(String, Tone)>,
}

/// The install of the Laya environment: its progress, its result, and, in a managed mode
/// with a missing environment, "Install…" with a short note. The commands for Terminal
/// are in the menu of the row.
fn install_offer(status: &Status) -> InstallOffer {
    let mut offer = InstallOffer::default();
    match &status.install {
        InstallState::Installing {
            step,
            of,
            label,
            since,
        } => {
            let seconds = since.elapsed().as_secs();
            let progress = if *of == 0 {
                format!("Installing the model: preparing ({seconds} s).")
            } else {
                format!("Installing the model: step {step} of {of}, {label} ({seconds} s).")
            };
            let what = if *label == FETCH_LABEL {
                "It downloads the Laya base weights (about 800 MB)."
            } else {
                "uv downloads Python packages."
            };
            offer.installing = true;
            offer.note = Some(format!("{progress} {what} This can take several minutes."));
            return offer;
        }
        InstallState::Failed { reason, .. } => {
            offer
                .warnings
                .push((format!("The install failed. {reason}"), Tone::Warning));
        }
        InstallState::Done if status.venv_ready => {
            offer.note = Some(format!(
                "The model is installed in {}.",
                status.laya_dir.display()
            ));
        }
        InstallState::Done | InstallState::Idle => {}
    }
    let problem = status
        .preflight
        .as_ref()
        .err()
        .filter(|problem| matches!(problem, Problem::NoScript | Problem::NoVenv { .. }));
    // Only the download of the weights failed: the server can start and downloads
    // them, and "Install…" tries the download again.
    let weights_retry = problem.is_none()
        && status.venv_ready
        && !status.weights_cached
        && matches!(status.install, InstallState::Failed { .. });
    if !status.settings.start.managed()
        || (problem.is_none() && status.venv_ready && !weights_retry)
    {
        return offer;
    }
    if weights_retry {
        offer.note = Some(
            "The model weights are not in the cache yet. The first start of the model server downloads the weights."
                .to_owned(),
        );
        match &status.uv {
            Some(_) => offer.button = Some("Download the model weights again".to_owned()),
            None => offer.warnings.push((UV_MISSING.to_owned(), Tone::Warning)),
        }
        if let Some(tools) = &status.script_dir {
            let command = format!(
                "cd {} && {}",
                shell_word(&status.laya_dir.to_string_lossy()),
                fetch_command(tools)
            );
            offer.commands = Some(("Copy the download command", command));
        }
        return offer;
    }
    let mut note = String::new();
    match problem {
        Some(Problem::NoScript) => note.push_str(
            "Apassy cannot find the start script tools/basemodel/start.sh. Build the app with scripts/build-app.sh. ",
        ),
        Some(_) => note.push_str("The Laya environment is missing. "),
        None => {}
    }
    if !status.venv_ready {
        match &status.uv {
            Some(uv) => {
                offer.button = Some(format!(
                    "Install the Laya environment in {} with {}. It downloads Python packages and can take several minutes.",
                    status.laya_dir.display(),
                    uv.display()
                ));
            }
            None => offer.warnings.push((UV_MISSING.to_owned(), Tone::Warning)),
        }
        offer.commands = Some(("Copy the install commands", install_commands(status)));
    }
    note.push_str("Until then, every run waits for you.");
    offer.note = Some(note);
    offer
}

/// A row for each LaunchAgent that runs `start.sh` with a missing model, or in a mode
/// where Apassy starts the server itself, with the commands that remove it. Apassy never
/// changes the LaunchAgent.
fn launch_agent_rows(g: &mut rows::Group<'_>, status: &Status) -> Option<ModelAction> {
    let mut action = None;
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
        g.line_note(
            "LaunchAgent",
            None,
            Some(kit::text(text, Font::Callout).color(Tone::Warning.text())),
            |ui| {
                if kit::small_button(ui, "Copy remove commands", Style::Bordered)
                    .on_hover_text("Apassy does not change the LaunchAgent. Paste the commands in Terminal to remove it.")
                    .clicked()
                {
                    action = Some(ModelAction::Copy(agent.remove_commands()));
                }
            },
        );
    }
    action
}

/// Settings > Tools > Command line (ADR 0017): the install, the open sessions with "End
/// all", and a socket that failed.
fn command_line_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let open = app.cli_sessions_open();
    let installed = super::cli_tools::installed();
    let mut end = false;
    let mut install = false;
    let footer = if installed {
        "In Terminal: add ~/.local/bin to PATH, then run eval \"$(apassy login)\"."
    } else {
        "Commands never show a secret value."
    };
    rows::section(ui, Some("Command line"), Some(footer), |g| {
        let place = if installed {
            "~/.local/bin"
        } else {
            "Not installed"
        };
        g.line("apassy", Some(rows::value(place)), |ui| {
            if !installed {
                install = kit::small_button(ui, "Install tools…", Style::Bordered)
                    .on_hover_text(
                        "Install links in ~/.local/bin. Existing commands are not replaced.",
                    )
                    .clicked();
            }
        });
        if open > 0 {
            let sessions = if open == 1 {
                "1 session open".to_owned()
            } else {
                format!("{open} sessions open")
            };
            g.line("Sessions", Some(rows::value(sessions)), |ui| {
                end = kit::small_button(ui, "End all", Style::Bordered)
                    .on_hover_text("End all sessions")
                    .clicked();
            });
        }
        if app.cli.socket_path().is_none()
            && let Some(problem) = app.cli.problem.as_deref()
        {
            g.tone_row(problem, Tone::Critical.text());
        }
    });
    if install {
        match super::cli_tools::install() {
            Ok(()) => app.set_ok(
                "CLI tools are installed in ~/.local/bin. Add it to PATH, then run eval \"$(apassy login)\" in Terminal.",
            ),
            Err(error) => app.set_err(error),
        }
    }
    if end {
        app.end_cli_sessions();
        app.set_ok("Every command-line session ended.");
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
