//! Settings in four tabs (ADR 0026 §3), as in the mockup: General (the vaults, import,
//! and the browser extension), Devices (each device that gets the questions, ADR 0025
//! §3e: this Mac, the other Macs through sync, the iPhones, and the relay; then sync and
//! the iPhone app), Security (Touch ID, the passphrase, owner checks, and backup), and
//! Advanced (the bouncer with calibration and learning, the command line, updates, and
//! the keyboard shortcuts).
//!
//! Each tab is a list of groups of rows ([`rows`]): the label on the left, the value or
//! the control on the right, and a short footnote only where it helps. Each change that
//! is rare or risky opens a sheet.
//!
//! Settings of single agents are gone (ADR 0025 §3f): the agent screen shows, it does
//! not configure.

use std::path::PathBuf;

use eframe::egui::{self, Color32, Pos2, Rect, Sense, Shape, Stroke, Vec2, WidgetInfo, WidgetType};

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

#[path = "settings_rows.rs"]
pub(super) mod rows;

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
/// Settings" when macOS notifications are off). Its rows are in Devices now. Remove
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
/// The width of the four tabs.
const TAB_BAR_WIDTH: f32 = 4.0 * TAB_SIZE.x + 3.0 * TAB_GAP;

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
        painter.rect_filled(rect, 7, Color32::from_black_alpha(20));
    } else if response.hovered() {
        painter.rect_filled(rect, 7, Color32::from_black_alpha(10));
    }
    let color = if selected {
        kit::ACCENT
    } else {
        kit::SECONDARY
    };
    let icon = Rect::from_center_size(
        Pos2::new(rect.center().x, rect.top() + 16.0),
        Vec2::splat(22.0),
    );
    paint_tab_icon(painter, icon, tab, color);
    let label = kit::galley(ui, kit::text(tab.label(), Font::Footnote));
    painter.galley(
        Pos2::new(rect.center().x - label.size().x / 2.0, icon.bottom() + 2.0),
        label,
        color,
    );
    if response.has_focus() {
        kit::focus_ring(painter, rect, 7);
    }
    response
}

/// The icon of a tab, as the line icons of the mockup on a 24-point grid: a gear, a
/// laptop, a lock, and two sliders.
fn paint_tab_icon(painter: &egui::Painter, rect: Rect, tab: SettingsTab, color: Color32) {
    let unit = rect.width() / 24.0;
    let p = |x: f32, y: f32| rect.min + Vec2::new(x, y) * unit;
    let stroke = Stroke::new(1.7 * unit, color);
    match tab {
        SettingsTab::General => {
            // Six teeth around the center, and the hole.
            let center = p(12.0, 12.0);
            let mut outline = Vec::new();
            for tooth in 0..6 {
                let base = (tooth as f32 * 60.0 - 90.0).to_radians();
                for (offset, radius) in [(-26.0, 7.4), (-13.0, 10.0), (13.0, 10.0), (26.0, 7.4)] {
                    let angle = base + f32::to_radians(offset);
                    outline.push(center + Vec2::angled(angle) * radius * unit);
                }
            }
            painter.add(Shape::closed_line(outline, stroke));
            painter.circle_stroke(center, 3.0 * unit, stroke);
        }
        SettingsTab::Devices => {
            painter.rect_stroke(
                Rect::from_min_max(p(5.0, 5.0), p(19.0, 15.0)),
                1.5 * unit,
                stroke,
                egui::StrokeKind::Middle,
            );
            painter.line_segment([p(3.0, 18.5), p(21.0, 18.5)], stroke);
        }
        SettingsTab::Security => {
            painter.rect_stroke(
                Rect::from_min_max(p(5.5, 10.5), p(18.5, 20.5)),
                2.0 * unit,
                stroke,
                egui::StrokeKind::Middle,
            );
            let mut shackle = vec![p(8.5, 10.5)];
            for step in 0..=12 {
                let angle = std::f32::consts::PI * (1.0 + step as f32 / 12.0);
                shackle.push(p(12.0, 7.5) + Vec2::angled(angle) * 3.5 * unit);
            }
            shackle.push(p(15.5, 10.5));
            painter.add(Shape::line(shackle, stroke));
        }
        SettingsTab::Advanced => {
            for (from, to) in [
                ((5.0, 7.0), (14.0, 7.0)),
                ((18.0, 7.0), (19.0, 7.0)),
                ((5.0, 17.0), (8.0, 17.0)),
                ((12.0, 17.0), (19.0, 17.0)),
            ] {
                painter.line_segment([p(from.0, from.1), p(to.0, to.1)], stroke);
            }
            painter.circle_stroke(p(16.0, 7.0), 2.0 * unit, stroke);
            painter.circle_stroke(p(10.0, 17.0), 2.0 * unit, stroke);
        }
    }
}

/// The groups of the selected tab. The tab bar is above them, in the window.
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
            super::companion::draw(app, ui);
        }
        SettingsTab::Security => {
            security_section(app, ui);
            backup_section(app, ui);
        }
        SettingsTab::Advanced => {
            broker_section(app, ui);
            command_line_section(app, ui);
            super::updates::section(app, ui);
            about_section(ui);
        }
    });
    // Room for the shadow of the last group.
    ui.add_space(2.0);
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
pub(super) const RELAY_ROW: &str = "Relay";
pub(super) const RELAY_QUESTIONS_ON: &str = "Questions also go to your other devices of this vault. The relay sees no command and no credential.";
pub(super) const RELAY_QUESTIONS_OFF: &str =
    "Off. Turn it on to answer on your other devices away from this network.";
pub(super) const RELAY_QUESTIONS_NEW_TEAM: &str = "Off. Turning it on makes a relay team for the questions only, with a team code from the operator.";
pub(super) const RELAY_QUESTIONS_LOCKED: &str = "Unlock the vault to change it.";
pub(super) const RELAY_QUESTIONS_JOIN: &str = "Off. Turning it on joins the questions team of this vault, with a link from a Mac that has it on.";
pub(super) const RELAY_QUESTIONS_REMOVED: &str =
    "Off. This Mac was removed. Turning it on again needs a link from a Mac that has it on.";
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

/// What the owner chose for the macOS notifications of this Mac.
enum NotifyAction {
    Allow,
    OpenSettings,
    Check,
}

/// Settings > Devices: each device that gets the questions of the bouncer (ADR 0025
/// §3e), the relay, and "Add device…". This Mac shows its macOS notifications. The sync
/// of the vaults and the iPhone app follow, each in its own group.
fn devices_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let others = super::sync::other_macs(app);
    let iphones = app
        .owner_ui
        .session
        .companion_devices()
        .map_or(0, |devices| devices.len());
    let mac_name = app.companion.mac_name().map(str::to_owned);
    let notifications = app.owner.notifications.as_ref().map(|center| center.view());
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
    let mut notify_action = None;
    rows::group(ui, Some("Questions go to every device"), |g| {
        // This Mac, with its macOS notifications (goal items N1 to N4).
        let (label, prefix) = match &mac_name {
            Some(name) => (name.clone(), "This Mac · "),
            None => ("This Mac".to_owned(), ""),
        };
        g.row(|ui| {
            let Some(view) = &notifications else {
                rows::one_line(
                    ui,
                    rows::label_text(&label).into(),
                    Some(rows::value(format!("{prefix}Notifications not running"))),
                    |_| {},
                );
                ui.add(
                    egui::Label::new(rows::note(
                        "They start with the Apassy window and the broker. Questions still wait in Decisions.",
                    ))
                    .wrap(),
                );
                return;
            };
            let channel = &view.channel;
            let words = if channel.can_deliver() {
                "Notifications on"
            } else if channel.needs_permission() {
                "Notifications not allowed yet"
            } else {
                "Notifications off"
            };
            rows::one_line(
                ui,
                rows::label_text(&label).into(),
                Some(rows::value(format!("{prefix}{words}"))),
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
            let failed = view
                .deliveries
                .values()
                .filter(|delivery| matches!(delivery, Delivery::Failed(_)))
                .count();
            if failed > 0 {
                ui.add(
                    egui::Label::new(
                        kit::text(
                            format!("{failed} notification(s) failed. Questions still wait in Decisions."),
                            Font::Callout,
                        )
                        .color(Tone::Critical.text()),
                    )
                    .wrap(),
                );
            }
        });
        g.line("Other Macs", Some(rows::value(&others.words)), |ui| {
            if others.relay.is_some()
                && kit::small_button(ui, "Devices…", Style::Bordered).clicked()
            {
                list = others.relay.clone();
            }
        });
        let phones = match iphones {
            0 => "None paired".to_owned(),
            1 => "1 paired".to_owned(),
            count => format!("{count} paired"),
        };
        g.line("iPhones", Some(rows::value(phones)), |_| {});
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
        // The devices that get the questions through the relay, "Remove…" for each
        // other device, and a new device.
        for device in &relay_devices {
            g.line_note(
                device.name.as_str(),
                None,
                Some(rows::note(&device.words)),
                |ui| {
                    if device.removable
                        && kit::small_button(ui, REMOVE_DEVICE, Style::Destructive).clicked()
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
    });
    let mut add_mac = false;
    let mut add_iphone = false;
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        let add = kit::button(ui, "Add device…", Style::Bordered);
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
    let ctx = ui.ctx().clone();
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

/// "Add device…" > "iPhone…": the iPhone listener goes on, and the pairing code of
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

/// Settings > Security > Unlock: Touch ID, the passphrase, and the owner checks.
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
        // Touch ID for owner checks, with the reason when it is not available.
        let note = app.owner.touch_id_note();
        g.line("Owner checks", None, |ui| {
            let words = if note.is_some() {
                "Passphrase"
            } else {
                "Touch ID"
            };
            let value = ui.label(rows::value(words));
            if let Some(note) = &note {
                value.on_hover_text(format!("Touch ID for owner checks: {note}"));
            }
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
/// first asks for the passphrase in a row below; "Off" acts at once.
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
    let note = if busy {
        Some(rows::note(
            "Apassy is reading or changing the Touch ID unlock setting.",
        ))
    } else {
        setting
            .as_ref()
            .and_then(|setting| setting.note.as_deref())
            .map(|note| kit::text(note, Font::Callout).color(Tone::Warning.text()))
    };
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

/// Settings > Security > Backup.
fn backup_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut open = None;
    rows::section(
        ui,
        Some("Backup"),
        Some(
            "The vault locks after a backup. Keep backups in a safe place, for example on an external disk.",
        ),
        |g| {
            g.line(
                "Backup",
                Some(rows::value("Encrypted copy of the vault")),
                |ui| {
                    if kit::small_button(ui, "Back up now…", Style::Bordered)
                        .on_hover_text("The vault locks after the backup.")
                        .clicked()
                    {
                        open = Some(Sheet::Backup);
                    }
                },
            );
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
const SHORTCUTS: [(&str, &str); 16] = [
    ("⌘1 ⌘2 ⌘3", "All credentials, Decisions, Agents"),
    ("⌘,", "Settings"),
    ("⌘W, Esc", "Close Settings"),
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

/// Settings > Advanced > About: the keyboard shortcuts behind "Show", and the contract.
fn about_section(ui: &mut egui::Ui) {
    let (id, open) = shows_more(ui, "shortcuts");
    rows::group(ui, Some("About"), |g| {
        g.line("Keyboard shortcuts", None, |ui| {
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
        g.line(
            "Contract",
            Some(rows::value(crate::contracts::CONTRACT_VERSION.to_string())),
            |_| {},
        );
    });
}

/// "Asked you": how often a run waited for the owner in the last 7 days.
fn asked_words(asked: u32) -> String {
    match asked {
        0 => "Not this week".to_owned(),
        1 => "1 time this week".to_owned(),
        count => format!("{count} times this week"),
    }
}

/// Settings > Advanced > Bouncer: the model server (ADR 0024) in one row with its state
/// and its action, how it starts, how often the bouncer asked you this week, the broker,
/// and calibration and learning behind "Show".
fn broker_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let server = app.model_server.clone();
    let status = server.as_ref().map(|server| server.status());
    let asked = crate::desktop::learning_ui::asked_this_week(app);
    let (learning_id, learning_open) = shows_more(ui, "learning");
    let mut action = None;
    rows::group(ui, Some("Bouncer"), |g| {
        if let Some(status) = &status {
            action = model_server_rows(g, status);
        }
        if let Some(asked) = asked {
            g.line("Asked you", Some(rows::value(asked_words(asked))), |_| {});
        }
        broker_rows(app, g);
        g.line("Calibration and learning", None, |ui| {
            show_more_button(ui, learning_id, learning_open, "calibration and learning");
        });
    });
    if learning_open {
        ui.add_space(12.0);
        crate::desktop::learning_ui::settings_panel(app, ui);
    }
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

/// The broker: whether it accepts agent requests, the bouncer address, and the socket
/// on hover.
fn broker_rows(app: &DesktopApp, g: &mut rows::Group<'_>) {
    match &app.broker {
        BrokerState::Running(handle) => {
            let socket = handle.socket_path().display().to_string();
            g.line("Broker", None, |ui| {
                ui.label(
                    kit::text("Accepts agent requests", Font::Body).color(Tone::Good.text()),
                )
                .on_hover_text(format!(
                    "Socket: {socket}\nA locked vault refuses all agent requests. Destinations use https://, or http:// on this computer only. The broker does not follow redirects."
                ));
            });
            match handle.bouncer_url() {
                Some(url) => g.line("Address", Some(rows::value(url)), |_| {}),
                None => g.line(
                    "Address",
                    Some(
                        kit::text("Not set. Every run waits for you.", Font::Body)
                            .color(Tone::Warning.text()),
                    ),
                    |_| {},
                ),
            }
        }
        BrokerState::Failed(message) => g.line_note(
            "Broker",
            None,
            Some(kit::text(message, Font::Callout).color(Tone::Critical.text())),
            |_| {},
        ),
        BrokerState::NotStarted => g.line(
            "Broker",
            Some(rows::value("Starts with the desktop window")),
            |_| {},
        ),
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

/// Settings > Advanced > Command line (ADR 0017).
fn command_line_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let open = app.cli_sessions_open();
    let installed = super::cli_tools::installed();
    let mut end = false;
    let mut install = false;
    rows::section(
        ui,
        Some("Command line"),
        Some(
            "Then add ~/.local/bin to PATH in ~/.zshrc, and run eval \"$(apassy login)\" and apassy doctor in Terminal. Commands never show a secret value.",
        ),
        |g| {
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
            match (app.cli.socket_path(), app.cli.problem.as_deref()) {
                // The name of the socket; its whole path on hover.
                (Some(path), _) => g.line("Socket", None, |ui| {
                    let name = path.file_name().map_or_else(
                        || path.display().to_string(),
                        |name| name.to_string_lossy().into_owned(),
                    );
                    ui.label(rows::value(name))
                        .on_hover_text(path.display().to_string());
                }),
                (None, Some(problem)) => g.line_note(
                    "Socket",
                    None,
                    Some(kit::text(problem, Font::Callout).color(Tone::Critical.text())),
                    |_| {},
                ),
                (None, None) => g.line(
                    "Socket",
                    Some(rows::value("Starts with the desktop window")),
                    |_| {},
                ),
            }
            let sessions = match open {
                0 => "None open".to_owned(),
                1 => "1 open".to_owned(),
                count => format!("{count} open"),
            };
            g.line("Sessions", Some(rows::value(sessions)), |ui| {
                if open > 0 {
                    end = kit::small_button(ui, "End all", Style::Bordered)
                        .on_hover_text("End all sessions")
                        .clicked();
                }
            });
        },
    );
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
