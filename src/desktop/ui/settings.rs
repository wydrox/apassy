//! Settings in five tabs: General (vaults, sync, import), Security (passphrase,
//! backup), Agents (token lifetime, broker, command line), Notifications (macOS, the
//! iPhone companion), and About (updates in `updates.rs`, shortcuts). Each change that
//! is rare or risky opens a sheet.

use std::path::PathBuf;

use eframe::egui;

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
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::Ephemeral;
use crate::desktop::unlock::UnlockMethod;
use crate::desktop::{BrokerState, DesktopApp, OwnerView};
use crate::vault::DEFAULT_TOKEN_LIFETIME_DAYS;

/// The tab of the Settings view. Each tab shows a few related sections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) enum SettingsTab {
    /// Vaults, sync, and import.
    #[default]
    General,
    /// The passphrase, the unlock method, and backups.
    Security,
    /// The token lifetime, the broker, and the command line.
    Agents,
    /// macOS notifications and the iPhone companion.
    Notifications,
    /// Updates, keyboard shortcuts, and the contract version.
    About,
}

const TABS: [(SettingsTab, &str); 5] = [
    (SettingsTab::General, "General"),
    (SettingsTab::Security, "Security"),
    (SettingsTab::Agents, "Agents"),
    (SettingsTab::Notifications, "Notifications"),
    (SettingsTab::About, "About"),
];

/// Show Settings with the given tab.
pub(crate) fn open(app: &mut DesktopApp, tab: SettingsTab) {
    app.view = OwnerView::Settings;
    app.ui.settings_tab = tab;
}

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    kit::page_header(ui, "Settings", None, |_| {});
    let mut tab = app.ui.settings_tab;
    let picker = kit::segmented(ui, "settings-tab", &mut tab, &TABS);
    ui.ctx()
        .accesskit_node_builder(picker.id, |node| node.set_label("Settings section"));
    app.ui.settings_tab = tab;
    ui.add_space(18.0);
    // Each tab has its own IDs, so the focus of one tab never moves to another.
    ui.push_id(tab, |ui| match tab {
        SettingsTab::General => {
            super::vaults::settings_section(app, ui);
            super::import::section(app, ui);
        }
        SettingsTab::Security => {
            security_section(app, ui);
            backup_section(app, ui);
        }
        SettingsTab::Agents => {
            agents_section(app, ui);
            broker_section(app, ui);
            command_line_section(app, ui);
        }
        SettingsTab::Notifications => {
            notifications_section(app, ui);
            super::companion::draw(app, ui);
        }
        SettingsTab::About => {
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
            // Return in the field saves, as the button does.
            save = kit::small_button(ui, "Save", Style::Bordered).clicked()
                || (field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)));
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
            // The actions sit at the trailing edge, as "Check now" in Settings > About.
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
                ("⌘1 ⌘2 ⌘3 ⌘4", "Credentials, Agents, Activity, Learning"),
                ("⌘,", "Settings"),
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

fn broker_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let server = app.model_server.clone();
    let status = server.as_ref().map(|server| server.status());
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
            "The apassy command talks to this window. apassy login asks you here first. Commands never show a secret value, and grants, approvals, and new tokens ask you here each time.",
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
