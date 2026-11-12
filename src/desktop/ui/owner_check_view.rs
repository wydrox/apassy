//! The owner check sheet (goal item A4). It shows the action, runs Touch ID, and takes
//! the passphrase when Touch ID is not available.

use eframe::egui::{self, Key};

use super::kit::{self, Font, Icon, Size, Style, Tone};
use super::{OWNER_CHECK_FIELD, PASSPHRASE_CAPACITY, secure_input};
use crate::broker::approvals::{CheckMethod, OwnerCheck};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{OwnerRequest, page_text};

/// The list of variables scrolls when it is taller than this.
const VARIABLES_HEIGHT: f32 = 200.0;
/// The list of accounts scrolls when it is taller than this.
const ACCOUNTS_HEIGHT: f32 = 220.0;

/// The same exact local question in Decisions and the floating prompt. Neither
/// surface can grant authority without the owner's global verification gate.
pub(super) fn browser_question(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(dialog) = app.owner.check.as_ref() else {
        return;
    };
    if !matches!(dialog.request, OwnerRequest::BrowserDebugging { .. }) {
        return;
    }
    ui.strong("Browser debugging permission");
    ui.label(dialog.request.describe());
    let running = dialog.running.is_some() || app.owner.check_probe.is_some();
    let message = dialog.message.clone();
    let mut allow = false;
    let mut dismiss = false;
    ui.horizontal(|ui| {
        allow = ui
            .add_enabled(!running, egui::Button::new("Allow"))
            .clicked();
        dismiss = ui.button("Dismiss").clicked();
    });
    if running {
        ui.label("Complete the owner check in Apassy.");
    }
    if let Some(message) = message {
        ui.label(message);
    }
    if dismiss {
        app.close_owner_check(Some(ui.ctx()));
    } else if allow {
        app.start_local_owner(
            crate::broker::approvals::LocalWindowSource::BrowserDebuggingClick,
            true,
            ui.ctx(),
        );
    }
}

/// The accounts of a passkey request with more than one account. The owner chooses one
/// before any check starts.
struct AccountChoice {
    rp_id: String,
    /// The origin of the page, or `None` for the macOS passkey sheet.
    origin: Option<String>,
    /// The login name, the user, and when the login was added ("Added …", empty when
    /// unknown) of each account, as the dialog shows them, the newest first.
    rows: Vec<(String, String, String)>,
    /// The index of the account that the owner chose, if they chose one.
    chosen: Option<usize>,
}

impl AccountChoice {
    fn of(request: &OwnerRequest) -> Option<Self> {
        let OwnerRequest::SignPasskey {
            request,
            accounts,
            chosen,
            ..
        } = request
        else {
            return None;
        };
        if accounts.len() < 2 {
            return None;
        }
        let rows = accounts
            .iter()
            .map(|account| {
                let name = page_text(&account.user_name);
                let display = page_text(&account.user_display_name);
                let who = match (name.is_empty(), display.is_empty() || display == name) {
                    (true, true) => String::new(),
                    (false, true) => name,
                    (true, false) => display,
                    (false, false) => format!("{name} ({display})"),
                };
                (
                    page_text(&account.item_name),
                    who,
                    account.added.map(added_text).unwrap_or_default(),
                )
            })
            .collect();
        Some(Self {
            rp_id: request.rp_id.clone(),
            origin: request.origin.clone(),
            rows,
            chosen: (*chosen < accounts.len()).then_some(*chosen),
        })
    }
}

pub(super) fn draw(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(dialog) = app.owner.check.as_ref() else {
        return;
    };
    let action = dialog.request.describe();
    let debugging = matches!(dialog.request, OwnerRequest::BrowserDebugging { .. });
    let copy_item_name = match &dialog.request {
        OwnerRequest::CopyField { item_id, .. } => app
            .owner_ui
            .session
            .details(*item_id)
            .ok()
            .map(|details| page_text(&details.name)),
        _ => None,
    };
    // The item name and the variable of each binding (ADR 0017, D1).
    let variables: Vec<(String, String)> = match &dialog.request {
        OwnerRequest::BindVariables { variables } => variables
            .iter()
            .map(|binding| (binding.item_name.clone(), binding.env_name.clone()))
            .collect(),
        _ => Vec::new(),
    };
    let choice = AccountChoice::of(&dialog.request);
    // A request that is not ready has no account yet: nothing can start.
    let ready = dialog.request.is_ready();
    let running = dialog.running.as_ref().map(|(method, _, _)| *method);
    let message = dialog.message.clone();
    let from_cli = dialog.origin.is_some();
    let from_browser = dialog.browser.is_some();
    let note = app.owner.touch_id_note();
    let has_helper = app.owner.helper.is_some();
    let mut touch_id = false;
    let mut passphrase = false;
    let mut cancel = false;
    let mut picked = None;

    let response = kit::sheet(ctx, "owner-check", 440.0, |ui| {
        ui.horizontal(|ui| {
            kit::icon_tile_sized(ui, Icon::Lock, kit::palette().accent, 32.0);
            ui.add_space(2.0);
            ui.label(kit::text("Confirm that it is you", Font::Title3).color(kit::palette().label));
        });
        ui.add_space(8.0);
        if let Some(name) = &copy_item_name {
            ui.label(kit::text(name, Font::Headline).color(kit::palette().label));
            ui.add_space(4.0);
        }
        kit::paragraph(ui, action, Font::Body, kit::palette().label);
        if !variables.is_empty() {
            ui.add_space(4.0);
            variable_list(ui, &variables);
        }
        if from_cli {
            ui.add_space(4.0);
            kit::tone_note(
                ui,
                crate::desktop::owner_cli::CLI_ORIGIN_NOTE,
                Tone::Warning,
            );
        }
        if from_browser {
            ui.add_space(4.0);
            kit::tone_note(
                ui,
                crate::desktop::browser::BROWSER_ORIGIN_NOTE,
                Tone::Warning,
            );
        }
        if let Some(choice) = &choice {
            ui.add_space(4.0);
            picked = account_list(ui, choice);
        }
        ui.add_space(10.0);
        match running {
            Some(CheckMethod::TouchId) => kit::tone_note(
                ui,
                "Waiting for Touch ID. Touch the sensor, or cancel the macOS prompt.",
                Tone::Warning,
            ),
            Some(CheckMethod::Polkit) => kit::tone_note(
                ui,
                "Waiting for system authentication. You can cancel and use the passphrase.",
                Tone::Warning,
            ),
            Some(CheckMethod::Passphrase) => {
                kit::tone_note(ui, "Apassy is checking the passphrase.", Tone::Accent);
            }
            // The Mac dialog never starts an iPhone check: the phone signs on its own.
            Some(CheckMethod::Companion | CheckMethod::Remote) | None => {}
        }
        if let Some(message) = &message {
            kit::tone_note(ui, message, Tone::Critical);
        }
        if !ready {
            kit::tone_note(ui, "Choose an account to continue.", Tone::Accent);
        }
        ui.add_enabled_ui(running.is_none() && ready, |ui| {
            kit::section(ui, None, note.as_deref(), |s| {
                if let Some(dialog) = app.owner.check.as_mut() {
                    let field = s.field("Passphrase", |ui| {
                        secure_input(
                            ui,
                            OWNER_CHECK_FIELD,
                            &mut dialog.passphrase,
                            PASSPHRASE_CAPACITY,
                            "Required",
                        )
                    });
                    if running.is_none() && !field.has_focus() && !field.lost_focus() {
                        let focused = field.ctx.memory(|memory| memory.focused());
                        if focused.is_none() {
                            field.request_focus();
                        }
                    }
                    if field.lost_focus() && field.ctx.input(|input| input.key_pressed(Key::Enter))
                    {
                        passphrase = true;
                    }
                }
            });
        });
        let idle = running.is_none() && ready;
        kit::sheet_buttons(
            ui,
            |ui| {
                #[cfg(target_os = "linux")]
                if ui
                    .add_enabled_ui(idle, |ui| {
                        kit::button_with(
                            ui,
                            None,
                            "Use system authentication",
                            Style::Link,
                            Size::Regular,
                        )
                    })
                    .inner
                    .clicked()
                {
                    touch_id = true;
                }
                if has_helper
                    && ui
                        .add_enabled_ui(idle, |ui| {
                            kit::button_with(ui, None, "Use Touch ID", Style::Link, Size::Regular)
                        })
                        .inner
                        .clicked()
                {
                    touch_id = true;
                }
            },
            |ui| {
                passphrase |= ui
                    .add_enabled_ui(idle, |ui| {
                        kit::button(
                            ui,
                            if debugging { "Allow" } else { "Confirm" },
                            Style::Prominent,
                        )
                    })
                    .inner
                    .clicked();
                cancel = kit::button(
                    ui,
                    if debugging { "Dismiss" } else { "Cancel" },
                    Style::Bordered,
                )
                .clicked();
            },
        );
    });

    if cancel || (response.escape && running.is_none()) {
        app.close_owner_check(Some(ctx));
        app.set_note("The owner check is cancelled.");
    } else if let Some(index) = picked {
        // The call drops a check that runs for the account before: its proof never signs.
        app.choose_passkey(index);
        if let Some(dialog) = app.owner.check.as_ref() {
            let (source, eligible) = if let Some(ticket) = &dialog.browser {
                (
                    crate::broker::approvals::LocalWindowSource::BrowserGesture,
                    ticket.allows_window(),
                )
            } else {
                (
                    crate::broker::approvals::LocalWindowSource::AutoFill,
                    dialog
                        .platform
                        .as_ref()
                        .is_some_and(crate::desktop::passkey_socket::PlatformTicket::is_live),
                )
            };
            app.start_local_owner(source, eligible, ctx);
        }
    } else if debugging && passphrase && ready {
        let has_passphrase = app
            .owner
            .check
            .as_ref()
            .is_some_and(|d| !d.passphrase.is_empty());
        if has_passphrase {
            app.start_passphrase_check(ctx);
        } else {
            app.start_local_owner(
                crate::broker::approvals::LocalWindowSource::BrowserDebuggingClick,
                true,
                ctx,
            );
        }
    } else if touch_id && ready {
        #[cfg(target_os = "linux")]
        app.start_owner_check(OwnerCheck::Polkit, Some(ctx.clone()));
        #[cfg(not(target_os = "linux"))]
        app.start_owner_check(OwnerCheck::TouchId, Some(ctx.clone()));
    } else if passphrase && ready {
        app.start_passphrase_check(ctx);
    }
}

/// The site, the caller, and one button for each account. Returns the account that the
/// owner clicked. The owner can click again to choose another account.
/// "Added 2026-11-10 14:03:05 UTC": the time of an account in the chooser, to the
/// second, so two passkeys made minutes apart differ.
fn added_text(at: u64) -> String {
    format!("Added {}", crate::vault::format_utc(at))
}

fn account_list(ui: &mut egui::Ui, choice: &AccountChoice) -> Option<usize> {
    let mut picked = None;
    kit::section(ui, None, None, |s| {
        s.labeled(
            "Site",
            kit::text(page_text(&choice.rp_id), Font::Mono).color(kit::palette().label),
        );
        let caller = match &choice.origin {
            Some(origin) => page_text(origin),
            None => crate::passkey_sheet!().to_owned(),
        };
        s.labeled(
            "Asked by",
            kit::text(caller, Font::Body).color(kit::palette().label),
        );
    });
    let count = match choice.rows.len() {
        1 => "1 account".to_owned(),
        count => format!("{count} accounts"),
    };
    ui.label(kit::text(count, Font::Headline).color(kit::palette().label));
    egui::ScrollArea::vertical()
        .id_salt("owner-check-accounts")
        .max_height(ACCOUNTS_HEIGHT)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            kit::section(ui, None, None, |s| {
                for (index, (login, who, added)) in choice.rows.iter().enumerate() {
                    let selected = choice.chosen == Some(index);
                    let name = format!("Use the account {who} of the login {login} {added}");
                    let response = s.clickable_row(&name, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(kit::text(login, Font::Body).color(kit::palette().label));
                                if !who.is_empty() {
                                    ui.label(
                                        kit::text(who, Font::Callout)
                                            .color(kit::palette().secondary),
                                    );
                                }
                                if !added.is_empty() {
                                    ui.label(
                                        kit::text(added, Font::Callout)
                                            .color(kit::palette().secondary),
                                    );
                                }
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if selected {
                                        kit::tag(ui, "Selected", Tone::Accent);
                                    }
                                },
                            );
                        });
                    });
                    if response.clicked() {
                        picked = Some(index);
                    }
                }
            });
        });
    picked
}

/// Each credential and its variable, with the count. A long list scrolls.
fn variable_list(ui: &mut egui::Ui, variables: &[(String, String)]) {
    let count = match variables.len() {
        1 => "1 variable".to_owned(),
        count => format!("{count} variables"),
    };
    ui.label(kit::text(count, Font::Headline).color(kit::palette().label));
    egui::ScrollArea::vertical()
        .id_salt("owner-check-variables")
        .max_height(VARIABLES_HEIGHT)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            kit::section(ui, None, None, |s| {
                for (item, variable) in variables {
                    s.labeled(
                        item,
                        kit::text(variable, Font::Mono).color(kit::palette().label),
                    );
                }
            });
        });
}

#[cfg(test)]
mod tests {
    //! Headless tests of the account choice in the owner check sheet. The requests are
    //! synthetic. No Touch ID helper exists, so only the passphrase starts a check.

    use std::time::{Duration, Instant};

    use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
    use tempfile::TempDir;

    use super::super::draw;
    use super::super::owner_tests::{PASS, finish_check, locked_app};
    use crate::broker::approvals::{CheckMethod, OwnerAction, OwnerCheck};
    use crate::desktop::DesktopApp;
    use crate::desktop::owner_check::{NO_ACCOUNT, OwnerRequest, PasskeyAccount, PasskeyRequest};

    const SIZE: Vec2 = Vec2::new(1180.0, 1600.0);
    const ORIGIN: &str = "https://login.example.test";
    const RP_ID: &str = "example.test";

    /// One window that keeps its egui state between frames.
    struct Window {
        ctx: egui::Context,
        time: f64,
        texts: Vec<(String, Pos2)>,
    }

    impl Window {
        fn new() -> Self {
            Self {
                ctx: egui::Context::default(),
                time: 0.0,
                texts: Vec::new(),
            }
        }

        fn frame(&mut self, app: &mut DesktopApp, events: Vec<Event>) {
            self.time += 0.1;
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            let output = self.ctx.run_ui(input, |ui| draw(app, ui));
            self.texts.clear();
            for clipped in &output.shapes {
                positions(&clipped.shape, &mut self.texts);
            }
            output.drop_without_applying_deltas();
        }

        fn idle(&mut self, app: &mut DesktopApp) {
            for _ in 0..4 {
                self.frame(app, Vec::new());
            }
        }

        fn has(&self, needle: &str) -> bool {
            self.texts.iter().any(|(text, _)| text == needle)
        }

        fn screen(&self) -> String {
            self.texts
                .iter()
                .map(|(text, _)| text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        }

        fn click(&mut self, app: &mut DesktopApp, needle: &str) {
            let at = self
                .texts
                .iter()
                .find(|(text, _)| text == needle)
                .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
                .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.screen()));
            let button = |pressed| Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Modifiers::NONE,
            };
            self.frame(app, vec![Event::PointerMoved(at)]);
            self.frame(app, vec![button(true)]);
            self.frame(app, vec![button(false)]);
            self.idle(app);
        }

        fn press_enter(&mut self, app: &mut DesktopApp) {
            self.frame(
                app,
                vec![Event::Key {
                    key: Key::Enter,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: Modifiers::NONE,
                }],
            );
            self.idle(app);
        }
    }

    fn positions(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
        match shape {
            egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
            egui::Shape::Vec(nested) => nested.iter().for_each(|inner| positions(inner, out)),
            _ => {}
        }
    }

    fn account(login: &str, user: &str, display: &str, id: u8) -> PasskeyAccount {
        PasskeyAccount {
            item_id: u64::from(id),
            item_name: login.to_owned(),
            user_name: user.to_owned(),
            user_display_name: display.to_owned(),
            credential_id: vec![id; 16],
            added: None,
        }
    }

    fn sign(accounts: Vec<PasskeyAccount>, origin: Option<&str>) -> OwnerRequest {
        let chosen = if accounts.len() > 1 { NO_ACCOUNT } else { 0 };
        OwnerRequest::SignPasskey {
            request: PasskeyRequest {
                origin: origin.map(str::to_owned),
                rid: "rid-1".to_owned(),
                rp_id: RP_ID.to_owned(),
                client_data_hash: [7; 32],
            },
            accounts,
            chosen,
            extensions: Default::default(),
        }
    }

    fn two_accounts() -> OwnerRequest {
        sign(
            vec![
                account("Work login", "ada@example.test", "Ada", 1),
                account("Home login", "bob@example.test", "Bob Example", 2),
            ],
            Some(ORIGIN),
        )
    }

    /// An unlocked app with the sheet open for `request` and the passphrase typed.
    fn open(dir: &TempDir, request: OwnerRequest) -> (DesktopApp, Window) {
        let mut app = locked_app(dir, "accounts");
        app.owner_ui.session.unlock(PASS).expect("unlock");
        app.ask_owner(request, None);
        app.owner.check.as_mut().expect("dialog").passphrase = PASS.to_owned();
        let mut window = Window::new();
        window.idle(&mut app);
        (app, window)
    }

    fn running(app: &DesktopApp) -> Option<CheckMethod> {
        app.owner
            .check
            .as_ref()
            .and_then(|dialog| dialog.running.as_ref().map(|(method, _, _)| *method))
    }

    fn chosen(app: &DesktopApp) -> usize {
        match &app.owner.check.as_ref().expect("dialog").request {
            OwnerRequest::SignPasskey { chosen, .. } => *chosen,
            _ => panic!("not a passkey request"),
        }
    }

    fn named_credential(app: &DesktopApp) -> Vec<u8> {
        let action = app.owner.check.as_ref().expect("dialog").request.action();
        match action {
            OwnerAction::SignPasskey { credential_id, .. } => credential_id,
            _ => panic!("not a passkey action"),
        }
    }

    #[test]
    fn several_accounts_show_the_site_the_caller_and_each_account_with_none_chosen() {
        let dir = TempDir::new().unwrap();
        let (app, window) = open(&dir, two_accounts());
        let screen = window.screen();
        for text in [
            "Site",
            RP_ID,
            "Asked by",
            ORIGIN,
            "2 accounts",
            "Work login",
            "ada@example.test (Ada)",
            "Home login",
            "bob@example.test (Bob Example)",
            "Choose an account to continue.",
        ] {
            assert!(window.has(text), "\"{text}\" is missing: {screen}");
        }
        assert!(!window.has("Selected"), "{screen}");
        assert_eq!(chosen(&app), NO_ACCOUNT);
        assert_eq!(running(&app), None);
    }

    /// Two passkeys of one site and one account looked the same, and the older one was
    /// once selected (Linux acceptance, 2026-11-10). The vault lists the newest first,
    /// the browser request selects it, and each row shows when its login was added.
    #[test]
    fn same_account_passkeys_differ_by_their_time_and_the_newest_is_selected() {
        let dir = TempDir::new().unwrap();
        let mut newer = account("localhost", "l4@example.test", "L4 Owner", 2);
        newer.added = Some(1_762_783_385); // 2025-11-10 14:03:05 UTC
        let mut older = account("localhost", "l4@example.test", "L4 Owner", 1);
        older.added = Some(1_762_779_600); // 2025-11-10 13:00:00 UTC
        let mut request = sign(vec![newer, older], Some(ORIGIN));
        if let OwnerRequest::SignPasskey { chosen, .. } = &mut request {
            *chosen = 0;
        }
        let (app, window) = open(&dir, request);
        let screen = window.screen();
        for text in [
            "2 accounts",
            "Added 2025-11-10 14:03:05 UTC",
            "Added 2025-11-10 13:00:00 UTC",
            "Selected",
        ] {
            assert!(window.has(text), "\"{text}\" is missing: {screen}");
        }
        assert!(!window.has("Choose an account to continue."), "{screen}");
        assert_eq!(chosen(&app), 0);
        assert_eq!(named_credential(&app), vec![2; 16], "the newest is named");
        // The selected tag is on the row of the newest passkey: above the older one.
        let y = |text: &str| {
            window
                .texts
                .iter()
                .find(|(painted, _)| painted == text)
                .map(|(_, pos)| pos.y)
                .unwrap()
        };
        let (newest, oldest) = (
            y("Added 2025-11-10 14:03:05 UTC"),
            y("Added 2025-11-10 13:00:00 UTC"),
        );
        assert!(newest < oldest, "the newest row comes first");
        assert!((y("Selected") - newest).abs() < (y("Selected") - oldest).abs());
    }

    #[test]
    fn the_macos_sheet_is_named_as_the_caller() {
        let dir = TempDir::new().unwrap();
        let request = sign(
            vec![
                account("Work login", "ada@example.test", "", 1),
                account("Home login", "bob@example.test", "", 2),
            ],
            None,
        );
        let (_app, window) = open(&dir, request);
        assert!(window.has(crate::passkey_sheet!()), "{}", window.screen());
        // A display name that is empty adds nothing to the user name.
        assert!(window.has("ada@example.test"), "{}", window.screen());
    }

    #[test]
    fn confirm_does_nothing_until_an_account_is_chosen() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut window) = open(&dir, two_accounts());
        window.click(&mut app, "Confirm");
        assert_eq!(running(&app), None, "a disabled Confirm started a check");
        window.press_enter(&mut app);
        assert_eq!(running(&app), None, "Enter started a check");
        // The controller refuses too, whatever the view does.
        app.start_owner_check(OwnerCheck::TouchId, None);
        app.start_passphrase_check(&window.ctx);
        let dialog = app.owner.check.as_ref().expect("the dialog stays open");
        assert!(dialog.running.is_none());
        assert!(
            dialog
                .message
                .as_deref()
                .is_some_and(|text| text.contains("Choose an account"))
        );
        assert_eq!(chosen(&app), NO_ACCOUNT);
    }

    #[test]
    fn the_first_account_can_be_chosen_and_confirmed() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut window) = open(&dir, two_accounts());
        window.click(&mut app, "Work login");
        assert_eq!(chosen(&app), 0);
        assert_eq!(named_credential(&app), vec![1; 16]);
        assert!(window.has("Selected"), "{}", window.screen());
        assert!(!window.has("Choose an account to continue."));
        window.click(&mut app, "Confirm");
        // The check can finish during the idle frames of the click. Require
        // either an in-flight passphrase check or its completed dialog.
        assert!(running(&app) == Some(CheckMethod::Passphrase) || app.owner.check.is_none());
        finish_check(&mut app, &window.ctx);
        // No request waits for the signature, so nothing is signed and the sheet is gone.
        assert!(app.owner.check.is_none());
    }

    #[test]
    fn the_second_account_is_the_one_the_proof_names() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut window) = open(&dir, two_accounts());
        window.click(&mut app, "Home login");
        assert_eq!(chosen(&app), 1);
        assert_eq!(named_credential(&app), vec![2; 16]);
        let selected: Vec<_> = window
            .texts
            .iter()
            .filter(|(text, _)| text == "Selected")
            .collect();
        assert_eq!(selected.len(), 1, "{}", window.screen());
        let home = window
            .texts
            .iter()
            .find(|(text, _)| text == "Home login")
            .unwrap();
        assert!(
            (selected[0].1.y - home.1.y).abs() < 30.0,
            "the tag is not in the row of the chosen account: {}",
            window.screen()
        );
    }

    #[test]
    fn choosing_another_account_drops_the_running_check() {
        let dir = TempDir::new().unwrap();
        let (mut app, mut window) = open(&dir, two_accounts());
        window.click(&mut app, "Work login");
        // Keep the old check in flight until after the click. A real passphrase
        // derivation can finish between UI frames and makes this test race.
        let cancel = crate::native::AuthCancel::new();
        let (release, waiting) = std::sync::mpsc::channel();
        app.owner.check.as_mut().unwrap().running = Some((
            CheckMethod::Passphrase,
            crate::desktop::owner_check::Task::spawn(None, move || {
                let _ = waiting.recv_timeout(Duration::from_secs(5));
                Err(crate::broker::approvals::OwnerAuthError::Cancelled)
            }),
            cancel.cancel_on_drop(),
        ));
        assert_eq!(running(&app), Some(CheckMethod::Passphrase));
        window.click(&mut app, "Home login");
        assert!(
            cancel.is_cancelled(),
            "the old native check was not cancelled"
        );
        release.send(()).unwrap();
        assert_eq!(chosen(&app), 1);
        assert_eq!(
            running(&app),
            None,
            "the check for the first account stayed"
        );
        // The dropped check never finishes the request: the sheet stays open.
        let until = Instant::now() + Duration::from_millis(600);
        while Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
            app.poll_owner_flows(&window.ctx);
        }
        assert!(
            app.owner.check.is_some(),
            "the old proof finished the request"
        );
        assert_eq!(running(&app), None);
        assert_eq!(named_credential(&app), vec![2; 16]);
    }

    #[test]
    fn one_account_keeps_the_sheet_without_a_list() {
        let dir = TempDir::new().unwrap();
        let request = sign(
            vec![account("Work login", "ada@example.test", "Ada", 1)],
            Some(ORIGIN),
        );
        assert!(request.is_ready());
        assert!(request.starts_touch_id());
        let (mut app, mut window) = open(&dir, request);
        assert!(!window.has("Asked by"), "{}", window.screen());
        assert!(!window.has("Choose an account to continue."));
        assert_eq!(chosen(&app), 0);
        window.click(&mut app, "Confirm");
        assert!(running(&app) == Some(CheckMethod::Passphrase) || app.owner.check.is_none());
        finish_check(&mut app, &window.ctx);
        assert!(app.owner.check.is_none());
    }
}
