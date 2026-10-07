//! "Get started": the steps from a new vault to the first agent request, on the
//! Credentials page. Each step reads its state from the vault, so the list follows
//! the owner and hides itself when every step is done. A vault from another Mac has
//! its own panel (`agents::next_steps_panel`), so this list waits until that closes.

use eframe::egui;

use super::Sheet;
use super::kit::{self, Font, Icon, Style, Tone};
use crate::desktop::{DesktopApp, OwnerView};

/// The key of "Hide" for a vault that has no list ID. This lasts for the session only.
const HIDDEN: &str = "get-started-hidden";

/// Did the owner hide the list of the open vault? `ui.json` keeps "Hide" per vault list
/// ID, so it does not hide the list of another vault.
fn is_hidden(app: &DesktopApp) -> bool {
    match app.vault_list.current.as_deref() {
        Some(id) => app.ui.get_started_hidden.contains(id),
        None => app.ui.is_expanded(HIDDEN),
    }
}

/// Hide the list of the open vault, and keep the choice.
fn hide(app: &mut DesktopApp) {
    match app.vault_list.current.clone() {
        Some(id) => {
            app.ui.get_started_hidden.insert(id);
            app.ui.save_prefs();
        }
        None => app.ui.set_expanded(HIDDEN, true),
    }
}

/// The hover text of "Hide". It says how long the choice lasts.
fn hide_hint(app: &DesktopApp) -> &'static str {
    match app.vault_list.current {
        Some(_) => "Hide these steps for this vault.",
        None => "Hide these steps until Apassy starts again.",
    }
}

/// What the vault already has, step by step.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Progress {
    pub credential: bool,
    pub variable: bool,
    pub agent: bool,
    pub grant: bool,
    pub request: bool,
}

impl Progress {
    fn read(app: &DesktopApp) -> Self {
        let session = &app.owner_ui.session;
        let agents: Vec<_> = session
            .agents()
            .unwrap_or_default()
            .into_iter()
            .filter(|agent| !agent.revoked)
            .collect();
        Self {
            credential: session.search("").is_ok_and(|items| !items.is_empty()),
            variable: session
                .env_bound_items()
                .is_ok_and(|items| !items.is_empty()),
            agent: !agents.is_empty(),
            grant: agents.iter().any(|agent| {
                session
                    .exec_grants(agent.id)
                    .is_ok_and(|grants| !grants.is_empty())
            }),
            // A request of an active agent. After a restore, the log still has the
            // requests of the revoked agents; they do not count.
            request: agents.iter().any(|agent| {
                session
                    .agent_activity(agent.id, 1)
                    .is_ok_and(|rows| !rows.is_empty())
            }),
        }
    }

    fn steps(self) -> [bool; 5] {
        [
            self.credential,
            self.variable,
            self.agent,
            self.grant,
            self.request,
        ]
    }

    pub(super) fn done(self) -> usize {
        self.steps().into_iter().filter(|done| *done).count()
    }

    pub(super) fn complete(self) -> bool {
        self.done() == self.steps().len()
    }
}

/// An action of a step.
enum Go {
    AddCredential,
    OpenCredential,
    RegisterAgent,
    OpenAgent,
    ShowConnect,
    Hide,
}

/// Draw the list when the vault needs it. Returns true when it showed: the page then
/// leaves out its own empty state, so "Add a credential" is the one main action.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) -> bool {
    if app.owner_ui.session.is_locked() || app.ui.setup_vault.is_some() || is_hidden(app) {
        return false;
    }
    let progress = Progress::read(app);
    if progress.complete() {
        return false;
    }
    let mut go = None;
    let hint = hide_hint(app);
    let header = format!("Get started · {} of 5", progress.done());
    kit::section(
        ui,
        Some(&header),
        Some(
            "Agents never receive a value. They ask Apassy to run a command with it, and Apassy decides or asks you.",
        ),
        |s| {
            let rows: [(bool, &str, &str, &str, Go); 5] = [
                (
                    progress.credential,
                    "Add a credential",
                    "An API key, a login, an SSH key, or a database password.",
                    "Add…",
                    Go::AddCredential,
                ),
                (
                    progress.variable,
                    "Let agents use it",
                    "Under Agent access, set its environment variable and its declaration.",
                    "Open",
                    Go::OpenCredential,
                ),
                (
                    progress.agent,
                    "Register your agent",
                    "Claude Code, Codex, or another host gets its own token.",
                    "Register…",
                    Go::RegisterAgent,
                ),
                (
                    progress.grant,
                    "Give the agent access",
                    "Choose the credentials that it can use, and the project folder.",
                    "Open",
                    Go::OpenAgent,
                ),
                (
                    progress.request,
                    "Connect the host and try a request",
                    "Add Apassy to the MCP servers of the host. The first request shows in Activity.",
                    "Show steps",
                    Go::ShowConnect,
                ),
            ];
            // Only the first open step has a button: one next action at a time.
            let next = rows.iter().position(|(done, ..)| !done);
            for (index, (done, title, note, action, target)) in rows.into_iter().enumerate() {
                s.row(|ui| {
                    egui::Sides::new().shrink_left().show(
                        ui,
                        |ui| {
                            step_mark(ui, done);
                            if done {
                                // Alone, the title stays centered with the mark.
                                ui.label(kit::text(title, Font::Body).color(kit::SECONDARY));
                            } else {
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 2.0;
                                    ui.label(kit::text(title, Font::Body).color(kit::LABEL));
                                    kit::note(ui, note);
                                });
                            }
                        },
                        |ui| {
                            if Some(index) == next {
                                let style = if index == 0 {
                                    Style::Prominent
                                } else {
                                    Style::Bordered
                                };
                                if kit::small_button(ui, action, style).clicked() {
                                    go = Some(target);
                                }
                            }
                        },
                    );
                });
            }
            s.row(|ui| {
                // `Sides` keeps the row one control high in the page scroll area.
                egui::Sides::new().show(
                    ui,
                    |_| {},
                    |ui| {
                        if kit::small_button(ui, "Hide", Style::Link)
                            .on_hover_text(hint)
                            .clicked()
                        {
                            go = Some(Go::Hide);
                        }
                    },
                );
            });
        },
    );
    if let Some(go) = go {
        act(app, go);
    }
    true
}

/// A green check for a done step, an empty circle for an open one. Not a chevron: the
/// row itself does not open anything.
fn step_mark(ui: &mut egui::Ui, done: bool) {
    let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(16.0), egui::Sense::hover());
    if done {
        kit::paint_icon(ui.painter(), rect, Icon::Check, Tone::Good.mark());
    } else {
        ui.painter()
            .circle_stroke(rect.center(), 6.5, egui::Stroke::new(1.3, kit::TERTIARY));
    }
}

fn act(app: &mut DesktopApp, go: Go) {
    let session = &app.owner_ui.session;
    match go {
        Go::AddCredential => super::items::open_add(app),
        Go::OpenCredential => {
            // The first credential without a variable: that is where the step happens.
            let bound: Vec<u64> = session
                .env_bound_items()
                .unwrap_or_default()
                .into_iter()
                .map(|(id, ..)| id)
                .collect();
            let first = session
                .search("")
                .unwrap_or_default()
                .into_iter()
                .find(|item| !bound.contains(&item.id));
            if let Some(item) = first {
                app.select_item(item.id.to_string());
                app.view = OwnerView::Item;
            }
        }
        Go::RegisterAgent => {
            app.view = OwnerView::Agents;
            app.owner_ui.selected_agent = None;
            app.ui.sheet = Some(Sheet::RegisterAgent);
        }
        Go::OpenAgent | Go::ShowConnect => {
            let agent = session
                .agents()
                .unwrap_or_default()
                .into_iter()
                .find(|agent| !agent.revoked);
            if let Some(agent) = agent {
                app.view = OwnerView::Agents;
                app.owner_ui.selected_agent = Some(agent.id);
                if matches!(go, Go::ShowConnect) {
                    app.ui.set_expanded("agent-setup", true);
                }
            }
        }
        Go::Hide => hide(app),
    }
}

#[cfg(test)]
mod tests {
    use eframe::egui;
    use tempfile::TempDir;

    use super::super::owner_tests::{PASS, app_frame, locked_app, unlocked_app_with_item};
    use super::Progress;
    use crate::desktop::OwnerView;

    #[test]
    fn the_steps_follow_the_vault_and_offer_one_next_action() {
        let dir = TempDir::new().expect("temp dir");
        let (mut app, _) = unlocked_app_with_item(&dir);
        app.view = OwnerView::Vault;
        let ctx = egui::Context::default();
        let text = app_frame(&ctx, &mut app);
        assert!(text.contains("Get started · 1 of 5"), "{text}");
        // The next open step has the button; the later ones do not.
        assert!(text.contains("Let agents use it"), "{text}");
        assert!(text.contains("Open"), "{text}");
        assert!(!text.contains("Register…"), "{text}");
        // The list does not hide the credentials.
        assert!(text.contains("Guarded key"), "{text}");

        app.owner_ui
            .session
            .register_agent("Step agent")
            .expect("register");
        let progress = Progress::read(&app);
        assert!(progress.credential && progress.agent);
        assert!(!progress.variable && !progress.grant && !progress.request);
        assert_eq!(progress.done(), 2);

        // "Hide" hides the list. This vault has no list ID, so only for the session.
        assert_eq!(
            super::hide_hint(&app),
            "Hide these steps until Apassy starts again."
        );
        app.ui.set_expanded(super::HIDDEN, true);
        let text = app_frame(&ctx, &mut app);
        assert!(!text.contains("Get started"), "{text}");
    }

    #[test]
    fn a_vault_without_credentials_shows_the_steps_instead_of_the_empty_state() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = locked_app(&dir, "empty.db");
        app.owner_ui.session.unlock(PASS).expect("unlock");
        app.view = OwnerView::Vault;
        let ctx = egui::Context::default();
        let text = app_frame(&ctx, &mut app);
        assert!(text.contains("Get started · 0 of 5"), "{text}");
        assert!(text.contains("Add…"), "{text}");
        assert!(!text.contains("No credentials yet"), "{text}");
    }

    #[test]
    fn hide_applies_to_one_vault_and_survives_a_restart() {
        let dir = TempDir::new().expect("temp dir");
        let data = TempDir::new().expect("temp dir");
        let (mut app, _) = unlocked_app_with_item(&dir);
        app.view = OwnerView::Vault;
        app.ui.load_prefs(data.path().to_path_buf());
        app.vault_list.current = Some("vault-a".to_owned());
        let ctx = egui::Context::default();
        assert!(app_frame(&ctx, &mut app).contains("Get started"));
        // The hover text says the choice stays, not that it ends at the next start.
        assert_eq!(super::hide_hint(&app), "Hide these steps for this vault.");

        super::hide(&mut app);
        assert!(!app_frame(&ctx, &mut app).contains("Get started"));
        // Another vault keeps its list.
        app.vault_list.current = Some("vault-b".to_owned());
        assert!(app_frame(&ctx, &mut app).contains("Get started"));
        app.vault_list.current = Some("vault-a".to_owned());
        assert!(!app_frame(&ctx, &mut app).contains("Get started"));

        // A new app reads the file: vault-a stays hidden, vault-b does not.
        let (mut again, _) = unlocked_app_with_item(&TempDir::new().expect("temp dir"));
        again.view = OwnerView::Vault;
        again.ui.load_prefs(data.path().to_path_buf());
        let ctx = egui::Context::default();
        again.vault_list.current = Some("vault-a".to_owned());
        assert!(super::is_hidden(&again));
        assert!(!app_frame(&ctx, &mut again).contains("Get started"));
        again.vault_list.current = Some("vault-b".to_owned());
        assert!(!super::is_hidden(&again));
        assert!(app_frame(&ctx, &mut again).contains("Get started"));
    }
}
