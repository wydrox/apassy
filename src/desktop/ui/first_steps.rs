//! The first steps of a new vault (ADR 0026 §7): paste the first credential, and
//! connect an agent. Each step reads its state from the vault, so a step shows done
//! once it is true, and the steps go away when both are done. A vault from another Mac
//! has its own panel (`agents::next_steps_panel`), so the steps wait until that closes.

use eframe::egui;

use super::Sheet;
use super::kit::{self, Font, Icon, Style, Tone};
use crate::desktop::DesktopApp;

/// What the vault already has.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Progress {
    /// The vault has a credential.
    pub credential: bool,
    /// An agent is connected: a registered agent that is not disconnected.
    pub agent: bool,
}

impl Progress {
    pub(super) fn read(app: &DesktopApp) -> Self {
        let session = &app.owner_ui.session;
        Self {
            credential: session.search("").is_ok_and(|items| !items.is_empty()),
            agent: session
                .agents()
                .is_ok_and(|agents| agents.iter().any(|agent| !agent.revoked)),
        }
    }

    pub(super) fn complete(self) -> bool {
        self.credential && self.agent
    }
}

/// The action of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Go {
    Paste,
    Connect,
}

/// Draw the steps when the vault needs them. Returns true when they showed. With no
/// credential, they are the empty state of the page.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) -> bool {
    if app.owner_ui.session.is_locked() || app.ui.setup_vault.is_some() {
        return false;
    }
    let progress = Progress::read(app);
    if progress.complete() {
        return false;
    }
    if !progress.credential {
        ui.vertical_centered(|ui| {
            ui.add_space(32.0);
            kit::paint_icon_in(ui, Icon::Key, 34.0, kit::TERTIARY);
            ui.add_space(10.0);
            ui.label(kit::text("No credentials yet", Font::Title3).color(kit::LABEL));
            ui.add_space(2.0);
            ui.label(
                kit::text(
                    "Agents use a credential through Apassy and never see its value.",
                    Font::Callout,
                )
                .color(kit::SECONDARY),
            );
            ui.add_space(16.0);
        });
    }
    let header = progress.credential.then_some("First steps");
    let mut go = None;
    kit::section(ui, header, None, |s| {
        let rows = [
            (
                progress.credential,
                "Paste your first credential",
                "An API key, a .env file, or a database URL.",
                "Paste…",
                Go::Paste,
            ),
            (
                progress.agent,
                "Connect an agent",
                "Claude Code, Codex, or another host. You confirm once.",
                "Connect…",
                Go::Connect,
            ),
        ];
        // The first open step is the main action.
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
                        if done {
                            return;
                        }
                        let style = if Some(index) == next {
                            Style::Prominent
                        } else {
                            Style::Bordered
                        };
                        if kit::small_button(ui, action, style).clicked() {
                            go = Some(target);
                        }
                    },
                );
            });
        }
    });
    if let Some(go) = go {
        act(app, go);
    }
    true
}

/// A green check for a done step, an empty circle for an open one.
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
    match go {
        Go::Paste => app.ui.sheet = Some(Sheet::NewCredential),
        Go::Connect => super::agent_onboarding::open(app),
    }
}

#[cfg(test)]
mod tests {
    use eframe::egui;
    use tempfile::TempDir;

    use super::super::Sheet;
    use super::super::owner_tests::{PASS, app_frame, locked_app, unlocked_app_with_item};
    use super::{Go, Progress, act};
    use crate::desktop::{DesktopApp, Place};

    fn empty_app(dir: &TempDir) -> DesktopApp {
        let mut app = locked_app(dir, "empty.db");
        app.owner_ui.session.unlock(PASS).expect("unlock");
        app.place = Place::CREDENTIALS;
        app
    }

    #[test]
    fn an_empty_vault_shows_the_two_steps_as_its_empty_state() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = empty_app(&dir);
        assert_eq!(Progress::read(&app), Progress::default());
        let text = app_frame(&egui::Context::default(), &mut app);
        assert!(text.contains("No credentials yet"), "{text}");
        assert!(text.contains("Paste your first credential"), "{text}");
        assert!(text.contains("Paste…"), "{text}");
        assert!(text.contains("Connect an agent"), "{text}");
        assert!(text.contains("Connect…"), "{text}");
        // The old panel and its steps are gone.
        for old in [
            "Get started",
            "Register",
            "Activity",
            "Allow in FOLDER",
            "Hide",
        ] {
            assert!(!text.contains(old), "{old}: {text}");
        }
        // Each step opens its sheet.
        act(&mut app, Go::Paste);
        assert_eq!(app.ui.sheet, Some(Sheet::NewCredential));
        app.ui.sheet = None;
        act(&mut app, Go::Connect);
        assert_eq!(app.ui.sheet, Some(Sheet::RegisterAgent));
    }

    #[test]
    fn the_first_step_is_done_once_a_credential_exists() {
        let dir = TempDir::new().expect("temp dir");
        let (mut app, _) = unlocked_app_with_item(&dir);
        app.place = Place::CREDENTIALS;
        let progress = Progress::read(&app);
        assert!(progress.credential && !progress.agent);
        let text = app_frame(&egui::Context::default(), &mut app);
        assert!(text.contains("First steps"), "{text}");
        assert!(text.contains("Paste your first credential"), "{text}");
        assert!(
            !text.contains("Paste…"),
            "a done step has no button: {text}"
        );
        assert!(text.contains("Connect…"), "{text}");
        assert!(!text.contains("No credentials yet"), "{text}");
        // The list still shows the credential.
        assert!(text.contains("Guarded key"), "{text}");
    }

    #[test]
    fn the_second_step_is_done_once_an_agent_connects() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = empty_app(&dir);
        let (agent, _) = app
            .owner_ui
            .session
            .register_agent("Step agent")
            .expect("register");
        let progress = Progress::read(&app);
        assert!(!progress.credential && progress.agent);
        let ctx = egui::Context::default();
        let text = app_frame(&ctx, &mut app);
        assert!(text.contains("Paste…"), "{text}");
        assert!(text.contains("Connect an agent"), "{text}");
        assert!(
            !text.contains("Connect…"),
            "a done step has no button: {text}"
        );

        // A disconnected agent does not count.
        app.owner_ui
            .session
            .revoke_agent(agent.id)
            .expect("disconnect");
        assert!(!Progress::read(&app).agent);
        assert!(app_frame(&ctx, &mut app).contains("Connect…"));
    }

    #[test]
    fn nothing_shows_once_both_steps_are_done() {
        let dir = TempDir::new().expect("temp dir");
        let (mut app, _) = unlocked_app_with_item(&dir);
        app.place = Place::CREDENTIALS;
        app.owner_ui
            .session
            .register_agent("Step agent")
            .expect("register");
        assert!(Progress::read(&app).complete());
        let text = app_frame(&egui::Context::default(), &mut app);
        for step in [
            "First steps",
            "Paste your first credential",
            "Connect an agent",
            "Paste…",
            "Connect…",
        ] {
            assert!(!text.contains(step), "{step}: {text}");
        }
        assert!(text.contains("No credential selected"), "{text}");
    }
}
