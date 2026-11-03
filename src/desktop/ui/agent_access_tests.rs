//! Tests of the "Agent Access" part of the credential page: the status line under its
//! title, the line under "Always ask me", and what an environment that is not set
//! means. Synthetic data only. The credentials are made in a temporary vault.

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::draw;
use super::super::owner_tests::{PASS, collect, locked_app};
use super::{AccessFacts, EnvState, environment_note};
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::model::{DetailDraft, ItemDraft};
use crate::desktop::owner_store::SecretForm;
use crate::vault::exceptions::ExceptionKind;
use crate::vault::{Declaration, Environment, Reversibility, RiskLevel, Scope};

const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);
const PASSWORD: &str = "agent-access-password-canary";
/// The SHA-1 seed of RFC 6238 appendix B.
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

const BOUNCER: &str = "The bouncer decides each use and asks you when it is not sure.";
const ALWAYS: &str = "Each use by an agent waits for you.";
const NO_DECLARATION: &str = "Each run waits for you until you set the environment.";

// ---- The status sentence. ----

/// A credential with a declaration that is not production: the bouncer decides.
fn declared() -> AccessFacts {
    AccessFacts {
        declared: true,
        ..AccessFacts::default()
    }
}

#[test]
fn the_status_says_each_use_waits_while_always_ask_is_on() {
    let facts = AccessFacts {
        always_ask: true,
        ..declared()
    };
    assert_eq!(facts.status(), ALWAYS);
    assert_eq!(facts.decider(), ALWAYS);
}

#[test]
fn the_status_says_the_bouncer_decides_while_always_ask_is_off() {
    assert_eq!(declared().status(), BOUNCER);
    assert!(declared().bouncer_decides());
}

/// Each rule that makes every use wait comes before the bouncer, in the order of the
/// broker.
#[test]
fn each_rule_that_waits_comes_before_the_bouncer() {
    let cases = [
        (
            AccessFacts {
                archived: true,
                always_ask: true,
                ..declared()
            },
            "Agents cannot use it while it is archived.",
        ),
        (
            AccessFacts {
                needs_review: true,
                ..declared()
            },
            "Agents cannot use it until you confirm its settings.",
        ),
        (
            AccessFacts {
                brain_off: true,
                ..declared()
            },
            "The bouncer brain is off, so each use waits for you.",
        ),
        (AccessFacts::default(), NO_DECLARATION),
        (
            AccessFacts {
                production: true,
                ..declared()
            },
            "Each use waits for you, because it is a production credential with write access.",
        ),
        (
            AccessFacts {
                production: true,
                read_only: true,
                ..declared()
            },
            BOUNCER,
        ),
    ];
    for (facts, expected) in cases {
        assert_eq!(facts.status(), expected, "{facts:?}");
    }
}

/// A one-time code waits unless an answer of the owner includes codes; a production
/// credential always asks for a code. Where each use waits anyway, codes add nothing.
#[test]
fn the_status_names_one_time_codes() {
    let codes = AccessFacts {
        codes: true,
        ..declared()
    };
    assert_eq!(
        codes.status(),
        format!("{BOUNCER} One-time codes wait for you unless your answer includes them.")
    );
    let production = AccessFacts {
        production: true,
        read_only: true,
        ..codes
    };
    assert_eq!(
        production.status(),
        format!("{BOUNCER} One-time codes always wait for you.")
    );
    let always = AccessFacts {
        always_ask: true,
        ..codes
    };
    assert_eq!(always.status(), ALWAYS);
}

/// The rules show as one short sentence, never one by one. An exception counts while
/// agents can use the credential; an answer only where the bouncer decides.
#[test]
fn the_status_says_rules_apply_without_repeating_them() {
    let never = AccessFacts {
        exceptions: true,
        always_ask: true,
        ..declared()
    };
    assert_eq!(never.status(), format!("{ALWAYS} Your rules also apply."));
    let answer = AccessFacts {
        answers: true,
        ..declared()
    };
    assert_eq!(answer.status(), format!("{BOUNCER} Your rules also apply."));
    let waiting = AccessFacts {
        always_ask: true,
        ..answer
    };
    assert_eq!(waiting.status(), ALWAYS, "an answer cannot skip always ask");
    let both = AccessFacts {
        codes: true,
        ..answer
    };
    assert_eq!(
        both.status(),
        format!(
            "{BOUNCER} One-time codes wait for you unless your answer includes them, and your rules also apply."
        )
    );
    let archived = AccessFacts {
        archived: true,
        ..never
    };
    assert_eq!(
        archived.status(),
        "Agents cannot use it while it is archived."
    );
}

#[test]
fn the_environment_note_says_what_not_set_and_not_confirmed_mean() {
    assert_eq!(
        environment_note(EnvState::None).as_deref(),
        Some("Each run waits for you until you set it.")
    );
    assert_eq!(
        environment_note(EnvState::Unconfirmed(Environment::Production)).as_deref(),
        Some("Treated as production until you choose one.")
    );
    assert_eq!(
        environment_note(EnvState::Known(Environment::Staging)),
        None
    );
    assert_eq!(environment_note(EnvState::Production), None);
}

// ---- The page. ----

/// One window that keeps its egui state between frames, with the AccessKit names and
/// descriptions of the last frame.
struct Window {
    ctx: egui::Context,
    time: f64,
    text: String,
    texts: Vec<String>,
    /// Each node with a label: its label and its description.
    nodes: Vec<(String, Option<String>)>,
}

impl Window {
    fn new() -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        Self {
            ctx,
            time: 0.0,
            text: String::new(),
            texts: Vec::new(),
            nodes: Vec::new(),
        }
    }

    fn frame(&mut self, app: &mut DesktopApp) {
        self.time += 0.1;
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            time: Some(self.time),
            ..Default::default()
        };
        let output = self.ctx.run_ui(input, |ui| draw(app, ui));
        self.nodes.clear();
        if let Some(update) = &output.platform_output.accesskit_update {
            for (_, node) in &update.nodes {
                if let Some(label) = node.label() {
                    self.nodes
                        .push((label.to_owned(), node.description().map(str::to_owned)));
                }
            }
        }
        self.text.clear();
        self.texts.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut self.text);
            texts(&clipped.shape, &mut self.texts);
        }
        output.drop_without_applying_deltas();
    }

    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..4 {
            self.frame(app);
        }
    }

    /// How often `needle` is a whole painted text.
    fn count(&self, needle: &str) -> usize {
        self.texts.iter().filter(|text| *text == needle).count()
    }

    fn has(&self, needle: &str) -> bool {
        self.count(needle) > 0
    }

    /// The description of the node named `name`.
    fn description(&self, name: &str) -> Option<&str> {
        self.nodes
            .iter()
            .find(|(label, _)| label == name)
            .and_then(|(_, description)| description.as_deref())
    }
}

fn texts(shape: &egui::Shape, out: &mut Vec<String>) {
    match shape {
        egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| texts(inner, out)),
        _ => {}
    }
}

fn unlocked_app(dir: &TempDir) -> DesktopApp {
    let mut app = locked_app(dir, "agent-access.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app
}

/// A login with a password, and with a one-time password when `code` is set.
fn add_login(app: &mut DesktopApp, name: &str, code: bool) -> u64 {
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    let mut details = Vec::new();
    if code {
        secrets.details[0] = SEED.to_owned();
        details.push(DetailDraft {
            label: crate::otp::LABEL.to_owned(),
            value: String::new(),
            hidden: true,
            stored: None,
        });
    }
    app.owner_ui
        .session
        .add(
            &ItemDraft {
                name: name.to_owned(),
                kind: CredentialKind::Login,
                username: "owner@example.test".to_owned(),
                details,
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add synthetic login")
        .id
}

/// A development declaration with read-only scope: no rule makes each use wait.
fn declare_development(app: &mut DesktopApp, id: u64) {
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault.set_declaration(
                id,
                &Declaration {
                    project: "synthetic".to_owned(),
                    environment: Environment::Development,
                    risk: RiskLevel::Low,
                    scope: Scope::ReadOnly,
                    reversibility: Reversibility::Reversible,
                },
            )
        })
        .expect("open")
        .expect("declaration");
}

fn set_always_ask(app: &mut DesktopApp, id: u64, on: bool) {
    app.owner_ui
        .session
        .with_vault(|vault| vault.set_always_ask(id, on))
        .expect("open")
        .expect("always ask");
}

fn open_page(app: &mut DesktopApp, window: &mut Window, id: u64, expanded: bool) {
    app.select_item(id.to_string());
    app.show_credentials();
    app.ui
        .set_expanded(&format!("credential-agent-settings-{id}"), expanded);
    window.idle(app);
}

/// The status line shows under the title while "Agent Access" is closed, and VoiceOver
/// reads it as the description of the title.
#[test]
fn the_status_shows_while_agent_access_is_closed() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let id = add_login(&mut app, "Synthetic mail", false);

    open_page(&mut app, &mut window, id, false);
    assert!(window.has("Agent Access"), "{}", window.text);
    assert!(!window.has("Always ask me"), "closed: {}", window.text);
    assert!(window.has(NO_DECLARATION), "{}", window.text);
    assert_eq!(
        window.description("Agent Access"),
        Some(NO_DECLARATION),
        "{:?}",
        window.nodes
    );

    set_always_ask(&mut app, id, true);
    window.idle(&mut app);
    assert!(window.has(ALWAYS), "{}", window.text);
    assert!(!window.has(NO_DECLARATION), "{}", window.text);
    assert!(!window.text.contains(PASSWORD), "a value is visible");
}

/// "Always ask me" has a line under its label in both states, the same as the status,
/// and VoiceOver reads it as the description of the switch.
#[test]
fn always_ask_me_has_a_line_under_it_in_both_states() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let id = add_login(&mut app, "Synthetic dashboard", false);
    declare_development(&mut app, id);

    open_page(&mut app, &mut window, id, true);
    assert!(window.has("Always ask me"), "{}", window.text);
    assert_eq!(
        window.count(BOUNCER),
        2,
        "the status and the line under the switch: {}",
        window.text
    );
    assert_eq!(
        window.description("Always ask me"),
        Some(BOUNCER),
        "{:?}",
        window.nodes
    );

    set_always_ask(&mut app, id, true);
    window.idle(&mut app);
    assert_eq!(window.count(ALWAYS), 2, "{}", window.text);
    assert!(!window.has(BOUNCER), "{}", window.text);
    assert_eq!(
        window.description("Always ask me"),
        Some(ALWAYS),
        "{:?}",
        window.nodes
    );
}

/// "Environment: Not set" says that each run waits, next to the menu, and the menu
/// keeps its name. "Hosts and risk" without a known host says what that does.
#[test]
fn environment_not_set_says_each_run_waits() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let id = add_login(&mut app, "Synthetic router", false);

    open_page(&mut app, &mut window, id, true);
    let note = "Each run waits for you until you set it.";
    assert!(window.has("Not set"), "{}", window.text);
    assert!(window.has(note), "{}", window.text);
    assert_eq!(
        window.description("Environment, Not set"),
        Some(note),
        "{:?}",
        window.nodes
    );
    let hosts = "A command that names a host waits for you, unless your answer covers it.";
    assert!(window.has(hosts), "{}", window.text);
    assert_eq!(
        window.description("Hosts and risk, Not set"),
        Some(hosts),
        "{:?}",
        window.nodes
    );

    declare_development(&mut app, id);
    window.idle(&mut app);
    assert!(
        !window.has(note),
        "a set environment needs no line: {}",
        window.text
    );
}

/// A credential with a one-time password and an exception of an agent: the status
/// names the codes and says that rules apply, without repeating the rules.
#[test]
fn the_status_names_one_time_codes_and_rules() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let id = add_login(&mut app, "Synthetic bank", true);
    declare_development(&mut app, id);

    open_page(&mut app, &mut window, id, false);
    let codes = format!("{BOUNCER} One-time codes wait for you unless your answer includes them.");
    assert!(window.has(&codes), "{}", window.text);

    app.owner_ui
        .session
        .with_vault(|vault| -> crate::vault::VaultResult<()> {
            let (agent, _) = vault.register_agent("Codex")?;
            vault.add_agent_exception(agent.id, id, ExceptionKind::Never)
        })
        .expect("open")
        .expect("exception");
    window.idle(&mut app);
    let ruled = format!(
        "{BOUNCER} One-time codes wait for you unless your answer includes them, and your rules also apply."
    );
    assert!(window.has(&ruled), "{}", window.text);
    assert!(!window.text.contains(SEED), "the seed is visible");
    assert!(!window.text.contains(PASSWORD), "a value is visible");
}
