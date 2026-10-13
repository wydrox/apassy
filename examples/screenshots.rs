//! Screenshots of the desktop app: the tour of each view for UI work, and the images of
//! the README and the site (scripts/screenshots.sh).
//!
//! `screenshots seed HOME`: make `HOME/Library/Application Support/Apassy/vault.db`
//! with synthetic data that looks like the approved mockup
//! (docs/design/app-v2-mockup.html): folders, credentials with provider tiles, agents,
//! agent uses, a remembered answer, exceptions, a credential request, and a suggestion.
//! Each value is fake.
//! The script uses a scratch HOME, never the owner's.
//!
//! `screenshots run`: open the real window for the vault of `$HOME`, type the
//! passphrase through the input hook of eframe, and walk the views. Before each view
//! it prints `SHOT <name>` and waits until the file `<name>.done` exists in the
//! current directory. The script then captures the window. No window input comes
//! from macOS, so the tour needs no Accessibility permission.
//!
//! After the unlock, the tour sends one run of an agent to the broker of the app (the
//! token is in `HOME/tour-agent-token`), so Decisions has a question that waits.
//!
//! Settings > Devices and "Add a device" use the fake relay of the tests
//! (`tests/common/fake_relay.rs`) on 127.0.0.1: before the window opens, `run` makes an
//! Apassy Connect team for the vault there, with an iPhone and a Mac in it, and points
//! the window's Apassy Connect at it. Nothing goes to the network.

#[path = "../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use apassy::broker::action_kind::ActionKind;
use apassy::contracts::CredentialKind;
use apassy::desktop::{DesktopApp, native_options};
use apassy::plan::FakePlanProvider;
use apassy::vault::agent_items::{CorrectionKind, NewCredentialRequest};
use apassy::vault::answers::ProjectRef;
use apassy::vault::exceptions::ExceptionKind;
use apassy::vault::usage::{InteractionKind, NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    ActivityDecision, DecidedBy, DecisionEntry, Declaration, Environment, ExecMode, Field,
    GrantPlace, ItemDraft, LoggedDecision, NewActivity, RequestSource, Reversibility, RiskLevel,
    Scope, SecretValue, Vault,
};
use eframe::egui;

const PASS: &str = "screenshots-demo-passphrase";
/// The file in the scratch HOME with the token of the agent that asks in the tour.
const TOKEN_FILE: &str = "tour-agent-token";
/// The file in the scratch HOME with the ID of the item that the agent asks for.
const ASK_ITEM_FILE: &str = "tour-ask-item";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, home] if cmd == "seed" => seed(Path::new(home)),
        [cmd, home] if cmd == "seed-empty" => seed_empty(Path::new(home)),
        [cmd] if cmd == "run" => run(),
        [] => {
            eprintln!(
                "usage: screenshots seed HOME | screenshots seed-empty HOME | screenshots run | screenshots COMMAND…"
            );
            std::process::exit(2);
        }
        // Each other command goes to the owner command line, as in the app binary. The
        // token sheet of the tour names this program, so `setup` works from it.
        _ => std::process::exit(apassy::cli::run(args)),
    }
}

// ---------------------------------------------------------------- seed

fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    }
}

fn declaration(project: &str, env: &str, risk: &str, scope: &str, undo: &str) -> Declaration {
    Declaration {
        project: project.to_owned(),
        environment: Environment::parse(env).expect("environment"),
        risk: RiskLevel::parse(risk).expect("risk"),
        scope: Scope::parse(scope).expect("scope"),
        reversibility: Reversibility::parse(undo).expect("reversibility"),
    }
}

/// The data directory in `home`, empty, with the settings that keep the tour offline.
fn data_dir(home: &Path) -> PathBuf {
    let data = home.join("Library/Application Support/Apassy");
    let path = data.join("vault.db");
    assert!(
        !path.exists(),
        "{} exists. Use an empty scratch HOME.",
        path.display()
    );
    std::fs::create_dir_all(&data).expect("data dir");
    set_owner_only(&data);
    // The tour must not ask the update server: the updater reads this file at start
    // (ADR 0015).
    std::fs::write(
        data.join("update.json"),
        r#"{"auto_check": false, "auto_install": false}"#,
    )
    .expect("update settings");
    data
}

/// A vault with no credential and no agent: the first steps.
fn seed_empty(home: &Path) {
    let path = data_dir(home).join("vault.db");
    let mut v = Vault::create(&path, PASS).expect("create");
    v.unlock(PASS).expect("unlock");
    v.lock().expect("lock");
    println!("seeded an empty vault {}", path.display());
}

/// One credential of the seed.
struct Seed {
    title: &'static str,
    kind: CredentialKind,
    folder: &'static str,
    /// `development`, `production`, or empty for no declaration.
    env: &'static str,
    /// The variable of the secret field, or empty.
    variable: &'static str,
    fields: Vec<Field>,
}

/// One use of the seed: the agent, its name, the credential, the project, the action,
/// the command, the outcome, who decided, and the device of the owner's answer.
type SeedUse = (
    u64,
    &'static str,
    &'static str,
    &'static str,
    ActionKind,
    &'static str,
    UseOutcome,
    UseDecidedBy,
    &'static str,
);

/// One kind of automatic decision of the seed: the agent, its name, the credential, the
/// project, the command, and what decided.
type SeedAutomatic = (
    u64,
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    DecidedBy,
);

fn seed(home: &Path) {
    let data = data_dir(home);
    let path = data.join("vault.db");
    let mut v = Vault::create(&path, PASS).expect("create");
    v.unlock(PASS).expect("unlock");

    // Folders as in the mockup: Work › Acme, Work › Apassy, Side projects, Infra, Home.
    let work = v.create_folder(None, "Work").expect("folder").uuid;
    let acme = v.create_folder(Some(&work), "Acme").expect("folder").uuid;
    let apassy = v.create_folder(Some(&work), "Apassy").expect("folder").uuid;
    let side = v.create_folder(None, "Side projects").expect("folder").uuid;
    let infra = v.create_folder(None, "Infra").expect("folder").uuid;
    let home_folder = v.create_folder(None, "Home").expect("folder").uuid;
    let folder_of = |name: &str| match name {
        "acme" => Some(acme.clone()),
        "apassy" => Some(apassy.clone()),
        "side" => Some(side.clone()),
        "infra" => Some(infra.clone()),
        "home" => Some(home_folder.clone()),
        _ => None,
    };

    use CredentialKind::{ApiKey, Custom, Database, Login, SshKey};
    let seeds = vec![
        Seed {
            title: "Anthropic API",
            kind: ApiKey,
            folder: "apassy",
            env: "development",
            variable: "ANTHROPIC_API_KEY",
            fields: vec![
                field("token", "demo-anthropic-key-not-real", true),
                field("host", "api.anthropic.com", false),
            ],
        },
        Seed {
            title: "GitHub deploy bot",
            kind: ApiKey,
            folder: "apassy",
            env: "development",
            variable: "GITHUB_TOKEN",
            fields: vec![
                field("token", "demo-github-token-not-real", true),
                field("host", "api.github.com", false),
            ],
        },
        Seed {
            title: "Stripe live",
            kind: ApiKey,
            folder: "acme",
            env: "production",
            variable: "STRIPE_SECRET_KEY",
            fields: vec![
                field("token", "demo-stripe-live-key-not-real", true),
                field("host", "api.stripe.com", false),
            ],
        },
        Seed {
            title: "Stripe test",
            kind: ApiKey,
            folder: "acme",
            env: "development",
            variable: "STRIPE_TEST_KEY",
            fields: vec![
                field("token", "demo-stripe-test-key-not-real", true),
                field("host", "api.stripe.com", false),
            ],
        },
        Seed {
            title: "Billing database",
            kind: Database,
            folder: "acme",
            env: "production",
            variable: "DATABASE_PASSWORD",
            fields: vec![
                field("host", "db.acme.internal", false),
                field("database", "billing", false),
                field("username", "billing_rw", false),
                field("password", "demo-billing-password-not-real", true),
            ],
        },
        Seed {
            title: "Cloudflare Workers",
            kind: ApiKey,
            folder: "infra",
            env: "development",
            variable: "CLOUDFLARE_API_TOKEN",
            fields: vec![
                field("token", "demo-cloudflare-token-not-real", true),
                field("host", "api.cloudflare.com", false),
            ],
        },
        Seed {
            title: "Fly.io",
            kind: Login,
            folder: "infra",
            env: "",
            variable: "",
            fields: vec![
                field("username", "rafal@example.com", false),
                field("password", "demo-fly-password-not-real", true),
            ],
        },
        Seed {
            title: "OpenAI API",
            kind: ApiKey,
            folder: "side",
            env: "",
            variable: "OPENAI_API_KEY",
            fields: vec![
                field("token", "demo-openai-key-not-real", true),
                field("host", "api.openai.com", false),
            ],
        },
        Seed {
            title: "Build server",
            kind: SshKey,
            folder: "infra",
            env: "",
            variable: "",
            fields: vec![field("private_key", "demo-ssh-private-key-not-real", true)],
        },
        Seed {
            title: "Netflix",
            kind: Login,
            folder: "home",
            env: "",
            variable: "",
            fields: vec![
                field("username", "family@example.com", false),
                field("password", "demo-netflix-password-not-real", true),
            ],
        },
        Seed {
            title: "Home Wi-Fi",
            kind: Custom,
            folder: "home",
            env: "",
            variable: "",
            fields: vec![field("password", "demo-wifi-password-not-real", true)],
        },
    ];
    let mut ids = std::collections::BTreeMap::new();
    for seed in seeds {
        let secret = seed
            .fields
            .iter()
            .find(|field| field.secret)
            .map(|field| field.name.clone())
            .expect("a secret field");
        let id = v
            .add(ItemDraft {
                title: seed.title.to_owned(),
                kind: seed.kind,
                notes: String::new(),
                tags: Vec::new(),
                fields: seed.fields,
            })
            .expect("add")
            .id;
        v.set_item_folder(id, folder_of(seed.folder).as_deref())
            .expect("folder");
        let project = match seed.folder {
            "acme" => "acme-billing",
            "apassy" => "apassy",
            "side" => "newsletter",
            _ => "infra",
        };
        match seed.env {
            "production" => v
                .set_declaration(
                    id,
                    &declaration(project, "production", "high", "read-write", "partial"),
                )
                .expect("declaration"),
            "development" => v
                .set_declaration(
                    id,
                    &declaration(project, "development", "low", "read-write", "reversible"),
                )
                .expect("declaration"),
            _ => {}
        }
        if !seed.variable.is_empty() {
            v.set_env_binding(id, seed.variable, &secret)
                .expect("env binding");
        }
        ids.insert(seed.title, id);
    }
    let id = |title: &str| ids[title];

    // Agents as in the mockup. Claude Code asks in the tour.
    let (claude, token) = v.register_agent("Claude Code").expect("agent");
    let (codex, _) = v.register_agent("Codex").expect("agent");
    let (t3, _) = v.register_agent("T3 Code").expect("agent");
    let (ci, _) = v.register_agent("CI on GitHub").expect("agent");
    let (claude, codex, t3, ci) = (claude.id, codex.id, t3.id, ci.id);
    // Connected in the app, an agent sees the name of each credential.
    for agent in [claude, codex, t3, ci] {
        v.set_agent_sees_all(agent, true).expect("sees all");
    }
    v.set_agent_note(ci, "CI agent for Acme. Only the Stripe test key.")
        .expect("note");
    std::fs::write(home.join(TOKEN_FILE), token.expose()).expect("token file");
    std::fs::write(home.join(ASK_ITEM_FILE), id("Stripe live").to_string()).expect("item file");
    set_file_owner_only(&home.join(TOKEN_FILE));

    // Claude Code may use the production key in the projects of the scratch HOME. With
    // no bouncer in the tour, its run waits for the owner.
    let code = home.join("code/acme-billing");
    std::fs::create_dir_all(&code).expect("project dir");
    let code = std::fs::canonicalize(home.join("code")).expect("project dir");
    v.set_exec_grants(
        claude,
        &[id("Stripe live")],
        &GrantPlace::Folder(code.display().to_string()),
        ExecMode::Bouncer,
    )
    .expect("grant");

    // A remembered answer of the owner, as in the mockup: "Allow reading in
    // acme-billing" for the production Stripe key, answered on the iPhone. In the app
    // only the broker stores it, after the owner check; the seed writes it directly.
    v.allow_production(
        id("Stripe live"),
        &ProjectRef {
            key: code.join("acme-billing").display().to_string(),
            label: "acme-billing".to_owned(),
        },
        ActionKind::Read,
        "iPhone",
        &["api.stripe.com".to_owned()],
    )
    .expect("answer");

    // Exceptions: they show in "Rules from your answers" of the credential and in the
    // agent.
    v.add_agent_exception(ci, id("Stripe live"), ExceptionKind::Never)
        .expect("exception");
    v.add_agent_exception(t3, id("Stripe live"), ExceptionKind::AlwaysAsk)
        .expect("exception");
    v.add_agent_exception(codex, id("Billing database"), ExceptionKind::Never)
        .expect("exception");

    // Agent use: the newest uses of each key, with their result. Claude Code, the first
    // agent of the tour, has each kind of action, a denied use, and one with no answer in
    // time, for "Actions this week" and "Recent" of its page.
    let uses: [SeedUse; 11] = [
        (
            t3,
            "T3 Code",
            "Stripe live",
            "scratch",
            ActionKind::Change,
            "curl -X POST paste.example",
            UseOutcome::Refused,
            UseDecidedBy::Bouncer,
            "",
        ),
        (
            codex,
            "Codex",
            "Stripe live",
            "acme-billing",
            ActionKind::Deploy,
            "stripe deploy",
            UseOutcome::Allowed,
            UseDecidedBy::Owner,
            "iPhone",
        ),
        (
            claude,
            "Claude Code",
            "Stripe live",
            "apassy",
            ActionKind::Read,
            "stripe status",
            UseOutcome::Allowed,
            UseDecidedBy::Bouncer,
            "",
        ),
        (
            claude,
            "Claude Code",
            "Stripe test",
            "acme-billing",
            ActionKind::Change,
            "stripe customers create",
            UseOutcome::Allowed,
            UseDecidedBy::Bouncer,
            "",
        ),
        (
            claude,
            "Claude Code",
            "GitHub deploy bot",
            "apassy",
            ActionKind::Deploy,
            "gh release create v0.5.1",
            UseOutcome::TimedOut,
            UseDecidedBy::Owner,
            "",
        ),
        (
            claude,
            "Claude Code",
            "Anthropic API",
            "apassy",
            ActionKind::Read,
            "npm run eval",
            UseOutcome::Allowed,
            UseDecidedBy::Bouncer,
            "",
        ),
        (
            claude,
            "Claude Code",
            "Billing database",
            "acme-billing",
            ActionKind::Delete,
            "psql -c drop table invoices_2019",
            UseOutcome::Denied,
            UseDecidedBy::Owner,
            "this Mac",
        ),
        (
            codex,
            "Codex",
            "OpenAI API",
            "newsletter",
            ActionKind::Change,
            "node scripts/summarize.mjs",
            UseOutcome::Allowed,
            UseDecidedBy::Bouncer,
            "",
        ),
        (
            claude,
            "Claude Code",
            "GitHub deploy bot",
            "apassy",
            ActionKind::Deploy,
            "git push origin main",
            UseOutcome::Allowed,
            UseDecidedBy::Owner,
            "this Mac",
        ),
        (
            claude,
            "Claude Code",
            "Billing database",
            "acme-billing",
            ActionKind::Read,
            "psql -c select count(*) from invoices",
            UseOutcome::Allowed,
            UseDecidedBy::Owner,
            "this Mac",
        ),
        (
            ci,
            "CI on GitHub",
            "Stripe test",
            "acme-billing",
            ActionKind::Read,
            "stripe balance retrieve",
            UseOutcome::Allowed,
            UseDecidedBy::Bouncer,
            "",
        ),
    ];
    for (agent, name, title, project, action, command, outcome, decided_by, on) in uses {
        v.record_item_use(&NewItemUse {
            item_id: id(title),
            agent_id: Some(agent),
            agent_name: name.to_owned(),
            project_key: format!("/Users/you/code/{project}"),
            project_label: project.to_owned(),
            action,
            command_summary: command.to_owned(),
            hosts: Vec::new(),
            outcome,
            decided_by,
            answered_on: on.to_owned(),
            decision_log_id: None,
        })
        .expect("use");
        v.record_activity(&NewActivity {
            agent_id: Some(agent),
            agent_name: name.to_owned(),
            item_id: Some(id(title)),
            operation: format!("run {command}"),
            decision: if outcome == UseOutcome::Allowed {
                ActivityDecision::Allow
            } else {
                ActivityDecision::Deny
            },
            reason: String::new(),
        })
        .expect("activity");
    }
    for _ in 0..7 {
        v.record_interaction(InteractionKind::Question, "tour", &[])
            .expect("interaction");
    }
    // The decisions of the week that did not wait for the owner, as in the mockup: "7 by
    // you · 128 automatic this week". The bouncer, a remembered pattern, or an answer of
    // the owner allowed them over the last five days.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let automatic: [SeedAutomatic; 4] = [
        (
            claude,
            "Claude Code",
            "Anthropic API",
            "apassy",
            &["npm", "run", "eval"],
            DecidedBy::Model,
        ),
        (
            codex,
            "Codex",
            "OpenAI API",
            "newsletter",
            &["node", "scripts/summarize.mjs"],
            DecidedBy::Pattern,
        ),
        (
            claude,
            "Claude Code",
            "Stripe test",
            "acme-billing",
            &["stripe", "customers", "list"],
            DecidedBy::Answer,
        ),
        (
            ci,
            "CI on GitHub",
            "Stripe test",
            "acme-billing",
            &["stripe", "balance", "retrieve"],
            DecidedBy::Model,
        ),
    ];
    for index in 0..128u64 {
        let (agent, name, title, project, command, decided_by) = automatic[(index % 4) as usize];
        v.record_decision(&DecisionEntry {
            at: now - 60 - index * (5 * 86_400 / 128),
            agent_id: agent,
            agent_name: name.to_owned(),
            project_dir: format!("/Users/you/code/{project}"),
            cwd_rel: ".".to_owned(),
            items: vec![id(title)],
            user_request: String::new(),
            user_request_source: RequestSource::None,
            command: command.iter().map(|arg| (*arg).to_owned()).collect(),
            purpose: String::new(),
            env_names: Vec::new(),
            declarations: vec![None],
            rule_flags: Vec::new(),
            known_safe: false,
            model_facts: Vec::new(),
            pattern: String::new(),
            grant_asks: false,
            asked: false,
            decision: LoggedDecision::Allow,
            decided_by,
            remembered: false,
            policy: String::new(),
            note: String::new(),
            instruction: String::new(),
        })
        .expect("decision");
    }

    // Decisions: a request of Codex and a suggestion for the OpenAI key.
    v.open_credential_request(&NewCredentialRequest {
        agent_id: codex,
        agent_name: "Codex".to_owned(),
        project_key: "/Users/you/code/newsletter".to_owned(),
        project_label: "newsletter".to_owned(),
        name: "Resend API key".to_owned(),
        purpose: "Send the test email of the newsletter".to_owned(),
        where_to_get: "resend.com/api-keys".to_owned(),
        folder: Some(side.clone()),
    })
    .expect("request");
    v.propose_correction(
        id("OpenAI API"),
        CorrectionKind::Environment,
        "development",
        &serde_json::json!({
            "signal": "Used only with api.openai.com, in three projects",
            "provider": "openai",
            "hosts": ["api.openai.com"],
            "uses": 14,
            "agents": ["Codex", "Claude Code"],
        }),
    )
    .expect("correction");

    v.lock().expect("lock");
    println!("seeded {}", path.display());
}

#[cfg(unix)]
fn set_owner_only(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    for dir in [dir, dir.parent().expect("parent")] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
}

#[cfg(unix)]
fn set_file_owner_only(file: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// The run that waits for the owner in Decisions: Claude Code reads the payouts with the
/// production Stripe key in `acme-billing`. It runs on its own thread and ends with the
/// answer, the timeout, or the app.
fn ask_in_background() {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return;
    };
    let (Ok(token), Ok(item)) = (
        std::fs::read_to_string(home.join(TOKEN_FILE)),
        std::fs::read_to_string(home.join(ASK_ITEM_FILE)),
    ) else {
        return;
    };
    let Ok(item) = item.trim().parse::<u64>() else {
        return;
    };
    let project = home.join("code/acme-billing");
    // A stand-in for the Stripe command line, so the broker finds the program. The
    // tour never answers, so it does not run.
    let bin = home.join("code/bin");
    let _ = std::fs::create_dir_all(&project);
    let _ = std::fs::create_dir_all(&bin);
    let _ = std::fs::write(bin.join("stripe"), "#!/bin/sh\nexit 0\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ =
            std::fs::set_permissions(bin.join("stripe"), std::fs::Permissions::from_mode(0o700));
    }
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let project = std::fs::canonicalize(&project).unwrap_or(project);
    std::thread::spawn(move || {
        let action = apassy::agent::wire::Action::Run {
            items: vec![item],
            command: ["stripe", "payouts", "list", "--limit", "10"]
                .map(str::to_owned)
                .to_vec(),
            cwd: project.display().to_string(),
            purpose: "List the last payouts for the monthly report.".to_owned(),
            path: Some(path),
            user_request: Some("Check why the October payout is late.".to_owned()),
        };
        let socket = apassy::agent::client::default_socket_path();
        match apassy::agent::client::send(&socket, token.trim(), action) {
            Ok(response) => eprintln!("tour: the run ended: {response:?}"),
            Err(error) => eprintln!("tour: the run failed: {error}"),
        }
    });
}

// ---------------------------------------------------------------- run

/// One step of the tour. Positions are in points of the 1180 x 740 window.
enum Step {
    Wait(f64),
    Type(&'static str),
    /// A paste from the clipboard, such as a `.env` file.
    Paste(&'static str),
    Click(f32, f32),
    Scroll(f32, f32, f32),
    Shot(&'static str),
    /// A key press with modifiers: `key cmd+1`, `key escape`, `key shift+tab`.
    Key(egui::Key, egui::Modifiers),
    /// Resize the window to this inner size in points.
    Size(f32, f32),
    /// Save the window content as `$APASSY_SNAP_DIR/NAME.png` (egui screenshot, no
    /// Screen Recording permission needed).
    Snap(&'static str),
    /// Minimize the window (`true`) or bring it back (`false`).
    Minimize(bool),
    /// Draw a second window in the main one (`true`), so the tour can click in it: the
    /// input hook reaches only the main window.
    Embed(bool),
    /// Send the run that waits for the owner ([`ask_in_background`]).
    Ask,
    /// An iPhone asks to join with the code that "Add a device" shows, through the
    /// fake relay ([`TourRelay::phone_asks`]).
    PhoneAsks,
    /// The window takes the fake plan of this name, with an offer
    /// ([`FakePlanProvider::for_screenshots`]): the plan screens show.
    Plan(&'static str),
    Quit,
}

struct Tour {
    app: DesktopApp,
    steps: VecDeque<Step>,
    events: Vec<egui::Event>,
    next_at: Instant,
    waiting_for: Option<PathBuf>,
    /// The name of a requested egui screenshot that has not arrived yet.
    snapping: Option<String>,
    /// Events for the frame after the next one, for example a key release.
    next_frame: Vec<egui::Event>,
    /// Live mode: the last batch ended and `done` is written.
    live_idle: bool,
    /// The fake relay of Settings > Devices, while the window runs.
    relay: Option<TourRelay>,
}

/// The fake relay of the tour with the Connect team of the vault, and the iPhone that
/// asks to join in "Add a device".
struct TourRelay {
    relay: fake_relay::FakeRelay,
    asking: Option<apassy::sync::PendingJoin>,
}

impl TourRelay {
    /// Start the fake relay and give the vault of `$HOME` a Connect team on it: this Mac,
    /// "iPhone 17" (with its Face ID answer key), and "Mac mini", each confirmed by a link
    /// as on the real relay. All keys are new and synthetic.
    fn start() -> Option<Self> {
        use apassy::questions::QuestionsClient;
        use apassy::questions::device_link::link_device_name;
        use apassy::relay::membership::{
            adopt_questions_team, create_connect_team, register_linked_device,
        };
        use apassy::sync::{DeviceKey, PendingJoin};
        let home = PathBuf::from(std::env::var_os("HOME")?);
        let path = home.join("Library/Application Support/Apassy/vault.db");
        if !path.exists() {
            return None;
        }
        let relay = fake_relay::FakeRelay::start();
        let mut vault = Vault::open(&path).expect("open the vault");
        vault.unlock(PASS).expect("unlock");
        let membership =
            create_connect_team(&relay.url, "Personal", "MacBook Pro").expect("connect team");
        adopt_questions_team(&mut vault, &membership, "MacBook Pro").expect("adopt");
        let client = QuestionsClient::from_membership(&membership).expect("client");
        let answer_key = DeviceKey::generate().expect("key");
        for name in ["iPhone 17", "Mac mini"] {
            let shown = if name.starts_with("iPhone") {
                link_device_name(name, answer_key.public_key()).expect("name")
            } else {
                name.to_owned()
            };
            let code = client.create_link().expect("link");
            let pending = PendingJoin::request(&code.link, "", &shown).expect("join");
            let links = client.pending_links(Some(&code)).expect("links");
            let device = client.confirm_link(&links[0]).expect("confirm");
            let _ = pending.poll();
            if name.starts_with("iPhone") {
                register_linked_device(
                    &mut vault,
                    &membership.team_id,
                    device.id,
                    &links[0].device_name,
                    &links[0].public_key,
                )
                .expect("the row of the iPhone");
            } else {
                let uuid = apassy::relay::membership::new_device_uuid().expect("uuid");
                vault
                    .register_trusted_device(
                        &uuid,
                        name,
                        apassy::vault::TrustedDeviceKind::Mac,
                        &links[0].public_key,
                        None,
                    )
                    .expect("the row of the Mac");
                vault
                    .set_trusted_device_relay_id(&uuid, &membership.team_id, device.id)
                    .expect("its number");
            }
        }
        vault.lock().expect("lock");
        drop(vault);
        // A paid plan can switch the vault to sync in its team (the Plan steps).
        relay.lift_plan(&membership.team_id);
        Some(Self {
            relay,
            asking: None,
        })
    }

    /// An iPhone scans the code that "Add a device" shows and asks to join: the safety
    /// words then show on the Mac.
    fn phone_asks(&mut self) {
        let Some(code) = self.relay.last_link_code() else {
            eprintln!("tour: no link to join");
            return;
        };
        let key = apassy::sync::DeviceKey::generate().expect("key");
        let name =
            apassy::questions::device_link::link_device_name("iPhone 17 Pro", key.public_key())
                .expect("name");
        let link = format!("{}/link#{code}", self.relay.url);
        match apassy::sync::PendingJoin::request(&link, "", &name) {
            Ok(pending) => self.asking = Some(pending),
            Err(error) => eprintln!("tour: the iPhone did not ask: {error}"),
        }
    }
}

fn run() {
    let steps = VecDeque::from(tour_steps());
    // The first steps run on an empty vault with no team.
    let relay = std::env::var_os("APASSY_TOUR_FIRST_STEPS")
        .is_none()
        .then(TourRelay::start)
        .flatten();
    // A fixed size, so the positions of the tour hold on each screen.
    let mut options = native_options();
    options.viewport = options.viewport.with_inner_size(egui::vec2(1180.0, 740.0));
    eframe::run_native(
        "apassy",
        options,
        Box::new(move |cc| {
            // An active window shows the traffic lights in color. macOS can refuse
            // the focus; scripts/screenshots.sh then colors them.
            cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            let mut app = DesktopApp::from_creation_context(cc);
            tour_plan(&mut app);
            // "Continue to checkout" and "Manage subscription" stay in the window: the
            // synthetic account service has no page.
            app.hold_plan_links();
            if let Some(relay) = &relay {
                assert!(app.set_connect_relay_url(&relay.relay.url));
            }
            Ok(Box::new(Tour {
                app,
                steps,
                events: Vec::new(),
                next_at: Instant::now() + Duration::from_secs(2),
                waiting_for: None,
                snapping: None,
                next_frame: Vec::new(),
                live_idle: false,
                relay,
            }))
        }),
    )
    .expect("window");
}

/// `APASSY_PLAN=free|personal|team|operator|ended` gives the window a fake plan with an
/// offer, so the plan screens show. Without it the window has the plan of the app as it
/// ships: none.
fn tour_plan(app: &mut DesktopApp) {
    if let Ok(name) = std::env::var("APASSY_PLAN") {
        set_plan(app, &name);
    }
}

/// Give the window the fake plan `name`, checked now. Only this example makes one; the
/// app as it ships has no plan to offer.
fn set_plan(app: &mut DesktopApp, name: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let provider = FakePlanProvider::for_screenshots(name, now)
        .expect("the plan is free, personal, team, operator, ended, past-due, or offline");
    app.set_plan_provider(std::sync::Arc::new(provider));
}

/// The `.env` file that the tour pastes in New Credential, as in the mockup.
const DOT_ENV: &str = "# .env\nRESEND_API_KEY=re_FAKE123\nSTRIPE_SECRET_KEY=sk_test_FAKE51H\nSENTRY_AUTH_TOKEN=sntrys_FAKE\nDATABASE_PASSWORD=fake-pass\n";

/// The views of the tour, after the unlock. Each `Shot` name becomes `ui-NAME.png`.
/// Positions are in points of the 1180 x 740 window; the places open with their
/// shortcuts, so most steps do not depend on the layout of the sidebar.
fn view_steps() -> Vec<Step> {
    use Step::*;
    let cmd = egui::Modifiers::COMMAND;
    let ctrl_cmd = egui::Modifiers::COMMAND | egui::Modifiers::CTRL;
    vec![
        Ask,
        Wait(1.0),
        // All credentials, nothing selected.
        Shot("all-credentials"),
        // The Work folder, opened in the sidebar: its subfolders and its groups.
        Click(LAYOUT.work_triangle.0, LAYOUT.work_triangle.1),
        Wait(0.5),
        Click(LAYOUT.work_row.0, LAYOUT.work_row.1),
        Wait(1.0),
        Shot("folder"),
        // The production Stripe key: the top of its detail, then its options.
        Click(LAYOUT.stripe_live_in_work.0, LAYOUT.stripe_live_in_work.1),
        Wait(1.5),
        Shot("credential"),
        Scroll(820.0, 450.0, -2000.0),
        Wait(1.0),
        Shot("credential-options"),
        // New Credential with a pasted .env file.
        Key(egui::Key::N, cmd),
        Wait(1.0),
        Paste(DOT_ENV),
        Wait(1.0),
        // The paste shows masked. A click on the left margin of the sheet ends the
        // keyboard focus of the masked field, as after a paste with the pointer.
        Click(338.0, 370.0),
        Wait(1.0),
        Shot("new-credential"),
        // The paste field no longer has the focus: one Escape closes the sheet.
        Key(egui::Key::Escape, egui::Modifiers::NONE),
        Wait(1.0),
        // Decisions: the question that waits (selected first), a request, a suggestion.
        Key(egui::Key::Num2, cmd),
        Wait(1.5),
        Shot("decisions-question"),
        Click(LAYOUT.decision_request.0, LAYOUT.decision_request.1),
        Wait(1.0),
        Shot("decisions-request"),
        Click(LAYOUT.decision_suggestion.0, LAYOUT.decision_suggestion.1),
        Wait(1.0),
        Shot("decisions-suggestion"),
        // Agents, the first one selected.
        Key(egui::Key::Num3, cmd),
        Wait(1.0),
        Click(LAYOUT.first_agent.0, LAYOUT.first_agent.1),
        Wait(1.0),
        Shot("agents"),
        // The sidebar as a rail (⌃⌘S), then the narrow window with its rail, and the
        // sidebar that floats over the list.
        Key(egui::Key::Num1, cmd),
        Wait(0.5),
        // A click on an empty part of the sidebar ends the keyboard focus that the
        // shortcut gave to the first control of the list.
        Click(110.0, 600.0),
        Key(egui::Key::S, ctrl_cmd),
        Wait(1.0),
        Shot("sidebar-collapsed"),
        Key(egui::Key::S, ctrl_cmd),
        Wait(0.5),
        Size(960.0, 740.0),
        Wait(1.0),
        Shot("narrow"),
        Key(egui::Key::S, ctrl_cmd),
        Wait(1.0),
        Shot("narrow-float"),
        Key(egui::Key::Escape, egui::Modifiers::NONE),
        Size(1180.0, 740.0),
        Wait(1.0),
        // Settings, a view of the window: ⌘, opens it on Vault, then each section of
        // its list.
        Key(egui::Key::Comma, cmd),
        Wait(1.5),
        Shot("settings-vault"),
        Click(LAYOUT.settings_list.0, LAYOUT.settings_list.1 + 48.0),
        Wait(1.0),
        Shot("settings-security"),
        Click(LAYOUT.settings_list.0, LAYOUT.settings_list.1 + 2.0 * 48.0),
        Wait(1.0),
        Shot("settings-devices"),
        Click(LAYOUT.settings_list.0, LAYOUT.settings_list.1 + 3.0 * 48.0),
        Wait(1.0),
        Shot("settings-bouncer"),
        Click(LAYOUT.settings_list.0, LAYOUT.settings_list.1 + 4.0 * 48.0),
        Wait(1.0),
        Shot("settings-tools"),
        Click(LAYOUT.settings_list.0, LAYOUT.settings_list.1 + 5.0 * 48.0),
        Wait(1.0),
        Shot("settings-updates"),
        // Settings > Devices, then "Add a device": the QR code, an iPhone that asks with
        // the safety words, the owner check, and the end. The relay is the fake one.
        Click(LAYOUT.settings_list.0, LAYOUT.settings_list.1 + 2.0 * 48.0),
        Wait(3.0),
        Click(LAYOUT.add_device.0, LAYOUT.add_device.1),
        Wait(3.0),
        Shot("devices-add"),
        PhoneAsks,
        Wait(7.0),
        Shot("devices-add-words"),
        Click(LAYOUT.confirm_device.0, LAYOUT.confirm_device.1),
        Wait(1.5),
        Type(PASS),
        Key(egui::Key::Enter, egui::Modifiers::NONE),
        Wait(4.0),
        Shot("devices-add-done"),
        Key(egui::Key::Escape, egui::Modifiers::NONE),
        Wait(1.5),
        Shot("settings-devices-added"),
    ]
    .into_iter()
    .chain(plan_steps())
    .collect()
}

/// The plan screens (flow spec M3 to M5, Flows B to E), with the fake plans of this
/// example. The steps before them run with no plan, as the app ships.
fn plan_steps() -> Vec<Step> {
    use Step::*;
    let cmd = egui::Modifiers::COMMAND;
    let none = egui::Modifiers::NONE;
    // With an offer, Settings lists Plan before Updates.
    let section = |index: f32| {
        Click(
            LAYOUT.settings_list.0,
            LAYOUT.settings_list.1 + index * 48.0,
        )
    };
    vec![
        // Free: Vault > Sync with the "Personal" tag, and the Shared empty state.
        Plan("free"),
        section(0.0),
        Wait(1.5),
        Shot("plan-sync-free"),
        // "Apassy" on Free: the Upgrade sheet, then the wait for the browser.
        Click(LAYOUT.sync_apassy_free.0, LAYOUT.sync_apassy_free.1),
        Wait(1.0),
        Shot("plan-upgrade"),
        Click(LAYOUT.checkout.0, LAYOUT.checkout.1),
        Wait(1.0),
        Shot("plan-upgrade-waiting"),
        Key(egui::Key::Escape, none),
        Wait(1.0),
        // Settings > Plan on Free, and Compare plans.
        section(5.0),
        Wait(1.0),
        Shot("plan-settings-free"),
        Click(LAYOUT.compare.0, LAYOUT.compare.1),
        Wait(1.0),
        Shot("plan-compare"),
        Key(egui::Key::Escape, none),
        Wait(1.0),
        Key(egui::Key::Num1, cmd),
        Wait(1.0),
        Shot("plan-shared-free"),
        // Personal: Settings > Plan, then Vault > Sync and "Apassy": the owner check
        // lists the devices that start to sync. It passes, and the vault syncs through
        // Apassy in its own team.
        Plan("personal"),
        Key(egui::Key::Comma, cmd),
        Wait(1.5),
        section(5.0),
        Wait(1.0),
        Shot("plan-settings-personal"),
        section(0.0),
        Wait(1.0),
        Shot("plan-sync-personal"),
        Click(LAYOUT.sync_apassy_paid.0, LAYOUT.sync_apassy_paid.1),
        Wait(1.5),
        Shot("plan-switch-check"),
        Type(PASS),
        Key(egui::Key::Enter, none),
        Wait(5.0),
        Shot("plan-sync-apassy"),
        // Payment failed, and offline.
        Plan("past-due"),
        section(5.0),
        Wait(1.0),
        Shot("plan-settings-past-due"),
        Plan("offline"),
        Wait(1.0),
        Shot("plan-settings-offline"),
        // The plan ended while the vault syncs through Apassy: "Personal ended" once.
        Plan("ended"),
        Wait(1.5),
        Shot("plan-ended"),
        Key(egui::Key::Escape, none),
        Wait(1.0),
    ]
}

/// The positions that the tour clicks, in points of the 1180 x 740 window.
struct Layout {
    work_triangle: (f32, f32),
    work_row: (f32, f32),
    stripe_live_in_work: (f32, f32),
    decision_request: (f32, f32),
    decision_suggestion: (f32, f32),
    first_agent: (f32, f32),
    /// The first section in the list of Settings; each next one is 48 points lower.
    settings_list: (f32, f32),
    /// "Add a device…" of Settings > Devices with devices in the list.
    add_device: (f32, f32),
    /// "Confirm with Touch ID" of "Add a device" while an iPhone asks.
    confirm_device: (f32, f32),
    /// The "Apassy" segment of Vault > Sync on Free, with its "Personal" tag.
    sync_apassy_free: (f32, f32),
    /// The same segment on a paid plan, with no tag.
    sync_apassy_paid: (f32, f32),
    /// "Continue to checkout" of the Upgrade sheet.
    checkout: (f32, f32),
    /// "Compare plans" of Settings > Plan on Free.
    compare: (f32, f32),
}

const LAYOUT: Layout = Layout {
    work_triangle: (33.0, 104.0),
    work_row: (120.0, 104.0),
    stripe_live_in_work: (450.0, 176.0),
    decision_request: (450.0, 174.0),
    decision_suggestion: (450.0, 250.0),
    first_agent: (450.0, 70.0),
    settings_list: (450.0, 70.0),
    add_device: (1093.0, 154.0),
    confirm_device: (412.0, 575.0),
    sync_apassy_free: (904.0, 268.0),
    sync_apassy_paid: (977.0, 268.0),
    checkout: (740.0, 478.0),
    compare: (602.0, 206.0),
};

/// The tour. `APASSY_TOUR` names a file with other steps after the unlock, one per
/// line: `click X Y`, `scroll X Y DY`, `wait S`, `shot NAME`, `snap NAME`, `size W H`,
/// `type TEXT`, `paste TEXT` (`\n` for a new line), `key cmd+2`, `embed on|off`, `ask`.
/// It helps to find the positions of a new layout. With `APASSY_TOUR_RAW` set, the
/// file steps run alone, without the unlock: for a scratch HOME with no vault (first
/// steps). `APASSY_TOUR_FIRST_STEPS` takes the first steps of an empty vault.
fn tour_steps() -> Vec<Step> {
    use Step::*;
    let mut steps = if std::env::var_os("APASSY_TOUR_RAW").is_some() {
        vec![Wait(1.0)]
    } else {
        vec![Type(PASS), Wait(0.5), Click(590.0, 461.0), Wait(3.5)]
    };
    if std::env::var_os("APASSY_TOUR_FIRST_STEPS").is_some() {
        // The first steps, then Settings > Devices with only this Mac.
        steps.extend([
            Wait(1.0),
            Shot("first-steps"),
            Key(egui::Key::Comma, egui::Modifiers::COMMAND),
            Wait(1.5),
            Click(LAYOUT.settings_list.0, LAYOUT.settings_list.1 + 2.0 * 48.0),
            Wait(1.5),
            Shot("settings-devices-empty"),
        ]);
    } else {
        match std::env::var("APASSY_TOUR") {
            Ok(file) => steps.extend(parse_steps(
                &std::fs::read_to_string(&file).expect("tour file"),
            )),
            Err(_) => steps.extend(view_steps()),
        }
    }
    // A live tour waits for more steps (`APASSY_TOUR_LIVE`) and ends on `quit`.
    if std::env::var_os("APASSY_TOUR_LIVE").is_none() {
        steps.push(Quit);
    }
    steps
}

/// Tour steps, one per line.
fn parse_steps(text: &str) -> Vec<Step> {
    use Step::*;
    let mut steps = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let num = |i: usize| {
            parts
                .get(i)
                .and_then(|p| p.parse::<f32>().ok())
                .unwrap_or(0.0)
        };
        let name = |i: usize| Box::leak(parts[i].to_owned().into_boxed_str()) as &'static str;
        match parts.first().copied() {
            Some("click") => steps.push(Click(num(1), num(2))),
            Some("scroll") => steps.push(Scroll(num(1), num(2), num(3))),
            Some("wait") => steps.push(Wait(f64::from(num(1)))),
            Some("shot") => steps.push(Shot(name(1))),
            Some("snap") => steps.push(Snap(name(1))),
            Some("size") => steps.push(Size(num(1), num(2))),
            Some("type") => steps.push(Type(Box::leak(parts[1..].join(" ").into_boxed_str()))),
            Some("paste") => steps.push(Paste(Box::leak(
                parts[1..].join(" ").replace("\\n", "\n").into_boxed_str(),
            ))),
            Some("key") => {
                let (key, modifiers) = parse_key(parts[1]);
                steps.push(Key(key, modifiers));
            }
            Some("embed") => steps.push(Embed(parts.get(1) != Some(&"off"))),
            Some("ask") => steps.push(Ask),
            Some("phone-asks") => steps.push(PhoneAsks),
            Some("plan") => steps.push(Plan(name(1))),
            Some("quit") => steps.push(Quit),
            Some("minimize") => steps.push(Minimize(true)),
            Some("restore") => steps.push(Minimize(false)),
            _ => {}
        }
    }
    steps
}

/// `cmd+shift+h` → the key and its modifiers.
fn parse_key(spec: &str) -> (egui::Key, egui::Modifiers) {
    let mut modifiers = egui::Modifiers::NONE;
    let mut key = None;
    for part in spec.split('+') {
        match part.to_ascii_lowercase().as_str() {
            "cmd" => modifiers |= egui::Modifiers::COMMAND,
            "ctrl" => modifiers |= egui::Modifiers::CTRL,
            "shift" => modifiers |= egui::Modifiers::SHIFT,
            "alt" => modifiers |= egui::Modifiers::ALT,
            name => {
                // `ArrowRight` as egui spells it, or `enter`, `n`, `comma`.
                key = egui::Key::from_name(part)
                    .or_else(|| egui::Key::from_name(name))
                    .or_else(|| egui::Key::from_name(&name.to_ascii_uppercase()))
                    .or_else(|| {
                        let mut chars = name.chars();
                        let first = chars.next()?.to_ascii_uppercase();
                        egui::Key::from_name(&format!("{first}{}", chars.as_str()))
                    })
            }
        }
    }
    (
        key.unwrap_or_else(|| panic!("unknown key {spec}")),
        modifiers,
    )
}

/// Write an sRGBA image as a PNG file: one IDAT, filter 0 on each row.
fn write_png(path: &Path, image: &egui::ColorImage) {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    let [width, height] = image.size;
    let mut raw = Vec::with_capacity(height * (width * 4 + 1));
    for row in image.pixels.chunks(width) {
        raw.push(0);
        for pixel in row {
            raw.extend_from_slice(&pixel.to_srgba_unmultiplied());
        }
    }
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::fast());
    zlib.write_all(&raw).expect("deflate");
    let data = zlib.finish().expect("deflate");
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |kind: &[u8], body: &[u8]| {
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        let mut crc = flate2::Crc::new();
        crc.update(kind);
        crc.update(body);
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out.extend_from_slice(&crc.sum().to_be_bytes());
    };
    let mut header = Vec::new();
    header.extend_from_slice(&(width as u32).to_be_bytes());
    header.extend_from_slice(&(height as u32).to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(b"IHDR", &header);
    chunk(b"IDAT", &data);
    chunk(b"IEND", &[]);
    std::fs::write(path, out).expect("png");
}

impl Tour {
    /// Live mode: when the steps run out, write `done` once, then take the steps of
    /// `next.txt` in `$APASSY_TOUR_LIVE` when it appears. A script drives the window
    /// one batch at a time and reads the result between batches.
    fn next_live_batch(&mut self) {
        let Some(dir) = std::env::var_os("APASSY_TOUR_LIVE").map(PathBuf::from) else {
            return;
        };
        if !self.live_idle {
            self.live_idle = true;
            let _ = std::fs::write(dir.join("done"), b"");
        }
        let next = dir.join("next.txt");
        if let Ok(text) = std::fs::read_to_string(&next) {
            let _ = std::fs::remove_file(&next);
            let _ = std::fs::remove_file(dir.join("done"));
            self.steps.extend(parse_steps(&text));
            self.live_idle = false;
        }
    }

    fn advance(&mut self, ctx: &egui::Context) {
        if self.snapping.is_some() {
            return;
        }
        if let Some(flag) = &self.waiting_for {
            if !flag.exists() {
                return;
            }
            let _ = std::fs::remove_file(flag);
            self.waiting_for = None;
            self.next_at = Instant::now() + Duration::from_millis(300);
        }
        if Instant::now() < self.next_at {
            return;
        }
        let Some(step) = self.steps.pop_front() else {
            self.next_live_batch();
            return;
        };
        let mut pause = 0.4;
        match step {
            Step::Wait(seconds) => pause = seconds,
            Step::Type(text) => self.events.push(egui::Event::Text(text.to_owned())),
            Step::Paste(text) => self.events.push(egui::Event::Paste(text.to_owned())),
            Step::Click(x, y) => {
                let pos = egui::pos2(x, y);
                self.events.push(egui::Event::PointerMoved(pos));
                for pressed in [true, false] {
                    self.events.push(egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    });
                }
                pause = 1.0;
            }
            Step::Scroll(x, y, dy) => {
                self.events
                    .push(egui::Event::PointerMoved(egui::pos2(x, y)));
                self.events.push(egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(0.0, dy),
                    phase: egui::TouchPhase::Move,
                    modifiers: egui::Modifiers::NONE,
                });
                pause = 1.0;
            }
            Step::Shot(name) => {
                // Move the pointer away, so no row shows a hover highlight.
                self.events.push(egui::Event::PointerGone);
                println!("SHOT {name}");
                let _ = std::io::stdout().flush();
                self.waiting_for = Some(PathBuf::from(format!("{name}.done")));
            }
            Step::Key(key, modifiers) => {
                // The press and the release come in two frames, as from a keyboard.
                let event = |pressed| egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed,
                    repeat: false,
                    modifiers,
                };
                self.events.push(event(true));
                self.next_frame.push(event(false));
            }
            Step::Size(width, height) => {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(width, height)));
                pause = 1.0;
            }
            Step::Snap(name) => {
                self.events.push(egui::Event::PointerGone);
                self.snapping = Some(name.to_owned());
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            }
            Step::Minimize(minimized) => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(minimized));
                if !minimized {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                pause = 1.0;
            }
            Step::Embed(on) => ctx.set_embed_viewports(on),
            Step::Ask => ask_in_background(),
            Step::Plan(name) => set_plan(&mut self.app, name),
            Step::PhoneAsks => {
                if let Some(relay) = self.relay.as_mut() {
                    relay.phone_asks();
                }
            }
            Step::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
        }
        self.next_at = Instant::now() + Duration::from_secs_f64(pause);
    }
}

impl eframe::App for Tour {
    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn on_exit(&mut self, gl: Option<&eframe::glow::Context>) {
        self.app.on_exit(gl);
    }

    /// The app answers the owner command line here, also while the window is hidden.
    /// The tour advances here too, so a minimized window still takes its steps.
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.app.logic(ctx, frame);
        self.advance(ctx);
        ctx.request_repaint_after(Duration::from_millis(50));
    }

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        self.app.clear_color(visuals)
    }

    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        for event in &raw_input.events {
            if let egui::Event::Screenshot { image, .. } = event
                && let Some(name) = self.snapping.take()
            {
                let dir = std::env::var("APASSY_SNAP_DIR").unwrap_or_else(|_| ".".to_owned());
                let path = Path::new(&dir).join(format!("{name}.png"));
                write_png(&path, image);
                println!("SNAP {}", path.display());
                let _ = std::io::stdout().flush();
                self.next_at = Instant::now() + Duration::from_millis(200);
            }
        }
        raw_input.events.append(&mut self.events);
        // Events of this step wait one frame; then they go in.
        self.events.append(&mut self.next_frame);
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.app.ui(ui, frame);
    }
}
