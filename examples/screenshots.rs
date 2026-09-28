//! Screenshots of the desktop app for the README and the site (scripts/screenshots.sh).
//!
//! `screenshots seed HOME`: make `HOME/Library/Application Support/Apassy/vault.db`
//! with synthetic credentials, agents, grants, activity, and decisions. Each value is
//! fake. The script uses a scratch HOME, never the owner's.
//!
//! `screenshots run`: open the real window for the vault of `$HOME`, type the
//! passphrase through the input hook of eframe, and walk the views. Before each view
//! it prints `SHOT <name>` and waits until the file `<name>.done` exists in the
//! current directory. The script then captures the window. No window input comes
//! from macOS, so the tour needs no Accessibility permission.

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::contracts::CredentialKind;
use apassy::desktop::{DesktopApp, native_options};
use apassy::vault::{
    ActivityDecision, DecidedBy, DecisionEntry, Declaration, Environment, ExecMode, ExecRule,
    Field, GrantPlace, ItemDraft, LoggedDecision, NewActivity, PatternKey, RequestSource,
    Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use eframe::egui;

const PASS: &str = "screenshots-demo-passphrase";
const DAY: u64 = 86_400;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, home] if cmd == "seed" => seed(Path::new(home)),
        [cmd] if cmd == "run" => run(),
        _ => {
            eprintln!("usage: screenshots seed HOME | screenshots run");
            std::process::exit(2);
        }
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

fn item(
    title: &str,
    kind: CredentialKind,
    notes: &str,
    tags: &[&str],
    fields: Vec<Field>,
) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind,
        notes: notes.to_owned(),
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
        fields,
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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn seed(home: &Path) {
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
    // Project folders as the owner would see them. The vault checks only that
    // they are absolute.
    let api = "/Users/you/code/acme-api".to_owned();
    let site = "/Users/you/code/acme-site".to_owned();

    let mut v = Vault::create(&path, PASS).expect("create");
    v.unlock(PASS).expect("unlock");

    let stripe = v
        .add(item(
            "Stripe test mode",
            CredentialKind::ApiKey,
            "Secret key of the acme-api sandbox account.",
            &["payments"],
            vec![field("token", "demo-stripe-test-key-not-real", true)],
        ))
        .expect("add")
        .id;
    let github = v
        .add(item(
            "GitHub deploy bot",
            CredentialKind::ApiKey,
            "Fine-grained token: contents and pull requests of acme/acme-api.",
            &["ci"],
            vec![field("token", "demo-github-token-not-real", true)],
        ))
        .expect("add")
        .id;
    let openai = v
        .add(item(
            "OpenAI API",
            CredentialKind::ApiKey,
            "Project key with a monthly budget of $50.",
            &["ai"],
            vec![field("token", "demo-openai-key-not-real", true)],
        ))
        .expect("add")
        .id;
    let cloudflare = v
        .add(item(
            "Cloudflare Workers",
            CredentialKind::ApiKey,
            "Edit Workers and R2 of the acme-site account.",
            &["hosting"],
            vec![field("token", "demo-cloudflare-token-not-real", true)],
        ))
        .expect("add")
        .id;
    let staging_db = v
        .add(item(
            "Staging database",
            CredentialKind::Database,
            "",
            &["postgres"],
            vec![
                field("host", "db.staging.acme.internal", false),
                field("database", "acme", false),
                field("username", "app", false),
                field("password", "demo-staging-password-not-real", true),
            ],
        ))
        .expect("add")
        .id;
    let prod_db = v
        .add(item(
            "Production database",
            CredentialKind::Database,
            "Read replica for debugging. Writes go through migrations only.",
            &["postgres"],
            vec![
                field("host", "db.acme.internal", false),
                field("database", "acme", false),
                field("username", "readonly", false),
                field("password", "demo-production-password-not-real", true),
            ],
        ))
        .expect("add")
        .id;
    let aws = v
        .add(item(
            "AWS S3 uploads",
            CredentialKind::ApiKey,
            "Access key of the preview bucket.",
            &["cloud"],
            vec![field("token", "demo-aws-secret-not-real", true)],
        ))
        .expect("add")
        .id;
    v.add(item(
        "Fly.io dashboard",
        CredentialKind::Login,
        "",
        &["hosting"],
        vec![
            field("username", "dev@acme.test", false),
            field("password", "demo-fly-password-not-real", true),
        ],
    ))
    .expect("add");
    v.add(item(
        "Build server",
        CredentialKind::SshKey,
        "Deploy key for ci-01.",
        &["ci"],
        vec![field("private_key", "demo-ssh-private-key-not-real", true)],
    ))
    .expect("add");

    for (id, decl) in [
        (
            stripe,
            declaration("acme-api", "development", "medium", "read-write", "partial"),
        ),
        (
            github,
            declaration(
                "acme-api",
                "production",
                "medium",
                "read-write",
                "reversible",
            ),
        ),
        (
            openai,
            declaration("acme-api", "development", "low", "read-write", "reversible"),
        ),
        (
            cloudflare,
            declaration("acme-site", "production", "high", "admin", "partial"),
        ),
        (
            staging_db,
            declaration("acme-api", "staging", "medium", "read-write", "partial"),
        ),
        (
            prod_db,
            declaration(
                "acme-api",
                "production",
                "high",
                "read-only",
                "irreversible",
            ),
        ),
        (
            aws,
            declaration("acme-site", "staging", "medium", "read-write", "reversible"),
        ),
    ] {
        v.set_declaration(id, &decl).expect("declaration");
    }
    for (id, env, name) in [
        (stripe, "STRIPE_SECRET_KEY", "token"),
        (github, "GITHUB_TOKEN", "token"),
        (openai, "OPENAI_API_KEY", "token"),
        (cloudflare, "CLOUDFLARE_API_TOKEN", "token"),
        (staging_db, "PGPASSWORD", "password"),
        (prod_db, "PROD_PGPASSWORD", "password"),
        (aws, "AWS_SECRET_ACCESS_KEY", "token"),
    ] {
        v.set_env_binding(id, env, name).expect("env binding");
    }

    let (claude, _) = v.register_agent("Claude Code").expect("agent");
    let (codex, _) = v.register_agent("Codex").expect("agent");
    let claude = claude.id;
    let codex = codex.id;
    v.set_exec_grants(
        claude,
        &[stripe, github, staging_db],
        &GrantPlace::Folder(api.clone()),
        ExecMode::Bouncer,
    )
    .expect("grant");
    v.set_exec_grant(claude, prod_db, &api, ExecMode::Ask)
        .expect("grant");
    v.set_exec_grants(
        codex,
        &[openai, cloudflare],
        &GrantPlace::Folder(site.clone()),
        ExecMode::Bouncer,
    )
    .expect("grant");
    v.set_exec_rule(
        claude,
        stripe,
        ExecRule {
            allowed_prefixes: Vec::new(),
            forbidden_words: vec!["refund".to_owned()],
            expires_at: None,
            max_runs_per_hour: Some(30),
            instruction: "Test mode only. Read balances and list objects. Never create refunds."
                .to_owned(),
        },
    )
    .expect("rule");
    v.set_exec_rule(
        claude,
        prod_db,
        ExecRule {
            allowed_prefixes: vec!["psql".to_owned()],
            forbidden_words: vec!["--force".to_owned(), "drop".to_owned()],
            expires_at: None,
            max_runs_per_hour: Some(10),
            instruction: "Read-only queries for debugging. Never run migrations.".to_owned(),
        },
    )
    .expect("rule");
    // ADR 0012: Codex sees the names of all credentials and asks for one.
    v.set_agent_sees_all(codex, true).expect("sees all");
    v.request_access(
        codex,
        aws,
        "Upload the preview build of acme-site to S3.",
        &site,
    )
    .expect("access request");

    // The activity log, oldest first: the view shows the newest on top.
    let runs: [(u64, &str, u64, &str, ActivityDecision, &str); 7] = [
        (
            claude,
            "Claude Code",
            github,
            "run git push origin feat/checkout",
            ActivityDecision::Allow,
            "The bouncer allowed it: it fits the task.",
        ),
        (
            codex,
            "Codex",
            openai,
            "run npm run eval -- --suite smoke",
            ActivityDecision::Allow,
            "The bouncer allowed it: it fits the task.",
        ),
        (
            claude,
            "Claude Code",
            staging_db,
            "run npm run migrate",
            ActivityDecision::Allow,
            "A remembered pattern allowed it.",
        ),
        (
            claude,
            "Claude Code",
            prod_db,
            "run psql -c \"select count(*) from orders\"",
            ActivityDecision::Allow,
            "The owner approved it.",
        ),
        (
            claude,
            "Claude Code",
            stripe,
            "run printenv STRIPE_SECRET_KEY",
            ActivityDecision::Deny,
            "The owner denied it: the command could print a secret.",
        ),
        (
            claude,
            "Claude Code",
            staging_db,
            "run npm run db:reset --force",
            ActivityDecision::Deny,
            "Your rule: never --force.",
        ),
        (
            claude,
            "Claude Code",
            stripe,
            "run stripe balance retrieve",
            ActivityDecision::Allow,
            "The bouncer allowed it: read-only.",
        ),
    ];
    for (agent_id, agent_name, item_id, operation, decision, reason) in runs {
        v.record_activity(&NewActivity {
            agent_id: Some(agent_id),
            agent_name: agent_name.to_owned(),
            item_id: Some(item_id),
            operation: operation.to_owned(),
            decision,
            reason: reason.to_owned(),
        })
        .expect("activity");
    }

    // Two weeks of decisions for the Learning view: the owner is asked less each week.
    let commands: [(&[&str], u64, &str); 6] = [
        (&["npm", "test"], staging_db, "PGPASSWORD"),
        (&["npm", "run", "migrate"], staging_db, "PGPASSWORD"),
        (
            &["stripe", "balance", "retrieve"],
            stripe,
            "STRIPE_SECRET_KEY",
        ),
        (&["git", "push", "origin", "HEAD"], github, "GITHUB_TOKEN"),
        (
            &["stripe", "customers", "list", "--limit", "5"],
            stripe,
            "STRIPE_SECRET_KEY",
        ),
        (&["gh", "pr", "create", "--fill"], github, "GITHUB_TOKEN"),
    ];
    let now = now();
    for day in 0..14u64 {
        let runs_today = 6 + (day % 4);
        // Runs half an hour apart, the last one of today a moment ago.
        let day_end = now - (13 - day) * DAY - 600;
        for n in 0..runs_today {
            let (command, item_id, env) = commands[((day * 7 + n * 3) % 6) as usize];
            // Early on, one run in two waits for the owner. After two weeks, one in ten.
            let asked = (n * 14) < (7 - day / 2).max(1) * runs_today;
            let denied = asked && n == 0 && day % 5 == 2;
            let decided_by = match (asked, denied) {
                (_, true) => DecidedBy::Owner,
                (true, false) => DecidedBy::Owner,
                (false, _) if day > 6 && n % 3 == 0 => DecidedBy::Pattern,
                _ => DecidedBy::Model,
            };
            v.record_decision(&DecisionEntry {
                at: day_end - (runs_today - 1 - n) * 1800,
                agent_id: claude,
                agent_name: "Claude Code".to_owned(),
                project_dir: api.clone(),
                cwd_rel: String::new(),
                items: vec![item_id],
                user_request: "Finish the checkout flow and its tests.".to_owned(),
                user_request_source: RequestSource::Host,
                command: command.iter().map(|arg| (*arg).to_owned()).collect(),
                purpose: "Run the task of the user.".to_owned(),
                env_names: vec![env.to_owned()],
                declarations: vec![None],
                rule_flags: Vec::new(),
                known_safe: false,
                model_facts: vec![
                    ("task_match".to_owned(), 0.93),
                    ("destroy".to_owned(), 0.02),
                ],
                pattern: command.join(" "),
                grant_asks: false,
                asked,
                decision: if denied {
                    LoggedDecision::Deny
                } else {
                    LoggedDecision::Allow
                },
                decided_by,
                remembered: false,
                policy: "apassy-bouncer-v7".to_owned(),
                note: String::new(),
                instruction: String::new(),
            })
            .expect("decision");
        }
    }
    // Remembered patterns: three owner approvals make a pattern active.
    for (item_id, template) in [
        (staging_db, "npm run migrate"),
        (stripe, "stripe balance retrieve"),
    ] {
        let key = PatternKey {
            agent_id: claude,
            project_dir: api.clone(),
            items: vec![item_id],
            policy: String::new(),
            cwd_rel: String::new(),
            template: template.to_owned(),
        };
        for n in 0..3 {
            v.remember_approval(&key, template, now - (3 - n) * DAY)
                .expect("pattern");
        }
    }
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

// ---------------------------------------------------------------- run

/// One step of the tour. Positions are in points of the 1180 x 800 window.
enum Step {
    Wait(f64),
    Type(&'static str),
    Click(f32, f32),
    Scroll(f32, f32, f32),
    Shot(&'static str),
    Quit,
}

struct Tour {
    app: DesktopApp,
    steps: VecDeque<Step>,
    events: Vec<egui::Event>,
    next_at: Instant,
    waiting_for: Option<PathBuf>,
}

fn run() {
    let steps = VecDeque::from(tour_steps());
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
            Ok(Box::new(Tour {
                app: DesktopApp::from_creation_context(cc),
                steps,
                events: Vec::new(),
                next_at: Instant::now() + Duration::from_secs(2),
                waiting_for: None,
            }))
        }),
    )
    .expect("window");
}

/// The tour. Positions are in points of the 1180 x 740 window. `APASSY_TOUR` names a
/// file with other steps after the unlock, one per line: `click X Y`, `scroll X Y DY`,
/// `wait S`, `shot NAME`. It helps to find the positions of a new layout.
fn tour_steps() -> Vec<Step> {
    use Step::*;
    let mut steps = vec![
        Type(PASS),
        Wait(0.5),
        Click(590.0, 461.0),
        Wait(3.5),
        Shot("vault"),
    ];
    match std::env::var("APASSY_TOUR") {
        Ok(file) => {
            for line in std::fs::read_to_string(&file).expect("tour file").lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let num = |i: usize| {
                    parts
                        .get(i)
                        .and_then(|p| p.parse::<f32>().ok())
                        .unwrap_or(0.0)
                };
                match parts.first().copied() {
                    Some("click") => steps.push(Click(num(1), num(2))),
                    Some("scroll") => steps.push(Scroll(num(1), num(2), num(3))),
                    Some("wait") => steps.push(Wait(f64::from(num(1)))),
                    Some("shot") => {
                        steps.push(Shot(Box::leak(parts[1].to_owned().into_boxed_str())))
                    }
                    _ => {}
                }
            }
        }
        Err(_) => steps.extend([
            // A production credential: its declaration and variable.
            Click(415.0, 675.0),
            Wait(1.5),
            Shot("credential"),
            // Claude Code: process access per credential, then its recent requests.
            Click(65.0, 92.0),
            Wait(1.0),
            Click(404.0, 135.0),
            Wait(1.5),
            Shot("agent"),
            Scroll(700.0, 500.0, -500.0),
            Wait(1.0),
            Shot("requests"),
            // Access requests and blocked runs.
            Click(65.0, 122.0),
            Wait(1.5),
            Shot("activity"),
            // The ask rate over two weeks.
            Click(65.0, 152.0),
            Wait(2.0),
            Shot("learning"),
        ]),
    }
    steps.push(Quit);
    steps
}

impl Tour {
    fn advance(&mut self, ctx: &egui::Context) {
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
            return;
        };
        let mut pause = 0.4;
        match step {
            Step::Wait(seconds) => pause = seconds,
            Step::Type(text) => self.events.push(egui::Event::Text(text.to_owned())),
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

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        self.app.clear_color(visuals)
    }

    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        raw_input.events.append(&mut self.events);
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.app.ui(ui, frame);
        self.advance(ui.ctx());
        ui.ctx().request_repaint_after(Duration::from_millis(50));
    }
}
