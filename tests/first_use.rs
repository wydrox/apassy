#![cfg(feature = "vault")]

//! The bouncer decides from the first use (ADR 0025 §2, §3; it replaces ADR 0024 §1).
//! Synthetic values only.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{
    ApprovalRefusal, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate, PendingRun,
    folder_is_broad, shown_path,
};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::project::Project;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    Declaration, Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "first-use-pass-ok";
const SECRET: &str = "FAKE-first-use-secret-3307-canary";
const ENV_NAME: &str = "SYNTH_SENTRY_KEY";

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    /// A project with `.git`. Runs start in its `sub` folder.
    project: PathBuf,
    item_id: u64,
    agent_id: u64,
    token: String,
    broker: BrokerHandle,
    bouncer: common::FakeBouncer,
}

fn declaration(environment: Environment, risk: RiskLevel) -> Declaration {
    Declaration {
        project: "synthetic".to_owned(),
        environment,
        risk,
        scope: Scope::ReadWrite,
        reversibility: Reversibility::Reversible,
    }
}

/// An agent that sees all credentials, and one Sentry key with `declared`.
fn fixture(declared: Option<Declaration>) -> Fixture {
    fixture_with(declared, true, Duration::from_secs(10))
}

fn fixture_with(declared: Option<Declaration>, see_all: bool, wait: Duration) -> Fixture {
    let bouncer = common::fake_bouncer(&[]);
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(project.join("sub")).expect("project dir");
    std::fs::create_dir_all(project.join(".git")).expect("git dir");
    let project = std::fs::canonicalize(project).expect("canonical project");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let item = vault
        .add(ItemDraft {
            title: "Synthetic Sentry key".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(SECRET.to_owned()),
                secret: true,
            }],
        })
        .expect("add")
        .id;
    vault
        .set_env_binding(item, ENV_NAME, "token")
        .expect("binding");
    if let Some(declared) = &declared {
        vault
            .save_declaration(item, declared, Some("sentry"), None)
            .expect("declaration");
    }
    let (agent, token) = vault.register_agent("First use agent").expect("register");
    if see_all {
        vault.set_agent_sees_all(agent.id, true).expect("see all");
    }
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = wait;
    options.run_timeout = Duration::from_secs(20);
    options.bouncer = Some(BouncerClient::new(&bouncer.url).expect("bouncer url"));
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    Fixture {
        dir,
        vault: shared,
        socket,
        project,
        item_id: item,
        agent_id: agent.id,
        token: token.expose().to_owned(),
        broker,
        bouncer,
    }
}

/// A clean command: the key goes only to a host of its provider (Sentry).
fn sentry_call() -> String {
    format!("true || curl -s -H \"Authorization: Bearer ${ENV_NAME}\" https://sentry.io/api/0/")
}

fn send_run(socket: &Path, token: &str, item: u64, cwd: &Path, script: &str) -> WireResponse {
    client::send(
        socket,
        token,
        Action::Run {
            items: vec![item],
            command: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: cwd.display().to_string(),
            purpose: "Check the synthetic Sentry project.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Check the synthetic Sentry project.".into()),
        },
    )
    .expect("broker answer")
}

fn run_in(fx: &Fixture, cwd: &Path, script: &str) -> WireResponse {
    send_run(&fx.socket, &fx.token, fx.item_id, cwd, script)
}

fn run_later(fx: &Fixture, cwd: &Path, script: &str) -> std::thread::JoinHandle<WireResponse> {
    let socket = fx.socket.clone();
    let token = fx.token.clone();
    let item = fx.item_id;
    let cwd = cwd.to_path_buf();
    let script = script.to_owned();
    std::thread::spawn(move || send_run(&socket, &token, item, &cwd, &script))
}

fn code(response: &WireResponse) -> &str {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response.error.as_ref().map_or("", |e| e.code.as_str())
}

fn decided_by(response: &WireResponse) -> String {
    assert!(response.ok, "{response:?}");
    response.result.as_ref().expect("result")["decided_by"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault mutex");
    f(guard.as_mut().expect("open vault"))
}

/// The first waiting run, within 10 seconds.
fn waiting(fx: &Fixture) -> PendingRun {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(run) = fx.broker.approvals().pending().into_iter().next() {
            return run;
        }
        assert!(Instant::now() < end, "no run waits");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn owner(fx: &Fixture, action: OwnerAction) -> Result<(), ApprovalRefusal> {
    let proof = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(action, OwnerCheck::passphrase(PASS))
        .expect("owner check");
    fx.broker.approvals().approve(proof)
}

fn model_calls(fx: &Fixture) -> usize {
    fx.bouncer.bodies.lock().expect("bodies").len()
}

#[test]
fn an_agent_that_does_not_see_all_credentials_gets_not_granted_and_an_empty_catalog() {
    let fx = fixture_with(
        Some(declaration(Environment::Development, RiskLevel::Low)),
        false,
        Duration::from_secs(5),
    );
    assert_eq!(
        code(&run_in(&fx, &fx.project, &sentry_call())),
        "not_granted"
    );
    // An unknown item gets the same answer: the refusal names no item that exists.
    let unknown = send_run(&fx.socket, &fx.token, 9999, &fx.project, &sentry_call());
    assert_eq!(code(&unknown), "not_granted");
    assert!(fx.broker.approvals().pending().is_empty());
    let listed = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("answer");
    let data = listed.result.expect("result");
    assert_eq!(data["catalog"], serde_json::json!([]));
    assert_eq!(data["sees_all_credentials"], false);
}

/// ADR 0025 §3: an item without history in the project whose declaration is not
/// development with low risk asks the owner. The card says why. The model is not asked.
#[test]
fn a_first_use_without_history_asks_the_owner_and_says_why() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let handle = run_later(&fx, &fx.project.join("sub"), &sentry_call());
    let run = waiting(&fx);
    let question = &run.question;
    assert_eq!(question.id, run.id);
    assert_eq!(question.item_ids, vec![fx.item_id]);
    let project = question.project.as_ref().expect("a project");
    assert_eq!(project.root, fx.project);
    assert_eq!(project.label, "project");
    assert_eq!(
        Path::new(&project.key),
        std::fs::canonicalize(fx.project.join(".git")).expect("git")
    );
    assert_eq!(question.action, ActionKind::Change);
    assert!(!question.production);
    assert!(
        question.why.contains("was not used in \"project\""),
        "{}",
        question.why
    );
    assert_eq!(run.risk, question.why);
    assert!(!format!("{run:?}").contains(SECRET));
    assert_eq!(model_calls(&fx), 0, "the model is not asked");
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("run thread")), "approval_denied");
    let uses = with_vault(&fx, |v| v.item_uses(fx.item_id, 10)).expect("uses");
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].outcome, UseOutcome::Denied);
    assert_eq!(uses[0].decided_by, UseDecidedBy::Owner);
    assert_eq!(uses[0].hosts, vec!["sentry.io".to_owned()]);
    assert!(!format!("{uses:?}").contains(SECRET));
}

/// ADR 0025 §3: a development key of a known provider that goes to its hosts goes to the
/// model at first use; the next use with the same kind of action in the project runs
/// from its history, without a question and without the model.
#[test]
fn a_development_item_with_a_provider_host_and_history_runs_without_a_question() {
    let fx = fixture(Some(declaration(Environment::Development, RiskLevel::Low)));
    let first = run_in(&fx, &fx.project.join("sub"), &sentry_call());
    assert_eq!(decided_by(&first), "Bouncer allowed");
    assert_eq!(model_calls(&fx), 1);
    let second = run_in(&fx, &fx.project, &sentry_call());
    assert_eq!(decided_by(&second), "Bouncer allowed");
    assert_eq!(model_calls(&fx), 1, "history decided, not the model");
    assert!(fx.broker.approvals().pending().is_empty());
    let uses = with_vault(&fx, |v| v.item_uses(fx.item_id, 10)).expect("uses");
    assert_eq!(uses.len(), 2);
    assert!(
        uses.iter()
            .all(|u| u.outcome == UseOutcome::Allowed && u.decided_by == UseDecidedBy::Bouncer)
    );
    let text = format!("{first:?} {second:?}");
    assert!(!text.contains(SECRET));
}

/// The history of a project counts for every connected agent (ADR 0025 §3, §3c): a
/// staging key that the bouncer allowed in the project before runs for a new agent.
#[test]
fn history_in_the_project_lets_another_agent_run_without_a_question() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let project_key = std::fs::canonicalize(fx.project.join(".git"))
        .expect("git")
        .display()
        .to_string();
    let other_token = with_vault(&fx, |v| {
        let (other, token) = v.register_agent("Other agent").expect("register");
        v.set_agent_sees_all(other.id, true).expect("see all");
        v.record_item_use(&NewItemUse {
            item_id: fx.item_id,
            agent_id: Some(fx.agent_id),
            agent_name: "First use agent".to_owned(),
            project_key: project_key.clone(),
            project_label: "project".to_owned(),
            action: ActionKind::Change,
            command_summary: "run sh -c true".to_owned(),
            hosts: vec!["sentry.io".to_owned()],
            outcome: UseOutcome::Allowed,
            decided_by: UseDecidedBy::Bouncer,
            answered_on: String::new(),
            decision_log_id: None,
        })
        .expect("history");
        token.expose().to_owned()
    });
    let response = send_run(
        &fx.socket,
        &other_token,
        fx.item_id,
        &fx.project,
        &sentry_call(),
    );
    assert_eq!(decided_by(&response), "Bouncer allowed");
    assert_eq!(model_calls(&fx), 0);
    // Another kind of action has no history: it asks.
    let fx_deploy = format!("true deploy || {}", sentry_call());
    let handle = std::thread::spawn({
        let socket = fx.socket.clone();
        let item = fx.item_id;
        let cwd = fx.project.clone();
        move || send_run(&socket, &other_token, item, &cwd, &fx_deploy)
    });
    let run = waiting(&fx);
    assert_eq!(run.question.action, ActionKind::Deploy);
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
}

#[test]
fn allow_once_runs_and_remembers_nothing() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    owner(&fx, OwnerAction::ApproveRun(run)).expect("approved");
    let response = handle.join().expect("run thread");
    assert_eq!(decided_by(&response), "Owner approved");
    assert!(response.result.as_ref().expect("result")["remembered"].is_null());
    with_vault(&fx, |v| {
        assert!(v.answers_for_item(fx.item_id).expect("answers").is_empty());
    });
    // "Allow once" is no history: the next use asks again.
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
}

/// ADR 0025 §3: an agent has at most one waiting question.
#[test]
fn a_second_question_of_the_same_agent_gets_question_waiting() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let first = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    let other = run_in(
        &fx,
        &fx.project,
        &format!("true deploy || {}", sentry_call()),
    );
    assert_eq!(code(&other), "question_waiting");
    assert_eq!(fx.broker.approvals().pending().len(), 1);
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&first.join().expect("thread")), "approval_denied");
}

/// ADR 0025 §3e: the same request again joins the waiting question. The newest call gets
/// the answer, the older call ends, and one answer starts one run. Another agent never
/// gets the answer of this agent.
#[test]
fn the_same_request_again_joins_the_question_and_gets_only_its_own_answer() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let other_token = with_vault(&fx, |v| {
        let (other, token) = v.register_agent("Other agent").expect("register");
        v.set_agent_sees_all(other.id, true).expect("see all");
        token.expose().to_owned()
    });
    let older = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    let newer = run_later(&fx, &fx.project, &sentry_call());
    let older = older.join().expect("older call");
    assert_eq!(code(&older), "question_waiting");
    assert!(
        older
            .error
            .as_ref()
            .expect("error")
            .message
            .contains("newer"),
        "{older:?}"
    );
    assert_eq!(fx.broker.approvals().pending(), vec![run.clone()]);
    // The same request from another agent is its own question.
    let foreign = std::thread::spawn({
        let socket = fx.socket.clone();
        let item = fx.item_id;
        let cwd = fx.project.clone();
        let script = sentry_call();
        move || send_run(&socket, &other_token, item, &cwd, &script)
    });
    let end = Instant::now() + Duration::from_secs(10);
    while fx.broker.approvals().pending().len() < 2 {
        assert!(Instant::now() < end, "the other agent does not wait");
        std::thread::sleep(Duration::from_millis(5));
    }
    owner(&fx, OwnerAction::ApproveRun(run.clone())).expect("approved");
    let newer = newer.join().expect("newer call");
    assert_eq!(decided_by(&newer), "Owner approved");
    // The other agent still waits for its own answer.
    let pending = fx.broker.approvals().pending();
    assert_eq!(pending.len(), 1);
    assert_ne!(pending[0].id, run.id);
    assert_eq!(pending[0].agent, "Other agent");
    assert!(fx.broker.approvals().deny(pending[0].id));
    assert_eq!(code(&foreign.join().expect("thread")), "approval_denied");
}

/// "Always ask me" of an item asks at each use, also with a remembered answer.
#[test]
fn an_always_ask_item_asks_each_time() {
    let fx = fixture(Some(declaration(Environment::Development, RiskLevel::Low)));
    with_vault(&fx, |v| v.set_always_ask(fx.item_id, true)).expect("always ask");
    for _ in 0..2 {
        let handle = run_later(&fx, &fx.project, &sentry_call());
        let run = waiting(&fx);
        assert!(
            run.question.why.contains("is set to always ask"),
            "{}",
            run.question.why
        );
        let project = run.question.project.clone().expect("project");
        owner(
            &fx,
            OwnerAction::ApproveInProject {
                run,
                project,
                action: ActionKind::Change,
            },
        )
        .expect("approved");
        assert!(handle.join().expect("thread").ok);
    }
    assert_eq!(model_calls(&fx), 0);
}

/// The root, HOME, and any available macOS aliases of HOME and its ancestors.
fn broad_folders() -> Vec<PathBuf> {
    let mut folders = vec![PathBuf::from("/")];
    if let Some(home) = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .and_then(|home| std::fs::canonicalize(home).ok())
    {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::MetadataExt;

            let home_metadata = std::fs::metadata(&home).expect("home metadata");
            let relative_home = home.strip_prefix("/").expect("absolute home");
            for prefix in [Path::new("/.nofollow"), Path::new("/System/Volumes/Data")] {
                // Metadata identifies a real alias without reading HOME's contents.
                if std::fs::metadata(prefix.join(relative_home)).is_ok_and(|metadata| {
                    metadata.dev() == home_metadata.dev() && metadata.ino() == home_metadata.ino()
                }) {
                    for ancestor in home.ancestors() {
                        folders.push(
                            prefix.join(ancestor.strip_prefix("/").expect("absolute ancestor")),
                        );
                    }
                }
            }
        }
        folders.push(home);
    }
    folders
}

/// A folder that is no project asks, and nothing can be remembered there: a crafted
/// "Allow in PROJECT" is refused, "Allow once" works.
#[test]
fn a_root_home_or_alias_folder_asks_and_refuses_a_crafted_answer() {
    for cwd in broad_folders() {
        let fx = fixture(Some(declaration(Environment::Development, RiskLevel::Low)));
        let handle = run_later(&fx, &cwd, &sentry_call());
        let run = waiting(&fx);
        assert!(run.question.project.is_none(), "{}", cwd.display());
        assert!(run.question.why.contains("not a project"), "{}", run.risk);
        let crafted = Project {
            key: cwd.display().to_string(),
            label: "home".to_owned(),
            root: cwd.clone(),
        };
        assert_eq!(
            owner(
                &fx,
                OwnerAction::ApproveInProject {
                    run: run.clone(),
                    project: crafted,
                    action: ActionKind::Change,
                },
            ),
            Err(ApprovalRefusal::NoProject)
        );
        assert_eq!(fx.broker.approvals().pending().len(), 1);
        owner(&fx, OwnerAction::ApproveRun(run)).expect("approved once");
        assert!(handle.join().expect("thread").ok);
        with_vault(&fx, |v| {
            assert!(v.answers_for_item(fx.item_id).expect("answers").is_empty());
        });
    }
}

#[test]
fn a_project_folder_is_not_broad_and_a_path_shown_has_no_control_or_direction_characters() {
    let fx = fixture(None);
    assert!(!folder_is_broad(&fx.project.display().to_string()));
    assert!(!folder_is_broad(
        &fx.project.join("sub").display().to_string()
    ));
    let linked_project = fx.dir.path().join("linked-project");
    std::os::unix::fs::symlink(&fx.project, &linked_project).expect("project symlink");
    assert!(!folder_is_broad(&linked_project.display().to_string()));
    let long = format!("/a/{}/end\u{202e}\n", "x".repeat(300));
    let shown = shown_path(&long, 60);
    assert_eq!(shown.chars().count(), 60);
    assert!(shown.starts_with("/a/") && shown.contains('…'), "{shown}");
    assert!(shown.ends_with("end??"), "{shown}");
    assert_eq!(shown_path("/short", 60), "/short");
}

/// A phone approves a run once only: it cannot remember an answer or allow production.
#[test]
fn a_phone_cannot_remember_an_answer() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    let project = run.question.project.clone().expect("project");
    for action in [
        OwnerAction::ApproveInProject {
            run: run.clone(),
            project: project.clone(),
            action: ActionKind::Change,
        },
        OwnerAction::AllowProduction {
            run: run.clone(),
            project,
            action: ActionKind::Change,
        },
    ] {
        let refused = OwnerGate::new(Arc::clone(&fx.vault), None).authorize(
            action,
            OwnerCheck::Companion {
                device_id: "synthetic-phone".to_owned(),
                time: 0,
                signature: vec![0; 8],
            },
        );
        assert!(matches!(refused, Err(OwnerAuthError::CompanionUnsupported)));
    }
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
}

#[test]
fn the_catalog_names_the_variable_and_the_folder_of_each_usable_credential() {
    let fx = fixture(None);
    with_vault(&fx, |v| {
        let work = v.create_folder(None, "Work").expect("folder");
        let sentry = v.create_folder(Some(&work.uuid), "Sentry").expect("folder");
        v.set_item_folder(fx.item_id, Some(&sentry.uuid))
            .expect("move");
    });
    let response = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("answer");
    assert!(response.ok, "{response:?}");
    let data = response.result.expect("result");
    let entry = &data["catalog"][0];
    assert_eq!(entry["access"], "can_request");
    assert_eq!(entry["env_name"], ENV_NAME);
    assert_eq!(entry["folder"], serde_json::json!(["Work", "Sentry"]));
    assert!(!data.to_string().contains(SECRET));
}

/// OTP setup keys require an explicit owner-selected field before any use.
#[test]
fn otp_only_items_are_needs_field_in_the_broker_catalog_and_cannot_be_used() {
    for (kind, name, value) in [
        (
            CredentialKind::Custom,
            "x_4f6e652d74696d652070617373776f7264",
            "GEZDGNBVGY3TQOJQ",
        ),
        (
            CredentialKind::Custom,
            "api_secret",
            "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ",
        ),
        (
            CredentialKind::ApiKey,
            "token",
            "otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ",
        ),
    ] {
        let mut fx = fixture(None);
        fx.item_id = with_vault(&fx, |vault| {
            vault
                .add(ItemDraft {
                    title: "Synthetic OTP-only credential".to_owned(),
                    kind,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: name.to_owned(),
                        value: SecretValue::new(value.to_owned()),
                        secret: true,
                    }],
                })
                .expect("synthetic OTP item")
                .id
        });
        let response = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("catalog");
        assert!(response.ok, "{response:?}");
        let data = response.result.expect("catalog result");
        let entry = data["catalog"]
            .as_array()
            .expect("catalog entries")
            .iter()
            .find(|entry| entry["item_id"] == fx.item_id)
            .expect("OTP catalog entry");
        assert_eq!(entry["access"], "needs_field", "{entry}");
        assert!(!data.to_string().contains(value), "setup key in catalog");
        assert_eq!(code(&run_in(&fx, &fx.project, "true")), "needs_field");
        assert!(fx.broker.approvals().pending().is_empty());
    }
}
