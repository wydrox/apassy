#![cfg(feature = "vault")]

//! Remembered answers of the owner and production allowances (ADR 0025 §3, §3b, §3c).
//! Synthetic values only.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{ApprovalRefusal, OwnerAction, OwnerCheck, OwnerGate, PendingRun};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::answers::AnswerScope;
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    Declaration, Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "owner-answers-pass-ok";
const SECRET: &str = "FAKE-owner-answer-secret-5521-canary";
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

fn project_key(dir: &Path) -> String {
    std::fs::canonicalize(dir.join(".git"))
        .expect("git")
        .display()
        .to_string()
}

/// A second project with `.git` next to the first one.
fn other_project(fx: &Fixture) -> PathBuf {
    let other = fx.dir.path().join("other");
    std::fs::create_dir_all(other.join(".git")).expect("other project");
    std::fs::canonicalize(other).expect("canonical")
}

fn deploy_call() -> String {
    format!("true deploy || {}", sentry_call())
}

/// Wait for the question of `script`, answer it with `answer`, and return the result.
fn answer_with(
    fx: &Fixture,
    cwd: &Path,
    script: &str,
    answer: impl FnOnce(PendingRun) -> OwnerAction,
) -> WireResponse {
    let handle = run_later(fx, cwd, script);
    let run = waiting(fx);
    owner(fx, answer(run)).expect("approved");
    handle.join().expect("run thread")
}

fn in_project(run: PendingRun) -> OwnerAction {
    let project = run.question.project.clone().expect("project");
    let action = run.question.action;
    OwnerAction::ApproveInProject {
        run,
        project,
        action,
    }
}

fn production(run: PendingRun) -> OwnerAction {
    let project = run.question.project.clone().expect("project");
    let action = run.question.action;
    OwnerAction::AllowProduction {
        run,
        project,
        action,
    }
}

/// Deny the next question and check that it waited.
fn asks(fx: &Fixture, cwd: &Path, script: &str) -> PendingRun {
    let handle = run_later(fx, cwd, script);
    let run = waiting(fx);
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    run
}

/// ADR 0025 §3, §3c: "Allow ACTION in PROJECT" covers every agent in the project, for
/// that kind of action only.
#[test]
fn allow_in_project_remembers_the_answer_for_all_agents_and_only_for_that_action() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let response = answer_with(&fx, &fx.project, &sentry_call(), in_project);
    assert!(response.ok, "{response:?}");
    let remembered = response.result.as_ref().expect("result")["remembered"]
        .as_str()
        .expect("remembered")
        .to_owned();
    assert!(remembered.contains("\"project\""), "{remembered}");
    let answers = with_vault(&fx, |v| v.answers_for_item(fx.item_id)).expect("answers");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].scope, AnswerScope::Project);
    assert_eq!(answers[0].action, ActionKind::Change);
    assert_eq!(answers[0].project.key, project_key(&fx.project));
    assert_eq!(answers[0].answered_on, "this Mac");
    // The same kind of action runs without a question, also for another agent.
    assert_eq!(
        decided_by(&run_in(&fx, &fx.project.join("sub"), &sentry_call())),
        "Remembered answer"
    );
    let other_token = with_vault(&fx, |v| {
        let (other, token) = v.register_agent("Other agent").expect("register");
        v.set_agent_sees_all(other.id, true).expect("see all");
        token.expose().to_owned()
    });
    let other = send_run(
        &fx.socket,
        &other_token,
        fx.item_id,
        &fx.project,
        &sentry_call(),
    );
    assert_eq!(decided_by(&other), "Remembered answer");
    assert_eq!(model_calls(&fx), 0);
    // Another kind of action and another project still ask.
    assert_eq!(
        asks(&fx, &fx.project, &deploy_call()).question.action,
        ActionKind::Deploy
    );
    let other_project = other_project(&fx);
    asks(&fx, &other_project, &sentry_call());
    let uses = with_vault(&fx, |v| v.item_uses(fx.item_id, 10)).expect("uses");
    assert!(
        uses.iter()
            .any(|u| u.decided_by == UseDecidedBy::Answer && u.outcome == UseOutcome::Allowed)
    );
    assert!(!format!("{uses:?} {answers:?}").contains(SECRET));
}

/// ADR 0010, ADR 0025 §3b: a production item waits at each run until the owner allows
/// production for the project and the kind of action. Then only that runs.
#[test]
fn production_asks_until_allow_production_then_only_for_that_project_and_action() {
    let fx = fixture(Some(declaration(Environment::Production, RiskLevel::Low)));
    // A certain model and "Allow once" do not lift the rule.
    let run = asks(&fx, &fx.project, &sentry_call());
    assert!(run.question.production);
    assert!(run.question.why.contains("is a production credential"));
    let once = answer_with(&fx, &fx.project, &sentry_call(), OwnerAction::ApproveRun);
    assert_eq!(decided_by(&once), "Owner approved");
    asks(&fx, &fx.project, &sentry_call());
    assert_eq!(
        model_calls(&fx),
        0,
        "the model is never asked for production"
    );

    let allowed = answer_with(&fx, &fx.project, &sentry_call(), production);
    assert!(allowed.ok, "{allowed:?}");
    let answers = with_vault(&fx, |v| v.answers_for_item(fx.item_id)).expect("answers");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].scope, AnswerScope::Production);
    assert_eq!(answers[0].action, ActionKind::Change);
    assert_eq!(
        decided_by(&run_in(&fx, &fx.project, &sentry_call())),
        "Remembered answer"
    );
    // Another kind of action and another project still wait.
    assert!(asks(&fx, &fx.project, &deploy_call()).question.production);
    let other_project = other_project(&fx);
    assert!(
        asks(&fx, &other_project, &sentry_call())
            .question
            .production
    );
    assert_eq!(model_calls(&fx), 0);
}

/// ADR 0025 §3b: only an owner answer makes a production allowance. A certain model,
/// "Allow once", "Approve and remember", a project answer, the usage log, and the
/// stricter answers never write one.
#[test]
fn no_path_except_allow_production_writes_a_production_answer() {
    let fx = fixture(Some(declaration(Environment::Production, RiskLevel::Low)));
    let no_production = |fx: &Fixture| {
        with_vault(fx, |v| {
            v.answers_for_item(fx.item_id)
                .expect("answers")
                .iter()
                .all(|answer| answer.scope != AnswerScope::Production)
        })
    };
    // History of the bouncer in the project does not count for production.
    with_vault(&fx, |v| {
        for _ in 0..3 {
            v.record_item_use(&NewItemUse {
                item_id: fx.item_id,
                agent_id: Some(fx.agent_id),
                agent_name: "First use agent".to_owned(),
                project_key: project_key(&fx.project),
                project_label: "project".to_owned(),
                action: ActionKind::Change,
                command_summary: "run sh -c true".to_owned(),
                hosts: Vec::new(),
                outcome: UseOutcome::Allowed,
                decided_by: UseDecidedBy::Bouncer,
                answered_on: String::new(),
                decision_log_id: None,
            })
            .expect("history");
        }
    });
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    assert!(run.remember.is_none(), "production teaches no pattern");
    assert_eq!(
        owner(&fx, OwnerAction::ApproveAndRemember(run.clone())),
        Err(ApprovalRefusal::NothingToRemember)
    );
    assert_eq!(
        owner(&fx, in_project(run.clone())),
        Err(ApprovalRefusal::ProductionNeedsAllowance)
    );
    owner(&fx, OwnerAction::ApproveRun(run)).expect("once");
    assert!(handle.join().expect("thread").ok);
    assert!(no_production(&fx));
    // The stricter answers write exceptions only.
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    with_vault(&fx, |v| {
        assert!(
            fx.broker
                .approvals()
                .deny_and_always_ask(run.id, v)
                .expect("deny")
        );
    });
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    assert!(no_production(&fx));
    assert_eq!(model_calls(&fx), 0);
    // Only "Allow production" makes one.
    let allowed = answer_with(&fx, &fx.project, &sentry_call(), production);
    assert!(allowed.ok, "{allowed:?}");
    assert!(!no_production(&fx));
}

/// A remembered answer must name the project and the kind of action of the question.
#[test]
fn an_answer_for_another_project_or_action_is_refused() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    let mut project = run.question.project.clone().expect("project");
    assert_eq!(
        owner(
            &fx,
            OwnerAction::ApproveInProject {
                run: run.clone(),
                project: project.clone(),
                action: ActionKind::Deploy,
            },
        ),
        Err(ApprovalRefusal::NoProject)
    );
    assert_eq!(
        owner(&fx, production(run.clone())),
        Err(ApprovalRefusal::NotProduction)
    );
    project.key.push_str("-other");
    assert_eq!(
        owner(
            &fx,
            OwnerAction::ApproveInProject {
                run: run.clone(),
                project,
                action: ActionKind::Change,
            },
        ),
        Err(ApprovalRefusal::NoProject)
    );
    // A question with another project in the run itself is another run.
    let mut changed = run.clone();
    changed.question.project = None;
    assert_eq!(
        owner(&fx, OwnerAction::ApproveRun(changed)),
        Err(ApprovalRefusal::Changed)
    );
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    with_vault(&fx, |v| {
        assert!(v.answers_for_item(fx.item_id).expect("answers").is_empty());
    });
}

/// Removing an answer needs no owner check; the next use asks again.
#[test]
fn a_removed_answer_asks_again() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    assert!(answer_with(&fx, &fx.project, &sentry_call(), in_project).ok);
    assert_eq!(
        decided_by(&run_in(&fx, &fx.project, &sentry_call())),
        "Remembered answer"
    );
    let id = with_vault(&fx, |v| v.answers_for_item(fx.item_id)).expect("answers")[0].id;
    assert!(with_vault(&fx, |v| v.remove_answer(id)).expect("remove"));
    // A use that a remembered answer allowed is no history.
    asks(&fx, &fx.project, &sentry_call());
}

/// Each passed owner check and each new question is counted (ADR 0025 §1).
#[test]
fn owner_checks_and_questions_are_counted() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let count = |fx: &Fixture| -> u64 {
        with_vault(fx, |v| v.interactions_per_week(1))
            .expect("count")
            .iter()
            .map(|(_, count)| count)
            .sum()
    };
    assert_eq!(count(&fx), 0);
    assert!(answer_with(&fx, &fx.project, &sentry_call(), OwnerAction::ApproveRun).ok);
    assert_eq!(count(&fx), 2, "one owner check and one question");
}

/// After a restore from a backup, no remembered answer, production allowance, or
/// history gives access without the owner.
#[test]
fn a_restore_clears_answers_and_old_history_does_not_count() {
    let fx = fixture(Some(declaration(Environment::Production, RiskLevel::Low)));
    assert!(answer_with(&fx, &fx.project, &sentry_call(), production).ok);
    let key = project_key(&fx.project);
    with_vault(&fx, |v| {
        v.record_item_use(&NewItemUse {
            item_id: fx.item_id,
            agent_id: Some(fx.agent_id),
            agent_name: "First use agent".to_owned(),
            project_key: key.clone(),
            project_label: "project".to_owned(),
            action: ActionKind::Read,
            command_summary: "run gh api user".to_owned(),
            hosts: Vec::new(),
            outcome: UseOutcome::Allowed,
            decided_by: UseDecidedBy::Bouncer,
            answered_on: String::new(),
            decision_log_id: None,
        })
        .expect("history");
        assert!(
            v.item_used_in_project(fx.item_id, &key, ActionKind::Read)
                .expect("history")
        );
        assert_eq!(v.answers_for_item(fx.item_id).expect("answers").len(), 1);
    });
    let backup = fx.dir.path().join("backup.db");
    with_vault(&fx, |v| v.backup(&backup)).expect("backup");
    let mut restored =
        Vault::restore(&backup, &fx.dir.path().join("restored.db"), PASS).expect("restore");
    restored.unlock(PASS).expect("unlock");
    assert!(
        restored
            .answers_for_item(fx.item_id)
            .expect("answers")
            .is_empty()
    );
    let (agent, _) = restored.register_agent("New agent").expect("register");
    restored
        .set_agent_sees_all(agent.id, true)
        .expect("see all");
    assert!(
        !restored
            .item_used_in_project(fx.item_id, &key, ActionKind::Read)
            .expect("history"),
        "the uses of revoked agents are no history"
    );
    assert!(restored.needs_review(fx.item_id).expect("review"));
}
