#![cfg(feature = "vault")]

//! Exceptions of one agent (ADR 0025 §3f): "Not for this agent", "Always ask for this
//! agent", "only these items", and the stricter answers to a question. Synthetic values
//! only.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::{
    AnswerKind, ApprovalRefusal, OwnerAction, OwnerCheck, OwnerGate, PendingRun,
};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::exceptions::{ExceptionKind, Standing};
use apassy::vault::usage::{UseDecidedBy, UseOutcome};
use apassy::vault::{
    Declaration, Environment, ExecMode, ExecRule, Field, ItemDraft, ONLY_MARKER_ITEM,
    Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "exceptions-pass-ok";
const SECRET: &str = "FAKE-exception-secret-8812-canary";
const ENV_NAME: &str = "SYNTH_SENTRY_KEY";

struct Fixture {
    _dir: TempDir,
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
        project: "project".to_owned(),
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
        _dir: dir,
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

fn catalog_ids(fx: &Fixture) -> Vec<u64> {
    let listed = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("answer");
    assert!(listed.ok, "{listed:?}");
    let data = listed.result.expect("result");
    assert!(!data.to_string().contains(SECRET));
    data["catalog"]
        .as_array()
        .expect("catalog")
        .iter()
        .map(|entry| entry["item_id"].as_u64().expect("id"))
        .collect()
}

/// A second usable item.
fn second_item(fx: &Fixture) -> u64 {
    with_vault(fx, |v| {
        let item = v
            .add(ItemDraft {
                title: "Second synthetic key".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("FAKE-second-exception-key".to_owned()),
                    secret: true,
                }],
            })
            .expect("add")
            .id;
        v.set_env_binding(item, "SYNTH_SECOND_KEY", "token")
            .expect("binding");
        item
    })
}

#[test]
fn never_hides_the_item_and_a_run_gets_not_granted() {
    let fx = fixture(Some(declaration(Environment::Development, RiskLevel::Low)));
    assert_eq!(catalog_ids(&fx), vec![fx.item_id]);
    with_vault(&fx, |v| {
        v.add_agent_exception(fx.agent_id, fx.item_id, ExceptionKind::Never)
    })
    .expect("never");
    assert!(catalog_ids(&fx).is_empty());
    let refused = run_in(&fx, &fx.project, &sentry_call());
    assert_eq!(code(&refused), "not_granted");
    // The same answer as for an item that does not exist.
    let unknown = send_run(&fx.socket, &fx.token, 9999, &fx.project, &sentry_call());
    assert_eq!(
        refused
            .error
            .as_ref()
            .map(|e| e.message.replace(&fx.item_id.to_string(), "N")),
        unknown
            .error
            .as_ref()
            .map(|e| e.message.replace("9999", "N"))
    );
    let request = client::send(
        &fx.socket,
        &fx.token,
        Action::RequestAccess {
            item_id: fx.item_id,
            reason: "Use the synthetic key.".into(),
            cwd: None,
        },
    )
    .expect("answer");
    assert_eq!(code(&request), "not_visible");
    assert!(fx.broker.approvals().pending().is_empty());
    assert_eq!(model_calls(&fx), 0);
    let uses = with_vault(&fx, |v| v.item_uses(fx.item_id, 10)).expect("uses");
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].outcome, UseOutcome::Refused);
    assert_eq!(uses[0].decided_by, UseDecidedBy::Rule);
}

/// ADR 0025 §3f: "only these items" shows and lets the agent use only its listed items.
/// The marker alone, with no listed item and no grant, hides everything, also when the
/// agent sees all credentials.
#[test]
fn only_lists_items_and_the_marker_alone_hides_everything() {
    let fx = fixture(Some(declaration(Environment::Development, RiskLevel::Low)));
    let second = second_item(&fx);
    let mut both = vec![fx.item_id, second];
    both.sort_unstable();
    let mut listed = catalog_ids(&fx);
    listed.sort_unstable();
    assert_eq!(listed, both);
    with_vault(&fx, |v| {
        v.add_agent_exception(fx.agent_id, fx.item_id, ExceptionKind::Only)
    })
    .expect("only");
    assert_eq!(catalog_ids(&fx), vec![fx.item_id]);
    assert_eq!(
        code(&send_run(
            &fx.socket,
            &fx.token,
            second,
            &fx.project,
            "true"
        )),
        "not_granted"
    );
    assert!(run_in(&fx, &fx.project, &sentry_call()).ok);
    // The marker stays when the last listed item goes.
    with_vault(&fx, |v| {
        assert!(
            v.remove_agent_exception(fx.agent_id, fx.item_id, ExceptionKind::Only)
                .expect("remove")
        );
        assert!(v.agent_sees_all(fx.agent_id).expect("see all"));
        assert_eq!(
            v.agent_item_standing(fx.agent_id, fx.item_id)
                .expect("standing"),
            Standing::Never
        );
        assert!(
            v.agent_exceptions(fx.agent_id)
                .expect("exceptions")
                .iter()
                .all(|exception| exception.item_id != ONLY_MARKER_ITEM),
            "the marker is never shown as an item"
        );
    });
    assert!(catalog_ids(&fx).is_empty());
    let listed = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("answer");
    assert_eq!(
        listed.result.expect("result")["sees_all_credentials"],
        false
    );
    assert_eq!(
        code(&run_in(&fx, &fx.project, &sentry_call())),
        "not_granted"
    );
    // "See all credentials" (an owner check in the app) removes the exception.
    with_vault(&fx, |v| v.set_agent_sees_all(fx.agent_id, true)).expect("see all");
    assert_eq!(catalog_ids(&fx).len(), 2);
}

/// An agent that does not see all credentials gets the marker, so it stays restricted.
#[test]
fn turning_see_all_off_restricts_the_agent_to_its_listed_items() {
    let fx = fixture(Some(declaration(Environment::Development, RiskLevel::Low)));
    with_vault(&fx, |v| v.set_agent_sees_all(fx.agent_id, false)).expect("off");
    assert!(catalog_ids(&fx).is_empty());
    assert_eq!(
        code(&run_in(&fx, &fx.project, &sentry_call())),
        "not_granted"
    );
}

/// "Always ask for this agent" asks at each use of this agent, also with a remembered
/// answer. Another agent uses the answer.
#[test]
fn always_ask_for_an_agent_asks_each_time_even_with_an_answer() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    let project = run.question.project.clone().expect("project");
    let action = run.question.action;
    owner(
        &fx,
        OwnerAction::ApproveInProject {
            run,
            project,
            action,
        },
    )
    .expect("approved");
    assert!(handle.join().expect("thread").ok);
    assert_eq!(
        decided_by(&run_in(&fx, &fx.project, &sentry_call())),
        "Remembered answer"
    );
    with_vault(&fx, |v| {
        v.add_agent_exception(fx.agent_id, fx.item_id, ExceptionKind::AlwaysAsk)
    })
    .expect("always ask");
    for _ in 0..2 {
        let handle = run_later(&fx, &fx.project, &sentry_call());
        let run = waiting(&fx);
        assert!(
            run.question.why.contains("always ask for this agent"),
            "{}",
            run.question.why
        );
        owner(&fx, OwnerAction::ApproveRun(run)).expect("once");
        assert_eq!(
            decided_by(&handle.join().expect("thread")),
            "Owner approved"
        );
    }
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
}

/// The stricter answers deny the run and need no owner check.
#[test]
fn stricter_answers_deny_and_make_the_agent_stricter_without_an_owner_check() {
    let fx = fixture(Some(declaration(Environment::Staging, RiskLevel::Medium)));
    // "Always ask for this agent".
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    with_vault(&fx, |v| {
        assert!(
            fx.broker
                .approvals()
                .deny_and_always_ask(run.id, v)
                .expect("deny")
        );
        assert_eq!(
            v.agent_item_standing(fx.agent_id, fx.item_id)
                .expect("standing"),
            Standing::AlwaysAsk
        );
    });
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    // A run that no longer waits changes nothing.
    with_vault(&fx, |v| {
        assert!(
            !fx.broker
                .approvals()
                .deny_and_never(run.id, v)
                .expect("not waiting")
        );
    });
    // "Not for this agent".
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    with_vault(&fx, |v| {
        assert!(
            fx.broker
                .approvals()
                .deny_and_never(run.id, v)
                .expect("deny")
        );
    });
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    assert_eq!(
        code(&run_in(&fx, &fx.project, &sentry_call())),
        "not_granted"
    );
    assert!(catalog_ids(&fx).is_empty());
    // Removing it gives authority back and needs an owner check.
    let proof = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(
            OwnerAction::RemoveAgentException {
                agent_id: fx.agent_id,
                item_id: fx.item_id,
                kind: ExceptionKind::Never,
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    assert!(matches!(
        proof.action(),
        OwnerAction::RemoveAgentException { .. }
    ));
    assert_eq!(
        fx.broker.approvals().approve(proof),
        Err(ApprovalRefusal::NotAnApproval)
    );
    with_vault(&fx, |v| {
        v.remove_agent_exception(fx.agent_id, fx.item_id, ExceptionKind::Never)
    })
    .expect("remove");
    // "Disconnect the agent".
    let handle = run_later(&fx, &fx.project, &sentry_call());
    let run = waiting(&fx);
    with_vault(&fx, |v| {
        assert!(
            fx.broker
                .approvals()
                .deny_and_disconnect(run.id, v)
                .expect("deny")
        );
    });
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    assert_eq!(
        code(&run_in(&fx, &fx.project, &sentry_call())),
        "unauthenticated"
    );
}

/// Gate 1 (C-F5): a process grant is no authority. A grant in "Ask me each time" made
/// after the upgrade does not ask, and its rule does not refuse: only exceptions do.
#[test]
fn a_process_grant_is_no_authority() {
    let fx = fixture(Some(declaration(Environment::Development, RiskLevel::Low)));
    with_vault(&fx, |v| {
        v.set_exec_grant(
            fx.agent_id,
            fx.item_id,
            &fx.project.display().to_string(),
            ExecMode::Ask,
        )?;
        v.set_exec_rule(
            fx.agent_id,
            fx.item_id,
            ExecRule {
                forbidden_words: vec!["curl".to_owned()],
                ..ExecRule::default()
            },
        )
    })
    .expect("grant");
    assert_eq!(
        decided_by(&run_in(&fx, &fx.project, &sentry_call())),
        "Bouncer allowed"
    );
    assert!(fx.broker.approvals().pending().is_empty());
}

fn connector_call(fx: &Fixture, item: u64) -> std::thread::JoinHandle<WireResponse> {
    let socket = fx.socket.clone();
    let token = fx.token.clone();
    std::thread::spawn(move || {
        client::send(
            &socket,
            &token,
            Action::Call {
                item_id: item,
                operation: "get_sales_summary".to_owned(),
                params: [
                    ("project_id", "project-a-synthetic"),
                    ("period_start", "2026-09-01"),
                    ("period_end", "2026-09-30"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            },
        )
        .expect("broker answer")
    })
}

/// Gate 1 (A-5, C-F4): the connector path keeps the standing rules of a run. "Always ask
/// for this agent", "Always ask me", and a production declaration wait for the owner;
/// "Not for this agent" refuses. Each decided use is in the use log.
#[test]
fn the_connector_path_respects_the_exceptions_and_production() {
    let fx = fixture(None);
    let item = with_vault(&fx, |v| {
        let item = v
            .add(ItemDraft {
                title: "Synthetic reporting key".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("FAKE-reporting-4417".to_owned()),
                    secret: true,
                }],
            })
            .expect("add")
            .id;
        v.set_destination(item, "reporting-api-v0", "https://reports.example.invalid")
            .expect("destination");
        v.set_grant(fx.agent_id, item, "get_sales_summary", true)
            .expect("grant");
        v.add_agent_exception(fx.agent_id, item, ExceptionKind::AlwaysAsk)
            .expect("always ask");
        item
    });
    let handle = connector_call(&fx, item);
    let run = waiting(&fx);
    assert_eq!(run.command[0], "apassy_use_credential");
    assert!(run.question.why.contains("always ask for this agent"), "{}", run.question.why);
    assert_eq!(run.question.item_ids, vec![item]);
    assert!(
        !run.question
            .valid_answers
            .iter()
            .any(|answer| matches!(answer, AnswerKind::InProject(_))),
        "a connector use has no project"
    );
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    let uses = with_vault(&fx, |v| v.item_uses(item, 5)).expect("uses");
    assert_eq!(uses[0].outcome, UseOutcome::Denied);
    assert_eq!(uses[0].decided_by, UseDecidedBy::Owner);
    assert_eq!(uses[0].hosts, vec!["reports.example.invalid".to_owned()]);

    // "Always ask me" of the item and a production declaration ask too.
    with_vault(&fx, |v| {
        v.remove_agent_exception(fx.agent_id, item, ExceptionKind::AlwaysAsk)?;
        v.set_always_ask(item, true)
    })
    .expect("always ask item");
    let handle = connector_call(&fx, item);
    let run = waiting(&fx);
    assert!(run.question.why.contains("is set to always ask"), "{}", run.question.why);
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");
    with_vault(&fx, |v| {
        v.set_always_ask(item, false)?;
        v.save_declaration(
            item,
            &declaration(Environment::Production, RiskLevel::Low),
            None,
            None,
        )
    })
    .expect("production");
    let handle = connector_call(&fx, item);
    let run = waiting(&fx);
    assert!(run.question.why.contains("production credential"), "{}", run.question.why);
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("thread")), "approval_denied");

    // "Not for this agent" hides the item: the connector grant does not count.
    with_vault(&fx, |v| {
        v.add_agent_exception(fx.agent_id, item, ExceptionKind::Never)
    })
    .expect("never");
    assert_eq!(
        code(&connector_call(&fx, item).join().expect("thread")),
        "not_granted"
    );
    assert!(fx.broker.approvals().pending().is_empty());
}
