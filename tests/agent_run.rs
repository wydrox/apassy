#![cfg(feature = "vault")]

//! Process runs with secrets in the environment (ADR 0006). Synthetic values only.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{
    ApprovalRefusal, OwnerAction, OwnerCheck, OwnerGate, OwnerProof, PendingRun,
};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::model_server::ModelGate;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::sync::{FolderSync, SyncConfig};
use apassy::vault::exceptions::ExceptionKind;
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    ActivityDecision, Declaration, EnvDelivery, Environment, ExecMode, ExecRule, Field, ItemDraft,
    Reversibility, RiskLevel, Scope, SecretValue, Vault, VaultErrorKind,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "agent-run-pass-ok";
const SECRET: &str = "FAKE-run-secret-5521-canary";
const ENV_NAME: &str = "DEMO_API_KEY";

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    project: PathBuf,
    item_id: u64,
    agent_id: u64,
    token: String,
    broker: BrokerHandle,
}

/// A fixture with a fake bouncer that finds no risk.
fn fixture(mode: ExecMode, approval_timeout: Duration) -> Fixture {
    let bouncer = common::fake_bouncer(&[]);
    fixture_with(mode, approval_timeout, Some(&bouncer.url), None)
}

fn fixture_with(
    mode: ExecMode,
    approval_timeout: Duration,
    bouncer: Option<&str>,
    model_gate: Option<Arc<dyn ModelGate>>,
) -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(project.join("sub")).expect("project dir");
    let project = std::fs::canonicalize(project).expect("canonical project");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let item = vault
        .add(ItemDraft {
            title: "Demo API key".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(SECRET.to_owned()),
                secret: true,
            }],
        })
        .expect("add");
    vault
        .set_env_binding(item.id, ENV_NAME, "token")
        .expect("binding");
    let (agent, token) = vault.register_agent("Run agent").expect("register");
    vault
        .set_exec_grant(agent.id, item.id, &project.display().to_string(), mode)
        .expect("exec grant");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = approval_timeout;
    options.run_timeout = Duration::from_secs(20);
    options.bouncer = bouncer.map(|url| BouncerClient::new(url).expect("bouncer url"));
    options.model_gate = model_gate;
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    Fixture {
        vault: shared,
        socket,
        project,
        item_id: item.id,
        agent_id: agent.id,
        token: token.expose().to_owned(),
        broker,
        dir,
    }
}

fn run(fx: &Fixture, cwd: &std::path::Path, script: &str) -> WireResponse {
    send_run(&fx.socket, &fx.token, fx.item_id, cwd, script)
}

fn send_run(
    socket: &std::path::Path,
    token: &str,
    item_id: u64,
    cwd: &std::path::Path,
    script: &str,
) -> WireResponse {
    client::send(
        socket,
        token,
        Action::Run {
            items: vec![item_id],
            command: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: cwd.display().to_string(),
            purpose: "Test the process mode.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Test the process mode.".into()),
        },
    )
    .expect("broker answer")
}

/// [`run`] in the project on another thread.
fn spawn_run(fx: &Fixture, script: &str) -> std::thread::JoinHandle<WireResponse> {
    let socket = fx.socket.clone();
    let token = fx.token.clone();
    let item_id = fx.item_id;
    let cwd = fx.project.clone();
    let script = script.to_owned();
    std::thread::spawn(move || send_run(&socket, &token, item_id, &cwd, &script))
}

fn code(response: &WireResponse) -> &str {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response.error.as_ref().map_or("", |e| e.code.as_str())
}

fn no_secret(value: &impl std::fmt::Debug) {
    let text = format!("{value:?}");
    assert!(!text.contains(SECRET), "secret leaked: {text}");
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault mutex");
    f(guard.as_mut().expect("open vault"))
}

/// The owner confirms the approval of `run` with the passphrase now (goal item A4).
fn owner_check(vault: &SharedVault, run: PendingRun) -> OwnerProof {
    OwnerGate::new(Arc::clone(vault), None)
        .authorize(OwnerAction::ApproveRun(run), OwnerCheck::passphrase(PASS))
        .expect("owner check")
}

/// Wait for one pending run, then decide it on another thread. An approval passes the
/// owner check before `before` runs, so `before` can change the vault after the check.
fn decide_later(fx: &Fixture, approve: bool, before: impl FnOnce() + Send + 'static) {
    decide_later_with_name(fx, approve, ENV_NAME.to_owned(), before);
}

fn decide_later_with_name(
    fx: &Fixture,
    approve: bool,
    env_name: String,
    before: impl FnOnce() + Send + 'static,
) {
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    std::thread::spawn(move || {
        let pending = loop {
            if let Some(run) = approvals.pending().into_iter().next() {
                break run;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(pending.env_names, vec![env_name]);
        assert!(!format!("{pending:?}").contains(SECRET));
        let proof = approve.then(|| owner_check(&vault, pending.clone()));
        before();
        match proof {
            Some(proof) => {
                let _ = approvals.approve(proof);
            }
            None => {
                approvals.deny(pending.id);
            }
        }
    });
}

#[test]
fn an_unbound_credential_uses_a_runtime_name_and_masks_output() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(5));
    with_vault(&fx, |vault| {
        vault.clear_env_binding(fx.item_id).expect("clear binding");
        assert!(
            vault
                .exec_grants_for_agent(fx.agent_id)
                .expect("grants")
                .is_empty()
        );
        vault
            .set_exec_grant(
                fx.agent_id,
                fx.item_id,
                &fx.project.display().to_string(),
                ExecMode::Ask,
            )
            .expect("grant without an owner variable");
        assert!(
            vault
                .env_binding(fx.item_id)
                .expect("stored binding")
                .is_none()
        );
    });
    let listed = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("list");
    assert!(listed.ok, "{listed:?}");
    no_secret(&listed);
    let env_name = listed.result.expect("result")["process_access"][0]["env_name"]
        .as_str()
        .expect("runtime name")
        .to_owned();
    assert_eq!(env_name, format!("APASSY_ITEM_{}", fx.item_id));
    decide_later_with_name(&fx, true, env_name.clone(), || {});
    let response = run(
        &fx,
        &fx.project,
        &format!("echo len=${{#{env_name}}}; echo \"${env_name}\"; echo \"${env_name}\" >&2"),
    );
    assert!(response.ok, "{response:?}");
    no_secret(&response);
    let result = response.result.expect("result");
    assert_eq!(result["exit_code"], 0);
    let stdout = result["stdout"].as_str().expect("stdout");
    assert!(stdout.contains(&format!("len={}", SECRET.len())));
    let mask = format!("[apassy:{env_name}]");
    assert!(stdout.contains(&mask));
    assert!(result["stderr"].as_str().expect("stderr").contains(&mask));
    assert_eq!(result["secrets_in_environment"], json!([env_name]));
    with_vault(&fx, |vault| {
        assert!(
            vault
                .env_binding(fx.item_id)
                .expect("stored binding")
                .is_none()
        );
    });
}

#[test]
fn duplicate_runtime_variable_names_stop_the_run_before_secret_use() {
    for automatic in [false, true] {
        let fx = fixture(ExecMode::Ask, Duration::from_secs(2));
        let collision_name = if automatic {
            format!("APASSY_ITEM_{}", fx.item_id)
        } else {
            ENV_NAME.to_owned()
        };
        let second = with_vault(&fx, |vault| {
            if automatic {
                vault.clear_env_binding(fx.item_id).expect("clear binding");
                vault
                    .set_exec_grant(
                        fx.agent_id,
                        fx.item_id,
                        &fx.project.display().to_string(),
                        ExecMode::Ask,
                    )
                    .expect("automatic grant");
            }
            let second = vault
                .add(ItemDraft {
                    title: "Second synthetic key".into(),
                    kind: CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: "token".into(),
                        value: SecretValue::new("FAKE-second-collision-canary".into()),
                        secret: true,
                    }],
                })
                .expect("second item");
            vault
                .set_env_binding(second.id, "SECOND_KEY", "token")
                .expect("second binding");
            vault
                .set_exec_grant(
                    fx.agent_id,
                    second.id,
                    &fx.project.display().to_string(),
                    ExecMode::Ask,
                )
                .expect("second grant");
            // Simulate an old synced binding. This database and passphrase belong
            // only to the synthetic temporary fixture, never to a live vault.
            let database = rusqlite::Connection::open(vault.path()).expect("synthetic database");
            database
                .pragma_update(None, "key", PASS)
                .expect("synthetic key");
            database
                .execute(
                    "UPDATE env_binding SET env_name = ?1 WHERE item_id = ?2",
                    (
                        &collision_name,
                        i64::try_from(second.id).expect("SQL item ID"),
                    ),
                )
                .expect("legacy duplicate binding");
            assert_eq!(
                vault
                    .process_binding(fx.item_id)
                    .expect("first binding")
                    .expect("first")
                    .env_name,
                collision_name
            );
            assert_eq!(
                vault
                    .process_binding(second.id)
                    .expect("second binding")
                    .expect("second")
                    .env_name,
                collision_name
            );
            second.id
        });
        let response = client::send(
            &fx.socket,
            &fx.token,
            Action::Run {
                items: vec![fx.item_id, second],
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "touch command-started".into(),
                ],
                cwd: fx.project.display().to_string(),
                purpose: "Use both synthetic credentials.".into(),
                path: Some("/usr/bin:/bin".into()),
                user_request: Some("Use both synthetic credentials.".into()),
            },
        )
        .expect("broker answer");
        assert_eq!(code(&response), "duplicate_env_name", "{response:?}");
        no_secret(&response);
        assert!(!format!("{response:?}").contains("FAKE-second-collision-canary"));
        assert!(!fx.project.join("command-started").exists());
        assert!(fx.broker.approvals().pending().is_empty());
        with_vault(&fx, |vault| {
            for item in [fx.item_id, second] {
                assert_eq!(
                    vault
                        .runs_in_last_hour(fx.agent_id, item)
                        .expect("run count"),
                    0
                );
            }
        });
    }
}

#[test]
fn approved_run_gets_the_secret_and_masks_output() {
    // The heuristics flag a command that prints the secret, so the owner approves it.
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(5));
    decide_later(&fx, true, || {});
    let response = run(
        &fx,
        &fx.project.join("sub"),
        "echo len=${#DEMO_API_KEY}; echo \"$DEMO_API_KEY\"; echo \"$DEMO_API_KEY\" >&2; pwd",
    );
    assert!(response.ok, "{response:?}");
    let result = response.result.clone().expect("result");
    assert_eq!(result["exit_code"], 0);
    let stdout = result["stdout"].as_str().unwrap_or_default();
    assert!(
        stdout.contains(&format!("len={}", SECRET.len())),
        "{stdout}"
    );
    assert!(stdout.contains("[apassy:DEMO_API_KEY]"));
    assert!(stdout.contains("/project/sub"));
    assert!(
        result["stderr"]
            .as_str()
            .unwrap_or_default()
            .contains("[apassy:DEMO_API_KEY]")
    );
    no_secret(&response);

    let activity = with_vault(&fx, |v| v.recent_activity(5).expect("activity"));
    assert_eq!(activity[0].decision, ActivityDecision::Allow);
    assert!(activity[0].operation.starts_with("run /bin/sh"));
    assert!(
        activity[0]
            .reason
            .contains("Purpose: Test the process mode.")
    );
    no_secret(&activity);
}

#[test]
fn a_placeholder_variable_gets_a_placeholder_and_the_run_proxy() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(5));
    with_vault(&fx, |vault| {
        vault
            .set_env_binding_with(
                fx.item_id,
                ENV_NAME,
                "token",
                &EnvDelivery::Placeholder(vec!["api.example.invalid".to_owned()]),
            )
            .expect("placeholder binding");
    });
    decide_later(&fx, true, || {});
    let response = run(
        &fx,
        &fx.project,
        "printf '%s' \"$DEMO_API_KEY\" | rev; echo; echo \"len=${#DEMO_API_KEY} proxy=${HTTPS_PROXY:+set}\"",
    );
    assert!(response.ok, "{response:?}");
    let result = response.result.clone().expect("result");
    let stdout = result["stdout"].as_str().unwrap_or_default();
    let reversed: String = SECRET.chars().rev().collect();
    assert!(
        !stdout.contains(&reversed),
        "the process has the value: {stdout}"
    );
    // The placeholder has the length of the value.
    assert!(
        stdout.contains(&format!("len={} proxy=set", SECRET.len())),
        "{stdout}"
    );
    assert_eq!(result["placeholders"], json!([ENV_NAME]));
    assert_eq!(result["network"]["proxy"], true);
    assert_eq!(result["network"]["only_proxy"], cfg!(target_os = "macos"));
    assert_eq!(result["network"]["requests"], json!([]));
    no_secret(&response);
    let history = with_vault(&fx, |vault| {
        vault.item_events(fx.item_id, 5).expect("history")
    });
    assert_eq!(
        history[0].detail,
        "DEMO_API_KEY, placeholder for api.example.invalid"
    );

    // A host that is not valid, and a variable name that the proxy uses, are refused.
    with_vault(&fx, |vault| {
        for hosts in [
            vec![],
            vec!["https://api.example.com".to_owned()],
            vec!["API.example.com".to_owned()],
        ] {
            assert_eq!(
                vault
                    .set_env_binding_with(
                        fx.item_id,
                        ENV_NAME,
                        "token",
                        &EnvDelivery::Placeholder(hosts.clone()),
                    )
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput,
                "{hosts:?}"
            );
        }
        assert!(
            vault
                .set_env_binding(fx.item_id, "HTTPS_PROXY", "token")
                .is_err()
        );
    });
}

/// ADR 0013: the result of a run goes only to the vault that decided it. When another
/// vault takes the shared slot during the run, it gets no entry of that run.
#[test]
fn a_run_result_stays_in_the_vault_of_the_run() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(5));
    decide_later(&fx, true, || {});
    let mut other = Vault::create(&fx.dir.path().join("other.db"), PASS).expect("create");
    other.unlock(PASS).expect("unlock");
    let started = fx.project.join("started");
    let swapper = {
        let vault = Arc::clone(&fx.vault);
        let started = started.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !started.exists() {
                assert!(Instant::now() < deadline, "the command did not start");
                std::thread::sleep(Duration::from_millis(10));
            }
            vault.lock().expect("vault").replace(other)
        })
    };
    let response = run(
        &fx,
        &fx.project,
        &format!("touch '{}'; sleep 1; echo done", started.display()),
    );
    assert!(response.ok, "{response:?}");
    let first = swapper.join().expect("swap").expect("the first vault");
    assert!(
        with_vault(&fx, |v| v.recent_activity(10).expect("activity")).is_empty(),
        "the other vault has no entry of the run"
    );
    assert!(
        first
            .recent_activity(10)
            .expect("activity")
            .iter()
            .all(|entry| !entry.reason.contains("Exit code")),
        "the result of a run in a vault that left the slot is not recorded"
    );
}

/// ADR 0025: a grant is no authority. Outside its folder the grant gives nothing: the
/// item has no declaration and no history there, so the run waits for the owner.
#[test]
fn working_directory_must_stay_in_the_project() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_millis(500));
    assert_eq!(code(&run(&fx, fx.dir.path(), "true")), "approval_timeout");

    let escape = fx.project.join("escape");
    std::os::unix::fs::symlink(fx.dir.path(), &escape).expect("symlink");
    assert_eq!(code(&run(&fx, &escape, "true")), "approval_timeout");

    assert_eq!(
        code(&run(&fx, &fx.project.join("missing"), "true")),
        "invalid_request"
    );
    let activity = with_vault(&fx, |v| v.recent_activity(5).expect("activity"));
    assert!(
        activity
            .iter()
            .all(|e| e.decision == ActivityDecision::Deny)
    );
}

#[test]
fn ask_mode_waits_for_the_owner() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(5));
    decide_later(&fx, true, || {});
    let approved = run(&fx, &fx.project, "echo ok");
    assert!(approved.ok, "{approved:?}");
    assert_eq!(approved.result.as_ref().expect("result")["stdout"], "ok\n");

    decide_later(&fx, false, || {});
    assert_eq!(code(&run(&fx, &fx.project, "echo no")), "approval_denied");
}

#[test]
fn ask_mode_times_out_without_a_decision() {
    let fx = fixture(ExecMode::Ask, Duration::from_millis(300));
    assert_eq!(
        code(&run(&fx, &fx.project, "echo late")),
        "approval_timeout"
    );
    assert!(fx.broker.approvals().pending().is_empty());
}

#[test]
fn revoke_or_lock_during_approval_stops_the_run() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(5));
    let vault = Arc::clone(&fx.vault);
    let agent_id = fx.agent_id;
    decide_later(&fx, true, move || {
        let mut guard = vault.lock().expect("vault");
        guard
            .as_mut()
            .expect("open")
            .revoke_agent(agent_id)
            .expect("revoke");
    });
    assert_eq!(code(&run(&fx, &fx.project, "echo x")), "unauthenticated");

    let fx = fixture(ExecMode::Ask, Duration::from_secs(5));
    let vault = Arc::clone(&fx.vault);
    decide_later(&fx, true, move || {
        let mut guard = vault.lock().expect("vault");
        guard.as_mut().expect("open").lock().expect("lock");
    });
    // The lock makes the approval invalid, whether it comes before or after the decision.
    assert_eq!(
        code(&run(&fx, &fx.project, "echo x")),
        "approval_invalidated"
    );
}

#[test]
fn a_changed_process_binding_invalidates_a_pending_approval() {
    for change in ["name", "field", "delivery", "hosts", "automatic"] {
        let fx = fixture(ExecMode::Ask, Duration::from_secs(5));
        with_vault(&fx, |vault| {
            if change == "field" {
                let revision = vault.details(fx.item_id).expect("item").summary.revision;
                vault
                    .update(
                        fx.item_id,
                        revision,
                        ItemDraft {
                            title: "Demo API key".to_owned(),
                            kind: CredentialKind::ApiKey,
                            notes: String::new(),
                            tags: Vec::new(),
                            fields: vec![
                                Field {
                                    name: "token".into(),
                                    value: SecretValue::new(SECRET.into()),
                                    secret: true,
                                },
                                Field {
                                    name: "selected_key".into(),
                                    value: SecretValue::new("FAKE-selected-key-canary".into()),
                                    secret: true,
                                },
                            ],
                        },
                    )
                    .expect("add another field");
            }
            if matches!(change, "delivery" | "hosts") {
                vault
                    .set_env_binding_with(
                        fx.item_id,
                        ENV_NAME,
                        "token",
                        &EnvDelivery::Placeholder(vec!["api.example.invalid".into()]),
                    )
                    .expect("placeholder");
            }
        });
        let vault = Arc::clone(&fx.vault);
        let item_id = fx.item_id;
        let agent_id = fx.agent_id;
        let project = fx.project.clone();
        decide_later(&fx, true, move || {
            let mut guard = vault.lock().expect("vault");
            let vault = guard.as_mut().expect("open");
            match change {
                "name" => vault
                    .set_env_binding(item_id, "CHANGED_KEY", "token")
                    .expect("name"),
                "field" => vault
                    .set_env_binding(item_id, ENV_NAME, "selected_key")
                    .expect("field"),
                "delivery" => vault
                    .set_env_binding(item_id, ENV_NAME, "token")
                    .expect("real value"),
                "hosts" => vault
                    .set_env_binding_with(
                        item_id,
                        ENV_NAME,
                        "token",
                        &EnvDelivery::Placeholder(vec!["different.example.invalid".into()]),
                    )
                    .expect("hosts"),
                "automatic" => {
                    vault.clear_env_binding(item_id).expect("clear");
                    vault
                        .set_exec_grant(
                            agent_id,
                            item_id,
                            &project.display().to_string(),
                            ExecMode::Ask,
                        )
                        .expect("grant with automatic name");
                }
                _ => unreachable!(),
            }
        });
        let response = run(
            &fx,
            &fx.project,
            "touch command-started; echo \"$DEMO_API_KEY\"",
        );
        assert_eq!(
            code(&response),
            "authorization_changed",
            "{change}: {response:?}"
        );
        no_secret(&response);
        assert!(!fx.project.join("command-started").exists(), "{change}");
        assert_eq!(
            with_vault(&fx, |v| v.runs_in_last_hour(agent_id, item_id)).expect("run count"),
            0
        );
    }
}

#[test]
fn a_changed_grant_declaration_or_item_invalidates_a_pending_approval() {
    // A process grant is no authority any more (ADR 0025): a change of its mode, place,
    // or rule changes no decision. An exception of the agent does.
    for change in ["exception", "declaration", "provider", "revision"] {
        let fx = fixture(ExecMode::Ask, Duration::from_secs(5));
        if change == "provider" {
            with_vault(&fx, |vault| {
                vault
                    .save_declaration(
                        fx.item_id,
                        &Declaration {
                            project: "project".into(),
                            environment: Environment::Development,
                            risk: RiskLevel::Low,
                            scope: Scope::ReadOnly,
                            reversibility: Reversibility::Reversible,
                        },
                        Some("github"),
                        None,
                    )
                    .expect("initial provider");
            });
        }
        let vault = Arc::clone(&fx.vault);
        let item_id = fx.item_id;
        let agent_id = fx.agent_id;
        decide_later(&fx, true, move || {
            let mut guard = vault.lock().expect("vault");
            let vault = guard.as_mut().expect("open");
            match change {
                "exception" => vault
                    .add_agent_exception(agent_id, item_id, ExceptionKind::AlwaysAsk)
                    .expect("exception"),
                "declaration" => vault
                    .set_declaration(
                        item_id,
                        &Declaration {
                            project: "Changed project".into(),
                            environment: Environment::Production,
                            risk: RiskLevel::High,
                            scope: Scope::Admin,
                            reversibility: Reversibility::Irreversible,
                        },
                    )
                    .expect("declaration"),
                "provider" => {
                    let declaration = vault
                        .declaration(item_id)
                        .expect("declaration")
                        .expect("present");
                    vault
                        .save_declaration(item_id, &declaration, Some("openai"), None)
                        .expect("change provider only");
                }
                "revision" => {
                    let revision = vault.details(item_id).expect("item").summary.revision;
                    vault
                        .update(
                            item_id,
                            revision,
                            ItemDraft {
                                title: "Changed API key".into(),
                                kind: CredentialKind::ApiKey,
                                notes: String::new(),
                                tags: Vec::new(),
                                fields: vec![Field {
                                    name: "token".into(),
                                    value: SecretValue::new("FAKE-replaced-key-canary".into()),
                                    secret: true,
                                }],
                            },
                        )
                        .expect("replace secret");
                }
                _ => unreachable!(),
            }
        });
        let response = run(
            &fx,
            &fx.project,
            "touch command-started; echo \"$DEMO_API_KEY\"",
        );
        assert_eq!(
            code(&response),
            "authorization_changed",
            "{change}: {response:?}"
        );
        no_secret(&response);
        assert!(!fx.project.join("command-started").exists(), "{change}");
        assert_eq!(
            with_vault(&fx, |v| v.runs_in_last_hour(agent_id, item_id)).expect("run count"),
            0
        );
    }
}

/// The value that the second Mac saves. A run must never show it either.
const MERGED_SECRET: &str = "FAKE-merged-secret-7730-canary";

/// The fixture vault synced through a temporary folder (ADR 0014), and a second Mac that
/// adopted it. The broker keeps the vault of the first Mac.
struct SecondMac {
    _root: TempDir,
    /// The sync of the vault of the broker.
    here: FolderSync,
    there: FolderSync,
    vault: Vault,
}

impl SecondMac {
    fn item_id(&self) -> u64 {
        self.vault
            .search("")
            .expect("search")
            .into_iter()
            .find(|summary| summary.title == "Demo API key")
            .expect("synced credential")
            .id
    }

    /// Change the credential on the second Mac and push it.
    fn change(&mut self, change: &str) {
        let item_id = self.item_id();
        match change {
            "value" => {
                let revision = self.vault.details(item_id).expect("item").summary.revision;
                self.vault
                    .update(
                        item_id,
                        revision,
                        ItemDraft {
                            title: "Demo API key".into(),
                            kind: CredentialKind::ApiKey,
                            notes: String::new(),
                            tags: Vec::new(),
                            fields: vec![Field {
                                name: "token".into(),
                                value: SecretValue::new(MERGED_SECRET.into()),
                                secret: true,
                            }],
                        },
                    )
                    .expect("new value");
            }
            "hosts" => self
                .vault
                .set_env_binding_with(
                    item_id,
                    ENV_NAME,
                    "token",
                    &EnvDelivery::Placeholder(vec![
                        "api.stripe.invalid".into(),
                        "collector.example.invalid".into(),
                    ]),
                )
                .expect("wider hosts"),
            _ => unreachable!(),
        }
        assert!(
            self.there.sync(&mut self.vault).expect("sync b").pushed,
            "{change}"
        );
    }
}

fn synced(fx: &Fixture) -> SecondMac {
    let root = TempDir::new().expect("temp dir");
    let service = root.path().join("Dropbox");
    std::fs::create_dir_all(&service).expect("sync service folder");
    let folder = service.join("Apassy");
    let here = FolderSync::new(SyncConfig::in_data_dir(
        fx.dir.path(),
        &fx.dir.path().join("vault.db"),
        &folder,
        "vault",
    ));
    let file = with_vault(fx, |vault| {
        here.enable(vault, "Personal").expect("enable").file_name
    });
    let data = root.path().join("mac-b").join("Apassy");
    std::fs::create_dir_all(&data).expect("data dir");
    let there = FolderSync::new(SyncConfig::in_data_dir(
        &data,
        &data.join("vault.db"),
        &folder,
        "vault",
    ));
    let (mut vault, _) = there.adopt(&file, PASS).expect("adopt");
    vault.unlock(PASS).expect("unlock b");
    SecondMac {
        _root: root,
        here,
        there,
        vault,
    }
}

/// The first waiting run other than `not`.
fn next_pending(fx: &Fixture, not: Option<u64>) -> PendingRun {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(run) = fx
            .broker
            .approvals()
            .pending()
            .into_iter()
            .find(|run| Some(run.id) != not)
        {
            return run;
        }
        assert!(Instant::now() < deadline, "no waiting run");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn no_merged_secret(value: &impl std::fmt::Debug) {
    no_secret(value);
    let text = format!("{value:?}");
    assert!(
        !text.contains(MERGED_SECRET),
        "merged secret leaked: {text}"
    );
}

/// ADR 0014 §6: the worker syncs while a run waits for the owner. A merge of a change
/// from another Mac (a new value, or wider hosts) after the question showed makes the
/// owner's approval of that question refuse the run: the run never starts with a
/// version that the owner did not see.
#[test]
fn a_merged_change_from_another_mac_refuses_a_waiting_run() {
    for change in ["value", "hosts"] {
        let fx = fixture(ExecMode::Ask, Duration::from_secs(10));
        with_vault(&fx, |vault| {
            vault
                .set_env_binding_with(
                    fx.item_id,
                    ENV_NAME,
                    "token",
                    &EnvDelivery::Placeholder(vec!["api.stripe.invalid".into()]),
                )
                .expect("placeholder");
        });
        let mut mac_b = synced(&fx);
        mac_b.change(change);
        let here = mac_b.here.clone();
        let vault = Arc::clone(&fx.vault);
        // The owner checks the card as it shows, then the merge comes, then the answer.
        decide_later(&fx, true, move || {
            let mut guard = vault.lock().expect("vault");
            let outcome = here
                .sync(guard.as_mut().expect("open"))
                .expect("merge on this Mac");
            assert!(outcome.merge.is_some(), "{outcome:?}");
        });
        let response = run(
            &fx,
            &fx.project,
            "touch command-started; echo \"$DEMO_API_KEY\"",
        );
        assert_eq!(
            code(&response),
            "authorization_changed",
            "{change}: {response:?}"
        );
        no_merged_secret(&response);
        assert!(!fx.project.join("command-started").exists(), "{change}");
        assert_eq!(
            with_vault(&fx, |v| v.runs_in_last_hour(fx.agent_id, fx.item_id)).expect("run count"),
            0
        );
        // The merge took the change of the other Mac.
        with_vault(&fx, |vault| {
            let binding = vault
                .env_binding(fx.item_id)
                .expect("binding")
                .expect("some");
            match change {
                "value" => assert_eq!(
                    vault.reveal(fx.item_id, "token").expect("reveal").expose(),
                    MERGED_SECRET
                ),
                _ => assert_eq!(
                    binding.delivery,
                    EnvDelivery::Placeholder(vec![
                        "api.stripe.invalid".into(),
                        "collector.example.invalid".into(),
                    ])
                ),
            }
        });
    }
}

/// The same request again after a merge (the agent's host ended the first call) does
/// not join the question that showed before the merge. That question ends, and its
/// approval does nothing. The new call asks again, and only the new card starts the run.
#[test]
fn the_same_request_after_a_merged_change_asks_again() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(20));
    let mut mac_b = synced(&fx);
    mac_b.change("value");
    let script = "touch command-started; echo len=${#DEMO_API_KEY}; echo \"$DEMO_API_KEY\"";

    let first = spawn_run(&fx, script);
    let old = next_pending(&fx, None);
    let old_card = owner_check(&fx.vault, old.clone());
    with_vault(&fx, |vault| {
        let outcome = mac_b.here.sync(vault).expect("merge on this Mac");
        assert!(outcome.merge.is_some(), "{outcome:?}");
    });
    let second = spawn_run(&fx, script);
    let response = first.join().expect("first call");
    assert_eq!(code(&response), "question_waiting", "{response:?}");
    no_merged_secret(&response);

    let new = next_pending(&fx, Some(old.id));
    assert_eq!(
        fx.broker.approvals().pending().len(),
        1,
        "the old card ended"
    );
    assert_eq!(
        fx.broker.approvals().approve(old_card),
        Err(ApprovalRefusal::NotWaiting)
    );
    assert!(!fx.project.join("command-started").exists());

    fx.broker
        .approvals()
        .approve(owner_check(&fx.vault, new))
        .expect("approve the new card");
    let response = second.join().expect("second call");
    assert!(response.ok, "{response:?}");
    no_merged_secret(&response);
    let stdout = response.result.expect("result")["stdout"]
        .as_str()
        .expect("stdout")
        .to_owned();
    assert!(
        stdout.contains(&format!("len={}", MERGED_SECRET.len())),
        "{stdout}"
    );
    assert!(stdout.contains(&format!("[apassy:{ENV_NAME}]")), "{stdout}");
}

struct ChangedBindingGate {
    target: Mutex<Option<(SharedVault, u64)>>,
}

impl std::fmt::Debug for ChangedBindingGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChangedBindingGate")
    }
}

impl ModelGate for ChangedBindingGate {
    fn before_model(&self) -> Result<(), String> {
        let (vault, item_id) = self
            .target
            .lock()
            .expect("target")
            .take()
            .expect("set target");
        vault
            .lock()
            .expect("vault")
            .as_mut()
            .expect("open")
            .set_env_binding(item_id, "CHANGED_KEY", "token")
            .expect("change during model phase");
        Ok(())
    }
}

#[test]
fn a_changed_binding_invalidates_a_model_decision_without_an_owner_prompt() {
    let bouncer = common::fake_bouncer(&[]);
    let gate = Arc::new(ChangedBindingGate {
        target: Mutex::new(None),
    });
    let fx = fixture_with(
        ExecMode::Bouncer,
        Duration::from_secs(2),
        Some(&bouncer.url),
        Some(gate.clone()),
    );
    *gate.target.lock().expect("target") = Some((Arc::clone(&fx.vault), fx.item_id));
    with_vault(&fx, |vault| {
        vault
            .set_declaration(
                fx.item_id,
                &Declaration {
                    project: "project".into(),
                    environment: Environment::Development,
                    risk: RiskLevel::Low,
                    scope: Scope::ReadOnly,
                    reversibility: Reversibility::Reversible,
                },
            )
            .expect("declaration");
    });
    let response = run(&fx, &fx.project, "echo done; node -e 0");
    assert_eq!(code(&response), "authorization_changed", "{response:?}");
    assert!(fx.broker.approvals().pending().is_empty());
    assert_eq!(bouncer.bodies.lock().expect("model requests").len(), 1);
    assert_eq!(
        with_vault(&fx, |vault| vault
            .runs_in_last_hour(fx.agent_id, fx.item_id))
        .expect("run count"),
        0
    );
    no_secret(&response);
}

fn first_pending(approvals: &broker::approvals::ApprovalQueue) -> PendingRun {
    loop {
        if let Some(run) = approvals.pending().into_iter().next() {
            return run;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Goal item V3: the broker starts with no open vault, and an opened vault starts locked.
#[test]
fn startup_is_locked() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("vault.db");
    let (token, item_id) = {
        let mut vault = Vault::create(&path, PASS).expect("create");
        assert!(vault.is_locked(), "a new vault starts locked");
        vault.unlock(PASS).expect("unlock");
        let item = vault
            .add(ItemDraft {
                title: "Startup key".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new(SECRET.to_owned()),
                    secret: true,
                }],
            })
            .expect("add");
        let (_, token) = vault.register_agent("Startup agent").expect("register");
        (token.expose().to_owned(), item.id)
    };
    let slot: SharedVault = Arc::new(Mutex::new(None));
    let socket = dir.path().join("run").join("broker.sock");
    let options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    let _broker = broker::start_with(Arc::clone(&slot), &socket, options).expect("broker");
    let run_request = || Action::Run {
        items: vec![item_id],
        command: vec!["true".into()],
        cwd: dir.path().display().to_string(),
        purpose: "Start.".into(),
        path: None,
        user_request: Some("Start.".into()),
    };
    // No vault file is open when the app starts.
    for action in [Action::ListAccess, run_request()] {
        let response = client::send(&socket, &token, action).expect("answer");
        assert_eq!(code(&response), "vault_locked");
    }
    // The owner opens the file. It is locked until the owner types the passphrase.
    *slot.lock().expect("slot") = Some(Vault::open(&path).expect("open"));
    assert!(
        slot.lock()
            .expect("slot")
            .as_ref()
            .expect("open")
            .is_locked()
    );
    for action in [Action::ListAccess, run_request()] {
        let response = client::send(&socket, &token, action).expect("answer");
        assert_eq!(code(&response), "vault_locked");
    }
    slot.lock()
        .expect("slot")
        .as_mut()
        .expect("open")
        .unlock(PASS)
        .expect("unlock");
    let list = client::send(&socket, &token, Action::ListAccess).expect("answer");
    assert!(list.ok, "{list:?}");
}

/// Goal item V3: a lock ends every waiting run. Nobody calls `invalidate_all` here:
/// the broker sees the new vault epoch by itself.
#[test]
fn lock_ends_waiting_runs() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(10));
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    let locker = std::thread::spawn(move || {
        let old = first_pending(&approvals);
        let mut guard = vault.lock().expect("vault");
        guard.as_mut().expect("open").lock().expect("lock");
        old
    });
    let marker = fx.project.join("ran");
    let started = Instant::now();
    let response = run(&fx, &fx.project, &format!("touch '{}'", marker.display()));
    let old = locker.join().expect("locker");
    assert_eq!(code(&response), "approval_invalidated");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the run ended early"
    );
    assert!(fx.broker.approvals().pending().is_empty());
    assert!(!marker.exists());

    // After the owner unlocks again, the old run cannot be approved, also with a
    // passed owner check.
    with_vault(&fx, |v| v.unlock(PASS).expect("unlock"));
    assert_eq!(
        fx.broker.approvals().approve(owner_check(&fx.vault, old)),
        Err(ApprovalRefusal::NotWaiting)
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(!marker.exists());
}

/// Goal item V3: an approval that the broker did not use before a lock is not valid
/// after the unlock. The owner thread holds the vault while it approves, locks, and
/// unlocks, so the broker cannot use the approval in between. The owner check runs
/// before the thread takes the vault, because the check reads the vault too.
#[test]
fn approval_before_lock_is_not_valid_after_unlock() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(10));
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    let owner = std::thread::spawn(move || {
        let pending = first_pending(&approvals);
        let proof = owner_check(&vault, pending);
        let mut guard = vault.lock().expect("vault");
        assert_eq!(approvals.approve(proof), Ok(()), "the owner approves");
        let vault = guard.as_mut().expect("open");
        vault.lock().expect("lock");
        vault.unlock(PASS).expect("unlock");
    });
    let marker = fx.project.join("ran");
    let response = run(&fx, &fx.project, &format!("touch '{}'", marker.display()));
    owner.join().expect("owner");
    assert_eq!(code(&response), "approval_invalidated");
    assert!(!marker.exists(), "the approved command did not run");
    let activity = with_vault(&fx, |v| v.recent_activity(1).expect("activity"));
    assert_eq!(activity[0].decision, ActivityDecision::Deny);
    assert!(
        activity[0].reason.contains("The approval is not valid"),
        "{}",
        activity[0].reason
    );

    // A new request in the new session runs after a new approval.
    decide_later(&fx, true, || {});
    let again = run(&fx, &fx.project, "echo again");
    assert!(again.ok, "{again:?}");
}

/// Goal item V3: a stop of the broker ends every waiting run. After a restart, the
/// vault is locked, and an approval from before the restart matches no run.
#[test]
fn restart_ends_waiting_runs_and_old_approvals() {
    let mut fx = fixture(ExecMode::Ask, Duration::from_secs(10));
    let marker = fx.project.join("ran");
    let waiter = {
        let (socket, token) = (fx.socket.clone(), fx.token.clone());
        let action = Action::Run {
            items: vec![fx.item_id],
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("touch '{}'", marker.display()),
            ],
            cwd: fx.project.display().to_string(),
            purpose: "Test the restart.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Test the restart.".into()),
        };
        std::thread::spawn(move || client::send(&socket, &token, action))
    };
    let old_approvals = Arc::clone(fx.broker.approvals());
    let old = first_pending(&old_approvals);
    let old_id = old.id;
    fx.broker.stop();
    let response = waiter.join().expect("waiter").expect("answer");
    assert_eq!(code(&response), "approval_invalidated");
    assert_eq!(
        old_approvals.approve(owner_check(&fx.vault, old.clone())),
        Err(ApprovalRefusal::NotWaiting),
        "the stopped queue takes no decision"
    );

    // Restart: close the vault file, open it again, and start a new broker.
    *fx.vault.lock().expect("vault") = None;
    let slot: SharedVault = Arc::new(Mutex::new(Some(
        Vault::open(&fx.dir.path().join("vault.db")).expect("open"),
    )));
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_millis(500);
    let restarted = broker::start_with(Arc::clone(&slot), &fx.socket, options).expect("restart");
    assert_eq!(code(&run(&fx, &fx.project, "true")), "vault_locked");
    slot.lock()
        .expect("slot")
        .as_mut()
        .expect("open")
        .unlock(PASS)
        .expect("unlock");

    let approvals = Arc::clone(restarted.approvals());
    let new_slot = Arc::clone(&slot);
    let owner = std::thread::spawn(move || {
        let new_id = first_pending(&approvals).id;
        let used_old = approvals.approve(owner_check(&new_slot, old)).is_ok();
        (new_id, used_old)
    });
    let response = run(&fx, &fx.project, &format!("touch '{}'", marker.display()));
    let (new_id, used_old) = owner.join().expect("owner");
    assert_ne!(new_id, old_id);
    assert!(
        !used_old,
        "an approval from before the restart matches no run"
    );
    assert_eq!(code(&response), "approval_timeout");
    assert!(!marker.exists());
}

#[test]
fn grants_and_bindings_are_checked() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(2));
    with_vault(&fx, |v| {
        let err = v.set_env_binding(fx.item_id, "PATH", "token").unwrap_err();
        assert_eq!(err.kind(), VaultErrorKind::InvalidInput);
        let err = v
            .set_env_binding(fx.item_id, "DYLD_INSERT_LIBRARIES", "token")
            .unwrap_err();
        assert_eq!(err.kind(), VaultErrorKind::InvalidInput);
        let err = v
            .set_env_binding(fx.item_id, "OTHER", "missing")
            .unwrap_err();
        assert_eq!(err.kind(), VaultErrorKind::InvalidInput);
        let err = v
            .set_exec_grant(fx.agent_id, fx.item_id, "relative/dir", ExecMode::Bouncer)
            .unwrap_err();
        assert_eq!(err.kind(), VaultErrorKind::InvalidInput);
        v.clear_env_binding(fx.item_id).expect("clear binding");
        assert!(
            v.exec_grants_for_agent(fx.agent_id)
                .expect("grants")
                .is_empty()
        );
    });
    assert_eq!(code(&run(&fx, &fx.project, "true")), "not_granted");

    let other = client::send(
        &fx.socket,
        &fx.token,
        Action::Run {
            items: vec![fx.item_id, fx.item_id],
            command: vec!["true".into()],
            cwd: fx.project.display().to_string(),
            purpose: "x".into(),
            path: None,
            user_request: None,
        },
    )
    .expect("answer");
    assert_eq!(code(&other), "invalid_request");
}

#[test]
fn restore_removes_process_grants() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(2));
    let backup = fx.dir.path().join("backup.db");
    with_vault(&fx, |v| v.backup(&backup).expect("backup"));
    let mut restored =
        Vault::restore(&backup, &fx.dir.path().join("restored.db"), PASS).expect("restore");
    restored.unlock(PASS).expect("unlock");
    assert!(
        restored
            .exec_grants_for_agent(fx.agent_id)
            .expect("grants")
            .is_empty()
    );
    assert!(restored.env_binding(fx.item_id).expect("binding").is_some());
}

/// Goal item V4: a restore revokes every agent and removes every grant and rule. Items
/// with agent settings wait for the owner review. The broker refuses a run with such an
/// item until the owner confirms the settings.
#[test]
fn restore_needs_owner_review_before_runs() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(2));
    let plain = with_vault(&fx, |v| {
        v.set_declaration(
            fx.item_id,
            &Declaration {
                project: "project".to_owned(),
                environment: Environment::Staging,
                risk: RiskLevel::Medium,
                scope: Scope::ReadWrite,
                reversibility: Reversibility::Reversible,
            },
        )
        .expect("declaration");
        v.set_exec_rule(
            fx.agent_id,
            fx.item_id,
            ExecRule {
                allowed_prefixes: vec!["echo".to_owned()],
                ..ExecRule::default()
            },
        )
        .expect("rule");
        v.add(ItemDraft {
            title: "No agent settings".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new("FAKE-plain-0003".to_owned()),
                secret: true,
            }],
        })
        .expect("add")
        .id
    });
    let backup = fx.dir.path().join("review.bak");
    with_vault(&fx, |v| v.backup(&backup).expect("backup"));
    let mut restored =
        Vault::restore(&backup, &fx.dir.path().join("review.db"), PASS).expect("restore");
    assert!(restored.is_locked());
    restored.unlock(PASS).expect("unlock");
    assert!(
        restored
            .list_agents()
            .expect("agents")
            .iter()
            .all(|agent| agent.revoked)
    );
    assert!(restored.authenticate_agent(&fx.token).is_err());
    assert!(
        restored
            .exec_grants_for_agent(fx.agent_id)
            .expect("grants")
            .is_empty(),
        "the restore removes grants and rules"
    );
    assert_eq!(
        restored.items_needing_review().expect("review"),
        vec![fx.item_id]
    );
    assert!(!restored.needs_review(plain).expect("plain"));
    assert!(restored.env_binding(fx.item_id).expect("binding").is_some());

    // The owner registers the agent again and gives process access again.
    let (agent, token) = restored.register_agent("Run agent").expect("register");
    restored
        .set_exec_grant(
            agent.id,
            fx.item_id,
            &fx.project.display().to_string(),
            ExecMode::Bouncer,
        )
        .expect("grant");
    // ADR 0025 §3: the model decides for a staging item that this agent used in the
    // project before.
    for action in [ActionKind::Read, ActionKind::Change] {
        restored
            .record_item_use(&NewItemUse {
                item_id: fx.item_id,
                agent_id: Some(agent.id),
                agent_name: "Run agent".to_owned(),
                project_key: fx.project.display().to_string(),
                project_label: "project".to_owned(),
                action,
                command_summary: "run echo".to_owned(),
                hosts: Vec::new(),
                outcome: UseOutcome::Allowed,
                decided_by: UseDecidedBy::Bouncer,
                answered_on: String::new(),
                decision_log_id: None,
            })
            .expect("history");
    }
    let token = token.expose().to_owned();
    let slot: SharedVault = Arc::new(Mutex::new(Some(restored)));
    let bouncer = common::fake_bouncer(&[]);
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_millis(500);
    options.bouncer = Some(BouncerClient::new(&bouncer.url).expect("bouncer url"));
    let socket = fx.dir.path().join("run2").join("broker.sock");
    let _broker = broker::start_with(Arc::clone(&slot), &socket, options).expect("broker");
    let send = || {
        client::send(
            &socket,
            &token,
            Action::Run {
                items: vec![fx.item_id],
                command: vec!["echo".into(), "ok".into()],
                cwd: fx.project.display().to_string(),
                purpose: "Print ok.".into(),
                path: Some("/usr/bin:/bin".into()),
                user_request: Some("Print ok.".into()),
            },
        )
        .expect("answer")
    };
    let refused = send();
    assert_eq!(code(&refused), "review_required");
    let message = &refused.error.as_ref().expect("error").message;
    assert!(message.contains("restored from a backup"), "{message}");
    let list = client::send(&socket, &token, Action::ListAccess).expect("list");
    assert_eq!(
        list.result.as_ref().expect("result")["process_access"][0]["owner_review_needed"],
        true
    );
    assert!(bouncer.bodies.lock().expect("bodies").is_empty());
    {
        let mut guard = slot.lock().expect("slot");
        let vault = guard.as_mut().expect("open");
        let activity = vault.recent_activity(2).expect("activity");
        assert!(activity.iter().any(|entry| {
            entry.decision == ActivityDecision::Deny && entry.reason.contains("restored")
        }));
        assert_eq!(
            vault.confirm_review(999).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        vault.confirm_review(fx.item_id).expect("confirm");
        vault
            .confirm_review(fx.item_id)
            .expect("a second confirm changes nothing");
        assert!(vault.items_needing_review().expect("review").is_empty());
    }
    let ok = send();
    assert!(ok.ok, "{ok:?}");
    assert_eq!(ok.result.as_ref().expect("result")["stdout"], "ok\n");
    no_secret(&ok);
}

#[test]
fn mcp_adapter_runs_with_masked_output() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(5));
    decide_later(&fx, true, || {});
    let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-mcp"))
        .env("APASSY_AGENT_TOKEN", &fx.token)
        .env("APASSY_BROKER_SOCKET", &fx.socket)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("adapter");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let message = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "apassy_run_with_secrets", "arguments": {
            "items": [fx.item_id],
            "command": ["sh", "-c", "echo key=$DEMO_API_KEY"],
            "cwd": fx.project.display().to_string(),
            "purpose": "Show that the process gets the key."
        }}
    });
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(stdin, "{message}").expect("write");
        stdin.flush().expect("flush");
    }
    let mut line = String::new();
    stdout.read_line(&mut line).expect("reply");
    let _ = child.kill();
    let _ = child.wait();
    let reply: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["result"]["stdout"],
        "key=[apassy:DEMO_API_KEY]\n"
    );
    assert!(!line.contains(SECRET));
}

/// Schema 10: an archived credential stays in the vault, but no run gets it, and the
/// access list hides it. A run with two credentials shows in the log of each one.
#[test]
fn archived_items_do_not_run_and_a_run_shows_for_each_item() {
    const SECOND: &str = "FAKE-second-run-secret-canary";
    let fx = fixture(ExecMode::Ask, Duration::from_secs(10));
    let second = with_vault(&fx, |v| {
        let item = v
            .add(ItemDraft {
                title: "Second key".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new(SECOND.to_owned()),
                    secret: true,
                }],
            })
            .expect("add");
        v.set_env_binding(item.id, "SECOND_KEY", "token")
            .expect("binding");
        v.set_exec_grant(
            fx.agent_id,
            item.id,
            &fx.project.display().to_string(),
            ExecMode::Ask,
        )
        .expect("grant");
        item.id
    });
    let run_both = || {
        client::send(
            &fx.socket,
            &fx.token,
            Action::Run {
                items: vec![fx.item_id, second],
                command: vec!["true".into()],
                cwd: fx.project.display().to_string(),
                purpose: "Use both keys.".into(),
                path: Some("/usr/bin:/bin".into()),
                user_request: Some("Use both keys.".into()),
            },
        )
        .expect("answer")
    };

    // The owner approves one run with both items.
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    let approver = std::thread::spawn(move || {
        let pending = loop {
            if let Some(run) = approvals.pending().into_iter().next() {
                break run;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let proof = owner_check(&vault, pending);
        approvals.approve(proof).expect("approve");
    });
    let ok = run_both();
    approver.join().expect("approver");
    assert!(ok.ok, "{ok:?}");
    with_vault(&fx, |v| {
        let first_log = v.item_activity(fx.item_id, 10).expect("first");
        let second_log = v.item_activity(second, 10).expect("second");
        assert_eq!(
            first_log[0].id, second_log[0].id,
            "one entry for both items"
        );
        assert_eq!(second_log[0].decision, ActivityDecision::Allow);
        let agent_log = v.agent_activity(fx.agent_id, 10).expect("agent");
        assert_eq!(agent_log[0].id, first_log[0].id);
        let times = v.item_times().expect("times");
        assert!(times[&second].used.is_some(), "the second item was used");
        v.set_archived(second, true).expect("archive");
    });

    // The archived item is refused before the owner is asked, and the list hides it.
    let refused = run_both();
    assert_eq!(code(&refused), "item_archived");
    let message = &refused.error.as_ref().expect("error").message;
    assert!(message.contains("archived"), "{message}");
    assert!(fx.broker.approvals().pending().is_empty());
    let list = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("list");
    let access = list.result.as_ref().expect("result")["process_access"]
        .as_array()
        .expect("process access")
        .clone();
    assert_eq!(access.len(), 1, "{access:?}");
    assert_eq!(access[0]["item_id"], json!(fx.item_id));
    no_secret(&list);
    let history = with_vault(&fx, |v| v.item_events(second, 10).expect("history"));
    assert_eq!(
        history[0].kind,
        apassy::vault::ItemEventKind::Archived,
        "{history:?}"
    );
    assert!(!format!("{history:?}").contains(SECOND));
}
