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
use apassy::broker::approvals::{
    ApprovalRefusal, OwnerAction, OwnerCheck, OwnerGate, OwnerProof, PendingRun,
};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
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
    fixture_with(mode, approval_timeout, Some(&bouncer.url))
}

fn fixture_with(mode: ExecMode, approval_timeout: Duration, bouncer: Option<&str>) -> Fixture {
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
    client::send(
        &fx.socket,
        &fx.token,
        Action::Run {
            items: vec![fx.item_id],
            command: vec!["/bin/sh".into(), "-c".into(), script.into()],
            cwd: cwd.display().to_string(),
            purpose: "Test the process mode.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Test the process mode.".into()),
        },
    )
    .expect("broker answer")
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
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    std::thread::spawn(move || {
        let pending = loop {
            if let Some(run) = approvals.pending().into_iter().next() {
                break run;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(pending.env_names, vec![ENV_NAME.to_owned()]);
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

#[test]
fn working_directory_must_stay_in_the_project() {
    let fx = fixture(ExecMode::Bouncer, Duration::from_secs(2));
    assert_eq!(code(&run(&fx, fx.dir.path(), "true")), "outside_project");

    let escape = fx.project.join("escape");
    std::os::unix::fs::symlink(fx.dir.path(), &escape).expect("symlink");
    assert_eq!(code(&run(&fx, &escape, "true")), "outside_project");

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
                project: "demo".to_owned(),
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
