#![cfg(feature = "vault")]

//! Process runs with secrets in the environment (ADR 0006). Synthetic values only.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::{
    ActivityDecision, ExecMode, Field, ItemDraft, SecretValue, Vault, VaultErrorKind,
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

fn fixture(mode: ExecMode, approval_timeout: Duration) -> Fixture {
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

/// Wait for one pending run, then decide it on another thread.
fn decide_later(fx: &Fixture, approve: bool, before: impl FnOnce() + Send + 'static) {
    let approvals = Arc::clone(fx.broker.approvals());
    std::thread::spawn(move || {
        let pending = loop {
            if let Some(run) = approvals.pending().into_iter().next() {
                break run;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(pending.env_names, vec![ENV_NAME.to_owned()]);
        assert!(!format!("{pending:?}").contains(SECRET));
        before();
        approvals.decide(pending.id, approve);
    });
}

#[test]
fn allow_mode_runs_with_the_secret_and_masks_output() {
    let fx = fixture(ExecMode::Allow, Duration::from_secs(2));
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
fn working_directory_must_stay_in_the_project() {
    let fx = fixture(ExecMode::Allow, Duration::from_secs(2));
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
    assert_eq!(code(&run(&fx, &fx.project, "echo x")), "vault_locked");
}

#[test]
fn grants_and_bindings_are_checked() {
    let fx = fixture(ExecMode::Allow, Duration::from_secs(2));
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
            .set_exec_grant(fx.agent_id, fx.item_id, "relative/dir", ExecMode::Allow)
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
        },
    )
    .expect("answer");
    assert_eq!(code(&other), "invalid_request");
}

#[test]
fn restore_removes_process_grants() {
    let fx = fixture(ExecMode::Allow, Duration::from_secs(2));
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

#[test]
fn mcp_adapter_runs_with_masked_output() {
    let fx = fixture(ExecMode::Allow, Duration::from_secs(2));
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
