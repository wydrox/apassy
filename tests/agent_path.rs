#![cfg(feature = "vault")]

//! Thin agent path (ADR 0004): vault, broker socket, synthetic service, MCP adapter.
//! Synthetic tokens only. This does not prove OS isolation. See tests/isolation.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::{self, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::{ActivityDecision, Field, ItemDraft, SecretValue, Vault};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "agent-path-pass-ok";
const SERVICE_TOKEN: &str = "FAKE-SERVICE-TOKEN-4417-canary";
const OP_SUMMARY: &str = "get_sales_summary";
const OP_JOB: &str = "get_report_job_status";

struct DevService {
    child: Child,
    base_url: String,
}

impl Drop for DevService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_dev_service() -> DevService {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-dev-reporting"))
        .env("APASSY_DEV_REPORTING_TOKEN", SERVICE_TOKEN)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start synthetic service");
    let stdout = child.stdout.take().expect("service stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read listen line");
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .expect("listen line")
        .to_owned();
    DevService {
        child,
        base_url: format!("http://{addr}"),
    }
}

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    item_id: u64,
    agent_id: u64,
    token: String,
    _service: DevService,
    _broker: broker::BrokerHandle,
}

fn api_item() -> ItemDraft {
    ItemDraft {
        title: "Reporting staging key".to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(SERVICE_TOKEN.to_owned()),
            secret: true,
        }],
    }
}

fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let service = start_dev_service();
    let vault_dir = dir.path().join("vault");
    std::fs::create_dir(&vault_dir).expect("vault dir");
    let mut vault = Vault::create(&vault_dir.join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let item = vault.add(api_item()).expect("add item");
    vault
        .set_destination(item.id, "reporting-api-v0", &service.base_url)
        .expect("destination");
    let (agent, token) = vault.register_agent("Test agent").expect("register");
    vault
        .set_grant(agent.id, item.id, OP_SUMMARY, true)
        .expect("grant");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let handle = broker::start(Arc::clone(&shared), &socket).expect("start broker");
    Fixture {
        vault: shared,
        socket,
        item_id: item.id,
        agent_id: agent.id,
        token: token.expose().to_owned(),
        _service: service,
        _broker: handle,
        dir,
    }
}

fn summary_params(project: &str) -> BTreeMap<String, String> {
    [
        ("project_id", project),
        ("period_start", "2026-09-01"),
        ("period_end", "2026-09-30"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

fn call(
    fx: &Fixture,
    token: &str,
    operation: &str,
    params: BTreeMap<String, String>,
) -> WireResponse {
    client::send(
        &fx.socket,
        token,
        Action::Call {
            item_id: fx.item_id,
            operation: operation.to_owned(),
            params,
        },
    )
    .expect("broker answer")
}

fn error_code(response: &WireResponse) -> &str {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response
        .error
        .as_ref()
        .map_or("", |error| error.code.as_str())
}

fn assert_no_secret(value: &impl std::fmt::Debug) {
    let text = format!("{value:?}");
    assert!(!text.contains(SERVICE_TOKEN), "secret leaked: {text}");
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault mutex");
    f(guard.as_mut().expect("open vault"))
}

#[test]
fn permitted_call_returns_only_permitted_fields() {
    let fx = fixture();
    let list = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("list");
    assert!(list.ok, "{list:?}");
    let result = list.result.clone().expect("list result");
    assert_eq!(result["items"][0]["item_id"], json!(fx.item_id));
    assert_eq!(result["items"][0]["operations"][0]["name"], OP_SUMMARY);
    assert_eq!(
        result["items"][0]["operations"].as_array().map(Vec::len),
        Some(1)
    );
    assert_no_secret(&list);

    let response = call(
        &fx,
        &fx.token,
        OP_SUMMARY,
        summary_params("project-a-synthetic"),
    );
    assert!(response.ok, "{response:?}");
    let output = response.result.clone().expect("output");
    assert_eq!(output["total_amount"], "12840.50");
    assert_eq!(output["order_count"], 318);
    assert!(output.get("internal_debug_note").is_none());
    assert_no_secret(&response);

    let activity = with_vault(&fx, |vault| vault.recent_activity(10).expect("activity"));
    assert_eq!(activity[0].decision, ActivityDecision::Allow);
    assert_eq!(activity[0].operation, OP_SUMMARY);
    assert_eq!(activity[0].agent_id, Some(fx.agent_id));
    assert_no_secret(&activity);
}

#[test]
fn refusals_are_specific_and_recorded() {
    let fx = fixture();
    let no_grant = call(
        &fx,
        &fx.token,
        OP_JOB,
        BTreeMap::from([("job_id".into(), "job-1".into())]),
    );
    assert_eq!(error_code(&no_grant), "not_granted");

    let mut injected = summary_params("project-a-synthetic");
    injected.insert("url".into(), "http://evil.invalid".into());
    assert_eq!(
        error_code(&call(&fx, &fx.token, OP_SUMMARY, injected)),
        "invalid_params"
    );

    let traversal = summary_params("../admin");
    assert_eq!(
        error_code(&call(&fx, &fx.token, OP_SUMMARY, traversal)),
        "invalid_params"
    );

    let echo = call(
        &fx,
        &fx.token,
        OP_SUMMARY,
        summary_params("echo-token-canary"),
    );
    assert_eq!(error_code(&echo), "output_blocked");
    assert_no_secret(&echo);

    let bad_token = "apassy_agt_0000000000000000000000000000000000000000000000000000000000000000";
    let unknown = call(
        &fx,
        bad_token,
        OP_SUMMARY,
        summary_params("project-a-synthetic"),
    );
    assert_eq!(error_code(&unknown), "unauthenticated");

    let activity = with_vault(&fx, |vault| vault.recent_activity(20).expect("activity"));
    let denies = activity
        .iter()
        .filter(|entry| entry.decision == ActivityDecision::Deny)
        .count();
    assert!(denies >= 4, "{activity:?}");
    assert!(
        activity
            .iter()
            .any(|entry| entry.decision == ActivityDecision::Error)
    );
    assert_no_secret(&activity);
}

#[test]
fn revoke_lock_and_destination_rules() {
    let fx = fixture();
    with_vault(&fx, |vault| vault.lock().expect("lock"));
    let locked = call(
        &fx,
        &fx.token,
        OP_SUMMARY,
        summary_params("project-a-synthetic"),
    );
    assert_eq!(error_code(&locked), "vault_locked");
    with_vault(&fx, |vault| vault.unlock(PASS).expect("unlock"));

    with_vault(&fx, |vault| {
        vault
            .set_destination(
                fx.item_id,
                "reporting-api-v0",
                "https://reporting.example.invalid:443",
            )
            .expect("store remote destination");
    });
    let remote = call(
        &fx,
        &fx.token,
        OP_SUMMARY,
        summary_params("project-a-synthetic"),
    );
    assert_eq!(error_code(&remote), "destination_not_permitted");

    with_vault(&fx, |vault| {
        vault.revoke_agent(fx.agent_id).expect("revoke")
    });
    let revoked = call(
        &fx,
        &fx.token,
        OP_SUMMARY,
        summary_params("project-a-synthetic"),
    );
    assert_eq!(error_code(&revoked), "unauthenticated");
    let grants = with_vault(&fx, |vault| {
        vault.grants_for_agent(fx.agent_id).expect("grants")
    });
    assert!(grants.is_empty());
}

#[test]
fn delete_item_removes_links_and_restore_revokes_agents() {
    let fx = fixture();
    let backup = fx.dir.path().join("backup.db");
    with_vault(&fx, |vault| vault.backup(&backup).expect("backup"));
    let restored_path = fx.dir.path().join("restored.db");
    let mut restored = Vault::restore(&backup, &restored_path, PASS).expect("restore");
    restored.unlock(PASS).expect("unlock restored");
    let agents = restored.list_agents().expect("agents");
    assert_eq!(agents.len(), 1);
    assert!(agents[0].revoked, "restore must revoke agents");
    assert!(restored.authenticate_agent(&fx.token).is_err());
    assert!(
        restored
            .grants_for_agent(fx.agent_id)
            .expect("grants")
            .is_empty()
    );

    with_vault(&fx, |vault| {
        vault.unlock(PASS).expect("unlock after backup");
        let revision = vault.details(fx.item_id).expect("details").summary.revision;
        vault.delete(fx.item_id, revision).expect("delete");
        assert!(
            vault
                .grants_for_agent(fx.agent_id)
                .expect("grants")
                .is_empty()
        );
        assert!(
            vault
                .destination(fx.item_id)
                .expect("destination")
                .is_none()
        );
    });
}

struct McpProcess {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl McpProcess {
    fn start(socket: &Path, token: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-mcp"))
            .env("APASSY_AGENT_TOKEN", token)
            .env("APASSY_BROKER_SOCKET", socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start adapter");
        let stdout = BufReader::new(child.stdout.take().expect("adapter stdout"));
        Self { child, stdout }
    }

    fn request(&mut self, message: &Value) -> Value {
        let stdin = self.child.stdin.as_mut().expect("adapter stdin");
        writeln!(stdin, "{message}").expect("write request");
        stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read reply");
        serde_json::from_str(&line).expect("reply JSON")
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn mcp_adapter_process_round_trip() {
    let fx = fixture();
    let mut mcp = McpProcess::start(&fx.socket, &fx.token);
    let init = mcp.request(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
    }));
    assert_eq!(init["result"]["serverInfo"]["name"], "apassy");
    let tools = mcp.request(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    assert_eq!(tools["result"]["tools"].as_array().map(Vec::len), Some(2));

    let reply = mcp.request(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "apassy_use_credential", "arguments": {
            "item_id": fx.item_id,
            "operation": OP_SUMMARY,
            "params": {"project_id": "project-a-synthetic", "period_start": "2026-09-01", "period_end": "2026-09-30"}
        }}
    }));
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["result"]["order_count"],
        318
    );
    assert!(!reply.to_string().contains(SERVICE_TOKEN));

    let refused = mcp.request(&json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "apassy_use_credential", "arguments": {
            "item_id": fx.item_id, "operation": OP_JOB, "params": {"job_id": "job-1"}
        }}
    }));
    assert_eq!(refused["result"]["isError"], true);
    let text = refused["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(text.starts_with("not_granted"), "{text}");
}

/// Same-user control, then the sandboxed adapter. Skipped where `sandbox-exec` is absent.
/// This is a fixture profile. It is not the product isolation profile.
#[test]
fn sandboxed_adapter_uses_broker_but_cannot_read_vault() {
    let sandbox = Path::new("/usr/bin/sandbox-exec");
    if !sandbox.exists() {
        eprintln!("SKIP: sandbox-exec is not available. This is not isolation evidence.");
        return;
    }
    let fx = fixture();
    let vault_dir = std::fs::canonicalize(fx.dir.path().join("vault")).expect("vault dir");
    let vault_file = vault_dir.join("vault.db");
    let quoted = vault_dir
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile = format!(
        "(version 1)(allow default)(deny file-read* (subpath \"{quoted}\"))(deny file-write* (subpath \"{quoted}\"))(deny network-outbound (remote ip))"
    );

    let control = Command::new("/bin/cat")
        .arg(&vault_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("control read");
    assert!(
        control.success(),
        "a same-user process can read the vault file"
    );

    let blocked = Command::new(sandbox)
        .args(["-p", &profile, "/bin/cat"])
        .arg(&vault_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("sandboxed read");
    assert!(!blocked.success(), "the sandbox must refuse the vault file");

    let mut child = Command::new(sandbox)
        .args(["-p", &profile])
        .arg(env!("CARGO_BIN_EXE_apassy-mcp"))
        .env("APASSY_AGENT_TOKEN", &fx.token)
        .env("APASSY_BROKER_SOCKET", &fx.socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start sandboxed adapter");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut mcp = McpProcess { child, stdout };
    let reply = mcp.request(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "apassy_use_credential", "arguments": {
            "item_id": fx.item_id,
            "operation": OP_SUMMARY,
            "params": {"project_id": "project-a-synthetic", "period_start": "2026-09-01", "period_end": "2026-09-30"}
        }}
    }));
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["result"]["order_count"],
        318
    );
    assert!(!reply.to_string().contains(SERVICE_TOKEN));
}
