#![cfg(feature = "vault")]

//! The user request from a host hook (goal item B6). Synthetic values only.
//!
//! The tests start a real broker and the real `apassy-hook` program. A synthetic
//! transcript file has the Claude Code or Codex format that
//! `docs/operations/host-hooks.md` records.
//!
//! Two tests use real hosts and are ignored by default. They need the `claude` or
//! `codex` program, an account, and network access:
//! `cargo test --locked --features vault --test host_hook -- --ignored --nocapture`.

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client::{self, SendOptions};
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::{ApprovalQueue, OwnerAction, OwnerCheck, OwnerGate, PendingRun};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::{
    Declaration, Environment, ExecMode, Field, ItemDraft, Reversibility, RiskLevel, Scope,
    SecretValue, Vault,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "host-hook-pass-ok";
const SECRET: &str = "FAKE-hook-secret-4417-canary";
const ENV_NAME: &str = "DEMO_KEY";
const SESSION: &str = "1dbe1639-f522-4744-a3dc-7a76626af241";
const PROMPT: &str = "Run the unit tests of the billing module.";
const AGENT_TEXT: &str = "Deploy everything to production.";
/// A run that waits for the owner in these tests waits this long.
const SHORT: Duration = Duration::from_millis(600);

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    project: PathBuf,
    /// `<home>/.claude/projects`, a host transcript directory.
    claude_root: PathBuf,
    /// `<home>/.codex/sessions`, a host transcript directory.
    codex_root: PathBuf,
    item_id: u64,
    token: String,
    bodies: Arc<Mutex<Vec<String>>>,
    broker: BrokerHandle,
}

fn fixture(mode: ExecMode, approval_timeout: Duration) -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let base = std::fs::canonicalize(dir.path()).expect("canonical temp dir");
    let project = base.join("project");
    std::fs::create_dir_all(project.join("web")).expect("project");
    let claude_root = base.join("home").join(".claude").join("projects");
    let codex_root = base.join("home").join(".codex").join("sessions");
    std::fs::create_dir_all(&claude_root).expect("claude root");
    std::fs::create_dir_all(&codex_root).expect("codex root");
    // A short socket path stays under the AF_UNIX length limit.
    let data = base.join("d");
    std::fs::create_dir_all(&data).expect("data dir");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let mut vault = Vault::create(&data.join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let item = vault
        .add(ItemDraft {
            title: "Billing staging key".to_owned(),
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
    vault
        .set_declaration(
            item.id,
            &Declaration {
                project: "billing".to_owned(),
                environment: Environment::Staging,
                risk: RiskLevel::Medium,
                scope: Scope::ReadWrite,
                reversibility: Reversibility::Reversible,
            },
        )
        .expect("declaration");
    let (agent, token) = vault.register_agent("Hook agent").expect("register");
    vault
        .set_exec_grant(agent.id, item.id, &project.display().to_string(), mode)
        .expect("grant");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let bouncer = common::fake_bouncer(&[]);
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = approval_timeout;
    options.run_timeout = Duration::from_secs(20);
    options.bouncer = Some(BouncerClient::new(&bouncer.url).expect("bouncer url"));
    // The real host tests need the real transcript directories too.
    options.transcript_roots = vec![claude_root.clone(), codex_root.clone()];
    options
        .transcript_roots
        .extend(broker::prompts::default_transcript_roots());
    let socket = data.join("broker.sock");
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    Fixture {
        dir,
        vault: shared,
        socket,
        project,
        claude_root,
        codex_root,
        item_id: item.id,
        token: token.expose().to_owned(),
        bodies: bouncer.bodies,
        broker,
    }
}

/// A Claude Code transcript with the record types measured on 2.1.283. The last user
/// prompt is `newest`.
fn claude_transcript(fx: &Fixture, session: &str, newest: &str) -> PathBuf {
    let folder = fx.claude_root.join("-private-tmp-project");
    std::fs::create_dir_all(&folder).expect("transcript folder");
    let path = folder.join(format!("{session}.jsonl"));
    let cwd = fx.project.display().to_string();
    let user = |text: &str, prompt_id: &str| {
        json!({"parentUuid": null, "isSidechain": false, "promptId": prompt_id, "type": "user",
            "message": {"role": "user", "content": text}, "uuid": format!("u-{prompt_id}"),
            "userType": "external", "entrypoint": "cli", "cwd": cwd, "sessionId": session,
            "version": "2.1.283"})
    };
    let lines = [
        json!({"type": "queue-operation", "operation": "enqueue", "sessionId": session}),
        user("Show the open invoices.", "p1"),
        json!({"type": "assistant", "message": {"role": "assistant",
            "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}]}}),
        json!({"type": "user", "isSidechain": false, "sessionId": session, "message": {"role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "invoices.csv"}]}}),
        json!({"type": "user", "isMeta": true, "sessionId": session,
            "message": {"role": "user", "content": "Caveat: local command output."}}),
        user(newest, "p2"),
        json!({"type": "attachment", "sessionId": session, "attachment": {"type": "hook_success"}}),
        json!({"type": "last-prompt", "lastPrompt": newest, "sessionId": session}),
    ];
    write_lines(&path, &lines);
    path
}

fn write_lines(path: &Path, lines: &[Value]) {
    let mut file = std::fs::File::create(path).expect("transcript");
    for line in lines {
        writeln!(file, "{line}").expect("write transcript");
    }
}

/// The newest user prompt in a Claude Code transcript, read without the broker code.
fn newest_prompt_in_transcript(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("read transcript");
    text.lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|line| line["type"] == "user" && line["isMeta"] != true)
        .filter_map(|line| line["message"]["content"].as_str().map(str::to_owned))
        .next()
        .expect("a user prompt")
}

/// Run the real `apassy-hook` program with one hook input.
fn hook_with(socket: &Path, token: Option<&str>, input: &[u8]) -> (Output, Duration) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apassy-hook"));
    command
        .env_remove("APASSY_AGENT_TOKEN")
        .env("APASSY_BROKER_SOCKET", socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(token) = token {
        command.env("APASSY_AGENT_TOKEN", token);
    }
    let started = Instant::now();
    let mut child = command.spawn().expect("start apassy-hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write hook input");
    let output = child.wait_with_output().expect("apassy-hook output");
    (output, started.elapsed())
}

/// Run the hook as the host does and check that it cannot change the prompt.
fn hook(fx: &Fixture, input: &Value) -> Output {
    let (output, _) = hook_with(&fx.socket, Some(&fx.token), input.to_string().as_bytes());
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty(), "stdout becomes model context");
    output
}

fn claude_input(fx: &Fixture, session: &str, transcript: &Path, prompt: &str) -> Value {
    json!({
        "session_id": session,
        "transcript_path": transcript.display().to_string(),
        "cwd": fx.project.display().to_string(),
        "prompt_id": "p2",
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt,
    })
}

fn run(fx: &Fixture, session: Option<&str>, agent_text: &str, command: &[&str]) -> WireResponse {
    client::send_with(
        &fx.socket,
        &fx.token,
        Action::Run {
            items: vec![fx.item_id],
            command: command.iter().map(|arg| (*arg).to_owned()).collect(),
            cwd: fx.project.join("web").display().to_string(),
            purpose: "Run the tests.".to_owned(),
            path: Some("/usr/bin:/bin".to_owned()),
            user_request: Some(agent_text.to_owned()),
        },
        SendOptions {
            host_session: session,
            timeout: None,
        },
    )
    .expect("broker answer")
}

fn code(response: &WireResponse) -> &str {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response.error.as_ref().map_or("", |e| e.code.as_str())
}

fn last_reason(fx: &Fixture) -> String {
    let guard = fx.vault.lock().expect("vault");
    let vault = guard.as_ref().expect("open vault");
    vault.recent_activity(1).expect("activity")[0]
        .reason
        .clone()
}

/// The quoted user request in an activity reason, after `marker`.
fn logged_request(reason: &str, marker: &str) -> String {
    let start = reason
        .find(marker)
        .unwrap_or_else(|| panic!("{marker} in {reason}"))
        + marker.len();
    let rest = &reason[start..];
    rest[..rest.find("\".").expect("closing quote")].to_owned()
}

/// Goal item B6 evidence: the request in the log matches the host transcript, and it
/// replaces the text from the agent.
#[test]
fn hook_request_replaces_the_agent_text_and_matches_the_transcript() {
    let fx = fixture(ExecMode::Bouncer, SHORT);
    let transcript = claude_transcript(&fx, SESSION, PROMPT);
    let output = hook(&fx, &claude_input(&fx, SESSION, &transcript, PROMPT));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(PROMPT));

    let response = run(&fx, Some(SESSION), AGENT_TEXT, &["echo", "tests ok"]);
    assert!(response.ok, "{response:?}");
    let result = response.result.expect("result");
    assert_eq!(result["decided_by"], "Bouncer allowed");
    assert_eq!(result["stdout"], "tests ok\n");

    // The bouncer saw the words of the user, not the text from the agent.
    let bodies = fx.bodies.lock().expect("bodies").clone();
    assert_eq!(bodies.len(), 1);
    let state = serde_json::from_str::<Value>(&bodies[0]).expect("body")["state"]
        .as_str()
        .expect("state")
        .to_owned();
    assert!(
        state.starts_with(&format!("User request: \"{PROMPT}\"")),
        "{state}"
    );
    assert!(!state.contains(AGENT_TEXT), "{state}");

    // The log shows the source, the request, and the different agent text.
    let reason = last_reason(&fx);
    let marker = "User request from the Claude Code hook, verified in the host transcript: \"";
    let logged = logged_request(&reason, marker);
    assert_eq!(logged, newest_prompt_in_transcript(&transcript), "{reason}");
    assert_eq!(logged, PROMPT);
    assert!(
        reason.contains(&format!("The agent sent: \"{AGENT_TEXT}\".")),
        "{reason}"
    );
    assert!(!reason.contains(SECRET));
}

/// The owner approves `pending` after a fresh passphrase check (goal item A4).
fn owner_approves(vault: &SharedVault, approvals: &ApprovalQueue, pending: &PendingRun) {
    let proof = OwnerGate::new(Arc::clone(vault), None)
        .authorize(
            OwnerAction::ApproveRun(pending.clone()),
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    assert_eq!(approvals.approve(proof), Ok(()));
}

#[test]
fn approval_card_shows_the_source_and_the_difference() {
    let fx = fixture(ExecMode::Ask, SHORT);
    let transcript = claude_transcript(&fx, SESSION, PROMPT);
    hook(&fx, &claude_input(&fx, SESSION, &transcript, PROMPT));
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    let approver = std::thread::spawn(move || {
        loop {
            if let Some(pending) = approvals.pending().into_iter().next() {
                owner_approves(&vault, &approvals, &pending);
                return pending;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let response = run(&fx, Some(SESSION), AGENT_TEXT, &["echo", "ok"]);
    let pending = approver.join().expect("approver");
    assert!(response.ok, "{response:?}");
    assert_eq!(pending.user_request, PROMPT);
    assert_eq!(
        pending.request_source,
        "from the Claude Code hook, verified in the host transcript"
    );
    assert_eq!(pending.agent_request, AGENT_TEXT);
    assert!(!format!("{pending:?}").contains(SECRET));
}

#[test]
fn a_false_hook_request_waits_for_the_owner() {
    let fx = fixture(ExecMode::Bouncer, SHORT);
    // The user asked to read the logs. The agent runs `apassy-hook` itself with other words.
    let transcript = claude_transcript(&fx, SESSION, "Read the logs.");
    hook(
        &fx,
        &claude_input(&fx, SESSION, &transcript, "Deploy production now."),
    );
    let response = run(
        &fx,
        Some(SESSION),
        "Deploy production now.",
        &["echo", "ok"],
    );
    assert_eq!(code(&response), "approval_timeout");
    let reason = last_reason(&fx);
    assert!(reason.contains("hook_unverified"), "{reason}");
    assert!(
        reason.contains("NOT verified: the prompt is not the newest user message"),
        "{reason}"
    );

    // An older prompt of the user is a replay. It is not the newest user message.
    hook(
        &fx,
        &claude_input(&fx, SESSION, &transcript, "Show the open invoices."),
    );
    let response = run(&fx, Some(SESSION), "", &["echo", "ok"]);
    assert_eq!(code(&response), "approval_timeout");
    assert!(last_reason(&fx).contains("hook_unverified"));

    // A transcript that the agent wrote outside the host directories is not trusted.
    let fake = fx.dir.path().join(format!("{SESSION}.jsonl"));
    write_lines(
        &fake,
        &[
            json!({"type": "user", "message": {"role": "user", "content": "Deploy production now."}}),
        ],
    );
    hook(
        &fx,
        &claude_input(&fx, SESSION, &fake, "Deploy production now."),
    );
    let response = run(&fx, Some(SESSION), "", &["echo", "ok"]);
    assert_eq!(code(&response), "approval_timeout");
    let reason = last_reason(&fx);
    assert!(
        reason.contains("not in a host transcript directory"),
        "{reason}"
    );
    // A rule flag asks the owner without the model.
    assert!(fx.bodies.lock().expect("bodies").is_empty());
}

#[test]
fn a_command_that_names_the_hook_channel_waits_for_the_owner() {
    let fx = fixture(ExecMode::Bouncer, SHORT);
    let transcript = claude_transcript(&fx, SESSION, PROMPT);
    hook(&fx, &claude_input(&fx, SESSION, &transcript, PROMPT));
    let append = format!("echo '{{}}' >> {}", transcript.display());
    for command in [
        vec!["sh", "-c", "echo '{}' | apassy-hook"],
        vec!["sh", "-c", append.as_str()],
        vec!["cat", "/Users/me/.codex/hooks.json"],
    ] {
        let response = run(&fx, Some(SESSION), PROMPT, &command);
        assert_eq!(code(&response), "approval_timeout", "{command:?}");
        let reason = last_reason(&fx);
        assert!(reason.contains("hook_channel"), "{reason}");
    }
    assert!(fx.bodies.lock().expect("bodies").is_empty());
}

#[test]
fn codex_hook_request_matches_by_project_directory() {
    let fx = fixture(ExecMode::Bouncer, SHORT);
    let thread = "01a0db20-fcae-7151-b2e6-b590a8175ded";
    let folder = fx.codex_root.join("2026").join("09").join("26");
    std::fs::create_dir_all(&folder).expect("codex folder");
    let transcript = folder.join(format!("rollout-2026-09-26T02-32-47-{thread}.jsonl"));
    let prompt = "Check the billing build.";
    // Record types measured on Codex 0.156.1.
    write_lines(
        &transcript,
        &[
            json!({"type": "session_meta", "payload": {"session_id": thread, "id": thread}}),
            json!({"type": "response_item", "payload": {"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": "<environment_context/>"}]}}),
            json!({"type": "response_item", "payload": {"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": prompt}]}}),
            json!({"type": "event_msg", "payload": {"type": "item_completed", "thread_id": thread,
                "turn_id": "01a0db21", "item": {"type": "UserMessage", "id": "i1",
                "content": [{"type": "text", "text": prompt, "text_elements": []}]}}}),
        ],
    );
    hook(
        &fx,
        &json!({
            "session_id": thread, "turn_id": "01a0db21",
            "transcript_path": transcript.display().to_string(),
            "cwd": fx.project.display().to_string(), "hook_event_name": "UserPromptSubmit",
            "model": "gpt-test", "permission_mode": "default", "prompt": prompt,
        }),
    );
    // Codex gives its MCP servers no session ID, so the run has none.
    let response = run(&fx, None, "", &["echo", "ok"]);
    assert!(response.ok, "{response:?}");
    let reason = last_reason(&fx);
    let marker = "User request from the Codex hook, matched by the project directory, verified in the host transcript: \"";
    assert_eq!(logged_request(&reason, marker), prompt, "{reason}");
}

#[test]
fn a_lock_ends_the_hook_request() {
    let fx = fixture(ExecMode::Bouncer, SHORT);
    let transcript = claude_transcript(&fx, SESSION, PROMPT);
    hook(&fx, &claude_input(&fx, SESSION, &transcript, PROMPT));
    {
        let mut guard = fx.vault.lock().expect("vault");
        let vault = guard.as_mut().expect("open vault");
        vault.lock().expect("lock");
        vault.unlock(PASS).expect("unlock");
    }
    let response = run(&fx, Some(SESSION), AGENT_TEXT, &["echo", "ok"]);
    assert!(
        response.ok || code(&response) == "approval_timeout",
        "{response:?}"
    );
    let reason = last_reason(&fx);
    assert!(
        reason.contains(&format!(
            "User request from the agent, no hook request for this host session: \"{AGENT_TEXT}\""
        )),
        "{reason}"
    );

    // A locked vault refuses the hook request. The hook still exits with code 0.
    fx.vault
        .lock()
        .expect("vault")
        .as_mut()
        .expect("open vault")
        .lock()
        .expect("lock");
    let output = hook(&fx, &claude_input(&fx, SESSION, &transcript, PROMPT));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vault_locked"), "{stderr}");
    assert!(!stderr.contains(PROMPT));
}

#[test]
fn the_hook_never_blocks_the_prompt() {
    let dir = TempDir::new().expect("temp dir");
    let input = json!({"session_id": SESSION, "cwd": "/tmp", "hook_event_name": "UserPromptSubmit", "prompt": PROMPT}).to_string();
    let check = |output: &Output, elapsed: Duration| {
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(PROMPT), "{stderr}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        stderr.into_owned()
    };

    // No broker.
    let absent = dir.path().join("absent.sock");
    let (output, elapsed) = hook_with(&absent, Some("apassy_agt_x"), input.as_bytes());
    assert!(check(&output, elapsed).contains("did not answer"));

    // A broker that accepts and never answers.
    let silent = dir.path().join("silent.sock");
    let listener = UnixListener::bind(&silent).expect("bind");
    let holder = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buffer = [0u8; 256];
        let _ = stream.read(&mut buffer);
        std::thread::sleep(Duration::from_secs(3));
    });
    let (output, elapsed) = hook_with(&silent, Some("apassy_agt_x"), input.as_bytes());
    assert!(check(&output, elapsed).contains("did not answer"));
    assert!(
        elapsed < Duration::from_secs(3),
        "the hook waits at most 2 s: {elapsed:?}"
    );
    holder.join().expect("holder");

    // No token, bad input, and another event.
    let (output, elapsed) = hook_with(&absent, None, input.as_bytes());
    assert!(check(&output, elapsed).contains("APASSY_AGENT_TOKEN"));
    let (output, elapsed) = hook_with(&absent, Some("t"), b"{not json");
    check(&output, elapsed);
    let other = br#"{"hook_event_name":"Stop","cwd":"/tmp"}"#;
    let (output, elapsed) = hook_with(&absent, Some("t"), other);
    assert!(
        check(&output, elapsed).is_empty(),
        "another event is not an error"
    );
}

/// The files that a real host needs: a hook wrapper with the token, and the
/// `apassy-sandbox` arguments for the fixture paths.
struct RealHost {
    dir: PathBuf,
    wrapper: PathBuf,
    sandbox: Vec<String>,
}

fn real_host(fx: &Fixture) -> RealHost {
    let base = std::fs::canonicalize(fx.dir.path()).expect("canonical temp dir");
    let dir = base.join("host");
    std::fs::create_dir_all(&dir).expect("host dir");
    // The wrapper keeps the token out of the host settings and the process arguments.
    let wrapper = dir.join("apassy-hook.sh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nAPASSY_AGENT_TOKEN='{}' APASSY_BROKER_SOCKET='{}' exec '{}'\n",
            fx.token,
            fx.socket.display(),
            env!("CARGO_BIN_EXE_apassy-hook")
        ),
    )
    .expect("wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let backups = base.join("backups");
    std::fs::create_dir_all(&backups).expect("backups");
    let backup = backups.join("apassy.backup");
    std::fs::write(&backup, "SYNTHETIC-BACKUP").expect("backup");
    let data = fx.socket.parent().expect("data dir").to_path_buf();
    let profile = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("sandbox")
        .join("apassy-agent-host.sb");
    let sandbox = vec![
        "--profile".to_owned(),
        profile.display().to_string(),
        "--data-dir".to_owned(),
        data.display().to_string(),
        "--vault-file".to_owned(),
        data.join("vault.db").display().to_string(),
        "--backup-file".to_owned(),
        backup.display().to_string(),
        "--socket".to_owned(),
        fx.socket.display().to_string(),
        "--".to_owned(),
    ];
    RealHost {
        dir,
        wrapper,
        sandbox,
    }
}

type Approver = (Arc<AtomicBool>, std::thread::JoinHandle<Option<PendingRun>>);

/// Approve the first waiting run and return it. The flag ends the wait without a run.
fn approver(fx: &Fixture) -> Approver {
    let stop = Arc::new(AtomicBool::new(false));
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    let flag = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            if let Some(pending) = approvals.pending().into_iter().next() {
                owner_approves(&vault, &approvals, &pending);
                return Some(pending);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    });
    (stop, handle)
}

/// The prompt for a real host. It stays short, so the activity log keeps all of it.
fn real_prompt(fx: &Fixture) -> String {
    let prompt = format!(
        "Call apassy_run_with_secrets once: items [{}], command [\"sh\",\"-c\",\"test -n \\\"${ENV_NAME}\\\" && echo key-present\"], cwd = your current directory, purpose \"Check the key.\", user_request = my words. Reply with its stdout.",
        fx.item_id
    );
    assert!(prompt.len() < 240, "{}", prompt.len());
    prompt
}

/// A real Claude Code session in the Apassy profile, with the hook (goal item B6).
#[test]
#[ignore = "needs the claude program, an account, and network access"]
fn real_claude_code_session_sends_the_user_request() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(120));
    let host = real_host(&fx);
    let hook_entry = json!([{ "hooks": [{
        "type": "command", "command": host.wrapper.display().to_string(), "timeout": 5,
    }]}]);
    // The Apassy profile confines the host. The Claude Code Bash sandbox cannot nest in it.
    let settings = host.dir.join("settings.json");
    let settings_json =
        json!({ "sandbox": { "enabled": false }, "hooks": { "UserPromptSubmit": hook_entry } });
    std::fs::write(&settings, settings_json.to_string()).expect("settings");
    let mcp = host.dir.join("mcp.json");
    let mcp_json = json!({ "mcpServers": { "apassy": {
        "command": env!("CARGO_BIN_EXE_apassy-mcp"),
        "env": { "APASSY_AGENT_TOKEN": fx.token, "APASSY_BROKER_SOCKET": fx.socket.display().to_string() },
    }}});
    std::fs::write(&mcp, mcp_json.to_string()).expect("mcp config");
    let prompt = real_prompt(&fx);
    let (stop, approver) = approver(&fx);
    let output = Command::new(env!("CARGO_BIN_EXE_apassy-sandbox"))
        .args(&host.sandbox)
        .args(["claude", "-p", &prompt, "--model", "haiku", "--settings"])
        .arg(&settings)
        .arg("--mcp-config")
        .arg(&mcp)
        .args([
            "--strict-mcp-config",
            "--allowedTools",
            "mcp__apassy__apassy_run_with_secrets",
            "--output-format",
            "json",
        ])
        .current_dir(&fx.project)
        .env("MCP_TOOL_TIMEOUT", "180000")
        .stdin(Stdio::null())
        .output()
        .expect("run claude in the Apassy profile");
    stop.store(true, Ordering::SeqCst);
    let pending = approver.join().expect("approver");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_str(&stdout).expect("claude JSON");
    let session = result["session_id"].as_str().expect("session id");
    let pending = pending.expect("the agent called apassy_run_with_secrets");
    eprintln!("session: {session}");
    eprintln!("card source: {}", pending.request_source);
    eprintln!("card user request: {}", pending.user_request);
    eprintln!("agent text: {}", pending.agent_request);
    eprintln!("agent reply: {}", result["result"]);
    assert_eq!(
        pending.request_source,
        "from the Claude Code hook, verified in the host transcript"
    );
    assert_eq!(pending.user_request, prompt);

    // The host transcript has the same prompt as its newest user message.
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    let transcript = std::fs::read_dir(home.join(".claude").join("projects"))
        .expect("projects")
        .flatten()
        .map(|folder| folder.path().join(format!("{session}.jsonl")))
        .find(|path| path.is_file())
        .expect("host transcript");
    eprintln!("transcript: {}", transcript.display());
    assert_eq!(newest_prompt_in_transcript(&transcript), prompt);
    let reason = last_reason(&fx);
    eprintln!("activity: {reason}");
    let marker = "User request from the Claude Code hook, verified in the host transcript: \"";
    assert_eq!(logged_request(&reason, marker), prompt);
    assert!(
        reason.starts_with("Owner approved. Exit code 0."),
        "{reason}"
    );
    assert!(!stdout.contains(SECRET) && !reason.contains(SECRET));
}

/// A real Codex session in the Apassy profile, with the hook (goal item B6). If the
/// model turn does not run, for example at the usage limit, the test sends the run
/// as the Codex adapter does: without a host session.
#[test]
#[ignore = "needs the codex program, an account, and network access"]
fn real_codex_session_sends_the_user_request() {
    let fx = fixture(ExecMode::Ask, Duration::from_secs(120));
    let host = real_host(&fx);
    let prompt = real_prompt(&fx);
    let hook_config = format!(
        "hooks.UserPromptSubmit=[{{hooks=[{{type=\"command\",command=\"{}\",timeout=5}}]}}]",
        host.wrapper.display()
    );
    let mcp_command = format!(
        "mcp_servers.apassy.command=\"{}\"",
        env!("CARGO_BIN_EXE_apassy-mcp")
    );
    let mcp_env = format!(
        "mcp_servers.apassy.env={{APASSY_AGENT_TOKEN=\"{}\",APASSY_BROKER_SOCKET=\"{}\"}}",
        fx.token,
        fx.socket.display()
    );
    let (stop, approver) = approver(&fx);
    let output = Command::new(env!("CARGO_BIN_EXE_apassy-sandbox"))
        .args(&host.sandbox)
        .args([
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-hook-trust",
            "-c",
            "sandbox_mode=\"danger-full-access\"",
            "-c",
            "approval_policy=\"never\"",
            "-c",
            &hook_config,
            "-c",
            &mcp_command,
            "-c",
            &mcp_env,
            "-c",
            "mcp_servers.apassy.tool_timeout_sec=180",
            &prompt,
        ])
        .current_dir(&fx.project)
        .stdin(Stdio::null())
        .output()
        .expect("run codex in the Apassy profile");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("codex exit: {:?}", output.status.code());
    if text.contains("usage limit") {
        eprintln!("The model turn did not run: usage limit. The test sends the run itself.");
        let response = client::send(
            &fx.socket,
            &fx.token,
            Action::Run {
                items: vec![fx.item_id],
                command: vec![
                    "sh".to_owned(),
                    "-c".to_owned(),
                    format!("test -n \"${ENV_NAME}\" && echo key-present"),
                ],
                cwd: fx.project.display().to_string(),
                purpose: "Check the key.".to_owned(),
                path: Some("/usr/bin:/bin".to_owned()),
                user_request: Some("check the key".to_owned()),
            },
        )
        .expect("broker answer");
        assert!(response.ok, "{response:?}");
    }
    stop.store(true, Ordering::SeqCst);
    let pending = approver
        .join()
        .expect("approver")
        .expect("a run waited for the owner");
    eprintln!("card source: {}", pending.request_source);
    eprintln!("card user request: {}", pending.user_request);
    eprintln!("agent text: {}", pending.agent_request);
    assert_eq!(
        pending.request_source,
        "from the Codex hook, matched by the project directory, verified in the host transcript"
    );
    assert_eq!(pending.user_request, prompt);
    let reason = last_reason(&fx);
    eprintln!("activity: {reason}");
    assert!(!reason.contains(SECRET));
}
