#![cfg(feature = "vault")]

//! Agents add credentials (ADR 0025 §6): capture, generate, save, ask the owner, update,
//! and describe. The value never leaves; only own items change; no oracle; a limit per
//! hour; capture refusals; a capture that is not a known token command waits for the
//! owner. Synthetic values only: no test runs a real token CLI.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use apassy::agent::client::{self, SendOptions};
use apassy::agent::wire::{Action, AgentSecret, Extract, GenerateSpec, WireRequest, WireResponse};
use apassy::broker::action_kind::ActionKind;
use apassy::broker::agent_items::{KNOWN_COMMANDS, KNOWN_DIRS};
use apassy::broker::approvals::{AnswerKind, OwnerAction, OwnerCheck, OwnerGate, PendingRun};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::agent_items::{
    CorrectionAnswer, CorrectionKind, CredentialRequestState, MAX_AGENT_ITEMS_PER_HOUR,
    MAX_AGENT_REQUESTS_PER_HOUR, NewCredentialRequest, RAISED_FROM_FACT, RequestOutcome,
};
use apassy::vault::detect;
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    DeclarationSource, EnvDelivery, Environment, Field, ItemDraft, MAX_ITEM_EVENTS, OriginTool,
    SecretValue, Vault, VaultErrorKind,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "agent-items-pass-ok";
const OWNER_SECRET: &str = "FAKE-owner-secret-7730-canary";
const WAIT: Duration = Duration::from_secs(20);

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    project: PathBuf,
    owner_item: u64,
    agent_id: u64,
    token: String,
    other_token: String,
    broker: BrokerHandle,
}

fn fixture(wait: Duration) -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(project.join(".git")).expect("project");
    let project = std::fs::canonicalize(project).expect("canonical project");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let owner_item = vault
        .add(ItemDraft {
            title: "Owner key".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(OWNER_SECRET.to_owned()),
                secret: true,
            }],
        })
        .expect("owner item")
        .id;
    vault
        .set_env_binding(owner_item, "OWNER_KEY", "token")
        .expect("binding");
    let (agent, token) = vault.register_agent("Tool agent").expect("agent");
    vault.set_agent_sees_all(agent.id, true).expect("see all");
    let (other, other_token) = vault.register_agent("Other agent").expect("other");
    vault.set_agent_sees_all(other.id, true).expect("see all");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = wait;
    options.run_timeout = Duration::from_secs(20);
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    Fixture {
        dir,
        vault: shared,
        socket,
        project,
        owner_item,
        agent_id: agent.id,
        token: token.expose().to_owned(),
        other_token: other_token.expose().to_owned(),
        broker,
    }
}

fn send_as(fx: &Fixture, token: &str, action: Action) -> WireResponse {
    client::send_with(
        &fx.socket,
        token,
        action,
        SendOptions {
            host_session: None,
            timeout: Some(Duration::from_secs(60)),
        },
    )
    .expect("broker answer")
}

fn send(fx: &Fixture, action: Action) -> WireResponse {
    send_as(fx, &fx.token, action)
}

/// Send on another thread: the call can wait for the owner.
fn spawn_send(fx: &Fixture, action: Action) -> JoinHandle<WireResponse> {
    let socket = fx.socket.clone();
    let token = fx.token.clone();
    std::thread::spawn(move || {
        client::send_with(
            &socket,
            &token,
            action,
            SendOptions {
                host_session: None,
                timeout: Some(Duration::from_secs(60)),
            },
        )
        .expect("broker answer")
    })
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault mutex");
    f(guard.as_mut().expect("open vault"))
}

fn code(response: &WireResponse) -> String {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response
        .error
        .as_ref()
        .map_or_else(String::new, |e| e.code.clone())
}

fn message(response: &WireResponse) -> String {
    response
        .error
        .as_ref()
        .map_or_else(String::new, |e| e.message.clone())
}

fn result(response: &WireResponse) -> Value {
    assert!(response.ok, "{response:?}");
    response.result.clone().expect("result")
}

fn item_of(response: &WireResponse) -> u64 {
    result(response)["item_id"].as_u64().expect("item_id")
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// The question that waits, within 10 seconds.
fn question(fx: &Fixture) -> PendingRun {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(run) = fx.broker.approvals().pending().into_iter().next() {
            return run;
        }
        assert!(Instant::now() < end, "no question waits");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// "Allow once" with the owner check.
fn allow_once(fx: &Fixture, run: PendingRun) {
    let proof = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(OwnerAction::ApproveRun(run), OwnerCheck::passphrase(PASS))
        .expect("owner check");
    fx.broker.approvals().approve(proof).expect("approved");
}

fn capture_action(
    fx: &Fixture,
    name: Option<&str>,
    command: &[&str],
    path: &str,
    extract: Option<Extract>,
) -> Action {
    Action::CaptureCredential {
        name: name.map(str::to_owned),
        command: Some(argv(command)),
        file: None,
        cwd: Some(fx.project.display().to_string()),
        folder: None,
        purpose: Some("Store the synthetic token.".to_owned()),
        path: Some(path.to_owned()),
        extract,
    }
}

fn capture_command(fx: &Fixture, name: Option<&str>, command: &[&str]) -> WireResponse {
    send(fx, capture_action(fx, name, command, "/usr/bin:/bin", None))
}

/// A capture of a command that is not a known token command: the owner allows it once.
fn capture_allowed(
    fx: &Fixture,
    name: Option<&str>,
    command: &[&str],
) -> (PendingRun, WireResponse) {
    let call = spawn_send(fx, capture_action(fx, name, command, "/usr/bin:/bin", None));
    let run = question(fx);
    allow_once(fx, run.clone());
    (run, call.join().expect("capture"))
}

fn capture_file_with(fx: &Fixture, file: &Path, extract: Option<Extract>) -> WireResponse {
    send(fx, file_action(fx, file, extract))
}

fn file_action(fx: &Fixture, file: &Path, extract: Option<Extract>) -> Action {
    Action::CaptureCredential {
        name: None,
        command: None,
        file: Some(file.display().to_string()),
        cwd: Some(fx.project.display().to_string()),
        folder: None,
        purpose: None,
        path: None,
        extract,
    }
}

fn capture_file(fx: &Fixture, file: &Path) -> WireResponse {
    capture_file_with(fx, file, None)
}

fn generate(fx: &Fixture, name: &str, length: Option<u32>, alphabet: Option<&str>) -> WireResponse {
    send(
        fx,
        Action::GenerateCredential {
            name: name.to_owned(),
            length,
            alphabet: alphabet.map(str::to_owned),
            cwd: Some(fx.project.display().to_string()),
            folder: None,
        },
    )
}

fn save_as(fx: &Fixture, token: &str, name: Option<&str>, value: &str) -> WireResponse {
    send_as(
        fx,
        token,
        Action::SaveCredential {
            name: name.map(str::to_owned),
            value: AgentSecret::new(value.to_owned()),
            cwd: Some(fx.project.display().to_string()),
            folder: None,
        },
    )
}

fn update_action(item_id: u64, file: Option<&Path>, generate: bool) -> Action {
    Action::UpdateCredential {
        item_id,
        command: None,
        file: file.map(|file| file.display().to_string()),
        generate: generate.then_some(GenerateSpec {
            length: Some(40),
            alphabet: None,
        }),
        // The project of the file: the parent of the file.
        cwd: file.and_then(|file| file.parent().map(|dir| dir.display().to_string())),
        path: None,
        extract: None,
    }
}

fn describe(
    fx: &Fixture,
    item_id: u64,
    name: Option<&str>,
    env: Option<&str>,
    hosts: Option<&[&str]>,
) -> WireResponse {
    send(
        fx,
        Action::DescribeCredential {
            item_id,
            name: name.map(str::to_owned),
            notes: None,
            env_name: env.map(str::to_owned),
            placeholder_hosts: hosts.map(argv),
        },
    )
}

fn reveal(fx: &Fixture, item: u64) -> String {
    with_vault(fx, |vault| {
        let binding = vault.process_binding(item).unwrap().expect("binding");
        vault
            .reveal(item, &binding.field)
            .unwrap()
            .expose()
            .to_owned()
    })
}

/// A file in the project of the agent: a capture reads it without a question.
fn project_file(fx: &Fixture, name: &str, text: &str) -> PathBuf {
    let file = fx.project.join(name);
    std::fs::write(&file, text).expect("file");
    file
}

/// The value is in no answer, activity entry, decision log entry, item history event,
/// use row, request, correction, question, or owner interaction.
fn assert_nowhere(fx: &Fixture, responses: &[&WireResponse], value: &str) {
    for response in responses {
        let text = serde_json::to_string(response).expect("json");
        assert!(!text.contains(value), "answer leaks the value: {text}");
        assert!(!format!("{response:?}").contains(value));
    }
    let pending = format!("{:?}", fx.broker.approvals().pending());
    assert!(!pending.contains(value), "a question leaks the value");
    with_vault(fx, |vault| {
        let activity = format!("{:?}", vault.recent_activity(1000).unwrap());
        assert!(!activity.contains(value), "activity leaks the value");
        let decisions = format!("{:?}", vault.decision_log().unwrap());
        assert!(!decisions.contains(value), "decision log leaks the value");
        for item in vault.search("").unwrap() {
            let events = format!("{:?}", vault.item_events(item.id, MAX_ITEM_EVENTS).unwrap());
            assert!(!events.contains(value), "history leaks the value");
            let uses = format!("{:?}", vault.item_uses(item.id, 1000).unwrap());
            assert!(!uses.contains(value), "use log leaks the value");
            let previous = format!("{:?}", vault.previous_value(item.id).unwrap());
            assert!(
                !previous.contains(value),
                "previous value info leaks the value"
            );
        }
        let requests = format!("{:?}", vault.credential_requests(false).unwrap());
        assert!(!requests.contains(value));
        let corrections = format!("{:?}", vault.corrections(false).unwrap());
        assert!(!corrections.contains(value));
    });
}

fn activity_text(fx: &Fixture) -> String {
    with_vault(fx, |vault| {
        format!("{:?}", vault.recent_activity(1000).unwrap())
    })
}

// ---- Capture: questions and known commands ----

/// H1: a command that is not a known token command does not run until the owner allows
/// it. The question names the agent, the resolved program, and the project; it offers
/// only "Allow once"; the value never shows.
#[test]
fn a_command_that_is_not_known_waits_for_the_owner_before_it_runs() {
    let fx = fixture(WAIT);
    let marker = fx.dir.path().join("ran");
    let canary = "FAKE-capture-canary-9931";
    let script = format!("touch {}; printf {canary}", marker.display());
    assert!(!script.contains('\''));
    let call = spawn_send(
        &fx,
        capture_action(
            &fx,
            Some("Synthetic CLI token"),
            &["sh", "-c", &script],
            "/usr/bin:/bin",
            None,
        ),
    );
    let run = question(&fx);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !marker.exists(),
        "the command ran before the owner answered"
    );
    // The first `sh` on PATH "/usr/bin:/bin": /bin/sh on macOS, /usr/bin/sh on a
    // merged-/usr Linux.
    let sh = ["/usr/bin/sh", "/bin/sh"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .expect("a shell");
    assert_eq!(run.command[0], sh, "the program as the PATH found it");
    assert_eq!(
        run.purpose,
        format!("Tool agent wants to capture the output of: {sh} -c '{script}' in project")
    );
    assert!(run.question.item_ids.is_empty());
    assert_eq!(run.question.valid_answers, vec![AnswerKind::Once]);
    assert_eq!(run.question.action, ActionKind::Read);
    assert!(
        run.remember.is_none(),
        "nothing is remembered for a capture"
    );
    // A remembered answer is refused for a capture question.
    let project = run.question.project.clone().expect("project");
    let remembered = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(
            OwnerAction::ApproveInProject {
                run: run.clone(),
                project,
                action: ActionKind::Read,
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    assert!(fx.broker.approvals().approve(remembered).is_err());
    assert!(!marker.exists());
    allow_once(&fx, run);
    let response = call.join().expect("capture");
    let item = item_of(&response);
    assert!(marker.exists(), "the command ran after the answer");
    assert_eq!(reveal(&fx, item), canary);
    assert_eq!(result(&response)["env_name"], "SYNTHETIC_CLI_TOKEN");
    with_vault(&fx, |vault| {
        let origin = vault.item_origin(item).unwrap().expect("origin");
        assert_eq!(origin.origin.agent_id, fx.agent_id);
        assert_eq!(origin.origin.tool, OriginTool::Capture);
        let created = vault.item_events(item, MAX_ITEM_EVENTS).unwrap();
        assert!(
            created
                .iter()
                .any(|event| event.detail == "Added by Tool agent in project (capture)."),
            "{created:?}"
        );
    });
    // Item 10: the activity names the agent.
    let activity = activity_text(&fx);
    assert!(
        activity
            .contains("Added by Tool agent in project (capture). The owner allowed the capture."),
        "{activity}"
    );
    assert!(!activity.contains("Added by the agent"), "{activity}");
    // The same value again returns the item and creates nothing; it asks again.
    let (_, again) = capture_allowed(&fx, None, &["sh", "-c", &format!("printf {canary}")]);
    assert_eq!(item_of(&again), item);
    assert_eq!(result(&again)["created"], false);
    assert_nowhere(&fx, &[&response, &again], canary);
}

#[test]
fn a_denied_capture_runs_nothing_and_stores_nothing() {
    let fx = fixture(WAIT);
    let marker = fx.dir.path().join("ran");
    let script = format!("touch {}; echo FAKE-denied-0001", marker.display());
    let call = spawn_send(
        &fx,
        capture_action(
            &fx,
            None,
            &["/bin/sh", "-c", &script],
            "/usr/bin:/bin",
            None,
        ),
    );
    let run = question(&fx);
    assert!(fx.broker.approvals().deny(run.id));
    let response = call.join().expect("capture");
    assert_eq!(code(&response), "approval_denied");
    assert!(!marker.exists());
    with_vault(&fx, |vault| {
        assert!(vault.items_created_by(fx.agent_id, 0).unwrap().is_empty());
    });
}

/// A capture question waits like a run question: the same request again joins it (the
/// older call ends with question_waiting), and another request of the agent gets
/// question_waiting.
#[test]
fn a_capture_question_reattaches_and_blocks_other_questions() {
    let fx = fixture(WAIT);
    let command = ["/bin/echo", "FAKE-reattach-0002"];
    let first = spawn_send(
        &fx,
        capture_action(&fx, None, &command, "/usr/bin:/bin", None),
    );
    let run = question(&fx);
    let second = spawn_send(
        &fx,
        capture_action(&fx, None, &command, "/usr/bin:/bin", None),
    );
    let superseded = first.join().expect("first");
    assert_eq!(code(&superseded), "question_waiting");
    assert_eq!(fx.broker.approvals().pending().len(), 1, "one question");
    let other = capture_command(&fx, None, &["/bin/echo", "FAKE-other-0003"]);
    assert_eq!(code(&other), "question_waiting");
    let still = question(&fx);
    assert_eq!(still.id, run.id);
    allow_once(&fx, still);
    assert!(item_of(&second.join().expect("second")) > 0);
}

/// H1: the PATH of the agent cannot make a known token command run a program of its
/// choice. A known shape with a program that is not in the fixed folders is a question
/// that shows the program that would run.
#[test]
fn the_path_of_the_agent_never_picks_a_known_command_program() {
    let candidates: [(&str, &[&str]); 3] = [
        ("heroku", &["heroku", "auth:token"]),
        ("flyctl", &["flyctl", "auth", "token"]),
        (
            "doppler",
            &["doppler", "secrets", "get", "API_KEY", "--plain"],
        ),
    ];
    // Only a program that this Mac does not have: no test runs a real token CLI.
    let Some((program, command)) = candidates.into_iter().find(|(program, _)| {
        KNOWN_DIRS
            .iter()
            .all(|dir| !Path::new(dir).join(program).exists())
    }) else {
        eprintln!("skipped: every candidate CLI is installed");
        return;
    };
    assert!(
        KNOWN_COMMANDS
            .iter()
            .any(|known| known.programs.contains(&program) && known.matches(&argv(&command[1..])))
    );
    let fx = fixture(WAIT);
    let evil = fx.dir.path().join("evil");
    std::fs::create_dir_all(&evil).expect("evil");
    let evil = std::fs::canonicalize(evil).expect("canonical");
    let marker = fx.dir.path().join("evil-ran");
    let fake = evil.join(program);
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\ntouch '{}'\necho FAKE-evil-0004\n",
            marker.display()
        ),
    )
    .expect("fake");
    std::process::Command::new("/bin/chmod")
        .args(["755", &fake.display().to_string()])
        .status()
        .expect("chmod");
    let path = format!("{}:/usr/bin:/bin", evil.display());
    let call = spawn_send(&fx, capture_action(&fx, None, command, &path, None));
    let run = question(&fx);
    assert_eq!(run.command[0], fake.display().to_string());
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !marker.exists(),
        "the program of the PATH ran without the owner"
    );
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&call.join().expect("capture")), "approval_denied");
    assert!(!marker.exists());
}

/// H3: `op://` is a reference, not a host. A command that names one is not refused.
#[test]
fn an_op_reference_is_not_refused() {
    let fx = fixture(WAIT);
    let (run, response) = capture_allowed(
        &fx,
        Some("Op reference"),
        &["/bin/echo", "op://Private/Stripe/key"],
    );
    assert!(!run.risk.contains("It names:"), "{}", run.risk);
    assert_eq!(reveal(&fx, item_of(&response)), "op://Private/Stripe/key");
}

/// Approved commands still meet the output rules.
#[test]
fn an_allowed_command_with_bad_output_stores_nothing() {
    let fx = fixture(WAIT);
    for command in [
        &["head", "-c", "70000", "/dev/zero"][..],
        &["/usr/bin/true"],
        &["/usr/bin/false"],
    ] {
        let (_, response) = capture_allowed(&fx, None, command);
        assert_eq!(code(&response), "capture_refused", "{command:?}");
    }
    with_vault(&fx, |vault| {
        assert!(vault.items_created_by(fx.agent_id, 0).unwrap().is_empty());
    });
}

// ---- Capture: files ----

#[test]
fn capture_reads_a_file_of_the_project_at_once() {
    let fx = fixture(WAIT);
    let canary = "FAKE-file-canary-1187";
    let file = project_file(&fx, "key.txt", &format!("  {canary}\n\n"));
    let response = capture_file(&fx, &file);
    let item = item_of(&response);
    assert_eq!(reveal(&fx, item), canary);
    assert!(fx.broker.approvals().pending().is_empty());
    assert_nowhere(&fx, &[&response], canary);
}

/// H2: a file outside the project is a question; the owner allows or denies it.
#[test]
fn a_file_outside_the_project_waits_for_the_owner() {
    let fx = fixture(WAIT);
    let canary = "FAKE-outside-canary-2201";
    let file = fx.dir.path().join("outside.txt");
    std::fs::write(&file, canary).expect("file");
    let call = spawn_send(&fx, file_action(&fx, &file, None));
    let run = question(&fx);
    let canonical = std::fs::canonicalize(&file).expect("canonical");
    assert_eq!(
        run.purpose,
        format!(
            "Tool agent wants to capture the file: {} in project",
            canonical.display()
        )
    );
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&call.join().expect("denied")), "approval_denied");
    let call = spawn_send(&fx, file_action(&fx, &file, None));
    allow_once(&fx, question(&fx));
    let response = call.join().expect("allowed");
    assert_eq!(reveal(&fx, item_of(&response)), canary);
    assert_nowhere(&fx, &[&response], canary);
}

#[test]
fn capture_refuses_apassy_paths_special_files_and_bad_output() {
    let fx = fixture(WAIT);
    let refused = |response: &WireResponse| {
        assert_eq!(code(response), "capture_refused", "{response:?}");
    };
    // The Apassy data folder: refused by its path, nothing is read or made there.
    refused(&capture_file(
        &fx,
        &apassy::paths::data_dir().join("t2-synthetic-probe"),
    ));
    // The open vault file, its sidecar, and its backup.
    let vault_file = with_vault(&fx, |vault| vault.path().to_path_buf());
    refused(&capture_file(&fx, &vault_file));
    let lock = PathBuf::from(format!("{}.lock", vault_file.display()));
    refused(&capture_file(&fx, &lock));
    let backup = PathBuf::from(format!("{}.backup", vault_file.display()));
    std::fs::write(&backup, "FAKE-backup-not-a-vault").expect("backup");
    refused(&capture_file(&fx, &backup));
    // The Apassy folder in iCloud Drive, also when it does not exist.
    if let Some(home) = std::env::var_os("HOME") {
        let cloud = PathBuf::from(home)
            .join("Library/Mobile Documents/com~apple~CloudDocs/Apassy/vault.db");
        refused(&capture_file(&fx, &cloud));
    }
    // A command never names a path of Apassy, also not after an answer: no question.
    refused(&capture_command(
        &fx,
        None,
        &["cat", &vault_file.display().to_string()],
    ));
    refused(&capture_command(
        &fx,
        None,
        &["cat", &backup.display().to_string()],
    ));
    // The Keychain tool never runs.
    refused(&capture_command(
        &fx,
        None,
        &["security", "find-generic-password", "-w"],
    ));
    assert!(fx.broker.approvals().pending().is_empty(), "no question");
    // A FIFO is refused at once, also outside the project; the read never blocks.
    let fifo = fx.dir.path().join("pipe");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(made.success());
    let started = Instant::now();
    refused(&capture_file(&fx, &fifo));
    assert!(started.elapsed() < Duration::from_secs(5));
    // A folder, a file over 64 KiB, an empty file.
    refused(&capture_file(&fx, &fx.project));
    let big = project_file(&fx, "big.txt", &"a".repeat(64 * 1024 + 1));
    refused(&capture_file(&fx, &big));
    let empty = project_file(&fx, "empty.txt", "  \n");
    refused(&capture_file(&fx, &empty));
    assert!(fx.broker.approvals().pending().is_empty(), "no question");
    // Nothing was made.
    with_vault(&fx, |vault| {
        assert!(vault.items_created_by(fx.agent_id, 0).unwrap().is_empty());
    });
}

/// H3: extract picks the credential from an output in the broker.
#[test]
fn extract_takes_a_json_path_a_line_or_the_text_after_a_label() {
    let fx = fixture(WAIT);
    let json_file = project_file(
        &fx,
        "session.json",
        r#"{"Credentials":{"AccessKeyId":"FAKEKEYID","SessionToken":"FAKE-json-session-7781"}}"#,
    );
    let response = capture_file_with(
        &fx,
        &json_file,
        Some(Extract::Json("Credentials.SessionToken".to_owned())),
    );
    assert_eq!(reveal(&fx, item_of(&response)), "FAKE-json-session-7781");
    let lines = project_file(
        &fx,
        "login.txt",
        "Logged in as synthetic\nToken: FAKE-after-token-7782\nFAKE-line-three-7783\n",
    );
    let after = capture_file_with(&fx, &lines, Some(Extract::After("Token:".to_owned())));
    assert_eq!(reveal(&fx, item_of(&after)), "FAKE-after-token-7782");
    let line = capture_file_with(&fx, &lines, Some(Extract::Line(3)));
    assert_eq!(reveal(&fx, item_of(&line)), "FAKE-line-three-7783");
    for (extract, file) in [
        (Extract::Json("Credentials.Missing".to_owned()), &json_file),
        (Extract::Line(9), &lines),
        (Extract::After("Secret:".to_owned()), &lines),
    ] {
        let refused = capture_file_with(&fx, file, Some(extract));
        assert_eq!(code(&refused), "capture_refused");
        assert!(!message(&refused).contains("FAKE"), "{refused:?}");
    }
    assert_eq!(
        code(&capture_file_with(
            &fx,
            &lines,
            Some(Extract::After("Token: FAKE".to_owned()))
        )),
        "invalid_request"
    );
    assert_nowhere(&fx, &[&response, &after, &line], "FAKE-json-session-7781");
}

// ---- Generate, save, limits ----

#[test]
fn generate_uses_the_length_and_the_alphabet_and_never_returns_the_value() {
    let fx = fixture(WAIT);
    let cases: [(Option<u32>, Option<&str>, usize, &str); 5] = [
        (
            None,
            None,
            32,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        ),
        (Some(16), Some("hex"), 16, "0123456789abcdef"),
        (
            Some(64),
            Some("base64url"),
            64,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        ),
        (
            Some(128),
            Some("symbols"),
            128,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%()*+,-./:;<=>?@[]^_{|}~",
        ),
        (
            Some(20),
            Some("alnum"),
            20,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        ),
    ];
    for (index, (length, alphabet, expected, chars)) in cases.into_iter().enumerate() {
        let response = generate(
            &fx,
            &format!("Synthetic password {index}"),
            length,
            alphabet,
        );
        let item = item_of(&response);
        let value = reveal(&fx, item);
        assert_eq!(value.len(), expected);
        assert!(value.chars().all(|c| chars.contains(c)), "{alphabet:?}");
        assert_eq!(
            result(&response)["env_name"],
            format!("SYNTHETIC_PASSWORD_{index}")
        );
        assert_nowhere(&fx, &[&response], &value);
    }
    for (length, alphabet) in [(Some(15), None), (Some(129), None), (None, Some("emoji"))] {
        assert_eq!(
            code(&generate(&fx, "Bad", length, alphabet)),
            "invalid_request"
        );
    }
}

#[test]
fn save_dedups_only_among_own_items_and_is_not_an_oracle() {
    let fx = fixture(WAIT);
    let canary = "FAKE-save-canary-6402";
    let first = save_as(&fx, &fx.token, Some("Webhook secret"), canary);
    let item = item_of(&first);
    assert_eq!(result(&first)["created"], true);
    let again = save_as(&fx, &fx.token, None, canary);
    assert_eq!(item_of(&again), item);
    assert_eq!(result(&again)["created"], false);
    // The value of the owner's item: a new item, nothing about the owner's item.
    let owner = save_as(&fx, &fx.token, None, OWNER_SECRET);
    assert_eq!(result(&owner)["created"], true);
    assert_ne!(item_of(&owner), fx.owner_item);
    // Another agent with the same value as this agent's item: its own new item.
    let other = save_as(&fx, &fx.other_token, None, canary);
    assert_eq!(result(&other)["created"], true);
    assert_ne!(item_of(&other), item);
    assert_nowhere(&fx, &[&first, &again, &other], canary);
    assert_nowhere(&fx, &[&owner], OWNER_SECRET);
    // The name never holds the value.
    assert_eq!(
        code(&save_as(
            &fx,
            &fx.token,
            Some(&format!("x {canary}2")),
            &format!("{canary}2")
        )),
        "invalid_request"
    );
}

#[test]
fn an_agent_adds_at_most_ten_items_an_hour() {
    let fx = fixture(WAIT);
    for index in 0..MAX_AGENT_ITEMS_PER_HOUR {
        item_of(&generate(&fx, &format!("Limit {index}"), None, None));
    }
    let over = generate(&fx, "Limit over", None, None);
    assert_eq!(code(&over), "too_many_items");
    assert!(message(&over).contains("apassy_ask_owner_for_credential"));
    assert_eq!(
        code(&save_as(&fx, &fx.token, None, "FAKE-limit-canary-0001")),
        "too_many_items"
    );
    // The limit comes before a question.
    assert_eq!(
        code(&capture_command(
            &fx,
            None,
            &["/bin/echo", "FAKE-limit-canary-0002"]
        )),
        "too_many_items"
    );
    assert!(fx.broker.approvals().pending().is_empty());
    // Another agent has its own limit.
    item_of(&save_as(
        &fx,
        &fx.other_token,
        None,
        "FAKE-limit-canary-0003",
    ));
}

/// Item 8: each new value counts toward the hourly limit.
#[test]
fn updates_count_toward_the_hourly_limit() {
    let fx = fixture(WAIT);
    let half = MAX_AGENT_ITEMS_PER_HOUR / 2;
    let items: Vec<u64> = (0..half)
        .map(|index| item_of(&generate(&fx, &format!("Rotating {index}"), None, None)))
        .collect();
    for item in &items {
        assert_eq!(
            result(&send(&fx, update_action(*item, None, true)))["updated"],
            true
        );
    }
    with_vault(&fx, |vault| {
        assert_eq!(
            vault.agent_changes_in_last_hour(fx.agent_id).unwrap(),
            MAX_AGENT_ITEMS_PER_HOUR
        );
    });
    let refused = send(&fx, update_action(items[0], None, true));
    assert_eq!(code(&refused), "too_many_items");
    assert!(
        message(&refused).contains("ask the owner") || message(&refused).contains("Ask the owner")
    );
    assert_eq!(
        code(&generate(&fx, "One more", None, None)),
        "too_many_items"
    );
}

// ---- Update ----

#[test]
fn update_and_describe_only_change_own_items() {
    let fx = fixture(WAIT);
    let own = item_of(&generate(&fx, "Own password", Some(32), None));
    let other = item_of(&save_as(
        &fx,
        &fx.other_token,
        None,
        "FAKE-other-canary-3310",
    ));
    for item in [fx.owner_item, other, 99_999] {
        assert_eq!(
            code(&send(&fx, update_action(item, None, true))),
            "not_owner",
            "{item}"
        );
        assert_eq!(
            code(&describe(&fx, item, Some("Mine"), None, None)),
            "not_owner"
        );
    }
    assert_eq!(reveal(&fx, fx.owner_item), OWNER_SECRET, "unchanged");
    let before = reveal(&fx, own);
    let updated = send(&fx, update_action(own, None, true));
    assert_eq!(result(&updated)["updated"], true);
    let after = reveal(&fx, own);
    assert_eq!(after.len(), 40);
    assert_ne!(before, after);
    assert_nowhere(&fx, &[&updated], &after);
    assert_nowhere(&fx, &[&updated], &before);
    let activity = activity_text(&fx);
    assert!(
        activity.contains("Tool agent gave its credential a new value."),
        "{activity}"
    );
    // Describe: name, variable.
    let described = describe(
        &fx,
        own,
        Some("Staging password"),
        Some("STAGING_DB_PASSWORD"),
        None,
    );
    assert_eq!(result(&described)["name"], "Staging password");
    assert_eq!(result(&described)["env_name"], "STAGING_DB_PASSWORD");
    assert!(
        activity_text(&fx).contains("Tool agent changed the name, variable of its credential.")
    );
    assert_eq!(
        code(&describe(&fx, own, None, Some("OWNER_KEY"), None)),
        "env_name_taken"
    );
    for reserved in ["PATH", "APASSY_ITEM_1"] {
        assert_eq!(
            code(&describe(&fx, own, None, Some(reserved), None)),
            "invalid_request"
        );
    }
}

/// H2 of the update: the previous value stays for the owner, never for an agent, and
/// goes after the next allowed use. The owner can restore it.
#[test]
fn update_keeps_the_previous_value_and_the_owner_can_restore_it() {
    let fx = fixture(WAIT);
    let own = item_of(&generate(&fx, "Rotated password", Some(32), None));
    let first = reveal(&fx, own);
    let updated = send(&fx, update_action(own, None, true));
    let second = reveal(&fx, own);
    assert_ne!(first, second);
    with_vault(&fx, |vault| {
        let previous = vault.previous_value(own).unwrap().expect("previous");
        assert_eq!(previous.replaced_by, "Tool agent");
        assert_eq!(previous.until, previous.replaced_at + 7 * 24 * 3600);
        // Never in the details or the catalog.
        let details = format!("{:?}", vault.details(own).unwrap());
        assert!(!details.contains(&first));
        assert!(!format!("{:?}", vault.catalog().unwrap()).contains(&first));
        vault.restore_previous_value(own).expect("restore");
        assert!(vault.previous_value(own).unwrap().is_none());
        assert_eq!(
            vault.restore_previous_value(own).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    });
    assert_eq!(reveal(&fx, own), first, "restored");
    let listed = send(&fx, Action::ListAccess);
    assert!(!serde_json::to_string(&listed).unwrap().contains(&second));
    assert_nowhere(&fx, &[&updated, &listed], &first);
    assert_nowhere(&fx, &[&updated, &listed], &second);
    // The next allowed use of the new value drops the previous value.
    send(&fx, update_action(own, None, true));
    let use_of = |outcome: UseOutcome| NewItemUse {
        item_id: own,
        agent_id: Some(fx.agent_id),
        agent_name: "Tool agent".to_owned(),
        project_key: String::new(),
        project_label: String::new(),
        action: ActionKind::Read,
        command_summary: "synthetic".to_owned(),
        hosts: Vec::new(),
        outcome,
        decided_by: UseDecidedBy::Bouncer,
        answered_on: String::new(),
        decision_log_id: None,
    };
    with_vault(&fx, |vault| {
        vault.record_item_use(&use_of(UseOutcome::Denied)).unwrap();
        assert!(
            vault.previous_value(own).unwrap().is_some(),
            "a denied use keeps it"
        );
        vault.record_item_use(&use_of(UseOutcome::Allowed)).unwrap();
        assert!(vault.previous_value(own).unwrap().is_none());
        assert_eq!(
            vault.restore_previous_value(own).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(vault.prune_previous_values().unwrap(), 1);
    });
}

/// Item 5: the new value is detected again. The declaration becomes the stricter of the
/// old and the new one, and each source the weaker one.
#[test]
fn update_makes_the_declaration_stricter_with_the_weaker_sources() {
    let fx = fixture(WAIT);
    let test_key = "sk_test_FAKEsyntheticStripeKey000000001";
    let own = item_of(&save_as(&fx, &fx.token, Some("Stripe test"), test_key));
    let (declaration, sources) = with_vault(&fx, |vault| {
        (
            vault.declaration(own).unwrap().expect("declaration"),
            vault.declaration_sources(own).unwrap(),
        )
    });
    assert_eq!(declaration.environment, Environment::Staging);
    assert_eq!(sources.environment, DeclarationSource::Signal);
    // A value without a signal: production, from the default; never "staging" from the
    // signal of the old value.
    let plain = project_file(&fx, "new.txt", "FAKEplainvaluewithoutanysignal0001");
    let updated = send(&fx, update_action(own, Some(&plain), false));
    assert_eq!(result(&updated)["updated"], true);
    with_vault(&fx, |vault| {
        let declaration = vault.declaration(own).unwrap().expect("declaration");
        let sources = vault.declaration_sources(own).unwrap();
        assert_eq!(declaration.environment, Environment::Production);
        assert_eq!(sources.environment, DeclarationSource::Default);
        assert_eq!(sources.risk, DeclarationSource::Default);
    });
    // Back to a test key: stays production (stricter), and the source stays the default.
    let back = project_file(&fx, "back.txt", "sk_test_FAKEsyntheticStripeKey000000002");
    send(&fx, update_action(own, Some(&back), false));
    with_vault(&fx, |vault| {
        let declaration = vault.declaration(own).unwrap().expect("declaration");
        assert_eq!(declaration.environment, Environment::Production);
        assert_eq!(
            vault.declaration_sources(own).unwrap().environment,
            DeclarationSource::Default
        );
    });
    assert_nowhere(&fx, &[&updated], test_key);
}

// ---- Describe ----

/// Item 6: an env_name must not be the variable of another item: its explicit name, the
/// variable of its provider, or an automatic name.
#[test]
fn describe_refuses_the_variable_of_another_item_or_its_provider() {
    let fx = fixture(WAIT);
    let stripe = with_vault(&fx, |vault| {
        let found = detect::detect("sk_test_FAKEownerStripeKey00000000003");
        let id = vault.add_detected(&found[0], None, None).unwrap().id;
        // The owner's Stripe item has no explicit name now: its provider still names
        // STRIPE_SECRET_KEY.
        vault.clear_env_binding(id).unwrap();
        id
    });
    let own = item_of(&generate(&fx, "Own token", None, None));
    assert_eq!(
        code(&describe(&fx, own, None, Some("STRIPE_SECRET_KEY"), None)),
        "env_name_taken"
    );
    assert_eq!(
        code(&describe(
            &fx,
            own,
            None,
            Some(&format!("APASSY_ITEM_{stripe}")),
            None
        )),
        "invalid_request"
    );
    assert!(describe(&fx, own, None, Some("OWN_TOKEN_2"), None).ok);
}

/// Item 6: placeholder hosts only for an API key or a login, and only narrowing.
#[test]
fn placeholder_hosts_are_only_for_api_keys_and_only_narrow() {
    let fx = fixture(WAIT);
    let custom = item_of(&generate(&fx, "Custom secret", None, None));
    let database = item_of(&save_as(
        &fx,
        &fx.token,
        Some("Synthetic database"),
        "postgres://app:FAKEdbpassword0005@db.example.com:5432/app",
    ));
    with_vault(&fx, |vault| {
        assert_eq!(
            vault.details(database).unwrap().summary.kind,
            CredentialKind::Database
        );
    });
    for item in [custom, database] {
        let refused = describe(&fx, item, None, None, Some(&["api.example.com"]));
        assert_eq!(code(&refused), "invalid_request");
        assert!(
            message(&refused).contains("only for an API key"),
            "{refused:?}"
        );
    }
    let resend = item_of(&save_as(
        &fx,
        &fx.token,
        Some("Synthetic Resend"),
        "re_FAKEsyntheticResendKey000000006",
    ));
    let hosts = with_vault(&fx, |vault| {
        match vault.process_binding(resend).unwrap().unwrap().delivery {
            EnvDelivery::Placeholder(hosts) => hosts,
            EnvDelivery::Value => Vec::new(),
        }
    });
    assert_eq!(hosts, vec!["api.resend.com".to_owned()]);
    assert!(describe(&fx, resend, None, None, Some(&["api.resend.com"])).ok);
    assert_eq!(
        code(&describe(
            &fx,
            resend,
            None,
            None,
            Some(&["api.resend.com", "evil.example.com"])
        )),
        "invalid_request",
        "widening is refused"
    );
}

// ---- Ask the owner ----

fn ask_action(fx: &Fixture, name: &str, purpose: &str, where_to_get: &str) -> Action {
    Action::AskOwnerForCredential {
        name: name.to_owned(),
        purpose: purpose.to_owned(),
        where_to_get: Some(where_to_get.to_owned()),
        cwd: Some(fx.project.display().to_string()),
        folder: None,
    }
}

fn open_requests(fx: &Fixture) -> Vec<apassy::vault::agent_items::CredentialRequest> {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let open = with_vault(fx, |vault| vault.credential_requests(true).unwrap());
        if !open.is_empty() {
            return open;
        }
        assert!(Instant::now() < end, "no request");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn ask_owner_waits_reattaches_and_gets_the_item_or_a_dismissal() {
    let fx = fixture(Duration::from_secs(3));
    // 1. Timeout: `waiting` with the request ID; the request stays open.
    let timed_out = send(
        &fx,
        ask_action(
            &fx,
            "Synthetic Sentry token",
            "Upload the synthetic source maps.",
            "https://sentry.io/settings/auth-tokens/",
        ),
    );
    assert_eq!(code(&timed_out), "waiting");
    let requests = open_requests(&fx);
    assert_eq!(requests.len(), 1);
    let request = requests[0].clone();
    assert_eq!(request.project_label, "project");
    assert!(message(&timed_out).contains(&format!("Request {}", request.id)));
    // Item 7: the place to get it is plain text, with its registrable domain.
    assert_eq!(
        request.where_to_get,
        "https://sentry.io/settings/auth-tokens/"
    );
    assert_eq!(request.where_domain.as_deref(), Some("sentry.io"));
    // 2. A paraphrased retry (same name, other words) re-attaches; the owner saves and
    //    the waiting call gets the item.
    let waiter = spawn_send(
        &fx,
        ask_action(
            &fx,
            "synthetic  SENTRY token",
            "I need it to upload maps.",
            "Sentry settings",
        ),
    );
    std::thread::sleep(Duration::from_millis(300));
    with_vault(&fx, |vault| {
        assert_eq!(
            vault.credential_requests(true).unwrap().len(),
            1,
            "re-attached"
        );
    });
    let pasted = "FAKE-pasted-canary-2219";
    let item = with_vault(&fx, |vault| {
        let found = detect::detect(pasted);
        vault.save_for_request(request.id, &found, None).unwrap()[0].id
    });
    let saved = waiter.join().expect("waiter");
    assert_eq!(item_of(&saved), item);
    assert_nowhere(&fx, &[&saved, &timed_out], pasted);
    with_vault(&fx, |vault| {
        let origin = vault.item_origin(item).unwrap().expect("origin");
        assert_eq!(origin.origin.tool, OriginTool::AskOwner);
        assert!(!vault.agent_owns_item(fx.agent_id, item).unwrap());
        assert_eq!(
            vault.credential_request(request.id).unwrap().state,
            CredentialRequestState::Saved
        );
    });
    // The same request after the save gets the item at once.
    assert_eq!(
        item_of(&send(
            &fx,
            ask_action(&fx, "Synthetic Sentry token", "Again.", "")
        )),
        item
    );
    // 3. A waiting request blocks another one (question_waiting names it); a dismissal
    //    answers the waiting call and the same request again.
    let waiter = spawn_send(&fx, ask_action(&fx, "Synthetic npm token", "Publish.", ""));
    let second = loop {
        if let Some(found) = open_requests(&fx)
            .into_iter()
            .find(|r| r.name == "Synthetic npm token")
        {
            break found;
        }
    };
    let busy = send(&fx, ask_action(&fx, "Synthetic PyPI token", "Publish.", ""));
    assert_eq!(code(&busy), "question_waiting");
    assert!(
        message(&busy).contains(&format!("Credential request {}", second.id)),
        "{busy:?}"
    );
    with_vault(&fx, |vault| {
        vault
            .settle_credential_request(second.id, RequestOutcome::Dismissed)
            .unwrap();
    });
    assert_eq!(code(&waiter.join().expect("waiter")), "dismissed");
    assert_eq!(
        code(&send(
            &fx,
            ask_action(&fx, "Synthetic npm token", "Publish now.", "")
        )),
        "dismissed"
    );
    with_vault(&fx, |vault| {
        assert!(vault.credential_requests(true).unwrap().is_empty());
        assert!(
            vault
                .settle_credential_request(second.id, RequestOutcome::Dismissed)
                .is_err(),
            "settled once"
        );
    });
}

/// Item 7: at most 5 open or new requests per agent in an hour.
#[test]
fn ask_owner_has_an_hourly_cap() {
    let fx = fixture(Duration::from_millis(200));
    with_vault(&fx, |vault| {
        for index in 0..MAX_AGENT_REQUESTS_PER_HOUR {
            let id = vault
                .open_credential_request(&NewCredentialRequest {
                    agent_id: fx.agent_id,
                    agent_name: "Tool agent".to_owned(),
                    project_key: String::new(),
                    project_label: String::new(),
                    name: format!("Old request {index}"),
                    purpose: "Synthetic.".to_owned(),
                    where_to_get: String::new(),
                    folder: None,
                })
                .unwrap();
            vault
                .settle_credential_request(id, RequestOutcome::Dismissed)
                .unwrap();
        }
    });
    let capped = send(&fx, ask_action(&fx, "One more token", "Synthetic.", ""));
    assert_eq!(code(&capped), "too_many_requests");
}

/// save_for_request: the items and the settled request in one transaction.
#[test]
fn save_for_request_is_atomic() {
    let fx = fixture(Duration::from_millis(200));
    with_vault(&fx, |vault| {
        vault.set_agent_sees_all(fx.agent_id, false).unwrap()
    });
    let request = with_vault(&fx, |vault| {
        vault
            .open_credential_request(&NewCredentialRequest {
                agent_id: fx.agent_id,
                agent_name: "Tool agent".to_owned(),
                project_key: String::new(),
                project_label: String::new(),
                name: "Synthetic env".to_owned(),
                purpose: "Synthetic.".to_owned(),
                where_to_get: String::new(),
                folder: None,
            })
            .unwrap()
    });
    let good = detect::detect("FAKE-request-canary-7001");
    let mut broken = detect::detect("FAKE-request-canary-7002");
    broken[0].provider = Some("no-such-provider".to_owned());
    let both: Vec<_> = good.iter().chain(&broken).cloned().collect();
    with_vault(&fx, |vault| {
        let before = vault.search("").unwrap().len();
        assert_eq!(
            vault
                .save_for_request(request, &both, None)
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(vault.search("").unwrap().len(), before, "nothing was added");
        assert_eq!(
            vault.credential_request(request).unwrap().state,
            CredentialRequestState::Open
        );
        let two: Vec<_> = good
            .iter()
            .chain(&detect::detect("FAKE-request-canary-7003"))
            .cloned()
            .collect();
        let saved = vault.save_for_request(request, &two, None).unwrap();
        assert_eq!(saved.len(), 2);
        let settled = vault.credential_request(request).unwrap();
        assert_eq!(settled.state, CredentialRequestState::Saved);
        assert_eq!(settled.item_id, Some(saved[0].id));
        let view = vault.agent_view(fx.agent_id).unwrap();
        for summary in &saved {
            assert!(view.visible(summary.id), "listed for the restricted agent");
            let origin = vault.item_origin(summary.id).unwrap().expect("origin");
            assert_eq!(origin.origin.tool, OriginTool::AskOwner);
        }
        assert_eq!(
            vault
                .save_for_request(request, &good, None)
                .unwrap_err()
                .kind(),
            VaultErrorKind::Conflict
        );
    });
}

// ---- Corrections ----

/// Item 11: the owner check of a correction answer that gives authority back.
#[test]
fn a_correction_answer_that_loosens_needs_the_owner_check() {
    let fx = fixture(Duration::from_millis(200));
    with_vault(&fx, |vault| {
        let found = detect::detect("FAKE-correction-canary-8001");
        let item = vault.add_detected(&found[0], None, None).unwrap().id;
        assert_eq!(
            vault.declaration(item).unwrap().unwrap().environment,
            Environment::Production
        );
        let development = vault
            .propose_correction(item, CorrectionKind::Environment, "development", &json!({}))
            .unwrap()
            .expect("proposed");
        assert!(vault.needs_owner_check_for_correction(development, CorrectionAnswer::Accepted));
        assert!(!vault.needs_owner_check_for_correction(development, CorrectionAnswer::Ignored));
        // A production correction that raised the item from development: ignoring it
        // gives development back.
        let raised = vault
            .propose_correction(
                item,
                CorrectionKind::Environment,
                "production",
                &json!({ RAISED_FROM_FACT: "development" }),
            )
            .unwrap()
            .expect("proposed");
        assert!(!vault.needs_owner_check_for_correction(raised, CorrectionAnswer::Accepted));
        assert!(vault.needs_owner_check_for_correction(raised, CorrectionAnswer::Ignored));
        let project = vault
            .propose_correction(item, CorrectionKind::Project, "project", &json!({}))
            .unwrap()
            .expect("proposed");
        assert!(!vault.needs_owner_check_for_correction(project, CorrectionAnswer::Accepted));
        assert!(!vault.needs_owner_check_for_correction(project, CorrectionAnswer::Ignored));
        assert!(vault.needs_owner_check_for_correction(99_999, CorrectionAnswer::Ignored));
    });
}

/// ADR 0025 §3f: an agent with "only these items" can use the item that it added, and
/// nothing else changes for it.
#[test]
fn a_restricted_agent_gets_its_own_new_item_on_its_list() {
    let fx = fixture(WAIT);
    with_vault(&fx, |vault| {
        vault.set_agent_sees_all(fx.agent_id, false).unwrap();
    });
    let item = item_of(&generate(&fx, "Restricted password", None, None));
    with_vault(&fx, |vault| {
        let view = vault.agent_view(fx.agent_id).unwrap();
        assert!(view.restricted);
        assert!(view.visible(item));
        assert!(!view.visible(fx.owner_item));
    });
}

#[test]
fn the_wire_request_debug_never_shows_a_saved_value() {
    let canary = "FAKE-debug-canary-4417";
    let request = WireRequest {
        v: 0,
        token: "apassy_agt_synthetic".to_owned(),
        host_session: None,
        action: Action::SaveCredential {
            name: None,
            value: AgentSecret::new(canary.to_owned()),
            cwd: None,
            folder: None,
        },
    };
    assert!(!format!("{request:?}").contains(canary));
}
