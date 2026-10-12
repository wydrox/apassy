#![cfg(feature = "vault")]

//! Agents add credentials (ADR 0025 §6): capture, generate, save, ask the owner, update,
//! and describe. The value never leaves; only own items change; no oracle; a limit per
//! hour; capture refusals. Synthetic values only.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client::{self, SendOptions};
use apassy::agent::wire::{Action, AgentSecret, GenerateSpec, WireRequest, WireResponse};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::agent_items::{
    CredentialRequestState, MAX_AGENT_ITEMS_PER_HOUR, RequestOutcome,
};
use apassy::vault::detect;
use apassy::vault::{
    EnvDelivery, Field, ItemDraft, MAX_ITEM_EVENTS, OriginTool, SecretValue, Vault,
};
use serde_json::Value;
use tempfile::TempDir;

const PASS: &str = "agent-items-pass-ok";
const OWNER_SECRET: &str = "FAKE-owner-secret-7730-canary";

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    project: PathBuf,
    owner_item: u64,
    agent_id: u64,
    token: String,
    other_token: String,
    _broker: BrokerHandle,
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
        _broker: broker,
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

fn capture_command(fx: &Fixture, name: Option<&str>, command: &[&str]) -> WireResponse {
    send(
        fx,
        Action::CaptureCredential {
            name: name.map(str::to_owned),
            command: Some(argv(command)),
            file: None,
            cwd: Some(fx.project.display().to_string()),
            folder: None,
            purpose: Some("Store the synthetic token.".to_owned()),
            path: Some("/usr/bin:/bin".to_owned()),
        },
    )
}

fn capture_file(fx: &Fixture, file: &Path) -> WireResponse {
    send(
        fx,
        Action::CaptureCredential {
            name: None,
            command: None,
            file: Some(file.display().to_string()),
            cwd: Some(fx.project.display().to_string()),
            folder: None,
            purpose: None,
            path: None,
        },
    )
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

/// The value is in no answer, activity entry, decision log entry, item history event,
/// use row, request, or correction.
fn assert_nowhere(fx: &Fixture, responses: &[&WireResponse], value: &str) {
    for response in responses {
        let text = serde_json::to_string(response).expect("json");
        assert!(!text.contains(value), "answer leaks the value: {text}");
        assert!(!format!("{response:?}").contains(value));
    }
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
            let details = format!("{:?}", vault.details(item.id).unwrap());
            assert!(!details.contains(value), "item details leak the value");
        }
        let requests = format!("{:?}", vault.credential_requests(false).unwrap());
        assert!(!requests.contains(value));
        let corrections = format!("{:?}", vault.corrections(false).unwrap());
        assert!(!corrections.contains(value));
    });
}

#[test]
fn capture_stores_the_output_of_a_command_and_never_returns_it() {
    let fx = fixture(Duration::from_secs(5));
    let canary = "FAKE-capture-canary-9931";
    let response = capture_command(&fx, Some("Synthetic CLI token"), &["/bin/echo", canary]);
    let answer = result(&response);
    let item = item_of(&response);
    assert_eq!(answer["created"], true);
    assert_eq!(answer["name"], "Synthetic CLI token");
    assert_eq!(answer["env_name"], "SYNTHETIC_CLI_TOKEN");
    assert_eq!(reveal(&fx, item), canary, "the trimmed output is the value");
    with_vault(&fx, |vault| {
        let origin = vault.item_origin(item).unwrap().expect("origin");
        assert_eq!(origin.origin.agent_id, fx.agent_id);
        assert_eq!(origin.origin.tool, OriginTool::Capture);
        assert_eq!(origin.origin.project_label, "project");
        let created = vault.item_events(item, MAX_ITEM_EVENTS).unwrap();
        assert!(
            created
                .iter()
                .any(|event| event.detail == "Added by Tool agent in project (capture)."),
            "{created:?}"
        );
    });
    // The same value again returns the item and creates nothing.
    let again = capture_command(&fx, None, &["/bin/echo", canary]);
    assert_eq!(item_of(&again), item);
    assert_eq!(result(&again)["created"], false);
    assert_nowhere(&fx, &[&response, &again], canary);
}

#[test]
fn capture_reads_a_regular_file() {
    let fx = fixture(Duration::from_secs(5));
    let canary = "FAKE-file-canary-1187";
    let file = fx.dir.path().join("key.txt");
    std::fs::write(&file, format!("  {canary}\n\n")).expect("file");
    let response = capture_file(&fx, &file);
    let item = item_of(&response);
    assert_eq!(reveal(&fx, item), canary);
    assert_nowhere(&fx, &[&response], canary);
}

#[test]
fn capture_refuses_apassy_paths_special_files_and_bad_output() {
    let fx = fixture(Duration::from_secs(5));
    let refused = |response: &WireResponse| {
        assert_eq!(code(response), "capture_refused", "{response:?}");
    };
    // The Apassy data folder: refused by its path, nothing is read or made there.
    refused(&capture_file(
        &fx,
        &apassy::paths::data_dir().join("t2-synthetic-probe"),
    ));
    // The open vault file and its sidecar.
    let vault_file = with_vault(&fx, |vault| vault.path().to_path_buf());
    refused(&capture_file(&fx, &vault_file));
    refused(&capture_file(
        &fx,
        Path::new(&format!("{}.lock", vault_file.display())),
    ));
    refused(&capture_command(
        &fx,
        None,
        &["cat", &vault_file.display().to_string()],
    ));
    // A FIFO is refused at once; the read never blocks.
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
    refused(&capture_file(&fx, fx.dir.path()));
    let big = fx.dir.path().join("big.txt");
    std::fs::write(&big, "a".repeat(64 * 1024 + 1)).expect("big");
    refused(&capture_file(&fx, &big));
    let empty = fx.dir.path().join("empty.txt");
    std::fs::write(&empty, "  \n").expect("empty");
    refused(&capture_file(&fx, &empty));
    // Output over 64 KiB, empty output, a failed command.
    refused(&capture_command(
        &fx,
        None,
        &["head", "-c", "70000", "/dev/zero"],
    ));
    refused(&capture_command(&fx, None, &["/usr/bin/true"]));
    refused(&capture_command(&fx, None, &["/usr/bin/false"]));
    // A shell, the Keychain tool, and a URL never run.
    refused(&capture_command(&fx, None, &["sh", "-c", "echo FAKE"]));
    refused(&capture_command(
        &fx,
        None,
        &["security", "find-generic-password", "-w"],
    ));
    refused(&capture_command(
        &fx,
        None,
        &["curl", "https://example.com/token"],
    ));
    // Nothing was made.
    with_vault(&fx, |vault| {
        assert!(vault.items_created_by(fx.agent_id, 0).unwrap().is_empty());
    });
}

#[test]
fn generate_uses_the_length_and_the_alphabet_and_never_returns_the_value() {
    let fx = fixture(Duration::from_secs(5));
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
    let fx = fixture(Duration::from_secs(5));
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
    let fx = fixture(Duration::from_secs(5));
    for index in 0..MAX_AGENT_ITEMS_PER_HOUR {
        item_of(&generate(&fx, &format!("Limit {index}"), None, None));
    }
    assert_eq!(
        code(&generate(&fx, "Limit over", None, None)),
        "too_many_items"
    );
    assert_eq!(
        code(&save_as(&fx, &fx.token, None, "FAKE-limit-canary-0001")),
        "too_many_items"
    );
    assert_eq!(
        code(&capture_command(
            &fx,
            None,
            &["/bin/echo", "FAKE-limit-canary-0002"]
        )),
        "too_many_items"
    );
    // Another agent has its own limit.
    item_of(&save_as(
        &fx,
        &fx.other_token,
        None,
        "FAKE-limit-canary-0003",
    ));
}

#[test]
fn update_and_describe_only_change_own_items() {
    let fx = fixture(Duration::from_secs(5));
    let own = item_of(&generate(&fx, "Own password", Some(32), None));
    let other = item_of(&save_as(
        &fx,
        &fx.other_token,
        None,
        "FAKE-other-canary-3310",
    ));
    let update = |token: &str, item_id: u64| {
        send_as(
            &fx,
            token,
            Action::UpdateCredential {
                item_id,
                command: None,
                file: None,
                generate: Some(GenerateSpec {
                    length: Some(40),
                    alphabet: None,
                }),
                cwd: None,
                path: None,
            },
        )
    };
    let describe = |item_id: u64, name: Option<&str>, env: Option<&str>, hosts: Option<&[&str]>| {
        send(
            &fx,
            Action::DescribeCredential {
                item_id,
                name: name.map(str::to_owned),
                notes: None,
                env_name: env.map(str::to_owned),
                hosts: hosts.map(argv),
            },
        )
    };
    for item in [fx.owner_item, other, 99_999] {
        assert_eq!(code(&update(&fx.token, item)), "not_owner", "{item}");
        assert_eq!(code(&describe(item, Some("Mine"), None, None)), "not_owner");
    }
    assert_eq!(reveal(&fx, fx.owner_item), OWNER_SECRET, "unchanged");
    let before = reveal(&fx, own);
    let updated = update(&fx.token, own);
    assert_eq!(result(&updated)["updated"], true);
    let after = reveal(&fx, own);
    assert_eq!(after.len(), 40);
    assert_ne!(before, after);
    assert_nowhere(&fx, &[&updated], &after);
    // Describe: name, variable, hosts.
    let described = describe(
        own,
        Some("Staging password"),
        Some("STAGING_DB_PASSWORD"),
        None,
    );
    assert_eq!(result(&described)["name"], "Staging password");
    assert_eq!(result(&described)["env_name"], "STAGING_DB_PASSWORD");
    assert_eq!(
        code(&describe(own, None, Some("OWNER_KEY"), None)),
        "env_name_taken"
    );
    assert_eq!(
        code(&describe(own, None, Some("PATH"), None)),
        "invalid_request"
    );
    // Hosts only narrow: a placeholder instead of the real value, then a subset.
    let hosts = ["api.example.com", "files.example.com"];
    assert!(describe(own, None, None, Some(&hosts)).ok);
    with_vault(&fx, |vault| {
        assert!(matches!(
            vault.process_binding(own).unwrap().unwrap().delivery,
            EnvDelivery::Placeholder(_)
        ));
    });
    assert!(describe(own, None, None, Some(&["api.example.com"])).ok);
    assert_eq!(
        code(&describe(own, None, None, Some(&hosts))),
        "invalid_request",
        "widening is refused"
    );
}

#[test]
fn ask_owner_waits_reattaches_and_gets_the_item_or_a_dismissal() {
    let fx = fixture(Duration::from_secs(3));
    let socket = fx.socket.clone();
    let token = fx.token.clone();
    let project = fx.project.display().to_string();
    let ask = move |name: &str| {
        let action = Action::AskOwnerForCredential {
            name: name.to_owned(),
            purpose: "Upload the synthetic source maps.".to_owned(),
            where_to_get: Some("Settings > Auth tokens".to_owned()),
            cwd: Some(project.clone()),
            folder: None,
        };
        client::send_with(
            &socket,
            &token,
            action,
            SendOptions {
                host_session: None,
                timeout: Some(Duration::from_secs(30)),
            },
        )
        .expect("broker answer")
    };
    let open = |fx: &Fixture| {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let open = with_vault(fx, |vault| vault.credential_requests(true).unwrap());
            if !open.is_empty() {
                return open;
            }
            assert!(Instant::now() < end, "no request");
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    // 1. Timeout: `waiting`; the request stays open.
    let timed_out = ask("Synthetic Sentry token");
    assert_eq!(code(&timed_out), "waiting");
    let requests = open(&fx);
    assert_eq!(requests.len(), 1);
    let request = requests[0].clone();
    assert_eq!(request.project_label, "project");
    // 2. The same request again re-attaches; another request meanwhile is
    //    question_waiting; the owner saves and the waiting call gets the item.
    let waiter = {
        let ask = ask.clone();
        std::thread::spawn(move || ask("Synthetic Sentry token"))
    };
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
        let summary = vault
            .add_detected(&found[0], None, Some(&request.origin()))
            .unwrap();
        vault
            .settle_credential_request(
                request.id,
                RequestOutcome::Saved {
                    item_id: summary.id,
                },
            )
            .unwrap();
        summary.id
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
    assert_eq!(item_of(&ask("Synthetic Sentry token")), item);
    // 3. A waiting request blocks another one; a dismissal answers the waiting call
    //    and the same request again.
    let waiter = {
        let ask = ask.clone();
        std::thread::spawn(move || ask("Synthetic npm token"))
    };
    let second = loop {
        let open = open(&fx);
        if let Some(found) = open.into_iter().find(|r| r.name == "Synthetic npm token") {
            break found;
        }
    };
    assert_eq!(code(&ask("Synthetic PyPI token")), "question_waiting");
    with_vault(&fx, |vault| {
        vault
            .settle_credential_request(second.id, RequestOutcome::Dismissed)
            .unwrap();
    });
    assert_eq!(code(&waiter.join().expect("waiter")), "dismissed");
    assert_eq!(code(&ask("Synthetic npm token")), "dismissed");
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

/// ADR 0025 §3f: an agent with "only these items" can use the item that it added, and
/// nothing else changes for it.
#[test]
fn a_restricted_agent_gets_its_own_new_item_on_its_list() {
    let fx = fixture(Duration::from_secs(5));
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
