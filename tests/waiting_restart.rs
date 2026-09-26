#![cfg(all(feature = "desktop", feature = "vault"))]

//! Goal item N3: a run that waits for the owner when the process ends without a quit
//! (a crash or `kill -9`). The broker stores a wait record in the vault (schema 7).
//! The next unlock turns it into an activity entry, so the inbox shows the event after
//! the restart. All data is synthetic.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::desktop::inbox::{self, InboxKind};
use apassy::desktop::owner_store::{ENDED_BY_QUIT, OwnerSession};
use apassy::vault::{ENDED_BY_RESTART, ExecMode, Field, ItemDraft, SecretValue};
use tempfile::TempDir;

const PASS: &str = "restart-pass-ok";
const AGENT: &str = "Restart agent";

struct Setup {
    dir: TempDir,
    path: PathBuf,
    session: OwnerSession,
    project: PathBuf,
    item_id: u64,
    token: String,
}

/// An unlocked vault with one process grant in "ask" mode.
fn setup() -> Setup {
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project dir");
    let project = std::fs::canonicalize(project).expect("canonical project");
    let path = dir.path().join("vault.db");
    let mut session = OwnerSession::new();
    session.create_file(&path, PASS).expect("create");
    session.unlock(PASS).expect("unlock");
    let path = session.vault_path().expect("path");
    let (item_id, token) = {
        let shared = session.shared_vault();
        let mut guard = shared.lock().expect("vault");
        let vault = guard.as_mut().expect("open");
        let item = vault
            .add(ItemDraft {
                title: "Restart key".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("FAKE-restart-secret-2718".to_owned()),
                    secret: true,
                }],
            })
            .expect("add");
        vault
            .set_env_binding(item.id, "RESTART_KEY", "token")
            .expect("binding");
        let (agent, token) = vault.register_agent(AGENT).expect("register");
        vault
            .set_exec_grant(
                agent.id,
                item.id,
                &project.display().to_string(),
                ExecMode::Ask,
            )
            .expect("grant");
        (item.id, token.expose().to_owned())
    };
    Setup {
        dir,
        path,
        session,
        project,
        item_id,
        token,
    }
}

fn start(setup: &Setup, vault: &SharedVault, name: &str) -> (broker::BrokerHandle, PathBuf) {
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_secs(30);
    let socket = setup.dir.path().join(name).join("broker.sock");
    let handle = broker::start_with(Arc::clone(vault), &socket, options).expect("broker");
    (handle, socket)
}

fn send_run(setup: &Setup, socket: PathBuf) -> std::thread::JoinHandle<WireResponse> {
    let token = setup.token.clone();
    let item_id = setup.item_id;
    let cwd = setup.project.display().to_string();
    std::thread::spawn(move || {
        client::send(
            &socket,
            &token,
            Action::Run {
                items: vec![item_id],
                command: vec!["/bin/echo".to_owned(), "restart".to_owned()],
                cwd,
                purpose: "Print a restart check.".to_owned(),
                path: None,
                user_request: Some("Check the restart path.".to_owned()),
            },
        )
        .expect("answer")
    })
}

fn wait_until_pending(handle: &broker::BrokerHandle) {
    let started = Instant::now();
    while handle.approvals().pending().is_empty() {
        assert!(started.elapsed() < Duration::from_secs(10), "no run waits");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn waiting_count(vault: &SharedVault) -> usize {
    vault
        .lock()
        .expect("vault")
        .as_ref()
        .expect("open")
        .waiting_count()
        .expect("count")
}

fn ended_events(session: &OwnerSession) -> Vec<inbox::InboxEvent> {
    inbox::collect(session, &[])
        .expect("inbox")
        .into_iter()
        .filter(|event| event.kind == InboxKind::ApprovalEnded { approved: false })
        .collect()
}

#[test]
fn a_run_that_waits_during_a_crash_is_in_the_inbox_after_a_restart() {
    let setup = setup();
    let vault = setup.session.shared_vault();
    let (broker, socket) = start(&setup, &vault, "run");
    let waiting = send_run(&setup, socket);
    wait_until_pending(&broker);
    assert_eq!(waiting_count(&vault), 1, "the wait has a durable record");

    // The crash: the app state goes with no lock, no quit, and no final entry. The file
    // keeps what it keeps after `kill -9`. The broker thread cannot reach the vault.
    let path = setup.path.clone();
    drop(vault.lock().expect("vault").take());
    let response = waiting.join().expect("waiter");
    assert!(!response.ok);
    drop(broker);

    // Restart: a new session opens the file. The unlock ends the recorded wait.
    let mut session = OwnerSession::new();
    session.open_file(&path).expect("open");
    session.unlock(PASS).expect("unlock");
    let ended = ended_events(&session);
    assert_eq!(ended.len(), 1, "one entry for the waiting run: {ended:?}");
    assert!(
        ended[0].detail.starts_with(ENDED_BY_RESTART),
        "{}",
        ended[0].detail
    );
    assert!(ended[0].detail.contains("Purpose: Print a restart check."));
    assert_eq!(ended[0].agent, AGENT);
    assert_eq!(ended[0].summary, "run /bin/echo restart");
    assert_eq!(waiting_count(&session.shared_vault()), 0);

    // A second restart adds no second entry.
    session.lock().expect("lock");
    session.unlock(PASS).expect("unlock");
    assert_eq!(ended_events(&session).len(), 1);
}

/// A quit records the waiting run once. The wait record goes with it, so the next
/// unlock adds no "ended by restart" entry.
#[test]
fn a_quit_records_a_waiting_run_once() {
    let mut setup = setup();
    let vault = setup.session.shared_vault();
    let (broker, socket) = start(&setup, &vault, "quit");
    let waiting = send_run(&setup, socket);
    wait_until_pending(&broker);
    let approvals = Arc::clone(broker.approvals());
    setup
        .session
        .lock_ending_runs(Some(&approvals), ENDED_BY_QUIT)
        .expect("quit");
    assert!(!waiting.join().expect("waiter").ok);
    drop(broker);

    setup.session.unlock(PASS).expect("unlock");
    let ended = ended_events(&setup.session);
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert!(
        ended[0].detail.starts_with(ENDED_BY_QUIT),
        "{}",
        ended[0].detail
    );
    assert_eq!(waiting_count(&vault), 0);
}
