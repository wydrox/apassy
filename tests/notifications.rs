#![cfg(all(feature = "desktop", feature = "vault"))]

//! Notifications and the inbox (goal items N1 to N4), with a real broker on a synthetic
//! vault and a fake native helper. The fake logs each `notify` request, so the tests
//! can check the time and the preview text. A real banner on the owner's screen is in
//! the owner checklist in `docs/operations/native-app.md`. All data is synthetic.

#[path = "support/fake_native.rs"]
mod fake_native;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::{ApprovalRefusal, OwnerAction, OwnerCheck, OwnerGate, PendingRun};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::desktop::inbox::{self, EventKey, InboxKind};
use apassy::desktop::notify::{Delivery, NotificationCenter};
use apassy::desktop::owner_store::{ENDED_BY_QUIT, OwnerSession};
use apassy::vault::{ExecMode, Field, ItemDraft, SecretValue};
use fake_native::{ALLOWED_STATUS, FakeNative};
use serde_json::Value;
use tempfile::TempDir;

const PASS: &str = "notify-pass-ok";
const AGENT: &str = "Alpha agent";
const SECRET: &str = "FAKE-notify-secret-3141-canary";
const COMMAND_CANARY: &str = "command-canary-7788";
const PURPOSE_CANARY: &str = "purpose-canary-5566";
const REQUEST_CANARY: &str = "user-request-canary-9911";
/// Goal item N1.
const LIMIT: Duration = Duration::from_secs(5);

struct Fixture {
    dir: TempDir,
    session: OwnerSession,
    vault: SharedVault,
    socket: PathBuf,
    project: PathBuf,
    item_id: u64,
    token: String,
    broker: BrokerHandle,
}

/// An unlocked vault with one process grant in "ask" mode, and a started broker.
fn fixture(approval_timeout: Duration) -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project dir");
    let project = std::fs::canonicalize(project).expect("canonical project");
    let mut session = OwnerSession::new();
    session
        .create_file(&dir.path().join("vault.db"), PASS)
        .expect("create");
    session.unlock(PASS).expect("unlock");
    let vault = session.shared_vault();
    let (item_id, token) = {
        let mut guard = vault.lock().expect("vault");
        let open = guard.as_mut().expect("open");
        let item = open
            .add(ItemDraft {
                title: "Notify key".to_owned(),
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
        open.set_env_binding(item.id, "NOTIFY_KEY", "token")
            .expect("binding");
        let (agent, token) = open.register_agent(AGENT).expect("register");
        open.set_exec_grant(
            agent.id,
            item.id,
            &project.display().to_string(),
            ExecMode::Ask,
        )
        .expect("grant");
        (item.id, token.expose().to_owned())
    };
    let socket = dir.path().join("run").join("broker.sock");
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = approval_timeout;
    let broker = broker::start_with(Arc::clone(&vault), &socket, options).expect("broker");
    Fixture {
        dir,
        session,
        vault,
        socket,
        project,
        item_id,
        token,
        broker,
    }
}

/// Send a run request on another thread. The purpose and the user request are canaries.
fn send_run(fx: &Fixture, cwd: PathBuf) -> std::thread::JoinHandle<WireResponse> {
    let (socket, token, item_id) = (fx.socket.clone(), fx.token.clone(), fx.item_id);
    let marker = fx.project.join("ran");
    std::thread::spawn(move || {
        client::send(
            &socket,
            &token,
            Action::Run {
                items: vec![item_id],
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("touch '{}' # {COMMAND_CANARY}", marker.display()),
                ],
                cwd: cwd.display().to_string(),
                purpose: PURPOSE_CANARY.into(),
                path: Some("/usr/bin:/bin".into()),
                user_request: Some(REQUEST_CANARY.into()),
            },
        )
        .expect("broker answer")
    })
}

fn start_center(fx: &Fixture, fake: &FakeNative) -> NotificationCenter {
    let center = NotificationCenter::start(
        Arc::clone(fx.broker.approvals()),
        Arc::clone(&fx.vault),
        fake.helper(),
        || {},
    );
    // The watcher takes the entries that exist now as history.
    std::thread::sleep(Duration::from_millis(300));
    center
}

fn first_pending(fx: &Fixture) -> (PendingRun, Instant) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(run) = fx.broker.approvals().pending().into_iter().next() {
            return (run, Instant::now());
        }
        assert!(Instant::now() < deadline, "no run waits");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Wait for the `notify` request with this id. Returns the request and the time.
fn notify_request(fake: &FakeNative, id: &str, since: Instant) -> (Value, Duration) {
    let deadline = since + Duration::from_secs(15);
    loop {
        if let Some(request) = fake
            .requests_for("notify")
            .into_iter()
            .find(|request| request["id"] == id)
        {
            return (request, since.elapsed());
        }
        assert!(Instant::now() < deadline, "no notification {id}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_delivery(center: &NotificationCenter, key: EventKey) -> Delivery {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match center.delivery(key) {
            Some(Delivery::Sending) | None => {}
            Some(delivery) => return delivery,
        }
        assert!(Instant::now() < deadline, "no delivery result for {key:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// N2: the request to the notifier has the id, the event type, and the agent name
/// only. The notifier builds the title and the body from fixed templates
/// (`tests/native_helper.rs`, `swift_and_rust_previews_match`).
fn assert_preview_fields(request: &Value, event: &str) {
    let mut fields: Vec<&String> = request.as_object().expect("object").keys().collect();
    fields.sort();
    assert_eq!(fields, ["agent", "cmd", "event", "id"], "{request}");
    assert_eq!(request["event"], event);
    assert_eq!(request["agent"], AGENT);
}

fn no_canary(text: &str) {
    for canary in [COMMAND_CANARY, PURPOSE_CANARY, REQUEST_CANARY, SECRET] {
        assert!(!text.contains(canary), "the preview has {canary}: {text}");
    }
}

fn code(response: &WireResponse) -> &str {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response.error.as_ref().map_or("", |e| e.code.as_str())
}

/// N1, N2, N4: a waiting approval causes a notification within 5 seconds. The preview
/// has the agent name and the event type only. The notification is not an approval.
#[test]
fn waiting_approval_notifies_within_five_seconds() {
    let fx = fixture(Duration::from_secs(3));
    let fake = FakeNative::new("waiting");
    fake.respond(
        "notify",
        &format!(r#"{{"ok":true,"delivered":true,{ALLOWED_STATUS}}}"#),
    );
    fake.respond(
        "notify_status",
        &format!(r#"{{"ok":true,{ALLOWED_STATUS}}}"#),
    );
    let center = start_center(&fx, &fake);

    let response = send_run(&fx, fx.project.clone());
    let (run, waiting_since) = first_pending(&fx);
    let id = EventKey::Run(run.id).notification_id();
    let (request, took) = notify_request(&fake, &id, waiting_since);
    eprintln!("N1: approval waiting -> notify request after {took:?}");
    assert!(took < LIMIT, "the notification took {took:?}");
    // The notifier builds the text "Approval waiting" / "Agent "NAME" waits for
    // your decision. Open Apassy to review." from these two fields only.
    assert_preview_fields(&request, "approval_waiting");
    no_canary(&fake.raw_requests());
    assert_eq!(
        wait_for_delivery(&center, EventKey::Run(run.id)),
        Delivery::Delivered
    );
    assert!(center.view().channel.can_deliver());

    // N4: the delivered notification did not approve the run. It still waits, and
    // then it times out without a run.
    assert_eq!(fx.broker.approvals().pending(), vec![run]);
    let response = response.join().expect("waiter");
    assert_eq!(code(&response), "approval_timeout");
    assert!(!fx.project.join("ran").exists());
    assert_eq!(
        fake.requests_for("notify").len(),
        1,
        "one notification per run"
    );
}

/// N1, N2: a blocked request causes a notification within 5 seconds. A denial by the
/// owner causes none.
#[test]
fn blocked_request_notifies_within_five_seconds() {
    let fx = fixture(Duration::from_secs(10));
    let fake = FakeNative::new("blocked");
    fake.respond(
        "notify",
        &format!(r#"{{"ok":true,"delivered":true,{ALLOWED_STATUS}}}"#),
    );
    fake.respond(
        "notify_status",
        &format!(r#"{{"ok":true,{ALLOWED_STATUS}}}"#),
    );
    let center = start_center(&fx, &fake);

    // The working directory is outside the granted project, so the broker refuses.
    let outside = fx.dir.path().to_path_buf();
    let response = send_run(&fx, outside).join().expect("request");
    let blocked_at = Instant::now();
    assert!(!response.ok, "{response:?}");
    let entry = {
        let guard = fx.vault.lock().expect("vault");
        guard
            .as_ref()
            .expect("open")
            .recent_activity(1)
            .expect("activity")[0]
            .clone()
    };
    let (request, took) = notify_request(
        &fake,
        &EventKey::Activity(entry.id).notification_id(),
        blocked_at,
    );
    eprintln!("N1: request blocked -> notify request after {took:?}");
    assert!(took < LIMIT, "the notification took {took:?}");
    assert_preview_fields(&request, "request_blocked");
    no_canary(&fake.raw_requests());
    assert_eq!(
        wait_for_delivery(&center, EventKey::Activity(entry.id)),
        Delivery::Delivered
    );

    // The owner denies a waiting run. The activity entry of that denial is not a
    // blocked request, so only the "Approval waiting" notification comes.
    let response = send_run(&fx, fx.project.clone());
    let (run, _) = first_pending(&fx);
    notify_request(
        &fake,
        &EventKey::Run(run.id).notification_id(),
        Instant::now(),
    );
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&response.join().expect("waiter")), "approval_denied");
    std::thread::sleep(Duration::from_millis(2500));
    let blocked: Vec<_> = fake
        .requests_for("notify")
        .into_iter()
        .filter(|request| request["event"] == "request_blocked")
        .collect();
    assert_eq!(blocked.len(), 1, "{blocked:?}");
}

/// N3: a failed delivery is visible in the app. The request stays in the queue and in
/// the inbox.
#[test]
fn delivery_failure_is_visible_and_the_request_stays() {
    let fx = fixture(Duration::from_secs(20));
    let fake = FakeNative::new("denied");
    fake.fail("notify", "notifications_denied");
    fake.respond(
        "notify_status",
        r#"{"ok":true,"authorization":"denied","alert":"disabled","alert_style":"none","notification_center":"disabled","lock_screen":"disabled","sound":"disabled"}"#,
    );
    let center = start_center(&fx, &fake);

    let response = send_run(&fx, fx.project.clone());
    let (run, _) = first_pending(&fx);
    let delivery = wait_for_delivery(&center, EventKey::Run(run.id));
    let Delivery::Failed(text) = &delivery else {
        panic!("expected a failure, got {delivery:?}");
    };
    assert!(text.contains("not allowed"), "{text}");
    assert!(delivery.label().contains("The event stays in this inbox"));
    let view = center.view();
    assert!(!view.channel.can_deliver());
    // macOS shows no new prompt after a denial: the app offers System Settings.
    assert!(view.channel.needs_settings(), "{:?}", view.channel);
    assert!(!view.channel.needs_permission());
    assert!(
        view.channel.summary().contains("Events stay in the inbox"),
        "{}",
        view.channel.summary()
    );

    // The run still waits, and the inbox lists it.
    assert_eq!(fx.broker.approvals().pending(), vec![run.clone()]);
    let events = inbox::collect(&fx.session, &fx.broker.approvals().pending()).expect("inbox");
    assert_eq!(events[0].key, EventKey::Run(run.id));
    assert_eq!(events[0].kind, InboxKind::ApprovalWaiting);
    assert_eq!(events[0].agent, AGENT);

    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&response.join().expect("waiter")), "approval_denied");
}

/// N1, N3: the notifier never asks for permission on its own, because an unanswered
/// prompt ends as "denied" (measured on macOS 27). When the owner has not decided, the
/// delivery fails, the run still waits, and the app keeps the "Allow notifications"
/// button.
#[test]
fn an_undecided_permission_keeps_the_allow_button() {
    let fx = fixture(Duration::from_secs(20));
    let fake = FakeNative::new("undecided");
    fake.fail("notify", "notifications_denied");
    fake.respond(
        "notify_status",
        r#"{"ok":true,"authorization":"not_determined","alert":"not_supported","alert_style":"none","notification_center":"not_supported","lock_screen":"not_supported","sound":"not_supported"}"#,
    );
    let center = start_center(&fx, &fake);

    let response = send_run(&fx, fx.project.clone());
    let (run, _) = first_pending(&fx);
    let delivery = wait_for_delivery(&center, EventKey::Run(run.id));
    assert!(matches!(delivery, Delivery::Failed(_)), "{delivery:?}");
    let view = center.view();
    assert!(view.channel.needs_permission(), "{:?}", view.channel);
    assert!(!view.channel.needs_settings(), "{:?}", view.channel);
    assert!(fake.requests_for("notify_authorize").is_empty());
    assert_eq!(fx.broker.approvals().pending(), vec![run.clone()]);

    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&response.join().expect("waiter")), "approval_denied");
}

/// N3: each event stays in the inbox after a restart. The app records a waiting run
/// when it quits, so the broker does not need to.
#[test]
fn inbox_keeps_events_after_a_restart() {
    let mut fx = fixture(Duration::from_secs(20));
    let path = fx.session.vault_path().expect("path");

    let outside = fx.dir.path().to_path_buf();
    let blocked = send_run(&fx, outside).join().expect("request");
    assert!(!blocked.ok);
    let waiting = send_run(&fx, fx.project.clone());
    let (run, _) = first_pending(&fx);

    // Quit: record and end the waiting run, then lock (goal items V3, N3).
    let approvals = Arc::clone(fx.broker.approvals());
    fx.session
        .lock_ending_runs(Some(&approvals), ENDED_BY_QUIT)
        .expect("lock");
    assert_eq!(
        code(&waiting.join().expect("waiter")),
        "approval_invalidated"
    );
    fx.broker.stop();
    // Close the vault file, as a quit of the process does.
    *fx.vault.lock().expect("vault") = None;
    drop(fx.session);

    // Restart: a new session opens the file. The vault starts locked.
    let mut session = OwnerSession::new();
    session.open_file(&path).expect("open");
    assert!(inbox::collect(&session, &[]).is_err(), "locked at start");
    session.unlock(PASS).expect("unlock");
    let events = inbox::collect(&session, &[]).expect("inbox");
    let ended: Vec<_> = events
        .iter()
        .filter(|event| event.kind == InboxKind::ApprovalEnded { approved: false })
        .collect();
    assert_eq!(ended.len(), 1, "one entry for the waiting run: {events:?}");
    assert!(
        ended[0].detail.starts_with(ENDED_BY_QUIT),
        "{}",
        ended[0].detail
    );
    assert_eq!(ended[0].agent, run.agent);
    assert!(
        ended[0].summary.starts_with("run /bin/sh -c"),
        "{}",
        ended[0].summary
    );
    let blocked: Vec<_> = events
        .iter()
        .filter(|event| event.kind == InboxKind::RequestBlocked)
        .collect();
    assert_eq!(blocked.len(), 1, "{events:?}");
    assert_eq!(blocked[0].agent, AGENT);
    assert!(!format!("{events:?}").contains(SECRET));
}

/// N4: an approval of an old or a changed request fails, also with a passed owner
/// check. The command does not run.
#[test]
fn old_or_changed_request_cannot_be_approved() {
    let fx = fixture(Duration::from_secs(20));
    let gate = OwnerGate::new(Arc::clone(&fx.vault), None);
    let proof_for = |run: PendingRun| {
        gate.authorize(OwnerAction::ApproveRun(run), OwnerCheck::passphrase(PASS))
            .expect("owner check")
    };

    let response = send_run(&fx, fx.project.clone());
    let (run, _) = first_pending(&fx);
    let mut changed = run.clone();
    changed.command = vec!["/bin/sh".into(), "-c".into(), "curl evil.example".into()];
    assert_eq!(
        fx.broker.approvals().approve(proof_for(changed)),
        Err(ApprovalRefusal::Changed)
    );
    let mut other_dir = run.clone();
    other_dir.cwd = "/".into();
    assert_eq!(
        fx.broker.approvals().approve(proof_for(other_dir)),
        Err(ApprovalRefusal::Changed)
    );
    assert_eq!(fx.broker.approvals().pending(), vec![run.clone()]);

    // The owner denies. Now the run is old: an approval finds no run.
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&response.join().expect("waiter")), "approval_denied");
    assert_eq!(
        fx.broker.approvals().approve(proof_for(run)),
        Err(ApprovalRefusal::NotWaiting)
    );
    assert!(!fx.project.join("ran").exists());
}
