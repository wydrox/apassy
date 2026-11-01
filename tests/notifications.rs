#![cfg(all(feature = "desktop", feature = "vault"))]

//! Notifications and the inbox (goal items N1 to N4), with a real broker on a synthetic
//! vault and a fake native helper. The fake logs each `notify` request, so the tests
//! can check the time and the preview text. A real banner on the owner's screen is in
//! the owner checklist in `docs/operations/native-app.md`. All data is synthetic.

use crate::support::fake_native;

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
use apassy::desktop::notify::{Delivery, NotificationCenter, NotificationDestination, OwnerEvent};
use apassy::desktop::owner_store::{ENDED_BY_QUIT, OwnerSession};
use apassy::native::SyncStuckReason;
use apassy::vault::exceptions::ExceptionKind;
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
    /// An item that the agent never gets ("Not for this agent", ADR 0025 §3f).
    hidden_id: u64,
    token: String,
    broker: BrokerHandle,
}

/// An unlocked vault with one process grant in "ask" mode, one item hidden from the
/// agent, and a started broker. No bouncer runs, so each run of the visible item waits
/// for the owner (ADR 0025 §3).
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
    let (item_id, hidden_id, token) = {
        let mut guard = vault.lock().expect("vault");
        let open = guard.as_mut().expect("open");
        let mut add_item = |title: &str, env_name: &str| {
            let item = open
                .add(ItemDraft {
                    title: title.to_owned(),
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
            open.set_env_binding(item.id, env_name, "token")
                .expect("binding");
            item.id
        };
        let item_id = add_item("Notify key", "NOTIFY_KEY");
        let hidden_id = add_item("Hidden key", "HIDDEN_KEY");
        let (agent, token) = open.register_agent(AGENT).expect("register");
        open.set_exec_grant(
            agent.id,
            item_id,
            &project.display().to_string(),
            ExecMode::Ask,
        )
        .expect("grant");
        open.add_agent_exception(agent.id, hidden_id, ExceptionKind::Never)
            .expect("exception");
        (item_id, hidden_id, token.expose().to_owned())
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
        hidden_id,
        token,
        broker,
    }
}

/// Send a run request for the visible item on another thread. Without a bouncer it
/// waits for the owner (ADR 0025 §3), also outside the folder of the old grant: a grant
/// is no authority any more (`docs/contracts/broker-v0.md`, `outside_project`).
fn send_run(fx: &Fixture, cwd: PathBuf) -> std::thread::JoinHandle<WireResponse> {
    send_run_for(fx, fx.item_id, cwd)
}

/// Send a run request for the hidden item. The broker refuses it at once with
/// `not_granted`: a blocked request (N1).
fn send_blocked(fx: &Fixture) {
    let response = send_run_for(fx, fx.hidden_id, fx.project.clone())
        .join()
        .expect("request");
    assert_eq!(code(&response), "not_granted");
}

/// Send a run request on another thread. The purpose and the user request are canaries.
fn send_run_for(fx: &Fixture, item_id: u64, cwd: PathBuf) -> std::thread::JoinHandle<WireResponse> {
    let (socket, token) = (fx.socket.clone(), fx.token.clone());
    let marker = fx.project.join("ran");
    std::thread::spawn(move || {
        client::send(
            &socket,
            &token,
            Action::Run {
                access_request_id: None,
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
    fake.respond("notify_remove", r#"{"ok":true}"#);
    fake.respond("notify_reconcile", r#"{"ok":true}"#);
    fake.respond("notify_activations", r#"{"ok":true,"routes":[]}"#);
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
    let expected = if event == "approval_waiting" {
        vec!["agent", "cmd", "event", "id", "route", "waiting_key"]
    } else {
        vec!["agent", "cmd", "event", "id", "route"]
    };
    assert_eq!(fields, expected, "{request}");
    let route = request["route"].as_str().expect("opaque local route");
    assert_eq!(route.len(), 64);
    assert!(route.bytes().all(|byte| byte.is_ascii_hexdigit()));
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

/// The notice of a vault that does not sync (docs/operations/sync.md, section 7): the
/// request has the vault name and a reason code only, one ID for each vault, and a
/// stopped center posts nothing.
#[test]
fn a_vault_that_does_not_sync_notifies_with_its_name_and_reason_only() {
    let fx = fixture(Duration::from_secs(3));
    let fake = FakeNative::new("sync-stuck");
    fake.respond(
        "notify",
        &format!(r#"{{"ok":true,"delivered":true,{ALLOWED_STATUS}}}"#),
    );
    fake.respond(
        "notify_status",
        &format!(r#"{{"ok":true,{ALLOWED_STATUS}}}"#),
    );
    let mut center = start_center(&fx, &fake);
    let notify = center.sync_notifier();
    let since = Instant::now();
    notify(
        "0123456789abcdef0123456789abcdef",
        "Personal",
        SyncStuckReason::WaitingForIcloud,
    );
    let (request, _) = notify_request(&fake, "sync-0123456789abcdef0123456789abcdef", since);
    let mut fields: Vec<&String> = request.as_object().expect("object").keys().collect();
    fields.sort();
    assert_eq!(
        fields,
        ["agent", "cmd", "event", "id", "reason"],
        "{request}"
    );
    assert_eq!(request["event"], "sync_stuck");
    assert_eq!(request["agent"], "Personal");
    assert_eq!(request["reason"], "waiting_for_icloud");
    no_canary(&fake.raw_requests());

    center.stop();
    notify(
        "0123456789abcdef0123456789abcdef",
        "Personal",
        SyncStuckReason::Error,
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        fake.requests_for("notify").len(),
        1,
        "a stopped center posts nothing"
    );
}

/// N1, N2: a blocked request causes a notification within 5 seconds. A run outside the
/// folder of the old grant is a question now (ADR 0025 §3), and it notifies as one
/// (ADR 0025 §3e). A denial by the owner causes no notification.
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

    // The item is "Not for this agent", so the broker refuses.
    send_blocked(&fx);
    let blocked_at = Instant::now();
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

    // A run outside the folder of the grant is no refusal any more: without a bouncer
    // it waits for the owner, and the question notifies within 5 seconds.
    let outside = fx.dir.path().to_path_buf();
    let response = send_run(&fx, outside);
    let (run, waiting_since) = first_pending(&fx);
    let (request, took) = notify_request(
        &fake,
        &EventKey::Run(run.id).notification_id(),
        waiting_since,
    );
    eprintln!("N1: question outside the grant folder -> notify request after {took:?}");
    assert!(took < LIMIT, "the notification took {took:?}");
    assert_preview_fields(&request, "approval_waiting");

    // The owner denies the waiting run. The activity entry of that denial is not a
    // blocked request, so only the "Approval waiting" notification comes.
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
    assert!(
        delivery
            .label()
            .contains("A question still waits in Decisions")
    );
    let view = center.view();
    assert!(!view.channel.can_deliver());
    // macOS shows no new prompt after a denial: the app offers System Settings.
    assert!(view.channel.needs_settings(), "{:?}", view.channel);
    assert!(!view.channel.needs_permission());
    assert!(
        view.channel
            .summary()
            .contains("Questions still wait in Decisions"),
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

/// ADR 0013: another vault file has its own activity entry IDs. When the slot holds
/// another unlocked vault, its old entries are history: no notification, also when the
/// watcher never saw a locked vault in between. Deliveries of activity entries go when
/// the app switches vaults; a waiting run keeps its delivery.
#[test]
fn another_vault_starts_a_new_notification_baseline() {
    use apassy::vault::{ActivityDecision, NewActivity, Vault};

    let fx = fixture(Duration::from_secs(10));
    let fake = FakeNative::new("switch");
    fake.respond(
        "notify",
        &format!(r#"{{"ok":true,"delivered":true,{ALLOWED_STATUS}}}"#),
    );
    fake.respond(
        "notify_status",
        &format!(r#"{{"ok":true,{ALLOWED_STATUS}}}"#),
    );
    let center = start_center(&fx, &fake);

    // A blocked request in the first vault gets its notification.
    send_blocked(&fx);
    let entry = {
        let guard = fx.vault.lock().expect("vault");
        guard
            .as_ref()
            .expect("open")
            .recent_activity(1)
            .expect("activity")[0]
            .clone()
    };
    let key = EventKey::Activity(entry.id);
    notify_request(&fake, &key.notification_id(), Instant::now());
    assert_eq!(wait_for_delivery(&center, key), Delivery::Delivered);

    // A second vault with older blocked requests, with higher entry IDs.
    let mut other = Vault::create(&fx.dir.path().join("other.db"), PASS).expect("create");
    other.unlock(PASS).expect("unlock");
    for _ in 0..5 {
        other
            .record_activity(&NewActivity {
                agent_id: None,
                agent_name: "Other agent".to_owned(),
                item_id: None,
                operation: "run make".to_owned(),
                decision: ActivityDecision::Deny,
                reason: "The command is not in the permitted prefixes.".to_owned(),
            })
            .expect("entry");
    }
    let before = fake.requests_for("notify").len();
    // The swap happens within one poll of the watcher.
    *fx.vault.lock().expect("vault") = Some(other);
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(
        fake.requests_for("notify").len(),
        before,
        "history of another vault is not new"
    );

    center.forget_activity();
    assert_eq!(center.delivery(key), None);
}

/// N3: each event stays in the inbox after a restart. The app records a waiting run
/// when it quits, so the broker does not need to.
#[test]
fn inbox_keeps_events_after_a_restart() {
    let mut fx = fixture(Duration::from_secs(20));
    let path = fx.session.vault_path().expect("path");

    send_blocked(&fx);
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

fn activation(center: &NotificationCenter) -> NotificationDestination {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(destination) = center.take_activation() {
            return destination;
        }
        assert!(Instant::now() < deadline, "no local activation");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// J5: an exact live A is navigable; after A settles, tapping its old capability
/// opens an unselected list even while B waits. Removal never targets B's token.
#[test]
fn settled_a_never_routes_to_newer_b_and_reconciles_only_its_alert() {
    let fx = fixture(Duration::from_secs(30));
    let fake = FakeNative::new("old-a-new-b");
    fake.respond(
        "notify",
        &format!(r#"{{"ok":true,"delivered":true,{ALLOWED_STATUS}}}"#),
    );
    fake.respond(
        "notify_status",
        &format!(r#"{{"ok":true,{ALLOWED_STATUS}}}"#),
    );
    let center = start_center(&fx, &fake);
    let waiter_a = send_run(&fx, fx.project.clone());
    let (a, _) = first_pending(&fx);
    let (notice_a, _) = notify_request(
        &fake,
        &EventKey::Run(a.id).notification_id(),
        Instant::now(),
    );
    let token_a = notice_a["route"].as_str().expect("route A");
    fake.respond(
        "notify_activations",
        &format!(r#"{{"ok":true,"routes":["{token_a}"]}}"#),
    );
    assert_eq!(
        activation(&center),
        NotificationDestination::Event {
            key: EventKey::Run(a.id),
            vault_path: fx.session.vault_path().expect("path"),
            session_epoch: fx.session.epoch().expect("epoch")
        }
    );
    fake.respond("notify_activations", r#"{"ok":true,"routes":[]}"#);
    assert!(fx.broker.approvals().deny(a.id));
    assert_eq!(code(&waiter_a.join().expect("A waiter")), "approval_denied");

    let waiter_b = send_run(&fx, fx.project.clone());
    let (b, _) = first_pending(&fx);
    assert_ne!(a.id, b.id);
    let (notice_b, _) = notify_request(
        &fake,
        &EventKey::Run(b.id).notification_id(),
        Instant::now(),
    );
    let token_b = notice_b["route"].as_str().expect("route B");
    assert_ne!(token_a, token_b);
    fake.respond(
        "notify_activations",
        &format!(r#"{{"ok":true,"routes":["{token_a}"]}}"#),
    );
    assert_eq!(activation(&center), NotificationDestination::Requests);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let removals = fake.requests_for("notify_remove");
        if removals.iter().any(|request| {
            request["ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id == token_a))
        }) {
            assert!(removals.iter().all(|request| {
                !request["ids"]
                    .as_array()
                    .expect("ids")
                    .iter()
                    .any(|id| id == token_b)
            }));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "settled alert was not reconciled"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fx.broker.approvals().pending(), vec![b.clone()]);
    let history = inbox::collect(&fx.session, std::slice::from_ref(&b)).expect("history");
    assert!(
        history
            .iter()
            .any(|event| matches!(event.kind, InboxKind::ApprovalEnded { approved: false }))
    );
    no_canary(&fake.raw_requests());
    assert!(!fx.project.join("ran").exists());
    assert!(fx.broker.approvals().deny(b.id));
    assert_eq!(code(&waiter_b.join().expect("B waiter")), "approval_denied");
}

/// A capability from an earlier app session is not guessed from a numeric ID.
/// Suggestions have a separate fixed template and never claim an agent is blocked.
#[test]
fn unknown_activation_opens_unselected_list_and_suggestions_are_nonurgent() {
    let fx = fixture(Duration::from_secs(10));
    let fake = FakeNative::new("unknown-and-suggestion");
    fake.respond(
        "notify",
        &format!(r#"{{"ok":true,"delivered":true,{ALLOWED_STATUS}}}"#),
    );
    fake.respond(
        "notify_status",
        &format!(r#"{{"ok":true,{ALLOWED_STATUS}}}"#),
    );
    let center = start_center(&fx, &fake);
    fake.respond(
        "notify_activations",
        &format!(r#"{{"ok":true,"routes":["{}"]}}"#, "0".repeat(64)),
    );
    assert_eq!(activation(&center), NotificationDestination::Requests);
    center.announce(OwnerEvent::CorrectionProposed, 77, "ignored agent");
    let (notice, _) = notify_request(&fake, "correction-77", Instant::now());
    assert_eq!(notice["event"], "suggestion");
    assert_eq!(notice["agent"], "Apassy");
    let preview = apassy::native::Notification::new(
        "correction-77",
        "Apassy",
        OwnerEvent::CorrectionProposed.native(),
    )
    .expect("preview");
    assert_eq!(preview.title(), "Suggestion available");
    assert!(!preview.body().contains("waits"));
    assert!(!preview.body().contains("Agent"));
    no_canary(&fake.raw_requests());
}

/// The local transport accepts no URL/path/command and malformed helper data never
/// becomes a destination. These calls use a fake process and do not contact macOS.
#[test]
fn notification_navigation_transport_rejects_untrusted_fields() {
    let fake = FakeNative::new("routing-validation");
    let helper = fake.helper();
    let notice =
        apassy::native::Notification::new("run-1", AGENT, OwnerEvent::QuestionWaiting.native())
            .expect("preview");
    for invalid in [
        "run-1",
        "apassy://approve/1",
        "../../other",
        "$(touch marker)",
    ] {
        assert!(helper.notify_routed(&notice, Some(invalid), None).is_err());
        assert!(helper.notify_routed(&notice, None, Some(invalid)).is_err());
    }
    assert!(helper.notify_remove(&["../run-1".to_owned()]).is_err());
    assert!(helper.notify_reconcile(&["run-1".to_owned()]).is_err());
    assert!(
        fake.requests().is_empty(),
        "invalid input reached the helper"
    );
    for response in [
        r#"{"ok":true,"routes":["run-1"]}"#,
        r#"{"ok":true,"routes":[3]}"#,
        r#"{"ok":true,"routes":null}"#,
    ] {
        fake.respond("notify_activations", response);
        assert!(
            helper.notify_activations().is_err(),
            "malformed activation accepted: {response}"
        );
    }
}

/// A route may wait in UI state after polling. Final consumption must retain both
/// vault identity and unlocked-session identity, even when the watcher never sees
/// the intermediate lock and the next vault reuses the same local activity ID.
#[test]
fn queued_destination_is_rejected_after_lock_reunlock_or_vault_switch_with_reused_id() {
    use apassy::vault::{ActivityDecision, NewActivity};

    let mut fx = fixture(Duration::from_secs(10));
    let fake = FakeNative::new("queued-route-vault-switch");
    fake.respond(
        "notify",
        &format!(r#"{{"ok":true,"delivered":true,{ALLOWED_STATUS}}}"#),
    );
    fake.respond(
        "notify_status",
        &format!(r#"{{"ok":true,{ALLOWED_STATUS}}}"#),
    );
    let center = start_center(&fx, &fake);
    send_blocked(&fx);
    let id = fx
        .vault
        .lock()
        .expect("vault")
        .as_ref()
        .expect("open")
        .recent_activity(1)
        .expect("activity")[0]
        .id;
    let (notice, _) = notify_request(
        &fake,
        &EventKey::Activity(id).notification_id(),
        Instant::now(),
    );
    let token = notice["route"].as_str().expect("route");
    fake.respond(
        "notify_activations",
        &format!(r#"{{"ok":true,"routes":["{token}"]}}"#),
    );
    let queued_a = activation(&center);
    assert!(
        matches!(queued_a, NotificationDestination::Event { key: EventKey::Activity(actual), .. } if actual == id)
    );
    fake.respond("notify_activations", r#"{"ok":true,"routes":[]}"#);

    // A lock invalidates a queued destination immediately, without a watcher pass.
    let epoch_a = fx.session.epoch().expect("A epoch");
    fx.session
        .lock_ending_runs(None, ENDED_BY_QUIT)
        .expect("lock A");
    assert_eq!(
        center.revalidate_destination(&queued_a),
        NotificationDestination::Requests
    );
    fx.session.unlock(PASS).expect("reunlock A");
    assert_ne!(fx.session.epoch(), Some(epoch_a));
    assert_eq!(
        center.revalidate_destination(&queued_a),
        NotificationDestination::Requests
    );

    // B has an existing eligible event with exactly the same vault-local numeric ID.
    fx.session
        .lock_ending_runs(None, ENDED_BY_QUIT)
        .expect("lock A again");
    let path_b = fx.dir.path().join("other-route.db");
    fx.session.create_file(&path_b, PASS).expect("create B");
    fx.session.unlock(PASS).expect("unlock B");
    {
        let mut guard = fx.vault.lock().expect("vault");
        let open = guard.as_mut().expect("B open");
        for _ in 0..id {
            open.record_activity(&NewActivity {
                agent_id: None,
                agent_name: "Other agent".to_owned(),
                item_id: None,
                operation: "run synthetic".to_owned(),
                decision: ActivityDecision::Deny,
                reason: "Synthetic blocked request.".to_owned(),
            })
            .expect("B activity");
        }
        assert!(
            open.recent_activity(50)
                .expect("B activity")
                .iter()
                .any(|row| row.id == id)
        );
    }
    assert_eq!(
        center.revalidate_destination(&queued_a),
        NotificationDestination::Requests
    );
    let current_b = NotificationDestination::Event {
        key: EventKey::Activity(id),
        vault_path: fx.session.vault_path().expect("B path"),
        session_epoch: fx.session.epoch().expect("B epoch"),
    };
    assert_eq!(
        center.revalidate_destination(&current_b),
        current_b,
        "the reused ID really is eligible in B"
    );
    no_canary(&fake.raw_requests());
}
