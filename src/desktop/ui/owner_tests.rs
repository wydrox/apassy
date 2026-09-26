//! Headless UI tests for the owner check (goal items A4, N4) and the secret fields
//! (key-memory review F1, F4). Synthetic values only.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::{
    PASSPHRASE_CAPACITY, SECRET_VALUE_CAPACITY, draw, draw_vault_file_card, secret_field_id,
    secret_inputs, unlock_with_passphrase,
};
use crate::broker::approvals::{ApprovalOutcome, PendingRun};
use crate::contracts::CredentialKind;
use crate::desktop::inbox::EventKey;
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::{Ephemeral, SecretForm};
use crate::desktop::{BrokerState, DesktopApp, ItemDraft, OwnerView};
use crate::native::{Biometry, HelperErrorCode, NativeHelper};

const PASS: &str = "ui-owner-pass-ok";
const WRONG: &str = "ui-owner-pass-no";
const TOKEN: &str = "ui-owner-token-canary";
const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

fn input(time: f64, events: Vec<Event>) -> RawInput {
    RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
        time: Some(time),
        events,
        ..Default::default()
    }
}

/// One frame of the Vault file card only. It shows the passphrase field in each state.
fn card_frame(ctx: &egui::Context, app: &mut DesktopApp, time: f64, events: Vec<Event>) {
    let output = ctx.run_ui(input(time, events), |ui| draw_vault_file_card(app, ui));
    output.drop_without_applying_deltas();
}

/// Three frames of the whole app. A new dialog is invisible in its first frame, while
/// egui measures it. Returns the painted text of the last frame.
fn app_frame(ctx: &egui::Context, app: &mut DesktopApp) -> String {
    let mut text = String::new();
    for _ in 0..3 {
        let output = ctx.run_ui(input(0.0, Vec::new()), |ui| draw(app, ui));
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn collect(shape: &egui::Shape, out: &mut String) {
    match shape {
        egui::Shape::Text(text) => {
            out.push_str(text.galley.text());
            out.push('\n');
        }
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| collect(inner, out)),
        _ => {}
    }
}

fn command_z() -> Event {
    Event::Key {
        key: Key::Z,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Modifiers::COMMAND,
    }
}

/// Focus the vault passphrase field at time `t`, type `text`, and wait until egui stores
/// an undo point with the text (egui waits for 1 s of stable text).
fn type_passphrase(ctx: &egui::Context, app: &mut DesktopApp, text: &str, t: f64) {
    let id = secret_field_id("vault-passphrase");
    card_frame(ctx, app, t, Vec::new());
    ctx.memory_mut(|memory| memory.request_focus(id));
    card_frame(ctx, app, t + 0.1, Vec::new());
    card_frame(ctx, app, t + 0.2, vec![Event::Text(text.to_owned())]);
    card_frame(ctx, app, t + 2.0, Vec::new());
    card_frame(ctx, app, t + 2.1, Vec::new());
    assert_eq!(app.owner_ui.passphrase, text);
}

fn press_undo(ctx: &egui::Context, app: &mut DesktopApp, t: f64) {
    let id = secret_field_id("vault-passphrase");
    ctx.memory_mut(|memory| memory.request_focus(id));
    card_frame(ctx, app, t, vec![command_z()]);
    card_frame(ctx, app, t + 0.1, Vec::new());
}

fn locked_app(dir: &TempDir, name: &str) -> DesktopApp {
    let mut app = DesktopApp::new();
    app.owner_ui
        .session
        .create_file(&dir.path().join(name), PASS)
        .expect("create");
    app
}

/// F1: Cmd+Z in the passphrase field does not bring the passphrase back after unlock.
/// The control without the fix shows that the harness finds the leak.
#[test]
fn unlock_erases_the_passphrase_undo_history() {
    let dir = TempDir::new().expect("temp dir");

    // Control: the app takes the text but keeps the undo history.
    let mut app = locked_app(&dir, "control.db");
    let ctx = egui::Context::default();
    type_passphrase(&ctx, &mut app, PASS, 0.0);
    drop(Ephemeral::take(&mut app.owner_ui.passphrase));
    assert!(app.owner_ui.passphrase.is_empty());
    press_undo(&ctx, &mut app, 3.0);
    assert_eq!(
        app.owner_ui.passphrase, PASS,
        "control: egui keeps the typed text in the undo history"
    );
    drop(app);

    // The unlock path erases the undo history.
    let mut app = locked_app(&dir, "fixed.db");
    let ctx = egui::Context::default();
    type_passphrase(&ctx, &mut app, PASS, 0.0);
    unlock_with_passphrase(&mut app, &ctx);
    assert!(
        !app.owner_ui.session.is_locked(),
        "the typed passphrase unlocks"
    );
    press_undo(&ctx, &mut app, 3.0);
    assert!(
        app.owner_ui.passphrase.is_empty(),
        "Cmd+Z restored {} bytes",
        app.owner_ui.passphrase.len()
    );

    // A lock erases the typed text and the undo history of every secret field.
    type_passphrase(&ctx, &mut app, WRONG, 10.0);
    app.lock_vault(Some(&ctx));
    assert!(app.owner_ui.passphrase.is_empty());
    press_undo(&ctx, &mut app, 13.0);
    assert!(
        app.owner_ui.passphrase.is_empty(),
        "Cmd+Z restored {} bytes after the lock",
        app.owner_ui.passphrase.len()
    );
}

/// F4: typing does not move a secret field buffer, and the field keeps its capacity
/// after the app takes the text.
#[test]
fn secret_fields_keep_their_buffer_while_typing() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "sized.db");
    let ctx = egui::Context::default();
    let id = secret_field_id("vault-passphrase");
    card_frame(&ctx, &mut app, 0.0, Vec::new());
    let (ptr, capacity) = (
        app.owner_ui.passphrase.as_ptr(),
        app.owner_ui.passphrase.capacity(),
    );
    assert!(capacity >= PASSPHRASE_CAPACITY);
    ctx.memory_mut(|memory| memory.request_focus(id));
    card_frame(&ctx, &mut app, 0.1, Vec::new());
    let typed: Vec<Event> = "synthetic-passphrase-abc-żółw-0123456789"
        .chars()
        .map(|c| Event::Text(c.to_string()))
        .collect();
    assert_eq!(typed.len(), 40);
    card_frame(&ctx, &mut app, 0.2, typed);
    assert_eq!(app.owner_ui.passphrase.chars().count(), 40);
    assert_eq!(app.owner_ui.passphrase.as_ptr(), ptr, "the buffer moved");
    assert_eq!(app.owner_ui.passphrase.capacity(), capacity);

    // The field takes at most capacity / 4 characters, so 4-byte characters fit too.
    let limit = PASSPHRASE_CAPACITY / 4;
    card_frame(&ctx, &mut app, 0.3, vec![Event::Text("🔑".repeat(limit))]);
    assert_eq!(app.owner_ui.passphrase.chars().count(), limit);
    assert_eq!(app.owner_ui.passphrase.as_ptr(), ptr, "the buffer moved");

    // The slot keeps a buffer of the same capacity after a take.
    drop(Ephemeral::take(&mut app.owner_ui.passphrase));
    assert!(app.owner_ui.passphrase.capacity() >= capacity);

    // The item secret fields follow the same rule.
    let mut secrets = SecretForm::default();
    let token_id = secret_field_id("add-token");
    let form_frame = |ctx: &egui::Context, secrets: &mut SecretForm, events| {
        let output = ctx.run_ui(input(0.0, events), |ui| {
            secret_inputs(ui, "add", CredentialKind::ApiKey, secrets);
        });
        output.drop_without_applying_deltas();
    };
    form_frame(&ctx, &mut secrets, Vec::new());
    let (ptr, capacity) = (secrets.token.as_ptr(), secrets.token.capacity());
    assert!(capacity >= SECRET_VALUE_CAPACITY);
    ctx.memory_mut(|memory| memory.request_focus(token_id));
    form_frame(&ctx, &mut secrets, Vec::new());
    form_frame(&ctx, &mut secrets, vec![Event::Text("t".repeat(40))]);
    assert_eq!(secrets.token.len(), 40);
    assert_eq!(secrets.token.as_ptr(), ptr, "the buffer moved");
    secrets.clear();
    assert!(secrets.token.is_empty());
    assert_eq!(secrets.token.capacity(), capacity, "clear keeps the buffer");
}

/// A fake Touch ID helper that answers `not_available`, as on the development Mac.
fn not_available_helper(dir: &Path) -> NativeHelper {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("helper");
    std::fs::write(
        &script,
        "#!/bin/sh\nIFS= read -r line\nprintf '%s\\n' \"$line\" >> \"$(dirname \"$0\")/requests.log\"\nprintf '%s\\n' '{\"ok\":false,\"error\":\"not_available\",\"message\":\"synthetic\"}'\n",
    )
    .expect("fake helper");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    NativeHelper::with_paths(&script, &script)
}

/// Poll the app until the running owner check ends.
fn finish_check(app: &mut DesktopApp, ctx: &egui::Context) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while app
        .owner
        .check
        .as_ref()
        .is_some_and(|dialog| dialog.running.is_some())
    {
        assert!(Instant::now() < deadline, "the owner check did not end");
        std::thread::sleep(Duration::from_millis(10));
        app.poll_owner_flows(ctx);
    }
}

fn unlocked_app_with_item(dir: &TempDir) -> (DesktopApp, u64) {
    let mut app = locked_app(dir, "items.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let mut secrets = SecretForm::default();
    secrets.token = TOKEN.to_owned();
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Guarded key".to_owned(),
                kind: CredentialKind::ApiKey,
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    (app, item.id)
}

/// A4: "Reveal values" shows the owner check. Touch ID answers `not_available`, and
/// the dialog says so. A wrong passphrase reveals nothing. The right one reveals.
#[test]
fn reveal_waits_for_the_owner_check_and_falls_back_to_the_passphrase() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    app.owner.helper = Some(not_available_helper(dir.path()));
    app.owner.native.biometry = Some(Biometry::Unavailable(HelperErrorCode::NotAvailable));
    app.select_item(item_id.to_string());
    app.view = OwnerView::Item;
    let ctx = egui::Context::default();

    let text = app_frame(&ctx, &mut app);
    assert!(text.contains("Reveal values"), "{text}");
    app.ask_owner(OwnerRequest::Reveal { item_id }, Some(&ctx));
    let text = app_frame(&ctx, &mut app);
    assert!(text.contains("Confirm that it is you"), "{text}");
    assert!(
        text.contains(
            "Touch ID is not available: the Touch ID keyboard is not connected or not paired"
        ),
        "{text}"
    );
    assert!(!text.contains(TOKEN));
    assert!(
        app.owner
            .check
            .as_ref()
            .is_some_and(|d| d.running.is_none()),
        "Touch ID does not start by itself when it is not available"
    );

    // "Use Touch ID": the helper answers not_available. Nothing is revealed.
    app.start_owner_check(
        crate::broker::approvals::OwnerCheck::TouchId,
        Some(ctx.clone()),
    );
    finish_check(&mut app, &ctx);
    let message = app
        .owner
        .check
        .as_ref()
        .and_then(|d| d.message.clone())
        .expect("message");
    assert!(message.contains("Type the passphrase"), "{message}");
    assert_eq!(app.owner_ui.session.revealed_value(item_id, "token"), None);

    // A wrong passphrase: nothing is revealed, and the field is empty again.
    app.owner
        .check
        .as_mut()
        .expect("dialog")
        .passphrase
        .push_str(WRONG);
    app.start_passphrase_check(&ctx);
    assert!(
        app.owner
            .check
            .as_ref()
            .expect("dialog")
            .passphrase
            .is_empty()
    );
    finish_check(&mut app, &ctx);
    let message = app
        .owner
        .check
        .as_ref()
        .and_then(|d| d.message.clone())
        .expect("message");
    assert!(message.contains("incorrect"), "{message}");
    assert_eq!(app.owner_ui.session.revealed_value(item_id, "token"), None);
    assert!(!app_frame(&ctx, &mut app).contains(TOKEN));

    // The right passphrase reveals the value.
    app.owner
        .check
        .as_mut()
        .expect("dialog")
        .passphrase
        .push_str(PASS);
    app.start_passphrase_check(&ctx);
    finish_check(&mut app, &ctx);
    assert!(app.owner.check.is_none(), "the dialog closes");
    assert_eq!(
        app.owner_ui.session.revealed_value(item_id, "token"),
        Some(TOKEN)
    );
    assert!(app_frame(&ctx, &mut app).contains(TOKEN));

    // Cancel does nothing.
    app.owner_ui.session.hide(item_id).expect("hide");
    app.ask_owner(OwnerRequest::Reveal { item_id }, Some(&ctx));
    app.close_owner_check(Some(&ctx));
    assert_eq!(app.owner_ui.session.revealed_value(item_id, "token"), None);
}

fn waiting_run(agent: &str) -> PendingRun {
    PendingRun {
        id: 0,
        agent: agent.to_owned(),
        command: vec!["npm".to_owned(), "test".to_owned()],
        cwd: "/tmp".to_owned(),
        env_names: vec!["DEMO_KEY".to_owned()],
        purpose: "Run the tests.".to_owned(),
        risk: String::new(),
        user_request: "Run the tests.".to_owned(),
        request_source: String::new(),
        agent_request: String::new(),
        remember: None,
    }
}

fn socket_dir(dir: &TempDir) -> PathBuf {
    dir.path().join("s").join("broker.sock")
}

/// A4, N4: "Approve once" needs the owner check. "Mark as seen" is not an approval.
#[test]
fn approval_needs_the_owner_check_and_seen_is_not_an_approval() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.start_broker(&socket_dir(&dir));
    let BrokerState::Running(handle) = &app.broker else {
        panic!("the broker did not start");
    };
    let approvals = Arc::clone(handle.approvals());
    let waiter = {
        let approvals = Arc::clone(&approvals);
        std::thread::spawn(move || {
            approvals.wait_for(waiting_run("UI agent"), Duration::from_secs(20), || true)
        })
    };
    let run = loop {
        if let Some(run) = approvals.pending().into_iter().next() {
            break run;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let ctx = egui::Context::default();
    app.view = OwnerView::Activity;
    let text = app_frame(&ctx, &mut app);
    assert!(
        text.contains("UI agent asks to run a command with secrets"),
        "{text}"
    );
    assert!(text.contains("Approval waiting"), "{text}");
    assert!(text.contains("Mark as seen"), "{text}");
    assert!(text.contains("A notification is not an approval"), "{text}");

    // "Mark as seen" only marks the event.
    app.owner.acknowledged.insert(EventKey::Run(run.id));
    let text = app_frame(&ctx, &mut app);
    assert!(text.contains("Seen"), "{text}");
    assert_eq!(approvals.pending(), vec![run.clone()]);

    // "Approve once" opens the owner check. The run still waits.
    app.ask_owner(OwnerRequest::ApproveRun(run.clone()), Some(&ctx));
    assert!(app_frame(&ctx, &mut app).contains("Approve one run of agent"));
    assert_eq!(approvals.pending(), vec![run.clone()]);
    app.owner
        .check
        .as_mut()
        .expect("dialog")
        .passphrase
        .push_str(WRONG);
    app.start_passphrase_check(&ctx);
    finish_check(&mut app, &ctx);
    assert_eq!(
        approvals.pending(),
        vec![run.clone()],
        "a wrong passphrase approves nothing"
    );

    app.owner
        .check
        .as_mut()
        .expect("dialog")
        .passphrase
        .push_str(PASS);
    app.start_passphrase_check(&ctx);
    finish_check(&mut app, &ctx);
    assert_eq!(waiter.join().expect("waiter"), ApprovalOutcome::Approved);
}
