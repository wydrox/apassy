//! Headless tests of the owner command line in the app (ADR 0017). Synthetic values only.

use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use eframe::egui;
use tempfile::TempDir;

use super::owner_tests::{
    PASS, WRONG, app_frame, finish_check, socket_dir, unlocked_app_with_item,
};
use crate::broker::approvals::OwnerCheck;
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::owner_cli::{CLI_ORIGIN_NOTE, SESSION_PREFIX};
use crate::desktop::owner_socket::Envelope;
use crate::owner::wire::{
    Command, Data, DetailInput, GrantMode, ItemInput, OWNER_WIRE_VERSION, Request, Response,
    SecretText,
};

const SECRET: &str = "sk_test_cli-canary-0123456789abcdef";
const HIDDEN: &str = "hidden-detail-canary";

fn next_steps_text(app: &mut DesktopApp, ctx: &egui::Context) -> String {
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 2400.0),
            )),
            ..Default::default()
        },
        |ui| {
            assert!(!super::agents::next_steps_panel(app, ui));
        },
    );
    let mut text = String::new();
    for clipped in &output.shapes {
        super::owner_tests::collect(&clipped.shape, &mut text);
    }
    output.drop_without_applying_deltas();
    text
}

#[test]
fn next_steps_show_choices_without_registration_and_exclude_archived_items() {
    let dir = TempDir::new().unwrap();
    let (mut app, item) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let text = next_steps_text(&mut app, &ctx);
    assert!(
        text.contains("1 active credential is available on this Mac"),
        "{text}"
    );
    for choice in ["Claude Code", "Codex", "CLI", "Skip"] {
        assert!(text.contains(choice), "{text}");
    }
    assert!(text.contains("Agents and grants stay on this Mac"));
    assert!(
        !text.contains("Setup checks"),
        "the initial panel stays compact"
    );
    assert!(!text.contains(SECRET));
    assert!(app.owner_ui.session.agents().unwrap().is_empty());
    assert!(app.owner_ui.fresh_token.is_none());
    assert!(app.ui.sheet.is_none());

    app.owner_ui.session.archive(item).unwrap();
    let text = next_steps_text(&mut app, &ctx);
    assert!(
        text.contains("0 active credentials are available on this Mac"),
        "{text}"
    );
    app.owner_ui.session.lock().unwrap();
    let text = next_steps_text(&mut app, &ctx);
    assert!(
        text.is_empty(),
        "the panel does not claim credentials are available when locked"
    );
}

#[test]
fn next_steps_distinguish_a_cli_session_from_a_successful_agent_request() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let token = login(&mut app, &ctx);
    app.ui.set_expanded("next-step-cli", true);
    let text = next_steps_text(&mut app, &ctx);
    // A status row paints its state first, then its title and the hint of an open
    // check, so the state names the row that follows it.
    assert!(text.contains("Checked\nCLI connected"), "{text}");
    assert!(
        text.contains(
            "To check\nFirst successful request\nCheck the result of a test request and its entry in Activity"
        ),
        "{text}"
    );
    assert!(text.contains("apassy status"), "{text}");
    assert!(!text.contains("Host connected"));
    assert!(!text.contains(&token));
    assert!(app.owner_ui.session.agents().unwrap().is_empty());
}

fn ask(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    session: Option<&str>,
    command: Command,
) -> Receiver<Response> {
    let (reply, answer) = mpsc::channel();
    app.handle_cli(
        Envelope {
            request: Request {
                v: OWNER_WIRE_VERSION,
                session: session.map(|token| SecretText::new(token.to_owned())),
                command,
            },
            reply,
        },
        ctx,
    );
    answer
}

/// The answer that the app gave at once.
fn now(answer: &Receiver<Response>) -> Response {
    answer.try_recv().expect("an answer without an owner check")
}

/// Run one command that needs no owner check.
fn run(app: &mut DesktopApp, ctx: &egui::Context, session: &str, command: Command) -> Response {
    now(&ask(app, ctx, Some(session), command))
}

/// Log in with the passphrase in the owner check dialog. Returns the token.
fn login(app: &mut DesktopApp, ctx: &egui::Context) -> String {
    let answer = ask(app, ctx, None, Command::Login);
    assert!(
        answer.try_recv().is_err(),
        "login waits for the owner check"
    );
    assert!(
        app.owner.check.as_ref().is_some_and(|d| d.origin.is_some()),
        "the dialog knows that the command line asked"
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("login answer");
    assert!(response.ok, "{response:?}");
    let Data::Session {
        token,
        idle_minutes,
    } = response.data
    else {
        panic!("no session: {:?}", response.data);
    };
    assert_eq!(idle_minutes, 30);
    assert!(token.expose().starts_with(SESSION_PREFIX));
    token.expose().to_owned()
}

fn as_json(response: &Response) -> String {
    serde_json::to_string(response).expect("json")
}

#[test]
fn without_a_session_only_status_lock_show_and_login_work() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();

    let status = now(&ask(&mut app, &ctx, None, Command::Status));
    assert!(status.ok);
    let Data::Status(view) = status.data else {
        panic!("no status");
    };
    assert!(!view.session);
    assert_eq!(view.waiting_runs, None, "counts need a session");

    for command in [
        Command::ItemList {
            query: String::new(),
            archived: false,
        },
        Command::AgentList,
        Command::DecisionExport,
        Command::Restore {
            backup: "/tmp/x".to_owned(),
        },
    ] {
        let response = now(&ask(&mut app, &ctx, None, command));
        assert_eq!(response.code, "session_required");
        let json = serde_json::to_string(&response).expect("serialize session error");
        let decoded: Response = serde_json::from_str(&json).expect("parse session error");
        assert!(decoded.message.contains(r#"eval "$(apassy login)""#));
        assert!(!decoded.message.contains(r#"\""#));
    }
    let forged = now(&ask(
        &mut app,
        &ctx,
        Some("apassy_cli_0000000000000000000000000000000000000000000000000000000000000000"),
        Command::AgentList,
    ));
    assert_eq!(forged.code, "session_required");

    let bad = Request {
        v: 99,
        session: None,
        command: Command::Status,
    };
    let (reply, answer) = mpsc::channel();
    app.handle_cli(
        Envelope {
            request: bad,
            reply,
        },
        &ctx,
    );
    assert_eq!(now(&answer).code, "bad_version");
}

#[test]
fn login_asks_the_owner_and_a_lock_ends_the_session() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();

    // The dialog names the command line.
    let answer = ask(&mut app, &ctx, None, Command::Login);
    let text = app_frame(&ctx, &mut app);
    assert!(text.contains("Start a command-line session"), "{text}");
    assert!(text.contains(CLI_ORIGIN_NOTE), "{text}");
    // A wrong passphrase keeps the dialog and the request open.
    if let Some(dialog) = app.owner.check.as_mut() {
        dialog.passphrase.push_str(WRONG);
    }
    app.start_passphrase_check(&ctx);
    finish_check(&mut app, &ctx);
    assert!(
        app.owner
            .check
            .as_ref()
            .is_some_and(|d| d.message.is_some())
    );
    assert!(answer.try_recv().is_err());
    app.close_owner_check(Some(&ctx));
    assert_eq!(now(&answer).code, "cancelled");

    let token = login(&mut app, &ctx);
    let status = run(&mut app, &ctx, &token, Command::Status);
    let Data::Status(view) = status.data else {
        panic!("no status");
    };
    assert!(view.session);
    assert_eq!(view.waiting_runs, Some(0));
    assert!(!as_json(&run(&mut app, &ctx, &token, Command::Status)).contains(&token));

    let listed = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemList {
            query: String::new(),
            archived: false,
        },
    );
    assert!(listed.ok, "{listed:?}");

    // Lock needs no session, and it ends every session.
    let locked = now(&ask(&mut app, &ctx, None, Command::Lock));
    assert!(locked.ok);
    assert!(app.owner_ui.session.is_locked());
    let after = run(&mut app, &ctx, &token, Command::AgentList);
    assert_eq!(after.code, "session_required");

    // A locked vault refuses a login.
    let refused = now(&ask(&mut app, &ctx, None, Command::Login));
    assert_eq!(refused.code, "vault_locked");
}

#[test]
fn a_cancel_or_a_second_request_answers_the_command_line() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();

    let first = ask(&mut app, &ctx, None, Command::Login);
    let second = ask(&mut app, &ctx, None, Command::Login);
    assert_eq!(
        now(&second).code,
        "busy",
        "a request cannot replace an open dialog"
    );
    app.close_owner_check(Some(&ctx));
    let cancelled = first.try_recv().expect("an answer after the cancel");
    assert_eq!(cancelled.code, "cancelled");
    assert!(app.owner.check.is_none());
    assert_eq!(app.cli.session_count(), 0);

    // A check from the window that replaces a command-line check also answers it.
    let third = ask(&mut app, &ctx, None, Command::Login);
    app.ask_owner(
        crate::desktop::owner_check::OwnerRequest::ConfirmReview { item_id: 1 },
        Some(&ctx),
    );
    assert_eq!(now(&third).code, "cancelled");
}

#[test]
fn sessions_end_when_idle_and_at_logout() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();

    let token = login(&mut app, &ctx);
    app.age_cli_sessions(Duration::from_secs(29 * 60));
    assert!(
        run(&mut app, &ctx, &token, Command::AgentList).ok,
        "29 idle minutes"
    );
    app.age_cli_sessions(Duration::from_secs(31 * 60));
    assert_eq!(
        run(&mut app, &ctx, &token, Command::AgentList).code,
        "session_required"
    );

    let token = login(&mut app, &ctx);
    assert!(run(&mut app, &ctx, &token, Command::Logout).ok);
    assert_eq!(
        run(&mut app, &ctx, &token, Command::AgentList).code,
        "session_required"
    );
}

#[test]
fn items_round_trip_and_no_answer_holds_a_value() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let token = login(&mut app, &ctx);

    let added = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemAdd {
            item: ItemInput {
                name: Some("CLI key".to_owned()),
                kind: Some(CredentialKind::ApiKey),
                service: Some("stripe.com".to_owned()),
                project: Some("billing".to_owned()),
                secret: Some(SecretText::new(SECRET.to_owned())),
                details: vec![
                    DetailInput {
                        label: "Region".to_owned(),
                        value: SecretText::new("eu-west-1".to_owned()),
                        hidden: false,
                    },
                    DetailInput {
                        label: "Webhook secret".to_owned(),
                        value: SecretText::new(HIDDEN.to_owned()),
                        hidden: true,
                    },
                ],
                ..ItemInput::default()
            },
        },
    );
    assert!(added.ok, "{added:?}");
    assert!(
        app.status_text.starts_with("Command line:"),
        "the window shows the change"
    );
    let Data::Items { items } = &added.data else {
        panic!("no row");
    };
    let id = items[0].id;

    // A kind is required, and a secret too.
    let missing = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemAdd {
            item: ItemInput {
                name: Some("No secret".to_owned()),
                kind: Some(CredentialKind::Login),
                username: Some("me".to_owned()),
                ..ItemInput::default()
            },
        },
    );
    assert_eq!(missing.code, "invalid_input");

    let shown = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemShow {
            item: "cli KEY".to_owned(),
        },
    );
    assert!(shown.ok, "{shown:?}");
    let json = as_json(&shown);
    assert!(!json.contains(SECRET) && !json.contains(HIDDEN), "{json}");
    let Data::Item(view) = shown.data else {
        panic!("no item");
    };
    assert_eq!(view.id, id);
    assert_eq!(view.secret_fields, ["token"]);
    assert_eq!(view.details.len(), 2);
    assert_eq!(view.details[0].value.as_deref(), Some("eu-west-1"));
    assert!(view.details[1].hidden && view.details[1].value.is_none());

    // An edit keeps the secrets that it does not name.
    let edited = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemEdit {
            item: id.to_string(),
            revision: None,
            changes: ItemInput {
                name: Some("CLI key 2".to_owned()),
                remove_details: vec!["region".to_owned()],
                ..ItemInput::default()
            },
        },
    );
    assert!(edited.ok, "{edited:?}");
    let vault_value = app
        .owner_ui
        .session
        .shared_vault()
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .reveal(id, "token")
        .unwrap();
    assert_eq!(vault_value.expose(), SECRET);
    let same = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemEdit {
            item: id.to_string(),
            revision: None,
            changes: ItemInput::default(),
        },
    );
    assert!(same.message.contains("unchanged"), "{same:?}");
    let stale = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemEdit {
            item: id.to_string(),
            revision: Some(1),
            changes: ItemInput {
                notes: Some("x".to_owned()),
                ..ItemInput::default()
            },
        },
    );
    assert_eq!(stale.code, "conflict", "{stale:?}");
    let kind = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemEdit {
            item: id.to_string(),
            revision: None,
            changes: ItemInput {
                kind: Some(CredentialKind::Login),
                ..ItemInput::default()
            },
        },
    );
    assert_eq!(kind.code, "category_locked");

    let history = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemHistory {
            item: id.to_string(),
            limit: None,
        },
    );
    let Data::Events { events } = history.data else {
        panic!("no events");
    };
    assert!(events.iter().any(|event| event.kind == "edited"));
    assert!(events.iter().any(|event| event.kind == "created"));

    // Archive needs no check. Unarchive asks the owner.
    assert!(
        run(
            &mut app,
            &ctx,
            &token,
            Command::ItemArchive {
                item: id.to_string()
            }
        )
        .ok
    );
    let list = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemList {
            query: String::new(),
            archived: false,
        },
    );
    let Data::Items { items } = list.data else {
        panic!("no list");
    };
    assert!(
        items.iter().all(|item| item.id != id),
        "the list hides an archived item"
    );
    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::ItemUnarchive {
            item: id.to_string(),
        },
    );
    assert!(answer.try_recv().is_err());
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(answer.try_recv().expect("answer").ok);
    assert!(!app.owner_ui.session.is_archived(id).unwrap());

    let ambiguous_add = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemAdd {
            item: ItemInput {
                name: Some("CLI key 2".to_owned()),
                kind: Some(CredentialKind::ApiKey),
                secret: Some(SecretText::new(SECRET.to_owned())),
                ..ItemInput::default()
            },
        },
    );
    assert!(ambiguous_add.ok);
    let ambiguous = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemShow {
            item: "CLI key 2".to_owned(),
        },
    );
    assert_eq!(ambiguous.code, "ambiguous");

    assert!(
        run(
            &mut app,
            &ctx,
            &token,
            Command::ItemDelete {
                item: id.to_string(),
                revision: None
            }
        )
        .ok
    );
    let gone = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemShow {
            item: id.to_string(),
        },
    );
    assert_eq!(gone.code, "not_found");
}

#[test]
fn agents_variables_and_grants_ask_the_owner_for_each_change() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let token = login(&mut app, &ctx);

    let added = run(
        &mut app,
        &ctx,
        &token,
        Command::AgentAdd {
            name: "Claude Code".to_owned(),
        },
    );
    let Data::Token {
        agent,
        token: agent_token,
    } = &added.data
    else {
        panic!("no token: {added:?}");
    };
    assert!(
        agent_token
            .expose()
            .starts_with(crate::vault::AGENT_TOKEN_PREFIX)
    );
    assert_eq!(
        crate::owner::wire::AGENT_TOKEN_PREFIX,
        crate::vault::AGENT_TOKEN_PREFIX
    );
    let agent_id = agent.id;
    assert!(
        app.owner_ui.fresh_token.is_none(),
        "the window does not show the token"
    );

    // A grant needs a variable first. The app says so before it asks the owner.
    let early = run(
        &mut app,
        &ctx,
        &token,
        Command::GrantSet {
            agent: "claude code".to_owned(),
            items: vec![item_id.to_string()],
            folder: Some("/tmp/project".to_owned()),
            mode: GrantMode::Ask,
        },
    );
    assert_eq!(early.code, "invalid_input");
    assert!(app.owner.check.is_none());

    let bad_name = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemSetVariable {
            item: item_id.to_string(),
            name: "PATH".to_owned(),
            field: None,
            hosts: Vec::new(),
        },
    );
    assert_eq!(bad_name.code, "invalid_input");

    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::ItemSetVariable {
            item: item_id.to_string(),
            name: "GUARDED_KEY".to_owned(),
            field: None,
            hosts: Vec::new(),
        },
    );
    let text = app_frame(&ctx, &mut app);
    assert!(text.contains("GUARDED_KEY"), "{text}");
    assert!(text.contains(CLI_ORIGIN_NOTE), "{text}");
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let bound = answer.try_recv().expect("answer");
    assert!(bound.ok, "{bound:?}");

    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::GrantSet {
            agent: agent_id.to_string(),
            items: vec!["Guarded key".to_owned()],
            folder: Some(dir.path().display().to_string()),
            mode: GrantMode::Bouncer,
        },
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let granted = answer.try_recv().expect("answer");
    assert!(granted.ok, "{granted:?}");

    let relative = run(
        &mut app,
        &ctx,
        &token,
        Command::GrantSet {
            agent: agent_id.to_string(),
            items: vec![item_id.to_string()],
            folder: Some("project".to_owned()),
            mode: GrantMode::Ask,
        },
    );
    assert_eq!(relative.code, "invalid_input");

    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::GrantRule {
            agent: agent_id.to_string(),
            item: item_id.to_string(),
            rule: crate::owner::wire::RuleInput {
                allow: vec!["npm test".to_owned()],
                forbid: vec!["prod".to_owned()],
                max_runs_per_hour: Some(10),
                ..crate::owner::wire::RuleInput::default()
            },
        },
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(answer.try_recv().expect("answer").ok);

    let shown = run(
        &mut app,
        &ctx,
        &token,
        Command::AgentShow {
            agent: "Claude Code".to_owned(),
        },
    );
    let Data::Agent(view) = shown.data else {
        panic!("no agent");
    };
    assert_eq!(view.grants.len(), 1);
    let canonical = std::fs::canonicalize(dir.path()).unwrap();
    assert_eq!(
        view.grants[0].folder.as_deref(),
        Some(canonical.display().to_string().as_str())
    );
    assert_eq!(view.grants[0].mode, GrantMode::Bouncer);
    assert_eq!(view.grants[0].rule.allow, ["npm test"]);
    assert_eq!(view.grants[0].rule.max_runs_per_hour, Some(10));

    // Rotation: the new token goes to the command line only.
    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::AgentRotate {
            agent: agent_id.to_string(),
        },
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let rotated = answer.try_recv().expect("answer");
    let Data::Token {
        token: new_token, ..
    } = &rotated.data
    else {
        panic!("no token: {rotated:?}");
    };
    assert_ne!(new_token.expose(), agent_token.expose());
    assert!(app.owner_ui.fresh_token.is_none());

    // Taking authority away needs no check.
    assert!(
        run(
            &mut app,
            &ctx,
            &token,
            Command::GrantRemove {
                agent: agent_id.to_string(),
                item: item_id.to_string()
            }
        )
        .ok
    );
    assert!(
        run(
            &mut app,
            &ctx,
            &token,
            Command::AgentRevoke {
                agent: agent_id.to_string()
            }
        )
        .ok
    );
    let rotate_revoked = run(
        &mut app,
        &ctx,
        &token,
        Command::AgentRotate {
            agent: agent_id.to_string(),
        },
    );
    assert_eq!(rotate_revoked.code, "invalid_input");
    assert!(app.owner.check.is_none());
}

#[test]
fn backup_locks_and_restore_opens_the_sheet() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let token = login(&mut app, &ctx);

    let relative = run(
        &mut app,
        &ctx,
        &token,
        Command::Backup {
            path: "backup.db".to_owned(),
        },
    );
    assert_eq!(relative.code, "invalid_input");
    let backup = dir.path().join("cli.backup");
    let restore = run(
        &mut app,
        &ctx,
        &token,
        Command::Restore {
            backup: backup.display().to_string(),
        },
    );
    assert_eq!(
        restore.code, "invalid_input",
        "the backup does not exist yet"
    );

    let done = run(
        &mut app,
        &ctx,
        &token,
        Command::Backup {
            path: backup.display().to_string(),
        },
    );
    assert!(done.ok, "{done:?}");
    assert!(backup.is_file());
    assert!(app.owner_ui.session.is_locked(), "a backup locks the vault");
    assert_eq!(app.cli.session_count(), 0);

    app.owner_ui.session.unlock(PASS).expect("unlock");
    let token = login(&mut app, &ctx);
    let restore = run(
        &mut app,
        &ctx,
        &token,
        Command::Restore {
            backup: backup.display().to_string(),
        },
    );
    assert!(restore.ok, "{restore:?}");
    assert!(matches!(app.ui.sheet, Some(super::Sheet::Restore)));
    // Settings > Security has Backup, under the sheet.
    assert_eq!(app.view, crate::desktop::OwnerView::Settings);
    assert_eq!(app.ui.settings_tab, super::SettingsTab::Security);
    assert_eq!(app.owner_ui.restore_source, backup.display().to_string());
}

#[test]
fn passphrase_change_from_the_command_line() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let token = login(&mut app, &ctx);
    let wrong = run(
        &mut app,
        &ctx,
        &token,
        Command::ChangePassphrase {
            current: SecretText::new(WRONG.to_owned()),
            new: SecretText::new("cli-new-pass-ok".to_owned()),
        },
    );
    assert!(!wrong.ok);
    let token = login(&mut app, &ctx);
    let changed = run(
        &mut app,
        &ctx,
        &token,
        Command::ChangePassphrase {
            current: SecretText::new(PASS.to_owned()),
            new: SecretText::new("cli-new-pass-ok".to_owned()),
        },
    );
    assert!(changed.ok, "{changed:?}");
    assert_eq!(
        app.cli.session_count(),
        0,
        "a passphrase change ends the sessions"
    );
}

/// The socket path end to end: mode 0600, one request per connection, and the answer
/// comes from the UI thread.
#[test]
fn the_owner_socket_answers_through_the_ui_thread() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let socket = socket_dir(&dir).with_file_name("owner.sock");
    app.start_cli(&socket, &ctx);
    assert!(app.cli.problem.is_none(), "{:?}", app.cli.problem);
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let path = socket.clone();
    let client = std::thread::spawn(move || {
        crate::owner::client::send(&path, None, Command::Status).expect("status")
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() {
        assert!(Instant::now() < deadline, "no answer");
        app.poll_cli(&ctx);
        std::thread::sleep(Duration::from_millis(5));
    }
    let response = client.join().unwrap();
    assert!(response.ok, "{response:?}");
    assert!(matches!(response.data, Data::Status(_)));

    // A second app cannot take the socket of a running one.
    let mut other = DesktopApp::new();
    other.start_cli(&socket, &ctx);
    assert!(other.cli.problem.is_some());

    app.cli.stop();
    assert!(!socket.exists(), "stop removes the socket file");
    let refused = crate::owner::client::send(&socket, None, Command::Status);
    assert!(matches!(
        refused,
        Err(crate::owner::client::SendError::NotRunning(_))
    ));
}

/// Run the `apassy` program code on a thread while the test thread plays the UI
/// thread. Returns the exit code.
fn program(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    words: &[impl AsRef<str>],
    session: Option<&str>,
) -> i32 {
    let words: Vec<String> = words.iter().map(|word| word.as_ref().to_owned()).collect();
    let session = session.map(|token| SecretText::new(token.to_owned()));
    let thread = std::thread::spawn(move || crate::cli::run_with(words, session));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !thread.is_finished() {
        assert!(Instant::now() < deadline, "the program did not end");
        app.poll_cli(ctx);
        std::thread::sleep(Duration::from_millis(5));
    }
    thread.join().expect("program thread")
}

#[test]
fn the_command_line_program_drives_the_app() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let socket = socket_dir(&dir).with_file_name("owner.sock");
    app.start_cli(&socket, &ctx);
    let socket = socket.display().to_string();
    let base = ["--socket", socket.as_str()];
    let with = |words: &[&str]| -> Vec<String> {
        base.iter()
            .chain(words)
            .map(|word| (*word).to_owned())
            .collect()
    };

    assert_eq!(program(&mut app, &ctx, &with(&["status"]), None), 0);
    assert_eq!(
        program(&mut app, &ctx, &with(&["--json", "status"]), None),
        0
    );
    assert_eq!(
        program(&mut app, &ctx, &with(&["item", "list"]), None),
        1,
        "no session"
    );
    assert_eq!(
        program(&mut app, &ctx, &with(&["item", "frobnicate"]), None),
        2
    );
    assert_eq!(program(&mut app, &ctx, &with(&["nonsense"]), None), 2);
    assert_eq!(program(&mut app, &ctx, &with(&["help", "item"]), None), 0);
    assert_eq!(program(&mut app, &ctx, &with(&["item", "--help"]), None), 0);
    let missing = dir.path().join("none.sock").display().to_string();
    assert_eq!(
        program(
            &mut app,
            &ctx,
            &["--socket", missing.as_str(), "status"],
            None
        ),
        3,
        "not running"
    );

    let token = login(&mut app, &ctx);
    let env_file = dir.path().join("import.env");
    std::fs::write(
        &env_file,
        format!("STRIPE_SECRET_KEY={SECRET}\nGITHUB_TOKEN=\"ghp_cli-canary-abcdef0123456789\"\nBROKEN LINE\n"),
    )
    .unwrap();
    let env_path = env_file.display().to_string();
    let import = with(&[
        "import",
        env_path.as_str(),
        "--project",
        "billing",
        "--dry-run",
    ]);
    assert_eq!(program(&mut app, &ctx, &import, Some(&token)), 0);
    let before = app.owner_ui.session.search("").unwrap().len();
    assert_eq!(before, 1, "a dry run adds nothing");
    let import = with(&["import", env_path.as_str(), "--project", "billing"]);
    assert_eq!(program(&mut app, &ctx, &import, Some(&token)), 0);
    let items = app.owner_ui.session.search("").unwrap();
    assert_eq!(items.len(), 3);
    assert!(
        items
            .iter()
            .any(|item| item.name == "GITHUB_TOKEN" && item.project == "billing")
    );
    // A second import leaves out the names that exist.
    assert_eq!(program(&mut app, &ctx, &import, Some(&token)), 0);
    assert_eq!(app.owner_ui.session.search("").unwrap().len(), 3);

    assert_eq!(
        program(
            &mut app,
            &ctx,
            &with(&["item", "show", "STRIPE_SECRET_KEY"]),
            Some(&token)
        ),
        0
    );
    assert_eq!(
        program(
            &mut app,
            &ctx,
            &with(&["item", "delete", "GITHUB_TOKEN", "--yes"]),
            Some(&token)
        ),
        0
    );
    assert_eq!(app.owner_ui.session.search("").unwrap().len(), 2);
    assert_eq!(
        program(
            &mut app,
            &ctx,
            &with(&["agent", "add", "Test", "agent"]),
            Some(&token)
        ),
        0
    );
    assert_eq!(app.owner_ui.session.agents().unwrap()[0].name, "Test agent");
    for words in [
        &["agent", "list"][..],
        &["agent", "show", "Test agent"],
        &["request", "list", "--all"],
        &["runs"],
        &["pattern", "list"],
        &["activity", "--limit", "5"],
        &["agent", "lifetime"],
        &["item", "history", "STRIPE_SECRET_KEY"],
    ] {
        assert_eq!(
            program(&mut app, &ctx, &with(words), Some(&token)),
            0,
            "{words:?}"
        );
    }
    let export = dir.path().join("decisions.jsonl");
    let export_path = export.display().to_string();
    assert_eq!(
        program(
            &mut app,
            &ctx,
            &with(&["decisions", "export", "--output", export_path.as_str()]),
            Some(&token)
        ),
        0
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&export).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(program(&mut app, &ctx, &with(&["lock"]), None), 0);
    assert!(app.owner_ui.session.is_locked());
}

/// Add an API key from the command line. Returns its ID.
fn add_key(app: &mut DesktopApp, ctx: &egui::Context, token: &str, name: &str) -> u64 {
    let added = run(
        app,
        ctx,
        token,
        Command::ItemAdd {
            item: ItemInput {
                name: Some(name.to_owned()),
                kind: Some(CredentialKind::ApiKey),
                secret: Some(SecretText::new(SECRET.to_owned())),
                ..ItemInput::default()
            },
        },
    );
    let Data::Items { items } = added.data else {
        panic!("no item: {added:?}");
    };
    items[0].id
}

fn bind(item_id: u64, name: &str) -> crate::owner::wire::VariableInput {
    crate::owner::wire::VariableInput {
        item_id,
        name: name.to_owned(),
    }
}

/// The variables of the vault: (item ID, variable).
fn bound_variables(app: &DesktopApp) -> Vec<(u64, String)> {
    app.owner_ui
        .session
        .env_bound_items()
        .unwrap()
        .into_iter()
        .map(|(id, _, name)| (id, name))
        .collect()
}

/// ADR 0017, D1: one owner check binds every variable. The dialog lists each name and
/// the count. The app refuses invalid names and taken names before the check, and the
/// answer reports them per item.
#[test]
fn a_batch_binding_asks_one_owner_check_and_lists_every_name() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, guarded) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let token = login(&mut app, &ctx);

    // The first item takes a name. A later batch cannot take it.
    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::ItemSetVariable {
            item: guarded.to_string(),
            name: "TAKEN_KEY".to_owned(),
            field: None,
            hosts: Vec::new(),
        },
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(answer.try_recv().expect("answer").ok);

    let stripe = add_key(&mut app, &ctx, &token, "Stripe batch");
    let github = add_key(&mut app, &ctx, &token, "GitHub batch");
    let openai = add_key(&mut app, &ctx, &token, "OpenAI batch");
    let lower = add_key(&mut app, &ctx, &token, "Lower batch");
    let taken = add_key(&mut app, &ctx, &token, "Taken batch");
    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::ItemBindVariables {
            variables: vec![
                bind(stripe, "STRIPE_SECRET_KEY"),
                bind(github, "GITHUB_TOKEN"),
                bind(openai, "OPENAI_API_KEY"),
                bind(lower, "lower_key"),
                bind(taken, "TAKEN_KEY"),
                bind(999_999, "MISSING_KEY"),
            ],
        },
    );
    assert!(
        answer.try_recv().is_err(),
        "the binding waits for the owner"
    );
    let dialog = app.owner.check.as_ref().expect("one owner check");
    let action = dialog.request.action();
    assert_eq!(
        action,
        crate::broker::approvals::OwnerAction::BindVariables {
            variables: vec![
                (stripe, "STRIPE_SECRET_KEY".to_owned()),
                (github, "GITHUB_TOKEN".to_owned()),
                (openai, "OPENAI_API_KEY".to_owned()),
            ],
        }
    );
    assert_eq!(action.reason(), "bind 3 environment variables");

    let text = app_frame(&ctx, &mut app);
    for name in [
        "Stripe batch",
        "STRIPE_SECRET_KEY",
        "GitHub batch",
        "GITHUB_TOKEN",
        "OpenAI batch",
        "OPENAI_API_KEY",
        "3 variables",
        CLI_ORIGIN_NOTE,
    ] {
        assert!(text.contains(name), "{name}: {text}");
    }
    // The vault list behind the dialog shows the item names, so only the refused
    // variables are checked.
    for refused in ["lower_key", "MISSING_KEY"] {
        assert!(!text.contains(refused), "{refused} is not in the dialog");
    }
    assert!(!text.contains(SECRET));

    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(app.owner.check.is_none(), "one check for all of them");
    let response = answer.try_recv().expect("answer");
    assert!(response.ok, "{response:?}");
    assert!(!as_json(&response).contains(SECRET));
    let Data::Bindings { results } = response.data else {
        panic!("no bindings: {:?}", response.data);
    };
    assert_eq!(results.len(), 6);
    let result = |item_id: u64| {
        results
            .iter()
            .find(|row| row.item_id == item_id)
            .expect("a row for each variable")
    };
    for item_id in [stripe, github, openai] {
        assert!(result(item_id).bound, "{:?}", result(item_id));
        assert!(result(item_id).reason.is_empty());
    }
    assert!(!result(lower).bound);
    assert!(result(lower).reason.contains("A-Z"), "{:?}", result(lower));
    assert!(!result(taken).bound);
    assert!(
        result(taken).reason.contains("Guarded key"),
        "{:?}",
        result(taken)
    );
    assert!(!result(999_999).bound);

    let mut variables = bound_variables(&app);
    variables.sort();
    let mut expected = vec![
        (guarded, "TAKEN_KEY".to_owned()),
        (stripe, "STRIPE_SECRET_KEY".to_owned()),
        (github, "GITHUB_TOKEN".to_owned()),
        (openai, "OPENAI_API_KEY".to_owned()),
    ];
    expected.sort();
    assert_eq!(variables, expected);
    assert_eq!(app.status_text, "Command line: 3 variables are bound.");

    // When every name is refused, nothing waits for the owner.
    let refused = run(
        &mut app,
        &ctx,
        &token,
        Command::ItemBindVariables {
            variables: vec![bind(lower, "PATH"), bind(taken, "GITHUB_TOKEN")],
        },
    );
    assert!(refused.ok, "{refused:?}");
    assert!(app.owner.check.is_none());
    let Data::Bindings { results } = refused.data else {
        panic!("no bindings");
    };
    assert!(results.iter().all(|row| !row.bound));
    assert!(results[1].reason.contains("GitHub batch"), "{results:?}");
}

/// A cancel binds nothing, and a long list shows its count.
#[test]
fn a_cancelled_batch_binding_binds_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let token = login(&mut app, &ctx);
    let variables: Vec<_> = (0..40)
        .map(|index| {
            let id = add_key(&mut app, &ctx, &token, &format!("Key {index:02}"));
            bind(id, &format!("KEY_{index:02}"))
        })
        .collect();
    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::ItemBindVariables { variables },
    );
    let text = app_frame(&ctx, &mut app);
    assert!(text.contains("40 variables"), "{text}");
    assert!(text.contains("Bind 40 credentials"), "{text}");
    assert!(text.contains("KEY_00"), "{text}");
    app.close_owner_check(Some(&ctx));
    assert_eq!(answer.try_recv().expect("answer").code, "cancelled");
    assert!(bound_variables(&app).is_empty());
}

/// Run the `apassy` program, and confirm or cancel each owner check that it opens.
/// Returns the exit code and the number of owner checks.
fn program_with_checks(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    words: &[String],
    session: &str,
    confirm: bool,
) -> (i32, usize) {
    let words = words.to_vec();
    let session = Some(SecretText::new(session.to_owned()));
    let thread = std::thread::spawn(move || crate::cli::run_with(words, session));
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut checks = 0;
    while !thread.is_finished() {
        assert!(Instant::now() < deadline, "the program did not end");
        app.poll_cli(ctx);
        if app.owner.check.is_some() {
            checks += 1;
            if confirm {
                app.confirm_owner_now(OwnerCheck::passphrase(PASS))
                    .expect("owner check");
            } else {
                app.close_owner_check(Some(ctx));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    (thread.join().expect("program thread"), checks)
}

/// `apassy import --bind`: one owner check for the variables of a .env file. Without
/// `--bind`, nothing is bound. A cancel binds nothing.
#[test]
fn import_bind_binds_the_keys_of_a_env_file_with_one_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, guarded) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let socket = socket_dir(&dir).with_file_name("owner.sock");
    app.start_cli(&socket, &ctx);
    let socket = socket.display().to_string();
    let token = login(&mut app, &ctx);
    let words = |file: &std::path::Path, bind: bool| -> Vec<String> {
        let mut words = vec![
            "--socket".to_owned(),
            socket.clone(),
            "import".to_owned(),
            file.display().to_string(),
        ];
        if bind {
            words.push("--bind".to_owned());
        }
        words
    };

    // Without --bind, an import binds nothing and asks nothing.
    let plain = dir.path().join("plain.env");
    std::fs::write(&plain, format!("PLAIN_KEY={SECRET}\n")).unwrap();
    assert_eq!(
        program_with_checks(&mut app, &ctx, &words(&plain, false), &token, true),
        (0, 0)
    );
    assert_eq!(app.owner_ui.session.search("PLAIN_KEY").unwrap().len(), 1);
    assert!(bound_variables(&app).is_empty());

    // A cancel adds the items and binds nothing.
    let cancelled = dir.path().join("cancelled.env");
    std::fs::write(&cancelled, format!("CANCELLED_KEY={SECRET}\n")).unwrap();
    let mut json = words(&cancelled, true);
    json.insert(2, "--json".to_owned());
    assert_eq!(
        program_with_checks(&mut app, &ctx, &json, &token, false),
        (1, 1)
    );
    assert_eq!(
        app.owner_ui.session.search("CANCELLED_KEY").unwrap().len(),
        1
    );
    assert!(bound_variables(&app).is_empty());

    // A name of another item, a system name, and a lowercase name are refused. The
    // others bind with one check.
    let answer = ask(
        &mut app,
        &ctx,
        Some(&token),
        Command::ItemSetVariable {
            item: guarded.to_string(),
            name: "TAKEN_KEY".to_owned(),
            field: None,
            hosts: Vec::new(),
        },
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(answer.try_recv().expect("answer").ok);
    let env = dir.path().join("bind.env");
    std::fs::write(
        &env,
        format!(
            "STRIPE_SECRET_KEY={SECRET}\nGITHUB_TOKEN=ghp_cli-canary-abcdef0123456789\nOPENAI_API_KEY={SECRET}\nTAKEN_KEY={SECRET}\nPATH=/tmp/canary\nlower_key={SECRET}\n"
        ),
    )
    .unwrap();
    assert_eq!(
        program_with_checks(&mut app, &ctx, &words(&env, true), &token, true),
        (1, 1),
        "one owner check; the refused names make the exit code 1"
    );
    let mut names: Vec<String> = bound_variables(&app)
        .into_iter()
        .map(|(_, name)| name)
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "STRIPE_SECRET_KEY",
            "TAKEN_KEY"
        ]
    );
    for name in ["TAKEN_KEY", "PATH", "lower_key"] {
        assert_eq!(
            app.owner_ui.session.search(name).unwrap().len(),
            1,
            "{name} is added"
        );
    }
}
