//! The guarded show and copy of one-time codes (TOTP): the proof names the item and the
//! field, it is fresh and of this vault session, and the copy never lets the seed out.
//! Synthetic values only. The seed is the SHA-1 seed of RFC 6238 appendix B. No test
//! touches the system clipboard.

use std::time::{Duration, Instant};

use eframe::egui;
use tempfile::TempDir;

use super::DesktopApp;
use super::clipboard::CodeClipboard;
use super::clipboard::memory::MemoryBoard;
use super::model::{DetailDraft, ItemDraft};
use super::owner_check::OwnerRequest;
use super::owner_store::{REVEAL_TIME, SecretForm, detail_field_name};
use crate::broker::approvals::{OwnerAction, OwnerCheck, OwnerProof, PROOF_LIFETIME};
use crate::contracts::CredentialKind;
use crate::otp::Totp;

const PASS: &str = "otp-guard-pass-ok";
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD: &str = "otp-guard-password-canary";
const RECOVERY: &str = "otp-guard-recovery-canary";
const OTP: &str = "One-time password";
const OTP_EIGHT: &str = "One-time password 2";

fn hidden(label: &str) -> DetailDraft {
    DetailDraft {
        label: label.to_owned(),
        value: String::new(),
        hidden: true,
        stored: None,
    }
}

/// An unlocked vault with one login: a password, a hidden recovery code, and two
/// one-time passwords (6 digits, and 8 digits as a link). The in-memory board is the
/// clipboard of the app.
fn app_with_login(dir: &TempDir) -> (DesktopApp, u64, MemoryBoard) {
    let mut app = DesktopApp::new();
    let session = &mut app.owner_ui.session;
    session
        .create_file(&dir.path().join("otp-guard.db"), PASS)
        .expect("create");
    if session.is_locked() {
        session.unlock(PASS).expect("unlock");
    }
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets.details[0] = SEED.to_owned();
    secrets.details[1] = RECOVERY.to_owned();
    secrets.details[2] = format!("otpauth://totp/Example?secret={SEED}&digits=8");
    let item = session
        .add(
            &ItemDraft {
                name: "Example login".to_owned(),
                kind: CredentialKind::Login,
                username: "user@example.test".to_owned(),
                details: vec![hidden(OTP), hidden("Recovery code"), hidden(OTP_EIGHT)],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    let board = MemoryBoard::default();
    app.owner.clipboard = CodeClipboard::with_board(Box::new(board.clone()));
    (app, item.id, board)
}

fn otp_field() -> String {
    detail_field_name(OTP)
}

fn show(item_id: u64, field: &str) -> OwnerAction {
    OwnerAction::ShowCode {
        item_id,
        field: field.to_owned(),
    }
}

fn copy(item_id: u64, field: &str) -> OwnerAction {
    OwnerAction::CopyCode {
        item_id,
        field: field.to_owned(),
    }
}

/// A proof of this session, issued now, without the cost of a passphrase check.
fn proof(app: &DesktopApp, action: OwnerAction) -> OwnerProof {
    let epoch = app.owner_ui.session.epoch().expect("unlocked");
    OwnerProof::issue_for_test(action, epoch, Instant::now())
}

/// A proof through the real gate and the passphrase.
fn checked_proof(app: &DesktopApp, action: OwnerAction) -> OwnerProof {
    app.owner_gate()
        .authorize(action, OwnerCheck::passphrase(PASS))
        .expect("owner check")
}

fn unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// The codes of the seed in the seconds around now. The test and the app read the clock
/// at different moments.
fn codes_near_now() -> Vec<String> {
    let totp = Totp::parse(SEED).expect("seed");
    let now = unix();
    (now - 2..=now + 2)
        .map(|time| totp.code_at(time).0)
        .collect()
}

fn assert_nothing_else_revealed(app: &DesktopApp, item_id: u64) {
    let session = &app.owner_ui.session;
    for field in [
        "password".to_owned(),
        detail_field_name("Recovery code"),
        detail_field_name(OTP_EIGHT),
    ] {
        assert_eq!(session.revealed_value(item_id, &field), None, "{field}");
    }
    let details = session.details(item_id).expect("details");
    assert!(!details.any_revealed(), "a shown code is not a reveal");
}

// ---- The actions and the requests. ----

#[test]
fn the_requests_name_the_item_and_the_field() {
    let field = otp_field();
    let request = OwnerRequest::ShowCode {
        item_id: 4,
        field: field.clone(),
    };
    assert_eq!(request.action(), show(4, &field));
    let request = OwnerRequest::CopyCode {
        item_id: 4,
        field: field.clone(),
    };
    assert_eq!(request.action(), copy(4, &field));
    assert_ne!(copy(4, &field), copy(4, &detail_field_name(OTP_EIGHT)));
    assert_ne!(copy(4, &field), copy(5, &field));
    assert_ne!(copy(4, &field), show(4, &field));
    assert_ne!(show(4, &field), OwnerAction::Reveal { item_id: 4 });
    // The dialog and the Touch ID prompt name the code, never a value.
    assert!(request.describe().contains("One-time password"));
    assert!(request.describe().contains("clears the clipboard"));
    assert_eq!(request.action().reason(), "copy a one-time code");
    assert_eq!(show(4, &field).reason(), "show a one-time code");
}

// ---- Show code. ----

#[test]
fn show_code_opens_the_seed_of_one_field_only() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, _) = app_with_login(&dir);
    let field = otp_field();
    let proof = checked_proof(&app, show(item_id, &field));
    app.owner_ui
        .session
        .reveal_one_code_seed(item_id, &field, proof)
        .expect("show code");
    let session = &app.owner_ui.session;
    assert_eq!(session.code_seed(item_id, &field), Some(SEED));
    // The seed is not in the cache of generic reveals.
    assert_eq!(session.revealed_value(item_id, &field), None);
    assert_nothing_else_revealed(&app, item_id);

    app.owner_ui.session.hide_code(item_id, &field);
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);
    assert_eq!(app.owner_ui.session.revealed_value(item_id, &field), None);
}

#[test]
fn show_code_through_the_owner_check_dialog() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, board) = app_with_login(&dir);
    let field = otp_field();
    app.ask_owner(
        OwnerRequest::ShowCode {
            item_id,
            field: field.clone(),
        },
        None,
    );
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), Some(SEED));
    assert_nothing_else_revealed(&app, item_id);
    assert!(!app.status_text.contains(SEED), "{}", app.status_text);
    // A show never writes the clipboard.
    assert_eq!(board.with(|b| b.writes), 0);
}

#[test]
fn a_proof_for_another_field_item_or_action_shows_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, _) = app_with_login(&dir);
    let field = otp_field();
    let wrong = [
        show(item_id, &detail_field_name(OTP_EIGHT)),
        show(item_id + 1, &field),
        copy(item_id, &field),
        OwnerAction::Reveal { item_id },
    ];
    for action in wrong {
        let proof = proof(&app, action.clone());
        let err = app
            .owner_ui
            .session
            .reveal_one_code_seed(item_id, &field, proof)
            .expect_err("wrong action");
        assert_eq!(err.code, "owner_check_required", "{action:?}");
        assert!(err.message.contains("another action"), "{}", err.message);
    }
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);
    assert_nothing_else_revealed(&app, item_id);
}

#[test]
fn a_code_proof_cannot_open_the_password_or_another_hidden_detail() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, board) = app_with_login(&dir);
    for field in [
        "password".to_owned(),
        detail_field_name("Recovery code"),
        // An OTP label that the item does not have.
        detail_field_name("OTP"),
        "x_zz".to_owned(),
    ] {
        let shown = proof(&app, show(item_id, &field));
        let err = app
            .owner_ui
            .session
            .reveal_one_code_seed(item_id, &field, shown)
            .expect_err("not a one-time password");
        assert_eq!(err.code, "invalid_input", "{field}");
        let copied = proof(&app, copy(item_id, &field));
        let err = app
            .owner_ui
            .session
            .copy_code(item_id, &field, copied)
            .expect_err("not a one-time password");
        assert_eq!(err.code, "invalid_input", "{field}");
        assert!(!err.message.contains(PASSWORD) && !err.message.contains(RECOVERY));
        assert_eq!(app.owner_ui.session.revealed_value(item_id, &field), None);
    }
    assert_nothing_else_revealed(&app, item_id);
    assert_eq!(board.with(|b| b.writes), 0);
}

#[test]
fn a_stale_proof_or_a_proof_of_an_earlier_session_is_refused() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, _) = app_with_login(&dir);
    let field = otp_field();
    let epoch = app.owner_ui.session.epoch().expect("unlocked");
    let old = Instant::now()
        .checked_sub(PROOF_LIFETIME + Duration::from_secs(1))
        .expect("old instant");
    let stale = OwnerProof::issue_for_test(show(item_id, &field), epoch, old);
    let err = app
        .owner_ui
        .session
        .reveal_one_code_seed(item_id, &field, stale)
        .expect_err("stale");
    assert!(err.message.contains("too old"), "{}", err.message);
    let stale = OwnerProof::issue_for_test(copy(item_id, &field), epoch, old);
    let err = app
        .owner_ui
        .session
        .copy_code(item_id, &field, stale)
        .expect_err("stale");
    assert!(err.message.contains("too old"), "{}", err.message);

    // A proof from before a lock and an unlock belongs to another session.
    let before = proof(&app, copy(item_id, &field));
    app.owner_ui.session.lock().expect("lock");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let err = app
        .owner_ui
        .session
        .copy_code(item_id, &field, before)
        .expect_err("other session");
    assert!(err.message.contains("locked after"), "{}", err.message);
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);
}

#[test]
fn a_shown_seed_expires_and_goes_at_hide_lock_and_change() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, _) = app_with_login(&dir);
    let field = otp_field();
    let open = |app: &mut DesktopApp| {
        let proof = proof(app, show(item_id, &field));
        app.owner_ui
            .session
            .reveal_one_code_seed(item_id, &field, proof)
            .expect("show code");
        assert!(app.owner_ui.session.code_seed(item_id, &field).is_some());
    };

    open(&mut app);
    let left = app.owner_ui.session.next_reveal_expiry().expect("expiry");
    assert!(left <= REVEAL_TIME);
    app.owner_ui
        .session
        .expire_reveals_at(Instant::now() + REVEAL_TIME);
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);
    assert_eq!(app.owner_ui.session.next_reveal_expiry(), None);

    open(&mut app);
    app.owner_ui.session.hide(item_id).expect("hide");
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);

    open(&mut app);
    app.lock_vault(None);
    app.owner_ui.session.unlock(PASS).expect("unlock");
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);

    open(&mut app);
    app.owner_ui.session.archive(item_id).expect("archive");
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);
}

// ---- Copy code. ----

#[test]
fn the_copied_code_follows_rfc_6238_and_the_seed_stays_inside() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, _) = app_with_login(&dir);
    let field = otp_field();
    let proof = proof(&app, copy(item_id, &field));
    let code = app
        .owner_ui
        .session
        .copy_code_at(item_id, &field, proof, 59)
        .expect("copy");
    // RFC 6238 appendix B, SHA-1, at 59 seconds, in 6 digits.
    assert_eq!(code.digits.as_str(), "287082");
    assert_eq!(code.left, 1);
    let shown = format!("{code:?}");
    assert!(
        !shown.contains("287082") && shown.contains("redacted"),
        "{shown}"
    );

    // The link with 8 digits.
    let eight = detail_field_name(OTP_EIGHT);
    let proof = self::proof(&app, copy(item_id, &eight));
    let code = app
        .owner_ui
        .session
        .copy_code_at(item_id, &eight, proof, 1_111_111_109)
        .expect("copy");
    assert_eq!(code.digits.as_str(), "07081804");

    // A copy opens no seed for the view and reveals nothing else.
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), None);
    assert_eq!(app.owner_ui.session.revealed_value(item_id, &field), None);
    assert_nothing_else_revealed(&app, item_id);
}

#[test]
fn copy_code_writes_the_code_only_and_clears_it_at_lock() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, board) = app_with_login(&dir);
    let field = otp_field();
    app.ask_owner(
        OwnerRequest::CopyCode {
            item_id,
            field: field.clone(),
        },
        None,
    );
    // Nothing before the check.
    assert_eq!(board.with(|b| b.writes), 0);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let copied = board.text().expect("the clipboard has the code");
    assert!(codes_near_now().contains(&copied), "not a current code");
    assert!(board.with(|b| b.concealed));
    assert_ne!(copied, SEED);
    assert!(app.owner.clipboard.is_pending());
    assert!(app.status_text.contains("copied"), "{}", app.status_text);
    assert!(!app.status_text.contains(&copied));
    assert_nothing_else_revealed(&app, item_id);

    // The lock clears the code and ends the buffer.
    app.lock_vault(None);
    assert_eq!(board.text(), None);
    assert!(!app.owner.clipboard.is_pending());
}

#[test]
fn a_wrong_field_copy_writes_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, board) = app_with_login(&dir);
    app.ask_owner(
        OwnerRequest::CopyCode {
            item_id,
            field: "password".to_owned(),
        },
        None,
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(board.with(|b| b.writes), 0);
    assert!(!app.owner.clipboard.is_pending());
    assert!(
        app.status_text.contains("not a one-time password"),
        "{}",
        app.status_text
    );
    assert!(!app.status_text.contains(PASSWORD));
}

#[test]
fn each_copy_needs_its_own_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, board) = app_with_login(&dir);
    let field = otp_field();
    let request = OwnerRequest::CopyCode {
        item_id,
        field: field.clone(),
    };
    app.ask_owner(request.clone(), None);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(board.with(|b| b.writes), 1);
    // The proof went with the copy: no dialog is open, and a new copy asks again.
    assert!(app.owner.check.is_none());
    app.ask_owner(request, None);
    assert_eq!(board.with(|b| b.writes), 1);
    app.close_owner_check(None);
    assert_eq!(board.with(|b| b.writes), 1);
    // A wrong passphrase makes no proof and no copy.
    app.ask_owner(
        OwnerRequest::CopyCode {
            item_id,
            field: field.clone(),
        },
        None,
    );
    assert!(
        app.confirm_owner_now(OwnerCheck::passphrase("not-the-passphrase"))
            .is_err()
    );
    assert_eq!(board.with(|b| b.writes), 1);
}

#[test]
fn the_frame_poll_clears_at_the_time_and_keeps_a_newer_copy() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, board) = app_with_login(&dir);
    let field = otp_field();
    let ctx = egui::Context::default();
    let epoch = app.owner_ui.session.epoch().expect("unlocked");

    // A copy whose time has come is cleared by the next frame.
    let proof = proof(&app, copy(item_id, &field));
    let code = app
        .owner_ui
        .session
        .copy_code(item_id, &field, proof)
        .expect("copy");
    let past = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .expect("past");
    app.owner
        .clipboard
        .copy(code.digits, code.left, epoch, past)
        .expect("copy");
    assert!(board.text().is_some());
    app.poll_owner_flows(&ctx);
    assert_eq!(board.text(), None);

    // The owner copied something else: the frame keeps it.
    let proof = self::proof(&app, copy(item_id, &field));
    let code = app
        .owner_ui
        .session
        .copy_code(item_id, &field, proof)
        .expect("copy");
    app.owner
        .clipboard
        .copy(code.digits, code.left, epoch, past)
        .expect("copy");
    board.other_app_writes("a note of the owner");
    app.poll_owner_flows(&ctx);
    assert_eq!(board.text().as_deref(), Some("a note of the owner"));
    assert!(!app.owner.clipboard.is_pending());
}

#[test]
fn a_lock_outside_the_app_flow_clears_at_the_next_frame() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id, board) = app_with_login(&dir);
    let field = otp_field();
    let ctx = egui::Context::default();
    app.ask_owner(
        OwnerRequest::CopyCode {
            item_id,
            field: field.clone(),
        },
        None,
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(board.text().is_some());
    // A frame before the time keeps the code.
    app.poll_owner_flows(&ctx);
    assert!(board.text().is_some());
    // The session ends without `lock_vault` (a switch or a sync reopen does this).
    app.owner_ui.session.lock().expect("lock");
    app.poll_owner_flows(&ctx);
    assert_eq!(board.text(), None);
    assert!(!app.owner.clipboard.is_pending());
}
