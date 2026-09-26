#![cfg(all(feature = "desktop", feature = "vault"))]

//! Owner authentication with a fake native helper (goal items A2, A3, A4).
//!
//! The fake answers like the Swift helper: success, cancel, `biometry_changed`,
//! `keychain_unavailable`, and `not_available`. On the development Mac, the real
//! keychain helper answers `keychain_unavailable` (no provisioning profile), and Touch
//! ID answers `not_available` (the keyboard is not paired). A real Touch ID prompt is
//! in the owner checklist in `docs/operations/native-app.md`. All data is synthetic.

#[path = "support/fake_native.rs"]
mod fake_native;

use std::path::PathBuf;

use apassy::broker::approvals::{OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate};
use apassy::desktop::owner_store::OwnerSession;
use apassy::desktop::unlock::{
    self, BIOMETRY_CHANGED_NOTE, HELPER_MISSING_NOTE, KEYCHAIN_UNAVAILABLE_NOTE, SetupError,
    TouchIdUnlockError, UNLOCK_REASON, UnlockMethod,
};
use apassy::native::{KEYCHAIN_SERVICE, NativeHelper, vault_unlock_account};
use fake_native::{FakeNative, base64};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASS: &str = "owner-auth-pass-ok";
const WRONG: &str = "owner-auth-pass-no";

/// A locked vault file and its canonical path.
fn vault(dir: &TempDir) -> (OwnerSession, PathBuf) {
    let mut session = OwnerSession::new();
    session
        .create_file(&dir.path().join("auth.db"), PASS)
        .expect("create");
    let path = session.vault_path().expect("canonical path");
    (session, path)
}

fn exists(found: bool, changed: bool) -> String {
    format!(r#"{{"ok":true,"exists":{found},"biometry_changed":{changed}}}"#)
}

/// A2: the keychain item is the source of truth. The app reads it before unlock,
/// without a prompt, for the account of this vault file.
#[test]
fn unlock_setting_comes_from_the_keychain_item() {
    let dir = TempDir::new().expect("temp dir");
    let (session, path) = vault(&dir);
    assert!(session.is_locked(), "the setting is read before unlock");
    let fake = FakeNative::new("setting");
    let helper = fake.helper();

    fake.respond("keychain_exists", &exists(true, false));
    let setting = unlock::read_setting(&helper, &path);
    assert_eq!(setting.method, UnlockMethod::TouchId);
    assert_eq!(setting.note, None);
    let request = &fake.requests_for("keychain_exists")[0];
    assert_eq!(request["account"], vault_unlock_account(&path));

    fake.respond("keychain_exists", &exists(false, false));
    let setting = unlock::read_setting(&helper, &path);
    assert_eq!(setting.method, UnlockMethod::Passphrase);
    assert!(setting.can_set_up);

    // No provisioning profile: passphrase unlock, with the explanation.
    fake.fail("keychain_exists", "keychain_unavailable");
    let setting = unlock::read_setting(&helper, &path);
    assert_eq!(setting.method, UnlockMethod::Passphrase);
    assert!(!setting.can_set_up);
    assert_eq!(setting.note.as_deref(), Some(KEYCHAIN_UNAVAILABLE_NOTE));
    assert!(KEYCHAIN_UNAVAILABLE_NOTE.contains(
        "Touch ID can confirm actions, but cannot unlock the vault until the app has a provisioning profile"
    ));

    // A build without the helper (for example `cargo run`).
    let missing = dir.path().join("no-helper");
    let setting = unlock::read_setting(&NativeHelper::with_paths(&missing, &missing), &path);
    assert_eq!(setting.method, UnlockMethod::Passphrase);
    assert_eq!(setting.note.as_deref(), Some(HELPER_MISSING_NOTE));
    assert!(fake.requests_for("keychain_delete").is_empty());
}

/// A3: after a fingerprint change, the setting falls back to the passphrase and the
/// stale item is deleted, without a prompt.
#[test]
fn biometry_change_removes_the_stale_item() {
    let dir = TempDir::new().expect("temp dir");
    let (_session, path) = vault(&dir);
    let fake = FakeNative::new("changed");
    fake.respond("keychain_exists", &exists(true, true));
    fake.respond("keychain_delete", r#"{"ok":true,"deleted":true}"#);
    let setting = unlock::read_setting(&fake.helper(), &path);
    assert_eq!(setting.method, UnlockMethod::Passphrase);
    assert_eq!(setting.note.as_deref(), Some(BIOMETRY_CHANGED_NOTE));
    let deleted = fake.requests_for("keychain_delete");
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["account"], vault_unlock_account(&path));
    assert!(fake.requests_for("keychain_read").is_empty(), "no prompt");

    // At unlock time: the helper answers `biometry_changed` without a prompt.
    fake.fail("keychain_read", "biometry_changed");
    let err = unlock::read_unlock_key(&fake.helper(), &path).unwrap_err();
    assert_eq!(err, TouchIdUnlockError::BiometryChanged);
    assert!(err.message().contains("Unlock with the passphrase"));
    assert_eq!(fake.requests_for("keychain_delete").len(), 2);
}

/// A2: setup needs the unlocked vault and the correct passphrase now. Apassy stores the
/// passphrase through `keychain_store` for this vault file only.
#[test]
fn touch_id_setup_needs_the_passphrase() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, path) = vault(&dir);
    let fake = FakeNative::new("setup");
    let helper = fake.helper();
    fake.respond(
        "keychain_store",
        r#"{"ok":true,"access_group":"TEAMID.com.wydrox.apassy"}"#,
    );
    let vault = session.shared_vault();
    let typed = |text: &str| Zeroizing::new(text.to_owned());

    assert_eq!(
        unlock::turn_on(&helper, &vault, typed(PASS)),
        Err(SetupError::VaultLocked)
    );
    session.unlock(PASS).expect("unlock");
    assert_eq!(
        unlock::turn_on(&helper, &vault, typed("")),
        Err(SetupError::EmptyPassphrase)
    );
    assert_eq!(
        unlock::turn_on(&helper, &vault, typed(WRONG)),
        Err(SetupError::WrongPassphrase)
    );
    assert!(
        fake.requests_for("keychain_store").is_empty(),
        "no store without the passphrase"
    );

    unlock::turn_on(&helper, &vault, typed(PASS)).expect("setup");
    let stored = fake.requests_for("keychain_store");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0]["account"], vault_unlock_account(&path));
    assert_eq!(stored[0]["secret_b64"], base64(PASS.as_bytes()));

    // No provisioning profile: setup fails with the explanation. Passphrase unlock stays.
    fake.fail("keychain_store", "keychain_unavailable");
    let err = unlock::turn_on(&helper, &vault, typed(PASS)).unwrap_err();
    assert_eq!(err, SetupError::KeychainUnavailable);
    assert!(
        err.message()
            .contains("cannot unlock the vault until the app has a provisioning profile")
    );

    // The Touch ID keyboard is not paired.
    fake.fail("keychain_store", "not_available");
    let err = unlock::turn_on(&helper, &vault, typed(PASS)).unwrap_err();
    assert!(matches!(err, SetupError::TouchIdUnavailable(_)), "{err:?}");
    assert!(
        err.message().contains("not connected or not paired"),
        "{}",
        err.message()
    );
}

/// A3: unlock with the key from `keychain_read`. The prompt text is fixed.
#[test]
fn touch_id_unlock_success_cancel_and_unavailable() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, path) = vault(&dir);
    let fake = FakeNative::new("unlock");
    let helper = fake.helper();

    fake.respond(
        "keychain_read",
        &format!(
            r#"{{"ok":true,"secret_b64":"{}"}}"#,
            base64(PASS.as_bytes())
        ),
    );
    let key = unlock::read_unlock_key(&helper, &path).expect("key");
    session
        .unlock(&key)
        .expect("unlock with the key from the keychain");
    drop(key);
    assert!(!session.is_locked());
    let read = &fake.requests_for("keychain_read")[0];
    assert_eq!(read["reason"], UNLOCK_REASON);
    assert_eq!(read["account"], vault_unlock_account(&path));
    session.lock().expect("lock");

    fake.fail("keychain_read", "cancelled");
    let err = unlock::read_unlock_key(&helper, &path).unwrap_err();
    assert_eq!(err, TouchIdUnlockError::Cancelled);
    assert!(err.message().contains("passphrase"));
    assert!(session.is_locked());

    fake.fail("keychain_read", "fallback");
    assert_eq!(
        unlock::read_unlock_key(&helper, &path).unwrap_err(),
        TouchIdUnlockError::UsePassphrase
    );

    fake.fail("keychain_read", "keychain_unavailable");
    assert_eq!(
        unlock::read_unlock_key(&helper, &path).unwrap_err(),
        TouchIdUnlockError::Unavailable(KEYCHAIN_UNAVAILABLE_NOTE.to_owned())
    );

    fake.fail("keychain_read", "not_available");
    let err = unlock::read_unlock_key(&helper, &path).unwrap_err();
    assert!(
        err.message().contains("not connected or not paired"),
        "{}",
        err.message()
    );

    fake.fail("keychain_read", "not_found");
    assert_eq!(
        unlock::read_unlock_key(&helper, &path).unwrap_err(),
        TouchIdUnlockError::NotSetUp
    );
    assert!(session.is_locked(), "no failure unlocks the vault");
    assert!(
        fake.requests_for("keychain_delete").is_empty(),
        "only a fingerprint change or a stale key deletes the item"
    );
}

/// A3: a stored key that does not open the vault (for example after a passphrase
/// change) is deleted. Turning Touch ID off deletes the item.
#[test]
fn stale_key_and_turn_off_delete_the_item() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, path) = vault(&dir);
    let fake = FakeNative::new("stale");
    let helper = fake.helper();
    fake.respond(
        "keychain_read",
        &format!(
            r#"{{"ok":true,"secret_b64":"{}"}}"#,
            base64(WRONG.as_bytes())
        ),
    );
    fake.respond("keychain_delete", r#"{"ok":true,"deleted":true}"#);
    let key = unlock::read_unlock_key(&helper, &path).expect("key");
    let err = session.unlock(&key).expect_err("stale key");
    assert_eq!(err.code, "wrong_key");
    assert_eq!(
        unlock::forget_stale_key(&helper, &path),
        TouchIdUnlockError::StaleKey
    );
    assert_eq!(fake.requests_for("keychain_delete").len(), 1);

    assert_eq!(unlock::turn_off(&helper, &path), Ok(true));
    let deletes = fake.requests_for("keychain_delete");
    assert_eq!(deletes.len(), 2);
    assert_eq!(deletes[1]["account"], vault_unlock_account(&path));
    assert!(fake.requests_for("keychain_store").is_empty());
    assert_eq!(KEYCHAIN_SERVICE, "com.wydrox.apassy.vault-unlock");
}

/// A4: Touch ID through the gate. Success gives a proof. Cancel, fallback, and
/// `not_available` give no proof and keep the passphrase path open.
#[test]
fn gate_touch_id_success_cancel_and_not_available() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _path) = vault(&dir);
    session.unlock(PASS).expect("unlock");
    let fake = FakeNative::new("gate");
    let gate = OwnerGate::new(session.shared_vault(), Some(fake.helper()));
    let action = OwnerAction::RotateToken { agent_id: 7 };

    fake.respond("authenticate", r#"{"ok":true}"#);
    let proof = gate
        .authorize(action.clone(), OwnerCheck::TouchId)
        .expect("Touch ID proof");
    assert_eq!(proof.action(), &action);
    let request = &fake.requests_for("authenticate")[0];
    assert_eq!(request["reason"], "give an agent a new token");

    for (code, expected) in [
        ("cancelled", OwnerAuthError::TouchIdCancelled),
        ("fallback", OwnerAuthError::PassphraseRequested),
        ("failed", OwnerAuthError::TouchIdFailed),
    ] {
        fake.fail("authenticate", code);
        let err = gate
            .authorize(action.clone(), OwnerCheck::TouchId)
            .unwrap_err();
        assert_eq!(err, expected);
        assert!(err.passphrase_fallback());
    }

    // The development Mac: the Touch ID keyboard is not paired.
    fake.fail("authenticate", "not_available");
    let err = gate
        .authorize(action.clone(), OwnerCheck::TouchId)
        .unwrap_err();
    assert!(err.passphrase_fallback());
    let message = err.message();
    assert!(
        message.starts_with("Touch ID is not available"),
        "{message}"
    );
    assert!(message.contains("not connected or not paired"), "{message}");
    assert!(message.contains("Type the passphrase"), "{message}");

    // The passphrase fallback works while Touch ID is not available.
    gate.authorize(action.clone(), OwnerCheck::passphrase(PASS))
        .expect("passphrase proof");
    assert_eq!(
        gate.authorize(action, OwnerCheck::passphrase(WRONG))
            .unwrap_err(),
        OwnerAuthError::WrongPassphrase
    );
}

/// A4: a lock during the Touch ID check ends the session, so the gate gives no proof.
#[test]
fn gate_refuses_when_the_vault_locks_during_the_check() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _path) = vault(&dir);
    session.unlock(PASS).expect("unlock");
    // A slow helper stands in for the owner at the Touch ID prompt. A second thread
    // locks the vault during the wait.
    let slow = FakeNative::new("relock");
    let script = r#"#!/bin/sh
IFS= read -r line
sleep 1
printf '%s\n' '{"ok":true}'
"#;
    std::fs::write(slow.helper().helper_path(), script).expect("slow helper");
    let gate = OwnerGate::new(session.shared_vault(), Some(slow.helper()));
    let vault = session.shared_vault();
    let locker = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        vault
            .lock()
            .expect("vault")
            .as_mut()
            .expect("open")
            .lock()
            .expect("lock");
    });
    let err = gate
        .authorize(OwnerAction::Reveal { item_id: 1 }, OwnerCheck::TouchId)
        .unwrap_err();
    locker.join().expect("locker");
    assert_eq!(err, OwnerAuthError::SessionChanged);
}
