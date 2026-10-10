//! The controller of browser passkeys, browser one-time codes, and the macOS passkey
//! sheet: checks before the dialog, the proof binding, the hang-up of the peer, and the
//! answers. A real vault signs and makes the passkeys, and the tests verify the
//! signatures. Synthetic values only: `example.com` relying parties, the SHA-1 seed of
//! RFC 6238 appendix B, and no real browser, vault, or clipboard.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::DesktopApp;
use super::model::{DetailDraft, ItemDraft};
use super::owner_check::OwnerRequest;
use super::owner_socket::{self, Envelope, LineWire, PeerGone};
use super::owner_store::{SecretForm, detail_field_name};
use super::passkey_socket::{Out, PeerRule, PlatformEvent, PlatformTicket, read_bridge};
use crate::broker::approvals::{OwnerAction, OwnerCheck, OwnerProof};
use crate::browser::site::Page;
use crate::browser::webauthn::encode_bytes;
use crate::browser::wire::{
    Command, Data, PasskeyCreateRequest, PasskeyGetRequest, Response, VaultState,
};
use crate::contracts::CredentialKind;
use crate::otp::Totp;
use crate::vault::passkey::b64url_encode;
use crate::vault::{PasskeyCreate, PasskeyCreated, PasskeyTarget};

const PASS: &str = "passkey-controller-pass";
const RID: &str = "0f8f2b52-1a3c-4d2e-9b1a-3c4d5e6f7a8b";
const OTHER_RID: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const ORIGIN: &str = "https://login.example.com";
const RP: &str = "example.com";
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD: &str = "passkey-controller-password-canary";
const OTP: &str = "One-time password";

// ---- Helpers. ----

fn unlocked_app(dir: &TempDir) -> DesktopApp {
    let mut app = DesktopApp::new();
    let session = &mut app.owner_ui.session;
    session
        .create_file(&dir.path().join("passkeys.db"), PASS)
        .expect("create");
    if session.is_locked() {
        session.unlock(PASS).expect("unlock");
    }
    app
}

fn client_json(kind: &str, origin: &str) -> String {
    let challenge = b64url_encode(&[0x5au8; 32]);
    format!(
        r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
}

fn get_request(allowed: &[&[u8]]) -> PasskeyGetRequest {
    PasskeyGetRequest {
        rid: RID.to_owned(),
        origin: ORIGIN.to_owned(),
        rp_id: RP.to_owned(),
        client_data_json: encode_bytes(client_json("webauthn.get", ORIGIN).as_bytes()),
        allowed: allowed.iter().map(|id| encode_bytes(id)).collect(),
    }
}

fn create_request(user_name: &str, excluded: &[&[u8]], algorithms: &[i64]) -> PasskeyCreateRequest {
    PasskeyCreateRequest {
        rid: RID.to_owned(),
        origin: ORIGIN.to_owned(),
        rp_id: RP.to_owned(),
        client_data_json: encode_bytes(client_json("webauthn.create", ORIGIN).as_bytes()),
        user_handle: encode_bytes(b"user-handle-1"),
        user_name: user_name.to_owned(),
        user_display_name: "Ada Example".to_owned(),
        algorithms: algorithms.to_vec(),
        excluded: excluded.iter().map(|id| encode_bytes(id)).collect(),
        title: "Example".to_owned(),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// A passkey made by the vault itself, in a new login.
fn add_passkey(app: &DesktopApp, user_name: &str, title: &str) -> PasskeyCreated {
    let handle = format!("handle-{user_name}");
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault.create_passkey(PasskeyCreate {
                rp_id: RP,
                user_handle: handle.as_bytes(),
                user_name,
                user_display_name: user_name,
                client_data_hash: &[1u8; 32],
                algorithms: &[-7],
                exclude: &[],
                target: PasskeyTarget::NewItem {
                    title: title.to_owned(),
                },
            })
        })
        .expect("open vault")
        .expect("create passkey")
}

fn ask(app: &mut DesktopApp, ctx: &egui::Context, command: Command) -> Receiver<Response> {
    let (reply, answer) = mpsc::channel();
    app.handle_browser(
        Envelope {
            request: command,
            reply,
        },
        ctx,
    );
    answer
}

fn ask_watched(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    command: Command,
) -> (Receiver<Response>, PeerGone) {
    let (reply, answer) = mpsc::channel();
    let gone = PeerGone::default();
    app.handle_browser_watched(
        Envelope {
            request: command,
            reply,
        },
        Some(gone.clone()),
        ctx,
    );
    (answer, gone)
}

fn now(answer: &Receiver<Response>) -> Response {
    answer.try_recv().expect("an answer")
}

/// The action of the open dialog.
fn dialog_action(app: &DesktopApp) -> OwnerAction {
    app.owner
        .check
        .as_ref()
        .expect("an owner check is open")
        .request
        .action()
}

/// A fresh proof of this session for `action`, without the cost of a passphrase check.
fn fresh_proof(app: &DesktopApp, action: OwnerAction) -> OwnerProof {
    let epoch = app.owner_ui.session.epoch().expect("unlocked");
    OwnerProof::issue_for_test(action, epoch, Instant::now())
}

/// Finish the open dialog with a proof for exactly its action.
fn confirm(app: &mut DesktopApp) {
    let action = dialog_action(app);
    let proof = fresh_proof(app, action);
    app.finish_owner_check_with(proof);
}

fn verify_assertion(spki: &[u8], data: &Value, client: &[u8]) {
    let decode = |name: &str| {
        crate::browser::webauthn::decode_bytes(data[name].as_str().expect(name), 1, 4096)
            .expect(name)
    };
    let authenticator_data = decode("authenticator_data");
    let signature = decode("signature");
    assert_eq!(&authenticator_data[..32], &sha256(RP.as_bytes()));
    // User presence and user verification: set after the owner check.
    assert_eq!(authenticator_data[32] & 0x05, 0x05);
    let mut message = authenticator_data.clone();
    message.extend_from_slice(&sha256(client));
    // The SPKI of P-256 is a 26-byte prefix and the uncompressed point.
    let key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        &spki[26..],
    );
    key.verify(&message, &signature)
        .expect("the signature verifies");
}

fn hidden(label: &str) -> DetailDraft {
    DetailDraft {
        label: label.to_owned(),
        value: String::new(),
        hidden: true,
        stored: None,
    }
}

fn visible(label: &str, value: &str) -> DetailDraft {
    DetailDraft {
        label: label.to_owned(),
        value: value.to_owned(),
        hidden: false,
        stored: None,
    }
}

/// A login for `website` with a password, a hidden recovery code, and a one-time
/// password with the label `otp_label` (or none).
fn add_code_login(app: &mut DesktopApp, website: &str, otp_label: Option<&str>, seed: &str) -> u64 {
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets.details[1] = "recovery-canary".to_owned();
    let mut details = vec![visible("Website", website), hidden("Recovery code")];
    if let Some(label) = otp_label {
        secrets.details[2] = seed.to_owned();
        details.push(hidden(label));
    }
    app.owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Example login".to_owned(),
                kind: CredentialKind::Login,
                username: "ada@example.com".to_owned(),
                details,
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add login")
        .id
}

fn codes_near_now(seed: &str) -> Vec<String> {
    let totp = Totp::parse(seed).expect("seed");
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    (unix - 2..=unix + 2).map(|t| totp.code_at(t).0).collect()
}

// ---- Browser assertion. ----

#[test]
fn a_browser_sign_in_checks_then_signs_a_valid_assertion() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let created = add_passkey(&app, "ada@example.com", "Example");
    let answer = ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    assert!(
        answer.try_recv().is_err(),
        "no answer before the owner check"
    );
    let action = dialog_action(&app);
    let OwnerAction::SignPasskey {
        origin,
        rid,
        rp_id,
        item_id,
        credential_id,
        client_data_hash,
    } = &action
    else {
        panic!("not a passkey action: {action:?}");
    };
    // The proof names the origin of the signed bytes, the request, the RP, the
    // credential, and the hash that the app computed.
    assert_eq!(origin.as_deref(), Some(ORIGIN));
    assert_eq!(rid, RID);
    assert_eq!(rp_id, RP);
    assert_eq!(*item_id, created.item_id);
    assert_eq!(credential_id, &created.credential_id);
    assert_eq!(
        client_data_hash,
        &sha256(client_json("webauthn.get", ORIGIN).as_bytes())
    );
    let dialog = app.owner.check.as_ref().unwrap();
    assert!(dialog.browser.is_some(), "the browser note shows");
    let text = dialog.request.describe();
    assert!(text.starts_with(&format!("For {ORIGIN}:")), "{text}");
    assert!(text.contains("ada@example.com"), "{text}");
    assert!(action.reason().contains("example.com"));

    confirm(&mut app);
    let response = now(&answer);
    assert!(response.ok, "{}: {}", response.code, response.message);
    let json = serde_json::to_value(&response).unwrap();
    let data = &json["data"];
    assert_eq!(data["type"], "passkey");
    assert_eq!(data["rid"], RID);
    assert_eq!(data["credential_id"], encode_bytes(&created.credential_id));
    assert_eq!(data["user_handle"], encode_bytes(b"handle-ada@example.com"));
    assert_eq!(
        data["client_data_json"],
        encode_bytes(client_json("webauthn.get", ORIGIN).as_bytes())
    );
    verify_assertion(
        &created.public_key_spki,
        data,
        client_json("webauthn.get", ORIGIN).as_bytes(),
    );
    assert!(app.browser_results_are_empty());
}

#[test]
fn no_passkey_answers_no_match_without_a_dialog() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let created = add_passkey(&app, "ada@example.com", "Example");
    // An allow list without the credential of the vault.
    let response = now(&ask(
        &mut app,
        &ctx,
        Command::PasskeyGet(get_request(&[b"another-credential"])),
    ));
    assert_eq!(response.code, "no_match");
    assert!(app.owner.check.is_none());
    // The allow list with it opens the dialog.
    let _answer = ask(
        &mut app,
        &ctx,
        Command::PasskeyGet(get_request(&[&created.credential_id])),
    );
    assert!(app.owner.check.is_some());
}

#[test]
fn bad_client_data_and_locked_vaults_answer_before_any_dialog() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    add_passkey(&app, "ada@example.com", "Example");
    // The client data names another origin than the browser gave.
    let mut forged = get_request(&[]);
    forged.client_data_json =
        encode_bytes(client_json("webauthn.get", "https://evil.example.org").as_bytes());
    assert_eq!(
        now(&ask(&mut app, &ctx, Command::PasskeyGet(forged))).code,
        "bad_request"
    );
    // A create type in a get.
    let mut wrong_type = get_request(&[]);
    wrong_type.client_data_json = encode_bytes(client_json("webauthn.create", ORIGIN).as_bytes());
    assert_eq!(
        now(&ask(&mut app, &ctx, Command::PasskeyGet(wrong_type))).code,
        "bad_request"
    );
    // A relying party of another site.
    let mut other_rp = get_request(&[]);
    other_rp.rp_id = "example.org".to_owned();
    assert!(!now(&ask(&mut app, &ctx, Command::PasskeyGet(other_rp))).ok);
    assert!(app.owner.check.is_none());
    app.owner_ui.session.lock().expect("lock");
    assert_eq!(
        now(&ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])))).code,
        "vault_locked"
    );
    assert!(app.owner.check.is_none());
}

#[test]
fn proofs_for_another_request_never_sign() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let created = add_passkey(&app, "ada@example.com", "Example");
    let other = add_passkey(&app, "bob@example.com", "Example 2");
    let hash = [7u8; 32];
    let exact = OwnerAction::SignPasskey {
        origin: Some(ORIGIN.to_owned()),
        rid: RID.to_owned(),
        rp_id: RP.to_owned(),
        item_id: created.item_id,
        credential_id: created.credential_id.clone(),
        client_data_hash: hash,
    };
    let change = |edit: &dyn Fn(&mut OwnerAction)| {
        let mut action = exact.clone();
        edit(&mut action);
        action
    };
    let wrong: Vec<(&str, OwnerAction)> = vec![
        (
            "rp",
            change(&|a| {
                if let OwnerAction::SignPasskey { rp_id, .. } = a {
                    *rp_id = "login.example.com".to_owned()
                }
            }),
        ),
        (
            "hash",
            change(&|a| {
                if let OwnerAction::SignPasskey {
                    client_data_hash, ..
                } = a
                {
                    client_data_hash[0] ^= 1
                }
            }),
        ),
        (
            "credential",
            change(&|a| {
                if let OwnerAction::SignPasskey { credential_id, .. } = a {
                    credential_id.clone_from(&other.credential_id)
                }
            }),
        ),
        (
            "item",
            change(&|a| {
                if let OwnerAction::SignPasskey { item_id, .. } = a {
                    *item_id = other.item_id
                }
            }),
        ),
        (
            "rid",
            change(&|a| {
                if let OwnerAction::SignPasskey { rid, .. } = a {
                    *rid = OTHER_RID.to_owned()
                }
            }),
        ),
        (
            "origin",
            change(&|a| {
                if let OwnerAction::SignPasskey { origin, .. } = a {
                    *origin = Some("https://example.com".to_owned())
                }
            }),
        ),
        // A proof for the macOS sheet never signs for the browser.
        (
            "caller",
            change(&|a| {
                if let OwnerAction::SignPasskey { origin, .. } = a {
                    *origin = None
                }
            }),
        ),
        (
            "fill",
            OwnerAction::FillLogin {
                item_id: created.item_id,
                login: "Example".to_owned(),
                origin: ORIGIN.to_owned(),
            },
        ),
        (
            "reveal",
            OwnerAction::Reveal {
                item_id: created.item_id,
            },
        ),
    ];
    for (what, action) in wrong {
        let proof = fresh_proof(&app, action);
        let err = app
            .owner_ui
            .session
            .sign_passkey(&exact, proof)
            .expect_err(what);
        assert_eq!(err.code, "owner_check_required", "{what}");
    }
    // A stale proof.
    let epoch = app.owner_ui.session.epoch().unwrap();
    let stale = OwnerProof::issue_for_test(
        exact.clone(),
        epoch,
        Instant::now() - crate::broker::approvals::PROOF_LIFETIME - Duration::from_secs(1),
    );
    assert!(app.owner_ui.session.sign_passkey(&exact, stale).is_err());
    // The exact proof signs.
    let proof = fresh_proof(&app, exact.clone());
    let signed = app
        .owner_ui
        .session
        .sign_passkey(&exact, proof)
        .expect("sign");
    assert_eq!(signed.credential_id, created.credential_id);
    // The values that sign come from the proof: an action with a credential of another
    // item cannot sign, even with a proof for exactly that action.
    let mixed = change(&|a| {
        if let OwnerAction::SignPasskey { credential_id, .. } = a {
            credential_id.clone_from(&other.credential_id);
        }
    });
    let proof = fresh_proof(&app, mixed.clone());
    assert_eq!(
        app.owner_ui
            .session
            .sign_passkey(&mixed, proof)
            .expect_err("mixed")
            .code,
        "not_found"
    );
}

#[test]
fn a_browser_that_hung_up_closes_the_dialog_and_gets_no_signature() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    add_passkey(&app, "ada@example.com", "Example");
    let (answer, gone) = ask_watched(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    let action = dialog_action(&app);
    gone.set();
    // A proof that arrives after the hang-up signs nothing.
    let proof = fresh_proof(&app, action.clone());
    app.finish_owner_check_with(proof);
    assert!(app.browser_results_are_empty());
    assert_eq!(now(&answer).code, "cancelled");

    // The frame after a hang-up closes the dialog, also with no owner action.
    let (answer, gone) = ask_watched(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    assert!(app.owner.check.is_some());
    gone.set();
    app.poll_browser(&ctx);
    assert!(app.owner.check.is_none(), "the dialog closes");
    assert_eq!(now(&answer).code, "cancelled");
    assert!(app.status_text.contains("cancelled"), "{}", app.status_text);
}

#[test]
fn a_deadline_or_a_lock_and_unlock_signs_nothing() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    add_passkey(&app, "ada@example.com", "Example");
    // The vault session changes while the dialog is open: the proof of the old session
    // is refused, and the browser gets no signature.
    let answer = ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    let action = dialog_action(&app);
    let old = fresh_proof(&app, action);
    app.owner_ui.session.lock().expect("lock");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app.finish_owner_check_with(old);
    let response = now(&answer);
    assert!(!response.ok);
    assert_eq!(response.code, "refused");
    assert!(app.browser_results_are_empty());

    // After the deadline the ticket is not live: a late proof signs nothing.
    let answer = ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    app.age_browser_check();
    confirm(&mut app);
    assert_eq!(now(&answer).code, "cancelled");
    assert!(app.browser_results_are_empty());

    // A lock in the app closes the dialog.
    let answer = ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    app.lock_vault(Some(&ctx));
    assert!(app.owner.check.is_none());
    assert_eq!(now(&answer).code, "cancelled");
}

#[test]
fn several_accounts_wait_for_a_choice_and_sign_the_chosen_one() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let ada = add_passkey(&app, "ada@example.com", "Ada");
    let bob = add_passkey(&app, "bob@example.com", "Bob");
    let answer = ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    let request = app.owner.check.as_ref().unwrap().request.clone();
    assert!(!request.is_ready(), "no account is chosen");
    assert!(!request.starts_touch_id(), "Touch ID waits for the choice");
    let text = request.describe();
    assert!(text.contains("Choose the account"), "{text}");
    // Nothing starts before the choice, and a proof for no account is never used.
    app.start_owner_check(OwnerCheck::TouchId, None);
    assert!(app.owner.check.as_ref().unwrap().running.is_none());
    app.choose_passkey(0);
    let text = app.owner.check.as_ref().unwrap().request.describe();
    assert!(text.contains("Other accounts"), "{text}");
    let first = dialog_action(&app);
    app.choose_passkey(1);
    let chosen = dialog_action(&app);
    assert_ne!(first, chosen);
    let OwnerAction::SignPasskey { credential_id, .. } = &chosen else {
        panic!("not a passkey action");
    };
    assert_eq!(credential_id, &bob.credential_id);
    // A proof for the account before the choice is refused.
    let stale_choice = fresh_proof(&app, first);
    app.finish_owner_check_with(stale_choice);
    assert_eq!(now(&answer).code, "refused");

    let answer = ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    app.choose_passkey(1);
    confirm(&mut app);
    let json = serde_json::to_value(now(&answer)).unwrap();
    assert_eq!(
        json["data"]["credential_id"],
        encode_bytes(&bob.credential_id)
    );
    verify_assertion(
        &bob.public_key_spki,
        &json["data"],
        client_json("webauthn.get", ORIGIN).as_bytes(),
    );
    assert_ne!(ada.credential_id, bob.credential_id);
}

// ---- Browser registration. ----

#[test]
fn a_browser_registration_makes_a_passkey_that_signs() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let answer = ask(
        &mut app,
        &ctx,
        Command::PasskeyCreate(create_request("ada@example.com", &[], &[-7, -257])),
    );
    let action = dialog_action(&app);
    let OwnerAction::CreatePasskey {
        origin,
        user_handle,
        user_name,
        excluded,
        target,
        ..
    } = &action
    else {
        panic!("not a create action");
    };
    assert_eq!(origin.as_deref(), Some(ORIGIN));
    assert_eq!(user_handle, b"user-handle-1");
    assert_eq!(user_name, "ada@example.com");
    assert!(excluded.is_empty());
    assert_eq!(
        target,
        &PasskeyTarget::NewItem {
            title: "Example".to_owned()
        }
    );
    confirm(&mut app);
    let json = serde_json::to_value(now(&answer)).unwrap();
    let data = &json["data"];
    assert_eq!(data["type"], "passkey_created", "{json}");
    assert_eq!(data["rid"], RID);
    assert_eq!(data["algorithm"], -7);
    let item = data["item"].as_u64().unwrap();
    let infos = app.owner_ui.session.passkeys_for(RP, &[]).unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].item_id, item);
    assert_eq!(data["credential_id"], encode_bytes(&infos[0].credential_id));
    let spki =
        crate::browser::webauthn::decode_bytes(data["public_key_spki"].as_str().unwrap(), 91, 91)
            .unwrap();

    // The new passkey signs for the browser.
    let answer = ask(&mut app, &ctx, Command::PasskeyGet(get_request(&[])));
    confirm(&mut app);
    let json = serde_json::to_value(now(&answer)).unwrap();
    verify_assertion(
        &spki,
        &json["data"],
        client_json("webauthn.get", ORIGIN).as_bytes(),
    );
}

#[test]
fn excluded_answers_only_after_the_check_and_unsupported_before_it() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let existing = add_passkey(&app, "ada@example.com", "Example");
    let answer = ask(
        &mut app,
        &ctx,
        Command::PasskeyCreate(create_request(
            "ada@example.com",
            &[&existing.credential_id],
            &[],
        )),
    );
    assert!(
        answer.try_recv().is_err(),
        "no answer before the owner check"
    );
    assert!(app.owner.check.is_some());
    confirm(&mut app);
    assert_eq!(now(&answer).code, "excluded");
    assert_eq!(app.owner_ui.session.passkeys_for(RP, &[]).unwrap().len(), 1);

    let response = now(&ask(
        &mut app,
        &ctx,
        Command::PasskeyCreate(create_request("ada@example.com", &[], &[-257, -8])),
    ));
    assert_eq!(response.code, "unsupported");
    assert!(app.owner.check.is_none());
}

#[test]
fn a_cancelled_registration_saves_nothing() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let (answer, gone) = ask_watched(
        &mut app,
        &ctx,
        Command::PasskeyCreate(create_request("ada@example.com", &[], &[])),
    );
    let action = dialog_action(&app);
    gone.set();
    let proof = fresh_proof(&app, action);
    app.finish_owner_check_with(proof);
    assert_eq!(now(&answer).code, "cancelled");
    assert!(
        app.owner_ui
            .session
            .passkeys_for(RP, &[])
            .unwrap()
            .is_empty()
    );
    assert!(
        app.owner_ui.session.search("").unwrap().is_empty(),
        "no login was made"
    );
}

#[test]
fn page_names_are_cleaned_for_the_dialog() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let mut request = create_request("ada\u{202e}moc.live", &[], &[]);
    request.user_display_name = "Ada\u{2066}\nExample".to_owned();
    request.title = "Bank\u{200f}".to_owned();
    let _answer = ask(&mut app, &ctx, Command::PasskeyCreate(request));
    let dialog = app.owner.check.as_ref().unwrap();
    let text = dialog.request.describe();
    assert!(text.starts_with(&format!("For {ORIGIN}:")), "{text}");
    for c in ['\u{202e}', '\u{2066}', '\u{200f}', '\n'] {
        assert!(!text.contains(c), "{text:?}");
    }
    let OwnerAction::CreatePasskey { user_name, .. } = dialog.request.action() else {
        panic!("not a create action");
    };
    assert_eq!(user_name, "adamoc.live");
}

#[test]
fn a_passkey_only_login_is_not_in_the_password_list_and_cannot_be_filled() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let answer = ask(
        &mut app,
        &ctx,
        Command::PasskeyCreate(create_request("ada@example.com", &[], &[])),
    );
    confirm(&mut app);
    let item = serde_json::to_value(now(&answer)).unwrap()["data"]["item"]
        .as_u64()
        .unwrap();
    // The passkey login gets the website of the page, so only the missing password
    // keeps it out of the list.
    let details = app.owner_ui.session.details(item).expect("details");
    let mut draft = details.to_draft();
    draft.website = ORIGIN.to_owned();
    app.owner_ui
        .session
        .update(item, details.revision, &draft, &SecretForm::default())
        .expect("a passkey login needs no password");
    let page = Page::parse(ORIGIN).unwrap();
    assert!(app.owner_ui.session.page_login(item, &page).is_err());
    let logins = now(&ask(
        &mut app,
        &ctx,
        Command::Logins {
            url: format!("{ORIGIN}/"),
        },
    ));
    let json = serde_json::to_value(&logins).unwrap();
    assert_eq!(
        json["data"]["logins"].as_array().unwrap().len(),
        0,
        "{json}"
    );
    let fill = now(&ask(
        &mut app,
        &ctx,
        Command::Fill {
            url: format!("{ORIGIN}/"),
            item,
        },
    ));
    assert_eq!(fill.code, "no_match");
    assert!(app.owner.check.is_none());
}

// ---- Browser one-time codes. ----

#[test]
fn a_code_fill_checks_the_site_and_returns_only_the_code() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let item = add_code_login(&mut app, "https://example.com", Some(OTP), SEED);
    let plain = add_code_login(&mut app, "https://example.com", None, SEED);
    // The list says which login has a code, and has no seed.
    let logins = now(&ask(
        &mut app,
        &ctx,
        Command::Logins {
            url: "https://example.com/login".to_owned(),
        },
    ));
    let json = serde_json::to_string(&logins).unwrap();
    assert!(!json.contains(SEED) && !json.contains(PASSWORD), "{json}");
    let rows: Value = serde_json::from_str(&json).unwrap();
    for row in rows["data"]["logins"].as_array().unwrap() {
        let id = row["item"].as_u64().unwrap();
        assert_eq!(row["has_totp"], json!(id == item), "{row}");
    }

    // Another site gets no dialog.
    let wrong_site = now(&ask(
        &mut app,
        &ctx,
        Command::FillCode {
            url: "https://evil.example.org/login".to_owned(),
            item,
            field: None,
        },
    ));
    assert_eq!(wrong_site.code, "no_match");
    // A login without a code, or a field that is not a code.
    let none = now(&ask(
        &mut app,
        &ctx,
        Command::FillCode {
            url: "https://example.com/login".to_owned(),
            item: plain,
            field: None,
        },
    ));
    assert_eq!(none.code, "no_code");
    let recovery = now(&ask(
        &mut app,
        &ctx,
        Command::FillCode {
            url: "https://example.com/login".to_owned(),
            item,
            field: Some("Recovery code".to_owned()),
        },
    ));
    assert_eq!(recovery.code, "no_code");
    assert!(app.owner.check.is_none());

    let answer = ask(
        &mut app,
        &ctx,
        Command::FillCode {
            url: "https://example.com/login".to_owned(),
            item,
            field: Some(OTP.to_owned()),
        },
    );
    assert_eq!(
        dialog_action(&app),
        OwnerAction::FillCode {
            item_id: item,
            field: detail_field_name(OTP),
            origin: "https://example.com".to_owned(),
        }
    );
    assert!(dialog_action(&app).reason().contains("example.com"));
    confirm(&mut app);
    let response = now(&answer);
    assert!(response.ok, "{}", response.message);
    let Data::Code {
        item: got,
        origin,
        code,
        remaining,
    } = &response.data
    else {
        panic!("not a code");
    };
    assert_eq!((*got, origin.as_str()), (item, "https://example.com"));
    assert!(codes_near_now(SEED).contains(&code.expose().to_owned()));
    assert!((1..=30).contains(remaining));
    let json = serde_json::to_string(&response).unwrap();
    assert!(!json.contains(SEED) && !json.contains(PASSWORD));
    assert!(!format!("{response:?}").contains(code.expose()));
    // A code is not a reveal of the item.
    assert!(!app.owner_ui.session.details(item).unwrap().any_revealed());
}

#[test]
fn a_code_proof_names_the_item_the_field_and_the_site() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let item = add_code_login(&mut app, "https://example.com", Some(OTP), SEED);
    let other = add_code_login(&mut app, "https://example.com", Some(OTP), SEED);
    let page = Page::parse("https://example.com/login").unwrap();
    let field = detail_field_name(OTP);
    let exact = OwnerAction::FillCode {
        item_id: item,
        field: field.clone(),
        origin: "https://example.com".to_owned(),
    };
    let wrong = [
        OwnerAction::FillCode {
            item_id: other,
            field: field.clone(),
            origin: "https://example.com".to_owned(),
        },
        OwnerAction::FillCode {
            item_id: item,
            field: detail_field_name("Recovery code"),
            origin: "https://example.com".to_owned(),
        },
        OwnerAction::FillCode {
            item_id: item,
            field: field.clone(),
            origin: "https://login.example.com".to_owned(),
        },
        // The proofs of the credential page never fill the browser.
        OwnerAction::CopyCode {
            item_id: item,
            field: field.clone(),
        },
        OwnerAction::ShowCode {
            item_id: item,
            field: field.clone(),
        },
        OwnerAction::FillLogin {
            item_id: item,
            login: "Example login".to_owned(),
            origin: "https://example.com".to_owned(),
        },
    ];
    for action in wrong {
        let proof = fresh_proof(&app, action.clone());
        let err = app
            .owner_ui
            .session
            .fill_code_at(item, &field, &page, proof, 59)
            .expect_err("wrong proof");
        assert_eq!(err.code, "owner_check_required", "{action:?}");
    }
    // RFC 6238 appendix B: SHA-1, T = 59, six digits.
    let proof = fresh_proof(&app, exact);
    let code = app
        .owner_ui
        .session
        .fill_code_at(item, &field, &page, proof, 59)
        .expect("code");
    assert_eq!(code.digits.as_str(), "287082");
    assert_eq!(code.left, 1);
    // A proof for another page of the site is refused even when the action matches it.
    let other_page = Page::parse("https://evil.example.org/").unwrap();
    let proof = fresh_proof(
        &app,
        OwnerAction::FillCode {
            item_id: item,
            field: field.clone(),
            origin: other_page.origin(),
        },
    );
    assert_eq!(
        app.owner_ui
            .session
            .fill_code_at(item, &field, &other_page, proof, 59)
            .expect_err("other site")
            .code,
        "no_match"
    );
}

#[test]
fn an_explicit_totp_link_under_another_label_is_a_code() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let link = format!("otpauth://totp/Example?secret={SEED}&digits=8");
    let item = add_code_login(
        &mut app,
        "https://example.com",
        Some("Authenticator"),
        &link,
    );
    let page = Page::parse("https://example.com/").unwrap();
    let code = app
        .owner_ui
        .session
        .page_code(item, &page, None)
        .expect("a code field");
    assert_eq!(code.field, detail_field_name("Authenticator"));
    let answer = ask(
        &mut app,
        &ctx,
        Command::FillCode {
            url: "https://example.com/".to_owned(),
            item,
            field: None,
        },
    );
    confirm(&mut app);
    let response = now(&answer);
    let Data::Code { code, .. } = &response.data else {
        panic!("not a code: {}", response.message);
    };
    assert_eq!(code.expose().len(), 8);
}

#[test]
fn a_code_for_a_browser_that_hung_up_is_never_made() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let item = add_code_login(&mut app, "https://example.com", Some(OTP), SEED);
    let (answer, gone) = ask_watched(
        &mut app,
        &ctx,
        Command::FillCode {
            url: "https://example.com/".to_owned(),
            item,
            field: None,
        },
    );
    gone.set();
    confirm(&mut app);
    assert_eq!(now(&answer).code, "cancelled");
    assert!(app.browser_results_are_empty());
}

// ---- The macOS passkey sheet. ----

/// A bridge request ID: a UUID as Foundation writes it.
fn rid(n: u64) -> String {
    format!("A1B2C3D4-0000-4000-8000-{n:012X}")
}

fn platform(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    id: u64,
    op: &str,
    args: Value,
) -> (Receiver<Out>, PeerGone) {
    let (ticket, cancel, lines) = PlatformTicket::for_test(&rid(id));
    app.handle_platform(op, args, ticket, ctx);
    (lines, cancel)
}

fn line(lines: &Receiver<Out>) -> Value {
    match lines.try_recv().expect("a line") {
        Out::Line(bytes) => serde_json::from_slice(&bytes).expect("json"),
        Out::Stop => panic!("stop"),
    }
}

#[test]
fn the_sheet_lists_metadata_and_signs_after_its_own_check() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let created = add_passkey(&app, "ada@example.com", "Example");
    let (lines, _) = platform(&mut app, &ctx, 1, "passkey_list", json!({ "rp_id": RP }));
    let list = line(&lines);
    assert_eq!(list["rid"], rid(1));
    assert_eq!(list["type"], "response");
    assert_eq!(list["result"]["ok"], true);
    let entry = &list["result"]["result"]["passkeys"][0];
    assert_eq!(entry["id"], created.item_id);
    assert_eq!(entry["credential_id"], encode_bytes(&created.credential_id));
    let keys: Vec<&String> = entry.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "credential_id",
            "id",
            "rp_id",
            "title",
            "user_display_name",
            "user_handle",
            "user_name"
        ]
    );
    assert!(app.owner.check.is_none(), "a list needs no check");

    let hash = [9u8; 32];
    let (lines, _) = platform(
        &mut app,
        &ctx,
        2,
        "passkey_assert",
        json!({
            "id": created.item_id,
            "rp_id": RP,
            "credential_id": encode_bytes(&created.credential_id),
            "client_data_hash": encode_bytes(&hash),
        }),
    );
    assert!(lines.try_recv().is_err(), "no answer before the check");
    let action = dialog_action(&app);
    let OwnerAction::SignPasskey {
        origin,
        rid: request_id,
        ..
    } = &action
    else {
        panic!("not a passkey action");
    };
    assert_eq!((origin, request_id), (&None, &rid(2)));
    let dialog = app.owner.check.as_ref().unwrap();
    assert!(dialog.browser.is_none(), "no browser note for the sheet");
    let text = dialog.request.describe();
    assert!(
        text.starts_with("macOS asks to sign in to example.com"),
        "{text}"
    );
    assert!(!text.contains("https://"), "{text}");
    // A browser proof for the same values cannot finish the request of the sheet.
    let browser_proof = fresh_proof(
        &app,
        OwnerAction::SignPasskey {
            origin: Some(ORIGIN.to_owned()),
            rid: rid(2),
            rp_id: RP.to_owned(),
            item_id: created.item_id,
            credential_id: created.credential_id.clone(),
            client_data_hash: hash,
        },
    );
    app.finish_owner_check_with(browser_proof);
    let refused = line(&lines);
    assert_eq!(refused["result"]["error"]["code"], "refused");

    let (lines, _) = platform(
        &mut app,
        &ctx,
        3,
        "passkey_assert",
        json!({
            "id": created.item_id,
            "rp_id": RP,
            "credential_id": encode_bytes(&created.credential_id),
            "client_data_hash": encode_bytes(&hash),
        }),
    );
    confirm(&mut app);
    let answer = line(&lines);
    assert_eq!(answer["rid"], rid(3));
    let result = &answer["result"]["result"];
    let decode = |name: &str| {
        crate::browser::webauthn::decode_bytes(result[name].as_str().unwrap(), 1, 4096).unwrap()
    };
    let mut message = decode("authenticator_data");
    message.extend_from_slice(&hash);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        &created.public_key_spki[26..],
    )
    .verify(&message, &decode("signature"))
    .expect("the signature verifies");
}

#[test]
fn the_sheet_cancel_closes_the_dialog_and_other_operations_are_refused() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let created = add_passkey(&app, "ada@example.com", "Example");
    let assert_args = json!({
        "id": created.item_id,
        "rp_id": RP,
        "credential_id": encode_bytes(&created.credential_id),
        "client_data_hash": encode_bytes(&[3u8; 32]),
    });
    let (lines, cancel) = platform(&mut app, &ctx, 5, "passkey_assert", assert_args.clone());
    cancel.set();
    app.expire_platform_check(&ctx);
    assert!(app.owner.check.is_none());
    assert_eq!(line(&lines)["result"]["error"]["code"], "cancelled");

    // A proof after the cancel signs nothing.
    let (lines, cancel) = platform(&mut app, &ctx, 6, "passkey_assert", assert_args.clone());
    cancel.set();
    confirm(&mut app);
    assert_eq!(line(&lines)["result"]["error"]["code"], "cancelled");
    assert!(app.browser_results_are_empty());

    // The deadline of the sheet closes the dialog.
    let (lines, _) = platform(&mut app, &ctx, 11, "passkey_assert", assert_args.clone());
    app.owner
        .check
        .as_mut()
        .and_then(|dialog| dialog.platform.as_mut())
        .expect("a sheet request")
        .age();
    app.expire_platform_check(&ctx);
    assert!(app.owner.check.is_none());
    assert_eq!(line(&lines)["result"]["error"]["code"], "cancelled");

    // No passkey of this item for another relying party: no dialog.
    let mut wrong = assert_args.clone();
    wrong["rp_id"] = json!("example.org");
    let (lines, _) = platform(&mut app, &ctx, 7, "passkey_assert", wrong);
    // The extension reads "not_found" (ProviderWire.swift).
    assert_eq!(line(&lines)["result"]["error"]["code"], "not_found");
    assert!(app.owner.check.is_none());

    for op in [
        "passkey_import",
        "passkey_remove",
        "passkey_export",
        "credential_export",
    ] {
        let (lines, _) = platform(&mut app, &ctx, 8, op, json!({}));
        assert_eq!(
            line(&lines)["result"]["error"]["code"],
            "unsupported",
            "{op}"
        );
    }
    // Unknown fields are refused, before any dialog.
    let mut extra = assert_args;
    extra["verified"] = json!(true);
    let (lines, _) = platform(&mut app, &ctx, 9, "passkey_assert", extra);
    assert_eq!(line(&lines)["result"]["error"]["code"], "bad_request");
    assert!(app.owner.check.is_none());

    app.owner_ui.session.lock().expect("lock");
    let (lines, _) = platform(&mut app, &ctx, 10, "passkey_list", json!({ "rp_id": RP }));
    assert_eq!(line(&lines)["result"]["error"]["code"], "locked");
}

#[test]
fn the_sheet_registers_a_passkey_after_the_check() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let args = json!({
        "rp_id": RP,
        "user_name": "ada@example.com",
        "user_display_name": "Ada",
        "user_handle": encode_bytes(b"uh"),
        "client_data_hash": encode_bytes(&[4u8; 32]),
        "algorithms": [-7],
        "excluded": [],
        "title": "Example",
    });
    let mut unsupported = args.clone();
    unsupported["algorithms"] = json!([-257]);
    let (lines, _) = platform(&mut app, &ctx, 1, "passkey_register", unsupported);
    assert_eq!(line(&lines)["result"]["error"]["code"], "unsupported");
    assert!(app.owner.check.is_none());

    let (lines, _) = platform(&mut app, &ctx, 2, "passkey_register", args);
    let OwnerAction::CreatePasskey { origin, .. } = dialog_action(&app) else {
        panic!("not a create action");
    };
    assert_eq!(origin, None);
    confirm(&mut app);
    let answer = line(&lines);
    let result = &answer["result"]["result"];
    let infos = app.owner_ui.session.passkeys_for(RP, &[]).unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(result["id"], infos[0].item_id);
    assert_eq!(
        result["credential_id"],
        encode_bytes(&infos[0].credential_id)
    );
    assert!(
        result["attestation_object"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

/// The registration of the sheet waits for the owner, who never answers. The frame hook
/// that eframe runs also for a hidden or covered window closes the dialog at the
/// deadline or at a cancel line, with no owner input. A proof that comes in after the
/// request ended saves no passkey and makes no login.
#[test]
fn an_ended_sheet_registration_closes_without_the_owner_and_saves_nothing() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let ctx = egui::Context::default();
    let args = json!({
        "rp_id": RP,
        "user_name": "ada@example.com",
        "user_display_name": "Ada",
        "user_handle": encode_bytes(b"uh"),
        "client_data_hash": encode_bytes(&[5u8; 32]),
        "algorithms": [-7],
        "excluded": [],
        "title": "Example",
    });
    let saved_nothing = |app: &DesktopApp| {
        assert!(
            app.owner_ui
                .session
                .passkeys_for(RP, &[])
                .unwrap()
                .is_empty()
        );
        assert!(
            app.owner_ui.session.search("").unwrap().is_empty(),
            "no login was made"
        );
    };
    let age = |app: &mut DesktopApp| {
        app.owner
            .check
            .as_mut()
            .and_then(|dialog| dialog.platform.as_mut())
            .expect("a sheet request")
            .age();
    };

    // The deadline passes: the next frame closes the dialog.
    let (lines, _) = platform(&mut app, &ctx, 21, "passkey_register", args.clone());
    app.poll_platform(&ctx);
    assert!(app.owner.check.is_some(), "a live request keeps its dialog");
    assert!(lines.try_recv().is_err(), "no answer before the deadline");
    age(&mut app);
    app.poll_platform(&ctx);
    assert!(app.owner.check.is_none());
    assert_eq!(line(&lines)["result"]["error"]["code"], "cancelled");
    saved_nothing(&app);

    // macOS cancels (the browser gave up): the next frame closes the dialog.
    let (lines, cancel) = platform(&mut app, &ctx, 22, "passkey_register", args.clone());
    cancel.set();
    app.poll_platform(&ctx);
    assert!(app.owner.check.is_none());
    assert_eq!(line(&lines)["result"]["error"]["code"], "cancelled");
    saved_nothing(&app);

    // A proof for a request whose deadline passed before any frame ran saves nothing.
    let (lines, _) = platform(&mut app, &ctx, 23, "passkey_register", args.clone());
    age(&mut app);
    confirm(&mut app);
    assert!(app.owner.check.is_none());
    assert_eq!(line(&lines)["result"]["error"]["code"], "cancelled");
    saved_nothing(&app);

    // The same after a cancel line.
    let (lines, cancel) = platform(&mut app, &ctx, 24, "passkey_register", args);
    cancel.set();
    confirm(&mut app);
    assert!(app.owner.check.is_none());
    assert_eq!(line(&lines)["result"]["error"]["code"], "cancelled");
    saved_nothing(&app);
}

fn peer(check: &str, identifier: &str, path: &str) -> Value {
    json!({
        "source": "macos_autofill_extension",
        "check": check,
        "signing_identifier": identifier,
        "team": "7S3F9767BM",
        "pid": 4242,
        "path": path,
    })
}

fn request_line(n: u64, peer: &Value) -> String {
    let line = json!({
        "type": "request",
        "v": 1,
        "rid": rid(n),
        "owner_check": false,
        "peer": peer,
        "payload": { "op": "passkey_list", "rp_id": RP },
    });
    format!("{line}\n")
}

/// Run the reader over `input` with `rule`. The events, and the lines it wrote back.
fn read_all(input: &str, rule: &PeerRule) -> (Vec<PlatformEvent>, Vec<Value>) {
    let waiting = Arc::default();
    let (events, received) = mpsc::channel();
    let (out, written) = mpsc::channel();
    read_bridge(input.as_bytes(), rule, &events, &out, &waiting, &|| {});
    let lines = written
        .try_iter()
        .map(|line| match line {
            Out::Line(bytes) => serde_json::from_slice(&bytes).unwrap(),
            Out::Stop => panic!("stop"),
        })
        .collect();
    (received.try_iter().collect(), lines)
}

const APPEX: &str = "/Applications/Apassy.app/Contents/PlugIns/ApassyAutoFill.appex";

#[test]
fn the_bridge_reader_follows_the_swift_protocol() {
    let signed = peer("code_signature", "com.wydrox.apassy.autofill", APPEX);
    let input = format!(
        "{}\n{}{}{}\n",
        json!({ "type": "ready", "v": 1, "socket": "/tmp/cp.sock" }),
        request_line(1, &signed),
        request_line(2, &signed),
        json!({ "type": "cancel", "v": 1, "rid": rid(2), "reason": "peer_closed" }),
    );
    let rule = PeerRule::Signed {
        appex: APPEX.into(),
    };
    let (events, written) = read_all(&input, &rule);
    assert!(written.is_empty());
    let mut cancels = Vec::new();
    let mut ready = false;
    let mut closed = false;
    for event in events {
        match event {
            PlatformEvent::Ready { socket } => ready = socket == "/tmp/cp.sock",
            PlatformEvent::Request {
                rid: id,
                op,
                args,
                cancel,
            } => {
                assert_eq!(op, "passkey_list");
                assert_eq!(args, json!({ "rp_id": RP }), "the op is not an argument");
                cancels.push((id, cancel));
            }
            PlatformEvent::Closed(why) => closed = why.contains("ended"),
        }
    }
    assert!(ready && closed);
    assert_eq!(cancels.len(), 2);
    // The cancel line cancels request 2. The end of the output cancels request 1.
    assert!(cancels.iter().all(|(_, cancel)| cancel.is_set()));

    // A fatal error line of the bridge ends it.
    let input = format!(
        "{}\n",
        json!({ "type": "error", "v": 1, "code": "caller_not_allowed", "message": "x" })
    );
    let (events, _) = read_all(&input, &rule);
    assert!(
        matches!(&events[..], [PlatformEvent::Closed(why)] if why.contains("caller_not_allowed"))
    );

    // Unknown fields, another version, or a request ID that is not a UUID end it too.
    for bad in [
        json!({ "type": "ready", "v": 1, "socket": "/s", "verified": true }),
        json!({ "type": "ready", "v": 2, "socket": "/s" }),
        json!({ "type": "cancel", "v": 1, "rid": "1", "reason": "timeout" }),
        json!({ "type": "response", "v": 1, "rid": rid(1), "result": {} }),
    ] {
        let (events, _) = read_all(&format!("{bad}\n"), &rule);
        assert!(
            matches!(&events[..], [PlatformEvent::Closed(why)] if why.contains("not valid")),
            "{bad}"
        );
    }
}

#[test]
fn the_app_refuses_requests_without_the_signed_extension() {
    let release = PeerRule::Signed {
        appex: APPEX.into(),
    };
    let refused = [
        // A development bridge in a release.
        peer("development_override", "", ""),
        // Another program, or the extension of another bundle.
        peer("code_signature", "com.example.other", APPEX),
        peer(
            "code_signature",
            "com.wydrox.apassy.autofill",
            "/tmp/Apassy.app/Contents/PlugIns/ApassyAutoFill.appex",
        ),
        json!({ "source": "macos_autofill_extension", "check": "code_signature" }),
        {
            let mut extra = peer("code_signature", "com.wydrox.apassy.autofill", APPEX);
            extra["verified"] = json!(true);
            extra
        },
    ];
    for peer in refused {
        let (events, written) = read_all(&request_line(1, &peer), &release);
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, PlatformEvent::Request { .. })),
            "{peer}"
        );
        assert_eq!(written.len(), 1, "{peer}");
        assert_eq!(written[0]["rid"], rid(1));
        assert_eq!(written[0]["result"]["error"]["code"], "caller_not_allowed");
    }
    // Debug builds and tests accept a development bridge.
    let (events, written) = read_all(
        &request_line(1, &peer("development_override", "", "")),
        &PeerRule::Development,
    );
    assert!(written.is_empty());
    assert!(
        events
            .iter()
            .any(|event| matches!(event, PlatformEvent::Request { .. }))
    );
}

// ---- The socket watches the peer. ----

struct WatchWire;

impl LineWire for WatchWire {
    type Request = PeerGone;
    type Response = Response;
    const NAME: &'static str = "watch-test";
    const MAX_REQUEST_BYTES: usize = 1024;
    const MAX_CONNECTIONS: usize = 2;
    const BUSY: &'static str = "busy";

    fn parse(_line: &[u8]) -> Result<PeerGone, Response> {
        Ok(PeerGone::default())
    }

    fn error(code: &'static str, message: &'static str) -> Response {
        Response::error(code, message)
    }

    fn watch(request: &PeerGone) -> Option<PeerGone> {
        Some(request.clone())
    }
}

#[test]
fn the_socket_marks_a_request_whose_peer_hung_up() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("w").join("watch.sock");
    let woken = Arc::new(Mutex::new(0u32));
    let count = Arc::clone(&woken);
    let (mut socket, inbox) = owner_socket::start_line::<WatchWire>(&path, move || {
        *count.lock().unwrap() += 1;
    })
    .expect("socket");

    // A peer that waits gets its answer.
    let mut client = UnixStream::connect(&path).unwrap();
    client.write_all(b"{}\n").unwrap();
    let envelope = inbox.recv_timeout(Duration::from_secs(5)).expect("request");
    assert!(!envelope.request.is_set());
    envelope
        .reply
        .send(Response::ok(
            "done",
            Data::Status {
                vault: VaultState::Unlocked,
                version: "test".to_owned(),
            },
        ))
        .unwrap();
    let mut text = String::new();
    client.read_to_string(&mut text).unwrap();
    assert!(text.contains("done"), "{text}");

    // A peer that hangs up while the UI works: the request is cancelled, and the UI
    // thread is woken.
    let client = UnixStream::connect(&path).unwrap();
    (&client).write_all(b"{}\n").unwrap();
    let envelope = inbox.recv_timeout(Duration::from_secs(5)).expect("request");
    let before = *woken.lock().unwrap();
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !envelope.request.is_set() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(envelope.request.is_set(), "the hang-up is seen");
    assert!(*woken.lock().unwrap() > before, "the UI thread is woken");

    // A peer that sends more after its line is cancelled too.
    let mut client = UnixStream::connect(&path).unwrap();
    client.write_all(b"{}\n").unwrap();
    let envelope = inbox.recv_timeout(Duration::from_secs(5)).expect("request");
    client.write_all(b"x").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !envelope.request.is_set() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(envelope.request.is_set());
    socket.stop();
}

// ---- Setup keys on the credential page. ----

/// A login as an older Apassy stored it: a visible detail with an explicit link, a
/// hidden detail with an explicit link under another label, and an ordinary detail.
fn add_legacy_login(app: &DesktopApp) -> u64 {
    use crate::vault::{Field, ItemDraft as VaultDraft, SecretValue};
    let field = |name: &str, value: &str, secret: bool| Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    };
    let link = format!("otpauth://totp/Example?secret={SEED}");
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault.add(VaultDraft {
                title: "Legacy".to_owned(),
                kind: CredentialKind::Login,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![
                    field("username", "ada@example.com", false),
                    field("password", PASSWORD, true),
                    field(&detail_field_name("Authenticator"), &link, false),
                    field(&detail_field_name("Backup"), &link, true),
                    field(&detail_field_name("Region"), "eu-west", false),
                ],
            })
        })
        .expect("open vault")
        .expect("add")
        .id
}

#[test]
fn setup_keys_are_classified_masked_and_never_in_a_generic_reveal() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let item = add_legacy_login(&app);
    let details = app.owner_ui.session.details(item).unwrap();
    let line = |label: &str| {
        details
            .details
            .iter()
            .find(|line| line.label == label)
            .unwrap_or_else(|| panic!("{label}"))
            .clone()
    };
    for label in ["Authenticator", "Backup"] {
        let line = line(label);
        assert!(line.totp && line.hidden && line.value.is_none(), "{label}");
    }
    let region = line("Region");
    assert!(!region.totp && !region.hidden);
    assert_eq!(region.value.as_deref(), Some("eu-west"));

    // A generic reveal opens the password, never a setup key.
    let proof = fresh_proof(&app, OwnerAction::Reveal { item_id: item });
    app.owner_ui.session.reveal(item, proof).expect("reveal");
    let session = &app.owner_ui.session;
    assert_eq!(session.revealed_value(item, "password"), Some(PASSWORD));
    for label in ["Authenticator", "Backup"] {
        assert_eq!(
            session.revealed_value(item, &detail_field_name(label)),
            None
        );
    }

    // `ShowCode` opens a setup key of either kind, and only into the code cache.
    for label in ["Authenticator", "Backup"] {
        let field = detail_field_name(label);
        let proof = fresh_proof(
            &app,
            OwnerAction::ShowCode {
                item_id: item,
                field: field.clone(),
            },
        );
        app.owner_ui
            .session
            .reveal_one_code_seed(item, &field, proof)
            .expect("show code");
        assert!(app.owner_ui.session.code_seed(item, &field).is_some());
    }
    // An ordinary detail is not a code.
    let region_field = detail_field_name("Region");
    let proof = fresh_proof(
        &app,
        OwnerAction::ShowCode {
            item_id: item,
            field: region_field.clone(),
        },
    );
    assert_eq!(
        app.owner_ui
            .session
            .reveal_one_code_seed(item, &region_field, proof)
            .expect_err("not a code")
            .code,
        "invalid_input"
    );

    // An edit stores the old visible setup key as a hidden detail, with its value.
    let details = app.owner_ui.session.details(item).unwrap();
    app.owner_ui
        .session
        .update(
            item,
            details.revision,
            &details.to_draft(),
            &SecretForm::default(),
        )
        .expect("update");
    let stored = app
        .owner_ui
        .session
        .with_vault(|vault| vault.details(item))
        .unwrap()
        .unwrap();
    let authenticator = detail_field_name("Authenticator");
    assert!(
        stored
            .fields
            .iter()
            .any(|field| field.name == authenticator && field.secret)
    );
}

#[test]
fn a_new_setup_key_is_saved_hidden_even_from_a_visible_row() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    let link = format!("otpauth://totp/Example?secret={SEED}");
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "New".to_owned(),
                kind: CredentialKind::Login,
                username: "ada@example.com".to_owned(),
                details: vec![visible("Authenticator", &link), visible(OTP, SEED)],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add")
        .id;
    let stored = app
        .owner_ui
        .session
        .with_vault(|vault| vault.details(item))
        .unwrap()
        .unwrap();
    for label in ["Authenticator", OTP] {
        let name = detail_field_name(label);
        assert!(
            stored
                .fields
                .iter()
                .any(|field| field.name == name && field.secret),
            "{label}"
        );
    }
}

// ---- Removing a passkey. ----

fn remove_request(app: &DesktopApp, item: u64, delete_login: bool) -> OwnerRequest {
    let details = app.owner_ui.session.details(item).unwrap();
    OwnerRequest::RemovePasskey {
        item_id: item,
        revision: details.revision,
        name: details.name,
        delete_login,
    }
}

#[test]
fn removing_the_passkey_of_a_login_without_a_password_deletes_it() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let created = add_passkey(&app, "ada@example.com", "Example");
    let item = created.item_id;
    let found = app
        .owner_ui
        .session
        .passkey_item(item)
        .unwrap()
        .expect("a passkey");
    assert!(!found.has_password);
    assert_eq!(found.info.credential_id, created.credential_id);
    assert!(!format!("{found:?}").contains("pkcs8"));

    // A proof for another revision removes nothing.
    let revision = app.owner_ui.session.details(item).unwrap().revision;
    let proof = fresh_proof(
        &app,
        OwnerAction::RemovePasskey {
            item_id: item,
            revision: revision + 1,
        },
    );
    assert_eq!(
        app.owner_ui
            .session
            .remove_passkey(item, revision, proof)
            .expect_err("wrong revision")
            .code,
        "owner_check_required"
    );
    assert!(app.owner_ui.session.passkey_item(item).unwrap().is_some());

    app.select_item(item.to_string());
    let request = remove_request(&app, item, true);
    assert!(
        request
            .describe()
            .starts_with("Delete the login \"Example\"")
    );
    app.ask_owner(request, None);
    confirm(&mut app);
    assert_eq!(
        app.owner_ui.session.details(item).unwrap_err().code,
        "not_found"
    );
    assert_eq!(app.selected_item_id, None);
    assert_eq!(app.view, super::OwnerView::Vault);
    assert!(app.status_text.contains("deleted"), "{}", app.status_text);
}

#[test]
fn removing_the_passkey_of_a_login_with_a_password_keeps_the_login() {
    let dir = TempDir::new().unwrap();
    let mut app = unlocked_app(&dir);
    let item = add_code_login(&mut app, "https://example.com", Some(OTP), SEED);
    let revision = app.owner_ui.session.details(item).unwrap().revision;
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault.create_passkey(PasskeyCreate {
                rp_id: RP,
                user_handle: b"uh",
                user_name: "ada@example.com",
                user_display_name: "",
                client_data_hash: &[1u8; 32],
                algorithms: &[],
                exclude: &[],
                target: PasskeyTarget::Attach {
                    item_id: item,
                    revision,
                },
            })
        })
        .unwrap()
        .expect("attach");
    assert!(
        app.owner_ui
            .session
            .passkey_item(item)
            .unwrap()
            .unwrap()
            .has_password
    );

    // A dialog that said "delete the login" removes nothing for a login with a password.
    app.ask_owner(remove_request(&app, item, true), None);
    confirm(&mut app);
    assert!(app.owner_ui.session.passkey_item(item).unwrap().is_some());

    app.select_item(item.to_string());
    let request = remove_request(&app, item, false);
    assert!(request.describe().starts_with("Remove the passkey"));
    app.ask_owner(request, None);
    confirm(&mut app);
    assert_eq!(app.owner_ui.session.passkey_item(item).unwrap(), None);
    let details = app.owner_ui.session.details(item).expect("the login stays");
    assert_eq!(
        app.owner_ui.edit_revision, details.revision,
        "the form is current"
    );
    assert_eq!(app.selected_item_id, Some(item.to_string()));
    let page = Page::parse("https://example.com/").unwrap();
    assert!(app.owner_ui.session.page_login(item, &page).is_ok());
}

// ---- Passwords and codes for macOS AutoFill. ----

struct AutofillVault {
    app: DesktopApp,
    /// A login for example.com with a password and a one-time password.
    coded: u64,
    /// A login for example.org with a password only.
    plain: u64,
    /// A login with a passkey only.
    passkey_only: u64,
}

fn autofill_vault(dir: &TempDir) -> AutofillVault {
    let mut app = unlocked_app(dir);
    let coded = add_code_login(&mut app, "https://example.com/login", Some(OTP), SEED);
    let plain = add_code_login(&mut app, "https://example.org", None, SEED);
    let archived = add_code_login(&mut app, "https://example.com", None, SEED);
    app.owner_ui.session.archive(archived).expect("archive");
    let passkey_only = add_passkey(&app, "ada@example.com", "Passkey only").item_id;
    AutofillVault {
        app,
        coded,
        plain,
        passkey_only,
    }
}

fn ids(list: &Value) -> Vec<u64> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_u64().unwrap())
        .collect()
}

fn assert_no_secret(json: &Value) {
    let text = json.to_string();
    for secret in [PASSWORD, SEED, "recovery-canary", "otpauth"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
}

#[test]
fn the_autofill_list_and_identities_have_metadata_only() {
    let dir = TempDir::new().unwrap();
    let AutofillVault {
        mut app,
        coded,
        plain,
        passkey_only,
    } = autofill_vault(&dir);
    let ctx = egui::Context::default();
    let (lines, _) = platform(
        &mut app,
        &ctx,
        1,
        "autofill_list",
        json!({ "domains": ["login.example.com", "https://example.com/x"] }),
    );
    let answer = line(&lines);
    let result = &answer["result"]["result"];
    assert_no_secret(&answer);
    assert_eq!(ids(&result["matches"]), [coded]);
    // A passkey-only login and an archived login are never offered for a password.
    assert_eq!(ids(&result["others"]), [plain]);
    let entry = &result["matches"][0];
    assert_eq!(entry["has_totp"], true);
    assert_eq!(entry["has_passkey"], false);
    assert_eq!(entry["username"], "ada@example.com");
    assert!(entry["revision"].as_u64().is_some());
    assert!(app.owner.check.is_none(), "a list needs no check");

    let (lines, _) = platform(&mut app, &ctx, 2, "credential_identities", json!({}));
    let answer = line(&lines);
    let result = &answer["result"]["result"];
    assert_no_secret(&answer);
    let identities: Vec<(u64, String)> = result["identities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["id"].as_u64().unwrap(),
                entry["host"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        identities,
        [
            (coded, "example.com".to_owned()),
            (plain, "example.org".to_owned())
        ]
    );
    assert_eq!(ids(&result["totp"]), [coded]);
    assert_eq!(ids(&result["passkeys"]), [passkey_only]);
    let keys: Vec<&String> = result["passkeys"][0].as_object().unwrap().keys().collect();
    assert!(!keys.iter().any(|key| key.contains("key")), "{keys:?}");

    // Unknown fields and too many websites are refused.
    let (lines, _) = platform(
        &mut app,
        &ctx,
        3,
        "credential_identities",
        json!({ "all": true }),
    );
    assert_eq!(line(&lines)["result"]["error"]["code"], "bad_request");
    let many: Vec<String> = (0..17).map(|n| format!("s{n}.example.com")).collect();
    let (lines, _) = platform(
        &mut app,
        &ctx,
        4,
        "autofill_list",
        json!({ "domains": many }),
    );
    assert_eq!(line(&lines)["result"]["error"]["code"], "bad_request");
    app.owner_ui.session.lock().expect("lock");
    let (lines, _) = platform(&mut app, &ctx, 5, "autofill_list", json!({ "domains": [] }));
    assert_eq!(line(&lines)["result"]["error"]["code"], "locked");
}

#[test]
fn a_password_for_autofill_needs_its_own_check_for_this_request() {
    let dir = TempDir::new().unwrap();
    let AutofillVault {
        mut app,
        coded,
        plain,
        passkey_only,
    } = autofill_vault(&dir);
    let ctx = egui::Context::default();
    // A passkey-only login never fills a password, and opens no dialog.
    let (lines, _) = platform(
        &mut app,
        &ctx,
        1,
        "autofill_credential",
        json!({ "id": passkey_only }),
    );
    assert_eq!(line(&lines)["result"]["error"]["code"], "not_found");
    assert!(app.owner.check.is_none());

    let (lines, _) = platform(
        &mut app,
        &ctx,
        2,
        "autofill_credential",
        json!({ "id": coded }),
    );
    assert!(lines.try_recv().is_err(), "no answer before the check");
    let exact = dialog_action(&app);
    assert_eq!(
        exact,
        OwnerAction::FillSystemLogin {
            rid: rid(2),
            item_id: coded,
            login: "Example login".to_owned(),
        }
    );
    let dialog = app.owner.check.as_ref().unwrap();
    assert!(dialog.browser.is_none());
    assert!(dialog.request.describe().starts_with("macOS AutoFill asks"));
    assert!(exact.reason().contains("macOS AutoFill"));
    // Proofs for another request, login, title, or for the browser never fill.
    let wrong = [
        OwnerAction::FillSystemLogin {
            rid: rid(9),
            item_id: coded,
            login: "Example login".to_owned(),
        },
        OwnerAction::FillSystemLogin {
            rid: rid(2),
            item_id: plain,
            login: "Example login".to_owned(),
        },
        OwnerAction::FillLogin {
            item_id: coded,
            login: "Example login".to_owned(),
            origin: "https://example.com".to_owned(),
        },
        OwnerAction::Reveal { item_id: coded },
    ];
    for action in wrong {
        let proof = fresh_proof(&app, action.clone());
        let err = app
            .owner_ui
            .session
            .system_fill(&rid(2), coded, "Example login", proof)
            .expect_err("wrong proof");
        assert_eq!(err.code, "owner_check_required", "{action:?}");
    }
    // Through the dialog, a wrong proof answers "refused" and nothing else.
    let wrong_proof = fresh_proof(
        &app,
        OwnerAction::FillSystemLogin {
            rid: rid(9),
            item_id: coded,
            login: "Example login".to_owned(),
        },
    );
    app.finish_owner_check_with(wrong_proof);
    let refused = line(&lines);
    assert_eq!(refused["result"]["error"]["code"], "refused");
    assert_no_secret(&refused);

    let (lines, _) = platform(
        &mut app,
        &ctx,
        3,
        "autofill_credential",
        json!({ "id": coded }),
    );
    confirm(&mut app);
    let answer = line(&lines);
    assert_eq!(
        answer["result"],
        json!({ "ok": true, "result": { "username": "ada@example.com", "password": PASSWORD } })
    );
    // The history has the fill, without a value.
    let events = app.owner_ui.session.item_events(coded, 10).unwrap();
    let text = format!("{events:?}");
    assert!(text.contains("macOS AutoFill"), "{text}");
    assert!(!text.contains(PASSWORD));
    assert!(app.platform.filled.is_none());

    // A cancel before the proof fills nothing.
    let (lines, cancel) = platform(
        &mut app,
        &ctx,
        4,
        "autofill_credential",
        json!({ "id": coded }),
    );
    cancel.set();
    confirm(&mut app);
    let cancelled = line(&lines);
    assert_eq!(cancelled["result"]["error"]["code"], "cancelled");
    assert_no_secret(&cancelled);
    assert!(app.platform.filled.is_none());

    // A lock and an unlock during the dialog: the proof of the old session fills nothing.
    let (lines, _) = platform(
        &mut app,
        &ctx,
        5,
        "autofill_credential",
        json!({ "id": coded }),
    );
    let old = fresh_proof(&app, dialog_action(&app));
    app.owner_ui.session.lock().expect("lock");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app.finish_owner_check_with(old);
    let refused = line(&lines);
    assert_eq!(refused["result"]["error"]["code"], "refused");
    assert_no_secret(&refused);
}

#[test]
fn a_code_for_autofill_needs_its_own_check_and_never_sends_the_seed() {
    let dir = TempDir::new().unwrap();
    let AutofillVault {
        mut app,
        coded,
        plain,
        ..
    } = autofill_vault(&dir);
    let ctx = egui::Context::default();
    let (lines, _) = platform(&mut app, &ctx, 1, "autofill_code", json!({ "id": plain }));
    assert_eq!(line(&lines)["result"]["error"]["code"], "not_found");
    assert!(app.owner.check.is_none());

    let (lines, _) = platform(&mut app, &ctx, 2, "autofill_code", json!({ "id": coded }));
    let field = detail_field_name(OTP);
    assert_eq!(
        dialog_action(&app),
        OwnerAction::FillSystemCode {
            rid: rid(2),
            item_id: coded,
            field: field.clone(),
        }
    );
    // The proofs of the credential page and of the browser never fill the sheet.
    for action in [
        OwnerAction::CopyCode {
            item_id: coded,
            field: field.clone(),
        },
        OwnerAction::FillCode {
            item_id: coded,
            field: field.clone(),
            origin: "https://example.com".to_owned(),
        },
        OwnerAction::FillSystemCode {
            rid: rid(2),
            item_id: coded,
            field: detail_field_name("Recovery code"),
        },
    ] {
        let proof = fresh_proof(&app, action.clone());
        assert_eq!(
            app.owner_ui
                .session
                .system_code(&rid(2), coded, &field, proof)
                .expect_err("wrong proof")
                .code,
            "owner_check_required",
            "{action:?}"
        );
    }
    confirm(&mut app);
    let answer = line(&lines);
    assert_no_secret(&answer);
    let result = &answer["result"]["result"];
    let code = result["code"].as_str().unwrap();
    assert!(codes_near_now(SEED).contains(&code.to_owned()), "{answer}");
    assert!((1..=30).contains(&result["remaining"].as_u64().unwrap()));

    // A proof for the recovery field cannot read it as a code, even when it names it.
    let recovery = detail_field_name("Recovery code");
    let proof = fresh_proof(
        &app,
        OwnerAction::FillSystemCode {
            rid: rid(3),
            item_id: coded,
            field: recovery.clone(),
        },
    );
    assert_eq!(
        app.owner_ui
            .session
            .system_code(&rid(3), coded, &recovery, proof)
            .expect_err("not a code")
            .code,
        "no_code"
    );
}
