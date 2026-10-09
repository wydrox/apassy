#![cfg(feature = "vault")]

//! Passkey export for Credential Exchange: only canonical passkeys leave the vault, the
//! key is the normalized PKCS #8 form, and the export record has no values. A conflict
//! copy of a credential that a normal item has, active or archived, is never a
//! candidate. When the owner deletes each normal item with the credential, the restored
//! copy is the candidate (tests/passkey_conflict_recovery.rs has more recovery cases).
//! Synthetic values only.

use apassy::contracts::CredentialKind;
use apassy::vault::passkey::{ES256, EXPORT_DETAIL};
use apassy::vault::{
    Field, ItemDraft, ItemEventKind, MAX_ITEM_EVENTS, PasskeyCreate, PasskeyCreated, PasskeyError,
    PasskeyExport, PasskeyImport, PasskeyTarget, SecretValue, SyncScope, Vault, VaultErrorKind,
};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASS: &str = "synthetic-export-pass";
const RP: &str = "example.com";
const HASH: [u8; 32] = [0x3c; 32];

fn vault(dir: &TempDir, name: &str) -> Vault {
    let mut vault = Vault::create(&dir.path().join(name), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    vault
}

fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    }
}

fn create(vault: &mut Vault, rp_id: &str, title: &str) -> PasskeyCreated {
    vault
        .create_passkey(PasskeyCreate {
            rp_id,
            user_handle: b"synthetic-user-1",
            user_name: "alice",
            user_display_name: "Alice Example",
            client_data_hash: &HASH,
            algorithms: &[ES256],
            exclude: &[],
            target: PasskeyTarget::NewItem {
                title: title.to_owned(),
            },
        })
        .unwrap()
}

fn import(key: &[u8], credential_id: Vec<u8>) -> PasskeyImport {
    PasskeyImport {
        rp_id: RP.to_owned(),
        credential_id,
        user_handle: b"imported-user".to_vec(),
        user_name: "bob".to_owned(),
        user_display_name: "Bob".to_owned(),
        pkcs8: Zeroizing::new(key.to_vec()),
        title: "Imported".to_owned(),
        attach: None,
    }
}

fn not_found<T: std::fmt::Debug>(result: Result<T, PasskeyError>) {
    match result.unwrap_err() {
        PasskeyError::Vault(vault) => assert_eq!(vault.kind(), VaultErrorKind::NotFound),
        other => panic!("not a vault error: {other:?}"),
    }
}

/// The uncompressed public point of an exported key, from `ring`.
fn public_point(export: &PasskeyExport) -> Vec<u8> {
    EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &export.pkcs8,
        &SystemRandom::new(),
    )
    .unwrap()
    .public_key()
    .as_ref()
    .to_vec()
}

fn signs_with(vault: &Vault, item_id: u64, credential_id: &[u8], point: &[u8]) -> bool {
    let assertion = vault
        .sign_passkey(item_id, RP, credential_id, &HASH)
        .unwrap();
    let mut message = assertion.authenticator_data.clone();
    message.extend_from_slice(&HASH);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&message, &assertion.signature)
        .is_ok()
}

fn revision_and_events(vault: &Vault, item_id: u64) -> (u64, usize) {
    (
        vault.details(item_id).unwrap().summary.revision,
        vault.item_events(item_id, MAX_ITEM_EVENTS).unwrap().len(),
    )
}

#[test]
fn export_gives_the_key_that_signs_and_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let created = create(&mut vault, RP, "Example");
    let before = revision_and_events(&vault, created.item_id);
    let export = vault.export_passkey(created.item_id).unwrap();
    assert_eq!(export.info, vault.passkey_info(created.item_id).unwrap());
    assert_eq!(export.info.title, "Example");
    assert_eq!(export.info.credential_id, created.credential_id);
    assert_eq!(export.info.user_handle, b"synthetic-user-1");
    // PKCS #8 v1 with the public point; the point is the registered one.
    assert_eq!(export.pkcs8.len(), 138);
    let point = public_point(&export);
    assert_eq!(&created.public_key_spki[26..], point.as_slice());
    assert!(signs_with(
        &vault,
        created.item_id,
        &created.credential_id,
        &point
    ));
    assert_eq!(revision_and_events(&vault, created.item_id), before);
    // Debug does not show the key.
    let text = format!("{export:?}");
    assert!(text.contains("[redacted]"), "{text}");
    let key_bytes = format!("{:?}", &export.pkcs8[36..44]);
    assert!(!text.contains(key_bytes.trim_matches(['[', ']'])), "{text}");
}

#[test]
fn an_imported_cryptokit_key_exports_in_the_normalized_form() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let raw = document.as_ref();
    // The same key with `[0] parameters` in ECPrivateKey, the CryptoKit form.
    let mut with_params = vec![0x30, 0x81, 0x93, 0x02, 0x01, 0x00];
    with_params.extend_from_slice(&raw[6..27]);
    with_params.extend_from_slice(&[0x04, 0x79, 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]);
    with_params.extend_from_slice(&raw[36..68]);
    with_params.extend_from_slice(&[
        0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ]);
    with_params.extend_from_slice(&raw[68..]);
    let id = vault
        .import_passkey(import(&with_params, vec![3; 20]))
        .unwrap();
    let export = vault.export_passkey(id).unwrap();
    assert_eq!(export.pkcs8.as_slice(), raw);
    assert_eq!(export.info.user_name, "bob");
    assert!(signs_with(&vault, id, &[3; 20], &public_point(&export)));
}

#[test]
fn only_canonical_active_login_passkeys_export() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let created = create(&mut vault, RP, "Example");
    let password = vault
        .add(ItemDraft {
            title: "Password only".to_owned(),
            kind: CredentialKind::Login,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![
                field("username", "alice", false),
                field("password", "SYNTH-pass", true),
            ],
        })
        .unwrap();
    let api = vault
        .add(ItemDraft {
            title: "Token".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![field("token", "SYNTH-token", true)],
        })
        .unwrap();
    not_found(vault.export_passkey(password.id));
    not_found(vault.export_passkey(api.id));
    not_found(vault.export_passkey(9_999));
    // Archived: no export, no signature; back: both again.
    vault.set_archived(created.item_id, true).unwrap();
    not_found(vault.export_passkey(created.item_id));
    vault.set_archived(created.item_id, false).unwrap();
    vault.export_passkey(created.item_id).unwrap();
    // A locked vault exports nothing.
    vault.lock().unwrap();
    match vault.export_passkey(created.item_id).unwrap_err() {
        PasskeyError::Vault(error) => assert_eq!(error.kind(), VaultErrorKind::Locked),
        other => panic!("{other:?}"),
    }
}

#[test]
fn record_export_is_a_reveal_event_without_values() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let created = create(&mut vault, RP, "Example");
    let revision = vault.details(created.item_id).unwrap().summary.revision;
    vault.record_export(created.item_id).unwrap();
    assert_eq!(EXPORT_DETAIL, "Credential Exchange export prepared");
    let events = vault.item_events(created.item_id, MAX_ITEM_EVENTS).unwrap();
    let exported: Vec<_> = events
        .iter()
        .filter(|event| event.kind == ItemEventKind::Revealed)
        .collect();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].detail, EXPORT_DETAIL);
    assert_eq!(
        vault.details(created.item_id).unwrap().summary.revision,
        revision
    );
    assert_eq!(
        vault.record_export(9_999).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
}

/// Two Macs edit the item: Mac A gets an archived conflict copy with the same passkey.
/// Returns (vault A, original, copy, credential ID).
fn conflict(dir: &TempDir) -> (Vault, u64, u64, Vec<u8>) {
    let mut a = vault(dir, "a.db");
    let created = create(&mut a, RP, "Example");
    let seed = dir.path().join("seed.db");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    let b_item = b.passkeys(RP, &[]).unwrap()[0].item_id;
    let rename = |vault: &mut Vault, id: u64, title: &str| {
        let revision = vault.details(id).unwrap().summary.revision;
        let draft = ItemDraft {
            title: title.to_owned(),
            kind: CredentialKind::Login,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![field("username", "alice", false)],
        };
        vault.update(id, revision, draft).unwrap();
    };
    rename(&mut a, created.item_id, "Example A");
    rename(&mut b, b_item, "Example B");
    let remote = dir.path().join("remote.db");
    b.write_sync_copy(&remote, "Mac B").unwrap();
    assert_eq!(
        a.merge_from(&remote, &SyncScope::vault())
            .unwrap()
            .conflicts
            .len(),
        1
    );
    let copies = a.conflict_copies().unwrap();
    let (&copy, &origin) = copies.first_key_value().unwrap();
    assert_eq!(origin, Some(created.item_id));
    assert!(a.is_archived(copy).unwrap());
    assert_eq!(
        a.passkey_info(copy).unwrap().credential_id,
        created.credential_id
    );
    (a, created.item_id, copy, created.credential_id)
}

#[test]
fn a_conflict_copy_is_never_a_candidate_even_when_the_original_is_archived() {
    let dir = TempDir::new().unwrap();
    let (mut a, original, copy, credential_id) = conflict(&dir);
    // The owner archives the original and brings the copy back.
    a.set_archived(original, true).unwrap();
    a.set_archived(copy, false).unwrap();
    assert!(a.all_passkeys().unwrap().is_empty());
    assert!(a.passkeys(RP, &[]).unwrap().is_empty());
    assert!(
        a.passkeys(RP, std::slice::from_ref(&credential_id))
            .unwrap()
            .is_empty()
    );
    not_found(a.sign_passkey(copy, RP, &credential_id, &HASH));
    not_found(a.sign_passkey(original, RP, &credential_id, &HASH));
    not_found(a.export_passkey(copy));
    not_found(a.export_passkey(original));
    // The original back: it is the only candidate, and the copy still is not.
    a.set_archived(original, false).unwrap();
    let listed = a.all_passkeys().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].item_id, original);
    let export = a.export_passkey(original).unwrap();
    assert!(signs_with(
        &a,
        original,
        &credential_id,
        &public_point(&export)
    ));
    not_found(a.sign_passkey(copy, RP, &credential_id, &HASH));
    not_found(a.export_passkey(copy));
}

#[test]
fn a_restored_copy_is_the_candidate_after_the_original_is_deleted() {
    let dir = TempDir::new().unwrap();
    let (mut a, original, copy, credential_id) = conflict(&dir);
    let point = public_point(&a.export_passkey(original).unwrap());
    a.set_archived(copy, false).unwrap();
    // The original (a normal item) has the credential: the copy is not the candidate.
    not_found(a.sign_passkey(copy, RP, &credential_id, &HASH));
    not_found(a.export_passkey(copy));
    // The owner deletes the original. The restored copy has the last key of the
    // credential, so it is the candidate.
    let revision = a.details(original).unwrap().summary.revision;
    a.delete(original, revision).unwrap();
    let listed = a.all_passkeys().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].item_id, copy);
    let export = a.export_passkey(copy).unwrap();
    assert_eq!(export.info.credential_id, credential_id);
    assert_eq!(public_point(&export), point);
    assert!(signs_with(&a, copy, &credential_id, &point));
    // The export imports into another vault and signs for the same point.
    let mut fresh = vault(&dir, "fresh.db");
    let imported = fresh
        .import_passkey(import(&export.pkcs8, credential_id.clone()))
        .unwrap();
    assert!(signs_with(&fresh, imported, &credential_id, &point));
    // Archived again, the copy is not the candidate.
    a.set_archived(copy, true).unwrap();
    assert!(a.all_passkeys().unwrap().is_empty());
    not_found(a.export_passkey(copy));
}

#[test]
fn of_two_ordinary_items_with_one_credential_the_lower_id_is_canonical() {
    let dir = TempDir::new().unwrap();
    let mut a = vault(&dir, "a.db");
    let seed = dir.path().join("seed.db");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    // Each Mac imports the same credential on its own: two items, not a conflict.
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap();
    let first = a
        .import_passkey(import(document.as_ref(), vec![7; 20]))
        .unwrap();
    b.import_passkey(import(document.as_ref(), vec![7; 20]))
        .unwrap();
    let remote = dir.path().join("remote.db");
    b.write_sync_copy(&remote, "Mac B").unwrap();
    let report = a.merge_from(&remote, &SyncScope::vault()).unwrap();
    assert!(report.conflicts.is_empty());
    assert!(a.conflict_copies().unwrap().is_empty());
    let second = a
        .search("Imported")
        .unwrap()
        .into_iter()
        .map(|summary| summary.id)
        .find(|&id| id != first)
        .unwrap();
    assert!(first < second);
    assert_eq!(a.passkey_info(second).unwrap().credential_id, vec![7; 20]);
    let listed = a.all_passkeys().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].item_id, first);
    a.export_passkey(first).unwrap();
    not_found(a.export_passkey(second));
    not_found(a.sign_passkey(second, RP, &[7; 20], &HASH));
    // The lower item archived: the other one is the candidate.
    a.set_archived(first, true).unwrap();
    let listed = a.all_passkeys().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].item_id, second);
    let export = a.export_passkey(second).unwrap();
    assert!(signs_with(&a, second, &[7; 20], &public_point(&export)));
}
