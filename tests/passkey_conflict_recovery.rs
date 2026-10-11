#![cfg(feature = "vault")]

//! A passkey that only the losing version of a sync conflict has: device A adds it to a
//! login, and a later password edit of device B wins. The owner restores the conflict
//! copy, and it signs and exports the passkey, also after the original is deleted. The
//! export imports into another vault. A normal item with the credential, active or
//! archived, has priority over each copy. Of two restored copies, the lower ID is the
//! one entry. An archived copy never signs. No passkey goes on a conflict copy.
//! Synthetic values only; the tests compare values and do not print them.

use std::path::Path;

use apassy::contracts::CredentialKind;
use apassy::vault::passkey::ES256;
use apassy::vault::{
    Field, ItemDraft, PasskeyCreate, PasskeyCreated, PasskeyError, PasskeyImport, PasskeyTarget,
    SecretValue, SyncScope, Vault, VaultErrorKind,
};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASS: &str = "synthetic-recovery-pass";
const RP: &str = "example.com";
const HASH: [u8; 32] = [0x5a; 32];
const OLD_PASSWORD: &str = "SYNTH-old-password";
const NEW_PASSWORD: &str = "SYNTH-new-password";

fn vault(dir: &TempDir, name: &str) -> Vault {
    let mut vault = Vault::create(&dir.path().join(name), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    vault
}

fn login(title: &str, password: &str) -> ItemDraft {
    let field = |name: &str, value: &str, secret: bool| Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    };
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::Login,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![
            field("username", "alice", false),
            field("password", password, true),
        ],
    }
}

fn edit(vault: &mut Vault, id: u64, title: &str, password: &str) {
    let revision = vault.details(id).unwrap().summary.revision;
    vault.update(id, revision, login(title, password)).unwrap();
}

fn attach(vault: &mut Vault, item_id: u64) -> Result<PasskeyCreated, PasskeyError> {
    let revision = vault.details(item_id).unwrap().summary.revision;
    vault.create_passkey(PasskeyCreate {
        rp_id: RP,
        user_handle: b"synthetic-user-1",
        user_name: "alice",
        user_display_name: "Alice Example",
        client_data_hash: &HASH,
        algorithms: &[ES256],
        exclude: &[],
        target: PasskeyTarget::Attach { item_id, revision },
    })
}

fn kind(error: PasskeyError) -> VaultErrorKind {
    match error {
        PasskeyError::Vault(vault) => vault.kind(),
        other => panic!("not a vault error: {other:?}"),
    }
}

fn not_found<T: std::fmt::Debug>(result: Result<T, PasskeyError>) {
    assert_eq!(kind(result.unwrap_err()), VaultErrorKind::NotFound);
}

/// The uncompressed point of a registration: the end of the SubjectPublicKeyInfo.
fn point(created: &PasskeyCreated) -> Vec<u8> {
    created.public_key_spki[created.public_key_spki.len() - 65..].to_vec()
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

/// The public point of the exported key.
fn exported_point(vault: &Vault, item_id: u64) -> Vec<u8> {
    let export = vault.export_passkey(item_id).unwrap();
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

fn id_of(vault: &Vault, title: &str) -> u64 {
    let found: Vec<u64> = vault
        .search(title)
        .unwrap()
        .into_iter()
        .filter(|summary| summary.title == title)
        .map(|summary| summary.id)
        .collect();
    assert_eq!(found.len(), 1);
    found[0]
}

fn merge(into: &mut Vault, from: &mut Vault, path: &Path, device: &str) -> usize {
    from.write_sync_copy(path, device).unwrap();
    into.merge_from(path, &SyncScope::vault())
        .unwrap()
        .conflicts
        .len()
}

/// Mac B's edit must be the later version of the conflict.
fn later() {
    std::thread::sleep(std::time::Duration::from_millis(20));
}

/// Two Macs with one vault and the login "Site" with a password and no passkey.
fn two_macs(dir: &TempDir) -> (Vault, Vault, u64) {
    let mut a = vault(dir, "a.db");
    let item = a.add(login("Site", OLD_PASSWORD)).unwrap().id;
    let seed = dir.path().join("seed.db");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    (a, b, item)
}

/// Mac A adds a passkey to "Site"; then Mac B changes its password. B's version wins on
/// A, and A's version with the passkey is the archived conflict copy.
fn lost_passkey(dir: &TempDir) -> (Vault, Vault, u64, u64, PasskeyCreated) {
    let (mut a, mut b, original) = two_macs(dir);
    let created = attach(&mut a, original).unwrap();
    later();
    let on_b = id_of(&b, "Site");
    edit(&mut b, on_b, "Site", NEW_PASSWORD);
    assert_eq!(
        merge(&mut a, &mut b, &dir.path().join("b.copy"), "Mac B"),
        1
    );
    let copies = a.conflict_copies().unwrap();
    assert_eq!(copies.len(), 1);
    let (&copy, &origin) = copies.first_key_value().unwrap();
    assert_eq!(origin, Some(original));
    assert!(a.is_archived(copy).unwrap());
    (a, b, original, copy, created)
}

#[test]
fn a_passkey_lost_to_a_later_password_edit_signs_from_the_restored_copy() {
    let dir = TempDir::new().unwrap();
    let (mut a, _b, original, copy, created) = lost_passkey(&dir);
    let credential_id = created.credential_id.clone();
    let point = point(&created);
    // The winning version has the new password and no passkey. The copy has the old
    // password and the passkey.
    assert!(a.reveal(original, "password").unwrap().expose() == NEW_PASSWORD);
    assert!(a.reveal(copy, "password").unwrap().expose() == OLD_PASSWORD);
    not_found(a.passkey_info(original));
    assert_eq!(a.passkey_info(copy).unwrap().credential_id, credential_id);
    // Archived, the copy does not sign.
    assert!(a.all_passkeys().unwrap().is_empty());
    not_found(a.sign_passkey(copy, RP, &credential_id, &HASH));
    not_found(a.export_passkey(copy));

    // The owner restores the copy: it is the one passkey of the credential.
    a.set_archived(copy, false).unwrap();
    let listed = a.all_passkeys().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].item_id, copy);
    let allowed = a
        .passkeys(RP, std::slice::from_ref(&credential_id))
        .unwrap();
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0].item_id, copy);
    assert!(signs_with(&a, copy, &credential_id, &point));
    not_found(a.sign_passkey(original, RP, &credential_id, &HASH));

    // The export has the key of the registration, and it imports into another vault.
    let export = a.export_passkey(copy).unwrap();
    let exported_point = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &export.pkcs8,
        &SystemRandom::new(),
    )
    .unwrap()
    .public_key()
    .as_ref()
    .to_vec();
    assert!(exported_point == point, "the export has the registered key");
    let import = |pkcs8: &[u8]| PasskeyImport {
        rp_id: export.info.rp_id.clone(),
        credential_id: export.info.credential_id.clone(),
        user_handle: export.info.user_handle.clone(),
        user_name: export.info.user_name.clone(),
        user_display_name: export.info.user_display_name.clone(),
        pkcs8: Zeroizing::new(pkcs8.to_vec()),
        title: String::new(),
        attach: None,
    };
    let mut fresh = vault(&dir, "fresh.db");
    let imported = fresh.import_passkey(import(&export.pkcs8)).unwrap();
    assert!(signs_with(&fresh, imported, &credential_id, &point));
    // The vault of the copy has the credential: no second item for it.
    assert!(matches!(
        a.import_passkey(import(&export.pkcs8)).unwrap_err(),
        PasskeyError::Exists
    ));
    // Archived again, the copy stops signing; restored, it signs again.
    a.set_archived(copy, true).unwrap();
    assert!(a.all_passkeys().unwrap().is_empty());
    a.set_archived(copy, false).unwrap();
    assert!(signs_with(&a, copy, &credential_id, &point));
}

#[test]
fn restored_copies_of_copies_list_the_credential_once() {
    let dir = TempDir::new().unwrap();
    let (mut a, mut b, _original, copy, created) = lost_passkey(&dir);
    let credential_id = created.credential_id.clone();
    let point = point(&created);
    a.set_archived(copy, false).unwrap();
    // Mac B gets the restored copy, and it signs there too.
    assert_eq!(
        merge(&mut b, &mut a, &dir.path().join("a.copy"), "Mac A"),
        0
    );
    let on_b = b
        .passkeys(RP, std::slice::from_ref(&credential_id))
        .unwrap();
    assert_eq!(on_b.len(), 1);
    let copy_on_b = on_b[0].item_id;
    assert!(signs_with(&b, copy_on_b, &credential_id, &point));
    // Both Macs edit the restored copy: the merge keeps a copy of the copy, with the
    // same passkey. The merge archives it.
    edit(&mut a, copy, "Site A", OLD_PASSWORD);
    later();
    edit(&mut b, copy_on_b, "Site B", OLD_PASSWORD);
    assert_eq!(
        merge(&mut a, &mut b, &dir.path().join("b2.copy"), "Mac B"),
        1
    );
    let copies = a.conflict_copies().unwrap();
    let (&second, &origin) = copies
        .iter()
        .find(|(id, _)| **id != copy)
        .expect("the second copy");
    assert_eq!(origin, Some(copy));
    assert!(copy < second);
    assert!(a.is_archived(second).unwrap());
    assert_eq!(a.passkey_info(second).unwrap().credential_id, credential_id);
    let listed = |a: &Vault| -> Vec<u64> {
        a.all_passkeys()
            .unwrap()
            .into_iter()
            .map(|info| info.item_id)
            .collect()
    };
    assert_eq!(listed(&a), [copy]);
    not_found(a.sign_passkey(second, RP, &credential_id, &HASH));

    // The owner restores the second copy too. No normal item has the credential, so
    // the copy with the lower ID is the one entry.
    a.set_archived(second, false).unwrap();
    assert_eq!(listed(&a), [copy]);
    let allowed = a
        .passkeys(RP, std::slice::from_ref(&credential_id))
        .unwrap();
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed[0].item_id, copy);
    assert!(signs_with(&a, copy, &credential_id, &point));
    not_found(a.sign_passkey(second, RP, &credential_id, &HASH));
    not_found(a.export_passkey(second));

    // The first copy archived: the restored second copy is the one entry.
    a.set_archived(copy, true).unwrap();
    assert_eq!(listed(&a), [second]);
    assert!(signs_with(&a, second, &credential_id, &point));
    not_found(a.sign_passkey(copy, RP, &credential_id, &HASH));
    not_found(a.export_passkey(copy));

    // The first copy (the original of the second copy) deleted: the second copy still
    // signs, and its export has the key of the registration.
    let revision = a.details(copy).unwrap().summary.revision;
    a.delete(copy, revision).unwrap();
    assert_eq!(a.conflict_copies().unwrap().get(&second), Some(&None));
    assert_eq!(listed(&a), [second]);
    assert_eq!(exported_point(&a, second), point);
    assert!(signs_with(&a, second, &credential_id, &point));

    // Archived again, the second copy stops signing.
    a.set_archived(second, true).unwrap();
    assert!(listed(&a).is_empty());
    not_found(a.sign_passkey(second, RP, &credential_id, &HASH));
    not_found(a.export_passkey(second));
}

#[test]
fn a_normal_item_with_the_credential_has_priority_active_or_archived() {
    let dir = TempDir::new().unwrap();
    let (mut a, _b, _original, copy, created) = lost_passkey(&dir);
    let credential_id = created.credential_id.clone();
    let point = point(&created);
    a.set_archived(copy, false).unwrap();
    let export = a.export_passkey(copy).unwrap();
    // Another vault has the same credential on a normal item, and it syncs in: Mac C
    // imported the export.
    let seed = dir.path().join("seed-c.db");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut c, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("c.db"), PASS).unwrap();
    c.unlock(PASS).unwrap();
    // On C the restored copy signs, so C cannot import the credential again. C removes
    // the passkey from the copy and imports it on a new item.
    let copy_on_c = c
        .passkeys(RP, std::slice::from_ref(&credential_id))
        .unwrap()[0]
        .item_id;
    let revision = c.details(copy_on_c).unwrap().summary.revision;
    c.remove_passkey(copy_on_c, revision).unwrap();
    let normal = c
        .import_passkey(PasskeyImport {
            rp_id: export.info.rp_id.clone(),
            credential_id: export.info.credential_id.clone(),
            user_handle: export.info.user_handle.clone(),
            user_name: export.info.user_name.clone(),
            user_display_name: export.info.user_display_name.clone(),
            pkcs8: Zeroizing::new(export.pkcs8.to_vec()),
            title: "Imported".to_owned(),
            attach: None,
        })
        .unwrap();
    assert_eq!(c.passkey_info(normal).unwrap().credential_id, credential_id);
    // A gets the new normal item, but keeps its own copy with the passkey: A's later
    // edit of the copy is concurrent with C's removal, and it wins.
    later();
    edit(&mut a, copy, "Site (kept)", OLD_PASSWORD);
    merge(&mut a, &mut c, &dir.path().join("c.copy"), "Mac C");
    assert_eq!(a.passkey_info(copy).unwrap().credential_id, credential_id);
    assert!(!a.is_archived(copy).unwrap());
    let normal_on_a = id_of(&a, "Imported");
    assert!(!a.conflict_copies().unwrap().contains_key(&normal_on_a));
    let listed = |a: &Vault| -> Vec<u64> {
        a.all_passkeys()
            .unwrap()
            .into_iter()
            .filter(|info| info.credential_id == credential_id)
            .map(|info| info.item_id)
            .collect()
    };
    // The active normal item is the one, also with a lower ID on the copy.
    assert!(copy < normal_on_a);
    assert_eq!(listed(&a), [normal_on_a]);
    assert!(signs_with(&a, normal_on_a, &credential_id, &point));
    for (id, _) in a.conflict_copies().unwrap() {
        not_found(a.sign_passkey(id, RP, &credential_id, &HASH));
        not_found(a.export_passkey(id));
    }
    // The normal item archived: it still has the credential, so no copy takes it.
    a.set_archived(normal_on_a, true).unwrap();
    assert!(listed(&a).is_empty());
    for (id, _) in a.conflict_copies().unwrap() {
        not_found(a.sign_passkey(id, RP, &credential_id, &HASH));
        not_found(a.export_passkey(id));
    }
    // The owner deletes the archived normal item. No normal item has the credential
    // now, so the restored copy signs it again: the delete does not lose the key.
    let revision = a.details(normal_on_a).unwrap().summary.revision;
    a.delete(normal_on_a, revision).unwrap();
    assert_eq!(listed(&a), [copy]);
    assert!(signs_with(&a, copy, &credential_id, &point));
}

#[test]
fn a_restored_copy_signs_after_its_original_is_deleted() {
    let dir = TempDir::new().unwrap();
    let (mut a, _b, original, copy, created) = lost_passkey(&dir);
    let credential_id = created.credential_id.clone();
    let point = point(&created);
    // The owner deletes the winning version first. The copy stays archived: only an
    // explicit restore makes it sign.
    let revision = a.details(original).unwrap().summary.revision;
    a.delete(original, revision).unwrap();
    assert_eq!(a.conflict_copies().unwrap().get(&copy), Some(&None));
    assert!(a.is_archived(copy).unwrap());
    assert!(a.all_passkeys().unwrap().is_empty());
    not_found(a.sign_passkey(copy, RP, &credential_id, &HASH));
    not_found(a.export_passkey(copy));

    a.set_archived(copy, false).unwrap();
    let listed = a.all_passkeys().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].item_id, copy);
    assert!(signs_with(&a, copy, &credential_id, &point));
    // The export has the key of the registration, and it signs in another vault.
    let export = a.export_passkey(copy).unwrap();
    assert_eq!(exported_point(&a, copy), point);
    let mut fresh = vault(&dir, "fresh.db");
    let imported = fresh
        .import_passkey(PasskeyImport {
            rp_id: export.info.rp_id.clone(),
            credential_id: export.info.credential_id.clone(),
            user_handle: export.info.user_handle.clone(),
            user_name: export.info.user_name.clone(),
            user_display_name: export.info.user_display_name.clone(),
            pkcs8: Zeroizing::new(export.pkcs8.to_vec()),
            title: String::new(),
            attach: None,
        })
        .unwrap();
    assert!(signs_with(&fresh, imported, &credential_id, &point));
    // Archived again, the copy stops signing.
    a.set_archived(copy, true).unwrap();
    assert!(a.all_passkeys().unwrap().is_empty());
    not_found(a.sign_passkey(copy, RP, &credential_id, &HASH));
    not_found(a.export_passkey(copy));
}

#[test]
fn no_passkey_goes_on_a_conflict_copy() {
    let dir = TempDir::new().unwrap();
    let (mut a, mut b, original) = two_macs(&dir);
    // Both Macs edit "Site": the merge keeps a copy without a passkey.
    edit(&mut a, original, "Site A", OLD_PASSWORD);
    later();
    let on_b = id_of(&b, "Site");
    edit(&mut b, on_b, "Site B", NEW_PASSWORD);
    assert_eq!(
        merge(&mut a, &mut b, &dir.path().join("b.copy"), "Mac B"),
        1
    );
    let (&copy, _) = a.conflict_copies().unwrap().first_key_value().unwrap();
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap();
    let import = |credential_id: Vec<u8>, attach: u64| PasskeyImport {
        rp_id: RP.to_owned(),
        credential_id,
        user_handle: b"imported-user".to_vec(),
        user_name: "bob".to_owned(),
        user_display_name: "Bob".to_owned(),
        pkcs8: Zeroizing::new(document.as_ref().to_vec()),
        title: String::new(),
        attach: Some(attach),
    };
    for restored in [false, true] {
        a.set_archived(copy, !restored).unwrap();
        let before = a.details(copy).unwrap().summary.revision;
        assert_eq!(
            kind(attach(&mut a, copy).unwrap_err()),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(
            kind(a.import_passkey(import(vec![9; 20], copy)).unwrap_err()),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(a.details(copy).unwrap().summary.revision, before);
        not_found(a.passkey_info(copy));
    }
    assert!(a.all_passkeys().unwrap().is_empty());
    // The refused import left nothing: the credential can go on the original.
    assert_eq!(
        a.import_passkey(import(vec![9; 20], original)).unwrap(),
        original
    );
    assert!(matches!(
        attach(&mut a, original).unwrap_err(),
        PasskeyError::Exists
    ));
}
