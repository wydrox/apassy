#![cfg(feature = "vault")]

//! Passkeys (schema 17): registration and assertion as a relying party checks them,
//! storage rules, and sync. Synthetic values only.

use apassy::contracts::CredentialKind;
use apassy::vault::passkey::ES256;
use apassy::vault::{
    Field, ItemDraft, PasskeyAssertion, PasskeyCreate, PasskeyCreated, PasskeyError, PasskeyImport,
    PasskeyTarget, SecretValue, SyncScope, Vault, VaultErrorKind,
};
use ciborium::value::Value;
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASS: &str = "synthetic-passkey-pass";
const RP: &str = "example.com";
const HASH: [u8; 32] = [0x5a; 32];
const RESERVED: [&str; 7] = [
    "passkey_format",
    "passkey_rp_id",
    "passkey_credential_id",
    "passkey_user_handle",
    "passkey_user_name",
    "passkey_user_display_name",
    "passkey_key",
];

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

fn login(title: &str, password: Option<&str>) -> ItemDraft {
    let mut fields = vec![field("username", "alice", false)];
    if let Some(password) = password {
        fields.push(field("password", password, true));
    }
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::Login,
        notes: String::new(),
        tags: Vec::new(),
        fields,
    }
}

fn request<'a>(
    rp_id: &'a str,
    exclude: &'a [Vec<u8>],
    algorithms: &'a [i64],
    target: PasskeyTarget,
) -> PasskeyCreate<'a> {
    PasskeyCreate {
        rp_id,
        user_handle: b"synthetic-user-1",
        user_name: "alice",
        user_display_name: "Alice Example",
        client_data_hash: &HASH,
        algorithms,
        exclude,
        target,
    }
}

fn new_item(title: &str) -> PasskeyTarget {
    PasskeyTarget::NewItem {
        title: title.to_owned(),
    }
}

fn create(vault: &mut Vault, rp_id: &str, title: &str) -> PasskeyCreated {
    vault
        .create_passkey(request(rp_id, &[], &[ES256], new_item(title)))
        .unwrap()
}

fn vault_kind(error: PasskeyError) -> VaultErrorKind {
    match error {
        PasskeyError::Vault(vault) => vault.kind(),
        other => panic!("not a vault error: {other:?}"),
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}

/// One CBOR item from `bytes`; the item must use all the bytes.
fn cbor_all(bytes: &[u8]) -> Value {
    let mut reader = bytes;
    let value: Value = ciborium::de::from_reader(&mut reader).unwrap();
    assert!(reader.is_empty(), "trailing CBOR bytes");
    value
}

fn int(value: &Value) -> i128 {
    value.as_integer().map(i128::from).unwrap()
}

/// Check a registration as a relying party: "none" attestation, the authenticator data,
/// and the COSE key. Returns the uncompressed public point.
fn verify_registration(rp_id: &str, created: &PasskeyCreated) -> Vec<u8> {
    assert_eq!(created.algorithm, -7);
    let Value::Map(object) = cbor_all(&created.attestation_object) else {
        panic!("attestation object is not a map");
    };
    let keys: Vec<&str> = object.iter().map(|(k, _)| k.as_text().unwrap()).collect();
    assert_eq!(
        keys,
        ["fmt", "attStmt", "authData"],
        "CTAP2 canonical order"
    );
    assert_eq!(object[0].1.as_text(), Some("none"));
    assert_eq!(object[1].1.as_map().map(Vec::len), Some(0));
    let auth = object[2].1.as_bytes().unwrap();
    assert_eq!(auth, &created.authenticator_data);

    assert_eq!(&auth[..32], sha256(rp_id.as_bytes()).as_slice());
    let flags = auth[32];
    assert_eq!(flags & 0x01, 0x01, "UP");
    assert_eq!(flags & 0x04, 0x04, "UV");
    assert_eq!(flags & 0x08, 0x08, "BE");
    assert_eq!(flags & 0x10, 0, "BS is not claimed");
    assert_eq!(flags & 0x40, 0x40, "AT");
    assert_eq!(flags & 0x80, 0, "no extensions");
    assert_eq!(&auth[33..37], &[0, 0, 0, 0], "counter");
    assert_eq!(&auth[37..53], &[0u8; 16], "AAGUID");
    let len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    assert_eq!(len, 32);
    assert_eq!(&auth[55..55 + len], created.credential_id.as_slice());
    let cose_bytes = &auth[55 + len..];
    // Exact canonical prefixes, independent of the CBOR library.
    assert_eq!(
        &cose_bytes[..10],
        &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
    );
    assert_eq!(
        &created.attestation_object[..30],
        b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58\xa4"
    );
    let Value::Map(cose) = cbor_all(cose_bytes) else {
        panic!("COSE key is not a map");
    };
    let labels: Vec<i128> = cose.iter().map(|(k, _)| int(k)).collect();
    assert_eq!(labels, [1, 3, -1, -2, -3]);
    assert_eq!(int(&cose[0].1), 2, "kty EC2");
    assert_eq!(int(&cose[1].1), -7, "alg ES256");
    assert_eq!(int(&cose[2].1), 1, "crv P-256");
    let x = cose[3].1.as_bytes().unwrap();
    let y = cose[4].1.as_bytes().unwrap();
    assert_eq!((x.len(), y.len()), (32, 32));
    let mut point = vec![0x04];
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    assert_eq!(created.public_key_spki.len(), 91);
    assert_eq!(&created.public_key_spki[..2], &[0x30, 0x59]);
    assert_eq!(&created.public_key_spki[26..], point.as_slice());
    point
}

/// Check an assertion as a relying party with `ring`. Returns false for a bad signature.
fn verify_assertion(rp_id: &str, point: &[u8], hash: &[u8; 32], a: &PasskeyAssertion) -> bool {
    let auth = &a.authenticator_data;
    assert_eq!(auth.len(), 37);
    if auth[..32] != *sha256(rp_id.as_bytes()) {
        return false;
    }
    assert_eq!(auth[32], 0x01 | 0x04 | 0x08, "UP, UV, BE");
    assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
    let mut message = auth.clone();
    message.extend_from_slice(hash);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&message, &a.signature)
        .is_ok()
}

#[test]
fn registration_and_assertion_verify_and_wrong_inputs_fail() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let created = create(&mut vault, RP, "Example");
    let point = verify_registration(RP, &created);
    let other = create(&mut vault, "other.example", "Other");
    let other_point = verify_registration("other.example", &other);
    assert_ne!(created.credential_id, other.credential_id);

    let assertion = vault
        .sign_passkey(created.item_id, RP, &created.credential_id, &HASH)
        .unwrap();
    assert_eq!(assertion.credential_id, created.credential_id);
    assert_eq!(assertion.user_handle, b"synthetic-user-1");
    assert!(verify_assertion(RP, &point, &HASH, &assertion));
    // A relying party with another challenge, another key, or another RP ID refuses it.
    assert!(!verify_assertion(RP, &point, &[0x5b; 32], &assertion));
    assert!(!verify_assertion(RP, &other_point, &HASH, &assertion));
    assert!(!verify_assertion(
        "other.example",
        &point,
        &HASH,
        &assertion
    ));
    // ECDSA signatures are random; each one verifies.
    let again = vault
        .sign_passkey(created.item_id, RP, &created.credential_id, &HASH)
        .unwrap();
    assert!(verify_assertion(RP, &point, &HASH, &again));

    // The vault does not sign for another RP ID or credential ID.
    for (rp, id) in [
        ("other.example", created.credential_id.clone()),
        (RP, other.credential_id.clone()),
        (RP, vec![1, 2, 3]),
    ] {
        let error = vault
            .sign_passkey(created.item_id, rp, &id, &HASH)
            .unwrap_err();
        assert_eq!(vault_kind(error), VaultErrorKind::NotFound);
    }

    let info = vault.passkey_info(created.item_id).unwrap();
    assert_eq!(info.rp_id, RP);
    assert_eq!(info.title, "Example");
    assert_eq!(info.user_name, "alice");
    assert_eq!(info.user_display_name, "Alice Example");
    assert_eq!(info.credential_id, created.credential_id);
    assert_eq!(vault.passkeys(RP, &[]).unwrap(), vec![info.clone()]);
    assert_eq!(
        vault
            .passkeys(RP, std::slice::from_ref(&created.credential_id))
            .unwrap(),
        vec![info]
    );
    assert!(vault.passkeys(RP, &[vec![9; 32]]).unwrap().is_empty());
    assert_eq!(vault.all_passkeys().unwrap().len(), 2);
}

#[test]
fn generic_details_reveal_catalog_and_bindings_never_show_passkey_fields() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let created = create(&mut vault, RP, "Example");
    let details = vault.details(created.item_id).unwrap();
    assert_eq!(details.summary.kind, CredentialKind::Login);
    let names: Vec<&str> = details.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["username"]);
    for name in RESERVED {
        assert_eq!(
            vault.reveal(created.item_id, name).unwrap_err().kind(),
            VaultErrorKind::NotFound,
            "{name}"
        );
    }
    assert_eq!(
        vault
            .reveal(created.item_id, "password")
            .unwrap_err()
            .kind(),
        VaultErrorKind::NotFound
    );
    let catalog = vault.catalog().unwrap();
    let entry = catalog
        .iter()
        .find(|entry| entry.item_id == created.item_id)
        .unwrap();
    assert!(
        entry
            .details
            .iter()
            .all(|(name, _)| !name.starts_with("passkey"))
    );
    assert_eq!(
        vault
            .set_env_binding(created.item_id, "SYNTH_KEY", "passkey_key")
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidInput
    );
}

#[test]
fn algorithms_and_bad_requests_are_refused() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let error = vault
        .create_passkey(request(RP, &[], &[-257, -8], new_item("RSA only")))
        .unwrap_err();
    assert!(matches!(error, PasskeyError::NoSupportedAlgorithm));
    // An empty list is the WebAuthn default, which has ES256. Order does not matter.
    for algorithms in [&[][..], &[-257, -7][..]] {
        let created = vault
            .create_passkey(request(RP, &[], algorithms, new_item("Default")))
            .unwrap();
        verify_registration(RP, &created);
    }
    for rp in ["", "Example.com", "example.com.", "https://example.com"] {
        let error = vault
            .create_passkey(request(rp, &[], &[ES256], new_item("Bad")))
            .unwrap_err();
        assert_eq!(vault_kind(error), VaultErrorKind::InvalidInput, "{rp}");
    }
    for handle in [&[][..], &[7u8; 65][..]] {
        let mut bad = request(RP, &[], &[ES256], new_item("Bad"));
        bad.user_handle = handle;
        assert_eq!(
            vault_kind(vault.create_passkey(bad).unwrap_err()),
            VaultErrorKind::InvalidInput
        );
    }
    let error = vault
        .create_passkey(request(RP, &[], &[ES256], new_item("   ")))
        .unwrap_err();
    assert_eq!(vault_kind(error), VaultErrorKind::InvalidInput);
    // Long names are cut at a character boundary.
    let long = "ż".repeat(300);
    let mut named = request(RP, &[], &[ES256], new_item("Long"));
    named.user_name = &long;
    let created = vault.create_passkey(named).unwrap();
    let info = vault.passkey_info(created.item_id).unwrap();
    assert_eq!(info.user_name.len(), 256);
    assert!(long.starts_with(&info.user_name));
}

#[test]
fn excluded_and_duplicate_credentials_are_refused() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let created = create(&mut vault, RP, "Example");
    let exclude = vec![vec![1u8; 16], created.credential_id.clone()];
    let error = vault
        .create_passkey(request(RP, &exclude, &[ES256], new_item("Again")))
        .unwrap_err();
    assert!(matches!(error, PasskeyError::Excluded));
    // The same credential ID for another RP ID does not exclude.
    vault
        .create_passkey(request(
            "other.example",
            &exclude,
            &[ES256],
            new_item("Other"),
        ))
        .unwrap();
    // An archived passkey still excludes.
    vault.set_archived(created.item_id, true).unwrap();
    let error = vault
        .create_passkey(request(RP, &exclude, &[ES256], new_item("Again")))
        .unwrap_err();
    assert!(matches!(error, PasskeyError::Excluded));
    assert!(vault.passkeys(RP, &[]).unwrap().is_empty());
    assert_eq!(
        vault_kind(
            vault
                .sign_passkey(created.item_id, RP, &created.credential_id, &HASH)
                .unwrap_err()
        ),
        VaultErrorKind::NotFound
    );
    // An item with a passkey gets no second one.
    vault.set_archived(created.item_id, false).unwrap();
    let revision = vault.details(created.item_id).unwrap().summary.revision;
    let target = PasskeyTarget::Attach {
        item_id: created.item_id,
        revision,
    };
    let error = vault
        .create_passkey(request(RP, &[], &[ES256], target))
        .unwrap_err();
    assert!(matches!(error, PasskeyError::Exists));
}

#[test]
fn generic_add_and_update_keep_their_rules_and_keep_the_passkey() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    // An ordinary login needs a password, and no draft names a passkey field.
    assert_eq!(
        vault.add(login("No password", None)).unwrap_err().kind(),
        VaultErrorKind::InvalidInput
    );
    for name in RESERVED {
        let mut draft = login("Reserved", Some("SYNTH-pass"));
        draft
            .fields
            .push(field(name, "SYNTH-value", name == "passkey_key"));
        assert_eq!(
            vault.add(draft).unwrap_err().kind(),
            VaultErrorKind::InvalidInput,
            "{name}"
        );
    }
    let ordinary = vault.add(login("Ordinary", Some("SYNTH-pass"))).unwrap();
    assert_eq!(
        vault
            .update(ordinary.id, ordinary.revision, login("Ordinary", None))
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidInput
    );

    let created = create(&mut vault, RP, "Example");
    let point = verify_registration(RP, &created);
    let before = vault.passkey_info(created.item_id).unwrap();
    let details = vault.details(created.item_id).unwrap();
    // The draft that an editor makes from details: no passkey field, no password.
    let mut draft = ItemDraft {
        title: "Example renamed".to_owned(),
        kind: CredentialKind::Login,
        notes: "SYNTH note".to_owned(),
        tags: vec!["web".to_owned()],
        fields: vec![field("username", "alice2", false)],
    };
    let updated = vault
        .update(created.item_id, details.summary.revision, draft.clone())
        .unwrap();
    assert_eq!(updated.revision, details.summary.revision + 1);
    let after = vault.passkey_info(created.item_id).unwrap();
    assert_eq!(after.title, "Example renamed");
    assert_eq!(
        (after.credential_id.clone(), after.user_handle.clone()),
        (before.credential_id.clone(), before.user_handle.clone())
    );
    let assertion = vault
        .sign_passkey(created.item_id, RP, &created.credential_id, &HASH)
        .unwrap();
    assert!(verify_assertion(RP, &point, &HASH, &assertion));
    let names: Vec<String> = vault
        .details(created.item_id)
        .unwrap()
        .fields
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert_eq!(names, ["username"]);
    // A draft cannot replace a passkey field, and a password must be secret.
    let mut reserved = draft.clone();
    reserved.fields.push(field("passkey_key", "SYNTH", true));
    assert_eq!(
        vault
            .update(created.item_id, updated.revision, reserved)
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidInput
    );
    let mut plain_password = draft.clone();
    plain_password
        .fields
        .push(field("password", "SYNTH", false));
    assert_eq!(
        vault
            .update(created.item_id, updated.revision, plain_password)
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidInput
    );
    draft.fields.push(field("password", "SYNTH-added", true));
    let with_password = vault
        .update(created.item_id, updated.revision, draft)
        .unwrap();
    assert_eq!(
        vault.reveal(created.item_id, "password").unwrap().expose(),
        "SYNTH-added"
    );
    assert!(vault.passkey_info(created.item_id).is_ok());
    // The history names no passkey field.
    let events = vault
        .item_events(created.item_id, apassy::vault::MAX_ITEM_EVENTS)
        .unwrap();
    assert!(
        events
            .iter()
            .all(|event| !event.detail.contains("passkey_"))
    );
    assert_eq!(with_password.revision, updated.revision + 1);
}

#[test]
fn attach_and_remove_use_revisions() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let item = vault.add(login("Site", Some("SYNTH-pass"))).unwrap();
    let stale = PasskeyTarget::Attach {
        item_id: item.id,
        revision: item.revision + 1,
    };
    let error = vault
        .create_passkey(request(RP, &[], &[ES256], stale))
        .unwrap_err();
    assert_eq!(vault_kind(error), VaultErrorKind::Conflict);
    let api = vault
        .add(ItemDraft {
            title: "Token".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![field("token", "SYNTH-token", true)],
        })
        .unwrap();
    let error = vault
        .create_passkey(request(
            RP,
            &[],
            &[ES256],
            PasskeyTarget::Attach {
                item_id: api.id,
                revision: api.revision,
            },
        ))
        .unwrap_err();
    assert_eq!(vault_kind(error), VaultErrorKind::InvalidInput);

    let created = vault
        .create_passkey(request(
            RP,
            &[],
            &[ES256],
            PasskeyTarget::Attach {
                item_id: item.id,
                revision: item.revision,
            },
        ))
        .unwrap();
    assert_eq!(created.item_id, item.id);
    verify_registration(RP, &created);
    let revision = vault.details(item.id).unwrap().summary.revision;
    assert_eq!(revision, item.revision + 1);
    assert_eq!(
        vault.reveal(item.id, "password").unwrap().expose(),
        "SYNTH-pass"
    );

    // Remove: a stale revision conflicts; the item keeps its password.
    assert_eq!(
        vault_kind(vault.remove_passkey(item.id, item.revision).unwrap_err()),
        VaultErrorKind::Conflict
    );
    vault.remove_passkey(item.id, revision).unwrap();
    let details = vault.details(item.id).unwrap();
    assert_eq!(details.summary.revision, revision + 1);
    assert_eq!(
        vault.reveal(item.id, "password").unwrap().expose(),
        "SYNTH-pass"
    );
    assert_eq!(
        vault_kind(vault.passkey_info(item.id).unwrap_err()),
        VaultErrorKind::NotFound
    );
    assert_eq!(
        vault_kind(vault.remove_passkey(item.id, revision + 1).unwrap_err()),
        VaultErrorKind::NotFound
    );
    // A passkey-only item goes with its passkey.
    let only = create(&mut vault, RP, "Only");
    let revision = vault.details(only.item_id).unwrap().summary.revision;
    vault.remove_passkey(only.item_id, revision).unwrap();
    assert_eq!(
        vault.details(only.item_id).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
    assert!(vault.all_passkeys().unwrap().is_empty());
}

#[test]
fn import_checks_the_key_and_signs_with_it() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "v.db");
    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng).unwrap();
    let import = |key: &[u8], credential_id: Vec<u8>, attach: Option<u64>| PasskeyImport {
        rp_id: RP.to_owned(),
        credential_id,
        user_handle: b"imported-user".to_vec(),
        user_name: "bob".to_owned(),
        user_display_name: "Bob".to_owned(),
        pkcs8: Zeroizing::new(key.to_vec()),
        title: String::new(),
        attach,
    };
    let id = vault
        .import_passkey(import(document.as_ref(), vec![3; 20], None))
        .unwrap();
    let info = vault.passkey_info(id).unwrap();
    assert_eq!(info.title, RP);
    let assertion = vault.sign_passkey(id, RP, &[3; 20], &HASH).unwrap();
    assert!(verify_assertion(
        RP,
        pair.public_key().as_ref(),
        &HASH,
        &assertion
    ));
    // The same RP ID and credential ID again.
    let error = vault
        .import_passkey(import(document.as_ref(), vec![3; 20], None))
        .unwrap_err();
    assert!(matches!(error, PasskeyError::Exists));
    // Damaged keys.
    let mut bad = document.as_ref().to_vec();
    bad[40] ^= 0xff;
    for key in [&bad[..], &document.as_ref()[..100], &[][..]] {
        let error = vault
            .import_passkey(import(key, vec![4; 20], None))
            .unwrap_err();
        assert!(matches!(error, PasskeyError::BadKey));
    }
    let error = vault
        .import_passkey(import(document.as_ref(), Vec::new(), None))
        .unwrap_err();
    assert_eq!(vault_kind(error), VaultErrorKind::InvalidInput);
    // Attach to a login without a passkey.
    let item = vault.add(login("Bob site", Some("SYNTH-pass"))).unwrap();
    let attached = vault
        .import_passkey(import(document.as_ref(), vec![5; 20], Some(item.id)))
        .unwrap();
    assert_eq!(attached, item.id);
    let error = vault
        .import_passkey(import(document.as_ref(), vec![6; 20], Some(item.id)))
        .unwrap_err();
    assert!(matches!(error, PasskeyError::Exists));
}

#[test]
fn passkeys_sync_and_conflict_copies_are_not_listed_twice() {
    let dir = TempDir::new().unwrap();
    let mut a = vault(&dir, "a.db");
    let created = create(&mut a, RP, "Example");
    let point = verify_registration(RP, &created);
    let seed = dir.path().join("seed.db");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    let on_b = b.passkeys(RP, &[]).unwrap();
    assert_eq!(on_b.len(), 1);
    let b_item = on_b[0].item_id;
    let assertion = b
        .sign_passkey(b_item, RP, &created.credential_id, &HASH)
        .unwrap();
    assert!(verify_assertion(RP, &point, &HASH, &assertion));

    // Both sides edit the item: the merge keeps an archived conflict copy.
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
    let report = a.merge_from(&remote, &SyncScope::vault()).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    let copies = a.conflict_copies().unwrap();
    let (&copy, _) = copies.first_key_value().unwrap();
    assert!(a.is_archived(copy).unwrap());
    let copy_info = a.passkey_info(copy).unwrap();
    assert_eq!(copy_info.credential_id, created.credential_id);
    let listed = a.passkeys(RP, &[]).unwrap();
    assert_eq!(listed.len(), 1);
    assert_ne!(listed[0].item_id, copy);
    // The owner brings the copy back: the list still has one entry, not the copy.
    a.set_archived(copy, false).unwrap();
    let listed = a.passkeys(RP, &[]).unwrap();
    assert_eq!(listed.len(), 1);
    assert_ne!(listed[0].item_id, copy);
    assert_eq!(a.all_passkeys().unwrap().len(), 1);
    // A conflict copy of a credential that its original has never signs, even
    // restored; the original does.
    assert_eq!(
        vault_kind(
            a.sign_passkey(copy, RP, &created.credential_id, &HASH)
                .unwrap_err()
        ),
        VaultErrorKind::NotFound
    );
    let from_original = a
        .sign_passkey(listed[0].item_id, RP, &created.credential_id, &HASH)
        .unwrap();
    assert!(verify_assertion(RP, &point, &HASH, &from_original));
}
