//! Passkeys through the JSON calls of the core (passkey v1 contract), as the app and
//! the AutoFill extension make them. Synthetic keys and vaults only.

use std::path::Path;

use apassy_core::Core;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-phone-pass";
const RP: &str = "example.com";

// ---- The wire: standard base64 with padding. ----

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
        out.push_str(&"=".repeat(3 - chunk.len()));
    }
    out
}

fn unb64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bits = 0u32;
    let mut count = 0;
    for byte in text.bytes().filter(|b| *b != b'=') {
        let value = ALPHABET.iter().position(|a| *a == byte).expect("base64") as u32;
        bits = bits << 6 | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count & 0xff) as u8);
        }
    }
    out
}

// ---- The core. ----

fn core(dir: &Path, role: &str) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Synthetic iPhone", "role": role});
    Core::new(&config.to_string()).expect("core")
}

fn answer(core: &Core, request: &Value) -> Value {
    serde_json::from_str(&core.call(&request.to_string())).expect("json")
}

fn call(core: &Core, request: Value) -> Value {
    let answer = answer(core, &request);
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

fn fails(core: &Core, request: Value) -> String {
    let answer = answer(core, &request);
    assert_eq!(answer["ok"], false, "{request} -> {answer}");
    assert!(!answer["error"]["message"].as_str().unwrap_or("").is_empty());
    answer["error"]["code"].as_str().expect("code").to_owned()
}

fn phone() -> (TempDir, std::path::PathBuf, Core) {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("Apassy");
    std::fs::create_dir_all(&dir).unwrap();
    let phone = core(&dir, "app");
    call(
        &phone,
        json!({"op": "create_local_vault", "name": "Synthetic", "passphrase": PASS}),
    );
    (root, dir, phone)
}

fn hash(byte: u8) -> String {
    b64(&[byte; 32])
}

fn register_request(rp: &str, user: &str, handle: &[u8], byte: u8) -> Value {
    json!({
        "op": "passkey_register", "rp_id": rp, "user_name": user,
        "user_display_name": "Synthetic User", "user_handle": b64(handle),
        "client_data_hash": hash(byte), "algorithms": [-7, -257], "excluded": [],
        "title": ""
    })
}

fn row(core: &Core, id: u64) -> Value {
    call(core, json!({"op": "items", "archived": "all"}))["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .expect("row")
        .clone()
}

/// The P-256 point of a none-attestation object: the COSE key `{1:2, 3:-7, -1:1, ...}`.
fn public_key(attestation_object: &[u8]) -> Vec<u8> {
    let marker = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    let at = attestation_object
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("cose key");
    let x = &attestation_object[at + marker.len()..][..32];
    let rest = &attestation_object[at + marker.len() + 32..];
    assert_eq!(&rest[..3], &[0x22, 0x58, 0x20]);
    let mut point = vec![4];
    point.extend_from_slice(x);
    point.extend_from_slice(&rest[3..35]);
    point
}

fn verify(point: &[u8], assertion: &Value, client_data_hash: &str) {
    let mut message = unb64(assertion["authenticator_data"].as_str().unwrap());
    message.extend_from_slice(&unb64(client_data_hash));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&message, &unb64(assertion["signature"].as_str().unwrap()))
        .expect("the signature checks");
}

fn synthetic_key() -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    (pkcs8.as_ref().to_vec(), pair.public_key().as_ref().to_vec())
}

fn account(rp: &str, credential: &[u8], key: &str) -> Value {
    json!({
        "rp_id": rp, "credential_id": b64(credential), "user_handle": b64(b"handle-1"),
        "user_name": "imported-user", "user_display_name": "Imported", "key": key,
        "title": "Imported passkey"
    })
}

#[test]
fn the_app_and_the_extension_register_list_and_sign() {
    let (_root, dir, phone) = phone();
    let created = call(
        &phone,
        register_request(RP, "app-user", b"user-handle-1", 1),
    );
    let attestation = unb64(created["attestation_object"].as_str().unwrap());
    let credential = created["credential_id"].as_str().unwrap().to_owned();
    assert_eq!(unb64(&credential).len(), 32);
    let point = public_key(&attestation);

    let listed = call(
        &phone,
        json!({"op": "passkey_list", "rp_id": RP, "allowed": []}),
    );
    let passkeys = listed["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    let entry = &passkeys[0];
    assert_eq!(entry["id"], created["id"]);
    assert_eq!(entry["rp_id"], RP);
    assert_eq!(entry["user_name"], "app-user");
    assert_eq!(entry["user_display_name"], "Synthetic User");
    assert_eq!(entry["credential_id"], credential.as_str());
    assert_eq!(entry["user_handle"], b64(b"user-handle-1"));
    let allowed = call(
        &phone,
        json!({"op": "passkey_list", "rp_id": RP, "allowed": [b64(b"another-credential")]}),
    );
    assert_eq!(allowed["passkeys"], json!([]));
    let other_site = call(
        &phone,
        json!({"op": "passkey_list", "rp_id": "other.example", "allowed": []}),
    );
    assert_eq!(other_site["passkeys"], json!([]));

    let sign = json!({
        "op": "passkey_assert", "id": created["id"], "rp_id": RP,
        "credential_id": credential, "client_data_hash": hash(7)
    });
    let assertion = call(&phone, sign.clone());
    assert_eq!(assertion["credential_id"], credential.as_str());
    assert_eq!(assertion["user_handle"], b64(b"user-handle-1"));
    verify(&point, &assertion, &hash(7));

    // The extension reads and signs with the same vault, and registers a second one.
    call(&phone, json!({"op": "lock"}));
    let extension = core(&dir, "autofill");
    call(&extension, json!({"op": "unlock", "passphrase": PASS}));
    let listed = call(
        &extension,
        json!({"op": "passkey_list", "rp_id": RP, "allowed": []}),
    );
    assert_eq!(listed["passkeys"].as_array().unwrap().len(), 1);
    verify(&point, &call(&extension, sign), &hash(7));
    let second = call(
        &extension,
        register_request(RP, "extension-user", b"user-handle-2", 2),
    );
    assert_ne!(second["id"], created["id"]);
    assert_ne!(second["credential_id"], created["credential_id"]);
    let listed = call(
        &extension,
        json!({"op": "passkey_list", "rp_id": RP, "allowed": []}),
    );
    assert_eq!(listed["passkeys"].as_array().unwrap().len(), 2);

    // The extension cannot import, remove, or save.
    let (pkcs8, _) = synthetic_key();
    assert_eq!(
        fails(
            &extension,
            json!({"op": "passkey_import", "accounts": [account(RP, b"credential-x", &b64(&pkcs8))]})
        ),
        "not_allowed"
    );
    assert_eq!(
        fails(
            &extension,
            json!({"op": "passkey_remove", "id": second["id"], "revision": 1})
        ),
        "not_allowed"
    );
    assert_eq!(
        fails(
            &extension,
            json!({"op": "save", "id": null, "revision": null, "item": {
                "title": "Z", "kind": "login", "fields": [
                    {"name": "username", "value": "z", "secret": false},
                    {"name": "password", "value": "z", "secret": true}]}})
        ),
        "not_allowed"
    );
    assert_eq!(
        call(
            &extension,
            json!({"op": "passkey_list", "rp_id": RP, "allowed": []})
        )["passkeys"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn a_registration_refuses_an_excluded_credential_and_unknown_algorithms() {
    let (_root, _dir, phone) = phone();
    let created = call(
        &phone,
        register_request(RP, "app-user", b"user-handle-1", 1),
    );
    let mut again = register_request(RP, "app-user", b"user-handle-1", 2);
    again["excluded"] = json!([created["credential_id"]]);
    assert_eq!(fails(&phone, again), "excluded");
    let mut unsupported = register_request(RP, "app-user", b"user-handle-3", 3);
    unsupported["algorithms"] = json!([-257, -8]);
    assert_eq!(fails(&phone, unsupported), "unsupported_algorithm");
    let listed = call(
        &phone,
        json!({"op": "passkey_list", "rp_id": RP, "allowed": []}),
    );
    assert_eq!(listed["passkeys"].as_array().unwrap().len(), 1);
}

#[test]
fn a_wrong_site_or_credential_does_not_sign() {
    let (_root, _dir, phone) = phone();
    let created = call(
        &phone,
        register_request(RP, "app-user", b"user-handle-1", 1),
    );
    let sign = |id: Value, rp: &str, credential: Value| {
        json!({"op": "passkey_assert", "id": id, "rp_id": rp,
               "credential_id": credential, "client_data_hash": hash(9)})
    };
    let credential = created["credential_id"].clone();
    let id = created["id"].clone();
    for request in [
        sign(id.clone(), "evil.example", credential.clone()),
        sign(id.clone(), "sub.example.com", credential.clone()),
        sign(id.clone(), RP, json!(b64(b"not-the-credential"))),
        sign(json!(u64::MAX), RP, credential.clone()),
    ] {
        let answer = answer(&phone, &request);
        assert_eq!(answer["ok"], false, "{request}");
        assert!(answer.get("result").is_none());
        assert!(!answer.to_string().contains("signature"));
    }
    // The right call still signs.
    assert!(call(&phone, sign(id, RP, credential))["signature"].is_string());
}

#[test]
fn invalid_encodings_sizes_and_requests_are_refused() {
    let (_root, _dir, phone) = phone();
    let created = call(
        &phone,
        register_request(RP, "app-user", b"user-handle-1", 1),
    );
    let good_assert = json!({
        "op": "passkey_assert", "id": created["id"], "rp_id": RP,
        "credential_id": created["credential_id"], "client_data_hash": hash(1)
    });
    let with = |field: &str, value: Value| {
        let mut request = good_assert.clone();
        request[field] = value;
        request
    };
    for request in [
        // Not standard base64: base64url, no padding, a stray letter, a space.
        with("credential_id", json!("-_-_")),
        with("credential_id", json!("AAAA AAA=")),
        with("credential_id", json!("AAA")),
        with("credential_id", json!("")),
        with("client_data_hash", json!(b64(&[1u8; 31]))),
        with("client_data_hash", json!(b64(&[1u8; 33]))),
        with("client_data_hash", json!("%%%%")),
        with("credential_id", json!(b64(&[1u8; 1024]))),
        with("rp_id", json!("")),
        with("rp_id", json!("example.com/evil")),
        with("rp_id", json!("EXAMPLE.com\n")),
        with("id", json!("1")),
    ] {
        assert_eq!(fails(&phone, request.clone()), "invalid_input", "{request}");
    }
    let register = |field: &str, value: Value| {
        let mut request = register_request(RP, "app-user", b"user-handle-9", 4);
        request[field] = value;
        request
    };
    for request in [
        register("user_handle", json!(b64(&[1u8; 65]))),
        register("user_handle", json!("")),
        register("user_handle", json!("not base64")),
        register("client_data_hash", json!("AAAA")),
        register("user_name", json!("a".repeat(257))),
        register("user_name", json!("bad\u{7}name")),
        register("title", json!("t".repeat(129))),
        register("algorithms", json!(vec![-7; 33])),
        register("excluded", json!(["!!"])),
        register("excluded", json!(vec![b64(b"x"); 257])),
        register("attach_id", json!(created["id"])),
        register("attach_revision", json!(1)),
    ] {
        assert_eq!(fails(&phone, request.clone()), "invalid_input", "{request}");
    }
    // An oversized request is refused before it is read.
    let huge = json!({"op": "passkey_list", "rp_id": RP, "allowed": [], "pad": "x".repeat(4 * 1024 * 1024)});
    assert_eq!(fails(&phone, huge), "invalid_input");
    // Nothing was added by the refused calls.
    assert_eq!(
        call(
            &phone,
            json!({"op": "passkey_list", "rp_id": RP, "allowed": []})
        )["passkeys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // A locked vault answers `locked`.
    call(&phone, json!({"op": "lock"}));
    assert_eq!(fails(&phone, good_assert), "locked");
}

#[test]
fn an_import_counts_each_account_and_never_shows_a_key() {
    let (_root, _dir, phone) = phone();
    let (pkcs8, point) = synthetic_key();
    let key = b64(&pkcs8);
    let (other, _) = synthetic_key();
    let other_key = b64(&other);
    let mut bad_handle = account(RP, b"credential-5", &key);
    bad_handle["user_handle"] = json!(b64(&[1u8; 65]));
    let accounts = json!([
        account(RP, b"credential-1", &key),
        // The same site and credential again.
        account(RP, b"credential-1", &other_key),
        // A key that is not base64, a key that is not a key, a bad site, a bad handle.
        account(RP, b"credential-2", "%%%%"),
        account(RP, b"credential-3", &b64(b"not a pkcs8 key at all")),
        account("bad site", b"credential-4", &key),
        bad_handle,
        account("second.example", b"credential-6", &other_key),
    ]);
    let request = json!({"op": "passkey_import", "accounts": accounts});
    let raw = core_raw(&phone, &request);
    let result = &serde_json::from_str::<Value>(&raw).unwrap()["result"];
    assert_eq!(
        (
            result["imported"].clone(),
            result["skipped_existing"].clone(),
            result["failed"].clone()
        ),
        (json!(2), json!(1), json!(4)),
        "{raw}"
    );
    for secret in [&key, &other_key, &"not a pkcs8 key at all".to_owned()] {
        assert!(!raw.contains(secret.as_str()));
    }

    // The imported key signs, and the answers never hold a key.
    let listed = call(
        &phone,
        json!({"op": "passkey_list", "rp_id": RP, "allowed": []}),
    );
    let entry = &listed["passkeys"][0];
    assert_eq!(entry["user_name"], "imported-user");
    assert_eq!(entry["credential_id"], b64(b"credential-1").as_str());
    let assertion = call(
        &phone,
        json!({"op": "passkey_assert", "id": entry["id"], "rp_id": RP,
               "credential_id": entry["credential_id"], "client_data_hash": hash(5)}),
    );
    verify(&point, &assertion, &hash(5));

    let id = entry["id"].as_u64().unwrap();
    let mut seen = vec![
        listed.to_string(),
        assertion.to_string(),
        call(&phone, json!({"op": "items", "archived": "all"})).to_string(),
        call(&phone, json!({"op": "item", "id": id})).to_string(),
        call(&phone, json!({"op": "history", "id": id})).to_string(),
        call(&phone, json!({"op": "credential_identities"})).to_string(),
        call(&phone, json!({"op": "autofill_list", "domains": [RP]})).to_string(),
    ];
    // Reserved fields are not readable or revealable through the generic calls.
    for field in [
        "passkey_key",
        "passkey_format",
        "passkey_rp_id",
        "passkey_credential_id",
        "passkey_user_handle",
        "passkey_user_name",
        "passkey_user_display_name",
    ] {
        for op in ["reveal", "totp"] {
            let request = json!({"op": op, "id": id, "field": field});
            let answer = answer(&phone, &request);
            assert_eq!(answer["ok"], false, "{request}");
            seen.push(answer.to_string());
        }
    }
    let detail = call(&phone, json!({"op": "item", "id": id}));
    for field in detail["fields"].as_array().unwrap() {
        assert!(!field["name"].as_str().unwrap().starts_with("passkey_"));
    }
    for text in seen {
        assert!(!text.contains(&key) && !text.contains(&other_key), "{text}");
        assert!(!text.contains("private") || !text.contains("BEGIN"));
        assert!(!text.contains("passkey_key"));
    }
}

#[test]
fn only_the_app_removes_and_a_stale_revision_conflicts() {
    let (_root, _dir, phone) = phone();
    let created = call(
        &phone,
        register_request(RP, "app-user", b"user-handle-1", 1),
    );
    let id = created["id"].as_u64().unwrap();
    let revision = row(&phone, id)["revision"].as_u64().unwrap();
    assert_eq!(
        fails(
            &phone,
            json!({"op": "passkey_remove", "id": id, "revision": revision + 100})
        ),
        "conflict"
    );
    call(
        &phone,
        json!({"op": "passkey_remove", "id": id, "revision": revision}),
    );
    assert_eq!(
        call(
            &phone,
            json!({"op": "passkey_list", "rp_id": RP, "allowed": []})
        )["passkeys"],
        json!([])
    );
    // The item was only the passkey, so the vault deletes it with the passkey.
    let rows = call(&phone, json!({"op": "items", "archived": "all"}));
    assert!(
        rows["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["id"] != id)
    );

    // A login with a password keeps the password and loses the passkey.
    let saved = call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item": {
            "title": "Both", "kind": "login", "fields": [
                {"name": "username", "value": "both-user", "secret": false},
                {"name": "password", "value": "synthetic-password", "secret": true}]}}),
    );
    let mut attach = register_request(RP, "both-user", b"user-handle-2", 2);
    attach["attach_id"] = saved["id"].clone();
    attach["attach_revision"] = saved["revision"].clone();
    let both = call(&phone, attach)["id"].as_u64().unwrap();
    let revision = row(&phone, both)["revision"].clone();
    call(
        &phone,
        json!({"op": "passkey_remove", "id": both, "revision": revision}),
    );
    assert_eq!(row(&phone, both)["has_passkey"], false);
    let password = call(
        &phone,
        json!({"op": "reveal", "id": both, "field": "password"}),
    );
    assert_eq!(password["value"], "synthetic-password");
}

#[test]
fn a_passwordless_passkey_login_survives_an_update() {
    let (_root, _dir, phone) = phone();
    let created = call(
        &phone,
        register_request(RP, "app-user", b"user-handle-1", 1),
    );
    let id = created["id"].as_u64().unwrap();
    let before = row(&phone, id);
    assert_eq!(before["has_passkey"], true);
    assert_eq!(before["kind"], "login");
    let detail = call(&phone, json!({"op": "item", "id": id}));
    assert_eq!(detail["passkey"]["rp_id"], RP);
    assert_eq!(detail["passkey"]["credential_id"], created["credential_id"]);
    assert!(
        detail["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["name"] != "password")
    );
    let point = public_key(&unb64(created["attestation_object"].as_str().unwrap()));

    // The owner edits the notes and the website, with no password.
    let edit = |notes: &str, fields: Vec<Value>| {
        json!({"op": "save", "id": id, "revision": row(&phone, id)["revision"],
               "item": {"title": "Example", "kind": "login", "notes": notes, "fields": fields}})
    };
    let username = json!({"name": "username", "value": "app-user", "secret": false});
    let saved = call(
        &phone,
        edit(
            "edited",
            vec![
                username.clone(),
                json!({"label": "Website", "value": "https://example.com", "secret": false}),
            ],
        ),
    );
    assert!(saved["revision"].as_u64().unwrap() > before["revision"].as_u64().unwrap());
    assert_eq!(row(&phone, id)["has_passkey"], true);
    assert_eq!(
        call(&phone, json!({"op": "item", "id": id}))["notes"],
        "edited"
    );
    let assertion = call(
        &phone,
        json!({"op": "passkey_assert", "id": id, "rp_id": RP,
               "credential_id": created["credential_id"], "client_data_hash": hash(3)}),
    );
    verify(&point, &assertion, &hash(3));

    // A reserved name is refused, however it is typed, and nothing is lost.
    for name in ["passkey_key", "passkey_rp_id", "passkey_extra"] {
        let request = edit(
            "edited",
            vec![
                username.clone(),
                json!({"name": name, "value": "x", "secret": true}),
            ],
        );
        assert_eq!(fails(&phone, request), "invalid_input", "{name}");
    }
    let custom = json!({"op": "save", "id": null, "revision": null, "item": {
        "title": "Other", "kind": "custom", "fields": [
            {"name": "passkey_key", "value": "x", "secret": true}]}});
    assert_eq!(fails(&phone, custom), "invalid_input");
    assert_eq!(
        call(
            &phone,
            json!({"op": "passkey_list", "rp_id": RP, "allowed": []})
        )["passkeys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // A passkey-only login can keep no account name. Its passkey still signs.
    call(&phone, edit("edited", vec![]));
    assert_eq!(row(&phone, id)["has_passkey"], true);
    let without_name = call(
        &phone,
        json!({"op": "passkey_assert", "id": id, "rp_id": RP,
               "credential_id": created["credential_id"], "client_data_hash": hash(3)}),
    );
    verify(&point, &without_name, &hash(3));
    // A new login still needs its username and password.
    let new_login = json!({"op": "save", "id": null, "revision": null, "item": {
        "title": "No password", "kind": "login", "fields": [username.clone()]}});
    assert_eq!(fails(&phone, new_login), "invalid_input");

    // AutoFill does not offer a password that is not there.
    let list = call(&phone, json!({"op": "autofill_list", "domains": [RP]}));
    assert_eq!(list["matches"], json!([]));
    assert_eq!(list["others"], json!([]));
    assert_eq!(
        fails(&phone, json!({"op": "autofill_credential", "id": id})),
        "not_found"
    );

    // Adding a password later is allowed, and the passkey stays.
    call(
        &phone,
        edit(
            "edited",
            vec![
                username,
                json!({"label": "Website", "value": "https://example.com", "secret": false}),
                json!({"name": "password", "value": "synthetic-password", "secret": true}),
            ],
        ),
    );
    let list = call(&phone, json!({"op": "autofill_list", "domains": [RP]}));
    assert_eq!(list["matches"].as_array().unwrap().len(), 1);
    assert_eq!(row(&phone, id)["has_passkey"], true);
}

#[test]
fn a_passkey_attaches_to_an_existing_login() {
    let (_root, _dir, phone) = phone();
    let saved = call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item": {
            "title": "Existing", "kind": "login", "fields": [
                {"name": "username", "value": "existing-user", "secret": false},
                {"name": "password", "value": "synthetic-password", "secret": true},
                {"label": "Website", "value": "https://example.com", "secret": false}]}}),
    );
    let mut request = register_request(RP, "existing-user", b"user-handle-5", 5);
    request["attach_id"] = saved["id"].clone();
    request["attach_revision"] = json!(saved["revision"].as_u64().unwrap() + 50);
    assert_eq!(fails(&phone, request.clone()), "conflict");
    request["attach_revision"] = saved["revision"].clone();
    let created = call(&phone, request);
    assert_eq!(created["id"], saved["id"]);
    let id = saved["id"].as_u64().unwrap();
    assert_eq!(row(&phone, id)["has_passkey"], true);
    // The password is still there and still revealable.
    let value = call(
        &phone,
        json!({"op": "reveal", "id": id, "field": "password"}),
    );
    assert_eq!(value["value"], "synthetic-password");
    // A second passkey on the same login is refused.
    let mut again = register_request(RP, "existing-user", b"user-handle-6", 6);
    again["attach_id"] = saved["id"].clone();
    again["attach_revision"] = row(&phone, id)["revision"].clone();
    assert!(!answer(&phone, &again)["ok"].as_bool().unwrap());
}

#[test]
fn identities_hold_passkeys_and_codes_without_secrets() {
    let (_root, _dir, phone) = phone();
    let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let uri = format!("otpauth://totp/Test?secret={seed}");
    call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item": {
            "title": "Imported login", "kind": "login", "fields": [
                {"name": "username", "value": "imported-user", "secret": false},
                {"name": "password", "value": "synthetic-password", "secret": true},
                {"label": "Website", "value": "https://login.example.org", "secret": false},
                {"label": "Authenticator", "value": uri, "secret": true}]}}),
    );
    let created = call(
        &phone,
        register_request(RP, "app-user", b"user-handle-1", 1),
    );
    let identities = call(&phone, json!({"op": "credential_identities"}));
    // The login with a password.
    let logins = identities["identities"].as_array().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0]["host"], "login.example.org");
    // The custom-titled one-time password, found by its URI.
    let codes = identities["totp"].as_array().unwrap();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0]["host"], "login.example.org");
    assert_eq!(codes[0]["username"], "imported-user");
    // The passkey, with no password needed.
    let passkeys = identities["passkeys"].as_array().unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0]["id"], created["id"]);
    assert_eq!(passkeys[0]["rp_id"], RP);
    assert_eq!(passkeys[0]["credential_id"], created["credential_id"]);
    assert_eq!(passkeys[0]["user_handle"], b64(b"user-handle-1").as_str());
    let text = identities.to_string();
    assert!(!text.contains(seed) && !text.contains("synthetic-password"));
    assert!(!text.contains("passkey_key") && !text.contains("pkcs8"));
}

fn core_raw(core: &Core, request: &Value) -> String {
    core.call(&request.to_string())
}
