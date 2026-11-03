//! Passkeys through the JSON calls of the core (passkey v1 contract), as the app and
//! the AutoFill extension make them. Synthetic keys and vaults only.

use std::path::Path;

use apassy_core::Core;
use ring::hmac;
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

/// Synthetic RSA and P-521 keys made with `openssl genpkey` for the tests only.
const RSA_2048: &[u8] = include_bytes!("../../../tests/fixtures/passkeys/rsa2048-synthetic.pk8");
const P521: &[u8] = include_bytes!("../../../tests/fixtures/passkeys/p521-synthetic.pk8");

/// Raw DEFLATE of `blob` in one stored block (RFC 1951, section 3.2.4).
fn stored_deflate(blob: &[u8]) -> Vec<u8> {
    let len = u16::try_from(blob.len()).unwrap();
    let mut data = vec![0x01];
    data.extend_from_slice(&len.to_le_bytes());
    data.extend_from_slice(&(!len).to_le_bytes());
    data.extend_from_slice(blob);
    data
}

/// The ID of the passkey with `credential` of `rp`.
fn passkey_id(core: &Core, rp: &str, credential: &[u8]) -> u64 {
    call(
        core,
        json!({"op": "passkey_list", "rp_id": rp, "allowed": [b64(credential)]}),
    )["passkeys"][0]["id"]
        .as_u64()
        .expect("listed")
}

fn assert_request(id: u64, rp: &str, credential: &[u8], byte: u8) -> Value {
    json!({"op": "passkey_assert", "id": id, "rp_id": rp,
           "credential_id": b64(credential), "client_data_hash": hash(byte)})
}

#[test]
fn imported_es384_eddsa_and_rs256_keys_sign_and_p521_fails() {
    use ring::signature::{
        ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING, ED25519, Ed25519KeyPair,
        RSA_PKCS1_2048_8192_SHA256, RsaKeyPair,
    };
    let (_root, _dir, phone) = phone();
    let rng = SystemRandom::new();
    let p384 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
    let p384_public =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, p384.as_ref(), &rng)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
    let ed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let ed_public = Ed25519KeyPair::from_pkcs8(ed.as_ref())
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let rsa_public = RsaKeyPair::from_pkcs8(RSA_2048)
        .unwrap()
        .public()
        .as_ref()
        .to_vec();
    let accounts = json!([
        account("p384.example", b"credential-384", &b64(p384.as_ref())),
        account("ed.example", b"credential-ed", &b64(ed.as_ref())),
        account("rsa.example", b"credential-rsa", &b64(RSA_2048)),
        account("p521.example", b"credential-521", &b64(P521)),
    ]);
    let counts = call(
        &phone,
        json!({"op": "passkey_import", "accounts": accounts}),
    );
    assert_eq!(
        counts,
        json!({"imported": 3, "skipped_existing": 0, "failed": 1})
    );
    type Case<'a> = (
        &'a str,
        &'a [u8],
        i64,
        &'static dyn ring::signature::VerificationAlgorithm,
        &'a [u8],
    );
    let cases: [Case<'_>; 3] = [
        (
            "p384.example",
            b"credential-384",
            -35,
            &ECDSA_P384_SHA384_ASN1,
            &p384_public,
        ),
        ("ed.example", b"credential-ed", -8, &ED25519, &ed_public),
        (
            "rsa.example",
            b"credential-rsa",
            -257,
            &RSA_PKCS1_2048_8192_SHA256,
            &rsa_public,
        ),
    ];
    for (n, (rp, credential, algorithm, verify_with, public)) in cases.into_iter().enumerate() {
        let id = passkey_id(&phone, rp, credential);
        let byte = 20 + n as u8;
        let assertion = call(&phone, assert_request(id, rp, credential, byte));
        assert_eq!(assertion["algorithm"], algorithm, "{rp}");
        assert!(assertion.get("prf").is_none() && assertion.get("large_blob").is_none());
        let mut message = unb64(assertion["authenticator_data"].as_str().unwrap());
        message.extend_from_slice(&unb64(&hash(byte)));
        UnparsedPublicKey::new(verify_with, public)
            .verify(&message, &unb64(assertion["signature"].as_str().unwrap()))
            .expect("the signature checks");
    }
    let empty = call(
        &phone,
        json!({"op": "passkey_list", "rp_id": "p521.example", "allowed": []}),
    );
    assert_eq!(empty["passkeys"], json!([]));
}

#[test]
fn prf_and_large_blob_through_the_app_and_the_extension() {
    let (_root, dir, phone) = phone();
    let (pkcs8, _) = synthetic_key();
    let blob = b"synthetic imported blob";
    let mut with_data = account(RP, b"credential-prf", &b64(&pkcs8));
    with_data["prf"] = json!({"with_uv": b64(&[0x11; 32]), "without_uv": b64(&[0x33; 32])});
    with_data["large_blob"] =
        json!({"data": b64(&stored_deflate(blob)), "uncompressed_size": blob.len()});
    let mut bad_blob = account(RP, b"credential-bad-blob", &b64(&pkcs8));
    bad_blob["large_blob"] =
        json!({"data": b64(&stored_deflate(blob)), "uncompressed_size": blob.len() + 1});
    let mut bad_prf = account(RP, b"credential-bad-prf", &b64(&pkcs8));
    bad_prf["prf"] = json!({"with_uv": b64(&[0x11; 31]), "without_uv": b64(&[0x33; 32])});
    let plain = account(RP, b"credential-plain", &b64(&pkcs8));
    let counts = call(
        &phone,
        json!({"op": "passkey_import", "accounts": [with_data, bad_blob, bad_prf, plain]}),
    );
    assert_eq!(
        counts,
        json!({"imported": 2, "skipped_existing": 0, "failed": 2})
    );
    let id = passkey_id(&phone, RP, b"credential-prf");
    let plain_id = passkey_id(&phone, RP, b"credential-plain");
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[0x11; 32]);
    let prf_of = |salt: &[u8]| -> Vec<u8> { hmac::sign(&key, salt).as_ref().to_vec() };
    let webauthn_salt = |input: &[u8]| -> Vec<u8> {
        let mut bytes = b"WebAuthn PRF\0".to_vec();
        bytes.extend_from_slice(input);
        ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .to_vec()
    };

    // PRF with WebAuthn inputs, and with hashed salts.
    let mut request = assert_request(id, RP, b"credential-prf", 1);
    request["prf"] = json!({"first": b64(b"one"), "second": b64(b"two")});
    let assertion = call(&phone, request);
    assert_eq!(
        unb64(assertion["prf"]["first"].as_str().unwrap()),
        prf_of(&webauthn_salt(b"one"))
    );
    assert_eq!(
        unb64(assertion["prf"]["second"].as_str().unwrap()),
        prf_of(&webauthn_salt(b"two"))
    );
    let mut request = assert_request(id, RP, b"credential-prf", 2);
    request["prf"] = json!({"first": b64(&[0x22; 32]), "hashed": true});
    let assertion = call(&phone, request);
    assert_eq!(
        unb64(assertion["prf"]["first"].as_str().unwrap()),
        prf_of(&[0x22; 32])
    );
    assert!(assertion["prf"].get("second").is_none());
    // No secrets: no output, and the assertion still signs.
    let mut request = assert_request(plain_id, RP, b"credential-plain", 3);
    request["prf"] = json!({"first": b64(b"one")});
    let assertion = call(&phone, request);
    assert!(assertion.get("prf").is_none());
    assert!(!assertion["signature"].as_str().unwrap().is_empty());
    // Bad PRF inputs.
    for prf in [
        json!({"first": b64(&[0x22; 31]), "hashed": true}),
        json!({"first": b64(&[1; 1025])}),
        json!({"first": ""}),
    ] {
        let mut request = assert_request(id, RP, b"credential-prf", 4);
        request["prf"] = prf.clone();
        assert_eq!(fails(&phone, request), "invalid_input", "{prf}");
    }

    // The imported blob reads; a passkey without one reads nothing.
    let mut request = assert_request(id, RP, b"credential-prf", 5);
    request["large_blob"] = json!({"read": true});
    let assertion = call(&phone, request.clone());
    assert_eq!(
        unb64(assertion["large_blob"]["data"].as_str().unwrap()),
        blob
    );
    let mut empty = assert_request(plain_id, RP, b"credential-plain", 5);
    empty["large_blob"] = json!({"read": true});
    assert!(call(&phone, empty).get("large_blob").is_none());

    // The AutoFill extension writes a new blob as part of its assertion.
    let revision = row(&phone, id)["revision"].as_u64().unwrap();
    call(&phone, json!({"op": "lock"}));
    let extension = core(&dir, "autofill");
    call(&extension, json!({"op": "unlock", "passphrase": PASS}));
    let written = b"a blob that the extension wrote".repeat(40);
    let mut write = assert_request(id, RP, b"credential-prf", 6);
    write["large_blob"] = json!({"write": b64(&written)});
    let assertion = call(&extension, write);
    assert_eq!(assertion["large_blob"], json!({"written": true}));
    let mut read = assert_request(id, RP, b"credential-prf", 7);
    read["large_blob"] = json!({"read": true});
    let assertion = call(&extension, read.clone());
    assert_eq!(
        unb64(assertion["large_blob"]["data"].as_str().unwrap()),
        written
    );
    // Too big: written false, and the blob stays.
    let mut big = assert_request(id, RP, b"credential-prf", 8);
    big["large_blob"] = json!({"write": b64(&vec![7u8; 65_537])});
    assert_eq!(
        call(&extension, big)["large_blob"],
        json!({"written": false})
    );
    let assertion = call(&extension, read);
    assert_eq!(
        unb64(assertion["large_blob"]["data"].as_str().unwrap()),
        written
    );
    // Bad largeBlob requests.
    for blob in [
        json!({"read": false}),
        json!({"read": true, "write": b64(b"x")}),
        json!({}),
    ] {
        let mut request = assert_request(id, RP, b"credential-prf", 9);
        request["large_blob"] = blob.clone();
        assert_eq!(fails(&extension, request), "invalid_input", "{blob}");
    }
    call(&extension, json!({"op": "lock"}));

    // The write is a passkey edit: a new revision and a history event without values.
    call(&phone, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(row(&phone, id)["revision"].as_u64().unwrap(), revision + 1);
    let history = call(&phone, json!({"op": "history", "id": id})).to_string();
    assert!(!history.contains(&b64(&written)) && !history.contains("extension wrote"));
    // The generic calls never show the extension fields.
    let detail = call(&phone, json!({"op": "item", "id": id}));
    for field in detail["fields"].as_array().unwrap() {
        assert!(!field["name"].as_str().unwrap().starts_with("passkey_"));
    }
    for field in [
        "passkey_prf_uv",
        "passkey_prf_no_uv",
        "passkey_large_blob",
        "passkey_large_blob_size",
    ] {
        let request = json!({"op": "reveal", "id": id, "field": field});
        assert_eq!(answer(&phone, &request)["ok"], false, "{field}");
    }
}

#[test]
fn an_import_attaches_to_an_existing_login() {
    let (_root, _dir, phone) = phone();
    let saved = call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item": {
            "title": "Existing", "kind": "login", "fields": [
                {"name": "username", "value": "existing-user", "secret": false},
                {"name": "password", "value": "synthetic-password", "secret": true}]}}),
    );
    let id = saved["id"].as_u64().unwrap();
    let (pkcs8, point) = synthetic_key();
    let mut first = account(RP, b"credential-attach", &b64(&pkcs8));
    first["attach_id"] = json!(id);
    let mut second = account(RP, b"credential-attach-2", &b64(&pkcs8));
    second["attach_id"] = json!(id);
    let counts = call(
        &phone,
        json!({"op": "passkey_import", "accounts": [first, second]}),
    );
    // The second account finds a passkey on the login.
    assert_eq!(
        counts,
        json!({"imported": 1, "skipped_existing": 1, "failed": 0})
    );
    assert_eq!(passkey_id(&phone, RP, b"credential-attach"), id);
    assert_eq!(row(&phone, id)["has_passkey"], true);
    let value = call(
        &phone,
        json!({"op": "reveal", "id": id, "field": "password"}),
    );
    assert_eq!(value["value"], "synthetic-password");
    let assertion = call(&phone, assert_request(id, RP, b"credential-attach", 9));
    verify(&point, &assertion, &hash(9));
}
