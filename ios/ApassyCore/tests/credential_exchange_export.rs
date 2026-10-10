//! The Credential Exchange export (`credential_export`) through the JSON calls of the
//! core: the scope, the values, the roles, the history, and a round trip of the answer
//! into a fresh vault with the import calls. Synthetic vaults and keys only.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use apassy::vault::{SyncScope, Vault};
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
const PREPARED: &str = "Prepared for a Credential Exchange transfer";
/// "12345678901234567890", the RFC 6238 seed.
const SEED32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SEED_BYTES: &[u8] = b"12345678901234567890";
const PASSWORD_A: &str = "synthetic-password-alpha";
const PASSWORD_C: &str = "synthetic-password-gamma";
const PASSWORD_K: &str = "synthetic-password-counter";

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

fn base32(bytes: &[u8]) -> String {
    const LETTERS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut bits, mut count) = (0u32, 0);
    for byte in bytes {
        bits = bits << 8 | u32::from(*byte);
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(char::from(LETTERS[(bits >> count & 31) as usize]));
        }
    }
    if count > 0 {
        out.push(char::from(LETTERS[(bits << (5 - count) & 31) as usize]));
    }
    out
}

/// RFC 6238, computed here and not by the core.
fn code(key: &[u8], algorithm: &str, digits: u32, period: u64, unix: u64) -> String {
    let algorithm = match algorithm {
        "sha1" => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        "sha256" => hmac::HMAC_SHA256,
        "sha512" => hmac::HMAC_SHA512,
        other => panic!("algorithm {other}"),
    };
    let tag = hmac::sign(
        &hmac::Key::new(algorithm, key),
        &(unix / period).to_be_bytes(),
    );
    let tag = tag.as_ref();
    let at = usize::from(tag[tag.len() - 1] & 15);
    let value = u32::from_be_bytes([tag[at] & 0x7f, tag[at + 1], tag[at + 2], tag[at + 3]]);
    format!(
        "{:0width$}",
        value % 10u32.pow(digits),
        width = digits as usize
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---- The core. ----

fn core(dir: &Path, role: &str) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Synthetic iPhone", "role": role});
    Core::new(&config.to_string()).expect("core")
}

fn answer(core: &Core, request: &Value) -> Value {
    serde_json::from_str(&core.call(&request.to_string())).expect("json")
}

fn raw(core: &Core, request: &Value) -> String {
    core.call(&request.to_string())
}

fn call(core: &Core, request: Value) -> Value {
    let answer = answer(core, &request);
    assert_eq!(answer["ok"], true, "{request} -> {}", answer["error"]);
    answer["result"].clone()
}

fn fails(core: &Core, request: Value) -> (String, String) {
    let answer = answer(core, &request);
    assert_eq!(answer["ok"], false);
    (
        answer["error"]["code"].as_str().expect("code").to_owned(),
        answer["error"]["message"].as_str().unwrap().to_owned(),
    )
}

fn phone() -> (TempDir, PathBuf, Core) {
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

fn save(core: &Core, title: &str, kind: &str, fields: Vec<Value>) -> Value {
    call(
        core,
        json!({"op": "save", "id": null, "revision": null, "item": {
            "title": title, "kind": kind, "notes": format!("notes of {title}"),
            "tags": ["synthetic", "transfer"], "fields": fields}}),
    )
}

fn plain(name: &str, value: &str) -> Value {
    json!({"name": name, "value": value, "secret": false})
}

fn hidden(name: &str, value: &str) -> Value {
    json!({"name": name, "value": value, "secret": true})
}

fn register(core: &Core, rp: &str, user: &str, handle: &[u8], byte: u8) -> Value {
    call(
        core,
        json!({
            "op": "passkey_register", "rp_id": rp, "user_name": user,
            "user_display_name": "Synthetic User", "user_handle": b64(handle),
            "client_data_hash": b64(&[byte; 32]), "algorithms": [-7], "excluded": [],
            "title": format!("{user} at {rp}")
        }),
    )
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

fn assert_and_verify(core: &Core, id: u64, passkey: &Value, point: &[u8], byte: u8) {
    let hash = b64(&[byte; 32]);
    let assertion = call(
        core,
        json!({"op": "passkey_assert", "id": id, "rp_id": passkey["rp_id"],
               "credential_id": passkey["credential_id"], "client_data_hash": hash}),
    );
    let mut message = unb64(assertion["authenticator_data"].as_str().unwrap());
    message.extend_from_slice(&[byte; 32]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&message, &unb64(assertion["signature"].as_str().unwrap()))
        .expect("the signature checks");
}

struct Fixture {
    _root: TempDir,
    dir: PathBuf,
    phone: Core,
    /// The ids of the logins that the export holds.
    alpha: u64,
    passkey_only: u64,
    gamma: u64,
    counter: u64,
    /// The ids that it does not hold.
    archived: u64,
    api_key: u64,
    custom: u64,
    point_passkey_only: Vec<u8>,
    point_gamma: Vec<u8>,
}

fn fixture() -> Fixture {
    let (root, dir, phone) = phone();
    let alpha = save(
        &phone,
        "Alpha Bank",
        "login",
        vec![
            plain("username", "alpha-user"),
            hidden("password", PASSWORD_A),
            json!({"label": "Website", "value": "https://bank.example.test/login", "secret": false}),
            json!({"label": "Website 2", "value": "https://www.bank-alt.example.test", "secret": false}),
            json!({"label": "One-time password", "secret": true, "value": format!(
                "otpauth://totp/Alpha%20Bank:alpha%40example.test?secret={SEED32}&algorithm=SHA256&digits=8&period=60&issuer=Alpha%20Bank")}),
            json!({"label": "Recovery hint", "value": "synthetic-hint", "secret": true}),
        ],
    )["id"]
        .as_u64()
        .unwrap();
    let created = register(&phone, RP, "passkey-user", b"handle-passkey-only", 1);
    let passkey_only = created["id"].as_u64().unwrap();
    let point_passkey_only = public_key(&unb64(created["attestation_object"].as_str().unwrap()));

    let gamma_login = save(
        &phone,
        "Gamma",
        "login",
        vec![
            plain("username", "gamma-user"),
            hidden("password", PASSWORD_C),
            json!({"label": "Website", "value": "gamma.example.test", "secret": false}),
            json!({"label": "OTP", "secret": true, "value": SEED32}),
        ],
    );
    let mut attach = json!({
        "op": "passkey_register", "rp_id": "gamma.example.test", "user_name": "gamma-user",
        "user_display_name": "Gamma", "user_handle": b64(b"handle-gamma"),
        "client_data_hash": b64(&[2u8; 32]), "algorithms": [-7], "excluded": [], "title": ""
    });
    attach["attach_id"] = gamma_login["id"].clone();
    attach["attach_revision"] = gamma_login["revision"].clone();
    let created = call(&phone, attach);
    let gamma = created["id"].as_u64().unwrap();
    let point_gamma = public_key(&unb64(created["attestation_object"].as_str().unwrap()));

    // A counter-based setting is not exported; the rest of the login is.
    let counter = save(
        &phone,
        "Counter",
        "login",
        vec![
            plain("username", "counter-user"),
            hidden("password", PASSWORD_K),
            json!({"label": "One-time password", "secret": true,
                   "value": format!("otpauth://hotp/x?secret={SEED32}&counter=1")}),
        ],
    )["id"]
        .as_u64()
        .unwrap();

    let archived = save(
        &phone,
        "Archived",
        "login",
        vec![
            plain("username", "old"),
            hidden("password", "synthetic-archived"),
        ],
    )["id"]
        .as_u64()
        .unwrap();
    call(
        &phone,
        json!({"op": "archive", "id": archived, "archived": true}),
    );
    let api_key = save(
        &phone,
        "A token",
        "api_key",
        vec![hidden("token", "synthetic-token")],
    )["id"]
        .as_u64()
        .unwrap();
    let custom = save(
        &phone,
        "A note",
        "custom",
        vec![hidden("secret", "synthetic-custom")],
    )["id"]
        .as_u64()
        .unwrap();
    Fixture {
        _root: root,
        dir,
        phone,
        alpha,
        passkey_only,
        gamma,
        counter,
        archived,
        api_key,
        custom,
        point_passkey_only,
        point_gamma,
    }
}

fn exported(result: &Value, id: u64) -> &Value {
    result["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == id)
        .unwrap_or_else(|| panic!("item {id} is not exported"))
}

fn files(dir: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, out: &mut BTreeSet<String>, root: &Path) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out, root);
            } else {
                out.insert(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, &mut out, dir);
    out
}

#[test]
fn the_export_holds_the_active_logins_with_their_values() {
    let f = fixture();
    let result = call(&f.phone, json!({"op": "credential_export"}));
    let items = result["items"].as_array().unwrap();
    let ids: BTreeSet<u64> = items.iter().map(|i| i["id"].as_u64().unwrap()).collect();
    assert_eq!(
        ids,
        BTreeSet::from([f.alpha, f.passkey_only, f.gamma, f.counter])
    );
    // The API key and the custom item are skipped; the archived login is out of scope.
    assert_eq!(result["skipped"], 2);
    assert!(!ids.contains(&f.archived) && !ids.contains(&f.api_key) && !ids.contains(&f.custom));

    // The exact shape: no reserved field and no generic detail in an export.
    let keys = |value: &Value| -> BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    };
    let item_keys: BTreeSet<String> = [
        "id",
        "title",
        "notes",
        "tags",
        "created_at",
        "changed_at",
        "username",
        "password",
        "websites",
        "totp",
        "passkey",
    ]
    .map(String::from)
    .into();
    for item in items {
        assert_eq!(keys(item), item_keys);
    }

    let alpha = exported(&result, f.alpha);
    assert_eq!(alpha["title"], "Alpha Bank");
    assert_eq!(alpha["notes"], "notes of Alpha Bank");
    assert_eq!(alpha["tags"], json!(["synthetic", "transfer"]));
    assert_eq!(alpha["username"], "alpha-user");
    assert_eq!(alpha["password"], PASSWORD_A);
    assert_eq!(
        alpha["websites"],
        json!([
            "https://bank.example.test/login",
            "https://www.bank-alt.example.test"
        ])
    );
    assert!(alpha["created_at"].as_i64().unwrap() > 1_600_000_000);
    assert!(alpha["changed_at"].as_i64().unwrap() >= alpha["created_at"].as_i64().unwrap());
    assert!(alpha["passkey"].is_null());
    // The other hidden field is not a credential of the exchange.
    assert!(!result.to_string().contains("synthetic-hint"));

    // The setting of the one-time password is the raw key and its parameters.
    let totp = &alpha["totp"];
    assert_eq!(
        keys(totp),
        ["secret", "period", "digits", "algorithm", "issuer", "user"]
            .map(String::from)
            .into()
    );
    assert_eq!(unb64(totp["secret"].as_str().unwrap()), SEED_BYTES);
    assert_eq!(
        (&totp["period"], &totp["digits"], &totp["algorithm"]),
        (&json!(60), &json!(8), &json!("sha256"))
    );
    assert_eq!(totp["issuer"], "Alpha Bank");
    assert_eq!(totp["user"], "alpha@example.test");
    // A code made from the exported setting is the code of the core.
    let from_core = call(&f.phone, json!({"op": "item", "id": f.alpha}));
    let field = from_core["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["role"] == "totp")
        .unwrap()["name"]
        .clone();
    let (before, shown, after) = {
        let before = now();
        let shown = call(
            &f.phone,
            json!({"op": "totp", "id": f.alpha, "field": field}),
        );
        (before, shown["code"].as_str().unwrap().to_owned(), now())
    };
    let key = unb64(totp["secret"].as_str().unwrap());
    assert!(
        (before..=after).any(|t| code(&key, "sha256", 8, 60, t) == shown),
        "the exported setting does not make the code of the core"
    );

    // A bare secret is SHA-1, 6 digits, 30 seconds, with no label.
    let gamma = exported(&result, f.gamma);
    assert_eq!(gamma["password"], PASSWORD_C);
    let totp = &gamma["totp"];
    assert_eq!(unb64(totp["secret"].as_str().unwrap()), SEED_BYTES);
    assert_eq!(
        (&totp["period"], &totp["digits"], &totp["algorithm"]),
        (&json!(30), &json!(6), &json!("sha1"))
    );
    assert!(totp["issuer"].is_null() && totp["user"].is_null());
    assert_eq!(code(SEED_BYTES, "sha1", 8, 30, 59), "94287082");

    // A passkey: a key that is the key of the registration, and the identifiers.
    let passkey_only = exported(&result, f.passkey_only);
    assert!(passkey_only["password"].is_null() && passkey_only["totp"].is_null());
    assert_eq!(passkey_only["username"], "passkey-user");
    for (id, point, rp, handle) in [
        (
            f.passkey_only,
            &f.point_passkey_only,
            RP,
            &b"handle-passkey-only"[..],
        ),
        (
            f.gamma,
            &f.point_gamma,
            "gamma.example.test",
            &b"handle-gamma"[..],
        ),
    ] {
        let passkey = &exported(&result, id)["passkey"];
        assert_eq!(
            keys(passkey),
            [
                "rp_id",
                "credential_id",
                "user_handle",
                "user_name",
                "user_display_name",
                "key"
            ]
            .map(String::from)
            .into()
        );
        assert_eq!(passkey["rp_id"], rp);
        assert_eq!(unb64(passkey["user_handle"].as_str().unwrap()), handle);
        assert_eq!(unb64(passkey["credential_id"].as_str().unwrap()).len(), 32);
        let pkcs8 = unb64(passkey["key"].as_str().unwrap());
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &pkcs8,
            &SystemRandom::new(),
        )
        .expect("a valid PKCS #8 P-256 key");
        assert_eq!(pair.public_key().as_ref(), point.as_slice());
    }

    // A counter-based setting gives null, not a guess; a missing password gives null.
    let counter = exported(&result, f.counter);
    assert_eq!(counter["username"], "counter-user");
    assert_eq!(counter["password"], PASSWORD_K);
    assert!(counter["totp"].is_null());
    assert!(!result.to_string().contains("hotp"));
}

#[test]
fn each_exported_item_gets_one_event_without_values() {
    let f = fixture();
    let history = |id: u64| call(&f.phone, json!({"op": "history", "id": id}));
    let prepared = |id: u64| {
        history(id)["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["detail"] == PREPARED)
            .count()
    };
    let before = call(&f.phone, json!({"op": "history", "id": f.alpha}))["events"]
        .as_array()
        .unwrap()
        .len();
    let revision = call(&f.phone, json!({"op": "item", "id": f.alpha}))["revision"].clone();
    let first = call(&f.phone, json!({"op": "credential_export"}));
    assert_eq!(
        call(&f.phone, json!({"op": "item", "id": f.alpha}))["revision"],
        revision
    );
    let ids = [f.alpha, f.passkey_only, f.gamma, f.counter];
    for id in ids {
        assert_eq!(prepared(id), 1, "item {id}");
    }
    for id in [f.archived, f.api_key, f.custom] {
        assert_eq!(prepared(id), 0, "item {id}");
    }
    assert_eq!(
        history(f.alpha)["events"].as_array().unwrap().len(),
        before + 1
    );
    // The event is a revealed event; the items do not change, and no value is in it.
    let events = history(f.alpha);
    let text = events.to_string();
    for secret in [PASSWORD_A, SEED32, &b64(SEED_BYTES)] {
        assert!(!text.contains(secret));
    }
    let key = first["items"][0]["passkey"]["key"]
        .as_str()
        .map(str::to_owned);
    assert!(key.is_none_or(|key| !text.contains(&key)));
    assert!(
        events["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "revealed" && event["detail"] == PREPARED)
    );
    // A second export is a second event.
    call(&f.phone, json!({"op": "credential_export"}));
    assert_eq!(prepared(f.alpha), 2);
}

#[test]
fn only_the_unlocked_app_exports_and_no_answer_quotes_a_value() {
    let f = fixture();
    let secrets = [PASSWORD_A, PASSWORD_C, SEED32];
    // AutoFill is not allowed, locked or not.
    let extension = core(&f.dir, "autofill");
    let (code, message) = fails(&extension, json!({"op": "credential_export"}));
    assert_eq!(code, "not_allowed");
    call(&f.phone, json!({"op": "lock"}));
    call(&extension, json!({"op": "unlock", "passphrase": PASS}));
    let (code, _) = fails(&extension, json!({"op": "credential_export"}));
    assert_eq!(code, "not_allowed");
    call(&extension, json!({"op": "lock"}));
    // A locked app answers locked, and nothing is written to a file.
    let (locked, locked_message) = fails(&f.phone, json!({"op": "credential_export"}));
    assert_eq!(locked, "locked");
    for text in [message, locked_message] {
        assert!(secrets.iter().all(|secret| !text.contains(secret)));
    }
    call(&f.phone, json!({"op": "unlock", "passphrase": PASS}));
    let before = files(&f.dir);
    let answer = raw(&f.phone, &json!({"op": "credential_export"}));
    call(&f.phone, json!({"op": "lock"}));
    assert_eq!(files(&f.dir), before, "the export writes no file");
    // The stored vault never holds the exported values in the clear.
    let key = serde_json::from_str::<Value>(&answer).unwrap()["result"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|item| item["passkey"]["key"].as_str().map(str::to_owned))
        .unwrap();
    for path in before {
        let bytes = std::fs::read(f.dir.join(&path)).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for secret in [PASSWORD_A, PASSWORD_C, SEED32, key.as_str()] {
            assert!(!text.contains(secret), "{path}");
        }
    }
}

#[test]
fn a_conflict_copy_is_not_exported_twice() {
    let f = fixture();
    let id = call(&f.phone, json!({"op": "info"}))["selected"]
        .as_str()
        .unwrap()
        .to_owned();
    call(&f.phone, json!({"op": "lock"}));
    f.phone.shutdown();
    let path = f.dir.join("vaults").join(format!("{id}.apassy"));
    let mut a = Vault::open(&path).unwrap();
    a.unlock(PASS).unwrap();
    let seed = f.dir.join("seed.copy");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &f.dir.join("b.apassy"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    // Both sides edit the passkey-only login: the merge keeps a conflict copy of it.
    let rename = |vault: &mut Vault, item: u64, title: &str| {
        let revision = vault.details(item).unwrap().summary.revision;
        let mut draft = apassy::vault::ItemDraft {
            title: title.to_owned(),
            kind: apassy::contracts::CredentialKind::Login,
            notes: String::new(),
            tags: Vec::new(),
            fields: Vec::new(),
        };
        draft.fields.push(apassy::vault::Field {
            name: "username".to_owned(),
            value: apassy::vault::SecretValue::new("passkey-user".to_owned()),
            secret: false,
        });
        vault.update(item, revision, draft).unwrap();
    };
    let on_b = b.passkeys(RP, &[]).unwrap()[0].item_id;
    rename(&mut a, f.passkey_only, "Passkey A");
    rename(&mut b, on_b, "Passkey B");
    let remote = f.dir.join("remote.copy");
    b.write_sync_copy(&remote, "Mac B").unwrap();
    let report = a.merge_from(&remote, &SyncScope::vault()).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    let copies = a.conflict_copies().unwrap();
    let copy = *copies.keys().next().unwrap();
    // The owner restored the copy: it is active, and it is still a conflict copy.
    a.set_archived(copy, false).unwrap();
    drop(a);

    let phone = core(&f.dir, "app");
    call(&phone, json!({"op": "select", "vault_id": id}));
    call(&phone, json!({"op": "unlock", "passphrase": PASS}));
    let rows = call(&phone, json!({"op": "items"}));
    assert!(
        rows["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == copy)
    );
    let result = call(&phone, json!({"op": "credential_export"}));
    let ids: Vec<u64> = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_u64().unwrap())
        .collect();
    assert!(!ids.contains(&copy), "the conflict copy is exported");
    assert!(ids.contains(&f.passkey_only));
    assert_eq!(ids.len(), 4);
    assert_eq!(result["skipped"], 2);
    let passkeys = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| !item["passkey"].is_null())
        .count();
    assert_eq!(passkeys, 2);
    let history = call(&phone, json!({"op": "history", "id": copy}));
    assert!(!history.to_string().contains(PREPARED));
}

/// Device A adds a passkey to a login, and a later password edit of device B wins. The
/// restored conflict copy has the only key of the credential: the export holds it as a
/// whole login, next to the winning version, and the key imports and signs.
#[test]
fn a_restored_copy_with_a_recovered_passkey_is_exported_once() {
    const RECOVERED_RP: &str = "recovered.example.test";
    const OLD: &str = "synthetic-password-old";
    const NEW: &str = "synthetic-password-new";
    let f = fixture();
    let id = call(&f.phone, json!({"op": "info"}))["selected"]
        .as_str()
        .unwrap()
        .to_owned();
    call(&f.phone, json!({"op": "lock"}));
    f.phone.shutdown();
    let path = f.dir.join("vaults").join(format!("{id}.apassy"));
    let mut a = Vault::open(&path).unwrap();
    a.unlock(PASS).unwrap();
    let draft = |password: &str| apassy::vault::ItemDraft {
        title: "Recovered".to_owned(),
        kind: apassy::contracts::CredentialKind::Login,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![
            apassy::vault::Field {
                name: "username".to_owned(),
                value: apassy::vault::SecretValue::new("recovered-user".to_owned()),
                secret: false,
            },
            apassy::vault::Field {
                name: "password".to_owned(),
                value: apassy::vault::SecretValue::new(password.to_owned()),
                secret: true,
            },
        ],
    };
    let original = a.add(draft(OLD)).unwrap();
    let seed = f.dir.join("seed.copy");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &f.dir.join("b.apassy"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    let created = a
        .create_passkey(apassy::vault::PasskeyCreate {
            rp_id: RECOVERED_RP,
            user_handle: b"handle-recovered",
            user_name: "recovered-user",
            user_display_name: "Recovered",
            client_data_hash: &[3; 32],
            algorithms: &[-7],
            exclude: &[],
            target: apassy::vault::PasskeyTarget::Attach {
                item_id: original.id,
                revision: original.revision,
            },
        })
        .unwrap();
    let point = created.public_key_spki[created.public_key_spki.len() - 65..].to_vec();
    // B's edit is the later version.
    std::thread::sleep(std::time::Duration::from_millis(20));
    let on_b = b
        .search("Recovered")
        .unwrap()
        .into_iter()
        .find(|summary| summary.title == "Recovered")
        .unwrap();
    b.update(on_b.id, on_b.revision, draft(NEW)).unwrap();
    let remote = f.dir.join("remote.copy");
    b.write_sync_copy(&remote, "Mac B").unwrap();
    let report = a.merge_from(&remote, &SyncScope::vault()).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    let copies = a.conflict_copies().unwrap();
    let (&copy, &origin) = copies.first_key_value().unwrap();
    assert_eq!(origin, Some(original.id));
    a.set_archived(copy, false).unwrap();
    drop(a);
    drop(b);

    let device = core(&f.dir, "app");
    call(&device, json!({"op": "select", "vault_id": id}));
    call(&device, json!({"op": "unlock", "passphrase": PASS}));
    let result = call(&device, json!({"op": "credential_export"}));
    let ids: Vec<u64> = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids.len(), 6);
    assert_eq!(result["skipped"], 2);
    // The winning version: the new password, no passkey.
    let winner = exported(&result, original.id);
    assert!(winner["password"] == NEW, "the winner has the new password");
    assert!(winner["passkey"].is_null());
    // The restored copy: the whole login with the old password and the passkey.
    let recovered = exported(&result, copy);
    assert!(
        recovered["password"] == OLD,
        "the copy has the old password"
    );
    let passkey = &recovered["passkey"];
    assert_eq!(passkey["rp_id"], RECOVERED_RP);
    assert_eq!(
        unb64(passkey["credential_id"].as_str().unwrap()),
        created.credential_id
    );
    let passkeys = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| !item["passkey"].is_null())
        .count();
    assert_eq!(passkeys, 3);
    let history = call(&device, json!({"op": "history", "id": copy}));
    assert!(history.to_string().contains(PREPARED));

    // The key imports into a fresh vault and signs for the point of the registration.
    let (_root, _dir, fresh) = phone();
    let accounts = json!([{"rp_id": passkey["rp_id"], "credential_id": passkey["credential_id"],
        "user_handle": passkey["user_handle"], "user_name": passkey["user_name"],
        "user_display_name": passkey["user_display_name"], "key": passkey["key"],
        "title": recovered["title"]}]);
    let counts = call(
        &fresh,
        json!({"op": "passkey_import", "accounts": accounts}),
    );
    assert_eq!(counts["imported"], 1);
    let listed = call(
        &fresh,
        json!({"op": "passkey_list", "rp_id": RECOVERED_RP,
               "allowed": [passkey["credential_id"]]}),
    );
    let entry = &listed["passkeys"][0];
    assert_and_verify(&fresh, entry["id"].as_u64().unwrap(), passkey, &point, 14);
}

/// The owner restores two conflict copies of a passkey login (a copy and a copy of that
/// copy), and then deletes the original. No normal login has the credential, so the
/// export holds the copy with the lower ID once, as a whole login. Its key imports and
/// signs for the point of the registration.
#[test]
fn a_recovered_login_is_exported_once_after_its_original_is_deleted() {
    let f = fixture();
    let id = call(&f.phone, json!({"op": "info"}))["selected"]
        .as_str()
        .unwrap()
        .to_owned();
    call(&f.phone, json!({"op": "lock"}));
    f.phone.shutdown();
    let path = f.dir.join("vaults").join(format!("{id}.apassy"));
    let mut a = Vault::open(&path).unwrap();
    a.unlock(PASS).unwrap();
    let seed = f.dir.join("seed.copy");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &f.dir.join("b.apassy"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    let rename = |vault: &mut Vault, item: u64, title: &str| {
        let revision = vault.details(item).unwrap().summary.revision;
        let draft = apassy::vault::ItemDraft {
            title: title.to_owned(),
            kind: apassy::contracts::CredentialKind::Login,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![apassy::vault::Field {
                name: "username".to_owned(),
                value: apassy::vault::SecretValue::new("passkey-user".to_owned()),
                secret: false,
            }],
        };
        vault.update(item, revision, draft).unwrap();
    };
    let later = || std::thread::sleep(std::time::Duration::from_millis(20));
    let merge = |into: &mut Vault, from: &mut Vault, name: &str, device: &str| {
        let copy = f.dir.join(name);
        from.write_sync_copy(&copy, device).unwrap();
        into.merge_from(&copy, &SyncScope::vault())
            .unwrap()
            .conflicts
            .len()
    };
    // Both sides edit the passkey-only login: A keeps an archived copy of it.
    let on_b = b.passkeys(RP, &[]).unwrap()[0].item_id;
    rename(&mut a, f.passkey_only, "Passkey A");
    later();
    rename(&mut b, on_b, "Passkey B");
    assert_eq!(merge(&mut a, &mut b, "b1.copy", "Mac B"), 1);
    let first = *a.conflict_copies().unwrap().keys().next().unwrap();
    a.set_archived(first, false).unwrap();
    // B gets the restored copy. Both sides edit it: A keeps a copy of the copy.
    assert_eq!(merge(&mut b, &mut a, "a1.copy", "Mac A"), 0);
    let first_on_b = *b.conflict_copies().unwrap().keys().next().unwrap();
    rename(&mut a, first, "Copy A");
    later();
    rename(&mut b, first_on_b, "Copy B");
    assert_eq!(merge(&mut a, &mut b, "b2.copy", "Mac B"), 1);
    let copies = a.conflict_copies().unwrap();
    let (&second, &origin) = copies.iter().find(|(id, _)| **id != first).unwrap();
    assert_eq!(origin, Some(first));
    assert!(first < second);
    a.set_archived(second, false).unwrap();
    let revision = a.details(f.passkey_only).unwrap().summary.revision;
    a.delete(f.passkey_only, revision).unwrap();
    drop(a);
    drop(b);

    let device = core(&f.dir, "app");
    call(&device, json!({"op": "select", "vault_id": id}));
    call(&device, json!({"op": "unlock", "passphrase": PASS}));
    let result = call(&device, json!({"op": "credential_export"}));
    let ids: Vec<u64> = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_u64().unwrap())
        .collect();
    assert_eq!(
        ids.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([f.alpha, f.gamma, f.counter, first])
    );
    assert_eq!(ids.len(), 4);
    assert_eq!(result["skipped"], 2);
    let with_passkey: Vec<&Value> = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| !item["passkey"].is_null())
        .collect();
    assert_eq!(with_passkey.len(), 2);
    let recovered = exported(&result, first);
    assert_eq!(recovered["title"], "Copy B");
    assert_eq!(recovered["username"], "passkey-user");
    let passkey = &recovered["passkey"];
    assert_eq!(passkey["rp_id"], RP);
    let history = call(&device, json!({"op": "history", "id": first}));
    assert!(history.to_string().contains(PREPARED));
    let history = call(&device, json!({"op": "history", "id": second}));
    assert!(!history.to_string().contains(PREPARED));

    // The key imports into a fresh vault and signs for the point of the registration.
    let (_root, _dir, fresh) = phone();
    let accounts = json!([{"rp_id": passkey["rp_id"], "credential_id": passkey["credential_id"],
        "user_handle": passkey["user_handle"], "user_name": passkey["user_name"],
        "user_display_name": passkey["user_display_name"], "key": passkey["key"],
        "title": recovered["title"]}]);
    let counts = call(
        &fresh,
        json!({"op": "passkey_import", "accounts": accounts}),
    );
    assert_eq!(counts["imported"], 1);
    let listed = call(
        &fresh,
        json!({"op": "passkey_list", "rp_id": RP, "allowed": [passkey["credential_id"]]}),
    );
    let entry = &listed["passkeys"][0];
    assert_and_verify(
        &fresh,
        entry["id"].as_u64().unwrap(),
        passkey,
        &f.point_passkey_only,
        15,
    );
}

/// The answer goes into a fresh vault with the import calls, as the app does.
#[test]
fn the_answer_imports_into_a_fresh_vault() {
    let f = fixture();
    let result = call(&f.phone, json!({"op": "credential_export"}));
    let (_root, _dir, fresh) = phone();

    let accounts: Vec<Value> = result["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| !item["passkey"].is_null())
        .map(|item| {
            let passkey = &item["passkey"];
            json!({"rp_id": passkey["rp_id"], "credential_id": passkey["credential_id"],
                   "user_handle": passkey["user_handle"], "user_name": passkey["user_name"],
                   "user_display_name": passkey["user_display_name"], "key": passkey["key"],
                   "title": item["title"]})
        })
        .collect();
    assert_eq!(accounts.len(), 2);
    let counts = call(
        &fresh,
        json!({"op": "passkey_import", "accounts": accounts}),
    );
    assert_eq!(
        (
            &counts["imported"],
            &counts["skipped_existing"],
            &counts["failed"]
        ),
        (&json!(2), &json!(0), &json!(0))
    );
    let again = call(
        &fresh,
        json!({"op": "passkey_import", "accounts": accounts}),
    );
    assert_eq!(
        (
            &again["imported"],
            &again["skipped_existing"],
            &again["failed"]
        ),
        (&json!(0), &json!(2), &json!(0))
    );

    // The imported keys sign for the points of the original registrations.
    for (item, point, byte) in [
        (f.passkey_only, &f.point_passkey_only, 11u8),
        (f.gamma, &f.point_gamma, 12),
    ] {
        let passkey = &exported(&result, item)["passkey"];
        let listed = call(
            &fresh,
            json!({"op": "passkey_list", "rp_id": passkey["rp_id"],
                   "allowed": [passkey["credential_id"]]}),
        );
        let entry = &listed["passkeys"][0];
        assert_eq!(entry["user_handle"], passkey["user_handle"]);
        assert_and_verify(&fresh, entry["id"].as_u64().unwrap(), passkey, point, byte);
    }

    // The password and the one-time password of the item with a passkey go in with a
    // plain save of the item, which keeps the passkey (the app's step 4).
    let gamma = exported(&result, f.gamma);
    let listed = call(
        &fresh,
        json!({"op": "passkey_list", "rp_id": "gamma.example.test",
               "allowed": [gamma["passkey"]["credential_id"]]}),
    );
    let new_id = listed["passkeys"][0]["id"].as_u64().unwrap();
    let revision = call(&fresh, json!({"op": "item", "id": new_id}))["revision"].clone();
    let totp = &gamma["totp"];
    let uri = format!(
        "otpauth://totp/Gamma?secret={}&algorithm={}&digits={}&period={}",
        base32(&unb64(totp["secret"].as_str().unwrap())),
        totp["algorithm"].as_str().unwrap().to_uppercase(),
        totp["digits"],
        totp["period"]
    );
    call(
        &fresh,
        json!({"op": "save", "id": new_id, "revision": revision, "item": {
            "title": gamma["title"], "kind": "login", "notes": gamma["notes"],
            "tags": gamma["tags"], "fields": [
                plain("username", gamma["username"].as_str().unwrap()),
                hidden("password", gamma["password"].as_str().unwrap()),
                json!({"label": "Website", "value": gamma["websites"][0], "secret": false}),
                json!({"label": "One-time password", "value": uri, "secret": true})]}}),
    );
    let detail = call(&fresh, json!({"op": "item", "id": new_id}));
    assert_eq!(detail["has_passkey"], true);
    assert_eq!(detail["has_totp"], true);
    assert_eq!(
        call(
            &fresh,
            json!({"op": "reveal", "id": new_id, "field": "password"})
        )["value"],
        PASSWORD_C
    );
    let field = detail["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["role"] == "totp")
        .unwrap()["name"]
        .clone();
    let (before, shown, after) = {
        let before = now();
        let shown = call(&fresh, json!({"op": "totp", "id": new_id, "field": field}));
        (before, shown["code"].as_str().unwrap().to_owned(), now())
    };
    assert!((before..=after).any(|t| code(SEED_BYTES, "sha1", 6, 30, t) == shown));
    let point = &f.point_gamma;
    assert_and_verify(&fresh, new_id, &gamma["passkey"], point, 13);
}
