//! `Row.has_password`: the metadata that tells the app what removing a passkey does.
//! The vault keeps a login only when its secret password has a value, so the row must
//! say the same, and it must never carry the value. Synthetic keys and vaults only, in
//! a temporary directory. The empty stored password cannot come from the JSON calls (the
//! core refuses it), so the test writes it with the vault API of the `apassy` crate.

use std::path::{Path, PathBuf};

use apassy::contracts::CredentialKind;
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use apassy_core::Core;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-phone-pass";
const RP: &str = "example.com";
const PASSWORD: &str = "synthetic-Pw-1!-never-in-a-row";

fn core(dir: &Path) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Synthetic iPhone", "role": "app"});
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
    answer["error"]["code"].as_str().expect("code").to_owned()
}

/// A phone with one vault, and the path of its file.
fn phone() -> (TempDir, Core, PathBuf) {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("Apassy");
    std::fs::create_dir_all(&dir).unwrap();
    let phone = core(&dir);
    call(
        &phone,
        json!({"op": "create_local_vault", "name": "Synthetic", "passphrase": PASS}),
    );
    let info = call(&phone, json!({"op": "info"}));
    let id = info["selected"].as_str().expect("selected").to_owned();
    let file = dir.join("vaults").join(format!("{id}.apassy"));
    assert!(file.exists());
    (root, phone, file)
}

fn register(core: &Core, user: &str, handle: u8, attach: Option<&Value>) -> u64 {
    let mut request = json!({
        "op": "passkey_register", "rp_id": RP, "user_name": user,
        "user_display_name": "Synthetic User", "user_handle": "AQIDBA==",
        "client_data_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "algorithms": [-7], "excluded": [], "title": format!("Login {user}-{handle}")
    });
    if let Some(saved) = attach {
        request["attach_id"] = saved["id"].clone();
        request["attach_revision"] = saved["revision"].clone();
    }
    call(core, request)["id"].as_u64().expect("id")
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

/// Replaces the fields of a login with a stored secret password that is empty. The vault
/// keeps the passkey fields. The core must be locked: it closes the vault file.
fn store_empty_password(core: &Core, file: &Path, id: u64, user: &str) {
    call(core, json!({"op": "lock"}));
    let mut vault = Vault::open(file).expect("open");
    vault.unlock(PASS).expect("unlock");
    let revision = vault.details(id).expect("details").summary.revision;
    let draft = ItemDraft {
        title: "Empty password".to_owned(),
        kind: CredentialKind::Login,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![
            Field {
                name: "username".to_owned(),
                value: SecretValue::new(user.to_owned()),
                secret: false,
            },
            Field {
                name: "password".to_owned(),
                value: SecretValue::new(String::new()),
                secret: true,
            },
        ],
    };
    vault.update(id, revision, draft).expect("update");
    // The stored row is what the test needs: a secret field "password" with no value.
    assert!(
        vault
            .details(id)
            .unwrap()
            .fields
            .iter()
            .any(|f| f.name == "password" && f.secret)
    );
    assert!(vault.reveal(id, "password").unwrap().expose().is_empty());
    drop(vault);
    call(core, json!({"op": "unlock", "passphrase": PASS}));
}

struct Logins {
    with_password: u64,
    passwordless: u64,
    empty_password: u64,
}

fn logins(core: &Core, file: &Path) -> Logins {
    let saved = call(
        core,
        json!({"op": "save", "id": null, "revision": null, "item": {
            "title": "With password", "kind": "login", "notes": "keep me", "tags": ["work"],
            "fields": [
                {"name": "username", "value": "ada", "secret": false},
                {"name": "password", "value": PASSWORD, "secret": true}]}}),
    );
    let with_password = register(core, "ada", 1, Some(&saved));
    let passwordless = register(core, "grace", 2, None);
    let empty_password = register(core, "edsger", 3, None);
    store_empty_password(core, file, empty_password, "edsger");
    Logins {
        with_password,
        passwordless,
        empty_password,
    }
}

#[test]
fn the_row_says_whether_the_password_has_a_value_and_never_gives_it() {
    let (_root, phone, file) = phone();
    let logins = logins(&phone, &file);

    assert_eq!(row(&phone, logins.with_password)["has_password"], true);
    assert_eq!(row(&phone, logins.passwordless)["has_password"], false);
    // The field is there but empty: the vault deletes the login, so the row says "no".
    assert_eq!(row(&phone, logins.empty_password)["has_password"], false);

    // The detail carries the same flag, and no answer holds the value or a plain copy.
    let mut seen = vec![
        call(&phone, json!({"op": "items", "archived": "all"})).to_string(),
        call(&phone, json!({"op": "items"})).to_string(),
    ];
    for id in [
        logins.with_password,
        logins.passwordless,
        logins.empty_password,
    ] {
        let detail = call(&phone, json!({"op": "item", "id": id}));
        assert_eq!(detail["has_password"], row(&phone, id)["has_password"]);
        for field in detail["fields"].as_array().unwrap() {
            if field["secret"] == true {
                assert!(field["value"].is_null(), "{field}");
            }
        }
        seen.push(detail.to_string());
    }
    for text in seen {
        assert!(!text.contains(PASSWORD), "{text}");
    }
}

#[test]
fn the_flag_matches_what_the_removal_does() {
    let (_root, phone, file) = phone();
    let logins = logins(&phone, &file);

    // True: the vault keeps the login with its notes, tags, and password.
    let kept = row(&phone, logins.with_password);
    assert_eq!(kept["has_password"], true);
    call(
        &phone,
        json!({"op": "passkey_remove", "id": logins.with_password, "revision": kept["revision"]}),
    );
    let after = call(&phone, json!({"op": "item", "id": logins.with_password}));
    assert_eq!(after["has_passkey"], false);
    assert_eq!(after["has_password"], true);
    assert_eq!(after["notes"], "keep me");
    assert_eq!(after["tags"], json!(["work"]));
    assert_eq!(
        call(
            &phone,
            json!({"op": "reveal", "id": logins.with_password, "field": "password"})
        )["value"],
        PASSWORD
    );

    // False, with no password field: the vault deletes the whole login.
    // False, with an empty stored password: the same.
    for id in [logins.passwordless, logins.empty_password] {
        let before = row(&phone, id);
        assert_eq!(before["has_password"], false, "{before}");
        call(
            &phone,
            json!({"op": "passkey_remove", "id": id, "revision": before["revision"]}),
        );
        assert_eq!(fails(&phone, json!({"op": "item", "id": id})), "not_found");
    }
}

#[test]
fn a_password_set_on_an_empty_one_keeps_the_login() {
    let (_root, phone, file) = phone();
    let logins = logins(&phone, &file);
    let id = logins.empty_password;
    assert_eq!(row(&phone, id)["has_password"], false);

    // The app can set a password on the login: the flag turns true, and the login stays.
    let revision = row(&phone, id)["revision"].clone();
    call(
        &phone,
        json!({"op": "save", "id": id, "revision": revision, "item": {
            "title": "Empty password", "kind": "login", "notes": "", "tags": [],
            "fields": [
                {"name": "username", "value": "edsger", "secret": false},
                {"name": "password", "value": PASSWORD, "secret": true}]}}),
    );
    let fixed = row(&phone, id);
    assert_eq!(fixed["has_password"], true);
    assert_eq!(fixed["has_passkey"], true);
    call(
        &phone,
        json!({"op": "passkey_remove", "id": id, "revision": fixed["revision"]}),
    );
    assert_eq!(row(&phone, id)["has_password"], true);
}
