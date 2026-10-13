//! Folders, adding by paste, and the options of a credential (contract ios-core-v1,
//! section 5.11), through the JSON calls as the iPhone app makes them. Synthetic values
//! only: the keys are a provider prefix and `EXAMPLE0` repeated, as in the Mac's tests.

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::fs;
use std::path::{Path, PathBuf};

use apassy::sync::{RelayConfig, RelaySync};
use apassy::vault::{DeclarationSource, Environment, Vault};
use apassy_core::Core;
use fake_relay::FakeRelay;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-phone-pass";

fn core(dir: &Path, role: &str) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Synthetic iPhone", "role": role});
    Core::new(&config.to_string()).expect("core")
}

fn answer(core: &Core, request: &Value) -> Value {
    serde_json::from_str(&core.call(&request.to_string())).expect("json")
}

/// A call that must work: its result.
fn call(core: &Core, request: Value) -> Value {
    let answer = answer(core, &request);
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

/// A call that must fail: its error code.
fn fails(core: &Core, request: Value) -> String {
    let answer = answer(core, &request);
    assert_eq!(answer["ok"], false, "{request} -> {answer}");
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(!message.is_empty());
    answer["error"]["code"].as_str().expect("code").to_owned()
}

fn data(root: &TempDir, name: &str) -> PathBuf {
    let dir = root.path().join(name).join("Apassy");
    fs::create_dir_all(&dir).expect("dir");
    dir
}

/// A synthetic key: a provider prefix and `EXAMPLE0` repeated.
fn fake(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", &"EXAMPLE0".repeat(len / 8 + 1)[..len])
}

/// A phone core with a new local vault, unlocked.
fn phone(root: &TempDir) -> (Core, PathBuf) {
    let dir = data(root, "phone");
    let phone = core(&dir, "app");
    call(
        &phone,
        json!({"op": "create_local_vault", "name": "Personal", "passphrase": PASS}),
    );
    (phone, dir)
}

fn folder_names(phone: &Core) -> Vec<(String, Option<String>, u64)> {
    call(phone, json!({"op": "folders"}))["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_owned(),
                f["parent"].as_str().map(str::to_owned),
                f["count"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn row(phone: &Core, id: u64) -> Value {
    call(phone, json!({"op": "items", "archived": "all"}))["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .cloned()
        .expect("row")
}

#[test]
fn folders_nest_rename_move_and_delete_like_the_mac() {
    let root = TempDir::new().unwrap();
    let (phone, _) = phone(&root);
    assert_eq!(call(&phone, json!({"op": "folders"}))["folders"], json!([]));

    let acme = call(&phone, json!({"op": "folder_create", "name": " Acme "}))["folder"].clone();
    assert_eq!(acme["name"], "Acme");
    assert_eq!(acme["parent"], Value::Null);
    assert_eq!(acme["count"], 0);
    let acme = acme["uuid"].as_str().unwrap().to_owned();
    let billing = call(
        &phone,
        json!({"op": "folder_create", "parent": acme, "name": "Billing"}),
    )["folder"]["uuid"]
        .as_str()
        .unwrap()
        .to_owned();
    let personal =
        call(&phone, json!({"op": "folder_create", "name": "Personal"}))["folder"]["uuid"]
            .as_str()
            .unwrap()
            .to_owned();

    // The Mac's rules: a sibling name is taken without regard to case, a name has no
    // control character, folders nest 4 levels, a parent must be there.
    assert_eq!(
        fails(&phone, json!({"op": "folder_create", "name": "acme"})),
        "exists"
    );
    assert_eq!(
        fails(&phone, json!({"op": "folder_create", "name": "  "})),
        "invalid_input"
    );
    assert_eq!(
        fails(&phone, json!({"op": "folder_create", "name": "a\u{7}b"})),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "folder_create", "parent": "no-such-folder", "name": "X"})
        ),
        "not_found"
    );
    let mut parent = billing.clone();
    for name in ["Level 3", "Level 4"] {
        parent = call(
            &phone,
            json!({"op": "folder_create", "parent": parent, "name": name}),
        )["folder"]["uuid"]
            .as_str()
            .unwrap()
            .to_owned();
    }
    assert_eq!(
        fails(
            &phone,
            json!({"op": "folder_create", "parent": parent, "name": "Level 5"})
        ),
        "invalid_input"
    );

    // Credentials in folders, with the count of each folder (archived ones do not count).
    let added = call(
        &phone,
        json!({"op": "add_pasted", "folder": billing,
               "text": format!("STRIPE_SECRET_KEY={}\nGITHUB_TOKEN={}", fake("sk_live_", 24), fake("ghp_", 36))}),
    )["items"]
        .clone();
    let stripe = added[0]["id"].as_u64().unwrap();
    let github = added[1]["id"].as_u64().unwrap();
    call(
        &phone,
        json!({"op": "item_folder_set", "id": github, "folder": acme}),
    );
    assert_eq!(row(&phone, github)["folder"], json!(acme));
    let detail = call(&phone, json!({"op": "item", "id": stripe}));
    assert_eq!(detail["folder"], json!(billing));
    assert_eq!(detail["folder_path"], json!(["Acme", "Billing"]));
    let names = folder_names(&phone);
    assert_eq!(names[0], ("Acme".to_owned(), None, 1));
    assert_eq!(names[1], ("Billing".to_owned(), Some(acme.clone()), 1));
    call(
        &phone,
        json!({"op": "archive", "id": github, "archived": true}),
    );
    assert_eq!(
        folder_names(&phone)[0].2,
        0,
        "an archived credential does not count"
    );
    call(
        &phone,
        json!({"op": "archive", "id": github, "archived": false}),
    );

    // Rename and move: the path follows.
    call(
        &phone,
        json!({"op": "folder_rename", "uuid": billing, "name": "Invoices"}),
    );
    assert_eq!(
        call(&phone, json!({"op": "item", "id": stripe}))["folder_path"],
        json!(["Acme", "Invoices"])
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "folder_rename", "uuid": personal, "name": "ACME"})
        ),
        "exists"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "folder_move", "uuid": acme, "parent": billing})
        ),
        "invalid_input",
        "a folder cannot move into its own subfolder"
    );
    call(
        &phone,
        json!({"op": "folder_move", "uuid": billing, "parent": personal}),
    );
    assert_eq!(
        call(&phone, json!({"op": "item", "id": stripe}))["folder_path"],
        json!(["Personal", "Invoices"])
    );
    call(
        &phone,
        json!({"op": "folder_move", "uuid": billing, "parent": null}),
    );
    assert_eq!(
        call(&phone, json!({"op": "item", "id": stripe}))["folder_path"],
        json!(["Invoices"])
    );
    call(
        &phone,
        json!({"op": "folder_move", "uuid": billing, "parent": acme}),
    );

    // Deleting a folder moves its credentials to the parent and deletes none.
    assert_eq!(
        call(&phone, json!({"op": "folder_delete", "uuid": billing}))["moved"],
        1
    );
    let detail = call(&phone, json!({"op": "item", "id": stripe}));
    assert_eq!(detail["folder"], json!(acme));
    assert_eq!(detail["folder_path"], json!(["Acme"]));
    assert_eq!(folder_names(&phone)[0], ("Acme".to_owned(), None, 2));
    assert!(
        !folder_names(&phone)
            .iter()
            .any(|(name, _, _)| name == "Invoices")
    );
    assert_eq!(
        call(&phone, json!({"op": "folder_delete", "uuid": acme}))["moved"],
        2
    );
    let detail = call(&phone, json!({"op": "item", "id": stripe}));
    assert_eq!(detail["folder"], Value::Null);
    assert_eq!(detail["folder_path"], json!([]));
    assert_eq!(
        call(&phone, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        fails(&phone, json!({"op": "folder_delete", "uuid": acme})),
        "not_found"
    );

    // A credential to a folder and back to the top level.
    call(
        &phone,
        json!({"op": "item_folder_set", "id": stripe, "folder": personal}),
    );
    assert_eq!(row(&phone, stripe)["folder"], json!(personal));
    call(&phone, json!({"op": "item_folder_set", "id": stripe}));
    assert_eq!(row(&phone, stripe)["folder"], Value::Null);
    assert_eq!(
        fails(
            &phone,
            json!({"op": "item_folder_set", "id": stripe, "folder": acme})
        ),
        "not_found",
        "a deleted folder"
    );
    assert_eq!(
        fails(&phone, json!({"op": "item_folder_set", "id": 9999})),
        "not_found"
    );
    let history = call(&phone, json!({"op": "history", "id": stripe}))["events"].to_string();
    assert!(history.contains("Moved to Personal"), "{history}");
}

#[test]
fn detect_finds_each_credential_and_never_answers_a_secret_value() {
    let root = TempDir::new().unwrap();
    let (phone, _) = phone(&root);
    let stripe = fake("sk_live_", 24);
    let test_key = fake("sk_test_", 24);
    let github = fake("ghp_", 36);
    let db_password = "SyntheticDbPw0042";
    let url = format!("postgres://app:{db_password}@db.example.com:5432/shop");

    // One Stripe key: the provider, the title, the variable, the hosts, production from
    // the value signal, and the prefix in the preview only.
    let found = call(&phone, json!({"op": "detect", "text": stripe}));
    let text = found.to_string();
    assert!(!text.contains(&stripe), "{text}");
    assert!(!text.contains("EXAMPLE0"), "{text}");
    let one = &found["found"][0];
    assert_eq!(found["found"].as_array().unwrap().len(), 1);
    assert_eq!(one["index"], 0);
    assert_eq!(one["title"], "Stripe live");
    assert_eq!(one["kind"], "api_key");
    assert_eq!(one["provider"], "Stripe");
    assert_eq!(one["env_name"], "STRIPE_SECRET_KEY");
    assert_eq!(one["environment"], "production");
    assert_eq!(one["environment_source"], "signal");
    assert_eq!(one["line"], Value::Null);
    assert_eq!(
        one["summary"],
        "Stripe live · STRIPE_SECRET_KEY · production"
    );
    assert!(!one["hosts"].as_array().unwrap().is_empty());
    assert_eq!(
        one["fields"],
        json!([{"name": "token", "label": "Token", "secret": true, "preview": "sk_live_••••••••"}])
    );

    let test = &call(&phone, json!({"op": "detect", "text": test_key}))["found"][0];
    assert_eq!(test["title"], "Stripe test");
    assert_ne!(test["environment"], "production");

    let token = call(&phone, json!({"op": "detect", "text": github}));
    assert!(!token.to_string().contains(&github));
    assert_eq!(token["found"][0]["provider"], "GitHub");
    assert_eq!(token["found"][0]["kind"], "api_key");

    // A database URL: plain parts are shown, the password and the whole URL are not.
    let db = call(&phone, json!({"op": "detect", "text": url}));
    let text = db.to_string();
    assert!(!text.contains(db_password), "{text}");
    assert!(!text.contains(&url), "{text}");
    let fields = db["found"][0]["fields"].as_array().unwrap().clone();
    assert!(
        fields.iter().any(
            |f| f["name"] == "host" && f["preview"] == "db.example.com:5432"
                || f["name"] == "host" && f["preview"] == "db.example.com"
        ),
        "{text}"
    );
    for field in &fields {
        if field["secret"] == true {
            assert!(field["preview"].as_str().unwrap().ends_with("••••••••"));
        }
    }

    // A .env file of three lines: one row each, with its line.
    let env = format!(
        "# synthetic\nSTRIPE_SECRET_KEY={stripe}\nGITHUB_TOKEN={github}\nDATABASE_URL={url}\n"
    );
    let found = call(&phone, json!({"op": "detect", "text": env}));
    let text = found.to_string();
    for secret in [stripe.as_str(), github.as_str(), db_password] {
        assert!(!text.contains(secret), "{text}");
    }
    let rows = found["found"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let lines: Vec<u64> = rows.iter().map(|r| r["line"].as_u64().unwrap()).collect();
    assert_eq!(lines, [2, 3, 4]);
    let indexes: Vec<u64> = rows.iter().map(|r| r["index"].as_u64().unwrap()).collect();
    assert_eq!(indexes, [0, 1, 2]);
    assert_eq!(rows[2]["env_name"], "DATABASE_URL");

    // Nothing found is an empty list; a text over 1 MiB is refused.
    assert_eq!(
        call(&phone, json!({"op": "detect", "text": "   "}))["found"],
        json!([])
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "detect", "text": "x".repeat(1_048_577)})
        ),
        "invalid_input"
    );
}

#[test]
fn add_pasted_saves_the_picked_rows_in_one_transaction_like_the_mac() {
    let root = TempDir::new().unwrap();
    let (phone, _) = phone(&root);
    let stripe = fake("sk_live_", 24);
    let github = fake("ghp_", 36);
    let env = format!(
        "STRIPE_SECRET_KEY={stripe}\nGITHUB_TOKEN={github}\nDATABASE_URL=postgres://app:SyntheticDbPw0042@db.example.com/shop\n"
    );
    let acme = call(&phone, json!({"op": "folder_create", "name": "Acme"}))["folder"]["uuid"]
        .as_str()
        .unwrap()
        .to_owned();

    // The owner unchecks the GitHub line and names the Stripe key.
    let added = call(
        &phone,
        json!({"op": "add_pasted", "text": env, "folder": acme, "pick": [0, 2],
               "titles": [{"index": 0, "title": "  Shop payments  "}]}),
    )["items"]
        .clone();
    let added = added.as_array().unwrap();
    assert_eq!(added.len(), 2);
    assert!(!serde_json::to_string(added).unwrap().contains(&stripe));
    assert_eq!(added[0]["title"], "Shop payments");
    assert_eq!(
        added[0]["summary"],
        "Shop payments · STRIPE_SECRET_KEY · production"
    );
    assert_eq!(added[0]["revision"], 1);
    let stripe_id = added[0]["id"].as_u64().unwrap();
    let db_id = added[1]["id"].as_u64().unwrap();
    let titles: Vec<String> = call(&phone, json!({"op": "items"}))["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["title"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(titles.len(), 2, "{titles:?}");

    // The row: the folder, the provider tile, and the red mark of production.
    let stripe_row = row(&phone, stripe_id);
    assert_eq!(stripe_row["folder"], json!(acme));
    assert_eq!(stripe_row["provider"], "Stripe");
    assert_eq!(stripe_row["production"], true);
    assert_eq!(stripe_row["kind"], "api_key");
    // The database URL has no strong environment signal: a default, not the red mark.
    let db_row = row(&phone, db_id);
    assert_eq!(db_row["production"], false);
    let db = call(&phone, json!({"op": "item", "id": db_id}));
    assert_eq!(db["environment"], "production");
    assert_eq!(db["environment_source"], "default");
    assert_eq!(db["env_name"], "DATABASE_URL");

    let detail = call(&phone, json!({"op": "item", "id": stripe_id}));
    assert_eq!(detail["env_name"], "STRIPE_SECRET_KEY");
    assert_eq!(detail["always_ask"], false);
    assert_eq!(detail["environment"], "production");
    assert_eq!(detail["environment_source"], "signal");
    assert_eq!(detail["folder_path"], json!(["Acme"]));
    assert_eq!(
        call(
            &phone,
            json!({"op": "reveal", "id": stripe_id, "field": "token"})
        )["value"],
        json!(stripe)
    );

    // Without `pick`: everything. A title that another item has gets " 2", as on the Mac.
    let all = call(
        &phone,
        json!({"op": "add_pasted", "text": format!("STRIPE_SECRET_KEY={stripe}\nGITHUB_TOKEN={github}")}),
    )["items"]
        .clone();
    assert_eq!(all.as_array().unwrap().len(), 2);
    assert_eq!(
        row(&phone, all[0]["id"].as_u64().unwrap())["folder"],
        Value::Null
    );
    let second =
        call(&phone, json!({"op": "add_pasted", "text": github.clone()}))["items"][0].clone();
    assert_eq!(second["title"], "GitHub token 2", "{second}");

    // A paste with nothing in it, a pick that does not match, an empty pick, and a
    // deleted folder add nothing.
    let before = call(&phone, json!({"op": "items"}))["items"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        fails(&phone, json!({"op": "add_pasted", "text": "  "})),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "add_pasted", "text": stripe.clone(), "pick": [1]})
        ),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "add_pasted", "text": stripe.clone(), "pick": [0, 0]})
        ),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "add_pasted", "text": stripe.clone(), "pick": []})
        ),
        "invalid_input"
    );
    call(&phone, json!({"op": "folder_delete", "uuid": acme}));
    assert_eq!(
        fails(
            &phone,
            json!({"op": "add_pasted", "text": stripe.clone(), "folder": acme})
        ),
        "not_found"
    );
    assert_eq!(
        call(&phone, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        before
    );

    // A paste is the owner's: the history has no agent origin.
    let history = call(&phone, json!({"op": "history", "id": stripe_id}))["events"].to_string();
    assert!(history.contains("Added"), "{history}");
    assert!(!history.contains("Added by"), "{history}");
}

#[test]
fn item_options_set_saves_the_owners_answer() {
    let root = TempDir::new().unwrap();
    let (phone, _) = phone(&root);
    let id = call(
        &phone,
        json!({"op": "add_pasted", "text": fake("sk_test_", 24)}),
    )["items"][0]["id"]
        .as_u64()
        .unwrap();
    let detail = call(&phone, json!({"op": "item", "id": id}));
    assert_eq!(detail["environment_source"], "signal");
    assert_ne!(detail["environment"], "production");
    assert_eq!(row(&phone, id)["production"], false);

    // The owner marks it as production and asks to be asked: the source is the owner.
    call(
        &phone,
        json!({"op": "item_options_set", "id": id, "always_ask": true, "environment": "production"}),
    );
    let detail = call(&phone, json!({"op": "item", "id": id}));
    assert_eq!(detail["always_ask"], true);
    assert_eq!(detail["environment"], "production");
    assert_eq!(detail["environment_source"], "owner");
    assert_eq!(detail["production"], true);
    assert_eq!(row(&phone, id)["production"], true);

    // Each option alone; the other stays.
    call(
        &phone,
        json!({"op": "item_options_set", "id": id, "always_ask": false}),
    );
    let detail = call(&phone, json!({"op": "item", "id": id}));
    assert_eq!(detail["always_ask"], false);
    assert_eq!(detail["environment"], "production");
    call(
        &phone,
        json!({"op": "item_options_set", "id": id, "environment": "staging"}),
    );
    let detail = call(&phone, json!({"op": "item", "id": id}));
    assert_eq!(detail["environment"], "staging");
    assert_eq!(detail["environment_source"], "owner");
    assert_eq!(detail["production"], false);

    // An item without a declaration gets one with this environment from the owner.
    let saved = call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item":
            {"title": "Wiki", "kind": "login", "fields": [
                {"name": "username", "value": "me", "secret": false},
                {"name": "password", "value": "synthetic-wiki-pw", "secret": true}]}}),
    )["id"]
        .as_u64()
        .unwrap();
    let plain = call(&phone, json!({"op": "item", "id": saved}));
    assert_eq!(plain["environment"], Value::Null);
    assert_eq!(plain["environment_source"], Value::Null);
    assert_eq!(plain["provider"], Value::Null);
    assert_eq!(plain["production"], false);
    call(
        &phone,
        json!({"op": "item_options_set", "id": saved, "environment": "development"}),
    );
    let plain = call(&phone, json!({"op": "item", "id": saved}));
    assert_eq!(plain["environment"], "development");
    assert_eq!(plain["environment_source"], "owner");

    assert_eq!(
        fails(
            &phone,
            json!({"op": "item_options_set", "id": id, "environment": "prod"})
        ),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "item_options_set", "id": 9999, "always_ask": true})
        ),
        "not_found"
    );
    let history = call(&phone, json!({"op": "history", "id": id}))["events"].to_string();
    assert!(history.contains("Declaration"), "{history}");
}

#[test]
fn a_locked_vault_and_the_autofill_extension_refuse_the_changes() {
    let root = TempDir::new().unwrap();
    let (phone, dir) = phone(&root);
    let folder = call(&phone, json!({"op": "folder_create", "name": "Acme"}))["folder"]["uuid"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = call(
        &phone,
        json!({"op": "add_pasted", "text": fake("ghp_", 36), "folder": folder}),
    )["items"][0]["id"]
        .as_u64()
        .unwrap();
    let requests = [
        json!({"op": "folders"}),
        json!({"op": "folder_create", "name": "X"}),
        json!({"op": "folder_rename", "uuid": folder, "name": "Y"}),
        json!({"op": "folder_move", "uuid": folder, "parent": null}),
        json!({"op": "folder_delete", "uuid": folder}),
        json!({"op": "item_folder_set", "id": id}),
        json!({"op": "detect", "text": fake("ghp_", 36)}),
        json!({"op": "add_pasted", "text": fake("ghp_", 36)}),
        json!({"op": "item_options_set", "id": id, "always_ask": true}),
    ];

    // The extension reads the folders and changes nothing.
    call(&phone, json!({"op": "suspend"}));
    let extension = core(&dir, "autofill");
    call(&extension, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(
        call(&extension, json!({"op": "folders"}))["folders"][0]["count"],
        1
    );
    assert_eq!(row(&extension, id)["folder"], json!(folder));
    for request in &requests[1..] {
        assert_eq!(
            fails(&extension, request.clone()),
            "not_allowed",
            "{request}"
        );
    }
    call(&extension, json!({"op": "lock"}));
    drop(extension);

    // Locked, every call is refused.
    call(&phone, json!({"op": "lock"}));
    for request in &requests {
        assert_eq!(fails(&phone, request.clone()), "locked", "{request}");
    }
    call(&phone, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(folder_names(&phone), [("Acme".to_owned(), None, 1)]);
}

#[test]
fn folder_and_option_changes_on_the_iphone_sync_with_the_mac() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();

    // The Mac: a vault on the relay as a new team.
    let mac_dir = data(&root, "mac");
    let mac_path = mac_dir.join("vault.db");
    let mac = RelaySync::new(RelayConfig::in_data_dir(
        &mac_dir, &mac_path, &relay.url, "vault",
    ));
    let mut mac_vault = Vault::create(&mac_path, PASS).unwrap();
    mac_vault.unlock(PASS).unwrap();
    let mac_folder = mac_vault.create_folder(None, "From the Mac").unwrap();
    mac.create_team(
        &mut mac_vault,
        "Personal",
        &relay.team_code(),
        "Synthetic MacBook",
    )
    .unwrap();

    // The iPhone joins.
    let phone_dir = data(&root, "phone");
    let phone = core(&phone_dir, "app");
    let code = mac.create_link(&mac_vault).unwrap();
    call(
        &phone,
        json!({"op": "join_start", "link": code.link.as_str(), "device_name": "Synthetic iPhone 18"}),
    );
    let links = mac.pending_links(&mac_vault, Some(&code)).unwrap();
    mac.confirm_link(&mac_vault, &links[0]).unwrap();
    assert_eq!(call(&phone, json!({"op": "join_poll"}))["state"], "ready");
    call(&phone, json!({"op": "join_finish", "passphrase": PASS}));
    assert_eq!(folder_names(&phone), [("From the Mac".to_owned(), None, 0)]);

    // The iPhone makes folders, pastes into one, and sets the options; one sync.
    let acme = call(&phone, json!({"op": "folder_create", "name": "Acme"}))["folder"]["uuid"]
        .as_str()
        .unwrap()
        .to_owned();
    let billing = call(
        &phone,
        json!({"op": "folder_create", "parent": acme, "name": "Billing"}),
    )["folder"]["uuid"]
        .as_str()
        .unwrap()
        .to_owned();
    let added = call(
        &phone,
        json!({"op": "add_pasted", "folder": billing,
               "text": format!("STRIPE_SECRET_KEY={}\nGITHUB_TOKEN={}", fake("sk_test_", 24), fake("ghp_", 36))}),
    )["items"]
        .clone();
    let stripe = added[0]["id"].as_u64().unwrap();
    let github = added[1]["id"].as_u64().unwrap();
    call(
        &phone,
        json!({"op": "item_folder_set", "id": github, "folder": mac_folder.uuid}),
    );
    call(
        &phone,
        json!({"op": "item_options_set", "id": stripe, "always_ask": true, "environment": "production"}),
    );
    let status = call(&phone, json!({"op": "sync"}))["status"].clone();
    assert_eq!(status["state"], "ok", "{status}");
    assert_eq!(status["pushed"], true, "{status}");

    mac.sync(&mut mac_vault).unwrap();
    let folders = mac_vault.folders().unwrap();
    let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
    assert!(
        names.contains(&"Acme") && names.contains(&"Billing"),
        "{names:?}"
    );
    let by_title = |title: &str| {
        mac_vault
            .search("")
            .unwrap()
            .into_iter()
            .find(|s| s.title == title)
            .unwrap_or_else(|| panic!("{title}"))
            .id
    };
    let mac_stripe = by_title("Stripe test");
    let mac_github = by_title("GitHub token");
    assert_eq!(
        mac_vault.item_folder(mac_stripe).unwrap(),
        Some(billing.clone())
    );
    assert_eq!(
        mac_vault.folder_path(Some(&billing)).unwrap(),
        ["Acme", "Billing"]
    );
    assert_eq!(
        mac_vault.item_folder(mac_github).unwrap(),
        Some(mac_folder.uuid.clone())
    );
    assert!(mac_vault.always_ask(mac_stripe).unwrap());
    assert_eq!(
        mac_vault
            .declaration(mac_stripe)
            .unwrap()
            .unwrap()
            .environment,
        Environment::Production
    );
    assert_eq!(
        mac_vault
            .declaration_sources(mac_stripe)
            .unwrap()
            .environment,
        DeclarationSource::Owner
    );

    // A folder-only change on the iPhone syncs too.
    call(
        &phone,
        json!({"op": "folder_rename", "uuid": acme, "name": "Acme Inc"}),
    );
    let status = call(&phone, json!({"op": "sync"}))["status"].clone();
    assert_eq!(status["pushed"], true, "{status}");
    mac.sync(&mut mac_vault).unwrap();
    assert_eq!(
        mac_vault.folder_path(Some(&billing)).unwrap(),
        ["Acme Inc", "Billing"]
    );

    // The Mac deletes a folder; the iPhone sees its credential at the parent.
    mac_vault.delete_folder(&billing).unwrap();
    mac.sync(&mut mac_vault).unwrap();
    call(&phone, json!({"op": "sync"}));
    let detail = call(&phone, json!({"op": "item", "id": stripe}));
    assert_eq!(detail["folder"], json!(acme));
    assert_eq!(detail["folder_path"], json!(["Acme Inc"]));
    assert!(
        !folder_names(&phone)
            .iter()
            .any(|(name, _, _)| name == "Billing")
    );
}
