//! Duplicates (contract ios-core-v1, section 5.3a), through the JSON calls as the iPhone
//! app makes them: the groups with labels only, a merge that archives the others, and
//! the errors of a merge. Synthetic values only: each secret starts with `SYNTH-DUP-`.

use std::fs;
use std::path::{Path, PathBuf};

use apassy_core::Core;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-phone-pass";
const CANARY: &str = "SYNTH-DUP-";

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
    assert!(!message.contains(CANARY), "a value is in the message");
    answer["error"]["code"].as_str().expect("code").to_owned()
}

fn data(root: &TempDir, name: &str) -> PathBuf {
    let dir = root.path().join(name).join("Apassy");
    fs::create_dir_all(&dir).expect("dir");
    dir
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

/// Save a new item: its ID.
fn save(phone: &Core, item: Value) -> u64 {
    call(
        phone,
        json!({"op": "save", "id": null, "revision": null, "item": item}),
    )["id"]
        .as_u64()
        .expect("id")
}

fn login(title: &str, password: &str, website: &str, notes: &str) -> Value {
    json!({
        "title": title,
        "kind": "login",
        "notes": notes,
        "fields": [
            {"name": "username", "value": "octo", "secret": false},
            {"name": "password", "value": password, "secret": true},
            {"label": "Website", "value": website, "secret": false},
        ],
    })
}

fn api_key(title: &str, token: &str, tags: Vec<String>) -> Value {
    json!({
        "title": title,
        "kind": "api_key",
        "tags": tags,
        "fields": [{"name": "token", "value": token, "secret": true}],
    })
}

fn groups(phone: &Core) -> Vec<Value> {
    let result = call(phone, json!({"op": "duplicates"}));
    assert!(
        !result.to_string().contains(CANARY),
        "a value is in the groups"
    );
    result["groups"].as_array().expect("groups").clone()
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
fn duplicates_list_labels_and_a_merge_archives_the_others() {
    let root = TempDir::new().unwrap();
    let (phone, _) = phone(&root);
    assert!(groups(&phone).is_empty());
    let kept = save(
        &phone,
        login("GitHub", "SYNTH-DUP-pw-1", "https://github.com", "Work"),
    );
    let import = save(
        &phone,
        login(
            "GitHub import",
            "SYNTH-DUP-pw-2",
            "www.github.com",
            "Imported",
        ),
    );
    save(&phone, login("Other", "SYNTH-DUP-pw-3", "other.test", ""));

    let list = groups(&phone);
    assert_eq!(list.len(), 1);
    let group = &list[0];
    let members: Vec<u64> = group["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_u64().unwrap())
        .collect();
    assert_eq!(members, [kept, import]);
    assert_eq!(group["items"][0]["kind"], "login");
    assert_eq!(group["items"][0]["title"], "GitHub");
    assert_eq!(group["items"][0]["revision"], 1);
    assert_eq!(group["items"][0]["has_passkey"], false);
    assert!(group["items"][0]["changed_at"].is_u64());
    assert_eq!(
        group["differences"],
        json!(["Password", "Website", "Notes", "Title"])
    );
    assert_eq!(group["identical"], false);
    assert_eq!(group["mergeable"], true);
    assert_eq!(group["reason"], Value::Null);
    assert!(members.contains(&group["keep"].as_u64().unwrap()));

    let merged = call(
        &phone,
        json!({"op": "duplicates_merge", "keep": kept, "keep_revision": 1,
               "others": [{"id": import, "revision": 1}]}),
    );
    assert_eq!(
        merged,
        json!({"id": kept, "revision": 2, "archived": [import]})
    );
    assert_eq!(row(&phone, import)["archived"], true);
    assert_eq!(row(&phone, kept)["archived"], false);
    assert!(groups(&phone).is_empty());
    // The other password is a hidden detail; the notes are joined.
    let detail = call(&phone, json!({"op": "item", "id": kept}));
    assert_eq!(detail["notes"], "Work\n\nImported");
    let previous = detail["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["label"] == "Previous password")
        .cloned()
        .expect("previous password");
    assert_eq!(previous["secret"], true);
    assert_eq!(previous["value"], Value::Null);
    let shown = call(
        &phone,
        json!({"op": "reveal", "id": kept, "field": previous["name"]}),
    );
    assert!(shown["value"] == "SYNTH-DUP-pw-2");
    // The archived item can come back.
    call(
        &phone,
        json!({"op": "archive", "id": import, "archived": false}),
    );
    assert_eq!(groups(&phone).len(), 1);
}

#[test]
fn a_merge_refuses_a_stale_revision_a_bad_group_and_a_limit() {
    let root = TempDir::new().unwrap();
    let (phone, _) = phone(&root);
    let one = save(&phone, api_key("One", "SYNTH-DUP-token", Vec::new()));
    let two = save(&phone, api_key("Two", "SYNTH-DUP-token", Vec::new()));
    let alone = save(&phone, api_key("Alone", "SYNTH-DUP-alone", Vec::new()));
    let merge = |keep: u64, keep_revision: u64, others: Value| {
        json!({"op": "duplicates_merge", "keep": keep, "keep_revision": keep_revision,
               "others": others})
    };
    assert_eq!(
        fails(&phone, merge(one, 2, json!([{"id": two, "revision": 1}]))),
        "conflict"
    );
    assert_eq!(
        fails(&phone, merge(one, 1, json!([{"id": alone, "revision": 1}]))),
        "invalid_input"
    );
    assert_eq!(fails(&phone, merge(one, 1, json!([]))), "invalid_input");
    assert_eq!(
        fails(&phone, merge(one, 1, json!([{"id": 9999, "revision": 1}]))),
        "not_found"
    );
    assert_eq!(
        fails(&phone, json!({"op": "duplicates_merge", "keep": one})),
        "invalid_input"
    );
    assert_eq!(row(&phone, two)["archived"], false);

    // Over 32 tags: `too_large`, and nothing changes.
    let tags = |prefix: &str, count: usize| -> Vec<String> {
        (0..count).map(|n| format!("{prefix}{n}")).collect()
    };
    let many = save(&phone, api_key("Many", "SYNTH-DUP-tags", tags("t", 30)));
    let more = save(&phone, api_key("More", "SYNTH-DUP-tags", tags("u", 3)));
    let list = groups(&phone);
    let group = list
        .iter()
        .find(|group| group["items"][0]["id"] == many)
        .expect("group");
    assert_eq!(group["mergeable"], false);
    assert_eq!(group["reason"], "Too many fields");
    assert_eq!(
        fails(&phone, merge(many, 1, json!([{"id": more, "revision": 1}]))),
        "too_large"
    );
    assert_eq!(row(&phone, more)["archived"], false);
    assert_eq!(row(&phone, many)["revision"], 1);
}

#[test]
fn only_the_app_finds_and_merges_duplicates() {
    let root = TempDir::new().unwrap();
    let (phone, dir) = phone(&root);
    let one = save(&phone, api_key("One", "SYNTH-DUP-role", Vec::new()));
    let two = save(&phone, api_key("Two", "SYNTH-DUP-role", Vec::new()));
    let requests = [
        json!({"op": "duplicates"}),
        json!({"op": "duplicates_merge", "keep": one, "keep_revision": 1,
               "others": [{"id": two, "revision": 1}]}),
    ];
    call(&phone, json!({"op": "suspend"}));
    let extension = core(&dir, "autofill");
    call(&extension, json!({"op": "unlock", "passphrase": PASS}));
    for request in &requests {
        assert_eq!(
            fails(&extension, request.clone()),
            "not_allowed",
            "{request}"
        );
    }
    call(&extension, json!({"op": "lock"}));
    drop(extension);
    let watch = core(&data(&root, "watch"), "watch");
    for request in &requests {
        assert_eq!(fails(&watch, request.clone()), "not_allowed", "{request}");
    }
    // Locked, the app gets `locked`.
    call(&phone, json!({"op": "lock"}));
    for request in &requests {
        assert_eq!(fails(&phone, request.clone()), "locked", "{request}");
    }
    call(&phone, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(groups(&phone).len(), 1);
}
