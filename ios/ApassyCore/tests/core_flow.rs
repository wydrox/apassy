//! The core through its JSON calls (contract ios-core-v1), as the iPhone app makes
//! them. A Mac on the in-process fake relay of the app's own tests stands in for the
//! owner's Mac. Synthetic values only.

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::fs;
use std::path::{Path, PathBuf};

use apassy::contracts::CredentialKind;
use apassy::sync::{RelayConfig, RelaySync};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use apassy_core::Core;
use fake_relay::FakeRelay;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-phone-pass";

fn core(dir: &Path, role: &str) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Synthetic iPhone", "role": role});
    Core::new(&config.to_string()).expect("core")
}

/// A call that must work: its result.
fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).expect("json");
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

/// A call that must fail: its error code.
fn fails(core: &Core, request: Value) -> String {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).expect("json");
    assert_eq!(answer["ok"], false, "{request} -> {answer}");
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(!message.is_empty());
    answer["error"]["code"].as_str().expect("code").to_owned()
}

fn login(title: &str, user: &str, password: &str, website: &str) -> Value {
    json!({"title": title, "kind": "login", "notes": "", "tags": ["work"], "fields": [
        {"name": "username", "value": user, "secret": false},
        {"name": "password", "value": password, "secret": true},
        {"label": "Website", "value": website, "secret": false},
        {"label": "One-time password", "value": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "secret": true},
    ]})
}

fn data(root: &TempDir, name: &str) -> PathBuf {
    let dir = root.path().join(name).join("Apassy");
    fs::create_dir_all(&dir).expect("dir");
    dir
}

#[test]
fn a_local_vault_lists_shows_reveals_and_saves_like_the_mac() {
    let root = TempDir::new().unwrap();
    let dir = data(&root, "phone");
    let phone = core(&dir, "app");
    assert_eq!(call(&phone, json!({"op": "info"}))["vaults"], json!([]));
    assert_eq!(fails(&phone, json!({"op": "items"})), "no_vault");
    assert_eq!(fails(&phone, json!({"op": "nope"})), "invalid_input");
    assert_eq!(
        fails(
            &phone,
            json!({"op": "create_local_vault", "name": "Personal", "passphrase": "short"})
        ),
        "invalid_input"
    );
    let vault = call(
        &phone,
        json!({"op": "create_local_vault", "name": "Personal", "passphrase": PASS}),
    );
    let id = vault["vault"]["id"].as_str().unwrap().to_owned();
    assert!(dir.join("vaults").join(format!("{id}.apassy")).exists());

    let saved = call(
        &phone,
        json!({"op": "save", "id": null, "revision": null,
        "item": login("GitHub", "octocat", "synthetic-Pw-7Hq2!kLm9x", "github.com")}),
    );
    let github = saved["id"].as_u64().unwrap();
    call(
        &phone,
        json!({"op": "save", "id": null, "revision": null,
        "item": login("Netflix", "family", "short1", "https://www.netflix.com/login")}),
    );
    let api = call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item":
        {"title": "Stripe", "kind": "api_key", "fields": [
            {"name": "service", "value": "stripe", "secret": false},
            {"name": "token", "value": "sk_synthetic", "secret": true}]}}),
    )["id"]
        .as_u64()
        .unwrap();

    // The list: sorted, no secret, the Mac's subtitle and websites.
    let items = call(&phone, json!({"op": "items"}))["items"].clone();
    let titles: Vec<&str> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["GitHub", "Netflix", "Stripe"]);
    assert_eq!(items[0]["subtitle"], "octocat");
    assert_eq!(items[0]["websites"], json!(["github.com"]));
    assert_eq!(items[0]["has_totp"], true);
    assert_eq!(
        items[2]["tags"],
        json!(["stripe"]),
        "the service is a tag, as on the Mac"
    );
    assert!(!items.to_string().contains("synthetic-Pw"));

    // One item: the Mac's labels and order, no secret value.
    let detail = call(&phone, json!({"op": "item", "id": github}));
    let names: Vec<&str> = detail["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["label"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["Username", "Password", "Website", "One-time password"]
    );
    let roles: Vec<&str> = detail["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["username", "password", "website", "totp"]);
    assert_eq!(detail["fields"][1]["value"], Value::Null);
    assert_eq!(detail["fields"][2]["custom"], true);
    let password_field = detail["fields"][1]["name"].as_str().unwrap();
    let totp_field = detail["fields"][3]["name"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            &phone,
            json!({"op": "reveal", "id": github, "field": password_field})
        )["value"],
        "synthetic-Pw-7Hq2!kLm9x"
    );
    let code = call(
        &phone,
        json!({"op": "totp", "id": github, "field": totp_field}),
    );
    assert_eq!(code["code"].as_str().unwrap().len(), 6);
    assert_eq!(code["period"], 30);
    let history = call(&phone, json!({"op": "history", "id": github}))["events"].clone();
    assert!(
        history.to_string().contains("Secret values shown"),
        "{history}"
    );

    // An edit keeps a secret that is null, refuses a stale revision and a new kind.
    let revision = detail["revision"].as_u64().unwrap();
    let mut edit = login("GitHub (work)", "octocat", "", "github.com");
    edit["fields"][1]["value"] = Value::Null;
    edit["fields"][3]["value"] = Value::Null;
    edit["fields"][3]["name"] = json!(totp_field);
    let edited = call(
        &phone,
        json!({"op": "save", "id": github, "revision": revision, "item": edit}),
    );
    assert!(edited["revision"].as_u64().unwrap() > revision);
    assert_eq!(
        call(
            &phone,
            json!({"op": "reveal", "id": github, "field": "password"})
        )["value"],
        "synthetic-Pw-7Hq2!kLm9x"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "save", "id": github, "revision": revision, "item": login("X", "u", "p", "x.com")})
        ),
        "conflict"
    );
    let mut other_kind = login("X", "u", "p", "x.com");
    other_kind["kind"] = json!("api_key");
    assert_eq!(
        fails(
            &phone,
            json!({"op": "save", "id": github, "revision": edited["revision"], "item": other_kind})
        ),
        "invalid_input"
    );
    let mut no_user = login("Y", "", "p", "y.com");
    no_user["fields"][0]["value"] = json!("  ");
    assert_eq!(
        fails(
            &phone,
            json!({"op": "save", "id": null, "revision": null, "item": no_user})
        ),
        "invalid_input"
    );

    // Watchtower: the weak and the reused password, by ID only.
    call(
        &phone,
        json!({"op": "save", "id": null, "revision": null,
        "item": login("Twin", "family2", "short1", "twin.example")}),
    );
    let report = call(&phone, json!({"op": "watchtower"}));
    assert_eq!(report["checked"], 3);
    assert_eq!(report["weak"].as_array().unwrap().len(), 2);
    assert_eq!(report["reused"].as_array().unwrap().len(), 1);
    assert!(!report.to_string().contains("short1"));

    // AutoFill: the match by host and subdomain, the fill, the identities.
    let fills = call(
        &phone,
        json!({"op": "autofill_list", "domains": ["accounts.netflix.com"]}),
    );
    assert_eq!(fills["matches"].as_array().unwrap().len(), 1);
    assert_eq!(fills["matches"][0]["title"], "Netflix");
    let netflix = fills["matches"][0]["id"].as_u64().unwrap();
    let credential = call(&phone, json!({"op": "autofill_credential", "id": netflix}));
    assert_eq!(
        credential,
        json!({"username": "family", "password": "short1"})
    );
    assert_eq!(
        fails(&phone, json!({"op": "autofill_credential", "id": api})),
        "invalid_input"
    );
    let identities = call(&phone, json!({"op": "credential_identities"}))["identities"].clone();
    assert!(
        identities.to_string().contains("\"host\":\"netflix.com\""),
        "{identities}"
    );
    assert!(!identities.to_string().contains("short1"));

    // Archive and delete.
    call(
        &phone,
        json!({"op": "archive", "id": api, "archived": true}),
    );
    assert_eq!(
        call(&phone, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        call(&phone, json!({"op": "items", "archived": "yes"}))["items"][0]["title"],
        "Stripe"
    );
    let stripe = call(&phone, json!({"op": "item", "id": api}));
    call(
        &phone,
        json!({"op": "delete", "id": api, "revision": stripe["revision"]}),
    );
    assert_eq!(fails(&phone, json!({"op": "item", "id": api})), "not_found");

    // The name decides the secret flag; a field of another kind is refused.
    let flagged = call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item":
        {"title": "Flags", "kind": "login", "fields": [
            {"name": "username", "value": "u", "secret": true},
            {"name": "password", "value": "synthetic-flag-pw", "secret": false}]}}),
    );
    let detail = call(&phone, json!({"op": "item", "id": flagged["id"]}));
    assert_eq!(detail["fields"][0]["secret"], false);
    assert_eq!(detail["fields"][1]["secret"], true);
    assert_eq!(detail["fields"][1]["value"], Value::Null);
    assert_eq!(
        fails(
            &phone,
            json!({"op": "save", "id": null, "revision": null, "item":
            {"title": "X", "kind": "login", "fields": [
                {"name": "username", "value": "u", "secret": false},
                {"name": "password", "value": "p", "secret": true},
                {"name": "token", "value": "t", "secret": true}]}})
        ),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "save", "id": null, "revision": null, "item":
            {"title": "X", "kind": "custom", "fields": [
                {"name": "one", "value": "1", "secret": true},
                {"name": "two", "value": "2", "secret": true}]}})
        ),
        "invalid_input"
    );
    let answer: Value = serde_json::from_str(
        &phone.call(
            &json!({"op": "save", "id": null, "revision": null, "item":
        {"title": "Long", "kind": "api_key", "fields": [
            {"name": "service", "value": "s".repeat(80), "secret": false},
            {"name": "token", "value": "t", "secret": true}]}})
            .to_string(),
        ),
    )
    .unwrap();
    assert_eq!(answer["ok"], false);
    assert!(
        !answer.to_string().contains(&"s".repeat(80)),
        "the message quotes no value"
    );
    let flags = call(&phone, json!({"op": "item", "id": flagged["id"]}));
    call(
        &phone,
        json!({"op": "delete", "id": flagged["id"], "revision": flags["revision"]}),
    );

    // Generator and strength.
    // The EFF list holds hyphenated words ("drop-down", "felt-tip", "t-shirt",
    // "yo-yo"), so "-" cannot count words; no word holds ".".
    let generated = call(
        &phone,
        json!({"op": "generate", "style": "memorable", "words": 4, "separator": "."}),
    );
    let words: Vec<&str> = generated["value"].as_str().unwrap().split('.').collect();
    assert_eq!(words.len(), 4);
    assert!(
        words
            .iter()
            .all(|word| word.chars().next().is_some_and(char::is_uppercase)
                && word.chars().all(|c| c.is_ascii_alphabetic() || c == '-')),
        "four capitalized words"
    );
    assert!((generated["bits"].as_f64().unwrap() - 4.0 * 7776f64.log2()).abs() < 0.1);
    assert_eq!(
        call(&phone, json!({"op": "strength", "value": "short1"}))["score"],
        0
    );

    // The owner check by passphrase works while the vault is open.
    assert_eq!(
        call(
            &phone,
            json!({"op": "check_passphrase", "passphrase": PASS})
        )["ok"],
        true
    );

    // A local vault does not sync.
    assert_eq!(
        call(&phone, json!({"op": "sync"}))["status"]["state"],
        "off"
    );

    // The lock closes the vault file, so another process can open it.
    call(&phone, json!({"op": "lock"}));
    assert_eq!(fails(&phone, json!({"op": "items"})), "locked");
    assert!(
        !dir.join("vaults")
            .join(format!("{id}.apassy.lock"))
            .exists()
            || {
                let file = Vault::open(&dir.join("vaults").join(format!("{id}.apassy")))
                    .expect("the lock is free");
                drop(file);
                true
            }
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "unlock", "passphrase": "synthetic-wrong-pass"})
        ),
        "wrong_passphrase"
    );
    assert_eq!(
        call(
            &phone,
            json!({"op": "check_passphrase", "passphrase": PASS})
        )["ok"],
        true
    );
    assert_eq!(
        call(
            &phone,
            json!({"op": "check_passphrase", "passphrase": "nope-nope-nope"})
        )["ok"],
        false
    );

    // Suspend and resume: with `keep`, without it.
    call(
        &phone,
        json!({"op": "unlock", "passphrase": PASS, "keep": true}),
    );
    call(&phone, json!({"op": "suspend"}));
    assert_eq!(fails(&phone, json!({"op": "items"})), "locked");
    assert_eq!(call(&phone, json!({"op": "resume"}))["unlocked"], true);
    assert_eq!(
        call(&phone, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    call(&phone, json!({"op": "lock"}));
    assert_eq!(call(&phone, json!({"op": "resume"}))["unlocked"], false);

    // The AutoFill extension reads the same vault, while the app has it closed.
    let extension = core(&dir, "autofill");
    let info = call(&extension, json!({"op": "info"}));
    assert_eq!(info["selected"], json!(id));
    call(&extension, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(
        call(&extension, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    for op in [
        "sync",
        "watchtower",
        "history",
        "join_start",
        "suspend",
        "generate",
        "strength",
    ] {
        assert_eq!(
            fails(&extension, json!({"op": op, "id": 1, "link": "x"})),
            "not_allowed",
            "{op}"
        );
    }
    assert_eq!(
        fails(
            &extension,
            json!({"op": "save", "id": null, "revision": null, "item": login("Z", "z", "z", "z.com")})
        ),
        "not_allowed"
    );
    // While the extension holds it, the app gets `busy`.
    assert_eq!(
        fails(&phone, json!({"op": "unlock", "passphrase": PASS})),
        "busy"
    );
    call(&extension, json!({"op": "lock"}));
    call(&phone, json!({"op": "unlock", "passphrase": PASS}));

    // Remove a vault that is not selected: the selected one stays open.
    let other = call(
        &phone,
        json!({"op": "create_local_vault", "name": "Other", "passphrase": PASS}),
    )["vault"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    call(&phone, json!({"op": "select", "vault_id": id}));
    call(&phone, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(
        call(
            &phone,
            json!({"op": "remove_vault", "vault_id": other, "force": true})
        )["left_relay"],
        true
    );
    assert_eq!(call(&phone, json!({"op": "info"}))["selected"], json!(id));
    assert_eq!(
        call(&phone, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    // A join that was cancelled is gone.
    assert_eq!(fails(&phone, json!({"op": "join_poll"})), "invalid_input");

    // Remove the vault from this iPhone.
    assert_eq!(
        call(
            &phone,
            json!({"op": "remove_vault", "vault_id": id, "force": false})
        )["left_relay"],
        true
    );
    assert!(!dir.join("vaults").join(format!("{id}.apassy")).exists());
    assert_eq!(call(&phone, json!({"op": "info"}))["vaults"], json!([]));
}

fn api_item(title: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(token.to_owned()),
            secret: true,
        }],
    }
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut titles: Vec<String> = vault
        .search("")
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    titles.sort();
    titles
}

#[test]
fn an_iphone_joins_a_mac_vault_on_the_relay_and_syncs_both_ways() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();

    // The Mac: a vault with one item, on the relay as a new team.
    let mac_dir = data(&root, "mac");
    let mac_path = mac_dir.join("vault.db");
    let mac = RelaySync::new(RelayConfig::in_data_dir(
        &mac_dir, &mac_path, &relay.url, "vault",
    ));
    let mut mac_vault = Vault::create(&mac_path, PASS).unwrap();
    mac_vault.unlock(PASS).unwrap();
    mac_vault.add(api_item("Alpha", "SYNTH-alpha")).unwrap();
    mac.create_team(
        &mut mac_vault,
        "Personal",
        &relay.team_code(),
        "Synthetic MacBook",
    )
    .unwrap();

    // The iPhone sends the link of "Add a device…"; both show the same words.
    let phone_dir = data(&root, "phone");
    let phone = core(&phone_dir, "app");
    assert_eq!(
        fails(&phone, json!({"op": "join_start", "link": "not a link"})),
        "link_invalid"
    );
    let code = mac.create_link(&mac_vault).unwrap();
    let join = call(
        &phone,
        json!({"op": "join_start", "link": code.link.as_str(), "device_name": "Synthetic iPhone 18"}),
    );
    assert_eq!(join["state"], "waiting");
    assert_eq!(join["team"], "Personal");
    assert_eq!(call(&phone, json!({"op": "join_poll"}))["state"], "waiting");
    let links = mac.pending_links(&mac_vault, Some(&code)).unwrap();
    assert_eq!(links[0].device_name, "Synthetic iPhone 18");
    let words: Vec<String> = join["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(links[0].safety.as_deref(), Some(words.join(" ").as_str()));
    assert_eq!(
        call(&phone, json!({"op": "info"}))["join"]["words"],
        join["words"]
    );

    // The owner confirms on the Mac; the iPhone downloads and opens the copy.
    mac.confirm_link(&mac_vault, &links[0]).unwrap();
    assert_eq!(call(&phone, json!({"op": "join_poll"}))["state"], "ready");
    assert_eq!(
        fails(
            &phone,
            json!({"op": "join_finish", "passphrase": "synthetic-wrong-pass"})
        ),
        "wrong_passphrase"
    );
    let vault = call(&phone, json!({"op": "join_finish", "passphrase": PASS}))["vault"].clone();
    assert_eq!(vault["name"], "Personal");
    assert_eq!(vault["relay_url"], json!(relay.url));
    assert!(vault["device_id"].as_u64().is_some());
    let id = vault["id"].as_str().unwrap().to_owned();
    assert!(
        phone_dir
            .join("vaults")
            .join(format!("{id}.apassy"))
            .exists()
    );
    assert!(phone_dir.join("sync").join(format!("{id}.json")).exists());
    let items = call(&phone, json!({"op": "items"}))["items"].clone();
    assert_eq!(items[0]["title"], "Alpha");
    assert_eq!(
        call(
            &phone,
            json!({"op": "reveal", "id": items[0]["id"], "field": "token"})
        )["value"],
        "SYNTH-alpha"
    );
    let devices = call(&phone, json!({"op": "devices"}))["devices"].clone();
    assert_eq!(devices.as_array().unwrap().len(), 2);
    assert!(devices.to_string().contains("Synthetic iPhone 18"));

    // The iPhone adds an item and syncs; the Mac merges it.
    call(
        &phone,
        json!({"op": "save", "id": null, "revision": null,
        "item": login("From the phone", "me", "synthetic-phone-pw", "phone.example")}),
    );
    let status = call(&phone, json!({"op": "sync"}))["status"].clone();
    assert_eq!(status["state"], "ok", "{status}");
    assert_eq!(status["pushed"], true);
    mac.sync(&mut mac_vault).unwrap();
    assert_eq!(titles(&mac_vault), ["Alpha", "From the phone"]);

    // The Mac changes an item; the long poll sees it and the iPhone merges it.
    mac_vault.add(api_item("Beta", "SYNTH-beta")).unwrap();
    mac.sync(&mut mac_vault).unwrap();
    assert_eq!(
        call(&phone, json!({"op": "sync_wait", "timeout": 2}))["changed"],
        true
    );
    let status = call(&phone, json!({"op": "sync"}))["status"].clone();
    assert_eq!(status["merged"]["inserted"], 1, "{status}");
    assert_eq!(
        call(&phone, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        call(&phone, json!({"op": "sync_status"}))["status"]["state"],
        "ok"
    );

    // The passphrase changes on the Mac: the iPhone takes it, and it opens the vault after.
    mac_vault
        .change_passphrase(PASS, "synthetic-new-pass")
        .unwrap();
    mac_vault.add(api_item("Gamma", "SYNTH-gamma")).unwrap();
    mac.sync(&mut mac_vault).unwrap();
    assert_eq!(
        call(&phone, json!({"op": "sync"}))["status"]["state"],
        "needs_passphrase"
    );
    assert_eq!(
        fails(
            &phone,
            json!({"op": "take_new_passphrase", "passphrase": "synthetic-wrong-pass"})
        ),
        "wrong_passphrase"
    );
    let taken = call(
        &phone,
        json!({"op": "take_new_passphrase", "passphrase": "synthetic-new-pass"}),
    );
    assert_eq!(taken["rekeyed"], true, "{taken}");
    assert_eq!(taken["status"]["state"], "ok");
    assert_eq!(
        call(&phone, json!({"op": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    call(&phone, json!({"op": "lock"}));
    assert_eq!(
        fails(&phone, json!({"op": "unlock", "passphrase": PASS})),
        "wrong_passphrase"
    );
    call(
        &phone,
        json!({"op": "unlock", "passphrase": "synthetic-new-pass"}),
    );
    call(&phone, json!({"op": "lock"}));

    // Locked, the iPhone does not sync.
    call(&phone, json!({"op": "lock"}));
    assert_eq!(fails(&phone, json!({"op": "sync"})), "locked");

    // Remove: the iPhone leaves the team; the Mac keeps its vault.
    call(
        &phone,
        json!({"op": "unlock", "passphrase": "synthetic-new-pass"}),
    );
    assert_eq!(
        call(
            &phone,
            json!({"op": "remove_vault", "vault_id": id, "force": false})
        )["left_relay"],
        true
    );
    assert_eq!(relay.devices().len(), 1);
    mac.sync(&mut mac_vault).unwrap();
}
