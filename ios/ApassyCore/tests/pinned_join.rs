//! The iPhone joins a vault on a pinned node (contract node-pairing-v1; plan S2–S3, unit
//! N3). The in-process fake relay of the app's tests stands behind the real TLS front of
//! the node on the loopback (`apassy::net::tls_front`, with its test hooks) and a new
//! self-signed node certificate. The Mac's device link carries the pin; the iPhone keeps
//! it in `phone.json` and in the membership, and syncs only through that pin. Synthetic
//! values only.

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use apassy::contracts::CredentialKind;
use apassy::net::certificate::NodeCertificate;
use apassy::net::pin::Pin;
use apassy::net::tls_front::{Front, FrontHandle, FrontLimits, FrontOptions};
use apassy::sync::{RelayConfig, RelaySync, TlsTrust};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use apassy_core::Core;
use fake_relay::FakeRelay;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-pinned-phone-pass";

fn core(dir: &Path) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Synthetic iPhone", "role": "app"});
    Core::new(&config.to_string()).expect("core")
}

fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).expect("json");
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

fn fails(core: &Core, request: Value) -> String {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).expect("json");
    assert_eq!(answer["ok"], false, "{request} -> {answer}");
    answer["error"]["code"].as_str().expect("code").to_owned()
}

fn data(root: &TempDir, name: &str) -> PathBuf {
    let dir = root.path().join(name).join("Apassy");
    fs::create_dir_all(&dir).expect("dir");
    dir
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

/// The fake relay behind a TLS front with a node certificate: the front, the node
/// origin, and the pin.
fn pinned_node(relay: &FakeRelay) -> (FrontHandle, String, Pin) {
    let target: SocketAddr = relay
        .url
        .strip_prefix("http://")
        .expect("plain fake relay")
        .parse()
        .expect("loopback address");
    let certificate = NodeCertificate::generate("Synthetic Test Mac").expect("certificate");
    let pin = certificate.pin;
    let mut options = FrontOptions::new(
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        0,
        certificate,
        target,
    );
    options.allow_loopback_bind = true;
    options.allow_test_peers = true;
    options.limits = FrontLimits {
        max_connections: 256,
        max_per_peer: 256,
        new_per_peer_per_minute: 100_000,
        ..FrontLimits::default()
    };
    let front = Front::start(options).expect("front");
    let origin = format!("https://127.0.0.1:{}", front.bound()[0].port());
    relay.set_origin(&origin);
    (front, origin, pin)
}

#[test]
fn an_iphone_joins_a_pinned_node_and_keeps_the_pin_in_its_entry() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let (_front, origin, pin) = pinned_node(&relay);

    // The Mac: a vault on the node as a new team, through the pin.
    let mac_dir = data(&root, "mac");
    let mac_path = mac_dir.join("vault.db");
    let mac = RelaySync::new(
        RelayConfig::in_data_dir(&mac_dir, &mac_path, &origin, "vault")
            .with_trust(TlsTrust::Pinned(pin), &[]),
    );
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

    // A link with another pin is refused before any request reaches the node.
    let phone_dir = data(&root, "phone");
    let phone = core(&phone_dir);
    let code = mac.create_link(&mac_vault).unwrap();
    assert!(code.link.contains(&format!("&pin={}", pin.text())));
    let other = Pin::of_certificate(b"synthetic other certificate").text();
    let wrong = code.link.replace(&pin.text(), &other);
    let seen = relay.log().len();
    assert_eq!(
        fails(
            &phone,
            json!({"op": "join_start", "link": wrong, "device_name": "Synthetic iPhone 18"})
        ),
        "pin_mismatch"
    );
    assert_eq!(relay.log().len(), seen, "no request reached the node");
    // A link with an unknown key is refused by the grammar.
    let unknown = format!("{}&foo=1", code.link.as_str());
    assert_eq!(
        fails(&phone, json!({"op": "join_start", "link": unknown})),
        "link_invalid"
    );

    // The pinned link joins: the same words on both, the owner confirms on the Mac. The
    // link carries the node's name (node-pairing-v1 section 7): it changes no word.
    let named = format!("{}&name=Mac%20mini", code.link.as_str());
    let join = call(
        &phone,
        json!({"op": "join_start", "link": named, "device_name": "Synthetic iPhone 18"}),
    );
    assert_eq!(join["state"], "waiting");
    // The app shows "via your Mac": the join names the node origin and its name.
    assert_eq!(join["node"]["origin"], json!(origin));
    assert_eq!(join["node"]["name"], "Mac mini", "{join}");
    // ... and the six node words of the pin (node-pairing-v1 section 4a), the words that
    // the Mac shows for the same pin.
    assert_eq!(join["node"]["node_words"], json!(pin.words()), "{join}");
    let links = mac.pending_links(&mac_vault, Some(&code)).unwrap();
    assert_eq!(links.len(), 1);
    let words: Vec<String> = join["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(links[0].safety.as_deref(), Some(words.join(" ").as_str()));
    mac.confirm_link(&mac_vault, &links[0]).unwrap();
    assert_eq!(call(&phone, json!({"op": "join_poll"}))["state"], "ready");
    let vault = call(&phone, json!({"op": "join_finish", "passphrase": PASS}))["vault"].clone();
    assert_eq!(
        vault["relay_url"],
        json!(origin),
        "the origin is the stored value"
    );
    assert_eq!(vault["pin"], json!(pin.text()));
    // The name stays with the entry for Settings > Devices (unit N6).
    assert_eq!(vault["node_name"], "Mac mini");
    let id = vault["id"].as_str().unwrap().to_owned();

    // The entry in phone.json has the pin; the list version stays 1.
    let list: Value =
        serde_json::from_str(&fs::read_to_string(phone_dir.join("phone.json")).unwrap()).unwrap();
    assert_eq!(list["version"], 1);
    let entry = list["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(id))
        .expect("entry")
        .clone();
    assert_eq!(entry["pin"], json!(pin.text()));
    assert_eq!(entry["relay_url"], json!(origin));
    assert_eq!(entry["node_name"], "Mac mini");
    let items = call(&phone, json!({"op": "items"}))["items"].clone();
    assert_eq!(items[0]["title"], "Alpha");

    // The iPhone syncs through the pin; the Mac merges its item.
    call(
        &phone,
        json!({"op": "save", "id": null, "revision": null, "item": {
            "title": "From the phone", "kind": "login", "notes": "", "tags": [],
            "fields": [
                {"name": "username", "value": "me", "secret": false},
                {"name": "password", "value": "synthetic-phone-pw", "secret": true}]}}),
    );
    let status = call(&phone, json!({"op": "sync"}))["status"].clone();
    assert_eq!(status["state"], "ok", "{status}");
    assert_eq!(status["pushed"], true);
    mac.sync(&mut mac_vault).unwrap();
    let mut titles: Vec<String> = mac_vault
        .search("")
        .unwrap()
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    titles.sort();
    assert_eq!(titles, ["Alpha", "From the phone"]);
    // No request byte to the relay carried the pin or the name.
    assert!(!relay.log().iter().any(|line| line.contains("pin=")));
    assert!(!relay.log().iter().any(|line| line.contains("name=Mac")));

    // The questions team of the vault is its sync team on the node: its status names the
    // node origin, for "via your Mac" in Settings > Devices (unit N6).
    let list = call(&phone, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["enabled"], true, "{list}");
    assert_eq!(list["status"]["node"]["origin"], json!(origin), "{list}");
    assert_eq!(list["vaults"][0]["status"]["node"]["origin"], json!(origin));
    assert_eq!(
        list["status"]["node"]["node_words"],
        json!(pin.words()),
        "{list}"
    );
    assert_eq!(
        list["vaults"][0]["status"]["node"]["node_words"],
        json!(pin.words())
    );
}
