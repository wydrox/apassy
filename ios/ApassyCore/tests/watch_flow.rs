//! The Apple Watch core (ADR 0039, contract ios-core-v1 section 5.13) through the JSON
//! calls, against the in-process fake relay: the role refuses every call but its own,
//! and a watch connects with a Connect code, answers access requests, and forgets its
//! replica. The asking Mac is played by the test. Synthetic keys only; no Keychain.

#[path = "common/questions_relay.rs"]
mod questions_relay;

#[path = "common/questions_fixture.rs"]
mod questions_fixture;

use std::path::Path;
use std::sync::Arc;

use apassy::questions::access_request as access;
use apassy::relay::{membership::register_linked_device, pairing::PairingChannel};
use apassy::sync::{DeviceKey, decode_b64u, encode_b64u};
use apassy::vault::{TrustedDeviceKind, Vault};
use apassy_core::Core;
use questions_fixture::*;
use questions_relay::{FakeGateway, QuestionsRelay, now};
use serde_json::{Value, json};

const WATCH_PASS: &str = "synthetic-watch-replica-pass";

const WATCH_OPS: [&str; 5] = [
    "watch_connect_start",
    "watch_connect_poll",
    "watch_connect_cancel",
    "watch_status",
    "watch_forget",
];

fn watch_core(data: &Path, keys: Arc<SyntheticHistoryKeys>) -> Core {
    std::fs::create_dir_all(data.join("request-history")).unwrap();
    // Synthetic host only: the shipping Swift host verifies Foundation backup exclusion.
    Core::new_with_history_key_provider(
        &json!({"data_dir": data, "device_name": "Test Watch", "role": "watch",
                "request_history_enabled": true, "request_guard_storage_ready": true})
        .to_string(),
        keys,
    )
    .unwrap()
}

fn failure(core: &Core, request: Value) -> (String, String) {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).unwrap();
    assert_eq!(answer["ok"], false, "{request} -> {answer}");
    (
        answer["error"]["code"].as_str().unwrap().to_owned(),
        answer["error"]["message"].as_str().unwrap().to_owned(),
    )
}

#[test]
fn a_watch_core_refuses_every_call_but_its_own() {
    let root = tempfile::tempdir().unwrap();
    let watch = watch_core(&root.path().join("Watch"), Arc::default());
    for op in [
        "items",
        "item",
        "reveal",
        "totp",
        "history",
        "save",
        "archive",
        "delete",
        "generate",
        "strength",
        "watchtower",
        "check_passphrase",
        "create_local_vault",
        "remove_vault",
        "sync",
        "sync_wait",
        "sync_status",
        "take_new_passphrase",
        "use_relay_copy",
        "devices",
        "icloud_import",
        "icloud_sync_prepare",
        "icloud_sync_complete",
        "join_start",
        "join_poll",
        "join_cancel",
        "join_finish",
        "autofill_list",
        "autofill_credential",
        "credential_export",
        "credential_identities",
        "passkey_list",
        "passkey_assert",
        "passkey_register",
        "passkey_import",
        "passkey_remove",
        "folders",
        "folder_create",
        "item_folder_set",
        "detect",
        "add_pasted",
        "item_options_set",
        "questions_list",
        "request_history",
        "clear_request_history",
        "questions_unlock",
        "question_open",
        "question_answer_string",
        "question_answer",
        "answer_key_register",
        "join_attach",
        "join_attach_poll",
        "join_attach_cancel",
        "feed_list",
        "feed_wait",
        "feed_action_string",
        "feed_action",
        "feed_action_wait",
        "feed_action_status",
        "no_such_call",
    ] {
        let (code, message) = failure(&watch, json!({"op": op}));
        assert_eq!(code, "not_allowed", "{op}");
        assert_eq!(message, "Not available on Apple Watch.", "{op}");
    }
    // Its own calls run.
    let info = call(&watch, json!({"op": "info"}));
    assert_eq!(info["vaults"], json!([]));
    assert_eq!(info["unlocked"], false);
    assert_eq!(
        call(&watch, json!({"op": "watch_status"})),
        json!({"state": "unpaired", "vault": null, "macs": [], "own": null})
    );
    call(&watch, json!({"op": "lock"}));
    call(&watch, json!({"op": "suspend"}));
    assert_eq!(call(&watch, json!({"op": "resume"}))["unlocked"], false);
    assert_eq!(
        call(&watch, json!({"op": "access_requests_list"}))["requests"],
        json!([])
    );
    call(&watch, json!({"op": "access_request_cancel_prepared"}));
    assert_eq!(
        fails(&watch, json!({"op": "questions_wait", "timeout": 1})),
        "no_vault"
    );
    assert_eq!(
        fails(&watch, json!({"op": "watch_connect_poll"})),
        "invalid_input"
    );
    call(&watch, json!({"op": "watch_connect_cancel"}));
    assert_eq!(
        call(&watch, json!({"op": "watch_forget"}))["state"],
        "unpaired"
    );
    // The app and the AutoFill extension refuse the calls of the watch.
    for role in ["app", "autofill"] {
        let dir = root.path().join(role);
        std::fs::create_dir_all(&dir).unwrap();
        let other = core(&dir, role);
        for op in WATCH_OPS {
            assert_eq!(
                fails(&other, json!({"op": op})),
                "not_allowed",
                "{role} {op}"
            );
        }
    }
}

#[test]
fn a_watch_connects_only_with_a_handoff_code() {
    let root = tempfile::tempdir().unwrap();
    let watch = watch_core(&root.path().join("Watch"), Arc::default());
    let plain = "https://relay.example.test/link#apassy_lnk_t_7k2m5q4x3c_synthetic";
    let start = |link: &str, answer_key: &str, passphrase: &str| {
        failure(
            &watch,
            json!({"op": "watch_connect_start", "link": link, "name": "Test Watch",
                   "answer_key": answer_key, "passphrase": passphrase}),
        )
    };
    let (code, message) = start(plain, ANSWER_PUBLIC, WATCH_PASS);
    assert_eq!(code, "link_invalid");
    assert_eq!(
        message,
        "This code can't connect a watch. Make a new code on the Mac."
    );
    let (code, _) = start(
        &format!("{plain}&handoff=2.broken"),
        ANSWER_PUBLIC,
        WATCH_PASS,
    );
    assert_eq!(code, "link_invalid");
    assert_eq!(start(plain, ANSWER_PUBLIC, "short").0, "invalid_input");
    assert_eq!(start(plain, "AAAA", WATCH_PASS).0, "invalid_input");
    assert_eq!(
        call(&watch, json!({"op": "watch_status"}))["state"],
        "unpaired"
    );
}

/// The asking Mac: a vault with the question key and its own row (device 1 of the
/// team), and the fake relay.
struct Mac {
    _dir: tempfile::TempDir,
    vault: Vault,
    key: DeviceKey,
    relay: QuestionsRelay,
}

fn mac() -> Mac {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("synthetic-mac.apassy");
    let mut vault = Vault::create(&file, PASS).unwrap();
    vault.unlock(PASS).unwrap();
    vault.lock().unwrap();
    drop(vault);
    {
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.pragma_update(None, "key", PASS).unwrap();
        conn.execute(
            "INSERT INTO vault_secret (name, value, updated_at, updated_by) VALUES ('question-key-v1', ?1, 1, 'mac')",
            [QUESTION_KEY.as_slice()],
        )
        .unwrap();
    }
    let key = DeviceKey::generate().unwrap();
    let mut vault = Vault::open(&file).unwrap();
    vault.unlock(PASS).unwrap();
    vault
        .register_trusted_device(
            ASKER,
            "MacBook Pro",
            TrustedDeviceKind::Mac,
            key.public_key(),
            None,
        )
        .unwrap();
    vault.set_trusted_device_relay_id(ASKER, TEAM, 1).unwrap();
    let relay = QuestionsRelay::start(TEAM, key.public_key());
    Mac {
        _dir: dir,
        vault,
        key,
        relay,
    }
}

/// The Mac posts a signed access request as `qid`.
fn publish(mac: &Mac, qid: &str) {
    let mut card: access::Card = serde_json::from_str(include_str!(
        "../../../tests/fixtures/access-request-v1/card-body.json"
    ))
    .unwrap();
    card.vault_id = mac.vault.sync_identity().unwrap().vault_id;
    card.qid = qid.to_owned();
    card.asker.relay_device_id = 1;
    card.created_at = now();
    card.expires_at = card.created_at + 300;
    let body = serde_json::to_vec(&card).unwrap();
    let signature = mac
        .key
        .sign(&access::body_signature_message("card", &body).unwrap())
        .unwrap();
    let wrapper = access::SignedBody::new("card", &body, &signature).unwrap();
    post(
        &mac.relay,
        &QUESTION_KEY,
        qid,
        &serde_json::to_string(&wrapper).unwrap(),
        card.expires_at,
    );
}

#[test]
fn a_watch_connects_answers_an_access_request_and_forgets_its_replica() {
    let mut mac = mac();
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("Watch");
    let watch = watch_core(&data, Arc::default());
    let (raw, _) = mac.relay.link();
    let channel = PairingChannel::generate(&raw).unwrap();
    let link = channel.link(&raw);
    let waiting = call(
        &watch,
        json!({"op": "watch_connect_start", "link": link.as_str(), "name": "Test Watch",
               "answer_key": ANSWER_PUBLIC, "passphrase": WATCH_PASS}),
    );
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(waiting["words"].as_array().unwrap().len(), 6);
    assert!(waiting["expires_at"].as_u64().unwrap() > now());
    assert_eq!(
        call(&watch, json!({"op": "watch_connect_poll"}))["state"],
        "waiting"
    );
    assert_eq!(
        call(&watch, json!({"op": "watch_status"}))["state"],
        "connecting"
    );
    // The owner confirms on the Mac: it writes a `watch` row from the link name.
    let ids = mac.relay.confirm_links();
    let (device_id, name, public) = mac.relay.confirmed().pop().unwrap();
    assert_eq!(ids, vec![device_id]);
    assert!(name.starts_with("Test Watch ~W"), "{name}");
    assert!(name.len() <= 64);
    assert_eq!(
        channel.mac_safety(TEAM, &public, &name).unwrap(),
        waiting["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|word| word.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(" ")
    );
    // A confirmation alone imports nothing.
    assert_eq!(
        call(&watch, json!({"op": "watch_connect_poll"}))["state"],
        "waiting"
    );
    let row = register_linked_device(&mut mac.vault, TEAM, device_id, &name, &public)
        .unwrap()
        .unwrap();
    assert_eq!(row.kind, TrustedDeviceKind::Watch);
    let sealed = channel.seal(&mac.vault, TEAM, &public).unwrap();
    mac.relay.post_question(
        channel.qid(),
        &sealed.key_id,
        &sealed.nonce,
        &sealed.ciphertext,
        now() + 600,
    );
    let vault_id = mac.vault.sync_identity().unwrap().vault_id;
    let attached = call(&watch, json!({"op": "watch_connect_poll"}));
    assert_eq!(
        attached,
        json!({"state": "attached", "vault": {"id": vault_id, "name": "MacBook Pro"}})
    );
    let info = call(&watch, json!({"op": "info"}));
    assert_eq!(info["unlocked"], true);
    assert_eq!(info["selected"], vault_id.as_str());
    assert_eq!(info["vaults"].as_array().unwrap().len(), 1);
    assert_eq!(info["vaults"][0]["relay_url"], Value::Null);
    let status = call(
        &watch,
        json!({"op": "watch_status", "answer_key": ANSWER_PUBLIC}),
    );
    assert_eq!(
        status,
        json!({"state": "ready", "vault": {"id": vault_id, "name": "MacBook Pro"},
               "macs": ["MacBook Pro"], "own": {"found": true, "answer_key_matches": true}})
    );
    let other = encode_b64u(DeviceKey::generate().unwrap().public_key());
    assert_eq!(
        call(&watch, json!({"op": "watch_status", "answer_key": other}))["own"],
        json!({"found": true, "answer_key_matches": false})
    );
    assert_eq!(
        fails(
            &watch,
            json!({"op": "watch_connect_start", "link": link.as_str(),
                   "answer_key": ANSWER_PUBLIC, "passphrase": WATCH_PASS})
        ),
        "already_connected"
    );
    // The watch's own push (push-gateway-v1 section 11): a handle of the kind `watch` for
    // the watch app's topic, and never a token to the relay.
    mac.relay.set_gateway_mode(true);
    let gateway = FakeGateway::start();
    let token = "c3".repeat(32);
    let set = call(
        &watch,
        json!({"op": "push_token_set", "token": token, "environment": "production",
               "gateway": gateway.url}),
    );
    assert_eq!(set["device_id"], device_id);
    assert_eq!(
        gateway.requests(),
        vec![
            json!({"v": 1, "kind": "watch", "token": token, "environment": "production",
                    "bundle_id": "com.wydrox.apassy.companion.watchkitapp"})
        ]
    );
    let (pushed_device, body) = mac.relay.push_handle().unwrap();
    assert_eq!(pushed_device, device_id);
    assert_eq!(body["handle"], FakeGateway::handle(1));
    assert!(mac.relay.push_token().is_none());
    let kept = std::fs::read_to_string(data.join("questions-push.json")).unwrap();
    assert!(kept.contains(&FakeGateway::handle(1)) && !kept.contains(&token));
    // The summary key of its one team, for its Notification Service Extension.
    let keys = call(&watch, json!({"op": "push_summary_keys"}));
    assert_eq!(keys["keys"].as_array().unwrap().len(), 1);
    assert_eq!(keys["keys"][0]["team_id"], TEAM);
    // Notifications on this watch off: the handle leaves the node.
    call(&watch, json!({"op": "push_token_clear"}));
    assert!(mac.relay.push_handle().is_none());
    mac.relay.set_gateway_mode(false);
    // A run question never shows on the watch; an access request does.
    post(&mac.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    let allow_qid = encode_b64u(&[0x11; 16]);
    let deny_qid = encode_b64u(&[0x22; 16]);
    publish(&mac, &allow_qid);
    publish(&mac, &deny_qid);
    let listed = call(&watch, json!({"op": "access_requests_list"}));
    let requests = listed["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 2, "{listed}");
    for request in requests {
        assert_eq!(request["vault_id"], vault_id.as_str());
        assert_eq!(request["answer_key"], ANSWER_PUBLIC);
        assert_eq!(request["state"], "open");
    }
    let digest = |qid: &str| {
        requests
            .iter()
            .find(|request| request["card"]["qid"] == qid)
            .unwrap()["digest"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // Allow once: signed by the answer key (Swift, with the wrist check).
    let allow_digest = digest(allow_qid.as_str());
    let prepared = call(
        &watch,
        json!({"op": "access_request_prepare", "vault_id": vault_id, "qid": allow_qid,
               "digest": allow_digest, "kind": "allow_once"}),
    );
    assert_eq!(prepared["needs_face_id"], true);
    let answer_key =
        DeviceKey::from_raw(&unhex(ANSWER_PRIVATE), &decode_b64u(ANSWER_PUBLIC).unwrap()).unwrap();
    let bytes = decode_b64u(prepared["bytes"].as_str().unwrap()).unwrap();
    let sent = call(
        &watch,
        json!({"op": "access_request_answer", "vault_id": vault_id, "qid": allow_qid,
               "digest": allow_digest, "kind": "allow_once", "time": prepared["time"],
               "signature": encode_b64u(&answer_key.sign(&bytes).unwrap())}),
    );
    assert_eq!(sent["sent"], true);
    // Deny: signed by the relay key of the watch in the core.
    let deny_digest = digest(deny_qid.as_str());
    let prepared = call(
        &watch,
        json!({"op": "access_request_prepare", "vault_id": vault_id, "qid": deny_qid,
               "digest": deny_digest, "kind": "deny"}),
    );
    assert_eq!(prepared["needs_face_id"], false);
    call(
        &watch,
        json!({"op": "access_request_answer", "vault_id": vault_id, "qid": deny_qid,
               "digest": deny_digest, "kind": "deny", "time": prepared["time"]}),
    );
    let answers = mac.relay.answers();
    assert_eq!(answers.len(), 2);
    let device = device_id.to_string();
    for (stored, qid, kind) in [
        (&answers[0], allow_qid.as_str(), "allow_once"),
        (&answers[1], deny_qid.as_str(), "deny"),
    ] {
        assert_eq!(stored.device_id, device_id);
        let aad = aad(&[
            "apassy-question-v1",
            "answer",
            TEAM,
            qid,
            KEY_ID,
            device.as_str(),
        ]);
        let plaintext = open(&QUESTION_KEY, &aad, &stored.nonce, &stored.ciphertext).unwrap();
        let answer = access::Answer::parse(&plaintext).unwrap();
        assert_eq!(answer.kind.text(), kind);
        assert_eq!(answer.by, row.uuid);
    }
    // The replica opens again with the passphrase of the app.
    call(&watch, json!({"op": "lock"}));
    assert_eq!(
        call(&watch, json!({"op": "watch_status"}))["state"],
        "locked"
    );
    call(&watch, json!({"op": "unlock", "passphrase": WATCH_PASS}));
    assert_eq!(
        call(&watch, json!({"op": "watch_status"}))["state"],
        "ready"
    );
    // Forget: the device leaves the team, and the replica and its guards go.
    let file = data.join("vaults").join(format!("{vault_id}.apassy"));
    let guards = data
        .join("request-history")
        .join(format!("access-guards-v1-{vault_id}.json"));
    assert!(file.exists() && guards.exists());
    assert_eq!(
        call(&watch, json!({"op": "watch_forget"}))["state"],
        "unpaired"
    );
    assert!(
        mac.relay
            .log()
            .contains(&format!("DELETE /v1/devices/{device_id}")),
        "{:?}",
        mac.relay.log()
    );
    assert!(!file.exists() && !guards.exists());
    assert_eq!(call(&watch, json!({"op": "info"}))["vaults"], json!([]));
    assert_eq!(
        call(&watch, json!({"op": "watch_status"}))["state"],
        "unpaired"
    );
}
