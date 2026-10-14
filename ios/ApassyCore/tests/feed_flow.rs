//! The agent feeds of the Macs on the iPhone (contract relay-feed-v1, ios-core-v1 section
//! 5.12), through the JSON calls as the app makes them, against the in-process fake of
//! the relay (`common/questions_relay.rs`, with its feed routes). The publishing Mac is
//! played by the test: it seals feeds with the question key of the vault, opens the
//! iPhone's actions, and settles them. The key, the team, the device UUIDs, the feed, the
//! action string, and the answer key are the synthetic values of the contract's test
//! vectors (section 17).

#[path = "common/questions_relay.rs"]
mod questions_relay;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use apassy::contracts::CredentialKind;
use apassy::sync::{DeviceKey, decode_b64u, encode_b64u, verify_signature};
use apassy::vault::{Field, ItemDraft, SecretValue, TrustedDeviceKind, Vault};
use apassy_core::Core;
use questions_relay::{QuestionsRelay, now};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-feed-pass";
const TEAM: &str = "t_7k2m5q4x3c";
const QUESTION_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const KEY_ID: &str = "630dcd2966c43366";
/// The publisher (Mac) and the sender (iPhone) of the vectors.
const MAC: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
const PHONE: &str = "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const SHOP_ITEM: &str = "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c";
const API_ITEM: &str = "8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e";
const ANSWER_PRIVATE: &str = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
const ACTION_ID: &str = "sLGys7S1tre4ubq7vL2-vw";
const SIGNATURE: &str = "MEUCIQCOrTEXw3oKicPKbs27qpgbvM95jFR7lYdT06KKIVWa-wIgT3NaBhBSf5jHK8K-zhPQ0hBmo181UGMB1WMeAjoHBRk";
const FEED: &str = r#"{"v":1,"mac":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"seq":1790000040,"generated_at":1790000040,"truncated":false,"week":{"by_you":3,"automatic":128},"agents":[{"id":"4","name":"Claude Code","host":"claude","where":"mac","revoked":false,"token_expires_at":1797776000,"last_use_at":1790000010,"uses_this_week":12,"projects":["synthetic-shop"],"note":"Deploys only from the main branch.","restricted":false,"actions":[{"action":"deploy","allowed":2,"not_allowed":1,"projects":["synthetic-shop"]}],"exceptions":[{"item":"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c","item_title":"Shop database","kind":"never","created_at":1789990000}],"recent":[{"at":1790000010,"item":"8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e","item_title":"API token","action":"deploy","project":"synthetic-shop","command":"npm run deploy -- --token [apassy:secret]","outcome":"allowed","decided_by":"owner","answered_on":"Test iPhone"}]}]}"#;
const FEED_NONCE: &str = "MDEyMzQ1Njc4OTo7";
const FEED_CIPHERTEXT: &str = "2dd63c68fed0fbc70573da2e4fe30a66aeb5b976a8a32b0bac67d36775ac2786b3c33d810f960fecdfb645235a84123fc5efd943182bc2ec6862253cd5f918b6ce2b3f1b5baec9990a838d36008edbf9ce1294712bbe2dcf1a7db5c7268e61beb68f20a72bd99de63f88d774bf4121b9a766adade408521da5b3f36aa0b6b57f5e0fdd956a7fc7471bbb5ff39441703e59e76517dcb23d098944e744d4a4797fdf44a9143e5ab65e2474eada739bb1f83ba85ea8dfe4ed55fe9ef01f8007eb352b281f2fdb1db7f9164a2ac9856b9b943786ee6ffef7f962e6fa81deb8a2d999509e18d91b746984c550dd8fccca1fcb1ff803ca97e48d04a78b79695b98bcddc170f808894ef24bd3a890358075f9031cee5ddec1bd9490f4d3162b902c38fbfb69f3ff41fecafa48d111d253daaf23f447d5f9998406241c60a1110213e932690c93933f6e4c91cf52a37380b2a48749999519caed7b735c7395e8e58d8a9e664b16308ec8c502a185a13289e31a5ba84d5ced3a4de5bbcfca9c3bc3b22eb0077f5e1d21af4bfac786ca23eeecaeecdc8e64d59c7997832031134b6d6239dd0ecaf50de6611493b21406f6c780c167cf92edbfe4ee5bf5b87b8d795535ee3249b614a699776b884198a76e346fa239a0ea2e05f5a9b3bf90cb5f99c966486d90836d591637195412f2d114eabe41e6a8d8291012700aac012c1e139e109fc35a7bbd491fb67a9f933dfda4d978f867c6263c4c2d39efeee34636166fb40b147823542fec687577d784b540c818dd16bd10b7b1fb553c70ed0771ad73ffc0079fd8e8a85d2ee5e1bafb2ab2c8aa43dca3380a58325fa7845fe922cb3e7720b691ca4bc360a72785c8c2d0dacee22d7571a5c30702f251bf4115b38c9dbdfdba02646beed6ba2422efe9b9699139b1fb1f6b6533a886dcca81c5230497105c0bf5f1e3a6d09a0598cbef92449133560456bb0b6452e3bd385f849f524a89ea9cd406570f140b8b79797d8e77b9cf1bc9203221717017326b8af9c8b9ba1610b5343065ff48341baa61bc19816baabab6cd5fbf29fc9d7e86de309a9738b1d30ca6401f19cfd66ea1fcc28bee2954d264c1e61ef8c4677ab0ade0bd5043f4c50fb7d4ff7e5b407fbb82fad706ab491b1fd76e9e8e6a20817218377e2f481959ce0ea36c147ee182bc197e97b243eba96d8e1099dd67a695addb320b15f539ad1f938a1d2b78d3d2b54e581453f73b73ea6b0345f7df9305d8f181c9c492e376bd3560d39b303b82c88ddb5c5bbe525d130633465b541678b0d6de4e7c01d3b980b2c6b4fd344af9";
const ACTION_STRING: &str = "apassy-feed-action-v1\n6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b\n0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d\nt_7k2m5q4x3c\nsLGys7S1tre4ubq7vL2-vw\nremove_exception:4:3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c:never:1789990000\n1790000040\n1790000060";

/// The second vault of the two-vault test: its own team, key, and Mac.
const TEAM_B: &str = "t_b4w5v6u7tz";
const QUESTION_KEY_B: [u8; 32] = [7; 32];
const MAC_B: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn key_id(key: &[u8]) -> String {
    sha256(key)[..16].to_owned()
}

fn answer_key() -> DeviceKey {
    DeviceKey::from_raw(&unhex(ANSWER_PRIVATE), &decode_b64u(ANSWER_PUBLIC).unwrap()).unwrap()
}

fn core(dir: &Path) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Test iPhone", "role": "app"});
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
    assert!(
        !answer["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );
    answer["error"]["code"].as_str().expect("code").to_owned()
}

fn aad(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> (String, String) {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).unwrap();
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());
    let mut sealed = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut sealed,
    )
    .unwrap();
    (encode_b64u(&nonce), encode_b64u(&sealed))
}

fn open(key: &[u8], aad: &[u8], nonce: &str, ciphertext: &str) -> Option<Vec<u8>> {
    let nonce: [u8; 12] = decode_b64u(nonce)?.try_into().ok()?;
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).unwrap());
    let mut buffer = decode_b64u(ciphertext)?;
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buffer,
        )
        .ok()?;
    Some(plain.to_vec())
}

/// The vector feed with `seq` and `generated_at`, changed by `edit`.
fn feed(seq: u64, generated_at: u64, edit: impl FnOnce(&mut Value)) -> String {
    let mut value: Value = serde_json::from_str(FEED).unwrap();
    value["seq"] = json!(seq);
    value["generated_at"] = json!(generated_at);
    edit(&mut value);
    value.to_string()
}

/// The Mac of relay device `device_id` publishes `plaintext` sealed with `key` in `team`.
fn publish(relay: &QuestionsRelay, team: &str, key: &[u8], device_id: u64, plaintext: &str) {
    let seq = serde_json::from_str::<Value>(plaintext).unwrap()["seq"]
        .as_u64()
        .unwrap();
    let key_id = key_id(key);
    let aad = aad(&[
        "apassy-feed-v1",
        "feed",
        team,
        &device_id.to_string(),
        &seq.to_string(),
        &key_id,
    ]);
    let (nonce, ciphertext) = seal(key, &aad, plaintext.as_bytes());
    relay.put_feed(device_id, seq, &key_id, &nonce, &ciphertext);
}

/// One vault on the iPhone with its questions team on its own fake relay. Relay device 1
/// is a Mac that is not in the vault, device 2 is the publishing Mac (a live trusted
/// `mac` row with that device number), and device 3 is this iPhone, whose row (written
/// as by the confirming Mac) has the answer key of the vectors.
struct VaultSetup {
    vault_id: String,
    file: PathBuf,
    relay: QuestionsRelay,
    key: [u8; 32],
}

/// A new vault `name` on the iPhone, selected and unlocked, attached to a new relay team.
fn add_vault(
    phone: &Core,
    data: &Path,
    name: &str,
    team: &'static str,
    key: [u8; 32],
    mac: (&str, &str),
) -> VaultSetup {
    let vault = call(
        phone,
        json!({"op": "create_local_vault", "name": name, "passphrase": PASS}),
    );
    let vault_id = vault["vault"]["id"].as_str().unwrap().to_owned();
    call(phone, json!({"op": "lock"}));
    let file = data.join("vaults").join(format!("{vault_id}.apassy"));
    // The question key arrives with the sync of a Mac.
    {
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.pragma_update(None, "key", PASS).unwrap();
        conn.execute(
            "INSERT INTO vault_secret (name, value, updated_at, updated_by) VALUES ('question-key-v1', ?1, 1, 'mac')",
            [key.as_slice()],
        )
        .unwrap();
    }
    let mac_key = DeviceKey::generate().unwrap();
    let item = {
        let mut vault = Vault::open(&file).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .register_trusted_device(
                mac.0,
                mac.1,
                TrustedDeviceKind::Mac,
                mac_key.public_key(),
                None,
            )
            .unwrap();
        vault.set_trusted_device_relay_id(mac.0, team, 2).unwrap();
        vault
            .add(ItemDraft {
                title: "Synthetic API token".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("SYNTH-token".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id
    };
    // The item of the recent use of the vector is in this vault (the UUID that sync gave
    // it is the one of the Mac's copy).
    {
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.pragma_update(None, "key", PASS).unwrap();
        conn.execute(
            "UPDATE item SET uuid = ?1 WHERE id = ?2",
            rusqlite::params![API_ITEM.replace('-', ""), item as i64],
        )
        .unwrap();
    }
    call(phone, json!({"op": "unlock", "passphrase": PASS}));
    let relay = QuestionsRelay::start(team, DeviceKey::generate().unwrap().public_key());
    assert_eq!(relay.add_device(mac_key.public_key()), 2);
    let (link, _) = relay.link();
    let waiting = call(
        phone,
        json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}),
    );
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(relay.confirm_links(), vec![3]);
    let attached = call(phone, json!({"op": "join_attach_poll"}));
    assert_eq!(attached["state"], "attached");
    // The confirming Mac writes the row of this iPhone; it reaches the iPhone with sync.
    let (device_id, _, public_key) = relay.confirmed().pop().unwrap();
    assert_eq!(device_id, 3);
    let setup = VaultSetup {
        vault_id,
        file,
        relay,
        key,
    };
    as_the_mac(phone, &setup, |vault| {
        vault
            .register_trusted_device(
                PHONE,
                "Test iPhone",
                TrustedDeviceKind::Iphone,
                &public_key,
                Some(&decode_b64u(ANSWER_PUBLIC).unwrap()),
            )
            .unwrap();
        vault.set_trusted_device_relay_id(PHONE, team, 3).unwrap();
    });
    setup
}

/// Change the iPhone's vault as the sync of a Mac does: the core locks, the change goes
/// into the file, and the core unlocks again.
fn as_the_mac<T>(phone: &Core, setup: &VaultSetup, change: impl FnOnce(&mut Vault) -> T) -> T {
    call(phone, json!({"op": "lock"}));
    let out = {
        let mut vault = Vault::open(&setup.file).unwrap();
        vault.unlock(PASS).unwrap();
        change(&mut vault)
    };
    call(phone, json!({"op": "unlock", "passphrase": PASS}));
    out
}

struct Setup {
    _root: TempDir,
    data: PathBuf,
    phone: Core,
    a: VaultSetup,
}

fn setup() -> Setup {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("Apassy");
    std::fs::create_dir_all(&data).unwrap();
    let phone = core(&data);
    let a = add_vault(
        &phone,
        &data,
        "Personal",
        TEAM,
        QUESTION_KEY,
        (MAC, "MacBook Pro"),
    );
    Setup {
        _root: root,
        data,
        phone,
        a,
    }
}

fn list(phone: &Core) -> Value {
    call(phone, json!({"op": "feed_list"}))
}

/// The Macs of the first vault in the list.
fn macs(phone: &Core) -> Vec<Value> {
    list(phone)["vaults"][0]["macs"].as_array().unwrap().clone()
}

fn string_request(setup: &Setup, kind: &str, created_at: u64, item: &str) -> Value {
    json!({"op": "feed_action_string", "vault_id": setup.a.vault_id, "mac_device": MAC,
           "agent": "4", "item": item, "kind": kind, "created_at": created_at})
}

/// The core builds the action string, "Face ID" signs it with the answer key of the
/// vectors when it needs to, and the core sends it.
fn act(setup: &Setup, kind: &str, created_at: u64, item: &str) -> (Value, Value) {
    let prepared = call(&setup.phone, string_request(setup, kind, created_at, item));
    let mut request = string_request(setup, kind, created_at, item);
    request["op"] = json!("feed_action");
    request["action_id"] = prepared["action_id"].clone();
    request["time"] = prepared["time"].clone();
    if prepared["needs_face_id"] == true {
        let text = prepared["action_string"].as_str().unwrap();
        request["signature"] = json!(encode_b64u(&answer_key().sign(text.as_bytes()).unwrap()));
    }
    let sent = call(&setup.phone, request);
    (prepared, sent)
}

/// A fresh feed of the publishing Mac with an exception of each kind.
fn fresh_feed(setup: &Setup) -> u64 {
    let seq = now();
    let text = feed(seq, seq, |value| {
        value["agents"][0]["exceptions"] = json!([
            {"item": SHOP_ITEM, "item_title": "Shop database", "kind": "never", "created_at": 1_789_990_000u64},
            {"item": API_ITEM, "item_title": "API token", "kind": "only", "created_at": 1_789_990_100u64},
        ]);
    });
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &text);
    seq
}

/// The target settles `action_id` with `outcome`, sealed with `key`; `clear` is the
/// outcome that the relay stores in clear.
fn settle(setup: &Setup, action_id: &str, outcome: &str, clear: &str, reason: &str) {
    let plaintext = json!({"v": 1, "action_id": action_id, "outcome": outcome, "reason": reason,
                           "feed_seq": null, "at": now()});
    let aad = aad(&["apassy-feed-v1", "settle", TEAM, action_id, KEY_ID, outcome]);
    let (nonce, ciphertext) = seal(&setup.a.key, &aad, plaintext.to_string().as_bytes());
    setup
        .a
        .relay
        .settle_action(action_id, clear, KEY_ID, &nonce, &ciphertext);
}

fn wait_action(setup: &Setup, action_id: &str, timeout: u64) -> Value {
    call(
        &setup.phone,
        json!({"op": "feed_action_wait", "action_id": action_id, "timeout": timeout}),
    )
}

#[test]
fn the_feed_of_the_vectors_is_read_and_shown() {
    let setup = setup();
    // No feed yet: the vault is listed without a Mac.
    let empty = list(&setup.phone);
    assert_eq!(empty["vaults"][0]["vault_id"], setup.a.vault_id.as_str());
    assert_eq!(empty["vaults"][0]["macs"], json!([]));
    assert_eq!(empty["vaults"][0]["registered"], true);
    assert_eq!(empty["vaults"][0]["answer_key"], true);

    setup.a.relay.put_feed(
        2,
        1_790_000_040,
        KEY_ID,
        FEED_NONCE,
        &encode_b64u(&unhex(FEED_CIPHERTEXT)),
    );
    let all = list(&setup.phone);
    let vault = &all["vaults"][0];
    assert_eq!(vault["vault_name"], "Personal");
    assert_eq!(vault["team_id"], TEAM);
    assert_eq!(vault["error"], Value::Null);
    let mac = &vault["macs"][0];
    assert_eq!(mac["device"], MAC);
    assert_eq!(mac["relay_device_id"], 2);
    assert_eq!(mac["name"], "MacBook Pro");
    assert_eq!(mac["seq"], 1_790_000_040u64);
    assert_eq!(mac["generated_at"], 1_790_000_040u64);
    assert_eq!(mac["truncated"], false);
    assert_eq!(mac["problem"], Value::Null);
    assert_eq!(mac["week"], json!({"by_you": 3, "automatic": 128}));
    let agent = &mac["agents"][0];
    assert_eq!(agent["id"], "4");
    assert_eq!(agent["name"], "Claude Code");
    assert_eq!(agent["host"], "claude");
    assert_eq!(agent["where"], "mac");
    assert_eq!(agent["last_use_at"], 1_790_000_010u64);
    assert_eq!(agent["note"], "Deploys only from the main branch.");
    assert_eq!(agent["actions"][0]["action"], "deploy");
    assert_eq!(agent["actions"][0]["not_allowed"], 1);
    // The exception's item is not in this vault; the recent use's item is.
    let exception = &agent["exceptions"][0];
    assert_eq!(exception["item"], SHOP_ITEM);
    assert_eq!(exception["item_title"], "Shop database");
    assert_eq!(exception["title"], Value::Null);
    assert_eq!(exception["here"], false);
    assert_eq!(exception["kind"], "never");
    assert_eq!(exception["created_at"], 1_789_990_000u64);
    let recent = &agent["recent"][0];
    assert_eq!(recent["item"], API_ITEM);
    assert_eq!(recent["item_title"], "API token");
    assert_eq!(recent["title"], "Synthetic API token");
    assert_eq!(recent["here"], true);
    assert_eq!(
        recent["command"],
        "npm run deploy -- --token [apassy:secret]"
    );
    assert_eq!(recent["answered_on"], "Test iPhone");

    // The mark on disk holds the team, the device, and the seq: no secret.
    let marks: Value =
        serde_json::from_slice(&std::fs::read(setup.data.join("feed-seq.json")).unwrap()).unwrap();
    assert_eq!(
        marks,
        json!({"version": 1, "teams": {TEAM: {"2": 1_790_000_040u64}}})
    );
    // The fake relay log shows the reads.
    assert!(
        setup
            .a
            .relay
            .log()
            .iter()
            .any(|line| line == "GET /v1/feed")
    );
}

#[test]
fn a_lower_or_equal_seq_is_ignored_also_after_a_restart() {
    let setup = setup();
    let seq = now();
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        2,
        &feed(seq, seq, |_| {}),
    );
    assert_eq!(macs(&setup.phone)[0]["seq"], seq);
    // A lower seq, and the same seq with another content: the screen keeps the feed.
    let older = feed(seq - 1, seq, |value| {
        value["agents"][0]["note"] = json!("An older feed.")
    });
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &older);
    let mac = &macs(&setup.phone)[0];
    assert_eq!(mac["seq"], seq);
    assert_eq!(
        mac["agents"][0]["note"],
        "Deploys only from the main branch."
    );
    let same = feed(seq, seq, |value| {
        value["agents"][0]["note"] = json!("Served again.")
    });
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &same);
    assert_eq!(
        macs(&setup.phone)[0]["agents"][0]["note"],
        "Deploys only from the main branch."
    );
    // A higher one shows.
    let newer = feed(seq + 1, seq, |value| {
        value["agents"][0]["note"] = json!("A newer feed.")
    });
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &newer);
    let mac = &macs(&setup.phone)[0];
    assert_eq!(mac["seq"], seq + 1);
    assert_eq!(mac["agents"][0]["note"], "A newer feed.");

    // A new process with the same data: the mark survives. The feed of the mark shows
    // again; an older one served after it does not.
    call(&setup.phone, json!({"op": "lock"}));
    let again = core(&setup.data);
    call(
        &again,
        json!({"op": "select", "vault_id": setup.a.vault_id}),
    );
    call(&again, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(macs(&again)[0]["seq"], seq + 1);
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &older);
    let mac = &macs(&again)[0];
    assert_eq!(mac["seq"], seq + 1);
    assert_eq!(mac["agents"][0]["note"], "A newer feed.");
    call(&again, json!({"op": "lock"}));
    // After the restart and a new unlock, a relay that serves only the older feed shows
    // nothing of that Mac.
    let third = core(&setup.data);
    call(&third, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(macs(&third), Vec::<Value>::new());
}

#[test]
fn a_feed_of_a_device_that_is_not_a_trusted_mac_is_refused() {
    let setup = setup();
    let seq = now();
    // Relay device 1 is not in the vault: neither its own name nor the uuid of the
    // trusted Mac (whose device number is 2) counts.
    let stranger = feed(seq, seq, |value| {
        value["mac"]["device"] = json!("9f8e7d6c-5b4a-4f3e-8d2c-1b0a9f8e7d6c")
    });
    publish(&setup.a.relay, TEAM, &setup.a.key, 1, &stranger);
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        1,
        &feed(seq + 1, seq, |_| {}),
    );
    // This iPhone's own row is no Mac.
    let phone = feed(seq, seq, |value| value["mac"]["device"] = json!(PHONE));
    publish(&setup.a.relay, TEAM, &setup.a.key, 3, &phone);
    assert_eq!(macs(&setup.phone), Vec::<Value>::new());
    assert!(
        !setup.data.join("feed-seq.json").exists(),
        "no mark for a refused feed"
    );

    // The trusted Mac: a feed under another key, then one of another version, each with
    // the text of its step; then a good one.
    let other_key = [9u8; 32];
    publish(&setup.a.relay, TEAM, &other_key, 2, &feed(seq, seq, |_| {}));
    let mac = &macs(&setup.phone)[0];
    assert_eq!(mac["device"], MAC);
    assert_eq!(mac["seq"], Value::Null);
    assert_eq!(
        mac["problem"],
        "Sync this vault to see the agents of MacBook Pro."
    );
    let newer = feed(seq + 1, seq, |value| value["v"] = json!(2));
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &newer);
    assert_eq!(
        macs(&setup.phone)[0]["problem"],
        "Update Apassy to see the agents of MacBook Pro."
    );
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        2,
        &feed(seq + 2, seq, |_| {}),
    );
    let mac = &macs(&setup.phone)[0];
    assert_eq!(mac["seq"], seq + 2);
    assert_eq!(mac["problem"], Value::Null);
    // A bad feed after a good one keeps the good one on the screen, with the text.
    let unknown = feed(seq + 3, seq, |value| value["extra"] = json!(true));
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &unknown);
    let mac = &macs(&setup.phone)[0];
    assert_eq!(mac["seq"], seq + 2);
    assert_eq!(
        mac["problem"],
        "Update Apassy to see the agents of MacBook Pro."
    );
}

#[test]
fn a_device_that_is_not_present_or_was_removed_leaves_the_list() {
    let setup = setup();
    let seq = now();
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        2,
        &feed(seq, seq, |_| {}),
    );
    assert_eq!(macs(&setup.phone).len(), 1);
    // The Mac turns "Show agents on the iPhone" off: its feed leaves the relay.
    setup.a.relay.delete_feed(2);
    assert_eq!(macs(&setup.phone), Vec::<Value>::new());
    // It publishes again; then the owner removes the Mac from the vault on another Mac.
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        2,
        &feed(seq + 1, seq, |_| {}),
    );
    assert_eq!(macs(&setup.phone).len(), 1);
    as_the_mac(&setup.phone, &setup.a, |vault| {
        assert!(vault.remove_trusted_device(MAC).unwrap());
    });
    assert_eq!(macs(&setup.phone), Vec::<Value>::new());
    assert_eq!(
        fails(
            &setup.phone,
            string_request(&setup, "never", 1_789_990_000, SHOP_ITEM)
        ),
        "not_found"
    );
}

#[test]
fn a_feed_older_than_a_day_is_stale_and_takes_no_action() {
    let setup = setup();
    let seq = now();
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        2,
        &feed(seq, seq - 100, |_| {}),
    );
    assert_eq!(macs(&setup.phone)[0]["stale"], false);
    let old = seq - 24 * 60 * 60 - 1;
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        2,
        &feed(seq + 1, old, |_| {}),
    );
    let mac = &macs(&setup.phone)[0];
    assert_eq!(mac["stale"], true);
    assert_eq!(mac["generated_at"], old);
    // The string can be built, but the action is not sent.
    let prepared = call(
        &setup.phone,
        string_request(&setup, "never", 1_789_990_000, SHOP_ITEM),
    );
    let signature = encode_b64u(
        &answer_key()
            .sign(prepared["action_string"].as_str().unwrap().as_bytes())
            .unwrap(),
    );
    let mut request = string_request(&setup, "never", 1_789_990_000, SHOP_ITEM);
    request["op"] = json!("feed_action");
    request["action_id"] = prepared["action_id"].clone();
    request["time"] = prepared["time"].clone();
    request["signature"] = json!(signature);
    assert_eq!(fails(&setup.phone, request), "stale_feed");
    assert!(setup.a.relay.actions().is_empty());
}

#[test]
fn the_feeds_of_two_vaults_show_together() {
    let setup = setup();
    let b = add_vault(
        &setup.phone,
        &setup.data,
        "Work",
        TEAM_B,
        QUESTION_KEY_B,
        (MAC_B, "Mac Studio"),
    );
    // Back to the first vault; the second gets its context from its passphrase.
    call(
        &setup.phone,
        json!({"op": "select", "vault_id": setup.a.vault_id}),
    );
    call(&setup.phone, json!({"op": "unlock", "passphrase": PASS}));
    call(
        &setup.phone,
        json!({"op": "questions_unlock", "vault_id": b.vault_id, "passphrase": PASS}),
    );
    let seq = now();
    publish(
        &setup.a.relay,
        TEAM,
        &setup.a.key,
        2,
        &feed(seq, seq, |_| {}),
    );
    let feed_b = feed(seq, seq, |value| {
        value["mac"] = json!({"device": MAC_B, "name": "Mac Studio"});
        value["agents"][0]["name"] = json!("Codex");
        value["agents"][0]["host"] = json!("codex");
    });
    publish(&b.relay, TEAM_B, &b.key, 2, &feed_b);
    // The feed of B under A's key does not open in B.
    let all = list(&setup.phone);
    let vaults = all["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 2);
    let of = |id: &str| {
        vaults
            .iter()
            .find(|vault| vault["vault_id"] == id)
            .unwrap()
            .clone()
    };
    let a = of(&setup.a.vault_id);
    let work = of(&b.vault_id);
    assert_eq!(a["team_id"], TEAM);
    assert_eq!(a["macs"][0]["name"], "MacBook Pro");
    assert_eq!(a["macs"][0]["agents"][0]["name"], "Claude Code");
    assert_eq!(work["vault_name"], "Work");
    assert_eq!(work["team_id"], TEAM_B);
    assert_eq!(work["macs"][0]["device"], MAC_B);
    assert_eq!(work["macs"][0]["name"], "Mac Studio");
    assert_eq!(work["macs"][0]["agents"][0]["name"], "Codex");
    // The titles of the second vault come from its unlock.
    assert_eq!(
        work["macs"][0]["agents"][0]["recent"][0]["title"],
        "Synthetic API token"
    );

    // One wait for both: news of the second vault ends it.
    let started = Instant::now();
    std::thread::scope(|scope| {
        let waiting = scope.spawn(|| call(&setup.phone, json!({"op": "feed_wait", "timeout": 20})));
        std::thread::sleep(Duration::from_millis(300));
        publish(
            &b.relay,
            TEAM_B,
            &b.key,
            2,
            &feed(seq + 1, seq, |value| {
                value["mac"] = json!({"device": MAC_B, "name": "Mac Studio"});
            }),
        );
        assert_eq!(waiting.join().unwrap()["changed"], true);
    });
    assert!(started.elapsed() < Duration::from_secs(10));

    // An action names its vault: one of A's Mac asked in B is not found there.
    let in_b = json!({"op": "feed_action_string", "vault_id": b.vault_id, "mac_device": MAC,
                      "agent": "4", "item": SHOP_ITEM, "kind": "never", "created_at": 1_789_990_000u64});
    assert_eq!(fails(&setup.phone, in_b), "not_found");
}

#[test]
fn the_action_string_is_the_contract_vector() {
    let setup = setup();
    setup.a.relay.put_feed(
        2,
        1_790_000_040,
        KEY_ID,
        FEED_NONCE,
        &encode_b64u(&unhex(FEED_CIPHERTEXT)),
    );
    let mut request = string_request(&setup, "never", 1_789_990_000, SHOP_ITEM);
    request["action_id"] = json!(ACTION_ID);
    request["time"] = json!(1_790_000_060u64);
    let prepared = call(&setup.phone, request.clone());
    assert_eq!(prepared["action_string"], ACTION_STRING);
    let text = prepared["action_string"].as_str().unwrap();
    assert_eq!(text.len(), 222);
    assert_eq!(
        sha256(text.as_bytes()),
        "4555d68b3fbe31ad493893152aa08eb21342feb0dbf69e91247748a6ae81ad6d"
    );
    assert_eq!(prepared["action_id"], ACTION_ID);
    assert_eq!(prepared["time"], 1_790_000_060u64);
    assert_eq!(prepared["feed_seq"], 1_790_000_040u64);
    assert_eq!(prepared["needs_face_id"], true);
    assert_eq!(prepared["vault_id"], setup.a.vault_id.as_str());
    assert_eq!(prepared["team_id"], TEAM);
    assert_eq!(
        prepared["face_id_reason"],
        "remove an exception of agent \"Claude Code\""
    );
    // The signature of the vectors verifies over it with the answer key.
    assert!(verify_signature(
        &decode_b64u(ANSWER_PUBLIC).unwrap(),
        text.as_bytes(),
        &decode_b64u(SIGNATURE).unwrap()
    ));
    // A new action ID each time without one.
    let first = call(
        &setup.phone,
        string_request(&setup, "never", 1_789_990_000, SHOP_ITEM),
    );
    let second = call(
        &setup.phone,
        string_request(&setup, "never", 1_789_990_000, SHOP_ITEM),
    );
    assert_ne!(first["action_id"], second["action_id"]);
    assert_eq!(first["action_id"].as_str().unwrap().len(), 22);
    // The time of the vector is long past: the action is not sent.
    request["op"] = json!("feed_action");
    request["signature"] = json!(SIGNATURE);
    assert_eq!(fails(&setup.phone, request), "stale_action");
    // An exception that the feed does not show, and an unknown kind.
    assert_eq!(
        fails(
            &setup.phone,
            string_request(&setup, "never", 1_789_990_001, SHOP_ITEM)
        ),
        "not_found"
    );
    assert_eq!(
        fails(
            &setup.phone,
            string_request(&setup, "always_ask", 1_789_990_000, SHOP_ITEM)
        ),
        "not_found"
    );
    assert_eq!(
        fails(
            &setup.phone,
            string_request(&setup, "sometimes", 1_789_990_000, SHOP_ITEM)
        ),
        "invalid_input"
    );
}

#[test]
fn an_action_is_sealed_with_its_aad_and_reaches_the_relay() {
    let setup = setup();
    let seq = fresh_feed(&setup);
    macs(&setup.phone);

    // "Not for this agent": Face ID signs with the answer key.
    let (prepared, sent) = act(&setup, "never", 1_789_990_000, SHOP_ITEM);
    assert_eq!(sent["action_id"], prepared["action_id"]);
    assert_eq!(sent["seq"], 1);
    let action_id = prepared["action_id"].as_str().unwrap().to_owned();
    let stored = setup.a.relay.actions().pop().unwrap();
    assert_eq!(stored.action_id, action_id);
    assert_eq!(stored.from_device, 3);
    assert_eq!(stored.to_device, 2);
    assert_eq!(stored.key_id, KEY_ID);
    let right = aad(&[
        "apassy-feed-v1",
        "action",
        TEAM,
        &action_id,
        KEY_ID,
        "3",
        "2",
    ]);
    let plaintext = open(&setup.a.key, &right, &stored.nonce, &stored.ciphertext)
        .expect("the action opens with the AAD of the stamped sender and the target");
    let action: Value = serde_json::from_slice(&plaintext).unwrap();
    let signature = action["signature"].as_str().unwrap().to_owned();
    assert_eq!(
        action,
        json!({"v": 1, "action_id": action_id, "by": PHONE, "to": MAC,
               "kind": "remove_exception", "agent": "4", "item": SHOP_ITEM,
               "exception": {"kind": "never", "created_at": 1_789_990_000u64},
               "feed_seq": seq, "time": prepared["time"], "signature": signature})
    );
    // The fields are in the contract's order.
    let text = String::from_utf8(plaintext.clone()).unwrap();
    assert!(text.starts_with(&format!("{{\"v\":1,\"action_id\":\"{action_id}\",\"by\":")));
    assert!(verify_signature(
        &decode_b64u(ANSWER_PUBLIC).unwrap(),
        prepared["action_string"].as_str().unwrap().as_bytes(),
        &decode_b64u(&signature).unwrap()
    ));
    for wrong in [
        aad(&[
            "apassy-feed-v1",
            "action",
            TEAM,
            &action_id,
            KEY_ID,
            "3",
            "5",
        ]),
        aad(&[
            "apassy-feed-v1",
            "action",
            TEAM,
            &action_id,
            KEY_ID,
            "4",
            "2",
        ]),
    ] {
        assert!(open(&setup.a.key, &wrong, &stored.nonce, &stored.ciphertext).is_none());
    }

    // A retry after a network error: the same ID and signature in a new envelope; the
    // relay has it already.
    let mut retry = string_request(&setup, "never", 1_789_990_000, SHOP_ITEM);
    retry["op"] = json!("feed_action");
    retry["action_id"] = json!(action_id);
    retry["time"] = prepared["time"].clone();
    retry["signature"] = json!(signature);
    let again = call(&setup.phone, retry.clone());
    assert_eq!(again["seq"], Value::Null);
    assert_eq!(setup.a.relay.actions().len(), 1);
    // Without Face ID, or with a signature by another key, nothing is sent.
    let mut unsigned = retry.clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    assert_eq!(fails(&setup.phone, unsigned), "invalid_input");
    let mut other = retry.clone();
    other["signature"] = json!(encode_b64u(
        &DeviceKey::generate()
            .unwrap()
            .sign(prepared["action_string"].as_str().unwrap().as_bytes())
            .unwrap()
    ));
    assert_eq!(fails(&setup.phone, other), "not_registered");

    // "Only these items": the core signs with the relay key, no Face ID.
    let (prepared, _) = act(&setup, "only", 1_789_990_100, API_ITEM);
    assert_eq!(prepared["needs_face_id"], false);
    let stored = setup.a.relay.actions().pop().unwrap();
    let action_id = prepared["action_id"].as_str().unwrap();
    let right = aad(&[
        "apassy-feed-v1",
        "action",
        TEAM,
        action_id,
        KEY_ID,
        "3",
        "2",
    ]);
    let action: Value = serde_json::from_slice(
        &open(&setup.a.key, &right, &stored.nonce, &stored.ciphertext).unwrap(),
    )
    .unwrap();
    assert_eq!(action["exception"]["kind"], "only");
    let signature = decode_b64u(action["signature"].as_str().unwrap()).unwrap();
    let text = prepared["action_string"].as_str().unwrap().as_bytes();
    assert!(verify_signature(
        &setup.a.relay.device_key(3),
        text,
        &signature
    ));
    assert!(!verify_signature(
        &decode_b64u(ANSWER_PUBLIC).unwrap(),
        text,
        &signature
    ));
    // A signature from Swift is refused for this kind.
    let mut signed = string_request(&setup, "only", 1_789_990_100, API_ITEM);
    signed["op"] = json!("feed_action");
    signed["action_id"] = prepared["action_id"].clone();
    signed["time"] = prepared["time"].clone();
    signed["signature"] = json!(SIGNATURE);
    assert_eq!(fails(&setup.phone, signed), "invalid_input");
}

#[test]
fn the_outcomes_of_an_action() {
    let setup = setup();
    fresh_feed(&setup);
    macs(&setup.phone);
    let (prepared, _) = act(&setup, "never", 1_789_990_000, SHOP_ITEM);
    let action_id = prepared["action_id"].as_str().unwrap().to_owned();
    let pending = wait_action(&setup, &action_id, 0);
    assert_eq!(pending["outcome"], "pending");
    assert_eq!(pending["verified"], false);

    // A long poll ends with the settle: applied, and the row leaves the list at once.
    std::thread::scope(|scope| {
        let waiting = scope.spawn(|| wait_action(&setup, &action_id, 20));
        std::thread::sleep(Duration::from_millis(300));
        settle(&setup, &action_id, "applied", "applied", "");
        let applied = waiting.join().unwrap();
        assert_eq!(applied["outcome"], "applied");
        assert_eq!(applied["verified"], true);
        assert_eq!(applied["reason"], Value::Null);
    });
    let exceptions = macs(&setup.phone)[0]["agents"][0]["exceptions"].clone();
    assert_eq!(exceptions.as_array().unwrap().len(), 1);
    assert_eq!(exceptions[0]["kind"], "only");
    // The next feed of the Mac says what is true.
    fresh_feed_with_seq(&setup, now() + 1);
    let exceptions = macs(&setup.phone)[0]["agents"][0]["exceptions"].clone();
    assert_eq!(exceptions.as_array().unwrap().len(), 2);

    // Refused with a reason, and stale.
    let (prepared, _) = act(&setup, "only", 1_789_990_100, API_ITEM);
    let refused_id = prepared["action_id"].as_str().unwrap().to_owned();
    settle(&setup, &refused_id, "refused", "refused", "too old");
    let refused = wait_action(&setup, &refused_id, 0);
    assert_eq!(refused["outcome"], "refused");
    assert_eq!(refused["verified"], true);
    assert_eq!(refused["reason"], "too old");
    let (prepared, _) = act(&setup, "never", 1_789_990_000, SHOP_ITEM);
    let stale_id = prepared["action_id"].as_str().unwrap().to_owned();
    settle(&setup, &stale_id, "stale", "stale", "The list changed.");
    assert_eq!(wait_action(&setup, &stale_id, 0)["outcome"], "stale");

    // A relay that flips the clear outcome: the settle does not open, the outcome is not
    // verified.
    let (prepared, _) = act(&setup, "never", 1_789_990_000, SHOP_ITEM);
    let flipped_id = prepared["action_id"].as_str().unwrap().to_owned();
    settle(&setup, &flipped_id, "refused", "applied", "");
    let flipped = wait_action(&setup, &flipped_id, 0);
    assert_eq!(flipped["outcome"], "applied");
    assert_eq!(flipped["verified"], false);
    assert_eq!(
        macs(&setup.phone)[0]["agents"][0]["exceptions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // No settle in time: expired.
    let (prepared, _) = act(&setup, "only", 1_789_990_100, API_ITEM);
    let expired_id = prepared["action_id"].as_str().unwrap().to_owned();
    setup.a.relay.expire_action(&expired_id);
    assert_eq!(wait_action(&setup, &expired_id, 0)["outcome"], "expired");

    // An action that this process did not post.
    assert_eq!(
        fails(
            &setup.phone,
            json!({"op": "feed_action_wait", "action_id": "AAAAAAAAAAAAAAAAAAAAAA"})
        ),
        "not_found"
    );
    // The name of relay-feed-v1 section 2 answers the same.
    assert_eq!(
        call(
            &setup.phone,
            json!({"op": "feed_action_status", "action_id": stale_id})
        )["outcome"],
        "stale"
    );
}

fn fresh_feed_with_seq(setup: &Setup, seq: u64) {
    let text = feed(seq, now(), |value| {
        value["agents"][0]["exceptions"] = json!([
            {"item": SHOP_ITEM, "item_title": "Shop database", "kind": "never", "created_at": 1_789_990_000u64},
            {"item": API_ITEM, "item_title": "API token", "kind": "only", "created_at": 1_789_990_100u64},
        ]);
    });
    publish(&setup.a.relay, TEAM, &setup.a.key, 2, &text);
}

#[test]
fn a_lock_drops_everything() {
    let setup = setup();
    fresh_feed(&setup);
    assert_eq!(macs(&setup.phone).len(), 1);
    let (prepared, _) = act(&setup, "only", 1_789_990_100, API_ITEM);
    let action_id = prepared["action_id"].as_str().unwrap().to_owned();

    // A lock ends a wait at once.
    let started = Instant::now();
    std::thread::scope(|scope| {
        let waiting =
            scope.spawn(|| fails(&setup.phone, json!({"op": "feed_wait", "timeout": 20})));
        std::thread::sleep(Duration::from_millis(300));
        call(&setup.phone, json!({"op": "lock"}));
        assert_eq!(waiting.join().unwrap(), "locked");
    });
    assert!(started.elapsed() < Duration::from_secs(10));
    // Nothing of the feeds answers while locked.
    assert_eq!(fails(&setup.phone, json!({"op": "feed_list"})), "locked");
    assert_eq!(
        fails(&setup.phone, json!({"op": "feed_wait", "timeout": 1})),
        "locked"
    );
    assert_eq!(
        fails(
            &setup.phone,
            string_request(&setup, "never", 1_789_990_000, SHOP_ITEM)
        ),
        "locked"
    );
    assert_eq!(
        fails(
            &setup.phone,
            json!({"op": "feed_action_wait", "action_id": action_id})
        ),
        "not_found"
    );
    // The AutoFill extension never reads feeds.
    let autofill = Core::new(
        &json!({"data_dir": setup.data, "device_name": "Test iPhone", "role": "autofill"})
            .to_string(),
    )
    .unwrap();
    assert_eq!(fails(&autofill, json!({"op": "feed_list"})), "not_allowed");
    drop(autofill);

    // After the unlock the feed of the mark shows again; the action of the old session
    // is not known any more.
    call(&setup.phone, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(macs(&setup.phone).len(), 1);
    assert_eq!(
        fails(
            &setup.phone,
            json!({"op": "feed_action_wait", "action_id": action_id})
        ),
        "not_found"
    );
    // A suspend drops them too.
    call(&setup.phone, json!({"op": "suspend"}));
    assert_eq!(fails(&setup.phone, json!({"op": "feed_list"})), "locked");
}
