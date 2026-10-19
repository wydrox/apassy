//! Synthetic question fixture shared by relay flow and compatibility tests.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::questions_relay::QuestionsRelay;
use apassy::sync::{DeviceKey, decode_b64u, encode_b64u};
use apassy::vault::{TrustedDeviceKind, Vault};
use apassy_core::{Core, HistoryKeyError, HistoryKeyProvider};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

/// A synthetic Keychain substitute. Its state outlives each restarted core, while
/// remaining scoped to one temp-vault setup and never touching the real Keychain.
#[derive(Default)]
pub(super) struct SyntheticHistoryKeys {
    keys: Mutex<BTreeMap<String, [u8; 32]>>,
    unavailable: AtomicBool,
}

impl SyntheticHistoryKeys {
    pub(super) fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }
}

impl HistoryKeyProvider for SyntheticHistoryKeys {
    fn key(
        &self,
        vault_id: &str,
        may_create: bool,
    ) -> Result<Zeroizing<[u8; 32]>, HistoryKeyError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(HistoryKeyError::Unavailable);
        }
        let mut keys = self.keys.lock().unwrap();
        if let Some(key) = keys.get(vault_id) {
            return Ok(Zeroizing::new(*key));
        }
        if !may_create {
            return Err(HistoryKeyError::Missing);
        }
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        keys.insert(vault_id.to_owned(), key);
        Ok(Zeroizing::new(key))
    }
}

pub(super) fn history_key(setup: &Setup, vault_id: &str) -> Zeroizing<[u8; 32]> {
    setup.history_keys.key(vault_id, false).unwrap()
}

pub(super) const PASS: &str = "synthetic-phone-pass";
pub(super) const TEAM: &str = "t_7k2m5q4x3c";
pub(super) const QUESTION_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
pub(super) const KEY_ID: &str = "630dcd2966c43366";
pub(super) const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
pub(super) const ASKER: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
pub(super) const ANSWER_PRIVATE: &str =
    "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
pub(super) const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
pub(super) const DIGEST: &str = "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d";
pub(super) const CARD: &str = r#"{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","asker":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"created_at":1790000000,"run":{"id":"123456789012345","agent":"claude-code","command":["npm","run","migrate"],"cwd":"/tmp/synthetic-shop","env_names":["DATABASE_URL","API_TOKEN"],"purpose":"Apply the new migration.","risk":"production credential: always asks the owner","user_request":"Deploy the new schema to staging.","request_source":"from the host hook","agent_request":"Run the migration.","remember":null},"question":{"id":"123456789012345","item_ids":["7","9"],"items":[{"item_id":"7","name":"Shop database","production":true,"unconfirmed":false,"always_ask":false},{"item_id":"9","name":"API token","production":false,"unconfirmed":true,"always_ask":false}],"project":{"key":"/tmp/synthetic-shop/.git","label":"synthetic-shop"},"action":"deploy","production":true,"why":"A production credential goes to a deploy.","valid_answers":["once","production:deploy","correct_environment","never_for_agent","always_ask_for_agent","disconnect"]},"digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"}"#;

pub(super) fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

pub(super) fn core(dir: &Path, role: &str) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Test iPhone", "role": role});
    Core::new(&config.to_string()).expect("core")
}

pub(super) fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).expect("json");
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

pub(super) fn fails(core: &Core, request: Value) -> String {
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

pub(super) fn aad(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

pub(super) fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> (String, String) {
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

pub(super) fn open(key: &[u8], aad: &[u8], nonce: &str, ciphertext: &str) -> Option<Vec<u8>> {
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

/// The asking Mac posts `card` as `qid`, sealed with `key`, expiring at `expires_at`.
pub(super) fn post(relay: &QuestionsRelay, key: &[u8], qid: &str, card: &str, expires_at: u64) {
    let key_id = hex_key_id(key);
    let aad = aad(&[
        "apassy-question-v1",
        "card",
        TEAM,
        qid,
        &key_id,
        "member",
        &expires_at.to_string(),
    ]);
    let (nonce, ciphertext) = seal(key, &aad, card.as_bytes());
    relay.post_question(qid, &key_id, &nonce, &ciphertext, expires_at);
}

pub(super) fn hex_key_id(key: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, key).as_ref()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The setup: an iPhone vault (as from iCloud Drive) with the question key and the
/// asking Mac's `trusted_device` row, and a fake relay team with the Mac as device 1.
pub(super) struct Setup {
    _root: TempDir,
    pub(super) data: PathBuf,
    /// The vault file of the iPhone.
    pub(super) file: PathBuf,
    pub(super) core: Core,
    pub(super) relay: QuestionsRelay,
    pub(super) history_keys: Arc<SyntheticHistoryKeys>,
}

pub(super) fn setup() -> Setup {
    setup_with_history(false)
}

pub(super) fn core_with_history(dir: &Path, keys: Arc<SyntheticHistoryKeys>) -> Core {
    std::fs::create_dir_all(dir.join("request-history")).unwrap();
    // Synthetic host only: the shipping Swift host verifies Foundation backup exclusion.
    Core::new_with_history_key_provider(
        &json!({"data_dir": dir, "device_name": "Test iPhone", "role": "app", "request_history_enabled": true, "request_history_required": true}).to_string(),
        keys,
    ).unwrap()
}

pub(super) fn setup_with_history(history: bool) -> Setup {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("Apassy");
    std::fs::create_dir_all(&data).unwrap();
    let history_keys = Arc::new(SyntheticHistoryKeys::default());
    let phone = if history {
        core_with_history(&data, Arc::clone(&history_keys))
    } else {
        core(&data, "app")
    };
    let vault = call(
        &phone,
        json!({"op": "create_local_vault", "name": "Personal", "passphrase": PASS}),
    );
    let id = vault["vault"]["id"].as_str().unwrap().to_owned();
    call(&phone, json!({"op": "lock"}));
    let file = data.join("vaults").join(format!("{id}.apassy"));
    // The question key arrives with the sync of a Mac (section 5.1).
    {
        let conn = rusqlite::Connection::open(&file).unwrap();
        conn.pragma_update(None, "key", PASS).unwrap();
        conn.execute(
            "INSERT INTO vault_secret (name, value, updated_at, updated_by) VALUES ('question-key-v1', ?1, 1, 'mac')",
            [QUESTION_KEY.as_slice()],
        )
        .unwrap();
    }
    let mac_key = DeviceKey::generate().unwrap();
    {
        let mut vault = Vault::open(&file).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .register_trusted_device(
                ASKER,
                "MacBook Pro",
                TrustedDeviceKind::Mac,
                mac_key.public_key(),
                None,
            )
            .unwrap();
        vault.set_trusted_device_relay_id(ASKER, TEAM, 1).unwrap();
    }
    call(&phone, json!({"op": "unlock", "passphrase": PASS}));
    let relay = QuestionsRelay::start(TEAM, mac_key.public_key());
    Setup {
        _root: root,
        data,
        file,
        core: phone,
        relay,
        history_keys,
    }
}

/// Change the iPhone's vault as the sync of a Mac does: the core locks, the change goes
/// into the file, and the core unlocks again.
pub(super) fn as_the_mac<T>(setup: &Setup, change: impl FnOnce(&mut Vault) -> T) -> T {
    call(&setup.core, json!({"op": "lock"}));
    let out = {
        let mut vault = Vault::open(&setup.file).unwrap();
        vault.unlock(PASS).unwrap();
        change(&mut vault)
    };
    call(&setup.core, json!({"op": "unlock", "passphrase": PASS}));
    out
}

/// The Mac confirmed the last link: it writes the row of the iPhone from the name and the
/// key of the link (relay-questions-v1 section 5.2), and the row reaches the iPhone with
/// the sync. Returns the UUID of the row.
pub(super) fn mac_writes_the_row(setup: &Setup) -> String {
    let (device_id, name, public_key) = setup.relay.confirmed().pop().expect("a confirmed link");
    assert!(name.starts_with("Test iPhone ~"), "{name}");
    assert!(name.len() <= 64);
    as_the_mac(setup, |vault| {
        apassy::relay::membership::register_linked_device(
            vault,
            TEAM,
            device_id,
            &name,
            &public_key,
        )
        .expect("the row")
        .expect("an iPhone")
        .uuid
    })
}

/// Join the notifications-only team with the answer key `answer_public` (b64u): the
/// relay device `device_id`. The iPhone writes no row; the Mac does.
pub(super) fn attach_with(setup: &Setup, answer_public: &str, device_id: u64) -> String {
    let (link, _) = setup.relay.link();
    let waiting = call(
        &setup.core,
        json!({"op": "join_attach", "link": link, "answer_key": answer_public}),
    );
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(waiting["words"].as_array().unwrap().len(), 2);
    let still = call(&setup.core, json!({"op": "join_attach_poll"}));
    assert_eq!(still["state"], "waiting");
    assert_eq!(setup.relay.confirm_links(), vec![device_id]);
    let attached = call(&setup.core, json!({"op": "join_attach_poll"}));
    assert_eq!(attached["state"], "attached");
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["enabled"], true);
    assert_eq!(list["status"]["team_id"], TEAM);
    assert_eq!(list["status"]["relay_device_id"], device_id);
    assert_eq!(list["status"]["has_key"], true);
    // Until the row of the Mac syncs here, the iPhone is not registered and writes none.
    assert_eq!(list["status"]["registered"], false);
    assert_eq!(list["status"]["removed"], false);
    assert_eq!(list["status"]["device_uuid"], Value::Null);
    assert_eq!(list["status"]["answer_key"], Value::Null);
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "answer_key_register", "public_key": answer_public})
        ),
        "not_registered"
    );
    let iphones = as_the_mac(setup, |vault| {
        vault
            .trusted_devices()
            .unwrap()
            .into_iter()
            .filter(|device| device.kind == TrustedDeviceKind::Iphone)
            .count()
    });
    assert_eq!(iphones, 0, "the iPhone wrote no row");
    let uuid = mac_writes_the_row(setup);
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["registered"], true);
    assert_eq!(list["status"]["device_uuid"], uuid.as_str());
    assert_eq!(list["status"]["answer_key"], answer_public);
    let registered = call(
        &setup.core,
        json!({"op": "answer_key_register", "public_key": answer_public}),
    );
    assert_eq!(registered["device_uuid"], uuid.as_str());
    assert_eq!(registered["relay_device_id"], device_id);
    uuid
}

/// Join the notifications-only team with the answer key of the vectors.
pub(super) fn attach(setup: &Setup) -> String {
    attach_with(setup, ANSWER_PUBLIC, 2)
}
