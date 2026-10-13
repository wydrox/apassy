//! Questions through the relay on the iPhone (contract relay-questions-v1, ios-core-v1
//! section 5.10), through the JSON calls as the app makes them, against an in-process
//! fake of the relay's question routes. The asking Mac is played by the test: it seals
//! cards with the question key of the vault, and opens the iPhone's answers. The card,
//! the key, and the answer key are the synthetic values of the contract's test vectors.

#[path = "common/questions_relay.rs"]
mod questions_relay;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use apassy::sync::{DeviceKey, decode_b64u, encode_b64u, verify_signature};
use apassy::vault::{TrustedDeviceKind, Vault};
use apassy_core::Core;
use questions_relay::{QuestionsRelay, now};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-phone-pass";
const TEAM: &str = "t_7k2m5q4x3c";
const QUESTION_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const KEY_ID: &str = "630dcd2966c43366";
const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
const ASKER: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
const ANSWER_PRIVATE: &str = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
const DIGEST: &str = "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d";
const CARD: &str = r#"{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","asker":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"created_at":1790000000,"run":{"id":"123456789012345","agent":"claude-code","command":["npm","run","migrate"],"cwd":"/tmp/synthetic-shop","env_names":["DATABASE_URL","API_TOKEN"],"purpose":"Apply the new migration.","risk":"production credential: always asks the owner","user_request":"Deploy the new schema to staging.","request_source":"from the host hook","agent_request":"Run the migration.","remember":null},"question":{"id":"123456789012345","item_ids":["7","9"],"items":[{"item_id":"7","name":"Shop database","production":true,"unconfirmed":false,"always_ask":false},{"item_id":"9","name":"API token","production":false,"unconfirmed":true,"always_ask":false}],"project":{"key":"/tmp/synthetic-shop/.git","label":"synthetic-shop"},"action":"deploy","production":true,"why":"A production credential goes to a deploy.","valid_answers":["once","production:deploy","correct_environment","never_for_agent","always_ask_for_agent","disconnect"]},"digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"}"#;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn core(dir: &Path, role: &str) -> Core {
    let config = json!({"data_dir": dir, "device_name": "Test iPhone", "role": role});
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

/// The asking Mac posts `card` as `qid`, sealed with `key`, expiring at `expires_at`.
fn post(relay: &QuestionsRelay, key: &[u8], qid: &str, card: &str, expires_at: u64) {
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

fn hex_key_id(key: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, key).as_ref()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The setup: an iPhone vault (as from iCloud Drive) with the question key and the
/// asking Mac's `trusted_device` row, and a fake relay team with the Mac as device 1.
struct Setup {
    _root: TempDir,
    data: PathBuf,
    /// The vault file of the iPhone.
    file: PathBuf,
    core: Core,
    relay: QuestionsRelay,
}

fn setup() -> Setup {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("Apassy");
    std::fs::create_dir_all(&data).unwrap();
    let phone = core(&data, "app");
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
    }
}

/// Change the iPhone's vault as the sync of a Mac does: the core locks, the change goes
/// into the file, and the core unlocks again.
fn as_the_mac<T>(setup: &Setup, change: impl FnOnce(&mut Vault) -> T) -> T {
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
fn mac_writes_the_row(setup: &Setup) -> String {
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
fn attach_with(setup: &Setup, answer_public: &str, device_id: u64) -> String {
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
fn attach(setup: &Setup) -> String {
    attach_with(setup, ANSWER_PUBLIC, 2)
}

#[test]
fn an_iphone_attaches_reads_a_card_and_answers_with_face_id_and_without() {
    let setup = setup();
    // No team yet: an empty list, and no answer.
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["enabled"], false);
    assert_eq!(
        call(&setup.core, json!({"op": "questions_wait", "timeout": 1}))["changed"],
        false
    );
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "push_token_set", "token": "ab".repeat(32), "environment": "development"})
        ),
        "no_questions"
    );
    let uuid = attach(&setup);
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["answer_key"], ANSWER_PUBLIC);
    assert_eq!(list["questions"].as_array().unwrap().len(), 0);
    // A second attach of the same vault is refused.
    let (link, _) = setup.relay.link();
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC})
        ),
        "invalid_input"
    );

    post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    let list = call(&setup.core, json!({"op": "questions_list"}));
    let question = &list["questions"][0];
    assert_eq!(question["qid"], QID);
    assert_eq!(question["state"], "open");
    assert_eq!(question["problem"], Value::Null);
    assert_eq!(question["asker_name"], "MacBook Pro");
    assert_eq!(question["card"]["run"]["agent"], "claude-code");
    assert_eq!(question["card"]["digest"], DIGEST);
    assert_eq!(
        question["card"]["question"]["project"]["label"],
        "synthetic-shop"
    );
    let opened = call(&setup.core, json!({"op": "question_open", "qid": QID}));
    assert_eq!(opened["card"]["question"]["action"], "deploy");

    // "Allow production: Deploy in synthetic-shop": Face ID signs in Swift.
    let prepared = call(
        &setup.core,
        json!({"op": "question_answer_string", "qid": QID, "kind": "allow_production"}),
    );
    assert_eq!(prepared["needs_face_id"], true);
    let time = prepared["time"].as_u64().unwrap();
    let text = prepared["answer_string"].as_str().unwrap().to_owned();
    assert_eq!(
        text,
        format!(
            "apassy-question-answer-v1\n{uuid}\n{TEAM}\n{QID}\nallow_production:deploy:/tmp/synthetic-shop/.git\n{DIGEST}\n{time}"
        )
    );
    let answer_key =
        DeviceKey::from_raw(&unhex(ANSWER_PRIVATE), &decode_b64u(ANSWER_PUBLIC).unwrap()).unwrap();
    let signature = encode_b64u(&answer_key.sign(text.as_bytes()).unwrap());
    // Without Face ID, or by another key, nothing is sent.
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "question_answer", "qid": QID, "kind": "allow_production", "time": time})
        ),
        "invalid_input"
    );
    let other = DeviceKey::generate().unwrap();
    let forged = encode_b64u(&other.sign(text.as_bytes()).unwrap());
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "question_answer", "qid": QID, "kind": "allow_production", "time": time, "signature": forged})
        ),
        "not_registered"
    );
    // A kind that the question does not offer.
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "question_answer_string", "qid": QID, "kind": "approve_in_project"})
        ),
        "invalid_input"
    );
    assert!(setup.relay.answers().is_empty());
    let sent = call(
        &setup.core,
        json!({"op": "question_answer", "qid": QID, "kind": "allow_production", "time": time, "signature": signature}),
    );
    assert_eq!(sent["kind"], "allow_production");

    // The Mac opens the answer with the stamped device id and checks it (section 12.3).
    let answers = setup.relay.answers();
    assert_eq!(answers.len(), 1);
    let stored = &answers[0];
    assert_eq!(stored.device_id, 2);
    assert_eq!(stored.key_id, KEY_ID);
    let answer_aad = aad(&["apassy-question-v1", "answer", TEAM, QID, KEY_ID, "2"]);
    let plaintext = open(
        &QUESTION_KEY,
        &answer_aad,
        &stored.nonce,
        &stored.ciphertext,
    )
    .unwrap();
    let moved = aad(&["apassy-question-v1", "answer", TEAM, QID, KEY_ID, "3"]);
    assert!(open(&QUESTION_KEY, &moved, &stored.nonce, &stored.ciphertext).is_none());
    let answer: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(
        answer
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .len(),
        9
    );
    assert_eq!(answer["by"], uuid.as_str());
    assert_eq!(answer["kind"], "allow_production");
    assert_eq!(answer["action"], "deploy");
    assert_eq!(answer["project_key"], "/tmp/synthetic-shop/.git");
    assert_eq!(answer["digest"], DIGEST);
    let rebuilt = format!(
        "apassy-question-answer-v1\n{}\n{TEAM}\n{QID}\nallow_production:{}:{}\n{}\n{}",
        answer["by"].as_str().unwrap(),
        answer["action"].as_str().unwrap(),
        answer["project_key"].as_str().unwrap(),
        answer["digest"].as_str().unwrap(),
        answer["time"]
    );
    let signature = decode_b64u(answer["signature"].as_str().unwrap()).unwrap();
    assert!(verify_signature(
        &decode_b64u(ANSWER_PUBLIC).unwrap(),
        rebuilt.as_bytes(),
        &signature
    ));

    // "Deny" takes authority away: the core signs with the relay key, no Face ID.
    let sent = call(
        &setup.core,
        json!({"op": "question_answer", "qid": QID, "kind": "deny", "time": now()}),
    );
    assert_eq!(sent["kind"], "deny");
    let stored = &setup.relay.answers()[1];
    let plaintext = open(
        &QUESTION_KEY,
        &answer_aad,
        &stored.nonce,
        &stored.ciphertext,
    )
    .unwrap();
    let answer: Value = serde_json::from_slice(&plaintext).unwrap();
    let rebuilt = format!(
        "apassy-question-answer-v1\n{uuid}\n{TEAM}\n{QID}\ndeny\n{DIGEST}\n{}",
        answer["time"]
    );
    let signature = decode_b64u(answer["signature"].as_str().unwrap()).unwrap();
    assert!(verify_signature(
        &setup.relay.device_key(2),
        rebuilt.as_bytes(),
        &signature
    ));
    assert!(!verify_signature(
        &decode_b64u(ANSWER_PUBLIC).unwrap(),
        rebuilt.as_bytes(),
        &signature
    ));
    // "Development" for the unconfirmed item needs Face ID; "Production" does not.
    let development = call(
        &setup.core,
        json!({"op": "question_answer_string", "qid": QID, "kind": "correct_environment", "item_id": "9", "environment": "development"}),
    );
    assert_eq!(development["needs_face_id"], true);
    assert!(
        development["answer_string"]
            .as_str()
            .unwrap()
            .contains("\ncorrect_environment:development:9\n")
    );
    // An old time is refused before anything is sent.
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "question_answer", "qid": QID, "kind": "deny", "time": now() - 120})
        ),
        "stale_answer"
    );

    // The Mac settles: the list shows who answered, and a late answer is refused.
    let settle = json!({"v":1,"qid":QID,"outcome":"approved","answered_by":uuid,"device_name":"Test iPhone","device_kind":"iphone","kind":"allow_production","at":now()}).to_string();
    let settle_aad = aad(&["apassy-question-v1", "settle", TEAM, QID, KEY_ID]);
    let (nonce, ciphertext) = seal(&QUESTION_KEY, &settle_aad, settle.as_bytes());
    setup.relay.settle(QID, KEY_ID, &nonce, &ciphertext);
    let list = call(&setup.core, json!({"op": "questions_list"}));
    let question = &list["questions"][0];
    assert_eq!(question["state"], "settled");
    assert_eq!(question["settle"]["outcome"], "approved");
    assert_eq!(question["settle"]["device_name"], "Test iPhone");
    assert_eq!(question["answered"], "deny");
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "question_answer", "qid": QID, "kind": "deny", "time": now()})
        ),
        "already_answered"
    );
}

#[test]
fn cards_that_fail_a_check_are_not_shown_or_answered() {
    let setup = setup();
    attach(&setup);
    // A card whose digest does not match its fields.
    let wrong_digest_qid = "AAAAAAAAAAAAAAAAAAAAAA";
    let wrong = CARD
        .replace(QID, wrong_digest_qid)
        .replace("\"migrate\"", "\"drop\"");
    post(
        &setup.relay,
        &QUESTION_KEY,
        wrong_digest_qid,
        &wrong,
        now() + 300,
    );
    // A card sealed with a key that this vault does not have.
    let other_key_qid = "AQEBAQEBAQEBAQEBAQEBAQ";
    post(
        &setup.relay,
        &[7u8; 32],
        other_key_qid,
        &CARD.replace(QID, other_key_qid),
        now() + 300,
    );
    // A card of an asker that is not a trusted device of the vault.
    let stranger_qid = "AgICAgICAgICAgICAgICAg";
    post(
        &setup.relay,
        &QUESTION_KEY,
        stranger_qid,
        &CARD
            .replace(QID, stranger_qid)
            .replace(ASKER, "11111111-2222-4333-8444-555555555555"),
        now() + 300,
    );
    // An expired question.
    let expired_qid = "AwMDAwMDAwMDAwMDAwMDAw";
    post(
        &setup.relay,
        &QUESTION_KEY,
        expired_qid,
        &CARD.replace(QID, expired_qid),
        now() - 1,
    );
    let list = call(&setup.core, json!({"op": "questions_list"}));
    let by_qid = |qid: &str| {
        list["questions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|question| question["qid"] == qid)
            .cloned()
            .unwrap()
    };
    let wrong = by_qid(wrong_digest_qid);
    assert_eq!(wrong["card"], Value::Null);
    assert_eq!(wrong["problem"], "This question could not be read.");
    assert_eq!(
        by_qid(other_key_qid)["problem"],
        "Sync this vault to read this question."
    );
    assert_eq!(
        by_qid(stranger_qid)["problem"],
        "This question could not be read."
    );
    assert_eq!(by_qid(expired_qid)["state"], "expired");
    for qid in [wrong_digest_qid, other_key_qid, stranger_qid] {
        assert_eq!(
            fails(&setup.core, json!({"op": "question_open", "qid": qid})),
            "unreadable"
        );
        assert_eq!(
            fails(
                &setup.core,
                json!({"op": "question_answer", "qid": qid, "kind": "deny", "time": now()})
            ),
            "unreadable"
        );
    }
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "question_answer", "qid": expired_qid, "kind": "deny", "time": now()})
        ),
        "expired"
    );
    assert!(setup.relay.answers().is_empty());
}

#[test]
fn the_long_poll_wakes_on_a_new_question_and_push_tokens_reach_the_relay() {
    let setup = setup();
    attach(&setup);
    call(&setup.core, json!({"op": "questions_list"}));
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(300));
            post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
        });
        let waited = call(&setup.core, json!({"op": "questions_wait", "timeout": 10}));
        assert_eq!(waited["changed"], true);
    });
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["questions"][0]["qid"], QID);

    let token = "0a".repeat(32);
    let set = call(
        &setup.core,
        json!({"op": "push_token_set", "token": token, "environment": "development"}),
    );
    assert_eq!(set["device_id"], 2);
    let (device, body) = setup.relay.push_token().unwrap();
    assert_eq!(device, 2);
    assert_eq!(
        body,
        json!({"token": token, "environment": "development", "bundle_id": "com.wydrox.apassy.companion"})
    );
    for bad in [
        json!({"op": "push_token_set", "token": "0A".repeat(32), "environment": "development"}),
        json!({"op": "push_token_set", "token": "0a", "environment": "development"}),
        json!({"op": "push_token_set", "token": token, "environment": "staging"}),
    ] {
        assert_eq!(fails(&setup.core, bad), "invalid_input");
    }
    call(&setup.core, json!({"op": "push_token_clear"}));
    assert!(setup.relay.push_token().is_none());

    // The AutoFill extension never answers; a lock ends the questions.
    let autofill = core(&setup.data, "autofill");
    assert_eq!(
        fails(&autofill, json!({"op": "questions_list"})),
        "not_allowed"
    );
    call(&setup.core, json!({"op": "lock"}));
    assert_eq!(
        fails(&setup.core, json!({"op": "questions_list"})),
        "locked"
    );
}

/// The list polls of `GET /v1/questions` in the log of the relay.
fn list_polls(relay: &QuestionsRelay) -> usize {
    relay
        .log()
        .iter()
        .filter(|line| *line == "GET /v1/questions")
        .count()
}

/// A list poll that comes back early with nothing new starts a pause (relay-connect-v1
/// section 5): `questions_wait` then waits without a relay call and answers "no change".
/// A poll that waited its full time does not.
#[test]
fn an_early_empty_list_poll_pauses_the_next_one() {
    let setup = setup();
    attach(&setup);
    call(&setup.core, json!({"op": "questions_list"}));

    // A full poll: the next one goes at once.
    let started = Instant::now();
    let waited = call(&setup.core, json!({"op": "questions_wait", "timeout": 2}));
    assert_eq!(waited["changed"], false);
    assert!(started.elapsed() >= Duration::from_secs(2));
    let before = list_polls(&setup.relay);
    call(&setup.core, json!({"op": "questions_wait", "timeout": 2}));
    assert_eq!(list_polls(&setup.relay), before + 1);

    // An early empty answer: the next call pauses for its timeout and asks nothing.
    setup.relay.answer_polls_at_once(true);
    let started = Instant::now();
    let waited = call(&setup.core, json!({"op": "questions_wait", "timeout": 10}));
    assert_eq!(waited["changed"], false);
    assert!(started.elapsed() < Duration::from_secs(5));
    let before = list_polls(&setup.relay);
    let started = Instant::now();
    let waited = call(&setup.core, json!({"op": "questions_wait", "timeout": 1}));
    assert_eq!(waited["changed"], false);
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(list_polls(&setup.relay), before);

    // A lock ends a pause at once.
    let before = list_polls(&setup.relay);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(300));
            call(&setup.core, json!({"op": "lock"}));
        });
        let started = Instant::now();
        let waited = call(&setup.core, json!({"op": "questions_wait", "timeout": 10}));
        assert_eq!(waited["changed"], false);
        assert!(started.elapsed() < Duration::from_secs(2));
    });
    assert_eq!(list_polls(&setup.relay), before);
}

/// The iPhone sends its answer key with the link and writes no row; an attach without it
/// is refused before the relay is asked.
#[test]
fn the_row_of_an_iphone_comes_from_the_confirming_mac() {
    let setup = setup();
    let (link, _) = setup.relay.link();
    assert_eq!(
        fails(&setup.core, json!({"op": "join_attach", "link": link})),
        "invalid_input"
    );
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "join_attach", "link": link, "answer_key": "AAAA"})
        ),
        "invalid_input"
    );
    assert!(setup.relay.confirm_links().is_empty(), "no link was sent");
    // `attach` checks that no row exists before the Mac writes it, and that
    // `answer_key_register` only checks.
    let uuid = attach(&setup);
    // Another answer key than the row's: refused, and nothing changes.
    let other = encode_b64u(DeviceKey::generate().unwrap().public_key());
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "answer_key_register", "public_key": other})
        ),
        "answer_key_changed"
    );
    let row = as_the_mac(&setup, |vault| {
        vault.trusted_device(&uuid).unwrap().unwrap()
    });
    assert_eq!(row.answer_key, decode_b64u(ANSWER_PUBLIC));
    assert_eq!(row.kind, TrustedDeviceKind::Iphone);
    assert_eq!(row.name, "Test iPhone");
    assert_eq!(row.sign_key, setup.relay.device_key(2));
}

/// The owner removes the iPhone on a Mac: once the removal syncs, the iPhone says so,
/// answers nothing, and its old keys never register again. A new attach with a new relay
/// key and a new answer key, confirmed on the Mac, makes it a device again.
#[test]
fn a_removed_iphone_cannot_answer_until_it_is_connected_again() {
    let setup = setup();
    let uuid = attach(&setup);
    post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    let (_, old_name, old_key) = setup.relay.confirmed().pop().unwrap();
    assert!(as_the_mac(&setup, |vault| vault
        .remove_trusted_device_and_rotate(&uuid)
        .unwrap()));
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["removed"], true);
    assert_eq!(list["status"]["registered"], false);
    assert_eq!(list["questions"].as_array().unwrap().len(), 0);
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "answer_key_register", "public_key": ANSWER_PUBLIC})
        ),
        "removed"
    );
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "question_answer", "qid": QID, "kind": "deny", "time": now()})
        ),
        "removed"
    );
    assert!(setup.relay.answers().is_empty());
    // The Mac cannot write the old keys again.
    let again = as_the_mac(&setup, |vault| {
        apassy::relay::membership::register_linked_device(vault, TEAM, 9, &old_name, &old_key)
            .unwrap_err()
            .kind()
    });
    assert_eq!(again, apassy::vault::VaultErrorKind::AlreadyExists);
    // The removed answer key cannot come back with a new relay key either.
    let (link, _) = setup.relay.link();
    call(
        &setup.core,
        json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}),
    );
    setup.relay.confirm_links();
    assert_eq!(
        call(&setup.core, json!({"op": "join_attach_poll"}))["state"],
        "attached"
    );
    let (device_id, name, key) = setup.relay.confirmed().pop().unwrap();
    assert_eq!(device_id, 3);
    let refused = as_the_mac(&setup, |vault| {
        apassy::relay::membership::register_linked_device(vault, TEAM, device_id, &name, &key)
            .unwrap_err()
            .kind()
    });
    assert_eq!(refused, apassy::vault::VaultErrorKind::AlreadyExists);
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["registered"], false);
    assert_eq!(list["status"]["removed"], false);
    assert_eq!(list["status"]["relay_device_id"], 3);
}

/// After the removal, a new answer key and a new relay key make the iPhone a device again.
#[test]
fn a_removed_iphone_joins_again_with_new_keys() {
    let setup = setup();
    let uuid = attach(&setup);
    as_the_mac(&setup, |vault| {
        vault.remove_trusted_device_and_rotate(&uuid).unwrap();
        // The new question key reaches the iPhone with the sync; the test keeps the
        // contract key so its cards still open.
        vault.rotate_question_key().unwrap();
    });
    call(&setup.core, json!({"op": "lock"}));
    {
        let conn = rusqlite::Connection::open(&setup.file).unwrap();
        conn.pragma_update(None, "key", PASS).unwrap();
        conn.execute(
            "UPDATE vault_secret SET value = ?1 WHERE name = 'question-key-v1'",
            [QUESTION_KEY.as_slice()],
        )
        .unwrap();
    }
    call(&setup.core, json!({"op": "unlock", "passphrase": PASS}));
    let new_answer = DeviceKey::generate().unwrap();
    let new_uuid = attach_with(&setup, &encode_b64u(new_answer.public_key()), 3);
    assert_ne!(new_uuid, uuid);
    post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    let sent = call(
        &setup.core,
        json!({"op": "question_answer", "qid": QID, "kind": "deny", "time": now()}),
    );
    assert_eq!(sent["kind"], "deny");
    assert_eq!(setup.relay.answers()[0].device_id, 3);
}

#[test]
fn a_cancelled_attach_leaves_the_vault_without_a_team() {
    let setup = setup();
    let (link, _) = setup.relay.link();
    call(
        &setup.core,
        json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}),
    );
    call(&setup.core, json!({"op": "join_attach_cancel"}));
    assert_eq!(
        fails(&setup.core, json!({"op": "join_attach_poll"})),
        "invalid_input"
    );
    assert!(setup.relay.confirm_links().is_empty());
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["enabled"], false);
    assert_eq!(
        fails(
            &setup.core,
            json!({"op": "answer_key_register", "public_key": ANSWER_PUBLIC})
        ),
        "no_questions"
    );
}

/// A link that the owner did not make: when the vault names its questions team (from the
/// Mac that connected it), a link of another team is refused before any relay call, so
/// it cannot bind this iPhone to a stranger's team. A link of the named team works.
#[test]
fn a_link_of_another_team_is_refused_when_the_vault_names_its_team() {
    let setup = setup();
    as_the_mac(&setup, |vault| {
        vault.set_questions_team("t_aaaaaaaaaa").unwrap()
    });
    let (link, _) = setup.relay.link();
    let answer: Value = serde_json::from_str(&setup.core.call(
        &json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}).to_string(),
    ))
    .unwrap();
    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["error"]["code"], "link_invalid");
    assert_eq!(
        answer["error"]["message"],
        "This code is for another vault's devices. On your Mac, open Settings > Devices > Add a device."
    );
    assert!(
        !setup
            .relay
            .log()
            .iter()
            .any(|line| line == "POST /v1/devices/link"),
        "no relay call"
    );
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["enabled"], false);

    // The vault names the team of the link: the iPhone joins.
    as_the_mac(&setup, |vault| vault.set_questions_team(TEAM).unwrap());
    attach(&setup);
}

/// "Disconnect from Apassy Connect": the iPhone leaves the team with no Face ID. The relay
/// removes its device, the vault drops the membership and its key, and a new code from the
/// owner's Mac connects it again.
#[test]
fn disconnect_takes_this_iphone_out_of_the_team() {
    let setup = setup();
    attach(&setup);
    assert!(setup.relay.is_live(2));
    call(&setup.core, json!({"op": "questions_disconnect"}));
    assert!(!setup.relay.is_live(2), "the relay removed the device");
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["enabled"], false);
    let memberships = as_the_mac(&setup, |vault| vault.relay_memberships().unwrap().len());
    assert_eq!(memberships, 0, "the key left the vault");
    // Again: nothing to do.
    call(&setup.core, json!({"op": "questions_disconnect"}));

    // The owner's Mac makes a new code: the iPhone joins again with a new relay key.
    let (link, _) = setup.relay.link();
    call(
        &setup.core,
        json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}),
    );
    assert_eq!(setup.relay.confirm_links(), vec![3]);
    let attached = call(&setup.core, json!({"op": "join_attach_poll"}));
    assert_eq!(attached["state"], "attached");
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["enabled"], true);
    assert_eq!(list["status"]["relay_device_id"], 3);
}

/// A cancel that the relay did not hear keeps its key and goes again when the relay
/// answers, so the Mac never confirms an iPhone whose key was dropped.
#[test]
fn a_cancel_that_the_relay_did_not_hear_is_sent_again() {
    let setup = setup();
    let (link, _) = setup.relay.link();
    call(
        &setup.core,
        json!({"op": "join_attach", "link": link, "answer_key": ANSWER_PUBLIC}),
    );
    assert_eq!(setup.relay.pending_links(), 1);
    setup.relay.set_offline(true);
    call(&setup.core, json!({"op": "join_attach_cancel"}));
    assert_eq!(setup.relay.pending_links(), 1, "the relay did not hear it");
    setup.relay.set_offline(false);
    call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(setup.relay.pending_links(), 0, "cancelled at the next call");
    assert!(setup.relay.confirm_links().is_empty());
}
