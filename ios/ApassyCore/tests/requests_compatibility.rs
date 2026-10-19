//! Synthetic compatibility checks for opt-in request history. No real vault or service.

#[path = "common/questions_fixture.rs"]
mod questions_fixture;
#[path = "common/questions_relay.rs"]
mod questions_relay;

use apassy::sync::encode_b64u;
use questions_fixture::*;
use questions_relay::now;
use serde_json::{Value, json};

fn restart(setup: &mut Setup, history: bool) {
    call(&setup.core, json!({"op":"lock"}));
    setup.core = if history {
        core_with_history(&setup.data, std::sync::Arc::clone(&setup.history_keys))
    } else {
        core(&setup.data, "app")
    };
    call(&setup.core, json!({"op":"unlock", "passphrase":PASS}));
}

fn history_entries(setup: &Setup) -> Vec<Value> {
    let history = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(history["vaults"][0]["availability"], "available");
    history["vaults"][0]["entries"].as_array().unwrap().clone()
}

fn entry<'a>(entries: &'a [Value], qid: &str) -> &'a Value {
    entries
        .iter()
        .find(|row| row["qid"] == qid)
        .expect("saved request")
}

/// Model an upgrade from the old question-key-encrypted journal using exactly
/// the metadata already recorded by this synthetic setup.
fn write_legacy_journal(setup: &Setup, vault_id: &str) -> (std::path::PathBuf, Vec<u8>) {
    let path = setup
        .data
        .join("request-history")
        .join(format!("{vault_id}.json"));
    let sealed: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(sealed["version"], 2);
    let local_key = history_key(setup, vault_id);
    let plaintext = open(
        local_key.as_slice(),
        &aad(&[
            "apassy-local-request-history-v2",
            vault_id,
            sealed["key_id"].as_str().unwrap(),
        ]),
        sealed["nonce"].as_str().unwrap(),
        sealed["ciphertext"].as_str().unwrap(),
    )
    .unwrap();
    let (nonce, ciphertext) = seal(
        &QUESTION_KEY,
        &aad(&["apassy-local-request-history-v1", vault_id, KEY_ID]),
        &plaintext,
    );
    let legacy = serde_json::to_vec(
        &json!({"version":1,"key_id":KEY_ID,"nonce":nonce,"ciphertext":ciphertext}),
    )
    .unwrap();
    std::fs::write(&path, &legacy).unwrap();
    (path, legacy)
}

#[test]
fn transient_legacy_migration_recovers_after_live_key_rotation_but_drops_on_lock() {
    for lock_before_recovery in [false, true] {
        let setup = setup_with_history(true);
        let uuid = attach(&setup);
        post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
        call(&setup.core, json!({"op":"questions_list"}));
        call(
            &setup.core,
            json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":now()}),
        );
        let old_entry = history_entries(&setup)[0].clone();
        let vault_id = old_entry["vault_id"].as_str().unwrap();
        let (path, legacy) = write_legacy_journal(&setup, vault_id);
        setup.history_keys.set_unavailable(true);
        call(&setup.core, json!({"op":"questions_list"}));
        assert_eq!(std::fs::read(&path).unwrap(), legacy);

        // Only synthetic SQL state changes. The authenticated Core remains open
        // throughout this sync, so it can retain its journal-only migration key.
        let rotated = [73u8; 32];
        {
            let conn = rusqlite::Connection::open(&setup.file).unwrap();
            conn.pragma_update(None, "key", PASS).unwrap();
            assert_eq!(conn.execute("UPDATE vault_secret SET value=?1, updated_at=updated_at+1 WHERE name='question-key-v1'", [rotated.as_slice()]).unwrap(), 1);
        }
        let qid = encode_b64u(&[43u8; 16]);
        post(
            &setup.relay,
            &rotated,
            &qid,
            &CARD.replace(QID, &qid),
            now() + 300,
        );
        let list = call(&setup.core, json!({"op":"questions_list"}));
        assert_eq!(list["status"]["registered"], true);
        assert_eq!(list["status"]["device_uuid"], uuid);
        assert_eq!(
            fails(
                &setup.core,
                json!({"op":"question_answer", "qid":qid, "kind":"deny", "time":now()})
            ),
            "history_storage_unavailable"
        );
        assert_eq!(setup.relay.answer_post_attempts(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), legacy);
        if lock_before_recovery {
            call(&setup.core, json!({"op":"lock"}));
        }
        setup.history_keys.set_unavailable(false);
        if lock_before_recovery {
            call(&setup.core, json!({"op":"unlock", "passphrase":PASS}));
            call(&setup.core, json!({"op":"questions_list"}));
            assert_eq!(
                fails(
                    &setup.core,
                    json!({"op":"question_answer", "qid":qid, "kind":"deny", "time":now()})
                ),
                "history_migration_blocked"
            );
            assert_eq!(
                fails(
                    &setup.core,
                    json!({"op":"clear_request_history", "vault_id":vault_id})
                ),
                "history_migration_blocked"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                legacy,
                "locking cannot invent recovery or erase the old encrypted guard"
            );
            assert_eq!(setup.relay.answer_post_attempts(), 1);
        } else {
            call(&setup.core, json!({"op":"questions_list"}));
            let entries = history_entries(&setup);
            assert_eq!(entry(&entries, QID), &old_entry);
            let migrated: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(migrated["version"], 2);
            call(
                &setup.core,
                json!({"op":"question_answer", "qid":qid, "kind":"deny", "time":now()}),
            );
            assert_eq!(setup.relay.answers().len(), 2);
            assert_eq!(setup.relay.answers()[1].key_id, hex_key_id(&rotated));
            assert_eq!(entry(&history_entries(&setup), QID), &old_entry);
        }
    }
}

#[test]
fn question_key_rotation_preserves_history_and_allows_a_registered_phone_to_answer() {
    for history in [false, true] {
        let mut setup = setup_with_history(history);
        let uuid = attach(&setup);
        post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
        call(&setup.core, json!({"op":"questions_list"}));
        call(
            &setup.core,
            json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":now()}),
        );
        let old_entry = history.then(|| entry(&history_entries(&setup), QID).clone());

        // Model a synced rotation caused by removing a different trusted device.
        // This iPhone keeps its registration, relay key and answer key.
        let rotated = as_the_mac(&setup, |vault| vault.rotate_question_key().unwrap());
        let qid = encode_b64u(&[42u8; 16]);
        post(
            &setup.relay,
            rotated.bytes(),
            &qid,
            &CARD.replace(QID, &qid),
            now() + 300,
        );
        let list = call(&setup.core, json!({"op":"questions_list"}));
        assert_eq!(list["status"]["registered"], true);
        assert_eq!(list["status"]["device_uuid"], uuid);
        assert!(
            list["questions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|q| q["qid"] == qid)
        );
        let sent = call(
            &setup.core,
            json!({"op":"question_answer", "qid":qid, "kind":"deny", "time":now()}),
        );
        assert_eq!(sent["kind"], "deny", "history enabled: {history}");
        assert_eq!(setup.relay.answers().len(), 2);
        assert_eq!(setup.relay.answers()[1].qid, qid);
        assert_eq!(setup.relay.answers()[1].key_id, hex_key_id(rotated.bytes()));

        if let Some(old_entry) = old_entry {
            let entries = history_entries(&setup);
            assert_eq!(entries.len(), 2);
            assert_eq!(
                entry(&entries, QID),
                &old_entry,
                "rotation must preserve the prior request"
            );
            assert_eq!(entry(&entries, &qid)["selected_kind"], "deny");
            assert!(entry(&entries, &qid)["sent_at"].is_number());
            assert!(entry(&entries, &qid)["outcome"].is_null());
            restart(&mut setup, history);
            let entries = history_entries(&setup);
            assert_eq!(entry(&entries, QID), &old_entry);
            assert_eq!(entry(&entries, &qid)["selected_kind"], "deny");
            call(&setup.core, json!({"op":"questions_list"}));
            assert_eq!(
                fails(
                    &setup.core,
                    json!({"op":"question_answer_string", "qid":qid, "kind":"never_for_agent"})
                ),
                "already_answered"
            );
            assert_eq!(
                setup.relay.answer_post_attempts(),
                2,
                "restart must retain the accepted answer guard"
            );
        }
    }
}

#[test]
fn definitive_429_allows_a_different_choice_immediately_and_after_restart() {
    for history in [false, true] {
        for restart_after_rejection in [false, true] {
            let mut setup = setup_with_history(history);
            attach(&setup);
            post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
            call(&setup.core, json!({"op":"questions_list"}));
            setup.relay.rate_answer_posts(1);
            assert_eq!(
                fails(
                    &setup.core,
                    json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":now()})
                ),
                "rate_limited"
            );
            assert_eq!(setup.relay.answer_post_attempts(), 1);
            assert!(
                setup.relay.answers().is_empty(),
                "429 must happen before relay acceptance"
            );
            // Preserve the relay's real backoff contract before reading/retrying.
            std::thread::sleep(std::time::Duration::from_millis(1100));
            if restart_after_rejection {
                restart(&mut setup, history);
            }
            let list = call(&setup.core, json!({"op":"questions_list"}));
            assert!(
                list["questions"][0]["answered"].is_null(),
                "definitive rejection is not an answer"
            );
            if history {
                let entries = history_entries(&setup);
                let rejected = entry(&entries, QID);
                assert!(rejected["sent_at"].is_null());
                assert!(rejected["outcome"].is_null());
            }
            let sent = call(
                &setup.core,
                json!({"op":"question_answer", "qid":QID, "kind":"never_for_agent", "time":now()}),
            );
            assert_eq!(
                sent["kind"], "never_for_agent",
                "history: {history}, restart: {restart_after_rejection}"
            );
            assert_eq!(setup.relay.answer_post_attempts(), 2);
            assert_eq!(setup.relay.answers().len(), 1);
            if history {
                restart(&mut setup, true);
                call(&setup.core, json!({"op":"questions_list"}));
                assert_eq!(
                    entry(&history_entries(&setup), QID)["selected_kind"],
                    "never_for_agent"
                );
                assert_eq!(
                    fails(
                        &setup.core,
                        json!({"op":"question_answer_string", "qid":QID, "kind":"deny"})
                    ),
                    "already_answered"
                );
                assert_eq!(setup.relay.answer_post_attempts(), 2);
            }
        }
    }
}

#[test]
fn accepted_answer_with_lost_response_keeps_its_guard_when_the_retry_gets_429() {
    let mut setup = setup_with_history(true);
    attach(&setup);
    post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    call(&setup.core, json!({"op":"questions_list"}));
    let answer_time = now();
    setup.relay.lose_answer_replies(1);
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":answer_time})
        ),
        "relay_unreachable"
    );
    assert_eq!(
        setup.relay.answers().len(),
        1,
        "the reply was lost after acceptance"
    );
    assert_eq!(
        setup.relay.answer_post_attempts(),
        1,
        "an ambiguous POST must not be retried invisibly"
    );

    setup.relay.rate_answer_posts(1);
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":answer_time})
        ),
        "rate_limited"
    );
    assert_eq!(setup.relay.answers().len(), 1);
    assert_eq!(setup.relay.answer_post_attempts(), 2);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    restart(&mut setup, true);
    let entries = history_entries(&setup);
    let pending = entry(&entries, QID);
    assert_eq!(pending["selected_kind"], "deny");
    assert!(pending["attempted_at"].is_number());
    assert!(
        pending["sent_at"].is_null(),
        "a lost reply proves no delivery timestamp"
    );
    assert!(pending["outcome"].is_null());
    call(&setup.core, json!({"op":"questions_list"}));
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"question_answer_string", "qid":QID, "kind":"never_for_agent"})
        ),
        "already_answered"
    );
    assert_eq!(
        setup.relay.answer_post_attempts(),
        2,
        "a rejection cannot erase an earlier ambiguous send"
    );
}

#[test]
fn required_history_bootstrap_failure_cannot_bypass_an_existing_guard() {
    let mut setup = setup_with_history(true);
    attach(&setup);
    post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    call(&setup.core, json!({"op":"questions_list"}));
    call(
        &setup.core,
        json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":now()}),
    );
    let vault_id = history_entries(&setup)[0]["vault_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let journal_path = setup
        .data
        .join("request-history")
        .join(format!("{vault_id}.json"));
    let before = std::fs::read(&journal_path).unwrap();
    call(&setup.core, json!({"op":"lock"}));
    // The native host reports that storage preparation failed, while retaining
    // the app's requirement for durable guards. No synthetic provider is installed.
    setup.core = apassy_core::Core::new(
        &json!({
            "data_dir":setup.data,
            "device_name":"Test iPhone",
            "role":"app",
            "request_history_enabled":false,
            "request_history_required":true
        })
        .to_string(),
    )
    .unwrap();
    call(&setup.core, json!({"op":"unlock", "passphrase":PASS}));
    call(&setup.core, json!({"op":"questions_list"}));
    for op in ["question_answer_string", "question_answer"] {
        assert_eq!(
            fails(
                &setup.core,
                json!({"op":op, "qid":QID, "kind":"never_for_agent", "time":now()})
            ),
            "history_storage_unavailable"
        );
    }
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"clear_request_history", "vault_id":vault_id})
        ),
        "history_storage_unavailable"
    );
    assert_eq!(setup.relay.answer_post_attempts(), 1);
    assert_eq!(
        std::fs::read(&journal_path).unwrap(),
        before,
        "bootstrap failure must preserve the encrypted guard"
    );
    restart(&mut setup, true);
    call(&setup.core, json!({"op":"questions_list"}));
    assert_eq!(
        entry(&history_entries(&setup), QID)["selected_kind"],
        "deny"
    );
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"question_answer_string", "qid":QID, "kind":"never_for_agent"})
        ),
        "already_answered"
    );
    assert_eq!(setup.relay.answer_post_attempts(), 1);
}
