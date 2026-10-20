//! Questions through the relay on the iPhone (contract relay-questions-v1, ios-core-v1
//! section 5.10), through the JSON calls as the app makes them, against an in-process
//! fake of the relay's question routes. The asking Mac is played by the test: it seals
//! cards with the question key of the vault, and opens the iPhone's answers. The card,
//! the key, and the answer key are the synthetic values of the contract's test vectors.

#[path = "common/questions_relay.rs"]
mod questions_relay;

#[path = "common/questions_fixture.rs"]
mod questions_fixture;

use apassy::sync::{DeviceKey, decode_b64u, encode_b64u, verify_signature};
use apassy::vault::TrustedDeviceKind;
use questions_fixture::*;
use questions_relay::now;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

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

/// A removed iPhone has nothing to ask the relay, but `questions_wait` still waits out its
/// time, so the app that waits again never spins; a lock ends the wait at once.
#[test]
fn a_removed_iphone_waits_out_the_long_poll() {
    let setup = setup();
    let uuid = attach(&setup);
    as_the_mac(&setup, |vault| {
        vault.remove_trusted_device_and_rotate(&uuid).unwrap();
    });
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["removed"], true);
    let before = setup.relay.log().len();
    let start = Instant::now();
    let waited = call(&setup.core, json!({"op": "questions_wait", "timeout": 1}));
    assert_eq!(waited["changed"], false);
    assert!(
        start.elapsed() >= Duration::from_millis(900),
        "the wait returned at once: {:?}",
        start.elapsed()
    );
    assert_eq!(setup.relay.log().len(), before, "the relay was not asked");

    std::thread::scope(|scope| {
        let waiting = scope.spawn(|| {
            let start = Instant::now();
            let code = fails(&setup.core, json!({"op": "questions_wait", "timeout": 20}));
            (code, start.elapsed())
        });
        std::thread::sleep(Duration::from_millis(200));
        call(&setup.core, json!({"op": "lock"}));
        let (code, took) = waiting.join().unwrap();
        assert_eq!(code, "locked");
        assert!(
            took < Duration::from_secs(5),
            "the lock did not end the wait: {took:?}"
        );
    });
}

/// Removing a vault with a notifications-only team takes the push token of this iPhone
/// off its team, then leaves the team, while the relay key is still in memory.
#[test]
fn removing_a_vault_takes_its_push_token_and_its_device_off_the_team() {
    let setup = setup();
    attach(&setup);
    call(
        &setup.core,
        json!({"op": "push_token_set", "token": "0e".repeat(32), "environment": "development"}),
    );
    assert!(setup.relay.push_token().is_some());
    let id = call(&setup.core, json!({"op": "info"}))["selected"]
        .as_str()
        .unwrap()
        .to_owned();
    let removed = call(
        &setup.core,
        json!({"op": "remove_vault", "vault_id": id, "force": false}),
    );
    assert_eq!(removed["left_relay"], true);
    assert!(
        setup.relay.push_token().is_none(),
        "the token left the team"
    );
    let log = setup.relay.log();
    let token = log.iter().position(|line| line == "DELETE /v1/push/token");
    let device = log.iter().position(|line| line == "DELETE /v1/devices/2");
    assert!(
        token.is_some() && device.is_some() && token < device,
        "the token, then the device: {log:?}"
    );
    assert!(!setup.file.exists());
}

#[test]
fn request_history_says_off_for_an_open_vault_without_a_questions_team() {
    // The vault is unlocked but this iPhone is not attached: History must not call it locked.
    let setup = setup_with_history(true);
    let open = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(open["vaults"][0]["availability"], "off");
    assert_eq!(open["vaults"][0]["entries"], json!([]));
    call(&setup.core, json!({"op":"lock"}));
    let locked = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(locked["vaults"][0]["availability"], "locked");
}

#[test]
fn request_history_survives_restart_hides_on_lock_and_never_invents_a_settle() {
    let mut setup = setup_with_history(true);
    attach(&setup);
    post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    call(&setup.core, json!({"op":"questions_list"}));
    let history = call(&setup.core, json!({"op":"request_history"}));
    let vault_id = history["vaults"][0]["vault_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let journal_path = setup
        .data
        .join("request-history")
        .join(format!("{vault_id}.json"));
    assert_eq!(history["vaults"][0]["availability"], "available");
    assert_eq!(history["vaults"][0]["entries"].as_array().unwrap().len(), 1);
    let row = &history["vaults"][0]["entries"][0];
    assert_eq!(row["title"], "Shop database, API token");
    for forbidden in [
        "command",
        "cwd",
        "purpose",
        "risk",
        "user_request",
        "agent_request",
        "why",
        "env_names",
    ] {
        assert!(row.get(forbidden).is_none(), "{forbidden} was saved");
    }
    let on_disk = std::fs::read_to_string(&journal_path).unwrap();
    assert!(!on_disk.contains("Shop database"));
    assert!(!on_disk.contains("Apply the new migration"));
    let answer_time = now();
    call(
        &setup.core,
        json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":answer_time}),
    );
    let sent = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(sent["vaults"][0]["entries"][0]["selected_kind"], "deny");
    assert!(sent["vaults"][0]["entries"][0]["sent_at"].is_number());
    assert!(sent["vaults"][0]["entries"][0]["outcome"].is_null());
    call(&setup.core, json!({"op":"lock"}));
    let locked = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(locked["vaults"][0]["availability"], "locked");
    assert_eq!(locked["vaults"][0]["entries"], json!([]));
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"clear_request_history", "vault_id":vault_id})
        ),
        "locked"
    );
    setup.core = core_with_history(&setup.data, std::sync::Arc::clone(&setup.history_keys));
    call(&setup.core, json!({"op":"unlock", "passphrase":PASS}));
    let restarted = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(
        restarted["vaults"][0]["entries"][0]["selected_kind"],
        "deny"
    );
    let questions = call(&setup.core, json!({"op":"questions_list"}));
    assert_eq!(questions["questions"][0]["answered"], "deny");
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"question_answer_string", "qid":QID, "kind":"allow_production"})
        ),
        "already_answered"
    );
    // The exact signed-payload retry remains valid while its 55-second window is open.
    call(
        &setup.core,
        json!({"op":"question_answer", "qid":QID, "kind":"deny", "time":answer_time}),
    );
    let settle = json!({"v":1,"qid":QID,"outcome":"denied","device_name":"Test Mac","kind":"deny","at":now()}).to_string();
    let (nonce, ciphertext) = seal(
        &QUESTION_KEY,
        &aad(&["apassy-question-v1", "settle", TEAM, QID, KEY_ID]),
        settle.as_bytes(),
    );
    setup.relay.settle(QID, KEY_ID, &nonce, &ciphertext);
    call(&setup.core, json!({"op":"questions_list"}));
    let settled = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(settled["vaults"][0]["entries"][0]["outcome"], "denied");
    assert_eq!(
        settled["vaults"][0]["entries"][0]["confirmed_by"],
        "Test Mac"
    );
    let extension = core(&setup.data, "autofill");
    assert_eq!(
        fails(&extension, json!({"op":"request_history"})),
        "not_allowed"
    );
    assert_eq!(
        fails(
            &extension,
            json!({"op":"clear_request_history", "vault_id":vault_id})
        ),
        "not_allowed"
    );
    drop(extension);
    call(
        &setup.core,
        json!({"op":"remove_vault", "vault_id":vault_id, "force":true}),
    );
    assert!(!journal_path.exists());
}

#[test]
fn history_intent_survives_lock_during_post_and_removal_never_resurrects_it() {
    for remove in [false, true] {
        let setup = setup_with_history(true);
        attach(&setup);
        post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
        call(&setup.core, json!({"op":"questions_list"}));
        let history = call(&setup.core, json!({"op":"request_history"}));
        let vault_id = history["vaults"][0]["vault_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let journal = setup
            .data
            .join("request-history")
            .join(format!("{vault_id}.json"));
        setup.relay.hold_answer_replies(true);
        std::thread::scope(|scope| {
            let pending = scope.spawn(|| {
                setup.core.call(
                    &json!({"op":"question_answer", "qid":QID,"kind":"deny","time":now()})
                        .to_string(),
                )
            });
            setup.relay.wait_for_accepted_answer();
            let intent = call(&setup.core, json!({"op":"request_history"}));
            assert!(intent["vaults"][0]["entries"][0]["attempted_at"].is_number());
            assert!(intent["vaults"][0]["entries"][0]["sent_at"].is_null());
            if remove {
                call(
                    &setup.core,
                    json!({"op":"remove_vault", "vault_id":vault_id,"force":true}),
                );
            } else {
                call(&setup.core, json!({"op":"lock"}));
            }
            setup.relay.hold_answer_replies(false);
            // Closing transport can cancel the local result even after relay acceptance.
            let _: Value = serde_json::from_str(&pending.join().unwrap()).unwrap();
        });
        if remove {
            assert!(
                !journal.exists(),
                "late reply recreated a removed vault journal"
            );
        } else {
            call(&setup.core, json!({"op":"unlock", "passphrase":PASS}));
            let restored = call(&setup.core, json!({"op":"request_history"}));
            let row = &restored["vaults"][0]["entries"][0];
            assert!(row["attempted_at"].is_number());
            assert!(row["sent_at"].is_null());
            assert!(row["outcome"].is_null());
            let questions = call(&setup.core, json!({"op":"questions_list"}));
            assert_eq!(questions["questions"][0]["answered"], "deny");
            assert_eq!(
                fails(
                    &setup.core,
                    json!({"op":"question_answer_string","qid":QID,"kind":"allow_production"})
                ),
                "already_answered"
            );
        }
    }
}

#[test]
fn full_pending_history_refuses_post_without_evicting_an_authority_guard() {
    let setup = setup_with_history(true);
    attach(&setup);
    post(&setup.relay, &QUESTION_KEY, QID, CARD, now() + 300);
    call(&setup.core, json!({"op":"questions_list"}));
    let history = call(&setup.core, json!({"op":"request_history"}));
    let vault_id = history["vaults"][0]["vault_id"].as_str().unwrap();
    let file = setup
        .data
        .join("request-history")
        .join(format!("{vault_id}.json"));
    let sealed: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(sealed["version"], 2);
    let local_key = history_key(&setup, vault_id);
    let local_key_id = format!("local-{}", hex_key_id(local_key.as_slice()));
    assert_eq!(sealed["key_id"], local_key_id);
    let journal_aad = aad(&["apassy-local-request-history-v2", vault_id, &local_key_id]);
    let bytes = open(
        local_key.as_slice(),
        &journal_aad,
        sealed["nonce"].as_str().unwrap(),
        sealed["ciphertext"].as_str().unwrap(),
    )
    .unwrap();
    let journal: Value = serde_json::from_slice(&bytes).unwrap();
    let template = journal["entries"][0].clone();
    let at = now();
    let entries: Vec<Value> = (0..1000u128)
        .map(|index| {
            let mut entry = template.clone();
            let qid = encode_b64u(&index.to_be_bytes());
            entry["id"] = json!(format!("relay:{vault_id}:{qid}"));
            entry["qid"] = json!(qid);
            entry["selected_kind"] = json!("deny");
            entry["attempted_at"] = json!(at);
            entry["answer_time"] = json!(at);
            entry["expires_at"] = json!(at + 300);
            entry
        })
        .collect();
    let plaintext = serde_json::to_vec(&json!({"entries": entries})).unwrap();
    let (nonce, ciphertext) = seal(local_key.as_slice(), &journal_aad, &plaintext);
    std::fs::write(
        &file,
        serde_json::to_vec(
            &json!({"version":2,"key_id":local_key_id,"nonce":nonce,"ciphertext":ciphertext}),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        fails(
            &setup.core,
            json!({"op":"question_answer","qid":QID,"kind":"deny","time":at})
        ),
        "history_full"
    );
    assert!(
        setup.relay.answers().is_empty(),
        "POST reached relay without space for its durable guard"
    );
    let restored = call(&setup.core, json!({"op":"request_history"}));
    assert_eq!(
        restored["vaults"][0]["entries"].as_array().unwrap().len(),
        1000
    );
    assert!(
        restored["vaults"][0]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["attempted_at"].is_number())
    );
}
