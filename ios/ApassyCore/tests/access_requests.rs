//! Real JSON calls; local fake relay, synthetic keys, no Keychain or live service.
#[path = "common/questions_fixture.rs"]
mod questions_fixture;
#[path = "common/questions_relay.rs"]
mod questions_relay;
use apassy::questions::access_request as access;
use apassy::sync::{DeviceKey, decode_b64u, encode_b64u};
use questions_fixture::*;
use serde_json::{Value, json};

fn publish(s: &Setup) -> (String, access::Card, String) {
    attach(s);
    let vault = as_the_mac(s, |v| v.sync_identity().unwrap().vault_id);
    let mut c: access::Card = serde_json::from_str(include_str!(
        "../../../tests/fixtures/access-request-v1/card-body.json"
    ))
    .unwrap();
    c.vault_id = vault;
    c.asker.relay_device_id = 1;
    c.created_at = questions_relay::now();
    c.expires_at = c.created_at + 300;
    let body = serde_json::to_vec(&c).unwrap();
    let sig = s
        .mac_key
        .sign(&access::body_signature_message("card", &body).unwrap())
        .unwrap();
    let wrapper = access::SignedBody::new("card", &body, &sig).unwrap();
    post(
        &s.relay,
        &QUESTION_KEY,
        QID,
        &serde_json::to_string(&wrapper).unwrap(),
        c.expires_at,
    );
    let listed = call(&s.core, json!({"op":"access_requests_list"}));
    assert_eq!(listed["requests"].as_array().unwrap().len(), 1, "{listed}");
    (
        listed["requests"][0]["vault_id"].as_str().unwrap().into(),
        c,
        wrapper.digest,
    )
}
fn prepare(s: &Setup, vault: &str, digest: &str, kind: &str) -> Value {
    call(
        &s.core,
        json!({"op":"access_request_prepare","vault_id":vault,"qid":QID,"digest":digest,"kind":kind}),
    )
}
#[test]
fn typed_access_calls_use_mac_authenticity_and_choice_specific_keys() {
    for kind in ["deny", "allow_once"] {
        let s = setup_with_history(true);
        let (vault, c, digest) = publish(&s);
        assert!(call(&s.core, json!({"op":"questions_list"}))["questions"][0]["card"].is_null());
        let p = prepare(&s, &vault, &digest, kind);
        assert_eq!(p["needs_face_id"], kind == "allow_once");
        let mut send = json!({"op":"access_request_answer","vault_id":vault,"qid":QID,"digest":digest,"kind":kind,"time":p["time"]});
        if kind == "allow_once" {
            let key =
                DeviceKey::from_raw(&unhex(ANSWER_PRIVATE), &decode_b64u(ANSWER_PUBLIC).unwrap())
                    .unwrap();
            let bytes = decode_b64u(p["bytes"].as_str().unwrap()).unwrap();
            let wrong = DeviceKey::generate().unwrap();
            send["signature"] = json!(encode_b64u(&wrong.sign(&bytes).unwrap()));
            assert_eq!(fails(&s.core, send.clone()), "access_unavailable");
            assert!(s.relay.answers().is_empty());
            send["signature"] = json!(encode_b64u(&key.sign(&bytes).unwrap()));
        }
        assert_eq!(call(&s.core, send.clone())["sent"], true);
        assert_eq!(s.relay.answers().len(), 1);
        assert_eq!(fails(&s.core, send), "access_unavailable");
        let stored = &s.relay.answers()[0];
        let aad = aad(&["apassy-question-v1", "answer", TEAM, QID, KEY_ID, "2"]);
        let plaintext = open(&QUESTION_KEY, &aad, &stored.nonce, &stored.ciphertext).unwrap();
        let answer = access::Answer::parse(&plaintext).unwrap();
        assert_eq!(answer.request_id, c.request_id);
        assert_eq!(answer.kind.text(), kind);
    }
}
#[test]
fn wrong_vault_and_three_uncertain_posts_never_reset_with_history_clear() {
    let s = setup_with_history(true);
    let (vault, _c, digest) = publish(&s);
    assert!(!fails(&s.core,json!({"op":"access_request_prepare","vault_id":"f".repeat(32),"qid":QID,"digest":digest,"kind":"deny"})).is_empty());
    let p = prepare(&s, &vault, &digest, "deny");
    s.relay.lose_answer_replies(3);
    let send = json!({"op":"access_request_answer","vault_id":vault,"qid":QID,"digest":digest,"kind":"deny","time":p["time"]});
    for _ in 0..3 {
        assert_eq!(fails(&s.core, send.clone()), "relay_unreachable");
    }
    let _ = s
        .core
        .call(&json!({"op":"clear_request_history","vault_id":vault}).to_string());
    assert_eq!(fails(&s.core, send), "access_unavailable");
    assert_eq!(s.relay.answer_post_attempts(), 3);
}
#[test]
fn cancellation_and_guard_storage_failure_send_nothing() {
    let s = setup_with_history(true);
    let (vault, _c, digest) = publish(&s);
    let p = prepare(&s, &vault, &digest, "allow_once");
    call(&s.core, json!({"op":"access_request_cancel_prepared"}));
    assert_eq!(
        fails(
            &s.core,
            json!({"op":"access_request_answer","vault_id":vault,"qid":QID,"digest":digest,"kind":"allow_once","time":p["time"],"signature":""})
        ),
        "access_unavailable"
    );
    s.history_keys.set_unavailable(true);
    assert_eq!(
        fails(
            &s.core,
            json!({"op":"access_request_prepare","vault_id":vault,"qid":QID,"digest":digest,"kind":"deny"})
        ),
        "history_storage_unavailable"
    );
    assert!(s.relay.answers().is_empty());
}

#[test]
fn guard_survives_restart_and_history_opt_out() {
    let mut s = setup_with_history(true);
    let (vault, _, digest) = publish(&s);
    let p = prepare(&s, &vault, &digest, "deny");
    s.relay.lose_answer_replies(3);
    let send = json!({"op":"access_request_answer","vault_id":vault,"qid":QID,"digest":digest,"kind":"deny","time":p["time"]});
    for _ in 0..3 {
        assert_eq!(fails(&s.core, send.clone()), "relay_unreachable");
    }
    call(&s.core, json!({"op":"lock"}));
    s.core=apassy_core::Core::new_with_history_key_provider(&json!({"data_dir":s.data,"device_name":"Test iPhone","role":"app","request_history_enabled":false,"request_guard_storage_ready":true}).to_string(),s.history_keys.clone()).unwrap();
    call(&s.core, json!({"op":"unlock","passphrase":PASS}));
    assert_eq!(
        call(&s.core, json!({"op":"access_requests_history"}))["requests"],
        json!([])
    );
    call(&s.core, json!({"op":"access_requests_list"}));
    assert_eq!(
        fails(
            &s.core,
            json!({"op":"access_request_prepare","vault_id":vault,"qid":QID,"digest":digest,"kind":"deny"})
        ),
        "access_unavailable"
    );
    assert_eq!(s.relay.answer_post_attempts(), 3);
}
#[test]
fn only_a_mac_signed_access_receipt_confirms_historical_consent() {
    let s = setup_with_history(true);
    let (_, c, digest) = publish(&s);
    let aad = apassy::questions::envelope::settle_aad(TEAM, QID, KEY_ID);
    let (nonce, ciphertext) = seal(
        &QUESTION_KEY,
        &aad,
        br#"{"v":1,"outcome":"approved","at":1,"by":"phone"}"#,
    );
    s.relay.settle(QID, KEY_ID, &nonce, &ciphertext);
    let listed = call(&s.core, json!({"op":"access_requests_list"}));
    assert!(listed["requests"][0]["receipt"].is_null());
    let receipt = access::Receipt {
        vault_id: c.vault_id,
        team_id: c.team_id,
        qid: c.qid,
        request_id: c.request_id,
        asker: c.asker.device,
        digest,
        outcome: access::Outcome::AllowedOnce,
        answered_by: Some("6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b".into()),
        device_name: Some("Synthetic iPhone".into()),
        device_kind: Some(access::DeviceKind::Iphone),
        kind: Some(access::ReceiptChoice::AllowOnce),
        at: questions_relay::now(),
        expires_at: c.expires_at,
    };
    let body = serde_json::to_vec(&receipt).unwrap();
    let sig = s
        .mac_key
        .sign(&access::body_signature_message("settle", &body).unwrap())
        .unwrap();
    let wrapper = access::SignedBody::new("settle", &body, &sig).unwrap();
    let (nonce, ciphertext) = seal(&QUESTION_KEY, &aad, &serde_json::to_vec(&wrapper).unwrap());
    s.relay.settle(QID, KEY_ID, &nonce, &ciphertext);
    let listed = call(&s.core, json!({"op":"access_requests_list"}));
    assert_eq!(listed["requests"][0]["receipt"]["outcome"], "allowed_once");
    assert_eq!(listed["requests"][0]["state"], "settled");
    assert!(listed["requests"][0].get("permit").is_none());
}
#[test]
fn a_correct_mac_signature_cannot_transplant_another_vaults_card() {
    let s = setup_with_history(true);
    let (_, mut c, _) = publish(&s);
    c.vault_id = "11111111-1111-4111-8111-111111111111".into();
    let body = serde_json::to_vec(&c).unwrap();
    let sig = s
        .mac_key
        .sign(&access::body_signature_message("card", &body).unwrap())
        .unwrap();
    let w = access::SignedBody::new("card", &body, &sig).unwrap();
    post(
        &s.relay,
        &QUESTION_KEY,
        QID,
        &serde_json::to_string(&w).unwrap(),
        c.expires_at,
    );
    assert_eq!(
        call(&s.core, json!({"op":"access_requests_list"}))["requests"],
        json!([])
    );
}
