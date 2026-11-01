#![cfg(feature = "vault")]

//! Questions through the relay (ADR 0025 §3e, contract relay-questions-v1). Synthetic
//! values only; no network beyond the in-process fake relay on 127.0.0.1.
//!
//! Mac A has the vault on the relay and asks: its approval queue, its owner gate, and its
//! questions waiter. Mac B joined the team and adopted the vault: it answers as a Mac
//! does, with its relay key after an owner check (the passphrase stands in for Touch ID
//! in a test). An "iPhone" joins the team with a link and signs with a P-256 answer key,
//! the key of the contract test vectors. Mac A also lists the questions of Mac B and
//! answers them from its own waiter, as Decisions does.

use crate::common::fake_relay;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{
    AnswerKind, ApprovalOutcome, ApprovalQueue, CheckMethod, OwnerCheck, OwnerGate, PendingRun,
    QuestionInfo, QuestionItem, QuestionRefusal, Settled, verify_remote_answer,
};
use apassy::broker::project::Project;
use apassy::companion::digest::{question_digest_v2_hex, run_digest_hex};
use apassy::contracts::CredentialKind;
use apassy::questions::envelope::{
    AnswerBody, Card, Choice, RemoteEnvironment, Sealed, SettleBody, answer_aad, answer_string,
    card_aad, settle_aad,
};
use apassy::questions::worker::ACTIVITY_OPERATION;
use apassy::questions::{
    AnswerError, OpenedQuestion, QuestionsClient, QuestionsConfig, QuestionsError, QuestionsWorker,
    Unreadable, answer_from_mac, open_question, open_settle, prepare_answer, remote_owner_action,
    send_answer,
};
use apassy::relay::membership::{
    QuestionsAvailability, adopt_questions_team, disable_questions, enable_questions,
    new_questions_team, questions_availability, questions_membership, questions_only,
};
use apassy::sync::{DeviceKey, PendingJoin, RelayConfig, RelaySync, decode_b64u, encode_b64u};
use apassy::vault::{
    Field, ItemDraft, QuestionKey, SecretValue, TrustedDevice, TrustedDeviceKind, Vault,
};
use fake_relay::FakeRelay;
use tempfile::TempDir;

const PASS: &str = "synthetic-question-pass";
const SHOP_SECRET: &str = "SYNTH-shop-database-secret";
const API_SECRET: &str = "SYNTH-api-token-secret";
const TEAM: &str = "t_7k2m5q4x3c";
const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
const PHONE_UUID: &str = "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const ASKER_UUID: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";
const ANSWER_PRIVATE: &str = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";

#[test]
fn access_cards_and_both_signed_choices_use_the_unchanged_fake_carrier() {
    use apassy::questions::access_request as access;
    for choice in [access::Choice::Deny, access::Choice::AllowOnce] {
        let w = world(true);
        let phone = w.iphone();
        let id = w.with_a(|v| {
            v.set_env_binding(w.items[1], "API_TOKEN", "token").unwrap();
            v.set_agent_sees_all(w.agent, true).unwrap();
            let agent = v
                .list_agents()
                .unwrap()
                .into_iter()
                .find(|a| a.id == w.agent)
                .unwrap();
            let response = apassy::broker::access_once::create(
                v,
                &agent,
                w.items[1],
                "Read synthetic status.",
                w._root.path().to_str(),
                &access::Scope {
                    action: access::Action::Read,
                    hosts: vec!["api.example.test".into()],
                },
            );
            assert!(response.ok, "{response:?}");
            response.result.unwrap()["request_id"].as_u64().unwrap()
        });
        let request = w.with_a(|v| v.scoped_access_request(id).unwrap());
        let start = Instant::now();
        let record = loop {
            if let Some(r) = phone
                .client
                .list(0, Duration::ZERO)
                .unwrap()
                .questions
                .into_iter()
                .find(|r| r.qid == request.card.card.qid)
            {
                break r;
            }
            assert!(start.elapsed() < Duration::from_secs(15));
            std::thread::sleep(Duration::from_millis(20));
        };
        let c = &request.card.card;
        let mac = phone
            .devices
            .iter()
            .find(|d| d.uuid == c.asker.device)
            .unwrap();
        let plaintext = record
            .card()
            .open(
                &phone.keys[0],
                &card_aad(
                    &w.team,
                    &record.qid,
                    &record.key_id,
                    "member",
                    record.expires_at,
                ),
            )
            .unwrap();
        let verified = access::verify_card(
            &plaintext,
            &mac.sign_key,
            &access::Context {
                vault_id: &c.vault_id,
                team_id: &w.team,
                qid: &record.qid,
                key_id: &record.key_id,
                asker: &mac.uuid,
                relay_device_id: record.from_device_id,
                expires_at: record.expires_at,
            },
            now(),
        )
        .unwrap();
        let mut answer = access::Answer::prepare(&verified, &phone.uuid, choice, now()).unwrap();
        let message = answer.message(&verified).unwrap();
        answer.signature = encode_b64u(&if choice == access::Choice::Deny {
            phone.client.sign(&message).unwrap()
        } else {
            answer_key().sign(&message).unwrap()
        });
        let bytes = serde_json::to_vec(&answer).unwrap();
        let sealed = Sealed::new(
            &phone.keys[0],
            &answer_aad(
                &w.team,
                &record.qid,
                &record.key_id,
                phone.client.device_id().unwrap(),
            ),
            &bytes,
        )
        .unwrap();
        phone.client.post_answer(&record.qid, &sealed).unwrap();
        // Appended duplicate copies can never install another permit.
        let _ = phone.client.post_answer(&record.qid, &sealed);
        let start = Instant::now();
        let receipt = loop {
            let state = w.with_a(|v| v.scoped_access_request(id).unwrap());
            if let Some(receipt) = state.receipt {
                break receipt;
            }
            assert!(start.elapsed() < Duration::from_secs(15));
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            receipt.outcome,
            if choice == access::Choice::Deny {
                access::Outcome::Denied
            } else {
                access::Outcome::AllowedOnce
            }
        );
        assert_eq!(receipt.answered_by.as_deref(), Some(phone.uuid.as_str()));
        assert_eq!(
            w.with_a(|v| v.access_status(w.agent, id).unwrap().permit),
            if choice == access::Choice::Deny {
                "unavailable"
            } else {
                "available"
            }
        );
        assert!(
            w.with_a(|v| v.exec_grants_for_agent(w.agent).unwrap())
                .is_empty()
        );
        assert!(w.with_a(|v| v.deny_access_request(id)).is_err());
    }
}

#[test]
fn two_iphones_and_local_denial_share_one_arbiter() {
    use apassy::questions::access_request as access;
    let w = world(true);
    let first = w.iphone();
    let second = w.iphone_named(
        "7f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
        "Second synthetic iPhone",
    );
    let id = w.with_a(|v| {
        v.set_env_binding(w.items[1], "API_TOKEN", "token").unwrap();
        v.set_agent_sees_all(w.agent, true).unwrap();
        let a = v
            .list_agents()
            .unwrap()
            .into_iter()
            .find(|a| a.id == w.agent)
            .unwrap();
        apassy::broker::access_once::create(
            v,
            &a,
            w.items[1],
            "Synthetic race",
            w._root.path().to_str(),
            &access::Scope {
                action: access::Action::Read,
                hosts: vec!["api.example.test".into()],
            },
        )
        .result
        .unwrap()["request_id"]
            .as_u64()
            .unwrap()
    });
    let proofs = w.with_a(|v| {
        let card = v.scoped_access_request(id).unwrap().card;
        [
            (&first, access::Choice::AllowOnce),
            (&second, access::Choice::Deny),
        ]
        .into_iter()
        .map(|(phone, choice)| {
            let mut answer = access::Answer::prepare(&card, &phone.uuid, choice, now()).unwrap();
            let bytes = answer.message(&card).unwrap();
            answer.signature = encode_b64u(&if choice == access::Choice::AllowOnce {
                answer_key().sign(&bytes).unwrap()
            } else {
                phone.client.sign(&bytes).unwrap()
            });
            apassy::broker::access_once::RemoteAccessAnswer::verify(
                v,
                id,
                answer,
                phone.client.device_id().unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
    });
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut tasks = Vec::new();
    for proof in proofs {
        let shared = w.shared_a.clone();
        let barrier = barrier.clone();
        tasks.push(std::thread::spawn(move || {
            barrier.wait();
            proof
                .commit(shared.lock().unwrap().as_mut().unwrap())
                .is_ok()
        }));
    }
    let shared = w.shared_a.clone();
    let wait = barrier.clone();
    tasks.push(std::thread::spawn(move || {
        wait.wait();
        shared
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .deny_access_request(id)
            .is_ok()
    }));
    assert_eq!(
        tasks
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    let r = w.with_a(|v| v.scoped_access_request(id).unwrap());
    assert!(r.receipt.is_some());
    assert!(
        w.with_a(|v| v.exec_grants_for_agent(w.agent).unwrap())
            .is_empty()
    );
}

#[test]
fn replaced_answer_key_invalidates_an_open_requests_prepared_remote_proof() {
    use apassy::questions::access_request as access;
    let w = world(true);
    let phone = w.iphone();
    w.with_a(|v| {
        v.set_env_binding(w.items[1], "API_TOKEN", "token").unwrap();
        v.set_agent_sees_all(w.agent, true).unwrap();
        let a = v
            .list_agents()
            .unwrap()
            .into_iter()
            .find(|a| a.id == w.agent)
            .unwrap();
        let id = apassy::broker::access_once::create(
            v,
            &a,
            w.items[1],
            "Synthetic rotation",
            w._root.path().to_str(),
            &access::Scope {
                action: access::Action::Read,
                hosts: vec!["api.example.test".into()],
            },
        )
        .result
        .unwrap()["request_id"]
            .as_u64()
            .unwrap();
        let r = v.scoped_access_request(id).unwrap();
        let mut answer =
            access::Answer::prepare(&r.card, &phone.uuid, access::Choice::AllowOnce, now())
                .unwrap();
        answer.signature = encode_b64u(
            &answer_key()
                .sign(&answer.message(&r.card).unwrap())
                .unwrap(),
        );
        let proof = apassy::broker::access_once::RemoteAccessAnswer::verify(
            v,
            id,
            answer,
            phone.client.device_id().unwrap(),
        )
        .unwrap();
        let old = v.trusted_device(&phone.uuid).unwrap().unwrap();
        let new = DeviceKey::generate().unwrap();
        v.register_trusted_device(
            &old.uuid,
            &old.name,
            old.kind,
            &old.sign_key,
            Some(new.public_key()),
        )
        .unwrap();
        assert!(proof.commit(v).is_err());
        assert_eq!(v.access_status(w.agent, id).unwrap().permit, "unavailable");
        assert!(v.scoped_access_request(id).unwrap().receipt.is_none());
    });
}

type SharedVault = Arc<Mutex<Option<Vault>>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn contract_key() -> QuestionKey {
    let mut bytes = [0u8; 32];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = at as u8;
    }
    QuestionKey::from_bytes(bytes)
}

fn answer_key() -> DeviceKey {
    DeviceKey::from_raw(
        &unhex(ANSWER_PRIVATE),
        &decode_b64u(ANSWER_PUBLIC).expect("public key"),
    )
    .expect("the answer key of the contract")
}

/// The run of section 7.1 of the contract, with items `ids`.
fn contract_run(id: u64, ids: [u64; 2], valid_answers: Vec<AnswerKind>) -> PendingRun {
    PendingRun {
        id,
        agent: "claude-code".to_owned(),
        command: vec!["npm".to_owned(), "run".to_owned(), "migrate".to_owned()],
        cwd: "/tmp/synthetic-shop".to_owned(),
        env_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
        purpose: "Apply the new migration.".to_owned(),
        risk: "production credential: always asks the owner".to_owned(),
        user_request: "Deploy the new schema to staging.".to_owned(),
        request_source: "from the host hook".to_owned(),
        agent_request: "Run the migration.".to_owned(),
        remember: None,
        question: QuestionInfo {
            id,
            item_ids: ids.to_vec(),
            project: Some(Project {
                key: "/tmp/synthetic-shop/.git".to_owned(),
                label: "synthetic-shop".to_owned(),
                root: PathBuf::from("/tmp/synthetic-shop"),
            }),
            action: ActionKind::Deploy,
            production: true,
            why: "A production credential goes to a deploy.".to_owned(),
            items: vec![
                QuestionItem {
                    item_id: ids[0],
                    name: "Shop database".to_owned(),
                    production: true,
                    unconfirmed: false,
                    always_ask: false,
                },
                QuestionItem {
                    item_id: ids[1],
                    name: "API token".to_owned(),
                    production: false,
                    unconfirmed: true,
                    always_ask: false,
                },
            ],
            valid_answers,
        },
    }
}

fn contract_answers() -> Vec<AnswerKind> {
    vec![
        AnswerKind::Once,
        AnswerKind::Production(ActionKind::Deploy),
        AnswerKind::CorrectEnvironment,
        AnswerKind::NeverForAgent,
        AnswerKind::AlwaysAskForAgent,
        AnswerKind::Disconnect,
    ]
}

// ---- The contract test vectors (section 20). ----

#[test]
fn the_contract_test_vectors_reproduce_exactly() {
    let key = contract_key();
    assert_eq!(key.key_id(), "630dcd2966c43366");
    let run = contract_run(123_456_789_012_345, [7, 9], contract_answers());
    let digest = question_digest_v2_hex(&run);
    assert_eq!(
        digest,
        "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"
    );
    let mut remembered = contract_run(123_456_789_012_345, [7, 9], vec![AnswerKind::Once]);
    remembered.remember = Some(apassy::broker::approvals::RememberOffer {
        pattern: "npm run migrate".to_owned(),
        approvals: 1,
        needed: 3,
    });
    remembered.question = QuestionInfo::default();
    assert_eq!(
        run_digest_hex(&remembered),
        "f9eaafb74648d988f9d086cd06f21f1f5f9a2429fa30e23ffa3a9d167dab4245"
    );
    assert_eq!(
        question_digest_v2_hex(&remembered),
        "0807a3e555dbde9f82b73ab8a6660911c1a28149eb1fe6382460166a798bf274"
    );

    // The card.
    let card = Card::from_run(QID, ASKER_UUID, "MacBook Pro", 1_790_000_000, &run);
    assert_eq!(card.digest, digest);
    let plaintext = card.to_plaintext().expect("card");
    assert_eq!(plaintext.len(), 1138);
    assert_eq!(
        hex(ring::digest::digest(&ring::digest::SHA256, &plaintext).as_ref()),
        "6b25b67d3570fe460fd30999abdd692269f46fd092f015846baafc2ba57c03dc"
    );
    let aad = card_aad(TEAM, QID, &key.key_id(), "member", 1_790_000_300);
    assert_eq!(
        hex(&aad),
        "6170617373792d7175657374696f6e2d7631006361726400745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636006d656d6265720031373930303030333030"
    );
    let card_nonce: [u8; 12] = std::array::from_fn(|at| at as u8);
    let sealed = Sealed::with_nonce(&key, &card_nonce, &aad, &plaintext);
    assert_eq!(sealed.nonce, "AAECAwQFBgcICQoL");
    let ciphertext = decode_b64u(&sealed.ciphertext).expect("b64u");
    assert_eq!(ciphertext.len(), 1154);
    assert_eq!(
        hex(ring::digest::digest(&ring::digest::SHA256, &ciphertext).as_ref()),
        "23bff23dc75b1d95e9e20a69e3b2fd622377422a0f781c749f0abec68c843d4f"
    );
    assert_eq!(
        hex(&ciphertext[ciphertext.len() - 16..]),
        "a64023ed808b856f3e612507ce64a66b"
    );
    assert_eq!(
        sealed.open(&key, &aad).expect("opens").as_slice(),
        plaintext.as_slice()
    );
    let parsed = Card::parse(&plaintext).expect("parse");
    assert_eq!(parsed, card);
    assert_eq!(parsed.to_run().expect("run"), {
        let mut back = run.clone();
        back.question.project.as_mut().unwrap().root = PathBuf::from(&run.cwd);
        back
    });
    // The card does not open with another routing bit, expiry, qid, team, key, or part.
    for other in [
        card_aad(TEAM, QID, &key.key_id(), "approvers", 1_790_000_300),
        card_aad(TEAM, QID, &key.key_id(), "member", 1_790_000_301),
        card_aad(
            TEAM,
            "oKGio6SlpqeoqaqrrK2urA",
            &key.key_id(),
            "member",
            1_790_000_300,
        ),
        card_aad("t_0000000000", QID, &key.key_id(), "member", 1_790_000_300),
        card_aad(TEAM, QID, "0000000000000000", "member", 1_790_000_300),
        answer_aad(TEAM, QID, &key.key_id(), 3),
        settle_aad(TEAM, QID, &key.key_id()),
    ] {
        assert!(sealed.open(&key, &other).is_none());
    }

    // The answer.
    let choice = Choice::AllowProduction {
        action: ActionKind::Deploy,
        project_key: "/tmp/synthetic-shop/.git".to_owned(),
    };
    let text = answer_string(PHONE_UUID, TEAM, QID, &choice, &digest, 1_790_000_030).expect("text");
    assert_eq!(
        text,
        "apassy-question-answer-v1\n6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b\nt_7k2m5q4x3c\noKGio6SlpqeoqaqrrK2urw\nallow_production:deploy:/tmp/synthetic-shop/.git\nf3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d\n1790000030"
    );
    assert_eq!(
        hex(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref()),
        "92988898270a1b99cbe4550c67ba69f8a5d3c872bc9f9b41341cb19d2eaab270"
    );
    let signature_b64u = "MEQCIGMC9y1cqvAp-20KSFEKld0OxGzAAChwzuk1koc-mdXRAiAU9SNPzZkCVoP16J25cR9fHwzNI7JcENt9p-SIAsvETA";
    let signature = decode_b64u(signature_b64u).expect("signature");
    let public = decode_b64u(ANSWER_PUBLIC).expect("public");
    let verifies = |message: &[u8], signature: &[u8], key: &[u8]| {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, key)
            .verify(message, signature)
            .is_ok()
    };
    assert!(verifies(text.as_bytes(), &signature, &public));
    let mut changed = text.clone().into_bytes();
    changed[30] ^= 1;
    assert!(!verifies(&changed, &signature, &public));
    let fresh = answer_key().sign(text.as_bytes()).expect("sign");
    assert_ne!(fresh, signature, "a new signature differs");
    assert!(verifies(text.as_bytes(), &fresh, &public));
    // The companion request key of companion-v1 is another key.
    let other = DeviceKey::generate().expect("key");
    assert!(!verifies(text.as_bytes(), &signature, other.public_key()));

    let body = AnswerBody::new(QID, PHONE_UUID, &choice, &digest, 1_790_000_030, &signature);
    let answer = body.to_plaintext().expect("answer");
    assert_eq!(
        String::from_utf8(answer.to_vec()).unwrap(),
        format!(
            r#"{{"v":1,"qid":"{QID}","by":"{PHONE_UUID}","kind":"allow_production","action":"deploy","project_key":"/tmp/synthetic-shop/.git","digest":"{digest}","time":1790000030,"signature":"{signature_b64u}"}}"#
        )
    );
    assert_eq!(answer.len(), 370);
    let aad = answer_aad(TEAM, QID, &key.key_id(), 3);
    assert_eq!(
        hex(&aad),
        "6170617373792d7175657374696f6e2d763100616e7377657200745f376b326d357134783363006f4b47696f36536c7071656f71617172724b3275727700363330646364323936366334333336360033"
    );
    let answer_nonce: [u8; 12] = std::array::from_fn(|at| 0x10 + at as u8);
    let sealed = Sealed::with_nonce(&key, &answer_nonce, &aad, &answer);
    assert_eq!(sealed.nonce, "EBESExQVFhcYGRob");
    assert_eq!(
        hex(&decode_b64u(&sealed.ciphertext).unwrap()),
        "25e833253c28ea4b6aaf5741e389da3e3d0f9a1fd7aea605e7fcc66c9dced1adcefff20efba899be0cb7c1ceb3cb32bf206d626c9953465defbab3b89e8d1ff8327cf7ec21c7ec2787484140c0b291f117db2557de3967a5f61be0d5bcf26128d2d20e2eda7de6910266abba48c80fb399588f148fb234ca61707674c2ca04549304e6b80a7a418b40b0a3e798143e954cf74dafda3441b8e0a99ded218ce4f533dcfdffac93b4114b8dd6b5a4bffeb094da742ad1e5e6a8821c796b3c594c23683028ef1c55d1b464cce313780013a5fecc377db92cc3bfcd5469686e75b04a01e226f674b06b3e519ad72f975b5aee88e3e4a8c5e8d3edca1a4b57c3d1627e17b8a7630579bf1b458e7660749530e2b713d036f4b7b363d0935a5b115481975d54a9351cda0cba86e3d202a94a984f4dd2bedf7d690c38ed4a3c058e95c8456e92c408d061d0062ede9e7299e4a0e157b9fc13d09fd25e76bfa0b456b99d17885a8f5d6583b02cbe06327ca1eb93ab08de920c3f69fd1aa8d635952bfa3b561c30"
    );
    assert_eq!(AnswerBody::parse(&answer), Some(body.clone()));
    assert_eq!(Choice::from_body(&body), Some(choice.clone()));
    assert!(
        sealed
            .open(&key, &answer_aad(TEAM, QID, &key.key_id(), 2))
            .is_none(),
        "the answer does not open with the device id 2"
    );

    // The settle.
    let settle = SettleBody {
        v: 1,
        qid: QID.to_owned(),
        outcome: "approved".to_owned(),
        answered_by: Some(PHONE_UUID.to_owned()),
        device_name: Some("Test iPhone".to_owned()),
        device_kind: Some("iphone".to_owned()),
        kind: Some("allow_production".to_owned()),
        at: 1_790_000_031,
        replaced_by: None,
    };
    let plaintext = settle.to_plaintext().expect("settle");
    assert_eq!(plaintext.len(), 205);
    let aad = settle_aad(TEAM, QID, &key.key_id());
    assert_eq!(
        hex(&aad),
        "6170617373792d7175657374696f6e2d763100736574746c6500745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636"
    );
    let settle_nonce: [u8; 12] = std::array::from_fn(|at| 0x20 + at as u8);
    let sealed = Sealed::with_nonce(&key, &settle_nonce, &aad, &plaintext);
    assert_eq!(sealed.nonce, "ICEiIyQlJicoKSor");
    assert_eq!(
        hex(&decode_b64u(&sealed.ciphertext).unwrap()),
        "08c5fe5e2bded018eaacc9ea731de0f33c0711044305ef3ce38e4cc5cdc9a95931c2f021ee37f50891bb8e780d94417ae76d1515fc3c76f7ca24e0c3472df717faea79cbe8b60ad589fe1467835b1e42cf7dad045cca0dc97bf303a57429ee4bc00a4175fd49e86be86a99b517e0fba583d6af00b7fc7d6a983f524c793c91a2f1a27695d2a61fb5a3dfb82ba1b0cc87f5cb65f8b240c5048e9db9946699d9cf33b2e300c919917c85e02c39b7da8a4cbd1d46065030eb6a8df582bea0f277bfec618de93fe7d74fd233a2f8646fb5f066a9390178f5251b3cc003cfec"
    );
    assert_eq!(SettleBody::parse(&plaintext), Some(settle));
    assert!(
        sealed
            .open(
                &key,
                &card_aad(TEAM, QID, &key.key_id(), "member", 1_790_000_300)
            )
            .is_none(),
        "the settle does not open as a card"
    );
}

/// Section 20.5: the asker accepts the answer of the vector from 1790000030 to
/// 1790000090 and refuses it after, with another digest, with a choice that the question
/// does not offer, and from a device whose answer key is another key.
#[test]
fn the_asker_takes_the_vector_answer_only_in_its_window() {
    let run = contract_run(123_456_789_012_345, [7, 9], contract_answers());
    let digest = question_digest_v2_hex(&run);
    let choice = Choice::AllowProduction {
        action: ActionKind::Deploy,
        project_key: "/tmp/synthetic-shop/.git".to_owned(),
    };
    let signature = decode_b64u(
        "MEQCIGMC9y1cqvAp-20KSFEKld0OxGzAAChwzuk1koc-mdXRAiAU9SNPzZkCVoP16J25cR9fHwzNI7JcENt9p-SIAsvETA",
    )
    .unwrap();
    let phone = TrustedDevice {
        uuid: PHONE_UUID.to_owned(),
        name: "Test iPhone".to_owned(),
        kind: TrustedDeviceKind::Iphone,
        relay_devices: [(TEAM.to_owned(), 3)].into(),
        sign_key: DeviceKey::generate().unwrap().public_key().to_vec(),
        answer_key: Some(decode_b64u(ANSWER_PUBLIC).unwrap()),
        created_at: 1,
        updated_at: 1,
        updated_by: String::new(),
    };
    assert!(choice.valid_for(&run.question));
    for clock in [1_790_000_030, 1_790_000_060, 1_790_000_090] {
        assert_eq!(
            verify_remote_answer(
                &phone,
                TEAM,
                QID,
                &choice,
                &digest,
                1_790_000_030,
                &signature,
                clock
            ),
            Ok(()),
            "{clock}"
        );
    }
    let check = |device: &TrustedDevice, choice: &Choice, digest: &str, clock| {
        verify_remote_answer(
            device,
            TEAM,
            QID,
            choice,
            digest,
            1_790_000_030,
            &signature,
            clock,
        )
    };
    assert_eq!(
        check(&phone, &choice, &digest, 1_790_000_091),
        Err(apassy::broker::approvals::OwnerAuthError::RemoteStale)
    );
    // The run changed: another digest.
    let mut changed = run.clone();
    changed.question.why = "Another reason.".to_owned();
    let other_digest = question_digest_v2_hex(&changed);
    assert_ne!(other_digest, digest, "changed");
    assert!(check(&phone, &choice, &other_digest, 1_790_000_030).is_err());
    // Not in valid_answers.
    let in_project = Choice::ApproveInProject {
        action: ActionKind::Deploy,
        project_key: "/tmp/synthetic-shop/.git".to_owned(),
    };
    assert!(!in_project.valid_for(&run.question));
    assert!(check(&phone, &in_project, &digest, 1_790_000_030).is_err());
    // Another answer key, or the relay key of the iPhone for an approval.
    let other = TrustedDevice {
        answer_key: Some(DeviceKey::generate().unwrap().public_key().to_vec()),
        ..phone.clone()
    };
    assert!(check(&other, &choice, &digest, 1_790_000_030).is_err());
    let swapped = TrustedDevice {
        sign_key: decode_b64u(ANSWER_PUBLIC).unwrap(),
        answer_key: Some(other.answer_key.clone().unwrap()),
        ..phone
    };
    assert!(
        check(&swapped, &choice, &digest, 1_790_000_030).is_err(),
        "a signature by the other key of the device is invalid"
    );
}

// ---- Two Macs and an iPhone with the fake relay. ----

struct Mac {
    data: PathBuf,
    vault_path: PathBuf,
    sync: RelaySync,
}

fn mac(root: &TempDir, name: &str, url: &str) -> Mac {
    let data = root.path().join(name).join("Apassy");
    fs::create_dir_all(&data).expect("data dir");
    let vault_path = data.join("vault.db");
    Mac {
        sync: RelaySync::new(RelayConfig::in_data_dir(&data, &vault_path, url, "vault")),
        data,
        vault_path,
    }
}

fn secret_item(title: &str, token: &str) -> ItemDraft {
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

struct World {
    _root: TempDir,
    relay: FakeRelay,
    a: Mac,
    b: Mac,
    shared_a: SharedVault,
    shared_b: SharedVault,
    queue: Arc<ApprovalQueue>,
    worker: QuestionsWorker,
    team: String,
    agent: u64,
    items: [u64; 2],
}

/// Mac A with the vault on the relay and Mac B that adopted it; with `enable`, both turn
/// the questions on and sync, so each has the question key and the row of the other.
/// Mac A runs its questions waiter.
fn world(enable: bool) -> World {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let a = mac(&root, "a", &relay.url);
    let b = mac(&root, "b", &relay.url);
    let mut vault_a = Vault::create(&a.vault_path, PASS).expect("create");
    vault_a.unlock(PASS).expect("unlock");
    let shop = vault_a
        .add(secret_item("Shop database", SHOP_SECRET))
        .expect("add")
        .id;
    let api = vault_a
        .add(secret_item("API token", API_SECRET))
        .expect("add")
        .id;
    let agent = vault_a.register_agent("claude-code").expect("agent").0.id;
    let report = a
        .sync
        .create_team(
            &mut vault_a,
            "Personal",
            &relay.team_code(),
            "Synthetic MacBook",
        )
        .expect("create team");
    let team = report.link.team_id.clone();
    let code = a.sync.create_link(&vault_a).expect("link");
    let pending = PendingJoin::request(&code.link, "", "Synthetic Mac mini").expect("request");
    let links = a.sync.pending_links(&vault_a, Some(&code)).expect("links");
    a.sync.confirm_link(&vault_a, &links[0]).expect("confirm");
    let joined = pending.poll().expect("poll").expect("confirmed");
    let download = joined.download(&b.data.join("sync")).expect("download");
    let (mut vault_b, _) = b.sync.adopt(&joined, &download, PASS).expect("adopt");
    vault_b.unlock(PASS).expect("unlock");
    if enable {
        enable_questions(&mut vault_a, "Synthetic MacBook").expect("on for A");
        a.sync.sync(&mut vault_a).expect("push A");
        b.sync.sync(&mut vault_b).expect("pull on B");
        enable_questions(&mut vault_b, "Synthetic Mac mini").expect("on for B");
        b.sync.sync(&mut vault_b).expect("push B");
        a.sync.sync(&mut vault_a).expect("pull on A");
        assert_eq!(vault_a.trusted_devices().unwrap().len(), 2);
        assert_eq!(vault_b.trusted_devices().unwrap().len(), 2);
        assert_eq!(
            vault_a.question_key().unwrap().unwrap().key_id(),
            vault_b.question_key().unwrap().unwrap().key_id(),
            "one key through the sync"
        );
    }
    let shared_a: SharedVault = Arc::new(Mutex::new(Some(vault_a)));
    let shared_b: SharedVault = Arc::new(Mutex::new(Some(vault_b)));
    let queue = Arc::new(ApprovalQueue::new());
    let worker = QuestionsWorker::start(
        Arc::clone(&queue),
        Arc::clone(&shared_a),
        OwnerGate::new(Arc::clone(&shared_a), None),
        QuestionsConfig {
            question_wait: Duration::from_secs(300),
            tick: Duration::from_millis(50),
            device_name: "Synthetic MacBook".to_owned(),
            ..QuestionsConfig::default()
        },
    );
    World {
        _root: root,
        relay,
        a,
        b,
        shared_a,
        shared_b,
        queue,
        worker,
        team,
        agent,
        items: [shop, api],
    }
}

impl World {
    fn run(&self, valid_answers: Vec<AnswerKind>) -> PendingRun {
        contract_run(0, self.items, valid_answers)
    }

    /// A run of agent `claude-code` waits on Mac A for `timeout`.
    fn ask(
        &self,
        run: PendingRun,
        timeout: Duration,
    ) -> JoinHandle<Result<Settled, QuestionRefusal>> {
        let epoch = self.shared_a.lock().unwrap().as_ref().unwrap().epoch();
        let queue = Arc::clone(&self.queue);
        let agent = self.agent;
        std::thread::spawn(move || {
            queue.wait_for_question(run, agent, epoch, [0; 32], timeout, || true)
        })
    }

    fn with_a<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.shared_a.lock().unwrap().as_mut().unwrap())
    }

    fn with_b<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.shared_b.lock().unwrap().as_mut().unwrap())
    }

    /// Mac B as an answering device.
    fn mac_b(&self) -> Answerer {
        self.with_b(|vault| {
            let membership = questions_membership(vault).unwrap().expect("membership");
            let me = vault
                .trusted_devices()
                .unwrap()
                .into_iter()
                .find(|device| device.sign_key == membership.public_key)
                .expect("B is registered");
            Answerer {
                client: QuestionsClient::from_membership(&membership).expect("client"),
                keys: vec![vault.question_key().unwrap().unwrap()],
                devices: vault.trusted_devices().unwrap(),
                uuid: me.uuid,
                team: membership.team_id,
            }
        })
    }

    /// An iPhone that joins the team with a link, registered in vault A as if its own
    /// row came through the sync: its relay key signs the stricter answers, the answer key
    /// of the contract the approving ones.
    fn iphone(&self) -> Answerer {
        self.iphone_named(PHONE_UUID, "Test iPhone")
    }

    fn iphone_named(&self, uuid: &str, name: &str) -> Answerer {
        let key = DeviceKey::generate().expect("key");
        let public = key.public_key().to_vec();
        let joined = {
            let guard = self.shared_a.lock().unwrap();
            let vault = guard.as_ref().unwrap();
            let code = self.a.sync.create_link(vault).expect("link");
            let pending = PendingJoin::request_with_key(&code.link, "", name, key).expect("join");
            let links = self
                .a
                .sync
                .pending_links(vault, Some(&code))
                .expect("links");
            self.a.sync.confirm_link(vault, &links[0]).expect("confirm");
            pending.poll().expect("poll").expect("confirmed")
        };
        let device_id = joined.device_id();
        self.with_a(|vault| {
            vault
                .register_trusted_device(
                    uuid,
                    name,
                    TrustedDeviceKind::Iphone,
                    &public,
                    Some(&decode_b64u(ANSWER_PUBLIC).unwrap()),
                )
                .expect("register");
            vault
                .set_trusted_device_relay_id(uuid, &self.team, device_id)
                .expect("relay id");
        });
        let (keys, devices) = self.with_a(|vault| {
            (
                vec![vault.question_key().unwrap().unwrap()],
                vault.trusted_devices().unwrap(),
            )
        });
        Answerer {
            // The device of the join, with its key in memory (`JoinedDevice::member`).
            client: QuestionsClient::from_member(joined.member()),
            keys,
            devices,
            uuid: uuid.to_owned(),
            team: self.team.clone(),
        }
    }

    /// The Activity lines of the answers that did not count, newest first.
    fn refused_lines(&self) -> Vec<String> {
        self.with_a(|vault| {
            vault
                .recent_activity(100)
                .unwrap()
                .into_iter()
                .filter(|row| row.operation == ACTIVITY_OPERATION)
                .map(|row| row.reason)
                .collect()
        })
    }

    /// The view of the waiter once `count` answers took effect.
    fn wait_answered(&self, count: usize) -> apassy::questions::QuestionsView {
        let start = Instant::now();
        loop {
            let view = self.worker.view();
            if view.answered.len() >= count {
                return view;
            }
            assert!(start.elapsed() < Duration::from_secs(20), "{view:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_refused(&self, count: usize) -> Vec<String> {
        let start = Instant::now();
        loop {
            let lines = self.refused_lines();
            if lines.len() >= count {
                return lines;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "{count} lines, got {lines:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Mac B proves the owner for an approving answer: the passphrase in a test, Touch ID
    /// in the app.
    fn proof_b(
        &self,
        opened: &OpenedQuestion,
        choice: &Choice,
    ) -> (apassy::broker::approvals::OwnerProof, [u8; 32]) {
        let action = remote_owner_action(opened, choice).expect("approving");
        let gate = OwnerGate::new(Arc::clone(&self.shared_b), None);
        let proof = gate
            .authorize(action, OwnerCheck::passphrase(PASS))
            .expect("owner check on B");
        let epoch = self.with_b(|vault| vault.epoch());
        (proof, epoch)
    }
}

struct Answerer {
    client: QuestionsClient,
    keys: Vec<QuestionKey>,
    devices: Vec<TrustedDevice>,
    uuid: String,
    team: String,
}

impl Answerer {
    /// The next open question that is not in `seen`, opened and checked.
    fn next(&self, seen: &[String]) -> OpenedQuestion {
        let start = Instant::now();
        loop {
            let list = self.client.list(0, Duration::from_secs(2)).expect("list");
            if let Some(record) = list
                .questions
                .iter()
                .find(|record| record.state == "open" && !seen.contains(&record.qid))
            {
                return open_question(record, &self.team, &self.keys, &self.devices, now())
                    .expect("the card opens");
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "no question came"
            );
        }
    }

    /// Seal and post an answer with what the caller chose: the digest, the team in the
    /// signed text and in the AAD, and the signature.
    #[allow(clippy::too_many_arguments)]
    fn raw(
        &self,
        opened: &OpenedQuestion,
        choice: &Choice,
        digest: &str,
        signed_team: &str,
        sealed_team: &str,
        time: u64,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Result<apassy::questions::AnswerReceipt, QuestionsError> {
        let qid = &opened.record.qid;
        let text = answer_string(&self.uuid, signed_team, qid, choice, digest, time).unwrap();
        let signature = sign(text.as_bytes());
        let body = AnswerBody::new(qid, &self.uuid, choice, digest, time, &signature);
        let key = &self.keys[0];
        let device_id = self.client.device_id().expect("device id");
        let sealed = Sealed::new(
            key,
            &answer_aad(sealed_team, qid, &key.key_id(), device_id),
            &body.to_plaintext().unwrap(),
        )
        .unwrap();
        self.client.post_answer(qid, &sealed)
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.client.sign(message).expect("sign")
    }
}

fn settled(handle: JoinHandle<Result<Settled, QuestionRefusal>>) -> Settled {
    handle
        .join()
        .expect("join")
        .expect("the call got the answer")
}

#[test]
fn questions_through_the_relay_are_off_by_default() {
    let world = world(false);
    world.with_a(|vault| {
        assert!(questions_membership(vault).unwrap().is_none());
        assert_eq!(
            questions_availability(vault).unwrap(),
            QuestionsAvailability::CanTurnOn {
                team_id: world.team.clone()
            }
        );
        assert!(vault.question_key().unwrap().is_none());
        assert!(vault.trusted_devices().unwrap().is_empty());
    });
    let waiting = world.ask(world.run(vec![AnswerKind::Once]), Duration::from_secs(1));
    let ended = settled(waiting);
    assert_eq!(ended.outcome, ApprovalOutcome::TimedOut);
    assert_eq!(
        world.relay.questions_posted(),
        0,
        "nothing went to the relay"
    );
    assert!(!world.worker.view().on);
    world.with_a(|vault| assert!(vault.question_key().unwrap().is_none()));
}

/// Mac A asks, Mac B answers "Allow once" after its owner check, and the run goes on with
/// a remote check. B reads the settle; a replay is refused by the relay, and the same
/// envelope in a new question does not open and is logged.
#[test]
fn two_macs_round_trip() {
    let world = world(true);
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let b = world.mac_b();
    let opened = b.next(&[]);
    assert_eq!(opened.card.asker.name, "Synthetic MacBook");
    assert_eq!(opened.card.run.agent, "claude-code");
    assert_eq!(opened.record.to, "member");
    let choice = Choice::ApproveOnce;
    // Without the owner check the Mac sends no approving answer.
    let epoch = world.with_b(|vault| vault.epoch());
    assert_eq!(
        answer_from_mac(
            &b.client,
            &opened,
            &b.uuid,
            choice.clone(),
            now(),
            &b.keys,
            None,
            &epoch
        )
        .unwrap_err(),
        AnswerError::NeedsOwnerCheck
    );
    let (proof, epoch) = world.proof_b(&opened, &choice);
    answer_from_mac(
        &b.client,
        &opened,
        &b.uuid,
        choice.clone(),
        now(),
        &b.keys,
        Some(proof),
        &epoch,
    )
    .expect("sent");
    let ended = settled(waiting);
    assert_eq!(ended.outcome, ApprovalOutcome::Approved);
    assert_eq!(ended.method, Some(CheckMethod::Remote));

    // The settle says who answered.
    let start = Instant::now();
    let record = loop {
        let list = b.client.list(0, Duration::ZERO).unwrap();
        if let Some(record) = list
            .questions
            .into_iter()
            .find(|record| record.qid == opened.record.qid && record.state == "settled")
        {
            break record;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "no settle");
        std::thread::sleep(Duration::from_millis(50));
    };
    let settle = open_settle(&record, &b.team, &b.keys).expect("settle opens");
    assert_eq!(settle.outcome, "approved");
    assert_eq!(settle.answered_by.as_deref(), Some(b.uuid.as_str()));
    assert_eq!(settle.device_name.as_deref(), Some("Synthetic Mac mini"));
    assert_eq!(settle.device_kind.as_deref(), Some("mac"));
    assert_eq!(settle.kind.as_deref(), Some("approve_once"));
    let view = world.wait_answered(1);
    assert_eq!(
        view.answered.last().unwrap().line(),
        "Answered on Synthetic Mac mini"
    );

    // A late answer: "Already answered".
    let late = prepare_answer(&opened, &b.uuid, Choice::Deny, now()).unwrap();
    let signature = b.sign(late.text.as_bytes());
    assert_eq!(
        send_answer(&b.client, &opened, &late, &signature, &b.keys).unwrap_err(),
        AnswerError::AlreadyAnswered
    );

    // The same answer envelope replayed into a new question does not open there.
    let replay_text = answer_string(
        &b.uuid,
        &b.team,
        &opened.record.qid,
        &choice,
        &opened.card.digest,
        now(),
    )
    .unwrap();
    let replay_body = AnswerBody::new(
        &opened.record.qid,
        &b.uuid,
        &choice,
        &opened.card.digest,
        now(),
        &b.sign(replay_text.as_bytes()),
    );
    let replay = Sealed::new(
        &b.keys[0],
        &answer_aad(
            &b.team,
            &opened.record.qid,
            &b.keys[0].key_id(),
            b.client.device_id().unwrap(),
        ),
        &replay_body.to_plaintext().unwrap(),
    )
    .unwrap();
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let second = b.next(std::slice::from_ref(&opened.record.qid));
    b.client
        .post_answer(&second.record.qid, &replay)
        .expect("the relay takes it");
    let lines = world.wait_refused(1);
    assert!(
        lines[0].starts_with("An answer from device ") && lines[0].contains("could not be read"),
        "{lines:?}"
    );
    // The question still waits; a deny ends it.
    let deny = prepare_answer(&second, &b.uuid, Choice::Deny, now()).unwrap();
    send_answer(
        &b.client,
        &second,
        &deny,
        &b.sign(deny.text.as_bytes()),
        &b.keys,
    )
    .unwrap();
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
}

/// An iPhone signs an approval with its answer key; the same approval signed with its
/// relay key does not count.
#[test]
fn an_iphone_approves_with_its_answer_key() {
    let world = world(true);
    let phone = world.iphone();
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let opened = phone.next(&[]);
    let choice = Choice::AllowProduction {
        action: ActionKind::Deploy,
        project_key: "/tmp/synthetic-shop/.git".to_owned(),
    };
    // The relay key of the iPhone is not its answer key.
    let wrong = prepare_answer(&opened, PHONE_UUID, choice.clone(), now()).unwrap();
    send_answer(
        &phone.client,
        &opened,
        &wrong,
        &phone.sign(wrong.text.as_bytes()),
        &phone.keys,
    )
    .expect("the relay takes it");
    let lines = world.wait_refused(1);
    assert_eq!(
        lines[0],
        "An answer from Test iPhone did not count: its signature does not verify."
    );
    let good = prepare_answer(&opened, PHONE_UUID, choice, now()).unwrap();
    let signature = answer_key().sign(good.text.as_bytes()).unwrap();
    send_answer(&phone.client, &opened, &good, &signature, &phone.keys).expect("sent");
    let ended = settled(waiting);
    assert_eq!(ended.outcome, ApprovalOutcome::Approved);
    assert_eq!(ended.method, Some(CheckMethod::Remote));
    let answer = ended.answer.expect("a production allowance to remember");
    assert!(answer.production);
    assert_eq!(answer.action, ActionKind::Deploy);
    let view = world.wait_answered(1);
    let last = view.answered.last().expect("answered");
    assert_eq!(last.device_name, "Test iPhone");
    assert_eq!(last.device_kind, TrustedDeviceKind::Iphone);
    assert_eq!(last.kind, "allow_production");
}

/// An invalid signature, an answer that the question does not offer, a stale digest,
/// another team, and an old answer are refused, each with an Activity line without
/// values; a valid stricter answer then ends the question. A device has at most 3
/// answers to a question on the relay, so three devices answer.
#[test]
fn invalid_answers_are_refused_and_logged() {
    let world = world(true);
    let phone = world.iphone();
    let other = world.iphone_named("2a7d9c41-8e3b-4f6a-9d2c-1b0e5f4a3c2d", "Old iPhone");
    let waiting = world.ask(
        world.run(vec![AnswerKind::Once, AnswerKind::NeverForAgent]),
        Duration::from_secs(60),
    );
    let b = world.mac_b();
    let opened = b.next(&[]);
    let digest = opened.card.digest.clone();
    let deny = Choice::Deny;
    // 1. A signature that does not verify.
    b.raw(&opened, &deny, &digest, &b.team, &b.team, now(), |_| {
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
    })
    .unwrap();
    world.wait_refused(1);
    // 2. Not offered: the question has no "Allow production".
    let production = Choice::AllowProduction {
        action: ActionKind::Deploy,
        project_key: "/tmp/synthetic-shop/.git".to_owned(),
    };
    assert_eq!(
        prepare_answer(&opened, &b.uuid, production.clone(), now()).unwrap_err(),
        AnswerError::NotOffered
    );
    b.raw(
        &opened,
        &production,
        &digest,
        &b.team,
        &b.team,
        now(),
        |m| b.sign(m),
    )
    .unwrap();
    world.wait_refused(2);
    // 3. A stale digest: the request changed.
    let stale = "0".repeat(64);
    b.raw(&opened, &deny, &stale, &b.team, &b.team, now(), |m| {
        b.sign(m)
    })
    .unwrap();
    world.wait_refused(3);
    // A fourth answer of the same device: the relay refuses it.
    assert_eq!(
        b.raw(&opened, &deny, &digest, &b.team, &b.team, now(), |m| b
            .sign(m))
            .unwrap_err()
            .code(),
        Some("too_many_answers")
    );
    // 4. Another team: in the AAD, then in the signed text.
    let opened_phone = phone.next(&[]);
    phone
        .raw(
            &opened_phone,
            &deny,
            &digest,
            &b.team,
            "t_0000000000",
            now(),
            |m| phone.sign(m),
        )
        .unwrap();
    world.wait_refused(4);
    phone
        .raw(
            &opened_phone,
            &deny,
            &digest,
            "t_0000000000",
            &b.team,
            now(),
            |m| phone.sign(m),
        )
        .unwrap();
    world.wait_refused(5);
    // 5. Too old.
    let opened_other = other.next(&[]);
    other
        .raw(
            &opened_other,
            &deny,
            &digest,
            &b.team,
            &b.team,
            now() - 120,
            |m| other.sign(m),
        )
        .unwrap();
    let lines = world.wait_refused(6);
    assert!(world.queue.pending().len() == 1, "the run still waits");
    let mut reasons: Vec<&str> = lines
        .iter()
        .map(|line| line.split(" did not count: ").nth(1).unwrap_or(line))
        .collect();
    reasons.sort_unstable();
    assert_eq!(
        reasons,
        [
            "it could not be read.",
            "its signature does not verify.",
            "its signature does not verify.",
            "the answer is too old.",
            "the question does not offer this answer.",
            "the request changed.",
        ],
        "{lines:?}"
    );
    for line in &lines {
        for value in [
            SHOP_SECRET,
            API_SECRET,
            "npm run",
            "Shop database",
            "DATABASE_URL",
        ] {
            assert!(!line.contains(value), "{line}");
        }
    }
    // A valid stricter answer, signed with the relay key without an owner check.
    let never = prepare_answer(&opened_phone, PHONE_UUID, Choice::NeverForAgent, now()).unwrap();
    send_answer(
        &phone.client,
        &opened_phone,
        &never,
        &phone.sign(never.text.as_bytes()),
        &phone.keys,
    )
    .unwrap();
    let ended = settled(waiting);
    assert_eq!(ended.outcome, ApprovalOutcome::Denied);
    assert_eq!(ended.method, None);
    let view = world.wait_answered(1);
    assert_eq!(view.answered[0].kind, "never_for_agent");
    assert_eq!(view.refused.len(), 6);
}

/// Two valid answers arrive before the asker reads them: the first one counts, and the
/// second finds the question settled.
#[test]
fn the_first_valid_answer_wins() {
    let world = world(true);
    world
        .relay
        .delay("GET /v1/questions/", Duration::from_millis(2500));
    let phone = world.iphone();
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let b = world.mac_b();
    let opened = b.next(&[]);
    let deny = prepare_answer(&opened, &b.uuid, Choice::Deny, now()).unwrap();
    send_answer(
        &b.client,
        &opened,
        &deny,
        &b.sign(deny.text.as_bytes()),
        &b.keys,
    )
    .unwrap();
    let opened_phone = phone.next(&[]);
    let approve = prepare_answer(&opened_phone, PHONE_UUID, Choice::ApproveOnce, now()).unwrap();
    let signature = answer_key().sign(approve.text.as_bytes()).unwrap();
    send_answer(
        &phone.client,
        &opened_phone,
        &approve,
        &signature,
        &phone.keys,
    )
    .expect("both answers are on the relay");
    assert_eq!(world.relay.answer_count(&opened.record.qid), 2);
    let ended = settled(waiting);
    assert_eq!(
        ended.outcome,
        ApprovalOutcome::Denied,
        "the first answer counts"
    );
    let view = world.wait_answered(1);
    assert_eq!(view.answered.len(), 1);
    assert_eq!(view.answered[0].device_name, "Synthetic Mac mini");
    assert!(
        world.refused_lines().is_empty(),
        "the second is not refused"
    );
}

/// A question ends with its wait: the settle says so and a late answer is "Already
/// answered". A question that expired on the relay refuses answers as "Expired".
#[test]
fn a_question_expires_with_its_wait() {
    let world = world(true);
    let b = world.mac_b();
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(3));
    let opened = b.next(&[]);
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::TimedOut);
    let start = Instant::now();
    while world.relay.question_state(&opened.record.qid).as_deref() != Some("settled") {
        assert!(start.elapsed() < Duration::from_secs(10), "no settle");
        std::thread::sleep(Duration::from_millis(50));
    }
    let record = b
        .client
        .list(0, Duration::ZERO)
        .unwrap()
        .questions
        .into_iter()
        .find(|record| record.qid == opened.record.qid)
        .unwrap();
    let settle = open_settle(&record, &b.team, &b.keys).unwrap();
    assert_eq!(settle.outcome, "timed_out");
    assert_eq!(settle.answered_by, None);
    let late = prepare_answer(&opened, &b.uuid, Choice::Deny, now()).unwrap();
    assert_eq!(
        send_answer(
            &b.client,
            &opened,
            &late,
            &b.sign(late.text.as_bytes()),
            &b.keys
        )
        .unwrap_err(),
        AnswerError::AlreadyAnswered
    );

    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(4));
    let opened = b.next(std::slice::from_ref(&opened.record.qid));
    world.relay.expire_questions();
    let late = prepare_answer(&opened, &b.uuid, Choice::Deny, now()).unwrap();
    assert_eq!(
        send_answer(
            &b.client,
            &opened,
            &late,
            &b.sign(late.text.as_bytes()),
            &b.keys
        )
        .unwrap_err(),
        AnswerError::Expired
    );
    let record = b
        .client
        .list(0, Duration::ZERO)
        .unwrap()
        .questions
        .into_iter()
        .find(|record| record.qid == opened.record.qid)
        .unwrap();
    assert_eq!(record.state, "expired");
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::TimedOut);
}

/// Removing a device writes a new question key: the next question uses it, and a device
/// with the old key only cannot read it. A question posted before keeps its key, so its
/// answers still open. The removed device's answers do not count.
#[test]
fn removing_a_device_rotates_the_question_key() {
    let world = world(true);
    let phone = world.iphone();
    let old_key = world.with_a(|vault| vault.question_key().unwrap().unwrap().key_id());
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let b = world.mac_b();
    let first = b.next(&[]);
    assert_eq!(first.record.key_id, old_key);
    let phone_first = phone.next(&[]);
    // The owner removes the iPhone on Mac A.
    assert!(world.with_a(|vault| vault.remove_trusted_device_and_rotate(PHONE_UUID).unwrap()));
    let new_key = world.with_a(|vault| vault.question_key().unwrap().unwrap().key_id());
    assert_ne!(new_key, old_key);
    // The removed iPhone's approval does not count.
    let approve = prepare_answer(&phone_first, PHONE_UUID, Choice::ApproveOnce, now()).unwrap();
    let signature = answer_key().sign(approve.text.as_bytes()).unwrap();
    send_answer(
        &phone.client,
        &phone_first,
        &approve,
        &signature,
        &phone.keys,
    )
    .unwrap();
    let lines = world.wait_refused(1);
    assert!(
        lines[0].contains("the device is not a device of this vault"),
        "{lines:?}"
    );
    // The open question keeps its key: B answers it with the old key.
    let deny = prepare_answer(&first, &b.uuid, Choice::Deny, now()).unwrap();
    send_answer(
        &b.client,
        &first,
        &deny,
        &b.sign(deny.text.as_bytes()),
        &b.keys,
    )
    .unwrap();
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);

    // The next question uses the new key. A device with the old key only cannot read it.
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let record = {
        let start = Instant::now();
        loop {
            let list = phone.client.list(0, Duration::from_secs(1)).unwrap();
            if let Some(record) = list
                .questions
                .into_iter()
                .find(|record| record.state == "open" && record.qid != first.record.qid)
            {
                break record;
            }
            assert!(start.elapsed() < Duration::from_secs(20));
        }
    };
    assert_eq!(record.key_id, new_key);
    assert_eq!(
        open_question(&record, &phone.team, &phone.keys, &phone.devices, now()).unwrap_err(),
        Unreadable::NoKey
    );
    // B gets the new key through the sync, then reads and answers.
    world
        .a
        .sync
        .sync_shared(&world.shared_a, |_| true)
        .expect("push the new key");
    world
        .b
        .sync
        .sync_shared(&world.shared_b, |_| true)
        .expect("pull the new key");
    let b = world.mac_b();
    assert_eq!(b.keys[0].key_id(), new_key);
    let opened = open_question(&record, &b.team, &b.keys, &b.devices, now()).expect("opens");
    let deny = prepare_answer(&opened, &b.uuid, Choice::Deny, now()).unwrap();
    send_answer(
        &b.client,
        &opened,
        &deny,
        &b.sign(deny.text.as_bytes()),
        &b.keys,
    )
    .unwrap();
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
}

/// The relay never gets a command, a credential name, a variable, or a secret value:
/// every JSON body of a whole round trip, sync included, is free of them.
#[test]
fn no_request_body_holds_a_command_an_item_name_or_a_secret() {
    let world = world(true);
    let phone = world.iphone();
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let b = world.mac_b();
    let opened = b.next(&[]);
    // A correction and an answer from each device.
    let correct = prepare_answer(
        &opened,
        &b.uuid,
        Choice::CorrectEnvironment {
            item_id: world.items[1],
            environment: RemoteEnvironment::Production,
        },
        now(),
    )
    .unwrap();
    send_answer(
        &b.client,
        &opened,
        &correct,
        &b.sign(correct.text.as_bytes()),
        &b.keys,
    )
    .unwrap();
    let opened_phone = phone.next(&[]);
    let approve = prepare_answer(&opened_phone, PHONE_UUID, Choice::ApproveOnce, now()).unwrap();
    let signature = answer_key().sign(approve.text.as_bytes()).unwrap();
    send_answer(
        &phone.client,
        &opened_phone,
        &approve,
        &signature,
        &phone.keys,
    )
    .unwrap();
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Approved);
    let bodies: Vec<String> = world
        .relay
        .request_bodies()
        .into_iter()
        .filter(|body| body.starts_with('{'))
        .collect();
    assert!(
        bodies.iter().any(|body| body.contains("\"ciphertext\"")),
        "the questions went through the relay"
    );
    let forbidden = [
        "npm",
        "migrate",
        "synthetic-shop",
        "Shop database",
        "API token",
        "DATABASE_URL",
        "API_TOKEN",
        "claude-code",
        "production credential",
        SHOP_SECRET,
        API_SECRET,
        "SYNTH-",
    ];
    for body in &bodies {
        // A random nonce, key, or signature can hold a short word such as "npm" by
        // chance. The words are looked for in the body without those values.
        let plain = without_random_values(body);
        for word in forbidden {
            assert!(!plain.contains(word), "{word} in {body}");
        }
        // Nor the secret values as b64u.
        for word in [SHOP_SECRET, API_SECRET] {
            assert!(
                !body.contains(&encode_b64u(word.as_bytes())),
                "{word} in {body}"
            );
        }
    }
    let keys: BTreeSet<String> = bodies
        .iter()
        .filter_map(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .filter_map(|value| {
            value
                .as_object()
                .map(|map| map.keys().cloned().collect::<Vec<_>>())
        })
        .flatten()
        .collect();
    assert!(keys.contains("ciphertext") && keys.contains("key_id"));
}

// ---- The questions of the other Macs on this Mac (section 13). ----

/// Post as B without starting another lister: every questions GET belongs to A.
fn post_question_from_b(world: &World) -> apassy::questions::client::Posted {
    let b = world.mac_b();
    let key = &b.keys[0];
    let created_at = now();
    let expires_at = created_at + 300;
    let card = Card::from_run(
        QID,
        &b.uuid,
        "Synthetic Mac mini",
        created_at,
        &world.run(contract_answers()),
    );
    let sealed = Sealed::new(
        key,
        &card_aad(&world.team, QID, &key.key_id(), "member", expires_at),
        &card.to_plaintext().expect("card"),
    )
    .expect("seal");
    b.client
        .post_question(QID, "member", expires_at, &sealed)
        .expect("B posts its question")
}

/// Two new polls prove a response after the preceding relay operation was consumed.
/// The fake relay logs paths without their query strings; only A runs a lister.
fn wait_for_receiver_polls(world: &World) {
    let polls = world.relay.count("GET /v1/questions");
    let started = Instant::now();
    while world.relay.count("GET /v1/questions") < polls + 2 {
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "A did not consume the relay response: {:?}",
            world.worker.view()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_receiver_view(
    world: &World,
    ready: impl Fn(&apassy::questions::QuestionsView) -> bool,
) -> apassy::questions::QuestionsView {
    let started = Instant::now();
    loop {
        let view = world.worker.view();
        if ready(&view) {
            return view;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "A did not reach the expected receiver state: {view:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn sync_b_to_a(world: &World) {
    world
        .b
        .sync
        .sync_shared(&world.shared_b, |_| true)
        .expect("push B's changes");
    world
        .a
        .sync
        .sync_shared(&world.shared_a, |_| true)
        .expect("pull B's changes on A");
}

fn assert_original_remote_question(world: &World, posted: &apassy::questions::client::Posted) {
    let view = wait_for_receiver_view(world, |view| {
        view.receive_problem.is_none()
            && view
                .remote
                .iter()
                .any(|question| question.question.record.qid == QID)
    });
    let remote = view
        .remote
        .iter()
        .find(|question| question.question.record.qid == QID)
        .unwrap();
    assert_eq!(remote.question.record.seq, posted.seq, "the original card");
    assert_eq!(remote.asker(), "Synthetic Mac mini");
    assert_eq!(
        world
            .worker
            .answering(remote.id)
            .expect("readable question")
            .send(Choice::ApproveOnce, None)
            .unwrap_err(),
        AnswerError::NeedsOwnerCheck,
        "retrying a card never authorizes an approval"
    );
    assert_eq!(world.relay.answer_count(QID), 0);
    assert_eq!(world.relay.questions_posted(), 1, "B never reposted");
    assert_eq!(world.relay.question_state(QID).as_deref(), Some("open"));
}

/// A question received before its rotated key has synced must become readable after
/// the key arrives, without another relay event, vault lock, or worker restart.
#[test]
fn an_unreadable_remote_question_reappears_after_its_key_syncs() {
    let world = world(true);
    world.relay.answer_polls_at_once(true);
    let epoch = world.with_a(|vault| vault.epoch());
    let old_key = world.with_a(|vault| vault.question_key().unwrap().unwrap().key_id());
    let new_key = world.with_b(|vault| vault.rotate_question_key().expect("rotate on B"));
    assert_ne!(new_key.key_id(), old_key);
    let posted = post_question_from_b(&world);
    wait_for_receiver_polls(&world);
    assert_eq!(
        world.with_a(|vault| vault.question_key().unwrap().unwrap().key_id()),
        old_key,
        "A still has the old key when it consumes the card"
    );
    assert!(world.worker.view().remote.is_empty());
    assert!(world.worker.view().receive_problem.is_some());

    sync_b_to_a(&world);
    world.with_a(|vault| {
        assert!(!vault.is_locked());
        assert_eq!(vault.epoch(), epoch, "sync preserves A's unlocked session");
        assert_eq!(
            vault.question_key().unwrap().unwrap().key_id(),
            new_key.key_id()
        );
    });
    assert_original_remote_question(&world, &posted);
}

/// The question key alone is insufficient: an unseen asking device is retried after
/// its trusted row arrives through ordinary vault sync in the same unlocked session.
#[test]
fn an_unreadable_remote_question_reappears_after_its_asker_syncs() {
    let world = world(false);
    world.relay.answer_polls_at_once(true);
    world.with_a(|vault| enable_questions(vault, "Synthetic MacBook").expect("on for A"));
    world
        .a
        .sync
        .sync_shared(&world.shared_a, |_| true)
        .expect("push A");
    world
        .b
        .sync
        .sync_shared(&world.shared_b, |_| true)
        .expect("pull A on B");
    world.with_b(|vault| enable_questions(vault, "Synthetic Mac mini").expect("on for B"));
    let b = world.mac_b();
    let epoch = world.with_a(|vault| {
        assert_eq!(
            vault.question_key().unwrap().unwrap().key_id(),
            b.keys[0].key_id()
        );
        assert!(
            !vault
                .trusted_devices()
                .unwrap()
                .iter()
                .any(|device| device.uuid == b.uuid)
        );
        vault.epoch()
    });
    let posted = post_question_from_b(&world);
    wait_for_receiver_polls(&world);
    assert!(world.worker.view().remote.is_empty());
    assert!(world.worker.view().receive_problem.is_some());

    sync_b_to_a(&world);
    world.with_a(|vault| {
        assert!(!vault.is_locked());
        assert_eq!(vault.epoch(), epoch);
        assert!(
            vault
                .trusted_devices()
                .unwrap()
                .iter()
                .any(|device| device.uuid == b.uuid)
        );
    });
    assert_original_remote_question(&world, &posted);
}

fn settle_question_from_b(world: &World) {
    let b = world.mac_b();
    let key = &b.keys[0];
    let body = SettleBody {
        v: 1,
        qid: QID.to_owned(),
        outcome: "denied".to_owned(),
        answered_by: None,
        device_name: None,
        device_kind: None,
        kind: None,
        at: now(),
        replaced_by: None,
    };
    let sealed = Sealed::new(
        key,
        &settle_aad(&world.team, QID, &key.key_id()),
        &body.to_plaintext().expect("settle body"),
    )
    .expect("sealed settle");
    b.client
        .settle(QID, &sealed)
        .expect("B settles its question");
}

/// A terminal relay record discards the unreadable cache entry before its key arrives.
#[test]
fn a_settled_unreadable_remote_question_never_reappears_after_key_sync() {
    let world = world(true);
    world.relay.answer_polls_at_once(true);
    world.with_b(|vault| vault.rotate_question_key().expect("rotate on B"));
    post_question_from_b(&world);
    wait_for_receiver_polls(&world);
    assert!(world.worker.view().receive_problem.is_some());
    settle_question_from_b(&world);
    wait_for_receiver_polls(&world);
    let view = world.worker.view();
    assert!(
        view.receive_problem.is_none(),
        "terminal records clear the warning"
    );
    assert!(view.remote.is_empty());

    sync_b_to_a(&world);
    wait_for_receiver_polls(&world);
    let view = world.worker.view();
    assert!(
        view.remote.is_empty(),
        "settled pending card must not resurrect"
    );
    assert!(view.receive_problem.is_none());
    assert_eq!(world.relay.question_state(QID).as_deref(), Some("settled"));
    assert_eq!(world.relay.questions_posted(), 1);
    assert_eq!(world.relay.answer_count(QID), 0);
}

/// Lock removes pending receiver state and its message. A terminal change while the
/// vault is locked must not leave an old card to reappear after unlocking and syncing.
#[test]
fn locking_clears_an_unreadable_remote_question_and_its_problem() {
    let world = world(true);
    world.relay.answer_polls_at_once(true);
    world.with_b(|vault| vault.rotate_question_key().expect("rotate on B"));
    post_question_from_b(&world);
    wait_for_receiver_polls(&world);
    assert!(world.worker.view().receive_problem.is_some());
    world.with_a(|vault| vault.lock().expect("lock A"));
    world.worker.forget();
    let view = wait_for_receiver_view(&world, |view| !view.on && view.receive_problem.is_none());
    assert!(view.remote.is_empty());
    settle_question_from_b(&world);
    world.with_a(|vault| vault.unlock(PASS).expect("unlock A"));
    sync_b_to_a(&world);
    wait_for_receiver_polls(&world);
    let view = world.worker.view();
    assert!(
        view.remote.is_empty(),
        "locked pending card must not resurrect"
    );
    assert!(view.receive_problem.is_none());
    assert_eq!(world.relay.question_state(QID).as_deref(), Some("settled"));
    assert_eq!(world.relay.answer_count(QID), 0);
}

/// Mac B asks with its own waiter; Mac A lists the question of B, "from" B, and answers
/// it from its Decisions with its relay key: "Allow once" only with a fresh owner check
/// of Mac A (`OwnerAction::AnswerRemoteQuestion`), and the run on B goes on with a
/// remote check. A stricter answer of A needs no check. Then the question leaves the
/// list of A.
#[test]
fn a_question_of_mac_b_shows_on_mac_a_and_its_answers_reach_b() {
    let world = world(true);
    let queue_b = Arc::new(ApprovalQueue::new());
    let _worker_b = QuestionsWorker::start(
        Arc::clone(&queue_b),
        Arc::clone(&world.shared_b),
        OwnerGate::new(Arc::clone(&world.shared_b), None),
        QuestionsConfig {
            question_wait: Duration::from_secs(300),
            tick: Duration::from_millis(50),
            device_name: "Synthetic Mac mini".to_owned(),
            ..QuestionsConfig::default()
        },
    );
    let agent_b = world.with_b(|vault| vault.register_agent("claude-code").expect("agent").0.id);
    let ask_b = |run: PendingRun| {
        let epoch = world.with_b(|vault| vault.epoch());
        let queue = Arc::clone(&queue_b);
        std::thread::spawn(move || {
            queue.wait_for_question(
                run,
                agent_b,
                epoch,
                [0; 32],
                Duration::from_secs(60),
                || true,
            )
        })
    };
    let wait_remote = |count: usize| {
        let start = Instant::now();
        loop {
            let view = world.worker.view();
            if view.remote.len() == count {
                return view.remote;
            }
            assert!(start.elapsed() < Duration::from_secs(20), "{view:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    };

    let waiting = ask_b(world.run(contract_answers()));
    let remote = wait_remote(1).remove(0);
    assert_eq!(remote.asker(), "Synthetic Mac mini");
    assert_eq!(remote.question.run.agent, "claude-code");
    assert_eq!(remote.question.record.to, "member");
    assert!(remote.sent.is_none());
    assert_eq!(world.relay.questions_posted(), 1, "only B asked");

    // Without the owner check of Mac A, no approving answer goes.
    let answering = world.worker.answering(remote.id).expect("answering");
    assert_eq!(
        answering.send(Choice::ApproveOnce, None).unwrap_err(),
        AnswerError::NeedsOwnerCheck
    );
    // A proof for another answer does not count either.
    let gate_a = OwnerGate::new(Arc::clone(&world.shared_a), None);
    let never = gate_a
        .authorize(
            remote_owner_action(answering.question(), &Choice::ApproveOnce)
                .map(|action| match action {
                    apassy::broker::approvals::OwnerAction::AnswerRemoteQuestion {
                        asker,
                        answer,
                        ..
                    } => apassy::broker::approvals::OwnerAction::AnswerRemoteQuestion {
                        qid: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                        asker,
                        answer,
                    },
                    other => other,
                })
                .expect("approving"),
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    assert_eq!(
        answering
            .send(Choice::ApproveOnce, Some(never))
            .unwrap_err(),
        AnswerError::NeedsOwnerCheck
    );
    let proof = gate_a
        .authorize(
            remote_owner_action(answering.question(), &Choice::ApproveOnce).expect("approving"),
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check on A");
    answering
        .send(Choice::ApproveOnce, Some(proof))
        .expect("sent");
    let ended = settled(waiting);
    assert_eq!(ended.outcome, ApprovalOutcome::Approved, "B goes on");
    assert_eq!(ended.method, Some(CheckMethod::Remote));
    // The settle takes it from the list of A.
    wait_remote(0);

    // A stricter answer from A: no owner check.
    let waiting = ask_b(world.run(contract_answers()));
    let remote = wait_remote(1).remove(0);
    world
        .worker
        .answering(remote.id)
        .expect("answering")
        .send(Choice::NeverForAgent, None)
        .expect("sent without a check");
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
    wait_remote(0);
    assert_eq!(
        world.worker.answering(remote.id).unwrap_err(),
        AnswerError::Gone,
        "an answered question is gone"
    );
}

/// A vault that syncs another way gets a notifications-only team: a membership for the
/// questions only, the question key, and this Mac as a trusted device, with no snapshot
/// on the relay. Off removes that membership; relay sync was never on.
#[test]
fn a_notifications_only_team_carries_the_questions_and_goes_with_off() {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let mut vault = Vault::create(&root.path().join("icloud.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    assert_eq!(
        questions_availability(&vault).unwrap(),
        QuestionsAvailability::NeedsTeam
    );
    let membership = new_questions_team(
        &relay.url,
        &relay.team_code(),
        "Personal",
        "Synthetic MacBook",
    )
    .expect("team");
    assert!(questions_only(&membership));
    let device = adopt_questions_team(&mut vault, &membership, "Synthetic MacBook").expect("adopt");
    assert_eq!(device.kind, TrustedDeviceKind::Mac);
    assert_eq!(device.sign_key, membership.public_key);
    assert!(vault.question_key().unwrap().is_some());
    assert!(vault.relay_device().unwrap().is_none(), "no relay sync");
    assert_eq!(
        questions_availability(&vault).unwrap(),
        QuestionsAvailability::On {
            team_id: membership.team_id.clone()
        }
    );
    assert!(matches!(
        adopt_questions_team(&mut vault, &membership, "Synthetic MacBook"),
        Err(apassy::sync::SyncError::AlreadyEnabled)
    ));
    // A wrong team code makes no team.
    assert!(new_questions_team(&relay.url, "apassy_tcd_wrong", "Personal", "Mac").is_err());
    assert!(disable_questions(&mut vault).unwrap());
    assert!(questions_membership(&vault).unwrap().is_none());
    assert!(
        vault.relay_memberships().unwrap().is_empty(),
        "the key goes"
    );
}

// ---- Gate 3: removal, replays, binding, a second Mac, an old relay. ----

/// Mac B as the judge probed it: the owner removes B on Mac A, the vault syncs, and B
/// tries to register again. The vault refuses its key, B's waiter writes no row and says
/// that B was removed, and after the next syncs Mac A still has no live row of B.
#[test]
fn a_removed_mac_does_not_register_again() {
    let world = world(true);
    let (b_uuid, b_key) = world.with_b(|vault| {
        let membership = questions_membership(vault).unwrap().unwrap();
        let me = vault
            .trusted_devices()
            .unwrap()
            .into_iter()
            .find(|device| device.sign_key == membership.public_key)
            .unwrap();
        (me.uuid, membership.public_key)
    });
    assert!(world.with_a(|vault| vault.remove_trusted_device_and_rotate(&b_uuid).unwrap()));
    world
        .a
        .sync
        .sync_shared(&world.shared_a, |_| true)
        .expect("push A");
    world
        .b
        .sync
        .sync_shared(&world.shared_b, |_| true)
        .expect("pull on B");
    world.with_b(|vault| {
        assert!(vault.trusted_device(&b_uuid).unwrap().is_none());
        assert!(vault.trusted_key_removed(&b_key).unwrap());
        assert_eq!(
            questions_availability(vault).unwrap(),
            QuestionsAvailability::Removed {
                team_id: world.team.clone(),
                sync: true
            }
        );
        // Turning the questions on again with the same key is refused, and so is any
        // registration of the key under a new UUID.
        assert!(matches!(
            enable_questions(vault, "Synthetic Mac mini"),
            Err(apassy::sync::SyncError::Vault(
                apassy::vault::VaultErrorKind::AlreadyExists
            ))
        ));
        assert_eq!(
            vault
                .register_trusted_device(
                    "3c1f4b2a-6d5e-4f70-8a9b-0c1d2e3f4a5b",
                    "Synthetic Mac mini",
                    TrustedDeviceKind::Mac,
                    &b_key,
                    None,
                )
                .unwrap_err()
                .kind(),
            apassy::vault::VaultErrorKind::AlreadyExists
        );
    });
    // B's waiter runs: it says that B was removed and writes nothing.
    let queue_b = Arc::new(ApprovalQueue::new());
    let worker_b = QuestionsWorker::start(
        Arc::clone(&queue_b),
        Arc::clone(&world.shared_b),
        OwnerGate::new(Arc::clone(&world.shared_b), None),
        QuestionsConfig {
            question_wait: Duration::from_secs(300),
            tick: Duration::from_millis(20),
            device_name: "Synthetic Mac mini".to_owned(),
            ..QuestionsConfig::default()
        },
    );
    let start = Instant::now();
    loop {
        let view = worker_b.view();
        if view.removed {
            assert!(!view.on);
            assert_eq!(
                view.problem.as_deref(),
                Some(apassy::questions::worker::REMOVED)
            );
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{view:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(worker_b);
    world
        .b
        .sync
        .sync_shared(&world.shared_b, |_| true)
        .expect("push B");
    world
        .a
        .sync
        .sync_shared(&world.shared_a, |_| true)
        .expect("pull on A");
    let live_b = world.with_a(|vault| {
        vault
            .trusted_devices()
            .unwrap()
            .into_iter()
            .filter(|device| device.sign_key == b_key)
            .count()
    });
    assert_eq!(live_b, 0, "Mac A has no live row of B");
}

/// "Remove" revokes the device on the relay too: its calls fail from then on.
#[test]
fn a_removed_device_is_revoked_on_the_relay() {
    let world = world(true);
    let phone = world.iphone();
    let (membership, phone_id) = world.with_a(|vault| {
        let membership = questions_membership(vault).unwrap().unwrap();
        let id = vault
            .trusted_device(PHONE_UUID)
            .unwrap()
            .unwrap()
            .relay_devices[&world.team];
        assert!(vault.remove_trusted_device_and_rotate(PHONE_UUID).unwrap());
        (membership, id)
    });
    assert!(phone.client.list(0, Duration::ZERO).is_ok());
    QuestionsClient::from_membership(&membership)
        .unwrap()
        .remove_device(phone_id)
        .expect("revoked");
    assert!(!world.relay.devices().contains(&phone_id));
    assert!(matches!(
        phone.client.list(0, Duration::ZERO),
        Err(QuestionsError::Removed)
    ));
}

/// The asking Mac's settled environment of `item`, as the declaration says.
fn environment_of(world: &World, item: u64) -> Option<apassy::vault::Environment> {
    world.with_a(|vault| {
        vault
            .declaration(item)
            .unwrap()
            .map(|declaration| declaration.environment)
    })
}

fn wait_environment(world: &World, item: u64, wanted: apassy::vault::Environment) {
    let start = Instant::now();
    while environment_of(world, item) != Some(wanted) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no correction to {wanted:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The judge's probe of a replayed correction: "Development", then "Production", then
/// the first envelope again. The replay does not count, and the credential stays
/// production.
#[test]
fn a_replayed_correction_does_not_undo_a_newer_one() {
    use apassy::vault::Environment;
    let world = world(true);
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let b = world.mac_b();
    let opened = b.next(&[]);
    let item = world.items[1];
    let seal = |environment, time| {
        let choice = Choice::CorrectEnvironment {
            item_id: item,
            environment,
        };
        let qid = &opened.record.qid;
        let text =
            answer_string(&b.uuid, &b.team, qid, &choice, &opened.card.digest, time).unwrap();
        let body = AnswerBody::new(
            qid,
            &b.uuid,
            &choice,
            &opened.card.digest,
            time,
            &b.sign(text.as_bytes()),
        );
        Sealed::new(
            &b.keys[0],
            &answer_aad(
                &b.team,
                qid,
                &b.keys[0].key_id(),
                b.client.device_id().unwrap(),
            ),
            &body.to_plaintext().unwrap(),
        )
        .unwrap()
    };
    let at = now();
    let development = seal(RemoteEnvironment::Development, at - 2);
    let production = seal(RemoteEnvironment::Production, at - 1);
    b.client
        .post_answer(&opened.record.qid, &development)
        .unwrap();
    wait_environment(&world, item, Environment::Development);
    b.client
        .post_answer(&opened.record.qid, &production)
        .unwrap();
    wait_environment(&world, item, Environment::Production);
    // The relay delivers the first envelope again.
    b.client
        .post_answer(&opened.record.qid, &development)
        .unwrap();
    let lines = world.wait_refused(1);
    assert!(
        lines[0].contains("Synthetic Mac mini")
            && lines[0].contains("not newer than an answer of this device that counted"),
        "{lines:?}"
    );
    assert_eq!(environment_of(&world, item), Some(Environment::Production));
    assert_eq!(
        world.queue.pending().len(),
        1,
        "a correction does not settle"
    );
    assert!(world.queue.deny(world.queue.pending()[0].id));
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
}

/// A correction of another device that the relay delivers after a newer one does not
/// count either: it is older than the last change of the credential.
#[test]
fn a_reordered_correction_of_another_device_does_not_count() {
    use apassy::vault::Environment;
    let world = world(true);
    let phone = world.iphone();
    let waiting = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let b = world.mac_b();
    let opened = b.next(&[]);
    let opened_phone = phone.next(&[]);
    let item = world.items[1];
    let at = now();
    // B answered "Production" after the iPhone answered "Development", but the relay
    // delivers B's answer first.
    let production = Choice::CorrectEnvironment {
        item_id: item,
        environment: RemoteEnvironment::Production,
    };
    let late = prepare_answer(&opened, &b.uuid, production, at - 1).unwrap();
    send_answer(
        &b.client,
        &opened,
        &late,
        &b.sign(late.text.as_bytes()),
        &b.keys,
    )
    .unwrap();
    wait_environment(&world, item, Environment::Production);
    let development = Choice::CorrectEnvironment {
        item_id: item,
        environment: RemoteEnvironment::Development,
    };
    let early = prepare_answer(&opened_phone, PHONE_UUID, development, at - 5).unwrap();
    let signature = answer_key().sign(early.text.as_bytes()).unwrap();
    send_answer(
        &phone.client,
        &opened_phone,
        &early,
        &signature,
        &phone.keys,
    )
    .unwrap();
    let lines = world.wait_refused(1);
    assert!(
        lines[0].contains("Test iPhone")
            && lines[0].contains("the environment of the credential changed after this answer"),
        "{lines:?}"
    );
    assert_eq!(environment_of(&world, item), Some(Environment::Production));
    assert!(world.queue.deny(world.queue.pending()[0].id));
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
}

/// A relay without the questions routes answers `404`: the questions stay on this Mac,
/// the waiter says "update the relay" once in Activity, and asks the relay no more for
/// minutes.
#[test]
fn an_old_relay_without_questions_keeps_them_on_this_mac() {
    use apassy::questions::worker::UNSUPPORTED;
    let world = world(true);
    world.relay.fail_next("POST /v1/questions", 1000, 404);
    world.relay.fail_next("GET /v1/questions?", 1000, 404);
    let first = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    let start = Instant::now();
    let view = loop {
        let view = world.worker.view();
        if view.unsupported && !view.local_only.is_empty() {
            break view;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{view:?}");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(view.problem.as_deref(), Some(UNSUPPORTED));
    assert_eq!(
        view.local_only.values().next().map(String::as_str),
        Some(UNSUPPORTED)
    );
    assert!(world.queue.deny(world.queue.pending()[0].id));
    assert_eq!(settled(first).outcome, ApprovalOutcome::Denied);
    // A second question stays here, with no post: the loops wait.
    let bodies = world.relay.request_bodies().len();
    let second = world.ask(world.run(contract_answers()), Duration::from_secs(60));
    while world.worker.view().local_only.is_empty() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        world.relay.request_bodies().len(),
        bodies,
        "no new post during the wait"
    );
    let lines: Vec<String> = world
        .refused_lines()
        .into_iter()
        .filter(|line| line == UNSUPPORTED)
        .collect();
    assert_eq!(lines.len(), 1, "once in Activity");
    assert_eq!(world.relay.questions_posted(), 0);
    assert!(world.queue.deny(world.queue.pending()[0].id));
    assert_eq!(settled(second).outcome, ApprovalOutcome::Denied);
}

/// A vault in iCloud Drive with a notifications-only team of Mac A, and the path of a
/// copy of the vault for Mac B.
struct Cloud {
    _root: TempDir,
    relay: FakeRelay,
    shared_a: SharedVault,
    membership: apassy::vault::RelayMembership,
    path_b: PathBuf,
}

fn cloud() -> Cloud {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let path_a = root.path().join("a.db");
    let mut vault = Vault::create(&path_a, PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let membership = new_questions_team(
        &relay.url,
        &relay.team_code(),
        "Personal",
        "Synthetic MacBook",
    )
    .expect("team");
    adopt_questions_team(&mut vault, &membership, "Synthetic MacBook").expect("adopt");
    assert_eq!(
        vault.questions_team().unwrap().as_deref(),
        Some(membership.team_id.as_str())
    );
    // Mac B gets the vault through iCloud Drive: a copy of the file.
    vault.lock().expect("lock");
    let path_b = root.path().join("b.db");
    fs::copy(&path_a, &path_b).expect("copy");
    vault.unlock(PASS).expect("unlock");
    Cloud {
        _root: root,
        relay,
        shared_a: Arc::new(Mutex::new(Some(vault))),
        membership,
        path_b,
    }
}

/// An iPhone sends its answer key with its link; the Mac writes its row from the link
/// after the confirmation, and its Face ID answer then counts.
#[test]
fn an_iphone_link_carries_its_answer_key_and_the_mac_writes_its_row() {
    use apassy::questions::device_link::link_device_name;
    use apassy::relay::membership::register_linked_device;
    let cloud = cloud();
    let client_a = QuestionsClient::from_membership(&cloud.membership).unwrap();
    let code = client_a.create_link().expect("link");
    let relay_key = DeviceKey::generate().unwrap();
    let relay_public = relay_key.public_key().to_vec();
    let answer_public = decode_b64u(ANSWER_PUBLIC).unwrap();
    let name = link_device_name("Test iPhone", &answer_public).unwrap();
    let pending = PendingJoin::request_with_key(&code.link, "", &name, relay_key).expect("join");
    let links = client_a.pending_links(Some(&code)).expect("links");
    assert_eq!(
        links[0].device_name, name,
        "the relay keeps the name with the key"
    );
    let device = client_a.confirm_link(&links[0]).expect("confirm");
    let joined = pending.poll().expect("poll").expect("confirmed");
    let row = {
        let mut guard = cloud.shared_a.lock().unwrap();
        let vault = guard.as_mut().unwrap();
        register_linked_device(
            vault,
            &cloud.membership.team_id,
            device.id,
            &links[0].device_name,
            &links[0].public_key,
        )
        .expect("row")
        .expect("an iPhone")
    };
    assert_eq!(row.kind, TrustedDeviceKind::Iphone);
    assert_eq!(row.name, "Test iPhone");
    assert_eq!(row.sign_key, relay_public);
    assert_eq!(row.answer_key.as_deref(), Some(answer_public.as_slice()));
    assert_eq!(row.relay_devices[&cloud.membership.team_id], device.id);
    // A Mac's link carries no answer key: the confirming Mac writes no row for it.
    {
        let mut guard = cloud.shared_a.lock().unwrap();
        let vault = guard.as_mut().unwrap();
        assert_eq!(
            register_linked_device(vault, &cloud.membership.team_id, 9, "Mac mini", &[4u8; 65])
                .unwrap(),
            None
        );
    }

    // Mac A asks; the iPhone approves with Face ID (its answer key) and it counts.
    let queue = Arc::new(ApprovalQueue::new());
    let _worker = QuestionsWorker::start(
        Arc::clone(&queue),
        Arc::clone(&cloud.shared_a),
        OwnerGate::new(Arc::clone(&cloud.shared_a), None),
        QuestionsConfig {
            question_wait: Duration::from_secs(300),
            tick: Duration::from_millis(50),
            device_name: "Synthetic MacBook".to_owned(),
            ..QuestionsConfig::default()
        },
    );
    let (agent, items, epoch) = {
        let mut guard = cloud.shared_a.lock().unwrap();
        let vault = guard.as_mut().unwrap();
        let shop = vault
            .add(secret_item("Shop database", SHOP_SECRET))
            .unwrap()
            .id;
        let api = vault.add(secret_item("API token", API_SECRET)).unwrap().id;
        let agent = vault.register_agent("claude-code").unwrap().0.id;
        (agent, [shop, api], vault.epoch())
    };
    let run = contract_run(0, items, contract_answers());
    let waiting = {
        let queue = Arc::clone(&queue);
        std::thread::spawn(move || {
            queue.wait_for_question(run, agent, epoch, [0; 32], Duration::from_secs(60), || true)
        })
    };
    let phone = {
        let guard = cloud.shared_a.lock().unwrap();
        let vault = guard.as_ref().unwrap();
        Answerer {
            client: QuestionsClient::from_member(joined.member()),
            keys: vec![vault.question_key().unwrap().unwrap()],
            devices: vault.trusted_devices().unwrap(),
            uuid: row.uuid.clone(),
            team: cloud.membership.team_id.clone(),
        }
    };
    let opened = phone.next(&[]);
    let approve = prepare_answer(&opened, &phone.uuid, Choice::ApproveOnce, now()).unwrap();
    let signature = answer_key().sign(approve.text.as_bytes()).unwrap();
    send_answer(&phone.client, &opened, &approve, &signature, &phone.keys).unwrap();
    let ended = settled(waiting);
    assert_eq!(ended.outcome, ApprovalOutcome::Approved);
    assert_eq!(ended.method, Some(CheckMethod::Remote));
}

/// A second Mac of a vault in iCloud Drive never makes a second questions team: it joins
/// the team of the vault with a link that Mac A confirms.
#[test]
fn a_second_mac_joins_the_questions_team_of_the_vault() {
    use apassy::relay::membership::{
        create_questions_team, existing_questions_team, join_questions_team,
    };
    use apassy::vault::{MembershipPurpose, RelayMembership};
    let cloud = cloud();
    let team = cloud.membership.team_id.clone();
    let mut vault_b = Vault::open(&cloud.path_b).expect("open");
    vault_b.unlock(PASS).expect("unlock");
    // The sync of a vault never carries the local table of the memberships: the copy of
    // the file does, so B drops A's key first.
    assert!(vault_b.remove_relay_membership(&team).unwrap());
    assert_eq!(
        questions_availability(&vault_b).unwrap(),
        QuestionsAvailability::JoinTeam {
            team_id: team.clone()
        }
    );
    assert_eq!(
        existing_questions_team(&vault_b).unwrap(),
        Some(team.clone())
    );
    // No second team: refused before the relay is asked.
    assert!(matches!(
        create_questions_team(
            &mut vault_b,
            &cloud.relay.url,
            &cloud.relay.team_code(),
            "Personal",
            "Synthetic Mac mini",
        ),
        Err(apassy::sync::SyncError::AlreadyEnabled)
    ));
    let other = new_questions_team(
        &cloud.relay.url,
        &cloud.relay.team_code(),
        "Personal",
        "Synthetic Mac mini",
    )
    .expect("a team on the relay");
    assert!(matches!(
        adopt_questions_team(&mut vault_b, &other, "Synthetic Mac mini"),
        Err(apassy::sync::SyncError::AlreadyEnabled)
    ));
    assert!(matches!(
        join_questions_team(&mut vault_b, &other, "Synthetic Mac mini"),
        Err(apassy::sync::SyncError::AlreadyEnabled)
    ));
    assert!(questions_membership(&vault_b).unwrap().is_none());

    // B joins with a link of A; A confirms (after its owner check in the app).
    let client_a = QuestionsClient::from_membership(&cloud.membership).unwrap();
    let code = client_a.create_link().expect("link");
    let pending = PendingJoin::request(&code.link, "", "Synthetic Mac mini").expect("join");
    let links = client_a.pending_links(Some(&code)).expect("links");
    client_a.confirm_link(&links[0]).expect("confirm");
    let joined = pending.poll().expect("poll").expect("confirmed");
    let member = joined.member();
    let membership = RelayMembership {
        team_id: member.team_id().to_owned(),
        relay_url: member.relay_url().to_owned(),
        device_id: member.device_id().unwrap(),
        public_key: member.public_key().to_vec(),
        key_pkcs8: joined.key_pkcs8().unwrap(),
        purposes: BTreeSet::from([MembershipPurpose::Questions]),
        created_at: 0,
    };
    let me = join_questions_team(&mut vault_b, &membership, "Synthetic Mac mini").expect("join");
    assert_eq!(me.kind, TrustedDeviceKind::Mac);
    assert_eq!(me.relay_devices[&team], membership.device_id);
    assert_eq!(
        questions_availability(&vault_b).unwrap(),
        QuestionsAvailability::On {
            team_id: team.clone()
        }
    );
    assert_eq!(client_a.devices().unwrap().len(), 2, "one team, two Macs");
}

/// The JSON `body` without its string values that are long base64url text (random
/// nonces, keys, signatures, and ciphertext). A body that is not JSON stays as it is.
fn without_random_values(body: &str) -> String {
    fn strip(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(text)
                if text.len() >= 22
                    && text.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
                    }) =>
            {
                text.clear();
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
            serde_json::Value::Object(fields) => fields.values_mut().for_each(strip),
            _ => {}
        }
    }
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(mut value) => {
            strip(&mut value);
            value.to_string()
        }
        Err(_) => body.to_owned(),
    }
}

/// MCP cancellation must withdraw the question on the Mac and settle the exact
/// encrypted question already delivered to an iPhone through the fake relay.
#[test]
fn mcp_cancellation_settles_the_iphone_relay_question() {
    use apassy::agent::{client, wire::Action};
    use apassy::broker::{BrokerOptions, http::TlsClient, server};
    let mut world = world(true);
    let phone = world.iphone();
    let token = world.with_a(|vault| {
        vault
            .set_env_binding(world.items[1], "SYNTHETIC_API", "token")
            .unwrap();
        let (agent, token) = vault.register_agent("Synthetic MCP relay test").unwrap();
        vault.set_agent_sees_all(agent.id, true).unwrap();
        token
    });
    world.worker.stop();
    let mut options = BrokerOptions::with_tls(TlsClient::platform().unwrap());
    options.approval_timeout = Duration::from_secs(10);
    options.run_timeout = Duration::from_secs(2);
    let broker = server::start_with(
        Arc::clone(&world.shared_a),
        &world._root.path().join("broker/run.sock"),
        options,
    )
    .unwrap();
    world.queue = Arc::clone(broker.approvals());
    world.worker = QuestionsWorker::start(
        Arc::clone(&world.queue),
        Arc::clone(&world.shared_a),
        OwnerGate::new(Arc::clone(&world.shared_a), None),
        QuestionsConfig {
            tick: Duration::from_millis(20),
            feed: false,
            ..QuestionsConfig::default()
        },
    );
    let socket = broker.socket_path().to_owned();
    let caller_token = token.expose().to_owned();
    let item = world.items[1];
    let cwd = world.a.data.display().to_string();
    let operation_id = "1234567890abcdef1234567890abcdef";
    let waiting = std::thread::spawn(move || {
        client::send(
            &socket,
            &caller_token,
            Action::Tracked {
                operation_id: operation_id.into(),
                idempotency_key: Some("relay-cancel".into()),
                action: Box::new(Action::Run {
                    access_request_id: None,
                    items: vec![item],
                    command: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf forbidden > cancelled.txt".into(),
                    ],
                    cwd,
                    purpose: "Synthetic cancellation test".into(),
                    path: None,
                    user_request: Some("Test cancellation".into()),
                }),
            },
        )
        .unwrap()
    });
    let opened = phone.next(&[]);
    let cancelled = client::send(
        broker.socket_path(),
        token.expose(),
        Action::CancelOperation {
            operation_id: operation_id.into(),
        },
    )
    .unwrap();
    assert_eq!(cancelled.result.unwrap()["may_have_run"], false);
    assert_eq!(waiting.join().unwrap().error.unwrap().code, "cancelled");
    assert!(world.queue.pending().is_empty());
    let deadline = Instant::now() + Duration::from_secs(10);
    while world.relay.question_state(&opened.record.qid).as_deref() != Some("settled") {
        assert!(
            Instant::now() < deadline,
            "the iPhone question was not withdrawn"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let record = phone
        .client
        .list(0, Duration::ZERO)
        .unwrap()
        .questions
        .into_iter()
        .find(|r| r.qid == opened.record.qid)
        .unwrap();
    assert_eq!(
        open_settle(&record, &phone.team, &phone.keys)
            .unwrap()
            .outcome,
        "invalidated"
    );
    let late = prepare_answer(&opened, &phone.uuid, Choice::Deny, now()).unwrap();
    assert_eq!(
        send_answer(
            &phone.client,
            &opened,
            &late,
            &phone.sign(late.text.as_bytes()),
            &phone.keys
        )
        .unwrap_err(),
        AnswerError::AlreadyAnswered
    );
    assert!(!world.a.data.join("cancelled.txt").exists());
}
