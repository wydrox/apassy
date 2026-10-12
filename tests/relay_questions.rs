#![cfg(feature = "vault")]

//! Questions through the relay (ADR 0025 §3e, contract relay-questions-v1). Synthetic
//! values only; no network beyond the in-process fake relay on 127.0.0.1.
//!
//! Mac A has the vault on the relay and asks: its approval queue, its owner gate, and its
//! questions waiter. Mac B joined the team and adopted the vault: it answers as a Mac
//! does, with its relay key after an owner check (the passphrase stands in for Touch ID
//! in a test). An "iPhone" joins the team with a link and signs with a P-256 answer key,
//! the key of the contract test vectors.

#[path = "common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

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
    QuestionsAvailability, enable_questions, questions_availability, questions_membership,
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
        std::thread::spawn(move || queue.wait_for_question(run, agent, epoch, timeout, || true))
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
        for word in forbidden {
            assert!(!body.contains(word), "{word} in {body}");
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
