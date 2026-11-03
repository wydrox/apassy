#![cfg(feature = "vault")]

//! Connect requests on the iPhone (card v2 `kind = connect`, contract relay-questions-v1
//! sections 7.4 and 12.7; plan "Bouncer section" unit U2c). Synthetic values only; no
//! network beyond the in-process fake relay on 127.0.0.1.
//!
//! Mac A has the vault on the relay and runs its questions waiter. The node is a test
//! handler: it records each verified answer. An "iPhone" joins the team with a link and
//! signs Allow with the P-256 answer key of the contract test vectors (Face ID in the
//! app), Deny with its relay key.

use crate::common::fake_relay;

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{
    AnswerKind, ApprovalQueue, OwnerGate, PendingRun, QuestionInfo, QuestionItem,
};
use apassy::broker::project::Project;
use apassy::questions::envelope::{
    AnswerBody, CONNECT_CARD_VERSION, Card, ConnectCard, ConnectChoice, QUESTION_CARD_VERSION,
    Sealed, answer_aad, card_aad, connect_answer_string,
};
use apassy::questions::{
    ConnectAnswer, ConnectApplied, ConnectDecision, ConnectEnd, PendingConnectCard, QuestionRecord,
    QuestionsClient, QuestionsConfig, QuestionsError, QuestionsWorker, Unreadable, open_question,
    open_settle,
};
use apassy::relay::membership::enable_questions;
use apassy::sync::{DeviceKey, PendingJoin, RelayConfig, RelaySync, decode_b64u};
use apassy::vault::{QuestionKey, TrustedDevice, TrustedDeviceKind, Vault};
use fake_relay::FakeRelay;
use tempfile::TempDir;

const PASS: &str = "synthetic-connect-pass";
const PHONE_UUID: &str = "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const ANSWER_PRIVATE: &str = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
const CONNECT_OPERATION: &str = "connect through the relay";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn answer_key() -> DeviceKey {
    DeviceKey::from_raw(
        &unhex(ANSWER_PRIVATE),
        &decode_b64u(ANSWER_PUBLIC).expect("public key"),
    )
    .expect("the answer key of the contract")
}

fn wait_until<T>(what: &str, mut found: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = found() {
            return value;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "{what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Mac A with the questions on, its waiter, the node's handler, and an iPhone of the
/// vault.
struct World {
    _root: TempDir,
    _relay: FakeRelay,
    shared: SharedVault,
    worker: QuestionsWorker,
    /// The verified answers that reached the node, in order.
    answers: Arc<Mutex<Vec<ConnectAnswer>>>,
    /// What the node says it did with each.
    applied: Arc<Mutex<ConnectApplied>>,
    phone: Phone,
}

type SharedVault = Arc<Mutex<Option<Vault>>>;

struct Phone {
    client: QuestionsClient,
    keys: Vec<QuestionKey>,
    devices: Vec<TrustedDevice>,
    team: String,
}

fn world() -> World {
    let root = TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let data = root.path().join("a").join("Apassy");
    fs::create_dir_all(&data).expect("data dir");
    let vault_path: PathBuf = data.join("vault.db");
    let sync = RelaySync::new(RelayConfig::in_data_dir(
        &data,
        &vault_path,
        &relay.url,
        "vault",
    ));
    let mut vault = Vault::create(&vault_path, PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let report = sync
        .create_team(
            &mut vault,
            "Personal",
            &relay.team_code(),
            "Synthetic MacBook",
        )
        .expect("create team");
    let team = report.link.team_id.clone();
    enable_questions(&mut vault, "Synthetic MacBook").expect("questions on");
    // The iPhone joins the team with a link; the Mac writes its row with its answer key.
    let key = DeviceKey::generate().expect("key");
    let public = key.public_key().to_vec();
    let code = sync.create_link(&vault).expect("link");
    let pending = PendingJoin::request_with_key(&code.link, "", "Test iPhone", key).expect("join");
    let links = sync.pending_links(&vault, Some(&code)).expect("links");
    sync.confirm_link(&vault, &links[0]).expect("confirm");
    let joined = pending.poll().expect("poll").expect("confirmed");
    vault
        .register_trusted_device(
            PHONE_UUID,
            "Test iPhone",
            TrustedDeviceKind::Iphone,
            &public,
            Some(&decode_b64u(ANSWER_PUBLIC).unwrap()),
        )
        .expect("register");
    vault
        .set_trusted_device_relay_id(PHONE_UUID, &team, joined.device_id())
        .expect("relay id");
    let phone = Phone {
        client: QuestionsClient::from_member(joined.member()),
        keys: vec![vault.question_key().unwrap().unwrap()],
        devices: vault.trusted_devices().unwrap(),
        team,
    };
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let queue = Arc::new(ApprovalQueue::new());
    let worker = QuestionsWorker::start(
        Arc::clone(&queue),
        Arc::clone(&shared),
        OwnerGate::new(Arc::clone(&shared), None),
        QuestionsConfig {
            tick: Duration::from_millis(50),
            short_poll_every: Duration::from_millis(50),
            access_every: Duration::from_millis(100),
            device_name: "Synthetic MacBook".to_owned(),
            ..QuestionsConfig::default()
        },
    );
    let answers = Arc::new(Mutex::new(Vec::new()));
    let applied = Arc::new(Mutex::new(ConnectApplied::Applied));
    {
        let answers = Arc::clone(&answers);
        let applied = Arc::clone(&applied);
        worker.set_on_connect_answer(move |answer| {
            answers.lock().unwrap().push(answer.clone());
            *applied.lock().unwrap()
        });
    }
    World {
        _root: root,
        _relay: relay,
        shared,
        worker,
        answers,
        applied,
        phone,
    }
}

fn connect(id: &str) -> PendingConnectCard {
    PendingConnectCard {
        id: id.to_owned(),
        client_name: "Grok Bot".to_owned(),
        mac_name: "Synthetic MacBook".to_owned(),
        code: "482 913".to_owned(),
        expires_at: now() + 300,
    }
}

impl World {
    /// The connect card of `id` once it is on the relay: its record and the card as the
    /// iPhone opens it.
    fn posted(&self, id: &str) -> (QuestionRecord, ConnectCard) {
        let qid = wait_until("the connect card is posted", || {
            self.worker.view().connect_posted.get(id).cloned()
        });
        let record = self.record(&qid);
        let key = &self.phone.keys[0];
        let aad = card_aad(
            &self.phone.team,
            &record.qid,
            &record.key_id,
            &record.to,
            record.expires_at,
        );
        let plaintext = record.card().open(key, &aad).expect("the card opens");
        let card = ConnectCard::parse(&plaintext).expect("a connect card");
        (record, card)
    }

    fn record(&self, qid: &str) -> QuestionRecord {
        let list = self.phone.client.list(0, Duration::ZERO).expect("list");
        list.questions
            .into_iter()
            .find(|record| record.qid == qid)
            .expect("the question is listed")
    }

    /// The settled record of `qid`.
    fn settled(&self, qid: &str) -> QuestionRecord {
        wait_until("the question settles", || {
            Some(self.record(qid)).filter(|record| record.state == "settled")
        })
    }

    /// Seal and post an answer of the iPhone to `card`, signed by `signer`.
    fn answer(
        &self,
        record: &QuestionRecord,
        card: &ConnectCard,
        choice: ConnectChoice,
        signer: &dyn Fn(&[u8]) -> Vec<u8>,
        time: u64,
    ) -> Result<(), QuestionsError> {
        let text = connect_answer_string(
            PHONE_UUID,
            &self.phone.team,
            &record.qid,
            choice,
            &card.digest,
            time,
        )
        .unwrap();
        let body = AnswerBody::connect(
            &record.qid,
            PHONE_UUID,
            choice,
            &card.digest,
            time,
            &signer(text.as_bytes()),
        );
        self.post_body(record, &body)
    }

    fn post_body(&self, record: &QuestionRecord, body: &AnswerBody) -> Result<(), QuestionsError> {
        let key = &self.phone.keys[0];
        let device_id = self.phone.client.device_id().expect("device id");
        let sealed = Sealed::new(
            key,
            &answer_aad(&self.phone.team, &record.qid, &key.key_id(), device_id),
            &body.to_plaintext().unwrap(),
        )
        .unwrap();
        self.phone
            .client
            .post_answer(&record.qid, &sealed)
            .map(|_| ())
    }

    fn face_id(&self) -> impl Fn(&[u8]) -> Vec<u8> {
        |message: &[u8]| answer_key().sign(message).expect("sign")
    }

    fn relay_key(&self) -> impl Fn(&[u8]) -> Vec<u8> + '_ {
        |message: &[u8]| self.phone.client.sign(message).expect("sign")
    }

    fn refused_lines(&self) -> Vec<String> {
        let guard = self.shared.lock().unwrap();
        guard
            .as_ref()
            .unwrap()
            .recent_activity(100)
            .unwrap()
            .into_iter()
            .filter(|row| row.operation == CONNECT_OPERATION)
            .map(|row| row.reason)
            .collect()
    }
}

/// The run of section 7.1 of the contract (items 7 and 9).
fn contract_run() -> PendingRun {
    PendingRun {
        id: 123_456_789_012_345,
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
            reason: Default::default(),
            id: 123_456_789_012_345,
            item_ids: vec![7, 9],
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
                    item_id: 7,
                    name: "Shop database".to_owned(),
                    production: true,
                    unconfirmed: false,
                    always_ask: false,
                },
                QuestionItem {
                    item_id: 9,
                    name: "API token".to_owned(),
                    production: false,
                    unconfirmed: true,
                    always_ask: false,
                },
            ],
            valid_answers: vec![
                AnswerKind::Once,
                AnswerKind::Production(ActionKind::Deploy),
                AnswerKind::CorrectEnvironment,
                AnswerKind::NeverForAgent,
                AnswerKind::AlwaysAskForAgent,
                AnswerKind::Disconnect,
            ],
        },
    }
}

/// Section 20.2 of the contract: the card plaintext, exactly 1138 bytes.
const CONTRACT_CARD: &str = r#"{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","asker":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"created_at":1790000000,"run":{"id":"123456789012345","agent":"claude-code","command":["npm","run","migrate"],"cwd":"/tmp/synthetic-shop","env_names":["DATABASE_URL","API_TOKEN"],"purpose":"Apply the new migration.","risk":"production credential: always asks the owner","user_request":"Deploy the new schema to staging.","request_source":"from the host hook","agent_request":"Run the migration.","remember":null},"question":{"id":"123456789012345","item_ids":["7","9"],"items":[{"item_id":"7","name":"Shop database","production":true,"unconfirmed":false,"always_ask":false},{"item_id":"9","name":"API token","production":false,"unconfirmed":true,"always_ask":false}],"project":{"key":"/tmp/synthetic-shop/.git","label":"synthetic-shop"},"action":"deploy","production":true,"why":"A production credential goes to a deploy.","valid_answers":["once","production:deploy","correct_environment","never_for_agent","always_ask_for_agent","disconnect"]},"digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"}"#;

#[test]
fn run_cards_stay_card_v1_byte_for_byte() {
    assert_eq!(QUESTION_CARD_VERSION, 1);
    assert_eq!(CONNECT_CARD_VERSION, 2);
    let card = Card::from_run(
        "oKGio6SlpqeoqaqrrK2urw",
        "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
        "MacBook Pro",
        1_790_000_000,
        &contract_run(),
    );
    assert_eq!(card.v, 1);
    assert!(card.owner_prompt.is_none());
    let plaintext = card.to_plaintext().unwrap();
    assert_eq!(plaintext.len(), 1138);
    assert_eq!(std::str::from_utf8(&plaintext).unwrap(), CONTRACT_CARD);
}

#[test]
fn a_connect_card_is_posted_answered_with_face_id_and_settled_once() {
    let world = world();
    world
        .worker
        .post_connect(connect("cr_allow"))
        .expect("taken");
    let (record, card) = world.posted("cr_allow");
    assert_eq!(card.v, 2);
    assert_eq!(card.kind, "connect");
    assert_eq!(card.connect.id, "cr_allow");
    assert_eq!(card.connect.client_name, "Grok Bot");
    assert_eq!(card.connect.mac_name, "Synthetic MacBook");
    assert_eq!(card.connect.code, "482 913");
    assert_eq!(card.connect.expires_at, record.expires_at);
    assert_eq!(record.to, "member");
    // An old reader (the run card reader) shows "Update Apassy to read this question".
    assert_eq!(
        open_question(
            &record,
            &world.phone.team,
            &world.phone.keys,
            &world.phone.devices,
            now()
        )
        .unwrap_err(),
        Unreadable::Update
    );
    assert_eq!(
        Unreadable::Update.message(),
        "Update Apassy to read this question."
    );
    let time = now();
    world
        .answer(&record, &card, ConnectChoice::Allow, &world.face_id(), time)
        .expect("the relay takes the answer");
    let answers = wait_until("the node gets the answer", || {
        let answers = world.answers.lock().unwrap().clone();
        (!answers.is_empty()).then_some(answers)
    });
    assert_eq!(
        answers,
        [ConnectAnswer {
            id: "cr_allow".to_owned(),
            decision: ConnectDecision::Allow,
            device_uuid: PHONE_UUID.to_owned(),
            device_name: "Test iPhone".to_owned(),
            time,
        }]
    );
    let settled = world.settled(&record.qid);
    let settle = open_settle(&settled, &world.phone.team, &world.phone.keys).expect("settle");
    assert_eq!(settle.outcome, "approved");
    assert_eq!(settle.kind.as_deref(), Some("allow_connect"));
    assert_eq!(settle.device_kind.as_deref(), Some("iphone"));
    assert_eq!(settle.device_name.as_deref(), Some("Test iPhone"));
    // Settled once: the same answer again does not reach the node.
    let again = world.answer(&record, &card, ConnectChoice::Allow, &world.face_id(), time);
    assert!(again.is_err(), "the relay refuses answers after the settle");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(world.answers.lock().unwrap().len(), 1);
    wait_until("the card leaves the view", || {
        (!world.worker.view().connect_posted.contains_key("cr_allow")).then_some(())
    });
    // The same ID again is a new connect request only after the first one ended.
    assert!(world.worker.view().connect_local_only.is_empty());
}

#[test]
fn a_forged_or_replayed_connect_answer_is_refused_and_logged() {
    let world = world();
    world
        .worker
        .post_connect(connect("cr_forged"))
        .expect("taken");
    let (record, card) = world.posted("cr_forged");
    // Allow signed with the relay key: no Face ID, so it does not count.
    world
        .answer(
            &record,
            &card,
            ConnectChoice::Allow,
            &world.relay_key(),
            now(),
        )
        .expect("posted");
    // Allow with a time outside the window: a replay of an old answer.
    world
        .answer(
            &record,
            &card,
            ConnectChoice::Allow,
            &world.face_id(),
            now() - 600,
        )
        .expect("posted");
    let lines = wait_until("two refused lines", || {
        let lines = world.refused_lines();
        (lines.len() >= 2).then_some(lines)
    });
    assert!(
        lines.iter().any(|line| line
            .contains("An answer from Test iPhone did not count: its signature does not verify.")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("did not count: the answer is too old")),
        "{lines:?}"
    );
    assert!(
        world.answers.lock().unwrap().is_empty(),
        "nothing reached the node"
    );
    assert_eq!(world.record(&record.qid).state, "open");
    // A valid Deny with the relay key counts, and settles the question as denied (the
    // relay takes three answers of a device per question).
    world
        .answer(
            &record,
            &card,
            ConnectChoice::Deny,
            &world.relay_key(),
            now(),
        )
        .expect("posted");
    let answers = wait_until("the node gets the denial", || {
        let answers = world.answers.lock().unwrap().clone();
        (!answers.is_empty()).then_some(answers)
    });
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].decision, ConnectDecision::Deny);
    let settled = world.settled(&record.qid);
    let settle = open_settle(&settled, &world.phone.team, &world.phone.keys).expect("settle");
    assert_eq!(settle.outcome, "denied");
    assert_eq!(settle.kind.as_deref(), Some("deny"));

    // The next connect request (one card at a time): a run answer kind does not count.
    wait_until("the first card leaves the view", || {
        world.worker.view().connect_posted.is_empty().then_some(())
    });
    world
        .worker
        .post_connect(connect("cr_kind"))
        .expect("taken");
    let (record, card) = world.posted("cr_kind");
    let mut run_kind = AnswerBody::connect(
        &record.qid,
        PHONE_UUID,
        ConnectChoice::Allow,
        &card.digest,
        now(),
        b"sig",
    );
    run_kind.kind = "approve_once".to_owned();
    world.post_body(&record, &run_kind).expect("posted");
    wait_until("a third refused line", || {
        world
            .refused_lines()
            .iter()
            .any(|line| line.contains("did not count: it has a bad form"))
            .then_some(())
    });
    assert_eq!(
        world.answers.lock().unwrap().len(),
        1,
        "still only the Deny"
    );
    world.worker.end_connect("cr_kind", ConnectEnd::Expired);
    let settled = world.settled(&record.qid);
    let settle = open_settle(&settled, &world.phone.team, &world.phone.keys).expect("settle");
    assert_eq!(settle.outcome, "timed_out");
}

#[test]
fn a_connect_that_ends_on_the_mac_settles_with_that_end() {
    let world = world();
    world.worker.post_connect(connect("cr_mac")).expect("taken");
    let (record, card) = world.posted("cr_mac");
    world.worker.end_connect("cr_mac", ConnectEnd::Allowed);
    let settled = world.settled(&record.qid);
    let settle = open_settle(&settled, &world.phone.team, &world.phone.keys).expect("settle");
    assert_eq!(settle.outcome, "approved");
    assert_eq!(settle.device_kind.as_deref(), Some("mac"));
    assert_eq!(settle.device_name.as_deref(), Some("Synthetic MacBook"));
    // A late answer of the iPhone: the relay refuses it, and the node never sees it.
    assert!(
        world
            .answer(
                &record,
                &card,
                ConnectChoice::Deny,
                &world.relay_key(),
                now()
            )
            .is_err()
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(world.answers.lock().unwrap().is_empty());
}

#[test]
fn an_answer_for_a_request_that_no_longer_waits_settles_once_at_its_end() {
    let world = world();
    *world.applied.lock().unwrap() = ConnectApplied::NotPending;
    world
        .worker
        .post_connect(connect("cr_gone"))
        .expect("taken");
    let (record, card) = world.posted("cr_gone");
    world
        .answer(
            &record,
            &card,
            ConnectChoice::Allow,
            &world.face_id(),
            now(),
        )
        .expect("posted");
    wait_until("the node gets the answer", || {
        (!world.answers.lock().unwrap().is_empty()).then_some(())
    });
    // The node did not take it: the lane reads no more answers and waits for the end.
    world
        .answer(
            &record,
            &card,
            ConnectChoice::Deny,
            &world.relay_key(),
            now(),
        )
        .expect("posted while open");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(world.answers.lock().unwrap().len(), 1);
    assert_eq!(world.record(&record.qid).state, "open");
    world.worker.end_connect("cr_gone", ConnectEnd::Withdrawn);
    let settled = world.settled(&record.qid);
    let settle = open_settle(&settled, &world.phone.team, &world.phone.keys).expect("settle");
    assert_eq!(settle.outcome, "invalidated");
    assert_eq!(settle.answered_by, None);
}
