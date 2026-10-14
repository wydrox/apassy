//! Questions through the relay with several hosts and several answering devices
//! (ADR 0025 §3e, contract relay-questions-v1 sections 11 to 13).
//!
//! The asking Macs are the app's own code: the approval queue, the owner gate, and the
//! questions waiter (`QuestionsWorker`). The iPhones are real cores, driven through the
//! JSON calls as the app makes them. The relay is the in-process fake of the Mac tests
//! (`tests/common/fake_relay.rs`): it keeps several teams and routes each question to
//! every other live device of the asking team, as the relay does for one member.
//!
//! - A1: two Macs of one vault ask; one iPhone of that vault answers both.
//! - B1: one Mac asks; two iPhones of the vault each get the question; the first answer
//!   settles it on the other.
//! - A2: two Macs with different vaults; one iPhone that holds both vaults lists and
//!   answers the questions of each, and its push token reaches both teams.
//! - The contexts of several vaults (stream Q1): a lock and a suspend drop them all, a
//!   selection keeps them, an answer names the right vault, a removed vault has none,
//!   `questions_unlock`, and the push token of a vault that opens later.
//!
//! Synthetic values only; no network beyond 127.0.0.1.

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{
    AnswerKind, ApprovalOutcome, ApprovalQueue, CheckMethod, OwnerGate, PendingRun, QuestionInfo,
    QuestionItem, QuestionRefusal, Settled,
};
use apassy::broker::project::Project;
use apassy::contracts::CredentialKind;
use apassy::questions::{QuestionsConfig, QuestionsWorker};
use apassy::relay::membership::{enable_questions, register_linked_device};
use apassy::sync::{DeviceKey, PendingJoin, RelayConfig, RelaySync, decode_b64u, encode_b64u};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use apassy_core::Core;
use fake_relay::FakeRelay;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-multi-host-pass";
/// The answer key of the contract test vectors (relay-questions-v1 section 20).
const ANSWER_PRIVATE: &str = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
const WAIT: Duration = Duration::from_secs(20);

type SharedVault = Arc<Mutex<Option<Vault>>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn contract_answer_key() -> DeviceKey {
    DeviceKey::from_raw(&unhex(ANSWER_PRIVATE), &decode_b64u(ANSWER_PUBLIC).unwrap()).unwrap()
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

/// The run of section 7.1 of the contract, with the items `ids` of the asking vault.
fn run(ids: [u64; 2]) -> PendingRun {
    PendingRun {
        id: 0,
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
            id: 0,
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
            valid_answers: vec![
                AnswerKind::Once,
                AnswerKind::Production(ActionKind::Deploy),
                AnswerKind::NeverForAgent,
                AnswerKind::Disconnect,
            ],
        },
    }
}

// ---- The asking Macs. ----

/// One Mac with its vault, its relay sync, its approval queue, and, once started, its
/// questions waiter.
struct Mac {
    name: &'static str,
    sync: RelaySync,
    vault: SharedVault,
    queue: Arc<ApprovalQueue>,
    worker: Option<QuestionsWorker>,
    team: String,
    agent: u64,
    items: [u64; 2],
}

fn mac_paths(root: &Path, dir: &str, url: &str) -> (PathBuf, PathBuf, RelaySync) {
    let data = root.join(dir).join("Apassy");
    fs::create_dir_all(&data).unwrap();
    let vault_path = data.join("vault.db");
    let sync = RelaySync::new(RelayConfig::in_data_dir(&data, &vault_path, url, "vault"));
    (data, vault_path, sync)
}

impl Mac {
    /// A Mac with a new vault named `vault_name` on a new relay sync team, with the
    /// questions on.
    fn with_new_vault(
        root: &Path,
        relay: &FakeRelay,
        dir: &str,
        name: &'static str,
        vault_name: &str,
    ) -> Self {
        let (_, vault_path, sync) = mac_paths(root, dir, &relay.url);
        let mut vault = Vault::create(&vault_path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let shop = vault
            .add(secret_item("Shop database", "SYNTH-db"))
            .unwrap()
            .id;
        let api = vault.add(secret_item("API token", "SYNTH-api")).unwrap().id;
        let agent = vault.register_agent("claude-code").unwrap().0.id;
        let report = sync
            .create_team(&mut vault, vault_name, &relay.team_code(), name)
            .unwrap();
        enable_questions(&mut vault, name).unwrap();
        sync.sync(&mut vault).unwrap();
        Self {
            name,
            sync,
            vault: Arc::new(Mutex::new(Some(vault))),
            queue: Arc::new(ApprovalQueue::new()),
            worker: None,
            team: report.link.team_id,
            agent,
            items: [shop, api],
        }
    }

    /// A second Mac of the vault of `first`: it joins the team with a device link that
    /// `first` confirms, adopts the vault, and turns the questions on. Both Macs sync, so
    /// each has the row of the other and the one question key.
    fn joining(root: &Path, relay: &FakeRelay, dir: &str, name: &'static str, first: &Mac) -> Self {
        let (data, _, sync) = mac_paths(root, dir, &relay.url);
        // `data` holds the download of the join.
        let joined = first.with(|vault| {
            let code = first.sync.create_link(&*vault).unwrap();
            let pending = PendingJoin::request(&code.link, "", name).unwrap();
            let links = first.sync.pending_links(&*vault, Some(&code)).unwrap();
            first.sync.confirm_link(&*vault, &links[0]).unwrap();
            pending.poll().unwrap().expect("confirmed")
        });
        let download = joined.download(&data.join("sync")).unwrap();
        let (mut vault, _) = sync.adopt(&joined, &download, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        enable_questions(&mut vault, name).unwrap();
        sync.sync(&mut vault).unwrap();
        first.with(|vault| first.sync.sync(vault).unwrap());
        let agent = vault.register_agent("claude-code").unwrap().0.id;
        Self {
            name,
            sync,
            vault: Arc::new(Mutex::new(Some(vault))),
            queue: Arc::new(ApprovalQueue::new()),
            worker: None,
            team: first.team.clone(),
            agent,
            items: first.items,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.vault.lock().unwrap().as_mut().unwrap())
    }

    /// Pull and push the vault through the relay.
    fn sync_now(&self) {
        self.with(|vault| self.sync.sync(vault).unwrap());
    }

    fn start_waiter(&mut self) {
        self.worker = Some(QuestionsWorker::start(
            Arc::clone(&self.queue),
            Arc::clone(&self.vault),
            OwnerGate::new(Arc::clone(&self.vault), None),
            QuestionsConfig {
                question_wait: Duration::from_secs(300),
                tick: Duration::from_millis(50),
                device_name: self.name.to_owned(),
            },
        ));
    }

    /// A run of agent `claude-code` starts to wait on this Mac.
    fn ask(&self) -> JoinHandle<Result<Settled, QuestionRefusal>> {
        let epoch = self.with(|vault| vault.epoch());
        let queue = Arc::clone(&self.queue);
        let agent = self.agent;
        let run = run(self.items);
        std::thread::spawn(move || {
            queue.wait_for_question(run, agent, epoch, [0; 32], Duration::from_secs(60), || true)
        })
    }

    /// "Add a device…" on this Mac for an iPhone: a new link, and after the owner check
    /// the confirmation, which writes the row of the iPhone from the keys of its link
    /// (`relay_register_linked` in the app). The vault then syncs, so the row reaches
    /// the relay copy that the iPhone downloads.
    fn add_iphone(&self, phone: &Core, answer_public: &str) {
        let code = self.with(|vault| self.sync.create_link(&*vault).unwrap());
        let started = call(
            phone,
            json!({"op": "join_start", "link": code.link.as_str(), "answer_key": answer_public}),
        );
        assert_eq!(started["state"], "waiting", "{started}");
        self.with(|vault| {
            let links = self.sync.pending_links(&*vault, Some(&code)).unwrap();
            assert_eq!(links.len(), 1, "one waiting link");
            let device = self.sync.confirm_link(&*vault, &links[0]).unwrap();
            register_linked_device(
                vault,
                &self.team,
                device.id,
                &links[0].device_name,
                &links[0].public_key,
            )
            .unwrap()
            .expect("an iPhone row");
            self.sync.sync(vault).unwrap();
        });
        let start = Instant::now();
        loop {
            let polled = call(phone, json!({"op": "join_poll"}));
            if polled["state"] == "ready" {
                break;
            }
            assert!(start.elapsed() < WAIT, "the join never got ready: {polled}");
            std::thread::sleep(Duration::from_millis(50));
        }
        call(phone, json!({"op": "join_finish", "passphrase": PASS}));
    }
}

fn settled(handle: JoinHandle<Result<Settled, QuestionRefusal>>) -> Settled {
    handle.join().expect("join").expect("the run got an answer")
}

// ---- The iPhones. ----

fn phone(root: &Path, dir: &str, name: &str) -> Core {
    let data = root.join(dir);
    fs::create_dir_all(&data).unwrap();
    let config = json!({"data_dir": data, "device_name": name, "role": "app"});
    Core::new(&config.to_string()).expect("core")
}

fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).unwrap();
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

fn fails(core: &Core, request: Value) -> String {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).unwrap();
    assert_eq!(answer["ok"], false, "{request} -> {answer}");
    answer["error"]["code"].as_str().unwrap().to_owned()
}

/// The open questions with a card that opened, once there are at least `count` (or what
/// came within the wait: the caller's assertion says what was missing).
fn open_questions(phone: &Core, count: usize) -> Vec<Value> {
    let start = Instant::now();
    loop {
        let list = call(phone, json!({"op": "questions_list"}));
        let open: Vec<Value> = list["questions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|question| question["state"] == "open" && !question["card"].is_null())
            .cloned()
            .collect();
        if open.len() >= count || start.elapsed() > WAIT {
            return open;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The question `qid` once the asker settled it.
fn settled_question(phone: &Core, qid: &str) -> Value {
    let start = Instant::now();
    loop {
        let list = call(phone, json!({"op": "questions_list"}));
        if let Some(question) = list["questions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|question| question["qid"] == qid && question["state"] == "settled")
        {
            return question.clone();
        }
        assert!(start.elapsed() < WAIT, "{qid} never settled: {list}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// "Allow Once": the core builds the answer string, Face ID signs it with `key` (the
/// test signs as the Secure Enclave would), and the core sends it. `extra` goes into
/// both calls (the vault of the question for A2).
fn allow_once(phone: &Core, qid: &str, key: &DeviceKey, extra: &Value) -> Value {
    let mut request = json!({"op": "question_answer_string", "qid": qid, "kind": "approve_once"});
    merge(&mut request, extra);
    let prepared = call(phone, request);
    assert_eq!(prepared["needs_face_id"], true);
    let text = prepared["answer_string"].as_str().unwrap();
    let signature = encode_b64u(&key.sign(text.as_bytes()).unwrap());
    let mut request = json!({"op": "question_answer", "qid": qid, "kind": "approve_once",
                             "time": prepared["time"], "signature": signature});
    merge(&mut request, extra);
    call(phone, request)
}

/// "Deny": signed by the core with the relay key, no Face ID.
fn deny(phone: &Core, qid: &str, extra: &Value) -> Value {
    let mut request = json!({"op": "question_answer", "qid": qid, "kind": "deny", "time": now()});
    merge(&mut request, extra);
    call(phone, request)
}

fn merge(request: &mut Value, extra: &Value) {
    if let (Some(request), Some(extra)) = (request.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            request.insert(key.clone(), value.clone());
        }
    }
}

fn asker_of(question: &Value) -> &str {
    question["asker_name"].as_str().unwrap()
}

// ---- A1: one iPhone, two Macs of one vault. ----

/// Mac A and Mac B hold one vault (relay sync) and are both in its questions team. One
/// iPhone joins the vault through "Add a device…" on Mac A. A question of each Mac
/// reaches the iPhone; the iPhone allows the one of Mac A with Face ID and denies the
/// one of Mac B; each Mac takes the answer meant for it, and the iPhone reads both
/// settles.
#[test]
fn a1_one_iphone_answers_the_questions_of_two_macs_of_one_vault() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let mut mac_a = Mac::with_new_vault(
        root.path(),
        &relay,
        "mac-a",
        "Synthetic MacBook",
        "Personal",
    );
    let mut mac_b = Mac::joining(root.path(), &relay, "mac-b", "Synthetic Mac mini", &mac_a);
    let iphone = phone(root.path(), "iphone", "Test iPhone");
    mac_a.add_iphone(&iphone, ANSWER_PUBLIC);
    // Mac B needs the row of the iPhone to check its answers: the vault syncs.
    mac_b.sync_now();
    assert_eq!(
        mac_b.with(|vault| vault.trusted_devices().unwrap().len()),
        3
    );
    let status = call(&iphone, json!({"op": "questions_list"}))["status"].clone();
    assert_eq!(status["enabled"], true, "{status}");
    assert_eq!(status["registered"], true, "{status}");
    assert_eq!(status["team_id"], mac_a.team.as_str());

    mac_a.start_waiter();
    mac_b.start_waiter();
    let waiting_a = mac_a.ask();
    let waiting_b = mac_b.ask();
    let open = open_questions(&iphone, 2);
    assert_eq!(open.len(), 2, "both questions reach the iPhone: {open:?}");
    let from_a = open
        .iter()
        .find(|question| asker_of(question) == "Synthetic MacBook")
        .expect("the question of Mac A");
    let from_b = open
        .iter()
        .find(|question| asker_of(question) == "Synthetic Mac mini")
        .expect("the question of Mac B");

    allow_once(
        &iphone,
        from_a["qid"].as_str().unwrap(),
        &contract_answer_key(),
        &json!({}),
    );
    deny(&iphone, from_b["qid"].as_str().unwrap(), &json!({}));
    let ended_a = settled(waiting_a);
    assert_eq!(ended_a.outcome, ApprovalOutcome::Approved);
    assert_eq!(ended_a.method, Some(CheckMethod::Remote));
    assert_eq!(settled(waiting_b).outcome, ApprovalOutcome::Denied);

    for question in [from_a, from_b] {
        let ended = settled_question(&iphone, question["qid"].as_str().unwrap());
        assert_eq!(ended["settle"]["device_name"], "Test iPhone", "{ended}");
    }
}

// ---- B1: two iPhones, one Mac. ----

/// One Mac, and two iPhones added with "Add a device…" twice. Each iPhone gets each
/// question and registers its own push token. The first answer settles the question:
/// the other iPhone reads "Answered on Phone One" and its late answer is refused. The
/// second iPhone answers the next question with its own answer key.
#[test]
fn b1_two_iphones_get_each_question_and_the_first_answer_settles_it_on_both() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let mut mac = Mac::with_new_vault(root.path(), &relay, "mac", "Synthetic MacBook", "Personal");
    let one = phone(root.path(), "phone-one", "Phone One");
    let two = phone(root.path(), "phone-two", "Phone Two");
    let key_two = DeviceKey::generate().unwrap();
    mac.add_iphone(&one, ANSWER_PUBLIC);
    mac.add_iphone(&two, &encode_b64u(key_two.public_key()));
    let rows = mac.with(|vault| vault.trusted_devices().unwrap());
    assert_eq!(rows.len(), 3, "the Mac and two iPhones");
    for phone in [&one, &two] {
        // Phone One has to sync once: its copy predates the row of Phone Two. Its own
        // row is enough to answer.
        let status = call(phone, json!({"op": "questions_list"}))["status"].clone();
        assert_eq!(status["registered"], true, "{status}");
        call(
            phone,
            json!({"op": "push_token_set", "token": "0a".repeat(32), "environment": "development"}),
        );
    }
    let tokens = relay.push_tokens();
    assert_eq!(tokens.len(), 2, "one token per iPhone: {tokens:?}");

    mac.start_waiter();
    let waiting = mac.ask();
    let on_one = open_questions(&one, 1);
    let on_two = open_questions(&two, 1);
    assert_eq!(on_one.len(), 1, "Phone One gets the question");
    assert_eq!(on_two.len(), 1, "Phone Two gets the question");
    let qid = on_one[0]["qid"].as_str().unwrap().to_owned();
    assert_eq!(on_two[0]["qid"], qid.as_str(), "the same question");

    allow_once(&one, &qid, &contract_answer_key(), &json!({}));
    let ended = settled(waiting);
    assert_eq!(ended.outcome, ApprovalOutcome::Approved);
    assert_eq!(ended.method, Some(CheckMethod::Remote));
    let seen = settled_question(&two, &qid);
    assert_eq!(seen["settle"]["device_name"], "Phone One", "{seen}");
    assert_eq!(seen["settle"]["outcome"], "approved");
    assert_eq!(
        fails(
            &two,
            json!({"op": "question_answer", "qid": qid, "kind": "deny", "time": now()})
        ),
        "already_answered"
    );

    // The next question: Phone Two answers it with its own answer key.
    let waiting = mac.ask();
    let start = Instant::now();
    let next = loop {
        let open = open_questions(&two, 1);
        if let Some(question) = open
            .into_iter()
            .find(|question| question["qid"] != qid.as_str())
        {
            break question;
        }
        assert!(start.elapsed() < WAIT, "no second question");
    };
    allow_once(&two, next["qid"].as_str().unwrap(), &key_two, &json!({}));
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Approved);
    let seen = settled_question(&one, next["qid"].as_str().unwrap());
    assert_eq!(seen["settle"]["device_name"], "Phone Two", "{seen}");
}

// ---- A2: one iPhone, two Macs with different vaults. ----

/// The vault ids on the iPhone, by name.
fn vault_id(phone: &Core, name: &str) -> String {
    let info = call(phone, json!({"op": "info"}));
    info["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vault| vault["name"] == name)
        .and_then(|vault| vault["id"].as_str())
        .unwrap_or_else(|| panic!("no vault {name}: {info}"))
        .to_owned()
}

/// Mac A asks in its vault "Personal", Mac B in its vault "Work". The iPhone holds both
/// (Settings > "Add another vault") and unlocked each once in this session; "Work" is
/// selected now. The core keeps a questions context per vault that was unlocked in this
/// session (team, relay key, question keys, trusted devices) until a `lock`;
/// `questions_list` lists the questions of every context with their `vault_id`; the
/// answer calls take `vault_id`.
#[test]
fn a2_the_iphone_lists_and_answers_the_questions_of_every_vault() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let mut mac_a = Mac::with_new_vault(
        root.path(),
        &relay,
        "mac-a",
        "Synthetic MacBook",
        "Personal",
    );
    let mut mac_b = Mac::with_new_vault(root.path(), &relay, "mac-b", "Synthetic Mac mini", "Work");
    assert_ne!(mac_a.team, mac_b.team, "two vaults, two teams");
    let iphone = phone(root.path(), "iphone", "Test iPhone");
    mac_a.add_iphone(&iphone, ANSWER_PUBLIC);
    mac_b.add_iphone(&iphone, ANSWER_PUBLIC);
    let personal = vault_id(&iphone, "Personal");
    let work = vault_id(&iphone, "Work");
    // Both vaults are unlocked once in this session; "Work" stays selected.
    for id in [&personal, &work] {
        call(&iphone, json!({"op": "select", "vault_id": id}));
        call(&iphone, json!({"op": "unlock", "passphrase": PASS}));
    }

    mac_a.start_waiter();
    mac_b.start_waiter();
    let waiting_a = mac_a.ask();
    let waiting_b = mac_b.ask();
    let open = open_questions(&iphone, 2);
    let askers: Vec<&str> = open.iter().map(asker_of).collect();
    assert_eq!(
        open.len(),
        2,
        "the questions of both vaults are listed, not only those of the selected vault: {askers:?}"
    );
    let of = |vault: &str| {
        open.iter()
            .find(|question| question["vault_id"] == vault)
            .unwrap_or_else(|| panic!("no question names the vault {vault}: {open:?}"))
    };
    let from_a = of(&personal);
    let from_b = of(&work);
    assert_eq!(asker_of(from_a), "Synthetic MacBook");
    assert_eq!(asker_of(from_b), "Synthetic Mac mini");

    // An answer to the vault that is not selected goes to its own team.
    deny(
        &iphone,
        from_a["qid"].as_str().unwrap(),
        &json!({"vault_id": personal}),
    );
    allow_once(
        &iphone,
        from_b["qid"].as_str().unwrap(),
        &contract_answer_key(),
        &json!({"vault_id": work}),
    );
    assert_eq!(settled(waiting_a).outcome, ApprovalOutcome::Denied);
    assert_eq!(settled(waiting_b).outcome, ApprovalOutcome::Approved);

    // A lock drops the questions of every vault: after it, only a vault unlocked again
    // lists its questions.
    call(&iphone, json!({"op": "lock"}));
    call(&iphone, json!({"op": "unlock", "passphrase": PASS}));
    let waiting_a = mac_a.ask();
    std::thread::sleep(Duration::from_millis(500));
    let list = call(&iphone, json!({"op": "questions_list"}));
    assert!(
        list["questions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|question| question["vault_id"] != personal.as_str()),
        "a locked vault shows no question: {list}"
    );
    drop(waiting_a);
}

/// The relay keeps one push token per device, and the iPhone is a separate device in the
/// team of each vault. A token must reach every team, or the questions of the other
/// vault never wake the iPhone: `push_token_set` goes to the questions team of every
/// context (the app sends the token once per launch, `QuestionsModel.askedForToken`).
#[test]
fn a2_the_push_token_reaches_the_team_of_every_vault() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let mac_a = Mac::with_new_vault(
        root.path(),
        &relay,
        "mac-a",
        "Synthetic MacBook",
        "Personal",
    );
    let mac_b = Mac::with_new_vault(root.path(), &relay, "mac-b", "Synthetic Mac mini", "Work");
    let iphone = phone(root.path(), "iphone", "Test iPhone");
    mac_a.add_iphone(&iphone, ANSWER_PUBLIC);
    mac_b.add_iphone(&iphone, ANSWER_PUBLIC);
    for name in ["Personal", "Work"] {
        let id = vault_id(&iphone, name);
        call(&iphone, json!({"op": "select", "vault_id": id}));
        call(&iphone, json!({"op": "unlock", "passphrase": PASS}));
    }
    call(
        &iphone,
        json!({"op": "push_token_set", "token": "0b".repeat(32), "environment": "development"}),
    );
    let mut teams: Vec<String> = relay
        .push_tokens()
        .into_iter()
        .map(|(team, _, _)| team)
        .collect();
    teams.sort();
    let mut wanted = vec![mac_a.team.clone(), mac_b.team.clone()];
    wanted.sort();
    assert_eq!(teams, wanted, "the token is in the team of each vault");
    // Turning notifications off clears it in every team.
    call(&iphone, json!({"op": "push_token_clear"}));
    assert!(relay.push_tokens().is_empty(), "{:?}", relay.push_tokens());
}

// ---- The contexts of several vaults (stream Q1). ----

/// Mac A with "Personal" and Mac B with "Work", both waiting for questions, and one
/// iPhone that holds both vaults and unlocked each once; "Work" stays selected.
struct TwoVaults {
    root: TempDir,
    relay: FakeRelay,
    mac_a: Mac,
    mac_b: Mac,
    iphone: Core,
    personal: String,
    work: String,
}

fn two_vaults() -> TwoVaults {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let mut mac_a = Mac::with_new_vault(
        root.path(),
        &relay,
        "mac-a",
        "Synthetic MacBook",
        "Personal",
    );
    let mut mac_b = Mac::with_new_vault(root.path(), &relay, "mac-b", "Synthetic Mac mini", "Work");
    let iphone = phone(root.path(), "iphone", "Test iPhone");
    mac_a.add_iphone(&iphone, ANSWER_PUBLIC);
    mac_b.add_iphone(&iphone, ANSWER_PUBLIC);
    let personal = vault_id(&iphone, "Personal");
    let work = vault_id(&iphone, "Work");
    for id in [&personal, &work] {
        call(&iphone, json!({"op": "select", "vault_id": id}));
        call(&iphone, json!({"op": "unlock", "passphrase": PASS}));
    }
    mac_a.start_waiter();
    mac_b.start_waiter();
    TwoVaults {
        root,
        relay,
        mac_a,
        mac_b,
        iphone,
        personal,
        work,
    }
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

/// The IDs of the vaults of `questions_list`, sorted.
fn listed_vaults(list: &Value) -> Vec<String> {
    sorted(
        list["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .map(|vault| vault["vault_id"].as_str().unwrap().to_owned())
            .collect(),
    )
}

/// The open question of `vault`, once it shows.
fn open_of(phone: &Core, vault: &str) -> Value {
    let start = Instant::now();
    loop {
        if let Some(question) = open_questions(phone, 1)
            .into_iter()
            .find(|question| question["vault_id"] == vault)
        {
            return question;
        }
        assert!(start.elapsed() < WAIT, "no open question of {vault}");
    }
}

/// A lock drops the context of every vault: no list, no long poll, no push token, until
/// a vault opens again. A suspend drops them too; `resume` brings back the selected
/// vault only.
#[test]
fn a_lock_drops_the_context_of_every_vault() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    let list = call(iphone, json!({"op": "questions_list"}));
    assert_eq!(
        listed_vaults(&list),
        sorted(vec![setup.personal.clone(), setup.work.clone()]),
        "{list}"
    );
    call(iphone, json!({"op": "lock"}));
    assert_eq!(fails(iphone, json!({"op": "questions_list"})), "locked");
    assert_eq!(
        fails(iphone, json!({"op": "questions_wait", "timeout": 1})),
        "locked"
    );
    assert_eq!(
        fails(
            iphone,
            json!({"op": "push_token_set", "token": "0c".repeat(32), "environment": "development"})
        ),
        "locked"
    );
    let waiting = setup.mac_a.ask();
    call(iphone, json!({"op": "unlock", "passphrase": PASS}));
    let list = call(iphone, json!({"op": "questions_list"}));
    assert_eq!(listed_vaults(&list), vec![setup.work.clone()], "{list}");
    assert_eq!(list["vaults"][0]["selected"], true);
    assert_eq!(list["vaults"][0]["unlocked"], true);
    assert_eq!(list["status"]["team_id"], setup.mac_b.team.as_str());

    // A suspend drops the contexts too: the app in the background holds no key.
    call(
        iphone,
        json!({"op": "questions_unlock", "vault_id": setup.personal, "passphrase": PASS}),
    );
    let qid = open_of(iphone, &setup.personal)["qid"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        iphone,
        json!({"op": "unlock", "passphrase": PASS, "keep": true}),
    );
    call(iphone, json!({"op": "suspend"}));
    assert_eq!(fails(iphone, json!({"op": "questions_list"})), "locked");
    assert_eq!(call(iphone, json!({"op": "resume"}))["unlocked"], true);
    let list = call(iphone, json!({"op": "questions_list"}));
    assert_eq!(listed_vaults(&list), vec![setup.work.clone()], "{list}");
    assert_eq!(
        fails(
            iphone,
            json!({"op": "question_answer", "qid": qid, "vault_id": setup.personal,
                   "kind": "deny", "time": now()})
        ),
        "locked"
    );
    drop(waiting);
}

/// Selecting another vault keeps the questions of both: the list of each stays, with
/// the vault of each question, and a question of a vault that is not selected (and not
/// open) is answered with the keys of its own context.
#[test]
fn selecting_another_vault_keeps_the_questions_of_both() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    let waiting_a = setup.mac_a.ask();
    let waiting_b = setup.mac_b.ask();
    assert_eq!(open_questions(iphone, 2).len(), 2);
    // "Personal" is selected now and stays locked.
    call(iphone, json!({"op": "select", "vault_id": setup.personal}));
    let list = call(iphone, json!({"op": "questions_list"}));
    assert_eq!(
        listed_vaults(&list),
        sorted(vec![setup.personal.clone(), setup.work.clone()]),
        "{list}"
    );
    for vault in list["vaults"].as_array().unwrap() {
        let is_personal = vault["vault_id"] == setup.personal.as_str();
        assert_eq!(vault["selected"], is_personal, "{vault}");
        assert_eq!(vault["unlocked"], false, "{vault}");
        assert_eq!(vault["status"]["registered"], true, "{vault}");
        let name = if is_personal { "Personal" } else { "Work" };
        assert_eq!(vault["vault_name"], name);
    }
    // The old field is of the selected vault.
    assert_eq!(list["status"]["team_id"], setup.mac_a.team.as_str());
    let open = open_questions(iphone, 2);
    assert_eq!(open.len(), 2, "{open:?}");
    let from_b = open
        .iter()
        .find(|question| question["vault_id"] == setup.work.as_str())
        .expect("the question of Work");
    assert_eq!(from_b["vault_name"], "Work");
    assert_eq!(asker_of(from_b), "Synthetic Mac mini");
    let from_a = open
        .iter()
        .find(|question| question["vault_id"] == setup.personal.as_str())
        .expect("the question of Personal");
    // Without `vault_id` the core finds the vault of the question.
    deny(iphone, from_b["qid"].as_str().unwrap(), &json!({}));
    allow_once(
        iphone,
        from_a["qid"].as_str().unwrap(),
        &contract_answer_key(),
        &json!({}),
    );
    assert_eq!(settled(waiting_b).outcome, ApprovalOutcome::Denied);
    assert_eq!(settled(waiting_a).outcome, ApprovalOutcome::Approved);
    // One long poll covers both vaults.
    let waiting = setup.mac_b.ask();
    let start = Instant::now();
    while call(iphone, json!({"op": "questions_wait", "timeout": 5}))["changed"] != true {
        assert!(start.elapsed() < WAIT, "the long poll never woke");
    }
    let next = open_of(iphone, &setup.work);
    deny(iphone, next["qid"].as_str().unwrap(), &json!({}));
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
}

/// An answer that names another vault than the one of its question is refused before
/// anything is signed or sent; the same answer with the right vault goes through.
#[test]
fn an_answer_with_the_wrong_vault_is_refused() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    let waiting = setup.mac_a.ask();
    let question = open_of(iphone, &setup.personal);
    let qid = question["qid"].as_str().unwrap();
    let wrong = json!({"vault_id": setup.work});
    for mut request in [
        json!({"op": "question_answer_string", "qid": qid, "kind": "approve_once"}),
        json!({"op": "question_answer", "qid": qid, "kind": "deny", "time": now()}),
        json!({"op": "question_open", "qid": qid}),
    ] {
        merge(&mut request, &wrong);
        assert_eq!(fails(iphone, request), "wrong_vault");
    }
    // A vault that is not on this iPhone.
    assert_eq!(
        fails(
            iphone,
            json!({"op": "question_answer", "qid": qid, "vault_id": "0123456789abcdef0123456789abcdef",
                   "kind": "deny", "time": now()})
        ),
        "no_vault"
    );
    let opened = call(
        iphone,
        json!({"op": "question_open", "qid": qid, "vault_id": setup.personal}),
    );
    assert_eq!(opened["vault_id"], setup.personal.as_str());
    deny(iphone, qid, &json!({"vault_id": setup.personal}));
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
}

/// A removed vault takes its context with it: its questions and its entry leave the
/// list, and an answer that names it is refused.
#[test]
fn a_removed_vault_has_no_context() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    let waiting = setup.mac_a.ask();
    let qid = open_of(iphone, &setup.personal)["qid"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        iphone,
        json!({"op": "remove_vault", "vault_id": setup.personal, "force": true}),
    );
    let list = call(iphone, json!({"op": "questions_list"}));
    assert_eq!(listed_vaults(&list), vec![setup.work.clone()], "{list}");
    assert!(
        list["questions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|question| question["vault_id"] == setup.work.as_str()),
        "{list}"
    );
    assert_eq!(
        fails(
            iphone,
            json!({"op": "question_answer", "qid": qid, "vault_id": setup.personal,
                   "kind": "deny", "time": now()})
        ),
        "no_vault"
    );
    assert_eq!(
        fails(
            iphone,
            json!({"op": "question_answer", "qid": qid, "kind": "deny", "time": now()})
        ),
        "expired"
    );
    drop(waiting);
}

/// `questions_unlock` makes the context of a vault that is not selected from its
/// passphrase, without opening it for the other calls.
#[test]
fn questions_unlock_makes_the_context_of_another_vault() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    call(iphone, json!({"op": "lock"}));
    call(iphone, json!({"op": "unlock", "passphrase": PASS}));
    assert_eq!(
        fails(
            iphone,
            json!({"op": "questions_unlock", "vault_id": setup.personal,
                   "passphrase": "synthetic-wrong-pass"})
        ),
        "wrong_passphrase"
    );
    let opened = call(
        iphone,
        json!({"op": "questions_unlock", "vault_id": setup.personal, "passphrase": PASS}),
    );
    assert_eq!(opened["vault_id"], setup.personal.as_str());
    assert_eq!(opened["status"]["registered"], true, "{opened}");
    assert_eq!(opened["status"]["team_id"], setup.mac_a.team.as_str());
    // The selected vault stays the open one.
    let info = call(iphone, json!({"op": "info"}));
    assert_eq!(info["selected"], setup.work.as_str());
    assert_eq!(info["unlocked"], true);
    let waiting = setup.mac_a.ask();
    let question = open_of(iphone, &setup.personal);
    deny(iphone, question["qid"].as_str().unwrap(), &json!({}));
    assert_eq!(settled(waiting).outcome, ApprovalOutcome::Denied);
}

/// The push token reaches a vault that opens after `push_token_set`. After
/// `push_token_clear`, the team of a vault that is not open keeps the token until the
/// vault opens, through a list on disk that holds vault IDs only.
#[test]
fn the_push_token_follows_the_vaults_that_open_later() {
    let setup = two_vaults();
    let teams = |relay: &FakeRelay| {
        sorted(
            relay
                .push_tokens()
                .into_iter()
                .map(|(team, _, _)| team)
                .collect(),
        )
    };
    let iphone = &setup.iphone;
    call(iphone, json!({"op": "lock"}));
    call(iphone, json!({"op": "unlock", "passphrase": PASS}));
    let set = call(
        iphone,
        json!({"op": "push_token_set", "token": "0d".repeat(32), "environment": "development"}),
    );
    assert_eq!(set["vaults"].as_array().unwrap().len(), 1, "{set}");
    assert_eq!(set["vaults"][0]["vault_id"], setup.work.as_str());
    assert_eq!(teams(&setup.relay), vec![setup.mac_b.team.clone()]);
    // "Personal" opens later: its team gets the token at its next relay call.
    call(
        iphone,
        json!({"op": "questions_unlock", "vault_id": setup.personal, "passphrase": PASS}),
    );
    call(iphone, json!({"op": "questions_list"}));
    assert_eq!(
        teams(&setup.relay),
        sorted(vec![setup.mac_a.team.clone(), setup.mac_b.team.clone()])
    );

    // Off while only "Work" is open: "Personal" waits on disk.
    call(iphone, json!({"op": "lock"}));
    call(iphone, json!({"op": "unlock", "passphrase": PASS}));
    let cleared = call(iphone, json!({"op": "push_token_clear"}));
    assert_eq!(cleared["cleared"], json!([setup.work]), "{cleared}");
    assert_eq!(cleared["pending"], json!([setup.personal]), "{cleared}");
    assert_eq!(teams(&setup.relay), vec![setup.mac_a.team.clone()]);
    let file = setup.root.path().join("iphone").join("questions-push.json");
    let saved: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(saved, json!({"version": 1, "clear": [setup.personal]}));
    // A new process reads the list; the vault opens, and its team drops the token.
    let TwoVaults {
        root,
        relay,
        iphone,
        personal,
        ..
    } = setup;
    iphone.shutdown();
    drop(iphone);
    let iphone = phone(root.path(), "iphone", "Test iPhone");
    call(&iphone, json!({"op": "unlock", "passphrase": PASS}));
    call(
        &iphone,
        json!({"op": "questions_unlock", "vault_id": personal, "passphrase": PASS}),
    );
    call(&iphone, json!({"op": "questions_list"}));
    assert!(relay.push_tokens().is_empty(), "{:?}", relay.push_tokens());
    let saved: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(saved, json!({"version": 1, "clear": []}));
}

/// The vault file of `vault` on the iPhone of `setup`.
fn vault_file(setup: &TwoVaults, vault: &str) -> PathBuf {
    setup
        .root
        .path()
        .join("iphone")
        .join("vaults")
        .join(format!("{vault}.apassy"))
}

/// `questions_unlock` of `vault` until it is not `busy` (the test opens the file too).
fn unlock_questions(phone: &Core, vault: &str) -> Value {
    loop {
        let request = json!({"op": "questions_unlock", "vault_id": vault, "passphrase": PASS});
        let answer: Value = serde_json::from_str(&phone.call(&request.to_string())).unwrap();
        if answer["error"]["code"] != "busy" {
            return answer;
        }
    }
}

/// A suspend waits for a `questions_unlock` that has the vault file open for its key
/// derivation: when the suspend returns, no file lock is left (iOS ends a suspended app
/// that holds one), and the context of that vault is gone with the others.
#[test]
fn a_suspend_waits_for_questions_unlock_and_leaves_no_file_lock() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    call(iphone, json!({"op": "lock"}));
    call(
        iphone,
        json!({"op": "unlock", "passphrase": PASS, "keep": true}),
    );
    let file = vault_file(&setup, &setup.personal);
    std::thread::scope(|scope| {
        let opening = scope.spawn(|| unlock_questions(iphone, &setup.personal));
        // Wait until the call holds the file: then the suspend comes.
        let start = Instant::now();
        let mut held = false;
        while !held && !opening.is_finished() {
            match Vault::open(&file) {
                Ok(probe) => drop(probe),
                Err(error) => {
                    assert_eq!(error.kind(), apassy::vault::VaultErrorKind::Busy);
                    held = true;
                }
            }
            assert!(
                start.elapsed() < WAIT,
                "questions_unlock never opened the file"
            );
        }
        call(iphone, json!({"op": "suspend"}));
        assert!(
            Vault::open(&file).is_ok(),
            "a file lock outlived the suspend (held during it: {held})"
        );
        let answer = opening.join().unwrap();
        assert!(
            answer["ok"] == true || answer["error"]["code"] == "locked",
            "{answer}"
        );
    });
    assert_eq!(fails(iphone, json!({"op": "questions_list"})), "locked");
    assert_eq!(call(iphone, json!({"op": "resume"}))["unlocked"], true);
    let list = call(iphone, json!({"op": "questions_list"}));
    assert_eq!(listed_vaults(&list), vec![setup.work.clone()], "{list}");
}

/// A `questions_unlock` that runs while its vault is removed never leaves a context of
/// the removed vault.
#[test]
fn a_removal_during_questions_unlock_leaves_no_context() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    call(iphone, json!({"op": "lock"}));
    call(iphone, json!({"op": "unlock", "passphrase": PASS}));
    let started = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let opening = scope.spawn(|| {
            loop {
                started.store(true, std::sync::atomic::Ordering::SeqCst);
                let answer = unlock_questions(iphone, &setup.personal);
                if answer["error"]["code"] == "no_vault" {
                    return;
                }
                assert!(
                    answer["ok"] == true || answer["error"]["code"] == "locked",
                    "{answer}"
                );
            }
        });
        while !started.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(100));
        call(
            iphone,
            json!({"op": "remove_vault", "vault_id": setup.personal, "force": true}),
        );
        opening.join().unwrap();
    });
    let list = call(iphone, json!({"op": "questions_list"}));
    assert_eq!(listed_vaults(&list), vec![setup.work.clone()], "{list}");
    assert!(!vault_file(&setup, &setup.personal).exists());
}

/// `questions_unlock` of the open selected vault checks the passphrase too: the app keeps
/// the passphrase behind Face ID after it.
#[test]
fn questions_unlock_of_the_open_vault_checks_the_passphrase() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    assert_eq!(
        fails(
            iphone,
            json!({"op": "questions_unlock", "vault_id": setup.work,
                   "passphrase": "synthetic-wrong-pass"})
        ),
        "wrong_passphrase"
    );
    assert_eq!(
        fails(
            iphone,
            json!({"op": "questions_unlock", "vault_id": setup.work, "passphrase": ""})
        ),
        "wrong_passphrase"
    );
    let opened = call(
        iphone,
        json!({"op": "questions_unlock", "vault_id": setup.work, "passphrase": PASS}),
    );
    assert_eq!(opened["status"]["team_id"], setup.mac_b.team.as_str());
    assert_eq!(call(iphone, json!({"op": "info"}))["unlocked"], true);
}

/// Removing a vault takes the push token of this iPhone off its questions team while the
/// relay key is in memory. When the relay does not answer, the next read tries again.
#[test]
fn removing_a_vault_clears_its_push_token_now_or_at_the_next_read() {
    let setup = two_vaults();
    let iphone = &setup.iphone;
    call(
        iphone,
        json!({"op": "push_token_set", "token": "0f".repeat(32), "environment": "development"}),
    );
    let teams = |relay: &FakeRelay| {
        sorted(
            relay
                .push_tokens()
                .into_iter()
                .map(|(team, _, _)| team)
                .collect(),
        )
    };
    assert_eq!(
        teams(&setup.relay),
        sorted(vec![setup.mac_a.team.clone(), setup.mac_b.team.clone()])
    );
    // "Personal" is not selected: the device stays on the relay (`force`), and its
    // token goes; the relay fails the first try.
    setup.relay.fail_next("DELETE /v1/push/token", 1, 500);
    let removed = call(
        iphone,
        json!({"op": "remove_vault", "vault_id": setup.personal, "force": true}),
    );
    assert_eq!(removed["left_relay"], false);
    assert_eq!(
        teams(&setup.relay),
        sorted(vec![setup.mac_a.team.clone(), setup.mac_b.team.clone()]),
        "the relay failed"
    );
    call(iphone, json!({"op": "questions_list"}));
    assert_eq!(teams(&setup.relay), vec![setup.mac_b.team.clone()]);
}
