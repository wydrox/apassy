//! Two Macs on a fake relay, for the Swift test of an iPhone with two vaults (development
//! only, synthetic values). "Synthetic MacBook" holds the vault "Personal" and "Synthetic
//! Mac mini" holds "Work"; each has its own relay sync team with the questions on and runs
//! the app's questions waiter (`QuestionsWorker`). The fake relay is the in-process one of
//! the Mac's tests, on 127.0.0.1.
//!
//! The program talks JSON lines. On stdout:
//!
//! - `{"event":"ready","passphrase":…,"links":{"Personal":…,"Work":…}}`: the device links
//!   of "Add a device…" of both Macs;
//! - `{"event":"confirmed","vault":…}`: the Mac confirmed the first device that asked;
//! - `{"event":"settled","vault":…,"outcome":…}`: the run of an `ask` got its answer
//!   (`approved`, `denied`, … or `refused`).
//!
//! On stdin, the line `ask` makes each Mac ask one question. End of input ends the program.
//! Diagnostics go to stderr.
//!
//!   cargo run -p apassy-core --example questions_macs

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use apassy::broker::action_kind::ActionKind;
use apassy::broker::approvals::{
    AnswerKind, ApprovalQueue, OwnerGate, PendingRun, QuestionInfo, QuestionItem, QuestionRefusal,
    Settled,
};
use apassy::broker::project::Project;
use apassy::contracts::CredentialKind;
use apassy::questions::{QuestionsConfig, QuestionsWorker};
use apassy::relay::membership::{enable_questions, register_linked_device};
use apassy::sync::{RelayConfig, RelaySync};
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use fake_relay::FakeRelay;
use serde_json::json;

const PASS: &str = "synthetic-multi-host-pass";

type SharedVault = Arc<Mutex<Option<Vault>>>;

/// One JSON line on stdout, flushed at once.
fn emit(value: serde_json::Value) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{value}").expect("stdout");
    out.flush().expect("flush");
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
            reason: Default::default(),
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

/// One Mac with its vault, its relay sync, its approval queue, and its questions waiter.
struct Mac {
    sync: RelaySync,
    vault: SharedVault,
    queue: Arc<ApprovalQueue>,
    team: String,
    agent: u64,
    items: [u64; 2],
    epoch: [u8; 32],
    /// Kept so the waiter runs for the life of the program.
    _worker: QuestionsWorker,
}

impl Mac {
    /// A Mac with a new vault named `vault_name` on a new relay sync team, with the
    /// questions on and the waiter started.
    fn start(root: &Path, relay: &FakeRelay, name: &'static str, vault_name: &str) -> Self {
        let data = root.join(vault_name).join("Apassy");
        std::fs::create_dir_all(&data).expect("data dir");
        let vault_path = data.join("vault.db");
        let sync = RelaySync::new(RelayConfig::in_data_dir(
            &data,
            &vault_path,
            &relay.url,
            "vault",
        ));
        let mut vault = Vault::create(&vault_path, PASS).expect("create");
        vault.unlock(PASS).expect("unlock");
        let shop = vault
            .add(secret_item("Shop database", "SYNTH-db"))
            .expect("item")
            .id;
        let api = vault
            .add(secret_item("API token", "SYNTH-api"))
            .expect("item")
            .id;
        let agent = vault.register_agent("claude-code").expect("agent").0.id;
        let report = sync
            .create_team(&mut vault, vault_name, &relay.team_code(), name)
            .expect("team");
        enable_questions(&mut vault, name).expect("questions");
        sync.sync(&mut vault).expect("sync");
        let epoch = vault.epoch();
        let vault: SharedVault = Arc::new(Mutex::new(Some(vault)));
        let queue = Arc::new(ApprovalQueue::new());
        let worker = QuestionsWorker::start(
            Arc::clone(&queue),
            Arc::clone(&vault),
            OwnerGate::new(Arc::clone(&vault), None),
            QuestionsConfig {
                question_wait: Duration::from_secs(300),
                tick: Duration::from_millis(50),
                device_name: name.to_owned(),
                feed: false,
                ..QuestionsConfig::default()
            },
        );
        Self {
            sync,
            vault,
            queue,
            team: report.link.team_id,
            agent,
            items: [shop, api],
            epoch,
            _worker: worker,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self
            .vault
            .lock()
            .expect("vault lock")
            .as_mut()
            .expect("open"))
    }

    /// A run of agent `claude-code` starts to wait on this Mac.
    fn ask(&self) -> JoinHandle<Result<Settled, QuestionRefusal>> {
        let queue = Arc::clone(&self.queue);
        let (agent, epoch) = (self.agent, self.epoch);
        let run = run(self.items);
        std::thread::spawn(move || {
            queue.wait_for_question(run, agent, epoch, [0; 32], Duration::from_secs(120), || {
                true
            })
        })
    }
}

fn main() {
    let root = tempfile::TempDir::new().expect("temp dir");
    let relay = FakeRelay::start();
    let macs = [
        (
            "Personal",
            Arc::new(Mac::start(
                root.path(),
                &relay,
                "Synthetic MacBook",
                "Personal",
            )),
        ),
        (
            "Work",
            Arc::new(Mac::start(
                root.path(),
                &relay,
                "Synthetic Mac mini",
                "Work",
            )),
        ),
    ];

    // "Add a device…" on each Mac: a link, and a thread that confirms the first device
    // that asks (the owner check, then `relay_register_linked` in the app).
    let mut links = serde_json::Map::new();
    let mut confirmers = Vec::new();
    for (vault_name, mac) in &macs {
        let code = mac.with(|vault| mac.sync.create_link(&*vault).expect("link"));
        links.insert((*vault_name).to_owned(), json!(code.link.as_str()));
        let mac = Arc::clone(mac);
        let vault_name = *vault_name;
        confirmers.push(std::thread::spawn(move || {
            loop {
                let confirmed = mac.with(|vault| {
                    let links = mac
                        .sync
                        .pending_links(&*vault, Some(&code))
                        .expect("pending links");
                    if links.len() != 1 {
                        return false;
                    }
                    let device = mac.sync.confirm_link(&*vault, &links[0]).expect("confirm");
                    register_linked_device(
                        vault,
                        &mac.team,
                        device.id,
                        &links[0].device_name,
                        &links[0].public_key,
                    )
                    .expect("register")
                    .expect("an iPhone row");
                    mac.sync.sync(vault).expect("sync");
                    true
                });
                if confirmed {
                    emit(json!({"event": "confirmed", "vault": vault_name}));
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }));
    }
    emit(json!({"event": "ready", "passphrase": PASS, "links": links}));

    let mut watchers = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim() != "ask" {
            eprintln!("questions_macs: unknown command {line:?}");
            continue;
        }
        for (vault_name, mac) in &macs {
            let handle = mac.ask();
            let vault_name = *vault_name;
            watchers.push(std::thread::spawn(move || {
                let outcome = match handle.join() {
                    Ok(Ok(settled)) => format!("{:?}", settled.outcome).to_lowercase(),
                    _ => "refused".to_owned(),
                };
                emit(json!({"event": "settled", "vault": vault_name, "outcome": outcome}));
            }));
        }
    }
    // End of input: the process ends; the threads wait on nothing that matters.
    drop((confirmers, watchers));
    std::process::exit(0);
}
