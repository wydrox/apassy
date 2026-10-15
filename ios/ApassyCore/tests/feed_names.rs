//! The names of a feed action, end to end (contract relay-feed-v1 sections 9.3, 9.5, 15;
//! contract ios-core-v1 section 5.12).
//!
//! The Mac is the app's own code: its vault, its relay sync, the owner gate, and the
//! questions waiter, which publishes the feed and checks the actions. The iPhone is a real
//! core, driven through the JSON calls as the app makes them; "Face ID" signs with the
//! answer key of the contract test vectors. The relay is the in-process fake of the Mac
//! tests (`tests/common/fake_relay.rs`).
//!
//! - A new Mac says in its feed that it checks the names; the iPhone signs the names it
//!   shows (v2), and the Mac applies the removal.
//! - A holder of the question key who works with the relay plants a feed with a false
//!   agent name on real ids. The iPhone signs what it shows; the Mac refuses it as
//!   `stale`, and the row stays. A later planted feed without the mark does not bring
//!   back actions without the names: the iPhone signs them for every Mac.
//!
//! Synthetic values only; no network beyond 127.0.0.1.

#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

/// The fake relay reads the app's sync module under this name.
use apassy::sync as relay_api;

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::broker::approvals::{ApprovalQueue, OwnerGate};
use apassy::contracts::CredentialKind;
use apassy::questions::envelope::Sealed;
use apassy::questions::feed::{feed_aad, names_digest};
use apassy::questions::{QuestionsConfig, QuestionsWorker};
use apassy::relay::membership::{enable_questions, questions_membership, register_linked_device};
use apassy::sync::{DeviceKey, RelayConfig, RelaySync, decode_b64u, encode_b64u};
use apassy::vault::exceptions::ExceptionKind;
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use apassy_core::Core;
use fake_relay::FakeRelay;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "synthetic-feed-names-pass";
/// The answer key of the contract test vectors (relay-questions-v1 section 20).
const ANSWER_PRIVATE: &str = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b";
const ANSWER_PUBLIC: &str =
    "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
const MAC_NAME: &str = "Synthetic MacBook";
const WAIT: Duration = Duration::from_secs(30);

type SharedVault = Arc<Mutex<Option<Vault>>>;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn answer_key() -> DeviceKey {
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

fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).unwrap();
    assert_eq!(answer["ok"], true, "{request} -> {answer}");
    answer["result"].clone()
}

fn wait_until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(found) = probe() {
            return found;
        }
        assert!(start.elapsed() < WAIT, "waited for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The Mac: a vault on a relay sync team with the questions on, an agent "Claude Code"
/// with a "Not for this agent" exception on "Shop database" and an "Only these items"
/// row on "API token", and, once started, its questions waiter with the feed on.
struct Mac {
    sync: RelaySync,
    vault: SharedVault,
    worker: Option<QuestionsWorker>,
    team: String,
    agent: u64,
}

impl Mac {
    fn new(root: &Path, relay: &FakeRelay) -> Self {
        let data = root.join("mac").join("Apassy");
        fs::create_dir_all(&data).unwrap();
        let vault_path = data.join("vault.db");
        let sync = RelaySync::new(RelayConfig::in_data_dir(
            &data,
            &vault_path,
            &relay.url,
            "vault",
        ));
        let mut vault = Vault::create(&vault_path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let shop = vault
            .add(secret_item("Shop database", "SYNTH-db"))
            .unwrap()
            .id;
        let api = vault.add(secret_item("API token", "SYNTH-api")).unwrap().id;
        let agent = vault.register_agent("Claude Code").unwrap().0.id;
        vault
            .add_agent_exception(agent, shop, ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(agent, api, ExceptionKind::Only)
            .unwrap();
        let report = sync
            .create_team(&mut vault, "Personal", &relay.team_code(), MAC_NAME)
            .unwrap();
        enable_questions(&mut vault, MAC_NAME).unwrap();
        sync.sync(&mut vault).unwrap();
        Self {
            sync,
            vault: Arc::new(Mutex::new(Some(vault))),
            worker: None,
            team: report.link.team_id,
            agent,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        f(self.vault.lock().unwrap().as_mut().unwrap())
    }

    /// The relay device id of this Mac in the questions team.
    fn device_id(&self) -> u64 {
        self.with(|vault| questions_membership(vault).unwrap().unwrap().device_id)
    }

    fn start(&mut self) {
        self.worker = Some(QuestionsWorker::start(
            Arc::new(ApprovalQueue::new()),
            Arc::clone(&self.vault),
            OwnerGate::new(Arc::clone(&self.vault), None),
            QuestionsConfig {
                question_wait: Duration::from_secs(300),
                tick: Duration::from_millis(50),
                device_name: MAC_NAME.to_owned(),
                feed: true,
                feed_every: Duration::from_secs(1),
                feed_beat: Duration::from_secs(600),
            },
        ));
    }

    /// "Add a device…" for the iPhone, as `multi_device_questions.rs` does it: the
    /// iPhone gets the vault, with its items and the Mac's row.
    fn add_iphone(&self, phone: &Core) {
        let code = self.with(|vault| self.sync.create_link(&*vault).unwrap());
        let started = call(
            phone,
            json!({"op": "join_start", "link": code.link.as_str(), "answer_key": ANSWER_PUBLIC}),
        );
        assert_eq!(started["state"], "waiting", "{started}");
        self.with(|vault| {
            let links = self.sync.pending_links(&*vault, Some(&code)).unwrap();
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
        wait_until("the join", || {
            (call(phone, json!({"op": "join_poll"}))["state"] == "ready").then_some(())
        });
        call(phone, json!({"op": "join_finish", "passphrase": PASS}));
    }

    fn kinds(&self) -> Vec<ExceptionKind> {
        self.with(|vault| {
            vault
                .agent_exceptions(self.agent)
                .unwrap()
                .into_iter()
                .map(|exception| exception.kind)
                .collect()
        })
    }

    fn activity(&self) -> Vec<String> {
        self.with(|vault| {
            vault
                .recent_activity(100)
                .unwrap()
                .into_iter()
                .filter(|row| row.operation == apassy::questions::feed::ACTIVITY_OPERATION)
                .map(|row| row.reason)
                .collect()
        })
    }

    /// The Mac's feed on the relay once its `seq` is above `above` and has not changed
    /// for a second: its `seq` and its plaintext, opened with the question key.
    fn settled_feed(&self, relay: &FakeRelay, above: u64) -> (u64, Vec<u8>) {
        let id = self.device_id();
        let mut last = None;
        let mut since = Instant::now();
        wait_until("a quiet feed of the Mac", || {
            let (seq, key_id, nonce, ciphertext) = relay.feed_of(id)?;
            if seq <= above {
                return None;
            }
            if last != Some(seq) {
                last = Some(seq);
                since = Instant::now();
                return None;
            }
            if since.elapsed() < Duration::from_secs(1) {
                return None;
            }
            let key = self.with(|vault| vault.question_key().unwrap().unwrap());
            let sealed = Sealed {
                key_id: key_id.clone(),
                nonce,
                ciphertext,
            };
            let aad = feed_aad(&self.team, id, seq, &key_id);
            Some((seq, sealed.open(&key, &aad)?.to_vec()))
        })
    }

    /// A holder of the question key seals `plaintext` as the feed `seq` of this Mac, and
    /// the relay serves it.
    fn plant(&self, relay: &FakeRelay, seq: u64, plaintext: &[u8]) {
        let id = self.device_id();
        let key = self.with(|vault| vault.question_key().unwrap().unwrap());
        let aad = feed_aad(&self.team, id, seq, &key.key_id());
        let sealed = Sealed::new(&key, &aad, plaintext).unwrap();
        relay.plant_feed(id, &sealed.key_id, &sealed.nonce, &sealed.ciphertext);
    }
}

fn phone(root: &Path) -> Core {
    let data = root.join("iphone");
    fs::create_dir_all(&data).unwrap();
    let config = json!({"data_dir": data, "device_name": "Test iPhone", "role": "app"});
    Core::new(&config.to_string()).expect("core")
}

/// The first Mac of the first vault in the iPhone's list.
fn shown_mac(phone: &Core) -> Value {
    call(phone, json!({"op": "feed_list"}))["vaults"][0]["macs"][0].clone()
}

fn request(phone: &Core, mac: &Value, exception: &Value) -> Value {
    let vault_id = call(phone, json!({"op": "feed_list"}))["vaults"][0]["vault_id"].clone();
    json!({"op": "feed_action_string", "vault_id": vault_id, "mac_device": mac["device"],
           "agent": mac["agents"][0]["id"], "item": exception["item"],
           "kind": exception["kind"], "created_at": exception["created_at"],
           "feed_seq": mac["seq"]})
}

/// Remove `exception` as the app does: the action string, "Face ID" when it needs it,
/// the action, and the Mac's outcome. Returns the action string and the outcome.
fn remove(phone: &Core, mac: &Value, exception: &Value) -> (String, Value) {
    let prepared = call(phone, request(phone, mac, exception));
    // The names that the action signs are those the list showed.
    assert_eq!(prepared["agent_name"], mac["agents"][0]["name"]);
    assert_eq!(prepared["mac_name"], mac["name"]);
    let shown_title = match exception["title"].as_str() {
        Some(title) if !title.is_empty() => title,
        _ => exception["item_title"].as_str().unwrap(),
    };
    assert_eq!(prepared["credential_name"], shown_title);
    let mut send = request(phone, mac, exception);
    send["op"] = json!("feed_action");
    send["action_id"] = prepared["action_id"].clone();
    send["time"] = prepared["time"].clone();
    let text = prepared["action_string"].as_str().unwrap().to_owned();
    if prepared["needs_face_id"] == true {
        send["signature"] = json!(encode_b64u(&answer_key().sign(text.as_bytes()).unwrap()));
    }
    call(phone, send);
    let outcome = wait_until("the outcome", || {
        let state = call(
            phone,
            json!({"op": "feed_action_wait", "action_id": prepared["action_id"], "timeout": 5}),
        );
        (state["outcome"] != "pending").then_some(state)
    });
    (text, outcome)
}

fn exception<'a>(mac: &'a Value, kind: &str) -> &'a Value {
    mac["agents"][0]["exceptions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|exception| exception["kind"] == kind)
        .unwrap()
}

#[test]
fn a_removal_with_the_names_the_owner_saw_applies_on_the_mac() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let mut mac = Mac::new(root.path(), &relay);
    let iphone = phone(root.path());
    mac.add_iphone(&iphone);
    mac.start();
    let (_, plaintext) = mac.settled_feed(&relay, 0);
    assert_eq!(plaintext.last(), Some(&b'\n'), "the feed says v2");

    let shown = wait_until("the agents on the iPhone", || {
        let mac = shown_mac(&iphone);
        (mac["agents"][0]["exceptions"].as_array()?.len() == 2).then_some(mac)
    });
    assert_eq!(shown["name"], MAC_NAME);
    assert_eq!(shown["agents"][0]["name"], "Claude Code");
    let never = exception(&shown, "never").clone();
    // The iPhone holds the item: its own title.
    assert_eq!(never["title"], "Shop database");
    let (text, outcome) = remove(&iphone, &shown, &never);
    let names = names_digest("Claude Code", "Shop database", MAC_NAME);
    assert!(text.starts_with("apassy-feed-action-v2\n"), "{text}");
    assert!(text.ends_with(&format!("\nnames:{names}")), "{text}");
    assert_eq!(outcome["outcome"], "applied", "{outcome}");
    assert_eq!(outcome["verified"], true);
    assert_eq!(mac.kinds(), vec![ExceptionKind::Only]);
    assert!(
        mac.activity().iter().any(|line| line
            == "Removed on Test iPhone: “Not for this agent” for Claude Code and Shop database"),
        "no note for a v2 action: {:?}",
        mac.activity()
    );

    // "Only these items": the same names, signed by the core with the relay key.
    let shown = wait_until("the feed without the row", || {
        let mac = shown_mac(&iphone);
        (mac["agents"][0]["exceptions"].as_array()?.len() == 1).then_some(mac)
    });
    let only = exception(&shown, "only").clone();
    let (text, outcome) = remove(&iphone, &shown, &only);
    assert!(text.starts_with("apassy-feed-action-v2\n"));
    assert!(text.ends_with(&format!(
        "\nnames:{}",
        names_digest("Claude Code", "API token", MAC_NAME)
    )));
    assert_eq!(outcome["outcome"], "applied", "{outcome}");
    assert!(mac.kinds().is_empty());
}

#[test]
fn a_planted_feed_with_false_names_is_refused_and_the_row_stays() {
    let root = TempDir::new().unwrap();
    let relay = FakeRelay::start();
    let mut mac = Mac::new(root.path(), &relay);
    let iphone = phone(root.path());
    mac.add_iphone(&iphone);
    mac.start();
    // The Mac's feed, before the iPhone reads it: the relay serves a feed of the same
    // `seq` with the real ids and another agent name instead.
    let (seq, plaintext) = mac.settled_feed(&relay, 0);
    let lie = |plaintext: &[u8], mark: bool| {
        let mut feed: Value = serde_json::from_slice(plaintext).unwrap();
        feed["agents"][0]["name"] = json!("Scratch Bot");
        let mut text = feed.to_string().into_bytes();
        if mark {
            text.push(b'\n');
        }
        text
    };
    mac.plant(&relay, seq, &lie(&plaintext, true));
    let shown = shown_mac(&iphone);
    assert_eq!(shown["seq"], seq);
    assert_eq!(shown["agents"][0]["name"], "Scratch Bot", "{shown}");
    let never = exception(&shown, "never").clone();
    let rows = mac.kinds();
    let (text, outcome) = remove(&iphone, &shown, &never);
    assert!(text.ends_with(&format!(
        "\nnames:{}",
        names_digest("Scratch Bot", "Shop database", MAC_NAME)
    )));
    assert_eq!(outcome["outcome"], "stale", "{outcome}");
    assert_eq!(outcome["verified"], true);
    assert_eq!(
        outcome["reason"],
        "the names on the iPhone did not match this Mac"
    );
    assert_eq!(mac.kinds(), rows, "the row stays");

    // A later planted feed without the mark: the iPhone still signs the names (it always
    // does), and the list says that the Mac lacks the mark.
    mac.with(|vault| vault.set_agent_note(mac.agent, "A new note.").unwrap());
    let (newer, plaintext) = mac.settled_feed(&relay, seq);
    mac.plant(&relay, newer, &lie(&plaintext, false));
    let shown = shown_mac(&iphone);
    assert_eq!(shown["seq"], newer);
    assert_eq!(shown["agents"][0]["name"], "Scratch Bot");
    assert_eq!(shown["checks_names"], false);
    let only = exception(&shown, "only").clone();
    let (text, outcome) = remove(&iphone, &shown, &only);
    assert!(text.starts_with("apassy-feed-action-v2\n"), "{text}");
    assert_eq!(outcome["outcome"], "stale", "{outcome}");
    assert_eq!(mac.kinds(), rows, "the row stays");

    // The Mac's own next feed shows the true names again, and they apply.
    mac.with(|vault| vault.set_agent_note(mac.agent, "Another note.").unwrap());
    let (truth, _) = mac.settled_feed(&relay, newer);
    let shown = wait_until("the true feed", || {
        let mac = shown_mac(&iphone);
        (mac["seq"] == truth).then_some(mac)
    });
    assert_eq!(shown["agents"][0]["name"], "Claude Code");
    let (_, outcome) = remove(&iphone, &shown, exception(&shown, "never"));
    assert_eq!(outcome["outcome"], "applied", "{outcome}");
    assert_eq!(mac.kinds(), vec![ExceptionKind::Only]);
}
