//! The owner's host (`apassy-team host`) against a real relay in process. The host
//! loop is the real one; the person at the terminal is a closure that gives the
//! answers a test wants, and records what it was asked.

#[path = "common/relay.rs"]
mod relay;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use apassy::broker::packs::RuleSet;
use apassy_relay::api::HostRequestView;
use apassy_relay::cli::client::Client;
use apassy_relay::cli::host::{Answer, HostContext, HostOptions, serve};
use apassy_relay::cli::keystore::{KeyEntry, KeyStore};
use apassy_relay::config::UpstreamOptions;
use apassy_relay::hostkeys;
use apassy_relay::secret::SecretString;
use relay::{CANARY, CANARY2, TestRelay, start, start_with};
use serde_json::{Value, json};

const USER: &str = "Please check the repository state.";

/// What the person was shown.
#[derive(Debug, Clone)]
struct Asked {
    run_id: u64,
    /// The environment of each item, from the key store of the host.
    environments: Vec<String>,
    why: String,
}

struct Host {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    asked: Arc<Mutex<Vec<Asked>>>,
}

impl Host {
    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }

    fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// Starts the host loop on a thread. `answer` is the person.
fn start_host(
    relay: &TestRelay,
    keys_dir: &Path,
    options: HostOptions,
    mut answer: impl FnMut(&HostRequestView) -> Answer + Send + 'static,
) -> Host {
    let stop = Arc::new(AtomicBool::new(false));
    let asked: Arc<Mutex<Vec<Asked>>> = Arc::default();
    let (stop2, asked2) = (stop.clone(), asked.clone());
    let url = relay.url.clone();
    let edge = relay.edge_secret.clone();
    let owner = relay.owner_token.clone();
    let dir = keys_dir.to_path_buf();
    let team = relay.team_id.clone();
    let thread = std::thread::spawn(move || {
        let client = Client::new(
            &url,
            Some(&SecretString::new(owner)),
            Some(&SecretString::new(edge)),
        );
        let store = KeyStore::at(dir);
        let rules = RuleSet::builtin().unwrap();
        let ctx = HostContext {
            team_id: &team,
            client: &client,
            store: &store,
            options,
            rules: &rules,
            poll_secs: 1,
        };
        let mut person = |request: &HostRequestView, local: &[&KeyEntry], why: &str| {
            asked2.lock().unwrap().push(Asked {
                run_id: request.run_id.0,
                environments: local.iter().map(|e| e.environment.clone()).collect(),
                why: why.to_string(),
            });
            answer(request)
        };
        serve(&ctx, &mut person, &stop2).unwrap();
    });
    Host {
        stop,
        thread: Some(thread),
        asked,
    }
}

/// An item that the owner adds with the CLI's steps: sealed, uploaded, and its key in
/// the key store of the host.
fn add_hosted_item(
    relay: &TestRelay,
    store: &KeyStore,
    collection: u64,
    env_name: &str,
    value: &str,
    environment: &str,
    provider: &str,
) -> u64 {
    let sealed = relay::seal(value);
    let body = relay::item_request(
        collection,
        env_name,
        &sealed,
        json!({"provider": provider, "environment": environment}),
    );
    let created = relay.ok("POST", "/v1/items", &relay.owner_token, Some(&body));
    let id = created["id"].as_u64().unwrap();
    store
        .add(KeyEntry {
            relay_url: relay.url.clone(),
            team: "Test Team".to_string(),
            team_id: Some(relay.team_id.clone()),
            uid: sealed.uid.clone(),
            item_id: Some(id),
            name: format!("Item {env_name}"),
            env_name: env_name.to_string(),
            environment: environment.to_string(),
            hosts: created["hosts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h.as_str().unwrap().to_string())
                .collect(),
            risk: "high".to_string(),
            scope: "admin".to_string(),
            reversibility: "irreversible".to_string(),
            key: SecretString::new(hostkeys::encode_key(&sealed.key).to_string()),
            created_at: 1,
        })
        .unwrap();
    id
}

struct World {
    relay: TestRelay,
    dir: tempfile::TempDir,
    store: KeyStore,
    agent: String,
    stripe: u64,
    github: u64,
    collection: u64,
}

/// A relay with a collection, a staging Stripe item and a production GitHub item (both
/// with keys in the key store), one member with a grant, and one agent.
fn world() -> World {
    world_with(start(UpstreamOptions::default()))
}

fn world_with(relay: TestRelay) -> World {
    let dir = tempfile::tempdir().unwrap();
    let store = KeyStore::at(dir.path().join("apassy-team"));
    let collection = relay.add_collection("payments", json!({}));
    let stripe = add_hosted_item(
        &relay,
        &store,
        collection,
        "STRIPE_API_KEY",
        CANARY,
        "staging",
        "stripe",
    );
    let github = add_hosted_item(
        &relay,
        &store,
        collection,
        "GITHUB_TOKEN",
        CANARY2,
        "production",
        "github",
    );
    let (member_id, member_token) = relay.join_member("member", "alice");
    relay.ok(
        "POST",
        "/v1/grants",
        &relay.owner_token,
        Some(&json!({"collection_id": collection, "member_id": member_id})),
    );
    let agent = relay.ok(
        "POST",
        "/v1/agents",
        &member_token,
        Some(&json!({"name": "alice-agent"})),
    );
    World {
        relay,
        dir,
        store,
        agent: agent["secret"].as_str().unwrap().to_string(),
        stripe,
        github,
        collection,
    }
}

impl World {
    fn ask_for(&self, items: &[u64], command: &[&str], request: Option<&str>) -> u64 {
        let mut body = json!({
            "items": items, "command": command, "purpose": "check the account", "cwd": "/work",
        });
        if let Some(text) = request {
            body["user_request"] = json!(text);
        }
        let (status, answer) = self.relay.run(&self.agent, &body);
        assert_eq!(status, 200, "{answer}");
        assert_eq!(answer["result"]["status"], "pending", "{answer}");
        answer["result"]["run_id"].as_u64().unwrap()
    }

    /// Waits until the run is decided. Returns the agent's view.
    fn decided(&self, run: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let view = self
                .relay
                .ok("GET", &format!("/v1/runs/{run}?wait=5"), &self.agent, None);
            if view["status"] != "pending" {
                return view;
            }
            assert!(Instant::now() < deadline, "run {run} is still pending");
        }
    }

    fn log(&self) -> Vec<Value> {
        let text = std::fs::read_to_string(self.store.log_path()).unwrap_or_default();
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn start_host(
        &self,
        options: HostOptions,
        answer: impl FnMut(&HostRequestView) -> Answer + Send + 'static,
    ) -> Host {
        start_host(&self.relay, self.store.dir(), options, answer)
    }
}

fn never_asked(_: &HostRequestView) -> Answer {
    panic!("the person must not be asked");
}

#[test]
fn a_known_safe_staging_run_is_released_without_a_question() {
    let world = world();
    let host = world.start_host(HostOptions::default(), never_asked);
    let run = world.ask_for(
        &[world.stripe],
        &["stripe", "balance", "retrieve"],
        Some(USER),
    );
    let view = world.decided(run);
    assert_eq!(view["status"], "ready", "{view}");
    assert_eq!(view["decided_by"], "host");
    assert_eq!(view["note"], "Released automatically: known safe command.");
    assert!(view["session"]["env"]["STRIPE_API_KEY"].is_string());
    host.finish();
    let log = world.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0]["run_id"], run);
    assert_eq!(log[0]["decision"], "auto");
    assert_eq!(log[0]["agent"], "alice-agent");
    assert_eq!(log[0]["member"], "alice");
    assert_eq!(log[0]["items"][0]["name"], "Item STRIPE_API_KEY");
    assert_eq!(log[0]["items"][0]["uid"].as_str().unwrap().len(), 32);
    // The log holds no key and no value.
    let text = std::fs::read_to_string(world.store.log_path()).unwrap();
    for entry in world.store.load().unwrap() {
        assert!(!text.contains(entry.key.expose()));
    }
    assert!(!text.contains(CANARY));
}

#[test]
fn a_production_item_asks_and_the_person_sees_the_local_environment() {
    let world = world();
    let answers = Arc::new(Mutex::new(vec![Answer::No, Answer::Yes]));
    let host = world.start_host(HostOptions::default(), {
        let answers = answers.clone();
        move |_| answers.lock().unwrap().remove(0)
    });
    let denied = world.ask_for(&[world.github], &["git", "status"], Some(USER));
    let view = world.decided(denied);
    assert_eq!(view["status"], "denied");
    assert_eq!(view["code"], "approval_denied");
    assert_eq!(view["note"], "Denied on the host.");
    assert_eq!(view["decided_by"], "host");
    let approved = world.ask_for(
        &[world.github, world.stripe],
        &["git", "status"],
        Some(USER),
    );
    let view = world.decided(approved);
    assert_eq!(view["status"], "ready", "{view}");
    assert_eq!(view["note"], "Approved on the host.");
    let asked = host.asked();
    assert_eq!(asked.len(), 2);
    assert_eq!(asked[0].run_id, denied);
    assert_eq!(asked[0].environments, vec!["production"]);
    assert!(
        asked[0].why.to_lowercase().contains("production"),
        "{}",
        asked[0].why
    );
    assert_eq!(asked[1].environments, vec!["production", "staging"]);
    host.finish();
    let decisions: Vec<String> = world
        .log()
        .iter()
        .map(|l| l["decision"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(decisions, vec!["denied", "approved"]);
}

#[test]
fn a_command_that_is_not_known_safe_asks_and_no_terminal_denies() {
    let world = world();
    let host = world.start_host(HostOptions::default(), |_| Answer::NoTerminal);
    let run = world.ask_for(&[world.stripe], &["python3", "script.py"], Some(USER));
    let view = world.decided(run);
    assert_eq!(view["status"], "denied");
    assert_eq!(view["code"], "approval_denied");
    assert_eq!(view["note"], "No one at the host.");
    assert_eq!(host.asked().len(), 1);
    assert!(
        host.asked()[0].why.contains("relay"),
        "{:?}",
        host.asked()[0]
    );
    host.finish();
    assert_eq!(world.log()[0]["decision"], "denied");
}

#[test]
fn ask_all_asks_even_for_a_run_that_would_be_released() {
    let world = world();
    let options = HostOptions {
        ask_all: true,
        ..HostOptions::default()
    };
    let host = world.start_host(options, |_| Answer::Yes);
    let run = world.ask_for(&[world.stripe], &["git", "status"], Some(USER));
    let view = world.decided(run);
    assert_eq!(view["status"], "ready");
    assert_eq!(view["note"], "Approved on the host.");
    assert_eq!(host.asked().len(), 1);
    assert!(host.asked()[0].why.contains("--ask-all"));
    host.finish();
    assert_eq!(world.log()[0]["decision"], "approved");
}

#[test]
fn an_item_that_is_not_in_the_key_store_is_denied_without_a_question() {
    let world = world();
    // The item is on the relay, but this host never had its key: someone with the
    // owner's token, or a relay that was taken over, added it.
    let foreign = world.relay.add_item(
        world.collection,
        "FOREIGN_KEY",
        CANARY,
        json!({"hosts": ["api.example.com"], "environment": "staging"}),
    );
    let host = world.start_host(HostOptions::default(), never_asked);
    let run = world.ask_for(&[foreign], &["git", "status"], Some(USER));
    let view = world.decided(run);
    assert_eq!(view["status"], "denied");
    assert_eq!(view["note"], "Unknown item on this host.");
    // A run with one known and one unknown item is denied as a whole.
    let run = world.ask_for(&[world.stripe, foreign], &["git", "status"], Some(USER));
    assert_eq!(world.decided(run)["note"], "Unknown item on this host.");
    assert!(host.asked().is_empty());
    host.finish();
    let decisions: Vec<String> = world
        .log()
        .iter()
        .map(|l| l["decision"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(decisions, vec!["unknown_item", "unknown_item"]);
}

#[test]
fn the_host_trusts_its_own_metadata_not_the_relays() {
    let world = world();
    // The relay has the Stripe item as staging. On this host it is production.
    let mut entries = world.store.load().unwrap();
    let uid = entries
        .iter()
        .find(|e| e.env_name == "STRIPE_API_KEY")
        .unwrap()
        .uid
        .clone();
    world.store.remove(&uid).unwrap();
    let mut entry = entries.remove(entries.iter().position(|e| e.uid == uid).unwrap());
    entry.environment = "production".to_string();
    world.store.add(entry).unwrap();
    let host = world.start_host(HostOptions::default(), |_| Answer::No);
    let run = world.ask_for(&[world.stripe], &["git", "status"], Some(USER));
    let view = world.decided(run);
    // The relay would allow it. (Its `run_pending` row says so; the host may have taken
    // the run before a test could list it.)
    let audit = world
        .relay
        .ok("GET", "/v1/audit?limit=500", &world.relay.owner_token, None);
    let pending = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["action"] == "run_pending" && row["run_id"] == run)
        .unwrap()
        .clone();
    assert_eq!(pending["detail"]["suggestion"], "allow", "{pending}");
    assert_eq!(view["status"], "denied");
    let asked = host.asked();
    assert_eq!(
        asked.len(),
        1,
        "the host asked: the local environment is production"
    );
    assert_eq!(asked[0].environments, vec!["production"]);
    host.finish();
}

#[test]
fn the_host_reads_the_key_store_again_for_each_run() {
    let world = world();
    let host = world.start_host(HostOptions::default(), never_asked);
    let run = world.ask_for(&[world.stripe], &["git", "status"], Some(USER));
    assert_eq!(world.decided(run)["status"], "ready");
    // An item that is added while the host runs can be used at once.
    let later = add_hosted_item(
        &world.relay,
        &world.store,
        world.collection,
        "OPENAI_API_KEY",
        "sk-proj-SyntheticCanaryThree0123456789abcdef",
        "staging",
        "openai",
    );
    let run = world.ask_for(&[later], &["git", "status"], Some(USER));
    assert_eq!(world.decided(run)["status"], "ready");
    host.finish();
}

#[test]
fn the_auto_limit_makes_the_host_ask() {
    let world = world();
    let options = HostOptions {
        ask_all: false,
        auto_limit: 2,
    };
    let host = world.start_host(options, |_| Answer::No);
    for _ in 0..2 {
        let run = world.ask_for(&[world.stripe], &["git", "status"], Some(USER));
        assert_eq!(world.decided(run)["status"], "ready");
    }
    assert!(host.asked().is_empty());
    let run = world.ask_for(&[world.stripe], &["git", "status"], Some(USER));
    let view = world.decided(run);
    assert_eq!(
        view["status"], "denied",
        "the third run asked, and the answer was no"
    );
    let asked = host.asked();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].why.contains("limit"), "{}", asked[0].why);
    host.finish();
}

#[test]
fn a_run_that_expires_while_the_host_waits_is_left_alone() {
    let relay = start_with(
        |config| config.approval_timeout_secs = 2,
        UpstreamOptions::default(),
    );
    let world = world_with(relay);
    let host = world.start_host(HostOptions::default(), |_| Answer::Expired);
    let run = world.ask_for(&[world.github], &["git", "status"], Some(USER));
    let view = world.decided(run);
    assert_eq!(view["status"], "timed_out");
    assert_eq!(view["code"], "approval_timeout");
    host.finish();
    assert_eq!(world.log()[0]["decision"], "expired");
}

#[test]
fn the_host_handles_runs_oldest_first_one_at_a_time() {
    let world = world();
    let first = world.ask_for(&[world.github], &["git", "status"], Some(USER));
    let second = world.ask_for(&[world.github], &["ls"], Some(USER));
    let third = world.ask_for(&[world.github], &["cargo", "test"], Some(USER));
    let order = Arc::new(Mutex::new(Vec::new()));
    let host = world.start_host(HostOptions::default(), {
        let order = order.clone();
        move |request| {
            order.lock().unwrap().push(request.run_id.0);
            Answer::No
        }
    });
    for run in [first, second, third] {
        assert_eq!(world.decided(run)["status"], "denied");
    }
    assert_eq!(*order.lock().unwrap(), vec![first, second, third]);
    host.finish();
}

#[test]
fn a_key_that_the_relay_cannot_use_ends_in_an_error_and_no_loop() {
    let world = world();
    // A broken key in the store: the host cannot seal it. It says so and does not try
    // the same run again and again.
    let entries = world.store.load().unwrap();
    let entry = entries
        .iter()
        .find(|e| e.env_name == "STRIPE_API_KEY")
        .unwrap();
    let path = world.store.path();
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace(entry.key.expose(), "not-a-key")).unwrap();
    let host = world.start_host(HostOptions::default(), never_asked);
    let run = world.ask_for(&[world.stripe], &["git", "status"], Some(USER));
    // The run is not released. It stays pending until it times out.
    std::thread::sleep(Duration::from_millis(2500));
    let view = world
        .relay
        .ok("GET", &format!("/v1/runs/{run}"), &world.agent, None);
    assert_eq!(view["status"], "pending");
    host.finish();
    let log = world.log();
    assert_eq!(log.len(), 1, "one try only: {log:?}");
    assert_eq!(log[0]["decision"], "error");
}

#[test]
fn the_key_file_modes_hold_after_the_host_wrote_its_log() {
    use std::os::unix::fs::PermissionsExt;
    let world = world();
    let host = world.start_host(HostOptions::default(), never_asked);
    let run = world.ask_for(&[world.stripe], &["git", "status"], Some(USER));
    world.decided(run);
    host.finish();
    for (path, mode) in [
        (world.store.path(), 0o600),
        (world.store.log_path(), 0o600),
        (world.store.dir().to_path_buf(), 0o700),
    ] {
        let got = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, mode, "{}", path.display());
    }
    let _ = world.dir.path();
}

#[test]
fn a_host_never_releases_another_teams_or_unbound_legacy_keys() {
    for binding in [Value::Null, json!("t_abcdefgh23")] {
        let world = world();
        let mut keys: Value =
            serde_json::from_slice(&std::fs::read(world.store.path()).unwrap()).unwrap();
        // Same relay, display name, UID and item id as the requested item. Only the
        // stable ownership differs, or is absent in a legacy key file.
        keys["entries"][0]["team_id"] = binding;
        std::fs::write(world.store.path(), serde_json::to_vec(&keys).unwrap()).unwrap();
        let host = start_host(
            &world.relay,
            world.store.dir(),
            HostOptions::default(),
            |_| Answer::Yes,
        );
        let run = world.ask_for(&[world.stripe], &["stripe", "balance", "retrieve"], None);
        let result = world.decided(run);
        assert_eq!(result["status"], "denied");
        assert_eq!(result["note"], "Unknown item on this host.");
        assert!(result.get("session").is_none());
        assert!(host.asked().is_empty());
        host.finish();
    }
}
