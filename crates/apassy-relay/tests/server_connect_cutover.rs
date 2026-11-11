//! Plan s7 unit C5 (docs/SPEC.md section 37, docs/operations/connect.md): the switches that
//! end the free hosted paths (`APASSY_RELAY_FREE_CONNECT=0` with
//! `APASSY_RELAY_CONNECT_SYNC_BYTES=0`), the Connect-only mode (`APASSY_RELAY_MODE=connect`),
//! the backup of a stopped relay, and `connect-cutover`. The cutover destroys data by
//! design, so its tests came first: a dry run changes nothing; the real run refuses while
//! the relay runs and without a stopped backup of the current state, keeps exactly the
//! vault stores of the accounts as plain files that `connect` mode opens, and never touches
//! a file of a store; a run stopped at any point is finished by the next one, and the
//! backup restores it. Free loopback ports and temporary directories only; synthetic values.

#[path = "common/connect.rs"]
mod connect;
#[path = "common/fake_stripe.rs"]
mod fake_stripe;
#[path = "common/relay.rs"]
mod relay;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use apassy_relay::config::{
    BillingSettings, ConnectConfig, PushConfig, RelayConfig, RelayMode, UpstreamOptions,
};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::encode_b64;
use apassy_relay::ids::TeamId;
use apassy_relay::secret::SecretString;
use apassy_relay::server::cutover::{self, Interrupt, Options, Report};
use apassy_relay::server::directory::{self, Directory};
use apassy_relay::server::operator::Command;
use apassy_relay::server::store::Store;
use apassy_relay::server::{Relay, rollback, sync};
use connect::{Connect, Dev, Pusher, send};
use fake_stripe::FakeStripe;
use relay::{EDGE_SECRET, TestRelay, VAULT_KEY, call_url, start_existing, start_with};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
const OTHER_VAULT: &str = "6b1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f";
const SYNC_BYTES: u64 = 67_108_864;
const KEY_ID: &str = "630dcd2966c43366";

// ---- Small helpers. ----

fn now() -> u64 {
    apassy_relay::now_unix()
}

/// The body of `POST /v1/connect`, signed by `key` for `origin`.
fn connect_body(origin: &str, key: &DeviceKey) -> Value {
    let public_key = key.public_key_b64();
    let signature = key
        .sign(&device::connect_message(origin, &public_key))
        .unwrap();
    json!({"v": 1, "team": "Rafal", "device_name": "Rafal's Mac", "public_key": public_key,
        "signature": encode_b64(&signature)})
}

/// `POST /v1/connect` as the Worker forwards it (a client prefix with its proof).
fn post_connect(relay: &TestRelay, body: &[u8]) -> (u16, Value) {
    let prefix = "2001:db8:c5::/48";
    let mac = apassy_relay::server::connect::prefix_mac(EDGE_SECRET, prefix);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut response = agent
        .post(format!("{}/v1/connect", relay.url))
        .header("X-Apassy-Edge", EDGE_SECRET)
        .header("X-Apassy-Client-Prefix", prefix)
        .header("X-Apassy-Client-Prefix-Mac", mac)
        .header("Content-Type", "application/json")
        .send(body)
        .unwrap();
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// A free Connect team made with a fresh key: its id, the key, and its device id.
fn free_team(relay: &TestRelay) -> (TeamId, DeviceKey, u64) {
    let key = DeviceKey::generate().unwrap();
    let body = serde_json::to_vec(&connect_body(&relay.config.public_url, &key)).unwrap();
    let (status, answer) = post_connect(relay, &body);
    assert_eq!(status, 200, "{answer}");
    let team: TeamId = serde_json::from_value(answer["result"]["team_id"].clone()).unwrap();
    (team, key, answer["result"]["device_id"].as_u64().unwrap())
}

/// A raw request with a body of bytes and extra headers: the status and the error code.
fn raw(
    base: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"))
        .header("X-Apassy-Edge", EDGE_SECRET);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut response = agent.run(builder.body(body.to_vec()).unwrap()).unwrap();
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    let code = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|value| value["error"]["code"].as_str().map(str::to_string))
        .unwrap_or_default();
    (status, code)
}

fn card(qid: &str) -> Value {
    json!({"v": 1, "qid": qid, "to": "member", "expires_at": now() + 300,
        "key_id": KEY_ID, "nonce": "AAECAwQFBgcICQoL", "ciphertext": encode_b64(&[9; 40])})
}

fn feed_body() -> Value {
    json!({"v": 1, "seq": 1, "key_id": KEY_ID, "nonce": "AAECAwQFBgcICQoL",
        "ciphertext": encode_b64(&[7; 64])})
}

fn sha256_hex(bytes: &[u8]) -> String {
    apassy_relay::sync_head::hex(&Sha256::digest(bytes))
}

/// Every file under `dir`, by relative name, with the SHA-256 and the modification time:
/// a fingerprint that any write changes.
fn fingerprint(dir: &Path) -> BTreeMap<String, (String, std::time::SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).unwrap().flatten() {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let name = path
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let bytes = std::fs::read(&path).unwrap();
                out.insert(name, (sha256_hex(&bytes), meta.modified().unwrap()));
            }
        }
    }
    out
}

/// The relative names of the files under `dir`.
fn names(dir: &Path) -> Vec<String> {
    fingerprint(dir).into_keys().collect()
}

/// Every file under `dir` but `relay.lock`, by relative name, with its SHA-256 only: the
/// bytes, whatever a read-write open did to the times.
fn contents(dir: &Path) -> BTreeMap<String, String> {
    fingerprint(dir)
        .into_iter()
        .filter(|(name, _)| name != "relay.lock")
        .map(|(name, (sha, _))| (name, sha))
        .collect()
}

/// True when `needle` occurs in `haystack`.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The data directory holds no team key in plain bytes, in any file.
fn assert_no_plain_key(dir: &Path, keys: &[String], at: &str) {
    for name in names(dir) {
        let bytes = std::fs::read(dir.join(&name)).unwrap();
        for key in keys {
            assert!(
                !holds(&bytes, key.as_bytes()),
                "{at}: {name} holds a team file key in plain"
            );
        }
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let meta = std::fs::symlink_metadata(entry.path()).unwrap();
        let target = to.join(entry.file_name());
        if meta.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if meta.is_file() {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// True when `path` reads as plain SQLite.
fn is_plain(path: &Path) -> bool {
    rusqlite::Connection::open(path)
        .and_then(|conn| {
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
        })
        .is_ok()
}

/// The configuration of `connect` mode on the data directory of `config`: no master key,
/// no push, no shared team vaults.
fn connect_mode(config: &RelayConfig) -> RelayConfig {
    let mut config = config.clone();
    config.connect.mode = RelayMode::Connect;
    config.connect.accounts = true;
    config.master_key = SecretString::new(String::new());
    config.team_vaults = false;
    config.free_connect = false;
    config.push = None;
    config
}

/// `connect_mode` on any free port, for a start in this process.
fn connect_on_any_port(config: &RelayConfig) -> RelayConfig {
    let mut config = connect_mode(config);
    config.listen = "127.0.0.1:0".parse().unwrap();
    config
}

/// The configuration before the cutover on any free port.
fn relay_on_any_port(config: &RelayConfig) -> RelayConfig {
    let mut config = config.clone();
    config.listen = "127.0.0.1:0".parse().unwrap();
    config
}

/// The account token of `dev` on the relay at `base` (after a restart the old one ended).
fn account_token(base: &str, dev: &Dev) -> String {
    let (status, challenge) = call_url(
        base,
        Some(EDGE_SECRET),
        "POST",
        "/v1/account/challenge",
        None,
        Some(&json!({"account_id": dev.account, "public_key": dev.key.public_key_b64()})),
    );
    assert_eq!(status, 200, "{challenge}");
    let origin = challenge["result"]["origin"].as_str().unwrap().to_string();
    let nonce = challenge["result"]["nonce"].as_str().unwrap();
    let message =
        device::account_sign_in_message(&origin, &dev.account, &dev.key.public_key_b64(), nonce);
    let (status, granted) = call_url(
        base,
        Some(EDGE_SECRET),
        "POST",
        "/v1/account/token",
        None,
        Some(
            &json!({"account_id": dev.account, "public_key": dev.key.public_key_b64(),
                     "nonce": nonce, "signature": encode_b64(&dev.key.sign(&message).unwrap())}),
        ),
    );
    assert_eq!(status, 200, "{granted}");
    granted["result"]["token"].as_str().unwrap().to_string()
}

// ---- The fixture of the cutover: a relay as the hosted one is before it. ----

/// A stopped relay with an operator team (a device and one snapshot, a `.pre-v7` copy), a
/// free Connect team with one snapshot, a suspended operator team, an account with two
/// vault stores (one with two snapshots), the old `team.db.pre-teams`, and an audit
/// archive; and its stopped backup.
struct Fixture {
    stripe: FakeStripe,
    config: RelayConfig,
    dir: tempfile::TempDir,
    operator: TeamId,
    owner_token: String,
    operator_key: DeviceKey,
    free: TeamId,
    free_key: DeviceKey,
    suspended: TeamId,
    account: Dev,
    store: TeamId,
    store_device: u64,
    other_store: TeamId,
    pusher: Pusher,
    snapshots: Vec<Vec<u8>>,
}

fn fixture() -> Fixture {
    let c = connect::start_with_config(|cfg| cfg.connect_sync_bytes = SYNC_BYTES);
    // The operator team: a device of a member pushes one snapshot.
    let (_, op_token, operator_key) = c.relay.join_device("member", "Ana");
    let me = c.relay.ok("GET", "/v1/me", &op_token, None);
    let op_device = me["device_id"].as_u64().unwrap();
    let mut op_push = Pusher::new(c.relay.team_id.as_str(), VAULT);
    let body = vec![1u8; 2048];
    let pushed = op_push.try_push_with(
        &c.relay.url,
        &op_token,
        op_device,
        &|message| operator_key.sign(message).unwrap(),
        &body,
    );
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    op_push.pushed(op_device, &body);
    // A free Connect team with relay sync (the hosted relay's 64 MiB of S0).
    let (free, free_key, free_device) = free_team(&c.relay);
    let free_token = c.relay.sign_in(&free, &free_key);
    let free_body = vec![2u8; 3000];
    let free_push = Pusher::new(free.as_str(), OTHER_VAULT);
    let pushed = free_push.try_push_with(
        &c.relay.url,
        &free_token,
        free_device,
        &|message| free_key.sign(message).unwrap(),
        &free_body,
    );
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    // A second operator team, suspended.
    let other_owner = c.relay.new_team("Other", "olga");
    let suspended = relay::team_of(&other_owner);
    c.relay
        .operator(Command::Suspend {
            team: suspended.clone(),
        })
        .unwrap();
    // An account on Connect Personal with two vault stores; the first has two snapshots.
    let account = c.account("Rafal");
    c.subscribe(&account, "connect_personal_month", 1);
    let (store, store_device) = c.store(&account, VAULT);
    let (other_store, _) = c.store(&account, OTHER_VAULT);
    let store_id = TeamId::parse(&store).unwrap();
    let store_token = c.store_token(&store, &account);
    let mut pusher = Pusher::new(&store, VAULT);
    let snapshots = vec![
        b"vault snapshot one".repeat(100),
        b"vault snapshot two".repeat(120),
    ];
    for body in &snapshots {
        let answer = c.try_push(&pusher, &store_token, store_device, &account, body);
        assert_eq!(answer.status, 200, "{}", answer.body);
        pusher.pushed(store_device, body);
    }
    let Connect { relay, stripe, .. } = c;
    let operator = relay.team_id.clone();
    let owner_token = relay.owner_token.clone();
    let (config, dir) = relay.stop_keep();
    // Files that the hosted relay has from its history.
    let pre = config.team_path(&operator).with_extension("db.pre-v7");
    std::fs::copy(config.team_path(&operator), &pre).unwrap();
    std::fs::write(
        config.data_dir.join("team.db.pre-teams"),
        b"an old team file, encrypted with the old key",
    )
    .unwrap();
    std::fs::create_dir_all(config.data_dir.join("audit-archive")).unwrap();
    std::fs::write(
        config.data_dir.join("audit-archive/t_zzzzzzzzzz-1.db"),
        b"an archived audit, encrypted with the master key",
    )
    .unwrap();
    cutover::stopped_backup(&config, now()).unwrap();
    Fixture {
        stripe,
        config,
        dir,
        operator,
        owner_token,
        operator_key,
        free,
        free_key,
        suspended,
        account,
        store: store_id,
        store_device,
        other_store: TeamId::parse(&other_store).unwrap(),
        pusher,
        snapshots,
    }
}

impl Fixture {
    fn data(&self) -> &Path {
        &self.config.data_dir
    }

    /// The dry run as it is now.
    fn dry(&self) -> apassy_relay::error::RelayResult<Report> {
        cutover::run(&self.config, &Options::default(), now())
    }

    /// The `plan_sha256` of the dry run as it is now.
    fn plan(&self) -> String {
        self.dry().unwrap().plan_sha256
    }

    /// A dry run, or a confirmed run with the plan of a dry run just before it.
    fn run(&self, confirm: bool) -> apassy_relay::error::RelayResult<Report> {
        if !confirm {
            return self.dry();
        }
        let plan = self.dry()?.plan_sha256;
        self.run_with(Options {
            confirm: Some(plan),
            ..Options::default()
        })
    }

    fn run_with(&self, options: Options) -> apassy_relay::error::RelayResult<Report> {
        cutover::run(&self.config, &options, now())
    }

    /// A confirmed run stopped at `at` as a kill would stop it.
    fn run_until(&self, at: Interrupt) -> apassy_relay::error::RelayResult<Report> {
        self.run_with(Options {
            confirm: Some(self.plan()),
            interrupt: Some(at),
            ..Options::default()
        })
    }

    /// A confirmed run that fails at `at` with an ordinary error.
    fn fail_at(&self, at: Interrupt) -> apassy_relay::error::RelayResult<Report> {
        self.run_with(Options {
            confirm: Some(self.plan()),
            fail: Some(at),
            ..Options::default()
        })
    }

    /// The file key of every team, from the keyed `relay.db`.
    fn file_keys(&self) -> Vec<String> {
        let directory =
            Store::open_read_only(&self.config.directory_path(), &self.config.master_key).unwrap();
        let keys: Vec<String> = directory
            .with(directory::read_teams)
            .unwrap()
            .iter()
            .map(|row| row.file_key.expose().to_string())
            .collect();
        assert_eq!(keys.len(), 5);
        assert!(keys.iter().all(|key| key.len() >= 32));
        keys
    }

    /// The file key of `team`, from the keyed `relay.db`.
    fn file_key(&self, team: &TeamId) -> SecretString {
        let directory =
            Store::open_read_only(&self.config.directory_path(), &self.config.master_key).unwrap();
        directory
            .with(|conn| directory::team_by_id(conn, team))
            .unwrap()
            .unwrap()
            .file_key
    }

    /// The folder of the fixture's stopped backup.
    fn backup(&self) -> PathBuf {
        std::fs::read_dir(&self.config.backup_dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .next()
            .unwrap()
    }

    /// A relay in `connect` mode on the data directory, with the fake Stripe of the
    /// fixture.
    fn start_connect(self) -> (Connect, Dev, TeamId, u64, Pusher, Vec<Vec<u8>>) {
        let config = connect_mode(&self.config);
        let relay = start_existing(config, self.dir, None, "");
        let c = Connect::around(relay, self.stripe);
        (
            c,
            self.account,
            self.store,
            self.store_device,
            self.pusher,
            self.snapshots,
        )
    }
}

/// The store's head and download work, and a new version can be pushed: the account
/// store is a working relay-sync team on `c`.
fn check_store_works(
    c: &Connect,
    account: &mut Dev,
    store: &TeamId,
    device: u64,
    pusher: &mut Pusher,
    snapshots: &[Vec<u8>],
) {
    account.token = account_token(&c.relay.url, account);
    let token = c.relay.sign_in(store, &account.key);
    let head = c.relay.ok("GET", "/v1/sync/head", &token, None);
    assert_eq!(head["version"], snapshots.len());
    let download = send(
        &c.relay.url,
        "GET",
        &format!("/v1/sync/snapshot?version={}", snapshots.len()),
        &token,
        &[],
        Vec::new(),
    );
    assert_eq!(download.status, 200);
    assert_eq!(&download.bytes, snapshots.last().unwrap());
    let next = b"vault snapshot three".to_vec();
    let answer = c.try_push(pusher, &token, device, account, &next);
    assert_eq!(answer.status, 200, "{}", answer.body);
    pusher.pushed(device, &next);
}

// ---- The transition switches: APASSY_RELAY_FREE_CONNECT and the free sync bytes. ----

#[test]
fn the_free_connect_switch_is_on_by_default_and_off_in_connect_mode() {
    let dir = tempfile::tempdir().unwrap();
    let base = vec![
        (
            "APASSY_RELAY_DATA",
            dir.path().join("d").to_string_lossy().into_owned(),
        ),
        (
            "APASSY_RELAY_PUBLIC_URL",
            "https://relay.example.test".to_string(),
        ),
        ("APASSY_RELAY_EDGE_SECRET", EDGE_SECRET.to_string()),
    ];
    let with = |extra: &[(&'static str, &str)]| {
        let mut pairs = base.clone();
        pairs.extend(extra.iter().map(|(key, value)| (*key, value.to_string())));
        RelayConfig::from_lookup(move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        })
    };
    let key = ("APASSY_RELAY_KEY", VAULT_KEY);
    // A relay that someone runs for themselves: the free paths as today.
    let default = with(&[key]).unwrap();
    assert!(default.free_connect && !default.free_sync_ended());
    let off = with(&[key, ("APASSY_RELAY_FREE_CONNECT", "0")]).unwrap();
    assert!(!off.free_connect && off.free_sync_ended());
    // Free approvals end first, free sync later: sync bytes above 0 keep the sync.
    let staged = with(&[
        key,
        ("APASSY_RELAY_FREE_CONNECT", "0"),
        ("APASSY_RELAY_CONNECT_SYNC_BYTES", "67108864"),
    ])
    .unwrap();
    assert!(!staged.free_connect && !staged.free_sync_ended());
    assert!(with(&[key, ("APASSY_RELAY_FREE_CONNECT", "no")]).is_err());
    // `connect` mode: always off.
    let connect = with(&[
        ("APASSY_RELAY_MODE", "connect"),
        ("APASSY_RELAY_FREE_CONNECT", "1"),
    ])
    .unwrap();
    assert!(!connect.free_connect);
}

#[test]
fn post_connect_ends_with_410_before_its_body_is_read() {
    let relay = start_with(|cfg| cfg.free_connect = false, UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let good = serde_json::to_vec(&connect_body(&relay.config.public_url, &key)).unwrap();
    // A valid body, and a body that is not JSON (400 if it were read): both 410.
    for body in [good.as_slice(), b"{not json".as_slice()] {
        let (status, answer) = post_connect(&relay, body);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (410, Some("free_connect_ended")),
            "{answer}"
        );
    }
    let (status, code) = raw(
        &relay.url,
        "POST",
        "/v1/connect/challenge",
        None,
        &[("Content-Type", "application/json")],
        b"{not json",
    );
    assert_eq!((status, code.as_str()), (410, "free_connect_ended"));
    // No team was made; the operator team of the relay is as it was.
    let teams = relay.operator(Command::Teams).unwrap();
    let kinds: Vec<&str> = teams
        .as_array()
        .unwrap()
        .iter()
        .map(|team| team["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["operator"]);
    // The same relay with the switch on makes the team: a self-run relay keeps the path.
    let (config, dir) = relay.stop_keep();
    let mut config = config;
    config.free_connect = true;
    let on = start_existing(config, dir, None, "");
    let body = serde_json::to_vec(&connect_body(&on.config.public_url, &key)).unwrap();
    assert_eq!(post_connect(&on, &body).0, 200);
}

#[test]
fn free_connect_teams_lose_questions_feed_and_push_and_operator_teams_keep_them() {
    let relay = start_with(|_| {}, UpstreamOptions::default());
    let (free, free_key, free_device) = free_team(&relay);
    let operator = relay.team_id.clone();
    let owner_token = relay.owner_token.clone();
    let (_, op_token, op_key) = relay.join_device("member", "Ana");
    let (config, dir) = relay.stop_keep();
    let mut config = config;
    config.free_connect = false;
    let relay = start_existing(config, dir, Some(operator.clone()), &owner_token);
    let free_token = relay.sign_in(&free, &free_key);
    let op_token = {
        drop(op_token);
        relay.sign_in(&operator, &op_key)
    };
    let qid = encode_b64(&[3; 16]);
    let routes: Vec<(&str, String, Option<Value>)> = vec![
        ("POST", "/v1/questions".to_string(), Some(card(&qid))),
        ("GET", "/v1/questions?since=0".to_string(), None),
        ("GET", format!("/v1/questions/{qid}/answers?after=0"), None),
        ("PUT", "/v1/feed".to_string(), Some(feed_body())),
        ("GET", "/v1/feed?since=0".to_string(), None),
        ("DELETE", "/v1/feed".to_string(), None),
        ("GET", "/v1/feed/actions?since=0".to_string(), None),
        (
            "PUT",
            "/v1/push/token".to_string(),
            Some(
                json!({"token": "00".repeat(32), "environment": "production",
                        "bundle_id": "com.example.app"}),
            ),
        ),
        ("DELETE", "/v1/push/token".to_string(), None),
    ];
    for (method, path, body) in &routes {
        let (status, answer) = relay.call(method, path, Some(&free_token), body.as_ref());
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (410, Some("free_connect_ended")),
            "{method} {path}: {answer}"
        );
    }
    // A body that is not JSON is never read: still 410.
    let (status, code) = raw(
        &relay.url,
        "POST",
        "/v1/questions",
        Some(&free_token),
        &[("Content-Type", "application/json")],
        b"{not json",
    );
    assert_eq!((status, code.as_str()), (410, "free_connect_ended"));
    // The free team keeps its devices and sign-in, so the app can move and leave.
    let me = relay.ok("GET", "/v1/me", &free_token, None);
    assert_eq!(me["device_id"], free_device);
    relay.ok("GET", "/v1/devices", &free_token, None);
    // An operator team on the same relay: questions and the feed as before.
    let posted = relay.ok("POST", "/v1/questions", &op_token, Some(&card(&qid)));
    assert_eq!(posted["qid"], qid);
    relay.ok("GET", "/v1/questions?since=0", &op_token, None);
    relay.ok("PUT", "/v1/feed", &op_token, Some(&feed_body()));
    relay.ok("GET", "/v1/feed?since=0", &op_token, None);
}

#[test]
fn free_sync_ends_for_existing_free_teams_and_never_for_operator_teams() {
    let relay = start_with(
        |cfg| cfg.connect_sync_bytes = SYNC_BYTES,
        UpstreamOptions::default(),
    );
    let (free, free_key, free_device) = free_team(&relay);
    let free_token = relay.sign_in(&free, &free_key);
    let mut free_push = Pusher::new(free.as_str(), VAULT);
    let first = vec![5u8; 1000];
    let sign_free = |message: &[u8]| free_key.sign(message).unwrap();
    let answer = free_push.try_push_with(&relay.url, &free_token, free_device, &sign_free, &first);
    assert_eq!(answer.status, 200, "{}", answer.body);
    free_push.pushed(free_device, &first);
    let operator = relay.team_id.clone();
    let owner_token = relay.owner_token.clone();
    let (_, _, op_key) = relay.join_device("member", "Ana");
    let (config, dir) = relay.stop_keep();

    // Free approvals end, free sync stays (the sync bytes are still above 0).
    let mut staged = config.clone();
    staged.free_connect = false;
    let relay = start_existing(staged, dir, Some(operator.clone()), &owner_token);
    let free_token = relay.sign_in(&free, &free_key);
    let second = vec![6u8; 1000];
    let answer = free_push.try_push_with(&relay.url, &free_token, free_device, &sign_free, &second);
    assert_eq!(answer.status, 200, "{}", answer.body);
    free_push.pushed(free_device, &second);
    let (config2, dir) = relay.stop_keep();

    // Both off: a push and a receipt of the free team are plan_required; its pulls work.
    let mut ended = config2;
    ended.free_connect = false;
    ended.connect_sync_bytes = 0;
    let relay = start_existing(ended, dir, Some(operator.clone()), &owner_token);
    let free_token = relay.sign_in(&free, &free_key);
    let third = vec![7u8; 1000];
    let refused = free_push.try_push_with(&relay.url, &free_token, free_device, &sign_free, &third);
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(refused.body["error"]["code"], "plan_required");
    let (status, answer) = relay.call(
        "POST",
        "/v1/sync/receipt",
        Some(&free_token),
        Some(&json!({"version": 2})),
    );
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("plan_required"))
    );
    let head = relay.ok("GET", "/v1/sync/head", &free_token, None);
    assert_eq!(head["version"], 2);
    let download = send(
        &relay.url,
        "GET",
        "/v1/sync/snapshot?version=2",
        &free_token,
        &[],
        Vec::new(),
    );
    assert_eq!(
        (download.status, download.bytes.as_slice()),
        (200, second.as_slice())
    );
    // A long poll of the head answers at once: nothing new can come.
    let started = std::time::Instant::now();
    relay.ok("GET", "/v1/sync/head?since=2&wait=20", &free_token, None);
    assert!(started.elapsed() < Duration::from_secs(10));
    // The operator team pushes as before: the switches never reach it.
    let op_token = relay.sign_in(&operator, &op_key);
    let me = relay.ok("GET", "/v1/me", &op_token, None);
    let op_device = me["device_id"].as_u64().unwrap();
    let op_body = vec![8u8; 1000];
    let answer = Pusher::new(operator.as_str(), VAULT).try_push_with(
        &relay.url,
        &op_token,
        op_device,
        &|message| op_key.sign(message).unwrap(),
        &op_body,
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
}

#[test]
fn vault_stores_of_accounts_ignore_the_switches() {
    let c = connect::start_with_config(|cfg| {
        cfg.free_connect = false;
        cfg.connect_sync_bytes = 0;
    });
    let account = c.account("Rafal");
    c.subscribe(&account, "connect_personal_month", 1);
    let (store, device) = c.store(&account, VAULT);
    let token = c.store_token(&store, &account);
    let mut pusher = Pusher::new(&store, VAULT);
    let body = b"a vault snapshot".to_vec();
    let answer = c.try_push(&pusher, &token, device, &account, &body);
    assert_eq!(answer.status, 200, "{}", answer.body);
    pusher.pushed(device, &body);
    let (status, answer) = c.relay.call(
        "POST",
        "/v1/sync/receipt",
        Some(&token),
        Some(&json!({"version": 1})),
    );
    assert_eq!(status, 200, "{answer}");
}

// ---- Connect-only mode. ----

/// A relay in `connect` mode with accounts and the fake Stripe, and no team.
fn connect_relay() -> Connect {
    connect::start_with_config(|cfg| {
        cfg.connect.mode = RelayMode::Connect;
        cfg.master_key = SecretString::new(String::new());
        cfg.team_vaults = false;
    })
}

fn health_headers(base: &str) -> (u16, String, Vec<(String, String)>) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut response = agent.get(format!("{base}/healthz")).call().unwrap();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let status = response.status().as_u16();
    (
        status,
        response.body_mut().read_to_string().unwrap(),
        headers,
    )
}

/// The status of a `GET` written by hand on a TCP stream, with or without the headers of a
/// WebSocket upgrade.
fn raw_get(base: &str, path: &str, upgrade: bool) -> u16 {
    let addr = base.strip_prefix("http://").unwrap();
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let extra = if upgrade {
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    } else {
        ""
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: relay.example.test\r\nX-Apassy-Edge: {EDGE_SECRET}\r\n{extra}\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    // The status line comes first: one read is enough.
    let mut answer = [0u8; 2048];
    let read = stream.read(&mut answer).unwrap();
    let text = String::from_utf8_lossy(&answer[..read]);
    text.split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("no status: {text}"))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[test]
fn connect_mode_answers_every_retired_route_with_410_before_the_body() {
    let c = connect_relay();
    let base = c.relay.url.clone();
    let retired = [
        ("POST", "/v1/connect"),
        ("GET", "/v1/connect"),
        ("POST", "/v1/connect/challenge"),
        ("POST", "/v1/teams"),
        ("POST", "/v1/join"),
        ("POST", "/v1/invites"),
        ("GET", "/v1/members"),
        ("POST", "/v1/questions"),
        ("GET", "/v1/questions"),
        ("POST", "/v1/questions/AAAAAAAAAAAAAAAAAAAAAA/answers"),
        ("PUT", "/v1/feed"),
        ("GET", "/v1/feed/actions"),
        ("PUT", "/v1/push/token"),
        ("DELETE", "/v1/push/handle"),
        ("POST", "/mcp"),
        ("GET", "/mcp"),
        ("POST", "/p/apassy_ses_t_abcdefgh23_00/v1/x"),
        ("GET", "/p/anything"),
        ("POST", "/v1/runs"),
        ("GET", "/v1/items"),
        ("POST", "/v1/devices/links"),
        ("POST", "/v1/devices/link"),
        ("DELETE", "/v1/devices/1"),
        ("GET", "/v1/host/requests"),
        ("GET", "/v1/audit"),
        ("POST", "/v1/leave"),
    ];
    for (method, path) in retired {
        // A body that is not JSON and a bearer that is not a token: 410 all the same,
        // before either is read.
        let (status, code) = raw(
            &base,
            method,
            path,
            Some("not-a-token"),
            &[("Content-Type", "application/json")],
            if method == "GET" { b"" } else { b"{not json" },
        );
        assert_eq!(
            (status, code.as_str()),
            (410, "hosted_retired"),
            "{method} {path}"
        );
    }
    // An `Upgrade` on a retired route is 400 before the 410: only the tunnel upgrades,
    // on every route and in both modes (section 35.6).
    for (path, upgrade, status) in [
        ("/v1/questions", true, 400),
        ("/v1/questions", false, 410),
        ("/mcp", true, 400),
    ] {
        assert_eq!(raw_get(&base, path, upgrade), status, "{path} {upgrade}");
    }
    // Served: health with the mode, the well-known document, accounts, billing, the
    // tunnel, and relay sync of a vault store (401 without a token, 400 for a bad body).
    let (status, body, headers) = health_headers(&base);
    assert_eq!((status, body.as_str()), (200, "ok\n"));
    assert_eq!(header(&headers, "x-apassy-relay-mode"), Some("connect"));
    assert_eq!(
        header(&headers, "x-apassy-relay-version"),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert!(header(&headers, "x-apassy-relay-commit").is_some());
    for (method, path, status) in [
        ("GET", "/.well-known/apassy-connect.json", 200),
        ("GET", "/v1/plans", 200),
        ("GET", "/v1/account", 401),
        ("GET", "/v1/tunnel/nodes", 401),
        ("GET", "/v1/me", 401),
        ("GET", "/v1/devices", 401),
        ("GET", "/v1/sync/head", 401),
        ("PUT", "/v1/sync/snapshot", 400),
        ("POST", "/v1/sync/receipt", 401),
        ("DELETE", "/v1/sync", 401),
        ("POST", "/v1/auth/challenge", 400),
        ("GET", "/v1/nothing-here", 404),
    ] {
        let (got, code) = raw(&base, method, path, None, &[], b"");
        assert_eq!(got, status, "{method} {path}: {code}");
    }
    // A relay in `relay` mode names its mode too.
    let plain = start_with(|_| {}, UpstreamOptions::default());
    let (_, _, headers) = health_headers(&plain.url);
    assert_eq!(header(&headers, "x-apassy-relay-mode"), Some("relay"));
}

#[test]
fn connect_mode_builds_no_proxy_and_starts_no_push_thread() {
    let c = connect_relay();
    assert!(c.relay.hub().config.push.is_none());
    // Start it again here, to hold the handle of the running relay.
    let (config, dir) = {
        let Connect { relay, .. } = c;
        relay.stop_keep()
    };
    let running = Relay::start(config.clone()).unwrap();
    assert!(!running.proxy_built());
    assert!(!running.push_on());
    #[cfg(target_os = "linux")]
    if std::env::var_os("NEXTEST").is_some() {
        // One test, one process (nextest): no thread of this process is a push sender.
        assert!(
            !thread_names()
                .iter()
                .any(|name| name.starts_with("relay-push")),
            "{:?}",
            thread_names()
        );
    }
    running.stop();
    drop(dir);
    // The control: a relay with push has its senders and a proxy.
    let relay = start_with(
        |cfg| {
            cfg.push = Some(PushConfig::new(
                "http://127.0.0.1:9/internal/push".to_string(),
                "com.example.app".to_string(),
                SecretString::new("p".repeat(40)),
            ))
        },
        UpstreamOptions::default(),
    );
    let (config, dir) = relay.stop_keep();
    let running = Relay::start(config).unwrap();
    assert!(running.proxy_built() && running.push_on());
    #[cfg(target_os = "linux")]
    if std::env::var_os("NEXTEST").is_some() {
        assert!(
            thread_names()
                .iter()
                .any(|name| name.starts_with("relay-push"))
        );
    }
    running.stop();
    drop(dir);
}

#[cfg(target_os = "linux")]
fn thread_names() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
        .map(|name| name.trim().to_string())
        .collect()
}

#[test]
fn connect_mode_refuses_push_the_master_key_and_node_settings_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let base = vec![
        (
            "APASSY_RELAY_DATA",
            dir.path().join("d").to_string_lossy().into_owned(),
        ),
        (
            "APASSY_RELAY_PUBLIC_URL",
            "https://connect.example.test".to_string(),
        ),
        ("APASSY_RELAY_EDGE_SECRET", EDGE_SECRET.to_string()),
        ("APASSY_RELAY_MODE", "connect".to_string()),
    ];
    let with = |extra: &[(&'static str, &str)]| {
        let mut pairs = base.clone();
        pairs.extend(extra.iter().map(|(key, value)| (*key, value.to_string())));
        RelayConfig::from_lookup(move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        })
    };
    let secret_file = dir.path().join("push-secret");
    std::fs::write(&secret_file, "s".repeat(40)).unwrap();
    let secret_file = secret_file.to_string_lossy().into_owned();
    for extra in [
        vec![(
            "APASSY_RELAY_PUSH_URL",
            "https://relay.example.test/internal/push",
        )],
        vec![("APASSY_RELAY_PUSH_TOPIC", "com.example.app")],
        vec![("APASSY_RELAY_PUSH_SECRET_FILE", secret_file.as_str())],
        vec![
            (
                "APASSY_RELAY_PUSH_URL",
                "https://relay.example.test/internal/push",
            ),
            ("APASSY_RELAY_PUSH_TOPIC", "com.example.app"),
            ("APASSY_RELAY_PUSH_SECRET_FILE", secret_file.as_str()),
        ],
    ] {
        let error = with(&extra).unwrap_err();
        assert!(error.message.contains("sends no push"), "{}", error.message);
    }
    for key in ["APASSY_RELAY_KEY", "APASSY_RELAY_KEY_FILE"] {
        let error = with(&[(key, VAULT_KEY)]).unwrap_err();
        assert!(
            error.message.contains("refuses a master key"),
            "{}",
            error.message
        );
    }
    let good = with(&[]).unwrap();
    assert!(good.push.is_none() && good.master_key.is_empty() && !good.team_vaults);
    // A configuration made in code keeps the same rules at `Relay::start`.
    let mut good = good;
    good.listen = "127.0.0.1:0".parse().unwrap();
    good.public_url = "http://127.0.0.1:1".to_string();
    good.backup_dir = dir.path().join("b");
    Relay::init_empty(&good).unwrap();
    type Edit = Box<dyn Fn(&mut RelayConfig)>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "a master key",
            Box::new(|cfg| cfg.master_key = SecretString::new(VAULT_KEY.into())),
        ),
        (
            "push",
            Box::new(|cfg| {
                cfg.push = Some(PushConfig::new(
                    "http://127.0.0.1:9/internal/push".to_string(),
                    "com.example.app".to_string(),
                    SecretString::new("p".repeat(40)),
                ))
            }),
        ),
        ("shared team vaults", Box::new(|cfg| cfg.team_vaults = true)),
        (
            "the public or tailnet listener",
            Box::new(|cfg| cfg.public_listen = Some("127.0.0.1:0".parse().unwrap())),
        ),
        (
            "the account routes off",
            Box::new(|cfg| cfg.connect.accounts = false),
        ),
    ];
    for (what, edit) in edits {
        let mut config = good.clone();
        edit(&mut config);
        let error = Relay::start(config)
            .err()
            .unwrap_or_else(|| panic!("{what}"));
        assert!(
            error.message.contains("cannot run with"),
            "{what}: {}",
            error.message
        );
    }
    let running = Relay::start(good.clone()).unwrap();
    assert!(running.hub().config.connect.plain_files());
    running.stop();
    // No operator team and no team code in `connect` mode.
    assert!(Relay::init(&good, "Team", "owner").is_err());
}

#[test]
fn connect_mode_backs_up_plain_files_and_refuses_the_keyed_rollbacks() {
    let c = connect_relay();
    let account = c.account("Rafal");
    c.subscribe(&account, "connect_personal_month", 1);
    let (store, device) = c.store(&account, VAULT);
    let token = c.store_token(&store, &account);
    let pusher = Pusher::new(&store, VAULT);
    let body = b"a plain store's snapshot".to_vec();
    assert_eq!(
        c.try_push(&pusher, &token, device, &account, &body).status,
        200
    );
    // No team code: Connect has no operator team.
    let error = c
        .relay
        .operator(Command::TeamCode { hours: 1 })
        .unwrap_err();
    assert!(
        error.message.contains("makes no team codes"),
        "{}",
        error.message
    );
    // The backup of the running relay: plain files, and the manifest says so.
    let manifest = c.relay.operator(Command::Backup).unwrap();
    assert_eq!(manifest["mode"], "connect");
    let folder = PathBuf::from(manifest["dir"].as_str().unwrap());
    let store_id = TeamId::parse(&store).unwrap();
    assert!(is_plain(&folder.join("relay.db")));
    assert!(is_plain(&folder.join(format!("teams/{store}.db"))));
    assert!(folder.join(format!("teams/{store}.sync/1.bin")).exists());
    let (config, dir) = {
        let Connect { relay, .. } = c;
        relay.stop_keep()
    };
    // The restore check of the backup: copied into an empty data directory, it passes.
    let restored = tempfile::tempdir().unwrap();
    let mut restore = config.clone();
    restore.data_dir = restored.path().join("data");
    copy_tree(&folder, &restore.data_dir);
    std::fs::remove_file(restore.data_dir.join("MANIFEST.json")).unwrap();
    assert_eq!(sync::verify_restored(&restore).unwrap(), 1);
    // The backup of the stopped relay works in this mode too.
    let stopped = cutover::stopped_backup(&config, now() + 2).unwrap();
    assert_eq!(
        (stopped["stopped"].clone(), stopped["mode"].clone()),
        (json!(true), json!("connect"))
    );
    // The keyed rollbacks do not apply: each says why and changes nothing.
    let before = fingerprint(&config.data_dir);
    let errors = [
        rollback::check(&config).map(drop).unwrap_err(),
        rollback::downgrade_to_6(&config).map(drop).unwrap_err(),
        rollback::downgrade_to_7(&config).map(drop).unwrap_err(),
        Directory::downgrade_to_1005(&config).map(drop).unwrap_err(),
        Directory::downgrade_to_1004(&config).map(drop).unwrap_err(),
        Directory::downgrade_to_1003(&config).map(drop).unwrap_err(),
    ];
    for error in errors {
        assert!(
            error
                .message
                .contains("does not apply in APASSY_RELAY_MODE=connect"),
            "{}",
            error.message
        );
    }
    assert_eq!(fingerprint(&config.data_dir), before);
    assert!(is_plain(&config.team_path(&store_id)));
    drop(dir);
}

// ---- The cutover. ----

#[test]
fn a_dry_run_changes_nothing_and_answers_the_plan() {
    let f = fixture();
    let before = fingerprint(f.data());
    let report = f.run(false).unwrap();
    assert_eq!(fingerprint(f.data()), before, "the dry run wrote a file");
    assert_eq!(report.state, "dry_run");
    let kept: Vec<&TeamId> = report.kept.iter().map(|store| &store.team_id).collect();
    let mut expected = vec![&f.store, &f.other_store];
    expected.sort();
    let mut kept_sorted = kept.clone();
    kept_sorted.sort();
    assert_eq!(kept_sorted, expected);
    let mut deleted: Vec<&TeamId> = report.deleted.iter().map(|team| &team.team_id).collect();
    deleted.sort();
    let mut gone = vec![&f.operator, &f.free, &f.suspended];
    gone.sort();
    assert_eq!(deleted, gone);
    assert_eq!(
        (
            report.before.operator,
            report.before.connect,
            report.before.account
        ),
        (2, 1, 2)
    );
    assert!(
        report
            .files_before
            .iter()
            .any(|entry| entry.name == "team.db.pre-teams")
    );
    assert!(report.backup.check.contains("byte-identical"));
    assert!(!f.data().join(cutover::CUTOVER_FILE).exists());
    // The relay starts on it as before.
    let relay = start_existing(
        f.config.clone(),
        f.dir,
        Some(f.operator.clone()),
        &f.owner_token,
    );
    relay.ok("GET", "/v1/me", &f.owner_token, None);
}

#[test]
fn the_cutover_refuses_while_the_relay_runs() {
    let f = fixture();
    let relay = start_existing(
        f.config.clone(),
        f.dir,
        Some(f.operator.clone()),
        &f.owner_token,
    );
    for confirm in [None, Some("0".repeat(64))] {
        let error = cutover::run(
            &relay.config,
            &Options {
                confirm,
                ..Options::default()
            },
            now(),
        )
        .unwrap_err();
        assert_eq!(error.code, "conflict");
        assert!(error.message.contains("relay.lock"), "{}", error.message);
    }
    let error = cutover::stopped_backup(&relay.config, now()).unwrap_err();
    assert!(error.message.contains("relay.lock"), "{}", error.message);
    // Nothing changed: the operator team still answers.
    relay.ok("GET", "/v1/me", &f.owner_token, None);
}

#[test]
fn the_cutover_needs_a_stopped_backup_of_the_data_directory_as_it_is() {
    let f = fixture();
    let backups = f.config.backup_dir.clone();
    let stopped: Vec<PathBuf> = std::fs::read_dir(&backups)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(stopped.len(), 1);
    let stopped = stopped[0].clone();
    // No stopped backup at all.
    let moved = backups.with_file_name("moved-away");
    std::fs::rename(&backups, &moved).unwrap();
    let error = f.run(true).unwrap_err();
    assert!(
        error.message.contains("apassy-relay backup"),
        "{}",
        error.message
    );
    std::fs::rename(&moved, &backups).unwrap();
    // Only a backup of the running relay (`admin backup`): not enough.
    let relay = start_existing(
        f.config.clone(),
        f.dir,
        Some(f.operator.clone()),
        &f.owner_token,
    );
    let online = relay.operator(Command::Backup).unwrap();
    let online = PathBuf::from(online["dir"].as_str().unwrap());
    let (config, dir) = relay.stop_keep();
    let named = cutover::run(
        &config,
        &Options {
            confirm: Some("0".repeat(64)),
            backup: Some(online),
            ..Options::default()
        },
        now(),
    )
    .unwrap_err();
    assert!(
        named.message.contains("while the relay ran"),
        "{}",
        named.message
    );
    // The relay ran after the stopped backup and wrote `relay.db` (the backup row of
    // `admin backup`): the backup is no longer the data directory as it is.
    let before = fingerprint(&config.data_dir);
    let error = cutover::run(
        &config,
        &Options {
            confirm: Some("0".repeat(64)),
            ..Options::default()
        },
        now(),
    )
    .unwrap_err();
    assert!(
        error
            .message
            .contains("is not a copy of the data directory"),
        "{}",
        error.message
    );
    // A new stopped backup passes the check; a damaged one does not.
    cutover::stopped_backup(&config, now() + 5).unwrap();
    let newest = std::fs::read_dir(&backups)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path != &stopped)
        .filter(|path| {
            std::fs::read_to_string(path.join("MANIFEST.json"))
                .is_ok_and(|text| text.contains("\"stopped\": true"))
        })
        .max()
        .unwrap();
    let report = cutover::run(&config, &Options::default(), now()).unwrap();
    assert_eq!(report.backup.dir, newest.to_string_lossy());
    std::fs::write(newest.join(format!("teams/{}.db", f.store)), b"damaged").unwrap();
    let error = cutover::run(
        &config,
        &Options {
            confirm: Some("0".repeat(64)),
            ..Options::default()
        },
        now(),
    )
    .unwrap_err();
    assert!(error.message.contains("is damaged"), "{}", error.message);
    assert_eq!(
        fingerprint(&config.data_dir),
        before,
        "a refused cutover wrote a file"
    );
    drop(dir);
}

#[test]
fn the_cutover_keeps_the_account_stores_as_plain_files_that_connect_mode_opens() {
    let f = fixture();
    let snapshot_names: Vec<String> = names(f.data())
        .into_iter()
        .filter(|name| name.starts_with(&format!("teams/{}.sync/", f.store)))
        .collect();
    assert_eq!(snapshot_names.len(), 2);
    let snapshots_before: BTreeMap<_, _> = fingerprint(f.data())
        .into_iter()
        .filter(|(name, _)| snapshot_names.contains(name))
        .map(|(name, (sha, _))| (name, sha))
        .collect();
    let report = f.run(true).unwrap();
    assert_eq!(report.state, "done");
    assert!(report.changed);
    assert!(cutover::summary(&report).contains("the cutover is done"));
    assert_eq!(report.kept.len(), 2);
    assert_eq!(report.deleted.len(), 3);
    assert_eq!(report.rows_deleted["team"], 3);
    let after = report.after.clone().unwrap();
    assert_eq!(
        (after.teams, after.account, after.operator, after.connect),
        (2, 2, 0, 0)
    );
    // Only `relay.db`, the record, and the two stores are left, plain.
    let mut expected = vec![
        "relay.db".to_string(),
        cutover::CUTOVER_FILE.to_string(),
        format!("teams/{}.db", f.store),
        format!("teams/{}.db", f.other_store),
    ];
    expected.extend(snapshot_names.iter().cloned());
    expected.sort();
    let left: Vec<String> = names(f.data())
        .into_iter()
        .filter(|name| name != "relay.lock")
        .collect();
    assert_eq!(left, expected);
    assert!(is_plain(&f.data().join("relay.db")));
    assert!(is_plain(&f.config.team_path(&f.store)));
    assert!(is_plain(&f.config.team_path(&f.other_store)));
    // No file key, no other team, and the record of the cutover in the relay audit.
    let conn = rusqlite::Connection::open(f.data().join("relay.db")).unwrap();
    let keys: Vec<String> = conn
        .prepare("SELECT file_key FROM team")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(keys, ["", ""]);
    let kinds: i64 = conn
        .query_row(
            "SELECT count(*) FROM team WHERE kind <> 'account'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(kinds, 0);
    for table in ["team_code", "connect_key"] {
        let rows: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0, "{table}");
    }
    let audit: i64 = conn
        .query_row(
            "SELECT count(*) FROM audit WHERE action = 'connect_cutover'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(audit, 1);
    // No old key in the bytes of the file (it was vacuumed).
    drop(conn);
    // The snapshots of the store are the bytes they were.
    let snapshots_after: BTreeMap<_, _> = fingerprint(f.data())
        .into_iter()
        .filter(|(name, _)| snapshot_names.contains(name))
        .map(|(name, (sha, _))| (name, sha))
        .collect();
    assert_eq!(snapshots_after, snapshots_before);
    // The record on disk is the answer, with the hashes before and after.
    let record: Report =
        serde_json::from_slice(&std::fs::read(f.data().join(cutover::CUTOVER_FILE)).unwrap())
            .unwrap();
    assert_eq!(record.state, "done");
    assert!(record.files_before.len() > record.files_after.as_ref().unwrap().len());
    assert!(
        record
            .files_deleted
            .iter()
            .any(|name| name == "team.db.pre-teams")
    );
    assert!(
        record
            .files_deleted
            .iter()
            .any(|name| name.starts_with("audit-archive/"))
    );
    assert!(!f.data().join(cutover::KEYED_DIRECTORY_FILE).exists());
    // A second run changes nothing and answers the record.
    let before = fingerprint(f.data());
    let again = f.run(true).unwrap();
    assert_eq!(
        (again.state.as_str(), again.finished_at),
        ("done", record.finished_at)
    );
    assert!(!again.changed);
    let line = cutover::summary(&again);
    assert!(line.contains("nothing changed"), "{line}");
    assert_eq!(fingerprint(f.data()), before);
    // `connect` mode opens it: the account signs in, the store pulls and pushes.
    let operator = f.operator.clone();
    let owner_token = f.owner_token.clone();
    let (free, free_key) = (f.free.clone(), f.free_key.clone_key());
    let (c, mut account, store, device, mut pusher, snapshots) = f.start_connect();
    check_store_works(&c, &mut account, &store, device, &mut pusher, &snapshots);
    let (_, _, headers) = health_headers(&c.relay.url);
    assert_eq!(header(&headers, "x-apassy-relay-mode"), Some("connect"));
    // The teams that went are gone: their tokens and sign-ins fail, their routes retired.
    let (status, _) = c.relay.call("GET", "/v1/me", Some(&owner_token), None);
    assert_eq!(status, 401);
    let (status, answer) = c.relay.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": free, "public_key": free_key.public_key_b64()})),
    );
    assert_ne!(status, 200, "{answer}");
    let (status, code) = raw(&c.relay.url, "POST", "/v1/connect", None, &[], b"{}");
    assert_eq!((status, code.as_str()), (410, "hosted_retired"));
    let _ = operator;
}

/// `DeviceKey` has no `Clone`: a test that moves the fixture keeps a second key from the
/// same secret.
trait CloneKey {
    fn clone_key(&self) -> DeviceKey;
}

impl CloneKey for DeviceKey {
    fn clone_key(&self) -> DeviceKey {
        DeviceKey::from_pkcs8(self.pkcs8()).unwrap()
    }
}

#[test]
fn a_cutover_stopped_before_its_commit_point_is_finished_by_a_second_run() {
    for at in [
        Interrupt::StagedOneStore,
        Interrupt::ExportedDirectory,
        Interrupt::Staged,
        Interrupt::KeptKeyed,
    ] {
        stopped_and_finished(at);
    }
}

#[test]
fn a_cutover_stopped_after_its_commit_point_is_finished_by_a_second_run() {
    for at in [
        Interrupt::Committed,
        Interrupt::MovedOneStore,
        Interrupt::DeletedOneTeam,
        Interrupt::Recorded,
    ] {
        stopped_and_finished(at);
    }
}

/// A cutover stopped at `at` as a kill stops it: no team key on the disk in plain, no start
/// in either mode, and a second run that finishes it to the same result.
fn stopped_and_finished(at: Interrupt) {
    {
        let f = fixture();
        let keys = f.file_keys();
        let error = f.run_until(at).unwrap_err();
        assert!(
            error.message.contains("stopped for a test"),
            "{at:?}: {}",
            error.message
        );
        // No team key is on the disk in plain at any point: the edits and the vacuum of
        // relay.db are made on a keyed copy, and only the result is exported.
        assert_no_plain_key(f.data(), &keys, &format!("{at:?}"));
        let committed = !matches!(
            at,
            Interrupt::StagedOneStore
                | Interrupt::ExportedDirectory
                | Interrupt::Staged
                | Interrupt::KeptKeyed
        );
        assert_eq!(is_plain(&f.data().join("relay.db")), committed, "{at:?}");
        // Neither mode starts on a cutover that is not finished, and the refused start
        // changes nothing (no sweep, no migration, no write).
        let before = contents(f.data());
        let refused = match Relay::start(connect_on_any_port(&f.config)) {
            Ok(running) => {
                running.stop();
                panic!("{at:?}: connect mode started on a cutover that is not finished");
            }
            Err(error) => error,
        };
        assert!(
            refused.message.contains("connect-cutover"),
            "{at:?}: {}",
            refused.message
        );
        assert!(
            !refused.message.contains("delete"),
            "{at:?}: {}",
            refused.message
        );
        assert_eq!(
            contents(f.data()),
            before,
            "{at:?}: the refused start wrote"
        );
        if committed {
            // The keys are still there until the end, and the record names the plan.
            assert!(
                f.data().join(cutover::KEYED_DIRECTORY_FILE).exists(),
                "{at:?}"
            );
            assert!(
                cutover::keyed_row_exists(&f.config, &f.store).unwrap(),
                "{at:?}"
            );
            // The relay mode refuses the plain relay.db with a message that names the way.
            let refused = match Relay::start(relay_on_any_port(&f.config)) {
                Ok(running) => {
                    running.stop();
                    panic!("{at:?}: relay mode started on a committed cutover");
                }
                Err(error) => error,
            };
            assert!(
                refused.message.contains("connect-cutover"),
                "{at:?}: {}",
                refused.message
            );
            // No backup of a committed cutover: the keyed copy is not part of it.
            let error = cutover::stopped_backup(&f.config, now() + 11).unwrap_err();
            assert!(
                error.message.contains("connect-cutover"),
                "{}",
                error.message
            );
            // A dry run of a committed cutover changes nothing and says what is left.
            let pending = f.run(false).unwrap();
            assert!(pending.pending.is_some(), "{at:?}");
            assert_eq!(pending.state, "committing", "{at:?}");
            assert!(!pending.changed, "{at:?}");
            let line = cutover::summary(&pending);
            assert!(
                line.contains("committed and not finished"),
                "{at:?}: {line}"
            );
            assert_eq!(contents(f.data()), before, "{at:?}");
        } else {
            // Before the commit point nothing of the relay changed: a backup check of the
            // data directory as it is still passes (the side files are not data).
            let report = f.run(false).unwrap();
            assert_eq!(report.state, "dry_run", "{at:?}");
        }
        // Every file of a kept store is still there at the interruption.
        for store in [&f.store, &f.other_store] {
            assert!(
                f.config.team_path(store).exists(),
                "{at:?}: the file of {store} is gone"
            );
        }
        assert!(f.config.sync_dir(&f.store).join("2.bin").exists(), "{at:?}");
        let report = f.run(true).unwrap();
        assert_eq!(report.state, "done", "{at:?}");
        assert!(report.changed, "{at:?}");
        assert!(
            !f.data().join(cutover::KEYED_DIRECTORY_FILE).exists(),
            "{at:?}"
        );
        // The record lists every file that went, also those of an earlier run.
        let after: BTreeSet<&str> = report
            .files_after
            .as_ref()
            .unwrap()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        let gone: Vec<String> = report
            .files_before
            .iter()
            .filter(|entry| !after.contains(entry.name.as_str()))
            .map(|entry| entry.name.clone())
            .collect();
        assert_eq!(report.files_deleted, gone, "{at:?}");
        for team in [&f.operator, &f.free, &f.suspended] {
            assert!(
                report.files_deleted.contains(&format!("teams/{team}.db")),
                "{at:?}: {team}"
            );
        }
        let mut expected = vec![
            "relay.db".to_string(),
            cutover::CUTOVER_FILE.to_string(),
            format!("teams/{}.db", f.store),
            format!("teams/{}.db", f.other_store),
            format!("teams/{}.sync/1.bin", f.store),
            format!("teams/{}.sync/2.bin", f.store),
        ];
        expected.sort();
        let left: Vec<String> = names(f.data())
            .into_iter()
            .filter(|name| name != "relay.lock")
            .collect();
        assert_eq!(left, expected, "{at:?}");
        let (c, mut account, store, device, mut pusher, snapshots) = f.start_connect();
        check_store_works(&c, &mut account, &store, device, &mut pusher, &snapshots);
    }
}

#[test]
fn a_cutover_that_fails_before_its_commit_point_leaves_no_side_file() {
    for at in [
        Interrupt::StagedOneStore,
        Interrupt::ExportedDirectory,
        Interrupt::Staged,
        Interrupt::KeptKeyed,
    ] {
        let f = fixture();
        let before = contents(f.data());
        let error = f.fail_at(at).unwrap_err();
        assert!(
            error.message.contains("failed for a test"),
            "{at:?}: {}",
            error.message
        );
        // The error removed every side file: the data directory is the bytes it was, with
        // no plain copy, no keyed copy, and no record.
        assert_eq!(contents(f.data()), before, "{at:?}");
        assert!(!is_plain(&f.data().join("relay.db")), "{at:?}");
        // The backup still matches: a new run can start at once.
        assert_eq!(f.run(false).unwrap().state, "dry_run", "{at:?}");
    }
}

#[test]
fn a_stale_keyed_copy_beside_a_keyed_relay_db_blocks_neither_backup_nor_cutover() {
    let f = fixture();
    // The process died between the two renames: relay.db is keyed and whole, and
    // relay.db.keyed is a copy beside it.
    f.run_until(Interrupt::KeptKeyed).unwrap_err();
    assert!(f.data().join(cutover::KEYED_DIRECTORY_FILE).exists());
    assert!(!is_plain(&f.data().join("relay.db")));
    // The relay ran again on it, as before the cutover, and wrote.
    let operator = f.operator.clone();
    let owner_token = f.owner_token.clone();
    let config = f.config.clone();
    let relay = start_existing(config, f.dir, Some(operator.clone()), &owner_token);
    relay.ok("GET", "/v1/me", &owner_token, None);
    relay.operator(Command::Backup).unwrap();
    let (config, dir) = relay.stop_keep();
    // The backup of the stopped relay works, without the stale copy in it.
    let manifest = cutover::stopped_backup(&config, now() + 7).unwrap();
    assert!(
        manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["name"] != cutover::KEYED_DIRECTORY_FILE)
    );
    // The cutover recovers by itself: the stale copy goes, the run finishes.
    let plan = cutover::run(&config, &Options::default(), now())
        .unwrap()
        .plan_sha256;
    let report = cutover::run(
        &config,
        &Options {
            confirm: Some(plan),
            ..Options::default()
        },
        now(),
    )
    .unwrap();
    assert_eq!(report.state, "done");
    assert!(!config.data_dir.join(cutover::KEYED_DIRECTORY_FILE).exists());
    assert!(is_plain(&config.directory_path()));
    drop(dir);
}

#[test]
fn a_resumed_cutover_checks_the_backup_again_before_it_deletes() {
    let f = fixture();
    let plan = f.plan();
    f.run_until(Interrupt::Committed).unwrap_err();
    let backup = f.backup();
    let before = contents(f.data());
    let resume = || {
        f.run_with(Options {
            confirm: Some(plan.clone()),
            ..Options::default()
        })
    };
    // The backup is gone: nothing is deleted.
    let away = backup.with_file_name("moved-away");
    std::fs::rename(&backup, &away).unwrap();
    let error = resume().unwrap_err();
    assert!(error.message.contains("backup"), "{}", error.message);
    assert_eq!(contents(f.data()), before);
    std::fs::rename(&away, &backup).unwrap();
    // A file of the backup changed: nothing is deleted either.
    let damaged = backup.join(format!("teams/{}.db", f.operator));
    let kept = std::fs::read(&damaged).unwrap();
    std::fs::write(&damaged, b"damaged").unwrap();
    let error = resume().unwrap_err();
    assert!(error.message.contains("backup"), "{}", error.message);
    assert_eq!(contents(f.data()), before);
    std::fs::write(&damaged, kept).unwrap();
    // The backup as it was: the run finishes.
    assert_eq!(resume().unwrap().state, "done");
}

#[test]
fn the_keyed_copy_is_deleted_only_when_it_is_the_relay_db_of_the_inventory() {
    let f = fixture();
    let plan = f.plan();
    f.run_until(Interrupt::Committed).unwrap_err();
    let keyed = f.data().join(cutover::KEYED_DIRECTORY_FILE);
    let mut bytes = std::fs::read(&keyed).unwrap();
    bytes.extend_from_slice(&[0u8; 16]);
    std::fs::write(&keyed, &bytes).unwrap();
    let before = contents(f.data());
    let error = f
        .run_with(Options {
            confirm: Some(plan),
            ..Options::default()
        })
        .unwrap_err();
    assert!(
        error.message.contains(cutover::KEYED_DIRECTORY_FILE),
        "{}",
        error.message
    );
    assert!(keyed.exists());
    assert_eq!(contents(f.data()), before);
}

#[test]
fn the_confirmed_run_is_bound_to_the_plan_of_the_dry_run() {
    let f = fixture();
    let plan = f.plan();
    assert_eq!(plan.len(), 64);
    assert!(plan.bytes().all(|byte| byte.is_ascii_hexdigit()));
    // The same state gives the same plan.
    assert_eq!(f.plan(), plan);
    let before = contents(f.data());
    let confirm = |plan: &str| {
        f.run_with(Options {
            confirm: Some(plan.to_string()),
            ..Options::default()
        })
    };
    for wrong in ["0".repeat(64), String::new(), plan[..32].to_string()] {
        let error = confirm(&wrong).unwrap_err();
        assert!(error.message.contains("plan"), "{}", error.message);
        assert_eq!(contents(f.data()), before);
    }
    // A newer stopped backup is another plan: the old confirmation is refused.
    cutover::stopped_backup(&f.config, now() + 9).unwrap();
    let newer = f.plan();
    assert_ne!(newer, plan);
    let error = confirm(&plan).unwrap_err();
    assert!(error.message.contains("plan"), "{}", error.message);
    assert_eq!(contents(f.data()), before);
    let report = confirm(&newer).unwrap();
    assert_eq!((report.state.as_str(), report.plan_sha256), ("done", newer));
}

#[test]
fn the_backup_and_the_cutover_cover_every_file_and_leave_no_keyed_copy_of_a_store() {
    let f = fixture();
    // Files of a migration that stopped: the cutover deletes them, so the backup has them.
    for name in ["relay.db.migrating", "relay.db.migrating-journal"] {
        std::fs::write(f.data().join(name), format!("left by a migration: {name}")).unwrap();
    }
    // A keyed copy of a kept store from before a schema change (`.pre-v7`): it becomes a
    // plain copy, never an unreadable file.
    let store_file = f.config.team_path(&f.store);
    let pre = store_file.with_extension("db.pre-v7");
    std::fs::copy(&store_file, &pre).unwrap();
    // A keyed copy from an older team schema (`.pre-v6`, another version and table set):
    // it becomes plain too, with its own version and rows.
    let pre_v6 = store_file.with_extension("db.pre-v6");
    std::fs::copy(&store_file, &pre_v6).unwrap();
    {
        let key = f.file_key(&f.store);
        let old = Store::open_at(&pre_v6, &key).unwrap();
        old.with(|conn| {
            conn.execute_batch(
                "CREATE TABLE old_v6 (v TEXT); INSERT INTO old_v6 VALUES ('six'); PRAGMA user_version = 6;",
            )
            .map_err(apassy_relay::server::store::db)
        })
        .unwrap();
    }
    let manifest = cutover::stopped_backup(&f.config, now() + 4).unwrap();
    let listed: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    for name in [
        "relay.db.migrating",
        "relay.db.migrating-journal",
        &format!("teams/{}.db.pre-v7", f.store),
        &format!("teams/{}.db.pre-v6", f.store),
    ] {
        assert!(listed.contains(&name), "{name} is not in the backup");
    }
    let plan = f.dry().unwrap();
    for name in [
        format!("teams/{}.db.pre-v7", f.store),
        format!("teams/{}.db.pre-v6", f.store),
    ] {
        assert!(plan.converted.contains(&name), "{:?}", plan.converted);
    }
    let report = f.run(true).unwrap();
    assert_eq!(report.state, "done");
    for name in ["relay.db.migrating", "relay.db.migrating-journal"] {
        assert!(!f.data().join(name).exists(), "{name}");
        assert!(report.files_deleted.contains(&name.to_string()), "{name}");
    }
    assert!(
        is_plain(&pre),
        "the .pre-v7 copy of a kept store is still keyed"
    );
    let conn = rusqlite::Connection::open(&pre).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 8);
    let heads: i64 = conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .unwrap();
    assert!(heads > 0);
    let conn = rusqlite::Connection::open(&pre_v6).unwrap();
    let (version, six): (i64, String) = (
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap(),
        conn.query_row("SELECT v FROM old_v6", [], |row| row.get(0))
            .unwrap(),
    );
    assert_eq!((version, six.as_str()), (6, "six"));
}

#[test]
fn a_relay_without_a_teams_folder_cuts_over() {
    let relay = start_with(|_| {}, UpstreamOptions::default());
    let (mut config, dir) = relay.stop_keep();
    config.data_dir = dir.path().join("empty");
    config.backup_dir = dir.path().join("empty-backups");
    Relay::init_empty(&config).unwrap();
    assert!(!config.teams_dir().exists());
    cutover::stopped_backup(&config, now()).unwrap();
    let plan = cutover::run(&config, &Options::default(), now())
        .unwrap()
        .plan_sha256;
    let report = cutover::run(
        &config,
        &Options {
            confirm: Some(plan),
            ..Options::default()
        },
        now(),
    )
    .unwrap();
    assert_eq!((report.state.as_str(), report.kept.len()), ("done", 0));
    assert!(is_plain(&config.directory_path()));
    let running = Relay::start(connect_on_any_port(&config)).unwrap();
    running.stop();
}

#[test]
fn the_stopped_backup_restores_a_cutover_stopped_halfway() {
    let f = fixture();
    let backup = std::fs::read_dir(&f.config.backup_dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .next()
        .unwrap();
    let error = f.run_until(Interrupt::DeletedOneTeam).unwrap_err();
    assert!(error.message.contains("stopped for a test"));
    // Some teams are gone already: the restore puts the backup's files into an empty data
    // directory, and the relay starts with the master key as before the cutover.
    let restored = tempfile::tempdir().unwrap();
    let mut config = f.config.clone();
    config.data_dir = restored.path().join("data");
    copy_tree(&backup, &config.data_dir);
    std::fs::remove_file(config.data_dir.join("MANIFEST.json")).unwrap();
    assert_eq!(sync::verify_restored(&config).unwrap(), 5);
    let relay = start_existing(config, restored, Some(f.operator.clone()), &f.owner_token);
    relay.ok("GET", "/v1/me", &f.owner_token, None);
    let token = relay.sign_in(&f.operator, &f.operator_key);
    assert_eq!(relay.ok("GET", "/v1/sync/head", &token, None)["version"], 1);
    let free_token = relay.sign_in(&f.free, &f.free_key);
    assert_eq!(
        relay.ok("GET", "/v1/sync/head", &free_token, None)["version"],
        1
    );
    let store_token = relay.sign_in(&f.store, &f.account.key);
    assert_eq!(
        relay.ok("GET", "/v1/sync/head", &store_token, None)["version"],
        2
    );
}

#[test]
fn the_cutover_never_deletes_a_file_of_an_account_store() {
    let f = fixture();
    // A file of a store that does not open with the store's key: after the cutover no key
    // would open it, so the cutover refuses before any change, and names it.
    let unreadable = f.config.team_path(&f.store).with_extension("db.pre-v7");
    std::fs::write(&unreadable, "not a file of the store's key").unwrap();
    cutover::stopped_backup(&f.config, now() + 2).unwrap();
    let before = contents(f.data());
    for options in [
        Options::default(),
        Options {
            confirm: Some("0".repeat(64)),
            ..Options::default()
        },
    ] {
        let error = f.run_with(options).unwrap_err();
        assert!(
            error
                .message
                .contains(&format!("teams/{}.db.pre-v7", f.store)),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("does not open with the store's key"),
            "{}",
            error.message
        );
        assert!(!error.message.contains("admin delete"), "{}", error.message);
        assert_eq!(contents(f.data()), before);
    }
    std::fs::remove_file(&unreadable).unwrap();
    // Files of a store that the relay never makes (a plain old copy, an extra snapshot):
    // the cutover leaves them, byte for byte; the files of the other teams go.
    let plain_copy = f.config.team_path(&f.store).with_extension("db.pre-v5");
    rusqlite::Connection::open(&plain_copy)
        .unwrap()
        .execute_batch("CREATE TABLE note (v TEXT); INSERT INTO note VALUES ('plain');")
        .unwrap();
    let extra = [
        plain_copy.clone(),
        f.config.sync_dir(&f.other_store).join("9.bin"),
    ];
    std::fs::create_dir_all(f.config.sync_dir(&f.other_store)).unwrap();
    std::fs::write(&extra[1], "store file 1").unwrap();
    let extra_bytes: Vec<Vec<u8>> = extra
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    // A file of no team stays and is named; another folder of a team that goes, goes.
    let stray = f.config.teams_dir().join("notes.txt");
    std::fs::write(&stray, "an operator's note").unwrap();
    let other_folder = f.config.teams_dir().join(format!("{}.extra", f.free));
    std::fs::create_dir_all(&other_folder).unwrap();
    std::fs::write(other_folder.join("x.bin"), "a file of the free team").unwrap();
    // The backup must be of the directory as it is now.
    cutover::stopped_backup(&f.config, now() + 3).unwrap();
    let report = f.run(true).unwrap();
    assert_eq!(report.state, "done");
    for (path, bytes) in extra.iter().zip(&extra_bytes) {
        assert_eq!(&std::fs::read(path).unwrap(), bytes, "{}", path.display());
    }
    for name in &report.files_deleted {
        let id = name
            .strip_prefix("teams/")
            .and_then(|rest| rest.split('.').next())
            .and_then(TeamId::parse);
        assert!(
            id.as_ref()
                .is_none_or(|id| id != &f.store && id != &f.other_store),
            "{name} was deleted"
        );
    }
    assert!(
        report
            .files_deleted
            .iter()
            .any(|name| name.starts_with(&format!("teams/{}", f.operator)))
    );
    assert_eq!(
        std::fs::read_to_string(&stray).unwrap(),
        "an operator's note"
    );
    assert!(
        report.left.contains(&"teams/notes.txt".to_string()),
        "{:?}",
        report.left
    );
    assert!(!other_folder.exists());
    assert!(
        report
            .files_deleted
            .contains(&format!("teams/{}.extra/x.bin", f.free))
    );
    // A plain file of a store (no key opens it, none needs to) is left and named.
    assert!(
        report
            .left
            .contains(&format!("teams/{}.db.pre-v5", f.store)),
        "{:?}",
        report.left
    );
}

/// `connect` mode starts on the data directory of `config`, then stops; or the error.
fn connect_start(config: &RelayConfig) -> Result<(), apassy_relay::error::RelayError> {
    Relay::start(connect_on_any_port(config)).map(|running| running.stop())
}

#[test]
fn the_start_after_a_finished_cutover_reads_the_files_when_the_record_is_damaged() {
    let f = fixture();
    assert_eq!(f.run(true).unwrap().state, "done");
    let record = f.data().join(cutover::CUTOVER_FILE);
    let good = std::fs::read(&record).unwrap();
    let mut committing: Value = serde_json::from_slice(&good).unwrap();
    committing["state"] = json!("committing");
    // A record that cannot be read, or that says another state: the files are those of a
    // finished cutover, so connect mode starts, and the record is left as it is.
    for damaged in [
        b"{ not json".to_vec(),
        Vec::new(),
        serde_json::to_vec(&committing).unwrap(),
    ] {
        std::fs::write(&record, &damaged).unwrap();
        connect_start(&f.config).unwrap();
        assert_eq!(
            std::fs::read(&record).unwrap(),
            damaged,
            "the start rewrote the record"
        );
        // The cutover says that there is nothing to do, and why, without a change.
        let before = contents(f.data());
        let error = f.dry().unwrap_err();
        assert!(
            error.message.contains("in the form of a finished cutover"),
            "{}",
            error.message
        );
        assert_eq!(contents(f.data()), before);
    }
    // A hot journal of the plain relay.db (a crash of Connect mid-write) beside a damaged
    // record: the start check reads no page, the relay rolls the write back and starts.
    std::fs::write(&record, b"{ not json").unwrap();
    let copy = tempfile::tempdir().unwrap();
    let mut config = f.config.clone();
    config.data_dir = copy.path().join("data");
    {
        let conn = rusqlite::Connection::open(f.data().join("relay.db")).unwrap();
        conn.execute_batch(
            "PRAGMA cache_size = 2; BEGIN; CREATE TABLE torn (v BLOB); \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 400) \
             INSERT INTO torn SELECT randomblob(2000) FROM n;",
        )
        .unwrap();
        // The copy, taken while the write is open, is the disk after a crash at this point.
        copy_tree(f.data(), &config.data_dir);
        conn.execute_batch("ROLLBACK").unwrap();
    }
    let _ = std::fs::remove_file(config.data_dir.join("relay.lock"));
    assert!(config.data_dir.join("relay.db-journal").exists());
    connect_start(&config).unwrap();
    assert!(!config.data_dir.join("relay.db-journal").exists());
    let tables: i64 = rusqlite::Connection::open(config.data_dir.join("relay.db"))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'torn'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0, "the write of the crash was not rolled back");
    assert_eq!(
        std::fs::read(config.data_dir.join(cutover::CUTOVER_FILE)).unwrap(),
        b"{ not json"
    );
    // With the record as it was, the relay starts as before.
    std::fs::write(&record, &good).unwrap();
    connect_start(&f.config).unwrap();
}

#[test]
fn the_start_refuses_a_record_that_is_not_done_when_the_cutover_is_not_finished() {
    let f = fixture();
    f.run_until(Interrupt::DeletedOneTeam).unwrap_err();
    // relay.db.keyed is lost by hand: relay.db is plain, the record says "committing", and
    // keyed files of the teams that go are still there.
    std::fs::remove_file(f.data().join(cutover::KEYED_DIRECTORY_FILE)).unwrap();
    let record = f.data().join(cutover::CUTOVER_FILE);
    let committing = std::fs::read(&record).unwrap();
    for damaged in [committing.clone(), b"{ not json".to_vec()] {
        std::fs::write(&record, &damaged).unwrap();
        let before = contents(f.data());
        let refused = connect_start(&f.config).unwrap_err();
        assert!(
            refused
                .message
                .contains("not in the form of a finished cutover"),
            "{}",
            refused.message
        );
        // The first file that shows it is named (here an old file that the cutover deletes).
        assert!(
            refused.message.contains("is there") || refused.message.contains("is encrypted"),
            "{}",
            refused.message
        );
        assert!(
            refused.message.contains("Restore the stopped backup"),
            "{}",
            refused.message
        );
        assert!(!refused.message.contains("delete"), "{}", refused.message);
        assert_eq!(contents(f.data()), before, "the refused start wrote");
        // The cutover cannot finish it, and says so.
        let error = f.dry().unwrap_err();
        assert!(
            error.message.contains("cannot finish it"),
            "{}",
            error.message
        );
        assert_eq!(contents(f.data()), before);
    }
}

#[test]
fn a_dry_run_of_a_committed_cutover_answers_what_the_confirmed_run_does() {
    let f = fixture();
    let plan = f.plan();
    f.run_until(Interrupt::Committed).unwrap_err();
    let confirm = || {
        f.run_with(Options {
            confirm: Some(plan.clone()),
            ..Options::default()
        })
    };
    let before = contents(f.data());
    let pending = f.dry().unwrap();
    assert_eq!(contents(f.data()), before, "the dry run wrote");
    assert_eq!(
        (pending.state.as_str(), pending.plan_sha256.as_str()),
        ("committing", plan.as_str())
    );
    let mut converted = pending.converted.clone();
    converted.sort();
    let mut to_convert = pending.to_convert.clone();
    to_convert.sort();
    assert_eq!(to_convert, converted);
    for team in [&f.operator, &f.free, &f.suspended] {
        assert!(
            pending.to_delete.contains(&format!("teams/{team}.db")),
            "{:?}",
            pending.to_delete
        );
    }
    assert!(pending.to_delete.contains(&"team.db.pre-teams".to_string()));
    for name in &pending.converted {
        assert!(
            pending.side_files.contains(&format!("{name}.plain")),
            "{:?}",
            pending.side_files
        );
    }
    let line = cutover::summary(&pending);
    assert!(
        line.contains("Every check of the confirmed run passed"),
        "{line}"
    );
    // A file of a team that goes, new since the backup: the dry run and the confirmed run
    // refuse alike, and nothing is deleted.
    let new = f.config.team_path(&f.operator).with_extension("db.pre-v9");
    std::fs::write(&new, b"new since the backup").unwrap();
    let before = contents(f.data());
    for error in [f.dry().unwrap_err(), confirm().unwrap_err()] {
        assert!(
            error
                .message
                .contains("is not in the backup that the cutover checked"),
            "{}",
            error.message
        );
        assert!(
            error
                .message
                .contains(&format!("teams/{}.db.pre-v9", f.operator)),
            "{}",
            error.message
        );
    }
    assert_eq!(contents(f.data()), before);
    std::fs::remove_file(&new).unwrap();
    // A record changed by hand (a list of the plan): it no longer gives its own plan, so
    // the dry run and the confirmed run refuse alike.
    let record = f.data().join(cutover::CUTOVER_FILE);
    let original = std::fs::read(&record).unwrap();
    for edit in ["converted", "left"] {
        let mut edited: Value = serde_json::from_slice(&original).unwrap();
        match edit {
            "converted" => {
                edited["converted"].as_array_mut().unwrap().pop();
            }
            _ => edited["left"] = json!([format!("teams/{}.db", f.operator)]),
        }
        std::fs::write(&record, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
        let before = contents(f.data());
        for error in [f.dry().unwrap_err(), confirm().unwrap_err()] {
            assert!(
                error.message.contains("does not give its own plan_sha256"),
                "{edit}: {}",
                error.message
            );
        }
        assert_eq!(contents(f.data()), before, "{edit}");
    }
    std::fs::write(&record, &original).unwrap();
    let done = confirm().unwrap();
    assert_eq!(done.state, "done");
    assert_eq!(done.files_deleted, pending.to_delete);
    assert!(done.to_convert.is_empty() && done.to_delete.is_empty());
}

#[test]
fn a_resumed_cutover_writes_a_missing_or_partial_plain_copy_again() {
    let f = fixture();
    let plan = f.plan();
    f.run_until(Interrupt::Committed).unwrap_err();
    // A re-export that stopped: one copy is half written, with a journal; the other is gone.
    let partial = f.data().join(format!("teams/{}.db.plain", f.store));
    let bytes = std::fs::read(&partial).unwrap();
    std::fs::write(&partial, &bytes[..bytes.len() / 2]).unwrap();
    std::fs::write(
        f.data().join(format!("teams/{}.db.plain-journal", f.store)),
        [0xd9u8; 600],
    )
    .unwrap();
    std::fs::remove_file(f.data().join(format!("teams/{}.db.plain", f.other_store))).unwrap();
    let pending = f.dry().unwrap();
    for store in [&f.store, &f.other_store] {
        assert!(pending.to_convert.contains(&format!("teams/{store}.db")));
    }
    assert!(
        pending
            .side_files
            .contains(&format!("teams/{}.db.plain-journal", f.store))
    );
    let report = f
        .run_with(Options {
            confirm: Some(plan),
            ..Options::default()
        })
        .unwrap();
    assert_eq!(report.state, "done");
    assert!(
        report
            .side_files
            .contains(&format!("teams/{}.db.plain-journal", f.store)),
        "{:?}",
        report.side_files
    );
    for store in [&f.store, &f.other_store] {
        assert!(is_plain(&f.config.team_path(store)));
        assert!(!f.data().join(format!("teams/{store}.db.plain")).exists());
    }
    let (c, mut account, store, device, mut pusher, snapshots) = f.start_connect();
    check_store_works(&c, &mut account, &store, device, &mut pusher, &snapshots);
}

#[test]
fn every_file_that_the_cutover_deletes_is_in_the_backup_and_the_record() {
    let f = fixture();
    // A `.plain` name of a team that goes and one of no team: data, not side files.
    let operator_plain = format!("teams/{}.db.plain", f.operator);
    std::fs::write(f.data().join(&operator_plain), b"an operator's file").unwrap();
    std::fs::write(f.data().join("teams/notes.plain"), b"a note").unwrap();
    // Files of a team id that relay.db does not name (a delete that stopped).
    let orphan = TeamId::parse("t_orphanqqq2").unwrap();
    let orphan_files = [
        format!("teams/{orphan}.db"),
        format!("teams/{orphan}.sync/1.bin"),
    ];
    std::fs::create_dir_all(f.config.sync_dir(&orphan)).unwrap();
    for name in &orphan_files {
        std::fs::write(f.data().join(name), b"left by a delete").unwrap();
    }
    // A side file of an earlier run: the plain copy of a store's file.
    let side = format!("teams/{}.db.plain", f.store);
    std::fs::write(f.data().join(&side), b"a copy of a run that stopped").unwrap();
    let manifest = cutover::stopped_backup(&f.config, now() + 6).unwrap();
    let listed: BTreeSet<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    for name in orphan_files
        .iter()
        .chain([&operator_plain, &"teams/notes.plain".to_string()])
    {
        assert!(
            listed.contains(name.as_str()),
            "{name} is not in the backup"
        );
    }
    assert!(
        !listed.contains(side.as_str()),
        "a side file is in the backup"
    );
    let plan = f.dry().unwrap();
    assert_eq!(plan.orphans, vec![orphan.clone()]);
    assert!(plan.side_files.contains(&side), "{:?}", plan.side_files);
    assert!(plan.left.contains(&"teams/notes.plain".to_string()));
    assert!(cutover::summary(&plan).contains("1 team ids that relay.db does not name"));
    let report = f.run(true).unwrap();
    assert_eq!(report.state, "done");
    for name in orphan_files.iter().chain([&operator_plain]) {
        assert!(
            report.files_deleted.contains(name),
            "{name} went without being counted"
        );
        assert!(!f.data().join(name).exists(), "{name}");
    }
    // Everything that went is in the inventory, so in the backup.
    let before: BTreeSet<&str> = report
        .files_before
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    for name in &report.files_deleted {
        assert!(before.contains(name.as_str()), "{name}");
        assert!(listed.contains(name.as_str()), "{name}");
    }
    assert!(report.side_files.contains(&side));
    assert_eq!(report.orphans, vec![orphan]);
    assert_eq!(
        std::fs::read(f.data().join("teams/notes.plain")).unwrap(),
        b"a note"
    );
    let record: Report =
        serde_json::from_slice(&std::fs::read(f.data().join(cutover::CUTOVER_FILE)).unwrap())
            .unwrap();
    assert_eq!(record.files_deleted, report.files_deleted);
    assert!(record.side_files.contains(&side));
}

#[test]
fn admin_delete_never_deletes_a_vault_store_in_either_mode() {
    let refuse = |c: &Connect, store: &TeamId, path: &Path| {
        c.relay
            .operator(Command::Suspend {
                team: store.clone(),
            })
            .unwrap();
        for free_connect_key in [false, true] {
            let error = c
                .relay
                .operator(Command::Delete {
                    team: store.clone(),
                    free_connect_key,
                })
                .unwrap_err();
            // The operator socket carries the code in the message.
            assert!(error.message.contains("conflict"), "{}", error.message);
            assert!(
                error.message.contains("Nothing was changed"),
                "{}",
                error.message
            );
            assert!(
                error
                    .message
                    .contains("DELETE /v1/account/vaults/{team_id}")
                    && error.message.contains("DELETE /v1/account"),
                "{}",
                error.message
            );
        }
        assert!(path.exists(), "the store's file is gone");
        let teams = c.relay.operator(Command::Teams).unwrap();
        assert!(
            teams
                .as_array()
                .unwrap()
                .iter()
                .any(|team| team["id"] == store.as_str()),
            "{teams}"
        );
    };
    // The hosted relay with accounts on.
    let c = connect::start_with_config(|_| {});
    let account = c.account("Rafal");
    c.subscribe(&account, "connect_personal_month", 1);
    let (store, _) = c.store(&account, VAULT);
    let store = TeamId::parse(&store).unwrap();
    let path = c.relay.config.team_path(&store);
    refuse(&c, &store, &path);
    // Connect mode.
    let c = connect_relay();
    let account = c.account("Rafal");
    c.subscribe(&account, "connect_personal_month", 1);
    let (store, _) = c.store(&account, VAULT);
    let store = TeamId::parse(&store).unwrap();
    let path = c.relay.config.team_path(&store);
    refuse(&c, &store, &path);
}

#[test]
fn the_binary_backs_up_cuts_over_and_serves_connect_mode() {
    use std::process::Command as Process;
    let dir = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_apassy-relay");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let relay = |mode: Option<&str>| {
        let mut command = Process::new(binary);
        command
            .env_clear()
            .env("APASSY_RELAY_DATA", dir.path().join("data"))
            .env("APASSY_RELAY_BACKUP_DIR", dir.path().join("backups"))
            .env("APASSY_RELAY_LISTEN", format!("127.0.0.1:{port}"))
            .env("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test")
            .env("APASSY_RELAY_EDGE_SECRET", EDGE_SECRET);
        match mode {
            Some(mode) => command.env("APASSY_RELAY_MODE", mode),
            None => command.env("APASSY_RELAY_KEY", VAULT_KEY),
        };
        command
    };
    let output = relay(None)
        .args(["init", "--team", "Acme", "--owner", "olga"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    // Without a stopped backup the cutover exits 1 and says what to do.
    let output = relay(None).arg("connect-cutover").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("apassy-relay backup"));
    let output = relay(None).arg("backup").output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The dry run is the default: exit 0, the plan on stdout, no change.
    let output = relay(None).arg("connect-cutover").output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        (
            plan["state"].as_str(),
            plan["deleted"].as_array().map(Vec::len)
        ),
        (Some("dry_run"), Some(1))
    );
    assert!(!is_plain(&dir.path().join("data/relay.db")));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--confirm-delete-teams"));
    let plan_sha256 = plan["plan_sha256"].as_str().unwrap().to_string();
    assert_eq!(plan_sha256.len(), 64);
    // Without the plan, or with another one, the binary refuses and changes nothing.
    let output = relay(None)
        .args(["connect-cutover", "--confirm-delete-teams"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let output = relay(None)
        .args(["connect-cutover", "--confirm-delete-teams", &"0".repeat(64)])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("plan"));
    assert!(!is_plain(&dir.path().join("data/relay.db")));
    let output = relay(None)
        .args(["connect-cutover", "--confirm-delete-teams", &plan_sha256])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let done: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(done["state"], "done");
    assert!(is_plain(&dir.path().join("data/relay.db")));
    // `connect` mode with a master key is refused; without one it serves.
    let refused = relay(Some("connect"))
        .env("APASSY_RELAY_KEY", VAULT_KEY)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    let mut child = relay(Some("connect"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let started = std::time::Instant::now();
    let headers = loop {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .into();
        if let Ok(response) = agent.get(format!("{base}/healthz")).call() {
            break response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    )
                })
                .collect::<Vec<_>>();
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the relay did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(header(&headers, "x-apassy-relay-mode"), Some("connect"));
    let (status, code) = raw(&base, "POST", "/v1/teams", None, &[], b"{}");
    assert_eq!((status, code.as_str()), (410, "hosted_retired"));
    child.kill().unwrap();
    let _ = child.wait();
    // A second cutover in `connect` mode answers the record of the finished one.
    let output = relay(Some("connect"))
        .arg("connect-cutover")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let again: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(again["state"], "done");
    let _ = BillingSettings::new;
    let _ = ConnectConfig::default;
}
