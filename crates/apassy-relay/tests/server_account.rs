//! Apassy Connect accounts on the relay (plan s7 unit C1, contract connect-account-v1,
//! docs/SPEC.md section 33): accounts, account devices, links and joins, sign-in, revoke,
//! vault stores, recovery, the entitlement token, plain files in `connect` mode, and the
//! directory step. Each test starts its own relay on a free loopback port in a temporary
//! directory. Synthetic values only.

#[path = "common/relay.rs"]
mod relay;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apassy_relay::api::PlanView;
use apassy_relay::config::{
    ConnectConfig, ConnectSigningKey, EdgeMode, RelayConfig, RelayMode, UpstreamOptions,
};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::{decode_b64, encode_b64};
use apassy_relay::ids::TeamId;
use apassy_relay::secret::SecretString;
use apassy_relay::server::RunningRelay;
use apassy_relay::server::account::Plans;
use apassy_relay::server::directory::{DIRECTORY_VERSION, Directory};
use apassy_relay::server::entitlement::{Entitlement, PublishedKey, key_id};
use apassy_relay::server::store::Store;
use apassy_relay::sync_head::{head_hash, hex};
use relay::{EDGE_SECRET, TestRelay, call_url, start_with};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../tests/fixtures/connect-account-v1/vectors.json");
const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// A list hash that no entry has: b64u of 32 zero bytes.
const ZEROS_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

/// The Ed25519 seed of the vectors (bytes 32 to 63) as a PKCS#8 v1 DER file.
fn signing_key() -> ConnectSigningKey {
    let mut der = unhex("302e020100300506032b657004220420");
    der.extend((32u8..64).collect::<Vec<_>>());
    ConnectSigningKey::from_file_bytes(&der).expect("signing key")
}

// ---- The plans of the tests: billing (C2) fills the real ones. ----

#[derive(Default)]
struct TestPlans(Mutex<HashMap<String, PlanView>>);

impl TestPlans {
    fn set(&self, account: &str, plan: PlanView) {
        self.0.lock().unwrap().insert(account.to_string(), plan);
    }
}

impl Plans for TestPlans {
    fn plan(
        &self,
        _directory: &Store,
        account: &str,
        _now: u64,
    ) -> apassy_relay::error::RelayResult<PlanView> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(account)
            .cloned()
            .unwrap_or_else(PlanView::none))
    }
}

fn entitled() -> PlanView {
    PlanView {
        plan: Some("personal".into()),
        status: "active".into(),
        entitled: true,
        interval: Some("month".into()),
        quantity: Some(1),
        ..PlanView::none()
    }
}

fn read_only() -> PlanView {
    PlanView {
        plan: Some("personal".into()),
        status: "read_only".into(),
        entitled: false,
        ..PlanView::none()
    }
}

fn suspended() -> PlanView {
    PlanView {
        plan: Some("personal".into()),
        status: "suspended".into(),
        entitled: false,
        ..PlanView::none()
    }
}

// ---- A relay with the account routes. ----

struct Connect {
    relay: TestRelay,
    plans: Arc<TestPlans>,
}

fn accounts_on(cfg: &mut RelayConfig) {
    cfg.connect = ConnectConfig::accounts(Some(signing_key()));
}

fn start() -> Connect {
    connect_with(accounts_on)
}

fn connect_with(config: impl FnOnce(&mut RelayConfig)) -> Connect {
    let relay = start_with(config, UpstreamOptions::default());
    let plans = Arc::new(TestPlans::default());
    relay.hub().set_plans(plans.clone());
    Connect { relay, plans }
}

impl Connect {
    fn origin(&self) -> &str {
        &self.relay.config.public_url
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        call_url(
            &self.relay.url,
            Some(EDGE_SECRET),
            method,
            path,
            token,
            body,
        )
    }

    fn ok(&self, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> Value {
        let (status, value) = self.call(method, path, token, body);
        assert_eq!(status, 200, "{method} {path}: {value}");
        value["result"].clone()
    }

    fn fails(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        status: u16,
        code: &str,
    ) {
        let (got, value) = self.call(method, path, token, body);
        assert_eq!(
            (got, value["error"]["code"].as_str()),
            (status, Some(code)),
            "{method} {path}: {value}"
        );
    }

    /// Runs SQL on `relay.db` while the relay runs (a time in the past).
    fn edit_directory(&self, sql: &str) {
        let conn = rusqlite::Connection::open(self.relay.config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
            .unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    fn directory_rows(&self, sql: &str) -> Vec<String> {
        let conn = rusqlite::Connection::open(self.relay.config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
            .unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        let mut statement = conn.prepare(sql).unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }
}

/// An account device of a test: its key and, once it is one, its ids.
struct Dev {
    key: DeviceKey,
    account: String,
    id: String,
}

fn recovery_key(code: &[u8; 16]) -> device::RecoveryKey {
    device::RecoveryKey::from_code(code).unwrap()
}

/// A new account id as a device makes it: `acc_` and 10 random characters of `a-z2-7`.
fn new_account_id() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 10];
    getrandom::fill(&mut bytes).unwrap();
    let id: String = bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(byte & 31)]))
        .collect();
    format!("acc_{id}")
}

/// The signature of `key` over the root entry (version 1) of the device list of `account`
/// with the device name `name`.
fn root_statement(c: &Connect, account: &str, key: &DeviceKey, name: &str) -> String {
    let public_key = key.public_key_b64();
    let message = device::account_list_message(
        c.origin(),
        account,
        1,
        device::LIST_NONE,
        "root",
        &public_key,
        device::LIST_NONE,
        name,
        &public_key,
    );
    encode_b64(&key.sign(&message).unwrap())
}

fn account_body(c: &Connect, key: &DeviceKey, recovery: &[u8; 16]) -> Value {
    let account = new_account_id();
    let public_key = key.public_key_b64();
    let recovery_key = recovery_key(recovery).public_key_b64();
    let signature = key
        .sign(&device::account_message(
            c.origin(),
            &public_key,
            &recovery_key,
        ))
        .unwrap();
    json!({"account_id": account, "name": "Rafal", "device_name": "MacBook Pro",
           "platform": "mac", "public_key": public_key, "recovery_key": recovery_key,
           "signature": encode_b64(&signature),
           "statement": root_statement(c, &account, key, "MacBook Pro")})
}

fn create(c: &Connect) -> Dev {
    let key = DeviceKey::generate().unwrap();
    let made = c.ok(
        "POST",
        "/v1/account",
        None,
        Some(&account_body(c, &key, &[7u8; 16])),
    );
    Dev {
        key,
        account: made["account_id"].as_str().unwrap().to_string(),
        id: made["device_id"].as_str().unwrap().to_string(),
    }
}

fn challenge(c: &Connect, account: &str, key: &DeviceKey) -> (u16, Value) {
    c.call(
        "POST",
        "/v1/account/challenge",
        None,
        Some(&json!({"account_id": account, "public_key": key.public_key_b64()})),
    )
}

fn token_body(account: &str, key: &DeviceKey, nonce: &str, message: &[u8]) -> Value {
    json!({"account_id": account, "public_key": key.public_key_b64(), "nonce": nonce,
           "signature": encode_b64(&key.sign(message).unwrap())})
}

fn sign_in(c: &Connect, dev: &Dev) -> String {
    let (status, answer) = challenge(c, &dev.account, &dev.key);
    assert_eq!(status, 200, "{answer}");
    let nonce = answer["result"]["nonce"].as_str().unwrap().to_string();
    assert_eq!(answer["result"]["origin"], c.origin());
    let message = device::account_sign_in_message(
        c.origin(),
        &dev.account,
        &dev.key.public_key_b64(),
        &nonce,
    );
    let granted = c.ok(
        "POST",
        "/v1/account/token",
        None,
        Some(&token_body(&dev.account, &dev.key, &nonce, &message)),
    );
    assert_eq!(granted["device_id"], dev.id.as_str());
    let token = granted["token"].as_str().unwrap().to_string();
    assert!(token.starts_with(&format!("apassy_act_{}_", dev.account)));
    token
}

/// A challenge and a signed token call of `key` for `account`: the status and the error
/// code of the token call (`None` when it granted a token).
fn token_call(c: &Connect, account: &str, key: &DeviceKey) -> (u16, Option<String>) {
    let (status, answer) = challenge(c, account, key);
    assert_eq!(status, 200, "{answer}");
    let nonce = answer["result"]["nonce"].as_str().unwrap().to_string();
    let message =
        device::account_sign_in_message(c.origin(), account, &key.public_key_b64(), &nonce);
    let (status, answer) = c.call(
        "POST",
        "/v1/account/token",
        None,
        Some(&token_body(account, key, &nonce, &message)),
    );
    (status, answer["error"]["code"].as_str().map(str::to_string))
}

/// A link code of `account` as the device that adds a device makes it: the account id,
/// 64 hex of the secret, and 32 hex of the key fingerprint (synthetic here: Connect never
/// reads the code).
fn link_code(account: &str) -> String {
    let mut bytes = [0u8; 48];
    getrandom::fill(&mut bytes).unwrap();
    format!(
        "apassy_alk_{account}_{}_{}",
        hex(&bytes[..32]),
        hex(&bytes[32..])
    )
}

fn join_body(c: &Connect, account: &str, link_hash: &str, key: &DeviceKey, name: &str) -> Value {
    let public_key = key.public_key_b64();
    let signature = key
        .sign(&device::account_join_message(
            c.origin(),
            account,
            link_hash,
            &public_key,
        ))
        .unwrap();
    json!({"account_id": account, "link_hash": link_hash, "device_name": name,
           "platform": "iphone", "public_key": public_key, "signature": encode_b64(&signature)})
}

/// The version and the list hash of the head of the signed device list `list` of
/// `account` (from `GET /v1/account` or a join answer), recomputed from its entries as a
/// client does: version 1 is the root, and each later entry verifies with its `by` key.
fn head_of(c: &Connect, account: &str, list: &Value) -> (u64, String) {
    let mut previous = device::LIST_NONE.to_string();
    let mut version = 0;
    for entry in list.as_array().expect("a device list") {
        version += 1;
        assert_eq!(entry["version"].as_u64(), Some(version), "{list}");
        let message = device::account_list_message(
            c.origin(),
            account,
            version,
            &previous,
            entry["op"].as_str().unwrap(),
            entry["key"].as_str().unwrap(),
            entry["link_hash"].as_str().unwrap_or(device::LIST_NONE),
            entry["name"].as_str().unwrap_or(device::LIST_NONE),
            entry["by"].as_str().unwrap(),
        );
        // A `root` and an `add` sign a device name; a `remove` names none.
        assert_eq!(
            entry["name"].is_string(),
            entry["op"] != "remove",
            "{entry}"
        );
        if version == 1 {
            assert_eq!(entry["op"], "root", "{list}");
            assert_eq!(entry["key"], entry["by"], "the root signs itself: {list}");
        }
        // Every entry is signed by its `by` key, the root by its own key.
        let by = decode_b64(entry["by"].as_str().unwrap(), 65).unwrap();
        let signature = decode_b64(entry["signature"].as_str().expect("a signature"), 72).unwrap();
        assert!(device::verify(&by, &message, &signature), "{entry}");
        previous = device::account_list_hash(&message);
    }
    (version, previous)
}

/// The head of the device list of the account of `token`.
fn list_head(c: &Connect, account: &str, token: &str) -> (u64, String) {
    let view = c.ok("GET", "/v1/account", Some(token), None);
    head_of(c, account, &view["device_list"])
}

/// The signature of `by` over the entry `version` of the device list after `previous`:
/// `link_hash` and `name` of an `add`, `None` for a `remove`.
fn list_statement(
    c: &Connect,
    by: &Dev,
    (version, previous): (u64, &str),
    op: &str,
    key_b64: &str,
    (link_hash, name): (Option<&str>, Option<&str>),
) -> String {
    let message = device::account_list_message(
        c.origin(),
        &by.account,
        version,
        previous,
        op,
        key_b64,
        link_hash.unwrap_or(device::LIST_NONE),
        name.unwrap_or(device::LIST_NONE),
        &by.key.public_key_b64(),
    );
    encode_b64(&by.key.sign(&message).unwrap())
}

/// The body of a confirmation by `by` (signed in with `token`) of the join of `key` named
/// `name` with the link `link_hash`: the key and the `add` entry of the next version of the
/// list.
fn confirm_body(
    c: &Connect,
    by: &Dev,
    token: &str,
    link_hash: &str,
    (key, name): (&DeviceKey, &str),
) -> Value {
    let (version, previous) = list_head(c, &by.account, token);
    let statement = list_statement(
        c,
        by,
        (version + 1, &previous),
        "add",
        &key.public_key_b64(),
        (Some(link_hash), Some(name)),
    );
    json!({"public_key": key.public_key_b64(), "version": version + 1, "statement": statement})
}

/// The body of a revoke of `target` by `by` (signed in with `token`): the `remove` entry
/// of the next version of the list.
fn revoke_body(c: &Connect, by: &Dev, token: &str, target: &Dev) -> Value {
    let (version, previous) = list_head(c, &by.account, token);
    let statement = list_statement(
        c,
        by,
        (version + 1, &previous),
        "remove",
        &target.key.public_key_b64(),
        (None, None),
    );
    json!({"version": version + 1, "statement": statement})
}

/// `by` revokes `target` with a signed `remove` entry.
fn revoke(c: &Connect, by: &Dev, token: &str, target: &Dev) -> Value {
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", target.id),
        Some(token),
        Some(&revoke_body(c, by, token, target)),
    )
}

/// The body of a cancel of its join by `key`.
fn cancel_body(c: &Connect, account: &str, link_hash: &str, key: &DeviceKey) -> Value {
    let signature = key
        .sign(&device::account_join_cancel_message(
            c.origin(),
            account,
            link_hash,
            &key.public_key_b64(),
        ))
        .unwrap();
    json!({"account_id": account, "link_hash": link_hash, "public_key": key.public_key_b64(),
           "signature": encode_b64(&signature)})
}

/// The body of `POST /v1/account/vaults/{team}/devices` for `dev`.
fn store_add_body(dev: &Dev) -> Value {
    json!({"device_id": dev.id, "public_key": dev.key.public_key_b64()})
}

/// `a` adds a new device to its account: the link, the join, the confirmation.
fn add_device(c: &Connect, a: &Dev, token: &str) -> Dev {
    let code = link_code(&a.account);
    let hash = device::account_link_hash(&code);
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(token),
        Some(&json!({"link_hash": hash})),
    );
    let key = DeviceKey::generate().unwrap();
    let joined = c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(c, &a.account, &hash, &key, "iPhone")),
    );
    let join_id = joined["join_id"].as_u64().unwrap();
    let added = c.ok(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(token),
        Some(&confirm_body(c, a, token, &hash, (&key, "iPhone"))),
    );
    Dev {
        key,
        account: a.account.clone(),
        id: added["device_id"].as_str().unwrap().to_string(),
    }
}

// ---- Relay sync on a vault store. ----

struct Answer {
    status: u16,
    body: Value,
}

fn send(
    base: &str,
    method: &str,
    path: &str,
    token: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> Answer {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"))
        .header("X-Apassy-Edge", EDGE_SECRET)
        .header("Authorization", format!("Bearer {token}"));
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let mut response = agent.run(builder.body(body).unwrap()).unwrap();
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    Answer {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
    }
}

/// The pushes of one store: the chain of relay-sync-v1 sections 8 and 24.
struct Pusher {
    team: TeamId,
    version: u64,
    previous: String,
}

impl Pusher {
    fn new(team: &TeamId) -> Self {
        Self {
            team: team.clone(),
            version: 0,
            previous: ZEROS.to_string(),
        }
    }

    fn head(&self, device: u64, body: &[u8]) -> String {
        format!(
            "apassy-relay-sync-head-v1\n{VAULT} {} {} {}\n{} {}/{device} 1790000000",
            self.version + 1,
            hex(&Sha256::digest(body)),
            body.len(),
            self.previous,
            self.team
        )
    }

    fn try_push(
        &self,
        c: &Connect,
        token: &str,
        device: u64,
        key: &DeviceKey,
        body: &[u8],
    ) -> Answer {
        let text = self.head(device, body);
        send(
            &c.relay.url,
            "PUT",
            "/v1/sync/snapshot",
            token,
            &[
                ("If-Match", format!("\"{}\"", self.version)),
                ("Content-Type", "application/octet-stream".to_string()),
                ("X-Apassy-Sync-Head", encode_b64(text.as_bytes())),
                (
                    "X-Apassy-Sync-Signature",
                    encode_b64(&key.sign(text.as_bytes()).unwrap()),
                ),
            ],
            body.to_vec(),
        )
    }

    fn push(&mut self, c: &Connect, token: &str, device: u64, key: &DeviceKey, body: &[u8]) {
        let text = self.head(device, body);
        let answer = self.try_push(c, token, device, key, body);
        assert_eq!(answer.status, 200, "{}", answer.body);
        self.version += 1;
        self.previous = hex(&head_hash(text.as_bytes()));
    }
}

/// The store of `a`'s account for `VAULT`: its id and `a`'s store device id.
fn make_store(c: &Connect, token: &str) -> (TeamId, u64) {
    let store = c.ok(
        "POST",
        "/v1/account/vaults",
        Some(token),
        Some(&json!({"vault_id": VAULT, "name": "Personal"})),
    );
    let team = TeamId::parse(store["team_id"].as_str().unwrap()).unwrap();
    let device = store["devices"][0]["store_device_id"].as_u64().unwrap();
    (team, device)
}

// ---- Acceptance (plan s7 unit C1). ----

/// An account is made only with a valid signature over this Connect's account message; one
/// key makes at most one account (a retry of the same body answers the same result); a
/// strict body refuses unknown fields; an edge route refuses a bearer.
#[test]
fn an_account_needs_a_valid_signature_and_one_key_makes_one_account() {
    let c = start();
    let key = DeviceKey::generate().unwrap();
    let body = account_body(&c, &key, &[1u8; 16]);
    let recovery = body["recovery_key"].as_str().unwrap().to_string();
    // Another origin, another key, another domain, another recovery key: 400, nothing made.
    let mut other_origin = body.clone();
    other_origin["signature"] = json!(encode_b64(
        &key.sign(&device::account_message(
            "https://connect.example.test",
            &key.public_key_b64(),
            &recovery
        ))
        .unwrap()
    ));
    let mut other_domain = body.clone();
    other_domain["signature"] = json!(encode_b64(
        &key.sign(&device::connect_message(c.origin(), &key.public_key_b64()))
            .unwrap()
    ));
    let stranger = DeviceKey::generate().unwrap();
    let mut other_key = body.clone();
    other_key["signature"] = json!(encode_b64(
        &stranger
            .sign(&device::account_message(
                c.origin(),
                &key.public_key_b64(),
                &recovery
            ))
            .unwrap()
    ));
    // The signature binds the recovery key: another one in the body is refused.
    let mut other_recovery = body.clone();
    other_recovery["recovery_key"] = json!(recovery_key(&[2u8; 16]).public_key_b64());
    let mut short_recovery = body.clone();
    short_recovery["recovery_key"] = json!(encode_b64(&[1u8; 31]));
    // The root statement: the key's signature over the root entry of this account id and
    // this device name. Another name, another id, another key, or none is 400.
    let account_id = body["account_id"].as_str().unwrap().to_string();
    let mut root_other_name = body.clone();
    root_other_name["statement"] = json!(root_statement(&c, &account_id, &key, "MacBook Air"));
    let mut root_other_account = body.clone();
    root_other_account["statement"] =
        json!(root_statement(&c, &new_account_id(), &key, "MacBook Pro"));
    let mut root_other_key = body.clone();
    root_other_key["statement"] = json!(root_statement(
        &c,
        &account_id,
        &DeviceKey::generate().unwrap(),
        "MacBook Pro"
    ));
    let mut root_missing = body.clone();
    root_missing.as_object_mut().unwrap().remove("statement");
    let mut bad_account_id = body.clone();
    bad_account_id["account_id"] = json!("acc_ABCDEFGHIJ");
    for bad in [
        &other_origin,
        &other_domain,
        &other_key,
        &other_recovery,
        &short_recovery,
        &root_other_name,
        &root_other_account,
        &root_other_key,
        &root_missing,
        &bad_account_id,
    ] {
        c.fails(
            "POST",
            "/v1/account",
            None,
            Some(bad),
            400,
            "invalid_request",
        );
    }
    let mut extra = body.clone();
    extra["email"] = json!("person@example.test");
    c.fails(
        "POST",
        "/v1/account",
        None,
        Some(&extra),
        400,
        "invalid_request",
    );
    c.fails(
        "POST",
        "/v1/account",
        Some("apassy_act_acc_aaaaaaaaaa_00"),
        Some(&body),
        400,
        "invalid_request",
    );
    assert!(c.directory_rows("SELECT id FROM account").is_empty());

    let made = c.ok("POST", "/v1/account", None, Some(&body));
    let account = made["account_id"].as_str().unwrap();
    // The account has the id that the device made.
    assert_eq!(account, account_id);
    // A retry of the same body (a lost answer) answers the same result.
    assert_eq!(c.ok("POST", "/v1/account", None, Some(&body)), made);
    // The same key with another body is a conflict, and makes nothing.
    let other = account_body(&c, &key, &[2u8; 16]);
    c.fails("POST", "/v1/account", None, Some(&other), 409, "conflict");
    // Another key with an id that exists: 409, nothing made (the device makes a new id).
    let taken_key = DeviceKey::generate().unwrap();
    let mut taken = account_body(&c, &taken_key, &[2u8; 16]);
    taken["account_id"] = json!(account);
    taken["statement"] = json!(root_statement(&c, account, &taken_key, "MacBook Pro"));
    c.fails("POST", "/v1/account", None, Some(&taken), 409, "conflict");
    assert_eq!(
        c.directory_rows("SELECT id FROM account"),
        [account.to_string()]
    );
    // A key of a device that joined another account cannot make one either.
    let a = Dev {
        key,
        account: account.to_string(),
        id: made["device_id"].as_str().unwrap().to_string(),
    };
    let token = sign_in(&c, &a);
    // The root entry is signed by the root key over its device name, and stays so.
    let view = c.ok("GET", "/v1/account", Some(&token), None);
    let root = &view["device_list"][0];
    assert_eq!(root["name"], "MacBook Pro");
    assert_eq!(root["signature"], body["statement"]);
    assert_eq!(head_of(&c, account, &view["device_list"]).0, 1);
    let b = add_device(&c, &a, &token);
    c.fails(
        "POST",
        "/v1/account",
        None,
        Some(&account_body(&c, &b.key, &[3u8; 16])),
        409,
        "conflict",
    );
    // The audit names ids, never a key, a hash, or a token.
    for (_, action, detail) in c.relay.relay_audit() {
        if action.starts_with("account_") {
            assert!(!detail.contains(&a.key.public_key_b64()), "{detail}");
            assert!(!detail.contains("apassy_act_"), "{detail}");
        }
    }
}

/// Sign-in: a signature for another origin, of another domain (the relay team sign-in,
/// the bouncer brain), over a used or an unknown nonce, is the same 401, and a refused call
/// uses nothing. A key that is not a device gets no nonce. An account token is no team
/// token and the reverse.
#[test]
fn sign_in_refuses_another_origin_another_domain_and_a_used_nonce() {
    let c = start();
    let a = create(&c);
    let public_key = a.key.public_key_b64();
    let nonce = || {
        let (status, answer) = challenge(&c, &a.account, &a.key);
        assert_eq!(status, 200);
        answer["result"]["nonce"].as_str().unwrap().to_string()
    };
    let refused = |message: &[u8], nonce: &str| {
        c.fails(
            "POST",
            "/v1/account/token",
            None,
            Some(&token_body(&a.account, &a.key, nonce, message)),
            401,
            "unauthenticated",
        );
    };
    // Another origin.
    let n = nonce();
    refused(
        &device::account_sign_in_message(
            "https://connect.example.test",
            &a.account,
            &public_key,
            &n,
        ),
        &n,
    );
    // The relay team sign-in domain, with the account id in the place of the team id.
    let n = nonce();
    let team_form = [
        "apassy-relay sign-in v1",
        c.origin(),
        &a.account,
        &public_key,
        &n,
    ]
    .join("\0");
    refused(team_form.as_bytes(), &n);
    // The bouncer brain's domain.
    let n = nonce();
    let brain = [
        device::BRAIN_SIGN_IN_DOMAIN,
        c.origin(),
        &a.account,
        &public_key,
        &n,
    ]
    .join("\0");
    refused(brain.as_bytes(), &n);
    // A refused attempt uses nothing: the right signature over the same nonce works, once.
    let message = device::account_sign_in_message(c.origin(), &a.account, &public_key, &n);
    c.ok(
        "POST",
        "/v1/account/token",
        None,
        Some(&token_body(&a.account, &a.key, &n, &message)),
    );
    refused(&message, &n);
    // A nonce made up, or one of another account, is refused.
    refused(
        &device::account_sign_in_message(c.origin(), &a.account, &public_key, "bm9uY2U"),
        "bm9uY2U",
    );
    // Later challenges of the same key never end an earlier one.
    let first = nonce();
    for _ in 0..8 {
        nonce();
    }
    let message = device::account_sign_in_message(c.origin(), &a.account, &public_key, &first);
    c.ok(
        "POST",
        "/v1/account/token",
        None,
        Some(&token_body(&a.account, &a.key, &first, &message)),
    );
    // A key that is no device of the account gets no nonce, also with the account id.
    let stranger = DeviceKey::generate().unwrap();
    let (status, answer) = challenge(&c, &a.account, &stranger);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (401, Some("unauthenticated"))
    );
    // An account token is not a team token, and a team token is 403 account_required.
    let token = sign_in(&c, &a);
    c.fails("GET", "/v1/me", Some(&token), None, 401, "unauthenticated");
    c.fails(
        "GET",
        "/v1/account",
        Some(&c.relay.owner_token),
        None,
        403,
        "account_required",
    );
    c.fails(
        "GET",
        "/v1/account",
        Some("apassy_act_acc_aaaaaaaaaa_0000"),
        None,
        401,
        "unauthenticated",
    );
    assert_eq!(
        c.ok("GET", "/v1/account", Some(&token), None)["devices"][0]["device_id"],
        a.id.as_str()
    );
}

/// A link works once and for ten minutes; nothing joins without the confirmation of the
/// device that made it.
#[test]
fn a_link_code_is_one_use_and_expires_at_ten_minutes() {
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    let code = link_code(&a.account);
    let hash = device::account_link_hash(&code);
    let link = c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(&token),
        Some(&json!({"link_hash": hash})),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = link["expires_at"].as_u64().unwrap();
    assert!((now + 595..=now + 605).contains(&expires_at), "{link}");
    // The code never reaches Connect: only its hash is in the directory.
    assert!(
        c.directory_rows("SELECT link_hash FROM account_link")
            .contains(&hash)
    );
    let b = DeviceKey::generate().unwrap();
    let body = join_body(&c, &a.account, &hash, &b, "iPhone");
    let joined = c.ok("POST", "/v1/account/devices/join", None, Some(&body));
    // The same body again: the same answer.
    assert_eq!(
        c.ok("POST", "/v1/account/devices/join", None, Some(&body)),
        joined
    );
    // A second device with the same link: 403.
    let other = DeviceKey::generate().unwrap();
    c.fails(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(&c, &a.account, &hash, &other, "Mac mini")),
        403,
        "forbidden",
    );
    // An expired link: 403.
    let late = device::account_link_hash(&link_code(&a.account));
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(&token),
        Some(&json!({"link_hash": late})),
    );
    c.edit_directory(&format!(
        "UPDATE account_link SET expires_at = {} WHERE link_hash = '{late}';",
        now - 1
    ));
    c.fails(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(&c, &a.account, &late, &other, "Mac mini")),
        403,
        "forbidden",
    );
    // A join of a link whose time ran out cannot be confirmed.
    let join_id = joined["join_id"].as_u64().unwrap();
    c.edit_directory(&format!(
        "UPDATE account_join SET expires_at = {} WHERE id = {join_id};",
        now - 1
    ));
    c.fails(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&token),
        Some(&confirm_body(&c, &a, &token, &hash, (&b, "iPhone"))),
        409,
        "conflict",
    );
    let (status, answer) = challenge(&c, &a.account, &b);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("join_refused"))
    );
}

/// The device list of the vectors is this relay's: each entry's message (with the device
/// name of a `root` or an `add`, `-` for a `remove`) has the hash of the vectors and
/// verifies with its `by` key, the root with its own key; each entry is an `api::ListEntry`
/// as this relay answers it.
#[test]
fn the_device_list_vectors_are_the_messages_of_this_relay() {
    let v = vectors();
    let origin = v["origin"].as_str().unwrap();
    let account = v["account_id"].as_str().unwrap();
    let list = &v["device_list"];
    let mut previous = device::LIST_NONE.to_string();
    for (index, entry) in list["entries"].as_array().unwrap().iter().enumerate() {
        let message = device::account_list_message(
            origin,
            account,
            entry["version"].as_u64().unwrap(),
            &previous,
            entry["op"].as_str().unwrap(),
            entry["key"].as_str().unwrap(),
            entry["link_hash"].as_str().unwrap_or(device::LIST_NONE),
            entry["name"].as_str().unwrap_or(device::LIST_NONE),
            entry["by"].as_str().unwrap(),
        );
        if index == 0 {
            assert_eq!(
                encode_b64(&message),
                list["root_message_b64u"].as_str().unwrap()
            );
        }
        previous = device::account_list_hash(&message);
        assert_eq!(previous, list["hashes"][index].as_str().unwrap(), "{entry}");
        let by = decode_b64(entry["by"].as_str().unwrap(), 65).unwrap();
        let signature = decode_b64(entry["signature"].as_str().unwrap(), 72).unwrap();
        assert!(device::verify(&by, &message, &signature), "{entry}");
        let mut changed = message.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(!device::verify(&by, &changed, &signature), "{entry}");
        let typed: apassy_relay::api::ListEntry = serde_json::from_value(entry.clone()).unwrap();
        assert_eq!(serde_json::to_value(&typed).unwrap(), *entry);
    }
    // The messages of the roots of a recovery and of a member's own account too.
    for (name, signer) in [
        ("device_list_root", "device_a"),
        ("device_list_recovery_root", "device_b"),
        ("device_list_member_root", "device_b"),
    ] {
        let vector = v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["name"] == name)
            .unwrap();
        let message = decode_b64(vector["message_b64u"].as_str().unwrap(), 4096).unwrap();
        let key = unhex(v[signer]["public_hex"].as_str().unwrap());
        let signature = decode_b64(vector["signature_b64u"].as_str().unwrap(), 72).unwrap();
        assert!(device::verify(&key, &message, &signature), "{name}");
        let parts: Vec<&[u8]> = message.split(|byte| *byte == 0).collect();
        assert_eq!(parts.len(), 10, "{name}");
        assert_eq!(parts[5], b"root");
        assert_eq!(parts[6], parts[9], "{name}: the root signs itself");
        let rebuilt = device::account_list_message(
            origin,
            std::str::from_utf8(parts[2]).unwrap(),
            1,
            device::LIST_NONE,
            "root",
            std::str::from_utf8(parts[6]).unwrap(),
            device::LIST_NONE,
            std::str::from_utf8(parts[8]).unwrap(),
            std::str::from_utf8(parts[9]).unwrap(),
        );
        assert_eq!(rebuilt, message, "{name}");
    }
}

/// A join waits for the confirmation of the device that made the link, for exactly the key
/// of the words; the words of the vectors are those of this relay and of the app; another
/// device of the account cannot confirm; a refused join ends.
#[test]
fn a_join_needs_the_confirmation_of_a_live_device_and_both_sides_show_the_same_words() {
    // The words of the vectors: this relay's function and the app's.
    let v = vectors();
    let a_key = unhex(v["device_a"]["public_hex"].as_str().unwrap());
    let b_key = unhex(v["device_b"]["public_hex"].as_str().unwrap());
    let account = v["account_id"].as_str().unwrap();
    let code = v["link"]["code"].as_str().unwrap();
    let words = device::account_safety_words(account, code, &a_key, &b_key);
    assert_eq!(words, v["safety"]["words"].as_str().unwrap());
    assert_eq!(
        words,
        apassy::connect::safety_words(account, code, &a_key, &b_key)
    );
    assert_eq!(
        device::account_link_hash(code),
        v["link"]["link_hash"].as_str().unwrap()
    );
    assert_eq!(
        device::account_link_hash(code),
        apassy::connect::link_hash(code)
    );

    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    let second = add_device(&c, &a, &token);
    let second_token = sign_in(&c, &second);
    let code = link_code(&a.account);
    let hash = device::account_link_hash(&code);
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(&token),
        Some(&json!({"link_hash": hash})),
    );
    let b = DeviceKey::generate().unwrap();
    let joined = c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(&c, &a.account, &hash, &b, "iPad")),
    );
    assert_eq!(joined["confirmer"]["device_id"], a.id.as_str());
    let join_id = joined["join_id"].as_u64().unwrap();
    // The new device waits.
    let (status, answer) = challenge(&c, &a.account, &b);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("join_pending"))
    );
    // Both sides compute the same words from what each has.
    let confirmer_key =
        decode_b64(joined["confirmer"]["public_key"].as_str().unwrap(), 65).unwrap();
    let pending = c.ok("GET", "/v1/account/devices/pending", Some(&token), None);
    assert_eq!(pending.as_array().unwrap().len(), 1);
    let joiner_key = decode_b64(pending[0]["public_key"].as_str().unwrap(), 65).unwrap();
    assert_eq!(
        device::account_safety_words(&a.account, &code, &confirmer_key, &b.public_key()),
        device::account_safety_words(&a.account, &code, &a.key.public_key(), &joiner_key)
    );
    // Only the device that made the link sees it and confirms it.
    assert_eq!(
        c.ok(
            "GET",
            "/v1/account/devices/pending",
            Some(&second_token),
            None
        ),
        json!([])
    );
    c.fails(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&second_token),
        Some(&confirm_body(
            &c,
            &second,
            &second_token,
            &hash,
            (&b, "iPad"),
        )),
        403,
        "forbidden",
    );
    // Another key than the one of the words: 409, nothing added.
    let other = DeviceKey::generate().unwrap();
    c.fails(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&token),
        Some(&confirm_body(&c, &a, &token, &hash, (&other, "iPad"))),
        409,
        "conflict",
    );
    // A statement that is not the confirming device's over this link and key: 400,
    // nothing added. So is a confirmation without one.
    let mut by_other_device = confirm_body(&c, &second, &second_token, &hash, (&b, "iPad"));
    by_other_device["public_key"] = json!(b.public_key_b64());
    let other_link = confirm_body(
        &c,
        &a,
        &token,
        &device::account_link_hash(&link_code(&a.account)),
        (&b, "iPad"),
    );
    // The entry signs the name of the join as Connect keeps it: another name is 400.
    let other_name = confirm_body(&c, &a, &token, &hash, (&b, "iPad Pro"));
    let mut other_domain = confirm_body(&c, &a, &token, &hash, (&b, "iPad"));
    other_domain["statement"] = json!(encode_b64(
        &a.key
            .sign(&device::account_join_message(
                c.origin(),
                &a.account,
                &hash,
                &b.public_key_b64()
            ))
            .unwrap()
    ));
    // A statement over another previous head (a fork of the list): 400 as well.
    let (version, _) = list_head(&c, &a.account, &token);
    let forked = json!({"public_key": b.public_key_b64(), "version": version + 1,
        "statement": list_statement(&c, &a, (version + 1, ZEROS_B64), "add",
            &b.public_key_b64(), (Some(&hash), Some("iPad")))});
    for bad in [
        by_other_device,
        other_link,
        other_name,
        other_domain,
        forked,
        json!({"public_key": b.public_key_b64(), "version": version + 1}),
        json!({"public_key": b.public_key_b64(), "version": version + 1, "statement": "not-a-signature"}),
    ] {
        c.fails(
            "POST",
            &format!("/v1/account/devices/pending/{join_id}/confirm"),
            Some(&token),
            Some(&bad),
            400,
            "invalid_request",
        );
    }
    assert_eq!(
        c.ok("GET", "/v1/account", Some(&token), None)["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let (status, answer) = challenge(&c, &a.account, &b);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("join_pending"))
    );
    // A version that is not the next one: 409 (the device reads the list again), nothing
    // added.
    let mut stale = confirm_body(&c, &a, &token, &hash, (&b, "iPad"));
    stale["version"] = json!(version);
    c.fails(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&token),
        Some(&stale),
        409,
        "conflict",
    );
    assert_eq!(list_head(&c, &a.account, &token).0, version);
    let added = c.ok(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&token),
        Some(&confirm_body(&c, &a, &token, &hash, (&b, "iPad"))),
    );
    assert_eq!(added["public_key"], b.public_key_b64());
    // The list has the `add` entry of the confirming device for this key and link.
    let view = c.ok("GET", "/v1/account", Some(&token), None);
    let entry = view["device_list"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(entry["version"], json!(version + 1));
    assert_eq!(entry["op"], "add");
    assert_eq!(entry["key"], b.public_key_b64());
    assert_eq!(entry["by"], a.key.public_key_b64());
    assert_eq!(entry["link_hash"], hash.as_str());
    assert_eq!(entry["name"], "iPad");
    assert_eq!(head_of(&c, &a.account, &view["device_list"]).0, version + 1);
    let b = Dev {
        id: String::new(),
        key: b,
        account: a.account.clone(),
    };
    let (status, _) = challenge(&c, &a.account, &b.key);
    assert_eq!(status, 200);
    // A refused join ends on the new device.
    let hash = device::account_link_hash(&link_code(&a.account));
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(&token),
        Some(&json!({"link_hash": hash})),
    );
    let refused = DeviceKey::generate().unwrap();
    let joined = c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(&c, &a.account, &hash, &refused, "Laptop")),
    );
    let join_id = joined["join_id"].as_u64().unwrap();
    c.ok(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/refuse"),
        Some(&token),
        Some(&json!({})),
    );
    let (status, answer) = challenge(&c, &a.account, &refused);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("join_refused"))
    );
    // A cancel by the new device ends it too.
    let hash = device::account_link_hash(&link_code(&a.account));
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(&token),
        Some(&json!({"link_hash": hash})),
    );
    let cancelled = DeviceKey::generate().unwrap();
    c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(&c, &a.account, &hash, &cancelled, "Tablet")),
    );
    // Only the joining key ends its join: another key's signature, the join message, or
    // none is 400, and the join still waits.
    let stranger = DeviceKey::generate().unwrap();
    let mut by_stranger = cancel_body(&c, &a.account, &hash, &stranger);
    by_stranger["public_key"] = json!(cancelled.public_key_b64());
    let mut join_signature = cancel_body(&c, &a.account, &hash, &cancelled);
    join_signature["signature"] =
        join_body(&c, &a.account, &hash, &cancelled, "Tablet")["signature"].clone();
    for bad in [
        by_stranger,
        join_signature,
        json!({"account_id": a.account, "link_hash": hash, "public_key": cancelled.public_key_b64()}),
    ] {
        c.fails(
            "POST",
            "/v1/account/devices/join/cancel",
            None,
            Some(&bad),
            400,
            "invalid_request",
        );
    }
    let (status, answer) = challenge(&c, &a.account, &cancelled);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("join_pending"))
    );
    c.ok(
        "POST",
        "/v1/account/devices/join/cancel",
        None,
        Some(&cancel_body(&c, &a.account, &hash, &cancelled)),
    );
    let (status, answer) = challenge(&c, &a.account, &cancelled);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("join_refused"))
    );
}

/// A revoked device loses its account token at once, and leaves every vault store: its
/// relay-sync token of the store ends at once, it cannot sign in to the store again, and
/// the store lists it no more.
#[test]
fn a_revoked_device_loses_its_token_at_once_and_vanishes_from_every_store() {
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let b_token = sign_in(&c, &b);
    let (team, _) = make_store(&c, &token);
    let added = c.ok(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&token),
        Some(&store_add_body(&b)),
    );
    assert_eq!(added["store_device_id"], 2);
    let b_store_token = c.relay.sign_in(&team, &b.key);
    assert_eq!(
        send(
            &c.relay.url,
            "GET",
            "/v1/sync/head",
            &b_store_token,
            &[],
            Vec::new()
        )
        .status,
        200
    );

    let revoked = revoke(&c, &a, &token, &b);
    assert_eq!(
        revoked,
        json!({"device_id": b.id, "removed_from_stores": 1})
    );
    // At once, without a new sign-in: the account token and the store token end.
    c.fails(
        "GET",
        "/v1/account",
        Some(&b_token),
        None,
        401,
        "unauthenticated",
    );
    assert_eq!(
        send(
            &c.relay.url,
            "GET",
            "/v1/sync/head",
            &b_store_token,
            &[],
            Vec::new()
        )
        .status,
        401
    );
    // Its own signed sign-in learns that it was removed; nothing else does.
    assert_eq!(
        token_call(&c, &b.account, &b.key),
        (403, Some("device_removed".to_string()))
    );
    let (status, _) = c.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": b.key.public_key_b64()})),
    );
    assert_eq!(status, 401);
    let stores = c.ok("GET", "/v1/account/vaults", Some(&token), None);
    assert_eq!(stores[0]["devices"].as_array().unwrap().len(), 1);
    assert_eq!(
        c.ok("GET", "/v1/account", Some(&token), None)["devices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // The revoked key never comes back as a device.
    c.fails(
        "POST",
        "/v1/account",
        None,
        Some(&account_body(&c, &b.key, &[5u8; 16])),
        409,
        "conflict",
    );
    // A device may revoke itself; its token ends with it.
    revoke(&c, &a, &token, &a);
    c.fails(
        "GET",
        "/v1/account",
        Some(&token),
        None,
        401,
        "unauthenticated",
    );
}

/// A vault store is a relay-sync-v1 team: the account device key signs in to it, pushes a
/// chain of signed heads, and posts a receipt. It needs an entitled plan to be made and to
/// take a push; a read-only plan still pulls; the same vault answers the same store; a
/// store serves no invites, items, or questions.
#[test]
fn a_vault_store_is_a_relay_sync_team_for_the_account_device_key() {
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    c.fails(
        "POST",
        "/v1/account/vaults",
        Some(&token),
        Some(&json!({"vault_id": VAULT, "name": "Personal"})),
        403,
        "plan_required",
    );
    c.fails(
        "GET",
        "/v1/account/entitlement",
        Some(&token),
        None,
        403,
        "plan_required",
    );
    c.plans.set(&a.account, entitled());
    let (team, a_store) = make_store(&c, &token);
    assert_eq!(a_store, 1);
    let again = c.ok(
        "POST",
        "/v1/account/vaults",
        Some(&token),
        Some(&json!({"vault_id": VAULT, "name": "Personal"})),
    );
    assert_eq!(again["team_id"], team.as_str());
    let b = add_device(&c, &a, &token);
    c.ok(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&token),
        Some(&store_add_body(&b)),
    );

    let a_sync = c.relay.sign_in(&team, &a.key);
    let b_sync = c.relay.sign_in(&team, &b.key);
    let mut pusher = Pusher::new(&team);
    pusher.push(&c, &a_sync, 1, &a.key, b"ciphertext one");
    pusher.push(&c, &b_sync, 2, &b.key, b"ciphertext two");
    let receipt = send(
        &c.relay.url,
        "POST",
        "/v1/sync/receipt",
        &a_sync,
        &[("Content-Type", "application/json".into())],
        br#"{"version":2}"#.to_vec(),
    );
    assert_eq!(receipt.status, 200, "{}", receipt.body);
    let head = send(
        &c.relay.url,
        "GET",
        "/v1/sync/head",
        &a_sync,
        &[],
        Vec::new(),
    );
    assert_eq!(head.status, 200);
    assert_eq!(head.body["result"]["version"], 2);
    // A head signed by another key than the device's is refused.
    let wrong = pusher.try_push(&c, &a_sync, 1, &b.key, b"three");
    assert_eq!(wrong.status, 403, "{}", wrong.body);

    // A store is relay sync only: no invites, items, or questions.
    for (method, path) in [
        ("POST", "/v1/invites"),
        ("GET", "/v1/items"),
        ("GET", "/v1/questions"),
        ("POST", "/v1/devices/links"),
    ] {
        let answer = send(
            &c.relay.url,
            method,
            path,
            &a_sync,
            &[("Content-Type", "application/json".into())],
            b"{}".to_vec(),
        );
        assert_eq!(answer.status, 403, "{method} {path}: {}", answer.body);
    }
    // A plan that ended: no push, pulls still work while read-only, then nothing.
    c.plans.set(&a.account, read_only());
    let refused = pusher.try_push(&c, &a_sync, 1, &a.key, b"three");
    assert_eq!(
        (refused.status, refused.body["error"]["code"].as_str()),
        (403, Some("plan_required"))
    );
    assert_eq!(
        send(
            &c.relay.url,
            "GET",
            "/v1/sync/head",
            &a_sync,
            &[],
            Vec::new()
        )
        .status,
        200
    );
    assert_eq!(
        send(
            &c.relay.url,
            "GET",
            "/v1/sync/snapshot?version=2",
            &a_sync,
            &[],
            Vec::new()
        )
        .status,
        200
    );
    c.plans.set(&a.account, suspended());
    assert_eq!(
        send(
            &c.relay.url,
            "GET",
            "/v1/sync/head",
            &a_sync,
            &[],
            Vec::new()
        )
        .status,
        403
    );
    // Deleting the store removes it and its snapshots.
    let sync_dir = c.relay.config.sync_dir(&team);
    assert!(sync_dir.exists());
    c.ok(
        "DELETE",
        &format!("/v1/account/vaults/{team}"),
        Some(&token),
        None,
    );
    assert!(!sync_dir.exists());
    assert!(!c.relay.config.team_path(&team).exists());
    assert_eq!(
        c.ok("GET", "/v1/account/vaults", Some(&token), None),
        json!([])
    );
}

/// A device of another account cannot be added to a store, cannot sign in to it, and
/// cannot read or delete it, without a group (403 `not_in_group` until groups, C3).
#[test]
fn a_device_of_another_account_cannot_read_or_join_a_store_without_a_group() {
    let c = start();
    let a = create(&c);
    let other = create(&c);
    c.plans.set(&a.account, entitled());
    c.plans.set(&other.account, entitled());
    let token = sign_in(&c, &a);
    let other_token = sign_in(&c, &other);
    let (team, _) = make_store(&c, &token);
    c.fails(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&token),
        Some(&store_add_body(&other)),
        403,
        "not_in_group",
    );
    // The other account's own device is not in the store: it adds nothing and deletes nothing.
    c.fails(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&other_token),
        Some(&store_add_body(&other)),
        403,
        "forbidden",
    );
    c.fails(
        "DELETE",
        &format!("/v1/account/vaults/{team}"),
        Some(&other_token),
        None,
        403,
        "forbidden",
    );
    assert_eq!(
        c.ok("GET", "/v1/account/vaults", Some(&other_token), None),
        json!([])
    );
    // Its key is no device of the store: no relay-sync sign-in.
    let (status, _) = c.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": other.key.public_key_b64()})),
    );
    assert_eq!(status, 401);
    // A team that is not a vault store: 404 not_found, as no team (connect-account-v1
    // section 8; `account_required` is only for a team token on an account route).
    let operator_team = c.relay.team_id.clone();
    for (method, path, body) in [
        (
            "POST",
            format!("/v1/account/vaults/{operator_team}/devices"),
            Some(store_add_body(&a)),
        ),
        (
            "DELETE",
            format!("/v1/account/vaults/{operator_team}"),
            None,
        ),
    ] {
        c.fails(method, &path, Some(&token), body.as_ref(), 404, "not_found");
    }
    assert!(c.relay.hub().team(&operator_team).is_some());
}

/// The body of a recovery of `account` by `new_key`, signed by the recovery key of `code`,
/// naming the recovery key of `next` as the next one.
fn recover_body(
    c: &Connect,
    account: &str,
    code: &[u8; 16],
    new_key: &DeviceKey,
    next: &[u8; 16],
) -> Value {
    let public_key = new_key.public_key_b64();
    let next_key = recovery_key(next).public_key_b64();
    let message = device::account_recover_message(c.origin(), account, &public_key, &next_key);
    json!({"account_id": account, "device_name": "MacBook Air", "platform": "mac",
           "public_key": public_key, "recovery_key": next_key,
           "signature": encode_b64(&new_key.sign(&message).unwrap()),
           "recovery_signature": encode_b64(&recovery_key(code).sign(&message)),
           "statement": root_statement(c, account, new_key, "MacBook Air")})
}

/// Recovery works only with zero live devices and a signature of the account's recovery
/// key, makes the new device the account's new root, replaces the recovery key, deletes
/// every vault store, keeps the account, answers a repeat of the same body the same, and
/// counts only failed recovery signatures of existing accounts: five an hour.
#[test]
fn recover_works_only_with_zero_live_devices_and_deletes_the_stores() {
    let c = start();
    let key = DeviceKey::generate().unwrap();
    let code: [u8; 16] = std::array::from_fn(|index| 16 + index as u8);
    let made = c.ok(
        "POST",
        "/v1/account",
        None,
        Some(&account_body(&c, &key, &code)),
    );
    let a = Dev {
        key,
        account: made["account_id"].as_str().unwrap().into(),
        id: made["device_id"].as_str().unwrap().into(),
    };
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let (team, _) = make_store(&c, &token);
    let recover = |body: &Value| c.call("POST", "/v1/account/recover", None, Some(body));
    let new_key = DeviceKey::generate().unwrap();
    // With a live device: 403, the same as a wrong recovery key, and not counted.
    let (status, answer) = recover(&recover_body(&c, &a.account, &code, &new_key, &[9u8; 16]));
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("forbidden"))
    );
    for _ in 0..10 {
        let (status, _) = recover(&recover_body(&c, &a.account, &code, &new_key, &[9u8; 16]));
        assert_eq!(status, 403);
    }
    let (_, wrong) = recover(&recover_body(
        &c, &a.account, &[0u8; 16], &new_key, &[9u8; 16],
    ));
    assert_eq!(wrong["error"], answer["error"]);
    // An unknown account is the same 403, and is not counted.
    let (_, unknown) = recover(&recover_body(
        &c,
        "acc_aaaaaaaaaa",
        &code,
        &new_key,
        &[9u8; 16],
    ));
    assert_eq!(unknown["error"], answer["error"]);
    // The new device key signs the request too: another signature is 400, not counted.
    let mut unsigned = recover_body(&c, &a.account, &code, &new_key, &[9u8; 16]);
    unsigned["signature"] = json!(encode_b64(
        &DeviceKey::generate().unwrap().sign(b"other").unwrap()
    ));
    let (status, _) = recover(&unsigned);
    assert_eq!(status, 400);
    // The root statement of the new list is checked with it: over another name, or by
    // another key, is 400 and is not counted.
    let mut other_root = recover_body(&c, &a.account, &code, &new_key, &[9u8; 16]);
    other_root["statement"] = json!(root_statement(&c, &a.account, &new_key, "MacBook Pro"));
    let mut stranger_root = recover_body(&c, &a.account, &code, &new_key, &[9u8; 16]);
    stranger_root["statement"] = json!(root_statement(
        &c,
        &a.account,
        &DeviceKey::generate().unwrap(),
        "MacBook Air"
    ));
    for bad in [&other_root, &stranger_root] {
        let (status, answer) = recover(bad);
        assert_eq!(
            (status, answer["error"]["code"].as_str()),
            (400, Some("invalid_request"))
        );
    }
    // The recovery signature covers the next recovery key: another one is 403.
    let mut swapped = recover_body(&c, &a.account, &code, &new_key, &[9u8; 16]);
    swapped["recovery_key"] = json!(recovery_key(&[6u8; 16]).public_key_b64());
    swapped["signature"] = json!(encode_b64(
        &new_key
            .sign(&device::account_recover_message(
                c.origin(),
                &a.account,
                &new_key.public_key_b64(),
                &recovery_key(&[6u8; 16]).public_key_b64()
            ))
            .unwrap()
    ));
    let (status, _) = recover(&swapped);
    assert_eq!(status, 403);
    // No live device: the right recovery key recovers.
    revoke(&c, &a, &token, &a);
    let body = recover_body(&c, &a.account, &code, &new_key, &[9u8; 16]);
    let (status, recovered) = recover(&body);
    assert_eq!(status, 200, "{recovered}");
    assert_eq!(recovered["result"]["account_id"], a.account.as_str());
    assert_eq!(recovered["result"]["deleted_stores"], 1);
    assert!(!c.relay.config.team_path(&team).exists());
    // A repeat of the same body (a lost answer): the same answer, nothing new.
    let (status, again) = recover(&body);
    assert_eq!((status, &again), (200, &recovered));
    let b = Dev {
        key: new_key,
        account: a.account.clone(),
        id: recovered["result"]["device_id"].as_str().unwrap().into(),
    };
    let b_token = sign_in(&c, &b);
    assert_eq!(
        c.ok("GET", "/v1/account/vaults", Some(&b_token), None),
        json!([])
    );
    // The recovered device is the account's new root: a new device list starts at it,
    // and no entry leads to the old one.
    let view = c.ok("GET", "/v1/account", Some(&b_token), None);
    assert_eq!(view["devices"].as_array().unwrap().len(), 1);
    let list = view["device_list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{view}");
    assert_eq!(list[0]["op"], "root");
    assert_eq!(list[0]["key"], b.key.public_key_b64());
    assert_eq!(list[0]["name"], "MacBook Air");
    assert_eq!(list[0]["signature"], body["statement"]);
    assert_eq!(head_of(&c, &a.account, &view["device_list"]).0, 1);
    // The old recovery key is gone: with no live device again, it does not work. Only
    // failed recovery signatures count and are limited, five an hour for the account: two
    // failed above, three more make five, and the next failure is 429. The right key is
    // never limited: it recovers.
    revoke(&c, &b, &b_token, &b);
    let third = DeviceKey::generate().unwrap();
    for _ in 0..3 {
        let (status, _) = recover(&recover_body(&c, &a.account, &code, &third, &[8u8; 16]));
        assert_eq!(status, 403);
    }
    let (status, limited) = recover(&recover_body(&c, &a.account, &code, &third, &[8u8; 16]));
    assert_eq!(
        (status, limited["error"]["code"].as_str()),
        (429, Some("rate_limited"))
    );
    let (status, again) = recover(&recover_body(
        &c, &a.account, &[9u8; 16], &third, &[8u8; 16],
    ));
    assert_eq!(status, 200, "{again}");
}

/// A recovery of one account counts its failures apart from another's, and the prefix
/// that the Worker proved has its own count over all accounts.
#[test]
fn recovery_failures_count_for_each_account_and_each_proven_prefix() {
    let c = start();
    let recover_from = |prefix: &str, body: &Value| {
        let mac = apassy_relay::server::connect::prefix_mac(EDGE_SECRET, prefix);
        let (status, text) = relay::call_raw(
            &c.relay.url,
            Some(EDGE_SECRET),
            "POST",
            "/v1/account/recover",
            None,
            &[
                ("X-Apassy-Client-Prefix", prefix),
                ("X-Apassy-Client-Prefix-Mac", mac.as_str()),
            ],
            Some(body),
        );
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, value["error"]["code"].as_str().map(str::to_string))
    };
    // Five accounts with no live device, each failed four times from one prefix: twenty.
    let mut accounts = Vec::new();
    for _ in 0..6 {
        let a = create(&c);
        let token = sign_in(&c, &a);
        revoke(&c, &a, &token, &a);
        accounts.push(a);
    }
    let key = DeviceKey::generate().unwrap();
    for a in &accounts[..5] {
        for _ in 0..4 {
            let body = recover_body(&c, &a.account, &[0u8; 16], &key, &[1u8; 16]);
            assert_eq!(
                recover_from("198.51.100.0/24", &body),
                (403, Some("forbidden".into()))
            );
        }
    }
    // The prefix made its twenty failures: a further failure from it is 429, also for a
    // sixth account. The right key is never limited: it recovers from that prefix too.
    let sixth = &accounts[5];
    let wrong = recover_body(&c, &sixth.account, &[0u8; 16], &key, &[1u8; 16]);
    assert_eq!(
        recover_from("198.51.100.0/24", &wrong),
        (429, Some("rate_limited".into()))
    );
    let body = recover_body(&c, &sixth.account, &[7u8; 16], &key, &[1u8; 16]);
    let (status, _) = recover_from("198.51.100.0/24", &body);
    assert_eq!(status, 200);
    // A prefix without the Worker's proof counts as `unknown`, not as the prefix it names.
    let (status, text) = relay::call_raw(
        &c.relay.url,
        Some(EDGE_SECRET),
        "POST",
        "/v1/account/recover",
        None,
        &[
            ("X-Apassy-Client-Prefix", "198.51.100.0/24"),
            ("X-Apassy-Client-Prefix-Mac", "00"),
        ],
        Some(&recover_body(
            &c,
            &accounts[0].account,
            &[7u8; 16],
            &DeviceKey::generate().unwrap(),
            &[1u8; 16],
        )),
    );
    assert_eq!(status, 200, "{text}");
    // A stranger without the proof fails until the account and `unknown` are limited:
    // the owner, also without the proof, still recovers.
    let owner = &accounts[1];
    let unproven = |body: &Value| {
        relay::call_raw(
            &c.relay.url,
            Some(EDGE_SECRET),
            "POST",
            "/v1/account/recover",
            None,
            &[],
            Some(body),
        )
        .0
    };
    let stranger = DeviceKey::generate().unwrap();
    let statuses: Vec<u16> = (0..25)
        .map(|_| {
            unproven(&recover_body(
                &c,
                &owner.account,
                &[0u8; 16],
                &stranger,
                &[1u8; 16],
            ))
        })
        .collect();
    assert!(statuses.contains(&429), "{statuses:?}");
    let right = recover_body(
        &c,
        &owner.account,
        &[7u8; 16],
        &DeviceKey::generate().unwrap(),
        &[1u8; 16],
    );
    assert_eq!(unproven(&right), 200);
}

/// The entitlement token verifies with the published key (with this relay's check and the
/// app's), and fails after `exp`, with a changed claim, or with another key.
#[test]
fn the_entitlement_token_verifies_with_the_published_key_and_fails_after_exp_or_a_changed_claim() {
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    c.plans.set(&a.account, entitled());
    let answer = c.ok("GET", "/v1/account/entitlement", Some(&token), None);
    let entitlement = answer["token"].as_str().unwrap();
    let known = c.ok("GET", "/.well-known/apassy-connect.json", None, None);
    assert_eq!(known["v"], 1);
    assert_eq!(known["origin"], c.origin());
    let published = &known["keys"][0];
    assert_eq!(published["alg"], "Ed25519");
    let vector_public = vectors()["entitlement"]["public_b64u"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(published["public_key"], vector_public.as_str());
    let kid = published["kid"].as_str().unwrap();
    assert_eq!(kid, key_id(&decode_b64(&vector_public, 32).unwrap()));
    let keys = [PublishedKey {
        kid: kid.to_string(),
        public_key: decode_b64(&vector_public, 32).unwrap().try_into().unwrap(),
    }];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Entitlement::verify(&keys, entitlement, now).expect("verifies");
    assert_eq!(
        (
            claims.acc.as_str(),
            claims.plan.as_str(),
            claims.exp - claims.iat
        ),
        (a.account.as_str(), "personal", 86_400)
    );
    assert_eq!(answer["expires_at"], claims.exp);
    // The app's check of the same token, with the well-known document's key.
    let app_key =
        apassy::connect::EntitlementKey::from_published(kid, "Ed25519", &vector_public).unwrap();
    apassy::connect::entitlement::verify(
        entitlement,
        std::slice::from_ref(&app_key),
        apassy::connect::Feature::Brain,
        &a.account,
        now,
    )
    .expect("the app verifies it");
    // After `exp`, with a changed claim, with another key: refused.
    assert!(Entitlement::verify(&keys, entitlement, claims.exp).is_err());
    let (payload, signature) = entitlement.split_once('.').unwrap();
    let text = String::from_utf8(decode_b64(payload, 2048).unwrap()).unwrap();
    let changed = encode_b64(text.replace("personal", "team").as_bytes());
    assert!(Entitlement::verify(&keys, &format!("{changed}.{signature}"), now).is_err());
    assert!(
        apassy::connect::entitlement::verify(
            &format!("{changed}.{signature}"),
            &[app_key],
            apassy::connect::Feature::Brain,
            &a.account,
            now
        )
        .is_err()
    );
    let other = [PublishedKey {
        kid: kid.to_string(),
        public_key: [7u8; 32],
    }];
    assert!(Entitlement::verify(&other, entitlement, now).is_err());
    // The token is no credential for Connect.
    c.fails(
        "GET",
        "/v1/account",
        Some(entitlement),
        None,
        401,
        "unauthenticated",
    );
    // An ended plan: no token.
    c.plans.set(&a.account, read_only());
    c.fails(
        "GET",
        "/v1/account/entitlement",
        Some(&token),
        None,
        403,
        "plan_required",
    );
}

/// Plain files only in `connect` mode without a master key: `Store::open_plain` refuses
/// every other relay, the configuration refuses the key in `connect` mode, and a relay in
/// `connect` mode keeps `relay.db` and its vault stores as plain SQLite.
#[test]
fn open_plain_refuses_a_master_key_and_connect_mode_refuses_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let edge = "edge-secret-for-tests-0123456789abcdef0123456789";
    let lookup = |pairs: Vec<(&'static str, String)>| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    };
    let base = vec![
        (
            "APASSY_RELAY_DATA",
            dir.path().join("data").to_string_lossy().into_owned(),
        ),
        (
            "APASSY_RELAY_PUBLIC_URL",
            "https://connect.example.test".to_string(),
        ),
        ("APASSY_RELAY_EDGE_SECRET", edge.to_string()),
    ];
    let with = |extra: &[(&'static str, &str)]| {
        let mut pairs = base.clone();
        pairs.extend(extra.iter().map(|(key, value)| (*key, value.to_string())));
        RelayConfig::from_lookup(lookup(pairs))
    };
    // `connect` mode refuses the master key, as a value or a file.
    for key in ["APASSY_RELAY_KEY", "APASSY_RELAY_KEY_FILE"] {
        let error = with(&[
            ("APASSY_RELAY_MODE", "connect"),
            (key, "a synthetic master key"),
        ])
        .unwrap_err();
        assert!(
            error.message.contains("refuses a master key"),
            "{}",
            error.message
        );
    }
    assert!(
        with(&[
            ("APASSY_RELAY_MODE", "connect"),
            ("APASSY_RELAY_CONNECT_ACCOUNTS", "0")
        ])
        .is_err()
    );
    assert!(with(&[("APASSY_RELAY_MODE", "other")]).is_err());
    let connect = with(&[
        ("APASSY_RELAY_MODE", "connect"),
        ("APASSY_RELAY_TEAM_VAULTS", "1"),
    ])
    .unwrap();
    assert_eq!(connect.connect.mode, RelayMode::Connect);
    assert!(connect.connect.accounts && connect.master_key.is_empty() && !connect.team_vaults);
    // The transition: the account routes beside every other route, with the master key.
    let transition = with(&[
        ("APASSY_RELAY_CONNECT_ACCOUNTS", "1"),
        ("APASSY_RELAY_KEY", "a synthetic master key"),
    ])
    .unwrap();
    assert!(transition.connect.accounts && transition.connect.mode == RelayMode::Relay);
    let plain = with(&[("APASSY_RELAY_KEY", "a synthetic master key")]).unwrap();
    assert!(!plain.connect.accounts);

    // `open_plain` refuses a relay with a key, or a relay that is not in connect mode.
    let file = dir.path().join("plain.db");
    for config in [&transition, &plain] {
        assert!(Store::create_plain(&file, config, "CREATE TABLE t (x);").is_err());
        assert!(Store::open_plain(&file, config).is_err());
    }
    let mut keyed_connect = connect.clone();
    keyed_connect.master_key = SecretString::new("a synthetic master key".into());
    assert!(Store::create_plain(&file, &keyed_connect, "CREATE TABLE t (x);").is_err());
    assert!(!file.exists());

    // A relay in connect mode: plain relay.db and plain vault stores.
    let c = connect_with(|cfg| {
        cfg.connect = ConnectConfig {
            mode: RelayMode::Connect,
            ..ConnectConfig::accounts(Some(signing_key()))
        };
        cfg.master_key = SecretString::new(String::new());
        cfg.team_vaults = false;
        cfg.data_dir = cfg.data_dir.with_file_name("connect-data");
    });
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let (team, _) = make_store(&c, &token);
    let a_sync = c.relay.sign_in(&team, &a.key);
    Pusher::new(&team).push(&c, &a_sync, 1, &a.key, b"ciphertext");
    for path in [
        c.relay.config.directory_path(),
        c.relay.config.team_path(&team),
    ] {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let tables: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap_or_else(|error| panic!("{} is not plain: {error}", path.display()));
        assert!(tables > 0);
    }
    // The downgrade commands do not apply to the plain files of `connect` mode: each is
    // refused, and relay.db and the store stay as they are.
    let (config, dir) = {
        let Connect { relay, .. } = c;
        relay.stop_keep()
    };
    assert!(Directory::downgrade_to_1005(&config, true).is_err());
    assert!(Directory::downgrade_to_1004(&config, true).is_err());
    assert!(Directory::downgrade_to_1003(&config, true).is_err());
    assert!(config.team_path(&team).exists());
    let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, DIRECTORY_VERSION);
    drop(conn);
    let directory = Directory::open(&config).unwrap();
    assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
    drop(directory);
    drop(dir);
}

/// Directory 1005 to the accounts step and back (`downgrade-directory-1005`): the vault
/// stores go with their files, the accounts stay, and the next start moves the file up
/// again with the schema of a new one. The rollback note is in OPERATIONS.md.
#[test]
fn the_directory_moves_to_the_accounts_step_and_back_with_the_rollback_note() {
    assert_eq!(DIRECTORY_VERSION, 1006);
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let (team, _) = make_store(&c, &token);
    let (config, dir) = {
        let Connect { relay, .. } = c;
        relay.stop_keep()
    };
    // Without the operator's word the vault stores stay, and nothing changes.
    for refused in [
        Directory::downgrade_to_1005(&config, false).map(drop),
        Directory::downgrade_to_1004(&config, false).map(drop),
        Directory::downgrade_to_1003(&config, false).map(drop),
    ] {
        let error = refused.unwrap_err();
        assert_eq!(error.code, apassy_relay::error::codes::CONFLICT);
        assert!(
            error.message.contains("--delete-vault-stores"),
            "{}",
            error.message
        );
    }
    assert!(config.team_path(&team).exists());
    assert_eq!(
        Directory::downgrade_to_1005(&config, true).unwrap(),
        (1006, 1005, 1)
    );
    assert!(!config.team_path(&team).exists());
    assert_eq!(
        Directory::downgrade_to_1005(&config, false).unwrap(),
        (1005, 1005, 0)
    );
    let directory = Directory::open(&config).unwrap();
    assert_eq!(directory.store.user_version().unwrap(), DIRECTORY_VERSION);
    assert!(directory.teams().unwrap().iter().all(|row| row.id != team));
    drop(directory);
    // The account and its device stay: it signs in on the upgraded relay.
    let mut config = config;
    let running: RunningRelay = relay::start_on_free_port(&mut config);
    running.hub().set_plans(Arc::new(TestPlans::default()));
    let origin = config.public_url.clone();
    let (status, answer) = call_url(
        &running.url(),
        Some(EDGE_SECRET),
        "POST",
        "/v1/account/challenge",
        None,
        Some(&json!({"account_id": a.account, "public_key": a.key.public_key_b64()})),
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["origin"], origin.as_str());
    running.stop();
    drop(dir);
    let operations = include_str!("../docs/OPERATIONS.md");
    assert!(operations.contains("downgrade-directory-1005"));
    assert!(operations.contains("Rollback of directory 1006"));
}

/// The account routes exist only with `APASSY_RELAY_CONNECT_ACCOUNTS=1`: else 404.
#[test]
fn without_the_setting_every_account_route_is_not_found() {
    let relay = start_with(|_| {}, UpstreamOptions::default());
    for (method, path) in [
        ("POST", "/v1/account"),
        ("GET", "/v1/account"),
        ("POST", "/v1/account/challenge"),
        ("GET", "/.well-known/apassy-connect.json"),
    ] {
        let (status, value) = relay.call(method, path, None, Some(&json!({})));
        assert_eq!(
            (status, value["error"]["code"].as_str()),
            (404, Some("not_found")),
            "{method} {path}"
        );
    }
}

// ---- Hardening of the account protocol. ----

const WELL_KNOWN: &str = "/.well-known/apassy-connect.json";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A challenge never ends another challenge: anyone may ask nonces for a device's key, and
/// the device's own nonce still signs it in. A removed device (revoked, or of a deleted
/// account) learns it from its own signed sign-in only (403 `device_removed`); a call
/// without its signature is the same 401 as any other.
#[test]
fn a_challenge_never_ends_another_and_only_the_device_learns_it_was_removed() {
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let (status, answer) = challenge(&c, &a.account, &b.key);
    assert_eq!(status, 200);
    let own = answer["result"]["nonce"].as_str().unwrap().to_string();
    // Someone else asks many nonces for the same key.
    for _ in 0..50 {
        assert_eq!(challenge(&c, &a.account, &b.key).0, 200);
    }
    let message =
        device::account_sign_in_message(c.origin(), &a.account, &b.key.public_key_b64(), &own);
    c.ok(
        "POST",
        "/v1/account/token",
        None,
        Some(&token_body(&a.account, &b.key, &own, &message)),
    );
    // A key that never was a device of the account gets no nonce.
    let stranger = DeviceKey::generate().unwrap();
    assert_eq!(challenge(&c, &a.account, &stranger).0, 401);
    // The device is removed: its own signed sign-in says so.
    revoke(&c, &a, &token, &b);
    assert_eq!(
        token_call(&c, &a.account, &b.key),
        (403, Some("device_removed".to_string()))
    );
    // Without its signature: 401, one answer for every cause.
    let (_, answer) = challenge(&c, &a.account, &b.key);
    let nonce = answer["result"]["nonce"].as_str().unwrap().to_string();
    let message =
        device::account_sign_in_message(c.origin(), &a.account, &b.key.public_key_b64(), &nonce);
    let mut by_stranger = token_body(&a.account, &stranger, &nonce, &message);
    by_stranger["public_key"] = json!(b.key.public_key_b64());
    let mut bad_signature = token_body(&a.account, &b.key, &nonce, &message);
    bad_signature["signature"] = json!("AAAA");
    let made_up = token_body(
        &a.account,
        &b.key,
        "bm9uY2U",
        &device::account_sign_in_message(
            c.origin(),
            &a.account,
            &b.key.public_key_b64(),
            "bm9uY2U",
        ),
    );
    for refused in [by_stranger, bad_signature, made_up] {
        c.fails(
            "POST",
            "/v1/account/token",
            None,
            Some(&refused),
            401,
            "unauthenticated",
        );
    }
    // A nonce for another account than the one the key was a device of: no nonce at all.
    let other = create(&c);
    assert_eq!(challenge(&c, &other.account, &b.key).0, 401);
    // The device of a deleted account learns it the same way.
    let d = create(&c);
    let d_token = sign_in(&c, &d);
    c.ok("DELETE", "/v1/account", Some(&d_token), None);
    assert_eq!(
        token_call(&c, &d.account, &d.key),
        (403, Some("device_removed".to_string()))
    );
}

/// The device list leads every device to the root: root A adds B, B adds C; the join of
/// C names B and carries the list; after A revokes B, the list keeps every entry before
/// the `remove` as it was (C's `add` by B stays valid), and every listed device is live in
/// it. A change signed over an old head is 409 and changes nothing.
#[test]
fn the_signed_device_list_leads_every_device_to_the_root_and_keeps_its_history() {
    let c = start();
    let a = create(&c);
    let a_token = sign_in(&c, &a);
    let b = add_device(&c, &a, &a_token);
    let b_token = sign_in(&c, &b);
    let hash = device::account_link_hash(&link_code(&a.account));
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(&b_token),
        Some(&json!({"link_hash": hash})),
    );
    let third = DeviceKey::generate().unwrap();
    let join = join_body(&c, &a.account, &hash, &third, "iPad");
    let joined = c.ok("POST", "/v1/account/devices/join", None, Some(&join));
    assert_eq!(joined["confirmer"]["device_id"], b.id.as_str());
    assert!(joined["confirmer"].get("chain").is_none());
    // The join answer carries the list: the root is A, and the confirmer B is in it.
    let list = joined["device_list"].as_array().unwrap();
    assert_eq!(list[0]["key"], a.key.public_key_b64());
    assert_eq!(list[1]["op"], "add");
    assert_eq!(list[1]["key"], b.key.public_key_b64());
    assert_eq!(head_of(&c, &a.account, &joined["device_list"]).0, 2);
    let join_id = joined["join_id"].as_u64().unwrap();
    c.ok(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&b_token),
        Some(&confirm_body(&c, &b, &b_token, &hash, (&third, "iPad"))),
    );
    // The same body of the join again answers the same confirmer and a longer list.
    let again = c.ok("POST", "/v1/account/devices/join", None, Some(&join));
    assert_eq!(again["confirmer"], joined["confirmer"]);
    assert_eq!(head_of(&c, &a.account, &again["device_list"]).0, 3);
    let before = c.ok("GET", "/v1/account", Some(&a_token), None)["device_list"].clone();
    // A revoke signed over an old head (version 2): 409, nothing changes.
    let old = c.ok("GET", "/v1/account", Some(&a_token), None)["device_list"]
        .as_array()
        .unwrap()[..2]
        .to_vec();
    let (version, previous) = head_of(&c, &a.account, &json!(old));
    let stale = json!({"version": version + 1, "statement": list_statement(
        &c, &a, (version + 1, &previous), "remove", &b.key.public_key_b64(), (None, None))});
    c.fails(
        "DELETE",
        &format!("/v1/account/devices/{}", b.id),
        Some(&a_token),
        Some(&stale),
        409,
        "conflict",
    );
    // A revoke without a statement, or with a statement of another device: 400.
    c.fails(
        "DELETE",
        &format!("/v1/account/devices/{}", b.id),
        Some(&a_token),
        None,
        400,
        "invalid_request",
    );
    let mut by_b = revoke_body(&c, &b, &b_token, &b);
    by_b["version"] = json!(4);
    c.fails(
        "DELETE",
        &format!("/v1/account/devices/{}", b.id),
        Some(&a_token),
        Some(&by_b),
        400,
        "invalid_request",
    );
    revoke(&c, &a, &a_token, &b);
    let view = c.ok("GET", "/v1/account", Some(&a_token), None);
    let list = view["device_list"].as_array().unwrap();
    assert_eq!(list.len(), 4);
    assert_eq!(&list[..3], before.as_array().unwrap().as_slice());
    assert_eq!(list[3]["op"], "remove");
    assert_eq!(list[3]["key"], b.key.public_key_b64());
    assert_eq!(list[3]["by"], a.key.public_key_b64());
    assert_eq!(head_of(&c, &a.account, &view["device_list"]).0, 4);
    // The live devices are A and C: the keys that the list holds now.
    let devices = view["devices"].as_array().unwrap();
    let keys: Vec<&str> = devices
        .iter()
        .map(|device| device["public_key"].as_str().unwrap())
        .collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&a.key.public_key_b64().as_str()));
    assert!(keys.contains(&third.public_key_b64().as_str()));
    assert!(devices.iter().all(|device| device.get("chain").is_none()));
    // The list keeps the link hash of each `add`, never a link code.
    assert!(
        c.directory_rows("SELECT link_hash FROM account_list WHERE link_hash IS NOT NULL")
            .contains(&hash)
    );
}

/// A device list is bounded: past `MAX_LIST_ENTRIES` a change is 403 `account_limit`.
#[test]
fn a_device_list_is_bounded() {
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let last = apassy_relay::server::account::MAX_LIST_ENTRIES;
    assert_eq!(list_head(&c, &a.account, &token).0, 2);
    // A list at its last version (only the version count matters for the limit).
    c.edit_directory(&format!(
        "UPDATE account_list SET version = {last} WHERE account_id = '{}' AND version = 2;",
        a.account
    ));
    // The next change would be past the limit: 403, nothing changes.
    let body = json!({"version": last + 1,
        "statement": encode_b64(&a.key.sign(b"apassy-connect device-list v1\0x").unwrap())});
    c.fails(
        "DELETE",
        &format!("/v1/account/devices/{}", b.id),
        Some(&token),
        Some(&body),
        403,
        "account_limit",
    );
    assert_eq!(
        c.ok("GET", "/v1/account", Some(&token), None)["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// Every key that the relay takes is a point on P-256: a 0x04-prefixed key off the curve
/// is refused on each route that names one.
#[test]
fn every_route_refuses_a_key_off_the_curve() {
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let (team, _) = make_store(&c, &token);
    let off = encode_b64(&[4u8; 65]);
    assert!(device::decode_public_key(&off).is_err());
    let signature = encode_b64(&a.key.sign(b"anything").unwrap());
    let hash = device::account_link_hash(&link_code(&a.account));
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(&token),
        Some(&json!({"link_hash": hash})),
    );
    let recovery = recovery_key(&[1u8; 16]).public_key_b64();
    let edge = [
        (
            "/v1/account",
            json!({"account_id": new_account_id(), "name": "Rafal", "device_name": "Mac",
                   "platform": "mac", "public_key": off, "recovery_key": recovery,
                   "signature": signature, "statement": signature}),
            400,
        ),
        (
            "/v1/account/challenge",
            json!({"account_id": a.account, "public_key": off}),
            400,
        ),
        (
            "/v1/account/token",
            json!({"account_id": a.account, "public_key": off,
                   "nonce": encode_b64(&[0u8; 32]), "signature": signature}),
            401,
        ),
        (
            "/v1/account/devices/join",
            json!({"account_id": a.account, "link_hash": hash, "device_name": "iPhone",
                   "platform": "iphone", "public_key": off, "signature": signature}),
            400,
        ),
        (
            "/v1/account/devices/join/cancel",
            json!({"account_id": a.account, "link_hash": hash, "public_key": off,
                   "signature": signature}),
            400,
        ),
        (
            "/v1/account/recover",
            json!({"account_id": a.account, "device_name": "Mac", "platform": "mac",
                   "public_key": off, "recovery_key": recovery, "signature": signature,
                   "recovery_signature": encode_b64(&[0u8; 64]), "statement": signature}),
            400,
        ),
    ];
    for (path, body, status) in edge {
        let (got, answer) = c.call("POST", path, None, Some(&body));
        assert_eq!(got, status, "{path}: {answer}");
    }
    let real = DeviceKey::generate().unwrap();
    let joined = c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(&c, &a.account, &hash, &real, "iPhone")),
    );
    let join_id = joined["join_id"].as_u64().unwrap();
    for (path, body) in [
        (
            format!("/v1/account/devices/pending/{join_id}/confirm"),
            json!({"public_key": off, "statement": signature}),
        ),
        (
            format!("/v1/account/vaults/{team}/devices"),
            json!({"device_id": a.id, "public_key": off}),
        ),
    ] {
        c.fails(
            "POST",
            &path,
            Some(&token),
            Some(&body),
            400,
            "invalid_request",
        );
    }
    assert!(
        c.directory_rows("SELECT id FROM account")
            .iter()
            .all(|id| *id == a.account)
    );
}

/// The store-device add takes the key that the caller checked: another key is 409 and
/// adds nothing; an unknown or revoked device is the same 403 `not_in_group` as a device
/// of another account. A vault store is deleted only by a device in it, of its account.
#[test]
fn a_store_device_add_needs_the_checked_key_and_a_delete_a_device_in_the_store() {
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let b_token = sign_in(&c, &b);
    let gone = add_device(&c, &a, &token);
    revoke(&c, &a, &token, &gone);
    let (team, _) = make_store(&c, &token);
    let path = format!("/v1/account/vaults/{team}/devices");
    let mut other_key = store_add_body(&b);
    other_key["public_key"] = json!(DeviceKey::generate().unwrap().public_key_b64());
    c.fails(
        "POST",
        &path,
        Some(&token),
        Some(&other_key),
        409,
        "conflict",
    );
    for target in [
        json!({"device_id": "dev_aaaaaaaaaa", "public_key": b.key.public_key_b64()}),
        store_add_body(&gone),
    ] {
        c.fails(
            "POST",
            &path,
            Some(&token),
            Some(&target),
            403,
            "not_in_group",
        );
    }
    assert_eq!(
        c.ok("GET", "/v1/account/vaults", Some(&token), None)[0]["devices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // A device of the account that is not in the store does not delete it.
    c.fails(
        "DELETE",
        &format!("/v1/account/vaults/{team}"),
        Some(&b_token),
        None,
        403,
        "forbidden",
    );
    c.ok("POST", &path, Some(&token), Some(&store_add_body(&b)));
    c.ok(
        "DELETE",
        &format!("/v1/account/vaults/{team}"),
        Some(&b_token),
        None,
    );
}

/// `revoked_at` of the store device named `device` in the open vault store `team`.
fn store_revoked(c: &Connect, team: &TeamId, device: &str) -> bool {
    c.relay
        .hub()
        .team(team)
        .unwrap()
        .store
        .with(|conn| {
            conn.query_row(
                "SELECT revoked_at IS NOT NULL FROM device WHERE name = ?1",
                [device],
                |row| row.get(0),
            )
            .map_err(apassy_relay::server::store::db)
        })
        .unwrap()
}

/// Turns writes of the open vault store `team` off or on (a file that refuses writes, as a
/// full one does).
fn store_writes(c: &Connect, team: &TeamId, on: bool) {
    let sql = if on {
        "PRAGMA query_only = 0;"
    } else {
        "PRAGMA query_only = 1;"
    };
    c.relay
        .hub()
        .team(team)
        .unwrap()
        .store
        .with(|conn| {
            conn.execute_batch(sql)
                .map_err(apassy_relay::server::store::db)
        })
        .unwrap();
}

/// A device removed while its vault store is suspended, or while the store file refuses
/// the write, is out of the store at once (its store token ends, no relay-sync sign-in),
/// and its row in the store file is revoked when the store opens (a resume, a restart) or
/// at the next maintenance pass.
#[test]
fn a_removal_that_waits_for_its_store_keeps_the_device_out_and_lands_later() {
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let devices: Vec<Dev> = (0..3).map(|_| add_device(&c, &a, &token)).collect();
    let (team, _) = make_store(&c, &token);
    for dev in &devices {
        c.ok(
            "POST",
            &format!("/v1/account/vaults/{team}/devices"),
            Some(&token),
            Some(&store_add_body(dev)),
        );
    }
    let pending = |c: &Connect| c.directory_rows("SELECT device_id FROM account_store_removal");
    let store_challenge = |c: &Connect, dev: &Dev| {
        c.call(
            "POST",
            "/v1/auth/challenge",
            None,
            Some(&json!({"team_id": team, "public_key": dev.key.public_key_b64()})),
        )
        .0
    };
    let revoke = |c: &Connect, dev: &Dev| {
        let revoked = revoke(c, &a, &token, dev);
        assert_eq!(revoked["removed_from_stores"], 1, "{revoked}");
    };

    // 1. The store is suspended: the removal waits for it, and its resume applies it.
    let first = &devices[0];
    let hub = c.relay.hub();
    hub.suspend(&team, now()).unwrap();
    revoke(&c, first);
    assert_eq!(pending(&c), std::slice::from_ref(&first.id));
    hub.resume(&team, now()).unwrap();
    assert!(store_revoked(&c, &team, &first.id));
    assert!(pending(&c).is_empty());
    assert_eq!(store_challenge(&c, first), 401);

    // 2. The store refuses the write: the device is out at once, and the maintenance pass
    // revokes its row once the file takes writes again.
    let second = &devices[1];
    let second_sync = c.relay.sign_in(&team, &second.key);
    store_writes(&c, &team, false);
    revoke(&c, second);
    assert_eq!(
        send(
            &c.relay.url,
            "GET",
            "/v1/sync/head",
            &second_sync,
            &[],
            Vec::new()
        )
        .status,
        401
    );
    assert!(!store_revoked(&c, &team, &second.id));
    assert_eq!(pending(&c), std::slice::from_ref(&second.id));
    // A challenge writes to its store: with writes back on, it refuses the device while
    // its row there may still wait.
    store_writes(&c, &team, true);
    assert_eq!(store_challenge(&c, second), 401);
    apassy_relay::server::http::maintain(
        &hub,
        now() + apassy_relay::server::hub::STORE_REMOVAL_MAX_WAIT_SECS,
    );
    assert!(store_revoked(&c, &team, &second.id));
    assert!(pending(&c).is_empty());

    // 3. The same with a restart before the retry: the open of the store applies it.
    let third = &devices[2];
    store_writes(&c, &team, false);
    revoke(&c, third);
    assert_eq!(pending(&c), std::slice::from_ref(&third.id));
    drop(hub);
    let third_id = third.id.clone();
    let third_key = third.key.public_key_b64();
    let Connect { relay, plans } = c;
    let relay = relay.restart();
    relay.hub().set_plans(plans.clone());
    let c = Connect { relay, plans };
    assert!(store_revoked(&c, &team, &third_id));
    assert!(pending(&c).is_empty());
    let (status, _) = c.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": third_key})),
    );
    assert_eq!(status, 401);
}

/// New accounts have the relay's caps (`APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY`, `_MAX`: 503
/// `busy` with `Retry-After: 3600`) and the cap of the client prefix that the Worker
/// proved (5 a day, 429); a retry of the same body counts nothing.
#[test]
fn new_accounts_have_the_relay_caps_and_a_cap_for_each_proven_prefix() {
    let create_from = |c: &Connect, prefix: Option<&str>, body: &Value| {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        let mut request = agent
            .post(format!("{}/v1/account", c.relay.url))
            .header("X-Apassy-Edge", EDGE_SECRET)
            .header("Content-Type", "application/json");
        if let Some(prefix) = prefix {
            request = request.header("X-Apassy-Client-Prefix", prefix).header(
                "X-Apassy-Client-Prefix-Mac",
                apassy_relay::server::connect::prefix_mac(EDGE_SECRET, prefix),
            );
        }
        let mut response = request.send(serde_json::to_vec(body).unwrap()).unwrap();
        let retry = response
            .headers()
            .get("Retry-After")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let value: Value =
            serde_json::from_str(&response.body_mut().read_to_string().unwrap()).unwrap();
        (
            response.status().as_u16(),
            value["error"]["code"].as_str().map(str::to_string),
            retry,
        )
    };
    let new_body = |c: &Connect| account_body(c, &DeviceKey::generate().unwrap(), &[1u8; 16]);
    // Five a day from one proven prefix; the sixth is 429; another prefix goes on.
    let c = start();
    for _ in 0..5 {
        assert_eq!(
            create_from(&c, Some("198.51.100.0/24"), &new_body(&c)).0,
            200
        );
    }
    let (status, code, _) = create_from(&c, Some("198.51.100.0/24"), &new_body(&c));
    assert_eq!((status, code.as_deref()), (429, Some("rate_limited")));
    assert_eq!(
        create_from(&c, Some("203.0.113.0/24"), &new_body(&c)).0,
        200
    );
    // A retry of the same body answers the same and counts nothing.
    let body = new_body(&c);
    let (status, _, _) = create_from(&c, Some("192.0.2.0/24"), &body);
    assert_eq!(status, 200);
    for _ in 0..6 {
        assert_eq!(create_from(&c, Some("192.0.2.0/24"), &body).0, 200);
    }
    assert_eq!(c.directory_rows("SELECT id FROM account").len(), 7);
    // The day's cap of the relay: 503 busy for an hour.
    let c = connect_with(|cfg| {
        accounts_on(cfg);
        cfg.connect.accounts_per_day = 2;
    });
    for prefix in ["198.51.100.0/24", "203.0.113.0/24"] {
        assert_eq!(create_from(&c, Some(prefix), &new_body(&c)).0, 200);
    }
    let (status, code, retry) = create_from(&c, Some("192.0.2.0/24"), &new_body(&c));
    assert_eq!(
        (status, code.as_deref(), retry.as_deref()),
        (503, Some("busy"), Some("3600"))
    );
    // The held cap, and 0: no new account.
    let c = connect_with(|cfg| {
        accounts_on(cfg);
        cfg.connect.accounts_max = 1;
    });
    assert_eq!(create_from(&c, None, &new_body(&c)).0, 200);
    assert_eq!(
        create_from(&c, Some("203.0.113.0/24"), &new_body(&c)).0,
        503
    );
    let c = connect_with(|cfg| {
        accounts_on(cfg);
        cfg.connect.accounts_per_day = 0;
    });
    assert_eq!(create_from(&c, None, &new_body(&c)).0, 503);
    assert!(c.directory_rows("SELECT id FROM account").is_empty());
}

/// The maintenance pass deletes links (with their joins) a day after they ended and the
/// relay audit rows of accounts after 90 days; newer rows stay.
#[test]
fn the_maintenance_pass_prunes_old_links_joins_and_account_audit_rows() {
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    let old = device::account_link_hash(&link_code(&a.account));
    let fresh = device::account_link_hash(&link_code(&a.account));
    for hash in [&old, &fresh] {
        c.ok(
            "POST",
            "/v1/account/devices/link",
            Some(&token),
            Some(&json!({"link_hash": hash})),
        );
    }
    c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(
            &c,
            &a.account,
            &old,
            &DeviceKey::generate().unwrap(),
            "iPhone",
        )),
    );
    let at = now();
    c.edit_directory(&format!(
        "UPDATE account_link SET expires_at = {} WHERE link_hash = '{old}';
         INSERT INTO audit (at, actor, action, detail) VALUES ({}, 'account:{}', 'account_link_created', '{{}}');
         INSERT INTO audit (at, actor, action, detail) VALUES ({}, 'operator', 'team_created', '{{}}');",
        at - 86_401,
        at - 91 * 86_400,
        a.account,
        at - 91 * 86_400,
    ));
    // The relay's own pass may have pruned them first: the rows decide.
    let (links, audit) = apassy_relay::server::account::prune(&c.relay.hub(), at).unwrap();
    assert!(links <= 1 && audit <= 1, "{links} {audit}");
    assert_eq!(
        c.directory_rows("SELECT link_hash FROM account_link"),
        [fresh]
    );
    assert!(c.directory_rows("SELECT name FROM account_join").is_empty());
    assert_eq!(
        c.directory_rows(
            "SELECT actor FROM audit WHERE actor = 'operator' AND action = 'team_created'"
        )
        .len(),
        1
    );
    assert!(
        c.directory_rows("SELECT actor FROM audit WHERE actor LIKE 'account:%'")
            .len()
            >= 2
    );
}

/// The maintenance pass deletes the rows of devices revoked more than 90 days ago and the
/// I-4 events delivered more than 90 days ago; an event that was never delivered stays,
/// however old (each event is delivered until a 2xx). A removed device still learns that it
/// was removed (its key stays in `account_key`), and the device list keeps its entries.
#[test]
fn the_maintenance_pass_prunes_old_revoked_devices_and_brain_events() {
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let fresh = add_device(&c, &a, &token);
    let delivered = add_device(&c, &a, &token);
    let recent = add_device(&c, &a, &token);
    revoke(&c, &a, &token, &b);
    revoke(&c, &a, &token, &fresh);
    revoke(&c, &a, &token, &delivered);
    revoke(&c, &a, &token, &recent);
    let at = now();
    c.edit_directory(&format!(
        "UPDATE account_device SET revoked_at = {old} WHERE id = '{}';
         UPDATE brain_event SET created_at = {old} WHERE subject IN ('{}', '{}', '{}');
         UPDATE brain_event SET done_at = {old} WHERE subject = '{}';
         UPDATE brain_event SET done_at = {at} WHERE subject = '{}';",
        b.id,
        b.id,
        delivered.id,
        recent.id,
        delivered.id,
        recent.id,
        old = at - 91 * 86_400,
    ));
    apassy_relay::server::account::prune(&c.relay.hub(), at).unwrap();
    assert!(
        c.directory_rows(&format!(
            "SELECT id FROM account_device WHERE id = '{}'",
            b.id
        ))
        .is_empty()
    );
    assert_eq!(
        c.directory_rows(&format!(
            "SELECT id FROM account_device WHERE id = '{}'",
            fresh.id
        )),
        std::slice::from_ref(&fresh.id)
    );
    let events = |device: &Dev| {
        c.directory_rows(&format!(
            "SELECT kind FROM brain_event WHERE subject = '{}'",
            device.id
        ))
    };
    // Old and never delivered: kept. Delivered 91 days ago: gone. Delivered now: kept.
    assert_eq!(events(&b), ["revoke"]);
    assert_eq!(events(&fresh), ["revoke"]);
    assert!(events(&delivered).is_empty());
    assert_eq!(events(&recent), ["revoke"]);
    // The pruned device: still `device_removed` for its own signed sign-in.
    assert_eq!(
        token_call(&c, &a.account, &b.key),
        (403, Some("device_removed".to_string()))
    );
    // The list keeps the entries of all: it still verifies.
    assert_eq!(list_head(&c, &a.account, &token).0, 9);
}

/// The published keys come from the configuration only: the signing key and the keys of
/// `APASSY_CONNECT_PUBLISHED_KEYS_FILE`. A new signing key signs one hour after this relay
/// first published it; the first key a relay has signs at once, also after a restart.
#[test]
fn published_keys_come_from_the_configuration_and_a_new_key_waits_an_hour() {
    use apassy_relay::server::entitlement::key_id;
    let other_key = || {
        let mut der = unhex("302e020100300506032b657004220420");
        der.extend([5u8; 32]);
        ConnectSigningKey::from_file_bytes(&der).unwrap()
    };
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    c.ok("GET", "/v1/account/entitlement", Some(&token), None);
    let first_kid = c.ok("GET", WELL_KNOWN, None, None)["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    // Restart with a new signing key, the old one no longer configured.
    let Connect { relay, plans } = c;
    let (mut config, dir) = relay.stop_keep();
    let rows = |config: &RelayConfig, sql: &str| {
        let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
            .unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        conn.execute_batch(sql).unwrap();
    };
    // The first key was published a day before the new one.
    rows(
        &config,
        "UPDATE entitlement_key SET created_at = created_at - 86400;",
    );
    config.connect.signing_key = Some(other_key());
    let running = relay::start_on_free_port(&mut config);
    running.hub().set_plans(plans.clone());
    let call = |method: &str, path: &str, token: Option<&str>| {
        call_url(&running.url(), Some(EDGE_SECRET), method, path, token, None)
    };
    let known = call("GET", WELL_KNOWN, None).1;
    let kids: Vec<&str> = known["result"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids.len(), 1, "{known}");
    assert_ne!(kids[0], first_kid);
    let new_kid = kids[0].to_string();
    // The old key signed a token a moment ago, yet it is not published: its row is
    // history only.
    let dev = Dev {
        key: a.key,
        account: a.account.clone(),
        id: a.id.clone(),
    };
    let base = running.url();
    let sign_in_at = || {
        let (_, answer) = call_url(
            &base,
            Some(EDGE_SECRET),
            "POST",
            "/v1/account/challenge",
            None,
            Some(&json!({"account_id": dev.account, "public_key": dev.key.public_key_b64()})),
        );
        let nonce = answer["result"]["nonce"].as_str().unwrap().to_string();
        let message = device::account_sign_in_message(
            &config.public_url,
            &dev.account,
            &dev.key.public_key_b64(),
            &nonce,
        );
        let (_, granted) = call_url(
            &base,
            Some(EDGE_SECRET),
            "POST",
            "/v1/account/token",
            None,
            Some(&token_body(&dev.account, &dev.key, &nonce, &message)),
        );
        granted["result"]["token"].as_str().unwrap().to_string()
    };
    let token = sign_in_at();
    let (status, answer) = call("GET", "/v1/account/entitlement", Some(&token));
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (503, Some("busy")),
        "{answer}"
    );
    // An hour after it was first published, it signs.
    rows(
        &config,
        &format!(
            "UPDATE entitlement_key SET created_at = created_at - 3601 WHERE kid = '{new_kid}';"
        ),
    );
    let (status, answer) = call("GET", "/v1/account/entitlement", Some(&token));
    assert_eq!(status, 200, "{answer}");
    let verified = Entitlement::verify(
        &[PublishedKey {
            kid: new_kid.clone(),
            public_key: decode_b64(
                known["result"]["keys"][0]["public_key"].as_str().unwrap(),
                32,
            )
            .unwrap()
            .try_into()
            .unwrap(),
        }],
        answer["result"]["token"].as_str().unwrap(),
        now(),
    )
    .unwrap();
    assert_eq!(verified.kid, new_kid);
    running.stop();
    // Back to the first key, with the second one published from the file: the first key
    // is the relay's first and signs at once; both are published.
    let file = dir.path().join("published.json");
    let second = other_key();
    let second_public: [u8; 32] = {
        let signer =
            apassy_relay::server::entitlement::EntitlementSigner::from_key(&second).unwrap();
        signer.public_key()
    };
    std::fs::write(
        &file,
        format!(
            r#"{{"keys":[{{"kid":"{}","public_key":"{}"}}]}}"#,
            key_id(&second_public),
            encode_b64(&second_public)
        ),
    )
    .unwrap();
    config.connect.signing_key = Some(signing_key());
    config.connect.published_keys =
        apassy_relay::config::published_keys_from(&std::fs::read(&file).unwrap()).unwrap();
    let running = relay::start_on_free_port(&mut config);
    running.hub().set_plans(plans.clone());
    let base = running.url();
    let (_, known) = call_url(&base, Some(EDGE_SECRET), "GET", WELL_KNOWN, None, None);
    let kids: Vec<&str> = known["result"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids, [first_kid.as_str(), new_kid.as_str()]);
    let (_, answer) = call_url(
        &base,
        Some(EDGE_SECRET),
        "POST",
        "/v1/account/challenge",
        None,
        Some(&json!({"account_id": dev.account, "public_key": dev.key.public_key_b64()})),
    );
    let nonce = answer["result"]["nonce"].as_str().unwrap().to_string();
    let message = device::account_sign_in_message(
        &config.public_url,
        &dev.account,
        &dev.key.public_key_b64(),
        &nonce,
    );
    let (_, granted) = call_url(
        &base,
        Some(EDGE_SECRET),
        "POST",
        "/v1/account/token",
        None,
        Some(&token_body(&dev.account, &dev.key, &nonce, &message)),
    );
    let token = granted["result"]["token"].as_str().unwrap().to_string();
    let (status, answer) = call_url(
        &base,
        Some(EDGE_SECRET),
        "GET",
        "/v1/account/entitlement",
        Some(&token),
        None,
    );
    assert_eq!(status, 200, "{answer}");
    running.stop();
    drop(dir);
}

/// A 1006 file of an earlier build of the accounts step (no `account_list.name`) is refused
/// at open with a message for the operator, also after a downgrade to 1005.
#[test]
fn a_directory_of_an_earlier_accounts_step_is_refused_at_open() {
    let c = start();
    create(&c);
    let (config, dir) = {
        let Connect { relay, .. } = c;
        relay.stop_keep()
    };
    let edit = |sql: &str| {
        let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{}';", relay::VAULT_KEY))
            .unwrap();
        conn.execute_batch(sql).unwrap();
    };
    edit("ALTER TABLE account_list DROP COLUMN name;");
    let refused = Directory::open(&config).err().expect("refused");
    assert!(
        refused.message.contains("earlier, unreleased build"),
        "{}",
        refused.message
    );
    edit("PRAGMA user_version = 1005;");
    let refused = Directory::open(&config).err().expect("refused");
    assert!(
        refused.message.contains("account_list.name"),
        "{}",
        refused.message
    );
    drop(dir);
}

// ---- The end of a device list, recovery answers, store adds, store nonces. ----

/// The head of the device list of `account` as `relay.db` holds it: its version and hash
/// (for a test that moved the version of the head).
fn stored_head(c: &Connect, account: &str) -> (u64, String) {
    let row = c.directory_rows(&format!(
        "SELECT version || ' ' || hash FROM account_list WHERE account_id = '{account}' \
         ORDER BY version DESC LIMIT 1"
    ));
    let (version, hash) = row[0].split_once(' ').unwrap();
    (version.parse().unwrap(), hash.to_string())
}

/// Moves the head of the device list of `account` to `version` (only the version counts
/// for the bounds of the list).
fn move_head(c: &Connect, account: &str, version: u64) {
    let (head, _) = stored_head(c, account);
    c.edit_directory(&format!(
        "UPDATE account_list SET version = {version} WHERE account_id = '{account}' AND version = {head};"
    ));
}

/// The `remove` of `target` by `by` (signed in with `token`) over the stored head.
fn remove_at_head(c: &Connect, by: &Dev, token: &str, target: &Dev) -> (u16, Value) {
    let (head, previous) = stored_head(c, &by.account);
    let statement = list_statement(
        c,
        by,
        (head + 1, &previous),
        "remove",
        &target.key.public_key_b64(),
        (None, None),
    );
    c.call(
        "DELETE",
        &format!("/v1/account/devices/{}", target.id),
        Some(token),
        Some(&json!({"version": head + 1, "statement": statement})),
    )
}

/// The confirmation by `by` of a new join named "iPhone" over the stored head: the status
/// and the answer.
fn add_at_head(c: &Connect, by: &Dev, token: &str) -> (u16, Value) {
    let hash = device::account_link_hash(&link_code(&by.account));
    c.ok(
        "POST",
        "/v1/account/devices/link",
        Some(token),
        Some(&json!({"link_hash": hash})),
    );
    let key = DeviceKey::generate().unwrap();
    let joined = c.ok(
        "POST",
        "/v1/account/devices/join",
        None,
        Some(&join_body(c, &by.account, &hash, &key, "iPhone")),
    );
    let (head, previous) = stored_head(c, &by.account);
    let statement = list_statement(
        c,
        by,
        (head + 1, &previous),
        "add",
        &key.public_key_b64(),
        (Some(&hash), Some("iPhone")),
    );
    c.call(
        "POST",
        &format!(
            "/v1/account/devices/pending/{}/confirm",
            joined["join_id"].as_u64().unwrap()
        ),
        Some(token),
        Some(
            &json!({"public_key": key.public_key_b64(), "version": head + 1,
                     "statement": statement}),
        ),
    )
}

/// The end of a device list is kept for removals: an `add` is refused after
/// `LAST_ADD_VERSION` (246) with 403 `account_limit`, while a `remove` works up to
/// `MAX_LIST_ENTRIES` (256), also the last device removing itself at 256; the account then
/// recovers and starts a new list.
#[test]
fn the_end_of_a_device_list_keeps_room_to_remove_every_device_and_recover() {
    use apassy_relay::server::account::{LAST_ADD_VERSION, MAX_DEVICES, MAX_LIST_ENTRIES};
    assert_eq!(LAST_ADD_VERSION, 822);
    const { assert!(MAX_LIST_ENTRIES - LAST_ADD_VERSION >= MAX_DEVICES) };
    let c = start();
    // 1. An add at 822 works; an add at 823 is refused and adds nothing; a remove at 823
    // still works.
    let a = create(&c);
    let token = sign_in(&c, &a);
    add_device(&c, &a, &token);
    move_head(&c, &a.account, LAST_ADD_VERSION - 1);
    let (status, added) = add_at_head(&c, &a, &token);
    assert_eq!(status, 200, "{added}");
    let last_added = Dev {
        key: DeviceKey::generate().unwrap(),
        account: a.account.clone(),
        id: added["result"]["device_id"].as_str().unwrap().to_string(),
    };
    assert_eq!(stored_head(&c, &a.account).0, LAST_ADD_VERSION);
    let (status, refused) = add_at_head(&c, &a, &token);
    assert_eq!(
        (status, refused["error"]["code"].as_str()),
        (403, Some("account_limit")),
        "{refused}"
    );
    let text = refused["error"]["message"].as_str().unwrap();
    assert!(
        text.contains("nearly full") && text.contains("Removing a device still works"),
        "{text}"
    );
    assert_eq!(stored_head(&c, &a.account).0, LAST_ADD_VERSION);
    assert_eq!(
        c.ok("GET", "/v1/account", Some(&token), None)["devices"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // A remove needs only the key in the list: a fresh `Dev` with the device's id and a
    // key of the view.
    let view = c.ok("GET", "/v1/account", Some(&token), None);
    let key_of = |id: &str| {
        view["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|device| device["device_id"] == id)
            .unwrap()["public_key"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (head, previous) = stored_head(&c, &a.account);
    let statement = list_statement(
        &c,
        &a,
        (head + 1, &previous),
        "remove",
        &key_of(&last_added.id),
        (None, None),
    );
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", last_added.id),
        Some(&token),
        Some(&json!({"version": head + 1, "statement": statement})),
    );

    // 2. A list at 1022: a remove at 1023 and the last device's own remove at 1024 work;
    // the account then recovers with a new list.
    let code: [u8; 16] = [7u8; 16];
    let r = create(&c);
    let r_token = sign_in(&c, &r);
    let other = add_device(&c, &r, &r_token);
    move_head(&c, &r.account, MAX_LIST_ENTRIES - 2);
    let (status, answer) = remove_at_head(&c, &r, &r_token, &other);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(stored_head(&c, &r.account).0, MAX_LIST_ENTRIES - 1);
    let (status, answer) = remove_at_head(&c, &r, &r_token, &r);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(stored_head(&c, &r.account).0, MAX_LIST_ENTRIES);
    let new_key = DeviceKey::generate().unwrap();
    let (status, recovered) = c.call(
        "POST",
        "/v1/account/recover",
        None,
        Some(&recover_body(&c, &r.account, &code, &new_key, &[8u8; 16])),
    );
    assert_eq!(status, 200, "{recovered}");
    assert_eq!(stored_head(&c, &r.account).0, 1);
}

/// A failed recovery has the same answers for an unknown and an existing account id: over
/// 6 wrong tries of one id, 5 times 403 and then 429 for both (unknown ids are counted in a
/// table of their own), and the limit of the client prefix stays 20 for both.
#[test]
fn a_recovery_answers_an_unknown_and_an_existing_account_the_same() {
    let c = start();
    let recover_from = |prefix: &str, body: &Value| {
        let mac = apassy_relay::server::connect::prefix_mac(EDGE_SECRET, prefix);
        let (status, text) = relay::call_raw(
            &c.relay.url,
            Some(EDGE_SECRET),
            "POST",
            "/v1/account/recover",
            None,
            &[
                ("X-Apassy-Client-Prefix", prefix),
                ("X-Apassy-Client-Prefix-Mac", mac.as_str()),
            ],
            Some(body),
        );
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, value["error"].clone())
    };
    let existing = create(&c);
    let token = sign_in(&c, &existing);
    revoke(&c, &existing, &token, &existing);
    let key = DeviceKey::generate().unwrap();
    let wrong = |account: &str| recover_body(&c, account, &[0u8; 16], &key, &[1u8; 16]);
    // Six wrong tries of one id, each from its own prefix: the same sequence for both.
    let sequence = |account: &str, net: u8| -> Vec<(u16, Value)> {
        (0..6)
            .map(|index| recover_from(&format!("198.51.{net}.{index}/32"), &wrong(account)))
            .collect()
    };
    let known = sequence(&existing.account, 1);
    let stranger = sequence(&new_account_id(), 2);
    assert_eq!(
        known.iter().map(|(status, _)| *status).collect::<Vec<_>>(),
        [403, 403, 403, 403, 403, 429]
    );
    assert_eq!(known, stranger);
    // The limit of one prefix is the same for both: 20 failures of fresh ids, then 429.
    for _ in 0..20 {
        assert_eq!(
            recover_from("203.0.113.0/24", &wrong(&new_account_id())).0,
            403
        );
    }
    let other = create(&c);
    let other_token = sign_in(&c, &other);
    revoke(&c, &other, &other_token, &other);
    let known = recover_from("203.0.113.0/24", &wrong(&other.account));
    let stranger = recover_from("203.0.113.0/24", &wrong(&new_account_id()));
    assert_eq!(known.0, 429, "{}", known.1);
    assert_eq!(known, stranger);
    // The right recovery key is never limited.
    let (status, _) = c.call(
        "POST",
        "/v1/account/recover",
        None,
        Some(&recover_body(
            &c,
            &existing.account,
            &[7u8; 16],
            &key,
            &[1u8; 16],
        )),
    );
    assert_eq!(status, 200);
}

/// The store add re-checks the device and its group in the directory transaction that maps
/// it: a device revoked after the checks of the route (here: the step of the hub after the
/// revoke) is not mapped, and its new row in the store file is revoked.
#[test]
fn a_store_device_add_that_races_a_revoke_maps_nothing() {
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let (team, _) = make_store(&c, &token);
    // The route checked B (live, of the account); then B is revoked; then the add runs.
    revoke(&c, &a, &token, &b);
    let added =
        c.relay
            .hub()
            .add_store_device(&team, &a.account, &b.id, &b.key.public_key(), now());
    assert_eq!(
        added.as_ref().map_err(|error| error.code),
        Err(apassy_relay::error::codes::NOT_IN_GROUP),
        "{added:?}"
    );
    assert!(
        c.directory_rows(&format!(
            "SELECT team_id FROM account_store_device WHERE device_id = '{}'",
            b.id
        ))
        .is_empty()
    );
    assert!(store_revoked(&c, &team, &b.id));
    assert!(
        c.directory_rows("SELECT device_id FROM account_store_removal")
            .is_empty()
    );
    let (status, _) = c.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": b.key.public_key_b64()})),
    );
    assert_eq!(status, 401);
}

/// A revoke that committed and whose store removal was never applied (a crash between the
/// commit and `Hub::apply_removals`): the device is out of the store at once, and the store
/// file revokes its row when it opens after a restart.
#[test]
fn a_removal_left_by_a_crash_after_the_commit_lands_when_the_store_opens() {
    use apassy_relay::server::store::db;
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let (team, _) = make_store(&c, &token);
    let added = c.ok(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&token),
        Some(&store_add_body(&b)),
    );
    let store_device = added["store_device_id"].as_u64().unwrap();
    revoke(&c, &a, &token, &b);
    // The state of the commit without its second half: the store row live again and the
    // waiting removal back, as the transaction of the revoke left them.
    c.relay
        .hub()
        .team(&team)
        .unwrap()
        .store
        .with(|conn| {
            conn.execute(
                "UPDATE device SET revoked_at = NULL WHERE id = ?1",
                [store_device as i64],
            )
            .map_err(db)
        })
        .unwrap();
    c.edit_directory(&format!(
        "INSERT INTO account_store_removal (team_id, store_device, device_id, created_at, attempts, next_at) \
         VALUES ('{team}', {store_device}, '{}', {at}, 0, {at});",
        b.id,
        at = now()
    ));
    assert!(!store_revoked(&c, &team, &b.id));
    let challenge = |c: &Connect| {
        c.call(
            "POST",
            "/v1/auth/challenge",
            None,
            Some(&json!({"team_id": team, "public_key": b.key.public_key_b64()})),
        )
        .0
    };
    // Out at once: the directory holds no map row for it.
    assert_eq!(challenge(&c), 401);
    let Connect { relay, plans } = c;
    let relay = relay.restart();
    relay.hub().set_plans(plans.clone());
    let c = Connect { relay, plans };
    assert!(store_revoked(&c, &team, &b.id));
    assert!(
        c.directory_rows("SELECT device_id FROM account_store_removal")
            .is_empty()
    );
    assert_eq!(challenge(&c), 401);
}

/// The used sign-in nonces are bounded for each key: past `USED_NONCES_PER_KEY` live ones a
/// key is 429 `rate_limited`, and another key of the same account still signs in.
#[test]
fn the_used_nonces_of_one_key_leave_another_key_of_the_account_alone() {
    use apassy_relay::server::account::USED_NONCES_PER_KEY;
    let c = start();
    let a = create(&c);
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    for _ in 1..USED_NONCES_PER_KEY {
        assert_eq!(token_call(&c, &a.account, &a.key), (200, None));
    }
    assert_eq!(
        token_call(&c, &a.account, &a.key),
        (429, Some("rate_limited".to_string()))
    );
    assert_eq!(token_call(&c, &a.account, &b.key), (200, None));
}

/// The relay-sync challenge of a vault store keeps no state until its nonce is used: many
/// challenges of one key never end an earlier one, a used nonce is refused, and a nonce of
/// one key signs in no other key. The nonce is b64u of 32 bytes, as for any team.
#[test]
fn a_vault_store_challenge_never_ends_another_and_a_nonce_works_once() {
    let c = start();
    let a = create(&c);
    c.plans.set(&a.account, entitled());
    let token = sign_in(&c, &a);
    let b = add_device(&c, &a, &token);
    let (team, _) = make_store(&c, &token);
    c.ok(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&token),
        Some(&store_add_body(&b)),
    );
    let nonce_for = |key: &DeviceKey| {
        let answer = c.ok(
            "POST",
            "/v1/auth/challenge",
            None,
            Some(&json!({"team_id": team, "public_key": key.public_key_b64()})),
        );
        let nonce = answer["nonce"].as_str().unwrap().to_string();
        assert_eq!(decode_b64(&nonce, 32).unwrap().len(), 32);
        nonce
    };
    let body = |key: &DeviceKey, nonce: &str| {
        let public_key = key.public_key_b64();
        let message = device::sign_in_message(c.origin(), &team, &public_key, nonce);
        json!({"team_id": team, "public_key": public_key, "nonce": nonce,
               "signature": encode_b64(&key.sign(&message).unwrap())})
    };
    let first = nonce_for(&a.key);
    // Another device of the store asks many nonces for A's key.
    for _ in 0..20 {
        nonce_for(&a.key);
    }
    let granted = c.ok("POST", "/v1/auth/token", None, Some(&body(&a.key, &first)));
    assert!(granted["token"].is_string(), "{granted}");
    // Used: refused.
    c.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&body(&a.key, &first)),
        401,
        "unauthenticated",
    );
    // A nonce of A's key does not sign in B, and stays good for A after B's try.
    let second = nonce_for(&a.key);
    c.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&body(&b.key, &second)),
        401,
        "unauthenticated",
    );
    c.ok("POST", "/v1/auth/token", None, Some(&body(&a.key, &second)));
    // A made-up nonce of the right size: 401.
    c.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&body(&a.key, &encode_b64(&[7u8; 32]))),
        401,
        "unauthenticated",
    );
}

// ---- The app's client against this relay (wire compatibility). ----

const PASS: &str = "synthetic-connect-pass";

/// An app device: its key store and its account file.
struct AppDevice {
    _dir: tempfile::TempDir,
    store: apassy::connect::MemoryKeyStore,
    path: std::path::PathBuf,
}

fn app_device() -> AppDevice {
    let dir = tempfile::tempdir().unwrap();
    let path = apassy::connect::account_file(dir.path());
    AppDevice {
        _dir: dir,
        store: apassy::connect::MemoryKeyStore::new(),
        path,
    }
}

/// The real `src/connect` client of the Mac (unit M1) against a relay with
/// the account routes on (no edge: the client talks to Connect as to the Worker): create,
/// sign-in, the view, "Add a device…" with the words and a fresh owner check, the join on
/// the new device, a vault store with a second device, the entitlement token checked with
/// the well-known keys, revoke, and the deletion.
#[test]
fn the_app_client_works_against_the_relay() {
    use apassy::broker::approvals::{OwnerCheck, OwnerGate};
    use apassy::connect::{ConnectAccount, ConnectClient, JoinPoll, JoinRequest};

    let c = connect_with(|cfg| {
        accounts_on(cfg);
        cfg.edge = EdgeMode::Off;
    });
    let vault_dir = tempfile::tempdir().unwrap();
    let mut vault = apassy::vault::Vault::create(&vault_dir.path().join("owner.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    let shared: apassy::broker::SharedVault = Arc::new(Mutex::new(Some(vault)));
    let gate = OwnerGate::new(Arc::clone(&shared), None);
    let proof = |action| {
        let proof = gate
            .authorize(action, OwnerCheck::passphrase(PASS))
            .unwrap();
        let epoch = shared.lock().unwrap().as_ref().unwrap().epoch();
        (proof, epoch)
    };
    let client = || ConnectClient::new(&c.relay.url).unwrap();

    let (a, b) = (app_device(), app_device());
    let (mut account, recovery) =
        ConnectAccount::create(client(), &a.store, &a.path, "Rafal", "MacBook Pro")
            .expect("create");
    let account_id = account.state().account_id.clone();
    assert_eq!(recovery.key().unwrap().public_key_b64u().len(), 43);
    let view = account.view().expect("view");
    assert_eq!(
        (
            view.account_id.as_str(),
            view.devices.len(),
            view.plan.status.as_str()
        ),
        (account_id.as_str(), 1, "none")
    );
    assert!(account.entitlement().expect("entitlement").is_none());

    // "Add a device…": the link, the join on the new device, the words, the owner check.
    let link = account.start_link().expect("link");
    let mut request =
        JoinRequest::start(client(), &b.store, &b.path, link.code(), "iPhone").expect("join");
    assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
    let pending = account.pending_joins(&link).expect("pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].words, request.words());
    let (owner, epoch) = proof(pending[0].owner_action(&account_id));
    let added = account
        .confirm_join(&link, &pending[0], owner, &epoch)
        .expect("confirm");
    let mut phone = match request.poll().expect("poll") {
        JoinPoll::Confirmed(joined) => *joined,
        other => panic!("not confirmed: {other:?}"),
    };
    assert_eq!(phone.state().device_id, added.device_id);
    assert_eq!(phone.view().expect("phone view").devices.len(), 2);

    // A vault store with both devices, and the entitlement token.
    c.plans.set(&account_id, entitled());
    let store = account
        .create_vault_store(VAULT, "Personal")
        .expect("store");
    let (owner, epoch) = proof(ConnectAccount::add_store_device_action(
        &store.team_id,
        &added.device_id,
        &account_id,
    ));
    let joined = account
        .add_store_device(&store.team_id, &added.device_id, &account_id, owner, &epoch)
        .expect("add to the store");
    assert_eq!(joined.store_device_id, 2);
    assert_eq!(phone.vault_stores().expect("stores")[0].devices.len(), 2);
    let entitlement = account
        .entitlement()
        .expect("entitlement")
        .expect("entitled");
    assert_eq!(entitlement.claims().acc, account_id);

    // Revoke the phone: it is a device no more.
    let device = account
        .view()
        .unwrap()
        .devices
        .into_iter()
        .find(|d| d.device_id == added.device_id)
        .unwrap();
    let (owner, epoch) = proof(account.revoke_action(&device));
    let outcome = account.revoke(&device, owner, &epoch).expect("revoke");
    assert_eq!(outcome.answer.removed_from_stores, 1);
    assert!(phone.view().is_err());
    // Delete the store and the account.
    let (owner, epoch) = proof(ConnectAccount::delete_vault_store_action(&store.team_id));
    account
        .delete_vault_store(&store.team_id, owner, &epoch)
        .expect("delete the store");
    let (owner, epoch) = proof(account.delete_action());
    let (deleted, _) = account.delete(&a.store, owner, &epoch).expect("delete");
    assert_eq!(deleted.deleted_stores, 0);
    assert!(c.directory_rows("SELECT id FROM account").is_empty());
}
