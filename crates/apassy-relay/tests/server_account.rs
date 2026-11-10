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

fn account_body(c: &Connect, key: &DeviceKey, recovery: &[u8; 16]) -> Value {
    let public_key = key.public_key_b64();
    let signature = key
        .sign(&device::account_message(c.origin(), &public_key))
        .unwrap();
    json!({"name": "Rafal", "device_name": "MacBook Pro", "platform": "mac",
           "public_key": public_key, "recovery_hash": device::account_recovery_hash(recovery),
           "signature": encode_b64(&signature)})
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

/// A link code of `account` as the device that adds a device makes it.
fn link_code(account: &str) -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    format!("apassy_alk_{account}_{}", hex(&bytes))
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
        Some(&json!({"public_key": key.public_key_b64()})),
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
    // Another origin, another key, another domain: 400, nothing made.
    let mut other_origin = body.clone();
    other_origin["signature"] = json!(encode_b64(
        &key.sign(&device::account_message(
            "https://connect.example.test",
            &key.public_key_b64()
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
            .sign(&device::account_message(c.origin(), &key.public_key_b64()))
            .unwrap()
    ));
    for bad in [&other_origin, &other_domain, &other_key] {
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
    assert!(account.starts_with("acc_") && account.len() == 14);
    // A retry of the same body (a lost answer) answers the same result.
    assert_eq!(c.ok("POST", "/v1/account", None, Some(&body)), made);
    // The same key with another body is a conflict, and makes nothing.
    let other = account_body(&c, &key, &[2u8; 16]);
    c.fails("POST", "/v1/account", None, Some(&other), 409, "conflict");
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
/// the bouncer brain), over a used or an unknown nonce, is the same 401. A key that is not
/// a device gets no nonce. An account token is no team token and the reverse.
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
    // A refused attempt used its nonce up: the right signature over it is 401 too.
    refused(
        &device::account_sign_in_message(c.origin(), &a.account, &public_key, &n),
        &n,
    );
    // A used nonce works once.
    let n = nonce();
    let message = device::account_sign_in_message(c.origin(), &a.account, &public_key, &n);
    c.ok(
        "POST",
        "/v1/account/token",
        None,
        Some(&token_body(&a.account, &a.key, &n, &message)),
    );
    refused(&message, &n);
    // At most four open nonces for each key: the oldest goes.
    let first = nonce();
    for _ in 0..4 {
        nonce();
    }
    refused(
        &device::account_sign_in_message(c.origin(), &a.account, &public_key, &first),
        &first,
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
        Some(&json!({"public_key": b.public_key_b64()})),
        409,
        "conflict",
    );
    let (status, answer) = challenge(&c, &a.account, &b);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("join_refused"))
    );
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
    let recovery: Vec<u8> = (16u8..32).collect();
    assert_eq!(
        device::account_recovery_hash(&recovery),
        v["recovery"]["recovery_hash"].as_str().unwrap()
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
        Some(&json!({"public_key": b.public_key_b64()})),
        403,
        "forbidden",
    );
    // Another key than the one of the words: 409, nothing added.
    let other = DeviceKey::generate().unwrap();
    c.fails(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&token),
        Some(&json!({"public_key": other.public_key_b64()})),
        409,
        "conflict",
    );
    assert_eq!(
        c.ok("GET", "/v1/account", Some(&token), None)["devices"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    c.ok(
        "POST",
        &format!("/v1/account/devices/pending/{join_id}/confirm"),
        Some(&token),
        Some(&json!({"public_key": b.public_key_b64()})),
    );
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
    c.ok("POST", "/v1/account/devices/join/cancel", None,
        Some(&json!({"account_id": a.account, "link_hash": hash, "public_key": cancelled.public_key_b64()})));
    let (status, _) = challenge(&c, &a.account, &cancelled);
    assert_eq!(status, 403);
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
        Some(&json!({"device_id": b.id})),
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

    let revoked = c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", b.id),
        Some(&token),
        None,
    );
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
    let (status, _) = challenge(&c, &a.account, &b.key);
    assert_eq!(status, 401);
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
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", a.id),
        Some(&token),
        None,
    );
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
        Some(&json!({"device_id": b.id})),
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
        Some(&json!({"device_id": other.id})),
        403,
        "not_in_group",
    );
    // The other account's own device is not in the store: it adds nothing and deletes nothing.
    c.fails(
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&other_token),
        Some(&json!({"device_id": other.id})),
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
    // A team that is not a vault store: 403 account_required.
    let operator_team = c.relay.team_id.clone();
    c.fails(
        "POST",
        &format!("/v1/account/vaults/{operator_team}/devices"),
        Some(&token),
        Some(&json!({"device_id": a.id})),
        403,
        "account_required",
    );
}

/// Recovery works only with zero live devices and the right code, replaces the code,
/// deletes every vault store, keeps the account, and has at most five tries an hour.
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
    let recover = |code: &[u8], new_key: &DeviceKey, new_code: &[u8; 16]| {
        let public_key = new_key.public_key_b64();
        let signature = new_key
            .sign(&device::account_recover_message(
                c.origin(),
                &a.account,
                &public_key,
            ))
            .unwrap();
        c.call("POST", "/v1/account/recover", None, Some(&json!({
            "account_id": a.account, "recovery": format!("apassy_rec_{}", hex(code)),
            "device_name": "MacBook Air", "platform": "mac", "public_key": public_key,
            "recovery_hash": device::account_recovery_hash(new_code), "signature": encode_b64(&signature)})))
    };
    let new_key = DeviceKey::generate().unwrap();
    // With a live device: 403, the same as a wrong code.
    let (status, answer) = recover(&code, &new_key, &[9u8; 16]);
    assert_eq!(
        (status, answer["error"]["code"].as_str()),
        (403, Some("forbidden"))
    );
    let (_, wrong) = recover(&[0u8; 16], &new_key, &[9u8; 16]);
    assert_eq!(wrong["error"], answer["error"]);
    // No live device: the right code recovers.
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", a.id),
        Some(&token),
        None,
    );
    let (status, _) = recover(&[0u8; 16], &new_key, &[9u8; 16]);
    assert_eq!(status, 403);
    let (status, recovered) = recover(&code, &new_key, &[9u8; 16]);
    assert_eq!(status, 200, "{recovered}");
    assert_eq!(recovered["result"]["account_id"], a.account.as_str());
    assert_eq!(recovered["result"]["deleted_stores"], 1);
    assert!(!c.relay.config.team_path(&team).exists());
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
    // The old code is gone: with no live device again, it does not work; the new one does.
    c.ok(
        "DELETE",
        &format!("/v1/account/devices/{}", b.id),
        Some(&b_token),
        None,
    );
    let third = DeviceKey::generate().unwrap();
    let (status, _) = recover(&code, &third, &[8u8; 16]);
    assert_eq!(status, 403);
    // Five tries an hour for each account: this was the fifth; the sixth is 429.
    let (status, _) = recover(&[9u8; 16], &third, &[8u8; 16]);
    assert_eq!(status, 429);
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
        &[app_key.clone()],
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
    assert_eq!(
        Directory::downgrade_to_1005(&config).unwrap(),
        (1006, 1005, 1)
    );
    assert!(!config.team_path(&team).exists());
    assert_eq!(
        Directory::downgrade_to_1005(&config).unwrap(),
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

/// The real `src/connect` client of the Mac (unit M1), unchanged, against a relay with
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
    assert_eq!(recovery.hash().len(), 64);
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
