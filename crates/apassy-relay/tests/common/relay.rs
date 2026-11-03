//! A relay in process for tests (docs/SPEC.md, "Tests").
//!
//! `start` makes a team vault in a temp dir, starts the relay on a free port on
//! 127.0.0.1, and gives back a handle. `call` sends a request with the edge header.
//! The extra methods below the spec API (`ok`, `setup`, `Team`) are shortcuts for
//! the server tests.
//!
//! The relay holds only sealed item values, so `add_item` seals the value here and
//! keeps the item key in the handle: the handle plays the part of the owner's host.
//! `release` answers a pending run like the host does, with the keys of its items.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apassy_relay::config::{EdgeMode, RelayConfig, UpstreamOptions};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::{self, Key32};
use apassy_relay::ids::TeamId;
use apassy_relay::secret::{SecretString, parse_token};
use apassy_relay::server::{Relay, RunningRelay};
use apassy_relay::session::SessionSource;
use serde_json::{Value, json};

pub const EDGE_SECRET: &str = "edge-secret-for-tests-0123456789abcdef0123456789";
pub const VAULT_KEY: &str = "a synthetic vault passphrase for tests";
/// A synthetic item value.
pub const CANARY: &str = "sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF";
/// A second synthetic item value.
pub const CANARY2: &str = "ghp_SyntheticCanaryTwoValue0123456789abcdefABCDEF";

pub struct TestRelay {
    pub url: String,
    pub edge_secret: String,
    pub owner_token: String,
    /// The team of `owner_token`.
    pub team_id: TeamId,
    pub dir: tempfile::TempDir,
    pub config: RelayConfig,
    running: Option<RunningRelay>,
    /// The item keys, by uid: what the owner's host keeps.
    book: Mutex<HashMap<String, Key32>>,
}

/// An item as the CLI makes it: a uid, a sealed text, and the key that stays on the host.
pub struct SealedItem {
    pub uid: String,
    pub sealed: String,
    pub key: Key32,
}

/// Seals a value like `apassy-team item add` does.
pub fn seal(value: &str) -> SealedItem {
    let uid = hostkeys::new_uid().expect("uid");
    let key = hostkeys::new_key().expect("key");
    let sealed = hostkeys::seal_item(&key, &uid, value.as_bytes()).expect("seal");
    SealedItem {
        uid,
        sealed: hostkeys::encode_b64(&sealed),
        key,
    }
}

/// The body of `POST /v1/items` for a sealed value. `extra` adds or replaces fields.
pub fn item_request(collection: u64, env_name: &str, sealed: &SealedItem, extra: Value) -> Value {
    let mut body = json!({
        "collection_id": collection,
        "name": format!("Item {env_name}"),
        "env_name": env_name,
        "uid": sealed.uid,
        "sealed": sealed.sealed,
    });
    for (key, v) in extra.as_object().expect("object") {
        body[key] = v.clone();
    }
    body
}

/// The release body that the host sends for `run_key`: the keys of `keys`, sealed to it.
pub fn release_body(
    run_key: &str,
    run_id: u64,
    keys: &[(String, &Key32)],
    reason: Option<&str>,
) -> Value {
    let key_texts: Vec<_> = keys
        .iter()
        .map(|(uid, key)| json!({"uid": uid, "key": hostkeys::encode_key(key).as_str()}))
        .collect();
    let plain = json!({"run_id": run_id, "keys": key_texts}).to_string();
    let run_key: [u8; 32] = hostkeys::decode_array(run_key).expect("run key");
    let release = hostkeys::seal_release(&run_key, run_id, plain.as_bytes()).expect("seal");
    let mut body = json!({
        "host_key": hostkeys::encode_b64(&release.host_key),
        "nonce": hostkeys::encode_b64(&release.nonce),
        "sealed_keys": hostkeys::encode_b64(&release.sealed_keys),
    });
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    body
}

/// The team id in a token.
pub fn team_of(token: &str) -> TeamId {
    parse_token(token)
        .and_then(|parsed| parsed.team)
        .expect("a token with a team")
}

/// Opens the file of a team with its key, read from the directory.
pub fn open_team_file(config: &RelayConfig, team: &TeamId) -> rusqlite::Connection {
    let (path, key) = Relay::team_vault(config, team).expect("team vault");
    let conn = rusqlite::Connection::open(path).expect("open vault");
    conn.execute_batch(&format!("PRAGMA key = '{}';", key.expose()))
        .expect("key");
    conn.busy_timeout(Duration::from_secs(10)).expect("busy");
    conn
}

/// A free port on 127.0.0.1: bind to port 0 and drop the listener.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// Starts the relay. The port of a test config is picked before the relay binds it, so
/// another test can take it in between: then the relay starts on a new free port, and
/// the config (listen address and public URL) follows it.
pub fn start_on_free_port(cfg: &mut RelayConfig) -> RunningRelay {
    for _ in 0..5 {
        match Relay::start(cfg.clone()) {
            Ok(running) => return running,
            Err(error) if error.message.starts_with("Cannot listen") => {
                let port = free_port();
                cfg.listen = format!("127.0.0.1:{port}").parse().expect("addr");
                cfg.public_url = format!("http://127.0.0.1:{port}");
            }
            Err(error) => panic!("start: {error:?}"),
        }
    }
    panic!("the relay found no free port in 5 tries")
}

/// The default config of a test relay.
pub fn test_config(dir: &std::path::Path, upstream: UpstreamOptions) -> RelayConfig {
    let port = free_port();
    RelayConfig {
        data_dir: dir.join("data"),
        listen: format!("127.0.0.1:{port}").parse().expect("addr"),
        public_listen: None,
        tailnet_listen: None,
        tailnet_agents: false,
        public_url: format!("http://127.0.0.1:{port}"),
        sign_in_origins: Vec::new(),
        edge: EdgeMode::Required(SecretString::new(EDGE_SECRET.to_string())),
        master_key: SecretString::new(VAULT_KEY.to_string()),
        session_ttl_secs: 60,
        approval_timeout_secs: 5,
        upstream,
        request_read_timeout: std::time::Duration::from_secs(30),
        request_handle_timeout: std::time::Duration::from_secs(90),
        limits: Default::default(),
        backup_dir: dir.join("backups"),
        push: None,
        team_vaults: true,
        questions_to_approvers: false,
        connect_teams_per_day: 200,
        connect_teams_max: 1000,
        connect_sync_bytes: 0,
        auth_limiter: false,
        oauth: None,
    }
}

pub fn start(upstream: UpstreamOptions) -> TestRelay {
    start_with(|_| {}, upstream)
}

pub fn start_with(config: impl FnOnce(&mut RelayConfig), upstream: UpstreamOptions) -> TestRelay {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = test_config(dir.path(), upstream);
    config(&mut cfg);
    let owner = Relay::init(&cfg, "Test Team", "owner").expect("init");
    let running = start_on_free_port(&mut cfg);
    TestRelay {
        url: running.url(),
        edge_secret: cfg
            .edge
            .secret()
            .map(|secret| secret.expose().to_string())
            .unwrap_or_default(),
        team_id: team_of(owner.expose()),
        owner_token: owner.expose().to_string(),
        dir,
        config: cfg,
        running: Some(running),
        book: Mutex::new(HashMap::new()),
    }
}

/// Sends a request with the edge header. `body` is JSON.
pub fn call_url(
    base: &str,
    edge: Option<&str>,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (u16, Value) {
    let (status, text) = call_raw(base, edge, method, path, token, &[], body);
    let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, value)
}

/// Like `call_url`, with extra headers, and the body as text.
pub fn call_raw(
    base: &str,
    edge: Option<&str>,
    method: &str,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"));
    if let Some(edge) = edge {
        builder = builder.header("X-Apassy-Edge", edge);
    }
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let bytes = match body {
        Some(body) => {
            builder = builder.header("Content-Type", "application/json");
            serde_json::to_vec(body).expect("json")
        }
        None => Vec::new(),
    };
    let request = builder.body(bytes).expect("request");
    let mut response = agent.run(request).expect("http call");
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, text)
}

impl TestRelay {
    /// A request with the edge header. Returns the status and the JSON body.
    pub fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        call_url(
            &self.url,
            Some(&self.edge_secret),
            method,
            path,
            token,
            body,
        )
    }

    /// A request with extra headers and the raw body text back.
    pub fn call_with_headers(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> (u16, String) {
        call_raw(
            &self.url,
            Some(&self.edge_secret),
            method,
            path,
            token,
            headers,
            body,
        )
    }

    /// A request without the edge header.
    pub fn call_no_edge(&self, method: &str, path: &str) -> (u16, Value) {
        call_url(&self.url, None, method, path, None, None)
    }

    /// A call that must answer 200 with `ok: true`. Returns `result`.
    pub fn ok(&self, method: &str, path: &str, token: &str, body: Option<&Value>) -> Value {
        let (status, value) = self.call(method, path, Some(token), body);
        assert_eq!(status, 200, "{method} {path}: {value}");
        assert_eq!(value["ok"], true, "{method} {path}: {value}");
        value["result"].clone()
    }

    /// A call that must fail with this HTTP status and error code.
    pub fn fails(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        status: u16,
        code: &str,
    ) {
        let (got, value) = self.call(method, path, token, body);
        assert_eq!(got, status, "{method} {path}: {value}");
        assert_eq!(value["ok"], false, "{method} {path}: {value}");
        assert_eq!(value["error"]["code"], code, "{method} {path}: {value}");
    }

    /// The live sessions as the proxy reads them.
    pub fn sessions(&self) -> Arc<dyn SessionSource> {
        self.running.as_ref().expect("running").sessions()
    }

    /// The live hub, for checks of per-team request counters.
    pub fn hub(&self) -> Arc<apassy_relay::server::hub::Hub> {
        self.running.as_ref().expect("running").hub()
    }

    /// Stops the relay. The temp dir goes with the handle.
    pub fn stop(mut self) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
    }

    /// Stops the relay and hands over the config and the temp dir, so a test can
    /// read the vault file or start a relay on it again.
    pub fn stop_keep(mut self) -> (RelayConfig, tempfile::TempDir) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
        let dir = std::mem::replace(&mut self.dir, tempfile::tempdir().expect("temp dir"));
        (self.config.clone(), dir)
    }

    /// Stops the relay and starts it again on the same vault and the same port.
    pub fn restart(mut self) -> TestRelay {
        if let Some(running) = self.running.take() {
            running.stop();
        }
        let running = start_on_free_port(&mut self.config);
        self.url = running.url();
        self.running = Some(running);
        self
    }

    /// Stops the relay, runs SQL on the vault file (to set a time in the past, which
    /// a test cannot wait for), and starts the relay again.
    pub fn edit_vault(&mut self, sql: &str) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
        let conn = open_team_file(&self.config, &self.team_id);
        conn.execute_batch(sql).expect("edit");
        drop(conn);
        let running = start_on_free_port(&mut self.config);
        self.url = running.url();
        self.running = Some(running);
    }

    /// Stops the relay, runs `edit` on its stopped data directory (to rename a team or
    /// change a file), and starts it again. Access tokens end with the restart.
    pub fn edit_offline(&mut self, edit: impl FnOnce(&RelayConfig)) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
        edit(&self.config);
        let running = start_on_free_port(&mut self.config);
        self.url = running.url();
        self.running = Some(running);
    }

    /// Runs SQL on the vault file while the relay runs (to set a time in the past on
    /// a pending run, which a test cannot wait for). The relay keeps its state, in
    /// particular the run keys.
    pub fn edit_vault_live(&self, sql: &str) {
        let conn = open_team_file(&self.config, &self.team_id);
        conn.execute_batch(sql).expect("edit");
    }

    /// Every cell of every table of the vault, as bytes (text and blobs). Reads the
    /// file with the key while the relay runs.
    pub fn vault_cells(&self) -> Vec<Vec<u8>> {
        use rusqlite::types::ValueRef;
        let conn = open_team_file(&self.config, &self.team_id);
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .expect("tables")
            .query_map([], |row| row.get(0))
            .expect("rows")
            .collect::<Result<_, _>>()
            .expect("names");
        let mut cells = Vec::new();
        for table in tables {
            let mut statement = conn
                .prepare(&format!("SELECT * FROM \"{table}\""))
                .expect("select");
            let columns = statement.column_count();
            let mut rows = statement.query([]).expect("query");
            while let Some(row) = rows.next().expect("row") {
                for i in 0..columns {
                    match row.get_ref(i).expect("cell") {
                        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => cells.push(bytes.to_vec()),
                        ValueRef::Integer(n) => cells.push(n.to_string().into_bytes()),
                        _ => {}
                    }
                }
            }
        }
        cells
    }

    /// Two columns of a query on the vault, as bytes. Reads the file with the key.
    pub fn vault_rows(&self, sql: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        use rusqlite::types::ValueRef;
        let conn = open_team_file(&self.config, &self.team_id);
        let mut statement = conn.prepare(sql).expect("prepare");
        let rows = statement
            .query_map([], |row| {
                let cell = |i: usize| -> Vec<u8> {
                    match row.get_ref(i).expect("cell") {
                        ValueRef::Text(b) | ValueRef::Blob(b) => b.to_vec(),
                        ValueRef::Integer(n) => n.to_string().into_bytes(),
                        _ => Vec::new(),
                    }
                };
                Ok((cell(0), cell(1)))
            })
            .expect("rows");
        rows.collect::<Result<_, _>>().expect("collect")
    }

    /// Signs in a device and returns its in-memory access token.
    pub fn sign_in(&self, team: &TeamId, key: &DeviceKey) -> String {
        let public_key = key.public_key_b64();
        let challenge = self.ok(
            "POST",
            "/v1/auth/challenge",
            "",
            Some(&json!({"team_id": team, "public_key": public_key})),
        );
        let nonce = challenge["nonce"].as_str().expect("nonce");
        let signature = key
            .sign(&device::sign_in_message(
                &self.config.public_url,
                team,
                &public_key,
                nonce,
            ))
            .expect("sign");
        let granted = self.ok(
            "POST",
            "/v1/auth/token",
            "",
            Some(&json!({"team_id": team, "public_key": public_key,
                "nonce": nonce, "signature": hostkeys::encode_b64(&signature)})),
        );
        granted["token"].as_str().expect("access token").to_string()
    }

    /// Adds an invite, confirms the join, and signs in its fresh device.
    /// Returns the member id, the access token, and the key for a later sign-in.
    pub fn join_device(&self, role: &str, name: &str) -> (u64, String, DeviceKey) {
        let key = DeviceKey::generate().expect("device key");
        let invite = self.ok(
            "POST",
            "/v1/invites",
            &self.owner_token,
            Some(&json!({"role": role})),
        );
        let code = invite["secret"].as_str().expect("code");
        let joined = self.ok(
            "POST",
            "/v1/join",
            "",
            Some(
                &json!({"code": code, "name": name, "device_name": "Test device",
                "public_key": key.public_key_b64()}),
            ),
        );
        assert_eq!(
            joined["safety"],
            device::safety_words(&self.team_id, code, &key.public_key())
        );
        let confirmed = self.ok(
            "POST",
            &format!("/v1/joins/{}/confirm", joined["id"]),
            &self.owner_token,
            Some(&json!({"safety": joined["safety"]})),
        );
        let token = self.sign_in(&self.team_id, &key);
        (
            confirmed["member_id"].as_u64().expect("member id"),
            token,
            key,
        )
    }

    /// Adds a confirmed member and returns its id and device access token.
    pub fn join_member(&self, role: &str, name: &str) -> (u64, String) {
        let (id, token, _) = self.join_device(role, name);
        (id, token)
    }

    /// A collection of the owner. Returns its id.
    pub fn add_collection(&self, name: &str, policy: Value) -> u64 {
        let created = self.ok(
            "POST",
            "/v1/collections",
            &self.owner_token,
            Some(&json!({"name": name, "policy": policy})),
        );
        created["id"].as_u64().expect("id")
    }

    /// An item of the owner, sealed here. Returns its id. The key stays in the handle.
    pub fn add_item(&self, collection: u64, env_name: &str, value: &str, extra: Value) -> u64 {
        let sealed = seal(value);
        let body = item_request(collection, env_name, &sealed, extra);
        let created = self.ok("POST", "/v1/items", &self.owner_token, Some(&body));
        self.keep_key(sealed);
        created["id"].as_u64().expect("id")
    }

    /// Keeps the key of a sealed item, as the owner's host would.
    pub fn keep_key(&self, sealed: SealedItem) {
        self.book
            .lock()
            .expect("book")
            .insert(sealed.uid, sealed.key);
    }

    /// The item keys in the handle, as text (base64url).
    pub fn item_key_texts(&self) -> Vec<String> {
        self.book
            .lock()
            .expect("book")
            .values()
            .map(|key| hostkeys::encode_key(key).to_string())
            .collect()
    }

    /// The key of one item in the handle, as text (base64url).
    pub fn item_key_text(&self, uid: &str) -> String {
        let book = self.book.lock().expect("book");
        hostkeys::encode_key(book.get(uid).expect("a key for this uid")).to_string()
    }

    /// The pending runs that wait for the host (`GET /v1/host/requests`, no wait).
    pub fn host_requests(&self) -> Vec<Value> {
        let result = self.ok("GET", "/v1/host/requests", &self.owner_token, None);
        result.as_array().expect("list").clone()
    }

    /// The host request of one run. Panics when the host does not see it.
    pub fn host_request(&self, run_id: u64) -> Value {
        self.host_requests()
            .into_iter()
            .find(|r| r["run_id"] == run_id)
            .unwrap_or_else(|| panic!("run {run_id} is not listed for the host"))
    }

    /// The release body for a run, from the keys in the handle.
    pub fn release_for(&self, request: &Value, reason: Option<&str>) -> Value {
        let book = self.book.lock().expect("book");
        let keys: Vec<(String, &Key32)> = request["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| {
                let uid = item["uid"].as_str().expect("uid").to_string();
                let key = book.get(&uid).expect("a key for this item");
                (uid, key)
            })
            .collect();
        release_body(
            request["run_key"].as_str().expect("run key"),
            request["run_id"].as_u64().expect("run id"),
            &keys,
            reason,
        )
    }

    /// Plays the host: releases a pending run with the keys of its items. Returns the
    /// raw status and body.
    pub fn release(&self, run_id: u64) -> (u16, Value) {
        let body = self.release_for(&self.host_request(run_id), None);
        self.call(
            "POST",
            &format!("/v1/host/requests/{run_id}/release"),
            Some(&self.owner_token),
            Some(&body),
        )
    }

    /// Releases a pending run, and expects `ready`.
    pub fn release_ok(&self, run_id: u64) -> Value {
        let (status, value) = self.release(run_id);
        assert_eq!(status, 200, "release {run_id}: {value}");
        assert_eq!(
            value["result"]["status"], "ready",
            "release {run_id}: {value}"
        );
        value["result"].clone()
    }

    /// An agent asks for a run, and the host releases it. Returns the `RunView` the
    /// agent gets when it asks again: `ready`, with the session.
    pub fn run_released(&self, agent_token: &str, body: &Value) -> Value {
        let (status, view) = self.run(agent_token, body);
        assert_eq!(status, 200, "{view}");
        let run_id = view["result"]["run_id"].as_u64().expect("run id");
        self.release_ok(run_id);
        self.ok("GET", &format!("/v1/runs/{run_id}"), agent_token, None)
    }

    /// One collection "payments" with a Stripe item of `environment`, one member
    /// "alice" with a grant, and one agent of alice.
    pub fn setup(&self, environment: &str) -> Team {
        let collection = self.add_collection("payments", json!({}));
        let item = self.add_item(
            collection,
            "STRIPE_API_KEY",
            CANARY,
            json!({"provider": "stripe", "environment": environment}),
        );
        let (member_id, member_token) = self.join_member("member", "alice");
        let grant = self.ok(
            "POST",
            "/v1/grants",
            &self.owner_token,
            Some(&json!({"collection_id": collection, "member_id": member_id})),
        );
        let agent = self.ok(
            "POST",
            "/v1/agents",
            &member_token,
            Some(&json!({"name": "alice-agent"})),
        );
        Team {
            collection,
            item,
            member_id,
            member_token,
            grant: grant["id"].as_u64().expect("id"),
            agent_id: agent["id"].as_u64().expect("id"),
            agent_token: agent["secret"].as_str().expect("token").to_string(),
        }
    }

    /// A run request of an agent. Returns the raw status and body.
    pub fn run(&self, agent_token: &str, body: &Value) -> (u16, Value) {
        self.call("POST", "/v1/runs", Some(agent_token), Some(body))
    }

    /// Points the handle at another team of the same relay: the owner token and the
    /// team id that the shortcuts use. Returns the previous owner token.
    pub fn switch_team(&mut self, owner_token: &str) -> String {
        self.team_id = team_of(owner_token);
        std::mem::replace(&mut self.owner_token, owner_token.to_string())
    }

    /// The audit of the relay (`relay.db`): actor, action, and detail of each row.
    pub fn relay_audit(&self) -> Vec<(String, String, String)> {
        let conn = rusqlite::Connection::open(self.config.directory_path()).expect("open relay.db");
        conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
            .expect("key");
        conn.busy_timeout(Duration::from_secs(10)).expect("busy");
        let mut statement = conn
            .prepare("SELECT actor, action, detail FROM audit ORDER BY id")
            .expect("prepare");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("rows")
            .collect::<Result<_, _>>()
            .expect("collect")
    }

    /// Sends a command to the operator socket of the running relay.
    pub fn operator(
        &self,
        command: apassy_relay::server::operator::Command,
    ) -> Result<Value, apassy_relay::error::RelayError> {
        apassy_relay::server::operator::send(&self.config.admin_socket_path(), &command)
    }

    /// A new team through a team code of the operator. Returns its owner token.
    pub fn new_team(&self, name: &str, owner: &str) -> String {
        self.new_team_device(name, owner).0
    }

    /// A new team and its owner's device key, for another sign-in after a restart.
    pub fn new_team_device(&self, name: &str, owner: &str) -> (String, DeviceKey) {
        let key = DeviceKey::generate().expect("device key");
        let code = self
            .operator(apassy_relay::server::operator::Command::TeamCode { hours: 1 })
            .expect("team code");
        let made = self.ok(
            "POST",
            "/v1/teams",
            "",
            Some(&json!({"code": code["code"], "team": name, "owner": owner,
                "device_name": "Owner device", "public_key": key.public_key_b64()})),
        );
        let team: TeamId = serde_json::from_value(made["team_id"].clone()).expect("team id");
        (self.sign_in(&team, &key), key)
    }
}

/// The ids and tokens of `setup`.
pub struct Team {
    pub collection: u64,
    pub item: u64,
    pub member_id: u64,
    pub member_token: String,
    pub grant: u64,
    pub agent_id: u64,
    pub agent_token: String,
}

impl Team {
    /// A run request for the Stripe item.
    pub fn request(&self, command: &[&str], user_request: Option<&str>) -> Value {
        let mut body = json!({
            "items": [self.item],
            "command": command,
            "purpose": "check the account",
            "cwd": "/work",
        });
        if let Some(text) = user_request {
            body["user_request"] = json!(text);
        }
        body
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
    }
}
