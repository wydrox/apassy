//! A relay in process for tests (docs/SPEC.md, "Tests").
//!
//! `start` makes a team vault in a temp dir, starts the relay on a free port on
//! 127.0.0.1, and gives back a handle. `call` sends a request with the edge header.
//! The extra methods below the spec API (`ok`, `setup`, `Team`) are shortcuts for
//! the server tests.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use apassy_relay::config::{RelayConfig, UpstreamOptions};
use apassy_relay::secret::SecretString;
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
    pub dir: tempfile::TempDir,
    pub config: RelayConfig,
    running: Option<RunningRelay>,
}

/// A free port on 127.0.0.1: bind to port 0 and drop the listener.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// The default config of a test relay.
pub fn test_config(dir: &std::path::Path, upstream: UpstreamOptions) -> RelayConfig {
    let port = free_port();
    RelayConfig {
        data_dir: dir.join("data"),
        listen: format!("127.0.0.1:{port}").parse().expect("addr"),
        public_url: format!("http://127.0.0.1:{port}"),
        edge_secret: SecretString::new(EDGE_SECRET.to_string()),
        vault_key: SecretString::new(VAULT_KEY.to_string()),
        session_ttl_secs: 60,
        approval_timeout_secs: 5,
        upstream,
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
    let running = Relay::start(cfg.clone()).expect("start");
    TestRelay {
        url: running.url(),
        edge_secret: cfg.edge_secret.expose().to_string(),
        owner_token: owner.expose().to_string(),
        dir,
        config: cfg,
        running: Some(running),
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
        self.running = Some(Relay::start(self.config.clone()).expect("restart"));
        self
    }

    /// Stops the relay, runs SQL on the vault file (to set a time in the past, which
    /// a test cannot wait for), and starts the relay again.
    pub fn edit_vault(&mut self, sql: &str) {
        if let Some(running) = self.running.take() {
            running.stop();
        }
        let conn = rusqlite::Connection::open(self.config.vault_path()).expect("open vault");
        conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
            .expect("key");
        conn.execute_batch(sql).expect("edit");
        drop(conn);
        self.running = Some(Relay::start(self.config.clone()).expect("restart"));
    }

    /// Adds an invite for `role`, joins as `name`, and returns the member id and token.
    pub fn join_member(&self, role: &str, name: &str) -> (u64, String) {
        let invite = self.ok(
            "POST",
            "/v1/invites",
            &self.owner_token,
            Some(&json!({"role": role})),
        );
        let code = invite["secret"].as_str().expect("code").to_string();
        let joined = self.ok(
            "POST",
            "/v1/join",
            "",
            Some(&json!({"code": code, "name": name})),
        );
        (
            joined["id"].as_u64().expect("id"),
            joined["secret"].as_str().expect("token").to_string(),
        )
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

    /// An item of the owner. Returns its id.
    pub fn add_item(&self, collection: u64, env_name: &str, value: &str, extra: Value) -> u64 {
        let mut body = json!({
            "collection_id": collection,
            "name": format!("Item {env_name}"),
            "env_name": env_name,
            "value": value,
        });
        for (key, v) in extra.as_object().expect("object") {
            body[key] = v.clone();
        }
        let created = self.ok("POST", "/v1/items", &self.owner_token, Some(&body));
        created["id"].as_u64().expect("id")
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
