//! The embedded node (docs/SPEC.md section 30): the edge mode, the public listener and its
//! scope, the failed-auth limiter, the personal team, agent item lists, the in-process
//! release, and the `tailscale-*` headers. Each node listens on free loopback ports and
//! keeps its data in a temporary directory. Synthetic values only.

#[path = "common/relay.rs"]
mod relay;
#[path = "common/upstream.rs"]
mod upstream;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use apassy::node::backend::{
    CatalogItem, NewCloudAgent, NodeAgentId, NodeBackend, NodeConfig, NodeRunId, NodeSecret,
    NodeTeamId, RunStatus, RunningNode, SyncReport, TokenIssue,
};
use apassy_relay::config::{EmbeddedOptions, RelayConfig};
use apassy_relay::embedded::{EmbeddedNode, EmbeddedRelay};
use apassy_relay::error::codes;
use apassy_relay::hostkeys;
use apassy_relay::secret::SecretString;
use apassy_relay::server::Relay;
use relay::{CANARY, CANARY2, call_raw, call_url, release_body, start};
use serde_json::{Value, json};
use upstream::MockUpstream;

const MASTER_KEY: &str = "a synthetic node master key for tests";
/// The Funnel origin of the node. Nothing listens there: the tests call the listeners.
const PUBLIC_URL: &str = "https://node.example.ts.net:8443";
const HOST: &str = "api.example.com";
const USER_REQUEST: &str = "Please check the example account.";

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn node_config(dir: &Path) -> NodeConfig {
    NodeConfig {
        data_dir: dir.join("node"),
        master_key: NodeSecret::new(MASTER_KEY.to_string()),
        public_url: PUBLIC_URL.to_string(),
        public_listen: Some(loopback()),
    }
}

fn catalog_item(uid: &str, env_name: &str) -> CatalogItem {
    CatalogItem {
        uid: uid.to_string(),
        name: format!("Item {env_name}"),
        env_name: env_name.to_string(),
        hosts: vec![HOST.to_string()],
        provider: None,
        environment: "development".to_string(),
        risk: None,
        scope: None,
        reversibility: None,
        allow_broad_host: false,
    }
}

/// A running node with a personal team, one catalog item for `HOST`, and a cloud agent
/// that may use it, as the app makes them.
struct Fixture {
    node: Option<Box<dyn RunningNode>>,
    team: NodeTeamId,
    uid: String,
    agent: NodeAgentId,
    token: String,
    mock: MockUpstream,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn start() -> Self {
        let mock = upstream::start(&[HOST]);
        let dir = tempfile::tempdir().expect("temp dir");
        let backend = EmbeddedRelay {
            upstream: mock.options(),
        };
        let node = backend.start(node_config(dir.path())).expect("start");
        let team = node.create_team("Personal").expect("team");
        let uid = hostkeys::new_uid().expect("uid");
        let report = node
            .sync_items(&team, &[catalog_item(&uid, "EXAMPLE_TOKEN")])
            .expect("sync");
        assert_eq!(
            report,
            SyncReport {
                added: 1,
                ..SyncReport::default()
            }
        );
        let made = node
            .create_agent(
                &team,
                &NewCloudAgent {
                    name: "Grok Bot".to_string(),
                    items: vec![uid.clone()],
                    token: TokenIssue::Now { lifetime_days: 90 },
                },
            )
            .expect("agent");
        assert!(
            made.token
                .as_ref()
                .expect("token now")
                .expose()
                .starts_with("apassy_tagt_")
        );
        Self {
            token: made.token.as_ref().expect("token now").expose().to_string(),
            agent: made.agent_id,
            node: Some(node),
            team,
            uid,
            mock,
            dir,
        }
    }

    fn node(&self) -> &dyn RunningNode {
        self.node.as_deref().expect("running")
    }

    /// `http://` of the public listener (what Funnel forwards to).
    fn public(&self) -> String {
        format!(
            "http://{}",
            self.node().public_addr().expect("public listener")
        )
    }

    /// `http://` of the node listener (every route).
    fn local(&self) -> String {
        format!("http://{}", self.node().node_addr())
    }

    /// The relay item ids that the agent sees, by variable.
    fn access(&self) -> Vec<(String, u64)> {
        let access = tool_ok(&self.public(), &self.token, "apassy_list_access", json!({}));
        access["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| {
                (
                    item["env_name"].as_str().expect("env").to_string(),
                    item["item_id"].as_u64().expect("id"),
                )
            })
            .collect()
    }

    /// The relay id of the one item the agent sees.
    fn item_id(&self) -> u64 {
        let access = self.access();
        assert_eq!(access.len(), 1, "{access:?}");
        access[0].1
    }

    /// The agent asks for a run of `items` over the public listener. Returns its id.
    fn request_run(&self, items: &[u64]) -> NodeRunId {
        let view = tool_ok(
            &self.public(),
            &self.token,
            "apassy_request_run",
            run_args(items),
        );
        assert_eq!(view["status"], "pending", "{view}");
        NodeRunId(view["run_id"].as_u64().expect("run id"))
    }

    /// Waits until the host sees `run` pending.
    fn wait_for(&self, run: NodeRunId) {
        let pending = self
            .node()
            .wait_pending(&self.team, Duration::from_secs(10))
            .expect("pending");
        let found = pending
            .iter()
            .find(|pending| pending.run_id == run)
            .expect("the run waits for the host");
        assert_eq!(found.agent_id, self.agent);
        assert_eq!(found.agent, "Grok Bot");
        assert_eq!(found.items.len(), 1);
        assert_eq!(found.user_request.as_deref(), Some(USER_REQUEST));
    }

    /// A released session of the one item: its key and the placeholder of the value.
    fn session(&self) -> (String, String) {
        let run = self.request_run(&[self.item_id()]);
        self.wait_for(run);
        let state = self
            .node()
            .release(
                &self.team,
                run,
                vec![NodeSecret::new(CANARY.to_string())],
                None,
            )
            .expect("release");
        assert_eq!(state.status, RunStatus::Ready, "{state:?}");
        let view = tool_ok(
            &self.public(),
            &self.token,
            "apassy_run_status",
            json!({"run_id": run.0, "wait_secs": 0}),
        );
        assert_eq!(view["status"], "ready", "{view}");
        let session = &view["session"];
        let base = session["base_urls"][HOST].as_str().expect("base url");
        assert!(base.starts_with(&format!("{PUBLIC_URL}/p/")), "{base}");
        let key = base
            .trim_start_matches(&format!("{PUBLIC_URL}/p/"))
            .split('/')
            .next()
            .expect("key")
            .to_string();
        let placeholder = session["env"]["EXAMPLE_TOKEN"]
            .as_str()
            .expect("placeholder")
            .to_string();
        assert_ne!(placeholder, CANARY);
        (key, placeholder)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            node.stop();
        }
    }
}

fn run_args(items: &[u64]) -> Value {
    json!({
        "items": items,
        "command": ["curl", format!("https://{HOST}/v1/account")],
        "purpose": "check the account",
        "user_request": USER_REQUEST,
    })
}

/// One `tools/call` on `POST /mcp`. Returns the HTTP status and the JSON-RPC reply.
fn mcp(base: &str, token: &str, name: &str, arguments: Value) -> (u16, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}});
    call_url(base, None, "POST", "/mcp", Some(token), Some(&body))
}

/// A tool call that must succeed. Returns its structured result.
fn tool_ok(base: &str, token: &str, name: &str, arguments: Value) -> Value {
    let (status, reply) = mcp(base, token, name, arguments);
    assert_eq!(status, 200, "{name}: {reply}");
    assert_eq!(reply["result"]["isError"], false, "{name}: {reply}");
    reply["result"]["structuredContent"].clone()
}

/// A tool call that must fail. Returns the text of its error.
fn tool_error(base: &str, token: &str, name: &str, arguments: Value) -> String {
    let (status, reply) = mcp(base, token, name, arguments);
    assert_eq!(status, 200, "{name}: {reply}");
    assert_eq!(reply["result"]["isError"], true, "{name}: {reply}");
    reply["result"]["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_string()
}

/// A request with headers. Returns the status, the `Retry-After` header, and the body.
fn call_with(
    base: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
) -> (u16, Option<String>, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"));
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut response = agent
        .run(builder.body(Vec::new()).expect("request"))
        .expect("http call");
    let retry = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, retry, text)
}

/// Every row of the relay audit (`relay.db`) of a node: action and detail.
fn relay_audit(data_dir: &Path) -> Vec<(String, String)> {
    let conn = rusqlite::Connection::open(data_dir.join("relay.db")).expect("open relay.db");
    conn.execute_batch(&format!("PRAGMA key = '{MASTER_KEY}';"))
        .expect("key");
    conn.busy_timeout(Duration::from_secs(10)).expect("busy");
    let mut statement = conn
        .prepare("SELECT action, detail FROM audit ORDER BY id")
        .expect("prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("collect")
}

#[test]
fn edge_off_is_refused_unless_every_listener_is_on_the_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let options = |public: Option<&str>| EmbeddedOptions {
        data_dir: dir.path().join("node"),
        master_key: SecretString::new(MASTER_KEY.to_string()),
        public_url: PUBLIC_URL.to_string(),
        public_listen: public.map(|addr| addr.parse().unwrap()),
    };
    for public in ["0.0.0.0:0", "[::]:0", "192.0.2.10:8443"] {
        let error = RelayConfig::embedded(options(Some(public))).unwrap_err();
        assert_eq!(error.code, codes::INVALID_REQUEST, "{public}");
    }
    // A node listener off the loopback is refused at start, before any file is made.
    let mut config = RelayConfig::embedded(options(Some("127.0.0.1:0"))).unwrap();
    config.listen = "0.0.0.0:0".parse().unwrap();
    let error = Relay::start(config.clone()).err().expect("refused");
    assert_eq!(error.code, codes::INVALID_REQUEST);
    let error = EmbeddedNode::start(config.clone()).err().expect("refused");
    assert_eq!(error.code, codes::INVALID_REQUEST);
    assert!(!config.data_dir.exists());
    // The same through the node backend.
    let error = EmbeddedRelay::default()
        .start(NodeConfig {
            public_listen: Some("0.0.0.0:0".parse().unwrap()),
            ..node_config(dir.path())
        })
        .err()
        .expect("refused");
    assert_eq!(error.code, codes::INVALID_REQUEST);
    assert!(!dir.path().join("node").exists());
}

#[test]
fn the_public_listener_serves_only_mcp_and_the_proxy() {
    let fixture = Fixture::start();
    let public = fixture.public();
    for (method, path, token) in [
        ("GET", "/v1/me", Some(fixture.token.as_str())),
        ("GET", "/healthz", None),
        ("GET", "/", None),
        ("GET", "/mcp", Some(fixture.token.as_str())),
        ("POST", "/v1/runs", Some(fixture.token.as_str())),
        ("GET", "/v1/host/requests", None),
        ("POST", "/v1/teams", None),
    ] {
        let (status, body) = call_url(&public, None, method, path, token, None);
        assert_eq!(status, 404, "{method} {path}: {body}");
        assert_eq!(
            body["error"]["code"], "not_found",
            "{method} {path}: {body}"
        );
    }
    // MCP works there, with no edge header.
    assert_eq!(fixture.access()[0].0, "EXAMPLE_TOKEN");
    // And so does the proxy.
    let (key, placeholder) = fixture.session();
    let (status, _, text) = call_with(
        &public,
        "GET",
        &format!("/p/{key}/{HOST}/v1/account"),
        Some(&placeholder),
        &[],
    );
    assert_eq!(status, 200, "{text}");
    let seen = fixture.mock.requests();
    let last = seen.last().expect("the upstream got the request");
    assert_eq!(
        last.header("authorization"),
        Some(&*format!("Bearer {CANARY}"))
    );
    assert!(!text.contains(CANARY), "{text}");
    // The node listener serves every route without an edge header.
    let local = fixture.local();
    let (status, _) = call_url(&local, None, "GET", "/healthz", None, None);
    assert_eq!(status, 200);
    let (status, me) = call_url(&local, None, "GET", "/v1/me", Some(&fixture.token), None);
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["result"]["kind"], "agent");
}

#[test]
fn tailscale_headers_do_not_reach_the_upstream() {
    let fixture = Fixture::start();
    let (key, placeholder) = fixture.session();
    let (status, _, text) = call_with(
        &fixture.public(),
        "GET",
        &format!("/p/{key}/{HOST}/v1/account"),
        Some(&placeholder),
        &[
            ("Tailscale-User-Login", "someone@example.com"),
            ("tailscale-user-name", "Someone"),
            ("Tailscale-User-Profile-Pic", "https://example.com/p.png"),
            ("TAILSCALE-APP-CAPABILITIES", "{}"),
            ("X-Trace", "kept"),
        ],
    );
    assert_eq!(status, 200, "{text}");
    let seen = fixture.mock.requests();
    let last = seen.last().expect("the upstream got the request");
    assert!(
        last.headers
            .iter()
            .all(|(name, _)| !name.to_ascii_lowercase().starts_with("tailscale-")),
        "{:?}",
        last.headers
    );
    assert_eq!(last.header("x-trace"), Some("kept"));
}

/// Review 0.5.16: on `/mcp` and `/p/` the limiter counts by the source address that
/// Funnel forwards, so a stranger with bad tokens holds only their own address at 429;
/// the owner's agent from another address, the flow of section 31, and requests without
/// an address keep working. Without an address the requests share a count of 600. The
/// other paths of a listener keep the count of 20 for the whole listener.
#[test]
fn the_failed_auth_limiter_counts_agent_routes_by_source() {
    use apassy_relay::server::http::{AGENT_SHARED_FAILURES_MAX, AUTH_FAILURES_MAX};
    let fixture = Fixture::start();
    let public = fixture.public();
    let stranger = [("X-Forwarded-For", "198.51.100.66")];
    let agent = [("X-Forwarded-For", "203.0.113.9")];
    for n in 0..AUTH_FAILURES_MAX {
        let (status, retry, text) =
            call_with(&public, "POST", "/mcp", Some("apassy_tagt_bad"), &stranger);
        assert_eq!(status, 401, "{n}: {text}");
        assert!(retry.is_none());
    }
    // The 21st request of the stranger's address is refused, with a good token too.
    for token in ["apassy_tagt_bad", fixture.token.as_str()] {
        let (status, retry, text) = call_with(&public, "POST", "/mcp", Some(token), &stranger);
        assert_eq!(status, 429, "{text}");
        assert_eq!(retry.as_deref(), Some("60"));
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["error"]["code"], "rate_limited");
    }
    let path = "/p/nothing/api.example.com/";
    let (status, _, _) = call_with(&public, "GET", path, None, &stranger);
    assert_eq!(status, 429);
    // The agent from another address, and a request without one, are not refused.
    for headers in [&agent[..], &[][..]] {
        let (status, _, text) = call_with(&public, "POST", "/mcp", Some(&fixture.token), headers);
        assert!(status != 401 && status != 429, "{status}: {text}");
    }
    let access = tool_ok(&public, &fixture.token, "apassy_list_access", json!({}));
    assert_eq!(access["items"][0]["env_name"], "EXAMPLE_TOKEN", "{access}");
    // The flow is in no count of the listener: its metadata answers the stranger too.
    let (status, _, text) = call_with(
        &public,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        &stranger,
    );
    assert_eq!(status, 200, "{text}");
    // At most one audit row for the listener in ten seconds; it names the count.
    let rows: Vec<_> = relay_audit(&fixture.dir.path().join("node"))
        .into_iter()
        .filter(|(action, _)| action == "rate_limited")
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].1.contains("\"scope\":\"public\""), "{rows:?}");
    assert!(rows[0].1.contains("\"bucket\":\"source\""), "{rows:?}");

    // Without an address, bad tokens share one count of 600: a flood is bounded.
    for n in 0..AGENT_SHARED_FAILURES_MAX {
        let (status, _, text) = call_with(&public, "POST", "/mcp", Some("apassy_tagt_bad"), &[]);
        assert_eq!(status, 401, "{n}: {text}");
    }
    let (status, retry, _) = call_with(&public, "POST", "/mcp", Some(&fixture.token), &[]);
    assert_eq!((status, retry.as_deref()), (429, Some("60")));
    // An agent whose address Funnel forwards keeps its own count.
    let (status, _, text) = call_with(&public, "POST", "/mcp", Some(&fixture.token), &agent);
    assert!(status != 401 && status != 429, "{status}: {text}");

    // The node listener has counts of its own. Bad session keys count on `/p/` only.
    let local = fixture.local();
    for n in 0..AUTH_FAILURES_MAX {
        let path = "/p/apassy_ses_bad/api.example.com/";
        let (status, _, text) = call_with(&local, "GET", path, None, &[]);
        assert_eq!(status, 403, "{n}: {text}");
    }
    let (status, _, text) = call_with(&local, "GET", "/v1/me", Some(&fixture.token), &[]);
    assert_eq!(status, 200, "{text}");
    // Its other paths keep the count of 20 for the whole listener.
    for n in 0..AUTH_FAILURES_MAX {
        let (status, _, text) = call_with(&local, "GET", "/v1/me", Some("apassy_tagt_bad"), &[]);
        assert_eq!(status, 401, "{n}: {text}");
    }
    let (status, retry, _) = call_with(&local, "GET", "/v1/me", Some(&fixture.token), &[]);
    assert_eq!((status, retry.as_deref()), (429, Some("60")));
}

#[test]
fn agent_items_narrow_access_and_the_runs_of_an_agent() {
    let fixture = Fixture::start();
    let node = fixture.node();
    let second = hostkeys::new_uid().unwrap();
    let report = node
        .sync_items(
            &fixture.team,
            &[
                catalog_item(&fixture.uid, "EXAMPLE_TOKEN"),
                catalog_item(&second, "SECOND_TOKEN"),
            ],
        )
        .unwrap();
    assert_eq!(
        report,
        SyncReport {
            added: 1,
            unchanged: 1,
            ..SyncReport::default()
        }
    );
    // The agent's list has the first item only: it sees no other.
    let first = fixture.item_id();
    node.set_agent_items(
        &fixture.team,
        fixture.agent,
        &[fixture.uid.clone(), second.clone()],
    )
    .unwrap();
    let access = fixture.access();
    assert_eq!(access.len(), 2, "{access:?}");
    let other = access
        .iter()
        .find(|(env, _)| env == "SECOND_TOKEN")
        .expect("second")
        .1;
    node.set_agent_items(
        &fixture.team,
        fixture.agent,
        std::slice::from_ref(&fixture.uid),
    )
    .unwrap();
    assert_eq!(fixture.access(), vec![("EXAMPLE_TOKEN".to_string(), first)]);
    // `check_access` refuses an item outside the list, as an unknown one.
    let text = tool_error(
        &fixture.public(),
        &fixture.token,
        "apassy_request_run",
        run_args(&[other]),
    );
    assert!(text.starts_with("not_granted"), "{text}");
    // A run that waits ends when the list leaves its item out.
    let run = fixture.request_run(&[first]);
    fixture.wait_for(run);
    node.set_agent_items(&fixture.team, fixture.agent, std::slice::from_ref(&second))
        .unwrap();
    let state = node.run_state(&fixture.team, run).unwrap();
    assert_eq!(state.status, RunStatus::Denied);
    assert_eq!(state.code.as_deref(), Some(codes::APPROVAL_INVALIDATED));
    // An item that is not in the catalog cannot be listed.
    let error = node
        .set_agent_items(
            &fixture.team,
            fixture.agent,
            &[hostkeys::new_uid().unwrap()],
        )
        .unwrap_err();
    assert_eq!(error.code, codes::INVALID_REQUEST);
    // The sync is idempotent, and an item that leaves the list is archived.
    let again = [catalog_item(&second, "SECOND_TOKEN")];
    let report = node.sync_items(&fixture.team, &again).unwrap();
    assert_eq!(
        report,
        SyncReport {
            archived: 1,
            unchanged: 1,
            ..SyncReport::default()
        }
    );
    let report = node.sync_items(&fixture.team, &again).unwrap();
    assert_eq!(
        report,
        SyncReport {
            unchanged: 1,
            ..SyncReport::default()
        }
    );
    assert_eq!(fixture.access(), vec![("SECOND_TOKEN".to_string(), other)]);
}

#[test]
fn release_values_is_single_use_fails_closed_and_writes_the_audit() {
    let fixture = Fixture::start();
    let node = fixture.node();
    let item = fixture.item_id();
    // No value for the item: denied, release_invalid. The key is used up.
    let run = fixture.request_run(&[item]);
    fixture.wait_for(run);
    let error = node
        .release(&fixture.team, run, Vec::new(), None)
        .unwrap_err();
    assert_eq!(error.code, codes::RELEASE_INVALID);
    let state = node.run_state(&fixture.team, run).unwrap();
    assert_eq!(state.status, RunStatus::Denied);
    assert_eq!(state.code.as_deref(), Some(codes::RELEASE_INVALID));
    let error = node
        .release(
            &fixture.team,
            run,
            vec![NodeSecret::new(CANARY.to_string())],
            None,
        )
        .unwrap_err();
    assert_eq!(error.code, codes::RUN_NOT_PENDING);
    let rows = node.recent_audit(&fixture.team, Some(run), 50).unwrap();
    let denied = rows
        .iter()
        .find(|row| row.action == "run_denied")
        .expect("run_denied");
    assert_eq!(denied.actor, "host:embedded");
    assert!(denied.detail.contains(codes::RELEASE_INVALID), "{denied:?}");
    // A value that breaks the value rules: denied the same way.
    let run = fixture.request_run(&[item]);
    fixture.wait_for(run);
    for bad in ["short", "quote\"in-a-value-0123456789abcdef"] {
        assert!(node.check_value(&NodeSecret::new(bad.to_string())).is_err());
    }
    let error = node
        .release(
            &fixture.team,
            run,
            vec![NodeSecret::new(
                "quote\"in-a-value-0123456789abcdef".to_string(),
            )],
            None,
        )
        .unwrap_err();
    assert_eq!(error.code, codes::RELEASE_INVALID);
    // A good value: ready once, then the run is not pending any more.
    node.check_value(&NodeSecret::new(CANARY2.to_string()))
        .unwrap();
    let run = fixture.request_run(&[item]);
    fixture.wait_for(run);
    let state = node
        .release(
            &fixture.team,
            run,
            vec![NodeSecret::new(CANARY2.to_string())],
            Some("Approved on the Mac."),
        )
        .unwrap();
    assert_eq!(state.status, RunStatus::Ready);
    assert!(state.session_expires_at.is_some());
    assert_eq!(state.note, "Approved on the Mac.");
    let error = node
        .release(
            &fixture.team,
            run,
            vec![NodeSecret::new(CANARY2.to_string())],
            None,
        )
        .unwrap_err();
    assert_eq!(error.code, codes::RUN_NOT_PENDING);
    let rows = node.recent_audit(&fixture.team, Some(run), 50).unwrap();
    let actions: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.actor.as_str(), row.action.as_str()))
        .collect();
    assert!(
        actions.contains(&("host:embedded", "run_released")),
        "{actions:?}"
    );
    assert!(
        actions.contains(&("relay", "session_started")),
        "{actions:?}"
    );
    assert!(rows.iter().all(|row| row.run_id == Some(run)));
    assert!(rows.iter().all(|row| !row.detail.contains(CANARY2)));
    // Newest first, and at most the limit.
    let recent = node.recent_audit(&fixture.team, None, 3).unwrap();
    assert_eq!(recent.len(), 3);
    assert!(recent.windows(2).all(|pair| pair[0].id > pair[1].id));
    assert_eq!(
        node.recent_audit(&fixture.team, None, 0).unwrap_err().code,
        codes::INVALID_REQUEST
    );
    // A denial by the host: the agent sees its reason.
    let run = fixture.request_run(&[item]);
    fixture.wait_for(run);
    let state = node
        .deny(&fixture.team, run, "Not from the cloud today.")
        .unwrap();
    assert_eq!(state.status, RunStatus::Denied);
    assert_eq!(state.code.as_deref(), Some(codes::APPROVAL_DENIED));
    assert_eq!(state.note, "Not from the cloud today.");
    let view = tool_ok(
        &fixture.public(),
        &fixture.token,
        "apassy_run_status",
        json!({"run_id": run.0, "wait_secs": 0}),
    );
    assert_eq!(view["status"], "denied");
    // A revoked agent is 401 at its next request.
    node.revoke_agent(&fixture.team, fixture.agent).unwrap();
    let (status, _) = mcp(
        &fixture.public(),
        &fixture.token,
        "apassy_list_access",
        json!({}),
    );
    assert_eq!(status, 401);
}

#[test]
fn an_item_without_a_sealed_value_fails_closed_on_the_http_release() {
    let relay = start(Default::default());
    let collection = relay.add_collection("cloud", json!({}));
    let me = relay.ok("GET", "/v1/me", &relay.owner_token, None);
    relay.ok(
        "POST",
        "/v1/grants",
        &relay.owner_token,
        Some(&json!({"collection_id": collection, "member_id": me["member_id"]})),
    );
    let agent = relay.ok(
        "POST",
        "/v1/agents",
        &relay.owner_token,
        Some(&json!({"name": "agent"})),
    );
    let token = agent["secret"].as_str().unwrap().to_string();
    // `POST /v1/items` never stores the one-byte marker: only an embedded node writes it.
    let uid = hostkeys::new_uid().unwrap();
    let body = json!({"collection_id": collection, "name": "Marker", "env_name": "MARKER_TOKEN",
        "uid": uid, "sealed": hostkeys::encode_b64(hostkeys::VALUE_ON_HOST),
        "hosts": [HOST], "environment": "development"});
    relay.fails(
        "POST",
        "/v1/items",
        Some(&relay.owner_token),
        Some(&body),
        400,
        "invalid_request",
    );
    relay.edit_vault_live(&format!(
        "INSERT INTO item (collection_id, name, env_name, uid, sealed, provider, hosts, \
         environment, risk, scope, reversibility, created_by, created_at) \
         VALUES ({collection}, 'Marker', 'MARKER_TOKEN', '{uid}', X'00', NULL, '[\"{HOST}\"]', \
         'development', 'high', 'admin', 'irreversible', 1, 100);"
    ));
    let item: u64 = String::from_utf8(
        relay.vault_rows(&format!("SELECT id, '' FROM item WHERE uid = '{uid}'"))[0]
            .0
            .clone(),
    )
    .unwrap()
    .parse()
    .unwrap();
    let mut request = run_args(&[item]);
    request["cwd"] = json!("/work");
    let (status, view) = relay.run(&token, &request);
    assert_eq!(status, 200, "{view}");
    let run = view["result"]["run_id"].as_u64().unwrap();
    // A host that has some key for the uid: the release still fails closed.
    let host = relay.host_request(run);
    let key = hostkeys::new_key().unwrap();
    let body = release_body(
        host["run_key"].as_str().unwrap(),
        run,
        &[(uid.clone(), &key)],
        None,
    );
    relay.fails(
        "POST",
        &format!("/v1/host/requests/{run}/release"),
        Some(&relay.owner_token),
        Some(&body),
        403,
        "release_invalid",
    );
    let status = relay.ok("GET", &format!("/v1/runs/{run}"), &token, None);
    assert_eq!(status["status"], "denied");
    assert_eq!(status["code"], "release_invalid");
}

#[test]
fn a_personal_team_is_made_without_a_code_and_a_restart_opens_it_again() {
    let dir = tempfile::tempdir().unwrap();
    let backend = EmbeddedRelay::default();
    let node = backend.start(node_config(dir.path())).unwrap();
    assert!(!node.has_team(&NodeTeamId("t_abcdefgh23".to_string())));
    let team = node.create_team("Personal").unwrap();
    assert!(node.has_team(&team));
    let uid = hostkeys::new_uid().unwrap();
    node.sync_items(&team, &[catalog_item(&uid, "EXAMPLE_TOKEN")])
        .unwrap();
    let made = node
        .create_agent(
            &team,
            &NewCloudAgent {
                name: "Grok Bot".to_string(),
                items: vec![uid.clone()],
                token: TokenIssue::Now { lifetime_days: 30 },
            },
        )
        .unwrap();
    let token = made.token.as_ref().expect("token now").expose().to_string();
    // One node for each data directory.
    let error = backend
        .start(node_config(dir.path()))
        .err()
        .expect("refused");
    assert_eq!(error.code, codes::CONFLICT);
    // No run waits: the wait ends at its timeout.
    assert!(
        node.wait_pending(&team, Duration::from_millis(300))
            .unwrap()
            .is_empty()
    );
    node.stop();
    // The team, its catalog, and the agent come back with the next start.
    let node = backend.start(node_config(dir.path())).unwrap();
    assert!(node.has_team(&team));
    let public = format!("http://{}", node.public_addr().unwrap());
    let access = tool_ok(&public, &token, "apassy_list_access", json!({}));
    assert_eq!(access["items"][0]["env_name"], "EXAMPLE_TOKEN", "{access}");
    assert_eq!(
        node.sync_items(&team, &[catalog_item(&uid, "EXAMPLE_TOKEN")])
            .unwrap(),
        SyncReport {
            unchanged: 1,
            ..SyncReport::default()
        }
    );
    // The team was made by no code, and nothing secret is in its directory.
    let audit = relay_audit(&dir.path().join("node"));
    assert!(
        audit
            .iter()
            .any(|(action, detail)| action == "team_created" && detail.contains("personal")),
        "{audit:?}"
    );
    node.stop();
}

/// An agent of the MCP authorization flow has no live token until its client connects
/// (`TokenIssue::Later`), yet it takes one of the 20 places of the personal team: a node
/// counts every agent that is not revoked.
#[test]
fn agents_without_a_token_count_toward_the_agent_limit_of_a_node() {
    let dir = tempfile::tempdir().unwrap();
    let node = EmbeddedRelay::default()
        .start(node_config(dir.path()))
        .unwrap();
    let team = node.create_team("Personal").unwrap();
    let later = |name: String| NewCloudAgent {
        name,
        items: Vec::new(),
        token: TokenIssue::Later,
    };
    let mut first = None;
    for index in 0..20 {
        let made = node
            .create_agent(&team, &later(format!("Remote {index}")))
            .unwrap_or_else(|error| panic!("agent {index}: {error}"));
        assert!(made.token.is_none(), "no token for the flow");
        first.get_or_insert(made.agent_id);
    }
    for token in [TokenIssue::Later, TokenIssue::Now { lifetime_days: 30 }] {
        let refused = node
            .create_agent(
                &team,
                &NewCloudAgent {
                    name: "One too many".to_string(),
                    items: Vec::new(),
                    token,
                },
            )
            .expect_err("the 21st agent");
        assert_eq!(refused.code, codes::TEAM_LIMIT, "{refused}");
    }
    // A revocation frees a place.
    node.revoke_agent(&team, first.expect("an agent")).unwrap();
    node.create_agent(&team, &later("Remote again".to_string()))
        .unwrap();
    node.stop();
}

#[test]
fn a_node_goes_back_to_schema_6_and_its_listed_agents_are_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let config = RelayConfig::embedded(EmbeddedOptions {
        data_dir: dir.path().join("node"),
        master_key: SecretString::new(MASTER_KEY.to_string()),
        public_url: PUBLIC_URL.to_string(),
        public_listen: Some(loopback()),
    })
    .unwrap();
    let node = EmbeddedNode::start(config.clone()).unwrap();
    let team = node.create_team("Personal").unwrap();
    let uid = hostkeys::new_uid().unwrap();
    node.sync_items(&team, &[catalog_item(&uid, "EXAMPLE_TOKEN")])
        .unwrap();
    let made = node
        .create_agent(
            &team,
            &NewCloudAgent {
                name: "Grok Bot".to_string(),
                items: vec![uid],
                token: TokenIssue::Now { lifetime_days: 30 },
            },
        )
        .unwrap();
    let token = made.token.as_ref().expect("token now").expose().to_string();
    Box::new(node).stop();
    let teams = apassy_relay::server::rollback::downgrade_to_6(&config).unwrap();
    let answer = serde_json::to_value(&teams).unwrap();
    assert_eq!(
        answer,
        json!([{"team": team.0, "from": 7, "to": 6, "agents_revoked": 1}])
    );
    // The image of schema 7 moves the file up again; the agent stays revoked.
    let node = EmbeddedNode::start(config).unwrap();
    let public = node.running().public_listener_url().unwrap();
    let (status, _) = mcp(&public, &token, "apassy_list_access", json!({}));
    assert_eq!(status, 401);
    Box::new(node).stop();
}

/// The connect page is public: anyone with its address reads it. A node that the app
/// starts (`EmbeddedRelay`) says "your Mac" there, never the name of the computer; only
/// the owner's own prompts name the Mac (security review finding 5).
#[test]
fn the_connect_page_of_a_node_of_the_app_says_your_mac_not_the_computer_name() {
    let dir = tempfile::tempdir().unwrap();
    let node = EmbeddedRelay::default()
        .start(node_config(dir.path()))
        .unwrap();
    node.create_team("Personal").unwrap();
    let public = format!("http://{}", node.public_addr().unwrap());
    let (status, reply) = call_url(
        &public,
        None,
        "POST",
        "/oauth/register",
        None,
        Some(&json!({"redirect_uris": ["https://client.example/cb"], "client_name": "Grok Bot"})),
    );
    assert_eq!(status, 201, "{reply}");
    let client = reply["client_id"].as_str().expect("client id").to_string();
    let authorize = format!(
        "/oauth/authorize?response_type=code&client_id={client}\
         &redirect_uri=https%3A%2F%2Fclient.example%2Fcb\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );
    let (status, text) = call_raw(&public, None, "GET", &authorize, None, &[], None);
    assert_eq!(status, 303, "{text}");
    let pending = node.pending_connects().unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let wait = format!("/oauth/wait/{}", pending[0].id);
    let (status, page) = call_raw(&public, None, "GET", &wait, None, &[], None);
    assert_eq!(status, 200, "{page}");
    assert!(
        page.contains("<h1>Grok Bot wants to connect to your Mac</h1>"),
        "{page}"
    );
    node.stop();
}

/// The agents of a Mac run as its user, and `<app data>/node` belongs to that user: an
/// embedded node serves no operator socket, so no local program can suspend or delete
/// the personal team or make a team code through it (review 0.5.16). A socket that an
/// older version left is removed at the start.
#[test]
fn an_embedded_node_serves_no_operator_socket() {
    use apassy_relay::server::operator::{self, Command};
    let dir = tempfile::tempdir().unwrap();
    let backend = EmbeddedRelay::default();
    let node = backend.start(node_config(dir.path())).unwrap();
    let team = node.create_team("Personal").unwrap();
    let socket = dir.path().join("node").join("admin.sock");
    assert!(!socket.exists(), "no operator socket");
    let delete: Command =
        serde_json::from_value(json!({"command": "delete", "team": team.0.as_str()}))
            .expect("command");
    let suspend: Command =
        serde_json::from_value(json!({"command": "suspend", "team": team.0.as_str()}))
            .expect("command");
    for command in [
        Command::TeamCode { hours: 1 },
        delete,
        suspend,
        Command::Teams,
    ] {
        assert!(
            operator::send(&socket, &command).is_err(),
            "{command:?} is unavailable"
        );
    }
    assert!(node.has_team(&team), "the team stays");
    node.stop();

    // A socket file of an older version: the next start removes it.
    drop(std::os::unix::net::UnixListener::bind(&socket).expect("stale socket"));
    assert!(socket.exists());
    let node = backend.start(node_config(dir.path())).unwrap();
    assert!(!socket.exists(), "the stale socket is gone");
    assert!(operator::send(&socket, &Command::TeamCode { hours: 1 }).is_err());
    assert!(node.has_team(&team));
    node.stop();
}
