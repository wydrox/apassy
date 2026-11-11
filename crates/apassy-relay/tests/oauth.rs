//! The MCP authorization flow of an embedded node (docs/SPEC.md section 31): metadata,
//! registration, the connect request and its page, the code with PKCE, refresh
//! rotation, family revocation, a second request of a client, the limits and the clients
//! that were never allowed, the per-client limit of bad codes and refresh tokens,
//! `WWW-Authenticate` on `/mcp`, the hosted relay without OAuth, and the
//! directory 1003 ↔ 1004. Each node listens on free loopback ports and keeps its data in
//! a temporary directory. Synthetic names and values only.

#[path = "common/relay.rs"]
mod relay;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use apassy::node::backend::{
    CatalogItem, ConnectDecision, NewCloudAgent, NodeAgentId, NodeTeamId, PendingConnect,
    RunningNode, TokenIssue,
};
use apassy_relay::config::{EmbeddedOptions, HOST_WORD, OAuthConfig, RelayConfig, UpstreamOptions};
use apassy_relay::embedded::EmbeddedNode;
use apassy_relay::hostkeys;
use apassy_relay::secret::SecretString;
use apassy_relay::server::directory::Directory;
use apassy_relay::server::oauth::{decode_form, percent_encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MASTER_KEY: &str = "a synthetic node master key for oauth tests";
/// The Funnel origin of the node. Nothing listens there: the tests call the listeners.
const PUBLIC_URL: &str = "https://node.example.ts.net:8443";
const MAC: &str = "Test Mac";
const REDIRECT: &str = "https://client.example/oauth/callback";
/// RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const OTHER_VERIFIER: &str = "a-different-verifier-of-forty-three-chars-xx";
const PAGE_HEADERS: [(&str, &str); 5] = [
    (
        "content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'",
    ),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
];

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn oauth_config() -> OAuthConfig {
    OAuthConfig::new(MAC)
}

/// An answer: status, headers (lowercase names), and body text.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    text: String,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::String(self.text.clone()))
    }
}

/// One request. `body`: content type and bytes.
fn call(
    base: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, Vec<u8>)>,
) -> Answer {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let bytes = match body {
        Some((kind, bytes)) => {
            builder = builder.header("Content-Type", kind);
            bytes
        }
        None => Vec::new(),
    };
    let mut response = agent
        .run(builder.body(bytes).expect("request"))
        .expect("http call");
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    Answer {
        status: response.status().as_u16(),
        headers,
        text: response.body_mut().read_to_string().unwrap_or_default(),
    }
}

fn get(base: &str, path: &str) -> Answer {
    call(base, "GET", path, &[], None)
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

fn post_form(base: &str, path: &str, pairs: &[(&str, &str)]) -> Answer {
    call(
        base,
        "POST",
        path,
        &[],
        Some(("application/x-www-form-urlencoded", form(pairs))),
    )
}

fn post_json(base: &str, path: &str, body: &Value) -> Answer {
    call(
        base,
        "POST",
        path,
        &[],
        Some(("application/json", serde_json::to_vec(body).unwrap())),
    )
}

/// `tools/call` of `apassy_list_access` on `POST /mcp` with a bearer token.
fn mcp_list(base: &str, token: &str) -> Answer {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "apassy_list_access", "arguments": {}}});
    let bearer = format!("Bearer {token}");
    call(
        base,
        "POST",
        "/mcp",
        &[("Authorization", bearer.as_str())],
        Some(("application/json", serde_json::to_vec(&body).unwrap())),
    )
}

/// The query of a `Location`, decoded.
fn query_of(location: &str) -> HashMap<String, String> {
    let query = location.split_once('?').map_or("", |(_, query)| query);
    decode_form(query).expect("a query")
}

fn sha256(text: &str) -> Vec<u8> {
    Sha256::digest(text.as_bytes()).to_vec()
}

fn unix_now() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    i64::try_from(secs).expect("in range")
}

/// Stores a client that the owner allowed (a redeemed request with its team), registered
/// at `created_at`, straight in the directory of a running node.
fn insert_allowed_client(conn: &rusqlite::Connection, client_id: &str, created_at: i64) {
    conn.execute(
        "INSERT INTO oauth_client (client_id, client_name, redirect_uris, created_at) \
         VALUES (?1, 'Allowed', ?2, ?3)",
        rusqlite::params![client_id, format!("[\"{REDIRECT}\"]"), created_at],
    )
    .expect("client");
    conn.execute(
        "INSERT INTO connect_request (id, client_id, redirect_uri, code_challenge, match_code, \
         status, created_at, expires_at, decided_at, team_id, agent_id) \
         VALUES (?1, ?2, ?3, ?4, 'K7Q-4MD', 'redeemed', ?5, ?5, ?5, 't_synthetic1', 1)",
        rusqlite::params![
            format!("r_{client_id}"),
            client_id,
            REDIRECT,
            CHALLENGE,
            created_at
        ],
    )
    .expect("request");
}

/// The stored clients with this id (0 or 1).
fn clients_with(conn: &rusqlite::Connection, client_id: &str) -> i64 {
    conn.query_row(
        "SELECT count(*) FROM oauth_client WHERE client_id = ?1",
        [client_id],
        |row| row.get(0),
    )
    .expect("count")
}

/// A running node with a personal team, as the app makes them.
struct Node {
    node: Option<EmbeddedNode>,
    team: NodeTeamId,
    config: RelayConfig,
    _dir: tempfile::TempDir,
}

/// The tokens of a finished flow.
struct Connected {
    client_id: String,
    agent: NodeAgentId,
    access: String,
    refresh: String,
}

impl Node {
    fn start() -> Self {
        Self::start_with(oauth_config())
    }

    fn start_with(oauth: OAuthConfig) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = RelayConfig::embedded(EmbeddedOptions {
            data_dir: dir.path().join("node"),
            master_key: SecretString::new(MASTER_KEY.to_string()),
            public_url: PUBLIC_URL.to_string(),
            public_listen: Some(loopback()),
            node_origin: None,
            tailnet_listen: None,
            tailnet_agents: false,
            push_gateway: None,
        })
        .expect("config");
        config.oauth = Some(oauth);
        let node = EmbeddedNode::start(config.clone()).expect("start");
        let team = node.create_team("Personal").expect("team");
        Self {
            node: Some(node),
            team,
            config,
            _dir: dir,
        }
    }

    fn node(&self) -> &EmbeddedNode {
        self.node.as_ref().expect("running")
    }

    fn stop(&mut self) {
        if let Some(node) = self.node.take() {
            Box::new(node).stop();
        }
    }

    /// `http://` of the public listener (what Funnel forwards to).
    fn public(&self) -> String {
        format!("http://{}", self.node().public_addr().expect("public"))
    }

    /// `http://` of the node listener.
    fn local(&self) -> String {
        format!("http://{}", self.node().node_addr())
    }

    fn register(&self, name: Option<&str>, redirect: &str) -> String {
        let mut body = json!({"redirect_uris": [redirect], "token_endpoint_auth_method": "none"});
        if let Some(name) = name {
            body["client_name"] = json!(name);
        }
        let answer = post_json(&self.public(), "/oauth/register", &body);
        assert_eq!(answer.status, 201, "{}", answer.text);
        let reply = answer.json();
        assert_eq!(reply["token_endpoint_auth_method"], "none");
        assert!(reply.get("client_secret").is_none(), "{reply}");
        reply["client_id"].as_str().expect("client id").to_string()
    }

    /// `GET /oauth/authorize`. Returns the answer.
    fn authorize_raw(&self, client_id: &str, extra: &[(&str, &str)]) -> Answer {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "state-123"),
            ("scope", "apassy"),
        ];
        for &(name, value) in extra {
            pairs.retain(|(key, _)| *key != name);
            pairs.push((name, value));
        }
        let query = String::from_utf8(form(&pairs)).unwrap();
        get(&self.public(), &format!("/oauth/authorize?{query}"))
    }

    /// A connect request. Returns the path of its page.
    fn authorize(&self, client_id: &str) -> String {
        let answer = self.authorize_raw(client_id, &[]);
        assert_eq!(answer.status, 303, "{}", answer.text);
        let location = answer.header("location").expect("location").to_string();
        assert!(location.starts_with("/oauth/wait/"), "{location}");
        location
    }

    /// The one request that waits.
    fn pending_one(&self) -> PendingConnect {
        let pending = self.node().pending_connects().expect("pending");
        assert_eq!(pending.len(), 1, "{pending:?}");
        pending.into_iter().next().unwrap()
    }

    /// An agent with no token and no item, as the app makes it for a connect.
    fn later_agent(&self, name: &str) -> NodeAgentId {
        let made = self
            .node()
            .create_agent(
                &self.team,
                &NewCloudAgent {
                    name: name.to_string(),
                    items: Vec::new(),
                    token: TokenIssue::Later,
                },
            )
            .expect("agent");
        assert!(made.token.is_none());
        made.agent_id
    }

    /// Allows the waiting request for a new agent. Returns the agent.
    fn allow(&self, request: &PendingConnect) -> NodeAgentId {
        let agent = self.later_agent("Grok Bot");
        self.node()
            .decide_connect(
                &request.id,
                ConnectDecision::Allow {
                    team: self.team.clone(),
                    agent,
                },
            )
            .expect("allow");
        agent
    }

    /// The page after the answer: 303 to the client with the code. Returns the code.
    fn code_from(&self, wait: &str) -> String {
        let answer = get(&self.public(), wait);
        assert_eq!(answer.status, 303, "{}", answer.text);
        let location = answer.header("location").expect("location");
        assert!(location.starts_with(&format!("{REDIRECT}?")), "{location}");
        let query = query_of(location);
        assert_eq!(query["state"], "state-123");
        assert_eq!(query["iss"], PUBLIC_URL);
        query["code"].clone()
    }

    fn token_code(&self, client_id: &str, code: &str, verifier: &str) -> Answer {
        let resource = format!("{PUBLIC_URL}/mcp");
        post_form(
            &self.public(),
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("client_id", client_id),
                ("code_verifier", verifier),
                ("resource", resource.as_str()),
            ],
        )
    }

    fn token_refresh(&self, client_id: &str, refresh: &str) -> Answer {
        post_form(
            &self.public(),
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", client_id),
            ],
        )
    }

    /// Register, authorize, allow, code, token. Returns the tokens.
    fn connect(&self, name: &str) -> Connected {
        let client_id = self.register(Some(name), REDIRECT);
        let wait = self.authorize(&client_id);
        let request = self.pending_one();
        let agent = self.allow(&request);
        let code = self.code_from(&wait);
        let answer = self.token_code(&client_id, &code, VERIFIER);
        assert_eq!(answer.status, 200, "{}", answer.text);
        let reply = answer.json();
        Connected {
            client_id,
            agent,
            access: reply["access_token"].as_str().expect("access").to_string(),
            refresh: reply["refresh_token"]
                .as_str()
                .expect("refresh")
                .to_string(),
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The directory of a node, keyed.
fn directory(config: &RelayConfig) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(config.directory_path()).expect("open relay.db");
    conn.execute_batch(&format!("PRAGMA key = '{MASTER_KEY}';"))
        .expect("key");
    conn.busy_timeout(Duration::from_secs(10)).expect("busy");
    conn
}

fn assert_page_headers(answer: &Answer) {
    for (name, value) in PAGE_HEADERS {
        assert_eq!(answer.header(name), Some(value), "{name}");
    }
    assert!(answer.header("set-cookie").is_none());
}

fn assert_no_active_part(html: &str) {
    let lower = html.to_ascii_lowercase();
    for word in [
        "<script", "<form", "<button", "<input", "<iframe", "<a ", "<img",
    ] {
        assert!(!lower.contains(word), "{word} in {html}");
    }
}

#[test]
fn metadata_documents_name_this_node_on_both_paths() {
    let node = Node::start();
    for base in [node.public(), node.local()] {
        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let answer = get(&base, path);
            assert_eq!(answer.status, 200, "{path}: {}", answer.text);
            assert_eq!(answer.header("cache-control"), Some("no-store"));
            assert_eq!(
                answer.json(),
                json!({
                    "resource": format!("{PUBLIC_URL}/mcp"),
                    "authorization_servers": [PUBLIC_URL],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["apassy"],
                    "resource_name": "Apassy",
                })
            );
        }
        for path in [
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        ] {
            let answer = get(&base, path);
            assert_eq!(answer.status, 200, "{path}: {}", answer.text);
            let meta = answer.json();
            assert_eq!(meta["issuer"], PUBLIC_URL);
            assert_eq!(
                meta["authorization_endpoint"],
                format!("{PUBLIC_URL}/oauth/authorize")
            );
            assert_eq!(meta["token_endpoint"], format!("{PUBLIC_URL}/oauth/token"));
            assert_eq!(
                meta["registration_endpoint"],
                format!("{PUBLIC_URL}/oauth/register")
            );
            assert_eq!(
                meta["revocation_endpoint"],
                format!("{PUBLIC_URL}/oauth/revoke")
            );
            assert_eq!(meta["response_types_supported"], json!(["code"]));
            assert_eq!(
                meta["grant_types_supported"],
                json!(["authorization_code", "refresh_token"])
            );
            assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
            assert_eq!(
                meta["token_endpoint_auth_methods_supported"],
                json!(["none"])
            );
        }
    }
    // Another method or path near them is not there.
    assert_eq!(
        call(
            &node.public(),
            "POST",
            "/.well-known/oauth-authorization-server",
            &[],
            None
        )
        .status,
        404
    );
    assert_eq!(get(&node.public(), "/oauth/token").status, 404);
    assert_eq!(get(&node.public(), "/.well-known/other").status, 404);
}

#[test]
fn a_401_of_mcp_points_at_the_resource_metadata() {
    let node = Node::start();
    let expected = format!(
        "Bearer resource_metadata=\"{PUBLIC_URL}/.well-known/oauth-protected-resource/mcp\", scope=\"apassy\""
    );
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let answer = call(
        &node.public(),
        "POST",
        "/mcp",
        &[],
        Some(("application/json", serde_json::to_vec(&body).unwrap())),
    );
    assert_eq!(answer.status, 401, "{}", answer.text);
    assert_eq!(answer.header("www-authenticate"), Some(expected.as_str()));
    assert_eq!(answer.json()["error"]["code"], "unauthenticated");
    let bad = format!("apassy_tagt_{}_{}", node.team.0, "ab".repeat(32));
    let answer = mcp_list(&node.public(), &bad);
    assert_eq!(answer.status, 401);
    assert_eq!(
        answer.header("www-authenticate"),
        Some(format!("{expected}, error=\"invalid_token\"").as_str())
    );
    // Other 401s carry no challenge.
    let bearer = format!("Bearer {bad}");
    let answer = call(
        &node.local(),
        "GET",
        "/v1/me",
        &[("Authorization", bearer.as_str())],
        None,
    );
    assert_eq!(answer.status, 401);
    assert!(answer.header("www-authenticate").is_none());
}

#[test]
fn register_authorize_wait_allow_token_and_mcp() {
    let node = Node::start();
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    assert!(client_id.starts_with("c_"));
    let wait = node.authorize(&client_id);
    // The page while it waits: the client, the Mac, and the code of the app.
    let request = node.pending_one();
    assert_eq!(request.client_id, client_id);
    assert_eq!(request.client_name.as_deref(), Some("Grok Bot"));
    assert_eq!(request.code.len(), 7);
    assert!(request.expires_at >= request.created_at + 299);
    // Where the code goes back, for the owner's prompts (review 0.5.16).
    assert_eq!(request.redirect_host, "client.example");
    let page = get(&node.public(), &wait);
    assert_eq!(page.status, 200, "{}", page.text);
    assert_page_headers(&page);
    assert_eq!(page.header("refresh"), Some("3"));
    assert_eq!(
        page.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_no_active_part(&page.text);
    assert!(
        page.text
            .contains(&format!("Grok Bot wants to connect to {MAC}"))
    );
    assert!(page.text.contains(&request.code));
    assert!(
        page.text
            .contains(&format!("Approve on your {HOST_WORD} or iPhone."))
    );
    // Allowed: the next refresh sends the browser back with the code, once.
    let agent = node.allow(&request);
    assert!(node.node().pending_connects().unwrap().is_empty());
    let code = node.code_from(&wait);
    let again = get(&node.public(), &wait);
    assert_eq!(again.status, 200);
    assert!(again.text.contains("Connected"), "{}", again.text);
    assert!(again.header("refresh").is_none());
    // The token.
    let answer = node.token_code(&client_id, &code, VERIFIER);
    assert_eq!(answer.status, 200, "{}", answer.text);
    assert_eq!(answer.header("cache-control"), Some("no-store"));
    assert_eq!(answer.header("pragma"), Some("no-cache"));
    let reply = answer.json();
    assert_eq!(reply["token_type"], "Bearer");
    assert_eq!(reply["expires_in"], 86_400);
    assert_eq!(reply["scope"], "apassy");
    let access = reply["access_token"].as_str().unwrap().to_string();
    let refresh = reply["refresh_token"].as_str().unwrap().to_string();
    assert!(access.starts_with(&format!("apassy_tagt_{}_", node.team.0)));
    // `/mcp` takes it as the agent's token: no credential until the owner chooses one.
    let answer = mcp_list(&node.public(), &access);
    assert_eq!(answer.status, 200, "{}", answer.text);
    let result = answer.json();
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(result["result"]["structuredContent"]["items"], json!([]));
    // The node reports the connection.
    let access_view = node.node().agent_access(&node.team, agent).unwrap();
    assert!(!access_view.revoked);
    assert!(access_view.token_expires_at.is_some());
    assert_eq!(access_view.client_id.as_deref(), Some(client_id.as_str()));
    assert!(access_view.connected_at.is_some());
    assert!(access_view.refresh_expires_at.is_some());
    // Codes and refresh tokens are stored as hashes only.
    let conn = directory(&node.config);
    let code_hash: Vec<u8> = conn
        .query_row(
            "SELECT code_hash FROM connect_request WHERE client_id = ?1",
            [&client_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(code_hash, sha256(&code));
    let stored: i64 = conn
        .query_row(
            "SELECT count(*) FROM oauth_refresh WHERE token_hash = ?1",
            [sha256(&refresh)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, 1);
    for (table, columns) in [
        (
            "connect_request",
            "id, client_id, redirect_uri, coalesce(state, ''), code_challenge, match_code, status",
        ),
        ("oauth_refresh", "family, client_id, team_id"),
        (
            "oauth_client",
            "client_id, coalesce(client_name, ''), redirect_uris",
        ),
        ("audit", "actor, action, detail"),
    ] {
        let mut statement = conn
            .prepare(&format!("SELECT {columns} FROM {table}"))
            .unwrap();
        let count = statement.column_count();
        let texts: Vec<String> = statement
            .query_map([], |row| {
                (0..count)
                    .map(|i| row.get::<_, String>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
            .flat_map(Result::unwrap)
            .collect();
        for text in texts {
            for secret in [&code, &refresh, &access] {
                assert!(!text.contains(secret.as_str()), "{table} holds a secret");
            }
        }
    }
}

#[test]
fn a_wrong_verifier_uses_up_the_code_and_revokes_the_family() {
    let node = Node::start();
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    let wait = node.authorize(&client_id);
    let agent = node.allow(&node.pending_one());
    let code = node.code_from(&wait);
    let answer = node.token_code(&client_id, &code, OTHER_VERIFIER);
    assert_eq!(answer.status, 400, "{}", answer.text);
    assert_eq!(answer.json()["error"], "invalid_grant");
    // The right verifier comes too late: the code is used up.
    let answer = node.token_code(&client_id, &code, VERIFIER);
    assert_eq!(answer.status, 400);
    assert_eq!(answer.json()["error"], "invalid_grant");
    let access = node.node().agent_access(&node.team, agent).unwrap();
    assert_eq!(access.token_expires_at, None);
    assert_eq!(access.client_id, None);
    // Another client cannot redeem a code either.
    let other = node.register(Some("Other"), REDIRECT);
    let answer = node.token_code(&other, "not-a-code", VERIFIER);
    assert_eq!(answer.json()["error"], "invalid_grant");
}

#[test]
fn a_reused_code_revokes_the_family_and_its_access_token() {
    let node = Node::start();
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    let wait = node.authorize(&client_id);
    node.allow(&node.pending_one());
    let code = node.code_from(&wait);
    let first = node.token_code(&client_id, &code, VERIFIER);
    assert_eq!(first.status, 200, "{}", first.text);
    let access = first.json()["access_token"].as_str().unwrap().to_string();
    let refresh = first.json()["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(mcp_list(&node.public(), &access).status, 200);
    let second = node.token_code(&client_id, &code, VERIFIER);
    assert_eq!(second.status, 400, "{}", second.text);
    assert_eq!(second.json()["error"], "invalid_grant");
    // Everything of the first use is gone.
    let answer = mcp_list(&node.public(), &access);
    assert_eq!(answer.status, 401);
    assert!(
        answer
            .header("www-authenticate")
            .is_some_and(|value| value.contains("error=\"invalid_token\""))
    );
    let answer = node.token_refresh(&client_id, &refresh);
    assert_eq!(answer.json()["error"], "invalid_grant");
}

#[test]
fn refresh_rotates_and_a_reused_refresh_token_revokes_the_family() {
    let node = Node::start();
    let connected = node.connect("Grok Bot");
    let answer = node.token_refresh(&connected.client_id, &connected.refresh);
    assert_eq!(answer.status, 200, "{}", answer.text);
    let reply = answer.json();
    let access = reply["access_token"].as_str().unwrap().to_string();
    let refresh = reply["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(access, connected.access);
    assert_ne!(refresh, connected.refresh);
    // One live access token for each agent.
    assert_eq!(mcp_list(&node.public(), &connected.access).status, 401);
    assert_eq!(mcp_list(&node.public(), &access).status, 200);
    // Another client cannot use the refresh token, and the try revokes the family.
    let thief = node.register(Some("Thief"), REDIRECT);
    let answer = node.token_refresh(&thief, &refresh);
    assert_eq!(answer.json()["error"], "invalid_grant");
    assert_eq!(mcp_list(&node.public(), &access).status, 401);
    // A fresh connection, then the reuse of a rotated token.
    let node = Node::start();
    let connected = node.connect("Grok Bot");
    let rotated = node.token_refresh(&connected.client_id, &connected.refresh);
    assert_eq!(rotated.status, 200);
    let access = rotated.json()["access_token"].as_str().unwrap().to_string();
    let refresh = rotated.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let reused = node.token_refresh(&connected.client_id, &connected.refresh);
    assert_eq!(reused.status, 400, "{}", reused.text);
    assert_eq!(reused.json()["error"], "invalid_grant");
    assert_eq!(mcp_list(&node.public(), &access).status, 401);
    let answer = node.token_refresh(&connected.client_id, &refresh);
    assert_eq!(answer.json()["error"], "invalid_grant");
    let view = node
        .node()
        .agent_access(&node.team, connected.agent)
        .unwrap();
    assert_eq!((view.token_expires_at, view.client_id), (None, None));
}

#[test]
fn an_access_token_ends_and_the_refresh_gives_a_new_one() {
    // Three seconds, so the new token below cannot end before its first use.
    let node = Node::start_with(OAuthConfig {
        access_token_secs: 3,
        ..oauth_config()
    });
    let connected = node.connect("Grok Bot");
    assert_eq!(
        node.token_code(&connected.client_id, "x", VERIFIER).json()["error"],
        "invalid_grant"
    );
    std::thread::sleep(Duration::from_millis(4100));
    let answer = mcp_list(&node.public(), &connected.access);
    assert_eq!(answer.status, 401);
    assert_eq!(answer.json()["error"]["code"], "token_expired");
    let answer = node.token_refresh(&connected.client_id, &connected.refresh);
    assert_eq!(answer.status, 200, "{}", answer.text);
    assert_eq!(answer.json()["expires_in"], 3);
    let access = answer.json()["access_token"].as_str().unwrap().to_string();
    assert_eq!(mcp_list(&node.public(), &access).status, 200);
}

#[test]
fn denied_and_ended_requests_show_their_page() {
    let node = Node::start();
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    let wait = node.authorize(&client_id);
    let request = node.pending_one();
    node.node()
        .decide_connect(&request.id, ConnectDecision::Deny)
        .unwrap();
    let page = get(&node.public(), &wait);
    assert_eq!(page.status, 200);
    assert_page_headers(&page);
    assert!(page.header("refresh").is_none());
    assert!(page.header("location").is_none());
    assert!(
        page.text.contains("You denied the connection."),
        "{}",
        page.text
    );
    let error = node
        .node()
        .decide_connect(&request.id, ConnectDecision::Deny)
        .unwrap_err();
    assert_eq!(error.code, "connect_not_pending");
    // An unknown page.
    let page = get(&node.public(), &format!("/oauth/wait/{}", "0".repeat(32)));
    assert_eq!(page.status, 404);
    assert!(page.text.contains("The request ended."));
    assert_page_headers(&page);
    // A request that nobody answers ends.
    let node = Node::start_with(OAuthConfig {
        connect_secs: 2,
        ..oauth_config()
    });
    let client_id = node.register(None, REDIRECT);
    let wait = node.authorize(&client_id);
    let request = node.pending_one();
    assert_eq!(request.client_name, None);
    let page = get(&node.public(), &wait);
    assert!(
        page.text
            .contains(&format!("An MCP client wants to connect to {MAC}"))
    );
    std::thread::sleep(Duration::from_millis(3100));
    let page = get(&node.public(), &wait);
    assert_eq!(page.status, 200);
    assert!(page.text.contains("The request ended."), "{}", page.text);
    assert!(page.header("refresh").is_none());
    assert!(node.node().pending_connects().unwrap().is_empty());
    let agent = node.later_agent("Late");
    let error = node
        .node()
        .decide_connect(
            &request.id,
            ConnectDecision::Allow {
                team: node.team.clone(),
                agent,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "connect_not_pending");
}

#[test]
fn authorize_checks_the_client_the_redirect_pkce_and_the_resource() {
    let node = Node::start();
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    // A bad client or redirect URI: a page, never a redirect.
    for extra in [
        vec![("client_id", "c_unknown")],
        vec![("redirect_uri", "https://evil.example/cb")],
    ] {
        let answer = node.authorize_raw(&client_id, &extra);
        assert_eq!(answer.status, 400, "{extra:?}");
        assert!(answer.header("location").is_none());
        assert!(answer.text.contains("This connection link is not valid."));
        assert_page_headers(&answer);
    }
    let long_state = "s".repeat(600);
    let errors = [
        (
            vec![("response_type", "token")],
            "unsupported_response_type",
        ),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
        (vec![("code_challenge", "short")], "invalid_request"),
        (
            vec![("resource", "https://other.example/mcp")],
            "invalid_target",
        ),
        (vec![("state", long_state.as_str())], "invalid_request"),
    ];
    // Any other error of a client that the owner never allowed: a page, never a
    // redirect. Anyone can register a client with any https redirect URI, so a redirect
    // would make a link of this Mac an open redirect (security review finding 3).
    let stranger = node.register(Some("Stranger"), "https://evil.example/cb");
    for (extra, _) in &errors {
        for client in [&client_id, &stranger] {
            let mut extra = extra.clone();
            if *client == stranger {
                extra.push(("redirect_uri", "https://evil.example/cb"));
            }
            let answer = node.authorize_raw(client, &extra);
            assert_eq!(answer.status, 400, "{extra:?}");
            assert!(answer.header("location").is_none(), "{extra:?}");
            assert!(answer.text.contains("This connection link is not valid."));
            assert!(!answer.text.contains("evil.example"));
            assert_page_headers(&answer);
        }
    }
    assert!(node.node().pending_connects().unwrap().is_empty());
    // A client that the owner allowed gets its errors back at its redirect URI.
    let allowed = node.connect("Allowed");
    for (extra, error) in &errors {
        let answer = node.authorize_raw(&allowed.client_id, extra);
        assert_eq!(answer.status, 303, "{extra:?}");
        let location = answer.header("location").unwrap();
        assert!(location.starts_with(&format!("{REDIRECT}?")), "{location}");
        let query = query_of(location);
        assert_eq!(query["error"], *error, "{extra:?}");
    }
    assert!(node.node().pending_connects().unwrap().is_empty());
    // A loopback redirect URI matches with any port (RFC 8252).
    let local = node.register(Some("CLI"), "http://127.0.0.1/callback");
    let answer = node.authorize_raw(
        &local,
        &[("redirect_uri", "http://127.0.0.1:53682/callback")],
    );
    assert_eq!(answer.status, 303, "{}", answer.text);
    assert!(
        answer
            .header("location")
            .unwrap()
            .starts_with("/oauth/wait/")
    );
    // The owner's prompts say where the code goes back: the loopback here (review 0.5.16).
    assert_eq!(node.pending_one().redirect_host, "127.0.0.1");
    // The token endpoint refuses another resource.
    let answer = post_form(
        &node.public(),
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", "x"),
            ("client_id", client_id.as_str()),
            ("resource", "https://other.example/mcp"),
        ],
    );
    assert_eq!(answer.json()["error"], "invalid_target");
    let answer = post_form(
        &node.public(),
        "/oauth/token",
        &[
            ("grant_type", "password"),
            ("client_id", client_id.as_str()),
        ],
    );
    assert_eq!(answer.json()["error"], "unsupported_grant_type");
}

#[test]
fn registration_is_checked_and_limited() {
    let node = Node::start();
    for body in [
        json!({"redirect_uris": ["http://client.example/cb"]}),
        json!({"redirect_uris": []}),
        json!({"redirect_uris": [format!("https://client.example/{}", "a".repeat(600))]}),
        json!({"redirect_uris": ["https://client.example/cb#x"]}),
        json!({"client_name": "x"}),
    ] {
        let answer = post_json(&node.public(), "/oauth/register", &body);
        assert_eq!(answer.status, 400, "{body}");
        assert_eq!(answer.json()["error"], "invalid_redirect_uri", "{body}");
    }
    let answer = post_json(&node.public(), "/oauth/register", &json!([1]));
    assert_eq!(answer.json()["error"], "invalid_client_metadata");
    // The name is cleaned and cut.
    let answer = post_json(
        &node.public(),
        "/oauth/register",
        &json!({"redirect_uris": [REDIRECT], "client_name": format!(" Grok\u{202E}  Bot{}", "x".repeat(80))}),
    );
    assert_eq!(answer.status, 201);
    let name = answer.json()["client_name"].as_str().unwrap().to_string();
    assert!(name.starts_with("Grok Bot"));
    assert!(name.len() <= 64);
    // Clients that the owner never allowed do not count in the window: a stranger's
    // registrations never stop a real client (security review finding 2).
    for _ in 1..15 {
        node.register(Some("Grok Bot"), REDIRECT);
    }
    // Ten clients registered in ten minutes and allowed: the window is full.
    let conn = directory(&node.config);
    for i in 0..10 {
        insert_allowed_client(&conn, &format!("c_allowed_{i}"), unix_now());
    }
    let answer = post_json(
        &node.public(),
        "/oauth/register",
        &json!({"redirect_uris": [REDIRECT]}),
    );
    assert_eq!(answer.status, 429, "{}", answer.text);
    assert_eq!(answer.header("retry-after"), Some("600"));
    let stored: i64 = conn
        .query_row("SELECT count(*) FROM oauth_client", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, 25);
}

/// A stranger can register any number of clients, and they never fill the table: at
/// `MAX_CLIENTS` the oldest client that was never allowed goes (one with no waiting
/// request first, then one with its request). Only clients that the owner allowed fill it
/// (security review finding 2).
#[test]
fn a_full_client_table_drops_the_oldest_client_that_was_never_allowed() {
    let node = Node::start();
    let conn = directory(&node.config);
    // 98 allowed clients, registered a day ago (outside the window of 10 minutes).
    for i in 0..98 {
        insert_allowed_client(&conn, &format!("c_allowed_{i:03}"), unix_now() - 86_400);
    }
    let waiting = node.register(Some("Waiting"), REDIRECT);
    let wait = node.authorize(&waiting);
    let idle = node.register(Some("Idle"), REDIRECT);
    // 100 stored: the next one drops "Idle", the oldest that has no waiting request.
    let third = node.register(Some("Third"), REDIRECT);
    assert_eq!(clients_with(&conn, &idle), 0);
    assert_eq!(clients_with(&conn, &waiting), 1);
    assert_eq!(clients_with(&conn, &third), 1);
    assert_eq!(node.pending_one().client_id, waiting);
    // One more allowed client: two never-allowed clients go, "Third" and then "Waiting"
    // with its request.
    insert_allowed_client(&conn, "c_allowed_098", unix_now() - 86_400);
    let fourth = node.register(Some("Fourth"), REDIRECT);
    assert_eq!(clients_with(&conn, &third), 0);
    assert_eq!(clients_with(&conn, &waiting), 0);
    assert_eq!(clients_with(&conn, &fourth), 1);
    assert!(node.node().pending_connects().unwrap().is_empty());
    let page = get(&node.public(), &wait);
    assert!(page.text.contains("The request ended."), "{}", page.text);
    let stored: i64 = conn
        .query_row("SELECT count(*) FROM oauth_client", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, 100);
    let evicted: i64 = conn
        .query_row(
            "SELECT count(*) FROM audit WHERE action = 'oauth_client_evicted'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(evicted, 3);
    // 100 allowed clients: the table is full for real.
    insert_allowed_client(&conn, "c_allowed_099", unix_now() - 86_400);
    let answer = post_json(
        &node.public(),
        "/oauth/register",
        &json!({"redirect_uris": [REDIRECT]}),
    );
    assert_eq!(answer.status, 429, "{}", answer.text);
    assert_eq!(answer.header("retry-after"), Some("600"));
}

/// A client that the owner never allowed goes an hour after its registration, with its
/// requests, and an authorize does not renew it. A client that was allowed stays.
#[test]
fn a_client_that_was_never_allowed_is_pruned_after_an_hour() {
    let node = Node::start();
    let allowed = node.connect("Allowed");
    let client = node.register(Some("Grok Bot"), REDIRECT);
    let wait = node.authorize(&client);
    let conn = directory(&node.config);
    let used: Option<i64> = conn
        .query_row(
            "SELECT used_at FROM oauth_client WHERE client_id = ?1",
            [&client],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(used, None, "an authorize renews no client");
    // Both registered an hour ago.
    for id in [&client, &allowed.client_id] {
        conn.execute(
            "UPDATE oauth_client SET created_at = created_at - 3601 WHERE client_id = ?1",
            [id],
        )
        .unwrap();
    }
    // The next registration prunes.
    node.register(Some("Later"), REDIRECT);
    assert_eq!(clients_with(&conn, &client), 0);
    assert_eq!(clients_with(&conn, &allowed.client_id), 1);
    assert!(node.node().pending_connects().unwrap().is_empty());
    let page = get(&node.public(), &wait);
    assert!(page.text.contains("The request ended."), "{}", page.text);
    let answer = node.authorize_raw(&client, &[]);
    assert_eq!(answer.status, 400);
    assert!(answer.text.contains("This connection link is not valid."));
    // The allowed client still refreshes.
    let answer = node.token_refresh(&allowed.client_id, &allowed.refresh);
    assert_eq!(answer.status, 200, "{}", answer.text);
}

#[test]
fn open_connect_requests_are_limited_per_node() {
    let node = Node::start();
    let clients: Vec<String> = (0..4)
        .map(|i| node.register(Some(&format!("Client {i}")), REDIRECT))
        .collect();
    let first = node.authorize(&clients[0]);
    // The same request again (a reload): its page.
    assert_eq!(node.authorize(&clients[0]), first);
    node.authorize(&clients[1]);
    node.authorize(&clients[2]);
    let answer = node.authorize_raw(&clients[3], &[]);
    assert_eq!(answer.status, 429);
    assert!(answer.text.contains("Too many connection requests wait."));
    assert!(
        answer.text.contains(&format!(
            "Deny requests on your {HOST_WORD} that you did not start, then connect again."
        )),
        "{}",
        answer.text
    );
    assert_page_headers(&answer);
    assert_eq!(node.node().pending_connects().unwrap().len(), 3);
    // A client that waits replaces its own request, also at the limit of the node.
    let answer = node.authorize_raw(&clients[0], &[("state", "other")]);
    assert_eq!(answer.status, 303, "{}", answer.text);
    assert_ne!(answer.header("location"), Some(first.as_str()));
    assert_eq!(node.node().pending_connects().unwrap().len(), 3);
    // An answer frees a seat.
    let pending = node.node().pending_connects().unwrap();
    node.node()
        .decide_connect(&pending[0].id, ConnectDecision::Deny)
        .unwrap();
    node.authorize(&clients[3]);
}

/// A client id is public. Someone who keeps a request of the client open must never make
/// the owner allow it for the client's own browser: a new authorize of the client ends the
/// waiting request and opens one with its own page and code, never a 429 page without a
/// code (security review finding 1a).
#[test]
fn a_new_authorize_of_the_same_client_ends_the_waiting_request_and_shows_its_own_code() {
    let node = Node::start();
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    // The stranger's request: the public client id, another state.
    let stranger = node.authorize_raw(&client_id, &[("state", "stranger")]);
    assert_eq!(stranger.status, 303, "{}", stranger.text);
    let stranger_wait = stranger.header("location").expect("location").to_string();
    let stranger_request = node.pending_one();
    // The client's own browser.
    let wait = node.authorize(&client_id);
    assert_ne!(wait, stranger_wait);
    let request = node.pending_one();
    assert_ne!(request.id, stranger_request.id);
    let page = get(&node.public(), &wait);
    assert_eq!(page.status, 200, "{}", page.text);
    assert!(page.text.contains(&request.code), "{}", page.text);
    assert!(
        page.text.contains(&format!(
            "Deny requests on your {HOST_WORD} that you did not start, then connect again."
        )),
        "{}",
        page.text
    );
    // The stranger's request ended: its page says so, and the owner cannot allow it.
    let old = get(&node.public(), &stranger_wait);
    assert_eq!(old.status, 200);
    assert!(old.text.contains("The request ended."), "{}", old.text);
    let agent = node.later_agent("Grok Bot");
    let error = node
        .node()
        .decide_connect(
            &stranger_request.id,
            ConnectDecision::Allow {
                team: node.team.clone(),
                agent,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "connect_not_pending");
    // The owner allows the request whose code the browser shows: the code goes to it.
    node.node()
        .decide_connect(
            &request.id,
            ConnectDecision::Allow {
                team: node.team.clone(),
                agent,
            },
        )
        .unwrap();
    let code = node.code_from(&wait);
    let answer = node.token_code(&client_id, &code, VERIFIER);
    assert_eq!(answer.status, 200, "{}", answer.text);
    // The stranger's page never gets a code.
    let old = get(&node.public(), &stranger_wait);
    assert!(old.header("location").is_none());
    assert!(old.text.contains("The request ended."), "{}", old.text);
    let replaced: i64 = directory(&node.config)
        .query_row(
            "SELECT count(*) FROM audit WHERE action = 'connect_replaced'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(replaced, 1);
}

/// Codes and refresh tokens are 256 random bits. A stranger who sends bad ones slows only
/// the client whose id they send: never another client, and never the listener (security
/// review finding 2).
#[test]
fn bad_codes_and_refresh_tokens_count_for_their_client_only() {
    let node = Node::start();
    let other = node.connect("Other");
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    for i in 0..20 {
        let answer = if i % 2 == 0 {
            node.token_code(&client_id, &format!("bad-code-{i}"), VERIFIER)
        } else {
            node.token_refresh(&client_id, &format!("bad-refresh-{i}"))
        };
        assert_eq!(answer.status, 400, "{i}: {}", answer.text);
        assert_eq!(answer.json()["error"], "invalid_grant");
    }
    // That client is at its limit for the window.
    let answer = node.token_refresh(&client_id, "bad-refresh-20");
    assert_eq!(answer.status, 429, "{}", answer.text);
    assert_eq!(answer.json()["error"], "rate_limited");
    assert_eq!(answer.header("retry-after"), Some("60"));
    // Another client is not refused: its refresh works.
    let answer = node.token_refresh(&other.client_id, &other.refresh);
    assert_eq!(answer.status, 200, "{}", answer.text);
    let access = answer.json()["access_token"]
        .as_str()
        .expect("access")
        .to_string();
    // The listener is not at a limit: metadata, registration, and `/mcp` answer.
    let answer = get(&node.public(), "/.well-known/oauth-authorization-server");
    assert_eq!(answer.status, 200, "{}", answer.text);
    node.register(Some("New"), REDIRECT);
    assert_eq!(mcp_list(&node.public(), &access).status, 200);
    // A client id that nobody registered is never counted, and never refused.
    for i in 0..25 {
        let answer = node.token_code("c_unknown", &format!("bad-code-{i}"), VERIFIER);
        assert_eq!(answer.status, 400, "{i}: {}", answer.text);
    }
}

#[test]
fn the_page_cleans_and_escapes_the_client_name() {
    let node = Node::start();
    let client_id = node.register(
        Some("  <script>alert(1)</script>\u{202E}\u{200B} \"Bot\" & co\n"),
        REDIRECT,
    );
    let wait = node.authorize(&client_id);
    let page = get(&node.public(), &wait);
    assert_eq!(page.status, 200);
    assert_page_headers(&page);
    assert_no_active_part(&page.text);
    assert!(
        page.text.contains(
            "&lt;script&gt;alert(1)&lt;/script&gt; &quot;Bot&quot; &amp; co wants to connect"
        ),
        "{}",
        page.text
    );
    assert!(!page.text.contains('\u{202E}'));
    let request = node.pending_one();
    assert_eq!(
        request.client_name.as_deref(),
        Some("<script>alert(1)</script> \"Bot\" & co")
    );
    // The 303 to the page and back to the client have the page headers too.
    let answer = node.authorize_raw(&client_id, &[]);
    assert_eq!(answer.status, 303);
    assert_page_headers(&answer);
    node.allow(&request);
    let answer = get(&node.public(), &wait);
    assert_eq!(answer.status, 303);
    assert_page_headers(&answer);
}

#[test]
fn revoking_an_agent_ends_its_connection_and_denies_its_client_requests() {
    let node = Node::start();
    let connected = node.connect("Grok Bot");
    // The same client asks again while the agent is live.
    let wait = node.authorize(&connected.client_id);
    node.node()
        .revoke_agent(&node.team, connected.agent)
        .unwrap();
    assert!(node.node().pending_connects().unwrap().is_empty());
    let page = get(&node.public(), &wait);
    assert!(page.text.contains("You denied the connection."));
    assert_eq!(mcp_list(&node.public(), &connected.access).status, 401);
    let answer = node.token_refresh(&connected.client_id, &connected.refresh);
    assert_eq!(answer.json()["error"], "invalid_grant");
    let view = node
        .node()
        .agent_access(&node.team, connected.agent)
        .unwrap();
    assert!(view.revoked);
    assert_eq!(view.token_expires_at, None);
    // A revoked agent cannot take a request.
    let client = node.register(Some("Again"), REDIRECT);
    node.authorize(&client);
    let request = node.pending_one();
    let error = node
        .node()
        .decide_connect(
            &request.id,
            ConnectDecision::Allow {
                team: node.team.clone(),
                agent: connected.agent,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "not_found");
}

#[test]
fn the_client_can_revoke_its_tokens() {
    let node = Node::start();
    let connected = node.connect("Grok Bot");
    let answer = post_form(
        &node.public(),
        "/oauth/revoke",
        &[
            ("token", connected.refresh.as_str()),
            ("token_type_hint", "refresh_token"),
        ],
    );
    assert_eq!(answer.status, 200);
    assert_eq!(mcp_list(&node.public(), &connected.access).status, 401);
    assert_eq!(
        node.token_refresh(&connected.client_id, &connected.refresh)
            .json()["error"],
        "invalid_grant"
    );
    // An access token of the flow revokes the same way; an unknown token is 200.
    let connected = node.connect("Grok Bot");
    let answer = post_form(
        &node.public(),
        "/oauth/revoke",
        &[("token", connected.access.as_str())],
    );
    assert_eq!(answer.status, 200);
    assert_eq!(mcp_list(&node.public(), &connected.access).status, 401);
    assert_eq!(
        node.token_refresh(&connected.client_id, &connected.refresh)
            .json()["error"],
        "invalid_grant"
    );
    assert_eq!(
        post_form(&node.public(), "/oauth/revoke", &[("token", "unknown")]).status,
        200
    );
}

#[test]
fn a_connect_request_wakes_the_host_loop() {
    let node = Node::start();
    let client_id = node.register(Some("Grok Bot"), REDIRECT);
    let started = Instant::now();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            node.node()
                .wait_pending(&node.team, Duration::from_secs(20))
        });
        std::thread::sleep(Duration::from_millis(300));
        node.authorize(&client_id);
        let runs = waiter.join().unwrap().unwrap();
        assert!(runs.is_empty());
    });
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(node.node().pending_connects().unwrap().len(), 1);
}

#[test]
fn a_token_now_agent_has_no_oauth_connection() {
    let node = Node::start();
    let uid = hostkeys::new_uid().unwrap();
    node.node()
        .sync_items(
            &node.team,
            &[CatalogItem {
                uid: uid.clone(),
                name: "Example".to_string(),
                env_name: "EXAMPLE_TOKEN".to_string(),
                hosts: vec!["api.example.com".to_string()],
                provider: None,
                environment: "development".to_string(),
                risk: None,
                scope: None,
                reversibility: None,
                allow_broad_host: false,
            }],
        )
        .unwrap();
    let made = node
        .node()
        .create_agent(
            &node.team,
            &NewCloudAgent {
                name: "CLI agent".to_string(),
                items: vec![uid],
                token: TokenIssue::Now { lifetime_days: 90 },
            },
        )
        .unwrap();
    let token = made.token.expect("a token now");
    assert_eq!(mcp_list(&node.public(), token.expose()).status, 200);
    let view = node.node().agent_access(&node.team, made.agent_id).unwrap();
    assert!(
        view.token_expires_at
            .is_some_and(|end| end == made.expires_at)
    );
    assert_eq!(view.client_id, None);
    // The client cannot revoke a CLI token through the flow.
    post_form(
        &node.public(),
        "/oauth/revoke",
        &[("token", token.expose())],
    );
    assert_eq!(mcp_list(&node.public(), token.expose()).status, 200);
    // A later agent has no token until a connect.
    let later = node.later_agent("Later");
    let view = node.node().agent_access(&node.team, later).unwrap();
    assert_eq!(view.token_expires_at, None);
    assert!(
        node.node()
            .agent_access(&node.team, NodeAgentId(999))
            .is_err()
    );
}

#[test]
fn the_hosted_relay_has_no_oauth_paths() {
    let relay = relay::start(UpstreamOptions::default());
    assert!(relay.config.oauth.is_none());
    let paths = [
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/.well-known/oauth-protected-resource/mcp"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/.well-known/openid-configuration"),
        ("POST", "/oauth/register"),
        ("GET", "/oauth/authorize?client_id=x"),
        ("GET", "/oauth/wait/00000000000000000000000000000000"),
        ("POST", "/oauth/token"),
        ("POST", "/oauth/revoke"),
    ];
    for (method, path) in paths {
        let answer = call(
            &relay.url,
            method,
            path,
            &[("X-Apassy-Edge", relay::EDGE_SECRET)],
            None,
        );
        assert_eq!(answer.status, 404, "{method} {path}: {}", answer.text);
    }
    // No challenge on its 401 of `/mcp`.
    let answer = call(
        &relay.url,
        "POST",
        "/mcp",
        &[("X-Apassy-Edge", relay::EDGE_SECRET)],
        Some(("application/json", b"{}".to_vec())),
    );
    assert_eq!(answer.status, 401, "{}", answer.text);
    assert!(answer.header("www-authenticate").is_none());
    // An embedded node without the setting: 404 on both listeners.
    let dir = tempfile::tempdir().unwrap();
    let mut config = RelayConfig::embedded(EmbeddedOptions {
        data_dir: dir.path().join("node"),
        master_key: SecretString::new(MASTER_KEY.to_string()),
        public_url: PUBLIC_URL.to_string(),
        public_listen: Some(loopback()),
        node_origin: None,
        tailnet_listen: None,
        tailnet_agents: false,
        push_gateway: None,
    })
    .unwrap();
    config.oauth = None;
    let node = EmbeddedNode::start(config).unwrap();
    for base in [
        format!("http://{}", node.public_addr().unwrap()),
        format!("http://{}", node.node_addr()),
    ] {
        for (method, path) in paths {
            assert_eq!(call(&base, method, path, &[], None).status, 404, "{path}");
        }
    }
    Box::new(node).stop();
}

#[test]
fn the_directory_goes_back_to_1003_and_up_to_1004_again() {
    let mut node = Node::start();
    let connected = node.connect("Grok Bot");
    node.stop();
    let version = |path: &Path| -> i64 {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{MASTER_KEY}';"))
            .unwrap();
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    };
    assert_eq!(version(&node.config.directory_path()), 1005);
    assert_eq!(
        Directory::downgrade_to_1003(&node.config).unwrap(),
        (1005, 1003)
    );
    assert_eq!(version(&node.config.directory_path()), 1003);
    // The image of 1005 moves it up again; the OAuth state is gone.
    let started = EmbeddedNode::start(node.config.clone()).unwrap();
    node.node = Some(started);
    assert_eq!(version(&node.config.directory_path()), 1005);
    assert!(node.node().has_team(&node.team));
    let answer = node.token_refresh(&connected.client_id, &connected.refresh);
    assert_eq!(answer.json()["error"], "invalid_grant");
    // The access token lives in the team file until it ends.
    assert_eq!(mcp_list(&node.public(), &connected.access).status, 200);
    // A new connection works.
    let again = node.connect("Grok Bot");
    assert_eq!(mcp_list(&node.public(), &again.access).status, 200);
}
