//! The public origins of an embedded node (docs/SPEC.md section 31.1): with Funnel and the
//! Connect route both on, the public listener has two origins and answers each request
//! with the one it arrived on. A connection without the front (Funnel's, from
//! `tailscaled`) has the Funnel origin; a `public` stream of the Connect tunnel has the
//! origin of the server name that the front wrote down for it (`front_peers`). No header
//! decides it. A connection of the MCP authorization flow (its client, code, refresh and
//! access tokens) and a session work only on the origin they were made for. Each node
//! listens on free loopback ports and keeps its data in a temporary directory; the tests
//! write each connection down as the front would. Synthetic names and values only.

#[path = "common/relay.rs"]
mod relay;
#[path = "common/upstream.rs"]
mod upstream;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use apassy::net::front_peers;
use apassy::node::backend::{
    CatalogItem, ConnectDecision, NewCloudAgent, NodeAgentId, NodeBackend, NodeConfig, NodeRunId,
    NodeSecret, NodeTeamId, RunStatus, RunningNode, TokenIssue,
};
use apassy_relay::embedded::EmbeddedRelay;
use apassy_relay::hostkeys;
use apassy_relay::server::oauth::{decode_form, percent_encode};
use relay::CANARY;
use serde_json::{Value, json};
use upstream::MockUpstream;

const MASTER_KEY: &str = "a synthetic node master key for the origin tests";
/// The Funnel origin of the node. Nothing listens there: the tests call the listener.
const FUNNEL: &str = "https://node.example.ts.net:8443";
const FUNNEL_HOST: &str = "node.example.ts.net";
/// The public name of the node at Connect, and its origin.
const CONNECT_NAME: &str = "k7m2q4x3ca.node.example.test";
const CONNECT: &str = "https://k7m2q4x3ca.node.example.test";
const HOST: &str = "api.example.com";
const REDIRECT: &str = "https://client.example/oauth/callback";
/// RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// How a request reaches the public listener.
#[derive(Debug, Clone, Copy)]
enum Via<'a> {
    /// Without the front, as Funnel's `tailscaled` connects.
    Funnel,
    /// A `public` stream of the Connect tunnel that the front wrote down with this server
    /// name.
    Tunnel(Option<&'a str>),
}

impl Via<'_> {
    /// The `Host` that a client of this way sends unless a test forges another.
    fn host(self) -> &'static str {
        match self {
            Via::Funnel => "node.example.ts.net:8443",
            Via::Tunnel(_) => CONNECT_NAME,
        }
    }
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

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let Some(end) = rest.windows(2).position(|pair| pair == b"\r\n") else {
            return out;
        };
        let size = std::str::from_utf8(&rest[..end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.split(';').next()?.trim(), 16).ok())
            .unwrap_or(0);
        if size == 0 {
            return out;
        }
        let start = end + 2;
        let stop = (start + size).min(rest.len());
        out.extend_from_slice(&rest[start..stop]);
        rest = rest.get(stop + 2..).unwrap_or_default();
    }
}

/// One request on a new connection to the public listener `listener`, written down as
/// the front writes down a tunnel stream for `Via::Tunnel`. `headers` without `Host` get
/// the `Host` of `via`.
fn send(
    listener: SocketAddr,
    via: Via<'_>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, Vec<u8>)>,
) -> Answer {
    let mut stream = TcpStream::connect(listener).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("timeout");
    let _entry = match via {
        Via::Funnel => None,
        Via::Tunnel(name) => Some(front_peers::register_tunnel_named(
            stream.local_addr().expect("local"),
            stream.peer_addr().expect("peer"),
            name,
        )),
    };
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        head.push_str(&format!("Host: {}\r\n", via.host()));
    }
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    let bytes = match body {
        Some((kind, bytes)) => {
            head.push_str(&format!("Content-Type: {kind}\r\n"));
            bytes
        }
        None => Vec::new(),
    };
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    ));
    stream.write_all(head.as_bytes()).expect("head");
    stream.write_all(&bytes).expect("body");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(&raw)));
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    if headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked"))
    {
        body = dechunk(&body);
    }
    Answer {
        status,
        headers,
        text: String::from_utf8_lossy(&body).to_string(),
    }
}

fn get(listener: SocketAddr, via: Via<'_>, path: &str) -> Answer {
    send(listener, via, "GET", path, &[], None)
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

fn post_form(listener: SocketAddr, via: Via<'_>, path: &str, pairs: &[(&str, &str)]) -> Answer {
    send(
        listener,
        via,
        "POST",
        path,
        &[],
        Some(("application/x-www-form-urlencoded", form(pairs))),
    )
}

fn query_of(location: &str) -> HashMap<String, String> {
    let query = location.split_once('?').map_or("", |(_, query)| query);
    decode_form(query).expect("a query")
}

/// One `tools/call` on `POST /mcp` with a bearer token.
fn mcp(listener: SocketAddr, via: Via<'_>, token: &str, name: &str, arguments: Value) -> Answer {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}});
    let bearer = format!("Bearer {token}");
    send(
        listener,
        via,
        "POST",
        "/mcp",
        &[("Authorization", bearer.as_str())],
        Some(("application/json", serde_json::to_vec(&body).unwrap())),
    )
}

/// A tool call that must succeed. Returns its structured result.
fn tool_ok(listener: SocketAddr, via: Via<'_>, token: &str, name: &str, arguments: Value) -> Value {
    let answer = mcp(listener, via, token, name, arguments);
    assert_eq!(answer.status, 200, "{name} {via:?}: {}", answer.text);
    let reply = answer.json();
    assert_eq!(reply["result"]["isError"], false, "{name}: {reply}");
    reply["result"]["structuredContent"].clone()
}

/// The resource metadata, the server metadata, and the challenge of `/mcp` all name
/// `origin`.
fn assert_names(listener: SocketAddr, via: Via<'_>, headers: &[(&str, &str)], origin: &str) {
    let resource = send(
        listener,
        via,
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        headers,
        None,
    );
    assert_eq!(resource.status, 200, "{via:?}: {}", resource.text);
    assert_eq!(
        resource.json(),
        json!({
            "resource": format!("{origin}/mcp"),
            "authorization_servers": [origin],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["apassy"],
            "resource_name": "Apassy",
        }),
        "{via:?}"
    );
    let server = send(
        listener,
        via,
        "GET",
        "/.well-known/oauth-authorization-server",
        headers,
        None,
    );
    assert_eq!(server.status, 200, "{via:?}: {}", server.text);
    let meta = server.json();
    assert_eq!(meta["issuer"], origin, "{via:?}");
    for (field, path) in [
        ("authorization_endpoint", "/oauth/authorize"),
        ("token_endpoint", "/oauth/token"),
        ("registration_endpoint", "/oauth/register"),
        ("revocation_endpoint", "/oauth/revoke"),
    ] {
        assert_eq!(meta[field], format!("{origin}{path}"), "{via:?} {field}");
    }
    for token in [None, Some("Bearer apassy_tagt_t_unknown0001_00")] {
        let mut with = headers.to_vec();
        if let Some(token) = token {
            with.push(("Authorization", token));
        }
        let challenge = send(
            listener,
            via,
            "POST",
            "/mcp",
            &with,
            Some(("application/json", b"{}".to_vec())),
        );
        assert_eq!(challenge.status, 401, "{via:?}: {}", challenge.text);
        let value = challenge.header("www-authenticate").expect("a challenge");
        assert!(
            value.starts_with(&format!(
                "Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource/mcp\""
            )),
            "{via:?}: {value}"
        );
    }
}

fn catalog_item(uid: &str) -> CatalogItem {
    CatalogItem {
        uid: uid.to_string(),
        name: "Item EXAMPLE_TOKEN".to_string(),
        env_name: "EXAMPLE_TOKEN".to_string(),
        hosts: vec![HOST.to_string()],
        provider: None,
        environment: "development".to_string(),
        risk: None,
        scope: None,
        reversibility: None,
        allow_broad_host: false,
    }
}

/// A running node with a personal team and one catalog item for `HOST`, as the app makes
/// them, with the public origins `public_url` and `further`.
struct Node {
    node: Option<Box<dyn RunningNode>>,
    team: NodeTeamId,
    uid: String,
    mock: MockUpstream,
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
    fn start(further: &[&str]) -> Self {
        let mock = upstream::start(&[HOST]);
        let dir = tempfile::tempdir().expect("temp dir");
        let backend = EmbeddedRelay {
            upstream: mock.options(),
        };
        let node = backend
            .start(NodeConfig {
                data_dir: dir.path().join("node"),
                master_key: NodeSecret::new(MASTER_KEY.to_string()),
                public_url: FUNNEL.to_string(),
                public_origins: further.iter().map(|origin| origin.to_string()).collect(),
                public_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
            })
            .expect("start");
        let team = node.create_team("Personal").expect("team");
        let uid = hostkeys::new_uid().expect("uid");
        node.sync_items(&team, &[catalog_item(&uid)]).expect("sync");
        Self {
            node: Some(node),
            team,
            uid,
            mock,
            _dir: dir,
        }
    }

    fn node(&self) -> &dyn RunningNode {
        self.node.as_deref().expect("running")
    }

    fn public(&self) -> SocketAddr {
        self.node().public_addr().expect("public listener")
    }

    fn register(&self, via: Via<'_>) -> String {
        let body = json!({"redirect_uris": [REDIRECT], "client_name": "Grok Bot"});
        let answer = send(
            self.public(),
            via,
            "POST",
            "/oauth/register",
            &[],
            Some(("application/json", serde_json::to_vec(&body).unwrap())),
        );
        assert_eq!(answer.status, 201, "{via:?}: {}", answer.text);
        answer.json()["client_id"]
            .as_str()
            .expect("client id")
            .to_string()
    }

    fn authorize(&self, via: Via<'_>, client_id: &str) -> Answer {
        let query = String::from_utf8(form(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "state-123"),
        ]))
        .unwrap();
        get(self.public(), via, &format!("/oauth/authorize?{query}"))
    }

    /// Allows the one waiting request for a new agent with no item. Returns the agent.
    fn allow_waiting(&self) -> NodeAgentId {
        let pending = self.node().pending_connects().expect("pending");
        assert_eq!(pending.len(), 1, "{pending:?}");
        let agent = self
            .node()
            .create_agent(
                &self.team,
                &NewCloudAgent {
                    name: "Grok Bot".to_string(),
                    items: Vec::new(),
                    token: TokenIssue::Later,
                },
            )
            .expect("agent")
            .agent_id;
        self.node()
            .decide_connect(
                &pending[0].id,
                ConnectDecision::Allow {
                    team: self.team.clone(),
                    agent,
                },
            )
            .expect("allow");
        agent
    }

    fn token_code(&self, via: Via<'_>, client_id: &str, code: &str, resource: &str) -> Answer {
        post_form(
            self.public(),
            via,
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("client_id", client_id),
                ("code_verifier", VERIFIER),
                ("resource", resource),
            ],
        )
    }

    fn token_refresh(&self, via: Via<'_>, client_id: &str, refresh: &str) -> Answer {
        post_form(
            self.public(),
            via,
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", client_id),
            ],
        )
    }

    /// The whole flow at `via`, whose origin is `origin`. Returns the tokens.
    fn connect(&self, via: Via<'_>, origin: &str) -> Connected {
        let client_id = self.register(via);
        let answer = self.authorize(via, &client_id);
        assert_eq!(answer.status, 303, "{}", answer.text);
        let wait = answer.header("location").expect("location").to_string();
        let agent = self.allow_waiting();
        let page = get(self.public(), via, &wait);
        assert_eq!(page.status, 303, "{}", page.text);
        let query = query_of(page.header("location").expect("location"));
        assert_eq!(query["iss"], origin);
        let answer = self.token_code(via, &client_id, &query["code"], &format!("{origin}/mcp"));
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

    /// The relay id of the one item that the agent of `token` sees at `via`.
    fn item_id(&self, via: Via<'_>, token: &str) -> u64 {
        let access = tool_ok(self.public(), via, token, "apassy_list_access", json!({}));
        let items = access["items"].as_array().expect("items");
        assert_eq!(items.len(), 1, "{access}");
        items[0]["item_id"].as_u64().expect("id")
    }

    /// A run of the one item that the agent of `token` asks for at `via`, released by the
    /// host with `CANARY`. Returns the session of its status at `via`.
    fn session(&self, via: Via<'_>, token: &str) -> Value {
        let item = self.item_id(via, token);
        let view = tool_ok(
            self.public(),
            via,
            token,
            "apassy_request_run",
            json!({
                "items": [item],
                "command": ["curl", format!("https://{HOST}/v1/account")],
                "purpose": "check the account",
                "user_request": "Please check the example account.",
            }),
        );
        assert_eq!(view["status"], "pending", "{view}");
        let run = NodeRunId(view["run_id"].as_u64().expect("run id"));
        let pending = self
            .node()
            .wait_pending(&self.team, Duration::from_secs(10))
            .expect("pending");
        assert!(pending.iter().any(|pending| pending.run_id == run));
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
            self.public(),
            via,
            token,
            "apassy_run_status",
            json!({"run_id": run.0, "wait_secs": 0}),
        );
        assert_eq!(view["status"], "ready", "{view}");
        view["session"].clone()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            node.stop();
        }
    }
}

/// The key of a session's base URL for `HOST` under `origin`.
fn session_key(session: &Value, origin: &str) -> String {
    let base = session["base_urls"][HOST].as_str().expect("base url");
    let prefix = format!("{origin}/p/");
    assert!(base.starts_with(&prefix), "{base} is not under {origin}");
    base[prefix.len()..]
        .split('/')
        .next()
        .expect("key")
        .to_string()
}

#[test]
fn each_origin_names_itself_whatever_the_host_and_forwarded_headers_say() {
    let node = Node::start(&[CONNECT]);
    let public = node.public();
    // As each client sends them, and forged to name the other origin.
    for (via, origin, other_host) in [
        (Via::Funnel, FUNNEL, CONNECT_NAME),
        (Via::Tunnel(Some(CONNECT_NAME)), CONNECT, FUNNEL_HOST),
    ] {
        assert_names(public, via, &[], origin);
        let forwarded = format!("host={other_host};proto=https");
        assert_names(
            public,
            via,
            &[
                ("Host", other_host),
                ("X-Forwarded-Host", other_host),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Port", "443"),
                ("Forwarded", forwarded.as_str()),
            ],
            origin,
        );
    }
    // The server name is compared without case and without a final dot.
    assert_names(
        public,
        Via::Tunnel(Some("K7M2Q4X3CA.Node.Example.Test.")),
        &[("Host", FUNNEL_HOST)],
        CONNECT,
    );
}

#[test]
fn a_tunnel_stream_without_a_server_name_of_the_node_is_not_served() {
    let node = Node::start(&[CONNECT]);
    let public = node.public();
    for via in [
        Via::Tunnel(None),
        Via::Tunnel(Some("other0node.node.example.test")),
        Via::Tunnel(Some("")),
    ] {
        for (method, path, body) in [
            ("GET", "/.well-known/oauth-protected-resource/mcp", None),
            ("GET", "/.well-known/oauth-authorization-server", None),
            (
                "POST",
                "/oauth/register",
                Some(json!({"redirect_uris": [REDIRECT]})),
            ),
            ("POST", "/mcp", Some(json!({}))),
            ("GET", "/p/apassy_sess_x/api.example.com/", None),
        ] {
            let answer = send(
                public,
                via,
                method,
                path,
                &[("Host", CONNECT_NAME)],
                body.map(|body| ("application/json", serde_json::to_vec(&body).unwrap())),
            );
            assert_eq!(
                answer.status, 404,
                "{via:?} {method} {path}: {}",
                answer.text
            );
            assert_eq!(
                answer.json()["error"]["code"],
                "not_found",
                "{via:?} {path}"
            );
            assert!(answer.header("www-authenticate").is_none());
        }
    }
    // Funnel's connections are answered meanwhile.
    assert_names(public, Via::Funnel, &[], FUNNEL);
}

#[test]
fn a_node_with_one_origin_answers_as_before_and_serves_no_other_name() {
    let node = Node::start(&[]);
    let public = node.public();
    // The Funnel origin, whatever the headers say.
    assert_names(public, Via::Funnel, &[], FUNNEL);
    assert_names(public, Via::Funnel, &[("Host", CONNECT_NAME)], FUNNEL);
    // A repeat of `public_url` is no second origin.
    let same = Node::start(&[FUNNEL, "https://node.example.ts.net:8443/"]);
    assert_names(same.public(), Via::Funnel, &[], FUNNEL);
    // A tunnel stream with a name that is no origin of this node: not served.
    let answer = get(
        public,
        Via::Tunnel(Some(CONNECT_NAME)),
        "/.well-known/oauth-protected-resource/mcp",
    );
    assert_eq!(answer.status, 404, "{}", answer.text);
    // A whole connection at the one origin works, as before.
    let connected = node.connect(Via::Funnel, FUNNEL);
    assert_eq!(
        node.token_refresh(Via::Funnel, &connected.client_id, &connected.refresh)
            .status,
        200
    );
}

/// A client, its connect request and page, its code, its refresh token, and its access
/// token work only on the origin that the client registered at; on the other origin of
/// the node they are unknown and change nothing.
#[test]
fn a_connection_works_only_on_the_origin_its_client_registered_at() {
    let node = Node::start(&[CONNECT]);
    let public = node.public();
    let tunnel = Via::Tunnel(Some(CONNECT_NAME));
    for (here, there, origin, other) in [
        (tunnel, Via::Funnel, CONNECT, FUNNEL),
        (Via::Funnel, tunnel, FUNNEL, CONNECT),
    ] {
        let client_id = node.register(here);
        // The authorize of the other origin does not know the client.
        let answer = node.authorize(there, &client_id);
        assert_eq!(answer.status, 400, "{}", answer.text);
        assert!(answer.text.contains("This connection link is not valid."));
        assert!(node.node().pending_connects().expect("pending").is_empty());
        let answer = node.authorize(here, &client_id);
        assert_eq!(answer.status, 303, "{}", answer.text);
        let wait = answer.header("location").expect("location").to_string();
        let agent = node.allow_waiting();
        // The page of the request is only at its own origin: the other one sends no code.
        let page = get(public, there, &wait);
        assert_eq!(page.status, 404, "{}", page.text);
        assert!(page.header("location").is_none());
        let page = get(public, here, &wait);
        assert_eq!(page.status, 303, "{}", page.text);
        let query = query_of(page.header("location").expect("location"));
        assert_eq!(query["iss"], origin);
        let code = query["code"].clone();
        // The code at the other origin: the client is not registered there, and the code
        // stays good.
        let answer = node.token_code(there, &client_id, &code, &format!("{other}/mcp"));
        assert_eq!(answer.status, 400, "{}", answer.text);
        assert_eq!(answer.json()["error"], "invalid_client");
        // The resource of the other origin is not this one's.
        let answer = node.token_code(here, &client_id, &code, &format!("{other}/mcp"));
        assert_eq!(answer.status, 400, "{}", answer.text);
        assert_eq!(answer.json()["error"], "invalid_target");
        let answer = node.token_code(here, &client_id, &code, &format!("{origin}/mcp"));
        assert_eq!(answer.status, 200, "{}", answer.text);
        let reply = answer.json();
        let access = reply["access_token"].as_str().expect("access").to_string();
        let refresh = reply["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_string();
        // The access token: 401 at the other origin, with that origin's challenge, so the
        // client can connect there.
        let answer = mcp(public, there, &access, "apassy_list_access", json!({}));
        assert_eq!(answer.status, 401, "{}", answer.text);
        let challenge = answer.header("www-authenticate").expect("challenge");
        assert!(
            challenge.contains(&format!(
                "resource_metadata=\"{other}/.well-known/oauth-protected-resource/mcp\""
            )) && challenge.contains("error=\"invalid_token\""),
            "{challenge}"
        );
        tool_ok(public, here, &access, "apassy_list_access", json!({}));
        // The refresh token at the other origin: unknown there, and still good here.
        let answer = node.token_refresh(there, &client_id, &refresh);
        assert_eq!(answer.status, 400, "{}", answer.text);
        assert_eq!(answer.json()["error"], "invalid_client");
        // A revocation at the other origin changes nothing, for either token.
        for token in [refresh.as_str(), access.as_str()] {
            let answer = post_form(public, there, "/oauth/revoke", &[("token", token)]);
            assert_eq!(answer.status, 200);
        }
        tool_ok(public, here, &access, "apassy_list_access", json!({}));
        let answer = node.token_refresh(here, &client_id, &refresh);
        assert_eq!(answer.status, 200, "{}", answer.text);
        let access = answer.json()["access_token"]
            .as_str()
            .expect("access")
            .to_string();
        tool_ok(public, here, &access, "apassy_list_access", json!({}));
        assert_eq!(
            mcp(public, there, &access, "apassy_list_access", json!({})).status,
            401
        );
        let access_now = node.node().agent_access(&node.team, agent).expect("access");
        assert_eq!(access_now.client_id.as_deref(), Some(client_id.as_str()));
        // A `Host` or `Origin` of this origin on the other one changes nothing.
        let bearer = format!("Bearer {access}");
        let host = match here {
            Via::Funnel => FUNNEL_HOST,
            Via::Tunnel(_) => CONNECT_NAME,
        };
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "apassy_list_access", "arguments": {}}});
        let answer = send(
            public,
            there,
            "POST",
            "/mcp",
            &[
                ("Host", host),
                ("X-Forwarded-Host", host),
                ("Authorization", bearer.as_str()),
            ],
            Some(("application/json", serde_json::to_vec(&body).unwrap())),
        );
        assert_eq!(answer.status, 401, "{}", answer.text);
        let answer = send(
            public,
            there,
            "POST",
            "/mcp",
            &[("Origin", origin), ("Authorization", bearer.as_str())],
            Some(("application/json", serde_json::to_vec(&body).unwrap())),
        );
        assert_eq!(answer.status, 403, "a browser Origin of the other origin");
    }
}

/// The base URLs of a session start with the origin of its agent, and the proxy serves
/// its key only there. The bearer token of `TokenIssue::Now` works on every origin, and
/// its sessions are on the first.
#[test]
fn a_session_is_made_for_the_origin_of_its_agent() {
    let node = Node::start(&[CONNECT]);
    let public = node.public();
    let tunnel = Via::Tunnel(Some(CONNECT_NAME));
    let connected = node.connect(tunnel, CONNECT);
    node.node()
        .set_agent_items(&node.team, connected.agent, std::slice::from_ref(&node.uid))
        .expect("items");
    let session = node.session(tunnel, &connected.access);
    let key = session_key(&session, CONNECT);
    let placeholder = session["env"]["EXAMPLE_TOKEN"]
        .as_str()
        .expect("placeholder")
        .to_string();
    assert_ne!(placeholder, CANARY);
    let path = format!("/p/{key}/{HOST}/v1/account");
    let bearer = format!("Bearer {placeholder}");
    // At Funnel, also with Connect's `Host`: the key names no session there.
    for headers in [
        vec![("Authorization", bearer.as_str())],
        vec![
            ("Authorization", bearer.as_str()),
            ("Host", CONNECT_NAME),
            ("X-Forwarded-Host", CONNECT_NAME),
        ],
    ] {
        let seen = node.mock.requests().len();
        let answer = send(public, Via::Funnel, "GET", &path, &headers, None);
        assert_eq!(answer.status, 403, "{}", answer.text);
        assert_eq!(answer.json()["error"]["code"], "session_invalid");
        assert_eq!(node.mock.requests().len(), seen, "nothing went upstream");
    }
    // At Connect: the value goes upstream in place of the placeholder.
    let answer = send(
        public,
        tunnel,
        "GET",
        &path,
        &[("Authorization", bearer.as_str())],
        None,
    );
    assert_eq!(answer.status, 200, "{}", answer.text);
    assert!(!answer.text.contains(CANARY));
    let seen = node.mock.requests();
    let last = seen.last().expect("the upstream got the request");
    assert_eq!(
        last.header("authorization"),
        Some(&*format!("Bearer {CANARY}"))
    );

    // The bearer token of `TokenIssue::Now`: on both origins, its sessions on the first.
    let made = node
        .node()
        .create_agent(
            &node.team,
            &NewCloudAgent {
                name: "CLI agent".to_string(),
                items: vec![node.uid.clone()],
                token: TokenIssue::Now { lifetime_days: 1 },
            },
        )
        .expect("agent");
    let token = made.token.expect("token").expose().to_string();
    tool_ok(public, tunnel, &token, "apassy_list_access", json!({}));
    let session = node.session(Via::Funnel, &token);
    let key = session_key(&session, FUNNEL);
    let answer = send(
        public,
        tunnel,
        "GET",
        &format!("/p/{key}/{HOST}/v1/account"),
        &[],
        None,
    );
    assert_eq!(answer.status, 403, "{}", answer.text);
    assert_eq!(answer.json()["error"]["code"], "session_invalid");
}
