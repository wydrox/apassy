//! The tailnet listener of a node (docs/SPEC.md section 32.1, `Scope::Tailnet`): what the
//! TLS front reaches. The device routes on every node; the team routes on the Linux node
//! (`tailnet_agents`); never the OAuth flow, `/v1/connect`, or anything else (404). Each
//! node listens on free loopback ports and keeps its data in a temporary directory.
//! Synthetic values only.

#[path = "common/node.rs"]
mod node;
#[path = "common/relay.rs"]
mod relay;

use apassy::node::backend::{NewCloudAgent, RunningNode, TokenIssue};
use apassy_relay::server::http::listener_alive;
use node::{Node, NodeOptions, code};
use serde_json::json;

/// The status of one request without a token.
fn status(node: &Node, base: &str, method: &str, path: &str) -> u16 {
    let body = (method == "POST" || method == "PUT").then(|| json!({}));
    node.call(base, method, path, None, body.as_ref()).0
}

/// `POST /mcp` without a token: the status and the `WWW-Authenticate` header, if any.
fn mcp_challenge(base: &str) -> (u16, Option<String>) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into();
    let request = ureq::http::Request::builder()
        .method("POST")
        .uri(format!("{base}/mcp"))
        .header("Content-Type", "application/json")
        .body(b"{}".to_vec())
        .unwrap();
    let response = agent.run(request).unwrap();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (response.status().as_u16(), challenge)
}

/// A cloud agent with a bearer token now, in a personal team of the node.
fn agent_token(node: &Node) -> String {
    let team = node.node().create_team("Personal").unwrap();
    let made = node
        .node()
        .create_agent(
            &team,
            &NewCloudAgent {
                name: "Build agent".to_string(),
                items: Vec::new(),
                token: TokenIssue::Now { lifetime_days: 1 },
            },
        )
        .unwrap();
    made.token.expect("a token now").expose().to_string()
}

#[test]
fn the_tailnet_listener_serves_the_device_routes_and_404s_the_rest() {
    let node = Node::start(NodeOptions::default());
    let base = node.tailnet();
    assert_ne!(base, node.local());
    // Health has no token and no edge.
    assert_eq!(status(&node, &base, "GET", "/healthz"), 200);
    // The device routes are there: without a token they ask for one.
    for (method, path) in [
        ("GET", "/v1/me"),
        ("GET", "/v1/devices"),
        ("GET", "/v1/questions"),
        ("PUT", "/v1/push/handle"),
        ("GET", "/v1/feed"),
        ("GET", "/v1/sync/head"),
    ] {
        assert_eq!(status(&node, &base, method, path), 401, "{method} {path}");
    }
    // A signed-in device reads its team and its questions.
    let (_, mac) = node.device_team("Questions");
    let me = node.ok(&base, "GET", "/v1/me", Some(&mac.token), None);
    assert_eq!(me["device_id"], mac.id);
    let list = node.ok(
        &base,
        "GET",
        "/v1/questions?since=0",
        Some(&mac.token),
        None,
    );
    assert!(list["questions"].as_array().is_some(), "{list}");
    // Everything else is not there, before any token check: the team routes of an agent,
    // the proxy, Connect, and the MCP authorization flow (which the app's listener and the
    // public listener serve).
    for (method, path) in [
        ("POST", "/mcp"),
        ("GET", "/p/apassy_ses_x/api.example.com/v1"),
        ("POST", "/v1/runs"),
        ("GET", "/v1/runs/1"),
        ("GET", "/v1/access"),
        ("GET", "/v1/host/requests"),
        ("GET", "/v1/items"),
        ("GET", "/v1/approvals"),
        ("GET", "/v1/audit"),
        ("POST", "/v1/connect"),
        ("POST", "/v1/connect/challenge"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("POST", "/oauth/register"),
        ("GET", "/oauth/authorize"),
        ("POST", "/oauth/token"),
        ("GET", "/"),
        ("GET", "/v1/nothing"),
    ] {
        let (got, value) = node.call(&base, method, path, Some(&mac.token), None);
        assert_eq!((got, code(&value)), (404, "not_found"), "{method} {path}");
    }
    // The same OAuth metadata is served where it belongs.
    for listener in [node.local(), node.public()] {
        assert_eq!(
            status(
                &node,
                &listener,
                "GET",
                "/.well-known/oauth-authorization-server"
            ),
            200,
            "{listener}"
        );
    }
    // An agent token is no use on the tailnet listener of the Mac node.
    let token = agent_token(&node);
    let (got, _) = node.call(&base, "GET", "/v1/access", Some(&token), None);
    assert_eq!(got, 404);
    let (got, _) = node.call(&node.local(), "GET", "/v1/access", Some(&token), None);
    assert_eq!(got, 200);
}

#[test]
fn with_agents_the_tailnet_listener_serves_mcp_runs_and_the_host_lane() {
    let node = Node::start(NodeOptions {
        agents: true,
        ..NodeOptions::default()
    });
    let base = node.tailnet();
    for (method, path) in [
        ("POST", "/mcp"),
        ("POST", "/v1/runs"),
        ("GET", "/v1/runs/1"),
        ("GET", "/v1/access"),
        ("GET", "/v1/host/requests"),
        ("GET", "/v1/items"),
        ("GET", "/v1/collections"),
        ("GET", "/v1/grants"),
        ("GET", "/v1/agents"),
        ("GET", "/v1/approvals"),
        ("GET", "/v1/audit"),
        ("GET", "/v1/me"),
    ] {
        assert_eq!(status(&node, &base, method, path), 401, "{method} {path}");
    }
    let token = agent_token(&node);
    let access = node.ok(&base, "GET", "/v1/access", Some(&token), None);
    assert!(access["items"].as_array().is_some(), "{access}");
    // A 401 of `/mcp` names the authorization flow only where it is served: never on the
    // tailnet listener.
    let (got, challenge) = mcp_challenge(&base);
    assert_eq!((got, challenge), (401, None));
    let (got, challenge) = mcp_challenge(&node.local());
    assert_eq!(got, 401);
    assert!(
        challenge.is_some_and(|value| value.contains("resource_metadata=")),
        "the app's listener names the flow"
    );
    // Still never Connect or the OAuth flow.
    for (method, path) in [
        ("POST", "/v1/connect"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("POST", "/oauth/token"),
    ] {
        assert_eq!(status(&node, &base, method, path), 404, "{method} {path}");
    }
}

#[test]
fn the_tailnet_listener_stops_with_the_node() {
    let mut node = Node::start(NodeOptions::default());
    let addr = node.node().tailnet_addr().expect("a tailnet listener");
    assert!(addr.ip().is_loopback());
    assert_eq!(node.node().running().tailnet_addr, Some(addr));
    assert!(listener_alive(addr));
    node.stop();
    assert!(!listener_alive(addr));
    // A node without the route has none.
    let plain = Node::start(NodeOptions {
        no_tailnet: true,
        ..NodeOptions::default()
    });
    assert!(plain.node().tailnet_addr().is_none());
    assert!(plain.node().running().tailnet_listener_url().is_none());
}
