//! The tailnet listener of a node (docs/SPEC.md section 32.1, `Scope::Tailnet`): what the
//! TLS front reaches. The device routes on every node; the team routes on the Linux node
//! (`tailnet_agents`); never the OAuth flow, `/v1/connect`, or anything else (404). Each
//! node listens on free loopback ports and keeps its data in a temporary directory.
//! Synthetic values only.

#[path = "common/node.rs"]
mod node;
#[path = "common/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};

use apassy::net::front_peers;
use apassy::node::backend::{NewCloudAgent, RunningNode, TokenIssue};
use apassy_relay::server::http::{AUTH_FAILURES_MAX, TUNNEL_DEVICE_FAILURES_MAX, listener_alive};
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

/// `GET /v1/me` with a bad token on a new connection to `listener`, as the TLS front
/// makes it for the tailnet peer `peer` (`front_peers`): `None` is a local process that
/// connects without the front. Returns the status.
fn bad_token_from(listener: SocketAddr, peer: Option<IpAddr>) -> u16 {
    let mut stream = TcpStream::connect(listener).expect("connect");
    let _entry = peer.map(|peer| {
        front_peers::register(
            stream.local_addr().expect("local"),
            stream.peer_addr().expect("peer"),
            peer,
        )
    });
    write!(
        stream,
        "GET /v1/me HTTP/1.1\r\nHost: 100.64.0.7:8444\r\nAuthorization: Bearer apr_bad\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {answer:?}"))
}

#[test]
fn one_tailnet_peer_with_bad_tokens_does_not_limit_another_peer_or_the_local_route() {
    let node = Node::start(NodeOptions::default());
    let (_team, mac) = node.device_team("Approvals");
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    let local = node
        .node()
        .running()
        .tailnet_local_addr
        .expect("a local route listener");
    assert_ne!(tailnet, local);
    assert_eq!(local.ip(), tailnet.ip());
    let peer_a: IpAddr = "100.64.0.11".parse().unwrap();
    let peer_b: IpAddr = "100.64.0.12".parse().unwrap();
    // Peer A sends 25 bad tokens in a minute: the first 20 get 401, then 429.
    let statuses: Vec<u16> = (0..25)
        .map(|_| bad_token_from(tailnet, Some(peer_a)))
        .collect();
    let limit = AUTH_FAILURES_MAX as usize;
    assert!(
        statuses[..limit].iter().all(|status| *status == 401),
        "{statuses:?}"
    );
    assert!(
        statuses[limit..].iter().all(|status| *status == 429),
        "{statuses:?}"
    );
    // Peer B still gets its own answers, and signs in.
    assert_eq!(bad_token_from(tailnet, Some(peer_b)), 401);
    // A connection without the front (keyed by the loopback) is not peer A either.
    assert_eq!(bad_token_from(tailnet, None), 401);
    // The Mac's own clients go through the local route listener: the same routes, and
    // no peer's failures count there.
    let base = node.local_route();
    let me = node.ok(&base, "GET", "/v1/me", Some(&mac.token), None);
    assert_eq!(me["device_id"].as_u64(), Some(mac.id));
    assert_eq!(status(&node, &base, "POST", "/v1/connect"), 404);
    assert_eq!(bad_token_from(local, None), 401);
    // The audit row of the limit names the peer.
    let limited: Vec<_> = node
        .relay_audit()
        .into_iter()
        .filter(|(action, detail)| action == "rate_limited" && detail.contains("\"peer\""))
        .collect();
    assert!(!limited.is_empty(), "an audit row of the limit");
    assert!(
        limited
            .iter()
            .all(|(_, detail)| detail.contains("100.64.0.11")),
        "{limited:?}"
    );
}

#[test]
fn the_local_route_listener_counts_its_own_failures() {
    let node = Node::start(NodeOptions::default());
    let local = node
        .node()
        .running()
        .tailnet_local_addr
        .expect("a local route listener");
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    for _ in 0..AUTH_FAILURES_MAX {
        assert_eq!(bad_token_from(local, None), 401);
    }
    assert_eq!(bad_token_from(local, None), 429);
    // The tailnet peers are not limited by the local route's failures.
    assert_eq!(
        bad_token_from(tailnet, Some("100.64.0.13".parse().unwrap())),
        401
    );
    assert!(
        node.relay_audit()
            .iter()
            .any(|(action, detail)| action == "rate_limited" && detail.contains("local_route"))
    );
}

#[test]
fn serve_without_peer_addresses_shares_a_higher_limit() {
    let node = Node::start(NodeOptions::default());
    let tailnet = node.node().tailnet_addr().unwrap();
    let local = node.node().running().tailnet_local_addr.unwrap();
    let limit = apassy_relay::server::http::AUTH_FAILURES_WITHOUT_PEER_MAX;
    assert_eq!(limit, 200);
    assert!(limit > AUTH_FAILURES_MAX);
    for _ in 0..limit {
        assert_eq!(
            bad_token_from(tailnet, Some("127.0.0.1".parse().unwrap())),
            401
        );
    }
    assert_eq!(
        bad_token_from(tailnet, Some("127.0.0.1".parse().unwrap())),
        429
    );
    assert_eq!(bad_token_from(local, None), 401);
}

/// One request on a new connection to `listener`, written down as the front writes down
/// a stream of the Connect tunnel (`front_peers::register_tunnel`) when `tunnel`, else as
/// a connection without the front. Returns the status.
fn request_via(listener: SocketAddr, tunnel: bool, head: &str, body: &str) -> u16 {
    let mut stream = TcpStream::connect(listener).expect("connect");
    let _entry = tunnel.then(|| {
        front_peers::register_tunnel(
            stream.local_addr().expect("local"),
            stream.peer_addr().expect("peer"),
        )
    });
    write!(
        stream,
        "{head}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {answer:?}"))
}

fn bad_mcp(forwarded_for: &str) -> String {
    format!(
        "POST /mcp HTTP/1.1\r\nHost: k7m2q4x3ca.node.example.test\r\nAuthorization: Bearer apr_bad\r\nContent-Type: application/json\r\nX-Forwarded-For: {forwarded_for}\r\n"
    )
}

#[test]
fn a_tunnel_stream_is_in_no_failed_auth_count_and_its_forwarded_for_is_not_read() {
    let node = Node::start(NodeOptions::default());
    let public = node
        .node()
        .running()
        .public_addr
        .expect("a public listener");
    // More bad tokens through the tunnel than the shared count takes, with changing and
    // with fixed X-Forwarded-For values: every one is answered, none is held at 429.
    let shared = apassy_relay::server::http::AGENT_SHARED_FAILURES_MAX as usize;
    for n in 0..shared + 20 {
        let forwarded = if n % 2 == 0 {
            "203.0.113.9".to_string()
        } else {
            format!("198.51.100.{}", n % 250)
        };
        assert_eq!(
            request_via(public, true, &bad_mcp(&forwarded), "{}"),
            401,
            "{n}"
        );
    }
    // Funnel's connections keep their count by source address: the tunnel's failures
    // were in no count, so this source starts at zero and reaches 429 at its 21st.
    for n in 0..AUTH_FAILURES_MAX {
        assert_eq!(
            request_via(public, false, &bad_mcp("203.0.113.9"), "{}"),
            401,
            "{n}"
        );
    }
    assert_eq!(
        request_via(public, false, &bad_mcp("203.0.113.9"), "{}"),
        429
    );
    // A tunnel stream that names that source is still answered.
    assert_eq!(
        request_via(public, true, &bad_mcp("203.0.113.9"), "{}"),
        401
    );
}

#[test]
fn a_device_stream_of_the_tunnel_reaches_no_team_code_invite_or_join_route() {
    let node = Node::start(NodeOptions::default());
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    let head = |method: &str, path: &str| {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 100.64.0.7:8444\r\nContent-Type: application/json\r\n"
        )
    };
    for (method, path) in [
        ("POST", "/v1/teams"),
        ("POST", "/v1/join"),
        ("POST", "/v1/invites"),
        ("GET", "/v1/invites"),
    ] {
        assert_eq!(
            request_via(tailnet, true, &head(method, path), "{}"),
            404,
            "{method} {path} through the tunnel"
        );
        assert_ne!(
            request_via(tailnet, false, &head(method, path), "{}"),
            404,
            "{method} {path} on the tailnet"
        );
    }
    // The device routes stay: a sign-in challenge and a device link (pairing through
    // Connect) are answered, not 404.
    for (method, path) in [("POST", "/v1/auth/challenge"), ("POST", "/v1/devices/link")] {
        assert_ne!(
            request_via(tailnet, true, &head(method, path), "{}"),
            404,
            "{method} {path} through the tunnel"
        );
    }
}

/// `GET /v1/me` with `token` on a new connection to `listener`, written down as a `device`
/// stream of the Connect tunnel. Returns the status.
fn me_via_tunnel(listener: SocketAddr, token: &str) -> u16 {
    let head = format!(
        "GET /v1/me HTTP/1.1\r\nHost: 100.64.0.7:8444\r\nAuthorization: Bearer {token}\r\n"
    );
    request_via(listener, true, &head, "")
}

#[test]
fn the_device_streams_of_the_tunnel_have_a_count_of_the_node_apart_from_the_peers() {
    let node = Node::start(NodeOptions::default());
    let (_team, mac) = node.device_team("Approvals");
    let tailnet = node.node().tailnet_addr().expect("a tailnet listener");
    // Each request here is a stream of its own, far below the count of one stream
    // (TUNNEL_STREAM_FAILURES_MAX): only the count of the node holds them.
    for n in 0..TUNNEL_DEVICE_FAILURES_MAX {
        assert_eq!(me_via_tunnel(tailnet, "apr_bad"), 401, "{n}");
    }
    // At it every device stream of the tunnel is held, a good token too, until the
    // window ends.
    assert_eq!(me_via_tunnel(tailnet, "apr_bad"), 429);
    assert_eq!(me_via_tunnel(tailnet, &mac.token), 429);
    // The tailnet peers and the Mac's local route keep their own counts: the tunnel's
    // failures are in none of them.
    let peer: IpAddr = "100.64.0.21".parse().unwrap();
    assert_eq!(bad_token_from(tailnet, Some(peer)), 401);
    let base = node.local_route();
    let me = node.ok(&base, "GET", "/v1/me", Some(&mac.token), None);
    assert_eq!(me["device_id"].as_u64(), Some(mac.id));
    // The audit row names the count of the node, and no address.
    let limited: Vec<_> = node
        .relay_audit()
        .into_iter()
        .filter(|(action, _)| action == "rate_limited")
        .collect();
    assert!(
        limited
            .iter()
            .any(|(_, detail)| detail.contains("\"bucket\":\"tunnel_node\"")),
        "{limited:?}"
    );
    assert!(
        limited
            .iter()
            .all(|(_, detail)| !detail.contains("\"peer\"")),
        "{limited:?}"
    );
}
