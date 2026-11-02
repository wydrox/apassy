//! `APASSY_RELAY_TEAM_VAULTS=0` (ADR 0037, D8): the hosted relay refuses shared team
//! vaults, runs, MCP, and the proxy, and keeps devices, relay sync, questions, feed, and
//! push.

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::config::UpstreamOptions;
use relay::{start, start_with};
use serde_json::json;

const RETIRED: &str = "team_vaults_retired";

/// Every team-vault request, with any or no token: 410 before any token check.
#[test]
fn team_vault_requests_are_retired() {
    let relay = start_with(
        |config| config.team_vaults = false,
        UpstreamOptions::default(),
    );
    let owner = relay.owner_token.clone();
    let body = json!({});
    for (method, path) in [
        ("POST", "/v1/runs"),
        ("GET", "/v1/runs/1"),
        ("GET", "/v1/access"),
        ("POST", "/mcp"),
        ("GET", "/v1/host/requests"),
        ("POST", "/v1/host/requests/1/release"),
        ("POST", "/v1/host/requests/1/deny"),
        ("POST", "/v1/collections"),
        ("PUT", "/v1/collections/1/policy"),
        ("POST", "/v1/items"),
        ("POST", "/v1/grants"),
        ("POST", "/v1/agents"),
    ] {
        for token in [Some(owner.as_str()), Some("apassy_tagt_t_unknown_00"), None] {
            relay.fails(method, path, token, Some(&body), 410, RETIRED);
        }
    }
}

#[test]
fn the_proxy_is_retired() {
    let relay = start_with(
        |config| config.team_vaults = false,
        UpstreamOptions::default(),
    );
    for path in ["/p/apassy_ses_x/api.example.com/v1/charges", "/p/anything"] {
        relay.fails("GET", path, None, None, 410, RETIRED);
        relay.fails("POST", path, None, Some(&json!({})), 410, RETIRED);
    }
}

/// What a team needs to see and clean up, and what relay sync, questions, feed, and push
/// use, still routes: no 410.
#[test]
fn identity_sync_questions_and_cleanup_go_on() {
    let relay = start_with(
        |config| config.team_vaults = false,
        UpstreamOptions::default(),
    );
    let owner = relay.owner_token.clone();
    relay.ok("GET", "/v1/me", &owner, None);
    relay.ok("GET", "/v1/collections", &owner, None);
    relay.ok("GET", "/v1/items", &owner, None);
    relay.ok("GET", "/v1/grants", &owner, None);
    relay.ok("GET", "/v1/agents", &owner, None);
    relay.ok("GET", "/v1/audit", &owner, None);
    for (method, path) in [
        ("GET", "/v1/devices"),
        ("GET", "/v1/sync/head"),
        ("GET", "/v1/sync/snapshot"),
        ("GET", "/v1/questions"),
        ("POST", "/v1/questions"),
        ("PUT", "/v1/push/token"),
        ("GET", "/v1/feed"),
        ("DELETE", "/v1/items/1"),
        ("DELETE", "/v1/agents/1"),
        ("DELETE", "/v1/grants/1"),
    ] {
        let (status, value) = relay.call(method, path, Some(&owner), Some(&json!({})));
        assert_ne!(status, 410, "{method} {path}: {value}");
        assert_ne!(value["error"]["code"], RETIRED, "{method} {path}: {value}");
    }
    let (status, _) = relay.call_no_edge("GET", "/healthz");
    assert_eq!(status, 200);
}

/// The default (a user's own node, and every other test): team vaults are served.
#[test]
fn team_vaults_stay_on_by_default() {
    let relay = start(UpstreamOptions::default());
    let collection = relay.add_collection("payments", json!({}));
    assert!(collection > 0);
    let (status, value) = relay.call("POST", "/v1/runs", None, Some(&json!({})));
    assert_ne!(status, 410, "{value}");
}
