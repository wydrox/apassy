//! Live sessions through `SessionSource`: find, expiry, revocation, and the audit of
//! proxied requests.

#[path = "common/relay.rs"]
mod relay;

use std::time::Duration;

use apassy_relay::config::UpstreamOptions;
use apassy_relay::ids::{AgentId, RunId, SessionId};
use apassy_relay::now_unix;
use apassy_relay::session::{ProxyEvent, ProxyOutcome};
use relay::{CANARY, CANARY2, Team, TestRelay, start, start_with};
use serde_json::{Value, json};

const USER: &str = "Please check the repository state.";

/// The session key in the base URLs of a run view.
fn key_of(view: &Value) -> String {
    let base = view["session"]["env"]["STRIPE_API_BASE"].as_str().unwrap();
    base.split("/p/")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string()
}

/// A ready run with the Stripe item: the agent asks, the host releases. Returns the
/// run id, the session key, and the view the agent gets.
fn ready_run(relay: &TestRelay, team: &Team) -> (u64, String, Value) {
    let view = relay.run_released(
        &team.agent_token,
        &team.request(&["git", "status"], Some(USER)),
    );
    assert_eq!(view["status"], "ready");
    (view["run_id"].as_u64().unwrap(), key_of(&view), view)
}

fn status_of(relay: &TestRelay, team: &Team, run: u64) -> String {
    let view = relay.ok("GET", &format!("/v1/runs/{run}"), &team.agent_token, None);
    view["status"].as_str().unwrap().to_string()
}

#[test]
fn find_returns_the_live_session_by_its_key() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (run, key, view) = ready_run(&relay, &team);
    let source = relay.sessions();
    let now = now_unix();
    let session = source.find(&key, now).expect("a live session");
    assert_eq!(session.run_id, RunId(run));
    assert_eq!(session.agent_id, AgentId(team.agent_id));
    assert_eq!(session.member_id.0, team.member_id);
    assert_eq!(session.secrets.len(), 1);
    let secret = &session.secrets[0];
    assert_eq!(secret.env_name, "STRIPE_API_KEY");
    assert_eq!(secret.value.expose(), CANARY);
    assert_eq!(
        secret.placeholder.expose(),
        view["session"]["env"]["STRIPE_API_KEY"].as_str().unwrap()
    );
    assert_ne!(secret.placeholder, secret.value);
    assert!(session.covers_host("api.stripe.com", 443));
    assert!(session.covers_host("files.stripe.com", 443));
    assert!(!session.covers_host("api.stripe.com", 8443));
    assert!(!session.covers_host("evil.example", 443));
    assert_eq!(
        session.expires_at,
        view["session"]["expires_at"].as_u64().unwrap()
    );
    assert_eq!(
        view["session"]["session_id"].as_u64().unwrap(),
        session.id.0
    );
    // Debug never shows the value or the placeholder.
    let shown = format!("{session:?}");
    assert!(!shown.contains(CANARY) && !shown.contains(secret.placeholder.expose()));
}

#[test]
fn find_refuses_unknown_malformed_and_wrong_kind_keys() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, key, _) = ready_run(&relay, &team);
    let source = relay.sessions();
    let now = now_unix();
    assert!(
        source
            .find(&format!("apassy_ses_{}", "0".repeat(64)), now)
            .is_none()
    );
    assert!(source.find("apassy_ses_short", now).is_none());
    assert!(source.find("", now).is_none());
    assert!(source.find(&team.agent_token, now).is_none());
    assert!(source.find(&relay.owner_token, now).is_none());
    assert!(source.find(&key.to_uppercase(), now).is_none());
    assert!(source.find(&key, now).is_some());
}

#[test]
fn find_is_none_after_the_expiry() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, key, view) = ready_run(&relay, &team);
    let expires = view["session"]["expires_at"].as_u64().unwrap();
    let source = relay.sessions();
    assert!(source.find(&key, expires - 1).is_some());
    assert!(source.find(&key, expires).is_none());
    assert!(source.find(&key, expires + 1000).is_none());
}

#[test]
fn a_run_shows_ended_after_the_session_expires() {
    let relay = start_with(
        |config| config.session_ttl_secs = 3,
        UpstreamOptions::default(),
    );
    let team = relay.setup("staging");
    let (run, key, _) = ready_run(&relay, &team);
    assert_eq!(status_of(&relay, &team, run), "ready");
    std::thread::sleep(Duration::from_millis(4200));
    assert!(relay.sessions().find(&key, now_unix()).is_none());
    let view = relay.ok("GET", &format!("/v1/runs/{run}"), &team.agent_token, None);
    assert_eq!(view["status"], "ended");
    assert!(view.get("session").is_none());
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let ended: Vec<&Value> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "session_ended")
        .collect();
    assert_eq!(ended.len(), 1, "{audit}");
    assert_eq!(ended[0]["detail"]["reason"], "expired");
}

#[test]
fn revoking_the_agent_ends_its_sessions() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (run, key, _) = ready_run(&relay, &team);
    let second = relay.ok(
        "POST",
        "/v1/agents",
        &team.member_token,
        Some(&json!({"name": "second"})),
    );
    let other_view = relay.run_released(
        second["secret"].as_str().unwrap(),
        &team.request(&["git", "status"], Some(USER)),
    );
    let other_key = key_of(&other_view);
    let source = relay.sessions();
    assert!(source.find(&key, now_unix()).is_some());
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", team.agent_id),
        &relay.owner_token,
        None,
    );
    assert!(source.find(&key, now_unix()).is_none());
    assert!(
        source.find(&other_key, now_unix()).is_some(),
        "the other agent keeps its session"
    );
    // The run of the revoked agent ended; the token is gone, so read it as the owner would see it: through the audit.
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let ended = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == "session_ended" && r["run_id"] == run)
        .expect("session_ended row");
    assert_eq!(ended["detail"]["reason"], "agent_revoked");
}

#[test]
fn revoking_the_grant_ends_the_sessions_of_that_member_only() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, bob) = relay.join_member("member", "bob");
    let bob_id = relay.ok("GET", "/v1/me", &bob, None)["member_id"]
        .as_u64()
        .unwrap();
    relay.ok(
        "POST",
        "/v1/grants",
        &relay.owner_token,
        Some(&json!({"collection_id": team.collection, "member_id": bob_id})),
    );
    let bobs_agent = relay.ok("POST", "/v1/agents", &bob, Some(&json!({"name": "b"})));
    let bobs_token = bobs_agent["secret"].as_str().unwrap();
    let (_, alice_key, _) = ready_run(&relay, &team);
    let bob_view = relay.run_released(bobs_token, &team.request(&["git", "status"], Some(USER)));
    let bob_key = key_of(&bob_view);
    let source = relay.sessions();
    relay.ok(
        "DELETE",
        &format!("/v1/grants/{}", team.grant),
        &relay.owner_token,
        None,
    );
    assert!(source.find(&alice_key, now_unix()).is_none());
    assert!(
        source.find(&bob_key, now_unix()).is_some(),
        "bob's grant is untouched"
    );
    // Alice can not start a new run, bob can.
    relay.fails(
        "POST",
        "/v1/runs",
        Some(&team.agent_token),
        Some(&team.request(&["git", "status"], Some(USER))),
        403,
        "not_granted",
    );
    assert_eq!(
        relay
            .run(bobs_token, &team.request(&["git", "status"], Some(USER)))
            .0,
        200
    );
}

#[test]
fn a_grant_of_another_collection_does_not_end_a_session() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let other = relay.add_collection("other", json!({}));
    relay.add_item(
        other,
        "OTHER_KEY",
        CANARY2,
        json!({"hosts": ["api.example.com"], "environment": "staging"}),
    );
    let grant = relay.ok(
        "POST",
        "/v1/grants",
        &relay.owner_token,
        Some(&json!({"collection_id": other, "member_id": team.member_id})),
    );
    let (_, key, _) = ready_run(&relay, &team);
    relay.ok(
        "DELETE",
        &format!("/v1/grants/{}", grant["id"]),
        &relay.owner_token,
        None,
    );
    assert!(relay.sessions().find(&key, now_unix()).is_some());
}

#[test]
fn revoking_the_member_ends_the_sessions() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, key, _) = ready_run(&relay, &team);
    relay.ok(
        "DELETE",
        &format!("/v1/members/{}", team.member_id),
        &relay.owner_token,
        None,
    );
    assert!(relay.sessions().find(&key, now_unix()).is_none());
}

#[test]
fn archiving_the_item_ends_the_sessions_that_hold_it() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let spare = relay.add_item(
        team.collection,
        "SPARE_KEY",
        CANARY2,
        json!({"hosts": ["api.example.com"], "environment": "staging"}),
    );
    let (run, key, _) = ready_run(&relay, &team);
    relay.ok(
        "DELETE",
        &format!("/v1/items/{spare}"),
        &relay.owner_token,
        None,
    );
    assert!(
        relay.sessions().find(&key, now_unix()).is_some(),
        "another item does not end it"
    );
    assert_eq!(status_of(&relay, &team, run), "ready");
    relay.ok(
        "DELETE",
        &format!("/v1/items/{}", team.item),
        &relay.owner_token,
        None,
    );
    assert!(relay.sessions().find(&key, now_unix()).is_none());
    assert_eq!(status_of(&relay, &team, run), "ended");
}

#[test]
fn each_run_gets_its_own_key_and_placeholder() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, key_a, view_a) = ready_run(&relay, &team);
    let (_, key_b, view_b) = ready_run(&relay, &team);
    assert_ne!(key_a, key_b);
    assert_ne!(
        view_a["session"]["env"]["STRIPE_API_KEY"],
        view_b["session"]["env"]["STRIPE_API_KEY"]
    );
    assert_ne!(
        view_a["session"]["session_id"],
        view_b["session"]["session_id"]
    );
    let source = relay.sessions();
    let a = source.find(&key_a, now_unix()).unwrap();
    let b = source.find(&key_b, now_unix()).unwrap();
    assert_ne!(a.secrets[0].placeholder, b.secrets[0].placeholder);
}

#[test]
fn record_writes_a_proxy_request_row_with_no_secret() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (run, key, view) = ready_run(&relay, &team);
    let placeholder = view["session"]["env"]["STRIPE_API_KEY"]
        .as_str()
        .unwrap()
        .to_string();
    let source = relay.sessions();
    let now = now_unix();
    source.record(ProxyEvent {
        session_id: Some(SessionId(1)),
        run_id: Some(RunId(run)),
        agent_id: Some(AgentId(team.agent_id)),
        at: now,
        method: "GET".into(),
        host: "api.stripe.com".into(),
        path: Some("/v1/balance".into()),
        status: 200,
        outcome: ProxyOutcome::Forwarded,
        code: None,
        swapped: vec!["STRIPE_API_KEY".into()],
    });
    source.record(ProxyEvent {
        session_id: None,
        run_id: None,
        agent_id: None,
        at: now,
        method: "POST".into(),
        host: "evil.example".into(),
        // A hostile path that holds the key, a placeholder, and the value.
        path: Some(format!("/{key}/{placeholder}/{CANARY}")),
        status: 403,
        outcome: ProxyOutcome::Refused,
        code: Some("session_invalid".into()),
        swapped: vec![],
    });
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let rows: Vec<&Value> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "proxy_request")
        .collect();
    assert_eq!(rows.len(), 2, "{audit}");
    assert_eq!(rows[0]["actor"], format!("agent:{}", team.agent_id));
    assert_eq!(rows[0]["run_id"], run);
    assert_eq!(rows[0]["detail"]["method"], "GET");
    assert_eq!(rows[0]["detail"]["host"], "api.stripe.com");
    assert_eq!(rows[0]["detail"]["path"], "/v1/balance");
    assert_eq!(rows[0]["detail"]["status"], 200);
    assert_eq!(rows[0]["detail"]["swapped"], json!(["STRIPE_API_KEY"]));
    assert_eq!(rows[1]["actor"], "relay");
    assert_eq!(rows[1]["detail"]["code"], "session_invalid");
    let text = audit.to_string();
    for secret in [CANARY, placeholder.as_str(), key.as_str()] {
        assert!(!text.contains(secret), "the audit holds a secret");
    }
}

#[test]
fn stop_ends_every_session_and_closes_the_port() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, key, _) = ready_run(&relay, &team);
    let source = relay.sessions();
    let url = relay.url.clone();
    assert!(source.find(&key, now_unix()).is_some());
    relay.stop();
    assert!(source.find(&key, now_unix()).is_none());
    let addr = url.trim_start_matches("http://");
    assert!(
        std::net::TcpStream::connect(addr).is_err(),
        "the port is closed"
    );
}
