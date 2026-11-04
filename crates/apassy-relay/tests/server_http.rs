//! The edge, the tokens and roles, the invites, and the shape of the HTTP layer.

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::config::UpstreamOptions;
use relay::{CANARY, start};
use serde_json::json;

fn fake_token(prefix: &str) -> String {
    format!("{prefix}{}", "ab".repeat(32))
}

#[test]
fn edge_header_is_required_everywhere_except_healthz() {
    let relay = start(UpstreamOptions::default());
    for (method, path) in [
        ("GET", "/v1/me"),
        ("POST", "/v1/join"),
        ("POST", "/mcp"),
        ("GET", "/p/apassy_ses_x/api.stripe.com/v1"),
        ("GET", "/no/such/path"),
        ("GET", "/healthz/"),
    ] {
        let (status, body) = relay.call_no_edge(method, path);
        assert_eq!(status, 403, "{method} {path}");
        assert_eq!(body["error"]["code"], "edge_refused", "{method} {path}");
        assert_eq!(body["ok"], false);
    }
    // A wrong header of the right length, of another length, and an empty one.
    for wrong in [
        "x".repeat(relay.edge_secret.len()),
        "x".to_string(),
        String::new(),
    ] {
        let (status, body) = relay::call_url(
            &relay.url,
            Some(&wrong),
            "GET",
            "/v1/me",
            Some(&relay.owner_token),
            None,
        );
        assert_eq!(status, 403);
        assert_eq!(body["error"]["code"], "edge_refused");
    }
    let (status, _) = relay::call_url(&relay.url, None, "GET", "/healthz", None, None);
    assert_eq!(status, 200);
    // With the header everything works.
    relay.ok("GET", "/v1/me", &relay.owner_token, None);
}

#[test]
fn edge_refusals_leave_at_most_one_audit_row_and_no_secret() {
    let relay = start(UpstreamOptions::default());
    for _ in 0..8 {
        relay.call_no_edge("GET", "/v1/me");
    }
    // A request without the edge header names no team: it goes to the audit of the
    // relay, at most one row, and never to a team.
    let audit = relay.ok("GET", "/v1/audit", &relay.owner_token, None);
    assert!(!audit.to_string().contains("\"actor\":\"edge\""), "{audit}");
    let rows = relay.relay_audit();
    let edge: Vec<_> = rows.iter().filter(|r| r.0 == "edge").collect();
    assert_eq!(edge.len(), 1, "{rows:?}");
    assert_eq!(edge[0].1, "auth_failed");
    assert!(!format!("{rows:?}").contains(&relay.edge_secret));
}

#[test]
fn every_response_is_an_envelope_with_no_store() {
    let relay = start(UpstreamOptions::default());
    let (status, text) =
        relay.call_with_headers("GET", "/v1/me", Some(&relay.owner_token), &[], None);
    assert_eq!(status, 200);
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["ok"], true);
    assert!(value["result"]["team"].is_string());
    // Headers, through a raw request.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let response = agent
        .get(&format!("{}/v1/me", relay.url))
        .header("X-Apassy-Edge", &relay.edge_secret)
        .header("Authorization", format!("Bearer {}", relay.owner_token))
        .call()
        .unwrap();
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let missing = agent
        .get(&format!("{}/v1/me", relay.url))
        .header("X-Apassy-Edge", &relay.edge_secret)
        .call()
        .unwrap();
    assert_eq!(missing.status().as_u16(), 401);
    assert_eq!(missing.headers().get("cache-control").unwrap(), "no-store");
}

#[test]
fn unknown_path_is_404_and_wrong_method_is_405() {
    let relay = start(UpstreamOptions::default());
    relay.fails(
        "GET",
        "/v1/nothing",
        Some(&relay.owner_token),
        None,
        404,
        "not_found",
    );
    relay.fails("GET", "/", None, None, 404, "not_found");
    relay.fails(
        "GET",
        "/v1/runs/abc",
        Some(&relay.owner_token),
        None,
        404,
        "not_found",
    );
    relay.fails("GET", "/v1/join", None, None, 405, "method_not_allowed");
    relay.fails("PATCH", "/v1/me", None, None, 405, "method_not_allowed");
    relay.fails("POST", "/v1/members", None, None, 405, "method_not_allowed");
}

#[test]
fn a_big_body_is_413_and_the_relay_goes_on() {
    let relay = start(UpstreamOptions::default());
    let big = json!({"name": "x".repeat(70 * 1024)});
    relay.fails(
        "POST",
        "/v1/collections",
        Some(&relay.owner_token),
        Some(&big),
        413,
        "payload_too_large",
    );
    relay.ok("GET", "/v1/me", &relay.owner_token, None);
}

#[test]
fn a_bad_body_is_400_and_never_echoes_a_value() {
    let relay = start(UpstreamOptions::default());
    let collection = relay.add_collection("c", json!({}));
    // The value has the wrong type: the error must not print it.
    let bad = json!({"collection_id": collection, "name": "n", "env_name": "K_KEY", "sealed": 5, "value": CANARY, "environment": "staging", "note": CANARY});
    let (status, body) = relay.call("POST", "/v1/items", Some(&relay.owner_token), Some(&bad));
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(!body.to_string().contains(CANARY), "{body}");
    // Not JSON at all.
    let (status, text) = relay.call_with_headers(
        "POST",
        "/v1/collections",
        Some(&relay.owner_token),
        &[],
        None,
    );
    assert_eq!(status, 400, "{text}");
    // Unknown fields are refused where the type says so.
    relay.fails(
        "POST",
        "/v1/collections",
        Some(&relay.owner_token),
        Some(&json!({"name": "d", "extra": 1})),
        400,
        "invalid_request",
    );
}

/// Every endpoint with a token of the wrong kind, no token, or a token that is not known.
#[test]
fn endpoints_refuse_missing_wrong_kind_and_unknown_tokens() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let member_endpoints = [
        ("GET", "/v1/collections"),
        ("GET", "/v1/items"),
        ("POST", "/v1/agents"),
        ("GET", "/v1/agents"),
        ("DELETE", "/v1/agents/1"),
    ];
    let approver_endpoints = [
        ("POST", "/v1/invites"),
        ("GET", "/v1/invites"),
        ("GET", "/v1/members"),
        ("DELETE", "/v1/members/2"),
        ("POST", "/v1/collections"),
        ("PUT", "/v1/collections/1/policy"),
        ("POST", "/v1/items"),
        ("DELETE", "/v1/items/1"),
        ("POST", "/v1/grants"),
        ("GET", "/v1/grants"),
        ("DELETE", "/v1/grants/1"),
        ("GET", "/v1/approvals"),
        ("POST", "/v1/approvals/1/approve"),
        ("POST", "/v1/approvals/1/deny"),
        ("GET", "/v1/audit"),
        ("GET", "/v1/host/requests"),
        ("POST", "/v1/host/requests/1/release"),
        ("POST", "/v1/host/requests/1/deny"),
    ];
    let agent_endpoints = [
        ("GET", "/v1/access"),
        ("POST", "/v1/runs"),
        ("GET", "/v1/runs/1"),
        ("POST", "/mcp"),
    ];
    let unknown_member = fake_token("apassy_mbr_");
    let unknown_agent = fake_token("apassy_agt_");
    let session_shaped = fake_token("apassy_ses_");
    let invite_shaped = fake_token("apassy_inv_");
    for (method, path) in member_endpoints.iter().chain(&approver_endpoints) {
        relay.fails(method, path, None, None, 401, "unauthenticated");
        relay.fails(
            method,
            path,
            Some(&unknown_member),
            None,
            401,
            "unauthenticated",
        );
        relay.fails(
            method,
            path,
            Some(&session_shaped),
            None,
            401,
            "unauthenticated",
        );
        relay.fails(
            method,
            path,
            Some(&invite_shaped),
            None,
            401,
            "unauthenticated",
        );
        relay.fails(method, path, Some("garbage"), None, 401, "unauthenticated");
        // An agent token is the wrong kind for a member endpoint.
        relay.fails(
            method,
            path,
            Some(&team.agent_token),
            None,
            401,
            "unauthenticated",
        );
    }
    for (method, path) in &agent_endpoints {
        relay.fails(method, path, None, None, 401, "unauthenticated");
        relay.fails(
            method,
            path,
            Some(&unknown_agent),
            None,
            401,
            "unauthenticated",
        );
        // A member token, even the owner's, is the wrong kind.
        relay.fails(
            method,
            path,
            Some(&relay.owner_token),
            None,
            401,
            "unauthenticated",
        );
        relay.fails(
            method,
            path,
            Some(&team.member_token),
            None,
            401,
            "unauthenticated",
        );
    }
    relay.fails("GET", "/v1/me", None, None, 401, "unauthenticated");
    relay.fails(
        "GET",
        "/v1/me",
        Some(&unknown_agent),
        None,
        401,
        "unauthenticated",
    );
    // Both kinds work on /v1/me.
    let me = relay.ok("GET", "/v1/me", &team.agent_token, None);
    assert_eq!(me["kind"], "agent");
    assert_eq!(me["member_name"], "alice");
    assert_eq!(me["agent_name"], "alice-agent");
    let me = relay.ok("GET", "/v1/me", &team.member_token, None);
    assert_eq!(me["kind"], "member");
    assert_eq!(me["role"], "member");
}

#[test]
fn a_plain_member_cannot_do_what_approvers_do() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let token = Some(team.member_token.as_str());
    for (method, path) in [
        ("POST", "/v1/invites"),
        ("GET", "/v1/invites"),
        ("GET", "/v1/members"),
        ("POST", "/v1/collections"),
        ("PUT", "/v1/collections/1/policy"),
        ("POST", "/v1/items"),
        ("DELETE", "/v1/items/1"),
        ("POST", "/v1/grants"),
        ("GET", "/v1/grants"),
        ("DELETE", "/v1/grants/1"),
        ("GET", "/v1/approvals"),
        ("POST", "/v1/approvals/1/approve"),
        ("POST", "/v1/approvals/1/deny"),
        ("GET", "/v1/audit"),
        ("DELETE", "/v1/members/1"),
        ("GET", "/v1/host/requests"),
        ("POST", "/v1/host/requests/1/release"),
        ("POST", "/v1/host/requests/1/deny"),
    ] {
        relay.fails(method, path, token, None, 403, "forbidden");
    }
    // What a member may do.
    relay.ok("GET", "/v1/collections", &team.member_token, None);
    relay.ok("GET", "/v1/agents", &team.member_token, None);
    relay.ok(
        "POST",
        "/v1/agents",
        &team.member_token,
        Some(&json!({"name": "second"})),
    );
}

#[test]
fn a_manager_works_but_cannot_invite_a_manager_or_revoke() {
    let relay = start(UpstreamOptions::default());
    let (manager_id, manager) = relay.join_member("manager", "maria");
    // A manager adds a collection, an item, and reads the audit.
    let created = relay.ok(
        "POST",
        "/v1/collections",
        &manager,
        Some(&json!({"name": "ops"})),
    );
    let collection = created["id"].as_u64().unwrap();
    let sealed = relay::seal(CANARY);
    relay.ok(
        "POST",
        "/v1/items",
        &manager,
        Some(&relay::item_request(
            collection,
            "OPS_TOKEN",
            &sealed,
            json!({"hosts": ["api.example.com"], "environment": "staging"}),
        )),
    );
    relay.ok("GET", "/v1/audit", &manager, None);
    relay.ok("GET", "/v1/members", &manager, None);
    relay.ok(
        "POST",
        "/v1/invites",
        &manager,
        Some(&json!({"role": "member"})),
    );
    // But not a manager invite, and not a revoke.
    relay.fails(
        "POST",
        "/v1/invites",
        Some(&manager),
        Some(&json!({"role": "manager"})),
        403,
        "forbidden",
    );
    relay.fails(
        "DELETE",
        &format!("/v1/members/{manager_id}"),
        Some(&manager),
        None,
        403,
        "forbidden",
    );
    relay.fails(
        "DELETE",
        "/v1/members/1",
        Some(&manager),
        None,
        403,
        "forbidden",
    );
}

#[test]
fn the_last_owner_cannot_revoke_themselves() {
    let relay = start(UpstreamOptions::default());
    let members = relay.ok("GET", "/v1/members", &relay.owner_token, None);
    let owner_id = members[0]["id"].as_u64().unwrap();
    assert_eq!(members[0]["role"], "owner");
    relay.fails(
        "DELETE",
        &format!("/v1/members/{owner_id}"),
        Some(&relay.owner_token),
        None,
        409,
        "conflict",
    );
    relay.ok("GET", "/v1/me", &relay.owner_token, None);
}

#[test]
fn revoked_member_loses_the_token_and_the_agents() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    relay.ok("GET", "/v1/me", &team.member_token, None);
    relay.ok("GET", "/v1/access", &team.agent_token, None);
    relay.ok(
        "DELETE",
        &format!("/v1/members/{}", team.member_id),
        &relay.owner_token,
        None,
    );
    relay.fails(
        "GET",
        "/v1/me",
        Some(&team.member_token),
        None,
        401,
        "unauthenticated",
    );
    relay.fails(
        "GET",
        "/v1/access",
        Some(&team.agent_token),
        None,
        401,
        "unauthenticated",
    );
    // Revoking again finds nothing.
    relay.fails(
        "DELETE",
        &format!("/v1/members/{}", team.member_id),
        Some(&relay.owner_token),
        None,
        404,
        "not_found",
    );
    let members = relay.ok("GET", "/v1/members", &relay.owner_token, None);
    assert!(
        members
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["revoked"] == true)
    );
    let grants = relay.ok("GET", "/v1/grants", &relay.owner_token, None);
    assert_eq!(
        grants.as_array().unwrap().len(),
        0,
        "the grant is revoked with the member"
    );
}

#[test]
fn a_revoked_agent_stops_and_only_the_owner_of_an_agent_or_an_approver_revokes() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, bob) = relay.join_member("member", "bob");
    relay.fails(
        "DELETE",
        &format!("/v1/agents/{}", team.agent_id),
        Some(&bob),
        None,
        404,
        "not_found",
    );
    relay.ok("GET", "/v1/access", &team.agent_token, None);
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", team.agent_id),
        &team.member_token,
        None,
    );
    relay.fails(
        "GET",
        "/v1/access",
        Some(&team.agent_token),
        None,
        401,
        "unauthenticated",
    );
    // An approver revokes any agent.
    let agent = relay.ok("POST", "/v1/agents", &bob, Some(&json!({"name": "b"})));
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", agent["id"]),
        &relay.owner_token,
        None,
    );
    relay.fails(
        "GET",
        "/v1/access",
        agent["secret"].as_str(),
        None,
        401,
        "unauthenticated",
    );
    // A member lists only their own agents; the owner sees all.
    let mine = relay.ok("GET", "/v1/agents", &bob, None);
    assert_eq!(mine.as_array().unwrap().len(), 1);
    let all = relay.ok("GET", "/v1/agents", &relay.owner_token, None);
    assert_eq!(all.as_array().unwrap().len(), 2);
}

#[test]
fn an_expired_agent_token_says_token_expired() {
    let mut relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    relay.edit_vault("UPDATE agent SET expires_at = 1");
    relay.fails(
        "GET",
        "/v1/access",
        Some(&team.agent_token),
        None,
        401,
        "token_expired",
    );
    relay.fails(
        "POST",
        "/v1/runs",
        Some(&team.agent_token),
        Some(&team.request(&["git", "status"], Some("x"))),
        401,
        "token_expired",
    );
    // A restart ends the device access token.
    relay.fails(
        "GET",
        "/v1/me",
        Some(&team.member_token),
        None,
        401,
        "unauthenticated",
    );
}

#[test]
fn agent_lifetime_is_1_to_365_days() {
    let relay = start(UpstreamOptions::default());
    let (_, token) = relay.join_member("member", "carol");
    for days in [0, 366] {
        relay.fails(
            "POST",
            "/v1/agents",
            Some(&token),
            Some(&json!({"name": "a", "days": days})),
            400,
            "invalid_request",
        );
    }
    let one = relay.ok(
        "POST",
        "/v1/agents",
        &token,
        Some(&json!({"name": "a", "days": 1})),
    );
    let default = relay.ok("POST", "/v1/agents", &token, Some(&json!({"name": "a"})));
    let long = relay.ok(
        "POST",
        "/v1/agents",
        &token,
        Some(&json!({"name": "a", "days": 365})),
    );
    let day = |v: &serde_json::Value| v["expires_at"].as_u64().unwrap();
    assert!(day(&one) < day(&default) && day(&default) < day(&long));
    assert!((day(&long) - day(&one)).abs_diff(364 * 86_400) < 5);
    assert!(
        default["secret"]
            .as_str()
            .unwrap()
            .starts_with("apassy_tagt_t_")
    );
    relay.fails(
        "POST",
        "/v1/agents",
        Some(&token),
        Some(&json!({"name": ""})),
        400,
        "invalid_request",
    );
}

#[test]
fn an_invite_works_once() {
    let relay = start(UpstreamOptions::default());
    let invite = relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "member"})),
    );
    let code = invite["secret"].as_str().unwrap();
    assert!(code.starts_with("apassy_inv_"));
    assert!(invite["expires_at"].as_u64().unwrap() > 0);
    let key = apassy_relay::device::DeviceKey::generate().unwrap();
    let joined = relay.ok(
        "POST",
        "/v1/join",
        "",
        Some(
            &json!({"code": code, "name": "dave", "device_name": "Dave device",
            "public_key": key.public_key_b64()}),
        ),
    );
    assert!(joined.get("secret").is_none());
    let other_key = apassy_relay::device::DeviceKey::generate().unwrap();
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(
            &json!({"code": code, "name": "erin", "device_name": "Erin device",
            "public_key": other_key.public_key_b64()}),
        ),
        403,
        "invite_invalid",
    );
    let confirmed = relay.ok(
        "POST",
        &format!("/v1/joins/{}/confirm", joined["id"]),
        &relay.owner_token,
        Some(&json!({"safety": joined["safety"]})),
    );
    let token = relay.sign_in(&relay.team_id, &key);
    assert!(token.starts_with("apassy_acc_"));
    let me = relay.ok("GET", "/v1/me", &token, None);
    assert_eq!(me["member_name"], "dave");
    assert_eq!(me["role"], "member");
    let list = relay.ok("GET", "/v1/invites", &relay.owner_token, None);
    assert_eq!(list[0]["used_by"], confirmed["member_id"]);
    assert!(!list.to_string().contains("apassy_inv_"));
}

#[test]
fn an_invite_for_a_manager_gives_a_manager() {
    let relay = start(UpstreamOptions::default());
    let (_, manager) = relay.join_member("manager", "maria");
    let me = relay.ok("GET", "/v1/me", &manager, None);
    assert_eq!(me["role"], "manager");
}

#[test]
fn an_expired_wrong_or_malformed_code_is_invite_invalid() {
    let mut relay = start(UpstreamOptions::default());
    let invite = relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "member"})),
    );
    let code = invite["secret"].as_str().unwrap().to_string();
    relay.edit_vault("UPDATE invite SET expires_at = 1");
    for wrong in [
        code.clone(),
        fake_token("apassy_inv_"),
        fake_token("apassy_mbr_"),
        "not a code".to_string(),
        String::new(),
    ] {
        relay.fails(
            "POST",
            "/v1/join",
            None,
            Some(&json!({"code": wrong, "name": "frank", "device_name": "Test device", "public_key": apassy_relay::device::DeviceKey::generate().unwrap().public_key_b64()})),
            403,
            "invite_invalid",
        );
    }
    let members = relay.ok("GET", "/v1/members", &relay.owner_token, None);
    assert_eq!(members.as_array().unwrap().len(), 1);
}

#[test]
fn a_taken_name_is_a_conflict_and_keeps_the_invite() {
    let relay = start(UpstreamOptions::default());
    let (_, _) = relay.join_member("member", "gina");
    let invite = relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "member"})),
    );
    let code = invite["secret"].as_str().unwrap();
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(&json!({"code": code, "name": "gina", "device_name": "Test device", "public_key": apassy_relay::device::DeviceKey::generate().unwrap().public_key_b64()})),
        409,
        "conflict",
    );
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(&json!({"code": code, "name": "owner", "device_name": "Test device", "public_key": apassy_relay::device::DeviceKey::generate().unwrap().public_key_b64()})),
        409,
        "conflict",
    );
    for bad in ["", "has space", "slash/name", &"n".repeat(65)] {
        relay.fails(
            "POST",
            "/v1/join",
            None,
            Some(&json!({"code": code, "name": bad, "device_name": "Test device", "public_key": apassy_relay::device::DeviceKey::generate().unwrap().public_key_b64()})),
            400,
            "invalid_request",
        );
    }
    // The invite is still good for another name.
    relay.ok(
        "POST",
        "/v1/join",
        "",
        Some(&json!({"code": code, "name": "gina.2", "device_name": "Test device", "public_key": apassy_relay::device::DeviceKey::generate().unwrap().public_key_b64()})),
    );
}

#[test]
fn invite_options_are_checked() {
    let relay = start(UpstreamOptions::default());
    for hours in [0, 169] {
        relay.fails(
            "POST",
            "/v1/invites",
            Some(&relay.owner_token),
            Some(&json!({"role": "member", "expires_hours": hours})),
            400,
            "invalid_request",
        );
    }
    relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "owner"})),
    );
    let short = relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "member", "expires_hours": 1})),
    );
    let long = relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "member", "expires_hours": 168})),
    );
    assert!(
        long["expires_at"].as_u64().unwrap() - short["expires_at"].as_u64().unwrap()
            >= 167 * 3600 - 5
    );
}

#[test]
fn many_requests_at_once_are_all_answered() {
    let relay = std::sync::Arc::new(start(UpstreamOptions::default()));
    let team = relay.setup("staging");
    let mut handles = Vec::new();
    for worker in 0..8 {
        let relay = relay.clone();
        let token = team.agent_token.clone();
        let item = team.item;
        handles.push(std::thread::spawn(move || {
            for i in 0..10 {
                let (status, body) = relay.call("GET", "/v1/access", Some(&token), None);
                assert_eq!(status, 200, "{body}");
                let request = json!({
                    "items": [item], "command": ["git", "status"],
                    "purpose": format!("worker {worker} run {i}"), "user_request": "check"
                });
                let (status, body) = relay.call("POST", "/v1/runs", Some(&token), Some(&request));
                assert_eq!(status, 200, "{body}");
                assert_eq!(body["result"]["status"], "pending");
                let run = body["result"]["run_id"].as_u64().unwrap();
                let (status, body) = relay.release(run);
                assert_eq!(status, 200, "{body}");
                assert_eq!(body["result"]["status"], "ready");
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let started = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "session_started")
        .count();
    assert!(started >= 80, "{started}");
}

#[test]
fn the_proxy_path_goes_to_the_proxy_after_the_edge_check() {
    let relay = start(UpstreamOptions::default());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let key = format!("apassy_ses_{}", "0".repeat(64));
    let url = format!("{}/p/{key}/api.stripe.com/v1/balance", relay.url);
    // No edge header: the relay refuses it itself, with no proxy header.
    let refused = agent.get(&url).call().unwrap();
    assert_eq!(refused.status().as_u16(), 403);
    assert!(refused.headers().get("x-apassy-relay").is_none());
    // With the edge header the proxy answers, and marks its refusal.
    let answered = agent
        .get(&url)
        .header("X-Apassy-Edge", &relay.edge_secret)
        .call()
        .unwrap();
    assert!(answered.status().as_u16() >= 400);
    assert_eq!(answered.headers().get("x-apassy-relay").unwrap(), "refused");
}

/// `100 Continue` is sent only after admission and authentication, when the
/// handler starts reading the body. Use it as a barrier instead of guessing when
/// a request has occupied a member slot.
fn incomplete_invite(relay: &relay::TestRelay) -> std::io::BufReader<std::net::TcpStream> {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::Duration;
    let mut socket = TcpStream::connect(relay.url.trim_start_matches("http://")).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(socket, "POST /v1/invites HTTP/1.1\r\nHost: relay\r\nX-Apassy-Edge: {}\r\nAuthorization: Bearer {}\r\nContent-Length: 4096\r\nExpect: 100-continue\r\n\r\n{{", relay.edge_secret, relay.owner_token).unwrap();
    std::io::BufReader::new(socket)
}

/// An incomplete upload that the relay admitted (`100 Continue`), within 2 seconds. The
/// handler of a request keeps its member seat until it returns, a moment after its
/// client read the answer: a new connection can then get `503 busy`. That refusal takes
/// no member seat, so the upload is sent again until a seat is free.
fn admitted_incomplete_invite(relay: &relay::TestRelay) -> std::io::BufReader<std::net::TcpStream> {
    use std::time::{Duration, Instant};
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let mut socket = incomplete_invite(relay);
        let head = read_response_head(&mut socket);
        if head.starts_with("HTTP/1.1 100 ") {
            return socket;
        }
        assert!(head.starts_with("HTTP/1.1 503 "), "{head}");
        assert!(Instant::now() < until, "no member seat was freed: {head}");
        // Few refusals at once: the relay closes the connections over 8 of them.
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_response_head(socket: &mut impl std::io::BufRead) -> String {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(
            socket.read_line(&mut line).unwrap(),
            0,
            "EOF before {head:?}"
        );
        head.push_str(&line);
        if line == "\r\n" {
            return head;
        }
    }
}

fn assert_unreadable_body(socket: &mut impl std::io::Read) {
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    assert!(response.contains("Connection: close\r\n"), "{response}");
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    let body: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(body["error"]["message"], "The body cannot be read.");
}

fn wait_for_approval_capacity(relay: &relay::TestRelay) {
    use std::time::{Duration, Instant};
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let (status, body) = relay.call("GET", "/v1/approvals", Some(&relay.owner_token), None);
        if status == 200 {
            return;
        }
        // The response may arrive just before the handler drops its slot guard.
        // Wait for that observable release, but never retry a parsing/body error.
        assert_eq!(status, 503, "{body}");
        assert_eq!(body["error"]["code"], "busy", "{body}");
        assert!(Instant::now() < until, "member slots were not released");
        std::thread::yield_now();
    }
}

#[test]
fn stalled_and_refused_bodies_leave_health_and_approvals_available() {
    use std::net::Shutdown;
    use std::time::{Duration, Instant};
    let relay = relay::start_with(
        |config| {
            config.limits.max_active = 2;
            config.limits.member_reserve = 1;
        },
        UpstreamOptions::default(),
    );
    // Use the normal body deadline here: capacity must stay occupied throughout
    // this phase. Deadline expiry is exercised separately below.
    let mut first = admitted_incomplete_invite(&relay);
    relay.ok("GET", "/v1/approvals", &relay.owner_token, None);
    let mut second = admitted_incomplete_invite(&relay);
    let mut refused = incomplete_invite(&relay);
    let started = Instant::now();
    let head = read_response_head(&mut refused);
    assert!(head.starts_with("HTTP/1.1 503 "), "{head}");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        relay::call_url(&relay.url, None, "GET", "/healthz", None, None).0,
        200
    );
    // End the incomplete uploads explicitly, then observe both responses instead
    // of sleeping and assuming their handlers have finished.
    first.get_ref().shutdown(Shutdown::Write).unwrap();
    second.get_ref().shutdown(Shutdown::Write).unwrap();
    assert_unreadable_body(&mut first);
    assert_unreadable_body(&mut second);
    wait_for_approval_capacity(&relay);
}

#[test]
fn expired_stalled_body_frees_capacity_for_a_new_connection() {
    use std::time::Duration;
    let relay = relay::start_with(
        |config| {
            config.limits.max_active = 1;
            config.request_read_timeout = Duration::from_millis(450);
        },
        UpstreamOptions::default(),
    );
    for _ in 0..2 {
        // A previously admitted upload expires and frees its slot. The next
        // incomplete upload is therefore admitted, then gets a body-error 400,
        // rather than the busy 503 the old sleep-based test always expected.
        let mut stalled = admitted_incomplete_invite(&relay);
        assert_unreadable_body(&mut stalled);
    }
    // A member request still gets the freed seat.
    wait_for_approval_capacity(&relay);
}

#[test]
fn parser_refuses_ambiguous_framing_and_header_injection() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let relay = start(UpstreamOptions::default());
    for framing in [
        "Transfer-Encoding: identity\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
        "Content-Length: 0\r\nContent-Length: 10\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: nope\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Content-Length: 18446744073709551616\r\n",
        "Transfer-Encoding: chunked\u{000b}\r\n",
        "Connection: upgrade\r\nContent-Length: 0\r\n",
        " Content-Length: 0\r\n",
        "X-Test: first\r\n\tContent-Length: 0\r\n",
        "X-Test: ok\nInjected: yes\r\n",
        "X-Test: ok\n\r\n",
        "X-Test: ok\rInjected: yes\r\n",
    ] {
        let mut socket = TcpStream::connect(relay.url.trim_start_matches("http://")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(socket, "GET /healthz HTTP/1.1\r\nHost: relay\r\n{framing}\r\nGET /healthz HTTP/1.1\r\nHost: relay\r\n\r\n").unwrap();
        let mut text = String::new();
        let _ = socket.read_to_string(&mut text);
        assert!(!text.contains("200 OK"), "{framing:?}: {text}");
    }
    for bad in ["x\r\nInjected: yes", "x\ny", "x\0y"] {
        assert!(tiny_http::Header::from_bytes("X-Test", bad).is_err());
    }
    assert!(tiny_http::Header::from_bytes("X-Test", "plain value").is_ok());
}

#[test]
fn parser_bounds_header_lines_count_and_total_bytes() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let relay = start(UpstreamOptions::default());
    for headers in [
        format!("X-Large: {}\r\n", "a".repeat(8193)),
        "X-Count: a\r\n".repeat(100), // plus Host = 101
        format!("X-Large: {}\r\n", "a".repeat(8000)).repeat(9),
    ] {
        let mut socket = TcpStream::connect(relay.url.trim_start_matches("http://")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _ = write!(
            socket,
            "GET /healthz HTTP/1.1\r\nHost: relay\r\n{headers}\r\n"
        );
        let mut response = String::new();
        let _ = socket.read_to_string(&mut response);
        assert!(!response.contains("200 OK"), "oversized headers accepted");
    }
}

#[test]
fn trickling_body_has_an_absolute_deadline() {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::Duration;
    let relay = relay::start_with(
        |config| {
            config.limits.max_active = 1;
            config.request_read_timeout = Duration::from_millis(250);
        },
        UpstreamOptions::default(),
    );
    let mut socket = TcpStream::connect(relay.url.trim_start_matches("http://")).unwrap();
    write!(socket, "POST /v1/invites HTTP/1.1\r\nHost: relay\r\nX-Apassy-Edge: {}\r\nAuthorization: Bearer {}\r\nContent-Length: 4096\r\n\r\n", relay.edge_secret, relay.owner_token).unwrap();
    for _ in 0..7 {
        let _ = socket.write_all(b" ");
        std::thread::sleep(Duration::from_millis(60));
    }
    relay.ok("GET", "/v1/approvals", &relay.owner_token, None);
}

#[test]
fn health_bodies_cannot_hold_the_reserved_seats() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    let relay = start(UpstreamOptions::default());
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut socket = TcpStream::connect(relay.url.trim_start_matches("http://")).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: relay\r\nContent-Length: 4096\r\n\r\n")
            .unwrap();
        let mut socket = BufReader::new(socket);
        let mut line = String::new();
        socket.read_line(&mut line).unwrap();
        assert!(line.contains("200"), "{line}");
        held.push(socket);
    }
    let start = Instant::now();
    // Repeated checks must succeed while all four untrusted bodies are still open.
    for _ in 0..8 {
        assert_eq!(
            relay::call_url(&relay.url, None, "GET", "/healthz", None, None).0,
            200
        );
    }
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn chunk_metadata_is_strict_bounded_and_requires_complete_data() {
    use std::io::Write;
    use std::net::{Shutdown, TcpStream};
    use std::time::Duration;
    for body in [
        "2\r\na", // a truncated chunk must be an error, not a clean EOF
        "\n1\r\na\r\n0\r\n\r\n",
        "+1\r\na\r\n0\r\n\r\n",
        "10000000000000000\r\n",
        &format!("{}\r\n", "0".repeat(8193)),
        &format!("1;{}\r\na\r\n0\r\n\r\n", "x".repeat(8193)),
    ] {
        let server = tiny_http::Server::http_with_deadlines(
            "127.0.0.1:0",
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .unwrap();
        let mut socket = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
        write!(
            socket,
            "POST / HTTP/1.1\r\nHost: relay\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
        )
        .unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        let mut request = server
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert!(
            request.as_reader().read_to_end(&mut Vec::new()).is_err(),
            "accepted {body:?}"
        );
        request.abort();
    }
}

#[test]
fn a_truncated_length_delimited_body_is_not_successful_eof() {
    use std::io::Write;
    use std::net::{Shutdown, TcpStream};
    use std::time::Duration;
    let server = tiny_http::Server::http_with_deadlines(
        "127.0.0.1:0",
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut socket = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
    socket
        .write_all(b"POST / HTTP/1.1\r\nHost: relay\r\nContent-Length: 4096\r\n\r\n{}")
        .unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    let mut request = server
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    assert!(request.as_reader().read_to_end(&mut Vec::new()).is_err());
    request.abort();
}

#[test]
fn small_slow_bodies_take_a_bounded_member_seat() {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::Duration;
    let relay = relay::start_with(
        |config| {
            config.limits.max_active = 1;
            config.request_read_timeout = Duration::from_secs(2);
        },
        UpstreamOptions::default(),
    );
    let mut socket = TcpStream::connect(relay.url.trim_start_matches("http://")).unwrap();
    write!(socket, "POST /v1/invites HTTP/1.1\r\nHost: relay\r\nX-Apassy-Edge: {}\r\nAuthorization: Bearer {}\r\nContent-Length: 2\r\n\r\n{{", relay.edge_secret, relay.owner_token).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    relay.fails(
        "GET",
        "/v1/approvals",
        Some(&relay.owner_token),
        None,
        503,
        "busy",
    );
    assert_eq!(
        relay::call_url(&relay.url, None, "GET", "/healthz", None, None).0,
        200
    );
}

#[test]
fn valid_chunks_work_and_pipelining_never_dispatches_a_successor() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    let server = tiny_http::Server::http_with_deadlines(
        "127.0.0.1:0",
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut socket = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.write_all(b"POST / HTTP/1.1\r\nHost: relay\r\nTransfer-Encoding: ChUnKeD\r\n\r\n2;foo=bar\r\nab\r\n1\r\nc\r\n0\r\n\r\nGET /second HTTP/1.1\r\nHost: relay\r\n\r\n").unwrap();
    let mut request = server
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    let mut body = String::new();
    request.as_reader().read_to_string(&mut body).unwrap();
    assert_eq!(body, "abc");
    request
        .respond(tiny_http::Response::from_string("done"))
        .unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert_eq!(response.matches("200 OK").count(), 1);
    assert!(response.contains("Connection: close"));
    assert!(
        server
            .recv_timeout(Duration::from_millis(50))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_blocked_response_write_obeys_the_absolute_handle_deadline() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::mpsc;
    use std::time::Duration;
    let server = tiny_http::Server::http_with_deadlines(
        "127.0.0.1:0",
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_millis(350),
    )
    .unwrap();
    let mut socket = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: relay\r\n\r\n")
        .unwrap();
    let request = server
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    let (done, result) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let response = tiny_http::Response::new(
            tiny_http::StatusCode(200),
            Vec::new(),
            std::io::repeat(42).take(64 * 1024 * 1024),
            Some(64 * 1024 * 1024),
            None,
        );
        done.send(request.respond(response)).unwrap();
    });
    // Never read the response: its size exceeds the TCP buffers on both ends.
    let _ = result
        .recv_timeout(Duration::from_secs(2))
        .expect("response writer survived its deadline");
    writer.join().unwrap();
    drop(socket);
}

/// Run in its own test process: other integration tests deliberately start servers.
#[test]
#[ignore = "isolated transport resource check; run with --ignored --exact"]
fn repeated_connection_bursts_release_threads_and_file_descriptors() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;
    fn resources() -> (usize, usize) {
        #[cfg(target_os = "linux")]
        let result = (
            std::fs::read_dir("/proc/self/fd").unwrap().count(),
            std::fs::read_dir("/proc/self/task").unwrap().count(),
        );
        #[cfg(target_os = "macos")]
        let result = {
            let output = std::process::Command::new("ps")
                .args(["-M", "-p", &std::process::id().to_string(), "-o", "pid="])
                .output()
                .unwrap();
            assert!(output.status.success());
            (
                std::fs::read_dir("/dev/fd").unwrap().count(),
                String::from_utf8(output.stdout).unwrap().lines().count(),
            )
        };
        result
    }
    let server = tiny_http::Server::http_with_deadlines(
        "127.0.0.1:0",
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let before = resources();
    for _ in 0..4 {
        let mut clients = Vec::new();
        for _ in 0..64 {
            let mut socket = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket.write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
            clients.push(socket);
        }
        std::thread::sleep(Duration::from_millis(50));
        for socket in &mut clients {
            socket.write_all(b" relay\r\n\r\n").unwrap();
        }
        for _ in 0..clients.len() {
            let request = server
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            request
                .respond(tiny_http::Response::from_string("ok"))
                .unwrap();
        }
        for socket in &mut clients {
            let mut response = String::new();
            socket.read_to_string(&mut response).unwrap();
            assert!(response.contains("200 OK"));
        }
    }
    // The upstream worker pool retires excess idle threads after five seconds.
    std::thread::sleep(Duration::from_secs(6));
    let after = resources();
    eprintln!("transport resources (fds, threads): {before:?} -> {after:?}; 256 connections");
    assert!(
        after.0 <= before.0 + 2,
        "file descriptors leaked: {before:?} -> {after:?}"
    );
    assert!(
        after.1 <= before.1 + 2,
        "threads leaked: {before:?} -> {after:?}"
    );
}

#[test]
fn header_and_handle_deadlines_close_the_actual_transport() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    let server = tiny_http::Server::http_with_deadlines(
        "127.0.0.1:0",
        Duration::from_millis(150),
        Duration::from_millis(300),
        Duration::from_millis(450),
    )
    .unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let mut partial = TcpStream::connect(addr).unwrap();
    partial
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    partial.write_all(b"GET / HTTP/1.1\r\nHost: ").unwrap();
    let start = Instant::now();
    let mut answer = String::new();
    let _ = partial.read_to_string(&mut answer);
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(!answer.contains("200 OK"));
    let mut handled = TcpStream::connect(addr).unwrap();
    handled
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    handled
        .write_all(b"GET / HTTP/1.1\r\nHost: relay\r\n\r\n")
        .unwrap();
    let request = server
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    let start = Instant::now();
    let _ = handled.read_to_string(&mut String::new());
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(request);
}
