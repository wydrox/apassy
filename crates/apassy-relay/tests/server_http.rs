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
