//! The audit: what it records, and that it never holds a value, a placeholder, a
//! token, or a session key.

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::config::UpstreamOptions;
use relay::{CANARY, CANARY2, TestRelay, start};
use serde_json::{Value, json};

fn actions(relay: &TestRelay) -> Vec<Value> {
    relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn every_step_is_recorded_with_its_actor() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, run) = relay.run(
        &team.agent_token,
        &team.request(&["python3", "x.py"], Some("go")),
    );
    let id = run["result"]["run_id"].as_u64().unwrap();
    relay.ok(
        "POST",
        &format!("/v1/approvals/{id}/approve"),
        &relay.owner_token,
        None,
    );
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", team.agent_id),
        &relay.owner_token,
        None,
    );
    relay.ok(
        "PUT",
        &format!("/v1/collections/{}/policy", team.collection),
        &relay.owner_token,
        Some(&json!({"mode": "ask"})),
    );
    relay.ok(
        "DELETE",
        &format!("/v1/items/{}", team.item),
        &relay.owner_token,
        None,
    );
    relay.ok(
        "DELETE",
        &format!("/v1/grants/{}", team.grant),
        &relay.owner_token,
        None,
    );
    relay.ok(
        "DELETE",
        &format!("/v1/members/{}", team.member_id),
        &relay.owner_token,
        None,
    );
    let rows = actions(&relay);
    let names: Vec<&str> = rows.iter().map(|r| r["action"].as_str().unwrap()).collect();
    for wanted in [
        "team_created",
        "invite_created",
        "member_joined",
        "collection_created",
        "item_added",
        "grant_created",
        "agent_created",
        "run_requested",
        "run_pending",
        "run_approved",
        "session_started",
        "session_ended",
        "agent_revoked",
        "policy_changed",
        "item_archived",
        "grant_revoked",
        "member_revoked",
    ] {
        assert!(names.contains(&wanted), "{wanted} missing in {names:?}");
    }
    // Ids ascend, times do not go back, and the actors have the known forms.
    let ids: Vec<u64> = rows.iter().map(|r| r["id"].as_u64().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    for row in &rows {
        let actor = row["actor"].as_str().unwrap();
        assert!(
            actor == "relay"
                || actor == "edge"
                || actor.starts_with("member:")
                || actor.starts_with("agent:"),
            "{actor}"
        );
    }
    let requested = rows
        .iter()
        .find(|r| r["action"] == "run_requested")
        .unwrap();
    assert_eq!(requested["actor"], format!("agent:{}", team.agent_id));
    assert_eq!(requested["run_id"], id);
    let approved = rows.iter().find(|r| r["action"] == "run_approved").unwrap();
    assert_eq!(approved["actor"], "member:1");
}

#[test]
fn the_audit_pages_by_after_and_limit() {
    let relay = start(UpstreamOptions::default());
    relay.setup("staging");
    let all = actions(&relay);
    assert!(all.len() > 5);
    let first = relay.ok("GET", "/v1/audit?limit=3", &relay.owner_token, None);
    assert_eq!(first.as_array().unwrap().len(), 3);
    let after = first[2]["id"].as_u64().unwrap();
    let next = relay.ok(
        "GET",
        &format!("/v1/audit?after={after}&limit=500"),
        &relay.owner_token,
        None,
    );
    assert_eq!(next.as_array().unwrap().len(), all.len() - 3);
    assert_eq!(next[0]["id"], all[3]["id"]);
    for bad in ["limit=0", "limit=501", "limit=x", "after=x"] {
        relay.fails(
            "GET",
            &format!("/v1/audit?{bad}"),
            Some(&relay.owner_token),
            None,
            400,
            "invalid_request",
        );
    }
    // The default limit is 100.
    for i in 0..110 {
        relay.ok(
            "POST",
            "/v1/collections",
            &relay.owner_token,
            Some(&json!({"name": format!("bulk{i}")})),
        );
    }
    assert_eq!(
        relay
            .ok("GET", "/v1/audit", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        100
    );
}

#[test]
fn no_endpoint_changes_or_deletes_a_row() {
    let relay = start(UpstreamOptions::default());
    for (method, path) in [
        ("PUT", "/v1/audit"),
        ("DELETE", "/v1/audit"),
        ("POST", "/v1/audit"),
        ("PATCH", "/v1/audit/1"),
        ("DELETE", "/v1/audit/1"),
    ] {
        let (status, _) = relay.call(method, path, Some(&relay.owner_token), None);
        assert!(status == 404 || status == 405, "{method} {path}: {status}");
    }
    assert!(!actions(&relay).is_empty());
}

/// Canary values, placeholders, tokens, and the session key go into every free-text
/// field. None of them may come back in any response except the one that issues it.
#[test]
fn canaries_placeholders_and_tokens_never_reach_the_audit_or_a_response() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    // A live session gives a placeholder and a key.
    let (_, first) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some("go")),
    );
    let env = first["result"]["session"]["env"].clone();
    let placeholder = env["STRIPE_API_KEY"].as_str().unwrap().to_string();
    let key = env["STRIPE_API_BASE"]
        .as_str()
        .unwrap()
        .split("/p/")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let invite = relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "member"})),
    );
    let invite_code = invite["secret"].as_str().unwrap().to_string();
    let agent_token = team.agent_token.clone();
    let member_token = team.member_token.clone();
    let owner_token = relay.owner_token.clone();
    let secrets: Vec<String> = vec![
        CANARY.to_string(),
        CANARY2.to_string(),
        placeholder.clone(),
        key.clone(),
        agent_token.clone(),
        member_token.clone(),
        owner_token.clone(),
        invite_code.clone(),
    ];
    let stuffed = |what: &str| {
        format!(
            "{what}: {} | {} | {} | {} | {} | {} | {} | {}",
            secrets[0],
            secrets[1],
            secrets[2],
            secrets[3],
            secrets[4],
            secrets[5],
            secrets[6],
            secrets[7]
        )
    };
    // The purpose and a reason are at most 500 bytes: two halves carry all secrets.
    let half = |what: &str, second: bool| {
        let range = if second { 4..8 } else { 0..4 };
        format!("{what}: {}", secrets[range].join(" | "))
    };
    // A second value that arrives later: it is masked from its first row on.
    let second_item = relay.add_item(
        team.collection,
        "GITHUB_TOKEN",
        CANARY2,
        json!({"provider": "github", "environment": "staging", "name": format!("n {CANARY2}")}),
    );
    let mut responses: Vec<(String, String)> = Vec::new();
    let mut record =
        |what: &str, value: &Value| responses.push((what.to_string(), value.to_string()));
    // A run with the canaries in purpose, user request, command, and cwd.
    let body = json!({
        "items": [team.item, second_item],
        "command": ["python3", "run.py", stuffed("arg"), stuffed("second arg")],
        "purpose": half("purpose", false),
        "user_request": stuffed("user request"),
        "cwd": format!("/work/{}", stuffed("cwd")),
    });
    let (status, pending) = relay.run(&team.agent_token, &body);
    assert_eq!(status, 200, "{pending}");
    record("run", &pending);
    let run_id = pending["result"]["run_id"].as_u64().unwrap();
    // A hard-rule denial with the canaries in the command.
    relay.ok("PUT", &format!("/v1/collections/{}/policy", team.collection), &relay.owner_token, Some(&json!({"rule": {"allowed_prefixes": ["git"], "instruction": half("instruction", true)}})));
    let (status, denied) = relay.run(&team.agent_token, &json!({
        "items": [team.item], "command": ["ls", stuffed("denied arg")], "purpose": half("denied purpose", false), "user_request": stuffed("denied user request"),
    }));
    assert_eq!(status, 403);
    record("denied", &denied);
    relay.ok(
        "PUT",
        &format!("/v1/collections/{}/policy", team.collection),
        &relay.owner_token,
        Some(&json!({})),
    );
    // Approve with a reason that holds them, then deny another run the same way.
    let approved = relay.ok(
        "POST",
        &format!("/v1/approvals/{run_id}/approve"),
        &relay.owner_token,
        Some(&json!({"reason": half("reason", true)})),
    );
    record("approve", &approved);
    let (_, other) = relay.run(&team.agent_token, &json!({
        "items": [team.item], "command": ["python3", "b.py"], "purpose": half("p2", false), "user_request": stuffed("u2"),
    }));
    let other_id = other["result"]["run_id"].as_u64().unwrap();
    let denial = relay.ok(
        "POST",
        &format!("/v1/approvals/{other_id}/deny"),
        &relay.owner_token,
        Some(&json!({"reason": half("deny reason", true)})),
    );
    record("deny", &denial);
    // A third run waits and is read while pending.
    let (_, third) = relay.run(&team.agent_token, &json!({
        "items": [team.item], "command": ["python3", "c.py", stuffed("c")], "purpose": half("p3", false), "user_request": stuffed("u3"),
    }));
    let third_id = third["result"]["run_id"].as_u64().unwrap();
    record(
        "approvals",
        &relay.ok("GET", "/v1/approvals", &relay.owner_token, None),
    );
    record(
        "run status",
        &relay.ok(
            "GET",
            &format!("/v1/runs/{third_id}"),
            &team.agent_token,
            None,
        ),
    );
    record(
        "run approved status",
        &relay.ok(
            "GET",
            &format!("/v1/runs/{run_id}"),
            &team.agent_token,
            None,
        )["note"],
    );
    // Names that hold them.
    relay.ok(
        "POST",
        "/v1/collections",
        &relay.owner_token,
        Some(&json!({"name": format!("c {CANARY}")})),
    );
    relay.ok(
        "POST",
        "/v1/agents",
        &team.member_token,
        Some(&json!({"name": format!("a {placeholder}")})),
    );
    // A proxy-path style event with a hostile path is covered in server_sessions.
    for (path, token) in [
        ("/v1/me", &owner_token),
        ("/v1/members", &owner_token),
        ("/v1/invites", &owner_token),
        ("/v1/collections", &owner_token),
        ("/v1/items", &owner_token),
        ("/v1/grants", &owner_token),
        ("/v1/agents", &owner_token),
        ("/v1/audit?limit=500", &owner_token),
        ("/v1/items", &member_token),
        ("/v1/collections", &member_token),
        ("/v1/agents", &member_token),
        ("/v1/access", &agent_token),
    ] {
        let (status, body) = relay.call("GET", path, Some(token), None);
        assert_eq!(status, 200, "{path}");
        record(path, &body);
    }
    let audit_text = record_audit(&responses);
    for (what, text) in &responses {
        for (i, secret) in secrets.iter().enumerate() {
            // The run that issued the session is not among these responses.
            assert!(
                !text.contains(secret.as_str()),
                "response `{what}` holds secret #{i}"
            );
        }
    }
    assert!(audit_text.contains("[apassy:STRIPE_API_KEY]"));
    assert!(audit_text.contains("[apassy:GITHUB_TOKEN]"));
    assert!(audit_text.contains("[apassy:token]"));
    // Fragments of the text around the secrets are still there: only the secret goes.
    assert!(audit_text.contains("purpose: "));
    // The stored text is masked too: after a restart nothing changes.
    let relay = relay.restart();
    let after = relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .to_string();
    for secret in &secrets {
        assert!(!after.contains(secret.as_str()));
    }
}

fn record_audit(responses: &[(String, String)]) -> String {
    responses
        .iter()
        .find(|(what, _)| what == "/v1/audit?limit=500")
        .map(|(_, text)| text.clone())
        .unwrap_or_default()
}

#[test]
fn a_placeholder_is_masked_after_its_session_ended() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, run) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some("go")),
    );
    let placeholder = run["result"]["session"]["env"]["STRIPE_API_KEY"]
        .as_str()
        .unwrap()
        .to_string();
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", team.agent_id),
        &relay.owner_token,
        None,
    );
    let member_agent = relay.ok(
        "POST",
        "/v1/agents",
        &team.member_token,
        Some(&json!({"name": format!("late {placeholder}")})),
    );
    assert!(!member_agent.to_string().contains(&placeholder) || member_agent["secret"].is_string());
    let audit = relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .to_string();
    assert!(!audit.contains(&placeholder));
    let agents = relay
        .ok("GET", "/v1/agents", &team.member_token, None)
        .to_string();
    assert!(!agents.contains(&placeholder), "the name is masked at once");
}

#[test]
fn auth_failures_are_rate_limited_and_hold_no_token() {
    let relay = start(UpstreamOptions::default());
    let secret_looking = format!("apassy_mbr_{}", "cd".repeat(32));
    for _ in 0..6 {
        relay.call("GET", "/v1/me", Some(&secret_looking), None);
    }
    let rows: Vec<Value> = actions(&relay)
        .into_iter()
        .filter(|r| r["action"] == "auth_failed")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["actor"], "edge");
    assert!(!Value::Array(rows).to_string().contains(&secret_looking));
}
