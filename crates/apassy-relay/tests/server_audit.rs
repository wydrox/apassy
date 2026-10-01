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
    relay.release_ok(id);
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
        "run_released",
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
    let released = rows.iter().find(|r| r["action"] == "run_released").unwrap();
    assert_eq!(released["actor"], "member:1");
    assert_eq!(released["run_id"], id);
    assert_eq!(released["detail"]["items"], json!([team.item]));
    assert_eq!(released["detail"]["suggestion"], "ask");
    // Nobody approves on the relay, so nothing writes that row.
    assert!(!names.contains(&"run_approved"), "{names:?}");
    assert!(!names.contains(&"run_allowed"), "{names:?}");
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

/// Canary values, placeholders, tokens, the session key, and the key material of a
/// release go into every free-text field. None of them may come back in any response
/// except the one that issues it, and none may be in the audit.
///
/// The relay holds a value only while a session lives, so the test starts with a
/// session that holds both values. The texts that follow are masked because of it.
#[test]
fn canaries_placeholders_and_tokens_never_reach_the_audit_or_a_response() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let second_item = relay.add_item(
        team.collection,
        "GITHUB_TOKEN",
        CANARY2,
        json!({"provider": "github", "environment": "staging"}),
    );
    // A live session with both values gives a placeholder and a key. The host
    // request and the release are kept, to look for their key material later.
    let (status, asked) = relay.run(
        &team.agent_token,
        &json!({
            "items": [team.item, second_item], "command": ["git", "status"],
            "purpose": "look", "user_request": "go", "cwd": "/work",
        }),
    );
    assert_eq!(status, 200, "{asked}");
    let first_id = asked["result"]["run_id"].as_u64().unwrap();
    let first_request = relay.host_request(first_id);
    let first_release = relay.release_for(&first_request, None);
    let (status, released) = relay.call(
        "POST",
        &format!("/v1/host/requests/{first_id}/release"),
        Some(&relay.owner_token),
        Some(&first_release),
    );
    assert_eq!(status, 200, "{released}");
    let first = relay.ok(
        "GET",
        &format!("/v1/runs/{first_id}"),
        &team.agent_token,
        None,
    );
    let env = first["session"]["env"].clone();
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
    // The key material of the release: the item keys, the run key, and the texts that
    // the host sent. The relay must not write any of them anywhere.
    let mut material: Vec<(String, String)> = relay
        .item_key_texts()
        .into_iter()
        .map(|text| ("an item key".to_string(), text))
        .collect();
    material.push((
        "the run key".into(),
        first_request["run_key"].as_str().unwrap().into(),
    ));
    for field in ["host_key", "nonce", "sealed_keys"] {
        material.push((field.into(), first_release[field].as_str().unwrap().into()));
    }
    let mut responses: Vec<(String, String)> = Vec::new();
    let mut record =
        |what: &str, value: &Value| responses.push((what.to_string(), value.to_string()));
    record("first release", &released);
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
    // The host request of that run, with the texts masked as stored.
    let listed = Value::Array(relay.host_requests());
    record("host requests", &listed);
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
    // Release with a reason that holds them, then deny another run the same way, once
    // through the host and once through an approver.
    let request = relay.host_request(run_id);
    let body = relay.release_for(&request, Some(&half("reason", true)));
    material.push((
        "host_key of a second release".into(),
        body["host_key"].as_str().unwrap().into(),
    ));
    material.push((
        "sealed_keys of a second release".into(),
        body["sealed_keys"].as_str().unwrap().into(),
    ));
    material.push((
        "run key of a second run".into(),
        request["run_key"].as_str().unwrap().into(),
    ));
    let (status, approved) = relay.call(
        "POST",
        &format!("/v1/host/requests/{run_id}/release"),
        Some(&relay.owner_token),
        Some(&body),
    );
    assert_eq!(status, 200, "{approved}");
    record("release", &approved);
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
    let (_, another) = relay.run(&team.agent_token, &json!({
        "items": [team.item], "command": ["python3", "d.py"], "purpose": half("p2b", false), "user_request": stuffed("u2b"),
    }));
    let another_id = another["result"]["run_id"].as_u64().unwrap();
    let denial = relay.ok(
        "POST",
        &format!("/v1/host/requests/{another_id}/deny"),
        &relay.owner_token,
        Some(&json!({"reason": half("host deny reason", true)})),
    );
    record("host deny", &denial);
    // A third run waits and is read while pending.
    let (_, third) = relay.run(&team.agent_token, &json!({
        "items": [team.item], "command": ["python3", "c.py", stuffed("c")], "purpose": half("p3", false), "user_request": stuffed("u3"),
    }));
    let third_id = third["result"]["run_id"].as_u64().unwrap();
    record(
        "approvals",
        &relay.ok("GET", "/v1/approvals", &relay.owner_token, None),
    );
    record("host requests again", &Value::Array(relay.host_requests()));
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
        "run released status",
        &relay.ok(
            "GET",
            &format!("/v1/runs/{run_id}"),
            &team.agent_token,
            None,
        )["note"],
    );
    // A release that does not check: its answer and its audit rows hold nothing either.
    let (_, fourth) = relay.run(&team.agent_token, &json!({
        "items": [team.item], "command": ["python3", "e.py"], "purpose": half("p4", false), "user_request": stuffed("u4"),
    }));
    let fourth_id = fourth["result"]["run_id"].as_u64().unwrap();
    let mut broken = relay.release_for(&relay.host_request(fourth_id), Some(&half("broken", true)));
    broken["sealed_keys"] = json!(apassy_relay::hostkeys::encode_b64(&[5u8; 40]));
    let (status, refused) = relay.call(
        "POST",
        &format!("/v1/host/requests/{fourth_id}/release"),
        Some(&relay.owner_token),
        Some(&broken),
    );
    assert_eq!(status, 403, "{refused}");
    record("broken release", &refused);
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
    // The audit, and every vault cell, hold no key material of a release.
    let cells: Vec<String> = relay
        .vault_cells()
        .into_iter()
        .map(|cell| String::from_utf8_lossy(&cell).into_owned())
        .collect();
    for (name, text) in &material {
        assert!(
            !audit_text.contains(text.as_str()),
            "the audit holds {name}"
        );
        for (what, response) in &responses {
            // The host request list shows the run key, to the host: that is its job.
            if what.starts_with("host requests") && name.contains("run key") {
                continue;
            }
            assert!(
                !response.contains(text.as_str()),
                "response `{what}` holds {name}"
            );
        }
        assert!(
            !cells.iter().any(|cell| cell.contains(text.as_str())),
            "the vault holds {name}"
        );
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
    let run = relay.run_released(
        &team.agent_token,
        &team.request(&["git", "status"], Some("go")),
    );
    let placeholder = run["session"]["env"]["STRIPE_API_KEY"]
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
    // A token of this team that is not known: the team's audit, at most one row.
    let secret_looking = format!("apassy_mbr_{}_{}", relay.team_id, "cd".repeat(32));
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
    // A token that names no known team goes to the audit of the relay, not of a team.
    let no_team = format!("apassy_mbr_{}", "ef".repeat(32));
    for _ in 0..6 {
        relay.call("GET", "/v1/me", Some(&no_team), None);
    }
    let rows = actions(&relay)
        .into_iter()
        .filter(|r| r["action"] == "auth_failed")
        .count();
    assert_eq!(rows, 1);
    let relay_rows = relay.relay_audit();
    assert_eq!(
        relay_rows.iter().filter(|r| r.1 == "auth_failed").count(),
        1,
        "{relay_rows:?}"
    );
    assert!(!format!("{relay_rows:?}").contains(&no_team));
}
