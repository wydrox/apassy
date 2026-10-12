//! Per-team storage, run, and request limits through the public HTTP and operator APIs.

#[path = "common/relay.rs"]
mod relay;

use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use apassy_relay::config::UpstreamOptions;
use apassy_relay::ids::TeamId;
use apassy_relay::server::Relay;
use apassy_relay::server::directory::{Directory, TeamLimits, TeamLimitsUpdate};
use apassy_relay::server::operator::Command;
use relay::{CANARY, TestRelay, item_request, seal, start, start_with, team_of};
use serde_json::{Value, json};

type CodeSnapshot = (i64, Vec<u8>, Option<i64>, Option<String>);

fn defaults() -> Value {
    json!({"members":50,"items":500,"agents":100,"runs_per_hour":1000,
           "pending_runs":50,"agent_requests":56,"sync_bytes":67108864,
           "sync_pushes_per_hour":600,"sync_transfers":2,
           "open_questions":20,"questions_per_hour":300,"question_bytes":8388608,
           "member_open_questions":15,"member_questions_per_hour":225,
           "device_open_questions":10,"device_questions_per_hour":150})
}

fn set(relay: &TestRelay, update: Value) -> Value {
    relay
        .operator(Command::Limits {
            team: relay.team_id.clone(),
            set: Some(serde_json::from_value::<TeamLimitsUpdate>(update).unwrap()),
        })
        .unwrap()
}

fn get(relay: &TestRelay, team: &TeamId) -> Value {
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: None,
        })
        .unwrap()
}

fn raw_operator(relay: &TestRelay, command: Value) -> Value {
    let mut stream =
        std::os::unix::net::UnixStream::connect(relay.config.admin_socket_path()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(stream, "{command}").unwrap();
    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer).unwrap();
    serde_json::from_str(&answer).unwrap()
}

fn pending(relay: &TestRelay, team: &relay::Team) -> u64 {
    let (status, body) = relay.run(
        &team.agent_token,
        &team.request(&["python3", "script.py"], Some("Check the account.")),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "pending", "{body}");
    body["result"]["run_id"].as_u64().unwrap()
}

fn run_count(relay: &TestRelay) -> i64 {
    relay::open_team_file(&relay.config, &relay.team_id)
        .query_row("SELECT count(*) FROM run", [], |row| row.get(0))
        .unwrap()
}

fn refuse_run(relay: &TestRelay, team: &relay::Team) {
    let count = run_count(relay);
    relay.fails(
        "POST",
        "/v1/runs",
        Some(&team.agent_token),
        Some(&team.request(&["python3", "script.py"], Some("Check the account."))),
        403,
        "team_limit",
    );
    assert_eq!(
        run_count(relay),
        count,
        "A refused request must not create a run."
    );
}

fn invite(relay: &TestRelay) -> Value {
    relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role":"member"})),
    )
}

fn agent(relay: &TestRelay, name: &str) -> Value {
    relay.ok(
        "POST",
        "/v1/agents",
        &relay.owner_token,
        Some(&json!({"name": name})),
    )
}

#[test]
fn operator_defaults_partial_updates_restart_and_team_separation() {
    let relay = start(UpstreamOptions::default());
    assert_eq!(
        serde_json::to_value(TeamLimits::default()).unwrap(),
        defaults()
    );
    assert_eq!(get(&relay, &relay.team_id), defaults());
    let b_owner = relay.new_team("Team B", "bob");
    let b = team_of(&b_owner);
    let mut expected = defaults();
    expected["members"] = json!(3);
    expected["items"] = json!(2);
    assert_eq!(set(&relay, json!({"members":3,"items":2})), expected);
    expected["pending_runs"] = json!(1);
    assert_eq!(set(&relay, json!({"pending_runs":1})), expected);
    assert_eq!(set(&relay, json!({})), expected);
    assert_eq!(get(&relay, &b), defaults());
    let audit_a = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let changed: Vec<_> = audit_a
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == "limits_changed")
        .collect();
    assert_eq!(changed.len(), 3, "{audit_a}");
    for row in changed {
        assert_eq!(row["actor"], "operator");
        assert_eq!(row["detail"]["team_id"], relay.team_id.as_str());
    }
    let audit_b = relay.ok("GET", "/v1/audit?limit=500", &b_owner, None);
    assert!(!audit_b.to_string().contains("limits_changed"));
    assert!(!audit_b.to_string().contains(relay.team_id.as_str()));
    let changes: Vec<_> = relay
        .relay_audit()
        .into_iter()
        .filter(|(_, action, _)| action == "limits_changed")
        .collect();
    assert_eq!(changes.len(), 3);
    for (actor, _, detail) in changes {
        assert_eq!(actor, "operator");
        assert_eq!(
            serde_json::from_str::<Value>(&detail).unwrap()["team_id"],
            relay.team_id.as_str()
        );
    }
    let relay = relay.restart();
    assert_eq!(get(&relay, &relay.team_id), expected);
    assert_eq!(get(&relay, &b), defaults());
}

#[test]
fn operator_refuses_invalid_updates_without_partial_writes() {
    let relay = start(UpstreamOptions::default());
    for field in [
        "members",
        "items",
        "agents",
        "runs_per_hour",
        "pending_runs",
        "agent_requests",
    ] {
        for bad in [json!(0), json!(-1), json!("1"), json!(1.5)] {
            let mut update = json!({"items":2});
            update[field] = bad;
            let answer = raw_operator(
                &relay,
                json!({"command":"limits","team":relay.team_id,"set":update}),
            );
            assert_eq!(answer["ok"], false, "{answer}");
            assert_eq!(answer["error"]["code"], "invalid_request", "{answer}");
            assert_eq!(get(&relay, &relay.team_id), defaults());
        }
    }
    for update in [
        json!({"unknown":1}),
        json!({"agent_requests":225}),
        json!({"items":u64::MAX}),
    ] {
        let answer = raw_operator(
            &relay,
            json!({"command":"limits","team":relay.team_id,"set":update}),
        );
        assert_eq!(answer["error"]["code"], "invalid_request", "{answer}");
        assert_eq!(get(&relay, &relay.team_id), defaults());
    }
    assert_eq!(
        set(&relay, json!({"agent_requests":224}))["agent_requests"],
        224
    );
    let answer = raw_operator(&relay, json!({"command":"limits","team":"t_unknownabc"}));
    assert_eq!(answer["error"]["code"], "not_found", "{answer}");
}

#[test]
fn member_limit_counts_active_members_and_leaves_invite_usable() {
    let relay = start(UpstreamOptions::default());
    set(&relay, json!({"members":2}));
    let (member, _) = relay.join_member("member", "alice");
    let code = invite(&relay);
    let join = json!({"code":code["secret"],"name":"carol", "device_name":"Carol device", "public_key":apassy_relay::device::DeviceKey::generate().unwrap().public_key_b64()});
    relay.fails("POST", "/v1/join", None, Some(&join), 403, "team_limit");
    let conn = relay::open_team_file(&relay.config, &relay.team_id);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM member", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM invite WHERE used_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    drop(conn);
    relay.ok(
        "DELETE",
        &format!("/v1/members/{member}"),
        &relay.owner_token,
        None,
    );
    let pending = relay.ok("POST", "/v1/join", "", Some(&join));
    relay.ok(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        &relay.owner_token,
        Some(&json!({"safety": pending["safety"]})),
    );
    let conn = relay::open_team_file(&relay.config, &relay.team_id);
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM member WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
}

#[test]
fn item_limit_releases_capacity_on_archive_and_does_not_affect_other_team() {
    let mut relay = start(UpstreamOptions::default());
    set(&relay, json!({"items":1}));
    let collection = relay.add_collection("test", json!({}));
    let first = relay.add_item(
        collection,
        "FIRST_KEY",
        CANARY,
        json!({"provider":"stripe","environment":"staging"}),
    );
    let sealed = seal(CANARY);
    let body = item_request(
        collection,
        "SECOND_KEY",
        &sealed,
        json!({"provider":"stripe","environment":"staging"}),
    );
    relay.fails(
        "POST",
        "/v1/items",
        Some(&relay.owner_token),
        Some(&body),
        403,
        "team_limit",
    );
    let a = relay.owner_token.clone();
    let b = relay.new_team("Team B", "bob");
    relay.switch_team(&b);
    let cb = relay.add_collection("test", json!({}));
    relay.add_item(
        cb,
        "FIRST_KEY",
        CANARY,
        json!({"provider":"stripe","environment":"staging"}),
    );
    relay.add_item(
        cb,
        "SECOND_KEY",
        CANARY,
        json!({"provider":"stripe","environment":"staging"}),
    );
    relay.switch_team(&a);
    relay.ok("DELETE", &format!("/v1/items/{first}"), &a, None);
    relay.ok("POST", "/v1/items", &a, Some(&body));
}

#[test]
fn agent_limit_releases_capacity_on_revoke_and_expiry() {
    let relay = start(UpstreamOptions::default());
    set(&relay, json!({"agents":1}));
    let first = agent(&relay, "first");
    let request = json!({"name":"second"});
    relay.fails(
        "POST",
        "/v1/agents",
        Some(&relay.owner_token),
        Some(&request),
        403,
        "team_limit",
    );
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", first["id"]),
        &relay.owner_token,
        None,
    );
    agent(&relay, "second");
    relay.fails(
        "POST",
        "/v1/agents",
        Some(&relay.owner_token),
        Some(&json!({"name":"third"})),
        403,
        "team_limit",
    );
    relay.edit_vault_live("UPDATE agent SET expires_at = 1 WHERE revoked_at IS NULL");
    agent(&relay, "third");
}

#[test]
fn hourly_run_limit_counts_all_run_outcomes_and_releases_old_capacity() {
    let mut relay = start_with(|c| c.approval_timeout_secs = 30, UpstreamOptions::default());
    let team = relay.setup("staging");
    set(&relay, json!({"runs_per_hour":2}));
    let first = pending(&relay, &team);
    relay.ok(
        "POST",
        &format!("/v1/approvals/{first}/deny"),
        &relay.owner_token,
        Some(&json!({"reason":"No."})),
    );
    let second = pending(&relay, &team);
    relay.release_ok(second);
    refuse_run(&relay, &team);
    relay.edit_vault_live("UPDATE run SET created_at = 1");
    let third = pending(&relay, &team);
    assert!(third > second);
    let a = relay.owner_token.clone();
    let b = relay.new_team("Team B", "bob");
    relay.switch_team(&b);
    let team_b = relay.setup("staging");
    for _ in 0..3 {
        pending(&relay, &team_b);
    }
    relay.switch_team(&a);
}

#[test]
fn pending_limit_releases_capacity_on_denial_release_and_timeout() {
    let relay = start_with(|c| c.approval_timeout_secs = 30, UpstreamOptions::default());
    let team = relay.setup("staging");
    set(&relay, json!({"pending_runs":1}));
    let first = pending(&relay, &team);
    refuse_run(&relay, &team);
    relay.ok(
        "POST",
        &format!("/v1/approvals/{first}/deny"),
        &relay.owner_token,
        Some(&json!({"reason":"No."})),
    );
    let second = pending(&relay, &team);
    refuse_run(&relay, &team);
    relay.release_ok(second);
    let third = pending(&relay, &team);
    refuse_run(&relay, &team);
    relay.edit_vault_live(&format!("UPDATE run SET expires_at = 1 WHERE id = {third}"));
    let view = relay.ok("GET", &format!("/v1/runs/{third}"), &team.agent_token, None);
    assert_eq!(view["status"], "timed_out");
    let fourth = pending(&relay, &team);
    assert!(fourth > third);
}

#[test]
fn limit_refusal_audit_is_bounded_per_kind_and_has_no_credentials() {
    let relay = start_with(|c| c.approval_timeout_secs = 30, UpstreamOptions::default());
    let team = relay.setup("staging");
    set(&relay, json!({"items":1,"agents":1,"pending_runs":1}));
    pending(&relay, &team);
    let sealed = seal(CANARY);
    let item = item_request(
        team.collection,
        "EXTRA_KEY",
        &sealed,
        json!({"provider":"stripe","environment":"staging"}),
    );
    for _ in 0..4 {
        refuse_run(&relay, &team);
        relay.fails(
            "POST",
            "/v1/items",
            Some(&relay.owner_token),
            Some(&item),
            403,
            "team_limit",
        );
        relay.fails(
            "POST",
            "/v1/agents",
            Some(&relay.owner_token),
            Some(&json!({"name":"extra"})),
            403,
            "team_limit",
        );
    }
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let rows: Vec<_> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "limit_reached")
        .collect();
    assert_eq!(rows.len(), 3, "{audit}");
    let mut kinds = std::collections::HashSet::new();
    for row in rows {
        assert!(
            kinds.insert(row["detail"]["limit"].clone().to_string()),
            "{audit}"
        );
    }
    let text = audit.to_string();
    for secret in [&relay.owner_token, &team.agent_token, &team.member_token] {
        assert!(!text.contains(secret));
    }
    assert!(!text.contains(CANARY));
}

fn wait_counter(core: &apassy_relay::server::Core, expected: usize) {
    let until = Instant::now() + Duration::from_secs(5);
    while core.agent_requests.load(Ordering::SeqCst) != expected {
        assert!(
            Instant::now() < until,
            "agent_requests = {}, expected {expected}",
            core.agent_requests.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn request_with_retry(relay: &TestRelay, token: &str, path: &str) -> (u16, Option<String>, Value) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let request = ureq::http::Request::builder()
        .method("GET")
        .uri(format!("{}{path}", relay.url))
        .header("X-Apassy-Edge", &relay.edge_secret)
        .header("Authorization", format!("Bearer {token}"))
        .body(Vec::<u8>::new())
        .unwrap();
    let mut response = agent.run(request).unwrap();
    let status = response.status().as_u16();
    let retry = response
        .headers()
        .get("Retry-After")
        .map(|h| h.to_str().unwrap().to_string());
    let text = response.body_mut().read_to_string().unwrap();
    (status, retry, serde_json::from_str(&text).unwrap())
}

#[test]
fn in_flight_agent_limit_is_per_team_and_counter_returns_to_zero() {
    let mut relay = start_with(|c| c.approval_timeout_secs = 30, UpstreamOptions::default());
    let team_a = relay.setup("staging");
    let run = pending(&relay, &team_a);
    set(&relay, json!({"agent_requests":1}));
    let a = relay.owner_token.clone();
    let a_id = relay.team_id.clone();
    let b = relay.new_team("Team B", "bob");
    relay.switch_team(&b);
    let team_b = relay.setup("staging");
    relay.switch_team(&a);
    let relay = Arc::new(relay);
    let core = relay.hub().team(&a_id).unwrap();
    let poller = {
        let relay = relay.clone();
        let token = team_a.agent_token.clone();
        std::thread::spawn(move || {
            relay.call(
                "GET",
                &format!("/v1/runs/{run}?wait=20"),
                Some(&token),
                None,
            )
        })
    };
    wait_counter(&core, 1);
    let (status, retry, body) = request_with_retry(&relay, &team_a.agent_token, "/v1/access");
    assert_eq!(status, 503, "{body}");
    assert_eq!(retry.as_deref(), Some("2"));
    assert_eq!(body["error"]["code"], "busy");
    relay.ok("GET", "/v1/access", &team_b.agent_token, None);
    relay.ok("GET", "/v1/me", &a, None);
    relay.ok("GET", "/v1/me", &team_a.agent_token, None);
    let fake_session = format!("apassy_ses_{}_{}", a_id.as_str(), "0".repeat(64));
    let (status, retry, body) = request_with_retry(
        &relay,
        &team_a.agent_token,
        &format!("/p/{fake_session}/api.stripe.com/v1/balance"),
    );
    assert_eq!(status, 503, "{body}");
    assert_eq!(retry.as_deref(), Some("2"));
    assert_eq!(body["error"]["code"], "busy");
    relay.release_ok(run);
    let (status, body) = poller.join().unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "ready");
    wait_counter(&core, 0);
    for (path, status, code) in [
        ("/v1/runs/999999", 404, "not_found"),
        ("/v1/runs/1?wait=x", 400, "invalid_request"),
    ] {
        relay.fails("GET", path, Some(&team_a.agent_token), None, status, code);
        wait_counter(&core, 0);
    }
    relay.fails(
        "POST",
        "/v1/runs",
        Some(&team_a.agent_token),
        Some(&json!({})),
        400,
        "invalid_request",
    );
    wait_counter(&core, 0);
    relay.ok("GET", "/v1/me", &team_a.agent_token, None);
    wait_counter(&core, 0);
}

fn directory_connection(config: &apassy_relay::config::RelayConfig) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{}';", config.master_key.expose()))
        .unwrap();
    conn
}

#[test]
fn directory_1001_migrates_to_1002_without_losing_teams_codes_or_audit() {
    let mut relay = start(UpstreamOptions::default());
    let a = relay.owner_token.clone();
    let a_id = relay.team_id.clone();
    let b = relay.new_team("Team B", "bob");
    relay.switch_team(&b);
    let b_id = relay.team_id.clone();
    let unused = relay.operator(Command::TeamCode { hours: 1 }).unwrap();
    let audit = relay.relay_audit();
    let (config, _dir) = relay.stop_keep();
    let conn = directory_connection(&config);
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1002
    );
    conn.execute_batch(
        "BEGIN IMMEDIATE; ALTER TABLE team DROP COLUMN limits; PRAGMA user_version = 1001; COMMIT;",
    )
    .unwrap();
    let original_codes: Vec<CodeSnapshot> = conn
        .prepare("SELECT id,code_hash,used_at,team_id FROM team_code ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    drop(conn);
    let running = Relay::start(config.clone()).unwrap();
    let url = running.url();
    for (owner, id) in [(&a, &a_id), (&b, &b_id)] {
        let (status, body) = relay::call_url(
            &url,
            Some(config.edge_secret.expose()),
            "GET",
            "/v1/me",
            Some(owner),
            None,
        );
        if owner == &a {
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["result"]["team_id"], id.as_str());
        } else {
            // Access tokens live in memory and end at a restart.
            assert_eq!(status, 401, "{body}");
        }
        assert_eq!(
            apassy_relay::server::operator::send(
                &config.admin_socket_path(),
                &Command::Limits {
                    team: id.clone(),
                    set: None
                }
            )
            .unwrap(),
            defaults()
        );
    }
    let conn = directory_connection(&config);
    assert_eq!(
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1002
    );
    let migrated_codes: Vec<CodeSnapshot> = conn
        .prepare("SELECT id,code_hash,used_at,team_id FROM team_code ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(migrated_codes, original_codes);
    let migrated_audit: Vec<(String, String, String)> = conn
        .prepare("SELECT actor,action,detail FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(migrated_audit, audit);
    drop(conn);
    let (status, body) = relay::call_url(
        &url,
        Some(config.edge_secret.expose()),
        "POST",
        "/v1/teams",
        None,
        Some(
            &json!({"code":unused["code"],"team":"Team C","owner":"carol", "device_name":"Carol device", "public_key":apassy_relay::device::DeviceKey::generate().unwrap().public_key_b64()}),
        ),
    );
    assert_eq!(status, 200, "{body}");
    running.stop();
}

#[test]
fn unknown_directory_versions_are_refused_without_changes() {
    let relay = start(UpstreamOptions::default());
    let (config, _dir) = relay.stop_keep();
    for version in [0, 1000, 1003, 2000] {
        let conn = directory_connection(&config);
        conn.execute_batch(&format!("PRAGMA user_version = {version}"))
            .unwrap();
        drop(conn);
        assert!(Directory::open(&config).is_err(), "version {version}");
        let conn = directory_connection(&config);
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            version
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM team", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn partial_agent_body_holds_the_team_slot_until_the_body_is_complete() {
    let mut relay = start(UpstreamOptions::default());
    let team_a = relay.setup("staging");
    set(&relay, json!({"agent_requests":1}));
    let a = relay.owner_token.clone();
    let a_id = relay.team_id.clone();
    let b = relay.new_team("Team B", "bob");
    relay.switch_team(&b);
    let team_b = relay.setup("staging");
    relay.switch_team(&a);
    let core = relay.hub().team(&a_id).unwrap();
    let mut stream =
        std::net::TcpStream::connect(relay.url.strip_prefix("http://").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // tiny_http buffers request bodies up to 1024 bytes before it exposes the request.
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"padding":"{}"}}}}"#,
        "x".repeat(2048)
    );
    write!(stream,"POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nX-Apassy-Edge: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        team_a.agent_token,relay.edge_secret,body.len(),&body[..1]).unwrap();
    stream.flush().unwrap();
    wait_counter(&core, 1);
    let (status, retry, answer) = request_with_retry(&relay, &team_a.agent_token, "/v1/access");
    assert_eq!(status, 503, "{answer}");
    assert_eq!(retry.as_deref(), Some("2"));
    assert_eq!(answer["error"]["code"], "busy");
    relay.ok("GET", "/v1/access", &team_b.agent_token, None);
    stream.write_all(&body.as_bytes()[1..]).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    assert!(status_line.starts_with("HTTP/1.1 200"), "{status_line}");
    wait_counter(&core, 0);
    relay.ok("GET", "/v1/access", &team_a.agent_token, None);
    wait_counter(&core, 0);
}

#[test]
fn limits_cli_reads_and_changes_limits_without_other_configuration() {
    let relay = start(UpstreamOptions::default());
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_apassy-relay"))
            .env_clear()
            .env("APASSY_RELAY_DATA", &relay.config.data_dir)
            .args(args)
            .output()
            .unwrap()
    };
    let output = run(&["admin", "limits", relay.team_id.as_str()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        defaults()
    );
    let output = run(&[
        "admin",
        "limits",
        relay.team_id.as_str(),
        "--items",
        "2",
        "--agent-requests",
        "224",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["items"], 2);
    assert_eq!(result["agent_requests"], 224);
    assert_eq!(result["members"], 50);
    assert_eq!(get(&relay, &relay.team_id), result);
    for flags in [
        &["--items", "0"][..],
        &["--agent-requests", "225"][..],
        &["--items", "1", "--items", "2"][..],
    ] {
        let mut args = vec!["admin", "limits", relay.team_id.as_str()];
        args.extend_from_slice(flags);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(get(&relay, &relay.team_id), result);
    }
    let unknown = run(&["admin", "limits", "t_unknownabc"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(unknown.stdout.is_empty());
}

#[test]
fn concurrent_agent_creation_cannot_exceed_the_team_limit() {
    let relay = Arc::new(start(UpstreamOptions::default()));
    set(&relay, json!({"agents":1}));
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|index| {
            let relay = relay.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                relay.call(
                    "POST",
                    "/v1/agents",
                    Some(&relay.owner_token),
                    Some(&json!({"name":format!("agent-{index}")})),
                )
            })
        })
        .collect();
    let answers: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(
        answers.iter().filter(|(status, _)| *status == 200).count(),
        1,
        "{answers:?}"
    );
    for (status, body) in answers {
        if status != 200 {
            assert_eq!(status, 403, "{body}");
            assert_eq!(body["error"]["code"], "team_limit");
        }
    }
    let conn = relay::open_team_file(&relay.config, &relay.team_id);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM agent", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
