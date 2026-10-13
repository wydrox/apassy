//! SPEC26 Connect teams: `POST /v1/connect` without a team code, one team per device
//! key, the relay-wide daily cap, the `connect` limits (`plan_required` on a snapshot
//! push), questions and device links in a Connect team, operator teams as before, the
//! directory migration from 1002 to 1003, and the idle sweep.

#[path = "common/relay.rs"]
mod relay;

use std::time::Duration;

use apassy_relay::config::{RelayConfig, UpstreamOptions};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::encode_b64;
use apassy_relay::ids::TeamId;
use apassy_relay::now_unix;
use apassy_relay::server::directory::TeamLimitsUpdate;
use apassy_relay::server::operator::Command;
use apassy_relay::sync_head::hex;
use relay::{EDGE_SECRET, TestRelay, VAULT_KEY, open_team_file, start, start_with, team_of};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const KEY_ID: &str = "630dcd2966c43366";
const DAY: u64 = 86_400;

/// One signed-in device of a Connect team.
struct Device {
    token: String,
    key: DeviceKey,
    id: u64,
}

/// An HTTP answer with its headers.
struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or_default()
    }
}

fn send(
    base: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> Answer {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"))
        .header("X-Apassy-Edge", EDGE_SECRET);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let mut response = agent
        .run(builder.body(body).expect("request"))
        .expect("http call");
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    Answer {
        status,
        headers,
        body: serde_json::from_str(&text).unwrap_or(Value::String(text)),
    }
}

fn connect_body(team: &str, device_name: &str, key: &DeviceKey) -> Value {
    json!({"v": 1, "team": team, "device_name": device_name, "public_key": key.public_key_b64()})
}

/// `POST /v1/connect` with a body, as the Worker forwards it.
fn post_connect(relay: &TestRelay, body: &Value) -> Answer {
    send(
        &relay.url,
        "POST",
        "/v1/connect",
        None,
        &[("Content-Type", "application/json".to_string())],
        serde_json::to_vec(body).unwrap(),
    )
}

/// A new Connect team of a fresh key. Returns its id and its signed-in Mac.
fn connect(relay: &TestRelay, name: &str) -> (TeamId, Device) {
    let key = DeviceKey::generate().unwrap();
    let made = relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body(name, "Rafal's Mac", &key)),
    );
    let team: TeamId = serde_json::from_value(made["team_id"].clone()).unwrap();
    let token = relay.sign_in(&team, &key);
    let id = made["device_id"].as_u64().unwrap();
    (team, Device { token, key, id })
}

/// Another device of the same member through a confirmed link with the safety words.
fn add_device(relay: &TestRelay, first: &Device, name: &str) -> Device {
    let key = DeviceKey::generate().unwrap();
    let team = team_of(&first.token);
    let made = relay.ok("POST", "/v1/devices/links", &first.token, None);
    let code = made["secret"].as_str().unwrap().to_string();
    let pending = relay.ok(
        "POST",
        "/v1/devices/link",
        "",
        Some(&json!({"code": code, "device_name": name, "public_key": key.public_key_b64()})),
    );
    let words = device::safety_words(&team, &code, &key.public_key());
    assert_eq!(pending["safety"], words);
    let added = relay.ok(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        &first.token,
        Some(&json!({"safety": words})),
    );
    assert_eq!(added["key_holder"], false);
    let token = relay.sign_in(&team, &key);
    let id = added["id"].as_u64().unwrap();
    Device { token, key, id }
}

fn teams(relay: &TestRelay) -> Vec<Value> {
    relay
        .operator(Command::Teams)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn team_info(relay: &TestRelay, team: &TeamId) -> Value {
    teams(relay)
        .into_iter()
        .find(|info| info["id"] == team.as_str())
        .expect("team listed")
}

fn sweep(relay: &TestRelay, dry_run: bool) -> Value {
    relay
        .operator(Command::ConnectSweep {
            idle_days: 30,
            delete_days: 30,
            dry_run,
        })
        .unwrap()
}

/// Runs SQL on `relay.db` with the master key. The relay must be stopped.
fn edit_directory(config: &RelayConfig, sql: &str) {
    let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.execute_batch(sql).unwrap();
}

#[test]
fn connect_makes_a_codeless_team_with_its_device_as_owner() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let answer = post_connect(&relay, &connect_body(" Rafal ", "Rafal's Mac", &key));
    assert_eq!(answer.status, 200, "{}", answer.body);
    let made = &answer.body["result"];
    let mut fields: Vec<&str> = made
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["device_id", "kind", "member_id", "team_id"]);
    assert_eq!(made["kind"], "connect");
    let team: TeamId = serde_json::from_value(made["team_id"].clone()).unwrap();
    assert_ne!(team, relay.team_id);

    // The device signs in like any other: the owner, the key holder, kind connect.
    let public_key = key.public_key_b64();
    let challenge = relay.ok(
        "POST",
        "/v1/auth/challenge",
        "",
        Some(&json!({"team_id": team, "public_key": public_key})),
    );
    let nonce = challenge["nonce"].as_str().unwrap();
    let signature = key
        .sign(&device::sign_in_message(
            &relay.config.public_url,
            &team,
            &public_key,
            nonce,
        ))
        .unwrap();
    let granted = relay.ok(
        "POST",
        "/v1/auth/token",
        "",
        Some(
            &json!({"team_id": team, "public_key": public_key, "nonce": nonce,
            "signature": encode_b64(&signature)}),
        ),
    );
    assert_eq!(granted["team"], "Rafal");
    assert_eq!(granted["member_name"], "owner");
    assert_eq!(granted["role"], "owner");
    assert_eq!(granted["key_holder"], true);
    assert_eq!(granted["device_id"], made["device_id"]);
    assert_eq!(granted["team_kind"], "connect");
    let token = granted["token"].as_str().unwrap();
    let me = relay.ok("GET", "/v1/me", token, None);
    assert_eq!(me["team_kind"], "connect");
    assert_eq!(me["team_id"], team.as_str());
    let devices = relay.ok("GET", "/v1/devices", token, None);
    assert_eq!(devices.as_array().unwrap().len(), 1);
    assert_eq!(devices[0]["name"], "Rafal's Mac");
    assert_eq!(devices[0]["public_key"], public_key);

    // The operator sees the kind and the connect limits.
    let info = team_info(&relay, &team);
    assert_eq!(info["kind"], "connect");
    assert_eq!(info["state"], "active");
    assert_eq!(info["open"], true);
    assert_eq!(info["members"], 1);
    let limits = &info["limits"];
    assert_eq!(
        (
            &limits["members"],
            &limits["items"],
            &limits["agents"],
            &limits["sync_bytes"],
            &limits["question_bytes"],
        ),
        (
            &json!(1),
            &json!(0),
            &json!(0),
            &json!(0),
            &json!(2_097_152)
        )
    );
    assert_eq!(limits["open_questions"], 20);
    assert_eq!(limits["device_questions_per_hour"], 150);
    assert_eq!(team_info(&relay, &relay.team_id)["kind"], "operator");

    // The relay audit names the team and its kind, never the key.
    let created: Vec<_> = relay
        .relay_audit()
        .into_iter()
        .filter(|(_, action, _)| action == "team_created")
        .collect();
    assert_eq!(created.len(), 1);
    let detail: Value = serde_json::from_str(&created[0].2).unwrap();
    assert_eq!(detail, json!({"team_id": team, "kind": "connect"}));
    for (_, _, detail) in relay.relay_audit() {
        assert!(!detail.contains(&public_key), "{detail}");
    }
}

#[test]
fn connect_refuses_bad_bodies_and_bearers_and_lists_nothing() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let good = connect_body("Rafal", "Mac", &key);
    let mut cases = Vec::new();
    for (field, value) in [
        ("v", json!(2)),
        ("team", json!("")),
        ("team", json!("x".repeat(65))),
        ("device_name", json!("")),
        ("device_name", json!("bad\nname")),
        ("public_key", json!("not a key")),
        ("public_key", json!(encode_b64(&[3; 65]))),
    ] {
        let mut body = good.clone();
        body[field] = value;
        cases.push(body);
    }
    let mut unknown = good.clone();
    unknown["code"] = json!("apassy_tcd_0000");
    cases.push(unknown);
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("v");
    cases.push(missing);
    for body in cases {
        let answer = post_connect(&relay, &body);
        assert_eq!(answer.status, 400, "{body}: {}", answer.body);
        assert_eq!(answer.code(), "invalid_request");
    }
    // A bearer token on an edge endpoint is refused.
    let (status, value) = relay.call("POST", "/v1/connect", Some(&relay.owner_token), Some(&good));
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (401, Some("unauthenticated"))
    );
    // The refused bodies used the key up nowhere, and made no team.
    assert_eq!(teams(&relay).len(), 1);
    relay.ok("POST", "/v1/connect", "", Some(&good));
    // No route lists or reads teams.
    for (method, path) in [
        ("GET", "/v1/connect"),
        ("GET", "/v1/teams"),
        ("DELETE", "/v1/connect"),
    ] {
        let (status, _) = relay.call(method, path, None, None);
        assert_eq!(status, 405, "{method} {path}");
    }
    let (status, _) = relay.call("GET", "/v1/connect/teams", None, None);
    assert_eq!(status, 404);
}

#[test]
fn one_public_key_makes_one_connect_team_ever() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let body = connect_body("Rafal", "Mac", &key);
    let made = relay.ok("POST", "/v1/connect", "", Some(&body));
    let team = made["team_id"].as_str().unwrap().to_string();
    let again = post_connect(&relay, &body);
    assert_eq!(again.status, 409);
    assert_eq!(again.code(), "connect_key_used");
    assert!(!again.body.to_string().contains(&team));
    // Another name or device name does not help.
    let renamed = post_connect(&relay, &connect_body("Other", "Other Mac", &key));
    assert_eq!((renamed.status, renamed.code()), (409, "connect_key_used"));
    // The answer is the same for every used key: it names no team.
    let other = DeviceKey::generate().unwrap();
    relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body("B", "Mac", &other)),
    );
    let again_other = post_connect(&relay, &connect_body("B", "Mac", &other));
    assert_eq!(again_other.body, again.body);
    // A key of an operator team is not a Connect key; but once used here it stays used,
    // even after its team is suspended and deleted.
    let team: TeamId = serde_json::from_value(made["team_id"].clone()).unwrap();
    relay
        .operator(Command::Suspend { team: team.clone() })
        .unwrap();
    relay
        .operator(Command::Delete { team: team.clone() })
        .unwrap();
    assert!(teams(&relay).iter().all(|info| info["id"] != team.as_str()));
    let after = post_connect(&relay, &body);
    assert_eq!((after.status, after.code()), (409, "connect_key_used"));
    let (status, _) = relay.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": key.public_key_b64()})),
    );
    assert_eq!(status, 401);
}

#[test]
fn the_relay_makes_at_most_connect_teams_per_day() {
    let relay = start_with(
        |config| config.connect_teams_per_day = 2,
        UpstreamOptions::default(),
    );
    let first = DeviceKey::generate().unwrap();
    relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body("A", "Mac", &first)),
    );
    let second = DeviceKey::generate().unwrap();
    relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body("B", "Mac", &second)),
    );
    let third = DeviceKey::generate().unwrap();
    let busy = post_connect(&relay, &connect_body("C", "Mac", &third));
    assert_eq!((busy.status, busy.code()), (503, "busy"));
    assert_eq!(busy.header("Retry-After"), Some("3600"));
    assert_eq!(
        busy.headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Retry-After"))
            .count(),
        1
    );
    // A used key still gets its 409, and no file was made for the refused team.
    let used = post_connect(&relay, &connect_body("A", "Mac", &first));
    assert_eq!((used.status, used.code()), (409, "connect_key_used"));
    assert_eq!(teams(&relay).len(), 3);
    let files = std::fs::read_dir(relay.config.teams_dir())
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".db")
        })
        .count();
    assert_eq!(files, 3);
    // The operator sees the refusal in the relay audit, without the key.
    let refused: Vec<_> = relay
        .relay_audit()
        .into_iter()
        .filter(|(_, action, _)| action == "connect_refused")
        .collect();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].2, r#"{"reason":"busy"}"#);
    // Operator teams do not count, and are not capped.
    relay.new_team("Family", "rafal");
    // The window is 24 hours: one Connect team older than that no longer counts.
    let mut relay = relay;
    relay.edit_offline(|config| {
        edit_directory(
            config,
            &format!(
                "UPDATE connect_key SET created_at = created_at - {} WHERE rowid = (SELECT min(rowid) FROM connect_key)",
                DAY + 1
            ),
        );
    });
    relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body("C", "Mac", &third)),
    );
    let fourth = DeviceKey::generate().unwrap();
    let busy = post_connect(&relay, &connect_body("D", "Mac", &fourth));
    assert_eq!((busy.status, busy.code()), (503, "busy"));
}

#[test]
fn connect_off_when_the_cap_is_zero() {
    let relay = start_with(
        |config| config.connect_teams_per_day = 0,
        UpstreamOptions::default(),
    );
    let key = DeviceKey::generate().unwrap();
    let answer = post_connect(&relay, &connect_body("A", "Mac", &key));
    assert_eq!((answer.status, answer.code()), (503, "busy"));
    assert_eq!(teams(&relay).len(), 1);
    // Operator teams still work.
    relay.new_team("Family", "rafal");
}

/// The headers of a first push of `body` by `mac`.
fn first_push(team: &TeamId, mac: &Device, body: &[u8]) -> Vec<(&'static str, String)> {
    let text = format!(
        "apassy-relay-sync-head-v1\n{VAULT} 1 {} {}\n{ZEROS} {team}/{} 1790000000",
        hex(&Sha256::digest(body)),
        body.len(),
        mac.id
    );
    vec![
        ("If-Match", "\"0\"".to_string()),
        ("Content-Type", "application/octet-stream".to_string()),
        ("X-Apassy-Sync-Head", encode_b64(text.as_bytes())),
        (
            "X-Apassy-Sync-Signature",
            encode_b64(&mac.key.sign(text.as_bytes()).unwrap()),
        ),
    ]
}

#[test]
fn a_snapshot_push_to_a_connect_team_is_plan_required() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Rafal");
    let body = vec![7u8; 4096];
    let refused = send(
        &relay.url,
        "PUT",
        "/v1/sync/snapshot",
        Some(&mac.token),
        &first_push(&team, &mac, &body),
        body.clone(),
    );
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(refused.code(), "plan_required");
    // Nothing is stored; the head says version 0.
    let head = relay.ok("GET", "/v1/sync/head", &mac.token, None);
    assert_eq!(head["version"], 0);
    assert!(!relay.config.sync_dir(&team).join("1.bin").exists());
    // Still 401 without a token: the plan check comes after the token.
    let anonymous = send(
        &relay.url,
        "PUT",
        "/v1/sync/snapshot",
        None,
        &first_push(&team, &mac, &body),
        body.clone(),
    );
    assert_eq!(anonymous.status, 401);
    // The refusal is in the team audit.
    let conn = open_team_file(&relay.config, &team);
    let reasons: Vec<String> = conn
        .prepare("SELECT detail FROM audit WHERE action = 'sync_refused'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(reasons, [r#"{"reason":"plan_required"}"#]);
    drop(conn);

    // The operator lifts the limit for this team only: the same push passes.
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                sync_bytes: Some(67_108_864),
                ..Default::default()
            }),
        })
        .unwrap();
    let pushed = send(
        &relay.url,
        "PUT",
        "/v1/sync/snapshot",
        Some(&mac.token),
        &first_push(&team, &mac, &body),
        body.clone(),
    );
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    // And can set it back to 0.
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                sync_bytes: Some(0),
                ..Default::default()
            }),
        })
        .unwrap();
    assert_eq!(team_info(&relay, &team)["limits"]["sync_bytes"], 0);
}

#[test]
fn connect_limits_one_member_no_items_no_agents() {
    let relay = start(UpstreamOptions::default());
    let (_, mac) = connect(&relay, "Rafal");
    // An invite can be made, but a join is refused: one member.
    let invite = relay.ok(
        "POST",
        "/v1/invites",
        &mac.token,
        Some(&json!({"role": "member"})),
    );
    let key = DeviceKey::generate().unwrap();
    let (status, value) = relay.call(
        "POST",
        "/v1/join",
        None,
        Some(
            &json!({"code": invite["secret"], "name": "guest", "device_name": "Phone",
            "public_key": key.public_key_b64()}),
        ),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("team_limit"))
    );
    // No items and no agents: no runs and no proxy session.
    let collection = relay.ok(
        "POST",
        "/v1/collections",
        &mac.token,
        Some(&json!({"name": "Work"})),
    );
    let sealed = relay::seal("sk_test_value");
    let (status, value) = relay.call(
        "POST",
        "/v1/items",
        Some(&mac.token),
        Some(&relay::item_request(
            collection["id"].as_u64().unwrap(),
            "OPS_TOKEN",
            &sealed,
            json!({"hosts": ["api.example.com"], "environment": "staging"}),
        )),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("team_limit")),
        "{value}"
    );
    let (status, value) = relay.call(
        "POST",
        "/v1/agents",
        Some(&mac.token),
        Some(&json!({"name": "claude"})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("team_limit")),
        "{value}"
    );
}

#[test]
fn device_links_need_the_safety_words_and_stop_at_ten_devices() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Rafal");
    // Wrong words: 409, the link stays pending; the right words add the device.
    let key = DeviceKey::generate().unwrap();
    let made = relay.ok("POST", "/v1/devices/links", &mac.token, None);
    let code = made["secret"].as_str().unwrap().to_string();
    let pending = relay.ok(
        "POST",
        "/v1/devices/link",
        "",
        Some(&json!({"code": code, "device_name": "iPhone", "public_key": key.public_key_b64()})),
    );
    let (status, value) = relay.call(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        Some(&mac.token),
        Some(&json!({"safety": "wrong words"})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (409, Some("conflict"))
    );
    let (status, value) = relay.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": key.public_key_b64()})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("join_pending"))
    );
    let words = device::safety_words(&team, &code, &key.public_key());
    relay.ok(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        &mac.token,
        Some(&json!({"safety": words})),
    );
    let phone_token = relay.sign_in(&team, &key);
    let me = relay.ok("GET", "/v1/me", &phone_token, None);
    assert_eq!(me["member_name"], "owner");
    assert_eq!(me["key_holder"], Value::Null);
    assert_eq!(me["team_kind"], "connect");
    // Up to 10 devices of the member; the 11th link is refused.
    for n in 3..=10 {
        add_device(&relay, &mac, &format!("Device {n}"));
    }
    let devices = relay.ok("GET", "/v1/devices", &mac.token, None);
    assert_eq!(devices.as_array().unwrap().len(), 10);
    let (status, value) = relay.call("POST", "/v1/devices/links", Some(&mac.token), None);
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (409, Some("conflict")),
        "{value}"
    );
}

fn card(qid: &str) -> Value {
    json!({"v": 1, "qid": qid, "to": "member", "expires_at": now_unix() + 300,
        "key_id": KEY_ID, "nonce": "AAECAwQFBgcICQoL", "ciphertext": encode_b64(&[9; 40])})
}

fn envelope(nonce: &str, byte: u8) -> Value {
    json!({"v": 1, "key_id": KEY_ID, "nonce": nonce, "ciphertext": encode_b64(&[byte; 30])})
}

#[test]
fn questions_go_from_the_mac_to_the_linked_iphone_and_back() {
    let relay = start(UpstreamOptions::default());
    let (_, mac) = connect(&relay, "Rafal");
    let phone = add_device(&relay, &mac, "iPhone");
    let qid = encode_b64(&[1; 16]);
    let posted = relay.ok("POST", "/v1/questions", &mac.token, Some(&card(&qid)));
    assert_eq!(posted["qid"], qid);
    // The asking Mac does not see its own question; the iPhone does.
    let mine = relay.ok("GET", "/v1/questions?since=0", &mac.token, None);
    assert!(mine["questions"].as_array().unwrap().is_empty());
    let listed = relay.ok("GET", "/v1/questions?since=0", &phone.token, None);
    let questions = listed["questions"].as_array().unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0]["qid"], qid);
    assert_eq!(questions[0]["from_device_id"], mac.id);
    assert_eq!(questions[0]["from_device_name"], "Rafal's Mac");
    let answered = relay.ok(
        "POST",
        &format!("/v1/questions/{qid}/answers"),
        &phone.token,
        Some(&envelope("EBESExQVFhcYGRob", 5)),
    );
    let answers = relay.ok(
        "GET",
        &format!("/v1/questions/{qid}/answers?after=0"),
        &mac.token,
        None,
    );
    let answers = answers["answers"].as_array().unwrap().clone();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["id"], answered["id"]);
    assert_eq!(answers[0]["device_id"], phone.id);
    assert_eq!(answers[0]["role"], "owner");
    let settled = relay.ok(
        "POST",
        &format!("/v1/questions/{qid}/settle"),
        &mac.token,
        Some(&envelope("ICEiIyQlJicoKSor", 6)),
    );
    assert_eq!(settled["state"], "settled");
    let after = relay.ok("GET", "/v1/questions?since=0", &phone.token, None);
    assert_eq!(after["questions"][0]["state"], "settled");
    // The team's question storage is the Connect preset: 2 MiB.
    let card_bytes = 32_784;
    let mut posted = 0;
    let mut refused = None;
    for n in 0..100u8 {
        let qid = encode_b64(&[n.wrapping_add(10); 16]);
        let mut body = card(&qid);
        body["ciphertext"] = json!(encode_b64(&vec![n; card_bytes]));
        let (status, value) = relay.call("POST", "/v1/questions", Some(&mac.token), Some(&body));
        if status == 200 {
            posted += 1;
            // Settle at once, so the open-question limits do not stop the loop first.
            relay.ok(
                "POST",
                &format!("/v1/questions/{qid}/settle"),
                &mac.token,
                Some(&envelope("ICEiIyQlJicoKSor", 6)),
            );
        } else {
            refused = Some(value);
            break;
        }
    }
    let refused = refused.expect("the 2 MiB budget refuses a card");
    assert_eq!(refused["error"]["code"], "too_many_questions");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("question_bytes"),
        "{refused}"
    );
    // About 2 MiB of cards and settles: far fewer than the 8 MiB of an operator team.
    assert!((50..=70).contains(&posted), "{posted}");
}

#[test]
fn operator_teams_are_unchanged() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let code = relay.operator(Command::TeamCode { hours: 1 }).unwrap();
    let made = relay.ok(
        "POST",
        "/v1/teams",
        "",
        Some(
            &json!({"code": code["code"], "team": "Family", "owner": "rafal",
            "device_name": "Owner device", "public_key": key.public_key_b64()}),
        ),
    );
    let mut fields: Vec<&str> = made
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["device_id", "member_id", "team_id"]);
    let team: TeamId = serde_json::from_value(made["team_id"].clone()).unwrap();
    let info = team_info(&relay, &team);
    assert_eq!(info["kind"], "operator");
    assert_eq!(
        info["limits"],
        serde_json::to_value(apassy_relay::server::directory::TeamLimits::default()).unwrap()
    );
    let token = relay.sign_in(&team, &key);
    assert_eq!(
        relay.ok("GET", "/v1/me", &token, None)["team_kind"],
        "operator"
    );
    // The same key can still make a Connect team: operator keys are not Connect keys.
    relay.ok(
        "POST",
        "/v1/connect",
        "",
        Some(&connect_body("Mine", "Mac", &key)),
    );
    // A snapshot push of an operator team still passes.
    let mac = Device {
        id: made["device_id"].as_u64().unwrap(),
        token,
        key,
    };
    let body = vec![3u8; 2048];
    let pushed = send(
        &relay.url,
        "PUT",
        "/v1/sync/snapshot",
        Some(&mac.token),
        &first_push(&team, &mac, &body),
        body,
    );
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    // The team made by `init` is an operator team, with its member token.
    assert_eq!(
        relay.ok("GET", "/v1/me", &relay.owner_token, None)["team_kind"],
        "operator"
    );
    // A team code used once is still refused the second time.
    let (status, value) = relay.call(
        "POST",
        "/v1/teams",
        None,
        Some(&json!({"code": code["code"], "team": "Again", "owner": "rafal",
            "device_name": "Owner device", "public_key": DeviceKey::generate().unwrap().public_key_b64()})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("invite_invalid"))
    );
}

#[test]
fn the_directory_moves_from_1002_to_1003_and_keeps_its_teams() {
    let mut relay = start(UpstreamOptions::default());
    let (family_token, family_key) = relay.new_team_device("Family", "rafal");
    let family = team_of(&family_token);
    relay
        .operator(Command::Limits {
            team: family.clone(),
            set: Some(TeamLimitsUpdate {
                members: Some(7),
                ..Default::default()
            }),
        })
        .unwrap();
    let paused = team_of(&relay.new_team("Paused", "rafal"));
    relay
        .operator(Command::Suspend {
            team: paused.clone(),
        })
        .unwrap();
    // Back to the directory of the image before Connect teams.
    relay.edit_offline(|config| {
        edit_directory(
            config,
            "ALTER TABLE team DROP COLUMN kind;
             ALTER TABLE team DROP COLUMN suspend_reason;
             DROP INDEX connect_key_created;
             DROP TABLE connect_key;
             PRAGMA user_version = 1002;",
        );
    });
    // The restart above moved it to 1003 again.
    let conn = rusqlite::Connection::open(relay.config.directory_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1003);
    let kinds: Vec<String> = conn
        .prepare("SELECT kind FROM team ORDER BY created_at")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(kinds, ["operator", "operator", "operator"]);
    drop(conn);
    let infos = teams(&relay);
    assert_eq!(infos.len(), 3);
    for info in &infos {
        assert_eq!(info["kind"], "operator");
    }
    assert_eq!(team_info(&relay, &family)["limits"]["members"], 7);
    assert_eq!(team_info(&relay, &paused)["state"], "suspended");
    // Every team works as before: the init team's member token, the device sign-in.
    relay.ok("GET", "/v1/me", &relay.owner_token, None);
    let token = relay.sign_in(&family, &family_key);
    assert_eq!(relay.ok("GET", "/v1/me", &token, None)["team"], "Family");
    relay.operator(Command::Resume { team: paused }).unwrap();
    // And Connect works on the moved directory.
    connect(&relay, "After");
}

#[test]
fn the_idle_sweep_suspends_then_deletes_lone_idle_connect_teams() {
    let mut relay = start(UpstreamOptions::default());
    let (lone, lone_mac) = connect(&relay, "Lone");
    let (pair, pair_mac) = connect(&relay, "Pair");
    add_device(&relay, &pair_mac, "iPhone");
    let (fresh, _) = connect(&relay, "Fresh");
    let (held, _) = connect(&relay, "Held");
    let (family_token, _) = relay.new_team_device("Family", "rafal");
    let family = team_of(&family_token);
    relay
        .operator(Command::Suspend { team: held.clone() })
        .unwrap();
    // Nothing is idle yet.
    let report = sweep(&relay, false);
    assert_eq!(report["suspended"], json!([]));
    assert_eq!(report["deleted"], json!([]));
    // 31 days without a sign-in for every device of lone, pair, and family.
    let old = now_unix() - 31 * DAY;
    relay.edit_offline(|config| {
        for team in [&lone, &pair, &family] {
            open_team_file(config, team)
                .execute_batch(&format!(
                    "UPDATE device SET last_seen_at = {old}, created_at = {old};"
                ))
                .unwrap();
        }
    });
    let dry = sweep(&relay, true);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["suspended"], json!([lone]));
    assert_eq!(team_info(&relay, &lone)["state"], "active");
    let report = sweep(&relay, false);
    assert_eq!(report["suspended"], json!([lone]));
    assert_eq!(report["deleted"], json!([]));
    assert_eq!(report["failed"], json!([]));
    let info = team_info(&relay, &lone);
    assert_eq!(info["state"], "suspended");
    assert_eq!(info["suspend_reason"], "idle");
    // Its device can no longer sign in; the others are untouched.
    let (status, _) = relay.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": lone, "public_key": lone_mac.key.public_key_b64()})),
    );
    assert_eq!(status, 401);
    for team in [&pair, &fresh, &family] {
        assert_eq!(team_info(&relay, team)["state"], "active");
    }
    // A second sweep the same day deletes nothing.
    assert_eq!(sweep(&relay, false)["deleted"], json!([]));
    // 31 days after the suspensions, the idle one goes; the one the operator suspended
    // stays.
    relay.edit_offline(|config| {
        edit_directory(
            config,
            &format!("UPDATE team SET suspended_at = {old} WHERE state = 'suspended';"),
        );
    });
    let dry = sweep(&relay, true);
    assert_eq!(dry["deleted"], json!([lone]));
    assert!(relay.config.team_path(&lone).exists());
    let report = sweep(&relay, false);
    assert_eq!(report["deleted"], json!([lone]));
    assert!(!relay.config.team_path(&lone).exists());
    assert!(teams(&relay).iter().all(|info| info["id"] != lone.as_str()));
    assert_eq!(team_info(&relay, &held)["state"], "suspended");
    assert!(team_info(&relay, &held)["suspend_reason"].is_null());
    // The deleted team's key stays used.
    let again = post_connect(&relay, &connect_body("Lone", "Mac", &lone_mac.key));
    assert_eq!((again.status, again.code()), (409, "connect_key_used"));
    // A resumed idle team is active again and loses its reason.
    let (late, _) = connect(&relay, "Late");
    relay.edit_offline(|config| {
        open_team_file(config, &late)
            .execute_batch(&format!(
                "UPDATE device SET last_seen_at = {old}, created_at = {old};"
            ))
            .unwrap();
    });
    assert_eq!(sweep(&relay, false)["suspended"], json!([late]));
    relay
        .operator(Command::Resume { team: late.clone() })
        .unwrap();
    let info = team_info(&relay, &late);
    assert_eq!(info["state"], "active");
    assert!(info["suspend_reason"].is_null());
}
