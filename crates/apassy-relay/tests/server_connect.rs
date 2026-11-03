//! SPEC26 Connect teams: `POST /v1/connect` without a team code, one team per device
//! key, the relay-wide daily cap, the `connect` limits (`plan_required` on a snapshot
//! push), questions and device links in a Connect team, operator teams as before, the
//! directory migration from 1002 to 1005, and the idle sweep.

#[path = "common/relay.rs"]
mod relay;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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

/// The body of `POST /v1/connect`, signed by `key` for this relay.
fn connect_body(relay: &TestRelay, team: &str, device_name: &str, key: &DeviceKey) -> Value {
    let public_key = key.public_key_b64();
    let signature = key
        .sign(&device::connect_message(
            &relay.config.public_url,
            &public_key,
        ))
        .unwrap();
    json!({"v": 1, "team": team, "device_name": device_name, "public_key": public_key,
        "signature": encode_b64(&signature)})
}

/// A new client prefix for each call, so the per-prefix count of the relay does not
/// stop tests that make many teams.
fn next_prefix() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    format!("2001:db8:{:x}::/48", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// `POST /v1/connect` with a body, as the Worker forwards it: from a new client prefix.
fn post_connect(relay: &TestRelay, body: &Value) -> Answer {
    post_connect_from(relay, body, Some(&next_prefix()))
}

/// `POST /v1/connect` from `prefix` (`X-Apassy-Client-Prefix` with the Worker's proof,
/// `X-Apassy-Client-Prefix-Mac`), or without the headers.
fn post_connect_from(relay: &TestRelay, body: &Value, prefix: Option<&str>) -> Answer {
    let mac = prefix.map(|prefix| apassy_relay::server::connect::prefix_mac(EDGE_SECRET, prefix));
    post_connect_with(relay, body, prefix, mac.as_deref())
}

/// `POST /v1/connect` with these prefix and proof headers, each when given.
fn post_connect_with(
    relay: &TestRelay,
    body: &Value,
    prefix: Option<&str>,
    mac: Option<&str>,
) -> Answer {
    let mut headers = vec![("Content-Type", "application/json".to_string())];
    if let Some(prefix) = prefix {
        headers.push(("X-Apassy-Client-Prefix", prefix.to_string()));
    }
    if let Some(mac) = mac {
        headers.push(("X-Apassy-Client-Prefix-Mac", mac.to_string()));
    }
    send(
        &relay.url,
        "POST",
        "/v1/connect",
        None,
        &headers,
        serde_json::to_vec(body).unwrap(),
    )
}

/// `POST /v1/connect` that must answer 200. Returns `result`.
fn connect_ok(relay: &TestRelay, body: &Value) -> Value {
    let answer = post_connect(relay, body);
    assert_eq!(answer.status, 200, "{}", answer.body);
    answer.body["result"].clone()
}

/// A new Connect team of a fresh key. Returns its id and its signed-in Mac.
fn connect(relay: &TestRelay, name: &str) -> (TeamId, Device) {
    let key = DeviceKey::generate().unwrap();
    let made = connect_ok(relay, &connect_body(relay, name, "Rafal's Mac", &key));
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

/// The team ids of a sweep report list, sorted.
fn sorted(list: &Value) -> Vec<String> {
    let mut ids: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
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

/// The first column of each row of a query on `relay.db`, as text. The relay must be
/// stopped.
fn read_directory(config: &RelayConfig, sql: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(config.directory_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    conn.prepare(sql)
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
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
    let answer = post_connect(
        &relay,
        &connect_body(&relay, " Rafal ", "Rafal's Mac", &key),
    );
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
    let good = connect_body(&relay, "Rafal", "Mac", &key);
    let mut cases = Vec::new();
    for (field, value) in [
        ("v", json!(2)),
        ("team", json!("")),
        ("team", json!("x".repeat(65))),
        ("device_name", json!("")),
        ("device_name", json!("bad\nname")),
        ("public_key", json!("not a key")),
        ("public_key", json!(encode_b64(&[3; 65]))),
        // 0x04 and 64 bytes that are not a point on P-256.
        ("public_key", json!(encode_b64(&[4; 65]))),
        ("signature", json!("")),
        ("signature", json!("not base64!")),
        ("signature", json!(encode_b64(&[0x30; 70]))),
    ] {
        let mut body = good.clone();
        body[field] = value;
        cases.push(body);
    }
    let mut unknown = good.clone();
    unknown["code"] = json!("apassy_tcd_0000");
    cases.push(unknown);
    for field in ["v", "signature"] {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(field);
        cases.push(missing);
    }
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
    connect_ok(&relay, &good);
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
    let body = connect_body(&relay, "Rafal", "Mac", &key);
    let made = connect_ok(&relay, &body);
    let team = made["team_id"].as_str().unwrap().to_string();
    let again = post_connect(&relay, &body);
    assert_eq!(again.status, 409);
    assert_eq!(again.code(), "connect_key_used");
    assert!(!again.body.to_string().contains(&team));
    // Another name or device name does not help.
    let renamed = post_connect(&relay, &connect_body(&relay, "Other", "Other Mac", &key));
    assert_eq!((renamed.status, renamed.code()), (409, "connect_key_used"));
    // The answer is the same for every used key: it names no team.
    let other = DeviceKey::generate().unwrap();
    connect_ok(&relay, &connect_body(&relay, "B", "Mac", &other));
    let again_other = post_connect(&relay, &connect_body(&relay, "B", "Mac", &other));
    assert_eq!(again_other.body, again.body);
    // A key of an operator team is not a Connect key; but once used here it stays used,
    // even after its team is suspended and deleted.
    let team: TeamId = serde_json::from_value(made["team_id"].clone()).unwrap();
    relay
        .operator(Command::Suspend { team: team.clone() })
        .unwrap();
    relay
        .operator(Command::Delete {
            team: team.clone(),
            free_connect_key: false,
        })
        .unwrap();
    assert!(teams(&relay).iter().all(|info| info["id"] != team.as_str()));
    let after = post_connect(&relay, &body);
    assert_eq!((after.status, after.code()), (409, "connect_key_used"));
    // The used key no longer names its deleted team; the live team's key still does.
    let mut relay = relay;
    relay.edit_offline(|config| {
        let links = read_directory(
            config,
            "SELECT coalesce(team_id, '-') FROM connect_key ORDER BY rowid",
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links[0], "-");
        assert!(links[1].starts_with("t_"));
    });
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
    connect_ok(&relay, &connect_body(&relay, "A", "Mac", &first));
    let second = DeviceKey::generate().unwrap();
    connect_ok(&relay, &connect_body(&relay, "B", "Mac", &second));
    let third = DeviceKey::generate().unwrap();
    let busy = post_connect(&relay, &connect_body(&relay, "C", "Mac", &third));
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
    let used = post_connect(&relay, &connect_body(&relay, "A", "Mac", &first));
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
    connect_ok(&relay, &connect_body(&relay, "C", "Mac", &third));
    let fourth = DeviceKey::generate().unwrap();
    let busy = post_connect(&relay, &connect_body(&relay, "D", "Mac", &fourth));
    assert_eq!((busy.status, busy.code()), (503, "busy"));
}

#[test]
fn connect_off_when_the_cap_is_zero() {
    let relay = start_with(
        |config| config.connect_teams_per_day = 0,
        UpstreamOptions::default(),
    );
    let key = DeviceKey::generate().unwrap();
    let answer = post_connect(&relay, &connect_body(&relay, "A", "Mac", &key));
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

/// A snapshot push of `body` by `mac` as the first version.
fn push_first(relay: &TestRelay, team: &TeamId, mac: &Device, body: &[u8]) -> Answer {
    send(
        &relay.url,
        "PUT",
        "/v1/sync/snapshot",
        Some(&mac.token),
        &first_push(team, mac, body),
        body.to_vec(),
    )
}

#[test]
fn a_connect_team_gets_the_configured_sync_bytes() {
    // The hosted relay's setting until Apassy Connect starts (plans section 4.1).
    let mut relay = start_with(
        |config| config.connect_sync_bytes = 67_108_864,
        UpstreamOptions::default(),
    );
    let (team, mac) = connect(&relay, "Rafal");
    let info = team_info(&relay, &team);
    assert_eq!(info["kind"], "connect");
    assert_eq!(info["limits"]["sync_bytes"], 67_108_864);
    // The rest of the preset is as before: one member, no items, no agents.
    assert_eq!(
        (
            &info["limits"]["members"],
            &info["limits"]["items"],
            &info["limits"]["agents"]
        ),
        (&json!(1), &json!(0), &json!(0))
    );
    // The first push of a vault passes, and the head names version 1.
    let body = vec![7u8; 4096];
    let pushed = push_first(&relay, &team, &mac, &body);
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let head = relay.ok("GET", "/v1/sync/head", &mac.token, None);
    assert_eq!(head["version"], 1);
    assert!(relay.config.sync_dir(&team).join("1.bin").exists());
    // The file cap has room for the sync heads: 2 + 1 + 8 + 16 MiB.
    assert_eq!(info["file_cap"], 27 * 1_048_576);
    // A team keeps the value it was made with when the setting changes: a relay that
    // sets 0 again makes teams with `plan_required`, and the old team still syncs.
    relay.config.connect_sync_bytes = 0;
    let restarted = relay.restart();
    let (late, late_mac) = connect(&restarted, "Late");
    assert_eq!(team_info(&restarted, &late)["limits"]["sync_bytes"], 0);
    let refused = push_first(&restarted, &late, &late_mac, &body);
    assert_eq!((refused.status, refused.code()), (403, "plan_required"));
    assert_eq!(
        team_info(&restarted, &team)["limits"]["sync_bytes"],
        67_108_864
    );
}

#[test]
fn connect_sync_bytes_zero_keeps_plan_required() {
    // The default of a relay that the owner runs, and of the hosted relay at the cutover.
    let relay = start(UpstreamOptions::default());
    assert_eq!(relay.config.connect_sync_bytes, 0);
    let (team, mac) = connect(&relay, "Rafal");
    assert_eq!(team_info(&relay, &team)["limits"]["sync_bytes"], 0);
    assert_eq!(team_info(&relay, &team)["file_cap"], 11 * 1_048_576);
    let refused = push_first(&relay, &team, &mac, &[7u8; 4096]);
    assert_eq!((refused.status, refused.code()), (403, "plan_required"));
}

#[test]
fn the_idle_sweep_takes_a_codeless_sync_team_only_without_a_head() {
    let mut relay = start_with(
        |config| config.connect_sync_bytes = 67_108_864,
        UpstreamOptions::default(),
    );
    let (idle, _) = connect(&relay, "Idle");
    let (synced, mac) = connect(&relay, "Synced");
    let pushed = push_first(&relay, &synced, &mac, &[7u8; 4096]);
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let old = now_unix() - 31 * DAY;
    relay.edit_offline(|config| {
        for team in [&idle, &synced] {
            open_team_file(config, team)
                .execute_batch(&format!(
                    "UPDATE device SET last_seen_at = {old}, created_at = {old};"
                ))
                .unwrap();
        }
    });
    // The setting's preset is a Connect preset: an idle team without a head goes; a
    // team with a vault sync head never does.
    assert_eq!(sweep(&relay, false)["suspended"], json!([idle]));
    assert_eq!(team_info(&relay, &synced)["state"], "active");
}

#[test]
fn connect_limits_one_member_no_items_no_agents() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Rafal");
    // One member: no invite. No items: no collection, policy, or grant. No agents.
    for (method, path, body, limit) in [
        ("POST", "/v1/invites", json!({"role": "member"}), "members"),
        ("POST", "/v1/collections", json!({"name": "Work"}), "items"),
        (
            "PUT",
            "/v1/collections/1/policy",
            json!({"mode": "ask"}),
            "items",
        ),
        (
            "POST",
            "/v1/grants",
            json!({"collection_id": 1, "member_id": 1}),
            "items",
        ),
        ("POST", "/v1/agents", json!({"name": "claude"}), "agents"),
    ] {
        for _ in 0..3 {
            let (status, value) = relay.call(method, path, Some(&mac.token), Some(&body));
            assert_eq!(
                (status, value["error"]["code"].as_str()),
                (403, Some("team_limit")),
                "{method} {path}: {value}"
            );
            assert!(
                value["error"]["message"].as_str().unwrap().contains(limit),
                "{value}"
            );
        }
    }
    // Nothing was written but one `limit_reached` row per limit (ten seconds apart).
    let conn = open_team_file(&relay.config, &team);
    let count = |sql: &str| conn.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap();
    assert_eq!(count("SELECT count(*) FROM invite"), 0);
    assert_eq!(count("SELECT count(*) FROM collection"), 0);
    assert_eq!(count("SELECT count(*) FROM access_grant"), 0);
    assert_eq!(count("SELECT count(*) FROM agent"), 0);
    assert_eq!(
        count("SELECT count(*) FROM audit WHERE action = 'limit_reached'"),
        3
    );
    let others: Vec<String> = conn
        .prepare(
            "SELECT action FROM audit WHERE action NOT IN \
             ('limit_reached', 'team_created', 'device_added', 'device_signed_in', \
             'host_bootstrap_ended')",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(others, Vec::<String>::new());
    drop(conn);
    // A plan that gives the team items and members lifts the refusals.
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                items: Some(10),
                members: Some(3),
                ..Default::default()
            }),
        })
        .unwrap();
    relay.ok(
        "POST",
        "/v1/collections",
        &mac.token,
        Some(&json!({"name": "Work"})),
    );
    relay.ok(
        "POST",
        "/v1/invites",
        &mac.token,
        Some(&json!({"role": "member"})),
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
    connect_ok(&relay, &connect_body(&relay, "Mine", "Mac", &key));
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
fn the_directory_moves_from_1002_to_1005_and_keeps_its_teams() {
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
             ALTER TABLE team_code DROP COLUMN kind;
             DROP INDEX connect_key_created;
             DROP TABLE connect_key;
             DROP TABLE oauth_refresh;
             DROP TABLE connect_request;
             DROP TABLE oauth_client;
             PRAGMA user_version = 1002;",
        );
    });
    // The restart above moved it to 1005 again.
    let conn = rusqlite::Connection::open(relay.config.directory_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
        .unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1005);
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
fn the_idle_sweep_suspends_then_deletes_idle_connect_teams() {
    let mut relay = start(UpstreamOptions::default());
    let (lone, lone_mac) = connect(&relay, "Lone");
    // Two devices do not keep an idle team: only a sign-in does.
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
    assert_eq!(sorted(&dry["suspended"]), sorted(&json!([lone, pair])));
    assert_eq!(team_info(&relay, &lone)["state"], "active");
    let report = sweep(&relay, false);
    assert_eq!(sorted(&report["suspended"]), sorted(&json!([lone, pair])));
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
    assert_eq!(team_info(&relay, &pair)["state"], "suspended");
    for team in [&fresh, &family] {
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
    assert_eq!(sorted(&dry["deleted"]), sorted(&json!([lone, pair])));
    assert!(relay.config.team_path(&lone).exists());
    let report = sweep(&relay, false);
    assert_eq!(sorted(&report["deleted"]), sorted(&json!([lone, pair])));
    assert!(!relay.config.team_path(&lone).exists());
    assert!(!relay.config.team_path(&pair).exists());
    assert!(teams(&relay).iter().all(|info| info["id"] != lone.as_str()));
    assert_eq!(team_info(&relay, &held)["state"], "suspended");
    assert!(team_info(&relay, &held)["suspend_reason"].is_null());
    // The deleted team's key stays used.
    let again = post_connect(&relay, &connect_body(&relay, "Lone", "Mac", &lone_mac.key));
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

#[test]
fn connect_needs_a_signature_of_its_own_key_for_this_relay() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let other = DeviceKey::generate().unwrap();
    let public_key = key.public_key_b64();
    let signed = |signer: &DeviceKey, message: &[u8]| -> Value {
        let mut body = connect_body(&relay, "Rafal", "Mac", &key);
        body["signature"] = json!(encode_b64(&signer.sign(message).unwrap()));
        body
    };
    for body in [
        // Another key signed the right message.
        signed(
            &other,
            &device::connect_message(&relay.config.public_url, &public_key),
        ),
        // The right key signed for another relay.
        signed(
            &key,
            &device::connect_message("https://other-relay.example", &public_key),
        ),
        // The right key signed another key's message.
        signed(
            &key,
            &device::connect_message(&relay.config.public_url, &other.public_key_b64()),
        ),
        // A sign-in message is not a connect message.
        signed(
            &key,
            &device::sign_in_message(&relay.config.public_url, &relay.team_id, &public_key, "N"),
        ),
    ] {
        let answer = post_connect(&relay, &body);
        assert_eq!(
            (answer.status, answer.code()),
            (400, "invalid_request"),
            "{}",
            answer.body
        );
    }
    // No refusal used the key or made a team.
    assert_eq!(teams(&relay).len(), 1);
    // A trailing slash on the origin signs the same message.
    let mut body = connect_body(&relay, "Rafal", "Mac", &key);
    body["signature"] = json!(encode_b64(
        &key.sign(&device::connect_message(
            &format!("{}/", relay.config.public_url),
            &public_key
        ))
        .unwrap()
    ));
    connect_ok(&relay, &body);
}

#[test]
fn a_public_key_off_the_curve_is_refused_on_every_route() {
    let relay = start(UpstreamOptions::default());
    let mut point = [7u8; 65];
    point[0] = 4;
    let bogus = encode_b64(&point);
    let mut body = connect_body(&relay, "Rafal", "Mac", &DeviceKey::generate().unwrap());
    body["public_key"] = json!(bogus);
    let answer = post_connect(&relay, &body);
    assert_eq!((answer.status, answer.code()), (400, "invalid_request"));
    let code = relay.operator(Command::TeamCode { hours: 1 }).unwrap();
    let (status, value) = relay.call(
        "POST",
        "/v1/teams",
        None,
        Some(
            &json!({"code": code["code"], "team": "Family", "owner": "rafal",
            "device_name": "Owner device", "public_key": bogus}),
        ),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (400, Some("invalid_request"))
    );
    // The team code was not used up by the refused key.
    relay.ok(
        "POST",
        "/v1/teams",
        "",
        Some(&json!({"code": code["code"], "team": "Family", "owner": "rafal",
            "device_name": "Owner device", "public_key": DeviceKey::generate().unwrap().public_key_b64()})),
    );
    let (_, mac) = connect(&relay, "Rafal");
    let link = relay.ok("POST", "/v1/devices/links", &mac.token, None);
    let (status, value) = relay.call(
        "POST",
        "/v1/devices/link",
        None,
        Some(&json!({"code": link["secret"], "device_name": "iPhone", "public_key": bogus})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (400, Some("invalid_request"))
    );
    let (status, _) = relay.call(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": relay.team_id, "public_key": bogus})),
    );
    assert_eq!(status, 401);
}

#[test]
fn one_client_prefix_makes_few_connect_teams_a_day_and_is_kept_in_memory_only() {
    let relay = start(UpstreamOptions::default());
    // Fixed request time: this test checks the ten-second audit throttle even on
    // a loaded runner where constructing the fixtures can take longer than that.
    let at = now_unix();
    let post = |body: &Value, prefix: Option<&str>| {
        relay
            .hub()
            .create_connect_team(
                &serde_json::from_value(body.clone()).unwrap(),
                prefix.unwrap_or("unknown"),
                at,
            )
            .map_or_else(|error| (error.status(), error.code), |_| (200, ""))
    };
    let prefix = "2001:db8:aaaa::/48";
    for n in 0..5 {
        let key = DeviceKey::generate().unwrap();
        let answer = post(
            &connect_body(&relay, &format!("T{n}"), "Mac", &key),
            Some(prefix),
        );
        assert_eq!(answer.0, 200, "{:?}", answer);
    }
    let key = DeviceKey::generate().unwrap();
    let body = connect_body(&relay, "Six", "Mac", &key);
    let limited = post(&body, Some(prefix));
    assert_eq!(limited, (429, "rate_limited"));
    // The refusal did not use the key: another prefix makes the team with it.
    let other = post(&body, Some("198.51.100.0/24"));
    assert_eq!(other.0, 200, "{:?}", other);
    // Requests without the Worker's header share one count.
    for n in 0..5 {
        let key = DeviceKey::generate().unwrap();
        let answer = post(&connect_body(&relay, &format!("U{n}"), "Mac", &key), None);
        assert_eq!(answer.0, 200, "{:?}", answer);
    }
    let key = DeviceKey::generate().unwrap();
    let limited = post(&connect_body(&relay, "U5", "Mac", &key), None);
    assert_eq!(limited, (429, "rate_limited"));
    // A refused bad body costs the prefix nothing.
    let fresh = "2001:db8:bbbb::/48";
    for _ in 0..10 {
        let mut bad = connect_body(&relay, "Bad", "Mac", &DeviceKey::generate().unwrap());
        bad["signature"] = json!("AAAA");
        assert_eq!(post(&bad, Some(fresh)).0, 400);
    }
    let key = DeviceKey::generate().unwrap();
    assert_eq!(
        post(&connect_body(&relay, "F", "Mac", &key), Some(fresh)).0,
        200
    );
    // The relay audit has the refusal, and nothing of the prefixes.
    let audit = relay.relay_audit();
    let refused: Vec<_> = audit
        .iter()
        .filter(|(_, action, _)| action == "connect_refused")
        .map(|(_, _, detail)| detail.as_str())
        .collect();
    assert_eq!(refused, [r#"{"reason":"rate_limited"}"#]);
    for (_, _, detail) in &audit {
        for text in ["2001:db8", "198.51.100", "unknown"] {
            assert!(!detail.contains(text), "{detail}");
        }
    }
}

#[test]
fn a_client_prefix_counts_only_with_the_proof_of_the_worker() {
    // A Worker from before the proof forwarded a client's own prefix header: without a
    // valid HMAC under the edge secret, every call counts as the one prefix `unknown`.
    let relay = start(UpstreamOptions::default());
    let wrong = apassy_relay::server::connect::prefix_mac(
        "another-edge-secret-0123456789abcdef0123",
        "198.51.100.0/24",
    );
    let other = apassy_relay::server::connect::prefix_mac(EDGE_SECRET, "198.51.101.0/24");
    let unproved: [(String, Option<String>); 5] = [
        ("198.51.100.0/24".into(), None),
        ("198.51.100.0/24".into(), Some(wrong)),
        ("198.51.100.0/24".into(), Some(other)),
        ("203.0.113.0/24".into(), Some("ab".repeat(32))),
        ("2001:db8:77::/48".into(), Some("not hex".into())),
    ];
    for (n, (prefix, mac)) in unproved.iter().enumerate() {
        let key = DeviceKey::generate().unwrap();
        let answer = post_connect_with(
            &relay,
            &connect_body(&relay, &format!("U{n}"), "Mac", &key),
            Some(prefix),
            mac.as_deref(),
        );
        assert_eq!(answer.status, 200, "{}", answer.body);
    }
    // Five forged prefixes used up the count of `unknown`: a call without any header is
    // refused, and a sixth forged prefix too.
    let key = DeviceKey::generate().unwrap();
    let limited = post_connect_from(&relay, &connect_body(&relay, "N", "Mac", &key), None);
    assert_eq!((limited.status, limited.code()), (429, "rate_limited"));
    let forged = post_connect_with(
        &relay,
        &connect_body(&relay, "F", "Mac", &DeviceKey::generate().unwrap()),
        Some("192.0.2.0/24"),
        None,
    );
    assert_eq!((forged.status, forged.code()), (429, "rate_limited"));
    // The same network with the Worker's proof has its own count.
    let proved = post_connect_from(
        &relay,
        &connect_body(&relay, "P", "Mac", &key),
        Some("198.51.100.0/24"),
    );
    assert_eq!(proved.status, 200, "{}", proved.body);
}

#[test]
fn a_prefix_takes_at_most_a_tenth_of_the_daily_cap() {
    let relay = start_with(
        |config| config.connect_teams_per_day = 20,
        UpstreamOptions::default(),
    );
    let prefix = Some("203.0.113.0/24");
    for name in ["A", "B"] {
        let key = DeviceKey::generate().unwrap();
        let answer = post_connect_from(&relay, &connect_body(&relay, name, "Mac", &key), prefix);
        assert_eq!(answer.status, 200, "{}", answer.body);
    }
    let key = DeviceKey::generate().unwrap();
    let limited = post_connect_from(&relay, &connect_body(&relay, "C", "Mac", &key), prefix);
    assert_eq!((limited.status, limited.code()), (429, "rate_limited"));
}

#[test]
fn the_relay_holds_at_most_connect_teams_max() {
    let relay = start_with(
        |config| config.connect_teams_max = 2,
        UpstreamOptions::default(),
    );
    let (first, _) = connect(&relay, "A");
    connect(&relay, "B");
    let key = DeviceKey::generate().unwrap();
    let body = connect_body(&relay, "C", "Mac", &key);
    let full = post_connect(&relay, &body);
    assert_eq!((full.status, full.code()), (503, "busy"));
    assert_eq!(full.header("Retry-After"), Some("3600"));
    assert!(
        full.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no room"),
        "{}",
        full.body
    );
    // Operator teams do not count.
    relay.new_team("Family", "rafal");
    // A suspended Connect team still holds its place; a deleted one does not.
    relay
        .operator(Command::Suspend {
            team: first.clone(),
        })
        .unwrap();
    assert_eq!(post_connect(&relay, &body).status, 503);
    relay
        .operator(Command::Delete {
            team: first,
            free_connect_key: false,
        })
        .unwrap();
    connect_ok(&relay, &body);
    let refused: Vec<_> = relay
        .relay_audit()
        .into_iter()
        .filter(|(_, action, _)| action == "connect_refused")
        .map(|(_, _, detail)| detail)
        .collect();
    assert_eq!(refused, [r#"{"reason":"full"}"#]);
    // No file was left by the refusals.
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
    assert_eq!(files, 4);
}

#[test]
fn concurrent_connects_with_one_key_make_one_team_and_one_file() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let body = connect_body(&relay, "Race", "Mac", &key);
    let answers: Vec<(u16, String)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let answer = post_connect(&relay, &body);
                    (answer.status, answer.code().to_string())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(
        answers.iter().filter(|(status, _)| *status == 200).count(),
        1,
        "{answers:?}"
    );
    assert!(
        answers
            .iter()
            .all(|(status, code)| *status == 200 || (*status == 409 && code == "connect_key_used")),
        "{answers:?}"
    );
    assert_eq!(teams(&relay).len(), 2);
    let files = std::fs::read_dir(relay.config.teams_dir())
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            let name = name.to_string_lossy();
            name.ends_with(".db") || name.ends_with("-journal")
        })
        .count();
    assert_eq!(files, 2);
}

/// Rows of one action in a team's audit.
fn audit_rows(relay: &TestRelay, team: &TeamId, action: &str) -> Vec<String> {
    open_team_file(&relay.config, team)
        .prepare("SELECT detail FROM audit WHERE action = ?1 ORDER BY id")
        .unwrap()
        .query_map([action], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn receipts_and_push_tokens_write_audit_rows_only_when_they_change() {
    let relay = start_with(
        |config| {
            config.push = Some(apassy_relay::config::PushConfig::new(
                "http://127.0.0.1:9/internal/push".to_string(),
                "com.example.apassy".to_string(),
                apassy_relay::secret::SecretString::new("p".repeat(40)),
            ));
        },
        UpstreamOptions::default(),
    );
    let (team, mac) = connect(&relay, "Rafal");
    // No vault sync on the relay: a receipt is plan_required, even for version 0.
    let (status, value) = relay.call(
        "POST",
        "/v1/sync/receipt",
        Some(&mac.token),
        Some(&json!({"version": 0})),
    );
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("plan_required"))
    );
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                sync_bytes: Some(67_108_864),
                ..Default::default()
            }),
        })
        .unwrap();
    for _ in 0..3 {
        relay.ok(
            "POST",
            "/v1/sync/receipt",
            &mac.token,
            Some(&json!({"version": 0})),
        );
    }
    assert_eq!(audit_rows(&relay, &team, "sync_received").len(), 1);
    // The same push token again moves its time only; a new one is a new row.
    let token = |hex: &str, environment: &str| json!({"token": hex.repeat(16), "environment": environment, "bundle_id": "com.example.apassy"});
    for _ in 0..3 {
        relay.ok(
            "PUT",
            "/v1/push/token",
            &mac.token,
            Some(&token("ab", "production")),
        );
    }
    assert_eq!(audit_rows(&relay, &team, "push_token_set").len(), 1);
    relay.ok(
        "PUT",
        "/v1/push/token",
        &mac.token,
        Some(&token("ab", "development")),
    );
    relay.ok(
        "PUT",
        "/v1/push/token",
        &mac.token,
        Some(&token("cd", "development")),
    );
    assert_eq!(audit_rows(&relay, &team, "push_token_set").len(), 3);
}

#[test]
fn expired_device_links_go_after_a_week_and_at_most_a_hundred_stay() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Rafal");
    for _ in 0..105 {
        relay.ok("POST", "/v1/devices/links", &mac.token, None);
    }
    let now = now_unix();
    let conn = open_team_file(&relay.config, &team);
    conn.execute_batch(&format!("UPDATE device_link SET expires_at = {};", now - 1))
        .unwrap();
    let hub = relay.hub();
    apassy_relay::server::http::maintain(&hub, now);
    let count = |sql: &str| conn.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap();
    assert_eq!(
        count("SELECT count(*) FROM device_link WHERE state = 'expired'"),
        100
    );
    assert_eq!(count("SELECT count(*) FROM device_link"), 100);
    // A week after they ended, the rest go too.
    conn.execute_batch(&format!(
        "UPDATE device_link SET decided_at = {};",
        now - 7 * DAY - 1
    ))
    .unwrap();
    relay.ok("GET", "/v1/me", &mac.token, None);
    apassy_relay::server::http::maintain(&hub, now + 1);
    assert_eq!(count("SELECT count(*) FROM device_link"), 0);
}

#[test]
fn a_connect_team_file_has_a_cap_and_a_full_team_is_refused_without_losing_its_audit() {
    use apassy_relay::server::audit::{CapLevel, watch_cap};
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Rafal");
    let hub = relay.hub();
    let core = hub.team(&team).unwrap();
    // question_bytes (2 MiB), feed_bytes (1 MiB), and 8 MiB, in pages of 4 KiB.
    let (_, max) = core.store.pages().unwrap();
    assert_eq!(max, (2 * 1_048_576 + 1_048_576 + 8 * 1_048_576) / 4096);
    // A small page cache for each Connect team; an operator team keeps the default.
    assert_eq!(
        core.store.cache_kib().unwrap(),
        Some(apassy_relay::server::connect::CACHE_KIB)
    );
    let operator = hub.team(&relay.team_id).unwrap();
    assert_ne!(
        operator.store.cache_kib().unwrap(),
        Some(apassy_relay::server::connect::CACHE_KIB)
    );
    // An operator team has no cap of its own.
    assert!(operator.store.pages().unwrap().1 >= 1_073_741_823);
    let info = team_info(&relay, &relay.team_id);
    assert!(info["file_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        (&info["file_cap"], &info["file_level"]),
        (&Value::Null, &Value::Null)
    );
    let info = team_info(&relay, &team);
    assert_eq!(info["file_cap"], max * 4096);
    assert_eq!(info["file_level"], "ok");
    // A plan that gives items gives room for them.
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                items: Some(10),
                ..Default::default()
            }),
        })
        .unwrap();
    assert_eq!(core.store.pages().unwrap().1, max + 10 * 16 * 1024 / 4096);
    // A question of yesterday, which the maintenance pass deletes.
    relay.ok(
        "POST",
        "/v1/questions",
        &mac.token,
        Some(&card(&encode_b64(&[7; 16]))),
    );
    // A full file: a write is 403 team_limit, and nothing is half written.
    core.store
        .with(|conn| {
            for n in 0..400 {
                conn.execute(
                    "INSERT INTO audit (at, actor, action, detail) VALUES (?1, 'relay', 'filler', ?2)",
                    rusqlite::params![n, "x".repeat(1000)],
                )
                .unwrap();
            }
            Ok(())
        })
        .unwrap();
    let audit_count = || {
        open_team_file(&relay.config, &team)
            .query_row("SELECT count(*), max(id) FROM audit", [], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
    };
    // About 90 %: a warning, once.
    let (used, _) = core.store.pages().unwrap();
    core.store
        .set_max_bytes(Some(used * 100 / 92 * 4096))
        .unwrap();
    // (The relay's own maintenance thread may warn first: only the level is certain.)
    let now = now_unix();
    assert_eq!(watch_cap(&core, now).unwrap(), CapLevel::Near);
    assert_eq!(core.cap_warning().0, CapLevel::Near);
    assert_eq!(team_info(&relay, &team)["file_level"], "near");
    // At the cap.
    core.store.set_max_bytes(Some((used + 2) * 4096)).unwrap();
    let before = audit_count();
    let mut body = card(&encode_b64(&[42; 16]));
    body["ciphertext"] = json!(encode_b64(&[1u8; 30_000]));
    let (status, value) = relay.call("POST", "/v1/questions", Some(&mac.token), Some(&body));
    assert_eq!(
        (status, value["error"]["code"].as_str()),
        (403, Some("team_limit")),
        "{value}"
    );
    let questions = || {
        open_team_file(&relay.config, &team)
            .query_row("SELECT count(*) FROM question", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    };
    assert_eq!(questions(), 1, "only the question of yesterday");
    // The maintenance pass warns (a rise: at once) and deletes no audit row: the owner
    // chose a refused write over a lost audit. A full team still frees its old questions.
    core.store
        .with(|conn| {
            conn.execute(
                "UPDATE question SET created_at = ?1, expires_at = ?1",
                [i64::try_from(now - 2 * DAY).unwrap()],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
    apassy_relay::server::http::maintain(&hub, now + 1);
    assert_eq!(questions(), 0);
    let warned = core.cap_warning();
    assert_eq!(warned.0, CapLevel::Full);
    assert_eq!(audit_count(), before);
    assert!(audit_rows(&relay, &team, "audit_trimmed").is_empty());
    let info = team_info(&relay, &team);
    assert_eq!(info["file_level"], "full");
    assert_eq!(info["file_cap"], (used + 2) * 4096);
    assert!(info["file_bytes"].as_u64().unwrap() >= used * 4096);
    // Again within the hour: no new warning.
    apassy_relay::server::http::maintain(&hub, now + 120);
    assert_eq!(core.cap_warning(), warned);
    let (status, _) = relay.call("POST", "/v1/questions", Some(&mac.token), Some(&body));
    assert_eq!(status, 403);
    assert_eq!(audit_count(), before);
    // The operator raises the limits: the cap follows them, and the write passes.
    relay
        .operator(Command::Limits {
            team: team.clone(),
            set: Some(TeamLimitsUpdate {
                question_bytes: Some(4 * 1_048_576),
                ..Default::default()
            }),
        })
        .unwrap();
    relay.ok("POST", "/v1/questions", &mac.token, Some(&body));
    assert_eq!(team_info(&relay, &team)["file_level"], "ok");
    let after = audit_count();
    assert!(after.0 > before.0 && after.1 > before.1, "{after:?}");
}

#[test]
fn an_outsider_who_knows_a_connect_team_id_cannot_grow_its_file() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Rafal");
    // The team id is in every device link code.
    let link = relay.ok("POST", "/v1/devices/links", &mac.token, None);
    assert!(link["secret"].as_str().unwrap().contains(team.as_str()));
    let rows = || {
        open_team_file(&relay.config, &team)
            .query_row(
                "SELECT count(*), coalesce(max(id), 0) FROM audit",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap()
    };
    let before = rows();
    let pages = relay.hub().team(&team).unwrap().store.pages().unwrap().0;
    let key = DeviceKey::generate().unwrap();
    for n in 0..5 {
        // A forged access token, member token, and session key with the team's id.
        for kind in ["apassy_acc_", "apassy_mbr_", "apassy_ses_", "apassy_tagt_"] {
            let forged = format!("{kind}{team}_{:064x}", n);
            let (status, _) = relay.call("GET", "/v1/me", Some(&forged), None);
            assert_eq!(status, 401, "{forged}");
        }
        // A sign-in without a challenge, and one with a wrong signature.
        let (status, _) = relay.call(
            "POST",
            "/v1/auth/token",
            None,
            Some(&json!({"team_id": team, "public_key": key.public_key_b64(),
                "nonce": format!("{n:032x}"), "signature": "AAAA"})),
        );
        assert_eq!(status, 401);
        let (status, _) = relay.call(
            "POST",
            "/v1/auth/token",
            None,
            Some(
                &json!({"team_id": team, "public_key": mac.key.public_key_b64(),
                "nonce": challenge(&relay, &team, &mac.key), "signature": "AAAA"}),
            ),
        );
        assert_eq!(status, 401);
        // The proxy path with a session key of the team.
        let (status, _) = relay.call(
            "GET",
            &format!("/p/apassy_ses_{team}_{:064x}/example.com/", n),
            None,
            None,
        );
        assert!(status >= 400, "{status}");
    }
    // Not one row in the team's file, and the file did not grow.
    assert_eq!(rows(), before);
    assert_eq!(
        relay.hub().team(&team).unwrap().store.pages().unwrap().0,
        pages
    );
    // The refusals are in the relay audit, with the team id, at most one per kind and
    // ten seconds for all Connect teams.
    let audit = relay.relay_audit();
    let named: Vec<_> = audit
        .iter()
        .filter(|(_, _, detail)| detail.contains(team.as_str()))
        .map(|(actor, action, _)| (actor.as_str(), action.as_str()))
        .collect();
    assert!(named.contains(&("edge", "auth_failed")), "{audit:?}");
    assert!(
        named.contains(&("edge", "device_sign_in_refused")),
        "{audit:?}"
    );
    assert!(named.len() <= 3, "{audit:?}");
    // The team's own device still works.
    relay.ok("GET", "/v1/me", &mac.token, None);
    // An operator team keeps such rows in its own audit, as before.
    let forged = format!("apassy_acc_{}_{:064x}", relay.team_id, 7);
    let (status, _) = relay.call("GET", "/v1/me", Some(&forged), None);
    assert_eq!(status, 401);
    let own = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    assert!(
        own.as_array()
            .unwrap()
            .iter()
            .any(|row| row["action"] == "auth_failed"),
        "{own}"
    );
}

/// A sign-in challenge of `key` in `team`: its nonce.
fn challenge(relay: &TestRelay, team: &TeamId, key: &DeviceKey) -> String {
    let answer = relay.ok(
        "POST",
        "/v1/auth/challenge",
        "",
        Some(&json!({"team_id": team, "public_key": key.public_key_b64()})),
    );
    answer["nonce"].as_str().unwrap().to_string()
}

#[test]
fn orphan_team_files_are_removed_at_start() {
    let mut relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Kept");
    // A file of a team whose row never committed (a crash between the file and the
    // commit), with its journal, and files that are not team files.
    let orphan = TeamId::parse("t_orphan2345").unwrap();
    let teams = relay.config.teams_dir();
    let names = [
        format!("{orphan}.db"),
        format!("{orphan}.db-journal"),
        format!("{orphan}.db.migrating"),
        "notes.db".to_string(),
    ];
    relay.edit_offline(|_| {
        for name in &names {
            std::fs::write(teams.join(name), b"x").unwrap();
        }
    });
    assert!(!teams.join(&names[0]).exists());
    assert!(!teams.join(&names[1]).exists());
    assert!(teams.join(&names[2]).exists());
    assert!(teams.join(&names[3]).exists());
    assert!(teams.join(format!("{team}.db")).exists());
    relay.ok("GET", "/v1/me", &relay.sign_in(&team, &mac.key), None);
}

#[test]
fn a_connect_team_has_a_request_rate_and_an_operator_team_has_none() {
    let relay = start(UpstreamOptions::default());
    let (team, mac) = connect(&relay, "Rafal");
    let per_minute = apassy_relay::server::connect::REQUESTS_PER_MINUTE as usize;
    // A fixed window of a minute: at most two windows' worth before a refusal.
    let mut limited = None;
    for _ in 0..=2 * per_minute {
        let answer = send(
            &relay.url,
            "GET",
            "/v1/me",
            Some(&mac.token),
            &[],
            Vec::new(),
        );
        if answer.status != 200 {
            limited = Some(answer);
            break;
        }
    }
    let limited = limited.expect("a refusal within two minutes' worth");
    assert_eq!((limited.status, limited.code()), (429, "rate_limited"));
    let wait: u64 = limited.header("Retry-After").unwrap().parse().unwrap();
    assert!((1..=60).contains(&wait), "{wait}");
    assert_eq!(
        audit_rows(&relay, &team, "limit_reached"),
        [r#"{"limit":"requests_per_minute"}"#]
    );
    for _ in 0..=per_minute {
        relay.ok("GET", "/v1/me", &relay.owner_token, None);
    }
}

#[test]
fn long_polls_of_a_connect_team_answer_at_once_when_nothing_can_come() {
    let relay = start(UpstreamOptions::default());
    let (_, mac) = connect(&relay, "Rafal");
    for path in ["/v1/host/requests?wait=3", "/v1/sync/head?since=0&wait=3"] {
        let started = Instant::now();
        relay.ok("GET", path, &mac.token, None);
        assert!(started.elapsed() < Duration::from_secs(2), "{path}");
    }
    // An operator team's sync poll still waits.
    let (token, key) = relay.new_team_device("Family", "rafal");
    let device = relay.sign_in(&team_of(&token), &key);
    let started = Instant::now();
    relay.ok("GET", "/v1/sync/head?since=0&wait=1", &device, None);
    assert!(started.elapsed() >= Duration::from_secs(1));
}

#[test]
fn connect_teams_hold_at_most_connect_long_polls() {
    let relay = start_with(
        |config| config.limits.connect_long_polls = 1,
        UpstreamOptions::default(),
    );
    let (_, first) = connect(&relay, "A");
    let (_, second) = connect(&relay, "B");
    let (token, key) = relay.new_team_device("Family", "rafal");
    let family = relay.sign_in(&team_of(&token), &key);
    std::thread::scope(|scope| {
        let held = scope.spawn(|| {
            let started = Instant::now();
            relay.ok("GET", "/v1/questions?since=0&wait=3", &first.token, None);
            started.elapsed()
        });
        std::thread::sleep(Duration::from_millis(500));
        // The one seat of Connect teams is taken: another Connect team's poll answers at
        // once; an operator team's poll still waits.
        let started = Instant::now();
        relay.ok("GET", "/v1/questions?since=0&wait=3", &second.token, None);
        assert!(started.elapsed() < Duration::from_secs(2));
        let started = Instant::now();
        relay.ok("GET", "/v1/questions?since=0&wait=1", &family, None);
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert!(held.join().unwrap() >= Duration::from_secs(3));
    });
    // The seat came back.
    let started = Instant::now();
    relay.ok("GET", "/v1/questions?since=0&wait=1", &second.token, None);
    assert!(started.elapsed() >= Duration::from_secs(1));
}

#[test]
fn a_connect_team_holds_two_question_polls_and_a_third_answers_at_once() {
    let relay = start(UpstreamOptions::default());
    let (_, mac) = connect(&relay, "Rafal");
    let phone = add_device(&relay, &mac, "iPhone");
    let tablet = add_device(&relay, &mac, "iPad");
    std::thread::scope(|scope| {
        let held: Vec<_> = [&mac, &phone]
            .into_iter()
            .map(|device| {
                let relay = &relay;
                scope.spawn(move || {
                    let started = Instant::now();
                    relay.ok("GET", "/v1/questions?since=0&wait=3", &device.token, None);
                    started.elapsed()
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(500));
        // The team's two seats are held: a third device's poll answers at once, and the
        // client backs off (docs/SPEC.md section 26.4).
        let started = Instant::now();
        relay.ok("GET", "/v1/questions?since=0&wait=3", &tablet.token, None);
        assert!(started.elapsed() < Duration::from_secs(2));
        for poll in held {
            assert!(poll.join().unwrap() >= Duration::from_secs(3));
        }
    });
    assert_eq!(apassy_relay::server::connect::TEAM_QUESTION_POLLS, 2);
}

#[test]
fn the_sweep_leaves_plan_teams_and_synced_teams() {
    let mut relay = start(UpstreamOptions::default());
    let (idle, _) = connect(&relay, "Idle");
    let (lifted, _) = connect(&relay, "Lifted");
    let (synced, synced_mac) = connect(&relay, "Synced");
    relay
        .operator(Command::Limits {
            team: lifted.clone(),
            set: Some(TeamLimitsUpdate {
                members: Some(3),
                ..Default::default()
            }),
        })
        .unwrap();
    // A team that synced once and went back to the Connect limits keeps its snapshots.
    let lift = |bytes: u64| {
        relay
            .operator(Command::Limits {
                team: synced.clone(),
                set: Some(TeamLimitsUpdate {
                    sync_bytes: Some(bytes),
                    ..Default::default()
                }),
            })
            .unwrap();
    };
    lift(67_108_864);
    let body = vec![5u8; 1024];
    let pushed = send(
        &relay.url,
        "PUT",
        "/v1/sync/snapshot",
        Some(&synced_mac.token),
        &first_push(&synced, &synced_mac, &body),
        body,
    );
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    lift(0);
    assert_eq!(
        team_info(&relay, &synced)["limits"],
        serde_json::to_value(apassy_relay::server::directory::TeamLimits::connect()).unwrap()
    );
    let old = now_unix() - 31 * DAY;
    relay.edit_offline(|config| {
        for team in [&idle, &lifted, &synced] {
            open_team_file(config, team)
                .execute_batch(&format!(
                    "UPDATE device SET last_seen_at = {old}, created_at = {old};"
                ))
                .unwrap();
        }
    });
    let report = sweep(&relay, false);
    assert_eq!(report["suspended"], json!([idle]));
    for team in [&lifted, &synced] {
        assert_eq!(team_info(&relay, team)["state"], "active");
    }
}

/// The resident memory (KiB) and the open files of this process. Linux only.
fn process_use() -> Option<(u64, usize)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    let files = std::fs::read_dir("/proc/self/fd").ok()?.count();
    Some((rss, files))
}

/// Not a check: what each Connect team costs the relay (memory, open files, start time),
/// for docs/OPERATIONS.md section 20.5. Linux only (it reads `/proc`). Run it on the
/// devbox, never on the VPS:
/// `APASSY_MEASURE_TEAMS=100 cargo test --release --test server_connect measure_connect_teams -- --ignored --nocapture`
#[test]
#[ignore = "a measurement for OPERATIONS 20.5, run by hand on the devbox"]
fn measure_connect_teams() {
    let teams: u64 = std::env::var("APASSY_MEASURE_TEAMS")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(100);
    let Some(empty) = process_use() else {
        println!("measure_connect_teams: Linux only (/proc)");
        return;
    };
    let relay = start_with(
        |config| {
            config.connect_teams_per_day = teams + 1;
            config.connect_teams_max = teams + 1;
        },
        UpstreamOptions::default(),
    );
    let started = process_use().unwrap();
    let mut body = card(&encode_b64(&[42; 16]));
    body["ciphertext"] = json!(encode_b64(&[1u8; 30_000]));
    for n in 0..teams {
        let (_, mac) = connect(&relay, &format!("M{n}"));
        relay.ok("POST", "/v1/questions", &mac.token, Some(&body));
        relay.ok("GET", "/v1/questions?since=0", &mac.token, None);
    }
    let made = process_use().unwrap();
    let clock = Instant::now();
    let relay = relay.restart();
    let start_secs = clock.elapsed().as_secs_f64();
    let reopened = process_use().unwrap();
    let per_team = |after: (u64, usize)| {
        (
            after.0.saturating_sub(started.0) / teams.max(1),
            after.1.saturating_sub(started.1) as f64 / teams.max(1) as f64,
        )
    };
    println!(
        "measure_connect_teams: {teams} teams; empty relay {} KiB, {} files; after the teams {} KiB, {} files ({:?} KiB and files per team); after a restart {} KiB, {} files ({:?} per team), start {start_secs:.1} s",
        started.0,
        started.1,
        made.0,
        made.1,
        per_team(made),
        reopened.0,
        reopened.1,
        per_team(reopened),
    );
    println!(
        "measure_connect_teams: the test process before the relay: {} KiB, {} files",
        empty.0, empty.1
    );
    drop(relay);
}

#[test]
fn lost_connect_acknowledgement_recovers_same_active_team_after_restart() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let body = connect_body(&relay, "Lost acknowledgement", "Mac", &key);
    let created = connect_ok(&relay, &body); // the server committed; pretend the response was lost
    let relay = relay.restart();
    let recovery = |key: &DeviceKey| {
        let challenge = relay.ok(
            "POST",
            "/v1/connect/challenge",
            "",
            Some(&json!({
                "public_key": key.public_key_b64()
            })),
        );
        let nonce = challenge["nonce"].as_str().unwrap();
        let mut message = device::connect_message(&relay.config.public_url, &key.public_key_b64());
        message.extend_from_slice(b"\0recovery\0");
        message.extend_from_slice(nonce.as_bytes());
        let mut retry = body.clone();
        retry["public_key"] = json!(key.public_key_b64());
        retry["signature"] = json!(encode_b64(&key.sign(&message).unwrap()));
        retry["recovery_nonce"] = json!(nonce);
        retry
    };
    let retry = recovery(&key);
    let recovered = connect_ok(&relay, &retry);
    assert_eq!(recovered, created);
    assert_eq!(
        post_connect(&relay, &retry).status,
        401,
        "nonce is consumed"
    );
    assert_eq!(
        post_connect(&relay, &body).status,
        409,
        "old proof cannot recover"
    );
    let other = DeviceKey::generate().unwrap();
    assert_eq!(post_connect(&relay, &recovery(&other)).status, 409);
    let team = TeamId::parse(created["team_id"].as_str().unwrap()).unwrap();
    let valid = recovery(&key);
    let mut forged = valid.clone();
    forged["signature"] = json!(body["signature"]);
    assert_eq!(post_connect(&relay, &forged).status, 400);
    assert_eq!(
        post_connect(&relay, &valid).status,
        401,
        "bad proof consumes nonce"
    );
    relay
        .operator(Command::Suspend { team: team.clone() })
        .unwrap();
    assert_eq!(post_connect(&relay, &recovery(&key)).status, 409);
    relay
        .operator(Command::Delete {
            team: team.clone(),
            free_connect_key: false,
        })
        .unwrap();
    assert_eq!(post_connect(&relay, &recovery(&key)).status, 409);
    assert!(teams(&relay).iter().all(|info| info["id"] != team.as_str()));
}

#[test]
fn reclamation_preserves_the_complete_encrypted_team_audit() {
    let relay = start(UpstreamOptions::default());
    let (team, _) = connect(&relay, "Abandoned");
    let now = now_unix();
    relay.hub().suspend(&team, now - 31 * 86400).unwrap();
    // Only an idle-sweep suspension may be deleted automatically.
    let directory = rusqlite::Connection::open(relay.config.directory_path()).unwrap();
    directory
        .pragma_update(None, "key", relay.config.master_key.expose())
        .unwrap();
    directory
        .execute(
            "UPDATE team SET suspend_reason = 'idle' WHERE id = ?1",
            [team.as_str()],
        )
        .unwrap();
    let source = open_team_file(&relay.config, &team);
    source
        .execute(
            "UPDATE device SET last_seen_at = ?1, created_at = ?1",
            [(now - 31 * DAY) as i64],
        )
        .unwrap();
    let before: Vec<(i64, String)> = source
        .prepare("SELECT id, detail FROM audit ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    drop(source);
    let report = sweep(&relay, false);
    assert_eq!(report["failed"], json!([]));
    assert_eq!(report["deleted"], json!([team]));
    assert!(!relay.config.team_path(&team).exists());
    let archives: Vec<_> = std::fs::read_dir(relay.config.data_dir.join("audit-archive"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(archives.len(), 1);
    let archive =
        apassy_relay::server::store::Store::open_read_only(&archives[0], &relay.config.master_key)
            .unwrap();
    let after = archive
        .with(|conn| {
            Ok(conn
                .prepare("SELECT id, detail FROM audit ORDER BY id")
                .unwrap()
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>())
        })
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(sweep(&relay, false)["deleted"], json!([]));
    assert!(
        archives[0].exists(),
        "later sweeps never prune archived audit"
    );
}

#[test]
fn recovery_proofs_are_key_bound_expire_and_do_not_bypass_limits() {
    let relay = start_with(
        |config| {
            config.connect_teams_per_day = 1;
            config.connect_teams_max = 1;
        },
        UpstreamOptions::default(),
    );
    let key = DeviceKey::generate().unwrap();
    let other = DeviceKey::generate().unwrap();
    let body = connect_body(&relay, "Original", "Mac", &key);
    let created = connect_ok(&relay, &body);
    let at = now_unix();
    let proof = |key: &DeviceKey, nonce: &str| {
        let mut value = body.clone();
        value["public_key"] = json!(key.public_key_b64());
        value["recovery_nonce"] = json!(nonce);
        value["signature"] = json!(encode_b64(
            &key.sign(&device::connect_recovery_message(
                &relay.config.public_url,
                &key.public_key_b64(),
                nonce,
            ))
            .unwrap()
        ));
        serde_json::from_value(value).unwrap()
    };
    let challenge = relay
        .hub()
        .connect_challenge(&key.public_key_b64(), at)
        .unwrap();
    let nonce = challenge["nonce"].as_str().unwrap();
    assert_eq!(
        relay
            .hub()
            .create_connect_team(&proof(&other, nonce), "any", at)
            .unwrap_err()
            .status(),
        401
    );
    let challenge = relay
        .hub()
        .connect_challenge(&key.public_key_b64(), at)
        .unwrap();
    let nonce = challenge["nonce"].as_str().unwrap();
    assert_eq!(
        relay
            .hub()
            .create_connect_team(&proof(&key, nonce), "any", at + 60)
            .unwrap_err()
            .status(),
        401
    );
    let challenge = relay
        .hub()
        .connect_challenge(&key.public_key_b64(), at)
        .unwrap();
    let recovered = relay
        .hub()
        .create_connect_team(
            &proof(&key, challenge["nonce"].as_str().unwrap()),
            "any",
            at,
        )
        .unwrap();
    assert_eq!(recovered.0.as_str(), created["team_id"]);
    // Recovery neither creates another seat nor consumes a creation quota.
    assert_eq!(
        post_connect(&relay, &connect_body(&relay, "Extra", "Mac", &other)).status,
        503
    );
    let core = relay.hub().team(&recovered.0).unwrap();
    for _ in 1..apassy_relay::server::connect::REQUESTS_PER_MINUTE {
        core.take_request(at).unwrap();
    }
    let challenge = relay
        .hub()
        .connect_challenge(&key.public_key_b64(), at)
        .unwrap();
    assert_eq!(
        relay
            .hub()
            .create_connect_team(
                &proof(&key, challenge["nonce"].as_str().unwrap()),
                "any",
                at
            )
            .unwrap_err()
            .status(),
        429
    );
    core.store
        .with(|conn| {
            conn.execute("UPDATE device SET revoked_at = ?1", [at as i64])
                .unwrap();
            Ok(())
        })
        .unwrap();
    let challenge = relay
        .hub()
        .connect_challenge(&key.public_key_b64(), at + 60)
        .unwrap();
    assert_eq!(
        relay
            .hub()
            .create_connect_team(
                &proof(&key, challenge["nonce"].as_str().unwrap()),
                "any",
                at + 60
            )
            .unwrap_err()
            .status(),
        409
    );
    // Challenges reveal the same fields for known and unknown keys.
    let unknown = relay
        .hub()
        .connect_challenge(&other.public_key_b64(), at + 60)
        .unwrap();
    assert_eq!(
        unknown.as_object().unwrap().keys().collect::<Vec<_>>(),
        challenge.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    assert_eq!(unknown["expires_at"], challenge["expires_at"]);
}

#[test]
fn a_sweep_cannot_change_more_than_ten_teams() {
    use apassy_relay::server::hub::MAX_SWEEP_ACTIONS;
    let relay = start(UpstreamOptions::default());
    let mut ids = Vec::new();
    for n in 0..=MAX_SWEEP_ACTIONS {
        ids.push(connect(&relay, &format!("Idle {n}")).0);
    }
    let old = now_unix() - 31 * DAY;
    for id in &ids {
        relay
            .hub()
            .team(id)
            .unwrap()
            .store
            .with(|conn| {
                conn.execute(
                    "UPDATE device SET last_seen_at = ?1, created_at = ?1",
                    [old as i64],
                )
                .unwrap();
                Ok(())
            })
            .unwrap();
    }
    let dry = sweep(&relay, true);
    assert_eq!(
        dry["suspended"].as_array().unwrap().len(),
        MAX_SWEEP_ACTIONS
    );
    assert_eq!(dry["capped"], true);
    assert!(teams(&relay).iter().all(|row| row["state"] == "active"));
    let applied = sweep(&relay, false);
    assert_eq!(
        applied["suspended"].as_array().unwrap().len(),
        MAX_SWEEP_ACTIONS
    );
    assert_eq!(applied["action_limit"], MAX_SWEEP_ACTIONS);
    assert_eq!(
        sweep(&relay, false)["suspended"].as_array().unwrap().len(),
        1
    );
    edit_directory(
        &relay.config,
        &format!("UPDATE team SET suspended_at = {old} WHERE suspend_reason = 'idle'"),
    );
    let deleted = sweep(&relay, false);
    assert_eq!(
        deleted["deleted"].as_array().unwrap().len(),
        MAX_SWEEP_ACTIONS
    );
    assert_eq!(deleted["capped"], true);
    assert_eq!(sweep(&relay, false)["deleted"].as_array().unwrap().len(), 1);
}

#[test]
fn recovery_challenge_floods_are_bounded_independent_of_key_existence() {
    let relay = start(UpstreamOptions::default());
    let key = DeviceKey::generate().unwrap();
    let at = now_unix() / 60 * 60;
    for _ in 0..1000 {
        relay
            .hub()
            .connect_challenge(&key.public_key_b64(), at)
            .unwrap();
    }
    assert_eq!(
        relay
            .hub()
            .connect_challenge(&key.public_key_b64(), at)
            .unwrap_err()
            .status(),
        429
    );
    relay
        .hub()
        .connect_challenge(&key.public_key_b64(), at + 60)
        .unwrap();
}
