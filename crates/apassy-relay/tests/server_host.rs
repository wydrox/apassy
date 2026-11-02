//! The endpoints of the owner's host: the list of runs that wait, the release of the
//! keys of a run, the denial, and every way a release can fail.
//!
//! `TestRelay::add_item` seals each value and keeps its key in the handle, so the
//! handle plays the part of the owner's host. The real host is tested in `host_cli.rs`.

#[path = "common/relay.rs"]
mod relay;
#[path = "common/upstream.rs"]
mod upstream;

use std::sync::Arc;
use std::time::{Duration, Instant};

use apassy_relay::config::UpstreamOptions;
use apassy_relay::hostkeys::{self, RunKey};
use relay::{CANARY, CANARY2, Team, TestRelay, start, start_with};
use serde_json::{Value, json};

const USER: &str = "Please check the repository state.";

/// A run that waits. Returns its id.
fn pending_run(relay: &TestRelay, team: &Team, command: &[&str]) -> u64 {
    let (status, body) = relay.run(&team.agent_token, &team.request(command, Some(USER)));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "pending");
    body["result"]["run_id"].as_u64().unwrap()
}

fn post_release(relay: &TestRelay, run: u64, body: &Value) -> (u16, Value) {
    relay.call(
        "POST",
        &format!("/v1/host/requests/{run}/release"),
        Some(&relay.owner_token),
        Some(body),
    )
}

fn view(relay: &TestRelay, team: &Team, run: u64) -> Value {
    relay.ok("GET", &format!("/v1/runs/{run}"), &team.agent_token, None)
}

fn audit(relay: &TestRelay) -> Vec<Value> {
    relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .as_array()
        .unwrap()
        .clone()
}

fn count(relay: &TestRelay, action: &str) -> usize {
    audit(relay)
        .iter()
        .filter(|row| row["action"] == action)
        .count()
}

/// A second item in the same collection, with its own key in the handle.
fn github_item(relay: &TestRelay, team: &Team) -> u64 {
    relay.add_item(
        team.collection,
        "GITHUB_TOKEN",
        CANARY2,
        json!({"provider": "github", "environment": "staging"}),
    )
}

/// A run with both items, pending.
fn two_item_run(relay: &TestRelay, team: &Team, second: u64) -> u64 {
    let mut body = team.request(&["git", "status"], Some(USER));
    body["items"] = json!([team.item, second]);
    let (status, result) = relay.run(&team.agent_token, &body);
    assert_eq!(status, 200, "{result}");
    result["result"]["run_id"].as_u64().unwrap()
}

// ---- The list ----

#[test]
fn the_host_list_is_oldest_first_and_has_every_field() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    assert!(relay.host_requests().is_empty());
    let first = pending_run(&relay, &team, &["git", "status"]);
    let second = pending_run(&relay, &team, &["python3", "script.py"]);
    let third = pending_run(&relay, &team, &["ls"]);
    let list = relay.host_requests();
    let ids: Vec<u64> = list.iter().map(|r| r["run_id"].as_u64().unwrap()).collect();
    assert_eq!(ids, vec![first, second, third]);
    let request = &list[1];
    for field in [
        "run_id",
        "agent",
        "member",
        "items",
        "command",
        "purpose",
        "user_request",
        "cwd",
        "ttl_secs",
        "flags",
        "suggestion",
        "note",
        "run_key",
        "expires_at",
    ] {
        assert!(request.get(field).is_some(), "{field} is missing");
    }
    assert_eq!(request["suggestion"], "ask");
    assert_eq!(
        request["note"],
        "Not a known safe command. The relay has no model, so a person decides."
    );
    assert_eq!(list[0]["suggestion"], "allow");
    // The run key is a public key: 32 bytes, base64url, and it differs from run to run.
    let keys: Vec<&str> = list
        .iter()
        .map(|r| r["run_key"].as_str().unwrap())
        .collect();
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[1], keys[2]);
    for key in keys {
        assert!(hostkeys::decode_array::<32>(key).is_ok(), "{key}");
    }
    // A denied run leaves the list.
    relay.ok(
        "POST",
        &format!("/v1/host/requests/{second}/deny"),
        &relay.owner_token,
        None,
    );
    let ids: Vec<u64> = relay
        .host_requests()
        .iter()
        .map(|r| r["run_id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![first, third]);
}

#[test]
fn only_the_owner_token_reaches_the_host_endpoints() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team, &["git", "status"]);
    let body = relay.release_for(&relay.host_request(run), None);
    let (_, manager) = relay.join_member("manager", "maria");
    let release = format!("/v1/host/requests/{run}/release");
    let deny = format!("/v1/host/requests/{run}/deny");
    // A manager and a member are members of the team but not the owner: 403.
    for token in [manager.as_str(), team.member_token.as_str()] {
        relay.fails(
            "GET",
            "/v1/host/requests",
            Some(token),
            None,
            403,
            "forbidden",
        );
        relay.fails("POST", &release, Some(token), Some(&body), 403, "forbidden");
        relay.fails("POST", &deny, Some(token), None, 403, "forbidden");
    }
    // An agent token is the wrong kind, and no token is no identity.
    for token in [Some(team.agent_token.as_str()), None] {
        relay.fails(
            "GET",
            "/v1/host/requests",
            token,
            None,
            401,
            "unauthenticated",
        );
        relay.fails("POST", &release, token, Some(&body), 401, "unauthenticated");
        relay.fails("POST", &deny, token, None, 401, "unauthenticated");
    }
    // Nothing of that changed the run.
    assert_eq!(view(&relay, &team, run)["status"], "pending");
    assert_eq!(relay.host_requests().len(), 1);
    // Wrong methods.
    relay.fails(
        "POST",
        "/v1/host/requests",
        Some(&relay.owner_token),
        None,
        405,
        "method_not_allowed",
    );
    relay.fails(
        "GET",
        &release,
        Some(&relay.owner_token),
        None,
        405,
        "method_not_allowed",
    );
    // The wait is 0 to 25.
    relay.fails(
        "GET",
        "/v1/host/requests?wait=26",
        Some(&relay.owner_token),
        None,
        400,
        "invalid_request",
    );
    relay.fails(
        "GET",
        "/v1/host/requests?wait=x",
        Some(&relay.owner_token),
        None,
        400,
        "invalid_request",
    );
}

#[test]
fn a_long_poll_holds_until_a_run_arrives() {
    let relay = Arc::new(start(UpstreamOptions::default()));
    let team = relay.setup("staging");
    let poller = {
        let relay = relay.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            let list = relay.ok("GET", "/v1/host/requests?wait=20", &relay.owner_token, None);
            (list, started.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(800));
    let run = pending_run(&relay, &team, &["git", "status"]);
    let (list, waited) = poller.join().unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["run_id"], run);
    assert!(waited >= Duration::from_millis(700), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    // With a run waiting, a poll answers at once.
    let started = Instant::now();
    relay.ok("GET", "/v1/host/requests?wait=20", &relay.owner_token, None);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_long_poll_with_nothing_to_do_ends_with_an_empty_list() {
    let relay = start(UpstreamOptions::default());
    let started = Instant::now();
    let list = relay.ok("GET", "/v1/host/requests?wait=1", &relay.owner_token, None);
    let waited = started.elapsed();
    assert_eq!(list, json!([]));
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(4),
        "{waited:?}"
    );
    let started = Instant::now();
    relay.ok("GET", "/v1/host/requests", &relay.owner_token, None);
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[test]
fn at_most_two_host_long_polls_hold_at_once() {
    let relay = Arc::new(start(UpstreamOptions::default()));
    let team = relay.setup("staging");
    let poll = |relay: &Arc<TestRelay>| {
        let relay = relay.clone();
        std::thread::spawn(move || {
            relay.ok("GET", "/v1/host/requests?wait=20", &relay.owner_token, None)
        })
    };
    let mut held = vec![poll(&relay), poll(&relay)];
    // A third poll is answered at once, with an empty list. A probe that starts
    // before a held poll has taken its place is tried again.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let asked = Instant::now();
        let list = relay.ok("GET", "/v1/host/requests?wait=3", &relay.owner_token, None);
        assert_eq!(list, json!([]));
        if asked.elapsed() < Duration::from_secs(1) {
            break;
        }
        assert!(Instant::now() < deadline, "the long polls did not start");
        // The probe took a slot and ended after 3 seconds: the held polls are there.
        for slot in &mut held {
            if slot.is_finished() {
                *slot = poll(&relay);
            }
        }
    }
    // A run wakes the held polls.
    let run = pending_run(&relay, &team, &["git", "status"]);
    for poller in held {
        let list = poller.join().unwrap();
        assert_eq!(list[0]["run_id"], run);
    }
}

// ---- The release ----

#[test]
fn a_release_starts_a_session_that_the_proxy_swaps() {
    let upstream = upstream::start(&["api.stripe.com"]);
    let relay = start(upstream.options());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team, &["stripe", "balance", "retrieve"]);
    // Nothing runs before the release.
    assert!(view(&relay, &team, run).get("session").is_none());
    relay.release_ok(run);
    let ready = view(&relay, &team, run);
    let env = &ready["session"]["env"];
    let placeholder = env["STRIPE_API_KEY"].as_str().unwrap();
    let base = env["STRIPE_API_BASE"].as_str().unwrap();
    assert_ne!(placeholder, CANARY);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut response = agent
        .get(&format!("{base}/v1/balance"))
        .header("X-Apassy-Edge", &relay.edge_secret)
        .header("Authorization", format!("Bearer {placeholder}"))
        .call()
        .expect("proxied call");
    assert_eq!(response.status().as_u16(), 200);
    let echo = response.body_mut().read_to_string().unwrap();
    // The upstream saw the value that was decrypted from the sealed text.
    let seen = upstream.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {CANARY}").as_str())
    );
    // The agent got the placeholder back, and never the value.
    assert!(echo.contains(placeholder), "{echo}");
    assert!(!echo.contains(CANARY), "{echo}");
    assert!(!ready.to_string().contains(CANARY));
    // The release made one session and two audit rows, and the value is in none.
    assert_eq!(count(&relay, "run_released"), 1);
    assert_eq!(count(&relay, "session_started"), 1);
}

#[test]
fn a_release_for_another_run_is_release_invalid_and_makes_no_session() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run_a = pending_run(&relay, &team, &["git", "status"]);
    let run_b = pending_run(&relay, &team, &["git", "status"]);
    let for_a = relay.release_for(&relay.host_request(run_a), None);
    // A release sealed for run A, posted to run B.
    let (status, answer) = post_release(&relay, run_b, &for_a);
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["error"]["code"], "release_invalid");
    let denied = view(&relay, &team, run_b);
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied["code"], "release_invalid");
    assert_eq!(denied["decided_by"], "host");
    assert!(denied.get("session").is_none());
    assert_eq!(count(&relay, "session_started"), 0);
    assert_eq!(count(&relay, "run_released"), 0);
    // The key of run B is used up, and run A is not touched.
    let listed: Vec<u64> = relay
        .host_requests()
        .iter()
        .map(|r| r["run_id"].as_u64().unwrap())
        .collect();
    assert_eq!(listed, vec![run_a]);
    // A correct release for run B now finds no pending run.
    let (status, answer) = post_release(&relay, run_b, &for_a);
    assert_eq!(status, 409, "{answer}");
    assert_eq!(answer["error"]["code"], "run_not_pending");
    // The release for run A still works, once.
    let (status, answer) = post_release(&relay, run_a, &for_a);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["status"], "ready");
    let (status, answer) = post_release(&relay, run_a, &for_a);
    assert_eq!(status, 409, "{answer}");
    assert_eq!(count(&relay, "session_started"), 1);
}

/// Seals a plaintext of our own to the key of a run, for a run id of our choosing.
fn forged(relay: &TestRelay, run: u64, plain: &Value, aad_run: u64) -> Value {
    let request = relay.host_request(run);
    let run_key: [u8; 32] = hostkeys::decode_array(request["run_key"].as_str().unwrap()).unwrap();
    let release = hostkeys::seal_release(&run_key, aad_run, plain.to_string().as_bytes()).unwrap();
    json!({
        "host_key": hostkeys::encode_b64(&release.host_key),
        "nonce": hostkeys::encode_b64(&release.nonce),
        "sealed_keys": hostkeys::encode_b64(&release.sealed_keys),
    })
}

/// The uid and the key text of each item of a host request, from the handle.
fn keys_of(relay: &TestRelay, run: u64) -> Vec<(String, String)> {
    relay.host_request(run)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let uid = item["uid"].as_str().unwrap().to_string();
            let key = relay.item_key_text(&uid);
            (uid, key)
        })
        .collect()
}

#[test]
fn a_release_that_does_not_check_denies_the_run() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let github = github_item(&relay, &team);
    let stranger_key = hostkeys::encode_key(&hostkeys::new_key().unwrap()).to_string();
    let short_key = hostkeys::encode_b64(&[1u8; 31]);

    // Each case: a name and a function from (run id, the real keys) to the body.
    type Forge = Box<dyn Fn(&TestRelay, u64, &[(String, String)]) -> Value>;
    let cases: Vec<(&str, Forge)> = vec![
        (
            "a changed sealed text",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                let mut bytes =
                    hostkeys::decode_b64(body["sealed_keys"].as_str().unwrap(), 4096).unwrap();
                bytes[3] ^= 1;
                body["sealed_keys"] = json!(hostkeys::encode_b64(&bytes));
                body
            }),
        ),
        (
            "a changed last byte (the tag)",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                let mut bytes =
                    hostkeys::decode_b64(body["sealed_keys"].as_str().unwrap(), 4096).unwrap();
                *bytes.last_mut().unwrap() ^= 0x80;
                body["sealed_keys"] = json!(hostkeys::encode_b64(&bytes));
                body
            }),
        ),
        (
            "a changed nonce",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                let mut bytes = hostkeys::decode_b64(body["nonce"].as_str().unwrap(), 12).unwrap();
                bytes[0] ^= 1;
                body["nonce"] = json!(hostkeys::encode_b64(&bytes));
                body
            }),
        ),
        (
            "a changed host key",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                let mut bytes =
                    hostkeys::decode_b64(body["host_key"].as_str().unwrap(), 32).unwrap();
                bytes[0] ^= 1;
                body["host_key"] = json!(hostkeys::encode_b64(&bytes));
                body
            }),
        ),
        (
            "a host key that is not on the curve in a useful way (all zero)",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                body["host_key"] = json!(hostkeys::encode_b64(&[0u8; 32]));
                body
            }),
        ),
        (
            "a host key of 31 bytes",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                body["host_key"] = json!(hostkeys::encode_b64(&[9u8; 31]));
                body
            }),
        ),
        (
            "a nonce of 11 bytes",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                body["nonce"] = json!(hostkeys::encode_b64(&[9u8; 11]));
                body
            }),
        ),
        (
            "text that is not base64url",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                body["sealed_keys"] = json!("not base64 at all!");
                body
            }),
        ),
        (
            "a sealed text with padding",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                let text = body["sealed_keys"].as_str().unwrap().to_string();
                body["sealed_keys"] = json!(format!("{text}="));
                body
            }),
        ),
        (
            "an empty sealed text",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                body["sealed_keys"] = json!("");
                body
            }),
        ),
        (
            "a sealed text over the limit",
            Box::new(|relay, run, _| {
                let mut body = relay.release_for(&relay.host_request(run), None);
                body["sealed_keys"] = json!(hostkeys::encode_b64(&vec![7u8; 20_000]));
                body
            }),
        ),
        (
            "a run id in the plaintext that is another run",
            Box::new(|relay, run, keys| {
                let plain = json!({"run_id": run + 1000, "keys": keys.iter().map(|(u, k)| json!({"uid": u, "key": k})).collect::<Vec<_>>()});
                forged(relay, run, &plain, run)
            }),
        ),
        (
            "a run id in the sealing that is another run",
            Box::new(|relay, run, keys| {
                let plain = json!({"run_id": run, "keys": keys.iter().map(|(u, k)| json!({"uid": u, "key": k})).collect::<Vec<_>>()});
                forged(relay, run, &plain, run + 1)
            }),
        ),
        (
            "a missing uid",
            Box::new(|relay, run, keys| {
                let plain = json!({"run_id": run, "keys": [{"uid": keys[0].0, "key": keys[0].1}]});
                forged(relay, run, &plain, run)
            }),
        ),
        (
            "an extra uid",
            Box::new(|relay, run, keys| {
                let mut list: Vec<Value> = keys
                    .iter()
                    .map(|(u, k)| json!({"uid": u, "key": k}))
                    .collect();
                list.push(json!({"uid": "0123456789abcdef0123456789abcdef", "key": keys[0].1}));
                forged(relay, run, &json!({"run_id": run, "keys": list}), run)
            }),
        ),
        (
            "a uid twice and another missing",
            Box::new(|relay, run, keys| {
                let plain = json!({"run_id": run, "keys": [
                    {"uid": keys[0].0, "key": keys[0].1}, {"uid": keys[0].0, "key": keys[0].1}]});
                forged(relay, run, &plain, run)
            }),
        ),
        (
            "an unknown uid instead of a real one",
            Box::new(|relay, run, keys| {
                let plain = json!({"run_id": run, "keys": [
                    {"uid": keys[0].0, "key": keys[0].1},
                    {"uid": "ffffffffffffffffffffffffffffffff", "key": keys[1].1}]});
                forged(relay, run, &plain, run)
            }),
        ),
        (
            "the keys of the two items swapped",
            Box::new(|relay, run, keys| {
                let plain = json!({"run_id": run, "keys": [
                    {"uid": keys[0].0, "key": keys[1].1}, {"uid": keys[1].0, "key": keys[0].1}]});
                forged(relay, run, &plain, run)
            }),
        ),
        (
            "a key that is not the key of the item",
            Box::new({
                let stranger = stranger_key.clone();
                move |relay, run, keys| {
                    let plain = json!({"run_id": run, "keys": [
                        {"uid": keys[0].0, "key": keys[0].1}, {"uid": keys[1].0, "key": stranger}]});
                    forged(relay, run, &plain, run)
                }
            }),
        ),
        (
            "a key of 31 bytes",
            Box::new({
                let short = short_key.clone();
                move |relay, run, keys| {
                    let plain = json!({"run_id": run, "keys": [
                        {"uid": keys[0].0, "key": keys[0].1}, {"uid": keys[1].0, "key": short}]});
                    forged(relay, run, &plain, run)
                }
            }),
        ),
        (
            "a plaintext that is not JSON",
            Box::new(|relay, run, _| {
                let request = relay.host_request(run);
                let run_key: [u8; 32] =
                    hostkeys::decode_array(request["run_key"].as_str().unwrap()).unwrap();
                let release = hostkeys::seal_release(&run_key, run, b"not json").unwrap();
                json!({
                    "host_key": hostkeys::encode_b64(&release.host_key),
                    "nonce": hostkeys::encode_b64(&release.nonce),
                    "sealed_keys": hostkeys::encode_b64(&release.sealed_keys),
                })
            }),
        ),
        (
            "a plaintext with an unknown field",
            Box::new(|relay, run, keys| {
                let plain = json!({"run_id": run, "extra": 1, "keys": keys.iter().map(|(u, k)| json!({"uid": u, "key": k})).collect::<Vec<_>>()});
                forged(relay, run, &plain, run)
            }),
        ),
    ];
    let mut denied = 0;
    for (name, forge) in &cases {
        let run = two_item_run(&relay, &team, github);
        let keys = keys_of(&relay, run);
        let body = forge(&relay, run, &keys);
        let (status, answer) = post_release(&relay, run, &body);
        assert_eq!(status, 403, "{name}: {answer}");
        assert_eq!(
            answer["error"]["code"], "release_invalid",
            "{name}: {answer}"
        );
        let after = view(&relay, &team, run);
        assert_eq!(after["status"], "denied", "{name}");
        assert_eq!(after["code"], "release_invalid", "{name}");
        assert_eq!(after["decided_by"], "host", "{name}");
        assert!(after.get("session").is_none(), "{name}");
        // The answer names no check and holds no text of the release.
        let text = answer.to_string();
        assert!(!text.contains(CANARY) && !text.contains(CANARY2), "{name}");
        // The key is used up.
        assert!(relay.host_requests().is_empty(), "{name}");
        let (status, _) = post_release(&relay, run, &body);
        assert_eq!(status, 409, "{name}");
        denied += 1;
    }
    assert!(denied >= 20);
    assert_eq!(count(&relay, "session_started"), 0);
    assert_eq!(count(&relay, "run_released"), 0);
    // Every failure left a run_denied row with the code and no more.
    let rows: Vec<Value> = audit(&relay)
        .into_iter()
        .filter(|row| row["action"] == "run_denied" && row["detail"]["code"] == "release_invalid")
        .collect();
    assert_eq!(rows.len(), cases.len());
    assert_eq!(rows[0]["actor"], "member:1");
    assert!(
        rows[0]["detail"].as_object().unwrap().len() <= 2,
        "{}",
        rows[0]["detail"]
    );
    // After all of that, a good release of a new run works.
    let run = two_item_run(&relay, &team, github);
    relay.release_ok(run);
}

#[test]
fn a_release_body_with_an_unknown_field_or_no_json_is_a_400_and_keeps_the_key() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team, &["git", "status"]);
    let good = relay.release_for(&relay.host_request(run), None);
    let mut extra = good.clone();
    extra["other"] = json!(1);
    assert_eq!(post_release(&relay, run, &extra).0, 400);
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("nonce");
    assert_eq!(post_release(&relay, run, &missing).0, 400);
    let mut wrong_type = good.clone();
    wrong_type["host_key"] = json!(5);
    assert_eq!(post_release(&relay, run, &wrong_type).0, 400);
    let (status, _) = relay.call(
        "POST",
        &format!("/v1/host/requests/{run}/release"),
        Some(&relay.owner_token),
        None,
    );
    assert_eq!(status, 400);
    // Nothing of that used the key: the good release still works.
    assert_eq!(view(&relay, &team, run)["status"], "pending");
    assert_eq!(post_release(&relay, run, &good).0, 200);
}

#[test]
fn the_release_reason_is_trimmed_masked_and_limited() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    // A live session holds the value, so the value is masked in the next texts.
    relay.run_released(
        &team.agent_token,
        &team.request(&["git", "status"], Some(USER)),
    );
    let run = pending_run(&relay, &team, &["git", "status"]);
    let body = relay.release_for(
        &relay.host_request(run),
        Some(&format!("  ok {CANARY} fine \n")),
    );
    let (status, answer) = post_release(&relay, run, &body);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["note"], "ok [apassy:STRIPE_API_KEY] fine");
    assert!(!view(&relay, &team, run).to_string().contains(CANARY));
    // 500 bytes are fine, a blank reason is no reason, 501 bytes are refused.
    let run = pending_run(&relay, &team, &["git", "status"]);
    let body = relay.release_for(&relay.host_request(run), Some(&"r".repeat(500)));
    assert_eq!(post_release(&relay, run, &body).0, 200);
    let run = pending_run(&relay, &team, &["git", "status"]);
    let body = relay.release_for(&relay.host_request(run), Some("   "));
    let (_, answer) = post_release(&relay, run, &body);
    assert_eq!(answer["result"]["note"], "Released by the owner's host.");
    let run = pending_run(&relay, &team, &["git", "status"]);
    let body = relay.release_for(&relay.host_request(run), Some(&"r".repeat(501)));
    assert_eq!(post_release(&relay, run, &body).0, 400);
}

#[test]
fn a_reason_with_the_value_of_this_very_run_is_masked_at_the_release() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    // No session holds the value yet: the relay learns it from this release.
    let run = pending_run(&relay, &team, &["git", "status"]);
    let body = relay.release_for(
        &relay.host_request(run),
        Some(&format!("value {CANARY} ok")),
    );
    let (status, answer) = post_release(&relay, run, &body);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["note"], "value [apassy:STRIPE_API_KEY] ok");
    assert!(!view(&relay, &team, run).to_string().contains(CANARY));
    let rows = audit(&relay);
    assert!(!Value::Array(rows).to_string().contains(CANARY));
}

// ---- The denial ----

#[test]
fn a_host_denial_is_approval_denied_and_drops_the_key() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team, &["git", "status"]);
    let old = relay.release_for(&relay.host_request(run), None);
    let (status, answer) = relay.call(
        "POST",
        &format!("/v1/host/requests/{run}/deny"),
        Some(&relay.owner_token),
        Some(&json!({"reason": "  No one asked for this. "})),
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["status"], "denied");
    assert_eq!(answer["result"]["code"], "approval_denied");
    assert_eq!(answer["result"]["decided_by"], "host");
    assert_eq!(answer["result"]["note"], "No one asked for this.");
    let seen = view(&relay, &team, run);
    assert_eq!(seen["status"], "denied");
    assert_eq!(seen["code"], "approval_denied");
    assert!(seen.get("session").is_none());
    assert!(relay.host_requests().is_empty());
    let (status, answer) = post_release(&relay, run, &old);
    assert_eq!(status, 409, "{answer}");
    assert_eq!(answer["error"]["code"], "run_not_pending");
    // The default note, a second denial, and an unknown run.
    let run = pending_run(&relay, &team, &["git", "status"]);
    let (_, answer) = relay.call(
        "POST",
        &format!("/v1/host/requests/{run}/deny"),
        Some(&relay.owner_token),
        None,
    );
    assert_eq!(answer["result"]["note"], "Denied by the owner's host.");
    relay.fails(
        "POST",
        &format!("/v1/host/requests/{run}/deny"),
        Some(&relay.owner_token),
        None,
        409,
        "run_not_pending",
    );
    relay.fails(
        "POST",
        "/v1/host/requests/9999/deny",
        Some(&relay.owner_token),
        None,
        404,
        "not_found",
    );
    let denied: Vec<Value> = audit(&relay)
        .into_iter()
        .filter(|row| row["action"] == "run_denied")
        .collect();
    assert_eq!(denied.len(), 2);
    assert_eq!(denied[0]["detail"]["by"], "host");
    assert_eq!(denied[0]["actor"], "member:1");
}

// ---- Runs that the host never sees ----

#[test]
fn a_pending_run_ends_explicitly_at_restart_without_replaying_the_command() {
    let relay = start_with(
        |config| config.approval_timeout_secs = 3,
        UpstreamOptions::default(),
    );
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team, &["git", "status"]);
    assert_eq!(relay.host_requests().len(), 1);
    let relay = relay.restart();
    let ended = view(&relay, &team, run);
    assert_eq!(ended["status"], "ended");
    assert_eq!(ended["code"], "run_interrupted");
    assert!(
        ended["note"]
            .as_str()
            .unwrap()
            .contains("Request a new run")
    );
    assert!(
        relay
            .ok("GET", "/v1/approvals", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(relay.host_requests().is_empty());
    let body = json!({"host_key": "x", "nonce": "x", "sealed_keys": "x"});
    let (status, answer) = post_release(&relay, run, &body);
    assert_eq!(status, 409, "{answer}");
    assert_eq!(answer["error"]["code"], "run_not_pending");
    let started = std::time::Instant::now();
    let ended = relay.ok(
        "GET",
        &format!("/v1/runs/{run}?wait=25"),
        &team.agent_token,
        None,
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(ended["code"], "run_interrupted");
    assert!(
        relay
            .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["action"] == "run_interrupted")
    );
}

#[test]
fn a_run_past_its_expiry_is_not_listed_even_before_a_sweep() {
    let relay = start_with(
        |config| config.approval_timeout_secs = 2,
        UpstreamOptions::default(),
    );
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team, &["git", "status"]);
    assert_eq!(relay.host_requests().len(), 1);
    relay.edit_vault_live(&format!("UPDATE run SET expires_at = 1 WHERE id = {run}"));
    assert!(relay.host_requests().is_empty());
    assert_eq!(view(&relay, &team, run)["status"], "timed_out");
}

#[test]
fn run_keys_are_made_for_every_pending_run_and_used_once() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let a = pending_run(&relay, &team, &["git", "status"]);
    let b = pending_run(&relay, &team, &["git", "status"]);
    let key_a = relay.host_request(a)["run_key"]
        .as_str()
        .unwrap()
        .to_string();
    let key_b = relay.host_request(b)["run_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(key_a, key_b);
    // Listing does not use the key up: the same key is offered again.
    assert_eq!(relay.host_request(a)["run_key"], key_a.as_str());
    // A release for a run that was sealed to a key of another relay run fails: make a
    // key of our own and seal to it.
    let ours = RunKey::generate().unwrap();
    let plain = json!({"run_id": a, "keys": []}).to_string();
    let release = hostkeys::seal_release(&ours.public(), a, plain.as_bytes()).unwrap();
    let body = json!({
        "host_key": hostkeys::encode_b64(&release.host_key),
        "nonce": hostkeys::encode_b64(&release.nonce),
        "sealed_keys": hostkeys::encode_b64(&release.sealed_keys),
    });
    let (status, answer) = post_release(&relay, a, &body);
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["error"]["code"], "release_invalid");
    // The other run is untouched.
    relay.release_ok(b);
}
