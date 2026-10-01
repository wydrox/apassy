//! SPEC23 devices: real HTTP sign-in, link confirmation, live authorization,
//! revocation, limits, and isolation between teams.

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::api::{ChallengeRequest, DeviceEnroll, TokenRequest};
use apassy_relay::config::UpstreamOptions;
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys;
use apassy_relay::ids::TeamId;
use apassy_relay::now_unix;
use apassy_relay::server::{auth, devices};
use relay::{TestRelay, start, start_with, team_of};
use serde_json::{Value, json};

fn challenge(relay: &TestRelay, team: &TeamId, key: &DeviceKey) -> Value {
    relay.ok(
        "POST",
        "/v1/auth/challenge",
        "",
        Some(&json!({
            "team_id": team, "public_key": key.public_key_b64(),
        })),
    )
}

fn signed_request(
    team: &TeamId,
    public_key: &DeviceKey,
    signer: &DeviceKey,
    nonce: &str,
    origin: &str,
) -> Value {
    let public = public_key.public_key_b64();
    let message = device::sign_in_message(origin, team, &public, nonce);
    json!({"team_id": team, "public_key": public, "nonce": nonce,
        "signature": hostkeys::encode_b64(&signer.sign(&message).unwrap())})
}

fn token_from_challenge(
    relay: &TestRelay,
    team: &TeamId,
    key: &DeviceKey,
    challenge: &Value,
) -> String {
    let body = signed_request(
        team,
        key,
        key,
        challenge["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    relay.ok("POST", "/v1/auth/token", "", Some(&body))["token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Replace the bootstrap member token only after the enrollment succeeds.
fn enroll_owner(relay: &mut TestRelay) -> (u64, DeviceKey, String) {
    let key = DeviceKey::generate().unwrap();
    let legacy = relay.owner_token.clone();
    let device = relay.ok(
        "POST",
        "/v1/devices/enroll",
        &legacy,
        Some(&json!({"name": "owner laptop", "public_key": key.public_key_b64()})),
    );
    let token = relay.sign_in(&relay.team_id, &key);
    relay.owner_token = token;
    (device["id"].as_u64().unwrap(), key, legacy)
}

fn make_link(relay: &TestRelay, token: &str, key: &DeviceKey) -> (String, Value) {
    let made = relay.ok("POST", "/v1/devices/links", token, None);
    let code = made["secret"].as_str().unwrap().to_string();
    let pending = relay.ok(
        "POST",
        "/v1/devices/link",
        "",
        Some(&json!({
            "code": code, "device_name": "second laptop", "public_key": key.public_key_b64(),
        })),
    );
    assert_eq!(
        pending["safety"],
        device::safety_words(&team_of(token), &code, &key.public_key())
    );
    (code, pending)
}

fn confirm_link(relay: &TestRelay, token: &str, pending: &Value) -> Value {
    relay.ok(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        token,
        Some(&json!({"safety": pending["safety"]})),
    )
}

#[test]
fn enrollment_ends_the_member_token_and_marks_the_initial_key_holder() {
    let mut relay = start(UpstreamOptions::default());
    let legacy_agent = relay.ok(
        "POST",
        "/v1/agents",
        &relay.owner_token,
        Some(&json!({"name": "legacy-agent"})),
    );
    let core = relay.hub().team(&relay.team_id).unwrap();
    let legacy_auth = auth::authenticate_core(&core, &relay.owner_token, now_unix())
        .unwrap()
        .member()
        .clone();
    let (id, key, old) = enroll_owner(&mut relay);
    assert_eq!(
        relay.vault_rows(&format!(
            "SELECT device_id, device_id FROM agent WHERE id = {}",
            legacy_agent["id"]
        ))[0]
            .0,
        id.to_string().as_bytes()
    );
    relay.ok(
        "GET",
        "/v1/me",
        legacy_agent["secret"].as_str().unwrap(),
        None,
    );
    relay.fails("GET", "/v1/me", Some(&old), None, 401, "unauthenticated");
    let me = relay.ok("GET", "/v1/me", &relay.owner_token, None);
    assert_eq!(me["device_id"], id);
    assert_eq!(me["key_holder"], true);
    let list = relay.ok("GET", "/v1/devices", &relay.owner_token, None);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["current"], true);
    assert_eq!(list[0]["key_holder"], true);
    assert!(list[0]["last_seen_at"].as_u64().is_some());
    let second = DeviceKey::generate().unwrap();
    relay.fails(
        "POST",
        "/v1/devices/enroll",
        Some(&relay.owner_token),
        Some(&json!({"name": "duplicate", "public_key": second.public_key_b64()})),
        401,
        "unauthenticated",
    );
    let duplicate = DeviceEnroll {
        name: "duplicate".into(),
        public_key: second.public_key_b64(),
    };
    assert_eq!(
        devices::enroll(&core, &legacy_auth, &duplicate, now_unix())
            .unwrap_err()
            .code,
        "conflict"
    );
    relay.ok("GET", "/v1/host/requests", &relay.owner_token, None);
    assert_eq!(
        challenge(&relay, &relay.team_id, &key)["origin"],
        relay.config.public_url
    );
}

#[test]
fn sign_in_rejects_wrong_signatures_and_consumes_each_nonce_once() {
    let mut relay = start(UpstreamOptions::default());
    let (_, key, _) = enroll_owner(&mut relay);
    let other = DeviceKey::generate().unwrap();
    let wrong_team = TeamId::generate().unwrap();
    for variant in ["key", "origin", "team", "nonce"] {
        let issued = challenge(&relay, &relay.team_id, &key);
        let nonce = issued["nonce"].as_str().unwrap();
        let mut bad = signed_request(
            &relay.team_id,
            &key,
            if variant == "key" { &other } else { &key },
            nonce,
            if variant == "origin" {
                "https://other-relay.test"
            } else {
                &relay.config.public_url
            },
        );
        if variant == "team" {
            // Body selects this team, but the signature signs another team.
            bad["signature"] = signed_request(
                &wrong_team,
                &key,
                &key,
                nonce,
                &relay.config.public_url,
            )["signature"]
                .clone();
        }
        if variant == "nonce" {
            bad["signature"] = signed_request(
                &relay.team_id,
                &key,
                &key,
                "another nonce",
                &relay.config.public_url,
            )["signature"]
                .clone();
        }
        relay.fails(
            "POST",
            "/v1/auth/token",
            None,
            Some(&bad),
            401,
            "unauthenticated",
        );
        let valid = signed_request(&relay.team_id, &key, &key, nonce, &relay.config.public_url);
        relay.fails(
            "POST",
            "/v1/auth/token",
            None,
            Some(&valid),
            401,
            "unauthenticated",
        );
    }
    let issued = challenge(&relay, &relay.team_id, &key);
    let token = token_from_challenge(&relay, &relay.team_id, &key, &issued);
    relay.ok("GET", "/v1/me", &token, None);
    let valid = signed_request(
        &relay.team_id,
        &key,
        &key,
        issued["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    relay.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&valid),
        401,
        "unauthenticated",
    );
}

#[test]
fn the_nonce_cap_removes_only_the_oldest_nonce_of_that_key() {
    let mut relay = start(UpstreamOptions::default());
    let (_, owner_key, _) = enroll_owner(&mut relay);
    let (_, _, member_key) = relay.join_device("member", "alice");
    let member_nonce = challenge(&relay, &relay.team_id, &member_key);
    let nonces: Vec<Value> = (0..5)
        .map(|_| challenge(&relay, &relay.team_id, &owner_key))
        .collect();
    let oldest = signed_request(
        &relay.team_id,
        &owner_key,
        &owner_key,
        nonces[0]["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    relay.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&oldest),
        401,
        "unauthenticated",
    );
    for nonce in &nonces[1..] {
        token_from_challenge(&relay, &relay.team_id, &owner_key, nonce);
    }
    let member = token_from_challenge(&relay, &relay.team_id, &member_key, &member_nonce);
    assert_eq!(
        relay.ok("GET", "/v1/me", &member, None)["member_name"],
        "alice"
    );
}

#[test]
fn access_tokens_end_at_restart_and_the_oldest_ends_at_the_device_cap() {
    let mut relay = start(UpstreamOptions::default());
    let (_, key, _) = enroll_owner(&mut relay);
    let tokens: Vec<String> = (0..9)
        .map(|_| relay.sign_in(&relay.team_id, &key))
        .collect();
    relay.fails(
        "GET",
        "/v1/me",
        Some(&tokens[0]),
        None,
        401,
        "unauthenticated",
    );
    for token in &tokens[1..] {
        relay.ok("GET", "/v1/me", token, None);
    }
    let nonce = challenge(&relay, &relay.team_id, &key);
    let relay = relay.restart();
    for token in &tokens[1..] {
        relay.fails("GET", "/v1/me", Some(token), None, 401, "unauthenticated");
    }
    let old_nonce = signed_request(
        &relay.team_id,
        &key,
        &key,
        nonce["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    relay.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&old_nonce),
        401,
        "unauthenticated",
    );
    let new = relay.sign_in(&relay.team_id, &key);
    relay.ok("GET", "/v1/me", &new, None);
}

#[test]
fn a_link_requires_the_same_member_and_the_correct_safety_words() {
    let mut relay = start(UpstreamOptions::default());
    enroll_owner(&mut relay);
    let (_, member, _) = relay.join_device("member", "alice");
    let key = DeviceKey::generate().unwrap();
    let (code, pending) = make_link(&relay, &member, &key);
    let path = format!("/v1/devices/links/{}/confirm", pending["id"]);
    relay.fails(
        "POST",
        &path,
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
        404,
        "not_found",
    );
    relay.fails(
        "POST",
        &path,
        Some(&member),
        Some(&json!({"safety": "wrong words"})),
        409,
        "conflict",
    );
    let listed = relay.ok("GET", "/v1/devices/links", &member, None);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(listed[0].get("safety").is_none());
    assert!(listed[0].get("code").is_none());
    assert!(listed[0].get("secret").is_none());
    let request =
        json!({"code": code, "device_name": "second laptop", "public_key": key.public_key_b64()});
    assert_eq!(
        relay.ok("POST", "/v1/devices/link", "", Some(&request)),
        pending
    );
    let other = DeviceKey::generate().unwrap();
    let used = json!({"code": code, "device_name": "different laptop", "public_key": other.public_key_b64()});
    relay.fails(
        "POST",
        "/v1/devices/link",
        None,
        Some(&used),
        403,
        "forbidden",
    );
    relay.fails(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": relay.team_id, "public_key": key.public_key_b64()})),
        403,
        "join_pending",
    );
    let added = confirm_link(&relay, &member, &pending);
    assert_eq!(added["key_holder"], false);
    let token = relay.sign_in(&relay.team_id, &key);
    assert_eq!(
        relay.ok("GET", "/v1/me", &token, None)["member_name"],
        "alice"
    );
    relay.fails(
        "POST",
        &path,
        Some(&member),
        Some(&json!({"safety": pending["safety"]})),
        409,
        "conflict",
    );
}

#[test]
fn expired_link_codes_and_requests_cannot_add_a_device() {
    let mut relay = start(UpstreamOptions::default());
    enroll_owner(&mut relay);
    let made = relay.ok("POST", "/v1/devices/links", &relay.owner_token, None);
    relay.edit_vault_live("UPDATE device_link SET expires_at = 0 WHERE state = 'open'");
    let key = DeviceKey::generate().unwrap();
    let body =
        json!({"code": made["secret"], "device_name": "late", "public_key": key.public_key_b64()});
    relay.fails(
        "POST",
        "/v1/devices/link",
        None,
        Some(&body),
        403,
        "forbidden",
    );
    let (_, pending) = make_link(&relay, &relay.owner_token, &key);
    relay.edit_vault_live("UPDATE device_link SET expires_at = 0 WHERE state = 'pending'");
    relay.fails(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
        409,
        "conflict",
    );
}

#[test]
fn a_shared_member_cannot_make_link_codes_or_change_its_role() {
    let mut relay = start(UpstreamOptions::default());
    enroll_owner(&mut relay);
    let invite = relay.ok(
        "POST",
        "/v1/invites",
        &relay.owner_token,
        Some(&json!({"role": "member", "shared": true, "name": "shared-machine"})),
    );
    let key = DeviceKey::generate().unwrap();
    let pending = relay.ok(
        "POST",
        "/v1/join",
        "",
        Some(&json!({"code": invite["secret"],
        "device_name": "family computer", "public_key": key.public_key_b64()})),
    );
    let confirmed = relay.ok(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        &relay.owner_token,
        Some(&json!({"safety": pending["safety"]})),
    );
    let token = relay.sign_in(&relay.team_id, &key);
    relay.fails(
        "POST",
        "/v1/devices/links",
        Some(&token),
        None,
        403,
        "forbidden",
    );
    relay.fails(
        "PUT",
        &format!("/v1/members/{}/role", confirmed["member_id"]),
        Some(&relay.owner_token),
        Some(&json!({"role": "owner"})),
        409,
        "conflict",
    );
}

#[test]
fn host_authorization_reads_the_current_key_holder_for_each_request() {
    let mut relay = start(UpstreamOptions::default());
    let (first, _, _) = enroll_owner(&mut relay);
    let key = DeviceKey::generate().unwrap();
    let (_, pending) = make_link(&relay, &relay.owner_token, &key);
    let second = confirm_link(&relay, &relay.owner_token, &pending)["id"]
        .as_u64()
        .unwrap();
    let second_token = relay.sign_in(&relay.team_id, &key);
    relay.fails(
        "GET",
        "/v1/host/requests",
        Some(&second_token),
        None,
        403,
        "not_key_holder",
    );
    relay.fails(
        "POST",
        &format!("/v1/devices/{second}/key-holder"),
        Some(&second_token),
        None,
        403,
        "not_key_holder",
    );
    relay.ok(
        "POST",
        &format!("/v1/devices/{second}/key-holder"),
        &relay.owner_token,
        None,
    );
    relay.fails(
        "GET",
        "/v1/host/requests",
        Some(&relay.owner_token),
        None,
        403,
        "not_key_holder",
    );
    relay.ok("GET", "/v1/host/requests", &second_token, None);
    assert_eq!(
        relay.ok("GET", "/v1/me", &second_token, None)["key_holder"],
        true
    );
    relay.ok(
        "POST",
        &format!("/v1/devices/{first}/key-holder"),
        &second_token,
        None,
    );
    relay.ok("GET", "/v1/host/requests", &relay.owner_token, None);
}

#[test]
fn device_revocation_ends_agents_sessions_pending_runs_tokens_and_links() {
    let mut relay = start_with(
        |config| config.approval_timeout_secs = 60,
        UpstreamOptions::default(),
    );
    enroll_owner(&mut relay);
    let team = relay.setup("staging");
    let device = relay.ok("GET", "/v1/me", &team.member_token, None)["device_id"]
        .as_u64()
        .unwrap();
    let ready = relay.run_released(
        &team.agent_token,
        &team.request(&["git", "status"], Some("check the repository")),
    );
    let base = ready["session"]["env"]["STRIPE_API_BASE"].as_str().unwrap();
    let session_key = base
        .split("/p/")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();
    assert!(relay.sessions().find(&session_key, now_unix()).is_some());
    let (status, pending) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some("check again")),
    );
    assert_eq!(status, 200);
    let run = pending["result"]["run_id"].as_u64().unwrap();
    let host_request = relay.host_request(run);
    let linked_key = DeviceKey::generate().unwrap();
    let (_, link) = make_link(&relay, &team.member_token, &linked_key);
    relay.ok(
        "DELETE",
        &format!("/v1/devices/{device}"),
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
        "/v1/me",
        Some(&team.agent_token),
        None,
        401,
        "unauthenticated",
    );
    assert!(relay.sessions().find(&session_key, now_unix()).is_none());
    assert!(relay.host_requests().iter().all(|r| r["run_id"] != run));
    let rows = relay.vault_rows(&format!("SELECT status, code FROM run WHERE id = {run}"));
    assert_eq!(
        rows,
        vec![(b"denied".to_vec(), b"approval_invalidated".to_vec())]
    );
    relay.fails(
        "POST",
        &format!("/v1/host/requests/{run}/release"),
        Some(&relay.owner_token),
        Some(&relay.release_for(&host_request, None)),
        409,
        "run_not_pending",
    );
    relay.fails(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": relay.team_id, "public_key": linked_key.public_key_b64()})),
        403,
        "join_refused",
    );
    assert_eq!(
        relay.vault_rows(&format!(
            "SELECT state, state FROM device_link WHERE id = {}",
            link["id"]
        ))[0]
            .0,
        b"expired"
    );
}

#[test]
fn the_last_owner_and_the_key_holders_role_are_protected() {
    let mut relay = start(UpstreamOptions::default());
    let (device, _, _) = enroll_owner(&mut relay);
    let member = relay.ok("GET", "/v1/me", &relay.owner_token, None)["member_id"]
        .as_u64()
        .unwrap();
    relay.fails(
        "POST",
        "/v1/leave",
        Some(&relay.owner_token),
        None,
        409,
        "conflict",
    );
    relay.fails(
        "DELETE",
        &format!("/v1/devices/{device}"),
        Some(&relay.owner_token),
        None,
        409,
        "conflict",
    );
    relay.fails(
        "DELETE",
        &format!("/v1/members/{member}"),
        Some(&relay.owner_token),
        None,
        409,
        "conflict",
    );
    let (_, other_owner, _) = relay.join_device("owner", "second-owner");
    relay.fails(
        "PUT",
        &format!("/v1/members/{member}/role"),
        Some(&other_owner),
        Some(&json!({"role": "member"})),
        409,
        "conflict",
    );
    let (_, ordinary, _) = relay.join_device("member", "alice");
    relay.ok("POST", "/v1/leave", &ordinary, None);
    relay.fails(
        "GET",
        "/v1/me",
        Some(&ordinary),
        None,
        401,
        "unauthenticated",
    );
    relay.ok("GET", "/v1/host/requests", &relay.owner_token, None);
}

#[test]
fn access_tokens_challenges_and_link_codes_do_not_cross_teams() {
    let mut relay = start(UpstreamOptions::default());
    let (_, key_a, _) = enroll_owner(&mut relay);
    let team_a = relay.team_id.clone();
    let token_a = relay.owner_token.clone();
    let token_b = relay.new_team("Team B", "bob");
    let team_b = team_of(&token_b);
    let edited = token_a.replacen(team_a.as_str(), team_b.as_str(), 1);
    relay.fails("GET", "/v1/me", Some(&edited), None, 401, "unauthenticated");
    relay.fails(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team_b, "public_key": key_a.public_key_b64()})),
        401,
        "unauthenticated",
    );
    let key = DeviceKey::generate().unwrap();
    let (code, pending) = make_link(&relay, &token_a, &key);
    let edited_code = code.replacen(team_a.as_str(), team_b.as_str(), 1);
    let body = json!({"code": edited_code, "device_name": "wrong team", "public_key": key.public_key_b64()});
    relay.fails(
        "POST",
        "/v1/devices/link",
        None,
        Some(&body),
        403,
        "forbidden",
    );
    relay.fails(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        Some(&token_b),
        Some(&json!({"safety": pending["safety"]})),
        404,
        "not_found",
    );
    confirm_link(&relay, &token_a, &pending);
    relay.ok("GET", "/v1/me", &token_a, None);
    relay.ok("GET", "/v1/me", &token_b, None);
}

#[test]
fn a_nonce_expires_at_60_seconds_and_an_access_token_at_900_seconds() {
    let mut relay = start(UpstreamOptions::default());
    let (_, key, _) = enroll_owner(&mut relay);
    let core = relay.hub().team(&relay.team_id).unwrap();
    let now = now_unix();
    let request = ChallengeRequest {
        team_id: relay.team_id.clone(),
        public_key: key.public_key_b64(),
    };
    let nonce = devices::challenge(&core, &request, now).unwrap();
    assert_eq!(nonce["expires_at"], now + 60);
    let token_request: TokenRequest = serde_json::from_value(signed_request(
        &relay.team_id,
        &key,
        &key,
        nonce["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    ))
    .unwrap();
    assert_eq!(
        devices::token(&core, &token_request, now + 60)
            .unwrap_err()
            .code,
        "unauthenticated"
    );
    assert_eq!(
        devices::token(&core, &token_request, now + 59)
            .unwrap_err()
            .code,
        "unauthenticated"
    );
    let nonce = devices::challenge(&core, &request, now).unwrap();
    let token_request: TokenRequest = serde_json::from_value(signed_request(
        &relay.team_id,
        &key,
        &key,
        nonce["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    ))
    .unwrap();
    let granted = devices::token(&core, &token_request, now + 59).unwrap();
    assert_eq!(granted["expires_at"], now + 959);
    let access = granted["token"].as_str().unwrap();
    assert!(auth::authenticate_core(&core, access, now + 958).is_ok());
    assert_eq!(
        auth::authenticate_core(&core, access, now + 959)
            .unwrap_err()
            .code,
        "token_expired"
    );
}

#[test]
fn a_wrong_public_key_consumes_the_nonce_and_device_revocation_ends_an_open_nonce() {
    let mut relay = start(UpstreamOptions::default());
    let (device, key, _) = enroll_owner(&mut relay);
    let (_, other_owner, other_key) = relay.join_device("owner", "second-owner");
    let issued = challenge(&relay, &relay.team_id, &key);
    let wrong = signed_request(
        &relay.team_id,
        &other_key,
        &other_key,
        issued["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    relay.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&wrong),
        401,
        "unauthenticated",
    );
    let valid = signed_request(
        &relay.team_id,
        &key,
        &key,
        issued["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    relay.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&valid),
        401,
        "unauthenticated",
    );
    let open = challenge(&relay, &relay.team_id, &key);
    let answer = relay.ok(
        "DELETE",
        &format!("/v1/devices/{device}"),
        &other_owner,
        None,
    );
    assert!(
        answer["message"]
            .as_str()
            .unwrap()
            .contains("no key holder")
    );
    relay.fails(
        "GET",
        "/v1/me",
        Some(&relay.owner_token),
        None,
        401,
        "unauthenticated",
    );
    let valid = signed_request(
        &relay.team_id,
        &key,
        &key,
        open["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    relay.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&valid),
        401,
        "unauthenticated",
    );
    relay.fails(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": relay.team_id, "public_key": key.public_key_b64()})),
        401,
        "unauthenticated",
    );
    let other_device = relay.ok("GET", "/v1/me", &other_owner, None)["device_id"]
        .as_u64()
        .unwrap();
    relay.ok(
        "POST",
        &format!("/v1/devices/{other_device}/key-holder"),
        &other_owner,
        None,
    );
    relay.ok("GET", "/v1/host/requests", &other_owner, None);
}

#[test]
fn a_member_cannot_exceed_ten_devices_even_with_two_open_link_codes() {
    let mut relay = start(UpstreamOptions::default());
    enroll_owner(&mut relay);
    for _ in 0..8 {
        let key = DeviceKey::generate().unwrap();
        let (_, pending) = make_link(&relay, &relay.owner_token, &key);
        confirm_link(&relay, &relay.owner_token, &pending);
    }
    let key_ten = DeviceKey::generate().unwrap();
    let key_eleven = DeviceKey::generate().unwrap();
    let (_, tenth) = make_link(&relay, &relay.owner_token, &key_ten);
    let (_, eleventh) = make_link(&relay, &relay.owner_token, &key_eleven);
    confirm_link(&relay, &relay.owner_token, &tenth);
    relay.fails(
        "POST",
        "/v1/devices/links",
        Some(&relay.owner_token),
        None,
        409,
        "conflict",
    );
    relay.fails(
        "POST",
        &format!("/v1/devices/links/{}/confirm", eleventh["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": eleventh["safety"]})),
        409,
        "conflict",
    );
    assert_eq!(
        relay
            .ok("GET", "/v1/devices", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        10
    );
}

#[test]
fn a_refused_link_cannot_sign_in_and_audit_rows_hold_no_credentials() {
    let mut relay = start(UpstreamOptions::default());
    let (_, owner_key, _) = enroll_owner(&mut relay);
    let nonce = challenge(&relay, &relay.team_id, &owner_key);
    let request = signed_request(
        &relay.team_id,
        &owner_key,
        &owner_key,
        nonce["nonce"].as_str().unwrap(),
        &relay.config.public_url,
    );
    let access = relay.ok("POST", "/v1/auth/token", "", Some(&request));
    relay.fails(
        "POST",
        "/v1/auth/token",
        None,
        Some(&request),
        401,
        "unauthenticated",
    );
    let new_key = DeviceKey::generate().unwrap();
    let (code, pending) = make_link(&relay, &relay.owner_token, &new_key);
    relay.ok(
        "POST",
        &format!("/v1/devices/links/{}/refuse", pending["id"]),
        &relay.owner_token,
        None,
    );
    relay.fails(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": relay.team_id, "public_key": new_key.public_key_b64()})),
        403,
        "join_refused",
    );
    relay.fails(
        "POST",
        &format!("/v1/devices/links/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
        409,
        "conflict",
    );
    let audit = relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .to_string();
    for credential in [
        owner_key.public_key_b64(),
        new_key.public_key_b64(),
        code,
        request["signature"].as_str().unwrap().to_string(),
        nonce["nonce"].as_str().unwrap().to_string(),
        access["token"].as_str().unwrap().to_string(),
        relay.owner_token.clone(),
    ] {
        assert!(!audit.contains(&credential), "audit contains a credential");
    }
}

#[test]
fn enrollment_rejects_agent_creation_from_an_earlier_member_principal() {
    let mut relay = start(UpstreamOptions::default());
    let core = relay.hub().team(&relay.team_id).unwrap();
    let before = auth::authenticate_core(&core, &relay.owner_token, now_unix()).unwrap();
    enroll_owner(&mut relay);
    let request = apassy_relay::api::AgentCreate {
        name: "delayed-agent".into(),
        days: None,
    };
    let error =
        apassy_relay::server::admin::agent_create(&core, before.member(), &request, now_unix())
            .unwrap_err();
    assert_eq!(error.code, "unauthenticated");
    assert!(
        relay
            .vault_rows("SELECT id, device_id FROM agent WHERE name = 'delayed-agent'")
            .is_empty()
    );
}

#[test]
fn edge_endpoints_refuse_a_bearer_instead_of_selecting_a_team_from_the_body() {
    let relay = start(UpstreamOptions::default());
    for endpoint in [
        "/v1/auth/challenge",
        "/v1/auth/token",
        "/v1/join",
        "/v1/devices/link",
        "/v1/teams",
    ] {
        relay.fails(
            "POST",
            endpoint,
            Some(&relay.owner_token),
            Some(&json!({"team_id": "t_abcdefghij"})),
            401,
            "unauthenticated",
        );
    }
}
