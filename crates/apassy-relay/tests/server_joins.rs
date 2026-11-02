//! Confirmed joins and invite rules (docs/SPEC.md section 23).

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::config::UpstreamOptions;
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::error::codes;
use relay::{TestRelay, start};
use serde_json::{Value, json};

fn invite(relay: &TestRelay, by: &str, body: Value) -> Value {
    relay.ok("POST", "/v1/invites", by, Some(&body))
}

fn request(code: &str, name: &str, key: &DeviceKey) -> Value {
    json!({
        "code": code,
        "name": name,
        "device_name": "Joiner's laptop",
        "public_key": key.public_key_b64(),
    })
}

fn join(relay: &TestRelay, invite: &Value, name: &str, key: &DeviceKey) -> Value {
    relay.ok(
        "POST",
        "/v1/join",
        "",
        Some(&request(invite["secret"].as_str().unwrap(), name, key)),
    )
}

fn confirm(relay: &TestRelay, by: &str, pending: &Value) -> Value {
    relay.ok(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"].as_u64().unwrap()),
        by,
        Some(&json!({"safety": pending["safety"]})),
    )
}

fn joins(relay: &TestRelay) -> Vec<Value> {
    relay
        .ok("GET", "/v1/joins", &relay.owner_token, None)
        .as_array()
        .unwrap()
        .clone()
}

fn challenge_fails(relay: &TestRelay, key: &DeviceKey, code: &str) {
    relay.fails(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": relay.team_id, "public_key": key.public_key_b64()})),
        403,
        code,
    );
}

fn audit(relay: &TestRelay, action: &str) -> Vec<Value> {
    relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["action"] == action)
        .cloned()
        .collect()
}

fn sql_count(relay: &TestRelay, sql: &str) -> i64 {
    relay::open_team_file(&relay.config, &relay.team_id)
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

#[test]
fn an_invite_sets_the_name_grants_and_shared_kind_after_confirmation() {
    let relay = start(UpstreamOptions::default());
    let first = relay.add_collection("family", json!({}));
    let second = relay.add_collection("work", json!({}));
    let hidden = relay.add_collection("private", json!({}));
    let before = apassy_relay::now_unix();
    let made = invite(
        &relay,
        &relay.owner_token,
        json!({"role": "member", "name": "shared-mac", "shared": true,
            "grants": [second, first, second]}),
    );
    let key = DeviceKey::generate().unwrap();
    let pending = join(&relay, &made, "ignored-name", &key);
    assert_eq!(pending["team_id"], relay.team_id.as_str());
    assert_eq!(pending["team"], "Test Team");
    assert_eq!(pending["by"], "owner");
    assert!(pending.get("secret").is_none());
    assert_eq!(
        pending["safety"],
        device::safety_words(
            &relay.team_id,
            made["secret"].as_str().unwrap(),
            &key.public_key()
        )
    );
    let expiry = pending["expires_at"].as_u64().unwrap();
    assert!(expiry >= before + 72 * 3600 && expiry <= apassy_relay::now_unix() + 72 * 3600);
    challenge_fails(&relay, &key, "join_pending");
    let waiting = joins(&relay);
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0]["id"], pending["id"]);
    assert_eq!(waiting[0]["name"], "shared-mac");
    assert_eq!(waiting[0]["device_name"], "Joiner's laptop");
    assert_eq!(waiting[0]["role"], "member");
    assert_eq!(waiting[0]["shared"], true);
    assert_eq!(waiting[0]["invited_by"], "owner");
    let mut names: Vec<_> = waiting[0]["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["family", "work"]);
    assert!(waiting[0].get("safety").is_none());
    assert!(waiting[0].get("public_key").is_none());
    assert_eq!(sql_count(&relay, "SELECT count(*) FROM member"), 1);
    assert_eq!(sql_count(&relay, "SELECT count(*) FROM device"), 0);
    assert_eq!(sql_count(&relay, "SELECT count(*) FROM access_grant"), 0);
    let before_confirm = relay.ok("GET", "/v1/invites", &relay.owner_token, None);
    let record = before_confirm
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == made["id"])
        .unwrap();
    assert!(record["used_at"].as_u64().is_some());
    assert!(record["used_by"].is_null());

    let confirmed = confirm(&relay, &relay.owner_token, &pending);
    let member = confirmed["member_id"].as_u64().unwrap();
    let device_id = confirmed["device_id"].as_u64().unwrap();
    assert!(confirmed.get("secret").is_none());
    assert!(joins(&relay).is_empty());
    let token = relay.sign_in(&relay.team_id, &key);
    let me = relay.ok("GET", "/v1/me", &token, None);
    assert_eq!(me["member_id"], member);
    assert_eq!(me["member_name"], "shared-mac");
    assert_eq!(me["role"], "member");
    assert_eq!(me["device_id"], device_id);
    assert!(!me["key_holder"].as_bool().unwrap_or(false));
    let members = relay.ok("GET", "/v1/members", &relay.owner_token, None);
    let view = members
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == member)
        .unwrap();
    assert_eq!(view["shared"], true);
    assert_eq!(view["devices"], 1);
    let devices = relay.ok("GET", "/v1/devices", &token, None);
    assert_eq!(devices.as_array().unwrap().len(), 1);
    assert_eq!(devices[0]["id"], device_id);
    assert_eq!(devices[0]["member_id"], member);
    assert_eq!(devices[0]["name"], "Joiner's laptop");
    assert_eq!(devices[0]["key_holder"], false);
    let grants = relay.ok("GET", "/v1/grants", &relay.owner_token, None);
    let mut granted: Vec<_> = grants
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["member_id"] == member)
        .map(|v| v["collection_id"].as_u64().unwrap())
        .collect();
    granted.sort_unstable();
    assert_eq!(granted, [first, second]);
    assert!(!granted.contains(&hidden));
    assert_eq!(
        sql_count(
            &relay,
            &format!(
                "SELECT count(*) FROM member WHERE id = {member} AND token_hash IS NULL AND kind = 'shared'"
            )
        ),
        1
    );
    assert_eq!(
        sql_count(
            &relay,
            &format!(
                "SELECT count(*) FROM invite WHERE id = {} AND used_by = {member} AND used_at IS NOT NULL",
                made["id"]
            )
        ),
        1
    );
    assert_eq!(audit(&relay, "member_joined").len(), 1);
    assert_eq!(audit(&relay, "device_added").len(), 1);
    let audit_text = relay
        .ok("GET", "/v1/audit?limit=500", &relay.owner_token, None)
        .to_string();
    for secret in [
        made["secret"].as_str().unwrap(),
        &key.public_key_b64(),
        &token,
    ] {
        assert!(!audit_text.contains(secret));
    }
    relay.fails(
        "PUT",
        &format!("/v1/members/{member}/role"),
        Some(&relay.owner_token),
        Some(&json!({"role": "manager"})),
        409,
        codes::CONFLICT,
    );
}

#[test]
fn invite_fields_are_checked_and_managers_cannot_invite_approvers() {
    let relay = start(UpstreamOptions::default());
    let (_, manager, _) = relay.join_device("manager", "manager");
    for role in ["manager", "owner"] {
        relay.fails(
            "POST",
            "/v1/invites",
            Some(&manager),
            Some(&json!({"role": role})),
            403,
            codes::FORBIDDEN,
        );
        relay.fails(
            "POST",
            "/v1/invites",
            Some(&relay.owner_token),
            Some(&json!({"role": role, "shared": true})),
            400,
            codes::INVALID_REQUEST,
        );
    }
    for name in ["", "bad name", "bad/name", &"n".repeat(65)] {
        relay.fails(
            "POST",
            "/v1/invites",
            Some(&relay.owner_token),
            Some(&json!({"role": "member", "name": name})),
            400,
            codes::INVALID_REQUEST,
        );
    }
    relay.fails(
        "POST",
        "/v1/invites",
        Some(&relay.owner_token),
        Some(&json!({"role": "member", "grants": [99999]})),
        404,
        codes::NOT_FOUND,
    );
    invite(
        &relay,
        &manager,
        json!({"role": "member", "name": "valid._-Name"}),
    );
}

#[test]
fn a_manager_confirms_members_but_only_an_owner_confirms_approvers() {
    let relay = start(UpstreamOptions::default());
    let (_, manager, _) = relay.join_device("manager", "manager");
    for role in ["member", "manager", "owner"] {
        let made = invite(&relay, &relay.owner_token, json!({"role": role}));
        let key = DeviceKey::generate().unwrap();
        let pending = join(&relay, &made, &format!("new-{role}"), &key);
        if role == "member" {
            confirm(&relay, &manager, &pending);
        } else {
            relay.fails(
                "POST",
                &format!("/v1/joins/{}/confirm", pending["id"]),
                Some(&manager),
                Some(&json!({"safety": pending["safety"]})),
                403,
                codes::FORBIDDEN,
            );
            assert!(joins(&relay).iter().any(|v| v["id"] == pending["id"]));
            confirm(&relay, &relay.owner_token, &pending);
        }
        let token = relay.sign_in(&relay.team_id, &key);
        let me = relay.ok("GET", "/v1/me", &token, None);
        assert_eq!(me["role"], role);
        assert!(!me["key_holder"].as_bool().unwrap_or(false));
    }
}

#[test]
fn wrong_safety_words_leave_the_join_pending_without_partial_rows() {
    let relay = start(UpstreamOptions::default());
    let made = invite(&relay, &relay.owner_token, json!({"role": "member"}));
    let key = DeviceKey::generate().unwrap();
    let pending = join(&relay, &made, "alice", &key);
    let wrong = format!("{} wrong", pending["safety"].as_str().unwrap());
    relay.fails(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": wrong})),
        409,
        codes::CONFLICT,
    );
    assert_eq!(joins(&relay).len(), 1);
    assert_eq!(sql_count(&relay, "SELECT count(*) FROM member"), 1);
    assert_eq!(sql_count(&relay, "SELECT count(*) FROM device"), 0);
    challenge_fails(&relay, &key, "join_pending");
    confirm(&relay, &relay.owner_token, &pending);
    relay.fails(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
        409,
        codes::CONFLICT,
    );
}

#[test]
fn refusal_removes_the_pending_join_and_sign_in_reports_join_refused() {
    let relay = start(UpstreamOptions::default());
    let made = invite(&relay, &relay.owner_token, json!({"role": "member"}));
    let key = DeviceKey::generate().unwrap();
    let pending = join(&relay, &made, "alice", &key);
    challenge_fails(&relay, &key, "join_pending");
    let refused = relay.ok(
        "POST",
        &format!("/v1/joins/{}/refuse", pending["id"]),
        &relay.owner_token,
        None,
    );
    assert_eq!(refused["id"], pending["id"]);
    assert!(joins(&relay).is_empty());
    challenge_fails(&relay, &key, "join_refused");
    assert_eq!(audit(&relay, "join_refused").len(), 1);
    assert_eq!(sql_count(&relay, "SELECT count(*) FROM member"), 1);
    relay.fails(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
        409,
        codes::CONFLICT,
    );
}

#[test]
fn a_join_expires_after_72_hours_without_a_wait_in_the_test() {
    let relay = start(UpstreamOptions::default());
    let made = invite(
        &relay,
        &relay.owner_token,
        json!({"role": "member", "expires_hours": 168}),
    );
    let key = DeviceKey::generate().unwrap();
    let before = apassy_relay::now_unix();
    let pending = join(&relay, &made, "alice", &key);
    assert!(pending["expires_at"].as_u64().unwrap() >= before + 72 * 3600);
    assert!(pending["expires_at"].as_u64().unwrap() <= apassy_relay::now_unix() + 72 * 3600);
    relay.edit_vault_live(&format!(
        "UPDATE join_request SET created_at = {}, expires_at = {} WHERE id = {};",
        before.saturating_sub(72 * 3600 + 1),
        before.saturating_sub(1),
        pending["id"]
    ));
    relay.fails(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
        409,
        codes::CONFLICT,
    );
    assert!(joins(&relay).is_empty());
    challenge_fails(&relay, &key, "join_refused");
    assert_eq!(
        sql_count(
            &relay,
            &format!(
                "SELECT count(*) FROM join_request WHERE id = {} AND state = 'expired'",
                pending["id"]
            )
        ),
        1
    );
    assert_eq!(sql_count(&relay, "SELECT count(*) FROM member"), 1);
}

#[test]
fn same_code_and_key_retry_returns_identical_pending_but_another_key_is_audited() {
    let relay = start(UpstreamOptions::default());
    let made = invite(&relay, &relay.owner_token, json!({"role": "member"}));
    let key = DeviceKey::generate().unwrap();
    let pending = join(&relay, &made, "alice", &key);
    assert_eq!(join(&relay, &made, "alice", &key), pending);
    assert_eq!(joins(&relay).len(), 1);
    let stranger = DeviceKey::generate().unwrap();
    let (status, refused) = relay.call(
        "POST",
        "/v1/join",
        None,
        Some(&request(
            made["secret"].as_str().unwrap(),
            "stranger",
            &stranger,
        )),
    );
    assert_eq!(status, 403, "{refused}");
    assert_eq!(refused["error"]["code"], codes::INVITE_INVALID);
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("tell the person who invited you")
    );
    let reused = audit(&relay, "invite_reused");
    assert_eq!(reused.len(), 1);
    let text = Value::Array(reused).to_string();
    assert!(!text.contains(made["secret"].as_str().unwrap()));
    assert!(!text.contains(&stranger.public_key_b64()));
    assert_eq!(join(&relay, &made, "alice", &key), pending);
    confirm(&relay, &relay.owner_token, &pending);
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(&request(
            made["secret"].as_str().unwrap(),
            "stranger",
            &stranger,
        )),
        403,
        codes::INVITE_INVALID,
    );
}

#[test]
fn two_pending_joins_cannot_take_the_same_name_and_conflict_does_not_use_an_invite() {
    let relay = start(UpstreamOptions::default());
    let first = invite(&relay, &relay.owner_token, json!({"role": "member"}));
    let second = invite(&relay, &relay.owner_token, json!({"role": "member"}));
    let key_a = DeviceKey::generate().unwrap();
    let key_b = DeviceKey::generate().unwrap();
    let pending = join(&relay, &first, "same-name", &key_a);
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(&request(
            second["secret"].as_str().unwrap(),
            "same-name",
            &key_b,
        )),
        409,
        codes::CONFLICT,
    );
    assert_eq!(joins(&relay).len(), 1);
    assert_eq!(
        sql_count(
            &relay,
            &format!(
                "SELECT count(*) FROM invite WHERE id = {} AND used_at IS NULL",
                second["id"]
            )
        ),
        1
    );
    let other = join(&relay, &second, "other-name", &key_b);
    let waiting = joins(&relay);
    assert_eq!(waiting.len(), 2);
    assert_eq!(waiting[0]["id"], pending["id"]);
    assert_eq!(waiting[1]["id"], other["id"]);
    confirm(&relay, &relay.owner_token, &pending);
    confirm(&relay, &relay.owner_token, &other);
}

#[test]
fn a_live_member_that_takes_the_name_before_confirmation_causes_conflict() {
    let relay = start(UpstreamOptions::default());
    let made = invite(&relay, &relay.owner_token, json!({"role": "member"}));
    let key = DeviceKey::generate().unwrap();
    let pending = join(&relay, &made, "taken", &key);
    // An existing member changes to this name between the request and confirmation.
    let (member, _, _) = relay.join_device("member", "existing");
    relay.edit_vault_live(&format!(
        "UPDATE member SET name = 'taken' WHERE id = {member};"
    ));
    relay.fails(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
        409,
        codes::CONFLICT,
    );
    assert!(joins(&relay).iter().any(|v| v["id"] == pending["id"]));
    assert_eq!(
        sql_count(
            &relay,
            "SELECT count(*) FROM member WHERE name = 'taken' AND revoked_at IS NULL"
        ),
        1
    );
    assert_eq!(
        sql_count(
            &relay,
            &format!(
                "SELECT count(*) FROM invite WHERE id = {} AND used_by IS NULL",
                made["id"]
            )
        ),
        1
    );
    challenge_fails(&relay, &key, "join_pending");
}

#[test]
fn an_old_cli_without_a_device_key_gets_the_update_message_without_using_the_invite() {
    let relay = start(UpstreamOptions::default());
    let made = invite(&relay, &relay.owner_token, json!({"role": "member"}));
    let key = DeviceKey::generate().unwrap();
    for body in [
        json!({"code": made["secret"], "name": "alice"}),
        json!({"code": made["secret"], "name": "alice", "device_name": "laptop"}),
        json!({"code": made["secret"], "name": "alice", "public_key": key.public_key_b64()}),
    ] {
        let (status, answer) = relay.call("POST", "/v1/join", None, Some(&body));
        assert_eq!(status, 400, "{answer}");
        assert_eq!(answer["error"]["code"], codes::INVALID_REQUEST);
        let message = answer["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("too old") && message.contains("update"),
            "{message}"
        );
        assert!(
            message.contains(&format!("{}/install.sh", relay.url)),
            "{message}"
        );
    }
    assert_eq!(
        sql_count(
            &relay,
            &format!(
                "SELECT count(*) FROM invite WHERE id = {} AND used_at IS NULL",
                made["id"]
            )
        ),
        1
    );
    join(&relay, &made, "alice", &key);
}

#[test]
fn the_invite_maker_must_still_have_permission_at_join_and_confirmation() {
    let relay = start(UpstreamOptions::default());
    let (maker, token, _) = relay.join_device("manager", "maker");
    let unused = invite(&relay, &token, json!({"role": "member"}));
    let waiting = invite(&relay, &token, json!({"role": "member"}));
    let key = DeviceKey::generate().unwrap();
    let pending = join(&relay, &waiting, "waiting", &key);
    relay.ok(
        "PUT",
        &format!("/v1/members/{maker}/role"),
        &relay.owner_token,
        Some(&json!({"role": "member"})),
    );
    let fresh = DeviceKey::generate().unwrap();
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(&request(unused["secret"].as_str().unwrap(), "new", &fresh)),
        403,
        codes::INVITE_INVALID,
    );
    let (status, _) = relay.call(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
    );
    assert!(
        (400..500).contains(&status),
        "a demoted maker's invite was confirmed: {status}"
    );
    assert_eq!(
        sql_count(&relay, "SELECT count(*) FROM member WHERE name = 'waiting'"),
        0
    );
    assert_eq!(
        sql_count(
            &relay,
            &format!(
                "SELECT count(*) FROM invite WHERE id = {} AND used_by IS NULL",
                waiting["id"]
            )
        ),
        1
    );

    let (owner, owner_token, _) = relay.join_device("owner", "second-owner");
    let unused = invite(&relay, &owner_token, json!({"role": "owner"}));
    let waiting = invite(&relay, &owner_token, json!({"role": "manager"}));
    let key = DeviceKey::generate().unwrap();
    let pending = join(&relay, &waiting, "new-manager", &key);
    relay.ok(
        "PUT",
        &format!("/v1/members/{owner}/role"),
        &relay.owner_token,
        Some(&json!({"role": "manager"})),
    );
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(&request(
            unused["secret"].as_str().unwrap(),
            "new-owner",
            &fresh,
        )),
        403,
        codes::INVITE_INVALID,
    );
    let (status, _) = relay.call(
        "POST",
        &format!("/v1/joins/{}/confirm", pending["id"]),
        Some(&relay.owner_token),
        Some(&json!({"safety": pending["safety"]})),
    );
    assert!(
        (400..500).contains(&status),
        "a maker who cannot invite managers confirmed one: {status}"
    );
    assert_eq!(
        sql_count(
            &relay,
            "SELECT count(*) FROM member WHERE name = 'new-manager'"
        ),
        0
    );
}

#[test]
fn revoking_or_leaving_as_the_maker_revokes_invites_and_refuses_pending_joins() {
    for leave in [false, true] {
        let relay = start(UpstreamOptions::default());
        let (maker, token, _) = relay.join_device("manager", "maker");
        let unused = invite(&relay, &token, json!({"role": "member"}));
        let used = invite(&relay, &token, json!({"role": "member"}));
        let key = DeviceKey::generate().unwrap();
        let pending = join(&relay, &used, "waiting", &key);
        let link = relay.ok("POST", "/v1/devices/links", &token, None);
        let link_key = DeviceKey::generate().unwrap();
        let linked = relay.ok("POST", "/v1/devices/link", "", Some(&json!({
            "code": link["secret"], "device_name": "second laptop", "public_key": link_key.public_key_b64()
        })));
        let open_link = relay.ok("POST", "/v1/devices/links", &token, None);
        if leave {
            relay.ok("POST", "/v1/leave", &token, None);
        } else {
            relay.ok(
                "DELETE",
                &format!("/v1/members/{maker}"),
                &relay.owner_token,
                None,
            );
        }
        assert!(joins(&relay).is_empty());
        challenge_fails(&relay, &key, "join_refused");
        challenge_fails(&relay, &link_key, "join_refused");
        relay.fails(
            "GET",
            "/v1/me",
            Some(&token),
            None,
            401,
            codes::UNAUTHENTICATED,
        );
        assert_eq!(
            sql_count(
                &relay,
                &format!(
                    "SELECT count(*) FROM invite WHERE id = {} AND revoked_at IS NOT NULL",
                    unused["id"]
                )
            ),
            1
        );
        assert_eq!(
            sql_count(
                &relay,
                &format!(
                    "SELECT count(*) FROM join_request WHERE id = {} AND state = 'refused'",
                    pending["id"]
                )
            ),
            1
        );
        assert_eq!(
            sql_count(
                &relay,
                &format!(
                    "SELECT count(*) FROM device_link WHERE member_id = {maker} AND state = 'expired'"
                )
            ),
            2
        );
        assert_eq!(
            sql_count(
                &relay,
                &format!(
                    "SELECT count(*) FROM device WHERE member_id = {maker} AND revoked_at IS NULL"
                )
            ),
            0
        );
        let fresh = DeviceKey::generate().unwrap();
        relay.fails(
            "POST",
            "/v1/join",
            None,
            Some(&request(unused["secret"].as_str().unwrap(), "new", &fresh)),
            403,
            codes::INVITE_INVALID,
        );
        let (status, _) = relay.call(
            "POST",
            &format!("/v1/joins/{}/confirm", pending["id"]),
            Some(&relay.owner_token),
            Some(&json!({"safety": pending["safety"]})),
        );
        assert!((400..500).contains(&status));
        assert_eq!(
            sql_count(&relay, "SELECT count(*) FROM member WHERE name = 'waiting'"),
            0
        );
        relay.fails("POST", "/v1/devices/link", None, Some(&json!({
            "code": open_link["secret"], "device_name": "new laptop", "public_key": fresh.public_key_b64()
        })), 403, codes::FORBIDDEN);
        assert_eq!(
            sql_count(
                &relay,
                &format!(
                    "SELECT count(*) FROM device_link WHERE id = {} AND state = 'expired'",
                    linked["id"]
                )
            ),
            1
        );
    }
}

#[test]
fn an_owner_device_ends_legacy_host_access_even_after_demotion() {
    let relay = start(UpstreamOptions::default());
    relay.ok("GET", "/v1/host/requests", &relay.owner_token, None);
    let (member_id, _, _) = relay.join_device("owner", "second-owner");
    relay.fails(
        "GET",
        "/v1/host/requests",
        Some(&relay.owner_token),
        None,
        403,
        "not_key_holder",
    );
    relay.ok(
        "PUT",
        &format!("/v1/members/{member_id}/role"),
        &relay.owner_token,
        Some(&json!({"role":"member"})),
    );
    relay.fails(
        "GET",
        "/v1/host/requests",
        Some(&relay.owner_token),
        None,
        403,
        "not_key_holder",
    );
}
