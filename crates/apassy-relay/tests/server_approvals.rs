//! Denials, the refused approve endpoint, timeouts, invalidation, and the long poll.
//! A run is released by the owner's host (`TestRelay::release` plays the host); the
//! host endpoints themselves are in `server_host.rs`.

#[path = "common/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use apassy_relay::config::{Limits, UpstreamOptions};
use relay::{CANARY, Team, TestRelay, start, start_with};
use serde_json::{Value, json};

const USER: &str = "Please check the repository state.";

/// A run that waits: a command that is not known safe.
fn pending_run(relay: &TestRelay, team: &Team) -> u64 {
    let (status, body) = relay.run(
        &team.agent_token,
        &team.request(&["python3", "script.py"], Some(USER)),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "pending");
    body["result"]["run_id"].as_u64().unwrap()
}

fn approve(relay: &TestRelay, run: u64, body: Option<Value>) -> (u16, Value) {
    relay.call(
        "POST",
        &format!("/v1/approvals/{run}/approve"),
        Some(&relay.owner_token),
        body.as_ref(),
    )
}

/// The host releases a pending run with the keys of its items.
fn release(relay: &TestRelay, run: u64) -> (u16, Value) {
    relay.release(run)
}

/// The release body for a run, made while the run is pending. It stays valid for one
/// try only: the relay takes the run key out at the first release.
fn release_body(relay: &TestRelay, run: u64, reason: Option<&str>) -> Value {
    relay.release_for(&relay.host_request(run), reason)
}

fn release_with(relay: &TestRelay, run: u64, body: &Value) -> (u16, Value) {
    relay.call(
        "POST",
        &format!("/v1/host/requests/{run}/release"),
        Some(&relay.owner_token),
        Some(body),
    )
}

fn get_run(relay: &TestRelay, team: &Team, run: u64) -> Value {
    relay.ok("GET", &format!("/v1/runs/{run}"), &team.agent_token, None)
}

#[test]
fn release_gives_a_session_with_placeholders_and_base_urls() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    // The approver sees the run.
    let list = relay.ok("GET", "/v1/approvals", &relay.owner_token, None);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["run_id"], run);
    assert_eq!(list[0]["command"], json!(["python3", "script.py"]));
    assert_eq!(list[0]["user_request"], USER);
    assert_eq!(list[0]["cwd"], "/work");
    let (status, body) = release(&relay, run);
    assert_eq!(status, 200, "{body}");
    let view = &body["result"];
    assert_eq!(view["status"], "ready");
    assert_eq!(view["decided_by"], "host");
    assert!(view.get("approver").is_none());
    assert_eq!(view["note"], "Released by the owner's host.");
    assert!(
        view.get("session").is_none(),
        "the host does not get the session"
    );
    assert_eq!(
        relay
            .ok("GET", "/v1/approvals", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        0
    );
    // The agent gets the session.
    let view = get_run(&relay, &team, run);
    assert_eq!(view["status"], "ready");
    let session = &view["session"];
    let env = session["env"].as_object().unwrap();
    let placeholder = env["STRIPE_API_KEY"].as_str().unwrap();
    assert_eq!(placeholder.len(), CANARY.len());
    assert_ne!(placeholder, CANARY);
    assert!(placeholder.starts_with("sk_test_"));
    let prefix = format!("{}/p/apassy_ses_", relay.url);
    for var in ["APASSY_BASE_STRIPE_API_KEY", "STRIPE_API_BASE"] {
        let url = env[var].as_str().unwrap();
        assert!(url.starts_with(&prefix), "{var}: {url}");
        assert!(url.ends_with("/api.stripe.com"), "{url}");
    }
    let expires = session["expires_at"].as_u64().unwrap();
    assert_eq!(env["APASSY_RELAY_SESSION_EXPIRES"], expires.to_string());
    assert_eq!(session["placeholders"], json!(["STRIPE_API_KEY"]));
    assert!(
        session["base_urls"]["api.stripe.com"]
            .as_str()
            .unwrap()
            .starts_with(&prefix)
    );
    assert!(expires >= view["created_at"].as_u64().unwrap() + 59);
    assert!(!view.to_string().contains(CANARY));
    // The same host list as the item: every known Stripe host has a base URL.
    assert!(session["base_urls"].as_object().unwrap().len() >= 2);
}

#[test]
fn nobody_approves_on_the_relay() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    // The owner, with or without a body, and for a run that does not exist.
    for body in [
        None,
        Some(json!({})),
        Some(json!({"reason": "fine"})),
        Some(json!({"anything": 1})),
    ] {
        let (status, answer) = approve(&relay, run, body);
        assert_eq!(status, 403, "{answer}");
        assert_eq!(answer["error"]["code"], "approve_on_host");
        assert_eq!(
            answer["error"]["message"],
            "The keys are on the owner's host. Approve there with apassy-team host."
        );
    }
    assert_eq!(
        approve(&relay, 9999, None).1["error"]["code"],
        "approve_on_host"
    );
    // A manager too. A plain member is refused earlier, as forbidden.
    let (_, manager) = relay.join_member("manager", "maria");
    let (_, member) = relay.join_member("member", "bob");
    relay.fails(
        "POST",
        &format!("/v1/approvals/{run}/approve"),
        Some(&manager),
        None,
        403,
        "approve_on_host",
    );
    relay.fails(
        "POST",
        &format!("/v1/approvals/{run}/approve"),
        Some(&member),
        None,
        403,
        "forbidden",
    );
    // The run still waits, and the host can release it.
    assert_eq!(get_run(&relay, &team, run)["status"], "pending");
    assert_eq!(release(&relay, run).0, 200);
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    assert!(
        !audit
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "run_approved")
    );
}

#[test]
fn release_and_deny_take_a_reason() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let body = release_body(&relay, run, Some("  Looks fine to me.  "));
    let (status, answer) = release_with(&relay, run, &body);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["result"]["note"], "Looks fine to me.");
    let run = pending_run(&relay, &team);
    let (status, body) = relay.call(
        "POST",
        &format!("/v1/approvals/{run}/deny"),
        Some(&relay.owner_token),
        Some(&json!({"reason": "Not today."})),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["note"], "Not today.");
    // A long reason, a NUL, and an unknown field are refused before the key is used.
    let run = pending_run(&relay, &team);
    for reason in [Some("r".repeat(501)), Some("a\u{0}b".to_string())] {
        let body = release_body(&relay, run, reason.as_deref());
        let (status, body) = release_with(&relay, run, &body);
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["code"], "invalid_request");
    }
    let mut body = release_body(&relay, run, None);
    body["other"] = json!(1);
    assert_eq!(release_with(&relay, run, &body).0, 400);
    for bad in [json!({"reason": "r".repeat(501)}), json!({"other": 1})] {
        let (status, body) = relay.call(
            "POST",
            &format!("/v1/host/requests/{run}/deny"),
            Some(&relay.owner_token),
            Some(&bad),
        );
        assert_eq!(status, 400, "{body}");
    }
    // The run still waits, and its key is still there.
    assert_eq!(get_run(&relay, &team, run)["status"], "pending");
    assert_eq!(release(&relay, run).0, 200);
}

#[test]
fn deny_ends_the_run_with_approval_denied() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let old_request = relay.host_request(run);
    let (status, body) = relay.call(
        "POST",
        &format!("/v1/approvals/{run}/deny"),
        Some(&relay.owner_token),
        None,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "denied");
    assert_eq!(body["result"]["code"], "approval_denied");
    assert_eq!(body["result"]["note"], "Denied by owner.");
    let view = get_run(&relay, &team, run);
    assert_eq!(view["status"], "denied");
    assert_eq!(view["code"], "approval_denied");
    assert_eq!(view["decided_by"], "approver");
    assert_eq!(view["approver"], "owner");
    assert!(view.get("session").is_none());
    // A second decision finds no pending run.
    relay.fails(
        "POST",
        &format!("/v1/approvals/{run}/deny"),
        Some(&relay.owner_token),
        None,
        409,
        "run_not_pending",
    );
    // The run is gone from the host, and a release for it is refused.
    assert!(relay.host_requests().is_empty());
    let body = relay.release_for(&old_request, None);
    let (status, body) = release_with(&relay, run, &body);
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["code"], "run_not_pending");
}

#[test]
fn releasing_twice_is_run_not_pending() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let request = relay.host_request(run);
    let again = relay.release_for(&request, None);
    assert_eq!(release(&relay, run).0, 200);
    let (status, body) = release_with(&relay, run, &again);
    assert_eq!(status, 409);
    assert_eq!(body["error"]["code"], "run_not_pending");
    relay.fails(
        "POST",
        &format!("/v1/approvals/{run}/deny"),
        Some(&relay.owner_token),
        None,
        409,
        "run_not_pending",
    );
    relay.fails(
        "POST",
        &format!("/v1/host/requests/{run}/deny"),
        Some(&relay.owner_token),
        None,
        409,
        "run_not_pending",
    );
    // The second release did not end the session of the first.
    assert_eq!(get_run(&relay, &team, run)["status"], "ready");
    // An unknown run is 404.
    let (status, _) = release_with(&relay, 9999, &again);
    assert_eq!(status, 404);
}

#[test]
fn a_manager_can_deny_but_not_release() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (_, manager) = relay.join_member("manager", "maria");
    let run = pending_run(&relay, &team);
    let body = release_body(&relay, run, None);
    let (status, answer) = relay.call(
        "POST",
        &format!("/v1/host/requests/{run}/release"),
        Some(&manager),
        Some(&body),
    );
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["error"]["code"], "forbidden");
    relay.fails(
        "GET",
        "/v1/host/requests",
        Some(&manager),
        None,
        403,
        "forbidden",
    );
    let (status, body) = relay.call(
        "POST",
        &format!("/v1/approvals/{run}/deny"),
        Some(&manager),
        None,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["approver"], "maria");
    assert_eq!(body["result"]["note"], "Denied by maria.");
}

#[test]
fn a_run_times_out_and_can_no_longer_be_released() {
    // Every expiry below is forced with SQL. A long timeout keeps the waiting runs from
    // expiring on their own while the later cases run (each vault edit derives keys).
    let relay = start_with(
        |config| config.approval_timeout_secs = 60,
        UpstreamOptions::default(),
    );
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let second = pending_run(&relay, &team);
    let body = release_body(&relay, second, None);
    assert_eq!(
        relay
            .ok("GET", "/v1/approvals", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(relay.host_requests().len(), 2);

    // A late release is refused even before any read of the run: the release of a third
    // run arrives first after its expiry.
    let late = pending_run(&relay, &team);
    let late_body = release_body(&relay, late, None);
    relay.edit_vault_live(&format!("UPDATE run SET expires_at = 1 WHERE id = {late}"));
    let (status, answer) = release_with(&relay, late, &late_body);
    assert_eq!(status, 409, "late release: {answer}");
    assert_eq!(get_run(&relay, &team, late)["status"], "timed_out");

    // A run past its expiry is not listed for the host: a fourth run with a known safe
    // command, listed while it waits.
    let (status, listed) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some(USER)),
    );
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["result"]["status"], "pending");
    let listed = listed["result"]["run_id"].as_u64().unwrap();
    assert!(
        relay
            .host_requests()
            .iter()
            .any(|request| request["run_id"] == listed)
    );
    relay.edit_vault_live(&format!(
        "UPDATE run SET expires_at = 1 WHERE id = {listed}"
    ));
    let requests = relay.host_requests();
    assert!(
        requests.iter().all(|request| request["run_id"] != listed),
        "{requests:?}"
    );
    assert_eq!(requests.len(), 2, "the first two runs still wait");
    assert_eq!(get_run(&relay, &team, listed)["status"], "timed_out");

    // Both first runs are past their expiry (no wait for the timeout): the relay sees it at a
    // read.
    relay.edit_vault_live(&format!(
        "UPDATE run SET expires_at = 1 WHERE id IN ({run}, {second})"
    ));
    // A read of the run shows the timeout.
    let view = get_run(&relay, &team, run);
    assert_eq!(view["status"], "timed_out");
    assert_eq!(view["code"], "approval_timeout");
    assert_eq!(view["decided_by"], "timeout");
    // The list of approvals sweeps the other one, and the host does not see either.
    assert_eq!(
        relay
            .ok("GET", "/v1/approvals", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(relay.host_requests().is_empty());
    let (status, answer) = release_with(&relay, second, &body);
    assert_eq!(status, 409, "{answer}");
    assert_eq!(answer["error"]["code"], "run_not_pending");
    assert_eq!(get_run(&relay, &team, second)["status"], "timed_out");
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    let timed_out = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["action"] == "run_timed_out")
        .count();
    assert_eq!(timed_out, 4, "one row per run, not per read");
}

#[test]
fn a_run_with_no_host_times_out() {
    let relay = start_with(
        |config| config.approval_timeout_secs = 1,
        UpstreamOptions::default(),
    );
    let team = relay.setup("staging");
    // A known safe command: the relay suggests allow, but nobody releases the keys.
    let (status, body) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some(USER)),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "pending");
    let run = body["result"]["run_id"].as_u64().unwrap();
    let view = relay.ok(
        "GET",
        &format!("/v1/runs/{run}?wait=10"),
        &team.agent_token,
        None,
    );
    assert_eq!(view["status"], "timed_out");
    assert_eq!(view["code"], "approval_timeout");
    assert!(view.get("session").is_none());
}

#[test]
fn a_grant_revoked_while_pending_invalidates_the_run() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let old = relay.host_request(run);
    relay.ok(
        "DELETE",
        &format!("/v1/grants/{}", team.grant),
        &relay.owner_token,
        None,
    );
    // The run is denied at once, and its key is dropped: the host does not see it.
    let view = get_run(&relay, &team, run);
    assert_eq!(view["status"], "denied");
    assert_eq!(view["code"], "approval_invalidated");
    assert_eq!(view["decided_by"], "revocation");
    assert!(view.get("session").is_none());
    assert!(relay.host_requests().is_empty());
    let body = relay.release_for(&old, None);
    let (status, answer) = release_with(&relay, run, &body);
    assert_eq!(status, 409, "{answer}");
    assert_eq!(answer["error"]["code"], "run_not_pending");
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "run_invalidated")
    );
}

#[test]
fn an_archived_item_or_a_revoked_agent_invalidates_the_run() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    relay.ok(
        "DELETE",
        &format!("/v1/items/{}", team.item),
        &relay.owner_token,
        None,
    );
    let view = get_run(&relay, &team, run);
    assert_eq!(view["code"], "approval_invalidated");
    assert!(relay.host_requests().is_empty());

    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let old = relay.host_request(run);
    relay.ok(
        "DELETE",
        &format!("/v1/agents/{}", team.agent_id),
        &relay.owner_token,
        None,
    );
    assert!(relay.host_requests().is_empty());
    let body = relay.release_for(&old, None);
    assert_eq!(release_with(&relay, run, &body).0, 409);
    relay.fails(
        "GET",
        &format!("/v1/runs/{run}"),
        Some(&team.agent_token),
        None,
        401,
        "unauthenticated",
    );
}

#[test]
fn the_recheck_at_release_denies_a_run_whose_agent_expired() {
    // Step 1 of the decision is checked again at release. An agent token can run
    // out while a run waits, without any revocation that drops the key.
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    relay.edit_vault_live("UPDATE agent SET expires_at = 1");
    let (status, body) = release(&relay, run);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "denied");
    assert_eq!(body["result"]["code"], "approval_invalidated");
    assert_eq!(body["result"]["decided_by"], "revocation");
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "run_invalidated")
    );
    // No session was made, and the key is used up.
    assert!(
        !audit
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "session_started")
    );
    assert!(relay.host_requests().is_empty());
}

#[test]
fn a_revoked_member_loses_the_pending_runs_at_once() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let old = relay.host_request(run);
    relay.ok(
        "DELETE",
        &format!("/v1/members/{}", team.member_id),
        &relay.owner_token,
        None,
    );
    assert_eq!(
        relay
            .ok("GET", "/v1/approvals", &relay.owner_token, None)
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(relay.host_requests().is_empty());
    let body = relay.release_for(&old, None);
    let (status, body) = release_with(&relay, run, &body);
    assert_eq!(status, 409, "{body}");
}

#[test]
fn only_the_agent_that_made_the_run_reads_it() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let second = relay.ok(
        "POST",
        "/v1/agents",
        &team.member_token,
        Some(&json!({"name": "second"})),
    );
    let other = second["secret"].as_str().unwrap();
    relay.fails(
        "GET",
        &format!("/v1/runs/{run}"),
        Some(other),
        None,
        404,
        "not_found",
    );
    relay.fails(
        "GET",
        "/v1/runs/9999",
        Some(&team.agent_token),
        None,
        404,
        "not_found",
    );
    // Another member's agent too.
    let (_, bob) = relay.join_member("member", "bob");
    let bobs = relay.ok("POST", "/v1/agents", &bob, Some(&json!({"name": "b"})));
    relay.fails(
        "GET",
        &format!("/v1/runs/{run}"),
        bobs["secret"].as_str(),
        None,
        404,
        "not_found",
    );
    // The member token and the owner token are the wrong kind.
    relay.fails(
        "GET",
        &format!("/v1/runs/{run}"),
        Some(&team.member_token),
        None,
        401,
        "unauthenticated",
    );
    assert_eq!(get_run(&relay, &team, run)["status"], "pending");
}

#[test]
fn wait_holds_the_response_until_the_release() {
    let relay = std::sync::Arc::new(start(UpstreamOptions::default()));
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let started = Instant::now();
    let poller = {
        let relay = relay.clone();
        let token = team.agent_token.clone();
        std::thread::spawn(move || {
            let view = relay.ok("GET", &format!("/v1/runs/{run}?wait=20"), &token, None);
            (view, started.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(800));
    assert_eq!(release(&relay, run).0, 200);
    let (view, waited) = poller.join().unwrap();
    assert_eq!(view["status"], "ready");
    assert!(view["session"]["env"]["STRIPE_API_KEY"].is_string());
    assert!(waited >= Duration::from_millis(700), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
}

#[test]
fn wait_returns_pending_when_the_time_is_up_and_ready_at_once() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let started = Instant::now();
    let view = relay.ok(
        "GET",
        &format!("/v1/runs/{run}?wait=1"),
        &team.agent_token,
        None,
    );
    let waited = started.elapsed();
    assert_eq!(view["status"], "pending");
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(4),
        "{waited:?}"
    );
    // No wait: at once.
    let started = Instant::now();
    relay.ok("GET", &format!("/v1/runs/{run}"), &team.agent_token, None);
    assert!(started.elapsed() < Duration::from_millis(500));
    // A ready run does not wait.
    let ready = relay.run_released(
        &team.agent_token,
        &team.request(&["git", "status"], Some(USER)),
    );
    let id = ready["run_id"].as_u64().unwrap();
    let started = Instant::now();
    let view = relay.ok(
        "GET",
        &format!("/v1/runs/{id}?wait=25"),
        &team.agent_token,
        None,
    );
    assert_eq!(view["status"], "ready");
    assert!(started.elapsed() < Duration::from_secs(1));
    relay.fails(
        "GET",
        &format!("/v1/runs/{id}?wait=26"),
        Some(&team.agent_token),
        None,
        400,
        "invalid_request",
    );
    relay.fails(
        "GET",
        &format!("/v1/runs/{id}?wait=x"),
        Some(&team.agent_token),
        None,
        400,
        "invalid_request",
    );
}

#[test]
fn wait_ends_with_the_timeout_of_the_run() {
    let relay = start_with(
        |config| config.approval_timeout_secs = 1,
        UpstreamOptions::default(),
    );
    let team = relay.setup("staging");
    let run = pending_run(&relay, &team);
    let started = Instant::now();
    let view = relay.ok(
        "GET",
        &format!("/v1/runs/{run}?wait=10"),
        &team.agent_token,
        None,
    );
    assert_eq!(view["status"], "timed_out");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn the_approval_list_is_oldest_first() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let first = pending_run(&relay, &team);
    let second = pending_run(&relay, &team);
    let third = pending_run(&relay, &team);
    let list = relay.ok("GET", "/v1/approvals", &relay.owner_token, None);
    let ids: Vec<u64> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["run_id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![first, second, third]);
    relay.ok(
        "POST",
        &format!("/v1/approvals/{second}/deny"),
        &relay.owner_token,
        None,
    );
    let list = relay.ok("GET", "/v1/approvals", &relay.owner_token, None);
    assert_eq!(list.as_array().unwrap().len(), 2);
}

/// A raw HTTP/1.1 request, for the status line and the headers of an answer.
fn raw_get(relay: &TestRelay, path: &str, token: &str) -> (u16, String, String) {
    use std::io::{Read, Write};
    let addr = relay.url.trim_start_matches("http://");
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: relay\r\nX-Apassy-Edge: {}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n",
        relay.edge_secret
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head.to_ascii_lowercase(), body.to_owned())
}

/// Many long polls of one agent: each over the limit is answered at once, and an
/// approver still gets through.
#[test]
fn many_long_polls_of_one_agent_do_not_block_the_approver() {
    let relay = std::sync::Arc::new(start_with(
        |config| config.approval_timeout_secs = 120,
        UpstreamOptions::default(),
    ));
    let team = relay.setup("production");
    let run = pending_run(&relay, &team);
    let started = Instant::now();
    let pollers: Vec<_> = (0..300)
        .map(|_| {
            let relay = relay.clone();
            let token = team.agent_token.clone();
            // A short gap, so the listen queue of the test machine does not overflow.
            std::thread::sleep(Duration::from_millis(3));
            std::thread::spawn(move || {
                let asked = Instant::now();
                let (status, body) = relay.call(
                    "GET",
                    &format!("/v1/runs/{run}?wait=25"),
                    Some(&token),
                    None,
                );
                (status, body, asked.elapsed())
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(1000));
    let (status, body) = release(&relay, run);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["status"], "ready");
    let mut quick_pending = 0;
    for poller in pollers {
        let (status, body, took) = poller.join().unwrap();
        match status {
            200 => {
                let run_status = body["result"]["status"].as_str().unwrap().to_owned();
                if run_status == "pending" {
                    // Over the limit of long polls: answered at once.
                    assert!(took < Duration::from_secs(5), "{took:?}");
                    quick_pending += 1;
                } else {
                    assert_eq!(run_status, "ready");
                }
            }
            503 => assert_eq!(body["error"]["code"], "busy", "{body}"),
            other => panic!("unexpected status {other}: {body}"),
        }
    }
    assert!(quick_pending > 0);
    assert!(started.elapsed() < Duration::from_secs(20));
}

/// A long poll that is held: who asks for which run, and the thread that waits.
type Held = Vec<(String, u64, std::thread::JoinHandle<(u16, Value)>)>;

/// Agent requests leave a reserve of slots to members and approvers. A request over
/// a limit gets 503 `busy` as an envelope with `Retry-After`.
#[test]
fn agent_requests_leave_slots_for_approvers_and_busy_is_an_envelope() {
    let relay = std::sync::Arc::new(start_with(
        |config| {
            config.approval_timeout_secs = 120;
            config.limits = Limits {
                max_active: 6,
                member_reserve: 2,
                long_polls_per_agent: 2,
                host_long_polls: 2,
                ..Default::default()
            };
        },
        UpstreamOptions::default(),
    ));
    let team = relay.setup("production");
    let second = relay.ok(
        "POST",
        "/v1/agents",
        &team.member_token,
        Some(&json!({"name": "alice-agent-2"})),
    );
    let second = Team {
        agent_id: second["id"].as_u64().unwrap(),
        agent_token: second["secret"].as_str().unwrap().to_owned(),
        member_token: team.member_token.clone(),
        ..team
    };
    let run_a = pending_run(&relay, &team);
    let run_b = pending_run(&relay, &second);
    let poll = |token: &str, run: u64| {
        let relay = relay.clone();
        let token = token.to_owned();
        std::thread::spawn(move || {
            // As `apassy-team run` does, ask again after 503 `busy`: a slot is freed
            // a moment after the answer that used it is sent.
            loop {
                let answer = relay.call(
                    "GET",
                    &format!("/v1/runs/{run}?wait=20"),
                    Some(&token),
                    None,
                );
                if answer.0 != 503 {
                    return answer;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };
    // The long polls that are held: who asks for which run, and the thread.
    let mut held: Held = vec![
        (
            team.agent_token.clone(),
            run_a,
            poll(&team.agent_token, run_a),
        ),
        (
            team.agent_token.clone(),
            run_a,
            poll(&team.agent_token, run_a),
        ),
    ];
    // A long poll that was answered at once (over the limit of its agent, or a probe that
    // took its place) is asked again.
    let renew = |held: &mut Held| {
        for (token, run, handle) in held.iter_mut() {
            if handle.is_finished() {
                let old = std::mem::replace(handle, poll(token, *run));
                let (status, body) = old.join().unwrap();
                assert_eq!(
                    (status, &body["result"]["status"]),
                    (200, &json!("pending"))
                );
            }
        }
    };
    // A third long poll of the same agent is answered at once. (A probe that starts
    // before a held poll takes its place; that poll is then asked again.)
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let asked = Instant::now();
        let view = relay.ok(
            "GET",
            &format!("/v1/runs/{run_a}?wait=2"),
            &team.agent_token,
            None,
        );
        assert_eq!(view["status"], "pending");
        if asked.elapsed() < Duration::from_secs(1) {
            break;
        }
        assert!(Instant::now() < deadline, "the long polls did not start");
        renew(&mut held);
    }
    for _ in 0..2 {
        held.push((
            second.agent_token.clone(),
            run_b,
            poll(&second.agent_token, run_b),
        ));
    }
    // Now 4 agent requests run: the agent slots (6 - 2) are full.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (status, head, body) = loop {
        let answer = raw_get(&relay, "/v1/access", &second.agent_token);
        if answer.0 == 503 {
            break answer;
        }
        assert!(Instant::now() < deadline, "the agent slots never filled");
        renew(&mut held);
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status, 503);
    assert!(head.contains("\r\nretry-after: 2"), "{head}");
    assert!(
        head.contains("\r\ncontent-type: application/json"),
        "{head}"
    );
    let envelope: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"]["code"], "busy");
    // The proxy and MCP are agent requests too.
    assert_eq!(raw_get(&relay, "/mcp", &second.agent_token).0, 503);
    assert_eq!(raw_get(&relay, "/p/x/api.example.com/", "x").0, 503);
    // Members, approvers, and the health check still get through.
    assert_eq!(raw_get(&relay, "/healthz", "x").0, 200);
    relay.ok("GET", "/v1/approvals", &relay.owner_token, None);
    // The host endpoints are in the member lane: they work while the agent slots are full.
    assert_eq!(relay.host_requests().len(), 2);
    let (status, body) = release(&relay, run_a);
    assert_eq!(status, 200, "{body}");
    let (status, body) = relay.call(
        "POST",
        &format!("/v1/host/requests/{run_b}/deny"),
        Some(&relay.owner_token),
        None,
    );
    assert_eq!(status, 200, "{body}");
    for (_, _, poller) in held {
        let (status, body) = poller.join().unwrap();
        assert_eq!(status, 200, "{body}");
        assert_ne!(body["result"]["status"], "pending", "{body}");
    }
    // The slots are free again.
    relay.ok("GET", "/v1/access", &second.agent_token, None);
}
