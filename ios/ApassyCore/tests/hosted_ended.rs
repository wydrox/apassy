//! The end of the free paths of the hosted relay (plan s7 section 5, R3; ios-core-v1
//! section 5.10, "The end of the free hosted paths"): the relay answers the questions,
//! the feed, and the push of a free team with 410 `free_connect_ended`, or every route
//! with 410 `hosted_retired`. The core reports one state (`relay_ended`), stops calling
//! that team for the rest of the process, and makes no storm of calls.

#[path = "common/questions_relay.rs"]
mod questions_relay;

#[path = "common/questions_fixture.rs"]
mod questions_fixture;

use questions_fixture::*;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn token_set() -> Value {
    json!({"op": "push_token_set", "token": "ab".repeat(32), "environment": "development"})
}

/// The calls of the relay after the first `skip`.
fn calls_since(setup: &Setup, skip: usize) -> Vec<String> {
    setup.relay.log().into_iter().skip(skip).collect()
}

fn assert_ended(setup: &Setup) {
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert_eq!(list["status"]["relay_ended"], true, "{list}");
    assert_eq!(list["status"]["enabled"], true, "{list}");
    assert_eq!(list["vaults"][0]["error"], "relay_ended", "{list}");
    assert_eq!(list["vaults"][0]["status"]["relay_ended"], true, "{list}");
    let feed = call(&setup.core, json!({"op": "feed_list"}));
    assert_eq!(feed["vaults"][0]["relay_ended"], true, "{feed}");
    assert_eq!(feed["vaults"][0]["error"], "relay_ended", "{feed}");
}

/// After the end is known, no call reaches the relay: not a read, not a long poll, not the
/// push, not after a lock and an unlock.
fn assert_quiet(setup: &Setup) {
    let before = setup.relay.log().len();
    for _ in 0..3 {
        assert_ended(setup);
    }
    let started = Instant::now();
    let waited = call(&setup.core, json!({"op": "questions_wait", "timeout": 1}));
    assert_eq!(waited["changed"], false);
    let fed = call(&setup.core, json!({"op": "feed_wait", "timeout": 1}));
    assert_eq!(fed["changed"], false);
    // Both long polls wait their time out: an app that waits again does not spin.
    assert!(
        started.elapsed() >= Duration::from_millis(1900),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(fails(&setup.core, token_set()), "relay_ended");
    let cleared = call(&setup.core, json!({"op": "push_token_clear"}));
    assert_eq!(cleared["pending"], json!([]), "{cleared}");
    call(&setup.core, json!({"op": "lock"}));
    call(&setup.core, json!({"op": "unlock", "passphrase": PASS}));
    assert_ended(setup);
    assert_eq!(calls_since(setup, before), Vec::<String>::new());
}

#[test]
fn free_connect_ended_is_one_quiet_state_with_no_more_calls() {
    let setup = setup();
    attach(&setup);
    // The push token is on the team, as before the cutover.
    call(&setup.core, token_set());
    assert!(setup.relay.push_token().is_some());
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert!(
        list["status"].get("relay_ended").is_none(),
        "absent before: {list}"
    );

    setup.relay.end_free_paths(Some("free_connect_ended"));
    let before = setup.relay.log().len();
    assert_ended(&setup);
    // One read of the questions and one of the feed found the end, then nothing more.
    let calls = calls_since(&setup, before);
    assert!(calls.len() <= 2, "{calls:?}");
    assert_quiet(&setup);
}

#[test]
fn the_push_registration_finds_the_end_first() {
    let setup = setup();
    attach(&setup);
    setup.relay.end_free_paths(Some("free_connect_ended"));
    let before = setup.relay.log().len();
    // The token change goes first and finds the end: one call, one state.
    assert_eq!(fails(&setup.core, token_set()), "relay_ended");
    assert_eq!(
        calls_since(&setup, before),
        vec!["PUT /v1/push/token".to_owned()]
    );
    assert_quiet(&setup);
}

#[test]
fn hosted_retired_ends_the_sign_in_too() {
    let setup = setup();
    attach(&setup);
    setup.relay.end_free_paths(Some("hosted_retired"));
    // A new process session: the sign-in itself answers 410.
    call(&setup.core, json!({"op": "lock"}));
    call(&setup.core, json!({"op": "unlock", "passphrase": PASS}));
    assert_ended(&setup);
    assert_quiet(&setup);
}

#[test]
fn another_410_is_no_end() {
    let setup = setup();
    attach(&setup);
    setup.relay.end_free_paths(Some("gone_elsewhere"));
    let answer: Value = serde_json::from_str(
        &setup
            .core
            .call(&json!({"op": "questions_list"}).to_string()),
    )
    .unwrap();
    assert_eq!(answer["ok"], false, "{answer}");
    assert_ne!(answer["error"]["code"], "relay_ended", "{answer}");
    // The relay serves again: the questions work, with no ended state.
    setup.relay.end_free_paths(None);
    let list = call(&setup.core, json!({"op": "questions_list"}));
    assert!(list["status"].get("relay_ended").is_none(), "{list}");
}
