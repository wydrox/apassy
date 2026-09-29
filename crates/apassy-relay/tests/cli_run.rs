//! `apassy-team run`: request, wait for an approver, then run the child with the session environment.

mod cli_support;

use std::time::{Duration, Instant};

use cli_support::*;
use serde_json::{Value, json};

const PLACEHOLDER: &str = "ph_synthetic_placeholder_value_0000000000000";
const BASE: &str = "http://127.0.0.1:9/p/apassy_ses_synthetic/api.foo.example";

fn session_env() -> Value {
    json!({"FOO_KEY": PLACEHOLDER, "APASSY_BASE_FOO_KEY": BASE, "APASSY_RELAY_SESSION_EXPIRES": "2"})
}

/// A relay: `POST /v1/runs` answers with `first`; each `GET /v1/runs/5` answers with the next of `polls`.
fn relay(first: Answer, polls: Vec<Answer>) -> Mock {
    let first = std::sync::Mutex::new(Some(first));
    let polls = std::sync::Mutex::new(polls.into_iter().collect::<std::collections::VecDeque<_>>());
    Mock::start(move |request, _| {
        if request.method == "POST" {
            first
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| err(500, "relay_error", "twice"))
        } else {
            polls
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| err(500, "relay_error", "no more answers"))
        }
    })
}

fn slow(mut answer: Answer, ms: u64) -> Answer {
    answer.delay = Duration::from_millis(ms);
    answer
}

#[test]
fn pending_then_ready_runs_the_child_with_the_session_environment() {
    let mock = relay(
        ok(run_view(5, "pending", None)),
        vec![
            slow(ok(run_view(5, "pending", None)), 300),
            ok(run_view(5, "ready", Some(session_env()))),
        ],
    );
    let dir = tempfile::tempdir().unwrap();
    let out_file = dir.path().join("out");
    let script = format!(
        "printf '%s|%s' \"$FOO_KEY\" \"$APASSY_BASE_FOO_KEY\" > {}",
        out_file.display()
    );
    let cli = Cli::new().agent(&mock.url).with("APASSY_EDGE_SECRET", EDGE);
    let output = cli.run(
        &[
            "run",
            "--items",
            "1,2",
            "--purpose",
            "T",
            "--request",
            "R",
            "--ttl",
            "120",
            "--wait",
            "60",
            "--",
            "sh",
            "-c",
            &script,
        ],
        None,
    );
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    assert_eq!(
        std::fs::read_to_string(&out_file).unwrap(),
        format!("{PLACEHOLDER}|{BASE}"),
        "the child sees the placeholder and the base URL"
    );
    let stderr = text(&output.stderr);
    assert_eq!(
        stderr.matches("Waiting for an approver (run 5).").count(),
        1,
        "{stderr}"
    );
    let shown = format!("{}{}", text(&output.stdout), stderr);
    assert!(
        !shown.contains(PLACEHOLDER) && !shown.contains(BASE) && !shown.contains("apassy_ses_")
    );

    let seen = mock.requests();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/v1/runs")
    );
    let body = seen[0].json();
    assert_eq!(body["items"], json!([1, 2]));
    assert_eq!(body["command"], json!(["sh", "-c", script]));
    assert_eq!(body["purpose"], "T");
    assert_eq!(body["user_request"], "R");
    assert_eq!(body["ttl_secs"], 120);
    let cwd = body["cwd"].as_str().unwrap();
    assert!(std::path::Path::new(cwd).is_absolute());
    for poll in &seen[1..] {
        assert_eq!(
            (poll.method.as_str(), poll.url.as_str()),
            ("GET", "/v1/runs/5?wait=25")
        );
    }
    for request in &seen {
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {AGENT_TOKEN}").as_str())
        );
        assert_eq!(request.header("x-apassy-edge"), Some(EDGE));
    }
}

#[test]
fn a_run_that_is_ready_at_once_does_not_poll() {
    let mock = relay(ok(run_view(5, "ready", Some(session_env()))), vec![]);
    let output = Cli::new().agent(&mock.url).run(
        &[
            "run",
            "--items",
            "1",
            "--purpose",
            "T",
            "--",
            "sh",
            "-c",
            "exit 0",
        ],
        None,
    );
    assert_eq!(code(&output), 0);
    assert_eq!(mock.requests().len(), 1);
    assert!(!text(&output.stderr).contains("Waiting"));
    // Without --request the body has no user_request.
    assert!(mock.requests()[0].json().get("user_request").is_none());
}

#[test]
fn the_exit_code_of_the_child_passes_through() {
    for (script, expected) in [
        ("exit 7", 7),
        ("exit 0", 0),
        ("kill -9 $$", 137),
        ("kill -15 $$", 143),
    ] {
        let mock = relay(ok(run_view(5, "ready", Some(session_env()))), vec![]);
        let output = Cli::new().agent(&mock.url).run(
            &[
                "run",
                "--items",
                "1",
                "--purpose",
                "T",
                "--",
                "sh",
                "-c",
                script,
            ],
            None,
        );
        assert_eq!(code(&output), expected, "{script}");
    }
}

#[test]
fn the_child_gets_stdio_a_directory_and_no_credentials() {
    let mock = relay(ok(run_view(5, "ready", Some(session_env()))), vec![]);
    let cwd = tempfile::tempdir().unwrap();
    let cli = Cli::new()
        .agent(&mock.url)
        .with("APASSY_EDGE_SECRET", EDGE)
        .with("APASSY_TEAM_TOKEN", MEMBER_TOKEN)
        .with("KEEP_ME", "yes");
    let output = cli.run(
        &[
            "run", "--items", "1", "--purpose", "T", "--cwd", cwd.path().to_str().unwrap(), "--",
            "sh", "-c",
            "cat; printf '|%s|%s|%s|%s|%s' \"${APASSY_TOKEN-unset}\" \"${APASSY_TEAM_TOKEN-unset}\" \"${APASSY_EDGE_SECRET-unset}\" \"$KEEP_ME\" \"$(pwd -P)\"",
        ],
        Some("from stdin"),
    );
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let real = std::fs::canonicalize(cwd.path()).unwrap();
    assert_eq!(
        text(&output.stdout),
        format!("from stdin|unset|unset|unset|yes|{}", real.display())
    );
    let sent = mock.requests()[0].json();
    assert_eq!(sent["cwd"], cwd.path().to_str().unwrap());
}

#[test]
fn a_denied_run_exits_3_and_never_starts_the_child() {
    let mut denied = run_view(5, "denied", None);
    denied["code"] = json!("approval_denied");
    denied["note"] = json!("Denied by olga.");
    let mock = relay(ok(run_view(5, "pending", None)), vec![ok(denied)]);
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let output = Cli::new().agent(&mock.url).run(
        &[
            "run",
            "--items",
            "1",
            "--purpose",
            "T",
            "--",
            "sh",
            "-c",
            &format!("touch {}", marker.display()),
        ],
        None,
    );
    assert_eq!(code(&output), 3);
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("denied")
            && stderr.contains("approval_denied")
            && stderr.contains("Denied by olga."),
        "{stderr}"
    );
    assert!(!marker.exists());
}

#[test]
fn timed_out_and_ended_runs_exit_3() {
    for (status, code_text, words) in [
        ("timed_out", "approval_timeout", "timed out"),
        ("ended", "", "ended"),
    ] {
        let mut view = run_view(5, status, None);
        if !code_text.is_empty() {
            view["code"] = json!(code_text);
        }
        let mock = relay(ok(run_view(5, "pending", None)), vec![ok(view)]);
        let output = Cli::new().agent(&mock.url).run(
            &["run", "--items", "1", "--purpose", "T", "--", "true"],
            None,
        );
        assert_eq!(code(&output), 3, "{status}");
        assert!(
            text(&output.stderr).contains(words),
            "{}",
            text(&output.stderr)
        );
    }
}

#[test]
fn hard_rule_and_access_refusals_are_denials_and_other_errors_are_relay_errors() {
    let mock = relay(
        err(
            403,
            "rule_forbidden_word",
            "The command has a forbidden word.",
        ),
        vec![],
    );
    let output = Cli::new().agent(&mock.url).run(
        &["run", "--items", "1", "--purpose", "T", "--", "true"],
        None,
    );
    assert_eq!(code(&output), 3);
    assert!(text(&output.stderr).contains("rule_forbidden_word"));

    for denial in ["not_granted", "item_archived"] {
        let mock = relay(err(403, denial, "No access to that item."), vec![]);
        let output = Cli::new().agent(&mock.url).run(
            &["run", "--items", "1", "--purpose", "T", "--", "true"],
            None,
        );
        assert_eq!(code(&output), 3, "{denial}");
        assert!(text(&output.stderr).contains(denial));
    }

    let mock = relay(err(500, "relay_error", "The relay failed."), vec![]);
    let output = Cli::new().agent(&mock.url).run(
        &["run", "--items", "1", "--purpose", "T", "--", "true"],
        None,
    );
    assert_eq!(code(&output), 4);
    assert!(text(&output.stderr).contains("relay_error"));

    let output = Cli::new().agent(&dead_url()).run(
        &["run", "--items", "1", "--purpose", "T", "--", "true"],
        None,
    );
    assert_eq!(code(&output), 4);
    assert!(!text(&output.stderr).contains(AGENT_TOKEN));
}

#[test]
fn a_poll_error_from_the_relay_ends_the_run_with_exit_4() {
    let mock = relay(
        ok(run_view(5, "pending", None)),
        vec![err(404, "not_found", "No such run.")],
    );
    let output = Cli::new().agent(&mock.url).run(
        &["run", "--items", "1", "--purpose", "T", "--", "true"],
        None,
    );
    assert_eq!(code(&output), 4);
    assert!(text(&output.stderr).contains("not_found"));
}

#[test]
fn waiting_stops_after_the_wait_option() {
    let pending = || slow(ok(run_view(5, "pending", None)), 200);
    let mock = relay(
        ok(run_view(5, "pending", None)),
        vec![pending(), pending(), pending(), pending()],
    );
    let started = Instant::now();
    let output = Cli::new().agent(&mock.url).run(
        &[
            "run",
            "--items",
            "1",
            "--purpose",
            "T",
            "--wait",
            "1",
            "--",
            "true",
        ],
        None,
    );
    assert_eq!(code(&output), 3);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(text(&output.stderr).contains("Gave up waiting"));
    assert_eq!(mock.requests()[1].url, "/v1/runs/5?wait=1");
}

#[test]
fn a_missing_command_exits_127_and_needs_no_secret_output() {
    let mock = relay(ok(run_view(5, "ready", Some(session_env()))), vec![]);
    let output = Cli::new().agent(&mock.url).run(
        &[
            "run",
            "--items",
            "1",
            "--purpose",
            "T",
            "--",
            "/nonexistent/apassy-test-command",
        ],
        None,
    );
    assert_eq!(code(&output), 127);
    let shown = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(!shown.contains(PLACEHOLDER) && !shown.contains(BASE));
}

#[test]
fn run_needs_an_agent_token_and_a_command() {
    let mock = relay(ok(run_view(5, "ready", None)), vec![]);
    let output = Cli::new()
        .with("APASSY_RELAY_URL", &mock.url)
        .with("APASSY_TEAM_TOKEN", MEMBER_TOKEN)
        .run(
            &["run", "--items", "1", "--purpose", "T", "--", "true"],
            None,
        );
    assert_eq!(code(&output), 2, "a member token does not work for run");
    assert!(text(&output.stderr).contains("APASSY_TOKEN"));
    let output = Cli::new()
        .agent(&mock.url)
        .run(&["run", "--items", "1", "--purpose", "T"], None);
    assert_eq!(code(&output), 2);
    assert!(mock.requests().is_empty());
}

#[test]
fn ready_without_a_session_is_a_relay_error() {
    let mock = relay(ok(run_view(5, "ready", None)), vec![]);
    let output = Cli::new().agent(&mock.url).run(
        &["run", "--items", "1", "--purpose", "T", "--", "true"],
        None,
    );
    assert_eq!(code(&output), 4);
}
