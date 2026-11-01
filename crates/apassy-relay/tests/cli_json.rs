mod cli_support;
use cli_support::*;
use serde_json::{Value, json};

fn document(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("one JSON document required: {e}: {}", text(&output.stdout)))
}

#[test]
fn json_is_one_envelope_for_lists_mutations_and_usage_errors() {
    let mock = Mock::start(|request, _| match request.url.as_str() {
        "/v1/members" => ok(json!([])),
        "/v1/collections" => ok(json!({"id": 42})),
        _ => err(403, "not_owner", "An owner is required."),
    });
    let cli = Cli::new().member(&mock.url);
    let output = cli.run(&["members", "--json"], None);
    assert_eq!(code(&output), 0);
    assert_eq!(
        document(&output),
        json!({"ok":true,"result":[],"exit_code":0})
    );
    let output = cli.run(&["--json", "collection", "create", "Secrets"], None);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    assert_eq!(document(&output)["result"]["id"], 42);
    let output = cli.run(&["--json", "unknown-command"], None);
    assert_eq!(code(&output), 2);
    assert_eq!(document(&output)["error"]["code"], "usage");
}

#[test]
fn json_keeps_relay_code_status_and_retry_metadata() {
    let mock = Mock::start(|_, _| {
        let mut answer = err(429, "rate_limited", "Try later.");
        answer.headers.push(("Retry-After".into(), "17".into()));
        answer
    });
    let output = Cli::new().member(&mock.url).run(&["--json", "me"], None);
    assert_eq!(code(&output), 4);
    let result = document(&output);
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "rate_limited");
    assert_eq!(result["error"]["status"], 429);
    assert_eq!(result["error"]["retryable"], true);
    assert_eq!(result["error"]["retry_after"], 17);
}

#[test]
fn json_rejects_one_time_secret_creation_before_the_request() {
    for args in [
        vec!["invite", "--json"],
        vec!["--json", "agent", "create", "ci"],
        vec!["device", "add", "--json"],
        vec!["--team", "t_abcdefgh23", "device", "add", "--json"],
    ] {
        let mock = Mock::start(|_, _| panic!("JSON mode must not issue a one-time secret"));
        let output = Cli::new().member(&mock.url).run(&args, None);
        assert_eq!(code(&output), 2);
        assert_eq!(document(&output)["error"]["code"], "usage");
        assert!(mock.requests().is_empty());
        assert!(!text(&output.stdout).contains("apassy_"));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn json_run_keeps_child_exit_and_delimiter_arguments() {
    let mock = Mock::start(|_, _| ok(run_view(5, "ready", Some(json!({})))));
    let output = Cli::new().agent(&mock.url).run(
        &[
            "--json",
            "run",
            "--items",
            "1",
            "--purpose",
            "test",
            "--",
            "/bin/sh",
            "-c",
            "printf child-secret-output; printf child-secret-error >&2; exit 7",
            "--json",
        ],
        None,
    );
    assert_eq!(code(&output), 7);
    assert_eq!(document(&output)["result"]["child_exit_code"], 7);
    assert!(!text(&output.stdout).contains("child-secret"));
    assert!(!text(&output.stderr).contains("child-secret"));
}

#[test]
fn help_leads_with_device_setup_and_has_a_compatibility_section() {
    let output = Cli::new().run(&["help"], None);
    let help = text(&output.stdout);
    assert!(help.find("create --relay").unwrap() < help.find("init --relay").unwrap());
    assert!(help.contains("Compatibility"));
    assert!(help.contains("--json"));
}

#[test]
fn json_rejects_streaming_wrappers_and_duplicate_flags_as_one_error_document() {
    for args in [
        vec!["--json", "mcp"],
        vec!["--json", "host"],
        vec!["--json", "--json", "me"],
    ] {
        let output = Cli::new().run(&args, None);
        assert_eq!(code(&output), 2);
        assert_eq!(document(&output)["error"]["code"], "usage");
    }
}

#[test]
fn json_decision_output_never_serializes_a_session_environment() {
    let mock = Mock::start(|_, _| ok(run_view(5, "ready", Some(json!({"SYNTHETIC_KEY":CANARY})))));
    let output = Cli::new()
        .member(&mock.url)
        .run(&["--json", "deny", "5"], None);
    assert_eq!(code(&output), 0);
    assert_eq!(document(&output)["result"]["run_id"], 5);
    assert!(!text(&output.stdout).contains(CANARY));
    assert!(!text(&output.stderr).contains(CANARY));
}

#[test]
fn json_redacts_reflected_credentials_in_metadata_and_errors() {
    for refused in [false, true] {
        let mock = Mock::start(move |_, _| {
            if refused {
                err(403, "refused", MEMBER_TOKEN)
            } else {
                ok(
                    json!({"team":"T","kind":"member","member_id":1,"member_name":MEMBER_TOKEN,"role":"owner"}),
                )
            }
        });
        let output = Cli::new().member(&mock.url).run(&["--json", "me"], None);
        assert!(!text(&output.stdout).contains(MEMBER_TOKEN));
        assert!(!text(&output.stderr).contains(MEMBER_TOKEN));
        assert!(text(&output.stdout).contains("[apassy:token]"));
    }
}
