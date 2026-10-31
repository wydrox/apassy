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
fn json_emits_one_time_secrets_once_and_never_on_stderr() {
    for (args, field, secret) in [
        (
            vec!["invite", "--json"],
            "url",
            "apassy_inv_synthetic_json_once",
        ),
        (
            vec!["--json", "agent", "create", "ci"],
            "token",
            "apassy_agt_synthetic_json_once",
        ),
        (
            vec!["device", "add", "--json"],
            "code",
            "apassy_lnk_synthetic_json_once",
        ),
    ] {
        let mock = Mock::start(move |_, _| ok(json!({"id":3,"secret":secret,"expires_at":100})));
        let output = Cli::new().member(&mock.url).run(&args, None);
        assert_eq!(code(&output), 0, "{}", text(&output.stderr));
        assert!(
            document(&output)["result"][field]
                .as_str()
                .unwrap()
                .ends_with(secret)
        );
        assert_eq!(text(&output.stdout).matches(secret).count(), 1);
        assert!(!text(&output.stderr).contains(secret));
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
            "printf child-output; exit 7",
            "--json",
        ],
        None,
    );
    assert_eq!(code(&output), 7);
    assert_eq!(document(&output)["result"]["child_exit_code"], 7);
    assert!(text(&output.stderr).contains("child-output"));
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
