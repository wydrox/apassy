//! `apassy-team mcp`: the stdio adapter forwards each line to POST /mcp.

mod cli_support;

use cli_support::*;
use serde_json::{Value, json};

fn rpc_ok(id: Value) -> Answer {
    raw(
        200,
        &json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}).to_string(),
    )
}

/// A relay for `/mcp`: a message with an id gets a result, a notification gets 202.
fn relay() -> Mock {
    Mock::start(|request, _| match request.json().get("id") {
        Some(id) => rpc_ok(id.clone()),
        None => raw(202, ""),
    })
}

fn lines(output: &std::process::Output) -> Vec<Value> {
    text(&output.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each output line is JSON"))
        .collect()
}

#[test]
fn a_request_is_forwarded_with_the_token_and_answered_on_one_line() {
    let mock = relay();
    let cli = Cli::new().agent(&mock.url).with("APASSY_EDGE_SECRET", EDGE);
    // Spaces and key order in the line are kept as sent.
    let line = r#"{"jsonrpc":"2.0",  "id": 1, "method":"tools/list"}"#;
    let output = cli.run(&["mcp"], Some(&format!("{line}\n")));
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let seen = mock.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/mcp")
    );
    assert_eq!(seen[0].body, line);
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {AGENT_TOKEN}").as_str())
    );
    assert_eq!(
        seen[0].header("accept"),
        Some("application/json, text/event-stream")
    );
    assert_eq!(seen[0].header("content-type"), Some("application/json"));
    assert_eq!(seen[0].header("x-apassy-edge"), Some(EDGE));
    let out = text(&output.stdout);
    assert_eq!(out.lines().count(), 1);
    assert_eq!(lines(&output)[0]["result"], json!({"tools": []}));
    assert_eq!(lines(&output)[0]["id"], 1);
    assert!(!text(&output.stderr).contains(AGENT_TOKEN));
}

#[test]
fn a_notification_gets_no_output_and_the_next_request_is_still_answered() {
    let mock = relay();
    let cli = Cli::new().agent(&mock.url);
    let input = concat!(
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n\n   \n",
        r#"{"jsonrpc":"2.0","id":"a","method":"ping"}"#,
        "\n",
    );
    let output = cli.run(&["mcp"], Some(input));
    assert_eq!(code(&output), 0);
    let answers = lines(&output);
    assert_eq!(
        answers.len(),
        1,
        "the notification and the blank lines wrote nothing"
    );
    assert_eq!(answers[0]["id"], "a");
    assert_eq!(mock.requests().len(), 2, "blank lines are not forwarded");
}

#[test]
fn messages_are_answered_in_order() {
    let mock = relay();
    let cli = Cli::new().agent(&mock.url);
    let input: String = (1..=5)
        .map(|i| format!("{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"ping\"}}\n"))
        .collect();
    let output = cli.run(&["mcp"], Some(&input));
    let ids: Vec<Value> = lines(&output).iter().map(|l| l["id"].clone()).collect();
    assert_eq!(ids, vec![json!(1), json!(2), json!(3), json!(4), json!(5)]);
}

#[test]
fn a_relay_that_is_down_gives_a_jsonrpc_error_with_the_request_id() {
    let cli = Cli::new().agent(&dead_url());
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":42,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
    );
    let output = cli.run(&["mcp"], Some(input));
    assert_eq!(code(&output), 0);
    let answers = lines(&output);
    assert_eq!(answers.len(), 1, "a failed notification writes nothing");
    assert_eq!(answers[0]["jsonrpc"], "2.0");
    assert_eq!(answers[0]["id"], 42);
    assert_eq!(answers[0]["error"]["code"], -32000);
    let message = answers[0]["error"]["message"].as_str().unwrap();
    assert!(message.starts_with("relay: unreachable: "), "{message}");
    assert!(!text(&output.stdout).contains(AGENT_TOKEN));
    assert!(!text(&output.stderr).contains(AGENT_TOKEN));
}

#[test]
fn an_envelope_error_from_the_relay_becomes_a_jsonrpc_error() {
    let mock = Mock::start(|_, _| {
        err(
            401,
            "unauthenticated",
            "The token is missing, unknown, or revoked.",
        )
    });
    let cli = Cli::new().agent(&mock.url);
    let output = cli.run(
        &["mcp"],
        Some("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\"}\n"),
    );
    let answers = lines(&output);
    assert_eq!(answers[0]["id"], 9);
    assert_eq!(answers[0]["error"]["code"], -32000);
    assert_eq!(
        answers[0]["error"]["message"],
        "relay: unauthenticated: The token is missing, unknown, or revoked."
    );
}

#[test]
fn a_page_that_is_not_jsonrpc_becomes_an_error_with_the_status() {
    let mock = Mock::start(|_, _| raw(530, "<html>tunnel down</html>"));
    let output = Cli::new().agent(&mock.url).run(
        &["mcp"],
        Some("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n"),
    );
    let answers = lines(&output);
    assert_eq!(answers[0]["id"], 3);
    assert!(
        answers[0]["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("relay: http_530: ")
    );
}

#[test]
fn the_relay_answers_for_bad_json_and_the_adapter_passes_it_on() {
    // The adapter does not judge a line: the relay says -32700 or -32600 itself.
    let mock = Mock::start(|request, _| {
        let code = if request.body.trim_start().starts_with('[') {
            -32600
        } else {
            -32700
        };
        raw(
            200,
            &json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": "x"}})
                .to_string(),
        )
    });
    let output = Cli::new()
        .agent(&mock.url)
        .run(&["mcp"], Some("not json\n[1]\n"));
    let answers = lines(&output);
    assert_eq!(answers[0]["error"]["code"], -32700);
    assert_eq!(answers[1]["error"]["code"], -32600);
    let seen = mock.requests();
    assert_eq!(seen[0].body, "not json");
}

#[test]
fn a_line_over_1_mib_is_refused_without_a_request() {
    let mock = relay();
    let cli = Cli::new().agent(&mock.url);
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\",\"params\":\"{}\"}}",
        "a".repeat(1024 * 1024)
    );
    let input = format!("{huge}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}}\n");
    let output = cli.run(&["mcp"], Some(&input));
    assert_eq!(code(&output), 0);
    let answers = lines(&output);
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0]["error"]["code"], -32600);
    assert_eq!(answers[0]["id"], Value::Null);
    assert_eq!(answers[1]["id"], 2, "the adapter goes on after a long line");
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn a_last_line_without_a_newline_is_still_forwarded() {
    let mock = relay();
    let output = Cli::new().agent(&mock.url).run(
        &["mcp"],
        Some("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"),
    );
    assert_eq!(lines(&output).len(), 1);
}

#[test]
fn mcp_needs_the_relay_url_and_the_agent_token() {
    let output = Cli::new().run(&["mcp"], Some(""));
    assert_eq!(code(&output), 2);
    let output = Cli::new()
        .with("APASSY_RELAY_URL", "http://127.0.0.1:1")
        .with("APASSY_TEAM_TOKEN", MEMBER_TOKEN)
        .run(&["mcp"], Some(""));
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).contains("APASSY_TOKEN"));
}
