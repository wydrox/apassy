//! The settings file (modes, location) and the precedence of the environment variables.

mod cli_support;

use std::os::unix::fs::PermissionsExt;

use cli_support::*;
use serde_json::{Value, json};

fn me_member() -> Value {
    json!({"team": "T", "kind": "member", "member_id": 1, "member_name": "olga", "role": "owner"})
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_checks_the_token_and_writes_the_file_with_private_modes() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    let output = cli.run(
        &["init", "--relay", &format!("{}/", mock.url)],
        Some(&format!("{MEMBER_TOKEN}\n")),
    );
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let seen = mock.requests();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("GET", "/v1/me")
    );
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {MEMBER_TOKEN}").as_str())
    );
    let file = cli.settings_file();
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(file.parent().unwrap()), 0o700);
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        saved["relay_url"],
        mock.url.as_str(),
        "the trailing slash is removed"
    );
    assert_eq!(saved["member_token"], MEMBER_TOKEN);
    assert!(!text(&output.stdout).contains(MEMBER_TOKEN));
    assert!(!text(&output.stderr).contains(MEMBER_TOKEN));
    assert!(text(&output.stdout).contains("olga"));
}

#[test]
fn the_file_is_found_under_home_when_xdg_is_not_set() {
    let mock = Mock::always(200, me_member());
    let mut cli = Cli::new();
    cli.xdg = false;
    let output = cli.run(&["init", "--relay", &mock.url], Some(MEMBER_TOKEN));
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let file = cli.home.path().join(".config/apassy-team/settings.json");
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(file.parent().unwrap()), 0o700);
}

#[test]
fn later_commands_read_the_saved_settings() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    let init = cli.run(&["init", "--relay", &mock.url], Some(MEMBER_TOKEN));
    assert_eq!(code(&init), 0);
    let me = cli.run(&["me"], None);
    assert_eq!(code(&me), 0, "{}", text(&me.stderr));
    let seen = mock.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[1].header("authorization"),
        Some(format!("Bearer {MEMBER_TOKEN}").as_str())
    );
}

#[test]
fn variables_win_over_the_file() {
    let from_file = Mock::always(200, me_member());
    let from_env = Mock::always(200, me_member());
    let cli = Cli::new();
    assert_eq!(
        code(&cli.run(&["init", "--relay", &from_file.url], Some(MEMBER_TOKEN))),
        0
    );
    let other = "apassy_mbr_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let cli = cli
        .with("APASSY_RELAY_URL", &from_env.url)
        .with("APASSY_TEAM_TOKEN", other);
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    assert_eq!(
        from_file.requests().len(),
        1,
        "only init went to the file's relay"
    );
    let seen = from_env.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {other}").as_str())
    );
    // A partial override: the URL from the variable, the token from the file.
    let cli = Cli {
        home: cli.home,
        env: vec![("APASSY_RELAY_URL".into(), from_env.url.clone())],
        xdg: true,
    };
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let seen = from_env.requests();
    assert_eq!(
        seen[1].header("authorization"),
        Some(format!("Bearer {MEMBER_TOKEN}").as_str())
    );
}

#[test]
fn an_empty_variable_counts_as_unset() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    assert_eq!(
        code(&cli.run(&["init", "--relay", &mock.url], Some(MEMBER_TOKEN))),
        0
    );
    let cli = cli
        .with("APASSY_RELAY_URL", "")
        .with("APASSY_TEAM_TOKEN", "  ");
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
}

#[test]
fn init_with_a_refused_token_writes_nothing() {
    let mock = Mock::start(|_, _| {
        err(
            401,
            "unauthenticated",
            "The token is missing, unknown, or revoked.",
        )
    });
    let cli = Cli::new();
    let output = cli.run(&["init", "--relay", &mock.url], Some(MEMBER_TOKEN));
    assert_eq!(code(&output), 4);
    assert!(text(&output.stderr).contains("unauthenticated"));
    assert!(!cli.settings_file().exists());
}

#[test]
fn init_refuses_an_agent_token() {
    let mock = Mock::always(
        200,
        json!({"team": "T", "kind": "agent", "member_id": 1, "member_name": "olga",
               "role": "member", "agent_id": 2, "agent_name": "ci"}),
    );
    let cli = Cli::new();
    let output = cli.run(&["init", "--relay", &mock.url], Some(AGENT_TOKEN));
    assert_eq!(code(&output), 2);
    assert!(!cli.settings_file().exists());
}

#[test]
fn init_and_join_need_a_pipe_and_a_relay_option() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    assert_eq!(
        code(&cli.run(&["init"], Some(MEMBER_TOKEN))),
        2,
        "--relay is required"
    );
    assert_eq!(
        code(&cli.run(&["init", "--relay", &mock.url], None)),
        2,
        "no stdin"
    );
    assert_eq!(
        code(&cli.run(&["join", "--relay", &mock.url], Some("code"))),
        2,
        "--name is required"
    );
    assert!(mock.requests().is_empty());
}

#[test]
fn join_sends_the_code_without_a_bearer_and_saves_the_new_token() {
    let code_text = "apassy_inv_3333333333333333333333333333333333333333333333333333333333333333";
    let mock = Mock::always(200, json!({"id": 5, "secret": MEMBER_TOKEN}));
    let cli = Cli::new().with("APASSY_EDGE_SECRET", EDGE);
    let output = cli.run(
        &["join", "--relay", &mock.url, "--name", "bob"],
        Some(&format!("{code_text}\n")),
    );
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let seen = mock.requests();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/v1/join")
    );
    assert_eq!(seen[0].header("authorization"), None);
    assert_eq!(seen[0].header("x-apassy-edge"), Some(EDGE));
    assert_eq!(seen[0].json(), json!({"code": code_text, "name": "bob"}));
    let file = cli.settings_file();
    assert_eq!(mode(&file), 0o600);
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(saved["member_token"], MEMBER_TOKEN);
    let printed = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(!printed.contains(MEMBER_TOKEN) && !printed.contains(code_text));
}

#[test]
fn create_sends_the_team_code_without_a_bearer_and_saves_the_owner_token() {
    let code_text = format!("apassy_tcd_{}", "4".repeat(64));
    let mock = Mock::always(
        200,
        json!({"team_id": "t_abcdefgh23", "member_id": 1, "secret": MEMBER_TOKEN}),
    );
    let cli = Cli::new().with("APASSY_EDGE_SECRET", EDGE);
    let output = cli.run(
        &[
            "create", "--relay", &mock.url, "--team", "Family", "--name", "rafal",
        ],
        Some(&format!("{code_text}\n")),
    );
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    let seen = mock.requests();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/v1/teams")
    );
    assert_eq!(seen[0].header("authorization"), None);
    assert_eq!(seen[0].header("x-apassy-edge"), Some(EDGE));
    assert_eq!(
        seen[0].json(),
        json!({"code": code_text, "team": "Family", "owner": "rafal"})
    );
    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(cli.settings_file()).unwrap()).unwrap();
    assert_eq!(saved["member_token"], MEMBER_TOKEN);
    let printed = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(printed.contains("t_abcdefgh23"), "{printed}");
    assert!(!printed.contains(MEMBER_TOKEN) && !printed.contains(&code_text));
    // A refused code writes nothing.
    let refused = Mock::start(|_, _| err(403, "invite_invalid", "The team code is not valid."));
    let other = Cli::new();
    let output = other.run(
        &[
            "create",
            "--relay",
            &refused.url,
            "--team",
            "Family",
            "--name",
            "rafal",
        ],
        Some(&code_text),
    );
    assert_eq!(code(&output), 4);
    assert!(!other.settings_file().exists());
}

#[test]
fn a_refused_invite_writes_nothing() {
    let mock = Mock::start(|_, _| err(403, "invite_invalid", "The invite code is not valid."));
    let cli = Cli::new();
    let output = cli.run(
        &["join", "--relay", &mock.url, "--name", "bob"],
        Some("apassy_inv_x"),
    );
    assert_eq!(code(&output), 4);
    assert!(!cli.settings_file().exists());
}

#[test]
fn a_loose_file_is_reported_and_init_tightens_it() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    assert_eq!(
        code(&cli.run(&["init", "--relay", &mock.url], Some(MEMBER_TOKEN))),
        0
    );
    let file = cli.settings_file();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 0);
    assert!(text(&output.stderr).contains("readable by others"));
    assert_eq!(
        code(&cli.run(&["init", "--relay", &mock.url], Some(MEMBER_TOKEN))),
        0
    );
    assert_eq!(mode(&file), 0o600);
}

#[test]
fn a_broken_file_is_a_usage_error() {
    let cli = Cli::new();
    std::fs::create_dir_all(cli.settings_file().parent().unwrap()).unwrap();
    std::fs::write(cli.settings_file(), "not json").unwrap();
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).contains("not valid"));
}

#[test]
fn plain_http_is_refused_except_for_loopback() {
    let cli = Cli::new().with("APASSY_TEAM_TOKEN", MEMBER_TOKEN);
    let output = cli
        .with("APASSY_RELAY_URL", "http://relay.example.com")
        .run(&["me"], None);
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).contains("https://"));
}
