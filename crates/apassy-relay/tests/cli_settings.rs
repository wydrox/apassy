//! The settings file (modes, location) and the precedence of the environment variables.

mod cli_support;

use std::os::unix::fs::PermissionsExt;

use cli_support::*;
use serde_json::{Value, json};

fn me_member() -> Value {
    json!({"team": "T", "team_id": "t_abcdefgh23", "kind": "member", "member_id": 1, "member_name": "olga", "role": "owner"})
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
        saved["teams"]["t_abcdefgh23"]["relay_url"],
        mock.url.as_str(),
        "the trailing slash is removed"
    );
    assert_eq!(saved["teams"]["t_abcdefgh23"]["member_token"], MEMBER_TOKEN);
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
fn a_refused_invite_keeps_the_device_key_for_a_retry() {
    let mock = Mock::start(|_, _| err(403, "invite_invalid", "The invite code is not valid."));
    let cli = Cli::new();
    let output = cli.run(
        &["join", "--relay", &mock.url, "--name", "bob"],
        Some(&format!("apassy_inv_t_abcdefgh23_{}", "3".repeat(64))),
    );
    assert_eq!(code(&output), 4);
    let saved: Value =
        serde_json::from_slice(&std::fs::read(cli.settings_file()).unwrap()).unwrap();
    let entry = &saved["teams"]["t_abcdefgh23"];
    assert!(entry["member_token"].is_null());
    assert!(entry["device_id"].is_null());
    let key = cli
        .settings_file()
        .parent()
        .unwrap()
        .join("device-t_abcdefgh23.key");
    assert_eq!(mode(&key), 0o600);
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

#[test]
fn version_one_identifies_the_team_and_migrates_only_on_the_next_save() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    let path = cli.settings_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let legacy = serde_json::to_vec(&json!({
        "version": 1, "relay_url": mock.url, "member_token": MEMBER_TOKEN,
    }))
    .unwrap();
    std::fs::write(&path, &legacy).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let listed = cli.run(&["team", "list"], None);
    assert_eq!(code(&listed), 0, "{}", text(&listed.stderr));
    assert!(text(&listed.stdout).contains("t_abcdefgh23"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        legacy,
        "a read must not save the migration"
    );
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        (requests[0].method.as_str(), requests[0].url.as_str()),
        ("GET", "/v1/me")
    );
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {MEMBER_TOKEN}").as_str())
    );

    let selected = cli.run(&["me", "--team", "t_abcdefgh23"], None);
    assert_eq!(code(&selected), 0, "{}", text(&selected.stderr));
    assert_eq!(std::fs::read(&path).unwrap(), legacy);

    let saved = cli.run(&["team", "use", "t_abcdefgh23"], None);
    assert_eq!(code(&saved), 0, "{}", text(&saved.stderr));
    let settings: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(settings["version"], 2);
    assert_eq!(settings["current"], "t_abcdefgh23");
    assert_eq!(settings["teams"].as_object().unwrap().len(), 1);
    let entry = &settings["teams"]["t_abcdefgh23"];
    assert_eq!(entry["relay_url"], mock.url);
    assert_eq!(entry["team"], "T");
    assert_eq!(entry["member"], "olga");
    assert_eq!(entry["member_token"], MEMBER_TOKEN);
    assert!(entry["device_id"].is_null());
    assert!(settings.get("relay_url").is_none());
    assert!(settings.get("member_token").is_none());
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
}

#[test]
fn an_unknown_settings_version_is_refused_without_a_request_or_write() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    let path = cli.settings_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec(&json!({
        "version": 9, "relay_url": mock.url, "member_token": MEMBER_TOKEN,
    }))
    .unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).contains("version is not supported"));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(mock.requests().is_empty());
}

#[test]
fn init_never_saves_an_access_token_supplied_on_stdin() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    let access = format!("apassy_acc_t_abcdefgh23_{}", "a".repeat(64));
    let output = cli.run(&["init", "--relay", &mock.url], Some(&access));
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).contains("Access tokens cannot be saved"));
    assert!(mock.requests().is_empty());
    assert!(!cli.settings_file().exists());
    assert!(!text(&output.stderr).contains(&access));
    assert!(!text(&output.stdout).contains(&access));
}
