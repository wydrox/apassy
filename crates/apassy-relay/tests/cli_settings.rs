//! The settings file (modes, location) and the precedence of the environment variables.

mod cli_support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use cli_support::*;
use serde_json::{Value, json};

fn me_member() -> Value {
    json!({"team": "T", "team_id": "t_abcdefgh23", "kind": "member", "member_id": 1, "member_name": "olga", "role": "owner"})
}

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn write_settings(cli: &Cli, value: Value) -> Vec<u8> {
    let path = cli.settings_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    bytes
}

fn selected_settings(cli: &Cli, relay: &str) {
    write_settings(
        cli,
        json!({
            "version": 2, "current": "t_abcdefgh23",
            "teams": {"t_abcdefgh23": {"relay_url": relay, "member_token": MEMBER_TOKEN}}
        }),
    );
}

#[test]
fn selected_team_refuses_a_token_for_another_team_before_any_request() {
    for selector in [None, Some("flag"), Some("env")] {
        let mock = Mock::always(200, me_member());
        let cli = Cli::new();
        selected_settings(&cli, &mock.url);
        let token = format!("apassy_mbr_t_bcdefgh234_{}", "a".repeat(64));
        let mut cli = cli.with("APASSY_TEAM_TOKEN", &token);
        let args = if selector == Some("flag") {
            vec!["me", "--team", "t_abcdefgh23"]
        } else {
            vec!["me"]
        };
        if selector == Some("env") {
            cli = cli.with("APASSY_TEAM", "t_abcdefgh23");
        }
        let output = cli.run(&args, None);
        assert_eq!(
            code(&output),
            2,
            "selector={selector:?}: {}",
            text(&output.stderr)
        );
        assert!(mock.requests().is_empty());
        assert!(!text(&output.stderr).contains(&token));
    }
}

#[test]
fn an_explicit_team_refuses_a_team_less_environment_token() {
    for flag in [true, false] {
        let mock = Mock::always(200, me_member());
        let cli = Cli::new();
        selected_settings(&cli, &mock.url);
        let mut cli = cli.with("APASSY_TEAM_TOKEN", MEMBER_TOKEN);
        let args = if flag {
            vec!["me", "--team", "t_abcdefgh23"]
        } else {
            vec!["me"]
        };
        if !flag {
            cli = cli.with("APASSY_TEAM", "t_abcdefgh23");
        }
        let output = cli.run(&args, None);
        assert_eq!(code(&output), 2, "{}", text(&output.stderr));
        assert!(mock.requests().is_empty());
    }
}

#[test]
fn selected_team_refuses_a_different_environment_relay_before_any_request() {
    let saved = Mock::always(200, me_member());
    let other = Mock::always(200, me_member());
    let cli = Cli::new();
    selected_settings(&cli, &saved.url);
    let output = cli.with("APASSY_RELAY_URL", &other.url).run(&["me"], None);
    assert_eq!(code(&output), 2, "{}", text(&output.stderr));
    assert!(saved.requests().is_empty());
    assert!(other.requests().is_empty());
}

#[test]
fn version_one_team_scoped_token_migrates_without_a_network_request() {
    let mock = Mock::always(200, me_member());
    let cli = Cli::new();
    let token = format!("apassy_mbr_t_abcdefgh23_{}", "a".repeat(64));
    write_settings(
        &cli,
        json!({"version":1,"relay_url":mock.url,"member_token":token}),
    );
    let output = cli.run(&["team", "list"], None);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("t_abcdefgh23"));
    assert!(mock.requests().is_empty());
    let migrated: Value =
        serde_json::from_slice(&std::fs::read(cli.settings_file()).unwrap()).unwrap();
    assert_eq!(migrated["version"], 2);
    assert_eq!(migrated["teams"]["t_abcdefgh23"]["member_token"], token);

    // The default selection must use the offline migration, too.
    let me = cli.run(&["me"], None);
    assert_eq!(code(&me), 0, "{}", text(&me.stderr));
    assert_eq!(mock.requests().len(), 1);
    assert_eq!(
        mock.requests()[0].header("authorization"),
        Some(format!("Bearer {token}").as_str())
    );
}

#[test]
fn failed_version_one_migration_archives_exact_bytes_and_continues_with_empty_v2() {
    for relay_result in ["network", "401", "missing_team", "invalid_url", "bad_json"] {
        let mock = Mock::start(move |_, _| match relay_result {
            "401" => err(401, "unauthenticated", "Refused."),
            "bad_json" => raw(200, "not json"),
            _ => ok(
                json!({"team":"T","kind":"member","member_id":1,"member_name":"olga","role":"owner"}),
            ),
        });
        let relay = match relay_result {
            "network" => dead_url(),
            "invalid_url" => "http://relay.example".to_owned(),
            _ => mock.url.clone(),
        };
        let cli = Cli::new();
        let original = write_settings(
            &cli,
            json!({"version":1,"relay_url":relay,"member_token":MEMBER_TOKEN}),
        );
        let inode = std::fs::metadata(cli.settings_file()).unwrap().ino();
        std::fs::set_permissions(cli.settings_file(), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let dir = cli.settings_file().parent().unwrap().to_owned();
        let previous = dir.join("settings.v1.json");
        let numbered = relay_result == "network";
        if numbered {
            std::fs::write(&previous, b"previous archive").unwrap();
        }
        let output = cli.run(&["team", "list"], None);
        assert_eq!(
            code(&output),
            0,
            "case={relay_result}: {}",
            text(&output.stderr)
        );
        let archive = dir.join(if numbered {
            "settings.v1.1.json"
        } else {
            "settings.v1.json"
        });
        assert_eq!(std::fs::read(&archive).unwrap(), original);
        assert_eq!(std::fs::metadata(&archive).unwrap().ino(), inode);
        assert_eq!(mode(&archive), 0o600);
        if numbered {
            assert_eq!(std::fs::read(previous).unwrap(), b"previous archive");
        }
        let settings: Value =
            serde_json::from_slice(&std::fs::read(cli.settings_file()).unwrap()).unwrap();
        assert_eq!(settings["version"], 2);
        assert_eq!(settings["teams"], json!({}));
        assert!(settings["current"].is_null());
        let stderr = text(&output.stderr);
        assert_eq!(stderr.matches("warning:").count(), 1);
        assert!(stderr.contains(archive.to_str().unwrap()));
        assert!(!stderr.contains(MEMBER_TOKEN));
        let again = cli.run(&["team", "list"], None);
        assert_eq!(code(&again), 0);
        assert!(text(&again.stderr).is_empty());
        assert!(!dir.join("settings.v1.2.json").exists());
    }
}

#[test]
fn matching_environment_team_and_normalized_relay_can_override_a_selected_entry() {
    for flag in [true, false] {
        let mock = Mock::always(200, me_member());
        let cli = Cli::new();
        selected_settings(&cli, &format!("{}/", mock.url));
        let token = format!("apassy_mbr_t_abcdefgh23_{}", "b".repeat(64));
        let cli = cli
            .with("APASSY_TEAM_TOKEN", &token)
            .with("APASSY_RELAY_URL", &format!(" {}/ ", mock.url));
        let args = if flag {
            vec!["me", "--team", "t_abcdefgh23"]
        } else {
            vec!["me"]
        };
        let output = cli.run(&args, None);
        assert_eq!(code(&output), 0, "{}", text(&output.stderr));
        assert_eq!(mock.requests().len(), 1);
        assert_eq!(
            mock.requests()[0].header("authorization"),
            Some(format!("Bearer {token}").as_str())
        );
    }
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
    assert_eq!(code(&cli.run(&["team", "use", "t_abcdefgh23"], None)), 0);
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
fn variables_supply_credentials_when_no_team_is_selected() {
    let from_file = Mock::always(200, me_member());
    let from_env = Mock::always(200, me_member());
    let cli = Cli::new();
    write_settings(
        &cli,
        json!({
            "version": 2, "current": null,
            "teams": {"t_abcdefgh23": {"relay_url": from_file.url, "member_token": MEMBER_TOKEN}}
        }),
    );
    let other = "apassy_mbr_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let cli = cli
        .with("APASSY_RELAY_URL", &from_env.url)
        .with("APASSY_TEAM_TOKEN", other);
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    assert!(from_file.requests().is_empty());
    let seen = from_env.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {other}").as_str())
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
    assert_eq!(code(&cli.run(&["team", "use", "t_abcdefgh23"], None)), 0);
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
    assert_eq!(code(&cli.run(&["team", "use", "t_abcdefgh23"], None)), 0);
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
fn version_one_identifies_the_team_and_saves_v2_on_first_load() {
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
    let migrated = std::fs::read(&path).unwrap();
    assert_ne!(migrated, legacy);
    assert_eq!(
        serde_json::from_slice::<Value>(&migrated).unwrap()["version"],
        2
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
    assert_eq!(std::fs::read(&path).unwrap(), migrated);
    assert_eq!(
        mock.requests().len(),
        2,
        "only one migration lookup and one me request"
    );

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
