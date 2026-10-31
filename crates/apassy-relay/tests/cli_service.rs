//! Service selectors use saved teams. No service manager or login Keychain is used.
mod cli_support;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use apassy_relay::cli::host::HostOptions;
use apassy_relay::cli::service::{generate_plist, generate_unit};
use apassy_relay::ids::TeamId;
use cli_support::{Cli, Mock, code, err, ok, text};
use serde_json::json;

const TEAM_A: &str = "t_abcdefgh23";
const TEAM_B: &str = "t_abcdefgh24";

fn save_teams(cli: &Cli, relay_a: &str, relay_b: &str) {
    let path = cli.settings_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        json!({"version":2,"current":TEAM_A,"teams":{
            TEAM_A: {"relay_url":relay_a,"member_token":"saved-owner-a"},
            TEAM_B: {"relay_url":relay_b,"member_token":"saved-owner-b"}
        }})
        .to_string(),
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn deny_owner() -> Mock {
    Mock::start(|_, _| err(403, "service_test_stop", "Stop before the service manager."))
}

#[test]
fn generated_team_a_host_keeps_team_a_after_team_b_becomes_current() {
    let relay_a = deny_owner();
    let relay_b = deny_owner();
    let cli = Cli::new();
    save_teams(&cli, &relay_a.url, &relay_b.url);
    let team = TeamId::parse(TEAM_A).unwrap();
    let plist = generate_plist(
        Path::new("/exe"),
        &team,
        HostOptions::default(),
        Path::new("/log"),
        None,
    )
    .unwrap();
    let unit = generate_unit(Path::new("/exe"), &team, HostOptions::default(), None).unwrap();
    let plist_args: Vec<_> = plist
        .split("<key>ProgramArguments</key>")
        .nth(1)
        .unwrap()
        .split("</array>")
        .next()
        .unwrap()
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("<string>")
                .and_then(|line| line.strip_suffix("</string>"))
        })
        .skip(1)
        .collect();
    let unit_args: Vec<_> = unit
        .lines()
        .find_map(|line| line.strip_prefix("ExecStart="))
        .unwrap()
        .split_whitespace()
        .skip(1)
        .collect();
    let output = cli.run(&["team", "use", TEAM_B], None);
    assert_eq!(code(&output), 0, "{}", text(&output.stderr));
    for arguments in [plist_args, unit_args] {
        let output = cli.run(&arguments, None);
        assert_eq!(code(&output), 4, "{}", text(&output.stderr));
        assert!(text(&output.stderr).contains("service_test_stop"));
    }
    let requests = relay_a.requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.url, "/v1/me");
        assert_eq!(
            request.header("Authorization"),
            Some("Bearer saved-owner-a")
        );
    }
    assert!(relay_b.requests().is_empty());
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(cli.settings_file()).unwrap()).unwrap();
    assert_eq!(saved["current"], TEAM_B);
}

#[test]
fn host_install_checks_the_explicit_saved_team_when_another_team_is_current() {
    let relay_a = deny_owner();
    let relay_b = deny_owner();
    let cli = Cli::new();
    save_teams(&cli, &relay_a.url, &relay_b.url);
    assert_eq!(code(&cli.run(&["team", "use", TEAM_B], None)), 0);
    let output = cli.run(&["--team", TEAM_A, "host", "install"], None);
    assert_eq!(code(&output), 4, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("service_test_stop"));
    let requests = relay_a.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url, "/v1/me");
    assert_eq!(
        requests[0].header("Authorization"),
        Some("Bearer saved-owner-a")
    );
    assert!(relay_b.requests().is_empty());
}

#[test]
fn legacy_host_install_saves_the_resolved_team_before_service_start() {
    let relay = Mock::start(|_, index| {
        if index == 0 {
            ok(json!({"team":"Team A","team_id":TEAM_A,"kind":"member",
                "member_id":1,"member_name":"owner","role":"owner"}))
        } else {
            err(403, "service_test_stop", "Stop before the service manager.")
        }
    });
    let cli = Cli::new();
    let path = cli.settings_file();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        json!({"relay_url":relay.url,"member_token":"saved-owner-a"}).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = cli.run(&["host", "install"], None);
    assert_eq!(code(&output), 4, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("service_test_stop"));
    let requests = relay.requests();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.url, "/v1/me");
        assert_eq!(
            request.header("Authorization"),
            Some("Bearer saved-owner-a")
        );
    }
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(saved["version"], 2);
    assert_eq!(saved["current"], TEAM_A);
    assert_eq!(saved["teams"][TEAM_A]["relay_url"], relay.url);
    assert_eq!(saved["teams"][TEAM_A]["member_token"], "saved-owner-a");
}

#[test]
fn two_teams_get_distinct_host_services_and_logs() {
    let a = TeamId::parse(TEAM_A).unwrap();
    let b = TeamId::parse(TEAM_B).unwrap();
    let plist = |team| {
        generate_plist(
            Path::new("/exe"),
            team,
            HostOptions::default(),
            Path::new("/log"),
            None,
        )
        .unwrap()
    };
    let label = |text: String| {
        text.split("<key>Label</key>")
            .nth(1)
            .unwrap()
            .split("</string>")
            .next()
            .unwrap()
            .to_string()
    };
    assert_ne!(
        label(plist(&a)),
        label(plist(&b)),
        "installing B cannot replace A"
    );
    let unit = |team| generate_unit(Path::new("/exe"), team, HostOptions::default(), None).unwrap();
    assert!(unit(&a).contains(&format!("service-{TEAM_A}.log")));
    assert!(unit(&b).contains(&format!("service-{TEAM_B}.log")));
}

#[cfg(target_os = "linux")]
#[test]
fn install_migrates_team_a_then_installs_and_removes_team_b_without_replacing_a() {
    let owner = || {
        Mock::start(|_, _| {
            ok(json!({"team":"Team","kind":"member",
        "member_id":1,"member_name":"owner","role":"owner"}))
        })
    };
    let a = owner();
    let b = owner();
    let cli = Cli::new();
    let bin = cli.home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let manager = bin.join("systemctl");
    std::fs::write(&manager,"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SERVICE_COMMANDS\"\ncase \"$*\" in *is-active*) echo active;; *show*) echo LoadState=loaded;; esac\n").unwrap();
    std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();
    let calls = cli.home.path().join("service-commands");
    let cli = cli
        .with("PATH", &format!("{}:/usr/bin:/bin", bin.display()))
        .with("SERVICE_COMMANDS", calls.to_str().unwrap());
    save_teams(&cli, &a.url, &b.url);
    let run = |args: &[&str]| {
        let output = cli.run(args, None);
        assert_eq!(code(&output), 0, "{}", text(&output.stderr));
        output
    };
    run(&[
        "--team",
        TEAM_A,
        "host",
        "install",
        "--ask-all",
        "--auto-limit",
        "7",
    ]);
    let units = cli.config_dir().join("systemd/user");
    let path_a = units.join(format!("apassy-team-host-{TEAM_A}.service"));
    let path_b = units.join(format!("apassy-team-host-{TEAM_B}.service"));
    let original = std::fs::read_to_string(&path_a).unwrap();
    let legacy = units.join("apassy-team-host.service");
    std::fs::write(
        &legacy,
        original.replace(&format!("service-{TEAM_A}.log"), "service.log"),
    )
    .unwrap();
    std::fs::remove_file(&path_a).unwrap();
    run(&["--team", TEAM_B, "host", "install"]);
    assert_eq!(std::fs::read_to_string(&path_a).unwrap(), original);
    assert!(path_b.exists());
    assert!(!legacy.exists());
    let output = run(&["--team", TEAM_A, "host", "status", "--json"]);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["result"]["service"],
        format!("apassy-team-host-{TEAM_A}.service")
    );
    // Removing saved credentials must not strand an installed service.
    std::fs::remove_file(cli.settings_file()).unwrap();
    run(&["--team", TEAM_B, "host", "uninstall"]);
    assert_eq!(
        a.requests().len(),
        1,
        "status/removal never contact the relay"
    );
    assert_eq!(
        b.requests().len(),
        1,
        "status/removal never contact the relay"
    );
    assert!(path_a.exists());
    assert!(!path_b.exists());
    let commands = std::fs::read_to_string(calls).unwrap();
    assert!(commands.contains("disable --now apassy-team-host.service"));
    assert!(commands.contains(&format!("enable --now apassy-team-host-{TEAM_A}.service")));
}
