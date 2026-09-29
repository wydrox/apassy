//! The team vault: key, file bytes, modes, build flags, restart.

#[path = "common/relay.rs"]
mod relay;

use std::os::unix::fs::PermissionsExt;

use apassy_relay::config::UpstreamOptions;
use apassy_relay::error::codes;
use apassy_relay::secret::SecretString;
use apassy_relay::server::{Relay, store};
use relay::{CANARY, start};
use serde_json::json;

#[test]
fn wrong_key_is_refused() {
    let relay = start(UpstreamOptions::default());
    relay.setup("staging");
    let (mut config, _dir) = relay.stop_keep();
    config.vault_key = SecretString::new("another synthetic vault passphrase".to_string());
    let error = Relay::start(config.clone())
        .err()
        .expect("a wrong key must fail");
    assert!(error.message.contains("key"), "{error}");
    assert!(!error.to_string().contains("passphrase"), "{error}");
    // The right key still opens it.
    config.vault_key = SecretString::new(relay::VAULT_KEY.to_string());
    Relay::start(config)
        .expect("the right key opens the vault")
        .stop();
}

#[test]
fn file_bytes_hold_no_value_and_no_plain_header() {
    let relay = start(UpstreamOptions::default());
    relay.setup("staging");
    let (config, dir) = relay.stop_keep();
    let path = config.vault_path();
    let bytes = std::fs::read(&path).expect("vault file");
    assert!(bytes.len() >= 4096);
    let has = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
    assert!(!has(CANARY), "the value is in the file");
    assert!(!has("SQLite format 3"), "the file is not encrypted");
    assert!(!has("Test Team"), "the team name is in the file");
    assert!(!has("payments"), "a collection name is in the file");
    // No journal or other file is left with a value either.
    for entry in std::fs::read_dir(dir.path().join("data")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().to_string();
        assert_eq!(name, "team.db", "unexpected file {name}");
    }
}

#[test]
fn init_twice_is_refused_and_keeps_the_first_team() {
    let relay = start(UpstreamOptions::default());
    let error =
        Relay::init(&relay.config, "Other Team", "mallory").expect_err("second init must fail");
    assert_eq!(error.code, codes::CONFLICT);
    let me = relay.ok("GET", "/v1/me", &relay.owner_token, None);
    assert_eq!(me["team"], "Test Team");
    assert_eq!(me["member_name"], "owner");
}

#[test]
fn init_checks_its_names() {
    let dir = tempfile::tempdir().unwrap();
    let config = relay::test_config(dir.path(), UpstreamOptions::default());
    assert!(Relay::init(&config, "", "owner").is_err());
    assert!(Relay::init(&config, "Team", "bad name").is_err());
    assert!(Relay::init(&config, "Team", "").is_err());
    assert!(
        !config.vault_path().exists(),
        "no vault after a refused init"
    );
    let token = Relay::init(&config, "Team", "owner.one").expect("init");
    assert!(token.expose().starts_with("apassy_mbr_"));
}

#[test]
fn compile_options_are_checked() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    store::require_build_options(&conn).expect("this build has the flags");
    let mut statement = conn.prepare("PRAGMA compile_options").unwrap();
    let options: Vec<String> = statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(store::build_options_ok(&options));
    let mut bad = options.clone();
    bad.push("ENABLE_LOAD_EXTENSION".to_string());
    assert!(!store::build_options_ok(&bad));
    let mut bad = options.clone();
    bad.push("USE_URI".to_string());
    assert!(!store::build_options_ok(&bad));
    let without: Vec<String> = options
        .into_iter()
        .filter(|o| o != "DEFAULT_LOOKASIDE=0,0")
        .collect();
    assert!(!store::build_options_ok(&without));
}

#[test]
fn file_mode_is_0600_and_dir_mode_is_0700() {
    let relay = start(UpstreamOptions::default());
    let file = std::fs::metadata(relay.config.vault_path()).unwrap();
    assert_eq!(file.permissions().mode() & 0o777, 0o600);
    let dir = std::fs::metadata(&relay.config.data_dir).unwrap();
    assert_eq!(dir.permissions().mode() & 0o777, 0o700);
}

#[test]
fn start_without_a_vault_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let config = relay::test_config(dir.path(), UpstreamOptions::default());
    let error = Relay::start(config).err().expect("no vault");
    assert!(error.message.contains("init"), "{error}");
}

#[test]
fn a_file_that_is_not_a_vault_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = relay::test_config(dir.path(), UpstreamOptions::default());
    std::fs::create_dir_all(&config.data_dir).unwrap();
    std::fs::write(config.vault_path(), vec![7u8; 8192]).unwrap();
    assert!(Relay::start(config).is_err());
}

#[test]
fn data_survives_a_restart_and_sessions_do_not() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let (status, run) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some("check the repo")),
    );
    assert_eq!(status, 200, "{run}");
    assert_eq!(run["result"]["status"], "ready");
    let run_id = run["result"]["run_id"].as_u64().unwrap();
    let relay = relay.restart();
    // The owner token, the items, and the grant are still there.
    let items = relay.ok("GET", "/v1/items", &relay.owner_token, None);
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert!(!items.to_string().contains(CANARY));
    relay.ok("GET", "/v1/access", &team.agent_token, None);
    // The session is gone: the run has ended.
    let run = relay.ok(
        "GET",
        &format!("/v1/runs/{run_id}"),
        &team.agent_token,
        None,
    );
    assert_eq!(run["status"], "ended");
    assert!(run.get("session").is_none());
    // A new run works.
    let (_, run) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some("again")),
    );
    assert_eq!(run["result"]["status"], "ready");
    // The value is still masked in the audit after the restart.
    let request = json!({
        "items": [team.item], "command": ["git", "status"],
        "purpose": format!("value {CANARY}"), "user_request": "x"
    });
    relay.run(&team.agent_token, &request);
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    assert!(!audit.to_string().contains(CANARY));
    assert!(audit.to_string().contains("session_ended"));
}

#[test]
fn health_needs_no_edge_header() {
    let relay = start(UpstreamOptions::default());
    let response = ureq::get(&format!("{}/healthz", relay.url))
        .call()
        .expect("healthz");
    assert_eq!(response.status().as_u16(), 200);
}
