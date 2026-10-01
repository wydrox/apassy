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
    config.master_key = SecretString::new("another synthetic vault passphrase".to_string());
    let error = Relay::start(config.clone())
        .err()
        .expect("a wrong key must fail");
    assert!(error.message.contains("key"), "{error}");
    assert!(!error.to_string().contains("passphrase"), "{error}");
    // The right key still opens it.
    config.master_key = SecretString::new(relay::VAULT_KEY.to_string());
    Relay::start(config)
        .expect("the right key opens the vault")
        .stop();
}

#[test]
fn file_bytes_hold_no_value_and_no_plain_header() {
    let relay = start(UpstreamOptions::default());
    relay.setup("staging");
    let team = relay.team_id.clone();
    let (config, dir) = relay.stop_keep();
    for path in [config.team_path(&team), config.directory_path()] {
        let bytes = std::fs::read(&path).expect("vault file");
        assert!(bytes.len() >= 4096);
        let has = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
        assert!(!has(CANARY), "the value is in {path:?}");
        assert!(!has("SQLite format 3"), "{path:?} is not encrypted");
        assert!(!has("Test Team"), "the team name is in {path:?}");
        assert!(!has("payments"), "a collection name is in {path:?}");
        assert!(!has(team.as_str()), "the team id is in {path:?}");
    }
    // No journal, socket, or other file is left.
    let names = |path: std::path::PathBuf| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        names(dir.path().join("data")),
        ["relay.db", "relay.lock", "teams"]
    );
    assert_eq!(names(config.teams_dir()), [format!("{team}.db")]);
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
        !config.directory_path().exists() && !config.teams_dir().exists(),
        "no relay after a refused init"
    );
    let token = Relay::init(&config, "Team", "owner.one").expect("init");
    assert!(token.expose().starts_with("apassy_mbr_t_"));
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
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&relay.config.team_path(&relay.team_id)), 0o600);
    assert_eq!(mode(&relay.config.directory_path()), 0o600);
    assert_eq!(mode(&relay.config.admin_socket_path()), 0o600);
    assert_eq!(mode(&relay.config.data_dir), 0o700);
    assert_eq!(mode(&relay.config.teams_dir()), 0o700);
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
    std::fs::write(config.directory_path(), vec![7u8; 8192]).unwrap();
    assert!(Relay::start(config).is_err());
}

#[test]
fn data_survives_a_restart_and_sessions_do_not() {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let run = relay.run_released(
        &team.agent_token,
        &team.request(&["git", "status"], Some("check the repo")),
    );
    assert_eq!(run["status"], "ready");
    let run_id = run["run_id"].as_u64().unwrap();
    // A second run waits when the relay stops.
    let (_, waiting) = relay.run(
        &team.agent_token,
        &team.request(&["git", "status"], Some("wait")),
    );
    let waiting_id = waiting["result"]["run_id"].as_u64().unwrap();
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
    // The run that waited is still pending, but its key is gone: the host never sees it.
    let waiting = relay.ok(
        "GET",
        &format!("/v1/runs/{waiting_id}"),
        &team.agent_token,
        None,
    );
    assert_eq!(waiting["status"], "pending");
    assert!(relay.host_requests().is_empty());
    // A new run works, and its key is new.
    let run = relay.run_released(
        &team.agent_token,
        &team.request(&["git", "status"], Some("again")),
    );
    assert_eq!(run["status"], "ready");
    // The session holds the value again, so the value is masked in the audit.
    let request = json!({
        "items": [team.item], "command": ["git", "status"],
        "purpose": format!("value {CANARY}"), "user_request": "x"
    });
    relay.run(&team.agent_token, &request);
    let audit = relay.ok("GET", "/v1/audit?limit=500", &relay.owner_token, None);
    assert!(!audit.to_string().contains(CANARY));
    assert!(audit.to_string().contains("session_ended"));
}

/// The first alpha kept the item values in the vault (user_version 1). A relay from
/// before teams is refused at start (it needs `migrate`), and `migrate` refuses a
/// version 1 vault without touching it.
#[test]
fn a_vault_from_the_first_alpha_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = relay::test_config(dir.path(), UpstreamOptions::default());
    const OLD_KEY: &str = "the old vault passphrase of the first alpha";
    let old_key = SecretString::new(OLD_KEY.to_string());
    std::fs::create_dir_all(&config.data_dir).unwrap();
    let conn = rusqlite::Connection::open(config.legacy_vault_path()).unwrap();
    conn.execute_batch(&format!("PRAGMA key = '{OLD_KEY}';"))
        .unwrap();
    conn.execute_batch(
        "CREATE TABLE team (id INTEGER PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL, created_at INTEGER NOT NULL);
         CREATE TABLE item (id INTEGER PRIMARY KEY, name TEXT NOT NULL, env_name TEXT NOT NULL, value TEXT NOT NULL);
         INSERT INTO team VALUES (1, 'Old Team', 0);
         PRAGMA user_version = 1;",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO item (name, env_name, value) VALUES ('old', 'OLD_KEY', ?1)",
        [CANARY],
    )
    .unwrap();
    drop(conn);
    let before = std::fs::read(config.legacy_vault_path()).unwrap();
    let error = Relay::start(config.clone())
        .err()
        .expect("a relay from before teams needs migrate");
    assert!(error.message.contains("migrate"), "{error}");
    let error = Relay::migrate(&config, &old_key).expect_err("a version 1 vault must be refused");
    assert!(error.message.contains("first alpha"), "{error}");
    assert!(error.message.contains("plaintext"), "{error}");
    assert!(error.message.contains("new data volume"), "{error}");
    assert!(!error.to_string().contains(CANARY), "{error}");
    assert_eq!(std::fs::read(config.legacy_vault_path()).unwrap(), before);
    assert!(!config.directory_path().exists());
    // A vault of a version that is not known is refused with another message.
    let conn = rusqlite::Connection::open(config.legacy_vault_path()).unwrap();
    conn.execute_batch(&format!(
        "PRAGMA key = '{OLD_KEY}'; PRAGMA user_version = 9;"
    ))
    .unwrap();
    drop(conn);
    let error = Relay::migrate(&config, &old_key).expect_err("version 9 is unknown");
    assert!(error.message.contains("unknown schema version"), "{error}");
    assert!(!config.directory_path().exists());
    assert!(
        !config.teams_dir().exists()
            || std::fs::read_dir(config.teams_dir())
                .unwrap()
                .next()
                .is_none()
    );
}

#[test]
fn a_new_vault_is_version_3_with_no_value_column() {
    let relay = start(UpstreamOptions::default());
    let version = relay.vault_rows("SELECT user_version, '' FROM pragma_user_version");
    assert_eq!(version[0].0, b"3");
    assert_eq!(store::SCHEMA_VERSION, 3);
}

#[test]
fn health_needs_no_edge_header() {
    let relay = start(UpstreamOptions::default());
    let response = ureq::get(&format!("{}/healthz", relay.url))
        .call()
        .expect("healthz");
    assert_eq!(response.status().as_u16(), 200);
}
