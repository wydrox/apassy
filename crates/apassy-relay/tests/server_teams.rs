//! Several teams on one relay (ADR 0019): separation, team codes, the operator
//! socket, and the migration of a relay from before teams.

#[path = "common/relay.rs"]
mod relay;

use apassy_relay::config::UpstreamOptions;
use apassy_relay::error::codes;
use apassy_relay::ids::TeamId;
use apassy_relay::secret::{SecretString, parse_token, token_hash};
use apassy_relay::server::Relay;
use apassy_relay::server::operator::Command;
use relay::{CANARY, CANARY2, start, team_of};
use serde_json::{Value, json};

/// The same token text with the team id of another team.
fn moved_to(token: &str, team: &TeamId) -> String {
    let from = team_of(token);
    token.replacen(from.as_str(), team.as_str(), 1)
}

#[test]
fn two_teams_share_ids_but_no_data() {
    let mut relay = start(UpstreamOptions::default());
    let owner_a = relay.owner_token.clone();
    let team_a = relay.setup("staging");
    let id_a = relay.team_id.clone();
    let owner_b = relay.new_team("Team B", "bob");
    let id_b = team_of(&owner_b);
    assert_ne!(id_a, id_b);
    relay.switch_team(&owner_b);
    let collection_b = relay.add_collection("payments", json!({}));
    let item_b = relay.add_item(
        collection_b,
        "STRIPE_API_KEY",
        CANARY2,
        json!({"provider": "stripe", "environment": "staging"}),
    );
    let (member_b, member_token_b) = relay.join_member("member", "alice");
    relay.ok(
        "POST",
        "/v1/grants",
        &owner_b,
        Some(&json!({"collection_id": collection_b, "member_id": member_b})),
    );
    let agent_b = relay.ok(
        "POST",
        "/v1/agents",
        &member_token_b,
        Some(&json!({"name": "b-agent"})),
    );
    let agent_token_b = agent_b["secret"].as_str().unwrap().to_string();
    // The local ids are the same in both teams.
    assert_eq!(
        (collection_b, item_b, member_b),
        (team_a.collection, team_a.item, team_a.member_id)
    );
    assert_eq!(team_of(&agent_token_b), id_b);

    // Each owner sees only its own team.
    let me_b = relay.ok("GET", "/v1/me", &owner_b, None);
    assert_eq!(me_b["team"], "Team B");
    assert_eq!(me_b["team_id"], id_b.as_str());
    let me_a = relay.ok("GET", "/v1/me", &owner_a, None);
    assert_eq!(me_a["team"], "Test Team");
    let members_b = relay.ok("GET", "/v1/members", &owner_b, None);
    let names: Vec<&str> = members_b
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["bob", "alice"], "{members_b}");

    // A run with id 1 in each team. Each agent sees only its own.
    let request_b = json!({
        "items": [item_b], "command": ["git", "status"],
        "purpose": "check the repo b", "user_request": "check b"
    });
    let (_, pending_a) = relay.run(
        &team_a.agent_token,
        &team_a.request(&["git", "status"], Some("check a")),
    );
    let (_, pending_b) = relay.run(&agent_token_b, &request_b);
    let run_a = pending_a["result"]["run_id"].as_u64().unwrap();
    let run_b = pending_b["result"]["run_id"].as_u64().unwrap();
    assert_eq!(run_a, run_b, "both teams start at run 1");
    // The host of each team sees only its own run.
    let host_b = relay.host_requests();
    assert_eq!(host_b.len(), 1);
    assert_eq!(host_b[0]["purpose"], "check the repo b");
    relay.switch_team(&owner_a);
    let host_a = relay.host_requests();
    assert_eq!(host_a.len(), 1);
    assert_eq!(host_a[0]["purpose"], "check the account");
    // Release both. The sessions have the same run id and different keys and values.
    relay.release_ok(run_a);
    relay.switch_team(&owner_b);
    relay.release_ok(run_b);
    let view_a = relay.ok(
        "GET",
        &format!("/v1/runs/{run_a}"),
        &team_a.agent_token,
        None,
    );
    let view_b = relay.ok("GET", &format!("/v1/runs/{run_b}"), &agent_token_b, None);
    let base_a = view_a["session"]["env"]["APASSY_BASE_STRIPE_API_KEY"]
        .as_str()
        .unwrap()
        .to_string();
    let base_b = view_b["session"]["env"]["APASSY_BASE_STRIPE_API_KEY"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(base_a, base_b);
    let key_a = base_a
        .split("/p/")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let key_b = base_b
        .split("/p/")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(team_of(&key_a), id_a);
    assert_eq!(team_of(&key_b), id_b);
    let source = relay.sessions();
    let now = apassy_relay::now_unix();
    assert_eq!(
        source.find(&key_a, now).unwrap().secrets[0].value.expose(),
        CANARY
    );
    assert_eq!(
        source.find(&key_b, now).unwrap().secrets[0].value.expose(),
        CANARY2
    );
    // A session key moved to the other team finds nothing.
    assert!(source.find(&moved_to(&key_a, &id_b), now).is_none());
    assert!(source.find(&moved_to(&key_b, &id_a), now).is_none());
    let (status, _) = relay.call(
        "GET",
        &format!("/p/{}/api.stripe.com/v1/balance", moved_to(&key_a, &id_b)),
        None,
        None,
    );
    assert_eq!(status, 403);

    // A token moved to the other team is unknown there, with the same error as any
    // unknown token.
    for token in [&owner_a, &team_a.agent_token, &team_a.member_token] {
        relay.fails(
            "GET",
            "/v1/me",
            Some(&moved_to(token, &id_b)),
            None,
            401,
            codes::UNAUTHENTICATED,
        );
    }
    let unknown_team = TeamId::parse("t_unknownabc").unwrap();
    relay.fails(
        "GET",
        "/v1/me",
        Some(&moved_to(&owner_a, &unknown_team)),
        None,
        401,
        codes::UNAUTHENTICATED,
    );

    // The audit of each team has none of the other's rows.
    let audit_a = relay
        .ok("GET", "/v1/audit?limit=500", &owner_a, None)
        .to_string();
    let audit_b = relay
        .ok("GET", "/v1/audit?limit=500", &owner_b, None)
        .to_string();
    assert!(audit_a.contains("check the account") && !audit_a.contains("check the repo b"));
    assert!(audit_b.contains("check the repo b") && !audit_b.contains("check the account"));
    assert!(!audit_a.contains(id_b.as_str()) && !audit_b.contains(id_a.as_str()));
    for audit in [&audit_a, &audit_b] {
        assert!(!audit.contains(CANARY) && !audit.contains(CANARY2));
        assert!(!audit.contains("apassy_ses_") && !audit.contains("apassy_mbr_"));
    }
}

#[test]
fn an_invite_joins_only_its_own_team() {
    let mut relay = start(UpstreamOptions::default());
    let owner_a = relay.owner_token.clone();
    let owner_b = relay.new_team("Team B", "bob");
    relay.switch_team(&owner_b);
    let invite = relay.ok(
        "POST",
        "/v1/invites",
        &owner_b,
        Some(&json!({"role": "member"})),
    );
    let code = invite["secret"].as_str().unwrap().to_string();
    assert_eq!(team_of(&code), team_of(&owner_b));
    // The code moved to team A is not an invite of team A.
    let moved = moved_to(&code, &team_of(&owner_a));
    relay.fails(
        "POST",
        "/v1/join",
        None,
        Some(&json!({"code": moved, "name": "carol"})),
        403,
        codes::INVITE_INVALID,
    );
    let joined = relay.ok(
        "POST",
        "/v1/join",
        "",
        Some(&json!({"code": code, "name": "carol"})),
    );
    let token = joined["secret"].as_str().unwrap();
    assert_eq!(team_of(token), team_of(&owner_b));
    assert_eq!(relay.ok("GET", "/v1/me", token, None)["team"], "Team B");
    let members_a = relay.ok("GET", "/v1/members", &owner_a, None);
    assert!(!members_a.to_string().contains("carol"));
}

#[test]
fn a_team_code_works_once_and_a_typo_does_not_use_it() {
    let relay = start(UpstreamOptions::default());
    let code = relay.operator(Command::TeamCode { hours: 1 }).unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(code.starts_with("apassy_tcd_"));
    // A bad name is refused before the code is used.
    relay.fails(
        "POST",
        "/v1/teams",
        None,
        Some(&json!({"code": code, "team": "", "owner": "bob"})),
        400,
        codes::INVALID_REQUEST,
    );
    relay.fails(
        "POST",
        "/v1/teams",
        None,
        Some(&json!({"code": code, "team": "B", "owner": "bad name"})),
        400,
        codes::INVALID_REQUEST,
    );
    // A wrong code, and a member token as a code, are refused alike.
    let wrong = format!("apassy_tcd_{}", "0".repeat(64));
    for bad in [wrong.as_str(), relay.owner_token.as_str(), "x"] {
        relay.fails(
            "POST",
            "/v1/teams",
            None,
            Some(&json!({"code": bad, "team": "B", "owner": "bob"})),
            403,
            codes::INVITE_INVALID,
        );
    }
    let made = relay.ok(
        "POST",
        "/v1/teams",
        "",
        Some(&json!({"code": code, "team": "B", "owner": "bob"})),
    );
    let token = made["secret"].as_str().unwrap();
    assert_eq!(made["team_id"], team_of(token).as_str());
    relay.fails(
        "POST",
        "/v1/teams",
        None,
        Some(&json!({"code": code, "team": "C", "owner": "eve"})),
        403,
        codes::INVITE_INVALID,
    );
    // The team has its own file.
    assert!(relay.config.team_path(&team_of(token)).exists());
    // A code that lives too long is refused.
    assert!(relay.operator(Command::TeamCode { hours: 0 }).is_err());
    assert!(relay.operator(Command::TeamCode { hours: 721 }).is_err());
}

#[test]
fn the_operator_suspends_resumes_and_deletes_a_team() {
    let mut relay = start(UpstreamOptions::default());
    let owner_a = relay.owner_token.clone();
    let owner_b = relay.new_team("Team B", "bob");
    let id_b = team_of(&owner_b);
    relay.switch_team(&owner_b);
    let team_b = relay.setup("staging");
    let run = relay.run_released(
        &team_b.agent_token,
        &team_b.request(&["git", "status"], Some("check")),
    );
    let key = run["session"]["env"]["APASSY_BASE_STRIPE_API_KEY"]
        .as_str()
        .unwrap()
        .split("/p/")
        .nth(1)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let source = relay.sessions();
    assert!(source.find(&key, apassy_relay::now_unix()).is_some());

    // The operator sees counts, not content.
    let teams = relay.operator(Command::Teams).unwrap();
    let list = teams.as_array().unwrap();
    assert_eq!(list.len(), 2);
    let b: &Value = list.iter().find(|t| t["id"] == id_b.as_str()).unwrap();
    assert_eq!(b["name"], "Team B");
    assert_eq!(b["state"], "active");
    assert_eq!(b["members"], 2);
    assert_eq!(b["items"], 1);
    for hidden in [
        "alice",
        "payments",
        "STRIPE_API_KEY",
        "check the account",
        CANARY,
    ] {
        assert!(!teams.to_string().contains(hidden), "{hidden} in {teams}");
    }

    // Delete needs a suspended team.
    let error = relay
        .operator(Command::Delete { team: id_b.clone() })
        .unwrap_err();
    assert!(error.message.contains("Suspend"), "{error}");
    relay
        .operator(Command::Suspend { team: id_b.clone() })
        .unwrap();
    assert!(
        relay
            .operator(Command::Suspend { team: id_b.clone() })
            .is_err()
    );
    // Its tokens stop, its session ends, team A goes on.
    relay.fails(
        "GET",
        "/v1/me",
        Some(&owner_b),
        None,
        401,
        codes::UNAUTHENTICATED,
    );
    relay.fails(
        "GET",
        "/v1/access",
        Some(&team_b.agent_token),
        None,
        401,
        codes::UNAUTHENTICATED,
    );
    assert!(source.find(&key, apassy_relay::now_unix()).is_none());
    relay.ok("GET", "/v1/me", &owner_a, None);
    let teams = relay.operator(Command::Teams).unwrap();
    let b = teams
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id_b.as_str())
        .unwrap()
        .clone();
    assert_eq!(b["state"], "suspended");
    assert!(b["members"].is_null());

    // Resume: the data is back, the old session is not.
    relay
        .operator(Command::Resume { team: id_b.clone() })
        .unwrap();
    relay.ok("GET", "/v1/me", &owner_b, None);
    let audit = relay
        .ok("GET", "/v1/audit?limit=500", &owner_b, None)
        .to_string();
    assert!(
        audit.contains("team_suspended")
            && audit.contains("team_resumed")
            && audit.contains("operator")
    );
    assert!(source.find(&key, apassy_relay::now_unix()).is_none());

    // Delete: the file and the key are gone, the tokens do not come back.
    relay
        .operator(Command::Suspend { team: id_b.clone() })
        .unwrap();
    relay
        .operator(Command::Delete { team: id_b.clone() })
        .unwrap();
    assert!(!relay.config.team_path(&id_b).exists());
    assert!(Relay::team_vault(&relay.config, &id_b).is_err());
    assert!(
        relay
            .operator(Command::Resume { team: id_b.clone() })
            .is_err()
    );
    relay.fails(
        "GET",
        "/v1/me",
        Some(&owner_b),
        None,
        401,
        codes::UNAUTHENTICATED,
    );
    let teams = relay.operator(Command::Teams).unwrap();
    assert_eq!(teams.as_array().unwrap().len(), 1);
    // After a restart team A is there, team B is not.
    relay.switch_team(&owner_a);
    let relay = relay.restart();
    relay.ok("GET", "/v1/me", &owner_a, None);
    relay.fails(
        "GET",
        "/v1/me",
        Some(&owner_b),
        None,
        401,
        codes::UNAUTHENTICATED,
    );
}

#[test]
fn an_unknown_operator_command_is_refused() {
    use std::io::{BufRead, BufReader, Write};
    let relay = start(UpstreamOptions::default());
    let mut stream =
        std::os::unix::net::UnixStream::connect(relay.config.admin_socket_path()).unwrap();
    stream
        .write_all(b"{\"command\":\"members\",\"team\":\"t_abcdefgh23\"}\n")
        .unwrap();
    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer).unwrap();
    let envelope: Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["error"]["code"], codes::INVALID_REQUEST);
}

/// A data directory of the old layout: one team.db with an old key, and member and
/// agent tokens without a team id. Returns the config, the temp dir, the old key, and
/// the old owner and agent tokens.
fn legacy_layout() -> (
    apassy_relay::config::RelayConfig,
    tempfile::TempDir,
    SecretString,
    String,
    String,
) {
    let relay = start(UpstreamOptions::default());
    let team = relay.setup("staging");
    let team_id = relay.team_id.clone();
    let (config, dir) = relay.stop_keep();
    let old_key = SecretString::new("the old vault passphrase of tests".to_string());
    let old_owner = format!("apassy_mbr_{}", "1a".repeat(32));
    let old_agent = format!("apassy_agt_{}", "2b".repeat(32));
    {
        let conn = relay::open_team_file(&config, &team_id);
        conn.execute(
            "UPDATE member SET token_hash = ?1 WHERE role = 'owner'",
            [token_hash(&old_owner).0.as_slice()],
        )
        .unwrap();
        conn.execute(
            "UPDATE agent SET token_hash = ?1 WHERE id = ?2",
            rusqlite::params![token_hash(&old_agent).0.as_slice(), team.agent_id as i64],
        )
        .unwrap();
        conn.execute_batch(&format!("PRAGMA rekey = '{}';", old_key.expose()))
            .unwrap();
    }
    std::fs::rename(config.team_path(&team_id), config.legacy_vault_path()).unwrap();
    std::fs::remove_file(config.directory_path()).unwrap();
    std::fs::remove_dir(config.teams_dir()).unwrap();
    (config, dir, old_key, old_owner, old_agent)
}

#[test]
fn a_relay_from_before_teams_migrates_with_its_tokens() {
    let (config, _dir, old_key, old_owner, old_agent) = legacy_layout();
    // The master key must not be the old key.
    let same = Relay::migrate(&config, &config.master_key.clone()).expect_err("same key");
    assert!(same.message.contains("master key"), "{same}");

    // Start refuses, migrate moves it.
    let error = Relay::start(config.clone()).err().unwrap();
    assert!(error.message.contains("migrate"), "{error}");
    let wrong = SecretString::new("not the old passphrase at all".to_string());
    assert!(Relay::migrate(&config, &wrong).is_err());
    assert!(
        !config.directory_path().exists(),
        "a failed migration leaves nothing"
    );
    let migrated = Relay::migrate(&config, &old_key).unwrap();
    assert!(Relay::migrate(&config, &old_key).is_err(), "only once");
    assert!(!config.legacy_vault_path().exists());
    let backup = config.data_dir.join("team.db.pre-teams");
    assert!(backup.exists());
    // The new file opens with its new key only; the backup with the old key only.
    let (path, key) = Relay::team_vault(&config, &migrated).unwrap();
    let opens = |path: &std::path::Path, key: &str| {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{key}';"))
            .unwrap();
        conn.query_row("SELECT count(*) FROM item", [], |r| r.get::<_, i64>(0))
            .is_ok()
    };
    assert!(opens(&path, key.expose()) && !opens(&path, old_key.expose()));
    assert!(opens(&backup, old_key.expose()) && !opens(&backup, key.expose()));

    // The old tokens work for the migrated team; new tokens name it.
    let running = Relay::start(config.clone()).unwrap();
    let url = running.url();
    let call = |method: &str, path: &str, token: &str, body: Option<&Value>| {
        relay::call_url(
            &url,
            Some(relay::EDGE_SECRET),
            method,
            path,
            Some(token),
            body,
        )
    };
    let (status, me) = call("GET", "/v1/me", &old_owner, None);
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["result"]["team"], "Test Team");
    assert_eq!(me["result"]["team_id"], migrated.as_str());
    let (status, access) = call("GET", "/v1/access", &old_agent, None);
    assert_eq!(status, 200, "{access}");
    let (_, items) = call("GET", "/v1/items", &old_owner, None);
    assert_eq!(items["result"].as_array().unwrap().len(), 1);
    let (_, invite) = call(
        "POST",
        "/v1/invites",
        &old_owner,
        Some(&json!({"role": "member"})),
    );
    let code = invite["result"]["secret"].as_str().unwrap();
    assert_eq!(parse_token(code).unwrap().team, Some(migrated.clone()));
    // An old-form invite or session key has no team and is refused.
    let (status, _) = call(
        "POST",
        "/v1/join",
        "",
        Some(&json!({"code": format!("apassy_inv_{}", "3c".repeat(32)), "name": "x"})),
    );
    assert_eq!(status, 403);
    running.stop();
}

#[test]
fn a_migration_that_stopped_is_finished_or_redone() {
    // Stopped before the commit point: leftovers of an earlier try, and no relay.db.
    let (config, _dir, old_key, old_owner, _) = legacy_layout();
    std::fs::create_dir_all(config.teams_dir()).unwrap();
    let leftover = config.teams_dir().join("t_leftoverab.db.migrating");
    std::fs::write(&leftover, b"half a copy").unwrap();
    std::fs::write(
        config.data_dir.join("relay.db.migrating"),
        b"half a directory",
    )
    .unwrap();
    let migrated = Relay::migrate(&config, &old_key).unwrap();
    assert!(!leftover.exists());
    assert!(!config.data_dir.join("relay.db.migrating").exists());
    // Stopped after the commit point: relay.db is written, the files are not renamed.
    let path = config.team_path(&migrated);
    let mut staged = path.clone().into_os_string();
    staged.push(".migrating");
    std::fs::rename(&path, &staged).unwrap();
    let backup = config.data_dir.join("team.db.pre-teams");
    std::fs::rename(&backup, config.legacy_vault_path()).unwrap();
    // The next start finishes it.
    let running = Relay::start(config.clone()).unwrap();
    assert!(path.exists() && backup.exists() && !config.legacy_vault_path().exists());
    let (status, me) = relay::call_url(
        &running.url(),
        Some(relay::EDGE_SECRET),
        "GET",
        "/v1/me",
        Some(&old_owner),
        None,
    );
    assert_eq!(status, 200, "{me}");
    running.stop();
}

#[test]
fn one_broken_team_does_not_stop_the_others() {
    let mut relay = start(UpstreamOptions::default());
    let owner_a = relay.owner_token.clone();
    let owner_b = relay.new_team("Team B", "bob");
    let id_b = team_of(&owner_b);
    relay.switch_team(&owner_a);
    let (config, dir) = relay.stop_keep();
    std::fs::write(config.team_path(&id_b), vec![9u8; 8192]).unwrap();
    // The relay starts, serves team A, and keeps team B out of service.
    let running = Relay::start(config.clone()).unwrap();
    let url = running.url();
    let me = |token: &str| {
        relay::call_url(
            &url,
            Some(relay::EDGE_SECRET),
            "GET",
            "/v1/me",
            Some(token),
            None,
        )
        .0
    };
    assert_eq!(me(&owner_a), 200);
    assert_eq!(me(&owner_b), 401);
    let send = |command: Command| {
        apassy_relay::server::operator::send(&config.admin_socket_path(), &command)
    };
    let teams = send(Command::Teams).unwrap();
    let b = teams
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id_b.as_str())
        .unwrap()
        .clone();
    assert_eq!(
        (b["state"].clone(), b["open"].clone()),
        (json!("active"), json!(false))
    );
    // The operator takes it out.
    send(Command::Suspend { team: id_b.clone() }).unwrap();
    send(Command::Delete { team: id_b.clone() }).unwrap();
    assert!(!config.team_path(&id_b).exists());
    assert_eq!(me(&owner_a), 200);
    running.stop();
    drop(dir);
}

#[test]
fn two_relays_cannot_use_one_data_directory() {
    let relay = start(UpstreamOptions::default());
    let mut second = relay.config.clone();
    second.listen = "127.0.0.1:0".parse().unwrap();
    let error = Relay::start(second.clone()).err().expect("a second relay");
    assert!(error.message.contains("Another relay"), "{error}");
    assert!(Relay::migrate(&second, &SecretString::new("x".repeat(20))).is_err());
    // The first relay still has its own operator socket.
    assert!(relay.operator(Command::Teams).is_ok());
    relay.ok("GET", "/v1/me", &relay.owner_token, None);
}

#[test]
fn an_operator_backup_restores_every_team() {
    let mut relay = start(UpstreamOptions::default());
    let owner_a = relay.owner_token.clone();
    relay.setup("staging");
    let owner_b = relay.new_team("Team B", "bob");
    relay.switch_team(&owner_b);
    relay.add_collection("family", json!({}));
    let owner_c = relay.new_team("Team C", "carol");
    relay
        .operator(Command::Suspend {
            team: team_of(&owner_c),
        })
        .unwrap();
    let made = relay.operator(Command::Backup).unwrap();
    assert_eq!(made["teams"], 3);
    let dir = std::path::PathBuf::from(made["dir"].as_str().unwrap());
    let names: Vec<&str> = made["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 4, "relay.db and three teams: {names:?}");
    assert!(names.contains(&"relay.db"));
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("relay.db")), 0o600);
    assert_eq!(mode(&dir.join("MANIFEST.json")), 0o600);
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("MANIFEST.json")).unwrap()).unwrap();
    assert_eq!(manifest["files"], made["files"]);
    // The values are not in the backup.
    for name in &names {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        assert!(!bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()));
    }
    // A second backup in the same second is refused, not mixed in.
    let again = relay.operator(Command::Backup);
    assert!(again.is_err() || again.unwrap()["dir"] != made["dir"]);

    // Restore into a new data directory with the same master key.
    let mut config = relay.config.clone();
    relay.switch_team(&owner_a);
    let fresh = tempfile::tempdir().unwrap();
    config.data_dir = fresh.path().join("data");
    config.listen = "127.0.0.1:0".parse().unwrap();
    std::fs::create_dir_all(config.teams_dir()).unwrap();
    for name in &names {
        std::fs::copy(dir.join(name), config.data_dir.join(name)).unwrap();
    }
    let restored = Relay::start(config.clone()).unwrap();
    let url = restored.url();
    let me = |token: &str| {
        relay::call_url(
            &url,
            Some(relay::EDGE_SECRET),
            "GET",
            "/v1/me",
            Some(token),
            None,
        )
    };
    assert_eq!(me(&owner_a).1["result"]["team"], "Test Team");
    assert_eq!(me(&owner_b).1["result"]["team"], "Team B");
    // Team C was suspended in the backup and stays so.
    assert_eq!(me(&owner_c).0, 401);
    let (_, items) = relay::call_url(
        &url,
        Some(relay::EDGE_SECRET),
        "GET",
        "/v1/items",
        Some(&owner_a),
        None,
    );
    assert_eq!(items["result"].as_array().unwrap().len(), 1);
    restored.stop();
}
