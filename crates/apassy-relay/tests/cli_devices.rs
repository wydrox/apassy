//! SPEC section 23 against a loopback relay. Every CLI uses an isolated file key store.
mod cli_support;

use apassy_relay::{device, hostkeys, ids::TeamId};
use cli_support::*;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TEAM: &str = "t_abcdefgh23";
const OTHER: &str = "t_abcdefgh24";
const INVITE: &str =
    "apassy_inv_t_abcdefgh23_1111111111111111111111111111111111111111111111111111111111111111";
const LINK: &str =
    "apassy_lnk_t_abcdefgh23_2222222222222222222222222222222222222222222222222222222222222222";
const ACCESS: &str =
    "apassy_acc_t_abcdefgh23_3333333333333333333333333333333333333333333333333333333333333333";
const WORDS: &str = "acorn zebra";

fn team() -> TeamId {
    TeamId::parse(TEAM).unwrap()
}
fn me() -> Value {
    json!({"team_id": TEAM, "team": "Family", "kind": "member", "member_id": 1,
        "member_name": "alice", "role": "owner"})
}
fn device_view() -> Value {
    json!({"id": 3, "member_id": 1, "member_name": "alice", "name": "Laptop",
        "key_holder": true, "current": true, "created_at": 1})
}
fn access() -> Value {
    json!({"token": ACCESS, "expires_at": 4_000_000_000u64, "team_id": TEAM,
        "team": "Family", "member_id": 1, "member_name": "alice", "role": "owner",
        "device_id": 3, "key_holder": true})
}
fn settings(cli: &Cli) -> Value {
    serde_json::from_slice(&std::fs::read(cli.settings_file()).unwrap()).unwrap()
}
fn key_path(cli: &Cli) -> std::path::PathBuf {
    cli.settings_file()
        .parent()
        .unwrap()
        .join(format!("device-{TEAM}.key"))
}
fn read_key(path: &Path) -> device::DeviceKey {
    let text = std::fs::read_to_string(path).unwrap();
    let bytes = hostkeys::decode_b64(text.trim(), 4096).unwrap();
    device::DeviceKey::from_pkcs8(&bytes).unwrap()
}
fn write_settings(cli: &Cli, value: Value) {
    let dir = cli.settings_file().parent().unwrap().to_owned();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(cli.settings_file(), value.to_string()).unwrap();
    std::fs::set_permissions(cli.settings_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn seed_device(cli: &Cli, url: &str) -> device::DeviceKey {
    write_settings(
        cli,
        json!({"version": 2, "current": TEAM, "teams": {TEAM: {
        "relay_url": url, "team": "Family", "member": "alice", "device_id": 3,
        "member_token": null}}}),
    );
    let key = device::DeviceKey::generate().unwrap();
    std::fs::write(key_path(cli), hostkeys::encode_b64(key.pkcs8())).unwrap();
    std::fs::set_permissions(key_path(cli), std::fs::Permissions::from_mode(0o600)).unwrap();
    key
}
fn assert_private(cli: &Cli, public: &str) {
    assert_eq!(read_key(&key_path(cli)).public_key_b64(), public);
    for (path, mode) in [
        (cli.settings_file(), 0o600),
        (key_path(cli), 0o600),
        (cli.settings_file().parent().unwrap().to_owned(), 0o700),
    ] {
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            mode
        );
    }
    let content = std::fs::read_to_string(cli.settings_file()).unwrap();
    assert!(!content.contains(MEMBER_TOKEN));
    assert!(!content.contains(ACCESS));
    assert!(!content.contains(&hostkeys::encode_b64(read_key(&key_path(cli)).pkcs8())));
}
fn successful(output: &std::process::Output) {
    assert_eq!(code(output), 0, "{}", text(&output.stderr));
}
fn pending(request: &Recorded) -> Answer {
    let body = request.json();
    let public = device::decode_public_key(body["public_key"].as_str().unwrap()).unwrap();
    let safety = device::safety_words(&team(), body["code"].as_str().unwrap(), &public);
    ok(
        json!({"id": 7, "team_id": TEAM, "team": "Family", "by": "alice",
        "safety": safety, "expires_at": 4_000_000_000u64}),
    )
}
fn auth_answer(request: &Recorded) -> Option<Answer> {
    match request.url.as_str() {
        "/v1/auth/challenge" => Some(ok(json!({"nonce": hostkeys::encode_b64(&[5u8;32]),
            "expires_at": 4_000_000_000u64,
            "origin": format!("http://{}", request.header("Host").unwrap())}))),
        "/v1/auth/token" => Some(ok(access())),
        _ => None,
    }
}
fn join_view() -> Value {
    json!({"id":7,"name":"bob","device_name":"Bob laptop","role":"member",
        "grants":["Work"],"invited_by":"alice","created_at":1,"expires_at":4_000_000_000u64})
}
fn link_view() -> Value {
    json!({"id":7,"device_name":"Bob laptop","created_at":1,"expires_at":4_000_000_000u64})
}

fn run_with_stdout(
    cli: &Cli,
    args: &[&str],
    captured: Arc<Mutex<Vec<u8>>>,
) -> std::process::Output {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut child = cli
        .command(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let copy = captured.clone();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            if reader.read_until(b'\n', &mut line).unwrap() == 0 {
                break;
            }
            copy.lock().unwrap().extend(line);
        }
    });
    let mut output = child.wait_with_output().unwrap();
    reader.join().unwrap();
    output.stdout = captured.lock().unwrap().clone();
    output
}

#[test]
fn create_sends_a_device_key_and_saves_version_two_without_a_member_token() {
    let cli = Cli::new();
    let dir = cli.settings_file().parent().unwrap().to_owned();
    let key_before = Arc::new(Mutex::new(None));
    let evidence = key_before.clone();
    let mock = Mock::start(move |_, _| {
        let paths = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "key"))
            .collect::<Vec<_>>();
        if paths.len() == 1 {
            *evidence.lock().unwrap() = Some(read_key(&paths[0]).public_key_b64());
        }
        ok(json!({"team_id":TEAM,"member_id":1,"device_id":3}))
    });
    let output = cli.run(
        &[
            "create", "--relay", &mock.url, "--team", "Family", "--name", "alice", "--device",
            "Laptop",
        ],
        Some("apassy_team_4444444444444444444444444444444444444444444444444444444444444444\n"),
    );
    successful(&output);
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!((&*request.method, &*request.url), ("POST", "/v1/teams"));
    assert!(request.header("Authorization").is_none());
    let body = request.json();
    assert_eq!(body["team"], "Family");
    assert_eq!(body["owner"], "alice");
    assert_eq!(body["device_name"], "Laptop");
    assert_eq!(
        key_before.lock().unwrap().as_deref(),
        body["public_key"].as_str()
    );
    assert_private(&cli, body["public_key"].as_str().unwrap());
    let saved = settings(&cli);
    assert_eq!(saved["version"], 2);
    assert_eq!(saved["current"], TEAM);
    assert_eq!(saved["teams"][TEAM]["device_id"], 3);
    assert!(saved["teams"][TEAM]["member_token"].is_null());
}

#[test]
fn join_and_link_accept_codes_and_fragments_and_store_the_key_before_request() {
    for is_link in [false, true] {
        for fragment in [false, true] {
            let cli = Cli::new();
            let path = key_path(&cli);
            let saved_before = Arc::new(Mutex::new(None));
            let seen = saved_before.clone();
            let mock = Mock::start(move |request, _| {
                let saved = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|s| hostkeys::decode_b64(s.trim(), 4096).ok())
                    .and_then(|bytes| device::DeviceKey::from_pkcs8(&bytes).ok());
                *seen.lock().unwrap() = saved.map(|key| key.public_key_b64());
                pending(request)
            });
            let code_text = if is_link { LINK } else { INVITE };
            let stdin = if fragment {
                format!(" \t{}/join#{}\r\n", mock.url, code_text)
            } else {
                format!(" \t{code_text}\r\n")
            };
            let args = if is_link {
                vec![
                    "device",
                    "link",
                    "--relay",
                    &mock.url,
                    "--device",
                    "Laptop",
                    "--no-wait",
                ]
            } else {
                vec![
                    "join",
                    "--relay",
                    &mock.url,
                    "--name",
                    "bob",
                    "--device",
                    "Laptop",
                    "--no-wait",
                ]
            };
            let output = cli.run(&args, Some(&stdin));
            successful(&output);
            let requests = mock.requests();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                requests[0].url,
                if is_link {
                    "/v1/devices/link"
                } else {
                    "/v1/join"
                }
            );
            assert!(requests[0].header("Authorization").is_none());
            let body = requests[0].json();
            assert_eq!(body["code"], code_text);
            assert_eq!(body["device_name"], "Laptop");
            if !is_link {
                assert_eq!(body["name"], "bob");
            }
            let public = body["public_key"].as_str().unwrap();
            assert_eq!(saved_before.lock().unwrap().as_deref(), Some(public));
            assert_private(&cli, public);
            let words = device::safety_words(
                &team(),
                code_text,
                &device::decode_public_key(public).unwrap(),
            );
            let display = format!("{}{}", text(&output.stdout), text(&output.stderr));
            for expected in ["Family", "alice", TEAM, &words, "Tell alice these words"] {
                assert!(display.contains(expected), "missing {expected}: {display}");
            }
        }
    }
}

#[test]
fn join_resume_uses_the_same_key_and_waits_five_seconds_between_pending_attempts() {
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let times = attempts.clone();
    let mock = Mock::start(move |request, _| {
        if request.url == "/v1/join" {
            return pending(request);
        }
        if request.url == "/v1/auth/challenge" {
            let mut attempts = times.lock().unwrap();
            attempts.push(Instant::now());
            if attempts.len() == 1 {
                return err(403, "join_pending", "The join waits.");
            }
        }
        auth_answer(request).unwrap_or_else(|| err(404, "not_found", "Unexpected request."))
    });
    let cli = Cli::new();
    successful(&cli.run(
        &["join", "--relay", &mock.url, "--name", "bob", "--no-wait"],
        Some(INVITE),
    ));
    let key = read_key(&key_path(&cli)).public_key_b64();
    let output = cli.run(&["--team", TEAM, "join", "--resume"], None);
    successful(&output);
    assert!(format!("{}{}", text(&output.stdout), text(&output.stderr)).contains("Joined"));
    let times = attempts.lock().unwrap();
    assert_eq!(times.len(), 2);
    assert!(times[1].duration_since(times[0]) >= Duration::from_millis(4900));
    assert_eq!(read_key(&key_path(&cli)).public_key_b64(), key);
    assert_eq!(
        mock.requests()
            .iter()
            .filter(|r| r.url == "/v1/join")
            .count(),
        1
    );
    assert!(settings(&cli)["teams"][TEAM]["member_token"].is_null());
    assert_eq!(settings(&cli)["current"], TEAM);
}

#[test]
fn join_waits_until_confirmed_and_refusal_exits_three() {
    for refused in [false, true] {
        let mock = Mock::start(move |request, _| {
            if request.url == "/v1/join" {
                pending(request)
            } else if refused {
                err(403, "join_refused", "The join was refused or expired.")
            } else {
                auth_answer(request).unwrap()
            }
        });
        let cli = Cli::new();
        let output = cli.run(
            &["join", "--relay", &mock.url, "--name", "bob"],
            Some(INVITE),
        );
        assert_eq!(
            code(&output),
            if refused { 3 } else { 0 },
            "{}",
            text(&output.stderr)
        );
        assert!(
            mock.requests()
                .iter()
                .any(|r| r.url == "/v1/auth/challenge")
        );
        if !refused {
            assert!(format!("{}{}", text(&output.stdout), text(&output.stderr)).contains("Joined"));
        }
    }
}

#[test]
fn different_relay_safety_words_stop_join_before_sign_in() {
    let mock = Mock::always(
        200,
        json!({"id":7,"team_id":TEAM,"team":"Family","by":"alice",
        "safety":"not valid","expires_at":4_000_000_000u64}),
    );
    let cli = Cli::new();
    let output = cli.run(
        &["join", "--relay", &mock.url, "--name", "bob"],
        Some(INVITE),
    );
    assert_eq!(code(&output), 2);
    assert!(text(&output.stderr).to_lowercase().contains("safety"));
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn enroll_with_an_environment_member_token_learns_the_team_then_saves_only_the_device() {
    let mock = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            ok(me())
        } else {
            ok(device_view())
        }
    });
    let cli = Cli::new().member(&mock.url);
    let output = cli.run(&["device", "enroll", "--name", "Laptop"], None);
    successful(&output);
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, "/v1/me");
    assert_eq!(requests[1].url, "/v1/devices/enroll");
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].header("Authorization"),
        Some(format!("Bearer {MEMBER_TOKEN}").as_str())
    );
    let body = requests[1].json();
    assert_eq!(body["name"], "Laptop");
    assert_private(&cli, body["public_key"].as_str().unwrap());
    assert_eq!(settings(&cli)["teams"][TEAM]["device_id"], 3);
    assert!(settings(&cli)["teams"][TEAM]["member_token"].is_null());
}

#[test]
fn a_member_token_entry_enrolls_and_keeps_the_token_until_the_device_exists() {
    let entry = |relay: &str, device: Value| {
        json!({"version":2,"current":TEAM,"teams":{TEAM:{"relay_url":relay,
        "team":"Family","member":"alice","device_id":device,"member_token":MEMBER_TOKEN}}})
    };
    // An HTTP error leaves the token in the file and removes the key.
    let failing = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            ok(me())
        } else {
            err(500, "relay_error", "synthetic failure")
        }
    });
    let cli = Cli::new();
    write_settings(&cli, entry(&failing.url, Value::Null));
    let output = cli.run(&["device", "enroll", "--name", "Laptop"], None);
    assert_ne!(code(&output), 0);
    assert_eq!(settings(&cli)["teams"][TEAM]["member_token"], MEMBER_TOKEN);
    assert!(settings(&cli)["teams"][TEAM]["device_id"].is_null());
    assert!(!key_path(&cli).exists());
    // The relay enrolls: the device is saved and the token leaves the file.
    let working = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            ok(me())
        } else {
            ok(device_view())
        }
    });
    let cli = Cli::new();
    write_settings(&cli, entry(&working.url, Value::Null));
    let output = cli.run(&["device", "enroll", "--name", "Laptop"], None);
    successful(&output);
    assert_eq!(settings(&cli)["teams"][TEAM]["device_id"], 3);
    assert!(settings(&cli)["teams"][TEAM]["member_token"].is_null());
    // An entry that has a device already refuses, and nothing changes.
    let cli = Cli::new().member(&working.url);
    write_settings(&cli, entry(&working.url, json!(3)));
    let before = std::fs::read(cli.settings_file()).unwrap();
    let output = cli.run(&["device", "enroll", "--name", "Laptop"], None);
    assert_eq!(code(&output), 2);
    assert_eq!(std::fs::read(cli.settings_file()).unwrap(), before);
}

#[test]
fn existing_device_key_refuses_join_and_link_without_overwriting_it() {
    let mock = Mock::always(200, json!({}));
    for is_link in [false, true] {
        let cli = Cli::new();
        seed_device(&cli, &mock.url);
        let before = std::fs::read(key_path(&cli)).unwrap();
        let args = if is_link {
            vec!["device", "link", "--relay", &mock.url, "--no-wait"]
        } else {
            vec!["join", "--relay", &mock.url, "--name", "bob", "--no-wait"]
        };
        let output = cli.run(&args, Some(if is_link { LINK } else { INVITE }));
        assert_eq!(code(&output), 2);
        assert_eq!(std::fs::read(key_path(&cli)).unwrap(), before);
    }
    assert!(mock.requests().is_empty());
}

#[test]
fn device_add_prints_the_code_once_and_invite_prints_the_fragment_link() {
    let mock = Mock::always(
        200,
        json!({"id":7,"secret":LINK,"expires_at":4_000_000_000u64}),
    );
    let cli = Cli::new().member(&mock.url);
    let output = cli.run(&["device", "add"], None);
    successful(&output);
    assert_eq!(text(&output.stdout), format!("{LINK}\n"));
    assert!(!text(&output.stderr).contains(LINK));
    assert_eq!(mock.requests()[0].url, "/v1/devices/links");
    let mock = Mock::always(
        200,
        json!({"id":7,"secret":INVITE,"expires_at":4_000_000_000u64}),
    );
    let cli = Cli::new().member(&mock.url);
    let output = cli.run(
        &[
            "invite", "--role", "owner", "--hours", "24", "--name", "bob", "--grant", "2",
            "--grant", "4",
        ],
        None,
    );
    successful(&output);
    assert_eq!(
        text(&output.stdout),
        format!("{}/join#{INVITE}\n", mock.url)
    );
    assert!(!text(&output.stderr).contains(INVITE));
    assert_eq!(
        mock.requests()[0].json(),
        json!({"role":"owner","expires_hours":24,"name":"bob","grants":[2,4]})
    );
    let output = cli.run(&["invite", "--shared"], None);
    successful(&output);
    assert_eq!(mock.requests()[1].json()["shared"], true);
}

#[test]
fn pending_tables_do_not_show_safety_words() {
    for is_link in [false, true] {
        let mut view = if is_link { link_view() } else { join_view() };
        view["safety"] = json!(WORDS); // Even an over-sharing relay must not disclose these words.
        let mock = Mock::always(200, json!([view]));
        let cli = Cli::new().member(&mock.url);
        let output = cli.run(
            if is_link {
                &["device", "pending"]
            } else {
                &["joins"]
            },
            None,
        );
        successful(&output);
        let display = format!("{}{}", text(&output.stdout), text(&output.stderr));
        assert!(display.contains("Bob laptop"));
        assert!(!display.contains(WORDS));
        assert!(!display.to_lowercase().contains("safety"));
    }
}

#[test]
fn confirms_fetch_the_name_and_send_the_words_and_refusals_send_no_words() {
    for is_link in [false, true] {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_at_request = captured.clone();
        let shown_before_request = Arc::new(Mutex::new(false));
        let shown = shown_before_request.clone();
        let mock = Mock::start(move |request, _| {
            if request.method == "GET" {
                ok(json!([if is_link { link_view() } else { join_view() }]))
            } else if request.url.ends_with("confirm") {
                // The pipe reader can run after the request reaches the server.
                // Withhold the response so printing after the call cannot pass.
                let deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    let text = text(&captured_at_request.lock().unwrap());
                    if text.contains("Bob laptop") && text.contains(WORDS) {
                        *shown.lock().unwrap() = true;
                        break;
                    }
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                ok(if is_link {
                    device_view()
                } else {
                    json!({"member_id":2,"device_id":4})
                })
            } else {
                ok(json!({"id":7}))
            }
        });
        let cli = Cli::new().member(&mock.url);
        let args = if is_link {
            vec!["device", "confirm", "7", "--words", WORDS]
        } else {
            vec!["confirm", "7", "--words", WORDS]
        };
        let output = run_with_stdout(&cli, &args, captured);
        successful(&output);
        assert!(
            *shown_before_request.lock().unwrap(),
            "name and words must precede the confirmation request"
        );
        let requests = mock.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(
            requests[0].url,
            if is_link {
                "/v1/devices/links"
            } else {
                "/v1/joins"
            }
        );
        assert_eq!(requests[1].json(), json!({"safety":WORDS}));
        let display = format!("{}{}", text(&output.stdout), text(&output.stderr));
        assert!(display.contains("Bob laptop"));
        assert!(display.contains(WORDS));
        let args = if is_link {
            vec!["device", "refuse", "7"]
        } else {
            vec!["refuse", "7"]
        };
        successful(&cli.run(&args, None));
        let request = mock.requests().last().unwrap().clone();
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.url,
            if is_link {
                "/v1/devices/links/7/refuse"
            } else {
                "/v1/joins/7/refuse"
            }
        );
        assert!(request.json().get("safety").is_none());
    }
}

#[test]
fn member_role_leave_device_list_revoke_and_key_holder_use_the_spec_endpoints() {
    for (args, method, path, body, result) in [
        (
            vec!["member", "role", "2", "manager"],
            "PUT",
            "/v1/members/2/role",
            Some(json!({"role":"manager"})),
            json!({"id":2,"name":"bob","role":"manager","created_at":1,"revoked":false,"devices":1}),
        ),
        (vec!["leave"], "POST", "/v1/leave", None, json!({"id":1})),
        (
            vec!["device", "list"],
            "GET",
            "/v1/devices",
            None,
            json!([device_view()]),
        ),
        (
            vec!["device", "revoke", "3"],
            "DELETE",
            "/v1/devices/3",
            None,
            json!({"id":3}),
        ),
        (
            vec!["device", "key-holder", "3"],
            "POST",
            "/v1/devices/3/key-holder",
            None,
            device_view(),
        ),
    ] {
        let mock = Mock::start(move |request, _| {
            if request.url == "/v1/me" {
                ok(me())
            } else {
                ok(result.clone())
            }
        });
        let cli = Cli::new().member(&mock.url);
        successful(&cli.run(&args, None));
        let requests = mock.requests();
        let operation = requests.last().unwrap();
        assert_eq!((&*operation.method, &*operation.url), (method, path));
        assert_eq!(
            requests.len(),
            if args == ["leave"] { 2 } else { 1 },
            "{args:?}"
        );
        if let Some(body) = body {
            assert_eq!(operation.json(), body);
        }
    }
}

#[test]
fn team_list_and_use_work_offline_and_team_overrides_select_the_bearer() {
    let mock = Mock::always(200, me());
    let cli = Cli::new();
    write_settings(
        &cli,
        json!({"version":2,"current":TEAM,"teams":{
        TEAM:{"relay_url":mock.url,"team":"Family","member":"alice","device_id":null,"member_token":MEMBER_TOKEN},
        OTHER:{"relay_url":mock.url,"team":"Work","member":"bob","device_id":null,"member_token":"other-synthetic-token"}}}),
    );
    let output = cli.run(&["team", "list"], None);
    successful(&output);
    for expected in [TEAM, OTHER, "Family", "Work"] {
        assert!(text(&output.stdout).contains(expected));
    }
    successful(&cli.run(&["team", "use", OTHER], None));
    assert_eq!(settings(&cli)["current"], OTHER);
    assert!(mock.requests().is_empty());
    successful(&cli.run(&["me", "--team", TEAM], None));
    assert_eq!(
        mock.requests()[0].header("Authorization"),
        Some(format!("Bearer {MEMBER_TOKEN}").as_str())
    );
    let cli = cli.with("APASSY_TEAM", TEAM);
    successful(&cli.run(&["me"], None));
    assert_eq!(
        mock.requests()[1].header("Authorization"),
        Some(format!("Bearer {MEMBER_TOKEN}").as_str())
    );
}

#[test]
fn device_auth_signs_the_exact_origin_team_key_nonce_message_and_keeps_tokens_in_memory() {
    let mock = Mock::start(|request, _| auth_answer(request).unwrap_or_else(|| ok(me())));
    let cli = Cli::new().with("APASSY_EDGE_SECRET", EDGE);
    let key = seed_device(&cli, &mock.url);
    let before = std::fs::read(cli.settings_file()).unwrap();
    for _ in 0..2 {
        successful(&cli.run(&["me"], None));
    }
    let requests = mock.requests();
    assert_eq!(requests.len(), 6);
    for request in requests.iter().filter(|r| r.url == "/v1/auth/token") {
        let body = request.json();
        assert_eq!(body["team_id"], TEAM);
        assert_eq!(body["public_key"], key.public_key_b64());
        let nonce = body["nonce"].as_str().unwrap();
        assert_eq!(hostkeys::decode_b64(nonce, 32).unwrap(), [5u8; 32]);
        let signature = hostkeys::decode_b64(body["signature"].as_str().unwrap(), 72).unwrap();
        let message = device::sign_in_message(&mock.url, &team(), &key.public_key_b64(), nonce);
        assert!(device::verify(&key.public_key(), &message, &signature));
        assert!(request.header("Authorization").is_none());
    }
    for request in requests.iter().filter(|r| r.url == "/v1/me") {
        assert_eq!(
            request.header("Authorization"),
            Some(format!("Bearer {ACCESS}").as_str())
        );
    }
    assert_eq!(std::fs::read(cli.settings_file()).unwrap(), before);
    assert_private(&cli, &key.public_key_b64());
}

#[test]
fn an_origin_mismatch_stops_before_the_signature_or_member_request() {
    let mock = Mock::always(
        200,
        json!({"nonce":hostkeys::encode_b64(&[5u8;32]),
        "expires_at":4_000_000_000u64,"origin":"https://wrong.example.test"}),
    );
    let cli = Cli::new();
    seed_device(&cli, &mock.url);
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 2);
    let stderr = text(&output.stderr);
    assert!(stderr.contains("https://wrong.example.test"));
    assert!(stderr.contains(&mock.url));
    assert_eq!(mock.requests().len(), 1);
    assert_eq!(mock.requests()[0].url, "/v1/auth/challenge");
}

#[test]
fn a_401_signs_in_and_repeats_the_member_call_once_then_fails() {
    let mock = Mock::start(|request, _| {
        auth_answer(request)
            .unwrap_or_else(|| err(401, "unauthenticated", "The access token is not valid."))
    });
    let cli = Cli::new();
    seed_device(&cli, &mock.url);
    let output = cli.run(&["me"], None);
    assert_eq!(code(&output), 4);
    let requests = mock.requests();
    assert_eq!(
        requests.iter().map(|r| r.url.as_str()).collect::<Vec<_>>(),
        vec![
            "/v1/auth/challenge",
            "/v1/auth/token",
            "/v1/me",
            "/v1/auth/challenge",
            "/v1/auth/token",
            "/v1/me"
        ]
    );
    assert!(!text(&output.stderr).contains(ACCESS));
}

#[test]
fn a_401_retry_can_succeed_with_a_new_access_token() {
    let calls = Arc::new(Mutex::new(0));
    let count = calls.clone();
    let mock = Mock::start(move |request, _| {
        if let Some(answer) = auth_answer(request) {
            return answer;
        }
        let mut calls = count.lock().unwrap();
        *calls += 1;
        if *calls == 1 {
            err(401, "unauthenticated", "The access token expired.")
        } else {
            ok(me())
        }
    });
    let cli = Cli::new();
    seed_device(&cli, &mock.url);
    successful(&cli.run(&["me"], None));
    assert_eq!(*calls.lock().unwrap(), 2);
    assert_eq!(
        mock.requests()
            .iter()
            .filter(|r| r.url == "/v1/auth/token")
            .count(),
        2
    );
}

#[test]
fn file_key_store_refuses_public_permissions_symlinks_and_key_replacement() {
    use apassy_relay::cli::devicekey::{FileKeyStore, KeyStore};
    let cli = Cli::new();
    let store = FileKeyStore::new(cli.settings_file().parent().unwrap().to_owned());
    let relay = "https://relay.example.test";
    let key = device::DeviceKey::generate().unwrap();
    store.save(relay, &team(), &key).unwrap();
    let before = std::fs::read(store.path(&team())).unwrap();
    assert_eq!(
        std::fs::metadata(store.path(&team()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(
        store
            .save(relay, &team(), &device::DeviceKey::generate().unwrap())
            .is_err()
    );
    assert_eq!(std::fs::read(store.path(&team())).unwrap(), before);
    std::fs::set_permissions(store.path(&team()), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load(relay, &team()).is_err());
    store.remove(relay, &team()).unwrap();
    let target = cli.home.path().join("synthetic-key");
    std::fs::write(&target, &before).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, store.path(&team())).unwrap();
    assert!(store.load(relay, &team()).is_err());
    assert!(store.save(relay, &team(), &key).is_err());
    assert_eq!(std::fs::read(target).unwrap(), before);
}

#[test]
fn a_failed_join_request_checks_pending_auth_and_replays_the_exact_body_and_key() {
    let cli = Cli::new();
    let mock = Mock::start(|request, index| match index {
        0 => raw(502, "<html>lost response</html>"),
        1 => err(403, "join_pending", "The join waits."),
        _ if request.url == "/v1/join" => pending(request),
        _ => err(500, "unexpected", "No sign-in for --no-wait."),
    });
    successful(&cli.run(
        &[
            "join",
            "--relay",
            &mock.url,
            "--name",
            "bob",
            "--device",
            "Laptop",
            "--no-wait",
        ],
        Some(INVITE),
    ));
    let requests = mock.requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.as_str())
            .collect::<Vec<_>>(),
        ["/v1/join", "/v1/auth/challenge", "/v1/join"]
    );
    assert_eq!(requests[0].body, requests[2].body);
    let public = requests[0].json()["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(requests[1].json()["public_key"], public);
    assert_private(&cli, &public);
    assert!(
        !std::fs::read_to_string(cli.settings_file())
            .unwrap()
            .contains(INVITE)
    );
}

#[test]
fn a_live_key_after_a_lost_join_response_still_replays_pending_and_checks_safety_before_sign_in() {
    let cli = Cli::new();
    let mock = Mock::start(|request, index| {
        if index == 0 {
            return raw(502, "<html>lost response</html>");
        }
        if request.url == "/v1/auth/challenge" {
            return auth_answer(request).unwrap();
        }
        if request.url == "/v1/join" {
            return ok(json!({"id":7,"team_id":TEAM,"team":"Family",
            "by":"alice","safety":"not valid","expires_at":4_000_000_000u64}));
        }
        err(500, "unexpected", "The safety mismatch must stop sign-in.")
    });
    let output = cli.run(
        &["join", "--relay", &mock.url, "--name", "bob"],
        Some(INVITE),
    );
    assert_eq!(code(&output), 2, "{}", text(&output.stderr));
    let requests = mock.requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.url.as_str())
            .collect::<Vec<_>>(),
        ["/v1/join", "/v1/auth/challenge", "/v1/join"]
    );
    assert_eq!(requests[0].body, requests[2].body);
    assert!(
        !requests
            .iter()
            .any(|request| request.url == "/v1/auth/token")
    );
}

#[test]
fn a_safety_mismatch_cannot_be_bypassed_with_resume_without_resupplying_the_code() {
    let mock = Mock::always(
        200,
        json!({"id":7,"team_id":TEAM,"team":"Family","by":"alice",
        "safety":"not valid","expires_at":4_000_000_000u64}),
    );
    let cli = Cli::new();
    let output = cli.run(
        &["join", "--relay", &mock.url, "--name", "bob"],
        Some(INVITE),
    );
    assert_eq!(code(&output), 2);
    let before = mock.requests().len();
    let key = std::fs::read(key_path(&cli)).unwrap();
    let output = cli.run(&["--team", TEAM, "join", "--resume"], None);
    assert_eq!(code(&output), 2, "{}", text(&output.stderr));
    assert_eq!(
        mock.requests().len(),
        before,
        "unverified safety must stop before HTTP"
    );
    assert_eq!(std::fs::read(key_path(&cli)).unwrap(), key);
    let recovery = key_path(&cli)
        .parent()
        .unwrap()
        .join(format!("recovery-{TEAM}.json"));
    assert!(recovery.exists());
    let body = std::fs::read_to_string(recovery).unwrap();
    assert!(!body.contains(INVITE));
    let recovery: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(recovery["blocked"], true);
    assert_eq!(settings(&cli)["teams"][TEAM]["safety_verified"], false);
    let output = cli.run(&["--team", TEAM, "device", "enroll"], None);
    assert_eq!(code(&output), 2, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("safety check"));
    assert_eq!(mock.requests().len(), before);
    assert_eq!(std::fs::read(key_path(&cli)).unwrap(), key);
}

#[test]
fn an_unknown_join_result_can_resume_with_the_original_code_and_saved_key() {
    let mock = Mock::start(|request, index| match index {
        0 | 2 => raw(502, "<html>lost response</html>"),
        1 => err(401, "unauthenticated", "The request is not known."),
        _ if request.url == "/v1/join" => pending(request),
        _ => auth_answer(request).unwrap_or_else(|| err(500, "unexpected", "Unexpected request.")),
    });
    let cli = Cli::new();
    let output = cli.run(
        &[
            "join",
            "--relay",
            &mock.url,
            "--name",
            "bob",
            "--device",
            "Laptop",
            "--no-wait",
        ],
        Some(INVITE),
    );
    assert_eq!(code(&output), 4, "{}", text(&output.stderr));
    assert_eq!(settings(&cli)["teams"][TEAM]["safety_verified"], false);
    let key = std::fs::read(key_path(&cli)).unwrap();
    let requests_before = mock.requests().len();
    let output = cli.run(&["--team", TEAM, "join", "--resume"], None);
    assert_eq!(code(&output), 2);
    assert_eq!(
        mock.requests().len(),
        requests_before,
        "the original code is required before HTTP"
    );
    let output = cli.run(&["--team", TEAM, "join", "--resume"], Some(INVITE));
    successful(&output);
    assert_eq!(std::fs::read(key_path(&cli)).unwrap(), key);
    let posts = mock
        .requests()
        .into_iter()
        .filter(|r| r.url == "/v1/join")
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 3);
    assert!(posts.iter().all(|request| request.body == posts[0].body));
    assert!(format!("{}{}", text(&output.stdout), text(&output.stderr)).contains("Joined"));
    for entry in std::fs::read_dir(cli.settings_file().parent().unwrap()).unwrap() {
        let content = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(!content.contains(INVITE));
        assert!(!content.contains(ACCESS));
    }
}

#[test]
fn a_failed_recovery_probe_preserves_the_key_for_a_later_process_with_the_original_code() {
    let mock = Mock::start(|request, index| {
        if index <= 1 {
            return raw(502, "<html>relay unavailable</html>");
        }
        if request.url == "/v1/join" {
            pending(request)
        } else {
            auth_answer(request).unwrap()
        }
    });
    let cli = Cli::new();
    let output = cli.run(
        &[
            "join",
            "--relay",
            &mock.url,
            "--name",
            "bob",
            "--device",
            "Laptop",
            "--no-wait",
        ],
        Some(INVITE),
    );
    assert_eq!(code(&output), 4);
    let before = std::fs::read(key_path(&cli)).unwrap();
    assert_eq!(settings(&cli)["teams"][TEAM]["safety_verified"], false);
    assert_eq!(mock.requests().len(), 2);
    successful(&cli.run(&["--team", TEAM, "join", "--resume"], Some(INVITE)));
    assert_eq!(std::fs::read(key_path(&cli)).unwrap(), before);
    let posts = mock
        .requests()
        .into_iter()
        .filter(|request| request.url == "/v1/join")
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].body, posts[1].body);
    assert_private(&cli, posts[0].json()["public_key"].as_str().unwrap());
}

#[test]
fn host_refuses_an_owner_device_that_does_not_hold_the_keys_before_poll_or_dialog() {
    let mock = Mock::start(|request, _| {
        if let Some(answer) = auth_answer(request) {
            return answer;
        }
        let mut result = me();
        result["device_id"] = json!(3);
        result["key_holder"] = json!(false);
        ok(result)
    });
    let cli = Cli::new();
    seed_device(&cli, &mock.url);
    let output = cli.run(&["host"], None);
    assert_eq!(code(&output), 2, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("not the key holder"));
    assert!(text(&output.stderr).contains("keys.json"));
    assert_eq!(
        mock.requests()
            .iter()
            .map(|request| request.url.as_str())
            .collect::<Vec<_>>(),
        ["/v1/auth/challenge", "/v1/auth/token", "/v1/me"]
    );
}

#[test]
fn host_exits_with_a_clear_error_when_the_relay_removes_the_key_holder_flag() {
    let mock = Mock::start(|request, _| {
        if let Some(answer) = auth_answer(request) {
            return answer;
        }
        if request.url == "/v1/me" {
            let mut result = me();
            result["device_id"] = json!(3);
            result["key_holder"] = json!(true);
            return ok(result);
        }
        err(403, "not_key_holder", "This device is not the key holder.")
    });
    let cli = Cli::new();
    seed_device(&cli, &mock.url);
    let output = cli.run(&["host"], None);
    assert_eq!(code(&output), 4, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("This device is not the key holder."));
    let requests = mock.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[3].url.starts_with("/v1/host/requests?wait="));
    assert_eq!(
        requests[3].header("Authorization"),
        Some(format!("Bearer {ACCESS}").as_str())
    );
    for secret in [MEMBER_TOKEN, ACCESS, INVITE, LINK] {
        assert!(!text(&output.stdout).contains(secret));
        assert!(!text(&output.stderr).contains(secret));
    }
}

#[test]
fn legacy_leave_migrates_before_the_relay_invalidates_the_member_token() {
    let mock = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            ok(me())
        } else {
            ok(json!({"id":1}))
        }
    });
    let cli = Cli::new();
    write_settings(
        &cli,
        json!({"relay_url":mock.url,"member_token":MEMBER_TOKEN}),
    );
    successful(&cli.run(&["leave"], None));
    assert_eq!(settings(&cli)["version"], 2);
    assert!(settings(&cli)["teams"].as_object().unwrap().is_empty());
    let requests = mock.requests();
    assert_eq!(requests.last().unwrap().url, "/v1/leave");
}

#[test]
fn host_stops_when_sign_in_after_a_401_refuses_the_device() {
    let mock = Mock::start(|request, index| {
        if request.url == "/v1/auth/challenge" && index >= 4 {
            return err(401, "unauthenticated", "The device was revoked.");
        }
        if let Some(answer) = auth_answer(request) {
            return answer;
        }
        if request.url == "/v1/me" {
            let mut result = me();
            result["device_id"] = json!(3);
            result["key_holder"] = json!(true);
            return ok(result);
        }
        if index == 3 {
            return err(401, "unauthenticated", "The access token ended.");
        }
        err(403, "forbidden", "The host cannot continue.")
    });
    let cli = Cli::new();
    seed_device(&cli, &mock.url);
    let output = cli.run(&["host"], None);
    assert_eq!(code(&output), 4, "{}", text(&output.stderr));
    assert!(text(&output.stderr).contains("device was revoked"));
    assert_eq!(mock.requests().len(), 5);
}

#[test]
fn enroll_http_errors_remove_the_key_and_allow_a_retry() {
    for status in [200, 400, 401, 403, 404, 409, 429, 500, 503] {
        let mock = Mock::start(move |request, index| {
            if request.url == "/v1/me" {
                ok(me())
            } else if index == 1 {
                if status == 200 {
                    err(200, "relay_error", "The relay refused enrollment.")
                } else {
                    raw(status, "HTTP error without an envelope")
                }
            } else {
                ok(device_view())
            }
        });
        let cli = Cli::new();
        write_settings(
            &cli,
            json!({"version":2,"current":TEAM,"teams":{TEAM:{
            "relay_url":mock.url,"member_token":MEMBER_TOKEN,"device_id":null}}}),
        );
        let output = cli.run(&["device", "enroll", "--name", "Laptop"], None);
        assert_eq!(code(&output), 4, "HTTP {status}: {}", text(&output.stderr));
        assert!(
            !key_path(&cli).exists(),
            "HTTP {status} must remove the key"
        );
        assert_eq!(settings(&cli)["teams"][TEAM]["member_token"], MEMBER_TOKEN);
        successful(&cli.run(&["device", "enroll", "--name", "Laptop"], None));
        assert_eq!(settings(&cli)["teams"][TEAM]["device_id"], 3);
    }
}

#[test]
fn enroll_resumes_a_saved_key_before_using_an_expired_member_token() {
    let mock = Mock::start(|request, _| {
        auth_answer(request)
            .unwrap_or_else(|| err(401, "unauthenticated", "The member token has ended."))
    });
    let cli = Cli::new();
    let key = seed_device(&cli, &mock.url);
    let mut saved = settings(&cli);
    saved["teams"][TEAM]["device_id"] = Value::Null;
    saved["teams"][TEAM]["member_token"] = json!(MEMBER_TOKEN);
    write_settings(&cli, saved);
    let before = std::fs::read(key_path(&cli)).unwrap();
    let output = cli.run(&["device", "enroll"], None);
    successful(&output);
    assert!(text(&output.stdout).contains("Enrolled"));
    assert_eq!(std::fs::read(key_path(&cli)).unwrap(), before);
    assert_eq!(
        mock.requests()
            .iter()
            .map(|r| r.url.as_str())
            .collect::<Vec<_>>(),
        ["/v1/auth/challenge", "/v1/auth/token"]
    );
    assert_eq!(
        mock.requests()[0].json()["public_key"],
        key.public_key_b64()
    );
    assert_eq!(settings(&cli)["teams"][TEAM]["device_id"], 3);
    assert!(settings(&cli)["teams"][TEAM]["member_token"].is_null());
}

#[test]
fn enroll_retries_an_unknown_device_with_the_same_saved_key() {
    let mock = Mock::start(|request, _| match request.url.as_str() {
        "/v1/auth/challenge" => err(401, "unauthenticated", "No such device."),
        "/v1/me" => ok(me()),
        "/v1/devices/enroll" => ok(device_view()),
        _ => err(500, "unexpected", "Unexpected request."),
    });
    let cli = Cli::new();
    let key = seed_device(&cli, &mock.url);
    let mut saved = settings(&cli);
    saved["teams"][TEAM]["device_id"] = Value::Null;
    saved["teams"][TEAM]["member_token"] = json!(MEMBER_TOKEN);
    write_settings(&cli, saved);
    let before = std::fs::read(key_path(&cli)).unwrap();
    successful(&cli.run(&["device", "enroll", "--name", "Laptop"], None));
    assert_eq!(std::fs::read(key_path(&cli)).unwrap(), before);
    let requests = mock.requests();
    assert_eq!(
        requests.iter().map(|r| r.url.as_str()).collect::<Vec<_>>(),
        ["/v1/auth/challenge", "/v1/me", "/v1/devices/enroll"]
    );
    assert_eq!(requests[2].json()["public_key"], key.public_key_b64());
}

#[test]
fn pending_join_and_link_do_not_change_the_current_team() {
    for link in [false, true] {
        let mock = Mock::start(|request, _| pending(request));
        let cli = Cli::new();
        write_settings(
            &cli,
            json!({"version":2,"current":OTHER,"teams":{OTHER:{
            "relay_url":mock.url,"device_id":9}}}),
        );
        let args = if link {
            vec!["device", "link", "--relay", &mock.url, "--no-wait"]
        } else {
            vec!["join", "--relay", &mock.url, "--name", "bob", "--no-wait"]
        };
        successful(&cli.run(&args, Some(if link { LINK } else { INVITE })));
        assert_eq!(settings(&cli)["current"], OTHER);
        assert!(settings(&cli)["teams"][TEAM]["device_id"].is_null());
    }
}

#[test]
fn enroll_transport_failure_keeps_the_key_for_a_retry() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = format!("http://{}", listener.local_addr().unwrap());
    let public_keys = Arc::new(Mutex::new(Vec::new()));
    let seen = public_keys.clone();
    let thread = std::thread::spawn(move || {
        for index in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            if index == 1 || index == 4 {
                let body: Value = serde_json::from_slice(&body).unwrap();
                seen.lock()
                    .unwrap()
                    .push(body["public_key"].as_str().unwrap().to_owned());
            }
            if index == 1 {
                continue;
            } // Connection closes before any HTTP answer.
            let answer = if index == 2 {
                err(401, "unauthenticated", "No such device.")
            } else if index == 4 {
                ok(device_view())
            } else {
                ok(me())
            };
            write!(stream, "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                answer.status, answer.body.len(), answer.body).unwrap();
        }
    });
    let cli = Cli::new();
    write_settings(
        &cli,
        json!({"version":2,"current":TEAM,"teams":{TEAM:{
        "relay_url":relay,"member_token":MEMBER_TOKEN,"device_id":null}}}),
    );
    let output = cli.run(&["device", "enroll", "--name", "Laptop"], None);
    assert_eq!(code(&output), 4);
    assert!(text(&output.stderr).contains("device enroll"));
    assert!(!text(&output.stderr).contains("join --resume"));
    let before = std::fs::read(key_path(&cli)).unwrap();
    assert_eq!(settings(&cli)["teams"][TEAM]["member_token"], MEMBER_TOKEN);
    successful(&cli.run(&["device", "enroll", "--name", "Laptop"], None));
    thread.join().unwrap();
    assert_eq!(std::fs::read(key_path(&cli)).unwrap(), before);
    let keys = public_keys.lock().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
}

#[test]
fn a_finished_join_or_link_selects_the_team_only_after_sign_in() {
    for link in [false, true] {
        let mock = Mock::start(|request, _| match request.url.as_str() {
            "/v1/join" | "/v1/devices/link" => pending(request),
            _ => auth_answer(request).unwrap(),
        });
        let cli = Cli::new();
        write_settings(
            &cli,
            json!({"version":2,"current":OTHER,"teams":{OTHER:{
            "relay_url":mock.url,"device_id":9}}}),
        );
        let args = if link {
            vec!["device", "link", "--relay", &mock.url]
        } else {
            vec!["join", "--relay", &mock.url, "--name", "bob"]
        };
        successful(&cli.run(&args, Some(if link { LINK } else { INVITE })));
        assert_eq!(settings(&cli)["current"], TEAM);
        assert_eq!(settings(&cli)["teams"][TEAM]["device_id"], 3);
        assert!(
            mock.requests()
                .iter()
                .any(|request| request.url == "/v1/auth/token")
        );
    }
}

#[test]
fn init_and_enroll_do_not_change_the_current_team() {
    let mock = Mock::start(|request, _| {
        if request.url == "/v1/me" {
            ok(me())
        } else {
            ok(device_view())
        }
    });
    let cli = Cli::new();
    write_settings(
        &cli,
        json!({"version":2,"current":OTHER,"teams":{OTHER:{
        "relay_url":mock.url,"device_id":9}}}),
    );
    successful(&cli.run(&["init", "--relay", &mock.url], Some(MEMBER_TOKEN)));
    assert_eq!(settings(&cli)["current"], OTHER);
    successful(&cli.run(&["--team", TEAM, "device", "enroll"], None));
    assert_eq!(settings(&cli)["current"], OTHER);
    assert_eq!(settings(&cli)["teams"][TEAM]["device_id"], 3);
}
