//! Native dialog tests use executable fixtures. No GUI or relay is contacted.
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use apassy_relay::api::{HostItem, HostRequestView, Suggestion};
use apassy_relay::cli::host::{
    Answer, Asker, DialogAsker, DialogKind, dialog_text, lock_host, render_request,
};
use apassy_relay::cli::keystore::KeyEntry;
use apassy_relay::ids::{ItemId, RunId};
use apassy_relay::secret::SecretString;

fn request() -> HostRequestView {
    HostRequestView {
        run_id: RunId(7),
        agent: "agent".into(),
        member: "member".into(),
        items: vec![],
        command: vec!["git".into(), "status".into()],
        purpose: "check".into(),
        user_request: None,
        cwd: None,
        ttl_secs: 60,
        flags: vec![],
        suggestion: Suggestion::Ask,
        note: "ask".into(),
        run_key: String::new(),
        expires_at: apassy_relay::now_unix() + 60,
    }
}

fn program(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("fake-dialog");
    std::fs::write(&path, format!("#!/usr/bin/python3\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn only_the_exact_mac_release_result_with_success_releases() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        ("release", 0, Answer::Yes),
        ("deny", 0, Answer::No),
        ("timeout", 0, Answer::Expired),
        ("garbage", 0, Answer::No),
        (" release", 0, Answer::No),
        ("release\ndeny", 0, Answer::No),
        ("release\n", 0, Answer::No),
        ("release", 1, Answer::No),
        ("release", 128, Answer::No),
        ("", 0, Answer::No),
    ];
    for (output, code, expected) in cases {
        let body = format!(
            "import sys\nprint({})\nsys.exit({code})",
            serde_json::to_string(output).unwrap()
        );
        let path = program(dir.path(), &body);
        assert_eq!(
            DialogAsker::with_program(path, DialogKind::MacOs).ask(&request(), &[], "why"),
            expected,
            "output={output:?}, code={code}"
        );
    }
    let path = program(dir.path(), "import sys\nsys.stdout.write('release')");
    assert_eq!(
        DialogAsker::with_program(path, DialogKind::MacOs).ask(&request(), &[], "why"),
        Answer::Yes
    );
    assert_eq!(
        DialogAsker::with_program(dir.path().join("missing"), DialogKind::MacOs).ask(
            &request(),
            &[],
            "why"
        ),
        Answer::NoTerminal
    );
}

#[test]
fn zenity_uses_exit_codes_and_requires_default_cancel_and_no_markup() {
    let dir = tempfile::tempdir().unwrap();
    for (code, expected) in [
        (0, Answer::Yes),
        (1, Answer::No),
        (5, Answer::Expired),
        (2, Answer::No),
    ] {
        let path = program(
            dir.path(),
            &format!(
                "import sys\nassert '--default-cancel' in sys.argv\nassert '--no-markup' in sys.argv\nassert sys.argv[sys.argv.index('--ok-label')+1] == 'Release'\nassert sys.argv[sys.argv.index('--cancel-label')+1] == 'Deny'\nsys.exit({code})"
            ),
        );
        assert_eq!(
            DialogAsker::with_program(path, DialogKind::Zenity).ask(&request(), &[], "why"),
            expected
        );
    }
    assert_eq!(
        DialogAsker::with_program(dir.path().join("missing"), DialogKind::Zenity).ask(
            &request(),
            &[],
            "why"
        ),
        Answer::NoTerminal
    );
}

#[test]
fn untrusted_text_is_one_argument_and_the_script_is_fixed() {
    let dir = tempfile::tempdir().unwrap();
    let capture = dir.path().join("argv.json");
    let path = program(
        dir.path(),
        &format!(
            "import json,sys,os\nwith open({}, 'w') as f: json.dump([sys.argv,dict(os.environ)], f)\nprint('deny')",
            serde_json::to_string(capture.to_str().unwrap()).unwrap()
        ),
    );
    let hostile = "quotes \" and \\ and \" & do shell script \"touch /tmp/x\" & \"\nnext\u{1b}";
    let mut r = request();
    r.command.push(hostile.into());
    r.purpose = hostile.into();
    r.user_request = Some(hostile.into());
    r.cwd = Some(hostile.into());
    r.agent = hostile.into();
    r.member = hostile.into();
    let entry = KeyEntry {
        team_id: apassy_relay::ids::TeamId::parse("t_abcdefgh23"),
        relay_url: "https://relay.example.test".into(),
        team: "test".into(),
        uid: "00".repeat(16),
        item_id: Some(1),
        name: hostile.into(),
        env_name: hostile.into(),
        environment: hostile.into(),
        hosts: vec![hostile.into()],
        risk: "low".into(),
        scope: "read".into(),
        reversibility: "reversible".into(),
        key: SecretString::new("not-used".into()),
        created_at: 1,
    };
    r.items.push(HostItem {
        uid: entry.uid.clone(),
        id: ItemId(1),
        name: hostile.into(),
        env_name: hostile.into(),
    });
    let before = apassy_relay::now_unix();
    let mut scripts = Vec::new();
    for kind in [DialogKind::MacOs, DialogKind::Zenity] {
        let mut asker = DialogAsker::with_program(&path, kind);
        let answer = asker.ask(&r, &[&entry], hostile);
        assert_eq!(
            answer,
            if matches!(kind, DialogKind::MacOs) {
                Answer::No
            } else {
                Answer::Yes
            }
        );
        let capture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&capture).unwrap()).unwrap();
        let argv: Vec<&str> = capture[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let text = match kind {
            DialogKind::MacOs => {
                assert_eq!(argv.len(), 7);
                assert_eq!(argv[1], "-e");
                assert_eq!(argv[3], "--");
                assert!(!argv[2].contains("touch /tmp/x"));
                assert!(argv[2].contains("default button \"Deny\""));
                assert!(argv[2].contains("cancel button \"Deny\""));
                assert!(!argv[2].contains("do shell script"));
                scripts.push(argv[2].to_string());
                argv[4]
            }
            DialogKind::Zenity => argv[argv.iter().position(|arg| *arg == "--text").unwrap() + 1],
        };
        assert!(
            (before..=apassy_relay::now_unix())
                .any(|now| text == render_request(&r, &[&entry], hostile, now))
        );
        assert!(text.contains("touch /tmp/x"));
        assert!(text.contains("\\nnext\\u{1b}"));
        assert!(!text.contains('\u{1b}'));
        for name in [
            "APASSY_TOKEN",
            "APASSY_TEAM_TOKEN",
            "APASSY_EDGE_SECRET",
            "PATH",
        ] {
            assert!(capture[1].get(name).is_none(), "unexpected env {name}");
        }
    }
    let mut asker = DialogAsker::with_program(&path, DialogKind::MacOs);
    assert_eq!(asker.ask(&request(), &[], "ordinary"), Answer::No);
    let capture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&capture).unwrap()).unwrap();
    assert_eq!(capture[0][2], scripts[0]);
}

#[test]
fn dialog_text_is_bounded_and_short_expiry_never_opens_a_program() {
    let large = "é".repeat(4000);
    let cut = dialog_text(&large);
    assert_eq!(cut.chars().count(), 3000);
    assert!(cut.ends_with("\n(cut)"));
    assert_eq!(dialog_text("short"), "short");
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("opened");
    let path = program(
        dir.path(),
        &format!(
            "open({},'w').close()\nprint('release')",
            serde_json::to_string(marker.to_str().unwrap()).unwrap()
        ),
    );
    let mut r = request();
    r.expires_at = apassy_relay::now_unix() + 4;
    assert_eq!(
        DialogAsker::with_program(path, DialogKind::MacOs).ask(&r, &[], "why"),
        Answer::Expired
    );
    assert!(!marker.exists());
}

#[test]
fn a_program_that_ignores_the_timeout_cannot_release_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = program(dir.path(), "import time\ntime.sleep(10)\nprint('release')");
    let mut r = request();
    // A fake dialog takes a duration below the five seconds of a real one.
    r.expires_at = apassy_relay::now_unix() + 2;
    let start = std::time::Instant::now();
    assert_eq!(
        DialogAsker::with_program(path, DialogKind::MacOs)
            .with_minimum_seconds(1)
            .ask(&r, &[], "why"),
        Answer::Expired
    );
    assert!(start.elapsed() < std::time::Duration::from_secs(7));
}

#[test]
fn second_host_refuses_before_it_can_contact_a_relay() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("apassy-team");
    let first = lock_host(&config).unwrap();
    assert_eq!(
        std::fs::metadata(config.join("host.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let error = lock_host(&config).unwrap_err();
    assert_eq!(error.code, 2);
    assert!(error.message.contains("already runs"));
    for args in [vec!["host"], vec!["host", "--dialog"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_apassy-team"))
            .args(args)
            .env_clear()
            .env("XDG_CONFIG_HOME", dir.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("already runs"));
    }
    // A different config has an independent lock, and exit releases the first.
    let _other = lock_host(&dir.path().join("other")).unwrap();
    drop(first);
    let _again = lock_host(&config).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn generated_plist_passes_the_mac_validator() {
    use apassy_relay::cli::host::HostOptions;
    use apassy_relay::cli::service::generate_plist;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("team-host.plist");
    let xml = generate_plist(
        Path::new("/Applications/a &<>'\"/apassy-team"),
        &apassy_relay::ids::TeamId::parse("t_abcdefgh23").unwrap(),
        HostOptions {
            ask_all: true,
            auto_limit: 0,
        },
        Path::new("/Users/a &<>'\"/Library/Logs/apassy-team-host.log"),
        Some("/tmp/config &<>'\""),
    )
    .unwrap();
    std::fs::write(&path, xml).unwrap();
    let output = Command::new("/usr/bin/plutil")
        .arg("-lint")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "plutil -lint: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
}

#[test]
fn team_host_locks_allow_two_teams_but_fence_duplicates_and_legacy_hosts() {
    use apassy_relay::cli::host::lock_team_host;
    use apassy_relay::ids::TeamId;
    let dir = tempfile::tempdir().unwrap();
    let a = TeamId::parse("t_abcdefgh23").unwrap();
    let b = TeamId::parse("t_abcdefgh24").unwrap();
    let first = lock_team_host(dir.path(), &a).unwrap();
    let second = lock_team_host(dir.path(), &b).unwrap();
    assert!(lock_team_host(dir.path(), &a).is_err());
    assert!(
        lock_host(dir.path()).is_err(),
        "an old binary cannot run beside per-team hosts"
    );
    drop(first);
    assert!(
        lock_host(dir.path()).is_err(),
        "team B still fences old hosts"
    );
    drop(second);
    let old = lock_host(dir.path()).unwrap();
    assert!(
        lock_team_host(dir.path(), &a).is_err(),
        "new binary cannot bypass a running old host"
    );
    drop(old);
    assert!(lock_team_host(dir.path(), &a).is_ok());
}
