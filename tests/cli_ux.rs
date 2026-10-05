//! CLI UX checks use an isolated socket and never open the desktop app.
#![cfg(all(feature = "desktop", feature = "vault"))]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output};

use apassy::owner::wire::{Data, Response, StatusView, VaultState};
use tempfile::TempDir;

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_apassy"))
        .args(args)
        .env_remove("APASSY_SESSION")
        .env_remove("APASSY_OWNER_SOCKET")
        .output()
        .expect("run the CLI")
}

#[test]
fn complete_help_paths_and_unknown_subjects_have_correct_exit_codes() {
    let direct = cli(&["help", "item", "show"]);
    assert_eq!(direct.status.code(), Some(0));
    let text = String::from_utf8(direct.stdout).unwrap();
    assert!(text.contains("apassy item show ITEM"));
    assert!(text.contains("Example:"));
    assert!(!text.contains("apassy item list"));
    let flag = cli(&["item", "show", "Example API", "--help"]);
    assert_eq!(flag.status.code(), Some(0));
    assert_eq!(String::from_utf8(flag.stdout).unwrap(), text);
    for args in [
        vec!["help", "setup", "codex"],
        vec!["agent", "setup", "codex", "--help"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("apassy setup codex")
        );
    }
    let unknown = cli(&["help", "nonsense", "--json"]);
    assert_eq!(unknown.status.code(), Some(2));
    let response: Response = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(response.code, "usage");
    assert!(response.message.contains("nonsense"));
    assert!(response.message.contains("Valid subjects:"));
    assert!(unknown.stderr.is_empty());
    let unknown = cli(&["help", "item", "nonsense"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stdout.is_empty());
    assert!(
        String::from_utf8(unknown.stderr)
            .unwrap()
            .contains("item nonsense")
    );
}

#[test]
fn a_missing_custom_socket_names_the_socket_and_connection_error() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("absent.sock");
    let listening = dir.path().join("owner.sock");
    let server = status_server(&listening);
    let default = Command::new(env!("CARGO_BIN_EXE_apassy"))
        .args(["status", "--json"])
        .env_remove("APASSY_SESSION")
        .env("APASSY_OWNER_SOCKET", &listening)
        .output()
        .unwrap();
    server.join().unwrap();
    assert_eq!(default.status.code(), Some(0));
    let status: Response = serde_json::from_slice(&default.stdout).unwrap();
    assert!(status.ok);
    let output = cli(&["status", "--socket", socket.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let response: Response = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response.code, "not_running");
    assert!(response.message.contains(socket.to_str().unwrap()));
    assert!(response.message.contains("No such file"));
    assert!(response.message.contains("Check the socket path"));
    assert!(!response.message.contains("Apassy is not running"));
}

fn status_server(socket: &Path) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(request["session"].is_null());
        let response = Response::ok(
            "Status",
            Data::Status(StatusView {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                vault: VaultState::Locked,
                vault_path: None,
                broker: "stopped for test".to_owned(),
                broker_socket: None,
                touch_id: false,
                session: false,
                waiting_runs: None,
                open_requests: None,
                items_to_review: None,
            }),
        );
        let mut stream = stream;
        serde_json::to_writer(&mut stream, &response).unwrap();
        stream.write_all(b"\n").unwrap();
    })
}

#[test]
fn doctor_json_session_fix_has_shell_quotes_without_extra_backslashes() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("owner.sock");
    let server = status_server(&socket);
    let output = Command::new(env!("CARGO_BIN_EXE_apassy"))
        .args(["doctor", "--json", "--socket", socket.to_str().unwrap()])
        .env_remove("APASSY_SESSION")
        .env_remove("CLAUDECODE")
        .env("HOME", dir.path())
        .env("CODEX_HOME", dir.path().join("codex"))
        .current_dir(dir.path())
        .output()
        .unwrap();
    server.join().unwrap();
    // Doctor emits its report, followed by a failure response when a check fails.
    let mut values =
        serde_json::Deserializer::from_slice(&output.stdout).into_iter::<serde_json::Value>();
    let report = values.next().unwrap().unwrap();
    let session = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "Session")
        .unwrap();
    let fix = session["fix"].as_str().unwrap();
    assert_eq!(
        fix,
        "eval \"$(apassy login)\" for item, agent, and grant commands."
    );
    assert!(!fix.contains('\\'));
    let command = fix.split(" for item").next().unwrap();
    let inert = command.replace(
        "apassy login",
        "printf 'export APASSY_UX_SYNTHETIC=example'",
    );
    let shell = Command::new("/bin/sh")
        .args([
            "-c",
            &format!("{inert}; test \"$APASSY_UX_SYNTHETIC\" = example"),
        ])
        .output()
        .unwrap();
    assert!(
        shell.status.success(),
        "{}",
        String::from_utf8_lossy(&shell.stderr)
    );
}
