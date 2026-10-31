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
fn review_malformed_import_never_contacts_the_owner_socket() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("owner.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let file = dir.path().join("export.csv");
    for tail in ["\"SYNTHETIC-unclosed", "\"SYNTHETIC-closed\"junk"] {
        std::fs::write(
            &file,
            format!("name,password\ngood,SYNTHETIC-pass\nbad,{tail}"),
        )
        .unwrap();
        let output = cli(&[
            "import",
            file.to_str().unwrap(),
            "--format",
            "csv",
            "--socket",
            socket.to_str().unwrap(),
            "--json",
        ]);
        assert!(!output.status.success());
        let reply: Response = serde_json::from_slice(&output.stdout).unwrap();
        assert!(reply.message.contains("Row 3"), "{}", reply.message);
        assert!(!reply.message.contains("SYNTHETIC"));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
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
    // Doctor emits exactly one report even when checks fail.
    let mut values =
        serde_json::Deserializer::from_slice(&output.stdout).into_iter::<serde_json::Value>();
    let report = values.next().unwrap().unwrap();
    assert!(values.next().is_none());
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

/// A fake app that answers one `add` with two summary rows, and returns the request
/// that it read.
fn add_server(socket: &Path) -> std::thread::JoinHandle<serde_json::Value> {
    use apassy::contracts::CredentialKind;
    use apassy::owner::wire::AddedRow;

    let listener = UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        let rows = [
            (2, "Anthropic API key", "ANTHROPIC_API_KEY", "production"),
            (3, "Dev Api Token", "DEV_API_TOKEN", "development"),
        ];
        let items = rows
            .iter()
            .map(|(id, name, variable, environment)| AddedRow {
                id: *id,
                name: (*name).to_owned(),
                kind: CredentialKind::ApiKey,
                variable: Some((*variable).to_owned()),
                environment: (*environment).to_owned(),
                folder: "Work / Acme".to_owned(),
                summary: format!("{name} · {variable} · {environment}"),
            })
            .collect();
        let response = Response::ok("2 credentials are added.", Data::Added { items });
        let mut stream = stream;
        serde_json::to_writer(&mut stream, &response).unwrap();
        stream.write_all(b"\n").unwrap();
        request
    })
}

#[test]
fn add_reads_the_paste_from_stdin_and_prints_one_line_for_each_credential() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("owner.sock");
    let anthropic = "sk-ant-api03-EXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0";
    let text = format!("ANTHROPIC_API_KEY={anthropic}\nDEV_API_TOKEN=plain-dev-0000\n");
    let paste = dir.path().join("paste.env");
    std::fs::write(&paste, &text).unwrap();
    for json in [false, true] {
        let server = add_server(&socket);
        let mut args = vec!["add", "--folder", "Work/Acme", "--socket"];
        args.push(socket.to_str().unwrap());
        if json {
            args.push("--json");
        }
        let output = Command::new(env!("CARGO_BIN_EXE_apassy"))
            .args(&args)
            .env("APASSY_SESSION", "apassy_cli_synthetic-session")
            .env_remove("APASSY_OWNER_SOCKET")
            .stdin(std::fs::File::open(&paste).unwrap())
            .output()
            .unwrap();
        let request = server.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(request["command"]["cmd"], "add");
        assert_eq!(request["command"]["secret"], text.trim_end_matches('\n'));
        assert_eq!(request["command"]["folder"], "Work/Acme");
        assert!(request["command"].get("create_folder").is_none());
        assert_eq!(request["session"], "apassy_cli_synthetic-session");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        for secret in [anthropic, "plain-dev-0000"] {
            assert!(!stdout.contains(secret) && !stderr.contains(secret));
        }
        if json {
            let response: Response = serde_json::from_str(&stdout).unwrap();
            assert!(matches!(response.data, Data::Added { ref items } if items.len() == 2));
        } else {
            assert_eq!(
                stdout,
                "Anthropic API key · ANTHROPIC_API_KEY · production\n\
                 Dev Api Token · DEV_API_TOKEN · development\n"
            );
        }
    }

    // Usage errors come before any connection.
    let missing = dir.path().join("none.sock");
    let empty = dir.path().join("empty.env");
    std::fs::write(&empty, "\n").unwrap();
    for (args, stdin) in [
        (vec!["add", "--create-folder"], &paste),
        (vec!["add"], &empty),
        (vec!["add", "extra"], &paste),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_apassy"))
            .args(&args)
            .args(["--socket", missing.to_str().unwrap()])
            .env_remove("APASSY_SESSION")
            .stdin(std::fs::File::open(stdin).unwrap())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains(anthropic));
    }
    let help = cli(&["help", "add"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("apassy add [--folder PATH")
    );
}

#[test]
fn audit_output_commands_emit_one_json_document_in_scratch_home() {
    let dir = TempDir::new().unwrap();
    for words in [
        vec!["logout", "--json"],
        vec!["doctor", "--json"],
        vec!["setup", "browser", "--json"],
        vec!["decisions", "export", "--json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_apassy"))
            .args(&words)
            .args([
                "--socket",
                dir.path().join("missing.sock").to_str().unwrap(),
            ])
            .env_remove("APASSY_SESSION")
            .env("HOME", dir.path())
            .env("CLAUDE_CONFIG_DIR", dir.path().join("custom-claude"))
            .env("CODEX_HOME", dir.path().join("codex"))
            .current_dir(dir.path())
            .output()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!(
                "{words:?}: {e}: {}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        assert!(value["ok"].is_boolean());
        if words[0] == "logout" {
            assert!(output.status.success());
            assert!(value["data"]["shell_command"].is_string());
        } else {
            assert!(!output.status.success());
        }
    }
}

#[test]
fn audit_doctor_honors_custom_claude_configs_and_disabled_entries() {
    let dir = TempDir::new().unwrap();
    let custom = dir.path().join("custom");
    std::fs::create_dir(&custom).unwrap();
    for config in [
        "not json",
        r#"{"mcpServers":{"apassy":{"command":"/missing/wrapper"}}}"#,
        r#"{"mcpServers":{"apassy":{"command":"/bin/sh","disabled":true}}}"#,
    ] {
        std::fs::write(custom.join(".claude.json"), config).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_apassy"))
            .args([
                "doctor",
                "--json",
                "--socket",
                dir.path().join("missing.sock").to_str().unwrap(),
            ])
            .env_remove("APASSY_SESSION")
            .env("HOME", dir.path())
            .env("CLAUDE_CONFIG_DIR", &custom)
            .env("CODEX_HOME", dir.path().join("codex"))
            .current_dir(dir.path())
            .output()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            value["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["level"] == "problem"
                    && (c["name"] == "Claude Code" || c["name"] == "Host config"))
        );
        assert!(
            value["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["level"] == "unverified")
        );
    }
}

#[test]
fn audit_export_json_wraps_jsonl_and_file_metadata() {
    for to_file in [false, true] {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let response = Response {
                ok: true,
                code: "ok".into(),
                message: "Synthetic export".into(),
                data: Data::Export {
                    jsonl: "{\"synthetic\":true}\n".into(),
                },
            };
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let path = dir.path().join("export.jsonl");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_apassy"));
        cmd.args([
            "decisions",
            "export",
            "--json",
            "--socket",
            socket.to_str().unwrap(),
        ]);
        if to_file {
            cmd.args(["--output", path.to_str().unwrap()]);
        }
        let output = cmd
            .env_remove("APASSY_SESSION")
            .env("HOME", dir.path())
            .env("CLAUDE_CONFIG_DIR", dir.path().join("claude"))
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if to_file {
            assert_eq!(value["data"]["output"], path.to_str().unwrap());
            assert!(path.is_file());
        } else {
            assert_eq!(value["data"]["jsonl"], "{\"synthetic\":true}\n");
        }
    }
}

#[test]
fn audit_browser_json_reports_success_and_partial_manifest_changes() {
    let dir = TempDir::new().unwrap();
    let macos = dir.path().join("Synthetic.app/Contents/MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    let program = macos.join("apassy");
    std::fs::hard_link(env!("CARGO_BIN_EXE_apassy"), &program).unwrap();
    std::fs::write(
        macos.join("apassy-browser-host"),
        "synthetic placeholder, never executed",
    )
    .unwrap();
    let support = dir.path().join("Library/Application Support");
    std::fs::create_dir_all(support.join("net.imput.helium")).unwrap();
    let run = |words: &[&str]| {
        let output = Command::new(&program)
            .args(words)
            .env_remove("APASSY_SESSION")
            .env("HOME", dir.path())
            .env("CLAUDE_CONFIG_DIR", dir.path().join("claude"))
            .current_dir(dir.path())
            .output()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status, value)
    };
    let (status, result) = run(&["setup", "browser", "--browser", "helium", "--json"]);
    assert!(status.success());
    assert_eq!(result["partial_state"]["changes"][0]["state"], "written");
    let (status, result) = run(&[
        "setup",
        "browser",
        "--browser",
        "helium",
        "--remove",
        "--json",
    ]);
    assert!(status.success());
    assert_eq!(result["partial_state"]["changes"][0]["state"], "removed");
    let chrome = support.join("Google/Chrome");
    std::fs::create_dir_all(&chrome).unwrap();
    std::fs::write(chrome.join("NativeMessagingHosts"), "synthetic blocker").unwrap();
    let (status, result) = run(&["setup", "browser", "--json"]);
    assert_eq!(status.code(), Some(1));
    assert_eq!(result["stage"], "manifests");
    assert_eq!(result["partial_state"]["changes"][0]["state"], "written");
}
