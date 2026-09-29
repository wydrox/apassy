//! The `apassy-relay` binary: usage, `init`, and `serve`.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const EDGE: &str = "edge-secret-for-tests-0123456789abcdef0123456789";
const KEY: &str = "a synthetic vault passphrase for tests";

fn relay(dir: &std::path::Path, listen: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apassy-relay"));
    command
        .env_clear()
        .env("APASSY_RELAY_DATA", dir.join("data"))
        .env("APASSY_RELAY_LISTEN", listen)
        .env("APASSY_RELAY_PUBLIC_URL", "https://relay.example.test")
        .env("APASSY_RELAY_EDGE_SECRET", EDGE)
        .env("APASSY_RELAY_KEY", KEY);
    command
}

#[test]
fn init_prints_the_owner_token_once_and_only_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let output = relay(dir.path(), "127.0.0.1:0")
        .args(["init", "--team", "Acme", "--owner", "olga"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let token = stdout.trim_end();
    assert!(token.starts_with("apassy_mbr_"), "{stdout}");
    assert_eq!(token.len(), "apassy_mbr_".len() + 64);
    assert_eq!(stdout.lines().count(), 1);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains(token), "the token is not on stderr");
    assert!(!stderr.contains(KEY) && !stderr.contains(EDGE));
    // A second init is refused with exit code 1 and a clear message.
    let again = relay(dir.path(), "127.0.0.1:0")
        .args(["init", "--team", "Acme", "--owner", "olga"])
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(1));
    assert!(again.stdout.is_empty());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
}

#[test]
fn usage_errors_exit_with_2() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["bogus"],
        vec!["init"],
        vec!["init", "--team", "T"],
        vec!["init", "--owner", "o"],
        vec!["init", "--team", "T", "--owner", "o", "--extra", "x"],
        vec!["init", "--team"],
        vec!["serve", "now"],
    ] {
        let output = relay(dir.path(), "127.0.0.1:0")
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Usage:"),
            "{args:?}"
        );
    }
    let help = relay(dir.path(), "127.0.0.1:0")
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(0));
}

#[test]
fn missing_or_bad_configuration_exits_with_1_and_says_what() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_apassy-relay"))
        .env_clear()
        .arg("serve")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("APASSY_RELAY_PUBLIC_URL"));
    let output = relay(dir.path(), "not an address").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("APASSY_RELAY_LISTEN"));
    // `serve` without a vault says to run init.
    let output = relay(dir.path(), "127.0.0.1:0").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("init"));
}

#[test]
fn serve_answers_and_refuses_without_the_edge_header() {
    let dir = tempfile::tempdir().unwrap();
    let init = relay(dir.path(), "127.0.0.1:0")
        .args(["init", "--team", "Acme", "--owner", "olga"])
        .output()
        .unwrap();
    let token = String::from_utf8(init.stdout).unwrap().trim().to_string();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let listen = format!("127.0.0.1:{port}");
    let mut child = relay(dir.path(), &listen)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    assert!(line.contains("listening on"), "{line}");
    let base = format!("http://{listen}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let health = loop {
        match ureq::get(&format!("{base}/healthz")).call() {
            Ok(response) => break response,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => panic!("the server did not answer: {error}"),
        }
    };
    assert_eq!(health.status().as_u16(), 200);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let refused = agent.get(&format!("{base}/v1/me")).call().unwrap();
    assert_eq!(refused.status().as_u16(), 403);
    let mut me = agent
        .get(&format!("{base}/v1/me"))
        .header("X-Apassy-Edge", EDGE)
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .unwrap();
    assert_eq!(me.status().as_u16(), 200);
    let text = me.body_mut().read_to_string().unwrap();
    assert!(
        text.contains("\"team\":\"Acme\"") && text.contains("olga"),
        "{text}"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn serve_fails_clearly_when_the_port_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    relay(dir.path(), "127.0.0.1:0")
        .args(["init", "--team", "Acme", "--owner", "olga"])
        .output()
        .unwrap();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = taken.local_addr().unwrap().to_string();
    let output = relay(dir.path(), &listen).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Cannot listen"));
}
