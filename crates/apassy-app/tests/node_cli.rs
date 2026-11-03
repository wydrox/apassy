//! The node commands of the `apassy` binary (plan S2-S3, unit L1): `serve` starts with
//! the loopback test hook of debug builds and stops on `SIGTERM` within 5 s and on
//! `serve --stop`; `pair` refuses a node that does not run; `team` is the team command
//! line. Each node keeps its files in its own directory under `/tmp` (short paths for
//! the Unix sockets) and uses a free loopback port. No Tailscale, no network.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_apassy-app");

/// A directory under `/tmp`, removed at the end.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.subsec_nanos())
            .unwrap_or(0);
        let path = PathBuf::from("/tmp").join(format!("an-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .expect("a free port")
}

/// A node directory with a free port and no push.
fn node_dir(root: &TempDir) -> (PathBuf, u16) {
    let dir = root.path().join("node");
    fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    fs::write(
        dir.join("settings.json"),
        format!("{{\"port\": {port}, \"push_gateway\": null}}"),
    )
    .unwrap();
    (dir, port)
}

fn command(root: &TempDir) -> Command {
    let mut command = Command::new(BIN);
    command
        .env("HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("APASSY_NODE_TEST_LOOPBACK")
        .stdin(Stdio::null());
    for name in [
        "APASSY_RELAY_URL",
        "APASSY_TEAM_TOKEN",
        "APASSY_TOKEN",
        "APASSY_EDGE_SECRET",
        "APASSY_TEAM",
    ] {
        command.env_remove(name);
    }
    command
}

fn spawn_serve(root: &TempDir, dir: &Path) -> Child {
    let log = fs::File::create(root.path().join("serve.log")).unwrap();
    command(root)
        .args(["serve", "--data-dir"])
        .arg(dir)
        .env("APASSY_NODE_TEST_LOOPBACK", "1")
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("start apassy serve")
}

fn log(root: &TempDir) -> String {
    fs::read_to_string(root.path().join("serve.log")).unwrap_or_default()
}

/// The value of `"key": "<value>"` in `state.json`.
fn state_text(dir: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(dir.join("state.json")).ok()?;
    let marker = format!("\"{key}\": \"");
    let rest = text.split(&marker).nth(1)?;
    Some(rest.split('"').next()?.to_owned())
}

/// Waits until `serve` wrote `state.json` with the relay's tailnet listener.
fn wait_for_node(root: &TempDir, dir: &Path, child: &mut Child) -> SocketAddr {
    let started = Instant::now();
    loop {
        if let Some(target) = state_text(dir, "tailnet_listen").and_then(|text| text.parse().ok()) {
            return target;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("serve ended with {status}: {}", log(root));
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "serve did not start: {}",
            log(root)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The status line of `GET /healthz` over plain HTTP on the loopback.
fn healthz(target: SocketAddr) -> String {
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Waits at most `within` for `child` to end.
fn ended_within(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let started = Instant::now();
    while started.elapsed() < within {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn serve_starts_and_stops_on_sigterm_within_5_seconds() {
    let root = TempDir::new("term");
    let (dir, port) = node_dir(&root);
    let mut child = spawn_serve(&root, &dir);
    let target = wait_for_node(&root, &dir, &mut child);
    assert!(
        healthz(target).starts_with("HTTP/1.1 200"),
        "{}",
        log(&root)
    );
    assert_eq!(
        state_text(&dir, "origin").as_deref(),
        Some(format!("https://127.0.0.1:{port}").as_str())
    );
    let front = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(TcpStream::connect_timeout(&front, Duration::from_secs(2)).is_ok());
    let sent = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let status = ended_within(&mut child, Duration::from_secs(5));
    let Some(status) = status else {
        let _ = child.kill();
        panic!("serve did not stop within 5 s: {}", log(&root));
    };
    assert_eq!(status.signal(), Some(15), "{status}");
    assert!(TcpStream::connect_timeout(&front, Duration::from_secs(1)).is_err());
    assert!(TcpStream::connect_timeout(&target, Duration::from_secs(1)).is_err());
}

#[test]
fn serve_stop_stops_the_front_and_the_relay() {
    let root = TempDir::new("stop");
    let (dir, port) = node_dir(&root);
    let mut child = spawn_serve(&root, &dir);
    let target = wait_for_node(&root, &dir, &mut child);
    let started = Instant::now();
    let stop = command(&root)
        .args(["serve", "--stop", "--data-dir"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let status = ended_within(&mut child, Duration::from_secs(5));
    let Some(status) = status else {
        let _ = child.kill();
        panic!("serve did not stop: {}", log(&root));
    };
    assert!(status.success(), "{status}: {}", log(&root));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!dir.join("state.json").exists());
    assert!(!dir.join("serve.sock").exists());
    let front = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(TcpStream::connect_timeout(&front, Duration::from_secs(1)).is_err());
    assert!(TcpStream::connect_timeout(&target, Duration::from_secs(1)).is_err());
    // A second stop finds no node and is not an error.
    let again = command(&root)
        .args(["serve", "--stop", "--data-dir"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("not running"));
}

fn run(root: &TempDir, args: &[&str]) -> Output {
    command(root).args(args).output().expect("run apassy")
}

#[test]
fn pair_needs_a_running_node() {
    let root = TempDir::new("pair");
    let (dir, _) = node_dir(&root);
    let dir = dir.to_str().unwrap().to_owned();
    let output = run(&root, &["pair", "--data-dir", &dir]);
    assert_eq!(output.status.code(), Some(3));
    let json = run(&root, &["pair", "--json", "--data-dir", &dir]);
    assert_eq!(json.status.code(), Some(3));
    let text = String::from_utf8_lossy(&json.stdout);
    assert!(text.contains("\"ok\":false"), "{text}");
    assert!(text.contains("\"not_running\""), "{text}");
    let bad = run(&root, &["pair", "--minutes", "11", "--data-dir", &dir]);
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn team_is_the_team_command_line() {
    let root = TempDir::new("team");
    let help = run(&root, &["team", "help"]);
    assert!(help.status.success());
    assert_eq!(
        String::from_utf8_lossy(&help.stdout),
        apassy_relay::cli::args::USAGE
    );
    let version = run(&root, &["team", "--version"]);
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout),
        format!("apassy-team {}\n", env!("CARGO_PKG_VERSION"))
    );
    // No saved team: the same usage error as `apassy-team me`, named `apassy team`.
    let me = run(&root, &["team", "me"]);
    assert_eq!(me.status.code(), Some(2));
    assert!(me.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&me.stderr);
    assert!(stderr.starts_with("apassy team: "), "{stderr}");
    let json = run(&root, &["team", "me", "--json"]);
    assert_eq!(json.status.code(), Some(2));
    let text = String::from_utf8_lossy(&json.stdout);
    assert!(
        text.contains("\"ok\":false") && text.contains("\"exit_code\":2"),
        "{text}"
    );
}
