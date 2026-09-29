//! Shared helpers of the `cli_*` tests: a recording HTTP server and a runner for the real binary.
#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

pub const BIN: &str = env!("CARGO_BIN_EXE_apassy-team");

/// Synthetic values. They are not real secrets.
pub const MEMBER_TOKEN: &str =
    "apassy_mbr_00000000000000000000000000000000000000000000000000000000000000aa";
pub const AGENT_TOKEN: &str =
    "apassy_agt_00000000000000000000000000000000000000000000000000000000000000bb";
pub const EDGE: &str = "edge-secret-synthetic-0123456789abcdef0123";
pub const CANARY: &str = "sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF";

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// What the mock answers.
pub struct Answer {
    pub status: u16,
    pub body: String,
    pub delay: Duration,
    pub headers: Vec<(String, String)>,
}

pub fn ok(result: serde_json::Value) -> Answer {
    Answer {
        status: 200,
        body: serde_json::json!({"ok": true, "result": result}).to_string(),
        delay: Duration::ZERO,
        headers: Vec::new(),
    }
}

pub fn err(status: u16, code: &str, message: &str) -> Answer {
    Answer {
        status,
        body: serde_json::json!({"ok": false, "error": {"code": code, "message": message}})
            .to_string(),
        delay: Duration::ZERO,
        headers: Vec::new(),
    }
}

pub fn raw(status: u16, body: &str) -> Answer {
    Answer {
        status,
        body: body.to_owned(),
        delay: Duration::ZERO,
        headers: Vec::new(),
    }
}

/// A recording HTTP server on 127.0.0.1. The handler picks the answer for each request.
pub struct Mock {
    pub url: String,
    seen: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Mock {
    pub fn start(handler: impl Fn(&Recorded, usize) -> Answer + Send + 'static) -> Mock {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", server.server_addr().to_ip().expect("ip"));
        let seen: Arc<Mutex<Vec<Recorded>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (seen2, stop2) = (seen.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(50)) else {
                    continue;
                };
                let mut body = String::new();
                let _ = std::io::Read::read_to_string(request.as_reader(), &mut body);
                let recorded = Recorded {
                    method: request.method().to_string(),
                    url: request.url().to_owned(),
                    headers: request
                        .headers()
                        .iter()
                        .map(|h| (h.field.to_string(), h.value.to_string()))
                        .collect(),
                    body,
                };
                let index = {
                    let mut all = seen2.lock().unwrap();
                    all.push(recorded.clone());
                    all.len() - 1
                };
                let answer = handler(&recorded, index);
                std::thread::sleep(answer.delay);
                let header =
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap();
                let mut response = tiny_http::Response::from_string(answer.body)
                    .with_status_code(answer.status)
                    .with_header(header);
                for (name, value) in &answer.headers {
                    let extra = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes());
                    response = response.with_header(extra.unwrap());
                }
                let _ = request.respond(response);
            }
        });
        Mock {
            url,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    /// A mock that always gives the same answer.
    pub fn always(status: u16, result: serde_json::Value) -> Mock {
        Mock::start(move |_, _| {
            if status == 200 {
                ok(result.clone())
            } else {
                raw(status, &result.to_string())
            }
        })
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A URL where nothing listens.
pub fn dead_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    url
}

/// The binary with a clean environment and a temp home.
pub struct Cli {
    pub home: tempfile::TempDir,
    pub env: Vec<(String, String)>,
    pub xdg: bool,
}

impl Cli {
    pub fn new() -> Cli {
        Cli {
            home: tempfile::tempdir().unwrap(),
            env: Vec::new(),
            xdg: true,
        }
    }

    pub fn with(mut self, name: &str, value: &str) -> Cli {
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The relay URL and a member token, and the edge secret.
    pub fn member(self, url: &str) -> Cli {
        self.with("APASSY_RELAY_URL", url)
            .with("APASSY_TEAM_TOKEN", MEMBER_TOKEN)
    }

    pub fn agent(self, url: &str) -> Cli {
        self.with("APASSY_RELAY_URL", url)
            .with("APASSY_TOKEN", AGENT_TOKEN)
    }

    pub fn config_dir(&self) -> PathBuf {
        self.home.path().join("xdg")
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config_dir().join("apassy-team").join("settings.json")
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(BIN);
        command.args(args).env_clear();
        command.env("PATH", "/usr/bin:/bin");
        command.env("HOME", self.home.path());
        if self.xdg {
            command.env("XDG_CONFIG_HOME", self.config_dir());
        }
        for (name, value) in &self.env {
            command.env(name, value);
        }
        command
    }

    /// Runs with `stdin` piped (or closed when `None`).
    pub fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = self.command(args);
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let mut child = command.spawn().unwrap();
        if let Some(text) = stdin {
            let mut pipe = child.stdin.take().unwrap();
            pipe.write_all(text.as_bytes()).unwrap();
        }
        child.wait_with_output().unwrap()
    }
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// A `RunView` result.
pub fn run_view(
    run_id: u64,
    status: &str,
    session_env: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut view = serde_json::json!({
        "run_id": run_id, "status": status, "note": "A note.", "flags": [], "created_at": 1
    });
    if let Some(env) = session_env {
        view["session"] = serde_json::json!({
            "session_id": 1, "expires_at": 2, "env": env, "placeholders": [], "base_urls": {}
        });
    }
    view
}
