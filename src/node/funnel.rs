//! The public route of the node: Tailscale Funnel on port 8443 (ADR 0037, cloud slice,
//! decision 4).
//!
//! Only the `tailscale` command line at the known paths of `companion::hosts` is used,
//! with these commands and no other:
//!
//! - `tailscale status --json`: `BackendState` must be `Running`; `Self.DNSName` is the
//!   name of the Mac in the tailnet, and `https://<DNSName>:8443` the origin of the node.
//! - `tailscale serve status --json`: what each port serves now.
//! - `tailscale funnel --bg --https=8443 http://127.0.0.1:<port>`: the route on.
//! - `tailscale funnel --https=8443 off`: the route off.
//!
//! Never port 443: on the owner's Mac, 443 serves other things through Tailscale Serve,
//! and the app never names it. Never `serve reset` or `funnel reset`: they would drop
//! the handlers of other programs. The app refuses when 443 is public through Funnel
//! (something else would be on the internet), and when 8443 serves another target; then
//! it names port 10000, the only other Funnel port. It turns off only its own handler.
//! When the owner chooses "Use Port 10000", the route uses 10000 instead of 8443
//! ([`Funnel::set_port`]; the node keeps the choice in its directory).
//! A refusal of the tailnet policy keeps the text of the command line and its link to
//! the admin console.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The Funnel port of the node.
pub const FUNNEL_PORT: u16 = 8443;
/// The only other Funnel port that the app names when 8443 is taken (443 is never one).
pub const OTHER_FUNNEL_PORT: u16 = 10000;
/// The port that the app never touches.
const NEVER_PORT: u16 = 443;
const CLI_TIMEOUT: Duration = Duration::from_secs(10);
/// A command writes at most this much.
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
/// A message of the command line in an error is cut to this many bytes.
const MAX_MESSAGE_BYTES: usize = 400;

/// What a command wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOutput {
    /// It exited with status 0 within the time limit.
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// The Tailscale command line. Tests use a fake.
pub trait TailscaleCli: Send + Sync {
    /// Run the command line with `args`. `None`: no Tailscale command line on this Mac.
    fn run(&self, args: &[&str]) -> Option<CliOutput>;
}

/// The command line at the first known path that exists.
pub struct SystemTailscale;

impl TailscaleCli for SystemTailscale {
    fn run(&self, args: &[&str]) -> Option<CliOutput> {
        let program = crate::companion::hosts::TAILSCALE_PROGRAMS
            .into_iter()
            .find(|program| Path::new(program).is_file())?;
        Some(run_within(program, args, CLI_TIMEOUT))
    }
}

/// Run `program` with a time limit. Both outputs are read on threads while it runs; on
/// a timeout it is stopped, and what it wrote until then is kept (a refusal of the
/// policy can come before the command line waits).
fn run_within(program: &str, args: &[&str], timeout: Duration) -> CliOutput {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return CliOutput::default();
    };
    let reader = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(stream) = stream {
                let _ = stream.take(MAX_OUTPUT_BYTES).read_to_end(&mut bytes);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let stdout = reader(
        child
            .stdout
            .take()
            .map(|stream| Box::new(stream) as Box<dyn Read + Send>),
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .map(|stream| Box::new(stream) as Box<dyn Read + Send>),
    );
    let end = Instant::now() + timeout;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() >= end => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    CliOutput {
        success,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    }
}

/// Tailscale on this Mac.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tailscale {
    /// No command line at the known paths: "Install Tailscale and sign in".
    Missing,
    /// It answers, but it is not running or not signed in: "Tailscale is not connected".
    NotConnected { state: String },
    /// Running, with the name of this Mac in the tailnet (without the last dot).
    Connected { dns_name: String },
}

/// What one port serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortUse {
    Free,
    /// The node: one handler `/` to the loopback target of the app.
    Ours,
    /// Something else, such as another program's handler.
    Other {
        target: String,
    },
}

/// The state of `tailscale serve` that the app needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeState {
    pub funnel_port: PortUse,
    /// Funnel is on for the Funnel port.
    pub funnel_port_public: bool,
    /// Funnel is on for 443.
    pub https_public: bool,
}

/// Why the route is not on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunnelError {
    /// "Install Tailscale and sign in."
    NoTailscale,
    /// "Tailscale is not connected."
    NotConnected(String),
    /// The Funnel port serves another target. The app does not change it. `alternative`:
    /// the other Funnel port, when the route is not on it already.
    PortTaken {
        port: u16,
        target: String,
        alternative: Option<u16>,
    },
    /// 443 is public through Funnel. The app adds nothing while it is.
    HttpsPublic,
    /// The tailnet policy does not allow Funnel for this Mac.
    Policy {
        message: String,
        link: Option<String>,
    },
    /// The state of `tailscale serve` cannot be read.
    Unreadable(String),
    /// The command failed.
    Failed(String),
}

impl FunnelError {
    /// The text for the owner.
    pub fn message(&self) -> String {
        match self {
            Self::NoTailscale => "Install Tailscale and sign in.".to_owned(),
            Self::NotConnected(state) => format!("Tailscale is not connected ({state})."),
            Self::PortTaken {
                port,
                target,
                alternative: Some(alternative),
            } => format!(
                "Port {port} of Tailscale Serve already serves {target}. Apassy does not change it. Remove that handler, or use port {alternative}."
            ),
            Self::PortTaken {
                port,
                target,
                alternative: None,
            } => format!(
                "Port {port} of Tailscale Serve already serves {target}. Apassy does not change it. Remove that handler."
            ),
            Self::HttpsPublic => format!(
                concat!(
                    "Port {NEVER_PORT} of this ",
                    crate::computer!(),
                    " is public through Tailscale Funnel. Apassy adds no route while it is: check `tailscale serve status`."
                ),
                NEVER_PORT = NEVER_PORT
            ),
            Self::Policy { message, link } => match link {
                Some(link) => format!(
                    "The tailnet policy does not allow Funnel: {message} Allow it at {link}"
                ),
                None => format!("The tailnet policy does not allow Funnel: {message}"),
            },
            Self::Unreadable(why) => format!("Apassy cannot read the Tailscale Serve state: {why}"),
            Self::Failed(why) => format!("Tailscale did not turn the route on: {why}"),
        }
    }
}

/// The loopback target of the route: the public listener of the node.
pub fn target_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// The origin of the node for agents on the usual Funnel port.
pub fn public_origin(dns_name: &str) -> String {
    public_origin_on(dns_name, FUNNEL_PORT)
}

/// The origin of the node for agents on the Funnel `port`.
pub fn public_origin_on(dns_name: &str, port: u16) -> String {
    format!("https://{dns_name}:{port}")
}

/// A Funnel port that the app may use: 8443, or 10000 when the owner chose it.
pub fn is_funnel_port(port: u16) -> bool {
    port == FUNNEL_PORT || port == OTHER_FUNNEL_PORT
}

/// The other Funnel port of `port`, for "Use Port 10000"; `None` on 10000.
pub fn alternative_port(port: u16) -> Option<u16> {
    (port == FUNNEL_PORT).then_some(OTHER_FUNNEL_PORT)
}

/// Printable text without control characters, cut at a character boundary.
fn clean(text: &str, max: usize) -> String {
    let text: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// `tailscale status --json`.
pub fn parse_status(json: &str) -> Tailscale {
    let Ok(status) = serde_json::from_str::<Value>(json) else {
        return Tailscale::NotConnected {
            state: "unreadable status".to_owned(),
        };
    };
    let state = status
        .get("BackendState")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if state != "Running" {
        return Tailscale::NotConnected {
            state: clean(state, 40),
        };
    }
    let name = status
        .get("Self")
        .and_then(|me| me.get("DNSName"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.contains('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    if valid {
        Tailscale::Connected { dns_name: name }
    } else {
        Tailscale::NotConnected {
            state: "no MagicDNS name".to_owned(),
        }
    }
}

/// The configs of `serve status --json`: the background one and each foreground one.
fn configs(root: &Value) -> Vec<(&Value, bool)> {
    let mut out = vec![(root, false)];
    if let Some(sessions) = root.get("Foreground").and_then(Value::as_object) {
        out.extend(sessions.values().map(|config| (config, true)));
    }
    out
}

fn has_port_key(map: Option<&Value>, port: u16) -> bool {
    map.and_then(Value::as_object).is_some_and(|map| {
        map.keys()
            .any(|key| key == &port.to_string() || key.ends_with(&format!(":{port}")))
    })
}

fn funnel_on(config: &Value, port: u16) -> bool {
    config
        .get("AllowFunnel")
        .and_then(Value::as_object)
        .is_some_and(|map| {
            map.iter()
                .any(|(key, on)| key.ends_with(&format!(":{port}")) && on.as_bool() == Some(true))
        })
}

/// What a handler serves, for the text.
fn handler_target(handler: &Value) -> String {
    for field in ["Proxy", "Path"] {
        if let Some(text) = handler.get(field).and_then(Value::as_str) {
            return clean(text, 120);
        }
    }
    if handler.get("Text").is_some() {
        return "a text answer".to_owned();
    }
    "another handler".to_owned()
}

/// `tailscale serve status --json`, for the route to `own_target` on port 8443.
pub fn parse_serve_status(json: &str, own_target: &str) -> Result<ServeState, FunnelError> {
    parse_serve_status_on(json, own_target, FUNNEL_PORT)
}

/// `tailscale serve status --json`, for the route to `own_target` on the Funnel port
/// `funnel_port`.
pub fn parse_serve_status_on(
    json: &str,
    own_target: &str,
    funnel_port: u16,
) -> Result<ServeState, FunnelError> {
    let trimmed = json.trim();
    // An empty configuration prints nothing or `{}`.
    let root: Value = if trimmed.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(trimmed)
            .map_err(|_| FunnelError::Unreadable("the answer is not JSON".to_owned()))?
    };
    if !root.is_object() {
        return Err(FunnelError::Unreadable(
            "the answer is not an object".to_owned(),
        ));
    }
    let mut https_public = false;
    let mut funnel_port_public = false;
    let mut uses = Vec::new();
    for (config, foreground) in configs(&root) {
        https_public |= funnel_on(config, NEVER_PORT);
        funnel_port_public |= funnel_on(config, funnel_port);
        let tcp = config
            .get("TCP")
            .and_then(Value::as_object)
            .and_then(|map| map.get(&funnel_port.to_string()));
        if let Some(forward) = tcp
            .and_then(|port| port.get("TCPForward"))
            .and_then(Value::as_str)
        {
            uses.push(PortUse::Other {
                target: format!("a TCP forward to {}", clean(forward, 120)),
            });
            continue;
        }
        let webs: Vec<&Value> = config
            .get("Web")
            .and_then(Value::as_object)
            .map(|web| {
                web.iter()
                    .filter(|(key, _)| key.ends_with(&format!(":{funnel_port}")))
                    .map(|(_, site)| site)
                    .collect()
            })
            .unwrap_or_default();
        if webs.is_empty() {
            if tcp.is_some() || has_port_key(config.get("Web"), funnel_port) {
                uses.push(PortUse::Other {
                    target: "another handler".to_owned(),
                });
            }
            continue;
        }
        for site in webs {
            let handlers = site.get("Handlers").and_then(Value::as_object);
            let ours = !foreground
                && handlers.is_some_and(|handlers| {
                    handlers.len() == 1
                        && handlers.get("/").is_some_and(|handler| {
                            handler
                                .get("Proxy")
                                .and_then(Value::as_str)
                                .is_some_and(|proxy| proxy.trim_end_matches('/') == own_target)
                        })
                });
            uses.push(if ours {
                PortUse::Ours
            } else {
                PortUse::Other {
                    target: handlers
                        .and_then(|handlers| handlers.values().next())
                        .map_or_else(|| "another handler".to_owned(), handler_target),
                }
            });
        }
    }
    let funnel_port = uses
        .iter()
        .find(|used| matches!(used, PortUse::Other { .. }))
        .or_else(|| uses.first())
        .cloned()
        .unwrap_or(PortUse::Free);
    Ok(ServeState {
        funnel_port,
        funnel_port_public,
        https_public,
    })
}

/// A refusal of the tailnet policy in the text of the command line, with its link to the
/// admin console. `None`: another failure.
pub fn parse_refusal(text: &str) -> Option<FunnelError> {
    let lower = text.to_lowercase();
    let refused = lower.contains("funnel")
        && [
            "not enabled",
            "not available",
            "node attribute",
            "nodeattr",
            "not allowed",
            "policy",
        ]
        .iter()
        .any(|phrase| lower.contains(phrase));
    if !refused {
        return None;
    }
    let link = text
        .split_whitespace()
        .map(|word| word.trim_matches(['.', ',', ')', '(', '"', '\'']))
        .find(|word| {
            ["https://login.tailscale.com/", "https://tailscale.com/"]
                .iter()
                .any(|prefix| word.starts_with(prefix))
                && word.len() <= 300
                && word.bytes().all(|b| b.is_ascii_graphic())
        })
        .map(str::to_owned);
    let message = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("https://"))
        .take(3)
        .collect::<Vec<_>>()
        .join(" ");
    Some(FunnelError::Policy {
        message: clean(&message, MAX_MESSAGE_BYTES),
        link,
    })
}

/// The route of the node through the Tailscale command line.
#[derive(Clone)]
pub struct Funnel {
    cli: Arc<dyn TailscaleCli>,
    /// The Funnel port of the route: [`FUNNEL_PORT`], or [`OTHER_FUNNEL_PORT`] when the
    /// owner chose it.
    port: Arc<AtomicU16>,
}

impl Funnel {
    pub fn new(cli: Arc<dyn TailscaleCli>) -> Self {
        Self {
            cli,
            port: Arc::new(AtomicU16::new(FUNNEL_PORT)),
        }
    }

    /// The Funnel port of the route.
    pub fn port(&self) -> u16 {
        self.port.load(Ordering::SeqCst)
    }

    /// Use the Funnel `port` from now on. Only 8443 and 10000 are taken; another port
    /// changes nothing and returns false. The caller turns the route on the old port off
    /// first.
    pub fn set_port(&self, port: u16) -> bool {
        if !is_funnel_port(port) {
            return false;
        }
        self.port.store(port, Ordering::SeqCst);
        true
    }

    /// The origin of the node for agents on this Mac's name.
    pub fn origin(&self, dns_name: &str) -> String {
        public_origin_on(dns_name, self.port())
    }

    /// `tailscale status --json`.
    pub fn status(&self) -> Tailscale {
        match self.cli.run(&["status", "--json"]) {
            None => Tailscale::Missing,
            Some(output) if output.stdout.trim().is_empty() => Tailscale::NotConnected {
                state: "no answer".to_owned(),
            },
            // The command exits with an error when it is stopped, and still prints JSON.
            Some(output) => parse_status(&output.stdout),
        }
    }

    /// `tailscale serve status --json` for the route to `port`.
    pub fn serve_state(&self, port: u16) -> Result<ServeState, FunnelError> {
        let output = self
            .cli
            .run(&["serve", "status", "--json"])
            .ok_or(FunnelError::NoTailscale)?;
        if !output.success {
            return Err(FunnelError::Unreadable(clean(
                &format!("{} {}", output.stderr, output.stdout),
                MAX_MESSAGE_BYTES,
            )));
        }
        parse_serve_status_on(&output.stdout, &target_url(port), self.port())
    }

    /// Turn the route on to the loopback `port` and return the name of this Mac. The
    /// route is applied again when it is there. `previous`: an earlier port of the app,
    /// whose handler is a stale entry of the app and goes first.
    pub fn enable(&self, port: u16, previous: Option<u16>) -> Result<String, FunnelError> {
        let dns_name = match self.status() {
            Tailscale::Missing => return Err(FunnelError::NoTailscale),
            Tailscale::NotConnected { state } => return Err(FunnelError::NotConnected(state)),
            Tailscale::Connected { dns_name } => dns_name,
        };
        let state = self.serve_state(port)?;
        if state.https_public {
            return Err(FunnelError::HttpsPublic);
        }
        match &state.funnel_port {
            PortUse::Ours if state.funnel_port_public => return Ok(dns_name),
            PortUse::Other { target }
                if previous.is_some_and(|old| old != port && *target == target_url(old)) =>
            {
                self.turn_off()?;
            }
            PortUse::Other { target } => {
                return Err(FunnelError::PortTaken {
                    port: self.port(),
                    target: target.clone(),
                    alternative: alternative_port(self.port()),
                });
            }
            PortUse::Free | PortUse::Ours => {}
        }
        let https = format!("--https={}", self.port());
        let target = target_url(port);
        let output = self
            .cli
            .run(&["funnel", "--bg", &https, &target])
            .ok_or(FunnelError::NoTailscale)?;
        if !output.success {
            let text = format!("{}\n{}", output.stderr, output.stdout);
            return Err(parse_refusal(&text)
                .unwrap_or_else(|| FunnelError::Failed(clean(&text, MAX_MESSAGE_BYTES))));
        }
        let after = self.serve_state(port)?;
        if after.funnel_port != PortUse::Ours || !after.funnel_port_public {
            return Err(FunnelError::Failed(
                "the route is not in `tailscale serve status` after the command".to_owned(),
            ));
        }
        Ok(dns_name)
    }

    /// Turn the route to `port` off. Returns true when it was on. A handler of another
    /// target stays as it is.
    pub fn disable(&self, port: u16) -> Result<bool, FunnelError> {
        let state = match self.serve_state(port) {
            Err(FunnelError::NoTailscale) => return Ok(false),
            other => other?,
        };
        if state.funnel_port != PortUse::Ours {
            return Ok(false);
        }
        self.turn_off()?;
        Ok(true)
    }

    fn turn_off(&self) -> Result<(), FunnelError> {
        let https = format!("--https={}", self.port());
        let output = self
            .cli
            .run(&["funnel", &https, "off"])
            .ok_or(FunnelError::NoTailscale)?;
        if output.success {
            Ok(())
        } else {
            Err(FunnelError::Failed(clean(
                &format!("{} {}", output.stderr, output.stdout),
                MAX_MESSAGE_BYTES,
            )))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use super::*;

    pub(crate) const DNS: &str = "mac.example-tailnet.ts.net";

    pub(crate) fn status_json() -> String {
        format!(
            r#"{{"BackendState":"Running","Self":{{"DNSName":"{DNS}.","TailscaleIPs":["100.101.102.103"]}}}}"#
        )
    }

    /// T3 Code on 443 through Serve, not Funnel: the owner's Mac.
    pub(crate) fn serve_443_only() -> String {
        format!(
            r#"{{"TCP":{{"443":{{"HTTPS":true}}}},"Web":{{"{DNS}:443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:3773"}}}}}}}}}}"#
        )
    }

    pub(crate) fn serve_with_8443(target: &str, public: bool) -> String {
        serve_with_port(FUNNEL_PORT, target, public)
    }

    pub(crate) fn serve_with_port(port: u16, target: &str, public: bool) -> String {
        format!(
            r#"{{"TCP":{{"443":{{"HTTPS":true}},"{port}":{{"HTTPS":true}}}},"Web":{{"{DNS}:443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:3773"}}}}}},"{DNS}:{port}":{{"Handlers":{{"/":{{"Proxy":"{target}"}}}}}}}},"AllowFunnel":{{"{DNS}:{port}":{public}}}}}"#
        )
    }

    /// 8443 serves another program, and the route of the app is on 10000.
    pub(crate) fn serve_other_8443_and_10000(target: &str) -> String {
        format!(
            r#"{{"TCP":{{"8443":{{"HTTPS":true}},"10000":{{"HTTPS":true}}}},"Web":{{"{DNS}:8443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:8080"}}}}}},"{DNS}:10000":{{"Handlers":{{"/":{{"Proxy":"{target}"}}}}}}}},"AllowFunnel":{{"{DNS}:8443":true,"{DNS}:10000":true}}}}"#
        )
    }

    const POLICY_REFUSAL: &str = "Funnel is not enabled on your tailnet.\nTo enable, visit:\n\n         https://login.tailscale.com/f/funnel?node=nSynthetic123\n";

    /// A Tailscale command line in memory: `serve status` answers its state, and the
    /// funnel commands change it.
    pub(crate) struct FakeCli {
        pub(crate) installed: bool,
        pub(crate) status: Mutex<String>,
        pub(crate) serve: Mutex<String>,
        /// The answer of `funnel --bg`: `None` succeeds and makes the route ours.
        pub(crate) refusal: Mutex<Option<String>>,
        pub(crate) calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeCli {
        pub(crate) fn connected(serve: String) -> Self {
            Self {
                installed: true,
                status: Mutex::new(status_json()),
                serve: Mutex::new(serve),
                refusal: Mutex::new(None),
                calls: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|call| call.join(" "))
                .collect()
        }
    }

    impl TailscaleCli for FakeCli {
        fn run(&self, args: &[&str]) -> Option<CliOutput> {
            if !self.installed {
                return None;
            }
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|arg| (*arg).to_owned()).collect());
            let ok = |stdout: String| CliOutput {
                success: true,
                stdout,
                stderr: String::new(),
            };
            Some(match args {
                ["status", "--json"] => ok(self.status.lock().unwrap().clone()),
                ["serve", "status", "--json"] => ok(self.serve.lock().unwrap().clone()),
                ["funnel", "--bg", https, target] => {
                    assert!(
                        *https == "--https=8443" || *https == "--https=10000",
                        "only 8443 or 10000: {https}"
                    );
                    if let Some(text) = self.refusal.lock().unwrap().clone() {
                        return Some(CliOutput {
                            success: false,
                            stdout: text,
                            stderr: String::new(),
                        });
                    }
                    *self.serve.lock().unwrap() = if *https == "--https=10000" {
                        serve_other_8443_and_10000(target)
                    } else {
                        serve_with_8443(target, true)
                    };
                    ok(String::new())
                }
                ["funnel", https, "off"] => {
                    assert!(
                        *https == "--https=8443" || *https == "--https=10000",
                        "only 8443 or 10000: {https}"
                    );
                    *self.serve.lock().unwrap() = serve_443_only();
                    ok(String::new())
                }
                other => panic!("an unexpected command: {other:?}"),
            })
        }
    }

    #[test]
    fn status_gives_the_name_or_says_why_not() {
        assert_eq!(
            parse_status(&status_json()),
            Tailscale::Connected {
                dns_name: DNS.to_owned()
            }
        );
        assert_eq!(
            parse_status(r#"{"BackendState":"NeedsLogin","Self":{"DNSName":""}}"#),
            Tailscale::NotConnected {
                state: "NeedsLogin".to_owned()
            }
        );
        assert!(matches!(
            parse_status(r#"{"BackendState":"Running","Self":{"DNSName":""}}"#),
            Tailscale::NotConnected { .. }
        ));
        assert!(matches!(
            parse_status("not json"),
            Tailscale::NotConnected { .. }
        ));
        let missing = Funnel::new(Arc::new(FakeCli {
            installed: false,
            ..FakeCli::connected(String::new())
        }));
        assert_eq!(missing.status(), Tailscale::Missing);
        assert_eq!(missing.enable(49200, None), Err(FunnelError::NoTailscale));
        assert_eq!(missing.disable(49200), Ok(false));
    }

    #[test]
    fn serve_status_fixtures_are_read() {
        let own = target_url(49200);
        // Normal: nothing, or `{}`.
        for empty in ["", "{}", " {}\n"] {
            let state = parse_serve_status(empty, &own).unwrap();
            assert_eq!(state.funnel_port, PortUse::Free);
            assert!(!state.https_public && !state.funnel_port_public);
        }
        // 443 in use by another handler through Serve: 8443 is free, nothing is public.
        let state = parse_serve_status(&serve_443_only(), &own).unwrap();
        assert_eq!(state.funnel_port, PortUse::Free);
        assert!(!state.https_public);
        // 8443 ours, and public.
        let state = parse_serve_status(&serve_with_8443(&own, true), &own).unwrap();
        assert_eq!(state.funnel_port, PortUse::Ours);
        assert!(state.funnel_port_public);
        assert_eq!(
            parse_serve_status(&serve_with_8443(&format!("{own}/"), false), &own)
                .unwrap()
                .funnel_port,
            PortUse::Ours
        );
        // 8443 of another target.
        let state =
            parse_serve_status(&serve_with_8443("http://127.0.0.1:8080", true), &own).unwrap();
        assert_eq!(
            state.funnel_port,
            PortUse::Other {
                target: "http://127.0.0.1:8080".to_owned()
            }
        );
        // A TCP forward on 8443, a foreground session of the same target, and 443 public.
        let tcp = r#"{"TCP":{"8443":{"TCPForward":"127.0.0.1:22"}}}"#;
        assert!(matches!(
            parse_serve_status(tcp, &own).unwrap().funnel_port,
            PortUse::Other { .. }
        ));
        let foreground = format!(
            r#"{{"Foreground":{{"s1":{}}}}}"#,
            serve_with_8443(&own, true)
        );
        assert!(matches!(
            parse_serve_status(&foreground, &own).unwrap().funnel_port,
            PortUse::Other { .. }
        ));
        let public_443 = format!(
            r#"{{"TCP":{{"443":{{"HTTPS":true}}}},"Web":{{"{DNS}:443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:3773"}}}}}}}},"AllowFunnel":{{"{DNS}:443":true}}}}"#
        );
        assert!(parse_serve_status(&public_443, &own).unwrap().https_public);
        assert!(matches!(
            parse_serve_status("[1]", &own),
            Err(FunnelError::Unreadable(_))
        ));
    }

    #[test]
    fn a_policy_refusal_keeps_its_admin_link() {
        let Some(FunnelError::Policy { message, link }) = parse_refusal(POLICY_REFUSAL) else {
            panic!("a policy refusal");
        };
        assert_eq!(
            link.as_deref(),
            Some("https://login.tailscale.com/f/funnel?node=nSynthetic123")
        );
        assert!(message.contains("Funnel is not enabled on your tailnet."));
        let attribute = "Funnel not available; \"funnel\" node attribute not set. See https://tailscale.com/s/no-funnel.";
        let Some(FunnelError::Policy { link, .. }) = parse_refusal(attribute) else {
            panic!("a policy refusal");
        };
        assert_eq!(link.as_deref(), Some("https://tailscale.com/s/no-funnel"));
        assert_eq!(parse_refusal("connection refused"), None);
        // A link to another host is not kept.
        let Some(FunnelError::Policy { link, .. }) =
            parse_refusal("Funnel is not enabled. Visit https://evil.example/funnel")
        else {
            panic!("a policy refusal");
        };
        assert_eq!(link, None);
    }

    #[test]
    fn enable_and_disable_touch_only_8443_and_only_the_own_handler() {
        let cli = Arc::new(FakeCli::connected(serve_443_only()));
        let funnel = Funnel::new(cli.clone());
        assert_eq!(funnel.enable(49200, None), Ok(DNS.to_owned()));
        assert_eq!(
            cli.calls(),
            [
                "status --json",
                "serve status --json",
                "funnel --bg --https=8443 http://127.0.0.1:49200",
                "serve status --json"
            ]
        );
        // Again: already on, no command.
        cli.calls.lock().unwrap().clear();
        assert_eq!(funnel.enable(49200, None), Ok(DNS.to_owned()));
        assert!(!cli.calls().iter().any(|call| call.starts_with("funnel")));
        // Off: only its own handler, never a reset, never 443.
        assert_eq!(funnel.disable(49200), Ok(true));
        assert_eq!(funnel.disable(49200), Ok(false));
        // A stale entry of an earlier port of the app goes first.
        *cli.serve.lock().unwrap() = serve_with_8443(&target_url(49100), true);
        assert_eq!(funnel.enable(49200, Some(49100)), Ok(DNS.to_owned()));
        // Another target is refused and kept, with 10000 as the other port.
        *cli.serve.lock().unwrap() = serve_with_8443("http://127.0.0.1:8080", true);
        assert_eq!(
            funnel.enable(49200, Some(49100)),
            Err(FunnelError::PortTaken {
                port: FUNNEL_PORT,
                target: "http://127.0.0.1:8080".to_owned(),
                alternative: Some(OTHER_FUNNEL_PORT)
            })
        );
        assert_eq!(funnel.disable(49200), Ok(false));
        for call in cli.calls() {
            assert!(!call.contains("reset"), "{call}");
            assert!(
                !call
                    .split(' ')
                    .any(|arg| arg == "--https=443" || arg == "443"),
                "{call}"
            );
        }
        // The policy refuses: its text and link reach the owner.
        *cli.serve.lock().unwrap() = serve_443_only();
        *cli.refusal.lock().unwrap() = Some(POLICY_REFUSAL.to_owned());
        let refused = funnel.enable(49200, None).unwrap_err();
        assert!(matches!(refused, FunnelError::Policy { link: Some(_), .. }));
        assert!(
            refused
                .message()
                .contains("https://login.tailscale.com/f/funnel")
        );
        // 443 public: nothing is added.
        *cli.refusal.lock().unwrap() = None;
        *cli.serve.lock().unwrap() = format!(
            r#"{{"AllowFunnel":{{"{DNS}:443":true}},"Web":{{"{DNS}:443":{{"Handlers":{{"/":{{"Proxy":"http://127.0.0.1:3773"}}}}}}}}}}"#
        );
        assert_eq!(funnel.enable(49200, None), Err(FunnelError::HttpsPublic));
    }

    #[test]
    fn port_10000_takes_the_route_when_8443_is_taken() {
        let cli = Arc::new(FakeCli::connected(serve_with_8443(
            "http://127.0.0.1:8080",
            true,
        )));
        let funnel = Funnel::new(cli.clone());
        assert_eq!(funnel.port(), FUNNEL_PORT);
        assert!(matches!(
            funnel.enable(49200, None),
            Err(FunnelError::PortTaken {
                alternative: Some(OTHER_FUNNEL_PORT),
                ..
            })
        ));
        // Only the two Funnel ports are taken.
        assert!(!funnel.set_port(443));
        assert!(!funnel.set_port(8080));
        assert_eq!(funnel.port(), FUNNEL_PORT);
        assert!(funnel.set_port(OTHER_FUNNEL_PORT));
        assert_eq!(
            funnel.origin(DNS),
            format!("https://{DNS}:{OTHER_FUNNEL_PORT}")
        );
        cli.calls.lock().unwrap().clear();
        assert_eq!(funnel.enable(49200, None), Ok(DNS.to_owned()));
        assert!(
            cli.calls()
                .contains(&"funnel --bg --https=10000 http://127.0.0.1:49200".to_owned()),
            "{:?}",
            cli.calls()
        );
        // The handler of the other program on 8443 stays; off turns 10000 off only.
        assert_eq!(funnel.disable(49200), Ok(true));
        assert!(cli.calls().contains(&"funnel --https=10000 off".to_owned()));
        assert!(!cli.calls().iter().any(|call| call.contains("--https=8443")));
        // A port taken on 10000 offers no other port.
        let taken = FunnelError::PortTaken {
            port: OTHER_FUNNEL_PORT,
            target: "x".to_owned(),
            alternative: alternative_port(OTHER_FUNNEL_PORT),
        };
        assert!(!taken.message().contains("use port"));
    }
}
