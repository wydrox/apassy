//! Passkeys for the macOS passkey sheet: the app side of the credential bridge.
//!
//! The AutoFill extension (`ApassyAutoFill.appex`) is sandboxed. It talks to the signed
//! credential bridge (`Contents/MacOS/apassy-credential-bridge`) through a socket in the
//! app group container. The bridge checks the code signature of each extension peer, and
//! that its own parent is the signed Apassy app. The app starts the bridge as its child
//! for each unlocked vault session, and talks to it through the pipes of the child: one
//! JSON object per line (`native/ApassyCredentialBridge/BridgeWire.swift`).
//!
//! - bridge to app: `{"type":"ready","v":1,"socket":…}`,
//!   `{"type":"request","v":1,"rid":UUID,"owner_check":…,"peer":{…},"payload":{"op":…}}`,
//!   `{"type":"cancel","v":1,"rid":UUID,"reason":…}`, and a fatal
//!   `{"type":"error","v":1,"code":…,"message":…}`.
//! - app to bridge: `{"type":"response","rid":UUID,"result":{"ok":…}}` with the result
//!   shape of the iPhone core (standard base64), and `{"type":"shutdown"}`.
//!
//! The app checks the provenance of each request (`peer`): the signed extension of this
//! Apassy.app, as the bridge found it. A development override is refused in a release.
//! `owner_check` is a hint of the bridge and never an authority: the app decides itself
//! which call needs its owner check. `passkey_list`, `autofill_list`, and
//! `credential_identities` answer at once: they have metadata only, no password, no
//! seed, and no key. `autofill_credential` and `autofill_code` open the owner check
//! dialog for exactly that request and login (and code field), like a passkey. A login
//! without a password (a passkey only) never fills a password.
//! `passkey_assert` and `passkey_register` open the owner check dialog of the app. The
//! proof names the request exactly, with no web origin: macOS checked the relying party.
//! So a proof for the browser never signs a request of the sheet, and the other way
//! around. A cancel line, a deadline, a bridge that ends, a lock, or a vault switch
//! closes the dialog, and a late check signs and fills nothing. There is no way to
//! export a key or a seed here: every other call answers `unsupported`.
//!
//! Before it starts the bridge, a release build checks that it is the program next to
//! the app executable, and that its signature is the Apassy team's
//! (`/usr/bin/codesign --verify`). A bridge that fails the check never starts.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use eframe::egui;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::DesktopApp;
use super::browser::PasskeyDone;
use super::owner_check::{OwnerRequest, PasskeyAccount, PasskeyRequest, page_text};
use super::owner_cli::bring_to_front;
use super::owner_socket::PeerGone;
use super::owner_store::{SYSTEM_FILL_ORIGIN, SystemLogin};
use crate::browser::site::{Page, Website};
use crate::browser::webauthn;
use crate::desktop::model::ModelError;
use crate::vault::PasskeyTarget;

/// The file name of the bridge in `Contents/MacOS`.
pub(crate) const BRIDGE_FILE: &str = "apassy-credential-bridge";
/// Debug builds only: the path of a bridge to start.
pub(crate) const BRIDGE_ENV: &str = "APASSY_CREDENTIAL_BRIDGE";
/// The code requirement of the bridge: Apple-issued Developer ID or development
/// certificate of the Apassy team, and the bridge's own identifier.
const BRIDGE_REQUIREMENT: &str = "=anchor apple generic and identifier \"com.wydrox.apassy.credential-bridge\" and certificate leaf[subject.OU] = \"7S3F9767BM\"";
const CODESIGN: &str = "/usr/bin/codesign";
/// The signed extension that may ask, as the bridge names it in `peer`.
const EXTENSION_IDENTIFIER: &str = "com.wydrox.apassy.autofill";
const TEAM: &str = "7S3F9767BM";
const EXTENSION_FROM_BUNDLE: &str = "Contents/PlugIns/ApassyAutoFill.appex";
/// The longest line of the bridge: a request of 64 KiB and its envelope.
pub(crate) const MAX_LINE_BYTES: usize = 72 * 1024;
/// The bridge gives up on a request after 180 s. The dialog closes a little before.
const REQUEST_TIME: Duration = Duration::from_secs(175);
/// After a bridge fails, the app waits this long before it starts one again.
const RESTART_PAUSE: Duration = Duration::from_secs(10);
/// A stopped bridge gets this long to exit after its input closes.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// The most requests that may wait at one time.
const MAX_WAITING: usize = 16;
/// The ES256 algorithm of COSE.
const ES256: i64 = -7;
const MAX_ALGORITHMS: usize = 16;
/// The most service identifiers in one `autofill_list`, as the bridge allows.
const MAX_DOMAINS: usize = 16;

/// A line for the bridge, or the end of its input.
pub(crate) enum Out {
    Line(Zeroizing<Vec<u8>>),
    Stop,
}

/// What the bridge sent.
pub(crate) enum PlatformEvent {
    /// The bridge listens on `socket`.
    Ready { socket: String },
    Request {
        rid: String,
        op: String,
        args: Value,
        cancel: PeerGone,
    },
    /// The bridge ended, failed, or sent a line that is not the protocol.
    Closed(String),
}

/// The provenance that a release accepts: the signed extension inside this Apassy.app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerRule {
    /// Release: the signature check of the bridge, this identifier and team, and the
    /// exact resolved path of the extension of this bundle.
    Signed { appex: PathBuf },
    /// Debug builds and tests: also the development override of a development bridge.
    Development,
}

impl PeerRule {
    /// The rule of the running app.
    fn for_this_app() -> Self {
        if cfg!(debug_assertions) {
            return Self::Development;
        }
        let appex = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .ok()
            .and_then(|exe| {
                Some(
                    exe.parent()?
                        .parent()?
                        .parent()?
                        .join(EXTENSION_FROM_BUNDLE),
                )
            })
            .and_then(|path| std::fs::canonicalize(path).ok())
            // No extension in the bundle: no path matches, so every request is refused.
            .unwrap_or_default();
        Self::Signed { appex }
    }

    /// Check the `peer` of a request. The error has no value of the request.
    fn check(&self, peer: &Value) -> Result<(), &'static str> {
        let fields = peer.as_object().ok_or("the request has no provenance")?;
        let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
        if keys
            != [
                "check",
                "path",
                "pid",
                "signing_identifier",
                "source",
                "team",
            ]
        {
            return Err("the provenance has other fields");
        }
        let text = |name: &str| fields.get(name).and_then(Value::as_str).unwrap_or("\u{0}");
        if text("source") != "macos_autofill_extension"
            || !fields
                .get("pid")
                .and_then(Value::as_u64)
                .is_some_and(|pid| (1..=u64::from(u32::MAX)).contains(&pid))
        {
            return Err("the provenance is not an extension process");
        }
        match (text("check"), self) {
            ("code_signature", Self::Signed { appex }) => {
                if text("signing_identifier") == EXTENSION_IDENTIFIER
                    && text("team") == TEAM
                    && !appex.as_os_str().is_empty()
                    && Path::new(text("path")) == appex.as_path()
                {
                    Ok(())
                } else {
                    Err("the extension is not the signed extension of this Apassy.app")
                }
            }
            ("code_signature", Self::Development) => {
                if text("signing_identifier") == EXTENSION_IDENTIFIER && text("team") == TEAM {
                    Ok(())
                } else {
                    Err("the extension is not the signed Apassy extension")
                }
            }
            ("development_override", Self::Development) => Ok(()),
            _ => Err("the bridge did not check the signature of the extension"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    rp_id: String,
    #[serde(default)]
    allowed: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertArgs {
    id: u64,
    rp_id: String,
    credential_id: String,
    client_data_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterArgs {
    rp_id: String,
    user_name: String,
    #[serde(default)]
    user_display_name: String,
    user_handle: String,
    client_data_hash: String,
    #[serde(default)]
    algorithms: Vec<i64>,
    #[serde(default)]
    excluded: Vec<String>,
    #[serde(default)]
    attach_id: Option<u64>,
    #[serde(default)]
    attach_revision: Option<u64>,
    #[serde(default)]
    title: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainsArgs {
    domains: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemArgs {
    id: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

/// A password or a code for macOS AutoFill after the owner check, on its way to the
/// ticket. The buffers are erased on drop.
pub(crate) enum SystemFilled {
    Login {
        item: u64,
        username: String,
        password: Zeroizing<String>,
    },
    Code {
        item: u64,
        digits: Zeroizing<String>,
        remaining: u64,
    },
}

/// The cancel state of each request that waits, by request ID. The reader thread sets it.
type Waiting = Arc<Mutex<HashMap<String, PeerGone>>>;

/// The bridge of the macOS passkey sheet. Idle until the window finds the bridge, so
/// tests start nothing.
#[derive(Default)]
pub(crate) struct PlatformHost {
    /// The bridge program. `None`: this build has none, or the window did not look.
    path: Option<PathBuf>,
    running: Option<Bridge>,
    /// Why the bridge does not run. Settings can show it.
    pub(crate) problem: Option<String>,
    /// The socket of the bridge after its `ready` line.
    pub(crate) socket: Option<String>,
    /// The password or code of the AutoFill check that passed.
    pub(crate) filled: Option<Result<SystemFilled, ModelError>>,
    retry_after: Option<Instant>,
}

struct Bridge {
    child: Child,
    out: Sender<Out>,
    events: Receiver<PlatformEvent>,
    waiting: Waiting,
    /// The vault session that the bridge serves.
    epoch: [u8; 32],
}

impl PlatformHost {
    /// Use the bridge at `path`. The app starts it at the next unlock.
    pub(crate) fn enable(&mut self, path: PathBuf) {
        self.path = Some(path);
    }

    /// Stop the bridge. Each request that waits is cancelled: its dialog closes at the
    /// next frame, and it signs nothing.
    pub(crate) fn stop(&mut self) {
        self.socket = None;
        self.filled = None;
        if let Some(bridge) = self.running.take() {
            bridge.stop();
        }
    }
}

impl Bridge {
    fn stop(self) {
        let Self {
            mut child,
            out,
            waiting,
            ..
        } = self;
        for gone in waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
        {
            gone.set();
        }
        let _ = out.send(Out::Line(json_line(&json!({ "type": "shutdown" }))));
        let _ = out.send(Out::Stop);
        // The bridge exits at the end of its input. A bridge that does not stops after
        // the grace time, on a thread, so the window never waits for it.
        let _ = std::thread::Builder::new()
            .name("apassy-bridge-reap".to_owned())
            .spawn(move || {
                let start = Instant::now();
                while start.elapsed() < STOP_GRACE {
                    if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
            });
    }
}

/// One JSON object and a line break, in an erasing buffer.
fn json_line(value: &Value) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    if serde_json::to_writer(&mut *bytes, value).is_err() {
        bytes.clear();
    }
    bytes.push(b'\n');
    bytes
}

/// The way back to one request of the bridge. A ticket that drops without an answer
/// answers `cancelled`: for example when the owner closes the dialog.
pub(crate) struct PlatformTicket {
    rid: String,
    out: Option<Sender<Out>>,
    cancel: PeerGone,
    deadline: Instant,
    waiting: Option<Waiting>,
}

impl PlatformTicket {
    fn new(rid: String, out: Sender<Out>, cancel: PeerGone, waiting: Option<Waiting>) -> Self {
        Self {
            rid,
            out: Some(out),
            cancel,
            deadline: Instant::now() + REQUEST_TIME,
            waiting,
        }
    }

    /// A ticket whose lines go to the returned receiver, for tests.
    #[cfg(test)]
    pub(crate) fn for_test(rid: &str) -> (Self, PeerGone, Receiver<Out>) {
        let (out, lines) = mpsc::channel();
        let cancel = PeerGone::default();
        (
            Self::new(rid.to_owned(), out, cancel.clone(), None),
            cancel,
            lines,
        )
    }

    /// Move the deadline to now, as if the time passed.
    #[cfg(test)]
    pub(crate) fn age(&mut self) {
        self.deadline = Instant::now();
    }

    /// True while the bridge still waits: no cancel line, the bridge runs, and the
    /// deadline did not pass. A passkey signs only for a live ticket.
    pub(crate) fn is_live(&self) -> bool {
        self.out.is_some() && !self.cancel.is_set() && Instant::now() < self.deadline
    }

    /// Send `{"ok":true,"result":…}`. False when the bridge is gone. A result with a
    /// secret is written straight into the erasing line buffer.
    fn ok(mut self, result: &impl Serialize) -> bool {
        #[derive(Serialize)]
        struct Done<'a, T> {
            ok: bool,
            result: &'a T,
        }
        self.answer(&Done { ok: true, result })
    }

    /// Send `{"ok":false,"error":{…}}`, with the error code that the extension knows.
    pub(crate) fn fail(mut self, code: &str, message: &str) -> bool {
        self.answer(&error_body(native_code(code), message))
    }

    fn answer(&mut self, result: &impl Serialize) -> bool {
        let Some(out) = self.out.take() else {
            return false;
        };
        if let Some(waiting) = &self.waiting {
            waiting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.rid);
        }
        #[derive(Serialize)]
        struct Response<'a, T> {
            #[serde(rename = "type")]
            kind: &'static str,
            rid: &'a str,
            result: &'a T,
        }
        let mut line = Zeroizing::new(Vec::with_capacity(4096));
        let response = Response {
            kind: "response",
            rid: &self.rid,
            result,
        };
        if serde_json::to_writer(&mut *line, &response).is_err() {
            return false;
        }
        line.push(b'\n');
        out.send(Out::Line(line)).is_ok() && !self.cancel.is_set()
    }
}

impl Drop for PlatformTicket {
    fn drop(&mut self) {
        if self.out.is_some() {
            self.answer(&error_body(
                "cancelled",
                "The owner check closed before it passed. Nothing was signed.",
            ));
        }
    }
}

/// The error code of the app as the extension reads it (`ProviderWire.swift`).
fn native_code(code: &str) -> &str {
    match code {
        "vault_locked" => "locked",
        "none_open" => "no_vault",
        "no_match" | "no_code" => "not_found",
        other => other,
    }
}

fn error_body(code: &str, message: &str) -> Value {
    json!({ "ok": false, "error": { "code": code, "message": message } })
}

// ---- The bridge program. ----

/// The bridge next to the running executable, when it is there. Debug builds first read
/// [`BRIDGE_ENV`]; release builds ignore it.
pub(crate) fn locate_bridge() -> Option<PathBuf> {
    if cfg!(debug_assertions)
        && let Some(path) = std::env::var_os(BRIDGE_ENV).filter(|value| !value.is_empty())
    {
        return Some(PathBuf::from(path));
    }
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .ok()?;
    let path = exe.parent()?.join(BRIDGE_FILE);
    path.is_file().then_some(path)
}

/// Check the bridge at `path` before it starts. Release builds: the program is the file
/// next to the running executable, and its signature meets [`BRIDGE_REQUIREMENT`].
/// Debug builds accept the path of [`BRIDGE_ENV`] as it is.
fn verify_bridge(path: &Path) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|err| format!("the credential bridge is missing: {err}"))?;
    if cfg!(debug_assertions) && std::env::var_os(BRIDGE_ENV).is_some() {
        return Ok(canonical);
    }
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|err| format!("cannot find the running executable: {err}"))?;
    if exe.parent().map(|dir| dir.join(BRIDGE_FILE)) != Some(canonical.clone()) {
        return Err("the credential bridge is not the one in this Apassy.app.".to_owned());
    }
    let status = Command::new(CODESIGN)
        .args(["--verify", "--strict", "-R", BRIDGE_REQUIREMENT])
        .arg(&canonical)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("cannot check the signature of the credential bridge: {err}"))?;
    if !status.success() {
        return Err("the credential bridge does not have the Apassy signature.".to_owned());
    }
    Ok(canonical)
}

/// Start the bridge at `path` for the vault session `epoch`. The bridge takes no
/// arguments.
fn start_bridge(
    path: &Path,
    epoch: [u8; 32],
    wake: impl Fn() + Send + 'static,
) -> Result<Bridge, String> {
    let program = verify_bridge(path)?;
    let mut child = Command::new(&program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("the credential bridge did not start: {err}"))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("the pipes of the credential bridge are missing.".to_owned());
    };
    let (out, lines) = mpsc::channel();
    let (events_in, events) = mpsc::channel();
    let waiting: Waiting = Arc::default();
    let rule = PeerRule::for_this_app();
    let refusals = out.clone();
    let spawned = std::thread::Builder::new()
        .name("apassy-bridge-write".to_owned())
        .spawn(move || write_bridge(stdin, &lines))
        .and_then(|_| {
            let waiting = Arc::clone(&waiting);
            std::thread::Builder::new()
                .name("apassy-bridge-read".to_owned())
                .spawn(move || read_bridge(stdout, &rule, &events_in, &refusals, &waiting, &wake))
        });
    if let Err(err) = spawned {
        let _ = out.send(Out::Stop);
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("the credential bridge did not start: {err}"));
    }
    Ok(Bridge {
        child,
        out,
        events,
        waiting,
        epoch,
    })
}

/// Write each line to the bridge until [`Out::Stop`] or the end of the channel. The
/// input of the bridge closes after.
fn write_bridge(mut stdin: ChildStdin, lines: &Receiver<Out>) {
    for line in lines {
        match line {
            Out::Line(bytes) => {
                if stdin
                    .write_all(&bytes)
                    .and_then(|()| stdin.flush())
                    .is_err()
                {
                    return;
                }
            }
            Out::Stop => return,
        }
    }
}

/// True for a request ID of the bridge: a UUID, as Foundation writes it.
fn is_rid(rid: &str) -> bool {
    rid.len() == 36
        && rid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

/// True when the keys of `line` are exactly `keys` (sorted), and `v` is 1.
fn exact(line: &Map<String, Value>, keys: &[&str]) -> bool {
    let mut have: Vec<&str> = line.keys().map(String::as_str).collect();
    have.sort_unstable();
    have == keys && line.get("v").and_then(Value::as_u64) == Some(1)
}

/// What one line of the bridge asks for.
enum Line {
    Ready(String),
    Request {
        rid: String,
        op: String,
        args: Value,
        peer: Value,
    },
    Cancel(String),
    Fatal(String),
}

/// Parse one line of the bridge strictly. `None`: not the protocol.
fn parse_line(bytes: &[u8]) -> Option<Line> {
    let Value::Object(mut line) = serde_json::from_slice::<Value>(bytes).ok()? else {
        return None;
    };
    let kind = line.get("type")?.as_str()?.to_owned();
    match kind.as_str() {
        "ready" if exact(&line, &["socket", "type", "v"]) => {
            Some(Line::Ready(line.get("socket")?.as_str()?.to_owned()))
        }
        "request"
            if exact(
                &line,
                &["owner_check", "payload", "peer", "rid", "type", "v"],
            ) =>
        {
            // `owner_check` is a hint of the bridge. The app decides by the call.
            line.get("owner_check")?.as_bool()?;
            let rid = line
                .get("rid")?
                .as_str()
                .filter(|rid| is_rid(rid))?
                .to_owned();
            let peer = line.remove("peer")?;
            let Value::Object(mut payload) = line.remove("payload")? else {
                return None;
            };
            let Value::String(op) = payload.remove("op")? else {
                return None;
            };
            Some(Line::Request {
                rid,
                op,
                args: Value::Object(payload),
                peer,
            })
        }
        "cancel" if exact(&line, &["reason", "rid", "type", "v"]) => {
            line.get("reason")?.as_str()?;
            let rid = line.get("rid")?.as_str().filter(|rid| is_rid(rid))?;
            Some(Line::Cancel(rid.to_owned()))
        }
        "error" if exact(&line, &["code", "message", "type", "v"]) => {
            let code = line.get("code")?.as_str()?;
            let code: String = code
                .chars()
                .filter(|c| c.is_ascii_lowercase() || *c == '_')
                .take(64)
                .collect();
            Some(Line::Fatal(format!(
                "the credential bridge stopped ({code})."
            )))
        }
        _ => None,
    }
}

/// Read the lines of the bridge until its output ends. A cancel line sets the cancel
/// state of its request. A request whose provenance `rule` refuses gets
/// `caller_not_allowed` through `out`, and the app never sees it. The end of the
/// output, an error line, or a line that is not the protocol cancels every request and
/// ends the bridge.
pub(crate) fn read_bridge(
    output: impl Read,
    rule: &PeerRule,
    events: &Sender<PlatformEvent>,
    out: &Sender<Out>,
    waiting: &Waiting,
    wake: &dyn Fn(),
) {
    let mut reader = BufReader::new(output);
    let why = loop {
        let mut bytes = Zeroizing::new(Vec::new());
        match (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut bytes)
        {
            Ok(0) => break "the credential bridge ended.".to_owned(),
            Ok(_) if bytes.last() == Some(&b'\n') => {}
            Ok(_) => break "the credential bridge sent a line that is too long.".to_owned(),
            Err(err) => break format!("the credential bridge cannot be read: {err}"),
        }
        let event = match parse_line(&bytes) {
            None => break "the credential bridge sent a line that is not valid.".to_owned(),
            Some(Line::Fatal(why)) => break why,
            Some(Line::Ready(socket)) => PlatformEvent::Ready { socket },
            Some(Line::Cancel(rid)) => {
                if let Some(gone) = waiting
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&rid)
                {
                    gone.set();
                }
                wake();
                continue;
            }
            Some(Line::Request {
                rid,
                op,
                args,
                peer,
            }) => {
                if let Err(why) = rule.check(&peer) {
                    let refusal = json!({
                        "type": "response",
                        "rid": rid,
                        "result": error_body("caller_not_allowed", &format!("Apassy refused the request: {why}.")),
                    });
                    let _ = out.send(Out::Line(json_line(&refusal)));
                    continue;
                }
                let mut table = waiting.lock().unwrap_or_else(PoisonError::into_inner);
                if table.contains_key(&rid) {
                    break "the credential bridge sent one request ID twice.".to_owned();
                }
                if table.len() >= MAX_WAITING {
                    break "the credential bridge sent too many requests.".to_owned();
                }
                let cancel = PeerGone::default();
                table.insert(rid.clone(), cancel.clone());
                PlatformEvent::Request {
                    rid,
                    op,
                    args,
                    cancel,
                }
            }
        };
        if events.send(event).is_err() {
            return;
        }
        wake();
    };
    for gone in waiting
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .drain()
        .map(|(_, gone)| gone)
    {
        gone.set();
    }
    let _ = events.send(PlatformEvent::Closed(why));
    wake();
}

// ---- The requests. ----

/// A failure before any dialog: a code and a message for the bridge.
type Refusal = (&'static str, String);

fn bad(message: &str) -> Refusal {
    ("bad_request", message.to_owned())
}

/// Bytes in standard base64 with `min..=max` bytes.
fn bytes_in(text: &str, min: usize, max: usize, what: &str) -> Result<Vec<u8>, Refusal> {
    webauthn::decode_bytes(text, min, max).map_err(|_| bad(&format!("The {what} is not valid.")))
}

fn hash_in(text: &str) -> Result<[u8; 32], Refusal> {
    let bytes = bytes_in(text, 32, 32, "client data hash")?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

fn ids_in(ids: &[String]) -> Result<Vec<Vec<u8>>, Refusal> {
    webauthn::decode_ids(ids).map_err(|_| bad("A credential ID is not valid."))
}

impl DesktopApp {
    /// Find the bridge of this build. The window calls this once; tests never do.
    pub(crate) fn find_credential_bridge(&mut self) {
        if let Some(path) = locate_bridge() {
            self.platform.enable(path);
        }
    }

    /// Start or stop the bridge with the vault session, and answer what it sent. The app
    /// calls this each frame, also while the window is hidden.
    pub(crate) fn poll_platform(&mut self, ctx: &egui::Context) {
        let epoch = self.owner_ui.session.epoch();
        if self
            .platform
            .running
            .as_ref()
            .is_some_and(|bridge| Some(bridge.epoch) != epoch)
        {
            // A lock, an unlock, or another vault ends the session of the bridge.
            self.platform.stop();
        }
        if self.platform.running.is_none()
            && let (Some(epoch), Some(path)) = (epoch, self.platform.path.clone())
            && self
                .platform
                .retry_after
                .is_none_or(|after| Instant::now() >= after)
        {
            let repaint = ctx.clone();
            match start_bridge(&path, epoch, move || repaint.request_repaint()) {
                Ok(bridge) => {
                    self.platform.running = Some(bridge);
                    self.platform.problem = None;
                }
                Err(problem) => {
                    self.platform.problem = Some(problem);
                    self.platform.retry_after = Some(Instant::now() + RESTART_PAUSE);
                }
            }
        }
        let Some(bridge) = &self.platform.running else {
            return self.expire_platform_check(ctx);
        };
        let events: Vec<PlatformEvent> = bridge.events.try_iter().collect();
        let out = bridge.out.clone();
        let waiting = Arc::clone(&bridge.waiting);
        for event in events {
            match event {
                PlatformEvent::Ready { socket } => self.platform.socket = Some(socket),
                PlatformEvent::Request {
                    rid,
                    op,
                    args,
                    cancel,
                } => {
                    let ticket =
                        PlatformTicket::new(rid, out.clone(), cancel, Some(Arc::clone(&waiting)));
                    self.handle_platform(&op, args, ticket, ctx);
                }
                PlatformEvent::Closed(why) => {
                    self.platform.stop();
                    self.platform.problem = Some(why);
                    self.platform.retry_after = Some(Instant::now() + RESTART_PAUSE);
                }
            }
        }
        self.expire_platform_check(ctx);
    }

    /// Answer one request of the bridge. Tests call this with a ticket of their own.
    pub(crate) fn handle_platform(
        &mut self,
        op: &str,
        args: Value,
        ticket: PlatformTicket,
        ctx: &egui::Context,
    ) {
        let rid = ticket.rid.clone();
        let request = match op {
            "passkey_list" => match self.platform_list(args) {
                Ok(list) => {
                    ticket.ok(&list);
                    return;
                }
                Err(refusal) => Err(refusal),
            },
            "autofill_list" | "credential_identities" => {
                let listed = if op == "autofill_list" {
                    self.platform_fill_list(args)
                } else {
                    self.platform_identities(args)
                };
                match listed {
                    Ok(list) => {
                        ticket.ok(&list);
                        return;
                    }
                    Err(refusal) => Err(refusal),
                }
            }
            "passkey_assert" => self.platform_assert(&rid, args),
            "passkey_register" => self.platform_register(&rid, args),
            "autofill_credential" => self.platform_fill(&rid, args),
            "autofill_code" => self.platform_code(&rid, args),
            // No import, no removal, and no export of a key or a seed through the sheet.
            _ => Err((
                "unsupported",
                "Apassy does not do this for the macOS passkey sheet.".to_owned(),
            )),
        };
        match request {
            Ok(request) => self.ask_owner_for_platform(request, ticket, ctx),
            Err((code, message)) => {
                ticket.fail(code, &message);
            }
        }
    }

    /// The vault state before a request: an open, unlocked vault.
    fn platform_unlocked(&self) -> Result<(), Refusal> {
        let session = &self.owner_ui.session;
        if !session.has_file() {
            Err((
                "none_open",
                "No vault is open. Open and unlock a vault in Apassy.".to_owned(),
            ))
        } else if session.is_locked() {
            Err((
                "vault_locked",
                "Apassy is locked. Unlock it to use passkeys.".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    /// The passkeys of a relying party, without keys.
    fn platform_list(&self, args: Value) -> Result<Value, Refusal> {
        let args: ListArgs =
            serde_json::from_value(args).map_err(|_| bad("The list request is not valid."))?;
        self.platform_unlocked()?;
        let allowed = ids_in(&args.allowed)?;
        let found = self
            .owner_ui
            .session
            .passkeys_for(&args.rp_id, &allowed)
            .map_err(|err| (err.code, err.message))?;
        let passkeys: Vec<Value> = found
            .iter()
            .map(|info| {
                json!({
                    "id": info.item_id,
                    "title": info.title,
                    "rp_id": info.rp_id,
                    "user_name": info.user_name,
                    "user_display_name": info.user_display_name,
                    "credential_id": webauthn::encode_bytes(&info.credential_id),
                    "user_handle": webauthn::encode_bytes(&info.user_handle),
                })
            })
            .collect();
        Ok(json!({ "passkeys": passkeys }))
    }

    /// The owner request of an assertion. The passkey must be canonical, for this relying
    /// party, with this credential ID: otherwise `no_match` without a dialog.
    fn platform_assert(&self, rid: &str, args: Value) -> Result<OwnerRequest, Refusal> {
        let args: AssertArgs =
            serde_json::from_value(args).map_err(|_| bad("The sign-in request is not valid."))?;
        self.platform_unlocked()?;
        let credential_id = bytes_in(
            &args.credential_id,
            1,
            crate::vault::passkey::MAX_CREDENTIAL_ID_BYTES,
            "credential ID",
        )?;
        let client_data_hash = hash_in(&args.client_data_hash)?;
        let info = self
            .owner_ui
            .session
            .passkey_of(args.id, &args.rp_id, &credential_id)
            .map_err(|err| (err.code, err.message))?
            .ok_or_else(|| {
                (
                    "no_match",
                    format!("Apassy has no such passkey for {}.", args.rp_id),
                )
            })?;
        Ok(OwnerRequest::SignPasskey {
            request: PasskeyRequest {
                origin: None,
                rid: rid.to_owned(),
                rp_id: info.rp_id.clone(),
                client_data_hash,
            },
            accounts: vec![PasskeyAccount {
                item_id: info.item_id,
                item_name: info.title,
                user_name: info.user_name,
                user_display_name: info.user_display_name,
                credential_id: info.credential_id,
            }],
            chosen: 0,
        })
    }

    /// The owner request of a registration. A request without ES256 answers
    /// `unsupported` without a dialog.
    fn platform_register(&self, rid: &str, args: Value) -> Result<OwnerRequest, Refusal> {
        let args: RegisterArgs = serde_json::from_value(args)
            .map_err(|_| bad("The passkey registration is not valid."))?;
        self.platform_unlocked()?;
        if args.algorithms.len() > MAX_ALGORITHMS {
            return Err(bad("The request names too many algorithms."));
        }
        if !args.algorithms.is_empty() && !args.algorithms.contains(&ES256) {
            return Err((
                "unsupported",
                "The request asks for a passkey type that Apassy does not make.".to_owned(),
            ));
        }
        // An invalid relying party ID fails here, before any dialog.
        self.owner_ui
            .session
            .passkeys_for(&args.rp_id, &[])
            .map_err(|err| (err.code, err.message))?;
        let user_handle = bytes_in(&args.user_handle, 1, 64, "user handle")?;
        let client_data_hash = hash_in(&args.client_data_hash)?;
        let excluded = ids_in(&args.excluded)?;
        let user_name = page_text(&args.user_name);
        if user_name.is_empty() {
            return Err(bad("A new passkey needs the name of the account."));
        }
        let user_display_name = page_text(&args.user_display_name);
        let (target, attach_name) = match (args.attach_id, args.attach_revision) {
            (Some(item_id), Some(revision)) => {
                let details = self
                    .owner_ui
                    .session
                    .details(item_id)
                    .map_err(|err| (err.code, err.message))?;
                (
                    PasskeyTarget::Attach { item_id, revision },
                    Some(details.name),
                )
            }
            (None, None) => {
                let title = match page_text(&args.title) {
                    title if title.is_empty() => args.rp_id.clone(),
                    title => title,
                };
                (PasskeyTarget::NewItem { title }, None)
            }
            _ => {
                return Err(bad(
                    "Adding a passkey to a login needs its id and its revision.",
                ));
            }
        };
        Ok(OwnerRequest::CreatePasskey {
            request: PasskeyRequest {
                origin: None,
                rid: rid.to_owned(),
                rp_id: args.rp_id,
                client_data_hash,
            },
            user_handle,
            user_name,
            user_display_name,
            algorithms: args.algorithms,
            excluded,
            target,
            attach_name,
        })
    }

    /// Open the owner check dialog for a request of the sheet, when no other check is
    /// open.
    fn ask_owner_for_platform(
        &mut self,
        request: OwnerRequest,
        ticket: PlatformTicket,
        ctx: &egui::Context,
    ) {
        if self.owner.check.is_some() {
            ticket.fail(
                "busy",
                "Another owner check is open in Apassy. Finish it, then try again.",
            );
            return;
        }
        self.ask_owner(request, Some(ctx));
        if let Some(dialog) = self.owner.check.as_mut() {
            dialog.platform = Some(ticket);
        }
        if !self.owner.touch_id_ready() {
            bring_to_front(ctx);
        }
    }

    /// Answer the request of a passed check with the result of [`Self::complete_passkey`].
    pub(crate) fn answer_platform_ticket(&mut self, ticket: PlatformTicket) {
        if let Some(filled) = self.platform.filled.take() {
            return self.answer_system_fill(ticket, filled);
        }
        let result = self.browser.passkey.take();
        let (delivered, created) = match result {
            Some(Ok(PasskeyDone::Signed(assertion))) => (
                ticket.ok(&json!({
                    "credential_id": webauthn::encode_bytes(&assertion.credential_id),
                    "user_handle": webauthn::encode_bytes(&assertion.user_handle),
                    "authenticator_data": webauthn::encode_bytes(&assertion.authenticator_data),
                    "signature": webauthn::encode_bytes(&assertion.signature),
                })),
                false,
            ),
            Some(Ok(PasskeyDone::Created(created))) => (
                ticket.ok(&json!({
                    "id": created.item_id,
                    "credential_id": webauthn::encode_bytes(&created.credential_id),
                    "attestation_object": webauthn::encode_bytes(&created.attestation_object),
                })),
                true,
            ),
            Some(Err(err)) => {
                let code = match err.code {
                    "excluded" | "unsupported" => err.code,
                    _ => "refused",
                };
                ticket.fail(code, &err.message);
                return;
            }
            None => {
                ticket.fail("refused", "Apassy did not sign.");
                return;
            }
        };
        match (delivered, created) {
            (true, false) => self.set_ok("You are signed in with a passkey from Apassy."),
            (true, true) => self.set_ok("The new passkey is saved in Apassy."),
            (false, false) => self.set_err("macOS stopped waiting. Nothing was signed in."),
            (false, true) => self.set_err(
                "The new passkey is saved in Apassy, but macOS stopped waiting for it. Remove it in Apassy, or add the passkey again.",
            ),
        }
    }

    /// Close a dialog of the sheet when its request no longer waits. A late check then
    /// signs nothing.
    pub(crate) fn expire_platform_check(&mut self, ctx: &egui::Context) {
        let Some(live) = self
            .owner
            .check
            .as_ref()
            .and_then(|dialog| dialog.platform.as_ref())
            .map(PlatformTicket::is_live)
        else {
            return;
        };
        if live {
            ctx.request_repaint_after(Duration::from_millis(500));
        } else {
            self.close_owner_check(Some(ctx));
            self.set_note("macOS cancelled the passkey request. Nothing was signed or saved.");
        }
    }

    // ---- Passwords and codes for macOS AutoFill. ----

    /// The logins for the service identifiers of macOS: the ones whose website matches
    /// (with the rule of a browser fill), then the others. Only logins with a password.
    /// No secret value.
    fn platform_fill_list(&self, args: Value) -> Result<Value, Refusal> {
        let args: DomainsArgs = serde_json::from_value(args)
            .map_err(|_| bad("The AutoFill list request is not valid."))?;
        if args.domains.len() > MAX_DOMAINS {
            return Err(bad("The AutoFill list request names too many websites."));
        }
        self.platform_unlocked()?;
        let pages: Vec<Page> = args
            .domains
            .iter()
            .filter_map(|text| service_page(text))
            .collect();
        let logins = self
            .owner_ui
            .session
            .system_logins()
            .map_err(|err| (err.code, err.message))?;
        let mut matches = Vec::new();
        let mut others = Vec::new();
        for login in logins.iter().filter(|login| login.has_password) {
            let hit = login
                .websites
                .iter()
                .filter_map(|value| Website::parse(value))
                .any(|site| pages.iter().any(|page| site.matches(page)));
            let entry = json!({
                "id": login.id,
                "title": login.title,
                "username": login.username,
                "website": login.websites.first(),
                "has_totp": login.code_field.is_some(),
                "revision": login.revision,
                "has_passkey": login.has_passkey,
            });
            if hit {
                matches.push(entry);
            } else {
                others.push(entry);
            }
        }
        Ok(json!({ "matches": matches, "others": others }))
    }

    /// The identities for the AutoFill list of macOS: the logins with a password, the
    /// passkeys, and the logins with a one-time password, once per host. No secret value.
    fn platform_identities(&self, args: Value) -> Result<Value, Refusal> {
        let _: NoArgs =
            serde_json::from_value(args).map_err(|_| bad("The identity request is not valid."))?;
        self.platform_unlocked()?;
        let session = &self.owner_ui.session;
        let logins = session
            .system_logins()
            .map_err(|err| (err.code, err.message))?;
        let mut identities = Vec::new();
        let mut totp = Vec::new();
        for login in &logins {
            for host in login_hosts(login) {
                if login.has_password {
                    identities.push(json!({
                        "id": login.id,
                        "username": login.username,
                        "host": host,
                    }));
                }
                if login.code_field.is_some() {
                    totp.push(json!({
                        "id": login.id,
                        "title": login.title,
                        "username": login.username,
                        "host": host,
                    }));
                }
            }
        }
        let passkeys: Vec<Value> = session
            .all_passkeys()
            .map_err(|err| (err.code, err.message))?
            .iter()
            .map(|info| {
                json!({
                    "id": info.item_id,
                    "title": info.title,
                    "rp_id": info.rp_id,
                    "user_name": info.user_name,
                    "user_display_name": info.user_display_name,
                    "credential_id": webauthn::encode_bytes(&info.credential_id),
                    "user_handle": webauthn::encode_bytes(&info.user_handle),
                })
            })
            .collect();
        Ok(json!({ "identities": identities, "passkeys": passkeys, "totp": totp }))
    }

    /// The owner request of a password fill. A login without a password never fills.
    fn platform_fill(&self, rid: &str, args: Value) -> Result<OwnerRequest, Refusal> {
        let args: ItemArgs =
            serde_json::from_value(args).map_err(|_| bad("The AutoFill request is not valid."))?;
        self.platform_unlocked()?;
        let login = self.platform_login(args.id)?;
        if !login.has_password {
            return Err((
                "not_found",
                "This login has no password: it signs in with a passkey only.".to_owned(),
            ));
        }
        Ok(OwnerRequest::SystemFillLogin {
            rid: rid.to_owned(),
            item_id: login.id,
            item_name: login.title,
            username: login.username,
        })
    }

    /// The owner request of a code fill: the first one-time password of the login.
    fn platform_code(&self, rid: &str, args: Value) -> Result<OwnerRequest, Refusal> {
        let args: ItemArgs =
            serde_json::from_value(args).map_err(|_| bad("The AutoFill request is not valid."))?;
        self.platform_unlocked()?;
        let login = self.platform_login(args.id)?;
        let Some(field) = login.code_field else {
            return Err((
                "not_found",
                "This login has no one-time password.".to_owned(),
            ));
        };
        Ok(OwnerRequest::SystemFillCode {
            rid: rid.to_owned(),
            item_id: login.id,
            item_name: login.title,
            field,
        })
    }

    fn platform_login(&self, id: u64) -> Result<SystemLogin, Refusal> {
        self.owner_ui
            .session
            .system_login(id)
            .map_err(|err| (err.code, err.message))?
            .ok_or_else(|| ("not_found", "This login is not in Apassy.".to_owned()))
    }

    /// Take the password of a passed AutoFill check. It waits for the ticket. The ticket
    /// was live just before.
    pub(crate) fn complete_system_fill(
        &mut self,
        rid: &str,
        item_id: u64,
        title: &str,
        proof: crate::broker::approvals::OwnerProof,
    ) {
        let result = self
            .owner_ui
            .session
            .system_fill(rid, item_id, title, proof)
            .map(|mut values| SystemFilled::Login {
                item: item_id,
                username: std::mem::take(&mut values.username),
                password: std::mem::take(&mut values.password),
            });
        if let Err(err) = &result {
            self.set_err(err.message.clone());
        }
        self.platform.filled = Some(result);
    }

    /// Make the code of a passed AutoFill check. It waits for the ticket.
    pub(crate) fn complete_system_code(
        &mut self,
        rid: &str,
        item_id: u64,
        field: &str,
        proof: crate::broker::approvals::OwnerProof,
    ) {
        let result = self
            .owner_ui
            .session
            .system_code(rid, item_id, field, proof)
            .map(|mut code| SystemFilled::Code {
                item: item_id,
                digits: std::mem::take(&mut code.digits),
                remaining: code.left,
            });
        if let Err(err) = &result {
            self.set_err(err.message.clone());
        }
        self.platform.filled = Some(result);
    }

    /// Answer a passed AutoFill check, and record the fill in the history of the login:
    /// the time and "macOS AutoFill", no value.
    fn answer_system_fill(
        &mut self,
        ticket: PlatformTicket,
        filled: Result<SystemFilled, ModelError>,
    ) {
        #[derive(Serialize)]
        struct Login<'a> {
            username: &'a str,
            password: &'a str,
        }
        #[derive(Serialize)]
        struct Code<'a> {
            code: &'a str,
            remaining: u64,
        }
        let (item, delivered, what) = match &filled {
            Ok(SystemFilled::Login {
                item,
                username,
                password,
            }) => (
                *item,
                ticket.ok(&Login {
                    username,
                    password: password.as_str(),
                }),
                "The login",
            ),
            Ok(SystemFilled::Code {
                item,
                digits,
                remaining,
            }) => (
                *item,
                ticket.ok(&Code {
                    code: digits.as_str(),
                    remaining: *remaining,
                }),
                "The one-time code",
            ),
            Err(err) => {
                let code = match err.code {
                    "not_found" | "no_code" => "not_found",
                    _ => "refused",
                };
                ticket.fail(code, &err.message);
                return;
            }
        };
        drop(filled);
        if !delivered {
            self.set_err("macOS stopped waiting. Nothing was filled.");
            return;
        }
        match self.owner_ui.session.record_fill(item, SYSTEM_FILL_ORIGIN) {
            Ok(()) => self.set_ok(format!("{what} is filled with macOS AutoFill.")),
            Err(err) => self.set_err(format!(
                "{what} is filled with macOS AutoFill, but the history did not save it: {}",
                err.message
            )),
        }
    }
}

/// The page of a service identifier of macOS: a URL, or a bare domain (then `https`).
fn service_page(text: &str) -> Option<Page> {
    let text = text.trim();
    if text.contains("://") {
        Page::parse(text).ok()
    } else {
        Page::parse(&format!("https://{text}")).ok()
    }
}

/// The hosts of the websites of a login, once each, as `host` or `host:port`.
fn login_hosts(login: &SystemLogin) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for value in &login.websites {
        if Website::parse(value).is_none() {
            continue;
        }
        let rest = value
            .trim()
            .split_once("://")
            .map_or(value.trim(), |(_, rest)| rest);
        let Ok(page) = Page::parse(&format!("https://{rest}")) else {
            continue;
        };
        let origin = page.origin();
        let host = origin.trim_start_matches("https://").to_owned();
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}
