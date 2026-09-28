//! Tests for the native helper client (`apassy::native`).
//!
//! Most tests use a fake helper: a shell script that logs each request and
//! prints a response from a file. The last tests build the real Swift helper
//! without a signature and check the protocol. They never send a request
//! that can show a Touch ID prompt: an unsigned helper has no keychain access
//! group, so each keychain command stops with `keychain_unavailable` first,
//! and `authenticate` gets only an invalid reason. All data is synthetic.
//!
//! Caller check: the real helper answers only the signed Apassy app that
//! contains it. Here the parent is this test process, and the helper has no
//! signature. So the tests build the helper with `-D APASSY_HELPER_DEV` and set
//! `APASSY_HELPER_DEV_ANY_CALLER=1` for the protocol checks. Other tests show
//! that the helper refuses this parent without the override, and that a helper
//! built without the flag (as `scripts/build-app.sh` builds it) ignores the
//! override. `scripts/build-app.sh` checks the signed helpers with a signed
//! parent.
//!
//! The notifier (`native/ApassyNotify`, goal items N1 and N2) has the same
//! caller check. The tests build it the same way. An unbundled notifier
//! answers each notification command with `notifications_unavailable` before
//! it contacts macOS, so these tests never show a permission prompt and never
//! post a notification.

// The real helper and notifier are Swift programs for macOS. Off macOS only the
// tests with a fake helper run, so the parts for the real ones are unused.
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use apassy::native::{
    AlertStyle, Biometry, HelperErrorCode, KeychainSecret, NativeError, NativeHelper, Notification,
    NotificationAuthorization, NotificationEvent, NotificationSetting, Timeouts,
};
use serde_json::Value;

const FAKE_SCRIPT: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
IFS= read -r line
printf '%s\n' "$line" >> "$dir/requests.log"
echo $$ > "$dir/pid"
if [ -f "$dir/sleep" ]; then exec sleep "$(cat "$dir/sleep")"; fi
if [ -f "$dir/response" ]; then cat "$dir/response"; fi
"#;

const STATUS_FIELDS: &str = r#""authorization":"authorized","alert":"enabled","alert_style":"banner","notification_center":"enabled","lock_screen":"disabled","sound":"not_supported""#;

struct Fake {
    dir: PathBuf,
}

impl Fake {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "native-fake-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create fake dir");
        let script = dir.join("helper");
        fs::write(&script, FAKE_SCRIPT).expect("write fake helper");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    fn path(&self) -> PathBuf {
        self.dir.join("helper")
    }

    fn client(&self) -> NativeHelper {
        NativeHelper::with_paths(self.path(), self.path())
    }

    fn respond(&self, line: &str) {
        self.respond_raw(format!("{line}\n").as_bytes());
    }

    fn respond_raw(&self, bytes: &[u8]) {
        fs::write(self.dir.join("response"), bytes).expect("write response");
    }

    fn requests(&self) -> Vec<Value> {
        match fs::read_to_string(self.dir.join("requests.log")) {
            Ok(text) => text
                .lines()
                .map(|line| serde_json::from_str(line).expect("request is JSON"))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn last_request(&self) -> Value {
        self.requests().pop().expect("the helper got a request")
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn helper_error(code: HelperErrorCode) -> String {
    format!(
        r#"{{"ok":false,"error":"{}","message":"synthetic message"}}"#,
        code.as_str()
    )
}

#[test]
fn authenticate_sends_the_reason_and_accepts_ok() {
    let fake = Fake::new("auth");
    fake.respond(r#"{"ok":true}"#);
    fake.client()
        .authenticate("Approve the run of agent Alpha")
        .expect("ok");
    let request = fake.last_request();
    assert_eq!(request["cmd"], "authenticate");
    assert_eq!(request["reason"], "Approve the run of agent Alpha");
}

#[test]
fn every_helper_error_code_maps_to_a_typed_error() {
    let fake = Fake::new("codes");
    let client = fake.client();
    for code in HelperErrorCode::ALL {
        fake.respond(&helper_error(code));
        let err = client.authenticate("Synthetic reason").unwrap_err();
        assert_eq!(
            err,
            NativeError::Helper {
                code,
                message: "synthetic message".into()
            }
        );
        assert_eq!(err.code(), Some(code));
        assert_eq!(err.to_string(), format!("{code}: synthetic message"));
    }
}

#[test]
fn broken_responses_are_protocol_errors() {
    let fake = Fake::new("broken");
    let client = fake.client();
    let cases: [&[u8]; 9] = [
        b"{\"ok\":false,\"error\":\"surprise\",\"message\":\"x\"}\n",
        b"not json\n",
        b"[1,2,3]\n",
        b"{\"error\":\"cancelled\"}\n",
        b"{\"ok\":\"yes\"}\n",
        b"{\"ok\":false,\"message\":\"no code\"}\n",
        b"{\"ok\":true}",
        b"",
        b"{\"ok\":true,\"exists\":\"maybe\",\"biometry_changed\":false}\n",
    ];
    for response in cases {
        fake.respond_raw(response);
        let result = if response.starts_with(b"{\"ok\":true,\"exists\"") {
            client.keychain_exists("synthetic").map(drop)
        } else {
            client.authenticate("Synthetic reason")
        };
        assert!(
            matches!(result, Err(NativeError::Protocol(_))),
            "{:?} gave {result:?}",
            String::from_utf8_lossy(response)
        );
    }
}

#[test]
fn an_oversized_response_is_refused() {
    let fake = Fake::new("huge");
    let mut response = vec![b'a'; 70 * 1024];
    response.push(b'\n');
    fake.respond_raw(&response);
    let err = fake.client().authenticate("Synthetic reason").unwrap_err();
    assert_eq!(
        err,
        NativeError::Protocol("the response is too long".into())
    );
}

#[test]
fn a_silent_helper_times_out_and_is_stopped() {
    let fake = Fake::new("slow");
    fs::write(fake.dir.join("sleep"), "30").expect("write sleep");
    let limit = Duration::from_millis(500);
    let client = fake.client().with_timeouts(Timeouts {
        quick: limit,
        notify: limit,
        interactive: limit,
    });
    let start = Instant::now();
    let err = client.authenticate("Synthetic reason").unwrap_err();
    assert_eq!(err, NativeError::Timeout(limit));
    assert!(start.elapsed() < Duration::from_secs(10));

    let pid = fs::read_to_string(fake.dir.join("pid")).expect("pid");
    let alive = Command::new("kill")
        .args(["-0", pid.trim()])
        .stderr(Stdio::null())
        .status()
        .expect("kill -0");
    assert!(!alive.success(), "the helper process {pid} still runs");
}

#[test]
fn a_missing_helper_is_reported() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-such-helper");
    let client = NativeHelper::with_paths(&path, &path);
    assert_eq!(client.ping(), Err(NativeError::HelperMissing(path.clone())));
    assert_eq!(
        client.keychain_exists("synthetic").unwrap_err(),
        NativeError::HelperMissing(path)
    );
}

#[test]
fn keychain_commands_go_to_the_keychain_helper() {
    let main = Fake::new("main");
    let keychain = Fake::new("keychain");
    let client = NativeHelper::with_paths(main.path(), keychain.path());

    keychain.respond(r#"{"ok":true,"deleted":true}"#);
    assert!(client.keychain_delete("synthetic").expect("delete"));
    keychain.respond(r#"{"ok":true,"exists":true,"biometry_changed":true}"#);
    let state = client.keychain_exists("synthetic").expect("exists");
    assert!(state.exists && state.biometry_changed);
    keychain.respond(r#"{"ok":true}"#);
    let secret = KeychainSecret::new(vec![1, 2, 3]).expect("secret");
    client.keychain_store("synthetic", &secret).expect("store");
    keychain.respond(r#"{"ok":true,"secret_b64":"AQID"}"#);
    client
        .keychain_read("synthetic", "Unlock the Apassy vault")
        .expect("read");

    main.respond(r#"{"ok":true}"#);
    client.authenticate("Synthetic reason").expect("auth");
    main.respond(&format!("{{\"ok\":true,{STATUS_FIELDS}}}"));
    client.notify_status().expect("status");

    let keychain_cmds: Vec<Value> = keychain
        .requests()
        .iter()
        .map(|r| r["cmd"].clone())
        .collect();
    let main_cmds: Vec<Value> = main.requests().iter().map(|r| r["cmd"].clone()).collect();
    assert_eq!(
        keychain_cmds,
        [
            "keychain_delete",
            "keychain_exists",
            "keychain_store",
            "keychain_read"
        ]
    );
    // `with_paths` uses the main helper as the notifier too (one fake for tests).
    assert_eq!(main_cmds, ["authenticate", "notify_status"]);
}

#[test]
fn notification_commands_go_to_the_notifier() {
    let main = Fake::new("n-main");
    let keychain = Fake::new("n-keychain");
    let notifier = Fake::new("n-notifier");
    let client =
        NativeHelper::with_paths(main.path(), keychain.path()).with_notifier(notifier.path());
    assert_eq!(client.notifier_path(), notifier.path());

    notifier.respond(&format!(
        "{{\"ok\":true,\"delivered\":true,{STATUS_FIELDS}}}"
    ));
    let notification = Notification::new("run-7", "Codex", NotificationEvent::ApprovalWaiting)
        .expect("notification");
    assert!(client.notify(&notification).expect("notify").delivered);
    client.notify_status().expect("status");
    client.notify_authorize().expect("authorize");
    main.respond(r#"{"ok":true}"#);
    client.authenticate("Synthetic reason").expect("auth");

    let notifier_cmds: Vec<Value> = notifier
        .requests()
        .iter()
        .map(|r| r["cmd"].clone())
        .collect();
    assert_eq!(
        notifier_cmds,
        ["notify", "notify_status", "notify_authorize"]
    );
    let main_cmds: Vec<Value> = main.requests().iter().map(|r| r["cmd"].clone()).collect();
    assert_eq!(main_cmds, ["authenticate"]);
    assert!(keychain.requests().is_empty());

    // The bundle layout: the notifier is the main program of its own bundle.
    let bundled = NativeHelper::for_executable(Path::new("/A/Apassy.app/Contents/MacOS/apassy"));
    assert_eq!(
        bundled.notifier_path(),
        Path::new("/A/Apassy.app/Contents/Helpers/ApassyNotify.app/Contents/MacOS/ApassyNotify")
    );
}

#[test]
fn keychain_store_and_read_carry_base64_and_redact_debug() {
    let fake = Fake::new("secret");
    let client = fake.client();
    let secret_bytes = b"synthetic-unlock-key-0001".to_vec();
    let secret = KeychainSecret::new(secret_bytes.clone()).expect("secret");
    assert_eq!(format!("{secret:?}"), "KeychainSecret([redacted])");

    fake.respond(r#"{"ok":true,"access_group":"TEAMID1234.com.wydrox.apassy"}"#);
    client
        .keychain_store("vault-unlock", &secret)
        .expect("store");
    let request = fake.last_request();
    assert_eq!(request["cmd"], "keychain_store");
    assert_eq!(request["account"], "vault-unlock");
    assert_eq!(
        request["secret_b64"],
        "c3ludGhldGljLXVubG9jay1rZXktMDAwMQ=="
    );

    fake.respond(r#"{"ok":true,"secret_b64":"c3ludGhldGljLXVubG9jay1rZXktMDAwMQ=="}"#);
    let read = client
        .keychain_read("vault-unlock", "Unlock the Apassy vault")
        .expect("read");
    assert_eq!(read.expose(), secret_bytes.as_slice());
    assert!(!format!("{read:?}").contains("synthetic"));
    let request = fake.last_request();
    assert_eq!(request["reason"], "Unlock the Apassy vault");
    assert!(request.get("secret_b64").is_none());

    fake.respond(r#"{"ok":true,"secret_b64":"c3ludGhldGlj!!!"}"#);
    let err = client
        .keychain_read("vault-unlock", "Unlock the Apassy vault")
        .unwrap_err();
    assert!(matches!(err, NativeError::Protocol(_)));
    assert!(!format!("{err:?} {err}").contains("c3ludGhldGlj"));

    fake.respond(r#"{"ok":true}"#);
    assert!(matches!(
        client.keychain_read("vault-unlock", "Unlock the Apassy vault"),
        Err(NativeError::Protocol(_))
    ));
}

#[test]
fn client_checks_run_before_the_helper_starts() {
    let fake = Fake::new("checks");
    fake.respond(r#"{"ok":true}"#);
    let client = fake.client();
    let secret = KeychainSecret::new(vec![9; 16]).expect("secret");
    let long_reason = "r".repeat(201);
    let results = [
        client.authenticate(""),
        client.authenticate("two\nlines"),
        client.authenticate(&long_reason),
        client.keychain_store("bad account", &secret),
        client.keychain_store("", &secret),
        client.keychain_read("vault-unlock", "   ").map(drop),
        client.keychain_read("a/b", "Unlock").map(drop),
        client.keychain_delete(&"x".repeat(65)).map(drop),
        client.keychain_exists("ümlaut").map(drop),
    ];
    for result in results {
        assert!(
            matches!(result, Err(NativeError::InvalidArgument(_))),
            "{result:?}"
        );
    }
    assert!(fake.requests().is_empty(), "the helper was started");
}

#[test]
fn notification_preview_has_only_agent_name_and_event_type() {
    let fake = Fake::new("notify");
    fake.respond(&format!(
        "{{\"ok\":true,\"delivered\":true,{STATUS_FIELDS}}}"
    ));
    let notification = Notification::new(
        "event-17",
        "Claude Code",
        NotificationEvent::ApprovalWaiting,
    )
    .expect("notification");
    let outcome = fake.client().notify(&notification).expect("notify");
    assert!(outcome.delivered);
    assert!(outcome.status.can_deliver());

    // The request has no text field: the notifier builds the text itself.
    let request = fake.last_request();
    let fields: Vec<&String> = request.as_object().expect("object").keys().collect();
    assert_eq!(fields, ["agent", "cmd", "event", "id"]);
    assert_eq!(request["id"], "event-17");
    assert_eq!(request["event"], "approval_waiting");
    assert_eq!(request["agent"], "Claude Code");
    assert_eq!(notification.title(), "Approval waiting");
    assert_eq!(
        notification.body(),
        "Agent \"Claude Code\" waits for your decision. Open Apassy to review."
    );

    let blocked = Notification::new("event-18", "Codex", NotificationEvent::RequestBlocked)
        .expect("notification");
    assert_eq!(blocked.title(), "Request blocked");
    assert_eq!(
        blocked.body(),
        "Apassy blocked a request from agent \"Codex\"."
    );

    for (id, name) in [
        ("event-1", ""),
        ("event-1", "  "),
        ("event-1", "name\nwith a command"),
        ("event-1", &"n".repeat(41)),
        ("bad id", "Codex"),
    ] {
        assert!(
            matches!(
                Notification::new(id, name, NotificationEvent::RequestBlocked),
                Err(NativeError::InvalidArgument(_))
            ),
            "{id:?} {name:?}"
        );
    }
}

#[test]
fn notification_status_is_parsed() {
    let fake = Fake::new("status");
    let client = fake.client();
    fake.respond(&format!("{{\"ok\":true,{STATUS_FIELDS}}}"));
    let status = client.notify_status().expect("status");
    assert_eq!(status.authorization, NotificationAuthorization::Authorized);
    assert_eq!(status.alert, NotificationSetting::Enabled);
    assert_eq!(status.alert_style, AlertStyle::Banner);
    assert_eq!(status.lock_screen, NotificationSetting::Disabled);
    assert_eq!(status.sound, NotificationSetting::NotSupported);

    fake.respond(
        r#"{"ok":true,"granted":false,"authorization":"denied","alert":"disabled","alert_style":"none","notification_center":"disabled","lock_screen":"disabled","sound":"disabled"}"#,
    );
    let status = client.notify_authorize().expect("authorize");
    assert_eq!(status.authorization, NotificationAuthorization::Denied);
    assert!(!status.can_deliver());

    fake.respond(&helper_error(HelperErrorCode::NotificationsDenied));
    let notification = Notification::new("event-2", "Codex", NotificationEvent::RequestBlocked)
        .expect("notification");
    assert_eq!(
        client.notify(&notification).unwrap_err().code(),
        Some(HelperErrorCode::NotificationsDenied)
    );
}

#[test]
fn ping_parses_info_and_checks_the_protocol_version() {
    let fake = Fake::new("ping");
    let client = fake.client();
    fake.respond(
        r#"{"ok":true,"protocol":1,"helper_version":"0.1.0","bundle_id":"com.wydrox.apassy","keychain_access_group":null,"biometry":"not_enrolled"}"#,
    );
    let info = client.ping().expect("ping");
    assert_eq!(info.bundle_id.as_deref(), Some("com.wydrox.apassy"));
    assert_eq!(info.keychain_access_group, None);
    assert_eq!(
        info.biometry,
        Biometry::Unavailable(HelperErrorCode::NotEnrolled)
    );

    fake.respond(
        r#"{"ok":true,"protocol":1,"helper_version":"0.1.0","bundle_id":null,"keychain_access_group":"TEAMID1234.com.wydrox.apassy","biometry":"available"}"#,
    );
    let info = client.ping_keychain().expect("ping");
    assert_eq!(
        info.keychain_access_group.as_deref(),
        Some("TEAMID1234.com.wydrox.apassy")
    );
    assert_eq!(info.biometry, Biometry::Available);

    fake.respond(
        r#"{"ok":true,"protocol":2,"helper_version":"9.0.0","bundle_id":null,"keychain_access_group":null,"biometry":"available"}"#,
    );
    assert!(matches!(client.ping(), Err(NativeError::Protocol(_))));
}

#[test]
fn swift_and_rust_error_codes_match() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("native/ApassyHelper/Protocol.swift"),
    )
    .expect("read Protocol.swift");
    let start = source.find("enum ErrorCode").expect("enum ErrorCode");
    let end = start + source[start..].find("\n}").expect("end of enum");
    let mut swift: Vec<String> = source[start..end]
        .lines()
        .filter_map(|line| line.split_once("= \"").map(|(_, rest)| rest))
        .map(|rest| rest.trim_end_matches('"').to_owned())
        .collect();
    let mut rust: Vec<String> = HelperErrorCode::ALL
        .iter()
        .map(|code| code.as_str().to_owned())
        .collect();
    swift.sort();
    rust.sort();
    assert_eq!(swift, rust);
}

/// The environment variable of the development caller override.
const DEV_ANY_CALLER: &str = "APASSY_HELPER_DEV_ANY_CALLER";

/// The Swift files in `native/<dir>`, sorted.
fn swift_sources(dir: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("native")
        .join(dir);
    let mut sources: Vec<PathBuf> = fs::read_dir(root)
        .expect("read sources")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "swift"))
        .collect();
    sources.sort();
    sources
}

#[cfg(target_os = "macos")]
/// Build the real helper without a signature. `dev` adds `-D APASSY_HELPER_DEV`.
fn build_helper(name: &str, dev: bool) -> PathBuf {
    build_swift(name, "apassy-helper", dev, &swift_sources("ApassyHelper"))
}

#[cfg(target_os = "macos")]
/// Build the real notifier as `scripts/build-app.sh` does: its own files and the
/// protocol and caller check of the helper.
fn build_notifier(name: &str, dev: bool) -> PathBuf {
    let helper_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("native/ApassyHelper");
    let mut sources = swift_sources("ApassyNotify");
    sources.push(helper_dir.join("Protocol.swift"));
    sources.push(helper_dir.join("Caller.swift"));
    build_swift(name, "ApassyNotify", dev, &sources)
}

#[cfg(target_os = "macos")]
/// Compile `sources` into `<tmp>/<name>/<program>` without a signature.
fn build_swift(name: &str, program: &str, dev: bool, sources: &[PathBuf]) -> PathBuf {
    let out_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::create_dir_all(&out_dir).expect("create out dir");
    let out = out_dir.join(program);
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    };
    let mut command = Command::new("xcrun");
    command
        .args(["--sdk", "macosx", "swiftc", "-Onone", "-swift-version", "5"])
        .args(["-warnings-as-errors", "-target"])
        .arg(format!("{arch}-apple-macos15.0"));
    if dev {
        command.args(["-D", "APASSY_HELPER_DEV"]);
    }
    let status = command
        .arg("-o")
        .arg(&out)
        .args(sources)
        .status()
        .expect("run xcrun: this test needs Xcode and the Swift compiler");
    assert!(status.success(), "swiftc failed to build {program}");
    out
}

#[cfg(target_os = "macos")]
/// The real helper, built once with the development override.
fn real_helper() -> &'static Path {
    static HELPER: OnceLock<PathBuf> = OnceLock::new();
    HELPER.get_or_init(|| build_helper("native-real", true))
}

#[cfg(target_os = "macos")]
/// The real helper, built once without the development flag, as a release.
fn real_release_helper() -> &'static Path {
    static HELPER: OnceLock<PathBuf> = OnceLock::new();
    HELPER.get_or_init(|| build_helper("native-release", false))
}

#[cfg(target_os = "macos")]
/// The real notifier, built once with the development override.
fn real_notifier() -> &'static Path {
    static NOTIFIER: OnceLock<PathBuf> = OnceLock::new();
    NOTIFIER.get_or_init(|| build_notifier("notifier-real", true))
}

#[cfg(target_os = "macos")]
/// The real notifier, built once without the development flag, as a release.
fn real_release_notifier() -> &'static Path {
    static NOTIFIER: OnceLock<PathBuf> = OnceLock::new();
    NOTIFIER.get_or_init(|| build_notifier("notifier-release", false))
}

#[cfg(target_os = "macos")]
/// A client for the development helper with the caller override on. The
/// client starts the helper without extra environment, so a small script sets
/// the variable and then replaces itself with the helper. The parent of the
/// helper stays this test process. The notifier is the development notifier,
/// started the same way.
fn dev_client() -> NativeHelper {
    static WRAPPERS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    let (helper, notifier) = WRAPPERS.get_or_init(|| {
        (
            dev_wrapper("native-real-wrapper", real_helper()),
            dev_wrapper("notifier-real-wrapper", real_notifier()),
        )
    });
    NativeHelper::with_paths(helper, helper).with_notifier(notifier)
}

#[cfg(target_os = "macos")]
/// A script in `<tmp>/<name>` that sets the development override and then
/// replaces itself with `program`.
fn dev_wrapper(name: &str, program: &Path) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::create_dir_all(&dir).expect("create wrapper dir");
    let path = dir.join("program");
    let script = format!(
        "#!/bin/sh\n{DEV_ANY_CALLER}=1 exec '{}'\n",
        program.display()
    );
    fs::write(&path, script).expect("write wrapper");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

fn raw_exchange(helper: &Path, input: &str) -> Vec<Value> {
    raw_exchange_with(helper, input, Some("1"))
}

/// Run `helper` with `input`. `any_caller` is the value of the development
/// override, or `None` for no variable.
fn raw_exchange_with(helper: &Path, input: &str, any_caller: Option<&str>) -> Vec<Value> {
    use std::io::Write;
    let mut command = Command::new(helper);
    command.env_remove(DEV_ANY_CALLER);
    if let Some(value) = any_caller {
        command.env(DEV_ANY_CALLER, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start helper");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success(), "helper exit: {:?}", output.status);
    String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("response is JSON"))
        .collect()
}

#[cfg(target_os = "macos")]
#[test]
fn real_helper_answers_each_line_with_one_line() {
    let helper = real_helper();
    let input = [
        r#"{"cmd":"ping"}"#,
        "",
        "not json",
        r#"{"no_cmd":true}"#,
        r#"{"cmd":"format_disk"}"#,
        r#"{"cmd":"authenticate","reason":""}"#,
        r#"{"cmd":"authenticate","reason":"line\nbreak"}"#,
        r#"{"cmd":"keychain_store","account":"bad account","secret_b64":"AQID"}"#,
        r#"{"cmd":"keychain_store","account":"synthetic","secret_b64":"%%%"}"#,
    ]
    .join("\n")
        + "\n";
    let responses = raw_exchange(helper, &input);
    assert_eq!(responses.len(), 8, "{responses:?}");
    assert_eq!(responses[0]["ok"], true);
    assert_eq!(responses[0]["protocol"], 1);
    for response in &responses[1..] {
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(response["error"], "invalid_request", "{response}");
        assert!(response["message"].is_string());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn the_helper_sends_no_notifications() {
    // Notifications run only in the notifier. The helper answers each
    // notification command with `notifications_unavailable` and does not
    // contact macOS.
    let input = [
        r#"{"cmd":"notify","id":"event-1","event":"request_blocked","agent":"Codex"}"#,
        r#"{"cmd":"notify_status"}"#,
        r#"{"cmd":"notify_authorize"}"#,
    ]
    .join("\n")
        + "\n";
    let responses = raw_exchange(real_helper(), &input);
    assert_eq!(responses.len(), 3, "{responses:?}");
    for response in &responses {
        assert_eq!(response["error"], "notifications_unavailable", "{response}");
    }
    for source in swift_sources("ApassyHelper") {
        let text = fs::read_to_string(&source).expect("read helper source");
        assert!(
            !text.contains("import UserNotifications"),
            "{} imports UserNotifications",
            source.display()
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn real_unsigned_helper_reports_missing_keychain_and_bundle() {
    let client = dev_client();

    let info = client.ping().expect("ping");
    assert_eq!(info.protocol, 1);
    assert_eq!(info.bundle_id, None);
    assert_eq!(info.keychain_access_group, None);

    let secret = KeychainSecret::new(b"synthetic".to_vec()).expect("secret");
    let checks = [
        client.keychain_exists("synthetic").map(drop),
        client.keychain_delete("synthetic").map(drop),
        client.keychain_store("synthetic", &secret),
        client
            .keychain_read("synthetic", "Unlock the Apassy vault")
            .map(drop),
    ];
    for result in checks {
        assert_eq!(
            result.unwrap_err().code(),
            Some(HelperErrorCode::KeychainUnavailable)
        );
    }
    // The notifier outside `ApassyNotify.app` refuses each notification command
    // before it contacts macOS. So no prompt shows and nothing is posted.
    assert_eq!(
        client.notify_status().unwrap_err().code(),
        Some(HelperErrorCode::NotificationsUnavailable)
    );
    assert_eq!(
        client.notify_authorize().unwrap_err().code(),
        Some(HelperErrorCode::NotificationsUnavailable)
    );
    let notification = Notification::new("event-1", "Codex", NotificationEvent::RequestBlocked)
        .expect("notification");
    assert_eq!(
        client.notify(&notification).unwrap_err().code(),
        Some(HelperErrorCode::NotificationsUnavailable)
    );
}

/// Requests that cannot show a prompt or post a notification, also when the
/// caller check is broken: each one is invalid or has no visible effect.
const HARMLESS_REQUESTS: [&str; 8] = [
    r#"{"cmd":"ping"}"#,
    r#"{"cmd":"notify_status"}"#,
    r#"{"cmd":"keychain_exists","account":"synthetic"}"#,
    r#"{"cmd":"authenticate","reason":""}"#,
    r#"{"cmd":"keychain_read","account":"bad account","reason":"x"}"#,
    r#"{"cmd":"notify","id":"event-1","title":"","body":"x"}"#,
    "not json",
    r#"{"cmd":"format_disk"}"#,
];

fn harmless_input() -> String {
    HARMLESS_REQUESTS.join("\n") + "\n"
}

fn assert_all_refused(responses: &[Value]) {
    assert_eq!(responses.len(), HARMLESS_REQUESTS.len(), "{responses:?}");
    for response in responses {
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(response["error"], "caller_not_allowed", "{response}");
        assert!(response["message"].is_string(), "{response}");
        assert!(response.get("protocol").is_none(), "{response}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn real_helper_refuses_a_parent_that_is_not_apassy() {
    // The parent is this test process, not the signed Apassy app. The helper
    // answers each request with `caller_not_allowed` before it reads the
    // request. So an invalid request also gets `caller_not_allowed`, not
    // `invalid_request`.
    for any_caller in [None, Some("0"), Some("yes")] {
        let responses = raw_exchange_with(real_helper(), &harmless_input(), any_caller);
        assert_all_refused(&responses);
    }

    // The same through the Rust client: the code maps to a typed error.
    let helper = real_helper();
    let client = NativeHelper::with_paths(helper, helper);
    assert_eq!(
        client.ping().unwrap_err().code(),
        Some(HelperErrorCode::CallerNotAllowed)
    );
    assert_eq!(
        client.keychain_exists("synthetic").unwrap_err().code(),
        Some(HelperErrorCode::CallerNotAllowed)
    );
    assert_eq!(
        client.notify_status().unwrap_err().code(),
        Some(HelperErrorCode::CallerNotAllowed)
    );

    // Control: with the override, the same development helper answers.
    let responses = raw_exchange_with(real_helper(), "{\"cmd\":\"ping\"}\n", Some("1"));
    assert_eq!(responses[0]["ok"], true, "{responses:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn a_helper_built_without_the_dev_flag_ignores_the_override() {
    // `scripts/build-app.sh` builds the helper without `-D APASSY_HELPER_DEV`.
    // Such a helper does not contain the override, so the variable changes
    // nothing.
    for any_caller in [None, Some("1")] {
        let responses = raw_exchange_with(real_release_helper(), &harmless_input(), any_caller);
        assert_all_refused(&responses);
    }
    let release = fs::read(real_release_helper()).expect("read release helper");
    let dev = fs::read(real_helper()).expect("read development helper");
    let name = DEV_ANY_CALLER.as_bytes();
    assert!(
        !release.windows(name.len()).any(|window| window == name),
        "the release helper contains {DEV_ANY_CALLER}"
    );
    assert!(
        dev.windows(name.len()).any(|window| window == name),
        "control: the development helper contains {DEV_ANY_CALLER}"
    );
}

/// Notifier requests that cannot show a prompt or post a notification, also
/// when the caller check is broken: an unbundled notifier refuses each
/// notification command before it contacts macOS, and the others are invalid.
const HARMLESS_NOTIFIER_REQUESTS: [&str; 7] = [
    r#"{"cmd":"ping"}"#,
    r#"{"cmd":"notify_status"}"#,
    r#"{"cmd":"notify_authorize"}"#,
    r#"{"cmd":"preview","event":"approval_waiting","agent":"Codex"}"#,
    r#"{"cmd":"notify","id":"event-1","event":"request_blocked","agent":"Codex"}"#,
    r#"{"cmd":"notify","id":"event-1","title":"free text","body":"free text"}"#,
    "not json",
];

fn harmless_notifier_input() -> String {
    HARMLESS_NOTIFIER_REQUESTS.join("\n") + "\n"
}

fn assert_notifier_refused(responses: &[Value]) {
    assert_eq!(
        responses.len(),
        HARMLESS_NOTIFIER_REQUESTS.len(),
        "{responses:?}"
    );
    for response in responses {
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(response["error"], "caller_not_allowed", "{response}");
        assert!(response.get("title").is_none(), "{response}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn real_notifier_refuses_a_parent_that_is_not_apassy() {
    // The guard of the notifier: the parent is this test process, not the
    // signed Apassy app that contains the notifier. Each request, also `ping`,
    // `preview`, and a malformed request, gets `caller_not_allowed`.
    for any_caller in [None, Some("0"), Some("yes")] {
        let responses = raw_exchange_with(real_notifier(), &harmless_notifier_input(), any_caller);
        assert_notifier_refused(&responses);
    }
    // The same through the Rust client.
    let client =
        NativeHelper::with_paths(real_helper(), real_helper()).with_notifier(real_notifier());
    assert_eq!(
        client.notify_status().unwrap_err().code(),
        Some(HelperErrorCode::CallerNotAllowed)
    );
    assert_eq!(
        client.notify_authorize().unwrap_err().code(),
        Some(HelperErrorCode::CallerNotAllowed)
    );
    let notification = Notification::new("event-3", "Codex", NotificationEvent::ApprovalWaiting)
        .expect("notification");
    assert_eq!(
        client.notify(&notification).unwrap_err().code(),
        Some(HelperErrorCode::CallerNotAllowed)
    );
    // Control: with the override, the same development notifier answers.
    let responses = raw_exchange_with(real_notifier(), "{\"cmd\":\"ping\"}\n", Some("1"));
    assert_eq!(responses[0]["ok"], true, "{responses:?}");
    assert_eq!(responses[0]["bundle_id"], Value::Null, "{responses:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn a_notifier_built_without_the_dev_flag_ignores_the_override() {
    for any_caller in [None, Some("1")] {
        let responses = raw_exchange_with(
            real_release_notifier(),
            &harmless_notifier_input(),
            any_caller,
        );
        assert_notifier_refused(&responses);
    }
    let release = fs::read(real_release_notifier()).expect("read release notifier");
    let name = DEV_ANY_CALLER.as_bytes();
    assert!(
        !release.windows(name.len()).any(|window| window == name),
        "the release notifier contains {DEV_ANY_CALLER}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn swift_and_rust_previews_match() {
    // The notifier builds the text from its own templates (goal item N2). The
    // Rust `Notification` shows the same text in the app and in the tests.
    for event in [
        NotificationEvent::ApprovalWaiting,
        NotificationEvent::RequestBlocked,
    ] {
        for agent in ["Codex", "Claude Code", "n1-check", "a \"quoted\" name"] {
            let request = serde_json::json!({
                "cmd": "preview",
                "event": event.as_wire(),
                "agent": agent,
            });
            let responses = raw_exchange(real_notifier(), &format!("{request}\n"));
            let rust = Notification::new("event-4", agent, event).expect("notification");
            assert_eq!(responses[0]["ok"], true, "{responses:?}");
            assert_eq!(responses[0]["title"], rust.title(), "{event:?} {agent}");
            assert_eq!(responses[0]["body"], rust.body(), "{event:?} {agent}");
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn the_notifier_takes_no_free_text() {
    // Goal item N2: a request has the id, the event type, and the agent name
    // only. Any other field, an unknown event, and a bad agent name are refused
    // before the notifier contacts macOS.
    let long_name = "n".repeat(41);
    let bad = [
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": "Codex", "title": "free text"}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": "Codex", "body": "rm -rf canary"}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": "Codex", "command": "canary"}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "title": "Approval waiting", "body": "x"}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "custom", "agent": "Codex"}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": ""}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": "   "}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": "two\nlines"}),
        serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": long_name}),
        serde_json::json!({"cmd": "notify", "id": "bad id", "event": "request_blocked", "agent": "Codex"}),
        serde_json::json!({"cmd": "preview", "event": "approval_waiting", "agent": "Codex", "body": "x"}),
    ];
    let input: String = bad.iter().map(|request| format!("{request}\n")).collect();
    let responses = raw_exchange(real_notifier(), &input);
    assert_eq!(responses.len(), bad.len(), "{responses:?}");
    for (request, response) in bad.iter().zip(&responses) {
        assert_eq!(
            response["error"], "invalid_request",
            "{request} gave {response}"
        );
    }
    // A valid request passes the checks. Outside `ApassyNotify.app`, the
    // notifier then stops with `notifications_unavailable`, before macOS.
    let valid = serde_json::json!({"cmd": "notify", "id": "event-5", "event": "request_blocked", "agent": "Codex"});
    let responses = raw_exchange(real_notifier(), &format!("{valid}\n"));
    assert_eq!(
        responses[0]["error"], "notifications_unavailable",
        "{responses:?}"
    );
}
