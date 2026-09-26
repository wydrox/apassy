//! Tests for the native helper client (`apassy::native`).
//!
//! Most tests use a fake helper: a shell script that logs each request and
//! prints a response from a file. The last tests build the real Swift helper
//! without a signature and check the protocol. They never send a request
//! that can show a Touch ID prompt: an unsigned helper has no keychain access
//! group, so each keychain command stops with `keychain_unavailable` first,
//! and `authenticate` gets only an invalid reason. All data is synthetic.

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
    assert_eq!(main_cmds, ["authenticate", "notify_status"]);
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

    let request = fake.last_request();
    let fields: Vec<&String> = request.as_object().expect("object").keys().collect();
    assert_eq!(fields, ["body", "cmd", "id", "title"]);
    assert_eq!(request["id"], "event-17");
    assert_eq!(request["title"], "Approval waiting");
    assert_eq!(
        request["body"],
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

/// Build the real helper once, without a signature.
fn real_helper() -> &'static Path {
    static HELPER: OnceLock<PathBuf> = OnceLock::new();
    HELPER.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("native-real");
        fs::create_dir_all(&out_dir).expect("create out dir");
        let out = out_dir.join("apassy-helper");
        let mut sources: Vec<PathBuf> = fs::read_dir(root.join("native/ApassyHelper"))
            .expect("read sources")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "swift"))
            .collect();
        sources.sort();
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        };
        let status = Command::new("xcrun")
            .args(["--sdk", "macosx", "swiftc", "-Onone", "-swift-version", "5"])
            .args(["-warnings-as-errors", "-target"])
            .arg(format!("{arch}-apple-macos15.0"))
            .arg("-o")
            .arg(&out)
            .args(&sources)
            .status()
            .expect("run xcrun: this test needs Xcode and the Swift compiler");
        assert!(status.success(), "swiftc failed to build the helper");
        out
    })
}

fn raw_exchange(helper: &Path, input: &str) -> Vec<Value> {
    use std::io::Write;
    let mut child = Command::new(helper)
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
        r#"{"cmd":"notify","id":"event-1","title":"","body":"x"}"#,
    ]
    .join("\n")
        + "\n";
    let responses = raw_exchange(helper, &input);
    assert_eq!(responses.len(), 9, "{responses:?}");
    assert_eq!(responses[0]["ok"], true);
    assert_eq!(responses[0]["protocol"], 1);
    for response in &responses[1..] {
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(response["error"], "invalid_request", "{response}");
        assert!(response["message"].is_string());
    }
}

#[test]
fn real_unsigned_helper_reports_missing_keychain_and_bundle() {
    let helper = real_helper();
    let client = NativeHelper::with_paths(helper, helper);

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
    assert_eq!(
        client.notify_status().unwrap_err().code(),
        Some(HelperErrorCode::NotificationsUnavailable)
    );
    let notification = Notification::new("event-1", "Codex", NotificationEvent::RequestBlocked)
        .expect("notification");
    assert_eq!(
        client.notify(&notification).unwrap_err().code(),
        Some(HelperErrorCode::NotificationsUnavailable)
    );
}
