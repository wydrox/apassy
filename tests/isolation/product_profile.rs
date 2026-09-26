#![cfg(feature = "vault")]

//! Product isolation profile test (goal items I1, I2, I4).
//!
//! It starts a real broker on a synthetic temporary vault, like
//! `tests/agent_path.rs`. Then it runs processes inside the product Seatbelt
//! profile through the `apassy-sandbox` launcher and checks the boundary:
//!
//!   - `apassy-mcp` inside the profile calls the broker and gets a permitted
//!     credential result. No secret value leaks.
//!   - A process inside the profile cannot read, copy, overwrite, or replace
//!     the vault file, a backup file, or a file under a fake Laya directory.
//!   - Ordinary work still runs: it reads the project directory and writes a
//!     temporary file.
//!
//! All values are synthetic. No real secret is used.
//!
//! I4: if the sandbox cannot start, the test fails. There is no skip. On a
//! host that is not macOS, or that has no `sandbox-exec`, the test fails,
//! because Apassy is a macOS product and isolation is a release gate.
//!
//! Apassy app bundle: the profile denies the start, the read, and a change of
//! the programs in `Apassy.app`, except `apassy-mcp` and `apassy-hook`. The
//! tests use a synthetic bundle with the layout of `scripts/build-app.sh`. Its
//! helpers are the real Swift helper, built without a signature. The notifier
//! bundle `Contents/Helpers/ApassyNotify.app` (goal item N1) has the real Swift
//! notifier. The profile denies its start, and its start through LaunchServices
//! (`notifier_bundle_cannot_be_opened_in_profile`).
//!
//! Keychain: goal item I2 also needs proof that the process cannot read the
//! Touch ID Keychain item. `keychain_item_is_not_readable_in_profile` checks it
//! with `/usr/bin/security` and shows that the Apassy keychain helper cannot
//! start in the profile.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use apassy::agent::client;
use apassy::agent::wire::Action;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use serde_json::{Value, json};
use tempfile::TempDir;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const PASS: &str = "isolation-pass-ok";
const SERVICE_TOKEN: &str = "FAKE-SERVICE-TOKEN-9911-canary";
const OP_SUMMARY: &str = "get_sales_summary";
const VAULT_TEXT: &str = "SYNTHETIC-VAULT-CANARY-NOT-A-SECRET\n";
const BACKUP_TEXT: &str = "SYNTHETIC-BACKUP-CANARY-NOT-A-SECRET\n";
const LAYA_TEXT: &str = "SYNTHETIC-LAYA-WEIGHTS-NOT-A-SECRET\n";
/// The development override of the helper caller check. No test sets it for a
/// process in the profile.
const DEV_ANY_CALLER: &str = "APASSY_HELPER_DEV_ANY_CALLER";

/// The synthetic reporting service. It answers only for the synthetic token.
struct DevService {
    child: Child,
    base_url: String,
}

impl Drop for DevService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_dev_service() -> DevService {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-dev-reporting"))
        .env("APASSY_DEV_REPORTING_TOKEN", SERVICE_TOKEN)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start synthetic service");
    let stdout = child.stdout.take().expect("service stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read listen line");
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .expect("listen line")
        .to_owned();
    DevService {
        child,
        base_url: format!("http://{addr}"),
    }
}

/// The synthetic layout: a data directory with a vault, a fake Laya model, and
/// a broker socket, plus a backup file in a sibling directory.
struct Layout {
    _dir: TempDir,
    data_dir: PathBuf,
    vault_file: PathBuf,
    backup_file: PathBuf,
    laya_file: PathBuf,
    socket: PathBuf,
    scratch: PathBuf,
    /// A synthetic owner home directory. The profile denies a write to the
    /// autostart locations under it. A test never touches the real `$HOME`.
    home: PathBuf,
}

fn make_layout() -> Layout {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().expect("temp dir");
    // The data directory holds the vault, the Laya model, and the socket. A
    // short name keeps the socket path under the AF_UNIX length limit.
    let data_dir = dir.path().join("d");
    std::fs::create_dir_all(data_dir.join("laya")).expect("data dir");
    // The broker needs the socket directory at mode 0700, like the real data
    // directory.
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).expect("data mode");
    let vault_file = data_dir.join("vault.db");
    let laya_file = data_dir.join("laya").join("model.bin");
    let socket = data_dir.join("broker.sock");
    // The backup lives outside the data directory, so the test also covers the
    // owner-chosen backup path and its parent directory.
    let backup_dir = dir.path().join("backups");
    std::fs::create_dir_all(&backup_dir).expect("backup dir");
    let backup_file = backup_dir.join("apassy.backup");
    std::fs::write(&laya_file, LAYA_TEXT).expect("laya");
    std::fs::write(&backup_file, BACKUP_TEXT).expect("backup");
    // A synthetic owner home directory with the autostart locations. The
    // profile denies a write under each of them. The test writes a control
    // file with the same layout under a temporary "outside" home, so the deny
    // is the only difference.
    let home = dir.path().join("home");
    for sub in [
        "Library/LaunchAgents",
        "Library/LaunchDaemons",
        "Library/Application Scripts",
        "Library/Preferences",
    ] {
        std::fs::create_dir_all(home.join(sub)).expect("home subdir");
    }
    // An existing shell startup file, to show that a read (a source) still
    // works while a write is denied.
    std::fs::write(home.join(".zshrc"), "# synthetic startup file\n").expect("zshrc");
    Layout {
        data_dir,
        vault_file,
        backup_file,
        laya_file,
        socket,
        scratch: dir.path().join("scratch.txt"),
        home,
        _dir: dir,
    }
}

fn api_item() -> ItemDraft {
    ItemDraft {
        title: "Reporting staging key".to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(SERVICE_TOKEN.to_owned()),
            secret: true,
        }],
    }
}

/// The started broker, the agent token, and the synthetic layout.
struct Fixture {
    layout: Layout,
    /// A synthetic `Apassy.app`, when the test needs one. The launcher gets it
    /// with `--app`.
    app: Option<PathBuf>,
    token: String,
    item_id: u64,
    _service: DevService,
    _broker: broker::BrokerHandle,
}

/// A fixture with a synthetic `Apassy.app` in its temporary directory.
fn fixture_with_app() -> Fixture {
    let mut fx = fixture();
    let dir = fx.layout.data_dir.parent().expect("temp dir").to_owned();
    fx.app = Some(make_app(&dir));
    fx
}

fn fixture() -> Fixture {
    let service = start_dev_service();
    let layout = make_layout();

    // The vault file is a readable plaintext canary, so a deny-read check looks
    // for a known marker. The live broker vault is a separate database in the
    // same (denied) data directory. The broker runs in this unsandboxed test
    // process, so it opens the live database without a problem.
    std::fs::write(&layout.vault_file, VAULT_TEXT).expect("vault canary");
    let live_path = layout.data_dir.join("live.db");
    let mut live = Vault::create(&live_path, PASS).expect("create live vault");
    live.unlock(PASS).expect("unlock live");
    let item = live.add(api_item()).expect("add item");
    live.set_destination(item.id, "reporting-api-v0", &service.base_url)
        .expect("destination");
    let (agent, token) = live.register_agent("Isolation agent").expect("register");
    live.set_grant(agent.id, item.id, OP_SUMMARY, true)
        .expect("grant");
    let shared: SharedVault = Arc::new(Mutex::new(Some(live)));
    let tls = TlsClient::platform().expect("platform TLS");
    let handle =
        broker::start_with_tls(shared, &layout.socket, tls).expect("start broker on socket");
    Fixture {
        token: token.expose().to_owned(),
        item_id: item.id,
        layout,
        app: None,
        _service: service,
        _broker: handle,
    }
}

/// The real Swift helper, built once without a signature and with
/// `-D APASSY_HELPER_DEV`. No test sets the override for it, so it runs its
/// caller check. It has no team signature, so it refuses every caller.
fn dev_helper() -> &'static Path {
    static HELPER: OnceLock<PathBuf> = OnceLock::new();
    HELPER.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("isolation-helper");
        std::fs::create_dir_all(&out_dir).expect("helper dir");
        let out = out_dir.join("apassy-helper");
        let mut sources: Vec<PathBuf> = std::fs::read_dir(root.join("native/ApassyHelper"))
            .expect("helper sources")
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
            .args(["-D", "APASSY_HELPER_DEV"])
            .args(["-target", &format!("{arch}-apple-macos15.0"), "-o"])
            .arg(&out)
            .args(&sources)
            .status()
            .expect("run xcrun: the helper checks need Xcode. This is a failure, not a skip.");
        assert!(status.success(), "swiftc failed to build the helper");
        out
    })
}

/// The real Swift notifier (`native/ApassyNotify`), built once without a
/// signature and with `-D APASSY_HELPER_DEV`, as `dev_helper`. It refuses every
/// caller.
fn dev_notifier() -> &'static Path {
    static NOTIFIER: OnceLock<PathBuf> = OnceLock::new();
    NOTIFIER.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("isolation-notifier");
        std::fs::create_dir_all(&out_dir).expect("notifier dir");
        let out = out_dir.join("ApassyNotify");
        let mut sources: Vec<PathBuf> = std::fs::read_dir(root.join("native/ApassyNotify"))
            .expect("notifier sources")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "swift"))
            .collect();
        sources.sort();
        sources.push(root.join("native/ApassyHelper/Protocol.swift"));
        sources.push(root.join("native/ApassyHelper/Caller.swift"));
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        };
        let status = Command::new("xcrun")
            .args(["--sdk", "macosx", "swiftc", "-Onone", "-swift-version", "5"])
            .args(["-D", "APASSY_HELPER_DEV"])
            .args(["-target", &format!("{arch}-apple-macos15.0"), "-o"])
            .arg(&out)
            .args(&sources)
            .status()
            .expect("run xcrun: the notifier checks need Xcode. This is a failure, not a skip.");
        assert!(status.success(), "swiftc failed to build the notifier");
        out
    })
}

/// The programs of the app bundle, relative to `Apassy.app`.
const APP_MAIN: &str = "Contents/MacOS/apassy";
const APP_HELPER: &str = "Contents/MacOS/apassy-helper";
const APP_KEYCHAIN_BUNDLE: &str = "Contents/Helpers/ApassyKeychain.app";
const APP_NOTIFIER_BUNDLE: &str = "Contents/Helpers/ApassyNotify.app";
const APP_MCP: &str = "Contents/MacOS/apassy-mcp";
const APP_HOOK: &str = "Contents/MacOS/apassy-hook";

/// A synthetic `Apassy.app` in `dir` with the layout of `scripts/build-app.sh`.
/// The helpers are copies of the real Swift helper, and the notifier is the
/// real Swift notifier. The main program is also a copy of the helper: it only
/// stands for a program in the bundle. `apassy-mcp` and `apassy-hook` are the
/// programs of this build.
fn make_app(dir: &Path) -> PathBuf {
    let app = dir.join("Apassy.app");
    let keychain = app
        .join("Contents")
        .join(apassy::native::KEYCHAIN_HELPER_FROM_CONTENTS);
    let notifier = notifier_program(&app);
    std::fs::create_dir_all(app.join("Contents/MacOS")).expect("MacOS dir");
    std::fs::create_dir_all(keychain.parent().expect("keychain dir")).expect("keychain dir");
    std::fs::create_dir_all(notifier.parent().expect("notifier dir")).expect("notifier dir");
    for (from, to) in [
        (dev_helper(), app.join(APP_MAIN)),
        (dev_helper(), app.join(APP_HELPER)),
        (dev_helper(), keychain),
        (dev_notifier(), notifier),
        (
            Path::new(env!("CARGO_BIN_EXE_apassy-mcp")),
            app.join(APP_MCP),
        ),
        (
            Path::new(env!("CARGO_BIN_EXE_apassy-hook")),
            app.join(APP_HOOK),
        ),
    ] {
        std::fs::copy(from, &to).expect("copy a program into the app");
    }
    std::fs::write(
        app.join("Contents/Info.plist"),
        "<plist version=\"1.0\"><dict/></plist>\n",
    )
    .expect("Info.plist");
    app
}

/// The keychain helper program in `app`.
fn keychain_program(app: &Path) -> PathBuf {
    app.join("Contents")
        .join(apassy::native::KEYCHAIN_HELPER_FROM_CONTENTS)
}

/// The notifier program in `app` (goal item N1).
fn notifier_program(app: &Path) -> PathBuf {
    app.join("Contents")
        .join(apassy::native::NOTIFIER_FROM_CONTENTS)
}

/// The path of the SBPL profile in the repository.
fn profile_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("sandbox")
        .join("apassy-agent-host.sb")
}

/// Build the shared `apassy-sandbox` arguments for this fixture.
fn sandbox_args(fx: &Fixture) -> Vec<String> {
    let l = &fx.layout;
    vec![
        "--profile".to_owned(),
        profile_path().display().to_string(),
        "--data-dir".to_owned(),
        l.data_dir.display().to_string(),
        "--vault-file".to_owned(),
        l.vault_file.display().to_string(),
        "--backup-file".to_owned(),
        l.backup_file.display().to_string(),
        "--socket".to_owned(),
        l.socket.display().to_string(),
        "--home".to_owned(),
        l.home.display().to_string(),
    ]
    .into_iter()
    .chain(
        fx.app
            .iter()
            .flat_map(|app| ["--app".to_owned(), app.display().to_string()]),
    )
    .chain(["--".to_owned()])
    .collect()
}

/// Run a command inside the profile. Return (exit ok, stdout, stderr).
fn in_sandbox(fx: &Fixture, host: &[&str]) -> (bool, String, String) {
    let mut args = sandbox_args(fx);
    args.extend(host.iter().map(|part| (*part).to_owned()));
    let output = Command::new(env!("CARGO_BIN_EXE_apassy-sandbox"))
        .args(&args)
        .env_remove(DEV_ANY_CALLER)
        .output()
        .expect("run apassy-sandbox");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The MCP adapter running inside the profile. It speaks JSON-RPC over stdio.
struct McpProcess {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl McpProcess {
    fn start_in_sandbox(fx: &Fixture) -> Self {
        Self::start_program_in_sandbox(fx, Path::new(env!("CARGO_BIN_EXE_apassy-mcp")))
    }

    /// Start the adapter at `program` inside the profile.
    fn start_program_in_sandbox(fx: &Fixture, program: &Path) -> Self {
        let mut args = sandbox_args(fx);
        args.push(program.display().to_string());
        let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-sandbox"))
            .args(&args)
            .env("APASSY_AGENT_TOKEN", &fx.token)
            .env("APASSY_BROKER_SOCKET", &fx.layout.socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start sandboxed adapter");
        let stdout = BufReader::new(child.stdout.take().expect("adapter stdout"));
        Self { child, stdout }
    }

    fn request(&mut self, message: &Value) -> Value {
        let stdin = self.child.stdin.as_mut().expect("adapter stdin");
        writeln!(stdin, "{message}").expect("write request");
        stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read reply");
        serde_json::from_str(&line).expect("reply JSON")
    }
}

impl Drop for McpProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// I4: the sandbox must be available. A skip is not a pass.
fn require_sandbox() {
    assert_eq!(
        std::env::consts::OS,
        "macos",
        "isolation needs macOS. This is a failure, not a skip. Apassy is macOS only."
    );
    assert!(
        Path::new(SANDBOX_EXEC).exists(),
        "{SANDBOX_EXEC} is absent. This is a failure, not a skip."
    );
}

#[test]
fn control_process_can_read_the_canaries() {
    // The baseline: a same-user process without the profile reads the files.
    // Without this control, a deny-all setup could look like isolation.
    let fx = fixture();
    assert_eq!(
        std::fs::read_to_string(&fx.layout.vault_file).unwrap(),
        VAULT_TEXT
    );
    assert_eq!(
        std::fs::read_to_string(&fx.layout.backup_file).unwrap(),
        BACKUP_TEXT
    );
    assert_eq!(
        std::fs::read_to_string(&fx.layout.laya_file).unwrap(),
        LAYA_TEXT
    );
}

#[test]
fn adapter_in_profile_reaches_broker_without_secret() {
    require_sandbox();
    let fx = fixture();
    let mut mcp = McpProcess::start_in_sandbox(&fx);
    assert_adapter_works(&fx, &mut mcp);
}

/// The adapter answers `initialize`, lists the grant, and makes a permitted,
/// mediated credential call. No secret value leaks.
fn assert_adapter_works(fx: &Fixture, mcp: &mut McpProcess) {
    let init = mcp.request(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "iso", "version": "0"}}
    }));
    assert_eq!(init["result"]["serverInfo"]["name"], "apassy", "{init}");

    // The adapter reaches the broker through the socket in the denied data
    // directory. The grant is visible.
    let list = mcp.request(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "apassy_list_access", "arguments": {}}
    }));
    assert_eq!(list["result"]["isError"], false, "{list}");
    let list_text = list.to_string();
    assert!(list_text.contains(OP_SUMMARY), "{list}");
    assert!(!list_text.contains(SERVICE_TOKEN), "secret leaked in list");

    // A permitted, mediated credential call returns only the allowed fields.
    let reply = mcp.request(&json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "apassy_use_credential", "arguments": {
            "item_id": fx.item_id,
            "operation": OP_SUMMARY,
            "params": {"project_id": "project-a-synthetic", "period_start": "2026-09-01", "period_end": "2026-09-30"}
        }}
    }));
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["result"]["order_count"], 318,
        "{reply}"
    );
    assert!(
        !reply.to_string().contains(SERVICE_TOKEN),
        "secret leaked in credential result"
    );
}

#[test]
fn direct_broker_call_from_socket_in_denied_dir() {
    // A second proof that the socket stays reachable although it lives inside
    // the denied data directory: the in-process client also connects.
    require_sandbox();
    let fx = fixture();
    let list = client::send(&fx.layout.socket, &fx.token, Action::ListAccess).expect("list");
    assert!(list.ok, "{list:?}");
}

#[test]
fn profile_denies_reading_protected_files() {
    require_sandbox();
    let fx = fixture();
    for (label, path) in [
        ("vault", &fx.layout.vault_file),
        ("backup", &fx.layout.backup_file),
        ("laya", &fx.layout.laya_file),
    ] {
        let (ok, out, err) = in_sandbox(&fx, &["/bin/cat", &path.display().to_string()]);
        assert!(
            !ok,
            "the profile must deny a read of the {label} file: {out}"
        );
        assert!(
            err.contains("Operation not permitted"),
            "the {label} denial must be a sandbox denial: {err}"
        );
        assert!(!out.contains("CANARY"), "the {label} bytes leaked: {out}");
    }
}

#[test]
fn profile_denies_listing_the_data_directory() {
    require_sandbox();
    let fx = fixture();
    let (ok, _out, err) = in_sandbox(&fx, &["/bin/ls", &fx.layout.data_dir.display().to_string()]);
    assert!(!ok, "the profile must deny a list of the data directory");
    assert!(err.contains("Operation not permitted"), "{err}");
}

#[test]
fn profile_denies_overwrite_replace_and_rename() {
    require_sandbox();
    let fx = fixture();
    let vault = fx.layout.vault_file.display().to_string();

    // Overwrite the vault bytes.
    let (ok, _o, _e) = in_sandbox(&fx, &["/bin/sh", "-c", &format!("echo x > '{vault}'")]);
    assert!(!ok, "the profile must deny an overwrite of the vault");

    // Delete the vault.
    let (ok, _o, _e) = in_sandbox(&fx, &["/bin/rm", "-f", &vault]);
    assert!(!ok, "the profile must deny a delete of the vault");

    // Replace the vault by a rename over it.
    let payload = fx.layout.data_dir.with_file_name("payload.db");
    std::fs::write(&payload, "SYNTHETIC-REPLACE-SHOULD-FAIL\n").expect("payload");
    let (ok, _o, _e) = in_sandbox(&fx, &["/bin/mv", &payload.display().to_string(), &vault]);
    assert!(!ok, "the profile must deny a replace of the vault");

    // Escape by a rename of the parent directory, then read at the new path.
    let renamed = fx.layout.data_dir.with_file_name("escaped");
    let (ok, out, _e) = in_sandbox(
        &fx,
        &[
            "/bin/sh",
            "-c",
            &format!(
                "mv '{}' '{}' && cat '{}/vault.db'",
                fx.layout.data_dir.display(),
                renamed.display(),
                renamed.display()
            ),
        ],
    );
    assert!(!ok, "the profile must deny a rename of the data directory");
    assert!(
        !out.contains("CANARY"),
        "the vault leaked after a rename: {out}"
    );

    // The vault bytes never changed.
    assert_eq!(
        std::fs::read_to_string(&fx.layout.vault_file).unwrap(),
        VAULT_TEXT,
        "the vault content changed"
    );
}

#[test]
fn ordinary_work_still_runs_in_profile() {
    require_sandbox();
    let fx = fixture();

    // Read a project file. The project directory is not protected.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let (ok, out, err) = in_sandbox(&fx, &["/bin/cat", &manifest.display().to_string()]);
    assert!(ok, "reading the project must work in the profile: {err}");
    assert!(out.contains("name = \"apassy\""), "{out}");

    // Write a temporary file next to the data directory.
    let scratch = fx.layout.scratch.display().to_string();
    let (ok, _o, err) = in_sandbox(
        &fx,
        &["/bin/sh", "-c", &format!("echo work-ok > '{scratch}'")],
    );
    assert!(
        ok,
        "writing a temporary file must work in the profile: {err}"
    );
    assert_eq!(
        std::fs::read_to_string(&fx.layout.scratch).unwrap(),
        "work-ok\n"
    );
}

// --- Launching outside the sandbox ---------------------------------------
//
// A process in the profile must not start a program that runs OUTSIDE the
// sandbox as the same user. Such a program is not confined, so it can read the
// vault. The tests below prove that the measured escape routes fail in the
// profile. The routes and the manual measurements (Apple Events, Shortcuts,
// and the LaunchServices control) are in
// `docs/operations/isolation.md`, section "Launching outside the sandbox".

/// Try a write to `path` from inside the profile. Return true when the profile
/// denies it. The command runs through `/bin/sh`, so a shell redirection
/// failure gives a non-zero exit with the sandbox message. The caller checks,
/// after the loop, that no file was planted and that an existing file did not
/// change.
fn write_is_denied(fx: &Fixture, path: &Path) -> bool {
    let target = path.display().to_string();
    let (ok, _out, err) = in_sandbox(
        fx,
        &["/bin/sh", "-c", &format!("echo planted > '{target}'")],
    );
    !ok && err.contains("Operation not permitted")
}

#[test]
fn profile_denies_writes_to_autostart_locations() {
    // launchd starts a LaunchAgent or a LaunchDaemon outside the sandbox at the
    // next load or login. A shell startup file runs outside the sandbox the next
    // time the owner opens a terminal. A login item and an application script
    // start outside the sandbox too. The profile denies a write to each of
    // these, so a process in the profile cannot plant one.
    require_sandbox();
    let fx = fixture();
    let home = &fx.layout.home;

    // Control: a write to an ordinary file in the same home directory works in
    // the profile. So the deny is on the specific autostart paths, not on the
    // home directory as a whole.
    let ordinary = home.join("notes.txt");
    let (ok, _o, err) = in_sandbox(
        &fx,
        &[
            "/bin/sh",
            "-c",
            &format!("echo hello > '{}'", ordinary.display()),
        ],
    );
    assert!(ok, "an ordinary home write must work in the profile: {err}");
    assert_eq!(std::fs::read_to_string(&ordinary).unwrap(), "hello\n");

    // Each autostart location: the profile denies a write.
    let denied = [
        home.join("Library/LaunchAgents/com.example.iso.plist"),
        home.join("Library/LaunchDaemons/com.example.iso.plist"),
        home.join("Library/Application Scripts/com.example.iso"),
        home.join("Library/Preferences/com.apple.loginitems.plist"),
        home.join(".zshenv"),
        home.join(".zprofile"),
        home.join(".zshrc"),
        home.join(".zlogin"),
        home.join(".zlogout"),
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".bash_login"),
        home.join(".profile"),
    ];
    for path in &denied {
        assert!(
            write_is_denied(&fx, path),
            "the profile must deny a write to {}",
            path.display()
        );
        // No file holds the planted content. A path that did not exist stays
        // absent; an existing file keeps its bytes.
        if let Ok(content) = std::fs::read_to_string(path) {
            assert!(
                !content.contains("planted"),
                "a write landed at {}",
                path.display()
            );
        }
    }

    // The existing startup file did not change: the deny does not corrupt it.
    assert_eq!(
        std::fs::read_to_string(home.join(".zshrc")).unwrap(),
        "# synthetic startup file\n",
        "the startup file changed"
    );

    // A read (a source) of a startup file still works in the profile, because
    // the deny is on writes only.
    let (ok, out, err) = in_sandbox(
        &fx,
        &["/bin/cat", &home.join(".zshrc").display().to_string()],
    );
    assert!(
        ok,
        "a startup file must stay readable in the profile: {err}"
    );
    assert!(out.contains("synthetic startup file"), "{out}");
}

/// A minimal headless application bundle in `dir`. Its executable reads the
/// vault canary and appends the result to `marker`. `LSBackgroundOnly` means it
/// shows no window. It exits at once, so it leaves no process. A build of this
/// bundle, started with `open`, runs OUTSIDE the sandbox.
fn make_canary_app(dir: &Path, vault_file: &Path, marker: &Path) -> PathBuf {
    let app = dir.join("IsoCanary.app");
    let macos = app.join("Contents/MacOS");
    std::fs::create_dir_all(&macos).expect("app MacOS dir");
    std::fs::write(
        app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\
         <key>CFBundleName</key><string>IsoCanary</string>\
         <key>CFBundleIdentifier</key><string>com.apassy.iso-canary</string>\
         <key>CFBundleExecutable</key><string>iso-canary</string>\
         <key>CFBundlePackageType</key><string>APPL</string>\
         <key>LSBackgroundOnly</key><true/></dict></plist>\n",
    )
    .expect("Info.plist");
    let exe = macos.join("iso-canary");
    std::fs::write(
        &exe,
        format!(
            "#!/bin/sh\n\
             if /bin/cat '{vault}' > '{marker}' 2>/dev/null; then\n\
             \techo ESCAPED-READ >> '{marker}'\n\
             else\n\
             \techo READ-DENIED >> '{marker}'\n\
             fi\n",
            vault = vault_file.display(),
            marker = marker.display(),
        ),
    )
    .expect("app executable");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("exe mode");
    app
}

/// Wait up to about `secs` seconds for `path` to appear.
fn wait_for(path: &Path, secs: u64) -> bool {
    for _ in 0..(secs * 10) {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    path.exists()
}

#[test]
fn profile_denies_lsopen_of_an_application() {
    // `open` and the `lsopen` operation start an application through
    // LaunchServices. The started application runs outside the sandbox. The
    // profile denies the operation. So a process in the profile cannot use
    // `open` to escape.
    require_sandbox();
    let fx = fixture();
    let app_dir = fx.layout.data_dir.with_file_name("lsopen");
    std::fs::create_dir_all(&app_dir).expect("app dir");
    let marker = app_dir.join("marker.txt");
    let app = make_canary_app(&app_dir, &fx.layout.vault_file, &marker);

    // In the profile: `open` is denied. The application does not start, so it
    // does not read the vault canary.
    let _ = std::fs::remove_file(&marker);
    let (ok, _out, err) = in_sandbox(&fx, &["/usr/bin/open", &app.display().to_string()]);
    assert!(!ok, "the profile must deny `open` of an application");
    assert!(
        err.contains("-54") || err.contains("failed"),
        "the `open` denial must be a LaunchServices failure: {err}"
    );
    assert!(
        !wait_for(&marker, 3),
        "the application started and read the canary in the profile"
    );

    // Control: outside the profile, the same `open` starts the application and
    // it reads the canary. This shows the route is a real escape and the test
    // host supports LaunchServices, so the deny above is meaningful.
    let _ = std::fs::remove_file(&marker);
    let control = Command::new("/usr/bin/open")
        .arg(&app)
        .output()
        .expect("control open");
    assert!(
        control.status.success(),
        "control: `open` outside the profile must start the application: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        wait_for(&marker, 20),
        "control: the application did not run outside the profile"
    );
    let escaped = std::fs::read_to_string(&marker).expect("marker");
    assert!(
        escaped.contains("SYNTHETIC-VAULT-CANARY") && escaped.contains("ESCAPED-READ"),
        "control: the application outside the profile must read the canary: {escaped}"
    );
}

/// A synthetic environment canary, like a secret that the broker puts in the
/// environment of an agent command.
const ENV_CANARY_NAME: &str = "APASSY_ISO_ENV_CANARY";
const ENV_CANARY_VALUE: &str = "FAKE-ENV-CANARY-4471-not-a-secret";

#[test]
fn ps_in_profile_cannot_show_environment_of_outside_process() {
    // F11: `ps eww` and `ps -E` show the environment of another process of the
    // same user. A broker child runs outside the profile with a secret in its
    // environment. The synthetic service stands in for that child. It is a
    // third-party binary, so macOS shows its environment to `ps`.
    require_sandbox();
    let service = Command::new(env!("CARGO_BIN_EXE_apassy-dev-reporting"))
        .env("APASSY_DEV_REPORTING_TOKEN", SERVICE_TOKEN)
        .env(ENV_CANARY_NAME, ENV_CANARY_VALUE)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start outside process");
    let mut outside = DevService {
        child: service,
        base_url: String::new(),
    };
    let stdout = outside.child.stdout.take().expect("outside stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("outside process is ready");
    let pid = outside.child.id().to_string();

    // Control: outside the profile, `ps eww` shows the canary.
    let control = Command::new("/bin/ps")
        .args(["eww", "-p", &pid])
        .output()
        .expect("control ps");
    assert!(
        String::from_utf8_lossy(&control.stdout).contains(ENV_CANARY_VALUE),
        "control: ps outside the profile must show the canary, or this check proves nothing"
    );

    // Inside the profile, neither `ps` form shows the canary.
    let fx = fixture();
    for args in [
        vec!["/bin/ps", "eww", "-p", pid.as_str()],
        vec!["/bin/ps", "-E", "-p", pid.as_str(), "-o", "command"],
    ] {
        let (_ok, out, err) = in_sandbox(&fx, &args);
        assert!(
            !out.contains(ENV_CANARY_VALUE) && !err.contains(ENV_CANARY_VALUE),
            "{args:?} in the profile showed the canary"
        );
    }
    drop(outside);
}

#[test]
fn own_child_processes_work_in_profile() {
    // The host starts child processes and passes them an environment. This
    // must keep working inside the profile.
    require_sandbox();
    let fx = fixture();
    let (ok, out, err) = in_sandbox(
        &fx,
        &[
            "/bin/sh",
            "-c",
            "CHILD_VAR=child-ok /bin/sh -c 'echo $CHILD_VAR' & wait",
        ],
    );
    assert!(ok, "a child process must run in the profile: {err}");
    assert_eq!(out.trim(), "child-ok");
}

/// One JSON request line for a helper.
const PING: &str = "{\"cmd\":\"ping\"}";

/// Start `program` outside the profile with one `ping` line, as the owner's
/// shell does. The helper starts and answers. Its parent is this test process,
/// not the signed Apassy app, so the answer is `caller_not_allowed`.
fn start_outside(program: &Path) -> Value {
    let mut child = Command::new(program)
        .env_remove(DEV_ANY_CALLER)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("control: the helper must start outside the profile");
    writeln!(child.stdin.take().expect("stdin"), "{PING}").expect("write ping");
    let output = child.wait_with_output().expect("wait for the helper");
    assert!(output.status.success(), "control exit: {:?}", output.status);
    serde_json::from_slice(&output.stdout).expect("control answer is JSON")
}

/// Assert that `program` does not start inside the profile: not by a direct
/// exec, not from a shell pipe, and not with the development override set.
fn assert_cannot_start_in_profile(fx: &Fixture, label: &str, program: &Path) {
    let path = program.display().to_string();
    let (ok, out, err) = in_sandbox(fx, &[&path]);
    assert!(!ok, "{label} started in the profile: {out}");
    assert!(
        err.contains("Operation not permitted"),
        "the {label} denial must be a sandbox denial: {err}"
    );
    for script in [
        format!("printf '%s\\n' '{PING}' | '{path}'"),
        format!("printf '%s\\n' '{PING}' | {DEV_ANY_CALLER}=1 '{path}'"),
    ] {
        let (ok, out, err) = in_sandbox(fx, &["/bin/sh", "-c", &script]);
        assert!(!ok, "{label} started in the profile: {out}");
        assert!(
            err.contains("Operation not permitted"),
            "the {label} denial must be a sandbox denial: {err}"
        );
        assert!(out.is_empty(), "{label} answered in the profile: {out}");
    }
}

#[test]
fn apassy_programs_cannot_start_in_profile() {
    require_sandbox();
    let fx = fixture_with_app();
    let app = fx.app.clone().expect("app");
    for (label, program) in [
        ("the keychain helper", keychain_program(&app)),
        ("the notifier", notifier_program(&app)),
        ("apassy-helper", app.join(APP_HELPER)),
        ("the main program", app.join(APP_MAIN)),
    ] {
        // Control: outside the profile the same file starts and answers.
        let answer = start_outside(&program);
        assert_eq!(answer["error"], "caller_not_allowed", "{label}: {answer}");
        assert_cannot_start_in_profile(&fx, label, &program);
    }
}

#[test]
fn notifier_bundle_cannot_be_opened_in_profile() {
    // Goal item N1: the notifier is the main program of its own app bundle,
    // `Contents/Helpers/ApassyNotify.app`. A process in the profile must not
    // start it through LaunchServices either: the started program runs outside
    // the sandbox, and it can post a notification. The profile denies `lsopen`
    // and each read in the bundle.
    //
    // A marker program stands for the notifier, so the test sees each start.
    // The bundle ID is synthetic, so the test does not register the Apassy
    // notifier with LaunchServices.
    require_sandbox();
    let fx = fixture_with_app();
    let app = fx.app.clone().expect("app");
    let bundle = app.join(APP_NOTIFIER_BUNDLE);
    let marker = fx.layout.data_dir.with_file_name("notifier-started.txt");
    std::fs::write(
        bundle.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\
         <key>CFBundleName</key><string>IsoNotify</string>\
         <key>CFBundleIdentifier</key><string>com.apassy.iso-notify</string>\
         <key>CFBundleExecutable</key><string>ApassyNotify</string>\
         <key>CFBundlePackageType</key><string>APPL</string>\
         <key>LSUIElement</key><true/></dict></plist>\n",
    )
    .expect("notifier Info.plist");
    let program = notifier_program(&app);
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\necho NOTIFIER-STARTED >> '{}'\n",
            marker.display()
        ),
    )
    .expect("marker program");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("marker mode");
    let bundle_s = bundle.display().to_string();

    // Control first: outside the profile, `open` starts the bundle. So the
    // bundle is valid, and LaunchServices now knows its bundle ID, as it knows
    // the real notifier after its first notification.
    let control = Command::new("/usr/bin/open")
        .args(["-g", "-j", "-n"])
        .arg(&bundle)
        .output()
        .expect("control open");
    assert!(
        control.status.success(),
        "control: `open` outside the profile must start the bundle: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        wait_for(&marker, 20),
        "control: the notifier bundle did not start outside the profile"
    );
    std::fs::remove_file(&marker).expect("remove marker");

    // In the profile: `open` of the path fails, because the profile denies each
    // read in the bundle. `open -b` of the bundle ID needs no read of the path,
    // and the `lsopen` denial stops it.
    let (ok, _out, err) = in_sandbox(&fx, &["/usr/bin/open", "-g", "-j", "-n", &bundle_s]);
    assert!(!ok, "the profile must deny `open` of the notifier bundle");
    assert!(
        err.contains("does not exist") || err.contains("-54") || err.contains("failed"),
        "the `open` denial must be a sandbox or LaunchServices failure: {err}"
    );
    let (ok, _out, err) = in_sandbox(
        &fx,
        &[
            "/usr/bin/open",
            "-g",
            "-j",
            "-n",
            "-b",
            "com.apassy.iso-notify",
        ],
    );
    assert!(!ok, "the profile must deny `open -b` of the notifier");
    assert!(
        err.contains("-54") || err.contains("failed"),
        "the `open -b` denial must be a LaunchServices failure: {err}"
    );
    assert!(
        !wait_for(&marker, 3),
        "the notifier bundle started from the profile"
    );

    // Remove the synthetic bundle from the LaunchServices database.
    let _ = Command::new(
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
    )
    .arg("-u")
    .arg(&bundle)
    .output();
}

/// Every file and link below `dir`, at any depth. Directories are not listed.
fn files_below(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        let meta = std::fs::symlink_metadata(&path).expect("metadata");
        if meta.is_dir() {
            found.extend(files_below(&path));
        } else {
            found.push(path);
        }
    }
    found
}

#[test]
fn apassy_programs_cannot_be_read_copied_linked_or_changed_in_profile() {
    require_sandbox();
    let fx = fixture_with_app();
    let app = fx.app.clone().expect("app");
    let keychain = keychain_program(&app);
    let helper = app.join(APP_HELPER);
    let out_dir = fx.layout.data_dir.with_file_name("copies");
    std::fs::create_dir_all(&out_dir).expect("copies dir");
    let keychain_s = keychain.display().to_string();
    let helper_s = helper.display().to_string();
    let app_s = app.display().to_string();
    let app_parent = app.parent().expect("parent").display().to_string();
    let out = |name: &str| out_dir.join(name).display().to_string();

    let attempts: Vec<(&str, Vec<String>)> = vec![
        ("read", vec!["/bin/cat".into(), keychain_s.clone()]),
        (
            "copy",
            vec!["/bin/cp".into(), keychain_s.clone(), out("copy")],
        ),
        (
            "clone",
            vec![
                "/bin/cp".into(),
                "-c".into(),
                helper_s.clone(),
                out("clone"),
            ],
        ),
        (
            "hard link",
            vec!["/bin/ln".into(), helper_s.clone(), out("link")],
        ),
        (
            "copy of the keychain bundle",
            vec![
                "/bin/cp".into(),
                "-R".into(),
                app.join(APP_KEYCHAIN_BUNDLE).display().to_string(),
                out("ApassyKeychain.app"),
            ],
        ),
        (
            "copy of the notifier bundle",
            vec![
                "/bin/cp".into(),
                "-R".into(),
                app.join(APP_NOTIFIER_BUNDLE).display().to_string(),
                out("ApassyNotify.app"),
            ],
        ),
        (
            "copy of the app",
            vec![
                "/bin/cp".into(),
                "-R".into(),
                app_s.clone(),
                out("Apassy.app"),
            ],
        ),
        (
            "list",
            vec!["/bin/ls".into(), app.join("Contents").display().to_string()],
        ),
        (
            "overwrite",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("echo x > '{helper_s}'"),
            ],
        ),
        (
            "new program",
            vec![
                "/usr/bin/touch".into(),
                app.join("Contents/MacOS/new-program").display().to_string(),
            ],
        ),
        (
            "rename of the app",
            vec!["/bin/mv".into(), app_s.clone(), out("Moved.app")],
        ),
        (
            "rename of the app parent",
            vec![
                "/bin/mv".into(),
                app_parent.clone(),
                format!("{app_parent}-moved"),
            ],
        ),
    ];
    for (label, command) in &attempts {
        let parts: Vec<&str> = command.iter().map(String::as_str).collect();
        let (ok, stdout, err) = in_sandbox(&fx, &parts);
        assert!(!ok, "the profile must deny the {label}: {stdout}");
        assert!(
            err.contains("Operation not permitted"),
            "the {label} denial must be a sandbox denial: {err}"
        );
    }
    // `cp -R` can make an empty target directory before the read fails. No
    // file may exist below the target directory.
    let left = files_below(&out_dir);
    assert!(left.is_empty(), "a copy or a link exists: {left:?}");
    let original = std::fs::read(dev_helper()).expect("helper bytes");
    for program in [&keychain, &helper] {
        assert_eq!(
            std::fs::read(program).expect("program bytes"),
            original,
            "{} changed",
            program.display()
        );
    }
    assert!(!app.join("Contents/MacOS/new-program").exists());
}

#[test]
fn a_helper_outside_the_bundle_refuses_a_caller_in_profile() {
    // The second layer. The owner (outside the profile) puts a copy of the
    // keychain helper bundle at a path that the profile does not protect. A
    // process in the profile can start this copy, but the helper refuses each
    // request: its parent is not the signed Apassy app that contains it.
    require_sandbox();
    let fx = fixture_with_app();
    let app = fx.app.clone().expect("app");
    let elsewhere = fx.layout.data_dir.with_file_name("elsewhere");
    let copy = elsewhere.join("ApassyKeychain.app/Contents/MacOS/ApassyKeychain");
    std::fs::create_dir_all(copy.parent().expect("dir")).expect("copy dir");
    std::fs::copy(keychain_program(&app), &copy).expect("owner copy");

    let account = apassy::native::vault_unlock_account(&fx.layout.vault_file);
    let requests = [
        PING.to_owned(),
        json!({"cmd": "keychain_exists", "account": account}).to_string(),
        json!({"cmd": "keychain_read", "account": account, "reason": "isolation check"})
            .to_string(),
        json!({"cmd": "authenticate", "reason": "isolation check"}).to_string(),
    ];
    let quoted: Vec<String> = requests.iter().map(|line| format!("'{line}'")).collect();
    let script = format!("printf '%s\\n' {} | '{}'", quoted.join(" "), copy.display());
    let (ok, out, err) = in_sandbox(&fx, &["/bin/sh", "-c", &script]);
    assert!(ok, "the copy outside the bundle must start: {err}");
    let answers: Vec<Value> = out
        .lines()
        .map(|line| serde_json::from_str(line).expect("helper answer is JSON"))
        .collect();
    assert_eq!(answers.len(), requests.len(), "{answers:?}");
    for answer in &answers {
        assert_eq!(answer["ok"], false, "{answer}");
        assert_eq!(answer["error"], "caller_not_allowed", "{answer}");
        assert!(answer.get("secret_b64").is_none(), "{answer}");
    }
}

/// Run the `apassy-hook` program at `hook` inside the profile with `input` on
/// stdin. Return (exit ok, stdout, stderr).
fn hook_in_sandbox(fx: &Fixture, hook: &Path, token: &str, input: &str) -> (bool, String, String) {
    let mut args = sandbox_args(fx);
    args.push(hook.display().to_string());
    let mut child = Command::new(env!("CARGO_BIN_EXE_apassy-sandbox"))
        .args(&args)
        .env("APASSY_AGENT_TOKEN", token)
        .env("APASSY_BROKER_SOCKET", &fx.layout.socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the hook in the profile");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write hook input");
    let output = child.wait_with_output().expect("wait for the hook");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn apassy_mcp_and_hook_in_the_app_bundle_work_in_profile() {
    // The agent host starts `apassy-mcp` and `apassy-hook`. The profile denies
    // the other programs of the bundle, but these two start and reach the
    // broker.
    require_sandbox();
    let fx = fixture_with_app();
    let app = fx.app.clone().expect("app");
    let mut mcp = McpProcess::start_program_in_sandbox(&fx, &app.join(APP_MCP));
    assert_adapter_works(&fx, &mut mcp);
    drop(mcp);

    let hook = app.join(APP_HOOK);
    let input = json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "isolation-session",
        "cwd": env!("CARGO_MANIFEST_DIR"),
        "prompt": "Run the synthetic isolation check.",
    })
    .to_string();
    // The hook starts, sends the prompt, and the broker accepts it: no stderr.
    let (ok, out, err) = hook_in_sandbox(&fx, &hook, &fx.token, &input);
    assert!(ok, "the hook must start in the profile: {err}");
    assert!(out.is_empty(), "the hook wrote to stdout: {out}");
    assert!(
        err.is_empty(),
        "the broker did not accept the hook request: {err}"
    );
    // Control: with a wrong token the broker refuses, and the hook says so.
    let (ok, _out, err) = hook_in_sandbox(&fx, &hook, "apassy_agt_synthetic-wrong-token", &input);
    assert!(ok, "the hook always exits 0: {err}");
    assert!(err.contains("the broker refused"), "control: {err}");
}

#[test]
fn profile_protects_the_build_app_without_the_installed_app_parameter() {
    // The profile uses /Applications/Apassy.app when APASSY_APP is absent, and
    // protects APASSY_APP_BUILD as a second bundle.
    require_sandbox();
    let fx = fixture_with_app();
    let app = std::fs::canonicalize(fx.app.clone().expect("app")).expect("canonical app");
    let l = &fx.layout;
    let resolved = |path: &Path| {
        let parent = std::fs::canonicalize(path.parent().expect("parent")).expect("parent");
        parent
            .join(path.file_name().expect("name"))
            .display()
            .to_string()
    };
    let base = [
        "-f".to_owned(),
        profile_path().display().to_string(),
        "-D".to_owned(),
        format!("APASSY_DATA_DIR={}", resolved(&l.data_dir)),
        "-D".to_owned(),
        format!("APASSY_VAULT_FILE={}", resolved(&l.vault_file)),
        "-D".to_owned(),
        format!("APASSY_BACKUP_FILE={}", resolved(&l.backup_file)),
        "-D".to_owned(),
        format!("APASSY_SOCKET={}", resolved(&l.socket)),
        "-D".to_owned(),
        format!("APASSY_HOME={}", resolved(&l.home)),
        "-D".to_owned(),
        format!("APASSY_APP_BUILD={}", app.display()),
    ];
    let denied = Command::new(SANDBOX_EXEC)
        .args(&base)
        .arg(keychain_program(&app))
        .output()
        .expect("run sandbox-exec");
    assert!(!denied.status.success(), "the keychain helper started");
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("Operation not permitted"),
        "{}",
        String::from_utf8_lossy(&denied.stderr)
    );
    let mcp = Command::new(SANDBOX_EXEC)
        .args(&base)
        .arg(app.join(APP_MCP))
        .arg("--version")
        .output()
        .expect("run sandbox-exec");
    assert!(
        mcp.status.success(),
        "apassy-mcp in the bundle must start: {}",
        String::from_utf8_lossy(&mcp.stderr)
    );
    assert!(String::from_utf8_lossy(&mcp.stdout).starts_with("apassy-mcp "));
}

#[test]
fn launcher_passes_the_installed_and_the_build_app() {
    // Defaults: the installed app, and `<target>/Apassy.app` next to the launcher.
    let launcher = Path::new(env!("CARGO_BIN_EXE_apassy-sandbox"));
    let target = std::fs::canonicalize(launcher.parent().and_then(Path::parent).expect("target"))
        .expect("canonical target");
    let print = |extra: &[&str]| {
        let output = Command::new(launcher)
            .args(["--data-dir", "/tmp/apassy-print-check/d"])
            .args(extra)
            .args(["--print", "--", "/usr/bin/true"])
            .output()
            .expect("run apassy-sandbox --print");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let defaults = print(&[]);
    assert!(
        defaults.contains(" -D APASSY_APP=/Applications/Apassy.app "),
        "{defaults}"
    );
    // The launcher passes the owner home for the autostart denials.
    assert!(defaults.contains(" -D APASSY_HOME="), "{defaults}");
    assert!(
        defaults.contains(&format!(
            " -D APASSY_APP_BUILD={} ",
            target.join("Apassy.app").display()
        )),
        "{defaults}"
    );
    let chosen = print(&[
        "--app",
        "/tmp/apassy-print-check/Installed.app",
        "--app-build",
        "/tmp/apassy-print-check/Build.app",
    ]);
    assert!(
        chosen.contains(" -D APASSY_APP=/private/tmp/apassy-print-check/Installed.app "),
        "{chosen}"
    );
    assert!(
        chosen.contains(" -D APASSY_APP_BUILD=/private/tmp/apassy-print-check/Build.app "),
        "{chosen}"
    );
}

/// Goal I2, Keychain part. A process in the profile cannot read the Apassy Touch ID
/// item: not with `/usr/bin/security`, and not through the Apassy keychain helper.
///
/// - `security` runs in the profile (so a "not found" is not a broken tool), and it
///   finds no item with the service and the account that the helper uses, inside and
///   outside the profile. The item is in the data protection keychain, which the
///   `security` tool does not search, and it needs the Apassy access group.
/// - The keychain helper of the app bundle does not start in the profile. The deny
///   does not depend on the signature or on a provisioning profile, so it also holds
///   for a provisioned build with a keychain access group. A process in the profile
///   cannot use the helper to show a Touch ID prompt or to read the unlock key.
/// - `apassy_programs_cannot_be_read_copied_linked_or_changed_in_profile` shows that
///   the process cannot copy the helper to a path that the profile does not deny.
///   `a_helper_outside_the_bundle_refuses_a_caller_in_profile` shows the caller check
///   of the helper for a copy that exists already. `scripts/build-app.sh` runs the
///   same checks with the signed helpers.
#[test]
fn keychain_item_is_not_readable_in_profile() {
    require_sandbox();
    let fx = fixture_with_app();
    let service = apassy::native::KEYCHAIN_SERVICE;
    let account = apassy::native::vault_unlock_account(&fx.layout.vault_file);

    // The tool runs in the profile.
    let (ok, out, err) = in_sandbox(&fx, &["/usr/bin/security", "list-keychains"]);
    assert!(ok, "security must run in the profile: {err}");
    assert!(out.contains(".keychain"), "{out}");

    // Control outside the profile, then the same query inside it.
    let query = [
        "/usr/bin/security",
        "find-generic-password",
        "-s",
        service,
        "-a",
        &account,
        "-w",
    ];
    let outside = Command::new(query[0])
        .args(&query[1..])
        .output()
        .expect("security outside");
    assert_eq!(
        outside.status.code(),
        Some(44),
        "control: no item in the file keychains"
    );
    let inside = Command::new(env!("CARGO_BIN_EXE_apassy-sandbox"))
        .args(sandbox_args(&fx))
        .args(query)
        .output()
        .expect("security inside");
    assert_eq!(
        inside.status.code(),
        Some(44),
        "security in the profile: {}",
        String::from_utf8_lossy(&inside.stderr)
    );
    assert!(
        inside.stdout.is_empty(),
        "security printed a value in the profile"
    );

    // The Apassy keychain helper: it starts outside the profile (control), and it
    // does not start inside it.
    let keychain = keychain_program(fx.app.as_deref().expect("app"));
    let answer = start_outside(&keychain);
    assert_eq!(answer["error"], "caller_not_allowed", "{answer}");
    assert_cannot_start_in_profile(&fx, "the keychain helper", &keychain);
    let request = json!({"cmd": "keychain_read", "account": account, "reason": "isolation check"});
    let script = format!("printf '%s\\n' '{request}' | '{}'", keychain.display());
    let (ok, out, err) = in_sandbox(&fx, &["/bin/sh", "-c", &script]);
    assert!(
        !ok && out.is_empty(),
        "keychain_read answered in the profile: {out}"
    );
    assert!(err.contains("Operation not permitted"), "{err}");
}
