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
//! Keychain: goal item I2 also needs proof that the process cannot read the
//! Touch ID Keychain item. `keychain_item_is_not_readable_in_profile` checks it
//! with `/usr/bin/security` and with the Apassy keychain helper. Its comment
//! says what it proves and what stays pending until the app has a
//! provisioning profile.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

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
    Layout {
        data_dir,
        vault_file,
        backup_file,
        laya_file,
        socket,
        scratch: dir.path().join("scratch.txt"),
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
    token: String,
    item_id: u64,
    _service: DevService,
    _broker: broker::BrokerHandle,
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
        _service: service,
        _broker: handle,
    }
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
        "--".to_owned(),
    ]
}

/// Run a command inside the profile. Return (exit ok, stdout, stderr).
fn in_sandbox(fx: &Fixture, host: &[&str]) -> (bool, String, String) {
    let mut args = sandbox_args(fx);
    args.extend(host.iter().map(|part| (*part).to_owned()));
    let output = Command::new(env!("CARGO_BIN_EXE_apassy-sandbox"))
        .args(&args)
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
        let mut args = sandbox_args(fx);
        args.push(env!("CARGO_BIN_EXE_apassy-mcp").to_owned());
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

/// The keychain helper of the signed app, or `None` when `scripts/build-app.sh` did not
/// run in this checkout.
fn bundled_keychain_helper() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/Apassy.app/Contents")
        .join(apassy::native::KEYCHAIN_HELPER_FROM_CONTENTS);
    path.is_file().then_some(path)
}

/// The helper code without a signature, built once with the Swift compiler.
fn unsigned_keychain_helper() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("isolation-keychain-helper");
    std::fs::create_dir_all(&out_dir).expect("helper dir");
    let out = out_dir.join("ApassyKeychain");
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
        .args(["-target", &format!("{arch}-apple-macos15.0"), "-o"])
        .arg(&out)
        .args(&sources)
        .status()
        .expect("run xcrun: the Keychain check needs Xcode. This is a failure, not a skip.");
    assert!(
        status.success(),
        "swiftc failed to build the keychain helper"
    );
    out
}

/// Send JSON lines to `helper` inside the profile. Returns one JSON value per line.
fn helper_in_sandbox(fx: &Fixture, helper: &Path, requests: &[Value]) -> Vec<Value> {
    let lines: Vec<String> = requests
        .iter()
        .map(|request| format!("'{request}'"))
        .collect();
    let script = format!(
        "printf '%s\\n' {} | '{}'",
        lines.join(" "),
        helper.display()
    );
    let (ok, out, err) = in_sandbox(fx, &["/bin/sh", "-c", &script]);
    assert!(ok, "the helper did not answer in the profile: {err}");
    out.lines()
        .map(|line| serde_json::from_str(line).expect("helper answer is JSON"))
        .collect()
}

/// Goal I2, Keychain part. A process in the profile cannot read the Apassy Touch ID
/// item: not with `/usr/bin/security`, and not through the Apassy keychain helper.
///
/// What this proves now:
/// - `security` runs in the profile (so a "not found" is not a broken tool), and it
///   finds no item with the service and the account that the helper uses, inside and
///   outside the profile. The item is in the data protection keychain, which the
///   `security` tool does not search, and it needs the Apassy access group.
/// - The keychain helper from `target/Apassy.app` (or the helper code without a
///   signature, when the app is not built) runs in the profile, has no keychain access
///   group, and answers `keychain_unavailable` to `keychain_exists` and to
///   `keychain_read`. So no process can read an unlock key from this build.
///
/// What stays pending (see `docs/operations/native-app.md`): the real
/// `.biometryCurrentSet` item needs a provisioning profile. With a profile, the helper
/// has an access group. Then a process in the profile could start the helper and ask
/// for a Touch ID prompt, and only the owner's finger would stop it. This test then
/// fails on purpose, until the agent profile denies the start of the Apassy helpers.
#[test]
fn keychain_item_is_not_readable_in_profile() {
    require_sandbox();
    let fx = fixture();
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

    // The Apassy keychain helper, started from inside the profile.
    let helper = bundled_keychain_helper().unwrap_or_else(unsigned_keychain_helper);
    eprintln!("keychain check uses {}", helper.display());
    let ping = helper_in_sandbox(&fx, &helper, &[json!({"cmd": "ping"})]);
    assert_eq!(ping[0]["ok"], true, "{ping:?}");
    assert!(
        ping[0]["keychain_access_group"].is_null(),
        "The keychain helper runs in the agent profile and has the keychain access group {}. \
         A process in the profile can then ask for the Touch ID unlock key. Deny the start of \
         the Apassy helpers in sandbox/apassy-agent-host.sb before a provisioned build is used.",
        ping[0]["keychain_access_group"]
    );
    let answers = helper_in_sandbox(
        &fx,
        &helper,
        &[
            json!({"cmd": "keychain_exists", "account": account}),
            json!({"cmd": "keychain_read", "account": account, "reason": "isolation check"}),
        ],
    );
    assert_eq!(answers.len(), 2, "{answers:?}");
    for answer in &answers {
        assert_eq!(answer["ok"], false, "{answer}");
        assert_eq!(answer["error"], "keychain_unavailable", "{answer}");
        assert!(answer.get("secret_b64").is_none(), "{answer}");
    }
}
