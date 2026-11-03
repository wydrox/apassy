#![cfg(target_os = "linux")]

//! The Linux sandbox (unit X1 of docs/design/implementation-plan-s5-env-0011.md;
//! docs/operations/isolation-linux.md).
//!
//! Each test starts real processes in a bubblewrap sandbox made by
//! `apassy::isolation::linux`, with `apassy-sandbox` as its init and bridge, and
//! checks the boundary with a control outside the sandbox:
//!
//! - a process cannot read a vault, the vault list's vaults outside the data
//!   folder, the link file, `~/.ssh`, the keyrings, the browser profiles, or a
//!   canary outside the project; the project stays readable and writable;
//! - the runtime folder (the session bus) and the other homes are not there;
//! - in its own network namespace it reaches the run proxy through the bridge, and
//!   nothing else: no other TCP port on 127.0.0.1, no public address, no UDP, no
//!   abstract Unix socket of the host;
//! - it cannot see the processes outside, and no process of the run outlives it;
//! - it cannot make a user namespace of its own.
//!
//! The tests need bubblewrap 0.8 or later with user namespaces, and `bash`, `curl`,
//! `python3`, `setsid`, and `unshare`. Without them a test prints why and passes,
//! except with `APASSY_REQUIRE_BWRAP=1` (the `linux-isolation` CI job), where it
//! fails. All values are synthetic.

use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{SocketAddr as UnixSocketAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy::isolation::linux::{
    self as linux, Availability, HomePolicy, HostPaths, HostRelay, NetPlan, Sandbox,
};

const REQUIRE: &str = "APASSY_REQUIRE_BWRAP";
const CANARY: &str = "SYNTHETIC-ISOLATION-CANARY-NOT-A-SECRET";
const PATH: &str = "/usr/bin:/bin";
const LIMIT: Duration = Duration::from_secs(60);

/// Prints a line for each path: `CANARY <path>` when the sandbox reads the canary
/// text in it, else `NO_CANARY <path>`. A denied file can read as empty (a mask
/// with `/dev/null`), so the test checks the text, not the exit code of a read.
const READ_SCRIPT: &str = r#"for p in "$@"; do if grep -qF SYNTHETIC-ISOLATION-CANARY -- "$p" 2>/dev/null; then echo "CANARY $p"; else echo "NO_CANARY $p"; fi; done"#;

fn required() -> bool {
    std::env::var_os(REQUIRE).is_some_and(|value| value == "1")
}

/// Is bubblewrap ready? Without it the test passes with a note, or fails when
/// `APASSY_REQUIRE_BWRAP=1`.
fn ready(test: &str) -> bool {
    match linux::probe() {
        Availability::Ready { .. } => true,
        other => {
            assert!(
                !required(),
                "{REQUIRE}=1, but bubblewrap cannot run here: {other:?}"
            );
            eprintln!("skip {test}: bubblewrap cannot run here: {other:?}");
            false
        }
    }
}

/// Is each tool installed? As [`ready`].
fn tools(test: &str, names: &[&str]) -> bool {
    for name in names {
        let found = ["/usr/bin", "/bin"]
            .iter()
            .any(|dir| Path::new(dir).join(name).is_file());
        if !found {
            assert!(!required(), "{REQUIRE}=1, but {name} is not installed");
            eprintln!("skip {test}: {name} is not installed");
            return false;
        }
    }
    true
}

/// The init and bridge program of each sandbox.
fn init_program() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_apassy-sandbox"))
}

fn unique() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A folder under `CARGO_TARGET_TMPDIR`, removed at the end.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "isolation-linux-{name}-{}-{}",
            std::process::id(),
            unique()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch folder");
        Scratch(fs::canonicalize(&dir).expect("canonical scratch folder"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("folders");
    fs::write(path, text).expect("write");
}

fn text(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
}

/// A synthetic home with a project, Apassy files, keys, keyrings, browser
/// profiles, and canaries.
struct Layout {
    _scratch: Scratch,
    paths: HostPaths,
    project: PathBuf,
    /// Paths that a sandbox must never read.
    secrets: Vec<PathBuf>,
    /// A vault of the vault list outside the data folder.
    extra_vault: PathBuf,
    /// Readable files next to the secrets, for the read-only home.
    home_note: PathBuf,
    other_project: PathBuf,
    elsewhere_note: PathBuf,
}

fn layout(name: &str) -> Layout {
    let scratch = Scratch::new(name);
    let root = scratch.0.clone();
    let home = root.join("home");
    let mut paths = HostPaths::under_home(&home);
    let runtime = root.join("shown").join("run-user");
    fs::create_dir_all(&runtime).expect("runtime folder");
    paths.runtime_dir = Some(runtime);
    let project = home.join("work").join("project");
    write(&project.join("README.md"), "a project file\n");

    let extra_vault = root.join("elsewhere").join("work.db");
    let secrets = vec![
        paths.data_dir.join("vault.db"),
        paths.data_dir.join("vault.db-wal"),
        paths.data_dir.join("laya").join("model.bin"),
        extra_vault.clone(),
        paths.link_file(),
        paths.config_dir().join("node.json"),
        home.join(".ssh").join("id_ed25519"),
        home.join(".gnupg")
            .join("private-keys-v1.d")
            .join("key.key"),
        paths.data_home.join("keyrings").join("login.keyring"),
        home.join(".mozilla")
            .join("firefox")
            .join("default")
            .join("logins.json"),
        paths
            .config_home
            .join("google-chrome")
            .join("Default")
            .join("Login Data"),
        paths
            .config_home
            .join("chromium")
            .join("Default")
            .join("Cookies"),
    ];
    for secret in &secrets {
        write(secret, &format!("{CANARY}\n"));
    }
    let mut registry = apassy::vaults::Registry::new();
    registry.add("Work", &extra_vault, 1).expect("add a vault");
    registry.save(&paths.data_dir).expect("save the vault list");

    let home_note = home.join("notes.txt");
    let other_project = home.join("work").join("other").join("secret.txt");
    let elsewhere_note = root.join("elsewhere").join("readme.txt");
    for path in [&home_note, &other_project, &elsewhere_note] {
        write(path, &format!("{CANARY}\n"));
    }
    Layout {
        _scratch: scratch,
        paths,
        project,
        secrets,
        extra_vault,
        home_note,
        other_project,
        elsewhere_note,
    }
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Output {
    fn has(&self, line: &str) -> bool {
        self.stdout.lines().any(|seen| seen == line)
    }

    #[track_caller]
    fn expect_line(&self, line: &str) {
        assert!(
            self.has(line),
            "expected the line {line:?}\nstdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
    }
}

fn finish(mut child: Child, limit: Duration) -> Output {
    let mut out = child.stdout.take().expect("stdout");
    let mut err = child.stderr.take().expect("stderr");
    let stdout = thread::spawn(move || {
        let mut text = String::new();
        let _ = out.read_to_string(&mut text);
        text
    });
    let stderr = thread::spawn(move || {
        let mut text = String::new();
        let _ = err.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the sandbox did not end in {limit:?}");
        }
        thread::sleep(Duration::from_millis(20));
    };
    Output {
        code: status.code(),
        stdout: stdout.join().expect("stdout"),
        stderr: stderr.join().expect("stderr"),
    }
}

fn run<I, S>(sandbox: &Sandbox, program: &str, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = sandbox.command(program, args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    finish(command.spawn().expect("start bubblewrap"), LIMIT)
}

fn sh(sandbox: &Sandbox, script: &str, args: &[&str]) -> Output {
    let mut all = vec!["-c", script, "sh"];
    all.extend_from_slice(args);
    run(sandbox, "sh", all)
}

/// The run profile of `layout` with `net`.
fn run_sandbox(layout: &Layout, net: NetPlan) -> Sandbox {
    Sandbox::for_run(&layout.paths, &layout.project)
        .expect("run profile")
        .net(net)
        .init_program(init_program())
        .env("PATH", PATH)
        .env("HOME", &layout.paths.home)
        .env("LANG", "C")
        .build()
        .expect("sandbox")
}

/// A fake HTTP proxy: it records the request line and answers `via-proxy`.
fn proxy_stand_in() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
    let addr = listener.local_addr().expect("proxy address");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut first = String::new();
                let _ = reader.read_line(&mut first);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line == "\r\n" || line == "\n" => break,
                        Ok(_) => {}
                    }
                }
                log.lock().expect("log").push(first.trim_end().to_owned());
                let mut stream = stream;
                let body = "via-proxy";
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    (addr, seen)
}

/// A listener that counts its connections without serving them.
fn counting_listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    (listener, port)
}

fn accepted_nothing(listener: &TcpListener) -> bool {
    matches!(listener.accept(), Err(err) if err.kind() == ErrorKind::WouldBlock)
}

/// The vault, the listed vault outside the data folder, the link file, the Apassy
/// configuration, `~/.ssh`, GPG, the keyring, the browser profiles, another project,
/// a note in the home, and a canary in the host `/tmp`: none is readable. The
/// project is readable and writable, and what the run writes in its private home
/// stays there.
#[test]
fn run_profile_hides_the_vault_ssh_and_files_outside_the_project() {
    if !ready("run_profile_hides_the_vault_ssh_and_files_outside_the_project") {
        return;
    }
    let layout = layout("run-profile");
    let host_tmp = std::env::temp_dir().join(format!(
        "apassy-isolation-canary-{}-{}",
        std::process::id(),
        unique()
    ));
    write(&host_tmp, &format!("{CANARY}\n"));
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    assert_eq!(sandbox.rule(), linux::RULE_NETNS);

    let mut hidden: Vec<PathBuf> = layout.secrets.clone();
    hidden.extend([
        layout.home_note.clone(),
        layout.other_project.clone(),
        host_tmp.clone(),
    ]);
    let args: Vec<&str> = hidden.iter().map(|path| text(path)).collect();
    let script = format!(
        "{READ_SCRIPT}\n\
         echo \"PROJECT $(cat \"$PWD/README.md\")\"\n\
         if head -c 1 /etc/passwd >/dev/null 2>&1; then echo READ_SYSTEM; fi\n\
         echo written > \"$PWD/written.txt\" && echo WROTE_PROJECT\n\
         echo private > \"$HOME/private.txt\" && echo WROTE_HOME"
    );
    let out = sh(&sandbox, &script, &args);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    for path in &hidden {
        // Control: the canary is readable outside the sandbox.
        assert!(
            fs::read_to_string(path)
                .expect("control read")
                .contains(CANARY)
        );
        out.expect_line(&format!("NO_CANARY {}", text(path)));
    }
    out.expect_line("PROJECT a project file");
    out.expect_line("READ_SYSTEM");
    out.expect_line("WROTE_PROJECT");
    assert_eq!(
        fs::read_to_string(layout.project.join("written.txt")).expect("the project write"),
        "written\n"
    );
    out.expect_line("WROTE_HOME");
    assert!(
        !layout.paths.home.join("private.txt").exists(),
        "a write in the private home reached the host"
    );
    assert!(!out.stdout.contains(CANARY) && !out.stderr.contains(CANARY));
    let _ = fs::remove_file(&host_tmp);
}

/// With the real home read-only (the agent-host plan), the deny list still hides
/// the Apassy files, the keys, the keyrings, and the browser profiles, and the
/// masks cannot be written. The other files of the home and a visible folder stay
/// readable (controls).
#[test]
fn a_read_only_home_still_hides_keys_keyrings_browsers_and_apassy_files() {
    if !ready("a_read_only_home_still_hides_keys_keyrings_browsers_and_apassy_files") {
        return;
    }
    let layout = layout("read-only-home");
    let elsewhere = layout.extra_vault.parent().expect("folder").to_owned();
    let sandbox = Sandbox::builder()
        .home(&layout.paths.home, HomePolicy::ReadOnly)
        .deny(layout.paths.denied().expect("deny list"))
        .read_only([&elsewhere])
        .rw([&layout.project])
        .cwd(&layout.project)
        .net(NetPlan::Bridged(Vec::new()))
        .init_program(init_program())
        .env("PATH", PATH)
        .env("HOME", &layout.paths.home)
        .build()
        .expect("sandbox");
    let readable = [
        layout.home_note.clone(),
        layout.other_project.clone(),
        layout.elsewhere_note.clone(),
    ];
    let mut args: Vec<&str> = layout.secrets.iter().map(|path| text(path)).collect();
    args.extend(readable.iter().map(|path| text(path)));
    let data = text(&layout.paths.data_dir).to_owned();
    let ssh = text(&layout.paths.home.join(".ssh")).to_owned();
    let script = format!(
        "{READ_SCRIPT}\n\
         echo \"LIST data $(ls -A '{data}' 2>/dev/null | wc -l)\"\n\
         echo \"LIST ssh $(ls -A '{ssh}' 2>/dev/null | wc -l)\"\n\
         if touch '{data}/planted' 2>/dev/null; then echo PLANTED; else echo NOT_PLANTED; fi\n\
         if touch \"$HOME/new.txt\" 2>/dev/null; then echo HOME_WRITABLE; else echo HOME_READ_ONLY; fi"
    );
    let out = sh(&sandbox, &script, &args);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    for path in &layout.secrets {
        out.expect_line(&format!("NO_CANARY {}", text(path)));
    }
    for path in &readable {
        out.expect_line(&format!("CANARY {}", text(path)));
    }
    out.expect_line("LIST data 0");
    out.expect_line("LIST ssh 0");
    out.expect_line("NOT_PLANTED");
    out.expect_line("HOME_READ_ONLY");
    assert!(!layout.paths.data_dir.join("planted").exists());
    // Control: the data folder is not empty outside.
    assert!(fs::read_dir(&layout.paths.data_dir).expect("data").count() > 0);
}

/// The runtime folder with the session bus socket, the session bus variable,
/// `/run/user`, the system bus, the Docker socket, the other homes, and the
/// Apassy data folder are not there.
#[test]
fn sandbox_hides_the_apassy_data_dir_and_the_runtime_dir() {
    if !ready("sandbox_hides_the_apassy_data_dir_and_the_runtime_dir") {
        return;
    }
    let layout = layout("runtime");
    let runtime = layout.paths.runtime_dir.clone().expect("runtime folder");
    let bus = runtime.join("bus");
    let listener = UnixListener::bind(&bus).expect("the fake session bus");
    listener.set_nonblocking(true).expect("nonblocking");
    // The runtime folder's parent is visible, so the deny list must hide it.
    let shown = runtime.parent().expect("parent").to_owned();
    let sandbox = Sandbox::for_run(&layout.paths, &layout.project)
        .expect("run profile")
        .read_only([&shown])
        .init_program(init_program())
        .env("PATH", PATH)
        .env("HOME", &layout.paths.home)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", text(&bus)),
        )
        .build()
        .expect("sandbox");
    let script = r#"
        for p in "$@" /run/user /run/dbus/system_bus_socket /run/docker.sock; do
            if [ -e "$p" ]; then echo "PRESENT $p"; else echo "ABSENT $p"; fi
        done
        if [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then echo BUS_VARIABLE; else echo NO_BUS_VARIABLE; fi
        if [ -n "${XDG_RUNTIME_DIR:-}" ]; then echo RUNTIME_VARIABLE; else echo NO_RUNTIME_VARIABLE; fi
        echo "HOMES $(ls -A /home 2>/dev/null | tr '\n' ' ')"
    "#;
    let data = layout.paths.data_dir.clone();
    let out = sh(&sandbox, script, &[text(&bus), text(&runtime), text(&data)]);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    // Controls: the socket and the data folder exist outside.
    assert!(fs::metadata(&bus).expect("bus").file_type().is_socket());
    assert!(data.join("vault.db").is_file());
    out.expect_line(&format!("ABSENT {}", text(&bus)));
    // The masks of the runtime and data folders are empty folders.
    let empty = |dir: &Path| {
        let script = format!("ls -A '{}' | wc -l", text(dir));
        sh(&sandbox, &script, &[]).stdout.trim().to_owned()
    };
    assert_eq!(empty(&runtime), "0");
    assert_eq!(empty(&data), "0");
    for path in [
        "/run/user",
        "/run/dbus/system_bus_socket",
        "/run/docker.sock",
    ] {
        out.expect_line(&format!("ABSENT {path}"));
    }
    out.expect_line("NO_BUS_VARIABLE");
    out.expect_line("NO_RUNTIME_VARIABLE");
    assert!(
        matches!(listener.accept(), Err(err) if err.kind() == ErrorKind::WouldBlock),
        "the session bus got a connection"
    );

    // Other homes: each entry of /home in the sandbox is on the way to a path that
    // the sandbox has; the others (other users, other files) are gone.
    let homes_line = out
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("HOMES "))
        .expect("HOMES line")
        .to_owned();
    let real_home = fs::canonicalize("/home").ok();
    if let Some(real_home) = real_home.filter(|dir| dir.as_path() == Path::new("/home")) {
        let on_the_way: Vec<String> = [&layout.paths.home, &layout.project]
            .iter()
            .filter_map(|path| path.strip_prefix(&real_home).ok())
            .filter_map(|rest| rest.components().next())
            .map(|first| first.as_os_str().to_string_lossy().into_owned())
            .collect();
        for entry in homes_line.split_whitespace() {
            assert!(
                on_the_way.iter().any(|name| name == entry),
                "/home/{entry} is visible in the sandbox"
            );
        }
        let outside: Vec<String> = fs::read_dir("/home")
            .expect("/home")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        eprintln!("/home outside: {outside:?}; inside: {homes_line:?}");
    }
}

/// The run reaches the run proxy through the bridge: the request goes through
/// `127.0.0.1:<port>` in the namespace, the bridge, and the host relay.
#[test]
fn netns_reaches_the_proxy_through_the_bridge() {
    if !ready("netns_reaches_the_proxy_through_the_bridge")
        || !tools("netns_reaches_the_proxy_through_the_bridge", &["curl"])
    {
        return;
    }
    let layout = layout("proxy");
    let (proxy, seen) = proxy_stand_in();
    let relay = HostRelay::start(proxy).expect("host relay");
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(vec![relay.bridge(proxy.port())]));
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port());
    let out = run(
        &sandbox,
        "curl",
        [
            "-sS",
            "--max-time",
            "20",
            "-x",
            proxy_url.as_str(),
            "http://api.e2e.apassy.test/ping",
        ],
    );
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert_eq!(out.stdout, "via-proxy");
    assert_eq!(
        seen.lock().expect("log").as_slice(),
        ["GET http://api.e2e.apassy.test/ping HTTP/1.1"]
    );
}

/// No route but the bridge: another listener on the host's 127.0.0.1, a public
/// address, and a direct `curl` fail; the bridged proxy port works in the same run.
#[test]
fn netns_reaches_only_the_bridged_port() {
    let test = "netns_reaches_only_the_bridged_port";
    if !ready(test) || !tools(test, &["bash", "curl", "timeout"]) {
        return;
    }
    let layout = layout("only-bridge");
    let (proxy, _seen) = proxy_stand_in();
    let relay = HostRelay::start(proxy).expect("host relay");
    let (other, other_port) = counting_listener();
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(vec![relay.bridge(proxy.port())]));
    let script = r#"
        proxy=$1; other=$2
        if curl -sS --max-time 10 -x "http://127.0.0.1:$proxy" http://api.e2e.apassy.test/x >/dev/null 2>&1; then echo "PROXY reached"; else echo "PROXY blocked"; fi
        if curl -sS --max-time 5 --noproxy '*' "http://127.0.0.1:$other/" >/dev/null 2>&1; then echo "CURL_OTHER reached"; else echo "CURL_OTHER blocked"; fi
        if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$other" 2>/dev/null; then echo "TCP_LOOPBACK reached"; else echo "TCP_LOOPBACK blocked"; fi
        if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then echo "TCP_PUBLIC reached"; else echo "TCP_PUBLIC blocked"; fi
        if timeout 5 curl -sS --max-time 4 --noproxy '*' https://1.1.1.1/ >/dev/null 2>&1; then echo "CURL_PUBLIC reached"; else echo "CURL_PUBLIC blocked"; fi
    "#;
    let ports = [proxy.port().to_string(), other_port.to_string()];
    let out = sh(&sandbox, script, &[ports[0].as_str(), ports[1].as_str()]);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    out.expect_line("PROXY reached");
    out.expect_line("CURL_OTHER blocked");
    out.expect_line("TCP_LOOPBACK blocked");
    out.expect_line("TCP_PUBLIC blocked");
    out.expect_line("CURL_PUBLIC blocked");
    assert!(
        accepted_nothing(&other),
        "a direct connection reached the host"
    );
    // Control: the same listener takes a connection from outside the sandbox.
    let _client = TcpStream::connect(("127.0.0.1", other_port)).expect("control connect");
    other.set_nonblocking(false).expect("blocking");
    other.accept().expect("the control connection");
}

/// No UDP: a datagram to the host's 127.0.0.1 never arrives, and a public address
/// has no route.
#[test]
fn netns_has_no_udp() {
    if !ready("netns_has_no_udp") || !tools("netns_has_no_udp", &["bash", "timeout"]) {
        return;
    }
    let layout = layout("udp");
    let udp = UdpSocket::bind("127.0.0.1:0").expect("udp");
    udp.set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("timeout");
    let port = udp.local_addr().expect("addr").port();
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    let script = r#"
        timeout 5 bash -c "echo canary > /dev/udp/127.0.0.1/$1" 2>/dev/null; echo "LOOPBACK_SENT $?"
        if timeout 5 bash -c 'echo canary > /dev/udp/1.1.1.1/53' 2>/dev/null; then echo "PUBLIC sent"; else echo "PUBLIC blocked"; fi
    "#;
    let port_text = port.to_string();
    let out = sh(&sandbox, script, &[port_text.as_str()]);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    out.expect_line("PUBLIC blocked");
    let mut buf = [0u8; 64];
    assert!(
        udp.recv_from(&mut buf).is_err(),
        "a datagram from the sandbox reached the host"
    );
    // Control: a datagram from outside arrives.
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
    sender
        .send_to(b"control", ("127.0.0.1", port))
        .expect("send");
    let (read, _) = udp.recv_from(&mut buf).expect("the control datagram");
    assert_eq!(&buf[..read], b"control");
}

/// An abstract Unix socket of the host (an old-style session bus, an X server)
/// belongs to the host's network namespace: the sandbox cannot reach it.
#[test]
fn netns_abstract_socket_of_the_host_is_unreachable() {
    let test = "netns_abstract_socket_of_the_host_is_unreachable";
    if !ready(test) || !tools(test, &["python3"]) {
        return;
    }
    let layout = layout("abstract");
    let name = format!("apassy-isolation-{}-{}", std::process::id(), unique());
    let addr = UnixSocketAddr::from_abstract_name(name.as_bytes()).expect("abstract name");
    let listener = UnixListener::bind_addr(&addr).expect("abstract listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let code = "import socket, sys\n\
                s = socket.socket(socket.AF_UNIX)\n\
                try:\n    s.connect(b'\\0' + sys.argv[1].encode())\n    print('ABSTRACT reached')\n\
                except OSError as e:\n    print('ABSTRACT blocked', e.errno)\n";
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    let out = run(&sandbox, "python3", ["-I", "-c", code, name.as_str()]);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    // ECONNREFUSED: no such name in the namespace of the sandbox.
    out.expect_line("ABSTRACT blocked 111");
    assert!(
        matches!(listener.accept(), Err(err) if err.kind() == ErrorKind::WouldBlock),
        "the abstract socket got a connection"
    );
    // Control: the same program outside reaches it.
    let control = Command::new("python3")
        .args(["-I", "-c", code, name.as_str()])
        .output()
        .expect("control python");
    assert_eq!(
        String::from_utf8_lossy(&control.stdout).trim(),
        "ABSTRACT reached"
    );
}

/// Stops the child at the end of a test.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The sandbox has its own PID namespace: a process outside (and its environment,
/// F11) is not there.
#[test]
fn netns_cannot_see_outside_processes() {
    if !ready("netns_cannot_see_outside_processes") {
        return;
    }
    let layout = layout("processes");
    let marker = format!("31{:05}.{}", std::process::id() % 100_000, unique());
    let outside = KillOnDrop(
        Command::new("sleep")
            .arg(&marker)
            .stdin(Stdio::null())
            .spawn()
            .expect("sleep"),
    );
    let pid = outside.0.id();
    // Control: the process and its arguments are visible outside.
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).expect("control cmdline");
    assert!(String::from_utf8_lossy(&cmdline).contains(&marker));
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    let script = r#"
        n=0
        for f in /proc/[0-9]*/cmdline; do
            n=$((n + 1))
            printf 'CMD '; tr '\0' ' ' < "$f"; echo
        done
        echo "COUNT $n"
        if [ -r "/proc/$1/environ" ]; then echo ENVIRON_READABLE; else echo NO_ENVIRON; fi
    "#;
    let pid_text = pid.to_string();
    let out = sh(&sandbox, script, &[pid_text.as_str()]);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(!out.stdout.contains(&marker), "{}", out.stdout);
    out.expect_line("NO_ENVIRON");
    let count: usize = out
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("COUNT "))
        .and_then(|count| count.trim().parse().ok())
        .expect("COUNT line");
    assert!(
        count <= 8,
        "the sandbox sees {count} processes:\n{}",
        out.stdout
    );
}

/// Wait until `path` has text, at most `limit`.
fn wait_for_text(path: &Path, limit: Duration) -> String {
    let deadline = Instant::now() + limit;
    loop {
        if let Ok(text) = fs::read_to_string(path)
            && !text.trim().is_empty()
        {
            return text;
        }
        assert!(Instant::now() < deadline, "{} has no text", path.display());
        thread::sleep(Duration::from_millis(50));
    }
}

/// `path` does not change for a while: nothing writes it any more.
#[track_caller]
fn assert_still(path: &Path) {
    thread::sleep(Duration::from_millis(700));
    let first = fs::read_to_string(path).expect("beat");
    thread::sleep(Duration::from_millis(900));
    let second = fs::read_to_string(path).expect("beat");
    assert_eq!(first, second, "a process of the run is still writing");
}

const BEAT: &str = r#"setsid sh -c 'while :; do date +%s%N > "$1"; sleep 0.1; done' beat "$1" >/dev/null 2>&1 </dev/null &"#;

/// When the program of the run ends, the run ends: a `setsid` grandchild that
/// would live on is stopped with it.
#[test]
fn netns_run_ends_with_its_descendants() {
    if !ready("netns_run_ends_with_its_descendants")
        || !tools("netns_run_ends_with_its_descendants", &["setsid", "date"])
    {
        return;
    }
    let layout = layout("descendants");
    let beat = layout.project.join("beat");
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    let script = format!("{BEAT}\nsleep 1\nexit 0");
    let started = Instant::now();
    let out = sh(&sandbox, &script, &[text(&beat)]);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the run waited for its grandchild"
    );
    // Control: the grandchild ran.
    wait_for_text(&beat, Duration::from_secs(1));
    assert_still(&beat);
}

/// A stop of the run (the caller kills bubblewrap) stops every process in it.
#[test]
fn stopping_the_sandbox_stops_every_process_in_it() {
    if !ready("stopping_the_sandbox_stops_every_process_in_it")
        || !tools(
            "stopping_the_sandbox_stops_every_process_in_it",
            &["setsid", "date"],
        )
    {
        return;
    }
    let layout = layout("stop");
    let beat = layout.project.join("beat");
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    let script = format!("{BEAT}\nexec sleep 120");
    let mut command = sandbox.command("sh", ["-c", script.as_str(), "sh", text(&beat)]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("start bubblewrap");
    wait_for_text(&beat, Duration::from_secs(20));
    child.kill().expect("stop the sandbox");
    child.wait().expect("wait");
    assert_still(&beat);
}

/// `--disable-userns`: the run cannot make a user namespace and remount its view.
#[test]
fn a_sandboxed_process_cannot_make_a_user_namespace() {
    if !ready("a_sandboxed_process_cannot_make_a_user_namespace")
        || !tools(
            "a_sandboxed_process_cannot_make_a_user_namespace",
            &["unshare"],
        )
    {
        return;
    }
    let layout = layout("userns");
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    let script = r#"
        if unshare -U true 2>/dev/null; then echo "USERNS made"; else echo "USERNS refused"; fi
        if unshare -Ur sh -c 'mount -t tmpfs none /tmp' 2>/dev/null; then echo "REMOUNT made"; else echo "REMOUNT refused"; fi
    "#;
    let out = sh(&sandbox, script, &[]);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    out.expect_line("USERNS refused");
    out.expect_line("REMOUNT refused");
    // Control, when this computer lets users make user namespaces.
    let outside = Command::new("unshare").args(["-U", "true"]).status();
    eprintln!("unshare -U outside the sandbox: {outside:?}");
}

/// The exit code of the program is the exit code of the sandbox; a missing program
/// is 127.
#[test]
fn the_exit_code_of_the_program_is_the_exit_code_of_the_sandbox() {
    if !ready("the_exit_code_of_the_program_is_the_exit_code_of_the_sandbox") {
        return;
    }
    let layout = layout("exit-code");
    let sandbox = run_sandbox(&layout, NetPlan::Bridged(Vec::new()));
    assert_eq!(sh(&sandbox, "exit 7", &[]).code, Some(7));
    let missing = run(&sandbox, "apassy-no-such-program", Vec::<&str>::new());
    assert_eq!(
        missing.code,
        Some(linux::EXIT_NOT_FOUND),
        "{}",
        missing.stderr
    );
}

/// The probe on this computer, for the log of the CI job: the measurement that the
/// s5 plan asks X1 to make first.
#[test]
fn the_probe_reports_the_network_rule_of_this_computer() {
    let found = linux::probe();
    let report = serde_json::to_string(&found.report()).expect("json");
    eprintln!("bubblewrap probe: {found:?}\nnetwork rule: {report}");
    if required() {
        assert!(found.is_ready(), "{found:?}");
        assert_eq!(found.report().rule, linux::RULE_NETNS);
    } else if !found.is_ready() {
        assert_eq!(found.report().rule, linux::RULE_NONE);
        assert!(found.report().fix.is_some());
    }
    // The scratch folder helper is used by every other test; keep it honest here.
    let scratch = Scratch::new("probe");
    let inner = scratch.0.clone();
    drop(scratch);
    assert!(!inner.exists());
}
