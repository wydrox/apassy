//! The T0 spike of the embedded tailnet node (docs/design/spike-tsnet.md).
//!
//! Each mode prints one JSON object per line on stdout. An auth key is read from the
//! first line of stdin, never from an argument or the environment.
//!
//! ```text
//! serve      --dir D --hostname H [--port 8443] [--control-url U] [--ephemeral]
//!            [--log-file F|stderr] [--ready-file F] [--up-timeout S] [--no-auth-key]
//!            [--no-wait] [--check-loopback] [--max-conns N]
//!            Joins, listens on the port, and echoes each connection.
//! dial       --dir D --hostname H --to HOST:PORT [--control-url U] [--ephemeral]
//!            [--log-file F|stderr] [--up-timeout S] [--attempts N] [--no-auth-key]
//!            Joins, connects, sends a line, and checks the echo.
//! login-url  --dir D --hostname H [--control-url U] [--wait S]
//!            Starts without an auth key and reports whether status has AuthURL.
//! signals    [--dir D]   Signal dispositions before and after a node starts.
//! state      --dir D     The files of a state directory: names, sizes, modes, and the
//!                        keys of tailscaled.state (never a value).
//! idle       [--seconds N]   The Go runtime without a node, for the idle numbers.
//! crash      rust-panic|rust-stack-overflow|rust-segv|go-panic
//! info       What this build linked.
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apassy_tailnet::spike::{self, Disposition};
use apassy_tailnet::{APASSY_PORT, BUILD, LogTarget, Status, TailnetNode, TailnetOptions};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// A control URL where nothing listens: a node that starts but never connects.
const OFFLINE_CONTROL: &str = "http://127.0.0.1:1";

const BOOL_FLAGS: [&str; 4] = [
    "--ephemeral",
    "--no-auth-key",
    "--no-wait",
    "--check-loopback",
];

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => return fail(&error),
    };
    let result = match args.mode.as_str() {
        "serve" => serve(&args),
        "dial" => dial(&args),
        "login-url" => login_url(&args),
        "signals" => signals(&args),
        "state" => state(&args),
        "idle" => idle(&args),
        "crash" => crash(&args),
        "info" => {
            info();
            Ok(())
        }
        other => Err(format!(
            "unknown mode {other:?}; modes: serve, dial, login-url, signals, state, idle, crash, info"
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&error),
    }
}

fn fail(error: &str) -> ExitCode {
    emit(&json!({ "event": "error", "error": error }));
    eprintln!("apassy-tailnet-spike: {error}");
    ExitCode::FAILURE
}

/// One JSON line on stdout. A closed stdout is not an error of the spike.
fn emit(value: &Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

fn millis(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct Args {
    mode: String,
    positional: Vec<String>,
    flags: BTreeMap<String, Option<String>>,
}

impl Args {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mode = args.next().ok_or("no mode; try `info`")?;
        let mut positional = Vec::new();
        let mut flags = BTreeMap::new();
        while let Some(arg) = args.next() {
            if arg.starts_with("--") {
                if BOOL_FLAGS.contains(&arg.as_str()) {
                    flags.insert(arg, None);
                } else {
                    let value = args.next().ok_or_else(|| format!("{arg} needs a value"))?;
                    flags.insert(arg, Some(value));
                }
            } else {
                positional.push(arg);
            }
        }
        Ok(Self {
            mode,
            positional,
            flags,
        })
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.flags.get(name).and_then(|value| value.as_deref())
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.value(name)
            .ok_or_else(|| format!("{name} is required"))
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }

    fn number(&self, name: &str, default: u64) -> Result<u64, String> {
        match self.value(name) {
            Some(text) => text
                .parse()
                .map_err(|_| format!("{name} needs a whole number, not {text:?}")),
            None => Ok(default),
        }
    }
}

/// The first line of stdin, in memory that is erased on drop.
fn read_auth_key() -> Result<Zeroizing<String>, String> {
    let mut line = Zeroizing::new(String::with_capacity(512));
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| format!("cannot read the auth key from stdin: {error}"))?;
    let key = line.trim();
    if key.is_empty() {
        return Err(
            "no auth key on stdin (pass --no-auth-key for a node with state or a login URL)"
                .to_owned(),
        );
    }
    Ok(Zeroizing::new(key.to_owned()))
}

fn options(args: &Args, with_key: bool) -> Result<TailnetOptions, String> {
    let mut options = TailnetOptions::new(args.required("--dir")?, args.required("--hostname")?);
    options.control_url = args.value("--control-url").map(str::to_owned);
    options.ephemeral = args.flag("--ephemeral");
    options.log = match args.value("--log-file") {
        None => LogTarget::Discard,
        Some("stderr") => LogTarget::Stderr,
        Some(path) => LogTarget::File(PathBuf::from(path)),
    };
    options.up_timeout = Duration::from_secs(args.number("--up-timeout", 120)?);
    if with_key && !args.flag("--no-auth-key") {
        options.auth_key = Some(read_auth_key()?);
    }
    Ok(options)
}

fn status_json(status: &Status) -> Value {
    json!({
        "backend_state": status.backend_state,
        "ips": status.tailscale_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "dns_name": status.dns_name,
        "stable_id": status.stable_id,
        "tailnet": status.tailnet,
        "magic_dns_suffix": status.magic_dns_suffix,
        "health": status.health,
        "peers": status.peers,
        "version": status.version,
        "auth_url_present": status.auth_url.is_some(),
    })
}

fn write_atomic(path: &str, text: &str) -> Result<(), String> {
    let temporary = format!("{path}.tmp");
    fs::write(&temporary, text)
        .and_then(|()| fs::rename(&temporary, path))
        .map_err(|error| format!("cannot write {path}: {error}"))
}

fn serve(args: &Args) -> Result<(), String> {
    let port = u16::try_from(args.number("--port", u64::from(APASSY_PORT))?)
        .map_err(|_| "--port must be at most 65535".to_owned())?;
    let max_conns = args.number("--max-conns", 0)?;
    let options = options(args, true)?;
    let timeout = options.up_timeout;
    let started = Instant::now();
    let node = TailnetNode::new(&options).map_err(|error| error.to_string())?;
    drop(options);
    let event = if args.flag("--no-wait") {
        node.start().map_err(|error| error.to_string())?;
        "started"
    } else {
        node.wait_up(timeout).map_err(|error| error.to_string())?;
        "up"
    };
    let up_ms = millis(started);
    let listener = node.listen(port).map_err(|error| error.to_string())?;
    let status = node.status().map_err(|error| error.to_string())?;
    let ready = json!({
        "event": event,
        "ms": up_ms,
        "pid": std::process::id(),
        "port": port,
        "status": status_json(&status),
    });
    emit(&ready);
    if let Some(path) = args.value("--ready-file") {
        write_atomic(path, &ready.to_string())?;
    }
    if args.flag("--check-loopback") {
        check_loopback(&node, &status);
    }

    let mut served = 0u64;
    loop {
        let accepted = listener.accept().map_err(|error| error.to_string())?;
        let since = Instant::now();
        let peer = match node.whois(accepted.remote) {
            Ok(peer) => json!({
                "node": peer.node_name,
                "stable_id": peer.stable_id,
                "login": peer.login_name,
                "tags": peer.tags,
            }),
            Err(error) => json!({ "error": error.to_string() }),
        };
        emit(&json!({
            "event": "accepted",
            "remote": accepted.remote.to_string(),
            "whois_ms": millis(since),
            "peer": peer,
        }));
        match echo(accepted.stream) {
            Ok(bytes) => emit(&json!({ "event": "closed", "bytes": bytes })),
            // A peer that goes away mid-echo gives EPIPE here, not a SIGPIPE death.
            Err(error) => emit(&json!({ "event": "echo_error", "error": error.to_string() })),
        }
        served += 1;
        if max_conns > 0 && served >= max_conns {
            emit(&json!({ "event": "done", "served": served }));
            return Ok(());
        }
    }
}

fn echo(stream: UnixStream) -> io::Result<u64> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    let bytes = io::copy(&mut reader, &mut writer)?;
    writer.shutdown(Shutdown::Write)?;
    Ok(bytes)
}

fn check_loopback(node: &TailnetNode, status: &Status) {
    let own = status.tailscale_ips.first().copied();
    let result = node.loopback().map(|api| {
        let addr_is_loopback = api.addr().ip().is_loopback();
        let status = match api.status() {
            Ok(status) => json!({ "ok": true, "backend_state": status.backend_state }),
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        };
        let whois = match own.map(|ip| api.whois(ip)) {
            Some(Ok(peer)) => json!({ "ok": true, "node": peer.node_name }),
            Some(Err(error)) => json!({ "ok": false, "error": error.to_string() }),
            None => json!({ "ok": false, "error": "the node has no address yet" }),
        };
        json!({ "addr_is_loopback": addr_is_loopback, "status": status, "whois": whois })
    });
    let in_memory = match own.map(|ip| node.whois(ip)) {
        Some(Ok(peer)) => json!({ "ok": true, "node": peer.node_name }),
        Some(Err(error)) => json!({ "ok": false, "error": error.to_string() }),
        None => json!({ "ok": false, "error": "the node has no address yet" }),
    };
    match result {
        Ok(value) => {
            emit(&json!({ "event": "loopback", "loopback": value, "in_memory_whois": in_memory }))
        }
        Err(error) => emit(&json!({
            "event": "loopback",
            "error": error.to_string(),
            "in_memory_whois": in_memory,
        })),
    }
}

fn dial(args: &Args) -> Result<(), String> {
    let to = args.required("--to")?.to_owned();
    let attempts = args.number("--attempts", 20)?.max(1);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .unwrap_or_default();
    let message = format!("apassy-tailnet-spike round trip {nonce}\n");
    let options = options(args, true)?;
    let timeout = options.up_timeout;
    let started = Instant::now();
    let node = TailnetNode::new(&options).map_err(|error| error.to_string())?;
    drop(options);
    let status = node.wait_up(timeout).map_err(|error| error.to_string())?;
    emit(&json!({ "event": "up", "ms": millis(started), "status": status_json(&status) }));

    let mut last_error = String::new();
    for attempt in 1..=attempts {
        let since = Instant::now();
        match node
            .dial(&to)
            .map_err(|error| error.to_string())
            .and_then(|stream| round_trip(stream, &message).map_err(|error| error.to_string()))
        {
            Ok(echoed) if echoed == message => {
                emit(&json!({
                    "event": "round_trip",
                    "ok": true,
                    "to": to,
                    "attempt": attempt,
                    "ms": millis(since),
                    "bytes": message.len(),
                }));
                return Ok(());
            }
            Ok(echoed) => last_error = format!("the echo differs ({} bytes back)", echoed.len()),
            Err(error) => last_error = error,
        }
        emit(
            &json!({ "event": "dial_failed", "attempt": attempt, "ms": millis(since), "error": last_error }),
        );
        if attempt < attempts {
            thread::sleep(Duration::from_secs(3));
        }
    }
    Err(format!(
        "no round trip to {to} after {attempts} attempts: {last_error}"
    ))
}

fn round_trip(mut stream: UnixStream, message: &str) -> io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(message.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut echoed = String::new();
    stream.read_to_string(&mut echoed)?;
    Ok(echoed)
}

fn login_url(args: &Args) -> Result<(), String> {
    let options = options(args, false)?;
    let wait = Duration::from_secs(args.number("--wait", 30)?);
    let started = Instant::now();
    let node = TailnetNode::new(&options).map_err(|error| error.to_string())?;
    node.start().map_err(|error| error.to_string())?;
    loop {
        let status = node.status().map_err(|error| error.to_string())?;
        if let Some(url) = &status.auth_url {
            // The URL itself would let a reader add this node to their tailnet.
            let host = url
                .split_once("://")
                .map(|(_, rest)| rest.split('/').next().unwrap_or_default())
                .unwrap_or_default();
            emit(&json!({
                "event": "login_url",
                "present": true,
                "host": host,
                "ms": millis(started),
                "status": status_json(&status),
            }));
            return Ok(());
        }
        if started.elapsed() >= wait {
            emit(&json!({
                "event": "login_url",
                "present": false,
                "ms": millis(started),
                "status": status_json(&status),
            }));
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }
}

const SIGNALS: [(&str, i32); 19] = [
    ("SIGHUP", libc::SIGHUP),
    ("SIGINT", libc::SIGINT),
    ("SIGQUIT", libc::SIGQUIT),
    ("SIGILL", libc::SIGILL),
    ("SIGTRAP", libc::SIGTRAP),
    ("SIGABRT", libc::SIGABRT),
    ("SIGBUS", libc::SIGBUS),
    ("SIGFPE", libc::SIGFPE),
    ("SIGSEGV", libc::SIGSEGV),
    ("SIGPIPE", libc::SIGPIPE),
    ("SIGALRM", libc::SIGALRM),
    ("SIGTERM", libc::SIGTERM),
    ("SIGCHLD", libc::SIGCHLD),
    ("SIGURG", libc::SIGURG),
    ("SIGPROF", libc::SIGPROF),
    ("SIGUSR1", libc::SIGUSR1),
    ("SIGUSR2", libc::SIGUSR2),
    ("SIGXCPU", libc::SIGXCPU),
    ("SIGWINCH", libc::SIGWINCH),
];

fn dispositions() -> Value {
    SIGNALS
        .iter()
        .map(|(name, number)| match spike::disposition(*number) {
            Some((disposition, flags)) => {
                let disposition = match disposition {
                    Disposition::Default => "default",
                    Disposition::Ignore => "ignore",
                    Disposition::Handler => "handler",
                };
                json!({ "signal": name, "disposition": disposition, "flags": format!("{flags:#x}") })
            }
            None => json!({ "signal": name, "disposition": "unknown" }),
        })
        .collect()
}

fn scratch_dir(args: &Args, name: &str) -> PathBuf {
    args.value("--dir").map_or_else(
        || std::env::temp_dir().join(format!("apassy-tailnet-{name}-{}", std::process::id())),
        PathBuf::from,
    )
}

fn offline_node(dir: &Path, hostname: &str) -> Result<TailnetNode, String> {
    let mut options = TailnetOptions::new(dir, hostname);
    options.control_url = Some(OFFLINE_CONTROL.to_owned());
    TailnetNode::new(&options).map_err(|error| error.to_string())
}

fn signals(args: &Args) -> Result<(), String> {
    // The Go runtime of a c-archive installs its handlers in a global constructor,
    // before Rust's main: "before_node" already shows them.
    emit(&json!({ "event": "signals", "when": "before_node", "signals": dispositions() }));
    let dir = scratch_dir(args, "signals");
    {
        let node = offline_node(&dir, "apassy-spike-signals")?;
        node.start().map_err(|error| error.to_string())?;
        let _listener = node
            .listen(APASSY_PORT)
            .map_err(|error| error.to_string())?;
        thread::sleep(Duration::from_secs(2));
        emit(&json!({ "event": "signals", "when": "after_start", "signals": dispositions() }));

        // A write to a closed peer: EPIPE, or the process dies of SIGPIPE.
        let (ours, theirs) = UnixStream::pair().map_err(|error| error.to_string())?;
        drop(theirs);
        let write = (&ours).write_all(b"x");
        emit(&json!({
            "event": "sigpipe",
            "survived": true,
            "write_error": write.err().map(|error| error.to_string()),
        }));
        #[cfg(target_os = "linux")]
        emit(&json!({ "event": "proc_signal_masks", "lines": proc_signal_masks() }));
    }
    if args.value("--dir").is_none() {
        let _ = fs::remove_dir_all(&dir);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn proc_signal_masks() -> Vec<String> {
    fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            ["SigBlk:", "SigIgn:", "SigCgt:", "Threads:"]
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .map(str::to_owned)
        .collect()
}

fn state(args: &Args) -> Result<(), String> {
    let dir = PathBuf::from(args.required("--dir")?);
    let dir_mode = fs::metadata(&dir)
        .map(|meta| format!("{:o}", meta.permissions().mode() & 0o7777))
        .map_err(|error| format!("cannot read {}: {error}", dir.display()))?;
    let mut files = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .map_err(|error| format!("cannot list {}: {error}", dir.display()))?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        if let Ok(meta) = entry.metadata() {
            files.push(json!({
                "name": entry.file_name().to_string_lossy(),
                "dir": meta.is_dir(),
                "bytes": meta.len(),
                "mode": format!("{:o}", meta.permissions().mode() & 0o7777),
            }));
        }
    }
    // tailscaled.state: a JSON object of state keys to base64 values. Only the keys
    // and the value lengths are printed.
    let keys = fs::read_to_string(dir.join("tailscaled.state"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Map<String, Value>>(&text).ok())
        .map(|map| {
            map.iter()
                .map(|(key, value)| {
                    json!({
                        "key": key,
                        "value_chars": value.as_str().map_or(0, str::len),
                    })
                })
                .collect::<Vec<_>>()
        });
    emit(&json!({ "event": "state", "dir_mode": dir_mode, "files": files, "state_keys": keys }));
    Ok(())
}

fn idle(args: &Args) -> Result<(), String> {
    let seconds = args.number("--seconds", 0)?;
    emit(&json!({ "event": "idle", "pid": std::process::id(), "seconds": seconds }));
    if seconds == 0 {
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }
    thread::sleep(Duration::from_secs(seconds));
    Ok(())
}

#[allow(unconditional_recursion)]
fn overflow(depth: u64) -> u64 {
    let frame = std::hint::black_box([depth.to_le_bytes()[0]; 4096]);
    overflow(depth + 1).wrapping_add(u64::from(frame[0]))
}

fn crash(args: &Args) -> Result<(), String> {
    let kind = args
        .positional
        .first()
        .map(String::as_str)
        .ok_or("crash needs rust-panic, rust-stack-overflow, rust-segv, or go-panic")?;
    emit(&json!({ "event": "crash", "kind": kind, "pid": std::process::id() }));
    match kind {
        "rust-panic" => panic!("apassy-tailnet-spike: a deliberate Rust panic"),
        "rust-stack-overflow" => {
            let depth = overflow(0);
            Err(format!("the recursion returned at {depth}"))
        }
        "rust-segv" => spike::fault_in_rust(),
        "go-panic" => {
            let dir = scratch_dir(args, "go-panic");
            let node = offline_node(&dir, "apassy-spike-go-panic")?;
            spike::go_panic(&node);
            Err("the Go panic returned".to_owned())
        }
        other => Err(format!("unknown crash {other:?}")),
    }
}

fn info() {
    emit(&json!({
        "event": "info",
        "linked": BUILD.linked,
        "libtailscale_commit": BUILD.libtailscale_commit,
        "go_version": BUILD.go_version,
        "tailscale_version": BUILD.tailscale_version,
        "link_flags": BUILD.link_flags,
        "archive_source": BUILD.archive_source,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    }));
}
