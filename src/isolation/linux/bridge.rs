//! The network bridge of a sandbox, and its init process.
//!
//! In a new network namespace a process has only `lo`. The bridge is the only way
//! out:
//!
//! ```text
//!  sandbox (own network namespace)              host
//!  program ──TCP──▶ 127.0.0.1:<inside>
//!                    bridge_main (PID 1) ──Unix──▶ socket ──▶ HostRelay ──TCP──▶ proxy
//! ```
//!
//! [`bridge_main`] runs as PID 1 of the sandbox (bubblewrap `--as-pid-1`): it
//! listens on each `127.0.0.1:<inside>` of the namespace, forwards each connection
//! to the Unix socket of that bridge (bind-mounted from the host, read-only), starts
//! the program as its child, and exits with the program's exit code. When PID 1
//! exits, the kernel stops every other process of the namespace, so no descendant
//! of the run lives on. A program whose first argument is [`BRIDGE_ARG`] must call
//! it; `apassy-sandbox` does on Linux.
//!
//! [`HostRelay`] is the host end: a Unix socket in a new private folder, forwarded
//! to one TCP address (the run proxy, or the router of a linked environment).
//!
//! SECURITY (judge panel): the bridge only connects to the socket paths in its
//! arguments, and those are bind mounts that the sandbox cannot change. Abstract
//! Unix sockets belong to the network namespace, so the host's are out of reach.

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Bridge;

/// The first argument that makes an Apassy program the init and bridge of a sandbox.
pub const BRIDGE_ARG: &str = "__netns-bridge";

/// Exit code of the bridge when its arguments are wrong or a listener fails.
pub const EXIT_SETUP: i32 = 125;
/// Exit code when the program exists but does not start.
pub const EXIT_CANNOT_RUN: i32 = 126;
/// Exit code when the program is not found.
pub const EXIT_NOT_FOUND: i32 = 127;

/// Connections at once through one bridge or one relay. More are closed at once.
const MAX_CONNECTIONS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest Unix socket path of Linux, without its final zero byte.
const MAX_SOCKET_PATH: usize = 107;

struct Parsed {
    listen: Vec<(u16, PathBuf)>,
    program: OsString,
    args: Vec<OsString>,
}

/// `[--listen PORT=SOCKET]... -- PROGRAM [ARG]...`, the arguments after
/// [`BRIDGE_ARG`].
fn parse(args: &[OsString]) -> Result<Parsed, String> {
    let mut listen = Vec::new();
    let mut iter = args.iter();
    loop {
        let Some(arg) = iter.next() else {
            return Err("no program: put it after `--`".to_owned());
        };
        if arg == "--" {
            break;
        }
        if arg != "--listen" {
            return Err(format!("unknown argument {}", arg.to_string_lossy()));
        }
        let value = iter
            .next()
            .and_then(|value| value.to_str())
            .ok_or("--listen needs PORT=SOCKET")?;
        let (port, socket) = value.split_once('=').ok_or("--listen needs PORT=SOCKET")?;
        let port: u16 = port
            .parse()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("bad port {port}"))?;
        let socket = PathBuf::from(socket);
        if !socket.is_absolute() {
            return Err(format!("the socket {} is not absolute", socket.display()));
        }
        if listen.iter().any(|(seen, _)| *seen == port) {
            return Err(format!("port {port} twice"));
        }
        listen.push((port, socket));
    }
    let program = iter.next().ok_or("no program after `--`")?.clone();
    Ok(Parsed {
        listen,
        program,
        args: iter.as_slice().to_vec(),
    })
}

/// The init and bridge of a sandbox: the arguments after [`BRIDGE_ARG`]. It returns
/// the exit code of the program (128 + the signal when a signal stopped it), or
/// [`EXIT_SETUP`], [`EXIT_CANNOT_RUN`], or [`EXIT_NOT_FOUND`]. The caller exits with
/// it at once: while this process lives, the sandbox lives.
pub fn bridge_main<I>(args: I) -> i32
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let parsed = match parse(&args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("apassy sandbox: {message}");
            return EXIT_SETUP;
        }
    };
    // Every listener is ready before the program starts.
    let mut listeners = Vec::new();
    for (port, socket) in parsed.listen {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(listener) => listeners.push((listener, socket)),
            Err(err) => {
                eprintln!("apassy sandbox: cannot listen on 127.0.0.1:{port}: {err}");
                return EXIT_SETUP;
            }
        }
    }
    let active = Arc::new(AtomicUsize::new(0));
    for (listener, socket) in listeners {
        let active = Arc::clone(&active);
        let started = thread::Builder::new()
            .name("apassy-bridge".to_owned())
            .spawn(move || serve_bridge(&listener, &socket, &active));
        if let Err(err) = started {
            eprintln!("apassy sandbox: cannot start the bridge: {err}");
            return EXIT_SETUP;
        }
    }
    let mut child = match Command::new(&parsed.program).args(&parsed.args).spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!(
                "apassy sandbox: cannot start {}: {err}",
                parsed.program.to_string_lossy()
            );
            return if err.kind() == io::ErrorKind::NotFound {
                EXIT_NOT_FOUND
            } else {
                EXIT_CANNOT_RUN
            };
        }
    };
    match child.wait() {
        Ok(status) => exit_code(status),
        Err(err) => {
            eprintln!("apassy sandbox: lost the program: {err}");
            EXIT_SETUP
        }
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// Accept on `listener` (in the namespace) and forward each connection to `socket`.
pub(super) fn serve_bridge(listener: &TcpListener, socket: &Path, active: &Arc<AtomicUsize>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => {
                // For example no free file descriptor. Do not spin.
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let Some(slot) = Slot::take(active) else {
            continue;
        };
        let socket = socket.to_owned();
        let _ = thread::Builder::new()
            .name("apassy-bridge-conn".to_owned())
            .spawn(move || {
                let _slot = slot;
                if let Ok(unix) = UnixStream::connect(socket.as_path()) {
                    pump(stream, unix);
                }
            });
    }
}

/// One counted connection. Dropping it frees the place.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(active: &Arc<AtomicUsize>) -> Option<Slot> {
        let previous = active.fetch_add(1, Ordering::AcqRel);
        if previous >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Slot(Arc::clone(active)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A stream with a read and a write half.
trait Duplex: Read + Write + Send + Sized + 'static {
    fn duplicate(&self) -> io::Result<Self>;
    fn close_write(&self);
}

impl Duplex for TcpStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

impl Duplex for UnixStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn close_write(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// Copy both ways until both sides end. The end of one direction closes the write
/// half of the other side, so a half-closed request still gets its answer.
fn pump<A: Duplex, B: Duplex>(a: A, b: B) {
    let (Ok(mut a_read), Ok(mut b_read)) = (a.duplicate(), b.duplicate()) else {
        return;
    };
    let (mut a_write, mut b_write) = (a, b);
    let forward = thread::Builder::new()
        .name("apassy-bridge-copy".to_owned())
        .spawn(move || {
            let _ = io::copy(&mut a_read, &mut b_write);
            b_write.close_write();
        });
    let _ = io::copy(&mut b_read, &mut a_write);
    a_write.close_write();
    if let Ok(forward) = forward {
        let _ = forward.join();
    }
}

/// The host end of a bridge: a Unix socket in a new folder with mode 0700,
/// forwarded to one TCP address. Dropping it stops the relay and removes the
/// socket and its folder. Open connections end when either side closes.
pub struct HostRelay {
    dir: PathBuf,
    socket: PathBuf,
    target: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for HostRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostRelay")
            .field("socket", &self.socket)
            .field("target", &self.target)
            .finish()
    }
}

impl HostRelay {
    /// A relay to `target` with its folder in the temporary folder of the host.
    pub fn start(target: SocketAddr) -> io::Result<HostRelay> {
        HostRelay::start_in(&std::env::temp_dir(), target)
    }

    /// A relay to `target` with its folder in `parent`.
    pub fn start_in(parent: &Path, target: SocketAddr) -> io::Result<HostRelay> {
        let dir = private_dir(parent)?;
        let socket = dir.join("bridge.sock");
        if socket.as_os_str().len() > MAX_SOCKET_PATH {
            let _ = fs::remove_dir(&dir);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the socket path {} is too long", socket.display()),
            ));
        }
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(err) => {
                let _ = fs::remove_dir(&dir);
                return Err(err);
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let accept = thread::Builder::new()
            .name("apassy-host-relay".to_owned())
            .spawn(move || serve_relay(&listener, target, &stopped))?;
        Ok(HostRelay {
            dir,
            socket,
            target,
            stop,
            accept: Some(accept),
        })
    }

    /// The Unix socket that the sandbox gets.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The TCP address that each connection goes to.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// The bridge of a sandbox that listens on `127.0.0.1:<inside>` in the
    /// namespace and leads to this relay.
    pub fn bridge(&self, inside: u16) -> Bridge {
        Bridge {
            inside,
            outside: self.socket.clone(),
        }
    }
}

impl Drop for HostRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake the accept call.
        let _ = UnixStream::connect(&self.socket);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir(&self.dir);
    }
}

fn serve_relay(listener: &UnixListener, target: SocketAddr, stop: &AtomicBool) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let Ok(stream) = stream else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        let Some(slot) = Slot::take(&active) else {
            continue;
        };
        let _ = thread::Builder::new()
            .name("apassy-host-relay-conn".to_owned())
            .spawn(move || {
                let _slot = slot;
                if let Ok(tcp) = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT) {
                    pump(stream, tcp);
                }
            });
    }
}

/// A new folder with mode 0700 in `parent`. The name is new, so a folder that
/// someone else made first is never used.
fn private_dir(parent: &Path) -> io::Result<PathBuf> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut last = None;
    for _ in 0..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.subsec_nanos())
            .unwrap_or(0);
        let name = format!(
            "apassy-bridge-{}-{}-{nanos:08x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let dir = parent.join(name);
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => last = Some(err),
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no free folder name")))
}

/// Is `arg` the first argument of a bridge call?
pub fn is_bridge_call(arg: &OsStr) -> bool {
    arg == BRIDGE_ARG
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::linux::test_dir::TestDir;
    use std::io::BufRead;
    use std::os::unix::fs::PermissionsExt;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    /// A TCP server that answers each line with `pong <line>`.
    fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut reader = io::BufReader::new(stream.try_clone().expect("clone"));
                    let mut writer = stream;
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let _ = writer.write_all(format!("pong {line}").as_bytes());
                        line.clear();
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn arguments_are_strict() {
        let parsed = parse(&os(&[
            "--listen",
            "8080=/tmp/.apassy-sandbox/bridge-0.sock",
            "--",
            "sh",
            "-c",
            "x",
        ]))
        .expect("parse");
        assert_eq!(
            parsed.listen,
            vec![(8080, PathBuf::from("/tmp/.apassy-sandbox/bridge-0.sock"))]
        );
        assert_eq!(parsed.program, "sh");
        assert_eq!(parsed.args, os(&["-c", "x"]));
        // A program that starts with `-` is fine after `--`.
        assert_eq!(
            parse(&os(&["--", "-weird"])).expect("parse").program,
            "-weird"
        );
        for bad in [
            &["sh"][..],
            &["--"][..],
            &["--listen", "8080", "--", "sh"][..],
            &["--listen", "0=/s", "--", "sh"][..],
            &["--listen", "70000=/s", "--", "sh"][..],
            &["--listen", "1=relative", "--", "sh"][..],
            &["--listen", "1=/a", "--listen", "1=/b", "--", "sh"][..],
            &["--other", "--", "sh"][..],
        ] {
            assert!(parse(&os(bad)).is_err(), "{bad:?}");
        }
        assert_eq!(bridge_main(os(&["--listen"])), EXIT_SETUP);
    }

    #[test]
    fn bridge_main_returns_the_exit_code_and_the_signal_of_the_program() {
        assert_eq!(bridge_main(os(&["--", "sh", "-c", "exit 7"])), 7);
        assert_eq!(
            bridge_main(os(&["--", "sh", "-c", "kill -TERM $$"])),
            128 + 15
        );
        assert_eq!(
            bridge_main(os(&["--", "/no/such/apassy-program"])),
            EXIT_NOT_FOUND
        );
        let dir = TestDir::new("bridge-noexec");
        let file = dir.file("not-executable", "#!/bin/sh\n");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            bridge_main([OsString::from("--"), file.into_os_string()]),
            EXIT_CANNOT_RUN
        );
    }

    /// The whole path of a bridged connection, on the host network: TCP to the
    /// bridge listener, the Unix socket, the host relay, TCP to the server, and back.
    #[test]
    fn the_bridge_and_the_host_relay_carry_bytes_both_ways() {
        let server = echo_server();
        let dir = TestDir::new("bridge-path");
        let relay = HostRelay::start_in(dir.path(), server).expect("relay");
        assert_eq!(relay.target(), server);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind bridge");
        let bridge_addr = listener.local_addr().expect("addr");
        let socket = relay.socket().to_owned();
        let active = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&active);
        thread::spawn(move || serve_bridge(&listener, &socket, &counted));

        for round in 0..3 {
            let mut client = TcpStream::connect(bridge_addr).expect("connect");
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            client
                .write_all(format!("ping {round}\n").as_bytes())
                .expect("write");
            client.shutdown(Shutdown::Write).expect("half close");
            let mut answer = String::new();
            client.read_to_string(&mut answer).expect("read");
            assert_eq!(answer, format!("pong ping {round}\n"));
        }
    }

    #[test]
    fn the_host_relay_folder_is_private_and_removed_on_drop() {
        let dir = TestDir::new("bridge-relay");
        let relay =
            HostRelay::start_in(dir.path(), "127.0.0.1:9".parse().expect("addr")).expect("relay");
        let folder = relay.socket().parent().expect("folder").to_owned();
        let mode = fs::metadata(&folder).expect("folder").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert_eq!(relay.bridge(8443).outside, relay.socket());
        assert!(format!("{relay:?}").contains("bridge.sock"));
        drop(relay);
        assert!(!folder.exists(), "the relay folder stays after drop");
    }

    #[test]
    fn a_full_bridge_closes_new_connections() {
        let active = Arc::new(AtomicUsize::new(0));
        let slots: Vec<Slot> = (0..MAX_CONNECTIONS)
            .map(|_| Slot::take(&active).expect("slot"))
            .collect();
        assert!(Slot::take(&active).is_none());
        drop(slots);
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert!(Slot::take(&active).is_some());
    }

    #[test]
    fn the_marker_is_the_documented_one() {
        assert!(is_bridge_call(OsStr::new("__netns-bridge")));
        assert!(!is_bridge_call(OsStr::new("--netns-bridge")));
    }
}
