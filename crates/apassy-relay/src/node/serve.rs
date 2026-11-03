//! `apassy serve`: the node without a window (plan D8).
//!
//! The order of a start: the node directory (0700) and its control socket, the settings,
//! the master key, the tailnet addresses (it waits for Tailscale, so the service can
//! start before `tailscaled` is up), the node certificate, the relay
//! (`config::relay_config`, every listener on the loopback), then the TLS front on the
//! tailnet addresses (or, with `Route::ServeTcp`, on `127.0.0.1` with a Tailscale Serve
//! TCP forward), then `state.json`. A stop goes the other way: the front first, then the
//! Serve forward, then the relay (every session and run key gone), then the files.
//!
//! **Signals.** The relay crate forbids `unsafe`, and no safe API of the standard
//! library or of the crates in the lock installs a signal handler, so `serve` installs
//! none (the decision of plan L1). The clean stop is the control socket `serve.sock`
//! (mode 0600 in the 0700 node directory): `apassy serve --stop` sends `stop` and waits
//! until `serve` has stopped. The systemd unit runs it as `ExecStop=`, so `systemctl
//! --user stop` stops the front before the relay; the `SIGTERM` that systemd sends after
//! it finds no process. A bare `SIGTERM` or `SIGINT` ends the process at once with the
//! default action: the kernel closes every listener, and SQLite keeps the files
//! consistent; `state.json` is left behind and `status` sees that the socket is dead.

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use apassy::net::tailnet::{self, ServeTcp};
use apassy::net::tls_front::{FOLLOW_INTERVAL, FrontRoute};
use apassy::net::{Front, FrontError, FrontHandle, FrontOptions, NodeCertificate};
use apassy::node::backend::RunningNode;
use apassy::node::funnel::{self, SystemTailscale, TailscaleCli};
use serde::{Deserialize, Serialize};

use super::config::{
    self, CONTROL_SOCKET, FRONT_DIR, HeadlessOptions, NodeSettings, RELAY_DIR, Route, STATE_FILE,
    ensure_private_dir,
};
use super::{NodeCliError, PROGRAM, keys, node_dir, parse_options};
use crate::embedded::EmbeddedNode;

/// Debug builds only: with this variable set to `1`, `serve` uses `127.0.0.1` as its
/// tailnet address (no Tailscale), and the front binds and serves the loopback. Release
/// builds do not read it.
pub const TEST_LOOPBACK_ENV: &str = "APASSY_NODE_TEST_LOOPBACK";
/// How long `serve --stop` waits for the node to stop.
pub const STOP_WAIT: Duration = Duration::from_secs(15);
/// How often `serve` looks for Tailscale while it waits.
const TAILNET_POLL: Duration = Duration::from_secs(5);
const CONTROL_POLL: Duration = Duration::from_millis(100);
const WAIT_POLL: Duration = Duration::from_millis(200);

/// `state.json`: what the running `serve` tells `status`, `pair`, and `doctor`. Nothing
/// in it is secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeState {
    pub version: String,
    pub pid: u32,
    pub started_at: u64,
    /// The node origin, `https://<Tailscale IPv4>:<port>`.
    pub origin: String,
    /// The port of the origin.
    pub port: u16,
    /// The pin of the node certificate, b64u of its SHA-256.
    pub pin: String,
    pub route: Route,
    /// The addresses the front listens on now (at the start).
    pub bound: Vec<String>,
    /// The loopback address of the relay's tailnet listener: the front's target.
    pub tailnet_listen: String,
    /// The alternative destinations of node-pairing-v1 section 7: the MagicDNS name and
    /// the Tailscale IPv6 in brackets, without a port.
    pub alternatives: Vec<String>,
    /// The machine name of the certificate and the pairing link.
    pub name: String,
    pub push_gateway: Option<String>,
    /// `credential` or `file`.
    pub key_source: String,
}

impl ServeState {
    /// `state.json` of `dir`, or `None` when the node never started or stopped cleanly.
    pub fn load(dir: &Path) -> Result<Option<Self>, NodeCliError> {
        let path = dir.join(STATE_FILE);
        match config::read_small(&path)? {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| NodeCliError::failed(format!("{} is not valid.", path.display()))),
        }
    }

    /// The tailnet listener of the relay, on the loopback.
    pub fn tailnet_target(&self) -> Option<SocketAddr> {
        self.tailnet_listen
            .parse::<SocketAddr>()
            .ok()
            .filter(|addr| addr.ip().is_loopback())
    }
}

/// The tailnet of this machine now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tailnet {
    /// The host of the node origin.
    pub ipv4: Ipv4Addr,
    /// The addresses the front binds (`Route::Direct`): Tailscale addresses that an
    /// interface of this machine has. Empty for `Route::ServeTcp`.
    pub addresses: Vec<IpAddr>,
    /// The MagicDNS name, without the last dot.
    pub dns_name: Option<String>,
    /// The Tailscale IPv6 address, when the front can be reached on it.
    pub ipv6: Option<Ipv6Addr>,
}

impl Tailnet {
    /// The alternatives of a pairing link: the name, then the IPv6 address in brackets.
    pub fn alternatives(&self) -> Vec<String> {
        let mut list = Vec::new();
        if let Some(name) = &self.dns_name {
            list.push(name.clone());
        }
        if let Some(v6) = self.ipv6 {
            list.push(format!("[{v6}]"));
        }
        list
    }
}

/// The tailnet of this machine through `cli` (`tailscale status --json`), or why there
/// is none yet.
pub fn tailnet_now(cli: &dyn TailscaleCli, route: Route) -> Result<Tailnet, String> {
    let Some(output) = cli.run(&["status", "--json"]) else {
        return Err("Tailscale is not installed. Install it: curl -fsSL https://tailscale.com/install.sh | sh".to_owned());
    };
    let status = tailnet::parse_status(&output.stdout);
    if !status.running {
        let state = match funnel::parse_status(&output.stdout) {
            funnel::Tailscale::NotConnected { state } => state,
            _ => "not running".to_owned(),
        };
        return Err(format!(
            "Tailscale is not connected ({state}). Run `sudo tailscale up`."
        ));
    }
    let ipv4 = status
        .ipv4()
        .ok_or_else(|| "Tailscale gives this machine no IPv4 address.".to_owned())?;
    let dns_name = match funnel::parse_status(&output.stdout) {
        funnel::Tailscale::Connected { dns_name } => Some(dns_name),
        _ => None,
    };
    match route {
        Route::Direct => {
            let addresses = tailnet::addresses(&status, &tailnet::assigned(&status.ips));
            if !addresses.contains(&IpAddr::V4(ipv4)) {
                return Err(format!(
                    "No interface of this machine has the Tailscale address {ipv4} (userspace networking?). Use `{PROGRAM} up --route serve-tcp`."
                ));
            }
            let ipv6 = status
                .ipv6()
                .filter(|v6| addresses.contains(&IpAddr::V6(*v6)));
            Ok(Tailnet {
                ipv4,
                addresses,
                dns_name,
                ipv6,
            })
        }
        Route::ServeTcp => Ok(Tailnet {
            ipv4,
            addresses: Vec::new(),
            dns_name,
            ipv6: status.ipv6(),
        }),
    }
}

/// What `Serving::start` needs.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub node_dir: PathBuf,
    /// `$CREDENTIALS_DIRECTORY` of systemd, or `None`.
    pub credentials_dir: Option<PathBuf>,
    /// How long the start waits for a tailnet address; `None`: until a stop.
    pub wait_for_tailnet: Option<Duration>,
    /// Tests only: `127.0.0.1` stands in for the tailnet address (no Tailscale), and the
    /// front binds and serves the loopback.
    #[doc(hidden)]
    pub test_loopback: bool,
}

impl ServeOptions {
    pub fn new(node_dir: PathBuf) -> Self {
        Self {
            node_dir,
            credentials_dir: keys::credentials_dir(),
            wait_for_tailnet: None,
            test_loopback: false,
        }
    }
}

/// Asks a running `Serving` to stop, from any thread.
#[derive(Debug, Clone)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_stopping(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The control socket `serve.sock`: `stop` asks the node to stop and gets its answer
/// (the end of the stream) when the stop is done; `ping` answers `running`.
struct Control {
    path: PathBuf,
    done: Arc<AtomicBool>,
    waiting: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl Control {
    fn start(path: &Path, stop: StopHandle) -> Result<Self, NodeCliError> {
        claim_socket(path)?;
        let listener = UnixListener::bind(path).map_err(|_| {
            NodeCliError::failed(format!(
                "The control socket {} cannot be made.",
                path.display()
            ))
        })?;
        let ready = fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .and_then(|()| listener.set_nonblocking(true));
        if ready.is_err() {
            let _ = fs::remove_file(path);
            return Err(NodeCliError::failed("The control socket cannot be set up."));
        }
        let done = Arc::new(AtomicBool::new(false));
        let waiting = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let done = Arc::clone(&done);
            let waiting = Arc::clone(&waiting);
            thread::Builder::new()
                .name("apassy-node-control".to_owned())
                .spawn(move || {
                    while !done.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => answer(stream, &stop, &waiting),
                            Err(_) => thread::sleep(CONTROL_POLL),
                        }
                    }
                })
        };
        match thread {
            Ok(thread) => Ok(Self {
                path: path.to_owned(),
                done,
                waiting,
                thread: Some(thread),
            }),
            Err(_) => {
                let _ = fs::remove_file(path);
                Err(NodeCliError::failed("The control thread cannot start."))
            }
        }
    }

    /// Ends the control thread, removes the socket, and closes the streams of the
    /// callers of `stop`: they see the stop done.
    fn finish(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.path);
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.finish();
    }
}

fn answer(stream: UnixStream, stop: &StopHandle, waiting: &Mutex<Vec<UnixStream>>) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut line = String::new();
    if BufReader::new((&stream).take(64))
        .read_line(&mut line)
        .is_err()
    {
        return;
    }
    match line.trim() {
        "stop" => {
            let _ = (&stream).write_all(b"stopping\n");
            stop.stop();
            waiting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(stream);
        }
        "ping" => {
            let _ = (&stream).write_all(b"running\n");
        }
        _ => {
            let _ = (&stream).write_all(b"unknown\n");
        }
    }
}

/// Removes a control socket that no process serves. A live one means another `serve`
/// runs on this directory; any other file there is refused.
fn claim_socket(path: &Path) -> Result<(), NodeCliError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(NodeCliError::failed(format!(
                    "A node already runs on {}. Stop it with `{PROGRAM} serve --stop`.",
                    path.parent().unwrap_or(path).display()
                )));
            }
            fs::remove_file(path).map_err(|_| {
                NodeCliError::failed(format!(
                    "The old socket {} cannot be removed.",
                    path.display()
                ))
            })
        }
        Ok(_) => Err(NodeCliError::failed(format!(
            "{} is not a socket. Remove it.",
            path.display()
        ))),
        Err(_) => Ok(()),
    }
}

/// True when a `serve` answers on the control socket of `dir`.
pub fn is_running(dir: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(dir.join(CONTROL_SOCKET)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    if stream.write_all(b"ping\n").is_err() {
        return false;
    }
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).is_ok() && line.trim() == "running"
}

/// Asks the `serve` of `dir` to stop and waits until it has stopped, at most `wait`.
/// False when no `serve` runs there.
pub fn stop_running(dir: &Path, wait: Duration) -> Result<bool, NodeCliError> {
    let Ok(mut stream) = UnixStream::connect(dir.join(CONTROL_SOCKET)) else {
        return Ok(false);
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    if stream.write_all(b"stop\n").is_err() {
        return Ok(false);
    }
    let _ = stream.set_read_timeout(Some(wait));
    let mut rest = Vec::new();
    match stream.read_to_end(&mut rest) {
        Ok(_) => Ok(true),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Err(NodeCliError::node(format!(
                "The node did not stop within {} s.",
                wait.as_secs()
            )))
        }
        // The process ended while the stream was open.
        Err(_) => Ok(true),
    }
}

/// True when the relay's tailnet listener of `state` answers `GET /healthz` with 200,
/// over plain HTTP on the loopback (not through the front).
pub fn loopback_healthy(state: &ServeState, timeout: Duration) -> bool {
    let Some(target) = state.tailnet_target() else {
        return false;
    };
    let host = state
        .origin
        .strip_prefix("https://")
        .unwrap_or(&state.origin)
        .to_owned();
    let Ok(mut stream) = TcpStream::connect_timeout(&target, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).is_ok() && head.starts_with(b"HTTP/1.1 200")
}

fn front_error(error: &FrontError, port: u16) -> NodeCliError {
    match error {
        FrontError::Bind(_) => NodeCliError::failed(format!(
            "Port {port} is taken: {error}. `{PROGRAM} doctor` names the program. Choose another port with `{PROGRAM} up --port N` before the first pairing."
        )),
        other => NodeCliError::failed(format!("The TLS front did not start: {other}")),
    }
}

/// The running node without a window.
pub struct Serving {
    node: Option<EmbeddedNode>,
    front: Option<FrontHandle>,
    /// The Tailscale Serve TCP forward: the tailnet port and the local port.
    serve_tcp: Option<(u16, u16)>,
    control: Option<Control>,
    stop: StopHandle,
    state: ServeState,
    node_dir: PathBuf,
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serving")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Waits for the tailnet of this machine. `None`: a stop came first.
fn wait_for_tailnet(
    options: &ServeOptions,
    route: Route,
    stop: &StopHandle,
) -> Result<Option<Tailnet>, NodeCliError> {
    if options.test_loopback {
        return Ok(Some(Tailnet {
            ipv4: Ipv4Addr::LOCALHOST,
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            dns_name: None,
            ipv6: None,
        }));
    }
    let started = Instant::now();
    let mut told: Option<String> = None;
    loop {
        match tailnet_now(&SystemTailscale, route) {
            Ok(found) => {
                if told.is_some() {
                    eprintln!("{PROGRAM} serve: Tailscale is up.");
                }
                return Ok(Some(found));
            }
            Err(why) => {
                if options
                    .wait_for_tailnet
                    .is_some_and(|limit| started.elapsed() >= limit)
                {
                    return Err(NodeCliError::failed(why));
                }
                if told.as_deref() != Some(why.as_str()) {
                    eprintln!("{PROGRAM} serve: waiting for Tailscale: {why}");
                    told = Some(why);
                }
            }
        }
        let next = Instant::now() + TAILNET_POLL;
        while Instant::now() < next {
            if stop.is_stopping() {
                return Ok(None);
            }
            thread::sleep(WAIT_POLL);
        }
    }
}

impl Serving {
    /// Starts the node in `options.node_dir`. `Ok(None)`: a stop came while it waited for
    /// Tailscale.
    pub fn start(options: ServeOptions) -> Result<Option<Self>, NodeCliError> {
        let dir = options.node_dir.clone();
        ensure_private_dir(&dir)?;
        let stop = StopHandle(Arc::new(AtomicBool::new(false)));
        // First, so that `serve --stop` works while the node waits for Tailscale.
        let mut control = Control::start(&dir.join(CONTROL_SOCKET), stop.clone())?;
        let mut settings = NodeSettings::load(&dir)?;
        let (key, key_source) = keys::load(&dir, options.credentials_dir.as_deref(), true)?;
        let Some(found) = wait_for_tailnet(&options, settings.route, &stop)? else {
            control.finish();
            return Ok(None);
        };
        let port = settings.port;
        let origin = config::node_origin(found.ipv4, port);
        if let Some(last) = settings.last_origin.as_deref()
            && last != origin
        {
            eprintln!(
                "{PROGRAM} serve: the node origin changed from {last} to {origin}. Every device must pair again: run `{PROGRAM} pair`."
            );
        }
        if settings.last_origin.as_deref() != Some(origin.as_str()) {
            settings.last_origin = Some(origin.clone());
            settings.save(&dir)?;
        }
        let name = apassy::sync::device_name();
        let certificate =
            NodeCertificate::load_or_make(&dir.join(FRONT_DIR), key.expose().as_bytes(), &name)
                .map_err(|error| {
                    NodeCliError::failed(format!("The node certificate cannot be loaded: {error}"))
                })?;
        let pin = certificate.pin;
        let relay_dir = dir.join(RELAY_DIR);
        ensure_private_dir(&relay_dir)?;
        let headless = HeadlessOptions {
            node_origin: origin.clone(),
            tailnet_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            push_gateway: settings.push_gateway.clone(),
            port,
        };
        let relay = config::relay_config(relay_dir, key, &headless)
            .map_err(|error| NodeCliError::failed(error.message))?;
        let node = EmbeddedNode::start(relay).map_err(|error| {
            NodeCliError::failed(format!(
                "The relay of the node did not start: {}",
                error.message
            ))
        })?;
        let stop_node = |node: EmbeddedNode| Box::new(node).stop();
        let tailnet_addr = node.running().tailnet_addr;
        let Some(target) = tailnet_addr else {
            stop_node(node);
            return Err(NodeCliError::failed(
                "The relay of the node has no tailnet listener.",
            ));
        };
        let mut front_options =
            FrontOptions::new(found.addresses.clone(), port, certificate, target);
        if settings.route == Route::ServeTcp {
            // The front on 127.0.0.1:<port>; Serve listens on the tailnet addresses.
            front_options.route = FrontRoute::ServeTcp;
        }
        if options.test_loopback {
            front_options.allow_loopback_bind = true;
            front_options.allow_test_peers = true;
        }
        let mut front = match Front::start(front_options) {
            Ok(front) => front,
            Err(error) => {
                stop_node(node);
                return Err(front_error(&error, port));
            }
        };
        let mut serve_tcp = None;
        match settings.route {
            Route::Direct if !options.test_loopback => {
                if front
                    .follow(tailnet::system_addresses, FOLLOW_INTERVAL)
                    .is_err()
                {
                    eprintln!(
                        "{PROGRAM} serve: the front does not follow address changes; restart the service after Tailscale changes."
                    );
                }
            }
            Route::Direct => {}
            Route::ServeTcp => {
                let local_port = front.bound().first().map_or(0, SocketAddr::port);
                let serve = ServeTcp::new(Arc::new(SystemTailscale));
                if let Err(error) = serve.enable(port, local_port) {
                    front.stop();
                    stop_node(node);
                    return Err(NodeCliError::failed(format!(
                        "Tailscale Serve did not forward port {port}: {error} If Tailscale needs root for this, run `sudo tailscale set --operator=$USER` once."
                    )));
                }
                serve_tcp = Some((port, local_port));
            }
        }
        let alternatives = found.alternatives();
        let state = ServeState {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            pid: std::process::id(),
            started_at: crate::now_unix(),
            origin: origin.clone(),
            port,
            pin: pin.text(),
            route: settings.route,
            bound: front.bound().iter().map(ToString::to_string).collect(),
            tailnet_listen: target.to_string(),
            alternatives,
            name,
            push_gateway: settings.push_gateway.clone(),
            key_source: key_source.label().to_owned(),
        };
        let mut serving = Self {
            node: Some(node),
            front: Some(front),
            serve_tcp,
            control: Some(control),
            stop,
            state,
            node_dir: dir,
        };
        let state_path = serving.node_dir.join(STATE_FILE);
        let written = serde_json::to_vec_pretty(&serving.state)
            .map_err(|_| NodeCliError::failed("The node state cannot be written."))
            .and_then(|text| config::write_private(&state_path, &text));
        if let Err(error) = written {
            serving.shutdown();
            return Err(error);
        }
        eprintln!(
            "{PROGRAM} serve: the node is on {origin} ({}). Pin: {}.",
            serving.state.bound.join(", "),
            serving.state.pin
        );
        Ok(Some(serving))
    }

    /// What `state.json` says.
    pub fn state(&self) -> &ServeState {
        &self.state
    }

    /// A handle that stops `wait`.
    pub fn stop_handle(&self) -> StopHandle {
        self.stop.clone()
    }

    /// Blocks until a stop comes (the control socket or a `StopHandle`).
    pub fn wait(&self) {
        while !self.stop.is_stopping() {
            thread::sleep(WAIT_POLL);
        }
    }

    /// Stops the front, the Serve forward, the relay, and removes `state.json` and the
    /// control socket. A caller of `serve --stop` sees its stream end after this.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(mut front) = self.front.take() {
            front.stop();
        }
        if let Some((port, local_port)) = self.serve_tcp.take()
            && let Err(error) = ServeTcp::new(Arc::new(SystemTailscale)).disable(port, local_port)
        {
            eprintln!("{PROGRAM} serve: the Tailscale Serve forward stays on: {error}");
        }
        if let Some(node) = self.node.take() {
            Box::new(node).stop();
        }
        let _ = fs::remove_file(self.node_dir.join(STATE_FILE));
        if let Some(mut control) = self.control.take() {
            control.finish();
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(debug_assertions)]
fn test_loopback_from_env() -> bool {
    std::env::var_os(TEST_LOOPBACK_ENV).is_some_and(|value| value == "1")
}

#[cfg(not(debug_assertions))]
fn test_loopback_from_env() -> bool {
    false
}

/// Runs the node until a stop, then stops it.
pub fn run(options: ServeOptions) -> Result<i32, NodeCliError> {
    let Some(serving) = Serving::start(options)? else {
        eprintln!("{PROGRAM} serve: stopped before the node started.");
        return Ok(0);
    };
    serving.wait();
    serving.stop();
    eprintln!("{PROGRAM} serve: stopped.");
    Ok(0)
}

/// `apassy serve [--stop] [--data-dir DIR]`.
pub fn command(args: &[String]) -> Result<i32, NodeCliError> {
    let options = parse_options(args, &[], &["stop"])?;
    if options.json {
        return Err(NodeCliError::usage(format!(
            "serve has no --json. Use `{PROGRAM} status --json`."
        )));
    }
    let dir = node_dir(&options)?;
    if options.flag("stop") {
        if stop_running(&dir, STOP_WAIT)? {
            eprintln!("{PROGRAM}: the node stopped.");
        } else {
            eprintln!("{PROGRAM}: the node is not running.");
        }
        return Ok(0);
    }
    let mut serve = ServeOptions::new(dir);
    serve.test_loopback = test_loopback_from_env();
    run(serve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apassy::node::funnel::CliOutput;

    struct FakeTailscale(Option<String>);

    impl TailscaleCli for FakeTailscale {
        fn run(&self, _args: &[&str]) -> Option<CliOutput> {
            self.0.as_ref().map(|stdout| CliOutput {
                success: true,
                stdout: stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn no_tailscale_or_a_stopped_one_gives_the_next_step() {
        let missing = tailnet_now(&FakeTailscale(None), Route::Direct).unwrap_err();
        assert!(missing.contains("install.sh"), "{missing}");
        let login = FakeTailscale(Some(
            r#"{"BackendState":"NeedsLogin","Self":{"DNSName":""}}"#.to_owned(),
        ));
        let stopped = tailnet_now(&login, Route::Direct).unwrap_err();
        assert!(stopped.contains("sudo tailscale up"), "{stopped}");
        assert!(stopped.contains("NeedsLogin"), "{stopped}");
    }

    #[test]
    fn serve_tcp_takes_the_addresses_of_the_status() {
        let status = FakeTailscale(Some(
            r#"{"BackendState":"Running","Self":{"DNSName":"build-box.tail0123.ts.net.","TailscaleIPs":["100.64.0.7","fd7a:115c:a1e0::7"]}}"#
                .to_owned(),
        ));
        let found = tailnet_now(&status, Route::ServeTcp).unwrap();
        assert_eq!(found.ipv4, Ipv4Addr::new(100, 64, 0, 7));
        assert!(found.addresses.is_empty());
        assert_eq!(
            found.alternatives(),
            vec![
                "build-box.tail0123.ts.net".to_owned(),
                "[fd7a:115c:a1e0::7]".to_owned()
            ]
        );
        // No interface of the test machine has 100.64.0.7: the direct route says so.
        let direct = tailnet_now(&status, Route::Direct).unwrap_err();
        assert!(direct.contains("serve-tcp"), "{direct}");
    }

    #[test]
    fn a_live_control_socket_refuses_a_second_serve() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONTROL_SOCKET);
        let stop = StopHandle(Arc::new(AtomicBool::new(false)));
        let mut control = Control::start(&path, stop.clone()).unwrap();
        assert!(is_running(dir.path()));
        assert!(Control::start(&path, stop.clone()).is_err());
        control.finish();
        assert!(!path.exists());
        assert!(!is_running(dir.path()));
        // A stale socket file is taken over.
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        let mut again = Control::start(&path, stop).unwrap();
        again.finish();
    }

    #[test]
    fn stop_over_the_control_socket_waits_for_the_finish() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONTROL_SOCKET);
        let stop = StopHandle(Arc::new(AtomicBool::new(false)));
        let mut control = Control::start(&path, stop.clone()).unwrap();
        let caller = {
            let dir = dir.path().to_owned();
            thread::spawn(move || stop_running(&dir, Duration::from_secs(10)))
        };
        let started = Instant::now();
        while !stop.is_stopping() {
            assert!(started.elapsed() < Duration::from_secs(5), "no stop came");
            thread::sleep(Duration::from_millis(20));
        }
        // The caller still waits: the stop is not done.
        thread::sleep(Duration::from_millis(200));
        assert!(!caller.is_finished());
        control.finish();
        assert!(caller.join().unwrap().unwrap());
        assert!(!stop_running(dir.path(), Duration::from_secs(1)).unwrap());
    }
}
