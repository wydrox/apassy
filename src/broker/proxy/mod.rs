//! The proxy of one run (ADR 0011).
//!
//! A variable in placeholder mode puts a placeholder into the environment of the
//! process, not the real value. The broker starts this proxy for the run and points
//! the process at it (`HTTPS_PROXY` and the trust files). For a host of a secret,
//! the proxy ends the TLS connection with a certificate of the run authority, checks
//! each request, puts the real value into its auth position, and sends the request
//! on with a new TLS connection that it verifies itself. In the response, it puts
//! the placeholder back in place of a real value. Other hosts get a tunnel without
//! a look inside, or a refusal.
//!
//! On macOS, a Seatbelt rule lets the process connect only to the proxy port, so a
//! program that ignores `HTTPS_PROXY` has no network at all. A program that goes
//! around the proxy in any other way still holds only placeholders.
//!
//! The proxy listens on 127.0.0.1 with a password for the run. It serves only the
//! run, and it stops when the run ends. A same-user process that reads the
//! environment of the run (F11) can send requests through it while the run lasts.
//! It gets what the swap rules allow, each request is logged, and it never gets a
//! value.

mod ca;
mod http1;
mod swap;

pub use swap::mint_placeholder;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use serde::Serialize;
use zeroize::Zeroizing;

use self::http1::{
    BodyLen, BodyStop, Conn, Replacer, RequestHead, Scanner, copy_request_body, copy_response_body,
    parse_request_head, parse_response_head, request_body,
};
use self::swap::{Refusal, SwapSecret, swap_request};
use super::http::TlsClient;
use crate::native::base64;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(120);
/// The request log keeps this many entries for one run.
const MAX_EVENTS: usize = 200;
const MAX_PATH_CHARS: usize = 120;
/// A client may try this many times to send the proxy password.
const MAX_AUTH_TRIES: usize = 3;
/// The system trust stores that the bundle for the process starts with.
const SYSTEM_BUNDLES: [&str; 4] = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];
/// Variables that point a process at the proxy. Upper and lower case, because
/// tools read different ones.
const PROXY_VARIABLES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];
/// Variables that name a full trust bundle (system roots and the run authority).
const BUNDLE_VARIABLES: [&str; 4] = [
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

/// Names that the proxy sets in the environment of the run. A binding cannot use them.
pub const RESERVED_VARIABLES: [&str; 14] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

/// Where the real value of a secret may go: a host with its subdomains, on one port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    host: String,
    port: u16,
}

impl HostRule {
    /// `api.example.com` (port 443) or `api.example.com:8443`. Lowercase names only.
    /// The vault checks the stored hosts with the same rule.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let (host, port) = crate::vault::parse_placeholder_host(text)
            .ok_or("A host is a lowercase name such as api.example.com, with an optional port.")?;
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// True for the host itself and each subdomain, on the port of the rule.
    pub fn covers(&self, host: &str, port: u16) -> bool {
        port == self.port
            && (host == self.host
                || host
                    .strip_suffix(self.host.as_str())
                    .is_some_and(|head| head.ends_with('.')))
    }
}

impl std::fmt::Display for HostRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.port == 443 {
            f.write_str(&self.host)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// One secret of a run in placeholder mode. Debug is redacted.
pub struct ProxySecret {
    /// The variable name, for the log.
    pub name: String,
    pub placeholder: String,
    pub value: Zeroizing<String>,
    pub hosts: Vec<HostRule>,
}

impl std::fmt::Debug for ProxySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxySecret({}=[redacted])", self.name)
    }
}

/// What the proxy does with a host that no secret of the run is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OtherHosts {
    /// A tunnel without a look inside. The process has only placeholders there.
    #[default]
    Tunnel,
    /// A refusal. The run reaches only the hosts of its secrets.
    Refuse,
}

#[derive(Debug, Clone)]
pub struct ProxyOptions {
    /// Verifies the services. Tests add a test root.
    pub tls: TlsClient,
    pub other_hosts: OtherHosts,
    /// On macOS: let the process connect only to the proxy.
    pub enforce: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyOutcome {
    /// Sent with a real value.
    Swapped,
    /// Sent without a real value.
    Passed,
    /// Sent through a tunnel, without a look inside.
    Tunneled,
    /// Stopped by the proxy.
    Refused,
    /// The connection or the TLS handshake failed.
    Failed,
}

/// One request or connection of a run. It has no value and no placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyEvent {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub outcome: ProxyOutcome,
    /// The variables whose real value went into the request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ProxyEvent {
    fn new(host: &str, port: u16, outcome: ProxyOutcome) -> Self {
        Self {
            host: host.to_owned(),
            port,
            method: None,
            path: None,
            status: None,
            outcome,
            secrets: Vec::new(),
            reason: None,
        }
    }

    /// An entry for a request. A placeholder in the path shows as `[apassy:NAME]`.
    fn for_request(host: &str, port: u16, request: &RequestHead, secrets: &[ProxySecret]) -> Self {
        let mut path = request
            .target
            .split('?')
            .next()
            .unwrap_or_default()
            .to_owned();
        for secret in secrets {
            if path.contains(&secret.placeholder) {
                path = path.replace(&secret.placeholder, &format!("[apassy:{}]", secret.name));
            }
        }
        let path: String = path.chars().take(MAX_PATH_CHARS).collect();
        Self {
            method: Some(request.method.clone()),
            path: Some(path),
            ..Self::new(host, port, ProxyOutcome::Passed)
        }
    }

    fn with_reason(mut self, outcome: ProxyOutcome, reason: impl Into<String>) -> Self {
        self.outcome = outcome;
        self.reason = Some(reason.into());
        self
    }
}

/// What the process needs: environment variables and, on macOS, a Seatbelt profile.
/// The trust files live as long as this value.
pub struct RunNetwork {
    pub env: Vec<(String, String)>,
    pub sandbox_profile: Option<String>,
    pub ca_file: PathBuf,
    _dir: tempfile::TempDir,
}

struct Shared {
    secrets: Vec<ProxySecret>,
    ca: ca::RunCa,
    tls: TlsClient,
    other_hosts: OtherHosts,
    /// The expected `Proxy-Authorization` value.
    auth: Zeroizing<String>,
    stop: AtomicBool,
    events: Mutex<Vec<ProxyEvent>>,
    /// Open sockets, so the end of the run can close them.
    streams: Mutex<HashMap<u64, TcpStream>>,
    next_stream: AtomicU64,
}

/// Removes a socket from the open list when its connection ends.
struct Tracked<'a> {
    shared: &'a Shared,
    id: Option<u64>,
}

impl Drop for Tracked<'_> {
    fn drop(&mut self) {
        if let (Some(id), Ok(mut streams)) = (self.id, self.shared.streams.lock()) {
            streams.remove(&id);
        }
    }
}

impl Shared {
    fn record(&self, event: ProxyEvent) {
        if let Ok(mut events) = self.events.lock()
            && events.len() < MAX_EVENTS
        {
            events.push(event);
        }
    }

    fn track(&self, stream: &TcpStream) -> Tracked<'_> {
        let id = self.next_stream.fetch_add(1, Ordering::SeqCst);
        let tracked = match (stream.try_clone(), self.streams.lock()) {
            (Ok(clone), Ok(mut streams)) => {
                streams.insert(id, clone);
                Some(id)
            }
            _ => None,
        };
        Tracked {
            shared: self,
            id: tracked,
        }
    }

    fn authorized(&self, request: &RequestHead) -> bool {
        request
            .header("proxy-authorization")
            .is_some_and(|given| same_bytes(given.as_bytes(), self.auth.as_bytes()))
    }

    fn is_secret_host(&self, host: &str, port: u16) -> bool {
        self.secrets
            .iter()
            .any(|secret| secret.hosts.iter().any(|rule| rule.covers(host, port)))
    }

    fn name(&self, index: usize) -> &str {
        self.secrets
            .get(index)
            .map_or("a secret", |secret| secret.name.as_str())
    }

    fn refusal_text(&self, refusal: &Refusal, host: &str) -> String {
        match refusal {
            Refusal::WrongHost { index } => {
                let hosts: Vec<String> = self.secrets[*index]
                    .hosts
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                if hosts.is_empty() {
                    format!("{} has no host for its real value.", self.name(*index))
                } else {
                    format!(
                        "{} is only for {}. The request went to {host}.",
                        self.name(*index),
                        hosts.join(", ")
                    )
                }
            }
            Refusal::Misplaced { index, place } => format!(
                "The request has the placeholder of {} in {place}. Apassy puts a real value only into the Authorization header, a known API key header, or a known key parameter.",
                self.name(*index)
            ),
        }
    }
}

/// Compare without an early exit.
fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut raw = vec![0u8; bytes];
    getrandom::fill(&mut raw).map_err(|_| io::Error::other("no random source"))?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// A running proxy. [`RunProxy::finish`] stops it and returns the request log.
pub struct RunProxy {
    shared: Arc<Shared>,
    network: RunNetwork,
    addr: SocketAddr,
    accept: Option<JoinHandle<()>>,
}

impl RunProxy {
    pub fn start(secrets: Vec<ProxySecret>, options: ProxyOptions) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let mut hosts: Vec<String> = secrets
            .iter()
            .flat_map(|secret| secret.hosts.iter().map(|rule| rule.host.clone()))
            .collect();
        hosts.sort();
        hosts.dedup();
        let ca = ca::RunCa::new(&hosts)?;
        let token = Zeroizing::new(random_hex(16)?);
        let auth = Zeroizing::new(format!(
            "Basic {}",
            base64::encode(format!("apassy:{}", token.as_str()).as_bytes())
        ));
        let proxy_url = format!("http://apassy:{}@127.0.0.1:{}", token.as_str(), addr.port());
        let network = network_for(ca.cert_pem(), &proxy_url, addr.port(), options.enforce)?;
        let shared = Arc::new(Shared {
            secrets,
            ca,
            tls: options.tls,
            other_hosts: options.other_hosts,
            auth,
            stop: AtomicBool::new(false),
            events: Mutex::new(Vec::new()),
            streams: Mutex::new(HashMap::new()),
            next_stream: AtomicU64::new(0),
        });
        let accept_shared = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name("apassy-run-proxy".to_owned())
            .spawn(move || accept_loop(&listener, &accept_shared))?;
        Ok(Self {
            shared,
            network,
            addr,
            accept: Some(accept),
        })
    }

    pub fn network(&self) -> &RunNetwork {
        &self.network
    }

    /// Stop the proxy, close each connection, and return the request log.
    pub fn finish(mut self) -> Vec<ProxyEvent> {
        self.stop();
        self.shared
            .events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    fn stop(&mut self) {
        let Some(accept) = self.accept.take() else {
            return;
        };
        self.shared.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        let _ = accept.join();
        if let Ok(streams) = self.shared.streams.lock() {
            for stream in streams.values() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}

impl Drop for RunProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn network_for(ca_pem: &str, proxy_url: &str, port: u16, enforce: bool) -> io::Result<RunNetwork> {
    // tempfile makes the folder with mode 0700.
    let dir = tempfile::Builder::new().prefix("apassy-run-").tempdir()?;
    let ca_file = dir.path().join("apassy-run-ca.pem");
    std::fs::write(&ca_file, ca_pem)?;
    let mut bundle = SYSTEM_BUNDLES
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default();
    if !bundle.ends_with('\n') && !bundle.is_empty() {
        bundle.push('\n');
    }
    bundle.push_str(ca_pem);
    let bundle_file = dir.path().join("trust-bundle.pem");
    std::fs::write(&bundle_file, bundle)?;

    let mut env: Vec<(String, String)> = PROXY_VARIABLES
        .iter()
        .map(|name| ((*name).to_owned(), proxy_url.to_owned()))
        .collect();
    env.push(("NO_PROXY".to_owned(), String::new()));
    env.push(("no_proxy".to_owned(), String::new()));
    // Node 22.21 and later read HTTPS_PROXY only with this switch.
    env.push(("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()));
    env.push((
        "NODE_EXTRA_CA_CERTS".to_owned(),
        ca_file.display().to_string(),
    ));
    for name in BUNDLE_VARIABLES {
        env.push((name.to_owned(), bundle_file.display().to_string()));
    }
    Ok(RunNetwork {
        env,
        sandbox_profile: enforce.then(|| sandbox_profile(port)).flatten(),
        ca_file,
        _dir: dir,
    })
}

/// The Seatbelt profile of a proxied run: each outgoing connection, also to a Unix
/// socket and to another loopback port, is denied, except the one to the proxy.
#[cfg(target_os = "macos")]
fn sandbox_profile(port: u16) -> Option<String> {
    Some(format!(
        "(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip \"localhost:{port}\"))\n"
    ))
}

#[cfg(not(target_os = "macos"))]
fn sandbox_profile(_port: u16) -> Option<String> {
    None
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    for stream in listener.incoming() {
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else {
            continue;
        };
        let shared = Arc::clone(shared);
        let _ = thread::Builder::new()
            .name("apassy-run-proxy-conn".to_owned())
            .spawn(move || {
                let _tracked = shared.track(&stream);
                serve(&shared, stream);
            });
    }
}

fn set_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
}

/// A short answer from the proxy itself. It closes the connection.
fn respond(to: &mut impl Write, status: u16, text: &str, reason: &str, extra: &str) {
    let body = serde_json::json!({ "error": "apassy_proxy", "reason": reason }).to_string();
    let _ = write!(
        to,
        "HTTP/1.1 {status} {text}\r\nContent-Type: application/json\r\nX-Apassy-Proxy: refused\r\n{extra}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = to.flush();
}

fn serve(shared: &Arc<Shared>, stream: TcpStream) {
    set_timeouts(&stream);
    let mut conn = Conn::new(stream);
    for _ in 0..MAX_AUTH_TRIES {
        let Ok(Some(head)) = conn.read_head() else {
            return;
        };
        let request = match parse_request_head(&head) {
            Ok(request) => request,
            Err(reason) => {
                respond(&mut conn.inner, 400, "Bad Request", reason, "");
                return;
            }
        };
        if !shared.authorized(&request) {
            // A request without a body can wait on the same connection for the retry.
            let _ = write!(
                conn.inner,
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"apassy\"\r\nContent-Length: 0\r\n\r\n"
            );
            if request_body(&request) != Ok(BodyLen::None) {
                return;
            }
            continue;
        }
        if request.method.eq_ignore_ascii_case("CONNECT") {
            connect(shared, conn, &request);
        } else {
            plain(shared, conn, &request);
        }
        return;
    }
}

/// `host:port` of a CONNECT request. An IPv6 address is in brackets.
fn parse_authority(target: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        (host, port)
    } else {
        target.rsplit_once(':')?
    };
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    let host = host.to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':');
    valid.then_some((host, port))
}

fn open_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                set_timeouts(&stream);
                return Ok(stream);
            }
            Err(err) => last = err,
        }
    }
    Err(last)
}

fn connect(shared: &Arc<Shared>, mut conn: Conn<TcpStream>, request: &RequestHead) {
    let Some((host, port)) = parse_authority(&request.target) else {
        respond(
            &mut conn.inner,
            400,
            "Bad Request",
            "The CONNECT target is not valid.",
            "",
        );
        return;
    };
    if shared.is_secret_host(&host, port) {
        intercept(shared, conn, &host, port);
        return;
    }
    if shared.other_hosts == OtherHosts::Refuse {
        let reason = "This run reaches only the hosts of its secrets.";
        respond(&mut conn.inner, 403, "Forbidden", reason, "");
        shared.record(
            ProxyEvent::new(&host, port, ProxyOutcome::Refused)
                .with_reason(ProxyOutcome::Refused, reason),
        );
        return;
    }
    let upstream = match open_tcp(&host, port) {
        Ok(upstream) => upstream,
        Err(_) => {
            respond(
                &mut conn.inner,
                502,
                "Bad Gateway",
                "Apassy could not connect to the host.",
                "",
            );
            shared.record(
                ProxyEvent::new(&host, port, ProxyOutcome::Failed)
                    .with_reason(ProxyOutcome::Failed, "The connection to the host failed."),
            );
            return;
        }
    };
    if conn
        .inner
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
    {
        return;
    }
    shared.record(ProxyEvent::new(&host, port, ProxyOutcome::Tunneled));
    let (client, rest) = conn.into_parts();
    tunnel(shared, client, upstream, &rest);
}

/// Copy bytes both ways until one side closes.
fn tunnel(shared: &Shared, client: TcpStream, mut upstream: TcpStream, first: &[u8]) {
    let _tracked = shared.track(&upstream);
    if upstream.write_all(first).is_err() {
        return;
    }
    let (Ok(mut client_read), Ok(mut upstream_write)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let forward = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let mut client_write = client;
    let _ = io::copy(&mut upstream, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Both);
    let _ = forward.join();
}

/// A plain `http://` request. The proxy never puts a real value into one. For
/// another host it sends this request and then copies bytes until the end.
fn plain(shared: &Arc<Shared>, mut conn: Conn<TcpStream>, request: &RequestHead) {
    let Some(rest) = request.target.strip_prefix("http://") else {
        respond(
            &mut conn.inner,
            400,
            "Bad Request",
            "The proxy takes CONNECT and http:// requests only.",
            "",
        );
        return;
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let authority_with_port = if authority.contains(':') && !authority.ends_with(']') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let Some((host, port)) = parse_authority(&authority_with_port) else {
        respond(
            &mut conn.inner,
            400,
            "Bad Request",
            "The URL host is not valid.",
            "",
        );
        return;
    };
    let mut event = ProxyEvent::for_request(&host, port, request, &shared.secrets);
    if shared.is_secret_host(&host, port) || shared.other_hosts == OtherHosts::Refuse {
        let reason = if shared.is_secret_host(&host, port) {
            "Apassy does not send a real value over plain http://. Use https://."
        } else {
            "This run reaches only the hosts of its secrets."
        };
        respond(&mut conn.inner, 403, "Forbidden", reason, "");
        event = event.with_reason(ProxyOutcome::Refused, reason);
        shared.record(event);
        return;
    }
    let Ok(mut upstream) = open_tcp(&host, port) else {
        respond(
            &mut conn.inner,
            502,
            "Bad Gateway",
            "Apassy could not connect to the host.",
            "",
        );
        shared.record(event.with_reason(ProxyOutcome::Failed, "The connection failed."));
        return;
    };
    let mut head = format!("{} {path} HTTP/1.1\r\n", request.method);
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "proxy-authorization" | "proxy-connection" | "connection" | "keep-alive"
        ) {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    if upstream.write_all(head.as_bytes()).is_err() {
        return;
    }
    event.outcome = ProxyOutcome::Tunneled;
    shared.record(event);
    let (client, rest) = conn.into_parts();
    tunnel(shared, client, upstream, &rest);
}

/// A reader that gives some bytes first, then reads the stream.
struct Prefixed {
    first: Vec<u8>,
    inner: TcpStream,
}

impl Read for Prefixed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.first.is_empty() {
            return self.inner.read(buf);
        }
        let count = self.first.len().min(buf.len());
        buf[..count].copy_from_slice(&self.first[..count]);
        self.first.drain(..count);
        Ok(count)
    }
}

impl Write for Prefixed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

type ClientSide = StreamOwned<ServerConnection, Prefixed>;
type ServiceSide = StreamOwned<ClientConnection, TcpStream>;

fn open_service<'a>(
    shared: &'a Shared,
    host: &str,
    port: u16,
) -> io::Result<(Conn<ServiceSide>, Tracked<'a>)> {
    let tcp = open_tcp(host, port)?;
    let tracked = shared.track(&tcp);
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "host name"))?;
    let conn = ClientConnection::new(shared.tls.client_config(), name).map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, tcp);
    // Finish the handshake before any request byte. A failed check sends no value.
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok((Conn::new(stream), tracked))
}

/// The value of a `Host` header matches the CONNECT target.
fn host_header_matches(value: &str, host: &str, port: u16) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value == host || value == format!("{host}:{port}") || value == format!("[{host}]:{port}")
}

fn intercept(shared: &Arc<Shared>, mut conn: Conn<TcpStream>, host: &str, port: u16) {
    let config = match shared.ca.server_config(host) {
        Ok(config) => config,
        Err(_) => {
            respond(
                &mut conn.inner,
                500,
                "Internal Server Error",
                "Apassy could not make a certificate for the host.",
                "",
            );
            return;
        }
    };
    if conn
        .inner
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let (tcp, first) = conn.into_parts();
    let Ok(tls) = ServerConnection::new(config) else {
        return;
    };
    let mut stream = StreamOwned::new(tls, Prefixed { first, inner: tcp });
    while stream.conn.is_handshaking() {
        if stream.conn.complete_io(&mut stream.sock).is_err() {
            shared.record(ProxyEvent::new(host, port, ProxyOutcome::Failed).with_reason(
                ProxyOutcome::Failed,
                "The program did not accept the certificate of the Apassy run. It may not read the trust file of the run (Go programs on macOS and Windows read only the system store), or it pins the certificate of the service.",
            ));
            return;
        }
    }
    if stream
        .conn
        .server_name()
        .is_some_and(|name| !name.eq_ignore_ascii_case(host))
    {
        return;
    }
    let mut client = Conn::new(stream);
    serve_requests(shared, &mut client, host, port);
    client.inner.conn.send_close_notify();
    let _ = client.inner.flush();
}

fn serve_requests(shared: &Arc<Shared>, client: &mut Conn<ClientSide>, host: &str, port: u16) {
    let secrets: Vec<SwapSecret<'_>> = shared
        .secrets
        .iter()
        .map(|secret| SwapSecret {
            placeholder: &secret.placeholder,
            value: &secret.value,
            hosts: &secret.hosts,
        })
        .collect();
    let placeholders: Vec<&[u8]> = shared
        .secrets
        .iter()
        .map(|secret| secret.placeholder.as_bytes())
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = shared
        .secrets
        .iter()
        .map(|secret| (secret.value.as_bytes(), secret.placeholder.as_bytes()))
        .collect();
    let mut service: Option<(Conn<ServiceSide>, Tracked<'_>)> = None;

    loop {
        let Ok(Some(head)) = client.read_head() else {
            return;
        };
        let request = match parse_request_head(&head) {
            Ok(request) => request,
            Err(reason) => {
                respond(&mut client.inner, 400, "Bad Request", reason, "");
                return;
            }
        };
        let event = ProxyEvent::for_request(host, port, &request, &shared.secrets);
        let refuse = |client: &mut Conn<ClientSide>, status: u16, text: &str, reason: String| {
            respond(&mut client.inner, status, text, &reason, "");
            shared.record(event.clone().with_reason(ProxyOutcome::Refused, reason));
        };
        if request
            .header("host")
            .is_some_and(|value| !host_header_matches(value, host, port))
        {
            refuse(
                client,
                400,
                "Bad Request",
                "The Host header does not match the CONNECT host.".to_owned(),
            );
            return;
        }
        if request.header("upgrade").is_some() {
            refuse(
                client,
                501,
                "Not Implemented",
                "The run proxy does not support a protocol upgrade (WebSocket) yet.".to_owned(),
            );
            return;
        }
        let body = match request_body(&request) {
            Ok(body) => body,
            Err(reason) => {
                refuse(client, 400, "Bad Request", reason.to_owned());
                return;
            }
        };
        let swapped = match swap_request(&request, host, port, &secrets) {
            Ok(swapped) => swapped,
            Err(refusal) => {
                refuse(
                    client,
                    403,
                    "Forbidden",
                    shared.refusal_text(&refusal, host),
                );
                return;
            }
        };
        if request
            .header("expect")
            .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
            && client
                .inner
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .and_then(|()| client.inner.flush())
                .is_err()
        {
            return;
        }
        // A kept connection can be closed by the service while it waits. A request
        // without a body gets one more try on a new connection.
        let mut retry = service.is_some() && body == BodyLen::None;
        let (response, head_replaced) = loop {
            if service.is_none() {
                match open_service(shared, host, port) {
                    Ok(opened) => service = Some(opened),
                    Err(_) => {
                        respond(
                            &mut client.inner,
                            502,
                            "Bad Gateway",
                            "Apassy could not open a verified connection to the service.",
                            "",
                        );
                        shared.record(event.with_reason(
                            ProxyOutcome::Failed,
                            "The connection or the certificate check of the service failed. No value was sent.",
                        ));
                        return;
                    }
                }
            }
            let Some((upstream, _)) = service.as_mut() else {
                return;
            };
            let sent = upstream.inner.write_all(&swapped.head).is_ok();
            if sent {
                let mut scanner = Scanner::new(&placeholders);
                match copy_request_body(client, &mut upstream.inner, body, &mut scanner) {
                    Ok(()) => {}
                    Err(BodyStop::Placeholder(index)) => {
                        // The service gets an incomplete request and a closed connection.
                        let _ = upstream.inner.sock.shutdown(Shutdown::Both);
                        refuse(
                            client,
                            403,
                            "Forbidden",
                            format!(
                                "The request body has the placeholder of {}. Apassy does not put a real value into a request body, so the service would store or use the placeholder.",
                                shared.name(index)
                            ),
                        );
                        return;
                    }
                    Err(_) => return,
                }
            }
            let head = if sent && upstream.inner.flush().is_ok() {
                upstream.read_head().ok().flatten()
            } else {
                None
            };
            let Some(mut raw) = head else {
                service = None;
                if retry {
                    retry = false;
                    continue;
                }
                respond(
                    &mut client.inner,
                    502,
                    "Bad Gateway",
                    "The service closed the connection.",
                    "",
                );
                return;
            };
            retry = false;
            // Interim answers (1xx) go to the program. The final answer follows.
            let mut replaced = false;
            let final_head = loop {
                replaced |= Replacer::replace_all(&pairs, &mut raw);
                let Ok(parsed) = parse_response_head(&raw, &request.method) else {
                    respond(
                        &mut client.inner,
                        502,
                        "Bad Gateway",
                        "The service answer is not valid HTTP/1.1.",
                        "",
                    );
                    return;
                };
                if client.inner.write_all(&raw).is_err() {
                    return;
                }
                if !(100..200).contains(&parsed.status) || parsed.upgrade {
                    break parsed;
                }
                let Some((upstream, _)) = service.as_mut() else {
                    return;
                };
                let Ok(Some(next)) = upstream.read_head() else {
                    return;
                };
                raw = next;
            };
            break (final_head, replaced);
        };
        drop(swapped.head);
        if response.upgrade {
            return;
        }
        let Some((upstream, _)) = service.as_mut() else {
            return;
        };
        let mut replacer = Replacer::new(&pairs);
        let copied = copy_response_body(upstream, &mut client.inner, response.body, &mut replacer);
        let _ = client.inner.flush();
        let mut event = event;
        event.status = Some(response.status);
        event.secrets = swapped
            .used
            .iter()
            .map(|index| shared.name(*index).to_owned())
            .collect();
        event.outcome = if event.secrets.is_empty() {
            ProxyOutcome::Passed
        } else {
            ProxyOutcome::Swapped
        };
        if head_replaced || replacer.replaced {
            event.reason =
                Some("The answer had a real value. The program got the placeholder.".to_owned());
        } else if response.encoded {
            event.reason = Some(
                "The answer was compressed, so Apassy could not check it for a real value."
                    .to_owned(),
            );
        }
        shared.record(event);
        if copied.is_err() {
            return;
        }
        if response.close {
            service = None;
        }
        if response.close || request.wants_close() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rules_cover_subdomains_on_their_port() {
        let rule = HostRule::parse("example.com").expect("rule");
        assert!(rule.covers("example.com", 443));
        assert!(rule.covers("api.example.com", 443));
        assert!(!rule.covers("badexample.com", 443));
        assert!(!rule.covers("api.example.com", 8443));
        let rule = HostRule::parse("localhost:8443").expect("rule");
        assert!(rule.covers("localhost", 8443));
        assert_eq!(rule.to_string(), "localhost:8443");
        for bad in [
            "",
            "Example.com",
            "a..b",
            ".a",
            "a:0",
            "a:x",
            "a b",
            "https://a",
        ] {
            assert!(HostRule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_binding_cannot_use_a_proxy_variable() {
        for name in RESERVED_VARIABLES {
            assert!(
                crate::vault::checked_env_name(name).is_err(),
                "{name} must be reserved"
            );
        }
    }

    #[test]
    fn connect_targets() {
        assert_eq!(
            parse_authority("API.example.com:443"),
            Some(("api.example.com".to_owned(), 443))
        );
        assert_eq!(
            parse_authority("[::1]:8443"),
            Some(("::1".to_owned(), 8443))
        );
        assert_eq!(parse_authority("example.com"), None);
        assert_eq!(parse_authority("a/b:443"), None);
    }

    #[test]
    fn equal_bytes() {
        assert!(same_bytes(b"abc", b"abc"));
        assert!(!same_bytes(b"abc", b"abd"));
        assert!(!same_bytes(b"abc", b"ab"));
    }
}
