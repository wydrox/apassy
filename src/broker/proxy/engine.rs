//! The engine of a run proxy (ADR 0011): the swap rules of one set of secrets,
//! served on connections that a listener hands over.
//!
//! [`ProxyCore`] does not listen. The listener of a local run
//! ([`super::RunProxy`]) accepts on 127.0.0.1 and gives each connection to
//! [`ProxyCore::serve_connection`]. Another front (the forward front of a linked
//! environment, ADR 0037 stage 5) can read the first request head itself, check
//! the password, and hand the connection over with that head as `preread` and
//! [`Auth::Checked`].
//!
//! For a host of a secret, the engine ends the TLS connection with a certificate
//! of the run authority, checks each request, puts the real value into its auth
//! position, and sends the request on with a new TLS connection that it verifies
//! itself. In the response, it puts the placeholder back in place of a real value.
//! Other hosts get a tunnel without a look inside, or a refusal.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use zeroize::Zeroizing;

use super::ca::{self, Alpn};
use super::http1::{
    BodyLen, BodyStop, Conn, Replacer, RequestHead, Scanner, copy_request_body, copy_response_body,
    parse_request_head, parse_response_head, request_body,
};
use super::public_addr::is_public_ip;
use super::swap::{Refusal, SwapSecret, swap_request};
use super::{OtherHosts, ProxyEvent, ProxyOutcome, ProxySecret};
use crate::broker::access_once::Admission;
use crate::broker::http::TlsClient;
use crate::native::base64;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(120);
/// The request log keeps this many entries for one run.
const MAX_EVENTS: usize = 200;
/// A client may try this many times to send the proxy password.
const MAX_AUTH_TRIES: usize = 3;
/// The user name of the proxy password.
const PROXY_USER: &str = "apassy";

/// Gets each event of the engine as it is recorded, also after the request log is
/// full. It runs on the thread of the connection; it must not block for long.
pub type EventSink = Arc<dyn Fn(&ProxyEvent) + Send + Sync>;

/// Which upstream addresses the engine connects to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum UpstreamPolicy {
    /// Every address that the name resolves to, also on the LAN and the loopback.
    /// Local runs: the process could reach them without the proxy, too.
    #[default]
    Any,
    /// Public addresses only (`is_public_ip`): no loopback, private, CGNAT (the
    /// tailnet), link-local, or unique-local address. For a proxy that serves
    /// another machine, so that it cannot reach the network of this one.
    PublicOnly {
        /// A host name in this list connects to its address as given, whatever
        /// the port of the request, and skips the public check. Tests only, as the
        /// relay's `UpstreamOptions::resolve`.
        fixed: Vec<(String, SocketAddr)>,
    },
}

impl UpstreamPolicy {
    /// The addresses that the engine may connect to for `host:port`.
    fn addresses(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let found = match self {
            Self::Any => return Ok((host, port).to_socket_addrs()?.collect()),
            Self::PublicOnly { fixed } => {
                if let Some((_, addr)) = fixed.iter().find(|(name, _)| name == host) {
                    return Ok(vec![*addr]);
                }
                (host, port).to_socket_addrs()?
            }
        };
        let allowed: Vec<SocketAddr> = found.filter(|addr| is_public_ip(addr.ip())).collect();
        if allowed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no public address",
            ));
        }
        Ok(allowed)
    }
}

/// How the engine checks a connection before it serves the first request.
pub enum Auth {
    /// The first request must carry `Proxy-Authorization: Basic` with the user
    /// `apassy` and this password. A client may try three times.
    Password(Zeroizing<String>),
    /// The front checked the client already. The engine serves the first request
    /// without a `Proxy-Authorization` check.
    Checked,
}

impl Auth {
    /// The expected `Proxy-Authorization` value, or `None` for a checked client.
    fn expected_header(&self) -> Option<Zeroizing<String>> {
        match self {
            Self::Password(password) => Some(Zeroizing::new(format!(
                "Basic {}",
                base64::encode(format!("{PROXY_USER}:{}", password.as_str()).as_bytes())
            ))),
            Self::Checked => None,
        }
    }
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Auth::Password([redacted])"),
            Self::Checked => f.write_str("Auth::Checked"),
        }
    }
}

/// The settings of one engine.
#[derive(Clone)]
pub struct CoreOptions {
    /// Verifies the services. Tests add a test root.
    pub tls: TlsClient,
    pub other_hosts: OtherHosts,
    pub upstream: UpstreamPolicy,
    /// Gets each event, for an audit log.
    pub sink: Option<EventSink>,
    /// The protocols offered to the program for a host of a secret.
    pub alpn: Alpn,
}

impl CoreOptions {
    /// The settings of a local run: tunnels to other hosts, any upstream address,
    /// no sink, HTTP/1.1.
    pub fn new(tls: TlsClient) -> Self {
        Self {
            tls,
            other_hosts: OtherHosts::Tunnel,
            upstream: UpstreamPolicy::Any,
            sink: None,
            alpn: Alpn::Http11,
        }
    }
}

impl std::fmt::Debug for CoreOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreOptions")
            .field("tls", &self.tls)
            .field("other_hosts", &self.other_hosts)
            .field("upstream", &self.upstream)
            .field("sink", &self.sink.is_some())
            .field("alpn", &self.alpn)
            .finish()
    }
}

/// The engine of one set of secrets: the run authority, the swap rules, the
/// request log, and the open connections. It holds the real values; it is dropped
/// with the last connection and the owner of the `Arc`.
pub struct ProxyCore {
    access: Option<Admission>,
    omit_event_details: bool,
    secrets: Vec<ProxySecret>,
    /// The host names of the secrets, sorted, without duplicates.
    hosts: Vec<String>,
    ca: ca::RunCa,
    tls: TlsClient,
    other_hosts: OtherHosts,
    upstream: UpstreamPolicy,
    sink: Option<EventSink>,
    alpn: Alpn,
    closed: AtomicBool,
    events: Mutex<Vec<ProxyEvent>>,
    /// Open sockets, so the end of the run can close them.
    streams: Mutex<HashMap<u64, TcpStream>>,
    next_stream: AtomicU64,
}

/// Removes a socket from the open list when its connection ends.
struct Tracked<'a> {
    proxy: &'a ProxyCore,
    id: Option<u64>,
}

impl Drop for Tracked<'_> {
    fn drop(&mut self) {
        if let (Some(id), Ok(mut streams)) = (self.id, self.proxy.streams.lock()) {
            streams.remove(&id);
        }
    }
}

impl ProxyCore {
    /// A new engine with a new run authority for the hosts of `secrets`.
    pub fn new(secrets: Vec<ProxySecret>, options: CoreOptions) -> io::Result<Arc<Self>> {
        Self::with_access(secrets, options, None, false)
    }

    /// As [`ProxyCore::new`], for a local run with a scoped access consent
    /// (`access`), and with `omit_event_details` for a run with one-time codes.
    pub(crate) fn with_access(
        secrets: Vec<ProxySecret>,
        options: CoreOptions,
        access: Option<Admission>,
        omit_event_details: bool,
    ) -> io::Result<Arc<Self>> {
        let mut hosts: Vec<String> = secrets
            .iter()
            .flat_map(|secret| secret.hosts.iter().map(|rule| rule.host.clone()))
            .collect();
        hosts.sort();
        hosts.dedup();
        let ca = ca::RunCa::new(&hosts)?;
        Ok(Arc::new(Self {
            access,
            omit_event_details,
            secrets,
            hosts,
            ca,
            tls: options.tls,
            other_hosts: options.other_hosts,
            upstream: options.upstream,
            sink: options.sink,
            alpn: options.alpn,
            closed: AtomicBool::new(false),
            events: Mutex::new(Vec::new()),
            streams: Mutex::new(HashMap::new()),
            next_stream: AtomicU64::new(0),
        }))
    }

    /// The certificate of the run authority, in PEM form, for the trust files of
    /// the process.
    pub fn ca_pem(&self) -> &str {
        self.ca.cert_pem()
    }

    /// The host names of the secrets, sorted, without duplicates. Each covers its
    /// subdomains.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    /// Serves one client connection on the calling thread until it ends.
    /// `preread` holds bytes that the caller read from `stream` already (a whole
    /// request head or a part of it); the engine reads them first. After
    /// [`ProxyCore::close_all`], the connection is closed at once.
    pub fn serve_connection(self: &Arc<Self>, stream: TcpStream, preread: Vec<u8>, auth: Auth) {
        let _tracked = self.track(&stream);
        if self.is_closed() {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        serve(self, stream, preread, &auth);
    }

    /// Closes each open connection, and every connection that comes later.
    pub fn close_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(streams) = self.streams.lock() {
            for stream in streams.values() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }

    /// True after [`ProxyCore::close_all`].
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// The request log: at most 200 entries. It has no value and no placeholder.
    pub fn events(&self) -> Vec<ProxyEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    fn record(&self, mut event: ProxyEvent) {
        if self.omit_event_details {
            event.erase_details();
        }
        if let Some(sink) = &self.sink {
            sink(&event);
        }
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
        // A socket that came in while the engine closed is closed, too.
        if self.is_closed() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        Tracked {
            proxy: self,
            id: tracked,
        }
    }

    /// TCP to `host:port` under the upstream policy.
    fn open_upstream(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        open_tcp(&self.upstream.addresses(host, port)?)
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

fn serve(proxy: &Arc<ProxyCore>, stream: TcpStream, preread: Vec<u8>, auth: &Auth) {
    set_timeouts(&stream);
    let expected = auth.expected_header();
    let mut conn = Conn::with_buffered(stream, preread);
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
        if let Some(expected) = &expected
            && !authorized(&request, expected)
        {
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
            connect(proxy, conn, &request);
        } else {
            plain(proxy, conn, &request);
        }
        return;
    }
}

fn authorized(request: &RequestHead, expected: &str) -> bool {
    request
        .header("proxy-authorization")
        .is_some_and(|given| same_bytes(given.as_bytes(), expected.as_bytes()))
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

/// Opens TCP to the first address that answers, from `addrs`.
fn open_tcp(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for addr in addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                set_timeouts(&stream);
                return Ok(stream);
            }
            Err(err) => last = err,
        }
    }
    Err(last)
}

fn connect(proxy: &Arc<ProxyCore>, mut conn: Conn<TcpStream>, request: &RequestHead) {
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
    if proxy.is_secret_host(&host, port) {
        intercept(proxy, conn, &host, port);
        return;
    }
    if proxy.other_hosts == OtherHosts::Refuse {
        let reason = "This run reaches only the hosts of its secrets.";
        respond(&mut conn.inner, 403, "Forbidden", reason, "");
        proxy.record(
            ProxyEvent::new(&host, port, ProxyOutcome::Refused)
                .with_reason(ProxyOutcome::Refused, reason),
        );
        return;
    }
    let upstream = match proxy.open_upstream(&host, port) {
        Ok(upstream) => upstream,
        Err(_) => {
            respond(
                &mut conn.inner,
                502,
                "Bad Gateway",
                "Apassy could not connect to the host.",
                "",
            );
            proxy.record(
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
    proxy.record(ProxyEvent::new(&host, port, ProxyOutcome::Tunneled));
    let (client, rest) = conn.into_parts();
    tunnel(proxy, client, upstream, &rest);
}

/// Copy bytes both ways until one side closes.
fn tunnel(proxy: &ProxyCore, client: TcpStream, mut upstream: TcpStream, first: &[u8]) {
    let _tracked = proxy.track(&upstream);
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
fn plain(proxy: &Arc<ProxyCore>, mut conn: Conn<TcpStream>, request: &RequestHead) {
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
    let mut event = ProxyEvent::for_request(&host, port, request, &proxy.secrets);
    if proxy.is_secret_host(&host, port) || proxy.other_hosts == OtherHosts::Refuse {
        let reason = if proxy.is_secret_host(&host, port) {
            "Apassy does not send a real value over plain http://. Use https://."
        } else {
            "This run reaches only the hosts of its secrets."
        };
        respond(&mut conn.inner, 403, "Forbidden", reason, "");
        event = event.with_reason(ProxyOutcome::Refused, reason);
        proxy.record(event);
        return;
    }
    let Ok(mut upstream) = proxy.open_upstream(&host, port) else {
        respond(
            &mut conn.inner,
            502,
            "Bad Gateway",
            "Apassy could not connect to the host.",
            "",
        );
        proxy.record(event.with_reason(ProxyOutcome::Failed, "The connection failed."));
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
    proxy.record(event);
    let (client, rest) = conn.into_parts();
    tunnel(proxy, client, upstream, &rest);
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
    proxy: &'a ProxyCore,
    host: &str,
    port: u16,
) -> io::Result<(Conn<ServiceSide>, Tracked<'a>)> {
    let tcp = proxy.open_upstream(host, port)?;
    let tracked = proxy.track(&tcp);
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "host name"))?;
    let conn = ClientConnection::new(proxy.tls.client_config(), name).map_err(io::Error::other)?;
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

fn intercept(proxy: &Arc<ProxyCore>, mut conn: Conn<TcpStream>, host: &str, port: u16) {
    let config = match proxy.ca.server_config(host, proxy.alpn) {
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
            proxy.record(ProxyEvent::new(host, port, ProxyOutcome::Failed).with_reason(
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
    serve_requests(proxy, &mut client, host, port);
    client.inner.conn.send_close_notify();
    let _ = client.inner.flush();
}

/// The requests of one intercepted connection. Each request head goes through
/// `swap_request` and then to the service; the body follows as a stream, checked
/// for placeholders. A step that needs the whole body before the head goes out (a
/// SigV4 re-sign, S6 unit E1) belongs between the swap and the send.
fn serve_requests(proxy: &Arc<ProxyCore>, client: &mut Conn<ClientSide>, host: &str, port: u16) {
    let secrets: Vec<SwapSecret<'_>> = proxy
        .secrets
        .iter()
        .map(|secret| SwapSecret {
            placeholder: &secret.placeholder,
            value: &secret.value,
            hosts: &secret.hosts,
        })
        .collect();
    let placeholders: Vec<&[u8]> = proxy
        .secrets
        .iter()
        .map(|secret| secret.placeholder.as_bytes())
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = proxy
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
        let event = ProxyEvent::for_request(host, port, &request, &proxy.secrets);
        let refuse = |client: &mut Conn<ClientSide>, status: u16, text: &str, reason: String| {
            respond(&mut client.inner, status, text, &reason, "");
            proxy.record(event.clone().with_reason(ProxyOutcome::Refused, reason));
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
        if proxy.access.as_ref().is_some_and(|a| !a.covers(host, port)) {
            respond(
                &mut client.inner,
                403,
                "Forbidden",
                "The exact scoped access consent expired, was revoked, or does not cover this host and port.",
                "",
            );
            proxy.record(ProxyEvent::new(host, port, ProxyOutcome::Refused));
            return;
        }
        let swapped = match swap_request(&request, host, port, &secrets) {
            Ok(swapped) => swapped,
            Err(refusal) => {
                refuse(client, 403, "Forbidden", proxy.refusal_text(&refusal, host));
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
                match open_service(proxy, host, port) {
                    Ok(opened) => service = Some(opened),
                    Err(_) => {
                        respond(
                            &mut client.inner,
                            502,
                            "Bad Gateway",
                            "Apassy could not open a verified connection to the service.",
                            "",
                        );
                        proxy.record(event.with_reason(
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
            let sent = if let Some(access) = &proxy.access {
                match access.deliver(host, port, || {
                    upstream
                        .inner
                        .write_all(&swapped.head)
                        .and_then(|()| upstream.inner.flush())
                }) {
                    Some(result) => result.is_ok(),
                    None => {
                        refuse(client,403,"Forbidden","The scoped access consent expired or was revoked before delivery. No value was sent.".into());
                        return;
                    }
                }
            } else {
                upstream.inner.write_all(&swapped.head).is_ok()
            };
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
                                proxy.name(index)
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
            .map(|index| proxy.name(*index).to_owned())
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
        proxy.record(event);
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
    use std::net::{Ipv4Addr, TcpListener};

    use super::super::HostRule;
    use super::*;

    fn secret() -> ProxySecret {
        ProxySecret {
            name: "EXAMPLE_KEY".to_owned(),
            placeholder: "sk_test_placeholder_0000000000000000".to_owned(),
            value: Zeroizing::new("sk_test_synthetic_value_1111111111".to_owned()),
            hosts: vec![HostRule::parse("api.example.com").expect("rule")],
        }
    }

    fn options(other_hosts: OtherHosts) -> CoreOptions {
        CoreOptions {
            other_hosts,
            ..CoreOptions::new(TlsClient::platform().expect("tls"))
        }
    }

    /// Two ends of one loopback TCP connection: the client and the served side.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (served, _) = listener.accept().expect("accept");
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        (client, served)
    }

    fn serve_in_thread(
        proxy: &Arc<ProxyCore>,
        served: TcpStream,
        preread: Vec<u8>,
        auth: Auth,
    ) -> thread::JoinHandle<()> {
        let proxy = Arc::clone(proxy);
        thread::spawn(move || proxy.serve_connection(served, preread, auth))
    }

    /// Reads up to and with the empty line of one answer head.
    fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).expect("read") == 0 {
                break;
            }
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("utf-8")
    }

    #[test]
    fn serve_connection_uses_the_preread_bytes() {
        let proxy = ProxyCore::new(vec![secret()], options(OtherHosts::Refuse)).expect("core");
        // A whole head read by the front, and no Proxy-Authorization: it was checked.
        let (mut client, served) = pair();
        let head = b"CONNECT other.example:443 HTTP/1.1\r\nHost: other.example:443\r\n\r\n";
        let serving = serve_in_thread(&proxy, served, head.to_vec(), Auth::Checked);
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("answer");
        serving.join().expect("serve");
        assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
        // A part of the head read by the front; the rest comes from the stream.
        let (mut client, served) = pair();
        let serving = serve_in_thread(
            &proxy,
            served,
            b"CONNECT second.exa".to_vec(),
            Auth::Checked,
        );
        client
            .write_all(b"mple:443 HTTP/1.1\r\n\r\n")
            .expect("write");
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("answer");
        serving.join().expect("serve");
        assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
        let hosts: Vec<(String, ProxyOutcome)> = proxy
            .events()
            .into_iter()
            .map(|event| (event.host, event.outcome))
            .collect();
        assert_eq!(
            hosts,
            vec![
                ("other.example".to_owned(), ProxyOutcome::Refused),
                ("second.example".to_owned(), ProxyOutcome::Refused),
            ]
        );
    }

    #[test]
    fn serve_connection_with_a_password_needs_the_header() {
        let proxy = ProxyCore::new(vec![secret()], options(OtherHosts::Refuse)).expect("core");
        let password = Zeroizing::new("0123456789abcdef".to_owned());
        let (mut client, served) = pair();
        let serving = serve_in_thread(&proxy, served, Vec::new(), Auth::Password(password));
        client
            .write_all(b"CONNECT other.example:443 HTTP/1.1\r\n\r\n")
            .expect("write");
        let first = read_head(&mut client);
        assert!(first.starts_with("HTTP/1.1 407 "), "{first}");
        let credentials = base64::encode(b"apassy:0123456789abcdef");
        client
            .write_all(
                format!(
                    "CONNECT other.example:443 HTTP/1.1\r\nProxy-Authorization: Basic {credentials}\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("write");
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("answer");
        serving.join().expect("serve");
        assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
        assert_eq!(proxy.events().len(), 1);
    }

    #[test]
    fn public_only_refuses_private_loopback_and_tailnet_addresses() {
        let fixed: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let policy = UpstreamPolicy::PublicOnly {
            fixed: vec![("api.fixed.test".to_owned(), fixed)],
        };
        for host in [
            "127.0.0.1",
            "localhost",
            "10.0.0.8",
            "172.16.1.1",
            "192.168.1.1",
            "100.100.100.100",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fd7a:115c:a1e0::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            let refused = policy.addresses(host, 443);
            assert!(refused.is_err(), "{host}: {refused:?}");
        }
        assert_eq!(
            policy.addresses("1.1.1.1", 443).expect("public"),
            vec!["1.1.1.1:443".parse::<SocketAddr>().expect("addr")]
        );
        assert_eq!(
            policy.addresses("api.fixed.test", 443).expect("fixed"),
            vec![fixed]
        );
        assert!(UpstreamPolicy::Any.addresses("127.0.0.1", 443).is_ok());

        // Through the engine: a tunnel to a loopback listener is refused before
        // any connection is made.
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        target.set_nonblocking(true).expect("nonblocking");
        let port = target.local_addr().expect("addr").port();
        let proxy = ProxyCore::new(
            vec![secret()],
            CoreOptions {
                upstream: UpstreamPolicy::PublicOnly { fixed: Vec::new() },
                ..options(OtherHosts::Tunnel)
            },
        )
        .expect("core");
        let (mut client, served) = pair();
        let head = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n");
        let serving = serve_in_thread(&proxy, served, head.into_bytes(), Auth::Checked);
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("answer");
        serving.join().expect("serve");
        assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
        assert!(matches!(
            target.accept(),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock
        ));
        assert_eq!(proxy.events()[0].outcome, ProxyOutcome::Failed);
    }

    #[test]
    fn the_sink_gets_each_event() {
        let seen: Arc<Mutex<Vec<ProxyEvent>>> = Arc::default();
        let sink_seen = Arc::clone(&seen);
        let sink: EventSink = Arc::new(move |event: &ProxyEvent| {
            sink_seen.lock().expect("sink").push(event.clone());
        });
        let proxy = ProxyCore::new(
            vec![secret()],
            CoreOptions {
                sink: Some(sink),
                ..options(OtherHosts::Refuse)
            },
        )
        .expect("core");
        let (mut client, served) = pair();
        let head = b"CONNECT other.example:443 HTTP/1.1\r\n\r\n";
        let serving = serve_in_thread(&proxy, served, head.to_vec(), Auth::Checked);
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("answer");
        serving.join().expect("serve");
        assert_eq!(*seen.lock().expect("sink"), proxy.events());
        // The sink also gets the events after the request log is full.
        for _ in 0..MAX_EVENTS + 5 {
            proxy.record(ProxyEvent::new(
                "api.example.com",
                443,
                ProxyOutcome::Passed,
            ));
        }
        assert_eq!(seen.lock().expect("sink").len(), MAX_EVENTS + 6);
        assert_eq!(proxy.events().len(), MAX_EVENTS);
    }

    #[test]
    fn close_all_closes_later_connections_too() {
        let proxy = ProxyCore::new(vec![secret()], options(OtherHosts::Refuse)).expect("core");
        proxy.close_all();
        assert!(proxy.is_closed());
        let (mut client, served) = pair();
        let head = b"CONNECT other.example:443 HTTP/1.1\r\n\r\n";
        let serving = serve_in_thread(&proxy, served, head.to_vec(), Auth::Checked);
        let mut answer = String::new();
        let _ = client.read_to_string(&mut answer);
        serving.join().expect("serve");
        assert!(answer.is_empty(), "{answer}");
        assert!(proxy.events().is_empty());
    }

    #[test]
    fn the_core_reports_its_hosts_and_authority() {
        let mut other = secret();
        other.hosts = vec![
            HostRule::parse("api.example.com").expect("rule"),
            HostRule::parse("example.org:8443").expect("rule"),
        ];
        let proxy =
            ProxyCore::new(vec![secret(), other], options(OtherHosts::Refuse)).expect("core");
        assert_eq!(proxy.hosts(), ["api.example.com", "example.org"]);
        assert!(proxy.ca_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn auth_debug_hides_the_password() {
        let auth = Auth::Password(Zeroizing::new("0123456789abcdef".to_owned()));
        assert!(!format!("{auth:?}").contains("0123"));
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
