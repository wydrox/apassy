//! Minimal HTTP/1.1 client for connector destinations (ADR 0005) and the
//! bouncer decision model (ADR 0007, ADR 0035).
//!
//! `https://` uses rustls with the macOS trust store. Plain `http://` is
//! permitted only on loopback addresses. The client sends no agent-controlled
//! header, follows no redirect, and reads at most 64 KiB.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response that the client reads, headers and chunk framing included.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HOST_BYTES: usize = 253;

/// A parsed destination base URL. It has no path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationUrl {
    /// `http://` on 127.0.0.1, `localhost`, or `[::1]` only.
    Loopback {
        addr: SocketAddr,
        host_header: String,
    },
    /// `https://` on any host. The host is the SNI and certificate name.
    Https { host: String, port: u16 },
}

impl DestinationUrl {
    fn host_header(&self) -> String {
        match self {
            Self::Loopback { host_header, .. } => host_header.clone(),
            Self::Https { host, port } => {
                let host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.clone()
                };
                if *port == 443 {
                    host
                } else {
                    format!("{host}:{port}")
                }
            }
        }
    }
}

/// Parse an owner-registered destination.
pub fn parse_destination(url: &str) -> Result<DestinationUrl, &'static str> {
    let url = url.trim();
    if let Some(rest) = url.strip_prefix("https://") {
        let authority = authority_only(rest)?;
        let (host, port) = split_host_port(authority, 443)?;
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if bare.is_empty() || bare.len() > MAX_HOST_BYTES {
            return Err("The destination host is not valid.");
        }
        let valid_chars = bare
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':');
        if !valid_chars || ServerName::try_from(bare.to_owned()).is_err() {
            return Err("The destination host is not valid.");
        }
        return Ok(DestinationUrl::Https {
            host: bare.to_ascii_lowercase(),
            port,
        });
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let authority = authority_only(rest)?;
        if !authority.contains(':') || authority.ends_with(']') {
            return Err("A loopback destination must have a port.");
        }
        let (host, port) = split_host_port(authority, 0)?;
        let ip = match host {
            "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "[::1]" => IpAddr::V6(Ipv6Addr::LOCALHOST),
            _ => return Err("Plain http:// is permitted only on this computer. Use https://."),
        };
        return Ok(DestinationUrl::Loopback {
            addr: SocketAddr::new(ip, port),
            host_header: format!("{host}:{port}"),
        });
    }
    Err("The destination must start with https://.")
}

fn authority_only(rest: &str) -> Result<&str, &'static str> {
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', ' ']) {
        return Err("The destination must be a host and an optional port, with no path.");
    }
    Ok(authority)
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(&str, u16), &'static str> {
    // An IPv6 literal is in brackets: [::1]:8443.
    let (host, port) = if let Some(end) = authority.find(']') {
        let host = &authority[..=end];
        match &authority[end + 1..] {
            "" => (host, None),
            port => (
                host,
                Some(port.strip_prefix(':').ok_or("The port is not valid.")?),
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(text) => text
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or("The destination port is not valid.")?,
        None if default_port != 0 => default_port,
        None => return Err("The destination must have a port."),
    };
    Ok((host, port))
}

/// TLS client settings. The desktop app uses [`TlsClient::platform`].
#[derive(Clone)]
pub struct TlsClient {
    config: Arc<ClientConfig>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsClient")
    }
}

impl TlsClient {
    /// Verify certificates with the macOS trust store.
    pub fn platform() -> io::Result<Self> {
        Self::build(Vec::new())
    }

    /// The client settings, for the run proxy (ADR 0011).
    pub(crate) fn client_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.config)
    }

    /// Also trust the given root certificates. Tests use this for a local test CA.
    pub fn with_extra_roots(roots: Vec<CertificateDer<'static>>) -> io::Result<Self> {
        Self::build(roots)
    }

    fn build(roots: Vec<CertificateDer<'static>>) -> io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = if roots.is_empty() {
            rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        } else {
            rustls_platform_verifier::Verifier::new_with_extra_roots(roots, Arc::clone(&provider))
        }
        .map_err(io::Error::other)?;
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why a request failed. None of these values contains the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFailure {
    Connect,
    Timeout,
    Tls,
    Protocol,
    TooLarge,
}

/// Send one GET request with a bearer token. `path` must be pre-validated ASCII.
pub fn get(
    destination: &DestinationUrl,
    path: &str,
    bearer: &str,
    tls: &TlsClient,
) -> Result<HttpResponse, HttpFailure> {
    if !path.starts_with('/') || path.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(HttpFailure::Protocol);
    }
    if bearer.is_empty() || bearer.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(HttpFailure::Protocol);
    }
    let host = destination.host_header();
    let request = request_bytes(&[
        b"GET ",
        path.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\nAuthorization: Bearer ",
        bearer.as_bytes(),
        b"\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n",
    ]);
    match destination {
        DestinationUrl::Loopback { addr, .. } => {
            let mut stream = connect(&[*addr])?;
            exchange(&mut stream, &request)
        }
        DestinationUrl::Https { host, port } => {
            let addrs: Vec<SocketAddr> = (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|_| HttpFailure::Connect)?
                .collect();
            let tcp = connect(&addrs)?;
            let name = ServerName::try_from(host.clone()).map_err(|_| HttpFailure::Protocol)?;
            let conn = ClientConnection::new(Arc::clone(&tls.config), name)
                .map_err(|_| HttpFailure::Tls)?;
            let mut stream = StreamOwned::new(conn, tcp);
            // Finish the handshake before any request byte. A failed check sends no token.
            while stream.conn.is_handshaking() {
                stream
                    .conn
                    .complete_io(&mut stream.sock)
                    .map_err(|err| classify(&err))?;
            }
            exchange(&mut stream, &request)
        }
    }
}

/// Join the request parts in one buffer of the exact size. The buffer does not
/// grow, so it leaves no partial copy of a token in freed memory. `Zeroizing`
/// erases it on each return path, also after an early error.
fn request_bytes(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let size = parts.iter().map(|part| part.len()).sum();
    let mut request = Zeroizing::new(Vec::with_capacity(size));
    for part in parts {
        request.extend_from_slice(part);
    }
    request
}

/// POST a JSON body to a loopback service with one time limit for the whole
/// exchange. The bouncer uses this for the local decision model (ADR 0007).
/// An `https://` destination is a protocol failure here; use [`post_json`].
pub fn post_json_loopback(
    destination: &DestinationUrl,
    path: &str,
    body: &[u8],
    bearer: Option<&str>,
    timeout: std::time::Duration,
) -> Result<HttpResponse, HttpFailure> {
    post_json(destination, path, body, bearer, timeout, None)
}

/// POST a JSON body with one time limit for the whole exchange: name lookup,
/// connect, TLS handshake, request, and response (ADR 0035). An `https://`
/// destination needs `tls`; without it the call is a protocol failure. The
/// client sends no body byte before the handshake and the certificate check
/// succeed. When the time limit ends, the failure is [`HttpFailure::Timeout`].
/// The client reads the whole response, headers included, at most 64 KiB
/// ([`MAX_RESPONSE_BYTES`]); a larger one is [`HttpFailure::TooLarge`].
///
/// On macOS the platform certificate check can, in rare cases, take longer
/// than the deadline (it may fetch issuer or revocation data). The result is
/// then a failure (`Tls` or `Timeout`), never a success after the deadline.
pub fn post_json(
    destination: &DestinationUrl,
    path: &str,
    body: &[u8],
    bearer: Option<&str>,
    timeout: Duration,
    tls: Option<&TlsClient>,
) -> Result<HttpResponse, HttpFailure> {
    post_json_with(
        destination,
        path,
        body,
        bearer,
        timeout,
        tls,
        system_resolve,
    )
}

fn post_json_with(
    destination: &DestinationUrl,
    path: &str,
    body: &[u8],
    bearer: Option<&str>,
    timeout: Duration,
    tls: Option<&TlsClient>,
    resolve: Resolve,
) -> Result<HttpResponse, HttpFailure> {
    let deadline = Instant::now() + timeout;
    if !is_request_path(path) {
        return Err(HttpFailure::Protocol);
    }
    let (auth_start, auth_key, auth_end): (&[u8], &[u8], &[u8]) = match bearer {
        Some(key) if !key.is_empty() && key.bytes().all(|b| (0x21..0x7f).contains(&b)) => {
            (b"Authorization: Bearer ", key.as_bytes(), b"\r\n")
        }
        Some(_) => return Err(HttpFailure::Protocol),
        None => (b"", b"", b""),
    };
    let host = destination.host_header();
    let length = body.len().to_string();
    let request = request_bytes(&[
        b"POST ",
        path.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\n",
        auth_start,
        auth_key,
        auth_end,
        b"Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: ",
        length.as_bytes(),
        b"\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n",
        body,
    ]);
    send_before(destination, &request, deadline, tls, resolve)
}

/// Send one GET request with no bearer token, for a health route such as
/// `/health`. The time limit and the TLS rules are the same as in [`post_json`].
/// The client reads the whole response, headers included, at most 64 KiB
/// ([`MAX_RESPONSE_BYTES`]); a larger one is [`HttpFailure::TooLarge`].
///
/// On macOS the platform certificate check can, in rare cases, take longer
/// than the deadline (it may fetch issuer or revocation data). The result is
/// then a failure (`Tls` or `Timeout`), never a success after the deadline.
pub fn get_health(
    destination: &DestinationUrl,
    path: &str,
    timeout: Duration,
    tls: Option<&TlsClient>,
) -> Result<HttpResponse, HttpFailure> {
    get_health_with(destination, path, timeout, tls, system_resolve)
}

fn get_health_with(
    destination: &DestinationUrl,
    path: &str,
    timeout: Duration,
    tls: Option<&TlsClient>,
    resolve: Resolve,
) -> Result<HttpResponse, HttpFailure> {
    let deadline = Instant::now() + timeout;
    if !is_request_path(path) {
        return Err(HttpFailure::Protocol);
    }
    let host = destination.host_header();
    let request = request_bytes(&[
        b"GET ",
        path.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n",
    ]);
    send_before(destination, &request, deadline, tls, resolve)
}

fn is_request_path(path: &str) -> bool {
    path.starts_with('/') && path.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// A name lookup. Tests replace the system lookup, so they need no network.
type Resolve = fn(&str, u16) -> io::Result<Vec<SocketAddr>>;

fn system_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

/// The time that is left before `deadline`, or a timeout when none is left.
fn remaining_before(deadline: Instant) -> Result<Duration, HttpFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(HttpFailure::Timeout)
}

/// Look up `host` on a helper thread and wait at most until `deadline`. The
/// system lookup has no time limit of its own. After a timeout the thread ends
/// on its own when the lookup returns; nobody reads its result.
fn resolve_before(
    host: &str,
    port: u16,
    deadline: Instant,
    resolve: Resolve,
) -> Result<Vec<SocketAddr>, HttpFailure> {
    let remaining = remaining_before(deadline)?;
    let (sender, receiver) = mpsc::channel();
    let host = host.to_owned();
    std::thread::Builder::new()
        .name("apassy-http-lookup".to_owned())
        .spawn(move || {
            let _ = sender.send(resolve(&host, port));
        })
        .map_err(|_| HttpFailure::Connect)?;
    match receiver.recv_timeout(remaining) {
        Ok(Ok(addrs)) if !addrs.is_empty() => Ok(addrs),
        Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(HttpFailure::Connect),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(HttpFailure::Timeout),
    }
}

/// Connect to the first address that answers. Each attempt has at most
/// `CONNECT_TIMEOUT` and never more than the time left before `deadline`.
fn connect_before(addrs: &[SocketAddr], deadline: Instant) -> Result<TcpStream, HttpFailure> {
    let mut failure = HttpFailure::Connect;
    for addr in addrs {
        let remaining = remaining_before(deadline)?;
        match TcpStream::connect_timeout(addr, remaining.min(CONNECT_TIMEOUT)) {
            Ok(stream) => return Ok(stream),
            Err(err) => failure = classify(&err),
        }
    }
    Err(failure)
}

/// Send `request` and read the response before `deadline`. Every socket
/// operation, the TLS handshake included, stops at the deadline.
fn send_before(
    destination: &DestinationUrl,
    request: &[u8],
    deadline: Instant,
    tls: Option<&TlsClient>,
    resolve: Resolve,
) -> Result<HttpResponse, HttpFailure> {
    match destination {
        DestinationUrl::Loopback { addr, .. } => {
            // The fields are public. Plain http:// never leaves this computer,
            // also for a value that does not come from `parse_destination`.
            if !addr.ip().is_loopback() {
                return Err(HttpFailure::Protocol);
            }
            let stream = connect_before(&[*addr], deadline)?;
            let mut stream = DeadlineStream { stream, deadline };
            exchange(&mut stream, request)
        }
        DestinationUrl::Https { host, port } => {
            let tls = tls.ok_or(HttpFailure::Protocol)?;
            let name = ServerName::try_from(host.clone()).map_err(|_| HttpFailure::Protocol)?;
            let addrs = resolve_before(host, *port, deadline, resolve)?;
            let stream = connect_before(&addrs, deadline)?;
            let conn = ClientConnection::new(Arc::clone(&tls.config), name)
                .map_err(|_| HttpFailure::Tls)?;
            let mut stream = StreamOwned::new(conn, DeadlineStream { stream, deadline });
            // Finish the handshake before any request byte. A failed check sends
            // no token and no body. On macOS the certificate check inside
            // `complete_io` can, in rare cases, take longer than the deadline (it
            // may fetch issuer or revocation data). The next socket operation
            // then fails, so the result is never a success after the deadline.
            while stream.conn.is_handshaking() {
                stream
                    .conn
                    .complete_io(&mut stream.sock)
                    .map_err(|err| classify(&err))?;
            }
            exchange(&mut stream, request)
        }
    }
}

/// Refresh the socket limit before every operation, so fragmented responses cannot
/// extend a bouncer request beyond its total exchange budget. Under TLS it also
/// limits the handshake.
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

fn connect(addrs: &[SocketAddr]) -> Result<TcpStream, HttpFailure> {
    for addr in addrs {
        if let Ok(stream) = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .map_err(|_| HttpFailure::Connect)?;
            stream
                .set_write_timeout(Some(IO_TIMEOUT))
                .map_err(|_| HttpFailure::Connect)?;
            return Ok(stream);
        }
    }
    Err(HttpFailure::Connect)
}

fn classify(err: &io::Error) -> HttpFailure {
    let is_tls = err
        .get_ref()
        .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some());
    // rustls reports its errors as InvalidData, sometimes without a rustls::Error inside.
    if matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        HttpFailure::Timeout
    } else if is_tls || err.kind() == io::ErrorKind::InvalidData {
        HttpFailure::Tls
    } else {
        HttpFailure::Connect
    }
}

fn exchange<S: Read + Write>(stream: &mut S, request: &[u8]) -> Result<HttpResponse, HttpFailure> {
    stream.write_all(request).map_err(|err| classify(&err))?;
    stream.flush().map_err(|err| classify(&err))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(response) = complete_response(&raw)? {
            return Ok(response);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return finish_at_eof(&raw),
            Ok(read) => {
                raw.extend_from_slice(&chunk[..read]);
                if raw.len() > MAX_RESPONSE_BYTES {
                    return Err(HttpFailure::TooLarge);
                }
            }
            // A server can close TLS without close_notify. Treat it as end of data.
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return finish_at_eof(&raw),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(classify(&err)),
        }
    }
}

enum BodyKind {
    Length(usize),
    Chunked,
    UntilClose,
}

struct Head {
    status: u16,
    body_start: usize,
    kind: BodyKind,
}

fn parse_head(raw: &[u8]) -> Result<Option<Head>, HttpFailure> {
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| HttpFailure::Protocol)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpFailure::Protocol)?;
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpFailure::Protocol);
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or(HttpFailure::Protocol)?;
    let mut kind = BodyKind::UntilClose;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(HttpFailure::Protocol)?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" {
            if value.eq_ignore_ascii_case("chunked") {
                kind = BodyKind::Chunked;
            } else {
                return Err(HttpFailure::Protocol);
            }
        } else if name == "content-length" && !matches!(kind, BodyKind::Chunked) {
            kind = BodyKind::Length(value.parse().map_err(|_| HttpFailure::Protocol)?);
        }
    }
    Ok(Some(Head {
        status,
        body_start: split + 4,
        kind,
    }))
}

/// A response when the bytes so far are enough. `None` asks for more bytes.
fn complete_response(raw: &[u8]) -> Result<Option<HttpResponse>, HttpFailure> {
    let Some(head) = parse_head(raw)? else {
        return Ok(None);
    };
    let body = &raw[head.body_start..];
    match head.kind {
        BodyKind::Length(length) if body.len() >= length => Ok(Some(HttpResponse {
            status: head.status,
            body: body[..length].to_vec(),
        })),
        BodyKind::Chunked => Ok(decode_chunked(body)?.map(|body| HttpResponse {
            status: head.status,
            body,
        })),
        BodyKind::Length(_) | BodyKind::UntilClose => Ok(None),
    }
}

fn finish_at_eof(raw: &[u8]) -> Result<HttpResponse, HttpFailure> {
    let head = parse_head(raw)?.ok_or(HttpFailure::Protocol)?;
    match head.kind {
        BodyKind::UntilClose => Ok(HttpResponse {
            status: head.status,
            body: raw[head.body_start..].to_vec(),
        }),
        // A length or chunked body that ends early is not complete.
        BodyKind::Length(_) | BodyKind::Chunked => Err(HttpFailure::Protocol),
    }
}

/// Decode a complete chunked body. `None` means that more bytes are necessary.
fn decode_chunked(mut data: &[u8]) -> Result<Option<Vec<u8>>, HttpFailure> {
    let mut body = Vec::new();
    loop {
        let Some(line_end) = data.windows(2).position(|window| window == b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&data[..line_end]).map_err(|_| HttpFailure::Protocol)?;
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| HttpFailure::Protocol)?;
        if size > MAX_RESPONSE_BYTES {
            return Err(HttpFailure::TooLarge);
        }
        data = &data[line_end + 2..];
        if size == 0 {
            // Trailers end with an empty line. This client ignores trailer fields.
            return Ok(data
                .windows(2)
                .any(|window| window == b"\r\n")
                .then_some(body));
        }
        if data.len() < size + 2 {
            return Ok(None);
        }
        if &data[size..size + 2] != b"\r\n" {
            return Err(HttpFailure::Protocol);
        }
        body.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_rules() {
        assert!(matches!(
            parse_destination("http://127.0.0.1:8787"),
            Ok(DestinationUrl::Loopback { .. })
        ));
        assert!(parse_destination("http://localhost:8787/").is_ok());
        assert!(parse_destination("http://[::1]:8787").is_ok());
        assert_eq!(
            parse_destination("https://Reporting.Example.invalid"),
            Ok(DestinationUrl::Https {
                host: "reporting.example.invalid".to_owned(),
                port: 443
            })
        );
        assert_eq!(
            parse_destination("https://localhost:8443/"),
            Ok(DestinationUrl::Https {
                host: "localhost".to_owned(),
                port: 8443
            })
        );
        for bad in [
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://10.0.0.1:80",
            "http://reporting.example.invalid:80",
            "http://127.0.0.1:8787/v1",
            "https://reporting.example.invalid/v1",
            "https://user@reporting.example.invalid",
            "https://reporting.example.invalid:0",
            "https://bad_host!",
            "https://",
            "ftp://127.0.0.1:21",
            "https://reporting.example.invalid?x=1",
        ] {
            assert!(parse_destination(bad).is_err(), "{bad}");
        }
    }

    /// Manual check with network access: `cargo test --features vault public_https -- --ignored`.
    /// It sends a dummy bearer value to example.com and expects a verified TLS session.
    #[test]
    #[ignore = "needs network access"]
    fn public_https_uses_the_macos_trust_store() {
        let tls = TlsClient::platform().expect("platform TLS");
        let destination = parse_destination("https://example.com").expect("destination");
        let response = get(&destination, "/", "dummy-not-a-secret", &tls).expect("verified TLS");
        assert!((200..500).contains(&response.status));
        let wrong_name = DestinationUrl::Https {
            host: "wrong.host.badssl.com".to_owned(),
            port: 443,
        };
        assert_eq!(
            get(&wrong_name, "/", "dummy-not-a-secret", &tls).unwrap_err(),
            HttpFailure::Tls
        );
    }

    /// Accept one connection, read one request with its body, and answer `{}`.
    fn capture_one_request(listener: std::net::TcpListener) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let read = stream.read(&mut buf).expect("read");
                seen.extend_from_slice(&buf[..read]);
                let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                    assert!(read > 0, "the request ended before its head");
                    continue;
                };
                let head = String::from_utf8_lossy(&seen[..end]).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .map_or(0, |value| value.parse::<usize>().expect("length"));
                if seen.len() >= end + 4 + length || read == 0 {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .expect("write");
            seen
        })
    }

    #[test]
    fn requests_are_built_in_exact_buffers_with_unchanged_bytes() {
        let parts: [&[u8]; 3] = [b"ab", b"", b"cde"];
        let joined = request_bytes(&parts);
        assert_eq!(joined.as_slice(), b"abcde");
        assert_eq!(joined.capacity(), joined.len());

        let tls = TlsClient::platform().expect("platform TLS");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
        let server = capture_one_request(listener);
        let response = get(&destination, "/v1/report", "synthetic-bearer-1", &tls).expect("get");
        assert_eq!(response.body, b"{}");
        assert_eq!(
            String::from_utf8(server.join().expect("server")).expect("text"),
            format!(
                "GET /v1/report HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer synthetic-bearer-1\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n"
            )
        );

        for bearer in [Some("synthetic-model-key"), None] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
            let server = capture_one_request(listener);
            let body = br#"{"synthetic":true}"#;
            let response = post_json_loopback(
                &destination,
                "/v1/score",
                body,
                bearer,
                Duration::from_secs(5),
            )
            .expect("post");
            assert_eq!(response.body, b"{}");
            let auth = bearer.map_or(String::new(), |key| {
                format!("Authorization: Bearer {key}\r\n")
            });
            assert_eq!(
                String::from_utf8(server.join().expect("server")).expect("text"),
                format!(
                    "POST /v1/score HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: 18\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n{{\"synthetic\":true}}"
                )
            );
        }
    }

    #[test]
    fn length_and_chunked_bodies() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra";
        let response = complete_response(raw).expect("parse").expect("complete");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}");
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}";
        assert!(complete_response(partial).expect("parse").is_none());
        assert_eq!(finish_at_eof(partial).unwrap_err(), HttpFailure::Protocol);

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3;x=1\r\n:1}\r\n0\r\n\r\n";
        let response = complete_response(chunked)
            .expect("parse")
            .expect("complete");
        assert_eq!(response.body, b"{\"a\":1}");
        let cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a";
        assert!(complete_response(cut).expect("parse").is_none());
        let bad = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(complete_response(bad).is_err());
        let until_close = b"HTTP/1.0 200 OK\r\n\r\n{}";
        assert_eq!(finish_at_eof(until_close).expect("eof body").body, b"{}");
    }

    #[test]
    fn bouncer_timeout_covers_the_whole_fragmented_response() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination =
            parse_destination(&format!("http://{}", listener.local_addr().expect("addr")))
                .expect("destination");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0u8; 4096];
            assert!(
                stream.read(&mut request).expect("request") > 0,
                "request bytes"
            );
            // Every individual fragment arrives before the timeout, but the whole
            // response does not. The absolute deadline must still stop the client.
            for chunk in [
                b"HTTP/1.1 200 OK\r\n".as_slice(),
                b"Content-Length: 2\r\n",
                b"\r\n",
                b"{",
                b"}",
            ] {
                std::thread::sleep(Duration::from_millis(80));
                if stream.write_all(chunk).is_err() {
                    break;
                }
            }
        });
        let began = Instant::now();
        let result = post_json_loopback(
            &destination,
            "/v1/systemone",
            b"{}",
            None,
            Duration::from_millis(200),
        );
        assert_eq!(
            result.expect_err("fragmented response must exceed total budget"),
            HttpFailure::Timeout
        );
        assert!(
            began.elapsed() < Duration::from_millis(350),
            "deadline applies to all reads"
        );
        server.join().expect("server");
    }

    #[test]
    fn timeout_is_distinct_from_protocol_and_connection_failures() {
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::TimedOut)),
            HttpFailure::Timeout
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::WouldBlock)),
            HttpFailure::Timeout
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            HttpFailure::Connect
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionReset)),
            HttpFailure::Connect
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::InvalidData)),
            HttpFailure::Tls
        );
    }

    /// A local HTTPS service for `localhost` with its own test root. The client
    /// trusts that root in addition to the platform roots.
    struct TestTls {
        config: Arc<rustls::ServerConfig>,
        client: TlsClient,
    }

    fn test_tls() -> TestTls {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        };
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        fn validity(params: &mut CertificateParams) {
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::hours(1);
            params.not_after = now + time::Duration::days(1);
        }

        let mut root = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Apassy http test root");
        root.distinguished_name = name;
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        validity(&mut root);
        let root_key = KeyPair::generate().expect("root key");
        let root_cert = root.self_signed(&root_key).expect("root");
        let issuer = Issuer::new(root, root_key);
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.use_authority_key_identifier_extension = true;
        validity(&mut leaf);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server config");
        TestTls {
            config: Arc::new(config),
            client: TlsClient::with_extra_roots(vec![root_cert.der().clone()])
                .expect("TLS client with test root"),
        }
    }

    /// Every name is this computer, on the port of the destination. No network.
    fn resolve_to_this_computer(_host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)])
    }

    /// A name lookup that does not answer in time.
    fn resolve_slowly(_host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        std::thread::sleep(Duration::from_secs(3));
        Err(io::Error::from(io::ErrorKind::TimedOut))
    }

    /// Read one request with its body. A failed handshake or a closed
    /// connection ends the read; the result is the plaintext that arrived.
    fn read_request<S: Read>(stream: &mut S) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return seen,
                Ok(read) => seen.extend_from_slice(&buf[..read]),
            }
            let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .map_or(0, |value| value.parse::<usize>().expect("length"));
            if seen.len() >= end + 4 + length {
                return seen;
            }
        }
    }

    /// The server side of the socket. It keeps a copy of every byte that it
    /// reads, before TLS decryption.
    struct RecordingStream {
        stream: TcpStream,
        raw: Vec<u8>,
    }

    impl Read for RecordingStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = self.stream.read(buffer)?;
            self.raw.extend_from_slice(&buffer[..read]);
            Ok(read)
        }
    }

    impl Write for RecordingStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.stream.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    /// The bytes that one TLS server connection received.
    struct ServerSeen {
        /// The request after TLS decryption.
        plaintext: Vec<u8>,
        /// Every byte that arrived on the socket, before TLS decryption.
        raw: Vec<u8>,
    }

    /// Accept one TLS connection and read one request. Then write `answer`, or,
    /// without an answer, stall until `release`.
    fn serve_one_tls_request(
        listener: std::net::TcpListener,
        config: Arc<rustls::ServerConfig>,
        answer: Option<Vec<u8>>,
        release: mpsc::Receiver<()>,
    ) -> ServerSeen {
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        let conn = rustls::ServerConnection::new(config).expect("server connection");
        let recording = RecordingStream {
            stream: tcp,
            raw: Vec::new(),
        };
        let mut tls = StreamOwned::new(conn, recording);
        let plaintext = read_request(&mut tls);
        match answer {
            Some(answer) => {
                let _ = tls.write_all(&answer);
                let _ = tls.flush();
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            }
            None => {
                let _ = release.recv_timeout(Duration::from_secs(10));
            }
        }
        ServerSeen {
            plaintext,
            raw: std::mem::take(&mut tls.sock.raw),
        }
    }

    /// [`serve_one_tls_request`] on a server thread. Returns the request plaintext.
    fn answer_one_tls_request(
        listener: std::net::TcpListener,
        config: Arc<rustls::ServerConfig>,
        answer: Option<Vec<u8>>,
        release: mpsc::Receiver<()>,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            serve_one_tls_request(listener, config, answer, release).plaintext
        })
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn localhost_https(listener: &std::net::TcpListener) -> DestinationUrl {
        DestinationUrl::Https {
            host: "localhost".to_owned(),
            port: listener.local_addr().expect("addr").port(),
        }
    }

    #[test]
    fn a_stalled_tls_server_fails_at_the_exchange_deadline() {
        let pki = test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination = localhost_https(&listener);
        let (release, held) = mpsc::channel::<()>();
        // The server accepts the connection and never answers the client hello.
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let _ = held.recv_timeout(Duration::from_secs(10));
            drop(stream);
        });
        let timeout = Duration::from_millis(400);
        let began = Instant::now();
        let result = post_json_with(
            &destination,
            "/v1/score",
            br#"{"synthetic":true}"#,
            Some("synthetic-model-key"),
            timeout,
            Some(&pki.client),
            resolve_to_this_computer,
        );
        let elapsed = began.elapsed();
        release.send(()).expect("release");
        server.join().expect("server");
        assert_eq!(result.unwrap_err(), HttpFailure::Timeout);
        assert!(
            elapsed < timeout + Duration::from_secs(1),
            "the handshake stopped at the deadline: {elapsed:?}"
        );
    }

    #[test]
    fn a_server_that_stalls_after_the_handshake_fails_at_the_deadline() {
        let pki = test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination = localhost_https(&listener);
        let (release, held) = mpsc::channel();
        let server = answer_one_tls_request(listener, Arc::clone(&pki.config), None, held);
        let timeout = Duration::from_millis(1500);
        let began = Instant::now();
        let result = post_json_with(
            &destination,
            "/v1/score",
            br#"{"synthetic":true}"#,
            Some("synthetic-model-key"),
            timeout,
            Some(&pki.client),
            resolve_to_this_computer,
        );
        let elapsed = began.elapsed();
        release.send(()).expect("release");
        let seen = String::from_utf8(server.join().expect("server")).expect("text");
        assert!(
            seen.ends_with(r#"{"synthetic":true}"#),
            "the handshake finished and the request arrived: {seen:?}"
        );
        assert_eq!(result.unwrap_err(), HttpFailure::Timeout);
        assert!(
            elapsed < timeout + Duration::from_secs(1),
            "the response read stopped at the deadline: {elapsed:?}"
        );
    }

    #[test]
    fn a_fragmented_tls_response_still_meets_the_deadline() {
        let pki = test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination = localhost_https(&listener);
        let config = Arc::clone(&pki.config);
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout");
            let conn = rustls::ServerConnection::new(config).expect("server connection");
            let mut tls = StreamOwned::new(conn, tcp);
            let seen = read_request(&mut tls);
            // Each piece is its own TLS record. Every piece arrives before the
            // previous one is late, but the whole response does not arrive
            // before the deadline. The absolute deadline must still stop the client.
            for piece in [
                b"HTTP/1.1 200 OK\r\n".as_slice(),
                b"Content-Length: 2\r\n",
                b"\r\n",
                b"{",
                b"}",
            ] {
                std::thread::sleep(Duration::from_millis(400));
                if tls.write_all(piece).and_then(|()| tls.flush()).is_err() {
                    break;
                }
            }
            seen
        });
        let timeout = Duration::from_millis(1500);
        let began = Instant::now();
        let result = post_json_with(
            &destination,
            "/v1/score",
            br#"{"synthetic":true}"#,
            Some("synthetic-model-key"),
            timeout,
            Some(&pki.client),
            resolve_to_this_computer,
        );
        let elapsed = began.elapsed();
        let seen = String::from_utf8(server.join().expect("server")).expect("text");
        assert!(
            seen.ends_with(r#"{"synthetic":true}"#),
            "the handshake finished and the request arrived: {seen:?}"
        );
        assert_eq!(
            result.expect_err("a fragmented response must exceed the total budget"),
            HttpFailure::Timeout
        );
        assert!(
            elapsed < timeout + Duration::from_secs(1),
            "the deadline applies to all TLS reads: {elapsed:?}"
        );
    }

    #[test]
    fn a_slow_name_lookup_fails_at_the_deadline() {
        let pki = test_tls();
        let destination = DestinationUrl::Https {
            host: "bouncer.example.invalid".to_owned(),
            port: 443,
        };
        let timeout = Duration::from_millis(300);
        let began = Instant::now();
        let post = post_json_with(
            &destination,
            "/v1/score",
            b"{}",
            Some("synthetic-model-key"),
            timeout,
            Some(&pki.client),
            resolve_slowly,
        );
        assert_eq!(post.unwrap_err(), HttpFailure::Timeout);
        assert!(
            began.elapsed() < timeout + Duration::from_secs(1),
            "the lookup wait stopped at the deadline"
        );
        let began = Instant::now();
        let health = get_health_with(
            &destination,
            "/health",
            timeout,
            Some(&pki.client),
            resolve_slowly,
        );
        assert_eq!(health.unwrap_err(), HttpFailure::Timeout);
        assert!(
            began.elapsed() < timeout + Duration::from_secs(1),
            "the health lookup wait stopped at the deadline"
        );
    }

    #[test]
    fn a_wrong_server_name_sends_no_byte_of_the_body() {
        let pki = test_tls();
        let marker = b"synthetic-marker-not-for-a-wrong-server";
        let body = br#"{"synthetic-marker-not-for-a-wrong-server":true}"#;
        let bearer = "synthetic-model-key";
        // The certificate is for `localhost`; the destination asks for another
        // name. Then a client without the test root asks for the right name.
        let platform = TlsClient::platform().expect("platform TLS");
        for (host, client) in [
            ("wrong.example.invalid", &pki.client),
            ("localhost", &platform),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let destination = DestinationUrl::Https {
                host: host.to_owned(),
                port: listener.local_addr().expect("addr").port(),
            };
            let (_release, held) = mpsc::channel();
            let config = Arc::clone(&pki.config);
            let server = std::thread::spawn(move || {
                serve_one_tls_request(
                    listener,
                    config,
                    Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec()),
                    held,
                )
            });
            let result = post_json_with(
                &destination,
                "/v1/score",
                body,
                Some(bearer),
                Duration::from_secs(5),
                Some(client),
                resolve_to_this_computer,
            );
            assert_eq!(result.unwrap_err(), HttpFailure::Tls, "{host}");
            let seen = server.join().expect("server");
            assert!(seen.plaintext.is_empty(), "{host}: no request byte arrived");
            // The check is on the raw socket bytes too, not only on what TLS
            // decrypted. The client hello arrived, so the recording works.
            assert!(!seen.raw.is_empty(), "{host}: the handshake bytes arrived");
            for secret in [marker.as_slice(), bearer.as_bytes()] {
                assert!(
                    !contains(&seen.raw, secret),
                    "{host}: {:?} is not on the socket",
                    String::from_utf8_lossy(secret)
                );
            }
        }
    }

    #[test]
    fn a_response_over_the_cap_is_too_large() {
        let pki = test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination = localhost_https(&listener);
        let size = MAX_RESPONSE_BYTES + 1;
        let mut answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").into_bytes();
        answer.resize(answer.len() + size, b'a');
        let (_release, held) = mpsc::channel();
        let server = answer_one_tls_request(listener, Arc::clone(&pki.config), Some(answer), held);
        let result = post_json_with(
            &destination,
            "/v1/score",
            b"{}",
            None,
            Duration::from_secs(5),
            Some(&pki.client),
            resolve_to_this_computer,
        );
        assert_eq!(result.unwrap_err(), HttpFailure::TooLarge);
        server.join().expect("server");
    }

    #[test]
    fn a_chunked_response_over_tls_is_decoded_and_capped() {
        let pki = test_tls();
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut chunked = head.to_vec();
        chunked.extend_from_slice(b"4\r\n{\"a\"\r\n3;x=1\r\n:1}\r\n0\r\n\r\n");
        // Every chunk is under the cap; all of them together are over it.
        let mut many = head.to_vec();
        while many.len() <= MAX_RESPONSE_BYTES {
            many.extend_from_slice(b"1000\r\n");
            many.resize(many.len() + 0x1000, b'a');
            many.extend_from_slice(b"\r\n");
        }
        many.extend_from_slice(b"0\r\n\r\n");
        // One chunk that says that it is larger than the cap.
        let mut one_large = head.to_vec();
        one_large.extend_from_slice(format!("{:x}\r\n", MAX_RESPONSE_BYTES + 1).as_bytes());
        for (name, answer, expected) in [
            ("decoded", chunked, Ok(br#"{"a":1}"#.to_vec())),
            ("many chunks", many, Err(HttpFailure::TooLarge)),
            ("one large chunk", one_large, Err(HttpFailure::TooLarge)),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let destination = localhost_https(&listener);
            let (_release, held) = mpsc::channel();
            let server =
                answer_one_tls_request(listener, Arc::clone(&pki.config), Some(answer), held);
            let result = post_json_with(
                &destination,
                "/v1/score",
                b"{}",
                None,
                Duration::from_secs(5),
                Some(&pki.client),
                resolve_to_this_computer,
            )
            .map(|response| {
                assert_eq!(response.status, 200, "{name}");
                response.body
            });
            assert_eq!(result, expected, "{name}");
            server.join().expect("server");
        }
    }

    #[test]
    fn an_https_plain_http_mix_is_protocol() {
        // An https:// destination without TLS settings fails before the name
        // lookup and before any connection.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let destination = localhost_https(&listener);
        let began = Instant::now();
        assert_eq!(
            post_json_with(
                &destination,
                "/v1/score",
                b"{}",
                Some("synthetic-model-key"),
                Duration::from_secs(5),
                None,
                resolve_slowly,
            )
            .unwrap_err(),
            HttpFailure::Protocol
        );
        assert_eq!(
            get_health_with(
                &destination,
                "/health",
                Duration::from_secs(5),
                None,
                resolve_slowly
            )
            .unwrap_err(),
            HttpFailure::Protocol
        );
        // The slow lookup takes 3 s, so a quick failure did no lookup.
        assert!(began.elapsed() < Duration::from_secs(1), "no name lookup");
        assert_eq!(
            listener.accept().map(|_| ()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "no connection arrived"
        );

        // Plain http:// off this computer cannot be built from a URL: the
        // loopback check in `parse_destination` refuses it.
        for url in [
            "http://10.0.0.1:80",
            "http://bouncer.example.invalid:80",
            "http://[2001:db8::1]:80",
        ] {
            assert_eq!(
                parse_destination(url),
                Err("Plain http:// is permitted only on this computer. Use https://."),
                "{url}"
            );
        }

        // The fields are public. A value built by hand with an address off this
        // computer is a protocol failure with no connection attempt.
        let off_this_computer = DestinationUrl::Loopback {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
            host_header: "192.0.2.1:80".to_owned(),
        };
        let began = Instant::now();
        assert_eq!(
            post_json_loopback(
                &off_this_computer,
                "/v1/score",
                b"{}",
                None,
                Duration::from_secs(5)
            )
            .unwrap_err(),
            HttpFailure::Protocol
        );
        assert_eq!(
            get_health(&off_this_computer, "/health", Duration::from_secs(5), None).unwrap_err(),
            HttpFailure::Protocol
        );
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "no connection attempt"
        );
    }

    #[test]
    fn https_post_returns_the_status_and_body() {
        let pki = test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination = localhost_https(&listener);
        let port = listener.local_addr().expect("addr").port();
        let (_release, held) = mpsc::channel();
        let server = answer_one_tls_request(
            listener,
            Arc::clone(&pki.config),
            Some(b"HTTP/1.1 201 Created\r\nContent-Length: 11\r\n\r\n{\"ok\":true}".to_vec()),
            held,
        );
        let response = post_json_with(
            &destination,
            "/v1/score",
            br#"{"synthetic":true}"#,
            Some("synthetic-model-key"),
            Duration::from_secs(5),
            Some(&pki.client),
            resolve_to_this_computer,
        )
        .expect("post");
        assert_eq!(response.status, 201);
        assert_eq!(response.body, br#"{"ok":true}"#);
        assert_eq!(
            String::from_utf8(server.join().expect("server")).expect("text"),
            format!(
                "POST /v1/score HTTP/1.1\r\nHost: localhost:{port}\r\nAuthorization: Bearer synthetic-model-key\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: 18\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n{{\"synthetic\":true}}"
            )
        );

        // Without TLS settings an https destination is a protocol failure.
        assert_eq!(
            post_json(
                &destination,
                "/v1/score",
                b"{}",
                None,
                Duration::from_secs(5),
                None
            )
            .unwrap_err(),
            HttpFailure::Protocol
        );
    }

    #[test]
    fn health_get_sends_no_bearer() {
        let pki = test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination = localhost_https(&listener);
        let port = listener.local_addr().expect("addr").port();
        let (_release, held) = mpsc::channel();
        let server = answer_one_tls_request(
            listener,
            Arc::clone(&pki.config),
            Some(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}".to_vec()),
            held,
        );
        let response = get_health_with(
            &destination,
            "/health",
            Duration::from_secs(5),
            Some(&pki.client),
            resolve_to_this_computer,
        )
        .expect("health over TLS");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"status":"ok"}"#);
        assert_eq!(
            String::from_utf8(server.join().expect("server")).expect("text"),
            format!(
                "GET /health HTTP/1.1\r\nHost: localhost:{port}\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n"
            )
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
        let server = capture_one_request(listener);
        let response =
            get_health(&destination, "/health", Duration::from_secs(5), None).expect("health");
        assert_eq!(response.body, b"{}");
        assert_eq!(
            String::from_utf8(server.join().expect("server")).expect("text"),
            format!(
                "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n"
            )
        );
    }

    #[test]
    fn loopback_post_is_unchanged() {
        let pki = test_tls();
        for use_wrapper in [true, false] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
            let server = capture_one_request(listener);
            let body = br#"{"synthetic":true}"#;
            let bearer = Some("synthetic-model-key");
            let timeout = Duration::from_secs(5);
            let response = if use_wrapper {
                post_json_loopback(&destination, "/v1/score", body, bearer, timeout)
            } else {
                // TLS settings change nothing for a loopback destination.
                post_json(
                    &destination,
                    "/v1/score",
                    body,
                    bearer,
                    timeout,
                    Some(&pki.client),
                )
            }
            .expect("post");
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"{}");
            assert_eq!(
                String::from_utf8(server.join().expect("server")).expect("text"),
                format!(
                    "POST /v1/score HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer synthetic-model-key\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: 18\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n{{\"synthetic\":true}}"
                )
            );
        }

        // The loopback wrapper still refuses https:// without a connection.
        let https = DestinationUrl::Https {
            host: "bouncer.example.invalid".to_owned(),
            port: 443,
        };
        let began = Instant::now();
        assert_eq!(
            post_json_loopback(&https, "/v1/score", b"{}", None, Duration::from_secs(5))
                .unwrap_err(),
            HttpFailure::Protocol
        );
        assert!(began.elapsed() < Duration::from_secs(1));
        for (path, bearer) in [("v1/score", None), ("/v1/score", Some("")), ("/a b", None)] {
            let loopback = parse_destination("http://127.0.0.1:9").expect("url");
            assert_eq!(
                post_json_loopback(&loopback, path, b"{}", bearer, Duration::from_secs(5))
                    .unwrap_err(),
                HttpFailure::Protocol,
                "{path:?} {bearer:?}"
            );
        }
        // A closed loopback port is a connection failure, not a timeout, so the
        // bouncer does not retry it.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);
        let loopback = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
        assert_eq!(
            post_json_loopback(&loopback, "/v1/score", b"{}", None, Duration::from_secs(5))
                .unwrap_err(),
            HttpFailure::Connect
        );
    }
}
