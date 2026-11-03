//! Minimal HTTP/1.1 client for connector destinations (ADR 0005) and the
//! bouncer decision model (ADR 0007, ADR 0035).
//!
//! `https://` uses rustls with the macOS trust store. Plain `http://` is
//! permitted only on loopback addresses. The client sends no agent-controlled
//! header, follows no redirect, and reads at most 64 KiB of a JSON answer.
//! [`send`] is the general request of the way C lease providers (implementation
//! plan s6, unit B): form or JSON bodies, the caller's own headers, `PUT` and
//! `DELETE`, and the response headers. The
//! head-file transfers of the bouncer brain ([`put_file`], [`get_to_file`]) stream
//! the file, with their own caps and a progress deadline.

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
    /// The `Host` header value that the client sends: the host, with the port
    /// unless it is 443 for `https://`. A SigV4 signer signs this value.
    pub fn host_header(&self) -> String {
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

/// One response. The body and the header values can hold a provider's secret
/// (a lease, a token), so `Debug` shows the status, the header names, and the
/// body length only.
pub struct HttpResponse {
    pub status: u16,
    /// The response header fields in their order: the name in lowercase, the
    /// value without surrounding white space. A repeated field is repeated here.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The value of the first header field `name` (any case), if there is one.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &names)
            .field("body_bytes", &self.body.len())
            .finish()
    }
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
    send_with(
        destination,
        &HttpRequest::new(Method::Get, path),
        deadline,
        tls,
        resolve,
    )
}

fn is_request_path(path: &str) -> bool {
    path.starts_with('/') && path.bytes().all(|b| (0x21..0x7f).contains(&b))
}

fn is_bearer(bearer: &str) -> bool {
    !bearer.is_empty() && bearer.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// The methods of [`request_json`] and [`send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    /// `PUT` with a short body. A head file goes up with [`put_file`].
    Put,
    Delete,
}

impl Method {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Get => b"GET",
            Self::Post => b"POST",
            Self::Put => b"PUT",
            Self::Delete => b"DELETE",
        }
    }

    /// `POST` and `PUT` carry a body (`Content-Length: 0` without one). `GET`
    /// and `DELETE` never do: a body with them is a protocol failure.
    fn takes_body(self) -> bool {
        matches!(self, Self::Post | Self::Put)
    }
}

/// Send one request with a bearer token and an optional JSON body, and read the
/// JSON response before `deadline`: name lookup, connect, TLS handshake, request,
/// and response (ADR 0035). The bouncer brain uses it for `GET` and `DELETE` of
/// `/v1/heads/<sha256>` and `DELETE /v1/owner`. Only `POST` and `PUT` have a
/// body; a body with `GET` or `DELETE` is a protocol failure. The TLS rules and
/// the 64 KiB caps are the ones of [`send`], which this wraps with the bearer
/// and a JSON body; the bytes are the ones of [`send`]. Unlike [`get`], the name
/// lookup has the deadline too.
#[allow(clippy::too_many_arguments)]
pub fn request_json(
    method: Method,
    destination: &DestinationUrl,
    path: &str,
    bearer: &str,
    body: Option<&[u8]>,
    deadline: Instant,
    tls: Option<&TlsClient>,
) -> Result<HttpResponse, HttpFailure> {
    request_json_with(
        method,
        destination,
        path,
        bearer,
        body,
        deadline,
        tls,
        system_resolve,
    )
}

#[allow(clippy::too_many_arguments)]
fn request_json_with(
    method: Method,
    destination: &DestinationUrl,
    path: &str,
    bearer: &str,
    body: Option<&[u8]>,
    deadline: Instant,
    tls: Option<&TlsClient>,
    resolve: Resolve,
) -> Result<HttpResponse, HttpFailure> {
    // A missing bearer is a protocol failure here; `send` permits none.
    if !is_bearer(bearer) {
        return Err(HttpFailure::Protocol);
    }
    let request = HttpRequest {
        bearer: Some(bearer),
        body: body.map(Body::Json),
        ..HttpRequest::new(method, path)
    };
    send_with(destination, &request, deadline, tls, resolve)
}

/// Largest request body of [`send`]. A larger one is [`HttpFailure::TooLarge`]
/// before any connection. Chosen by implementation plan s6 (unit B): the largest
/// provider body of way C is a few KiB (an STS session policy is at most 2 KiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
/// Most extra header fields of one [`send`] request.
pub const MAX_REQUEST_HEADERS: usize = 32;
/// Longest extra header name of [`send`].
const MAX_HEADER_NAME_BYTES: usize = 64;
/// Longest extra header value of [`send`]. An `X-Amz-Security-Token` or a
/// SigV4 `Authorization` value is far shorter.
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
/// Longest path and query of [`send`].
const MAX_PATH_BYTES: usize = 8 * 1024;

/// The header fields that the client writes itself. An extra header with one
/// of these names is a protocol failure: they decide the framing or the
/// connection, or they name the destination.
const CLIENT_HEADERS: [&str; 11] = [
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "user-agent",
];

/// The body of a [`send`] request, with the `Content-Type` that it sets.
#[derive(Clone, Copy)]
pub enum Body<'a> {
    /// `Content-Type: application/json`.
    Json(&'a [u8]),
    /// `Content-Type: application/x-www-form-urlencoded`. Build the bytes with
    /// [`form_body`], so a signer (SigV4) can hash the exact bytes that are sent.
    Form(&'a [u8]),
}

impl<'a> Body<'a> {
    fn content_type(self) -> &'static [u8] {
        match self {
            Self::Json(_) => b"application/json",
            Self::Form(_) => b"application/x-www-form-urlencoded",
        }
    }

    fn bytes(self) -> &'a [u8] {
        match self {
            Self::Json(bytes) | Self::Form(bytes) => bytes,
        }
    }
}

/// One request of [`send`]. The caller owns every value; the client copies them
/// once into the request buffer, which it erases after the exchange.
///
/// `Debug` shows the method, the path without its query, the header names, and
/// the body length: never the bearer, a header value, or a body byte.
#[derive(Clone, Copy)]
pub struct HttpRequest<'a> {
    pub method: Method,
    /// The path and the query, already percent-encoded: printable ASCII that
    /// starts with `/`, at most 8 KiB.
    pub path: &'a str,
    /// `Authorization: Bearer <token>`. With a bearer, an extra `Authorization`
    /// header is a protocol failure.
    pub bearer: Option<&'a str>,
    /// Extra header fields, sent in this order after `Host` and the bearer. A
    /// name is an HTTP token (at most 64 bytes); a value is printable ASCII
    /// without surrounding spaces (at most 8 KiB); a name appears at most once
    /// (any case); at most 32 fields. An `Accept` field replaces the default
    /// `Accept: application/json`. The names that the client writes itself are
    /// refused: `Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`,
    /// `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Expect`, and
    /// `User-Agent`.
    pub headers: &'a [(&'a str, &'a str)],
    /// The body. Only `POST` and `PUT` take one; at most 64 KiB.
    pub body: Option<Body<'a>>,
}

impl<'a> HttpRequest<'a> {
    /// A request with no bearer, no extra header, and no body.
    pub const fn new(method: Method, path: &'a str) -> Self {
        Self {
            method,
            path,
            bearer: None,
            headers: &[],
            body: None,
        }
    }
}

impl std::fmt::Debug for HttpRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self
            .path
            .split_once('?')
            .map_or(self.path, |(path, _)| path);
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| *name).collect();
        let body = self.body.map(|body| match body {
            Body::Json(bytes) => ("json", bytes.len()),
            Body::Form(bytes) => ("form", bytes.len()),
        });
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &path)
            .field("bearer", &self.bearer.is_some())
            .field("headers", &names)
            .field("body", &body)
            .finish()
    }
}

/// Encode `pairs` as an `application/x-www-form-urlencoded` body: `name=value`
/// joined by `&`, each byte outside the RFC 3986 unreserved set
/// (`A-Z a-z 0-9 - . _ ~`) as `%XX` with uppercase hex, a space as `%20`. This
/// is also the `UriEncode` of AWS SigV4. The buffer has the exact size and is
/// erased when dropped, because a value can be a secret (a refresh token).
pub fn form_body(pairs: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    fn encoded_len(text: &str) -> usize {
        text.bytes()
            .map(|byte| if is_unreserved(byte) { 1 } else { 3 })
            .sum()
    }
    fn push_encoded(out: &mut Vec<u8>, text: &str) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for byte in text.bytes() {
            if is_unreserved(byte) {
                out.push(byte);
            } else {
                out.extend_from_slice(&[
                    b'%',
                    HEX[usize::from(byte >> 4)],
                    HEX[usize::from(byte & 0x0f)],
                ]);
            }
        }
    }
    let size = pairs
        .iter()
        .map(|(name, value)| encoded_len(name) + 1 + encoded_len(value))
        .sum::<usize>()
        + pairs.len().saturating_sub(1);
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push(b'&');
        }
        push_encoded(&mut out, name);
        out.push(b'=');
        push_encoded(&mut out, value);
    }
    out
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// An HTTP field name (RFC 9110 `token`), at most 64 bytes.
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HEADER_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// A header value: printable ASCII and spaces, no control character (no CR, LF,
/// NUL, or tab), no space at either end, at most 8 KiB. It may be empty.
fn is_header_value(value: &str) -> bool {
    value.len() <= MAX_HEADER_VALUE_BYTES
        && value.bytes().all(|byte| (0x20..0x7f).contains(&byte))
        && !value.starts_with(' ')
        && !value.ends_with(' ')
}

/// Check the extra headers of `request`. Returns whether they hold an `Accept`.
fn check_headers(request: &HttpRequest<'_>) -> Result<bool, HttpFailure> {
    if request.headers.len() > MAX_REQUEST_HEADERS {
        return Err(HttpFailure::Protocol);
    }
    let mut accept = false;
    for (index, (name, value)) in request.headers.iter().enumerate() {
        if !is_header_name(name) || !is_header_value(value) {
            return Err(HttpFailure::Protocol);
        }
        if CLIENT_HEADERS
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(HttpFailure::Protocol);
        }
        if name.eq_ignore_ascii_case("authorization") && request.bearer.is_some() {
            return Err(HttpFailure::Protocol);
        }
        if request.headers[..index]
            .iter()
            .any(|(earlier, _)| earlier.eq_ignore_ascii_case(name))
        {
            return Err(HttpFailure::Protocol);
        }
        accept |= name.eq_ignore_ascii_case("accept");
    }
    Ok(accept)
}

/// Send one request and read its response before `deadline`: name lookup,
/// connect, TLS handshake, request, and response, all within the one deadline
/// (a caller that makes several calls for one result, such as a lease, passes
/// the same deadline to each). The way C lease providers (implementation plan
/// s6) use it for form and JSON bodies, their own headers (`X-Amz-Date`, a SigV4
/// `Authorization`, `Accept: application/vnd.github+json`), `PUT`, and `DELETE`.
///
/// The rules are the ones of [`post_json`]: `https://` needs `tls` and sends no
/// byte before the handshake and the certificate check succeed; plain `http://`
/// only to the loopback; the response, headers included, at most 64 KiB
/// ([`MAX_RESPONSE_BYTES`]), else [`HttpFailure::TooLarge`]. The client follows
/// no redirect: a 3xx is returned as it is, with its `Location` in
/// [`HttpResponse::headers`]. A request that breaks a rule of [`HttpRequest`] is
/// [`HttpFailure::Protocol`], and a body over 64 KiB is
/// [`HttpFailure::TooLarge`], both before any connection. No failure value holds
/// a byte of the request or the response.
///
/// The request is `<METHOD> <path> HTTP/1.1`, `Host`, the bearer, the extra
/// headers in their order, `Content-Type` and `Content-Length` (or
/// `Content-Length: 0` for a `POST` or `PUT` without a body), `Accept:
/// application/json` unless an extra `Accept` is given, `User-Agent:
/// apassy-broker/0`, and `Connection: close`. A signer that signs `host` uses
/// [`DestinationUrl::host_header`].
pub fn send(
    destination: &DestinationUrl,
    request: &HttpRequest<'_>,
    deadline: Instant,
    tls: Option<&TlsClient>,
) -> Result<HttpResponse, HttpFailure> {
    send_with(destination, request, deadline, tls, system_resolve)
}

fn send_with(
    destination: &DestinationUrl,
    request: &HttpRequest<'_>,
    deadline: Instant,
    tls: Option<&TlsClient>,
    resolve: Resolve,
) -> Result<HttpResponse, HttpFailure> {
    if !is_request_path(request.path) || request.path.len() > MAX_PATH_BYTES {
        return Err(HttpFailure::Protocol);
    }
    if request.bearer.is_some_and(|bearer| !is_bearer(bearer)) {
        return Err(HttpFailure::Protocol);
    }
    if request.body.is_some() && !request.method.takes_body() {
        return Err(HttpFailure::Protocol);
    }
    let has_accept = check_headers(request)?;
    if request
        .body
        .is_some_and(|body| body.bytes().len() > MAX_REQUEST_BODY_BYTES)
    {
        return Err(HttpFailure::TooLarge);
    }
    let host = destination.host_header();
    let length = request.body.map(|body| body.bytes().len().to_string());
    let mut parts: Vec<&[u8]> = Vec::with_capacity(16 + 4 * request.headers.len());
    parts.extend_from_slice(&[
        request.method.as_bytes(),
        b" ",
        request.path.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\n",
    ]);
    if let Some(bearer) = request.bearer {
        parts.extend_from_slice(&[b"Authorization: Bearer ", bearer.as_bytes(), b"\r\n"]);
    }
    for (name, value) in request.headers {
        parts.extend_from_slice(&[name.as_bytes(), b": ", value.as_bytes(), b"\r\n"]);
    }
    match (request.body, &length) {
        (Some(body), Some(length)) => parts.extend_from_slice(&[
            b"Content-Type: ",
            body.content_type(),
            b"\r\nContent-Length: ",
            length.as_bytes(),
            b"\r\n",
        ]),
        _ if request.method.takes_body() => parts.push(b"Content-Length: 0\r\n"),
        _ => {}
    }
    if !has_accept {
        parts.push(b"Accept: application/json\r\n");
    }
    parts.push(b"User-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n");
    if let Some(body) = request.body {
        parts.push(body.bytes());
    }
    let bytes = request_bytes(&parts);
    drop(parts);
    send_before(destination, &bytes, deadline, tls, resolve)
}

/// Largest head file that [`put_file`] sends (contract bouncer-brain-v1 section 5).
pub const MAX_UPLOAD_BYTES: u64 = 160 * 1024 * 1024;
/// Largest body that [`get_to_file`] writes.
pub const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
/// Largest encoded `Apassy-Manifest` header (contract section 5).
pub const MAX_MANIFEST_HEADER_BYTES: usize = 16 * 1024;
/// A transfer that moves no byte for this long fails with [`HttpFailure::Timeout`].
/// Chosen by implementation plan 0035; the owner can change it.
pub const TRANSFER_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest time of one whole transfer. Chosen by implementation plan 0035; the
/// owner can change it.
pub const TRANSFER_TOTAL_LIMIT: Duration = Duration::from_secs(15 * 60);
/// The buffer of one read from the file or the socket during a transfer.
const TRANSFER_BUFFER: usize = 64 * 1024;
/// Longest chunk-size line or trailer line of a chunked download.
const MAX_CHUNK_LINE: u64 = 1024;
/// Most trailer lines after the last chunk of a chunked download.
const MAX_TRAILER_LINES: usize = 32;

/// The limits of one transfer. Tests use small values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransferLimits {
    max_bytes: u64,
    progress: Duration,
    total: Duration,
}

impl TransferLimits {
    const UPLOAD: Self = Self {
        max_bytes: MAX_UPLOAD_BYTES,
        progress: TRANSFER_PROGRESS_TIMEOUT,
        total: TRANSFER_TOTAL_LIMIT,
    };
    const DOWNLOAD: Self = Self {
        max_bytes: MAX_DOWNLOAD_BYTES,
        progress: TRANSFER_PROGRESS_TIMEOUT,
        total: TRANSFER_TOTAL_LIMIT,
    };
}

/// Why a file transfer failed. None of these values contains the token.
#[derive(Debug)]
pub enum TransferFailure {
    /// The transport failed. [`HttpFailure::TooLarge`]: the file or the body is
    /// over the cap. [`HttpFailure::Timeout`]: the progress deadline or the total
    /// limit ended.
    Http(HttpFailure),
    /// A download answered with a status other than 200. The body is at most
    /// 64 KiB; no file was written.
    Status(HttpResponse),
    /// The downloaded bytes do not have the expected SHA-256. The file is deleted.
    WrongHash,
    /// The local file could not be read, created, or written.
    File,
}

impl From<HttpFailure> for TransferFailure {
    fn from(failure: HttpFailure) -> Self {
        Self::Http(failure)
    }
}

/// Upload one file with `PUT` (contract bouncer-brain-v1 section 5): the file as
/// `application/octet-stream` with its `Content-Length`, `manifest` as the
/// `Apassy-Manifest` header (base64url without padding), and
/// `Expect: 100-continue`. The client sends no body byte before `100 Continue`. A
/// final response that arrives instead is the answer, and no body byte is sent.
/// A file over 160 MiB or an encoded manifest over 16 KiB is
/// [`HttpFailure::TooLarge`] before any connection. The transfer fails after
/// 30 s without a byte and after 15 min in total. If the connection ends during
/// the body, the result is unknown: the caller checks with `GET`.
pub fn put_file(
    destination: &DestinationUrl,
    path: &str,
    bearer: &str,
    file: &std::path::Path,
    manifest: &[u8],
    tls: Option<&TlsClient>,
) -> Result<HttpResponse, TransferFailure> {
    put_file_with(
        destination,
        path,
        bearer,
        file,
        manifest,
        tls,
        TransferLimits::UPLOAD,
        system_resolve,
    )
}

#[allow(clippy::too_many_arguments)]
fn put_file_with(
    destination: &DestinationUrl,
    path: &str,
    bearer: &str,
    file: &std::path::Path,
    manifest: &[u8],
    tls: Option<&TlsClient>,
    limits: TransferLimits,
    resolve: Resolve,
) -> Result<HttpResponse, TransferFailure> {
    if !is_request_path(path) || !is_bearer(bearer) {
        return Err(HttpFailure::Protocol.into());
    }
    let encoded = crate::sync::relay_crypto::encode_b64u(manifest);
    if encoded.len() > MAX_MANIFEST_HEADER_BYTES {
        return Err(HttpFailure::TooLarge.into());
    }
    let mut source = std::fs::File::open(file).map_err(|_| TransferFailure::File)?;
    let size = source.metadata().map_err(|_| TransferFailure::File)?.len();
    if size > limits.max_bytes {
        return Err(HttpFailure::TooLarge.into());
    }
    let deadline = Instant::now() + limits.total;
    let host = destination.host_header();
    let length = size.to_string();
    let head = request_bytes(&[
        b"PUT ",
        path.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\nAuthorization: Bearer ",
        bearer.as_bytes(),
        b"\r\nContent-Type: application/octet-stream\r\nContent-Length: ",
        length.as_bytes(),
        b"\r\nApassy-Manifest: ",
        encoded.as_bytes(),
        b"\r\nExpect: 100-continue\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n",
    ]);
    let mut conn = open_before(destination, deadline, Some(limits.progress), tls, resolve)?;
    conn.write_all(&head).map_err(|err| classify(&err))?;
    conn.flush().map_err(|err| classify(&err))?;
    drop(head);
    // Wait for `100 Continue`. A final response instead is the answer.
    let mut raw = Vec::new();
    if let Reply::Final(response) = read_reply(&mut conn, &mut raw, true)? {
        return Ok(response);
    }
    let mut buffer = vec![0u8; TRANSFER_BUFFER];
    let mut sent: u64 = 0;
    while sent < size {
        let want = usize::try_from((size - sent).min(TRANSFER_BUFFER as u64))
            .map_err(|_| TransferFailure::File)?;
        let read = source
            .read(&mut buffer[..want])
            .map_err(|_| TransferFailure::File)?;
        if read == 0 {
            // The file became shorter than its declared length.
            return Err(TransferFailure::File);
        }
        if let Err(err) = conn.write_all(&buffer[..read]) {
            // The server may have answered and closed the connection, for
            // example with 413. Its answer, if it arrived, is the result.
            return match read_reply(&mut conn, &mut raw, false) {
                Ok(Reply::Final(response)) => Ok(response),
                _ => Err(classify(&err).into()),
            };
        }
        sent += read as u64;
    }
    conn.flush().map_err(|err| classify(&err))?;
    match read_reply(&mut conn, &mut raw, false)? {
        Reply::Final(response) => Ok(response),
        Reply::Continue => Err(HttpFailure::Protocol.into()),
    }
}

/// What [`read_reply`] found.
enum Reply {
    /// `100 Continue`: the client may send the body.
    Continue,
    /// A final response.
    Final(HttpResponse),
}

/// Read responses into `raw` until a final one, at most 64 KiB. Interim (1xx)
/// responses are skipped; with `until_continue`, `100 Continue` returns
/// [`Reply::Continue`] and leaves the bytes after it in `raw`.
fn read_reply<S: Read>(
    stream: &mut S,
    raw: &mut Vec<u8>,
    until_continue: bool,
) -> Result<Reply, HttpFailure> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(head) = parse_head(raw)? {
            if (100..200).contains(&head.status) {
                raw.drain(..head.body_start);
                if head.status == 100 && until_continue {
                    return Ok(Reply::Continue);
                }
                continue;
            }
            if let Some(response) = complete_response(raw)? {
                return Ok(Reply::Final(response));
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) => return finish_at_eof(raw).map(Reply::Final),
            Ok(read) => {
                raw.extend_from_slice(&chunk[..read]);
                if raw.len() > MAX_RESPONSE_BYTES {
                    return Err(HttpFailure::TooLarge);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return finish_at_eof(raw).map(Reply::Final);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(classify(&err)),
        }
    }
}

/// A downloaded file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    /// The number of body bytes in the file.
    pub bytes: u64,
    /// The lowercase hex SHA-256 of the file, computed while it was read.
    pub sha256: String,
}

/// Download the body of a `GET` with a bearer token into a new file `file`
/// (mode 0600; it must not exist yet). The SHA-256 is computed while the body is
/// read. With `expected_sha256`, a different hash deletes the file and is
/// [`TransferFailure::WrongHash`]. A body over 256 MiB is
/// [`HttpFailure::TooLarge`] and deletes the file. A status other than 200 is
/// [`TransferFailure::Status`] and writes no file. The transfer fails after
/// 30 s without a byte and after 15 min in total; a failure deletes the file.
pub fn get_to_file(
    destination: &DestinationUrl,
    path: &str,
    bearer: &str,
    file: &std::path::Path,
    expected_sha256: Option<&str>,
    tls: Option<&TlsClient>,
) -> Result<Downloaded, TransferFailure> {
    get_to_file_with(
        destination,
        path,
        bearer,
        file,
        expected_sha256,
        tls,
        TransferLimits::DOWNLOAD,
        system_resolve,
    )
}

#[allow(clippy::too_many_arguments)]
fn get_to_file_with(
    destination: &DestinationUrl,
    path: &str,
    bearer: &str,
    file: &std::path::Path,
    expected_sha256: Option<&str>,
    tls: Option<&TlsClient>,
    limits: TransferLimits,
    resolve: Resolve,
) -> Result<Downloaded, TransferFailure> {
    if !is_request_path(path) || !is_bearer(bearer) {
        return Err(HttpFailure::Protocol.into());
    }
    let deadline = Instant::now() + limits.total;
    let host = destination.host_header();
    let request = request_bytes(&[
        b"GET ",
        path.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\nAuthorization: Bearer ",
        bearer.as_bytes(),
        b"\r\nAccept: application/octet-stream, application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n",
    ]);
    let mut conn = open_before(destination, deadline, Some(limits.progress), tls, resolve)?;
    conn.write_all(&request).map_err(|err| classify(&err))?;
    conn.flush().map_err(|err| classify(&err))?;
    drop(request);
    // Read the head of the final response.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let head = loop {
        if let Some(head) = parse_head(&raw)? {
            if (100..200).contains(&head.status) {
                raw.drain(..head.body_start);
                continue;
            }
            break head;
        }
        match conn.read(&mut chunk) {
            Ok(0) => return Err(HttpFailure::Protocol.into()),
            Ok(read) => {
                raw.extend_from_slice(&chunk[..read]);
                if raw.len() > MAX_RESPONSE_BYTES {
                    return Err(HttpFailure::TooLarge.into());
                }
            }
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(HttpFailure::Protocol.into());
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(classify(&err).into()),
        }
    };
    if head.status != 200 {
        // A short error body, read with the cap of a JSON answer.
        return match read_reply(&mut conn, &mut raw, false)? {
            Reply::Final(response) => Err(TransferFailure::Status(response)),
            Reply::Continue => Err(HttpFailure::Protocol.into()),
        };
    }
    if let BodyKind::Length(length) = head.kind
        && length as u64 > limits.max_bytes
    {
        return Err(HttpFailure::TooLarge.into());
    }
    let leftover = raw.split_off(head.body_start);
    drop(raw);
    let mut out = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(file)
            .map_err(|_| TransferFailure::File)?
    };
    let mut body = io::BufReader::with_capacity(
        TRANSFER_BUFFER,
        Prefixed {
            prefix: io::Cursor::new(leftover),
            rest: &mut conn,
        },
    );
    let mut sink = HashingFile {
        file: &mut out,
        digest: ring::digest::Context::new(&ring::digest::SHA256),
        bytes: 0,
        max_bytes: limits.max_bytes,
    };
    let copied = copy_body(&mut body, head.kind, &mut sink).and_then(|()| {
        sink.file.sync_all().map_err(|_| TransferFailure::File)?;
        Ok(())
    });
    let bytes = sink.bytes;
    let sha256 = hex_lower(sink.digest.finish().as_ref());
    drop(out);
    let outcome = copied.and_then(|()| match expected_sha256 {
        Some(expected) if expected != sha256 => Err(TransferFailure::WrongHash),
        _ => Ok(Downloaded { bytes, sha256 }),
    });
    if outcome.is_err() {
        let _ = std::fs::remove_file(file);
    }
    outcome
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The bytes that arrived with the response head, then the rest of the stream.
struct Prefixed<'a, S> {
    prefix: io::Cursor<Vec<u8>>,
    rest: &'a mut S,
}

impl<S: Read> Read for Prefixed<'_, S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buffer)?;
        if read > 0 || buffer.is_empty() {
            return Ok(read);
        }
        self.rest.read(buffer)
    }
}

/// The download file with the running SHA-256 and the byte cap.
struct HashingFile<'a> {
    file: &'a mut std::fs::File,
    digest: ring::digest::Context,
    bytes: u64,
    max_bytes: u64,
}

impl HashingFile<'_> {
    fn take(&mut self, data: &[u8]) -> Result<(), TransferFailure> {
        self.bytes += data.len() as u64;
        if self.bytes > self.max_bytes {
            return Err(HttpFailure::TooLarge.into());
        }
        self.digest.update(data);
        self.file.write_all(data).map_err(|_| TransferFailure::File)
    }
}

/// A read error of a download body. An early end is a protocol failure.
fn body_failure(err: &io::Error) -> TransferFailure {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        HttpFailure::Protocol.into()
    } else {
        classify(err).into()
    }
}

/// Copy `count` body bytes into `sink`. An early end is a protocol failure.
fn copy_exact<R: Read>(
    body: &mut R,
    mut count: u64,
    sink: &mut HashingFile<'_>,
) -> Result<(), TransferFailure> {
    let mut buffer = vec![0u8; TRANSFER_BUFFER];
    while count > 0 {
        let want = usize::try_from(count.min(TRANSFER_BUFFER as u64))
            .map_err(|_| TransferFailure::from(HttpFailure::Protocol))?;
        match body.read(&mut buffer[..want]) {
            Ok(0) => return Err(HttpFailure::Protocol.into()),
            Ok(read) => {
                sink.take(&buffer[..read])?;
                count -= read as u64;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(body_failure(&err)),
        }
    }
    Ok(())
}

/// One CRLF-terminated line of a chunked body, at most [`MAX_CHUNK_LINE`] bytes,
/// without the CRLF.
fn chunk_line<R: io::BufRead>(body: &mut R) -> Result<Vec<u8>, TransferFailure> {
    use std::io::BufRead as _;
    let mut line = Vec::new();
    body.by_ref()
        .take(MAX_CHUNK_LINE)
        .read_until(b'\n', &mut line)
        .map_err(|err| body_failure(&err))?;
    if !line.ends_with(b"\r\n") {
        return Err(HttpFailure::Protocol.into());
    }
    line.truncate(line.len() - 2);
    Ok(line)
}

/// Copy the body of a 200 response into `sink`, by its framing.
fn copy_body<R: io::BufRead>(
    body: &mut R,
    kind: BodyKind,
    sink: &mut HashingFile<'_>,
) -> Result<(), TransferFailure> {
    match kind {
        BodyKind::Length(length) => copy_exact(body, length as u64, sink),
        BodyKind::UntilClose => {
            let mut buffer = vec![0u8; TRANSFER_BUFFER];
            loop {
                match body.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(read) => sink.take(&buffer[..read])?,
                    // A server can close TLS without close_notify. Treat it as end of data.
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => return Err(classify(&err).into()),
                }
            }
        }
        BodyKind::Chunked => {
            loop {
                let line = chunk_line(body)?;
                let line = std::str::from_utf8(&line).map_err(|_| HttpFailure::Protocol)?;
                let size_text = line.split(';').next().unwrap_or_default().trim();
                let size = u64::from_str_radix(size_text, 16).map_err(|_| HttpFailure::Protocol)?;
                if size > sink.max_bytes.saturating_sub(sink.bytes) {
                    return Err(HttpFailure::TooLarge.into());
                }
                if size == 0 {
                    break;
                }
                copy_exact(body, size, sink)?;
                if !chunk_line(body)?.is_empty() {
                    return Err(HttpFailure::Protocol.into());
                }
            }
            // Trailers end with an empty line. This client ignores trailer fields.
            for _ in 0..MAX_TRAILER_LINES {
                if chunk_line(body)?.is_empty() {
                    return Ok(());
                }
            }
            Err(HttpFailure::Protocol.into())
        }
    }
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
    let mut conn = open_before(destination, deadline, None, tls, resolve)?;
    exchange(&mut conn, request)
}

/// Open a connection to `destination` before `deadline`: name lookup, connect,
/// and, for `https://`, the whole TLS handshake. No request byte is sent here.
/// With `idle`, every socket operation also stops after `idle` without a byte
/// (the progress deadline of a transfer), and the setup stops after `idle`.
fn open_before(
    destination: &DestinationUrl,
    deadline: Instant,
    idle: Option<Duration>,
    tls: Option<&TlsClient>,
    resolve: Resolve,
) -> Result<Conn, HttpFailure> {
    let setup = idle.map_or(deadline, |idle| deadline.min(Instant::now() + idle));
    match destination {
        DestinationUrl::Loopback { addr, .. } => {
            // The fields are public. Plain http:// never leaves this computer,
            // also for a value that does not come from `parse_destination`.
            if !addr.ip().is_loopback() {
                return Err(HttpFailure::Protocol);
            }
            let stream = connect_before(&[*addr], setup)?;
            Ok(Conn::Plain(DeadlineStream {
                stream,
                deadline,
                idle,
            }))
        }
        DestinationUrl::Https { host, port } => {
            let tls = tls.ok_or(HttpFailure::Protocol)?;
            let name = ServerName::try_from(host.clone()).map_err(|_| HttpFailure::Protocol)?;
            let addrs = resolve_before(host, *port, setup, resolve)?;
            let stream = connect_before(&addrs, setup)?;
            let conn = ClientConnection::new(Arc::clone(&tls.config), name)
                .map_err(|_| HttpFailure::Tls)?;
            let mut stream = StreamOwned::new(
                conn,
                DeadlineStream {
                    stream,
                    deadline,
                    idle,
                },
            );
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
            Ok(Conn::Tls(Box::new(stream)))
        }
    }
}

/// An open connection: plain loopback or TLS.
enum Conn {
    Plain(DeadlineStream),
    Tls(Box<StreamOwned<ClientConnection, DeadlineStream>>),
}

impl Read for Conn {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// Refresh the socket limit before every operation, so fragmented responses cannot
/// extend a bouncer request beyond its total exchange budget. Under TLS it also
/// limits the handshake.
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
    /// The longest wait of one socket operation of a transfer: a transfer that
    /// moves no byte for this long fails. `None` for a short exchange.
    idle: Option<Duration>,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
        Ok(self.idle.map_or(left, |idle| left.min(idle)))
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
    // The answer can hold a provider's secret (a lease, a token). The buffer has
    // room for the whole capped answer, so it never grows and leaves no partial
    // copy in freed memory; `Zeroizing` erases it and the read chunk on return.
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES + EXCHANGE_CHUNK));
    let mut chunk = Zeroizing::new([0u8; EXCHANGE_CHUNK]);
    loop {
        if let Some(response) = complete_response(&raw)? {
            return Ok(response);
        }
        match stream.read(&mut chunk[..]) {
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

/// One socket read of [`exchange`].
const EXCHANGE_CHUNK: usize = 4096;

enum BodyKind {
    Length(usize),
    Chunked,
    UntilClose,
}

struct Head {
    status: u16,
    body_start: usize,
    kind: BodyKind,
    /// The header fields: the name in lowercase, the value trimmed.
    headers: Vec<(String, String)>,
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
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(HttpFailure::Protocol)?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        headers.push((name.clone(), value.to_owned()));
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
        headers,
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
            headers: head.headers,
            body: body[..length].to_vec(),
        })),
        BodyKind::Chunked => Ok(decode_chunked(body)?.map(|body| HttpResponse {
            status: head.status,
            headers: head.headers,
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
            headers: head.headers,
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

/// The test PKI of the TLS tests of this module and of the bouncer client.
#[cfg(test)]
pub(crate) mod test_support {
    use super::TlsClient;
    use std::sync::Arc;

    /// A local HTTPS service for `localhost` with its own test root. The client
    /// trusts that root in addition to the platform roots.
    pub(crate) struct TestTls {
        pub(crate) config: Arc<rustls::ServerConfig>,
        pub(crate) client: TlsClient,
    }

    pub(crate) fn test_tls() -> TestTls {
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
}

#[cfg(test)]
mod tests {
    use super::test_support::test_tls;
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

    /// Small limits for the transfer tests.
    fn test_limits(max_bytes: u64, progress: Duration, total: Duration) -> TransferLimits {
        TransferLimits {
            max_bytes,
            progress,
            total,
        }
    }

    /// Read from `stream` until the end of a request head. Returns the head text and
    /// the bytes that arrived after it.
    fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&seen[..end]).into_owned();
                return (head, seen[end + 4..].to_vec());
            }
            let read = stream.read(&mut buf).expect("read head");
            assert!(read > 0, "the request ended before its head");
            seen.extend_from_slice(&buf[..read]);
        }
    }

    /// Bytes that arrive in `wait`, until the end of the stream or the wait.
    fn bytes_within(stream: &mut TcpStream, wait: Duration) -> Vec<u8> {
        stream.set_read_timeout(Some(wait)).expect("read timeout");
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        let began = Instant::now();
        while began.elapsed() < wait {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => seen.extend_from_slice(&buf[..read]),
            }
        }
        seen
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_lower(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
    }

    /// A synthetic head file: a byte pattern, no model data.
    fn synthetic_file(dir: &std::path::Path, size: usize) -> (std::path::PathBuf, Vec<u8>) {
        let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let path = dir.join("candidate.safetensors");
        std::fs::write(&path, &content).expect("write file");
        (path, content)
    }

    const MANIFEST: &[u8] = br#"{"name":"synthetic-heads","checkpoint":{"sha256":"0000"}}"#;
    const BRAIN_KEY: &str = "synthetic-brain-key-not-a-secret";

    #[test]
    fn a_bearer_request_has_one_deadline_and_no_body_for_get_or_delete() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
        let server = capture_one_request(listener);
        let hash = "a".repeat(64);
        let path = format!("/v1/heads/{hash}");
        let response = request_json(
            Method::Delete,
            &destination,
            &path,
            BRAIN_KEY,
            None,
            Instant::now() + Duration::from_secs(5),
            None,
        )
        .expect("delete");
        assert_eq!(response.status, 200);
        assert_eq!(
            String::from_utf8(server.join().expect("server")).expect("text"),
            format!(
                "DELETE {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {BRAIN_KEY}\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n"
            )
        );
        // A body with GET or DELETE, a missing bearer, or a bad path sends nothing.
        for (method, bearer, body, path) in [
            (Method::Get, BRAIN_KEY, Some(&b"{}"[..]), "/v1/heads/x"),
            (Method::Delete, BRAIN_KEY, Some(&b"{}"[..]), "/v1/owner"),
            (Method::Get, "", None, "/v1/heads/x"),
            (Method::Get, "a b", None, "/v1/heads/x"),
            (Method::Get, BRAIN_KEY, None, "v1/heads/x"),
        ] {
            assert_eq!(
                request_json(
                    method,
                    &destination,
                    path,
                    bearer,
                    body,
                    Instant::now() + Duration::from_secs(5),
                    None,
                )
                .unwrap_err(),
                HttpFailure::Protocol,
                "{method:?} {path}"
            );
        }
        // The name lookup has the deadline too (unlike `get`).
        let pki = test_tls();
        let remote = DestinationUrl::Https {
            host: "brain.example.invalid".to_owned(),
            port: 443,
        };
        let timeout = Duration::from_millis(300);
        let began = Instant::now();
        assert_eq!(
            request_json_with(
                Method::Get,
                &remote,
                &path,
                BRAIN_KEY,
                None,
                began + timeout,
                Some(&pki.client),
                resolve_slowly,
            )
            .unwrap_err(),
            HttpFailure::Timeout
        );
        assert!(began.elapsed() < timeout + Duration::from_secs(1));
    }

    #[test]
    fn an_upload_sends_no_body_before_100_continue() {
        assert_eq!(MAX_UPLOAD_BYTES, 160 * 1024 * 1024);
        assert_eq!(MAX_MANIFEST_HEADER_BYTES, 16 * 1024);
        let dir = tempfile::tempdir().expect("temp dir");
        let (file, content) = synthetic_file(dir.path(), 200 * 1024);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
        let size = content.len();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let (head, mut early) = read_head(&mut stream);
            // The client waits for `100 Continue`: nothing more arrives before it.
            early.extend(bytes_within(&mut stream, Duration::from_millis(400)));
            stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .expect("continue");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout");
            let mut body = early.clone();
            let mut buf = [0u8; 16 * 1024];
            while body.len() < size {
                let read = stream.read(&mut buf).expect("body");
                assert!(read > 0, "the body ended early");
                body.extend_from_slice(&buf[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}")
                .expect("answer");
            (head, early, body)
        });
        let path = format!("/v1/heads/{}", sha256_hex(&content));
        let response = put_file_with(
            &destination,
            &path,
            BRAIN_KEY,
            &file,
            MANIFEST,
            None,
            test_limits(
                MAX_UPLOAD_BYTES,
                Duration::from_secs(5),
                Duration::from_secs(30),
            ),
            system_resolve,
        )
        .expect("upload");
        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"{}");
        let (head, early, body) = server.join().expect("server");
        assert!(early.is_empty(), "{} body bytes before 100", early.len());
        assert_eq!(body, content);
        let manifest = crate::sync::relay_crypto::encode_b64u(MANIFEST);
        assert_eq!(
            head,
            format!(
                "PUT {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {BRAIN_KEY}\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\nApassy-Manifest: {manifest}\r\nExpect: 100-continue\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close"
            )
        );

        // A file over the cap and a manifest header over 16 KiB fail before any
        // connection: nothing listens at port 9.
        let nowhere = parse_destination("http://127.0.0.1:9").expect("url");
        let small = test_limits(1024, Duration::from_secs(5), Duration::from_secs(30));
        assert!(matches!(
            put_file_with(
                &nowhere,
                &path,
                BRAIN_KEY,
                &file,
                MANIFEST,
                None,
                small,
                system_resolve
            ),
            Err(TransferFailure::Http(HttpFailure::TooLarge))
        ));
        let large_manifest = vec![b'a'; MAX_MANIFEST_HEADER_BYTES];
        assert!(matches!(
            put_file(&nowhere, &path, BRAIN_KEY, &file, &large_manifest, None),
            Err(TransferFailure::Http(HttpFailure::TooLarge))
        ));
        assert!(matches!(
            put_file(
                &nowhere,
                &path,
                BRAIN_KEY,
                &dir.path().join("missing"),
                MANIFEST,
                None
            ),
            Err(TransferFailure::File)
        ));
    }

    #[test]
    fn an_early_final_response_stops_the_upload() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (file, _) = synthetic_file(dir.path(), 512 * 1024);
        for answer in [
            &b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}"[..],
            &b"HTTP/1.1 409 Conflict\r\nContent-Length: 2\r\n\r\n{}"[..],
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("url");
            let reply = answer.to_vec();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let (_head, mut after) = read_head(&mut stream);
                // A final response instead of `100 Continue`.
                stream.write_all(&reply).expect("answer");
                after.extend(bytes_within(&mut stream, Duration::from_millis(500)));
                after
            });
            let response = put_file_with(
                &destination,
                "/v1/heads/0000",
                BRAIN_KEY,
                &file,
                MANIFEST,
                None,
                test_limits(
                    MAX_UPLOAD_BYTES,
                    Duration::from_secs(5),
                    Duration::from_secs(30),
                ),
                system_resolve,
            )
            .expect("final response");
            let status: u16 = String::from_utf8_lossy(&answer[9..12])
                .parse()
                .expect("status");
            assert_eq!(response.status, status);
            let after = server.join().expect("server");
            assert!(
                after.is_empty(),
                "status {status}: {} body bytes after the final response",
                after.len()
            );
        }
    }

    /// Accept one connection, read the request head, write `answer`, and close.
    fn answer_once(
        listener: std::net::TcpListener,
        answer: Vec<u8>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_head(&mut stream);
            let _ = stream.write_all(&answer);
        })
    }

    fn loopback_listener() -> (std::net::TcpListener, DestinationUrl) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination =
            parse_destination(&format!("http://{}", listener.local_addr().expect("addr")))
                .expect("url");
        (listener, destination)
    }

    #[test]
    fn a_download_over_the_cap_is_too_large() {
        assert_eq!(MAX_DOWNLOAD_BYTES, 256 * 1024 * 1024);
        let dir = tempfile::tempdir().expect("temp dir");
        let limits = test_limits(1024, Duration::from_secs(5), Duration::from_secs(30));
        // A declared length over the cap, over TLS: refused before any file.
        let pki = test_tls();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let destination = localhost_https(&listener);
        let mut answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n".to_vec();
        answer.resize(answer.len() + 2048, b'a');
        let (_release, held) = mpsc::channel();
        let server = answer_one_tls_request(listener, Arc::clone(&pki.config), Some(answer), held);
        let target = dir.path().join("declared.bin");
        assert!(matches!(
            get_to_file_with(
                &destination,
                "/v1/train/1/result",
                BRAIN_KEY,
                &target,
                None,
                Some(&pki.client),
                limits,
                resolve_to_this_computer,
            ),
            Err(TransferFailure::Http(HttpFailure::TooLarge))
        ));
        let seen = String::from_utf8(server.join().expect("server")).expect("text");
        assert!(
            seen.starts_with("GET /v1/train/1/result HTTP/1.1\r\n"),
            "{seen}"
        );
        assert!(
            !target.exists(),
            "no file for a declared length over the cap"
        );

        // A chunked body and a body until close that grow over the cap: the file is
        // deleted.
        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..3 {
            chunked.extend_from_slice(b"200\r\n");
            chunked.resize(chunked.len() + 0x200, b'b');
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        let mut until_close = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        until_close.resize(until_close.len() + 2048, b'c');
        for (name, answer) in [("chunked", chunked), ("until close", until_close)] {
            let (listener, destination) = loopback_listener();
            let server = answer_once(listener, answer);
            let target = dir.path().join(format!("{name}.bin"));
            let result = get_to_file_with(
                &destination,
                "/v1/train/1/result",
                BRAIN_KEY,
                &target,
                None,
                None,
                limits,
                system_resolve,
            );
            assert!(
                matches!(result, Err(TransferFailure::Http(HttpFailure::TooLarge))),
                "{name}: {result:?}"
            );
            server.join().expect("server");
            assert!(!target.exists(), "{name}: the partial file is deleted");
        }
    }

    #[test]
    fn a_download_with_a_wrong_hash_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temp dir");
        let content = b"synthetic head file bytes, not a model".to_vec();
        let right = sha256_hex(&content);
        let wrong = sha256_hex(b"another synthetic file");
        let limits = test_limits(1024, Duration::from_secs(5), Duration::from_secs(30));
        let length_answer = {
            let mut answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                content.len()
            )
            .into_bytes();
            answer.extend_from_slice(&content);
            answer
        };
        let chunked_answer = {
            let mut answer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            let (first, second) = content.split_at(10);
            for part in [first, second] {
                answer.extend_from_slice(format!("{:x};x=1\r\n", part.len()).as_bytes());
                answer.extend_from_slice(part);
                answer.extend_from_slice(b"\r\n");
            }
            answer.extend_from_slice(b"0\r\nX-Trailer: 1\r\n\r\n");
            answer
        };
        for (name, answer) in [("length", length_answer), ("chunked", chunked_answer)] {
            let (listener, destination) = loopback_listener();
            let server = answer_once(listener, answer.clone());
            let target = dir.path().join(format!("{name}-wrong.bin"));
            let result = get_to_file_with(
                &destination,
                "/v1/train/1/result",
                BRAIN_KEY,
                &target,
                Some(&wrong),
                None,
                limits,
                system_resolve,
            );
            assert!(
                matches!(result, Err(TransferFailure::WrongHash)),
                "{name}: {result:?}"
            );
            server.join().expect("server");
            assert!(!target.exists(), "{name}: a wrong file is deleted");

            let (listener, destination) = loopback_listener();
            let server = answer_once(listener, answer);
            let target = dir.path().join(format!("{name}-right.bin"));
            let downloaded = get_to_file_with(
                &destination,
                "/v1/train/1/result",
                BRAIN_KEY,
                &target,
                Some(&right),
                None,
                limits,
                system_resolve,
            )
            .expect("download");
            server.join().expect("server");
            assert_eq!(
                downloaded,
                Downloaded {
                    bytes: content.len() as u64,
                    sha256: right.clone(),
                },
                "{name}"
            );
            assert_eq!(std::fs::read(&target).expect("file"), content, "{name}");
            let mode = std::fs::metadata(&target)
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
            // The file must be new: an existing file is not overwritten.
            let (listener, destination) = loopback_listener();
            let server = answer_once(
                listener,
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nother".to_vec(),
            );
            assert!(matches!(
                get_to_file_with(
                    &destination,
                    "/v1/train/1/result",
                    BRAIN_KEY,
                    &target,
                    None,
                    None,
                    limits,
                    system_resolve,
                ),
                Err(TransferFailure::File)
            ));
            server.join().expect("server");
            assert_eq!(std::fs::read(&target).expect("file"), content, "{name}");
        }

        // A status other than 200 writes no file and gives the short body.
        let (listener, destination) = loopback_listener();
        let server = answer_once(
            listener,
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 25\r\n\r\n{\"detail\":{\"code\":\"x\"}}  "
                .to_vec(),
        );
        let target = dir.path().join("missing.bin");
        match get_to_file_with(
            &destination,
            "/v1/train/1/result",
            BRAIN_KEY,
            &target,
            Some(&right),
            None,
            limits,
            system_resolve,
        ) {
            Err(TransferFailure::Status(response)) => {
                assert_eq!(response.status, 404);
                assert_eq!(response.body, br#"{"detail":{"code":"x"}}  "#);
            }
            other => panic!("a 404 gave {other:?}"),
        }
        server.join().expect("server");
        assert!(!target.exists());
    }

    #[test]
    fn a_stalled_transfer_fails_at_the_progress_deadline() {
        assert_eq!(TRANSFER_PROGRESS_TIMEOUT, Duration::from_secs(30));
        assert_eq!(TRANSFER_TOTAL_LIMIT, Duration::from_secs(15 * 60));
        let dir = tempfile::tempdir().expect("temp dir");
        let progress = Duration::from_millis(300);
        let limits = test_limits(1024 * 1024, progress, Duration::from_secs(30));

        // A download that stops after part of its body.
        let (listener, destination) = loopback_listener();
        let (release, held) = mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_head(&mut stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
            let _ = held.recv_timeout(Duration::from_secs(10));
        });
        let target = dir.path().join("stalled.bin");
        let began = Instant::now();
        let result = get_to_file_with(
            &destination,
            "/v1/train/1/result",
            BRAIN_KEY,
            &target,
            None,
            None,
            limits,
            system_resolve,
        );
        let elapsed = began.elapsed();
        release.send(()).expect("release");
        server.join().expect("server");
        assert!(
            matches!(result, Err(TransferFailure::Http(HttpFailure::Timeout))),
            "{result:?}"
        );
        assert!(elapsed < progress + Duration::from_secs(1), "{elapsed:?}");
        assert!(!target.exists(), "the partial file is deleted");

        // An upload whose server never sends `100 Continue`: no body byte, a timeout.
        let (file, _) = synthetic_file(dir.path(), 4096);
        let (listener, destination) = loopback_listener();
        let (release, held) = mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let (_head, mut after) = read_head(&mut stream);
            after.extend(bytes_within(&mut stream, Duration::from_millis(800)));
            let _ = held.recv_timeout(Duration::from_secs(10));
            after
        });
        let began = Instant::now();
        let result = put_file_with(
            &destination,
            "/v1/heads/0000",
            BRAIN_KEY,
            &file,
            MANIFEST,
            None,
            limits,
            system_resolve,
        );
        let elapsed = began.elapsed();
        release.send(()).expect("release");
        assert!(
            matches!(result, Err(TransferFailure::Http(HttpFailure::Timeout))),
            "{result:?}"
        );
        assert!(elapsed < progress + Duration::from_secs(1), "{elapsed:?}");
        assert!(server.join().expect("server").is_empty(), "no body byte");

        // Bytes that keep coming, each before the progress deadline, still stop at
        // the total limit.
        let (listener, destination) = loopback_listener();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_head(&mut stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n");
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(100));
                if stream.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let total = Duration::from_millis(700);
        let target = dir.path().join("trickle.bin");
        let began = Instant::now();
        let result = get_to_file_with(
            &destination,
            "/v1/train/1/result",
            BRAIN_KEY,
            &target,
            None,
            None,
            test_limits(1024 * 1024, progress, total),
            system_resolve,
        );
        let elapsed = began.elapsed();
        assert!(
            matches!(result, Err(TransferFailure::Http(HttpFailure::Timeout))),
            "{result:?}"
        );
        assert!(elapsed < total + Duration::from_secs(1), "{elapsed:?}");
        assert!(!target.exists());
        server.join().expect("server");
    }
}
