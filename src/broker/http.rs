//! Minimal HTTP/1.1 GET client for connector destinations (ADR 0005).
//!
//! `https://` uses rustls with the macOS trust store. Plain `http://` is
//! permitted only on loopback addresses. The client sends no agent-controlled
//! header, follows no redirect, and reads at most 64 KiB.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response that the client reads, headers included.
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
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {bearer}\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n",
        host = destination.host_header(),
    );
    let raw = match destination {
        DestinationUrl::Loopback { addr, .. } => {
            let mut stream = connect(&[*addr])?;
            exchange(&mut stream, request.as_bytes())
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
            exchange(&mut stream, request.as_bytes())
        }
    };
    let mut request = request.into_bytes();
    request.fill(0);
    raw
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
    if is_tls || err.kind() == io::ErrorKind::InvalidData {
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
}
