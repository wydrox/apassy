//! Track proxy: the connection to an upstream host and its response head.
//!
//! The TLS client follows `TlsClient::build` of `src/broker/http.rs` and the
//! `open_service` handshake of `src/broker/proxy/mod.rs` of wydrox/apassy at rev
//! 77f6628 (Apache-2.0): rustls with ring, the platform verifier, and a finished
//! handshake before the first request byte.
//!
//! HTTPS only, HTTP/1.1, one connection per request (`Connection: close`).

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use zeroize::Zeroizing;

use super::stream::{BodyLen, Conn};
use crate::config::UpstreamOptions;
use crate::error::{RelayError, RelayResult};

/// A finished TLS connection to an upstream host.
pub(super) type ServiceStream = StreamOwned<ClientConnection, TcpStream>;

/// The buffered connection.
pub(super) type ServiceConn = Conn<ServiceStream>;

/// How the relay reaches upstream hosts. One per relay.
pub(super) struct Upstream {
    config: Arc<ClientConfig>,
    options: UpstreamOptions,
}

/// Why an upstream exchange failed. The text names no value.
#[derive(Debug)]
pub(super) struct UpstreamError(pub &'static str);

impl From<io::Error> for UpstreamError {
    fn from(_: io::Error) -> Self {
        Self("The upstream connection failed.")
    }
}

impl Upstream {
    /// The system roots (rustls-platform-verifier), plus `options.extra_roots_der`.
    pub fn new(options: &UpstreamOptions) -> RelayResult<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = if options.extra_roots_der.is_empty() {
            rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
        } else {
            let roots: Vec<CertificateDer<'static>> = options
                .extra_roots_der
                .iter()
                .map(|der| CertificateDer::from(der.clone()))
                .collect();
            rustls_platform_verifier::Verifier::new_with_extra_roots(roots, Arc::clone(&provider))
        }
        .map_err(|_| RelayError::internal("The system certificate roots cannot be loaded."))?;
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| RelayError::internal("The TLS protocol versions cannot be set."))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
            options: options.clone(),
        })
    }

    /// The addresses of a host. A fixed address of the options (tests) is used as it
    /// is. From DNS, only public addresses are kept: a team must not reach the relay's
    /// own machine, its networks, or other services on them (ADR 0019).
    fn addresses(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, UpstreamError> {
        if let Some((_, _, addr)) = self
            .options
            .resolve
            .iter()
            .find(|(name, fixed_port, _)| name == host && *fixed_port == port)
        {
            return Ok(vec![*addr]);
        }
        let found: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
        let public: Vec<SocketAddr> = found
            .iter()
            .copied()
            .filter(|addr| is_public_ip(addr.ip()))
            .collect();
        if public.is_empty() && !found.is_empty() {
            return Err(UpstreamError("The upstream host has no public address."));
        }
        Ok(public)
    }

    /// Opens TCP, and finishes the TLS handshake with SNI `host`. No request byte
    /// goes out before the handshake is done and the certificate is checked.
    pub fn connect(&self, host: &str, port: u16) -> Result<ServiceConn, UpstreamError> {
        let tcp = self
            .addresses(host, port)?
            .into_iter()
            .find_map(|addr| TcpStream::connect_timeout(&addr, self.options.connect_timeout).ok())
            .ok_or(UpstreamError("The upstream host cannot be reached."))?;
        tcp.set_read_timeout(Some(self.options.io_timeout))?;
        tcp.set_write_timeout(Some(self.options.io_timeout))?;
        let _ = tcp.set_nodelay(true);
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| UpstreamError("The host name is not valid."))?;
        let conn = ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(|_| UpstreamError("The TLS client cannot start."))?;
        let mut stream = StreamOwned::new(conn, tcp);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|_| UpstreamError("The TLS handshake with the upstream host failed."))?;
        }
        Ok(Conn::new(stream))
    }
}

/// What the relay sends: a swapped request. Values sit in `Zeroizing` buffers.
pub(super) struct UpstreamRequest<'a> {
    pub method: &'a str,
    pub target: &'a str,
    /// `host` or `host:port`, the `Host` header.
    pub authority: &'a str,
    pub headers: &'a [(String, Zeroizing<String>)],
    pub body: &'a [u8],
}

/// Writes the request head and body. The head is built in a buffer that is erased.
pub(super) fn send_request(
    conn: &mut ServiceConn,
    request: &UpstreamRequest<'_>,
) -> io::Result<()> {
    let mut head = Zeroizing::new(Vec::with_capacity(512));
    head.extend_from_slice(request.method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(request.target.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    head.extend_from_slice(request.authority.as_bytes());
    head.extend_from_slice(b"\r\n");
    for (name, value) in request.headers {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n");
    let has_body_method = ["POST", "PUT", "PATCH"]
        .iter()
        .any(|method| request.method.eq_ignore_ascii_case(method));
    if !request.body.is_empty() || has_body_method {
        head.extend_from_slice(format!("Content-Length: {}\r\n", request.body.len()).as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    conn.inner.write_all(&head)?;
    conn.inner.write_all(request.body)?;
    conn.inner.flush()
}

/// A parsed response head, before the values are put back to placeholders.
pub(super) struct ResponseHead {
    pub status: u16,
    /// Header names and raw values, in order. Values may hold a real value.
    pub headers: Vec<(String, Zeroizing<Vec<u8>>)>,
    pub body: BodyLen,
    /// The value of `Content-Length`, if the head has a valid one.
    pub content_length: Option<u64>,
    /// `Content-Encoding` is present and is not `identity`.
    pub encoded: bool,
}

/// Reads the response head. Skips `100 Continue` and other 1xx heads. A `101` comes
/// back as it is, and the caller refuses it.
pub(super) fn read_response_head(
    conn: &mut ServiceConn,
    method: &str,
) -> Result<ResponseHead, UpstreamError> {
    loop {
        let raw = conn
            .read_head()
            .map_err(|_| UpstreamError("The upstream response head could not be read."))?;
        let mut slots = [httparse::EMPTY_HEADER; 100];
        let mut response = httparse::Response::new(&mut slots);
        match response.parse(&raw) {
            Ok(httparse::Status::Complete(_)) => {}
            _ => return Err(UpstreamError("The upstream response head is not valid.")),
        }
        if response.version != Some(1) {
            return Err(UpstreamError("The upstream response is not HTTP/1.1."));
        }
        let status = response
            .code
            .filter(|code| (100..600).contains(code))
            .ok_or(UpstreamError("The upstream status is not valid."))?;
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        let headers: Vec<(String, Zeroizing<Vec<u8>>)> = response
            .headers
            .iter()
            .map(|header| {
                (
                    header.name.to_owned(),
                    Zeroizing::new(header.value.to_vec()),
                )
            })
            .collect();
        return framing(status, headers, method);
    }
}

fn header_text<'a>(headers: &'a [(String, Zeroizing<Vec<u8>>)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .filter_map(|(_, value)| std::str::from_utf8(value).ok())
        .collect()
}

fn framing(
    status: u16,
    headers: Vec<(String, Zeroizing<Vec<u8>>)>,
    method: &str,
) -> Result<ResponseHead, UpstreamError> {
    let mut content_length = None;
    for value in header_text(&headers, "content-length") {
        for part in value.split(',') {
            let part = part.trim();
            let parsed: u64 = part
                .parse()
                .ok()
                .filter(|_| part.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(UpstreamError("The upstream Content-Length is not valid."))?;
            if content_length.is_some_and(|known| known != parsed) {
                return Err(UpstreamError(
                    "The upstream sent two Content-Length values.",
                ));
            }
            content_length = Some(parsed);
        }
    }
    let codings: Vec<String> = header_text(&headers, "transfer-encoding")
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty())
        .collect();
    let body = if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        BodyLen::None
    } else if !codings.is_empty() {
        if codings.last().is_some_and(|last| last == "chunked") {
            BodyLen::Chunked
        } else {
            BodyLen::UntilClose
        }
    } else {
        match content_length {
            Some(0) => BodyLen::None,
            Some(length) => BodyLen::Length(length),
            None => BodyLen::UntilClose,
        }
    };
    let encoded = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("content-encoding"))
        .any(|(_, value)| {
            std::str::from_utf8(value)
                .map(|text| !text.trim().eq_ignore_ascii_case("identity"))
                .unwrap_or(true)
        });
    Ok(ResponseHead {
        status,
        headers,
        body,
        content_length,
        encoded,
    })
}

/// True for an address on the public internet. False for loopback, private, link-local,
/// CGNAT, unique-local, multicast, documentation, benchmark, reserved, and unspecified
/// addresses, and for IPv6 forms that carry such an IPv4 address.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let segments = ip.segments();
    // 64:ff9b::/96 (NAT64) carries an IPv4 address in its last 32 bits.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., hi, lo] = segments;
        return is_public_v4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[..6] == [0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_pass() {
        for text in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "::127.0.0.1",
        ] {
            assert!(!is_public_ip(text.parse().unwrap()), "{text}");
        }
        for text in [
            "1.1.1.1",
            "9.9.9.117",
            "2620:fe::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(is_public_ip(text.parse().unwrap()), "{text}");
        }
    }

    fn head_of(text: &str, method: &str) -> ResponseHead {
        let mut slots = [httparse::EMPTY_HEADER; 100];
        let mut response = httparse::Response::new(&mut slots);
        assert!(matches!(
            response.parse(text.as_bytes()),
            Ok(httparse::Status::Complete(_))
        ));
        let headers = response
            .headers
            .iter()
            .map(|h| (h.name.to_owned(), Zeroizing::new(h.value.to_vec())))
            .collect();
        framing(response.code.unwrap(), headers, method).expect("framing")
    }

    #[test]
    fn response_framing() {
        assert_eq!(
            head_of("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", "GET").body,
            BodyLen::Length(3)
        );
        let head = head_of("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", "HEAD");
        assert_eq!(head.body, BodyLen::None);
        assert_eq!(head.content_length, Some(3));
        assert_eq!(
            head_of(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                "GET"
            )
            .body,
            BodyLen::Chunked
        );
        assert_eq!(
            head_of("HTTP/1.1 200 OK\r\n\r\n", "GET").body,
            BodyLen::UntilClose
        );
        assert_eq!(
            head_of("HTTP/1.1 204 No Content\r\n\r\n", "GET").body,
            BodyLen::None
        );
        assert_eq!(
            head_of(
                "HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n",
                "GET"
            )
            .body,
            BodyLen::None
        );
        assert_eq!(
            head_of("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "GET").body,
            BodyLen::None
        );
    }

    #[test]
    fn content_encoding_other_than_identity_is_encoded() {
        assert!(head_of("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n", "GET").encoded);
        assert!(
            !head_of(
                "HTTP/1.1 200 OK\r\nContent-Encoding: Identity\r\n\r\n",
                "GET"
            )
            .encoded
        );
        assert!(!head_of("HTTP/1.1 200 OK\r\n\r\n", "GET").encoded);
    }

    #[test]
    fn bad_lengths_are_errors() {
        let bad = |text: &str| {
            let mut slots = [httparse::EMPTY_HEADER; 100];
            let mut response = httparse::Response::new(&mut slots);
            response.parse(text.as_bytes()).expect("parse");
            let headers = response
                .headers
                .iter()
                .map(|h| (h.name.to_owned(), Zeroizing::new(h.value.to_vec())))
                .collect();
            framing(200, headers, "GET").is_err()
        };
        assert!(bad(
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"
        ));
        assert!(bad("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"));
        assert!(bad("HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\n"));
    }
}
