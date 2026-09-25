//! Minimal HTTP/1.1 GET client for loopback destinations only.
//!
//! This phase has no TLS client (ADR 0004). The client refuses every host that
//! is not a loopback literal. It sends no agent-controlled header.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response that the client reads, headers included.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A parsed loopback base URL such as `http://127.0.0.1:8787`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackBase {
    addr: SocketAddr,
    host_header: String,
}

impl LoopbackBase {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Accept only `http://127.0.0.1:PORT`, `http://localhost:PORT`, or `http://[::1]:PORT`.
pub fn parse_loopback_base(url: &str) -> Result<LoopbackBase, &'static str> {
    let rest = url
        .trim()
        .strip_prefix("http://")
        .ok_or("The destination must start with http:// in this phase.")?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#', '@']) || authority.is_empty() {
        return Err("The destination must be a host and a port, with no path.");
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or("The destination must have a port.")?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or("The destination port is not valid.")?;
    let ip = match host {
        "127.0.0.1" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        "[::1]" => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => return Err("Only loopback destinations are permitted in this phase."),
    };
    Ok(LoopbackBase {
        addr: SocketAddr::new(ip, port),
        host_header: format!("{host}:{port}"),
    })
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Send one GET request with a bearer token. `path` must be pre-validated ASCII.
pub fn get(base: &LoopbackBase, path: &str, bearer: &str) -> io::Result<HttpResponse> {
    if !path.starts_with('/') || path.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad path"));
    }
    if bearer.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad token"));
    }
    let mut stream = TcpStream::connect_timeout(&base.addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {bearer}\r\nAccept: application/json\r\nUser-Agent: apassy-broker/0\r\nConnection: close\r\n\r\n",
        host = base.host_header,
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> io::Result<HttpResponse> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP response");
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(invalid)?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| invalid())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(invalid)?;
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(invalid());
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(invalid)?;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" {
            // Chunked bodies are not supported by this minimal client.
            return Err(invalid());
        }
        if name == "content-length" {
            content_length = Some(value.parse::<usize>().map_err(|_| invalid())?);
        }
    }
    let mut body = raw[split + 4..].to_vec();
    if let Some(length) = content_length {
        if body.len() < length {
            return Err(invalid());
        }
        body.truncate(length);
    }
    Ok(HttpResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_only() {
        assert!(parse_loopback_base("http://127.0.0.1:8787").is_ok());
        assert!(parse_loopback_base("http://localhost:8787/").is_ok());
        assert!(parse_loopback_base("http://[::1]:8787").is_ok());
        for bad in [
            "https://127.0.0.1:8787",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://10.0.0.1:80",
            "http://reporting.example.invalid:443",
            "http://127.0.0.1:8787/v1",
            "http://user@127.0.0.1:8787",
            "http://127.0.0.2:8787",
        ] {
            assert!(parse_loopback_base(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn response_parse() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra";
        let response = parse_response(raw).expect("parse");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{}");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(parse_response(b"garbage").is_err());
    }
}
