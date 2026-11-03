//! The loopback LocalAPI of tsnet (`tailscale_loopback`): HTTP on 127.0.0.1 with
//! the header `Sec-Tailscale: localapi` and the credential as the Basic password.
//! The spike checks with it that the loopback path answers status and WhoIs; the
//! node itself uses the in-memory LocalAPI and opens no TCP port for it.

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::{Error, Peer, Result, Status, redact};

/// The host name that the Tailscale clients send (`apitype.LocalAPIHost`).
const LOCAL_API_HOST: &str = "local-tailscaled.sock";
/// A status of a node with many peers stays far below this.
const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

pub struct LoopbackApi {
    addr: SocketAddr,
    credential: Zeroizing<String>,
}

impl fmt::Debug for LoopbackApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackApi")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl LoopbackApi {
    pub(crate) fn new(addr: SocketAddr, credential: Zeroizing<String>) -> Self {
        Self { addr, credential }
    }

    /// The loopback address (127.0.0.1 and a free port).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `GET path` → (HTTP status, body). HTTP/1.0, so the body ends with the connection.
    pub fn get(&self, path: &str) -> Result<(u16, String)> {
        if !path.starts_with("/localapi/") || path.bytes().any(|byte| byte <= b' ') {
            return Err(Error::InvalidOption {
                option: "LocalAPI path",
                reason: "must start with /localapi/ and have no spaces".to_owned(),
            });
        }
        let mut stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut userpass = Zeroizing::new(String::with_capacity(self.credential.len() + 1));
        userpass.push(':');
        userpass.push_str(&self.credential);
        let authorization = Zeroizing::new(base64(userpass.as_bytes()));
        let request = Zeroizing::new(format!(
            "GET {path} HTTP/1.0\r\nHost: {LOCAL_API_HOST}\r\nSec-Tailscale: localapi\r\n\
             Authorization: Basic {}\r\nConnection: close\r\n\r\n",
            authorization.as_str()
        ));
        stream.write_all(request.as_bytes())?;
        let mut response = Vec::new();
        stream.take(MAX_RESPONSE).read_to_end(&mut response)?;
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| Error::LocalApi {
                path: path.to_owned(),
                status: 0,
                body: "the answer has no header end".to_owned(),
            })?;
        let head = String::from_utf8_lossy(&response[..split]);
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = String::from_utf8_lossy(&response[split + 4..]).into_owned();
        Ok((status, body))
    }

    fn get_200(&self, path: &str) -> Result<String> {
        match self.get(path)? {
            (200, body) => Ok(body),
            (status, body) => Err(Error::LocalApi {
                path: path.to_owned(),
                status,
                body: redact(body.trim()).chars().take(300).collect(),
            }),
        }
    }

    /// `/localapi/v0/status`.
    pub fn status(&self) -> Result<Status> {
        Status::parse(&self.get_200("/localapi/v0/status")?)
    }

    /// `/localapi/v0/whois?addr=<ip>`.
    pub fn whois(&self, addr: IpAddr) -> Result<Peer> {
        let path = format!("/localapi/v0/whois?addr={addr}");
        match self.get(&path)? {
            (200, body) => Peer::parse(&body),
            (404, _) => Err(Error::NotFound(addr)),
            (status, body) => Err(Error::LocalApi {
                path,
                status,
                body: redact(body.trim()).chars().take(300).collect(),
            }),
        }
    }
}

/// Standard base64 with padding (RFC 4648), for the Basic header.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        out.push(char::from(ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(ALPHABET[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_matches_rfc_4648() {
        for (input, output) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), output);
        }
    }
}
