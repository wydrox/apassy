//! Loopback fakes of the providers for the tests of unit C2 (plan s6): one thread that
//! accepts a fixed number of connections on `127.0.0.1`, reads one request from each
//! (the client sends `Connection: close`), records it, and answers it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::ProviderEndpoints;
use crate::broker::http::{DestinationUrl, parse_destination};
use crate::native::base64;

/// One request as the fake saw it.
pub(crate) struct Seen {
    pub method: String,
    /// The path and the query.
    pub path: String,
    /// The header fields, the names in lowercase.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Every byte of the request.
    pub raw: Vec<u8>,
}

impl Seen {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }

    /// The token of `Authorization: Bearer <token>`.
    pub(crate) fn bearer(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ")
    }

    /// The user and the password of `Authorization: Basic …`, each form-decoded.
    pub(crate) fn basic(&self) -> Option<(String, String)> {
        let encoded = self.header("authorization")?.strip_prefix("Basic ")?;
        let decoded = String::from_utf8(base64::decode(encoded)?).ok()?;
        let (user, password) = decoded.split_once(':')?;
        Some((percent_decode(user), percent_decode(password)))
    }

    /// The pairs of a form body, decoded, in their order.
    pub(crate) fn form(&self) -> Vec<(String, String)> {
        let text = std::str::from_utf8(&self.body).expect("form body is ASCII");
        if text.is_empty() {
            return Vec::new();
        }
        text.split('&')
            .map(|pair| {
                let (name, value) = pair.split_once('=').expect("name=value");
                (percent_decode(name), percent_decode(value))
            })
            .collect()
    }

    pub(crate) fn form_value(&self, name: &str) -> Option<String> {
        self.form()
            .into_iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value)
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON body")
    }
}

/// What the fake answers to one request.
pub(crate) struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    pub(crate) fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            body: body.to_string(),
        }
    }

    pub(crate) fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_owned(),
        }
    }
}

/// A fake that answers `count` requests in order with `answer(index, &seen)`. The
/// handle gives every request it saw.
pub(crate) fn fake(
    count: usize,
    answer: impl Fn(usize, &Seen) -> Reply + Send + 'static,
) -> (DestinationUrl, JoinHandle<Vec<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("loopback");
    let handle = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for index in 0..count {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let request = read_request(&mut stream);
            let reply = answer(index, &request);
            let response = format!(
                "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                reply.status,
                reply.body.len(),
                reply.body
            );
            stream.write_all(response.as_bytes()).expect("write");
            seen.push(request);
        }
        seen
    });
    (destination, handle)
}

/// The endpoints of a test: every provider at `destination`.
pub(crate) fn endpoints(destination: DestinationUrl) -> ProviderEndpoints {
    ProviderEndpoints::all_at(destination)
}

/// Endpoints that must not be called: a listener that is never accepted. After the
/// test, `listener.accept()` must fail (no connection waits).
pub(crate) fn untouched() -> (ProviderEndpoints, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let destination = parse_destination(&format!("http://127.0.0.1:{port}")).expect("loopback");
    (ProviderEndpoints::all_at(destination), listener)
}

/// A deadline for one exchange of a test.
pub(crate) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn read_request(stream: &mut TcpStream) -> Seen {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        let read = stream.read(&mut chunk).expect("read");
        raw.extend_from_slice(&chunk[..read]);
        if let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |value| value.trim().parse::<usize>().expect("length"));
            if raw.len() >= end + 4 + length {
                break end;
            }
        }
        assert!(read > 0, "the request ended early");
    };
    let head = String::from_utf8(raw[..end].to_vec()).expect("ASCII head");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut parts = request_line.split(' ');
    let method = parts.next().expect("method").to_owned();
    let path = parts.next().expect("path").to_owned();
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').expect("header");
            (name.trim().to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    Seen {
        method,
        path,
        headers,
        body: raw[end + 4..].to_vec(),
        raw,
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex");
            out.push(u8::from_str_radix(hex, 16).expect("hex"));
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).expect("UTF-8")
}
