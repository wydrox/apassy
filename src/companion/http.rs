//! The strict HTTP/1.1 framing of the companion listener (contract companion-v1,
//! section 3).
//!
//! The listener reads one request from a connection and closes it after the answer.
//! The reader is small and strict, because the listener is reachable from the local
//! network:
//!
//! - The request line and the headers are at most 8 KiB (`413`).
//! - A body needs `Content-Length` and is at most 16 KiB (`413`).
//! - A `GET` or a `DELETE` with a body is refused with `400` before the body is read.
//! - `Transfer-Encoding`, HTTP/1.0, a folded header, a repeated `Content-Length`, a
//!   repeated `X-Apassy-*` header, a control character, and a byte outside ASCII are
//!   refused with `400`. The signature covers the bytes of the request, so two readers
//!   must not read two different requests from the same bytes.
//! - The head has a total deadline, and the body has its own total deadline. A peer that
//!   sends one byte at a time does not get more time.
//!
//! The reader does not know sockets: a stream sets its own deadline through [`Timed`].
//! The proxy parser in `broker::proxy::http1` has other limits and stays as it is.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use super::wire::{ErrorBody, ErrorCode};

/// The request line and the headers, with the empty line, are at most this long.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// A body is at most this long.
pub const MAX_BODY_BYTES: usize = 16 * 1024;
/// The request target is at most this long.
const MAX_TARGET_BYTES: usize = 2048;
const MAX_HEADERS: usize = 64;
const READ_CHUNK: usize = 4096;

/// How long the listener waits for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// From accept to the end of the headers. It includes the TLS handshake.
    pub head: Duration,
    /// From the end of the headers to the last byte of the body.
    pub body: Duration,
    /// For the answer.
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            head: Duration::from_secs(10),
            body: Duration::from_secs(5),
            write: Duration::from_secs(5),
        }
    }
}

/// A stream with a deadline for the reads that follow. A read that passes the deadline
/// fails with `TimedOut`, also when the peer sent a byte just before.
pub trait Timed: Read {
    fn set_deadline(&mut self, at: Instant);
}

/// One request. Header names are lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The request target as sent, for example `/v1/runs/123/approve`.
    pub target: String,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The value of a header. `name` is lowercase.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Why no request was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFailure {
    /// The request is refused with this answer. The body may not be read.
    Refuse(ErrorCode),
    /// The connection failed, ended, or ran out of time. There is nothing to answer.
    Drop,
}

/// The head of a request, before its body.
#[derive(Debug)]
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    content_length: usize,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Parse a head that ends with the empty line.
fn parse_head(raw: &[u8]) -> Result<Head, ErrorCode> {
    // Only printable ASCII, and a horizontal tab in a value. A bare CR or LF is a
    // control character, so it is refused here.
    let text = raw.strip_suffix(b"\r\n\r\n").ok_or(ErrorCode::BadRequest)?;
    if !text
        .iter()
        .all(|b| matches!(b, b'\r' | b'\n' | b'\t' | 0x20..=0x7e))
    {
        return Err(ErrorCode::BadRequest);
    }
    let text = std::str::from_utf8(text).map_err(|_| ErrorCode::BadRequest)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(ErrorCode::BadRequest)?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ErrorCode::BadRequest);
    };
    if version != "HTTP/1.1"
        || method.is_empty()
        || method.len() > 16
        || !method.bytes().all(token_char)
        || !target.starts_with('/')
        || target.len() > MAX_TARGET_BYTES
    {
        return Err(ErrorCode::BadRequest);
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS
            || line.contains(['\r', '\n'])
            || line.starts_with([' ', '\t'])
        {
            return Err(ErrorCode::BadRequest);
        }
        let (name, value) = line.split_once(':').ok_or(ErrorCode::BadRequest)?;
        if name.is_empty() || !name.bytes().all(token_char) {
            return Err(ErrorCode::BadRequest);
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    if headers.iter().any(|(name, _)| name == "transfer-encoding") {
        return Err(ErrorCode::BadRequest);
    }
    for (index, (name, _)) in headers.iter().enumerate() {
        let single = name == "content-length" || name.starts_with("x-apassy-");
        if single && headers[..index].iter().any(|(earlier, _)| earlier == name) {
            return Err(ErrorCode::BadRequest);
        }
    }
    let content_length = match headers.iter().find(|(name, _)| name == "content-length") {
        None => 0,
        Some((_, value)) => {
            if value.is_empty() || value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ErrorCode::BadRequest);
            }
            match value.parse::<usize>() {
                Ok(length) if length <= MAX_BODY_BYTES => length,
                _ => return Err(ErrorCode::TooLarge),
            }
        }
    };
    if content_length > 0 && matches!(method, "GET" | "DELETE") {
        return Err(ErrorCode::BadRequest);
    }
    Ok(Head {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
        content_length,
    })
}

/// Read one request: the head under the head deadline, then the body under the body
/// deadline. Bytes after the body are ignored: the connection closes after the answer.
pub fn read_request<S: Timed>(stream: &mut S, timeouts: &Timeouts) -> Result<Request, ReadFailure> {
    stream.set_deadline(Instant::now() + timeouts.head);
    let mut buffer: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let head_end = loop {
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() >= MAX_HEAD_BYTES {
            return Err(ReadFailure::Refuse(ErrorCode::TooLarge));
        }
        read_more(stream, &mut buffer)?;
    };
    if head_end > MAX_HEAD_BYTES {
        return Err(ReadFailure::Refuse(ErrorCode::TooLarge));
    }
    let head = parse_head(&buffer[..head_end]).map_err(ReadFailure::Refuse)?;
    stream.set_deadline(Instant::now() + timeouts.body);
    let mut body = buffer.split_off(head_end);
    body.truncate(head.content_length);
    while body.len() < head.content_length {
        let mut chunk = [0u8; READ_CHUNK];
        let want = (head.content_length - body.len()).min(READ_CHUNK);
        match stream.read(&mut chunk[..want]) {
            Ok(0) | Err(_) => return Err(ReadFailure::Drop),
            Ok(read) => body.extend_from_slice(&chunk[..read]),
        }
    }
    Ok(Request {
        method: head.method,
        target: head.target,
        headers: head.headers,
        body,
    })
}

fn read_more<S: Read>(stream: &mut S, buffer: &mut Vec<u8>) -> Result<(), ReadFailure> {
    let mut chunk = [0u8; READ_CHUNK];
    match stream.read(&mut chunk) {
        Ok(0) | Err(_) => Err(ReadFailure::Drop),
        Ok(read) => {
            buffer.extend_from_slice(&chunk[..read]);
            Ok(())
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Content Too Large",
        423 => "Locked",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    }
}

/// An answer: a status and a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    /// A `200` with a JSON body. A value that cannot be serialized gives `internal`.
    pub fn json<T: serde::Serialize>(value: &T) -> Self {
        match serde_json::to_string(value) {
            Ok(body) => Self { status: 200, body },
            Err(_) => Self::error(ErrorCode::Internal),
        }
    }

    /// The error with the standard message of `code`.
    pub fn error(code: ErrorCode) -> Self {
        Self::from_body(code, &ErrorBody::new(code))
    }

    /// The error with a prepared body.
    pub fn from_body(code: ErrorCode, body: &ErrorBody) -> Self {
        Self {
            status: code.status(),
            body: body.to_json(),
        }
    }
}

/// Write the answer with `Connection: close`.
pub fn write_response<W: Write>(stream: &mut W, response: &Response) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.body.len()
    );
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(response.body.as_bytes());
    stream.write_all(&bytes)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream that gives its bytes in pieces and can fail when they run out.
    struct Script {
        pieces: Vec<Vec<u8>>,
        deadlines: Vec<Instant>,
    }

    impl Script {
        fn new(pieces: &[&[u8]]) -> Self {
            Self {
                pieces: pieces.iter().rev().map(|piece| piece.to_vec()).collect(),
                deadlines: Vec::new(),
            }
        }
    }

    impl Read for Script {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let Some(mut piece) = self.pieces.pop() else {
                return Ok(0);
            };
            let take = piece.len().min(out.len());
            out[..take].copy_from_slice(&piece[..take]);
            if take < piece.len() {
                self.pieces.push(piece.split_off(take));
            }
            Ok(take)
        }
    }

    impl Timed for Script {
        fn set_deadline(&mut self, at: Instant) {
            self.deadlines.push(at);
        }
    }

    fn read(raw: &[u8]) -> Result<Request, ReadFailure> {
        read_request(&mut Script::new(&[raw]), &Timeouts::default())
    }

    fn refused(raw: &[u8]) -> ErrorCode {
        match read(raw) {
            Err(ReadFailure::Refuse(code)) => code,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_plain_request_is_read() {
        let request = read(
            b"POST /v1/pair HTTP/1.1\r\nHost: mac.local\r\nX-Apassy-Device: abc\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/v1/pair");
        assert_eq!(request.header("x-apassy-device"), Some("abc"));
        assert_eq!(request.header("host"), Some("mac.local"));
        assert_eq!(request.body, b"{}");
    }

    #[test]
    fn a_request_in_small_pieces_is_read_and_a_pipelined_tail_is_ignored() {
        let mut stream = Script::new(&[
            b"GET /v1/sta",
            b"tus HTTP/1.1\r\n",
            b"\r",
            b"\n",
            b"GET /next HTTP/1.1\r\n\r\n",
        ]);
        let request = read_request(&mut stream, &Timeouts::default()).expect("request");
        assert_eq!(request.target, "/v1/status");
        assert!(request.body.is_empty());
        assert_eq!(
            stream.deadlines.len(),
            2,
            "one deadline for the head, one for the body"
        );
    }

    #[test]
    fn a_body_is_cut_at_its_length() {
        let request =
            read(b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcdef").expect("request");
        assert_eq!(request.body, b"abc");
    }

    #[test]
    fn a_short_body_or_a_short_head_drops_the_connection() {
        assert_eq!(
            read(b"POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc").unwrap_err(),
            ReadFailure::Drop
        );
        assert_eq!(
            read(b"GET /x HTTP/1.1\r\nHost: a").unwrap_err(),
            ReadFailure::Drop
        );
        assert_eq!(read(b"").unwrap_err(), ReadFailure::Drop);
    }

    #[test]
    fn the_head_limit_is_8_kib() {
        let mut fits = b"GET /x HTTP/1.1\r\nX-Pad: ".to_vec();
        fits.resize(MAX_HEAD_BYTES - 4, b'a');
        fits.extend_from_slice(b"\r\n\r\n");
        assert_eq!(fits.len(), MAX_HEAD_BYTES);
        assert!(read(&fits).is_ok());

        let mut over = b"GET /x HTTP/1.1\r\nX-Pad: ".to_vec();
        over.resize(MAX_HEAD_BYTES - 3, b'a');
        over.extend_from_slice(b"\r\n\r\n");
        assert_eq!(refused(&over), ErrorCode::TooLarge);

        // A head that never ends is refused at the limit, not read forever.
        let endless = vec![b'a'; MAX_HEAD_BYTES * 4];
        assert_eq!(refused(&endless), ErrorCode::TooLarge);
    }

    #[test]
    fn the_body_limit_is_16_kib_and_is_checked_before_the_body() {
        let ok = format!("POST /x HTTP/1.1\r\nContent-Length: {MAX_BODY_BYTES}\r\n\r\n");
        let mut raw = ok.into_bytes();
        raw.extend(std::iter::repeat_n(b'a', MAX_BODY_BYTES));
        assert_eq!(read(&raw).expect("request").body.len(), MAX_BODY_BYTES);
        // No body follows: the refusal comes from the header alone.
        let over = format!(
            "POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert_eq!(refused(over.as_bytes()), ErrorCode::TooLarge);
        assert_eq!(
            refused(b"POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n"),
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn a_request_that_could_be_read_two_ways_is_refused() {
        for raw in [
            &b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            b"POST /x HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: identity\r\n\r\na",
            b"GET /x HTTP/1.0\r\n\r\n",
            b"GET /x HTTP/2.0\r\n\r\n",
            b"GET /x\r\n\r\n",
            b"GET  /x HTTP/1.1\r\n\r\n",
            b"GET /x HTTP/1.1 extra\r\n\r\n",
            b"GET x HTTP/1.1\r\n\r\n",
            b"GET * HTTP/1.1\r\n\r\n",
            b"POST /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
            b"POST /x HTTP/1.1\r\nContent-Length: +1\r\n\r\na",
            b"POST /x HTTP/1.1\r\nContent-Length: 1 2\r\n\r\na",
            b"POST /x HTTP/1.1\r\nContent-Length:\r\n\r\n",
            b"GET /x HTTP/1.1\r\nX-Apassy-Time: 1\r\nx-apassy-time: 2\r\n\r\n",
            b"GET /x HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
            b"GET /x HTTP/1.1\r\nHost a\r\n\r\n",
            b"GET /x HTTP/1.1\r\nHo st: a\r\n\r\n",
            b"GET /x HTTP/1.1\r\n: a\r\n\r\n",
            b"GET /x HTTP/1.1\r\nHost: a\nX: b\r\n\r\n",
            b"GET /x HTTP/1.1\r\nHost: a\rX: b\r\n\r\n",
            b"GET /x\x00 HTTP/1.1\r\n\r\n",
            b"GET /x HTTP/1.1\r\nHost: \x7f\r\n\r\n",
            b"GET /x HTTP/1.1\r\nHost: caf\xc3\xa9\r\n\r\n",
            b"G(T /x HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                refused(raw),
                ErrorCode::BadRequest,
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn a_get_or_a_delete_with_a_body_is_refused_before_the_body() {
        // No body follows: the refusal comes from the head alone.
        for method in ["GET", "DELETE"] {
            let raw = format!("{method} /x HTTP/1.1\r\nContent-Length: 2\r\n\r\n");
            assert_eq!(refused(raw.as_bytes()), ErrorCode::BadRequest, "{method}");
            let raw = format!("{method} /x HTTP/1.1\r\nContent-Length: 2\r\n\r\n{{}}");
            assert_eq!(refused(raw.as_bytes()), ErrorCode::BadRequest, "{method}");
            // A zero length is no body.
            let raw = format!("{method} /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
            assert!(read(raw.as_bytes()).expect("request").body.is_empty());
        }
        // Another method keeps its body. So does a body over the limit: 413 first.
        assert_eq!(
            read(b"POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
                .expect("request")
                .body,
            b"{}"
        );
        let over = format!(
            "GET /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert_eq!(refused(over.as_bytes()), ErrorCode::TooLarge);
    }

    #[test]
    fn a_repeated_ordinary_header_is_allowed() {
        let request = read(b"GET /x HTTP/1.1\r\nAccept: a\r\nAccept: b\r\n\r\n").expect("request");
        assert_eq!(request.header("accept"), Some("a"));
    }

    #[test]
    fn an_answer_has_a_length_and_closes() {
        let mut out = Vec::new();
        write_response(&mut out, &Response::error(ErrorCode::NotFound)).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        let (head, body) = text.split_once("\r\n\r\n").expect("head");
        assert!(head.starts_with("HTTP/1.1 404 Not Found\r\n"), "{head}");
        assert!(head.contains("Connection: close"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(body.contains(r#""code":"not_found""#));
    }
}
