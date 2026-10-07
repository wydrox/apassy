//! The HTTPS client of the relay (contract relay-sync-v1, section 3).
//!
//! `https://` uses rustls with the macOS trust store, as `crate::broker::http` does.
//! Plain `http://` is allowed only for a loopback address with a port (the rule of
//! `broker::http::parse_destination`). One connection per request, HTTP/1.1,
//! `Connection: close`, no redirect. A request always has `Content-Length`; a snapshot
//! streams from or to a file and never sits in memory. A JSON answer is read up to
//! 2 MiB.
//!
//! The request head holds the access token, so it is built in one buffer of the exact
//! size and erased after the write. A JSON request body and every answer buffer are
//! erased on drop too: they can hold a token, a link code, or a team code.
//!
//! A request can be ended from another thread ([`Cancel`]): a lock closes the sockets of
//! a long poll and of a download or an upload in flight, so the device key and the token
//! do not wait in memory for the relay. The name lookup and the TCP connect run on a
//! helper thread that holds no token, and the request stops waiting for it at a cancel;
//! the socket is in the [`Cancel`] before the TLS handshake. A request can also have an
//! overall deadline ([`Request::deadline`]): connecting, sending, and reading all end by
//! then.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use zeroize::Zeroizing;

use super::SyncError;
use crate::broker::http::{DestinationUrl, TlsClient, parse_destination};

/// The relay address that the app proposes.
pub const DEFAULT_RELAY_URL: &str = "https://apassy-relay.wyderka.cc";
/// The time to connect to one address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest name lookup and connect of a request, over every address.
const CONNECT_LIMIT: Duration = Duration::from_secs(30);
/// How often a request that waits for its connection looks at its cancel.
const CANCEL_CHECK: Duration = Duration::from_millis(50);
/// The time for the answer headers. A long poll adds its wait.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// A body read or write that makes no progress for this long fails.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest JSON answer that the app reads.
pub(crate) const MAX_JSON_ANSWER: usize = 2 * 1024 * 1024;
/// The largest answer head.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The size of one read or write of a body.
const CHUNK: usize = 64 * 1024;
/// The first capacity of an answer buffer. A small answer (a token, a link code) then
/// never moves to a larger buffer and leaves no copy behind.
const ANSWER_CAPACITY: usize = 64 * 1024;

/// A relay address: an origin, `https://<host>[:port]` or a loopback `http://` with a
/// port. It has no path, query, user, or trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    origin: String,
    destination: DestinationUrl,
}

impl RelayUrl {
    /// Parse an address that the owner typed. A trailing slash goes.
    pub fn parse(text: &str) -> Result<Self, SyncError> {
        let destination =
            parse_destination(text.trim()).map_err(|_| SyncError::InvalidRelayAddress)?;
        let origin = match &destination {
            DestinationUrl::Loopback { host_header, .. } => format!("http://{host_header}"),
            DestinationUrl::Https { host, port } => {
                let host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.clone()
                };
                if *port == 443 {
                    format!("https://{host}")
                } else {
                    format!("https://{host}:{port}")
                }
            }
        };
        Ok(Self {
            origin,
            destination,
        })
    }

    /// The origin, as the app stores it and as the sign-in message has it.
    pub fn as_str(&self) -> &str {
        &self.origin
    }

    /// Whether this is a plain `http://` address on this computer.
    pub fn is_loopback(&self) -> bool {
        matches!(self.destination, DestinationUrl::Loopback { .. })
    }

    fn host_header(&self) -> &str {
        self.origin
            .strip_prefix("https://")
            .or_else(|| self.origin.strip_prefix("http://"))
            .unwrap_or(&self.origin)
    }
}

/// Why an exchange failed. No value holds the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpError {
    /// No connection: no byte of the request reached the relay.
    Connect,
    /// The connection failed after the request started. A push may have landed.
    Broken,
    /// The answer is not valid HTTP, too large, or a body is longer than allowed.
    Protocol,
}

/// The body of a request.
pub(crate) enum Body<'a> {
    None,
    /// JSON bytes, erased on drop.
    Json(Zeroizing<Vec<u8>>),
    /// A file that streams with its exact size.
    File(&'a Path, u64),
}

/// One request.
pub(crate) struct Request<'a> {
    pub(crate) method: &'static str,
    /// The path and query, pre-validated ASCII.
    pub(crate) path: String,
    pub(crate) bearer: Option<&'a str>,
    /// More headers: `If-Match`, the sync headers.
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) body: Body<'a>,
    /// The extra time of a long poll for the answer headers.
    pub(crate) wait: Duration,
    /// Lets another thread end this request (a lock, a pause, a quit).
    pub(crate) cancel: Option<&'a Cancel>,
    /// The request ends by then, whatever it is doing: connecting, sending, or reading.
    pub(crate) deadline: Option<Instant>,
}

/// Ends the requests in flight from another thread: [`Self::close`] shuts their sockets
/// down, and a request that starts after it fails at once. Several requests can use one
/// `Cancel` at the same time (a long poll and a download).
#[derive(Debug, Default)]
pub(crate) struct Cancel {
    closed: AtomicBool,
    /// The sockets of the requests in flight, with a number for each request.
    sockets: Mutex<Vec<(u64, TcpStream)>>,
    next: AtomicU64,
}

impl Cancel {
    /// End the requests in flight and every later one.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let sockets =
            std::mem::take(&mut *self.sockets.lock().unwrap_or_else(PoisonError::into_inner));
        for (_, socket) in sockets {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Keep a handle of the socket of a request in flight. Fails when closed.
    fn hold(&self, socket: &TcpStream) -> Result<u64, HttpError> {
        let mut sockets = self.sockets.lock().unwrap_or_else(PoisonError::into_inner);
        if self.is_closed() {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(HttpError::Broken);
        }
        let number = self.next.fetch_add(1, Ordering::SeqCst);
        if let Ok(handle) = socket.try_clone() {
            sockets.push((number, handle));
        }
        Ok(number)
    }

    fn release(&self, number: u64) {
        self.sockets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(held, _)| *held != number);
    }
}

/// Releases the socket handle of a [`Cancel`] when the request ends.
struct Held<'a>(Option<(&'a Cancel, u64)>);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some((cancel, number)) = self.0 {
            cancel.release(number);
        }
    }
}

/// The time left before `deadline`, at most `cap`. `Err(error)` when it passed.
fn time_left(
    deadline: Option<Instant>,
    cap: Duration,
    error: HttpError,
) -> Result<Duration, HttpError> {
    match deadline {
        None => Ok(cap),
        Some(deadline) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                Err(error)
            } else {
                Ok(left.min(cap))
            }
        }
    }
}

impl<'a> Request<'a> {
    pub(crate) fn new(method: &'static str, path: String, bearer: Option<&'a str>) -> Self {
        Self {
            method,
            path,
            bearer,
            headers: Vec::new(),
            body: Body::None,
            wait: Duration::ZERO,
            cancel: None,
            deadline: None,
        }
    }
}

/// An answer. A download leaves `body` empty after a `200`. The body is erased on drop.
#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) status: u16,
    headers: Vec<(String, String)>,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl Answer {
    /// An answer with a body, for a test.
    #[cfg(test)]
    pub(crate) fn for_test(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Zeroizing::new(body.as_bytes().to_vec()),
        }
    }

    /// The value of the header `name` (lowercase), when it is there.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Conn {
    fn socket(&self) -> &TcpStream {
        match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => &stream.sock,
        }
    }

    fn set_read_timeout(&self, timeout: Duration) -> Result<(), HttpError> {
        self.socket()
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))
            .map_err(|_| HttpError::Broken)
    }

    fn set_write_timeout(&self, timeout: Duration) -> Result<(), HttpError> {
        self.socket()
            .set_write_timeout(Some(timeout.max(Duration::from_millis(1))))
            .map_err(|_| HttpError::Broken)
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        };
        match read {
            // A server can close TLS without close_notify. The body length decides.
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn tls() -> Result<&'static TlsClient, HttpError> {
    static TLS: OnceLock<Option<TlsClient>> = OnceLock::new();
    TLS.get_or_init(|| TlsClient::platform().ok())
        .as_ref()
        .ok_or(HttpError::Connect)
}

/// Connect to the first address that answers, each within `CONNECT_TIMEOUT`, all by
/// `end`. Stops when the request gave up (`abandoned`).
fn connect_any(
    addrs: &[SocketAddr],
    end: Instant,
    abandoned: &AtomicBool,
) -> Result<TcpStream, HttpError> {
    for addr in addrs {
        if abandoned.load(Ordering::SeqCst) {
            break;
        }
        let timeout = time_left(Some(end), CONNECT_TIMEOUT, HttpError::Connect)?;
        if let Ok(stream) = TcpStream::connect_timeout(addr, timeout) {
            return Ok(stream);
        }
    }
    Err(HttpError::Connect)
}

/// The TCP connection of a request. The name lookup and the connect run on a helper
/// thread that holds no token: a cancel or the deadline ends the wait at once, and the
/// helper drops a connection that comes too late. All of it ends within
/// `CONNECT_LIMIT`.
fn open_tcp(
    url: &RelayUrl,
    cancel: Option<&Cancel>,
    deadline: Option<Instant>,
) -> Result<TcpStream, HttpError> {
    let limit = Instant::now() + CONNECT_LIMIT;
    let end = deadline.map_or(limit, |deadline| deadline.min(limit));
    let destination = url.destination.clone();
    let abandoned = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    {
        let abandoned = Arc::clone(&abandoned);
        std::thread::Builder::new()
            .name("apassy-relay-connect".to_owned())
            .spawn(move || {
                let addrs = match &destination {
                    DestinationUrl::Loopback { addr, .. } => Ok(vec![*addr]),
                    DestinationUrl::Https { host, port } => (host.as_str(), *port)
                        .to_socket_addrs()
                        .map(Iterator::collect)
                        .map_err(|_| HttpError::Connect),
                };
                let _ = sender.send(addrs.and_then(|addrs| connect_any(&addrs, end, &abandoned)));
            })
            .map_err(|_| HttpError::Connect)?;
    }
    let give_up = || {
        abandoned.store(true, Ordering::SeqCst);
        Err(HttpError::Connect)
    };
    loop {
        if cancel.is_some_and(Cancel::is_closed) {
            return give_up();
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return give_up();
        }
        match receiver.recv_timeout(left.min(CANCEL_CHECK)) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return give_up(),
        }
    }
}

/// Connect for `request`. Its socket is in its [`Cancel`] from the TCP connect on, so a
/// cancel also ends the TLS handshake. A failed check sends no token.
fn connect<'a>(url: &RelayUrl, request: &Request<'a>) -> Result<(Conn, Held<'a>), HttpError> {
    let tcp = open_tcp(url, request.cancel, request.deadline)?;
    let stall = time_left(request.deadline, STALL_TIMEOUT, HttpError::Connect)?;
    let header = time_left(request.deadline, HEADER_TIMEOUT, HttpError::Connect)?;
    tcp.set_write_timeout(Some(stall))
        .map_err(|_| HttpError::Connect)?;
    tcp.set_read_timeout(Some(header))
        .map_err(|_| HttpError::Connect)?;
    let mut held = Held(None);
    if let Some(cancel) = request.cancel {
        let number = cancel.hold(&tcp).map_err(|_| HttpError::Connect)?;
        held = Held(Some((cancel, number)));
    }
    match &url.destination {
        DestinationUrl::Loopback { .. } => Ok((Conn::Plain(tcp), held)),
        DestinationUrl::Https { host, .. } => {
            let name = ServerName::try_from(host.clone()).map_err(|_| HttpError::Connect)?;
            let conn = ClientConnection::new(tls()?.client_config(), name)
                .map_err(|_| HttpError::Connect)?;
            let mut stream = StreamOwned::new(conn, tcp);
            // Finish the handshake before any request byte.
            while stream.conn.is_handshaking() {
                stream
                    .conn
                    .complete_io(&mut stream.sock)
                    .map_err(|_| HttpError::Connect)?;
            }
            Ok((Conn::Tls(Box::new(stream)), held))
        }
    }
}

fn valid_header_text(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| (0x20..0x7f).contains(&byte))
}

/// The request head in one buffer of the exact size.
fn request_head(url: &RelayUrl, request: &Request<'_>) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    if !request.path.starts_with('/') || request.path.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(HttpError::Protocol);
    }
    let (content_type, length) = match &request.body {
        Body::None => (None, 0),
        Body::Json(bytes) => (Some("application/json"), bytes.len() as u64),
        Body::File(_, size) => (Some("application/octet-stream"), *size),
    };
    let mut lines: Vec<(&str, &str)> = vec![("Host", url.host_header())];
    let bearer;
    if let Some(token) = request.bearer {
        if !valid_header_text(token) || token.contains(' ') {
            return Err(HttpError::Protocol);
        }
        bearer = Zeroizing::new(format!("Bearer {token}"));
        lines.push(("Authorization", bearer.as_str()));
    }
    if let Some(content_type) = content_type {
        lines.push(("Content-Type", content_type));
    }
    let length = length.to_string();
    lines.push(("Content-Length", &length));
    for (name, value) in &request.headers {
        if !valid_header_text(value) {
            return Err(HttpError::Protocol);
        }
        lines.push((name, value));
    }
    lines.push(("User-Agent", "apassy-sync/1"));
    lines.push(("Connection", "close"));
    let size = request.method.len()
        + 1
        + request.path.len()
        + 11
        + lines
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum::<usize>()
        + 2;
    let mut head = Zeroizing::new(Vec::with_capacity(size));
    head.extend_from_slice(request.method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(request.path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in lines {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    Ok(head)
}

/// Send the request. Returns the connection and whether the whole request went out.
/// The body always goes out whole: a relay that answers early (a `412` or a `413`)
/// reads the rest anyway, and the caller then reads that answer. A request with a
/// [`Cancel`] registers its socket there; a body write stops at the deadline.
fn send<'a>(url: &RelayUrl, request: &Request<'a>) -> Result<(Conn, bool, Held<'a>), HttpError> {
    if request.cancel.is_some_and(Cancel::is_closed) {
        return Err(HttpError::Connect);
    }
    time_left(request.deadline, CONNECT_TIMEOUT, HttpError::Connect)?;
    let head = request_head(url, request)?;
    let mut file = match &request.body {
        Body::File(path, size) => {
            let file = File::open(path).map_err(|_| HttpError::Protocol)?;
            let actual = file.metadata().map_err(|_| HttpError::Protocol)?.len();
            if actual != *size {
                return Err(HttpError::Protocol);
            }
            Some(file)
        }
        _ => None,
    };
    let (mut conn, held) = connect(url, request)?;
    if conn.write_all(&head).is_err() {
        return Err(HttpError::Broken);
    }
    drop(head);
    let complete = match (&request.body, file.as_mut()) {
        (Body::Json(bytes), _) => conn.write_all(bytes).is_ok(),
        (Body::File(..), Some(file)) => {
            let mut buffer = vec![0u8; CHUNK];
            loop {
                let read = file.read(&mut buffer).map_err(|_| HttpError::Broken)?;
                if read == 0 {
                    break true;
                }
                let Ok(stall) = time_left(request.deadline, STALL_TIMEOUT, HttpError::Broken)
                else {
                    break false;
                };
                if conn.set_write_timeout(stall).is_err()
                    || conn.write_all(&buffer[..read]).is_err()
                {
                    break false;
                }
            }
        }
        _ => true,
    };
    let flushed = complete && conn.flush().is_ok();
    Ok((conn, flushed, held))
}

/// Bytes from the connection with a buffer in front. The buffer is erased on drop.
struct Source<'a> {
    conn: &'a mut Conn,
    buffer: Zeroizing<Vec<u8>>,
    start: usize,
    /// A read after this fails.
    deadline: Option<Instant>,
}

impl Source<'_> {
    fn pending(&self) -> &[u8] {
        &self.buffer[self.start..]
    }

    /// Read more bytes into the buffer. `false` at the end of the stream.
    fn fill(&mut self) -> io::Result<bool> {
        if self.start > 0 {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        if self.deadline.is_some() {
            let stall = time_left(self.deadline, STALL_TIMEOUT, HttpError::Broken)
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            self.conn
                .set_read_timeout(stall)
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        }
        let mut chunk = Zeroizing::new([0u8; 8192]);
        let read = self.conn.read(chunk.as_mut())?;
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(read > 0)
    }

    fn take(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pending().is_empty() && !self.fill()? {
            return Ok(0);
        }
        let count = out.len().min(self.pending().len());
        out[..count].copy_from_slice(&self.buffer[self.start..self.start + count]);
        self.start += count;
        Ok(count)
    }

    /// One line without its `\r\n`, at most `max` bytes.
    fn line(&mut self, max: usize) -> io::Result<Vec<u8>> {
        loop {
            if let Some(end) = self.pending().windows(2).position(|pair| pair == b"\r\n") {
                let line = self.pending()[..end].to_vec();
                self.start += end + 2;
                return Ok(line);
            }
            if self.pending().len() > max {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if !self.fill()? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}

enum BodyKind {
    Length(u64),
    Chunked,
    UntilClose,
}

/// The body of an answer as a reader.
struct BodyReader<'a> {
    source: Source<'a>,
    kind: BodyKind,
    /// The bytes left of the current chunk.
    chunk_left: u64,
    done: bool,
}

impl Read for BodyReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        match self.kind {
            BodyKind::Length(ref mut left) => {
                if *left == 0 {
                    self.done = true;
                    return Ok(0);
                }
                let want = usize::try_from(*left).unwrap_or(usize::MAX).min(out.len());
                let read = self.source.take(&mut out[..want])?;
                if read == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                *left -= read as u64;
                Ok(read)
            }
            BodyKind::UntilClose => {
                let read = self.source.take(out)?;
                self.done = read == 0;
                Ok(read)
            }
            BodyKind::Chunked => {
                if self.chunk_left == 0 {
                    let line = self.source.line(1024)?;
                    let text = std::str::from_utf8(&line)
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                    let size = text.split(';').next().unwrap_or_default().trim();
                    let size = u64::from_str_radix(size, 16)
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                    if size == 0 {
                        // Trailers end with an empty line. This client ignores them.
                        while !self.source.line(MAX_HEAD_BYTES)?.is_empty() {}
                        self.done = true;
                        return Ok(0);
                    }
                    self.chunk_left = size;
                }
                let want = usize::try_from(self.chunk_left)
                    .unwrap_or(usize::MAX)
                    .min(out.len());
                let read = self.source.take(&mut out[..want])?;
                if read == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                self.chunk_left -= read as u64;
                if self.chunk_left == 0 && !self.source.line(2)?.is_empty() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok(read)
            }
        }
    }
}

/// The header lines of an answer: lowercase names and trimmed values.
type Headers = Vec<(String, String)>;

/// The status, the headers, and the rest of the stream after the head.
struct Head<'a> {
    status: u16,
    headers: Headers,
    source: Source<'a>,
}

/// Read the answer head. Interim `1xx` answers are skipped. Every read of the answer
/// ends by `overall`, when the request has a deadline.
fn read_head(
    conn: &mut Conn,
    wait: Duration,
    overall: Option<Instant>,
) -> Result<Head<'_>, HttpError> {
    let mut deadline = Instant::now() + HEADER_TIMEOUT + wait;
    if let Some(overall) = overall {
        deadline = deadline.min(overall);
    }
    let mut source = Source {
        conn,
        buffer: Zeroizing::new(Vec::with_capacity(ANSWER_CAPACITY)),
        start: 0,
        deadline: None,
    };
    loop {
        let end = loop {
            if let Some(end) = source.pending().windows(4).position(|w| w == b"\r\n\r\n") {
                break end;
            }
            if source.pending().len() > MAX_HEAD_BYTES {
                return Err(HttpError::Protocol);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(HttpError::Broken);
            }
            source.conn.set_read_timeout(left.min(STALL_TIMEOUT))?;
            match source.fill() {
                Ok(true) => {}
                Ok(false) | Err(_) => return Err(HttpError::Broken),
            }
        };
        let text = std::str::from_utf8(&source.pending()[..end])
            .map_err(|_| HttpError::Protocol)?
            .to_owned();
        source.start += end + 4;
        let mut lines = text.split("\r\n");
        let mut status_line = lines.next().unwrap_or_default().split(' ');
        let version = status_line.next().unwrap_or_default();
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return Err(HttpError::Protocol);
        }
        let status: u16 = status_line
            .next()
            .and_then(|code| code.parse().ok())
            .filter(|code| (100..600).contains(code))
            .ok_or(HttpError::Protocol)?;
        if (100..200).contains(&status) {
            continue;
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or(HttpError::Protocol)?;
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        source.conn.set_read_timeout(STALL_TIMEOUT)?;
        source.deadline = overall;
        return Ok(Head {
            status,
            headers,
            source,
        });
    }
}

fn body_kind(status: u16, headers: &[(String, String)]) -> Result<BodyKind, HttpError> {
    if status == 204 || status == 304 {
        return Ok(BodyKind::Length(0));
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if let Some(encoding) = find("transfer-encoding") {
        return if encoding.eq_ignore_ascii_case("chunked") {
            Ok(BodyKind::Chunked)
        } else {
            Err(HttpError::Protocol)
        };
    }
    match find("content-length") {
        Some(length) => length
            .parse()
            .map(BodyKind::Length)
            .map_err(|_| HttpError::Protocol),
        None => Ok(BodyKind::UntilClose),
    }
}

fn read_limited(reader: &mut impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    let mut body = Zeroizing::new(Vec::with_capacity(ANSWER_CAPACITY));
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| HttpError::Broken)?;
    if body.len() > limit {
        return Err(HttpError::Protocol);
    }
    Ok(body)
}

/// Send a request and read the answer into memory (at most 2 MiB).
pub(crate) fn exchange(url: &RelayUrl, request: &Request<'_>) -> Result<Answer, HttpError> {
    let (mut conn, _complete, _held) = send(url, request)?;
    let Head {
        status,
        headers,
        source,
    } = read_head(&mut conn, request.wait, request.deadline)?;
    let kind = body_kind(status, &headers)?;
    let mut reader = BodyReader {
        source,
        kind,
        chunk_left: 0,
        done: false,
    };
    let body = read_limited(&mut reader, MAX_JSON_ANSWER)?;
    Ok(Answer {
        status,
        headers,
        body,
    })
}

/// What a download wrote.
#[derive(Debug)]
pub(crate) struct Downloaded {
    /// SHA-256 of the bytes.
    pub(crate) sha256: [u8; 32],
    /// The number of bytes.
    pub(crate) size: u64,
}

/// Send a request and stream a `200` body to `dest` while hashing it. A body longer
/// than `max` bytes fails. Another status reads its (JSON) body into the answer.
pub(crate) fn download(
    url: &RelayUrl,
    request: &Request<'_>,
    dest: &mut File,
    max: u64,
) -> Result<(Answer, Option<Downloaded>), HttpError> {
    let (mut conn, _complete, _held) = send(url, request)?;
    let Head {
        status,
        headers,
        source,
    } = read_head(&mut conn, request.wait, request.deadline)?;
    let kind = body_kind(status, &headers)?;
    let mut reader = BodyReader {
        source,
        kind,
        chunk_left: 0,
        done: false,
    };
    if status != 200 {
        let body = read_limited(&mut reader, MAX_JSON_ANSWER)?;
        return Ok((
            Answer {
                status,
                headers,
                body,
            },
            None,
        ));
    }
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut size = 0u64;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| HttpError::Broken)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > max {
            return Err(HttpError::Protocol);
        }
        hash.update(&buffer[..read]);
        dest.write_all(&buffer[..read])
            .map_err(|_| HttpError::Broken)?;
    }
    dest.sync_all().map_err(|_| HttpError::Broken)?;
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(hash.finish().as_ref());
    Ok((
        Answer {
            status,
            headers,
            body: Zeroizing::new(Vec::new()),
        },
        Some(Downloaded { sha256, size }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn https_anywhere_and_plain_http_only_on_loopback() {
        for (text, origin) in [
            (
                "https://apassy-relay.wyderka.cc",
                "https://apassy-relay.wyderka.cc",
            ),
            ("https://Relay.Example.test/", "https://relay.example.test"),
            (
                "https://relay.example.test:443",
                "https://relay.example.test",
            ),
            (
                "https://relay.example.test:8443",
                "https://relay.example.test:8443",
            ),
            ("http://127.0.0.1:8787", "http://127.0.0.1:8787"),
            ("http://localhost:8787/", "http://localhost:8787"),
            ("http://[::1]:8787", "http://[::1]:8787"),
        ] {
            let url = RelayUrl::parse(text).expect(text);
            assert_eq!(url.as_str(), origin, "{text}");
        }
        assert!(
            RelayUrl::parse("http://127.0.0.1:8787")
                .unwrap()
                .is_loopback()
        );
        for bad in [
            "http://relay.example.test:80",
            "http://10.0.0.1:8787",
            "http://127.0.0.1",
            "https://relay.example.test/v1",
            "https://user@relay.example.test",
            "https://relay.example.test?x=1",
            "ftp://relay.example.test",
            "relay.example.test",
        ] {
            assert_eq!(
                RelayUrl::parse(bad),
                Err(SyncError::InvalidRelayAddress),
                "{bad}"
            );
        }
    }

    /// Accept one connection and answer with `answer` after reading the head.
    fn serve_once(answer: &'static [u8]) -> (RelayUrl, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut buf).unwrap();
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..read]);
            }
            stream.write_all(answer).unwrap();
            seen
        });
        (url, server)
    }

    #[test]
    fn a_request_has_its_headers_and_a_chunked_answer_reads() {
        let (url, server) = serve_once(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: \"3\"\r\n\r\n4\r\n{\"ok\r\n3;x=1\r\n\":1\r\n1\r\n}\r\n0\r\n\r\n",
        );
        let mut request = Request::new(
            "GET",
            "/v1/sync/head?since=2".to_owned(),
            Some("apassy_acc_synthetic"),
        );
        request.headers.push(("If-Match", "\"2\"".to_owned()));
        let answer = exchange(&url, &request).unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body.as_slice(), b"{\"ok\":1}");
        assert_eq!(answer.header("etag"), Some("\"3\""));
        let seen = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(seen.starts_with("GET /v1/sync/head?since=2 HTTP/1.1\r\nHost: 127.0.0.1:"));
        assert!(seen.contains("\r\nAuthorization: Bearer apassy_acc_synthetic\r\n"));
        assert!(seen.contains("\r\nContent-Length: 0\r\n"));
        assert!(seen.contains("\r\nIf-Match: \"2\"\r\n"));
        assert!(seen.ends_with("Connection: close\r\n\r\n"));
        assert!(!seen.contains("chunked"));
    }

    #[test]
    fn a_download_stops_at_its_limit_and_a_short_body_fails() {
        let (url, _server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789");
        let mut file = tempfile::tempfile().unwrap();
        let request = Request::new("GET", "/v1/sync/snapshot?version=1".to_owned(), None);
        assert_eq!(
            download(&url, &request, &mut file, 9).unwrap_err(),
            HttpError::Protocol
        );
        let (url, _server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n01234");
        let mut file = tempfile::tempfile().unwrap();
        assert_eq!(
            download(&url, &request, &mut file, 100).unwrap_err(),
            HttpError::Broken
        );
        let (url, _server) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
        let mut file = tempfile::tempfile().unwrap();
        let (_, got) = download(&url, &request, &mut file, 100).unwrap();
        let got = got.unwrap();
        assert_eq!(got.size, 3);
        assert_eq!(
            crate::companion::crypto::hex(&got.sha256),
            crate::companion::crypto::sha256_hex(b"abc")
        );
    }

    /// A lock ends a long poll at once: closing its [`Cancel`] shuts the socket down,
    /// and a request after the close does not connect.
    #[test]
    fn a_cancel_ends_a_long_poll_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        // A relay that takes the request and never answers.
        let _server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            drop(stream);
        });
        let cancel = std::sync::Arc::new(Cancel::default());
        let poll = {
            let cancel = std::sync::Arc::clone(&cancel);
            let url = url.clone();
            std::thread::spawn(move || {
                let mut request = Request::new(
                    "GET",
                    "/v1/sync/head?since=1&wait=25".to_owned(),
                    Some("apassy_acc_synthetic"),
                );
                request.wait = Duration::from_secs(25);
                request.cancel = Some(&cancel);
                let started = Instant::now();
                (exchange(&url, &request).unwrap_err(), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        cancel.close();
        let (error, waited) = poll.join().unwrap();
        assert_eq!(error, HttpError::Broken);
        assert!(waited < Duration::from_secs(3), "{waited:?}");
        let mut request = Request::new("GET", "/v1/sync/head".to_owned(), None);
        request.cancel = Some(&cancel);
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
    }

    /// A cancel ends a request in its TLS handshake at once: the socket is in the
    /// `Cancel` from the TCP connect on, and no request byte went out.
    #[test]
    fn a_cancel_ends_a_tls_handshake_at_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "https://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        // A relay that takes the connection and never answers the client hello.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        let cancel = std::sync::Arc::new(Cancel::default());
        let call = {
            let cancel = std::sync::Arc::clone(&cancel);
            std::thread::spawn(move || {
                let mut request = Request::new(
                    "GET",
                    "/v1/devices".to_owned(),
                    Some("apassy_acc_synthetic"),
                );
                request.cancel = Some(&cancel);
                let started = Instant::now();
                (exchange(&url, &request).unwrap_err(), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(500));
        cancel.close();
        let (error, waited) = call.join().unwrap();
        assert_eq!(error, HttpError::Connect);
        assert!(waited < Duration::from_secs(3), "{waited:?}");
    }

    /// A relay that takes each request, sends `head`, then trickles one byte every 100
    /// ms and never ends the body.
    fn serve_slow(head: &'static [u8], connections: usize) -> RelayUrl {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = RelayUrl::parse(&format!(
            "http://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(head);
                    for _ in 0..300 {
                        std::thread::sleep(Duration::from_millis(100));
                        if stream.write_all(b"x").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        url
    }

    /// One `Cancel` ends a long poll and a download that run at the same time: a lock
    /// stops a transfer, not only the long poll.
    #[test]
    fn a_cancel_ends_a_download_and_a_long_poll_together() {
        let url = serve_slow(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n", 2);
        let cancel = std::sync::Arc::new(Cancel::default());
        let download = {
            let (cancel, url) = (std::sync::Arc::clone(&cancel), url.clone());
            std::thread::spawn(move || {
                let mut request =
                    Request::new("GET", "/v1/sync/snapshot?version=2".to_owned(), None);
                request.cancel = Some(&cancel);
                let mut file = tempfile::tempfile().unwrap();
                let started = Instant::now();
                let error = download(&url, &request, &mut file, 2_000_000).unwrap_err();
                (error, started.elapsed())
            })
        };
        let poll = {
            let (cancel, url) = (std::sync::Arc::clone(&cancel), url.clone());
            std::thread::spawn(move || {
                let mut request =
                    Request::new("GET", "/v1/sync/head?since=1&wait=25".to_owned(), None);
                request.wait = Duration::from_secs(25);
                request.cancel = Some(&cancel);
                let started = Instant::now();
                (exchange(&url, &request).unwrap_err(), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(500));
        cancel.close();
        for (error, waited) in [download.join().unwrap(), poll.join().unwrap()] {
            assert_eq!(error, HttpError::Broken);
            assert!(waited < Duration::from_secs(3), "{waited:?}");
        }
    }

    /// A request with a deadline ends by then, also while the relay still sends.
    #[test]
    fn a_deadline_ends_a_slow_download() {
        let url = serve_slow(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n", 1);
        let mut request = Request::new("GET", "/v1/sync/snapshot?version=2".to_owned(), None);
        request.deadline = Some(Instant::now() + Duration::from_millis(600));
        let mut file = tempfile::tempfile().unwrap();
        let started = Instant::now();
        let error = download(&url, &request, &mut file, 2_000_000).unwrap_err();
        assert_eq!(error, HttpError::Broken);
        let waited = started.elapsed();
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        // A deadline that passed sends nothing.
        request.deadline = Some(Instant::now());
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
    }

    #[test]
    fn a_closed_port_is_a_connect_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = RelayUrl::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let request = Request::new("GET", "/v1/sync/head".to_owned(), None);
        assert_eq!(exchange(&url, &request).unwrap_err(), HttpError::Connect);
    }
}
