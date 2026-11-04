//! WebSocket in the run proxy (ADR 0011 stage 5; decision D11 and unit P3 of
//! `docs/design/implementation-plan-s5-env-0011.md`). Review: judge panel (P3).
//!
//! The engine (`engine.rs`) takes an upgrade only to a host of the run, only on
//! `GET` with `Upgrade: websocket`. The handshake goes through the swap rules of
//! every request (the `Authorization` header, a known key header, or a known key
//! query parameter), and [`handshake_request`] removes `Sec-WebSocket-Extensions`,
//! so no compression is agreed. A `101` that turns on an extension anyway is
//! refused ([`check_accept`]). After the `101`, [`relay`] reads the frames of both
//! sides:
//!
//! - A frame of the program is unmasked, checked for a placeholder (also one split
//!   over frames), and sent on with a new mask. A frame with a placeholder is not
//!   sent: the program gets Close 1008, the service Close 1001, and the request log
//!   a refusal.
//! - A frame of the service has each real value replaced with its placeholder, of
//!   the same length. A value split over the fragments of one message is found
//!   too; each message is complete at its last fragment, so no byte moves into
//!   another message. A value that starts at the end of one message and ends in
//!   the next one cannot be replaced: the proxy keeps the end of the stream across
//!   messages, and such a value closes the WebSocket with 1008 before its rest is
//!   sent (judge finding L2).
//! - A frame with a reserved bit (a compressed frame), an unknown opcode, a wrong
//!   mask, a long or fragmented control frame, or a broken fragment sequence is a
//!   protocol error (Close 1002). It is never passed on, so the proxy never passes
//!   a frame that it could not check.
//! - Limits (the frame cap is from the plan; the deadlines are chosen by this unit,
//!   the owner can change them): a frame of at most 1 MiB (Close 1009); 5 minutes
//!   without a frame from either side (Close 1001 to both); 5 seconds for the other
//!   side to answer a Close.
//!
//! The texts of a refusal (event and close reason) name the variable, never a
//! value or a placeholder.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use rustls::ConnectionCommon;
use zeroize::Zeroizing;

use super::http1::{Replacer, RequestHead, Scanner};

/// The largest frame payload, both ways (plan P3).
pub(super) const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// No frame from either side for this long closes the connection.
const IDLE: Duration = Duration::from_secs(300);
/// After the first Close, the other side has this long to answer.
const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// How often a waiting read checks the deadlines.
pub(super) const TICK: Duration = Duration::from_secs(1);
const READ_CHUNK: usize = 16 * 1024;
/// A close reason fits a control frame with its code (RFC 6455 §5.5.1).
const MAX_CLOSE_REASON: usize = 123;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

const GOING_AWAY: u16 = 1001;
const PROTOCOL_ERROR: u16 = 1002;
const POLICY_VIOLATION: u16 = 1008;
const TOO_BIG: u16 = 1009;
/// The service sent something that the proxy does not pass on (IANA registry).
const BAD_GATEWAY: u16 = 1014;

fn has_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .flat_map(|(_, value)| value.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

/// A WebSocket handshake: `GET` with `Upgrade: websocket` and `Connection: upgrade`.
pub(super) fn is_websocket(request: &RequestHead) -> bool {
    request.method == "GET"
        && has_token(&request.headers, "upgrade", "websocket")
        && has_token(&request.headers, "connection", "upgrade")
}

/// The handshake for the service: the request without `Sec-WebSocket-Extensions`,
/// so the frames stay uncompressed and the proxy can check them.
pub(super) fn handshake_request(request: &RequestHead) -> RequestHead {
    let mut out = request.clone();
    out.headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("sec-websocket-extensions"));
    out
}

/// Checks the `101` of the service: it switches to WebSocket, without an extension.
pub(super) fn check_accept(raw: &[u8]) -> Result<(), &'static str> {
    let text = String::from_utf8_lossy(raw);
    let headers: Vec<(String, String)> = text
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    if !has_token(&headers, "upgrade", "websocket") {
        return Err("The service switched to a protocol other than WebSocket.");
    }
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-extensions"))
    {
        return Err(
            "The service turned on a WebSocket extension that Apassy did not offer, so Apassy could not check its frames.",
        );
    }
    Ok(())
}

/// One side of a relayed WebSocket.
pub(super) trait Endpoint: Sync {
    /// Reads bytes. `Ok(0)` at the end. A read timeout (`WouldBlock` or
    /// `TimedOut`) lets the relay check its deadlines; it is not the end.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes all of `data` as one unit, so the frames of the two directions never
    /// mix.
    fn write_all(&self, data: &[u8]) -> io::Result<()>;
    /// Closes the connection. A blocked read of the other direction ends.
    fn shutdown(&self);
}

/// A TLS connection of the engine as an [`Endpoint`]. Two threads use it: one
/// reads, one writes. The TLS state is behind a lock; the read of the socket
/// happens outside it, so a write does not wait for the peer to send.
pub(super) struct TlsEndpoint<'a, D> {
    state: Mutex<TlsState<'a, D>>,
    sock: &'a TcpStream,
}

struct TlsState<'a, D> {
    conn: &'a mut ConnectionCommon<D>,
    /// TLS bytes read from the socket but not given to the connection yet.
    raw: Vec<u8>,
}

impl<'a, D> TlsEndpoint<'a, D> {
    /// `raw` holds TLS bytes that were read from `sock` before and that `conn` has
    /// not seen yet. The socket needs a read timeout ([`TICK`]).
    pub(super) fn new(
        conn: &'a mut ConnectionCommon<D>,
        sock: &'a TcpStream,
        raw: Vec<u8>,
    ) -> Self {
        Self {
            state: Mutex::new(TlsState { conn, raw }),
            sock,
        }
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, TlsState<'a, D>>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("the TLS state is poisoned"))
    }
}

fn flush_tls<D>(conn: &mut ConnectionCommon<D>, mut sock: &TcpStream) -> io::Result<()> {
    while conn.wants_write() {
        conn.write_tls(&mut sock)?;
    }
    Ok(())
}

/// Decrypts what came in. An alert or a key update goes out, also after an error.
fn process_tls<D>(conn: &mut ConnectionCommon<D>, sock: &TcpStream) -> io::Result<()> {
    let processed = conn.process_new_packets();
    let flushed = flush_tls(conn, sock);
    processed.map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    flushed
}

impl<D> Endpoint for TlsEndpoint<'_, D>
where
    ConnectionCommon<D>: Send,
{
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            {
                let mut guard = self.lock()?;
                let state = &mut *guard;
                match state.conn.reader().read(buf) {
                    Ok(read) => return Ok(read),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    // The peer closed without close_notify: the end, too.
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                    Err(err) => return Err(err),
                }
                if !state.raw.is_empty() {
                    let mut pending: &[u8] = &state.raw;
                    let used = state.conn.read_tls(&mut pending)?;
                    state.raw.drain(..used);
                    process_tls(&mut *state.conn, self.sock)?;
                    continue;
                }
            }
            let mut sock = self.sock;
            let read = sock.read(&mut chunk)?;
            let mut guard = self.lock()?;
            let state = &mut *guard;
            if read == 0 {
                // The connection learns of the end; its reader then gives the end.
                state.conn.read_tls(&mut io::empty())?;
                process_tls(&mut *state.conn, self.sock)?;
            } else {
                state.raw.extend_from_slice(&chunk[..read]);
            }
        }
    }

    fn write_all(&self, data: &[u8]) -> io::Result<()> {
        let mut guard = self.lock()?;
        let state = &mut *guard;
        let mut rest = data;
        let mut stalled = false;
        while !rest.is_empty() {
            let written = state.conn.writer().write(rest)?;
            flush_tls(&mut *state.conn, self.sock)?;
            if written == 0 {
                if stalled {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                stalled = true;
                continue;
            }
            stalled = false;
            rest = &rest[written..];
        }
        Ok(())
    }

    fn shutdown(&self) {
        // The other direction can hold the lock in a write; then no close_notify.
        if let Ok(mut state) = self.state.try_lock() {
            state.conn.send_close_notify();
            let _ = flush_tls(&mut *state.conn, self.sock);
        }
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}

/// The limits of one relay. [`Limits::default`] is the production set.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    pub max_frame: usize,
    pub idle: Duration,
    pub close_wait: Duration,
    /// Tests only: the relay checks the deadlines when a read times out, so a
    /// shorter deadline needs a shorter socket read timeout as well.
    pub tick: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame: MAX_FRAME_BYTES,
            idle: IDLE,
            close_wait: CLOSE_WAIT,
            tick: TICK,
        }
    }
}

/// The secrets of the run, as the relay sees them. Index `i` of each list is the
/// same secret.
pub(super) struct Secrets<'a> {
    pub placeholders: &'a [&'a [u8]],
    /// (real value, placeholder), each pair of one length.
    pub pairs: &'a [(&'a [u8], &'a [u8])],
    /// The variable names, for the texts.
    pub names: &'a [&'a str],
}

/// What the relay tells the request log. No text has a value or a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Report {
    /// The program sent a frame that the proxy does not pass on.
    Refused(String),
    /// The service sent a frame that the proxy does not pass on.
    Failed(String),
    /// A frame of the service had a real value; the program got the placeholder.
    /// Sent once for each connection.
    Replaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Zeroizing<Vec<u8>>,
}

enum Next {
    Frame(Frame),
    /// A read timed out: check the deadlines.
    Tick,
    End,
}

enum Fault {
    Io,
    Bad { code: u16, detail: &'static str },
}

fn bad<T>(code: u16, detail: &'static str) -> Result<T, Fault> {
    Err(Fault::Bad { code, detail })
}

/// One frame at the start of `buf`, unmasked, and its length in `buf`. `None`
/// while the frame is not complete. `masked`: the frames of this side must be
/// masked (the program) or must not be (the service).
fn parse(buf: &[u8], masked: bool, max: usize) -> Result<Option<(Frame, usize)>, Fault> {
    let (Some(&first), Some(&second)) = (buf.first(), buf.get(1)) else {
        return Ok(None);
    };
    let fin = first & 0x80 != 0;
    let opcode = first & 0x0f;
    if first & 0x70 != 0 {
        return bad(
            PROTOCOL_ERROR,
            "a reserved bit is set (a compressed frame), and no extension was agreed",
        );
    }
    if !matches!(
        opcode,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return bad(PROTOCOL_ERROR, "an unknown opcode");
    }
    if (second & 0x80 != 0) != masked {
        return bad(
            PROTOCOL_ERROR,
            if masked {
                "the frame is not masked"
            } else {
                "the frame is masked"
            },
        );
    }
    let (len, mut at) = match second & 0x7f {
        126 => {
            let Some(bytes) = buf.get(2..4) else {
                return Ok(None);
            };
            (u64::from(u16::from_be_bytes([bytes[0], bytes[1]])), 4)
        }
        127 => {
            let Some(bytes) = buf.get(2..10) else {
                return Ok(None);
            };
            let mut word = [0u8; 8];
            word.copy_from_slice(bytes);
            (u64::from_be_bytes(word), 10)
        }
        short => (u64::from(short), 2),
    };
    if opcode >= OP_CLOSE && (!fin || len > 125) {
        return bad(
            PROTOCOL_ERROR,
            "a control frame is fragmented or longer than 125 bytes",
        );
    }
    // Before the payload is read: a large length does not fill the buffer.
    let Some(len) = usize::try_from(len).ok().filter(|len| *len <= max) else {
        return bad(TOO_BIG, "the frame is larger than the limit of 1 MiB");
    };
    let key = if masked {
        let Some(key) = buf.get(at..at + 4) else {
            return Ok(None);
        };
        at += 4;
        Some([key[0], key[1], key[2], key[3]])
    } else {
        None
    };
    let Some(data) = buf.get(at..at + len) else {
        return Ok(None);
    };
    let mut payload = Zeroizing::new(data.to_vec());
    if let Some(key) = key {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }
    Ok(Some((
        Frame {
            fin,
            opcode,
            payload,
        },
        at + len,
    )))
}

/// A frame with the shortest length form. A frame to the service has `mask`.
fn encode(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 14));
    out.push((u8::from(fin) << 7) | opcode);
    let mask_bit: u8 = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        len if len < 126 => out.push(mask_bit | len as u8),
        len if len <= usize::from(u16::MAX) => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(
                payload
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % 4]),
            );
        }
        None => out.extend_from_slice(payload),
    }
    out
}

fn truncated(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn close_frame(code: u16, reason: &str, mask: Option<[u8; 4]>) -> Zeroizing<Vec<u8>> {
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(truncated(reason, MAX_CLOSE_REASON).as_bytes());
    encode(true, OP_CLOSE, &payload, mask)
}

/// A new mask key for a frame to the service (RFC 6455 §5.3).
fn mask_key() -> Option<[u8; 4]> {
    let mut key = [0u8; 4];
    getrandom::fill(&mut key).ok()?;
    Some(key)
}

/// The fragments of a message: a new message only after the last fragment, a
/// continuation only inside a message. Control frames can come between.
fn check_sequence(in_message: &mut bool, frame: &Frame) -> Result<(), &'static str> {
    match frame.opcode {
        OP_TEXT | OP_BINARY if *in_message => Err("a new message started inside a fragmented one"),
        OP_CONTINUATION if !*in_message => Err("a continuation frame without a message"),
        OP_TEXT | OP_BINARY | OP_CONTINUATION => {
            *in_message = !frame.fin;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The frames that one side sends.
struct Frames {
    buf: Zeroizing<Vec<u8>>,
    chunk: Zeroizing<Vec<u8>>,
    masked: bool,
    max: usize,
}

/// Adds `data` to `buf`. A larger buffer is new, so no copy stays behind in freed
/// memory.
fn push(buf: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    if buf.len() + data.len() > buf.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity((buf.len() + data.len()) * 2));
        grown.extend_from_slice(buf);
        *buf = grown;
    }
    buf.extend_from_slice(data);
}

impl Frames {
    fn new(early: &[u8], masked: bool, max: usize) -> Self {
        let mut buf = Zeroizing::new(Vec::with_capacity(READ_CHUNK.max(early.len())));
        buf.extend_from_slice(early);
        Self {
            buf,
            chunk: Zeroizing::new(vec![0u8; READ_CHUNK]),
            masked,
            max,
        }
    }

    fn next(&mut self, from: &dyn Endpoint) -> Result<Next, Fault> {
        loop {
            if let Some((frame, used)) = parse(&self.buf, self.masked, self.max)? {
                self.buf.drain(..used);
                return Ok(Next::Frame(frame));
            }
            match from.read(&mut self.chunk) {
                Ok(0) => return Ok(Next::End),
                Ok(read) => push(&mut self.buf, &self.chunk[..read]),
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(Next::Tick);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Fault::Io),
            }
        }
    }
}

const NOT_CLOSING: u64 = u64::MAX;

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The state of one relay that both directions share.
struct Shared<'e> {
    client: &'e dyn Endpoint,
    server: &'e dyn Endpoint,
    limits: Limits,
    started: Instant,
    /// Milliseconds after `started` of the last frame.
    last: AtomicU64,
    /// Milliseconds after `started` of the first Close, or [`NOT_CLOSING`].
    closing: AtomicU64,
    client_closed: AtomicBool,
    server_closed: AtomicBool,
    done: AtomicBool,
}

impl Shared<'_> {
    fn now(&self) -> u64 {
        millis(self.started.elapsed())
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    fn closed(&self, side: Side) -> &AtomicBool {
        match side {
            Side::Client => &self.client_closed,
            Side::Server => &self.server_closed,
        }
    }

    /// Ends the relay once: sends the given Close frames, then closes both
    /// connections, so the other direction stops too.
    fn end(&self, to_client: Option<(u16, &str)>, to_server: Option<(u16, &str)>) {
        if self.done.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some((code, reason)) = to_client {
            let _ = self.client.write_all(&close_frame(code, reason, None));
        }
        if let Some((code, reason)) = to_server
            && let Some(key) = mask_key()
        {
            let _ = self.server.write_all(&close_frame(code, reason, Some(key)));
        }
        self.client.shutdown();
        self.server.shutdown();
    }

    /// The close and idle deadlines, when a read times out.
    fn tick(&self) {
        let now = self.now();
        let closing = self.closing.load(Ordering::SeqCst);
        if closing != NOT_CLOSING {
            if now.saturating_sub(closing) >= millis(self.limits.close_wait) {
                self.end(None, None);
            }
        } else if now.saturating_sub(self.last.load(Ordering::SeqCst)) >= millis(self.limits.idle) {
            let reason = "Apassy closed the WebSocket: no frame for too long.";
            self.end(Some((GOING_AWAY, reason)), Some((GOING_AWAY, reason)));
        }
    }

    /// A frame that breaks the protocol. It is not passed on.
    fn fault(&self, from: Side, code: u16, detail: &'static str, report: &(dyn Fn(Report) + Sync)) {
        match from {
            Side::Client => {
                report(Report::Refused(format!(
                    "The program sent a WebSocket frame that Apassy does not pass on: {detail}."
                )));
                self.end(Some((code, detail)), Some((GOING_AWAY, "")));
            }
            Side::Server => {
                report(Report::Failed(format!(
                    "The service sent a WebSocket frame that Apassy does not pass on: {detail}."
                )));
                self.end(
                    Some((
                        BAD_GATEWAY,
                        "Apassy: the service sent a frame that it does not pass on.",
                    )),
                    Some((code, detail)),
                );
            }
        }
    }
}

/// Relays the frames of one WebSocket both ways until it ends, on this thread and
/// one more. `early_client` and `early_server` are bytes that the handshake read
/// already after the heads. The caller records the handshake; `report` gets the
/// rest. Each endpoint needs a socket read timeout of `limits.tick`.
pub(super) fn relay(
    client: &dyn Endpoint,
    server: &dyn Endpoint,
    early_client: &[u8],
    early_server: &[u8],
    secrets: &Secrets<'_>,
    limits: Limits,
    report: &(dyn Fn(Report) + Sync),
) {
    let shared = Shared {
        client,
        server,
        limits,
        started: Instant::now(),
        last: AtomicU64::new(0),
        closing: AtomicU64::new(NOT_CLOSING),
        client_closed: AtomicBool::new(false),
        server_closed: AtomicBool::new(false),
        done: AtomicBool::new(false),
    };
    thread::scope(|scope| {
        let upward = thread::Builder::new()
            .name("apassy-run-proxy-ws".to_owned())
            .spawn_scoped(scope, || {
                direction(&shared, Side::Client, early_client, secrets, report);
            });
        if upward.is_err() {
            shared.end(None, None);
            return;
        }
        direction(&shared, Side::Server, early_server, secrets, report);
    });
}

/// The frames of one side, to the other side.
fn direction(
    shared: &Shared<'_>,
    from: Side,
    early: &[u8],
    secrets: &Secrets<'_>,
    report: &(dyn Fn(Report) + Sync),
) {
    let (source, sink, other) = match from {
        Side::Client => (shared.client, shared.server, Side::Server),
        Side::Server => (shared.server, shared.client, Side::Client),
    };
    let mut frames = Frames::new(early, from == Side::Client, shared.limits.max_frame);
    let mut scanner = Scanner::new(secrets.placeholders);
    let mut replacer = Replacer::new(secrets.pairs);
    let mut reported = false;
    let mut in_message = false;
    let mut boundary = Boundary::new(secrets.pairs);
    loop {
        if shared.is_done() {
            return;
        }
        let frame = match frames.next(source) {
            Ok(Next::Frame(frame)) => frame,
            Ok(Next::Tick) => {
                shared.tick();
                continue;
            }
            Ok(Next::End) => {
                // A side that ends its connection after its Close leaves time for
                // the answer of the other side; the close deadline still holds.
                if !(shared.closed(from).load(Ordering::SeqCst)
                    && !shared.closed(other).load(Ordering::SeqCst))
                {
                    shared.end(None, None);
                }
                return;
            }
            Err(Fault::Io) => {
                shared.end(None, None);
                return;
            }
            Err(Fault::Bad { code, detail }) => {
                shared.fault(from, code, detail, report);
                return;
            }
        };
        shared.last.store(shared.now(), Ordering::SeqCst);
        if let Err(detail) = check_sequence(&mut in_message, &frame) {
            shared.fault(from, PROTOCOL_ERROR, detail, report);
            return;
        }
        let out = match from {
            Side::Client => {
                // Each frame, data or control, with the end of the earlier ones.
                if let Some(index) = scanner.feed(&frame.payload) {
                    let name = secrets.names.get(index).copied().unwrap_or("a secret");
                    report(Report::Refused(format!(
                        "A WebSocket frame of the program has the placeholder of {name}. Apassy does not put a real value into a frame, so the service would get the placeholder."
                    )));
                    let reason = format!("Apassy: a frame has the placeholder of {name}.");
                    shared.end(
                        Some((POLICY_VIOLATION, reason.as_str())),
                        Some((GOING_AWAY, "")),
                    );
                    return;
                }
                let Some(key) = mask_key() else {
                    shared.end(None, None);
                    return;
                };
                encode(frame.fin, frame.opcode, &frame.payload, Some(key))
            }
            Side::Server => {
                let mut replaced = false;
                let payload = if frame.opcode >= OP_CLOSE {
                    let mut payload = frame.payload.clone();
                    replaced = Replacer::replace_all(secrets.pairs, &mut payload[..]);
                    payload
                } else {
                    if let Some(index) =
                        boundary.feed(frame.opcode == OP_CONTINUATION, &frame.payload)
                    {
                        let name = secrets.names.get(index).copied().unwrap_or("a secret");
                        report(Report::Failed(format!(
                            "A real value of {name} was split over two WebSocket messages of the service. Apassy cannot replace it across messages, so it closed the WebSocket before the rest was sent."
                        )));
                        shared.end(
                            Some((
                                POLICY_VIOLATION,
                                "Apassy: the service split a real value over two messages.",
                            )),
                            Some((GOING_AWAY, "")),
                        );
                        return;
                    }
                    // A value can start in one fragment and end in the next. A
                    // fragment may go out shorter; the last one has the rest.
                    let mut payload = replacer.feed(&frame.payload);
                    if frame.fin {
                        payload.extend_from_slice(&replacer.finish());
                    }
                    payload
                };
                if (replaced || replacer.replaced) && !reported {
                    reported = true;
                    report(Report::Replaced);
                }
                encode(frame.fin, frame.opcode, &payload, None)
            }
        };
        if sink.write_all(&out).is_err() {
            shared.end(None, None);
            return;
        }
        if frame.opcode == OP_CLOSE {
            shared.closed(from).store(true, Ordering::SeqCst);
            if shared.closed(other).load(Ordering::SeqCst) {
                // Both Close frames went through: the WebSocket is closed.
                shared.end(None, None);
                return;
            }
            let _ = shared.closing.compare_exchange(
                NOT_CLOSING,
                shared.now(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
    }
}

/// Finds a real value that starts at the end of one data message of the service
/// and ends in the next one (judge finding L2). It keeps the end of the data
/// stream across messages (the longest value less one byte) and the start of the
/// current message.
struct Boundary<'a> {
    pairs: &'a [(&'a [u8], &'a [u8])],
    patterns: Vec<(usize, super::echo::Pattern)>,
    keep: usize,
    /// The last `keep` bytes of the data stream, before this frame.
    tail: Zeroizing<Vec<u8>>,
    /// The tail at the start of the current message.
    before: Zeroizing<Vec<u8>>,
    /// The first bytes of the current message, up to `keep`.
    start: Zeroizing<Vec<u8>>,
}

impl<'a> Boundary<'a> {
    fn new(pairs: &'a [(&'a [u8], &'a [u8])]) -> Self {
        let patterns: Vec<_> = pairs
            .iter()
            .enumerate()
            .filter_map(|(index, (from, to))| {
                super::echo::Pattern::escaped(from, to).map(|p| (index, p))
            })
            .collect();
        let keep = pairs
            .iter()
            .map(|(from, _)| from.len())
            .chain(patterns.iter().map(|(_, pattern)| pattern.max_len()))
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Self {
            pairs,
            patterns,
            keep,
            tail: Zeroizing::new(Vec::new()),
            before: Zeroizing::new(Vec::new()),
            start: Zeroizing::new(Vec::new()),
        }
    }

    /// One data frame; `continuation` for a later fragment of a message. The index
    /// of a pair whose value spans the start of this message, before the frame is
    /// sent.
    fn feed(&mut self, continuation: bool, payload: &[u8]) -> Option<usize> {
        if !continuation {
            self.before = Zeroizing::new(self.tail.to_vec());
            self.start.clear();
        }
        let mut found = None;
        if self.start.len() < self.keep && !self.before.is_empty() {
            let more = (self.keep - self.start.len()).min(payload.len());
            self.start.extend_from_slice(&payload[..more]);
            found = self.pairs.iter().position(|(value, _)| {
                (1..value.len()).any(|k| {
                    self.before.ends_with(&value[..k]) && self.start.starts_with(&value[k..])
                })
            });
            if found.is_none() {
                let mut window = Zeroizing::new(self.before.to_vec());
                window.extend_from_slice(&self.start);
                found = self.patterns.iter().find_map(|(index, pattern)| {
                    (0..self.before.len()).any(|start| {
                        matches!(pattern.match_at(&window, start, true), super::echo::Step::Full(len)
                            if start + len > self.before.len())
                    }).then_some(*index)
                });
            }
        }
        let mut window = Zeroizing::new(Vec::with_capacity(self.tail.len() + payload.len()));
        window.extend_from_slice(&self.tail);
        window.extend_from_slice(payload);
        let from = window.len().saturating_sub(self.keep);
        self.tail = Zeroizing::new(window[from..].to_vec());
        found
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;

    use super::super::http1::parse_request_head;
    use super::*;

    #[test]
    fn encoded_values_cannot_cross_websocket_message_boundaries() {
        let value = b"FAKE+token/value&";
        let placeholder = vec![b'Q'; value.len()];
        let pairs = [(value.as_slice(), placeholder.as_slice())];
        for echo in [
            "FAKE%2Btoken%2Fvalue%26",
            "FAKE%2btoken%2fvalue%26",
            r"FAKE+token\/value&",
            "FAKE+token&#x2F;value&amp;",
        ] {
            for split in 1..echo.len() {
                let mut boundary = Boundary::new(&pairs);
                assert_eq!(boundary.feed(false, &echo.as_bytes()[..split]), None);
                assert_eq!(
                    boundary.feed(false, &echo.as_bytes()[split..]),
                    Some(0),
                    "{echo}, {split}"
                );
                let mut boundary = Boundary::new(&pairs);
                assert_eq!(boundary.feed(false, &echo.as_bytes()[..split]), None);
                assert_eq!(boundary.feed(true, &echo.as_bytes()[split..]), None);
            }
        }
    }

    const VALUE: &[u8] = b"sk_test_FAKE-ws-value-0123456789";
    const PLACEHOLDER: &[u8] = b"sk_test_PHPH-ws-phold-abcdefghij";
    const NAME: &str = "WS_KEY";

    /// A plain TCP side, for the tests of the frame relay.
    struct Plain {
        stream: TcpStream,
        write: Mutex<()>,
    }

    impl Endpoint for Plain {
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut stream = &self.stream;
            stream.read(buf)
        }

        fn write_all(&self, data: &[u8]) -> io::Result<()> {
            let _guard = self.write.lock().map_err(|_| io::Error::other("lock"))?;
            let mut stream = &self.stream;
            stream.write_all(data)
        }

        fn shutdown(&self) {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let outer = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (inner, _) = listener.accept().expect("accept");
        outer
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        (outer, inner)
    }

    struct Running {
        /// The program's end of the client connection.
        program: TcpStream,
        /// The service's end of the server connection.
        service: TcpStream,
        reports: Arc<Mutex<Vec<Report>>>,
        relay: thread::JoinHandle<()>,
    }

    fn limits() -> Limits {
        Limits {
            max_frame: 1024,
            idle: Duration::from_secs(30),
            close_wait: Duration::from_millis(300),
            tick: Duration::from_millis(50),
        }
    }

    fn start(limits: Limits, early_client: Vec<u8>, early_server: Vec<u8>) -> Running {
        let (program, client_side) = pair();
        let (service, server_side) = pair();
        for side in [&client_side, &server_side] {
            side.set_read_timeout(Some(limits.tick)).expect("tick");
        }
        let reports: Arc<Mutex<Vec<Report>>> = Arc::default();
        let seen = Arc::clone(&reports);
        let relay = thread::spawn(move || {
            let client = Plain {
                stream: client_side,
                write: Mutex::new(()),
            };
            let server = Plain {
                stream: server_side,
                write: Mutex::new(()),
            };
            let placeholders: [&[u8]; 1] = [PLACEHOLDER];
            let pairs: [(&[u8], &[u8]); 1] = [(VALUE, PLACEHOLDER)];
            let names = [NAME];
            let secrets = Secrets {
                placeholders: &placeholders,
                pairs: &pairs,
                names: &names,
            };
            let report = move |report: Report| seen.lock().expect("reports").push(report);
            relay(
                &client,
                &server,
                &early_client,
                &early_server,
                &secrets,
                limits,
                &report,
            );
        });
        Running {
            program,
            service,
            reports,
            relay,
        }
    }

    /// A frame as a peer reads it: (fin, opcode, unmasked payload, was masked).
    fn read_frame(stream: &mut TcpStream) -> Option<(bool, u8, Vec<u8>, bool)> {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).ok()?;
        let masked = head[1] & 0x80 != 0;
        let len = match head[1] & 0x7f {
            126 => {
                let mut bytes = [0u8; 2];
                stream.read_exact(&mut bytes).ok()?;
                usize::from(u16::from_be_bytes(bytes))
            }
            127 => {
                let mut bytes = [0u8; 8];
                stream.read_exact(&mut bytes).ok()?;
                usize::try_from(u64::from_be_bytes(bytes)).ok()?
            }
            short => usize::from(short),
        };
        let mut key = [0u8; 4];
        if masked {
            stream.read_exact(&mut key).ok()?;
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).ok()?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[index % 4];
            }
        }
        Some((head[0] & 0x80 != 0, head[0] & 0x0f, payload, masked))
    }

    fn client_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        encode(fin, opcode, payload, Some([0x11, 0x22, 0x33, 0x44])).to_vec()
    }

    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        encode(fin, opcode, payload, None).to_vec()
    }

    fn close_code(payload: &[u8]) -> u16 {
        u16::from_be_bytes([payload[0], payload[1]])
    }

    /// Reads until the end of the stream; true when it ends (a reset counts), false
    /// when the read timeout comes first.
    fn ends(stream: &mut TcpStream) -> bool {
        let mut rest = Vec::new();
        match stream.read_to_end(&mut rest) {
            Ok(_) => true,
            Err(err) => !matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn no_secret_in(reports: &[Report]) {
        let text = format!("{reports:?}");
        assert!(!contains(text.as_bytes(), VALUE), "{text}");
        assert!(!contains(text.as_bytes(), PLACEHOLDER), "{text}");
    }

    #[test]
    fn frames_go_both_ways_with_a_new_mask_to_the_service() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        run.program
            .write_all(&client_frame(true, OP_TEXT, b"hello"))
            .expect("write");
        let (fin, opcode, payload, masked) = read_frame(&mut run.service).expect("frame");
        assert!(fin && masked);
        assert_eq!((opcode, payload.as_slice()), (OP_TEXT, &b"hello"[..]));
        run.service
            .write_all(&server_frame(true, OP_BINARY, b"\x00\x01world"))
            .expect("write");
        let (_, opcode, payload, masked) = read_frame(&mut run.program).expect("frame");
        assert!(!masked);
        assert_eq!(
            (opcode, payload.as_slice()),
            (OP_BINARY, &b"\x00\x01world"[..])
        );
        // A ping and its pong pass, too.
        run.service
            .write_all(&server_frame(true, OP_PING, b"p"))
            .expect("ping");
        assert_eq!(read_frame(&mut run.program).expect("ping").1, OP_PING);
        run.program
            .write_all(&client_frame(true, OP_PONG, b"p"))
            .expect("pong");
        assert_eq!(read_frame(&mut run.service).expect("pong").1, OP_PONG);
        // A larger frame keeps its bytes.
        let big = vec![b'x'; 700];
        run.program
            .write_all(&client_frame(true, OP_BINARY, &big))
            .expect("big");
        assert_eq!(read_frame(&mut run.service).expect("big").2, big);
        drop(run.program);
        assert!(ends(&mut run.service));
        run.relay.join().expect("relay");
        assert!(run.reports.lock().expect("reports").is_empty());
    }

    #[test]
    fn early_bytes_of_the_handshake_come_first() {
        let mut run = start(
            limits(),
            client_frame(true, OP_TEXT, b"early from the program"),
            server_frame(true, OP_TEXT, b"early from the service"),
        );
        assert_eq!(
            read_frame(&mut run.service).expect("frame").2,
            b"early from the program"
        );
        assert_eq!(
            read_frame(&mut run.program).expect("frame").2,
            b"early from the service"
        );
        drop(run.service);
        assert!(ends(&mut run.program));
        run.relay.join().expect("relay");
    }

    #[test]
    fn a_server_frame_with_the_value_reaches_the_client_as_the_placeholder() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        let mut whole = b"{\"token\":\"".to_vec();
        whole.extend_from_slice(VALUE);
        whole.extend_from_slice(b"\"}");
        run.service
            .write_all(&server_frame(true, OP_TEXT, &whole))
            .expect("write");
        let (_, _, payload, _) = read_frame(&mut run.program).expect("frame");
        assert_eq!(payload.len(), whole.len(), "the same length");
        assert!(contains(&payload, PLACEHOLDER), "{payload:?}");
        assert!(!contains(&payload, VALUE));

        // The value split over two fragments of one message, with a ping between.
        let (a, b) = VALUE.split_at(11);
        let mut first = b"v=".to_vec();
        first.extend_from_slice(a);
        let mut second = b.to_vec();
        second.extend_from_slice(b";");
        run.service
            .write_all(&server_frame(false, OP_TEXT, &first))
            .expect("first");
        run.service
            .write_all(&server_frame(true, OP_PING, b"keep"))
            .expect("ping");
        run.service
            .write_all(&server_frame(true, OP_CONTINUATION, &second))
            .expect("second");
        let mut message = Vec::new();
        loop {
            let (fin, opcode, payload, _) = read_frame(&mut run.program).expect("fragment");
            if opcode == OP_PING {
                continue;
            }
            message.extend_from_slice(&payload);
            if fin {
                break;
            }
        }
        let mut expected = b"v=".to_vec();
        expected.extend_from_slice(PLACEHOLDER);
        expected.push(b';');
        assert_eq!(message, expected);

        // A value in a control frame.
        let mut close = 1000u16.to_be_bytes().to_vec();
        close.extend_from_slice(VALUE);
        run.service
            .write_all(&server_frame(true, OP_CLOSE, &close))
            .expect("close");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("close");
        assert_eq!(opcode, OP_CLOSE);
        assert_eq!(&payload[2..], PLACEHOLDER);
        run.program
            .write_all(&client_frame(true, OP_CLOSE, &1000u16.to_be_bytes()))
            .expect("close answer");
        assert_eq!(read_frame(&mut run.service).expect("close").1, OP_CLOSE);
        run.relay.join().expect("relay");
        let reports = run.reports.lock().expect("reports").clone();
        assert_eq!(
            reports,
            vec![Report::Replaced],
            "one note for the connection"
        );
    }

    /// Judge finding L2: a value that the service splits over two messages closes
    /// the WebSocket with 1008; the rest of the value never reaches the program.
    #[test]
    fn a_value_split_over_two_server_messages_closes_with_1008() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        // Two whole messages that only touch: they pass.
        run.service
            .write_all(&server_frame(true, OP_TEXT, b"first"))
            .expect("first");
        assert_eq!(read_frame(&mut run.program).expect("first").2, b"first");
        run.service
            .write_all(&server_frame(true, OP_TEXT, b"second"))
            .expect("second");
        assert_eq!(read_frame(&mut run.program).expect("second").2, b"second");

        let (a, b) = VALUE.split_at(11);
        let mut first = b"v=".to_vec();
        first.extend_from_slice(a);
        let mut second = b.to_vec();
        second.extend_from_slice(b";");
        run.service
            .write_all(&server_frame(true, OP_TEXT, &first))
            .expect("first part");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("first part");
        assert_eq!((opcode, payload.as_slice()), (OP_TEXT, first.as_slice()));
        run.service
            .write_all(&server_frame(true, OP_TEXT, &second))
            .expect("second part");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("close");
        assert_eq!(opcode, OP_CLOSE);
        assert_eq!(close_code(&payload), 1008);
        assert!(!contains(&payload, b), "the rest of the value is not sent");
        let (_, opcode, payload, _) = read_frame(&mut run.service).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1001));
        run.relay.join().expect("relay");
        let reports = run.reports.lock().expect("reports").clone();
        assert!(
            matches!(reports.as_slice(), [Report::Failed(text)] if text.contains(NAME)),
            "{reports:?}"
        );
        no_secret_in(&reports);
    }

    #[test]
    fn the_boundary_check_sees_a_value_over_three_messages() {
        let pairs: [(&[u8], &[u8]); 1] = [(VALUE, PLACEHOLDER)];
        let mut boundary = Boundary::new(&pairs);
        assert_eq!(boundary.feed(false, &VALUE[..5]), None);
        assert_eq!(boundary.feed(false, &VALUE[5..7]), None, "undecided");
        assert_eq!(boundary.feed(false, &VALUE[7..]), Some(0));
        // A value inside one message, then another message: no finding.
        let mut boundary = Boundary::new(&pairs);
        assert_eq!(boundary.feed(false, VALUE), None);
        assert_eq!(boundary.feed(false, b"next"), None);
        // Fragments of one message are the replacer's work, not a boundary.
        let mut boundary = Boundary::new(&pairs);
        assert_eq!(boundary.feed(false, &VALUE[..9]), None);
        assert_eq!(boundary.feed(true, &VALUE[9..]), None);
    }

    #[test]
    fn a_client_frame_with_a_placeholder_closes_with_1008() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        run.program
            .write_all(&client_frame(true, OP_TEXT, b"fine"))
            .expect("write");
        assert_eq!(read_frame(&mut run.service).expect("frame").2, b"fine");
        // Split over two frames: the second one is not sent.
        let (a, b) = PLACEHOLDER.split_at(9);
        run.program
            .write_all(&client_frame(false, OP_TEXT, a))
            .expect("first");
        let (_, _, first, _) = read_frame(&mut run.service).expect("first part");
        assert_eq!(first, a);
        run.program
            .write_all(&client_frame(true, OP_CONTINUATION, b))
            .expect("second");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("close");
        assert_eq!(opcode, OP_CLOSE);
        assert_eq!(close_code(&payload), 1008);
        let reason = String::from_utf8(payload[2..].to_vec()).expect("utf-8");
        assert!(reason.contains(NAME), "{reason}");
        assert!(ends(&mut run.program));
        // The service gets Close 1001 and never the rest of the placeholder.
        let (_, opcode, payload, _) = read_frame(&mut run.service).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1001));
        let mut rest = Vec::new();
        let _ = run.service.read_to_end(&mut rest);
        assert!(!contains(&rest, b), "{rest:?}");
        run.relay.join().expect("relay");
        let reports = run.reports.lock().expect("reports").clone();
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(&reports[0], Report::Refused(text) if text.contains(NAME)),
            "{reports:?}"
        );
        no_secret_in(&reports);
    }

    #[test]
    fn a_placeholder_in_a_control_frame_is_refused_too() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        run.program
            .write_all(&client_frame(true, OP_PING, PLACEHOLDER))
            .expect("ping");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1008));
        let (_, opcode, _, _) = read_frame(&mut run.service).expect("close");
        assert_eq!(opcode, OP_CLOSE, "the ping is not sent");
        run.relay.join().expect("relay");
        no_secret_in(&run.reports.lock().expect("reports"));
    }

    #[test]
    fn a_close_handshake_goes_through_and_ends_both() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        run.program
            .write_all(&client_frame(true, OP_CLOSE, &1000u16.to_be_bytes()))
            .expect("close");
        let (_, opcode, payload, _) = read_frame(&mut run.service).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1000));
        run.service
            .write_all(&server_frame(true, OP_CLOSE, &1000u16.to_be_bytes()))
            .expect("answer");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("answer");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1000));
        assert!(ends(&mut run.program));
        assert!(ends(&mut run.service));
        run.relay.join().expect("relay");
    }

    #[test]
    fn an_unanswered_close_ends_after_the_close_deadline() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        let started = Instant::now();
        run.program
            .write_all(&client_frame(true, OP_CLOSE, &1000u16.to_be_bytes()))
            .expect("close");
        assert_eq!(read_frame(&mut run.service).expect("close").1, OP_CLOSE);
        // The service never answers.
        assert!(ends(&mut run.program));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(250), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        run.relay.join().expect("relay");
    }

    #[test]
    fn a_program_that_hangs_up_after_its_close_still_gets_the_deadline() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        run.program
            .write_all(&client_frame(true, OP_CLOSE, &1000u16.to_be_bytes()))
            .expect("close");
        run.program.shutdown(Shutdown::Write).expect("half close");
        assert_eq!(read_frame(&mut run.service).expect("close").1, OP_CLOSE);
        // The answer of the service still reaches the program.
        run.service
            .write_all(&server_frame(true, OP_CLOSE, &1000u16.to_be_bytes()))
            .expect("answer");
        assert_eq!(read_frame(&mut run.program).expect("answer").1, OP_CLOSE);
        run.relay.join().expect("relay");
    }

    #[test]
    fn an_idle_websocket_is_closed_with_1001() {
        let mut run = start(
            Limits {
                idle: Duration::from_millis(300),
                ..limits()
            },
            Vec::new(),
            Vec::new(),
        );
        run.program
            .write_all(&client_frame(true, OP_TEXT, b"one"))
            .expect("write");
        assert_eq!(read_frame(&mut run.service).expect("frame").2, b"one");
        let started = Instant::now();
        let (_, opcode, payload, masked) = read_frame(&mut run.program).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1001));
        assert!(!masked);
        let (_, opcode, payload, masked) = read_frame(&mut run.service).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1001));
        assert!(masked);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(ends(&mut run.program));
        assert!(ends(&mut run.service));
        run.relay.join().expect("relay");
        assert!(run.reports.lock().expect("reports").is_empty());
    }

    #[test]
    fn a_frame_above_the_cap_closes_with_1009_and_is_not_sent() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        // Only the head: the relay refuses before the payload comes.
        let mut head = vec![0x82, 0x80 | 126];
        head.extend_from_slice(&2000u16.to_be_bytes());
        head.extend_from_slice(&[1, 2, 3, 4]);
        run.program.write_all(&head).expect("head");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1009));
        let (_, opcode, payload, _) = read_frame(&mut run.service).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1001));
        run.relay.join().expect("relay");
        let reports = run.reports.lock().expect("reports").clone();
        assert!(matches!(&reports[..], [Report::Refused(_)]), "{reports:?}");
    }

    #[test]
    fn protocol_errors_close_with_1002() {
        for bad in [
            // An unmasked frame of the program.
            server_frame(true, OP_TEXT, b"x"),
            // A reserved bit: a compressed frame.
            {
                let mut frame = client_frame(true, OP_TEXT, b"x");
                frame[0] |= 0x40;
                frame
            },
            // An unknown opcode.
            client_frame(true, 0x3, b"x"),
            // A fragmented control frame.
            client_frame(false, OP_PING, b"x"),
            // A continuation without a message.
            client_frame(true, OP_CONTINUATION, b"x"),
        ] {
            let mut run = start(limits(), Vec::new(), Vec::new());
            run.program.write_all(&bad).expect("write");
            let (_, opcode, payload, _) = read_frame(&mut run.program).expect("close");
            assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1002), "{bad:?}");
            let (_, opcode, _, _) = read_frame(&mut run.service).expect("close");
            assert_eq!(
                opcode, OP_CLOSE,
                "{bad:?}: nothing else reaches the service"
            );
            run.relay.join().expect("relay");
        }
    }

    #[test]
    fn a_compressed_frame_of_the_service_is_not_passed_on() {
        let mut run = start(limits(), Vec::new(), Vec::new());
        let mut frame = server_frame(true, OP_TEXT, VALUE);
        frame[0] |= 0x40;
        run.service.write_all(&frame).expect("write");
        let (_, opcode, payload, _) = read_frame(&mut run.program).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1014));
        assert!(!contains(&payload, VALUE));
        let (_, opcode, payload, masked) = read_frame(&mut run.service).expect("close");
        assert_eq!((opcode, close_code(&payload)), (OP_CLOSE, 1002));
        assert!(masked);
        run.relay.join().expect("relay");
        let reports = run.reports.lock().expect("reports").clone();
        assert!(matches!(&reports[..], [Report::Failed(_)]), "{reports:?}");
        no_secret_in(&reports);
    }

    #[test]
    fn the_handshake_helpers() {
        let request = parse_request_head(
            b"GET /ws HTTP/1.1\r\nHost: a.example\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        )
        .expect("head");
        assert!(is_websocket(&request));
        let sent = handshake_request(&request);
        assert!(sent.header("sec-websocket-extensions").is_none());
        assert_eq!(sent.header("sec-websocket-key"), Some("x"));
        assert_eq!(sent.header("upgrade"), Some("websocket"));
        for other in [
            &b"POST /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"[..],
            b"GET /ws HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
            b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
        ] {
            assert!(!is_websocket(&parse_request_head(other).expect("head")));
        }
        assert!(
            check_accept(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .is_ok()
        );
        assert!(check_accept(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n").is_err());
        assert!(check_accept(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n").is_err());
    }

    #[test]
    fn frames_round_trip_in_every_length_form() {
        for len in [0usize, 125, 126, 65535, 65536] {
            let payload: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
            for mask in [None, Some([9, 8, 7, 6])] {
                let frame = encode(true, OP_BINARY, &payload, mask);
                let (parsed, used) = parse(&frame, mask.is_some(), 1 << 20)
                    .ok()
                    .flatten()
                    .expect("frame");
                assert_eq!(used, frame.len());
                assert_eq!(parsed.payload.as_slice(), payload.as_slice());
                // A part of the frame is not a frame yet.
                assert!(matches!(
                    parse(&frame[..frame.len() - 1], mask.is_some(), 1 << 20),
                    Ok(None)
                ));
            }
        }
        let long = "é".repeat(100);
        let frame = close_frame(1008, &long, None);
        let (parsed, _) = parse(&frame, false, 1024).ok().flatten().expect("close");
        assert!(parsed.payload.len() <= 125);
        assert!(std::str::from_utf8(&parsed.payload[2..]).is_ok());
    }
}
