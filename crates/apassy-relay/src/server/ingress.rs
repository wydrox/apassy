//! The Connect ingress for cloud agents (docs/contracts/connect-tunnel-v1.md section 7).
//!
//! Port 443 (`APASSY_CONNECT_INGRESS_LISTEN`): read the first TLS record (at most
//! 16 KiB, within 5 seconds), take only the `server_name` of the ClientHello with a
//! strict parser, and forward the exact bytes read as the `open` of a `public` stream to
//! the node of that name; then copy both ways unchanged. A name of no registered,
//! online, entitled node gets the fatal alert `unrecognized_name` and a close.
//!
//! Port 80 (`APASSY_CONNECT_ACME_LISTEN`): read the request head (at most 8 KiB, within
//! 5 seconds); forward only `GET /.well-known/acme-challenge/<token>` over HTTP/1.1 for
//! the public name of an online node, as an `acme` stream; answer anything else
//! `404 Not Found` and forward nothing.
//!
//! Client addresses stay in memory, for a per-address limit of new connections
//! ([`IngressConfig::per_address_per_minute`], IPv6 by /64), and are never logged,
//! stored, or sent to the node. Handshakes in progress are capped
//! ([`IngressConfig::max_pending`]); after the handshake a connection is a stream of the
//! ingress class of the node's account (its own slots, per-node open rate, first-byte
//! deadline, and byte budget: `tunnel::Limits`), apart from the account's dials. A
//! failing accept backs off ([`accept_backoff`]).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::tunnel::frame::{CLOSE, Kind};
use super::tunnel::{Broker, IngressRefusal};

/// The largest TLS record payload the ingress reads (2^14, RFC 8446 section 5.1).
pub const MAX_RECORD: usize = 16 * 1024;
/// The largest ACME request head.
pub const MAX_ACME_HEAD: usize = 8 * 1024;
/// The fatal TLS alert `unrecognized_name` (contract 7.1).
pub const ALERT_UNRECOGNIZED_NAME: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];
/// The answer to every ACME request that is not forwarded.
pub const ACME_NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const ACME_PREFIX: &str = "/.well-known/acme-challenge/";

/// Why a first TLS record is not a ClientHello with one server name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloError {
    /// The record ended before a field did.
    Truncated,
    /// Not a handshake record.
    NotHandshake,
    /// A record or hello version that is not TLS 1.0 to 1.2 on the wire.
    BadVersion,
    /// A record length over 16 KiB, or 0.
    BadRecordLength,
    /// The first handshake message is not a ClientHello.
    NotClientHello,
    /// The ClientHello does not fit in the first record.
    Fragmented,
    /// A length or a field that does not add up, a duplicate extension, or extra bytes.
    Malformed,
    /// No `server_name` extension (or no `host_name` in it).
    NoServerName,
    /// A server name that is not a host name, or more than one name.
    BadServerName,
}

/// Why reading the first record stopped.
#[derive(Debug)]
pub enum ReadError {
    Hello(HelloError),
    /// The 5-second deadline passed.
    Timeout,
    Io(io::Error),
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], HelloError> {
        let end = self.at.checked_add(len).ok_or(HelloError::Truncated)?;
        let slice = self.bytes.get(self.at..end).ok_or(HelloError::Truncated)?;
        self.at = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, HelloError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, HelloError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
    fn u24(&mut self) -> Result<usize, HelloError> {
        let bytes = self.take(3)?;
        Ok(usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]))
    }
    fn rest(&self) -> usize {
        self.bytes.len() - self.at
    }
    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

/// The payload length of a TLS record from its 5-byte header.
pub fn record_length(header: &[u8; 5]) -> Result<usize, HelloError> {
    if header[0] != 0x16 {
        return Err(HelloError::NotHandshake);
    }
    if header[1] != 0x03 || !(0x01..=0x03).contains(&header[2]) {
        return Err(HelloError::BadVersion);
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length == 0 || length > MAX_RECORD {
        return Err(HelloError::BadRecordLength);
    }
    Ok(length)
}

/// The server name of the ClientHello in one whole TLS record (header and payload,
/// nothing after), lowercased. Strict: every length must add up exactly.
pub fn server_name(record: &[u8]) -> Result<String, HelloError> {
    let header: &[u8; 5] = record
        .get(..5)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(HelloError::Truncated)?;
    let length = record_length(header)?;
    if record.len() - 5 < length {
        return Err(HelloError::Truncated);
    }
    if record.len() - 5 > length {
        return Err(HelloError::Malformed);
    }
    let mut payload = Cursor::new(&record[5..]);
    if payload.u8()? != 0x01 {
        return Err(HelloError::NotClientHello);
    }
    let hello_length = payload.u24()?;
    if hello_length > payload.rest() {
        return Err(HelloError::Fragmented);
    }
    if hello_length < payload.rest() {
        return Err(HelloError::Malformed);
    }
    let mut hello = Cursor::new(payload.take(hello_length)?);
    let version = hello.u16()?;
    if !(0x0301..=0x0303).contains(&version) {
        return Err(HelloError::BadVersion);
    }
    hello.take(32)?; // random
    let session = usize::from(hello.u8()?);
    if session > 32 {
        return Err(HelloError::Malformed);
    }
    hello.take(session)?;
    let suites = usize::from(hello.u16()?);
    if suites < 2 || suites % 2 != 0 {
        return Err(HelloError::Malformed);
    }
    hello.take(suites)?;
    let compression = usize::from(hello.u8()?);
    if compression < 1 {
        return Err(HelloError::Malformed);
    }
    hello.take(compression)?;
    if hello.done() {
        return Err(HelloError::NoServerName);
    }
    let extensions_length = usize::from(hello.u16()?);
    if extensions_length != hello.rest() {
        return Err(HelloError::Malformed);
    }
    let mut extensions = Cursor::new(hello.take(extensions_length)?);
    let mut seen = Vec::new();
    let mut name = None;
    while !extensions.done() {
        let kind = extensions.u16()?;
        let length = usize::from(extensions.u16()?);
        let data = extensions.take(length)?;
        if seen.contains(&kind) {
            return Err(HelloError::Malformed);
        }
        seen.push(kind);
        if kind == 0 {
            name = Some(parse_server_name(data)?);
        }
    }
    name.ok_or(HelloError::NoServerName)
}

fn parse_server_name(data: &[u8]) -> Result<String, HelloError> {
    let mut cursor = Cursor::new(data);
    let list = usize::from(cursor.u16()?);
    if list != cursor.rest() {
        return Err(HelloError::Malformed);
    }
    let mut host = None;
    while !cursor.done() {
        let kind = cursor.u8()?;
        let length = usize::from(cursor.u16()?);
        let name = cursor.take(length)?;
        if kind != 0 || host.is_some() {
            // One `host_name` entry and nothing else (contract 7.1).
            return Err(HelloError::BadServerName);
        }
        host = Some(name);
    }
    let host = host.ok_or(HelloError::NoServerName)?;
    if !valid_host(host) {
        return Err(HelloError::BadServerName);
    }
    Ok(String::from_utf8_lossy(host).to_ascii_lowercase())
}

/// A DNS host name: 1 to 253 bytes, labels of 1 to 63 letters, digits, and hyphens,
/// not starting or ending with a hyphen, no trailing dot.
pub fn valid_host(host: &[u8]) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
        })
}

fn read_until(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), ReadError> {
    let mut filled = 0;
    while filled < buffer.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ReadError::Timeout);
        }
        stream.set_read_timeout(Some(left)).map_err(ReadError::Io)?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(ReadError::Hello(HelloError::Truncated)),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ReadError::Timeout);
            }
            Err(error) => return Err(ReadError::Io(error)),
        }
    }
    Ok(())
}

/// Reads exactly the first TLS record (never a byte more) within `limit`.
pub fn read_first_record(stream: &mut TcpStream, limit: Duration) -> Result<Vec<u8>, ReadError> {
    let deadline = Instant::now() + limit;
    let mut header = [0u8; 5];
    read_until(stream, &mut header, deadline)?;
    let length = record_length(&header).map_err(ReadError::Hello)?;
    let mut record = vec![0u8; 5 + length];
    record[..5].copy_from_slice(&header);
    read_until(stream, &mut record[5..], deadline)?;
    Ok(record)
}

/// The host of an ACME HTTP-01 request head (lowercased, without `:80`), if the head is
/// exactly `GET /.well-known/acme-challenge/<token> HTTP/1.1` with one `Host` and no
/// body. `head` ends with the empty line.
pub fn acme_host(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let body = text.strip_suffix("\r\n\r\n")?;
    if body.split("\r\n").any(|line| line.contains(['\r', '\n'])) {
        return None;
    }
    let mut lines = body.split("\r\n");
    let request = lines.next()?;
    let path = request.strip_prefix("GET ")?.strip_suffix(" HTTP/1.1")?;
    let token = path.strip_prefix(ACME_PREFIX)?;
    if token.is_empty()
        || token.len() > 128
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    let mut host = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return None;
        }
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            return None;
        }
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return None;
            }
            let value = value.trim_matches([' ', '\t']);
            let value = value.strip_suffix(":80").unwrap_or(value);
            if !valid_host(value.as_bytes()) {
                return None;
            }
            host = Some(value.to_ascii_lowercase());
        }
    }
    host
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Reads an HTTP request head of at most [`MAX_ACME_HEAD`] bytes within `limit`.
/// `None` for a head that is too long, cut, slow, or followed by more bytes.
pub fn read_acme_head(stream: &mut TcpStream, limit: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + limit;
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(left)).ok()?;
        let room = MAX_ACME_HEAD - head.len();
        if room == 0 {
            return None;
        }
        let want = room.min(chunk.len());
        let read = match stream.read(&mut chunk[..want]) {
            Ok(0) => return None,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        head.extend_from_slice(&chunk[..read]);
        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            // Bytes after the head (a body or a second request) are refused.
            return (end + 4 == head.len()).then_some(head);
        }
    }
}

/// The settings of both listeners.
#[derive(Debug, Clone)]
pub struct IngressConfig {
    /// New connections of one address (IPv6: one /64) in one minute (contract: 30).
    pub per_address_per_minute: u32,
    /// Addresses remembered at once; when full and none has expired, new ones are
    /// refused.
    pub max_addresses: usize,
    /// Connections still in their first record or request head.
    pub max_pending: usize,
    /// The deadline of the first record or head (contract: 5 seconds).
    pub read_limit: Duration,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            per_address_per_minute: 30,
            max_addresses: 65_536,
            max_pending: 256,
            read_limit: Duration::from_secs(5),
        }
    }
}

/// Counters of one listener. No address, no name.
#[derive(Debug, Default)]
pub struct IngressStats {
    pub accepted: AtomicU64,
    pub rate_limited: AtomicU64,
    pub busy: AtomicU64,
    pub malformed: AtomicU64,
    pub timeouts: AtomicU64,
    pub unrecognized: AtomicU64,
    pub limited: AtomicU64,
    pub forwarded: AtomicU64,
    /// Accepts that failed (such as a full descriptor table); each waits
    /// [`accept_backoff`] before the next accept.
    pub accept_errors: AtomicU64,
}

impl IngressStats {
    /// The counters by name.
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        [
            ("accepted", &self.accepted),
            ("rate_limited", &self.rate_limited),
            ("busy", &self.busy),
            ("malformed", &self.malformed),
            ("timeouts", &self.timeouts),
            ("unrecognized", &self.unrecognized),
            ("limited", &self.limited),
            ("forwarded", &self.forwarded),
            ("accept_errors", &self.accept_errors),
        ]
        .into_iter()
        .map(|(name, counter)| (name, counter.load(Ordering::Relaxed)))
        .collect()
    }
}

/// The per-address limit of new connections, in memory only.
struct AddressLimiter {
    epoch: Instant,
    per_minute: u32,
    max: usize,
    windows: Mutex<HashMap<[u8; 16], (u64, u32)>>,
}

impl AddressLimiter {
    fn new(per_minute: u32, max: usize) -> Self {
        Self {
            epoch: Instant::now(),
            per_minute,
            max,
            windows: Mutex::new(HashMap::new()),
        }
    }

    fn key(ip: IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_ipv6_mapped().octets(),
                None => {
                    // One /64: a single host easily holds a whole /64.
                    let mut key = v6.octets();
                    key[8..].fill(0);
                    key
                }
            },
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let minute = self.epoch.elapsed().as_secs() / 60;
        let key = Self::key(ip);
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !windows.contains_key(&key) && windows.len() >= self.max {
            windows.retain(|_, (at, _)| *at == minute);
            if windows.len() >= self.max {
                return false;
            }
        }
        let window = windows.entry(key).or_insert((minute, 0));
        if window.0 != minute {
            *window = (minute, 0);
        }
        if window.1 >= self.per_minute {
            return false;
        }
        window.1 += 1;
        true
    }
}

/// A running listener.
pub struct IngressHandle {
    pub addr: SocketAddr,
    pub stats: Arc<IngressStats>,
    stop: Arc<AtomicBool>,
}

impl IngressHandle {
    /// Stops accepting (open streams go on).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

impl Drop for IngressHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The wait after `failures` accepts in a row failed: 10 ms, doubling, at most 1 s. A
/// failing accept (a full descriptor table, a full backlog) never spins the loop.
pub fn accept_backoff(failures: u32) -> Duration {
    let millis = 10u64.saturating_mul(1u64 << failures.saturating_sub(1).min(16));
    Duration::from_millis(millis.min(1000))
}

#[derive(Clone, Copy)]
enum Port {
    Tls,
    Acme,
}

/// Serves the SNI ingress (port 443) on `listener`.
pub fn serve_sni(
    listener: TcpListener,
    broker: Broker,
    config: IngressConfig,
) -> io::Result<IngressHandle> {
    serve(listener, broker, config, Port::Tls)
}

/// Serves the ACME HTTP-01 listener (port 80) on `listener`.
pub fn serve_acme(
    listener: TcpListener,
    broker: Broker,
    config: IngressConfig,
) -> io::Result<IngressHandle> {
    serve(listener, broker, config, Port::Acme)
}

struct Pending<'a>(&'a AtomicUsize);

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve(
    listener: TcpListener,
    broker: Broker,
    config: IngressConfig,
    port: Port,
) -> io::Result<IngressHandle> {
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(IngressStats::default());
    let handle = IngressHandle {
        addr,
        stats: stats.clone(),
        stop: stop.clone(),
    };
    let limiter = Arc::new(AddressLimiter::new(
        config.per_address_per_minute,
        config.max_addresses,
    ));
    let pending = Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new()
        .name("ingress-accept".into())
        .spawn(move || {
            let mut failures: u32 = 0;
            for connection in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let connection = match connection {
                    Ok(connection) => {
                        failures = 0;
                        connection
                    }
                    Err(_) => {
                        failures = failures.saturating_add(1);
                        stats.accept_errors.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(accept_backoff(failures));
                        continue;
                    }
                };
                // The address is used here and then dropped; it is never logged.
                let allowed = connection
                    .peer_addr()
                    .is_ok_and(|peer| limiter.allow(peer.ip()));
                if !allowed {
                    stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                    drop(connection);
                    continue;
                }
                if pending.fetch_add(1, Ordering::SeqCst) >= config.max_pending {
                    pending.fetch_sub(1, Ordering::SeqCst);
                    stats.busy.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                stats.accepted.fetch_add(1, Ordering::Relaxed);
                let (conn_broker, conn_stats, conn_pending, limit) = (
                    broker.clone(),
                    stats.clone(),
                    pending.clone(),
                    config.read_limit,
                );
                let spawned = std::thread::Builder::new()
                    .name("ingress-conn".into())
                    .stack_size(128 * 1024)
                    .spawn(move || {
                        let guard = Pending(&conn_pending);
                        match port {
                            Port::Tls => {
                                handle_tls(&conn_broker, &conn_stats, connection, limit, guard)
                            }
                            Port::Acme => {
                                handle_acme(&conn_broker, &conn_stats, connection, limit, guard)
                            }
                        }
                    });
                if spawned.is_err() {
                    stats.busy.fetch_add(1, Ordering::Relaxed);
                }
            }
        })?;
    Ok(handle)
}

fn handle_tls(
    broker: &Broker,
    stats: &IngressStats,
    mut connection: TcpStream,
    limit: Duration,
    pending: Pending<'_>,
) {
    let record = match read_first_record(&mut connection, limit) {
        Ok(record) => record,
        Err(ReadError::Timeout) => {
            stats.timeouts.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Err(_) => {
            stats.malformed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let name = match server_name(&record) {
        Ok(name) => name,
        Err(HelloError::NoServerName | HelloError::BadServerName) => {
            stats.unrecognized.fetch_add(1, Ordering::Relaxed);
            return refuse_tls(connection);
        }
        Err(_) => {
            stats.malformed.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    match broker.open_ingress(&name, Kind::Public, record, 0) {
        Ok(ticket) => {
            drop(pending);
            stats.forwarded.fetch_add(1, Ordering::Relaxed);
            broker.run_raw(ticket, connection, true);
        }
        Err(IngressRefusal::Unrecognized) => {
            stats.unrecognized.fetch_add(1, Ordering::Relaxed);
            refuse_tls(connection);
        }
        Err(IngressRefusal::Limit) => {
            stats.limited.fetch_add(1, Ordering::Relaxed);
            let _ = connection.shutdown(Shutdown::Both);
        }
    }
}

fn refuse_tls(mut connection: TcpStream) {
    let _ = connection.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = connection.write_all(&ALERT_UNRECOGNIZED_NAME);
    let _ = connection.flush();
    let _ = connection.shutdown(Shutdown::Both);
}

fn handle_acme(
    broker: &Broker,
    stats: &IngressStats,
    mut connection: TcpStream,
    limit: Duration,
    pending: Pending<'_>,
) {
    let Some(head) = read_acme_head(&mut connection, limit) else {
        stats.malformed.fetch_add(1, Ordering::Relaxed);
        return not_found(connection);
    };
    let Some(host) = acme_host(&head) else {
        stats.malformed.fetch_add(1, Ordering::Relaxed);
        return not_found(connection);
    };
    match broker.open_ingress(&host, Kind::Acme, head, CLOSE) {
        Ok(ticket) => {
            drop(pending);
            stats.forwarded.fetch_add(1, Ordering::Relaxed);
            broker.run_raw(ticket, connection, false);
        }
        Err(IngressRefusal::Unrecognized) => {
            stats.unrecognized.fetch_add(1, Ordering::Relaxed);
            not_found(connection);
        }
        Err(IngressRefusal::Limit) => {
            stats.limited.fetch_add(1, Ordering::Relaxed);
            not_found(connection);
        }
    }
}

fn not_found(mut connection: TcpStream) {
    let _ = connection.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = connection.write_all(ACME_NOT_FOUND);
    let _ = connection.flush();
    let _ = connection.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic ClientHello record with the given extensions.
    fn hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x5a; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn sni(names: &[(u8, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (kind, name) in names {
            list.push(*kind);
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name);
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        let mut extension = vec![0x00, 0x00];
        extension.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extension.extend_from_slice(&data);
        extension
    }

    #[test]
    fn reads_the_server_name() {
        let record = hello(&sni(&[(0, b"K7M2Q4X3CA.node.example.test")]));
        assert_eq!(
            server_name(&record).unwrap(),
            "k7m2q4x3ca.node.example.test"
        );
    }

    #[test]
    fn every_truncation_fails_and_never_panics() {
        let mut extensions = vec![0x00, 0x0b, 0x00, 0x02, 0x01, 0x00];
        extensions.extend(sni(&[(0, b"a.example.test")]));
        let record = hello(&extensions);
        assert!(server_name(&record).is_ok());
        for cut in 0..record.len() {
            assert!(server_name(&record[..cut]).is_err(), "cut at {cut}");
        }
        let mut longer = record.clone();
        longer.push(0);
        assert_eq!(server_name(&longer), Err(HelloError::Malformed));
    }

    #[test]
    fn malformed_records() {
        let good = hello(&sni(&[(0, b"a.example.test")]));
        let mut not_handshake = good.clone();
        not_handshake[0] = 0x17;
        assert_eq!(server_name(&not_handshake), Err(HelloError::NotHandshake));
        let mut ssl3 = good.clone();
        ssl3[2] = 0x00;
        assert_eq!(server_name(&ssl3), Err(HelloError::BadVersion));
        let mut not_hello = good.clone();
        not_hello[5] = 0x02;
        assert_eq!(server_name(&not_hello), Err(HelloError::NotClientHello));
        // The handshake claims more than the record holds: it spans records.
        let mut spans = good.clone();
        spans[8] = spans[8].wrapping_add(1);
        assert_eq!(server_name(&spans), Err(HelloError::Fragmented));
        assert_eq!(
            record_length(&[0x16, 0x03, 0x01, 0x40, 0x01]),
            Err(HelloError::BadRecordLength)
        );
        assert_eq!(
            record_length(&[0x16, 0x03, 0x01, 0x00, 0x00]),
            Err(HelloError::BadRecordLength)
        );
        let two_names = hello(&sni(&[(0, b"a.example.test"), (0, b"b.example.test")]));
        assert_eq!(server_name(&two_names), Err(HelloError::BadServerName));
        let other_type = hello(&sni(&[(1, b"a.example.test")]));
        assert_eq!(server_name(&other_type), Err(HelloError::BadServerName));
        let not_host = hello(&sni(&[(0, b"a..example")]));
        assert_eq!(server_name(&not_host), Err(HelloError::BadServerName));
        let ip_like_with_slash = hello(&sni(&[(0, b"a/b")]));
        assert_eq!(
            server_name(&ip_like_with_slash),
            Err(HelloError::BadServerName)
        );
        let mut twice = sni(&[(0, b"a.example.test")]);
        twice.extend(sni(&[(0, b"a.example.test")]));
        assert_eq!(server_name(&hello(&twice)), Err(HelloError::Malformed));
        assert_eq!(server_name(&hello(&[])), Err(HelloError::NoServerName));
        assert_eq!(
            server_name(&hello(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00])),
            Err(HelloError::NoServerName)
        );
    }

    #[test]
    fn acme_heads() {
        let good = b"GET /.well-known/acme-challenge/Tok_en-1 HTTP/1.1\r\nHost: K7M2Q4X3CA.node.example.test:80\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(
            acme_host(good).as_deref(),
            Some("k7m2q4x3ca.node.example.test")
        );
        for bad in [
            &b"GET /.well-known/acme-challenge/ HTTP/1.1\r\nHost: a.test\r\n\r\n"[..],
            b"GET /.well-known/acme-challenge/a/b HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET /.well-known/acme-challenge/a HTTP/1.0\r\nHost: a.test\r\n\r\n",
            b"POST /.well-known/acme-challenge/a HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET /mcp HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET /.well-known/acme-challenge/a HTTP/1.1\r\n\r\n",
            b"GET /.well-known/acme-challenge/a HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n",
            b"GET /.well-known/acme-challenge/a HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\n\r\n",
            b"GET /.well-known/acme-challenge/a HTTP/1.1\nHost: a.test\r\n\r\n",
            b"GET /.well-known/acme-challenge/a HTTP/1.1\r\nHost: a.test\r\n",
        ] {
            assert_eq!(acme_host(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        let long = format!(
            "GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: a.test\r\n\r\n",
            "a".repeat(129)
        );
        assert_eq!(acme_host(long.as_bytes()), None);
    }

    #[test]
    fn a_failing_accept_backs_off() {
        let waits: Vec<u64> = (1..=9)
            .map(|failures| accept_backoff(failures).as_millis() as u64)
            .collect();
        assert_eq!(waits, [10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
        assert_eq!(accept_backoff(u32::MAX), Duration::from_secs(1));
    }

    #[test]
    fn address_limits() {
        let limiter = AddressLimiter::new(2, 2);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        let b_same_64: IpAddr = "2001:db8::ffff".parse().unwrap();
        let c: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(limiter.allow(a));
        assert!(limiter.allow(a));
        assert!(!limiter.allow(a));
        assert!(limiter.allow(b));
        assert!(limiter.allow(b_same_64));
        assert!(!limiter.allow(b));
        // The table is full for this minute: a new address is refused.
        assert!(!limiter.allow(c));
    }
}
