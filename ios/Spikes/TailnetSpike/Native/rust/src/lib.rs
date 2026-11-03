//! Spike only (plan s8 unit T0, ADR 0040). Not a part of the app.
//!
//! The vault core will run its pinned rustls client over a stream that the embedded tailnet node
//! dialed (ADR 0040 section 1). This crate checks that path with the same rustls and ring
//! versions: it takes the file descriptor from Swift, sets the deadlines on it, runs TLS with a
//! certificate pin, sends one HTTP request, and reports what it saw as JSON. It also holds the
//! Rust crash tests of the spike. The C declarations are in `Native/include/tailnet_spike_rs.h`.

use std::ffi::{CStr, c_char};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError,
    SignatureScheme, StreamOwned,
};

/// The most bytes of an answer that the probe reads.
const READ_LIMIT: usize = 256 * 1024;

/// Probes a stream from `tailscale_dial`. See `tailnet_spike_rs.h`.
///
/// # Safety
///
/// `fd` is an open descriptor that the caller gives up. `server_name`, `pin` and `path` are null
/// or NUL-terminated strings. `out` is null or has room for `out_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spike_rs_probe(
    fd: i32,
    use_tls: bool,
    server_name: *const c_char,
    pin: *const c_char,
    path: *const c_char,
    timeout_ms: u32,
    out: *mut c_char,
    out_len: usize,
) -> i32 {
    // SAFETY: the caller's contract above.
    let (server_name, pin, path) = unsafe { (text(server_name), text(pin), text(path)) };
    let path = if path.is_empty() { "/".to_owned() } else { path };
    let timeout = Duration::from_millis(u64::from(timeout_ms.max(1)));
    let report = probe(fd, use_tls, &server_name, &pin, &path, timeout);
    // SAFETY: the caller's contract above.
    unsafe { write_out(&report.to_json(), out, out_len) };
    if report.ok { 0 } else { -1 }
}

/// Ends the process from Rust. See `tailnet_spike_rs.h`.
#[unsafe(no_mangle)]
pub extern "C" fn spike_rs_crash(kind: i32) {
    match kind {
        0 => panic!("apassy spike: a Rust panic at the C boundary"),
        1 => {
            // Deliberately invalid: the SIGSEGV test. The first 4 GiB of an iOS process are
            // unmapped (__PAGEZERO), and a non-null aligned address passes the debug checks.
            let address = std::ptr::without_provenance_mut::<u32>(0x40);
            // SAFETY: none; this write is meant to fault.
            unsafe { std::ptr::write_volatile(address, 1) };
        }
        _ => std::process::abort(),
    }
}

#[derive(Default)]
struct Report {
    ok: bool,
    fd_kind: String,
    tls: bool,
    tls_version: String,
    cipher: String,
    pin_seen: String,
    pin_check: String,
    handshake_ms: Option<f64>,
    first_byte_ms: Option<f64>,
    total_ms: Option<f64>,
    status_line: String,
    bytes_read: usize,
    error: String,
}

impl Report {
    fn to_json(&self) -> String {
        let mut s = String::from("{");
        let _ = write!(s, "\"ok\":{}", self.ok);
        push_str(&mut s, "fd_kind", &self.fd_kind);
        let _ = write!(s, ",\"tls\":{}", self.tls);
        push_str(&mut s, "tls_version", &self.tls_version);
        push_str(&mut s, "cipher", &self.cipher);
        push_str(&mut s, "pin_seen", &self.pin_seen);
        push_str(&mut s, "pin_check", &self.pin_check);
        push_num(&mut s, "handshake_ms", self.handshake_ms);
        push_num(&mut s, "first_byte_ms", self.first_byte_ms);
        push_num(&mut s, "total_ms", self.total_ms);
        push_str(&mut s, "status_line", &self.status_line);
        let _ = write!(s, ",\"bytes_read\":{}", self.bytes_read);
        push_str(&mut s, "error", &self.error);
        s.push('}');
        s
    }
}

fn probe(fd: i32, use_tls: bool, server_name: &str, pin: &str, path: &str, timeout: Duration) -> Report {
    let start = Instant::now();
    let mut report = Report { tls: use_tls, ..Report::default() };
    if fd < 0 {
        report.error = "no file descriptor".into();
        return report;
    }
    // SAFETY: Swift hands over a descriptor that it owns and does not use again.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    match file.metadata() {
        Ok(meta) => {
            let kind = meta.file_type();
            report.fd_kind = if kind.is_socket() {
                "socket"
            } else if kind.is_fifo() {
                "fifo"
            } else {
                "other"
            }
            .into();
        }
        Err(e) => {
            report.error = format!("fstat: {e}");
            return report;
        }
    }
    // The vault core would hold the descriptor the same way: a stream with its own deadlines.
    let stream = UnixStream::from(OwnedFd::from(file));
    if let Err(e) = stream.set_read_timeout(Some(timeout)).and_then(|()| stream.set_write_timeout(Some(timeout))) {
        report.error = format!("deadline: {e}");
        return report;
    }
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {server_name}\r\nUser-Agent: apassy-tailnet-spike\r\nConnection: close\r\n\r\n"
    );
    let result = if use_tls {
        tls_exchange(stream, server_name, pin, request.as_bytes(), start, &mut report)
    } else {
        plain_exchange(stream, request.as_bytes(), start, &mut report)
    };
    match result {
        Ok(()) => report.ok = true,
        Err(e) => report.error = e,
    }
    report.total_ms = Some(ms(start.elapsed()));
    report
}

fn plain_exchange(mut stream: UnixStream, request: &[u8], start: Instant, report: &mut Report) -> Result<(), String> {
    stream.write_all(request).map_err(|e| format!("write: {e}"))?;
    read_answer(&mut stream, start, report)
}

fn tls_exchange(
    stream: UnixStream,
    server_name: &str,
    pin: &str,
    request: &[u8],
    start: Instant,
    report: &mut Report,
) -> Result<(), String> {
    let expected = if pin.trim().is_empty() { None } else { Some(parse_pin(pin)?) };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinVerifier { expected, seen: Mutex::new(None), provider: provider.clone() });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(server_name.to_owned()).map_err(|e| format!("server name: {e}"))?;
    let connection = ClientConnection::new(Arc::new(config), name).map_err(|e| format!("tls: {e}"))?;
    let mut tls = StreamOwned::new(connection, stream);

    let mut handshake_error = None;
    while tls.conn.is_handshaking() {
        if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
            handshake_error = Some(e);
            break;
        }
    }
    let seen = *verifier.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(seen) = seen {
        report.pin_seen = b64u(&seen);
    }
    report.pin_check = match (expected, seen) {
        (None, _) => "not_checked",
        (Some(want), Some(got)) if want == got => "match",
        (Some(_), Some(_)) => "mismatch",
        (Some(_), None) => "no_certificate",
    }
    .into();
    if let Some(e) = handshake_error {
        return Err(format!("tls handshake: {e}"));
    }
    report.handshake_ms = Some(ms(start.elapsed()));
    report.tls_version = tls.conn.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default();
    report.cipher = tls.conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())).unwrap_or_default();
    tls.write_all(request).map_err(|e| format!("write: {e}"))?;
    tls.flush().map_err(|e| format!("write: {e}"))?;
    read_answer(&mut tls, start, report)
}

fn read_answer<R: Read>(reader: &mut R, start: Instant, report: &mut Report) -> Result<(), String> {
    let mut buf = [0u8; 4096];
    let mut head: Vec<u8> = Vec::new();
    let mut end_error = None;
    while report.bytes_read < READ_LIMIT {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if report.first_byte_ms.is_none() {
                    report.first_byte_ms = Some(ms(start.elapsed()));
                }
                report.bytes_read += n;
                let room = 512usize.saturating_sub(head.len());
                head.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                end_error = Some(e);
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&head);
    report.status_line = text.lines().next().unwrap_or("").chars().take(200).collect();
    match (report.first_byte_ms, end_error) {
        // A server that closes without a TLS close_notify ends with an error after its answer.
        (Some(_), _) => Ok(()),
        (None, Some(e)) => Err(format!("read: {e}")),
        (None, None) => Err("the server closed the stream without an answer".into()),
    }
}

/// Accepts only the pinned leaf certificate (or any, without a pin), and records what it saw.
#[derive(Debug)]
struct PinVerifier {
    expected: Option<[u8; 32]>,
    seen: Mutex<Option<[u8; 32]>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        let mut got = [0u8; 32];
        got.copy_from_slice(digest.as_ref());
        *self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(got);
        match self.expected {
            Some(want) if want != got => {
                Err(TlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
            }
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A pin: base64url of the SHA-256 of the certificate DER (companion-v1), or 64 hex digits, with
/// or without colons, as `openssl x509 -fingerprint -sha256` prints them.
fn parse_pin(text: &str) -> Result<[u8; 32], String> {
    let text = text.trim();
    let text = match text.find("Fingerprint=") {
        Some(i) => &text[i + "Fingerprint=".len()..],
        None => text,
    };
    let hex: String = text.chars().filter(|c| *c != ':').collect();
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(|_| "a hex pin is ASCII".to_string())?;
            out[i] = u8::from_str_radix(pair, 16).map_err(|e| format!("hex pin: {e}"))?;
        }
        return Ok(out);
    }
    let bytes = b64u_decode(text.trim_end_matches('='))?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| format!("a pin is 32 bytes, this one is {len}"))
}

const B64U: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64u(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for i in 0..=chunk.len() {
            let index = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(B64U[index]));
        }
    }
    out
}

fn b64u_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return Err(format!("not base64url: {:?}", char::from(c))),
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    Ok(out)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn push_str(s: &mut String, key: &str, value: &str) {
    let _ = write!(s, ",\"{key}\":\"");
    for c in value.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(s, "\\u{:04x}", u32::from(c));
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

fn push_num(s: &mut String, key: &str, value: Option<f64>) {
    match value {
        Some(v) => {
            let _ = write!(s, ",\"{key}\":{v:.1}");
        }
        None => {
            let _ = write!(s, ",\"{key}\":null");
        }
    }
}

/// # Safety
///
/// `p` is null or a NUL-terminated string.
unsafe fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// # Safety
///
/// `out` is null or has room for `out_len` bytes.
unsafe fn write_out(s: &str, out: *mut c_char, out_len: usize) {
    if out.is_null() || out_len == 0 {
        return;
    }
    let bytes = s.as_bytes();
    let n = bytes.len().min(out_len - 1);
    // SAFETY: the caller's contract; n < out_len.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), n);
        *out.add(n) = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_companion_vector_round_trips() {
        // companion-v1 section 9: the pin of the DER bytes 30 00.
        let digest = ring::digest::digest(&ring::digest::SHA256, &[0x30, 0x00]);
        assert_eq!(b64u(digest.as_ref()), "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU");
        let pin = parse_pin("5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU").unwrap();
        assert_eq!(&pin[..], digest.as_ref());
    }

    #[test]
    fn a_hex_fingerprint_is_a_pin() {
        let digest = ring::digest::digest(&ring::digest::SHA256, &[0x30, 0x00]);
        let hex: Vec<String> = digest.as_ref().iter().map(|b| format!("{b:02X}")).collect();
        let pin = parse_pin(&format!("sha256 Fingerprint={}", hex.join(":"))).unwrap();
        assert_eq!(&pin[..], digest.as_ref());
    }

    #[test]
    fn a_short_pin_is_refused() {
        assert!(parse_pin("AAAA").is_err());
    }
}
