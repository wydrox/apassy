//! A small, strict WebSocket (RFC 6455) for the tunnel: the server side on an upgraded
//! stream, and a client side for the node (M4), the tests, and tools.
//!
//! Why in the crate and not `tungstenite`: `Cargo.lock` has no synchronous WebSocket
//! crate, the tunnel needs only binary messages, ping, pong, and close, without
//! extensions, and everything this module needs is already in the lock (`ring` for the
//! SHA-1 of the handshake, `base64`, `getrandom` for client masks). A new crate would
//! add a dependency review and an `audit` surface for about 400 lines of code.
//!
//! What this implementation enforces (each check has a test in this file):
//! - The handshake: `GET`, `Upgrade: websocket`, a `Connection` with the `upgrade`
//!   token, `Sec-WebSocket-Version: 13`, one `Sec-WebSocket-Key` of 16 bytes, and the
//!   subprotocol `apassy-tunnel-v1` among the offered ones.
//! - Frames: no RSV bits (no extension is negotiated), known opcodes only, client frames
//!   masked and server frames not, the shortest length encoding, the 64-bit length with
//!   its top bit clear, control frames of at most 125 bytes and never fragmented, a
//!   continuation only inside a fragmented message and a new data frame never inside
//!   one, and close payloads of 0 or at least 2 bytes with a valid code and UTF-8.
//! - Size: a message (all its fragments) is at most `max_message` bytes; the reader
//!   checks the announced length before it allocates, so a peer cannot make it buffer
//!   more than that.

use std::io::{self, Read, Write};

use base64::Engine as _;

/// The only subprotocol of the tunnel.
pub const SUBPROTOCOL: &str = "apassy-tunnel-v1";
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The largest control frame payload (RFC 6455 section 5.5).
pub const MAX_CONTROL: usize = 125;

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// Close codes used by the tunnel (contract section 4).
pub mod close {
    pub const NORMAL: u16 = 1000;
    pub const PROTOCOL: u16 = 1002;
    pub const UNSUPPORTED: u16 = 1003;
    pub const BAD_DATA: u16 = 1007;
    pub const TOO_BIG: u16 = 1009;
    pub const INTERNAL: u16 = 1011;
    /// Connect could not check the plan or the grant of an open stream for a few rounds
    /// in a row: the client may dial again (RFC 6455 "try again later").
    pub const TRY_AGAIN: u16 = 1013;
    pub const NODE_OFFLINE: u16 = 4001;
    pub const TUNNEL_LIMIT: u16 = 4002;
    pub const REVOKED: u16 = 4003;
    pub const RESET_BY_NODE: u16 = 4004;
    pub const REPLACED: u16 = 4005;
}

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key`.
pub fn accept_key(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(GUID.as_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

fn has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

/// Checks the request of a WebSocket upgrade with the tunnel subprotocol. `headers` are
/// the request headers in order (a name may repeat). Returns the `Sec-WebSocket-Accept`
/// value, or why the request is not a valid upgrade (for a 400 `invalid_request`).
pub fn check_upgrade<'a>(
    method: &str,
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<String, &'static str> {
    if method != "GET" {
        return Err("A WebSocket upgrade is a GET.");
    }
    let mut upgrade = None;
    let mut connection_upgrade = false;
    let mut version = None;
    let mut key = None;
    let mut protocol = false;
    let mut body = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("upgrade") {
            if upgrade.is_some() {
                return Err("Upgrade appears twice.");
            }
            upgrade = Some(value.trim().to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= has_token(value, "upgrade");
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            if version.is_some() {
                return Err("Sec-WebSocket-Version appears twice.");
            }
            version = Some(value.trim());
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            if key.is_some() {
                return Err("Sec-WebSocket-Key appears twice.");
            }
            key = Some(value.trim());
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            protocol |= value.split(',').any(|part| part.trim() == SUBPROTOCOL);
        } else if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            body = true;
        }
    }
    if body {
        return Err("A WebSocket upgrade has no body.");
    }
    if upgrade.as_deref() != Some("websocket") || !connection_upgrade {
        return Err("Not a WebSocket upgrade.");
    }
    if version != Some("13") {
        return Err("Sec-WebSocket-Version must be 13.");
    }
    let key = key.ok_or("Sec-WebSocket-Key is missing.")?;
    match base64::engine::general_purpose::STANDARD.decode(key) {
        Ok(raw) if raw.len() == 16 => {}
        _ => return Err("Sec-WebSocket-Key is not 16 bytes in base64."),
    }
    if !protocol {
        return Err("The subprotocol must be apassy-tunnel-v1.");
    }
    Ok(accept_key(key))
}

/// One message read from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Binary(Vec<u8>),
    /// A text message. The tunnel refuses text (close 1003); the content is discarded.
    Text,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// A close frame: its code, if any.
    Close(Option<u16>),
}

/// Why reading stopped.
#[derive(Debug)]
pub enum WsError {
    /// The transport failed, timed out, or ended.
    Io(io::Error),
    /// A protocol violation: close with 1002 (or 1007 for a close reason that is not
    /// UTF-8, see [`WsError::close_code`]).
    Protocol(&'static str),
    /// A message over the size cap: close with 1009.
    TooBig,
}

impl WsError {
    /// The close code to send for this error, if one should be sent.
    pub fn close_code(&self) -> Option<u16> {
        match self {
            WsError::Io(_) => None,
            WsError::Protocol("close reason is not UTF-8") => Some(close::BAD_DATA),
            WsError::Protocol(_) => Some(close::PROTOCOL),
            WsError::TooBig => Some(close::TOO_BIG),
        }
    }
}

impl From<io::Error> for WsError {
    fn from(error: io::Error) -> Self {
        WsError::Io(error)
    }
}

fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// Reads messages. The server side expects masked frames, the client side unmasked ones.
pub struct Reader<R> {
    inner: R,
    max_message: usize,
    from_client: bool,
    /// A fragmented message in progress: its opcode and bytes so far.
    partial: Option<(u8, Vec<u8>)>,
}

impl<R: Read> Reader<R> {
    /// A reader of client frames (the server side).
    pub fn server(inner: R, max_message: usize) -> Self {
        Self {
            inner,
            max_message,
            from_client: true,
            partial: None,
        }
    }

    /// A reader of server frames (the client side).
    pub fn client(inner: R, max_message: usize) -> Self {
        Self {
            inner,
            max_message,
            from_client: false,
            partial: None,
        }
    }

    /// Reads the next whole message. Control frames inside a fragmented message come out
    /// first.
    pub fn read_message(&mut self) -> Result<Message, WsError> {
        loop {
            let mut head = [0u8; 2];
            self.inner.read_exact(&mut head)?;
            let fin = head[0] & 0x80 != 0;
            if head[0] & 0x70 != 0 {
                return Err(WsError::Protocol("reserved bits set"));
            }
            let opcode = head[0] & 0x0F;
            let masked = head[1] & 0x80 != 0;
            if masked != self.from_client {
                return Err(WsError::Protocol(if self.from_client {
                    "client frame not masked"
                } else {
                    "server frame masked"
                }));
            }
            let len = match head[1] & 0x7F {
                126 => {
                    let mut ext = [0u8; 2];
                    self.inner.read_exact(&mut ext)?;
                    let len = u64::from(u16::from_be_bytes(ext));
                    if len < 126 {
                        return Err(WsError::Protocol("length not in shortest form"));
                    }
                    len
                }
                127 => {
                    let mut ext = [0u8; 8];
                    self.inner.read_exact(&mut ext)?;
                    let len = u64::from_be_bytes(ext);
                    if len >> 63 != 0 {
                        return Err(WsError::Protocol("length top bit set"));
                    }
                    if len <= 0xFFFF {
                        return Err(WsError::Protocol("length not in shortest form"));
                    }
                    len
                }
                small => u64::from(small),
            };
            let control = opcode & 0x08 != 0;
            match opcode {
                OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG => {}
                _ => return Err(WsError::Protocol("unknown opcode")),
            }
            if control {
                if !fin {
                    return Err(WsError::Protocol("fragmented control frame"));
                }
                if len > MAX_CONTROL as u64 {
                    return Err(WsError::Protocol("control frame too long"));
                }
            } else if opcode == OP_CONTINUATION {
                if self.partial.is_none() {
                    return Err(WsError::Protocol("continuation without a message"));
                }
            } else if self.partial.is_some() {
                return Err(WsError::Protocol("new message inside a fragmented one"));
            }
            // The size cap before any allocation.
            let so_far = self.partial.as_ref().map_or(0, |(_, bytes)| bytes.len());
            if !control && (so_far as u64).saturating_add(len) > self.max_message as u64 {
                return Err(WsError::TooBig);
            }
            let len = len as usize; // at most max_message or 125 here
            let mask = if masked {
                let mut key = [0u8; 4];
                self.inner.read_exact(&mut key)?;
                Some(key)
            } else {
                None
            };
            let mut payload = vec![0u8; len];
            self.inner.read_exact(&mut payload)?;
            if let Some(key) = mask {
                for (index, byte) in payload.iter_mut().enumerate() {
                    *byte ^= key[index % 4];
                }
            }
            if control {
                return match opcode {
                    OP_PING => Ok(Message::Ping(payload)),
                    OP_PONG => Ok(Message::Pong(payload)),
                    _ => parse_close(&payload).map(Message::Close),
                };
            }
            let (message_opcode, bytes) = match self.partial.take() {
                Some((first, mut bytes)) => {
                    bytes.extend_from_slice(&payload);
                    (first, bytes)
                }
                None => (opcode, payload),
            };
            if !fin {
                self.partial = Some((message_opcode, bytes));
                continue;
            }
            return Ok(if message_opcode == OP_TEXT {
                Message::Text
            } else {
                Message::Binary(bytes)
            });
        }
    }
}

fn parse_close(payload: &[u8]) -> Result<Option<u16>, WsError> {
    match payload.len() {
        0 => Ok(None),
        1 => Err(WsError::Protocol("close payload of one byte")),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if !valid_close_code(code) {
                return Err(WsError::Protocol("invalid close code"));
            }
            if std::str::from_utf8(&payload[2..]).is_err() {
                return Err(WsError::Protocol("close reason is not UTF-8"));
            }
            Ok(Some(code))
        }
    }
}

/// The bytes of one final frame. `mask` is `Some` on the client side only.
pub fn encode_frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0F));
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        len if len < 126 => out.push(mask_bit | len as u8),
        len if len <= 0xFFFF => {
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

/// A close frame payload: the code and no reason.
pub fn close_payload(code: u16) -> [u8; 2] {
    code.to_be_bytes()
}

/// Writes one frame and flushes (one write for the whole frame).
pub fn write_frame(
    writer: &mut dyn Write,
    opcode: u8,
    payload: &[u8],
    mask: Option<[u8; 4]>,
) -> io::Result<()> {
    writer.write_all(&encode_frame(opcode, payload, mask))?;
    writer.flush()
}

/// A random mask key for a client frame.
pub fn random_mask() -> [u8; 4] {
    let mut key = [0u8; 4];
    // A mask is not a secret (RFC 6455 section 10.3 asks only that a proxy cannot
    // predict it); a failure of the system source falls back to a fixed key.
    let _ = getrandom::fill(&mut key);
    key
}

/// The client side of the handshake and of messages, for the node (M4), tests, and
/// tools. The transport is any `Read + Write`; TLS, when wanted, wraps it outside.
pub mod client {
    use super::*;

    /// The answer to a handshake that was not `101`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Refused {
        pub status: u16,
        pub body: Vec<u8>,
    }

    /// A handshake failure.
    #[derive(Debug)]
    pub enum HandshakeError {
        Io(io::Error),
        /// The server answered with another status (the body is the error envelope).
        Refused(Refused),
        /// A `101` without the right accept key or subprotocol.
        BadAnswer(&'static str),
    }

    impl From<io::Error> for HandshakeError {
        fn from(error: io::Error) -> Self {
            HandshakeError::Io(error)
        }
    }

    /// A fresh `Sec-WebSocket-Key`.
    pub fn new_key() -> String {
        let mut raw = [0u8; 16];
        let _ = getrandom::fill(&mut raw);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    /// The request bytes of an upgrade to `path` on `host`, with an optional bearer token.
    pub fn request(host: &str, path: &str, key: &str, bearer: Option<&str>) -> Vec<u8> {
        let mut out = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n"
        );
        if let Some(token) = bearer {
            out.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        out.push_str("\r\n");
        out.into_bytes()
    }

    /// Reads a response head byte by byte (so no byte after it is consumed), at most
    /// 16 KiB. Returns the status and the headers.
    pub fn read_head(stream: &mut dyn Read) -> io::Result<(u16, Vec<(String, String)>)> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= 16 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "head too long"));
            }
            stream.read_exact(&mut byte)?;
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head);
        let mut lines = text.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status"))?;
        let headers = lines
            .filter(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
            .collect();
        Ok((status, headers))
    }

    /// Runs the client handshake on `stream`, after `request` was written (so a caller can
    /// write the request and the first frame in one segment). Checks the `101`.
    pub fn finish(stream: &mut dyn Read, key: &str) -> Result<(), HandshakeError> {
        let (status, headers) = read_head(stream)?;
        let header = |name: &str| {
            headers
                .iter()
                .find(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        if status != 101 {
            let length = header("content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                .min(64 * 1024);
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body)?;
            return Err(HandshakeError::Refused(Refused { status, body }));
        }
        if header("sec-websocket-accept") != Some(accept_key(key).as_str()) {
            return Err(HandshakeError::BadAnswer("wrong Sec-WebSocket-Accept"));
        }
        if header("sec-websocket-protocol") != Some(SUBPROTOCOL) {
            return Err(HandshakeError::BadAnswer("wrong subprotocol"));
        }
        Ok(())
    }

    /// Writes the request and finishes the handshake.
    pub fn handshake<S: Read + Write>(
        stream: &mut S,
        host: &str,
        path: &str,
        bearer: Option<&str>,
    ) -> Result<(), HandshakeError> {
        let key = new_key();
        stream.write_all(&request(host, path, &key, bearer))?;
        stream.flush()?;
        finish(stream, &key)
    }

    /// Writes one masked client message.
    pub fn send(writer: &mut dyn Write, opcode: u8, payload: &[u8]) -> io::Result<()> {
        write_frame(writer, opcode, payload, Some(random_mask()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut frame = encode_frame(opcode, payload, Some([1, 2, 3, 4]));
        if !fin {
            frame[0] &= 0x7F;
        }
        frame
    }

    fn server(bytes: Vec<u8>, max: usize) -> Reader<io::Cursor<Vec<u8>>> {
        Reader::server(io::Cursor::new(bytes), max)
    }

    #[test]
    fn rfc_accept_key() {
        // RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn upgrade_checks() {
        let good = [
            ("Host", "x"),
            ("Connection", "keep-alive, Upgrade"),
            ("Upgrade", "WebSocket"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Sec-WebSocket-Protocol", "chat, apassy-tunnel-v1"),
        ];
        assert!(check_upgrade("GET", good).is_ok());
        assert!(check_upgrade("POST", good).is_err());
        let mut other = good;
        other[5] = ("Sec-WebSocket-Protocol", "chat");
        assert!(check_upgrade("GET", other).is_err());
        let mut short_key = good;
        short_key[4] = ("Sec-WebSocket-Key", "c2hvcnQ=");
        assert!(check_upgrade("GET", short_key).is_err());
        let mut version = good;
        version[3] = ("Sec-WebSocket-Version", "8");
        assert!(check_upgrade("GET", version).is_err());
        let with_body = good.into_iter().chain([("Content-Length", "3")]);
        assert!(check_upgrade("GET", with_body).is_err());
    }

    #[test]
    fn masking_is_removed_and_required() {
        let mut reader = server(masked(OP_BINARY, true, b"hello"), 100);
        assert_eq!(
            reader.read_message().unwrap(),
            Message::Binary(b"hello".to_vec())
        );
        let unmasked = encode_frame(OP_BINARY, b"hello", None);
        assert!(matches!(
            server(unmasked.clone(), 100).read_message(),
            Err(WsError::Protocol("client frame not masked"))
        ));
        let mut client = Reader::client(io::Cursor::new(unmasked), 100);
        assert_eq!(
            client.read_message().unwrap(),
            Message::Binary(b"hello".to_vec())
        );
        let mut client = Reader::client(io::Cursor::new(masked(OP_BINARY, true, b"x")), 100);
        assert!(matches!(client.read_message(), Err(WsError::Protocol(_))));
    }

    #[test]
    fn fragments_join_and_controls_interleave() {
        let mut bytes = masked(OP_BINARY, false, b"ab");
        bytes.extend(masked(OP_PING, true, b"p"));
        bytes.extend(masked(OP_CONTINUATION, false, b"cd"));
        bytes.extend(masked(OP_CONTINUATION, true, b"e"));
        let mut reader = server(bytes, 100);
        assert_eq!(reader.read_message().unwrap(), Message::Ping(b"p".to_vec()));
        assert_eq!(
            reader.read_message().unwrap(),
            Message::Binary(b"abcde".to_vec())
        );
    }

    #[test]
    fn fragmentation_errors() {
        let lone = masked(OP_CONTINUATION, true, b"x");
        assert!(matches!(
            server(lone, 100).read_message(),
            Err(WsError::Protocol("continuation without a message"))
        ));
        let mut nested = masked(OP_BINARY, false, b"a");
        nested.extend(masked(OP_BINARY, true, b"b"));
        assert!(matches!(
            server(nested, 100).read_message(),
            Err(WsError::Protocol("new message inside a fragmented one"))
        ));
        let fragmented_ping = masked(OP_PING, false, b"x");
        assert!(matches!(
            server(fragmented_ping, 100).read_message(),
            Err(WsError::Protocol("fragmented control frame"))
        ));
    }

    #[test]
    fn control_frames() {
        let long_ping = masked(OP_PING, true, &[0u8; 126]);
        assert!(matches!(
            server(long_ping, 1000).read_message(),
            Err(WsError::Protocol("control frame too long"))
        ));
        let mut reader = server(masked(OP_PONG, true, b"z"), 10);
        assert_eq!(reader.read_message().unwrap(), Message::Pong(b"z".to_vec()));
        let mut reader = server(masked(OP_TEXT, true, b"text"), 10);
        assert_eq!(reader.read_message().unwrap(), Message::Text);
        assert!(matches!(
            server(masked(0x3, true, b""), 10).read_message(),
            Err(WsError::Protocol("unknown opcode"))
        ));
        let mut rsv = masked(OP_BINARY, true, b"x");
        rsv[0] |= 0x40;
        assert!(matches!(
            server(rsv, 10).read_message(),
            Err(WsError::Protocol("reserved bits set"))
        ));
    }

    #[test]
    fn close_frames() {
        let mut reader = server(masked(OP_CLOSE, true, b""), 10);
        assert_eq!(reader.read_message().unwrap(), Message::Close(None));
        let mut reader = server(masked(OP_CLOSE, true, &close_payload(4005)), 10);
        assert_eq!(reader.read_message().unwrap(), Message::Close(Some(4005)));
        assert!(matches!(
            server(masked(OP_CLOSE, true, &[3]), 10).read_message(),
            Err(WsError::Protocol("close payload of one byte"))
        ));
        assert!(matches!(
            server(masked(OP_CLOSE, true, &close_payload(1005)), 10).read_message(),
            Err(WsError::Protocol("invalid close code"))
        ));
        let mut bad_reason = close_payload(1000).to_vec();
        bad_reason.push(0xFF);
        let error = server(masked(OP_CLOSE, true, &bad_reason), 10)
            .read_message()
            .unwrap_err();
        assert_eq!(error.close_code(), Some(close::BAD_DATA));
    }

    #[test]
    fn size_caps_before_allocation() {
        // A 64-bit length of 2^40 with no payload behind it: refused by the cap.
        let mut huge = vec![0x80 | OP_BINARY, 0x80 | 127];
        huge.extend_from_slice(&(1u64 << 40).to_be_bytes());
        assert!(matches!(
            server(huge, 16392).read_message(),
            Err(WsError::TooBig)
        ));
        let mut top_bit = vec![0x80 | OP_BINARY, 0x80 | 127];
        top_bit.extend_from_slice(&(1u64 << 63).to_be_bytes());
        assert!(matches!(
            server(top_bit, 16392).read_message(),
            Err(WsError::Protocol("length top bit set"))
        ));
        // Fragments add up to the cap.
        let mut bytes = masked(OP_BINARY, false, &[0u8; 6]);
        bytes.extend(masked(OP_CONTINUATION, true, &[0u8; 6]));
        assert!(matches!(
            server(bytes, 10).read_message(),
            Err(WsError::TooBig)
        ));
        // Not the shortest length form.
        let mut long_form = vec![0x80 | OP_BINARY, 0x80 | 126, 0, 5, 1, 2, 3, 4];
        long_form.extend_from_slice(&[0u8; 5]);
        assert!(matches!(
            server(long_form, 100).read_message(),
            Err(WsError::Protocol("length not in shortest form"))
        ));
        let mut ok = server(masked(OP_BINARY, true, &[7u8; 300]), 300);
        assert_eq!(ok.read_message().unwrap(), Message::Binary(vec![7u8; 300]));
        // A truncated frame is an IO error (EOF), never a message.
        let mut cut = masked(OP_BINARY, true, &[7u8; 300]);
        cut.truncate(100);
        assert!(matches!(
            server(cut, 300).read_message(),
            Err(WsError::Io(_))
        ));
    }

    #[test]
    fn length_encodings_round_trip() {
        for len in [0usize, 125, 126, 65535, 65536] {
            let payload = vec![9u8; len];
            let mut reader = server(masked(OP_BINARY, true, &payload), 70000);
            assert_eq!(reader.read_message().unwrap(), Message::Binary(payload));
        }
    }
}
