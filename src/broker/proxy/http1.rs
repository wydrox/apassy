//! The HTTP/1.1 parts of the run proxy (ADR 0011): heads, body framing, and a
//! streaming search for placeholders and real values.
//!
//! The parser is strict. A request with both `Content-Length` and
//! `Transfer-Encoding`, a folded header, or an unknown transfer coding is refused, so
//! the proxy and the service cannot read different request borders.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

/// The largest request or response head.
pub(super) const MAX_HEAD_BYTES: usize = 64 * 1024;
const READ_CHUNK: usize = 16 * 1024;
const MAX_LINE_BYTES: usize = 4096;

/// A byte stream with a read buffer. The buffer can hold a real value from a
/// response, so it is erased on drop.
pub(super) struct Conn<S> {
    pub inner: S,
    buf: Zeroizing<Vec<u8>>,
    start: usize,
}

impl<S: Read> Conn<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Zeroizing::new(Vec::with_capacity(READ_CHUNK)),
            start: 0,
        }
    }

    /// The bytes read from the stream but not used yet.
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    fn consume(&mut self, count: usize) {
        self.start += count;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Read more bytes. Returns 0 at the end of the stream.
    fn fill(&mut self) -> io::Result<usize> {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let mut chunk = Zeroizing::new([0u8; READ_CHUNK]);
        let read = self.inner.read(&mut chunk[..])?;
        if self.buf.len() + read > self.buf.capacity() {
            // Grow into a new buffer, so no copy stays behind in freed memory.
            let mut grown = Zeroizing::new(Vec::with_capacity((self.buf.len() + read) * 2));
            grown.extend_from_slice(&self.buf);
            self.buf = grown;
        }
        self.buf.extend_from_slice(&chunk[..read]);
        Ok(read)
    }

    /// A head up to and with the empty line. `None` at the end of the stream before
    /// the first byte.
    pub fn read_head(&mut self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            if let Some(end) = find(self.buffered(), b"\r\n\r\n") {
                let head = Zeroizing::new(self.buffered()[..end + 4].to_vec());
                self.consume(end + 4);
                return Ok(Some(head));
            }
            if self.buffered().len() > MAX_HEAD_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
            }
            if self.fill()? == 0 {
                return if self.buffered().is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    /// One line with its CRLF, for chunk sizes and trailers.
    fn read_line(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(end) = find(self.buffered(), b"\r\n") {
                let line = Zeroizing::new(self.buffered()[..end + 2].to_vec());
                self.consume(end + 2);
                return Ok(line);
            }
            if self.buffered().len() > MAX_LINE_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.fill()? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// At most `max` bytes. Returns an empty slice at the end of the stream.
    fn read_some(&mut self, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        if self.buffered().is_empty() && self.fill()? == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let count = self.buffered().len().min(max);
        let bytes = Zeroizing::new(self.buffered()[..count].to_vec());
        self.consume(count);
        Ok(bytes)
    }

    /// Give back the stream and the unused bytes.
    pub fn into_parts(self) -> (S, Vec<u8>) {
        let rest = self.buffered().to_vec();
        (self.inner, rest)
    }
}

pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// A parsed request head. It comes from the agent process, so it has placeholders
/// and never a real value.
#[derive(Debug, Clone)]
pub(super) struct RequestHead {
    pub method: String,
    pub target: String,
    pub http10: bool,
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    pub fn wants_close(&self) -> bool {
        wants_close(&self.headers, self.http10)
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn has_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .flat_map(|(_, value)| value.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn wants_close(headers: &[(String, String)], http10: bool) -> bool {
    has_token(headers, "connection", "close")
        || (http10 && !has_token(headers, "connection", "keep-alive"))
}

fn token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// The first line and the headers of a head.
type Lines = (String, Vec<(String, String)>);

fn parse_lines(raw: &[u8]) -> Result<Lines, &'static str> {
    let text = std::str::from_utf8(raw).map_err(|_| "the head is not UTF-8")?;
    let text = text.strip_suffix("\r\n\r\n").ok_or("the head has no end")?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or("the head is empty")?.to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err("a folded header");
        }
        let (name, value) = line.split_once(':').ok_or("a header without a colon")?;
        if name.is_empty() || !name.bytes().all(token_char) {
            return Err("a header name is not valid");
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err("a header value is not valid");
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    Ok((first, headers))
}

pub(super) fn parse_request_head(raw: &[u8]) -> Result<RequestHead, &'static str> {
    let (first, headers) = parse_lines(raw)?;
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the request line is not valid");
    };
    if method.is_empty() || !method.bytes().all(token_char) {
        return Err("the method is not valid");
    }
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err("only HTTP/1.1 and HTTP/1.0"),
    };
    if target.is_empty() || target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err("the request target is not valid");
    }
    Ok(RequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        http10,
        headers,
    })
}

/// How a message body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyLen {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

fn content_length(headers: &[(String, String)]) -> Result<Option<u64>, &'static str> {
    let mut length = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err("Content-Length is not valid");
            }
            let parsed: u64 = part.parse().map_err(|_| "Content-Length is not valid")?;
            if length.is_some_and(|known| known != parsed) {
                return Err("two different Content-Length values");
            }
            length = Some(parsed);
        }
    }
    Ok(length)
}

fn transfer_codings(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty())
        .collect()
}

pub(super) fn request_body(head: &RequestHead) -> Result<BodyLen, &'static str> {
    let codings = transfer_codings(&head.headers);
    let length = content_length(&head.headers)?;
    if !codings.is_empty() {
        if length.is_some() {
            return Err("both Content-Length and Transfer-Encoding");
        }
        if codings != ["chunked"] {
            return Err("a transfer coding other than chunked");
        }
        return Ok(BodyLen::Chunked);
    }
    Ok(match length {
        Some(0) | None => BodyLen::None,
        Some(length) => BodyLen::Length(length),
    })
}

/// A response head after the proxy put placeholders back into it.
#[derive(Debug)]
pub(super) struct ResponseHead {
    pub status: u16,
    pub close: bool,
    pub body: BodyLen,
    pub upgrade: bool,
    /// The body is compressed, so the proxy cannot find a real value in it.
    pub encoded: bool,
}

pub(super) fn parse_response_head(raw: &[u8], method: &str) -> Result<ResponseHead, &'static str> {
    let text = String::from_utf8_lossy(raw);
    let (first, headers) = parse_lines(text.as_bytes())?;
    let mut parts = first.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err("the status line is not valid"),
    };
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .filter(|code| (100..600).contains(code))
        .ok_or("the status is not valid")?;
    let codings = transfer_codings(&headers);
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
        match content_length(&headers)? {
            Some(0) => BodyLen::None,
            Some(length) => BodyLen::Length(length),
            None => BodyLen::UntilClose,
        }
    };
    let encoded = header(&headers, "content-encoding")
        .is_some_and(|coding| !coding.trim().eq_ignore_ascii_case("identity"));
    Ok(ResponseHead {
        status,
        close: wants_close(&headers, http10) || body == BodyLen::UntilClose,
        body,
        upgrade: status == 101,
        encoded,
    })
}

/// Finds placeholders in a request body that comes in pieces.
pub(super) struct Scanner<'a> {
    needles: &'a [&'a [u8]],
    carry: Vec<u8>,
    keep: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(needles: &'a [&'a [u8]]) -> Self {
        let keep = needles
            .iter()
            .map(|needle| needle.len())
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Self {
            needles,
            carry: Vec::new(),
            keep,
        }
    }

    /// The index of a needle that ends in `data`, with the end of the earlier data.
    pub fn feed(&mut self, data: &[u8]) -> Option<usize> {
        let mut window = std::mem::take(&mut self.carry);
        window.extend_from_slice(data);
        let found = self
            .needles
            .iter()
            .position(|needle| find(&window, needle).is_some());
        let start = window.len().saturating_sub(self.keep);
        self.carry = window[start..].to_vec();
        found
    }
}

/// Swaps real values for placeholders in a response that comes in pieces. Each pair
/// has the same length, so the body keeps its length. It holds back only an end of a
/// piece that can be the start of a value, so a stream (server-sent events) flows.
pub(super) struct Replacer<'a> {
    pairs: &'a [(&'a [u8], &'a [u8])],
    pending: Zeroizing<Vec<u8>>,
    pub replaced: bool,
}

impl<'a> Replacer<'a> {
    pub fn new(pairs: &'a [(&'a [u8], &'a [u8])]) -> Self {
        debug_assert!(pairs.iter().all(|(from, to)| from.len() == to.len()));
        Self {
            pairs,
            pending: Zeroizing::new(Vec::new()),
            replaced: false,
        }
    }

    /// Replace in place. Returns true when a value was found.
    pub fn replace_all(pairs: &[(&[u8], &[u8])], data: &mut [u8]) -> bool {
        let mut found = false;
        for (from, to) in pairs {
            if from.is_empty() {
                continue;
            }
            let mut offset = 0;
            while let Some(position) = find(&data[offset..], from) {
                let at = offset + position;
                data[at..at + to.len()].copy_from_slice(to);
                offset = at + to.len();
                found = true;
            }
        }
        found
    }

    /// The length of the longest end of `data` that is the start of a value.
    fn open_end(&self, data: &[u8]) -> usize {
        self.pairs
            .iter()
            .map(|(from, _)| {
                (1..from.len().min(data.len() + 1))
                    .rev()
                    .find(|&k| data[data.len() - k..] == from[..k])
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0)
    }

    /// Add `data`. Returns the bytes that are final: no value can start in them.
    pub fn feed(&mut self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut window = Zeroizing::new(Vec::with_capacity(self.pending.len() + data.len()));
        window.extend_from_slice(&self.pending);
        window.extend_from_slice(data);
        self.replaced |= Self::replace_all(self.pairs, &mut window);
        let split = window.len() - self.open_end(&window);
        self.pending = Zeroizing::new(window[split..].to_vec());
        window.truncate(split);
        window
    }

    /// The rest, at the end of the body.
    pub fn finish(&mut self) -> Zeroizing<Vec<u8>> {
        let mut rest = std::mem::replace(&mut self.pending, Zeroizing::new(Vec::new()));
        self.replaced |= Self::replace_all(self.pairs, &mut rest);
        rest
    }
}

/// Why a request body stopped.
#[derive(Debug)]
pub(super) enum BodyStop {
    Io,
    Framing,
    /// A placeholder of the secret with this index is in the body.
    Placeholder(usize),
}

impl From<io::Error> for BodyStop {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

fn chunk_size(line: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(line).ok()?.strip_suffix("\r\n")?;
    let size = text.split(';').next()?.trim();
    if size.is_empty() || size.len() > 15 {
        return None;
    }
    u64::from_str_radix(size, 16).ok()
}

/// Copy a request body from the agent process to the service. A piece with a
/// placeholder is not sent: the copy stops before it.
pub(super) fn copy_request_body<C: Read, U: Write>(
    from: &mut Conn<C>,
    to: &mut U,
    body: BodyLen,
    scanner: &mut Scanner<'_>,
) -> Result<(), BodyStop> {
    let send = |to: &mut U, data: &[u8], scanner: &mut Scanner<'_>| -> Result<(), BodyStop> {
        if let Some(index) = scanner.feed(data) {
            return Err(BodyStop::Placeholder(index));
        }
        to.write_all(data)?;
        Ok(())
    };
    match body {
        BodyLen::None => Ok(()),
        BodyLen::Length(mut left) => {
            while left > 0 {
                let piece = from.read_some(usize::try_from(left).unwrap_or(usize::MAX))?;
                if piece.is_empty() {
                    return Err(BodyStop::Io);
                }
                send(to, &piece, scanner)?;
                left -= piece.len() as u64;
            }
            Ok(())
        }
        BodyLen::Chunked => loop {
            let line = from.read_line()?;
            let size = chunk_size(&line).ok_or(BodyStop::Framing)?;
            to.write_all(&line)?;
            if size == 0 {
                // Trailers, then the empty line.
                loop {
                    let trailer = from.read_line()?;
                    if let Some(index) = scanner.feed(&trailer) {
                        return Err(BodyStop::Placeholder(index));
                    }
                    to.write_all(&trailer)?;
                    if trailer.as_slice() == b"\r\n" {
                        return Ok(());
                    }
                }
            }
            let mut left = size;
            while left > 0 {
                let piece = from.read_some(usize::try_from(left).unwrap_or(usize::MAX))?;
                if piece.is_empty() {
                    return Err(BodyStop::Io);
                }
                send(to, &piece, scanner)?;
                left -= piece.len() as u64;
            }
            let end = from.read_line()?;
            if end.as_slice() != b"\r\n" {
                return Err(BodyStop::Framing);
            }
            to.write_all(&end)?;
        },
        // A request body cannot end with the connection.
        BodyLen::UntilClose => Err(BodyStop::Framing),
    }
}

/// Copy a response body from the service to the agent process, with placeholders
/// in place of real values. A chunked body is sent again in new chunks.
pub(super) fn copy_response_body<U: Read, C: Write>(
    from: &mut Conn<U>,
    to: &mut C,
    body: BodyLen,
    replacer: &mut Replacer<'_>,
) -> io::Result<()> {
    match body {
        BodyLen::None => Ok(()),
        BodyLen::Length(mut left) => {
            while left > 0 {
                let piece = from.read_some(usize::try_from(left).unwrap_or(usize::MAX))?;
                if piece.is_empty() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                left -= piece.len() as u64;
                to.write_all(&replacer.feed(&piece))?;
            }
            to.write_all(&replacer.finish())
        }
        BodyLen::UntilClose => {
            loop {
                let piece = from.read_some(READ_CHUNK)?;
                if piece.is_empty() {
                    break;
                }
                to.write_all(&replacer.feed(&piece))?;
                to.flush()?;
            }
            to.write_all(&replacer.finish())
        }
        BodyLen::Chunked => {
            let write_chunk = |to: &mut C, data: &[u8]| -> io::Result<()> {
                if data.is_empty() {
                    return Ok(());
                }
                write!(to, "{:x}\r\n", data.len())?;
                to.write_all(data)?;
                to.write_all(b"\r\n")?;
                to.flush()
            };
            loop {
                let line = from.read_line()?;
                let size = chunk_size(&line)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size"))?;
                if size == 0 {
                    write_chunk(to, &replacer.finish())?;
                    to.write_all(b"0\r\n")?;
                    loop {
                        let mut trailer = from.read_line()?;
                        replacer.replaced |= Replacer::replace_all(replacer.pairs, &mut trailer);
                        to.write_all(&trailer)?;
                        if trailer.as_slice() == b"\r\n" {
                            return Ok(());
                        }
                    }
                }
                let mut left = size;
                while left > 0 {
                    let piece = from.read_some(usize::try_from(left).unwrap_or(usize::MAX))?;
                    if piece.is_empty() {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    left -= piece.len() as u64;
                    write_chunk(to, &replacer.feed(&piece))?;
                }
                if from.read_line()?.as_slice() != b"\r\n" {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk end"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_heads_are_strict() {
        let head = parse_request_head(
            b"POST /x?y=1 HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n\r\n",
        )
        .expect("head");
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/x?y=1");
        assert_eq!(request_body(&head), Ok(BodyLen::Length(5)));
        for bad in [
            &b"GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n"[..],
            b"GET / HTTP/2\r\n\r\n",
            b"GET  / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n",
        ] {
            assert!(parse_request_head(bad).is_err(), "{bad:?}");
        }
        let both = parse_request_head(
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .expect("head");
        assert!(request_body(&both).is_err());
        let gzip =
            parse_request_head(b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
                .expect("head");
        assert!(request_body(&gzip).is_err());
        let two = parse_request_head(
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        )
        .expect("head");
        assert!(request_body(&two).is_err());
    }

    #[test]
    fn response_framing() {
        let head = |raw: &str, method: &str| {
            parse_response_head(raw.as_bytes(), method).expect("response head")
        };
        assert_eq!(
            head("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", "GET").body,
            BodyLen::Length(3)
        );
        assert_eq!(
            head("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", "HEAD").body,
            BodyLen::None
        );
        assert_eq!(
            head(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                "GET"
            )
            .body,
            BodyLen::Chunked
        );
        let until = head("HTTP/1.1 200 OK\r\n\r\n", "GET");
        assert_eq!(until.body, BodyLen::UntilClose);
        assert!(until.close);
        assert_eq!(
            head("HTTP/1.1 204 No Content\r\n\r\n", "GET").body,
            BodyLen::None
        );
    }

    #[test]
    fn scanner_finds_a_needle_split_over_pieces() {
        let needles: [&[u8]; 1] = [b"PLACEHOLDER"];
        let mut scanner = Scanner::new(&needles);
        assert_eq!(scanner.feed(b"abc PLACE"), None);
        assert_eq!(scanner.feed(b"HOLD"), None);
        assert_eq!(scanner.feed(b"ER tail"), Some(0));
    }

    #[test]
    fn replacer_keeps_length_across_pieces() {
        let pairs: [(&[u8], &[u8]); 1] = [(b"REALVALUE1", b"placehold1")];
        let mut replacer = Replacer::new(&pairs);
        let mut out = Vec::new();
        for piece in [&b"x REALV"[..], b"ALUE1 y REAL", b"VALUE1", b" z"] {
            out.extend_from_slice(&replacer.feed(piece));
        }
        out.extend_from_slice(&replacer.finish());
        assert_eq!(out, b"x placehold1 y placehold1 z");
        assert!(replacer.replaced);
    }

    #[test]
    fn replacer_holds_back_only_a_possible_start_of_a_value() {
        let pairs: [(&[u8], &[u8]); 1] = [(b"REALVALUE1", b"placehold1")];
        let mut replacer = Replacer::new(&pairs);
        // An event of a stream goes out at once.
        assert_eq!(replacer.feed(b"data: {}\n\n").as_slice(), b"data: {}\n\n");
        // "REA" can be the start of the value, so it waits.
        assert_eq!(replacer.feed(b"data: REA").as_slice(), b"data: ");
        assert_eq!(replacer.feed(b"DY\n\n").as_slice(), b"READY\n\n");
        assert!(!replacer.replaced);
    }

    #[test]
    fn chunked_bodies_are_copied_and_checked() {
        let body = b"4\r\nabcd\r\n3;ext=1\r\nefg\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        let mut from = Conn::new(&body[..]);
        let mut out = Vec::new();
        let needles: [&[u8]; 1] = [b"zzzz"];
        copy_request_body(
            &mut from,
            &mut out,
            BodyLen::Chunked,
            &mut Scanner::new(&needles),
        )
        .expect("copy");
        assert_eq!(out, &body[..body.len() - 4]);
        assert_eq!(from.buffered(), b"NEXT");

        let needles: [&[u8]; 1] = [b"cdef"];
        let mut from = Conn::new(&body[..]);
        let mut out = Vec::new();
        let stopped = copy_request_body(
            &mut from,
            &mut out,
            BodyLen::Chunked,
            &mut Scanner::new(&needles),
        );
        assert!(matches!(stopped, Err(BodyStop::Placeholder(0))));
        assert!(
            !out.windows(3).any(|w| w == b"efg"),
            "the piece is not sent"
        );

        let response = b"5\r\nhe-RE\r\n6\r\nAL-lo!\r\n0\r\n\r\n";
        let pairs: [(&[u8], &[u8]); 1] = [(b"REAL", b"fake")];
        let mut from = Conn::new(&response[..]);
        let mut out = Vec::new();
        copy_response_body(
            &mut from,
            &mut out,
            BodyLen::Chunked,
            &mut Replacer::new(&pairs),
        )
        .expect("copy response");
        let mut plain = Vec::new();
        let mut rest = &out[..];
        loop {
            let line_end = find(rest, b"\r\n").expect("size line");
            let size =
                usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16).unwrap();
            rest = &rest[line_end + 2..];
            if size == 0 {
                break;
            }
            plain.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
        assert_eq!(plain, b"he-fake-lo!");
    }
}
