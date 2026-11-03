//! Track proxy: byte-stream helpers.
//!
//! A copy, with attribution, of the `Conn`, `Scanner`, and `Replacer` of
//! `src/broker/proxy/http1.rs` of wydrox/apassy at rev 77f6628 (Apache-2.0), changed
//! for the relay: the `Replacer` owns its pairs, and `BodyReader` turns the body of an
//! upstream response into a `Read` that replaces each value with its placeholder.
//! The bytes stay the same length, so a `Content-Length` stays true.
//!
//! - `Scanner` finds a placeholder in a request body that comes in pieces.
//! - `Replacer` replaces values with placeholders in a response stream, across the
//!   borders of the pieces. A `Pattern` (relay only) adds the JSON and HTML escapes
//!   of a value.
//! - `BodyReader` reads a `Content-Length`, chunked, or read-to-close body.

use std::io::{self, Read};

use zeroize::Zeroizing;

/// The largest response head.
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
    #[cfg(test)]
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    fn buffered_len(&self) -> usize {
        self.buf.len() - self.start
    }

    fn consume(&mut self, count: usize) {
        self.start += count;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Reads more bytes. Returns 0 at the end of the stream.
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

    /// A head up to and with the empty line.
    pub fn read_head(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(end) = find(&self.buf[self.start..], b"\r\n\r\n") {
                let head = Zeroizing::new(self.buf[self.start..self.start + end + 4].to_vec());
                self.consume(end + 4);
                return Ok(head);
            }
            if self.buffered_len() > MAX_HEAD_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
            }
            if self.fill()? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// One line with its CRLF, for chunk sizes and trailers.
    fn read_line(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(end) = find(&self.buf[self.start..], b"\r\n") {
                let line = Zeroizing::new(self.buf[self.start..self.start + end + 2].to_vec());
                self.consume(end + 2);
                return Ok(line);
            }
            if self.buffered_len() > MAX_LINE_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.fill()? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// At most `max` bytes. Returns an empty vector at the end of the stream.
    fn read_some(&mut self, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        if self.buffered_len() == 0 && self.fill()? == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let count = self.buffered_len().min(max);
        let bytes = Zeroizing::new(self.buf[self.start..self.start + count].to_vec());
        self.consume(count);
        Ok(bytes)
    }
}

/// The position of `needle` in `haystack`.
pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// How a message body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyLen {
    None,
    Length(u64),
    Chunked,
    UntilClose,
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

/// One real value and the placeholder of the same length that replaces it.
pub(super) struct Pair {
    pub from: Zeroizing<Vec<u8>>,
    pub to: Vec<u8>,
}

/// Replaces real values with placeholders in a response that comes in pieces. Each
/// pair has the same length, so the body keeps its length. It holds back only an end
/// of a piece that can be the start of a value, so a stream (server-sent events) flows.
pub(super) struct Replacer {
    pairs: Vec<Pair>,
    patterns: Vec<Pattern>,
    pending: Zeroizing<Vec<u8>>,
}

/// A byte of a value that a JSON or HTML encoder can escape: every printable byte
/// that is not a letter, a digit, or one of `-_.`.
fn escapable(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !b"-_.".contains(&byte)
}

/// One form of one byte of a value, and the bytes of the same length that replace it.
struct Form {
    from: Zeroizing<Vec<u8>>,
    to: Vec<u8>,
}

/// The escaped forms of one value (`\/`, `\u002f`, `&amp;`, `&lt;`, `&#39;`, `&#x2F;`
/// ...), in any mix: an upstream host that echoes the value in JSON or HTML escapes
/// gives back no value. Each byte of the value is one place with its forms. The
/// matching form of the placeholder byte replaces each form: the same escape of the
/// placeholder byte, or, where no escape of that byte has the length (`\/`, `&lt;`),
/// the placeholder byte repeated. So the bytes keep their length and show no part of
/// the value.
pub(super) struct Pattern {
    places: Vec<Vec<Form>>,
    /// The longest form of the whole value.
    max_len: usize,
}

/// The result of a match at one offset.
enum Step {
    /// A whole form of the value: its length and the bytes that replace it.
    Full(usize, Vec<u8>),
    /// The data ends inside a possible form of the value.
    Partial,
    Miss,
}

/// `&#` + decimal + `;` of `byte` in exactly `len` bytes (leading zeros), or the byte
/// repeated when the decimal does not fit.
fn html_decimal(byte: u8, len: usize) -> Vec<u8> {
    let digits = byte.to_string();
    if 3 + digits.len() > len {
        return vec![byte; len];
    }
    format!("&#{}{digits};", "0".repeat(len - 3 - digits.len())).into_bytes()
}

fn json_u(byte: u8, upper: bool) -> Vec<u8> {
    if upper {
        format!("\\u00{byte:02X}").into_bytes()
    } else {
        format!("\\u00{byte:02x}").into_bytes()
    }
}

fn html_hex(byte: u8, upper: bool) -> Vec<u8> {
    if upper {
        format!("&#x{byte:02X};").into_bytes()
    } else {
        format!("&#x{byte:02x};").into_bytes()
    }
}

impl Pattern {
    /// The escaped forms of `value` with those of `placeholder`. `None` when the
    /// lengths differ or no byte of the value has an escape: the raw pair covers it.
    pub fn escaped(value: &[u8], placeholder: &[u8]) -> Option<Self> {
        if value.is_empty()
            || value.len() != placeholder.len()
            || !value.iter().copied().any(escapable)
        {
            return None;
        }
        let places: Vec<Vec<Form>> = value
            .iter()
            .zip(placeholder)
            .map(|(&byte, &shown)| Self::forms(byte, shown))
            .collect();
        let max_len = places
            .iter()
            .map(|forms| forms.iter().map(|form| form.from.len()).max().unwrap_or(1))
            .sum();
        Some(Self { places, max_len })
    }

    fn forms(byte: u8, shown: u8) -> Vec<Form> {
        let mut forms = vec![Form {
            from: Zeroizing::new(vec![byte]),
            to: vec![shown],
        }];
        if !escapable(byte) {
            return forms;
        }
        let mut add = |from: Vec<u8>, to: Vec<u8>| {
            debug_assert_eq!(from.len(), to.len());
            if !forms.iter().any(|form| *form.from == from) {
                forms.push(Form {
                    from: Zeroizing::new(from),
                    to,
                });
            }
        };
        // JSON: `\/` and `\u00xx` in either case.
        if byte == b'/' {
            add(b"\\/".to_vec(), vec![shown; 2]);
        }
        for upper in [false, true] {
            add(json_u(byte, upper), json_u(shown, upper));
        }
        // HTML: named, decimal (also with one leading zero, as PHP writes `&#039;`),
        // and hexadecimal entities.
        let named: Option<&[u8]> = match byte {
            b'&' => Some(&b"&amp;"[..]),
            b'<' => Some(&b"&lt;"[..]),
            b'>' => Some(&b"&gt;"[..]),
            b'\'' => Some(&b"&apos;"[..]),
            b'"' => Some(&b"&quot;"[..]),
            _ => None,
        };
        if let Some(named) = named {
            add(named.to_vec(), html_decimal(shown, named.len()));
        }
        for zeros in 0..=1 {
            let from = format!("&#{}{byte};", "0".repeat(zeros)).into_bytes();
            let len = from.len();
            add(from, html_decimal(shown, len));
        }
        for upper in [false, true] {
            add(html_hex(byte, upper), html_hex(shown, upper));
        }
        forms
    }

    /// A form of the value that starts at `start` of `data`. Every mix of forms is
    /// tried: each step keeps the offsets that the forms of the place can reach.
    fn match_at(&self, data: &[u8], start: usize) -> Step {
        let Some(&first) = data.get(start) else {
            return Step::Miss;
        };
        if !self.places[0].iter().any(|form| form.from[0] == first) {
            return Step::Miss;
        }
        // Each layer: (offset after the place, index in the layer before, form).
        let mut layers: Vec<Vec<(usize, usize, usize)>> = Vec::with_capacity(self.places.len() + 1);
        layers.push(vec![(start, 0, 0)]);
        let mut partial = false;
        for forms in &self.places {
            let mut next: Vec<(usize, usize, usize)> = Vec::new();
            for (parent, &(offset, _, _)) in layers[layers.len() - 1].iter().enumerate() {
                let rest = &data[offset..];
                for (index, form) in forms.iter().enumerate() {
                    let from = form.from.as_slice();
                    if rest.len() >= from.len() {
                        let end = offset + from.len();
                        if rest[..from.len()] == *from && !next.iter().any(|step| step.0 == end) {
                            next.push((end, parent, index));
                        }
                    } else if from.starts_with(rest) {
                        partial = true;
                    }
                }
            }
            if next.is_empty() {
                return if partial { Step::Partial } else { Step::Miss };
            }
            layers.push(next);
        }
        let end = layers[layers.len() - 1][0].0;
        let mut chosen = Vec::with_capacity(self.places.len());
        let mut at = 0;
        for layer in layers[1..].iter().rev() {
            let (_, parent, form) = layer[at];
            chosen.push(form);
            at = parent;
        }
        chosen.reverse();
        let mut to = Vec::with_capacity(end - start);
        for (forms, &index) in self.places.iter().zip(&chosen) {
            to.extend_from_slice(&forms[index].to);
        }
        Step::Full(end - start, to)
    }
}

impl Replacer {
    /// Every pair must have `from.len() == to.len()` and a non-empty `from`.
    pub fn new(pairs: Vec<Pair>) -> Self {
        assert!(
            pairs
                .iter()
                .all(|pair| !pair.from.is_empty() && pair.from.len() == pair.to.len()),
            "a pair keeps the length"
        );
        Self {
            pairs,
            patterns: Vec::new(),
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// Also replace the escaped forms of these values ([`Pattern`]).
    pub fn with_patterns(mut self, patterns: Vec<Pattern>) -> Self {
        self.patterns = patterns;
        self
    }

    /// Replaces in place. Returns true when a value was found.
    pub fn replace_all(&self, data: &mut [u8]) -> bool {
        let mut found = false;
        for pair in &self.pairs {
            let mut offset = 0;
            while let Some(position) = find(&data[offset..], &pair.from) {
                let at = offset + position;
                data[at..at + pair.to.len()].copy_from_slice(&pair.to);
                offset = at + pair.to.len();
                found = true;
            }
        }
        for pattern in &self.patterns {
            let mut offset = 0;
            while offset < data.len() {
                match pattern.match_at(data, offset) {
                    Step::Full(len, to) => {
                        data[offset..offset + len].copy_from_slice(&to);
                        offset += len;
                        found = true;
                    }
                    Step::Partial | Step::Miss => offset += 1,
                }
            }
        }
        found
    }

    /// The length of the longest end of `data` that is the start of a value.
    fn open_end(&self, data: &[u8]) -> usize {
        self.pairs
            .iter()
            .map(|pair| {
                let from = pair.from.as_slice();
                (1..from.len().min(data.len() + 1))
                    .rev()
                    .find(|&k| data[data.len() - k..] == from[..k])
                    .unwrap_or(0)
            })
            .chain(self.patterns.iter().map(|pattern| {
                (data.len().saturating_sub(pattern.max_len)..data.len())
                    .find(|&start| matches!(pattern.match_at(data, start), Step::Partial))
                    .map_or(0, |start| data.len() - start)
            }))
            .max()
            .unwrap_or(0)
    }

    /// Adds `data`. Returns the bytes that are final: no value can start in them.
    pub fn feed(&mut self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut window = Zeroizing::new(Vec::with_capacity(self.pending.len() + data.len()));
        window.extend_from_slice(&self.pending);
        window.extend_from_slice(data);
        self.replace_all(&mut window);
        let split = window.len() - self.open_end(&window);
        self.pending = Zeroizing::new(window[split..].to_vec());
        window.truncate(split);
        window
    }

    /// The rest, at the end of the body.
    pub fn finish(&mut self) -> Zeroizing<Vec<u8>> {
        let mut rest = std::mem::replace(&mut self.pending, Zeroizing::new(Vec::new()));
        self.replace_all(&mut rest);
        rest
    }
}

/// The size of a chunk from its size line. `None` for a bad line.
fn chunk_size(line: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(line).ok()?.strip_suffix("\r\n")?;
    let size = text.split(';').next()?.trim();
    if size.is_empty() || size.len() > 15 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(size, 16).ok()
}

enum State {
    /// `Content-Length`: this many bytes are left.
    Length(u64),
    /// Chunked: expecting a chunk size line.
    ChunkSize,
    /// Chunked: this many bytes of the chunk are left.
    ChunkData(u64),
    UntilClose,
    Done,
}

/// The body of an upstream response as a `Read`. The bytes it gives have every real
/// value replaced by its placeholder. A `Content-Length` or chunked body that ends
/// early is an error, so the client sees a broken message and not a short one.
pub(super) struct BodyReader<S> {
    conn: Conn<S>,
    state: State,
    replacer: Replacer,
    out: Zeroizing<Vec<u8>>,
    out_pos: usize,
}

impl<S: Read> BodyReader<S> {
    pub fn new(conn: Conn<S>, body: BodyLen, replacer: Replacer) -> Self {
        let state = match body {
            BodyLen::None | BodyLen::Length(0) => State::Done,
            BodyLen::Length(length) => State::Length(length),
            BodyLen::Chunked => State::ChunkSize,
            BodyLen::UntilClose => State::UntilClose,
        };
        Self {
            conn,
            state,
            replacer,
            out: Zeroizing::new(Vec::new()),
            out_pos: 0,
        }
    }

    fn piece(&mut self, max: u64) -> io::Result<Zeroizing<Vec<u8>>> {
        let max = usize::try_from(max).unwrap_or(usize::MAX).min(READ_CHUNK);
        let piece = self.conn.read_some(max)?;
        if piece.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(piece)
    }

    /// Produces more output, or moves to `Done` after the last of it.
    fn pull(&mut self) -> io::Result<()> {
        let produced = match self.state {
            State::Done => return Ok(()),
            State::Length(left) => {
                let piece = self.piece(left)?;
                let left = left - piece.len() as u64;
                self.state = if left == 0 {
                    State::Done
                } else {
                    State::Length(left)
                };
                let mut out = self.replacer.feed(&piece);
                if left == 0 {
                    out.extend_from_slice(&self.replacer.finish());
                }
                out
            }
            State::UntilClose => match self.conn.read_some(READ_CHUNK) {
                Ok(piece) if !piece.is_empty() => self.replacer.feed(&piece),
                // A server that closes the socket without `close_notify` ends a
                // read-to-close body too.
                Ok(_) => self.end_of_stream(),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => self.end_of_stream(),
                Err(error) => return Err(error),
            },
            State::ChunkSize => {
                let line = self.conn.read_line()?;
                let size = chunk_size(&line).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "chunk size is not valid")
                })?;
                if size == 0 {
                    // Trailers are dropped. They end with an empty line.
                    while self.conn.read_line()?.as_slice() != b"\r\n" {}
                    self.state = State::Done;
                    self.replacer.finish()
                } else {
                    self.state = State::ChunkData(size);
                    Zeroizing::new(Vec::new())
                }
            }
            State::ChunkData(left) => {
                let piece = self.piece(left)?;
                let left = left - piece.len() as u64;
                if left == 0 {
                    if self.conn.read_line()?.as_slice() != b"\r\n" {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk end is not valid",
                        ));
                    }
                    self.state = State::ChunkSize;
                } else {
                    self.state = State::ChunkData(left);
                }
                self.replacer.feed(&piece)
            }
        };
        self.out = produced;
        self.out_pos = 0;
        Ok(())
    }

    fn end_of_stream(&mut self) -> Zeroizing<Vec<u8>> {
        self.state = State::Done;
        self.replacer.finish()
    }
}

impl<S: Read> Read for BodyReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.out_pos < self.out.len() {
                let count = (self.out.len() - self.out_pos).min(buf.len());
                buf[..count].copy_from_slice(&self.out[self.out_pos..self.out_pos + count]);
                self.out_pos += count;
                return Ok(count);
            }
            if matches!(self.state, State::Done) {
                return Ok(0);
            }
            self.pull()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(from: &[u8], to: &[u8]) -> Pair {
        Pair {
            from: Zeroizing::new(from.to_vec()),
            to: to.to_vec(),
        }
    }

    /// A reader that gives at most `step` bytes per call.
    struct Slow<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Slow<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = self.data.len().min(self.step).min(buf.len());
            buf[..count].copy_from_slice(&self.data[..count]);
            self.data = &self.data[count..];
            Ok(count)
        }
    }

    fn read_body(raw: &[u8], step: usize, body: BodyLen, pairs: Vec<Pair>) -> io::Result<Vec<u8>> {
        let conn = Conn::new(Slow { data: raw, step });
        let mut reader = BodyReader::new(conn, body, Replacer::new(pairs));
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
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
        let mut replacer = Replacer::new(vec![pair(b"REALVALUE1", b"placehold1")]);
        let mut out = Vec::new();
        for piece in [&b"x REALV"[..], b"ALUE1 y REAL", b"VALUE1", b" z"] {
            out.extend_from_slice(&replacer.feed(piece));
        }
        out.extend_from_slice(&replacer.finish());
        assert_eq!(out, b"x placehold1 y placehold1 z");
    }

    #[test]
    fn replacer_holds_back_only_a_possible_start_of_a_value() {
        let mut replacer = Replacer::new(vec![pair(b"REALVALUE1", b"placehold1")]);
        // An event of a stream goes out at once.
        assert_eq!(replacer.feed(b"data: {}\n\n").as_slice(), b"data: {}\n\n");
        // "REA" can be the start of the value, so it waits.
        assert_eq!(replacer.feed(b"data: REA").as_slice(), b"data: ");
        assert_eq!(replacer.feed(b"DY\n\n").as_slice(), b"READY\n\n");
    }

    #[test]
    fn replacer_handles_two_values() {
        let replacer = Replacer::new(vec![pair(b"AAAA", b"aaaa"), pair(b"BBBB", b"bbbb")]);
        let mut data = b"xAAAAyBBBBz".to_vec();
        assert!(replacer.replace_all(&mut data));
        assert_eq!(data, b"xaaaaybbbbz");
        assert!(!replacer.replace_all(&mut data));
    }

    #[test]
    fn length_body_is_replaced_across_every_read_size() {
        let raw = b"he-REAL-lo, REAL again, REA";
        for step in 1..=raw.len() {
            let out = read_body(
                raw,
                step,
                BodyLen::Length(raw.len() as u64),
                vec![pair(b"REAL", b"fake")],
            )
            .expect("body");
            assert_eq!(out, b"he-fake-lo, fake again, REA", "step {step}");
        }
    }

    // A value with bytes that JSON and HTML encoders escape, and a placeholder of the
    // same length (letters where the value has those bytes, as `mint` makes it).
    const VALUE: &[u8] = b"sk_test_AB/cd<ef>gh&ij'kl%mn";
    const PLACEHOLDER: &[u8] = b"sk_test_PQRSTUVWXYZabcdefghi";

    /// Each escaped echo of the value and what the client gets in its place.
    const ESCAPED: [(&str, &str); 6] = [
        // PHP json_encode: `\/`. No escape of `R` has two bytes: it repeats.
        (
            r"sk_test_AB\/cd<ef>gh&ij'kl%mn",
            "sk_test_PQRRSTUVWXYZabcdefghi",
        ),
        // Go encoding/json: `<`, `>`, `&`.
        (
            r"sk_test_AB/cd<ef>gh&ij'kl%mn",
            r"sk_test_PQRSTUVWXYZabcdefghi",
        ),
        // .NET System.Text.Json: upper-case hex, and `'` too.
        (
            r"sk_test_AB/cd<ef>gh&ij'kl%mn",
            r"sk_test_PQRSTUVWXYZabcdefghi",
        ),
        // Python html.escape: `&lt;`, `&gt;`, `&amp;`, `&#x27;`.
        (
            "sk_test_AB/cd&lt;ef&gt;gh&amp;ij&#x27;kl%mn",
            "sk_test_PQRSTUUUUVWXXXXYZ&#97;bc&#x64;efghi",
        ),
        // PHP htmlspecialchars with ENT_QUOTES: `&#039;`.
        (
            "sk_test_AB/cd&lt;ef&gt;gh&amp;ij&#039;kl%mn",
            "sk_test_PQRSTUUUUVWXXXXYZ&#97;bc&#100;efghi",
        ),
        // OWASP: `&#x2F;` too.
        (
            "sk_test_AB&#x2F;cd&lt;ef&gt;gh&amp;ij&#x27;kl%mn",
            "sk_test_PQ&#x52;STUUUUVWXXXXYZ&#97;bc&#x64;efghi",
        ),
    ];

    fn escaped_replacer() -> Replacer {
        Replacer::new(vec![pair(VALUE, PLACEHOLDER)]).with_patterns(vec![
            Pattern::escaped(VALUE, PLACEHOLDER).expect("a pattern"),
        ])
    }

    #[test]
    fn a_pattern_is_only_for_a_value_with_an_escapable_byte() {
        assert!(Pattern::escaped(b"sk_test_AB-cd_ef.gh", b"sk_test_PQ-RS_TU.VW").is_none());
        assert!(Pattern::escaped(VALUE, b"short").is_none());
        assert!(Pattern::escaped(VALUE, PLACEHOLDER).is_some());
    }

    #[test]
    fn an_escaped_echo_of_a_value_comes_back_as_the_placeholder() {
        let value = String::from_utf8(VALUE.to_vec()).unwrap();
        for (echo, shown) in ESCAPED {
            assert_eq!(echo.len(), shown.len(), "{echo}");
            let body = format!(r#"{{"echo":"{echo}","raw":"{value}","again":"{echo}"}}"#);
            let placeholder = String::from_utf8(PLACEHOLDER.to_vec()).unwrap();
            let want = format!(r#"{{"echo":"{shown}","raw":"{placeholder}","again":"{shown}"}}"#);

            let mut data = body.clone().into_bytes();
            assert!(escaped_replacer().replace_all(&mut data), "{echo}");
            assert_eq!(String::from_utf8(data).unwrap(), want, "{echo}");

            // Split across two reads, at every byte.
            for split in 0..=body.len() {
                let mut replacer = escaped_replacer();
                let mut out = replacer.feed(&body.as_bytes()[..split]).to_vec();
                out.extend_from_slice(&replacer.feed(&body.as_bytes()[split..]));
                out.extend_from_slice(&replacer.finish());
                assert_eq!(
                    String::from_utf8(out).unwrap(),
                    want,
                    "{echo} split {split}"
                );
            }

            // A body that comes in pieces of every size.
            for step in 1..=body.len() {
                let conn = Conn::new(Slow {
                    data: body.as_bytes(),
                    step,
                });
                let mut reader =
                    BodyReader::new(conn, BodyLen::Length(body.len() as u64), escaped_replacer());
                let mut out = Vec::new();
                reader.read_to_end(&mut out).expect("body");
                let out = String::from_utf8(out).unwrap();
                assert_eq!(out, want, "{echo} step {step}");
                assert!(!out.contains("AB/cd") && !out.contains("cd&lt;ef"), "{out}");
            }
        }
    }

    #[test]
    fn a_stream_does_not_wait_for_text_that_cannot_be_an_escaped_value() {
        let mut replacer = escaped_replacer();
        assert_eq!(replacer.feed(b"data: {}\n\n").as_slice(), b"data: {}\n\n");
        // A possible start of an escaped value waits; the rest goes out.
        assert_eq!(replacer.feed(br"data: sk_test_AB\").as_slice(), b"data: ");
        assert_eq!(
            replacer.feed(br"/cd<ef>gh&ij'kl%mn").as_slice(),
            b"sk_test_PQRRSTUVWXYZabcdefghi"
        );
    }

    #[test]
    fn a_short_length_body_is_an_error() {
        let error = read_body(b"abc", 2, BodyLen::Length(10), Vec::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn chunked_body_is_decoded_and_replaced() {
        let raw = b"5\r\nhe-RE\r\n6;ext=1\r\nAL-lo!\r\n0\r\nX-T: REAL\r\n\r\nNEXT";
        for step in 1..=8 {
            let out = read_body(raw, step, BodyLen::Chunked, vec![pair(b"REAL", b"fake")])
                .expect("chunked");
            assert_eq!(out, b"he-fake-lo!", "step {step}");
        }
        assert!(read_body(b"zz\r\nab\r\n", 4, BodyLen::Chunked, Vec::new()).is_err());
        assert!(read_body(b"2\r\nabXX0\r\n\r\n", 4, BodyLen::Chunked, Vec::new()).is_err());
        assert!(read_body(b"5\r\nab", 4, BodyLen::Chunked, Vec::new()).is_err());
    }

    #[test]
    fn read_to_close_body_ends_at_the_end_of_the_stream() {
        let out = read_body(
            b"all REAL here",
            3,
            BodyLen::UntilClose,
            vec![pair(b"REAL", b"fake")],
        )
        .expect("body");
        assert_eq!(out, b"all fake here");
    }

    #[test]
    fn no_body_reads_nothing() {
        let out = read_body(b"ignored", 3, BodyLen::None, Vec::new()).expect("body");
        assert!(out.is_empty());
    }

    #[test]
    fn head_and_lines_come_from_the_buffer() {
        let mut conn = Conn::new(Slow {
            data: b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nrest",
            step: 5,
        });
        let head = conn.read_head().expect("head");
        assert!(head.starts_with(b"HTTP/1.1 200"));
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(conn.read_some(100).expect("rest").as_slice(), b"rest");
        assert!(conn.buffered().is_empty());
        let mut long = Conn::new(Slow {
            data: &[b'a'; MAX_HEAD_BYTES + 10],
            step: 4096,
        });
        assert!(long.read_head().is_err());
    }
}
