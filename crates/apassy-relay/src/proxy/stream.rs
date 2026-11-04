//! Track proxy: byte-stream helpers.
//!
//! A copy, with attribution, of the `Conn` and `Scanner` of
//! `src/broker/proxy/http1.rs` of wydrox/apassy at rev 77f6628 (Apache-2.0), changed
//! for the relay. The shared `echo::Replacer` owns its pairs; `BodyReader` turns an
//! upstream response into a `Read` that replaces each value with its placeholder.
//! The bytes stay the same length, so a `Content-Length` stays true.
//!
//! - `Scanner` finds a placeholder in a request body that comes in pieces.
//! - `Replacer` replaces values with placeholders in a response stream, across the
//!   borders of the pieces. A shared `Pattern` adds the JSON, HTML, and
//!   percent escapes of a value.
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

pub(super) use apassy::broker::proxy::echo::{Pair, Pattern, Replacer};

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

    /// Escaped echoes of the value. The client gets the placeholder in place of each,
    /// then the last byte of the placeholder for each byte that the echo has more.
    const ESCAPED: [&str; 10] = [
        // PHP json_encode: `\/`.
        r"sk_test_AB\/cd<ef>gh&ij'kl%mn",
        // Go encoding/json: `<`, `>`, `&`.
        r"sk_test_AB/cd\u003cef\u003egh\u0026ij'kl%mn",
        // .NET System.Text.Json: upper-case hex, and `'` too.
        r"sk_test_AB/cd\u003Cef\u003Egh\u0026ij\u0027kl%mn",
        // Python html.escape: `&lt;`, `&gt;`, `&amp;`, `&#x27;`.
        "sk_test_AB/cd&lt;ef&gt;gh&amp;ij&#x27;kl%mn",
        // PHP htmlspecialchars with ENT_QUOTES: `&#039;`.
        "sk_test_AB/cd&lt;ef&gt;gh&amp;ij&#039;kl%mn",
        // OWASP: `&#x2F;` too.
        "sk_test_AB&#x2F;cd&lt;ef&gt;gh&amp;ij&#x27;kl%mn",
        // Upper-case `X`, and leading zeros in decimal and hexadecimal entities.
        "sk_test_AB&#X2F;cd&#00060;ef&#x003E;gh&#0038;ij&#X0027;kl%mn",
        // Percent-encoding of a value that went raw in a header, in either case.
        "sk_test_AB%2Fcd%3Cef%3Egh%26ij%27kl%25mn",
        "sk_test_AB%2fcd%3cef%3egh%26ij%27kl%25mn",
        // A mix of every kind.
        r"sk_test_AB\/cd%3cef\u003Egh&amp;ij&#39;kl%25mn",
    ];

    fn escaped_replacer() -> Replacer {
        Replacer::new(vec![pair(VALUE, PLACEHOLDER)]).with_patterns(vec![
            Pattern::escaped(VALUE, PLACEHOLDER).expect("a pattern"),
        ])
    }

    /// The placeholder, then its last byte for each byte that `echo` has more.
    fn shown_for(placeholder: &[u8], echo: &[u8]) -> Vec<u8> {
        let mut shown = placeholder.to_vec();
        shown.resize(echo.len(), *placeholder.last().expect("a placeholder"));
        shown
    }

    /// `body` through a replacer of `value`: whole, split in two at every byte, and in
    /// pieces of every size. Each gives `want`, which has the length of `body`.
    fn assert_scrubbed(value: &[u8], placeholder: &[u8], body: &[u8], want: &[u8]) {
        assert_eq!(body.len(), want.len());
        let text = String::from_utf8_lossy(body);
        let replacer = || {
            Replacer::new(vec![pair(value, placeholder)]).with_patterns(vec![
                Pattern::escaped(value, placeholder).expect("a pattern"),
            ])
        };
        let mut data = body.to_vec();
        assert!(replacer().replace_all(&mut data), "{text}");
        assert_eq!(
            String::from_utf8_lossy(&data),
            String::from_utf8_lossy(want),
            "{text}"
        );
        for split in 0..=body.len() {
            let mut replacer = replacer();
            let mut out = replacer.feed(&body[..split]).to_vec();
            out.extend_from_slice(&replacer.feed(&body[split..]));
            out.extend_from_slice(&replacer.finish());
            assert_eq!(out, want, "{text} split {split}");
        }
        for step in 1..=body.len() {
            let conn = Conn::new(Slow { data: body, step });
            let mut reader = BodyReader::new(conn, BodyLen::Length(body.len() as u64), replacer());
            let mut out = Vec::new();
            reader.read_to_end(&mut out).expect("body");
            assert_eq!(out, want, "{text} step {step}");
        }
    }

    /// A JSON body with the echo twice and the raw value once, and what the client gets.
    fn json_echo(value: &[u8], placeholder: &[u8], echo: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let body = |echo: &[u8], value: &[u8]| -> Vec<u8> {
            let mut out = b"{\"echo\":\"".to_vec();
            out.extend_from_slice(echo);
            out.extend_from_slice(b"\",\"raw\":\"");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\",\"again\":\"");
            out.extend_from_slice(echo);
            out.extend_from_slice(b"\"}");
            out
        };
        (
            body(echo, value),
            body(&shown_for(placeholder, echo), placeholder),
        )
    }

    #[test]
    fn a_pattern_is_only_for_a_value_with_an_escapable_byte() {
        assert!(Pattern::escaped(b"sk_test_AB-cd_ef.gh", b"sk_test_PQ-RS_TU.VW").is_none());
        assert!(Pattern::escaped(VALUE, b"short").is_none());
        assert!(Pattern::escaped(VALUE, PLACEHOLDER).is_some());
    }

    #[test]
    fn an_escaped_echo_of_a_value_comes_back_as_the_placeholder() {
        for echo in ESCAPED {
            let (body, want) = json_echo(VALUE, PLACEHOLDER, echo.as_bytes());
            assert_scrubbed(VALUE, PLACEHOLDER, &body, &want);
            let out = String::from_utf8(want).unwrap();
            assert!(!out.contains("AB/cd") && !out.contains("cd&lt;ef"), "{out}");
        }
    }

    /// Finding 2 of the 0.5.16 review: the short JSON escapes `\"` and `\\`, and the
    /// `\u` escapes of non-ASCII characters, per code point: é (2 bytes in UTF-8), €
    /// (3 bytes), and 😀 (4 bytes, a surrogate pair in JSON).
    #[test]
    fn short_and_non_ascii_escapes_come_back_as_the_placeholder() {
        let value = "sk_test_AB\"cd\\efé€😀ghIJklMNop".as_bytes();
        let mut placeholder = b"sk_test_".to_vec();
        placeholder.resize(value.len(), b'Q');
        for echo in [
            // JSON without ASCII escapes: only `\"` and `\\`.
            r#"sk_test_AB\"cd\\efé€😀ghIJklMNop"#,
            // Python json.dumps: lower-case `\u`, a surrogate pair for 😀.
            r#"sk_test_AB\"cd\\ef\u00e9\u20ac\ud83d\ude00ghIJklMNop"#,
            r#"sk_test_AB\"cd\\ef\u00E9\u20AC\uD83D\uDE00ghIJklMNop"#,
            r"sk_test_AB\u0022cd\u005cef\u00e9\u20ac\ud83d\ude00ghIJklMNop",
            // HTML entities of each code point, decimal and hexadecimal.
            "sk_test_AB&quot;cd\\ef&#233;&#8364;&#128512;ghIJklMNop",
            "sk_test_AB&#x22;cd&#X5c;ef&#xE9;&#x20ac;&#x1F600;ghIJklMNop",
            // Percent-encoding of the UTF-8 bytes, in either case.
            "sk_test_AB%22cd%5Cef%C3%A9%E2%82%AC%F0%9F%98%80ghIJklMNop",
            "sk_test_AB%22cd%5cef%c3%a9%e2%82%ac%f0%9f%98%80ghIJklMNop",
        ] {
            let (body, want) = json_echo(value, &placeholder, echo.as_bytes());
            assert_scrubbed(value, &placeholder, &body, &want);
        }
        // The `\u` escapes of the single UTF-8 bytes are no escape of é: the encoders
        // write the code point.
        let wrong = r"sk_test_AB\u0022cd\u005cef\u00c3\u00a9€😀ghIJklMNop".as_bytes();
        let mut data = wrong.to_vec();
        let replacer = Replacer::new(vec![pair(value, &placeholder)]).with_patterns(vec![
            Pattern::escaped(value, &placeholder).expect("a pattern"),
        ]);
        assert!(!replacer.replace_all(&mut data));
    }

    /// Finding 3 of the 0.5.16 review: a value that ends with `&`, `\`, or `%` matched
    /// its raw bytes first, so `amp;` of `&amp;` stayed behind the placeholder and
    /// showed the last character. The longest form wins, also across reads.
    #[test]
    fn a_trailing_escape_leaves_no_rest_behind_the_placeholder() {
        for (value, echo) in [
            ("sk_test_ABcdEFghIJklMN&", "sk_test_ABcdEFghIJklMN&amp;"),
            ("sk_test_ABcdEFghIJklMN&", "sk_test_ABcdEFghIJklMN&#38;"),
            ("sk_test_ABcdEFghIJklMN&", "sk_test_ABcdEFghIJklMN&#x00026;"),
            ("sk_test_ABcdEFghIJklMN\\", r"sk_test_ABcdEFghIJklMN\\"),
            ("sk_test_ABcdEFghIJklMN\\", r"sk_test_ABcdEFghIJklMN\u005C"),
            ("sk_test_ABcdEFghIJklMN%", "sk_test_ABcdEFghIJklMN%25"),
        ] {
            let (value, echo) = (value.as_bytes(), echo.as_bytes());
            let mut placeholder = b"sk_test_".to_vec();
            placeholder.resize(value.len(), b'Q');
            let (body, want) = json_echo(value, &placeholder, echo);
            assert_scrubbed(value, &placeholder, &body, &want);
            for rest in ["amp;", "#38;", "x00026;", "u005C", "\\\\", "%25"] {
                assert!(
                    !String::from_utf8_lossy(&want).contains(rest),
                    "{}",
                    String::from_utf8_lossy(&want)
                );
            }
            // The raw value at the very end of a body waits for a longer form, and the
            // end of the body replaces it as it is.
            let mut replacer = Replacer::new(vec![pair(value, &placeholder)]).with_patterns(vec![
                Pattern::escaped(value, &placeholder).expect("a pattern"),
            ]);
            assert_eq!(replacer.feed(b"x ").as_slice(), b"x ");
            assert!(replacer.feed(value).is_empty());
            assert_eq!(replacer.finish().as_slice(), placeholder.as_slice());
        }
    }

    /// A pattern replaces the raw pair of its value; another pair (an encoded form that
    /// the request sent) stays and goes first.
    #[test]
    fn a_pattern_replaces_the_raw_pair_of_its_value() {
        let replacer = Replacer::new(vec![
            pair(b"ZWNobw==", b"c2hvd24="),
            pair(VALUE, PLACEHOLDER),
        ])
        .with_patterns(vec![
            Pattern::escaped(VALUE, PLACEHOLDER).expect("a pattern"),
        ]);
        let mut data = [&b"ZWNobw== "[..], VALUE].concat();
        assert!(replacer.replace_all(&mut data));
        assert_eq!(data, [&b"c2hvd24= "[..], PLACEHOLDER].concat());
    }

    #[test]
    fn a_stream_does_not_wait_for_text_that_cannot_be_an_escaped_value() {
        let mut replacer = escaped_replacer();
        assert_eq!(replacer.feed(b"data: {}\n\n").as_slice(), b"data: {}\n\n");
        // A possible start of an escaped value waits; the rest goes out.
        assert_eq!(replacer.feed(br"data: sk_test_AB\").as_slice(), b"data: ");
        assert_eq!(
            replacer.feed(br"/cd<ef>gh&ij'kl%mn").as_slice(),
            b"sk_test_PQRSTUVWXYZabcdefghii"
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
