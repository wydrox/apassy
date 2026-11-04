//! Shared, length-preserving response masking for the Mac and relay proxies.
//! Secret-bearing pattern bytes are erased on drop; no encoding dependencies.

use zeroize::Zeroizing;

/// One real value and the placeholder of the same length that replaces it.
pub struct Pair {
    pub from: Zeroizing<Vec<u8>>,
    pub to: Vec<u8>,
}

/// Replaces real values with placeholders in a response that comes in pieces. Each
/// pair has the same length, so the body keeps its length. It holds back only an end
/// of a piece that can be the start of a value, so a stream (server-sent events) flows.
pub struct Replacer {
    pairs: Vec<Pair>,
    patterns: Vec<Pattern>,
    pending: Zeroizing<Vec<u8>>,
    /// Whether any fed bytes were replaced.
    pub replaced: bool,
}

/// A byte of a value that a JSON, HTML, or URL encoder can escape: every byte that is
/// not a letter, a digit, or one of `-_.`, also each byte of a non-ASCII character.
fn escapable(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && !b"-_.".contains(&byte)
}

/// HTML numeric entities can have leading zeros (`&#039;`, `&#x002F;`): this many at
/// most are matched.
const MAX_LEADING_ZEROS: usize = 4;

/// The escaped forms of one value, in any mix: an upstream host that echoes the value
/// escaped gives back no value.
///
/// - JSON: `\/`, `\"`, `\\` (and `\b`, `\f`, `\n`, `\r`, `\t`), `\u002f` in either
///   case, and `\u00e9` of a non-ASCII character, built per code point from UTF-8,
///   with a surrogate pair (`\ud83d\ude00`) above U+FFFF.
/// - HTML: `&amp;`, `&lt;`, `&gt;`, `&apos;`, `&quot;`, and decimal and hexadecimal
///   entities (`&#39;`, `&#x2F;`, `&#X2F;`), also with leading zeros (`&#039;`).
/// - Percent-encoding: `%2F` and `%2f`, for a value that went raw in a header and comes
///   back in a URL.
///
/// Each character of the value is one place with its forms; the first form of each
/// place is its raw bytes. A whole form of the value becomes the placeholder, and the
/// bytes that the form has more than the value come after it (the last byte of the
/// placeholder, repeated). So the bytes keep their length and show neither the value
/// nor where it has a byte that an encoder escapes: only the total length shows.
pub struct Pattern {
    places: Vec<Vec<Zeroizing<Vec<u8>>>>,
    placeholder: Vec<u8>,
    /// The longest form of the whole value.
    max_len: usize,
}

/// The result of a match at one offset.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// A whole form of the value, the longest one that the data has: its length.
    Full(usize),
    /// The data ends inside a possible form of the value, or a longer form than a
    /// whole one can still complete with more data.
    Partial,
    Miss,
}

fn json_u(code: u32, upper: bool) -> Vec<u8> {
    if upper {
        format!("\\u{code:04X}").into_bytes()
    } else {
        format!("\\u{code:04x}").into_bytes()
    }
}

/// The JSON `\u` escape of a code point: one escape, or a surrogate pair above U+FFFF.
fn json_code_point(code: u32, upper: bool) -> Vec<u8> {
    if code <= 0xFFFF {
        return json_u(code, upper);
    }
    let offset = code - 0x10000;
    let mut both = json_u(0xD800 + (offset >> 10), upper);
    both.extend_from_slice(&json_u(0xDC00 + (offset & 0x3FF), upper));
    both
}

/// The short JSON escape of an ASCII byte.
fn json_short(byte: u8) -> Option<&'static [u8]> {
    match byte {
        b'/' => Some(&br"\/"[..]),
        b'"' => Some(&br#"\""#[..]),
        b'\\' => Some(&br"\\"[..]),
        0x08 => Some(&br"\b"[..]),
        0x0C => Some(&br"\f"[..]),
        b'\n' => Some(&br"\n"[..]),
        b'\r' => Some(&br"\r"[..]),
        b'\t' => Some(&br"\t"[..]),
        _ => None,
    }
}

/// The named HTML entity of an ASCII byte.
fn html_named(byte: u8) -> Option<&'static [u8]> {
    match byte {
        b'&' => Some(&b"&amp;"[..]),
        b'<' => Some(&b"&lt;"[..]),
        b'>' => Some(&b"&gt;"[..]),
        b'\'' => Some(&b"&apos;"[..]),
        b'"' => Some(&b"&quot;"[..]),
        _ => None,
    }
}

/// The decimal and hexadecimal HTML entities of a code point, with up to
/// [`MAX_LEADING_ZEROS`] leading zeros, `x` or `X`, and hex digits in either case.
fn html_numeric(code: u32) -> Vec<Vec<u8>> {
    let mut forms = Vec::new();
    for zeros in 0..=MAX_LEADING_ZEROS {
        let zeros = "0".repeat(zeros);
        forms.push(format!("&#{zeros}{code};").into_bytes());
        for mark in ["x", "X"] {
            forms.push(format!("&#{mark}{zeros}{code:x};").into_bytes());
            forms.push(format!("&#{mark}{zeros}{code:X};").into_bytes());
        }
    }
    forms
}

/// The percent-encoding of bytes, in either case.
fn percent(bytes: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        out.extend_from_slice(&[
            b'%',
            digits[usize::from(byte >> 4)],
            digits[usize::from(byte & 0x0F)],
        ]);
    }
    out
}

/// Adds `from` to the forms of a place, once.
fn add_form(forms: &mut Vec<Zeroizing<Vec<u8>>>, from: Vec<u8>) {
    let from = Zeroizing::new(from);
    if !forms.iter().any(|form| form.as_slice() == from.as_slice()) {
        forms.push(from);
    }
}

/// The characters of `value`: the bytes of each code point with the code point. A
/// value that is not UTF-8 is cut into bytes; a byte above 0x7F then has no code point.
fn characters(value: &[u8]) -> Vec<(&[u8], Option<u32>)> {
    match std::str::from_utf8(value) {
        Ok(text) => text
            .char_indices()
            .map(|(at, character)| {
                (
                    &value[at..at + character.len_utf8()],
                    Some(u32::from(character)),
                )
            })
            .collect(),
        Err(_) => value
            .iter()
            .enumerate()
            .map(|(at, &byte)| (&value[at..=at], byte.is_ascii().then_some(u32::from(byte))))
            .collect(),
    }
}

impl Pattern {
    /// Maximum length of an encoded form, for bounded stream lookbehind.
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// The escaped forms of `value`, which `placeholder` replaces. `None` when the
    /// lengths differ or no byte of the value has an escape: the raw pair covers it.
    pub fn escaped(value: &[u8], placeholder: &[u8]) -> Option<Self> {
        if value.is_empty()
            || value.len() != placeholder.len()
            || !value.iter().copied().any(escapable)
        {
            return None;
        }
        let places: Vec<Vec<Zeroizing<Vec<u8>>>> = characters(value)
            .into_iter()
            .map(|(raw, code)| Self::forms(raw, code))
            .collect();
        let max_len = places
            .iter()
            .map(|forms| forms.iter().map(|form| form.len()).max().unwrap_or(1))
            .sum();
        Some(Self {
            places,
            placeholder: placeholder.to_vec(),
            max_len,
        })
    }

    /// The forms of one character: its raw bytes first, then its escapes.
    fn forms(raw: &[u8], code: Option<u32>) -> Vec<Zeroizing<Vec<u8>>> {
        let mut forms = vec![Zeroizing::new(raw.to_vec())];
        if !raw.iter().copied().any(escapable) {
            return forms;
        }
        for upper in [false, true] {
            add_form(&mut forms, percent(raw, upper));
        }
        let Some(code) = code else {
            return forms;
        };
        if let Ok(byte) = u8::try_from(code)
            && byte.is_ascii()
        {
            if let Some(short) = json_short(byte) {
                add_form(&mut forms, short.to_vec());
            }
            if let Some(named) = html_named(byte) {
                add_form(&mut forms, named.to_vec());
            }
        }
        for upper in [false, true] {
            add_form(&mut forms, json_code_point(code, upper));
        }
        for numeric in html_numeric(code) {
            add_form(&mut forms, numeric);
        }
        forms
    }

    /// Whether `pair` is the raw value of this pattern with its placeholder.
    fn covers(&self, pair: &Pair) -> bool {
        if pair.to != self.placeholder {
            return false;
        }
        let mut rest = pair.from.as_slice();
        for forms in &self.places {
            let Some(tail) = rest.strip_prefix(forms[0].as_slice()) else {
                return false;
            };
            rest = tail;
        }
        rest.is_empty()
    }

    /// The bytes that replace a whole form of `len` bytes: the placeholder, then the
    /// last byte of the placeholder for each byte that the form has more.
    fn shown(&self, len: usize) -> Vec<u8> {
        let mut shown = self.placeholder.clone();
        let fill = shown.last().copied().unwrap_or(b'x');
        shown.resize(len.max(shown.len()), fill);
        shown
    }

    /// A form of the value that starts at `start` of `data`. Every mix of forms is
    /// tried: each step keeps the offsets that the forms of the place can reach. The
    /// longest whole form wins, so no rest of an escape (`amp;` of `&amp;`) stays
    /// behind the placeholder. Unless `at_end` (no more data comes), a form that the
    /// data ends inside is `Partial`, also when a shorter form is whole: more data can
    /// make the longer one.
    pub fn match_at(&self, data: &[u8], start: usize, at_end: bool) -> Step {
        let Some(&first) = data.get(start) else {
            return Step::Miss;
        };
        if !self.places[0].iter().any(|form| form[0] == first) {
            return Step::Miss;
        }
        let mut offsets = vec![start];
        let mut partial = false;
        for forms in &self.places {
            let mut next: Vec<usize> = Vec::new();
            for &offset in &offsets {
                let rest = &data[offset..];
                for form in forms {
                    let from = form.as_slice();
                    if rest.len() >= from.len() {
                        let end = offset + from.len();
                        if rest[..from.len()] == *from && !next.contains(&end) {
                            next.push(end);
                        }
                    } else if from.starts_with(rest) {
                        partial = true;
                    }
                }
            }
            if next.is_empty() {
                return if partial && !at_end {
                    Step::Partial
                } else {
                    Step::Miss
                };
            }
            offsets = next;
        }
        if partial && !at_end {
            return Step::Partial;
        }
        let end = offsets.into_iter().max().unwrap_or(start);
        Step::Full(end - start)
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
            replaced: false,
        }
    }

    /// Also replace the escaped forms of these values ([`Pattern`]). A pattern has the
    /// raw form of its value too, and it replaces the raw pair of the value: a raw pair
    /// would replace the raw bytes of `…&` in `…&amp;` and leave `amp;` behind, which
    /// shows the last character of the value.
    pub fn with_patterns(mut self, patterns: Vec<Pattern>) -> Self {
        self.pairs
            .retain(|pair| !patterns.iter().any(|pattern| pattern.covers(pair)));
        self.patterns = patterns;
        self
    }

    /// Replaces in place a whole text, such as a header value. Returns true when a
    /// value was found.
    pub fn replace_all(&self, data: &mut [u8]) -> bool {
        self.replace(data, true)
    }

    /// Replaces in place. `at_end`: no more data follows `data`, so a form that more
    /// data could make longer is replaced as it is. The longest complete match wins;
    /// an explicit request echo wins a tie with a generic escaped form.
    fn replace(&self, data: &mut [u8], at_end: bool) -> bool {
        let mut found = false;
        let mut offset = 0;
        while offset < data.len() {
            let rest = &data[offset..];
            let pair = self
                .pairs
                .iter()
                .rev()
                .filter(|pair| rest.starts_with(&pair.from))
                .max_by_key(|pair| pair.from.len());
            let mut best = pair.map(|pair| (pair.from.len(), pair.to.clone()));
            let mut partial = !at_end
                && self
                    .pairs
                    .iter()
                    .any(|pair| rest.len() < pair.from.len() && pair.from.starts_with(rest));
            for pattern in &self.patterns {
                match pattern.match_at(data, offset, at_end) {
                    Step::Full(len) if best.as_ref().is_none_or(|(old, _)| len > *old) => {
                        best = Some((len, pattern.shown(len)));
                    }
                    Step::Partial => partial = true,
                    _ => {}
                }
            }
            if partial {
                // A longer value or escape may complete in the next read.
                break;
            }
            if let Some((len, shown)) = best {
                data[offset..offset + len].copy_from_slice(&shown);
                offset += len;
                found = true;
            } else {
                offset += 1;
            }
        }
        found
    }

    /// The length of the longest end of `data` that is the start of a value, or of a
    /// form of a value that more data can make longer.
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
                    .find(|&start| pattern.match_at(data, start, false) == Step::Partial)
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
        self.replaced |= self.replace(&mut window, false);
        let split = window.len() - self.open_end(&window);
        self.pending = Zeroizing::new(window[split..].to_vec());
        window.truncate(split);
        window
    }

    /// The rest, at the end of the body.
    pub fn finish(&mut self) -> Zeroizing<Vec<u8>> {
        let mut rest = std::mem::replace(&mut self.pending, Zeroizing::new(Vec::new()));
        self.replaced |= self.replace(&mut rest, true);
        rest
    }
}

/// An encoded form of a value that a proxy sent upstream, and the same form of
/// the placeholder. Both have the same length. The response gets `shown` in place
/// of `sent`, so an upstream host that echoes the request gives back no value.
pub struct Echo {
    pub sent: Zeroizing<String>,
    pub shown: String,
}

/// True for a byte that stays as it is in a query value.
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}

/// Writes `text` percent-encoded. A byte is escaped when it is not unreserved or
/// when `escape_at` is true for its position. `upper` picks the case of the hex digits.
pub fn percent_encode_into(
    text: &str,
    escape_at: impl Fn(usize) -> bool,
    upper: bool,
    out: &mut String,
) {
    let hex: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    for (position, byte) in text.bytes().enumerate() {
        if unreserved(byte) && !escape_at(position) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(hex[usize::from(byte >> 4)]));
            out.push(char::from(hex[usize::from(byte & 15)]));
        }
    }
}

/// The percent-encoded forms of a value in a query parameter, with the same forms of
/// its placeholder: first the form the proxy sends (upper-case hex), then the
/// lower-case one when it differs. The placeholder is escaped at each position where
/// the value is, so each pair has the same length. `None` when the placeholder needs
/// an escape where the value does not (a placeholder from `mint` never does).
pub fn query_echoes(value: &str, placeholder: &str) -> Option<Vec<Echo>> {
    if value.len() != placeholder.len() {
        return None;
    }
    let escaped = |position: usize| !unreserved(value.as_bytes()[position]);
    let mut echoes = Vec::with_capacity(2);
    for upper in [true, false] {
        let mut sent = Zeroizing::new(String::with_capacity(value.len() * 3));
        percent_encode_into(value, |_| false, upper, &mut sent);
        let mut shown = String::with_capacity(sent.len());
        percent_encode_into(placeholder, escaped, upper, &mut shown);
        if sent.len() != shown.len() {
            return None;
        }
        if !upper && echoes.iter().any(|echo: &Echo| *echo.sent == *sent) {
            continue;
        }
        echoes.push(Echo { sent, shown });
    }
    Some(echoes)
}
