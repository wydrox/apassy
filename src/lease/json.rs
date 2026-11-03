//! A strict reader of the small JSON objects of way C: a service-account key and the
//! answers of the token endpoints (plan s6 unit C2).
//!
//! `serde_json` copies a string with an escape (`\n`, `\/`, `\u…`) into a scratch buffer
//! that it never erases, and a `serde_json::Value` holds every string in a `String` that
//! is freed without erasure. A service-account key always has escapes (the `\n` of its
//! PEM private key), and an OAuth answer can have them (`\/`). This reader therefore:
//!
//! 1. checks the whole text with `serde_json` as [`IgnoredAny`], which skips each string
//!    in place without a copy: the grammar, the nesting limit, and no trailing text;
//! 2. walks the top-level object itself and keeps each member value as a slice of the
//!    caller's text (a string without its quotes, with its escapes as they are);
//! 3. unescapes a string only when it is asked for, into a [`Zeroizing`] buffer of the
//!    exact size, so the buffer never grows and leaves no partial copy.
//!
//! A key that is in the object twice is refused. `Debug` shows the keys only.

use std::fmt;

use serde::de::IgnoredAny;
use zeroize::Zeroizing;

/// One member value: a JSON string (the text between its quotes, escapes as they are)
/// or any other JSON value (its raw text).
#[derive(Clone, Copy)]
enum Raw<'a> {
    Text(&'a str),
    Other(&'a str),
}

/// The members of one JSON object, in their order.
pub(crate) struct Object<'a> {
    members: Vec<(String, Raw<'a>)>,
}

impl fmt::Debug for Object<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Object")
            .field(
                "keys",
                &self
                    .members
                    .iter()
                    .map(|(key, _)| key.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl<'a> Object<'a> {
    /// Read `text`: one JSON object, white space around it allowed, with distinct keys.
    /// `None` for any other text.
    pub(crate) fn parse(text: &'a str) -> Option<Self> {
        serde_json::from_str::<IgnoredAny>(text).ok()?;
        let bytes = text.as_bytes();
        let mut at = skip_space(bytes, 0);
        if bytes.get(at) != Some(&b'{') {
            return None;
        }
        at = skip_space(bytes, at + 1);
        let mut members: Vec<(String, Raw<'a>)> = Vec::new();
        if bytes.get(at) == Some(&b'}') {
            return Some(Self { members });
        }
        loop {
            let (raw_key, end) = string_at(text, at)?;
            let key = decode(raw_key)?.as_str().to_owned();
            if members.iter().any(|(earlier, _)| *earlier == key) {
                return None;
            }
            at = skip_space(bytes, end);
            if bytes.get(at) != Some(&b':') {
                return None;
            }
            at = skip_space(bytes, at + 1);
            let (value, end) = if bytes.get(at) == Some(&b'"') {
                let (content, end) = string_at(text, at)?;
                (Raw::Text(content), end)
            } else {
                let end = value_end(text, at)?;
                (Raw::Other(text.get(at..end)?), end)
            };
            members.push((key, value));
            at = skip_space(bytes, end);
            match bytes.get(at) {
                Some(b',') => at = skip_space(bytes, at + 1),
                Some(b'}') => return Some(Self { members }),
                _ => return None,
            }
        }
    }

    fn get(&self, name: &str) -> Option<Raw<'a>> {
        self.members
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| *value)
    }

    /// Whether the object has the member `name` with a value other than `null`.
    pub(crate) fn has(&self, name: &str) -> bool {
        match self.get(name) {
            None => false,
            Some(Raw::Other(raw)) => raw != "null",
            Some(Raw::Text(_)) => true,
        }
    }

    /// The string member `name`, unescaped into an erased buffer. `None`: no such member,
    /// a value that is not a string, or a string with a lone surrogate.
    pub(crate) fn text(&self, name: &str) -> Option<Zeroizing<String>> {
        match self.get(name)? {
            Raw::Text(raw) => decode(raw),
            Raw::Other(_) => None,
        }
    }

    /// The member `name` as a whole number of seconds: a JSON number of digits only, or
    /// a JSON string of digits only (some OAuth servers send `"3600"`). No sign, fraction,
    /// or exponent.
    pub(crate) fn uint(&self, name: &str) -> Option<u64> {
        let (Raw::Other(digits) | Raw::Text(digits)) = self.get(name)?;
        if digits.is_empty() || digits.len() > 19 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    }
}

fn skip_space(bytes: &[u8], mut at: usize) -> usize {
    while matches!(bytes.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

/// The content of the JSON string that starts at `at` (its opening quote), and the
/// index after its closing quote. The text is valid JSON already.
fn string_at(text: &str, at: usize) -> Option<(&str, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(at) != Some(&b'"') {
        return None;
    }
    let mut index = at + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Some((text.get(at + 1..index)?, index + 1)),
            _ => index += 1,
        }
    }
    None
}

/// The index after the JSON value that starts at `at` and is not a string: an object
/// or an array (strings inside are skipped as strings), or a number, `true`, `false`,
/// or `null`.
fn value_end(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    match bytes.get(at)? {
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut index = at;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => {
                        index = string_at(text, index)?.1;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(index + 1);
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
            None
        }
        _ => {
            let mut index = at;
            while index < bytes.len()
                && !matches!(
                    bytes[index],
                    b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'
                )
            {
                index += 1;
            }
            (index > at).then_some(index)
        }
    }
}

/// Walk the characters of the content of a JSON string, escapes resolved. `false` for
/// an escape that is not valid or a lone surrogate.
fn walk(raw: &str, mut emit: impl FnMut(char)) -> bool {
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            emit(c);
            continue;
        }
        let resolved = match chars.next() {
            Some('"') => '"',
            Some('\\') => '\\',
            Some('/') => '/',
            Some('b') => '\u{8}',
            Some('f') => '\u{c}',
            Some('n') => '\n',
            Some('r') => '\r',
            Some('t') => '\t',
            Some('u') => {
                let Some(high) = hex4(&mut chars) else {
                    return false;
                };
                let code = match high {
                    0xD800..=0xDBFF => {
                        if chars.next() != Some('\\') || chars.next() != Some('u') {
                            return false;
                        }
                        let Some(low) = hex4(&mut chars) else {
                            return false;
                        };
                        if !(0xDC00..=0xDFFF).contains(&low) {
                            return false;
                        }
                        0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                    }
                    0xDC00..=0xDFFF => return false,
                    code => code,
                };
                match char::from_u32(code) {
                    Some(c) => c,
                    None => return false,
                }
            }
            _ => return false,
        };
        emit(resolved);
    }
    true
}

fn hex4(chars: &mut std::str::Chars<'_>) -> Option<u32> {
    let mut value = 0u32;
    for _ in 0..4 {
        value = value * 16 + chars.next()?.to_digit(16)?;
    }
    Some(value)
}

/// The content of a JSON string with its escapes resolved, in an erased buffer of the
/// exact size.
fn decode(raw: &str) -> Option<Zeroizing<String>> {
    let mut size = 0usize;
    if !walk(raw, |c| size += c.len_utf8()) {
        return None;
    }
    let mut out = Zeroizing::new(String::with_capacity(size));
    walk(raw, |c| out.push(c));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reader_takes_one_object_with_distinct_keys() {
        let text = r#" {"a": "x\n\/y", "n": 3600, "s": "900", "z": null,
            "nested": {"k": ["}", "\"", {"q": 1}]}, "e": "é😀"} "#;
        let object = Object::parse(text).expect("object");
        assert_eq!(object.text("a").expect("a").as_str(), "x\n/y");
        assert_eq!(object.uint("n"), Some(3600));
        assert_eq!(object.uint("s"), Some(900));
        assert_eq!(object.text("e").expect("e").as_str(), "\u{e9}\u{1f600}");
        assert!(object.has("nested") && !object.has("z") && !object.has("missing"));
        assert_eq!(object.text("n"), None, "a number is not a string");
        assert_eq!(object.text("nested"), None);
        assert_eq!(object.uint("a"), None);
        assert_eq!(
            format!("{object:?}"),
            r#"Object { keys: ["a", "n", "s", "z", "nested", "e"] }"#
        );
        assert!(Object::parse("{}").expect("empty").members.is_empty());
        for refused in [
            "",
            "[]",
            "\"text\"",
            r#"{"a": 1, "a": 2}"#,
            r#"{"a": 1} x"#,
            r#"{"a": 1,}"#,
            r#"{"a" 1}"#,
            r#"{"a": "\x"}"#,
            "{\"a\": \"raw\nnewline\"}",
        ] {
            assert!(Object::parse(refused).is_none(), "{refused:?}");
        }
        // A lone surrogate passes the grammar but is not text.
        let lone = Object::parse(r#"{"a": "\ud800"}"#);
        assert!(lone.is_none_or(|object| object.text("a").is_none()));
        for bad in [
            "-1",
            "1.5",
            "1e3",
            "\"12a\"",
            "\"\"",
            "99999999999999999999",
        ] {
            let text = format!(r#"{{"n": {bad}}}"#);
            assert_eq!(
                Object::parse(&text).expect("object").uint("n"),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_decoded_string_has_the_exact_capacity() {
        let object =
            Object::parse(r#"{"k": "-----BEGIN-----\nABC\n-----END-----\n"}"#).expect("object");
        let key = object.text("k").expect("text");
        assert_eq!(key.as_str(), "-----BEGIN-----\nABC\n-----END-----\n");
        assert_eq!(key.capacity(), key.len(), "the buffer never grew");
    }
}
