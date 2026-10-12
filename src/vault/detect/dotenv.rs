//! The `.env` parser that the paste detection (`src/vault/detect.rs`) and the command-line import
//! (`src/cli/import.rs`) share.
//!
//! The command line builds without the vault feature, so `src/cli/import.rs` includes
//! this file with `#[path]`. It uses only `std` and `zeroize`.
//!
//! The rules: one `KEY=value` per line, an optional `export`, `#` comments and blank
//! lines, a value in double quotes (with `\n`, `\r`, `\t`, and `\"`) or single quotes
//! (as written) that can span lines, and an unquoted value that ends at ` #`.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// One `KEY=value` line with a value. `line` is the line of the key, from 1. Debug
/// hides the value. Drop erases it.
pub struct Line {
    pub line: usize,
    pub key: String,
    pub value: Zeroizing<String>,
}

impl fmt::Debug for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Line")
            .field("line", &self.line)
            .field("key", &self.key)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// A line that gives no value, with the reason. Comments and blank lines are not
/// skipped lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub line: usize,
    pub reason: String,
    /// The line is not a `KEY=value` line at all (not an empty value or an open quote).
    pub not_env: bool,
}

/// The key and the rest of a `KEY=value` line, with an optional `export`. A key has
/// ASCII letters, digits, and `_`, and does not start with a digit.
pub fn env_key(line: &str) -> Option<(&str, &str)> {
    let line = line.strip_prefix("export ").map_or(line, str::trim_start);
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    let valid = !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !key.as_bytes()[0].is_ascii_digit();
    valid.then_some((key, value))
}

/// Parse a `.env` text. Lines with an empty value, an open quote, or no `KEY=` are
/// skipped with a reason.
pub fn parse(text: &str) -> (Vec<Line>, Vec<Skipped>) {
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let number = index + 1;
        let line = lines[index].trim_start();
        index += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = env_key(line) else {
            skipped.push(Skipped {
                line: number,
                reason: "not a KEY=value line".to_owned(),
                not_env: true,
            });
            continue;
        };
        let raw = raw.trim_start();
        let mut value = match raw.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                // A quoted value can span lines, for example a private key.
                let mut body = raw[1..].to_owned();
                loop {
                    if let Some(end) = closing_quote(&body, quote) {
                        body.truncate(end);
                        break;
                    }
                    if index >= lines.len() {
                        body.zeroize();
                        skipped.push(Skipped {
                            line: number,
                            reason: format!("{key}: the quote does not close"),
                            not_env: false,
                        });
                        body = String::new();
                        break;
                    }
                    body.push('\n');
                    body.push_str(lines[index]);
                    index += 1;
                }
                if quote == '"' {
                    let out = unescape_double(&body);
                    body.zeroize();
                    out
                } else {
                    body
                }
            }
            _ => {
                // An unquoted value ends at " #".
                let end = raw.find(" #").unwrap_or(raw.len());
                raw[..end].trim().to_owned()
            }
        };
        if value.is_empty() {
            if !skipped.iter().any(|s| s.line == number) {
                skipped.push(Skipped {
                    line: number,
                    reason: format!("{key}: the value is empty"),
                    not_env: false,
                });
            }
            continue;
        }
        entries.push(Line {
            line: number,
            key: key.to_owned(),
            value: Zeroizing::new(std::mem::take(&mut value)),
        });
    }
    (entries, skipped)
}

/// The position of the closing quote. In double quotes, `\"` does not close.
fn closing_quote(body: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (at, c) in body.char_indices() {
        if quote == '"' && c == '\\' && !escaped {
            escaped = true;
            continue;
        }
        if c == quote && !escaped {
            return Some(at);
        }
        escaped = false;
    }
    None
}

fn unescape_double(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// A custom field name from a variable name: lowercase letters, digits, and `_`. A
/// built-in name gets a `value_` prefix.
pub fn custom_field(key: &str) -> String {
    let name = key.to_lowercase();
    match name.as_str() {
        "service" | "project" | "token" | "password" | "private_key" | "passphrase"
        | "username" | "host" | "database" | "public_key" | "website" => {
            format!("value_{name}")
        }
        // `x_` names a custom detail, and `passkey_` a field of the passkey path.
        _ if name.starts_with("x_") || name.starts_with("passkey_") => format!("value_{name}"),
        _ => name,
    }
}
