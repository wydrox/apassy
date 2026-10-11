//! Requests and answers (contract section 4). A passphrase or a secret of a request is
//! parsed into an erasing buffer, and an answer is serialized straight from borrowed
//! values: no intermediate JSON tree keeps a copy. This is best effort, as the import
//! of the Mac app: `serde_json` keeps a scratch copy of a string with escapes, and the
//! request text belongs to the caller.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{self, Write};
use zeroize::Zeroize;
use zeroize::Zeroizing;

use super::errors::CoreError;

/// A secret of a request. Debug is redacted.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The parsed string moves into the erasing buffer without a copy.
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}

#[derive(Serialize)]
struct Ok<'a, T: Serialize> {
    ok: bool,
    result: &'a T,
}

#[derive(Serialize)]
struct Failure<'a> {
    ok: bool,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    rekeyed: bool,
}

/// `{"ok": true, "result": …}`.
pub fn ok<T: Serialize>(result: &T) -> String {
    exact_json(&Ok { ok: true, result })
        .unwrap_or_else(|| error(&CoreError::internal("The answer cannot be written.")))
}

/// Count first, then write into one allocation with room for the FFI NUL byte.
/// A serializer whose second pass changes length fails instead of growing a
/// buffer that contains secrets. On failure, the buffer is erased.
fn exact_json<T: Serialize>(value: &T) -> Option<String> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("The answer is too large."))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Fixed {
        bytes: Zeroizing<Vec<u8>>,
        limit: usize,
    }
    impl Write for Fixed {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit - self.bytes.len() {
                return Err(io::Error::other("The answer changed during serialization."));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value).ok()?;
    let mut writer = Fixed {
        bytes: Zeroizing::new(Vec::with_capacity(count.0.checked_add(1)?)),
        limit: count.0,
    };
    serde_json::to_writer(&mut writer, value).ok()?;
    if writer.bytes.len() != count.0 {
        return None;
    }
    match String::from_utf8(std::mem::take(&mut *writer.bytes)) {
        Ok(text) => Some(text),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            None
        }
    }
}

/// `{"ok": false, "error": {…}}`.
pub fn error(error: &CoreError) -> String {
    serde_json::to_string(&Failure {
        ok: false,
        error: ErrorBody {
            code: error.code,
            message: &error.message,
            rekeyed: error.rekeyed,
        },
    })
    .unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"code":"internal","message":"The answer cannot be written."}}"#
            .to_owned()
    })
}

/// The empty result `{}`.
#[derive(Serialize)]
pub struct Empty {}

/// Parse the parameters of a request.
pub fn params<'a, T: Deserialize<'a>>(request: &'a str) -> Result<T, CoreError> {
    serde_json::from_str(request).map_err(|error| {
        let field = error.to_string();
        // serde_json names a missing field as "missing field `name` at …".
        let name = field
            .split('`')
            .nth(1)
            .filter(|_| field.starts_with("missing field") || field.starts_with("invalid type"))
            .unwrap_or("a parameter");
        CoreError::invalid(format!("The request has no valid {name}."))
    })
}

/// Serialize an erasing buffer as a string (`#[serde(serialize_with = …)]`).
pub fn zeroizing<S: Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn secret_answer_keeps_exact_room_for_ffi_termination() {
        let value = "synthetic \"escaped\" \\ text\nzażółć";
        let answer = ok(&value);
        assert_eq!(answer.capacity(), answer.len() + 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&answer).unwrap()["result"],
            value
        );
    }

    #[test]
    fn a_changed_serializer_cannot_grow_a_secret_buffer() {
        struct Changed(Cell<bool>);
        impl Serialize for Changed {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let second = self.0.replace(true);
                serializer.serialize_str(if second {
                    "a longer synthetic answer"
                } else {
                    "a"
                })
            }
        }
        let answer = ok(&Changed(Cell::new(false)));
        assert!(answer.contains("internal"));
        assert!(!answer.contains("synthetic"));
    }
}
