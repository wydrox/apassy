//! Requests and answers (contract section 4). A passphrase or a secret of a request is
//! parsed into an erasing buffer, and an answer is serialized straight from borrowed
//! values: no intermediate JSON tree keeps a copy. This is best effort, as the import
//! of the Mac app: `serde_json` keeps a scratch copy of a string with escapes, and the
//! request text belongs to the caller.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
    serde_json::to_string(&Ok { ok: true, result })
        .unwrap_or_else(|_| error(&CoreError::internal("The answer cannot be written.")))
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
