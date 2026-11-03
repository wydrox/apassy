//! The JSON of the external HTTP transport (contract section 2.1, ADR 0039 section 5):
//! a relay request for the host, and the host's answer. Safe Rust; `ffi` moves the bytes.
//!
//! The request holds the bearer and the body, and the answer can hold a token: both are
//! built and read in erasing buffers of their exact size.

use std::io::{self, Write};

use apassy::sync::{ExternalAnswer, ExternalRequest, HttpError, decode_b64u, encode_b64u};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

/// The longest answer text that the core reads: a body of the largest JSON answer in
/// b64u, and room for the status and the headers.
pub(crate) const MAX_ANSWER_TEXT: usize = (2 * 1024 * 1024usize).div_ceil(3) * 4 + 64 * 1024;

#[derive(Serialize)]
struct RequestWire<'a> {
    id: u64,
    method: &'a str,
    url: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_b64u: Option<&'a str>,
    timeout_ms: u64,
    /// The pin of a pinned origin (node-pairing-v1 section 4). Absent: system trust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pin: Option<&'a str>,
}

/// A string of the answer in an erasing buffer.
struct SecretText(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}

#[derive(Deserialize)]
struct AnswerWire {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body_b64u: Option<SecretText>,
    #[serde(default)]
    error: Option<String>,
}

/// The request as NUL-terminated JSON: `{"id", "method", "url", "headers": [[name,
/// value], …], "body_b64u" (absent without a body), "timeout_ms", "pin" (absent for
/// system trust)}`.
pub(crate) fn request_json(request: &ExternalRequest<'_>) -> Option<Zeroizing<Vec<u8>>> {
    let body = request.body.map(|body| Zeroizing::new(encode_b64u(body)));
    let wire = RequestWire {
        id: request.id,
        method: request.method,
        url: &request.url,
        headers: request
            .headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect(),
        body_b64u: body.as_ref().map(|body| body.as_str()),
        timeout_ms: u64::try_from(request.timeout.as_millis())
            .unwrap_or(u64::MAX)
            .max(1),
        pin: request.pin.as_deref(),
    };
    exact_json(&wire)
}

/// The answer of the host: `{"status", "headers", "body_b64u"}` or `{"error":
/// "connect" | "broken" | "protocol" | "pin_mismatch"}`. Text that is not such an answer
/// is `Protocol`. `pin_mismatch` counts only for a pinned request: for another one it is
/// `Broken`, as any unknown text.
pub(crate) fn parse_answer(text: &[u8], pinned: bool) -> Result<ExternalAnswer, HttpError> {
    if text.len() > MAX_ANSWER_TEXT {
        return Err(HttpError::Protocol);
    }
    let wire: AnswerWire = serde_json::from_slice(text).map_err(|_| HttpError::Protocol)?;
    if let Some(error) = wire.error {
        return Err(match error.as_str() {
            "connect" => HttpError::Connect,
            "protocol" => HttpError::Protocol,
            "pin_mismatch" if pinned => HttpError::PinMismatch,
            _ => HttpError::Broken,
        });
    }
    let status = wire.status.ok_or(HttpError::Protocol)?;
    let body = match wire.body_b64u {
        Some(text) => Zeroizing::new(decode_b64u(&text.0).ok_or(HttpError::Protocol)?),
        None => Zeroizing::new(Vec::new()),
    };
    Ok(ExternalAnswer {
        status,
        headers: wire.headers,
        body,
    })
}

/// `value` as JSON with a NUL byte, in one erasing buffer of the exact size: the length
/// is counted first. `None` when the serializer fails or changes its length.
fn exact_json<T: Serialize>(value: &T) -> Option<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("The request is too large."))?;
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
                return Err(io::Error::other(
                    "The request changed during serialization.",
                ));
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
    let mut fixed = Fixed {
        bytes: Zeroizing::new(Vec::with_capacity(count.0.checked_add(1)?)),
        limit: count.0,
    };
    serde_json::to_writer(&mut fixed, value).ok()?;
    if fixed.bytes.len() != count.0 {
        return None;
    }
    fixed.bytes.push(0);
    Some(fixed.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_request_is_json_with_its_headers_and_body() {
        let request = ExternalRequest {
            id: 7,
            method: "POST",
            url: "https://relay.example.test/v1/devices/link".to_owned(),
            headers: vec![
                (
                    "Authorization",
                    Zeroizing::new("Bearer apassy_acc_synthetic".to_owned()),
                ),
                ("User-Agent", Zeroizing::new("apassy-sync/1".to_owned())),
            ],
            body: Some(&b"{\"code\":\"synthetic\"}"[..]),
            timeout: Duration::from_secs(55),
            pin: None,
        };
        let json = request_json(&request).unwrap();
        assert_eq!(json.last(), Some(&0));
        let value: serde_json::Value = serde_json::from_slice(&json[..json.len() - 1]).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "id": 7,
                "method": "POST",
                "url": "https://relay.example.test/v1/devices/link",
                "headers": [["Authorization", "Bearer apassy_acc_synthetic"], ["User-Agent", "apassy-sync/1"]],
                "body_b64u": encode_b64u(b"{\"code\":\"synthetic\"}"),
                "timeout_ms": 55000,
            })
        );
        let without = ExternalRequest {
            body: None,
            timeout: Duration::ZERO,
            ..request
        };
        let json = request_json(&without).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json[..json.len() - 1]).unwrap();
        assert!(value.get("body_b64u").is_none());
        assert_eq!(value["timeout_ms"], 1);
        assert!(value.get("pin").is_none(), "system trust names no pin");

        // A pinned origin (unit N6): the request names its pin.
        let pinned = ExternalRequest {
            pin: Some("u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE".to_owned()),
            url: "https://100.64.0.7:8444/v1/questions".to_owned(),
            body: None,
            ..without
        };
        let json = request_json(&pinned).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json[..json.len() - 1]).unwrap();
        assert_eq!(value["pin"], "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE");
        assert_eq!(value["url"], "https://100.64.0.7:8444/v1/questions");
    }

    #[test]
    fn an_answer_or_an_error_of_the_host_reads() {
        let body = encode_b64u(b"{\"ok\":true}");
        let text = format!(r#"{{"status":200,"headers":[["ETag","\"3\""]],"body_b64u":"{body}"}}"#);
        let answer = parse_answer(text.as_bytes(), false).unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(answer.headers, [("ETag".to_owned(), "\"3\"".to_owned())]);
        assert_eq!(answer.body.as_slice(), b"{\"ok\":true}");
        let empty = parse_answer(br#"{"status":204}"#, false).unwrap();
        assert!(empty.body.is_empty() && empty.headers.is_empty());
        for (text, error) in [
            (r#"{"error":"connect"}"#, HttpError::Connect),
            (r#"{"error":"broken"}"#, HttpError::Broken),
            (r#"{"error":"protocol"}"#, HttpError::Protocol),
            (r#"{"error":"something else"}"#, HttpError::Broken),
            (r#"{"headers":[]}"#, HttpError::Protocol),
            (
                r#"{"status":200,"body_b64u":"not b64u!"}"#,
                HttpError::Protocol,
            ),
            (r#"{"status":70000}"#, HttpError::Protocol),
            ("not json", HttpError::Protocol),
            // A pin mismatch of a request without a pin is no pin mismatch.
            (r#"{"error":"pin_mismatch"}"#, HttpError::Broken),
        ] {
            assert_eq!(
                parse_answer(text.as_bytes(), false).err(),
                Some(error),
                "{text}"
            );
        }
        assert_eq!(
            parse_answer(br#"{"error":"pin_mismatch"}"#, true).err(),
            Some(HttpError::PinMismatch)
        );
        assert_eq!(
            parse_answer(br#"{"error":"connect"}"#, true).err(),
            Some(HttpError::Connect)
        );
        let large = vec![b' '; MAX_ANSWER_TEXT + 1];
        assert_eq!(parse_answer(&large, false).err(), Some(HttpError::Protocol));
    }
}
