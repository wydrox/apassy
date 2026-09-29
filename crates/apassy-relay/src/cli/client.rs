//! The HTTP client of the relay API (ureq): the relay origin, the bearer token, the optional edge header, and the envelope parsing.
//!
//! No redirects and no status-as-error: the client sees every status. A secret in a
//! request body or a response body lives in a `Zeroizing` string or a `SecretString`.

use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::api::{EDGE_HEADER, WireError};
use crate::cli::CliError;
use crate::secret::SecretString;

/// The timeout of a call, and how much more than a long poll it must be.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(60);
pub const LONG_POLL_MARGIN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// A raw answer: the status and the body text.
pub struct RawReply {
    pub status: u16,
    pub body: Zeroizing<String>,
}

/// The envelope with a typed `result`, so a secret in it lands in a `SecretString`.
#[derive(Deserialize)]
struct Reply<T> {
    ok: bool,
    #[serde(default = "none")]
    result: Option<T>,
    #[serde(default)]
    error: Option<WireError>,
}

fn none<T>() -> Option<T> {
    None
}

/// A relay error: the code and message from the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl ApiError {
    /// A refusal at `POST /v1/runs` by a hard rule or by access (no grant, an
    /// archived item): the run is denied, not broken, and a retry does not help.
    pub fn is_run_denial(&self) -> bool {
        self.code.starts_with("rule_")
            || self.code == crate::error::codes::NOT_GRANTED
            || self.code == crate::error::codes::ITEM_ARCHIVED
    }
}

pub enum CallError {
    Api(ApiError),
    Transport(String),
}

impl CallError {
    pub fn into_cli(self) -> CliError {
        match self {
            Self::Api(e) => CliError::relay(format!("relay: {}: {}", e.code, e.message)),
            Self::Transport(m) => CliError::relay(m),
        }
    }
}

pub struct Client {
    base: String,
    bearer: Option<SecretString>,
    edge: Option<SecretString>,
}

impl Client {
    /// `base` is a normalized origin (see `settings::normalize_url`).
    pub fn new(base: &str, bearer: Option<&SecretString>, edge: Option<&SecretString>) -> Self {
        Self {
            base: base.to_owned(),
            bearer: bearer.cloned(),
            edge: edge.cloned(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn agent(timeout: Duration) -> ureq::Agent {
        ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(timeout))
                .build(),
        )
    }

    /// One request. `accept` overrides the `Accept` header.
    pub fn raw(
        &self,
        method: Method,
        path: &str,
        body: Option<&str>,
        accept: Option<&str>,
        timeout: Duration,
    ) -> Result<RawReply, String> {
        let url = format!("{}{}", self.base, path);
        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(url)
            .header("Accept", accept.unwrap_or("application/json"));
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        if let Some(token) = &self.bearer {
            builder = builder.header("Authorization", format!("Bearer {}", token.expose()));
        }
        if let Some(edge) = &self.edge {
            builder = builder.header(EDGE_HEADER, edge.expose());
        }
        let request = builder
            .body(body.unwrap_or("").to_owned())
            .map_err(|_| "The request is not valid (check the tokens and the URL).".to_owned())?;
        let mut response = Self::agent(timeout)
            .run(request)
            .map_err(|e| format!("Cannot reach the relay: {}", transport_words(&e)))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("Cannot read the relay answer: {}", transport_words(&e)))?;
        Ok(RawReply {
            status,
            body: Zeroizing::new(text),
        })
    }

    /// One call to the API. Returns the typed `result`, or the error of the envelope.
    pub fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<T, CallError> {
        let reply = self
            .raw(method, path, body, None, timeout)
            .map_err(CallError::Transport)?;
        parse_reply(reply.status, &reply.body)
    }

    /// Like `call`, mapped to a CLI error (exit 4).
    pub fn ok<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&str>,
    ) -> Result<T, CliError> {
        self.call(method, path, body, CALL_TIMEOUT)
            .map_err(CallError::into_cli)
    }
}

/// Words for a transport failure, without the URL or any header.
fn transport_words(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Timeout(_) => "the call timed out.".to_owned(),
        ureq::Error::Io(e) => format!("{}.", e.kind()),
        other => {
            let text = other.to_string();
            let first = text.lines().next().unwrap_or("error");
            format!("{first}.")
        }
    }
}

pub fn parse_reply<T: DeserializeOwned>(status: u16, body: &str) -> Result<T, CallError> {
    match serde_json::from_str::<Reply<T>>(body) {
        Ok(Reply {
            ok: true,
            result: Some(result),
            ..
        }) => Ok(result),
        Ok(Reply {
            ok: false,
            error: Some(error),
            ..
        }) => Err(CallError::Api(ApiError {
            status,
            code: error.code,
            message: error.message,
        })),
        _ => Err(CallError::Transport(format!(
            "The relay answered with HTTP {status} and a body that is not an envelope. Is this the relay URL?"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_result_and_error() {
        let ok: Result<u64, CallError> = parse_reply(200, r#"{"ok":true,"result":5}"#);
        assert!(matches!(ok, Ok(5)));
        let err: Result<u64, CallError> = parse_reply(
            403,
            r#"{"ok":false,"error":{"code":"forbidden","message":"No."}}"#,
        );
        match err {
            Err(CallError::Api(e)) => assert_eq!((e.status, e.code.as_str()), (403, "forbidden")),
            _ => panic!("expected an api error"),
        }
        let junk: Result<u64, CallError> = parse_reply(502, "<html>bad gateway</html>");
        assert!(matches!(junk, Err(CallError::Transport(_))));
    }
}
