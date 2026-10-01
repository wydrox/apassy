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

/// A failure before an answer: words for a person, and whether the request can have
/// reached the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawError {
    /// HTTP status when the relay answered but the body could not be read.
    pub status: Option<u16>,
    pub message: String,
    /// False when the request certainly did not reach the relay (no route, refused
    /// connection, failed TLS handshake). True when it may have (a timeout or a
    /// broken connection after the connect).
    pub maybe_sent: bool,
    pub usage: bool,
    pub api: Option<ApiError>,
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

    /// 503 `busy`: the relay has no free request slot. A retry later can work.
    pub fn is_busy(&self) -> bool {
        self.code == crate::error::codes::BUSY
    }
}

pub enum CallError {
    /// The local settings or sign-in origin are wrong.
    Usage(String),
    Api(ApiError),
    /// The call failed and the relay may have got the request.
    Transport(String),
    /// The call failed and the relay certainly did not get the request.
    Unsent(String),
}

impl CallError {
    pub fn into_cli(self) -> CliError {
        match self {
            Self::Usage(m) => CliError::usage(m),
            Self::Api(e) if e.code == "not_key_holder" => CliError::relay(
                "This device is not the key holder. Copy keys.json and move the key-holder flag before you start host.",
            ),
            Self::Api(e) => CliError::relay(format!("relay: {}: {}", e.code, e.message)),
            Self::Transport(m) | Self::Unsent(m) => CliError::relay(m),
        }
    }
}

pub struct Client {
    base: String,
    bearer: std::sync::Mutex<Option<SecretString>>,
    device: Option<(crate::ids::TeamId, crate::device::DeviceKey)>,
    edge: Option<SecretString>,
}

impl Client {
    /// `base` is a normalized origin (see `settings::normalize_url`).
    pub fn new(base: &str, bearer: Option<&SecretString>, edge: Option<&SecretString>) -> Self {
        Self {
            base: base.to_owned(),
            bearer: std::sync::Mutex::new(bearer.cloned()),
            device: None,
            edge: edge.cloned(),
        }
    }

    /// Device authentication wins unless a member token is explicitly supplied.
    pub fn member(settings: &crate::cli::settings::Settings) -> Result<Self, CliError> {
        let relay = settings.relay()?;
        let explicit_token = crate::cli::settings::env_secret(crate::cli::settings::ENV_TEAM_TOKEN);
        if explicit_token.is_some() || settings.device_id.is_none() {
            return Ok(Self::new(
                relay,
                Some(settings.member()?),
                settings.edge_secret.as_ref(),
            ));
        }
        let team = settings
            .team_id
            .as_ref()
            .ok_or_else(|| CliError::usage("There is no team id for this device."))?;
        let key = crate::cli::devicekey::store()?
            .load(relay, team)?
            .ok_or_else(|| {
                CliError::usage(
                    "There is no device key for this team. Use another device to make a link.",
                )
            })?;
        Self::with_device(relay, settings.edge_secret.as_ref(), team.clone(), key)
    }

    /// Starts a process-local access token using an injected device key.
    pub fn with_device(
        base: &str,
        edge: Option<&SecretString>,
        team: crate::ids::TeamId,
        key: crate::device::DeviceKey,
    ) -> Result<Self, CliError> {
        let mut client = Self::new(base, None, edge);
        let access =
            crate::cli::signin::sign_in(&client, &team, &key).map_err(CallError::into_cli)?;
        *client
            .bearer
            .get_mut()
            .map_err(|_| CliError::relay("Cannot read the access token."))? = Some(access.token);
        client.device = Some((team, key));
        Ok(client)
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
    ) -> Result<RawReply, RawError> {
        let reply = self.raw_once(method, path, body, accept, timeout)?;
        if reply.status == 401
            && let Some((team, key)) = &self.device
        {
            let auth = Self::new(&self.base, None, self.edge.as_ref());
            let token = crate::cli::signin::sign_in(&auth, team, key).map_err(|error| {
                let api = match &error {
                    CallError::Api(api) => Some(api.clone()),
                    _ => None,
                };
                let error = error.into_cli();
                RawError {
                    status: None,
                    message: error.message,
                    maybe_sent: false,
                    usage: error.code == 2,
                    api,
                }
            })?;
            *self.bearer.lock().map_err(|_| RawError {
                status: None,
                message: "Cannot read the access token.".into(),
                maybe_sent: false,
                usage: false,
                api: None,
            })? = Some(token.token);
            return self.raw_once(method, path, body, accept, timeout);
        }
        Ok(reply)
    }

    fn raw_once(
        &self,
        method: Method,
        path: &str,
        body: Option<&str>,
        accept: Option<&str>,
        timeout: Duration,
    ) -> Result<RawReply, RawError> {
        let url = format!("{}{}", self.base, path);
        let mut builder = ureq::http::Request::builder()
            .method(method.as_str())
            .uri(url)
            .header("Accept", accept.unwrap_or("application/json"));
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        let bearer = self.bearer.lock().map_err(|_| RawError {
            status: None,
            message: "Cannot read the access token.".into(),
            maybe_sent: false,
            usage: false,
            api: None,
        })?;
        if let Some(token) = &*bearer {
            builder = builder.header("Authorization", format!("Bearer {}", token.expose()));
        }
        if let Some(edge) = &self.edge {
            builder = builder.header(EDGE_HEADER, edge.expose());
        }
        drop(bearer);
        let request = builder
            .body(body.unwrap_or("").to_owned())
            .map_err(|_| RawError {
                status: None,
                message: "The request is not valid (check the tokens and the URL).".to_owned(),
                maybe_sent: false,
                usage: false,
                api: None,
            })?;
        let mut response = Self::agent(timeout).run(request).map_err(|e| RawError {
            status: None,
            message: format!("Cannot reach the relay: {}", transport_words(&e)),
            maybe_sent: !failed_before_send(&e),
            usage: false,
            api: None,
        })?;
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().map_err(|e| RawError {
            status: Some(status),
            message: format!("Cannot read the relay answer: {}", transport_words(&e)),
            maybe_sent: true,
            usage: false,
            api: None,
        })?;
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
        let reply = self.raw(method, path, body, None, timeout).map_err(|e| {
            if let Some(api) = e.api {
                CallError::Api(api)
            } else if e.usage {
                CallError::Usage(e.message)
            } else if e.maybe_sent {
                CallError::Transport(e.message)
            } else {
                CallError::Unsent(e.message)
            }
        })?;
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

/// True when the failure came before the request could leave: no address, a refused
/// connection, a failed handshake. Then the relay did not get the request.
fn failed_before_send(err: &ureq::Error) -> bool {
    match err {
        ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed
        | ureq::Error::BadUri(_)
        | ureq::Error::Http(_)
        | ureq::Error::Tls(_)
        | ureq::Error::Rustls(_) => true,
        ureq::Error::Timeout(timeout) => {
            matches!(timeout, ureq::Timeout::Resolve | ureq::Timeout::Connect)
        }
        ureq::Error::Io(e) => matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::HostUnreachable
        ),
        _ => false,
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
        _ if status == 503 => Err(CallError::Transport(
            "The relay or its edge is not available (HTTP 503 without an envelope). Try again later."
                .to_owned(),
        )),
        _ => Err(CallError::Transport(format!(
            "The relay answered with HTTP {status} and a body that is not an envelope. Is this the relay URL?"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_before_the_send_is_told_from_one_that_may_have_sent() {
        use std::io::{Error, ErrorKind};
        for before in [
            ureq::Error::HostNotFound,
            ureq::Error::ConnectionFailed,
            ureq::Error::Tls("handshake"),
            ureq::Error::Timeout(ureq::Timeout::Connect),
            ureq::Error::Timeout(ureq::Timeout::Resolve),
            ureq::Error::Io(Error::from(ErrorKind::ConnectionRefused)),
        ] {
            assert!(failed_before_send(&before), "{before:?}");
        }
        for maybe in [
            ureq::Error::Timeout(ureq::Timeout::Global),
            ureq::Error::Timeout(ureq::Timeout::RecvResponse),
            ureq::Error::Timeout(ureq::Timeout::SendBody),
            ureq::Error::Io(Error::from(ErrorKind::ConnectionReset)),
            ureq::Error::Io(Error::from(ErrorKind::UnexpectedEof)),
            ureq::Error::Io(Error::from(ErrorKind::BrokenPipe)),
        ] {
            assert!(!failed_before_send(&maybe), "{maybe:?}");
        }
    }

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
        let busy: Result<u64, CallError> = parse_reply(
            503,
            r#"{"ok":false,"error":{"code":"busy","message":"The relay is busy."}}"#,
        );
        match busy {
            Err(CallError::Api(e)) => {
                assert!(e.is_busy());
                let cli = CallError::Api(e).into_cli();
                assert_eq!(cli.code, 4);
                assert!(cli.message.contains("busy"), "{}", cli.message);
            }
            _ => panic!("expected an api error"),
        }
        match parse_reply::<u64>(503, "relay not configured") {
            Err(CallError::Transport(message)) => assert!(message.contains("503"), "{message}"),
            _ => panic!("expected a transport error"),
        }
    }
}
