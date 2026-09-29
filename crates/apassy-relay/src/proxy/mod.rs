//! Track proxy: the reverse proxy of a session (docs/SPEC.md, "Reverse proxy").
//!
//! `ANY /p/<session key>/<host[:port]>/<path>?<query>` goes to
//! `https://<host[:port]>/<path>?<query>`. The proxy puts the real value in place of
//! a placeholder only in an auth position, only for a host of that item, and puts
//! the placeholder back in the response. Everything else with a placeholder is
//! refused with 403 and `X-Apassy-Relay: refused`.
//!
//! The public interface below is fixed by the skeleton: the server calls
//! `Proxy::new` once and `Proxy::handle` for each request on the proxy path, after
//! it has checked the edge secret. `base_url` and `mint` are what the server uses
//! to build the environment of a session.

mod stream;
mod swap;
mod upstream;

use std::sync::Arc;

use apassy::broker::proxy::HostRule;

use crate::api::{RELAY_HEADER, paths};
use crate::config::UpstreamOptions;
use crate::error::{RelayError, RelayResult, codes};
use crate::secret::SecretString;
use crate::session::SessionSource;

/// The largest request body the proxy reads. It must read the whole body to look
/// for placeholders before it sends anything upstream. Larger: 413.
pub const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// The base URL of one host in one session: `<public_url>/p/<session key>/<host>`.
/// `host` is shown as `host` for port 443 and `host:port` otherwise.
pub fn base_url(public_url: &str, session_key: &SecretString, host: &HostRule) -> String {
    format!(
        "{}{}{}/{}",
        public_url.trim_end_matches('/'),
        paths::PROXY_PREFIX,
        session_key.expose(),
        host
    )
}

/// A fresh placeholder for a value (ADR 0011 of the core: same length, known
/// prefix kept, at least 64 random bits). `None` when the value is too short or
/// has too little room for random characters; the server then refuses the item.
pub fn mint(value: &SecretString) -> Option<SecretString> {
    apassy::broker::proxy::mint_placeholder(value.expose()).map(SecretString::new)
}

/// The reverse proxy. One per relay; `handle` is called from many threads.
pub struct Proxy {
    sessions: Arc<dyn SessionSource>,
    #[allow(dead_code)]
    options: UpstreamOptions,
}

impl Proxy {
    /// Builds the TLS client configuration for upstream hosts: the system roots
    /// (rustls-platform-verifier) plus `options.extra_roots_der`.
    pub fn new(options: &UpstreamOptions, sessions: Arc<dyn SessionSource>) -> RelayResult<Self> {
        Ok(Self {
            sessions,
            options: options.clone(),
        })
    }

    /// Serves one request whose path starts with `/p/`, and responds to it.
    /// It never panics on input and never returns an error: every failure is a
    /// response (403, 404, 413, 501, 502) with `X-Apassy-Relay`, and one
    /// `SessionSource::record` call.
    pub fn handle(&self, request: tiny_http::Request, now: u64) {
        // Skeleton: the proxy track replaces this body.
        let _ = (&self.sessions, now);
        let error = RelayError::new(codes::NOT_SUPPORTED, "The proxy is not built yet.");
        respond_refused(request, &error);
    }
}

/// A JSON error response with `X-Apassy-Relay: refused`.
fn respond_refused(request: tiny_http::Request, error: &RelayError) {
    let body = serde_json::to_vec(&error.to_envelope()).unwrap_or_default();
    let mut response = tiny_http::Response::from_data(body).with_status_code(error.status());
    for (name, value) in [
        (RELAY_HEADER, "refused"),
        ("Content-Type", "application/json"),
    ] {
        if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    }
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_shape() {
        let key = SecretString::new(format!("apassy_ses_{}", "a".repeat(64)));
        let host = HostRule::parse("api.stripe.com").unwrap();
        assert_eq!(
            base_url("https://relay.example.test/", &key, &host),
            format!(
                "https://relay.example.test/p/apassy_ses_{}/api.stripe.com",
                "a".repeat(64)
            )
        );
        let port = HostRule::parse("api.example.com:8443").unwrap();
        assert!(base_url("https://r.test", &key, &port).ends_with("/api.example.com:8443"));
    }

    #[test]
    fn mint_keeps_length_and_prefix() {
        let value = SecretString::new("sk_test_51SyntheticCanaryValue0123456789abcdef".into());
        let placeholder = mint(&value).expect("a placeholder");
        assert_eq!(placeholder.len(), value.len());
        assert!(placeholder.expose().starts_with("sk_test_"));
        assert_ne!(placeholder, value);
        assert!(mint(&SecretString::new("short".into())).is_none());
    }
}
