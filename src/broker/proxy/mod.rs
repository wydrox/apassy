//! The proxy of one run (ADR 0011).
//!
//! A variable in placeholder mode puts a placeholder into the environment of the
//! process, not the real value. The broker starts this proxy for the run and points
//! the process at it (`HTTPS_PROXY` and the trust files). For a host of a secret,
//! the proxy ends the TLS connection with a certificate of the run authority, checks
//! each request, puts the real value into its auth position, and sends the request
//! on with a new TLS connection that it verifies itself. In the response, it puts
//! the placeholder back in place of a real value. Other hosts get a tunnel without
//! a look inside, or a refusal.
//!
//! On macOS, a Seatbelt rule lets the process connect only to the proxy port, so a
//! program that ignores `HTTPS_PROXY` has no network at all. On Linux a bubblewrap
//! sandbox with its own network namespace does the same, when bubblewrap can run
//! there (`network.rs`). A program that goes
//! around the proxy in any other way still holds only placeholders.
//!
//! The proxy listens on 127.0.0.1 with a password for the run. It serves only the
//! run, and it stops when the run ends. A same-user process that reads the
//! environment of the run (F11) can send requests through it while the run lasts.
//! It gets what the swap rules allow, each request is logged, and it never gets a
//! value.
//!
//! The parts:
//!
//! - `engine.rs`: [`ProxyCore`], the swap rules of one set of secrets, served on
//!   connections that a listener or another front hands over.
//! - `listener.rs`: [`RunProxy`], the 127.0.0.1 listener of a local run.
//! - `network.rs`: [`network_for`], the variables, trust files, and network rule
//!   of the process.
//! - `public_addr.rs`: [`is_public_ip`], shared with the relay proxy.
//! - `base_env.rs`: the base URL variables, shared with the relay.
//! - `ws.rs`: the WebSocket frame relay (ADR 0011 stage 5).

pub mod base_env;
mod ca;
mod engine;
mod http1;
mod listener;
mod network;
mod public_addr;
mod swap;
mod ws;

pub use ca::Alpn;
pub use engine::{Auth, CoreOptions, EventSink, ProxyCore, UpstreamPolicy};
pub use listener::RunProxy;
pub use network::{LinuxNet, NetworkRule, NoRule, RunNetwork, network_for};
pub use public_addr::is_public_ip;
pub use swap::mint_placeholder;

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use self::http1::RequestHead;
use super::http::TlsClient;

const MAX_PATH_CHARS: usize = 120;

/// Names that the proxy sets in the environment of the run. A binding cannot use them.
pub const RESERVED_VARIABLES: [&str; 14] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

/// Where the real value of a secret may go: a host with its subdomains, on one port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    host: String,
    port: u16,
}

impl HostRule {
    /// `api.example.com` (port 443) or `api.example.com:8443`. Lowercase names only.
    /// The vault checks the stored hosts with the same rule.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let (host, port) = crate::vault::parse_placeholder_host(text)
            .ok_or("A host is a lowercase name such as api.example.com, with an optional port.")?;
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// True for the host itself and each subdomain, on the port of the rule.
    pub fn covers(&self, host: &str, port: u16) -> bool {
        port == self.port
            && (host == self.host
                || host
                    .strip_suffix(self.host.as_str())
                    .is_some_and(|head| head.ends_with('.')))
    }
}

impl std::fmt::Display for HostRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.port == 443 {
            f.write_str(&self.host)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// One secret of a run in placeholder mode. Debug is redacted.
pub struct ProxySecret {
    /// The variable name, for the log.
    pub name: String,
    pub placeholder: String,
    pub value: Zeroizing<String>,
    pub hosts: Vec<HostRule>,
}

impl std::fmt::Debug for ProxySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProxySecret({}=[redacted])", self.name)
    }
}

/// What the proxy does with a host that no secret of the run is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OtherHosts {
    /// A tunnel without a look inside. The process has only placeholders there.
    #[default]
    Tunnel,
    /// A refusal. The run reaches only the hosts of its secrets.
    Refuse,
}

#[derive(Debug, Clone)]
pub struct ProxyOptions {
    /// Verifies the services. Tests add a test root.
    pub tls: TlsClient,
    pub other_hosts: OtherHosts,
    /// On macOS: let the process connect only to the proxy.
    pub enforce: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyOutcome {
    /// Sent with a real value.
    Swapped,
    /// Sent without a real value.
    Passed,
    /// Sent through a tunnel, without a look inside.
    Tunneled,
    /// Stopped by the proxy.
    Refused,
    /// The connection or the TLS handshake failed.
    Failed,
}

/// One request or connection of a run. It has no value and no placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxyEvent {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub outcome: ProxyOutcome,
    /// The variables whose real value went into the request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ProxyEvent {
    /// Codes may appear in any free text. Erase it before retaining an event for
    /// a code-bearing run; only outcome/count metadata is needed for that run.
    fn erase_details(&mut self) {
        self.host.zeroize();
        for slot in [&mut self.method, &mut self.path, &mut self.reason] {
            if let Some(mut text) = slot.take() {
                text.zeroize();
            }
        }
        self.secrets.zeroize();
    }

    fn new(host: &str, port: u16, outcome: ProxyOutcome) -> Self {
        Self {
            host: host.to_owned(),
            port,
            method: None,
            path: None,
            status: None,
            outcome,
            secrets: Vec::new(),
            reason: None,
        }
    }

    /// An entry for a request. A placeholder in the path shows as `[apassy:NAME]`.
    fn for_request(host: &str, port: u16, request: &RequestHead, secrets: &[ProxySecret]) -> Self {
        let mut path = request
            .target
            .split('?')
            .next()
            .unwrap_or_default()
            .to_owned();
        for secret in secrets {
            if path.contains(&secret.placeholder) {
                path = path.replace(&secret.placeholder, &format!("[apassy:{}]", secret.name));
            }
        }
        let path: String = path.chars().take(MAX_PATH_CHARS).collect();
        Self {
            method: Some(request.method.clone()),
            path: Some(path),
            ..Self::new(host, port, ProxyOutcome::Passed)
        }
    }

    fn with_reason(mut self, outcome: ProxyOutcome, reason: impl Into<String>) -> Self {
        self.outcome = outcome;
        self.reason = Some(reason.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_run_events_erase_free_text_before_retention() {
        let mut event = ProxyEvent {
            host: "123456.example.invalid".into(),
            port: 443,
            method: Some("123456".into()),
            path: Some("/confirm/123456".into()),
            status: Some(200),
            outcome: ProxyOutcome::Passed,
            secrets: vec!["123456".into()],
            reason: Some("synthetic 123456".into()),
        };
        event.erase_details();
        assert!(!serde_json::to_string(&event).unwrap().contains("123456"));
        assert_eq!(event.outcome, ProxyOutcome::Passed);
        assert_eq!(event.status, Some(200));
    }

    #[test]
    fn host_rules_cover_subdomains_on_their_port() {
        let rule = HostRule::parse("example.com").expect("rule");
        assert!(rule.covers("example.com", 443));
        assert!(rule.covers("api.example.com", 443));
        assert!(!rule.covers("badexample.com", 443));
        assert!(!rule.covers("api.example.com", 8443));
        let rule = HostRule::parse("localhost:8443").expect("rule");
        assert!(rule.covers("localhost", 8443));
        assert_eq!(rule.to_string(), "localhost:8443");
        for bad in [
            "",
            "Example.com",
            "a..b",
            ".a",
            "a:0",
            "a:x",
            "a b",
            "https://a",
        ] {
            assert!(HostRule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_binding_cannot_use_a_proxy_variable() {
        for name in RESERVED_VARIABLES {
            assert!(
                crate::vault::checked_env_name(name).is_err(),
                "{name} must be reserved"
            );
        }
    }
}
