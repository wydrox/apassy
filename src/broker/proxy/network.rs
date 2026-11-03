//! What the process of a proxied run needs (ADR 0011 §4): the proxy and trust
//! variables, the trust files, and the network rule of the system.
//!
//! On macOS, a Seatbelt rule lets the process connect only to the proxy port, so a
//! program that ignores `HTTPS_PROXY` has no network at all. On other systems the
//! run has no rule yet; a program that goes around the proxy still holds only
//! placeholders.

use std::io;
use std::path::PathBuf;

use serde::Serialize;

/// The system trust stores that the bundle for the process starts with.
const SYSTEM_BUNDLES: [&str; 4] = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];
/// Variables that point a process at the proxy. Upper and lower case, because
/// tools read different ones.
const PROXY_VARIABLES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];
/// Variables that name a full trust bundle (system roots and the run authority).
const BUNDLE_VARIABLES: [&str; 4] = [
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

/// The rule that keeps a proxied run on the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRule {
    /// macOS: a Seatbelt profile allows only the connection to the proxy.
    Seatbelt,
    /// Linux: a network namespace whose only way out leads to the proxy.
    Netns,
    /// No rule: the process has the network of the user.
    None,
}

impl NetworkRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seatbelt => "seatbelt",
            Self::Netns => "netns",
            Self::None => "none",
        }
    }
}

/// What the process needs: environment variables and, on macOS, a Seatbelt profile.
/// The trust files live as long as this value.
pub struct RunNetwork {
    pub env: Vec<(String, String)>,
    /// The rule that the run gets. `Seatbelt` exactly when `sandbox_profile` is set.
    pub rule: NetworkRule,
    pub sandbox_profile: Option<String>,
    pub ca_file: PathBuf,
    _dir: tempfile::TempDir,
}

/// Writes the trust files of a run into a new 0700 folder and builds the variables
/// that point a process at `proxy_url`. With `enforce`, the run gets the network
/// rule of this system for the proxy `port`.
pub fn network_for(
    ca_pem: &str,
    proxy_url: &str,
    port: u16,
    enforce: bool,
) -> io::Result<RunNetwork> {
    // tempfile makes the folder with mode 0700.
    let dir = tempfile::Builder::new().prefix("apassy-run-").tempdir()?;
    let ca_file = dir.path().join("apassy-run-ca.pem");
    std::fs::write(&ca_file, ca_pem)?;
    let mut bundle = SYSTEM_BUNDLES
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default();
    if !bundle.ends_with('\n') && !bundle.is_empty() {
        bundle.push('\n');
    }
    bundle.push_str(ca_pem);
    let bundle_file = dir.path().join("trust-bundle.pem");
    std::fs::write(&bundle_file, bundle)?;

    let mut env: Vec<(String, String)> = PROXY_VARIABLES
        .iter()
        .map(|name| ((*name).to_owned(), proxy_url.to_owned()))
        .collect();
    env.push(("NO_PROXY".to_owned(), String::new()));
    env.push(("no_proxy".to_owned(), String::new()));
    // Node 22.21 and later read HTTPS_PROXY only with this switch.
    env.push(("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()));
    env.push((
        "NODE_EXTRA_CA_CERTS".to_owned(),
        ca_file.display().to_string(),
    ));
    for name in BUNDLE_VARIABLES {
        env.push((name.to_owned(), bundle_file.display().to_string()));
    }
    let sandbox_profile = enforce.then(|| sandbox_profile(port)).flatten();
    let rule = if sandbox_profile.is_some() {
        NetworkRule::Seatbelt
    } else {
        NetworkRule::None
    };
    Ok(RunNetwork {
        env,
        rule,
        sandbox_profile,
        ca_file,
        _dir: dir,
    })
}

/// The Seatbelt profile of a proxied run: each outgoing connection, also to a Unix
/// socket and to another loopback port, is denied, except the one to the proxy.
#[cfg(target_os = "macos")]
fn sandbox_profile(port: u16) -> Option<String> {
    Some(format!(
        "(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip \"localhost:{port}\"))\n"
    ))
}

#[cfg(not(target_os = "macos"))]
fn sandbox_profile(_port: u16) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_follows_the_sandbox_profile() {
        let pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";
        let url = "http://apassy:secret@127.0.0.1:4100";
        let enforced = network_for(pem, url, 4100, true).expect("network");
        assert_eq!(
            enforced.rule == NetworkRule::Seatbelt,
            enforced.sandbox_profile.is_some()
        );
        assert_eq!(
            enforced.rule,
            if cfg!(target_os = "macos") {
                NetworkRule::Seatbelt
            } else {
                NetworkRule::None
            }
        );
        let open = network_for(pem, url, 4100, false).expect("network");
        assert_eq!(open.rule, NetworkRule::None);
        assert!(open.sandbox_profile.is_none());
        assert_eq!(std::fs::read_to_string(&open.ca_file).expect("ca"), pem);
        assert_eq!(
            serde_json::to_value([NetworkRule::Seatbelt, NetworkRule::Netns, NetworkRule::None])
                .expect("json"),
            serde_json::json!(["seatbelt", "netns", "none"])
        );
        assert_eq!(NetworkRule::Netns.as_str(), "netns");
    }
}
