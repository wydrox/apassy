//! The parts of tsnet's JSON answers that Apassy reads: `ipnstate.Status` (status) and
//! `apitype.WhoIsResponse` (WhoIs). Unknown fields are ignored; a missing field is
//! empty.

use std::fmt;
use std::net::IpAddr;

use serde::Deserialize;

use crate::{Error, Result};

/// The node's state (`ipnstate.Status`).
#[derive(Clone, PartialEq, Eq)]
pub struct Status {
    /// "NoState", "NeedsLogin", "NeedsMachineAuth", "Stopped", "Starting", or "Running".
    pub backend_state: String,
    /// The login URL of a node that needs a login (no auth key, or an expired one).
    /// Whoever opens it can add the node to their tailnet: never log it.
    pub auth_url: Option<String>,
    pub tailscale_ips: Vec<IpAddr>,
    /// The node's MagicDNS name, with the trailing dot.
    pub dns_name: Option<String>,
    /// The node's stable ID ("n…CNTRL"), the device ID of the Tailscale API.
    pub stable_id: Option<String>,
    pub tailnet: Option<String>,
    pub magic_dns_suffix: Option<String>,
    pub health: Vec<String>,
    pub peers: usize,
    pub version: Option<String>,
}

impl Status {
    pub fn is_running(&self) -> bool {
        self.backend_state == "Running"
    }

    pub(crate) fn parse(json: &str) -> Result<Self> {
        let raw: RawStatus = serde_json::from_str(json).map_err(|error| Error::Json {
            what: "status",
            message: error.to_string(),
        })?;
        let me = raw.self_status.unwrap_or_default();
        let tailnet = raw.current_tailnet.unwrap_or_default();
        Ok(Self {
            backend_state: raw.backend_state,
            auth_url: non_empty(raw.auth_url),
            tailscale_ips: raw
                .tailscale_ips
                .unwrap_or_default()
                .iter()
                .filter_map(|ip| ip.parse().ok())
                .collect(),
            dns_name: non_empty(me.dns_name),
            stable_id: non_empty(me.id),
            tailnet: non_empty(tailnet.name),
            magic_dns_suffix: non_empty(raw.magic_dns_suffix)
                .or_else(|| non_empty(tailnet.magic_dns_suffix)),
            health: raw.health.unwrap_or_default(),
            peers: raw.peer.map(|peers| peers.len()).unwrap_or(0),
            version: non_empty(raw.version),
        })
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Status")
            .field("backend_state", &self.backend_state)
            .field("auth_url", &self.auth_url.as_ref().map(|_| "<login URL>"))
            .field("tailscale_ips", &self.tailscale_ips)
            .field("dns_name", &self.dns_name)
            .field("stable_id", &self.stable_id)
            .field("tailnet", &self.tailnet)
            .field("magic_dns_suffix", &self.magic_dns_suffix)
            .field("health", &self.health)
            .field("peers", &self.peers)
            .field("version", &self.version)
            .finish()
    }
}

/// The owner of a tailnet address (`apitype.WhoIsResponse`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The node's MagicDNS name, with the trailing dot.
    pub node_name: String,
    pub stable_id: String,
    /// The user's login, for example "konrad@example.com"; for a tagged node, the
    /// placeholder user of tagged devices.
    pub login_name: Option<String>,
    pub display_name: Option<String>,
    pub tags: Vec<String>,
    /// The node's addresses as prefixes, for example "100.64.0.7/32".
    pub addresses: Vec<String>,
}

impl Peer {
    pub(crate) fn parse(json: &str) -> Result<Self> {
        let raw: RawWhoIs = serde_json::from_str(json).map_err(|error| Error::Json {
            what: "WhoIs",
            message: error.to_string(),
        })?;
        let node = raw.node.unwrap_or_default();
        let user = raw.user_profile.unwrap_or_default();
        Ok(Self {
            node_name: node.name,
            stable_id: node.stable_id,
            login_name: non_empty(user.login_name),
            display_name: non_empty(user.display_name),
            tags: node.tags.unwrap_or_default(),
            addresses: node.addresses.unwrap_or_default(),
        })
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawStatus {
    #[serde(default)]
    version: String,
    #[serde(default)]
    backend_state: String,
    #[serde(default, rename = "AuthURL")]
    auth_url: String,
    #[serde(default, rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(default, rename = "Self")]
    self_status: Option<RawPeerStatus>,
    #[serde(default)]
    health: Option<Vec<String>>,
    #[serde(default, rename = "MagicDNSSuffix")]
    magic_dns_suffix: String,
    #[serde(default)]
    current_tailnet: Option<RawTailnet>,
    #[serde(default)]
    peer: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Default, Deserialize)]
struct RawPeerStatus {
    #[serde(default, rename = "ID")]
    id: String,
    #[serde(default, rename = "DNSName")]
    dns_name: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawTailnet {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "MagicDNSSuffix")]
    magic_dns_suffix: String,
}

#[derive(Deserialize)]
struct RawWhoIs {
    #[serde(default, rename = "Node")]
    node: Option<RawNode>,
    #[serde(default, rename = "UserProfile")]
    user_profile: Option<RawUser>,
}

#[derive(Default, Deserialize)]
struct RawNode {
    #[serde(default, rename = "Name")]
    name: String,
    #[serde(default, rename = "StableID")]
    stable_id: String,
    #[serde(default, rename = "Tags")]
    tags: Option<Vec<String>>,
    #[serde(default, rename = "Addresses")]
    addresses: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
struct RawUser {
    #[serde(default, rename = "LoginName")]
    login_name: String,
    #[serde(default, rename = "DisplayName")]
    display_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_status_parses_and_hides_the_login_url() {
        let status = Status::parse(
            r#"{"Version":"1.104.1","BackendState":"Running","AuthURL":"https://login.tailscale.com/a/x",
               "TailscaleIPs":["100.64.0.7","fd7a:115c:a1e0::7"],
               "Self":{"ID":"nAbc1CNTRL","DNSName":"apassy-team-acme.tail1.ts.net.","HostName":"apassy-team-acme"},
               "Health":null,"MagicDNSSuffix":"tail1.ts.net",
               "CurrentTailnet":{"Name":"rafal@example.com","MagicDNSSuffix":"tail1.ts.net"},
               "Peer":{"k1":{},"k2":{}}}"#,
        )
        .unwrap();
        assert!(status.is_running());
        assert_eq!(status.tailscale_ips.len(), 2);
        assert_eq!(status.stable_id.as_deref(), Some("nAbc1CNTRL"));
        assert_eq!(status.peers, 2);
        assert!(status.health.is_empty());
        assert!(!format!("{status:?}").contains("login.tailscale.com"));
    }

    #[test]
    fn a_starting_status_with_nulls_parses() {
        let status = Status::parse(
            r#"{"BackendState":"NeedsLogin","TailscaleIPs":null,"Self":null,"Peer":null}"#,
        )
        .unwrap();
        assert!(!status.is_running());
        assert!(status.tailscale_ips.is_empty() && status.auth_url.is_none());
    }

    #[test]
    fn a_whois_answer_parses() {
        let peer = Peer::parse(
            r#"{"Node":{"ID":7,"StableID":"nB2CNTRL","Name":"konrad-mac.tail2.ts.net.",
                "Addresses":["100.64.0.9/32"],"Tags":null},
               "UserProfile":{"ID":3,"LoginName":"konrad@example.com","DisplayName":"Konrad"},
               "CapMap":null}"#,
        )
        .unwrap();
        assert_eq!(peer.login_name.as_deref(), Some("konrad@example.com"));
        assert_eq!(peer.node_name, "konrad-mac.tail2.ts.net.");
        assert!(peer.tags.is_empty());
    }
}
