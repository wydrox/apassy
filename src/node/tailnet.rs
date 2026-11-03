//! The tailnet route of the Mac's node (ADR 0037 stage 2; plan
//! `docs/design/implementation-plan-s2-s3.md`, unit N4, decisions D1, D2, D6).
//!
//! With the route on, the node also serves the devices of the vault (the iPhone, the
//! Apple Watch, other Macs) on the tailnet:
//!
//! - The **node origin** is `https://<Tailscale IPv4>:<port>` (port 8444 unless the owner
//!   changed it before the first pairing). Every device stores it, signs it at sign-in,
//!   and shows it. The MagicDNS name and the Tailscale IPv6 address are alternative
//!   destinations of a pairing link ([`TailnetHere::alternatives`]).
//! - The relay of the node serves the device routes on a third loopback listener
//!   (`RunningNode::tailnet_addr`). The **TLS front** (`crate::net::tls_front`) binds only
//!   the tailnet addresses of this Mac and pumps bytes to that listener. It never binds
//!   `0.0.0.0` or `::`. It follows address changes within 10 s
//!   ([`FrontHandle::follow`]).
//! - When no interface of this Mac has the Tailscale address (a Tailscale variant that
//!   routes in user space), the front binds `127.0.0.1` and Tailscale Serve in TCP mode
//!   forwards the tailnet port to it ([`FrontRoute::ServeTcp`], the plan's first risk).
//!   Serve in TCP mode does not end TLS: the pin holds end to end. Every peer then looks
//!   like `127.0.0.1`, so the per-peer limits equal the total limits ([`front_limits`]).
//! - The Mac's own clients (the questions worker, the feed, the access requests) reach
//!   the node over the loopback without TLS: the route sets the **local route** of the
//!   node origin (`crate::sync::relay_http::set_local_route`), and the requests still
//!   sign the node origin. So the questions worker does not change.
//!
//! [`TailnetRoute`] is the running route. Its stop is in two steps, around the stop of the
//! relay: [`TailnetRoute::stop_front`] first (the listeners close, every connection
//! ends, the Serve forward goes off), then the caller stops the relay (every session and
//! run key goes), then [`TailnetRoute::finish`] clears the local route.
//!
//! Tailscale identity is never authorization (ADR 0037 §3): a peer still signs in with
//! its device key, and only the owner adds a device.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use super::backend::NodeError;
use super::funnel::{self, TailscaleCli};
use crate::net::certificate::{CertificateError, NodeCertificate};
use crate::net::pin::Pin;
use crate::net::tailnet::{self, ServeTcp};
use crate::net::tls_front::{
    DEFAULT_PORT, FOLLOW_INTERVAL, Front, FrontError, FrontHandle, FrontLimits, FrontOptions,
    FrontRoute,
};

/// The push gateway of the Apassy project (contract push-gateway-v1). A node setting:
/// a self-hoster names their own (`Vault::set_cloud_push_gateway`). The relay crate
/// keeps the same text (`apassy_relay::config::DEFAULT_PUSH_GATEWAY`).
pub const DEFAULT_PUSH_GATEWAY: &str = "https://push.apassy.wyderka.cc";
/// The directory of the node certificate in the node directory: `cert.der` and the
/// sealed key `key.sealed` (plan D2).
pub const FRONT_DIR: &str = "front";
/// The name of the team of devices that carries the questions of a vault on the node.
pub const QUESTIONS_TEAM_NAME: &str = "Approvals";

/// The port of the node origin when the owner chose none.
pub fn port_or_default(port: Option<u16>) -> u16 {
    port.unwrap_or(DEFAULT_PORT)
}

/// The node origin for `ipv4` and `port`: `https://100.64.0.7:8444`.
pub fn node_origin(ipv4: Ipv4Addr, port: u16) -> String {
    format!("https://{ipv4}:{port}")
}

/// The tailnet of this Mac now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailnetHere {
    /// The host of the node origin.
    pub ipv4: Ipv4Addr,
    /// The addresses the front binds ([`FrontRoute::Direct`]): the Tailscale addresses
    /// that an interface of this Mac has. Empty for [`FrontRoute::ServeTcp`].
    pub addresses: Vec<IpAddr>,
    /// The MagicDNS name, without the last dot.
    pub dns_name: Option<String>,
    /// The Tailscale IPv6 address, when the front can be reached on it.
    pub ipv6: Option<Ipv6Addr>,
    pub route: FrontRoute,
    /// Tests only: `127.0.0.1` stands in for the tailnet address.
    pub test_loopback: bool,
}

impl TailnetHere {
    /// The stand-in of the tests: `127.0.0.1` is the tailnet address, and the front binds
    /// and admits the loopback.
    pub fn test_loopback() -> Self {
        Self {
            ipv4: Ipv4Addr::LOCALHOST,
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            dns_name: None,
            ipv6: None,
            route: FrontRoute::Direct,
            test_loopback: true,
        }
    }

    /// The node origin on `port`.
    pub fn origin(&self, port: u16) -> String {
        node_origin(self.ipv4, port)
    }

    /// The alternative destinations of a pairing link (node-pairing-v1 section 7), with
    /// the port written: the MagicDNS name, then the IPv6 address in brackets. A name of
    /// one label is left out (the link grammar needs two).
    pub fn alternatives(&self, port: u16) -> Vec<String> {
        let mut list = Vec::new();
        if let Some(name) = &self.dns_name
            && name.contains('.')
        {
            list.push(format!("{name}:{port}"));
        }
        if let Some(v6) = self.ipv6 {
            list.push(format!("[{v6}]:{port}"));
        }
        list
    }
}

/// The tailnet of this Mac through `cli` (`tailscale status --json`), or why there is
/// none: `no_tailscale`, `tailscale_not_connected`, or `tailscale_no_address`.
pub fn find(cli: &dyn TailscaleCli) -> Result<TailnetHere, NodeError> {
    let Some(output) = cli.run(&["status", "--json"]) else {
        return Err(NodeError::new(
            "no_tailscale",
            "Tailscale is not installed on this Mac. Install it from tailscale.com, then sign in.",
        ));
    };
    if !output.success {
        return Err(NodeError::new(
            "tailscale_not_connected",
            "Tailscale did not answer. Open Tailscale and connect.",
        ));
    }
    find_in(&output.stdout, tailnet::assigned)
}

/// [`find`] for the text of `tailscale status --json` and `assigned` (the addresses that
/// an interface of this Mac has; tests give their own).
pub fn find_in(
    status_json: &str,
    assigned: impl Fn(&[IpAddr]) -> Vec<IpAddr>,
) -> Result<TailnetHere, NodeError> {
    let status = tailnet::parse_status(status_json);
    if !status.running {
        let state = match funnel::parse_status(status_json) {
            funnel::Tailscale::NotConnected { state } => state,
            _ => "not running".to_owned(),
        };
        return Err(NodeError::new(
            "tailscale_not_connected",
            format!("Tailscale is not connected ({state}). Open Tailscale and connect."),
        ));
    }
    let ipv4 = status.ipv4().ok_or_else(|| {
        NodeError::new(
            "tailscale_no_address",
            "Tailscale gives this Mac no IPv4 address.",
        )
    })?;
    let dns_name = match funnel::parse_status(status_json) {
        funnel::Tailscale::Connected { dns_name } => Some(dns_name),
        _ => None,
    };
    let addresses = tailnet::addresses(&status, &assigned(&status.ips));
    if addresses.contains(&IpAddr::V4(ipv4)) {
        let ipv6 = status
            .ipv6()
            .filter(|v6| addresses.contains(&IpAddr::V6(*v6)));
        Ok(TailnetHere {
            ipv4,
            addresses,
            dns_name,
            ipv6,
            route: FrontRoute::Direct,
            test_loopback: false,
        })
    } else {
        // No interface has the address: Tailscale Serve forwards the port (plan, risk 2).
        Ok(TailnetHere {
            ipv4,
            addresses: Vec::new(),
            dns_name,
            ipv6: status.ipv6(),
            route: FrontRoute::ServeTcp,
            test_loopback: false,
        })
    }
}

/// The limits of the front for `route`: plan D2's numbers. With
/// [`FrontRoute::ServeTcp`] every peer is Tailscale's daemon on `127.0.0.1`, so the
/// per-peer limits are the total limits: 64 connections, and the new connections of the
/// eight peers that the total admits.
pub fn front_limits(route: FrontRoute) -> FrontLimits {
    let limits = FrontLimits::default();
    match route {
        FrontRoute::Direct => limits,
        FrontRoute::ServeTcp => {
            let peers = (limits.max_connections / limits.max_per_peer.max(1)).max(1);
            FrontLimits {
                max_per_peer: limits.max_connections,
                new_per_peer_per_minute: limits.new_per_peer_per_minute.saturating_mul(peers),
                ..limits
            }
        }
    }
}

/// The limits of the tests: one connection per request, more than a real peer makes.
fn test_limits() -> FrontLimits {
    FrontLimits {
        max_connections: 256,
        max_per_peer: 256,
        new_per_peer_per_minute: 100_000,
        ..FrontLimits::default()
    }
}

/// The pin as six words for a visual check (Settings > Devices on the Mac and on the
/// iPhone): `WORDS[pin[0]]` to `WORDS[pin[5]]` of the relay-sync-v1 list (section 16),
/// one space between them. The pin is the SHA-256 of the certificate, so the words
/// change with the certificate. They are a check for a person, never the trust: the
/// client compares the whole pin.
pub fn pin_words(pin: &Pin) -> String {
    let bytes = pin.as_bytes();
    bytes[..6]
        .iter()
        .map(|byte| crate::sync::relay_crypto::WORDS[usize::from(*byte)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// The node certificate of `node_dir` (`front/`), made at the first start. A certificate
/// whose key does not open with `master_key` (the node key is new) is replaced: the pin
/// changes and every device pairs again. Returns the certificate and whether it is new.
pub fn certificate(
    node_dir: &Path,
    master_key: &[u8],
    machine_name: &str,
) -> Result<(NodeCertificate, bool), NodeError> {
    let dir = node_dir.join(FRONT_DIR);
    let had = dir.join(crate::net::certificate::CERT_FILE).is_file();
    let failed = |error: CertificateError| {
        NodeError::new(
            "node_failed",
            format!("The node certificate cannot be made: {error}"),
        )
    };
    match NodeCertificate::load_or_make(&dir, master_key, machine_name) {
        Ok(certificate) => Ok((certificate, !had)),
        Err(CertificateError::Unreadable) => {
            NodeCertificate::replace(&dir, master_key, machine_name)
                .map(|certificate| (certificate, true))
                .map_err(failed)
        }
        Err(error) => Err(failed(error)),
    }
}

fn front_error(error: &FrontError, port: u16) -> NodeError {
    match error {
        FrontError::Bind(_) => NodeError::new(
            "tailnet_port_taken",
            format!(
                "Port {port} on the tailnet address of this Mac is taken: {error}. Choose another port before the first pairing."
            ),
        ),
        other => NodeError::new(
            "node_failed",
            format!("The TLS front of the node did not start: {other}"),
        ),
    }
}

/// What [`TailnetRoute::start`] needs.
pub struct RouteOptions<'a> {
    pub here: &'a TailnetHere,
    /// The port of the node origin.
    pub port: u16,
    pub certificate: NodeCertificate,
    /// The relay's tailnet listener on the loopback (`RunningNode::tailnet_addr`).
    pub target: SocketAddr,
    pub cli: Arc<dyn TailscaleCli>,
    /// The node's display name of the pairing links.
    pub name: String,
}

/// The running tailnet route: the front, the Serve forward of the fallback, and the
/// local route. Drop stops the front and clears the local route.
pub struct TailnetRoute {
    front: Option<FrontHandle>,
    /// The Serve TCP forward: the tailnet port and the local port of the front.
    serve_tcp: Option<(u16, u16)>,
    cli: Arc<dyn TailscaleCli>,
    local_route: bool,
    /// The node origin, the value that every device stores and signs.
    pub origin: String,
    pub port: u16,
    pub pin: Pin,
    /// The alternative destinations of the pairing links.
    pub alt: Vec<String>,
    /// The node's display name of the pairing links.
    pub name: String,
    pub route: FrontRoute,
    /// The relay's tailnet listener: the front's target and the local route.
    pub target: SocketAddr,
}

impl std::fmt::Debug for TailnetRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TailnetRoute")
            .field("origin", &self.origin)
            .field("pin", &self.pin)
            .field("route", &self.route)
            .field("bound", &self.bound())
            .finish_non_exhaustive()
    }
}

impl TailnetRoute {
    /// Start the front on the tailnet of `options.here` (or on `127.0.0.1` with the Serve
    /// forward), follow the address changes, and set the local route of the origin. On an
    /// error nothing of the route is left.
    pub fn start(options: RouteOptions<'_>) -> Result<Self, NodeError> {
        let RouteOptions {
            here,
            port,
            certificate,
            target,
            cli,
            name,
        } = options;
        let pin = certificate.pin;
        let origin = here.origin(port);
        let mut front_options =
            FrontOptions::new(here.addresses.clone(), port, certificate, target);
        front_options.route = here.route;
        front_options.limits = front_limits(here.route);
        if here.test_loopback {
            front_options.allow_loopback_bind = true;
            front_options.allow_test_peers = true;
            front_options.limits = test_limits();
        }
        if here.route == FrontRoute::ServeTcp {
            // The front takes any free port on 127.0.0.1; Serve forwards the tailnet port.
            front_options.port = 0;
        }
        let mut front = Front::start(front_options).map_err(|error| front_error(&error, port))?;
        let mut serve_tcp = None;
        match here.route {
            FrontRoute::Direct if !here.test_loopback => {
                // A failed follow thread leaves the front on its first addresses: the route
                // check of the node (`Node::maintain`) restarts it after a change.
                let _ = front.follow(tailnet::system_addresses, FOLLOW_INTERVAL);
            }
            FrontRoute::Direct => {}
            FrontRoute::ServeTcp => {
                let local_port = front.bound().first().map_or(0, SocketAddr::port);
                if let Err(error) = ServeTcp::new(Arc::clone(&cli)).enable(port, local_port) {
                    front.stop();
                    return Err(NodeError::new(
                        "tailnet_serve_failed",
                        format!("Tailscale Serve did not forward port {port} to the node: {error}"),
                    ));
                }
                serve_tcp = Some((port, local_port));
            }
        }
        let mut route = Self {
            front: Some(front),
            serve_tcp,
            cli,
            local_route: false,
            alt: if here.test_loopback {
                Vec::new()
            } else {
                here.alternatives(port)
            },
            origin,
            port,
            pin,
            name,
            route: here.route,
            target,
        };
        if crate::sync::relay_http::set_local_route(&route.origin, target).is_err() {
            route.stop_front();
            return Err(NodeError::new(
                "node_failed",
                "The node origin cannot be routed to the node on this Mac.",
            ));
        }
        route.local_route = true;
        Ok(route)
    }

    /// The addresses that the front listens on now.
    pub fn bound(&self) -> Vec<SocketAddr> {
        self.front
            .as_ref()
            .map(FrontHandle::bound)
            .unwrap_or_default()
    }

    /// True while the front runs.
    pub fn front_running(&self) -> bool {
        self.front.is_some()
    }

    /// The first step of a stop: the front (its listeners close, every connection ends,
    /// its key goes), then the Serve forward. The local route stays until [`Self::finish`].
    pub fn stop_front(&mut self) {
        if let Some(mut front) = self.front.take() {
            front.stop();
        }
        if let Some((port, local_port)) = self.serve_tcp.take() {
            let _ = ServeTcp::new(Arc::clone(&self.cli)).disable(port, local_port);
        }
    }

    /// The last step of a stop, after the relay stopped: the local route of the origin
    /// goes.
    pub fn finish(mut self) {
        self.stop_front();
        self.clear_route();
    }

    fn clear_route(&mut self) {
        if self.local_route {
            crate::sync::relay_http::clear_local_route(&self.origin);
            self.local_route = false;
        }
    }
}

impl Drop for TailnetRoute {
    fn drop(&mut self) {
        self.stop_front();
        self.clear_route();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(addresses: &[&str]) -> String {
        serde_json::json!({
            "BackendState": "Running",
            "Self": {"DNSName": "apassy-mini.tail0123.ts.net.", "TailscaleIPs": addresses},
        })
        .to_string()
    }

    #[test]
    fn an_assigned_address_gives_the_direct_route_and_the_alternatives() {
        let json = status(&["100.64.0.7", "fd7a:115c:a1e0::7"]);
        let here = find_in(&json, |ips| ips.to_vec()).unwrap();
        assert_eq!(here.route, FrontRoute::Direct);
        assert_eq!(here.ipv4, Ipv4Addr::new(100, 64, 0, 7));
        assert_eq!(here.origin(8444), "https://100.64.0.7:8444");
        assert_eq!(
            here.alternatives(8444),
            vec![
                "apassy-mini.tail0123.ts.net:8444".to_owned(),
                "[fd7a:115c:a1e0::7]:8444".to_owned()
            ]
        );
        // Never the unspecified addresses.
        assert!(here.addresses.iter().all(|ip| !ip.is_unspecified()));
    }

    #[test]
    fn no_assigned_address_falls_back_to_serve_tcp() {
        let json = status(&["100.64.0.7"]);
        let here = find_in(&json, |_| Vec::new()).unwrap();
        assert_eq!(here.route, FrontRoute::ServeTcp);
        assert!(here.addresses.is_empty());
        assert_eq!(here.origin(8444), "https://100.64.0.7:8444");
    }

    #[test]
    fn a_stopped_tailscale_says_why() {
        let stopped = find_in(
            r#"{"BackendState":"NeedsLogin","Self":{"DNSName":""}}"#,
            |ips| ips.to_vec(),
        )
        .unwrap_err();
        assert_eq!(stopped.code, "tailscale_not_connected");
        assert!(
            stopped.message.contains("NeedsLogin"),
            "{}",
            stopped.message
        );
        let no_v4 = find_in(&status(&["fd7a:115c:a1e0::7"]), |ips| ips.to_vec()).unwrap_err();
        assert_eq!(no_v4.code, "tailscale_no_address");
    }

    #[test]
    fn serve_tcp_limits_per_peer_equal_the_total() {
        let direct = front_limits(FrontRoute::Direct);
        assert_eq!(direct, FrontLimits::default());
        let serve = front_limits(FrontRoute::ServeTcp);
        assert_eq!(serve.max_per_peer, serve.max_connections);
        assert_eq!(serve.max_connections, direct.max_connections);
        assert_eq!(
            serve.new_per_peer_per_minute,
            direct.new_per_peer_per_minute * (direct.max_connections / direct.max_per_peer)
        );
        assert_eq!(serve.handshake, direct.handshake);
        assert_eq!(serve.idle, direct.idle);
    }

    #[test]
    fn pin_words_are_six_words_of_the_list_and_follow_the_pin() {
        let a = Pin::of_certificate(b"synthetic certificate a");
        let b = Pin::of_certificate(b"synthetic certificate b");
        let words = pin_words(&a);
        assert_eq!(words.split(' ').count(), 6, "{words}");
        for word in words.split(' ') {
            assert!(crate::sync::relay_crypto::WORDS.contains(&word), "{word}");
        }
        assert_eq!(words, pin_words(&a));
        assert_ne!(words, pin_words(&b));
        let first = crate::sync::relay_crypto::WORDS[usize::from(a.as_bytes()[0])];
        assert!(words.starts_with(first));
    }

    #[test]
    fn the_test_route_binds_the_loopback_sets_the_local_route_and_clears_it_last() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let (cert, new) = certificate(dir.path(), &key, "Synthetic Mac").unwrap();
        assert!(new);
        let pin = cert.pin;
        // The same key opens the same certificate; another key makes a new one.
        let (again, new) = certificate(dir.path(), &key, "Synthetic Mac").unwrap();
        assert!(!new);
        assert_eq!(again.pin, pin);
        let target = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target_addr = target.local_addr().unwrap();
        let port = {
            let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            probe.local_addr().unwrap().port()
        };
        let here = TailnetHere::test_loopback();
        let cli: Arc<dyn TailscaleCli> = Arc::new(super::super::funnel::tests::FakeCli::connected(
            super::super::funnel::tests::serve_443_only(),
        ));
        let mut route = TailnetRoute::start(RouteOptions {
            here: &here,
            port,
            certificate: again,
            target: target_addr,
            cli,
            name: "Synthetic Mac".to_owned(),
        })
        .unwrap();
        assert_eq!(route.origin, format!("https://127.0.0.1:{port}"));
        assert_eq!(route.pin, pin);
        assert!(route.alt.is_empty());
        assert_eq!(
            route.bound(),
            vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))]
        );
        // The local route goes to the relay's listener, plain.
        let url = crate::sync::RelayUrl::parse(&route.origin).unwrap();
        assert_eq!(
            crate::sync::relay_http::local_route_for_test(&url),
            Some(target_addr)
        );
        route.stop_front();
        assert!(!route.front_running());
        assert!(route.bound().is_empty());
        // The front is gone; the local route stays until the relay stopped.
        assert!(std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
        assert_eq!(
            crate::sync::relay_http::local_route_for_test(&url),
            Some(target_addr)
        );
        route.finish();
        assert_eq!(crate::sync::relay_http::local_route_for_test(&url), None);
        let (_, replaced) = certificate(dir.path(), &[9u8; 32], "Synthetic Mac").unwrap();
        assert!(replaced, "a new node key makes a new certificate");
    }
}
