//! The tailnet addresses of this machine (ADR 0037 §2, plan N2).
//!
//! Tailscale gives each node an IPv4 address in `100.64.0.0/10` and an IPv6 address in
//! `fd7a:115c:a1e0::/48`. The TLS front binds only addresses that pass two checks:
//!
//! 1. the running daemon names them in `Self.TailscaleIPs` of `tailscale status --json`
//!    (`BackendState` is `Running`), and they are in one of the two ranges;
//! 2. they are assigned to an interface of this machine. A userspace-only Tailscale
//!    can report a `Self` address that no interface has; nothing can listen there.
//!
//! A CGNAT address alone does not identify Tailscale (a carrier can use `100.64/10`), so
//! an address is never taken from the interfaces alone. `0.0.0.0` and `::` are never
//! a result.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

use serde_json::Value;

/// Only known installation paths are used. The process environment cannot select a
/// different executable through PATH. The companion's link hosts and the Funnel route
/// of the node use the same paths (`crate::companion::hosts`, `crate::node::funnel`).
pub const TAILSCALE_PROGRAMS: [&str; 4] = [
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
    "/usr/bin/tailscale",
];

/// The Tailscale IPv6 prefix, `fd7a:115c:a1e0::/48`, as its first three segments.
const TAILNET_V6_PREFIX: [u16; 3] = [0xfd7a, 0x115c, 0xa1e0];

/// True for an IPv4 address in `100.64.0.0/10`.
pub fn is_tailnet_v4(address: Ipv4Addr) -> bool {
    let [first, second, _, _] = address.octets();
    first == 100 && (64..=127).contains(&second)
}

/// True for an IPv6 address in `fd7a:115c:a1e0::/48`.
pub fn is_tailnet_v6(address: Ipv6Addr) -> bool {
    address.segments()[..3] == TAILNET_V6_PREFIX
}

/// True when `ip` is in one of the two Tailscale ranges. An IPv4-mapped IPv6 address
/// counts as its IPv4 address, as the accept loop sees peers on a dual-stack socket.
pub fn is_tailnet_peer(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_tailnet_v4(v4),
        IpAddr::V6(v6) => is_tailnet_v6(v6),
    }
}

/// What `tailscale status --json` says about this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleSelf {
    /// `BackendState` is `Running`.
    pub running: bool,
    /// The addresses of `Self.TailscaleIPs` in the two ranges, IPv4 first, in the order
    /// of the status, without duplicates. Empty when not running.
    pub ips: Vec<IpAddr>,
}

impl TailscaleSelf {
    /// The first Tailscale IPv4 address: the host of the node origin (plan D1).
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ips.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
    }

    /// The first Tailscale IPv6 address: an alternative destination.
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ips.iter().find_map(|ip| match ip {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        })
    }
}

/// Parse `tailscale status --json`. Malformed text, a missing `Self`, or a state other
/// than `Running` gives no address. An entry that is not a plain address (with a port,
/// a zone, a prefix length) or that is outside the ranges is skipped.
pub fn parse_status(json: &str) -> TailscaleSelf {
    let Ok(status) = serde_json::from_str::<Value>(json) else {
        return TailscaleSelf::default();
    };
    if status.get("BackendState").and_then(Value::as_str) != Some("Running") {
        return TailscaleSelf::default();
    }
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let entries = status
        .get("Self")
        .and_then(|me| me.get("TailscaleIPs"))
        .and_then(Value::as_array);
    for entry in entries.into_iter().flatten() {
        let Some(ip) = entry.as_str().and_then(|text| text.parse::<IpAddr>().ok()) else {
            continue;
        };
        match ip {
            IpAddr::V4(address) if is_tailnet_v4(address) && !v4.contains(&ip) => v4.push(ip),
            IpAddr::V6(address) if is_tailnet_v6(address) && !v6.contains(&ip) => v6.push(ip),
            _ => {}
        }
    }
    v4.extend(v6);
    TailscaleSelf {
        running: true,
        ips: v4,
    }
}

/// The addresses the front may bind: the Tailscale addresses of `status` that are also
/// among `interfaces` (the addresses assigned to this machine). The order is the order
/// of `status`: IPv4 first.
pub fn addresses(status: &TailscaleSelf, interfaces: &[IpAddr]) -> Vec<IpAddr> {
    status
        .ips
        .iter()
        .copied()
        .filter(|ip| is_tailnet_peer(*ip) && !ip.is_unspecified())
        .filter(|ip| interfaces.contains(ip))
        .collect()
}

/// The addresses among `candidates` that an interface of this machine has. Binding a
/// UDP socket works only for an address of the host; it sends no packet and frees the
/// port at once. This works on macOS (the `utun` of Tailscale, also the App Store
/// variant) and on Linux (`tailscale0`) without reading interface tables.
pub fn assigned(candidates: &[IpAddr]) -> Vec<IpAddr> {
    candidates
        .iter()
        .copied()
        .filter(|ip| !ip.is_unspecified() && UdpSocket::bind((*ip, 0)).is_ok())
        .collect()
}

/// The tailnet addresses of this machine now: `tailscale status --json` from the first
/// known program that answers, checked against the interfaces. `run` runs one program
/// with arguments and gives its standard output, or `None`.
pub fn discover(mut run: impl FnMut(&str, &[&str]) -> Option<String>) -> Vec<IpAddr> {
    for program in TAILSCALE_PROGRAMS {
        let Some(output) = run(program, &["status", "--json"]) else {
            continue;
        };
        let status = parse_status(&output);
        if !status.running {
            continue;
        }
        let found = addresses(&status, &assigned(&status.ips));
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

/// [`discover`] with the system's Tailscale command line (10 s limit, 1 MiB of output).
pub fn system_addresses() -> Vec<IpAddr> {
    use crate::node::funnel::{SystemTailscale, TailscaleCli};
    let output = SystemTailscale.run(&["status", "--json"]);
    match output {
        Some(output) if output.success => {
            let status = parse_status(&output.stdout);
            addresses(&status, &assigned(&status.ips))
        }
        _ => Vec::new(),
    }
}

/// What Tailscale Serve does with one TCP port of the tailnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeTcpState {
    Free,
    /// Our forward: plain TCP to `127.0.0.1:<front port>`, TLS not ended by Serve, no
    /// Funnel.
    Ours,
    /// Something else: another program's forward, an HTTP(S) handler, a forward that
    /// ends TLS, or Funnel.
    Other {
        target: String,
    },
}

/// Why the Serve forward is not on or not off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeTcpError {
    /// No Tailscale command line at the known paths.
    NoTailscale,
    /// The port is 443 or a Funnel port; the app never touches them.
    Forbidden(u16),
    /// The local port is not a port.
    BadLocalPort,
    /// The port serves something else. The app does not change it.
    Taken { target: String },
    /// `tailscale serve status --json` cannot be read.
    Unreadable(String),
    /// The command failed.
    Failed(String),
}

impl std::fmt::Display for ServeTcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTailscale => f.write_str("Install Tailscale and sign in."),
            Self::Forbidden(port) => {
                write!(f, "Apassy never changes port {port} of Tailscale Serve.")
            }
            Self::BadLocalPort => f.write_str("The front has no loopback port."),
            Self::Taken { target } => write!(
                f,
                "This port of Tailscale Serve already serves {target}. Apassy does not change it."
            ),
            Self::Unreadable(why) => {
                write!(f, "Apassy cannot read the Tailscale Serve state: {why}")
            }
            Self::Failed(why) => write!(f, "Tailscale did not change the forward: {why}"),
        }
    }
}

impl std::error::Error for ServeTcpError {}

/// The Serve target of the front: `127.0.0.1:<port>`.
pub fn serve_tcp_target(local_port: u16) -> String {
    format!("127.0.0.1:{local_port}")
}

fn port_entry(map: Option<&Value>, port: u16) -> Option<&Value> {
    map.and_then(Value::as_object)?
        .iter()
        .find_map(|(key, value)| {
            (key == &port.to_string() || key.ends_with(&format!(":{port}"))).then_some(value)
        })
}

/// Parse `tailscale serve status --json` for the TCP `port`. `own_target` is
/// [`serve_tcp_target`] of the front. The background config and each foreground config
/// count; a port with Funnel on is never ours.
pub fn parse_serve_tcp(json: &str, port: u16, own_target: &str) -> Result<ServeTcpState, String> {
    let trimmed = json.trim();
    // An empty Serve config prints nothing or `{}`.
    if trimmed.is_empty() {
        return Ok(ServeTcpState::Free);
    }
    let root: Value = serde_json::from_str(trimmed).map_err(|_| "not JSON".to_owned())?;
    if !root.is_object() {
        return Err("not an object".to_owned());
    }
    let mut configs = vec![&root];
    if let Some(sessions) = root.get("Foreground").and_then(Value::as_object) {
        configs.extend(sessions.values());
    }
    let mut state = ServeTcpState::Free;
    for config in configs {
        let funnel = config
            .get("AllowFunnel")
            .and_then(Value::as_object)
            .is_some_and(|map| {
                map.iter().any(|(key, on)| {
                    key.ends_with(&format!(":{port}")) && on.as_bool() == Some(true)
                })
            });
        let web = port_entry(config.get("Web"), port).is_some();
        let Some(entry) = port_entry(config.get("TCP"), port) else {
            if funnel || web {
                return Ok(ServeTcpState::Other {
                    target: "a web handler".to_owned(),
                });
            }
            continue;
        };
        let forward = entry.get("TCPForward").and_then(Value::as_str);
        let plain_tcp = entry.get("HTTPS").is_none()
            && entry.get("HTTP").is_none()
            && entry
                .get("TerminateTLS")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty);
        match forward {
            Some(target) if target == own_target && plain_tcp && !funnel && !web => {
                state = ServeTcpState::Ours;
            }
            Some(target) => {
                return Ok(ServeTcpState::Other {
                    target: target
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(80)
                        .collect(),
                });
            }
            None => {
                return Ok(ServeTcpState::Other {
                    target: "a web handler".to_owned(),
                });
            }
        }
    }
    Ok(state)
}

/// The fallback route of the front (plan, risk 2): Tailscale Serve in TCP mode forwards
/// the tailnet `port` to the front on `127.0.0.1:<local port>`. Serve in TCP mode does
/// not end TLS, so the iPhone still sees the node certificate and checks its pin.
///
/// Commands, and no other: `tailscale serve status --json`,
/// `tailscale serve --bg --tcp=<port> --proxy-protocol=1 tcp://127.0.0.1:<local port>`
/// (and without `--proxy-protocol` when the command line does not know it), and
/// `tailscale serve --tcp=<port> off`. Never `serve reset`. Port 443 and the Funnel ports
/// (8443, 10000) are refused.
///
/// With the PROXY protocol, Serve writes the tailnet peer in a first line, so the front
/// limits each peer (N8-5). Without it every peer is the loopback. Either way the front
/// cannot tell Serve from another process on this machine (docs/security/trust-model.md).
pub struct ServeTcp {
    cli: std::sync::Arc<dyn crate::node::funnel::TailscaleCli>,
}

impl ServeTcp {
    pub fn new(cli: std::sync::Arc<dyn crate::node::funnel::TailscaleCli>) -> Self {
        Self { cli }
    }

    fn check_ports(port: u16, local_port: u16) -> Result<(), ServeTcpError> {
        if matches!(port, 443 | 8443 | 10000) {
            return Err(ServeTcpError::Forbidden(port));
        }
        if local_port == 0 {
            return Err(ServeTcpError::BadLocalPort);
        }
        Ok(())
    }

    /// What `port` serves now.
    pub fn state(&self, port: u16, local_port: u16) -> Result<ServeTcpState, ServeTcpError> {
        Self::check_ports(port, local_port)?;
        let output = self
            .cli
            .run(&["serve", "status", "--json"])
            .ok_or(ServeTcpError::NoTailscale)?;
        if !output.success {
            return Err(ServeTcpError::Unreadable(
                output.stderr.trim().chars().take(200).collect(),
            ));
        }
        parse_serve_tcp(&output.stdout, port, &serve_tcp_target(local_port))
            .map_err(ServeTcpError::Unreadable)
    }

    /// Turn the forward on. A port that serves something else is refused; our forward
    /// is kept as it is. After the command the state must be [`ServeTcpState::Ours`].
    pub fn enable(&self, port: u16, local_port: u16) -> Result<(), ServeTcpError> {
        match self.state(port, local_port)? {
            ServeTcpState::Ours => return Ok(()),
            ServeTcpState::Other { target } => return Err(ServeTcpError::Taken { target }),
            ServeTcpState::Free => {}
        }
        let tcp = format!("--tcp={port}");
        let target = format!("tcp://{}", serve_tcp_target(local_port));
        let mut output = self
            .cli
            .run(&["serve", "--bg", &tcp, "--proxy-protocol=1", &target])
            .ok_or(ServeTcpError::NoTailscale)?;
        if !output.success && output.stderr.contains("proxy-protocol") {
            // A Tailscale before the PROXY protocol: the forward without it.
            output = self
                .cli
                .run(&["serve", "--bg", &tcp, &target])
                .ok_or(ServeTcpError::NoTailscale)?;
        }
        if !output.success {
            return Err(ServeTcpError::Failed(
                output
                    .stderr
                    .trim()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(400)
                    .collect(),
            ));
        }
        match self.state(port, local_port)? {
            ServeTcpState::Ours => Ok(()),
            ServeTcpState::Other { target } => Err(ServeTcpError::Taken { target }),
            ServeTcpState::Free => {
                Err(ServeTcpError::Failed("the forward is not there".to_owned()))
            }
        }
    }

    /// Before the front takes a port: turn off a forward of `port` to the front's earlier
    /// local port `previous`, left by a crash (N8-5). Until then the forward points at a
    /// loopback port that any local process could bind. True when one was turned off.
    /// Another program's forward stays.
    pub fn clear_stale(&self, port: u16, previous: Option<u16>) -> Result<bool, ServeTcpError> {
        match previous {
            Some(previous) if previous != 0 => self.disable(port, previous),
            _ => Ok(false),
        }
    }

    /// Turn our forward off. True when it was on. Another program's forward stays.
    pub fn disable(&self, port: u16, local_port: u16) -> Result<bool, ServeTcpError> {
        if self.state(port, local_port)? != ServeTcpState::Ours {
            return Ok(false);
        }
        let tcp = format!("--tcp={port}");
        let output = self
            .cli
            .run(&["serve", &tcp, "off"])
            .ok_or(ServeTcpError::NoTailscale)?;
        if output.success {
            Ok(true)
        } else {
            Err(ServeTcpError::Failed(
                output
                    .stderr
                    .trim()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(400)
                    .collect(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: &str, addresses: &[&str]) -> String {
        serde_json::json!({
            "BackendState": state,
            "Self": { "TailscaleIPs": addresses },
        })
        .to_string()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    #[test]
    fn the_ranges_are_100_64_slash_10_and_fd7a_115c_a1e0_slash_48() {
        for inside in [
            "100.64.0.0",
            "100.64.0.7",
            "100.127.255.255",
            "fd7a:115c:a1e0::",
            "fd7a:115c:a1e0:ab12:4843:cd96:6258:b240",
            "fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff",
            "::ffff:100.100.1.2",
        ] {
            assert!(is_tailnet_peer(ip(inside)), "{inside}");
        }
        for outside in [
            "100.63.255.255",
            "100.128.0.0",
            "192.168.1.5",
            "10.0.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "::",
            "::1",
            "fd7a:115c:a1e1::1",
            "fd7a:115d:a1e0::1",
            "fe80::1",
            "::ffff:192.168.1.5",
        ] {
            assert!(!is_tailnet_peer(ip(outside)), "{outside}");
        }
    }

    #[test]
    fn the_status_gives_the_running_self_addresses_in_the_ranges_ipv4_first() {
        let parsed = parse_status(&status(
            "Running",
            &[
                "fd7a:115c:a1e0::7",
                "192.168.1.20",
                "100.64.0.7",
                "100.64.0.7",
                "fd7a:115c:a1e0::7",
                "100.64.0.7:8444",
                "fd7a:115c:a1e0::8/128",
                "not-an-address",
            ],
        ));
        assert!(parsed.running);
        assert_eq!(parsed.ips, vec![ip("100.64.0.7"), ip("fd7a:115c:a1e0::7")]);
        assert_eq!(parsed.ipv4(), Some(Ipv4Addr::new(100, 64, 0, 7)));
        assert_eq!(parsed.ipv6(), Some("fd7a:115c:a1e0::7".parse().unwrap()));
    }

    #[test]
    fn a_stopped_absent_or_malformed_status_has_no_address() {
        for text in [
            String::new(),
            "not json".to_owned(),
            "null".to_owned(),
            "{}".to_owned(),
            status("Stopped", &["100.64.0.7"]),
            status("NeedsLogin", &["100.64.0.7"]),
            r#"{"BackendState":"Running","TailscaleIPs":["100.64.0.7"]}"#.to_owned(),
            r#"{"BackendState":"Running","Peer":{"x":{"TailscaleIPs":["100.64.0.7"]}}}"#.to_owned(),
            r#"{"BackendState":"Running","Self":{"TailscaleIPs":"100.64.0.7"}}"#.to_owned(),
            r#"{"BackendState":"Running","Self":{"TailscaleIPs":[null,7]}}"#.to_owned(),
        ] {
            assert!(parse_status(&text).ips.is_empty(), "{text}");
        }
    }

    #[test]
    fn an_address_is_bound_only_when_tailscale_names_it_and_an_interface_has_it() {
        let parsed = parse_status(&status("Running", &["100.64.0.7", "fd7a:115c:a1e0::7"]));
        // The interfaces have the IPv4 only, and a CGNAT address that Tailscale does
        // not name (a carrier's): only the named and assigned one is a result.
        let interfaces = [ip("100.64.0.7"), ip("100.100.9.9"), ip("192.168.1.20")];
        assert_eq!(addresses(&parsed, &interfaces), vec![ip("100.64.0.7")]);
        assert!(addresses(&parsed, &[]).is_empty());
        assert!(addresses(&TailscaleSelf::default(), &interfaces).is_empty());
        // A hand-made status with wrong addresses still gives nothing outside the
        // ranges and never an unspecified address.
        let forged = TailscaleSelf {
            running: true,
            ips: vec![ip("0.0.0.0"), ip("::"), ip("192.168.1.20")],
        };
        assert!(addresses(&forged, &[ip("0.0.0.0"), ip("::"), ip("192.168.1.20")]).is_empty());
    }

    #[test]
    fn assigned_keeps_only_addresses_of_this_host() {
        assert_eq!(
            assigned(&[ip("127.0.0.1"), ip("192.0.2.55"), ip("0.0.0.0")]),
            vec![ip("127.0.0.1")]
        );
    }

    #[test]
    fn discovery_uses_the_known_paths_and_needs_an_assigned_address() {
        let mut programs = Vec::new();
        // A status that names an address no interface has (documentation range is
        // outside the tailnet ranges, so use a tailnet address that is not ours).
        let found = discover(|program, args| {
            programs.push(program.to_owned());
            assert_eq!(args, ["status", "--json"]);
            match program {
                "/Applications/Tailscale.app/Contents/MacOS/Tailscale" => None,
                "/usr/local/bin/tailscale" => Some("malformed".to_owned()),
                _ => Some(status("Running", &["100.127.254.253"])),
            }
        });
        assert_eq!(programs, TAILSCALE_PROGRAMS);
        // On a CI machine 100.127.254.253 is not assigned, so nothing is found.
        if UdpSocket::bind((Ipv4Addr::new(100, 127, 254, 253), 0)).is_err() {
            assert!(found.is_empty());
        }
        assert!(discover(|_, _| None).is_empty());
    }

    #[test]
    fn the_serve_state_of_a_tcp_port_is_free_ours_or_other() {
        let own = serve_tcp_target(51000);
        assert_eq!(parse_serve_tcp("", 8444, &own), Ok(ServeTcpState::Free));
        assert_eq!(parse_serve_tcp("{}", 8444, &own), Ok(ServeTcpState::Free));
        let ours = r#"{"TCP":{"8444":{"TCPForward":"127.0.0.1:51000"}}}"#;
        assert_eq!(parse_serve_tcp(ours, 8444, &own), Ok(ServeTcpState::Ours));
        assert_eq!(
            parse_serve_tcp(ours, 8445, &own),
            Ok(ServeTcpState::Free),
            "another port"
        );
        let other = r#"{"TCP":{"8444":{"TCPForward":"127.0.0.1:22"}}}"#;
        assert_eq!(
            parse_serve_tcp(other, 8444, &own),
            Ok(ServeTcpState::Other {
                target: "127.0.0.1:22".to_owned()
            })
        );
        // Serve that ends TLS would show its own certificate: the pin would fail, and
        // the app never takes it as its forward.
        let terminated =
            r#"{"TCP":{"8444":{"TCPForward":"127.0.0.1:51000","TerminateTLS":"mac.ts.net"}}}"#;
        assert!(matches!(
            parse_serve_tcp(terminated, 8444, &own),
            Ok(ServeTcpState::Other { .. })
        ));
        let https = r#"{"TCP":{"8444":{"HTTPS":true}},"Web":{"mac.ts.net:8444":{}}}"#;
        assert!(matches!(
            parse_serve_tcp(https, 8444, &own),
            Ok(ServeTcpState::Other { .. })
        ));
        let foreground = r#"{"Foreground":{"x":{"TCP":{"8444":{"TCPForward":"127.0.0.1:9"}}}}}"#;
        assert!(matches!(
            parse_serve_tcp(foreground, 8444, &own),
            Ok(ServeTcpState::Other { .. })
        ));
        let funnel = r#"{"TCP":{"8444":{"TCPForward":"127.0.0.1:51000"}},"AllowFunnel":{"mac.ts.net:8444":true}}"#;
        assert!(matches!(
            parse_serve_tcp(funnel, 8444, &own),
            Ok(ServeTcpState::Other { .. })
        ));
        assert!(parse_serve_tcp("not json", 8444, &own).is_err());
        assert!(parse_serve_tcp("[]", 8444, &own).is_err());
    }

    struct FakeCli {
        status: std::sync::Mutex<String>,
        calls: std::sync::Mutex<Vec<Vec<String>>>,
        /// The command line knows `--proxy-protocol`.
        proxy_protocol: std::sync::Mutex<bool>,
    }

    impl crate::node::funnel::TailscaleCli for FakeCli {
        fn run(&self, args: &[&str]) -> Option<crate::node::funnel::CliOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|a| (*a).to_owned()).collect());
            let stdout = match args {
                ["serve", "status", "--json"] => self.status.lock().unwrap().clone(),
                ["serve", "--bg", tcp, "--proxy-protocol=1", target]
                    if *self.proxy_protocol.lock().unwrap() =>
                {
                    let port = tcp.trim_start_matches("--tcp=");
                    let forward = target.trim_start_matches("tcp://");
                    *self.status.lock().unwrap() = format!(
                        r#"{{"TCP":{{"{port}":{{"TCPForward":"{forward}","ProxyProtocol":1}}}}}}"#
                    );
                    String::new()
                }
                ["serve", "--bg", _, "--proxy-protocol=1", _] => {
                    return Some(crate::node::funnel::CliOutput {
                        success: false,
                        stdout: String::new(),
                        stderr: "flag provided but not defined: -proxy-protocol".to_owned(),
                    });
                }
                ["serve", "--bg", tcp, target] => {
                    let port = tcp.trim_start_matches("--tcp=");
                    let forward = target.trim_start_matches("tcp://");
                    *self.status.lock().unwrap() =
                        format!(r#"{{"TCP":{{"{port}":{{"TCPForward":"{forward}"}}}}}}"#);
                    String::new()
                }
                ["serve", _, "off"] => {
                    *self.status.lock().unwrap() = "{}".to_owned();
                    String::new()
                }
                _ => panic!("unexpected command {args:?}"),
            };
            Some(crate::node::funnel::CliOutput {
                success: true,
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn the_serve_fallback_turns_only_its_own_forward_on_and_off() {
        let cli = std::sync::Arc::new(FakeCli {
            status: std::sync::Mutex::new("{}".to_owned()),
            calls: std::sync::Mutex::new(Vec::new()),
            proxy_protocol: std::sync::Mutex::new(true),
        });
        let serve = ServeTcp::new(cli.clone());
        assert_eq!(serve.enable(443, 51000), Err(ServeTcpError::Forbidden(443)));
        assert_eq!(
            serve.enable(8443, 51000),
            Err(ServeTcpError::Forbidden(8443))
        );
        assert_eq!(serve.enable(8444, 0), Err(ServeTcpError::BadLocalPort));
        serve.enable(8444, 51000).expect("on");
        assert!(cli.calls.lock().unwrap().contains(&vec![
            "serve".to_owned(),
            "--bg".to_owned(),
            "--tcp=8444".to_owned(),
            "--proxy-protocol=1".to_owned(),
            "tcp://127.0.0.1:51000".to_owned(),
        ]));
        assert_eq!(serve.state(8444, 51000), Ok(ServeTcpState::Ours));
        serve.enable(8444, 51000).expect("already on");
        assert_eq!(serve.disable(8444, 51001), Ok(false), "not our target");
        assert_eq!(serve.disable(8444, 51000), Ok(true));
        assert_eq!(serve.state(8444, 51000), Ok(ServeTcpState::Free));
        *cli.status.lock().unwrap() =
            r#"{"TCP":{"8444":{"TCPForward":"127.0.0.1:22"}}}"#.to_owned();
        assert!(matches!(
            serve.enable(8444, 51000),
            Err(ServeTcpError::Taken { .. })
        ));
        assert_eq!(serve.disable(8444, 51000), Ok(false));
        assert!(
            !cli.calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.iter().any(|word| word == "reset")),
            "never serve reset"
        );
    }

    #[test]
    fn an_old_command_line_gets_the_forward_without_the_proxy_protocol() {
        let cli = std::sync::Arc::new(FakeCli {
            status: std::sync::Mutex::new("{}".to_owned()),
            calls: std::sync::Mutex::new(Vec::new()),
            proxy_protocol: std::sync::Mutex::new(false),
        });
        let serve = ServeTcp::new(cli.clone());
        serve.enable(8444, 51000).expect("on");
        assert_eq!(serve.state(8444, 51000), Ok(ServeTcpState::Ours));
        assert!(cli.calls.lock().unwrap().contains(&vec![
            "serve".to_owned(),
            "--bg".to_owned(),
            "--tcp=8444".to_owned(),
            "tcp://127.0.0.1:51000".to_owned(),
        ]));
    }

    #[test]
    fn a_stale_forward_of_a_crash_goes_before_the_front_takes_a_port() {
        let cli = std::sync::Arc::new(FakeCli {
            status: std::sync::Mutex::new(
                r#"{"TCP":{"8444":{"TCPForward":"127.0.0.1:51000","ProxyProtocol":1}}}"#.to_owned(),
            ),
            calls: std::sync::Mutex::new(Vec::new()),
            proxy_protocol: std::sync::Mutex::new(true),
        });
        let serve = ServeTcp::new(cli.clone());
        // No earlier port known, or another one: nothing changes.
        assert_eq!(serve.clear_stale(8444, None), Ok(false));
        assert_eq!(serve.clear_stale(8444, Some(51001)), Ok(false));
        assert_eq!(serve.state(8444, 51000), Ok(ServeTcpState::Ours));
        // The forward of the front's earlier port goes; then the new one goes on.
        assert_eq!(serve.clear_stale(8444, Some(51000)), Ok(true));
        assert_eq!(serve.state(8444, 51000), Ok(ServeTcpState::Free));
        serve.enable(8444, 52000).expect("the new forward");
        assert_eq!(serve.state(8444, 52000), Ok(ServeTcpState::Ours));
        // Another program's forward is never touched.
        *cli.status.lock().unwrap() =
            r#"{"TCP":{"8444":{"TCPForward":"127.0.0.1:22"}}}"#.to_owned();
        assert_eq!(serve.clear_stale(8444, Some(52000)), Ok(false));
        assert!(matches!(
            serve.state(8444, 52000),
            Ok(ServeTcpState::Other { .. })
        ));
    }

    #[test]
    #[ignore = "requires a running local Tailscale daemon and APASSY_TEST_TAILSCALE_IPV4"]
    fn live_tailnet_addresses_hold_the_tailscale_ipv4() {
        let expected: IpAddr = std::env::var("APASSY_TEST_TAILSCALE_IPV4")
            .expect("set the known local Tailscale IPv4 address")
            .parse()
            .expect("a valid IPv4 address");
        let found = system_addresses();
        eprintln!("tailnet addresses: {found:?}");
        assert_eq!(found.first(), Some(&expected));
    }
}
