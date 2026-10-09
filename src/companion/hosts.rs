//! The hosts for the pairing link: a confirmed local Tailscale IPv4 address, the
//! `.local` name of the Mac, then its primary IPv4 address on the local network.
//!
//! These are looked up when the owner opens a pairing window, because the network can
//! change. A lookup that fails gives fewer hosts, never a wrong one. The link never
//! names a loopback address, a link-local address (`169.254.0.0/16`), or an address of
//! an unconfirmed tunnel interface (a VPN, `utun`). Tailscale is an explicit exception
//! for a phone on the same Tailscale network.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SCUTIL: &str = "/usr/sbin/scutil";
const IFCONFIG: &str = "/sbin/ifconfig";
/// Only known installation paths are used. The process environment cannot select a
/// different executable through PATH.
const TAILSCALE_PROGRAMS: [&str; 4] = [
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/local/bin/tailscale",
    "/opt/homebrew/bin/tailscale",
    "/usr/bin/tailscale",
];
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// A command writes at most this much. `ifconfig -a` of a busy Mac is some KiB.
const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
/// An address that no packet reaches: a UDP `connect` only picks the route to it.
const PROBE_ADDRESS: (Ipv4Addr, u16) = (Ipv4Addr::new(192, 0, 2, 1), 9);
/// Interface name prefixes of tunnels and VPNs.
const TUNNEL_PREFIXES: [&str; 4] = ["utun", "ipsec", "ppp", "tun"];

/// The hosts for the link, in the order the phone tries them.
pub fn link_hosts() -> Vec<String> {
    hosts_from_addresses(tailscale_ipv4(), local_host_name(), primary_ipv4())
}

fn hosts_from_addresses(
    tailscale: Option<Ipv4Addr>,
    local_name: Option<String>,
    primary: Option<Ipv4Addr>,
) -> Vec<String> {
    // The phone tries hosts in this order. Bonjour can time out on a remote network.
    unique_hosts(
        tailscale
            .map(|address| address.to_string())
            .into_iter()
            .chain(local_name.map(|name| format!("{name}.local")))
            .chain(primary.map(|address| address.to_string())),
    )
}

fn unique_hosts(candidates: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut hosts = Vec::new();
    for host in candidates {
        if !hosts.contains(&host) {
            hosts.push(host);
            if hosts.len() == super::link::MAX_HOSTS {
                break;
            }
        }
    }
    hosts
}

fn tailscale_ipv4() -> Option<Ipv4Addr> {
    discover_tailscale_ipv4(command_output, |address| {
        // Userspace-only Tailscale can report a Self address that is not assigned to
        // this host. The companion listener cannot receive connections there.
        UdpSocket::bind((address, 0)).is_ok()
    })
}

fn discover_tailscale_ipv4(
    mut output: impl FnMut(&str, &[&str]) -> Option<String>,
    mut locally_assigned: impl FnMut(Ipv4Addr) -> bool,
) -> Option<Ipv4Addr> {
    for program in TAILSCALE_PROGRAMS {
        let Some(status) = output(program, &["status", "--json"]) else {
            continue;
        };
        if let Some(address) = parse_tailscale_ipv4(&status)
            && locally_assigned(address)
        {
            return Some(address);
        }
    }
    None
}

/// A CGNAT address alone does not identify Tailscale. Only the running daemon's Self
/// record can supply an address, and only the Tailscale IPv4 range is accepted.
fn parse_tailscale_ipv4(output: &str) -> Option<Ipv4Addr> {
    let status: serde_json::Value = serde_json::from_str(output).ok()?;
    if status.get("BackendState")?.as_str()? != "Running" {
        return None;
    }
    status
        .get("Self")?
        .get("TailscaleIPs")?
        .as_array()?
        .iter()
        .filter_map(|value| value.as_str()?.parse::<Ipv4Addr>().ok())
        .find(|address| {
            let [first, second, _, _] = address.octets();
            first == 100 && (64..=127).contains(&second)
        })
}

/// The name of the Mac for the phone (`scutil --get ComputerName`, for example
/// "Rafal's Mac mini"), or the Bonjour name when the computer name is missing. `None`
/// when both fail. The listener cleans the name (no control character, at most 40
/// characters).
pub fn computer_name() -> Option<String> {
    command_output(SCUTIL, &["--get", "ComputerName"])
        .map(|output| output.trim().to_owned())
        .filter(|name| !name.is_empty())
        .or_else(local_host_name)
}

/// The output of a command, or `None` when it fails, takes longer than two seconds, or
/// writes more than [`MAX_OUTPUT_BYTES`].
///
/// A thread reads the output while the command runs. A command that writes more than
/// the pipe holds would block on its write if the caller waited for its exit first.
fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    // One byte more than the limit tells "exactly the limit" from "too much". A reader
    // that stops early drops the pipe, and the command ends on its next write.
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()
            .map(|_| bytes)
    });
    let end = Instant::now() + COMMAND_TIMEOUT;
    let exited_well = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() >= end => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let bytes = reader.join().ok()??;
    if !exited_well || u64::try_from(bytes.len()).is_ok_and(|len| len > MAX_OUTPUT_BYTES) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// `scutil --get LocalHostName`: the Bonjour name without `.local`.
fn local_host_name() -> Option<String> {
    parse_local_host_name(&command_output(SCUTIL, &["--get", "LocalHostName"])?)
}

/// A local host name is one DNS label: letters, digits, and `-`, at most 63 characters,
/// with no `-` at the start or the end.
pub fn parse_local_host_name(output: &str) -> Option<String> {
    let name = output.trim();
    let valid = !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    valid.then(|| name.to_owned())
}

/// The IPv4 address of the interface that carries the default route, or `None` when the
/// Mac has no route or the address is not one the phone can reach.
fn primary_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(PROBE_ADDRESS).ok()?;
    let IpAddr::V4(address) = socket.local_addr().ok()?.ip() else {
        return None;
    };
    // When the interfaces cannot be read, the address is not known to be free of a
    // tunnel, so the link does not name it.
    let tunnels = tunnel_addresses(&command_output(IFCONFIG, &["-a"])?);
    usable_address(address, &tunnels).then_some(address)
}

/// True when the phone can reach `address` on the local network.
pub fn usable_address(address: Ipv4Addr, tunnels: &[Ipv4Addr]) -> bool {
    !(address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || tunnels.contains(&address))
}

/// The IPv4 addresses of tunnel interfaces in the output of `ifconfig -a`. An interface
/// starts at a line without indentation, and its `inet` lines are indented.
pub fn tunnel_addresses(ifconfig: &str) -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();
    let mut tunnel = false;
    for line in ifconfig.lines() {
        if !line.starts_with([' ', '\t']) {
            let name = line.split(':').next().unwrap_or_default();
            tunnel = TUNNEL_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix));
            continue;
        }
        let mut words = line.split_whitespace();
        if tunnel
            && words.next() == Some("inet")
            && let Some(address) = words.next().and_then(|word| word.parse().ok())
        {
            addresses.push(address);
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tailscale_status(addresses: &[&str]) -> String {
        serde_json::json!({
            "BackendState": "Running",
            "Self": { "TailscaleIPs": addresses },
        })
        .to_string()
    }

    #[test]
    fn tailscale_ipv4_comes_only_from_running_self_in_the_tailscale_range() {
        assert_eq!(
            parse_tailscale_ipv4(&tailscale_status(&[
                "fd7a:115c:a1e0::1",
                "192.168.1.20",
                "100.64.0.7",
            ])),
            Some(Ipv4Addr::new(100, 64, 0, 7)),
        );
        for address in ["100.64.0.0", "100.127.255.255"] {
            assert_eq!(
                parse_tailscale_ipv4(&tailscale_status(&[address])),
                address.parse().ok(),
            );
        }
        for address in [
            "100.63.255.255",
            "100.128.0.0",
            "192.168.1.20",
            "127.0.0.1",
            "0.0.0.0",
            "fd7a:115c:a1e0::1",
            "100.64.0.7:1234",
            "not-an-address",
        ] {
            assert_eq!(
                parse_tailscale_ipv4(&tailscale_status(&[address])),
                None,
                "{address}",
            );
        }
    }

    #[test]
    fn absent_stopped_or_malformed_tailscale_status_has_no_address() {
        for status in [
            "",
            "not json",
            "null",
            "{}",
            r#"{"BackendState":"Stopped","Self":{"TailscaleIPs":["100.64.0.7"]}}"#,
            r#"{"BackendState":"NeedsLogin","Self":{"TailscaleIPs":["100.64.0.7"]}}"#,
            r#"{"BackendState":"Running","TailscaleIPs":["100.64.0.7"]}"#,
            r#"{"BackendState":"Running","Peer":{"other":{"TailscaleIPs":["100.64.0.7"]}}}"#,
            r#"{"BackendState":"Running","Self":null}"#,
            r#"{"BackendState":"Running","Self":{"TailscaleIPs":"100.64.0.7"}}"#,
            r#"{"BackendState":"Running","Self":{"TailscaleIPs":[null,7]}}"#,
            r#"{"BackendState":"Running","Self":{"TailscaleIPs":[]}}"#,
        ] {
            assert_eq!(parse_tailscale_ipv4(status), None, "{status}");
        }
    }

    #[test]
    fn discovery_uses_known_paths_and_requires_a_local_address() {
        let address = Ipv4Addr::new(100, 64, 0, 7);
        let mut programs = Vec::new();
        assert_eq!(
            discover_tailscale_ipv4(
                |program, args| {
                    programs.push(program.to_owned());
                    assert_eq!(args, ["status", "--json"]);
                    match program {
                        "/Applications/Tailscale.app/Contents/MacOS/Tailscale" => None,
                        "/usr/local/bin/tailscale" => Some("malformed".to_owned()),
                        "/opt/homebrew/bin/tailscale" => Some(tailscale_status(&["100.64.0.7"])),
                        _ => panic!("must stop after a confirmed address"),
                    }
                },
                |candidate| candidate == address,
            ),
            Some(address),
        );
        assert_eq!(programs, TAILSCALE_PROGRAMS[..3]);
        assert_eq!(
            discover_tailscale_ipv4(|_, _| None, |_| panic!("no address to check")),
            None,
        );
        assert_eq!(
            discover_tailscale_ipv4(|_, _| Some(tailscale_status(&["100.64.0.7"])), |_| false),
            None,
            "userspace-only Tailscale must not supply a listener address",
        );
    }

    #[test]
    fn tailscale_is_first_and_bonjour_and_lan_are_fallbacks() {
        let tailscale = Ipv4Addr::new(100, 64, 0, 7);
        let lan = Ipv4Addr::new(192, 168, 1, 20);
        assert_eq!(
            hosts_from_addresses(Some(tailscale), Some("Mac-mini".to_owned()), Some(lan)),
            ["100.64.0.7", "Mac-mini.local", "192.168.1.20"],
        );
        assert_eq!(
            hosts_from_addresses(None, Some("Mac-mini".to_owned()), Some(lan)),
            ["Mac-mini.local", "192.168.1.20"],
        );
        assert_eq!(
            hosts_from_addresses(Some(tailscale), None, None),
            ["100.64.0.7"],
        );
        assert_eq!(
            hosts_from_addresses(None, None, Some(lan)),
            ["192.168.1.20"]
        );
        assert!(hosts_from_addresses(None, None, None).is_empty());
    }

    #[test]
    fn hosts_are_unique_and_limited_to_the_link_capacity() {
        let tailscale = Ipv4Addr::new(100, 64, 0, 7);
        assert_eq!(
            hosts_from_addresses(Some(tailscale), None, Some(tailscale)),
            ["100.64.0.7"],
        );
        assert_eq!(
            unique_hosts(
                [
                    "100.64.0.7",
                    "100.64.0.7",
                    "Mac.local",
                    "192.168.1.20",
                    "10.0.0.7",
                    "10.0.0.8"
                ]
                .into_iter()
                .map(str::to_owned),
            ),
            ["100.64.0.7", "Mac.local", "192.168.1.20", "10.0.0.7"],
        );
    }

    #[test]
    fn a_local_host_name_is_one_dns_label() {
        assert_eq!(
            parse_local_host_name("Mac-mini\n").as_deref(),
            Some("Mac-mini")
        );
        assert_eq!(parse_local_host_name("  a1  ").as_deref(), Some("a1"));
        for bad in [
            "",
            "\n",
            "-mac",
            "mac-",
            "mac mini",
            "mac.local",
            "mac\u{e9}",
            "a/b",
            &"a".repeat(64),
        ] {
            assert_eq!(parse_local_host_name(bad), None, "{bad:?}");
        }
        assert!(parse_local_host_name(&"a".repeat(63)).is_some());
    }

    const IFCONFIG_SAMPLE: &str = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 100.64.0.7 --> 100.64.0.7 netmask 0xffffffff
\tinet6 fe80::1%utun3 prefixlen 64 scopeid 0xf
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet 10.9.0.2 --> 10.9.0.1 netmask 0xffffffff
bridge0: flags=8863<UP> mtu 1500
\tinet 10.5.0.1 netmask 0xffffff00
";

    #[test]
    fn tunnel_addresses_come_from_tunnel_interfaces_only() {
        assert_eq!(
            tunnel_addresses(IFCONFIG_SAMPLE),
            vec![Ipv4Addr::new(100, 64, 0, 7), Ipv4Addr::new(10, 9, 0, 2)]
        );
        assert!(tunnel_addresses("").is_empty());
    }

    #[test]
    fn an_address_of_the_local_network_is_usable() {
        let tunnels = tunnel_addresses(IFCONFIG_SAMPLE);
        assert!(usable_address(Ipv4Addr::new(192, 168, 1, 20), &tunnels));
        assert!(usable_address(Ipv4Addr::new(10, 0, 0, 5), &tunnels));
        for bad in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(169, 254, 3, 4),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(100, 64, 0, 7),
            Ipv4Addr::new(10, 9, 0, 2),
        ] {
            assert!(!usable_address(bad, &tunnels), "{bad}");
        }
    }

    #[test]
    fn a_missing_program_gives_no_output() {
        assert_eq!(command_output("/nonexistent/apassy-test", &[]), None);
        assert_eq!(command_output("/usr/bin/false", &[]), None);
    }

    #[test]
    fn an_output_larger_than_the_pipe_is_read_while_the_command_runs() {
        // 400 KB is far more than the 64 KiB of a pipe. Read after the exit, this
        // command blocks on its write until the timeout kills it.
        let begin = Instant::now();
        let output = command_output("/bin/sh", &["-c", "head -c 400000 /dev/zero | tr '\\0' a"])
            .expect("the output");
        assert_eq!(output.len(), 400_000);
        assert!(output.bytes().all(|b| b == b'a'));
        assert!(
            begin.elapsed() < COMMAND_TIMEOUT,
            "it did not wait for the timeout"
        );
    }

    #[test]
    fn an_output_over_the_limit_or_a_command_that_hangs_gives_nothing() {
        let too_much = format!("head -c {} /dev/zero | tr '\\0' a", MAX_OUTPUT_BYTES + 1);
        assert_eq!(command_output("/bin/sh", &["-c", &too_much]), None);
        let begin = Instant::now();
        assert_eq!(command_output("/bin/sleep", &["30"]), None);
        assert!(begin.elapsed() < COMMAND_TIMEOUT + Duration::from_secs(2));
    }

    #[test]
    fn every_host_that_link_hosts_finds_is_fit_for_a_link() {
        // The machine may have no network. Whatever is found must pass the link rules.
        for host in link_hosts() {
            let parts = super::super::link::LinkParts {
                hosts: std::slice::from_ref(&host),
                port: 48620,
                pin: &crate::companion::crypto::certificate_pin(&[0x30, 0x00]),
                secret: &[1u8; 32],
                mac_name: "Mac",
                expires_at: 1,
            };
            assert!(super::super::link::pairing_link(&parts).is_ok(), "{host}");
        }
    }

    #[test]
    #[ignore = "requires a running local Tailscale daemon and APASSY_TEST_TAILSCALE_IPV4"]
    fn live_tailscale_address_is_first_in_the_link_hosts() {
        let expected: Ipv4Addr = std::env::var("APASSY_TEST_TAILSCALE_IPV4")
            .expect("set the known local Tailscale IPv4 address")
            .parse()
            .expect("a valid IPv4 address");
        let hosts = link_hosts();
        assert_eq!(hosts.first(), Some(&expected.to_string()));
        eprintln!("companion hosts: {hosts:?}");
    }
}
