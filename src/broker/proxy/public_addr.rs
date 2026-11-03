//! Which upstream addresses are on the public internet.
//!
//! The relay proxy and a run proxy with `UpstreamPolicy::PublicOnly` reach only
//! public addresses, so a team or a linked environment cannot reach the machine of
//! the proxy, its networks, or the tailnet through it (ADR 0019, ADR 0037 stage 5).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// True for an address on the public internet. False for loopback, private, link-local,
/// CGNAT, unique-local, multicast, documentation, benchmark, reserved, and unspecified
/// addresses, and for IPv6 forms that carry such an IPv4 address.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let segments = ip.segments();
    // 64:ff9b::/96 (NAT64) carries an IPv4 address in its last 32 bits.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., hi, lo] = segments;
        return is_public_v4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] == 0x64 && segments[1] == 0xff9b && segments[2] == 1)
        || segments[..6] == [0, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailnet_and_mapped_loopback_addresses_are_not_public() {
        for text in [
            "100.64.0.1",
            "100.100.100.100",
            "100.127.255.254",
            "::ffff:127.0.0.1",
            "fd7a:115c:a1e0::1",
        ] {
            assert!(!is_public_ip(text.parse().unwrap()), "{text}");
        }
        for text in ["1.1.1.1", "2620:fe::1"] {
            assert!(is_public_ip(text.parse().unwrap()), "{text}");
        }
    }
}
