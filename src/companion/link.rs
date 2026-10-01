//! The pairing link (contract companion-v1, section 5.1).
//!
//! ```text
//! apassy://pair?v=1&h=Mac-mini.local,192.168.1.20&p=48620&c=<pin>&s=<secret>&n=Mac%20mini&e=1790000300
//! ```
//!
//! The link is the payload of a QR code. It has the pairing secret, so the Mac never
//! puts it on the pasteboard and never logs it.

use std::net::Ipv4Addr;

use super::crypto::SECRET_BYTES;
use super::wire::{MAX_DEVICE_NAME_CHARS, decode_fixed};
use crate::native::base64::encode_url;

/// A link names at most this many hosts.
pub const MAX_HOSTS: usize = 4;

/// What goes into a pairing link.
#[derive(Debug, Clone, Copy)]
pub struct LinkParts<'a> {
    /// Hosts to try, in order: the `.local` name, then the primary IPv4 address.
    pub hosts: &'a [String],
    pub port: u16,
    /// The certificate pin, b64u of a SHA-256.
    pub pin: &'a str,
    pub secret: &'a [u8; SECRET_BYTES],
    /// The name of the Mac for the phone. Control characters go, and the name is cut at
    /// 40 characters.
    pub mac_name: &'a str,
    /// The end of the window, Unix seconds.
    pub expires_at: u64,
}

/// Why a link cannot be built. Each variant is a bug of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// No host is left.
    NoHost,
    /// A host is empty, has a character outside letters, digits, `.` and `-`, or is a
    /// loopback, link-local, or unspecified IPv4 address.
    BadHost,
    /// The pin is not the b64u text of 32 bytes.
    BadPin,
    /// The port is 0.
    BadPort,
}

/// Build the pairing link. It refuses a host that the phone must never try.
pub fn pairing_link(parts: &LinkParts<'_>) -> Result<String, LinkError> {
    build_link(parts, false)
}

/// Build a link that may name a loopback host. Only the development server uses it, for
/// a client on the same machine (the listener has `allow_local_peers` then). The app
/// never does.
pub fn pairing_link_for_development(parts: &LinkParts<'_>) -> Result<String, LinkError> {
    build_link(parts, true)
}

fn build_link(parts: &LinkParts<'_>, allow_loopback: bool) -> Result<String, LinkError> {
    if parts.hosts.is_empty() {
        return Err(LinkError::NoHost);
    }
    if parts.port == 0 {
        return Err(LinkError::BadPort);
    }
    if decode_fixed::<32>(parts.pin).is_none() {
        return Err(LinkError::BadPin);
    }
    let mut hosts = Vec::new();
    for host in parts.hosts.iter().take(MAX_HOSTS) {
        if !valid_host(host, allow_loopback) {
            return Err(LinkError::BadHost);
        }
        hosts.push(host.as_str());
    }
    Ok(format!(
        "apassy://pair?v=1&h={}&p={}&c={}&s={}&n={}&e={}",
        hosts.join(","),
        parts.port,
        parts.pin,
        encode_url(parts.secret),
        percent_encode(&link_name(parts.mac_name)),
        parts.expires_at
    ))
}

/// The Mac name in the link: no control character, at most 40 characters.
fn link_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DEVICE_NAME_CHARS)
        .collect();
    if clean.trim().is_empty() {
        "Mac".to_owned()
    } else {
        clean
    }
}

fn valid_host(host: &str, allow_loopback: bool) -> bool {
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || host.starts_with(['.', '-'])
        || host.ends_with(['.', '-'])
    {
        return false;
    }
    match host.parse::<Ipv4Addr>() {
        Ok(address) => {
            !((address.is_loopback() && !allow_loopback)
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_multicast())
        }
        // A name. `localhost` is a loopback name.
        Err(_) => allow_loopback || !host.eq_ignore_ascii_case("localhost"),
    }
}

/// Percent-encode every byte except the unreserved characters of RFC 3986.
fn percent_encode(text: &str) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::crypto::certificate_pin;

    fn hosts(list: &[&str]) -> Vec<String> {
        list.iter().map(|host| (*host).to_owned()).collect()
    }

    fn link_with(hosts: &[String], name: &str) -> Result<String, LinkError> {
        let pin = certificate_pin(&[0x30, 0x00]);
        pairing_link(&LinkParts {
            hosts,
            port: 48620,
            pin: &pin,
            secret: &[7u8; 32],
            mac_name: name,
            expires_at: 1_790_000_300,
        })
    }

    #[test]
    fn the_link_has_the_parameters_in_order() {
        let link =
            link_with(&hosts(&["Mac-mini.local", "192.168.1.20"]), "Mac mini").expect("link");
        assert_eq!(
            link,
            format!(
                "apassy://pair?v=1&h=Mac-mini.local,192.168.1.20&p=48620&c=5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU&s={}&n=Mac%20mini&e=1790000300",
                encode_url(&[7u8; 32])
            )
        );
        // The secret in the link is the b64u of 32 bytes.
        let secret = link
            .split("&s=")
            .nth(1)
            .and_then(|rest| rest.split('&').next());
        assert_eq!(secret.map(str::len), Some(43));
    }

    #[test]
    fn the_name_is_percent_encoded_cleaned_and_cut() {
        let link =
            link_with(&hosts(&["a.local"]), "Rafa\u{142}'s Mac & \"mini\"\n#1").expect("link");
        assert!(
            link.contains("&n=Rafa%C5%82%27s%20Mac%20%26%20%22mini%22%231&"),
            "{link}"
        );
        let long = link_with(&hosts(&["a.local"]), &"m".repeat(60)).expect("link");
        assert!(long.contains(&format!("&n={}&", "m".repeat(40))));
        let blank = link_with(&hosts(&["a.local"]), " \n ").expect("link");
        assert!(blank.contains("&n=Mac&"));
        // A multi-byte name is cut at 40 characters, not in the middle of a character.
        let wide = link_with(&hosts(&["a.local"]), &"\u{142}".repeat(50)).expect("link");
        assert!(wide.contains(&format!("&n={}&", "%C5%82".repeat(40))));
    }

    #[test]
    fn at_most_four_hosts() {
        let five = hosts(&["a.local", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]);
        let link = link_with(&five, "Mac").expect("link");
        assert!(
            link.contains("&h=a.local,10.0.0.1,10.0.0.2,10.0.0.3&"),
            "{link}"
        );
    }

    #[test]
    fn a_host_that_the_phone_must_not_try_is_refused() {
        assert_eq!(link_with(&[], "Mac"), Err(LinkError::NoHost));
        for bad in [
            "127.0.0.1",
            "127.1.2.3",
            "169.254.10.20",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "localhost",
            "LocalHost",
            "",
            "a b.local",
            "a,b.local",
            "a.local&x=1",
            "a.local/",
            ".local",
            "a.local.",
            "-a.local",
            "a\n.local",
            "[::1]",
            "a.local:80",
        ] {
            assert_eq!(
                link_with(&hosts(&[bad]), "Mac"),
                Err(LinkError::BadHost),
                "{bad:?}"
            );
        }
        // One bad host anywhere is refused.
        assert_eq!(
            link_with(&hosts(&["a.local", "127.0.0.1"]), "Mac"),
            Err(LinkError::BadHost)
        );
        assert!(link_with(&hosts(&["192.168.1.20", "10.0.0.5", "172.16.0.9"]), "Mac").is_ok());
    }

    #[test]
    fn only_the_development_link_may_name_a_loopback_host() {
        let host = hosts(&["127.0.0.1", "localhost"]);
        let parts = LinkParts {
            hosts: &host,
            port: 48620,
            pin: "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU",
            secret: &[7u8; 32],
            mac_name: "Mac",
            expires_at: 1,
        };
        assert_eq!(pairing_link(&parts), Err(LinkError::BadHost));
        let link = pairing_link_for_development(&parts).expect("link");
        assert!(link.contains("&h=127.0.0.1,localhost&"), "{link}");
        // The other rules stay.
        let bad = hosts(&["169.254.1.1"]);
        assert_eq!(
            pairing_link_for_development(&LinkParts {
                hosts: &bad,
                ..parts
            }),
            Err(LinkError::BadHost)
        );
    }

    #[test]
    fn a_bad_pin_or_port_is_refused() {
        let secret = [7u8; 32];
        let host = hosts(&["a.local"]);
        let base = LinkParts {
            hosts: &host,
            port: 48620,
            pin: "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU",
            secret: &secret,
            mac_name: "Mac",
            expires_at: 1,
        };
        assert!(pairing_link(&base).is_ok());
        assert_eq!(
            pairing_link(&LinkParts {
                pin: "short",
                ..base
            }),
            Err(LinkError::BadPin)
        );
        assert_eq!(
            pairing_link(&LinkParts {
                pin: "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU=",
                ..base
            }),
            Err(LinkError::BadPin)
        );
        assert_eq!(
            pairing_link(&LinkParts { port: 0, ..base }),
            Err(LinkError::BadPort)
        );
    }
}
