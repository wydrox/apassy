//! The text of the QR code and of the pasted link of "Add a device…" (build plan §2d,
//! contract relay-connect-v1).
//!
//! ```text
//! https://<relay>/link#apassy_lnk_<team>_<64 hex>&r=sync|connect&n=<Mac name>&e=<expires>&p=<b64u of apassy://pair…>
//! ```
//!
//! The iPhone has no URL scheme, so the QR code and the pasted text are the same
//! string. The body stays the link of relay-sync-v1 section 7.1; the fragment gets
//! parameters after the link code:
//!
//! - `r`: what the device does with the link. `sync` joins relay sync (paid);
//!   `connect` joins the Connect team for the questions only (Free). A link with no
//!   `r` is `sync`, as every link before this one.
//! - `n`: the name of the Mac, percent-encoded.
//! - `e`: when the link code expires, Unix seconds.
//! - `p`: the pairing link of the local network (contract companion-v1 section 5.1),
//!   b64u. The device falls back to "Pair on this network" when the relay does not
//!   answer.
//!
//! A parser takes the link code before the first `&`. It ignores keys that it does not
//! know, and an `n`, `e`, or `p` that is not valid: they only help. The link holds the
//! link code and the pairing secret, so Debug is redacted.

use std::fmt;

use zeroize::Zeroizing;

use super::relay::clean_name;
use super::relay_crypto::{decode_b64u, encode_b64u, link_code_team};
use super::{RelayRefusal, RelayUrl, SyncError};
use crate::companion::link::percent_encode;

/// A link is at most this many bytes. A longer text is not a link.
pub const MAX_LINK_BYTES: usize = 2048;
/// The pairing link in `p` is at most this many bytes.
const MAX_PAIRING_BYTES: usize = 1024;
/// The start of a pairing link.
const PAIRING_PREFIX: &str = "apassy://pair?";

/// What the device that reads a link does with it (`r`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRoute {
    /// Join relay sync: the device downloads the copy of the vault (`join_finish`).
    Sync,
    /// Join the Connect team for the questions only (`join_attach`); the vault comes
    /// from iCloud Drive.
    Connect,
}

impl LinkRoute {
    /// The value of `r`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Connect => "connect",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "sync" => Some(Self::Sync),
            "connect" => Some(Self::Connect),
            _ => None,
        }
    }
}

/// Why a text is not a link of "Add a device…".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPayloadError {
    /// The text has no valid link code, or is longer than [`MAX_LINK_BYTES`].
    NotALink,
    /// The relay address is not `https://`, or `http://` with a port on this computer.
    InvalidRelayAddress,
    /// `r` names a route that this version does not know: a newer Mac made the link.
    UnknownRoute,
}

impl fmt::Display for LinkPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotALink => "this is not a link of Apassy. Copy the link again on the Mac",
            Self::InvalidRelayAddress => {
                "the relay address of the link is not valid. Use https://, or http:// with a port on this computer"
            }
            Self::UnknownRoute => {
                "this link needs a newer version of Apassy. Update Apassy, then try again"
            }
        })
    }
}

impl std::error::Error for LinkPayloadError {}

impl From<LinkPayloadError> for SyncError {
    fn from(error: LinkPayloadError) -> Self {
        match error {
            LinkPayloadError::InvalidRelayAddress => Self::InvalidRelayAddress,
            LinkPayloadError::NotALink | LinkPayloadError::UnknownRoute => {
                Self::Relay(RelayRefusal::Forbidden)
            }
        }
    }
}

/// A link of "Add a device…", built on the Mac or parsed on the device that reads it.
/// Debug is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayLinkPayload {
    /// The relay of the team.
    pub relay: RelayUrl,
    /// `apassy_lnk_<team id>_<64 hex>`.
    pub code: Zeroizing<String>,
    pub route: LinkRoute,
    /// The name of the Mac that made the link, cleaned (no control character, at most
    /// 64 bytes).
    pub mac_name: Option<String>,
    /// Unix time when the link code expires.
    pub expires_at: Option<u64>,
    /// The pairing link of the local network, `apassy://pair?…`.
    pub pairing: Option<Zeroizing<String>>,
}

impl fmt::Debug for RelayLinkPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayLinkPayload")
            .field("relay", &self.relay.as_str())
            .field("route", &self.route)
            .field("mac_name", &self.mac_name)
            .field("expires_at", &self.expires_at)
            .field("pairing", &self.pairing.is_some())
            .finish_non_exhaustive()
    }
}

impl RelayLinkPayload {
    /// A link with the code `code` of a team on `relay`, and no optional part.
    pub fn new(relay: RelayUrl, code: Zeroizing<String>, route: LinkRoute) -> Self {
        Self {
            relay,
            code,
            route,
            mac_name: None,
            expires_at: None,
            pairing: None,
        }
    }

    /// The text of the QR code and of "Copy link". It always has `r`.
    pub fn link(&self) -> Zeroizing<String> {
        let name = self
            .mac_name
            .as_ref()
            .map(|name| percent_encode(&clean_name(name, "Mac")));
        let pairing = self
            .pairing
            .as_ref()
            .map(|pairing| Zeroizing::new(encode_b64u(pairing.as_bytes())));
        // One buffer of the final size, so no copy of the code stays behind a growth.
        let mut text = Zeroizing::new(String::with_capacity(
            self.relay.as_str().len()
                + self.code.len()
                + name.as_ref().map_or(0, String::len)
                + pairing.as_ref().map_or(0, |pairing| pairing.len())
                + 64,
        ));
        text.push_str(self.relay.as_str());
        text.push_str("/link#");
        text.push_str(&self.code);
        text.push_str("&r=");
        text.push_str(self.route.as_str());
        if let Some(name) = &name {
            text.push_str("&n=");
            text.push_str(name);
        }
        if let Some(expires_at) = self.expires_at {
            text.push_str("&e=");
            text.push_str(&expires_at.to_string());
        }
        if let Some(pairing) = &pairing {
            text.push_str("&p=");
            text.push_str(pairing);
        }
        text
    }

    /// Parse a scanned or pasted text: `<relay URL>/link#<code>[&key=value…]`, or a bare
    /// code (with or without parameters) on the relay `relay_url` of the settings.
    pub fn parse(text: &str, relay_url: &str) -> Result<Self, LinkPayloadError> {
        let parts = split_link(text)?;
        let relay = RelayUrl::parse(parts.relay.unwrap_or(relay_url))
            .map_err(|_| LinkPayloadError::InvalidRelayAddress)?;
        let mut route = None;
        let mut mac_name = None;
        let mut expires_at = None;
        let mut pairing = None;
        for pair in parts.params.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            // The first value of a key counts.
            match key {
                "r" if route.is_none() => {
                    route = Some(LinkRoute::parse(value).ok_or(LinkPayloadError::UnknownRoute)?);
                }
                "n" if mac_name.is_none() => mac_name = parse_name(value),
                "e" if expires_at.is_none() => expires_at = parse_expiry(value),
                "p" if pairing.is_none() => pairing = parse_pairing(value),
                _ => {}
            }
        }
        Ok(Self {
            relay,
            code: Zeroizing::new(parts.code.to_owned()),
            route: route.unwrap_or(LinkRoute::Sync),
            mac_name,
            expires_at,
            pairing,
        })
    }
}

/// The parts of a link text, before any check but the link code's.
pub(crate) struct LinkParts<'a> {
    /// The relay address before `/link#`; `None` for a bare code.
    pub(crate) relay: Option<&'a str>,
    /// The link code, valid.
    pub(crate) code: &'a str,
    /// The parameters after the code, without the first `&`.
    pub(crate) params: &'a str,
}

/// Split a link text into its relay address, its link code (before the first `&`),
/// and its parameters. The code must be valid ([`link_code_team`]).
pub(crate) fn split_link(text: &str) -> Result<LinkParts<'_>, LinkPayloadError> {
    let text = text.trim();
    if text.len() > MAX_LINK_BYTES {
        return Err(LinkPayloadError::NotALink);
    }
    let (relay, fragment) = match text.split_once("/link#") {
        Some((relay, fragment)) => (Some(relay), fragment),
        None => (None, text),
    };
    let (code, params) = fragment.split_once('&').unwrap_or((fragment, ""));
    if link_code_team(code).is_none() {
        return Err(LinkPayloadError::NotALink);
    }
    Ok(LinkParts {
        relay,
        code,
        params,
    })
}

fn parse_name(value: &str) -> Option<String> {
    let name = clean_name(&percent_decode(value)?, "");
    (!name.is_empty()).then_some(name)
}

/// A decimal number of at most 20 digits with no leading zero.
fn parse_expiry(value: &str) -> Option<u64> {
    let valid = !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && !value.starts_with('0');
    if valid { value.parse().ok() } else { None }
}

/// The pairing link in `p`: b64u of an `apassy://pair?` link of printable ASCII.
fn parse_pairing(value: &str) -> Option<Zeroizing<String>> {
    if value.len() > MAX_PAIRING_BYTES.div_ceil(3) * 4 {
        return None;
    }
    let bytes = Zeroizing::new(decode_b64u(value)?);
    let valid = bytes.len() <= MAX_PAIRING_BYTES
        && bytes.starts_with(PAIRING_PREFIX.as_bytes())
        && bytes.iter().all(|byte| byte.is_ascii_graphic());
    if !valid {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    Some(Zeroizing::new(text.to_owned()))
}

/// Decode `%XX` escapes. `None` for a broken escape or text that is not UTF-8. A `+`
/// stays a `+`.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "https://relay.example.test";
    const PAIRING: &str = "apassy://pair?v=1&h=Mac-mini.local,192.0.2.10&p=48620&c=5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU&s=s9IIzFKuwMPGM-IW92PJK8U5dG0y14hgHYP9lX4UI0g&n=Mac%20mini&e=1790000300";

    fn code() -> String {
        format!("apassy_lnk_t_7k2m5q4x3c_{}", "ab".repeat(32))
    }

    fn payload() -> RelayLinkPayload {
        RelayLinkPayload {
            relay: RelayUrl::parse(RELAY).unwrap(),
            code: Zeroizing::new(code()),
            route: LinkRoute::Connect,
            mac_name: Some("Rafał's Mac mini & co".to_owned()),
            expires_at: Some(1_790_000_600),
            pairing: Some(Zeroizing::new(PAIRING.to_owned())),
        }
    }

    #[test]
    fn a_built_link_parses_back_to_the_same_payload() {
        let built = payload();
        let link = built.link();
        assert!(
            link.starts_with(&format!("{RELAY}/link#{}&r=connect&n=", code())),
            "{}",
            link.as_str()
        );
        assert!(link.len() <= MAX_LINK_BYTES);
        let parsed = RelayLinkPayload::parse(&link, "").unwrap();
        assert_eq!(parsed, built);
        let sync = RelayLinkPayload::new(
            RelayUrl::parse(RELAY).unwrap(),
            Zeroizing::new(code()),
            LinkRoute::Sync,
        );
        assert_eq!(
            sync.link().as_str(),
            format!("{RELAY}/link#{}&r=sync", code())
        );
        assert_eq!(RelayLinkPayload::parse(&sync.link(), "").unwrap(), sync);
    }

    #[test]
    fn the_name_is_percent_encoded() {
        let link = payload().link();
        assert!(link.contains("&n=Rafa%C5%82%27s%20Mac%20mini%20%26%20co&e="));
        // A name with a broken escape or bytes that are not UTF-8 is dropped.
        for name in ["Mac%2", "Mac%zz", "%FF%FE", "%00%01"] {
            let text = format!("{RELAY}/link#{}&n={name}", code());
            let parsed = RelayLinkPayload::parse(&text, "").unwrap();
            assert_eq!(parsed.mac_name, None, "{name}");
        }
    }

    #[test]
    fn a_link_of_the_old_form_and_a_bare_code_still_parse() {
        let old = format!(" {RELAY}/link#{} ", code());
        let parsed = RelayLinkPayload::parse(&old, "").unwrap();
        assert_eq!(parsed.relay.as_str(), RELAY);
        assert_eq!(parsed.code.as_str(), code());
        assert_eq!(parsed.route, LinkRoute::Sync);
        assert_eq!(
            (parsed.mac_name, parsed.expires_at, parsed.pairing),
            (None, None, None)
        );

        let bare = RelayLinkPayload::parse(&code(), "http://127.0.0.1:8787").unwrap();
        assert_eq!(bare.relay.as_str(), "http://127.0.0.1:8787");
        assert_eq!(bare.route, LinkRoute::Sync);
        let bare = RelayLinkPayload::parse(&format!("{}&r=connect", code()), RELAY).unwrap();
        assert_eq!(bare.relay.as_str(), RELAY);
        assert_eq!(bare.route, LinkRoute::Connect);
        assert_eq!(
            RelayLinkPayload::parse(&code(), "http://relay.example.test:80").unwrap_err(),
            LinkPayloadError::InvalidRelayAddress
        );
    }

    #[test]
    fn a_missing_route_is_sync_and_an_unknown_one_is_refused() {
        let with =
            |params: &str| RelayLinkPayload::parse(&format!("{RELAY}/link#{}{params}", code()), "");
        assert_eq!(with("&n=Mac").unwrap().route, LinkRoute::Sync);
        assert_eq!(with("&r=connect&r=sync").unwrap().route, LinkRoute::Connect);
        for params in ["&r=share", "&r=", "&r=SYNC"] {
            assert_eq!(
                with(params).unwrap_err(),
                LinkPayloadError::UnknownRoute,
                "{params}"
            );
        }
        // Unknown keys, empty parts, and parts with no value are ignored.
        let parsed = with("&&x=1&future&r=connect&zz=%%").unwrap();
        assert_eq!(parsed.route, LinkRoute::Connect);
        assert_eq!(
            SyncError::from(LinkPayloadError::UnknownRoute),
            SyncError::Relay(RelayRefusal::Forbidden)
        );
    }

    #[test]
    fn a_bad_pairing_link_or_expiry_is_dropped() {
        let with = |params: &str| {
            RelayLinkPayload::parse(&format!("{RELAY}/link#{}&r=sync{params}", code()), "").unwrap()
        };
        for p in [
            "not*b64u".to_owned(),
            "QQ".to_owned(),
            encode_b64u(b"https://evil.example.test/pair?"),
            encode_b64u(b"apassy://pair?v=1 &h=x"),
            encode_b64u(&[b'a', 0xFF, 0xFE]),
            String::new(),
        ] {
            assert_eq!(with(&format!("&p={p}")).pairing, None, "{p}");
        }
        for e in ["", "0", "0123", "12a", "123456789012345678901"] {
            assert_eq!(with(&format!("&e={e}")).expires_at, None, "{e}");
        }
        assert_eq!(with("&e=1790000600").expires_at, Some(1_790_000_600));
    }

    #[test]
    fn very_long_values_are_cut_or_refused() {
        let long_name = "M".repeat(500);
        let parsed =
            RelayLinkPayload::parse(&format!("{RELAY}/link#{}&n={long_name}", code()), "").unwrap();
        assert_eq!(parsed.mac_name.unwrap().len(), 64);
        let long_pairing = encode_b64u(format!("{PAIRING_PREFIX}{}", "a".repeat(1100)).as_bytes());
        let parsed =
            RelayLinkPayload::parse(&format!("{RELAY}/link#{}&p={long_pairing}", code()), "")
                .unwrap();
        assert_eq!(parsed.pairing, None);
        let too_long = format!("{RELAY}/link#{}&x={}", code(), "a".repeat(MAX_LINK_BYTES));
        assert_eq!(
            RelayLinkPayload::parse(&too_long, "").unwrap_err(),
            LinkPayloadError::NotALink
        );
        let mut built = payload();
        built.mac_name = Some("Ż".repeat(200));
        let parsed = RelayLinkPayload::parse(&built.link(), "").unwrap();
        assert_eq!(parsed.mac_name.unwrap(), "Ż".repeat(32));
    }

    #[test]
    fn a_text_without_a_valid_code_is_not_a_link() {
        for text in [
            String::new(),
            "apassy_lnk_bad".to_owned(),
            format!("{RELAY}/link#"),
            format!("{RELAY}/link#&r=sync&{}", code()),
            format!("{RELAY}/link#{}x&r=sync", code()),
            "apassy_tcd_".repeat(3),
        ] {
            assert_eq!(
                RelayLinkPayload::parse(&text, RELAY).unwrap_err(),
                LinkPayloadError::NotALink,
                "{text}"
            );
        }
    }

    #[test]
    fn debug_hides_the_code_and_the_pairing_link() {
        let text = format!("{:?}", payload());
        assert!(!text.contains("apassy_lnk_"), "{text}");
        assert!(!text.contains("apassy://pair"), "{text}");
    }
}
