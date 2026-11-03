//! The links of contract node-pairing-v1 (sections 5 to 9): the **device link**
//! `<origin>/link#<link code>` that a new device of a team scans or pastes, and the
//! **node pairing link** `<origin>/pair#<team code>` that `apassy pair` makes on a node.
//!
//! The fragment carries the pin of the node and its other destinations
//! (`&pin=…&alt=…&name=…`) and, for an iPhone, the ADR 0032 handoff (`&handoff=…`,
//! always last). A link without a pin is a hosted link: today's form, system trust. The
//! fragment never reaches a server: [`PairedLink::url`] gives the address with its trust,
//! and only the code goes to the relay.
//!
//! [`PairedLink::parse`] reads the whole text with the grammar of section 5 and refuses a
//! link with the first reason of section 7 ([`LinkRefusal`]); a refusal makes no request.
//! Every refusal shows one text ([`LINK_INVALID_TEXT`]), except a key of a later contract
//! version, which asks for an update ([`LINK_UPDATE_TEXT`], section 5 rule 5).
//! [`PairedLink::format`] writes a link that this reader takes.

use std::fmt;

use zeroize::Zeroizing;

use crate::broker::http::Pin;
use crate::sync::SyncError;
use crate::sync::relay_crypto::{decode_b64u, link_code_team, valid_team_code};
use crate::sync::relay_http::{MAX_ALTERNATIVES, RelayUrl, TlsTrust, split_host_port};

/// The longest link, in bytes, after the white space at its ends goes (section 5 rule 3).
pub const MAX_LINK_BYTES: usize = 2048;
/// The most Unicode scalar values of a node name (section 7).
pub const MAX_NODE_NAME_CHARS: usize = 40;
/// What every refused link shows (section 7, the iPhone core's `link_invalid`).
pub const LINK_INVALID_TEXT: &str = "This code isn't valid. Make a new code on the node.";
/// What a link with a key of a later contract version shows (section 5 rule 5).
pub const LINK_UPDATE_TEXT: &str = "Update Apassy to use this code.";
/// What a device shows when a pinned node presents another certificate (section 4).
pub const PIN_CHANGED_TEXT: &str = "This node's certificate changed. Pair again.";

/// The keys of the fragment, in their order (section 5 rule 1).
const KEYS: [&str; 4] = ["pin", "alt", "name", "handoff"];

/// What a link is for (section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// `/link#`: a new device joins an existing team (`POST /v1/devices/link`).
    Device,
    /// `/pair#`: a Mac makes a new team on a node (`POST /v1/teams` with a team code of
    /// kind `node`).
    Pair,
}

/// Why a link was refused, in the precedence of section 7: when a link has several
/// faults, the reason is the first of this list. Reasons are for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRefusal {
    TooLong,
    /// No `/link#` or `/pair#`, a `?`, a second `#`, or an origin of another form than
    /// section 3.
    BadOrigin,
    UnknownKey,
    RepeatedKey,
    KeyOrder,
    EmptyValue,
    BadCode,
    NeedsPin,
    HandoffOnPair,
    BadPin,
    BadAlt,
    BadName,
    BadHandoff,
}

impl LinkRefusal {
    /// The reason as the contract writes it, for example `bad_pin`.
    pub fn reason(self) -> &'static str {
        match self {
            Self::TooLong => "too_long",
            Self::BadOrigin => "bad_origin",
            Self::UnknownKey => "unknown_key",
            Self::RepeatedKey => "repeated_key",
            Self::KeyOrder => "key_order",
            Self::EmptyValue => "empty_value",
            Self::BadCode => "bad_code",
            Self::NeedsPin => "needs_pin",
            Self::HandoffOnPair => "handoff_on_pair",
            Self::BadPin => "bad_pin",
            Self::BadAlt => "bad_alt",
            Self::BadName => "bad_name",
            Self::BadHandoff => "bad_handoff",
        }
    }

    /// The text for the owner.
    pub fn message(self) -> &'static str {
        match self {
            Self::UnknownKey => LINK_UPDATE_TEXT,
            _ => LINK_INVALID_TEXT,
        }
    }
}

impl fmt::Display for LinkRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// A link that passed the grammar (section 9 step 1). The code and the handoff are
/// secrets: they are erased on drop, and Debug leaves them out.
#[derive(Clone, PartialEq, Eq)]
pub struct PairedLink {
    pub kind: LinkKind,
    /// The origin, the value that the device stores, signs, and shows.
    pub origin: String,
    /// The link code (`apassy_lnk_…`) or the team code of kind node (`apassy_tcd_…`).
    pub code: Zeroizing<String>,
    pub pin: Option<Pin>,
    /// The alternative destinations, `host:port` each with the port written, in order.
    pub alt: Vec<String>,
    /// The node's display name, decoded: a label, never an authority.
    pub name: Option<String>,
    /// The ADR 0032 handoff (`2.<qid>.<secret>.<key>`), unchanged bytes.
    pub handoff: Option<Zeroizing<String>>,
    /// "The original full link without handoff" of the handoff AAD and of the safety
    /// words (section 8): the text up to, not including, `&handoff=`.
    pub without_handoff: Zeroizing<String>,
}

impl fmt::Debug for PairedLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedLink")
            .field("kind", &self.kind)
            .field("origin", &self.origin)
            .field("pin", &self.pin)
            .field("alt", &self.alt)
            .field("name", &self.name)
            .field("handoff", &self.handoff.is_some())
            .finish_non_exhaustive()
    }
}

impl PairedLink {
    /// Read `text` (a scanned or pasted link) with the grammar of node-pairing-v1. The
    /// ASCII white space at both ends goes, nothing inside.
    pub fn parse(text: &str) -> Result<Self, LinkRefusal> {
        let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
        if text.len() > MAX_LINK_BYTES {
            return Err(LinkRefusal::TooLong);
        }
        let (base, fragment) = text.split_once('#').ok_or(LinkRefusal::BadOrigin)?;
        if fragment.contains('#') || text.contains('?') {
            return Err(LinkRefusal::BadOrigin);
        }
        let (origin, kind) = if let Some(origin) = base.strip_suffix("/link") {
            (origin, LinkKind::Device)
        } else if let Some(origin) = base.strip_suffix("/pair") {
            (origin, LinkKind::Pair)
        } else {
            return Err(LinkRefusal::BadOrigin);
        };
        let mut parts = fragment.split('&');
        let code = parts.next().unwrap_or_default();
        let params: Vec<(Option<usize>, &str)> = parts
            .map(|part| match part.split_once('=') {
                Some((key, value)) => (KEYS.iter().position(|known| *known == key), value),
                None => (None, ""),
            })
            .collect();
        // The precedence of section 7: each category over all parameters.
        if params.iter().any(|(index, _)| index.is_none()) {
            return Err(LinkRefusal::UnknownKey);
        }
        let indexes: Vec<usize> = params.iter().filter_map(|(index, _)| *index).collect();
        for (n, index) in indexes.iter().enumerate() {
            if indexes[..n].contains(index) {
                return Err(LinkRefusal::RepeatedKey);
            }
        }
        if indexes.windows(2).any(|pair| pair[1] < pair[0]) {
            return Err(LinkRefusal::KeyOrder);
        }
        if params.iter().any(|(_, value)| value.is_empty()) {
            return Err(LinkRefusal::EmptyValue);
        }
        let mut values: [Option<&str>; 4] = [None; 4];
        for (index, value) in &params {
            if let Some(index) = index {
                values[*index] = Some(*value);
            }
        }
        let [pin, alt, name, handoff] = values;

        let code_ok = match kind {
            LinkKind::Device => link_code_team(code).is_some(),
            LinkKind::Pair => valid_team_code(code),
        };
        if !code_ok {
            return Err(LinkRefusal::BadCode);
        }
        if pin.is_none() && (alt.is_some() || name.is_some() || kind == LinkKind::Pair) {
            return Err(LinkRefusal::NeedsPin);
        }
        if kind == LinkKind::Pair && handoff.is_some() {
            return Err(LinkRefusal::HandoffOnPair);
        }
        let (origin_host, origin_port) = parse_origin(origin, pin.is_some())?;
        let pin = match pin {
            Some(text) => Some(Pin::parse(text).ok_or(LinkRefusal::BadPin)?),
            None => None,
        };
        let alt = match alt {
            Some(list) => parse_alt(list, &origin_host, origin_port)?,
            None => Vec::new(),
        };
        let name = name.map(decode_node_name).transpose()?;
        if let Some(handoff) = handoff
            && !valid_handoff(handoff)
        {
            return Err(LinkRefusal::BadHandoff);
        }
        let without_handoff = text
            .split_once("&handoff=")
            .map_or(text, |(raw, _)| raw)
            .to_owned();
        Ok(Self {
            kind,
            origin: origin.to_owned(),
            code: Zeroizing::new(code.to_owned()),
            pin,
            alt,
            name,
            handoff: handoff.map(|text| Zeroizing::new(text.to_owned())),
            without_handoff: Zeroizing::new(without_handoff),
        })
    }

    /// The trust of the link: pinned when it has a pin (section 9 step 2).
    pub fn trust(&self) -> TlsTrust {
        self.pin.map_or(TlsTrust::System, TlsTrust::Pinned)
    }

    /// The address to connect to: the origin with the trust and the alternatives of the
    /// link. The pin, the alternatives, and the name never go to a server.
    pub fn url(&self) -> Result<RelayUrl, SyncError> {
        RelayUrl::parse_with_trust(&self.origin, self.trust())?.alternatives(&self.alt)
    }

    /// Write a link of `kind` for `url` (its origin, pin, and alternatives) with `code`
    /// and the node name `name`, cut to its limits ([`clean_node_name`]). The link has no
    /// handoff: the ADR 0032 channel appends it (`PairingChannel::link`). The result
    /// passes [`Self::parse`]; else the reason, for example `NeedsPin` for a pair link of
    /// a hosted address, or `BadAlt` for a loopback alternative.
    pub fn format(
        kind: LinkKind,
        url: &RelayUrl,
        code: &str,
        name: Option<&str>,
    ) -> Result<Zeroizing<String>, LinkRefusal> {
        let path = match kind {
            LinkKind::Device => "link",
            LinkKind::Pair => "pair",
        };
        let mut link = Zeroizing::new(format!("{}/{path}#{code}", url.as_str()));
        if let Some(pin) = url.pin() {
            link.push_str("&pin=");
            link.push_str(&pin.text());
            let alt = url.alternative_list();
            if !alt.is_empty() {
                link.push_str("&alt=");
                link.push_str(&alt.join(","));
            }
            if let Some(name) = name.and_then(clean_node_name) {
                link.push_str("&name=");
                link.push_str(&encode_node_name(&name));
            }
        }
        let parsed = Self::parse(&link)?;
        if parsed.kind != kind || parsed.handoff.is_some() {
            return Err(LinkRefusal::BadCode);
        }
        Ok(link)
    }
}

/// Section 3. A pinned origin is `https://host:port` with an explicit port other than
/// 443. Any origin is also a relay address of this app (`RelayUrl::parse`), in its
/// canonical text.
fn parse_origin(origin: &str, pinned: bool) -> Result<(String, u16), LinkRefusal> {
    let rest = match origin.strip_prefix("https://") {
        Some(rest) => rest,
        None if pinned => return Err(LinkRefusal::BadOrigin),
        None => origin
            .strip_prefix("http://")
            .ok_or(LinkRefusal::BadOrigin)?,
    };
    if rest.contains('/') || rest.contains('@') {
        return Err(LinkRefusal::BadOrigin);
    }
    let (host, port) = split_host_port(rest).ok_or(LinkRefusal::BadOrigin)?;
    if pinned && (port.is_none() || port == Some(443)) {
        return Err(LinkRefusal::BadOrigin);
    }
    let url = RelayUrl::parse(origin).map_err(|_| LinkRefusal::BadOrigin)?;
    if url.as_str() != origin && !(port == Some(443) && !pinned) {
        return Err(LinkRefusal::BadOrigin);
    }
    let bare = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    Ok((bare, port.unwrap_or(443)))
}

/// Whether the host of an alternative is a loopback, an unspecified, or a link-local
/// address (section 7).
fn local_or_unspecified(host: &str) -> bool {
    if let Some(inside) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inside.parse::<std::net::Ipv6Addr>().is_ok_and(|address| {
            address.is_loopback()
                || address.is_unspecified()
                || (address.segments()[0] & 0xffc0) == 0xfe80
        });
    }
    host.parse::<std::net::Ipv4Addr>().is_ok_and(|address| {
        address.is_loopback() || address.is_unspecified() || address.is_link_local()
    })
}

/// The alternatives of section 7: 1 to 4 entries, each `host[:port]` with the origin's
/// port when it has none; the origin itself, a repeated entry, a loopback, an
/// unspecified, or a link-local address is `BadAlt`.
fn parse_alt(list: &str, origin_host: &str, origin_port: u16) -> Result<Vec<String>, LinkRefusal> {
    let entries: Vec<&str> = list.split(',').collect();
    if entries.is_empty() || entries.len() > MAX_ALTERNATIVES {
        return Err(LinkRefusal::BadAlt);
    }
    let mut out: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let (host, port) = split_host_port(entry).ok_or(LinkRefusal::BadAlt)?;
        let port = port.unwrap_or(origin_port);
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if local_or_unspecified(&host) || (bare == origin_host && port == origin_port) {
            return Err(LinkRefusal::BadAlt);
        }
        let text = format!("{host}:{port}");
        if out.contains(&text) {
            return Err(LinkRefusal::BadAlt);
        }
        out.push(text);
    }
    Ok(out)
}

/// A byte that the name writes literally (RFC 3986 unreserved).
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Whether a decoded name has a character that a name must not have.
fn forbidden_name_char(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

/// The canonical percent-encoding of a node name (section 7): each byte of
/// `A-Za-z0-9-._~` literal, every other byte `%` and two uppercase hex digits.
pub fn encode_node_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() * 3);
    for byte in name.bytes() {
        if unreserved(byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A machine name as a node name: trimmed, without control characters, U+2028, and
/// U+2029, cut to [`MAX_NODE_NAME_CHARS`]. `None` when nothing is left.
pub fn clean_node_name(text: &str) -> Option<String> {
    let name: String = text
        .trim()
        .chars()
        .filter(|c| !forbidden_name_char(*c))
        .take(MAX_NODE_NAME_CHARS)
        .collect();
    let name = name.trim().to_owned();
    (!name.is_empty()).then_some(name)
}

/// Decode a name of a link: only the canonical encoding, valid UTF-8, 1 to 40 scalar
/// values, and no control character, U+2028, or U+2029 (`BadName` otherwise).
fn decode_node_name(text: &str) -> Result<String, LinkRefusal> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if unreserved(byte) {
            out.push(byte);
            i += 1;
            continue;
        }
        if byte != b'%' {
            return Err(LinkRefusal::BadName);
        }
        let hex = bytes.get(i + 1..i + 3).ok_or(LinkRefusal::BadName)?;
        if !hex
            .iter()
            .all(|h| h.is_ascii_digit() || (b'A'..=b'F').contains(h))
        {
            return Err(LinkRefusal::BadName);
        }
        let hex = std::str::from_utf8(hex).map_err(|_| LinkRefusal::BadName)?;
        let value = u8::from_str_radix(hex, 16).map_err(|_| LinkRefusal::BadName)?;
        if unreserved(value) {
            return Err(LinkRefusal::BadName);
        }
        out.push(value);
        i += 3;
    }
    let name = String::from_utf8(out).map_err(|_| LinkRefusal::BadName)?;
    let count = name.chars().count();
    if !(1..=MAX_NODE_NAME_CHARS).contains(&count) || name.chars().any(forbidden_name_char) {
        return Err(LinkRefusal::BadName);
    }
    Ok(name)
}

/// The handoff of relay-questions-v1 section 21: `2.<qid>.<32 bytes>.<a P-256 point>`.
fn valid_handoff(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    let [version, qid, secret, public] = parts.as_slice() else {
        return false;
    };
    *version == "2"
        && crate::questions::envelope::valid_qid(qid)
        && decode_b64u(secret).is_some_and(|bytes| bytes.len() == 32)
        && decode_b64u(public).is_some_and(|bytes| {
            bytes.len() == 65 && p256::PublicKey::from_sec1_bytes(&bytes).is_ok()
        })
}

#[cfg(test)]
mod tests {
    //! The test table of contract node-pairing-v1 section 12: every accepted link, and
    //! every refused link with its reason.
    use super::*;

    const PIN: &str = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE";
    const ORIGIN: &str = "https://100.64.0.7:8444";
    const LINK_CODE: &str =
        "apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab";
    const TEAM_CODE: &str =
        "apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const NAME: &str = "Mac mini “Studio”";
    const NAME_ENCODED: &str = "Mac%20mini%20%E2%80%9CStudio%E2%80%9D";
    const ALT: &str = "apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444";
    const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
    const HANDOFF_SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const MAC_PUBLIC: &str =
        "BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";
    const FULL_LINK: &str = "https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=Mac%20mini%20%E2%80%9CStudio%E2%80%9D&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";
    const FULL_WITHOUT_HANDOFF: &str = "https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=Mac%20mini%20%E2%80%9CStudio%E2%80%9D";
    const PIN_HANDOFF_LINK: &str = "https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";
    const PAIR_LINK: &str = "https://100.64.0.7:8444/pair#apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=build-box";
    const HOSTED_LINK: &str = "https://apassy-relay.wyderka.cc/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";

    fn handoff() -> String {
        format!("2.{QID}.{HANDOFF_SECRET}.{MAC_PUBLIC}")
    }

    fn pin() -> Pin {
        Pin::parse(PIN).unwrap()
    }

    /// The refused links of section 12: each is link 1 or link 3 with one change.
    fn refused() -> Vec<(String, LinkRefusal)> {
        let handoff = handoff();
        let pin_pair = format!("pin={PIN}");
        let second_pin = format!("&pin={PIN}&alt=");
        let short_pin = &PIN[..42];
        let padded_pin = format!("{short_pin}F");
        let with_alt = |list: &str| FULL_LINK.replace(ALT, list);
        let with_name = |name: &str| FULL_LINK.replace(NAME_ENCODED, name);
        let mut too_long = format!("{FULL_LINK}&x=");
        too_long.push_str(&"a".repeat(MAX_LINK_BYTES + 1 - too_long.len()));
        vec![
            (
                FULL_LINK.replace("&handoff=", "&foo=1&handoff="),
                LinkRefusal::UnknownKey,
            ),
            (
                FULL_LINK.replace("&alt=", &second_pin),
                LinkRefusal::RepeatedKey,
            ),
            (
                format!("{ORIGIN}/link#{LINK_CODE}&name={NAME_ENCODED}&pin={PIN}"),
                LinkRefusal::KeyOrder,
            ),
            (
                format!("{ORIGIN}/link#{LINK_CODE}&handoff={handoff}&pin={PIN}"),
                LinkRefusal::KeyOrder,
            ),
            (
                HOSTED_LINK.replace("&handoff=", "&alt=relay2.example.com&handoff="),
                LinkRefusal::NeedsPin,
            ),
            (
                FULL_LINK.replace(pin_pair.as_str(), "pin="),
                LinkRefusal::EmptyValue,
            ),
            (FULL_LINK.replace(PIN, short_pin), LinkRefusal::BadPin),
            (FULL_LINK.replace(PIN, &padded_pin), LinkRefusal::BadPin),
            (
                FULL_LINK.replacen("https://", "http://", 1),
                LinkRefusal::BadOrigin,
            ),
            (
                FULL_LINK.replacen(
                    "https://100.64.0.7:8444/link#",
                    "https://100.64.0.7/link#",
                    1,
                ),
                LinkRefusal::BadOrigin,
            ),
            (
                FULL_LINK.replacen(":8444/link#", ":8444//link#", 1),
                LinkRefusal::BadOrigin,
            ),
            (
                with_alt("a.example.com,b.example.com,c.example.com,d.example.com,e.example.com"),
                LinkRefusal::BadAlt,
            ),
            (with_alt("100.64.0.7:8444"), LinkRefusal::BadAlt),
            (with_alt("[FD7A:115C:A1E0::7]"), LinkRefusal::BadAlt),
            (with_alt("127.0.0.1"), LinkRefusal::BadAlt),
            (
                with_name("Mac%20mini%20%e2%80%9cStudio%e2%80%9d"),
                LinkRefusal::BadName,
            ),
            (with_name("%4Dac"), LinkRefusal::BadName),
            (with_name("Mac%0Amini"), LinkRefusal::BadName),
            (with_name(&"a".repeat(41)), LinkRefusal::BadName),
            (
                PAIR_LINK.replace(TEAM_CODE, LINK_CODE),
                LinkRefusal::BadCode,
            ),
            (
                format!("{PAIR_LINK}&handoff={handoff}"),
                LinkRefusal::HandoffOnPair,
            ),
            (format!("{ORIGIN}/pair#{TEAM_CODE}"), LinkRefusal::NeedsPin),
            (too_long, LinkRefusal::TooLong),
        ]
    }

    #[test]
    fn link_1_with_every_key_parses_to_the_vectors_of_the_contract() {
        assert_eq!(FULL_LINK.len(), 430);
        let full = PairedLink::parse(&format!(" \n{FULL_LINK}\n")).expect("link 1");
        assert_eq!(full.kind, LinkKind::Device);
        assert_eq!(full.origin, ORIGIN);
        assert_eq!(full.code.as_str(), LINK_CODE);
        assert_eq!(full.pin, Some(pin()));
        assert_eq!(
            full.alt,
            [
                "apassy-mini.tail0123.ts.net:8444",
                "[fd7a:115c:a1e0::7]:8444"
            ]
        );
        assert_eq!(full.name.as_deref(), Some(NAME));
        assert_eq!(
            full.handoff.as_deref().map(String::as_str),
            Some(handoff().as_str())
        );
        assert_eq!(full.without_handoff.as_str(), FULL_WITHOUT_HANDOFF);
        assert_eq!(full.trust(), TlsTrust::Pinned(pin()));
        // The address carries the pin and the alternatives; the origin stays the value.
        let url = full.url().unwrap();
        assert_eq!(url.as_str(), ORIGIN);
        assert_eq!(url.pin(), Some(pin()));
        assert_eq!(url.alternative_list(), full.alt);
        // Debug shows no code and no handoff.
        let debug = format!("{full:?}");
        assert!(!debug.contains("apassy_lnk_") && !debug.contains(HANDOFF_SECRET));
    }

    #[test]
    fn links_2_to_4_parse_as_the_contract_says() {
        let pinned = PairedLink::parse(PIN_HANDOFF_LINK).expect("link 2");
        assert_eq!(pinned.pin, Some(pin()));
        assert!(pinned.alt.is_empty() && pinned.name.is_none());
        assert_eq!(
            pinned.handoff.as_deref().map(String::as_str),
            Some(handoff().as_str())
        );
        assert_eq!(
            pinned.without_handoff.as_str(),
            format!("{ORIGIN}/link#{LINK_CODE}&pin={PIN}")
        );

        let pair = PairedLink::parse(PAIR_LINK).expect("link 3");
        assert_eq!(pair.kind, LinkKind::Pair);
        assert_eq!(pair.code.as_str(), TEAM_CODE);
        assert_eq!(pair.name.as_deref(), Some("build-box"));
        assert!(pair.handoff.is_none());
        assert_eq!(pair.without_handoff.as_str(), PAIR_LINK);

        let hosted = PairedLink::parse(HOSTED_LINK).expect("link 4");
        assert!(hosted.pin.is_none());
        assert_eq!(hosted.trust(), TlsTrust::System);
        assert_eq!(
            hosted.without_handoff.as_str(),
            format!("https://apassy-relay.wyderka.cc/link#{LINK_CODE}")
        );
        assert_eq!(hosted.url().unwrap().trust(), TlsTrust::System);
        // A hosted link without a handoff, and one of a loopback relay, as before.
        let local = format!("http://127.0.0.1:8787/link#{LINK_CODE}");
        assert_eq!(
            PairedLink::parse(&local).unwrap().url().unwrap().as_str(),
            "http://127.0.0.1:8787"
        );
    }

    #[test]
    fn every_refused_link_of_the_contract_has_its_reason() {
        let table = refused();
        assert_eq!(table.len(), 23);
        for (text, reason) in table {
            assert_eq!(PairedLink::parse(&text).err(), Some(reason), "{text}");
            assert_eq!(reason.to_string(), reason.reason());
        }
    }

    #[test]
    fn more_refusals_follow_the_precedence_of_section_7() {
        let cases = [
            // A key without `=`, an empty part, and a key in another case are unknown.
            (
                format!("{ORIGIN}/link#{LINK_CODE}&pin"),
                LinkRefusal::UnknownKey,
            ),
            (
                format!("{ORIGIN}/link#{LINK_CODE}&"),
                LinkRefusal::UnknownKey,
            ),
            (
                format!("{ORIGIN}/link#{LINK_CODE}&PIN={PIN}"),
                LinkRefusal::UnknownKey,
            ),
            // A query or a second `#` is a bad origin, before any key.
            (
                format!("{ORIGIN}/link?x=1#{LINK_CODE}&foo=1"),
                LinkRefusal::BadOrigin,
            ),
            (
                format!("{ORIGIN}/link#{LINK_CODE}#&foo=1"),
                LinkRefusal::BadOrigin,
            ),
            (format!("{ORIGIN}/join#{LINK_CODE}"), LinkRefusal::BadOrigin),
            (LINK_CODE.to_owned(), LinkRefusal::BadOrigin),
            // An unknown key before a bad code; a bad code before a missing pin.
            (
                format!("{ORIGIN}/pair#apassy_tcd_bad&foo=1"),
                LinkRefusal::UnknownKey,
            ),
            (
                format!("{ORIGIN}/pair#apassy_tcd_bad"),
                LinkRefusal::BadCode,
            ),
            (
                format!("{ORIGIN}/link#{TEAM_CODE}&pin={PIN}"),
                LinkRefusal::BadCode,
            ),
            // A name needs a pin too.
            (
                format!("https://relay.example.test/link#{LINK_CODE}&name=x"),
                LinkRefusal::NeedsPin,
            ),
            // An uppercase or non-canonical origin host, a user, and port 443.
            (
                format!("https://Relay.example.test:8444/link#{LINK_CODE}&pin={PIN}"),
                LinkRefusal::BadOrigin,
            ),
            (
                format!("https://100.64.0.07:8444/link#{LINK_CODE}&pin={PIN}"),
                LinkRefusal::BadOrigin,
            ),
            (
                format!("https://u@100.64.0.7:8444/link#{LINK_CODE}&pin={PIN}"),
                LinkRefusal::BadOrigin,
            ),
            (
                format!("https://100.64.0.7:443/link#{LINK_CODE}&pin={PIN}"),
                LinkRefusal::BadOrigin,
            ),
            (
                format!("https://100.64.0.7:08444/link#{LINK_CODE}&pin={PIN}"),
                LinkRefusal::BadOrigin,
            ),
            // A hosted origin that is not a relay address of this app.
            (
                format!("http://relay.example.test:80/link#{LINK_CODE}"),
                LinkRefusal::BadOrigin,
            ),
            // Alternatives: unspecified, link-local, and a repeated entry.
            (FULL_LINK.replace(ALT, "0.0.0.0"), LinkRefusal::BadAlt),
            (FULL_LINK.replace(ALT, "[::]"), LinkRefusal::BadAlt),
            (FULL_LINK.replace(ALT, "169.254.1.1"), LinkRefusal::BadAlt),
            (FULL_LINK.replace(ALT, "[fe80::1]"), LinkRefusal::BadAlt),
            (FULL_LINK.replace(ALT, "[::1]"), LinkRefusal::BadAlt),
            (
                FULL_LINK.replace(ALT, "b.example.com,b.example.com:8444"),
                LinkRefusal::BadAlt,
            ),
            // Names: a separator, an invalid UTF-8 sequence, a cut escape.
            (
                FULL_LINK.replace(NAME_ENCODED, "%E2%80%A8"),
                LinkRefusal::BadName,
            ),
            (FULL_LINK.replace(NAME_ENCODED, "%FF"), LinkRefusal::BadName),
            (
                FULL_LINK.replace(NAME_ENCODED, "Mac%2"),
                LinkRefusal::BadName,
            ),
            (
                FULL_LINK.replace(NAME_ENCODED, "Mac+mini"),
                LinkRefusal::BadName,
            ),
            // A handoff of another version or with a short secret.
            (
                FULL_LINK.replace("&handoff=2.", "&handoff=3."),
                LinkRefusal::BadHandoff,
            ),
            (
                FULL_LINK.replace(HANDOFF_SECRET, &HANDOFF_SECRET[..42]),
                LinkRefusal::BadHandoff,
            ),
        ];
        for (text, reason) in cases {
            assert_eq!(PairedLink::parse(&text).err(), Some(reason), "{text}");
        }
        // 40 letters are a name.
        let forty = FULL_LINK.replace(NAME_ENCODED, &"a".repeat(40));
        assert_eq!(
            PairedLink::parse(&forty).unwrap().name,
            Some("a".repeat(40))
        );
    }

    #[test]
    fn refusals_show_one_text_and_a_later_key_asks_for_an_update() {
        assert_eq!(LinkRefusal::BadPin.message(), LINK_INVALID_TEXT);
        assert_eq!(LinkRefusal::TooLong.message(), LINK_INVALID_TEXT);
        assert_eq!(LinkRefusal::UnknownKey.message(), LINK_UPDATE_TEXT);
        assert_eq!(
            SyncError::LinkInvalid(LinkRefusal::BadAlt).to_string(),
            LINK_INVALID_TEXT
        );
        assert_eq!(SyncError::PinMismatch.to_string(), PIN_CHANGED_TEXT);
    }

    #[test]
    fn a_written_link_reads_back_and_carries_the_pin_and_alternatives() {
        let url = RelayUrl::parse_with_trust(ORIGIN, TlsTrust::Pinned(pin()))
            .unwrap()
            .alternatives(&[
                "apassy-mini.tail0123.ts.net".to_owned(),
                "[fd7a:115c:a1e0::7]:8444".to_owned(),
            ])
            .unwrap();
        let link = PairedLink::format(LinkKind::Device, &url, LINK_CODE, Some(NAME)).unwrap();
        assert_eq!(
            link.as_str(),
            format!(
                "{ORIGIN}/link#{LINK_CODE}&pin={PIN}&alt=apassy-mini.tail0123.ts.net:8444,[fd7a:115c:a1e0::7]:8444&name={NAME_ENCODED}"
            )
        );
        let read = PairedLink::parse(&link).unwrap();
        assert_eq!(read.url().unwrap(), url);
        assert_eq!(read.name.as_deref(), Some(NAME));

        let pair = PairedLink::format(LinkKind::Pair, &url, TEAM_CODE, Some("build-box")).unwrap();
        assert_eq!(PairedLink::parse(&pair).unwrap().kind, LinkKind::Pair);
        // A long machine name is cut to 40 characters; control characters go.
        let long = format!("Mac\u{7}{}", "x".repeat(60));
        let named = PairedLink::format(LinkKind::Device, &url, LINK_CODE, Some(&long)).unwrap();
        let name = PairedLink::parse(&named).unwrap().name.unwrap();
        assert_eq!(name.chars().count(), MAX_NODE_NAME_CHARS);
        assert!(name.starts_with("Macx"));
        assert_eq!(clean_node_name(" \u{2028} "), None);

        // A hosted address writes today's link: no pin, no name.
        let hosted = RelayUrl::parse("https://apassy-relay.wyderka.cc").unwrap();
        let link = PairedLink::format(LinkKind::Device, &hosted, LINK_CODE, Some(NAME)).unwrap();
        assert_eq!(
            link.as_str(),
            format!("https://apassy-relay.wyderka.cc/link#{LINK_CODE}")
        );
        // A pair link needs a pin, and a link code is not a team code.
        assert_eq!(
            PairedLink::format(LinkKind::Pair, &hosted, TEAM_CODE, None).unwrap_err(),
            LinkRefusal::NeedsPin
        );
        assert_eq!(
            PairedLink::format(LinkKind::Pair, &url, LINK_CODE, None).unwrap_err(),
            LinkRefusal::BadCode
        );
        assert_eq!(encode_node_name("build-box"), "build-box");
        assert_eq!(encode_node_name(NAME), NAME_ENCODED);
    }

    /// `PendingJoin::parse_link`, the reader of the Mac and of the iPhone core, takes the
    /// same table: the accepted device links give the address with its trust, and every
    /// refused link is `LinkInvalid` with its reason, before any request.
    #[test]
    fn pending_join_reads_links_with_the_table_of_the_contract() {
        use crate::sync::{DEFAULT_RELAY_URL, PendingJoin};

        let (url, code) = PendingJoin::parse_link(FULL_LINK, DEFAULT_RELAY_URL).unwrap();
        assert_eq!(url.as_str(), ORIGIN);
        assert_eq!(url.pin(), Some(pin()));
        assert_eq!(
            url.alternative_list(),
            [
                "apassy-mini.tail0123.ts.net:8444",
                "[fd7a:115c:a1e0::7]:8444"
            ]
        );
        assert_eq!(
            code.as_str(),
            LINK_CODE,
            "the handoff never reaches the relay"
        );

        let (url, code) = PendingJoin::parse_link(PIN_HANDOFF_LINK, "").unwrap();
        assert_eq!(url.pin(), Some(pin()));
        assert!(url.alternative_list().is_empty());
        assert_eq!(code.as_str(), LINK_CODE);

        let (url, code) = PendingJoin::parse_link(HOSTED_LINK, DEFAULT_RELAY_URL).unwrap();
        assert_eq!(url.as_str(), "https://apassy-relay.wyderka.cc");
        assert_eq!(url.trust(), TlsTrust::System);
        assert_eq!(code.as_str(), LINK_CODE);

        // A bare code takes the field above it, with system trust, as before.
        let (url, code) = PendingJoin::parse_link(LINK_CODE, "http://localhost:8787").unwrap();
        assert_eq!(url.as_str(), "http://localhost:8787");
        assert_eq!(code.as_str(), LINK_CODE);
        let paired =
            PendingJoin::parse_paired(&format!(" {LINK_CODE} "), DEFAULT_RELAY_URL).unwrap();
        assert_eq!(
            paired.without_handoff.as_str(),
            format!("{DEFAULT_RELAY_URL}/link#{LINK_CODE}")
        );

        // The full parts of a pinned link, for the device that stores them.
        let paired = PendingJoin::parse_paired(FULL_LINK, "").unwrap();
        assert_eq!(paired.name.as_deref(), Some(NAME));
        assert_eq!(paired.without_handoff.as_str(), FULL_WITHOUT_HANDOFF);

        // A node pairing link is not a device link.
        assert_eq!(
            PendingJoin::parse_link(PAIR_LINK, DEFAULT_RELAY_URL).unwrap_err(),
            SyncError::LinkInvalid(LinkRefusal::BadCode)
        );
        for (text, reason) in refused() {
            assert_eq!(
                PendingJoin::parse_link(&text, DEFAULT_RELAY_URL).unwrap_err(),
                SyncError::LinkInvalid(reason),
                "{text}"
            );
        }
    }
}
