//! `apassy pair`: a node pairing link (node-pairing-v1 sections 5 to 7).
//!
//! `<origin>/pair#<team code>&pin=<pin>[&alt=<a>,<b>][&name=<name>]`: the team code is a
//! one-use `team_code` of kind `node` (relay directory 1005), 1 to 10 minutes, made by
//! the running node through its operator socket (`Command::NodeCode`). A Mac takes the
//! link and makes a new team on this node with `POST /v1/teams` (relay-sync-v1 §6).
//!
//! The link holds the code: it is printed on stdout once and never logged.

use std::path::Path;

use serde_json::json;

use super::config::admin_socket;
use super::serve::{self, ServeState};
use super::{NodeCliError, PROGRAM, node_dir, parse_options, qr, utc_text};
use crate::server::operator::{self, Command};

/// The longest link (node-pairing-v1 section 5, rule 3).
pub const MAX_LINK_BYTES: usize = 2048;
/// The most alternatives of a link.
pub const MAX_ALTERNATIVES: usize = 4;
/// The longest name, in Unicode scalar values.
pub const MAX_NAME_CHARS: usize = 40;
/// The default and the longest life of a node pairing code.
pub const DEFAULT_MINUTES: u64 = 10;

/// A node pairing link and what `--json` shows of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairLink {
    pub link: String,
    pub origin: String,
    pub pin: String,
    pub expires_at: u64,
}

/// The canonical percent-encoding of a display name (node-pairing-v1 section 7): control
/// characters, U+2028, and U+2029 are dropped, the rest is trimmed and cut to 40 scalar
/// values; each byte of `A-Za-z0-9-._~` is literal, every other byte is `%` and two
/// uppercase hex digits. `None` when nothing is left.
pub fn encode_name(name: &str) -> Option<String> {
    let clean: String = name
        .chars()
        .filter(|ch| !ch.is_control() && !matches!(ch, '\u{2028}' | '\u{2029}'))
        .collect();
    let clean: String = clean.trim().chars().take(MAX_NAME_CHARS).collect();
    let clean = clean.trim_end();
    if clean.is_empty() {
        return None;
    }
    let mut encoded = String::new();
    for byte in clean.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Some(encoded)
}

/// True for a DNS name of node-pairing-v1 section 7: lowercase LDH labels of 1 to 63
/// characters, no label that starts or ends with `-`, at least two labels, at most 253.
fn is_dns_name(text: &str) -> bool {
    let labels: Vec<&str> = text.split('.').collect();
    text.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// True when `alt` (a host without a port: a DNS name, an IPv4 address, or an IPv6
/// address in brackets) is an alternative that node-pairing-v1 section 7 allows next to
/// the origin's host: canonical text, not the origin's host, not unspecified, loopback,
/// or link-local.
pub fn is_alternative(alt: &str, origin_host: &str) -> bool {
    if alt == origin_host {
        return false;
    }
    if let Some(inner) = alt
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner.parse::<std::net::Ipv6Addr>().is_ok_and(|v6| {
            v6.to_string() == inner
                && !v6.is_unspecified()
                && !v6.is_loopback()
                && (v6.segments()[0] & 0xffc0) != 0xfe80
                && v6.to_ipv4_mapped().is_none()
        });
    }
    if let Ok(v4) = alt.parse::<std::net::Ipv4Addr>() {
        return v4.to_string() == alt
            && !v4.is_unspecified()
            && !v4.is_loopback()
            && !v4.is_link_local();
    }
    is_dns_name(alt)
}

/// The text of a node pairing link. `alternatives` are hosts of `is_alternative` (at
/// most four are used); `name` is the encoded name of `encode_name`.
pub fn pair_link(
    origin: &str,
    team_code: &str,
    pin: &str,
    alternatives: &[String],
    name: Option<&str>,
) -> Result<String, NodeCliError> {
    let mut link = format!("{origin}/pair#{team_code}&pin={pin}");
    if !alternatives.is_empty() {
        link.push_str("&alt=");
        link.push_str(
            &alternatives
                .iter()
                .take(MAX_ALTERNATIVES)
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(name) = name {
        link.push_str("&name=");
        link.push_str(name);
    }
    if link.len() > MAX_LINK_BYTES {
        return Err(NodeCliError::failed("The pairing link is too long."));
    }
    Ok(link)
}

/// True for a team code: `apassy_tcd_` and 64 lowercase hex characters.
fn is_team_code(code: &str) -> bool {
    code.strip_prefix("apassy_tcd_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The host of an origin `https://<host>:<port>`.
fn origin_host(origin: &str) -> &str {
    let rest = origin.strip_prefix("https://").unwrap_or(origin);
    rest.rsplit_once(':').map_or(rest, |(host, _)| host)
}

/// A new node pairing link of the node that runs in `dir`, valid for `minutes`.
pub fn make(dir: &Path, minutes: u64) -> Result<PairLink, NodeCliError> {
    if !(1..=DEFAULT_MINUTES).contains(&minutes) {
        return Err(NodeCliError::usage(format!(
            "--minutes is a number from 1 to {DEFAULT_MINUTES}."
        )));
    }
    let state = match ServeState::load(dir)? {
        Some(state) if serve::is_running(dir) => state,
        _ => {
            return Err(NodeCliError::not_running(format!(
                "The node is not running. Start it with `{PROGRAM} up` or `systemctl --user start apassy-node.service`."
            )));
        }
    };
    let answer = operator::send(&admin_socket(dir), &Command::NodeCode { minutes })
        .map_err(|error| NodeCliError::node(error.message))?;
    let code = answer["code"].as_str().filter(|code| is_team_code(code));
    let (Some(code), Some(expires_at)) = (code, answer["expires_at"].as_u64()) else {
        return Err(NodeCliError::node(
            "The node did not give a node pairing code.",
        ));
    };
    let host = origin_host(&state.origin);
    let alternatives: Vec<String> = state
        .alternatives
        .iter()
        .filter(|alt| is_alternative(alt, host))
        .take(MAX_ALTERNATIVES)
        .cloned()
        .collect();
    let name = encode_name(&state.name);
    let link = pair_link(
        &state.origin,
        code,
        &state.pin,
        &alternatives,
        name.as_deref(),
    )?;
    Ok(PairLink {
        link,
        origin: state.origin,
        pin: state.pin,
        expires_at,
    })
}

/// The `--json` form of a link: `{link, expires_at, pin, origin}`.
pub fn to_json(paired: &PairLink) -> serde_json::Value {
    json!({
        "link": paired.link,
        "expires_at": paired.expires_at,
        "pin": paired.pin,
        "origin": paired.origin,
    })
}

/// Prints a link for a person: what to do, the QR code, the link, the pin, the expiry.
pub fn print_text(paired: &PairLink) {
    println!(
        "Pair a Mac with this node: in Apassy on the Mac, choose \"Your own node\" and scan this code or paste the link. It works once."
    );
    println!();
    if let Some(code) = qr::render(&paired.link) {
        print!("{code}");
        println!();
    }
    println!("{}", paired.link);
    println!();
    println!("Node:    {}", paired.origin);
    println!("Pin:     {}", paired.pin);
    println!("Expires: {}", utc_text(paired.expires_at));
}

/// `apassy pair [--minutes N] [--json] [--data-dir DIR]`.
pub fn command(args: &[String]) -> Result<i32, NodeCliError> {
    let options = parse_options(args, &["minutes"], &[])?;
    let minutes = options.number("minutes", 1, DEFAULT_MINUTES, DEFAULT_MINUTES)?;
    let dir = node_dir(&options)?;
    let paired = make(&dir, minutes)?;
    if options.json {
        println!("{}", to_json(&paired));
    } else {
        print_text(&paired);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://100.64.0.7:8444";
    const PIN: &str = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE";
    const TEAM_CODE: &str =
        "apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    /// node-pairing-v1 section 12, accepted link 3.
    const VECTOR_3: &str = "https://100.64.0.7:8444/pair#apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=build-box";

    #[test]
    fn the_link_is_the_contract_vector() {
        let alternatives = vec![
            "apassy-mini.tail0123.ts.net".to_owned(),
            "[fd7a:115c:a1e0::7]:8444".to_owned(),
        ];
        let name = encode_name("build-box");
        let link = pair_link(ORIGIN, TEAM_CODE, PIN, &alternatives, name.as_deref()).unwrap();
        assert_eq!(link, VECTOR_3);
        let bare = pair_link(ORIGIN, TEAM_CODE, PIN, &[], None).unwrap();
        assert_eq!(bare, format!("{ORIGIN}/pair#{TEAM_CODE}&pin={PIN}"));
    }

    #[test]
    fn names_have_one_encoding() {
        assert_eq!(
            encode_name("Mac mini \u{201c}Studio\u{201d}").as_deref(),
            Some("Mac%20mini%20%E2%80%9CStudio%E2%80%9D")
        );
        assert_eq!(encode_name("a\nb\u{2028}c").as_deref(), Some("abc"));
        assert_eq!(encode_name("  \t ").as_deref(), None);
        let long = "a".repeat(41);
        assert_eq!(encode_name(&long), Some("a".repeat(40)));
        assert_eq!(encode_name("x~y.z_w-v").as_deref(), Some("x~y.z_w-v"));
    }

    #[test]
    fn alternatives_follow_the_contract() {
        let host = "100.64.0.7";
        for good in [
            "apassy-mini.tail0123.ts.net",
            "[fd7a:115c:a1e0::7]",
            "100.100.1.2",
        ] {
            assert!(is_alternative(good, host), "{good}");
        }
        for bad in [
            "100.64.0.7",
            "[FD7A:115C:A1E0::7]",
            "[fd7a:115c:a1e0:0:0:0:0:7]",
            "127.0.0.1",
            "0.0.0.0",
            "[::]",
            "[::1]",
            "[fe80::1]",
            "169.254.1.1",
            "localhost",
            "Build-Box.ts.net",
            "-a.ts.net",
            "a..ts.net",
            "a.ts.net.",
        ] {
            assert!(!is_alternative(bad, host), "{bad}");
        }
    }

    #[test]
    fn team_codes_and_origin_hosts() {
        assert!(is_team_code(TEAM_CODE));
        assert!(!is_team_code("apassy_tcd_CDCD"));
        assert!(!is_team_code(
            "apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab"
        ));
        assert_eq!(origin_host(ORIGIN), "100.64.0.7");
    }

    #[test]
    fn a_node_that_does_not_run_cannot_pair() {
        let dir = tempfile::tempdir().unwrap();
        let error = make(dir.path(), 10).unwrap_err();
        assert_eq!(error.code, 3);
        assert_eq!(make(dir.path(), 11).unwrap_err().code, 2);
        assert_eq!(make(dir.path(), 0).unwrap_err().code, 2);
    }
}
