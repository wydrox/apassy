//! Placeholders and the swap rules of the run proxy (ADR 0011).
//!
//! A placeholder has the length of the real value, and it keeps a known vendor prefix
//! such as `sk_live_`. Tools that check the form of a key still accept it, and the
//! proxy can swap it in both directions without a change of length. The rest is
//! random. It never contains a character of the real value.
//!
//! The proxy puts the real value only into an authentication position: the
//! `Authorization` header, a known API key header, or a known API key query parameter.
//! A placeholder in any other place of a request (path, other header, body) stops the
//! request. A real value would there become data that the service stores or returns.

use zeroize::Zeroizing;

use super::HostRule;
use super::http1::RequestHead;
use crate::native::base64;

/// Vendor prefixes that a placeholder keeps. The longest match wins. Only listed
/// prefixes are kept, so a placeholder never repeats a random part of a value.
const KNOWN_PREFIXES: [&str; 40] = [
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "pk_live_",
    "pk_test_",
    "whsec_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xapp-",
    "sk-ant-api03-",
    "sk-ant-admin01-",
    "sk-ant-",
    "sk-proj-",
    "sk-svcacct-",
    "sk-",
    "npm_",
    "hf_",
    "dop_v1_",
    "pypi-",
    "shpat_",
    "shpss_",
    "lin_api_",
    "secret_",
    "ntn_",
    "sq0atp-",
    "sq0csp-",
    "SG.",
    "AKIA",
    "ASIA",
    "re_",
    "vercel_",
];

/// Characters that keep their place in a placeholder: they are form, not secret.
const SEPARATORS: &[u8] = b"-_.=";

/// A placeholder needs at least this much randomness, in 1/100 bit.
const MIN_RANDOM_CENTIBITS: u32 = 64 * 100;

/// Headers that carry an API key on their own.
const KEY_HEADERS: [&str; 9] = [
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-api-token",
    "x-access-token",
    "private-token",
    "x-goog-api-key",
    "x-figma-token",
];

/// Query parameters that carry an API key.
const KEY_PARAMS: [&str; 7] = [
    "key",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "token",
    "auth",
];

#[derive(Clone, Copy)]
enum Alphabet {
    Digits,
    HexLower,
    HexUpper,
    Alnum,
}

impl Alphabet {
    fn chars(self) -> &'static [u8] {
        match self {
            Self::Digits => b"0123456789",
            Self::HexLower => b"0123456789abcdef",
            Self::HexUpper => b"0123456789ABCDEF",
            Self::Alnum => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        }
    }

    /// log2 of the size, in 1/100 bit, rounded down.
    fn centibits(self) -> u32 {
        match self {
            Self::Digits => 332,
            Self::HexLower | Self::HexUpper => 400,
            Self::Alnum => 595,
        }
    }

    fn of(rest: &[u8]) -> Self {
        let body = || rest.iter().filter(|b| !SEPARATORS.contains(b));
        if body().all(u8::is_ascii_digit) {
            Self::Digits
        } else if body().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
            Self::HexLower
        } else if body().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b)) {
            Self::HexUpper
        } else {
            Self::Alnum
        }
    }
}

fn prefix_of(value: &str) -> &'static str {
    KNOWN_PREFIXES
        .iter()
        .filter(|prefix| value.len() > prefix.len() && value.starts_with(*prefix))
        .max_by_key(|prefix| prefix.len())
        .copied()
        .unwrap_or("")
}

/// A random index below `n`, without modulo bias.
fn random_below(n: usize, pool: &mut Vec<u8>) -> Option<usize> {
    let n = u8::try_from(n).ok()?;
    let limit = u8::MAX - (u8::MAX % n);
    loop {
        if pool.is_empty() {
            let mut fresh = [0u8; 64];
            getrandom::fill(&mut fresh).ok()?;
            pool.extend_from_slice(&fresh);
        }
        let byte = pool.pop()?;
        if byte < limit {
            return Some(usize::from(byte % n));
        }
    }
}

/// A placeholder for `value`, or `None` when the value is too short to hide behind
/// one (less than 64 random bits) or the system has no random source.
pub fn mint_placeholder(value: &str) -> Option<String> {
    let prefix = prefix_of(value);
    let rest = &value.as_bytes()[prefix.len()..];
    let alphabet = Alphabet::of(rest);
    let random_places = rest.iter().filter(|b| !SEPARATORS.contains(b)).count();
    let bits = u32::try_from(random_places)
        .ok()?
        .saturating_mul(alphabet.centibits());
    if bits < MIN_RANDOM_CENTIBITS {
        return None;
    }
    let chars = alphabet.chars();
    let mut pool = Vec::new();
    loop {
        let mut out = String::with_capacity(value.len());
        out.push_str(prefix);
        for byte in rest {
            if SEPARATORS.contains(byte) {
                out.push(char::from(*byte));
            } else {
                out.push(char::from(chars[random_below(chars.len(), &mut pool)?]));
            }
        }
        if out != value {
            return Some(out);
        }
    }
}

/// One secret of a run, as the swap rules see it.
pub(super) struct SwapSecret<'a> {
    pub placeholder: &'a str,
    pub value: &'a str,
    pub hosts: &'a [HostRule],
}

/// Why the proxy stopped a request. The texts name no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The placeholder of secret `index` is in a place that is not an auth position.
    Misplaced { index: usize, place: String },
    /// The placeholder of secret `index` goes to a host that it is not for.
    WrongHost { index: usize },
}

/// The request head for the service, and the secrets that went into it.
pub(super) struct Swapped {
    pub head: Zeroizing<Vec<u8>>,
    pub used: Vec<usize>,
}

/// Headers that the proxy removes. `Accept-Encoding` goes so the response comes
/// back uncompressed and the proxy can find a real value in it.
fn dropped_header(lower: &str) -> bool {
    matches!(
        lower,
        "proxy-authorization" | "proxy-connection" | "accept-encoding" | "expect" | "te"
    )
}

/// Swap the placeholders in a request for `host:port`. Each placeholder must be in an
/// auth position and for this host. Otherwise the request stops.
pub(super) fn swap_request(
    head: &RequestHead,
    host: &str,
    port: u16,
    secrets: &[SwapSecret<'_>],
) -> Result<Swapped, Refusal> {
    let mut used = Vec::new();
    let mut take = |index: usize| -> Result<(), Refusal> {
        if !secrets[index]
            .hosts
            .iter()
            .any(|rule| rule.covers(host, port))
        {
            return Err(Refusal::WrongHost { index });
        }
        if !used.contains(&index) {
            used.push(index);
        }
        Ok(())
    };

    let target = swap_target(&head.target, secrets, &mut take)?;
    let mut headers: Vec<(&str, Zeroizing<String>)> = Vec::with_capacity(head.headers.len());
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if dropped_header(&lower) {
            continue;
        }
        let swapped = if lower == "authorization" {
            swap_authorization(value, secrets, &mut take)?
        } else if KEY_HEADERS.contains(&lower.as_str()) {
            swap_key_header(value, secrets, &mut take)?
        } else {
            None
        };
        let value = match swapped {
            Some(value) => value,
            None => {
                if let Some(index) = find_placeholder(value, secrets) {
                    return Err(Refusal::Misplaced {
                        index,
                        place: format!("the {name} header"),
                    });
                }
                Zeroizing::new(value.clone())
            }
        };
        headers.push((name.as_str(), value));
    }

    let size = head.method.len()
        + 1
        + target.len()
        + 11
        + headers
            .iter()
            .map(|(name, value)| name.len() + 2 + value.len() + 2)
            .sum::<usize>()
        + 2;
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    out.extend_from_slice(head.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in &headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(Swapped { head: out, used })
}

fn find_placeholder(text: &str, secrets: &[SwapSecret<'_>]) -> Option<usize> {
    secrets
        .iter()
        .position(|secret| text.contains(secret.placeholder))
}

fn exact_placeholder(text: &str, secrets: &[SwapSecret<'_>]) -> Option<usize> {
    secrets.iter().position(|secret| text == secret.placeholder)
}

/// `Authorization: <placeholder>`, `Authorization: <scheme> <placeholder>`, or Basic
/// with the placeholder as the user name or the password.
fn swap_authorization(
    value: &str,
    secrets: &[SwapSecret<'_>],
    take: &mut impl FnMut(usize) -> Result<(), Refusal>,
) -> Result<Option<Zeroizing<String>>, Refusal> {
    if let Some(index) = exact_placeholder(value, secrets) {
        take(index)?;
        return Ok(Some(Zeroizing::new(secrets[index].value.to_owned())));
    }
    let Some((scheme, credentials)) = value.split_once(' ') else {
        return Ok(None);
    };
    let credentials = credentials.trim();
    if scheme.eq_ignore_ascii_case("basic") {
        return swap_basic(scheme, credentials, secrets, take);
    }
    if let Some(index) = exact_placeholder(credentials, secrets) {
        take(index)?;
        let mut out = Zeroizing::new(String::with_capacity(
            scheme.len() + 1 + secrets[index].value.len(),
        ));
        out.push_str(scheme);
        out.push(' ');
        out.push_str(secrets[index].value);
        return Ok(Some(out));
    }
    Ok(None)
}

fn swap_basic(
    scheme: &str,
    credentials: &str,
    secrets: &[SwapSecret<'_>],
    take: &mut impl FnMut(usize) -> Result<(), Refusal>,
) -> Result<Option<Zeroizing<String>>, Refusal> {
    let Some(decoded) = base64::decode(credentials).map(Zeroizing::<Vec<u8>>::new) else {
        return Ok(None);
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return Ok(None);
    };
    let Some((user, password)) = text.split_once(':') else {
        return Ok(None);
    };
    let user_index = exact_placeholder(user, secrets);
    let password_index = exact_placeholder(password, secrets);
    if user_index.is_none() && password_index.is_none() {
        if let Some(index) = find_placeholder(text, secrets) {
            return Err(Refusal::Misplaced {
                index,
                place: "a part of the Basic credentials".to_owned(),
            });
        }
        return Ok(None);
    }
    let user = match user_index {
        Some(index) => {
            take(index)?;
            secrets[index].value
        }
        None => user,
    };
    let password = match password_index {
        Some(index) => {
            take(index)?;
            secrets[index].value
        }
        None => password,
    };
    let mut plain = Zeroizing::new(String::with_capacity(user.len() + 1 + password.len()));
    plain.push_str(user);
    plain.push(':');
    plain.push_str(password);
    let encoded = Zeroizing::new(base64::encode(plain.as_bytes()));
    let mut out = Zeroizing::new(String::with_capacity(scheme.len() + 1 + encoded.len()));
    out.push_str(scheme);
    out.push(' ');
    out.push_str(&encoded);
    Ok(Some(out))
}

/// `X-Api-Key: <placeholder>` or `X-Api-Key: Bearer <placeholder>`.
fn swap_key_header(
    value: &str,
    secrets: &[SwapSecret<'_>],
    take: &mut impl FnMut(usize) -> Result<(), Refusal>,
) -> Result<Option<Zeroizing<String>>, Refusal> {
    if let Some(index) = exact_placeholder(value, secrets) {
        take(index)?;
        return Ok(Some(Zeroizing::new(secrets[index].value.to_owned())));
    }
    swap_authorization(value, secrets, take)
}

/// Swap a placeholder in a known key parameter of the query. A placeholder in the
/// path or in another parameter stops the request.
fn swap_target(
    target: &str,
    secrets: &[SwapSecret<'_>],
    take: &mut impl FnMut(usize) -> Result<(), Refusal>,
) -> Result<Zeroizing<String>, Refusal> {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if let Some(index) =
        find_placeholder(path, secrets).or_else(|| find_placeholder(&percent_decode(path), secrets))
    {
        return Err(Refusal::Misplaced {
            index,
            place: "the URL path".to_owned(),
        });
    }
    let mut out = Zeroizing::new(String::with_capacity(target.len() + 64));
    out.push_str(path);
    let Some(query) = query else {
        return Ok(out);
    };
    out.push('?');
    for (position, pair) in query.split('&').enumerate() {
        if position > 0 {
            out.push('&');
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded = Zeroizing::new(percent_decode(value));
        let name_lower = percent_decode(name).to_ascii_lowercase();
        if let Some(index) = exact_placeholder(&decoded, secrets)
            && KEY_PARAMS.contains(&name_lower.as_str())
        {
            take(index)?;
            out.push_str(name);
            out.push('=');
            percent_encode_into(secrets[index].value, &mut out);
            continue;
        }
        if let Some(index) =
            find_placeholder(pair, secrets).or_else(|| find_placeholder(&decoded, secrets))
        {
            return Err(Refusal::Misplaced {
                index,
                place: format!("the query parameter {name}"),
            });
        }
        out.push_str(pair);
    }
    Ok(out)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(high * 16 + low);
            i += 3;
            continue;
        }
        out.push(if byte == b'+' { b' ' } else { byte });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_encode_into(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::proxy::http1::parse_request_head;

    fn rule(text: &str) -> HostRule {
        HostRule::parse(text).expect("host rule")
    }

    #[test]
    fn placeholder_keeps_length_prefix_and_form() {
        let value = "sk_live_FAKE-51HxAbCdEfGh-IjKlMnOpQr-StUv01234567";
        let placeholder = mint_placeholder(value).expect("placeholder");
        assert_eq!(placeholder.len(), value.len());
        assert!(placeholder.starts_with("sk_live_"));
        assert_ne!(placeholder, value);
        assert!(
            placeholder
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        );
        assert_eq!(
            placeholder.as_bytes()[12],
            b'-',
            "a separator keeps its place"
        );

        let hex = "0123456789abcdef0123456789abcdef";
        let placeholder = mint_placeholder(hex).expect("hex placeholder");
        assert!(
            placeholder
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );

        let uuid = "3f2b8c1e-9d4a-4e7f-b6a2-1c9e8d7f6a5b";
        let placeholder = mint_placeholder(uuid).expect("uuid placeholder");
        assert_eq!(placeholder.as_bytes()[8], b'-');
        assert_eq!(placeholder.as_bytes()[13], b'-');
    }

    #[test]
    fn placeholder_does_not_keep_an_unknown_prefix() {
        let value = "abc_DEFghiJKLmnoPQRstuVWXyz0123";
        let placeholder = mint_placeholder(value).expect("placeholder");
        assert_eq!(placeholder.as_bytes()[3], b'_');
        assert_ne!(&placeholder[..3], "abc", "an unknown prefix is random");
    }

    #[test]
    fn short_values_get_no_placeholder() {
        assert!(mint_placeholder("hunter2").is_none());
        assert!(mint_placeholder("1234567890123456").is_none(), "53 bits");
        assert!(mint_placeholder("0123456789abcdef").is_some(), "64 bits");
    }

    fn secrets<'a>(hosts: &'a [HostRule]) -> Vec<SwapSecret<'a>> {
        vec![
            SwapSecret {
                placeholder: "ph_AAAAAAAAAAAAAAAAAAAA",
                value: "REAL-ONE-value/with+chars",
                hosts,
            },
            SwapSecret {
                placeholder: "ph_BBBBBBBBBBBBBBBBBBBB",
                value: "REAL-TWO-value",
                hosts: &[],
            },
        ]
    }

    fn head(text: &str) -> RequestHead {
        parse_request_head(text.as_bytes()).expect("head")
    }

    fn swapped_text(swapped: &Swapped) -> String {
        String::from_utf8(swapped.head.to_vec()).expect("utf8")
    }

    #[test]
    fn bearer_basic_key_header_and_query_are_swapped() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let request = head(
            "GET /v1/x?key=ph_AAAAAAAAAAAAAAAAAAAA&q=1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer ph_AAAAAAAAAAAAAAAAAAAA\r\nX-Api-Key: ph_AAAAAAAAAAAAAAAAAAAA\r\nAccept-Encoding: gzip\r\nProxy-Authorization: Basic eDp5\r\n\r\n",
        );
        let swapped = swap_request(&request, "api.example.com", 443, &secrets).expect("swap");
        let text = swapped_text(&swapped);
        assert!(text.starts_with("GET /v1/x?key=REAL-ONE-value%2Fwith%2Bchars&q=1 HTTP/1.1\r\n"));
        assert!(text.contains("\r\nAuthorization: Bearer REAL-ONE-value/with+chars\r\n"));
        assert!(text.contains("\r\nX-Api-Key: REAL-ONE-value/with+chars\r\n"));
        assert!(!text.contains("Accept-Encoding") && !text.contains("Proxy-Authorization"));
        assert_eq!(swapped.used, vec![0]);

        let basic = base64::encode(b"x-access-token:ph_AAAAAAAAAAAAAAAAAAAA");
        let request = head(&format!(
            "GET / HTTP/1.1\r\nHost: sub.api.example.com\r\nAuthorization: Basic {basic}\r\n\r\n"
        ));
        let swapped =
            swap_request(&request, "sub.api.example.com", 443, &secrets).expect("basic swap");
        let expected = base64::encode(b"x-access-token:REAL-ONE-value/with+chars");
        assert!(swapped_text(&swapped).contains(&format!("Authorization: Basic {expected}\r\n")));
    }

    #[test]
    fn placeholders_outside_auth_positions_or_hosts_stop_the_request() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let refused = |text: &str, host: &str| {
            swap_request(&head(text), host, 443, &secrets)
                .err()
                .expect("refusal")
        };
        assert_eq!(
            refused(
                "GET / HTTP/1.1\r\nAuthorization: Bearer ph_AAAAAAAAAAAAAAAAAAAA\r\n\r\n",
                "evil.example.net"
            ),
            Refusal::WrongHost { index: 0 }
        );
        assert_eq!(
            refused(
                "GET / HTTP/1.1\r\nAuthorization: Bearer ph_BBBBBBBBBBBBBBBBBBBB\r\n\r\n",
                "api.example.com"
            ),
            Refusal::WrongHost { index: 1 }
        );
        assert!(matches!(
            refused(
                "GET / HTTP/1.1\r\nUser-Agent: x ph_AAAAAAAAAAAAAAAAAAAA\r\n\r\n",
                "api.example.com"
            ),
            Refusal::Misplaced { index: 0, .. }
        ));
        assert!(matches!(
            refused(
                "GET /store/ph_AAAAAAAAAAAAAAAAAAAA HTTP/1.1\r\n\r\n",
                "api.example.com"
            ),
            Refusal::Misplaced { index: 0, .. }
        ));
        assert!(matches!(
            refused(
                "GET /?note=ph_AAAAAAAAAAAAAAAAAAAA HTTP/1.1\r\n\r\n",
                "api.example.com"
            ),
            Refusal::Misplaced { index: 0, .. }
        ));
        // A port that the rule does not cover.
        assert_eq!(
            swap_request(
                &head("GET / HTTP/1.1\r\nAuthorization: Bearer ph_AAAAAAAAAAAAAAAAAAAA\r\n\r\n"),
                "api.example.com",
                8443,
                &secrets
            )
            .err(),
            Some(Refusal::WrongHost { index: 0 })
        );
    }

    #[test]
    fn a_request_without_placeholders_passes_unchanged() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let swapped = swap_request(
            &head("POST /v1/x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n"),
            "api.example.com",
            443,
            &secrets,
        )
        .expect("swap");
        assert!(swapped.used.is_empty());
        assert_eq!(
            swapped_text(&swapped),
            "POST /v1/x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n"
        );
    }
}
