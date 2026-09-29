//! Track proxy: the swap rules (auth positions only).
//!
//! A copy, with attribution, of the swap rules of `src/broker/proxy/swap.rs` of
//! wydrox/apassy at rev 77f6628 (Apache-2.0), changed to work on a target and a list
//! of headers instead of a raw request head. The placeholder minting stays in the
//! core (`apassy::broker::proxy::mint_placeholder`).
//!
//! The proxy puts the real value only into an authentication position: the
//! `Authorization` header, a known API key header, or a known API key query
//! parameter. A placeholder in any other place of a request (path, other header) stops
//! the request. A real value would there become data that the service stores or
//! returns. A placeholder that goes to a host it is not for stops the request too.

use apassy::broker::proxy::HostRule;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use zeroize::Zeroizing;

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

/// One secret of a session, as the swap rules see it.
pub(super) struct SwapSecret<'a> {
    pub placeholder: &'a str,
    pub value: &'a str,
    pub hosts: &'a [HostRule],
}

/// Why the proxy stopped a request. The texts name no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The placeholder of secret `index` is in a place that is not an auth position.
    /// `place` is a fixed text: it never repeats a name from the request.
    Misplaced { index: usize, place: &'static str },
    /// The placeholder of secret `index` goes to a host that it is not for.
    WrongHost { index: usize },
}

/// The request for the service after the swap, and the secrets that went into it.
pub(super) struct Swapped {
    pub target: Zeroizing<String>,
    pub headers: Vec<(String, Zeroizing<String>)>,
    pub used: Vec<usize>,
}

/// Headers that the relay never forwards: the hop-by-hop ones, the ones it sets
/// again, the edge and proxy chain ones, and `Accept-Encoding` (the response must
/// come back uncompressed so a real value can be found in it).
pub(super) fn dropped_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("cf-")
        || matches!(
            lower.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "expect"
                | "accept-encoding"
                | "content-length"
                | "x-apassy-edge"
                | "cdn-loop"
                | "x-forwarded-for"
                | "x-forwarded-proto"
                | "x-forwarded-host"
                | "x-real-ip"
        )
}

/// Swaps the placeholders of a request for `host:port`. Each placeholder must be in an
/// auth position and for this host. Otherwise the request stops. Dropped headers are
/// removed and are not looked at.
pub(super) fn swap_request(
    target: &str,
    headers: &[(String, String)],
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

    let target = swap_target(target, secrets, &mut take)?;
    let mut out_headers: Vec<(String, Zeroizing<String>)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if dropped_header(name) {
            continue;
        }
        let lower = name.to_ascii_lowercase();
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
                        place: "a header that is not an auth header",
                    });
                }
                Zeroizing::new(value.clone())
            }
        };
        out_headers.push((name.clone(), value));
    }
    Ok(Swapped {
        target,
        headers: out_headers,
        used,
    })
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
    let Ok(decoded) = BASE64_STANDARD
        .decode(credentials)
        .map(Zeroizing::<Vec<u8>>::new)
    else {
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
                place: "a part of the Basic credentials",
            });
        }
        return Ok(None);
    }
    // A placeholder that is one part and also sits inside the other part is refused.
    for (part, index) in [(user, user_index), (password, password_index)] {
        if index.is_none()
            && let Some(found) = find_placeholder(part, secrets)
        {
            return Err(Refusal::Misplaced {
                index: found,
                place: "a part of the Basic credentials",
            });
        }
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
    let encoded = Zeroizing::new(BASE64_STANDARD.encode(plain.as_bytes()));
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

/// Swaps a placeholder in a known key parameter of the query. A placeholder in the
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
            place: "the URL path",
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
                place: "a query parameter that is not a key parameter",
            });
        }
        out.push_str(pair);
    }
    Ok(out)
}

/// The text with `%XX` escapes and `+` decoded. Bytes that are not UTF-8 become
/// replacement characters.
pub(super) fn percent_decode(text: &str) -> String {
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

    fn rule(text: &str) -> HostRule {
        HostRule::parse(text).expect("host rule")
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

    fn headers(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn header<'a>(swapped: &'a Swapped, name: &str) -> Option<&'a str> {
        swapped
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn bearer_basic_key_header_and_query_are_swapped() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let request = headers(&[
            ("Host", "api.example.com"),
            ("Authorization", "Bearer ph_AAAAAAAAAAAAAAAAAAAA"),
            ("X-Api-Key", "ph_AAAAAAAAAAAAAAAAAAAA"),
            ("Accept-Encoding", "gzip"),
            ("Proxy-Authorization", "Basic eDp5"),
        ]);
        let swapped = swap_request(
            "/v1/x?key=ph_AAAAAAAAAAAAAAAAAAAA&q=1",
            &request,
            "api.example.com",
            443,
            &secrets,
        )
        .expect("swap");
        assert_eq!(
            swapped.target.as_str(),
            "/v1/x?key=REAL-ONE-value%2Fwith%2Bchars&q=1"
        );
        assert_eq!(
            header(&swapped, "Authorization"),
            Some("Bearer REAL-ONE-value/with+chars")
        );
        assert_eq!(
            header(&swapped, "X-Api-Key"),
            Some("REAL-ONE-value/with+chars")
        );
        assert!(header(&swapped, "Accept-Encoding").is_none());
        assert!(header(&swapped, "Proxy-Authorization").is_none());
        assert!(header(&swapped, "Host").is_none());
        assert_eq!(swapped.used, vec![0]);

        let basic = BASE64_STANDARD.encode(b"x-access-token:ph_AAAAAAAAAAAAAAAAAAAA");
        let request = headers(&[("Authorization", &format!("Basic {basic}"))]);
        let swapped =
            swap_request("/", &request, "sub.api.example.com", 443, &secrets).expect("basic");
        let expected = BASE64_STANDARD.encode(b"x-access-token:REAL-ONE-value/with+chars");
        assert_eq!(
            header(&swapped, "Authorization"),
            Some(format!("Basic {expected}").as_str())
        );
    }

    #[test]
    fn basic_swaps_the_user_and_the_password() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let both = BASE64_STANDARD.encode(b"ph_AAAAAAAAAAAAAAAAAAAA:ph_AAAAAAAAAAAAAAAAAAAA");
        let request = headers(&[("Authorization", &format!("Basic {both}"))]);
        let swapped = swap_request("/", &request, "api.example.com", 443, &secrets).expect("swap");
        let expected =
            BASE64_STANDARD.encode(b"REAL-ONE-value/with+chars:REAL-ONE-value/with+chars");
        assert_eq!(
            header(&swapped, "authorization"),
            Some(format!("Basic {expected}").as_str())
        );
        let plain = BASE64_STANDARD.encode(b"user:pass");
        let request = headers(&[("Authorization", &format!("Basic {plain}"))]);
        let swapped = swap_request("/", &request, "api.example.com", 443, &secrets).expect("swap");
        assert_eq!(
            header(&swapped, "authorization"),
            Some(format!("Basic {plain}").as_str())
        );
        assert!(swapped.used.is_empty());
    }

    #[test]
    fn every_key_header_and_key_param_is_an_auth_position() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        for name in KEY_HEADERS {
            let request = headers(&[(name, "Bearer ph_AAAAAAAAAAAAAAAAAAAA")]);
            let swapped =
                swap_request("/", &request, "api.example.com", 443, &secrets).expect(name);
            assert_eq!(
                header(&swapped, name),
                Some("Bearer REAL-ONE-value/with+chars"),
                "{name}"
            );
        }
        for name in KEY_PARAMS {
            let target = format!("/?{}=ph_AAAAAAAAAAAAAAAAAAAA", name.to_ascii_uppercase());
            let swapped = swap_request(&target, &[], "api.example.com", 443, &secrets).expect(name);
            assert!(swapped.target.contains("REAL-ONE-value%2Fwith%2Bchars"));
        }
    }

    #[test]
    fn a_percent_encoded_key_param_is_swapped() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let swapped = swap_request(
            "/?ap%69_key=ph_AAAAAAAAAAAAAAAAAAA%41",
            &[],
            "api.example.com",
            443,
            &secrets,
        )
        .expect("swap");
        assert_eq!(
            swapped.target.as_str(),
            "/?ap%69_key=REAL-ONE-value%2Fwith%2Bchars"
        );
    }

    #[test]
    fn placeholders_outside_auth_positions_or_hosts_stop_the_request() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let refused = |target: &str, list: &[(&str, &str)], host: &str| {
            swap_request(target, &headers(list), host, 443, &secrets)
                .err()
                .expect("refusal")
        };
        let bearer_a = [("Authorization", "Bearer ph_AAAAAAAAAAAAAAAAAAAA")];
        let bearer_b = [("Authorization", "Bearer ph_BBBBBBBBBBBBBBBBBBBB")];
        assert_eq!(
            refused("/", &bearer_a, "evil.example.net"),
            Refusal::WrongHost { index: 0 }
        );
        assert_eq!(
            refused("/", &bearer_b, "api.example.com"),
            Refusal::WrongHost { index: 1 }
        );
        assert!(matches!(
            refused(
                "/",
                &[("User-Agent", "x ph_AAAAAAAAAAAAAAAAAAAA")],
                "api.example.com"
            ),
            Refusal::Misplaced { index: 0, .. }
        ));
        assert!(matches!(
            refused("/store/ph_AAAAAAAAAAAAAAAAAAAA", &[], "api.example.com"),
            Refusal::Misplaced { index: 0, .. }
        ));
        assert!(matches!(
            refused("/store/ph_AAAAAAAAAAAAAAAAAAA%41", &[], "api.example.com"),
            Refusal::Misplaced { index: 0, .. }
        ));
        assert!(matches!(
            refused("/?note=ph_AAAAAAAAAAAAAAAAAAAA", &[], "api.example.com"),
            Refusal::Misplaced { index: 0, .. }
        ));
        assert!(matches!(
            refused(
                "/?note=x&key=a%20ph_AAAAAAAAAAAAAAAAAAAA",
                &[],
                "api.example.com"
            ),
            Refusal::Misplaced { index: 0, .. }
        ));
        // A Basic part with more text.
        let text = BASE64_STANDARD.encode(b"user:pw-ph_AAAAAAAAAAAAAAAAAAAA");
        assert!(matches!(
            refused(
                "/",
                &[("Authorization", &format!("Basic {text}"))],
                "api.example.com"
            ),
            Refusal::Misplaced { index: 0, .. }
        ));
        let mixed = BASE64_STANDARD.encode(b"ph_AAAAAAAAAAAAAAAAAAAA:pw-ph_AAAAAAAAAAAAAAAAAAAA");
        assert!(matches!(
            refused(
                "/",
                &[("Authorization", &format!("Basic {mixed}"))],
                "api.example.com"
            ),
            Refusal::Misplaced { index: 0, .. }
        ));
        // A port that the rule does not cover.
        assert_eq!(
            swap_request("/", &headers(&bearer_a), "api.example.com", 8443, &secrets).err(),
            Some(Refusal::WrongHost { index: 0 })
        );
        // A placeholder in a header that is dropped does not stop the request.
        let swapped = swap_request(
            "/",
            &headers(&[("X-Forwarded-For", "ph_AAAAAAAAAAAAAAAAAAAA")]),
            "api.example.com",
            443,
            &secrets,
        )
        .expect("dropped headers are not looked at");
        assert!(swapped.headers.is_empty());
    }

    #[test]
    fn a_request_without_placeholders_passes_unchanged() {
        let hosts = [rule("api.example.com")];
        let secrets = secrets(&hosts);
        let request = headers(&[("Content-Type", "application/json"), ("X-Trace", "1")]);
        let swapped =
            swap_request("/v1/x?a=1&b=2", &request, "api.example.com", 443, &secrets).expect("ok");
        assert!(swapped.used.is_empty());
        assert_eq!(swapped.target.as_str(), "/v1/x?a=1&b=2");
        assert_eq!(swapped.headers.len(), 2);
        assert_eq!(header(&swapped, "x-trace"), Some("1"));
    }

    #[test]
    fn dropped_headers_are_the_listed_ones_and_cf() {
        for name in [
            "Host",
            "connection",
            "Keep-Alive",
            "Proxy-Authorization",
            "Proxy-Connection",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
            "Expect",
            "Accept-Encoding",
            "Content-Length",
            "X-Apassy-Edge",
            "CDN-Loop",
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            "X-Forwarded-Host",
            "X-Real-IP",
            "CF-Connecting-IP",
            "cf-ray",
        ] {
            assert!(dropped_header(name), "{name}");
        }
        for name in ["Authorization", "User-Agent", "Content-Type", "Cookie"] {
            assert!(!dropped_header(name), "{name}");
        }
    }

    #[test]
    fn percent_coding_round_trips() {
        assert_eq!(percent_decode("a%2Fb+c%zz%4"), "a/b c%zz%4");
        let mut out = String::new();
        percent_encode_into("a/b c~-._", &mut out);
        assert_eq!(out, "a%2Fb%20c~-._");
    }
}
