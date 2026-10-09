//! WebAuthn checks of browser passkey requests (contract section 9).
//!
//! The extension builds `clientDataJSON` in its service worker from the origin that
//! the browser gives it (`port.sender.origin`). The app never takes a hash from the
//! extension: [`client_data`] decodes the exact bytes, checks every field, checks the
//! relying party ID against the public suffix list, and computes SHA-256 itself.
//!
//! Byte fields on the wire are standard base64 with padding ([`encode_bytes`],
//! [`decode_bytes`]). The decoder is strict: one encoding per byte string, so two
//! different strings never name the same credential.
//!
//! The base64 and origin syntax checks need no feature, so the host and the wire
//! parse build without the vault. The public suffix list and SHA-256 need the vault
//! feature.

use super::wire::{MAX_URL_BYTES, WireError};

/// The most credential IDs in `allowed` or `excluded`.
pub const MAX_CREDENTIAL_IDS: usize = 256;
/// The longest credential ID, in bytes (WebAuthn: at most 1023).
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
/// The longest user handle, in bytes (WebAuthn: 1 to 64).
pub const MAX_USER_HANDLE_BYTES: usize = 64;
/// The shortest and the longest challenge, in bytes.
pub const MIN_CHALLENGE_BYTES: usize = 16;
pub const MAX_CHALLENGE_BYTES: usize = 1024;
/// The longest `clientDataJSON`, in bytes: the fixed keys, a challenge of 1024 bytes
/// (1366 characters), and an origin of at most 2048 bytes.
pub const MAX_CLIENT_DATA_BYTES: usize = 4096;
/// The longest relying party ID (a DNS name).
pub const MAX_RP_ID_BYTES: usize = 253;
/// `type` of an assertion and of a registration.
pub const TYPE_GET: &str = "webauthn.get";
pub const TYPE_CREATE: &str = "webauthn.create";

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#[cfg(any(feature = "vault", test))]
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn bad(message: &str) -> WireError {
    WireError::new("bad_request", message)
}

#[cfg(feature = "vault")]
fn unsupported(message: &str) -> WireError {
    WireError::new("unsupported", message)
}

/// Standard base64 with padding (RFC 4648 section 4).
pub fn encode_bytes(bytes: &[u8]) -> String {
    encode(bytes, ALPHABET, true)
}

fn encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        let symbols = chunk.len() + 1;
        for index in 0..4 {
            if index < symbols {
                out.push(char::from(alphabet[(n >> (18 - 6 * index)) as usize & 63]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Decode standard base64 with padding, and check that the result has `min` to `max`
/// bytes. Strict: no white space, no line break, no URL alphabet, padding only at the
/// end, and the unused bits of the last symbol are zero. So each byte string has
/// exactly one accepted encoding.
pub fn decode_bytes(text: &str, min: usize, max: usize) -> Result<Vec<u8>, WireError> {
    let error = || bad("A byte field is not canonical standard base64 of the allowed length.");
    // Each 3 bytes are 4 symbols, so a longer text cannot decode to `max` bytes.
    if text.len() > max.div_ceil(3).saturating_mul(4) || !text.len().is_multiple_of(4) {
        return Err(error());
    }
    let bytes = text.as_bytes();
    let pad = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if pad > 2 {
        return Err(error());
    }
    let out = decode(&bytes[..bytes.len() - pad], ALPHABET).ok_or_else(error)?;
    // The symbols before the padding must be exactly the symbols of the decoded
    // bytes: 2 symbols for 1 byte, 3 for 2 bytes.
    if out.len().div_ceil(3) * 4 != bytes.len() || (out.len() % 3 != 0 && 3 - out.len() % 3 != pad)
    {
        return Err(error());
    }
    if out.len() < min || out.len() > max {
        return Err(error());
    }
    Ok(out)
}

/// Decode base64url without padding, strictly (canonical last symbol).
#[cfg(any(feature = "vault", test))]
fn decode_url(text: &str) -> Option<Vec<u8>> {
    decode(text.as_bytes(), URL_ALPHABET)
}

/// Decode symbols of `alphabet` without padding. `None` for a symbol outside the
/// alphabet, a length that cannot come from bytes (one symbol in the last group), or a
/// last symbol with unused bits that are not zero.
fn decode(symbols: &[u8], alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    if symbols.len() % 4 == 1 {
        return None;
    }
    let value = |symbol: u8| -> Option<u32> {
        alphabet
            .iter()
            .position(|candidate| *candidate == symbol)
            .map(|index| index as u32)
    };
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3 + 2);
    for group in symbols.chunks(4) {
        let mut n = 0u32;
        for symbol in group {
            n = (n << 6) | value(*symbol)?;
        }
        match group.len() {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => {
                if n & 0b11 != 0 {
                    return None;
                }
                out.extend_from_slice(&[(n >> 10) as u8, (n >> 2) as u8]);
            }
            2 => {
                if n & 0b1111 != 0 {
                    return None;
                }
                out.push((n >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Decode a list of credential IDs: at most [`MAX_CREDENTIAL_IDS`], each 1 to
/// [`MAX_CREDENTIAL_ID_BYTES`] bytes of strict standard base64.
pub fn decode_ids(ids: &[String]) -> Result<Vec<Vec<u8>>, WireError> {
    if ids.len() > MAX_CREDENTIAL_IDS {
        return Err(bad("A passkey request has too many credential IDs."));
    }
    ids.iter()
        .map(|id| decode_bytes(id, 1, MAX_CREDENTIAL_ID_BYTES))
        .collect()
}

/// The parts of a page origin that a passkey request may have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin<'a> {
    pub https: bool,
    pub host: &'a str,
    pub port: Option<u16>,
}

/// Check the syntax of a passkey origin, as the browser serializes it:
/// `https://<host>[:<port>]`, or `http://localhost[:<port>]`. The host is a lowercase
/// ASCII DNS name with at least two labels (or `localhost`), not an IP address; the
/// port has no leading zero and is not the default port of the scheme. No user, no
/// path, no trailing slash, no opaque `null`.
pub fn parse_origin(origin: &str) -> Result<Origin<'_>, WireError> {
    let error = || bad("A passkey request needs an https origin, or http://localhost.");
    if origin.len() > MAX_URL_BYTES {
        return Err(error());
    }
    let (https, rest) = if let Some(rest) = origin.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = origin.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(error());
    };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => {
            let valid = !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && !port.starts_with('0');
            let port: u16 = valid
                .then(|| port.parse().ok())
                .flatten()
                .ok_or_else(error)?;
            if port == if https { 443 } else { 80 } {
                return Err(error());
            }
            (host, Some(port))
        }
        None => (rest, None),
    };
    if host == "localhost" {
        return Ok(Origin { https, host, port });
    }
    if !https || !is_dns_name(host) {
        return Err(error());
    }
    Ok(Origin { https, host, port })
}

/// Check the syntax of a relying party ID: `localhost`, or a lowercase ASCII DNS name
/// with at least two labels that is not an IPv4 address.
pub fn check_rp_id(rp_id: &str) -> Result<(), WireError> {
    if rp_id == "localhost" || is_dns_name(rp_id) {
        Ok(())
    } else {
        Err(bad("A passkey request needs a valid relying party ID."))
    }
}

/// A lowercase ASCII DNS name of at least two labels: letters, digits, and inner
/// hyphens, each label 1 to 63 bytes, at most 253 bytes, the last label not all
/// digits (so not an IPv4 address). An IPv6 address has `[` and `:`, so it fails.
fn is_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_RP_ID_BYTES {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && !labels
            .last()
            .is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The checked client data of one passkey request. `Debug` shows no bytes.
#[cfg(feature = "vault")]
#[derive(Clone, PartialEq, Eq)]
pub struct ClientData {
    pub rid: String,
    /// The origin of the page, from the browser and from the signed bytes.
    pub origin: String,
    pub rp_id: String,
    /// The exact bytes that the extension sent and that the page gets back.
    pub client_data_json: Vec<u8>,
    /// SHA-256 of `client_data_json`, computed here.
    pub client_data_hash: [u8; 32],
}

#[cfg(feature = "vault")]
impl std::fmt::Debug for ClientData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientData")
            .field("rid", &self.rid)
            .field("origin", &self.origin)
            .field("rp_id", &self.rp_id)
            .field(
                "client_data_json",
                &format_args!("<{} bytes>", self.client_data_json.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Check the client data of a passkey request and hash it.
///
/// - `rid`: the random request ID of the extension (a lowercase UUID).
/// - `origin`: the origin from the browser ([`parse_origin`]).
/// - `rp_id`: the origin host or a registrable suffix of it. The relying party ID is
///   not a public suffix, ICANN or private (`com`, `co.uk`, `github.io`), its suffix is
///   on the list, and it has the registrable domain of the origin host. `localhost`
///   only for the origin host `localhost`.
/// - `json_base64`: standard base64 of exactly
///   `{"type":"<expected_type>","challenge":"<base64url>","origin":"<origin>","crossOrigin":false}`.
///   The challenge has 16 to 1024 bytes, without padding.
/// - `expected_type`: [`TYPE_GET`] or [`TYPE_CREATE`].
///
/// A malformed request gets `bad_request`. A relying party ID that the browser may
/// accept but Apassy does not (for example a suffix that is not on the list) gets
/// `unsupported`, so the browser does the request itself.
#[cfg(feature = "vault")]
pub fn client_data(
    rid: &str,
    origin: &str,
    rp_id: &str,
    json_base64: &str,
    expected_type: &str,
) -> Result<ClientData, WireError> {
    if !super::wire::is_request_id(rid) {
        return Err(bad("A passkey request needs a request ID."));
    }
    if expected_type != TYPE_GET && expected_type != TYPE_CREATE {
        return Err(bad("A passkey request has an unknown type."));
    }
    let page = parse_origin(origin)?;
    check_rp_id(rp_id)?;
    check_rp_for_host(rp_id, page.host)?;
    let bytes = decode_bytes(json_base64, 1, MAX_CLIENT_DATA_BYTES)?;
    check_json(&bytes, origin, expected_type)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let mut client_data_hash = [0u8; 32];
    client_data_hash.copy_from_slice(digest.as_ref());
    Ok(ClientData {
        rid: rid.to_owned(),
        origin: origin.to_owned(),
        rp_id: rp_id.to_owned(),
        client_data_json: bytes,
        client_data_hash,
    })
}

/// The relying party ID `rp_id` may sign for a page on `host`.
#[cfg(feature = "vault")]
pub fn check_rp_for_host(rp_id: &str, host: &str) -> Result<(), WireError> {
    let refused = || unsupported("Apassy does not sign for this relying party on this page.");
    if rp_id == "localhost" || host == "localhost" {
        return if rp_id == host {
            Ok(())
        } else {
            Err(refused())
        };
    }
    // The host is the relying party ID, or a subdomain of it: a whole label boundary,
    // so `evilexample.com` is not under `example.com`.
    let under = host == rp_id
        || host
            .strip_suffix(rp_id)
            .is_some_and(|prefix| prefix.ends_with('.'));
    if !under {
        return Err(refused());
    }
    // `psl::domain` is `None` for a public suffix itself, ICANN or private.
    let Some(rp_domain) = psl::domain(rp_id.as_bytes()) else {
        return Err(refused());
    };
    if !rp_domain.suffix().is_known() {
        return Err(refused());
    }
    match psl::domain(host.as_bytes()) {
        Some(host_domain) if host_domain.as_bytes() == rp_domain.as_bytes() => Ok(()),
        _ => Err(refused()),
    }
}

/// The bytes are exactly the client data of the extension for this origin and type.
#[cfg(feature = "vault")]
fn check_json(bytes: &[u8], origin: &str, expected_type: &str) -> Result<(), WireError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fields {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }
    let error = || bad("The client data of the passkey request does not match the request.");
    let fields: Fields = serde_json::from_slice(bytes).map_err(|_| error())?;
    if fields.kind != expected_type || fields.origin != origin || fields.cross_origin {
        return Err(error());
    }
    let challenge = decode_url(&fields.challenge).ok_or_else(error)?;
    if !(MIN_CHALLENGE_BYTES..=MAX_CHALLENGE_BYTES).contains(&challenge.len()) {
        return Err(error());
    }
    // One accepted form: the keys in this order, no white space, no escapes. The
    // values have no character that JSON escapes, so this is `JSON.stringify` of the
    // extension.
    let canonical = format!(
        r#"{{"type":"{expected_type}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        fields.challenge
    );
    if canonical.as_bytes() != bytes {
        return Err(error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_is_canonical() {
        for length in 0..40 {
            let bytes: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode_bytes(&bytes);
            assert_eq!(decode_bytes(&text, 0, 64).unwrap(), bytes, "{text}");
        }
        assert_eq!(encode_bytes(b"\xfb\xff"), "+/8=");
        assert_eq!(encode(b"\xfb\xff", URL_ALPHABET, false), "-_8");
        assert_eq!(decode_url("-_8").unwrap(), b"\xfb\xff");
        // Not canonical: unused bits, URL alphabet, missing padding, white space.
        for text in [
            "+/9=", "-_8=", "+/8", "+/8= ", " +/8=", "+/\n8=", "QQ==QQ==", "Q===", "QR==",
        ] {
            assert!(decode_bytes(text, 0, 64).is_err(), "{text:?}");
        }
        assert!(decode_url("-_9").is_none());
        assert!(decode_url("Q").is_none());
        assert!(decode_url("+/8").is_none());
    }

    #[test]
    fn origins_and_rp_ids_have_one_syntax() {
        assert_eq!(
            parse_origin("https://example.com:8443").unwrap(),
            Origin {
                https: true,
                host: "example.com",
                port: Some(8443)
            }
        );
        assert!(parse_origin("http://localhost:3000").is_ok());
        assert!(parse_origin("https://localhost").is_ok());
        for origin in [
            "http://example.com",
            "https://example.com/",
            "https://example.com:443",
            "http://localhost:80",
            "https://example.com:0443",
            "https://example.com:",
            "https://Example.com",
            "https://user@example.com",
            "https://127.0.0.1",
            "https://[::1]",
            "https://com",
            "null",
            "chrome-extension://abc",
            "https://exa_mple.com",
            "https://-a.example.com",
        ] {
            assert!(parse_origin(origin).is_err(), "{origin}");
        }
        assert!(check_rp_id("example.com").is_ok());
        assert!(check_rp_id("localhost").is_ok());
        for rp in ["com", "Example.com", "example.com.", "1.2.3.4", "", "a..b"] {
            assert!(check_rp_id(rp).is_err(), "{rp:?}");
        }
    }
}
