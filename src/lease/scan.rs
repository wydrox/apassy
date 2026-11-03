//! The no-secret scan of plan s6 (contract private-sharing-v1 section 11): every test
//! that holds a synthetic long-lived secret scans what the agent's side can see (the
//! child's environment, the run output, the session view, the audit rows, the activity
//! log) and fails when the secret is there.
//!
//! The scan looks for the secret as it is and in the forms that a leak most likely
//! takes: percent-encoded (a form body or a query, uppercase or lowercase hex), JSON
//! with an escaped `/`, and standard or URL-safe base64 at each of the three byte
//! alignments (an HTTP Basic header, a JWT, a base64 blob that holds it). A failure
//! names the form and the byte offset, never the secret or the text around it.
//!
//! It is public so that the integration tests of the core and the relay crate (units F,
//! G, H, and L) use the same scan.

use crate::native::base64;

/// The shortest secret that a scan accepts: a shorter canary would match by chance.
pub const MIN_SECRET_BYTES: usize = 8;

/// The form in which a secret was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// The bytes of the secret.
    Plain,
    /// RFC 3986 percent-encoding with uppercase hex (`http::form_body`, SigV4).
    Percent,
    /// Percent-encoding with lowercase hex.
    PercentLower,
    /// JSON text that writes `/` as `\/`.
    JsonSlash,
    /// Standard base64 (RFC 4648 section 4), at any byte alignment.
    Base64,
    /// URL-safe base64 (RFC 4648 section 5), at any byte alignment.
    Base64Url,
}

/// Where a secret was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    pub encoding: Encoding,
    /// The byte offset in the haystack.
    pub offset: usize,
}

/// The first place where `secret` is in `haystack`, in any form of [`Encoding`].
///
/// # Panics
///
/// When `secret` is shorter than [`MIN_SECRET_BYTES`]: such a scan proves nothing.
pub fn find_secret(haystack: &[u8], secret: &str) -> Option<Found> {
    assert!(
        secret.len() >= MIN_SECRET_BYTES,
        "the canary is shorter than {MIN_SECRET_BYTES} bytes, so a scan for it proves nothing"
    );
    for (encoding, needle) in needles(secret.as_bytes()) {
        if let Some(offset) = find(haystack, &needle) {
            return Some(Found { encoding, offset });
        }
    }
    None
}

/// Whether `secret` is in `haystack` in any form of [`Encoding`].
pub fn contains_secret(haystack: impl AsRef<[u8]>, secret: &str) -> bool {
    find_secret(haystack.as_ref(), secret).is_some()
}

/// Fail the test when `secret` is in `haystack`. The panic message names the form and
/// the offset only.
#[track_caller]
pub fn assert_no_secret(haystack: impl AsRef<[u8]>, secret: &str) {
    let haystack = haystack.as_ref();
    if let Some(found) = find_secret(haystack, secret) {
        panic!(
            "the secret was found ({:?}) at byte {} of {}",
            found.encoding,
            found.offset,
            haystack.len()
        );
    }
}

/// [`assert_no_secret`] for each of `secrets`. The message also names the index of the
/// secret in `secrets`.
#[track_caller]
pub fn assert_no_secrets(haystack: impl AsRef<[u8]>, secrets: &[&str]) {
    let haystack = haystack.as_ref();
    for (index, secret) in secrets.iter().enumerate() {
        if let Some(found) = find_secret(haystack, secret) {
            panic!(
                "secret {index} was found ({:?}) at byte {} of {}",
                found.encoding,
                found.offset,
                haystack.len()
            );
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Every form of `secret` to look for. A form that equals an earlier one is left out.
fn needles(secret: &[u8]) -> Vec<(Encoding, Vec<u8>)> {
    let mut out: Vec<(Encoding, Vec<u8>)> = vec![(Encoding::Plain, secret.to_vec())];
    let mut push = |encoding: Encoding, needle: Vec<u8>| {
        if !needle.is_empty() && !out.iter().any(|(_, earlier)| *earlier == needle) {
            out.push((encoding, needle));
        }
    };
    push(Encoding::Percent, percent(secret, b"0123456789ABCDEF"));
    push(Encoding::PercentLower, percent(secret, b"0123456789abcdef"));
    if secret.contains(&b'/') {
        let mut escaped = Vec::with_capacity(secret.len() + 8);
        for &byte in secret {
            if byte == b'/' {
                escaped.push(b'\\');
            }
            escaped.push(byte);
        }
        push(Encoding::JsonSlash, escaped);
    }
    for shift in 0..3 {
        let standard = base64_core(secret, shift);
        let url_safe: Vec<u8> = standard
            .iter()
            .map(|&byte| match byte {
                b'+' => b'-',
                b'/' => b'_',
                other => other,
            })
            .collect();
        push(Encoding::Base64, standard);
        push(Encoding::Base64Url, url_safe);
    }
    out
}

fn percent(secret: &[u8], hex: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(secret.len() * 3);
    for &byte in secret {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte);
        } else {
            out.extend_from_slice(&[
                b'%',
                hex[usize::from(byte >> 4)],
                hex[usize::from(byte & 0x0f)],
            ]);
        }
    }
    out
}

/// The base64 characters that depend only on the bytes of `secret` when it starts
/// `shift` bytes after a 3-byte boundary: they are the same in the base64 of any text
/// that holds the secret at such an offset.
fn base64_core(secret: &[u8], shift: usize) -> Vec<u8> {
    let mut padded = vec![0u8; shift];
    padded.extend_from_slice(secret);
    let encoded = base64::encode(&padded);
    // Character i covers bits 6i..6i+6 of the padded input; keep the characters whose
    // bits all lie in the secret: from bit 8*shift to bit 8*(shift + len).
    let start = (8 * shift).div_ceil(6);
    let end = (8 * (shift + secret.len())) / 6;
    if start >= end {
        return Vec::new();
    }
    encoded.as_bytes()[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    #[test]
    fn the_secret_is_found_in_each_form() {
        let percent_upper = "Policy=a&Secret=wJalrXUtnFEMI%2FK7MDENG%2BbPxRfiCYEXAMPLEKEY";
        let percent_lower = "x=wJalrXUtnFEMI%2fK7MDENG%2bbPxRfiCYEXAMPLEKEY";
        let json = r#"{"value":"wJalrXUtnFEMI\/K7MDENG+bPxRfiCYEXAMPLEKEY"}"#;
        let cases = [
            (format!("env: AWS={SECRET}\n"), Encoding::Plain),
            (percent_upper.to_owned(), Encoding::Percent),
            (percent_lower.to_owned(), Encoding::PercentLower),
            (json.to_owned(), Encoding::JsonSlash),
        ];
        for (haystack, encoding) in &cases {
            let found = find_secret(haystack.as_bytes(), SECRET).expect("found");
            assert_eq!(found.encoding, *encoding, "{haystack}");
        }
        // Base64 of a text that holds the secret at each offset, as in an HTTP Basic
        // header (`user:secret`) or a JWT claim.
        for prefix in ["", "u", "us", "user:", "user:x", "AKIAIOSFODNN7EXAMPLE:"] {
            let text = format!("{prefix}{SECRET} trailing");
            let standard = format!("Authorization: Basic {}", base64::encode(text.as_bytes()));
            assert_eq!(
                find_secret(standard.as_bytes(), SECRET).map(|found| found.encoding),
                Some(Encoding::Base64),
                "prefix {prefix:?}"
            );
            let url = format!("eyJ.{}.sig", base64::encode_url(text.as_bytes()));
            assert!(contains_secret(url.as_bytes(), SECRET), "prefix {prefix:?}");
        }
    }

    #[test]
    fn other_text_is_not_a_hit() {
        for haystack in [
            "",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKE",
            "AWS_SECRET_ACCESS_KEY=ph_wJalrXUtnFEMIAAAAAAAAAAAAAAAAAAAAAAAAA",
            "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        ] {
            assert_no_secret(haystack, SECRET);
        }
        assert_no_secrets("nothing here", &[SECRET, "another-canary-0001"]);
    }

    #[test]
    fn a_failure_never_prints_the_secret() {
        let haystack = format!("prefix-context {SECRET} suffix-context");
        let panic = std::panic::catch_unwind(|| assert_no_secret(haystack.as_bytes(), SECRET))
            .expect_err("the scan fails");
        let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(message.contains("Plain"), "{message}");
        assert!(message.contains("at byte 15"), "{message}");
        assert!(!message.contains(SECRET));
        assert!(!message.contains("context"));
        let panic = std::panic::catch_unwind(|| {
            assert_no_secrets(haystack.as_bytes(), &["other-canary-0001", SECRET]);
        })
        .expect_err("the scan fails");
        let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(message.starts_with("secret 1 was found"), "{message}");
        assert!(!message.contains(SECRET));
    }

    #[test]
    fn a_short_canary_is_refused() {
        let panic =
            std::panic::catch_unwind(|| contains_secret("abc", "short")).expect_err("too short");
        let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(message.contains("shorter than 8 bytes"), "{message}");
    }
}
