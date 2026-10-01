//! Standard base64 (RFC 4648, with padding) for the helper protocol, and base64url
//! without padding (b64u) for the companion wire (ADR 0014).
//!
//! The crate adds no base64 dependency. Swift `Data.base64EncodedString()`
//! and `Data(base64Encoded:)` use the same alphabet and padding.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(char::from(ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(ALPHABET[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

fn value(byte: u8) -> Option<u32> {
    let v = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Strict decode: the length is a multiple of 4, and padding is only at the
/// end. Returns `None` for any other input.
pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.len() / 4;
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index + 1 == chunks;
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &b in &chunk[..4 - pad] {
            n = (n << 6) | value(b)?;
        }
        n <<= 6 * pad as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(feature = "vault")]
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// b64u: the URL alphabet (`-` and `_`) and no padding.
#[cfg(feature = "vault")]
pub(crate) fn encode_url(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(char::from(URL_ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(URL_ALPHABET[(n >> 12) as usize & 63]));
        if chunk.len() > 1 {
            out.push(char::from(URL_ALPHABET[(n >> 6) as usize & 63]));
        }
        if chunk.len() > 2 {
            out.push(char::from(URL_ALPHABET[n as usize & 63]));
        }
    }
    out
}

#[cfg(feature = "vault")]
fn url_value(byte: u8) -> Option<u32> {
    let v = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Strict b64u decode. It refuses padding, a character outside the URL alphabet, a
/// length of 1 modulo 4, and trailing bits that are not zero (a non-canonical text).
/// So each byte string has exactly one text.
#[cfg(feature = "vault")]
pub(crate) fn decode_url(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for &b in chunk {
            n = (n << 6) | url_value(b)?;
        }
        n <<= 6 * (4 - chunk.len() as u32);
        let produced = chunk.len() * 6 / 8;
        let triple = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&triple[..produced]);
        // The bits that no byte uses must be zero.
        if n & ((1 << (24 - 8 * produced)) - 1) != 0 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_vectors_round_trip() {
        for (plain, encoded) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), encoded);
            assert_eq!(decode(encoded).as_deref(), Some(plain.as_bytes()));
        }
    }

    #[test]
    fn all_byte_values_round_trip() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&bytes)), Some(bytes));
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "Zg=", "Zg", "Z===", "Zg==Zg==", "Zm9v!A==", "Zm9 ", "====", "Zm\n9v",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[cfg(feature = "vault")]
    mod url {
        use super::super::{decode_url, encode_url};

        /// RFC 4648 section 10 vectors, without padding.
        const VECTORS: [(&str, &str); 7] = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];

        #[test]
        fn rfc4648_vectors_round_trip_without_padding() {
            for (plain, encoded) in VECTORS {
                assert_eq!(encode_url(plain.as_bytes()), encoded);
                assert_eq!(decode_url(encoded).as_deref(), Some(plain.as_bytes()));
            }
        }

        #[test]
        fn uses_the_url_alphabet() {
            // 0xfb 0xff 0xfe is "+//+" in the standard alphabet.
            assert_eq!(encode_url(&[0xfb, 0xff, 0xfe]), "-__-");
            assert_eq!(decode_url("-__-"), Some(vec![0xfb, 0xff, 0xfe]));
            assert_eq!(decode_url("+//+"), None);
        }

        #[test]
        fn every_length_and_byte_value_round_trips() {
            let bytes: Vec<u8> = (0..=255).collect();
            for len in 0..=bytes.len() {
                let text = encode_url(&bytes[..len]);
                assert!(!text.contains('='));
                assert_eq!(decode_url(&text).as_deref(), Some(&bytes[..len]));
            }
        }

        #[test]
        fn rejects_padding_bad_characters_and_bad_lengths() {
            for bad in [
                "Zg==",
                "Zm8=",
                "Zg=",
                "Z",
                "Zm9vY",
                "Zm9v!A",
                "Zm9 ",
                "Zm\n9v",
                " Zm9v",
                "Zm9v ",
                "Zm9vYg\u{e9}",
                "Zm+v",
                "Zm/v",
                "=",
                "====",
            ] {
                assert_eq!(decode_url(bad), None, "{bad:?}");
            }
        }

        #[test]
        fn rejects_non_canonical_trailing_bits() {
            // "Zg" is "f". "Zh" has the same byte but a set bit in the unused part.
            assert_eq!(decode_url("Zg"), Some(b"f".to_vec()));
            assert_eq!(decode_url("Zh"), None);
            assert_eq!(decode_url("Zm9"), None);
            assert_eq!(decode_url("Zm8"), Some(b"fo".to_vec()));
            // The last character of a 32-byte value has 4 unused bits.
            let text = encode_url(&[0u8; 32]);
            let mut bad = text.clone();
            bad.pop();
            bad.push('B');
            assert_eq!(decode_url(&text), Some(vec![0u8; 32]));
            assert_eq!(decode_url(&bad), None);
        }
    }
}
