//! The certificate pin: `b64u(SHA-256(certificate DER))`, 43 characters without padding.
//!
//! It is the format of the companion (contract companion-v1 §3) and of
//! `PinnedTLS.pinText` on the iPhone, so the Rust check and the Swift check agree on
//! one string. A pin is public: a pairing link carries it.

use ring::digest::{SHA256, digest};
use ring::hmac;

use crate::native::base64::{decode_url, encode_url};

/// The length of a pin in text.
pub const PIN_TEXT_CHARS: usize = 43;

/// A parsed pin: the SHA-256 of the leaf certificate DER.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pin([u8; 32]);

impl Pin {
    /// The pin of a certificate.
    pub fn of_certificate(certificate_der: &[u8]) -> Self {
        let mut out = [0u8; 32];
        out.copy_from_slice(digest(&SHA256, certificate_der).as_ref());
        Self(out)
    }

    /// The 32 bytes of the hash.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The pin as six words for a visual check ("node words", contract node-pairing-v1
    /// section 4a): `WORDS[pin[0]]` to `WORDS[pin[5]]` of the relay-sync-v1 list (section
    /// 16), lowercase, one space between them. The pin is the SHA-256 of the certificate,
    /// so the words change with the certificate. They are a check for a person, never the
    /// trust: the client compares the whole pin. The Mac and the iPhone core call this one
    /// function, so they show the same words.
    pub fn words(&self) -> String {
        self.0[..6]
            .iter()
            .map(|byte| crate::sync::WORDS[usize::from(*byte)])
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The text form, `b64u` without padding.
    pub fn text(&self) -> String {
        encode_url(&self.0)
    }

    /// True when `certificate_der` has this pin. The two hashes are compared in
    /// constant time: both are tagged with HMAC-SHA256 under a fixed key and
    /// `ring::hmac::verify` compares the tags (as `companion::crypto::constant_time_eq`).
    pub fn matches(&self, certificate_der: &[u8]) -> bool {
        let other = Self::of_certificate(certificate_der);
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"apassy-net-pin-compare-v1");
        let tag = hmac::sign(&key, &self.0);
        hmac::verify(&key, &other.0, tag.as_ref()).is_ok()
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pin({})", self.text())
    }
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

/// The pin text of a certificate: `b64u(SHA-256(DER))`.
pub fn certificate_pin(certificate_der: &[u8]) -> String {
    Pin::of_certificate(certificate_der).text()
}

/// Parse a pin text. Only the canonical form is accepted: exactly 43 characters of the
/// URL alphabet, no padding, no whitespace, and no unused bits set in the last
/// character. Anything else is `None`.
pub fn parse(text: &str) -> Option<Pin> {
    if text.len() != PIN_TEXT_CHARS
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let bytes = decode_url(text)?;
    let hash: [u8; 32] = bytes.try_into().ok()?;
    let pin = Pin(hash);
    // A second check that the text is the one canonical spelling of these bytes.
    (pin.text() == text).then_some(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector of the companion contract and of the iPhone Kit
    /// (`ios/ApassyCompanionKit/Tests/ApassyCompanionKitTests/Vectors.swift`,
    /// `pinOf3000`, checked against `PinnedTLS.pinText`).
    const PIN_OF_3000: &str = "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU";

    /// The node words of the node-pairing-v1 fixture certificate (contract section 4a, test
    /// vector). The iPhone core and the Swift model test check the same string.
    const NODE_CERT_WORDS: &str = "noodle monkey dinner sled guitar garden";

    #[test]
    fn pin_words_of_the_node_pairing_fixture_are_the_contract_vector() {
        let der = include_bytes!("../../tests/fixtures/node-pairing-v1/node-cert.der");
        let pin = Pin::of_certificate(der);
        assert_eq!(
            pin.as_bytes()[..6],
            [0xbb, 0xb4, 0x62, 0xef, 0x89, 0x7f],
            "the first six bytes of the pin"
        );
        assert_eq!(pin.words(), NODE_CERT_WORDS);
        assert_eq!(
            crate::node::tailnet::pin_words(&pin),
            NODE_CERT_WORDS,
            "the Mac's function is the same"
        );
    }

    #[test]
    fn the_pin_of_the_fixture_der_is_the_swift_vector() {
        assert_eq!(certificate_pin(&[0x30, 0x00]), PIN_OF_3000);
        assert_ne!(certificate_pin(&[0x30, 0x01]), PIN_OF_3000);
        let pin = parse(PIN_OF_3000).expect("the vector parses");
        assert_eq!(pin.text(), PIN_OF_3000);
        assert!(pin.matches(&[0x30, 0x00]));
        assert!(!pin.matches(&[0x30, 0x01]));
        assert!(!pin.matches(&[]));
    }

    #[test]
    fn a_pin_text_parses_only_in_its_canonical_form() {
        assert!(parse(PIN_OF_3000).is_some());
        let mut bad = vec![
            String::new(),
            PIN_OF_3000[..42].to_owned(),
            format!("{PIN_OF_3000}A"),
            format!("{PIN_OF_3000}="),
            format!(" {}", &PIN_OF_3000[1..]),
            PIN_OF_3000.replace('5', "+"),
        ];
        // The last character carries 2 unused bits: "U" is canonical, "V" is not.
        bad.push(format!("{}V", &PIN_OF_3000[..42]));
        for text in bad {
            assert_eq!(parse(&text), None, "{text:?}");
        }
    }

    #[test]
    fn every_byte_of_the_hash_changes_the_pin() {
        let pin = Pin::of_certificate(b"certificate");
        for index in 0..32 {
            let mut bytes = *pin.as_bytes();
            bytes[index] ^= 1;
            assert_ne!(Pin(bytes), pin);
            assert_ne!(Pin(bytes).text(), pin.text());
        }
    }
}
