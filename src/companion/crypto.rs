//! The cryptography of the companion wire (contract companion-v1, sections 2 and 5 to 7).
//!
//! This file calls `ring` and implements no primitive: SHA-256, HMAC-SHA256, and ECDSA
//! P-256 verification. It also builds the four signing strings, so that the Mac and the
//! phone sign and check exactly the same text.
//!
//! A signing string is lines joined with `\n`, without a trailing newline. A builder
//! that takes text from a client returns `None` when a field has a control character,
//! so a client cannot move a field into another line.

use ring::digest::{self, SHA256};
use ring::hmac;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

use crate::native::base64::encode_url;

/// A P-256 point in X9.63 uncompressed form.
pub const PUBLIC_KEY_BYTES: usize = 65;
/// The pairing secret and the tag of an HMAC-SHA256.
pub const SECRET_BYTES: usize = 32;
/// A DER ECDSA P-256 signature is at most this long.
pub const MAX_SIGNATURE_BYTES: usize = 72;

/// First line of the pair string (contract 5.3).
pub const PAIR_TAG: &str = "apassy-companion-pair-v1";
/// First line of the code string (contract 5.3).
pub const CODE_TAG: &str = "apassy-companion-code-v1";
/// First line of the request string (contract 6).
pub const REQUEST_TAG: &str = "apassy-companion-request-v1";
/// First line of the approval string (contract 7).
pub const APPROVE_TAG: &str = "apassy-companion-approve-v1";

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = digest::digest(&SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

/// Lowercase hexadecimal SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

/// HMAC-SHA256 of `message` under `key`. The phone side of a pairing test uses it to
/// make a proof. The Mac checks a proof with [`verify_hmac`].
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Check an HMAC-SHA256 tag in constant time.
pub fn verify_hmac(key: &[u8], message: &[u8], tag: &[u8]) -> bool {
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), message, tag).is_ok()
}

/// Equality of two byte strings with a time that does not depend on where they differ.
/// It hashes both with HMAC-SHA256 under a fixed key and compares the tags with
/// `ring::hmac::verify`, which compares in constant time. So the two inputs can have
/// different lengths, and only the lengths (not the content) change the time.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"apassy-companion-compare-v1");
    let tag = hmac::sign(&key, a);
    hmac::verify(&key, b, tag.as_ref()).is_ok()
}

/// True when `key` has the shape of an X9.63 P-256 point: 65 bytes, first byte `0x04`.
/// That the point is on the curve is checked when a signature is verified with it.
pub fn is_public_key_shape(key: &[u8]) -> bool {
    key.len() == PUBLIC_KEY_BYTES && key[0] == 0x04
}

/// Verify an ECDSA P-256 signature with SHA-256. `public_key` is X9.63, `signature` is
/// DER. A key that is not a point of the curve does not verify.
pub fn verify_ecdsa(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if !is_public_key_shape(public_key) || signature.len() > MAX_SIGNATURE_BYTES {
        return false;
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature)
        .is_ok()
}

/// True when a line of a signing string has a control character.
fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// The pair string (contract 5.3). The keys are raw X9.63 bytes, and the string has
/// their b64u text. `None` when the device ID or the name has a control character.
pub fn pair_string(
    device_id: &str,
    device_name: &str,
    request_key: &[u8],
    approval_key: &[u8],
) -> Option<String> {
    if has_control(device_id) || has_control(device_name) {
        return None;
    }
    Some(format!(
        "{PAIR_TAG}\n{device_id}\n{device_name}\n{}\n{}",
        encode_url(request_key),
        encode_url(approval_key)
    ))
}

/// The code string (contract 5.3). The phone and the Mac compute the pairing code from
/// it.
pub fn code_string(secret: &[u8], request_key: &[u8], approval_key: &[u8]) -> String {
    format!(
        "{CODE_TAG}\n{}\n{}\n{}",
        encode_url(secret),
        encode_url(request_key),
        encode_url(approval_key)
    )
}

/// The request string (contract 6). `path` is the request target as sent. `None` when
/// a field has a control character.
pub fn request_string(
    method: &str,
    path: &str,
    device_id: &str,
    time: u64,
    nonce: &[u8],
    body: &[u8],
) -> Option<String> {
    if has_control(method) || has_control(path) || has_control(device_id) {
        return None;
    }
    Some(format!(
        "{REQUEST_TAG}\n{method}\n{path}\n{device_id}\n{time}\n{}\n{}",
        encode_url(nonce),
        sha256_hex(body)
    ))
}

/// What an approval string says the owner confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveAction {
    /// Approve the run once.
    Approve,
    /// Approve the run and remember its pattern.
    ApproveAndRemember,
}

impl ApproveAction {
    /// The line in the approval string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::ApproveAndRemember => "approve_and_remember",
        }
    }
}

/// The approval string (contract 7). `digest` is the 64-character hex digest of the
/// run. `None` when the device ID or the digest has a control character.
pub fn approve_string(
    device_id: &str,
    action: ApproveAction,
    run_id: u64,
    digest: &str,
    time: u64,
) -> Option<String> {
    if has_control(device_id) || has_control(digest) {
        return None;
    }
    Some(format!(
        "{APPROVE_TAG}\n{device_id}\n{}\n{run_id}\n{digest}\n{time}",
        action.as_str()
    ))
}

/// SHA-256 of the code string of a pairing (contract 5.3).
pub fn pairing_code_hash(secret: &[u8], request_key: &[u8], approval_key: &[u8]) -> [u8; 32] {
    sha256(code_string(secret, request_key, approval_key).as_bytes())
}

/// The 6-digit pairing code from the hash of the code string: the first four bytes as a
/// big-endian number, modulo one million, with leading zeros. The text has no space.
pub fn pairing_code(hash: &[u8; 32]) -> String {
    let n = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    format!("{:06}", n % 1_000_000)
}

/// The code as the phone shows it, "ddd ddd".
pub fn display_code(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_owned()
    }
}

/// The certificate pin: b64u of the SHA-256 of the certificate DER (contract 3).
pub fn certificate_pin(certificate_der: &[u8]) -> String {
    encode_url(&sha256(certificate_der))
}

#[cfg(test)]
pub(crate) mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair,
    };

    use super::*;
    use crate::native::base64::decode_url;

    // Contract section 9. The values are synthetic.
    pub(crate) const REQUEST_KEY: &str =
        "BIcY3rZ6TdzHFNUttUCSdryZE3YayizgQ0KT5D1LKMdwv4E2AxLTggQEYU3HYfQzwIm-fdsPZYt5aEYV6-EJskE";
    pub(crate) const APPROVAL_KEY: &str =
        "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";
    pub(crate) const SECRET: &str = "s9IIzFKuwMPGM-IW92PJK8U5dG0y14hgHYP9lX4UI0g";
    pub(crate) const DEVICE_ID: &str = "d4c0ffee00000000000000000000beef";
    pub(crate) const DEVICE_NAME: &str = "Test iPhone";
    pub(crate) const PROOF: &str = "KGSWHAv-NdQat1HFN0hqCLYCiGJnuQaxbQ3kogGaqFE";
    pub(crate) const PAIR_SIGNATURE_BY_REQUEST_KEY: &str = "MEYCIQCDKleQt7-bz06sJBuMu2Mgxo4-sOmKfR8ZnRk3WX-xPgIhAMidi2mo3Lbz1aK4ROOSYNlvsoWqc-RI7Zbi5oLDHujf";
    pub(crate) const PAIR_SIGNATURE_BY_APPROVAL_KEY: &str = "MEUCIQC-Lswfys1i6xzmUbXHou1gX-N5cpBnnrH6wkqo4LU46gIgIqEtSlpfzZhyiJuHgALfdyQ0Uu6XlIC3w_dL60VmQUQ";
    const CODE_HASH: &str = "7050e20eb0016a113bfb886cf0ca8e4eefc9bccd1861d2d9f292aa637ca28555";
    const NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";
    const TIME: u64 = 1_790_000_000;
    const EMPTY_BODY_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const REQUEST_SIGNATURE: &str = "MEQCICGLPWDhC0B33p0zHBaApsO593Vzug0WuvtkmZ5F6Wx3AiB5QXmACxIlrPnUhtpTMplEC2h1h6fqwvAyUIOA2PFipw";
    const APPROVE_SIGNATURE: &str = "MEUCIEdCbu0iVNdaKys-5EkPMdAn4R79c0p0wtlE9Jnk5QtfAiEAtyrTuQWKWoTxZRvziO4_A-NK1QD5B-gXMiuV5Pvs9wo";

    const EXPECTED_PAIR_STRING: &str = "apassy-companion-pair-v1
d4c0ffee00000000000000000000beef
Test iPhone
BIcY3rZ6TdzHFNUttUCSdryZE3YayizgQ0KT5D1LKMdwv4E2AxLTggQEYU3HYfQzwIm-fdsPZYt5aEYV6-EJskE
BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";

    const EXPECTED_REQUEST_STRING: &str = "apassy-companion-request-v1
GET
/v1/inbox
d4c0ffee00000000000000000000beef
1790000000
AAECAwQFBgcICQoLDA0ODw
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    const EXPECTED_APPROVE_STRING: &str = "apassy-companion-approve-v1
d4c0ffee00000000000000000000beef
approve
123456789012345
abababababababababababababababababababababababababababababababab
1790000000";

    pub(crate) fn bytes(text: &str) -> Vec<u8> {
        decode_url(text).expect("b64u")
    }

    pub(crate) fn vector_pair_string() -> String {
        pair_string(
            DEVICE_ID,
            DEVICE_NAME,
            &bytes(REQUEST_KEY),
            &bytes(APPROVAL_KEY),
        )
        .expect("no control character")
    }

    /// A device key made by ring, as the phone would hold one. The public key is X9.63.
    pub(crate) struct TestKey {
        pair: EcdsaKeyPair,
        rng: SystemRandom,
    }

    impl TestKey {
        pub(crate) fn generate() -> Self {
            let rng = SystemRandom::new();
            let algorithm: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).expect("generate");
            let pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8.as_ref(), &rng).expect("parse");
            Self { pair, rng }
        }

        pub(crate) fn public(&self) -> Vec<u8> {
            self.pair.public_key().as_ref().to_vec()
        }

        /// A DER signature over the UTF-8 bytes of `text`.
        pub(crate) fn sign(&self, text: &str) -> Vec<u8> {
            self.pair
                .sign(&self.rng, text.as_bytes())
                .expect("sign")
                .as_ref()
                .to_vec()
        }
    }

    /// Flip one character of `text` to another character of the b64u alphabet. The
    /// result is another string of the same length.
    fn change_one_character(text: &str) -> String {
        let mut chars: Vec<char> = text.chars().collect();
        let at = chars.len() / 2;
        chars[at] = if chars[at] == 'x' { 'y' } else { 'x' };
        chars.into_iter().collect()
    }

    #[test]
    fn sha256_and_hex_match_known_values() {
        assert_eq!(sha256_hex(b""), EMPTY_BODY_HASH);
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn body_hash_of_the_vector_body() {
        assert_eq!(
            sha256_hex(br#"{"remember":false}"#),
            "c21638494d6f31b1eb753c01dc27df1491cafaa42e908bf82eaede49134884c3"
        );
    }

    #[test]
    fn the_certificate_pin_matches_the_vector() {
        assert_eq!(
            certificate_pin(&[0x30, 0x00]),
            "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU"
        );
        assert_ne!(
            certificate_pin(&[0x30, 0x01]),
            "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU"
        );
    }

    #[test]
    fn the_pair_string_matches_the_vector() {
        assert_eq!(vector_pair_string(), EXPECTED_PAIR_STRING);
    }

    #[test]
    fn the_pair_proof_matches_the_vector() {
        let secret = bytes(SECRET);
        let proof = hmac_sha256(&secret, vector_pair_string().as_bytes());
        assert_eq!(encode_url(&proof), PROOF);
        assert!(verify_hmac(
            &secret,
            vector_pair_string().as_bytes(),
            &bytes(PROOF)
        ));
    }

    #[test]
    fn a_wrong_proof_or_secret_or_string_fails() {
        let secret = bytes(SECRET);
        let string = vector_pair_string();
        let proof = bytes(PROOF);
        // One changed character of the proof.
        let bad = bytes(&change_one_character(PROOF));
        assert!(!verify_hmac(&secret, string.as_bytes(), &bad));
        // Another secret.
        let other = bytes(&change_one_character(SECRET));
        assert!(!verify_hmac(&other, string.as_bytes(), &proof));
        // Another pair string: the name changed by one character.
        let other_string = string.replace("Test iPhone", "Test iPhonf");
        assert!(!verify_hmac(&secret, other_string.as_bytes(), &proof));
        // A proof of another length.
        assert!(!verify_hmac(&secret, string.as_bytes(), &proof[..31]));
        assert!(!verify_hmac(&secret, string.as_bytes(), &[]));
    }

    #[test]
    fn the_pair_signatures_verify_and_fail_after_one_changed_character() {
        let string = vector_pair_string();
        let request_key = bytes(REQUEST_KEY);
        let approval_key = bytes(APPROVAL_KEY);
        let by_request = bytes(PAIR_SIGNATURE_BY_REQUEST_KEY);
        let by_approval = bytes(PAIR_SIGNATURE_BY_APPROVAL_KEY);
        assert!(verify_ecdsa(&request_key, string.as_bytes(), &by_request));
        assert!(verify_ecdsa(&approval_key, string.as_bytes(), &by_approval));
        // With the other key.
        assert!(!verify_ecdsa(&approval_key, string.as_bytes(), &by_request));
        assert!(!verify_ecdsa(&request_key, string.as_bytes(), &by_approval));
        // After one changed character of the string, in each line.
        for line in 0..5 {
            let mut lines: Vec<String> = string.lines().map(str::to_owned).collect();
            lines[line] = change_one_character(&lines[line]);
            let changed = lines.join("\n");
            assert!(!verify_ecdsa(&request_key, changed.as_bytes(), &by_request));
            assert!(!verify_ecdsa(
                &approval_key,
                changed.as_bytes(),
                &by_approval
            ));
        }
        // A trailing newline is another string.
        let with_newline = format!("{string}\n");
        assert!(!verify_ecdsa(
            &request_key,
            with_newline.as_bytes(),
            &by_request
        ));
    }

    #[test]
    fn the_request_and_approval_vectors_verify() {
        let request = request_string("GET", "/v1/inbox", DEVICE_ID, TIME, &bytes(NONCE), b"")
            .expect("string");
        assert_eq!(request, EXPECTED_REQUEST_STRING);
        let signature = bytes(REQUEST_SIGNATURE);
        let request_key = bytes(REQUEST_KEY);
        let approval_key = bytes(APPROVAL_KEY);
        assert!(verify_ecdsa(&request_key, request.as_bytes(), &signature));
        assert!(!verify_ecdsa(&approval_key, request.as_bytes(), &signature));
        let changed = request.replace("/v1/inbox", "/v1/inboy");
        assert!(!verify_ecdsa(&request_key, changed.as_bytes(), &signature));
        let changed = request.replace("GET", "PUT");
        assert!(!verify_ecdsa(&request_key, changed.as_bytes(), &signature));
        let changed = request.replace("1790000000", "1790000001");
        assert!(!verify_ecdsa(&request_key, changed.as_bytes(), &signature));
        let changed = request.replace("AAECAwQ", "AAECAwR");
        assert!(!verify_ecdsa(&request_key, changed.as_bytes(), &signature));

        let digest = "ab".repeat(32);
        let approval = approve_string(
            DEVICE_ID,
            ApproveAction::Approve,
            123_456_789_012_345,
            &digest,
            TIME,
        )
        .expect("string");
        assert_eq!(approval, EXPECTED_APPROVE_STRING);
        let signature = bytes(APPROVE_SIGNATURE);
        assert!(verify_ecdsa(&approval_key, approval.as_bytes(), &signature));
        assert!(!verify_ecdsa(&request_key, approval.as_bytes(), &signature));
        let changed = approval.replace("approve\n", "approvf\n");
        assert!(!verify_ecdsa(&approval_key, changed.as_bytes(), &signature));
        let other_action = approve_string(
            DEVICE_ID,
            ApproveAction::ApproveAndRemember,
            123_456_789_012_345,
            &digest,
            TIME,
        )
        .expect("string");
        assert!(!verify_ecdsa(
            &approval_key,
            other_action.as_bytes(),
            &signature
        ));
        let other_run = approve_string(
            DEVICE_ID,
            ApproveAction::Approve,
            123_456_789_012_346,
            &digest,
            TIME,
        )
        .expect("string");
        assert!(!verify_ecdsa(
            &approval_key,
            other_run.as_bytes(),
            &signature
        ));
        let other_digest = approve_string(
            DEVICE_ID,
            ApproveAction::Approve,
            123_456_789_012_345,
            &"ac".repeat(32),
            TIME,
        )
        .expect("string");
        assert!(!verify_ecdsa(
            &approval_key,
            other_digest.as_bytes(),
            &signature
        ));
    }

    #[test]
    fn the_empty_body_hash_is_in_the_request_string() {
        let request =
            request_string("GET", "/v1/status", DEVICE_ID, TIME, &[0; 16], b"").expect("string");
        assert!(request.ends_with(EMPTY_BODY_HASH));
        let with_body = request_string(
            "POST",
            "/x",
            DEVICE_ID,
            TIME,
            &[0; 16],
            br#"{"remember":false}"#,
        )
        .expect("string");
        assert!(
            with_body.ends_with("c21638494d6f31b1eb753c01dc27df1491cafaa42e908bf82eaede49134884c3")
        );
    }

    #[test]
    fn the_pairing_code_matches_the_vector() {
        let hash = pairing_code_hash(&bytes(SECRET), &bytes(REQUEST_KEY), &bytes(APPROVAL_KEY));
        assert_eq!(hex(&hash), CODE_HASH);
        let code = pairing_code(&hash);
        assert_eq!(code, "348942");
        assert_eq!(display_code(&code), "348 942");
    }

    #[test]
    fn the_pairing_code_has_leading_zeros_and_depends_on_every_input() {
        let mut hash = [0u8; 32];
        hash[3] = 7;
        assert_eq!(pairing_code(&hash), "000007");
        assert_eq!(display_code("000007"), "000 007");
        let secret = bytes(SECRET);
        let request_key = bytes(REQUEST_KEY);
        let approval_key = bytes(APPROVAL_KEY);
        let base = pairing_code_hash(&secret, &request_key, &approval_key);
        let mut other_secret = secret.clone();
        other_secret[0] ^= 1;
        assert_ne!(
            base,
            pairing_code_hash(&other_secret, &request_key, &approval_key)
        );
        assert_ne!(
            base,
            pairing_code_hash(&secret, &approval_key, &request_key)
        );
        let mut other_key = approval_key.clone();
        other_key[64] ^= 1;
        assert_ne!(base, pairing_code_hash(&secret, &request_key, &other_key));
    }

    #[test]
    fn builders_refuse_a_control_character() {
        let key = bytes(REQUEST_KEY);
        assert!(pair_string(DEVICE_ID, "a\nb", &key, &key).is_none());
        assert!(pair_string("a\rb", DEVICE_NAME, &key, &key).is_none());
        assert!(pair_string(DEVICE_ID, "a\u{0}b", &key, &key).is_none());
        assert!(request_string("GET", "/v1/x\n/v1/y", DEVICE_ID, 1, &[0; 16], b"").is_none());
        assert!(request_string("GE\tT", "/v1/x", DEVICE_ID, 1, &[0; 16], b"").is_none());
        assert!(approve_string(DEVICE_ID, ApproveAction::Approve, 1, "ab\ncd", 1).is_none());
        assert!(approve_string("d\n", ApproveAction::Approve, 1, "ab", 1).is_none());
    }

    #[test]
    fn fresh_signatures_verify_differ_and_fail_when_changed() {
        let key = TestKey::generate();
        let other = TestKey::generate();
        let text = "apassy-companion-request-v1\nGET\n/v1/status";
        let first = key.sign(text);
        let second = key.sign(text);
        assert_ne!(first, second, "ECDSA signatures are randomized");
        assert!(is_public_key_shape(&key.public()));
        for signature in [&first, &second] {
            assert!(verify_ecdsa(&key.public(), text.as_bytes(), signature));
            assert!(!verify_ecdsa(&other.public(), text.as_bytes(), signature));
            assert!(!verify_ecdsa(
                &key.public(),
                change_one_character(text).as_bytes(),
                signature
            ));
        }
    }

    #[test]
    fn a_bad_key_or_signature_does_not_verify() {
        let key = TestKey::generate();
        let text = "text";
        let signature = key.sign(text);
        let public = key.public();
        // Not 65 bytes, not uncompressed, not on the curve.
        assert!(!verify_ecdsa(&public[..64], text.as_bytes(), &signature));
        let mut compressed_tag = public.clone();
        compressed_tag[0] = 0x02;
        assert!(!verify_ecdsa(&compressed_tag, text.as_bytes(), &signature));
        let mut off_curve = public.clone();
        off_curve[64] ^= 1;
        assert!(!verify_ecdsa(&off_curve, text.as_bytes(), &signature));
        assert!(!verify_ecdsa(&[], text.as_bytes(), &signature));
        // A signature that is empty, truncated, too long, or not DER.
        assert!(!verify_ecdsa(&public, text.as_bytes(), &[]));
        assert!(!verify_ecdsa(
            &public,
            text.as_bytes(),
            &signature[..signature.len() - 1]
        ));
        let mut long = signature.clone();
        long.extend_from_slice(&[0; 8]);
        assert!(!verify_ecdsa(&public, text.as_bytes(), &long));
        assert!(!verify_ecdsa(&public, text.as_bytes(), &[0x30; 71]));
        assert!(verify_ecdsa(&public, text.as_bytes(), &signature));
    }

    #[test]
    fn constant_time_eq_compares_bytes() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"12345", b"123456"));
        assert!(constant_time_eq(b"", b""));
    }
}
