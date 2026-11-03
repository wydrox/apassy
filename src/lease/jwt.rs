//! RS256 compact JSON Web Tokens (RFC 7515 and 7519) for way C (plan s6 unit C2): the
//! JWT of a GitHub App (`iss` = the app) and the assertion of a Google service account.
//!
//! The private key is a PEM `RSA PRIVATE KEY` (PKCS#1, read with
//! [`RsaKeyPair::from_der`]) or `PRIVATE KEY` (PKCS#8, [`RsaKeyPair::from_pkcs8`]), the
//! two forms of contract private-sharing-v1 section 3.1. The armor is stripped here: one
//! `BEGIN` line, base64 lines, one `END` line with the same label. An encrypted key (its
//! `Proc-Type` header, or `ENCRYPTED PRIVATE KEY`) is refused. The base64 text and the
//! DER are held in erased buffers; `ring` holds the parsed key. `ring` takes an RSA key of
//! 2048 to 4096 bits. No new crate: `ring` signs, `crate::native::base64` encodes.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::native::base64;

/// The PEM label of a PKCS#1 RSA key (GitHub's download).
const PKCS1_LABEL: &str = "RSA PRIVATE KEY";
/// The PEM label of a PKCS#8 key (a Google service-account key).
const PKCS8_LABEL: &str = "PRIVATE KEY";
/// The longest PEM text that is read; a 4096-bit key is about 3.3 KB.
const MAX_PEM_BYTES: usize = 16 * 1024;
/// `iat` of a JWT this many seconds in the past, for a provider whose clock is behind
/// (contract section 3.3: "`iat` 60 s back").
pub const BACKDATE_SECS: u64 = 60;
/// `exp` of a JWT this many seconds after now: 9 minutes, under GitHub's limit of 10
/// minutes (contract section 3.3: "`exp` at most 9 minutes ahead").
pub const LIFETIME_SECS: u64 = 540;

const NOT_A_KEY: &str = "the private key is not an unencrypted PEM RSA PRIVATE KEY or PRIVATE KEY.";
const NOT_RSA: &str =
    "the private key is not an RSA key of 2048 to 4096 bits that Apassy can read.";

/// An RSA private key for RS256. `Debug` shows nothing of it.
pub struct RsaKey(RsaKeyPair);

impl fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RsaKey([redacted])")
    }
}

impl RsaKey {
    /// Read a PEM private key (module documentation). The reason of a refusal names no
    /// part of the key.
    pub fn from_pem(pem: &str) -> Result<Self, &'static str> {
        if pem.len() > MAX_PEM_BYTES {
            return Err(NOT_A_KEY);
        }
        let text = pem.trim();
        let (pkcs1, body) = [(true, PKCS1_LABEL), (false, PKCS8_LABEL)]
            .into_iter()
            .find_map(|(pkcs1, label)| {
                let body = text
                    .strip_prefix(&format!("-----BEGIN {label}-----"))?
                    .strip_suffix(&format!("-----END {label}-----"))?;
                Some((pkcs1, body))
            })
            .ok_or(NOT_A_KEY)?;
        let mut base64_text = Zeroizing::new(String::with_capacity(body.len()));
        for c in body.chars() {
            if c.is_ascii_whitespace() {
                continue;
            }
            if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')) {
                // A header such as `Proc-Type: 4,ENCRYPTED`, or not base64.
                return Err(NOT_A_KEY);
            }
            base64_text.push(c);
        }
        let der = Zeroizing::new(base64::decode(&base64_text).ok_or(NOT_A_KEY)?);
        drop(base64_text);
        let pair = if pkcs1 {
            RsaKeyPair::from_der(&der)
        } else {
            RsaKeyPair::from_pkcs8(&der)
        };
        pair.map(Self).map_err(|_| NOT_RSA)
    }

    /// The public key (DER `RSAPublicKey`), for a test that verifies a signature.
    pub fn public_key_der(&self) -> &[u8] {
        self.0.public().as_ref()
    }

    fn sign(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let mut signature = Zeroizing::new(vec![0u8; self.0.public().modulus_len()]);
        self.0
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| "the private key could not sign.")?;
        Ok(signature)
    }
}

/// A compact JWS `header.claims.signature` with RS256: the header is
/// `{"alg":"RS256","typ":"JWT"}`, with `"kid"` when `kid` is given; `claims` is a JSON
/// object of claims (no secret). The token is a credential for its lifetime, so it is
/// returned in an erased buffer of the exact size.
pub fn rs256(
    key: &RsaKey,
    kid: Option<&str>,
    claims: &Value,
) -> Result<Zeroizing<String>, &'static str> {
    if !claims.is_object() {
        return Err("the claims of a JWT are a JSON object.");
    }
    let mut header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    if let Some(kid) = kid {
        header["kid"] = Value::String(kid.to_owned());
    }
    let header = serde_json::to_vec(&header).map_err(|_| "the JWT header could not be written.")?;
    let claims = serde_json::to_vec(claims).map_err(|_| "the JWT claims could not be written.")?;
    let header = base64::encode_url(&header);
    let claims = base64::encode_url(&claims);
    let mut signing_input = String::with_capacity(header.len() + 1 + claims.len());
    signing_input.push_str(&header);
    signing_input.push('.');
    signing_input.push_str(&claims);
    let signature = key.sign(signing_input.as_bytes())?;
    let signature = Zeroizing::new(base64::encode_url(&signature));
    let mut token = Zeroizing::new(String::with_capacity(
        signing_input.len() + 1 + signature.len(),
    ));
    token.push_str(&signing_input);
    token.push('.');
    token.push_str(&signature);
    Ok(token)
}

#[cfg(test)]
pub(crate) mod tests {
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    use super::*;

    /// The synthetic RSA 2048 key of the passkey tests, PKCS#8 DER. Not a real key.
    pub(crate) const RSA_PKCS8_DER: &[u8] =
        include_bytes!("../../tests/fixtures/passkeys/rsa2048-synthetic.pk8");

    /// The PEM form of `der` with `label`, in lines of 64 characters.
    pub(crate) fn pem(label: &str, der: &[u8]) -> String {
        let body = base64::encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64"));
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    }

    /// The test key as a PKCS#8 PEM (`PRIVATE KEY`), as in a Google key file.
    pub(crate) fn pkcs8_pem() -> String {
        pem(PKCS8_LABEL, RSA_PKCS8_DER)
    }

    /// The test key as a PKCS#1 PEM (`RSA PRIVATE KEY`), as GitHub gives it: the
    /// `RSAPrivateKey` inside the PKCS#8 wrapper.
    pub(crate) fn pkcs1_pem() -> String {
        pem(PKCS1_LABEL, pkcs1_der())
    }

    /// The `RSAPrivateKey` (the content of the `privateKey` OCTET STRING) of the PKCS#8
    /// test key.
    pub(crate) fn pkcs1_der() -> &'static [u8] {
        fn next(input: &[u8]) -> (u8, &[u8], &[u8]) {
            let tag = input[0];
            let (len, start) = match input[1] {
                n if n < 0x80 => (usize::from(n), 2),
                0x81 => (usize::from(input[2]), 3),
                0x82 => ((usize::from(input[2]) << 8) | usize::from(input[3]), 4),
                other => panic!("DER length form {other:#x}"),
            };
            (tag, &input[start..start + len], &input[start + len..])
        }
        let (tag, outer, _) = next(RSA_PKCS8_DER);
        assert_eq!(tag, 0x30);
        let (tag, _version, rest) = next(outer);
        assert_eq!(tag, 0x02);
        let (tag, _algorithm, rest) = next(rest);
        assert_eq!(tag, 0x30);
        let (tag, key, _) = next(rest);
        assert_eq!(tag, 0x04);
        key
    }

    /// The test key.
    pub(crate) fn key() -> RsaKey {
        RsaKey::from_pem(&pkcs8_pem()).expect("test key")
    }

    /// Check an RS256 JWT with the public key of the test key and give its header and
    /// claims. Panics when the form or the signature is wrong.
    pub(crate) fn verify(token: &str) -> (Value, Value) {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "a compact JWS has three parts");
        let public = key();
        let signature = base64::decode_url(parts[2]).expect("base64url signature");
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public.public_key_der())
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("the signature verifies with the test key");
        let json = |part: &str| -> Value {
            serde_json::from_slice(&base64::decode_url(part).expect("base64url")).expect("JSON")
        };
        (json(parts[0]), json(parts[1]))
    }

    #[test]
    fn both_pem_forms_read_and_sign_rs256() {
        let claims = serde_json::json!({"iss": "123456", "iat": 1, "exp": 541});
        for pem in [
            pkcs8_pem(),
            pkcs1_pem(),
            format!("\n  {}\r\n", pkcs1_pem().replace('\n', "\r\n")),
        ] {
            let key = RsaKey::from_pem(&pem).expect("key");
            let token = rs256(&key, None, &claims).expect("token");
            assert_eq!(token.capacity(), token.len(), "the buffer never grew");
            let (header, read) = verify(&token);
            assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
            assert_eq!(read, claims);
            assert!(!token.contains('='), "base64url without padding");
        }
        let token = rs256(&key(), Some("abc123"), &claims).expect("token");
        let (header, _) = verify(&token);
        assert_eq!(header["kid"], "abc123");
        assert!(rs256(&key(), None, &serde_json::json!([1])).is_err());
        assert_eq!(format!("{:?}", key()), "RsaKey([redacted])");
    }

    #[test]
    fn a_key_that_is_not_an_unencrypted_rsa_pem_is_refused() {
        let pkcs8 = pkcs8_pem();
        let body_line = pkcs8.lines().nth(1).expect("a base64 line").to_owned();
        let encrypted = pkcs1_pem().replace(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n",
        );
        let rsa1024 = pem(
            PKCS8_LABEL,
            include_bytes!("../../tests/fixtures/passkeys/rsa1024-synthetic.pk8"),
        );
        let p521 = pem(
            PKCS8_LABEL,
            include_bytes!("../../tests/fixtures/passkeys/p521-synthetic.pk8"),
        );
        let cases = [
            String::new(),
            "not a key".to_owned(),
            pkcs8.replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"),
            pkcs8.replace("-----END PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
            encrypted,
            pkcs8.replace(&body_line, &body_line[..63]),
            pem(PKCS1_LABEL, RSA_PKCS8_DER),
            pem(PKCS8_LABEL, pkcs1_der()),
            rsa1024,
            p521,
            format!("{pkcs8}{}", "A".repeat(MAX_PEM_BYTES)),
        ];
        for (index, pem) in cases.iter().enumerate() {
            let why = RsaKey::from_pem(pem).unwrap_err();
            assert!(why == NOT_A_KEY || why == NOT_RSA, "case {index}: {why}");
            assert!(!why.contains(&body_line));
        }
    }
}
