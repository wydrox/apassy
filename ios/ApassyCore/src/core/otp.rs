//! One-time passwords (contract section 7): RFC 6238 TOTP from an `otpauth://totp/`
//! URI or a bare Base32 secret. The seed stays in an erasing buffer; only the code
//! leaves the core.

use ring::hmac;
use zeroize::Zeroizing;

use super::errors::{CoreError, CoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP setting. Debug is redacted.
pub struct Totp {
    key: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("key", &"[redacted]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

fn not_valid() -> CoreError {
    CoreError::invalid("This one-time password is not a TOTP setting that Apassy can read.")
}

impl Totp {
    /// Parse the stored value of a one-time password field.
    pub fn parse(value: &str) -> CoreResult<Self> {
        let value = value.trim();
        let lower = value
            .get(..10)
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if lower.starts_with("otpauth://") {
            return Self::parse_uri(value);
        }
        Ok(Self {
            key: base32(value).ok_or_else(not_valid)?,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        })
    }

    fn parse_uri(uri: &str) -> CoreResult<Self> {
        let rest = &uri["otpauth://".len()..];
        let (kind, rest) = rest.split_once('/').ok_or_else(not_valid)?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(CoreError::invalid(
                "Apassy shows time-based codes (TOTP) only. This one is counter-based (HOTP).",
            ));
        }
        let query = rest.split_once('?').map(|(_, query)| query).unwrap_or("");
        let mut key = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        for pair in query.split('&') {
            let (name, raw) = pair.split_once('=').unwrap_or((pair, ""));
            let value = Zeroizing::new(percent_decode(raw).ok_or_else(not_valid)?);
            match name.to_ascii_lowercase().as_str() {
                "secret" => key = Some(base32(&value).ok_or_else(not_valid)?),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(not_valid()),
                    }
                }
                "digits" => {
                    digits = value
                        .parse()
                        .ok()
                        .filter(|d| (6..=8).contains(d))
                        .ok_or_else(not_valid)?
                }
                "period" => {
                    period = value
                        .parse()
                        .ok()
                        .filter(|p| (15..=120).contains(p))
                        .ok_or_else(not_valid)?
                }
                _ => {}
            }
        }
        Ok(Self {
            key: key.ok_or_else(not_valid)?,
            algorithm,
            digits,
            period,
        })
    }

    /// The code at `unix` seconds, and the seconds left in its period.
    pub fn code_at(&self, unix: u64) -> (String, u64) {
        let counter = unix / self.period;
        let algorithm = match self.algorithm {
            Algorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::Sha256 => hmac::HMAC_SHA256,
            Algorithm::Sha512 => hmac::HMAC_SHA512,
        };
        let key = hmac::Key::new(algorithm, &self.key);
        let tag = hmac::sign(&key, &counter.to_be_bytes());
        let mac = tag.as_ref();
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let binary = (u32::from(mac[offset] & 0x7f) << 24)
            | (u32::from(mac[offset + 1]) << 16)
            | (u32::from(mac[offset + 2]) << 8)
            | u32::from(mac[offset + 3]);
        let code = binary % 10u32.pow(self.digits);
        let width = self.digits as usize;
        (format!("{code:0width$}"), self.period - unix % self.period)
    }
}

/// RFC 4648 Base32 without padding; spaces, `-`, and `=` are ignored, any case. At
/// least 10 bytes (80 bits), as RFC 4226 asks at least 128 and recommends 160.
fn base32(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for ch in text.chars() {
        let value = match ch.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            ' ' | '-' | '=' => continue,
            _ => return None,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    (out.len() >= 10).then_some(out)
}

/// `%XX` and `+` of a query value.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = text.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Whether a field is a one-time password by its label (contract section 7).
pub fn is_otp_label(label: &str) -> bool {
    let label = label.trim().to_lowercase();
    label == "otp" || label == "totp" || label.starts_with("one-time password")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B. The seeds are the ASCII strings of the RFC, in Base32.
    const SHA1_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"
    const SHA256_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SHA512_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    fn uri(seed: &str, algorithm: &str) -> String {
        format!("otpauth://totp/Test?secret={seed}&algorithm={algorithm}&digits=8&period=30")
    }

    #[test]
    fn rfc_6238_vectors() {
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let sha1 = Totp::parse(&uri(SHA1_SEED, "SHA1")).unwrap();
        let sha256 = Totp::parse(&uri(SHA256_SEED, "SHA256")).unwrap();
        let sha512 = Totp::parse(&uri(SHA512_SEED, "SHA512")).unwrap();
        for (time, one, two, five) in cases {
            assert_eq!(sha1.code_at(time).0, one, "SHA1 at {time}");
            assert_eq!(sha256.code_at(time).0, two, "SHA256 at {time}");
            assert_eq!(sha512.code_at(time).0, five, "SHA512 at {time}");
        }
    }

    #[test]
    fn a_bare_secret_has_the_defaults() {
        let totp = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(
            (totp.digits, totp.period, totp.algorithm),
            (6, 30, Algorithm::Sha1)
        );
        let (code, left) = totp.code_at(59);
        assert_eq!(code, "287082");
        assert_eq!(left, 1);
    }

    #[test]
    fn refuses_hotp_short_and_bad_values() {
        assert!(
            Totp::parse("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1")
                .is_err()
        );
        assert!(Totp::parse("GEZDGNBV").is_err());
        assert!(Totp::parse("not base32!").is_err());
        assert!(
            Totp::parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=12")
                .is_err()
        );
        assert!(Totp::parse("otpauth://totp/x?issuer=Example").is_err());
    }

    #[test]
    fn labels() {
        assert!(is_otp_label("One-time password"));
        assert!(is_otp_label("one-time password 2"));
        assert!(is_otp_label("TOTP"));
        assert!(!is_otp_label("Password"));
    }

    #[test]
    fn debug_is_redacted() {
        let totp = Totp::parse(SHA1_SEED).unwrap();
        assert!(!format!("{totp:?}").contains("12345"));
    }
}
