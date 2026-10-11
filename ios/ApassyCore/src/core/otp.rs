//! One-time passwords (contract section 7). The RFC 6238 code is in `apassy::otp`; this
//! file maps its errors to `CoreError` and keeps the shape that the core uses. The seed
//! stays in an erasing buffer; only the code leaves the core.

use super::errors::{CoreError, CoreResult};

#[cfg(test)]
use apassy::otp::Algorithm;
pub use apassy::otp::{is_otp_label, is_totp_uri};

/// A parsed TOTP setting. Debug is redacted.
#[derive(Debug)]
pub struct Totp {
    inner: apassy::otp::Totp,
    pub digits: u32,
    pub period: u64,
}

impl Totp {
    /// Parse the stored value of a one-time password field.
    pub fn parse(value: &str) -> CoreResult<Self> {
        let inner =
            apassy::otp::Totp::parse(value).map_err(|err| CoreError::invalid(err.to_string()))?;
        Ok(Self {
            digits: inner.digits(),
            period: inner.period(),
            inner,
        })
    }

    /// The code at `unix` seconds, and the seconds left in its period.
    pub fn code_at(&self, unix: u64) -> (String, u64) {
        self.inner.code_at(unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

    #[test]
    fn the_core_reads_a_secret_and_an_rfc_vector() {
        let totp = Totp::parse(&format!(
            "otpauth://totp/Test?secret={SHA1_SEED}&digits=8&period=30"
        ))
        .unwrap();
        assert_eq!(
            (totp.digits, totp.period, totp.inner.algorithm()),
            (8, 30, Algorithm::Sha1)
        );
        assert_eq!(totp.code_at(59), ("94287082".to_owned(), 1));
        let bare = Totp::parse(SHA1_SEED).unwrap();
        assert_eq!(bare.code_at(59).0, "287082");
    }

    #[test]
    fn errors_are_invalid_input_with_a_plain_message() {
        let hotp =
            Totp::parse(&format!("otpauth://hotp/x?secret={SHA1_SEED}&counter=1")).unwrap_err();
        assert_eq!(hotp.code, "invalid_input");
        assert!(hotp.message.contains("HOTP"));
        let bad = Totp::parse("not base32!").unwrap_err();
        assert_eq!(bad.code, "invalid_input");
        assert!(bad.message.contains("not a TOTP setting"));
    }

    #[test]
    fn the_labels_and_uris_come_from_the_shared_module() {
        for label in ["One-time password", "One-time code", "OTP", "totp 2"] {
            assert!(is_otp_label(label), "{label}");
        }
        assert!(!is_otp_label("Password"));
        assert!(is_totp_uri("otpauth://totp/x?secret=ABC"));
        assert!(!is_totp_uri("otpauth://hotp/x"));
    }

    #[test]
    fn debug_is_redacted() {
        let totp = Totp::parse(SHA1_SEED).unwrap();
        let text = format!("{totp:?}");
        assert!(!text.contains("12345") && !text.contains("GEZD"));
    }
}
