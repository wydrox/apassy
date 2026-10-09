//! One-time passwords: RFC 6238 TOTP from an `otpauth://totp/` URI or a bare Base32
//! secret. The seed stays in an erasing buffer. `Debug` never shows it.
//!
//! The desktop app, the iPhone core, and the importers use this one module, so a code
//! and a label mean the same thing on every side.

use ring::hmac;
use zeroize::Zeroizing;

/// The label that Apassy gives to a one-time password field that it creates.
pub const LABEL: &str = "One-time password";

/// The longest value that `Totp::parse` reads.
const MAX_VALUE_BYTES: usize = 2048;
/// RFC 4226 asks for at least 128 bits and recommends 160. Apassy accepts 80 bits or
/// more, because some services issue shorter seeds.
const MIN_KEY_BYTES: usize = 10;

/// Why a value is not a TOTP setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// The value is not a TOTP setting that Apassy can read.
    Invalid,
    /// The value is an `otpauth://hotp/` setting. Apassy does not make counter-based codes.
    Hotp,
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "This one-time password is not a TOTP setting that Apassy can read.",
            Self::Hotp => {
                "Apassy shows time-based codes (TOTP) only. This one is counter-based (HOTP)."
            }
        })
    }
}

impl std::error::Error for OtpError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP setting. `Debug` hides the seed.
pub struct Totp {
    key: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
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

impl Totp {
    /// Parse the stored value of a one-time password field: an `otpauth://totp/` URI or
    /// a bare Base32 secret (30 seconds, 6 digits, SHA-1).
    ///
    /// The parser is strict. It refuses HOTP, other `otpauth` types, a missing or short
    /// secret, an unknown algorithm, digits outside 6 to 8, a period outside 15 to 120
    /// seconds, and a parameter that appears twice.
    pub fn parse(value: &str) -> Result<Self, OtpError> {
        let value = value.trim();
        if value.len() > MAX_VALUE_BYTES {
            return Err(OtpError::Invalid);
        }
        if has_uri_prefix(value) {
            return Self::parse_uri(value);
        }
        Ok(Self {
            key: base32(value).ok_or(OtpError::Invalid)?,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        })
    }

    fn parse_uri(uri: &str) -> Result<Self, OtpError> {
        let rest = &uri[SCHEME.len()..];
        // Some providers omit the label and put the query after the type.
        let end = rest.find(['/', '?']).ok_or(OtpError::Invalid)?;
        let (kind, rest) = rest.split_at(end);
        if kind.eq_ignore_ascii_case("hotp") {
            return Err(OtpError::Hotp);
        }
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(OtpError::Invalid);
        }
        let query = rest.split_once('?').map_or("", |(_, query)| query);
        // A fragment is not part of the query.
        let query = query.split_once('#').map_or(query, |(query, _)| query);
        let mut key = None;
        let mut algorithm = None;
        let mut digits = None;
        let mut period = None;
        for pair in query.split('&') {
            let (name, raw) = pair.split_once('=').unwrap_or((pair, ""));
            let name = name.to_ascii_lowercase();
            if !matches!(name.as_str(), "secret" | "algorithm" | "digits" | "period") {
                continue;
            }
            let value = percent_decode(raw).ok_or(OtpError::Invalid)?;
            match name.as_str() {
                "secret" => set_once(&mut key, base32(&value).ok_or(OtpError::Invalid)?)?,
                "algorithm" => set_once(
                    &mut algorithm,
                    match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(OtpError::Invalid),
                    },
                )?,
                "digits" => set_once(
                    &mut digits,
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|d| (6..=8).contains(d))
                        .ok_or(OtpError::Invalid)?,
                )?,
                _ => set_once(
                    &mut period,
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|p| (15..=120).contains(p))
                        .ok_or(OtpError::Invalid)?,
                )?,
            }
        }
        Ok(Self {
            key: key.ok_or(OtpError::Invalid)?,
            algorithm: algorithm.unwrap_or(Algorithm::Sha1),
            digits: digits.unwrap_or(6),
            period: period.unwrap_or(30),
        })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// Borrow the setup key for an owner-approved platform credential transfer.
    /// The caller must not display, log, or write it to an unencrypted file.
    /// The key remains in this setting's erasing buffer.
    pub fn setup_key_bytes(&self) -> &[u8] {
        &self.key
    }

    /// The length of one code period, in seconds.
    pub fn period(&self) -> u64 {
        self.period
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

    /// The code now, and the seconds left in its period.
    pub fn code_now(&self) -> (String, u64) {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        self.code_at(unix)
    }
}

const SCHEME: &str = "otpauth://";

/// A parameter may appear once.
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), OtpError> {
    match slot {
        Some(_) => Err(OtpError::Invalid),
        None => {
            *slot = Some(value);
            Ok(())
        }
    }
}

fn has_uri_prefix(value: &str) -> bool {
    value
        .get(..SCHEME.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(SCHEME))
}

/// RFC 4648 Base32 in any case. Spaces and `-` between groups are ignored, and `=`
/// padding is allowed at the end only. At least 10 bytes (80 bits). The text must have
/// a length that Base32 can make.
fn base32(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let text = text.trim_end_matches('=');
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let mut buffer: u64 = 0;
    let mut bits = 0;
    let mut symbols = 0usize;
    for ch in text.chars() {
        let value = match ch.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            ' ' | '-' => continue,
            _ => return None,
        };
        symbols += 1;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    // 1, 3, and 6 symbols in a group of 8 cannot come from whole bytes.
    if matches!(symbols % 8, 1 | 3 | 6) {
        return None;
    }
    (out.len() >= MIN_KEY_BYTES).then_some(out)
}

/// `%XX` and `+` of a query value.
fn percent_decode(text: &str) -> Option<Zeroizing<String>> {
    let bytes = text.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
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
    Some(Zeroizing::new(std::str::from_utf8(&out).ok()?.to_owned()))
}

/// Whether a field is a one-time password by its label.
///
/// It accepts `OTP` and `TOTP`, and the labels that start with "One-time password" or
/// "One-time code" (also "One time ..."), in any case. The legacy command-line import
/// used "One-time code". A number after the name (`OTP 2`) or text after a space or
/// punctuation (`One-time password (work)`) is allowed, because labels must be unique.
pub fn is_otp_label(label: &str) -> bool {
    let label = label.split_whitespace().collect::<Vec<_>>().join(" ");
    let label = label.to_lowercase();
    let after = |name: &str| label.strip_prefix(name);
    for name in ["otp", "totp"] {
        if let Some(rest) = after(name) {
            return rest.is_empty()
                || rest.strip_prefix(' ').is_some_and(|suffix| {
                    !suffix.is_empty()
                        && (suffix.chars().all(|c| c.is_ascii_digit())
                            || (suffix.starts_with('(') && suffix.ends_with(')'))
                            || (suffix.starts_with('[') && suffix.ends_with(']')))
                });
        }
    }
    ["one-time", "one time", "one\u{2011}time"]
        .iter()
        .filter_map(|prefix| after(prefix))
        .filter_map(|rest| rest.strip_prefix(' '))
        .any(|rest| {
            ["password", "code"].iter().any(|word| {
                rest.strip_prefix(word)
                    .is_some_and(|tail| !tail.starts_with(|c: char| c.is_alphanumeric()))
            })
        })
}

/// Whether a value is an explicit `otpauth://totp/` URI. It checks the start only and
/// reads no seed, so it is cheap for a list of fields.
pub fn is_totp_uri(value: &str) -> bool {
    let value = value.trim_start();
    let start = "otpauth://totp";
    value
        .get(..start.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(start))
        && matches!(value.as_bytes().get(start.len()), None | Some(b'/' | b'?'))
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
    fn a_uri_without_a_label_makes_the_same_code() {
        let labeled = Totp::parse(&uri(SHA1_SEED, "SHA1")).unwrap();
        let unlabeled =
            format!("otpauth://totp?secret={SHA1_SEED}&algorithm=SHA1&digits=8&period=30");
        assert!(is_totp_uri(&unlabeled));
        assert_eq!(
            Totp::parse(&unlabeled).unwrap().code_at(59),
            labeled.code_at(59)
        );
        assert_eq!(
            Totp::parse("otpauth://hotp?secret=ABC").unwrap_err(),
            OtpError::Hotp
        );
    }

    #[test]
    fn rfc_6238_vectors() {
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let sha1 = Totp::parse(&uri(SHA1_SEED, "SHA1")).unwrap();
        let sha256 = Totp::parse(&uri(SHA256_SEED, "SHA256")).unwrap();
        let sha512 = Totp::parse(&uri(SHA512_SEED, "SHA512")).unwrap();
        assert_eq!(sha256.algorithm(), Algorithm::Sha256);
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
            (totp.digits(), totp.period(), totp.algorithm()),
            (6, 30, Algorithm::Sha1)
        );
        let (code, left) = totp.code_at(59);
        assert_eq!(code, "287082");
        assert_eq!(left, 1);
        assert_eq!(totp.code_at(60).1, 30);
    }

    #[test]
    fn the_period_and_the_digits_change_the_code() {
        let totp = Totp::parse(&format!(
            "OTPAUTH://TOTP/Example:me%40example.test?SECRET={SHA1_SEED}&issuer=Example&period=60&digits=7"
        ))
        .unwrap();
        assert_eq!((totp.digits(), totp.period()), (7, 60));
        let (code, left) = totp.code_at(59);
        assert_eq!(code.len(), 7);
        assert_eq!(left, 1);
        // Counter 0 for the whole first 60 seconds.
        assert_eq!(totp.code_at(0).0, code);
        assert_ne!(totp.code_at(60).0, code);
    }

    #[test]
    fn padding_and_groups_are_allowed() {
        let plain = Totp::parse(SHA1_SEED).unwrap().code_at(59).0;
        for value in [
            "GEZDGNBV-GY3TQOJQ-GEZDGNBV-GY3TQOJQ",
            "  gezdgnbvgy3tqojqgezdgnbvgy3tqojq  ",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
        ] {
            assert_eq!(Totp::parse(value).unwrap().code_at(59).0, plain, "{value}");
        }
        // A percent-encoded space or a plus is a space, and a space is a group break.
        let encoded = "otpauth://totp/x?secret=GEZDGNBV%20GY3TQOJQ+GEZDGNBV%20GY3TQOJQ";
        assert_eq!(Totp::parse(encoded).unwrap().code_at(59).0, plain);
    }

    #[test]
    fn refuses_hotp_short_and_bad_values() {
        assert_eq!(
            Totp::parse("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1")
                .unwrap_err(),
            OtpError::Hotp
        );
        assert_eq!(
            Totp::parse("otpauth://steam/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap_err(),
            OtpError::Invalid
        );
        for bad in [
            "",
            "GEZDGNBV",
            "not base32!",
            "GEZDGNBVGY3TQOJ1",
            // Padding in the middle.
            "GEZDGNBV=GY3TQOJQ",
            // A length that Base32 cannot make (17 symbols).
            "GEZDGNBVGY3TQOJQG",
            "otpauth://totp",
            "otpauth://totp/x?issuer=Example",
            "otpauth://totp/x?secret=",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=12",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=5",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=300",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&period=30",
            "otpauth://totp/x?secret=%ZZ",
            "otpauth://totp/x?secret=%FF%FE",
        ] {
            assert_eq!(Totp::parse(bad).unwrap_err(), OtpError::Invalid, "{bad:?}");
        }
        let long = format!("otpauth://totp/{}?secret={SHA1_SEED}", "a".repeat(3000));
        assert!(Totp::parse(&long).is_err());
        // A multi-byte character at the cut must not panic.
        assert!(Totp::parse("ééééééééééé").is_err());
        assert!(Totp::parse("otpauth:/é").is_err());
    }

    #[test]
    fn the_error_messages_are_plain() {
        assert!(OtpError::Hotp.to_string().contains("HOTP"));
        assert!(OtpError::Invalid.to_string().contains("TOTP"));
    }

    #[test]
    fn labels() {
        for label in [
            "One-time password",
            "one-time password 2",
            "ONE-TIME PASSWORD",
            "  One-time   password ",
            "One-time password (work)",
            "One-time code",
            "One-time code 3",
            "one time password",
            "One time code",
            "TOTP",
            "totp",
            "OTP",
            "otp 2",
            "OTP (work)",
            "TOTP [backup]",
        ] {
            assert!(is_otp_label(label), "{label:?}");
        }
        for label in [
            "Password",
            "",
            "otpx",
            "otp backup",
            "OTP (work",
            "totp-ish",
            "one-timer password",
            "One-time",
            "One-time passwords",
            "One-time codes",
            "Hotpot",
            "Recovery code",
            "Footprint",
        ] {
            assert!(!is_otp_label(label), "{label:?}");
        }
    }

    #[test]
    fn the_canonical_label_is_recognized() {
        assert!(is_otp_label(LABEL));
    }

    #[test]
    fn explicit_totp_uris() {
        assert!(is_totp_uri("otpauth://totp/x?secret=ABC"));
        assert!(is_totp_uri("  OTPAUTH://TOTP/x"));
        assert!(!is_totp_uri("otpauth://hotp/x?secret=ABC"));
        assert!(!is_totp_uri("otpauth://totpx/x"));
        assert!(!is_totp_uri("GEZDGNBVGY3TQOJQ"));
        assert!(!is_totp_uri("é"));
    }

    #[test]
    fn debug_hides_the_seed() {
        let totp = Totp::parse(SHA1_SEED).unwrap();
        let text = format!("{totp:?}");
        assert!(text.contains("[redacted]"));
        assert!(!text.contains("GEZD"));
        assert!(!text.contains("12345"));
        assert!(!text.contains("49, 50"), "no key bytes in {text}");
        let from_uri = Totp::parse(&uri(SHA1_SEED, "SHA1")).unwrap();
        assert!(!format!("{from_uri:?}").contains("GEZD"));
    }

    #[test]
    fn code_now_has_a_valid_remaining_time() {
        let totp = Totp::parse(SHA1_SEED).unwrap();
        let (code, left) = totp.code_now();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&left));
    }
}
