//! The values of a Connect account that a person reads or types (contract
//! connect-account-v1 sections 2, 7.3, and 9): the ids, the link code and its hash, the
//! six safety words of a device link, and the recovery code.
//!
//! The words are the 256 words of relay-sync-v1 section 16 ([`WORDS`]), the list of the
//! relay sync link (`src/sync/relay/devices.rs`); the account link shows six of them,
//! the ADR 0032 handoff form. Nothing here talks to Connect.

use std::fmt;

use zeroize::Zeroizing;

use super::ConnectError;
use crate::companion::crypto::sha256;
use crate::sync::{WORDS, encode_b64u, sha256_hex};

/// The domain of the link hash.
pub const LINK_TAG: &str = "apassy-connect link v1";
/// The domain of the safety words.
pub const SAFETY_TAG: &str = "apassy-connect safety v1";
/// The domain of the recovery hash.
pub const RECOVERY_TAG: &str = "apassy-connect recovery v1";

/// The prefix of a link code.
const LINK_PREFIX: &str = "apassy_alk_";
/// The prefix of a recovery code on the wire.
const RECOVERY_PREFIX: &str = "apassy_rec_";
/// The random bytes of a link code.
const LINK_BYTES: usize = 32;
/// The random bytes of a recovery code.
pub const RECOVERY_BYTES: usize = 16;
/// The number of safety words.
pub const SAFETY_WORDS: usize = 6;

/// `<prefix>` and 10 characters of `a-z2-7`.
fn valid_id(text: &str, prefix: &str) -> bool {
    text.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 10
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    })
}

/// An account id: `acc_` and 10 characters of `a-z2-7`.
pub fn valid_account_id(text: &str) -> bool {
    valid_id(text, "acc_")
}

/// An account device id: `dev_` and 10 characters of `a-z2-7`.
pub fn valid_device_id(text: &str) -> bool {
    valid_id(text, "dev_")
}

/// A group id: `grp_` and 10 characters of `a-z2-7`.
pub fn valid_group_id(text: &str) -> bool {
    valid_id(text, "grp_")
}

/// 64 lowercase hex characters.
fn is_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_lower(bytes: &[u8]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    text
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, ConnectError> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::fill(&mut bytes[..]).map_err(|_| ConnectError::Local)?;
    Ok(bytes)
}

/// A link code: `apassy_alk_<account id>_<64 hex>` (section 2). The device that adds a
/// device makes it and keeps it in memory; it never reaches Connect, which sees only
/// [`LinkCode::link_hash`]. Debug is redacted; the text is erased on drop.
pub struct LinkCode(Zeroizing<String>);

impl fmt::Debug for LinkCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LinkCode").field(&"[redacted]").finish()
    }
}

impl LinkCode {
    /// A new code for `account_id` from the system random source.
    pub fn generate(account_id: &str) -> Result<Self, ConnectError> {
        if !valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        let secret = random::<LINK_BYTES>()?;
        let mut text = Zeroizing::new(String::with_capacity(LINK_PREFIX.len() + 15 + 64));
        text.push_str(LINK_PREFIX);
        text.push_str(account_id);
        text.push('_');
        text.push_str(&hex_lower(&secret[..]));
        Ok(Self(text))
    }

    /// A code that the person pasted or a QR code gave, trimmed. `None` outside the
    /// grammar of section 2.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let rest = text.strip_prefix(LINK_PREFIX)?;
        let (account, secret) = (rest.get(..14)?, rest.get(14..)?);
        let secret = secret.strip_prefix('_')?;
        (valid_account_id(account) && is_hex64(secret))
            .then(|| Self(Zeroizing::new(text.to_owned())))
    }

    /// The account id inside the code.
    pub fn account_id(&self) -> &str {
        &self.0[LINK_PREFIX.len()..LINK_PREFIX.len() + 14]
    }

    /// The text, for the Copy button and the QR code of "Add a device…".
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The link hash that Connect keeps.
    pub fn link_hash(&self) -> String {
        link_hash(&self.0)
    }
}

/// The link hash: b64u of `SHA-256("apassy-connect link v1" 0x00 <link code>)`.
pub fn link_hash(code: &str) -> String {
    let mut message = Zeroizing::new(Vec::with_capacity(LINK_TAG.len() + 1 + code.len()));
    message.extend_from_slice(LINK_TAG.as_bytes());
    message.push(0);
    message.extend_from_slice(code.as_bytes());
    encode_b64u(&sha256(&message))
}

/// The six safety words of a device link (section 7.3): both devices compute them from
/// the account, the code, and both public keys (X9.63, 65 bytes each), and show them with
/// one space between them.
pub fn safety_words(
    account_id: &str,
    link_code: &str,
    confirmer_public_key: &[u8],
    joiner_public_key: &[u8],
) -> String {
    let mut message = Zeroizing::new(Vec::new());
    for part in [
        SAFETY_TAG.as_bytes(),
        account_id.as_bytes(),
        link_code.as_bytes(),
        confirmer_public_key,
    ] {
        message.extend_from_slice(part);
        message.push(0);
    }
    message.extend_from_slice(joiner_public_key);
    let digest = sha256(&message);
    digest[..SAFETY_WORDS]
        .iter()
        .map(|byte| WORDS[usize::from(*byte)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether two texts name the same six safety words. Case and surrounding spaces do not
/// count.
pub fn same_safety_words(a: &str, b: &str) -> bool {
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_lowercase).collect() };
    let (a, b) = (words(a), words(b));
    a.len() == SAFETY_WORDS && a == b
}

/// The recovery code of an account (section 9): 16 random bytes, shown once as 16 words
/// and never stored by Apassy. Debug is redacted; the bytes are erased on drop.
pub struct RecoveryCode(Zeroizing<[u8; RECOVERY_BYTES]>);

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecoveryCode").field(&"[redacted]").finish()
    }
}

impl RecoveryCode {
    /// A new code from the system random source.
    pub fn generate() -> Result<Self, ConnectError> {
        Ok(Self(random::<RECOVERY_BYTES>()?))
    }

    /// The code of these bytes (the test vectors).
    pub fn from_bytes(bytes: [u8; RECOVERY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A code that the person typed: the 16 words (any case, any spaces), or the wire
    /// form `apassy_rec_<32 hex>`. `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let mut bytes = Zeroizing::new([0u8; RECOVERY_BYTES]);
        if let Some(hex) = text.strip_prefix(RECOVERY_PREFIX) {
            if hex.len() != RECOVERY_BYTES * 2
                || !hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return None;
            }
            for (index, pair) in hex.as_bytes().chunks(2).enumerate() {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    _ => byte - b'a' + 10,
                };
                bytes[index] = (digit(pair[0]) << 4) | digit(pair[1]);
            }
            return Some(Self(bytes));
        }
        let words: Vec<String> = text.split_whitespace().map(str::to_lowercase).collect();
        if words.len() != RECOVERY_BYTES {
            return None;
        }
        for (index, word) in words.iter().enumerate() {
            let position = WORDS.iter().position(|known| known == word)?;
            bytes[index] = u8::try_from(position).ok()?;
        }
        Some(Self(bytes))
    }

    /// The 16 words, one space between them, as the Mac shows them once.
    pub fn words(&self) -> Zeroizing<String> {
        Zeroizing::new(
            self.0
                .iter()
                .map(|byte| WORDS[usize::from(*byte)])
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    /// The wire form, `apassy_rec_<32 hex>`, for `POST /v1/account/recover` only.
    pub fn wire(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::from(RECOVERY_PREFIX));
        text.push_str(&hex_lower(&self.0[..]));
        text
    }

    /// The recovery hash that Connect keeps: hex of
    /// `SHA-256("apassy-connect recovery v1" 0x00 <16 bytes>)`.
    pub fn hash(&self) -> String {
        let mut message = Zeroizing::new(Vec::with_capacity(RECOVERY_TAG.len() + 17));
        message.extend_from_slice(RECOVERY_TAG.as_bytes());
        message.push(0);
        message.extend_from_slice(&self.0[..]);
        sha256_hex(&message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_follow_the_grammar() {
        assert!(valid_account_id("acc_k7m2q4x3ca"));
        assert!(valid_device_id("dev_m2k7q3x4ab"));
        assert!(valid_group_id("grp_f4m6n2p7qa"));
        for bad in [
            "acc_k7m2q4x3c",
            "acc_k7m2q4x3cab",
            "acc_K7M2Q4X3CA",
            "acc_k7m2q4x3c1",
            "dev_m2k7q3x4ab",
        ] {
            assert!(!valid_account_id(bad), "{bad}");
        }
    }

    #[test]
    fn a_link_code_names_its_account_and_hides_in_debug() {
        let code = LinkCode::generate("acc_k7m2q4x3ca").unwrap();
        assert_eq!(code.account_id(), "acc_k7m2q4x3ca");
        assert_eq!(code.expose().len(), "apassy_alk_".len() + 14 + 1 + 64);
        let again = LinkCode::parse(&format!("  {}\n", code.expose())).unwrap();
        assert_eq!(again.link_hash(), code.link_hash());
        assert_eq!(code.link_hash().len(), 43);
        assert!(!format!("{code:?}").contains(&code.expose()[20..]));
        assert_ne!(
            LinkCode::generate("acc_k7m2q4x3ca").unwrap().expose(),
            code.expose()
        );
        for bad in [
            "apassy_lnk_t_7k2m5q4x3c_".to_owned() + &"cd".repeat(32),
            "apassy_alk_acc_k7m2q4x3ca_".to_owned() + &"CD".repeat(32),
            "apassy_alk_acc_k7m2q4x3ca_".to_owned() + &"cd".repeat(31),
            "apassy_alk_acc_k7m2q4x3ca".to_owned() + &"cd".repeat(32),
        ] {
            assert!(LinkCode::parse(&bad).is_none(), "{bad}");
        }
        assert!(LinkCode::generate("t_7k2m5q4x3c").is_err());
    }

    #[test]
    fn six_words_compare_without_case_and_spaces() {
        assert!(same_safety_words(
            "blaze cable flute board seal tiger",
            "  Blaze CABLE flute  board seal tiger "
        ));
        assert!(!same_safety_words(
            "blaze cable flute board seal",
            "blaze cable flute board seal"
        ));
        assert!(!same_safety_words(
            "blaze cable flute board seal tiger",
            "blaze cable flute board tiger seal"
        ));
    }

    #[test]
    fn a_recovery_code_reads_back_from_its_words_and_its_wire_form() {
        let code = RecoveryCode::generate().unwrap();
        let words = code.words();
        assert_eq!(words.split(' ').count(), 16);
        let typed = RecoveryCode::parse(&words.to_uppercase()).unwrap();
        assert_eq!(typed.hash(), code.hash());
        let wire = RecoveryCode::parse(&code.wire()).unwrap();
        assert_eq!(wire.hash(), code.hash());
        assert_eq!(code.hash().len(), 64);
        assert!(!format!("{code:?}").contains(words.split(' ').next().unwrap()));
        assert!(RecoveryCode::parse("apassy_rec_00").is_none());
        assert!(RecoveryCode::parse("atlas attic").is_none());
        assert!(RecoveryCode::parse(&"notaword ".repeat(16)).is_none());
    }
}
