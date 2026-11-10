//! The values of a Connect account that a person reads or types (contract
//! connect-account-v1 sections 2, 7.3, and 9): the ids, the link code with its key
//! fingerprint and its hash, the six safety words of a device link, and the recovery code
//! with the Ed25519 key that it is the seed of.
//!
//! The words are the 256 words of relay-sync-v1 section 16 ([`WORDS`]), the list of the
//! relay sync link (`src/sync/relay/devices.rs`); the account link shows six of them,
//! the ADR 0032 handoff form. Nothing here talks to Connect.

use std::fmt;

use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

use super::ConnectError;
use crate::companion::crypto::sha256;
use crate::sync::{WORDS, encode_b64u};

/// The domain of the link hash.
pub const LINK_TAG: &str = "apassy-connect link v1";
/// The domain of the key fingerprint inside a link code.
pub const LINK_KEYS_TAG: &str = "apassy-connect link-keys v1";
/// The domain of the safety words.
pub const SAFETY_TAG: &str = "apassy-connect safety v1";
/// The domain of the seed of the recovery key.
pub const RECOVERY_KEY_TAG: &str = "apassy-connect recovery key v1";

/// The prefix of a link code.
const LINK_PREFIX: &str = "apassy_alk_";
/// The prefix of the text form of a recovery code.
const RECOVERY_PREFIX: &str = "apassy_rec_";
/// The random bytes of a link code.
const LINK_BYTES: usize = 32;
/// The bytes of the key fingerprint of a link code (32 hex characters).
const FINGERPRINT_BYTES: usize = 16;
/// The length of a link code: the prefix, the account id, the secret, the fingerprint.
const LINK_CODE_LEN: usize = 11 + 14 + 1 + 64 + 1 + 32;
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

/// `len` lowercase hex characters.
fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len
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

/// The key fingerprint of a link code: the first 16 bytes of
/// `SHA-256("apassy-connect link-keys v1" 0x00 <root key> 0x00 <confirmer key>)`, as 32
/// lowercase hex characters. Both keys are X9.63 (65 bytes). It names the root of the
/// account that the making device pinned and the key of the making device, which
/// confirms the join.
pub fn link_fingerprint(root_key: &[u8], confirmer_key: &[u8]) -> String {
    let mut message = Vec::with_capacity(LINK_KEYS_TAG.len() + 2 + root_key.len() * 2);
    message.extend_from_slice(LINK_KEYS_TAG.as_bytes());
    message.push(0);
    message.extend_from_slice(root_key);
    message.push(0);
    message.extend_from_slice(confirmer_key);
    let digest = sha256(&message);
    hex_lower(&digest[..FINGERPRINT_BYTES]).to_string()
}

/// A link code: `apassy_alk_<account id>_<64 hex>_<32 hex fingerprint>` (section 2). The
/// device that adds a device makes it and keeps it in memory; it never reaches Connect,
/// which sees only [`LinkCode::link_hash`]. The fingerprint ([`link_fingerprint`]) lets
/// the joining device check the keys that Connect names for the account. Debug is
/// redacted; the text is erased on drop.
pub struct LinkCode(Zeroizing<String>);

impl fmt::Debug for LinkCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LinkCode").field(&"[redacted]").finish()
    }
}

impl LinkCode {
    /// A new code for `account_id` from the system random source, with the fingerprint of
    /// the account root `root_key` and the key of this device `confirmer_key`.
    pub fn generate(
        account_id: &str,
        root_key: &[u8],
        confirmer_key: &[u8],
    ) -> Result<Self, ConnectError> {
        if !valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        let secret = random::<LINK_BYTES>()?;
        let mut text = Zeroizing::new(String::with_capacity(LINK_CODE_LEN));
        text.push_str(LINK_PREFIX);
        text.push_str(account_id);
        text.push('_');
        text.push_str(&hex_lower(&secret[..]));
        text.push('_');
        text.push_str(&link_fingerprint(root_key, confirmer_key));
        Ok(Self(text))
    }

    /// A code that the person pasted or a QR code gave, trimmed. `None` outside the
    /// grammar of section 2.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.len() != LINK_CODE_LEN {
            return None;
        }
        let rest = text.strip_prefix(LINK_PREFIX)?;
        let (account, rest) = (rest.get(..14)?, rest.get(14..)?);
        let rest = rest.strip_prefix('_')?;
        let (secret, rest) = (rest.get(..64)?, rest.get(64..)?);
        let fingerprint = rest.strip_prefix('_')?;
        (valid_account_id(account)
            && is_hex(secret, 64)
            && is_hex(fingerprint, FINGERPRINT_BYTES * 2))
        .then(|| Self(Zeroizing::new(text.to_owned())))
    }

    /// The account id inside the code.
    pub fn account_id(&self) -> &str {
        &self.0[LINK_PREFIX.len()..LINK_PREFIX.len() + 14]
    }

    /// The key fingerprint inside the code: 32 lowercase hex characters.
    pub fn fingerprint(&self) -> &str {
        &self.0[LINK_CODE_LEN - FINGERPRINT_BYTES * 2..]
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
/// and never stored or sent by Apassy. It is the seed of an Ed25519 key pair
/// ([`RecoveryCode::key`]): Connect keeps only the public key, and a recovery proves the
/// code with a signature. Debug is redacted; the bytes are erased on drop.
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

    /// A code that the person typed: the 16 words (any case, any spaces), or the text
    /// form `apassy_rec_<32 hex>`. `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let mut bytes = Zeroizing::new([0u8; RECOVERY_BYTES]);
        if let Some(hex) = text.strip_prefix(RECOVERY_PREFIX) {
            if !is_hex(hex, RECOVERY_BYTES * 2) {
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

    /// The text form, `apassy_rec_<32 hex>`: a person may type it instead of the words.
    /// It is never sent.
    pub fn text(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::from(RECOVERY_PREFIX));
        text.push_str(&hex_lower(&self.0[..]));
        text
    }

    /// The recovery key: the Ed25519 key pair of the seed
    /// `SHA-256("apassy-connect recovery key v1" 0x00 <16 bytes>)`.
    pub fn key(&self) -> Result<RecoveryKey, ConnectError> {
        let mut message = Zeroizing::new(Vec::with_capacity(RECOVERY_KEY_TAG.len() + 17));
        message.extend_from_slice(RECOVERY_KEY_TAG.as_bytes());
        message.push(0);
        message.extend_from_slice(&self.0[..]);
        let seed = Zeroizing::new(sha256(&message));
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&seed[..]).map_err(|_| ConnectError::Local)?;
        Ok(RecoveryKey(pair))
    }
}

/// The Ed25519 key pair of a recovery code, in memory while a creation or a recovery
/// runs. Debug shows the public key only.
pub struct RecoveryKey(Ed25519KeyPair);

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecoveryKey")
            .field(&self.public_key_b64u())
            .finish()
    }
}

impl RecoveryKey {
    /// The public key as the wire carries it: b64u of 32 bytes (43 characters).
    pub fn public_key_b64u(&self) -> String {
        encode_b64u(self.0.public_key().as_ref())
    }

    /// The Ed25519 signature (64 bytes) over `message`. It signs only an
    /// `apassy-connect recover v1` message ([`super::device_key::recover_message`]); any
    /// other message is [`ConnectError::TagRefused`].
    pub fn sign_recover(&self, message: &[u8]) -> Result<Vec<u8>, ConnectError> {
        let tag = super::device_key::RECOVER_TAG.as_bytes();
        if message.len() <= tag.len() || !message.starts_with(tag) || message[tag.len()] != 0 {
            return Err(ConnectError::TagRefused);
        }
        Ok(self.0.sign(message).as_ref().to_vec())
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
    fn a_link_code_names_its_account_and_keys_and_hides_in_debug() {
        let (root, confirmer) = ([4u8; 65], [5u8; 65]);
        let code = LinkCode::generate("acc_k7m2q4x3ca", &root, &confirmer).unwrap();
        assert_eq!(code.account_id(), "acc_k7m2q4x3ca");
        assert_eq!(code.expose().len(), 123);
        assert_eq!(code.fingerprint(), link_fingerprint(&root, &confirmer));
        assert_ne!(code.fingerprint(), link_fingerprint(&confirmer, &root));
        assert!(code.expose().ends_with(&format!("_{}", code.fingerprint())));
        let again = LinkCode::parse(&format!("  {}\n", code.expose())).unwrap();
        assert_eq!(again.link_hash(), code.link_hash());
        assert_eq!(again.fingerprint(), code.fingerprint());
        assert_eq!(code.link_hash().len(), 43);
        assert!(!format!("{code:?}").contains(&code.expose()[20..]));
        assert_ne!(
            LinkCode::generate("acc_k7m2q4x3ca", &root, &confirmer)
                .unwrap()
                .expose(),
            code.expose()
        );
        let fp = "ab".repeat(16);
        let secret = "cd".repeat(32);
        assert!(LinkCode::parse(&format!("apassy_alk_acc_k7m2q4x3ca_{secret}_{fp}")).is_some());
        for bad in [
            "apassy_lnk_t_7k2m5q4x3c_".to_owned() + &secret,
            "apassy_alk_acc_k7m2q4x3ca_".to_owned() + &secret,
            format!("apassy_alk_acc_k7m2q4x3ca_{}_{fp}", "CD".repeat(32)),
            format!("apassy_alk_acc_k7m2q4x3ca_{}_{fp}0", "cd".repeat(31)),
            format!("apassy_alk_acc_k7m2q4x3ca_{secret}_{}", "AB".repeat(16)),
            format!("apassy_alk_acc_k7m2q4x3ca_{secret}_{}", "ab".repeat(15)),
            format!("apassy_alk_acc_k7m2q4x3ca_{secret}-{fp}"),
            format!("apassy_alk_acc_k7m2q4x3ca0{secret}_{fp}"),
        ] {
            assert!(LinkCode::parse(&bad).is_none(), "{bad}");
        }
        assert!(LinkCode::generate("t_7k2m5q4x3c", &root, &confirmer).is_err());
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
    fn a_recovery_code_reads_back_from_its_words_and_its_text_form() {
        let code = RecoveryCode::generate().unwrap();
        let words = code.words();
        assert_eq!(words.split(' ').count(), 16);
        let public = code.key().unwrap().public_key_b64u();
        assert_eq!(public.len(), 43);
        let typed = RecoveryCode::parse(&words.to_uppercase()).unwrap();
        assert_eq!(typed.key().unwrap().public_key_b64u(), public);
        let text = RecoveryCode::parse(&code.text()).unwrap();
        assert_eq!(text.key().unwrap().public_key_b64u(), public);
        assert_ne!(
            RecoveryCode::generate()
                .unwrap()
                .key()
                .unwrap()
                .public_key_b64u(),
            public
        );
        // The recovery key signs only a recover message.
        let key = code.key().unwrap();
        assert_eq!(
            key.sign_recover(b"apassy-connect recover v1\0o")
                .unwrap()
                .len(),
            64
        );
        for refused in [
            &b"apassy-connect recover v1"[..],
            b"apassy-connect account v1\0o",
            b"",
        ] {
            assert_eq!(
                key.sign_recover(refused).unwrap_err(),
                ConnectError::TagRefused
            );
        }
        assert!(!format!("{code:?}").contains(words.split(' ').next().unwrap()));
        assert!(RecoveryCode::parse("apassy_rec_00").is_none());
        assert!(RecoveryCode::parse("atlas attic").is_none());
        assert!(RecoveryCode::parse(&"notaword ".repeat(16)).is_none());
    }
}
