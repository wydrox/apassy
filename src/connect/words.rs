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
/// The domain of the key fingerprint inside a share code (section 16.2).
pub const SHARE_KEYS_TAG: &str = "apassy-connect share-keys v1";
/// The domain of the hash of a share code that Connect keeps.
pub const SHARE_LINK_TAG: &str = "apassy-connect share-link v1";
/// The domain of the six words of a share between two accounts.
pub const SHARE_SAFETY_TAG: &str = "apassy-connect share-safety v1";

/// The prefix of a link code.
const LINK_PREFIX: &str = "apassy_alk_";
/// The prefix of the text form of a recovery code.
const RECOVERY_PREFIX: &str = "apassy_rec_";
/// The prefix of a share code.
const SHARE_PREFIX: &str = "apassy_shr_";
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

/// A new account id, made by the device that makes the account (its root entry names
/// it): `acc_` and 10 random characters of `a-z2-7`.
pub fn new_account_id() -> Result<String, ConnectError> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bytes = random::<10>()?;
    let mut id = String::from("acc_");
    for byte in bytes.iter() {
        id.push(char::from(ALPHABET[usize::from(byte & 31)]));
    }
    Ok(id)
}

/// A new vault store id, made by the device that makes the store (its `store` entry names
/// it, connect-account-v1 section 8): `t_` and 10 random characters of `a-z2-7`.
pub fn new_store_id() -> Result<String, ConnectError> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let bytes = random::<10>()?;
    let mut id = String::from("t_");
    for byte in bytes.iter() {
        id.push(char::from(ALPHABET[usize::from(byte & 31)]));
    }
    Ok(id)
}

/// The short fingerprint of a device key (X9.63) that an owner check shows: the first 6
/// bytes of its SHA-256, as three groups of four lowercase hex characters
/// (`1a2b 3c4d 5e6f`). Settings › Connect shows the fingerprint of this device's own key,
/// so the owner can compare it on each device.
pub fn key_fingerprint(key: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, key);
    let hex = hex_lower(&digest.as_ref()[..6]);
    format!("{} {} {}", &hex[..4], &hex[4..8], &hex[8..12])
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

/// The key fingerprint of a share code (section 16.2): the first 16 bytes of
/// `SHA-256("apassy-connect share-keys v1" 0x00 <root of the inviting account> 0x00 <key of
/// the inviting device>)`, as 32 lowercase hex characters. Both keys are X9.63 (65 bytes).
pub fn share_fingerprint(root_key: &[u8], inviter_key: &[u8]) -> String {
    let mut message = Vec::with_capacity(SHARE_KEYS_TAG.len() + 2 + root_key.len() * 2);
    message.extend_from_slice(SHARE_KEYS_TAG.as_bytes());
    message.push(0);
    message.extend_from_slice(root_key);
    message.push(0);
    message.extend_from_slice(inviter_key);
    let digest = sha256(&message);
    hex_lower(&digest[..FINGERPRINT_BYTES]).to_string()
}

/// A share code: `apassy_shr_<account id>_<64 hex>_<32 hex fingerprint>` (section 16.2).
/// The device of the account that shares makes it and keeps it in memory; it never reaches
/// Connect, which sees only [`ShareCode::link_hash`]. The fingerprint
/// ([`share_fingerprint`]) lets the other account check the root and the inviting device
/// that Connect names. Debug is redacted; the text is erased on drop.
pub struct ShareCode(Zeroizing<String>);

impl fmt::Debug for ShareCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ShareCode").field(&"[redacted]").finish()
    }
}

impl ShareCode {
    /// A new code of `account_id` from the system random source, with the fingerprint of
    /// its root `root_key` and of this device's key `inviter_key`.
    pub fn generate(
        account_id: &str,
        root_key: &[u8],
        inviter_key: &[u8],
    ) -> Result<Self, ConnectError> {
        if !valid_account_id(account_id) {
            return Err(ConnectError::Invalid);
        }
        let secret = random::<LINK_BYTES>()?;
        let mut text = Zeroizing::new(String::with_capacity(LINK_CODE_LEN));
        text.push_str(SHARE_PREFIX);
        text.push_str(account_id);
        text.push('_');
        text.push_str(&hex_lower(&secret[..]));
        text.push('_');
        text.push_str(&share_fingerprint(root_key, inviter_key));
        Ok(Self(text))
    }

    /// A code that the person pasted or a QR code gave, trimmed. `None` outside the
    /// grammar.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.len() != LINK_CODE_LEN {
            return None;
        }
        let rest = text.strip_prefix(SHARE_PREFIX)?;
        let (account, rest) = (rest.get(..14)?, rest.get(14..)?);
        let rest = rest.strip_prefix('_')?;
        let (secret, rest) = (rest.get(..64)?, rest.get(64..)?);
        let fingerprint = rest.strip_prefix('_')?;
        (valid_account_id(account)
            && is_hex(secret, 64)
            && is_hex(fingerprint, FINGERPRINT_BYTES * 2))
        .then(|| Self(Zeroizing::new(text.to_owned())))
    }

    /// The account id of the inviting account.
    pub fn account_id(&self) -> &str {
        &self.0[SHARE_PREFIX.len()..SHARE_PREFIX.len() + 14]
    }

    /// The key fingerprint inside the code: 32 lowercase hex characters.
    pub fn fingerprint(&self) -> &str {
        &self.0[LINK_CODE_LEN - FINGERPRINT_BYTES * 2..]
    }

    /// The text, for the Copy button and the QR code of "Share with…".
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The hash that Connect keeps.
    pub fn link_hash(&self) -> String {
        share_link_hash(&self.0)
    }
}

/// The hash of a share code: b64u of `SHA-256("apassy-connect share-link v1" 0x00 <code>)`.
pub fn share_link_hash(code: &str) -> String {
    let mut message = Zeroizing::new(Vec::with_capacity(SHARE_LINK_TAG.len() + 1 + code.len()));
    message.extend_from_slice(SHARE_LINK_TAG.as_bytes());
    message.push(0);
    message.extend_from_slice(code.as_bytes());
    encode_b64u(&sha256(&message))
}

/// The six words of a share between two accounts (section 16.2): both devices compute
/// them from the code, the inviting account, its root, and its device, and the joining
/// account, its root, and its device (keys X9.63, 65 bytes each). The store is not in
/// them: the pin is for the pair of accounts, and each signed `share` names its store.
pub fn share_safety_words(
    code: &str,
    (inviter_account, inviter_root, inviter_key): (&str, &[u8], &[u8]),
    (joiner_account, joiner_root, joiner_key): (&str, &[u8], &[u8]),
) -> String {
    let mut message = Zeroizing::new(Vec::new());
    for part in [
        SHARE_SAFETY_TAG.as_bytes(),
        code.as_bytes(),
        inviter_account.as_bytes(),
        inviter_root,
        inviter_key,
        joiner_account.as_bytes(),
        joiner_root,
    ] {
        message.extend_from_slice(part);
        message.push(0);
    }
    message.extend_from_slice(joiner_key);
    let digest = sha256(&message);
    digest[..SAFETY_WORDS]
        .iter()
        .map(|byte| WORDS[usize::from(*byte)])
        .collect::<Vec<_>>()
        .join(" ")
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

/// What a recovery code that the person typed or pasted holds (the sheet that recovers an
/// account): the 16 words in any case, with any spaces, line breaks, and commas between
/// them, or the text form. The numbers of the sheet that showed the words (`1`, `2.`) and
/// an account id pasted with them are skipped. Debug never shows the words.
#[derive(Clone, PartialEq, Eq)]
pub enum TypedRecovery {
    /// Nothing typed yet.
    Empty,
    /// A code that [`RecoveryCode::parse`] takes: the words, one space between them, or
    /// the text form.
    Ready(Zeroizing<String>),
    /// The word at `position` (from 1) is not a word of the list.
    UnknownWord { position: usize, word: String },
    /// Every word is of the list, and there are this many, not 16.
    Count(usize),
}

impl fmt::Debug for TypedRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Ready(_) => f.write_str("Ready([redacted])"),
            Self::UnknownWord { position, .. } => f
                .debug_struct("UnknownWord")
                .field("position", position)
                .finish_non_exhaustive(),
            Self::Count(count) => f.debug_tuple("Count").field(count).finish(),
        }
    }
}

/// The pieces of a typed recovery code: words, numbers, and an account id, split at
/// spaces, line breaks, and commas, in lower case. A label at the start of a line
/// ("Account ID:", "Recovery Code:", of the Copy button) is skipped.
fn typed_tokens(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| match line.split_once(':') {
            Some((head, tail))
                if head.trim().contains(' ')
                    && head.chars().all(|c| c.is_alphabetic() || c == ' ') =>
            {
                tail
            }
            _ => line,
        })
        .flat_map(|line| line.split(|c: char| c.is_whitespace() || c == ',' || c == ';'))
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Read a recovery code that the person typed or pasted ([`TypedRecovery`]).
pub fn read_recovery(text: &str) -> TypedRecovery {
    let tokens = typed_tokens(text);
    let words: Vec<&str> = tokens
        .iter()
        .map(|token| token.trim_end_matches(['.', ')', ':']))
        .filter(|token| !token.is_empty())
        .filter(|token| !token.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|token| !valid_account_id(token))
        .collect();
    if words.is_empty() {
        return TypedRecovery::Empty;
    }
    if let [single] = words.as_slice() {
        if single.starts_with(RECOVERY_PREFIX) {
            return if RecoveryCode::parse(single).is_some() {
                TypedRecovery::Ready(Zeroizing::new((*single).to_owned()))
            } else {
                TypedRecovery::UnknownWord {
                    position: 1,
                    word: (*single).to_owned(),
                }
            };
        }
    }
    if let Some((index, word)) = words
        .iter()
        .enumerate()
        .find(|(_, word)| !WORDS.contains(word))
    {
        return TypedRecovery::UnknownWord {
            position: index + 1,
            word: (*word).to_owned(),
        };
    }
    if words.len() != RECOVERY_BYTES {
        return TypedRecovery::Count(words.len());
    }
    TypedRecovery::Ready(Zeroizing::new(words.join(" ")))
}

/// The account id in a pasted text (the Copy button of the recovery code copies the id with
/// the words), in lower case.
pub fn find_account_id(text: &str) -> Option<String> {
    typed_tokens(text)
        .into_iter()
        .map(|token| token.trim_end_matches(['.', ')', ':']).to_owned())
        .find(|token| valid_account_id(token))
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

    /// The sheet that recovers an account takes the words in any case, with extra spaces,
    /// line breaks, the numbers of the sheet that showed them, and the account id pasted
    /// with them; it names the first word that is not of the list, and counts the words.
    #[test]
    fn a_typed_recovery_code_tolerates_its_layout_and_names_a_wrong_word() {
        let code = RecoveryCode::from_bytes([7; RECOVERY_BYTES]);
        let words = code.words();
        let list: Vec<&str> = words.split(' ').collect();
        let numbered: String = list
            .iter()
            .enumerate()
            .map(|(index, word)| format!("{:>2} {}", index + 1, word.to_uppercase()))
            .collect::<Vec<_>>()
            .join("\n");
        for typed in [
            words.to_string(),
            format!("  {}  ", list.join("   ")),
            list.join("\n"),
            numbered,
            format!("acc_k7m2q4x3ca\n{}", words.as_str()),
            format!(
                "Account ID: acc_k7m2q4x3ca\nRecovery Code: {}",
                words.as_str()
            ),
            list.join(", "),
        ] {
            let TypedRecovery::Ready(ready) = read_recovery(&typed) else {
                panic!("not read: {:?}", read_recovery(&typed));
            };
            assert_eq!(ready.as_str(), words.as_str());
            assert_eq!(
                RecoveryCode::parse(&ready)
                    .unwrap()
                    .key()
                    .unwrap()
                    .public_key_b64u(),
                code.key().unwrap().public_key_b64u()
            );
        }
        assert_eq!(read_recovery(" \n "), TypedRecovery::Empty);
        let text = code.text();
        assert_eq!(read_recovery(&text), TypedRecovery::Ready(text.clone()));
        let mut wrong = list.clone();
        wrong[4] = "zzzq";
        assert_eq!(
            read_recovery(&wrong.join(" ")),
            TypedRecovery::UnknownWord {
                position: 5,
                word: "zzzq".to_owned()
            }
        );
        assert_eq!(
            read_recovery(&list[..15].join(" ")),
            TypedRecovery::Count(15)
        );
        assert_eq!(format!("{:?}", read_recovery(&words)), "Ready([redacted])");
        assert_eq!(
            find_account_id(&format!("ACC_K7M2Q4X3CA\n{}", words.as_str())).as_deref(),
            Some("acc_k7m2q4x3ca")
        );
        assert_eq!(find_account_id(&words), None);
    }

    #[test]
    fn a_new_account_id_has_the_form_of_section_2() {
        let first = new_account_id().unwrap();
        assert!(valid_account_id(&first), "{first}");
        assert_ne!(first, new_account_id().unwrap());
        let fingerprint = key_fingerprint(&[4; 65]);
        assert_eq!(fingerprint.len(), 14);
        assert_eq!(fingerprint.split(' ').count(), 3);
    }

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
    fn a_share_code_names_its_account_and_keys_and_hides_in_debug() {
        let (root, inviter) = ([4u8; 65], [5u8; 65]);
        let code = ShareCode::generate("acc_k7m2q4x3ca", &root, &inviter).unwrap();
        assert_eq!(code.account_id(), "acc_k7m2q4x3ca");
        assert_eq!(code.expose().len(), 123);
        assert!(code.expose().starts_with("apassy_shr_acc_k7m2q4x3ca_"));
        assert_eq!(code.fingerprint(), share_fingerprint(&root, &inviter));
        // Another domain than the device link: the same keys give another fingerprint.
        assert_ne!(code.fingerprint(), link_fingerprint(&root, &inviter));
        assert_ne!(code.link_hash(), link_hash(code.expose()));
        let again = ShareCode::parse(&format!("  {}\n", code.expose())).unwrap();
        assert_eq!(again.link_hash(), code.link_hash());
        assert!(!format!("{code:?}").contains(&code.expose()[20..]));
        // A device link code is no share code, and the reverse.
        let link = LinkCode::generate("acc_k7m2q4x3ca", &root, &inviter).unwrap();
        assert!(ShareCode::parse(link.expose()).is_none());
        assert!(LinkCode::parse(code.expose()).is_none());
        // The words cover every input: each change gives other words.
        let (x_root, x_key) = ([6u8; 65], [7u8; 65]);
        let words = share_safety_words(
            code.expose(),
            ("acc_k7m2q4x3ca", &root, &inviter),
            ("acc_m3n5p7q2rb", &x_root, &x_key),
        );
        assert_eq!(words.split(' ').count(), 6);
        for other in [
            share_safety_words(
                link.expose(),
                ("acc_k7m2q4x3ca", &root, &inviter),
                ("acc_m3n5p7q2rb", &x_root, &x_key),
            ),
            share_safety_words(
                code.expose(),
                ("acc_k7m2q4x3ca", &x_root, &inviter),
                ("acc_m3n5p7q2rb", &x_root, &x_key),
            ),
            share_safety_words(
                code.expose(),
                ("acc_k7m2q4x3ca", &root, &inviter),
                ("acc_m3n5p7q2rb", &x_root, &inviter),
            ),
            share_safety_words(
                code.expose(),
                ("acc_k7m2q4x3ca", &root, &inviter),
                ("acc_aaaaaaaaaa", &x_root, &x_key),
            ),
        ] {
            assert_ne!(other, words);
        }
        assert!(ShareCode::generate("t_7k2m5q4x3c", &root, &inviter).is_err());
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
