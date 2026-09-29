//! Secret strings and the tokens of the relay.
//!
//! Rules: a secret is zeroized on drop, its `Debug` is redacted, and a secret type
//! is never `Serialize`. To send a secret, a caller builds a borrowed `...Ref<'a>`
//! struct of `api` from `SecretString::expose`.
//!
//! Every token is 32 random bytes as 64 lowercase hex characters after a prefix
//! that names its kind. The vault stores only `token_hash` of a token.
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<apassy_relay::secret::SecretString>();
//! ```

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{RelayError, RelayResult};

/// A string that holds a secret: a value, a token, a placeholder, or a session key.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// The text. Do not log it, format it, or put it in an error.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// The number of hex characters after the prefix of a token.
pub const TOKEN_HEX_LEN: usize = 64;

/// The kinds of token. The prefix makes a leaked token easy to find and revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A member token: the owner, a manager, or a member. `apassy_mbr_`.
    Member,
    /// An agent token. The same prefix as the core broker: `apassy_agt_`.
    Agent,
    /// A one-time invite code. `apassy_inv_`.
    Invite,
    /// The key of one proxy session, in the base URLs of a run. `apassy_ses_`.
    Session,
}

impl TokenKind {
    pub const ALL: [TokenKind; 4] = [Self::Member, Self::Agent, Self::Invite, Self::Session];

    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Member => "apassy_mbr_",
            Self::Agent => apassy::vault::AGENT_TOKEN_PREFIX,
            Self::Invite => "apassy_inv_",
            Self::Session => "apassy_ses_",
        }
    }

    /// The kind of a well-formed token: a known prefix and 64 lowercase hex characters.
    pub fn of(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| {
            token.strip_prefix(kind.prefix()).is_some_and(|rest| {
                rest.len() == TOKEN_HEX_LEN
                    && rest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
    }
}

/// A new random token of one kind.
pub fn new_token(kind: TokenKind) -> RelayResult<SecretString> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|_| RelayError::internal("The system has no random source."))?;
    let mut text = String::with_capacity(kind.prefix().len() + TOKEN_HEX_LEN);
    text.push_str(kind.prefix());
    for byte in bytes.iter() {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(SecretString::new(text))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The SHA-256 of a token: what the vault stores and looks up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash(pub [u8; 32]);

/// The hash of a token. The whole text, prefix included, is hashed.
pub fn token_hash(token: &str) -> TokenHash {
    TokenHash(Sha256::digest(token.as_bytes()).into())
}

/// Compares two byte strings in time that depends only on their lengths.
/// Use it for the edge secret.
pub fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_have_their_kind_and_differ() {
        for kind in TokenKind::ALL {
            let a = new_token(kind).unwrap();
            let b = new_token(kind).unwrap();
            assert_ne!(a, b);
            assert_eq!(a.len(), kind.prefix().len() + TOKEN_HEX_LEN);
            assert_eq!(TokenKind::of(a.expose()), Some(kind));
        }
        assert_eq!(TokenKind::of("apassy_mbr_1234"), None);
        let upper = format!("apassy_agt_{}", "A".repeat(64));
        assert_eq!(TokenKind::of(&upper), None);
    }

    #[test]
    fn hash_is_stable_and_not_the_token() {
        let token = new_token(TokenKind::Agent).unwrap();
        assert_eq!(token_hash(token.expose()), token_hash(token.expose()));
        assert_ne!(token_hash(token.expose()), token_hash("apassy_agt_other"));
    }

    #[test]
    fn debug_is_redacted_and_deserialize_works() {
        let secret: SecretString = serde_json::from_str("\"sk_test_canary_value\"").unwrap();
        assert_eq!(secret.expose(), "sk_test_canary_value");
        let shown = format!("{secret:?}");
        assert!(!shown.contains("canary"), "{shown}");
    }

    #[test]
    fn same_bytes_compares() {
        assert!(same_bytes(b"abc", b"abc"));
        assert!(!same_bytes(b"abc", b"abd"));
        assert!(!same_bytes(b"abc", b"ab"));
    }
}
