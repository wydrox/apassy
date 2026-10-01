//! Secret strings and the tokens of the relay.
//!
//! Rules: a secret is zeroized on drop, its `Debug` is redacted, and a secret type
//! is never `Serialize`. To send a secret, a caller builds a borrowed `...Ref<'a>`
//! struct of `api` from `SecretString::expose`.
//!
//! Every token ends with 32 random bytes as 64 lowercase hex characters. Before them
//! are a prefix that names its kind and, for a token of a team, the team id. The
//! vault stores only `token_hash` of a token.
//!
//! ```compile_fail
//! fn needs_serialize<T: serde::Serialize>() {}
//! needs_serialize::<apassy_relay::secret::SecretString>();
//! ```

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{RelayError, RelayResult};
use crate::ids::{TEAM_ID_LEN, TeamId};

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

/// The number of hex characters at the end of a token.
pub const TOKEN_HEX_LEN: usize = 64;

/// The kinds of token. The prefix makes a leaked token easy to find and revoke.
///
/// A token of a team is `<prefix><team id>_<64 hex>`: the relay reads the team from it
/// before it opens anything (ADR 0019). A team code of the operator has no team:
/// `apassy_tcd_<64 hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A member token: the owner, a manager, or a member. `apassy_mbr_`.
    Member,
    /// An agent token. `apassy_tagt_` (the core uses `apassy_agt_` for its local tokens).
    Agent,
    /// A one-time invite code. `apassy_inv_`.
    Invite,
    /// The key of one proxy session, in the base URLs of a run. `apassy_ses_`.
    Session,
    /// A one-time code of the operator that makes one team. `apassy_tcd_`.
    TeamCode,
    /// The access token of a signed-in device, 15 minutes, in memory. `apassy_acc_`.
    Access,
    /// A one-time code that adds a device to its member, 10 minutes. `apassy_lnk_`.
    Link,
}

/// The agent prefix of the first alpha, without a team id. Only the migrated team
/// accepts it, until its members make new tokens.
pub const LEGACY_AGENT_PREFIX: &str = apassy::vault::AGENT_TOKEN_PREFIX;

impl TokenKind {
    pub const ALL: [TokenKind; 7] = [
        Self::Member,
        Self::Agent,
        Self::Invite,
        Self::Session,
        Self::TeamCode,
        Self::Access,
        Self::Link,
    ];

    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Member => "apassy_mbr_",
            Self::Agent => "apassy_tagt_",
            Self::Invite => "apassy_inv_",
            Self::Session => "apassy_ses_",
            Self::TeamCode => "apassy_tcd_",
            Self::Access => "apassy_acc_",
            Self::Link => "apassy_lnk_",
        }
    }

    /// True for the kinds whose tokens name a team.
    pub const fn has_team(self) -> bool {
        !matches!(self, Self::TeamCode)
    }

    /// The kind of a well-formed token, in any accepted form.
    pub fn of(token: &str) -> Option<Self> {
        parse_token(token).map(|parsed| parsed.kind)
    }
}

/// A well-formed token: its kind, and its team. `team` is `None` for a team code, and
/// for a member or agent token of the first alpha.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToken {
    pub kind: TokenKind,
    pub team: Option<TeamId>,
}

fn is_token_hex(text: &str) -> bool {
    text.len() == TOKEN_HEX_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Reads the kind and the team of a token. `None` for anything else.
pub fn parse_token(token: &str) -> Option<ParsedToken> {
    let plain = |kind| Some(ParsedToken { kind, team: None });
    if let Some(rest) = token.strip_prefix(TokenKind::TeamCode.prefix()) {
        return if is_token_hex(rest) {
            plain(TokenKind::TeamCode)
        } else {
            None
        };
    }
    if let Some(rest) = token.strip_prefix(LEGACY_AGENT_PREFIX) {
        return if is_token_hex(rest) {
            plain(TokenKind::Agent)
        } else {
            None
        };
    }
    let kind = TokenKind::ALL
        .into_iter()
        .filter(|kind| kind.has_team())
        .find(|kind| token.starts_with(kind.prefix()))?;
    let rest = &token[kind.prefix().len()..];
    if kind == TokenKind::Member && is_token_hex(rest) {
        return plain(TokenKind::Member);
    }
    let (team, hex) = rest.split_at_checked(TEAM_ID_LEN)?;
    let team = TeamId::parse(team)?;
    let hex = hex.strip_prefix('_')?;
    is_token_hex(hex).then_some(ParsedToken {
        kind,
        team: Some(team),
    })
}

/// The length of the token that starts `text`, if one does. For the audit masks, so
/// it takes every shape that a token of any kind had or has: a prefix, then the team id
/// and `_` or nothing, then 64 hex. That is wider than `parse_token` accepts.
pub fn token_len_at(text: &str) -> Option<usize> {
    let prefixes = TokenKind::ALL
        .iter()
        .map(|kind| kind.prefix())
        .chain([LEGACY_AGENT_PREFIX]);
    for prefix in prefixes {
        let Some(rest) = text.strip_prefix(prefix) else {
            continue;
        };
        let teamed = rest
            .split_at_checked(TEAM_ID_LEN)
            .filter(|(team, after)| TeamId::parse(team).is_some() && after.starts_with('_'))
            .and_then(|(_, after)| after[1..].get(..TOKEN_HEX_LEN))
            .filter(|hex| is_token_hex(hex));
        if teamed.is_some() {
            return Some(prefix.len() + TEAM_ID_LEN + 1 + TOKEN_HEX_LEN);
        }
        if rest.get(..TOKEN_HEX_LEN).is_some_and(is_token_hex) {
            return Some(prefix.len() + TOKEN_HEX_LEN);
        }
    }
    None
}

fn random_hex(text: &mut String) -> RelayResult<()> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|_| RelayError::internal("The system has no random source."))?;
    for byte in bytes.iter() {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(())
}

/// A new random token of one kind for one team.
pub fn new_token(kind: TokenKind, team: &TeamId) -> RelayResult<SecretString> {
    if !kind.has_team() {
        return Err(RelayError::internal("This kind of token has no team."));
    }
    let mut text = String::with_capacity(kind.prefix().len() + TEAM_ID_LEN + 1 + TOKEN_HEX_LEN);
    text.push_str(kind.prefix());
    text.push_str(team.as_str());
    text.push('_');
    random_hex(&mut text)?;
    Ok(SecretString::new(text))
}

/// A new one-time team code of the operator.
pub fn new_team_code() -> RelayResult<SecretString> {
    let mut text = String::with_capacity(TokenKind::TeamCode.prefix().len() + TOKEN_HEX_LEN);
    text.push_str(TokenKind::TeamCode.prefix());
    random_hex(&mut text)?;
    Ok(SecretString::new(text))
}

/// A random 256-bit key as 64 hex characters: the key of one team file.
pub fn new_file_key() -> RelayResult<SecretString> {
    let mut text = String::with_capacity(TOKEN_HEX_LEN);
    random_hex(&mut text)?;
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

    fn team() -> TeamId {
        TeamId::parse("t_abcdefgh23").unwrap()
    }

    #[test]
    fn tokens_have_their_kind_team_and_differ() {
        for kind in TokenKind::ALL.into_iter().filter(|k| k.has_team()) {
            let a = new_token(kind, &team()).unwrap();
            let b = new_token(kind, &team()).unwrap();
            assert_ne!(a, b);
            assert_eq!(
                a.len(),
                kind.prefix().len() + TEAM_ID_LEN + 1 + TOKEN_HEX_LEN
            );
            assert_eq!(
                parse_token(a.expose()),
                Some(ParsedToken {
                    kind,
                    team: Some(team())
                })
            );
            assert_eq!(token_len_at(&format!("{} tail", a.expose())), Some(a.len()));
        }
        assert!(new_token(TokenKind::TeamCode, &team()).is_err());
        let code = new_team_code().unwrap();
        assert_eq!(TokenKind::of(code.expose()), Some(TokenKind::TeamCode));
        assert_eq!(parse_token(code.expose()).unwrap().team, None);
        assert_eq!(TokenKind::of("apassy_mbr_1234"), None);
        let upper = format!("apassy_tagt_t_abcdefgh23_{}", "A".repeat(64));
        assert_eq!(TokenKind::of(&upper), None);
    }

    #[test]
    fn first_alpha_member_and_agent_tokens_have_no_team() {
        let hex = "ab".repeat(32);
        for (text, kind) in [
            (format!("apassy_mbr_{hex}"), TokenKind::Member),
            (format!("apassy_agt_{hex}"), TokenKind::Agent),
        ] {
            assert_eq!(parse_token(&text), Some(ParsedToken { kind, team: None }));
            assert_eq!(token_len_at(&text), Some(text.len()));
        }
        // Invites and session keys always name a team.
        assert_eq!(parse_token(&format!("apassy_inv_{hex}")), None);
        assert_eq!(parse_token(&format!("apassy_ses_{hex}")), None);
        assert_eq!(parse_token(&format!("apassy_tagt_{hex}")), None);
        // A bad team id is not a token.
        assert_eq!(parse_token(&format!("apassy_ses_t_ABCDEFGH23_{hex}")), None);
        assert_eq!(parse_token(&format!("apassy_ses_t_abcdefgh23-{hex}")), None);
    }

    #[test]
    fn hash_is_stable_and_not_the_token() {
        let token = new_token(TokenKind::Agent, &team()).unwrap();
        assert_eq!(token_hash(token.expose()), token_hash(token.expose()));
        assert_ne!(token_hash(token.expose()), token_hash("apassy_tagt_other"));
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
