//! The entitlement token of Apassy Connect (contract connect-account-v1 section 10).
//!
//! `<payload b64u>.<signature b64u>`: the payload is the compact UTF-8 JSON of
//! [`EntitlementClaims`], the signature is Ed25519 over
//! `"apassy-connect entitlement v1" 0x00 <payload b64u>` with the Connect signing key,
//! whose public keys `GET /.well-known/apassy-connect.json` publishes. A service checks
//! it with [`verify`] and never calls Connect for a request. The token is not a
//! credential for Connect, and the Mac never sends it to the bouncer brain (the brain
//! learns the entitlement from its own directory, I-3).
//!
//! The Mac keeps the token of its account in memory only ([`Entitlement`]), to show the
//! plan and for the other Connect services.

use std::fmt;

use ring::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::sync::decode_b64u;

/// The domain of the signature.
pub const ENTITLEMENT_TAG: &str = "apassy-connect entitlement v1";
/// The longest life of a token: 24 hours.
pub const MAX_LIFETIME: u64 = 86_400;
/// How far `iat` may be ahead of the clock of the checking service.
pub const CLOCK_SKEW: u64 = 300;
/// A token text longer than this is refused before any decode.
const MAX_TOKEN_CHARS: usize = 2048;

/// A plan of the claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    Personal,
    Family,
    Team,
}

/// A feature of the claims, sorted by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Feature {
    Brain,
    Sync,
    Tunnel,
}

/// The claims of a token. Unknown fields are refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementClaims {
    pub v: u8,
    pub kid: String,
    pub acc: String,
    pub plan: Plan,
    pub group: Option<String>,
    pub feats: Vec<Feature>,
    pub iat: u64,
    pub exp: u64,
}

/// A published key: its id and its Ed25519 public key (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementKey {
    pub kid: String,
    pub public_key: [u8; 32],
}

impl EntitlementKey {
    /// A key of the well-known document: `alg` must be `Ed25519` and the key 32 bytes of
    /// b64u.
    pub fn from_published(kid: &str, alg: &str, public_key_b64u: &str) -> Option<Self> {
        if alg != "Ed25519" || kid.is_empty() || kid.len() > 64 {
            return None;
        }
        let bytes = decode_b64u(public_key_b64u)?;
        Some(Self {
            kid: kid.to_owned(),
            public_key: bytes.try_into().ok()?,
        })
    }
}

/// Why a token was refused. One kind for each check of section 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementError {
    /// Not two parts of canonical b64u, too long, or the claims do not parse strictly.
    Malformed,
    /// The `kid` is not a published key.
    UnknownKey,
    /// The signature does not verify.
    Signature,
    /// `v` is not 1, `feats` is not sorted without repeats, or `exp - iat` is too long.
    Claims,
    /// `now >= exp`, or `iat` is too far ahead.
    Expired,
    /// The feature is not in `feats`.
    NoFeature,
    /// `acc` is not the account that the service authenticated.
    OtherAccount,
}

impl fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the entitlement token is malformed",
            Self::UnknownKey => "the entitlement token names an unknown key",
            Self::Signature => "the entitlement token signature does not verify",
            Self::Claims => "the entitlement token claims are not valid",
            Self::Expired => "the entitlement token is expired or not yet valid",
            Self::NoFeature => "the entitlement token does not include this feature",
            Self::OtherAccount => "the entitlement token is for another account",
        })
    }
}

impl std::error::Error for EntitlementError {}

/// The claims of `token` after every check of section 10: two parts of canonical b64u, a
/// known `kid`, the signature, strict claims, `v` 1, `now < exp`, `iat <= now + 300`,
/// `exp - iat <= 86400`, `feature` in `feats`, and `acc == account`.
pub fn verify(
    token: &str,
    keys: &[EntitlementKey],
    feature: Feature,
    account: &str,
    now: u64,
) -> Result<EntitlementClaims, EntitlementError> {
    let claims = verify_signed(token, keys)?;
    check_time(&claims, now)?;
    if !claims.feats.contains(&feature) {
        return Err(EntitlementError::NoFeature);
    }
    if claims.acc != account {
        return Err(EntitlementError::OtherAccount);
    }
    Ok(claims)
}

/// The signed claims of `token`, with the checks of the form, the key, the signature,
/// and the claims, but not the time, the feature, or the account.
pub fn verify_signed(
    token: &str,
    keys: &[EntitlementKey],
) -> Result<EntitlementClaims, EntitlementError> {
    if token.len() > MAX_TOKEN_CHARS {
        return Err(EntitlementError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(payload_b64u), Some(signature_b64u), None) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(EntitlementError::Malformed);
    };
    let payload = decode_b64u(payload_b64u).ok_or(EntitlementError::Malformed)?;
    let signature = decode_b64u(signature_b64u).ok_or(EntitlementError::Malformed)?;
    if signature.len() != 64 {
        return Err(EntitlementError::Malformed);
    }
    let claims: EntitlementClaims =
        serde_json::from_slice(&payload).map_err(|_| EntitlementError::Malformed)?;
    let key = keys
        .iter()
        .find(|key| key.kid == claims.kid)
        .ok_or(EntitlementError::UnknownKey)?;
    let mut message = Vec::with_capacity(ENTITLEMENT_TAG.len() + 1 + payload_b64u.len());
    message.extend_from_slice(ENTITLEMENT_TAG.as_bytes());
    message.push(0);
    message.extend_from_slice(payload_b64u.as_bytes());
    UnparsedPublicKey::new(&ED25519, key.public_key)
        .verify(&message, &signature)
        .map_err(|_| EntitlementError::Signature)?;
    let sorted = claims.feats.windows(2).all(|pair| pair[0] < pair[1]);
    if claims.v != 1
        || !sorted
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > MAX_LIFETIME
        || !super::words::valid_account_id(&claims.acc)
        || claims
            .group
            .as_deref()
            .is_some_and(|group| !super::words::valid_group_id(group))
    {
        return Err(EntitlementError::Claims);
    }
    Ok(claims)
}

fn check_time(claims: &EntitlementClaims, now: u64) -> Result<(), EntitlementError> {
    if now >= claims.exp || claims.iat > now.saturating_add(CLOCK_SKEW) {
        return Err(EntitlementError::Expired);
    }
    Ok(())
}

/// The entitlement token of the account of this Mac, in memory only. Debug shows the
/// claims, never the token.
pub struct Entitlement {
    token: Zeroizing<String>,
    claims: EntitlementClaims,
}

impl fmt::Debug for Entitlement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entitlement")
            .field("claims", &self.claims)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl Entitlement {
    /// A token that Connect gave for `account`, checked with the published `keys` at
    /// `now` (every check of [`verify`] but the feature).
    pub fn checked(
        token: &str,
        keys: &[EntitlementKey],
        account: &str,
        now: u64,
    ) -> Result<Self, EntitlementError> {
        let claims = verify_signed(token, keys)?;
        check_time(&claims, now)?;
        if claims.acc != account {
            return Err(EntitlementError::OtherAccount);
        }
        Ok(Self {
            token: Zeroizing::new(token.to_owned()),
            claims,
        })
    }

    pub fn claims(&self) -> &EntitlementClaims {
        &self.claims
    }

    /// The token, for a Connect service that checks it. Never for Connect itself and never
    /// for the bouncer brain.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Whether the token is still good at `now` with five minutes to spare, so a cache
    /// renews it before a service would refuse it.
    pub fn is_fresh(&self, now: u64) -> bool {
        now.saturating_add(CLOCK_SKEW) < self.claims.exp
    }

    /// Whether the token gives `feature`.
    pub fn has(&self, feature: Feature) -> bool {
        self.claims.feats.contains(&feature)
    }
}
