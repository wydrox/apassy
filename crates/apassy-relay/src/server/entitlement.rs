//! The entitlement token of Apassy Connect (connect-account-v1 section 10, docs/SPEC.md
//! section 33.9).
//!
//! `<payload b64u>.<signature b64u>`: the payload is the compact UTF-8 JSON of [`Claims`]
//! (fields in the order of the contract), the signature is Ed25519 over
//! `"apassy-connect entitlement v1" 0x00 <payload b64u>` with the Connect signing key
//! (`APASSY_CONNECT_SIGNING_KEY_FILE`). `GET /.well-known/apassy-connect.json` publishes
//! the public keys. A service checks a token with [`Entitlement::verify`] and never calls
//! Connect for a request. The token is not a credential for Connect: no route takes it in
//! `Authorization`.

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::ConnectSigningKey;
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::{decode_b64, encode_b64};

/// The domain of the signature.
pub const ENTITLEMENT_DOMAIN: &str = "apassy-connect entitlement v1";
/// The life of a token: 24 hours.
pub const LIFETIME_SECS: u64 = 86_400;
/// How far `iat` may be ahead of the clock of the checking service.
pub const CLOCK_SKEW_SECS: u64 = 300;
/// The features of v1, sorted: every entitled account gets all three.
pub const FEATURES: [&str; 3] = ["brain", "sync", "tunnel"];
/// A token text longer than this is refused before any decode.
const MAX_TOKEN_CHARS: usize = 2048;

/// The claims of a token. Unknown fields are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub v: u8,
    pub kid: String,
    pub acc: String,
    /// `personal`, `family`, or `team`.
    pub plan: String,
    pub group: Option<String>,
    /// Sorted, without repeats, from [`FEATURES`].
    pub feats: Vec<String>,
    pub iat: u64,
    pub exp: u64,
}

impl Claims {
    /// The claims of an entitled account at `now`: v 1, every feature, 24 hours.
    pub fn new(kid: &str, account: &str, plan: &str, group: Option<&str>, now: u64) -> Self {
        Self {
            v: 1,
            kid: kid.to_string(),
            acc: account.to_string(),
            plan: plan.to_string(),
            group: group.map(str::to_string),
            feats: FEATURES.iter().map(|feat| (*feat).to_string()).collect(),
            iat: now,
            exp: now.saturating_add(LIFETIME_SECS),
        }
    }
}

/// A published key: its id and its Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    pub kid: String,
    pub public_key: [u8; 32],
}

/// The signing key of this Connect, with its key id. Debug shows the kid only.
pub struct EntitlementSigner {
    pair: Ed25519KeyPair,
    kid: String,
}

impl std::fmt::Debug for EntitlementSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntitlementSigner")
            .field("kid", &self.kid)
            .finish()
    }
}

/// The key id of a public key: `ek_` and the first 16 hex characters of its SHA-256. A new
/// key has a new id by itself, so a rotation needs no setting of its own.
pub fn key_id(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    let hex: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("ek_{hex}")
}

impl EntitlementSigner {
    /// The signer of the key of `APASSY_CONNECT_SIGNING_KEY_FILE`, its kid from
    /// [`key_id`].
    pub fn from_key(key: &ConnectSigningKey) -> RelayResult<Self> {
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(key.pkcs8())
            .map_err(|_| RelayError::internal("The Connect signing key is not valid."))?;
        let kid = key_id(pair.public_key().as_ref());
        Ok(Self { pair, kid })
    }

    /// A signer of an Ed25519 seed with the key id `kid` (the test vectors: bytes 32 to 63,
    /// `ek_test_1`).
    pub fn from_seed(seed: &[u8; 32], kid: &str) -> RelayResult<Self> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|_| RelayError::internal("The Ed25519 seed is not valid."))?;
        Ok(Self {
            pair,
            kid: kid.to_string(),
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The 32 bytes of the public key.
    pub fn public_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        key.copy_from_slice(self.pair.public_key().as_ref());
        key
    }

    /// The key as the well-known document publishes it.
    pub fn published(&self) -> PublishedKey {
        PublishedKey {
            kid: self.kid.clone(),
            public_key: self.public_key(),
        }
    }
}

/// The message that the signature covers.
fn signed_message(payload_b64u: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(ENTITLEMENT_DOMAIN.len() + 1 + payload_b64u.len());
    message.extend_from_slice(ENTITLEMENT_DOMAIN.as_bytes());
    message.push(0);
    message.extend_from_slice(payload_b64u.as_bytes());
    message
}

/// Why a token was refused; one kind for each check of section 10.
fn refused(why: &str) -> RelayError {
    RelayError::new(
        codes::UNAUTHENTICATED,
        format!("The entitlement token is not valid: {why}"),
    )
}

/// The entitlement token: [`Entitlement::sign`] and [`Entitlement::verify`].
pub struct Entitlement;

impl Entitlement {
    /// The token of `claims` signed with `signer`. `claims.kid` must be the signer's.
    pub fn sign(signer: &EntitlementSigner, claims: &Claims) -> RelayResult<String> {
        if claims.kid != signer.kid {
            return Err(RelayError::internal(
                "The claims name another key than the signer.",
            ));
        }
        let payload = serde_json::to_vec(claims)
            .map_err(|_| RelayError::internal("The claims cannot be written."))?;
        let payload_b64u = encode_b64(&payload);
        let signature = signer.pair.sign(&signed_message(&payload_b64u));
        Ok(format!("{payload_b64u}.{}", encode_b64(signature.as_ref())))
    }

    /// The claims of `token` after every check of section 10 except the feature and the
    /// account, which the service compares itself: two parts of canonical b64u, a known
    /// `kid` of `keys`, the signature, strict claims, `v` 1, `feats` sorted without
    /// repeats from [`FEATURES`], `now < exp`, `iat <= now + 300`, and `exp - iat <=
    /// 86400`. Every refusal is 401 `unauthenticated` with the check in the message.
    pub fn verify(keys: &[PublishedKey], token: &str, now: u64) -> RelayResult<Claims> {
        if token.len() > MAX_TOKEN_CHARS {
            return Err(refused("too long"));
        }
        let mut parts = token.split('.');
        let (Some(payload_b64u), Some(signature_b64u), None) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(refused("not two parts"));
        };
        let payload =
            decode_b64(payload_b64u, MAX_TOKEN_CHARS).map_err(|_| refused("the payload"))?;
        let signature = decode_b64(signature_b64u, 64).map_err(|_| refused("the signature"))?;
        if signature.len() != 64 {
            return Err(refused("the signature"));
        }
        let claims: Claims = serde_json::from_slice(&payload).map_err(|_| refused("the claims"))?;
        let key = keys
            .iter()
            .find(|key| key.kid == claims.kid)
            .ok_or_else(|| refused("an unknown key"))?;
        UnparsedPublicKey::new(&ED25519, key.public_key)
            .verify(&signed_message(payload_b64u), &signature)
            .map_err(|_| refused("the signature does not verify"))?;
        let sorted = claims.feats.windows(2).all(|pair| pair[0] < pair[1]);
        let known = claims
            .feats
            .iter()
            .all(|feat| FEATURES.contains(&feat.as_str()));
        if claims.v != 1
            || !sorted
            || !known
            || !matches!(claims.plan.as_str(), "personal" | "family" | "team")
            || !crate::secret::is_connect_id(&claims.acc, "acc_")
            || claims
                .group
                .as_deref()
                .is_some_and(|group| !crate::secret::is_connect_id(group, "grp_"))
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > LIFETIME_SECS
        {
            return Err(refused("the claims"));
        }
        if now >= claims.exp || claims.iat > now.saturating_add(CLOCK_SKEW_SECS) {
            return Err(refused("expired or not yet valid"));
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = 32 + index as u8;
        }
        seed
    }

    #[test]
    fn a_token_signs_and_verifies_and_a_changed_claim_fails() {
        let signer = EntitlementSigner::from_seed(&seed(), "ek_test_1").unwrap();
        let claims = Claims::new(
            "ek_test_1",
            "acc_k7m2q4x3ca",
            "personal",
            None,
            1_790_000_000,
        );
        let token = Entitlement::sign(&signer, &claims).unwrap();
        let keys = [signer.published()];
        assert_eq!(
            Entitlement::verify(&keys, &token, 1_790_000_001).unwrap(),
            claims
        );
        assert!(Entitlement::verify(&keys, &token, claims.exp).is_err());
        let (payload, signature) = token.split_once('.').unwrap();
        let changed = encode_b64(
            String::from_utf8(decode_b64(payload, 2048).unwrap())
                .unwrap()
                .replace("personal", "family")
                .as_bytes(),
        );
        assert!(
            Entitlement::verify(&keys, &format!("{changed}.{signature}"), 1_790_000_001).is_err()
        );
        assert_eq!(key_id(&signer.public_key()).len(), 19);
    }
}
