//! Device keys, sign-in, and safety words (ADR 0019 stages 2 and 3; docs/SPEC.md
//! section 23). Shared by the relay and the CLI, so both sides compute the same bytes.
//!
//! A device has a P-256 key pair. The relay stores only the public key: 65 bytes,
//! uncompressed SEC1 (`0x04 || X || Y`), as Apple's Secure Enclave and ring make it.
//! Signatures are ECDSA P-256 with SHA-256, ASN.1 DER. The CLI keeps the private key
//! as PKCS#8 (in the macOS Keychain, or in a file with mode 0600 on Linux).

use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::hostkeys::{decode_b64, encode_b64};
use crate::ids::TeamId;

/// The length of a public key: uncompressed SEC1.
pub const PUBLIC_KEY_BYTES: usize = 65;
/// The length of a sign-in nonce.
pub const NONCE_BYTES: usize = 32;
/// The longest DER signature of P-256.
pub const MAX_SIGNATURE_BYTES: usize = 72;
/// The domain of the sign-in message.
pub const SIGN_IN_DOMAIN: &str = "apassy-relay sign-in v1";
/// The domain of the safety words.
pub const SAFETY_DOMAIN: &str = "apassy-relay safety v1";
/// The domain of the proof of key of `POST /v1/connect` (docs/SPEC.md section 26).
pub const CONNECT_DOMAIN: &str = "apassy-relay connect v1";

/// The domains of Apassy Connect accounts (connect-account-v1 section 5). Each signed
/// message starts with its own domain, so a signature for one purpose (a team sign-in, an
/// account sign-in, the bouncer brain's sign-in) is worthless for another.
pub const ACCOUNT_DOMAIN: &str = "apassy-connect account v1";
pub const ACCOUNT_SIGN_IN_DOMAIN: &str = "apassy-connect sign-in v1";
pub const ACCOUNT_JOIN_DOMAIN: &str = "apassy-connect join v1";
pub const ACCOUNT_JOIN_CANCEL_DOMAIN: &str = "apassy-connect join-cancel v1";
/// The signed device list of an account: each change (an added or a removed device) is
/// an entry signed by a device of the list, naming the entry before it.
pub const ACCOUNT_LIST_DOMAIN: &str = "apassy-connect device-list v1";
/// The `previous` of the first entry of a device list, and the `link_hash` of an entry
/// without a link.
pub const LIST_NONE: &str = "-";
/// An entry of the device list that names another account (section 16): a `peer`,
/// `unpeer`, `share`, `unshare`, `join`, or `leave`, signed by a device of the list.
pub const SHARE_LIST_DOMAIN: &str = "apassy-connect share-list v1";
/// The answer of a device of another account to a share code (section 16.2).
pub const PEER_JOIN_DOMAIN: &str = "apassy-connect peer-join v1";
/// The hashes of a share code that are not signatures (section 16.2).
pub const SHARE_KEYS_DOMAIN: &str = "apassy-connect share-keys v1";
pub const SHARE_LINK_DOMAIN: &str = "apassy-connect share-link v1";
pub const SHARE_SAFETY_DOMAIN: &str = "apassy-connect share-safety v1";
pub const ACCOUNT_RECOVER_DOMAIN: &str = "apassy-connect recover v1";
/// The bouncer brain's sign-in (plan 0035 A). Connect never accepts it.
pub const BRAIN_SIGN_IN_DOMAIN: &str = "apassy-bouncer sign-in v1";
/// The hashes of Connect that are not signatures (section 5).
pub const ACCOUNT_LINK_DOMAIN: &str = "apassy-connect link v1";
pub const ACCOUNT_SAFETY_DOMAIN: &str = "apassy-connect safety v1";
pub const ACCOUNT_LINK_KEYS_DOMAIN: &str = "apassy-connect link-keys v1";
pub const ACCOUNT_RECOVERY_KEY_DOMAIN: &str = "apassy-connect recovery key v1";
/// The length of an Ed25519 public key (the recovery key) and of its signature.
pub const RECOVERY_KEY_BYTES: usize = 32;
pub const RECOVERY_SIGNATURE_BYTES: usize = 64;

/// The parts joined with one `0x00` byte, no trailing `0x00`.
fn joined_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut message = Vec::with_capacity(parts.iter().map(|part| part.len() + 1).sum());
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            message.push(0);
        }
        message.extend_from_slice(part);
    }
    message
}

fn joined(parts: &[&str]) -> Vec<u8> {
    let parts: Vec<&[u8]> = parts.iter().map(|part| part.as_bytes()).collect();
    joined_bytes(&parts)
}

/// `"apassy-connect account v1" 0x00 origin 0x00 public_key_b64 0x00 recovery_key_b64`:
/// the proof of key of `POST /v1/account`. It binds the recovery key of the new account.
pub fn account_message(origin: &str, public_key_b64: &str, recovery_key_b64: &str) -> Vec<u8> {
    joined(&[
        ACCOUNT_DOMAIN,
        origin.trim_end_matches('/'),
        public_key_b64,
        recovery_key_b64,
    ])
}

/// `"apassy-connect sign-in v1" 0x00 origin 0x00 account 0x00 public_key_b64 0x00 nonce`:
/// the sign-in of an account device (`POST /v1/account/token`).
pub fn account_sign_in_message(
    origin: &str,
    account: &str,
    public_key_b64: &str,
    nonce_b64: &str,
) -> Vec<u8> {
    joined(&[
        ACCOUNT_SIGN_IN_DOMAIN,
        origin.trim_end_matches('/'),
        account,
        public_key_b64,
        nonce_b64,
    ])
}

/// `"apassy-connect join v1" 0x00 origin 0x00 account 0x00 link_hash 0x00 public_key_b64`:
/// the request of a new device (`POST /v1/account/devices/join`).
pub fn account_join_message(
    origin: &str,
    account: &str,
    link_hash: &str,
    public_key_b64: &str,
) -> Vec<u8> {
    joined(&[
        ACCOUNT_JOIN_DOMAIN,
        origin.trim_end_matches('/'),
        account,
        link_hash,
        public_key_b64,
    ])
}

/// `"apassy-connect join-cancel v1" 0x00 origin 0x00 account 0x00 link_hash 0x00
/// public_key_b64`: the joining device ends its own pending join
/// (`POST /v1/account/devices/join/cancel`).
pub fn account_join_cancel_message(
    origin: &str,
    account: &str,
    link_hash: &str,
    public_key_b64: &str,
) -> Vec<u8> {
    joined(&[
        ACCOUNT_JOIN_CANCEL_DOMAIN,
        origin.trim_end_matches('/'),
        account,
        link_hash,
        public_key_b64,
    ])
}

/// One entry of the signed device list of an account (connect-account-v1 section 7.5):
/// `"apassy-connect device-list v1" 0x00 origin 0x00 account 0x00 version 0x00 previous
/// 0x00 op 0x00 key_b64 0x00 link_hash 0x00 name 0x00 by_b64`. `version` is decimal;
/// `previous` is the list hash of the entry before ([`account_list_hash`]), or `-` for
/// version 1; `op` is `root`, `add`, or `remove`; `link_hash` is the link of an `add`,
/// else `-`; `name` is the device name of a `root` or an `add`, else `-`; `by` is the key
/// of the device that signs the entry (for the `root`, the root key itself).
#[allow(clippy::too_many_arguments)]
pub fn account_list_message(
    origin: &str,
    account: &str,
    version: u64,
    previous: &str,
    op: &str,
    key_b64: &str,
    link_hash: &str,
    name: &str,
    by_b64: &str,
) -> Vec<u8> {
    joined(&[
        ACCOUNT_LIST_DOMAIN,
        origin.trim_end_matches('/'),
        account,
        &version.to_string(),
        previous,
        op,
        key_b64,
        link_hash,
        name,
        by_b64,
    ])
}

/// `"apassy-connect share-list v1" 0x00 origin 0x00 account 0x00 version 0x00 previous
/// 0x00 op 0x00 peer_account 0x00 root_b64 0x00 team_id 0x00 by_b64` (section 16): an
/// entry of the device list that names another account. `root_b64` is the root that a
/// `peer` pins, else `-`; `team_id` the store of a store op, else `-`.
#[allow(clippy::too_many_arguments)]
pub fn share_list_message(
    origin: &str,
    account: &str,
    version: u64,
    previous: &str,
    op: &str,
    peer_account: &str,
    root_b64: &str,
    team_id: &str,
    by_b64: &str,
) -> Vec<u8> {
    joined(&[
        SHARE_LIST_DOMAIN,
        origin.trim_end_matches('/'),
        account,
        &version.to_string(),
        previous,
        op,
        peer_account,
        root_b64,
        team_id,
        by_b64,
    ])
}

/// `"apassy-connect peer-join v1" 0x00 origin 0x00 inviter_account 0x00 link_hash 0x00
/// joiner_account 0x00 joiner_root_b64 0x00 key_b64` (`POST /v1/account/peers/join`):
/// signed by the answering device of the joining account.
pub fn peer_join_message(
    origin: &str,
    inviter_account: &str,
    link_hash: &str,
    joiner_account: &str,
    joiner_root_b64: &str,
    key_b64: &str,
) -> Vec<u8> {
    joined(&[
        PEER_JOIN_DOMAIN,
        origin.trim_end_matches('/'),
        inviter_account,
        link_hash,
        joiner_account,
        joiner_root_b64,
        key_b64,
    ])
}

/// The hash of a share code: b64u of SHA-256(`"apassy-connect share-link v1" 0x00
/// code`), 43 characters.
pub fn share_link_hash(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SHARE_LINK_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(code.as_bytes());
    encode_b64(&hasher.finalize())
}

/// The key fingerprint of a share code: the first 16 bytes of SHA-256(`"apassy-connect
/// share-keys v1" 0x00 root 0x00 inviter key`), keys as 65 raw bytes, as 32 lowercase hex.
pub fn share_fingerprint(root: &[u8], inviter_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SHARE_KEYS_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(root);
    hasher.update([0]);
    hasher.update(inviter_key);
    hasher.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The six words of a share between two accounts (section 16.2): SHA-256(`"apassy-connect
/// share-safety v1" 0x00 code 0x00 inviter_account 0x00 inviter_root 0x00 inviter_key 0x00
/// joiner_account 0x00 joiner_root 0x00 joiner_key`), keys as 65 raw bytes, and
/// `WORDS[digest[0]]` to `WORDS[digest[5]]`. Connect never knows the code.
pub fn share_safety_words(
    code: &str,
    (inviter_account, inviter_root, inviter_key): (&str, &[u8], &[u8]),
    (joiner_account, joiner_root, joiner_key): (&str, &[u8], &[u8]),
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SHARE_SAFETY_DOMAIN.as_bytes());
    for part in [
        code.as_bytes(),
        inviter_account.as_bytes(),
        inviter_root,
        inviter_key,
        joiner_account.as_bytes(),
        joiner_root,
        joiner_key,
    ] {
        hasher.update([0]);
        hasher.update(part);
    }
    hasher.finalize()[..6]
        .iter()
        .map(|byte| WORDS[usize::from(*byte)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// The list hash of an entry: b64u of SHA-256 of its message, 43 characters. The next
/// entry names it as `previous`.
pub fn account_list_hash(message: &[u8]) -> String {
    encode_b64(&Sha256::digest(message))
}

/// `"apassy-connect recover v1" 0x00 origin 0x00 account 0x00 public_key_b64 0x00
/// recovery_key_b64` (`POST /v1/account/recover`): signed by the new device key and by
/// the account's current recovery key; it names the next recovery key.
pub fn account_recover_message(
    origin: &str,
    account: &str,
    public_key_b64: &str,
    recovery_key_b64: &str,
) -> Vec<u8> {
    joined(&[
        ACCOUNT_RECOVER_DOMAIN,
        origin.trim_end_matches('/'),
        account,
        public_key_b64,
        recovery_key_b64,
    ])
}

/// The link hash of a link code: b64u of SHA-256(`"apassy-connect link v1" 0x00 code`),
/// 43 characters. The device that made the code sends only this.
pub fn account_link_hash(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_LINK_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(code.as_bytes());
    encode_b64(&hasher.finalize())
}

/// The key fingerprint of a link code: the first 16 bytes of
/// SHA-256(`"apassy-connect link-keys v1" 0x00 root_key 0x00 confirmer_key`), the keys as
/// 65 raw bytes, as 32 lowercase hex characters. The code names the account's root key
/// and the confirming device's key, so the joining device knows both before the answer.
pub fn account_link_fingerprint(root_key: &[u8], confirmer_key: &[u8]) -> String {
    let digest = Sha256::digest(joined_bytes(&[
        ACCOUNT_LINK_KEYS_DOMAIN.as_bytes(),
        root_key,
        confirmer_key,
    ]));
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The Ed25519 seed of the recovery key of a recovery code's 16 bytes:
/// SHA-256(`"apassy-connect recovery key v1" 0x00 bytes`).
pub fn account_recovery_seed(code: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(
        Sha256::digest(joined_bytes(&[
            ACCOUNT_RECOVERY_KEY_DOMAIN.as_bytes(),
            code,
        ]))
        .into(),
    )
}

/// The recovery key of an account: the Ed25519 key pair of [`account_recovery_seed`].
/// Connect holds its public key only; the recovery code stays with the person.
pub struct RecoveryKey {
    pair: ring::signature::Ed25519KeyPair,
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

impl RecoveryKey {
    /// The recovery key of the 16 bytes of a recovery code.
    pub fn from_code(code: &[u8]) -> Result<Self, DeviceKeyError> {
        let seed = account_recovery_seed(code);
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed.as_slice())
            .map_err(|_| DeviceKeyError)?;
        Ok(Self { pair })
    }

    /// The 32 bytes of the public key.
    pub fn public_key(&self) -> [u8; RECOVERY_KEY_BYTES] {
        let mut key = [0u8; RECOVERY_KEY_BYTES];
        key.copy_from_slice(self.pair.public_key().as_ref());
        key
    }

    /// The public key on the wire: b64u, 43 characters.
    pub fn public_key_b64(&self) -> String {
        encode_b64(&self.public_key())
    }

    /// The 64-byte Ed25519 signature of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; RECOVERY_SIGNATURE_BYTES] {
        let mut signature = [0u8; RECOVERY_SIGNATURE_BYTES];
        signature.copy_from_slice(self.pair.sign(message).as_ref());
        signature
    }
}

/// Decodes a recovery key from the wire: b64u of 32 bytes, 43 characters.
pub fn decode_recovery_key(text: &str) -> Result<[u8; RECOVERY_KEY_BYTES], DeviceKeyError> {
    if text.len() != 43 {
        return Err(DeviceKeyError);
    }
    decode_b64(text, RECOVERY_KEY_BYTES)
        .map_err(|_| DeviceKeyError)?
        .try_into()
        .map_err(|_| DeviceKeyError)
}

/// True when `signature` (64 bytes) is the Ed25519 signature of `message` by the recovery
/// key `public_key` (32 bytes).
pub fn verify_recovery(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    public_key.len() == RECOVERY_KEY_BYTES
        && signature.len() == RECOVERY_SIGNATURE_BYTES
        && ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
            .verify(message, signature)
            .is_ok()
}

/// The six safety words of an account device link (section 7.3):
/// SHA-256(`"apassy-connect safety v1" 0x00 account 0x00 code 0x00 confirmer key 0x00
/// joiner key`), the keys as 65 raw bytes, and `WORDS[digest[0]]` to `WORDS[digest[5]]`.
/// Connect never knows the code, so it cannot compute them; the devices can, and the
/// relay's CLI and tests use this.
pub fn account_safety_words(
    account: &str,
    code: &str,
    confirmer_key: &[u8],
    joiner_key: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_SAFETY_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(account.as_bytes());
    hasher.update([0]);
    hasher.update(code.as_bytes());
    hasher.update([0]);
    hasher.update(confirmer_key);
    hasher.update([0]);
    hasher.update(joiner_key);
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..6]
        .iter()
        .map(|byte| WORDS[usize::from(*byte)])
        .collect::<Vec<_>>()
        .join(" ")
}

/// A device key failed: a bad key, a bad encoding, or no random source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceKeyError;

impl std::fmt::Display for DeviceKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the device key is not valid")
    }
}

impl std::error::Error for DeviceKeyError {}

/// The private key of this device.
pub struct DeviceKey {
    pair: EcdsaKeyPair,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKey(<redacted>)")
    }
}

impl DeviceKey {
    /// A new random key.
    pub fn generate() -> Result<Self, DeviceKeyError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| DeviceKeyError)?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// The key from its PKCS#8 document.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, DeviceKeyError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
            .map_err(|_| DeviceKeyError)?;
        Ok(Self {
            pair,
            pkcs8: Zeroizing::new(pkcs8.to_vec()),
        })
    }

    /// The PKCS#8 document, to store the key. Secret.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The public key, 65 bytes.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut out = [0u8; PUBLIC_KEY_BYTES];
        out.copy_from_slice(self.pair.public_key().as_ref());
        out
    }

    /// The public key as base64url without padding: the form on the wire.
    pub fn public_key_b64(&self) -> String {
        encode_b64(&self.public_key())
    }

    /// Signs a message. ASN.1 DER.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        let rng = SystemRandom::new();
        self.pair
            .sign(&rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| DeviceKeyError)
    }
}

/// Decodes a public key from the wire: base64url, 65 bytes, starting with 0x04, and a
/// point on P-256 (`on_curve`). 64 random bytes after 0x04 are refused.
pub fn decode_public_key(text: &str) -> Result<[u8; PUBLIC_KEY_BYTES], DeviceKeyError> {
    let bytes = decode_b64(text, PUBLIC_KEY_BYTES).map_err(|_| DeviceKeyError)?;
    let key: [u8; PUBLIC_KEY_BYTES] = bytes.try_into().map_err(|_| DeviceKeyError)?;
    if key[0] != 0x04 || !on_curve(&key) {
        return Err(DeviceKeyError);
    }
    Ok(key)
}

/// True when `key` (uncompressed SEC1) is a point on P-256. ring has no call that only
/// checks a public key, but its ECDH validates the peer's point before anything else
/// (on the curve, coordinates below the field prime): one agreement with a throwaway key
/// answers the question. No random source: false.
fn on_curve(key: &[u8]) -> bool {
    use ring::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
    let Ok(own) = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()) else {
        return false;
    };
    agree_ephemeral(own, &UnparsedPublicKey::new(&ECDH_P256, key), |_| ()).is_ok()
}

/// True when `signature` (DER) is a valid signature of `message` by `public_key`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    public_key.len() == PUBLIC_KEY_BYTES
        && signature.len() <= MAX_SIGNATURE_BYTES
        && UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
            .verify(message, signature)
            .is_ok()
}

/// The message that a device signs to sign in:
/// `"apassy-relay sign-in v1" 0x00 origin 0x00 team_id 0x00 public_key_b64 0x00 nonce_b64`.
///
/// `origin` is the relay URL that the CLI is configured with, without a trailing
/// slash; the relay checks it against its own public URL, so a signature for one
/// relay is worthless at another. The team id and the key bind it to one device of
/// one team.
pub fn sign_in_message(
    origin: &str,
    team: &TeamId,
    public_key_b64: &str,
    nonce_b64: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGN_IN_DOMAIN.len() + origin.len() + public_key_b64.len() + nonce_b64.len() + 20,
    );
    for (i, part) in [
        SIGN_IN_DOMAIN,
        origin.trim_end_matches('/'),
        team.as_str(),
        public_key_b64,
        nonce_b64,
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            message.push(0);
        }
        message.extend_from_slice(part.as_bytes());
    }
    message
}

/// The message that the app signs to make a Connect team (`POST /v1/connect`):
/// `"apassy-relay connect v1" 0x00 origin 0x00 public_key_b64`, the same form as the
/// sign-in message. `origin` is the relay URL without a trailing slash; the relay checks
/// it against its own public URL. It proves that the caller holds the private key of
/// the public key it names.
pub fn connect_message(origin: &str, public_key_b64: &str) -> Vec<u8> {
    let origin = origin.trim_end_matches('/');
    let mut message =
        Vec::with_capacity(CONNECT_DOMAIN.len() + origin.len() + public_key_b64.len() + 2);
    message.extend_from_slice(CONNECT_DOMAIN.as_bytes());
    message.push(0);
    message.extend_from_slice(origin.as_bytes());
    message.push(0);
    message.extend_from_slice(public_key_b64.as_bytes());
    message
}

/// Fresh Connect recovery proof, distinct from creation and ordinary sign-in.
pub fn connect_recovery_message(origin: &str, public_key_b64: &str, nonce: &str) -> Vec<u8> {
    let mut message = connect_message(origin, public_key_b64);
    message.extend_from_slice(b"\0recovery\0");
    message.extend_from_slice(nonce.as_bytes());
    message
}

/// A new random sign-in nonce, base64url.
pub fn new_nonce() -> Result<String, DeviceKeyError> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| DeviceKeyError)?;
    Ok(encode_b64(&bytes))
}

/// Two words that the joiner and the confirmer compare, for an invite code or a device
/// link code and the public key of the new device:
/// SHA-256(`"apassy-relay safety v1" 0x00 team_id 0x00 code 0x00 public_key`), the
/// first two bytes as indexes into a list of 256 words. The joiner knows the code and
/// its key; the relay computes the same when the join arrives and keeps the words.
pub fn safety_words(team: &TeamId, code: &str, public_key: &[u8]) -> String {
    let digest = safety_hash(team, code, public_key);
    format!(
        "{} {}",
        WORDS[usize::from(digest[0])],
        WORDS[usize::from(digest[1])]
    )
}

/// The SHA-256 of the safety message of [`safety_words`].
fn safety_hash(team: &TeamId, code: &str, public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SAFETY_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(team.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(code.as_bytes());
    hasher.update([0]);
    hasher.update(public_key);
    hasher.finalize().into()
}

/// True when `typed` names the same two words as `expected`, ignoring case and the
/// spaces around and between them.
pub fn same_safety(typed: &str, expected: &str) -> bool {
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_lowercase).collect() };
    let typed = words(typed);
    typed.len() == 2 && typed == words(expected)
}

const WORDS: [&str; 256] = [
    "acid", "acorn", "actor", "adult", "agent", "alarm", "album", "alert", "alpha", "amber",
    "angle", "apple", "april", "arena", "armor", "arrow", "atlas", "attic", "audio", "aunt",
    "autumn", "award", "bacon", "badge", "bagel", "baker", "bamboo", "banana", "band", "barn",
    "basil", "basket", "beach", "beard", "beaver", "bell", "berry", "bike", "bird", "blade",
    "blaze", "bloom", "board", "boat", "bonus", "book", "boot", "bottle", "brain", "branch",
    "bread", "brick", "bridge", "broom", "brush", "bubble", "bucket", "cabin", "cable", "cactus",
    "camel", "camera", "candle", "canoe", "canyon", "carbon", "carpet", "carrot", "castle", "cave",
    "cedar", "cello", "chalk", "cherry", "chess", "chief", "cider", "circle", "cliff", "cloud",
    "clover", "coast", "cobra", "cocoa", "comet", "coral", "cotton", "cousin", "coyote", "crane",
    "crayon", "cream", "cube", "cup", "daisy", "dancer", "delta", "desert", "dinner", "disk",
    "doctor", "domino", "donkey", "door", "dragon", "dream", "drum", "eagle", "earth", "echo",
    "elbow", "ember", "engine", "falcon", "fence", "ferry", "fiber", "field", "finch", "flag",
    "flame", "flute", "forest", "fossil", "fox", "frost", "galaxy", "garden", "garlic", "gecko",
    "giant", "ginger", "globe", "goat", "gold", "grape", "gravel", "guitar", "hammer", "harbor",
    "harp", "hazel", "helmet", "heron", "hippo", "honey", "hornet", "hotel", "husky", "igloo",
    "island", "ivory", "jacket", "jaguar", "jelly", "jungle", "kayak", "kettle", "kiwi", "koala",
    "ladder", "lagoon", "laser", "lemon", "lilac", "lime", "lion", "lizard", "locket", "lotus",
    "lunar", "magnet", "mango", "maple", "marble", "meadow", "melon", "meteor", "mint", "mirror",
    "monkey", "moose", "mosaic", "muffin", "nectar", "needle", "nest", "noodle", "oasis", "ocean",
    "olive", "onion", "orange", "orbit", "orchid", "otter", "owl", "oyster", "paddle", "panda",
    "paper", "parrot", "peach", "peanut", "pearl", "pebble", "pencil", "pepper", "piano", "pilot",
    "pine", "planet", "plum", "pocket", "pony", "poppy", "potato", "prism", "puzzle", "quartz",
    "quill", "rabbit", "radar", "radio", "raven", "ribbon", "river", "robin", "rocket", "rose",
    "ruby", "saddle", "salmon", "sandal", "satin", "scarf", "seal", "shark", "shell", "sled",
    "snail", "solar", "spoon", "squid", "stamp", "star", "stone", "sugar", "swan", "tango",
    "tiger", "topaz", "tulip", "whale", "wolf", "zebra",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn team() -> TeamId {
        TeamId::parse("t_abcdefgh23").unwrap()
    }

    #[test]
    fn a_key_signs_and_its_public_key_verifies() {
        let key = DeviceKey::generate().unwrap();
        let again = DeviceKey::from_pkcs8(key.pkcs8()).unwrap();
        assert_eq!(key.public_key(), again.public_key());
        let public = decode_public_key(&key.public_key_b64()).unwrap();
        assert_eq!(public[0], 0x04);
        let message = sign_in_message(
            "https://relay.example.test/",
            &team(),
            &key.public_key_b64(),
            "bm9uY2U",
        );
        let signature = again.sign(&message).unwrap();
        assert!(verify(&public, &message, &signature));
        // Another message, another key, or a changed signature fails.
        let other = sign_in_message(
            "https://relay.example.test",
            &team(),
            &key.public_key_b64(),
            "b3RoZXI",
        );
        assert!(!verify(&public, &other, &signature));
        let stranger = DeviceKey::generate().unwrap();
        assert!(!verify(&stranger.public_key(), &message, &signature));
        let mut bad = signature.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(!verify(&public, &message, &bad));
        assert!(!verify(&public[..64], &message, &signature));
        assert!(format!("{key:?}").contains("redacted"));
    }

    /// The sign-in and safety vectors of the app's contract
    /// (`docs/contracts/relay-sync-v1.md` section 15): both sides must build the same
    /// bytes.
    #[test]
    fn the_contract_sign_in_and_safety_vectors_hold() {
        use crate::sync_head::hex;
        let team = TeamId::parse("t_7k2m5q4x3c").unwrap();
        let public_b64 = "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";
        let public = decode_public_key(public_b64).unwrap();
        let nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        assert_eq!(
            decode_b64(nonce, NONCE_BYTES).unwrap(),
            (0u8..32).collect::<Vec<u8>>()
        );
        let message = sign_in_message("https://relay.example.test", &team, public_b64, nonce);
        assert_eq!(
            hex(&Sha256::digest(&message)),
            "43722057f746ba2b1759952943e9532ad49c68496c11a6f1bef65709c20e7aaa"
        );
        let signature = decode_b64(
            "MEUCIAyr22ugUYumzN6x8ktWI1ruvFmEVjktZGhAfa7dRmeXAiEAiHEWtFJmR5giJlad5O0jy9dVkHD3IAKRM3TZRXzwJEY",
            MAX_SIGNATURE_BYTES,
        )
        .unwrap();
        assert!(verify(&public, &message, &signature));
        let other = sign_in_message("https://relay.example.test", &team, public_b64, "AAEC");
        assert!(!verify(&public, &other, &signature));

        let code = format!("apassy_lnk_t_7k2m5q4x3c_{}", "ab".repeat(32));
        assert_eq!(
            hex(&safety_hash(&team, &code, &public)),
            "fc0f67b7df128c3d82fae26d0b646d9bcd3623adcb562f7d85d313f7456a3b7c"
        );
        assert_eq!(safety_words(&team, &code, &public), "tulip arrow");
    }

    #[test]
    fn the_connect_message_has_one_form() {
        assert_eq!(
            connect_message("https://r.test/", "PK"),
            b"apassy-relay connect v1\0https://r.test\0PK".to_vec()
        );
        let key = DeviceKey::generate().unwrap();
        let message = connect_message("https://r.test", &key.public_key_b64());
        let signature = key.sign(&message).unwrap();
        assert!(verify(&key.public_key(), &message, &signature));
        assert!(!verify(
            &key.public_key(),
            &connect_message("https://other.test", &key.public_key_b64()),
            &signature
        ));
    }

    #[test]
    fn the_account_messages_have_one_form() {
        assert_eq!(
            account_message("https://c.test/", "PK", "RK"),
            b"apassy-connect account v1\0https://c.test\0PK\0RK".to_vec()
        );
        assert_eq!(
            account_join_cancel_message("https://c.test", "acc_a", "LH", "PK"),
            b"apassy-connect join-cancel v1\0https://c.test\0acc_a\0LH\0PK".to_vec()
        );
        assert_eq!(
            account_list_message(
                "https://c.test/",
                "acc_a",
                2,
                "PH",
                "add",
                "PK",
                "LH",
                "iPhone",
                "BY"
            ),
            b"apassy-connect device-list v1\0https://c.test\0acc_a\x002\0PH\0add\0PK\0LH\0iPhone\0BY"
                .to_vec()
        );
        assert_eq!(
            account_list_message(
                "https://c.test",
                "acc_a",
                3,
                "PH",
                "remove",
                "PK",
                "-",
                "-",
                "BY"
            ),
            b"apassy-connect device-list v1\0https://c.test\0acc_a\x003\0PH\0remove\0PK\0-\0-\0BY"
                .to_vec()
        );
        assert_eq!(account_list_hash(b"").len(), 43);
        assert_eq!(
            account_recover_message("https://c.test", "acc_a", "PK", "RK"),
            b"apassy-connect recover v1\0https://c.test\0acc_a\0PK\0RK".to_vec()
        );
        // The fingerprint of a link: raw keys joined, the first 16 bytes of the hash.
        let root: Vec<u8> = std::iter::once(4u8).chain([1u8; 64]).collect();
        let confirmer: Vec<u8> = std::iter::once(4u8).chain([2u8; 64]).collect();
        assert_eq!(
            account_link_fingerprint(&root, &confirmer),
            "586e3b37bebf6d16108a30de31e68499"
        );
        assert_ne!(
            account_link_fingerprint(&confirmer, &root),
            account_link_fingerprint(&root, &confirmer)
        );
    }

    #[test]
    fn a_recovery_code_makes_one_recovery_key() {
        use crate::sync_head::hex;
        let code: Vec<u8> = (16u8..32).collect();
        assert_eq!(
            hex(account_recovery_seed(&code).as_slice()),
            "01a7c586b139da386c54e38672688a157f0c798a657c5cdc91e2b57adfb142e6"
        );
        let key = RecoveryKey::from_code(&code).unwrap();
        let again = RecoveryKey::from_code(&code).unwrap();
        assert_eq!(key.public_key(), again.public_key());
        assert_eq!(key.public_key_b64().len(), 43);
        assert_eq!(
            decode_recovery_key(&key.public_key_b64()).unwrap(),
            key.public_key()
        );
        assert!(decode_recovery_key(&encode_b64(&[1u8; 33])).is_err());
        assert!(decode_recovery_key("").is_err());
        let message = account_recover_message("https://c.test", "acc_a", "PK", "RK");
        let signature = key.sign(&message);
        assert!(verify_recovery(&key.public_key(), &message, &signature));
        let other = RecoveryKey::from_code(&[0u8; 16]).unwrap();
        assert_ne!(other.public_key(), key.public_key());
        assert!(!verify_recovery(&other.public_key(), &message, &signature));
        assert!(!verify_recovery(
            &key.public_key(),
            &account_recover_message("https://c.test", "acc_a", "PK", "R2"),
            &signature
        ));
        assert!(!verify_recovery(
            &key.public_key(),
            &message,
            &signature[..63]
        ));
        assert!(format!("{key:?}").contains("redacted"));
    }

    #[test]
    fn the_sign_in_message_has_one_form() {
        let message = sign_in_message("https://r.test/", &team(), "PK", "NONCE");
        assert_eq!(
            message,
            b"apassy-relay sign-in v1\0https://r.test\0t_abcdefgh23\0PK\0NONCE".to_vec()
        );
    }

    #[test]
    fn public_keys_are_checked_on_the_wire() {
        assert!(decode_public_key("").is_err());
        assert!(decode_public_key(&encode_b64(&[4u8; 64])).is_err());
        assert!(decode_public_key(&encode_b64(&[2u8; 65])).is_err());
        assert!(decode_public_key(&encode_b64(&[4u8; 66])).is_err());
        // 0x04 and 64 bytes that are not a point on P-256.
        assert!(decode_public_key(&encode_b64(&[4u8; 65])).is_err());
        let mut zero = [0u8; 65];
        zero[0] = 4;
        assert!(decode_public_key(&encode_b64(&zero)).is_err());
        // A real key passes; one bit flipped in Y does not.
        let key = DeviceKey::generate().unwrap();
        assert_eq!(
            decode_public_key(&key.public_key_b64()).unwrap(),
            key.public_key()
        );
        let mut flipped = key.public_key();
        flipped[64] ^= 1;
        assert!(decode_public_key(&encode_b64(&flipped)).is_err());
        assert!(!new_nonce().unwrap().is_empty());
        assert_ne!(new_nonce().unwrap(), new_nonce().unwrap());
    }

    #[test]
    fn typed_safety_words_ignore_case_and_spaces() {
        assert!(same_safety(" Lion   PEBBLE ", "lion pebble"));
        assert!(!same_safety("lion", "lion pebble"));
        assert!(!same_safety("pebble lion", "lion pebble"));
        assert!(!same_safety("lion pebble extra", "lion pebble"));
        assert!(!same_safety("", "lion pebble"));
    }

    #[test]
    fn safety_words_depend_on_team_code_and_key() {
        let words = safety_words(&team(), "apassy_inv_x", &[4u8; 65]);
        assert_eq!(words.split(' ').count(), 2);
        assert!(words.split(' ').all(|w| WORDS.contains(&w)));
        assert_eq!(words, safety_words(&team(), "apassy_inv_x", &[4u8; 65]));
        let mut differ = 0;
        for i in 0..20u8 {
            let mut key = [4u8; 65];
            key[1] = i;
            if safety_words(&team(), "apassy_inv_x", &key) != words {
                differ += 1;
            }
        }
        assert!(differ >= 18, "the key changes the words");
        let mut sorted = WORDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 256, "256 different words");
    }
}
