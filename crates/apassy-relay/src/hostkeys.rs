//! Host-held item keys (docs/SPEC.md, "Host-held item keys").
//!
//! The relay never stores a readable item value. Each item is sealed in the CLI with
//! a key of its own, and the key stays on the owner's host. For one run, the host
//! seals the keys of the items of that run to a one-time X25519 key of that run,
//! and the relay opens them in memory, decrypts the values, and forgets them when the
//! session ends. Both sides use this module, so there is one copy of the formats.
//!
//! - Item: `sealed = nonce(12) || AES-256-GCM(item_key, nonce, value, aad = "apassy-relay item v1\0" || uid)`.
//! - Release: `shared = X25519(run private, host public)`,
//!   `wrap_key = HKDF-SHA256(salt = run_key || host_key, ikm = shared, info = "apassy-relay release v1")`,
//!   `sealed_keys = AES-256-GCM(wrap_key, nonce, plaintext, aad = "apassy-relay release v1\0" || run_id || "\0" || run_key)`.
//!
//! Key material lives in `Zeroizing` buffers. A failure is one `CryptoError` that says
//! nothing about which check failed.

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::secret::SecretString;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
/// A uid is 16 random bytes as 32 lowercase hex characters.
pub const UID_HEX_LEN: usize = 32;
/// The longest item value, in bytes.
pub const MAX_VALUE_BYTES: usize = 4096;
/// The shortest and the longest `sealed` of an item: nonce, tag, and 1 to 4096 bytes.
pub const MIN_SEALED_BYTES: usize = NONCE_BYTES + TAG_BYTES + 1;
pub const MAX_SEALED_BYTES: usize = NONCE_BYTES + TAG_BYTES + MAX_VALUE_BYTES;
/// The largest `sealed_keys` of a release, decoded. 16 items need about 2 KiB.
pub const MAX_SEALED_KEYS_BYTES: usize = 16 * 1024;

const ITEM_AAD: &[u8] = b"apassy-relay item v1\0";
const RELEASE_INFO: &[u8] = b"apassy-relay release v1";
const RELEASE_AAD: &[u8] = b"apassy-relay release v1\0";

/// A key of 32 bytes that is erased on drop.
pub type Key32 = Zeroizing<[u8; KEY_BYTES]>;

/// Any crypto or format failure. It never says which check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a key or a sealed text did not check")
    }
}

impl std::error::Error for CryptoError {}

type Result<T> = std::result::Result<T, CryptoError>;

fn fill(buf: &mut [u8]) -> Result<()> {
    SystemRandom::new().fill(buf).map_err(|_| CryptoError)
}

// ---- Base64 (URL-safe, no padding) ----

pub fn encode_b64(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes text of at most `max_bytes` decoded bytes. For text that is not secret
/// (a public key, a nonce, a sealed text). Padding and non-canonical text are refused.
pub fn decode_b64(text: &str, max_bytes: usize) -> Result<Vec<u8>> {
    if text.len() > max_bytes.saturating_mul(4) / 3 + 4 {
        return Err(CryptoError);
    }
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| CryptoError)?;
    if bytes.len() > max_bytes {
        return Err(CryptoError);
    }
    Ok(bytes)
}

/// Decodes exactly `N` bytes into an array.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = decode_b64(text, N)?;
    bytes.try_into().map_err(|_| CryptoError)
}

/// Decodes a 32-byte key without leaving a plain copy behind.
pub fn decode_key(text: &str) -> Result<Key32> {
    let mut buf = Zeroizing::new([0u8; KEY_BYTES + 8]);
    let written = BASE64_URL_SAFE_NO_PAD
        .decode_slice(text.as_bytes(), buf.as_mut())
        .map_err(|_| CryptoError)?;
    if written != KEY_BYTES {
        return Err(CryptoError);
    }
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    key.copy_from_slice(&buf[..KEY_BYTES]);
    Ok(key)
}

/// A key as text, in a buffer that is erased on drop.
pub fn encode_key(key: &Key32) -> Zeroizing<String> {
    Zeroizing::new(BASE64_URL_SAFE_NO_PAD.encode(key.as_slice()))
}

// ---- Items ----

/// A new uid: 16 random bytes as 32 lowercase hex characters.
pub fn new_uid() -> Result<String> {
    let mut bytes = [0u8; UID_HEX_LEN / 2];
    fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// True for 32 lowercase hex characters.
pub fn is_uid(text: &str) -> bool {
    text.len() == UID_HEX_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A new item key: 32 random bytes.
pub fn new_key() -> Result<Key32> {
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    fill(key.as_mut())?;
    Ok(key)
}

/// A copy with room for the tag, so sealing does not move the plaintext to a new
/// allocation that nothing would erase.
fn with_room(plain: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(plain.len() + TAG_BYTES);
    buf.extend_from_slice(plain);
    buf
}

fn aead_key(key: &[u8; KEY_BYTES]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError)
}

fn item_aad(uid: &str) -> Vec<u8> {
    [ITEM_AAD, uid.as_bytes()].concat()
}

/// Seals a value for an item: `nonce || ciphertext || tag`. The value is 1 to 4096 bytes.
pub fn seal_item(key: &Key32, uid: &str, value: &[u8]) -> Result<Vec<u8>> {
    if !is_uid(uid) || value.is_empty() || value.len() > MAX_VALUE_BYTES {
        return Err(CryptoError);
    }
    let mut nonce = [0u8; NONCE_BYTES];
    fill(&mut nonce)?;
    let mut inout = Zeroizing::new(with_room(value));
    aead_key(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(item_aad(uid)),
            &mut *inout,
        )
        .map_err(|_| CryptoError)?;
    let mut sealed = Vec::with_capacity(NONCE_BYTES + inout.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&inout);
    Ok(sealed)
}

/// Opens the `sealed` of an item. A wrong key, a wrong uid, or a changed text fails.
pub fn open_item(key: &Key32, uid: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !is_uid(uid) || sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(CryptoError);
    }
    let (nonce, body) = sealed.split_at(NONCE_BYTES);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| CryptoError)?;
    open_body(key, nonce, &item_aad(uid), body)
}

fn open_body(
    key: &[u8; KEY_BYTES],
    nonce: [u8; NONCE_BYTES],
    aad: &[u8],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(body.to_vec());
    let plain_len = aead_key(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| CryptoError)?
        .len();
    buf.truncate(plain_len);
    Ok(buf)
}

/// What the CLI checks before it seals a value (docs/SPEC.md, section 8). The relay
/// cannot check a value any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueProblem {
    /// Not 1 to 4096 bytes of printable ASCII without `"` and `\`.
    Shape,
    /// `proxy::mint` cannot make a placeholder for it.
    Placeholder,
}

impl ValueProblem {
    pub fn message(self) -> &'static str {
        match self {
            Self::Shape => {
                "The value is 1 to 4096 bytes of printable ASCII, with no quote (\") and no backslash."
            }
            Self::Placeholder => {
                "This value cannot get a placeholder: it is too short or has too little variety. The relay cannot use an item that has none."
            }
        }
    }
}

/// The value rules: printable ASCII (space to `~`), 1 to 4096 bytes, no `"` and no
/// `\`, so JSON writes the value as it is and a JSON echo of it is found. And
/// `proxy::mint` must make a placeholder for it.
pub fn check_value(value: &str) -> std::result::Result<(), ValueProblem> {
    let shape_ok = !value.is_empty()
        && value.len() <= MAX_VALUE_BYTES
        && value
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) && b != b'"' && b != b'\\');
    if !shape_ok {
        return Err(ValueProblem::Shape);
    }
    if crate::proxy::mint(&SecretString::new(value.to_owned())).is_none() {
        return Err(ValueProblem::Placeholder);
    }
    Ok(())
}

// ---- Releases ----

/// The one-time key of one run. The private half exists only in memory and only
/// until a release is tried: `open_release` consumes it.
pub struct RunKey {
    private: EphemeralPrivateKey,
    public: [u8; KEY_BYTES],
}

impl std::fmt::Debug for RunKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunKey(<redacted>)")
    }
}

impl RunKey {
    pub fn generate() -> Result<Self> {
        let private = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
            .map_err(|_| CryptoError)?;
        let public = private
            .compute_public_key()
            .map_err(|_| CryptoError)?
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError)?;
        Ok(Self { private, public })
    }

    /// The `run_key` that goes to the host.
    pub fn public(&self) -> [u8; KEY_BYTES] {
        self.public
    }

    /// Opens a release from the host. The key is used up, whatever the result.
    pub fn open_release(
        self,
        run_id: u64,
        host_key: &[u8; KEY_BYTES],
        nonce: [u8; NONCE_BYTES],
        sealed_keys: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if sealed_keys.len() < TAG_BYTES {
            return Err(CryptoError);
        }
        let run_key = self.public;
        let peer = UnparsedPublicKey::new(&X25519, host_key);
        agreement::agree_ephemeral(self.private, &peer, |shared| {
            let wrap = wrap_key(shared, &run_key, host_key)?;
            open_body(&wrap, nonce, &release_aad(run_id, &run_key), sealed_keys)
        })
        .map_err(|_| CryptoError)?
    }
}

/// What the host sends: its one-time public key, a nonce, and the sealed keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub host_key: [u8; KEY_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub sealed_keys: Vec<u8>,
}

/// Seals `plaintext` (the keys of one run) to the `run_key` of run `run_id`, with a
/// new one-time key of the host.
pub fn seal_release(run_key: &[u8; KEY_BYTES], run_id: u64, plaintext: &[u8]) -> Result<Release> {
    let rng = SystemRandom::new();
    let private = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| CryptoError)?;
    let host_key: [u8; KEY_BYTES] = private
        .compute_public_key()
        .map_err(|_| CryptoError)?
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError)?;
    let mut nonce = [0u8; NONCE_BYTES];
    fill(&mut nonce)?;
    let peer = UnparsedPublicKey::new(&X25519, run_key);
    let sealed_keys = agreement::agree_ephemeral(private, &peer, |shared| {
        let wrap = wrap_key(shared, run_key, &host_key)?;
        let mut inout = Zeroizing::new(with_room(plaintext));
        aead_key(&wrap)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(release_aad(run_id, run_key)),
                &mut *inout,
            )
            .map_err(|_| CryptoError)?;
        Ok(inout.to_vec())
    })
    .map_err(|_| CryptoError)??;
    Ok(Release {
        host_key,
        nonce,
        sealed_keys,
    })
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// `HKDF-SHA256(salt = run_key || host_key, ikm = shared, info = "apassy-relay release v1")`, 32 bytes.
fn wrap_key(shared: &[u8], run_key: &[u8; KEY_BYTES], host_key: &[u8; KEY_BYTES]) -> Result<Key32> {
    let salt_bytes = [run_key.as_slice(), host_key.as_slice()].concat();
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes).extract(shared);
    let okm = prk
        .expand(&[RELEASE_INFO], Len(KEY_BYTES))
        .map_err(|_| CryptoError)?;
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    okm.fill(key.as_mut()).map_err(|_| CryptoError)?;
    Ok(key)
}

/// `"apassy-relay release v1\0" || run_id as decimal || "\0" || run_key`.
fn release_aad(run_id: u64, run_key: &[u8; KEY_BYTES]) -> Vec<u8> {
    let mut aad = RELEASE_AAD.to_vec();
    aad.extend_from_slice(run_id.to_string().as_bytes());
    aad.push(0);
    aad.extend_from_slice(run_key);
    aad
}

/// The plaintext of a release, read side. The relay checks that `run_id` is the run
/// and that the uids are exactly the uids of its items.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlain {
    pub run_id: u64,
    pub keys: Vec<ReleaseKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseKey {
    pub uid: String,
    /// 32 bytes, base64url without padding.
    pub key: SecretString,
}

/// Write side of `ReleasePlain`, for the host.
#[derive(serde::Serialize)]
pub struct ReleasePlainRef<'a> {
    pub run_id: u64,
    pub keys: Vec<ReleaseKeyRef<'a>>,
}

#[derive(serde::Serialize)]
pub struct ReleaseKeyRef<'a> {
    pub uid: &'a str,
    pub key: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const VALUE: &str = "sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF";

    #[test]
    fn item_round_trip() {
        let key = new_key().unwrap();
        let uid = new_uid().unwrap();
        assert!(is_uid(&uid));
        let sealed = seal_item(&key, &uid, VALUE.as_bytes()).unwrap();
        assert_eq!(sealed.len(), NONCE_BYTES + VALUE.len() + TAG_BYTES);
        assert!(!sealed.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
        let opened = open_item(&key, &uid, &sealed).unwrap();
        assert_eq!(opened.as_slice(), VALUE.as_bytes());
        // Two seals of the same value differ: the nonce is random.
        assert_ne!(sealed, seal_item(&key, &uid, VALUE.as_bytes()).unwrap());
    }

    #[test]
    fn item_needs_its_uid_and_its_key() {
        let key = new_key().unwrap();
        let uid = new_uid().unwrap();
        let sealed = seal_item(&key, &uid, VALUE.as_bytes()).unwrap();
        let other_uid = new_uid().unwrap();
        assert_eq!(open_item(&key, &other_uid, &sealed), Err(CryptoError));
        let other_key = new_key().unwrap();
        assert_eq!(open_item(&other_key, &uid, &sealed), Err(CryptoError));
        let mut changed = sealed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(open_item(&key, &uid, &changed), Err(CryptoError));
        let mut changed = sealed.clone();
        changed[0] ^= 1;
        assert_eq!(open_item(&key, &uid, &changed), Err(CryptoError));
        assert_eq!(open_item(&key, &uid, &sealed[..20]), Err(CryptoError));
        assert_eq!(open_item(&key, "not-a-uid", &sealed), Err(CryptoError));
    }

    #[test]
    fn item_value_bounds() {
        let key = new_key().unwrap();
        let uid = new_uid().unwrap();
        assert!(seal_item(&key, &uid, b"").is_err());
        let longest = vec![b'a'; MAX_VALUE_BYTES];
        let sealed = seal_item(&key, &uid, &longest).unwrap();
        assert_eq!(sealed.len(), MAX_SEALED_BYTES);
        assert!(seal_item(&key, &uid, &vec![b'a'; MAX_VALUE_BYTES + 1]).is_err());
        assert_eq!(seal_item(&key, &uid, b"x").unwrap().len(), MIN_SEALED_BYTES);
    }

    #[test]
    fn uid_form() {
        assert!(is_uid(&"0123456789abcdef".repeat(2)));
        assert!(!is_uid(&"0123456789ABCDEF".repeat(2)));
        assert!(!is_uid(&"0123456789abcdef".repeat(2)[1..]));
        assert!(!is_uid(""));
        assert_ne!(new_uid().unwrap(), new_uid().unwrap());
    }

    #[test]
    fn value_rules() {
        assert_eq!(check_value(VALUE), Ok(()));
        for bad in [
            "",
            "has\"quote-0123456789abcdef",
            "back\\slash-0123456789abcdef",
            "tab\there-0123456789abcdef",
            "é-0123456789abcdef",
        ] {
            assert_eq!(check_value(bad), Err(ValueProblem::Shape), "{bad:?}");
        }
        assert_eq!(
            check_value(&"a".repeat(MAX_VALUE_BYTES + 1)),
            Err(ValueProblem::Shape)
        );
        assert_eq!(check_value("ab"), Err(ValueProblem::Placeholder));
    }

    fn release_plain(run_id: u64) -> Vec<u8> {
        format!(
            r#"{{"run_id":{run_id},"keys":[{{"uid":"{}","key":"k"}}]}}"#,
            "0".repeat(32)
        )
        .into_bytes()
    }

    #[test]
    fn release_round_trip() {
        let run = RunKey::generate().unwrap();
        let plain = release_plain(7);
        let release = seal_release(&run.public(), 7, &plain).unwrap();
        assert_eq!(release.sealed_keys.len(), plain.len() + TAG_BYTES);
        let opened = run
            .open_release(7, &release.host_key, release.nonce, &release.sealed_keys)
            .unwrap();
        assert_eq!(opened.as_slice(), plain.as_slice());
    }

    #[test]
    fn release_for_another_run_id_fails() {
        let run = RunKey::generate().unwrap();
        let release = seal_release(&run.public(), 7, &release_plain(7)).unwrap();
        let result = run.open_release(8, &release.host_key, release.nonce, &release.sealed_keys);
        assert_eq!(result.unwrap_err(), CryptoError);
    }

    #[test]
    fn release_for_another_run_key_fails() {
        let run_a = RunKey::generate().unwrap();
        let run_b = RunKey::generate().unwrap();
        let release = seal_release(&run_a.public(), 7, &release_plain(7)).unwrap();
        let result = run_b.open_release(7, &release.host_key, release.nonce, &release.sealed_keys);
        assert_eq!(result.unwrap_err(), CryptoError);
    }

    #[test]
    fn a_changed_release_fails() {
        let plain = release_plain(3);
        let tries: [fn(&mut Release); 4] = [
            |r| r.sealed_keys[0] ^= 1,
            |r| *r.sealed_keys.last_mut().unwrap() ^= 1,
            |r| r.nonce[0] ^= 1,
            |r| r.host_key[0] ^= 1,
        ];
        for change in tries {
            let run = RunKey::generate().unwrap();
            let mut release = seal_release(&run.public(), 3, &plain).unwrap();
            change(&mut release);
            let result =
                run.open_release(3, &release.host_key, release.nonce, &release.sealed_keys);
            assert!(result.is_err());
        }
        // Too short to hold a tag.
        let run = RunKey::generate().unwrap();
        let release = seal_release(&run.public(), 3, &plain).unwrap();
        assert!(
            run.open_release(3, &release.host_key, release.nonce, &[0u8; 8])
                .is_err()
        );
    }

    #[test]
    fn a_low_order_host_key_is_refused() {
        // The all-zero point gives an all-zero shared secret: ring refuses it.
        let run = RunKey::generate().unwrap();
        let result = run.open_release(1, &[0u8; KEY_BYTES], [0u8; NONCE_BYTES], &[0u8; 40]);
        assert!(result.is_err());
    }

    #[test]
    fn run_keys_are_one_time_and_differ() {
        let a = RunKey::generate().unwrap();
        let b = RunKey::generate().unwrap();
        assert_ne!(a.public(), b.public());
        assert!(!format!("{a:?}").contains(&encode_b64(&a.public())));
    }

    fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut block = [0u8; 64];
        assert!(key.len() <= 64);
        block[..key.len()].copy_from_slice(key);
        let inner: Vec<u8> = block
            .iter()
            .map(|b| b ^ 0x36)
            .chain(data.iter().copied())
            .collect();
        let inner = Sha256::digest(&inner);
        let outer: Vec<u8> = block
            .iter()
            .map(|b| b ^ 0x5c)
            .chain(inner.iter().copied())
            .collect();
        Sha256::digest(&outer).into()
    }

    #[test]
    fn wrap_key_is_rfc_5869_with_the_documented_inputs() {
        // HKDF by hand (RFC 5869, one block of output) against the ring HKDF, with the
        // salt, the input key, and the info that docs/SPEC.md names.
        let rng = SystemRandom::new();
        let a = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let b = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        let run_key: [u8; 32] = a.compute_public_key().unwrap().as_ref().try_into().unwrap();
        let host_key: [u8; 32] = b.compute_public_key().unwrap().as_ref().try_into().unwrap();
        let peer = UnparsedPublicKey::new(&X25519, &run_key);
        agreement::agree_ephemeral(b, &peer, |shared| {
            let salt = [run_key.as_slice(), host_key.as_slice()].concat();
            let prk = hmac(&salt, shared);
            let by_hand = hmac(&prk, &[RELEASE_INFO, &[1u8]].concat());
            let by_ring = wrap_key(shared, &run_key, &host_key).unwrap();
            assert_eq!(by_hand, *by_ring);
        })
        .unwrap();
    }

    #[test]
    fn base64_is_url_safe_without_padding_and_canonical() {
        let key = new_key().unwrap();
        let text = encode_key(&key);
        assert_eq!(text.len(), 43);
        assert!(!text.contains(['+', '/', '=']));
        assert_eq!(*decode_key(&text).unwrap(), *key);
        assert!(decode_key(&format!("{}=", text.as_str())).is_err());
        assert!(decode_key(&text[..42]).is_err());
        assert!(decode_key("").is_err());
        assert!(decode_array::<12>(&encode_b64(&[1u8; 12])).is_ok());
        assert!(decode_array::<12>(&encode_b64(&[1u8; 13])).is_err());
        assert!(decode_b64(&"A".repeat(10_000), 100).is_err());
        assert!(decode_b64("+/+/", 10).is_err());
    }
}
