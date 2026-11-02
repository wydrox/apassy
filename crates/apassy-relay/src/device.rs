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
