//! The cryptography of relay sync (contract relay-sync-v1, sections 2, 5, 7.3, and 8).
//!
//! This file calls `ring` and implements no primitive. It holds the device key, builds
//! and parses the signed head, builds the sign-in message, and computes the safety
//! words. The app and the relay build exactly the same bytes; the test vectors of the
//! contract (section 15) check that.
//!
//! The head is three ASCII lines joined with `\n`, with no trailing newline. The parser
//! accepts only the exact grammar of section 8.1, so one head has one text and one hash.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use zeroize::Zeroizing;

use super::SyncError;
use crate::companion::crypto::{hex, sha256, verify_ecdsa};
use crate::native::base64::{decode_url, encode_url};
use crate::vault::VaultErrorKind;

/// The first line of a head.
pub const HEAD_TAG: &str = "apassy-relay-sync-head-v1";
/// The first part of the sign-in message.
pub const SIGN_IN_TAG: &str = "apassy-relay sign-in v1";
/// The first part of the safety message.
pub const SAFETY_TAG: &str = "apassy-relay safety v1";
/// The largest snapshot: 64 MiB.
pub const MAX_SNAPSHOT_BYTES: u64 = 67_108_864;
/// The `previous` of the first head: 64 zeros.
pub const NO_PREVIOUS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// A head text in the `X-Apassy-Sync-Head` header has at most this many b64u characters.
pub const MAX_HEAD_B64U: usize = 512;
/// A signature in the `X-Apassy-Sync-Signature` header has at most this many characters.
pub const MAX_SIGNATURE_B64U: usize = 96;

/// b64u: base64url without padding (contract section 2).
pub fn encode_b64u(bytes: &[u8]) -> String {
    encode_url(bytes)
}

/// Strict b64u decode: no padding, no character outside the URL alphabet, and only the
/// canonical text of each byte string.
pub fn decode_b64u(text: &str) -> Option<Vec<u8>> {
    decode_url(text)
}

/// Lowercase hexadecimal SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

/// Whether `text` is 64 lowercase hexadecimal characters.
pub fn is_hash_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The 32 bytes of a hash in lowercase hexadecimal, or `None`.
pub fn hash_from_hex(text: &str) -> Option<[u8; 32]> {
    if !is_hash_hex(text) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            _ => byte - b'a' + 10,
        };
        out[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Some(out)
}

/// A team id: `t_` and 10 characters of `a-z2-7` (contract section 2, the relay's rule).
pub fn valid_team_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 12
        && bytes.starts_with(b"t_")
        && bytes[2..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(byte))
}

/// A vault id: a UUID of 36 lowercase characters, `8-4-4-4-12`.
pub fn valid_vault_id(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

/// A link code: `apassy_lnk_<team id>_<64 hex>`. Returns the team id.
pub fn link_code_team(code: &str) -> Option<&str> {
    let rest = code.strip_prefix("apassy_lnk_")?;
    let (team, secret) = (rest.get(..12)?, rest.get(12..)?);
    let secret = secret.strip_prefix('_')?;
    (valid_team_id(team) && is_hash_hex(secret)).then_some(team)
}

/// A team code from the operator: `apassy_tcd_<64 hex>`.
pub fn valid_team_code(code: &str) -> bool {
    code.strip_prefix("apassy_tcd_").is_some_and(is_hash_hex)
}

/// A decimal number with no leading zero (or `0` itself when `zero` is allowed).
fn parse_decimal(text: &str, zero: bool, max_digits: usize) -> Option<u64> {
    let valid = !text.is_empty()
        && text.len() <= max_digits
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (!text.starts_with('0') || (zero && text == "0"));
    if valid { text.parse().ok() } else { None }
}

/// The P-256 key of this Mac on the relay (contract section 2). Debug is redacted.
pub struct DeviceKey {
    secret: KeySecret,
    public: Vec<u8>,
}

enum KeySecret {
    /// The PKCS#8 document of `ring`, as the vault keeps it.
    Pkcs8(Zeroizing<Vec<u8>>),
    /// A raw private scalar. The test vectors of the contract use it.
    Raw(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKey")
            .field("public_key", &encode_url(&self.public))
            .field("secret", &"[redacted]")
            .finish()
    }
}

fn key_error() -> SyncError {
    SyncError::Vault(VaultErrorKind::Storage)
}

impl DeviceKey {
    /// A new key from the system random source.
    pub fn generate() -> Result<Self, SyncError> {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| key_error())?;
        Self::from_pkcs8(Zeroizing::new(document.as_ref().to_vec()))
    }

    /// The key of a PKCS#8 document of `ring`.
    pub fn from_pkcs8(document: Zeroizing<Vec<u8>>) -> Result<Self, SyncError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &document, &rng)
            .map_err(|_| key_error())?;
        let public = pair.public_key().as_ref().to_vec();
        Ok(Self {
            secret: KeySecret::Pkcs8(document),
            public,
        })
    }

    /// The key of a raw 32-byte private scalar and its X9.63 public point, as the test
    /// vectors give it.
    pub fn from_raw(private: &[u8], public: &[u8]) -> Result<Self, SyncError> {
        let rng = SystemRandom::new();
        EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            private,
            public,
            &rng,
        )
        .map_err(|_| key_error())?;
        Ok(Self {
            secret: KeySecret::Raw(Zeroizing::new(private.to_vec())),
            public: public.to_vec(),
        })
    }

    /// The PKCS#8 document, for the vault. `None` for a raw key.
    pub fn pkcs8(&self) -> Option<&Zeroizing<Vec<u8>>> {
        match &self.secret {
            KeySecret::Pkcs8(document) => Some(document),
            KeySecret::Raw(_) => None,
        }
    }

    /// The public key, X9.63 (65 bytes).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// The public key as b64u, as the wire carries it.
    pub fn public_key_b64u(&self) -> String {
        encode_url(&self.public)
    }

    /// An ECDSA P-256 SHA-256 signature over `message`, DER. A new signature of the
    /// same message differs: ECDSA is randomized.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SyncError> {
        let rng = SystemRandom::new();
        let pair = match &self.secret {
            KeySecret::Pkcs8(document) => {
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document, &rng)
            }
            KeySecret::Raw(private) => EcdsaKeyPair::from_private_key_and_public_key(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                private,
                &self.public,
                &rng,
            ),
        }
        .map_err(|_| key_error())?;
        pair.sign(&rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| key_error())
    }
}

/// Whether `signature` (DER) is a signature of `message` by `public_key` (X9.63).
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_ecdsa(public_key, message, signature)
}

/// The fields of a head (contract section 8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadFields {
    /// The vault id of `sync_meta.vault_id`.
    pub vault_id: String,
    /// The version: the current version on the relay plus one.
    pub version: u64,
    /// Lowercase hexadecimal SHA-256 of the snapshot bytes.
    pub snapshot_sha256: String,
    /// The number of snapshot bytes.
    pub size: u64,
    /// The head hash of the previous head, or [`NO_PREVIOUS`].
    pub previous: String,
    /// The team of the pushing device.
    pub team_id: String,
    /// The device number of the pushing device.
    pub device_id: u64,
    /// Unix seconds of the pushing Mac. Informational.
    pub time: u64,
}

impl HeadFields {
    /// Whether the fields fit the grammar, so that [`Self::text`] parses back.
    pub fn is_valid(&self) -> bool {
        valid_vault_id(&self.vault_id)
            && self.version >= 1
            && is_hash_hex(&self.snapshot_sha256)
            && (1..=MAX_SNAPSHOT_BYTES).contains(&self.size)
            && is_hash_hex(&self.previous)
            && valid_team_id(&self.team_id)
            && self.device_id >= 1
            && self.time < 1_000_000_000_000
    }

    /// The head text: three lines joined with `\n`, no trailing newline.
    pub fn text(&self) -> String {
        format!(
            "{HEAD_TAG}\n{} {} {} {}\n{} {}/{} {}",
            self.vault_id,
            self.version,
            self.snapshot_sha256,
            self.size,
            self.previous,
            self.team_id,
            self.device_id,
            self.time
        )
    }

    /// Parse a head text. `None` for any text outside the grammar of section 8.1.
    pub fn parse(text: &str) -> Option<Self> {
        if !text.is_ascii() || text.contains('\r') {
            return None;
        }
        let mut lines = text.split('\n');
        let (tag, second, third) = (lines.next()?, lines.next()?, lines.next()?);
        if tag != HEAD_TAG || lines.next().is_some() {
            return None;
        }
        let second: Vec<&str> = second.split(' ').collect();
        let third: Vec<&str> = third.split(' ').collect();
        let ([vault_id, version, snapshot_sha256, size], [previous, device, time]) =
            (second.as_slice(), third.as_slice())
        else {
            return None;
        };
        let (team_id, device_number) = device.split_once('/')?;
        let fields = Self {
            vault_id: (*vault_id).to_owned(),
            version: parse_decimal(version, false, 20)?,
            snapshot_sha256: (*snapshot_sha256).to_owned(),
            size: parse_decimal(size, false, 8)?,
            previous: (*previous).to_owned(),
            team_id: team_id.to_owned(),
            device_id: parse_decimal(device_number, false, 20)?,
            time: parse_decimal(time, true, 12)?,
        };
        (fields.is_valid() && fields.text() == text).then_some(fields)
    }
}

/// The head hash: lowercase hexadecimal SHA-256 of the head text.
pub fn head_hash(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

/// A head with its signature. The signature is not checked yet: see
/// [`SignedHead::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    pub fields: HeadFields,
    /// The exact head text.
    pub text: String,
    /// The DER signature.
    pub signature: Vec<u8>,
}

impl SignedHead {
    /// Sign the head of `fields` with `key`.
    pub fn sign(fields: HeadFields, key: &DeviceKey) -> Result<Self, SyncError> {
        if !fields.is_valid() {
            return Err(SyncError::Damaged);
        }
        let text = fields.text();
        let signature = key.sign(text.as_bytes())?;
        Ok(Self {
            fields,
            text,
            signature,
        })
    }

    /// A head from the two b64u values of the wire (the headers, or the JSON fields
    /// `head` and `signature`). `None` when a value or the text is malformed.
    pub fn from_wire(head_b64u: &str, signature_b64u: &str) -> Option<Self> {
        if head_b64u.len() > MAX_HEAD_B64U || signature_b64u.len() > MAX_SIGNATURE_B64U {
            return None;
        }
        let text = String::from_utf8(decode_url(head_b64u)?).ok()?;
        let signature = decode_url(signature_b64u)?;
        if signature.is_empty() || signature.len() > 72 {
            return None;
        }
        let fields = HeadFields::parse(&text)?;
        Some(Self {
            fields,
            text,
            signature,
        })
    }

    /// The head hash.
    pub fn hash(&self) -> String {
        head_hash(&self.text)
    }

    /// The value of `X-Apassy-Sync-Head`.
    pub fn head_b64u(&self) -> String {
        encode_url(self.text.as_bytes())
    }

    /// The value of `X-Apassy-Sync-Signature`.
    pub fn signature_b64u(&self) -> String {
        encode_url(&self.signature)
    }

    /// Whether the signature verifies with `public_key`.
    pub fn verify(&self, public_key: &[u8]) -> bool {
        verify_ecdsa(public_key, self.text.as_bytes(), &self.signature)
    }
}

/// The sign-in message (contract section 5): the parts joined with `\0`.
pub fn sign_in_message(
    origin: &str,
    team_id: &str,
    public_key_b64u: &str,
    nonce_b64u: &str,
) -> Vec<u8> {
    [SIGN_IN_TAG, origin, team_id, public_key_b64u, nonce_b64u]
        .join("\0")
        .into_bytes()
}

/// The safety words of a device link (contract section 7.3): two words of [`WORDS`].
pub fn safety_words(team_id: &str, link_code: &str, public_key: &[u8]) -> String {
    let mut message = Vec::new();
    for part in [
        SAFETY_TAG.as_bytes(),
        team_id.as_bytes(),
        link_code.as_bytes(),
    ] {
        message.extend_from_slice(part);
        message.push(0);
    }
    message.extend_from_slice(public_key);
    let digest = sha256(&message);
    format!(
        "{} {}",
        WORDS[usize::from(digest[0])],
        WORDS[usize::from(digest[1])]
    )
}

/// Whether two texts name the same safety words. Case and surrounding spaces do not
/// count.
pub fn same_words(a: &str, b: &str) -> bool {
    let words =
        |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_lowercase).collect() };
    words(a) == words(b) && words(a).len() == 2
}

/// The 256 words of the safety words, in index order (contract section 16).
pub const WORDS: [&str; 256] = [
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

    const PRIVATE: &str = "4f2d9c6e1b3a7d8f0c5e2a9b7f4d1c3e6a8b0d2f4c6e8a1b3d5f7a9c0e2b4d6f";
    const PUBLIC: &str = "04ea47901e55bd31d76b0a545d9c60bb8e10f7b2366f3abd1bfb88ead14cf668fc0ded38eded5f35623c3081110ec6b18410b48a1d433df5da33899d05b1318eb0";
    const PUBLIC_B64U: &str =
        "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";
    const VAULT_ID: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
    const TEAM: &str = "t_7k2m5q4x3c";
    const HEAD_1_HASH: &str = "d562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9";
    const HEAD_2_HASH: &str = "2a3d34a3454acf98a897115ed30e8ea195852d7e943c780974c1f2489810cc3c";
    const HEAD_1_B64U: &str = "YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMSA1Yjc3MzQzYmQ4ODFhNGY0MjViZGUxZWM5OTc5OTQ2ZWMxYWRkMTFkZTAyMDEwZDRjNjMxNTk5NzdiYWM0ZGU4IDE4CjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgdF83azJtNXE0eDNjLzIgMTc5MDAwMDAwMA";
    const HEAD_2_B64U: &str = "YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMiA3ZGQ5MWFiMjFiMzBkZjEyYTk0M2M1MDdkNmU3ZDgwOGY2ZWEyNjA4ZmFhMzIzOWFhN2ZlZDYyMWVjYWUyNDFhIDIwCmQ1NjJhNGM5OTUxYWMzNmIyMTFlZDk3ODZhNjg5N2YxNjg3MDYzOWM1NGRmOWQxNjhjNTZjMzlkNGNlMzg3ZDkgdF83azJtNXE0eDNjLzIgMTc5MDAwMDA2MA";
    const SIGNATURE_1: &str = "MEUCIHD6Ih2lhM6u-hBJFTF2urGCw1UeM8vL3oM2mIDm0MvgAiEAxXcwrQRcPb0WAAgj4tylCij4Qxlbu7jISfCuxGIJDHA";
    const SIGNATURE_2: &str = "MEUCIQDpxvOaoLg8rz7vXW0U0xd6lGyttG8CeaRV76DrHTChYgIgIpwTtg1Z-BqkmTw1uDnO8FHS_YddNgbMPCWJP8KKa-g";
    const SIGN_IN_SIGNATURE: &str = "MEUCIAyr22ugUYumzN6x8ktWI1ruvFmEVjktZGhAfa7dRmeXAiEAiHEWtFJmR5giJlad5O0jy9dVkHD3IAKRM3TZRXzwJEY";
    const LINK_CODE: &str =
        "apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab";

    fn bytes_of_hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn head_1() -> HeadFields {
        HeadFields {
            vault_id: VAULT_ID.to_owned(),
            version: 1,
            snapshot_sha256: sha256_hex(b"synthetic snapshot"),
            size: 18,
            previous: NO_PREVIOUS.to_owned(),
            team_id: TEAM.to_owned(),
            device_id: 2,
            time: 1_790_000_000,
        }
    }

    fn head_2() -> HeadFields {
        HeadFields {
            version: 2,
            snapshot_sha256: sha256_hex(b"synthetic snapshot 2"),
            size: 20,
            previous: HEAD_1_HASH.to_owned(),
            time: 1_790_000_060,
            ..head_1()
        }
    }

    #[test]
    fn the_vector_key_and_snapshots_match() {
        let key = DeviceKey::from_raw(&bytes_of_hex(PRIVATE), &bytes_of_hex(PUBLIC)).unwrap();
        assert_eq!(key.public_key_b64u(), PUBLIC_B64U);
        assert!(key.pkcs8().is_none());
        assert!(!format!("{key:?}").contains(PRIVATE));
        assert_eq!(
            sha256_hex(b"synthetic snapshot"),
            "5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8"
        );
        assert_eq!(
            sha256_hex(b"synthetic snapshot 2"),
            "7dd91ab21b30df12a943c507d6e7d808f6ea2608faa3239aa7fed621ecae241a"
        );
    }

    #[test]
    fn the_vector_heads_have_their_text_hash_and_signature() {
        let one = head_1();
        assert_eq!(one.text().len(), 223);
        assert_eq!(head_hash(&one.text()), HEAD_1_HASH);
        assert_eq!(encode_url(one.text().as_bytes()), HEAD_1_B64U);
        assert_eq!(head_hash(&head_2().text()), HEAD_2_HASH);
        assert_eq!(encode_url(head_2().text().as_bytes()), HEAD_2_B64U);
        let public = bytes_of_hex(PUBLIC);
        for (b64u, signature, fields) in [
            (HEAD_1_B64U, SIGNATURE_1, head_1()),
            (HEAD_2_B64U, SIGNATURE_2, head_2()),
        ] {
            let head = SignedHead::from_wire(b64u, signature).expect("vector head");
            assert_eq!(head.fields, fields);
            assert!(head.verify(&public));
            // One changed character of the text fails.
            let mut changed = head.clone();
            changed.text = changed.text.replacen("t_7k2m5q4x3c/2", "t_7k2m5q4x3c/3", 1);
            assert!(!changed.verify(&public));
            // Another key fails.
            let other = DeviceKey::generate().unwrap();
            assert!(!head.verify(other.public_key()));
        }
        // A new signature of the same text differs and still verifies.
        let key = DeviceKey::from_raw(&bytes_of_hex(PRIVATE), &public).unwrap();
        let fresh = SignedHead::sign(head_1(), &key).unwrap();
        assert_ne!(fresh.signature_b64u(), SIGNATURE_1);
        assert!(fresh.verify(&public));
        assert_eq!(fresh.head_b64u(), HEAD_1_B64U);
    }

    #[test]
    fn the_vector_sign_in_message_and_safety_words() {
        let nonce: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            encode_url(&nonce),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        let message = sign_in_message(
            "https://relay.example.test",
            TEAM,
            PUBLIC_B64U,
            &encode_url(&nonce),
        );
        assert_eq!(
            sha256_hex(&message),
            "43722057f746ba2b1759952943e9532ad49c68496c11a6f1bef65709c20e7aaa"
        );
        let public = bytes_of_hex(PUBLIC);
        assert!(verify_signature(
            &public,
            &message,
            &decode_url(SIGN_IN_SIGNATURE).unwrap()
        ));
        let mut safety = Vec::new();
        for part in [SAFETY_TAG, TEAM, LINK_CODE] {
            safety.extend_from_slice(part.as_bytes());
            safety.push(0);
        }
        safety.extend_from_slice(&public);
        assert_eq!(
            sha256_hex(&safety),
            "fc0f67b7df128c3d82fae26d0b646d9bcd3623adcb562f7d85d313f7456a3b7c"
        );
        assert_eq!(safety_words(TEAM, LINK_CODE, &public), "tulip arrow");
        assert!(same_words("  Marble KAYAK ", "marble kayak"));
        assert!(!same_words("marble", "marble"));
        assert!(!same_words("marble kayak", "kayak marble"));
    }

    #[test]
    fn the_word_list_has_256_different_words() {
        let mut sorted = WORDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 256);
        // Contract section 16: the words of the examples, and of the vector (0xfc, 0x0f).
        assert_eq!(WORDS[174], "marble");
        assert_eq!(WORDS[156], "kayak");
        assert_eq!(WORDS[252], "tulip");
        assert_eq!(WORDS[15], "arrow");
    }

    #[test]
    fn the_head_grammar_is_exact() {
        let text = head_1().text();
        assert!(HeadFields::parse(&text).is_some());
        for bad in [
            format!("{text}\n"),
            text.replace('\n', "\r\n"),
            text.replacen(" 1 ", " 01 ", 1),
            text.replacen(" 18\n", " 018\n", 1),
            text.replacen(" 18\n", " 0\n", 1),
            text.replacen(" 18\n", " 67108865\n", 1),
            text.replacen(" 18\n", "  18\n", 1),
            text.replacen("0f3c2a10", "0F3C2A10", 1),
            text.replacen("t_7k2m5q4x3c/2", "t_7k2m5q4x3c/0", 1),
            text.replacen("t_7k2m5q4x3c/2", "t_7k2m5q4x3c", 1),
            text.replacen("t_7k2m5q4x3c/2", "t_7k2m9q4x8c/2", 1),
            text.replacen(" 1790000000", " 1790000000000", 1),
            text.replacen(HEAD_TAG, "apassy-relay-sync-head-v2", 1),
            text.replacen("5b77", "5B77", 1),
        ] {
            assert!(HeadFields::parse(&bad).is_none(), "{bad:?}");
        }
        let mut max = head_1();
        max.size = MAX_SNAPSHOT_BYTES;
        assert!(HeadFields::parse(&max.text()).is_some());
        assert!(SignedHead::from_wire(&"A".repeat(513), SIGNATURE_1).is_none());
    }

    #[test]
    fn codes_and_ids_have_their_shape() {
        assert_eq!(link_code_team(LINK_CODE), Some(TEAM));
        assert_eq!(link_code_team("apassy_lnk_t_7k2m5q4x3c_abab"), None);
        assert_eq!(link_code_team("apassy_tcd_t_7k2m5q4x3c_ab"), None);
        assert!(valid_team_code(&format!("apassy_tcd_{}", "0".repeat(64))));
        assert!(!valid_team_code(&format!("apassy_tcd_{}", "G".repeat(64))));
        assert!(valid_team_id(TEAM));
        assert!(valid_team_id("t_abcdefgh23"));
        // The relay's alphabet: a-z and 2-7, no 0, 1, 8, or 9.
        assert!(!valid_team_id("t_7k2m9q4x8c"));
        assert!(!valid_team_id("t_7k2m5q4x0c"));
        assert!(!valid_team_id("t_7k2m5q4x3"));
        assert!(!valid_team_id("t_7K2M5Q4X3C"));
        assert!(!valid_team_id("t_7k2m5q4x3_"));
        assert_eq!(
            hash_from_hex(HEAD_1_HASH)
                .map(|bytes| hex(&bytes))
                .as_deref(),
            Some(HEAD_1_HASH)
        );
        let key = DeviceKey::generate().unwrap();
        let again = DeviceKey::from_pkcs8(key.pkcs8().unwrap().clone()).unwrap();
        assert_eq!(key.public_key(), again.public_key());
        let signature = again.sign(b"synthetic").unwrap();
        assert!(verify_signature(key.public_key(), b"synthetic", &signature));
    }
}
