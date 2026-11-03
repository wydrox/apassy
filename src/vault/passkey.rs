//! Passkeys (schema 17, schema 25): one WebAuthn credential on a login item.
//!
//! A passkey is a set of reserved fields on a login item. They sync in the encrypted
//! `item_field` rows like each other field:
//!
//! - `passkey_format`: the algorithm and the form of the key (schema 25 adds the last
//!   three):
//!   - `es256-pkcs8-v1`: ES256 (COSE -7), a P-256 key, PKCS #8 v1 with the public point.
//!   - `es384-pkcs8-v1`: ES384 (COSE -35), a P-384 key, PKCS #8 v1 with the public point.
//!   - `ed25519-pkcs8-v1`: EdDSA (COSE -8), an Ed25519 key, PKCS #8 v2 with the public
//!     key (RFC 8410, the form that `ring` makes).
//!   - `rs256-pkcs8-v1`: RS256 (COSE -257), an RSA key of 2048 to 4096 bits, PKCS #8 v1
//!     with `rsaEncryption` and a NULL parameter, and no attributes.
//! - `passkey_rp_id`: the relying party ID.
//! - `passkey_credential_id`, `passkey_user_handle`: base64url without padding.
//! - `passkey_user_name`, `passkey_user_display_name`: text.
//! - `passkey_key` (secret): the private key in the form of its format, base64url without
//!   padding.
//!
//! Optional fields (schema 25), from Credential Exchange or a largeBlob write:
//!
//! - `passkey_prf_uv`, `passkey_prf_no_uv` (secret, both or neither): the two 32-byte
//!   CredRandom values of the PRF extension (CTAP hmac-secret), base64url without
//!   padding. An assertion always has user verification, so only `passkey_prf_uv`
//!   makes PRF outputs. `passkey_prf_no_uv` is kept for an export.
//! - `passkey_large_blob` (secret) and `passkey_large_blob_size` (plain, both or
//!   neither): the large blob as CTAP and Credential Exchange keep it, raw DEFLATE data
//!   (RFC 1951) in base64url without padding, and its uncompressed size in decimal.
//!
//! An optional field with a bad value (a wrong length, a bad encoding, one of a pair)
//! counts as absent: the passkey still signs, and it has no PRF output or no large blob.
//! A bad key or a bad required field always makes the whole passkey invalid.
//!
//! Each format has one normalized key form, and a stored key must be in it. An import
//! detects the algorithm from the PKCS #8 `AlgorithmIdentifier` (and the named curve of
//! an EC key). An RSA key is taken as RS256 (RSASSA-PKCS1-v1_5 with SHA-256): PKCS #8
//! does not say which RSA signature scheme the relying party chose, and RS256 is the
//! RSA algorithm of WebAuthn. P-521 and other algorithms are refused (`BadKey`). A new
//! passkey of this vault is always ES256.
//!
//! Only this module writes them. Generic add and update refuse them, details and reveal
//! hide them, and update keeps them. Only [`Vault::export_passkey`] returns the private
//! key and the extension secrets, for an owner-approved transfer to another provider
//! (Credential Exchange).
//!
//! The raw functions are for the owner only. The platform layer (the iPhone credential
//! provider, the browser bridge) does a fresh owner verification before each create and
//! each assertion, so the authenticator data sets user presence and user verification.
//! The signature counter is always zero, as for each synced credential.
//!
//! Backup flags. The credential is in an encrypted vault that syncs and that the owner
//! can export, so it is backup eligible (BE). Each registration and each assertion also
//! sets backup state (BS), on each route: the macOS and iPhone credential providers and
//! the browser extension. BS is a provider policy, not a proof: this module cannot see
//! if a copy with the credential is on another device. The system credential provider
//! API requires BE and BS together; macOS refuses a new passkey without BS ("AuthData is
//! missing a required flag"). One value on each route keeps the flags of a credential
//! the same for a relying party.
//!
//! A passkey made before this policy (BE without BS) now signs with BS. WebAuthn lets
//! BS change while BE stays, and a relying party updates its stored BS. The flags are
//! not stored, so nothing in the vault changes.
//!
//! A sync conflict can keep a passkey only in a conflict copy: device A adds a passkey
//! to a login, and a later edit of device B without it wins. A merge archives each
//! conflict copy, and an archived item never signs. The owner can restore the copy.
//! A normal item (an item that is not a conflict copy) always has priority:
//!
//! - When a normal item has the credential, active or archived, no conflict copy signs
//!   or exports it.
//! - When no normal item has the credential, a restored conflict copy can sign and
//!   export it. The original of the copy can be deleted or can be another copy.
//!
//! Each credential has one canonical item at most: the active item with the lowest ID.
//! A new or imported passkey never goes on a conflict copy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Write};

use ciborium::value::Value;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use ring::{digest, hmac};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use crate::contracts::CredentialKind;

use super::history::{self, EditChange, ItemEventKind};
use super::types::{
    Field, ItemDraft, MAX_FIELD_VALUE_BYTES, PASSKEY_FIELD_PREFIX, SecretValue, VaultError,
    VaultErrorKind, VaultResult, err, kind_as_str, validate_draft_with,
};
use super::{Vault, insert_fields, to_hex, to_public_id, to_sql_id, to_sql_revision};

/// The value of `passkey_format` of an ES256 passkey.
pub const PASSKEY_FORMAT: &str = "es256-pkcs8-v1";
/// The value of `passkey_format` of an ES384 passkey (schema 25).
pub const PASSKEY_FORMAT_ES384: &str = "es384-pkcs8-v1";
/// The value of `passkey_format` of an EdDSA (Ed25519) passkey (schema 25).
pub const PASSKEY_FORMAT_ED25519: &str = "ed25519-pkcs8-v1";
/// The value of `passkey_format` of an RS256 passkey (schema 25).
pub const PASSKEY_FORMAT_RS256: &str = "rs256-pkcs8-v1";
/// COSE algorithm ES256: ECDSA with P-256 and SHA-256.
pub const ES256: i64 = -7;
/// COSE algorithm ES384: ECDSA with P-384 and SHA-384.
pub const ES384: i64 = -35;
/// COSE algorithm EdDSA, here always Ed25519.
pub const EDDSA: i64 = -8;
/// COSE algorithm RS256: RSASSA-PKCS1-v1_5 with SHA-256.
pub const RS256: i64 = -257;
/// The largest uncompressed large blob, in bytes.
pub const MAX_LARGE_BLOB_BYTES: usize = 65_536;
/// The length of a PRF secret (CredRandom), of a PRF salt, and of a PRF output.
pub const PRF_BYTES: usize = 32;
/// The longest credential ID (WebAuthn: 1023 bytes).
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
/// The longest user handle (WebAuthn: 64 bytes).
pub const MAX_USER_HANDLE_BYTES: usize = 64;
/// The longest relying party ID (a DNS name).
pub const MAX_RP_ID_BYTES: usize = 253;
/// User name and display name are cut to this length, at a character boundary. WebAuthn
/// lets an authenticator cut them (to 64 bytes or more).
pub const MAX_USER_TEXT_BYTES: usize = 256;
/// The length of a new credential ID.
pub const NEW_CREDENTIAL_ID_BYTES: usize = 32;

const FIELD_FORMAT: &str = "passkey_format";
const FIELD_RP_ID: &str = "passkey_rp_id";
const FIELD_CREDENTIAL_ID: &str = "passkey_credential_id";
const FIELD_USER_HANDLE: &str = "passkey_user_handle";
const FIELD_USER_NAME: &str = "passkey_user_name";
const FIELD_USER_DISPLAY_NAME: &str = "passkey_user_display_name";
const FIELD_KEY: &str = "passkey_key";
const FIELD_PRF_UV: &str = "passkey_prf_uv";
const FIELD_PRF_NO_UV: &str = "passkey_prf_no_uv";
const FIELD_LARGE_BLOB: &str = "passkey_large_blob";
const FIELD_LARGE_BLOB_SIZE: &str = "passkey_large_blob_size";

/// The context of a PRF salt (WebAuthn PRF extension): `"WebAuthn PRF"` and a zero byte.
const PRF_CONTEXT: &[u8] = b"WebAuthn PRF\0";

/// The detail name prefix of a custom label (see `access::custom_detail_label`).
const DETAIL_PREFIX: &str = "x_";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
/// UP, UV, BE, BS (see the module documentation). A registration adds AT.
const ASSERTION_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;

/// PKCS #8 v1 of a P-256 key, up to the private scalar: the form that `ring` makes, with
/// no `parameters` in `ECPrivateKey` (RFC 5958, RFC 5915).
const PKCS8_PREFIX: [u8; 36] = [
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20,
];
/// `[1]` public key, a BIT STRING of the 65-byte point.
const PKCS8_PUBLIC_PREFIX: [u8; 5] = [0xa1, 0x44, 0x03, 0x42, 0x00];
const PKCS8_BYTES: usize = 138;
/// SubjectPublicKeyInfo of a P-256 key, up to the point (RFC 5480).
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// PKCS #8 v1 of a P-384 key, up to the private scalar: the form that `ring` makes.
const PKCS8_P384_PREFIX: [u8; 35] = [
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01,
    0x01, 0x04, 0x30,
];
/// `[1]` public key, a BIT STRING of the 97-byte point.
const PKCS8_P384_PUBLIC_PREFIX: [u8; 5] = [0xa1, 0x64, 0x03, 0x62, 0x00];
/// PKCS #8 v2 of an Ed25519 key, up to the 32-byte seed (RFC 8410): the form that
/// `ring` makes.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// `[1] IMPLICIT` public key, a BIT STRING of the 32-byte key.
const PKCS8_ED25519_PUBLIC_PREFIX: [u8; 3] = [0x81, 0x21, 0x00];
const PKCS8_ED25519_BYTES: usize = 83;
/// The `AlgorithmIdentifier` of an RSA key in PKCS #8: `rsaEncryption` and NULL.
const RSA_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// Object identifiers (DER content) of the key algorithms and the named curves.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// The key algorithm of a passkey: its COSE algorithm, its format, and its key form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAlgorithm {
    Es256,
    Es384,
    Ed25519,
    Rs256,
}

impl KeyAlgorithm {
    fn cose(self) -> i64 {
        match self {
            Self::Es256 => ES256,
            Self::Es384 => ES384,
            Self::Ed25519 => EDDSA,
            Self::Rs256 => RS256,
        }
    }

    fn format(self) -> &'static str {
        match self {
            Self::Es256 => PASSKEY_FORMAT,
            Self::Es384 => PASSKEY_FORMAT_ES384,
            Self::Ed25519 => PASSKEY_FORMAT_ED25519,
            Self::Rs256 => PASSKEY_FORMAT_RS256,
        }
    }

    fn from_format(format: &str) -> Option<Self> {
        [Self::Es256, Self::Es384, Self::Ed25519, Self::Rs256]
            .into_iter()
            .find(|algorithm| algorithm.format() == format)
    }
}

/// The form of a normalized EC key of one curve.
struct EcForm {
    signing: &'static EcdsaSigningAlgorithm,
    prefix: &'static [u8],
    public_prefix: &'static [u8],
    scalar_bytes: usize,
    point_bytes: usize,
}

static P256_FORM: EcForm = EcForm {
    signing: &ECDSA_P256_SHA256_ASN1_SIGNING,
    prefix: &PKCS8_PREFIX,
    public_prefix: &PKCS8_PUBLIC_PREFIX,
    scalar_bytes: 32,
    point_bytes: 65,
};

static P384_FORM: EcForm = EcForm {
    signing: &ECDSA_P384_SHA384_ASN1_SIGNING,
    prefix: &PKCS8_P384_PREFIX,
    public_prefix: &PKCS8_P384_PUBLIC_PREFIX,
    scalar_bytes: 48,
    point_bytes: 97,
};

/// The detail of the [`ItemEventKind::Revealed`] event of [`Vault::record_export`]. The
/// export is only prepared: the event does not prove that the recipient took it.
pub const EXPORT_DETAIL: &str = "Credential Exchange export prepared";

/// Schema version 17: the passkey fields. A field of an earlier version with a reserved
/// name is an ordinary field of the owner, so it gets another name.
const SCHEMA_V17_SQL: &str = "
UPDATE vault_meta SET schema_version = 17 WHERE id = 1;
PRAGMA user_version = 17;
";

/// A passkey without its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    pub item_id: u64,
    pub title: String,
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

/// Where a new passkey goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyTarget {
    /// A new login item with this title.
    NewItem { title: String },
    /// An existing login item without a passkey, at this revision.
    Attach { item_id: u64, revision: u64 },
}

/// A registration request (WebAuthn authenticatorMakeCredential). The caller did a fresh
/// owner verification for it.
#[derive(Debug, Clone)]
pub struct PasskeyCreate<'a> {
    pub rp_id: &'a str,
    pub user_handle: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub client_data_hash: &'a [u8; 32],
    /// COSE algorithms in the order of the relying party. An empty list means the
    /// WebAuthn defaults, which include ES256.
    pub algorithms: &'a [i64],
    /// Credential IDs that the relying party already has for the user.
    pub exclude: &'a [Vec<u8>],
    pub target: PasskeyTarget,
}

/// The result of a registration, with "none" attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCreated {
    pub item_id: u64,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// DER SubjectPublicKeyInfo.
    pub public_key_spki: Vec<u8>,
    pub algorithm: i64,
}

/// The PRF inputs of an assertion (WebAuthn PRF extension, CTAP hmac-secret). With
/// `hashed: false` the inputs are the WebAuthn values, and the vault makes each salt:
/// SHA-256 of `"WebAuthn PRF"`, a zero byte, and the input. With `hashed: true` the
/// inputs are the 32-byte salts already (the form of the macOS and iOS credential
/// provider APIs). Debug shows only the lengths.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyPrfInput {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
    pub hashed: bool,
}

impl fmt::Debug for PasskeyPrfInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyPrfInput")
            .field("first", &self.first.len())
            .field("second", &self.second.as_ref().map(Vec::len))
            .field("hashed", &self.hashed)
            .finish()
    }
}

/// The largeBlob operation of an assertion. `Write` has the uncompressed blob. Debug
/// shows only the length.
#[derive(Clone, PartialEq, Eq)]
pub enum LargeBlobOp {
    Read,
    Write(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for LargeBlobOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("Read"),
            Self::Write(blob) => f.debug_tuple("Write").field(&blob.len()).finish(),
        }
    }
}

/// The WebAuthn extensions of an assertion. The default asks for none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasskeyAssertionExtensions {
    pub prf: Option<PasskeyPrfInput>,
    pub large_blob: Option<LargeBlobOp>,
}

/// The PRF outputs of an assertion: HMAC-SHA-256 of each salt with the secret with user
/// verification. Debug does not show them; drop erases them.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyPrfOutput {
    pub first: Zeroizing<[u8; PRF_BYTES]>,
    pub second: Option<Zeroizing<[u8; PRF_BYTES]>>,
}

impl fmt::Debug for PasskeyPrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyPrfOutput")
            .field("first", &"[redacted]")
            .field("second", &self.second.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// The largeBlob result of an assertion. `Read(None)`: the passkey has no blob, or the
/// stored blob does not inflate to its size. `Written(false)`: the blob is too large, or
/// the vault could not store it. Debug shows only the length.
#[derive(Clone, PartialEq, Eq)]
pub enum LargeBlobResult {
    Read(Option<Zeroizing<Vec<u8>>>),
    Written(bool),
}

impl fmt::Debug for LargeBlobResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(blob) => f
                .debug_tuple("Read")
                .field(&blob.as_ref().map(|blob| blob.len()))
                .finish(),
            Self::Written(written) => f.debug_tuple("Written").field(written).finish(),
        }
    }
}

/// The result of an assertion (WebAuthn authenticatorGetAssertion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// ES256 and ES384: an ASN.1 DER ECDSA signature. EdDSA: the 64-byte Ed25519
    /// signature. RS256: the RSASSA-PKCS1-v1_5 signature, as long as the modulus.
    pub signature: Vec<u8>,
    /// The COSE algorithm of the key: [`ES256`], [`ES384`], [`EDDSA`], or [`RS256`].
    pub algorithm: i64,
    /// The PRF outputs, when the request had PRF inputs and the passkey has PRF secrets.
    pub prf: Option<PasskeyPrfOutput>,
    /// The largeBlob result, when the request had a largeBlob operation.
    pub large_blob: Option<LargeBlobResult>,
}

/// The two CredRandom values of the PRF extension, from Credential Exchange
/// (`credentialWithUV`, `credentialWithoutUV`). Debug does not show them; drop erases
/// them. No `Clone`: each copy is explicit.
pub struct PasskeyPrfSecrets {
    pub with_uv: Zeroizing<[u8; PRF_BYTES]>,
    pub without_uv: Zeroizing<[u8; PRF_BYTES]>,
}

impl fmt::Debug for PasskeyPrfSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyPrfSecrets([redacted])")
    }
}

/// The large blob of a passkey, in the form of CTAP and Credential Exchange: raw DEFLATE
/// data (RFC 1951) and the uncompressed size. Debug shows only the sizes; drop erases the
/// data. No `Clone`.
pub struct PasskeyLargeBlob {
    pub data: Zeroizing<Vec<u8>>,
    pub uncompressed_size: u64,
}

impl fmt::Debug for PasskeyLargeBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyLargeBlob")
            .field("data", &self.data.len())
            .field("uncompressed_size", &self.uncompressed_size)
            .finish()
    }
}

/// A passkey from another provider. `pkcs8` is a P-256, P-384, Ed25519, or RSA PKCS #8
/// key (see the module documentation for the forms that are taken). Debug does not show
/// the key or the extension data.
pub struct PasskeyImport {
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub pkcs8: Zeroizing<Vec<u8>>,
    /// The title of a new item. An empty title becomes the relying party ID.
    pub title: String,
    /// A login item without a passkey that gets the passkey, at its current revision.
    pub attach: Option<u64>,
    /// The PRF secrets of the passkey, when the other provider had them.
    pub prf: Option<PasskeyPrfSecrets>,
    /// The large blob of the passkey, when the other provider had one.
    pub large_blob: Option<PasskeyLargeBlob>,
}

impl fmt::Debug for PasskeyImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyImport")
            .field("rp_id", &self.rp_id)
            .field("credential_id", &self.credential_id)
            .field("user_handle", &self.user_handle)
            .field("user_name", &self.user_name)
            .field("user_display_name", &self.user_display_name)
            .field("pkcs8", &"[redacted]")
            .field("title", &self.title)
            .field("attach", &self.attach)
            .field("prf", &self.prf.as_ref().map(|_| "[redacted]"))
            .field("large_blob", &self.large_blob)
            .finish()
    }
}

/// A passkey with its private key, for an owner-approved transfer to another provider.
/// `pkcs8` is the key in the normalized form of its algorithm (see the module
/// documentation); for ES256 the P-256 PKCS #8 v1 key with the public point, in the form
/// that `ring` makes. Debug does not show the key or the PRF secrets; drop erases them.
/// It has no `Serialize` and no `Clone`, so each copy of the key is explicit.
pub struct PasskeyExport {
    pub info: PasskeyInfo,
    pub pkcs8: Zeroizing<Vec<u8>>,
    /// The COSE algorithm of the key: [`ES256`], [`ES384`], [`EDDSA`], or [`RS256`].
    pub algorithm: i64,
    pub prf: Option<PasskeyPrfSecrets>,
    pub large_blob: Option<PasskeyLargeBlob>,
}

impl fmt::Debug for PasskeyExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyExport")
            .field("info", &self.info)
            .field("pkcs8", &"[redacted]")
            .field("algorithm", &self.algorithm)
            .field("prf", &self.prf.as_ref().map(|_| "[redacted]"))
            .field("large_blob", &self.large_blob)
            .finish()
    }
}

/// A passkey failure. The text does not quote keys or inputs.
#[derive(Debug)]
pub enum PasskeyError {
    Vault(VaultError),
    /// The relying party excluded a credential that the vault has for it.
    Excluded,
    /// The request has no algorithm that the vault supports (ES256 only).
    NoSupportedAlgorithm,
    /// The item has a passkey already, or the vault has this credential.
    Exists,
    /// The private key is not a valid key of a supported algorithm: P-256 or P-384
    /// PKCS #8 v1 with its public point, Ed25519 PKCS #8 v1 or v2, or RSA PKCS #8 v1 of
    /// 2048 to 4096 bits.
    BadKey,
}

impl PasskeyError {
    fn kind(kind: VaultErrorKind) -> Self {
        Self::Vault(err(kind))
    }
}

impl fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(vault) => fmt::Display::fmt(vault, f),
            Self::Excluded => f.write_str("the vault has an excluded credential"),
            Self::NoSupportedAlgorithm => f.write_str("no requested algorithm is supported"),
            Self::Exists => f.write_str("the passkey exists"),
            Self::BadKey => f.write_str("the passkey key is not valid"),
        }
    }
}

impl std::error::Error for PasskeyError {}

impl From<VaultError> for PasskeyError {
    fn from(vault: VaultError) -> Self {
        Self::Vault(vault)
    }
}

type PasskeyResult<T> = Result<T, PasskeyError>;

fn storage<E>(_: E) -> PasskeyError {
    PasskeyError::kind(VaultErrorKind::Storage)
}

fn invalid() -> PasskeyError {
    PasskeyError::kind(VaultErrorKind::InvalidInput)
}

/// A stored passkey. Debug does not show the key or the extension data; drop erases
/// them.
struct StoredPasskey {
    algorithm: KeyAlgorithm,
    rp_id: String,
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    user_name: String,
    user_display_name: String,
    pkcs8: Zeroizing<Vec<u8>>,
    prf: Option<PasskeyPrfSecrets>,
    large_blob: Option<PasskeyLargeBlob>,
}

impl fmt::Debug for StoredPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredPasskey")
            .field("algorithm", &self.algorithm)
            .field("rp_id", &self.rp_id)
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

/// A field of the reserved rows.
fn reserved(name: &str, value: String, secret: bool) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value),
        secret,
    }
}

/// The two rows of a large blob.
fn large_blob_fields(blob: &PasskeyLargeBlob) -> [Field; 2] {
    [
        reserved(FIELD_LARGE_BLOB, b64url_encode(&blob.data), true),
        reserved(
            FIELD_LARGE_BLOB_SIZE,
            blob.uncompressed_size.to_string(),
            false,
        ),
    ]
}

impl StoredPasskey {
    /// The reserved fields, in their stored order. An ES256 passkey without extension
    /// data has the rows of schema 17, byte for byte.
    fn fields(&self) -> Vec<Field> {
        let mut fields = vec![
            reserved(FIELD_FORMAT, self.algorithm.format().to_owned(), false),
            reserved(FIELD_RP_ID, self.rp_id.clone(), false),
            reserved(
                FIELD_CREDENTIAL_ID,
                b64url_encode(&self.credential_id),
                false,
            ),
            reserved(FIELD_USER_HANDLE, b64url_encode(&self.user_handle), false),
            reserved(FIELD_USER_NAME, self.user_name.clone(), false),
            reserved(
                FIELD_USER_DISPLAY_NAME,
                self.user_display_name.clone(),
                false,
            ),
            reserved(FIELD_KEY, b64url_encode(&self.pkcs8), true),
        ];
        if let Some(prf) = &self.prf {
            fields.push(reserved(FIELD_PRF_UV, b64url_encode(&*prf.with_uv), true));
            fields.push(reserved(
                FIELD_PRF_NO_UV,
                b64url_encode(&*prf.without_uv),
                true,
            ));
        }
        if let Some(blob) = &self.large_blob {
            fields.extend(large_blob_fields(blob));
        }
        fields
    }

    fn info(&self, item_id: u64, title: String) -> PasskeyInfo {
        PasskeyInfo {
            item_id,
            title,
            rp_id: self.rp_id.clone(),
            credential_id: self.credential_id.clone(),
            user_handle: self.user_handle.clone(),
            user_name: self.user_name.clone(),
            user_display_name: self.user_display_name.clone(),
        }
    }
}

// ---- Encoding ----

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 4648 section 5).
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for index in 0..=chunk.len() {
            let sextet = (n >> (18 - 6 * index)) & 0x3f;
            text.push(char::from(B64URL[sextet as usize]));
        }
    }
    text
}

/// The length of the base64url text without padding of `bytes` bytes.
fn b64url_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

/// Strict base64url without padding: no padding, no other characters, and zero
/// trailing bits, so each byte string has one text form.
pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| B64URL.iter().position(|&d| d == c).map(|v| v as u32);
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (index, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * index);
        }
        let produced = chunk.len() - 1;
        let unused = match produced {
            1 => n & 0xffff,
            2 => n & 0xff,
            _ => 0,
        };
        if unused != 0 {
            return None;
        }
        for index in 0..produced {
            out.push((n >> (16 - 8 * index)) as u8);
        }
    }
    Some(out)
}

fn cut_text(text: &str) -> String {
    if text.len() <= MAX_USER_TEXT_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_USER_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// A relying party ID: a lower-case ASCII DNS name. The platform layer checks it against
/// the origin and the public suffix list; this check keeps the stored form canonical.
fn valid_rp_id(rp_id: &str) -> bool {
    if rp_id.is_empty() || rp_id.len() > MAX_RP_ID_BYTES {
        return false;
    }
    rp_id.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn valid_credential_id(id: &[u8]) -> bool {
    (1..=MAX_CREDENTIAL_ID_BYTES).contains(&id.len())
}

fn valid_user_handle(handle: &[u8]) -> bool {
    (1..=MAX_USER_HANDLE_BYTES).contains(&handle.len())
}

// ---- Keys ----

/// One DER element: (tag, content, rest). Definite lengths up to 0xffff.
fn der_next(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x00..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            (usize::from(len), rest)
        }
        0x82 => {
            let (len, rest) = rest.split_at_checked(2)?;
            (usize::from(u16::from_be_bytes([len[0], len[1]])), rest)
        }
        _ => return None,
    };
    let (content, rest) = rest.split_at_checked(len)?;
    Some((tag, content, rest))
}

/// The content of the `privateKey` OCTET STRING of a PKCS #8 key, and the content of
/// its `AlgorithmIdentifier`.
fn pkcs8_parts(pkcs8: &[u8]) -> Option<(&[u8], &[u8])> {
    let (0x30, outer, _) = der_next(pkcs8)? else {
        return None;
    };
    let (0x02, _, rest) = der_next(outer)? else {
        return None;
    };
    let (0x30, algorithm, rest) = der_next(rest)? else {
        return None;
    };
    let (0x04, private_key, _) = der_next(rest)? else {
        return None;
    };
    Some((private_key, algorithm))
}

/// The algorithm of a PKCS #8 key, from its `AlgorithmIdentifier`: the OID, and the
/// named curve of an EC key. `None` for any other algorithm or curve (P-521 too).
fn detect_algorithm(pkcs8: &[u8]) -> Option<KeyAlgorithm> {
    let (_, algorithm) = pkcs8_parts(pkcs8)?;
    let (0x06, oid, parameters) = der_next(algorithm)? else {
        return None;
    };
    if oid == OID_EC_PUBLIC_KEY {
        let (0x06, curve, rest) = der_next(parameters)? else {
            return None;
        };
        if !rest.is_empty() {
            return None;
        }
        if curve == OID_P256 {
            Some(KeyAlgorithm::Es256)
        } else if curve == OID_P384 {
            Some(KeyAlgorithm::Es384)
        } else {
            None
        }
    } else if oid == OID_ED25519 {
        parameters.is_empty().then_some(KeyAlgorithm::Ed25519)
    } else if oid == OID_RSA_ENCRYPTION {
        // `ring` takes only the NULL parameter.
        Some(KeyAlgorithm::Rs256)
    } else {
        None
    }
}

/// The private scalar of `len` bytes in a PKCS #8 v1 EC key that `ring` accepted.
fn ec_private_scalar(pkcs8: &[u8], len: usize) -> Option<&[u8]> {
    let (wrapped, _) = pkcs8_parts(pkcs8)?;
    let (0x30, ec, _) = der_next(wrapped)? else {
        return None;
    };
    let (0x02, _, rest) = der_next(ec)? else {
        return None;
    };
    let (0x04, scalar, _) = der_next(rest)? else {
        return None;
    };
    (scalar.len() == len).then_some(scalar)
}

fn ec_key_pair(form: &EcForm, pkcs8: &[u8]) -> PasskeyResult<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(form.signing, pkcs8, &SystemRandom::new())
        .map_err(|_| PasskeyError::BadKey)
}

/// Check an EC PKCS #8 v1 key of the curve of `form` with its public point, and give it
/// in one form: the form of `ring`, without `parameters` in `ECPrivateKey`. Returns the
/// key and the uncompressed public point.
fn normalize_ec(form: &EcForm, input: &[u8]) -> PasskeyResult<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let checked = ec_key_pair(form, input)?;
    let public = checked.public_key().as_ref().to_vec();
    if public.len() != form.point_bytes {
        return Err(PasskeyError::BadKey);
    }
    let scalar = ec_private_scalar(input, form.scalar_bytes).ok_or(PasskeyError::BadKey)?;
    let bytes = form.prefix.len() + form.scalar_bytes + form.public_prefix.len() + form.point_bytes;
    let mut key = Zeroizing::new(Vec::with_capacity(bytes));
    key.extend_from_slice(form.prefix);
    key.extend_from_slice(scalar);
    key.extend_from_slice(form.public_prefix);
    key.extend_from_slice(&public);
    // The new form must give the same key pair.
    if key.len() != bytes || ec_key_pair(form, &key)?.public_key().as_ref() != public.as_slice() {
        return Err(PasskeyError::BadKey);
    }
    Ok((key, public))
}

/// Check a P-256 PKCS #8 v1 key with its public point, and give it in one form: the
/// form of `ring`, without `parameters` in `ECPrivateKey`. Returns the key and the
/// uncompressed public point.
fn normalize_pkcs8(input: &[u8]) -> PasskeyResult<(Zeroizing<Vec<u8>>, [u8; 65])> {
    let (key, public) = normalize_ec(&P256_FORM, input)?;
    let public: [u8; 65] = public
        .as_slice()
        .try_into()
        .map_err(|_| PasskeyError::BadKey)?;
    if key.len() != PKCS8_BYTES {
        return Err(PasskeyError::BadKey);
    }
    Ok((key, public))
}

/// The 32-byte seed of an Ed25519 PKCS #8 key (v1 or v2): the `CurvePrivateKey` OCTET
/// STRING inside the `privateKey` OCTET STRING (RFC 8410).
fn ed25519_seed(pkcs8: &[u8]) -> Option<&[u8]> {
    let (wrapped, _) = pkcs8_parts(pkcs8)?;
    let (0x04, seed, rest) = der_next(wrapped)? else {
        return None;
    };
    (rest.is_empty() && seed.len() == 32).then_some(seed)
}

/// Check an Ed25519 PKCS #8 key, v1 (no public key) or v2 (`ring` checks the public key
/// against the seed), and give it in one form: v2 with the public key, the form that
/// `ring` makes.
fn normalize_ed25519(input: &[u8]) -> PasskeyResult<Zeroizing<Vec<u8>>> {
    let checked =
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(input).map_err(|_| PasskeyError::BadKey)?;
    let seed = ed25519_seed(input).ok_or(PasskeyError::BadKey)?;
    let public = checked.public_key().as_ref();
    let mut key = Zeroizing::new(Vec::with_capacity(PKCS8_ED25519_BYTES));
    key.extend_from_slice(&PKCS8_ED25519_PREFIX);
    key.extend_from_slice(seed);
    key.extend_from_slice(&PKCS8_ED25519_PUBLIC_PREFIX);
    key.extend_from_slice(public);
    // The new form must give the same key pair, with the strict v2 check.
    let again = Ed25519KeyPair::from_pkcs8(&key).map_err(|_| PasskeyError::BadKey)?;
    if key.len() != PKCS8_ED25519_BYTES || again.public_key().as_ref() != public {
        return Err(PasskeyError::BadKey);
    }
    Ok(key)
}

/// The `RSAPrivateKey` of an RSA PKCS #8 key: the one DER SEQUENCE in `privateKey`.
fn rsa_private_key(pkcs8: &[u8]) -> Option<&[u8]> {
    let (inner, _) = pkcs8_parts(pkcs8)?;
    let (0x30, _, rest) = der_next(inner)? else {
        return None;
    };
    rest.is_empty().then_some(inner)
}

fn rsa_key_pair(pkcs8: &[u8]) -> PasskeyResult<RsaKeyPair> {
    RsaKeyPair::from_pkcs8(pkcs8).map_err(|_| PasskeyError::BadKey)
}

/// DER length octets, for lengths up to 0xffff.
fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

/// Check an RSA PKCS #8 v1 key and give it in one form: version 0, `rsaEncryption` with
/// NULL, the `RSAPrivateKey`, and no attributes. `ring` takes a modulus of 2048 to 4096
/// bits and a public exponent of at least 65537, and checks that the parts agree.
fn normalize_rsa(input: &[u8]) -> PasskeyResult<Zeroizing<Vec<u8>>> {
    let checked = rsa_key_pair(input)?;
    let inner = rsa_private_key(input).ok_or(PasskeyError::BadKey)?;
    // `der_next` reads lengths up to 0xffff; a key of 4096 bits is about 2.4 KB.
    if inner.len() > 0xff00 {
        return Err(PasskeyError::BadKey);
    }
    let mut body = Zeroizing::new(Vec::with_capacity(inner.len() + 24));
    body.extend_from_slice(&[0x02, 0x01, 0x00]);
    body.extend_from_slice(&RSA_ALGORITHM_ID);
    body.push(0x04);
    der_length(inner.len(), &mut body);
    body.extend_from_slice(inner);
    let mut key = Zeroizing::new(Vec::with_capacity(body.len() + 4));
    key.push(0x30);
    der_length(body.len(), &mut key);
    key.extend_from_slice(&body);
    // The new form must give the same key pair.
    let again = rsa_key_pair(&key)?;
    let (before, after): (&[u8], &[u8]) = (checked.public().as_ref(), again.public().as_ref());
    if before != after {
        return Err(PasskeyError::BadKey);
    }
    Ok(key)
}

/// Check a PKCS #8 key of a supported algorithm, and give it in the normalized form of
/// that algorithm. The algorithm comes from the `AlgorithmIdentifier`.
fn normalize_key(input: &[u8]) -> PasskeyResult<(KeyAlgorithm, Zeroizing<Vec<u8>>)> {
    let algorithm = detect_algorithm(input).ok_or(PasskeyError::BadKey)?;
    let key = match algorithm {
        KeyAlgorithm::Es256 => normalize_pkcs8(input)?.0,
        KeyAlgorithm::Es384 => normalize_ec(&P384_FORM, input)?.0,
        KeyAlgorithm::Ed25519 => normalize_ed25519(input)?,
        KeyAlgorithm::Rs256 => normalize_rsa(input)?,
    };
    Ok((algorithm, key))
}

/// The key pair of a stored passkey.
enum Signer {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

impl Signer {
    fn new(algorithm: KeyAlgorithm, pkcs8: &[u8]) -> PasskeyResult<Self> {
        Ok(match algorithm {
            KeyAlgorithm::Es256 => Self::Ecdsa(ec_key_pair(&P256_FORM, pkcs8)?),
            KeyAlgorithm::Es384 => Self::Ecdsa(ec_key_pair(&P384_FORM, pkcs8)?),
            KeyAlgorithm::Ed25519 => {
                Self::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| PasskeyError::BadKey)?)
            }
            KeyAlgorithm::Rs256 => Self::Rsa(rsa_key_pair(pkcs8)?),
        })
    }

    /// The WebAuthn signature of `message`: DER ECDSA, raw Ed25519, or RSASSA-PKCS1-v1_5
    /// with SHA-256.
    fn sign(&self, message: &[u8]) -> PasskeyResult<Vec<u8>> {
        let rng = SystemRandom::new();
        match self {
            Self::Ecdsa(pair) => Ok(pair.sign(&rng, message).map_err(storage)?.as_ref().to_vec()),
            Self::Ed25519(pair) => Ok(pair.sign(message).as_ref().to_vec()),
            Self::Rsa(pair) => {
                let mut signature = vec![0u8; pair.public().modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
                    .map_err(storage)?;
                Ok(signature)
            }
        }
    }
}

// ---- Extensions ----

/// The salt of one PRF input. `hashed`: the input is the salt, and must have 32 bytes.
fn prf_salt(input: &[u8], hashed: bool) -> PasskeyResult<[u8; PRF_BYTES]> {
    if hashed {
        return input.try_into().map_err(|_| invalid());
    }
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(PRF_CONTEXT);
    context.update(input);
    context.finish().as_ref().try_into().map_err(storage)
}

/// HMAC-SHA-256 of `salt` with the CredRandom `secret` (CTAP hmac-secret).
fn prf_eval(secret: &[u8; PRF_BYTES], salt: &[u8; PRF_BYTES]) -> Zeroizing<[u8; PRF_BYTES]> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, salt);
    let mut out = Zeroizing::new([0u8; PRF_BYTES]);
    out.copy_from_slice(tag.as_ref());
    out
}

/// The PRF outputs of `input` with the secret with user verification, or `None` without
/// secrets. The salts are checked also without secrets.
fn prf_output(
    input: &PasskeyPrfInput,
    secrets: Option<&PasskeyPrfSecrets>,
) -> PasskeyResult<Option<PasskeyPrfOutput>> {
    let first = prf_salt(&input.first, input.hashed)?;
    let second = input
        .second
        .as_ref()
        .map(|second| prf_salt(second, input.hashed))
        .transpose()?;
    Ok(secrets.map(|secrets| PasskeyPrfOutput {
        first: prf_eval(&secrets.with_uv, &first),
        second: second.map(|salt| prf_eval(&secrets.with_uv, &salt)),
    }))
}

/// The uncompressed large blob, when `data` is raw DEFLATE that inflates to exactly
/// `size` bytes, at most [`MAX_LARGE_BLOB_BYTES`]. The read stops after `size + 1`
/// bytes, so a bad blob never fills the memory.
fn inflate(data: &[u8], size: u64) -> Option<Zeroizing<Vec<u8>>> {
    let size = usize::try_from(size)
        .ok()
        .filter(|size| *size <= MAX_LARGE_BLOB_BYTES)?;
    let mut out = Zeroizing::new(Vec::with_capacity(size + 1));
    DeflateDecoder::new(data)
        .take(size as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() == size).then_some(out)
}

/// Raw DEFLATE (RFC 1951) of a large blob.
fn deflate(blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let buffer = Vec::with_capacity(blob.len() + blob.len() / 8 + 64);
    let mut encoder = DeflateEncoder::new(buffer, Compression::default());
    encoder.write_all(blob).ok()?;
    encoder.finish().ok().map(Zeroizing::new)
}

/// True when a large blob can be stored: at most [`MAX_LARGE_BLOB_BYTES`] uncompressed,
/// data whose base64url fits a field value, and data that inflates to the size.
fn valid_large_blob(blob: &PasskeyLargeBlob) -> bool {
    !blob.data.is_empty()
        && b64url_len(blob.data.len()) <= MAX_FIELD_VALUE_BYTES
        && inflate(&blob.data, blob.uncompressed_size).is_some()
}

/// A new P-256 key. `ring` gives the PKCS #8 document in its own buffer, which it does
/// not erase; the copy here is erased on drop.
fn generate_key(rng: &SystemRandom) -> PasskeyResult<(Zeroizing<Vec<u8>>, [u8; 65])> {
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, rng).map_err(storage)?;
    normalize_pkcs8(document.as_ref())
}

fn public_key_spki(public: &[u8; 65]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(SPKI_PREFIX.len() + public.len());
    spki.extend_from_slice(&SPKI_PREFIX);
    spki.extend_from_slice(public);
    spki
}

fn cbor(value: &Value) -> PasskeyResult<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(storage)?;
    Ok(out)
}

/// The COSE_Key of the public point (RFC 9053): kty EC2, alg ES256, crv P-256, x, y.
/// The keys are in CTAP2 canonical order.
fn cose_key(public: &[u8; 65]) -> PasskeyResult<Vec<u8>> {
    cbor(&Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer(ES256.into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (
            Value::Integer((-2).into()),
            Value::Bytes(public[1..33].to_vec()),
        ),
        (
            Value::Integer((-3).into()),
            Value::Bytes(public[33..65].to_vec()),
        ),
    ]))
}

/// Authenticator data: SHA-256 of the RP ID, flags, a zero counter, and for a
/// registration the attested credential data with a zero AAGUID.
fn authenticator_data(
    rp_id: &str,
    flags: u8,
    attested: Option<(&[u8], &[u8])>,
) -> PasskeyResult<Vec<u8>> {
    let mut data =
        Vec::with_capacity(37 + attested.map_or(0, |(id, key)| 18 + id.len() + key.len()));
    data.extend_from_slice(digest::digest(&digest::SHA256, rp_id.as_bytes()).as_ref());
    data.push(flags);
    data.extend_from_slice(&0u32.to_be_bytes());
    if let Some((credential_id, cose)) = attested {
        let len = u16::try_from(credential_id.len()).map_err(|_| invalid())?;
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(cose);
    }
    Ok(data)
}

/// The attestation object with "none" attestation, keys in CTAP2 canonical order.
fn attestation_object(auth_data: &[u8]) -> PasskeyResult<Vec<u8>> {
    cbor(&Value::Map(vec![
        (
            Value::Text("fmt".to_owned()),
            Value::Text("none".to_owned()),
        ),
        (Value::Text("attStmt".to_owned()), Value::Map(Vec::new())),
        (
            Value::Text("authData".to_owned()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]))
}

// ---- Storage ----

/// The PRF secrets of the reserved fields: two secret fields of 32 bytes each. `None`
/// when either is missing or bad.
fn parse_prf(fields: &[Field]) -> Option<PasskeyPrfSecrets> {
    let secret = |name: &str| -> Option<Zeroizing<[u8; PRF_BYTES]>> {
        let field = fields
            .iter()
            .find(|field| field.name == name)
            .filter(|field| field.secret)?;
        let raw = Zeroizing::new(b64url_decode(field.value.expose())?);
        let bytes: [u8; PRF_BYTES] = raw.as_slice().try_into().ok()?;
        Some(Zeroizing::new(bytes))
    };
    Some(PasskeyPrfSecrets {
        with_uv: secret(FIELD_PRF_UV)?,
        without_uv: secret(FIELD_PRF_NO_UV)?,
    })
}

/// A decimal number without a sign and without a leading zero.
fn parse_decimal(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse::<u64>().ok()).flatten()
}

/// The large blob of the reserved fields: the secret data and the plain size. `None`
/// when either is missing, the size is above [`MAX_LARGE_BLOB_BYTES`], or the data is
/// empty, too long, or not strict base64url. The data is inflated only when it is read.
fn parse_large_blob(fields: &[Field]) -> Option<PasskeyLargeBlob> {
    let get = |name: &str| fields.iter().find(|field| field.name == name);
    let data = get(FIELD_LARGE_BLOB).filter(|field| field.secret)?;
    let size = get(FIELD_LARGE_BLOB_SIZE).filter(|field| !field.secret)?;
    let uncompressed_size = parse_decimal(size.value.expose())?;
    if uncompressed_size > MAX_LARGE_BLOB_BYTES as u64
        || data.value.expose().len() > MAX_FIELD_VALUE_BYTES
    {
        return None;
    }
    let data = Zeroizing::new(b64url_decode(data.value.expose())?);
    if data.is_empty() {
        return None;
    }
    Some(PasskeyLargeBlob {
        data,
        uncompressed_size,
    })
}

/// Parse the reserved fields of an item. `check_key` also parses the private key and the
/// optional extension fields; a list without secret values (see [`listed_rows`]) skips
/// them. The key must be in the normalized form of the format. Bad optional fields count
/// as absent (see the module documentation); a bad key never does.
fn parse_stored(fields: &[Field], check_key: bool) -> Option<StoredPasskey> {
    let get = |name: &str| fields.iter().find(|field| field.name == name);
    let plain = |name: &str| get(name).filter(|field| !field.secret);
    let algorithm = KeyAlgorithm::from_format(plain(FIELD_FORMAT)?.value.expose())?;
    let rp_id = plain(FIELD_RP_ID)?.value.expose().to_owned();
    let credential_id = b64url_decode(plain(FIELD_CREDENTIAL_ID)?.value.expose())?;
    let user_handle = b64url_decode(plain(FIELD_USER_HANDLE)?.value.expose())?;
    let user_name = plain(FIELD_USER_NAME)?.value.expose().to_owned();
    let user_display_name = plain(FIELD_USER_DISPLAY_NAME)?.value.expose().to_owned();
    let key = get(FIELD_KEY).filter(|field| field.secret)?;
    if !valid_rp_id(&rp_id) || !valid_credential_id(&credential_id) {
        return None;
    }
    if !valid_user_handle(&user_handle) {
        return None;
    }
    let (pkcs8, prf, large_blob) = if check_key {
        let raw = Zeroizing::new(b64url_decode(key.value.expose())?);
        let (found, pkcs8) = normalize_key(&raw).ok()?;
        if found != algorithm || *pkcs8 != *raw {
            return None;
        }
        (pkcs8, parse_prf(fields), parse_large_blob(fields))
    } else {
        (Zeroizing::new(Vec::new()), None, None)
    };
    Some(StoredPasskey {
        algorithm,
        rp_id,
        credential_id,
        user_handle,
        user_name,
        user_display_name,
        pkcs8,
        prf,
        large_blob,
    })
}

/// The reserved fields of an item, in their stored order. Values are erased on drop.
pub(super) fn stored_fields(conn: &Connection, item: i64) -> VaultResult<Vec<Field>> {
    let mut stmt = conn
        .prepare(
            "SELECT name, value, secret FROM item_field
             WHERE item_id = ?1 AND substr(name, 1, 8) = 'passkey_' ORDER BY position",
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let rows = stmt
        .query_map([item], |row| {
            Ok(Field {
                name: row.get(0)?,
                value: SecretValue::new(row.get(1)?),
                secret: row.get::<_, i64>(2)? == 1,
            })
        })
        .map_err(|_| err(VaultErrorKind::Storage))?;
    rows.collect::<Result<_, _>>()
        .map_err(|_| err(VaultErrorKind::Storage))
}

/// True when the reserved fields are one valid passkey, with a key that parses.
pub(super) fn is_valid_passkey(fields: &[Field]) -> bool {
    parse_stored(fields, true).is_some()
}

/// Reserved rows of login items, without secret values (the key and the extension
/// data): item ID to (title, fields).
fn listed_rows(
    conn: &Connection,
    include_archived: bool,
) -> VaultResult<BTreeMap<i64, (String, Vec<Field>)>> {
    let archive = if include_archived {
        ""
    } else {
        "AND i.id NOT IN (SELECT item_id FROM item_archive)"
    };
    let mut stmt = conn
        .prepare(&format!(
            "SELECT i.id, i.title, f.name,
                    CASE WHEN f.secret = 1 THEN '' ELSE f.value END, f.secret
             FROM item_field f JOIN item i ON i.id = f.item_id
             WHERE i.kind = 'login' AND substr(f.name, 1, 8) = 'passkey_' {archive}
             ORDER BY i.id, f.position"
        ))
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                Field {
                    name: row.get(2)?,
                    value: SecretValue::new(row.get(3)?),
                    secret: row.get::<_, i64>(4)? == 1,
                },
            ))
        })
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let mut items: BTreeMap<i64, (String, Vec<Field>)> = BTreeMap::new();
    for row in rows {
        let (id, title, field) = row.map_err(|_| err(VaultErrorKind::Storage))?;
        items
            .entry(id)
            .or_insert_with(|| (title, Vec::new()))
            .1
            .push(field);
    }
    Ok(items)
}

/// The (RP ID, credential ID) of the reserved fields, also when other reserved fields
/// are not valid. A normal item with damaged rows still holds its credential, so a
/// conflict copy cannot take it.
fn claimed_credential(fields: &[Field]) -> Option<(String, Vec<u8>)> {
    let plain = |name: &str| {
        fields
            .iter()
            .find(|field| field.name == name && !field.secret)
            .map(|field| field.value.expose())
    };
    let credential_id = b64url_decode(plain(FIELD_CREDENTIAL_ID)?)?;
    Some((plain(FIELD_RP_ID)?.to_owned(), credential_id))
}

/// Each (RP ID, credential ID) in the vault, archived items too.
fn known_credentials(conn: &Connection) -> VaultResult<Vec<(String, Vec<u8>)>> {
    Ok(listed_rows(conn, true)?
        .into_values()
        .filter_map(|(_, fields)| parse_stored(&fields, false))
        .map(|stored| (stored.rp_id, stored.credential_id))
        .collect())
}

fn is_archived(conn: &Connection, item: i64) -> VaultResult<bool> {
    conn.query_row(
        "SELECT count(*) FROM item_archive WHERE item_id = ?1",
        [item],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
    .map_err(|_| err(VaultErrorKind::Storage))
}

/// The generic fields of an item, for the limit check of an attach.
fn generic_draft(conn: &Connection, item: i64) -> VaultResult<ItemDraft> {
    let (title, notes): (String, String) = conn
        .query_row(
            "SELECT title, notes FROM item WHERE id = ?1",
            [item],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let mut stmt = conn
        .prepare(
            "SELECT name, value, secret FROM item_field
             WHERE item_id = ?1 AND substr(name, 1, 8) <> 'passkey_' ORDER BY position",
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let fields = stmt
        .query_map([item], |row| {
            Ok(Field {
                name: row.get(0)?,
                value: SecretValue::new(row.get(1)?),
                secret: row.get::<_, i64>(2)? == 1,
            })
        })
        .map_err(|_| err(VaultErrorKind::Storage))?
        .collect::<Result<_, _>>()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(ItemDraft {
        title,
        kind: CredentialKind::Login,
        notes,
        tags: super::load_tags(conn, item)?,
        fields,
    })
}

/// Put `stored` on a new login item or on the login item of `attach` (at `revision`, or
/// at the current revision when it is `None`). Returns the item ID.
fn store(
    tx: &rusqlite::Transaction<'_>,
    stored: &StoredPasskey,
    title: &str,
    attach: Option<(u64, Option<u64>)>,
) -> PasskeyResult<u64> {
    let kept = stored.fields();
    let Some((item_id, revision)) = attach else {
        let mut fields = Vec::new();
        if !stored.user_name.is_empty() {
            fields.push(Field {
                name: "username".to_owned(),
                value: SecretValue::new(stored.user_name.clone()),
                secret: false,
            });
        }
        let draft = validate_draft_with(
            ItemDraft {
                title: title.to_owned(),
                kind: CredentialKind::Login,
                notes: String::new(),
                tags: Vec::new(),
                fields,
            },
            &kept,
            true,
        )?;
        tx.execute(
            "INSERT INTO item (title, kind, notes, revision) VALUES (?1, ?2, '', 1)",
            (draft.title.as_str(), kind_as_str(CredentialKind::Login)),
        )
        .map_err(storage)?;
        let id = tx.last_insert_rowid();
        insert_fields(tx, id, 0, &draft.fields)?;
        insert_fields(tx, id, draft.fields.len(), &kept)?;
        history::record(tx, id, ItemEventKind::Created, "")?;
        return Ok(to_public_id(id)?);
    };
    let sql_id = to_sql_id(item_id)?;
    let (current, kind) = super::current_revision_and_kind(tx, sql_id)?;
    if kind != CredentialKind::Login || is_archived(tx, sql_id)? {
        return Err(invalid());
    }
    if let Some(expected) = revision
        && current != to_sql_revision(expected)?
    {
        return Err(PasskeyError::kind(VaultErrorKind::Conflict));
    }
    if !stored_fields(tx, sql_id)?.is_empty() {
        return Err(PasskeyError::Exists);
    }
    // The item with the passkey must still pass the limits.
    validate_draft_with(generic_draft(tx, sql_id)?, &kept, true)?;
    let start: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(position), -1) + 1 FROM item_field WHERE item_id = ?1",
            [sql_id],
            |row| row.get(0),
        )
        .map_err(storage)?;
    insert_fields(tx, sql_id, usize::try_from(start).map_err(storage)?, &kept)?;
    let next = current.checked_add(1).ok_or_else(|| storage(()))?;
    tx.execute(
        "UPDATE item SET revision = ?1 WHERE id = ?2",
        (next, sql_id),
    )
    .map_err(storage)?;
    history::record(
        tx,
        sql_id,
        ItemEventKind::Edited,
        &EditChange::detail(&[EditChange::Secret("passkey".to_owned())]),
    )?;
    Ok(item_id)
}

impl Vault {
    /// Active passkeys of `rp_id`. A non-empty `allowed` keeps only those credential IDs.
    /// See [`Vault::all_passkeys`] for the items in the list.
    pub fn passkeys(&self, rp_id: &str, allowed: &[Vec<u8>]) -> PasskeyResult<Vec<PasskeyInfo>> {
        if !valid_rp_id(rp_id) {
            return Err(invalid());
        }
        Ok(self
            .all_passkeys()?
            .into_iter()
            .filter(|info| info.rp_id == rp_id)
            .filter(|info| allowed.is_empty() || allowed.contains(&info.credential_id))
            .collect())
    }

    /// Each canonical passkey, in item ID order: one entry for each credential (RP ID
    /// and credential ID). Only these passkeys sign and export. An archived item is
    /// never canonical. The canonical item of a credential is one of these:
    ///
    /// - When a normal item (not a conflict copy) has the credential, active or
    ///   archived: the active normal item with the lowest ID. When each normal item
    ///   with the credential is archived, the credential has no canonical item.
    /// - When no normal item has the credential: the restored (active) conflict copy
    ///   with the lowest ID. This keeps a passkey that only the losing version of a sync
    ///   conflict had, also when the original is deleted or is another copy.
    ///
    /// A conflict copy never takes a credential from a normal item. Only the owner can
    /// restore a copy: a merge archives each new copy, and the archive state syncs with
    /// the item.
    pub fn all_passkeys(&self) -> PasskeyResult<Vec<PasskeyInfo>> {
        let conn = self.conn_ref()?;
        let copies = self.conflict_copies()?;
        let archived = self.archived_items()?;
        type Credential = (String, Vec<u8>);
        let rows = listed_rows(conn, true)?;
        // The credentials of normal items, archived too.
        let mut normal: BTreeSet<Credential> = BTreeSet::new();
        for (&id, (_, fields)) in &rows {
            if !copies.contains_key(&to_public_id(id)?)
                && let Some(credential) = claimed_credential(fields)
            {
                normal.insert(credential);
            }
        }
        let mut chosen: BTreeMap<Credential, PasskeyInfo> = BTreeMap::new();
        // The rows are in item ID order, so the first active item of a credential stays.
        for (id, (title, fields)) in rows {
            let item_id = to_public_id(id)?;
            if archived.contains_key(&item_id) {
                continue;
            }
            let Some(stored) = parse_stored(&fields, false) else {
                continue;
            };
            let key = (stored.rp_id.clone(), stored.credential_id.clone());
            if copies.contains_key(&item_id) && normal.contains(&key) {
                continue;
            }
            chosen
                .entry(key)
                .or_insert_with(|| stored.info(item_id, title));
        }
        let mut list: Vec<PasskeyInfo> = chosen.into_values().collect();
        list.sort_by_key(|info| info.item_id);
        Ok(list)
    }

    /// `Vault(InvalidInput)` when `attach` is a conflict copy, archived or restored. A
    /// conflict copy keeps the losing version of a sync conflict, and it holds only a
    /// passkey of that version. A new or imported credential goes on a normal login,
    /// which has priority in [`Vault::all_passkeys`].
    fn refuse_conflict_copy(&self, attach: Option<u64>) -> PasskeyResult<()> {
        match attach {
            Some(item_id) if self.conflict_copies()?.contains_key(&item_id) => Err(invalid()),
            _ => Ok(()),
        }
    }

    /// The passkey of one item, archived or not. `NotFound` when it has none.
    pub fn passkey_info(&self, item_id: u64) -> PasskeyResult<PasskeyInfo> {
        let conn = self.conn_ref()?;
        let sql_id = to_sql_id(item_id)?;
        let title: String = conn
            .query_row(
                "SELECT title FROM item WHERE id = ?1 AND kind = 'login'",
                [sql_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| PasskeyError::kind(VaultErrorKind::NotFound))?;
        let fields = stored_fields(conn, sql_id)?;
        parse_stored(&fields, false)
            .map(|stored| stored.info(item_id, title))
            .ok_or_else(|| PasskeyError::kind(VaultErrorKind::NotFound))
    }

    /// Make a new ES256 passkey (WebAuthn authenticatorMakeCredential) with "none"
    /// attestation. The caller did a fresh owner verification for this request.
    ///
    /// - `NoSupportedAlgorithm`: ES256 is not in a non-empty `algorithms`.
    /// - `Excluded`: the vault has a credential of `exclude` for this RP, archived too.
    /// - `Exists`: the attach item has a passkey.
    /// - `Vault(Conflict)`: the attach revision is not current.
    /// - `Vault(InvalidInput)`: a bad RP ID, user handle, or title, or an attach item that
    ///   is not an active login or is a conflict copy (archived or restored).
    pub fn create_passkey(&mut self, request: PasskeyCreate<'_>) -> PasskeyResult<PasskeyCreated> {
        self.require_unlocked()?;
        if !valid_rp_id(request.rp_id) || !valid_user_handle(request.user_handle) {
            return Err(invalid());
        }
        if let PasskeyTarget::Attach { item_id, .. } = request.target {
            self.refuse_conflict_copy(Some(item_id))?;
        }
        if !request.algorithms.is_empty() && !request.algorithms.contains(&ES256) {
            return Err(PasskeyError::NoSupportedAlgorithm);
        }
        let rng = SystemRandom::new();
        let (pkcs8, public) = generate_key(&rng)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let known = known_credentials(&tx)?;
        if known
            .iter()
            .any(|(rp, id)| rp == request.rp_id && request.exclude.contains(id))
        {
            return Err(PasskeyError::Excluded);
        }
        let taken: BTreeSet<&[u8]> = known.iter().map(|(_, id)| id.as_slice()).collect();
        let mut credential_id = None;
        for _ in 0..4 {
            let mut id = vec![0u8; NEW_CREDENTIAL_ID_BYTES];
            rng.fill(&mut id).map_err(storage)?;
            if !taken.contains(id.as_slice()) {
                credential_id = Some(id);
                break;
            }
        }
        let credential_id = credential_id.ok_or_else(|| storage(()))?;
        let stored = StoredPasskey {
            algorithm: KeyAlgorithm::Es256,
            rp_id: request.rp_id.to_owned(),
            credential_id: credential_id.clone(),
            user_handle: request.user_handle.to_vec(),
            user_name: cut_text(request.user_name),
            user_display_name: cut_text(request.user_display_name),
            pkcs8,
            prf: None,
            large_blob: None,
        };
        let (title, attach) = match &request.target {
            PasskeyTarget::NewItem { title } => (title.as_str(), None),
            PasskeyTarget::Attach { item_id, revision } => ("", Some((*item_id, Some(*revision)))),
        };
        let item_id = store(&tx, &stored, title, attach)?;
        let cose = cose_key(&public)?;
        let authenticator_data = authenticator_data(
            request.rp_id,
            ASSERTION_FLAGS | FLAG_AT,
            Some((&credential_id, &cose)),
        )?;
        let attestation_object = attestation_object(&authenticator_data)?;
        tx.commit().map_err(storage)?;
        Ok(PasskeyCreated {
            item_id,
            credential_id,
            attestation_object,
            authenticator_data,
            public_key_spki: public_key_spki(&public),
            algorithm: ES256,
        })
    }

    /// Sign an assertion (WebAuthn authenticatorGetAssertion) with the passkey of an
    /// active item, without extensions. The caller did a fresh owner verification for
    /// this request. The signature is over the authenticator data and
    /// `client_data_hash`. See [`Vault::assert_passkey`] for the errors.
    pub fn sign_passkey(
        &self,
        item_id: u64,
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
    ) -> PasskeyResult<PasskeyAssertion> {
        self.sign_with(
            item_id,
            rp_id,
            credential_id,
            client_data_hash,
            &PasskeyAssertionExtensions::default(),
        )
    }

    /// Sign an assertion with the passkey of an active item, with the WebAuthn
    /// extensions of the request. The caller did a fresh owner verification for this
    /// request, so the authenticator data sets user verification.
    ///
    /// - PRF: with PRF secrets, the outputs of the secret with user verification. Without
    ///   secrets, no output.
    /// - largeBlob read: the uncompressed blob, or `Read(None)` without a blob or for a
    ///   blob that does not inflate to its size.
    /// - largeBlob write: after the signature, [`Vault::write_large_blob`]. A write that
    ///   fails for any reason gives `Written(false)`; the assertion still stands.
    ///
    /// - `Vault(NotFound)`: the passkey of the item is not canonical (see
    ///   [`Vault::all_passkeys`]: archived, a conflict copy of a credential that a normal
    ///   item has, or a duplicate), its key does not parse, or it has another RP ID or
    ///   credential ID.
    /// - `Vault(InvalidInput)`: a hashed PRF input that does not have 32 bytes.
    pub fn assert_passkey(
        &mut self,
        item_id: u64,
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
        extensions: &PasskeyAssertionExtensions,
    ) -> PasskeyResult<PasskeyAssertion> {
        let mut assertion =
            self.sign_with(item_id, rp_id, credential_id, client_data_hash, extensions)?;
        if let Some(LargeBlobOp::Write(blob)) = &extensions.large_blob {
            let written = self
                .write_large_blob(item_id, rp_id, credential_id, blob)
                .unwrap_or(false);
            assertion.large_blob = Some(LargeBlobResult::Written(written));
        }
        Ok(assertion)
    }

    /// The assertion and the read-only extensions (PRF and a largeBlob read).
    fn sign_with(
        &self,
        item_id: u64,
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
        extensions: &PasskeyAssertionExtensions,
    ) -> PasskeyResult<PasskeyAssertion> {
        let (stored, _) = self.canonical_stored(item_id)?;
        if stored.rp_id != rp_id || stored.credential_id != credential_id {
            return Err(PasskeyError::kind(VaultErrorKind::NotFound));
        }
        let prf = match &extensions.prf {
            Some(input) => prf_output(input, stored.prf.as_ref())?,
            None => None,
        };
        let signer = Signer::new(stored.algorithm, &stored.pkcs8)?;
        let authenticator_data = authenticator_data(rp_id, ASSERTION_FLAGS, None)?;
        let mut message = Vec::with_capacity(authenticator_data.len() + 32);
        message.extend_from_slice(&authenticator_data);
        message.extend_from_slice(client_data_hash);
        let signature = signer.sign(&message)?;
        let large_blob = match &extensions.large_blob {
            Some(LargeBlobOp::Read) => {
                Some(LargeBlobResult::Read(stored.large_blob.as_ref().and_then(
                    |blob| inflate(&blob.data, blob.uncompressed_size),
                )))
            }
            // [`Vault::assert_passkey`] writes after the signature.
            Some(LargeBlobOp::Write(_)) | None => None,
        };
        Ok(PasskeyAssertion {
            credential_id: stored.credential_id.clone(),
            user_handle: stored.user_handle.clone(),
            authenticator_data,
            signature,
            algorithm: stored.algorithm.cose(),
            prf,
            large_blob,
        })
    }

    /// Store `blob` (uncompressed) as the large blob of the canonical passkey of an item,
    /// compressed with raw DEFLATE: the WebAuthn largeBlob write. It replaces the blob
    /// that the item had. The item gets a new revision and a history event without
    /// values, and the change syncs like any other edit.
    ///
    /// `Ok(false)`, and nothing changes: the blob has more than [`MAX_LARGE_BLOB_BYTES`],
    /// its compressed base64url is longer than a field value, the item with the new
    /// blob would go over the limits of an item, or the item has no canonical passkey
    /// for this RP ID and credential ID.
    pub fn write_large_blob(
        &mut self,
        item_id: u64,
        rp_id: &str,
        credential_id: &[u8],
        blob: &[u8],
    ) -> PasskeyResult<bool> {
        self.require_unlocked()?;
        if blob.len() > MAX_LARGE_BLOB_BYTES {
            return Ok(false);
        }
        let stored = match self.canonical_stored(item_id) {
            Ok((stored, _)) => stored,
            Err(PasskeyError::Vault(error)) if error.kind() == VaultErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if stored.rp_id != rp_id || stored.credential_id != credential_id {
            return Ok(false);
        }
        let Some(data) = deflate(blob) else {
            return Ok(false);
        };
        if b64url_len(data.len()) > MAX_FIELD_VALUE_BYTES {
            return Ok(false);
        }
        let new_blob = PasskeyLargeBlob {
            data,
            uncompressed_size: blob.len() as u64,
        };
        let sql_id = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // The rows must still be the passkey that was checked.
        let fields = stored_fields(&tx, sql_id)?;
        let Some(again) = parse_stored(&fields, true) else {
            return Ok(false);
        };
        if again.rp_id != stored.rp_id
            || again.credential_id != stored.credential_id
            || *again.pkcs8 != *stored.pkcs8
        {
            return Ok(false);
        }
        let (current, kind) = super::current_revision_and_kind(&tx, sql_id)?;
        if kind != CredentialKind::Login || is_archived(&tx, sql_id)? {
            return Ok(false);
        }
        let rows = large_blob_fields(&new_blob);
        let mut kept: Vec<Field> = fields
            .into_iter()
            .filter(|field| field.name != FIELD_LARGE_BLOB && field.name != FIELD_LARGE_BLOB_SIZE)
            .collect();
        kept.extend(rows);
        // The item with the new blob must still pass the limits.
        if validate_draft_with(generic_draft(&tx, sql_id)?, &kept, true).is_err() {
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM item_field WHERE item_id = ?1 AND name IN (?2, ?3)",
            (sql_id, FIELD_LARGE_BLOB, FIELD_LARGE_BLOB_SIZE),
        )
        .map_err(storage)?;
        let start: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM item_field WHERE item_id = ?1",
                [sql_id],
                |row| row.get(0),
            )
            .map_err(storage)?;
        insert_fields(
            &tx,
            sql_id,
            usize::try_from(start).map_err(storage)?,
            &kept[kept.len() - 2..],
        )?;
        let next = current.checked_add(1).ok_or_else(|| storage(()))?;
        tx.execute(
            "UPDATE item SET revision = ?1 WHERE id = ?2",
            (next, sql_id),
        )
        .map_err(storage)?;
        history::record(
            &tx,
            sql_id,
            ItemEventKind::Edited,
            &EditChange::detail(&[EditChange::Secret("passkey".to_owned())]),
        )?;
        tx.commit().map_err(storage)?;
        Ok(true)
    }

    /// The passkey of an item with its private key, its algorithm, its PRF secrets, and
    /// its large blob (compressed, as stored), for an owner-approved transfer to another
    /// provider (Credential Exchange). This is the only path that returns the key and
    /// the PRF secrets. The caller did a fresh owner verification for the export, and hands the key
    /// to the system transfer without a file or a log. Generic details, reveal, and agent
    /// paths still hide each passkey field. After the hand-off the caller records it with
    /// [`Vault::record_export`]. Nothing is written here.
    ///
    /// `Vault(NotFound)`: the item is not a login, or its passkey is not canonical (see
    /// [`Vault::all_passkeys`]: archived, a conflict copy of a credential that a normal
    /// item has, or a duplicate), or its key does not parse to the normalized form.
    pub fn export_passkey(&self, item_id: u64) -> PasskeyResult<PasskeyExport> {
        // `canonical_stored` parsed the key with `ring` and checked that it is the
        // normalized form, so a key that `ring` does not take never leaves the vault.
        let (stored, info) = self.canonical_stored(item_id)?;
        let StoredPasskey {
            algorithm,
            pkcs8,
            prf,
            large_blob,
            ..
        } = stored;
        Ok(PasskeyExport {
            info,
            pkcs8,
            algorithm: algorithm.cose(),
            prf,
            large_blob,
        })
    }

    /// Record that the owner prepared a Credential Exchange export of an item: a
    /// [`ItemEventKind::Revealed`] event with the detail [`EXPORT_DETAIL`] and no values.
    /// It does not prove that the recipient took the item. Any item that the export
    /// has (a passkey, a password, a one-time password) can have the event.
    pub fn record_export(&mut self, item_id: u64) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let found: Option<i64> = tx
            .query_row("SELECT id FROM item WHERE id = ?1", [item], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if found.is_none() {
            return Err(err(VaultErrorKind::NotFound));
        }
        history::record(&tx, item, ItemEventKind::Revealed, EXPORT_DETAIL)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// The stored passkey of an item, with its key, when it is canonical: an active
    /// login item that is the list entry of its credential in [`Vault::all_passkeys`],
    /// with a key that parses. Returns its list entry too. Else `Vault(NotFound)`.
    fn canonical_stored(&self, item_id: u64) -> PasskeyResult<(StoredPasskey, PasskeyInfo)> {
        let conn = self.conn_ref()?;
        let sql_id = to_sql_id(item_id)?;
        let not_found = || PasskeyError::kind(VaultErrorKind::NotFound);
        let kind: Option<String> = conn
            .query_row("SELECT kind FROM item WHERE id = ?1", [sql_id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?;
        if kind.as_deref() != Some("login") || is_archived(conn, sql_id)? {
            return Err(not_found());
        }
        let stored = parse_stored(&stored_fields(conn, sql_id)?, true).ok_or_else(not_found)?;
        let info = self
            .all_passkeys()?
            .into_iter()
            .find(|info| {
                info.item_id == item_id
                    && info.rp_id == stored.rp_id
                    && info.credential_id == stored.credential_id
            })
            .ok_or_else(not_found)?;
        Ok((stored, info))
    }

    /// Add a passkey from another provider, with its PRF secrets and its large blob.
    /// Returns the item ID. The algorithm comes from the key (see the module
    /// documentation).
    ///
    /// - `BadKey`: the key is not a key of a supported algorithm in a form that is taken
    ///   (P-521 and other algorithms too).
    /// - `Exists`: the vault has this RP ID and credential ID (a conflict copy too), or
    ///   the attach item has a passkey.
    /// - `Vault(InvalidInput)`: a bad RP ID, credential ID, or user handle; a large blob
    ///   that is empty, larger than [`MAX_LARGE_BLOB_BYTES`] uncompressed, too long for a
    ///   field, or that does not inflate to its size; or an attach item that is not an
    ///   active login or is a conflict copy (archived or restored).
    pub fn import_passkey(&mut self, import: PasskeyImport) -> PasskeyResult<u64> {
        self.require_unlocked()?;
        if !valid_rp_id(&import.rp_id)
            || !valid_credential_id(&import.credential_id)
            || !valid_user_handle(&import.user_handle)
        {
            return Err(invalid());
        }
        if import
            .large_blob
            .as_ref()
            .is_some_and(|blob| !valid_large_blob(blob))
        {
            return Err(invalid());
        }
        self.refuse_conflict_copy(import.attach)?;
        let (algorithm, pkcs8) = normalize_key(&import.pkcs8)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if known_credentials(&tx)?
            .iter()
            .any(|(rp, id)| *rp == import.rp_id && *id == import.credential_id)
        {
            return Err(PasskeyError::Exists);
        }
        let title = if import.title.trim().is_empty() {
            import.rp_id.clone()
        } else {
            import.title.clone()
        };
        let stored = StoredPasskey {
            algorithm,
            rp_id: import.rp_id.clone(),
            credential_id: import.credential_id.clone(),
            user_handle: import.user_handle.clone(),
            user_name: cut_text(&import.user_name),
            user_display_name: cut_text(&import.user_display_name),
            pkcs8,
            prf: import.prf,
            large_blob: import.large_blob,
        };
        let item_id = store(&tx, &stored, &title, import.attach.map(|id| (id, None)))?;
        tx.commit().map_err(storage)?;
        Ok(item_id)
    }

    /// Remove the passkey of an item at `revision`. An item with a password keeps it and
    /// gets a new revision. An item without a password is deleted, like
    /// [`Vault::delete`]: with its notes, tags, website, one-time password, custom
    /// fields, grants, and history. A login is not valid without a password or a
    /// passkey. The owner interface must say so before it calls this.
    pub fn remove_passkey(&mut self, item_id: u64, revision: u64) -> PasskeyResult<()> {
        self.require_unlocked()?;
        let sql_id = to_sql_id(item_id)?;
        let expected = to_sql_revision(revision)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (current, _) = super::current_revision_and_kind(&tx, sql_id)?;
        if current != expected {
            return Err(PasskeyError::kind(VaultErrorKind::Conflict));
        }
        if stored_fields(&tx, sql_id)?.is_empty() {
            return Err(PasskeyError::kind(VaultErrorKind::NotFound));
        }
        let password: i64 = tx
            .query_row(
                "SELECT count(*) FROM item_field
                 WHERE item_id = ?1 AND name = 'password' AND secret = 1 AND value <> ''",
                [sql_id],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if password == 0 {
            super::delete_item_rows(&tx, sql_id)?;
        } else {
            tx.execute(
                "DELETE FROM item_field WHERE item_id = ?1 AND substr(name, 1, 8) = 'passkey_'",
                [sql_id],
            )
            .map_err(storage)?;
            let next = current.checked_add(1).ok_or_else(|| storage(()))?;
            tx.execute(
                "UPDATE item SET revision = ?1 WHERE id = ?2",
                (next, sql_id),
            )
            .map_err(storage)?;
            history::record(
                &tx,
                sql_id,
                ItemEventKind::Edited,
                &EditChange::detail(&[EditChange::Secret("passkey".to_owned())]),
            )?;
        }
        tx.commit().map_err(storage)
    }
}

// ---- Schema 17 ----

/// A free name for an ordinary field of an earlier schema with a reserved name: the
/// custom label of the old name, then the label with a number, then `legacy_field_<n>`.
/// Each name is at most 64 bytes and not in `taken`.
fn legacy_name(name: &str, taken: &BTreeSet<String>) -> String {
    for n in 1..=9 {
        let label = if n == 1 {
            name.to_owned()
        } else {
            format!("{name} ({n})")
        };
        let candidate = format!("{DETAIL_PREFIX}{}", to_hex(label.as_bytes()));
        if candidate.len() <= 64 && !taken.contains(&candidate) {
            return candidate;
        }
    }
    (1..)
        .map(|n| format!("legacy_field_{n}"))
        .find(|candidate| !taken.contains(candidate))
        .unwrap_or_default()
}

/// Plan the schema-16 reserved-field conversion in stored field order. Both the
/// local SQL migration and read-only sync merge use this exact collision handling.
pub(super) fn legacy_field_renames<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Vec<(String, String)> {
    let names: Vec<&str> = names.into_iter().collect();
    let mut taken: BTreeSet<String> = names.iter().map(|name| (*name).to_owned()).collect();
    let mut renames = Vec::new();
    for name in names {
        if name.starts_with(PASSKEY_FIELD_PREFIX) {
            let new = legacy_name(name, &taken);
            taken.insert(new.clone());
            renames.push((name.to_owned(), new));
        }
    }
    renames
}

/// Add schema version 17 in the migration or create transaction. Each ordinary field
/// with a reserved name gets a free name; its value and secret flag stay. An environment
/// binding of the old name gets the new name, so an agent run still reads the value.
/// The item keeps its revision and sync version, so two copies of the vault that
/// migrate do not conflict: each gives the same names.
///
/// It works on the `main` schema of the connection of `tx`, at schema 16, and leaves
/// `sync_device.applying` as it found it. A sync snapshot of schema 16 can use it in its
/// own connection to get the same names.
pub(super) fn add_schema_v17(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    let legacy: Vec<(i64, i64, String)> = {
        let mut stmt = tx
            .prepare(&format!(
                "SELECT item_id, rowid, name FROM item_field
                 WHERE substr(name, 1, 8) = '{PASSKEY_FIELD_PREFIX}'
                 ORDER BY item_id, position, rowid"
            ))
            .map_err(storage)?;
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?
    };
    let mut by_item: BTreeMap<i64, Vec<(i64, String)>> = BTreeMap::new();
    for (item, rowid, name) in legacy {
        by_item.entry(item).or_default().push((rowid, name));
    }
    let applying: Option<i64> = tx
        .query_row("SELECT applying FROM sync_device WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(storage)?;
    if !by_item.is_empty() {
        tx.execute("UPDATE sync_device SET applying = 1 WHERE id = 1", [])
            .map_err(storage)?;
    }
    for (item, fields) in by_item {
        let version: Option<(i64, String)> = tx
            .query_row(
                "SELECT updated_at, updated_by FROM item WHERE id = ?1",
                [item],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let names: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT name FROM item_field WHERE item_id = ?1 ORDER BY position, rowid")
                .map_err(storage)?;
            stmt.query_map([item], |row| row.get(0))
                .map_err(storage)?
                .collect::<Result<_, _>>()
                .map_err(storage)?
        };
        let renames = legacy_field_renames(names.iter().map(String::as_str));
        for ((rowid, name), (_, new)) in fields.into_iter().zip(renames) {
            tx.execute(
                "UPDATE item_field SET name = ?1 WHERE rowid = ?2",
                (&new, rowid),
            )
            .map_err(storage)?;
            tx.execute(
                "UPDATE env_binding SET field = ?1 WHERE item_id = ?2 AND field = ?3",
                (&new, item, &name),
            )
            .map_err(storage)?;
        }
        if let Some((at, by)) = version {
            tx.execute(
                "UPDATE item SET updated_at = ?1, updated_by = ?2 WHERE id = ?3",
                (at, by, item),
            )
            .map_err(storage)?;
        }
    }
    tx.execute(
        "UPDATE sync_device SET applying = ?1 WHERE id = 1",
        [applying.unwrap_or(0)],
    )
    .map_err(storage)?;
    tx.execute_batch(SCHEMA_V17_SQL).map_err(storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{ItemDraft, VaultErrorKind};
    use tempfile::TempDir;

    const PASS: &str = "synthetic-passkey-migration";

    #[test]
    fn base64url_is_strict_and_round_trips() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|n| (n * 37 + 11) as u8).collect();
            let text = b64url_encode(&bytes);
            assert!(!text.contains('='));
            assert_eq!(b64url_decode(&text).unwrap(), bytes);
        }
        assert_eq!(b64url_encode(b"\xfb\xff"), "-_8");
        assert!(b64url_decode("-_9").is_none(), "non-zero trailing bits");
        assert!(b64url_decode("AA==").is_none());
        assert!(b64url_decode("A").is_none());
        assert!(b64url_decode("AB+/").is_none());
    }

    #[test]
    fn rp_ids_must_be_canonical_dns_names() {
        for good in [
            "example.com",
            "login.example.co.uk",
            "localhost",
            "a-b.example",
        ] {
            assert!(valid_rp_id(good), "{good}");
        }
        for bad in [
            "",
            "Example.com",
            "example.com.",
            ".example.com",
            "exa mple.com",
            "-a.example",
            "https://example.com",
        ] {
            assert!(!valid_rp_id(bad), "{bad}");
        }
    }

    #[test]
    fn normalized_key_is_the_ring_form_and_parameters_are_removed() {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let (key, public) = normalize_pkcs8(document.as_ref()).unwrap();
        assert_eq!(key.as_slice(), document.as_ref());
        // The same key with `[0] parameters` in ECPrivateKey (the CryptoKit form).
        let raw = document.as_ref();
        let scalar = ec_private_scalar(raw, 32).unwrap();
        let mut with_params = vec![0x30, 0x81, 0x93, 0x02, 0x01, 0x00];
        with_params.extend_from_slice(&raw[6..27]);
        with_params.extend_from_slice(&[0x04, 0x79, 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]);
        with_params.extend_from_slice(scalar);
        with_params.extend_from_slice(&[
            0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]);
        with_params.extend_from_slice(&PKCS8_PUBLIC_PREFIX);
        with_params.extend_from_slice(&public);
        let (again, public_again) = normalize_pkcs8(&with_params).unwrap();
        assert_eq!(again.as_slice(), document.as_ref());
        assert_eq!(public_again, public);
        // Damaged keys fail.
        assert!(matches!(
            normalize_pkcs8(&raw[..raw.len() - 1]),
            Err(PasskeyError::BadKey)
        ));
        let mut other_point = raw.to_vec();
        let last = other_point.len() - 1;
        other_point[last] ^= 1;
        assert!(matches!(
            normalize_pkcs8(&other_point),
            Err(PasskeyError::BadKey)
        ));
        assert!(matches!(normalize_pkcs8(&[]), Err(PasskeyError::BadKey)));
    }

    #[test]
    fn stored_passkey_debug_has_no_key() {
        let stored = StoredPasskey {
            algorithm: KeyAlgorithm::Es256,
            rp_id: "example.com".to_owned(),
            credential_id: vec![1],
            user_handle: vec![2],
            user_name: String::new(),
            user_display_name: String::new(),
            pkcs8: Zeroizing::new(b"SYNTH-KEY-BYTES".to_vec()),
            prf: Some(synthetic_prf()),
            large_blob: Some(PasskeyLargeBlob {
                data: Zeroizing::new(b"SYNTH-BLOB".to_vec()),
                uncompressed_size: 10,
            }),
        };
        let text = format!("{stored:?}");
        assert!(
            !text.contains("SYNTH") && !text.contains("83, 89"),
            "{text}"
        );
        let import = PasskeyImport {
            rp_id: "example.com".to_owned(),
            credential_id: vec![1],
            user_handle: vec![2],
            user_name: String::new(),
            user_display_name: String::new(),
            pkcs8: Zeroizing::new(b"SYNTH-KEY-BYTES".to_vec()),
            title: String::new(),
            attach: None,
            prf: Some(synthetic_prf()),
            large_blob: Some(PasskeyLargeBlob {
                data: Zeroizing::new(b"SYNTH-BLOB".to_vec()),
                uncompressed_size: 10,
            }),
        };
        let text = format!("{import:?}");
        assert!(
            text.contains("[redacted]") && !text.contains("83, 89") && !text.contains("17, 17"),
            "{text}"
        );
        // The values of the extensions: lengths only.
        let output = prf_output(
            &PasskeyPrfInput {
                first: b"SYNTH-input".to_vec(),
                second: None,
                hashed: false,
            },
            Some(&synthetic_prf()),
        )
        .unwrap()
        .unwrap();
        let assertion = PasskeyAssertion {
            credential_id: vec![1],
            user_handle: vec![2],
            authenticator_data: Vec::new(),
            signature: Vec::new(),
            algorithm: ES256,
            prf: Some(output.clone()),
            large_blob: Some(LargeBlobResult::Read(Some(Zeroizing::new(
                b"SYNTH-BLOB".to_vec(),
            )))),
        };
        let first = output.first.iter().map(u8::to_string).collect::<Vec<_>>();
        for text in [
            format!("{assertion:?}"),
            format!("{output:?}"),
            format!("{:?}", synthetic_prf()),
            format!(
                "{:?}",
                PasskeyAssertionExtensions {
                    prf: Some(PasskeyPrfInput {
                        first: b"SYNTH-input".to_vec(),
                        second: Some(b"SYNTH-input".to_vec()),
                        hashed: false,
                    }),
                    large_blob: Some(LargeBlobOp::Write(Zeroizing::new(b"SYNTH-BLOB".to_vec()))),
                }
            ),
        ] {
            assert!(
                !text.contains("SYNTH") && !text.contains("83, 89") && !text.contains("17, 17"),
                "{text}"
            );
            assert!(!text.contains(&first[..4].join(", ")), "{text}");
        }
    }

    /// Synthetic PRF secrets: 0x11 with user verification, 0x33 without.
    fn synthetic_prf() -> PasskeyPrfSecrets {
        PasskeyPrfSecrets {
            with_uv: Zeroizing::new([0x11; PRF_BYTES]),
            without_uv: Zeroizing::new([0x33; PRF_BYTES]),
        }
    }

    /// Synthetic RSA keys made with `openssl genpkey` for these tests only.
    const RSA_2048: &[u8] = include_bytes!("../../tests/fixtures/passkeys/rsa2048-synthetic.pk8");
    const RSA_1024: &[u8] = include_bytes!("../../tests/fixtures/passkeys/rsa1024-synthetic.pk8");
    const P521: &[u8] = include_bytes!("../../tests/fixtures/passkeys/p521-synthetic.pk8");

    fn verify(
        algorithm: &'static dyn ring::signature::VerificationAlgorithm,
        public: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        ring::signature::UnparsedPublicKey::new(algorithm, public)
            .verify(message, signature)
            .is_ok()
    }

    #[test]
    fn each_algorithm_normalizes_signs_and_verifies() {
        let rng = SystemRandom::new();
        let message = b"synthetic authenticator data and hash";
        // ES384: the form of `ring`, the CryptoKit form is not needed.
        let p384 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let (algorithm, key) = normalize_key(p384.as_ref()).unwrap();
        assert_eq!(algorithm, KeyAlgorithm::Es384);
        assert_eq!(key.as_slice(), p384.as_ref());
        let public = ec_key_pair(&P384_FORM, &key)
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let signature = Signer::new(algorithm, &key).unwrap().sign(message).unwrap();
        assert!(verify(
            &ring::signature::ECDSA_P384_SHA384_ASN1,
            &public,
            message,
            &signature
        ));
        // ES256 keeps its form.
        let p256 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let (algorithm, key) = normalize_key(p256.as_ref()).unwrap();
        assert_eq!(algorithm, KeyAlgorithm::Es256);
        assert_eq!(key.as_slice(), p256.as_ref());
        // Ed25519: v2 of `ring` stays, and v1 (no public key) becomes v2.
        let ed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let (algorithm, key) = normalize_key(ed.as_ref()).unwrap();
        assert_eq!(algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(key.as_slice(), ed.as_ref());
        let mut v1 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        v1.extend_from_slice(ed25519_seed(ed.as_ref()).unwrap());
        let (_, from_v1) = normalize_key(&v1).unwrap();
        assert_eq!(from_v1.as_slice(), ed.as_ref());
        let public = Ed25519KeyPair::from_pkcs8(ed.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let signature = Signer::new(algorithm, &key).unwrap().sign(message).unwrap();
        assert_eq!(signature.len(), 64);
        assert!(verify(
            &ring::signature::ED25519,
            &public,
            message,
            &signature
        ));
        // A v2 key with another public key fails.
        let mut wrong = ed.as_ref().to_vec();
        let last = wrong.len() - 1;
        wrong[last] ^= 1;
        assert!(matches!(normalize_key(&wrong), Err(PasskeyError::BadKey)));
        // RS256: the OpenSSL form is the normalized form already (no attributes).
        let (algorithm, key) = normalize_key(RSA_2048).unwrap();
        assert_eq!(algorithm, KeyAlgorithm::Rs256);
        assert_eq!(key.as_slice(), RSA_2048);
        let pair = RsaKeyPair::from_pkcs8(&key).unwrap();
        let signature = Signer::new(algorithm, &key).unwrap().sign(message).unwrap();
        assert_eq!(signature.len(), 256);
        assert!(verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            pair.public().as_ref(),
            message,
            &signature
        ));
        // The same RSA key with attributes loses them.
        let inner = rsa_private_key(RSA_2048).unwrap();
        let mut body = vec![0x02, 0x01, 0x00];
        body.extend_from_slice(&RSA_ALGORITHM_ID);
        body.push(0x04);
        der_length(inner.len(), &mut body);
        body.extend_from_slice(inner);
        body.extend_from_slice(&[0xa0, 0x00]);
        let mut with_attributes = vec![0x30];
        der_length(body.len(), &mut with_attributes);
        with_attributes.extend_from_slice(&body);
        let (_, again) = normalize_key(&with_attributes).unwrap();
        assert_eq!(again.as_slice(), RSA_2048);
    }

    #[test]
    fn other_algorithms_and_damaged_keys_are_refused() {
        assert_eq!(detect_algorithm(P521), None);
        assert!(matches!(normalize_key(P521), Err(PasskeyError::BadKey)));
        // ring takes no RSA key below 2048 bits.
        assert_eq!(detect_algorithm(RSA_1024), Some(KeyAlgorithm::Rs256));
        assert!(matches!(normalize_key(RSA_1024), Err(PasskeyError::BadKey)));
        let mut damaged = RSA_2048.to_vec();
        damaged[300] ^= 0xff;
        assert!(matches!(normalize_key(&damaged), Err(PasskeyError::BadKey)));
        assert!(matches!(
            normalize_key(&RSA_2048[..RSA_2048.len() - 1]),
            Err(PasskeyError::BadKey)
        ));
        assert!(matches!(normalize_key(&[]), Err(PasskeyError::BadKey)));
        assert!(matches!(
            normalize_key(&[0x30, 0x00]),
            Err(PasskeyError::BadKey)
        ));
        // A stored key must match its format.
        let rng = SystemRandom::new();
        let p384 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let mut fields = sample(KeyAlgorithm::Es384, p384.as_ref()).fields();
        assert!(parse_stored(&fields, true).is_some());
        fields[0] = reserved(FIELD_FORMAT, PASSKEY_FORMAT.to_owned(), false);
        assert!(parse_stored(&fields, true).is_none());
        fields[0] = reserved(FIELD_FORMAT, "es512-pkcs8-v1".to_owned(), false);
        assert!(parse_stored(&fields, false).is_none());
    }

    /// A stored passkey of `algorithm` with `key`, without extension data.
    fn sample(algorithm: KeyAlgorithm, key: &[u8]) -> StoredPasskey {
        StoredPasskey {
            algorithm,
            rp_id: "example.com".to_owned(),
            credential_id: vec![5; 16],
            user_handle: vec![6],
            user_name: "alice".to_owned(),
            user_display_name: "Alice".to_owned(),
            pkcs8: Zeroizing::new(key.to_vec()),
            prf: None,
            large_blob: None,
        }
    }

    #[test]
    fn prf_outputs_match_a_hand_computed_vector() {
        let secrets = synthetic_prf();
        // Python: salt = sha256(b"WebAuthn PRF\x00" + input);
        // hmac.new(b"\x11" * 32, salt, sha256).
        assert_eq!(
            to_hex(&prf_salt(b"synthetic-prf-first", false).unwrap()),
            "cd013fc41cbd6813cf3cb85942ad6a065c9494fb804bace17b64a3fdf2c330a6"
        );
        let output = prf_output(
            &PasskeyPrfInput {
                first: b"synthetic-prf-first".to_vec(),
                second: Some(b"synthetic-prf-second".to_vec()),
                hashed: false,
            },
            Some(&secrets),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            to_hex(&*output.first),
            "9571da642d67583945aa87b1608cf138bb294b9782c0876b9eb895b8ad5d4e4a"
        );
        assert_eq!(
            to_hex(&**output.second.as_ref().unwrap()),
            "828096fb564983a3471aaf5e933b4ff0a31256b6184a53c2432521647fbeb6ac"
        );
        // A hashed input is the salt.
        let hashed = prf_output(
            &PasskeyPrfInput {
                first: vec![0x22; 32],
                second: None,
                hashed: true,
            },
            Some(&secrets),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            to_hex(&*hashed.first),
            "acfecbc329264d7fdf1f0b9428f9fcd8936da6200960a422170f3d7a97eaed0e"
        );
        assert!(hashed.second.is_none());
        // A hashed input of another length is refused, with or without secrets.
        for secrets in [Some(&secrets), None] {
            let error = prf_output(
                &PasskeyPrfInput {
                    first: vec![0x22; 31],
                    second: None,
                    hashed: true,
                },
                secrets,
            )
            .unwrap_err();
            assert!(
                matches!(error, PasskeyError::Vault(e) if e.kind() == VaultErrorKind::InvalidInput)
            );
        }
        // No secrets: no output.
        let none = prf_output(
            &PasskeyPrfInput {
                first: b"synthetic-prf-first".to_vec(),
                second: None,
                hashed: false,
            },
            None,
        )
        .unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn large_blobs_deflate_and_inflate_exactly() {
        let blob: Vec<u8> = (0..5000u32).map(|n| (n % 251) as u8).collect();
        let data = deflate(&blob).unwrap();
        assert!(data.len() < blob.len());
        assert_eq!(inflate(&data, 5000).unwrap().as_slice(), blob.as_slice());
        // A wrong size, garbage, and a size above the limit give nothing.
        assert!(inflate(&data, 4999).is_none());
        assert!(inflate(&data, 5001).is_none());
        assert!(inflate(&[0xff, 0xff, 0xff], 3).is_none());
        let big = deflate(&vec![0u8; MAX_LARGE_BLOB_BYTES + 1]).unwrap();
        assert!(inflate(&big, (MAX_LARGE_BLOB_BYTES + 1) as u64).is_none());
        // The empty blob has a deflate stream too.
        let empty = deflate(&[]).unwrap();
        assert!(!empty.is_empty());
        assert_eq!(inflate(&empty, 0).unwrap().len(), 0);
    }

    #[test]
    fn bad_optional_fields_are_absent_and_the_key_still_parses() {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let mut stored = sample(KeyAlgorithm::Es256, document.as_ref());
        // Without extension data the rows are the rows of schema 17.
        let plain = stored.fields();
        assert_eq!(plain.len(), 7);
        assert_eq!(plain[0].value.expose(), "es256-pkcs8-v1");
        stored.prf = Some(synthetic_prf());
        let data = deflate(b"synthetic blob").unwrap();
        stored.large_blob = Some(PasskeyLargeBlob {
            data,
            uncompressed_size: 14,
        });
        let fields = stored.fields();
        let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
        assert_eq!(
            &names[7..],
            [
                FIELD_PRF_UV,
                FIELD_PRF_NO_UV,
                FIELD_LARGE_BLOB,
                FIELD_LARGE_BLOB_SIZE
            ]
        );
        let parsed = parse_stored(&fields, true).unwrap();
        assert_eq!(*parsed.prf.as_ref().unwrap().with_uv, [0x11; PRF_BYTES]);
        assert_eq!(*parsed.prf.as_ref().unwrap().without_uv, [0x33; PRF_BYTES]);
        assert_eq!(parsed.large_blob.as_ref().unwrap().uncompressed_size, 14);
        // The list form has no extension data.
        assert!(parse_stored(&fields, false).unwrap().prf.is_none());
        let change = |name: &str, value: &str, secret: bool| -> Vec<Field> {
            fields
                .iter()
                .map(|field| {
                    if field.name == name {
                        reserved(name, value.to_owned(), secret)
                    } else {
                        field.clone()
                    }
                })
                .collect()
        };
        let without = |name: &str| -> Vec<Field> {
            fields
                .iter()
                .filter(|field| field.name != name)
                .cloned()
                .collect()
        };
        let short = b64url_encode(&[0x11; 31]);
        let uv = b64url_encode(&[0x11; 32]);
        for broken in [
            change(FIELD_PRF_UV, &short, true),
            change(FIELD_PRF_UV, "not base64!", true),
            change(FIELD_PRF_UV, &uv, false),
            without(FIELD_PRF_NO_UV),
        ] {
            let parsed = parse_stored(&broken, true).expect("the key still parses");
            assert!(parsed.prf.is_none());
            assert!(parsed.large_blob.is_some());
        }
        for broken in [
            change(FIELD_LARGE_BLOB_SIZE, "014", false),
            change(FIELD_LARGE_BLOB_SIZE, "-1", false),
            change(FIELD_LARGE_BLOB_SIZE, "65537", false),
            change(FIELD_LARGE_BLOB_SIZE, "14", true),
            change(FIELD_LARGE_BLOB, "", true),
            change(FIELD_LARGE_BLOB, "A", true),
            without(FIELD_LARGE_BLOB_SIZE),
        ] {
            let parsed = parse_stored(&broken, true).expect("the key still parses");
            assert!(parsed.large_blob.is_none());
            assert!(parsed.prf.is_some());
        }
        // A bad key is never optional.
        assert!(parse_stored(&change(FIELD_KEY, &short, true), true).is_none());
    }

    #[test]
    fn legacy_names_are_short_and_free() {
        let mut taken = BTreeSet::new();
        let first = legacy_name("passkey_key", &taken);
        assert_eq!(
            crate::vault::custom_detail_label(&first).as_deref(),
            Some("passkey_key")
        );
        taken.insert(first);
        let second = legacy_name("passkey_key", &taken);
        assert_eq!(
            crate::vault::custom_detail_label(&second).as_deref(),
            Some("passkey_key (2)")
        );
        let long = format!("passkey_{}", "a".repeat(56));
        let fallback = legacy_name(&long, &BTreeSet::new());
        assert_eq!(fallback, "legacy_field_1");
        assert!(fallback.len() <= 64);
    }

    fn field(name: &str, value: &str, secret: bool) -> Field {
        Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        }
    }

    /// A schema 16 vault with ordinary fields that have reserved names migrates: the
    /// values and secret flags stay under free names, and the sync version stays.
    #[test]
    fn schema_16_reserved_names_are_renamed_and_values_kept() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("legacy.db");
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let label_key = format!("x_{}", to_hex(b"passkey_key"));
        let id = vault
            .add(ItemDraft {
                title: "Legacy".to_owned(),
                kind: CredentialKind::Custom,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![
                    field("aaa", "SYNTH-plain", false),
                    field("bbb", "SYNTH-secret", true),
                    field(&label_key, "SYNTH-label", false),
                ],
            })
            .unwrap()
            .id;
        let before: (i64, String) = vault
            .conn_ref()
            .unwrap()
            .query_row(
                "SELECT updated_at, updated_by FROM item WHERE id = ?1",
                [id as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        vault.lock().unwrap();
        // Make it a schema 16 file whose owner fields have reserved names.
        let conn = Connection::open_with_flags(&path, super::super::OPEN_EXISTING).unwrap();
        super::super::apply_key(&conn, PASS).unwrap();
        conn.execute_batch(&super::super::schema20::downgrade_sql())
            .unwrap();
        conn.execute_batch(super::super::schema19::DOWNGRADE_TO_18_SQL)
            .unwrap();
        conn.execute_batch(
            "UPDATE sync_device SET applying = 1;
             UPDATE item_field SET name = 'passkey_rp_id' WHERE name = 'aaa';
             UPDATE item_field SET name = 'passkey_key' WHERE name = 'bbb';
             UPDATE sync_device SET applying = 0;
             DROP TABLE folder; DROP TABLE item_folder; DROP TABLE item_policy;
             DROP TABLE declaration_source; DROP TABLE shared_vault; DROP TABLE item_share;
             DROP TABLE vault_secret; DROP TABLE agent_exception; DROP TABLE owner_answer;
             DROP TABLE item_use; DROP TABLE item_origin; DROP TABLE credential_request;
             DROP TABLE correction; DROP TABLE owner_interaction;
             ALTER TABLE agent DROP COLUMN note;
             UPDATE vault_meta SET schema_version = 16 WHERE id = 1;
             PRAGMA user_version = 16;",
        )
        .unwrap();
        super::super::close_conn(conn).unwrap();
        vault.unlock(PASS).unwrap();
        let details = vault.details(id).unwrap();
        let names: Vec<&str> = details.fields.iter().map(|f| f.name.as_str()).collect();
        let rp_label = format!("x_{}", to_hex(b"passkey_rp_id"));
        let key_label = format!("x_{}", to_hex(b"passkey_key (2)"));
        assert_eq!(
            names,
            [rp_label.as_str(), key_label.as_str(), label_key.as_str()]
        );
        assert!(!details.fields[0].secret);
        assert!(details.fields[1].secret);
        assert_eq!(vault.reveal(id, &rp_label).unwrap().expose(), "SYNTH-plain");
        assert_eq!(
            vault.reveal(id, &key_label).unwrap().expose(),
            "SYNTH-secret"
        );
        assert_eq!(
            vault.reveal(id, &label_key).unwrap().expose(),
            "SYNTH-label"
        );
        let after: (i64, String, i64) = vault
            .conn_ref()
            .unwrap()
            .query_row(
                "SELECT updated_at, updated_by, revision FROM item WHERE id = ?1",
                [id as i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((after.0, after.1), before);
        assert_eq!(after.2, 1);
        let version: i64 = vault
            .conn_ref()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, crate::vault::SCHEMA_VERSION);
        assert!(vault.all_passkeys().unwrap().is_empty());
        assert_eq!(
            vault.passkey_info(id).unwrap_err().to_string(),
            err(VaultErrorKind::NotFound).to_string()
        );
    }

    /// Damaged reserved rows of a normal item still hold the credential, so a conflict
    /// copy cannot take it.
    #[test]
    fn damaged_rows_still_claim_their_credential() {
        let stored = StoredPasskey {
            algorithm: KeyAlgorithm::Es256,
            rp_id: "example.com".to_owned(),
            credential_id: vec![5; 16],
            user_handle: vec![6],
            user_name: String::new(),
            user_display_name: String::new(),
            pkcs8: Zeroizing::new(Vec::new()),
            prf: None,
            large_blob: None,
        };
        let mut fields = stored.fields();
        let claimed = Some(("example.com".to_owned(), vec![5; 16]));
        assert_eq!(claimed_credential(&fields), claimed);
        fields.retain(|field| field.name != FIELD_KEY && field.name != FIELD_USER_HANDLE);
        assert!(parse_stored(&fields, false).is_none());
        assert_eq!(claimed_credential(&fields), claimed);
        fields.retain(|field| field.name != FIELD_CREDENTIAL_ID);
        assert_eq!(claimed_credential(&fields), None);
    }

    #[test]
    fn the_stored_key_is_never_listed() {
        let dir = TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("v.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let created = vault
            .create_passkey(PasskeyCreate {
                rp_id: "example.com",
                user_handle: b"user-1",
                user_name: "alice",
                user_display_name: "Alice",
                client_data_hash: &[7; 32],
                algorithms: &[ES256],
                exclude: &[],
                target: PasskeyTarget::NewItem {
                    title: "Example".to_owned(),
                },
            })
            .unwrap();
        let rows = listed_rows(vault.conn_ref().unwrap(), true).unwrap();
        let (_, fields) = rows.get(&(created.item_id as i64)).unwrap();
        let key = fields.iter().find(|f| f.name == FIELD_KEY).unwrap();
        assert_eq!(key.value.expose(), "");
        let all = stored_fields(vault.conn_ref().unwrap(), created.item_id as i64).unwrap();
        assert!(is_valid_passkey(&all));
    }
}
