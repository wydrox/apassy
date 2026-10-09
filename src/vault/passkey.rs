//! Passkeys (schema 17): one WebAuthn ES256 credential on a login item.
//!
//! A passkey is a set of reserved fields on a login item. They sync in the encrypted
//! `item_field` rows like each other field:
//!
//! - `passkey_format`: `es256-pkcs8-v1`.
//! - `passkey_rp_id`: the relying party ID.
//! - `passkey_credential_id`, `passkey_user_handle`: base64url without padding.
//! - `passkey_user_name`, `passkey_user_display_name`: text.
//! - `passkey_key` (secret): the P-256 private key, PKCS #8 v1 with the public point,
//!   base64url without padding.
//!
//! Only this module writes them. Generic add and update refuse them, details and reveal
//! hide them, and update keeps them. Only [`Vault::export_passkey`] returns the private
//! key, for an owner-approved transfer to another provider (Credential Exchange).
//!
//! The raw functions are for the owner only. The platform layer (the iPhone credential
//! provider, the browser bridge) does a fresh owner verification before each create and
//! each assertion, so the authenticator data sets user presence and user verification.
//! The credential is in a vault that syncs, so it is backup eligible (BE). This module
//! cannot see if a copy with the credential is on another device, so backup state (BS)
//! stays clear. The signature counter is always zero, as for each synced credential.
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

use ciborium::value::Value;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use crate::contracts::CredentialKind;

use super::history::{self, EditChange, ItemEventKind};
use super::types::{
    Field, ItemDraft, PASSKEY_FIELD_PREFIX, SecretValue, VaultError, VaultErrorKind, VaultResult,
    err, kind_as_str, validate_draft_with,
};
use super::{Vault, insert_fields, to_hex, to_public_id, to_sql_id, to_sql_revision};

/// The value of `passkey_format`.
pub const PASSKEY_FORMAT: &str = "es256-pkcs8-v1";
/// COSE algorithm ES256: ECDSA with P-256 and SHA-256.
pub const ES256: i64 = -7;
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

/// The detail name prefix of a custom label (see `access::custom_detail_label`).
const DETAIL_PREFIX: &str = "x_";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_AT: u8 = 0x40;
/// UP, UV, BE. BS stays clear (see the module documentation).
const ASSERTION_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_BE;

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

/// The result of an assertion (WebAuthn authenticatorGetAssertion).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// ASN.1 DER ECDSA signature.
    pub signature: Vec<u8>,
}

/// A passkey from another provider. `pkcs8` is a P-256 PKCS #8 v1 key with the public
/// point. Debug does not show the key.
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
            .finish()
    }
}

/// A passkey with its private key, for an owner-approved transfer to another provider.
/// `pkcs8` is the P-256 PKCS #8 v1 key with the public point, in the form that `ring`
/// makes. Debug does not show the key; drop erases it. It has no `Serialize` and no
/// `Clone`, so each copy of the key is explicit.
pub struct PasskeyExport {
    pub info: PasskeyInfo,
    pub pkcs8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PasskeyExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyExport")
            .field("info", &self.info)
            .field("pkcs8", &"[redacted]")
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
    /// The private key is not a valid P-256 PKCS #8 v1 key with its public point.
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

/// A stored passkey. Debug does not show the key; drop erases it.
struct StoredPasskey {
    rp_id: String,
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    user_name: String,
    user_display_name: String,
    pkcs8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for StoredPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredPasskey")
            .field("rp_id", &self.rp_id)
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

impl StoredPasskey {
    /// The reserved fields, in their stored order.
    fn fields(&self) -> Vec<Field> {
        let plain = |name: &str, value: String| Field {
            name: name.to_owned(),
            value: SecretValue::new(value),
            secret: false,
        };
        vec![
            plain(FIELD_FORMAT, PASSKEY_FORMAT.to_owned()),
            plain(FIELD_RP_ID, self.rp_id.clone()),
            plain(FIELD_CREDENTIAL_ID, b64url_encode(&self.credential_id)),
            plain(FIELD_USER_HANDLE, b64url_encode(&self.user_handle)),
            plain(FIELD_USER_NAME, self.user_name.clone()),
            plain(FIELD_USER_DISPLAY_NAME, self.user_display_name.clone()),
            Field {
                name: FIELD_KEY.to_owned(),
                value: SecretValue::new(b64url_encode(&self.pkcs8)),
                secret: true,
            },
        ]
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

/// The private scalar in a PKCS #8 v1 P-256 key that `ring` accepted.
fn private_scalar(pkcs8: &[u8]) -> Option<&[u8]> {
    let (0x30, outer, _) = der_next(pkcs8)? else {
        return None;
    };
    let (0x02, _, rest) = der_next(outer)? else {
        return None;
    };
    let (0x30, _, rest) = der_next(rest)? else {
        return None;
    };
    let (0x04, wrapped, _) = der_next(rest)? else {
        return None;
    };
    let (0x30, ec, _) = der_next(wrapped)? else {
        return None;
    };
    let (0x02, _, rest) = der_next(ec)? else {
        return None;
    };
    let (0x04, scalar, _) = der_next(rest)? else {
        return None;
    };
    (scalar.len() == 32).then_some(scalar)
}

fn key_pair(pkcs8: &[u8]) -> PasskeyResult<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &SystemRandom::new())
        .map_err(|_| PasskeyError::BadKey)
}

/// Check a P-256 PKCS #8 v1 key with its public point, and give it in one form: the
/// form of `ring`, without `parameters` in `ECPrivateKey`. Returns the key and the
/// uncompressed public point.
fn normalize_pkcs8(input: &[u8]) -> PasskeyResult<(Zeroizing<Vec<u8>>, [u8; 65])> {
    let checked = key_pair(input)?;
    let public: [u8; 65] = checked
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| PasskeyError::BadKey)?;
    let scalar = private_scalar(input).ok_or(PasskeyError::BadKey)?;
    let mut key = Zeroizing::new(Vec::with_capacity(PKCS8_BYTES));
    key.extend_from_slice(&PKCS8_PREFIX);
    key.extend_from_slice(scalar);
    key.extend_from_slice(&PKCS8_PUBLIC_PREFIX);
    key.extend_from_slice(&public);
    // The new form must give the same key pair.
    if key.len() != PKCS8_BYTES || key_pair(&key)?.public_key().as_ref() != public.as_slice() {
        return Err(PasskeyError::BadKey);
    }
    Ok((key, public))
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

/// Parse the reserved fields of an item. `check_key` also parses the private key; a
/// list without key values (see [`listed_rows`]) skips that.
fn parse_stored(fields: &[Field], check_key: bool) -> Option<StoredPasskey> {
    let get = |name: &str| fields.iter().find(|field| field.name == name);
    let plain = |name: &str| get(name).filter(|field| !field.secret);
    if plain(FIELD_FORMAT)?.value.expose() != PASSKEY_FORMAT {
        return None;
    }
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
    let pkcs8 = if check_key {
        let raw = Zeroizing::new(b64url_decode(key.value.expose())?);
        let (pkcs8, _) = normalize_pkcs8(&raw).ok()?;
        if *pkcs8 != *raw {
            return None;
        }
        pkcs8
    } else {
        Zeroizing::new(Vec::new())
    };
    Some(StoredPasskey {
        rp_id,
        credential_id,
        user_handle,
        user_name,
        user_display_name,
        pkcs8,
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

/// Reserved rows of login items, without key values: item ID to (title, fields).
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
                    CASE WHEN f.name = '{FIELD_KEY}' THEN '' ELSE f.value END, f.secret
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
            rp_id: request.rp_id.to_owned(),
            credential_id: credential_id.clone(),
            user_handle: request.user_handle.to_vec(),
            user_name: cut_text(request.user_name),
            user_display_name: cut_text(request.user_display_name),
            pkcs8,
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
    /// active item. The caller did a fresh owner verification for this request. The
    /// signature is over the authenticator data and `client_data_hash`.
    ///
    /// `Vault(NotFound)`: the passkey of the item is not canonical (see
    /// [`Vault::all_passkeys`]: archived, a conflict copy of a credential that a normal
    /// item has, or a duplicate), its key does not parse, or it has another RP ID or
    /// credential ID.
    pub fn sign_passkey(
        &self,
        item_id: u64,
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
    ) -> PasskeyResult<PasskeyAssertion> {
        let (stored, _) = self.canonical_stored(item_id)?;
        if stored.rp_id != rp_id || stored.credential_id != credential_id {
            return Err(PasskeyError::kind(VaultErrorKind::NotFound));
        }
        let pair = key_pair(&stored.pkcs8)?;
        let authenticator_data = authenticator_data(rp_id, ASSERTION_FLAGS, None)?;
        let mut message = Vec::with_capacity(authenticator_data.len() + 32);
        message.extend_from_slice(&authenticator_data);
        message.extend_from_slice(client_data_hash);
        let signature = pair
            .sign(&SystemRandom::new(), &message)
            .map_err(storage)?
            .as_ref()
            .to_vec();
        Ok(PasskeyAssertion {
            credential_id: stored.credential_id.clone(),
            user_handle: stored.user_handle.clone(),
            authenticator_data,
            signature,
        })
    }

    /// The passkey of an item with its private key, for an owner-approved transfer to
    /// another provider (Credential Exchange). This is the only path that returns the
    /// key. The caller did a fresh owner verification for the export, and hands the key
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
        Ok(PasskeyExport {
            info,
            pkcs8: stored.pkcs8,
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

    /// Add a passkey from another provider. Returns the item ID.
    ///
    /// - `BadKey`: the key is not a P-256 PKCS #8 v1 key with its public point.
    /// - `Exists`: the vault has this RP ID and credential ID (a conflict copy too), or
    ///   the attach item has a passkey.
    /// - `Vault(InvalidInput)`: a bad RP ID, credential ID, or user handle, or an attach
    ///   item that is not an active login or is a conflict copy (archived or restored).
    pub fn import_passkey(&mut self, import: PasskeyImport) -> PasskeyResult<u64> {
        self.require_unlocked()?;
        if !valid_rp_id(&import.rp_id)
            || !valid_credential_id(&import.credential_id)
            || !valid_user_handle(&import.user_handle)
        {
            return Err(invalid());
        }
        self.refuse_conflict_copy(import.attach)?;
        let (pkcs8, _) = normalize_pkcs8(&import.pkcs8)?;
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
            rp_id: import.rp_id.clone(),
            credential_id: import.credential_id.clone(),
            user_handle: import.user_handle.clone(),
            user_name: cut_text(&import.user_name),
            user_display_name: cut_text(&import.user_display_name),
            pkcs8,
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
        let mut taken: BTreeSet<String> = {
            let mut stmt = tx
                .prepare("SELECT name FROM item_field WHERE item_id = ?1")
                .map_err(storage)?;
            stmt.query_map([item], |row| row.get(0))
                .map_err(storage)?
                .collect::<Result<_, _>>()
                .map_err(storage)?
        };
        for (rowid, name) in fields {
            let new = legacy_name(&name, &taken);
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
            taken.insert(new);
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
        let scalar = private_scalar(raw).unwrap();
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
            rp_id: "example.com".to_owned(),
            credential_id: vec![1],
            user_handle: vec![2],
            user_name: String::new(),
            user_display_name: String::new(),
            pkcs8: Zeroizing::new(b"SYNTH-KEY-BYTES".to_vec()),
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
        };
        let text = format!("{import:?}");
        assert!(
            text.contains("[redacted]") && !text.contains("83, 89"),
            "{text}"
        );
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
        conn.execute_batch(
            "UPDATE sync_device SET applying = 1;
             UPDATE item_field SET name = 'passkey_rp_id' WHERE name = 'aaa';
             UPDATE item_field SET name = 'passkey_key' WHERE name = 'bbb';
             UPDATE sync_device SET applying = 0;
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
        assert_eq!(version, 17);
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
            rp_id: "example.com".to_owned(),
            credential_id: vec![5; 16],
            user_handle: vec![6],
            user_name: String::new(),
            user_display_name: String::new(),
            pkcs8: Zeroizing::new(Vec::new()),
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
