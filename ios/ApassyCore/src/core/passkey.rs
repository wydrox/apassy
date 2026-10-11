//! Passkeys (passkey v1 contract): the wire of the six `passkey_*` calls and the
//! passkey data of a row, a detail, and an identity. The vault does the cryptography
//! and keeps the key (`apassy::vault::passkey`); this file checks the size and the
//! encoding of every value, maps the errors, and never writes a key into an answer.
//!
//! Every byte value on the wire is standard base64 with padding, as the rest of the
//! iOS wire. An error never quotes an identifier, a handle, or a key.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use apassy::vault::passkey::{
    PasskeyCreate, PasskeyError, PasskeyImport, PasskeyInfo, PasskeyTarget,
};
use apassy::vault::{Vault, VaultErrorKind};

use super::errors::{CoreError, CoreResult};
use super::wire::Secret;

/// The largest request of a passkey call. An import of many accounts is the largest.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// WebAuthn: a credential ID has at most 1023 bytes.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
/// WebAuthn: a user handle has 1 to 64 bytes.
const MAX_USER_HANDLE_BYTES: usize = 64;
const MAX_RP_ID_BYTES: usize = 253;
const MAX_USER_NAME_BYTES: usize = 256;
const MAX_TITLE_BYTES: usize = 128;
/// The size of a PKCS8 P-256 key is about 140 bytes; this is a loose bound.
const MAX_KEY_BYTES: usize = 1024;
/// The credential IDs of an allow list or an exclude list.
const MAX_CREDENTIALS: usize = 256;
const MAX_ALGORITHMS: usize = 32;
const MAX_IMPORT_ACCOUNTS: usize = 1000;

// ---- Base64 (standard alphabet, padding required). ----

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

fn sextet(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode `text` into an erasing buffer, or None when it is not canonical base64: a
/// wrong length, a wrong letter, misplaced padding, or non-zero spare bits. More than
/// `max` decoded bytes is refused before anything is decoded.
fn decode(text: &str, max: usize) -> Option<Zeroizing<Vec<u8>>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) || bytes.len() / 4 * 3 > max + 2 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() / 4 * 3));
    let last = bytes.len() / 4 - 1;
    for (index, quad) in bytes.chunks(4).enumerate() {
        let padding = quad.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 || (padding > 0 && index != last) {
            return None;
        }
        let mut n = 0u32;
        for byte in &quad[..4 - padding] {
            n = (n << 6) | sextet(*byte)?;
        }
        n <<= 6 * padding as u32;
        // The unused low bits of the last sextet are zero.
        if padding > 0 && n & ((1 << (8 * padding)) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..4 - padding]);
    }
    (out.len() <= max).then_some(out)
}

fn bytes_in(text: &str, max: usize, what: &str) -> CoreResult<Vec<u8>> {
    let decoded = decode(text, max).filter(|bytes| !bytes.is_empty());
    decoded
        .map(|bytes| bytes.to_vec())
        .ok_or_else(|| CoreError::invalid(format!("The {what} is not valid.")))
}

fn credential_id_in(text: &str) -> CoreResult<Vec<u8>> {
    bytes_in(text, MAX_CREDENTIAL_ID_BYTES, "passkey ID")
}

fn user_handle_in(text: &str) -> CoreResult<Vec<u8>> {
    bytes_in(text, MAX_USER_HANDLE_BYTES, "passkey user handle")
}

fn client_data_hash_in(text: &str) -> CoreResult<[u8; 32]> {
    decode(text, 32)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| CoreError::invalid("The client data hash is not valid."))
}

fn credential_list_in(list: &[String]) -> CoreResult<Vec<Vec<u8>>> {
    if list.len() > MAX_CREDENTIALS {
        return Err(CoreError::invalid("The request names too many passkeys."));
    }
    list.iter().map(|id| credential_id_in(id)).collect()
}

// ---- Other checks. ----

/// A relying party ID: a host name in ASCII (a punycode label stays ASCII).
fn rp_id_in(rp_id: &str) -> CoreResult<()> {
    let valid = !rp_id.is_empty()
        && rp_id.len() <= MAX_RP_ID_BYTES
        && !rp_id.starts_with(['.', '-'])
        && !rp_id.ends_with(['.', '-'])
        && !rp_id.contains("..")
        && rp_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
    if valid {
        Ok(())
    } else {
        Err(CoreError::invalid(
            "The website of the passkey is not valid.",
        ))
    }
}

/// A user name or a display name: text without control characters, possibly empty.
fn person_in(text: &str, what: &str) -> CoreResult<String> {
    if text.len() > MAX_USER_NAME_BYTES || text.chars().any(char::is_control) {
        return Err(CoreError::invalid(format!("The {what} is not valid.")));
    }
    Ok(text.to_owned())
}

fn title_in(title: &str, rp_id: &str) -> CoreResult<String> {
    let title = title.trim();
    if title.len() > MAX_TITLE_BYTES || title.chars().any(char::is_control) {
        return Err(CoreError::invalid("The item name is not valid."));
    }
    Ok(if title.is_empty() { rp_id } else { title }.to_owned())
}

/// Map the error of the vault. No value of the request is quoted.
fn map_error(error: PasskeyError) -> CoreError {
    match error {
        PasskeyError::Vault(error) => error.into(),
        PasskeyError::Excluded => CoreError::new(
            "excluded",
            "A passkey for this account is in Apassy already.",
        ),
        PasskeyError::NoSupportedAlgorithm => CoreError::new(
            "unsupported_algorithm",
            "Apassy cannot make a passkey with the algorithms of this website.",
        ),
        PasskeyError::Exists => {
            CoreError::new("exists", "A passkey with this ID is in Apassy already.")
        }
        PasskeyError::BadKey => CoreError::new("bad_key", "The key of the passkey is not valid."),
    }
}

// ---- What the app and the extension read. ----

/// A passkey in a list or an identity: no key, ever.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    pub title: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub credential_id: String,
    pub user_handle: String,
}

impl From<&PasskeyInfo> for Entry {
    fn from(info: &PasskeyInfo) -> Self {
        Self {
            id: info.item_id,
            title: info.title.clone(),
            rp_id: info.rp_id.clone(),
            user_name: info.user_name.clone(),
            user_display_name: info.user_display_name.clone(),
            credential_id: encode(&info.credential_id),
            user_handle: encode(&info.user_handle),
        }
    }
}

/// The passkey of an item in its details.
#[derive(Debug, Serialize)]
pub struct Summary {
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub credential_id: String,
    pub user_handle: String,
}

impl From<&PasskeyInfo> for Summary {
    fn from(info: &PasskeyInfo) -> Self {
        Self {
            rp_id: info.rp_id.clone(),
            user_name: info.user_name.clone(),
            user_display_name: info.user_display_name.clone(),
            credential_id: encode(&info.credential_id),
            user_handle: encode(&info.user_handle),
        }
    }
}

/// The passkeys of the active items, in the order of the vault.
pub fn all(vault: &Vault) -> CoreResult<Vec<PasskeyInfo>> {
    vault.all_passkeys().map_err(map_error)
}

/// The passkey of one item, or None for an item without a valid one.
pub fn of_item(vault: &Vault, id: u64) -> CoreResult<Option<PasskeyInfo>> {
    match vault.passkey_info(id) {
        Ok(info) => Ok(Some(info)),
        // The vault answers that an item has no passkey with an error of its own.
        Err(PasskeyError::Vault(error)) if error.kind() == VaultErrorKind::NotFound => Ok(None),
        Err(error) => Err(map_error(error)),
    }
}

/// Whether an existing item holds a genuine passkey, so that its password is optional.
pub fn is_genuine(vault: &Vault, id: u64) -> bool {
    matches!(of_item(vault, id), Ok(Some(_)))
}

// ---- The calls. ----

#[derive(Serialize)]
pub struct Listed {
    pub passkeys: Vec<Entry>,
}

#[derive(Deserialize)]
pub struct ListIn {
    rp_id: String,
    #[serde(default)]
    allowed: Vec<String>,
}

pub fn list(vault: &Vault, request: ListIn) -> CoreResult<Listed> {
    rp_id_in(&request.rp_id)?;
    let allowed = credential_list_in(&request.allowed)?;
    let found = vault
        .passkeys(&request.rp_id, &allowed)
        .map_err(map_error)?;
    Ok(Listed {
        passkeys: found.iter().map(Entry::from).collect(),
    })
}

#[derive(Deserialize)]
pub struct AssertIn {
    id: u64,
    rp_id: String,
    credential_id: String,
    client_data_hash: String,
}

#[derive(Serialize)]
pub struct Asserted {
    pub credential_id: String,
    pub user_handle: String,
    pub authenticator_data: String,
    pub signature: String,
}

pub fn sign(vault: &mut Vault, request: AssertIn) -> CoreResult<Asserted> {
    rp_id_in(&request.rp_id)?;
    let credential_id = credential_id_in(&request.credential_id)?;
    let hash = client_data_hash_in(&request.client_data_hash)?;
    let answer = vault
        .sign_passkey(request.id, &request.rp_id, &credential_id, &hash)
        .map_err(map_error)?;
    Ok(Asserted {
        credential_id: encode(&answer.credential_id),
        user_handle: encode(&answer.user_handle),
        authenticator_data: encode(&answer.authenticator_data),
        signature: encode(&answer.signature),
    })
}

#[derive(Deserialize)]
pub struct RegisterIn {
    rp_id: String,
    user_name: String,
    #[serde(default)]
    user_display_name: String,
    user_handle: String,
    client_data_hash: String,
    #[serde(default)]
    algorithms: Vec<i64>,
    #[serde(default)]
    excluded: Vec<String>,
    #[serde(default)]
    attach_id: Option<u64>,
    #[serde(default)]
    attach_revision: Option<u64>,
    #[serde(default)]
    title: String,
}

#[derive(Serialize)]
pub struct Registered {
    pub id: u64,
    pub credential_id: String,
    pub attestation_object: String,
}

pub fn register(vault: &mut Vault, request: RegisterIn) -> CoreResult<Registered> {
    rp_id_in(&request.rp_id)?;
    let user_name = person_in(&request.user_name, "user name")?;
    let display_name = person_in(&request.user_display_name, "display name")?;
    let user_handle = user_handle_in(&request.user_handle)?;
    let hash = client_data_hash_in(&request.client_data_hash)?;
    if request.algorithms.len() > MAX_ALGORITHMS {
        return Err(CoreError::invalid("The request names too many algorithms."));
    }
    let exclude = credential_list_in(&request.excluded)?;
    let target = match (request.attach_id, request.attach_revision) {
        (Some(item_id), Some(revision)) => PasskeyTarget::Attach { item_id, revision },
        (None, None) => PasskeyTarget::NewItem {
            title: title_in(&request.title, &request.rp_id)?,
        },
        _ => {
            return Err(CoreError::invalid(
                "Adding a passkey to a login needs its id and its revision.",
            ));
        }
    };
    let created = vault
        .create_passkey(PasskeyCreate {
            rp_id: &request.rp_id,
            user_handle: &user_handle,
            user_name: &user_name,
            user_display_name: &display_name,
            client_data_hash: &hash,
            algorithms: &request.algorithms,
            exclude: &exclude,
            target,
        })
        .map_err(map_error)?;
    Ok(Registered {
        id: created.item_id,
        credential_id: encode(&created.credential_id),
        attestation_object: encode(&created.attestation_object),
    })
}

#[derive(Deserialize)]
pub struct ImportIn {
    accounts: Vec<AccountIn>,
}

#[derive(Deserialize)]
struct AccountIn {
    rp_id: String,
    credential_id: String,
    user_handle: String,
    #[serde(default)]
    user_name: String,
    #[serde(default)]
    user_display_name: String,
    key: Secret,
    #[serde(default)]
    title: String,
}

#[derive(Serialize)]
pub struct Imported {
    pub imported: u64,
    pub skipped_existing: u64,
    pub failed: u64,
}

/// What became of one account.
enum Outcome {
    Imported,
    Existing,
    Failed,
}

fn account(vault: &mut Vault, account: AccountIn) -> CoreResult<Outcome> {
    rp_id_in(&account.rp_id)?;
    let import = PasskeyImport {
        credential_id: credential_id_in(&account.credential_id)?,
        user_handle: user_handle_in(&account.user_handle)?,
        user_name: person_in(&account.user_name, "user name")?,
        user_display_name: person_in(&account.user_display_name, "display name")?,
        pkcs8: decode(account.key.expose(), MAX_KEY_BYTES)
            .ok_or_else(|| CoreError::invalid("The key of the passkey is not valid."))?,
        title: title_in(&account.title, &account.rp_id)?,
        attach: None,
        rp_id: account.rp_id,
    };
    Ok(match vault.import_passkey(import) {
        Ok(_) => Outcome::Imported,
        Err(PasskeyError::Exists) => Outcome::Existing,
        Err(_) => Outcome::Failed,
    })
}

/// Import each account on its own: one that fails is counted and the others go on.
/// The answer holds counts only; nothing of a failed account is returned or logged.
pub fn import(vault: &mut Vault, request: ImportIn) -> CoreResult<Imported> {
    if request.accounts.len() > MAX_IMPORT_ACCOUNTS {
        return Err(CoreError::invalid("The import holds too many passkeys."));
    }
    let mut counts = Imported {
        imported: 0,
        skipped_existing: 0,
        failed: 0,
    };
    for entry in request.accounts {
        match account(vault, entry) {
            Ok(Outcome::Imported) => counts.imported += 1,
            Ok(Outcome::Existing) => counts.skipped_existing += 1,
            Ok(Outcome::Failed) | Err(_) => counts.failed += 1,
        }
    }
    Ok(counts)
}

#[derive(Deserialize)]
pub struct RemoveIn {
    id: u64,
    revision: u64,
}

pub fn remove(vault: &mut Vault, request: RemoveIn) -> CoreResult<()> {
    vault
        .remove_passkey(request.id, request.revision)
        .map_err(map_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_refuses_junk() {
        for length in 0..40usize {
            let bytes: Vec<u8> = (0..length).map(|i| (i * 7 + 3) as u8).collect();
            let text = encode(&bytes);
            if bytes.is_empty() {
                assert!(decode(&text, 64).is_none());
            } else {
                assert_eq!(decode(&text, 64).unwrap().as_slice(), bytes.as_slice());
            }
        }
        assert_eq!(encode(b"Ma"), "TWE=");
        for bad in [
            "TWE", "TW==E", "=WE=", "TWF=", "T WE=", "TWE=\n", "TW-_", "TQ=A", "TR==",
        ] {
            assert!(decode(bad, 64).is_none(), "{bad}");
        }
        // Base64url and the unpadded form are not the wire.
        assert!(decode("-_-_", 64).is_none());
        assert!(decode("TQ", 64).is_none());
        assert!(decode(&encode(&[1u8; 65]), 64).is_none());
        assert!(decode(&encode(&[1u8; 64]), 64).is_some());
    }

    #[test]
    fn relying_party_ids_are_hosts() {
        for good in [
            "example.com",
            "a-b.example.co.uk",
            "localhost",
            "xn--mnchen-3ya.de",
        ] {
            assert!(rp_id_in(good).is_ok(), "{good}");
        }
        for bad in [
            "", ".com", "a..b", "-a.com", "a.com.", "a b.com", "a/b.com", "a:1", "ü.de",
        ] {
            assert!(rp_id_in(bad).is_err(), "{bad}");
        }
        assert!(rp_id_in(&"a".repeat(MAX_RP_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn the_values_have_limits() {
        assert!(credential_id_in(&encode(&[1u8; 1023])).is_ok());
        assert!(credential_id_in(&encode(&[1u8; 1024])).is_err());
        assert!(user_handle_in(&encode(&[1u8; 64])).is_ok());
        assert!(user_handle_in(&encode(&[1u8; 65])).is_err());
        assert!(client_data_hash_in(&encode(&[1u8; 32])).is_ok());
        assert!(client_data_hash_in(&encode(&[1u8; 31])).is_err());
        assert!(person_in("tab\there", "user name").is_err());
        assert!(person_in(&"a".repeat(MAX_USER_NAME_BYTES + 1), "user name").is_err());
        assert_eq!(title_in("  ", "example.com").unwrap(), "example.com");
    }
}
