//! The Credential Exchange export (`credential_export`): the active logins of the vault
//! with their password, one-time password, and passkey, for the system transfer UI of
//! iOS (`ASCredentialExportManager`). The app calls it after a fresh owner check and
//! hands the answer straight over. Nothing is written to a file here.
//!
//! The values stay in erasing buffers until the answer is written, and none of these
//! types has `Debug`. The password comes from the generic `reveal`, the one-time
//! password from the shared `apassy::otp::Totp`, and the passkey key from the one
//! dedicated vault call, `Vault::export_passkey`: the generic reveal never shows it.
//! One history event without values records each exported item.
//!
//! The scope is the active logins that are not conflict copies, and each restored
//! conflict copy whose passkey is canonical (see `Vault::all_passkeys`): no normal
//! login has the credential, and the copy has the lowest ID of the restored copies
//! with it. That copy goes once, as a whole login. Other kinds and logins with nothing
//! to export count in `skipped`. An archived item or another conflict copy is not
//! counted.

use std::collections::BTreeSet;

use serde::Serialize;
use zeroize::Zeroizing;

use apassy::otp::{Algorithm, Totp, is_totp_uri};
use apassy::vault::passkey::PasskeyError;
use apassy::vault::{Vault, VaultErrorKind};

use super::errors::{CoreError, CoreResult};
use super::items::{self, Archived};
use super::passkey::encode;
use super::wire::zeroizing;

#[derive(Serialize)]
pub struct Exported {
    pub items: Vec<Export>,
    pub skipped: u32,
}

#[derive(Serialize)]
pub struct Export {
    id: u64,
    title: String,
    notes: String,
    tags: Vec<String>,
    created_at: Option<i64>,
    changed_at: Option<i64>,
    username: Option<String>,
    #[serde(serialize_with = "optional")]
    password: Option<Zeroizing<String>>,
    websites: Vec<String>,
    totp: Option<TotpExport>,
    passkey: Option<PasskeyExport>,
}

#[derive(Serialize)]
struct TotpExport {
    #[serde(serialize_with = "zeroizing")]
    secret: Zeroizing<String>,
    period: u16,
    digits: u16,
    algorithm: &'static str,
    issuer: Option<String>,
    user: Option<String>,
}

#[derive(Serialize)]
struct PasskeyExport {
    rp_id: String,
    credential_id: String,
    user_handle: String,
    user_name: String,
    user_display_name: String,
    #[serde(serialize_with = "zeroizing")]
    key: Zeroizing<String>,
}

fn optional<S: serde::Serializer>(
    value: &Option<Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(text) => serializer.serialize_str(text),
        None => serializer.serialize_none(),
    }
}

/// A plain or secret value of a login, or None when the field is not there or empty.
fn value(vault: &Vault, id: u64, name: &str) -> CoreResult<Option<Zeroizing<String>>> {
    match vault.reveal(id, name) {
        Ok(value) if value.expose().is_empty() => Ok(None),
        Ok(value) => Ok(Some(Zeroizing::new(value.expose().to_owned()))),
        Err(error) if error.kind() == VaultErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Sha1 => "sha1",
        Algorithm::Sha256 => "sha256",
        Algorithm::Sha512 => "sha512",
    }
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = text.get(at + 1..at + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(if bytes[at] == b'+' { b' ' } else { bytes[at] });
            at += 1;
        }
    }
    String::from_utf8(out).ok().filter(|text| !text.is_empty())
}

/// The issuer and the account of an `otpauth://totp/Issuer:account?issuer=…` label. A
/// bare secret has neither. The secret itself is the business of `apassy::otp`.
fn label(stored: &str) -> (Option<String>, Option<String>) {
    if !is_totp_uri(stored) {
        return (None, None);
    }
    let rest = stored.trim().split_once("://").map_or("", |(_, rest)| rest);
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let path = path.split_once('/').map_or("", |(_, path)| path);
    let param = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| name.eq_ignore_ascii_case("issuer"))
        .and_then(|(_, issuer)| percent_decode(issuer));
    let decoded = percent_decode(path);
    let (prefix, user) = match decoded.as_deref().and_then(|text| text.split_once(':')) {
        Some((prefix, user)) => (Some(prefix.trim().to_owned()), user.trim().to_owned()),
        None => (None, decoded.unwrap_or_default().trim().to_owned()),
    };
    let issuer = param.or(prefix).filter(|issuer| !issuer.is_empty());
    (issuer, Some(user).filter(|user| !user.is_empty()))
}

/// The first one-time password of the item that Apassy can read. A counter-based or
/// unreadable one is not exported.
fn totp_of(vault: &Vault, details: &apassy::vault::ItemDetails) -> CoreResult<Option<TotpExport>> {
    for name in items::totp_fields(vault, details)? {
        let Some(stored) = value(vault, details.summary.id, &name)? else {
            continue;
        };
        let Ok(totp) = Totp::parse(&stored) else {
            continue;
        };
        let (Ok(period), Ok(digits)) = (u16::try_from(totp.period()), u16::try_from(totp.digits()))
        else {
            continue;
        };
        let (issuer, user) = label(&stored);
        return Ok(Some(TotpExport {
            secret: Zeroizing::new(encode(totp.setup_key_bytes())),
            period,
            digits,
            algorithm: algorithm_name(totp.algorithm()),
            issuer,
            user,
        }));
    }
    Ok(None)
}

/// The passkey of an item with its key, or None when the vault has no usable one. A
/// failure of the vault itself is an error: an export never drops data in silence.
fn passkey_of(vault: &Vault, id: u64) -> CoreResult<Option<PasskeyExport>> {
    match vault.export_passkey(id) {
        Ok(export) => Ok(Some(PasskeyExport {
            rp_id: export.info.rp_id.clone(),
            credential_id: encode(&export.info.credential_id),
            user_handle: encode(&export.info.user_handle),
            user_name: export.info.user_name.clone(),
            user_display_name: export.info.user_display_name.clone(),
            key: Zeroizing::new(encode(&export.pkcs8)),
        })),
        Err(PasskeyError::Vault(error)) if error.kind() == VaultErrorKind::NotFound => Ok(None),
        // A stored key that is not a key is not exported; the other data still is.
        Err(PasskeyError::BadKey) => Ok(None),
        Err(PasskeyError::Vault(error)) => Err(error.into()),
        Err(_) => Err(CoreError::internal("The passkey cannot be exported.")),
    }
}

pub fn export(vault: &mut Vault) -> CoreResult<Exported> {
    let copies = vault.conflict_copies()?;
    // The items of the canonical passkeys: a restored copy here holds the only entry
    // of its credential.
    let canonical: BTreeSet<u64> = match vault.all_passkeys() {
        Ok(list) => list.into_iter().map(|info| info.item_id).collect(),
        Err(PasskeyError::Vault(error)) => return Err(error.into()),
        Err(_) => return Err(CoreError::internal("The passkeys cannot be read.")),
    };
    let mut exports = Vec::new();
    let mut skipped = 0u32;
    for row in items::rows(vault, Archived::No)? {
        if copies.contains_key(&row.id) && !canonical.contains(&row.id) {
            continue;
        }
        if row.kind != "login" {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let details = vault.details(row.id)?;
        let username = value(vault, row.id, "username")?;
        let password = value(vault, row.id, "password")?;
        let totp = totp_of(vault, &details)?;
        let passkey = if row.has_passkey {
            passkey_of(vault, row.id)?
        } else {
            None
        };
        if username.is_none() && password.is_none() && totp.is_none() && passkey.is_none() {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let time = |at: Option<u64>| at.and_then(|at| i64::try_from(at).ok());
        exports.push(Export {
            id: row.id,
            title: row.title,
            notes: details.notes,
            tags: row.tags,
            created_at: time(row.added_at),
            changed_at: time(row.changed_at),
            username: username.map(|name| name.to_string()),
            password,
            websites: row.websites,
            totp,
            passkey,
        });
    }
    // One event per item that leaves, before the answer does.
    for export in &exports {
        vault.record_export(export.id)?;
    }
    Ok(Exported {
        items: exports,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::marker::PhantomData;

    use super::{Export, Exported, PasskeyExport, TotpExport, label};

    /// Whether `T: Debug`, decided at compile time: the inherent constant wins when the
    /// bound holds, the trait constant is the fallback.
    struct Probe<T>(PhantomData<T>);
    trait Fallback {
        const IS_DEBUG: bool = false;
    }
    impl<T> Fallback for Probe<T> {}
    impl<T: Debug> Probe<T> {
        const IS_DEBUG: bool = true;
    }

    #[test]
    fn nothing_that_holds_a_value_has_debug() {
        const { assert!(!Probe::<Exported>::IS_DEBUG) };
        const { assert!(!Probe::<Export>::IS_DEBUG) };
        const { assert!(!Probe::<TotpExport>::IS_DEBUG) };
        const { assert!(!Probe::<PasskeyExport>::IS_DEBUG) };
        // The probe sees a type that has Debug.
        const { assert!(Probe::<String>::IS_DEBUG) };
    }

    #[test]
    fn the_label_gives_issuer_and_account() {
        assert_eq!(
            label("otpauth://totp/Example:me%40example.test?secret=ABC&issuer=Other"),
            (Some("Other".to_owned()), Some("me@example.test".to_owned()))
        );
        assert_eq!(
            label("otpauth://totp/Example:me?secret=ABC"),
            (Some("Example".to_owned()), Some("me".to_owned()))
        );
        assert_eq!(
            label("otpauth://totp/me?secret=ABC"),
            (None, Some("me".to_owned()))
        );
        assert_eq!(label("GEZDGNBVGY3TQOJQ"), (None, None));
        assert_eq!(label("otpauth://totp/?secret=ABC"), (None, None));
    }
}
