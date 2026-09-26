//! Unlock method: passphrase or Touch ID (goal items A2 and A3, ADR 0010).
//!
//! The master passphrase stays the root key. With Touch ID, the keychain holds a copy
//! of the passphrase in an item with biometric access control for the current
//! fingerprints. The Swift keychain helper applies that access control.
//!
//! Source of truth: the keychain item itself. `keychain_exists` answers without a
//! prompt, so Apassy can read the setting before unlock. The encrypted vault cannot
//! hold the setting, because Apassy needs it before the vault opens. Apassy keeps no
//! preference file: an item that exists means "Touch ID", no item means "passphrase".
//! The item account comes from the canonical vault path
//! ([`crate::native::vault_unlock_account`]), so each vault file has its own setting.
//!
//! Rules:
//! - Setup needs the passphrase now, and the vault must be unlocked (A2).
//! - Backup restore and recovery use the passphrase. A restored file has a new path,
//!   so Touch ID is off for it until the owner turns it on.
//! - After a fingerprint change, the item is not usable. Apassy deletes it, and the
//!   owner unlocks with the passphrase (A3).
//! - Turning Touch ID off deletes the item (A3).
//! - Without a provisioning profile, the keychain helper returns
//!   `keychain_unavailable`. Touch ID can then confirm actions, but cannot unlock.
//!
//! Each function here blocks on the native helper. The app calls them from a worker
//! thread.

use std::path::Path;

use zeroize::Zeroizing;

use crate::broker::SharedVault;
use crate::broker::approvals::touch_id_detail;
use crate::native::{
    HelperErrorCode, KeychainSecret, NativeError, NativeHelper, vault_unlock_account,
};
use crate::vault::{Vault, VaultErrorKind};

/// Text for the Touch ID prompt at unlock. macOS shows it after "Apassy is trying to".
pub const UNLOCK_REASON: &str = "unlock the Apassy vault";

/// The owner text when the keychain helper has no provisioning profile.
pub const KEYCHAIN_UNAVAILABLE_NOTE: &str = "Touch ID can confirm actions, but cannot unlock the vault until the app has a provisioning profile. Unlock with the passphrase.";

/// The owner text after a fingerprint change.
pub const BIOMETRY_CHANGED_NOTE: &str = "The fingerprints on this Mac changed after you turned on Touch ID unlock. Apassy removed the old unlock key. Unlock with the passphrase, then turn on Touch ID unlock again.";

/// The owner text when this build has no keychain helper.
pub const HELPER_MISSING_NOTE: &str = "Touch ID unlock works only in Apassy.app. This build has no keychain helper. Unlock with the passphrase.";

/// The owner text after a passphrase change removed the unlock key.
pub const PASSPHRASE_CHANGED_NOTE: &str = "Touch ID unlock is off, because the passphrase changed. Turn it on again with the new passphrase.";

/// How the owner unlocks this vault file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    Passphrase,
    TouchId,
}

/// The unlock setting of one vault file, read before unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockSetting {
    pub method: UnlockMethod,
    /// Why Touch ID unlock is off or changed. `None` when there is nothing to say.
    pub note: Option<String>,
    /// True when this build can store a Touch ID unlock key.
    pub can_set_up: bool,
}

impl UnlockSetting {
    fn passphrase(note: Option<&str>, can_set_up: bool) -> Self {
        Self {
            method: UnlockMethod::Passphrase,
            note: note.map(str::to_owned),
            can_set_up,
        }
    }
}

/// Read the setting for the vault file at `vault_path` without a prompt. A stale item
/// after a fingerprint change is deleted here.
pub fn read_setting(helper: &NativeHelper, vault_path: &Path) -> UnlockSetting {
    let account = vault_unlock_account(vault_path);
    match helper.keychain_exists(&account) {
        Ok(state) if state.exists && state.biometry_changed => {
            let _ = helper.keychain_delete(&account);
            UnlockSetting::passphrase(Some(BIOMETRY_CHANGED_NOTE), true)
        }
        Ok(state) if state.exists => UnlockSetting {
            method: UnlockMethod::TouchId,
            note: None,
            can_set_up: true,
        },
        Ok(_) => UnlockSetting::passphrase(None, true),
        Err(err) => unavailable_setting(&err),
    }
}

fn unavailable_setting(err: &NativeError) -> UnlockSetting {
    match err {
        NativeError::Helper {
            code: HelperErrorCode::KeychainUnavailable,
            ..
        } => UnlockSetting::passphrase(Some(KEYCHAIN_UNAVAILABLE_NOTE), false),
        NativeError::HelperMissing(_) => {
            UnlockSetting::passphrase(Some(HELPER_MISSING_NOTE), false)
        }
        other => UnlockSetting::passphrase(
            Some(&format!(
                "Apassy could not read the Touch ID unlock setting ({other}). Unlock with the passphrase."
            )),
            true,
        ),
    }
}

/// Why Touch ID did not unlock the vault. The owner can always use the passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TouchIdUnlockError {
    /// The fingerprints changed. Apassy deleted the item.
    BiometryChanged,
    /// No unlock key is in the keychain for this vault file.
    NotSetUp,
    /// The owner or the system cancelled Touch ID.
    Cancelled,
    /// The owner selected "Use Apassy Passphrase".
    UsePassphrase,
    /// Touch ID or the keychain cannot run now.
    Unavailable(String),
    /// The stored key does not open the vault. Apassy deleted the item.
    StaleKey,
    /// Another failure. The text has no secret value.
    Failed(String),
}

impl TouchIdUnlockError {
    /// Text for the owner. Each text ends with the passphrase fallback.
    pub fn message(&self) -> String {
        match self {
            Self::BiometryChanged => BIOMETRY_CHANGED_NOTE.to_owned(),
            Self::NotSetUp => {
                "Touch ID unlock is not set up for this vault file. Unlock with the passphrase."
                    .to_owned()
            }
            Self::Cancelled => "Touch ID was cancelled. Unlock with the passphrase, or try Touch ID again.".to_owned(),
            Self::UsePassphrase => "Unlock with the passphrase.".to_owned(),
            Self::Unavailable(note) => note.clone(),
            Self::StaleKey => "The Touch ID unlock key does not open this vault, for example after a passphrase change. Apassy removed it. Unlock with the passphrase, then turn on Touch ID unlock again.".to_owned(),
            Self::Failed(text) => format!("Touch ID unlock failed ({text}). Unlock with the passphrase."),
        }
    }
}

/// Show the Touch ID prompt and read the unlock key of the vault file at `vault_path`.
/// On `biometry_changed`, delete the stale item.
pub fn read_unlock_key(
    helper: &NativeHelper,
    vault_path: &Path,
) -> Result<Zeroizing<String>, TouchIdUnlockError> {
    let account = vault_unlock_account(vault_path);
    let secret = match helper.keychain_read(&account, UNLOCK_REASON) {
        Ok(secret) => secret,
        Err(err) => {
            return Err(match err.code() {
                Some(HelperErrorCode::BiometryChanged) => {
                    let _ = helper.keychain_delete(&account);
                    TouchIdUnlockError::BiometryChanged
                }
                Some(HelperErrorCode::NotFound) => TouchIdUnlockError::NotSetUp,
                Some(HelperErrorCode::Cancelled) => TouchIdUnlockError::Cancelled,
                Some(HelperErrorCode::Fallback) => TouchIdUnlockError::UsePassphrase,
                Some(HelperErrorCode::KeychainUnavailable) => {
                    TouchIdUnlockError::Unavailable(KEYCHAIN_UNAVAILABLE_NOTE.to_owned())
                }
                Some(
                    code @ (HelperErrorCode::NotAvailable
                    | HelperErrorCode::NotEnrolled
                    | HelperErrorCode::LockedOut),
                ) => TouchIdUnlockError::Unavailable(format!(
                    "Touch ID is not available: {} Unlock with the passphrase.",
                    touch_id_detail(code)
                )),
                _ => match err {
                    NativeError::HelperMissing(_) => {
                        TouchIdUnlockError::Unavailable(HELPER_MISSING_NOTE.to_owned())
                    }
                    other => TouchIdUnlockError::Failed(other.to_string()),
                },
            });
        }
    };
    // The key is the passphrase in UTF-8. The copy erases itself on drop.
    let text = Zeroizing::new(secret.expose().to_vec());
    drop(secret);
    match std::str::from_utf8(&text) {
        Ok(passphrase) => Ok(Zeroizing::new(passphrase.to_owned())),
        Err(_) => {
            let _ = helper.keychain_delete(&account);
            Err(TouchIdUnlockError::StaleKey)
        }
    }
}

/// Call after an unlock with a key from [`read_unlock_key`] failed with a wrong key.
/// The key is stale, so delete it.
pub fn forget_stale_key(helper: &NativeHelper, vault_path: &Path) -> TouchIdUnlockError {
    let _ = helper.keychain_delete(&vault_unlock_account(vault_path));
    TouchIdUnlockError::StaleKey
}

/// Why Touch ID unlock could not be turned on. The text has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupError {
    /// The vault is not open and unlocked.
    VaultLocked,
    /// The field is empty.
    EmptyPassphrase,
    /// The passphrase does not open the vault.
    WrongPassphrase,
    /// No provisioning profile: Touch ID can confirm actions only.
    KeychainUnavailable,
    /// Touch ID cannot run now.
    TouchIdUnavailable(String),
    /// Another failure.
    Failed(String),
}

impl SetupError {
    pub fn message(&self) -> String {
        match self {
            Self::VaultLocked => "Unlock the vault first.".to_owned(),
            Self::EmptyPassphrase => "Type the passphrase to turn on Touch ID unlock.".to_owned(),
            Self::WrongPassphrase => {
                "The passphrase is incorrect. Touch ID unlock stays off.".to_owned()
            }
            Self::KeychainUnavailable => KEYCHAIN_UNAVAILABLE_NOTE.to_owned(),
            Self::TouchIdUnavailable(detail) => {
                format!("Touch ID is not available: {detail} Touch ID unlock stays off.")
            }
            Self::Failed(text) => format!("Touch ID unlock stays off: {text}"),
        }
    }
}

/// Turn on Touch ID unlock for the unlocked vault in `vault` (goal item A2). The owner
/// types the passphrase now. Apassy checks it on a second connection, then stores it
/// in the keychain item. The helper needs Touch ID to work at store time.
pub fn turn_on(
    helper: &NativeHelper,
    vault: &SharedVault,
    passphrase: Zeroizing<String>,
) -> Result<(), SetupError> {
    if passphrase.is_empty() {
        return Err(SetupError::EmptyPassphrase);
    }
    let path = {
        let guard = vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.as_ref() {
            Some(open) if !open.is_locked() => open.path().to_path_buf(),
            _ => return Err(SetupError::VaultLocked),
        }
    };
    match Vault::verify_passphrase_at(&path, &passphrase) {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                VaultErrorKind::WrongKeyOrCorrupt | VaultErrorKind::InvalidInput
            ) =>
        {
            return Err(SetupError::WrongPassphrase);
        }
        Err(err) => return Err(SetupError::Failed(err.to_string())),
    }
    let secret = KeychainSecret::new(passphrase.as_bytes().to_vec())
        .map_err(|err| SetupError::Failed(err.to_string()))?;
    drop(passphrase);
    helper
        .keychain_store(&vault_unlock_account(&path), &secret)
        .map_err(|err| match err.code() {
            Some(HelperErrorCode::KeychainUnavailable) => SetupError::KeychainUnavailable,
            Some(
                code @ (HelperErrorCode::NotAvailable
                | HelperErrorCode::NotEnrolled
                | HelperErrorCode::LockedOut),
            ) => SetupError::TouchIdUnavailable(touch_id_detail(code).to_owned()),
            _ => match err {
                NativeError::HelperMissing(_) => SetupError::Failed(HELPER_MISSING_NOTE.to_owned()),
                other => SetupError::Failed(other.to_string()),
            },
        })
}

/// Turn off Touch ID unlock for the vault file at `vault_path` (goal item A3). Returns
/// true when an item was deleted.
pub fn turn_off(helper: &NativeHelper, vault_path: &Path) -> Result<bool, String> {
    helper
        .keychain_delete(&vault_unlock_account(vault_path))
        .map_err(|err| err.to_string())
}
