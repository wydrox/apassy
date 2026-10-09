//! The errors of the core (contract section 4): a stable code and a message for the
//! owner. A message never quotes a value, a passphrase, SQL, or a driver error.

use std::fmt;

use apassy::sync::{RelayRefusal, SyncError};
use apassy::vault::{VaultError, VaultErrorKind};

/// An error answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    pub code: &'static str,
    pub message: String,
    /// An iCloud prepare can accept a new key before publication preparation fails.
    pub rekeyed: bool,
}

pub type CoreResult<T> = Result<T, CoreError>;

impl CoreError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            rekeyed: false,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }

    pub fn locked() -> Self {
        Self::new("locked", "The vault is locked.")
    }

    pub fn no_vault() -> Self {
        Self::new("no_vault", "No vault is open on this iPhone.")
    }

    pub fn not_allowed() -> Self {
        Self::new("not_allowed", "AutoFill cannot do this. Open Apassy.")
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }

    pub fn io() -> Self {
        Self::new("io", "A file of the vault cannot be read or written.")
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<VaultErrorKind> for CoreError {
    fn from(kind: VaultErrorKind) -> Self {
        match kind {
            VaultErrorKind::Locked => Self::locked(),
            VaultErrorKind::AlreadyExists => Self::new("io", "A file is in the way of the vault."),
            VaultErrorKind::NotFound => {
                Self::new("not_found", "This item is not in the vault any more.")
            }
            VaultErrorKind::Conflict => Self::new(
                "conflict",
                "This item changed. Open it again to see the new version.",
            ),
            VaultErrorKind::InvalidInput => {
                Self::invalid("Apassy cannot save this. Check the fields.")
            }
            VaultErrorKind::WrongKeyOrCorrupt => Self::new(
                "wrong_passphrase",
                "The passphrase does not open this vault.",
            ),
            VaultErrorKind::UnsupportedSchema => Self::new(
                "unsupported_schema",
                "This vault is from another version of Apassy. Update Apassy on this iPhone and on your Macs.",
            ),
            VaultErrorKind::Busy => Self::new(
                "busy",
                "Apassy uses the vault in another place on this iPhone. Try again in a moment.",
            ),
            VaultErrorKind::Io => Self::io(),
            VaultErrorKind::Storage => Self::new("storage", "The vault file failed a check."),
            VaultErrorKind::Expired => Self::internal("An agent token expired."),
            VaultErrorKind::Damaged => Self::new("damaged", "The copy of the vault fails a check."),
            VaultErrorKind::OtherVault => {
                Self::new("damaged", "The copy holds another vault than this one.")
            }
        }
    }
}

impl From<VaultError> for CoreError {
    fn from(error: VaultError) -> Self {
        error.kind().into()
    }
}

impl From<SyncError> for CoreError {
    fn from(error: SyncError) -> Self {
        match error {
            SyncError::Vault(kind) => kind.into(),
            SyncError::NotEnabled => Self::invalid("Sync is off for this vault."),
            SyncError::AlreadyEnabled => Self::invalid("This vault is on this iPhone already."),
            SyncError::NeedsPassphrase => Self::new(
                "needs_passphrase",
                "The passphrase of this vault changed on a Mac. Type the new passphrase.",
            ),
            SyncError::Damaged => Self::new("damaged", "The copy on the relay fails a check."),
            SyncError::OtherVault => {
                Self::new("damaged", "The copy on the relay holds another vault.")
            }
            SyncError::WrongVault => Self::internal("The vault does not match its sync settings."),
            SyncError::State => Self::new("storage", "The sync state of this vault is damaged."),
            SyncError::Io
            | SyncError::FolderUnavailable
            | SyncError::NotDownloaded
            | SyncError::InvalidName
            | SyncError::TimedOut => Self::io(),
            SyncError::PreconditionFailed | SyncError::RelayBusy | SyncError::Running => Self::new(
                "busy",
                "Another device saves to the relay now. Apassy tries again.",
            ),
            SyncError::RelayUnreachable => Self::new(
                "relay_unreachable",
                "The relay is not reachable. Apassy syncs when it is back.",
            ),
            SyncError::RemovedFromRelay => Self::new(
                "removed",
                "A Mac removed this iPhone from the vault. The vault on this iPhone stays as it is.",
            ),
            SyncError::StaleCopy => Self::new(
                "stale_copy",
                "The relay has an older copy than this iPhone saw.",
            ),
            SyncError::ForkedCopy => Self::new(
                "forked_copy",
                "The relay served a copy that does not include this iPhone's last change.",
            ),
            SyncError::TooLarge => Self::new(
                "too_large",
                "The vault is too large for the relay (64 MiB).",
            ),
            SyncError::InvalidRelayAddress | SyncError::OriginMismatch => Self::new(
                "link_invalid",
                "The relay address in this link is not valid.",
            ),
            SyncError::RelayEmpty => Self::invalid(
                "The relay has no copy of this vault yet. Turn on relay sync for it on the Mac first.",
            ),
            SyncError::SafetyMismatch => Self::new(
                "safety_mismatch",
                "The relay's words differ from this iPhone's. Do not confirm on the Mac. Cancel, and make a new link.",
            ),
            SyncError::Relay(refusal) => refusal.into(),
        }
    }
}

impl From<RelayRefusal> for CoreError {
    fn from(refusal: RelayRefusal) -> Self {
        match refusal {
            RelayRefusal::Forbidden | RelayRefusal::InviteInvalid => Self::new(
                "link_invalid",
                "This link does not work: it was used, it expired, or it is not valid. Make a new link on the Mac.",
            ),
            RelayRefusal::JoinRefused => Self::new(
                "join_refused",
                "The Mac refused this iPhone, or the link expired. Make a new link on the Mac.",
            ),
            RelayRefusal::JoinPending => Self::new("busy", "The Mac did not confirm yet."),
            RelayRefusal::HeadInvalid => {
                Self::new("damaged", "The relay refused the copy of this iPhone.")
            }
            RelayRefusal::TeamLimit => Self::new(
                "rate_limited",
                "The relay takes no more changes this hour. Apassy tries again later.",
            ),
            RelayRefusal::RateLimited => Self::new(
                "rate_limited",
                "The relay asks Apassy to wait. Apassy tries again later.",
            ),
            RelayRefusal::Busy => Self::new(
                "relay_unreachable",
                "The relay is busy. Apassy tries again later.",
            ),
            RelayRefusal::Conflict => {
                Self::new("busy", "The relay is busy with another device. Try again.")
            }
            RelayRefusal::NotFound => Self::new("removed", "The relay does not know this vault."),
            RelayRefusal::InvalidRequest | RelayRefusal::Error => {
                Self::internal("The relay refused the request.")
            }
        }
    }
}
