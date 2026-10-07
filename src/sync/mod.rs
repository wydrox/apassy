//! Sync of a vault through a folder (ADR 0014, `docs/operations/sync.md`) or through the
//! Apassy relay (ADR 0022, contract `docs/contracts/relay-sync-v1.md`).
//!
//! The owner picks a folder that a sync service keeps in step on each Mac: iCloud Drive
//! (the default), Dropbox, Google Drive, OneDrive, Syncthing, or a network share. The
//! folder holds `<name>.apassy`, a closed, encrypted copy of the vault without the data
//! that stays on each Mac (agents, grants, activity, learning). The live vault stays a
//! local file; SQLite never opens a file in the synced folder.
//!
//! - A sync (vault unlocked) reads the synced file through a private local copy and
//!   merges it record by record into the vault with the key of the open connection
//!   ([`crate::vault::Vault::merge_from`]). A credential that both sides changed stays
//!   twice: the older version becomes an archived conflict copy. Then, when the vault
//!   has content that the file does not have, the sync pushes: it writes a stripped copy
//!   in the data folder, copies it to `<name>.apassy.push.nosync` in the synced folder,
//!   syncs it, and renames it to `<name>.apassy`.
//! - A status needs no key: it compares the hash of the file with the hash after the
//!   last sync.
//! - A copy that does not open with the key of the vault means that the passphrase
//!   changed on another Mac. The owner types the new passphrase once
//!   ([`FolderSync::take_new_passphrase`]).
//!
//! The engine does not know the vault list. The caller gives each path in
//! [`SyncConfig`]. One sync covers one [`SyncScope`]: now the whole vault.
//!
//! The bytes move through a transport ([`SyncTransport`]): a folder
//! ([`FolderTransport`]) or the relay ([`RelayTransport`], [`RelaySync`]). The relay
//! stores one opaque, device-signed, versioned copy per vault and does a
//! compare-and-swap on its version.

mod directory;
mod folder;
mod relay;
mod relay_crypto;
mod relay_http;
mod state;
mod transport;

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub use folder::{
    FOLDER_NAME, FolderEntry, PUSH_SUFFIX, SYNC_FILE_EXTENSION, SyncFolder, detect_folders_in,
    file_name_for, list_folder_vaults, start_download,
};
pub use relay::{
    DeviceView, JoinedDevice, KeySource, LinkCode, PendingJoin, PendingLink, Receipt,
    RelayAdoptReport, RelayConfig, RelayDownload, RelayEnableReport, RelayPoll, RelaySync,
    RelayTransport, clear_relay_work,
};
pub use relay_crypto::{
    DeviceKey, HeadFields, MAX_SNAPSHOT_BYTES, NO_PREVIOUS, SignedHead, WORDS, decode_b64u,
    encode_b64u, head_hash, link_code_team, safety_words, same_words, sha256_hex, sign_in_message,
    valid_team_code, verify_signature,
};
pub use relay_http::{DEFAULT_RELAY_URL, RelayUrl};
pub use state::{SyncState, TransportKind};
pub use transport::{FolderTransport, Precondition, Remote, RemoteHead, SyncTransport, Transport};

use crate::vault::{
    MergeReport, SyncIdentity, SyncScope, Vault, VaultError, VaultErrorKind, copy_hashing,
    hash_open_file, to_hex,
};
use folder::Probe;
use transport::RemoteHead as Head;

/// Enable tries at most this many file names (`Personal.apassy`, `Personal-2.apassy`,
/// ...).
const MAX_NAME_TRIES: u32 = 99;

/// The home directory, or `None` when `HOME` is not set.
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// The Apassy folder in iCloud Drive:
/// `$HOME/Library/Mobile Documents/com~apple~CloudDocs/Apassy`. The folder may not
/// exist yet. `None` on a system without iCloud Drive, or when `HOME` is not set.
#[cfg(target_os = "macos")]
pub fn icloud_folder() -> Option<PathBuf> {
    home().map(|home| folder::icloud_drive(&home).join(FOLDER_NAME))
}

/// There is no iCloud Drive on this system.
#[cfg(not(target_os = "macos"))]
pub fn icloud_folder() -> Option<PathBuf> {
    None
}

/// The synced folders of the owner: iCloud Drive, the folders of
/// `~/Library/CloudStorage`, and `~/Dropbox`, when they exist.
pub fn detect_folders() -> Vec<SyncFolder> {
    try_detect_folders().unwrap_or_default()
}

/// Discover synced folders, with an error if the sync service does not respond.
pub fn try_detect_folders() -> Result<Vec<SyncFolder>, SyncError> {
    home().map_or_else(
        || Ok(Vec::new()),
        |home| folder::try_detect_folders_in(&home),
    )
}

/// The name of this computer for the sync record: `scutil --get ComputerName` on macOS,
/// else the host name, else "Unknown device". Read once for each process.
pub fn device_name() -> String {
    static NAME: OnceLock<String> = OnceLock::new();
    NAME.get_or_init(read_device_name).clone()
}

fn read_device_name() -> String {
    let clean = |text: &str| {
        let text: String = text.trim().chars().filter(|ch| !ch.is_control()).collect();
        (!text.is_empty()).then_some(text)
    };
    let command = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|text| clean(&text))
    };
    if cfg!(target_os = "macos")
        && let Some(name) = command("/usr/sbin/scutil", &["--get", "ComputerName"])
    {
        return name;
    }
    if let Some(name) = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .and_then(|text| clean(&text))
    {
        return name;
    }
    command("/bin/hostname", &[]).unwrap_or_else(|| "Unknown device".to_owned())
}

/// The paths for the sync of one vault. The engine does not change them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConfig {
    /// The live local vault file.
    pub vault_path: PathBuf,
    /// The synced folder that holds `<name>.apassy`.
    pub folder: PathBuf,
    /// The local sync state file (JSON). Keep it in the Apassy data folder, which the
    /// Seatbelt profile denies.
    pub state_path: PathBuf,
    /// A private folder for the copies that a merge reads and a push strips. Keep it in
    /// the Apassy data folder.
    pub work_dir: PathBuf,
}

impl SyncConfig {
    /// The usual layout: the state file `<data_dir>/sync/<state_name>.json`, and the
    /// work folder `<data_dir>/sync`.
    pub fn in_data_dir(
        data_dir: &Path,
        vault_path: &Path,
        folder: &Path,
        state_name: &str,
    ) -> Self {
        let dir = data_dir.join("sync");
        Self {
            vault_path: vault_path.to_owned(),
            folder: folder.to_owned(),
            state_path: dir.join(format!("{state_name}.json")),
            work_dir: dir,
        }
    }
}

/// The state of the synced file, from the files only (no key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// The file is as after the last sync.
    UpToDate,
    /// Another Mac changed the file. A sync merges it.
    Changed,
    /// The folder has no file. A sync writes it again.
    Missing,
    /// The file is in iCloud but not on this Mac yet ([`FolderSync::request_download`]).
    NotDownloaded,
    /// The folder is not there: the drive, the share, or the sync service is away.
    FolderUnavailable,
}

/// The result of [`FolderSync::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub status: FileStatus,
    /// The synced file name, for example `Personal.apassy`.
    pub file_name: String,
    /// The path of the synced file.
    pub file_path: PathBuf,
    /// Duplicates that iCloud made next to the file (`Personal 2.apassy`, ...). Apassy
    /// does not use them.
    pub duplicates: Vec<String>,
    /// The time of the last sync, in Unix seconds.
    pub last_sync_at: Option<u64>,
}

/// What a sync did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub file_name: String,
    /// The merge of the synced file, when it had changed.
    pub merge: Option<MergeReport>,
    /// Whether the sync wrote the synced file.
    pub pushed: bool,
}

/// The result of [`FolderSync::enable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableReport {
    /// The synced file name.
    pub file_name: String,
    /// `true` when the file of this vault was in the folder already and the vault
    /// merged with it. `false` when enable wrote a new file.
    pub linked: bool,
    pub outcome: SyncOutcome,
}

/// The result of [`FolderSync::adopt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptReport {
    pub file_name: String,
    /// The sync record of the copy: its last writer.
    pub identity: SyncIdentity,
}

/// A sync failure. The text is for the owner and has no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    /// Sync is off for this vault (no state file).
    NotEnabled,
    /// Sync is already on for this vault.
    AlreadyEnabled,
    /// The folder is not there.
    FolderUnavailable,
    /// The synced file is not downloaded to this Mac yet.
    NotDownloaded,
    /// The synced file does not open with the key of the vault: its passphrase changed
    /// on another Mac.
    NeedsPassphrase,
    /// The synced file opens but fails a check.
    Damaged,
    /// The synced file holds another vault.
    OtherVault,
    /// The vault does not match the sync settings (another path or vault ID).
    WrongVault,
    /// The file name is not valid, or enable found no free name.
    InvalidName,
    /// The sync state file is damaged.
    State,
    /// A vault operation failed.
    Vault(VaultErrorKind),
    /// A file operation failed.
    Io,
    /// The synced folder did not finish a directory flush within the time limit.
    TimedOut,
    /// Another Mac pushed to the relay first. The engine fetches, merges, and pushes
    /// again.
    PreconditionFailed,
    /// Three pushes in a row lost to another Mac. The next sync tries again.
    RelayBusy,
    /// The relay does not answer, or something else answers in its place.
    RelayUnreachable,
    /// The relay refuses the device of this Mac: it was removed.
    RemovedFromRelay,
    /// The relay serves an older copy than this Mac saw.
    StaleCopy,
    /// The relay serves a copy whose chain does not include this Mac's last change.
    ForkedCopy,
    /// Another sync of this vault runs now. The next sync tries again.
    Running,
    /// The copy is larger than the relay takes (64 MiB).
    TooLarge,
    /// The relay address is not `https://`, or `http://` with a port on this computer.
    InvalidRelayAddress,
    /// The relay calls itself by another address than the settings.
    OriginMismatch,
    /// The relay has no copy of this vault yet.
    RelayEmpty,
    /// The safety words of the relay differ from the ones that this Mac computes.
    SafetyMismatch,
    /// The relay refused a request.
    Relay(RelayRefusal),
}

/// Why the relay refused a request (contract relay-sync-v1, section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRefusal {
    /// `400 invalid_request`.
    InvalidRequest,
    /// `403 forbidden`: a link code that is not valid, was used, or expired.
    Forbidden,
    /// `403 invite_invalid`: a team code that is wrong, used, or expired.
    InviteInvalid,
    /// `403 join_pending`: the other Mac has not confirmed yet.
    JoinPending,
    /// `403 join_refused`: the other Mac refused, or the link expired.
    JoinRefused,
    /// `403 sync_head_invalid`: the relay refused the head of a push.
    HeadInvalid,
    /// `403 team_limit`: the pushes of this hour are used up.
    TeamLimit,
    /// `404 not_found`.
    NotFound,
    /// `409 conflict`.
    Conflict,
    /// `429 rate_limited`.
    RateLimited,
    /// `503 busy` after the retries.
    Busy,
    /// Another error of the relay.
    Error,
}

impl fmt::Display for RelayRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "the relay refused a malformed request",
            Self::Forbidden => {
                "this link does not work. Another device may have used it. Make a new link on the other Mac"
            }
            Self::InviteInvalid => "the team code is wrong, used, or expired",
            Self::JoinPending => "the other Mac has not confirmed this Mac yet",
            Self::JoinRefused => "the other Mac refused, or the link expired",
            Self::HeadInvalid => "the relay refused the signed head of this push",
            Self::TeamLimit => "the relay limits the pushes of this vault for this hour",
            Self::NotFound => "the relay does not have this item",
            Self::Conflict => {
                "the relay's record of this Mac does not match. Nothing was added"
            }
            Self::RateLimited => "the relay asks to wait a minute",
            Self::Busy => "the relay is busy. Apassy tries again",
            Self::Error => "the relay had an error",
        })
    }
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnabled => f.write_str("sync is off for this vault"),
            Self::AlreadyEnabled => f.write_str("sync is already on for this vault"),
            Self::FolderUnavailable => f.write_str("the synced folder is not available"),
            Self::NotDownloaded => {
                f.write_str("the synced file is not on this Mac yet; wait for the download")
            }
            Self::NeedsPassphrase => f.write_str(
                "the synced file has another passphrase: the passphrase changed on another Mac",
            ),
            Self::Damaged => f.write_str("the synced file is damaged"),
            Self::OtherVault => f.write_str("the synced file holds another vault"),
            Self::WrongVault => f.write_str("the vault does not match its sync settings"),
            Self::InvalidName => f.write_str("the name of the synced file is not valid"),
            Self::State => f.write_str("the sync state file is damaged"),
            Self::Vault(kind) => fmt::Display::fmt(&VaultError::new(*kind), f),
            Self::Io => f.write_str("a file operation for sync failed"),
            Self::TimedOut => f.write_str(
                "the synced folder did not respond in time. The local vault is safe. Check the sync service and try again",
            ),
            Self::PreconditionFailed => f.write_str("another Mac pushed to the relay first"),
            Self::RelayBusy => {
                f.write_str("the relay is busy with another Mac. Apassy tries again")
            }
            Self::RelayUnreachable => {
                f.write_str("relay not reachable. Apassy syncs when it is back")
            }
            Self::RemovedFromRelay => f.write_str(
                "removed from the relay. This Mac keeps its vault. Turn relay sync off, then join again with a link from another Mac",
            ),
            Self::StaleCopy => f.write_str(
                "the relay has an older copy than this Mac saw. To go on, select “Use the relay copy…” in Settings > General > Sync",
            ),
            Self::ForkedCopy => f.write_str(
                "the relay served a copy that does not include this Mac's last change. To go on, select “Use the relay copy…” in Settings > General > Sync",
            ),
            Self::Running => f.write_str("another sync of this vault runs now. Apassy tries again"),
            Self::TooLarge => f.write_str("the vault is too large for the relay (64 MiB)"),
            Self::InvalidRelayAddress => f.write_str(
                "the relay address is not valid. Use https://, or http:// with a port on this computer",
            ),
            Self::OriginMismatch => {
                f.write_str("the relay calls itself by another address than the settings say")
            }
            Self::RelayEmpty => f.write_str(
                "the relay has no copy of this vault yet. Turn on relay sync on the other Mac first",
            ),
            Self::SafetyMismatch => f.write_str(
                "the relay's words differ from this Mac's. Cancel and make a new link",
            ),
            Self::Relay(refusal) => fmt::Display::fmt(refusal, f),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<VaultError> for SyncError {
    fn from(vault_err: VaultError) -> Self {
        match vault_err.kind() {
            VaultErrorKind::Damaged => Self::Damaged,
            VaultErrorKind::OtherVault => Self::OtherVault,
            kind => Self::Vault(kind),
        }
    }
}

/// The error of a read of the synced file with the key of the vault.
fn copy_error(vault_err: VaultError) -> SyncError {
    match vault_err.kind() {
        VaultErrorKind::WrongKeyOrCorrupt => SyncError::NeedsPassphrase,
        _ => SyncError::from(vault_err),
    }
}

/// A file that Apassy removes on drop unless it is kept.
struct TempFile {
    path: PathBuf,
    keep: bool,
}

impl TempFile {
    fn new(path: PathBuf) -> Result<Self, SyncError> {
        state::remove_if_present(&path)?;
        Ok(Self { path, keep: false })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Sync of one vault through a folder.
#[derive(Debug, Clone)]
pub struct FolderSync {
    config: SyncConfig,
    scope: SyncScope,
}

impl FolderSync {
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            scope: SyncScope::vault(),
        }
    }

    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// The local sync state. `None` when sync is off.
    pub fn state(&self) -> Result<Option<SyncState>, SyncError> {
        state::read(&self.config.state_path)
    }

    /// The folder state. A relay state belongs to [`RelaySync`].
    fn require_state(&self) -> Result<SyncState, SyncError> {
        self.state()?
            .filter(|state| state.transport == TransportKind::Folder)
            .ok_or(SyncError::NotEnabled)
    }

    /// The transport of the synced file `name` in the folder of the config.
    pub fn transport(&self, name: &str) -> FolderTransport {
        FolderTransport::new(&self.config.folder, name)
    }

    /// Write the state with the path of the local vault file and the time.
    fn write_state(&self, state: &SyncState) -> Result<(), SyncError> {
        let mut state = state.clone();
        state.vault_path = Some(
            fs::canonicalize(&self.config.vault_path)
                .unwrap_or_else(|_| self.config.vault_path.clone()),
        );
        state.folder = Some(self.config.folder.clone());
        state.last_sync_at = Some(unix_now());
        state::write(&self.config.state_path, &state)
    }

    /// The state of the synced file. No key, no change to any file.
    pub fn status(&self) -> Result<StatusReport, SyncError> {
        let sync = self.clone();
        directory::read(move || sync.status_inner())
    }

    fn status_inner(&self) -> Result<StatusReport, SyncError> {
        let state = self.require_state()?;
        let name = &state.file_name;
        let probe = folder::probe_inner(&self.config.folder, name)?;
        let duplicates = match probe {
            Probe::Unavailable | Probe::NoFolder => Vec::new(),
            _ => folder::duplicates_of(&self.config.folder, name)?,
        };
        let status = match &probe {
            Probe::Unavailable => FileStatus::FolderUnavailable,
            Probe::NoFolder | Probe::Missing => FileStatus::Missing,
            Probe::Evicted(_) => FileStatus::NotDownloaded,
            Probe::Present(path) => {
                if Some(hash_path(path)?) == state.last_file_sha256 {
                    FileStatus::UpToDate
                } else {
                    FileStatus::Changed
                }
            }
        };
        Ok(StatusReport {
            status,
            file_name: name.clone(),
            file_path: self.config.folder.join(name),
            duplicates,
            last_sync_at: state.last_sync_at,
        })
    }

    /// Whether the vault has synced content that the last sync did not see: a change of
    /// a credential, not agent activity. The vault must be unlocked.
    pub fn local_changed(&self, vault: &Vault) -> Result<bool, SyncError> {
        let state = self.require_state()?;
        let content = to_hex(&vault.sync_content(&self.scope)?);
        Ok(state.last_content.as_deref() != Some(content.as_str()))
    }

    /// Ask iCloud Drive to download the synced file. Returns whether the request
    /// started.
    pub fn request_download(&self) -> Result<bool, SyncError> {
        let state = self.require_state()?;
        Ok(start_download(&self.config.folder.join(&state.file_name)))
    }

    /// Sync the unlocked vault: merge the synced file when it changed, then push when
    /// the vault has content that the file does not have. A missing file is written
    /// again. The vault stays unlocked.
    pub fn sync(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        self.sync_with(vault, &mut state)
    }

    fn sync_with(
        &self,
        vault: &mut Vault,
        state: &mut SyncState,
    ) -> Result<SyncOutcome, SyncError> {
        self.sync_with_directory_sync(vault, state, directory::sync)
    }

    fn sync_with_directory_sync(
        &self,
        vault: &mut Vault,
        state: &mut SyncState,
        flush_directory: impl FnOnce(&Path) -> Result<(), SyncError>,
    ) -> Result<SyncOutcome, SyncError> {
        let confirmed_hash = state.last_file_sha256.clone();
        let name = state.file_name.clone();
        let transport = self.transport(&name);
        let head = match transport.head()? {
            Remote::Head(head) => head,
            Remote::Empty => {
                self.push(vault, state)?;
                self.write_state(state)?;
                return Ok(SyncOutcome {
                    file_name: name,
                    merge: None,
                    pushed: true,
                });
            }
            Remote::NotReady => return Err(SyncError::NotDownloaded),
            Remote::Unavailable => return Err(SyncError::FolderUnavailable),
        };
        let mut merge = None;
        let mut file_content = state.last_content.clone();
        if Some(to_hex(&head.sha256)) != state.last_file_sha256 {
            let work = TempFile::new(self.work_path(&name, "merge")?)?;
            let (_held, hash) = transport.fetch(&head, &work.path)?;
            let report = vault
                .merge_from(&work.path, &self.scope)
                .map_err(copy_error)?;
            file_content = Some(to_hex(&report.remote_content));
            state.last_file_sha256 = Some(hash);
            merge = Some(report);
        }
        let content = to_hex(&vault.sync_content(&self.scope)?);
        let pushed = file_content.as_deref() != Some(content.as_str());
        if pushed {
            self.push(vault, state)?;
        } else {
            // A prior push may have renamed the file but timed out before the
            // directory flush. Reading that file does not confirm its durability.
            // This comparison also covers retry after an app restart.
            if confirmed_hash != state.last_file_sha256 {
                flush_directory(&self.config.folder)?;
            }
            state.last_content = Some(content);
        }
        self.write_state(state)?;
        Ok(SyncOutcome {
            file_name: name,
            merge,
            pushed,
        })
    }

    /// The path of the synced file when it is there. `None` when the folder has no file
    /// yet (a missing folder whose parent exists is made).
    fn probe_ready(&self, name: &str) -> Result<Option<PathBuf>, SyncError> {
        match folder::probe(&self.config.folder, name)? {
            Probe::Present(path) => Ok(Some(path)),
            Probe::Missing => Ok(None),
            Probe::NoFolder => {
                self.ensure_folder()?;
                Ok(None)
            }
            Probe::Evicted(path) => {
                start_download(&path);
                Err(SyncError::NotDownloaded)
            }
            Probe::Unavailable => Err(SyncError::FolderUnavailable),
        }
    }

    /// Write the stripped copy in the work folder and put it through the transport: it
    /// copies it to `<name>.apassy.push.nosync` in the synced folder, syncs it, renames
    /// it to the file name, and syncs the folder.
    fn push(&self, vault: &mut Vault, state: &mut SyncState) -> Result<(), SyncError> {
        self.push_with_directory_sync(vault, state, directory::sync)
    }

    fn push_with_directory_sync(
        &self,
        vault: &mut Vault,
        state: &mut SyncState,
        flush_directory: impl FnOnce(&Path) -> Result<(), SyncError>,
    ) -> Result<(), SyncError> {
        let name = state.file_name.clone();
        let work = TempFile::new(self.work_path(&name, "push")?)?;
        let copy = vault.write_sync_copy(&work.path, &device_name())?;
        let Head { sha256, .. } =
            self.transport(&name)
                .put_with(&work.path, &copy.sha256, flush_directory)?;
        state.last_file_sha256 = Some(to_hex(&sha256));
        state.last_content = Some(to_hex(&copy.content));
        Ok(())
    }

    /// Last resort for a damaged synced file: replace it with the vault of this Mac,
    /// without a merge. The vault must be unlocked.
    pub fn replace_synced_file(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        let name = state.file_name.clone();
        if let Probe::NoFolder = folder::probe(&self.config.folder, &name)? {
            self.ensure_folder()?;
        }
        self.push(vault, &mut state)?;
        self.write_state(&state)?;
        Ok(SyncOutcome {
            file_name: name,
            merge: None,
            pushed: true,
        })
    }

    /// The passphrase changed on another Mac: take `passphrase` from the owner. It must
    /// open the synced file, and the file must hold this vault. Then the vault file is
    /// rekeyed to it, and the sync runs. The vault must be unlocked, and stays unlocked
    /// with the new passphrase.
    pub fn take_new_passphrase(
        &self,
        vault: &mut Vault,
        passphrase: &str,
    ) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        let name = state.file_name.clone();
        let Some(path) = self.probe_ready(&name)? else {
            return Err(SyncError::Vault(VaultErrorKind::NotFound));
        };
        let work = TempFile::new(self.work_path(&name, "passphrase")?)?;
        copy_cloud_to_new(&path, &work.path)?;
        vault.take_passphrase_of_copy(&work.path, passphrase)?;
        drop(work);
        self.sync_with(vault, &mut state)
    }

    /// Turn on sync for the unlocked vault in the folder of the config.
    ///
    /// The file name comes from `vault_name` ([`file_name_for`]). A file with that name
    /// that does not open with the key of the vault, or that holds another vault, belongs
    /// to someone else: enable tries `<name>-2`, `<name>-3`, and so on. A file of this
    /// vault (the same vault ID) links: the vault merges with it and pushes. Else enable
    /// writes a new file. No passphrase: the open connection has the key.
    pub fn enable(&self, vault: &mut Vault, vault_name: &str) -> Result<EnableReport, SyncError> {
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled);
        }
        self.require_config_path(vault)?;
        if vault.is_locked() {
            return Err(SyncError::Vault(VaultErrorKind::Locked));
        }
        let local = vault.sync_identity()?;
        self.ensure_folder()?;
        let first = file_name_for(vault_name);
        for n in 1..=MAX_NAME_TRIES {
            let name = folder::candidate_name(&first, n);
            match folder::probe(&self.config.folder, &name)? {
                Probe::Missing => {
                    let mut state = SyncState::new(&name, &local.vault_id);
                    self.push(vault, &mut state)?;
                    self.write_state(&state)?;
                    return Ok(EnableReport {
                        file_name: name.clone(),
                        linked: false,
                        outcome: SyncOutcome {
                            file_name: name,
                            merge: None,
                            pushed: true,
                        },
                    });
                }
                Probe::Evicted(path) => {
                    start_download(&path);
                    return Err(SyncError::NotDownloaded);
                }
                Probe::Present(path) => {
                    let work = TempFile::new(self.work_path(&name, "check")?)?;
                    copy_cloud_to_new(&path, &work.path)?;
                    match vault.check_sync_copy(&work.path, &self.scope) {
                        Ok(theirs) if theirs.vault_id == local.vault_id => {
                            drop(work);
                            let mut state = SyncState::new(&name, &local.vault_id);
                            let outcome = self.sync_with(vault, &mut state)?;
                            return Ok(EnableReport {
                                file_name: name,
                                linked: true,
                                outcome,
                            });
                        }
                        Ok(_) => {}
                        Err(check_err)
                            if matches!(
                                check_err.kind(),
                                VaultErrorKind::WrongKeyOrCorrupt | VaultErrorKind::Damaged
                            ) => {}
                        Err(other) => return Err(SyncError::from(other)),
                    }
                }
                Probe::NoFolder | Probe::Unavailable => return Err(SyncError::FolderUnavailable),
            }
        }
        Err(SyncError::InvalidName)
    }

    /// Turn off sync: remove the local state file. The synced file stays. Returns whether
    /// sync was on.
    pub fn disable(&self) -> Result<bool, SyncError> {
        state::remove(&self.config.state_path)
    }

    /// Make a new local vault at `SyncConfig::vault_path` from the synced file
    /// `file_name` in the folder, and turn on sync for it (a new Mac, or a teammate).
    /// The new vault opens locked. `passphrase` must open the copy.
    pub fn adopt(
        &self,
        file_name: &str,
        passphrase: &str,
    ) -> Result<(Vault, AdoptReport), SyncError> {
        self.adopt_with_reader(file_name, passphrase, copy_cloud_to_new)
    }

    fn adopt_with_reader(
        &self,
        file_name: &str,
        passphrase: &str,
        read: impl FnOnce(&Path, &Path) -> Result<(File, String), SyncError>,
    ) -> Result<(Vault, AdoptReport), SyncError> {
        if !folder::valid_file_name(file_name) {
            return Err(SyncError::InvalidName);
        }
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled);
        }
        let path = match folder::probe(&self.config.folder, file_name)? {
            Probe::Present(path) => path,
            Probe::Evicted(path) => {
                start_download(&path);
                return Err(SyncError::NotDownloaded);
            }
            Probe::Missing | Probe::NoFolder => {
                return Err(SyncError::Vault(VaultErrorKind::NotFound));
            }
            Probe::Unavailable => return Err(SyncError::FolderUnavailable),
        };
        let work = TempFile::new(self.work_path(file_name, "adopt")?)?;
        let (_held, hash) = read(&path, &work.path)?;
        let (vault, adopted) =
            Vault::adopt_sync_copy(&work.path, &self.config.vault_path, passphrase)?;
        let mut state = SyncState::new(file_name, &adopted.identity.vault_id);
        state.last_file_sha256 = Some(hash);
        state.last_content = Some(to_hex(&adopted.content));
        if let Err(state_err) = self.write_state(&state) {
            let new_file = vault.path().to_owned();
            drop(vault);
            let _ = fs::remove_file(&new_file);
            return Err(state_err);
        }
        Ok((
            vault,
            AdoptReport {
                file_name: file_name.to_owned(),
                identity: adopted.identity,
            },
        ))
    }

    /// A private path in the work folder for a copy of the synced file `name`.
    fn work_path(&self, name: &str, purpose: &str) -> Result<PathBuf, SyncError> {
        state::ensure_private_dir(&self.config.work_dir)?;
        Ok(self.config.work_dir.join(format!(".{name}.{purpose}")))
    }

    /// Make the synced folder when its parent exists.
    fn ensure_folder(&self) -> Result<(), SyncError> {
        FolderTransport::new(&self.config.folder, "").ensure_folder()
    }

    /// The vault must be the vault of `SyncConfig::vault_path`.
    fn require_config_path(&self, vault: &Vault) -> Result<(), SyncError> {
        match fs::canonicalize(&self.config.vault_path) {
            Ok(path) if path == vault.path() => Ok(()),
            _ => Err(SyncError::WrongVault),
        }
    }

    /// The vault must be the configured one, unlocked, and have the vault ID of the
    /// state.
    fn require_unlocked_vault(&self, vault: &Vault, state: &SyncState) -> Result<(), SyncError> {
        self.require_config_path(vault)?;
        if vault.is_locked() {
            return Err(SyncError::Vault(VaultErrorKind::Locked));
        }
        if vault.sync_identity()?.vault_id != state.vault_id {
            return Err(SyncError::WrongVault);
        }
        Ok(())
    }
}

/// The sync of one vault, through a folder or through the relay. The background worker
/// holds this value.
#[derive(Debug, Clone)]
pub enum VaultSync {
    Folder(FolderSync),
    Relay(RelaySync),
}

impl From<FolderSync> for VaultSync {
    fn from(sync: FolderSync) -> Self {
        Self::Folder(sync)
    }
}

impl From<RelaySync> for VaultSync {
    fn from(sync: RelaySync) -> Self {
        Self::Relay(sync)
    }
}

impl VaultSync {
    /// The live local vault file.
    pub fn vault_path(&self) -> &Path {
        match self {
            Self::Folder(sync) => &sync.config().vault_path,
            Self::Relay(sync) => &sync.config().vault_path,
        }
    }

    /// The relay sync, when the vault syncs through the relay.
    pub fn as_relay(&self) -> Option<&RelaySync> {
        match self {
            Self::Relay(sync) => Some(sync),
            Self::Folder(_) => None,
        }
    }

    /// The local sync state. `None` when sync is off.
    pub fn state(&self) -> Result<Option<SyncState>, SyncError> {
        match self {
            Self::Folder(sync) => sync.state(),
            Self::Relay(sync) => sync.state(),
        }
    }

    /// Whether the vault has synced content that the last sync did not see.
    pub fn local_changed(&self, vault: &Vault) -> Result<bool, SyncError> {
        match self {
            Self::Folder(sync) => sync.local_changed(vault),
            Self::Relay(sync) => sync.local_changed(vault),
        }
    }

    /// Sync the unlocked vault.
    pub fn sync(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        match self {
            Self::Folder(sync) => sync.sync(vault),
            Self::Relay(sync) => sync.sync(vault),
        }
    }

    /// Sync the vault in the shared slot of the app. A folder sync holds the slot's
    /// mutex for the whole sync (its I/O is bounded); a relay sync holds it only for the
    /// local steps ([`RelaySync::sync_shared`]). `accept` tells whether the vault in the
    /// slot is the one of this sync. A locked or other vault is `Locked`.
    pub fn sync_shared(
        &self,
        slot: &std::sync::Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
    ) -> Result<SyncOutcome, SyncError> {
        match self {
            Self::Folder(sync) => {
                let mut slot = slot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match slot.as_mut() {
                    Some(vault) if !vault.is_locked() && accept(vault) => sync.sync(vault),
                    _ => Err(SyncError::Vault(VaultErrorKind::Locked)),
                }
            }
            Self::Relay(sync) => sync.sync_shared(slot, accept),
        }
    }

    /// Whether both sync the same vault the same way.
    pub fn same_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Folder(a), Self::Folder(b)) => a.config() == b.config(),
            (Self::Relay(a), Self::Relay(b)) => a.config() == b.config(),
            _ => false,
        }
    }
}

/// Read the sync state file at `path`. `None` when it does not exist.
pub fn read_state(path: &Path) -> Result<Option<SyncState>, SyncError> {
    state::read(path)
}

/// Lowercase hexadecimal SHA-256 of the file at `path`.
pub fn file_sha256(path: &Path) -> Result<String, SyncError> {
    let path = path.to_owned();
    directory::read(move || hash_path(&path))
}

/// Lowercase hexadecimal SHA-256 of the file at `path`. A missing file is
/// `Vault(NotFound)`.
fn hash_path(path: &Path) -> Result<String, SyncError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            return Err(SyncError::Vault(VaultErrorKind::NotFound));
        }
        Err(_) => return Err(SyncError::Io),
    };
    hash_open_file(&mut file)
        .map(|hash| to_hex(&hash))
        .map_err(|_| SyncError::Io)
}

fn create_new_private(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Read cloud bytes without giving the worker a named destination or a vault.
/// A timed-out worker can only write its anonymous local file. The channel drops
/// a late result, which closes that file. Only this caller publishes a work file.
fn copy_cloud_to_new(source: &Path, dest: &Path) -> Result<(File, String), SyncError> {
    let source = source.to_owned();
    copy_cloud_to_new_with(dest, move |snapshot| {
        directory::read_until(move |deadline| {
            snapshot_cloud_file(&source, snapshot, Some(deadline))
        })
    })
}

fn snapshot_cloud_file(
    source: &Path,
    snapshot: File,
    deadline: Option<Instant>,
) -> Result<(File, String), SyncError> {
    let source = File::open(source).map_err(|_| SyncError::Io)?;
    let metadata = source.metadata().map_err(|_| SyncError::Io)?;
    if !metadata.is_file() {
        return Err(SyncError::Io);
    }
    snapshot_bytes(source, snapshot, metadata.len(), deadline)
}

/// Bound growth to the initial length without a new product size limit. Reject
/// a shorter or longer read and stop after a timed-out syscall returns.
fn snapshot_bytes(
    mut source: impl Read,
    mut snapshot: File,
    expected: u64,
    deadline: Option<Instant>,
) -> Result<(File, String), SyncError> {
    let expired = || deadline.is_some_and(|at| Instant::now() >= at);
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    loop {
        if expired() {
            return Err(SyncError::TimedOut);
        }
        let limit = expected
            .saturating_sub(bytes)
            .saturating_add(1)
            .min(buffer.len() as u64) as usize;
        let read = source
            .read(&mut buffer[..limit])
            .map_err(|_| SyncError::Io)?;
        if expired() {
            return Err(SyncError::TimedOut);
        }
        if read == 0 {
            break;
        }
        bytes += read as u64;
        if bytes > expected {
            return Err(SyncError::Io);
        }
        snapshot
            .write_all(&buffer[..read])
            .map_err(|_| SyncError::Io)?;
        hash.update(&buffer[..read]);
    }
    if bytes != expected {
        return Err(SyncError::Io);
    }
    snapshot.sync_all().map_err(|_| SyncError::Io)?;
    snapshot.rewind().map_err(|_| SyncError::Io)?;
    Ok((snapshot, to_hex(hash.finish().as_ref())))
}

fn copy_cloud_to_new_with(
    dest: &Path,
    read: impl FnOnce(File) -> Result<(File, String), SyncError>,
) -> Result<(File, String), SyncError> {
    let parent = dest.parent().ok_or(SyncError::Io)?;
    let snapshot = tempfile::tempfile_in(parent).map_err(|_| SyncError::Io)?;
    let snapshot = private_snapshot(snapshot)?;
    let (mut snapshot, expected_hash) = read(snapshot)?;
    let mut dest_file = create_new_private(dest).map_err(|_| SyncError::Io)?;
    match copy_hashing(&mut snapshot, &mut dest_file) {
        Ok(hash) if to_hex(&hash) == expected_hash => Ok((dest_file, expected_hash)),
        _ => {
            drop(dest_file);
            let _ = fs::remove_file(dest);
            Err(SyncError::Io)
        }
    }
}

/// Linux O_TMPFILE creation can use the process umask instead of mode 0600.
/// The descriptor is still anonymous and empty here. Set its mode before the
/// cloud worker can write any vault bytes, without changing the process umask.
fn private_snapshot(snapshot: File) -> Result<File, SyncError> {
    snapshot
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| SyncError::Io)?;
    Ok(snapshot)
}

/// Copy `source` to the new file `dest` (mode `0600`) and sync it. Returns the open
/// copy and the hash of the bytes.
fn copy_to_new(source: &Path, dest: &Path) -> Result<(File, String), SyncError> {
    let mut dest_file = create_new_private(dest).map_err(|_| SyncError::Io)?;
    let copied = File::open(source).and_then(|mut src| copy_hashing(&mut src, &mut dest_file));
    match copied {
        Ok(hash) => Ok((dest_file, to_hex(&hash))),
        Err(_) => {
            drop(dest_file);
            let _ = fs::remove_file(dest);
            Err(SyncError::Io)
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn adopt_timeout_creates_no_vault_or_state_and_can_retry() {
        let root = tempfile::tempdir().expect("test root");
        let cloud = root.path().join("cloud");
        fs::create_dir(&cloud).expect("cloud folder");
        let passphrase = "synthetic-adopt-timeout-pass";
        drop(Vault::create(&cloud.join("Synthetic.apassy"), passphrase).expect("source vault"));
        let local = root.path().join("new-vault.db");
        let sync = FolderSync::new(SyncConfig::in_data_dir(
            root.path(),
            &local,
            &cloud,
            "new-vault",
        ));
        assert_eq!(
            sync.adopt_with_reader("Synthetic.apassy", passphrase, |_, _| Err(
                SyncError::TimedOut
            ))
            .expect_err("cloud read timeout"),
            SyncError::TimedOut
        );
        assert!(!local.exists());
        assert!(!sync.config.state_path.exists());
        assert_eq!(fs::read_dir(&sync.config.work_dir).unwrap().count(), 0);

        let (vault, _) = sync.adopt("Synthetic.apassy", passphrase).expect("retry");
        assert!(vault.is_locked());
        assert!(local.exists());
        assert!(sync.state().unwrap().is_some());
    }

    #[test]
    fn timed_out_cloud_read_cannot_publish_a_late_file_and_retry_succeeds() {
        let root = tempfile::tempdir().expect("test root");
        let source = root.path().join("encrypted-cloud-copy");
        fs::write(&source, b"synthetic encrypted bytes").expect("source");
        let dest = root.path().join("work-copy");
        let state = root.path().join("state.json");
        let vault = root.path().join("vault.db");
        let worker = directory::DirectorySync::default();
        let (release, wait) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        let late_source = source.clone();
        let error = copy_cloud_to_new_with(&dest, |snapshot| {
            let metadata = snapshot.metadata().expect("snapshot metadata");
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 0, "the worker file must have no name");
            worker.run(Duration::from_millis(25), move || {
                wait.recv().expect("release cloud open");
                let result = snapshot_cloud_file(&late_source, snapshot, None);
                finished.send(()).expect("completed late cloud read");
                result
            })
        })
        .expect_err("cloud open must time out");
        assert_eq!(error, SyncError::TimedOut);
        assert!(!dest.exists());
        release.send(()).expect("release worker");
        done.recv_timeout(Duration::from_secs(1))
            .expect("late read completes");
        assert!(!dest.exists());
        assert!(!state.exists());
        assert!(!vault.exists());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);

        // The successful path publishes a private named copy only after the read.
        let (_held, hash) = copy_cloud_to_new(&source, &dest).expect("fresh retry");
        assert_eq!(fs::read(&dest).unwrap(), fs::read(&source).unwrap());
        assert_eq!(hash, hash_path(&dest).unwrap());
        assert_eq!(fs::metadata(&dest).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn cloud_staging_and_copy_stay_private_with_public_source_permissions() {
        let root = tempfile::tempdir().expect("test root");
        // Simulate the mode of an anonymous Linux O_TMPFILE independently of
        // this test process's umask and of the host operating system.
        let snapshot = tempfile::tempfile_in(root.path()).expect("anonymous snapshot");
        snapshot
            .set_permissions(fs::Permissions::from_mode(0o644))
            .expect("public snapshot permissions");
        assert_eq!(snapshot.metadata().unwrap().mode() & 0o777, 0o644);
        let snapshot = private_snapshot(snapshot).expect("private snapshot");
        let metadata = snapshot.metadata().unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 0, "the snapshot must remain anonymous");
        assert_eq!(
            metadata.len(),
            0,
            "the mode changes before any bytes arrive"
        );
        drop(snapshot);

        let source = root.path().join("encrypted-cloud-copy");
        fs::write(&source, b"synthetic encrypted bytes").expect("source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644))
            .expect("public source permissions");
        let dest = root.path().join("private-work-copy");
        let (_held, hash) = copy_cloud_to_new_with(&dest, |snapshot| {
            let metadata = snapshot.metadata().expect("snapshot metadata");
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 0);
            snapshot_cloud_file(&source, snapshot, None)
        })
        .expect("cloud copy");
        assert_eq!(fs::read(&dest).unwrap(), fs::read(&source).unwrap());
        assert_eq!(hash, hash_path(&dest).unwrap());
        assert_eq!(fs::metadata(&dest).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&source).unwrap().mode() & 0o777, 0o644);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn cloud_snapshot_rejects_size_changes_and_stops_after_deadline() {
        for expected in [2, 4] {
            let snapshot = tempfile::tempfile().unwrap();
            assert_eq!(
                snapshot_bytes(&b"abc"[..], snapshot, expected, None).expect_err("size changed"),
                SyncError::Io
            );
        }
        let snapshot = tempfile::tempfile().unwrap();
        assert_eq!(
            snapshot_bytes(&b"abc"[..], snapshot, 3, Some(Instant::now()))
                .expect_err("deadline passed"),
            SyncError::TimedOut
        );
    }

    #[test]
    fn push_timeout_keeps_state_unconfirmed_and_allows_retry() {
        let root = tempfile::tempdir().expect("test root");
        let folder = root.path().join("cloud");
        fs::create_dir(&folder).expect("cloud folder");
        let vault_path = root.path().join("vault.db");
        let passphrase = "synthetic-directory-timeout-pass";
        let mut vault = Vault::create(&vault_path, passphrase).expect("vault");
        vault.unlock(passphrase).expect("unlock");
        let identity = vault.sync_identity().expect("identity");
        let sync = FolderSync::new(SyncConfig::in_data_dir(
            root.path(),
            &vault_path,
            &folder,
            "test",
        ));
        let mut state = SyncState::new("Synthetic.apassy", &identity.vault_id);
        let before = state.clone();
        let error = sync
            .push_with_directory_sync(&mut vault, &mut state, |_| Err(SyncError::TimedOut))
            .expect_err("an unconfirmed directory flush must fail");
        assert_eq!(error, SyncError::TimedOut);
        assert_eq!(state, before);
        assert!(sync.state().expect("state read").is_none());
        assert!(!vault.is_locked());
        let copy = folder.join("Synthetic.apassy");
        assert_eq!(
            Vault::inspect_sync_copy(&copy, passphrase)
                .expect("complete encrypted copy")
                .vault_id,
            identity.vault_id
        );

        for last_hash in [None, Some("0".repeat(64))] {
            let mut retry = before.clone();
            retry.last_file_sha256 = last_hash;
            let mut checked = false;
            assert_eq!(
                sync.sync_with_directory_sync(&mut vault, &mut retry, |_| {
                    checked = true;
                    Err(SyncError::TimedOut)
                }),
                Err(SyncError::TimedOut)
            );
            assert!(
                checked,
                "a changed checkpoint needs a fresh directory flush"
            );
            assert!(sync.state().unwrap().is_none());
        }

        // Retry recognizes the already renamed file, checks it, and records a
        // confirmed sync instead of creating a duplicate or losing local data.
        let report = sync.enable(&mut vault, "Synthetic").expect("retry");
        assert!(report.linked);
        assert_eq!(report.file_name, "Synthetic.apassy");
        assert!(sync.state().expect("confirmed state").is_some());
    }
}
