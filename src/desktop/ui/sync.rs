//! Sync of the vaults through a folder in the app (ADR 0014, docs/operations/sync.md):
//! the Sync setting of each vault, the status in plain words, "Sync now", the prompt for
//! a passphrase that changed on another Mac, and "Open a synced vault…".
//!
//! The engine is [`crate::sync`]. The vault list keeps the setting of each vault
//! ([`crate::vaults::VaultEntry::sync`]): the synced folder, the file name, and the name
//! of its sync state file in `<data dir>/sync/` (the list ID of the vault).
//!
//! When it runs: right after each unlock, before the owner sees the list; while the vault
//! is unlocked, every 30 seconds for the synced file and 5 to 8 seconds after a change of
//! a credential; and in the step before each lock of the session
//! ([`crate::desktop::owner_store::BeforeLock`]), so a lock, a switch, a backup, a quit,
//! and a restart for an update sync too. Never while an agent run waits for the owner. A
//! failure never stops a lock; the app shows it once as a note.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Label};
use zeroize::Zeroize;

use super::files::{self, DialogKind};
use super::kit::{self, Font, Style, Tone};
use super::start::Step;
use super::vaults::VaultSheet;
use super::{
    PASSPHRASE_CAPACITY, Sheet, VAULT_PASSPHRASE_FIELD, close_sheet, forget_secret_field,
    secure_input,
};
use crate::desktop::owner_store::Ephemeral;
use crate::desktop::{DesktopApp, OwnerView};
use crate::sync::{
    FileStatus, FolderEntry, FolderSync, SYNC_FILE_EXTENSION, SyncConfig, SyncError, SyncFolder,
    SyncOutcome, list_folder_vaults, read_state,
};
use crate::vault::{ConflictCopy, Vault, VaultErrorKind, format_utc};
use crate::vaults::{self, Registry, SyncLink, VaultEntry};

/// How often the app looks at the synced file of each vault.
const CHECK_EVERY: Duration = Duration::from_secs(30);
/// How often it looks again while iCloud downloads the file of the open vault.
const DOWNLOAD_EVERY: Duration = Duration::from_secs(2);
/// How often it looks for a change of a credential in the open vault.
const LOCAL_EVERY: Duration = Duration::from_secs(3);
/// A change of a credential syncs this long after the app first saw it: 5 to 8 seconds
/// after the change.
const SETTLE: Duration = Duration::from_secs(5);
/// The passphrase field of the sync sheets.
pub(crate) const SYNC_PASSPHRASE_FIELD: &str = "sync-passphrase";
/// The folder of the sync state files in the data directory.
const STATE_DIR: &str = "sync";

/// Sync state of the app. It holds no secret after an action: the passphrase field is
/// erased after each try, at a lock, and at a switch.
#[derive(Default)]
pub(crate) struct SyncUiState {
    /// The app offers sync. A window turns it on; a test turns it on with its own
    /// folders, so no test uses a real synced folder.
    pub(crate) offered: bool,
    /// The Apassy folder in iCloud Drive, when this Mac has iCloud Drive.
    pub(crate) icloud: Option<PathBuf>,
    /// The synced folders of this Mac (iCloud Drive first).
    pub(crate) folders: Vec<SyncFolder>,
    /// A failed folder discovery must not look like an empty successful scan.
    folder_error: Option<SyncError>,
    detected_folders: bool,
    /// The step before a lock, and what it did.
    hook: Arc<Mutex<HookShared>>,
    hook_installed: bool,
    /// The status of each synced vault of the list, by list ID.
    pub(crate) statuses: BTreeMap<String, UiStatus>,
    next_check: Option<Instant>,
    next_local_check: Option<Instant>,
    /// A change of a credential that waits to sync, and when the app saw it.
    changed_since: Option<Instant>,
    /// The failure text that the app showed last. A failure shows once.
    shown_failure: Option<String>,
    /// A note that stays until the owner closes it: kept conflict copies, a damaged
    /// synced file, skipped variables.
    pub(crate) notice: Option<Notice>,
    /// The passphrase field of the sync sheets.
    pub(crate) passphrase: String,
    /// The folder field of "Choose folder…".
    pub(crate) folder_input: String,
    /// The Sync choice of the Create screen: `None` is off.
    pub(crate) create_folder: Option<PathBuf>,
    /// "Choose folder…" on the Create screen shows the folder field.
    pub(crate) create_custom: bool,
    /// The synced file that the owner picked on "Open a synced vault".
    pub(crate) open_pick: Option<PathBuf>,
    /// The file field of "Open a synced vault".
    pub(crate) open_path: String,
    /// Successful adoption for the next setup step. Set only after unlock.
    pub(crate) adopted_vault: Option<String>,
    /// Cached discovery prevents repeated cloud I/O after a failure.
    open_found: Option<Vec<(String, FolderEntry)>>,
    open_error: Option<SyncError>,
    open_error_from_adopt: bool,
    open_waiting: bool,
    open_next_download: Option<Instant>,
    /// List IDs of vaults for which the app asked iCloud for a download.
    downloads: BTreeSet<String>,
}

/// What the step before a lock shares with the window.
#[derive(Default)]
struct HookShared {
    /// The sync of the open vault. `None` when sync is off.
    sync: Option<FolderSync>,
    /// A failed sync, for a note.
    failure: Option<String>,
    /// What the sync did.
    outcome: Option<SyncOutcome>,
}

/// The status of a synced vault in plain words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UiStatus {
    /// Up to date. The time of the last sync, in Unix seconds.
    UpToDate(Option<u64>),
    /// A change waits to sync, on this Mac or in the folder.
    Syncing,
    /// iCloud has not downloaded the synced file to this Mac yet.
    Waiting,
    /// The synced file has a new passphrase from another Mac.
    NeedsPassphrase,
    /// The synced folder is not there.
    FolderUnavailable,
    /// The synced file is damaged.
    Damaged,
    /// Another problem, in words.
    Problem(String),
}

impl UiStatus {
    fn from_error(err: SyncError) -> Self {
        match err {
            SyncError::NotDownloaded => Self::Waiting,
            SyncError::NeedsPassphrase => Self::NeedsPassphrase,
            SyncError::FolderUnavailable => Self::FolderUnavailable,
            SyncError::Damaged => Self::Damaged,
            other => Self::Problem(other.to_string()),
        }
    }

    fn from_file(status: FileStatus, last: Option<u64>) -> Self {
        match status {
            FileStatus::UpToDate => Self::UpToDate(last),
            FileStatus::Changed | FileStatus::Missing => Self::Syncing,
            FileStatus::NotDownloaded => Self::Waiting,
            FileStatus::FolderUnavailable => Self::FolderUnavailable,
        }
    }

    /// The short tag and its tone.
    pub(crate) fn tag(&self) -> (&'static str, Tone) {
        match self {
            Self::UpToDate(_) => ("Saved to sync folder", Tone::Good),
            Self::Syncing => ("Sync pending", Tone::Accent),
            Self::Waiting => ("Waiting for file", Tone::Neutral),
            Self::NeedsPassphrase => ("Needs the new passphrase", Tone::Warning),
            Self::FolderUnavailable => ("Folder not available", Tone::Warning),
            Self::Damaged => ("Damaged copy", Tone::Warning),
            Self::Problem(_) => ("Problem", Tone::Warning),
        }
    }

    /// The status in a sentence.
    pub(crate) fn words(&self, icloud: bool) -> String {
        match self {
            Self::UpToDate(Some(at)) => format!(
                "This Mac matches the local file in the sync folder. Last folder sync {}. Receipt on another Mac is not confirmed.",
                ago(*at)
            ),
            Self::UpToDate(None) => {
                "This Mac matches the local file in the sync folder. Receipt on another Mac is not confirmed."
                    .to_owned()
            }
            Self::Syncing => "Saved on this Mac. A change waits for the sync folder.".to_owned(),
            Self::Waiting if icloud => "Waiting for iCloud to download the synced file.".to_owned(),
            Self::Waiting => "Waiting for the synced file to download.".to_owned(),
            Self::NeedsPassphrase => {
                "The passphrase changed on another Mac. Type the new passphrase.".to_owned()
            }
            Self::FolderUnavailable => {
                "The synced folder is not available. Apassy syncs when it is back.".to_owned()
            }
            Self::Damaged => "The synced copy is damaged. Apassy did not use it.".to_owned(),
            Self::Problem(text) => format!("Sync: {text}."),
        }
    }
}

/// A note in the window about sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    pub(crate) title: String,
    pub(crate) text: String,
    pub(crate) warning: bool,
    /// The vault that the note is about.
    pub(crate) vault: String,
}

/// A sync sheet in Settings > Vaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncSheet {
    /// "Choose folder…": a folder path for the vault.
    ChooseFolder { id: String },
    /// The passphrase changed on another Mac.
    NewPassphrase { id: String },
    /// Turn off sync.
    TurnOff { id: String },
    /// Last resort: replace a damaged synced file with the vault of this Mac.
    ReplaceDamaged { id: String },
}

/// "just now", "5 minutes ago", "2 hours ago", or "on 2026-09-28".
fn ago(unix: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let secs = now.saturating_sub(unix);
    match secs {
        0..=59 => "just now".to_owned(),
        60..=119 => "1 minute ago".to_owned(),
        120..=3599 => format!("{} minutes ago", secs / 60),
        3600..=7199 => "1 hour ago".to_owned(),
        7200..=86_399 => format!("{} hours ago", secs / 3600),
        _ => format!("on {}", &format_utc(unix)[..10]),
    }
}

/// The note after a merge that kept both versions of some credentials.
fn conflict_notice(vault: &str, id: &str, conflicts: &[ConflictCopy]) -> Notice {
    let names: Vec<String> = conflicts
        .iter()
        .map(|copy| format!("“{}”", copy.title))
        .collect();
    Notice {
        title: format!("Sync kept both versions in “{vault}”"),
        text: format!(
            "{} changed on this Mac and on {} at the same time. Apassy kept the later change, and the other version as an archived credential “… (conflict copy, <device>)”. Open Credentials > Archived to compare, and delete the copy when you are done.",
            names.join(", "),
            conflicts
                .first()
                .map_or("another device", |copy| copy.device.as_str())
        ),
        warning: false,
        vault: id.to_owned(),
    }
}

/// The folder label of `path`: a synced folder of this Mac, or the path.
fn folder_label(folders: &[SyncFolder], path: &Path) -> String {
    folders
        .iter()
        .find(|folder| folder.path == path)
        .map_or_else(|| path.display().to_string(), |folder| folder.label.clone())
}

/// The path of the sync state file `state` in `data_dir`, as in
/// [`SyncConfig::in_data_dir`].
fn state_path(data_dir: &Path, state: &str) -> PathBuf {
    data_dir.join(STATE_DIR).join(format!("{state}.json"))
}

/// Link each synced vault of a rebuilt list to its sync state again: the state names the
/// vault file of an entry, and its synced folder and file. Each sync then checks the
/// vault ID of the state, so a different vault file at that path never syncs. Returns a
/// line for the note of the list.
pub(crate) fn relink_states(data_dir: &Path, registry: &mut Registry) -> Option<String> {
    let read = std::fs::read_dir(data_dir.join(STATE_DIR)).ok()?;
    let linked: BTreeSet<String> = registry
        .entries()
        .iter()
        .filter_map(|entry| entry.sync_state().map(str::to_owned))
        .collect();
    let mut files: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    let (mut relinked, mut lost) = (Vec::new(), 0usize);
    for path in files {
        let Some(state_name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if SyncLink::new(state_name, Path::new("/"), "x")
            .state_name()
            .is_none()
            || linked.contains(state_name)
        {
            continue;
        }
        let Ok(Some(state)) = read_state(&path) else {
            lost += 1;
            continue;
        };
        let target = state.vault_path.as_deref().and_then(|vault_path| {
            registry
                .find_path(vault_path)
                .filter(|entry| entry.sync.is_none())
                .map(|entry| (entry.id.clone(), entry.name.clone()))
        });
        match (target, state.folder) {
            (Some((id, name)), Some(folder)) => {
                if let Some(entry) = registry.entry_mut(&id) {
                    entry.sync = Some(SyncLink::new(state_name, &folder, &state.file_name));
                }
                relinked.push(name);
            }
            _ => lost += 1,
        }
    }
    if relinked.is_empty() && lost == 0 {
        return None;
    }
    let mut line = String::new();
    if !relinked.is_empty() {
        let names: Vec<String> = relinked.iter().map(|name| format!("“{name}”")).collect();
        line.push_str(&format!("Sync is on again for {}.", names.join(", ")));
    }
    if lost > 0 {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(
            "Apassy could not link the sync of a vault in another folder. Open that vault, then choose its synced folder again in Settings > Vaults; Apassy then merges with the same file.",
        );
    }
    Some(line)
}

impl DesktopApp {
    /// Read the synced folders of this Mac for the window.
    pub(crate) fn sync_detect_folders(&mut self) {
        self.sync.offered = true;
        self.sync.detected_folders = true;
        self.sync.icloud = crate::sync::icloud_folder();
        match crate::sync::try_detect_folders() {
            Ok(folders) => {
                self.sync.folders = folders;
                self.sync.folder_error = None;
            }
            Err(error) => self.sync.folder_error = Some(error),
        }
    }

    fn sync_config(&self, entry: &VaultEntry) -> Option<SyncConfig> {
        let link = entry.sync.as_ref()?;
        let state = link.state_name()?;
        link.file_path()?;
        Some(SyncConfig::in_data_dir(
            &self.vault_list.data_dir,
            &entry.path,
            &link.folder,
            state,
        ))
    }

    /// The sync of the listed vault `id`, when sync is on for it.
    pub(crate) fn sync_of(&self, id: &str) -> Option<FolderSync> {
        let entry = self.vault_list.registry.get(id)?;
        self.sync_config(entry).map(FolderSync::new)
    }

    /// The list ID and the sync of the open vault, when sync is on for it.
    fn sync_current(&self) -> Option<(String, FolderSync)> {
        let id = self.current_vault()?.id.clone();
        let sync = self.sync_of(&id)?;
        Some((id, sync))
    }

    fn is_icloud(&self, id: &str) -> bool {
        let folder = self
            .vault_list
            .registry
            .get(id)
            .and_then(|entry| entry.sync.as_ref())
            .map(|link| link.folder.clone());
        folder.is_some() && folder == self.sync.icloud
    }

    fn runs_wait(&self) -> bool {
        self.approvals()
            .is_some_and(|queue| !queue.pending().is_empty())
    }

    /// The step before a lock syncs the open vault from now on. Call it when the open
    /// vault or its setting changes. The engine refuses a vault at another path or with
    /// another vault ID, so a sync never reaches the file of another vault.
    pub(crate) fn sync_track_open_vault(&mut self) {
        if !self.sync.hook_installed {
            let shared = Arc::clone(&self.sync.hook);
            self.owner_ui
                .session
                .set_before_lock(Some(Box::new(move |vault: &mut Vault| {
                    let mut shared = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    let Some(sync) = shared.sync.clone() else {
                        return;
                    };
                    match sync.sync(vault) {
                        Ok(outcome) => {
                            shared.failure = None;
                            shared.outcome = Some(outcome);
                        }
                        Err(err) => shared.failure = Some(lock_failure(err)),
                    }
                })));
            self.sync.hook_installed = true;
        }
        let sync = self.sync_current().map(|(_, sync)| sync);
        self.sync
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync = sync;
        self.sync.next_check = None;
        self.sync.next_local_check = None;
        self.sync.changed_since = None;
    }

    /// The open vault is gone: no sync before a lock, no typed passphrase, and no note
    /// about it.
    pub(crate) fn sync_forget_open_vault(&mut self, ctx: Option<&egui::Context>) {
        self.sync
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync = None;
        self.sync_forget_secrets(ctx);
        self.sync.notice = None;
        self.sync.next_check = None;
        self.sync.changed_since = None;
    }

    /// Erase the passphrase field of the sync sheets and its undo history.
    pub(crate) fn sync_forget_secrets(&mut self, ctx: Option<&egui::Context>) {
        self.sync.passphrase.zeroize();
        if let Some(ctx) = ctx {
            forget_secret_field(ctx, SYNC_PASSPHRASE_FIELD);
        }
    }

    /// Read the file status of each synced vault of the list. The open, unlocked vault
    /// also counts a change of a credential that waits to sync.
    pub(crate) fn sync_refresh(&mut self) {
        let ids: Vec<String> = self
            .vault_list
            .registry
            .entries()
            .iter()
            .filter(|entry| entry.sync_state().is_some())
            .map(|entry| entry.id.clone())
            .collect();
        let mut statuses = BTreeMap::new();
        for id in ids {
            let Some(sync) = self.sync_of(&id) else {
                continue;
            };
            let kept = self.sync.statuses.get(&id).filter(|status| {
                matches!(
                    status,
                    UiStatus::NeedsPassphrase | UiStatus::Damaged | UiStatus::Problem(_)
                )
            });
            let status = match (kept, sync.status()) {
                (Some(kept), Ok(report)) if report.status == FileStatus::UpToDate => kept.clone(),
                (_, Ok(report)) => UiStatus::from_file(report.status, report.last_sync_at),
                (_, Err(err)) => UiStatus::from_error(err),
            };
            statuses.insert(id, status);
        }
        if let Some((id, _)) = self.sync_current()
            && self.sync.changed_since.is_some()
            && let Some(UiStatus::UpToDate(_)) = statuses.get(&id)
        {
            statuses.insert(id, UiStatus::Syncing);
        }
        self.sync.statuses = statuses;
    }

    /// Each frame: take what the step before a lock did, and sync when it is time.
    pub(crate) fn poll_sync(&mut self, ctx: &egui::Context) {
        if !self.sync.offered {
            return;
        }
        self.sync_take_hook_results();
        let now = Instant::now();
        let unlocked = self.owner_ui.session.has_file() && !self.owner_ui.session.is_locked();
        if unlocked
            && self.sync_current().is_some()
            && self.sync.next_local_check.is_none_or(|at| now >= at)
        {
            self.sync.next_local_check = Some(now + LOCAL_EVERY);
            let changed = self
                .sync_current()
                .and_then(|(_, sync)| {
                    self.owner_ui
                        .session
                        .with_vault(|vault| sync.local_changed(vault).ok())
                })
                .flatten()
                .unwrap_or(false);
            match (changed, self.sync.changed_since) {
                (true, None) => self.sync.changed_since = Some(now),
                (false, Some(_)) => self.sync.changed_since = None,
                _ => {}
            }
        }
        let settled = self
            .sync
            .changed_since
            .is_some_and(|since| now.duration_since(since) >= SETTLE);
        if settled && unlocked && !self.runs_wait() {
            self.sync_quietly();
        }
        if self.sync.next_check.is_none_or(|at| now >= at) {
            self.sync_poll_now();
        }
        let next = [self.sync.next_check, self.sync.next_local_check]
            .into_iter()
            .flatten()
            .min();
        if let Some(at) = next {
            ctx.request_repaint_after(at.saturating_duration_since(now));
        }
    }

    /// One look at the synced files: the statuses, a download request, and a sync of
    /// the open vault when its file changed.
    pub(crate) fn sync_poll_now(&mut self) {
        self.sync_refresh();
        let now = Instant::now();
        let current = self.sync_current();
        let status = current
            .as_ref()
            .and_then(|(id, _)| self.sync.statuses.get(id).cloned());
        self.sync.next_check = Some(
            now + if status == Some(UiStatus::Waiting) {
                DOWNLOAD_EVERY
            } else {
                CHECK_EVERY
            },
        );
        let Some((id, sync)) = current else {
            return;
        };
        if status != Some(UiStatus::Waiting) {
            self.sync.downloads.remove(&id);
        } else if self.sync.downloads.insert(id.clone()) {
            let _ = sync.request_download();
        }
        let unlocked = !self.owner_ui.session.is_locked();
        let file_moved = matches!(
            sync.status().map(|report| report.status),
            Ok(FileStatus::Changed | FileStatus::Missing)
        );
        if unlocked && file_moved && !self.runs_wait() {
            self.sync_quietly();
        }
    }

    fn sync_take_hook_results(&mut self) {
        let (failure, outcome) = {
            let mut shared = self
                .sync
                .hook
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (shared.failure.take(), shared.outcome.take())
        };
        if let Some(outcome) = outcome {
            self.sync.shown_failure = None;
            self.sync.next_check = None;
            if let Some(id) = self.vault_list.current.clone() {
                self.sync_note_merge(&id, &outcome);
            }
        }
        if let Some(text) = failure {
            self.sync_failure_once(text);
        }
    }

    /// Show a failure as a note, once until something changes.
    fn sync_failure_once(&mut self, text: String) {
        if self.sync.shown_failure.as_deref() != Some(text.as_str()) {
            self.set_note(text.clone());
            self.sync.shown_failure = Some(text);
        }
    }

    /// Keep what a merge reported: kept conflict copies and skipped variables become a
    /// note that stays.
    fn sync_note_merge(&mut self, id: &str, outcome: &SyncOutcome) {
        let Some(merge) = &outcome.merge else {
            return;
        };
        let vault = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        if !merge.conflicts.is_empty() {
            self.sync.notice = Some(conflict_notice(&vault, id, &merge.conflicts));
        } else if !merge.skipped_variables.is_empty() {
            self.sync.notice = Some(Notice {
                title: format!("A variable of “{vault}” is taken on this Mac"),
                text: format!(
                    "Another credential on this Mac has the variable {}. The credential from the other device came without it. Rename one of the variables.",
                    merge.skipped_variables.join(", ")
                ),
                warning: true,
                vault: id.to_owned(),
            });
        }
    }

    /// Sync the open vault now, without a message unless something needs the owner.
    pub(crate) fn sync_quietly(&mut self) -> Option<Result<SyncOutcome, SyncError>> {
        let (id, sync) = self.sync_current()?;
        if self.owner_ui.session.is_locked() {
            return None;
        }
        let result = self.owner_ui.session.with_vault(|vault| sync.sync(vault))?;
        self.sync.changed_since = None;
        self.sync.next_local_check = None;
        match &result {
            Ok(outcome) => {
                self.sync.shown_failure = None;
                self.sync_note_merge(&id, outcome);
                let last = sync
                    .state()
                    .ok()
                    .flatten()
                    .and_then(|state| state.last_sync_at);
                self.sync.statuses.insert(id, UiStatus::UpToDate(last));
            }
            Err(err) => {
                let err = *err;
                self.sync
                    .statuses
                    .insert(id.clone(), UiStatus::from_error(err));
                match err {
                    SyncError::NeedsPassphrase => self.sync_ask_passphrase(&id),
                    SyncError::Damaged => {
                        let vault = self.current_vault_name().unwrap_or_default();
                        self.sync.notice = Some(Notice {
                            title: format!("The synced copy of “{vault}” is damaged"),
                            text: "The file in the synced folder fails a check, so Apassy did not merge it. The vault on this Mac did not change. If no other Mac can repair it, replace it with this Mac's vault in Settings > Vaults.".to_owned(),
                            warning: true,
                            vault: id.clone(),
                        });
                    }
                    SyncError::FolderUnavailable | SyncError::NotDownloaded => {}
                    other => self.sync_failure_once(format!("Sync: {other}.")),
                }
            }
        }
        Some(result)
    }

    fn sync_ask_passphrase(&mut self, id: &str) {
        if self.ui.sheet.is_none() && !self.owner_ui.session.is_locked() {
            self.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::NewPassphrase {
                id: id.to_owned(),
            })));
        }
    }

    /// Right after an unlock: sync before the owner sees the list. Returns a line for
    /// the result message.
    pub(crate) fn sync_after_unlock(&mut self) -> Option<String> {
        // A sync in the step before the last lock can have kept conflict copies.
        self.sync_take_hook_results();
        self.sync_track_open_vault();
        let result = self.sync_quietly()?;
        match result {
            Ok(outcome) => outcome
                .merge
                .as_ref()
                .filter(|merge| merge.changed_local())
                .map(|merge| {
                    let changed = merge.inserted + merge.updated;
                    let mut line = format!(
                        "Sync brought {changed} changed credential{} from {}.",
                        if changed == 1 { "" } else { "s" },
                        if merge.remote.pushed_by.is_empty() {
                            "the synced folder"
                        } else {
                            merge.remote.pushed_by.as_str()
                        }
                    );
                    if merge.deleted > 0 {
                        line.push_str(&format!(" {} deleted there.", merge.deleted));
                    }
                    line
                }),
            Err(SyncError::NeedsPassphrase) => {
                Some("The passphrase changed on another Mac: type the new one to sync.".to_owned())
            }
            Err(_) => None,
        }
    }

    /// "Sync now" in Settings > Vaults.
    pub(crate) fn sync_now(&mut self) {
        let Some((id, sync)) = self.sync_current() else {
            return;
        };
        if matches!(
            sync.status().map(|report| report.status),
            Ok(FileStatus::NotDownloaded)
        ) {
            let _ = sync.request_download();
        }
        match self.sync_quietly() {
            Some(Ok(outcome)) => {
                let text = match (&outcome.merge, outcome.pushed) {
                    (Some(merge), _) if merge.changed_local() => format!(
                        "Folder sync: {} credential{} changed on this Mac.",
                        merge.inserted + merge.updated + merge.deleted,
                        if merge.inserted + merge.updated + merge.deleted == 1 {
                            ""
                        } else {
                            "s"
                        }
                    ),
                    (_, true) => "Saved to the sync folder on this Mac.".to_owned(),
                    _ => "Saved to the sync folder on this Mac.".to_owned(),
                };
                self.set_ok(text);
            }
            Some(Err(err)) => {
                let icloud = self.is_icloud(&id);
                self.set_note(UiStatus::from_error(err).words(icloud));
            }
            None => {}
        }
    }

    /// Turn on sync for the open, unlocked vault `id` in `folder`.
    pub(crate) fn sync_enable(&mut self, id: &str, folder: &Path) -> Result<String, String> {
        let entry = self
            .vault_list
            .registry
            .get(id)
            .cloned()
            .ok_or_else(|| "This vault is not in the list any more.".to_owned())?;
        if self.vault_list.current.as_deref() != Some(id) || self.owner_ui.session.is_locked() {
            return Err("Unlock the vault first.".to_owned());
        }
        if !folder.is_absolute() {
            return Err("Type the absolute path of a folder.".to_owned());
        }
        if self.sync_of(id).is_some() {
            self.sync_disable(id);
        }
        let sync = FolderSync::new(SyncConfig::in_data_dir(
            &self.vault_list.data_dir,
            &entry.path,
            folder,
            &entry.id,
        ));
        // A state of an earlier try with the same name goes first.
        let _ = sync.disable();
        let report = self
            .owner_ui
            .session
            .with_vault(|vault| sync.enable(vault, &entry.name))
            .unwrap_or(Err(SyncError::Vault(VaultErrorKind::NotFound)))
            .map_err(|err| enable_error(err, &entry.name))?;
        if let Some(listed) = self.vault_list.registry.entry_mut(id) {
            listed.sync = Some(SyncLink::new(&entry.id, folder, &report.file_name));
        }
        self.save_vault_list();
        self.sync_track_open_vault();
        self.sync_note_merge(id, &report.outcome);
        self.sync_refresh();
        let label = folder_label(&self.sync.folders, folder);
        Ok(if report.linked {
            format!(
                "“{}” syncs with {label} and merged with its file {}.",
                entry.name, report.file_name
            )
        } else {
            format!(
                "“{}” syncs with {label} as {}. On your other Mac, select “Use a vault from another Mac”.",
                entry.name, report.file_name
            )
        })
    }

    /// Turn off sync for the vault `id`. The sync state goes; the synced file stays.
    /// Returns the folder and the file name, when sync was on.
    pub(crate) fn sync_disable(&mut self, id: &str) -> Option<(PathBuf, String)> {
        let link = self.vault_list.registry.get(id)?.sync.clone()?;
        if let Some(state) = link.state_name() {
            let _ = std::fs::remove_file(state_path(&self.vault_list.data_dir, state));
        }
        if let Some(entry) = self.vault_list.registry.entry_mut(id) {
            entry.sync = None;
        }
        self.save_vault_list();
        self.sync.statuses.remove(id);
        if self.vault_list.current.as_deref() == Some(id) {
            self.sync_track_open_vault();
        }
        Some((link.folder, link.file))
    }

    /// Before the vault `id` leaves the list: turn off its sync. Returns the text for
    /// the result message, when sync was on.
    pub(crate) fn sync_on_remove(&mut self, id: &str) -> Option<String> {
        let (folder, file) = self.sync_disable(id)?;
        Some(format!(
            " The synced copy {file} stays in {}.",
            folder.display()
        ))
    }

    /// The passphrase changed on another Mac: take it from the owner, rekey this vault,
    /// and sync.
    pub(crate) fn sync_take_passphrase(&mut self, passphrase: &str) -> Result<(), String> {
        let (id, sync) = self
            .sync_current()
            .ok_or_else(|| "Sync is off for this vault.".to_owned())?;
        let result = self
            .owner_ui
            .session
            .with_vault(|vault| sync.take_new_passphrase(vault, passphrase))
            .unwrap_or(Err(SyncError::Vault(VaultErrorKind::NotFound)));
        match result {
            Ok(outcome) => {
                self.sync_note_merge(&id, &outcome);
                self.sync_refresh();
                // Touch ID has the old passphrase now.
                self.refresh_unlock_setting(None);
                Ok(())
            }
            Err(SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt)) => Err(
                "This passphrase does not open the synced copy. Nothing changed.".to_owned(),
            ),
            Err(SyncError::OtherVault) => Err(
                "The synced file holds another vault. Nothing changed. Choose another synced folder, or turn sync off.".to_owned(),
            ),
            Err(err) => Err(format!("Nothing changed: {err}.")),
        }
    }

    /// Last resort: replace a damaged synced file with the vault of this Mac.
    pub(crate) fn sync_replace_damaged(&mut self) -> Result<(), String> {
        let (id, sync) = self
            .sync_current()
            .ok_or_else(|| "Sync is off for this vault.".to_owned())?;
        let result = self
            .owner_ui
            .session
            .with_vault(|vault| sync.replace_synced_file(vault))
            .unwrap_or(Err(SyncError::Vault(VaultErrorKind::NotFound)));
        result.map_err(|err| format!("Apassy did not replace the synced copy: {err}."))?;
        if self
            .sync
            .notice
            .as_ref()
            .is_some_and(|notice| notice.vault == id)
        {
            self.sync.notice = None;
        }
        self.sync_refresh();
        Ok(())
    }

    /// Open the synced file `file` on this Mac as a new vault in `<data dir>/vaults/`,
    /// with sync on, and unlock it. The name field and the passphrase field of the start
    /// screens give the name and the passphrase.
    pub(crate) fn sync_open_vault(&mut self, file: &Path, ctx: Option<&egui::Context>) {
        let (Some(folder), Some(file_name)) = (
            file.parent().filter(|folder| folder.is_absolute()),
            file.file_name().and_then(|name| name.to_str()),
        ) else {
            self.set_err("Type the absolute path of an .apassy file.");
            return;
        };
        let stem = file_name
            .strip_suffix(SYNC_FILE_EXTENSION)
            .unwrap_or(file_name);
        let (name, path) = match self.new_vault_target("", Some(stem)) {
            Ok(target) => target,
            Err(message) => {
                self.set_err(message);
                return;
            }
        };
        if let Err(message) = super::start::ensure_private_folder(&path) {
            self.set_err(message);
            return;
        }
        let passphrase = Ephemeral::take(&mut self.owner_ui.passphrase);
        if let Some(ctx) = ctx {
            forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
        }
        if passphrase.expose().is_empty() {
            self.ui.focus_start_field = true;
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
            self.set_err("Type the passphrase of the vault.");
            return;
        }
        let mut registry = self.vault_list.registry.clone();
        let id = match registry.add(&name, &path, vaults::now()) {
            Ok(id) => id,
            Err(err) => {
                self.set_err(err.to_string());
                return;
            }
        };
        if let Some(entry) = registry.entry_mut(&id) {
            entry.sync = Some(SyncLink::new(&id, folder, file_name));
        }
        let sync = FolderSync::new(SyncConfig::in_data_dir(
            &self.vault_list.data_dir,
            &path,
            folder,
            &id,
        ));
        match sync.adopt(file_name, passphrase.expose()) {
            Ok((vault, _)) => drop(vault),
            Err(err) => {
                self.sync.open_error = Some(err);
                self.sync.open_error_from_adopt = true;
                self.ui.focus_start_field = err != SyncError::NotDownloaded;
                if self.ui.focus_start_field
                    && let Some(ctx) = ctx
                {
                    ctx.request_repaint();
                }
                if err == SyncError::TimedOut {
                    self.sync.open_next_download = None;
                }
                if err == SyncError::NotDownloaded {
                    self.sync_select_open_file(file.to_path_buf(), true, ctx);
                }
                self.set_err(adopt_error(err));
                return;
            }
        }
        self.vault_list.registry = registry;
        self.save_vault_list();
        let opened = self.owner_ui.session.open_file(&path);
        if self.apply(opened, "The synced vault is open.").is_none() {
            return;
        }
        self.reset_vault_state(ctx);
        self.end_waiting_runs();
        self.list_open_vault(&name, ctx);
        let unlocked = self.owner_ui.session.unlock(passphrase.expose());
        drop(passphrase);
        self.sync.open_pick = None;
        self.sync.open_path.clear();
        self.ui.start = Step::Home;
        self.view = OwnerView::Vault;
        if unlocked.is_ok() {
            let _ = self.sync_after_unlock();
            self.sync.adopted_vault = Some(id);
        }
        let _ = self.apply(
            unlocked,
            &format!(
                "“{name}” is on this Mac. Folder sync is on for {}.",
                folder_label(&self.sync.folders, folder)
            ),
        );
    }

    /// The synced files in the folders of this Mac that no vault of the list syncs with.
    #[cfg(test)]
    pub(crate) fn sync_unlisted(&self) -> Vec<(String, FolderEntry)> {
        self.sync_unlisted_report().0
    }

    fn sync_unlisted_report(&self) -> (Vec<(String, FolderEntry)>, Option<SyncError>) {
        let synced: BTreeSet<PathBuf> = self
            .vault_list
            .registry
            .entries()
            .iter()
            .filter_map(VaultEntry::sync_file)
            .collect();
        let mut found = Vec::new();
        let mut failure = self.sync.folder_error;
        for folder in &self.sync.folders {
            match list_folder_vaults(&folder.path) {
                Ok(entries) => {
                    for entry in entries {
                        if !synced.contains(&entry.path) {
                            found.push((folder.label.clone(), entry));
                        }
                    }
                }
                Err(error) => failure = Some(error),
            }
        }
        (found, failure)
    }
}

#[cfg(test)]
impl DesktopApp {
    pub(crate) fn sync_retry_open_in_for_test(&mut self, home: &Path) {
        self.sync.detected_folders = true;
        self.sync_retry_open_with(|| Ok(crate::sync::detect_folders_in(home)));
    }

    pub(crate) fn sync_open_error_for_test(&mut self, error: SyncError) {
        self.sync.open_found = Some(Vec::new());
        self.sync.open_error = Some(error);
        self.sync.open_next_download = None;
    }

    pub(crate) fn sync_open_waiting_for_test(&self) -> bool {
        self.sync.open_waiting
    }

    /// Pretend that a change of a credential waits to sync since `since`.
    pub(crate) fn sync_force_settled_for_test(&mut self, since: Instant) {
        self.sync.changed_since = Some(since);
    }

    /// Whether a change of a credential waits to sync.
    pub(crate) fn sync_change_waits_for_test(&self) -> bool {
        self.sync.changed_since.is_some()
    }
}

/// The note text of a sync that failed in the step before a lock.
fn lock_failure(err: SyncError) -> String {
    match err {
        SyncError::NeedsPassphrase => "Sync: the passphrase changed on another Mac. Unlock the vault, then type the new passphrase.".to_owned(),
        SyncError::FolderUnavailable => "Sync: the synced folder is not available. The changes stay on this Mac and sync when it is back.".to_owned(),
        SyncError::NotDownloaded => "Sync: iCloud has not downloaded the synced file yet. The changes stay on this Mac.".to_owned(),
        other => format!("Sync: {other}. The changes stay on this Mac."),
    }
}

fn enable_error(err: SyncError, vault: &str) -> String {
    match err {
        SyncError::FolderUnavailable => "The folder is not available. Choose a folder that exists, or the folder of a sync service.".to_owned(),
        SyncError::NotDownloaded => "A file with this name is in iCloud but not on this Mac yet. Apassy asked iCloud for it. Try again when the download ends.".to_owned(),
        SyncError::Vault(VaultErrorKind::UnsupportedSchema) => "A file with this name in the folder is from another Apassy version. Update Apassy, then try again.".to_owned(),
        SyncError::Vault(VaultErrorKind::InvalidInput) => "Another program uses the vault file (a journal file is next to it). Sync stays off.".to_owned(),
        other => format!("Sync of “{vault}” stays off: {other}."),
    }
}

fn adopt_error(err: SyncError) -> String {
    match err {
        SyncError::TimedOut => "The synced file did not respond in time. No vault was added. Check the sync service and try again.".to_owned(),
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt) => "The passphrase does not open this synced vault, or the file is damaged. Nothing changed on this Mac.".to_owned(),
        SyncError::NotDownloaded => "The file is not on this Mac yet. Apassy asked iCloud for it. Try again when the download ends.".to_owned(),
        SyncError::Vault(VaultErrorKind::UnsupportedSchema) => "This file is from another Apassy version, or it is not a synced vault. Update Apassy, then try again.".to_owned(),
        SyncError::Vault(VaultErrorKind::NotFound) => "Apassy cannot find this file.".to_owned(),
        SyncError::InvalidName => "Pick an .apassy file.".to_owned(),
        other => format!("Apassy could not open the synced vault: {other}."),
    }
}

// ---- Drawing. ----

/// The note that stays until closed.
fn draw_notice(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(notice) = app.sync.notice.clone() else {
        return;
    };
    let tone = if notice.warning {
        Tone::Warning
    } else {
        Tone::Accent
    };
    let mut close = false;
    let mut replace = false;
    let damaged = app.sync.statuses.get(&notice.vault) == Some(&UiStatus::Damaged);
    kit::notice(ui, tone, &notice.title, Some(&notice.text), |ui| {
        ui.horizontal(|ui| {
            if damaged
                && app.vault_list.current.as_deref() == Some(notice.vault.as_str())
                && kit::small_button(ui, "Replace with this Mac's vault…", Style::Bordered)
                    .clicked()
            {
                replace = true;
            }
            close = kit::small_button(ui, "Close", Style::Link).clicked();
        });
    });
    if close {
        app.sync.notice = None;
    } else if replace {
        app.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::ReplaceDamaged {
            id: notice.vault,
        })));
    }
}

/// On top of each page: the sync note, and a passphrase that changed on another Mac.
pub(super) fn banner(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.sync.offered {
        return;
    }
    draw_notice(app, ui);
    let Some(entry) = app.current_vault().cloned() else {
        return;
    };
    if app.sync.statuses.get(&entry.id) == Some(&UiStatus::NeedsPassphrase) {
        let mut type_it = false;
        kit::notice(
            ui,
            Tone::Warning,
            &format!("The passphrase of “{}” changed on another Mac", entry.name),
            Some("Type the new passphrase to go on syncing. Apassy then uses it on this Mac too."),
            |ui| {
                type_it =
                    kit::small_button(ui, "Type the new passphrase…", Style::Prominent).clicked();
            },
        );
        if type_it {
            app.sync_forget_secrets(Some(ui.ctx()));
            app.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::NewPassphrase {
                id: entry.id,
            })));
        }
    }
}

/// The choices of the Sync picker: off, each synced folder of this Mac, and "Choose
/// folder…". Returns the chosen folder, `Some(None)` for off, or `None` for no change.
enum Pick {
    Off,
    Folder(PathBuf),
    Choose,
}

fn sync_picker(
    ui: &mut egui::Ui,
    salt: &str,
    folders: &[SyncFolder],
    current: Option<&Path>,
) -> Option<Pick> {
    let label = match current {
        None => "Off".to_owned(),
        Some(path) => folder_label(folders, path),
    };
    let mut pick = None;
    kit::menu(
        salt,
        kit::text(&label, Font::Body),
        ui.available_width().min(220.0),
    )
    .truncate()
    .show_ui(ui, |ui| {
        if ui.selectable_label(current.is_none(), "Off").clicked() {
            pick = Some(Pick::Off);
        }
        for folder in folders {
            let selected = current == Some(folder.path.as_path());
            if ui.selectable_label(selected, &folder.label).clicked() && !selected {
                pick = Some(Pick::Folder(folder.path.clone()));
            }
        }
        if ui.selectable_label(false, "Choose folder…").clicked() {
            pick = Some(Pick::Choose);
        }
    })
    .response
    .on_hover_text(label);
    pick
}

/// Settings > Vaults: Sync, with each vault, its folder, its status, and its actions.
pub(super) fn settings_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.sync.offered {
        return;
    }
    let current = app.vault_list.current.clone();
    let unlocked = app.owner_ui.session.has_file() && !app.owner_ui.session.is_locked();
    let missing =
        app.vault_list.registry.entries().iter().any(|entry| {
            entry.sync_state().is_some() && !app.sync.statuses.contains_key(&entry.id)
        });
    if missing {
        app.sync_refresh();
    }
    draw_notice(app, ui);
    let mut action: Option<(String, Pick)> = None;
    let mut sheet = None;
    let mut sync_now = false;
    let mut open_synced = false;
    kit::section(
        ui,
        Some("Sync"),
        Some(
            "Apassy keeps an encrypted copy of a vault in a folder that iCloud Drive, Dropbox, Google Drive, OneDrive, Syncthing, or a network share keeps in step. Changes from each Mac merge by credential. Agents, grants, rules, and activity stay on each Mac: register the agents of each Mac there. Turning sync off keeps the synced copy.",
        ),
        |s| {
            for entry in app.vault_list.registry.entries() {
                let open_unlocked = unlocked && Some(&entry.id) == current.as_ref();
                let status = app.sync.statuses.get(&entry.id);
                let link = entry.sync.as_ref().filter(|_| entry.sync_state().is_some());
                s.row(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            Label::new(kit::medium(&entry.name, Font::Body).color(kit::LABEL))
                                .wrap(),
                        );
                        if let Some(status) = status.filter(|_| link.is_some()) {
                            let (tag, tone) = status.tag();
                            kit::tag(ui, tag, tone);
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        if open_unlocked {
                            let folder = link.map(|link| link.folder.as_path());
                            if let Some(pick) = sync_picker(
                                ui,
                                &format!("sync-picker-{}", entry.id),
                                &app.sync.folders,
                                folder,
                            ) {
                                action = Some((entry.id.clone(), pick));
                            }
                            if link.is_some()
                                && kit::small_button(ui, "Sync now", Style::Bordered).clicked()
                            {
                                sync_now = true;
                            }
                        } else if link.is_some()
                            && kit::small_button(ui, "Turn off…", Style::Link).clicked()
                        {
                            sheet = Some(SyncSheet::TurnOff {
                                id: entry.id.clone(),
                            });
                        }
                    });
                    let icloud =
                        link.is_some_and(|link| Some(&link.folder) == app.sync.icloud.as_ref());
                    let line = match (link, status) {
                        (Some(link), Some(status)) => format!(
                            "{} {} in {}.",
                            status.words(icloud),
                            link.file,
                            folder_label(&app.sync.folders, &link.folder)
                        ),
                        (Some(link), None) => format!(
                            "Syncs as {} in {}.",
                            link.file,
                            folder_label(&app.sync.folders, &link.folder)
                        ),
                        (None, _) if open_unlocked => "Sync is off.".to_owned(),
                        (None, _) => {
                            "Sync is off. Open and unlock this vault to turn it on.".to_owned()
                        }
                    };
                    ui.add(
                        Label::new(kit::text(line, Font::Footnote).color(kit::SECONDARY)).wrap(),
                    );
                    if status == Some(&UiStatus::NeedsPassphrase)
                        && open_unlocked
                        && kit::small_button(ui, "Type the new passphrase…", Style::Prominent)
                            .clicked()
                    {
                        sheet = Some(SyncSheet::NewPassphrase {
                            id: entry.id.clone(),
                        });
                    }
                });
            }
            if s.clickable_row("Open a synced vault…", |ui| {
                ui.label(kit::text("Open a synced vault…", Font::Body).color(kit::ACCENT_TEXT));
            })
            .clicked()
            {
                open_synced = true;
            }
        },
    );
    let ctx = ui.ctx().clone();
    if sync_now {
        app.sync_now();
    } else if open_synced {
        app.leave_vault_for(Step::OpenSynced, Some(&ctx));
    } else if let Some((id, pick)) = action {
        match pick {
            Pick::Off => {
                sheet = Some(SyncSheet::TurnOff { id });
            }
            Pick::Choose => {
                app.sync.folder_input.clear();
                sheet = Some(SyncSheet::ChooseFolder { id });
            }
            Pick::Folder(folder) => match app.sync_enable(&id, &folder) {
                Ok(text) => app.set_ok(text),
                Err(text) => app.set_err(text),
            },
        }
    }
    if let Some(sheet) = sheet {
        app.sync_forget_secrets(Some(&ctx));
        app.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(sheet)));
    }
}

/// A sync sheet. Returns true when the owner pressed Escape. The passphrase field is
/// erased when the sheet closes.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, sheet: &SyncSheet) -> bool {
    let (SyncSheet::ChooseFolder { id }
    | SyncSheet::NewPassphrase { id }
    | SyncSheet::TurnOff { id }
    | SyncSheet::ReplaceDamaged { id }) = sheet;
    let Some(entry) = app.vault_list.registry.get(id).cloned() else {
        close_sheet(app, ctx);
        return false;
    };
    let escape = match sheet {
        SyncSheet::ChooseFolder { .. } => choose_folder_sheet(app, ctx, &entry),
        SyncSheet::NewPassphrase { .. } => new_passphrase_sheet(app, ctx, &entry),
        SyncSheet::TurnOff { .. } => turn_off_sheet(app, ctx, &entry),
        SyncSheet::ReplaceDamaged { .. } => replace_sheet(app, ctx, &entry),
    };
    if escape {
        app.sync_forget_secrets(Some(ctx));
    }
    escape
}

fn cancel_sheet(app: &mut DesktopApp, ctx: &egui::Context) {
    app.sync_forget_secrets(Some(ctx));
    close_sheet(app, ctx);
}

fn choose_folder_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut save = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-choose-folder", 500.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Sync “{}” with a folder", entry.name),
            Some(
                "Type the path of a folder that a sync service keeps in step on each Mac: Dropbox, Google Drive, OneDrive, Syncthing, or a network share. Apassy puts the encrypted file <name>.apassy there. A teammate who opens that file with the passphrase shares the whole vault.",
            ),
        );
        kit::section(ui, None, None, |s| {
            let field = s.field("Folder", |ui| {
                kit::text_input(
                    ui,
                    &mut app.sync.folder_input,
                    "sync-folder",
                    "/Users/me/Dropbox/Apassy",
                )
            });
            save = field.lost_focus() && ctx.input(|input| input.key_pressed(egui::Key::Enter));
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                save |= kit::button(ui, "Sync here", Style::Prominent).clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if save {
        let typed = app.sync.folder_input.trim().to_owned();
        let folder = PathBuf::from(&typed);
        match app.sync_enable(&entry.id, &folder) {
            Ok(text) => {
                app.ui.sheet = None;
                app.sync.folder_input.clear();
                app.set_ok(text);
            }
            Err(text) => app.set_err(text),
        }
    }
    if cancel {
        cancel_sheet(app, ctx);
    }
    response.escape
}

fn new_passphrase_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut take = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-new-passphrase", 480.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("The passphrase of “{}” changed on another Mac", entry.name),
            Some(
                "Type the new passphrase. Apassy checks it with the synced copy, then uses it for the vault on this Mac too, and syncs. Touch ID unlock on this Mac then needs to be turned on again.",
            ),
        );
        kit::section(ui, None, None, |s| {
            let field = s.field("New passphrase", |ui| {
                secure_input(
                    ui,
                    SYNC_PASSPHRASE_FIELD,
                    &mut app.sync.passphrase,
                    PASSPHRASE_CAPACITY,
                    "Required",
                )
            });
            take =
                field.lost_focus() && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                take |= kit::button(ui, "Use this passphrase", Style::Prominent).clicked();
                cancel = kit::button(ui, "Later", Style::Bordered).clicked();
            },
        );
    });
    if take {
        let passphrase = Ephemeral::take(&mut app.sync.passphrase);
        forget_secret_field(ctx, SYNC_PASSPHRASE_FIELD);
        match app.sync_take_passphrase(passphrase.expose()) {
            Ok(()) => {
                app.ui.sheet = None;
                app.set_ok(format!(
                    "“{}” uses the new passphrase and is in sync.",
                    entry.name
                ));
            }
            Err(text) => app.set_err(text),
        }
    }
    if cancel {
        cancel_sheet(app, ctx);
    }
    response.escape
}

fn turn_off_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut off = false;
    let mut cancel = false;
    let (folder, file) = entry
        .sync
        .as_ref()
        .map(|link| {
            (
                folder_label(&app.sync.folders, &link.folder),
                link.file.clone(),
            )
        })
        .unwrap_or_default();
    let response = kit::sheet(ctx, "sync-turn-off", 460.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Stop syncing “{}”?", entry.name),
            Some(&format!(
                "Apassy stops merging this vault. The vault on this Mac stays. The synced copy {file} stays in {folder}, and your other Macs keep it. Delete it there if you do not want it."
            )),
        );
        kit::sheet_buttons(
            ui,
            |ui| {
                off = kit::button(ui, "Turn off", Style::Destructive).clicked();
            },
            |ui| {
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if off {
        app.sync_disable(&entry.id);
        app.ui.sheet = None;
        app.set_ok(format!(
            "Sync of “{}” is off. The synced copy {file} stays in {folder}.",
            entry.name
        ));
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

fn replace_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut replace = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-replace", 480.0, |ui| {
        kit::sheet_title(
            ui,
            "Replace the damaged synced copy?",
            Some(&format!(
                "The synced copy of “{}” fails a check, so no Mac can merge it. Apassy can write the vault of this Mac in its place. Changes that only the damaged copy had are lost; a change that another Mac still has comes back when that Mac syncs.",
                entry.name
            )),
        );
        kit::sheet_buttons(
            ui,
            |ui| {
                replace = kit::button(ui, "Replace", Style::Destructive).clicked();
            },
            |ui| {
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if replace {
        match app.sync_replace_damaged() {
            Ok(()) => {
                app.ui.sheet = None;
                app.set_ok("The synced copy has the vault of this Mac now.");
            }
            Err(text) => app.set_err(text),
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// Begin second-Mac setup. Discard stale panel results and old form data.
pub(super) fn begin_open(app: &mut DesktopApp) {
    app.files.forget();
    app.vault_list.name_input.clear();
    app.owner_ui.passphrase.zeroize();
    app.sync.open_pick = None;
    app.sync.open_path.clear();
    app.sync.open_found = None;
    app.sync.open_error = None;
    app.sync.open_error_from_adopt = false;
    app.sync.open_waiting = false;
    app.sync.open_next_download = None;
    app.ui.start = Step::OpenSynced;
    app.ui.focus_start_field = true;
    app.ui.focus.focus_page_start();
}

/// Second-Mac setup remains available from a locked vault.
pub(super) fn start_link(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.sync.offered {
        return;
    }
    ui.vertical_centered(|ui| {
        if kit::small_button(ui, "Use a vault from another Mac…", Style::Link).clicked() {
            begin_open(app);
        }
    });
}

/// The Sync choice of the Create screen. Off by default.
pub(super) fn create_option(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.sync.offered {
        return;
    }
    let mut pick = None;
    kit::section(
        ui,
        None,
        Some(
            "Sync keeps an encrypted copy in a folder that your other Macs, or your team, keep in step.",
        ),
        |s| {
            s.row(|ui| {
                egui::Sides::new().show(
                    ui,
                    |ui| ui.label(kit::text("Sync", Font::Body).color(kit::LABEL)),
                    |ui| {
                        let current = if app.sync.create_custom {
                            None
                        } else {
                            app.sync.create_folder.as_deref()
                        };
                        pick = sync_picker(ui, "sync-create-picker", &app.sync.folders, current);
                    },
                );
            });
            if app.sync.create_custom {
                s.field("Folder", |ui| {
                    kit::text_input(
                        ui,
                        &mut app.sync.folder_input,
                        "sync-create-folder",
                        "/Users/me/Dropbox/Apassy",
                    )
                });
            }
        },
    );
    match pick {
        Some(Pick::Off) => {
            app.sync.create_folder = None;
            app.sync.create_custom = false;
        }
        Some(Pick::Folder(folder)) => {
            app.sync.create_folder = Some(folder);
            app.sync.create_custom = false;
        }
        Some(Pick::Choose) => {
            app.sync.create_folder = None;
            app.sync.create_custom = true;
        }
        None => {}
    }
}

/// After a create: turn on sync in the chosen folder. Returns a line for the result
/// message, or the error text.
pub(super) fn after_create(app: &mut DesktopApp) -> Result<Option<String>, String> {
    let folder = if app.sync.create_custom {
        Some(PathBuf::from(app.sync.folder_input.trim()))
            .filter(|path| !path.as_os_str().is_empty())
    } else {
        app.sync.create_folder.clone()
    };
    app.sync.create_folder = None;
    app.sync.create_custom = false;
    app.sync.folder_input.clear();
    let (Some(folder), true) = (folder, app.sync.offered) else {
        return Ok(None);
    };
    let Some(id) = app.current_vault().map(|entry| entry.id.clone()) else {
        return Ok(None);
    };
    match app.sync_enable(&id, &folder) {
        Ok(_) => Ok(Some(format!(
            " Folder sync is on for {}.",
            folder_label(&app.sync.folders, &folder)
        ))),
        Err(message) => Err(format!(
            "The vault is ready, but sync is off: {message} Turn it on later in Settings > Vaults."
        )),
    }
}

impl DesktopApp {
    /// Keep the selected file through discovery retries and placeholder downloads.
    pub(crate) fn sync_select_open_file(
        &mut self,
        path: PathBuf,
        waiting: bool,
        ctx: Option<&egui::Context>,
    ) {
        if self.sync.open_pick.as_ref() != Some(&path) {
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("Vault");
            self.vault_list.name_input = self.vault_list.registry.free_name(stem);
            self.owner_ui.passphrase.zeroize();
            if let Some(ctx) = ctx {
                forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
            }
            self.ui.focus_start_field = true;
        }
        self.sync.open_path = path.display().to_string();
        self.sync.open_pick = Some(path.clone());
        self.sync.open_waiting = waiting;
        self.sync.open_error = None;
        self.sync.open_error_from_adopt = false;
        self.sync.open_next_download = waiting.then(|| Instant::now() + DOWNLOAD_EVERY);
        if waiting {
            crate::sync::start_download(&path);
        }
    }

    pub(crate) fn sync_retry_open(&mut self) {
        if self.sync.detected_folders {
            self.sync.icloud = crate::sync::icloud_folder();
        }
        self.sync_retry_open_with(crate::sync::try_detect_folders);
    }

    fn sync_retry_open_with(
        &mut self,
        detect: impl FnOnce() -> Result<Vec<SyncFolder>, SyncError>,
    ) {
        // Explicit retries redetect providers, including after an empty scan.
        // Synthetic test apps never inspect this Mac's real cloud folders.
        if self.sync.detected_folders {
            match detect() {
                Ok(folders) => {
                    self.sync.folders = folders;
                    self.sync.folder_error = None;
                }
                Err(error) => self.sync.folder_error = Some(error),
            }
        }
        self.sync_refresh_open_files();
    }

    fn sync_refresh_open_files(&mut self) {
        // Automatic download checks use the existing folder list. Keep safe form state.
        let (mut found, mut error) = self.sync_unlisted_report();
        // A native panel can select a file outside the discovered service folders.
        // Use the same bounded read when that file needs a download.
        if let Some(parent) = self.sync.open_pick.as_deref().and_then(Path::parent)
            && !self.sync.folders.iter().any(|folder| folder.path == parent)
        {
            match list_folder_vaults(parent) {
                Ok(entries) => found.extend(
                    entries
                        .into_iter()
                        .map(|entry| ("Selected folder".to_owned(), entry)),
                ),
                Err(err) => error = Some(err),
            }
        }
        if let Some(path) = &self.sync.open_pick
            && let Some((_, entry)) = found.iter().find(|(_, entry)| &entry.path == path)
        {
            self.sync.open_waiting = !entry.downloaded;
        }
        self.sync.open_found = Some(found);
        self.sync.open_error = error;
        self.sync.open_error_from_adopt = false;
        self.sync.open_next_download =
            (self.sync.open_waiting && error.is_none()).then(|| Instant::now() + DOWNLOAD_EVERY);
    }
}

/// Choose a file first, then enter its existing passphrase.
pub(super) fn open_screen(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if kit::back_link(ui, "Back") {
        app.files.forget();
        app.sync.open_pick = None;
        app.sync.open_waiting = false;
        app.sync.open_next_download = None;
        app.ui.start = Step::Home;
        app.ui.focus.focus_page_start();
        return;
    }
    ui.add_space(8.0);
    ui.label(kit::text("Use a vault from another Mac", Font::Title).color(kit::LABEL));
    kit::paragraph(
        ui,
        "Select your vault file. Use the same vault passphrase as on the other Mac. Apassy keeps a local copy on this Mac.",
        Font::Callout,
        kit::SECONDARY,
    );
    kit::paragraph(
        ui,
        "macOS can ask for permission to use iCloud Drive before Apassy can read the file.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    if app.sync.open_found.is_none()
        || app
            .sync
            .open_next_download
            .is_some_and(|at| Instant::now() >= at)
    {
        app.sync_refresh_open_files();
    }
    if let Some(at) = app.sync.open_next_download {
        ui.ctx()
            .request_repaint_after(at.saturating_duration_since(Instant::now()));
    }
    let found = app.sync.open_found.clone().unwrap_or_default();
    let mut pick = None;
    if !found.is_empty() {
        kit::section(ui, Some("Vaults in your synced folders"), None, |s| {
            for (label, entry) in &found {
                let chosen = app.sync.open_pick.as_deref() == Some(entry.path.as_path());
                let subtitle = match (&entry.duplicate_of, entry.downloaded) {
                    (_, false) => format!("{label} · file download required"),
                    (Some(base), true) => format!("{label} · a duplicate of {base}"),
                    (None, true) => label.clone(),
                };
                let detail =
                    chosen.then(|| kit::text("Selected", Font::Footnote).color(kit::ACCENT_TEXT));
                let gray = egui::Color32::from_rgb(99, 99, 104);
                if s.nav(
                    Some((kit::Icon::Lock, gray)),
                    &entry.name,
                    Some(&subtitle),
                    detail,
                )
                .clicked()
                {
                    pick = Some((entry.path.clone(), !entry.downloaded));
                }
            }
        });
    } else if app.sync.open_error.is_none() {
        kit::paragraph(
            ui,
            "No vault files were found. Select a file from your synced folder.",
            Font::Callout,
            kit::SECONDARY,
        );
    }
    if let Some(error) = app.sync.open_error {
        let text = if app.sync.open_error_from_adopt {
            adopt_error(error)
        } else if error == SyncError::TimedOut {
            "The synced folder did not respond in time. The cause is not known. Your selected file and name stay in this form. Check for a macOS permission request or a file download. Then try again.".to_owned()
        } else {
            format!("Apassy could not read the synced file or folder: {error}.")
        };
        kit::paragraph(ui, &text, Font::Callout, kit::SECONDARY);
    }
    let refresh_label = if app.sync.open_error.is_some() {
        "Retry"
    } else {
        "Refresh"
    };
    if kit::small_button(ui, refresh_label, Style::Bordered).clicked() {
        app.sync_retry_open();
    }
    let ctx = ui.ctx().clone();
    if let Some((path, waiting)) = pick.take() {
        app.sync_select_open_file(path, waiting, Some(&ctx));
    }
    if files::choose_file(
        ui,
        &mut app.files,
        &mut app.sync.open_path,
        "sync-open-path",
        "Choose another file…",
        DialogKind::OpenSyncedVault,
    )
    .changed()
    {
        let path = PathBuf::from(app.sync.open_path.trim());
        app.sync_select_open_file(path, false, Some(&ctx));
    }
    let mut help = app.ui.is_expanded("sync-open-help");
    if kit::disclosure(ui, &mut help, "Help with iCloud").changed() {
        app.ui.set_expanded("sync-open-help", help);
    }
    if help {
        kit::paragraph(
            ui,
            "If macOS shows an iCloud permission request, permit access for Apassy. In Finder, open iCloud Drive and find the vault file. If the file needs a download, use Download Now. Then select Refresh or Retry.",
            Font::Callout,
            kit::SECONDARY,
        );
    }
    if let Some(file) = app.sync.open_pick.clone() {
        let filename = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Vault file");
        let service = file
            .parent()
            .map(|folder| folder_label(&app.sync.folders, folder))
            .unwrap_or_default();
        // Unknown folders belong in Details, not in the main choice summary.
        let service = if app
            .sync
            .folders
            .iter()
            .any(|folder| Some(folder.path.as_path()) == file.parent())
        {
            service
        } else {
            "Selected folder".to_owned()
        };
        ui.add_space(10.0);
        kit::paragraph(
            ui,
            format!("Selected: {filename} · {service}"),
            Font::Body,
            kit::LABEL,
        );
        if app.sync.open_waiting {
            kit::paragraph(
                ui,
                "The file download is not complete. Apassy keeps this selection and checks the file again.",
                Font::Callout,
                kit::SECONDARY,
            );
        }
        let mut submit = false;
        if !app.sync.open_waiting {
            kit::section(
                ui,
                None,
                Some(
                    "Use the existing passphrase. After an open error, type the passphrase again.",
                ),
                |s| {
                    let field = s.field("Existing vault passphrase", |ui| {
                        secure_input(
                            ui,
                            VAULT_PASSPHRASE_FIELD,
                            &mut app.owner_ui.passphrase,
                            PASSPHRASE_CAPACITY,
                            "Vault passphrase",
                        )
                    });
                    if std::mem::take(&mut app.ui.focus_start_field) && kit::keyboard_mode(&ctx) {
                        field.request_focus();
                    }
                    submit = field.lost_focus()
                        && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
                },
            );
        }
        let mut details = app.ui.is_expanded("sync-open-details");
        if kit::disclosure(ui, &mut details, "Details").changed() {
            app.ui.set_expanded("sync-open-details", details);
        }
        if details {
            kit::section(
                ui,
                None,
                Some("The local name comes from the filename. You can change the local name."),
                |s| {
                    let field = s.field("Full path", |ui| {
                        kit::text_input(
                            ui,
                            &mut app.sync.open_path,
                            "sync-open-manual-path",
                            "Absolute path of an .apassy file",
                        )
                    });
                    if field.changed() {
                        pick = Some((PathBuf::from(app.sync.open_path.trim()), false));
                    }
                    super::vaults::name_field(app, s, "vault-sync-name", "Name on this Mac");
                },
            );
        }
        if pick.is_none()
            && !app.sync.open_waiting
            && (kit::wide_button(ui, "Use this vault", Style::Prominent).clicked() || submit)
        {
            app.sync_open_vault(&file, Some(&ctx));
        }
    } else {
        let mut details = app.ui.is_expanded("sync-open-details");
        if kit::disclosure(ui, &mut details, "Details").changed() {
            app.ui.set_expanded("sync-open-details", details);
        }
        if details {
            kit::section(ui, None, None, |s| {
                let field = s.field("Full path", |ui| {
                    kit::text_input(
                        ui,
                        &mut app.sync.open_path,
                        "sync-open-manual-path",
                        "Absolute path of an .apassy file",
                    )
                });
                if field.changed() {
                    pick = Some((PathBuf::from(app.sync.open_path.trim()), false));
                }
            });
        }
    }
    if let Some((path, waiting)) = pick {
        app.sync_select_open_file(path, waiting, Some(&ctx));
    }
}

/// The unlock screen: the sync note, and a synced file that waits for its download.
pub(super) fn unlock_notices(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.sync.offered {
        return;
    }
    draw_notice(app, ui);
    let Some(entry) = app.current_vault().cloned() else {
        return;
    };
    if entry.sync_state().is_none() {
        return;
    }
    if !app.sync.statuses.contains_key(&entry.id) {
        app.sync_refresh();
    }
    let icloud = app.is_icloud(&entry.id);
    match app.sync.statuses.get(&entry.id) {
        Some(status @ (UiStatus::Waiting | UiStatus::FolderUnavailable)) => {
            kit::tone_note(
                ui,
                format!(
                    "{} You can unlock the vault on this Mac now.",
                    status.words(icloud)
                ),
                Tone::Accent,
            );
            ui.add_space(10.0);
        }
        Some(UiStatus::Syncing) => {
            kit::note(ui, "Apassy syncs when you unlock.");
            ui.add_space(10.0);
        }
        _ => {}
    }
}
