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

use eframe::egui::{self, Align, Label};
use zeroize::Zeroize;

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
            Self::UpToDate(_) => ("Up to date", Tone::Good),
            Self::Syncing => ("Syncing", Tone::Accent),
            Self::Waiting => ("Downloading", Tone::Neutral),
            Self::NeedsPassphrase => ("Needs the new passphrase", Tone::Warning),
            Self::FolderUnavailable => ("Folder not available", Tone::Warning),
            Self::Damaged => ("Damaged copy", Tone::Warning),
            Self::Problem(_) => ("Problem", Tone::Warning),
        }
    }

    /// The status in a sentence.
    pub(crate) fn words(&self, icloud: bool) -> String {
        match self {
            Self::UpToDate(Some(at)) => format!("Up to date. Last sync {}.", ago(*at)),
            Self::UpToDate(None) => "Up to date.".to_owned(),
            Self::Syncing => "Syncing: a change waits to sync.".to_owned(),
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
        self.sync.icloud = crate::sync::icloud_folder();
        self.sync.folders = crate::sync::detect_folders();
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
                        "Synced: {} credential{} changed here.",
                        merge.inserted + merge.updated + merge.deleted,
                        if merge.inserted + merge.updated + merge.deleted == 1 {
                            ""
                        } else {
                            "s"
                        }
                    ),
                    (_, true) => "Synced: the synced file has the changes of this Mac.".to_owned(),
                    _ => "Up to date.".to_owned(),
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
                "“{}” syncs with {label} as {}. Your other Macs open it with “Open a synced vault…”.",
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
        }
        let _ = self.apply(
            unlocked,
            &format!(
                "“{name}” is on this Mac now and stays in sync with {}. Register the agents of this Mac in Agents.",
                folder_label(&self.sync.folders, folder)
            ),
        );
    }

    /// The synced files in the folders of this Mac that no vault of the list syncs with.
    pub(crate) fn sync_unlisted(&self) -> Vec<(String, FolderEntry)> {
        let synced: BTreeSet<PathBuf> = self
            .vault_list
            .registry
            .entries()
            .iter()
            .filter_map(VaultEntry::sync_file)
            .collect();
        let mut found = Vec::new();
        for folder in &self.sync.folders {
            if let Ok(entries) = list_folder_vaults(&folder.path) {
                for entry in entries {
                    if !synced.contains(&entry.path) {
                        found.push((folder.label.clone(), entry));
                    }
                }
            }
        }
        found
    }
}

#[cfg(test)]
impl DesktopApp {
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
    kit::menu(salt, kit::text(label, Font::Body), 220.0).show_ui(ui, |ui| {
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
    });
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
                    ui.horizontal(|ui| {
                        ui.label(kit::medium(&entry.name, Font::Body).color(kit::LABEL));
                        if let Some(status) = status.filter(|_| link.is_some()) {
                            let (tag, tone) = status.tag();
                            kit::tag(ui, tag, tone);
                        }
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
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
            if s.clickable_row(|ui| {
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

/// "Open a synced vault…" on the welcome and the unlock screens.
pub(super) fn start_link(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.sync.offered {
        return;
    }
    ui.vertical_centered(|ui| {
        if kit::small_button(ui, "Open a synced vault…", Style::Link).clicked() {
            app.vault_list.name_input.clear();
            app.sync.open_pick = None;
            app.sync.open_path.clear();
            app.ui.start = Step::OpenSynced;
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
            " It syncs with {}.",
            folder_label(&app.sync.folders, &folder)
        ))),
        Err(message) => Err(format!(
            "The vault is ready, but sync is off: {message} Turn it on later in Settings > Vaults."
        )),
    }
}

/// The screen "Open a synced vault": the synced files of this Mac that are not in the
/// list, and a field for any `.apassy` file.
pub(super) fn open_screen(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if kit::back_link(ui, "Back") {
        app.sync.open_pick = None;
        app.ui.start = Step::Home;
    }
    ui.add_space(8.0);
    ui.label(kit::text("Open a synced vault", Font::Title).color(kit::LABEL));
    kit::paragraph(
        ui,
        "Pick a synced vault: from another Mac of yours, or a vault that your team shares in a folder. Apassy copies it to this Mac, checks it with its passphrase, and keeps it in sync. Agents stay on each Mac: register the agents of this Mac after.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    let found = app.sync_unlisted();
    let mut pick = None;
    let mut download = None;
    if !found.is_empty() {
        kit::section(ui, Some("In your synced folders"), None, |s| {
            for (label, entry) in &found {
                let chosen = app.sync.open_pick.as_deref() == Some(entry.path.as_path());
                let subtitle = match (&entry.duplicate_of, entry.downloaded) {
                    (_, false) => format!("{label} · not on this Mac yet"),
                    (Some(base), true) => format!("{label} · a duplicate of {base}"),
                    (None, true) => label.clone(),
                };
                let stem = entry
                    .name
                    .strip_suffix(SYNC_FILE_EXTENSION)
                    .unwrap_or(&entry.name);
                let detail =
                    chosen.then(|| kit::text("Chosen", Font::Footnote).color(kit::ACCENT_TEXT));
                let gray = egui::Color32::from_rgb(99, 99, 104);
                if s.nav(Some((kit::Icon::Lock, gray)), stem, Some(&subtitle), detail)
                    .clicked()
                {
                    if entry.downloaded {
                        pick = Some(entry.path.clone());
                    } else {
                        download = Some(entry.path.clone());
                    }
                }
            }
        });
    }
    if let Some(path) = download {
        crate::sync::start_download(&path);
        app.set_note("Apassy asked iCloud for the file. Pick it again when the download ends.");
    }
    kit::section(
        ui,
        None,
        Some("Or type the path of an .apassy file in any synced folder."),
        |s| {
            let field = s.field("File", |ui| {
                kit::text_input(
                    ui,
                    &mut app.sync.open_path,
                    "sync-open-path",
                    "/Users/me/Dropbox/Apassy/Team.apassy",
                )
            });
            if field.changed() {
                app.sync.open_pick = None;
            }
        },
    );
    if let Some(path) = pick {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("Vault")
            .to_owned();
        app.vault_list.name_input = app.vault_list.registry.free_name(&stem);
        app.sync.open_path = path.display().to_string();
        app.sync.open_pick = Some(path);
    }
    let file = match (&app.sync.open_pick, app.sync.open_path.trim()) {
        (Some(path), _) => Some(path.clone()),
        (None, "") => None,
        (None, typed) => Some(PathBuf::from(typed)),
    };
    let Some(file) = file else {
        return;
    };
    let stem = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("Vault")
        .to_owned();
    let mut submit = false;
    kit::section(
        ui,
        None,
        Some(
            "The new vault file goes to the Apassy data folder, which the sandbox profile closes to agents.",
        ),
        |s| {
            super::vaults::name_field(app, s, "vault-sync-name", &stem);
            let field = s.field("Passphrase", |ui| {
                secure_input(
                    ui,
                    VAULT_PASSPHRASE_FIELD,
                    &mut app.owner_ui.passphrase,
                    PASSPHRASE_CAPACITY,
                    "Passphrase of the vault",
                )
            });
            submit =
                field.lost_focus() && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
        },
    );
    if kit::wide_button(ui, "Open synced vault", Style::Prominent).clicked() || submit {
        let ctx = ui.ctx().clone();
        app.sync_open_vault(&file, Some(&ctx));
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
