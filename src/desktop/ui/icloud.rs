//! iCloud sync in the app (ADR 0014, docs/operations/icloud.md): the setting of each
//! vault, the status in plain words, the push before each lock and every few minutes,
//! the pull before an unlock, the conflict choice, and "Open a vault from iCloud…".
//!
//! The engine is [`crate::cloud`]. The vault list keeps the setting of each vault
//! ([`crate::vaults::VaultEntry::cloud`]): the name of its sync state file in
//! `<data dir>/icloud/`, which is the list ID of the vault. The app shows iCloud only
//! when it knows the path of the iCloud Drive folder: a window on macOS sets it
//! (`load_vault_list` with `persist`), tests set a temporary folder, and Linux has none.
//!
//! The push runs in the step before a lock of the session
//! ([`crate::desktop::owner_store::BeforeLock`]): after the runs that wait end, and
//! before the lock. So a lock, a switch, a backup, a quit, and a restart for an update
//! all push. A failed push never stops the lock; the app shows it once as a note.

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
use crate::cloud::{
    CLOUD_FILE_EXTENSION, CloudEntry, CloudError, CloudSync, EnableReport, SyncConfig, SyncOutcome,
    SyncReport, SyncStatus, file_sha256, list_cloud_vaults, read_state, start_download,
};
use crate::desktop::owner_store::{ENDED_BY_LOCK, Ephemeral};
use crate::desktop::{DesktopApp, OwnerView};
use crate::vault::{Vault, VaultErrorKind, format_utc};
use crate::vaults::{self, CloudLink, Registry, VaultEntry};

/// How often the app reads the iCloud status of the synced vaults.
const STATUS_EVERY: Duration = Duration::from_secs(30);
/// How often the app looks again while iCloud downloads the copy of the open vault.
const DOWNLOAD_EVERY: Duration = Duration::from_secs(2);
/// How often an unlocked vault with changes pushes, at most.
const PUSH_EVERY: Duration = Duration::from_secs(180);
/// The passphrase field of the iCloud sheets.
pub(crate) const ICLOUD_PASSPHRASE_FIELD: &str = "icloud-passphrase";
/// The folder of the sync state files in the data directory.
const STATE_DIR: &str = "icloud";

/// iCloud sync state of the app. It holds no secret after an action: the passphrase
/// field is erased after each try, at a lock, and at a switch.
#[derive(Default)]
pub(crate) struct IcloudState {
    /// The Apassy folder in iCloud Drive. `None`: the app does not offer iCloud.
    pub(crate) cloud_dir: Option<PathBuf>,
    /// The step before a lock and what it did.
    hook: Arc<Mutex<HookShared>>,
    hook_installed: bool,
    /// The last status of each synced vault in the list, by list ID.
    pub(crate) statuses: BTreeMap<String, Result<SyncReport, CloudError>>,
    next_poll: Option<Instant>,
    last_push: Option<Instant>,
    /// The failure text that the app showed last. A failure shows once.
    shown_failure: Option<String>,
    /// A note that stays until the owner closes it: a refused pull, or the place of a
    /// conflict copy.
    pub(crate) notice: Option<Notice>,
    /// The passphrase field of the iCloud sheets.
    pub(crate) passphrase: String,
    /// "Keep a copy in iCloud Drive" on the Create screen.
    pub(crate) on_create: bool,
    /// The cloud file that the owner picked on the "Open a vault from iCloud" screen.
    pub(crate) adopt_pick: Option<String>,
    /// List IDs of vaults for which the app asked iCloud for a download.
    downloads: BTreeSet<String>,
}

/// What the step before a lock shares with the window.
#[derive(Default)]
struct HookShared {
    /// The sync of the open vault. `None` when sync is off, or during "Use the iCloud
    /// version", which must not push.
    sync: Option<CloudSync>,
    /// A failed push, for a note.
    failure: Option<String>,
    /// A push copied the vault.
    pushed: bool,
}

/// A note in the window about iCloud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notice {
    pub(crate) title: String,
    pub(crate) text: String,
    pub(crate) warning: bool,
}

/// An iCloud sheet in Settings > Vaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IcloudSheet {
    TurnOn { id: String },
    TurnOff { id: String },
    Conflict { id: String },
}

/// The version that the owner keeps in a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice {
    KeepThisMac,
    UseIcloud,
}

/// What happened before an unlock.
#[derive(Debug, Default)]
pub(crate) struct PreUnlock {
    loaded: Option<SyncOutcome>,
    refused: Option<CloudError>,
}

/// The path of the sync state file `state` in `data_dir`, as in
/// [`SyncConfig::in_data_dir`].
fn state_path(data_dir: &Path, state: &str) -> PathBuf {
    data_dir.join(STATE_DIR).join(format!("{state}.json"))
}

/// Push when this Mac has changes, or when the cloud copy is gone. Returns the push, or
/// `None` when there was nothing to push. The error is text for a note.
fn push_if_needed(sync: &CloudSync, vault: &mut Vault) -> Result<Option<SyncOutcome>, String> {
    let report = sync.status().map_err(|err| push_failure(&err))?;
    match report.status {
        SyncStatus::PushNeeded | SyncStatus::CloudMissing => {
            sync.push(vault).map(Some).map_err(|err| push_failure(&err))
        }
        SyncStatus::Conflict => Err(
            "iCloud: this Mac and iCloud both changed the vault, so Apassy did not upload the changes of this Mac. Unlock the vault and choose which version to keep."
                .to_owned(),
        ),
        SyncStatus::NotDownloaded => Err(
            "iCloud: the iCloud copy is still downloading, so Apassy did not upload the changes of this Mac yet."
                .to_owned(),
        ),
        SyncStatus::Unavailable => Err(
            "iCloud Drive is off, so Apassy did not upload the changes. They stay on this Mac."
                .to_owned(),
        ),
        SyncStatus::InSync | SyncStatus::PullAvailable => Ok(None),
    }
}

fn push_failure(err: &CloudError) -> String {
    format!("iCloud: Apassy did not upload the changes ({err}). They stay on this Mac.")
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

/// The time the cloud file was saved, in Unix seconds.
fn cloud_saved_at(report: &SyncReport) -> Option<u64> {
    std::fs::metadata(&report.cloud_path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs())
}

/// The status of a vault in plain words, and its tone.
pub(crate) fn status_words(status: &Result<SyncReport, CloudError>) -> (String, Tone) {
    let report = match status {
        Ok(report) => report,
        Err(CloudError::State) => {
            return (
                "The sync settings are damaged. Turn iCloud sync off and on again.".to_owned(),
                Tone::Warning,
            );
        }
        Err(CloudError::Vault(VaultErrorKind::NotFound)) => {
            return ("The vault file is missing.".to_owned(), Tone::Warning);
        }
        Err(err) => return (format!("iCloud: {err}."), Tone::Warning),
    };
    match report.status {
        SyncStatus::InSync => (
            match report.last_sync_at {
                Some(at) => format!("In sync with iCloud. Last sync {}.", ago(at)),
                None => "In sync with iCloud.".to_owned(),
            },
            Tone::Good,
        ),
        SyncStatus::PushNeeded => (
            "Changes on this Mac are not uploaded yet.".to_owned(),
            Tone::Neutral,
        ),
        SyncStatus::PullAvailable => (
            match cloud_saved_at(report) {
                Some(at) => format!(
                    "A newer copy from another Mac is in iCloud, saved {}.",
                    ago(at)
                ),
                None => "A newer copy from another Mac is in iCloud.".to_owned(),
            },
            Tone::Accent,
        ),
        SyncStatus::Conflict => (
            "This Mac and iCloud both changed the vault. Choose which version to keep.".to_owned(),
            Tone::Warning,
        ),
        SyncStatus::CloudMissing => (
            "The copy in iCloud is missing. “Sync now” uploads it again.".to_owned(),
            Tone::Warning,
        ),
        SyncStatus::NotDownloaded => ("Downloading from iCloud…".to_owned(), Tone::Neutral),
        SyncStatus::Unavailable => ("iCloud Drive is off on this Mac.".to_owned(), Tone::Warning),
    }
}

/// The short tag of a status.
fn status_tag(status: &Result<SyncReport, CloudError>) -> (&'static str, Tone) {
    match status.as_ref().map(|report| report.status) {
        Ok(SyncStatus::InSync) => ("In sync", Tone::Good),
        Ok(SyncStatus::PushNeeded) => ("Not uploaded", Tone::Neutral),
        Ok(SyncStatus::PullAvailable) => ("Newer in iCloud", Tone::Accent),
        Ok(SyncStatus::Conflict) => ("Conflict", Tone::Warning),
        Ok(SyncStatus::CloudMissing) => ("Missing in iCloud", Tone::Warning),
        Ok(SyncStatus::NotDownloaded) => ("Downloading", Tone::Neutral),
        Ok(SyncStatus::Unavailable) => ("iCloud Drive off", Tone::Warning),
        Err(_) => ("Problem", Tone::Warning),
    }
}

/// The line after a pull: who saved the copy, and when.
fn loaded_line(outcome: &SyncOutcome) -> String {
    let when = outcome
        .pushed_at
        .map(|at| format!(", saved {}", ago(at)))
        .unwrap_or_default();
    if outcome.pushed_by.is_empty() {
        format!("Apassy loaded the newer copy from iCloud{when}.")
    } else {
        format!(
            "Apassy loaded the newer copy from {}{when}.",
            outcome.pushed_by
        )
    }
}

/// The note after a refused pull. The vault on this Mac did not change.
fn refused_notice(err: &CloudError, vault: &str, cloud_file: &str) -> Notice {
    let text = match err {
        CloudError::Rollback {
            cloud_generation,
            synced_generation,
        } if cloud_generation < synced_generation => format!(
            "The iCloud copy of “{vault}” is older than the copy that this Mac synced last (generation {cloud_generation}, last sync {synced_generation}). Someone may have put an old copy back, or iCloud delivered an old version late. The vault on this Mac did not change. To put this Mac's version back in iCloud, choose “Keep this Mac's version” in Settings > Vaults."
        ),
        CloudError::Rollback { .. } => format!(
            "The iCloud copy of “{vault}” has the generation of the last sync but other content: two Macs saved it at the same time. The vault on this Mac did not change. Choose which version to keep in Settings > Vaults."
        ),
        CloudError::DifferentVault => format!(
            "The iCloud file “{cloud_file}” holds another vault now. The vault on this Mac did not change. Turn iCloud sync of “{vault}” off and on again to use a new iCloud file."
        ),
        CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt) => format!(
            "The iCloud copy of “{vault}” does not open with this passphrase, or it is damaged. If you changed the passphrase on another Mac, lock and unlock with the new passphrase. The vault on this Mac did not change."
        ),
        other => format!(
            "Apassy did not load the iCloud copy of “{vault}”: {other}. The vault on this Mac did not change."
        ),
    };
    Notice {
        title: "Apassy did not load the iCloud copy".to_owned(),
        text,
        warning: true,
    }
}

fn enable_error(err: &CloudError, vault: &str) -> String {
    match err {
        CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt) => format!(
            "This is not the passphrase of “{vault}”. iCloud sync stays off."
        ),
        CloudError::Vault(VaultErrorKind::Locked) => "Unlock the vault first.".to_owned(),
        CloudError::NotDownloaded => "A file with this name is in iCloud but not on this Mac yet. Apassy asked iCloud for it. Try again when the download ends.".to_owned(),
        CloudError::Unavailable => "iCloud Drive is off on this Mac. Turn it on in System Settings, then try again.".to_owned(),
        CloudError::Vault(VaultErrorKind::UnsupportedSchema) => "A file with this name in iCloud Drive is from a newer Apassy. Update Apassy, then try again.".to_owned(),
        CloudError::Vault(VaultErrorKind::InvalidInput) => "Another program uses the vault file (a journal file is next to it). iCloud sync stays off.".to_owned(),
        other => format!("iCloud sync stays off: {other}."),
    }
}

fn adopt_error(err: &CloudError) -> String {
    match err {
        CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt) => "The passphrase does not open this iCloud copy, or the copy is damaged. Nothing changed on this Mac.".to_owned(),
        CloudError::NotDownloaded => "The copy is not on this Mac yet. Apassy asked iCloud for it. Try again when the download ends.".to_owned(),
        CloudError::Vault(VaultErrorKind::UnsupportedSchema) => "This copy is from a newer Apassy, or it is not a synced vault. Update Apassy, then try again.".to_owned(),
        CloudError::Vault(VaultErrorKind::AlreadyExists) => "A file is already at the place of the new vault. Choose another name.".to_owned(),
        other => format!("Apassy could not open the iCloud copy: {other}."),
    }
}

/// The stem of a cloud file name: `Personal` for `Personal.apassy`.
fn cloud_stem(name: &str) -> &str {
    name.strip_suffix(CLOUD_FILE_EXTENSION).unwrap_or(name)
}

/// Link each synced vault of a rebuilt list to its sync state again, when the proof
/// holds: the state names the vault file, and the file has the hash of the last sync.
/// Returns a line for the note of the list, or `None` when there was nothing to link.
pub(crate) fn relink_states(data_dir: &Path, registry: &mut Registry) -> Option<String> {
    let dir = data_dir.join(STATE_DIR);
    let read = std::fs::read_dir(&dir).ok()?;
    let linked: BTreeSet<String> = registry
        .entries()
        .iter()
        .filter_map(|entry| entry.cloud_state().map(str::to_owned))
        .collect();
    let mut relinked = Vec::new();
    let mut lost = 0usize;
    let mut files: Vec<PathBuf> = read
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    for path in files {
        let Some(state_name) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if CloudLink::new(state_name).state_name().is_none() || linked.contains(state_name) {
            continue;
        }
        let Ok(Some(state)) = read_state(&path) else {
            lost += 1;
            continue;
        };
        let matched = state.vault_path.as_deref().and_then(|vault_path| {
            registry
                .find_path(vault_path)
                .filter(|entry| entry.cloud.is_none())
                .map(|entry| (entry.id.clone(), entry.name.clone(), entry.path.clone()))
        });
        let proven = matched.filter(|(_, _, file)| {
            state.last_sha256.is_some() && file_sha256(file).ok() == state.last_sha256
        });
        match proven {
            Some((id, name, _)) => {
                if let Some(entry) = registry.entry_mut(&id) {
                    entry.cloud = Some(CloudLink::new(state_name));
                }
                relinked.push(name);
            }
            None => lost += 1,
        }
    }
    if relinked.is_empty() && lost == 0 {
        return None;
    }
    let mut line = String::new();
    if !relinked.is_empty() {
        let names: Vec<String> = relinked.iter().map(|name| format!("“{name}”")).collect();
        line.push_str(&format!(
            "iCloud sync is on again for {}: the file matches its last sync.",
            names.join(", ")
        ));
    }
    if lost > 0 {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&format!(
            "Apassy could not prove which vault {} iCloud sync {} to. Turn iCloud sync on again in Settings > Vaults; Apassy then links to the same iCloud file.",
            if lost == 1 { "one" } else { "some" },
            if lost == 1 { "belongs" } else { "belong" },
        ));
    }
    Some(line)
}

impl DesktopApp {
    /// The app offers iCloud sync: it knows the path of the iCloud Drive folder.
    pub(crate) fn icloud_offered(&self) -> bool {
        self.icloud.cloud_dir.is_some()
    }

    /// iCloud Drive is on: the folder above the Apassy folder exists.
    pub(crate) fn icloud_ready(&self) -> bool {
        self.icloud
            .cloud_dir
            .as_deref()
            .and_then(Path::parent)
            .is_some_and(Path::is_dir)
    }

    fn icloud_config(&self, entry: &VaultEntry, state: &str) -> Option<SyncConfig> {
        let cloud_dir = self.icloud.cloud_dir.as_ref()?;
        Some(SyncConfig::in_data_dir(
            &self.vault_list.data_dir,
            &entry.path,
            cloud_dir,
            state,
        ))
    }

    /// The sync of the listed vault `id`, when iCloud sync is on for it.
    pub(crate) fn icloud_sync(&self, id: &str) -> Option<CloudSync> {
        let entry = self.vault_list.registry.get(id)?;
        let state = entry.cloud_state()?;
        self.icloud_config(entry, state).map(CloudSync::new)
    }

    /// The list ID and the sync of the open vault, when iCloud sync is on for it.
    fn icloud_current(&self) -> Option<(String, CloudSync)> {
        let id = self.current_vault()?.id.clone();
        let sync = self.icloud_sync(&id)?;
        Some((id, sync))
    }

    /// The last status of the open vault.
    fn icloud_current_status(&self) -> Option<SyncStatus> {
        let id = self.current_vault()?.id.as_str();
        match self.icloud.statuses.get(id)? {
            Ok(report) => Some(report.status),
            Err(_) => None,
        }
    }

    /// The step before a lock pushes the open vault from now on. Call it when the open
    /// vault or its setting changes. The engine refuses a vault at another path or with
    /// another vault ID, so a push never reaches the iCloud file of another vault.
    pub(crate) fn icloud_track_open_vault(&mut self) {
        if !self.icloud.hook_installed {
            let shared = Arc::clone(&self.icloud.hook);
            self.owner_ui
                .session
                .set_before_lock(Some(Box::new(move |vault: &mut Vault| {
                    let mut shared = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    let Some(sync) = shared.sync.clone() else {
                        return;
                    };
                    match push_if_needed(&sync, vault) {
                        Ok(pushed) => {
                            shared.failure = None;
                            shared.pushed |= pushed.is_some();
                        }
                        Err(text) => shared.failure = Some(text),
                    }
                })));
            self.icloud.hook_installed = true;
        }
        let sync = self.icloud_current().map(|(_, sync)| sync);
        self.icloud
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync = sync;
        self.icloud.next_poll = None;
        self.icloud.last_push = None;
    }

    /// The open vault is gone: no push before a lock, no typed passphrase, and no note
    /// about it.
    pub(crate) fn icloud_forget_open_vault(&mut self, ctx: Option<&egui::Context>) {
        self.icloud
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync = None;
        self.icloud_forget_secrets(ctx);
        self.icloud.notice = None;
        self.icloud.next_poll = None;
    }

    /// Erase the passphrase field of the iCloud sheets and its undo history.
    pub(crate) fn icloud_forget_secrets(&mut self, ctx: Option<&egui::Context>) {
        self.icloud.passphrase.zeroize();
        if let Some(ctx) = ctx {
            forget_secret_field(ctx, ICLOUD_PASSPHRASE_FIELD);
        }
    }

    /// Read the status of each synced vault of the list.
    pub(crate) fn icloud_refresh(&mut self) {
        let ids: Vec<String> = self
            .vault_list
            .registry
            .entries()
            .iter()
            .filter(|entry| entry.cloud_state().is_some())
            .map(|entry| entry.id.clone())
            .collect();
        let mut statuses = BTreeMap::new();
        for id in ids {
            if let Some(sync) = self.icloud_sync(&id) {
                statuses.insert(id, sync.status());
            }
        }
        self.icloud.statuses = statuses;
    }

    /// Each frame: take what the step before a lock did, read the status now and then,
    /// ask iCloud for a download, and push an unlocked vault with changes every few
    /// minutes when no run waits for the owner.
    pub(crate) fn poll_icloud(&mut self, ctx: &egui::Context) {
        if self.icloud.cloud_dir.is_none() {
            return;
        }
        self.icloud_take_hook_results();
        let now = Instant::now();
        if self.icloud.next_poll.is_none_or(|at| now >= at) {
            self.icloud_poll_now();
            let wait = if self.icloud_current_status() == Some(SyncStatus::NotDownloaded) {
                DOWNLOAD_EVERY
            } else {
                STATUS_EVERY
            };
            self.icloud.next_poll = Some(now + wait);
        }
        if let Some(at) = self.icloud.next_poll {
            ctx.request_repaint_after(at.saturating_duration_since(now));
        }
    }

    /// One poll: the statuses, a download request, and a push when it is time.
    pub(crate) fn icloud_poll_now(&mut self) {
        self.icloud_refresh();
        let Some((id, sync)) = self.icloud_current() else {
            return;
        };
        let status = self.icloud_current_status();
        if status != Some(SyncStatus::NotDownloaded) {
            // A later eviction asks iCloud again.
            self.icloud.downloads.remove(&id);
        }
        match status {
            Some(SyncStatus::NotDownloaded) if self.icloud.downloads.insert(id) => {
                let _ = sync.request_download();
            }
            Some(SyncStatus::PushNeeded | SyncStatus::CloudMissing) => {
                let due = self
                    .icloud
                    .last_push
                    .is_none_or(|at| at.elapsed() >= PUSH_EVERY);
                let waiting = self
                    .approvals()
                    .is_some_and(|queue| !queue.pending().is_empty());
                if due && !waiting && !self.owner_ui.session.is_locked() {
                    let _ = self.icloud_push_now();
                }
            }
            _ => {}
        }
    }

    fn icloud_take_hook_results(&mut self) {
        let (failure, pushed) = {
            let mut shared = self
                .icloud
                .hook
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (shared.failure.take(), std::mem::take(&mut shared.pushed))
        };
        if pushed {
            self.icloud.last_push = Some(Instant::now());
            self.icloud.shown_failure = None;
            self.icloud.next_poll = None;
        }
        if let Some(text) = failure {
            self.icloud_failure_once(text);
        }
    }

    /// Show a failure as a note, once until something changes.
    fn icloud_failure_once(&mut self, text: String) {
        if self.icloud.shown_failure.as_deref() != Some(text.as_str()) {
            self.set_note(text.clone());
            self.icloud.shown_failure = Some(text);
        }
    }

    /// Push the open, unlocked vault when it has changes. `None` when sync is off or
    /// the vault is locked.
    pub(crate) fn icloud_push_now(&mut self) -> Option<Result<Option<SyncOutcome>, String>> {
        let (id, sync) = self.icloud_current()?;
        if self.owner_ui.session.is_locked() {
            return None;
        }
        let result = self
            .owner_ui
            .session
            .with_vault(|vault| push_if_needed(&sync, vault))?;
        self.icloud.last_push = Some(Instant::now());
        match &result {
            Ok(_) => self.icloud.shown_failure = None,
            Err(text) => self.icloud_failure_once(text.clone()),
        }
        self.icloud.statuses.insert(id, sync.status());
        Some(result)
    }

    /// "Sync now" in Settings > Vaults.
    pub(crate) fn icloud_sync_now(&mut self) {
        let Some((id, sync)) = self.icloud_current() else {
            return;
        };
        let status = sync.status();
        if let Ok(report) = &status
            && report.status == SyncStatus::Conflict
        {
            self.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(IcloudSheet::Conflict {
                id,
            })));
            return;
        }
        if let Ok(report) = &status
            && report.status == SyncStatus::NotDownloaded
        {
            let _ = sync.request_download();
            self.set_note("iCloud is downloading the copy. Apassy syncs when the download ends.");
            self.icloud.statuses.insert(id, status);
            return;
        }
        match self.icloud_push_now() {
            Some(Ok(Some(outcome))) => self.set_ok(format!(
                "iCloud has the changes of this Mac ({}).",
                outcome.cloud_file_name
            )),
            Some(Ok(None)) => {
                let (words, _) = status_words(&status);
                self.set_ok(match status.as_ref().map(|report| report.status) {
                    Ok(SyncStatus::PullAvailable) => {
                        "A newer copy is in iCloud. Lock and unlock the vault to load it."
                            .to_owned()
                    }
                    _ => words,
                });
            }
            Some(Err(text)) => self.set_err(text),
            None => {}
        }
    }

    /// Before an unlock with `passphrase`: when another Mac pushed a newer copy, pull it
    /// into the locked vault. A refused pull changes nothing on this Mac; the owner sees
    /// why after the unlock. A copy that iCloud did not download yet is requested.
    pub(crate) fn icloud_before_unlock(&mut self, passphrase: &str) -> PreUnlock {
        let mut pre = PreUnlock::default();
        let Some((id, sync)) = self.icloud_current() else {
            return pre;
        };
        if !self.owner_ui.session.is_locked() {
            return pre;
        }
        match sync.status().map(|report| report.status) {
            Ok(SyncStatus::PullAvailable) => {
                match self
                    .owner_ui
                    .session
                    .with_vault(|vault| sync.pull(vault, passphrase))
                {
                    Some(Ok(outcome)) => pre.loaded = Some(outcome),
                    Some(Err(err)) => pre.refused = Some(err),
                    None => {}
                }
            }
            Ok(SyncStatus::NotDownloaded) if self.icloud.downloads.insert(id.clone()) => {
                let _ = sync.request_download();
            }
            _ => {}
        }
        self.icloud.statuses.insert(id, sync.status());
        self.icloud.next_poll = None;
        pre
    }

    /// After the unlock: the note of a refused pull, and the line of a loaded copy for
    /// the result message.
    pub(crate) fn icloud_after_unlock(&mut self, pre: PreUnlock, unlocked: bool) -> Option<String> {
        if let Some(err) = pre.refused
            && unlocked
        {
            let vault = self.current_vault_name().unwrap_or_default();
            let cloud_file = self
                .icloud_current()
                .and_then(|(_, sync)| sync.state().ok().flatten())
                .map(|state| state.cloud_file_name)
                .unwrap_or_default();
            self.icloud.notice = Some(refused_notice(&err, &vault, &cloud_file));
        }
        if unlocked {
            self.icloud_track_open_vault();
            // A newer copy loaded: an earlier refusal is old news.
            if pre.loaded.is_some()
                && self
                    .icloud
                    .notice
                    .as_ref()
                    .is_some_and(|notice| notice.warning)
            {
                self.icloud.notice = None;
            }
        }
        pre.loaded.as_ref().map(loaded_line)
    }

    /// Turn on iCloud sync for the open, unlocked vault `id`, with its passphrase.
    pub(crate) fn icloud_enable(
        &mut self,
        id: &str,
        passphrase: &str,
    ) -> Result<EnableReport, String> {
        if !self.icloud_offered() {
            return Err("iCloud sync is not available on this computer.".to_owned());
        }
        if !self.icloud_ready() {
            return Err(enable_error(&CloudError::Unavailable, ""));
        }
        let entry = self
            .vault_list
            .registry
            .get(id)
            .cloned()
            .ok_or_else(|| "This vault is not in the list any more.".to_owned())?;
        if self.vault_list.current.as_deref() != Some(id) || self.owner_ui.session.is_locked() {
            return Err("Unlock the vault first.".to_owned());
        }
        let config = self
            .icloud_config(&entry, &entry.id)
            .ok_or_else(|| "iCloud sync is not available on this computer.".to_owned())?;
        let sync = CloudSync::new(config);
        // A state of an earlier try with the same name goes first.
        let _ = sync.disable();
        let report = self
            .owner_ui
            .session
            .with_vault(|vault| sync.enable(vault, passphrase, &entry.name))
            .unwrap_or(Err(CloudError::Vault(VaultErrorKind::NotFound)))
            .map_err(|err| enable_error(&err, &entry.name))?;
        if let Some(listed) = self.vault_list.registry.entry_mut(id) {
            listed.cloud = Some(CloudLink::new(&entry.id));
        }
        self.save_vault_list();
        self.icloud_track_open_vault();
        self.icloud.statuses.insert(id.to_owned(), sync.status());
        Ok(report)
    }

    /// The result text of a turn-on, for the owner.
    fn enable_message(&mut self, id: &str, report: &EnableReport) {
        let name = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        match (report.pushed, report.status) {
            (true, _) => self.set_ok(format!(
                "“{name}” is in iCloud Drive as {}. Apassy uploads changes when you lock the vault and every few minutes.",
                report.cloud_file_name
            )),
            (false, SyncStatus::Conflict) => {
                self.set_note(format!(
                    "iCloud Drive has another version of “{name}” ({}). Choose which version to keep.",
                    report.cloud_file_name
                ));
                self.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(IcloudSheet::Conflict {
                    id: id.to_owned(),
                })));
            }
            (false, _) => self.set_ok(format!(
                "“{name}” is linked to its copy in iCloud Drive ({}).",
                report.cloud_file_name
            )),
        }
    }

    /// Turn off iCloud sync for the vault `id`. The sync state goes; the iCloud file
    /// stays. Returns the name of the iCloud file, when Apassy knows it.
    pub(crate) fn icloud_disable(&mut self, id: &str) -> Option<String> {
        let state = self
            .vault_list
            .registry
            .get(id)
            .and_then(VaultEntry::cloud_state)
            .map(str::to_owned)?;
        let path = state_path(&self.vault_list.data_dir, &state);
        let cloud_file = read_state(&path)
            .ok()
            .flatten()
            .map(|state| state.cloud_file_name);
        let _ = std::fs::remove_file(&path);
        if let Some(entry) = self.vault_list.registry.entry_mut(id) {
            entry.cloud = None;
        }
        self.save_vault_list();
        self.icloud.statuses.remove(id);
        if self.vault_list.current.as_deref() == Some(id) {
            self.icloud_track_open_vault();
        }
        Some(cloud_file.unwrap_or_else(|| "the vault file".to_owned()))
    }

    /// Before the vault `id` leaves the list: turn off its sync. Returns the text for
    /// the result message, when sync was on.
    pub(crate) fn icloud_on_remove(&mut self, id: &str) -> Option<String> {
        let cloud_file = self.icloud_disable(id)?;
        Some(format!(
            " The copy in iCloud Drive ({cloud_file}) stays; delete it in Finder if you do not want it."
        ))
    }

    /// Keep one version in a conflict, with the passphrase of the vault. The other
    /// version goes to the conflicts folder first. The vault is unlocked after it.
    pub(crate) fn icloud_resolve(
        &mut self,
        choice: Choice,
        passphrase: &str,
        ctx: Option<&egui::Context>,
    ) -> bool {
        let Some((_, sync)) = self.icloud_current() else {
            self.set_err("iCloud sync is off for this vault.");
            return false;
        };
        let result = match choice {
            Choice::KeepThisMac => {
                if self.owner_ui.session.is_locked() {
                    if let Err(err) = self.owner_ui.session.unlock(passphrase) {
                        self.set_err(err.message);
                        return false;
                    }
                    self.view = OwnerView::Vault;
                }
                self.owner_ui
                    .session
                    .with_vault(|vault| sync.keep_this_mac(vault, passphrase))
            }
            Choice::UseIcloud => {
                if !self.owner_ui.session.is_locked() {
                    // A wrong passphrase must not lock the owner out: the file of this
                    // Mac opens again with it after the pull.
                    if let Some(path) = self.owner_ui.session.vault_path()
                        && Vault::verify_passphrase_at(&path, passphrase).is_err()
                    {
                        self.set_err(
                            "This is not the passphrase of the vault. Nothing changed. If the iCloud copy has a new passphrase, lock the vault and choose on the unlock screen.",
                        );
                        return false;
                    }
                    // The owner chose the iCloud version, so this lock must not push.
                    let saved = self
                        .icloud
                        .hook
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .sync
                        .take();
                    let approvals = self.approvals();
                    let _ = self
                        .owner_ui
                        .session
                        .lock_ending_runs(approvals.as_deref(), ENDED_BY_LOCK);
                    self.icloud
                        .hook
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .sync = saved;
                }
                let result = self
                    .owner_ui
                    .session
                    .with_vault(|vault| sync.use_icloud(vault, passphrase));
                // The loaded copy, or the file of this Mac after a failure, opens again.
                let unlocked = self.owner_ui.session.unlock(passphrase);
                self.reset_vault_state(ctx);
                self.end_waiting_runs();
                self.icloud_track_open_vault();
                self.view = OwnerView::Vault;
                if let (Err(err), Some(Ok(_))) = (&unlocked, &result) {
                    self.set_err(err.message.clone());
                }
                result
            }
        };
        let id = self.current_vault().map(|entry| entry.id.clone());
        if let Some(id) = id {
            self.icloud.statuses.insert(id, sync.status());
        }
        match result {
            Some(Ok(outcome)) => {
                let kept = match choice {
                    Choice::KeepThisMac => "Apassy kept the version of this Mac and uploaded it.",
                    Choice::UseIcloud => "Apassy loaded the iCloud version.",
                };
                let text = match &outcome.conflict_copy {
                    Some(path) => format!(
                        "{kept} The other version is saved at {}. Open it with “Open vault file…” and the passphrase of its time to copy what you need.",
                        path.display()
                    ),
                    None => format!("{kept} The two versions were the same."),
                };
                self.icloud.notice = Some(Notice {
                    title: "The conflict is solved".to_owned(),
                    text,
                    warning: false,
                });
                self.set_ok(kept);
                true
            }
            Some(Err(err)) => {
                let vault = self.current_vault_name().unwrap_or_default();
                self.set_err(match err {
                    CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt) => {
                        "The passphrase does not open the iCloud copy, or the copy is damaged. Nothing changed.".to_owned()
                    }
                    CloudError::Rollback { .. } => refused_notice(&err, &vault, "").text,
                    other => format!("Apassy did not solve the conflict: {other}."),
                });
                false
            }
            None => false,
        }
    }

    /// Open the cloud file `cloud_name` on this Mac as a new vault in
    /// `<data dir>/vaults/`, with sync on, and unlock it. The name field and the
    /// passphrase field of the start screens give the name and the passphrase.
    pub(crate) fn icloud_adopt(&mut self, cloud_name: &str, ctx: Option<&egui::Context>) {
        let (name, path) = match self.new_vault_target("", Some(cloud_stem(cloud_name))) {
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
            entry.cloud = Some(CloudLink::new(&id));
        }
        let Some(config) = registry
            .get(&id)
            .and_then(|entry| self.icloud_config(entry, &id))
        else {
            self.set_err("iCloud sync is not available on this computer.");
            return;
        };
        let outcome = match CloudSync::new(config).adopt(cloud_name, passphrase.expose()) {
            Ok((vault, outcome)) => {
                // The session opens the file below.
                drop(vault);
                outcome
            }
            Err(err) => {
                self.set_err(adopt_error(&err));
                return;
            }
        };
        self.vault_list.registry = registry;
        self.save_vault_list();
        let opened = self.owner_ui.session.open_file(&path);
        if self
            .apply(opened, "The vault from iCloud is open.")
            .is_none()
        {
            return;
        }
        self.reset_vault_state(ctx);
        self.end_waiting_runs();
        self.list_open_vault(&name, ctx);
        let unlocked = self.owner_ui.session.unlock(passphrase.expose());
        drop(passphrase);
        self.icloud.adopt_pick = None;
        self.ui.start = Step::Home;
        self.view = OwnerView::Vault;
        let from = if outcome.pushed_by.is_empty() {
            String::new()
        } else {
            format!(" It is the copy from {}.", outcome.pushed_by)
        };
        let _ = self.apply(
            unlocked,
            &format!("“{name}” is on this Mac now and stays in sync with iCloud.{from}"),
        );
    }

    /// The cloud vaults that no vault of the list syncs with.
    pub(crate) fn icloud_unlisted(&self) -> Result<Vec<CloudEntry>, CloudError> {
        let cloud_dir = self
            .icloud
            .cloud_dir
            .as_ref()
            .ok_or(CloudError::Unavailable)?;
        let synced: BTreeSet<String> = self
            .vault_list
            .registry
            .entries()
            .iter()
            .filter_map(|entry| {
                let state = entry.cloud_state()?;
                read_state(&state_path(&self.vault_list.data_dir, state))
                    .ok()
                    .flatten()
                    .map(|state| state.cloud_file_name)
            })
            .collect();
        Ok(list_cloud_vaults(cloud_dir)?
            .into_iter()
            .filter(|entry| !synced.contains(&entry.name))
            .collect())
    }
}

/// The name of the iCloud file of a synced vault.
fn cloud_file_of(app: &DesktopApp, entry: &VaultEntry) -> Option<String> {
    let state = entry.cloud_state()?;
    read_state(&state_path(&app.vault_list.data_dir, state))
        .ok()
        .flatten()
        .map(|state| state.cloud_file_name)
}

// ---- Drawing. ----

/// The note that stays until closed.
fn draw_notice(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(notice) = app.icloud.notice.clone() else {
        return;
    };
    let tone = if notice.warning {
        Tone::Warning
    } else {
        Tone::Good
    };
    let mut close = false;
    kit::notice(ui, tone, &notice.title, Some(&notice.text), |ui| {
        close = kit::small_button(ui, "Close", Style::Link).clicked();
    });
    if close {
        app.icloud.notice = None;
    }
}

/// On top of each page: the iCloud note, a newer copy in iCloud, or a conflict.
pub(super) fn banner(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.icloud_offered() {
        return;
    }
    if app.icloud.notice.is_some() {
        draw_notice(app, ui);
        return;
    }
    let Some(entry) = app.current_vault().cloned() else {
        return;
    };
    let Some(status) = app.icloud.statuses.get(&entry.id).cloned() else {
        return;
    };
    let Ok(report) = &status else {
        return;
    };
    match report.status {
        SyncStatus::PullAvailable => {
            let (words, _) = status_words(&status);
            let mut lock = false;
            kit::notice(
                ui,
                Tone::Accent,
                &format!("A newer copy of “{}” is in iCloud", entry.name),
                Some(&format!("{words} Lock and unlock to load it.")),
                |ui| {
                    lock = kit::small_button(ui, "Lock now", Style::Bordered).clicked();
                },
            );
            if lock {
                let ctx = ui.ctx().clone();
                app.lock_vault(Some(&ctx));
            }
        }
        SyncStatus::Conflict => {
            let mut choose = false;
            kit::notice(
                ui,
                Tone::Warning,
                &format!("This Mac and iCloud both changed “{}”", entry.name),
                Some(
                    "Apassy does not merge. Choose which version to keep; Apassy saves the other one as a file.",
                ),
                |ui| {
                    choose = kit::small_button(ui, "Choose version…", Style::Prominent).clicked();
                },
            );
            if choose {
                app.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(IcloudSheet::Conflict {
                    id: entry.id.clone(),
                })));
            }
        }
        _ => {}
    }
}

/// Settings > Vaults: iCloud Drive, with each vault, its status, and its actions.
pub(super) fn settings_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.icloud_offered() {
        return;
    }
    let ready = app.icloud_ready();
    let current = app.vault_list.current.clone();
    let unlocked = app.owner_ui.session.has_file() && !app.owner_ui.session.is_locked();
    let missing: Vec<String> = app
        .vault_list
        .registry
        .entries()
        .iter()
        .filter(|entry| {
            entry.cloud_state().is_some() && !app.icloud.statuses.contains_key(&entry.id)
        })
        .map(|entry| entry.id.clone())
        .collect();
    if !missing.is_empty() {
        app.icloud_refresh();
    }
    draw_notice(app, ui);
    let mut sheet = None;
    let mut sync_now = false;
    let mut adopt = false;
    kit::section(
        ui,
        Some("iCloud Drive"),
        Some(
            "Apassy keeps an encrypted copy of a vault in iCloud Drive and syncs it with your other Macs. The file on each Mac stays the working vault. Apassy uploads changes when you lock the vault and every few minutes, and loads a newer copy when you unlock. Turning sync off keeps the copy in iCloud Drive.",
        ),
        |s| {
            if !ready {
                s.row(|ui| {
                    kit::tone_note(
                        ui,
                        "iCloud Drive is off on this Mac. Turn it on in System Settings > Apple Account > iCloud > iCloud Drive.",
                        Tone::Warning,
                    );
                });
            }
            for entry in app.vault_list.registry.entries() {
                let is_open = Some(&entry.id) == current.as_ref();
                let open_unlocked = is_open && unlocked;
                let status = app.icloud.statuses.get(&entry.id);
                let synced = entry.cloud_state().is_some();
                let cloud_file = synced.then(|| cloud_file_of(app, entry)).flatten();
                s.row(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(kit::medium(&entry.name, Font::Body).color(kit::LABEL));
                        match (synced, status) {
                            (true, Some(status)) => {
                                let (tag, tone) = status_tag(status);
                                kit::tag(ui, tag, tone);
                            }
                            (true, None) => {
                                kit::tag(ui, "On", Tone::Neutral);
                            }
                            (false, _) => {
                                kit::tag(ui, "Off", Tone::Neutral);
                            }
                        }
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if synced {
                                if kit::small_button(ui, "Turn off…", Style::Link).clicked() {
                                    sheet = Some(IcloudSheet::TurnOff {
                                        id: entry.id.clone(),
                                    });
                                }
                                let conflict = matches!(
                                    status,
                                    Some(Ok(report)) if report.status == SyncStatus::Conflict
                                );
                                if open_unlocked && conflict {
                                    if kit::small_button(ui, "Choose version…", Style::Prominent)
                                        .clicked()
                                    {
                                        sheet = Some(IcloudSheet::Conflict {
                                            id: entry.id.clone(),
                                        });
                                    }
                                } else if open_unlocked
                                    && kit::small_button(ui, "Sync now", Style::Bordered).clicked()
                                {
                                    sync_now = true;
                                }
                            } else if open_unlocked
                                && ready
                                && kit::small_button(ui, "Turn on iCloud sync…", Style::Bordered)
                                    .clicked()
                            {
                                sheet = Some(IcloudSheet::TurnOn {
                                    id: entry.id.clone(),
                                });
                            }
                        });
                    });
                    let line = match (synced, status) {
                        (true, Some(status)) => {
                            let (words, _) = status_words(status);
                            match &cloud_file {
                                Some(file) => format!("{words} iCloud file: {file}."),
                                None => words,
                            }
                        }
                        (true, None) => "iCloud sync is on.".to_owned(),
                        (false, _) if open_unlocked => "iCloud sync is off.".to_owned(),
                        (false, _) => "iCloud sync is off. Open and unlock this vault to turn it on.".to_owned(),
                    };
                    ui.add(Label::new(kit::text(line, Font::Footnote).color(kit::SECONDARY)).wrap());
                    if let Some(Ok(report)) = status
                        && !report.duplicates.is_empty()
                    {
                        kit::tone_note(
                            ui,
                            format!(
                                "iCloud also made {} next to it. Apassy does not use a duplicate. Open it from iCloud as a separate vault to see what it has, or delete it in Finder.",
                                report.duplicates.join(", ")
                            ),
                            Tone::Warning,
                        );
                    }
                });
            }
            if ready
                && s.clickable_row(|ui| {
                    ui.label(
                        kit::text("Open a vault from iCloud…", Font::Body).color(kit::ACCENT_TEXT),
                    );
                })
                .clicked()
            {
                adopt = true;
            }
        },
    );
    if sync_now {
        app.icloud_sync_now();
    } else if adopt {
        let ctx = ui.ctx().clone();
        app.leave_vault_for(Step::Icloud, Some(&ctx));
    } else if let Some(sheet) = sheet {
        app.icloud_forget_secrets(Some(ui.ctx()));
        app.ui.sheet = Some(Sheet::Vault(VaultSheet::Icloud(sheet)));
    }
}

/// An iCloud sheet. Returns true when the owner pressed Escape. The passphrase field is
/// erased when the sheet closes.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, sheet: &IcloudSheet) -> bool {
    let (IcloudSheet::TurnOn { id } | IcloudSheet::TurnOff { id } | IcloudSheet::Conflict { id }) =
        sheet;
    let Some(entry) = app.vault_list.registry.get(id).cloned() else {
        close_sheet(app, ctx);
        return false;
    };
    let escape = match sheet {
        IcloudSheet::TurnOn { .. } => turn_on_sheet(app, ctx, &entry),
        IcloudSheet::TurnOff { .. } => turn_off_sheet(app, ctx, &entry),
        IcloudSheet::Conflict { .. } => conflict_sheet(app, ctx, &entry),
    };
    if escape {
        app.icloud_forget_secrets(Some(ctx));
    }
    escape
}

fn passphrase_field(app: &mut DesktopApp, s: &mut kit::Section<'_>) -> bool {
    let field = s.field("Passphrase", |ui| {
        secure_input(
            ui,
            ICLOUD_PASSPHRASE_FIELD,
            &mut app.icloud.passphrase,
            PASSPHRASE_CAPACITY,
            "Required",
        )
    });
    field.lost_focus() && field.ctx.input(|input| input.key_pressed(egui::Key::Enter))
}

fn cancel_sheet(app: &mut DesktopApp, ctx: &egui::Context) {
    app.icloud_forget_secrets(Some(ctx));
    close_sheet(app, ctx);
}

fn turn_on_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut turn_on = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "icloud-turn-on", 480.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Sync “{}” with iCloud", entry.name),
            Some(
                "Apassy puts an encrypted copy of this vault in iCloud Drive, in the Apassy folder. Your other Macs open it with “Open a vault from iCloud…”. The copy has the passphrase of the vault. Anyone with the passphrase and your iCloud account can open it.",
            ),
        );
        kit::section(ui, None, Some("The passphrase of this vault."), |s| {
            turn_on |= passphrase_field(app, s);
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                turn_on |= kit::button(ui, "Turn on", Style::Prominent).clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if turn_on {
        let passphrase = Ephemeral::take(&mut app.icloud.passphrase);
        forget_secret_field(ctx, ICLOUD_PASSPHRASE_FIELD);
        match app.icloud_enable(&entry.id, passphrase.expose()) {
            Ok(report) => {
                app.ui.sheet = None;
                app.enable_message(&entry.id, &report);
            }
            Err(message) => app.set_err(message),
        }
    }
    if cancel {
        cancel_sheet(app, ctx);
    }
    response.escape
}

fn turn_off_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut turn_off = false;
    let mut cancel = false;
    let file = cloud_file_of(app, entry).unwrap_or_else(|| "the copy".to_owned());
    let response = kit::sheet(ctx, "icloud-turn-off", 460.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Stop syncing “{}”?", entry.name),
            Some(&format!(
                "Apassy stops uploading and loading this vault. The vault on this Mac stays. The copy in iCloud Drive ({file}) stays too, and your other Macs keep it. Delete it in Finder if you do not want it there."
            )),
        );
        kit::sheet_buttons(
            ui,
            |ui| {
                turn_off = kit::button(ui, "Turn off", Style::Destructive).clicked();
            },
            |ui| {
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if turn_off {
        let file = app.icloud_disable(&entry.id);
        app.ui.sheet = None;
        app.set_ok(format!(
            "iCloud sync of “{}” is off. The copy in iCloud Drive ({}) stays.",
            entry.name,
            file.unwrap_or_else(|| "the copy".to_owned())
        ));
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

fn conflict_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let mut choice = None;
    let mut cancel = false;
    let conflicts = app.vault_list.data_dir.join("conflicts");
    let response = kit::sheet(ctx, "icloud-conflict", 520.0, |ui| {
        kit::sheet_title(
            ui,
            "Choose which version to keep",
            Some(&format!(
                "This Mac and iCloud both changed “{}” since the last sync. Apassy does not merge. It keeps the version you choose, and saves the other version as a vault file in {}. You can open that file later.",
                entry.name,
                conflicts.display()
            )),
        );
        kit::section(
            ui,
            None,
            Some(
                "The passphrase of the vault. For the iCloud version, the passphrase of that copy.",
            ),
            |s| {
                passphrase_field(app, s);
            },
        );
        kit::sheet_buttons(
            ui,
            |ui| {
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
            |ui| {
                if kit::button(ui, "Keep this Mac's version", Style::Prominent).clicked() {
                    choice = Some(Choice::KeepThisMac);
                }
                if kit::button(ui, "Use the iCloud version", Style::Bordered).clicked() {
                    choice = Some(Choice::UseIcloud);
                }
            },
        );
    });
    if let Some(choice) = choice {
        let passphrase = Ephemeral::take(&mut app.icloud.passphrase);
        forget_secret_field(ctx, ICLOUD_PASSPHRASE_FIELD);
        if passphrase.expose().is_empty() {
            app.set_err("Type the passphrase first.");
        } else if app.icloud_resolve(choice, passphrase.expose(), Some(ctx)) {
            app.ui.sheet = None;
        }
    }
    if cancel {
        cancel_sheet(app, ctx);
    }
    response.escape
}

/// The unlock screen: the iCloud note, a download, a newer copy, or the conflict
/// choice. The choice uses the typed passphrase; "Unlock" still opens the file of this
/// Mac.
pub(super) fn unlock_notices(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.icloud_offered() {
        return;
    }
    draw_notice(app, ui);
    let Some(entry) = app.current_vault().cloned() else {
        return;
    };
    if entry.cloud_state().is_none() {
        return;
    }
    let status = match app.icloud.statuses.get(&entry.id) {
        Some(status) => status.clone(),
        None => {
            app.icloud_refresh();
            match app.icloud.statuses.get(&entry.id) {
                Some(status) => status.clone(),
                None => return,
            }
        }
    };
    let Ok(report) = &status else {
        return;
    };
    match report.status {
        SyncStatus::NotDownloaded => {
            kit::tone_note(
                ui,
                "Downloading from iCloud… You can unlock the file on this Mac now. Apassy checks the iCloud copy again when the download ends.",
                Tone::Accent,
            );
            ui.add_space(10.0);
        }
        SyncStatus::PullAvailable => {
            let (words, _) = status_words(&status);
            kit::tone_note(
                ui,
                format!("{words} Apassy loads it when you unlock."),
                Tone::Accent,
            );
            ui.add_space(10.0);
        }
        SyncStatus::Unavailable => {
            kit::note(
                ui,
                "iCloud Drive is off. You can unlock the file on this Mac. Apassy syncs when iCloud Drive is back.",
            );
            ui.add_space(10.0);
        }
        SyncStatus::Conflict => {
            let mut choice = None;
            kit::notice(
                ui,
                Tone::Warning,
                &format!("This Mac and iCloud both changed “{}”", entry.name),
                Some(
                    "Type the passphrase, then choose which version to keep. Apassy saves the other version as a file. “Unlock” opens the version of this Mac and keeps the choice for later.",
                ),
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        if kit::small_button(ui, "Keep this Mac's version", Style::Bordered)
                            .clicked()
                        {
                            choice = Some(Choice::KeepThisMac);
                        }
                        if kit::small_button(ui, "Use the iCloud version", Style::Bordered)
                            .clicked()
                        {
                            choice = Some(Choice::UseIcloud);
                        }
                    });
                },
            );
            if let Some(choice) = choice {
                let ctx = ui.ctx().clone();
                let passphrase = Ephemeral::take(&mut app.owner_ui.passphrase);
                forget_secret_field(&ctx, VAULT_PASSPHRASE_FIELD);
                if passphrase.expose().is_empty() {
                    app.set_err("Type the passphrase first.");
                } else {
                    app.icloud_resolve(choice, passphrase.expose(), Some(&ctx));
                }
            }
        }
        _ => {}
    }
}

/// "Open a vault from iCloud…" on the welcome and the unlock screens.
pub(super) fn start_link(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.icloud_offered() {
        return;
    }
    ui.vertical_centered(|ui| {
        if kit::small_button(ui, "Open a vault from iCloud…", Style::Link).clicked() {
            app.vault_list.name_input.clear();
            app.icloud.adopt_pick = None;
            app.ui.start = Step::Icloud;
        }
    });
}

/// "Keep a copy in iCloud Drive" on the Create screen.
pub(super) fn create_option(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.icloud_offered() {
        return;
    }
    let ready = app.icloud_ready();
    let subtitle = if ready {
        "An encrypted copy syncs with your other Macs. Open it there with “Open a vault from iCloud…”."
    } else {
        "iCloud Drive is off on this Mac."
    };
    kit::section(ui, None, None, |s| {
        let mut on = app.icloud.on_create && ready;
        if s.toggle("Keep a copy in iCloud Drive", Some(subtitle), &mut on)
            .changed()
        {
            app.icloud.on_create = on && ready;
        }
    });
}

/// After a create with the option on: turn on sync with the passphrase just typed.
/// Returns a line for the result message, or the error text.
pub(super) fn after_create(
    app: &mut DesktopApp,
    passphrase: &str,
) -> Result<Option<String>, String> {
    let wanted = std::mem::take(&mut app.icloud.on_create);
    if !wanted || !app.icloud_offered() {
        return Ok(None);
    }
    let Some(id) = app.current_vault().map(|entry| entry.id.clone()) else {
        return Ok(None);
    };
    match app.icloud_enable(&id, passphrase) {
        Ok(report) => Ok(Some(format!(
            " A copy is in iCloud Drive as {}.",
            report.cloud_file_name
        ))),
        Err(message) => Err(format!(
            "The vault is ready, but iCloud sync is off: {message} Turn it on later in Settings > Vaults."
        )),
    }
}

/// The screen "Open a vault from iCloud": the cloud vaults that are not in the list.
pub(super) fn adopt_screen(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if kit::back_link(ui, "Back") {
        app.icloud.adopt_pick = None;
        app.ui.start = Step::Home;
    }
    ui.add_space(8.0);
    ui.label(kit::text("Open a vault from iCloud", Font::Title).color(kit::LABEL));
    kit::paragraph(
        ui,
        "These vaults are in iCloud Drive and not in your list. Apassy copies the one you choose to this Mac, checks it with its passphrase, and keeps it in sync. Its agents and rules come with it.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    if !app.icloud_ready() {
        kit::tone_note(
            ui,
            "iCloud Drive is off on this Mac. Turn it on in System Settings > Apple Account > iCloud > iCloud Drive.",
            Tone::Warning,
        );
        return;
    }
    let found = match app.icloud_unlisted() {
        Ok(found) => found,
        Err(err) => {
            kit::tone_note(
                ui,
                format!("Apassy cannot read iCloud Drive: {err}."),
                Tone::Warning,
            );
            return;
        }
    };
    if found.is_empty() {
        kit::note(
            ui,
            "No other vault is in iCloud Drive. On the other Mac, turn on iCloud sync in Settings > Vaults, then wait for iCloud.",
        );
        return;
    }
    let mut pick = None;
    let mut download = None;
    kit::section(ui, Some("In iCloud Drive"), None, |s| {
        for entry in &found {
            let chosen = app.icloud.adopt_pick.as_deref() == Some(entry.name.as_str());
            let subtitle = match (&entry.duplicate_of, entry.downloaded) {
                (_, false) => "In iCloud, not on this Mac yet".to_owned(),
                (Some(base), true) => format!("An iCloud duplicate of {base}"),
                (None, true) => entry.name.clone(),
            };
            let detail =
                chosen.then(|| kit::text("Chosen", Font::Footnote).color(kit::ACCENT_TEXT));
            let gray = egui::Color32::from_rgb(99, 99, 104);
            if s.nav(
                Some((kit::Icon::Lock, gray)),
                cloud_stem(&entry.name),
                Some(&subtitle),
                detail,
            )
            .clicked()
            {
                if entry.downloaded {
                    pick = Some(entry.name.clone());
                } else {
                    download = Some(entry.path.clone());
                }
            }
        }
    });
    if let Some(path) = download {
        start_download(&path);
        app.set_note("Apassy asked iCloud for the file. Choose it again when the download ends.");
    }
    if let Some(name) = pick {
        app.vault_list.name_input = app.vault_list.registry.free_name(cloud_stem(&name));
        app.icloud.adopt_pick = Some(name);
    }
    let Some(cloud_name) = app.icloud.adopt_pick.clone() else {
        return;
    };
    let mut submit = false;
    kit::section(
        ui,
        None,
        Some(
            "The new vault file goes to the Apassy data folder, which the sandbox profile closes to agents.",
        ),
        |s| {
            super::vaults::name_field(app, s, "vault-icloud-name", cloud_stem(&cloud_name));
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
    if kit::wide_button(ui, "Open from iCloud", Style::Prominent).clicked() || submit {
        let ctx = ui.ctx().clone();
        app.icloud_adopt(&cloud_name, Some(&ctx));
    }
}
