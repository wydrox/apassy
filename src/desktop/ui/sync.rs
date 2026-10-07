//! Sync of the vaults through a folder (ADR 0014) or through the Apassy relay (ADR 0022)
//! in the app (docs/operations/sync.md): the Sync setting of each vault, the status in
//! plain words, "Sync now", the prompt for a passphrase that changed on another Mac, and
//! "Use a vault from another Mac". The relay sheets ("Apassy relay", "Add a Mac…",
//! "Devices…") and the relay source of "Use a vault from another Mac" are in [`relay`].
//!
//! The engine is [`crate::sync`]. The vault list keeps the setting of each vault
//! ([`crate::vaults::VaultEntry::sync`]): the synced folder and the file name, or the
//! relay, and the name of its sync state file in `<data dir>/sync/` (the list ID of the
//! vault).
//!
//! When it runs: right after each unlock, before the owner sees the list; while the vault
//! is unlocked, every 30 seconds for the synced file and 5 to 8 seconds after a change of
//! a credential, on the thread of [`crate::desktop::sync_worker`], also while the window
//! is hidden; and in the step before each lock of the session
//! ([`crate::desktop::owner_store::BeforeLock`]), so a lock, a switch, a backup, a quit,
//! and a restart for an update sync too. Never while an agent run waits for the owner. A
//! failure never stops a lock; the app shows it once as a note. Each frame only shows
//! what the worker did: see [`DesktopApp::poll_sync`].
//!
//! A vault on the relay syncs on the worker after an unlock, so an unlock never waits for
//! the network. The step before a lock pushes it only when a change waits, no other sync
//! of it runs, and the last relay sync did not fail; its relay calls end within
//! [`BEFORE_LOCK_LIMIT`]. Each relay call that the owner starts runs on its own thread
//! (see [`relay`]).

pub(super) mod relay;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Label};
use zeroize::{Zeroize, Zeroizing};

use super::files::{self, DialogKind};
use super::kit::{self, Font, Style, Tone};
use super::start::Step;
use super::vaults::VaultSheet;
use super::{
    PASSPHRASE_CAPACITY, Sheet, VAULT_PASSPHRASE_FIELD, close_sheet, forget_secret_field,
    secure_input,
};
use crate::desktop::owner_store::Ephemeral;
pub(crate) use crate::desktop::sync_worker::UiStatus;
use crate::desktop::sync_worker::{BEFORE_LOCK_LIMIT, DOWNLOAD_EVERY, SyncEvent, SyncWorker};
use crate::desktop::{DesktopApp, OwnerView};
use crate::sync::{
    FileStatus, FolderEntry, FolderSync, SYNC_FILE_EXTENSION, SyncConfig, SyncError, SyncFolder,
    SyncOutcome, TransportKind, VaultSync, list_folder_vaults, read_state,
};
use crate::vault::{ConflictCopy, Vault, VaultErrorKind, format_utc};
use crate::vaults::{self, Registry, RelayLink, SyncLink, VaultEntry};
pub(crate) use relay::{Job, OpenSource, RelayUi};

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
    /// The schedule of the sync of the open vault, on its own thread.
    pub(crate) worker: SyncWorker,
    /// The status of each synced vault of the list, by list ID: a copy of the statuses
    /// of the worker for drawing. Change them through the worker.
    pub(crate) statuses: BTreeMap<String, UiStatus>,
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
    /// Sync through the Apassy relay: the sheets, "Add a Mac…", and a Mac that joins.
    pub(crate) relay: RelayUi,
}

/// What the step before a lock shares with the window.
#[derive(Default)]
struct HookShared {
    /// The sync of the open vault. `None` when sync is off.
    sync: Option<VaultSync>,
    /// A failed sync, for a note.
    failure: Option<String>,
    /// What the sync did.
    outcome: Option<SyncOutcome>,
}

/// The words of a status ([`UiStatus`] lives with the worker).
impl UiStatus {
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

/// A sync sheet in Settings > General > Sync.
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
    /// "Use the relay copy…": this Mac refuses the relay copy (an older copy, or a
    /// history without its last change); it takes the copy as it is now and merges it.
    UseRelayCopy { id: String },
    /// "Apassy relay": the relay address, the team code, and the name of this Mac; or a
    /// link from another Mac for a vault that is on the relay already.
    RelaySetup { id: String },
    /// "Add a Mac…": the link for the other Mac, and its safety words to confirm.
    AddMac { id: String },
    /// "Devices…": the Macs of the relay team.
    Devices { id: String },
}

impl SyncSheet {
    /// The list ID of the vault of the sheet.
    pub(crate) fn id(&self) -> &str {
        let (Self::ChooseFolder { id }
        | Self::NewPassphrase { id }
        | Self::TurnOff { id }
        | Self::ReplaceDamaged { id }
        | Self::UseRelayCopy { id }
        | Self::RelaySetup { id }
        | Self::AddMac { id }
        | Self::Devices { id }) = self;
        id
    }
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

/// The status line of the open vault in the sidebar: where it lives, and the state of
/// its sync in a few words. A tone other than neutral means that the owner has something
/// to do, and the line names it.
pub(crate) fn sidebar_status(app: &DesktopApp) -> (String, Tone) {
    let Some(entry) = app.vault_list.current.as_ref().and_then(|id| {
        app.vault_list
            .registry
            .entries()
            .iter()
            .find(|entry| &entry.id == id)
    }) else {
        return ("On this Mac".to_owned(), Tone::Neutral);
    };
    let Some(link) = entry.sync.as_ref().filter(|_| entry.sync_state().is_some()) else {
        return ("On this Mac".to_owned(), Tone::Neutral);
    };
    let folder = if link.is_relay() {
        relay::LABEL.to_owned()
    } else {
        sidebar_folder_label(&app.sync.folders, &link.folder)
    };
    // The state first: a narrow sidebar cuts the end of the line.
    match app.sync.statuses.get(&entry.id) {
        Some(UiStatus::UpToDate(Some(at))) => {
            (format!("Synced {} · {folder}", ago(*at)), Tone::Neutral)
        }
        Some(UiStatus::UpToDate(None)) | None => (format!("Synced · {folder}"), Tone::Neutral),
        Some(UiStatus::Syncing) => (format!("Sync pending · {folder}"), Tone::Neutral),
        Some(UiStatus::Waiting) => (format!("Waiting for the file · {folder}"), Tone::Neutral),
        Some(status) => (status_tag(link, status).0.to_owned(), Tone::Warning),
    }
}

/// The short tag of a status and its tone, for a folder or the relay.
fn status_tag(link: &SyncLink, status: &UiStatus) -> (&'static str, Tone) {
    if link.is_relay() {
        relay::tag(status)
    } else {
        status.tag()
    }
}

/// A short folder name for the sidebar: the label of a detected folder, else the last
/// part of the path.
fn sidebar_folder_label(folders: &[SyncFolder], path: &Path) -> String {
    folders
        .iter()
        .find(|folder| folder.path == path)
        .map(|folder| folder.label.clone())
        .or_else(|| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| path.display().to_string())
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
        // A relay state names the relay, the team, and the device instead of a folder.
        let relay = (state.transport == TransportKind::Relay)
            .then(|| {
                Some(RelayLink::new(
                    state.relay_url.as_deref()?,
                    state.team_id.as_deref()?,
                    state.device_id?,
                ))
            })
            .flatten();
        let link = match (relay, state.folder) {
            (Some(relay), _) => Some(SyncLink::relay(state_name, relay)),
            (None, Some(folder)) if state.transport == TransportKind::Folder => {
                Some(SyncLink::new(state_name, &folder, &state.file_name))
            }
            _ => None,
        };
        match (target, link) {
            (Some((id, name)), Some(link)) => {
                if let Some(entry) = registry.entry_mut(&id) {
                    entry.sync = Some(link);
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
            "Apassy could not link the sync of a vault in another folder. Open that vault, then choose its synced folder again in Settings > General > Sync; Apassy then merges with the same file.",
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

    /// The sync of the listed vault `id`, through a folder or through the relay, when
    /// sync is on for it.
    pub(crate) fn vault_sync_of(&self, id: &str) -> Option<VaultSync> {
        let entry = self.vault_list.registry.get(id)?;
        if entry.sync_relay().is_some() {
            return self.relay_of(id).map(VaultSync::Relay);
        }
        self.sync_config(entry)
            .map(|config| VaultSync::Folder(FolderSync::new(config)))
    }

    /// The list ID and the sync of the open vault, when sync is on for it.
    fn sync_current(&self) -> Option<(String, VaultSync)> {
        let id = self.current_vault()?.id.clone();
        let sync = self.vault_sync_of(&id)?;
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

    /// The synced vaults of the list, for the worker. No file I/O.
    fn sync_synced_list(&self) -> Vec<(String, VaultSync)> {
        self.vault_list
            .registry
            .entries()
            .iter()
            .filter(|entry| entry.sync_state().is_some())
            .filter_map(|entry| {
                self.vault_sync_of(&entry.id)
                    .map(|sync| (entry.id.clone(), sync))
            })
            .collect()
    }

    /// Hand the synced vaults of the list to the worker. It keeps them when they did not
    /// change.
    fn sync_send_list(&self) {
        self.sync.worker.set_synced_all(self.sync_synced_list());
    }

    /// Start the sync worker, when the app offers sync. The window calls this once.
    pub(crate) fn start_sync_worker(&mut self, ctx: &egui::Context) {
        if self.sync.offered {
            // No relay call runs yet: the work files of a crash can go.
            crate::sync::clear_relay_work(&self.vault_list.data_dir);
            self.sync_send_list();
            self.sync.worker.start(ctx);
        }
    }

    /// Stop the sync worker. A sync that runs now finishes first.
    pub(crate) fn stop_sync_worker(&mut self) {
        self.sync.worker.stop();
    }

    /// Set the status of the vault `id`, in the worker and in the copy for drawing.
    fn sync_set_status(&mut self, id: &str, status: UiStatus) {
        self.sync.worker.set_status(id, status);
        self.sync.statuses = self.sync.worker.statuses();
    }

    /// The step before a lock and the worker sync the open vault from now on. Call it
    /// when the open vault or its setting changes. The engine refuses a vault at another
    /// path or with another vault ID, so a sync never reaches the file of another vault.
    pub(crate) fn sync_track_open_vault(&mut self) {
        if !self.sync.hook_installed {
            // The step runs with the vault mutex held, so it does not take the sync op
            // lock (see the lock order in `crate::desktop::sync_worker`).
            let shared = Arc::clone(&self.sync.hook);
            let backoff = self.sync.worker.relay_backoff_flag();
            self.owner_ui
                .session
                .set_before_lock(Some(Box::new(move |vault: &mut Vault| {
                    let mut shared = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    let Some(sync) = shared.sync.clone() else {
                        return;
                    };
                    let result = match &sync {
                        // The relay is pushed only when a change waits and the relay did
                        // not fail a moment ago, so a lock does not wait for a relay that
                        // is away. A relay sync that runs (the worker) is not waited for:
                        // the change goes up after the next unlock. A removed Mac does
                        // not ask the relay at all.
                        VaultSync::Relay(relay) => {
                            if backoff.load(Ordering::SeqCst)
                                || relay.is_removed()
                                || !relay.local_changed(vault).unwrap_or(false)
                            {
                                return;
                            }
                            match relay.sync_within(vault, BEFORE_LOCK_LIMIT) {
                                Err(SyncError::Running) => return,
                                other => other,
                            }
                        }
                        VaultSync::Folder(_) => sync.sync(vault),
                    };
                    match result {
                        Ok(outcome) => {
                            shared.failure = None;
                            shared.outcome = Some(outcome);
                        }
                        Err(err) => shared.failure = Some(lock_failure(err)),
                    }
                })));
            self.sync.hook_installed = true;
        }
        let current = self.sync_current();
        if let Some((_, VaultSync::Relay(relay))) = &current {
            // The end of a pause of "Turn off".
            relay.resume();
        }
        self.sync
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync = current.as_ref().map(|(_, sync)| sync.clone());
        self.sync_send_list();
        self.sync.worker.track_sync(
            current,
            self.owner_ui.session.shared_vault(),
            self.approvals(),
        );
    }

    /// No sync of the open vault before a lock, in the background, or by an owner call
    /// that waits for the guard of its relay sync ([`crate::sync::RelaySync::pause`]) until the next
    /// [`Self::sync_track_open_vault`]: its relay device leaves the team.
    fn sync_pause_open_vault(&mut self) {
        if let Some((_, VaultSync::Relay(relay))) = self.sync_current() {
            relay.pause();
        }
        self.sync
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync = None;
        self.sync
            .worker
            .track_sync(None, self.owner_ui.session.shared_vault(), self.approvals());
    }

    /// The open vault is gone: no sync before a lock or in the background, no typed
    /// passphrase, and no note about it.
    pub(crate) fn sync_forget_open_vault(&mut self, ctx: Option<&egui::Context>) {
        self.sync
            .hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync = None;
        self.sync
            .worker
            .track(None, self.owner_ui.session.shared_vault(), self.approvals());
        let _ = self.sync.worker.take_events();
        self.sync_forget_secrets(ctx);
        self.sync.notice = None;
        self.sync.relay.forget_open_vault();
    }

    /// Erase the passphrase field of the sync sheets and its undo history, and the codes
    /// of the relay sheets: the team code, a pasted link of a vault on this Mac, and the
    /// link of "Add a Mac…". The relay keys in memory go, except the one of the open,
    /// unlocked vault.
    pub(crate) fn sync_forget_secrets(&mut self, ctx: Option<&egui::Context>) {
        self.sync.passphrase.zeroize();
        if let Some(ctx) = ctx {
            forget_secret_field(ctx, SYNC_PASSPHRASE_FIELD);
            forget_secret_field(ctx, relay::TEAM_CODE_FIELD);
        }
        self.relay_forget_codes();
        // A lock drops the relay keys at once, also during a transfer of the worker.
        self.relay_forget_keys();
    }

    /// Read the file status of each synced vault of the list now. The open, unlocked
    /// vault also counts a change of a credential that waits to sync.
    pub(crate) fn sync_refresh(&mut self) {
        self.sync_send_list();
        self.sync.worker.refresh();
        self.sync.statuses = self.sync.worker.statuses();
    }

    /// Each frame: take what the step before a lock and the worker did, and copy the
    /// statuses for drawing. The worker syncs on its own thread; nothing here reads a
    /// synced file.
    pub(crate) fn poll_sync(&mut self, ctx: &egui::Context) {
        if !self.sync.offered {
            return;
        }
        self.relay_poll(Some(ctx));
        self.sync_take_hook_results();
        self.sync_send_list();
        for event in self.sync.worker.take_events() {
            self.sync_apply_event(event);
        }
        self.sync.statuses = self.sync.worker.statuses();
    }

    /// Show what a sync of the worker means for the owner. An event about a vault that
    /// is not open any more shows nothing.
    fn sync_apply_event(&mut self, event: SyncEvent) {
        let current = self.vault_list.current.clone();
        let (SyncEvent::Synced { id, .. }
        | SyncEvent::Failure { id, .. }
        | SyncEvent::NeedsPassphrase(id)
        | SyncEvent::Damaged(id)) = &event;
        if current.as_deref() != Some(id.as_str()) {
            return;
        }
        match event {
            SyncEvent::Synced { id, outcome } => {
                self.sync.shown_failure = None;
                if outcome.pushed {
                    // A new version: no other Mac has received it yet.
                    self.sync.relay.forget_receipt(&id);
                }
                self.sync_note_merge(&id, &outcome);
            }
            SyncEvent::Failure { text, .. } => self.sync_failure_once(text),
            SyncEvent::NeedsPassphrase(id) => self.sync_ask_passphrase(&id),
            SyncEvent::Damaged(id) => self.sync_note_damaged(&id),
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
            // The worker looks at the synced files again.
            self.sync.worker.reset();
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

    /// The note about a damaged synced copy of the open vault `id`.
    fn sync_note_damaged(&mut self, id: &str) {
        let vault = self.current_vault_name().unwrap_or_default();
        if self.is_relay(id) {
            self.sync.notice = Some(Notice {
                title: format!("The copy of “{vault}” on the relay fails a check"),
                text: "Apassy did not merge it, and the vault on this Mac did not change. Apassy does not download that copy again until it changes. If no other Mac can repair it, replace it with this Mac's vault. Also look at the Macs in Settings > General > Sync > Devices…, and remove a Mac that you do not know.".to_owned(),
                warning: true,
                vault: id.to_owned(),
            });
            return;
        }
        self.sync.notice = Some(Notice {
            title: format!("The synced copy of “{vault}” is damaged"),
            text: "The file in the synced folder fails a check, so Apassy did not merge it. The vault on this Mac did not change. If no other Mac can repair it, replace it with this Mac's vault in Settings > General > Sync.".to_owned(),
            warning: true,
            vault: id.to_owned(),
        });
    }

    /// Sync the open vault now, without a message unless something needs the owner.
    /// The window calls it for an unlock and "Sync now"; the worker has its own.
    pub(crate) fn sync_quietly(&mut self) -> Option<Result<SyncOutcome, SyncError>> {
        let (id, sync) = self.sync_current()?;
        if self.owner_ui.session.is_locked() {
            return None;
        }
        let op = self.sync.worker.op_lock();
        let result = {
            let _op = op.lock().unwrap_or_else(PoisonError::into_inner);
            self.owner_ui.session.with_vault(|vault| sync.sync(vault))
        }?;
        self.sync_take_result(&id, &sync, &result);
        Some(result)
    }

    /// Show the result of a sync of the vault `id` that the owner started: its status,
    /// a note from the merge, and what needs the owner.
    fn sync_take_result(
        &mut self,
        id: &str,
        sync: &VaultSync,
        result: &Result<SyncOutcome, SyncError>,
    ) {
        if result == &Err(SyncError::Vault(VaultErrorKind::Locked)) {
            // A lock, a pause, or a quit ended it: nothing to tell, as for the worker.
            return;
        }
        let id = id.to_owned();
        // No change waits now; the worker starts its schedule again.
        self.sync.worker.reset();
        match result {
            Ok(outcome) => {
                self.sync.shown_failure = None;
                if outcome.pushed {
                    self.sync.relay.forget_receipt(&id);
                }
                self.sync_note_merge(&id, outcome);
                let last = sync
                    .state()
                    .ok()
                    .flatten()
                    .and_then(|state| state.last_sync_at);
                self.sync_set_status(&id, UiStatus::UpToDate(last));
            }
            Err(err) => {
                let err = *err;
                self.sync_set_status(&id, UiStatus::from_error(err));
                match err {
                    SyncError::NeedsPassphrase => self.sync_ask_passphrase(&id),
                    SyncError::Damaged => self.sync_note_damaged(&id),
                    // The status says it; Apassy syncs when it is back.
                    SyncError::FolderUnavailable
                    | SyncError::NotDownloaded
                    | SyncError::RelayUnreachable
                    | SyncError::RelayBusy => {}
                    other => self.sync_failure_once(format!("Sync: {other}.")),
                }
            }
        }
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
        // The worker pulls a relay vault at its first step: the unlock does not wait for
        // the network.
        if self
            .vault_list
            .current
            .as_deref()
            .is_some_and(|id| self.is_relay(id))
        {
            return None;
        }
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

    /// "Sync now" in Settings > General > Sync.
    pub(crate) fn sync_now(&mut self) {
        let Some((id, sync)) = self.sync_current() else {
            return;
        };
        let sync = match sync {
            VaultSync::Folder(sync) => sync,
            VaultSync::Relay(_) => {
                self.relay_sync_now(&id);
                return;
            }
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
        if self.relay_changing(id) {
            return Err(
                "Relay sync of this vault is turning on or off. Try again when it is done."
                    .to_owned(),
            );
        }
        // One transport per vault: a folder or a relay sync goes first.
        if self.vault_sync_of(id).is_some() {
            self.sync_disable(id);
        }
        let sync = FolderSync::new(SyncConfig::in_data_dir(
            &self.vault_list.data_dir,
            &entry.path,
            folder,
            &entry.id,
        ));
        let op = self.sync.worker.op_lock();
        let report = {
            let _op = op.lock().unwrap_or_else(PoisonError::into_inner);
            // A state of an earlier try with the same name goes first.
            let _ = sync.disable();
            self.owner_ui
                .session
                .with_vault(|vault| sync.enable(vault, &entry.name))
        }
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
    /// Returns the folder and the file name, when sync was on (both empty for the
    /// relay). For the relay, the device key leaves the vault when it is open and
    /// unlocked; the copy on the relay stays.
    pub(crate) fn sync_disable(&mut self, id: &str) -> Option<(PathBuf, String)> {
        let link = self.vault_list.registry.get(id)?.sync.clone()?;
        if link.is_relay() {
            self.relay_disable(id);
        }
        if let Some(state) = link.state_name() {
            let op = self.sync.worker.op_lock();
            let _op = op.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = std::fs::remove_file(state_path(&self.vault_list.data_dir, state));
        }
        if let Some(entry) = self.vault_list.registry.entry_mut(id) {
            entry.sync = None;
        }
        self.save_vault_list();
        self.sync.worker.remove_status(id);
        self.sync.statuses = self.sync.worker.statuses();
        if self.vault_list.current.as_deref() == Some(id) {
            self.sync_track_open_vault();
        } else {
            self.sync_send_list();
        }
        Some((link.folder, link.file))
    }

    /// Before the vault `id` leaves the list: turn off its sync. Returns the text for
    /// the result message, when sync was on.
    pub(crate) fn sync_on_remove(&mut self, id: &str) -> Option<String> {
        let relay = self.is_relay(id);
        let (folder, file) = self.sync_disable(id)?;
        if relay {
            return Some(
                " The copy on the Apassy relay stays, and this Mac stays in its relay team: remove it in “Devices…” on another Mac."
                    .to_owned(),
            );
        }
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
        let op = self.sync.worker.op_lock();
        let result = {
            let _op = op.lock().unwrap_or_else(PoisonError::into_inner);
            self.owner_ui.session.with_vault(|vault| match &sync {
                VaultSync::Folder(sync) => sync.take_new_passphrase(vault, passphrase),
                // The vault uses the new passphrase once the outer step succeeded; a
                // failed sync after it tries again later.
                VaultSync::Relay(sync) => {
                    sync.take_new_passphrase(vault, passphrase).map(|synced| {
                        synced.unwrap_or(SyncOutcome {
                            file_name: String::new(),
                            merge: None,
                            pushed: false,
                        })
                    })
                }
            })
        }
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
        let VaultSync::Folder(sync) = sync else {
            return Err("The relay copy is not a file in a folder. Nothing changed.".to_owned());
        };
        let op = self.sync.worker.op_lock();
        let result = {
            let _op = op.lock().unwrap_or_else(PoisonError::into_inner);
            self.owner_ui
                .session
                .with_vault(|vault| sync.replace_synced_file(vault))
        }
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
        let op = self.sync.worker.op_lock();
        let adopted = {
            let _op = op.lock().unwrap_or_else(PoisonError::into_inner);
            sync.adopt(file_name, passphrase.expose())
        };
        match adopted {
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
        self.sync.worker.force_changed_since(since);
    }

    /// Whether a change of a credential waits to sync.
    pub(crate) fn sync_change_waits_for_test(&self) -> bool {
        self.sync.worker.change_waits()
    }

    /// One step of the sync worker at `now`, then a frame that takes what it did. No
    /// thread and no drawing.
    pub(crate) fn sync_tick_for_test(&mut self, now: Instant) {
        self.sync.worker.tick(now);
        self.poll_sync(&egui::Context::default());
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
    // A synced file or a relay copy that fails a check.
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
        let (title, text) = passphrase_words(app, &entry);
        kit::notice(ui, Tone::Warning, &title, Some(text), |ui| {
            type_it =
                kit::small_button(ui, passphrase_button(app, &entry), Style::Prominent).clicked();
        });
        if type_it {
            app.sync_forget_secrets(Some(ui.ctx()));
            app.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::NewPassphrase {
                id: entry.id,
            })));
        }
    }
}

/// The title and the text of the passphrase banner. A relay copy without an anchor can
/// be from before a passphrase change: its passphrase only opens it for the merge.
fn passphrase_words(app: &DesktopApp, entry: &VaultEntry) -> (String, &'static str) {
    if entry.sync_relay().is_some() && app.relay_keeps_passphrase(&entry.id) {
        (
            format!("The relay copy of “{}” uses another passphrase", entry.name),
            "It can be from before a passphrase change. Type the passphrase of that copy to go on syncing. This vault keeps its passphrase.",
        )
    } else {
        (
            format!("The passphrase of “{}” changed on another Mac", entry.name),
            "Type the new passphrase to go on syncing. Apassy then uses it on this Mac too.",
        )
    }
}

/// The button that opens the passphrase sheet.
fn passphrase_button(app: &DesktopApp, entry: &VaultEntry) -> &'static str {
    if entry.sync_relay().is_some() && app.relay_keeps_passphrase(&entry.id) {
        "Type the passphrase of the copy…"
    } else {
        "Type the new passphrase…"
    }
}

/// The choices of the Sync picker: off, each synced folder of this Mac, the Apassy relay,
/// and "Choose folder…".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Pick {
    Off,
    Folder(PathBuf),
    /// The Apassy relay (ADR 0022). Settings offers it; the Create screen does not.
    Relay,
    Choose,
}

/// Where a vault syncs now, for the picker.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Current<'a> {
    Off,
    Folder(&'a Path),
    Relay,
}

/// The choices of the picker in their order, with their labels: off, the detected
/// folders, the Apassy relay after them when `relay` is true, and "Choose folder…".
pub(super) fn picker_choices(folders: &[SyncFolder], relay: bool) -> Vec<(Pick, String)> {
    let mut choices = vec![(Pick::Off, "Off".to_owned())];
    choices.extend(
        folders
            .iter()
            .map(|folder| (Pick::Folder(folder.path.clone()), folder.label.clone())),
    );
    if relay {
        choices.push((Pick::Relay, relay::LABEL.to_owned()));
    }
    choices.push((Pick::Choose, "Choose folder…".to_owned()));
    choices
}

/// The Sync picker. Returns the choice, or `None` for no change.
fn sync_picker(
    ui: &mut egui::Ui,
    salt: &str,
    folders: &[SyncFolder],
    current: Current<'_>,
    relay: bool,
) -> Option<Pick> {
    let label = match current {
        Current::Off => "Off".to_owned(),
        Current::Folder(path) => folder_label(folders, path),
        Current::Relay => relay::LABEL.to_owned(),
    };
    let mut pick = None;
    kit::menu(
        salt,
        kit::text(&label, Font::Body),
        ui.available_width().min(220.0),
    )
    .truncate()
    .show_ui(ui, |ui| {
        for (choice, text) in picker_choices(folders, relay) {
            let selected = match (&choice, current) {
                (Pick::Off, Current::Off) | (Pick::Relay, Current::Relay) => true,
                (Pick::Folder(path), Current::Folder(now)) => path == now,
                _ => false,
            };
            // "Off" again turns nothing off; a choice that is on now does nothing.
            let repeat = selected && choice != Pick::Off;
            if ui.selectable_label(selected, text).clicked() && !repeat {
                pick = Some(choice);
            }
        }
    })
    .response
    .on_hover_text(label);
    pick
}

/// Settings > General > Sync: each vault, its folder or the relay, its status, and its
/// actions.
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
    if unlocked && let Some(id) = current.as_deref().filter(|id| app.is_relay(id)) {
        // "Received by …" needs the receipts of the other Macs.
        app.relay_receipts_due(id, ui.ctx());
    }
    let mut action: Option<(String, Pick)> = None;
    let mut sheet = None;
    let mut sync_now = false;
    let mut open_synced = false;
    kit::section(
        ui,
        Some("Sync"),
        Some(
            "Apassy keeps an encrypted copy of a vault in a folder that iCloud Drive, Dropbox, Google Drive, OneDrive, Syncthing, or a network share keeps in step, or on the Apassy relay. Changes from each Mac merge by credential. Agents, grants, rules, and activity stay on each Mac: register the agents of each Mac there. Turning sync off keeps the synced copy.",
        ),
        |s| {
            for entry in app.vault_list.registry.entries() {
                let open_unlocked = unlocked && Some(&entry.id) == current.as_ref();
                let status = app.sync.statuses.get(&entry.id);
                let link = entry.sync.as_ref().filter(|_| entry.sync_state().is_some());
                let on_relay = link.is_some_and(SyncLink::is_relay);
                let syncing = on_relay && app.relay_busy(&entry.id, Job::SyncNow);
                // No other choice while relay sync turns on or off.
                let changing = app.relay_changing(&entry.id);
                let refused = on_relay && status.is_some_and(relay::refused_copy);
                // Removed from the relay: the line says to turn relay sync off.
                let removed = on_relay && app.relay_removed(&entry.id);
                s.row(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            Label::new(kit::medium(&entry.name, Font::Body).color(kit::LABEL))
                                .wrap(),
                        );
                        if let (Some(status), Some(link)) = (status, link) {
                            let (tag, tone) = status_tag(link, status);
                            kit::tag(ui, tag, tone);
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        if open_unlocked {
                            let now = match link {
                                None => Current::Off,
                                Some(link) if link.is_relay() => Current::Relay,
                                Some(link) => Current::Folder(link.folder.as_path()),
                            };
                            let picked = ui
                                .add_enabled_ui(!changing, |ui| {
                                    sync_picker(
                                        ui,
                                        &format!("sync-picker-{}", entry.id),
                                        &app.sync.folders,
                                        now,
                                        true,
                                    )
                                })
                                .inner;
                            if let Some(pick) = picked {
                                action = Some((entry.id.clone(), pick));
                            }
                            if link.is_some()
                                && !removed
                                && ui
                                    .add_enabled_ui(!syncing, |ui| {
                                        kit::small_button(ui, "Sync now", Style::Bordered)
                                    })
                                    .inner
                                    .clicked()
                            {
                                sync_now = true;
                            }
                            if on_relay && !removed {
                                if kit::small_button(ui, "Add a Mac…", Style::Bordered).clicked()
                                {
                                    sheet = Some(SyncSheet::AddMac {
                                        id: entry.id.clone(),
                                    });
                                }
                                if kit::small_button(ui, "Devices…", Style::Bordered).clicked() {
                                    sheet = Some(SyncSheet::Devices {
                                        id: entry.id.clone(),
                                    });
                                }
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
                        _ if syncing => Job::SyncNow.progress().to_owned(),
                        (Some(_), Some(UiStatus::NeedsPassphrase))
                            if on_relay && app.relay_keeps_passphrase(&entry.id) =>
                        {
                            relay::OLDER_COPY_WORDS.to_owned()
                        }
                        (Some(_), Some(status)) if on_relay => {
                            relay::words(status, app.sync.relay.receipt(&entry.id))
                        }
                        (Some(_), None) if on_relay => "Syncs through the Apassy relay.".to_owned(),
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
                        && kit::small_button(ui, passphrase_button(app, entry), Style::Prominent)
                            .clicked()
                    {
                        sheet = Some(SyncSheet::NewPassphrase {
                            id: entry.id.clone(),
                        });
                    }
                    if refused
                        && open_unlocked
                        && kit::small_button(ui, "Use the relay copy…", Style::Prominent).clicked()
                    {
                        sheet = Some(SyncSheet::UseRelayCopy {
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
        let on = app
            .vault_list
            .registry
            .get(&id)
            .is_some_and(|entry| entry.sync_state().is_some());
        match pick {
            Pick::Off if on => {
                sheet = Some(SyncSheet::TurnOff { id });
            }
            Pick::Off => {}
            Pick::Choose => {
                app.sync.folder_input.clear();
                sheet = Some(SyncSheet::ChooseFolder { id });
            }
            Pick::Relay => {
                sheet = Some(SyncSheet::RelaySetup { id });
            }
            // A vault on the relay leaves its relay team first, in the "Turn off" sheet.
            Pick::Folder(folder) if app.is_relay(&id) => {
                app.relay_switch_to_folder(&id, folder, Some(&ctx));
            }
            Pick::Folder(folder) => match app.sync_enable(&id, &folder) {
                Ok(text) => app.set_ok(text),
                Err(text) => app.set_err(text),
            },
        }
    }
    if let Some(sheet) = sheet {
        app.sync_open_sheet(sheet, Some(&ctx));
    }
}

impl DesktopApp {
    /// Open a sync sheet. Typed secrets of the last sync sheet go first; a relay sheet
    /// gets its fields and its first data.
    pub(crate) fn sync_open_sheet(&mut self, sheet: SyncSheet, ctx: Option<&egui::Context>) {
        self.sync_forget_secrets(ctx);
        self.relay_prepare_sheet(&sheet);
        self.ui.sheet = Some(Sheet::Vault(VaultSheet::Sync(sheet)));
    }
}

/// A sync sheet. Returns true when the owner pressed Escape. The passphrase field is
/// erased when the sheet closes.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, sheet: &SyncSheet) -> bool {
    let (SyncSheet::ChooseFolder { id }
    | SyncSheet::NewPassphrase { id }
    | SyncSheet::TurnOff { id }
    | SyncSheet::ReplaceDamaged { id }
    | SyncSheet::UseRelayCopy { id }
    | SyncSheet::RelaySetup { id }
    | SyncSheet::AddMac { id }
    | SyncSheet::Devices { id }) = sheet;
    let Some(entry) = app.vault_list.registry.get(id).cloned() else {
        close_sheet(app, ctx);
        return false;
    };
    let escape = match sheet {
        SyncSheet::ChooseFolder { .. } => choose_folder_sheet(app, ctx, &entry),
        SyncSheet::NewPassphrase { .. } => new_passphrase_sheet(app, ctx, &entry),
        SyncSheet::TurnOff { .. } if entry.sync_relay().is_some() => {
            relay::turn_off_sheet(app, ctx, &entry)
        }
        SyncSheet::TurnOff { .. } => turn_off_sheet(app, ctx, &entry),
        SyncSheet::ReplaceDamaged { .. } => replace_sheet(app, ctx, &entry),
        SyncSheet::UseRelayCopy { .. } => relay::use_copy_sheet(app, ctx, &entry),
        SyncSheet::RelaySetup { .. } => relay::setup_sheet(app, ctx, &entry),
        SyncSheet::AddMac { .. } => relay::add_mac_sheet(app, ctx, &entry),
        SyncSheet::Devices { .. } => relay::devices_sheet(app, ctx, &entry),
    };
    if escape {
        app.relay_sheet_closed();
        app.sync_forget_secrets(Some(ctx));
    }
    escape
}

fn cancel_sheet(app: &mut DesktopApp, ctx: &egui::Context) {
    app.relay_sheet_closed();
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
    if save && entry.sync_relay().is_some() {
        let folder = PathBuf::from(app.sync.folder_input.trim());
        app.sync.folder_input.clear();
        app.relay_switch_to_folder(&entry.id, folder, Some(ctx));
    } else if save {
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
    let relay = entry.sync_relay().is_some();
    let busy = relay && app.relay_busy(&entry.id, Job::Passphrase);
    // A relay copy without an anchor: its passphrase only opens it for the merge.
    let older = relay && app.relay_keeps_passphrase(&entry.id);
    let mut take = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-new-passphrase", 480.0, |ui| {
        if older {
            kit::sheet_title(
                ui,
                &format!("The relay copy of “{}” uses another passphrase", entry.name),
                Some(
                    "The copy on the relay can be from before a passphrase change. Type the passphrase that it was made with. Apassy uses it only to open the copy, merges the copy into the vault on this Mac, and uploads the result under the passphrase of this Mac. This vault keeps its passphrase.",
                ),
            );
        } else {
            kit::sheet_title(
                ui,
                &format!("The passphrase of “{}” changed on another Mac", entry.name),
                Some(
                    "Type the new passphrase. Apassy checks it with the synced copy, then uses it for the vault on this Mac too, and syncs. Touch ID unlock on this Mac then needs to be turned on again.",
                ),
            );
        }
        kit::section(ui, None, None, |s| {
            let label = if older {
                "Passphrase of the copy"
            } else {
                "New passphrase"
            };
            let field = s.field(label, |ui| {
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
        if busy {
            kit::tone_note(ui, Job::Passphrase.progress(), Tone::Accent);
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                take |= ui
                    .add_enabled_ui(!busy, |ui| {
                        kit::button(ui, "Use this passphrase", Style::Prominent)
                    })
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Later", Style::Bordered).clicked();
            },
        );
    });
    if take && busy {
        // A check with the relay copy runs already.
    } else if take && relay {
        let passphrase = Ephemeral::take(&mut app.sync.passphrase);
        forget_secret_field(ctx, SYNC_PASSPHRASE_FIELD);
        // The answer of the relay closes the sheet.
        app.relay_take_passphrase(&entry.id, Zeroizing::new(passphrase.expose().to_owned()));
    } else if take {
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
    let relay = entry.sync_relay().is_some();
    let busy = relay && app.relay_busy(&entry.id, Job::Replace);
    let mut replace = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-replace", 480.0, |ui| {
        if relay {
            kit::sheet_title(
                ui,
                "Replace the damaged copy on the relay?",
                Some(&format!(
                    "The copy of “{}” on the relay fails a check, so no Mac can merge it. Apassy can upload the vault of this Mac as a new version over it. Changes that only the damaged copy had are lost; a change that another Mac still has comes back when that Mac syncs.",
                    entry.name
                )),
            );
            if busy {
                kit::tone_note(ui, Job::Replace.progress(), Tone::Accent);
            }
        } else {
            kit::sheet_title(
                ui,
                "Replace the damaged synced copy?",
                Some(&format!(
                    "The synced copy of “{}” fails a check, so no Mac can merge it. Apassy can write the vault of this Mac in its place. Changes that only the damaged copy had are lost; a change that another Mac still has comes back when that Mac syncs.",
                    entry.name
                )),
            );
        }
        kit::sheet_buttons(
            ui,
            |ui| {
                replace = ui
                    .add_enabled_ui(!busy, |ui| kit::button(ui, "Replace", Style::Destructive))
                    .inner
                    .clicked();
            },
            |ui| {
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if replace && relay {
        // The answer of the relay closes the sheet.
        app.relay_replace(&entry.id);
    } else if replace {
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
    app.relay_join_cancel();
    app.relay_fill_fields();
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
                        let current = match app.sync.create_folder.as_deref() {
                            Some(folder) if !app.sync.create_custom => Current::Folder(folder),
                            _ => Current::Off,
                        };
                        pick = sync_picker(
                            ui,
                            "sync-create-picker",
                            &app.sync.folders,
                            current,
                            false,
                        );
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
        Some(Pick::Relay) | None => {}
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
            "The vault is ready, but sync is off: {message} Turn it on later in Settings > General > Sync."
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
        app.relay_join_cancel();
        app.ui.start = Step::Home;
        app.ui.focus.focus_page_start();
        return;
    }
    ui.add_space(8.0);
    ui.label(kit::text("Use a vault from another Mac", Font::Title).color(kit::LABEL));
    ui.add_space(6.0);
    let before = app.sync.relay.source;
    kit::segmented(
        ui,
        "sync-open-source",
        &mut app.sync.relay.source,
        &[
            (OpenSource::Folder, "Synced folder"),
            (OpenSource::Relay, relay::LABEL),
        ],
    );
    if app.sync.relay.source != before {
        app.ui.focus_start_field = true;
    }
    ui.add_space(8.0);
    if app.sync.relay.source == OpenSource::Relay {
        relay::open_screen(app, ui);
        return;
    }
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
    let ctx = ui.ctx().clone();
    if let Some((path, waiting)) = pick.take() {
        app.sync_select_open_file(path, waiting, Some(&ctx));
    }
    // The two ways to find the file, side by side under the list.
    let mut chosen = false;
    ui.horizontal(|ui| {
        if kit::small_button(ui, refresh_label, Style::Bordered).clicked() {
            app.sync_retry_open();
        }
        chosen = files::choose_file(
            ui,
            &mut app.files,
            &mut app.sync.open_path,
            "sync-open-path",
            "Choose another file…",
            DialogKind::OpenSyncedVault,
        )
        .changed();
    });
    if chosen {
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
                    // Also after a click on a file in the list.
                    kit::claim_start_focus(&mut app.ui.focus_start_field, &field);
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
                    // The path is picked when the owner is done typing it: Return or a
                    // click elsewhere. A pick on each character would move the focus
                    // to the passphrase after the first one.
                    if field.lost_focus()
                        && app.sync.open_pick.as_deref()
                            != Some(Path::new(app.sync.open_path.trim()))
                    {
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
                // As above: pick the path when the owner is done typing it.
                if field.lost_focus() && !app.sync.open_path.trim().is_empty() {
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
