//! Sync through the Apassy relay in the app (ADR 0022 section 5, contract relay-sync-v1
//! sections 6 and 7): the "Apassy relay" sheet that turns it on, "Add a Mac…" with the
//! safety words and the owner check, "Devices…", the relay source of "Use a vault from
//! another Mac", "Turn off" with "Delete the copy on the relay", "Replace with this Mac's
//! vault…", and the status words.
//!
//! The engine is [`crate::sync::RelaySync`]. Every relay call that the owner starts runs
//! on its own thread ([`Task`]): turning sync on with the first upload, "Add a Mac…" and
//! its question every 5 seconds, "Devices…", "Sync now", the receipts of the other Macs,
//! "Turn off", the replace of a damaged copy, a new passphrase, and the link, the wait,
//! the download, and the adoption of a Mac that joins. The window shows what runs
//! ([`Job::progress`]) and stays responsive; each frame takes the answers
//! ([`DesktopApp::relay_poll`]).
//!
//! A device call reads the device key from the unlocked vault first, for a moment and
//! with no network, then signs in on its thread with the key in memory
//! ([`KeySource::Memory`]). A call that changes the vault or its state takes the guard of
//! the relay sync of its vault, then the vault mutex only for each local step (the
//! `*_shared` calls of the engine), never across the network. It never takes the sync op
//! lock, so the window never waits for a transfer. A lock and a quit drop the keys in
//! memory and end the relay calls that run ([`DesktopApp::relay_forget_keys`]).
//!
//! "Turn on" keeps the relay state under a name of its own ([`STAGED`]) until the relay
//! answered: a folder sync of the vault goes on until then, and stays when the relay
//! refuses.
//!
//! The link of "Add a Mac…", a typed team code, and a pasted link for a vault of this
//! Mac stay in memory only while their sheet is open. A lock drops them. The team code
//! field is masked, and its text goes after each try, as a passphrase does.
//!
//! A join for a vault of the list whose relay copy has another passphrase asks for the
//! passphrase of the copy ([`JoinView::Passphrase`]). The vault takes it, as on the
//! other Macs of the team, and merges the copy (contract section 6). The step stays on
//! the screen while the merge runs.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use eframe::egui::{self, Label};
use zeroize::{Zeroize, Zeroizing};

use super::super::kit::{self, Font, Style, Tone};
use super::super::vaults::VaultSheet;
use super::super::{
    PASSPHRASE_CAPACITY, Sheet, VAULT_PASSPHRASE_FIELD, close_sheet, forget_secret_field,
    secure_input,
};
use super::{SyncSheet, UiStatus, ago};
use crate::broker::SharedVault;
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
use crate::desktop::owner_store::Ephemeral;
use crate::desktop::{DesktopApp, OwnerView};
use crate::sync::{
    DEFAULT_RELAY_URL, DeviceKey, DeviceView, JoinedDevice, KeySource, LinkCode, PendingJoin,
    PendingLink, Receipt, RelayAdoptReport, RelayConfig, RelayDownload, RelayEnableReport,
    RelayRefusal, RelaySync, RelayUrl, SyncError, SyncOutcome, VaultSync, device_name,
    valid_team_code,
};
use crate::vault::{Vault, VaultErrorKind};
use crate::vaults::{self, Registry, SyncLink, VaultEntry};

/// The name of the relay in the picker, the sidebar, and "Use a vault from another Mac".
pub(crate) const LABEL: &str = "Apassy relay";
/// How often a sheet asks the relay about a Mac that joins (contract section 7).
const POLL_EVERY: Duration = Duration::from_secs(5);
/// How long a cancel waits for a poll or a download to end before it gives up on the
/// relay.
const CANCEL_WAIT: Duration = Duration::from_secs(120);
/// How often Settings reads the receipts of the other Macs while it shows the open vault.
const RECEIPTS_EVERY: Duration = Duration::from_secs(15);
/// How long a quit waits for the relay to hear the cancel of a Mac that joins.
const QUIT_WAIT: Duration = Duration::from_secs(3);
/// A relay call whose thread ended without an answer.
const LOST: &str = "The relay call ended without an answer. Try again.";
/// A cancel of a link that the relay did not hear.
const NOT_CANCELLED: &str = "The relay did not hear that this Mac cancelled. The link ends on its own within 10 minutes. If the other Mac shows this Mac, select “Refuse” there.";
/// A device of a Mac that joined that Apassy could not remove.
const NOT_REMOVED: &str = "Apassy could not remove this Mac from the relay. The other Mac shows it in “Devices…”: remove it there.";
/// The end of the state name of a relay sync that turns on, until the relay answered.
const STAGED: &str = ".relay-new";
/// The masked team code field of the "Apassy relay" sheet.
pub(crate) const TEAM_CODE_FIELD: &str = "sync-relay-team-code";
/// The byte capacity of the team code field: 128 characters, 4 bytes each at most.
const TEAM_CODE_CAPACITY: usize = 4 * 128;

/// The source of "Use a vault from another Mac".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum OpenSource {
    /// A synced file in a folder (ADR 0014).
    #[default]
    Folder,
    /// A link from a Mac that syncs the vault through the relay (ADR 0022).
    Relay,
}

/// How the "Apassy relay" sheet turns sync on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SetupMode {
    /// A new personal team with an operator team code (contract section 6).
    #[default]
    NewCopy,
    /// The vault is on the relay already: a link from another Mac, then a merge.
    Join,
}

/// A relay call of the owner that runs on its own thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Job {
    /// "Turn on" with a team code and the first upload, or "Join from another Mac" for a
    /// vault of the list.
    TurnOn,
    /// The link of "Add a Mac…".
    NewLink,
    /// The Macs that wait in "Add a Mac…".
    Links,
    /// "Confirm…" after the owner check.
    Confirm,
    /// "Refuse".
    Refuse,
    /// The list of "Devices…".
    Devices,
    /// "Remove" in "Devices…".
    Remove,
    /// Whether this Mac is the last of its team, for "Turn off…".
    LastMac,
    /// "Sync now".
    SyncNow,
    /// The receipts of the other Macs.
    Receipts,
    /// "Turn off".
    TurnOff,
    /// "Replace with this Mac's vault".
    Replace,
    /// The passphrase that changed on another Mac.
    Passphrase,
    /// "Use the relay copy" after this Mac refused it.
    UseCopy,
    /// The cancel of a Mac that joins.
    Cancel,
}

impl Job {
    /// What the window shows while the call runs.
    pub(crate) fn progress(self) -> &'static str {
        match self {
            Self::TurnOn => "Apassy turns relay sync on and uploads the vault…",
            Self::NewLink => "Apassy asks the relay for a link…",
            Self::Links => "Apassy asks the relay for the Macs that wait…",
            Self::Confirm => "Apassy adds the other Mac…",
            Self::Refuse => "Apassy refuses the other Mac…",
            Self::Devices => "Apassy asks the relay for the Macs…",
            Self::Remove => "Apassy removes the Mac…",
            Self::LastMac => "Apassy asks the relay for the Macs of the team…",
            Self::SyncNow => "Apassy syncs with the relay…",
            Self::Receipts => "Apassy asks the relay which Macs have the vault…",
            Self::TurnOff => "Apassy removes this Mac from the relay team…",
            Self::Replace => "Apassy uploads the vault of this Mac to the relay…",
            Self::Passphrase => "Apassy checks the passphrase with the relay copy…",
            Self::UseCopy => "Apassy merges the relay copy and uploads the vault…",
            Self::Cancel => "Apassy cancels the link…",
        }
    }
}

/// What "Turn off" did with the device of this Mac on the relay.
enum Left {
    /// "Delete the copy on the relay".
    Deleted,
    /// This Mac left the team.
    Removed,
    /// This Mac was the last of the team: its device stays with the copy.
    LastMac,
    /// Another Mac had removed this one from the team already.
    Gone,
    /// The device stays, for this reason.
    Kept(String),
    /// "Delete the copy on the relay" failed: sync stays on.
    NotDeleted(SyncError),
}

/// The answer of "Turn on" or of a join for a vault of the list.
struct TurnedOn {
    /// The relay sync of the job, with its staged state.
    relay: RelaySync,
    name: String,
    joined: bool,
    /// The sync setting of the vault when the job started.
    before: Option<SyncLink>,
    result: Result<RelayEnableReport, SyncError>,
    /// A join that failed: the device that the other Mac confirmed, with the relay
    /// address, for the passphrase step or for its removal.
    device: Option<(Arc<JoinedDevice>, String)>,
    /// A join with the passphrase of the relay copy.
    typed: bool,
    /// The vault took the passphrase of the relay copy: on success, and on a failure
    /// after the passphrase opened the copy.
    rekeyed: bool,
}

/// The answer of a relay call of the owner.
enum Reply {
    TurnedOn(Box<TurnedOn>),
    Link(Result<LinkCode, SyncError>),
    Links(Result<Vec<PendingLink>, SyncError>),
    Confirmed {
        link_id: u64,
        result: Result<DeviceView, SyncError>,
    },
    Refused {
        link_id: u64,
        name: String,
        result: Result<(), SyncError>,
    },
    Devices(Result<Vec<DeviceView>, SyncError>),
    Removed {
        name: String,
        result: Result<(), SyncError>,
    },
    LastMac(Option<bool>),
    Synced {
        sync: VaultSync,
        result: Result<SyncOutcome, SyncError>,
        receipts: Option<Vec<Receipt>>,
    },
    Receipts(Vec<Receipt>),
    TurnedOff {
        left: Left,
        switch_to: Option<PathBuf>,
    },
    Replaced(Result<SyncOutcome, SyncError>),
    /// `Ok`: the vault uses the new passphrase, with the sync after it. `kept`: the
    /// passphrase only opened an older copy for the merge, and the vault kept its own
    /// ([`RelaySync::keeps_passphrase`]).
    Passphrase {
        kept: bool,
        result: Result<Result<SyncOutcome, SyncError>, SyncError>,
    },
    UsedCopy(Result<SyncOutcome, SyncError>),
    /// A cancel of a Mac that joins: the note when the relay did not hear it.
    Cancelled(Option<String>),
    Nothing,
}

/// A relay call that runs, for the vault `id` (empty for a Mac that joins).
struct Running {
    job: Job,
    id: String,
    task: Task<Reply>,
    /// The relay sync of the call, so that a lock or a quit can end its relay calls.
    relay: Option<RelaySync>,
}

/// "Add a Mac…" while its sheet is open.
struct AddMac {
    /// The vault (list ID).
    id: String,
    /// The link code. It works once, for 10 minutes.
    code: Option<LinkCode>,
    /// The Macs that wait for a confirmation.
    links: Vec<PendingLink>,
    next_poll: Instant,
    /// A failed call. The sheet stops asking until the owner selects "Check again".
    error: Option<String>,
    /// "Added. Mac mini receives the vault now."
    added: Option<String>,
}

/// "Devices…" while its sheet is open.
struct Devices {
    id: String,
    /// `None` while the relay answers.
    list: Option<Result<Vec<DeviceView>, String>>,
    /// The Mac of "Remove", while its confirmation is open: its id and name.
    confirm_remove: Option<(u64, String)>,
}

/// "Turn off…" of a vault on the relay.
struct TurnOff {
    id: String,
    /// Whether this Mac is the last device of the team. `None` when the vault is locked
    /// or the relay did not answer (yet).
    last: Option<bool>,
    /// "Delete the copy on the relay".
    delete: bool,
}

/// A Mac that joins the relay team of a vault with a link (contract section 7.2).
struct Join {
    /// `None`: a new vault on this Mac ("Use a vault from another Mac"). A list ID: that
    /// vault turns on relay sync and merges the relay copy.
    target: Option<String>,
    /// The relay origin of the link.
    url: String,
    /// The team name on the relay: the vault name on the other Mac.
    team: String,
    /// The safety words that both Macs show.
    safety: String,
    phase: Phase,
}

enum Phase {
    /// `POST /v1/devices/link`.
    Requesting(Task<Result<PendingJoin, SyncError>>),
    /// The other Mac has not confirmed yet.
    Waiting {
        pending: Arc<PendingJoin>,
        poll: Option<Task<Result<Option<JoinedDevice>, SyncError>>>,
        next_poll: Instant,
    },
    /// Confirmed: the copy downloads.
    Downloading {
        joined: Arc<JoinedDevice>,
        task: Task<Result<RelayDownload, SyncError>>,
    },
    /// Downloaded: the owner types the passphrase.
    Ready {
        joined: Arc<JoinedDevice>,
        download: RelayDownload,
    },
    /// The passphrase opens the copy, and the new vault is written.
    Adopting(Task<Adopted>),
    /// A vault of the list: the relay copy has another passphrase. The owner types the
    /// passphrase of the copy, and the vault takes it.
    Passphrase { joined: Arc<JoinedDevice> },
    /// The passphrase of the copy was typed: the merge runs ([`Job::TurnOn`]), and its
    /// answer ends this phase.
    Merging { joined: Arc<JoinedDevice> },
}

/// What the adoption of a relay copy brought back to the window.
struct Adopted {
    result: Result<RelayAdoptReport, SyncError>,
    /// The device and the copy, for another try after a wrong passphrase.
    joined: Arc<JoinedDevice>,
    download: RelayDownload,
    passphrase: Zeroizing<String>,
    relay: RelaySync,
    /// The vault list with the new vault.
    registry: Registry,
    id: String,
    name: String,
    path: PathBuf,
}

/// What a screen shows of a Mac that joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JoinView {
    Sending,
    Waiting {
        safety: String,
    },
    Downloading {
        team: String,
    },
    Ready {
        team: String,
    },
    Opening {
        team: String,
    },
    /// The relay copy of a vault of the list has another passphrase.
    Passphrase {
        team: String,
    },
}

/// The relay part of the sync state of the app.
#[derive(Default)]
pub(crate) struct RelayUi {
    /// The relay sync of each listed vault, by list ID. A clone shares the key and the
    /// access token in memory, so the window, the worker, and the step before a lock
    /// sign in once.
    cache: Mutex<BTreeMap<String, RelaySync>>,
    /// The source of "Use a vault from another Mac".
    pub(crate) source: OpenSource,
    /// The way of the "Apassy relay" sheet.
    pub(crate) mode: SetupMode,
    /// The relay address field.
    pub(crate) url_input: String,
    /// The team code field, masked. Erased after each try, when its sheet closes, and at
    /// a lock.
    pub(crate) team_code: String,
    /// The name of this Mac on the relay.
    pub(crate) device_input: String,
    /// The pasted link from the other Mac.
    pub(crate) link_input: String,
    add: Option<AddMac>,
    devices: Option<Devices>,
    turn_off: Option<TurnOff>,
    /// The folder that the vault syncs with after "Turn off": a switch from the relay
    /// to a folder.
    switch_to: Option<PathBuf>,
    join: Option<Join>,
    /// The pasted link code of the last join request and the device key it sent: a
    /// retry of that code sends the same key. Erased at a lock and after the relay
    /// answered.
    join_key: Option<(Zeroizing<String>, Zeroizing<Vec<u8>>)>,
    /// Why the last join failed, for the screen that started it.
    pub(crate) join_error: Option<String>,
    /// The newest receipt of the current version by another Mac, by list ID.
    received: BTreeMap<String, Receipt>,
    /// When Settings last asked for the receipts, by list ID.
    receipts_read: BTreeMap<String, Instant>,
    /// The relay calls that run.
    jobs: Vec<Running>,
    /// The window, which a call wakes when it ends.
    repaint: Option<egui::Context>,
}

impl RelayUi {
    /// The open vault changed: its sheets and their codes go.
    pub(crate) fn forget_open_vault(&mut self) {
        self.add = None;
        self.devices = None;
        self.turn_off = None;
        self.switch_to = None;
    }

    /// The vault `id` pushed a version that no other Mac has received yet.
    pub(crate) fn forget_receipt(&mut self, id: &str) {
        self.received.remove(id);
    }

    /// The newest receipt of the current version of `id` by another Mac.
    pub(crate) fn receipt(&self, id: &str) -> Option<&Receipt> {
        self.received.get(id)
    }

    /// What the screen of `target` shows of a Mac that joins.
    pub(crate) fn join_view(&self, target: Option<&str>) -> Option<JoinView> {
        let join = self
            .join
            .as_ref()
            .filter(|join| join.target.as_deref() == target)?;
        Some(match &join.phase {
            Phase::Requesting(_) => JoinView::Sending,
            Phase::Waiting { .. } => JoinView::Waiting {
                safety: join.safety.clone(),
            },
            Phase::Downloading { .. } => JoinView::Downloading {
                team: join.team.clone(),
            },
            Phase::Ready { .. } => JoinView::Ready {
                team: join.team.clone(),
            },
            Phase::Adopting(_) => JoinView::Opening {
                team: join.team.clone(),
            },
            Phase::Passphrase { .. } | Phase::Merging { .. } => JoinView::Passphrase {
                team: join.team.clone(),
            },
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An error text of the engine as a sentence: a capital first letter and a full stop.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    let mut line: String = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    };
    if !line.ends_with('.') {
        line.push('.');
    }
    line
}

/// Whether this Mac refuses the relay copy of a vault with `status`: an older copy, or
/// a history without its last change. "Use the relay copy…" goes on from there.
pub(crate) fn refused_copy(status: &UiStatus) -> bool {
    matches!(status, UiStatus::Problem(text)
        if matches!(problem(text), Some(SyncError::StaleCopy | SyncError::ForkedCopy)))
}

/// The relay problem of a status text ([`UiStatus::from_error`] keeps the text only).
fn problem(text: &str) -> Option<SyncError> {
    [
        SyncError::RelayUnreachable,
        SyncError::RelayBusy,
        SyncError::RemovedFromRelay,
        SyncError::StaleCopy,
        SyncError::ForkedCopy,
        SyncError::Relay(RelayRefusal::RateLimited),
        SyncError::Relay(RelayRefusal::Busy),
        SyncError::Relay(RelayRefusal::TeamLimit),
    ]
    .into_iter()
    .find(|error| error.to_string() == text)
}

/// The short tag of the status of a vault on the relay, and its tone.
pub(crate) fn tag(status: &UiStatus) -> (&'static str, Tone) {
    match status {
        UiStatus::UpToDate(_) => ("Saved to the relay", Tone::Good),
        UiStatus::Syncing => ("Sync pending", Tone::Accent),
        // Either the passphrase of another Mac, or the one of an older copy.
        UiStatus::NeedsPassphrase => ("Needs a passphrase", Tone::Warning),
        UiStatus::Damaged => ("Damaged copy", Tone::Warning),
        UiStatus::Problem(text) => match problem(text) {
            // The worker tries again on its own after a wait.
            Some(
                SyncError::RelayBusy
                | SyncError::Relay(RelayRefusal::RateLimited | RelayRefusal::Busy),
            ) => ("Sync pending", Tone::Accent),
            Some(SyncError::Relay(RelayRefusal::TeamLimit)) => ("Sync paused", Tone::Warning),
            Some(SyncError::RemovedFromRelay) => ("Removed from the relay", Tone::Warning),
            Some(SyncError::StaleCopy | SyncError::ForkedCopy) => {
                ("Relay copy refused", Tone::Warning)
            }
            Some(_) => ("Relay not reachable", Tone::Warning),
            None => ("Problem", Tone::Warning),
        },
        // Folder statuses; the relay has no file to wait for.
        UiStatus::Waiting | UiStatus::FolderUnavailable => ("Relay not reachable", Tone::Warning),
    }
}

/// The status of a vault on the relay in a sentence (ADR 0022 section 5). `received` is
/// the newest receipt of the current version by another Mac.
pub(crate) fn words(status: &UiStatus, received: Option<&Receipt>) -> String {
    match status {
        UiStatus::UpToDate(at) => {
            let mut line = "Saved to the relay.".to_owned();
            match (received, at) {
                (Some(receipt), _) => line.push_str(&format!(
                    " Received by {} {}.",
                    match receipt.device_name.trim() {
                        "" => "another Mac",
                        name => name,
                    },
                    ago(receipt.at)
                )),
                (None, Some(at)) => line.push_str(&format!(" Last sync {}.", ago(*at))),
                (None, None) => {}
            }
            line
        }
        UiStatus::Syncing => "Saved on this Mac. A change waits for the relay.".to_owned(),
        UiStatus::NeedsPassphrase => {
            "The passphrase changed on another Mac. Type the new passphrase.".to_owned()
        }
        UiStatus::Damaged => {
            "The copy on the relay fails a check. Apassy did not use it, and does not download it again until it changes.".to_owned()
        }
        UiStatus::Problem(text) => match problem(text) {
            Some(SyncError::Relay(RelayRefusal::RateLimited)) => {
                "The relay asks Apassy to wait a minute. Apassy syncs after that.".to_owned()
            }
            Some(SyncError::Relay(RelayRefusal::TeamLimit)) => {
                "The relay limits the pushes of this vault for this hour. The changes stay on this Mac and sync later.".to_owned()
            }
            _ => sentence(text),
        },
        UiStatus::Waiting | UiStatus::FolderUnavailable => {
            sentence(&SyncError::RelayUnreachable.to_string())
        }
    }
}

/// The status of a vault whose relay copy needs its own passphrase, when this Mac has no
/// anchor ([`RelaySync::keeps_passphrase`]): the copy can be from before a passphrase
/// change.
pub(crate) const OLDER_COPY_WORDS: &str = "The copy on the relay uses another passphrase than this vault. It can be from before a passphrase change. Type the passphrase of that copy.";

/// The text of a failed relay call of an owner action.
fn call_error(error: SyncError) -> String {
    match error {
        SyncError::RelayUnreachable => {
            "Relay not reachable. Check the relay address and the network, then try again."
                .to_owned()
        }
        SyncError::Relay(RelayRefusal::RateLimited) => {
            "The relay asks Apassy to wait a minute. Try again then.".to_owned()
        }
        SyncError::Vault(VaultErrorKind::Locked) => "Unlock the vault first.".to_owned(),
        other => sentence(&other.to_string()),
    }
}

/// The text of a failed join (contract section 7.2).
fn join_error(error: SyncError) -> String {
    match error {
        SyncError::Relay(RelayRefusal::JoinRefused) => {
            "The other Mac refused, or the link expired. Make a new link on the other Mac."
                .to_owned()
        }
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt) => {
            "The passphrase does not open this vault. Nothing changed on this Mac. Type it again."
                .to_owned()
        }
        SyncError::OtherVault => "The relay copy holds another vault. Nothing changed.".to_owned(),
        other => call_error(other),
    }
}

/// The text of a relay sync that did not turn on. `folder`: the vault syncs with a
/// folder, and that stays.
fn enable_error(error: SyncError, vault: &str, folder: bool) -> String {
    let stays = if folder {
        "Folder sync stays on."
    } else {
        "Sync stays off."
    };
    match error {
        SyncError::Relay(RelayRefusal::InviteInvalid) => format!(
            "The team code is wrong, used, or expired. Ask the operator of the relay for a new code. {stays}"
        ),
        SyncError::RelayUnreachable => format!(
            "Relay not reachable. Check the relay address and the network, then try again. {stays}"
        ),
        SyncError::OtherVault => format!("The relay copy holds another vault. {stays}"),
        // The passphrase step of a join ended before the owner typed it.
        SyncError::NeedsPassphrase => format!(
            "The relay copy uses another passphrase than “{vault}”. Join again, and type the passphrase of the relay copy when Apassy asks. {stays}"
        ),
        other if folder => {
            format!("Relay sync of “{vault}” did not turn on: {other}. Folder sync stays on.")
        }
        other => format!("Relay sync of “{vault}” stays off: {other}."),
    }
}

/// Why the device of this Mac stays on the relay after "Turn off".
fn kept_reason(error: SyncError) -> String {
    match error {
        SyncError::RelayUnreachable => "the relay is not reachable".to_owned(),
        SyncError::Vault(VaultErrorKind::Locked) => "the vault is locked".to_owned(),
        other => other.to_string(),
    }
}

/// Wait until `shared` is the only handle of its value, at most [`CANCEL_WAIT`]: a poll
/// or a download that still runs holds another.
fn sole<T>(mut shared: Arc<T>) -> Option<T> {
    let deadline = Instant::now() + CANCEL_WAIT;
    loop {
        match Arc::try_unwrap(shared) {
            Ok(value) => return Some(value),
            Err(again) if Instant::now() < deadline => {
                shared = again;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

/// A check that the vault in the shared slot is the file of `relay`: a switch can put
/// another vault there between two steps.
fn same_file(relay: &RelaySync) -> impl Fn(&Vault) -> bool + Send + 'static {
    let path = relay.config().vault_path.clone();
    move |vault: &Vault| std::fs::canonicalize(&path).is_ok_and(|path| path == vault.path())
}

impl DesktopApp {
    /// Whether the listed vault `id` syncs through the relay.
    pub(crate) fn is_relay(&self, id: &str) -> bool {
        self.vault_list
            .registry
            .get(id)
            .is_some_and(|entry| entry.sync_relay().is_some())
    }

    /// Whether another Mac removed this one from the relay team of the vault `id`
    /// ([`RelaySync::is_removed`]). Until the worker asks the relay again, every relay
    /// call of the vault fails at once, so the window offers only turning relay sync
    /// off: no "Sync now", "Add a Mac…", "Devices…", "Check again", or "Refresh".
    pub(crate) fn relay_removed(&self, id: &str) -> bool {
        lock(&self.sync.relay.cache)
            .get(id)
            .is_some_and(RelaySync::is_removed)
    }

    /// The relay sync of the listed vault `id`, when it syncs through the relay. Each
    /// call gives a clone of one value per vault and configuration.
    pub(crate) fn relay_of(&self, id: &str) -> Option<RelaySync> {
        let entry = self.vault_list.registry.get(id)?;
        let link = entry.sync_relay()?;
        let state = entry.sync_state()?;
        let config =
            RelayConfig::in_data_dir(&self.vault_list.data_dir, &entry.path, &link.url, state);
        let mut cache = lock(&self.sync.relay.cache);
        if let Some(sync) = cache.get(id).filter(|sync| *sync.config() == config) {
            return Some(sync.clone());
        }
        let sync = RelaySync::new(config);
        cache.insert(id.to_owned(), sync.clone());
        Some(sync)
    }

    /// Whether the open vault `id` is unlocked.
    fn relay_open(&self, id: &str) -> bool {
        self.vault_list.current.as_deref() == Some(id) && !self.owner_ui.session.is_locked()
    }

    /// The relay sync of the open, unlocked vault `id` with its device key in memory,
    /// for a call on another thread ([`KeySource::Memory`]). It takes the vault mutex
    /// for a moment, with no network.
    fn relay_ready(&self, id: &str) -> Result<RelaySync, SyncError> {
        if !self.relay_open(id) {
            return Err(SyncError::Vault(VaultErrorKind::Locked));
        }
        let relay = self.relay_of(id).ok_or(SyncError::NotEnabled)?;
        self.owner_ui
            .session
            .with_vault(|vault| relay.session(vault).map(|_| ()))
            .unwrap_or(Err(SyncError::Vault(VaultErrorKind::NotFound)))?;
        Ok(relay)
    }

    /// The shared vault slot for a `*_shared` call of the engine.
    fn relay_slot(&self) -> SharedVault {
        self.owner_ui.session.shared_vault()
    }

    /// Whether the relay call `job` of the vault `id` runs.
    pub(crate) fn relay_busy(&self, id: &str, job: Job) -> bool {
        self.sync
            .relay
            .jobs
            .iter()
            .any(|running| running.job == job && running.id == id)
    }

    /// Whether relay sync of the vault `id` turns on or off now: the sync setting of
    /// the vault waits for it.
    pub(crate) fn relay_changing(&self, id: &str) -> bool {
        self.relay_busy(id, Job::TurnOn) || self.relay_busy(id, Job::TurnOff)
    }

    /// Run `work` on its own thread. Its answer comes back in [`Self::relay_poll`].
    fn relay_spawn(&mut self, id: &str, job: Job, work: impl FnOnce() -> Reply + Send + 'static) {
        self.relay_spawn_with(id, job, None, work);
    }

    /// [`Self::relay_spawn`] for a call of `relay` that a lock or a quit ends
    /// ([`Self::relay_forget_keys`]).
    fn relay_spawn_with(
        &mut self,
        id: &str,
        job: Job,
        relay: Option<RelaySync>,
        work: impl FnOnce() -> Reply + Send + 'static,
    ) {
        let task = Task::spawn(self.sync.relay.repaint.clone(), work);
        self.sync.relay.jobs.push(Running {
            job,
            id: id.to_owned(),
            task,
            relay,
        });
    }

    /// The key and the access token of each relay sync leave the memory, and their
    /// relay calls end at once, except for the open, unlocked vault. A lock, a switch,
    /// and a quit call this, also while the worker or a call of the owner is in a
    /// transfer.
    pub(crate) fn relay_forget_keys(&mut self) {
        let open = self
            .vault_list
            .current
            .clone()
            .filter(|_| !self.owner_ui.session.is_locked());
        for (id, relay) in lock(&self.sync.relay.cache).iter() {
            if open.as_ref() != Some(id) {
                relay.forget();
            }
        }
        for running in &self.sync.relay.jobs {
            if let Some(relay) = running.relay.as_ref()
                && open.as_ref() != Some(&running.id)
            {
                relay.forget();
            }
        }
    }

    /// Each frame: take the answers of the relay calls that ended.
    pub(crate) fn relay_poll(&mut self, ctx: Option<&egui::Context>) {
        if let Some(ctx) = ctx {
            self.sync.relay.repaint = Some(ctx.clone());
        }
        let mut done = Vec::new();
        self.sync
            .relay
            .jobs
            .retain(|running| match running.task.poll() {
                TaskPoll::Waiting => true,
                TaskPoll::Done(reply) => {
                    done.push((running.job, running.id.clone(), Some(reply)));
                    false
                }
                TaskPoll::Lost => {
                    done.push((running.job, running.id.clone(), None));
                    false
                }
            });
        for (job, id, reply) in done {
            match reply {
                Some(reply) => self.relay_apply(&id, reply),
                None => self.relay_lost(&id, job),
            }
        }
    }

    /// A relay call whose thread ended without an answer.
    fn relay_lost(&mut self, id: &str, job: Job) {
        match job {
            Job::Links | Job::NewLink => {
                if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                    add.error = Some(LOST.to_owned());
                }
            }
            Job::Devices => {
                if let Some(devices) = self.sync.relay.devices.as_mut() {
                    devices.list = Some(Err(LOST.to_owned()));
                }
            }
            Job::TurnOff => {
                self.sync_track_open_vault();
                self.set_err(LOST);
            }
            Job::Receipts | Job::Cancel => {}
            _ => self.set_err(LOST),
        }
    }

    /// Close the sync sheet of the vault `id` that `which` names, when it is open.
    fn relay_close_sheet(&mut self, id: &str, which: impl Fn(&SyncSheet) -> bool) {
        if let Some(Sheet::Vault(VaultSheet::Sync(sheet))) = &self.ui.sheet
            && sheet.id() == id
            && which(sheet)
        {
            self.ui.sheet = None;
        }
    }

    /// Show the answer of a relay call of the vault `id`.
    fn relay_apply(&mut self, id: &str, reply: Reply) {
        match reply {
            Reply::TurnedOn(turned_on) => self.relay_turned_on(id, *turned_on),
            Reply::Link(result) => {
                if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                    match result {
                        Ok(code) => add.code = Some(code),
                        Err(error) => add.error = Some(call_error(error)),
                    }
                }
            }
            Reply::Links(result) => {
                if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                    add.next_poll = Instant::now() + POLL_EVERY;
                    match result {
                        Ok(links) => {
                            add.links = links;
                            add.error = None;
                        }
                        Err(error) => add.error = Some(call_error(error)),
                    }
                }
            }
            Reply::Confirmed { link_id, result } => self.relay_confirmed(id, link_id, result),
            Reply::Refused {
                link_id,
                name,
                result,
            } => match result {
                Ok(()) => {
                    if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                        add.links.retain(|link| link.id != link_id);
                    }
                    self.set_ok(format!("“{name}” is refused. It does not get the vault."));
                }
                Err(error) => self.set_err(call_error(error)),
            },
            Reply::Devices(result) => {
                if let Some(devices) = self
                    .sync
                    .relay
                    .devices
                    .as_mut()
                    .filter(|devices| devices.id == id)
                {
                    devices.list = Some(result.map_err(call_error));
                }
            }
            Reply::Removed { name, result } => {
                match result {
                    Ok(()) => self.set_ok(format!(
                        "“{name}” is removed from the relay. It keeps its copy of the vault, but it cannot sync any more."
                    )),
                    Err(error) => {
                        self.set_err(format!("“{name}” is not removed. {}", call_error(error)));
                    }
                }
                if self
                    .sync
                    .relay
                    .devices
                    .as_ref()
                    .is_some_and(|devices| devices.id == id)
                {
                    self.relay_load_devices(id);
                }
            }
            Reply::LastMac(last) => {
                if let Some(turn_off) = self
                    .sync
                    .relay
                    .turn_off
                    .as_mut()
                    .filter(|turn_off| turn_off.id == id)
                {
                    turn_off.last = last;
                }
            }
            Reply::Synced {
                sync,
                result,
                receipts,
            } => {
                self.sync_take_result(id, &sync, &result);
                match result {
                    Ok(outcome) => {
                        if let Some(receipts) = receipts {
                            self.relay_keep_receipts(id, receipts);
                        }
                        let changed = outcome.merge.as_ref().filter(|merge| merge.changed_local());
                        let text = match changed {
                            Some(merge) => {
                                let count = merge.inserted + merge.updated + merge.deleted;
                                format!(
                                    "Relay sync: {count} credential{} changed on this Mac.",
                                    if count == 1 { "" } else { "s" }
                                )
                            }
                            None => "Saved to the relay.".to_owned(),
                        };
                        self.set_ok(text);
                    }
                    // A lock, a pause, or a quit ended it: nothing to tell.
                    Err(SyncError::Vault(VaultErrorKind::Locked)) => {}
                    Err(error) => self.set_note(words(&UiStatus::from_error(error), None)),
                }
            }
            Reply::Receipts(receipts) => self.relay_keep_receipts(id, receipts),
            Reply::TurnedOff { left, switch_to } => self.relay_turned_off(id, left, switch_to),
            Reply::Replaced(result) => match result {
                Ok(_) => {
                    if self
                        .sync
                        .notice
                        .as_ref()
                        .is_some_and(|notice| notice.vault == id)
                    {
                        self.sync.notice = None;
                    }
                    self.relay_synced_status(id);
                    self.relay_close_sheet(id, |sheet| {
                        matches!(sheet, SyncSheet::ReplaceDamaged { .. })
                    });
                    self.set_ok(
                        "The relay has the vault of this Mac now. Your other Macs merge it at their next sync.",
                    );
                }
                Err(error) => {
                    self.set_err(format!(
                        "Apassy did not replace the copy on the relay: {error}."
                    ));
                }
            },
            Reply::Passphrase { kept, result } => match result {
                Ok(synced) => {
                    if !kept {
                        // Touch ID has the old passphrase now.
                        self.refresh_unlock_setting(None);
                    }
                    self.relay_close_sheet(id, |sheet| {
                        matches!(sheet, SyncSheet::NewPassphrase { .. })
                    });
                    let name = self
                        .vault_list
                        .registry
                        .get(id)
                        .map(|entry| entry.name.clone())
                        .unwrap_or_default();
                    let done = if kept {
                        format!(
                            "Apassy merged the relay copy into “{name}”, which keeps the passphrase of this Mac."
                        )
                    } else {
                        format!("“{name}” uses the new passphrase.")
                    };
                    match synced {
                        Ok(outcome) => {
                            self.sync_note_merge(id, &outcome);
                            self.relay_synced_status(id);
                            self.set_ok(format!("{done} It is in sync."));
                        }
                        Err(error) => {
                            // The worker syncs again after its wait.
                            self.sync.worker.reset();
                            self.sync_set_status(id, UiStatus::from_error(error));
                            self.set_note(format!(
                                "{done} The sync after it did not finish: {error}. Apassy tries again."
                            ));
                        }
                    }
                }
                Err(SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt)) => self.set_err(
                    "This passphrase does not open the copy on the relay. Nothing changed.",
                ),
                Err(SyncError::OtherVault) => {
                    self.set_err("The relay copy holds another vault. Nothing changed.");
                }
                Err(error) => self.set_err(format!("Nothing changed: {error}.")),
            },
            Reply::UsedCopy(result) => match result {
                Ok(outcome) => {
                    if self
                        .sync
                        .notice
                        .as_ref()
                        .is_some_and(|notice| notice.vault == id)
                    {
                        self.sync.notice = None;
                    }
                    self.sync_note_merge(id, &outcome);
                    self.relay_synced_status(id);
                    self.relay_close_sheet(id, |sheet| {
                        matches!(sheet, SyncSheet::UseRelayCopy { .. })
                    });
                    self.set_ok(
                        "Apassy merged the relay copy with this vault and uploaded the result. Relay sync goes on.",
                    );
                }
                Err(error) => {
                    // The next step of the owner: the new passphrase, or "Replace with
                    // this Mac's vault…" for a damaged copy. The relay copy stays the one
                    // to use (the engine keeps the forgotten anchor).
                    if matches!(error, SyncError::NeedsPassphrase | SyncError::Damaged) {
                        self.relay_close_sheet(id, |sheet| {
                            matches!(sheet, SyncSheet::UseRelayCopy { .. })
                        });
                    }
                    if let Some(relay) = self.relay_of(id) {
                        self.sync_take_result(id, &VaultSync::Relay(relay), &Err(error));
                    }
                    match error {
                        SyncError::Vault(VaultErrorKind::Locked) => {}
                        SyncError::NeedsPassphrase => self.set_note(
                            "The relay copy uses another passphrase than this vault. Type the passphrase of that copy to merge it.",
                        ),
                        other => {
                            self.set_err(format!("Apassy did not use the relay copy: {other}."));
                        }
                    }
                }
            },
            Reply::Cancelled(note) => {
                if let Some(note) = note {
                    self.set_note(note);
                }
            }
            Reply::Nothing => {}
        }
    }

    /// The answer of "Turn on", or of a join for a vault of the list. A join whose relay
    /// copy has another passphrase asks for it; any other failed join removes its
    /// device.
    fn relay_turned_on(&mut self, id: &str, turned_on: TurnedOn) {
        let TurnedOn {
            relay,
            name,
            joined,
            before,
            result,
            device,
            typed,
            rekeyed,
        } = turned_on;
        let name = name.as_str();
        // The merge with the passphrase of the copy ended.
        if self.sync.relay.join.as_ref().is_some_and(|join| {
            join.target.as_deref() == Some(id) && matches!(join.phase, Phase::Merging { .. })
        }) {
            self.sync.relay.join = None;
        }
        if rekeyed {
            // Touch ID has the old passphrase now.
            self.refresh_unlock_setting(None);
        }
        let took = if rekeyed {
            format!(" “{name}” uses the passphrase of the relay copy now.")
        } else {
            String::new()
        };
        if let (Err(error), Some((device, url))) = (&result, device) {
            // The copy needs its passphrase, or the typed one does not open it.
            let asks = *error == SyncError::NeedsPassphrase
                || (typed && *error == SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt));
            let open = matches!(&self.ui.sheet,
                Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::RelaySetup { id: shown })))
                    if shown == id);
            if asks && open && self.relay_open(id) {
                self.sync.relay.join_error = (*error != SyncError::NeedsPassphrase).then(|| {
                    "This passphrase does not open the relay copy. Nothing changed. Type it again."
                        .to_owned()
                });
                self.sync.relay.join = Some(Join {
                    target: Some(id.to_owned()),
                    url,
                    team: device.team().to_owned(),
                    safety: String::new(),
                    phase: Phase::Passphrase { joined: device },
                });
                self.ui.focus_start_field = true;
                return;
            }
            // The device leaves the relay again.
            self.relay_end_joined(device);
        }
        match result {
            Ok(report) => {
                let relay = match self.relay_take_staged(id, &relay, before) {
                    Ok(relay) => relay,
                    Err(text) => {
                        if joined {
                            self.sync.relay.join_error = Some(text.clone());
                        }
                        self.set_err(text);
                        return;
                    }
                };
                self.relay_linked(id, relay, report.link, &report.outcome);
                if !joined {
                    self.sync.relay.team_code.zeroize();
                }
                self.relay_close_sheet(id, |sheet| matches!(sheet, SyncSheet::RelaySetup { .. }));
                self.set_ok(if typed {
                    format!(
                        "“{name}” uses the passphrase of the relay copy now, as your other Macs, and merged with the copy. It syncs through the Apassy relay."
                    )
                } else if joined {
                    format!("“{name}” syncs through the Apassy relay and merged with the relay copy.")
                } else {
                    format!(
                        "“{name}” syncs through the Apassy relay. To add your other Mac, select “Add a Mac…”."
                    )
                });
            }
            Err(error) => {
                let text = format!("{}{took}", enable_error(error, name, before.is_some()));
                if joined {
                    self.sync.relay.join_error = Some(text.clone());
                }
                self.set_err(text);
            }
        }
    }

    /// The vault `id` matches the relay now: the worker starts its schedule again.
    fn relay_synced_status(&mut self, id: &str) {
        self.sync.worker.reset();
        self.sync.shown_failure = None;
        self.sync.relay.forget_receipt(id);
        let last = self
            .relay_of(id)
            .and_then(|relay| relay.state().ok().flatten())
            .and_then(|state| state.last_sync_at);
        self.sync_set_status(id, UiStatus::UpToDate(last));
    }

    /// The fields of a relay sheet that opens, and its first relay call.
    pub(crate) fn relay_prepare_sheet(&mut self, sheet: &SyncSheet) {
        let relay = &mut self.sync.relay;
        match sheet {
            SyncSheet::RelaySetup { .. } => {
                relay.mode = SetupMode::NewCopy;
                relay.join_error = None;
                self.relay_fill_fields();
            }
            SyncSheet::AddMac { .. } => relay.add = None,
            SyncSheet::Devices { .. } => relay.devices = None,
            SyncSheet::TurnOff { .. } => {
                relay.turn_off = None;
                relay.switch_to = None;
            }
            _ => {}
        }
    }

    /// The relay address and the name of this Mac, when the fields are empty.
    pub(crate) fn relay_fill_fields(&mut self) {
        let relay = &mut self.sync.relay;
        if relay.url_input.trim().is_empty() {
            relay.url_input = DEFAULT_RELAY_URL.to_owned();
        }
        if relay.device_input.trim().is_empty() {
            relay.device_input = device_name();
        }
    }

    /// Erase the team code and a pasted link, and drop the link of "Add a Mac…". A Mac
    /// that joins for a vault of this list stops.
    pub(crate) fn relay_forget_codes(&mut self) {
        let relay = &mut self.sync.relay;
        relay.team_code.zeroize();
        relay.link_input.zeroize();
        relay.join_key = None;
        relay.add = None;
        if relay
            .join
            .as_ref()
            .is_some_and(|join| join.target.is_some())
        {
            self.relay_join_cancel();
        }
    }

    /// A relay sheet closed: "Add a Mac…" refuses the Macs that wait for its link
    /// (contract section 7.1 step 4), and a join for a vault of this list stops.
    pub(crate) fn relay_sheet_closed(&mut self) {
        if let Some(add) = self.sync.relay.add.take() {
            let waiting: Vec<u64> = add
                .links
                .iter()
                .filter(|link| link.safety.is_some())
                .map(|link| link.id)
                .collect();
            if !waiting.is_empty()
                && let Ok(relay) = self.relay_ready(&add.id)
            {
                self.relay_spawn(&add.id, Job::Refuse, move || {
                    for link in waiting {
                        let _ = relay.refuse_link(KeySource::Memory, link);
                    }
                    Reply::Nothing
                });
            }
        }
        let relay = &mut self.sync.relay;
        relay.devices = None;
        relay.turn_off = None;
        relay.switch_to = None;
        if relay
            .join
            .as_ref()
            .is_some_and(|join| join.target.is_some())
        {
            self.relay_join_cancel();
        }
    }

    /// The disabling part of `sync_disable` for a vault on the relay: the device key
    /// leaves the vault when it is open and unlocked, and the key and the access token
    /// leave the memory. A relay sync of the vault that runs ends first: its relay calls
    /// end at once. The state file goes in `sync_disable`. No network.
    pub(crate) fn relay_disable(&mut self, id: &str) {
        let Some(relay) = self.relay_of(id) else {
            return;
        };
        let open = self.relay_open(id);
        {
            let _runs = relay.stop_runs();
            let op = self.sync.worker.op_lock();
            let _op = lock(&op);
            let removed = open
                && self
                    .owner_ui
                    .session
                    .with_vault(|vault| relay.disable(Some(vault)))
                    .is_some_and(|result| result.is_ok());
            if !removed {
                let _ = relay.disable(None);
            }
        }
        relay.forget();
        lock(&self.sync.relay.cache).remove(id);
        self.sync.relay.received.remove(id);
        self.sync.relay.receipts_read.remove(id);
    }

    /// Turn on relay sync for the open, unlocked vault `id` with a new personal team
    /// (contract section 6), on its own thread. A folder sync of the vault goes when the
    /// relay sync is on (one transport per vault), and stays when it fails. An error in
    /// the fields comes back at once; the answer of the relay comes in a later frame.
    pub(crate) fn relay_enable_new(
        &mut self,
        id: &str,
        url: &str,
        team_code: &str,
        device: &str,
    ) -> Result<(), String> {
        let entry = self.relay_target(id)?;
        let url = match url.trim() {
            "" => DEFAULT_RELAY_URL.to_owned(),
            typed => RelayUrl::parse(typed)
                .map_err(|error| sentence(&error.to_string()))?
                .as_str()
                .to_owned(),
        };
        let team_code = Zeroizing::new(team_code.trim().to_owned());
        if !valid_team_code(&team_code) {
            return Err(
                "Type the team code from the operator of the relay. It starts with apassy_tcd_."
                    .to_owned(),
            );
        }
        let device = match device.trim() {
            "" => device_name(),
            typed => typed.to_owned(),
        };
        if self.relay_changing(id) {
            return Ok(());
        }
        let relay = self.relay_staged(&entry, &url);
        let before = entry.sync.clone();
        let slot = self.relay_slot();
        let name = entry.name;
        let job = relay.clone();
        self.relay_spawn_with(id, Job::TurnOn, Some(relay.clone()), move || {
            let result =
                relay.create_team_shared(&slot, same_file(&relay), &name, &team_code, &device);
            Reply::TurnedOn(Box::new(TurnedOn {
                relay: job,
                name,
                joined: false,
                before,
                result,
                device: None,
                typed: false,
                rekeyed: false,
            }))
        });
        Ok(())
    }

    /// The relay sync of the vault `entry` that turns on, with its state under a name of
    /// its own ([`STAGED`]) until the relay answered. A state of an earlier try goes.
    fn relay_staged(&self, entry: &VaultEntry, url: &str) -> RelaySync {
        let relay = RelaySync::new(RelayConfig::in_data_dir(
            &self.vault_list.data_dir,
            &entry.path,
            url,
            &format!("{}{STAGED}", entry.id),
        ));
        let _ = relay.disable(None);
        relay
    }

    /// Relay sync of the vault `id` is on: a folder sync of it goes now, and the staged
    /// state takes the name of the vault. Returns the relay sync for the list. When the
    /// sync setting changed while the relay answered (`before` differs), the device key
    /// and the staged state go instead, and the setting stays.
    fn relay_take_staged(
        &mut self,
        id: &str,
        staged: &RelaySync,
        before: Option<SyncLink>,
    ) -> Result<RelaySync, String> {
        let entry = self
            .vault_list
            .registry
            .get(id)
            .cloned()
            .ok_or_else(|| "This vault is not in the list any more.".to_owned())?;
        staged.forget();
        if entry.sync != before {
            let removed = self.relay_open(id)
                && self
                    .owner_ui
                    .session
                    .with_vault(|vault| staged.disable(Some(vault)))
                    .is_some_and(|result| result.is_ok());
            if !removed {
                let _ = staged.disable(None);
            }
            return Err(format!(
                "Relay sync of “{}” did not turn on: its sync setting changed in the meantime. The relay team stays; remove this Mac in “Devices…” on another Mac, or ask the operator of the relay.",
                entry.name
            ));
        }
        if entry.sync.is_some() {
            self.sync_disable(id);
        }
        let relay = RelaySync::new(RelayConfig::in_data_dir(
            &self.vault_list.data_dir,
            &entry.path,
            &staged.config().url,
            &entry.id,
        ));
        let moved = {
            let op = self.sync.worker.op_lock();
            let _op = lock(&op);
            std::fs::rename(&staged.config().state_path, &relay.config().state_path)
        };
        moved.map_err(|_| {
            format!(
                "Relay sync of “{}” did not turn on: Apassy could not write its sync state. Turn it on again.",
                entry.name
            )
        })?;
        Ok(relay)
    }

    /// The open, unlocked vault `id`, for turning on relay sync.
    fn relay_target(&self, id: &str) -> Result<VaultEntry, String> {
        let entry = self
            .vault_list
            .registry
            .get(id)
            .cloned()
            .ok_or_else(|| "This vault is not in the list any more.".to_owned())?;
        if !self.relay_open(id) {
            return Err("Unlock the vault first.".to_owned());
        }
        Ok(entry)
    }

    /// Relay sync is on for `id`: the link goes into the vault list, the worker and the
    /// step before a lock take the vault, and a merge can leave a note.
    fn relay_linked(
        &mut self,
        id: &str,
        relay: RelaySync,
        link: vaults::RelayLink,
        outcome: &SyncOutcome,
    ) {
        if let Some(listed) = self.vault_list.registry.entry_mut(id) {
            listed.sync = Some(SyncLink::relay(id, link));
        }
        lock(&self.sync.relay.cache).insert(id.to_owned(), relay);
        self.save_vault_list();
        self.sync_track_open_vault();
        self.sync_note_merge(id, outcome);
        self.sync_refresh();
    }

    /// The relay copy of the vault `id` is this vault, from another Mac: turn on relay
    /// sync with the device that the other Mac confirmed, merge, and push (contract
    /// section 6, last paragraph), on its own thread. `passphrase` opens a relay copy
    /// under another passphrase, and the vault takes it. A copy under another
    /// passphrase, or a wrong passphrase, asks for it ([`Phase::Passphrase`]); any other
    /// failure removes the device.
    fn relay_enable_joined(
        &mut self,
        id: &str,
        joined: Arc<JoinedDevice>,
        url: &str,
        passphrase: Option<Zeroizing<String>>,
    ) -> Result<(), String> {
        let entry = match self.relay_target(id) {
            Ok(entry) => entry,
            Err(text) => {
                self.relay_end_joined(joined);
                return Err(text);
            }
        };
        if self.relay_changing(id) {
            self.relay_end_joined(joined);
            return Err(
                "Relay sync of this vault is turning on or off. Try again when it is done."
                    .to_owned(),
            );
        }
        let relay = self.relay_staged(&entry, url);
        let before = entry.sync.clone();
        let slot = self.relay_slot();
        let name = entry.name;
        let job = relay.clone();
        let url = url.to_owned();
        self.relay_spawn_with(id, Job::TurnOn, Some(relay.clone()), move || {
            let typed = passphrase.is_some();
            let result = match &passphrase {
                None => relay.enable_joined_shared(&slot, same_file(&relay), &joined),
                Some(passphrase) => relay.enable_joined_with_passphrase_shared(
                    &slot,
                    same_file(&relay),
                    &joined,
                    passphrase,
                ),
            };
            // The vault takes the passphrase of the copy before the merge: a failure
            // after it leaves the vault with it.
            let rekeyed = match (&passphrase, &result) {
                (None, _) => false,
                (Some(_), Ok(_)) => true,
                (Some(_), Err(SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt))) => false,
                (Some(passphrase), Err(_)) => {
                    Vault::verify_passphrase_at(&relay.config().vault_path, passphrase).is_ok()
                }
            };
            drop(passphrase);
            Reply::TurnedOn(Box::new(TurnedOn {
                relay: job,
                name,
                joined: true,
                before,
                device: result.is_err().then_some((joined, url)),
                result,
                typed,
                rekeyed,
            }))
        });
        Ok(())
    }

    /// The passphrase of the relay copy for the join of a vault of the list that asks
    /// for it ([`Phase::Passphrase`]): the merge runs on its own thread, and the step
    /// stays on the screen until it answers ([`Phase::Merging`]).
    pub(crate) fn relay_join_passphrase(&mut self, passphrase: Zeroizing<String>) {
        let Some(join) = self.sync.relay.join.take() else {
            return;
        };
        let (Some(id), Phase::Passphrase { joined } | Phase::Merging { joined }) =
            (join.target.clone(), &join.phase)
        else {
            self.sync.relay.join = Some(join);
            return;
        };
        if passphrase.is_empty() || self.relay_busy(&id, Job::TurnOn) {
            if passphrase.is_empty() {
                self.sync.relay.join_error =
                    Some("Type the passphrase of the relay copy.".to_owned());
            }
            self.sync.relay.join = Some(join);
            return;
        }
        self.sync.relay.join_error = None;
        let joined = Arc::clone(joined);
        self.sync.relay.join = Some(Join {
            phase: Phase::Merging {
                joined: Arc::clone(&joined),
            },
            ..join
        });
        let url = self
            .sync
            .relay
            .join
            .as_ref()
            .map(|join| join.url.clone())
            .unwrap_or_default();
        if let Err(text) = self.relay_enable_joined(&id, joined, &url, Some(passphrase)) {
            // The device left the relay already.
            self.sync.relay.join = None;
            self.sync.relay.join_error = Some(text);
        }
    }

    /// "Turn off" for the vault `id` on the relay, then sync with `switch_to` when it is
    /// a folder. The copy on the relay stays unless `delete_copy`; only the last device
    /// of the team gets that choice. The device of this Mac leaves the team when another
    /// device stays; the result message says what stays on the relay. The relay call
    /// runs on its own thread; an error comes back at once.
    pub(crate) fn relay_turn_off(
        &mut self,
        id: &str,
        delete_copy: bool,
        switch_to: Option<PathBuf>,
    ) -> Result<(), String> {
        let entry = self
            .vault_list
            .registry
            .get(id)
            .cloned()
            .ok_or_else(|| "This vault is not in the list any more.".to_owned())?;
        if self.relay_changing(id) {
            return Ok(());
        }
        let device = entry.sync_relay().map(|link| link.device_id);
        let last = self
            .sync
            .relay
            .turn_off
            .as_ref()
            .filter(|turn_off| turn_off.id == id)
            .and_then(|turn_off| turn_off.last);
        if !self.relay_open(id) {
            // The key of this Mac is in the vault: it leaves with the vault unlocked only.
            return Err(format!(
                "Open and unlock “{}” first. Relay sync stays on.",
                entry.name
            ));
        }
        if !delete_copy && last == Some(true) {
            self.relay_turned_off(id, Left::LastMac, switch_to);
            return Ok(());
        }
        // No sync of the worker, of the step before a lock, or of an owner call that
        // waits, while the device leaves: it would meet a removed device.
        self.sync_pause_open_vault();
        let relay = match self.relay_ready(id) {
            Ok(relay) => relay,
            Err(error) if delete_copy => {
                self.sync_track_open_vault();
                return Err(format!(
                    "Apassy did not delete the copy on the relay. {} Relay sync stays on.",
                    call_error(error)
                ));
            }
            Err(error) => {
                self.relay_turned_off(id, Left::Kept(kept_reason(error)), switch_to);
                return Ok(());
            }
        };
        self.relay_spawn(id, Job::TurnOff, move || {
            let left = if delete_copy {
                match relay.delete_relay_copy(KeySource::Memory) {
                    Ok(_) => Left::Deleted,
                    Err(error) => Left::NotDeleted(error),
                }
            } else if let Some(device) = device {
                // The key leaves the vault next, so this device could never sign in
                // again.
                match relay.remove_device(KeySource::Memory, device) {
                    Ok(()) => Left::Removed,
                    // Another Mac removed this one already.
                    Err(SyncError::RemovedFromRelay) => Left::Gone,
                    // The relay keeps the last device of the team.
                    Err(SyncError::Relay(RelayRefusal::Conflict)) => Left::LastMac,
                    Err(error) => Left::Kept(kept_reason(error)),
                }
            } else {
                Left::Kept(kept_reason(SyncError::NotEnabled))
            };
            Reply::TurnedOff { left, switch_to }
        });
        Ok(())
    }

    /// After "Turn off": sync is off, a folder sync takes over when the owner switched,
    /// and the message says what stays on the relay.
    fn relay_turned_off(&mut self, id: &str, left: Left, switch_to: Option<PathBuf>) {
        let name = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        let off = format!("Relay sync of “{name}” is off.");
        let relay_text = match left {
            Left::NotDeleted(error) => {
                self.sync_track_open_vault();
                self.set_err(format!(
                    "Apassy did not delete the copy on the relay: {error}. Relay sync stays on."
                ));
                return;
            }
            Left::Deleted => {
                format!("{off} The copy on the relay is deleted. The vault on this Mac stays.")
            }
            Left::Removed => format!("{off} The copy on the relay stays."),
            Left::Gone => format!(
                "{off} The copy on the relay stays. This Mac was no longer in the relay team. If the relay was paused and this Mac still shows in “Devices…” on another Mac, remove it there."
            ),
            Left::LastMac => format!(
                "{off} The copy on the relay stays. This Mac was the last Mac of the relay team, so only the operator of the relay can delete the copy now."
            ),
            Left::Kept(reason) => format!(
                "{off} The copy on the relay stays. This Mac is still in the relay team ({reason}): remove it in “Devices…” on another Mac."
            ),
        };
        self.sync_disable(id);
        self.sync.relay.turn_off = None;
        self.relay_close_sheet(id, |sheet| matches!(sheet, SyncSheet::TurnOff { .. }));
        match switch_to {
            None => self.set_ok(relay_text),
            Some(folder) => match self.sync_enable(id, &folder) {
                Ok(text) => self.set_ok(format!("{text} {relay_text}")),
                Err(text) => self.set_err(format!("{text} {relay_text}")),
            },
        }
    }

    /// Picking a folder for the vault `id` on the relay: the "Turn off" sheet asks
    /// first, and the folder sync starts after it.
    pub(crate) fn relay_switch_to_folder(
        &mut self,
        id: &str,
        folder: PathBuf,
        ctx: Option<&egui::Context>,
    ) {
        self.sync_open_sheet(SyncSheet::TurnOff { id: id.to_owned() }, ctx);
        self.sync.relay.switch_to = Some(folder);
    }

    /// "Sync now" for the open vault `id` on the relay, then the receipts of the other
    /// Macs, on its own thread.
    pub(crate) fn relay_sync_now(&mut self, id: &str) {
        if self.relay_busy(id, Job::SyncNow) || !self.relay_open(id) {
            return;
        }
        let Some(relay) = self.relay_of(id) else {
            return;
        };
        let slot = self.relay_slot();
        self.relay_spawn_with(id, Job::SyncNow, Some(relay.clone()), move || {
            let result = relay.sync_shared(&slot, same_file(&relay));
            let receipts = match result {
                Ok(_) => relay.receipts(KeySource::Memory).ok(),
                Err(_) => None,
            };
            Reply::Synced {
                sync: VaultSync::Relay(relay),
                result,
                receipts,
            }
        });
    }

    /// Settings shows the open vault `id`: ask for the receipts of the other Macs every
    /// [`RECEIPTS_EVERY`], for "Received by …".
    pub(crate) fn relay_receipts_due(&mut self, id: &str, ctx: &egui::Context) {
        ctx.request_repaint_after(RECEIPTS_EVERY);
        let due = self
            .sync
            .relay
            .receipts_read
            .get(id)
            .is_none_or(|at| at.elapsed() >= RECEIPTS_EVERY);
        if due {
            self.relay_read_receipts(id);
        }
    }

    /// Ask the relay for the receipts of the current version, on its own thread.
    fn relay_read_receipts(&mut self, id: &str) {
        if self.relay_busy(id, Job::Receipts) {
            return;
        }
        self.sync
            .relay
            .receipts_read
            .insert(id.to_owned(), Instant::now());
        let Ok(relay) = self.relay_ready(id) else {
            return;
        };
        self.relay_spawn(id, Job::Receipts, move || {
            match relay.receipts(KeySource::Memory) {
                Ok(receipts) => Reply::Receipts(receipts),
                Err(_) => Reply::Nothing,
            }
        });
    }

    /// Keep the newest receipt of the current version by another Mac (contract section
    /// 9). Each Mac sends one after it merged a version. A relay that has none keeps
    /// none.
    fn relay_keep_receipts(&mut self, id: &str, receipts: Vec<Receipt>) {
        let own = self
            .vault_list
            .registry
            .get(id)
            .and_then(VaultEntry::sync_relay)
            .map(|link| link.device_id);
        let version = self
            .relay_of(id)
            .and_then(|relay| relay.state().ok().flatten())
            .map_or(0, |state| state.last_remote_version);
        let newest = receipts
            .into_iter()
            .filter(|receipt| {
                Some(receipt.device_id) != own && version > 0 && receipt.version >= version
            })
            .max_by_key(|receipt| receipt.at);
        match newest {
            Some(receipt) => {
                self.sync.relay.received.insert(id.to_owned(), receipt);
            }
            None => {
                self.sync.relay.received.remove(id);
            }
        }
    }

    /// "Replace with this Mac's vault" for a damaged copy of the open vault `id` on the
    /// relay: this vault goes up as a new version, without a merge. On its own thread.
    pub(crate) fn relay_replace(&mut self, id: &str) {
        if self.relay_busy(id, Job::Replace) {
            return;
        }
        let Some(relay) = self.relay_of(id).filter(|_| self.relay_open(id)) else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        let slot = self.relay_slot();
        self.relay_spawn_with(id, Job::Replace, Some(relay.clone()), move || {
            Reply::Replaced(relay.replace_relay_copy_shared(&slot, same_file(&relay)))
        });
    }

    /// "Use the relay copy" for the open vault `id` after this Mac refused the relay
    /// copy: the copy as it is now merges into the vault, and the vault goes up. On its
    /// own thread.
    pub(crate) fn relay_use_copy(&mut self, id: &str) {
        if self.relay_busy(id, Job::UseCopy) {
            return;
        }
        let Some(relay) = self.relay_of(id).filter(|_| self.relay_open(id)) else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        let slot = self.relay_slot();
        self.relay_spawn_with(id, Job::UseCopy, Some(relay.clone()), move || {
            Reply::UsedCopy(relay.use_relay_copy_shared(&slot, same_file(&relay)))
        });
    }

    /// The passphrase changed on another Mac: `passphrase` must open the relay copy of
    /// the open vault `id`; the vault then takes it, and syncs. Without an anchor the
    /// vault keeps its passphrase and only merges the copy
    /// ([`RelaySync::keeps_passphrase`]). On its own thread.
    pub(crate) fn relay_take_passphrase(&mut self, id: &str, passphrase: Zeroizing<String>) {
        if self.relay_busy(id, Job::Passphrase) {
            return;
        }
        let Some(relay) = self.relay_of(id).filter(|_| self.relay_open(id)) else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        let slot = self.relay_slot();
        self.relay_spawn_with(id, Job::Passphrase, Some(relay.clone()), move || {
            // A sync meanwhile fails on the same copy, so the anchor stays as it is.
            let kept = relay.keeps_passphrase();
            Reply::Passphrase {
                kept,
                result: relay.take_new_passphrase_shared(&slot, same_file(&relay), &passphrase),
            }
        });
    }

    /// Whether the passphrase step of the relay vault `id` only opens an older copy for
    /// the merge, and the vault keeps its passphrase ([`RelaySync::keeps_passphrase`]).
    pub(crate) fn relay_keeps_passphrase(&self, id: &str) -> bool {
        self.relay_of(id)
            .is_some_and(|relay| relay.keeps_passphrase())
    }

    // ---- "Add a Mac…". ----

    /// A new link for another Mac.
    fn relay_add_mac_start(&mut self, id: &str) {
        let ready = self.relay_ready(id);
        self.sync.relay.add = Some(AddMac {
            id: id.to_owned(),
            code: None,
            links: Vec::new(),
            next_poll: Instant::now() + POLL_EVERY,
            error: ready.as_ref().err().map(|error| call_error(*error)),
            added: None,
        });
        if let Ok(relay) = ready {
            self.relay_spawn(id, Job::NewLink, move || {
                Reply::Link(relay.create_link(KeySource::Memory))
            });
        }
    }

    /// Ask the relay for the Macs that wait for a confirmation, with their safety words.
    fn relay_add_mac_poll(&mut self) {
        let Some(add) = self.sync.relay.add.as_ref() else {
            return;
        };
        let id = add.id.clone();
        if self.relay_busy(&id, Job::Links) {
            return;
        }
        let held = add.code.as_ref().map(|code| LinkCode {
            code: code.code.clone(),
            link: code.link.clone(),
            expires_at: code.expires_at,
        });
        match self.relay_ready(&id) {
            Ok(relay) => self.relay_spawn(&id, Job::Links, move || {
                Reply::Links(relay.pending_links(KeySource::Memory, held.as_ref()))
            }),
            Err(error) => {
                if let Some(add) = self.sync.relay.add.as_mut() {
                    add.next_poll = Instant::now() + POLL_EVERY;
                    add.error = Some(call_error(error));
                }
            }
        }
    }

    /// "Confirm…" for the Mac of `link_id`: the owner check first (ADR 0022 decision 6).
    fn relay_ask_confirm(&mut self, link_id: u64, ctx: Option<&egui::Context>) {
        let Some(add) = self.sync.relay.add.as_ref() else {
            return;
        };
        let Some(link) = add
            .links
            .iter()
            .find(|link| link.id == link_id && link.safety.is_some())
        else {
            return;
        };
        let request = OwnerRequest::ConfirmSyncDevice {
            vault: add.id.clone(),
            link_id,
            device_name: link.device_name.clone(),
            public_key: link.public_key.clone(),
        };
        self.ask_owner(request, ctx);
    }

    /// After the owner check: confirm the Mac of `link_id` for the vault `id` with the
    /// safety words of this Mac, on its own thread. `proof` must name this link exactly
    /// as the sheet showed it, in this vault session.
    pub(crate) fn relay_confirm_link(&mut self, id: &str, link_id: u64, proof: OwnerProof) {
        let link = self
            .sync
            .relay
            .add
            .as_ref()
            .filter(|add| add.id == id)
            .and_then(|add| add.links.iter().find(|link| link.id == link_id))
            .cloned();
        let Some(link) = link else {
            self.set_err("The “Add a Mac” sheet is closed. Nothing was added.");
            return;
        };
        let expected = OwnerAction::ConfirmSyncDevice {
            link_id,
            device_name: link.device_name.clone(),
            public_key: link.public_key.clone(),
        };
        let relay = match self.relay_ready(id) {
            Ok(relay) => relay,
            Err(error) => {
                self.set_err(format!("Nothing was added. {}", call_error(error)));
                return;
            }
        };
        let checked = self
            .owner_ui
            .session
            .with_vault(|vault| proof.check(&expected, &vault.epoch()));
        match checked {
            Some(Ok(())) => {}
            Some(Err(refusal)) => {
                self.set_err(refusal.message());
                return;
            }
            None => {
                self.set_err("Unlock the vault first. Nothing was added.");
                return;
            }
        }
        self.relay_spawn(id, Job::Confirm, move || Reply::Confirmed {
            link_id,
            result: relay.confirm_link(KeySource::Memory, &link),
        });
    }

    /// The answer of a confirmation.
    fn relay_confirmed(&mut self, id: &str, link_id: u64, result: Result<DeviceView, SyncError>) {
        let forget_link = |app: &mut Self| {
            if let Some(add) = app.sync.relay.add.as_mut().filter(|add| add.id == id) {
                add.links.retain(|link| link.id != link_id);
            }
        };
        match result {
            Ok(device) => {
                let text = format!("Added. {} receives the vault now.", device.name);
                forget_link(self);
                if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                    // The code is used: the sheet shows the result only, and asks no more.
                    add.added = Some(text.clone());
                    add.code = None;
                }
                self.set_ok(text);
            }
            Err(SyncError::Relay(RelayRefusal::Conflict)) => {
                forget_link(self);
                self.set_err("The relay's record of this Mac does not match. Nothing was added.");
            }
            Err(error) => self.set_err(format!("Nothing was added. {}", call_error(error))),
        }
    }

    /// "Refuse" for the Mac of `link_id`.
    fn relay_refuse_link(&mut self, link_id: u64) {
        let Some(add) = self.sync.relay.add.as_ref() else {
            return;
        };
        let id = add.id.clone();
        let name = add
            .links
            .iter()
            .find(|link| link.id == link_id)
            .map(|link| link.device_name.clone())
            .unwrap_or_default();
        match self.relay_ready(&id) {
            Ok(relay) => self.relay_spawn(&id, Job::Refuse, move || Reply::Refused {
                link_id,
                name,
                result: relay.refuse_link(KeySource::Memory, link_id),
            }),
            Err(error) => self.set_err(call_error(error)),
        }
    }

    // ---- "Devices…" and "Turn off…". ----

    fn relay_load_devices(&mut self, id: &str) {
        let ready = self.relay_ready(id);
        self.sync.relay.devices = Some(Devices {
            id: id.to_owned(),
            list: ready.as_ref().err().map(|error| Err(call_error(*error))),
            confirm_remove: None,
        });
        if let Ok(relay) = ready {
            self.relay_spawn(id, Job::Devices, move || {
                Reply::Devices(relay.devices(KeySource::Memory))
            });
        }
    }

    /// Remove another Mac from the relay team, after the confirmation of "Devices…". It
    /// needs no owner check: it only takes authority away (contract section 9).
    fn relay_remove_device(&mut self, id: &str, device_id: u64, name: &str) {
        let name = name.to_owned();
        match self.relay_ready(id) {
            Ok(relay) => self.relay_spawn(id, Job::Remove, move || Reply::Removed {
                name,
                result: relay.remove_device(KeySource::Memory, device_id),
            }),
            Err(error) => self.set_err(format!("“{name}” is not removed. {}", call_error(error))),
        }
    }

    /// Whether this Mac is the last device of the team, for "Turn off…".
    fn relay_check_turn_off(&mut self, id: &str) {
        self.sync.relay.turn_off = Some(TurnOff {
            id: id.to_owned(),
            last: None,
            delete: false,
        });
        if let Ok(relay) = self.relay_ready(id) {
            self.relay_spawn(id, Job::LastMac, move || {
                Reply::LastMac(
                    relay
                        .devices(KeySource::Memory)
                        .ok()
                        .map(|devices| devices.len() <= 1),
                )
            });
        }
    }

    // ---- A Mac that joins. ----

    /// Send the pasted link to the relay (contract section 7.2, steps 1 to 3). `target`
    /// is `None` for a new vault on this Mac, or the list ID of a vault that turns on
    /// relay sync.
    pub(crate) fn relay_join_request(
        &mut self,
        target: Option<String>,
        ctx: Option<&egui::Context>,
    ) {
        let relay = &mut self.sync.relay;
        relay.join_error = None;
        let text = Zeroizing::new(relay.link_input.trim().to_owned());
        if text.is_empty() {
            relay.join_error = Some("Paste the link from the other Mac.".to_owned());
            return;
        }
        let url_field = match relay.url_input.trim() {
            "" => DEFAULT_RELAY_URL.to_owned(),
            typed => typed.to_owned(),
        };
        let (url, code) = match PendingJoin::parse_link(&text, &url_field) {
            Ok((url, code)) => (url.as_str().to_owned(), code),
            Err(error) => {
                relay.join_error = Some(join_error(error));
                return;
            }
        };
        let device = match relay.device_input.trim() {
            "" => device_name(),
            typed => typed.to_owned(),
        };
        // One key for each pasted code: a retry after a lost answer is the same request.
        let key = match relay
            .join_key
            .as_ref()
            .filter(|(held, _)| held.as_str() == code.as_str())
        {
            Some((_, pkcs8)) => DeviceKey::from_pkcs8(pkcs8.clone()),
            None => DeviceKey::generate(),
        };
        let key = match key {
            Ok(key) => key,
            Err(error) => {
                relay.join_error = Some(join_error(error));
                return;
            }
        };
        relay.join_key = key.pkcs8().map(|pkcs8| (code, pkcs8.clone()));
        self.relay_join_cancel();
        let task = Task::spawn(ctx.cloned(), move || {
            PendingJoin::request_with_key(&text, &url_field, &device, key)
        });
        self.sync.relay.join = Some(Join {
            target,
            url,
            team: String::new(),
            safety: String::new(),
            phase: Phase::Requesting(task),
        });
    }

    /// End a Mac that joins on its own thread, best effort: `end` cancels the link or
    /// removes the device, and returns a note when the relay did not hear it. A quit
    /// waits for it a moment ([`Self::relay_quit`]).
    fn relay_end(&mut self, end: impl FnOnce() -> Option<String> + Send + 'static) {
        self.relay_spawn("", Job::Cancel, move || Reply::Cancelled(end()));
    }

    /// Remove the device of a Mac that the other Mac confirmed, when no vault holds its
    /// key (contract section 7.2 step 7). A download that still runs holds the device.
    fn relay_end_joined(&mut self, joined: Arc<JoinedDevice>) {
        self.relay_end(move || match sole(joined) {
            Some(device) => {
                device.cancel();
                None
            }
            None => Some(NOT_REMOVED.to_owned()),
        });
    }

    /// Cancel a link that waits for the other Mac (`POST /v1/devices/link/cancel`). When
    /// the other Mac confirmed in the meantime, the engine removes the new device.
    fn relay_end_pending(&mut self, pending: Arc<PendingJoin>) {
        self.relay_end(move || match sole(pending).map(PendingJoin::cancel) {
            Some(Ok(())) => None,
            Some(Err(_)) | None => Some(NOT_CANCELLED.to_owned()),
        });
    }

    /// Cancel a link that the relay has not answered yet: wait for its answer, then
    /// cancel it.
    fn relay_end_request(&mut self, task: Task<Result<PendingJoin, SyncError>>) {
        self.relay_end(move || {
            let deadline = Instant::now() + CANCEL_WAIT;
            loop {
                match task.poll() {
                    TaskPoll::Waiting if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    TaskPoll::Waiting => return Some(NOT_CANCELLED.to_owned()),
                    TaskPoll::Done(Ok(pending)) => {
                        return pending.cancel().err().map(|_| NOT_CANCELLED.to_owned());
                    }
                    TaskPoll::Done(Err(_)) | TaskPoll::Lost => return None,
                }
            }
        });
    }

    /// Stop a Mac that joins: its link is cancelled, or its device leaves the relay,
    /// best effort. A vault that the passphrase opens already is not stopped: it opens
    /// in a moment.
    pub(crate) fn relay_join_cancel(&mut self) {
        self.sync.relay.join_error = None;
        let Some(join) = self.sync.relay.join.take() else {
            return;
        };
        match join.phase {
            Phase::Requesting(task) => self.relay_end_request(task),
            Phase::Waiting { pending, .. } => self.relay_end_pending(pending),
            Phase::Downloading { joined, .. }
            | Phase::Ready { joined, .. }
            | Phase::Passphrase { joined } => {
                self.relay_end_joined(joined);
            }
            // The answer of the job ends it: a failure then removes the device.
            running @ (Phase::Adopting(_) | Phase::Merging { .. }) => {
                self.sync.relay.join = Some(Join {
                    phase: running,
                    ..join
                });
            }
        }
    }

    /// Before the app quits: a Mac that joins cancels its link or its device, and the
    /// quit waits up to [`QUIT_WAIT`] for the relay. What the relay did not hear stays:
    /// a link ends on its own within 10 minutes, and a device shows in "Devices…" on
    /// the other Mac.
    pub(crate) fn relay_quit(&mut self) {
        self.relay_join_cancel();
        // The relay calls of the owner that run end now; a quit does not wait for them.
        for running in &self.sync.relay.jobs {
            if let Some(relay) = running.relay.as_ref() {
                relay.forget();
            }
        }
        let deadline = Instant::now() + QUIT_WAIT;
        loop {
            self.sync.relay.jobs.retain(|running| {
                running.job != Job::Cancel || matches!(running.task.poll(), TaskPoll::Waiting)
            });
            let waiting = self
                .sync
                .relay
                .jobs
                .iter()
                .any(|running| running.job == Job::Cancel);
            if !waiting || Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// One look at a Mac that joins: the answer of the relay, the wait for the other Mac
    /// every 5 seconds, the download, and the adoption. Each frame of its screen calls
    /// it.
    pub(crate) fn relay_join_step(&mut self, ctx: Option<&egui::Context>) {
        let Some(join) = self.sync.relay.join.take() else {
            return;
        };
        let Join {
            target,
            url,
            mut team,
            mut safety,
            phase,
        } = join;
        let lost = || LOST.to_owned();
        let mut failure = None;
        let now = Instant::now();
        let next = match phase {
            Phase::Requesting(task) => match task.poll() {
                TaskPoll::Waiting => Some(Phase::Requesting(task)),
                TaskPoll::Done(Ok(pending)) => {
                    // The code is used: the field and the key of a retry forget it.
                    self.sync.relay.link_input.zeroize();
                    self.sync.relay.join_key = None;
                    team.clone_from(&pending.team);
                    safety.clone_from(&pending.safety);
                    Some(Phase::Waiting {
                        pending: Arc::new(pending),
                        poll: None,
                        next_poll: now + POLL_EVERY,
                    })
                }
                TaskPoll::Done(Err(error)) => {
                    failure = Some(join_error(error));
                    None
                }
                TaskPoll::Lost => {
                    failure = Some(lost());
                    None
                }
            },
            Phase::Waiting {
                pending,
                poll: Some(task),
                next_poll,
            } => match task.poll() {
                TaskPoll::Waiting => Some(Phase::Waiting {
                    pending,
                    poll: Some(task),
                    next_poll,
                }),
                TaskPoll::Done(Ok(None)) => Some(Phase::Waiting {
                    pending,
                    poll: None,
                    next_poll: now + POLL_EVERY,
                }),
                TaskPoll::Done(Ok(Some(joined))) => match &target {
                    None => {
                        let joined = Arc::new(joined);
                        let work = self.vault_list.data_dir.join("sync");
                        let device = Arc::clone(&joined);
                        let task = Task::spawn(ctx.cloned(), move || device.download(&work));
                        Some(Phase::Downloading { joined, task })
                    }
                    Some(id) => {
                        // The sheet shows the merge while it runs ([`Job::TurnOn`]).
                        if let Err(text) =
                            self.relay_enable_joined(id, Arc::new(joined), &url, None)
                        {
                            failure = Some(text);
                        }
                        None
                    }
                },
                TaskPoll::Done(Err(error)) => {
                    failure = Some(join_error(error));
                    None
                }
                TaskPoll::Lost => {
                    failure = Some(lost());
                    None
                }
            },
            Phase::Waiting {
                pending,
                poll: None,
                next_poll,
            } => {
                if now >= next_poll {
                    let asking = Arc::clone(&pending);
                    Some(Phase::Waiting {
                        pending,
                        poll: Some(Task::spawn(ctx.cloned(), move || asking.poll())),
                        next_poll,
                    })
                } else {
                    if let Some(ctx) = ctx {
                        ctx.request_repaint_after(next_poll - now);
                    }
                    Some(Phase::Waiting {
                        pending,
                        poll: None,
                        next_poll,
                    })
                }
            }
            Phase::Downloading { joined, task } => match task.poll() {
                TaskPoll::Waiting => Some(Phase::Downloading { joined, task }),
                TaskPoll::Done(Ok(download)) => {
                    self.vault_list.name_input = self.vault_list.registry.free_name(&team);
                    self.owner_ui.passphrase.zeroize();
                    if let Some(ctx) = ctx {
                        forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
                    }
                    self.ui.focus_start_field = true;
                    Some(Phase::Ready { joined, download })
                }
                TaskPoll::Done(Err(error)) => {
                    self.relay_end_joined(joined);
                    failure = Some(join_error(error));
                    None
                }
                TaskPoll::Lost => {
                    self.relay_end_joined(joined);
                    failure = Some(lost());
                    None
                }
            },
            ready @ (Phase::Ready { .. } | Phase::Passphrase { .. } | Phase::Merging { .. }) => {
                Some(ready)
            }
            Phase::Adopting(task) => match task.poll() {
                TaskPoll::Waiting => Some(Phase::Adopting(task)),
                TaskPoll::Done(adopted) => self.relay_adopted(adopted, ctx),
                TaskPoll::Lost => {
                    failure = Some(lost());
                    None
                }
            },
        };
        if failure.is_some() {
            self.sync.relay.join_error = failure;
        }
        // A finished join for a vault of the list may have closed its sheet already.
        self.sync.relay.join = next.map(|phase| Join {
            target,
            url,
            team,
            safety,
            phase,
        });
    }

    /// Make the relay copy a new vault on this Mac in `<data dir>/vaults/`, with relay
    /// sync on (contract section 7.2, steps 5 and 6). The name field and the passphrase
    /// field of the start screens give the name and the passphrase. The passphrase
    /// opens the copy on its own thread; [`Self::relay_adopted`] then unlocks the vault.
    pub(crate) fn relay_open_vault(&mut self, ctx: Option<&egui::Context>) {
        let Some(join) = self.sync.relay.join.take() else {
            return;
        };
        if join.target.is_some() || !matches!(join.phase, Phase::Ready { .. }) {
            self.sync.relay.join = Some(join);
            return;
        }
        let (name, path) = match self.new_vault_target("", Some(&join.team)) {
            Ok(target) => target,
            Err(message) => {
                self.sync.relay.join = Some(join);
                self.set_err(message);
                return;
            }
        };
        if let Err(message) = super::super::start::ensure_private_folder(&path) {
            self.sync.relay.join = Some(join);
            self.set_err(message);
            return;
        }
        let passphrase = Ephemeral::take(&mut self.owner_ui.passphrase);
        if let Some(ctx) = ctx {
            forget_secret_field(ctx, VAULT_PASSPHRASE_FIELD);
        }
        if passphrase.expose().is_empty() {
            self.sync.relay.join = Some(join);
            self.ui.focus_start_field = true;
            self.set_err("Type the passphrase of the vault.");
            return;
        }
        let mut registry = self.vault_list.registry.clone();
        let id = match registry.add(&name, &path, vaults::now()) {
            Ok(id) => id,
            Err(error) => {
                self.sync.relay.join = Some(join);
                self.set_err(error.to_string());
                return;
            }
        };
        let relay = RelaySync::new(RelayConfig::in_data_dir(
            &self.vault_list.data_dir,
            &path,
            &join.url,
            &id,
        ));
        let Join {
            target,
            url,
            team,
            safety,
            phase,
        } = join;
        let Phase::Ready { joined, download } = phase else {
            return;
        };
        let passphrase = passphrase.into_zeroizing();
        let repaint = ctx.cloned().or_else(|| self.sync.relay.repaint.clone());
        let task = Task::spawn(repaint, move || {
            let result = relay
                .adopt(&joined, &download, &passphrase)
                .map(|(vault, report)| {
                    drop(vault);
                    report
                });
            Adopted {
                result,
                joined,
                download,
                passphrase,
                relay,
                registry,
                id,
                name,
                path,
            }
        });
        self.sync.relay.join = Some(Join {
            target,
            url,
            team,
            safety,
            phase: Phase::Adopting(task),
        });
    }

    /// The adoption ended: list the new vault, open it, and unlock it. A wrong
    /// passphrase keeps the copy for another try.
    fn relay_adopted(&mut self, adopted: Adopted, ctx: Option<&egui::Context>) -> Option<Phase> {
        let Adopted {
            result,
            joined,
            download,
            passphrase,
            relay,
            mut registry,
            id,
            name,
            path,
        } = adopted;
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                let wrong = error == SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt);
                self.set_err(join_error(error));
                if wrong {
                    self.ui.focus_start_field = true;
                    return Some(Phase::Ready { joined, download });
                }
                drop(download);
                self.relay_end_joined(joined);
                return None;
            }
        };
        // The device belongs to the new vault now; the downloaded copy goes.
        drop(download);
        drop(joined);
        if let Some(entry) = registry.entry_mut(&id) {
            entry.sync = Some(SyncLink::relay(&id, report.link));
        }
        lock(&self.sync.relay.cache).insert(id.clone(), relay);
        self.vault_list.registry = registry;
        self.save_vault_list();
        let opened = self.owner_ui.session.open_file(&path);
        self.apply(opened, "The vault is open.")?;
        self.reset_vault_state(ctx);
        self.end_waiting_runs();
        self.list_open_vault(&name, ctx);
        let unlocked = self.owner_ui.session.unlock(&passphrase);
        drop(passphrase);
        self.ui.start = super::Step::Home;
        self.view = OwnerView::Vault;
        if unlocked.is_ok() {
            let _ = self.sync_after_unlock();
            self.sync.adopted_vault = Some(id);
        }
        let _ = self.apply(
            unlocked,
            &format!("“{name}” is on this Mac. Relay sync is on."),
        );
        None
    }
}

#[cfg(test)]
impl DesktopApp {
    /// Take the answers of the relay calls and look at a Mac that joins until no
    /// thread runs for them. At most 20 seconds.
    pub(crate) fn relay_settle_for_test(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.relay_poll(None);
            self.relay_join_step(None);
            let joining = match self.sync.relay.join.as_ref().map(|join| &join.phase) {
                Some(Phase::Requesting(_) | Phase::Downloading { .. } | Phase::Adopting(_)) => true,
                Some(Phase::Waiting { poll, .. }) => poll.is_some(),
                _ => false,
            };
            if (!joining && self.sync.relay.jobs.is_empty()) || Instant::now() > deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Look at a Mac that joins until no worker thread runs for it.
    pub(crate) fn relay_join_settle_for_test(&mut self) {
        self.relay_settle_for_test();
    }

    /// Ask the relay about a Mac that joins at the next look, not in 5 seconds.
    pub(crate) fn relay_join_poll_now_for_test(&mut self) {
        if let Some(Join {
            phase: Phase::Waiting { next_poll, .. },
            ..
        }) = self.sync.relay.join.as_mut()
        {
            *next_poll = Instant::now();
        }
        self.relay_join_step(None);
        self.relay_settle_for_test();
    }

    /// "Add a Mac…" asks the relay now, and takes the answer.
    pub(crate) fn relay_add_mac_poll_for_test(&mut self) {
        self.relay_add_mac_poll();
        self.relay_settle_for_test();
    }

    /// The link of the open "Add a Mac…" sheet.
    pub(crate) fn relay_add_mac_link_for_test(&self) -> Option<String> {
        let add = self.sync.relay.add.as_ref()?;
        add.code.as_ref().map(|code| code.link.to_string())
    }

    /// The Macs that wait in the open "Add a Mac…" sheet.
    pub(crate) fn relay_add_mac_links_for_test(&self) -> Vec<PendingLink> {
        self.sync
            .relay
            .add
            .as_ref()
            .map(|add| add.links.clone())
            .unwrap_or_default()
    }

    /// "Confirm…" in the open "Add a Mac…" sheet.
    pub(crate) fn relay_ask_confirm_for_test(&mut self, link_id: u64) {
        self.relay_ask_confirm(link_id, None);
    }

    /// Whether a relay call runs.
    pub(crate) fn relay_jobs_for_test(&self) -> usize {
        self.sync.relay.jobs.len()
    }

    /// "Remove" for the Mac `device_id` in the open "Devices…" sheet: its confirmation
    /// opens.
    pub(crate) fn relay_ask_remove_for_test(&mut self, device_id: u64, name: &str) {
        if let Some(devices) = self.sync.relay.devices.as_mut() {
            devices.confirm_remove = Some((device_id, name.to_owned()));
        }
    }

    /// Whether the confirmation of "Remove" is open.
    pub(crate) fn relay_remove_asked_for_test(&self) -> bool {
        self.sync
            .relay
            .devices
            .as_ref()
            .is_some_and(|devices| devices.confirm_remove.is_some())
    }
}

// ---- Drawing. ----

/// The safety words in a large font, with the sentence of the screen.
fn safety_lines(ui: &mut egui::Ui, before: &str, words: &str, after: &str) {
    kit::paragraph(ui, before, Font::Body, kit::LABEL);
    ui.add_space(4.0);
    ui.label(kit::text(words, Font::Title).color(kit::LABEL));
    ui.add_space(4.0);
    kit::paragraph(ui, after, Font::Callout, kit::SECONDARY);
}

/// What a Mac that joins shows while it waits: the words, the download.
fn join_progress(ui: &mut egui::Ui, view: &JoinView) {
    match view {
        JoinView::Sending => {
            kit::tone_note(ui, "Apassy sends the link to the relay…", Tone::Accent)
        }
        JoinView::Waiting { safety } => safety_lines(
            ui,
            "Waiting for the other Mac… Both Macs show:",
            safety,
            "Confirm on the other Mac if it shows the same words.",
        ),
        JoinView::Downloading { team } => kit::tone_note(
            ui,
            format!("The other Mac confirmed this Mac. Apassy downloads “{team}” from the relay…"),
            Tone::Accent,
        ),
        JoinView::Ready { team } => kit::tone_note(
            ui,
            format!("“{team}” is on this Mac, still encrypted."),
            Tone::Good,
        ),
        JoinView::Opening { team } => kit::tone_note(
            ui,
            format!("Apassy opens “{team}” with the passphrase…"),
            Tone::Accent,
        ),
        JoinView::Passphrase { team } => kit::tone_note(
            ui,
            format!(
                "The other Mac confirmed this Mac. The relay copy of “{team}” uses another passphrase than this vault."
            ),
            Tone::Warning,
        ),
    }
}

/// The progress of the relay call `job` of the vault `id`, when it runs. Returns
/// whether it runs.
fn progress(app: &DesktopApp, ui: &mut egui::Ui, id: &str, job: Job) -> bool {
    let busy = app.relay_busy(id, job);
    if busy {
        kit::tone_note(ui, job.progress(), Tone::Accent);
    }
    busy
}

/// The relay address, the link, and the name of this Mac, for a Mac that joins. Returns
/// true when the owner pressed Return in the link field.
fn link_fields(app: &mut DesktopApp, s: &mut kit::Section<'_>, focus: bool) -> bool {
    let link = s.field("Link", |ui| {
        kit::mono_input(
            ui,
            &mut app.sync.relay.link_input,
            "sync-relay-link",
            "https://…/link#apassy_lnk_…",
        )
    });
    // Also after a click on "Apassy relay".
    if focus {
        kit::claim_start_focus(&mut app.ui.focus_start_field, &link);
    }
    s.field("Name of this Mac", |ui| {
        kit::text_input(
            ui,
            &mut app.sync.relay.device_input,
            "sync-relay-device",
            "MacBook Pro",
        )
    });
    link.lost_focus() && link.ctx.input(|input| input.key_pressed(egui::Key::Enter))
}

/// "Apassy relay" in Settings > General > Sync: a new relay copy with a team code, or a
/// link from a Mac that syncs this vault through the relay already.
pub(super) fn setup_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    app.relay_join_step(Some(ctx));
    let joining = app.sync.relay.join_view(Some(&entry.id));
    let asks = matches!(joining, Some(JoinView::Passphrase { .. }));
    let busy = app.relay_busy(&entry.id, Job::TurnOn);
    let mut turn_on = false;
    let mut send = false;
    let mut merge = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-relay-setup", 520.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Sync “{}” through the Apassy relay", entry.name),
            Some(
                "The relay keeps one encrypted copy of this vault and passes the changes of each Mac to the others within seconds. It never gets the passphrase, so it cannot open the vault. Agents, grants, rules, and activity stay on each Mac.",
            ),
        );
        if joining.is_none() {
            kit::segmented(
                ui,
                "sync-relay-mode",
                &mut app.sync.relay.mode,
                &[
                    (SetupMode::NewCopy, "New relay copy"),
                    (SetupMode::Join, "Join from another Mac"),
                ],
            );
            ui.add_space(12.0);
        }
        match (app.sync.relay.mode, &joining) {
            (_, Some(view @ JoinView::Passphrase { .. })) => {
                join_progress(ui, view);
                ui.add_space(8.0);
                kit::section(
                    ui,
                    None,
                    Some(&format!(
                        "Type the passphrase of the relay copy. “{}” takes it, as on your other Macs, and Apassy merges the copy into it. From then on you unlock “{}” with the passphrase of the copy.",
                        entry.name, entry.name
                    )),
                    |s| {
                        let field = s.field("Passphrase of the copy", |ui| {
                            secure_input(
                                ui,
                                super::SYNC_PASSPHRASE_FIELD,
                                &mut app.sync.passphrase,
                                PASSPHRASE_CAPACITY,
                                "Required",
                            )
                        });
                        kit::claim_start_focus(&mut app.ui.focus_start_field, &field);
                        merge = field.lost_focus()
                            && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
                    },
                );
            }
            (_, Some(view)) => join_progress(ui, view),
            (SetupMode::NewCopy, None) => {
                kit::section(
                    ui,
                    None,
                    Some(
                        "The operator of the relay gives you a team code. It works once. Apassy makes a key for this Mac and keeps it in the vault.",
                    ),
                    |s| {
                        s.field("Relay address", |ui| {
                            kit::text_input(
                                ui,
                                &mut app.sync.relay.url_input,
                                "sync-relay-url",
                                DEFAULT_RELAY_URL,
                            )
                        });
                        // A one-time secret: masked, and erased after each try.
                        s.field("Team code", |ui| {
                            secure_input(
                                ui,
                                TEAM_CODE_FIELD,
                                &mut app.sync.relay.team_code,
                                TEAM_CODE_CAPACITY,
                                "apassy_tcd_…",
                            )
                        });
                        s.field("Name of this Mac", |ui| {
                            kit::text_input(
                                ui,
                                &mut app.sync.relay.device_input,
                                "sync-relay-device",
                                "MacBook Pro",
                            )
                        });
                    },
                );
            }
            (SetupMode::Join, None) => {
                kit::section(
                    ui,
                    None,
                    Some(
                        "For a vault that is on the relay already. On the Mac that syncs it, select “Add a Mac…” and copy the link. Apassy merges the relay copy with this vault.",
                    ),
                    |s| {
                        s.field("Relay address", |ui| {
                            kit::text_input(
                                ui,
                                &mut app.sync.relay.url_input,
                                "sync-relay-url",
                                DEFAULT_RELAY_URL,
                            )
                        });
                        send = link_fields(app, s, false);
                    },
                );
            }
        }
        progress(app, ui, &entry.id, Job::TurnOn);
        if let Some(error) = app.sync.relay.join_error.clone() {
            kit::tone_note(ui, error, Tone::Critical);
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                ui.add_enabled_ui(!busy, |ui| match (app.sync.relay.mode, &joining) {
                    (_, Some(JoinView::Passphrase { .. })) => {
                        merge |= kit::button(ui, "Merge", Style::Prominent).clicked();
                    }
                    (_, Some(_)) => {}
                    (SetupMode::NewCopy, None) => {
                        turn_on |= kit::button(ui, "Turn on", Style::Prominent).clicked();
                    }
                    (SetupMode::Join, None) => {
                        send |= kit::button(ui, "Send link", Style::Prominent).clicked();
                    }
                });
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    // Return in a field, or with no focus, does the default action of the sheet.
    if joining.is_none() && !busy && super::super::save_pressed(app, ctx) {
        match app.sync.relay.mode {
            SetupMode::NewCopy => turn_on = true,
            SetupMode::Join => send = true,
        }
    }
    if asks && !busy && super::super::save_pressed(app, ctx) {
        merge = true;
    }
    if merge && asks && !busy {
        let passphrase = Ephemeral::take(&mut app.sync.passphrase);
        forget_secret_field(ctx, super::SYNC_PASSPHRASE_FIELD);
        // The answer of the relay closes the sheet, or asks again.
        app.relay_join_passphrase(passphrase.into_zeroizing());
    } else if turn_on {
        let (url, device) = (
            app.sync.relay.url_input.clone(),
            app.sync.relay.device_input.clone(),
        );
        // The code works once: the field forgets it after each try.
        let code = Ephemeral::take(&mut app.sync.relay.team_code);
        forget_secret_field(ctx, TEAM_CODE_FIELD);
        // The answer of the relay closes the sheet ([`Job::TurnOn`]).
        if let Err(text) = app.relay_enable_new(&entry.id, &url, code.expose(), &device) {
            app.set_err(text);
        }
    } else if send {
        app.relay_join_request(Some(entry.id.clone()), Some(ctx));
    }
    if cancel {
        super::cancel_sheet(app, ctx);
    }
    response.escape
}

/// "Add a Mac…": the link for the other Mac, then each Mac that asks, with the safety
/// words, "Confirm…", and "Refuse" (contract section 7.1).
pub(super) fn add_mac_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    if app
        .sync
        .relay
        .add
        .as_ref()
        .is_none_or(|add| add.id != entry.id)
    {
        app.relay_add_mac_start(&entry.id);
    }
    let due = app.sync.relay.add.as_ref().is_some_and(|add| {
        add.error.is_none()
            && add.added.is_none()
            && add.code.is_some()
            && Instant::now() >= add.next_poll
    }) && !app.relay_busy(&entry.id, Job::Links);
    // No new question while the owner check of a confirmation is open.
    if due && app.owner.check.is_none() {
        app.relay_add_mac_poll();
    }
    ctx.request_repaint_after(POLL_EVERY);
    let Some(add) = app.sync.relay.add.as_ref() else {
        return false;
    };
    let link = add
        .code
        .as_ref()
        .map(|code| Zeroizing::new(code.link.to_string()));
    let expired = add
        .code
        .as_ref()
        .is_some_and(|code| kit::now() >= code.expires_at);
    let links = add.links.clone();
    let error = add.error.clone();
    let added = add.added.clone();
    // A removed Mac cannot add one: its link works no more, and a new call fails at once.
    let removed = app.relay_removed(&entry.id);
    let link = link.filter(|_| added.is_none() && !removed);
    let mut new_link = false;
    let mut check = false;
    let mut confirm = None;
    let mut refuse = None;
    let mut done = false;
    let response = kit::sheet(ctx, "sync-relay-add-mac", 520.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Add a Mac to “{}”", entry.name),
            added.is_none().then_some(
                "On the other Mac, open Apassy, select “Use a vault from another Mac”, then Apassy relay, and paste this link. The link works once, for 10 minutes. It gives nothing until you confirm the other Mac here.",
            ),
        );
        if let Some(link) = &link {
            let heading = ui.label(kit::text("Link", Font::Headline).color(kit::LABEL));
            kit::code_block(ui, link, 1).labelled_by(heading.id);
            ui.horizontal(|ui| {
                if kit::small_button(ui, "Copy link", Style::Bordered).clicked() {
                    ui.ctx().copy_text(link.to_string());
                }
                if expired && kit::small_button(ui, "New link", Style::Link).clicked() {
                    new_link = true;
                }
            });
            ui.add_space(10.0);
        }
        if let Some(added) = &added {
            // After a confirmation: the result and Done, nothing else.
            kit::tone_note(ui, added, Tone::Good);
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| {
                    done = kit::button(ui, "Done", Style::Prominent).clicked();
                },
            );
            return;
        }
        for job in [Job::NewLink, Job::Confirm, Job::Refuse] {
            progress(app, ui, &entry.id, job);
        }
        if let Some(error) = &error {
            kit::tone_note(ui, error, Tone::Critical);
            if !removed {
                ui.horizontal(|ui| {
                    check = kit::small_button(ui, "Check again", Style::Bordered).clicked();
                    if link.is_none() {
                        new_link = kit::small_button(ui, "New link", Style::Link).clicked();
                    }
                });
            }
        } else if expired {
            kit::note(ui, "The link expired. Make a new link for the other Mac.");
        } else if links.is_empty() && link.is_some() {
            kit::tone_note(ui, "Waiting for the other Mac…", Tone::Accent);
        }
        let deciding =
            app.relay_busy(&entry.id, Job::Confirm) || app.relay_busy(&entry.id, Job::Refuse);
        for pending in &links {
            ui.add_space(8.0);
            match &pending.safety {
                Some(words) => {
                    safety_lines(
                        ui,
                        &format!(
                            "“{}” asks to sync “{}”. Both Macs show:",
                            pending.device_name, entry.name
                        ),
                        words,
                        "Confirm only if the other Mac shows the same words.",
                    );
                    ui.add_enabled_ui(!deciding, |ui| {
                        ui.horizontal(|ui| {
                            if kit::small_button(ui, "Confirm…", Style::Prominent).clicked() {
                                confirm = Some(pending.id);
                            }
                            if kit::small_button(ui, "Refuse", Style::Bordered).clicked() {
                                refuse = Some(pending.id);
                            }
                        });
                    });
                }
                None => {
                    kit::paragraph(
                        ui,
                        format!(
                            "“{}” asks to join with an older link. Refuse it, and make a new link.",
                            pending.device_name
                        ),
                        Font::Body,
                        kit::LABEL,
                    );
                    if kit::small_button(ui, "Refuse", Style::Bordered).clicked() {
                        refuse = Some(pending.id);
                    }
                }
            }
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                done = kit::button(ui, "Done", Style::Bordered).clicked();
            },
        );
    });
    if new_link {
        app.relay_add_mac_start(&entry.id);
    } else if check {
        app.relay_add_mac_poll();
    } else if let Some(link_id) = confirm {
        app.relay_ask_confirm(link_id, Some(ctx));
    } else if let Some(link_id) = refuse {
        app.relay_refuse_link(link_id);
    }
    if done {
        super::cancel_sheet(app, ctx);
    }
    response.escape
}

/// "Devices…": the Macs of the relay team, and "Remove" for each other Mac.
pub(super) fn devices_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    if app
        .sync
        .relay
        .devices
        .as_ref()
        .is_none_or(|devices| devices.id != entry.id)
    {
        app.relay_load_devices(&entry.id);
    }
    let list = app
        .sync
        .relay
        .devices
        .as_ref()
        .and_then(|devices| devices.list.clone());
    let removing = app.relay_busy(&entry.id, Job::Remove);
    // A removed Mac sees the list it had, and nothing to do with it.
    let removed = app.relay_removed(&entry.id);
    let confirming = app
        .sync
        .relay
        .devices
        .as_ref()
        .and_then(|devices| devices.confirm_remove.clone());
    let mut ask = None;
    let mut refresh = false;
    let mut done = false;
    let response = kit::sheet(ctx, "sync-relay-devices", 500.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Macs that sync “{}”", entry.name),
            Some(
                "Each Mac has its own key on the relay. A removed Mac keeps its copy of the vault and the passphrase: to lock a person out, also change the passphrase and rotate each credential.",
            ),
        );
        progress(app, ui, &entry.id, Job::Remove);
        match &list {
            None => kit::tone_note(ui, Job::Devices.progress(), Tone::Accent),
            Some(Ok(devices)) => {
                kit::section(ui, None, None, |s| {
                    for device in devices {
                        s.row(|ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.add(
                                    Label::new(
                                        kit::text(&device.name, Font::Body).color(kit::LABEL),
                                    )
                                    .wrap(),
                                );
                                if device.current {
                                    kit::tag(ui, "This Mac", Tone::Neutral);
                                }
                            });
                            let seen = device.last_seen_at.map_or_else(
                                || "Not seen yet".to_owned(),
                                |at| format!("Last seen {}", ago(at)),
                            );
                            ui.add(
                                Label::new(kit::text(seen, Font::Footnote).color(kit::SECONDARY))
                                    .wrap(),
                            );
                            if !device.current
                                && !removed
                                && ui
                                    .add_enabled_ui(!removing, |ui| {
                                        kit::small_button(ui, "Remove", Style::Destructive)
                                    })
                                    .inner
                                    .clicked()
                            {
                                ask = Some((device.id, device.name.clone()));
                            }
                        });
                    }
                });
            }
            Some(Err(error)) => kit::tone_note(ui, error, Tone::Critical),
        }
        kit::sheet_buttons(
            ui,
            |ui| {
                if !removed {
                    refresh = ui
                        .add_enabled_ui(list.is_some(), |ui| {
                            kit::button(ui, "Refresh", Style::Bordered)
                        })
                        .inner
                        .clicked();
                }
            },
            |ui| {
                done = kit::button(ui, "Done", Style::Bordered).clicked();
            },
        );
    });
    // "Remove" asks first; Cancel has the focus for the keyboard.
    let mut remove = None;
    let mut keep = false;
    if let Some((device_id, name)) = &confirming {
        let alert = kit::sheet(ctx, "sync-relay-remove-device", 420.0, |ui| {
            kit::sheet_title(
                ui,
                &format!("Remove “{name}” from the relay?"),
                Some(
                    "It keeps its vault but stops syncing. To add it again you need a new link and the owner check.",
                ),
            );
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| {
                    if kit::button(ui, "Remove", Style::DestructiveProminent).clicked() {
                        remove = Some((*device_id, name.clone()));
                    }
                    keep = kit::alert_cancel(ui).clicked();
                },
            );
        });
        keep |= alert.escape;
    }
    if let Some(devices) = app.sync.relay.devices.as_mut() {
        if keep || remove.is_some() {
            devices.confirm_remove = None;
        } else if ask.is_some() {
            devices.confirm_remove = ask;
        }
    }
    if let Some((device_id, name)) = remove {
        app.relay_remove_device(&entry.id, device_id, &name);
    } else if refresh {
        app.relay_load_devices(&entry.id);
    }
    if done {
        super::cancel_sheet(app, ctx);
    }
    response.escape
}

/// "Turn off" for a vault on the relay, also before a switch to a folder. The copy on
/// the relay stays; the last device of the team also gets "Delete the copy on the relay".
pub(super) fn turn_off_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
) -> bool {
    let open = app.vault_list.current.as_deref() == Some(entry.id.as_str())
        && !app.owner_ui.session.is_locked();
    if open
        && app
            .sync
            .relay
            .turn_off
            .as_ref()
            .is_none_or(|turn_off| turn_off.id != entry.id)
    {
        app.relay_check_turn_off(&entry.id);
    }
    let last = app
        .sync
        .relay
        .turn_off
        .as_ref()
        .filter(|turn_off| open && turn_off.id == entry.id)
        .and_then(|turn_off| turn_off.last);
    let checking = open && app.relay_busy(&entry.id, Job::LastMac);
    let leaving = app.relay_busy(&entry.id, Job::TurnOff);
    let switch_to = app.sync.relay.switch_to.clone();
    let mut off = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-relay-turn-off", 480.0, |ui| {
        let mut text = match (open, last) {
            (false, _) => {
                "The key of this Mac for the relay is in the vault. Open and unlock the vault to turn relay sync off: the key then leaves the vault, and this Mac leaves the relay team."
            }
            (true, Some(true)) => {
                "Apassy stops merging this vault, and its key for the relay leaves the vault. The vault on this Mac stays. This Mac is the last Mac of the relay team: the copy on the relay stays unless you delete it now."
            }
            (true, _) => {
                "Apassy stops merging this vault, and this Mac leaves the relay team. The vault on this Mac stays. The copy on the relay stays, and your other Macs keep syncing with it. To sync this Mac again, add it from another Mac."
            }
        }
        .to_owned();
        let title = match &switch_to {
            Some(folder) => {
                let label = super::folder_label(&app.sync.folders, folder);
                text.push_str(&format!(" Then “{}” syncs with {label}.", entry.name));
                format!("Sync “{}” with {label} instead of the relay?", entry.name)
            }
            None => format!("Stop syncing “{}” through the relay?", entry.name),
        };
        kit::sheet_title(ui, &title, Some(&text));
        progress(app, ui, &entry.id, Job::LastMac);
        progress(app, ui, &entry.id, Job::TurnOff);
        if last == Some(true)
            && let Some(turn_off) = app.sync.relay.turn_off.as_mut()
        {
            kit::section(ui, None, None, |s| {
                s.toggle(
                    "Delete the copy on the relay",
                    Some(
                        "Apassy deletes every version of the copy on the relay. The vault on this Mac stays.",
                    ),
                    &mut turn_off.delete,
                );
            });
        }
        let label = if switch_to.is_some() {
            "Switch"
        } else {
            "Turn off"
        };
        kit::sheet_buttons(
            ui,
            |ui| {
                off = ui
                    .add_enabled_ui(open && !checking && !leaving, |ui| {
                        kit::button(ui, label, Style::Destructive)
                    })
                    .inner
                    .clicked();
            },
            |ui| {
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if off {
        let delete = last == Some(true)
            && app
                .sync
                .relay
                .turn_off
                .as_ref()
                .is_some_and(|turn_off| turn_off.delete);
        // The answer of the relay closes the sheet and says what stays on the relay.
        if let Err(text) = app.relay_turn_off(&entry.id, delete, switch_to) {
            app.set_err(text);
        }
    }
    if cancel {
        app.sync.relay.turn_off = None;
        app.sync.relay.switch_to = None;
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Use a vault from another Mac" > "Apassy relay": paste the link, wait for the other
/// Mac with the safety words, then type the passphrase (contract section 7.2).
pub(super) fn open_screen(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    app.relay_fill_fields();
    app.relay_join_step(Some(&ctx));
    let view = app.sync.relay.join_view(None);
    kit::paragraph(
        ui,
        "On the Mac that has the vault, open Settings > General > Sync, select “Add a Mac…”, and copy the link. Paste it here. Both Macs then show the same two words.",
        Font::Callout,
        kit::SECONDARY,
    );
    ui.add_space(14.0);
    let mut connect = false;
    let mut cancel = false;
    let mut submit = false;
    match &view {
        None => {
            kit::section(ui, None, None, |s| {
                connect = link_fields(app, s, true);
            });
            let mut details = app.ui.is_expanded("sync-relay-details");
            if kit::disclosure(ui, &mut details, "Relay address").changed() {
                app.ui.set_expanded("sync-relay-details", details);
            }
            if details {
                kit::section(
                    ui,
                    None,
                    Some("Only for a link without an address, or another relay."),
                    |s| {
                        s.field("Relay address", |ui| {
                            kit::text_input(
                                ui,
                                &mut app.sync.relay.url_input,
                                "sync-relay-open-url",
                                DEFAULT_RELAY_URL,
                            )
                        });
                    },
                );
            }
        }
        Some(JoinView::Ready { team }) => {
            join_progress(ui, &JoinView::Ready { team: team.clone() });
            ui.add_space(10.0);
            kit::section(
                ui,
                None,
                Some(
                    "Use the passphrase of the vault on the other Mac. Apassy keeps a local copy on this Mac.",
                ),
                |s| {
                    let field = s.field("Vault passphrase", |ui| {
                        secure_input(
                            ui,
                            VAULT_PASSPHRASE_FIELD,
                            &mut app.owner_ui.passphrase,
                            PASSPHRASE_CAPACITY,
                            "Vault passphrase",
                        )
                    });
                    kit::claim_start_focus(&mut app.ui.focus_start_field, &field);
                    submit = field.lost_focus()
                        && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
                    super::super::vaults::name_field(
                        app,
                        s,
                        "vault-relay-name",
                        "Name on this Mac",
                    );
                },
            );
        }
        Some(view) => join_progress(ui, view),
    }
    if let Some(error) = app.sync.relay.join_error.clone() {
        kit::paragraph(ui, error, Font::Callout, kit::SECONDARY);
    }
    ui.add_space(8.0);
    match &view {
        None => {
            connect |= kit::wide_button(ui, "Connect", Style::Prominent).clicked();
        }
        Some(JoinView::Ready { .. }) => {
            submit |= kit::wide_button(ui, "Use this vault", Style::Prominent).clicked();
            cancel = kit::small_button(ui, "Cancel", Style::Link).clicked();
        }
        // The passphrase opened the copy: the vault opens in a moment.
        Some(JoinView::Opening { .. }) => {}
        Some(_) => {
            cancel = kit::small_button(ui, "Cancel", Style::Link).clicked();
        }
    }
    if connect {
        app.relay_join_request(None, Some(&ctx));
    } else if submit {
        app.relay_open_vault(Some(&ctx));
    } else if cancel {
        app.relay_join_cancel();
        app.ui.focus_start_field = true;
    }
}

/// "Use the relay copy…": this Mac refuses the relay copy (an older copy, or a history
/// without its last change). The owner takes it as it is now; the vault merges it and
/// goes up.
pub(super) fn use_copy_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
) -> bool {
    let busy = app.relay_busy(&entry.id, Job::UseCopy);
    let mut use_copy = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-relay-use-copy", 500.0, |ui| {
        kit::sheet_title(
            ui,
            "Use the copy on the relay?",
            Some(&format!(
                "This Mac refuses the copy of “{}” on the relay: it is older than the copy that this Mac saw last, or its history does not include the last change of this Mac. That happens when the relay comes back from a backup. Apassy can take the relay copy as it is now, merge it with the vault on this Mac, and upload the result. Nothing on this Mac is lost. First look at the Macs in “Devices…”, and remove a Mac that you do not know.",
                entry.name
            )),
        );
        progress(app, ui, &entry.id, Job::UseCopy);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                use_copy = ui
                    .add_enabled_ui(!busy, |ui| {
                        kit::button(ui, "Use the relay copy", Style::Prominent)
                    })
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if use_copy {
        // The answer of the relay closes the sheet.
        app.relay_use_copy(&entry.id);
    }
    if cancel {
        super::cancel_sheet(app, ctx);
    }
    response.escape
}
