//! Sync through the Apassy relay in the app (ADR 0022 section 5, contract relay-sync-v1
//! sections 6 and 7): the "Apassy relay" sheet that turns it on, "Add a device…" with the
//! safety words and the owner check, "Devices…", the relay source of "Use a vault from
//! another Mac", "Turn off" with "Delete the copy on the relay", "Replace with this Mac's
//! vault…", and the status words.
//!
//! The engine is [`crate::sync::RelaySync`]. Every relay call that the owner starts runs
//! on its own thread ([`Task`]): turning sync on with the first upload, "Add a device…" and
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
//! The link of "Add a device…", a typed team code, and a pasted link for a vault of this
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

use super::super::companion::draw_qr;
use super::super::kit::{self, Font, Style, Tone};
use super::super::vaults::VaultSheet;
use super::super::{
    PASSPHRASE_CAPACITY, Sheet, VAULT_PASSPHRASE_FIELD, close_sheet, forget_secret_field,
    secure_input,
};
use super::{SyncSheet, UiStatus, ago};
use crate::broker::SharedVault;
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::desktop::companion::QrModules;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
use crate::desktop::owner_store::Ephemeral;
use crate::desktop::sync_worker::ConnectState;
use crate::desktop::{DesktopApp, Place};
use crate::questions::device_link::{LinkedDeviceKind, shown_link_name, split_linked_device_name};
use crate::questions::{QuestionsClient, TeamDevice};
use crate::sync::{
    DEFAULT_RELAY_URL, DepartedHead, DeviceKey, DeviceView, JoinedDevice, KeySource, LinkCode,
    LinkKind, PIN_CHANGED_TEXT, PairedLink, PendingJoin, PendingLink, Receipt, RelayAdoptReport,
    RelayConfig, RelayDownload, RelayEnableReport, RelayRefusal, RelaySync, RelayUrl, StoreDeleted,
    StorePlan, SyncError, SyncOutcome, TlsTrust, VaultSync, device_name, link_code_team,
    valid_team_code,
};
use crate::vault::{TrustedDeviceKind, Vault, VaultErrorKind};
use crate::vaults::{self, Registry, SyncLink, VaultEntry};

/// The name of the relay in the picker, the sidebar, and "Use a vault from another Mac".
pub(crate) const LABEL: &str = "Apassy relay";
/// The name of the sync of a vault through a vault store of the Apassy Connect account
/// (plan s7 unit M3), in the same places.
pub(crate) const CONNECT_LABEL: &str = "Apassy Connect";
/// What a vault store of Apassy Connect offers instead of "Add a device…" and
/// "Devices…": a store has no device links; the devices of the account sync it.
pub(crate) const CONNECT_DEVICES: &str = "Account Devices…";
/// Its hint.
pub(crate) const CONNECT_DEVICES_NOTE: &str =
    "Every device of your Apassy Connect account syncs this vault.";

/// The name of the sync of a vault on the relay: [`CONNECT_LABEL`] for a vault store of
/// Apassy Connect, else [`LABEL`].
pub(crate) fn label_of(connect: bool) -> &'static str {
    if connect { CONNECT_LABEL } else { LABEL }
}
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
const NOT_CANCELLED: &str = concat!(
    "The relay did not hear that this ",
    crate::computer!(),
    " cancelled. The link ends on its own within 10 minutes. If the other ",
    crate::computer!(),
    " shows this ",
    crate::computer!(),
    ", select “Refuse” there."
);
/// A device of a Mac that joined that Apassy could not remove.
const NOT_REMOVED: &str = concat!(
    "Apassy could not remove this ",
    crate::computer!(),
    " from the relay. The other ",
    crate::computer!(),
    " shows it in “Devices…”: remove it there."
);
/// How often the window hands the account session to the relay syncs and the worker.
pub(crate) const CONNECT_TICK_EVERY: Duration = Duration::from_secs(30);
/// "Replace It with This Mac's Copy…" of a vault store that waits on the head of a device
/// that left the account.
pub(crate) const REPLACE_DEPARTED: &str =
    concat!("Replace It with This ", crate::computer_cap!(), "'s Copy…");
/// The click of "Use the Copy That … Left…" on a screen of a device that joins: the next
/// step of the join takes it ([`DesktopApp::relay_join_step`]).
const TAKE_DEPARTED: &str = "sync-relay-take-departed";
/// The click of "Take This Copy Without Its Earlier History…" on a screen of a device that
/// joins ([`DesktopApp::relay_join_step`]).
const TAKE_WITHOUT_HISTORY: &str = "sync-relay-take-without-history";
/// The button of a first download whose earlier history does not verify.
pub(crate) const WITHOUT_HISTORY: &str = "Take This Copy Without Its Earlier History…";
/// The step of a vault whose vault store Apassy Connect deleted at a recovery: the sync
/// through Apassy Connect turns on again with a new store ([`DesktopApp::relay_enable_connect`]).
pub(crate) const SYNC_AGAIN: &str = "Sync Again…";
/// The line of a vault store that refuses this device: it does not claim why.
pub(crate) const STORE_REFUSED_WORDS: &str = concat!(
    "Apassy Connect no longer lets this ",
    crate::computer!(),
    " into this vault's copy. Check Settings › Connect."
);
/// A vault store that checks the device list this long says that Connect cannot be reached
/// to check it, with "Try Again" (connect-account-v1 section 7.5).
pub(crate) const CHECK_LIST_LONG: Duration = Duration::from_secs(10 * 60);
/// The line of such a store.
pub(crate) const CHECK_LIST_UNREACHABLE: &str = concat!(
    "Apassy Connect cannot be reached to check the devices. Changes stay on this ",
    crate::computer!(),
    " until then."
);
/// What to do instead of taking the copy of a removed device.
pub(crate) const DEPARTED_ADVICE: &str =
    "Ask on another device of the account instead, or replace the copy from a device you trust.";

/// "Use a vault from another Mac" › "Apassy Connect" while the key of the account was not
/// read (cancelled, or unavailable): "Sign In…" reads it again.
pub(crate) const CONNECT_SIGN_IN: &str =
    "Sign in to Apassy Connect to see the vaults of your account.";

/// A link for the origin of this Mac's Apassy Connect account while the account is not
/// signed in: nothing is sent.
pub(crate) const CONNECT_SIGN_IN_FOR_LINK: &str =
    "This link is for Apassy Connect. Choose Sign In… in Settings › Connect, then paste it again.";

/// The end of the state name of a relay sync that turns on, until the relay answered.
const STAGED: &str = ".relay-new";
/// The masked team code field of the "Apassy relay" sheet.
pub(crate) const TEAM_CODE_FIELD: &str = "sync-relay-team-code";
/// The byte capacity of the team code field: 128 characters, 4 bytes each at most.
pub(super) const TEAM_CODE_CAPACITY: usize = 4 * 128;

/// The source of "Use a vault from another Mac".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum OpenSource {
    /// A synced file in a folder (ADR 0014).
    #[default]
    Folder,
    /// A link from a Mac that syncs the vault through the relay (ADR 0022).
    Relay,
    /// The vault store of a vault of the Connect account of this Mac that this Mac does
    /// not have yet (plan s7 unit M5, leftover of M3): no link code; the passphrase of
    /// the vault opens the copy.
    Connect,
}

/// How the "Apassy relay" sheet turns sync on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SetupMode {
    /// A new personal team with an operator team code (contract section 6).
    #[default]
    NewCopy,
    /// The vault is on the relay already: a link from another Mac, then a merge.
    Join,
    /// "Your own node" (plan S2–S3 unit L4): a new team on the owner's Linux node with
    /// the node pairing link of `apassy pair` (node-pairing-v1, `/pair#`): its origin,
    /// its pin, its alternatives, and a one-use team code of kind `node`.
    Node,
    /// "Apassy Connect" (plan s7 unit M3): the vault store of the account of this Mac,
    /// offered while the account has a plan that pushes. A second Mac of the account
    /// turns on the same way, without a link code, and merges.
    Connect,
}

/// A relay call of the owner that runs on its own thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Job {
    /// "Turn on" with a team code and the first upload, or "Join from another Mac" for a
    /// vault of the list.
    TurnOn,
    /// The link of "Add a device…".
    NewLink,
    /// The devices that wait in "Add a device…".
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
    /// "Use the Copy That … Left…" of a vault store that waits on a device that left.
    UseDeparted,
    /// The cancel of a Mac that joins.
    Cancel,
    /// "Move the relay copy to Connect".
    Move,
    /// "Undo the move" after a move that kept both copies.
    UndoMove,
    /// The newer devices of the account join the vault store of the open vault.
    Register,
}

impl Job {
    /// What the window shows while the call runs.
    pub(crate) fn progress(self) -> &'static str {
        match self {
            Self::TurnOn => "Apassy turns relay sync on and uploads the vault…",
            Self::NewLink => "Apassy asks the relay for a link…",
            Self::Links => concat!(
                "Apassy asks the relay for the ",
                crate::computers!(),
                " that wait…"
            ),
            Self::Confirm => concat!("Apassy adds the other ", crate::computer!(), "…"),
            Self::Refuse => concat!("Apassy refuses the other ", crate::computer!(), "…"),
            Self::Devices => concat!("Apassy asks the relay for the ", crate::computers!(), "…"),
            Self::Remove => concat!("Apassy removes the ", crate::computer!(), "…"),
            Self::LastMac => concat!(
                "Apassy asks the relay for the ",
                crate::computers!(),
                " of the team…"
            ),
            Self::SyncNow => "Apassy syncs with the relay…",
            Self::Receipts => concat!(
                "Apassy asks the relay which ",
                crate::computers!(),
                " have the vault…"
            ),
            Self::TurnOff => concat!(
                "Apassy removes this ",
                crate::computer!(),
                " from the relay team…"
            ),
            Self::Replace => concat!(
                "Apassy uploads the vault of this ",
                crate::computer!(),
                " to the relay…"
            ),
            Self::Passphrase => "Apassy checks the passphrase with the relay copy…",
            Self::UseCopy => "Apassy merges the relay copy and uploads the vault…",
            Self::UseDeparted => {
                "Apassy merges the copy that the device left and uploads the vault…"
            }
            Self::Cancel => "Apassy cancels the link…",
            Self::Move => "Apassy moves the relay copy to Apassy Connect…",
            Self::UndoMove => "Apassy deletes the copy on Apassy Connect…",
            Self::Register => "Apassy adds your other devices to the copy on Apassy Connect…",
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
    /// The text of a Connect refusal of a relay copy without a code (capacity, a saved
    /// key, another Mac's team); `result` then holds a stand-in error.
    refused: Option<String>,
}

/// The answer of a relay call of the owner.
enum Reply {
    TurnedOn(Box<TurnedOn>),
    Link(Result<LinkCode, SyncError>),
    Links(Result<Vec<PendingLink>, SyncError>),
    Handoff {
        qid: String,
        result: Result<(), String>,
    },
    Confirmed {
        link: PendingLink,
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
        sync: Box<VaultSync>,
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
    /// "Use the Copy That … Left…", with the name of that device.
    UsedDeparted {
        name: Option<String>,
        result: Result<SyncOutcome, SyncError>,
    },
    /// A cancel of a Mac that joins: the note when the relay did not hear it.
    Cancelled(Option<String>),
    /// "Move the relay copy to Connect" ended: the relay sync of Connect that ran it,
    /// the sync setting when it started, and the result.
    Moved(Box<Moved>),
    /// "Undo the move" ended.
    Undone(Result<(), String>),
    /// The newer devices of the account that joined the store of the open vault.
    Registered(Vec<String>),
    Nothing,
}

/// The answer of "Move the relay copy to Connect".
struct Moved {
    connect: RelaySync,
    before: Option<SyncLink>,
    result: Result<crate::sync::ConnectEnableReport, crate::sync::MoveFailure>,
}

/// A relay call that runs, for the vault `id` (empty for a Mac that joins).
struct Running {
    job: Job,
    id: String,
    task: Task<Reply>,
    /// The relay sync of the call, so that a lock or a quit can end its relay calls.
    relay: Option<RelaySync>,
}

/// "Add a device…" while its sheet is open.
struct AddMac {
    older: Vec<(crate::vault::TrustedDevice, String)>,
    /// The vault (list ID).
    id: String,
    /// The link code. It works once, for 10 minutes.
    code: Option<LinkCode>,
    /// The QR code of the link of `code`, for the iPhone app. It goes with `code`.
    qr: Option<QrModules>,
    /// The Macs that wait for a confirmation.
    links: Vec<PendingLink>,
    next_poll: Instant,
    /// A failed call. The sheet stops asking until the owner selects "Check again".
    error: Option<String>,
    /// "Added. Mac mini receives the vault now."
    added: Option<String>,
    /// "Add an iPhone…" of a notifications-only team (plan §A7): the links go through
    /// the questions team of the vault, not through relay sync.
    via: Option<QuestionsClient>,
    channel: Option<crate::relay::pairing::PairingChannel>,
    /// The sealed keys for a confirmed iPhone or Apple Watch, the expiry of the code, the
    /// shown name of the device, and whether it is a watch.
    handoff: Option<(crate::questions::envelope::Sealed, u64, String, bool)>,
    /// The link names this Mac's node (a pinned node team): "via your Mac", Copy, and
    /// the Tailscale line of frame 2c.
    node: bool,
    /// The iPhone or Apple Watch that this sheet added, and whether it is a watch: frame
    /// 2c of the questions mode.
    added_device: Option<(String, bool)>,
}

impl AddMac {
    fn new(id: &str, error: Option<String>, via: Option<QuestionsClient>) -> Self {
        Self {
            older: Vec::new(),
            id: id.to_owned(),
            code: None,
            qr: None,
            links: Vec::new(),
            next_poll: Instant::now() + POLL_EVERY,
            error,
            added: None,
            via,
            channel: None,
            handoff: None,
            node: false,
            added_device: None,
        }
    }
}

/// A device of the questions team as the sheet of "Add a device…" shows it.
fn team_device_view(device: TeamDevice) -> DeviceView {
    DeviceView {
        id: device.id,
        member_id: 0,
        member_name: String::new(),
        name: device.name,
        public_key: String::new(),
        key_holder: false,
        created_at: 0,
        last_seen_at: device.last_seen_at,
        current: device.current,
    }
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

impl Join {
    /// The confirmed device of this join, once it has one.
    fn joined(&self) -> Option<&JoinedDevice> {
        match &self.phase {
            Phase::Downloading { joined, .. }
            | Phase::Departed { joined, .. }
            | Phase::WithoutHistory { joined, .. }
            | Phase::Ready { joined, .. }
            | Phase::Passphrase { joined }
            | Phase::Merging { joined } => Some(joined),
            _ => None,
        }
    }
}

/// What a link for the origin of this Mac's Connect account turned out to be.
enum Resolved {
    /// A vault store of the account that lists this Mac: no link is used.
    Store(JoinedDevice),
    /// A relay team at that origin: the link was sent with a key of its own.
    Link(PendingJoin),
}

enum Phase {
    /// `POST /v1/devices/link`.
    Requesting(Task<Result<PendingJoin, SyncError>>),
    /// A link for the origin of the Connect account: the stores of the account first,
    /// then the store or the link ([`Resolved`]).
    Resolving(Task<Result<Resolved, String>>),
    /// The device of this Mac in a vault store of its Connect account
    /// (`RelaySync::joined_from_store`): no link and no confirmation.
    FromStore(Task<Result<JoinedDevice, String>>),
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
    /// A vault store whose head a device that left the account pushed, and no live device
    /// signed over it: the owner can take it once ("Use the Copy That … Left…").
    Departed {
        joined: Arc<JoinedDevice>,
        head: DepartedHead,
    },
    /// A vault store whose head a device of a verified list signed, while an earlier entry
    /// of its history is by a key that no list verifies ([`SyncError::HistoryUnverified`]):
    /// the owner can take that head without its earlier history.
    WithoutHistory {
        joined: Arc<JoinedDevice>,
        head: DepartedHead,
        /// Its device as a sentence names it ([`DesktopApp::relay_signed_name`]).
        device: String,
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
    /// The copy of a vault store waits on a device that left the account
    /// ([`Departed::words`], [`Departed::use_label`]). No copy is on this Mac, so it cannot
    /// replace it.
    Departed {
        words: String,
        label: String,
    },
    /// The first download of a vault store: earlier versions of its copy were saved by
    /// devices that no list verifies; the owner can take the copy without them
    /// ([`WITHOUT_HISTORY`]).
    WithoutHistory {
        words: String,
    },
}

/// The head that a vault store waits on ([`SyncError::WaitsForAccountDevice`]), for the
/// steps of the owner: "Use the Copy That … Left…" and "Replace It with This Mac's Copy…".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Departed {
    pub(crate) head: DepartedHead,
    /// The signed name of the device, from the verified device list of the account (or of
    /// the other account of a shared vault); `None` when no verified list is in memory.
    pub(crate) name: Option<String>,
    /// The person of another account of a shared vault whose device it was, as its
    /// verified list names them; `None` for a device of this account.
    pub(crate) person: Option<String>,
}

impl Departed {
    /// The device and its key, by `departed_names` (this account) or `shared_devices`
    /// (the other accounts of the shared vaults).
    pub(crate) fn of(
        head: DepartedHead,
        departed_names: &BTreeMap<Vec<u8>, String>,
        shared_devices: &BTreeMap<Vec<u8>, (String, String)>,
    ) -> Self {
        match departed_names.get(&head.key) {
            Some(name) => Self {
                name: Some(name.clone()),
                person: None,
                head,
            },
            None => {
                let shared = shared_devices.get(&head.key).cloned();
                Self {
                    name: shared.as_ref().map(|(device, _)| device.clone()),
                    person: shared.map(|(_, person)| person),
                    head,
                }
            }
        }
    }

    /// The device at the start of a sentence.
    fn who(&self) -> String {
        match (&self.name, &self.person) {
            (Some(name), Some(person)) => format!("“{name}” of {person}"),
            (Some(name), None) => format!("“{name}”"),
            (None, _) => "A device that left the account".to_owned(),
        }
    }

    /// The device inside a sentence.
    fn who_in(&self) -> String {
        match (&self.name, &self.person) {
            (Some(name), Some(person)) => format!("“{name}” of {person}"),
            (Some(name), None) => format!("“{name}”"),
            (None, _) => "a device that left the account".to_owned(),
        }
    }

    /// The button that takes the copy.
    pub(crate) fn use_label(&self) -> String {
        match (&self.name, &self.person) {
            (Some(name), Some(person)) => format!("Use the Copy That “{name}” of {person} Left…"),
            (Some(name), None) => format!("Use the Copy That “{name}” Left…"),
            (None, _) => "Use the Copy That a Removed Device Left…".to_owned(),
        }
    }

    /// The line under the status: who saved the copy, and when (by its clock).
    pub(crate) fn words(&self) -> String {
        match &self.name {
            Some(_) if self.person.is_some() => format!(
                "{} saved the last copy {} and then stopped sharing this vault.",
                self.who(),
                ago(self.head.time)
            ),
            Some(_) => format!(
                "{} saved the last copy {} and then left the account.",
                self.who(),
                ago(self.head.time)
            ),
            None => format!(
                "{} saved the last copy {}.",
                self.who(),
                ago(self.head.time)
            ),
        }
    }
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
    /// "Relay with a team code" on the hosted relay (plan s7 unit S0): the team code
    /// field instead of a relay copy without a code.
    pub(crate) with_code: bool,
    /// The name of this Mac on the relay.
    pub(crate) device_input: String,
    /// The pasted link from the other Mac.
    pub(crate) link_input: String,
    /// The pasted node pairing link of "Your own node". Its team code works once: erased
    /// after each try, when its sheet closes, and at a lock.
    pub(crate) pair_input: String,
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
    /// The join runs from a vault store of the Connect account: its device stays in the
    /// store at a cancel or a failure (it is this Mac's account device, not a new one).
    store_join: bool,
    /// The source of "Use a vault from another Mac" that started the join: a join that
    /// holds the account key ends when the owner leaves that source.
    join_source: OpenSource,
    /// The vault stores of the account that this Mac can use and does not have, for "Use
    /// a vault from another Mac" › "Apassy Connect"; `None` until read.
    stores: Option<Result<Vec<crate::connect::VaultStoreView>, String>>,
    stores_task: Option<Task<Result<Vec<crate::connect::VaultStoreView>, String>>>,
    /// When the window last handed the account session to the relay syncs and the worker
    /// ([`DesktopApp::relay_connect_tick`]).
    connect_tick: Option<Instant>,
    /// The newest receipt of the current version by another Mac, by list ID.
    received: BTreeMap<String, Receipt>,
    /// When Settings last asked for the receipts, by list ID.
    receipts_read: BTreeMap<String, Instant>,
    /// The relay calls that run.
    jobs: Vec<Running>,
    /// The window, which a call wakes when it ends.
    repaint: Option<egui::Context>,
    /// "Send questions through the relay" in Settings > Devices.
    pub(crate) questions: super::questions::QuestionsUi,
    /// The text of the last move to Connect that did not finish, by list ID.
    move_error: BTreeMap<String, String>,
    /// The vault whose "Undo the move" waits for its owner check.
    undo: Option<String>,
    /// The vault whose step on the copy of a device that left waits for its owner check,
    /// with the exact action that the check names.
    departed_check: Option<(String, OwnerAction)>,
    /// The vault whose "Use the relay copy…" of a vault store of the Connect account waits
    /// for its owner check, with the exact action that the check names.
    use_copy_check: Option<(String, OwnerAction)>,
    /// "Use the Copy That … Left…" of a device that joins (the start screen) waits for its
    /// owner check: the exact action that the check names.
    join_departed_check: Option<OwnerAction>,
    /// The signed names of the devices that the verified device list of the account
    /// removed, by key, for the steps of a vault store that waits on one of them.
    departed_names: BTreeMap<Vec<u8>, String>,
    /// The devices of other accounts of the shared vaults by key (X9.63): the name that
    /// their verified lists signed, and the person (Settings › Connect › Shared Vaults
    /// sets it after each refresh).
    pub(crate) shared_devices: BTreeMap<Vec<u8>, (String, String)>,
    /// The same names, read by the worker of a join from a vault store while it holds the
    /// account (the window takes them when the join goes on).
    join_names: Arc<Mutex<RemovedNames>>,
    /// When the newest device list that verified was asked of Connect, as of the last
    /// hand-over to the relay syncs; `None` before one.
    listed: Option<Instant>,
}

impl RelayUi {
    /// The source that started a join that holds the account key of the Connect session:
    /// one that resolves a link for the account's origin, takes this device's own device
    /// in a vault store, or goes on from it. `None` without such a join.
    pub(crate) fn join_with_account(&self) -> Option<OpenSource> {
        let join = self.join.as_ref()?;
        let holds = match &join.phase {
            Phase::Resolving(_) | Phase::FromStore(_) => true,
            Phase::Downloading { .. }
            | Phase::Departed { .. }
            | Phase::WithoutHistory { .. }
            | Phase::Ready { .. }
            | Phase::Passphrase { .. }
            | Phase::Adopting(_)
            | Phase::Merging { .. } => self.store_join,
            Phase::Requesting(_) | Phase::Waiting { .. } => false,
        };
        holds.then_some(self.join_source)
    }

    /// Whether the sheet of "Add a device…" (any mode) is open for the vault `id`.
    pub(crate) fn add_open_for(&self, id: &str) -> bool {
        self.add.as_ref().is_some_and(|add| add.id == id)
    }

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
            Phase::Requesting(_) | Phase::Resolving(_) => JoinView::Sending,
            Phase::FromStore(_) => JoinView::Downloading {
                team: join.team.clone(),
            },
            Phase::Waiting { .. } => JoinView::Waiting {
                safety: join.safety.clone(),
            },
            Phase::Downloading { .. } => JoinView::Downloading {
                team: join.team.clone(),
            },
            Phase::Departed { head, .. } => {
                let departed =
                    Departed::of(head.clone(), &self.departed_names, &self.shared_devices);
                JoinView::Departed {
                    words: departed.words(),
                    label: departed.use_label(),
                }
            }
            Phase::WithoutHistory { head, device, .. } => JoinView::WithoutHistory {
                words: without_history_words(device, head),
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

/// The line of a first download whose earlier history does not verify: the head that the
/// owner can take, by its version, its device, and its time (by that device's clock).
pub(crate) fn without_history_words(device: &str, head: &DepartedHead) -> String {
    format!(
        concat!(
            "Version {version} of this copy was saved by {device} on {day}. Some earlier versions were saved by devices that this ",
            crate::computer!(),
            " cannot verify, for example of a person who reset their account. Apassy can take this copy without its earlier history; ask the person who shares the vault first if you are unsure."
        ),
        version = head.version,
        device = device,
        day = kit::day_month_year(head.time),
    )
}

/// The download of a copy of a vault store at a join, from `slot` (the account of the
/// session): a chain entry by a key that this device does not know yet makes it read the
/// lists of the other accounts once more (the refresh of Shared Vaults), hand their
/// signers to the device and note when they were asked, and download again. That second
/// download is decided: the copy, [`SyncError::HistoryUnverified`] (the owner's choice),
/// or a refusal. Without an answer of Connect it still checks the device list.
fn download_store_copy(
    device: &JoinedDevice,
    work: &std::path::Path,
    slot: &Mutex<Option<crate::connect::ConnectAccount>>,
) -> Result<RelayDownload, SyncError> {
    match device.download(work) {
        Err(SyncError::ChecksDeviceList) => {
            let listed = lock(slot).as_mut().and_then(|account| {
                let status = account.refresh_shares(&[]).ok()?;
                let shared = device.follows_shared_signers();
                let asked = join_lists_asked(&status, device.team_id(), shared)?;
                Some((crate::connect::signer_policy(account.state()), asked))
            });
            if let Some((policy, asked)) = listed {
                device.set_signers(Some(policy));
                device.note_device_list(asked);
            }
            device.download(work)
        }
        other => other,
    }
}

/// When the lists that decide the download of a join from the store `team` were asked in
/// the refresh `status`: for a store shared between accounts (`shared`, or a store that
/// the refresh lists) the lists of every account of the store and the own list
/// ([`crate::connect::ShareStatus::asked_for`]), `None` when one of them was not read or
/// did not verify, so the download keeps checking the device list; for a store of this
/// account alone the own list.
pub(crate) fn join_lists_asked(
    status: &crate::connect::ShareStatus,
    team: &str,
    shared: bool,
) -> Option<Instant> {
    if shared || status.stores.iter().any(|store| store.team_id == team) {
        status.asked_for(team)
    } else {
        status.own_read
    }
}

/// The signed names of removed devices, by key.
type RemovedNames = Vec<(Vec<u8>, String)>;

/// Keep the signed names of the devices that the verified device list of `account` removed
/// in `names`, for the window: a worker of a join from a vault store holds the account.
fn keep_removed_names(account: &crate::connect::ConnectAccount, names: &Mutex<RemovedNames>) {
    if let Some(list) = account.verified_list() {
        *lock(names) = list
            .removed
            .iter()
            .cloned()
            .zip(list.removed_names.iter().cloned())
            .collect();
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
    if matches!(
        problem(text),
        Some(SyncError::StaleCopy | SyncError::ForkedCopy | SyncError::UnknownSigner)
    ))
}

/// The relay problem of a status text ([`UiStatus::from_error`] keeps the text only).
fn problem(text: &str) -> Option<SyncError> {
    [
        SyncError::RelayUnreachable,
        SyncError::RelayBusy,
        SyncError::RemovedFromRelay,
        SyncError::StaleCopy,
        SyncError::ForkedCopy,
        SyncError::WaitsForAccountDevice,
        SyncError::ChecksDeviceList,
        SyncError::UnknownSigner,
        SyncError::Relay(RelayRefusal::RateLimited),
        SyncError::Relay(RelayRefusal::Busy),
        SyncError::Relay(RelayRefusal::TeamLimit),
    ]
    .into_iter()
    .find(|error| error.to_string() == text)
}

/// Whether `status` is a refusal of a head whose signer the policy does not hold: the
/// device list is checked ([`SyncError::ChecksDeviceList`]), or a fresh list still refused
/// it ([`SyncError::UnknownSigner`], or a damaged copy for the current head itself).
/// Shared Vaults keys its quiet time on it, with the head of `RelaySync::unlisted_head`.
pub(crate) fn is_unlisted_signer(status: &UiStatus) -> bool {
    matches!(status, UiStatus::Damaged)
        || matches!(status, UiStatus::Problem(text) if matches!(
            problem(text),
            Some(SyncError::ChecksDeviceList | SyncError::UnknownSigner)
        ))
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
            Some(SyncError::StaleCopy | SyncError::ForkedCopy | SyncError::UnknownSigner) => {
                ("Relay copy refused", Tone::Warning)
            }
            Some(SyncError::WaitsForAccountDevice) => ("Waiting for another device", Tone::Accent),
            Some(SyncError::ChecksDeviceList) => ("Checking the device list", Tone::Accent),
            Some(_) => ("Relay not reachable", Tone::Warning),
            None => ("Problem", Tone::Warning),
        },
        // Folder statuses; the relay has no file to wait for.
        UiStatus::Waiting | UiStatus::FolderUnavailable => ("Relay not reachable", Tone::Warning),
        UiStatus::Connect(state) => connect_tag(*state),
    }
}

/// The tag of a vault on the relay, or of a vault store of Apassy Connect (`connect`):
/// the same states, named after the place of the copy.
pub(crate) fn tag_of(status: &UiStatus, connect: bool) -> (&'static str, Tone) {
    let (tag, tone) = tag(status);
    if !connect {
        return (tag, tone);
    }
    let tag = match tag {
        "Saved to the relay" => "Saved to Apassy Connect",
        "Relay not reachable" => "Connect not reachable",
        "Removed from the relay" => "Removed from the store",
        "Relay copy refused" => "Copy at Connect refused",
        other => other,
    };
    (tag, tone)
}

/// The short tag of a vault store of Apassy Connect in a plan state (plan s7 unit M3).
pub(crate) fn connect_tag(state: ConnectState) -> (&'static str, Tone) {
    match state {
        ConnectState::PastDue { .. } => ("Connect: past due", Tone::Warning),
        ConnectState::ReadOnly { .. } => ("Connect: read-only", Tone::Warning),
        ConnectState::Suspended { .. } => ("Connect: suspended", Tone::Warning),
        ConnectState::SignedOut => ("Connect: signed out", Tone::Warning),
        ConnectState::HostedEnded(_) => ("Relay copy ended", Tone::Warning),
        ConnectState::StoreDeleted(_) => ("Copy at Connect deleted", Tone::Warning),
    }
}

/// The plan state of a vault store in a sentence: what works and what to do. No price
/// and no purchase words (plans section 5).
pub(crate) fn connect_words(state: ConnectState) -> String {
    use crate::desktop::ui::connect::day;
    match state {
        ConnectState::PastDue { grace_until, .. } => match grace_until {
            Some(until) => format!(
                "Connect: past due. Sync works until {}. Update the payment in Settings › Connect.",
                day(until)
            ),
            None => "Connect: past due. Update the payment in Settings › Connect.".to_owned(),
        },
        ConnectState::ReadOnly { until } => format!(
            "{}. Changes made here upload when the plan is active again.",
            match until {
                Some(until) => format!("Connect: read-only until {}", day(until)),
                None => "Connect: read-only".to_owned(),
            }
        ),
        ConnectState::Suspended { delete_at } => match delete_at {
            Some(at) => format!(
                "Connect: suspended. The copy at Connect is kept until {}.",
                day(at)
            ),
            None => "Connect: suspended. See Settings › Connect.".to_owned(),
        },
        ConnectState::SignedOut => {
            "Connect: signed out. Choose Sign In… in Settings › Connect.".to_owned()
        }
        ConnectState::HostedEnded(why) => crate::desktop::sync_worker::ended_copy_words(why),
        ConnectState::StoreDeleted(why) => {
            crate::desktop::sync_worker::deleted_copy_words(why).to_owned()
        }
    }
}

/// The status of a vault on the relay in a sentence (ADR 0022 section 5). `received` is
/// the newest receipt of the current version by another Mac.
pub(crate) fn words(status: &UiStatus, received: Option<&Receipt>) -> String {
    words_of(status, received, false)
}

/// [`words`] for a vault on the relay, or for a vault store of Apassy Connect
/// (`connect`), whose copy is at Apassy Connect.
pub(crate) fn words_of(status: &UiStatus, received: Option<&Receipt>, connect: bool) -> String {
    match status {
        UiStatus::UpToDate(at) => {
            let mut line = if connect {
                "Saved to Apassy Connect.".to_owned()
            } else {
                "Saved to the relay.".to_owned()
            };
            match (received, at) {
                (Some(receipt), _) => line.push_str(&format!(
                    " Received by {} {}.",
                    match receipt.device_name.trim() {
                        "" => concat!("another ", crate::computer!()),
                        name => name,
                    },
                    ago(receipt.at)
                )),
                (None, Some(at)) => line.push_str(&format!(" Last sync {}.", ago(*at))),
                (None, None) => {}
            }
            line
        }
        UiStatus::Syncing if connect => concat!("Saved on this ", crate::computer!(), ". A change waits for Apassy Connect.").to_owned(),
        UiStatus::Syncing => concat!("Saved on this ", crate::computer!(), ". A change waits for the relay.").to_owned(),
        UiStatus::NeedsPassphrase => {
            concat!("The passphrase changed on another ", crate::computer!(), ". Type the new passphrase.").to_owned()
        }
        UiStatus::Damaged if connect => {
            "The copy at Apassy Connect fails a check. Apassy did not use it, and does not download it again until it changes.".to_owned()
        }
        UiStatus::Damaged => {
            "The copy on the relay fails a check. Apassy did not use it, and does not download it again until it changes.".to_owned()
        }
        UiStatus::Problem(text)
            if connect && problem(text) == Some(SyncError::RelayUnreachable) =>
        {
            CONNECT_UNREACHABLE.to_owned()
        }
        // A vault store has no device link: never "join again with a link".
        UiStatus::Problem(text)
            if connect && problem(text) == Some(SyncError::RemovedFromRelay) =>
        {
            STORE_REFUSED_WORDS.to_owned()
        }
        UiStatus::Problem(text) => match problem(text) {
            Some(SyncError::Relay(RelayRefusal::RateLimited)) => {
                "The relay asks Apassy to wait a minute. Apassy syncs after that.".to_owned()
            }
            Some(SyncError::Relay(RelayRefusal::TeamLimit)) => {
                concat!("The relay limits the pushes of this vault for this hour. The changes stay on this ", crate::computer!(), " and sync later.").to_owned()
            }
            _ => sentence(text),
        },
        UiStatus::Waiting | UiStatus::FolderUnavailable if connect => {
            CONNECT_UNREACHABLE.to_owned()
        }
        UiStatus::Waiting | UiStatus::FolderUnavailable => {
            sentence(&SyncError::RelayUnreachable.to_string())
        }
        UiStatus::Connect(state) => connect_words(*state),
    }
}

/// The row of a vault whose vault store Apassy Connect deleted at a recovery: its line, and
/// [`SYNC_AGAIN`] when the vault is open and unlocked (`offer`). The line wraps, and the
/// button goes under it when the row is narrow ([`rows::text_buttons`]), so nothing of the
/// row passes the window at any width. Returns whether the owner pressed the button.
///
/// [`rows::text_buttons`]: super::super::settings::rows::text_buttons
pub(crate) fn deleted_store_row(ui: &mut egui::Ui, why: StoreDeleted, offer: bool) -> bool {
    use super::super::settings::rows;
    let line = crate::desktop::sync_worker::deleted_copy_words(why);
    let buttons: &[(&str, Style)] = if offer {
        &[(SYNC_AGAIN, Style::Prominent)]
    } else {
        &[]
    };
    rows::text_buttons(ui, rows::note(line), buttons).is_some()
}

/// The line of a vault store of Apassy Connect that cannot reach it.
pub(crate) const CONNECT_UNREACHABLE: &str =
    "Apassy Connect cannot be reached. Apassy syncs when it is back.";

/// The status of a vault whose relay copy needs its own passphrase, when this Mac has no
/// anchor ([`RelaySync::keeps_passphrase`]): the copy can be from before a passphrase
/// change.
pub(crate) const OLDER_COPY_WORDS: &str = "The copy on the relay uses another passphrase than this vault. It can be from before a passphrase change. Type the passphrase of that copy.";

/// The notice of ADR 0037 D14 for relay sync (plan s7 unit N1): under the relay row of
/// Settings > Vault > Sync while the vault syncs through the hosted relay. A relay that
/// the owner runs gets no notice. Relay sync is not the paid feature (plans section 5):
/// the hosted store becomes part of Apassy Connect, and an own node stays free.
pub(crate) fn relay_sync_notice(relay_url: &str) -> Option<String> {
    crate::relay::membership::on_hosted_relay(relay_url).then(|| {
        format!(
            concat!("Relay sync on apassy-relay.wyderka.cc is free until Apassy {}. Then the hosted store is part of Apassy Connect; your own ", crate::computer!(), " or Linux node can be the sync home (free)."),
            crate::relay::membership::FREE_RELAY_PATHS_END_VERSION
        )
    })
}

/// Whether "New relay copy" asks for a team code (plan s7 unit S0): on the hosted relay
/// (an empty address is the hosted one) only when the owner chose "Relay with a team
/// code"; on a relay that the owner runs always, since its operator decides whether
/// Connect teams get relay sync.
pub(crate) fn needs_team_code(url_input: &str, with_code: bool) -> bool {
    let url = match url_input.trim() {
        "" => DEFAULT_RELAY_URL,
        typed => typed,
    };
    with_code || !crate::relay::membership::on_hosted_relay(url)
}

/// The words of "New relay copy" without a team code (plans section 4.1): what Apassy
/// does, and that the free relay sync ends with Apassy Connect, by version (N1).
pub(crate) fn codeless_copy_words() -> String {
    format!(
        concat!(
            "No team code needed. Apassy makes a key for this ",
            crate::computer!(),
            ", keeps it in the vault, and uploads the encrypted copy. Relay sync is free until Apassy Connect starts with Apassy {}; then the hosted store is part of Apassy Connect, and your own ",
            crate::computer!(),
            " or Linux node can be the sync home (free)."
        ),
        crate::relay::membership::FREE_RELAY_PATHS_END_VERSION
    )
}

/// The relay address of the "Relay address" field: the hosted relay when it is empty.
/// A typed address has system trust; a node comes only from its pairing link.
fn typed_relay_url(typed: &str) -> Result<RelayUrl, String> {
    let text = match typed.trim() {
        "" => DEFAULT_RELAY_URL,
        typed => typed,
    };
    RelayUrl::parse(text).map_err(|error| sentence(&error.to_string()))
}

/// What "Your own node" says when the pasted text is a device link of another Mac, not
/// the pairing link of a node.
pub(crate) const NOT_A_PAIRING_LINK: &str = concat!(
    "This is a link from another ",
    crate::computer!(),
    ". Choose “Join from another ",
    crate::computer!(),
    "” and paste it there."
);
/// What "Join from another Mac" says for the pairing link of a node.
pub(crate) const A_PAIRING_LINK: &str =
    "This is the pairing link of a node. Choose “Your own node” and paste it there.";

/// The words of "Your own node" (plan S2–S3 unit L4): where the link comes from, and what
/// Apassy checks.
pub(crate) const NODE_SETUP_WORDS: &str = concat!(
    "Your own node keeps the encrypted copy of this vault on your Linux machine, over your tailnet. On the node, run “apassy pair” and paste the link that it prints. The link works once, for 10 minutes. Apassy connects only to the node whose certificate matches the link, makes a key for this ",
    crate::computer!(),
    ", and keeps it in the vault."
);

/// Why "Apassy Connect" is not offered or did not start: no signed-in account with a
/// plan that pushes. No price and no purchase words (plans section 5).
pub(crate) const CONNECT_NEEDS_PLAN: &str =
    "Apassy Connect needs a signed-in account with an active plan. See Settings › Connect.";

/// The words of the "Apassy Connect" choice (plan s7 unit M3).
/// The lead of the setup sheet on "Apassy Connect".
pub(crate) const CONNECT_SETUP_LEAD: &str =
    "Your Apassy Connect account keeps one encrypted copy of this vault.";
pub(crate) const CONNECT_SETUP_WORDS: &str =
    "Your other devices of the account turn it on the same way, without a link code.";

/// The relay row of a move that kept both copies.
pub(crate) const MOVE_BOTH_COPIES: &str =
    "Both copies are kept, and the vault still syncs with the relay. Try again, or undo the move.";

/// The relay row of a move whose old copy is deleted, while Connect did not turn on.
pub(crate) const MOVE_OLD_DELETED: &str =
    "The old copy is deleted, but sync with Apassy Connect is not on yet. Try again.";

/// The words of "Move the relay copy to Connect" before it runs.
pub(crate) const MOVE_WORDS: &str = "Apassy uploads this vault to Apassy Connect, then deletes the relay copy. If a step fails, both copies stay.";

/// "<names> got the vault on Apassy Connect too." for the devices that a Mac added.
fn registered_words(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => format!(" “{one}” of your account can turn it on without a link code."),
        many => format!(
            " {} of your account can turn it on without a link code.",
            many.iter()
                .map(|name| format!("“{name}”"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The text of a failed relay call of an owner action.
pub(super) fn call_error(error: SyncError) -> String {
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
        SyncError::Relay(RelayRefusal::JoinRefused) => concat!(
            "The other ",
            crate::computer!(),
            " refused, or the link expired. Make a new link on the other ",
            crate::computer!(),
            "."
        )
        .to_owned(),
        SyncError::Vault(VaultErrorKind::WrongKeyOrCorrupt) => concat!(
            "The passphrase does not open this vault. Nothing changed on this ",
            crate::computer!(),
            ". Type it again."
        )
        .to_owned(),
        SyncError::OtherVault => "The relay copy holds another vault. Nothing changed.".to_owned(),
        other => call_error(other),
    }
}

/// The text of a relay sync that did not turn on. `folder`: the vault syncs with a
/// folder, and that stays.
fn enable_error(error: SyncError, vault: &str, folder: bool, node: bool) -> String {
    let stays = if folder {
        "Folder sync stays on."
    } else {
        "Sync stays off."
    };
    match error {
        // A node: its pairing link, not an operator code (node-pairing-v1 section 6).
        SyncError::Relay(RelayRefusal::InviteInvalid) if node => format!(
            "The pairing link is wrong, used, or expired. Run “apassy pair” on the node for a new link. {stays}"
        ),
        SyncError::RelayUnreachable if node => format!(
            concat!(
                "Your node is not reachable. Check that it runs (“apassy status”) and that this ",
                crate::computer!(),
                " is on the same tailnet, then try again. {stays}"
            ),
            stays = stays
        ),
        SyncError::PinMismatch => format!("{PIN_CHANGED_TEXT} {stays}"),
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
    /// off: no "Sync now", "Add a device…", "Devices…", "Check again", or "Refresh".
    pub(crate) fn relay_removed(&self, id: &str) -> bool {
        lock(&self.sync.relay.cache)
            .get(id)
            .is_some_and(RelaySync::is_removed)
    }

    /// Why the vault store of the vault `id` is gone, when Apassy Connect deleted it at a
    /// recovery ([`RelaySync::store_deleted`], [`Self::relay_note_deleted_stores`]). Its row
    /// then offers only [`SYNC_AGAIN`].
    pub(crate) fn relay_store_deleted(&self, id: &str) -> Option<StoreDeleted> {
        lock(&self.sync.relay.cache)
            .get(id)
            .and_then(RelaySync::store_deleted)
    }

    /// Mark the relay sync of each vault of the list whose vault store Apassy Connect
    /// deleted at a recovery, from the account file and the sync state of the vault alone
    /// ([`crate::sync::store_deleted`]; no network, and no answer of Connect is waited
    /// for): it asks Connect nothing more, and says so once. Every other relay sync loses
    /// the mark. The statuses follow at once when a mark changed.
    pub(crate) fn relay_note_deleted_stores(&mut self) {
        let file = self.ui.connect.live.session().account_state();
        let ids: Vec<String> = self
            .vault_list
            .registry
            .entries()
            .iter()
            .filter(|entry| entry.sync_relay().is_some())
            .map(|entry| entry.id.clone())
            .collect();
        let mut changed = false;
        for id in ids {
            let Some(relay) = self.relay_of(&id) else {
                continue;
            };
            let deleted = file
                .as_ref()
                .zip(relay.state().ok().flatten())
                .and_then(|(file, state)| crate::sync::store_deleted(file, &state));
            if relay.store_deleted() != deleted {
                relay.set_store_deleted(deleted);
                changed = true;
            }
        }
        if changed {
            self.sync_refresh();
        }
    }

    /// [`SYNC_AGAIN`] for the open, unlocked vault `id` whose vault store was deleted at a
    /// recovery: the setup sheet on its "Apassy Connect" choice, whose "Turn on" is the step
    /// that turns on the sync through Apassy Connect with a new store
    /// ([`Self::relay_enable_connect`]; it drops the sync of the deleted store on this Mac
    /// first).
    pub(crate) fn relay_sync_again(&mut self, id: &str, ctx: Option<&egui::Context>) {
        if !self.relay_open(id) || self.relay_store_deleted(id).is_none() {
            return;
        }
        self.sync_open_sheet(SyncSheet::RelaySetup { id: id.to_owned() }, ctx);
        self.sync.relay.mode = SetupMode::Connect;
    }

    /// The relay sync of the listed vault `id`, when it syncs through the relay. Each
    /// call gives a clone of one value per vault and configuration. A link of a node
    /// keeps its pin and alternatives (`RelayConfig::for_link`); a stored pin that is not
    /// a pin gives no relay sync, never system trust.
    /// Whether the vault `id` syncs through a vault store of the Apassy Connect account
    /// (plan s7 unit M3), so the window names its sync "Apassy Connect": its link in the
    /// vault list says so, its relay sync signs with the account key, or Shared Vaults
    /// lists its team among the stores of the account.
    pub(crate) fn syncs_on_connect(&self, id: &str) -> bool {
        let Some(link) = self
            .vault_list
            .registry
            .get(id)
            .and_then(VaultEntry::sync_relay)
        else {
            return false;
        };
        link.connect || self.relay_shows_connect(id, &link.team_id)
    }

    /// What the relay sync of `id` and Shared Vaults show now, without the vault list.
    fn relay_shows_connect(&self, id: &str, team_id: &str) -> bool {
        lock(&self.sync.relay.cache)
            .get(id)
            .is_some_and(RelaySync::uses_account_key)
            || self.ui.connect.share.lists_store(team_id)
    }

    /// Keep in the vault list that the vault `id` syncs through Apassy Connect, once its
    /// relay sync or Shared Vaults shows it: the name stays after a restart, for a vault
    /// that is not open, and before the first sync.
    pub(crate) fn relay_note_connect(&mut self, id: &str) {
        let Some(team) = self
            .vault_list
            .registry
            .get(id)
            .and_then(VaultEntry::sync_relay)
            .filter(|link| !link.connect)
            .map(|link| link.team_id.clone())
        else {
            return;
        };
        if !self.relay_shows_connect(id, &team) {
            return;
        }
        if let Some(link) = self
            .vault_list
            .registry
            .entry_mut(id)
            .and_then(|entry| entry.sync.as_mut())
            .and_then(|link| link.relay.as_mut())
        {
            link.connect = true;
            self.save_vault_list();
        }
    }

    pub(crate) fn relay_of(&self, id: &str) -> Option<RelaySync> {
        let entry = self.vault_list.registry.get(id)?;
        let link = entry.sync_relay()?;
        let state = entry.sync_state()?;
        let config =
            RelayConfig::for_link(&self.vault_list.data_dir, &entry.path, link, state).ok()?;
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
        self.relay_undo_step();
        self.relay_departed_step();
        self.relay_use_copy_step();
        self.relay_connect_tick();
    }

    /// At most every [`CONNECT_TICK_EVERY`]: whatever account session the app has
    /// (`sync_account`, plan s7 unit M5; unit M5b opens it at the unlock) gives its key
    /// and its plan state to the relay sync of each vault, so the rows show the plan
    /// without a visit to Settings › Connect, and the worker gets the account for the
    /// registration of newer devices (`SyncWorker::set_account`). No network here.
    pub(crate) fn relay_connect_tick(&mut self) {
        if self
            .sync
            .relay
            .connect_tick
            .is_some_and(|at| at.elapsed() < CONNECT_TICK_EVERY)
        {
            return;
        }
        self.sync.relay.connect_tick = Some(Instant::now());
        // A vault store that Connect deleted at a recovery asks nothing more, before the
        // key of the account reaches its sync.
        self.relay_note_deleted_stores();
        // A sync of a vault store that was refused, or waits for another device of the
        // account, asks Connect for the account soon: a removal or a newer device reaches
        // the policy of the running sessions within a minute, not at the next refresh.
        let refused = self.sync.statuses.values().any(|status| {
            matches!(status, UiStatus::Damaged)
                || matches!(status, UiStatus::Problem(text) if matches!(
                    problem(text),
                    Some(
                        SyncError::WaitsForAccountDevice
                            | SyncError::RemovedFromRelay
                            | SyncError::ChecksDeviceList
                    )
                ))
        });
        if refused {
            self.ui.connect.live.refresh_soon();
        }
        let account = self.ui.connect.live.sync_account();
        if let Some(account) = &account {
            for relay in lock(&self.sync.relay.cache).values() {
                if let Some(signer) = &account.signer {
                    relay.set_account_signers(Some(account.signers.clone()));
                    relay.set_account_signer(Some(Arc::clone(signer)));
                }
                if let Some(plan) = account.plan {
                    relay.set_store_plan(Some(plan));
                }
            }
            self.relay_take_list(account);
        }
        self.sync
            .worker
            .set_account(account.map(|account| Arc::clone(&account.account)));
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
                        Ok(code) => {
                            add.channel = add.via.as_ref().and_then(|_| {
                                crate::relay::pairing::PairingChannel::generate(&code.link)
                            });
                            if add.via.is_some() && add.channel.is_none() {
                                add.error = Some(
                                    "Could not make a secure pairing code. Try again.".to_owned(),
                                );
                                return;
                            }
                            if let Some(channel) = &add.channel {
                                let shared = LinkCode {
                                    code: code.code.clone(),
                                    link: channel.link(&code.link),
                                    expires_at: code.expires_at,
                                };
                                add.qr = link_qr(&shared);
                            } else {
                                add.qr = link_qr(&code);
                            }
                            add.handoff = None;
                            add.code = Some(code);
                        }
                        Err(error) => add.error = Some(call_error(error)),
                    }
                }
            }
            Reply::Handoff { qid, result } => {
                if let Some(add) = self.sync.relay.add.as_mut().filter(|add| {
                    add.id == id
                        && add.handoff.is_some()
                        && add
                            .channel
                            .as_ref()
                            .is_some_and(|channel| channel.qid() == qid)
                }) {
                    match result {
                        Ok(()) => {
                            let text = match add.handoff.as_ref() {
                                Some((_, _, name, true)) => format!(
                                    "Connected. {} can now allow an access request once while it is unlocked on a wrist. It cannot approve runs or change access.",
                                    crate::questions::device_link::watch_label(name)
                                ),
                                Some((_, _, name, false)) => format!(
                                    "Connected. {name} can now show requests and answer with Face ID. Turn on request notifications on the iPhone for push alerts."
                                ),
                                None => "Connected. Your iPhone can now show requests and answer with Face ID. Turn on request notifications on the iPhone for push alerts.".to_owned(),
                            };
                            add.added = Some(text.clone());
                            add.handoff = None;
                            add.code = None;
                            add.qr = None;
                            add.channel = None;
                            add.error = None;
                            self.set_ok(text);
                        }
                        Err(error) => {
                            let device = if add.handoff.as_ref().is_some_and(|h| h.3) {
                                "Apple Watch"
                            } else {
                                "iPhone"
                            };
                            add.error = Some(format!(
                                "The {device} was confirmed, but its connection keys have not arrived. Keep this screen open and select Check again. {error}"
                            ))
                        }
                    }
                }
            }
            Reply::Links(result) => {
                if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                    add.next_poll = Instant::now() + POLL_EVERY;
                    match result {
                        Ok(mut links) => {
                            if let (Some(channel), Some(client)) = (&add.channel, &add.via) {
                                links.retain(|link| {
                                    channel
                                        .mac_safety(
                                            client.team_id(),
                                            &link.public_key,
                                            &link.device_name,
                                        )
                                        .is_some()
                                });
                            }
                            add.links = links;
                            add.error = None;
                        }
                        Err(error) => add.error = Some(call_error(error)),
                    }
                }
            }
            Reply::Confirmed { link, result } => self.relay_confirmed(id, &link, result),
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
                                    concat!(
                                        "Relay sync: {count} credential{} changed on this ",
                                        crate::computer!(),
                                        "."
                                    ),
                                    if count == 1 { "" } else { "s" },
                                    count = count,
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
                        matches!(
                            sheet,
                            SyncSheet::ReplaceDamaged { .. }
                                | SyncSheet::ReplaceDepartedCopy { .. }
                        )
                    });
                    self.set_ok(concat!(
                        "The relay has the vault of this ",
                        crate::computer!(),
                        " now. Your other ",
                        crate::computers!(),
                        " merge it at their next sync."
                    ));
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
                            concat!(
                                "Apassy merged the relay copy into “{name}”, which keeps the passphrase of this ",
                                crate::computer!(),
                                "."
                            ),
                            name = name
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
            Reply::UsedDeparted { name, result } => {
                self.relay_close_sheet(id, |sheet| {
                    matches!(sheet, SyncSheet::UseDepartedCopy { .. })
                });
                match result {
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
                        let device = name.map_or_else(
                            || "the device that left the account".to_owned(),
                            |name| format!("“{name}”"),
                        );
                        self.set_ok(format!(
                            "Apassy merged the copy that {device} left with this vault and uploaded the result. Relay sync goes on."
                        ));
                    }
                    Err(error) => {
                        // A copy that changed meanwhile: the row shows its new state.
                        if let Some(relay) = self.relay_of(id) {
                            self.sync_take_result(id, &VaultSync::Relay(relay), &Err(error));
                        }
                        if error != SyncError::Vault(VaultErrorKind::Locked) {
                            self.set_err(format!("Nothing changed: {error}."));
                        }
                    }
                }
            }
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
            Reply::Moved(moved) => {
                let Moved {
                    connect,
                    before,
                    result,
                } = *moved;
                self.relay_moved(id, connect, before, result);
            }
            Reply::Registered(names) => {
                if !names.is_empty() {
                    let vault = self
                        .vault_list
                        .registry
                        .get(id)
                        .map(|entry| entry.name.clone())
                        .unwrap_or_default();
                    self.set_ok(format!(
                        "“{vault}” is on Apassy Connect for your other devices too.{}",
                        registered_words(&names)
                    ));
                }
            }
            Reply::Undone(result) => match result {
                Ok(()) => {
                    self.sync.relay.move_error.remove(id);
                    self.set_ok(
                        "The copy on Apassy Connect is deleted. The vault syncs with the relay as before."
                            .to_owned(),
                    );
                }
                Err(text) => self.set_err(text),
            },
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
            refused,
        } = turned_on;
        let name = name.as_str();
        // A node: a pinned relay (node-pairing-v1), the owner's own.
        let node = relay.config().trust != TlsTrust::System;
        // A vault store of Apassy Connect: its session signs with the account key.
        let connect = relay.uses_account_key();
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
                    self.sync.relay.pair_input.zeroize();
                }
                self.relay_close_sheet(id, |sheet| matches!(sheet, SyncSheet::RelaySetup { .. }));
                self.set_ok(if typed {
                    format!(
                        concat!(
                            "“{name}” uses the passphrase of the relay copy now, as your other ",
                            crate::computers!(),
                            ", and merged with the copy. It syncs through the Apassy relay."
                        ),
                        name = name
                    )
                } else if connect && joined {
                    format!("“{name}” syncs through Apassy Connect and merged with the copy there.")
                } else if connect && report.outcome.merge.is_some() {
                    format!(
                        concat!(
                            "“{name}” syncs through Apassy Connect and merged with the copy of your other ",
                            crate::computer!(),
                            ". No link code was needed."
                        ),
                        name = name
                    )
                } else if connect {
                    format!(
                        "“{name}” syncs through Apassy Connect. Your other devices of the account get it in Settings › Vault › Sync › Apassy Connect, without a link code."
                    )
                } else if joined {
                    format!(
                        "“{name}” syncs through the Apassy relay and merged with the relay copy."
                    )
                } else if node {
                    format!(
                        concat!(
                            "“{name}” syncs through your own node. To add another ",
                            crate::computer!(),
                            " or an iPhone, select “Add a device…”."
                        ),
                        name = name
                    )
                } else {
                    format!(
                        concat!(
                            "“{name}” syncs through the Apassy relay. To add another ",
                            crate::computer!(),
                            " or an iPhone, select “Add a device…”."
                        ),
                        name = name
                    )
                });
            }
            Err(error) => {
                let stays = if before.is_some() {
                    "Folder sync stays on."
                } else {
                    "Sync stays off."
                };
                let text = match refused {
                    Some(refused) => format!("{refused} {stays}"),
                    None => format!(
                        "{}{took}",
                        enable_error(error, name, before.is_some(), node)
                    ),
                };
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
                relay.with_code = false;
                relay.join_error = None;
                self.relay_fill_fields();
            }
            SyncSheet::AddMac { .. } | SyncSheet::AddIphone { .. } => relay.add = None,
            SyncSheet::Devices { .. } => relay.devices = None,
            SyncSheet::QuestionsTeam { .. } => {
                relay.questions.error = None;
                self.relay_fill_fields();
                if let Some(Some(pending)) = self
                    .owner_ui
                    .session
                    .with_vault(|vault| vault.pending_connect().ok().flatten())
                {
                    self.sync.relay.url_input = pending.relay_url;
                    self.sync.relay.device_input = pending.device_name;
                }
            }
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

    /// Erase the team code and a pasted link, and drop the link of "Add a device…". A Mac
    /// that joins for a vault of this list stops.
    pub(crate) fn relay_forget_codes(&mut self) {
        let relay = &mut self.sync.relay;
        relay.team_code.zeroize();
        relay.link_input.zeroize();
        relay.pair_input.zeroize();
        relay.join_key = None;
        // A lock ends the calls of "Add an iPhone…" at once.
        if let Some(client) = relay.add.take().and_then(|add| add.via) {
            client.close();
        }
        relay.questions.forget_codes();
        if relay
            .join
            .as_ref()
            .is_some_and(|join| join.target.is_some())
        {
            self.relay_join_cancel();
        }
    }

    /// A relay sheet closed: "Add a device…" refuses the Macs that wait for its link
    /// (contract section 7.1 step 4), and a join for a vault of this list stops.
    pub(crate) fn relay_sheet_closed(&mut self) {
        // A move before its join stops; an ended move's sheet is seen.
        if let Some(id) = self.sync.relay.add.as_ref().map(|add| add.id.clone()) {
            self.questions_cancel_move(&id);
        }
        self.questions_move_seen(false);
        if let Some(add) = self.sync.relay.add.take() {
            let waiting: Vec<u64> = add
                .links
                .iter()
                .filter(|link| link.safety.is_some())
                .map(|link| link.id)
                .collect();
            if let Some(client) = add.via {
                if !waiting.is_empty() {
                    self.relay_spawn(&add.id, Job::Refuse, move || {
                        for link in waiting {
                            let _ = client.refuse_link(link);
                        }
                        Reply::Nothing
                    });
                }
            } else if !waiting.is_empty()
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
        let url = typed_relay_url(url)?;
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
                refused: None,
            }))
        });
        Ok(())
    }

    /// Turn on relay sync for the open, unlocked vault `id` on the owner's own node ("Your
    /// own node", plan S2–S3 unit L4): `link` is the node pairing link of `apassy pair`
    /// (node-pairing-v1, `/pair#`). Its origin is the relay address, its pin and
    /// alternatives the only trust of the new team, and its one-use team code of kind
    /// `node` makes the team (`POST /v1/teams`, after the pin check). The sync link of the
    /// vault list and the membership keep the pin. A link that the grammar refuses, or a
    /// device link, comes back at once and makes no request; as [`Self::relay_enable_new`]
    /// otherwise.
    pub(crate) fn relay_enable_node(
        &mut self,
        id: &str,
        link: &str,
        device: &str,
    ) -> Result<(), String> {
        let entry = self.relay_target(id)?;
        let paired = PairedLink::parse(link).map_err(|refusal| refusal.message().to_owned())?;
        if paired.kind != LinkKind::Pair {
            return Err(NOT_A_PAIRING_LINK.to_owned());
        }
        let url = paired.url().map_err(|error| sentence(&error.to_string()))?;
        if url.pin().is_none() {
            // The grammar gives a pair link a pin always; never a node without one.
            return Err(crate::sync::LINK_INVALID_TEXT.to_owned());
        }
        let team_code = paired.code;
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
                refused: None,
            }))
        });
        Ok(())
    }

    /// Turn on relay sync for the open, unlocked vault `id` without a team code (plans
    /// section 4.1): `RelaySync::create_team_codeless` on its own thread, which takes the
    /// vault's Connect team (its questions team, or a new one with the purpose `sync`)
    /// and pushes version 1. As [`Self::relay_enable_new`] otherwise.
    pub(crate) fn relay_enable_codeless(
        &mut self,
        id: &str,
        url: &str,
        device: &str,
    ) -> Result<(), String> {
        let entry = self.relay_target(id)?;
        let url = typed_relay_url(url)?;
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
            use crate::relay::connect::ConnectError;
            let (result, refused) =
                match relay.create_team_codeless_shared(&slot, same_file(&relay), &name, &device) {
                    Ok(report) => (Ok(report), None),
                    Err(ConnectError::Sync(error)) => (Err(error), None),
                    Err(other) => (
                        Err(SyncError::Relay(RelayRefusal::Error)),
                        Some(other.to_string()),
                    ),
                };
            Reply::TurnedOn(Box::new(TurnedOn {
                relay: job,
                name,
                joined: false,
                before,
                result,
                device: None,
                typed: false,
                rekeyed: false,
                refused,
            }))
        });
        Ok(())
    }

    /// Turn on the sync of the open, unlocked vault `id` through Apassy Connect with the
    /// account of this Mac (plan s7 unit M3): `RelaySync::enable_on_connect_shared` on
    /// its own thread makes the vault store (or takes the store of this vault), pushes
    /// version 1 or merges the copy of another Mac of the account, and registers the
    /// other devices of the account. As [`Self::relay_enable_new`] otherwise.
    pub(crate) fn relay_enable_connect(&mut self, id: &str) -> Result<(), String> {
        let entry = self.relay_target(id)?;
        let account = self
            .ui
            .connect
            .live
            .sync_account()
            .filter(|account| account.plan.is_some_and(StorePlan::entitled))
            .ok_or_else(|| CONNECT_NEEDS_PLAN.to_owned())?;
        let url = RelayUrl::parse(&account.origin).map_err(|error| sentence(&error.to_string()))?;
        if self.relay_changing(id) {
            return Ok(());
        }
        // The vault store of this vault was deleted at a recovery ("Sync Through Apassy
        // Connect Again…"): its sync goes on this Mac first (no network), so the new store
        // is the only sync of the vault.
        let entry = if self.relay_store_deleted(id).is_some() {
            self.sync_disable(id);
            self.relay_target(id)?
        } else {
            entry
        };
        let relay = self.relay_staged(&entry, &url);
        let before = entry.sync.clone();
        let slot = self.relay_slot();
        let name = entry.name;
        let job = relay.clone();
        self.relay_spawn_with(id, Job::TurnOn, Some(relay.clone()), move || {
            let mut guard = lock(&account.account);
            let (result, refused) = match guard.as_mut() {
                None => (
                    Err(SyncError::Relay(RelayRefusal::Error)),
                    Some(crate::connect::ConnectError::SignedOut.to_string()),
                ),
                Some(account) => {
                    match relay.enable_on_connect_shared(&slot, same_file(&relay), account, &name) {
                        Ok(report) => (Ok(report.enable), None),
                        Err(crate::sync::StoreError::Sync(error)) => (Err(error), None),
                        Err(other) => (
                            Err(SyncError::Relay(RelayRefusal::Error)),
                            Some(other.to_string()),
                        ),
                    }
                }
            };
            drop(guard);
            Reply::TurnedOn(Box::new(TurnedOn {
                relay: job,
                name,
                joined: false,
                before,
                result,
                device: None,
                typed: false,
                rekeyed: false,
                refused,
            }))
        });
        Ok(())
    }

    /// Whether this Mac can sync through Apassy Connect now: an account that is signed
    /// in, with a plan that pushes.
    pub(crate) fn connect_sync_available(&self) -> bool {
        self.ui
            .connect
            .live
            .sync_account()
            .is_some_and(|account| account.plan.is_some_and(StorePlan::entitled))
    }

    /// Whether "Move the relay copy to Connect" fits the vault `id`: it syncs through the
    /// hosted relay with a key of its own, and this Mac can sync through Connect.
    pub(crate) fn relay_can_move(&self, id: &str) -> bool {
        let hosted = self
            .relay_of(id)
            .and_then(|relay| relay.state().ok().flatten())
            .and_then(|state| state.relay_url)
            .is_some_and(|url| crate::relay::membership::on_hosted_relay(&url));
        hosted
            && self.connect_sync_available()
            && self
                .relay_of(id)
                .is_some_and(|relay| !relay.uses_account_key())
    }

    /// The move of the vault `id` that did not finish: its step and the text of its
    /// failure, for the relay row.
    pub(crate) fn relay_move_state(&self, id: &str) -> Option<(crate::sync::MoveStep, String)> {
        let relay = self.relay_of(id).or_else(|| self.relay_old_of(id))?;
        let record = relay.pending_move()?;
        let text = self
            .sync
            .relay
            .move_error
            .get(id)
            .cloned()
            .unwrap_or_else(|| match record.step {
                crate::sync::MoveStep::Pushed => MOVE_BOTH_COPIES.to_owned(),
                crate::sync::MoveStep::OldDeleted => MOVE_OLD_DELETED.to_owned(),
            });
        Some((record.step, text))
    }

    /// The relay sync of the vault `id` under its own state name, also when the vault
    /// list no longer names a relay (a move after its old copy went).
    fn relay_old_of(&self, id: &str) -> Option<RelaySync> {
        let entry = self.vault_list.registry.get(id)?;
        Some(RelaySync::new(RelayConfig::in_data_dir(
            &self.vault_list.data_dir,
            &entry.path,
            DEFAULT_RELAY_URL,
            &entry.id,
        )))
    }

    /// "Move the relay copy to Connect" for the open, unlocked vault `id` (plan s7 unit
    /// M3): `RelaySync::move_to_connect_shared` on its own thread pushes to Connect first
    /// and deletes the old copy second. The same call goes on after a failure.
    pub(crate) fn relay_move_to_connect(&mut self, id: &str) -> Result<(), String> {
        let entry = self.relay_target(id)?;
        let account = self
            .ui
            .connect
            .live
            .sync_account()
            .filter(|account| account.plan.is_some_and(StorePlan::entitled))
            .ok_or_else(|| CONNECT_NEEDS_PLAN.to_owned())?;
        let url = RelayUrl::parse(&account.origin).map_err(|error| sentence(&error.to_string()))?;
        if self.relay_changing(id) {
            return Ok(());
        }
        let old = self
            .relay_of(id)
            .or_else(|| self.relay_old_of(id))
            .ok_or_else(|| "This vault has no relay copy to move.".to_owned())?;
        let connect = self.relay_staged(&entry, &url);
        let before = entry.sync.clone();
        let slot = self.relay_slot();
        let name = entry.name;
        let job = connect.clone();
        self.sync.relay.move_error.remove(id);
        self.relay_spawn_with(id, Job::Move, Some(old.clone()), move || {
            let mut guard = lock(&account.account);
            let result = match guard.as_mut() {
                None => Err(crate::sync::MoveFailure {
                    step: old.pending_move().map(|record| record.step),
                    error: crate::sync::StoreError::Connect(
                        crate::connect::ConnectError::SignedOut,
                    ),
                }),
                Some(account) => {
                    old.move_to_connect_shared(&connect, &slot, same_file(&old), account, &name)
                }
            };
            drop(guard);
            Reply::Moved(Box::new(Moved {
                connect: job,
                before,
                result,
            }))
        });
        Ok(())
    }

    /// The answer of "Move the relay copy to Connect".
    fn relay_moved(
        &mut self,
        id: &str,
        connect: RelaySync,
        before: Option<SyncLink>,
        result: Result<crate::sync::ConnectEnableReport, crate::sync::MoveFailure>,
    ) {
        let name = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        match result {
            Ok(report) => {
                self.sync.relay.move_error.remove(id);
                // The old sync is off here; the vault list still names the old relay.
                let relay = match self.relay_take_staged(id, &connect, before) {
                    Ok(relay) => relay,
                    Err(text) => {
                        self.set_err(text);
                        return;
                    }
                };
                self.relay_linked(id, relay, report.enable.link, &report.enable.outcome);
                self.set_ok(format!(
                    "“{name}” syncs through Apassy Connect now. The copy on apassy-relay.wyderka.cc is deleted.{}",
                    registered_words(&report.registered)
                ));
            }
            Err(failure) => {
                if failure.step == Some(crate::sync::MoveStep::OldDeleted) {
                    // The old sync is off: the vault list no longer names the old relay.
                    if let Some(listed) = self.vault_list.registry.entry_mut(id) {
                        listed.sync = None;
                    }
                    lock(&self.sync.relay.cache).remove(id);
                    self.save_vault_list();
                    self.sync_track_open_vault();
                    self.sync_refresh();
                }
                let _ = connect.disable(None);
                let text = failure.to_string();
                self.sync
                    .relay
                    .move_error
                    .insert(id.to_owned(), text.clone());
                self.set_err(text);
            }
        }
    }

    /// "Undo the move": the owner check for the deletion of the Connect copy first.
    pub(crate) fn relay_ask_undo_move(&mut self, id: &str, ctx: Option<&egui::Context>) {
        let Some(old) = self.relay_of(id).or_else(|| self.relay_old_of(id)) else {
            return;
        };
        let Some(record) = old
            .pending_move()
            .filter(|record| record.step == crate::sync::MoveStep::Pushed)
        else {
            return;
        };
        let vault_name = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        self.sync.relay.undo = Some(id.to_owned());
        self.ask_owner(
            OwnerRequest::DeleteVaultStore {
                team_id: record.team_id,
                vault_name,
            },
            ctx,
        );
    }

    /// The undo of a move after its owner check: the proof of the check, once.
    fn relay_undo_step(&mut self) {
        let Some(id) = self.sync.relay.undo.clone() else {
            return;
        };
        if self.ui.connect.live.guarded.is_some() {
            return;
        }
        let Some(proof) = self.owner.take_connect_proof() else {
            if self.owner.check.is_none() {
                self.sync.relay.undo = None;
            }
            return;
        };
        self.sync.relay.undo = None;
        let (Some(epoch), Some(old), Some(account)) = (
            self.owner_ui.session.epoch(),
            self.relay_of(&id).or_else(|| self.relay_old_of(&id)),
            self.ui.connect.live.sync_account(),
        ) else {
            self.set_err(CONNECT_NEEDS_PLAN.to_owned());
            return;
        };
        self.relay_spawn_with(&id, Job::UndoMove, None, move || {
            let mut guard = lock(&account.account);
            let result = match guard.as_mut() {
                None => Err(crate::connect::ConnectError::SignedOut.to_string()),
                Some(account) => old
                    .undo_move(account, proof, &epoch)
                    .map_err(|error| error.to_string()),
            };
            Reply::Undone(result)
        });
    }

    /// The account key, the signers of the vault stores, and the plan state go to the
    /// relay sync of each vault, and the sessions that run take the signers at their next
    /// check of a head. Nothing else: no registration of devices. Returns the account of
    /// the session.
    pub(crate) fn relay_hand_over_signers(
        &mut self,
    ) -> Option<crate::desktop::ui::connect::live::SyncAccount> {
        let account = self.ui.connect.live.sync_account()?;
        for relay in lock(&self.sync.relay.cache).values() {
            if let Some(signer) = &account.signer {
                relay.set_account_signers(Some(account.signers.clone()));
                relay.set_account_signer(Some(Arc::clone(signer)));
            }
            if let Some(plan) = account.plan {
                relay.set_store_plan(Some(plan));
            }
        }
        // A copy of a vault store that downloads follows the same signers.
        if let Some(joined) = self.sync.relay.join.as_ref().and_then(Join::joined)
            && account.signer.is_some()
        {
            joined.set_signers(Some(account.signers.clone()));
        }
        self.relay_take_list(&account);
        Some(account)
    }

    /// The account key and the plan state of this Mac's Connect account go to the relay
    /// sync of each vault (plan s7 unit M3): a vault store signs with that key and shows
    /// the plan state. Settings › Connect calls it after each refresh.
    pub(crate) fn relay_share_connect(&mut self) {
        let Some(account) = self.relay_hand_over_signers() else {
            return;
        };
        // The open vault store takes the newer devices of the account (connect-account-v1
        // section 8); no owner check, as at its start (`register_own_store_device`).
        if let Some(id) = self.current_vault().map(|entry| entry.id.clone())
            && let Some(relay) = self.relay_of(&id).filter(RelaySync::uses_account_key)
            && !self.relay_busy(&id, Job::Register)
        {
            let slot = Arc::clone(&account.account);
            self.relay_spawn_with(&id, Job::Register, None, move || {
                let mut guard = lock(&slot);
                let names = guard
                    .as_mut()
                    .and_then(|account| relay.register_account_devices(account).ok())
                    .unwrap_or_default();
                Reply::Registered(names)
            });
        }
        // A vault store that waited for the account syncs now.
        if let Some(id) = self.current_vault().map(|entry| entry.id.clone())
            && matches!(
                self.sync.statuses.get(&id),
                Some(UiStatus::Connect(ConnectState::SignedOut))
            )
            && account.signer.is_some()
        {
            self.relay_sync_now(&id);
        }
    }

    /// The relay sync of the vault `entry` that turns on, with its state under a name of
    /// its own ([`STAGED`]) until the relay answered. A state of an earlier try goes. The
    /// trust of `url` goes with it: a node (a pinned origin, node-pairing-v1) connects
    /// only with its pin and alternatives, a hosted relay with system trust.
    fn relay_staged(&self, entry: &VaultEntry, url: &RelayUrl) -> RelaySync {
        let relay = RelaySync::new(
            RelayConfig::in_data_dir(
                &self.vault_list.data_dir,
                &entry.path,
                url.as_str(),
                &format!("{}{STAGED}", entry.id),
            )
            .with_url_trust(url),
        );
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
                concat!(
                    "Relay sync of “{}” did not turn on: its sync setting changed in the meantime. The relay team stays; remove this ",
                    crate::computer!(),
                    " in “Devices…” on another ",
                    crate::computer!(),
                    ", or ask the operator of the relay."
                ),
                entry.name
            ));
        }
        if entry.sync.is_some() {
            self.sync_disable(id);
        }
        // The trust of the staged relay (a pinned node) goes with it.
        let relay = RelaySync::new(
            RelayConfig::in_data_dir(
                &self.vault_list.data_dir,
                &entry.path,
                &staged.config().url,
                &entry.id,
            )
            .with_trust(staged.config().trust, &staged.config().alt),
        );
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
        let mut link = link;
        link.connect = relay.uses_account_key();
        if let Some(listed) = self.vault_list.registry.entry_mut(id) {
            listed.sync = Some(SyncLink::relay(id, link));
        }
        lock(&self.sync.relay.cache).insert(id.to_owned(), relay);
        self.save_vault_list();
        self.relay_share_connect();
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
        // The address of the confirmed device, with the pin of a pinned link.
        let relay = self.relay_staged(&entry, joined.member().url());
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
                refused: None,
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
                format!(
                    concat!(
                        "{off} The copy on the relay is deleted. The vault on this ",
                        crate::computer!(),
                        " stays."
                    ),
                    off = off
                )
            }
            Left::Removed => format!("{off} The copy on the relay stays."),
            Left::Gone => format!(
                concat!(
                    "{off} The copy on the relay stays. This ",
                    crate::computer!(),
                    " was no longer in the relay team. If the relay was paused and this ",
                    crate::computer!(),
                    " still shows in “Devices…” on another ",
                    crate::computer!(),
                    ", remove it there."
                ),
                off = off
            ),
            Left::LastMac => format!(
                concat!(
                    "{off} The copy on the relay stays. This ",
                    crate::computer!(),
                    " was the last ",
                    crate::computer!(),
                    " of the relay team, so only the operator of the relay can delete the copy now."
                ),
                off = off
            ),
            Left::Kept(reason) => format!(
                concat!(
                    "{off} The copy on the relay stays. This ",
                    crate::computer!(),
                    " is still in the relay team ({reason}): remove it in “Devices…” on another ",
                    crate::computer!(),
                    "."
                ),
                off = off,
                reason = reason
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
        // A vault store that Connect deleted at a recovery is asked nothing.
        if self.relay_busy(id, Job::SyncNow)
            || !self.relay_open(id)
            || self.relay_store_deleted(id).is_some()
        {
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
                sync: Box::new(VaultSync::Relay(relay)),
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

    /// The device list of the account session reached the relay syncs (after their
    /// policy): keep the signed names of the removed devices; and tell each relay sync
    /// when the newest list that verified was asked ([`RelaySync::note_device_list`]): it
    /// ends the check of a head refused before that time. When that list is newer than at
    /// the last hand-over, check again a vault store that waits for it. A refresh whose
    /// list did not verify, and the end of any other step, change nothing here.
    fn relay_take_list(&mut self, account: &crate::desktop::ui::connect::live::SyncAccount) {
        for (key, name) in &account.removed_names {
            self.sync
                .relay
                .departed_names
                .insert(key.clone(), name.clone());
        }
        let Some(asked) = account.verified_at else {
            return;
        };
        let ids: Vec<String> = lock(&self.sync.relay.cache).keys().cloned().collect();
        for id in ids {
            // A store shared between accounts: Shared Vaults reads the lists of the other
            // accounts too, and notes them after the quiet time of the head
            // (`connect::share`).
            if self.share_reads_lists(&id) {
                continue;
            }
            if let Some(relay) = self.relay_of(&id) {
                relay.note_device_list(asked);
            }
        }
        if self.sync.relay.listed.replace(asked) == Some(asked) {
            return;
        }
        let checking: Vec<String> = self
            .sync
            .statuses
            .iter()
            .filter(|(_, status)| {
                matches!(status, UiStatus::Problem(text)
                    if problem(text) == Some(SyncError::ChecksDeviceList))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in checking {
            self.relay_sync_now(&id);
        }
    }

    /// Whether the vault store `id` has checked the device list for at least
    /// [`CHECK_LIST_LONG`]: its line then says that Connect cannot be reached to check it.
    pub(crate) fn relay_checks_list_long(&self, id: &str) -> bool {
        let checking = matches!(self.sync.statuses.get(id), Some(UiStatus::Problem(text))
            if problem(text) == Some(SyncError::ChecksDeviceList));
        checking
            && self
                .relay_of(id)
                .and_then(|relay| relay.checking_since())
                .is_some_and(|since| since.elapsed() >= CHECK_LIST_LONG)
    }

    /// "Try Again" of a vault store that checks the device list: ask Connect for the
    /// account now, and sync the store again; the check goes on until a verified list
    /// that was asked after the refusal decides it.
    pub(crate) fn relay_check_list_again(&mut self, id: &str) {
        self.ui.connect.live.refresh_now();
        // A store shared between accounts: Shared Vaults reads the other accounts' lists.
        if self.share_reads_lists(id) {
            self.ui.connect.share.check_again();
        }
        self.relay_sync_now(id);
    }

    /// The head that the vault store `id` waits on, with the signed name of its device,
    /// while its status is "Waiting for another device".
    pub(crate) fn relay_departed(&self, id: &str) -> Option<Departed> {
        let waiting = matches!(self.sync.statuses.get(id), Some(UiStatus::Problem(text))
            if problem(text) == Some(SyncError::WaitsForAccountDevice));
        if !waiting {
            return None;
        }
        let head = self.relay_of(id)?.waiting_head()?;
        Some(Departed::of(
            head,
            &self.sync.relay.departed_names,
            &self.sync.relay.shared_devices,
        ))
    }

    /// "Use This Copy" or "Replace" of the copy that a device that left pushed to the
    /// vault store `id`: a fresh owner check first, for exactly the head that the store
    /// waits on and the choice ([`OwnerAction::TakeDepartedCopy`]).
    pub(crate) fn relay_ask_departed(
        &mut self,
        id: &str,
        replace: bool,
        ctx: Option<&egui::Context>,
    ) {
        let Some(departed) = self.relay_departed(id) else {
            self.set_err("The copy on the relay changed. Nothing changed.");
            return;
        };
        let Some(team_id) = self
            .relay_of(id)
            .and_then(|relay| relay.state().ok().flatten())
            .and_then(|state| state.team_id)
        else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        let vault_name = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        let request = OwnerRequest::TakeDepartedCopy {
            team_id,
            version: departed.head.version,
            head: departed.head.head_hash.clone(),
            replace,
            device_name: departed.who_in(),
            vault_name,
            start: false,
        };
        self.sync.relay.departed_check = Some((id.to_owned(), request.action()));
        self.ask_owner(request, ctx);
    }

    /// The step on the copy of a device that left, after its owner check: the proof must
    /// name exactly the head that the store still waits on, in this vault session; then
    /// the copy is taken or replaced.
    fn relay_departed_step(&mut self) {
        let Some((id, action)) = self.sync.relay.departed_check.clone() else {
            return;
        };
        if self.ui.connect.live.guarded.is_some() || self.sync.relay.undo.is_some() {
            return;
        }
        let Some(proof) = self.owner.take_connect_proof() else {
            if self.owner.check.is_none() {
                self.sync.relay.departed_check = None;
            }
            return;
        };
        self.sync.relay.departed_check = None;
        let Some(epoch) = self.owner_ui.session.epoch() else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        if let Err(refusal) = proof.check(&action, &epoch) {
            self.set_err(refusal.message());
            return;
        }
        drop(proof);
        let OwnerAction::TakeDepartedCopy {
            version,
            head,
            replace,
            ..
        } = action
        else {
            return;
        };
        let Some(approved) = self
            .relay_departed(&id)
            .map(|departed| departed.head)
            .filter(|waiting| waiting.version == version && waiting.head_hash == head)
        else {
            self.set_err("The copy on the relay changed. Nothing changed.");
            return;
        };
        if replace {
            self.relay_replace(&id);
        } else {
            self.relay_use_departed(&id, &approved);
        }
    }

    /// "Use the Copy That … Left…" for the open vault `id`: `approved`, the head that the
    /// owner check named, merges into the vault once, and the vault goes up over it. The
    /// store must still wait on exactly that head; another one is refused and nothing
    /// changes. The relay copy is checked again first. On its own thread.
    pub(crate) fn relay_use_departed(&mut self, id: &str, approved: &DepartedHead) {
        if self.relay_busy(id, Job::UseDeparted) {
            return;
        }
        let Some(departed) = self
            .relay_departed(id)
            .filter(|departed| departed.head == *approved)
        else {
            self.set_err("The copy on the relay changed. Nothing changed.");
            return;
        };
        let Some(relay) = self.relay_of(id).filter(|_| self.relay_open(id)) else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        let slot = self.relay_slot();
        self.relay_spawn_with(id, Job::UseDeparted, Some(relay.clone()), move || {
            Reply::UsedDeparted {
                name: departed.name.clone(),
                result: relay.use_departed_copy_shared(&slot, same_file(&relay), &departed.head),
            }
        });
    }

    /// "Use the relay copy" for the open vault `id` after this Mac refused the relay
    /// copy: the copy as it is now merges into the vault, and the vault goes up. On its
    /// own thread. A vault store of the Connect account takes this step only after an
    /// owner check that names the copy ([`Self::relay_ask_use_copy`]).
    pub(crate) fn relay_use_copy(&mut self, id: &str) {
        if self.relay_busy(id, Job::UseCopy) {
            return;
        }
        let Some(relay) = self.relay_of(id).filter(|_| self.relay_open(id)) else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        if relay.uses_account_key() {
            self.set_err("Confirm which copy to use first. Nothing changed.");
            return;
        }
        let slot = self.relay_slot();
        self.relay_spawn_with(id, Job::UseCopy, Some(relay.clone()), move || {
            Reply::UsedCopy(relay.use_relay_copy_shared(&slot, same_file(&relay)))
        });
    }

    /// The device of `key` as a sentence names it, by its signed name: “name” for a device of
    /// the account (one that the verified device list removed, or a device of that list),
    /// “name” of <person> for a device of another account of a shared vault, by that
    /// account's verified list.
    fn relay_signed_name(&self, key: &[u8]) -> Option<String> {
        if let Some(name) = self.sync.relay.departed_names.get(key) {
            return Some(format!("“{name}”"));
        }
        let own = self
            .ui
            .connect
            .live
            .session()
            .slot()
            .try_lock()
            .ok()
            .and_then(|guard| {
                guard
                    .as_ref()?
                    .verified_list()?
                    .name_of(key)
                    .map(|name| format!("“{name}”"))
            });
        own.or_else(|| {
            let (device, person) = self.sync.relay.shared_devices.get(key)?;
            Some(format!("“{device}” of {person}"))
        })
    }

    /// The copy that "Use the relay copy…" of the vault store of `id` takes: the current
    /// head that the relay served at the last check, and its device as a sentence names it
    /// ([`Self::relay_signed_name`]).
    pub(crate) fn relay_served_copy(&self, id: &str) -> Option<(DepartedHead, Option<String>)> {
        let head = self.relay_of(id)?.served_head()?;
        let name = self.relay_signed_name(&head.key);
        Some((head, name))
    }

    /// "Use the relay copy…" of a vault store of the Connect account: a fresh owner check
    /// first, for exactly the current head that the relay served
    /// ([`OwnerAction::UseRelayCopy`]); its sheet names the version, the device that signed
    /// it, and its time.
    pub(crate) fn relay_ask_use_copy(&mut self, id: &str, ctx: Option<&egui::Context>) {
        let Some((head, name)) = self.relay_served_copy(id) else {
            self.set_err("Apassy cannot tell which copy the relay holds now. Sync again first. Nothing changed.");
            return;
        };
        let Some(team_id) = self
            .relay_of(id)
            .and_then(|relay| relay.state().ok().flatten())
            .and_then(|state| state.team_id)
        else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        let vault_name = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
            .unwrap_or_default();
        let request = OwnerRequest::UseRelayCopy {
            team_id,
            version: head.version,
            head: head.head_hash.clone(),
            device_name: name.unwrap_or_else(|| {
                concat!("a device that this ", crate::computer!(), " does not know").to_owned()
            }),
            time: head.time,
            vault_name,
        };
        self.sync.relay.use_copy_check = Some((id.to_owned(), request.action()));
        self.ask_owner(request, ctx);
    }

    /// "Use the relay copy…" of a vault store after its owner check: the proof must name
    /// exactly the head that the relay served last, in this vault session; then only that
    /// head is taken ([`RelaySync::use_relay_copy_approved`]).
    fn relay_use_copy_step(&mut self) {
        let Some((id, action)) = self.sync.relay.use_copy_check.clone() else {
            return;
        };
        if self.ui.connect.live.guarded.is_some()
            || self.sync.relay.undo.is_some()
            || self.sync.relay.departed_check.is_some()
        {
            return;
        }
        let Some(proof) = self.owner.take_connect_proof() else {
            if self.owner.check.is_none() {
                self.sync.relay.use_copy_check = None;
            }
            return;
        };
        self.sync.relay.use_copy_check = None;
        let Some(epoch) = self.owner_ui.session.epoch() else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        if let Err(refusal) = proof.check(&action, &epoch) {
            self.set_err(refusal.message());
            return;
        }
        drop(proof);
        let OwnerAction::UseRelayCopy { version, head, .. } = action else {
            return;
        };
        let Some((approved, _)) = self
            .relay_served_copy(&id)
            .filter(|(served, _)| served.version == version && served.head_hash == head)
        else {
            self.set_err("The copy on the relay changed. Nothing changed.");
            return;
        };
        if self.relay_busy(&id, Job::UseCopy) {
            return;
        }
        let Some(relay) = self.relay_of(&id).filter(|_| self.relay_open(&id)) else {
            self.set_err("Unlock the vault first. Nothing changed.");
            return;
        };
        let slot = self.relay_slot();
        self.relay_spawn_with(&id, Job::UseCopy, Some(relay.clone()), move || {
            Reply::UsedCopy(relay.use_relay_copy_approved(&slot, same_file(&relay), &approved))
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

    // ---- "Add a device…". ----

    /// A new link for another Mac or an iPhone.
    fn relay_add_mac_start(&mut self, id: &str) {
        let ready = self.relay_ready(id);
        self.sync.relay.add = Some(AddMac::new(
            id,
            ready.as_ref().err().map(|error| call_error(*error)),
            None,
        ));
        if let Ok(relay) = ready {
            self.relay_spawn(id, Job::NewLink, move || {
                Reply::Link(relay.create_link(KeySource::Memory))
            });
        }
    }

    /// A new link for an iPhone of the notifications-only team of the vault `id`, or of
    /// the node team of a move ("Move approvals to this Mac"). A team on the Mac's node
    /// gives the pinned link: the node origin, the pin, the alternatives, and the node
    /// name (node-pairing-v1 section 6); the pairing channel appends the handoff.
    ///
    /// While the node runs on Apassy Connect, the pinned link carries the Connect route
    /// beside the tailnet address (node-pairing-v1 section 7a, plan s7 unit M5); otherwise
    /// it is the link of today, which an older iPhone app reads.
    fn relay_add_iphone_start(&mut self, id: &str) {
        let (client, advertise) = match self.questions_move_client(id) {
            Some((client, url, name)) => (Ok(client), Some((url, name))),
            None => (
                self.questions_team_client(id),
                self.questions_node_advertise(id),
            ),
        };
        let advertise = advertise.map(|(url, name)| match self.questions_connect_route() {
            Some(route) => (url.clone().with_tunnel(Some(route)).unwrap_or(url), name),
            None => (url, name),
        });
        let via = client.as_ref().ok().cloned();
        let mut add = AddMac::new(id, client.err(), via.clone());
        add.node = advertise.is_some();
        self.sync.relay.add = Some(add);
        if let Some(client) = via {
            self.relay_spawn(id, Job::NewLink, move || {
                Reply::Link(client.create_link().and_then(|code| match &advertise {
                    Some((url, name)) => code.for_origin(url, Some(name.as_str())),
                    None => Ok(code),
                }))
            });
        }
    }

    /// Retry the same sealed handoff after an ambiguous response; never mint another device.
    fn relay_send_handoff(&mut self) {
        let Some(add) = self.sync.relay.add.as_ref() else {
            return;
        };
        let (Some(channel), Some(client), Some((sealed, expiry, ..))) =
            (&add.channel, &add.via, &add.handoff)
        else {
            return;
        };
        if self.relay_busy(&add.id, Job::Confirm) {
            return;
        }
        let (id, channel, client, sealed, expiry) = (
            add.id.clone(),
            channel.clone(),
            client.clone(),
            sealed.clone(),
            *expiry,
        );
        self.relay_spawn(&id, Job::Confirm, move || Reply::Handoff {
            qid: channel.qid().to_owned(),
            result: channel
                .send(&client, expiry, &sealed)
                .map_err(|_| "Check the internet connection and try again.".to_owned()),
        });
    }

    /// The client of the questions team of the open, unlocked vault `id`, whether it
    /// also syncs the vault or carries questions only. No network while reading the key.
    pub(crate) fn questions_team_client(&self, id: &str) -> Result<QuestionsClient, String> {
        if !self.relay_open(id) {
            return Err(call_error(SyncError::Vault(VaultErrorKind::Locked)));
        }
        self.owner_ui
            .session
            .with_vault(|vault| crate::relay::membership::questions_membership(vault))
            .and_then(|found| found.ok().flatten())
            .ok_or_else(|| {
                "Turn on “Send questions through the relay” for this vault first.".to_owned()
            })
            .and_then(|membership| {
                QuestionsClient::from_membership(&membership).map_err(call_error)
            })
    }

    /// Ask the relay for the Macs that wait for a confirmation, with their safety words.
    fn relay_add_mac_poll(&mut self) {
        if self
            .sync
            .relay
            .add
            .as_ref()
            .is_some_and(|add| add.handoff.is_some())
        {
            self.relay_send_handoff();
            return;
        }
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
        if let Some(client) = add.via.clone() {
            self.relay_spawn(&id, Job::Links, move || {
                Reply::Links(client.pending_links(held.as_ref()))
            });
            return;
        }
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
        let request = if add.via.is_some() {
            OwnerRequest::ConfirmQuestionsDevice {
                vault: add.id.clone(),
                link_id,
                device_name: link.device_name.clone(),
                public_key: link.public_key.clone(),
            }
        } else {
            OwnerRequest::ConfirmSyncDevice {
                vault: add.id.clone(),
                link_id,
                device_name: link.device_name.clone(),
                public_key: link.public_key.clone(),
            }
        };
        self.ask_owner(request, ctx);
    }

    /// After the owner check: confirm the Mac of `link_id` for the vault `id` with the
    /// safety words of this Mac, on its own thread. `proof` must name this link exactly
    /// as the sheet showed it, in this vault session.
    pub(crate) fn relay_confirm_link(&mut self, id: &str, link_id: u64, proof: OwnerProof) {
        let add = self.sync.relay.add.as_ref().filter(|add| add.id == id);
        let via = add.and_then(|add| add.via.clone());
        let link = add
            .and_then(|add| add.links.iter().find(|link| link.id == link_id))
            .cloned();
        let Some(link) = link else {
            self.set_err("The “Add a device” sheet is closed. Nothing was added.");
            return;
        };
        if link.expires_at <= kit::now()
            || add
                .and_then(|a| a.code.as_ref())
                .is_none_or(|c| c.expires_at <= kit::now())
        {
            self.set_err("This pairing code expired. Make a new code.");
            return;
        }
        let expected = OwnerAction::ConfirmSyncDevice {
            link_id,
            device_name: link.device_name.clone(),
            public_key: link.public_key.clone(),
        };
        let relay = match via {
            Some(_) => None,
            None => match self.relay_ready(id) {
                Ok(relay) => Some(relay),
                Err(error) => {
                    self.set_err(format!("Nothing was added. {}", call_error(error)));
                    return;
                }
            },
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
        self.relay_spawn(id, Job::Confirm, move || {
            let result = match (relay, via) {
                (Some(relay), _) => relay.confirm_link(KeySource::Memory, &link),
                (None, Some(client)) => client.confirm_link(&link).map(team_device_view),
                (None, None) => Err(SyncError::NotEnabled),
            };
            Reply::Confirmed { link, result }
        });
    }

    /// The answer of a confirmation.
    fn relay_confirmed(
        &mut self,
        id: &str,
        link: &PendingLink,
        result: Result<DeviceView, SyncError>,
    ) {
        let link_id = link.id;
        let forget_link = |app: &mut Self| {
            if let Some(add) = app.sync.relay.add.as_mut().filter(|add| add.id == id) {
                add.links.retain(|link| link.id != link_id);
            }
        };
        match result {
            Ok(device) => {
                let questions = self
                    .sync
                    .relay
                    .add
                    .as_ref()
                    .is_some_and(|add| add.id == id && add.via.is_some());
                let name = shown_link_name(&device.name);
                // The kind comes from the link that the owner confirmed (ADR 0039 §2).
                let watch = link_is_watch(&link.device_name);
                let device_word = if watch { "Apple Watch" } else { "iPhone" };
                // The owner check of this confirmation covers the keys of the link: the
                // row of an iPhone or an Apple Watch is written here, from them
                // (relay-questions-v1 section 5.2). A Mac writes its own row after its
                // own owner check.
                let iphone = self.relay_register_linked(id, link, device.id);
                if matches!(&iphone, Some(Ok(()))) {
                    // A device in the node team of a move: the approvals move now.
                    let team = self
                        .sync
                        .relay
                        .add
                        .as_ref()
                        .and_then(|add| add.via.as_ref())
                        .map(|client| client.team_id().to_owned());
                    if let Some(team) = team {
                        self.questions_device_joined(id, &team, &name);
                    }
                    if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                        add.added_device = Some((name.clone(), watch));
                    }
                    let channel = self
                        .sync
                        .relay
                        .add
                        .as_ref()
                        .and_then(|add| add.channel.clone());
                    if let Some(channel) = channel {
                        let team = self
                            .sync
                            .relay
                            .add
                            .as_ref()
                            .and_then(|add| add.via.as_ref())
                            .map(|client| client.team_id().to_owned());
                        if let Some(team) = team {
                            let sealed = self
                                .owner_ui
                                .session
                                .with_vault(|vault| channel.seal(vault, &team, &link.public_key));
                            match sealed {
                                Some(Ok(sealed)) => {
                                    forget_link(self);
                                    if let Some(add) = self.sync.relay.add.as_mut() {
                                        let expiry = add
                                            .code
                                            .as_ref()
                                            .map(|c| c.expires_at)
                                            .unwrap_or(kit::now());
                                        add.handoff = Some((sealed, expiry, name.clone(), watch));
                                    }
                                    self.relay_send_handoff();
                                    return;
                                }
                                _ => {
                                    self.set_err(format!("The {device_word} was confirmed, but the vault could not transfer its keys. Keep the vault unlocked and pair again with a new code."));
                                    return;
                                }
                            }
                        }
                    }
                }
                let text = match iphone {
                    Some(Err(error)) => format!(
                        "Added {name} to the relay, but the vault did not keep its keys: {}",
                        call_error(error)
                    ),
                    Some(Ok(())) if watch => format!(
                        "Added. {} gets the access requests of this vault and can allow one once while it is unlocked on a wrist.",
                        crate::questions::device_link::watch_label(&name)
                    ),
                    Some(Ok(())) => format!(
                        "Added. {name} gets the questions of this vault and answers with Face ID once this vault syncs to it."
                    ),
                    None if questions => {
                        format!("Added. {name} gets the questions of this vault now.")
                    }
                    None => format!("Added. {name} receives the vault now."),
                };
                forget_link(self);
                if let Some(add) = self.sync.relay.add.as_mut().filter(|add| add.id == id) {
                    // The code is used: the sheet shows the result only, and asks no more.
                    add.added = Some(text.clone());
                    add.code = None;
                    add.qr = None;
                }
                self.set_ok(text);
            }
            Err(SyncError::Relay(RelayRefusal::Conflict)) => {
                forget_link(self);
                self.set_err(concat!(
                    "The relay's record of this ",
                    crate::computer!(),
                    " does not match. Nothing was added."
                ));
            }
            Err(error) => self.set_err(format!("Nothing was added. {}", call_error(error))),
        }
    }

    /// The row of a device that this Mac confirmed: an iPhone or an Apple Watch whose link
    /// carries its answer key, in the questions team (the team of "Add an iPhone or a
    /// Mac…", or the sync team). `None` for a link without an answer key (a Mac) or a
    /// vault that is not open here.
    fn relay_register_linked(
        &mut self,
        id: &str,
        link: &PendingLink,
        device_id: u64,
    ) -> Option<Result<(), SyncError>> {
        let (name, found) = split_linked_device_name(&link.device_name);
        let kind = match found?.0 {
            LinkedDeviceKind::Iphone => TrustedDeviceKind::Iphone,
            LinkedDeviceKind::Watch => TrustedDeviceKind::Watch,
        };
        let via_team = self
            .sync
            .relay
            .add
            .as_ref()
            .filter(|add| add.id == id)
            .and_then(|add| add.via.as_ref())
            .map(|client| client.team_id().to_owned());
        if !self.relay_open(id) {
            return Some(Err(SyncError::Vault(VaultErrorKind::Locked)));
        }
        let mut older = Vec::new();
        let written = self.owner_ui.session.with_vault(|vault| {
            let team = match via_team {
                Some(team) => team,
                None => vault.relay_device()?.ok_or(SyncError::NotEnabled)?.team_id,
            };
            crate::relay::membership::register_linked_device(
                vault,
                &team,
                device_id,
                &link.device_name,
                &link.public_key,
            )?;
            older = older_devices(
                vault.trusted_devices()?,
                &link.public_key,
                &name,
                &team,
                kind,
            );
            Ok(())
        });
        if matches!(&written, Some(Ok(())))
            && let Some(add) = self.sync.relay.add.as_mut().filter(|a| a.id == id)
        {
            add.older = older;
        }
        self.wake_questions();
        Some(written.unwrap_or(Err(SyncError::Vault(VaultErrorKind::Locked))))
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
            .map(|link| shown_link_name(&link.device_name))
            .unwrap_or_default();
        if let Some(client) = add.via.clone() {
            self.relay_spawn(&id, Job::Refuse, move || Reply::Refused {
                link_id,
                name,
                result: client.refuse_link(link_id),
            });
            return;
        }
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
        // The device leaves the questions too, whatever the relay answers: its trusted
        // device of the sync team is removed, and the vault gets a new question key.
        if self.relay_open(id) && self.questions_forget_relay_device(device_id).is_some() {
            self.wake_questions();
        }
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
        relay.store_join = false;
        relay.join_source = relay.source;
        let text = Zeroizing::new(relay.link_input.trim().to_owned());
        if text.is_empty() {
            relay.join_error =
                Some(concat!("Paste the link from the other ", crate::computer!(), ".").to_owned());
            return;
        }
        let url_field = match relay.url_input.trim() {
            "" => DEFAULT_RELAY_URL.to_owned(),
            typed => typed.to_owned(),
        };
        if PairedLink::parse(&text).is_ok_and(|paired| paired.kind == LinkKind::Pair) {
            relay.join_error = Some(A_PAIRING_LINK.to_owned());
            return;
        }
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
        // A link for the origin of this Mac's Connect account, decided from the account
        // file: a vault store of the account has no device link (its devices come from the
        // account), so the store of the link's team is taken from the account, and only a
        // relay team at that origin gets the link. That needs the open account session; a
        // key of its own is never sent for a store of the account.
        let for_account =
            self.ui.connect.live.account_origin().is_some_and(|origin| {
                RelayUrl::parse(&origin).is_ok_and(|own| own.as_str() == url)
            });
        let account = if for_account {
            match self.ui.connect.live.sync_account() {
                Some(account) => Some(account),
                // The start screen: the session opens for this step there, and the link
                // goes on when it is open.
                None if self.owner_ui.session.epoch().is_none() => {
                    self.sync.relay.join_error = Some(CONNECT_OPEN_SIGNING_IN.to_owned());
                    self.connect_open_for_link(target, ctx);
                    return;
                }
                None => {
                    self.sync.relay.join_error = Some(CONNECT_SIGN_IN_FOR_LINK.to_owned());
                    return;
                }
            }
        } else {
            None
        };
        let relay = &mut self.sync.relay;
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
        let team = link_code_team(&code).unwrap_or_default().to_owned();
        relay.join_key = key.pkcs8().map(|pkcs8| (code, pkcs8.clone()));
        self.relay_join_cancel();
        if let Some(account) = account {
            self.sync.relay.store_join = false;
            let names = Arc::clone(&self.sync.relay.join_names);
            let task = Task::spawn(ctx.cloned(), move || {
                let store = {
                    let mut guard = lock(&account.account);
                    let account = guard
                        .as_mut()
                        .ok_or_else(|| crate::connect::ConnectError::SignedOut.to_string())?;
                    let store = account
                        .vault_stores()
                        .map_err(|error| error.to_string())?
                        .into_iter()
                        .find(|store| store.team_id == team);
                    match store {
                        Some(store) => {
                            keep_removed_names(account, &names);
                            Some(
                                RelaySync::joined_from_store(account, &store)
                                    .map_err(|error| error.to_string())?,
                            )
                        }
                        None => None,
                    }
                };
                match store {
                    Some(joined) => Ok(Resolved::Store(joined)),
                    None => PendingJoin::request_with_key(&text, &url_field, &device, key)
                        .map(Resolved::Link)
                        .map_err(join_error),
                }
            });
            self.sync.relay.join = Some(Join {
                target,
                url,
                team: String::new(),
                safety: String::new(),
                phase: Phase::Resolving(task),
            });
            return;
        }
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
        if std::mem::take(&mut self.sync.relay.store_join) {
            // The device of this Mac in a vault store of its account stays there.
            drop(joined);
            return;
        }
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

    /// Cancel a link for the origin of the Connect account that is still resolving: wait
    /// for its answer, then cancel the link when one was sent. A store of the account
    /// needs nothing.
    fn relay_end_resolving(&mut self, task: Task<Result<Resolved, String>>) {
        self.relay_end(move || {
            let deadline = Instant::now() + CANCEL_WAIT;
            loop {
                match task.poll() {
                    TaskPoll::Waiting if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    TaskPoll::Waiting => return Some(NOT_CANCELLED.to_owned()),
                    TaskPoll::Done(Ok(Resolved::Link(pending))) => {
                        return pending.cancel().err().map(|_| NOT_CANCELLED.to_owned());
                    }
                    TaskPoll::Done(_) | TaskPoll::Lost => return None,
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
            // A link of a relay team is cancelled when it was sent; the account device
            // stays in a store.
            Phase::Resolving(task) => self.relay_end_resolving(task),
            // The account device stays in the store; nothing to cancel.
            Phase::FromStore(_) => self.sync.relay.store_join = false,
            Phase::Waiting { pending, .. } => self.relay_end_pending(pending),
            Phase::Downloading { joined, .. }
            | Phase::Departed { joined, .. }
            | Phase::WithoutHistory { joined, .. }
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
            Phase::Resolving(task) => match task.poll() {
                TaskPoll::Waiting => Some(Phase::Resolving(task)),
                TaskPoll::Done(Ok(Resolved::Store(joined))) => {
                    self.relay_take_join_names();
                    // A store of the account: the copy downloads; no link was used.
                    self.sync.relay.link_input.zeroize();
                    self.sync.relay.join_key = None;
                    self.sync.relay.store_join = true;
                    let joined = Arc::new(joined);
                    joined.team().clone_into(&mut team);
                    match &target {
                        None => {
                            let work = self.vault_list.data_dir.join("sync");
                            let device = Arc::clone(&joined);
                            let slot = self.ui.connect.live.session().slot();
                            let task = Task::spawn(ctx.cloned(), move || {
                                download_store_copy(&device, &work, &slot)
                            });
                            Some(Phase::Downloading { joined, task })
                        }
                        Some(id) => {
                            if let Err(text) = self.relay_enable_joined(id, joined, &url, None) {
                                failure = Some(text);
                            }
                            None
                        }
                    }
                }
                TaskPoll::Done(Ok(Resolved::Link(pending))) => {
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
                TaskPoll::Done(Err(text)) => {
                    failure = Some(text);
                    None
                }
                TaskPoll::Lost => {
                    failure = Some(lost());
                    None
                }
            },
            Phase::FromStore(task) => match task.poll() {
                TaskPoll::Waiting => Some(Phase::FromStore(task)),
                TaskPoll::Done(Ok(joined)) => {
                    self.relay_take_join_names();
                    let joined = Arc::new(joined);
                    let work = self.vault_list.data_dir.join("sync");
                    let device = Arc::clone(&joined);
                    let slot = self.ui.connect.live.session().slot();
                    let task = Task::spawn(ctx.cloned(), move || {
                        download_store_copy(&device, &work, &slot)
                    });
                    Some(Phase::Downloading { joined, task })
                }
                TaskPoll::Done(Err(text)) => {
                    self.sync.relay.store_join = false;
                    failure = Some(text);
                    None
                }
                TaskPoll::Lost => {
                    self.sync.relay.store_join = false;
                    failure = Some(lost());
                    None
                }
            },
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
                TaskPoll::Done(Err(error)) => match (
                    joined
                        .waiting_head()
                        .filter(|_| error == SyncError::WaitsForAccountDevice),
                    joined
                        .unverified_history_head()
                        .filter(|_| error == SyncError::HistoryUnverified),
                ) {
                    // The owner can take the copy that a device that left pushed.
                    (Some(head), _) => Some(Phase::Departed { joined, head }),
                    // The owner can take the head without its earlier history.
                    (None, Some(head)) => {
                        let device = self.relay_signed_name(&head.key).unwrap_or_else(|| {
                            "a device of this account or of a person who shares this vault"
                                .to_owned()
                        });
                        Some(Phase::WithoutHistory {
                            joined,
                            head,
                            device,
                        })
                    }
                    (None, None) => {
                        self.relay_end_joined(joined);
                        failure = Some(join_error(error));
                        None
                    }
                },
                TaskPoll::Lost => {
                    self.relay_end_joined(joined);
                    failure = Some(lost());
                    None
                }
            },
            Phase::Departed { joined, head } => {
                let take = ctx.is_some_and(|ctx| {
                    ctx.data_mut(|data| data.remove_temp::<bool>(egui::Id::new(TAKE_DEPARTED)))
                        .is_some()
                });
                if take {
                    self.relay_ask_join_departed(&joined, &head, ctx);
                }
                if self.relay_join_departed_approved(&head) {
                    Some(self.relay_join_departed(joined, head, ctx))
                } else {
                    Some(Phase::Departed { joined, head })
                }
            }
            Phase::WithoutHistory {
                joined,
                head,
                device,
            } => {
                let take = ctx.is_some_and(|ctx| {
                    ctx.data_mut(|data| {
                        data.remove_temp::<bool>(egui::Id::new(TAKE_WITHOUT_HISTORY))
                    })
                    .is_some()
                });
                if take {
                    self.relay_ask_without_history(&joined, &head, &device, ctx);
                }
                if self.relay_without_history_approved(&head) {
                    let work = self.vault_list.data_dir.join("sync");
                    let device = Arc::clone(&joined);
                    let task = Task::spawn(ctx.cloned(), move || {
                        device.download_without_history(&work, &head)
                    });
                    Some(Phase::Downloading { joined, task })
                } else {
                    Some(Phase::WithoutHistory {
                        joined,
                        head,
                        device,
                    })
                }
            }
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

    /// The signed names that the worker of a join from a vault store read
    /// ([`keep_removed_names`]).
    fn relay_take_join_names(&mut self) {
        let names = std::mem::take(&mut *lock(&self.sync.relay.join_names));
        self.sync.relay.departed_names.extend(names);
    }

    /// Forget the vault stores that "Use a vault from another Mac" › "Apassy Connect"
    /// listed: each visit of the screen, and "Try Again", ask Connect again.
    pub(crate) fn relay_connect_forget_stores(&mut self) {
        self.sync.relay.stores = None;
        self.sync.relay.stores_task = None;
    }

    /// The vault stores of the Connect account of this Mac that list this Mac and whose
    /// vault is not in the list here, for "Use a vault from another Mac" › "Apassy
    /// Connect", read once for each visit on their own thread
    /// (`ConnectAccount::vault_stores`). `None` while they load, and while the account
    /// session is not open (the screen shows the account then).
    pub(crate) fn relay_connect_stores(
        &mut self,
        ctx: &egui::Context,
    ) -> Option<&Result<Vec<crate::connect::VaultStoreView>, String>> {
        if let Some(task) = self.sync.relay.stores_task.as_ref() {
            match task.poll() {
                TaskPoll::Waiting => ctx.request_repaint_after(Duration::from_millis(200)),
                TaskPoll::Done(result) => {
                    self.sync.relay.stores = Some(result);
                    self.sync.relay.stores_task = None;
                }
                TaskPoll::Lost => {
                    self.sync.relay.stores = Some(Err(LOST.to_owned()));
                    self.sync.relay.stores_task = None;
                }
            }
        }
        if self.sync.relay.stores.is_none() && self.sync.relay.stores_task.is_none() {
            let account = self.ui.connect.live.sync_account()?;
            // The vault ids of the list are in their sync states; a vault without sync
            // shows its store, and the adoption refuses a second copy of the same vault.
            let known: Vec<String> = lock(&self.sync.relay.cache)
                .values()
                .filter_map(|relay| relay.state().ok().flatten().map(|state| state.vault_id))
                .collect();
            self.sync.relay.stores_task = Some(Task::spawn(Some(ctx.clone()), move || {
                let mut guard = lock(&account.account);
                let account = guard
                    .as_mut()
                    .ok_or_else(|| crate::connect::ConnectError::SignedOut.to_string())?;
                let me = account.state().device_id.clone();
                let stores = account.vault_stores().map_err(|error| error.to_string())?;
                Ok(stores
                    .into_iter()
                    .filter(|store| {
                        // A store that holds devices of another account is offered only
                        // with a share of it that this device verified (connect-account-v1
                        // section 16).
                        !known.contains(&store.vault_id)
                            && (!store.shared || account.shares_store(&store.team_id))
                            && store
                                .devices
                                .iter()
                                .any(|device| device.device_id == me && device.store_device_id > 0)
                    })
                    .collect())
            }));
        }
        self.sync.relay.stores.as_ref()
    }

    /// "Use This Vault" of a vault store: this Mac's device in the store
    /// (`RelaySync::joined_from_store`), then the download and the passphrase step of
    /// "Use a vault from another Mac". No link and no confirmation: the store lists this
    /// Mac already.
    pub(crate) fn relay_connect_use(
        &mut self,
        store: crate::connect::VaultStoreView,
        ctx: Option<&egui::Context>,
    ) {
        self.sync.relay.join_error = None;
        if self.sync.relay.join.is_some() {
            return;
        }
        let Some(account) = self.ui.connect.live.sync_account() else {
            self.sync.relay.join_error = Some(CONNECT_SIGN_IN.to_owned());
            return;
        };
        let team = store.name.clone();
        let names = Arc::clone(&self.sync.relay.join_names);
        let task = Task::spawn(ctx.cloned(), move || {
            let mut guard = lock(&account.account);
            let account = guard
                .as_mut()
                .ok_or_else(|| crate::connect::ConnectError::SignedOut.to_string())?;
            keep_removed_names(account, &names);
            RelaySync::joined_from_store(account, &store).map_err(|error| error.to_string())
        });
        self.sync.relay.store_join = true;
        self.sync.relay.join_source = OpenSource::Connect;
        self.sync.relay.join = Some(Join {
            target: None,
            url: account.origin.clone(),
            team,
            safety: String::new(),
            phase: Phase::FromStore(task),
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
        // The address of the confirmed device: a pinned link keeps its pin and
        // alternatives with the sync of the new vault (node-pairing-v1 section 9).
        let relay = RelaySync::new(
            RelayConfig::in_data_dir(&self.vault_list.data_dir, &path, &url, &id)
                .with_url_trust(joined.member().url()),
        );
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
        // A copy from a vault store: the window names its sync "Apassy Connect".
        let store_join = std::mem::take(&mut self.sync.relay.store_join);
        if let Some(entry) = registry.entry_mut(&id) {
            let mut link = report.link;
            link.connect = store_join || relay.uses_account_key();
            entry.sync = Some(SyncLink::relay(&id, link));
        }
        lock(&self.sync.relay.cache).insert(id.clone(), relay);
        self.vault_list.registry = registry;
        // A copy from a vault store: the account key and the plan go to its relay sync.
        if store_join {
            self.relay_share_connect();
        }
        self.save_vault_list();
        let opened = self.owner_ui.session.open_file(&path);
        self.apply(opened, "The vault is open.")?;
        self.reset_vault_state(ctx);
        self.end_waiting_runs();
        self.list_open_vault(&name, ctx);
        let unlocked = self.owner_ui.session.unlock(&passphrase);
        drop(passphrase);
        self.ui.start = super::Step::Home;
        self.place = Place::CREDENTIALS;
        if unlocked.is_ok() {
            let _ = self.sync_after_unlock();
            self.sync.adopted_vault = Some(id);
        }
        let _ = self.apply(
            unlocked,
            &format!(
                concat!(
                    "“{name}” is on this ",
                    crate::computer!(),
                    ". Relay sync is on."
                ),
                name = name
            ),
        );
        None
    }
}

impl DesktopApp {
    /// "Use the Copy That … Left…" of a device that joins (the start screen): a fresh owner
    /// check first, for exactly the store, the version, and the head that the download
    /// waits on ([`OwnerAction::TakeDepartedCopy`]), as in the window with an open vault.
    /// With no vault unlocked it is Touch ID, or system authentication on Linux, bound to
    /// the session of the start-screen step.
    fn relay_ask_join_departed(
        &mut self,
        joined: &JoinedDevice,
        head: &DepartedHead,
        ctx: Option<&egui::Context>,
    ) {
        let departed = Departed::of(
            head.clone(),
            &self.sync.relay.departed_names,
            &self.sync.relay.shared_devices,
        );
        let request = OwnerRequest::TakeDepartedCopy {
            team_id: joined.team_id().to_owned(),
            version: head.version,
            head: head.head_hash.clone(),
            replace: false,
            device_name: departed.who_in(),
            vault_name: joined.team().to_owned(),
            start: true,
        };
        self.sync.relay.join_departed_check = Some(request.action());
        self.ask_owner(request, ctx);
    }

    /// Whether the owner check of [`Self::relay_ask_join_departed`] passed for exactly
    /// `head`, the head that the download still waits on, in the session that asked it
    /// (the vault session, or else the start-screen step). A cancelled or refused check
    /// drops the step; a proof for another head or session changes nothing.
    fn relay_join_departed_approved(&mut self, head: &DepartedHead) -> bool {
        let Some(action) = self.sync.relay.join_departed_check.clone() else {
            return false;
        };
        if self.ui.connect.live.guarded.is_some() {
            return false;
        }
        let Some(proof) = self.owner.take_connect_proof() else {
            if self.owner.check.is_none() {
                self.sync.relay.join_departed_check = None;
            }
            return false;
        };
        self.sync.relay.join_departed_check = None;
        let Some(epoch) = self
            .owner_ui
            .session
            .epoch()
            .or_else(|| self.connect_session().start_epoch())
        else {
            self.set_err("The step ended. Nothing changed.");
            return false;
        };
        if let Err(refusal) = proof.check(&action, &epoch) {
            self.set_err(refusal.message());
            return false;
        }
        drop(proof);
        let same = matches!(
            &action,
            OwnerAction::TakeDepartedCopy {
                version,
                head: hash,
                replace: false,
                ..
            } if *version == head.version && *hash == head.head_hash
        );
        if !same {
            self.set_err("The copy on the relay changed. Nothing changed.");
        }
        same
    }

    /// "Take This Copy Without Its Earlier History…" of a device that joins: a fresh owner
    /// check that names the store, the head, its device, and its time
    /// ([`OwnerAction::TakeCopyWithoutHistory`]); with no vault unlocked it is bound to the
    /// session of the start-screen step, as the step on the copy of a removed device.
    fn relay_ask_without_history(
        &mut self,
        joined: &JoinedDevice,
        head: &DepartedHead,
        device: &str,
        ctx: Option<&egui::Context>,
    ) {
        let request = OwnerRequest::TakeCopyWithoutHistory {
            team_id: joined.team_id().to_owned(),
            version: head.version,
            head: head.head_hash.clone(),
            device_name: device.to_owned(),
            time: head.time,
            vault_name: joined.team().to_owned(),
            start: true,
        };
        self.sync.relay.join_departed_check = Some(request.action());
        self.ask_owner(request, ctx);
    }

    /// Whether the owner check of [`Self::relay_ask_without_history`] passed for exactly
    /// `head`, in the session that asked it.
    fn relay_without_history_approved(&mut self, head: &DepartedHead) -> bool {
        let named = matches!(
            &self.sync.relay.join_departed_check,
            Some(OwnerAction::TakeCopyWithoutHistory { .. })
        );
        if !named {
            return false;
        }
        let Some(action) = self.relay_join_proof() else {
            return false;
        };
        let same = matches!(
            &action,
            OwnerAction::TakeCopyWithoutHistory { version, head: hash, .. }
                if *version == head.version && *hash == head.head_hash
        );
        if !same {
            self.set_err("The copy on the relay changed. Nothing changed.");
        }
        same
    }

    /// The proof of the owner check of a step of a device that joins
    /// (`join_departed_check`), checked against its action in the session that asked it
    /// (the vault session, or else the start-screen step): the action, or `None` while no
    /// proof came or it failed. A cancelled or refused check drops the step.
    fn relay_join_proof(&mut self) -> Option<OwnerAction> {
        let action = self.sync.relay.join_departed_check.clone()?;
        if self.ui.connect.live.guarded.is_some() {
            return None;
        }
        let Some(proof) = self.owner.take_connect_proof() else {
            if self.owner.check.is_none() {
                self.sync.relay.join_departed_check = None;
            }
            return None;
        };
        self.sync.relay.join_departed_check = None;
        let Some(epoch) = self
            .owner_ui
            .session
            .epoch()
            .or_else(|| self.connect_session().start_epoch())
        else {
            self.set_err("The step ended. Nothing changed.");
            return None;
        };
        if let Err(refusal) = proof.check(&action, &epoch) {
            self.set_err(refusal.message());
            return None;
        }
        drop(proof);
        Some(action)
    }

    /// "Use the Copy That … Left…" of a device that joins, after its owner check: the
    /// download takes the head that it waited on, once
    /// ([`JoinedDevice::download_departed`]); the adoption then makes it the anchor, and
    /// the first sync pushes a head of this device over it.
    fn relay_join_departed(
        &mut self,
        joined: Arc<JoinedDevice>,
        head: DepartedHead,
        ctx: Option<&egui::Context>,
    ) -> Phase {
        let work = self.vault_list.data_dir.join("sync");
        let device = Arc::clone(&joined);
        let task = Task::spawn(ctx.cloned(), move || device.download_departed(&work, &head));
        Phase::Downloading { joined, task }
    }
}

#[cfg(test)]
impl DesktopApp {
    /// [`Self::relay_connect_tick`] now, whenever it ran last.
    pub(crate) fn relay_connect_tick_now_for_test(&mut self) {
        self.sync.relay.connect_tick = None;
        self.relay_connect_tick();
    }

    /// Take the answers of the relay calls and look at a Mac that joins until no
    /// thread runs for them. At most 20 seconds.
    pub(crate) fn relay_settle_for_test(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.relay_poll(None);
            self.relay_join_step(None);
            let joining = match self.sync.relay.join.as_ref().map(|join| &join.phase) {
                Some(
                    Phase::Requesting(_)
                    | Phase::Resolving(_)
                    | Phase::FromStore(_)
                    | Phase::Downloading { .. }
                    | Phase::Adopting(_),
                ) => true,
                Some(Phase::Waiting { poll, .. }) => poll.is_some(),
                _ => false,
            };
            if (!joining && self.sync.relay.jobs.is_empty()) || Instant::now() > deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// "Use the Copy That … Left…" of a device that joins, as a click, and one look.
    pub(crate) fn relay_take_departed_for_test(&mut self, ctx: &egui::Context) {
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(TAKE_DEPARTED), true));
        self.relay_join_step(Some(ctx));
    }

    /// "Take This Copy Without Its Earlier History…" on the screen of a device that joins.
    pub(crate) fn relay_take_without_history_for_test(&mut self, ctx: &egui::Context) {
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(TAKE_WITHOUT_HISTORY), true));
        self.relay_join_step(Some(ctx));
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

    /// "Add a device…" asks the relay now, and takes the answer.
    pub(crate) fn relay_add_mac_poll_for_test(&mut self) {
        self.relay_add_mac_poll();
        self.relay_settle_for_test();
    }

    pub(crate) fn relay_set_link_expiry_for_test(&mut self, expires_at: u64) -> Option<u64> {
        let code = self.sync.relay.add.as_mut()?.code.as_mut()?;
        Some(std::mem::replace(&mut code.expires_at, expires_at))
    }

    /// The link of the open "Add a device…" sheet.
    pub(crate) fn relay_add_mac_link_for_test(&self) -> Option<String> {
        let add = self.sync.relay.add.as_ref()?;
        add.code.as_ref().map(|code| match &add.channel {
            Some(channel) => channel.link(&code.link).to_string(),
            None => code.link.to_string(),
        })
    }

    /// The QR code of the open "Add a device…" sheet.
    pub(crate) fn relay_add_mac_qr_for_test(&self) -> Option<&QrModules> {
        self.sync.relay.add.as_ref()?.qr.as_ref()
    }

    /// The devices that wait in the open "Add a device…" sheet.
    pub(crate) fn relay_add_mac_links_for_test(&self) -> Vec<PendingLink> {
        self.sync
            .relay
            .add
            .as_ref()
            .map(|add| add.links.clone())
            .unwrap_or_default()
    }

    /// "Confirm…" in the open "Add a device…" sheet.
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
pub(super) fn safety_lines(ui: &mut egui::Ui, before: &str, words: &str, after: &str) {
    kit::paragraph(ui, before, Font::Body, kit::palette().label);
    ui.add_space(4.0);
    ui.label(kit::text(words, Font::Title).color(kit::palette().label));
    ui.add_space(4.0);
    kit::paragraph(ui, after, Font::Callout, kit::palette().secondary);
}

/// What a Mac that joins shows while it waits: the words, the download.
fn join_progress(ui: &mut egui::Ui, view: &JoinView) {
    match view {
        // A copy that the device would take against a warning: the warning with its
        // icon, and a bordered button, not the default one.
        JoinView::Departed { words, label } => {
            kit::tone_note_icon(
                ui,
                format!(
                    "{words} No device of the account has saved a copy over it yet. This copy comes from a device that was removed from the account. Do not use it if that device was lost or stolen. {DEPARTED_ADVICE} Apassy can take this copy once, and the vault of this {} starts from it.",
                    crate::computer!()
                ),
                Tone::Warning,
                Font::Footnote,
            );
            ui.add_space(6.0);
            if kit::small_button(ui, label, Style::Bordered).clicked() {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(egui::Id::new(TAKE_DEPARTED), true));
            }
        }
        JoinView::WithoutHistory { words } => {
            kit::tone_note_icon(ui, words.as_str(), Tone::Warning, Font::Footnote);
            ui.add_space(6.0);
            if kit::small_button(ui, WITHOUT_HISTORY, Style::Bordered).clicked() {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(egui::Id::new(TAKE_WITHOUT_HISTORY), true));
            }
        }
        JoinView::Sending => {
            kit::tone_note(ui, "Apassy sends the link to the relay…", Tone::Accent)
        }
        JoinView::Waiting { safety } => safety_lines(
            ui,
            concat!(
                "Waiting for the other ",
                crate::computer!(),
                "… Both ",
                crate::computers!(),
                " show:"
            ),
            safety,
            concat!(
                "Confirm on the other ",
                crate::computer!(),
                " if it shows the same words."
            ),
        ),
        JoinView::Downloading { team } => kit::tone_note(
            ui,
            format!(
                concat!(
                    "The other ",
                    crate::computer!(),
                    " confirmed this ",
                    crate::computer!(),
                    ". Apassy downloads “{team}” from the relay…"
                ),
                team = team
            ),
            Tone::Accent,
        ),
        JoinView::Ready { team } => kit::tone_note_icon(
            ui,
            format!(
                concat!(
                    "“{team}” is on this ",
                    crate::computer!(),
                    ", still encrypted."
                ),
                team = team
            ),
            Tone::Good,
            Font::Footnote,
        ),
        JoinView::Opening { team } => kit::tone_note(
            ui,
            format!("Apassy opens “{team}” with the passphrase…"),
            Tone::Accent,
        ),
        JoinView::Passphrase { team } => kit::tone_note(
            ui,
            format!(
                concat!(
                    "The other ",
                    crate::computer!(),
                    " confirmed this ",
                    crate::computer!(),
                    ". The relay copy of “{team}” uses another passphrase than this vault."
                ),
                team = team
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
pub(super) fn link_fields(app: &mut DesktopApp, s: &mut kit::Section<'_>, focus: bool) -> bool {
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
    s.field(concat!("Name of this ", crate::computer!()), |ui| {
        kit::text_input(
            ui,
            &mut app.sync.relay.device_input,
            "sync-relay-device",
            "MacBook Pro",
        )
    });
    link.lost_focus() && link.ctx.input(|input| input.key_pressed(egui::Key::Enter))
}

/// "Apassy relay" in Settings > Vault > Sync: a new relay copy (without a team code on
/// the hosted relay, plan s7 unit S0; with one on a relay that needs it), or a
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
        // "Apassy Connect" while this Mac has an account with a plan that pushes.
        let connect = app.connect_sync_available();
        if !connect && app.sync.relay.mode == SetupMode::Connect {
            app.sync.relay.mode = SetupMode::NewCopy;
        }
        if app.sync.relay.mode == SetupMode::Connect && joining.is_none() {
            kit::sheet_title(
                ui,
                &format!("Sync “{}” through Apassy Connect", entry.name),
                Some(CONNECT_SETUP_LEAD),
            );
        } else {
            kit::sheet_title(
                ui,
                &format!("Sync “{}” through the Apassy relay", entry.name),
                Some(concat!(
                    "The relay keeps one encrypted copy of this vault and passes the changes of each ",
                    crate::computer!(),
                    " to the others within seconds. It never gets the passphrase, so it cannot open the vault. Agents, their exceptions, your answers, and the activity stay on each ",
                    crate::computer!(),
                    "."
                )),
            );
        }
        if joining.is_none() {
            let mut modes = vec![
                (SetupMode::NewCopy, "New relay copy"),
                (
                    SetupMode::Join,
                    concat!("Join from another ", crate::computer!()),
                ),
                (SetupMode::Node, "Your own node"),
            ];
            if connect {
                modes.insert(0, (SetupMode::Connect, "Apassy Connect"));
            }
            kit::segmented(ui, "sync-relay-mode", &mut app.sync.relay.mode, &modes);
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
                        concat!(
                            "Type the passphrase of the relay copy. “{}” takes it, as on your other ",
                            crate::computers!(),
                            ", and Apassy merges the copy into it. From then on you unlock “{}” with the passphrase of the copy."
                        ),
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
            (SetupMode::Connect, None) => {
                kit::note(ui, CONNECT_SETUP_WORDS);
                ui.add_space(8.0);
            }
            (SetupMode::NewCopy, None) => {
                // The hosted relay needs no team code (plan s7 unit S0).
                let hosted = !needs_team_code(&app.sync.relay.url_input, false);
                let code = needs_team_code(&app.sync.relay.url_input, app.sync.relay.with_code);
                let words = if code {
                    concat!("The operator of the relay gives you a team code. It works once. Apassy makes a key for this ", crate::computer!(), " and keeps it in the vault.").to_owned()
                } else {
                    codeless_copy_words()
                };
                kit::section(ui, None, Some(words.as_str()), |s| {
                    s.field("Relay address", |ui| {
                        kit::text_input(
                            ui,
                            &mut app.sync.relay.url_input,
                            "sync-relay-url",
                            DEFAULT_RELAY_URL,
                        )
                    });
                    if hosted {
                        s.toggle(
                            "Relay with a team code",
                            Some("For a team code from the operator of the relay."),
                            &mut app.sync.relay.with_code,
                        );
                    }
                    // A one-time secret: masked, and erased after each try.
                    if code {
                        s.field("Team code", |ui| {
                            secure_input(
                                ui,
                                TEAM_CODE_FIELD,
                                &mut app.sync.relay.team_code,
                                TEAM_CODE_CAPACITY,
                                "apassy_tcd_…",
                            )
                        });
                    }
                    s.field(concat!("Name of this ", crate::computer!()), |ui| {
                        kit::text_input(
                            ui,
                            &mut app.sync.relay.device_input,
                            "sync-relay-device",
                            "MacBook Pro",
                        )
                    });
                });
            }
            (SetupMode::Node, None) => {
                kit::section(ui, None, Some(NODE_SETUP_WORDS), |s| {
                    let link = s.field("Pairing link", |ui| {
                        kit::mono_input(
                            ui,
                            &mut app.sync.relay.pair_input,
                            "sync-relay-pair",
                            "https://…/pair#apassy_tcd_…",
                        )
                    });
                    kit::claim_start_focus(&mut app.ui.focus_start_field, &link);
                    s.field(concat!("Name of this ", crate::computer!()), |ui| {
                        kit::text_input(
                            ui,
                            &mut app.sync.relay.device_input,
                            "sync-relay-device",
                            "MacBook Pro",
                        )
                    });
                });
            }
            (SetupMode::Join, None) => {
                kit::section(
                    ui,
                    None,
                    Some(if connect {
                        concat!(
                            "For a vault that is on the relay or on Apassy Connect already. On the ",
                            crate::computer!(),
                            " that syncs it, select “Add a device…” and copy the link. Apassy merges the copy with this vault. A family or team vault that someone shares with you joins the same way: their ",
                            crate::computer!(),
                            " shows the same words as this one, and you type the passphrase of the vault."
                        )
                    } else {
                        concat!(
                            "For a vault that is on the relay already. On the ",
                            crate::computer!(),
                            " that syncs it, select “Add a device…” and copy the link. Apassy merges the relay copy with this vault."
                        )
                    }),
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
                    (SetupMode::NewCopy | SetupMode::Node | SetupMode::Connect, None) => {
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
            SetupMode::NewCopy | SetupMode::Node | SetupMode::Connect => turn_on = true,
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
    } else if turn_on && app.sync.relay.mode == SetupMode::Connect {
        // The answer of Connect closes the sheet ([`Job::TurnOn`]).
        if let Err(text) = app.relay_enable_connect(&entry.id) {
            app.set_err(text);
        }
    } else if turn_on && app.sync.relay.mode == SetupMode::Node {
        // The team code of the link works once: the field forgets it after each try.
        let link = Zeroizing::new(std::mem::take(&mut app.sync.relay.pair_input));
        let device = app.sync.relay.device_input.clone();
        // The answer of the node closes the sheet ([`Job::TurnOn`]).
        if let Err(text) = app.relay_enable_node(&entry.id, &link, &device) {
            app.set_err(text);
        }
    } else if turn_on && !needs_team_code(&app.sync.relay.url_input, app.sync.relay.with_code) {
        let (url, device) = (
            app.sync.relay.url_input.clone(),
            app.sync.relay.device_input.clone(),
        );
        // The answer of the relay closes the sheet ([`Job::TurnOn`]).
        if let Err(text) = app.relay_enable_codeless(&entry.id, &url, &device) {
            app.set_err(text);
        }
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

/// The width of the QR code of "Add a device…" in points, about.
const LINK_QR_POINTS: f32 = 180.0;

/// The QR code of a link of "Add a device…" for the iPhone app: exactly the text of the
/// link, `<relay URL>/link#apassy_lnk_…`, as "Copy link" copies it.
fn link_qr(code: &LinkCode) -> Option<QrModules> {
    QrModules::new(&code.link)
}

/// "Add a device…": the link for another Mac, as text and as a QR code for an iPhone, then
/// each device that asks, with the safety words, "Confirm…", and "Refuse" (contract
/// section 7.1). With `iphone`, "Add an iPhone…" of a notifications-only team (plan §A7):
/// the same steps through the questions team, for an iPhone that joins with
/// `join_attach` and gets the questions only.
pub(super) fn add_mac_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
    iphone: bool,
) -> bool {
    if app
        .sync
        .relay
        .add
        .as_ref()
        .is_none_or(|add| add.id != entry.id || add.via.is_some() != iphone)
    {
        if iphone {
            app.relay_add_iphone_start(&entry.id);
        } else {
            app.relay_add_mac_start(&entry.id);
        }
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
    let link = add.code.as_ref().map(|code| match &add.channel {
        Some(channel) => channel.link(&code.link),
        None => Zeroizing::new(code.link.to_string()),
    });
    let expired = add
        .code
        .as_ref()
        .is_some_and(|code| kit::now() >= code.expires_at);
    // An expired link gives nothing to scan; "New link" makes a new code.
    let qr = add.qr.clone().filter(|_| !expired);
    let links = add.links.clone();
    let error = add.error.clone();
    let added = add.added.clone();
    let older = add.older.first().cloned();
    // A removed Mac cannot add one: its link works no more, and a new call fails at once.
    let removed = !iphone && app.relay_removed(&entry.id);
    let link = link.filter(|_| added.is_none() && !removed);
    if iphone {
        return questions_add_sheet(app, ctx, entry, link, qr, links, error, older);
    }
    let (title, intro, asks) = if iphone {
        (
            format!("Connect your iPhone to “{}”", entry.name),
            "On your iPhone, open the same vault from iCloud Drive, open Requests, and choose Connect this iPhone. Scan this code, compare the safety words, and confirm here. Requests work on any network; answers use Face ID. No account or subscription is needed. This code works once, for 10 minutes. After reinstalling, use a new code and remove the old iPhone in Devices.",
            "asks for the questions of",
        )
    } else {
        (
            format!("Add a device to “{}”", entry.name),
            concat!(
                "On an iPhone, open Apassy, select “Add your vault”, and scan this code. On another ",
                crate::computer!(),
                ", open Apassy, select “Use a vault from another ",
                crate::computer!(),
                "”, then Apassy relay, and paste the link. The link works once, for 10 minutes. It gives nothing until you confirm the device here."
            ),
            "asks to sync",
        )
    };
    let mut new_link = false;
    let mut check = false;
    let mut confirm = None;
    let mut refuse = None;
    let mut done = false;
    let mut remove_older = false;
    let mut keep_older = false;
    let response = kit::sheet(ctx, "sync-relay-add-mac", 520.0, |ui| {
        kit::sheet_title(ui, &title, added.is_none().then_some(intro));
        if let Some(link) = &link {
            if let Some(qr) = &qr {
                ui.vertical_centered(|ui| {
                    draw_qr(ui, qr, LINK_QR_POINTS, "Device link QR code");
                });
                ui.add_space(10.0);
            }
            if !iphone {
                let heading =
                    ui.label(kit::text("Link", Font::Headline).color(kit::palette().label));
                kit::code_block(ui, link, 1).labelled_by(heading.id);
            }
            ui.horizontal(|ui| {
                if !iphone && kit::small_button(ui, "Copy link", Style::Bordered).clicked() {
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
            if let Some((device, _)) = &older {
                let kind = if device.kind == TrustedDeviceKind::Watch {
                    "Apple Watch"
                } else {
                    "iPhone"
                };
                kit::paragraph(
                    ui,
                    format!(
                        "An older {kind} '{}' is still paired. Remove it?",
                        device.name
                    ),
                    Font::Body,
                    kit::palette().label,
                );
                ui.horizontal(|ui| {
                    remove_older = kit::button(ui, "Remove", Style::Bordered).clicked();
                    keep_older = kit::button(ui, "Keep", Style::Bordered).clicked();
                });
            }
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
            kit::note(
                ui,
                "The link expired. Make a new link for the other device.",
            );
        } else if links.is_empty() && link.is_some() {
            kit::tone_note(ui, "Waiting for the other device…", Tone::Accent);
        }
        let deciding =
            app.relay_busy(&entry.id, Job::Confirm) || app.relay_busy(&entry.id, Job::Refuse);
        for pending in &links {
            ui.add_space(8.0);
            match &pending.safety {
                Some(words) => {
                    let (shown, found) = split_linked_device_name(&pending.device_name);
                    let watch = matches!(found, Some((LinkedDeviceKind::Watch, _)));
                    let kind = match found {
                        Some((LinkedDeviceKind::Iphone, _)) => {
                            " (an iPhone that answers with Face ID)"
                        }
                        Some((LinkedDeviceKind::Watch, _)) | None => "",
                    };
                    let bound_words = app.sync.relay.add.as_ref().and_then(|add| {
                        let channel = add.channel.as_ref()?;
                        let client = add.via.as_ref()?;
                        channel.mac_safety(
                            client.team_id(),
                            &pending.public_key,
                            &pending.device_name,
                        )
                    });
                    if watch {
                        // The kind is visible before Touch ID (ADR 0039 §2).
                        ui.label(
                            kit::text(watch_confirm_title(&shown), Font::Headline)
                                .color(kit::palette().label),
                        );
                        kit::paragraph(ui, WATCH_CONFIRM_LINE, Font::Body, kit::palette().label);
                        ui.add_space(4.0);
                    }
                    safety_lines(
                        ui,
                        &format!(
                            "“{shown}”{kind} {asks} “{}”. Both devices show:",
                            entry.name
                        ),
                        bound_words.as_deref().unwrap_or(words),
                        "Compare every word. Confirm only if all words match.",
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
                            shown_link_name(&pending.device_name)
                        ),
                        Font::Body,
                        kit::palette().label,
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
    if remove_older || keep_older {
        if let Some(add) = app.sync.relay.add.as_mut()
            && !add.older.is_empty()
        {
            add.older.remove(0);
        }
        if remove_older && let Some((device, team)) = older {
            app.ask_owner(OwnerRequest::RemoveOlderIphone { device, team }, Some(ctx));
        }
    } else if new_link && iphone {
        app.relay_add_iphone_start(&entry.id);
    } else if new_link {
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

/// The width of the QR code of the move sheet (frame 4b) in points, about.
const MOVE_QR_POINTS: f32 = 140.0;

/// The questions mode of "Add a device…": the sheet of "Add an iPhone or a Mac…" and of
/// "Move Here…" in Settings > Devices, with the frames and the exact
/// texts of `docs/design/devices-settings-mockup.html`: 2a the link, 2b the safety
/// words, 2c done; 4b the move, 4c moved, 4d the old entry still on Apassy relay.
#[allow(clippy::too_many_arguments)]
fn questions_add_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
    link: Option<Zeroizing<String>>,
    qr: Option<QrModules>,
    links: Vec<PendingLink>,
    error: Option<String>,
    older: Option<(crate::vault::TrustedDevice, String)>,
) -> bool {
    use super::super::devices::{self, Kind, LinkStep, MovePhase, Route, StepChoice};
    let Some(add) = app.sync.relay.add.as_ref() else {
        return false;
    };
    let node = add.node;
    let added = add.added.clone();
    let added_device = add.added_device.clone();
    let seconds_left = add
        .code
        .as_ref()
        .map(|code| code.expires_at.saturating_sub(kit::now()));
    let route = if node { Route::Mac } else { Route::Relay };
    let step = LinkStep {
        route,
        shown: link
            .as_ref()
            .filter(|_| node)
            .map(|link| devices::shown_link(link)),
        seconds_left: seconds_left.filter(|_| link.is_some()),
    };
    let moving = app.questions_move_sheet(&entry.id);
    let moved = app.questions_moved(&entry.id).cloned();
    let removing = moving
        .as_ref()
        .is_some_and(|(_, removing)| *removing || added_device.is_some());
    let deciding =
        app.relay_busy(&entry.id, Job::Confirm) || app.relay_busy(&entry.id, Job::Refuse);
    // The first device that asks with the safety words: frame 2b.
    let asking = links
        .iter()
        .find(|pending| pending.safety.is_some())
        .cloned()
        .filter(|_| added.is_none() && !removing && moved.is_none());
    let bound_words = asking.as_ref().and_then(|pending| {
        let add = app.sync.relay.add.as_ref()?;
        let channel = add.channel.as_ref()?;
        let client = add.via.as_ref()?;
        channel.mac_safety(client.team_id(), &pending.public_key, &pending.device_name)
    });
    let mut choice = None;
    let mut check = false;
    let mut refuse_old = None;
    let mut remove_older = false;
    let mut keep_older = false;
    let qr_view = |ui: &mut egui::Ui, points: f32| {
        if let Some(qr) = &qr {
            draw_qr(ui, qr, points, "Device link QR code");
        }
    };
    // The progress and the error of the sheet, and a device that asks with an older
    // link.
    let extra =
        |ui: &mut egui::Ui, check: &mut bool, new_link: &mut bool, refuse_old: &mut Option<u64>| {
            for job in [Job::NewLink, Job::Confirm, Job::Refuse] {
                progress(app, ui, &entry.id, job);
            }
            if let Some(error) = &error {
                kit::tone_note(ui, error, Tone::Critical);
                ui.horizontal(|ui| {
                    *check = kit::small_button(ui, "Check Again", Style::Bordered).clicked();
                    if link.is_none() {
                        *new_link = kit::small_button(ui, devices::NEW_LINK, Style::Link).clicked();
                    }
                });
            }
            for pending in links.iter().filter(|pending| pending.safety.is_none()) {
                ui.add_space(6.0);
                kit::paragraph(
                    ui,
                    format!(
                        "“{}” asks to join with an older link. Refuse it, and make a new link.",
                        shown_link_name(&pending.device_name)
                    ),
                    Font::Callout,
                    kit::palette().label,
                );
                if kit::small_button(ui, "Refuse", Style::Bordered).clicked() {
                    *refuse_old = Some(pending.id);
                }
            }
        };
    let mut new_link = false;
    let response = kit::sheet(ctx, "sync-relay-add-mac", 440.0, |ui| {
        if let Some(moved) = &moved {
            choice = if moved.failed {
                devices::old_entry_step(ui, false)
            } else {
                devices::moved_step(ui, &moved.joined, moved.removed, &moved.watches)
            };
            return;
        }
        if let Some((iphone, _)) = moving.as_ref().filter(|_| removing) {
            devices::move_step(
                ui,
                iphone,
                MovePhase::Removing,
                None,
                |_| {},
                |ui| {
                    extra(ui, &mut check, &mut new_link, &mut refuse_old);
                },
            );
            return;
        }
        if let Some((name, watch)) = &added_device {
            choice = devices::added_step(ui, name, *watch, node, |ui| {
                let Some((device, _)) = &older else {
                    return;
                };
                let kind = if device.kind == TrustedDeviceKind::Watch {
                    "Apple Watch"
                } else {
                    "iPhone"
                };
                kit::paragraph(
                    ui,
                    format!(
                        "An older {kind} '{}' is still paired. Remove it?",
                        device.name
                    ),
                    Font::Callout,
                    kit::palette().label,
                );
                ui.horizontal(|ui| {
                    remove_older = kit::button(ui, "Remove", Style::Bordered).clicked();
                    keep_older = kit::button(ui, "Keep", Style::Bordered).clicked();
                });
                ui.add_space(8.0);
            });
            return;
        }
        if let Some(added) = &added {
            // A confirmation whose keys the vault did not keep: the result and Done.
            kit::tone_note(ui, added, Tone::Critical);
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| {
                    if kit::button(ui, "Done", Style::Prominent).clicked() {
                        choice = Some(StepChoice::Done);
                    }
                },
            );
            return;
        }
        if let Some(pending) = &asking {
            let (shown, found) = split_linked_device_name(&pending.device_name);
            let kind = match found {
                Some((LinkedDeviceKind::Iphone, _)) => Kind::Iphone,
                Some((LinkedDeviceKind::Watch, _)) => Kind::Watch,
                None => Kind::Mac,
            };
            let words = bound_words
                .as_deref()
                .or(pending.safety.as_deref())
                .unwrap_or_default();
            choice = devices::join_step(ui, &shown, kind, words, route, !deciding, |ui| {
                if kind == Kind::Watch {
                    // What a watch can do is visible before Touch ID (ADR 0039 §2).
                    ui.add_space(6.0);
                    kit::note(ui, WATCH_CONFIRM_LINE);
                }
                extra(ui, &mut check, &mut new_link, &mut refuse_old);
            });
            return;
        }
        if let Some((iphone, _)) = &moving {
            choice = devices::move_step(
                ui,
                iphone,
                MovePhase::Scan,
                Some(&step),
                |ui| qr_view(ui, MOVE_QR_POINTS),
                |ui| extra(ui, &mut check, &mut new_link, &mut refuse_old),
            );
            return;
        }
        choice = devices::link_step(
            ui,
            &step,
            |ui| qr_view(ui, LINK_QR_POINTS),
            |ui| extra(ui, &mut check, &mut new_link, &mut refuse_old),
        );
    });
    if remove_older || keep_older {
        if let Some(add) = app.sync.relay.add.as_mut()
            && !add.older.is_empty()
        {
            add.older.remove(0);
        }
        if remove_older && let Some((device, team)) = older {
            app.ask_owner(OwnerRequest::RemoveOlderIphone { device, team }, Some(ctx));
        }
        return false;
    }
    if check {
        app.relay_add_mac_poll();
    } else if let Some(link_id) = refuse_old {
        app.relay_refuse_link(link_id);
    } else if new_link {
        app.relay_add_iphone_start(&entry.id);
    }
    match choice {
        Some(StepChoice::Copy) => {
            if let Some(link) = &link {
                ctx.copy_text(link.to_string());
                app.set_ok("The link is copied. It works once, for 10 minutes.");
            }
        }
        Some(StepChoice::NewLink) => app.relay_add_iphone_start(&entry.id),
        Some(StepChoice::Confirm) => {
            if let Some(pending) = &asking {
                app.relay_ask_confirm(pending.id, Some(ctx));
            }
        }
        Some(StepChoice::Refuse) => {
            if let Some(pending) = &asking {
                app.relay_refuse_link(pending.id);
            }
        }
        Some(StepChoice::Later) => {
            app.questions_move_seen(true);
            super::cancel_sheet(app, ctx);
        }
        Some(StepChoice::Cancel | StepChoice::Done | StepChoice::TryAgain) => {
            super::cancel_sheet(app, ctx);
        }
        None => {}
    }
    // After the join there is no cancel: the end of the move runs.
    response.escape && !removing
}

/// The title of the confirmation of a watch link (ADR 0039 §2).
pub(crate) fn watch_confirm_title(name: &str) -> String {
    format!("Connect Apple Watch “{name}”")
}

/// What a watch can do, under [`watch_confirm_title`].
pub(crate) const WATCH_CONFIRM_LINE: &str = "This watch can allow an access request once while it is unlocked on a wrist. It cannot approve runs or change access.";

/// Whether the `device_name` of a link ends in the marker and key of an Apple Watch.
pub(crate) fn link_is_watch(device_name: &str) -> bool {
    matches!(
        split_linked_device_name(device_name).1,
        Some((LinkedDeviceKind::Watch, _))
    )
}

/// The name of a device of the relay for a list: the name without the answer key, with
/// "(Apple Watch)" after the name of a watch.
pub(crate) fn link_device_label(device_name: &str) -> String {
    match split_linked_device_name(device_name) {
        (name, Some((LinkedDeviceKind::Watch, _))) => {
            crate::questions::device_link::watch_label(&name)
        }
        (name, _) => name,
    }
}

/// The devices of `kind` that a new device of that kind may replace: the same name, or
/// a device in the team. A new watch never offers to remove an iPhone, nor the reverse.
fn older_devices(
    devices: Vec<crate::vault::TrustedDevice>,
    new_key: &[u8],
    name: &str,
    team: &str,
    kind: TrustedDeviceKind,
) -> Vec<(crate::vault::TrustedDevice, String)> {
    devices
        .into_iter()
        .filter(|d| {
            d.kind == kind
                && d.sign_key != new_key
                && (d.name == name || d.relay_devices.contains_key(team))
        })
        .map(|d| (d, team.to_owned()))
        .collect()
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
            &format!(
                concat!(crate::computers_cap!(), " that sync “{}”"),
                entry.name
            ),
            Some(concat!(
                "Each ",
                crate::computer!(),
                " has its own key on the relay. A removed ",
                crate::computer!(),
                " keeps its copy of the vault and the passphrase: to lock a person out, also change the passphrase and rotate each credential."
            )),
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
                                        kit::text(link_device_label(&device.name), Font::Body)
                                            .color(kit::palette().label),
                                    )
                                    .wrap(),
                                );
                                if device.current {
                                    kit::tag(
                                        ui,
                                        concat!("This ", crate::computer!()),
                                        Tone::Neutral,
                                    );
                                }
                            });
                            let seen = device.last_seen_at.map_or_else(
                                || "Not seen yet".to_owned(),
                                |at| format!("Last seen {}", ago(at)),
                            );
                            ui.add(
                                Label::new(
                                    kit::text(seen, Font::Footnote).color(kit::palette().secondary),
                                )
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
                                ask = Some((device.id, link_device_label(&device.name)));
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
                    "It keeps its vault but stops syncing, and it can no longer answer the questions of this vault: Apassy makes a new question key. To add it again you need a new link and the owner check.",
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
                concat!("The key of this ", crate::computer!(), " for the relay is in the vault. Open and unlock the vault to turn relay sync off: the key then leaves the vault, and this ", crate::computer!(), " leaves the relay team.")
            }
            (true, Some(true)) => {
                concat!("Apassy stops merging this vault, and its key for the relay leaves the vault. The vault on this ", crate::computer!(), " stays. This ", crate::computer!(), " is the last ", crate::computer!(), " of the relay team: the copy on the relay stays unless you delete it now.")
            }
            (true, _) => {
                concat!("Apassy stops merging this vault, and this ", crate::computer!(), " leaves the relay team. The vault on this ", crate::computer!(), " stays. The copy on the relay stays, and your other ", crate::computers!(), " keep syncing with it. To sync this ", crate::computer!(), " again, add it from another ", crate::computer!(), ".")
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
                    Some(concat!(
                        "Apassy deletes every version of the copy on the relay. The vault on this ",
                        crate::computer!(),
                        " stays."
                    )),
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
        concat!(
            "On the ",
            crate::computer!(),
            " that has the vault, open Settings > Vault > Sync, select “Add a device…”, and copy the link. Paste it here. Both ",
            crate::computers!(),
            " then show the same two words."
        ),
        Font::Callout,
        kit::palette().secondary,
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
            submit = ready_fields(app, ui);
        }
        Some(view) => join_progress(ui, view),
    }
    if let Some(error) = app.sync.relay.join_error.clone() {
        kit::paragraph(ui, error, Font::Callout, kit::palette().secondary);
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

/// The passphrase and the name of a downloaded copy. Returns true on Enter.
fn ready_fields(app: &mut DesktopApp, ui: &mut egui::Ui) -> bool {
    let mut submit = false;
    kit::section(
        ui,
        None,
        Some(concat!(
            "Use the passphrase of the vault on the other ",
            crate::computer!(),
            ". Apassy keeps a local copy on this ",
            crate::computer!(),
            "."
        )),
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
            submit =
                field.lost_focus() && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
            // The name of the vault here (frame 10c: "Name on this Mac").
            s.field(concat!("Name on this ", crate::computer!()), |ui| {
                kit::text_input(
                    ui,
                    &mut app.vault_list.name_input,
                    "vault-relay-name",
                    "Name",
                )
            });
        },
    );
    submit
}

/// The lead of "Use a vault from another Mac" › "Apassy Connect" (mockup frame 10a).
pub(crate) const CONNECT_OPEN_LEAD: &str =
    "Your vaults in Apassy Connect. Open one with its passphrase.";
/// The list is empty (frame 10b).
pub(crate) const CONNECT_OPEN_EMPTY: &str = concat!(
    "No vault waits for this ",
    crate::computer!(),
    ". On the other ",
    crate::computer!(),
    ", choose Apassy Connect in Settings › Vault › Sync."
);
/// The button of a vault store in the list.
pub(crate) const CONNECT_OPEN_USE: &str = "Use This Vault…";
/// No account file on this computer: it joins the account first.
pub(crate) const CONNECT_OPEN_JOIN: &str = concat!(
    "This ",
    crate::computer!(),
    " is not in an Apassy Connect account yet."
);
/// The account file of this computer is of an earlier version of Apassy.
pub(crate) const CONNECT_OPEN_OLD_FILE: &str = concat!(
    "This ",
    crate::computer!(),
    "'s account file is from an earlier Apassy. Forget the account in Settings › Connect, then join it again."
);
/// The key of the account is being read for this step.
pub(crate) const CONNECT_OPEN_SIGNING_IN: &str = "Apassy signs in to Apassy Connect…";
/// The list loads.
pub(crate) const CONNECT_OPEN_LOADING: &str = "Apassy asks Apassy Connect for your vaults…";

/// "Use a vault from another Mac" › "Apassy Connect" (plan s7 unit M5; mockup frames 10a
/// to 10c): the vault stores of the account that list this Mac and are not on it yet,
/// each with "Use This Vault…"; then the download, the passphrase of the vault, and the
/// new vault with sync through Apassy Connect. The screen is drawn while no vault is
/// unlocked: the account session opens for this step only (`live::start_path`), and a
/// computer without an account file joins the account here first, with the same sheets
/// as Settings › Connect.
pub(super) fn connect_open_screen(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use super::super::connect::live::{self, StartAccount};
    use super::super::connect::{ADD_THIS_MAC, Action, CHECK_AGAIN, SIGN_IN, TRY_AGAIN};
    let ctx = ui.ctx().clone();
    app.relay_join_step(Some(&ctx));
    let view = app.sync.relay.join_view(None);
    let mut cancel = false;
    let mut submit = false;
    let mut chosen = None;
    let mut join = false;
    let mut sign_in = false;
    let mut again = false;
    let spinner = |ui: &mut egui::Ui, text: &str| {
        ui.horizontal(|ui| {
            kit::spinner(ui, 12.0);
            ui.label(rows_note(text));
        });
    };
    match &view {
        None => {
            let account = live::start_account(app);
            if !matches!(account, StartAccount::Join { .. }) {
                kit::paragraph(
                    ui,
                    CONNECT_OPEN_LEAD,
                    Font::Callout,
                    kit::palette().secondary,
                );
                ui.add_space(14.0);
            }
            match account {
                StartAccount::Join { error } => {
                    kit::paragraph(
                        ui,
                        CONNECT_OPEN_JOIN,
                        Font::Callout,
                        kit::palette().secondary,
                    );
                    ui.add_space(14.0);
                    join = kit::wide_button(ui, ADD_THIS_MAC, Style::Bordered).clicked();
                    ui.add_space(8.0);
                    kit::paragraph(
                        ui,
                        super::super::connect::START_NO_DEVICE,
                        Font::Callout,
                        kit::palette().secondary,
                    );
                    if let Some(error) = error {
                        ui.add_space(4.0);
                        kit::paragraph(ui, error, Font::Callout, Tone::Critical.text());
                    }
                }
                StartAccount::OldFile => kit::paragraph(
                    ui,
                    CONNECT_OPEN_OLD_FILE,
                    Font::Callout,
                    kit::palette().secondary,
                ),
                StartAccount::Opening => spinner(ui, CONNECT_OPEN_SIGNING_IN),
                StartAccount::SignedOut { note } => {
                    kit::paragraph(ui, CONNECT_SIGN_IN, Font::Callout, kit::palette().secondary);
                    if let Some(note) = note {
                        kit::paragraph(ui, note, Font::Callout, Tone::Critical.text());
                    }
                    ui.add_space(8.0);
                    sign_in = kit::small_button(ui, SIGN_IN, Style::Bordered).clicked();
                }
                StartAccount::Removed { note } => {
                    kit::paragraph(ui, note, Font::Callout, kit::palette().secondary);
                }
                StartAccount::Open => match app.relay_connect_stores(&ctx).cloned() {
                    None => spinner(ui, CONNECT_OPEN_LOADING),
                    Some(Err(text)) => {
                        kit::paragraph(ui, sentence(&text), Font::Callout, Tone::Critical.text());
                        ui.add_space(8.0);
                        again = kit::small_button(ui, TRY_AGAIN, Style::Bordered).clicked();
                    }
                    Some(Ok(stores)) if stores.is_empty() => {
                        kit::paragraph(
                            ui,
                            CONNECT_OPEN_EMPTY,
                            Font::Callout,
                            kit::palette().secondary,
                        );
                        ui.add_space(8.0);
                        again = kit::small_button(ui, CHECK_AGAIN, Style::Bordered).clicked();
                    }
                    Some(Ok(stores)) => {
                        kit::section(ui, Some("Vaults in Apassy Connect"), None, |s| {
                            for store in &stores {
                                let subtitle = if store.shared {
                                    "Shared vault"
                                } else {
                                    "Your vault"
                                };
                                s.row(|ui| {
                                    egui::Sides::new().shrink_left().show(
                                        ui,
                                        |ui| {
                                            ui.vertical(|ui| {
                                                ui.spacing_mut().item_spacing.y = 1.0;
                                                ui.label(
                                                    kit::text(&store.name, Font::Body)
                                                        .color(kit::palette().label),
                                                );
                                                ui.label(rows_note(subtitle));
                                            });
                                        },
                                        |ui| {
                                            if kit::small_button(
                                                ui,
                                                CONNECT_OPEN_USE,
                                                Style::Bordered,
                                            )
                                            .clicked()
                                            {
                                                chosen = Some(store.clone());
                                            }
                                        },
                                    );
                                });
                            }
                        });
                    }
                },
            }
        }
        Some(JoinView::Ready { team }) => {
            join_progress(ui, &JoinView::Ready { team: team.clone() });
            ui.add_space(10.0);
            submit = ready_fields(app, ui);
        }
        Some(view) => join_progress(ui, view),
    }
    if let Some(error) = app.sync.relay.join_error.clone() {
        kit::paragraph(ui, error, Font::Callout, kit::palette().secondary);
    }
    ui.add_space(8.0);
    match &view {
        None => {}
        Some(JoinView::Ready { .. }) => {
            submit |= kit::wide_button(ui, "Use this vault", Style::Prominent).clicked();
            cancel = kit::small_button(ui, "Cancel", Style::Link).clicked();
        }
        Some(JoinView::Opening { .. }) => {}
        Some(_) => {
            cancel = kit::small_button(ui, "Cancel", Style::Link).clicked();
        }
    }
    // The join of this computer: the sheets of Settings › Connect.
    live::sheets(app, &ctx);
    if let Some(store) = chosen {
        app.relay_connect_use(store, Some(&ctx));
    } else if submit {
        app.relay_open_vault(Some(&ctx));
    } else if cancel {
        app.relay_join_cancel();
        app.relay_connect_forget_stores();
    } else if join {
        live::act(app, &ctx, Action::AddThisMac);
    } else if sign_in {
        live::start_sign_in(app, Some(&ctx));
    } else if again {
        app.relay_connect_forget_stores();
    }
}

/// A gray note line of the open screen.
fn rows_note(text: &str) -> egui::RichText {
    kit::text(text, Font::Callout).color(kit::palette().secondary)
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
    // A vault store of the Connect account: the sheet names the copy, and an owner check
    // names it again before anything is taken.
    let connect = app
        .relay_of(&entry.id)
        .is_some_and(|relay| relay.uses_account_key());
    if connect {
        return use_store_copy_sheet(app, ctx, entry, busy);
    }
    let mut use_copy = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-relay-use-copy", 500.0, |ui| {
        kit::sheet_title(
            ui,
            "Use the copy on the relay?",
            Some(&format!(
                concat!(
                    "This ",
                    crate::computer!(),
                    " refuses the copy of “{}” on the relay: it is older than the copy that this ",
                    crate::computer!(),
                    " saw last, or its history does not include the last change of this ",
                    crate::computer!(),
                    ". That happens when the relay comes back from a backup. Apassy can take the relay copy as it is now, merge it with the vault on this ",
                    crate::computer!(),
                    ", and upload the result. Nothing on this ",
                    crate::computer!(),
                    " is lost. First look at the ",
                    crate::computers!(),
                    " in “Devices…”, and remove a ",
                    crate::computer!(),
                    " that you do not know."
                ),
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

/// The text of "Use the relay copy…" for a vault store of the Connect account: which copy
/// it takes (`version`, the signed name of the device that signed it, its time), and that
/// the record of what this computer had merged is replaced.
pub(crate) fn store_copy_text(
    vault: &str,
    version: u64,
    device: Option<&str>,
    time: u64,
) -> String {
    let device = device.map_or_else(
        || concat!("a device that this ", crate::computer!(), " does not know").to_owned(),
        str::to_owned,
    );
    format!(
        concat!(
            "This ",
            crate::computer!(),
            " refuses the copy of “{vault}” on the relay: it is older than the copy that this ",
            crate::computer!(),
            " saw last, or its history does not include the last change of this ",
            crate::computer!(),
            ". The relay holds version {version}, which {device} saved on {day}. Apassy can take that copy, merge it with the vault on this ",
            crate::computer!(),
            ", and upload the result; this ",
            crate::computer!(),
            "'s record of the copies it had merged is replaced by that version. Nothing in the vault on this ",
            crate::computer!(),
            " is lost. Use it only if you know that device."
        ),
        vault = vault,
        version = version,
        device = device,
        day = crate::desktop::ui::connect::day(time),
    )
}

/// "Use the relay copy…" of a vault store of the Connect account: the sheet names the
/// copy that the relay holds now, and "Use This Copy…" asks for the owner check that names
/// it ([`DesktopApp::relay_ask_use_copy`]).
fn use_store_copy_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
    busy: bool,
) -> bool {
    let served = app.relay_served_copy(&entry.id);
    let mut use_copy = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "sync-relay-use-store-copy", 500.0, |ui| {
        let lead = match &served {
            Some((head, name)) => {
                store_copy_text(&entry.name, head.version, name.as_deref(), head.time)
            }
            None => {
                "Apassy cannot tell which copy the relay holds now. Sync again first.".to_owned()
            }
        };
        kit::sheet_title(ui, "Use the copy on the relay?", Some(&lead));
        progress(app, ui, &entry.id, Job::UseCopy);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                use_copy = ui
                    .add_enabled_ui(!busy && served.is_some(), |ui| {
                        kit::button(ui, "Use This Copy…", Style::Prominent)
                    })
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if use_copy {
        // The owner check takes the place of the sheet; the answer of the step shows in
        // the status of the vault.
        super::cancel_sheet(app, ctx);
        app.relay_ask_use_copy(&entry.id, Some(ctx));
    } else if cancel {
        super::cancel_sheet(app, ctx);
    }
    response.escape
}

/// "Use the Copy That … Left…" (`replace` false) or "Replace It with This Mac's Copy…"
/// (`replace` true): a vault store waits on the head that a device that left the account
/// pushed, and no live device signed over it. The owner takes that copy once, or replaces
/// it with the vault of this Mac. A copy that changed meanwhile closes the step: the row
/// shows its new state.
pub(super) fn departed_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
    replace: bool,
) -> bool {
    let job = if replace {
        Job::Replace
    } else {
        Job::UseDeparted
    };
    let busy = app.relay_busy(&entry.id, job);
    let departed = app.relay_departed(&entry.id);
    let mut go = false;
    let mut take = false;
    let mut cancel = false;
    let id = if replace {
        "sync-relay-replace-departed"
    } else {
        "sync-relay-use-departed"
    };
    let response = kit::sheet(ctx, id, 500.0, |ui| {
        match &departed {
            None if busy => kit::sheet_title(ui, job.progress(), None),
            None => kit::sheet_title(
                ui,
                "The copy on the relay changed",
                Some(
                    "Nothing changed. The state of the vault in Settings > Vault > Sync shows the copy as it is now.",
                ),
            ),
            Some(departed) if replace => kit::sheet_title(
                ui,
                &format!("Replace the copy that {} left?", departed.who_in()),
                Some(&format!(
                    concat!(
                        "{who} saved the last copy of “{vault}” on the relay {ago}, then left the account. Apassy can upload the vault of this ",
                        crate::computer!(),
                        " as a new version over it. Changes that only that copy had are lost; a change that another device still has comes back when that device syncs."
                    ),
                    who = departed.who(),
                    vault = entry.name,
                    ago = ago(departed.head.time),
                )),
            ),
            Some(departed) => kit::sheet_title(
                ui,
                &format!("Use the copy that {} left?", departed.who_in()),
                Some(&format!(
                    concat!(
                        "{who} saved the last copy of “{vault}” on the relay {ago}, then left the account. No device of the account has saved a copy over it, so this ",
                        crate::computer!(),
                        " waits. Apassy can take this copy once, merge it with the vault on this ",
                        crate::computer!(),
                        ", and upload the result. Take it only if you know the change. Nothing on this ",
                        crate::computer!(),
                        " is lost."
                    ),
                    who = departed.who(),
                    vault = entry.name,
                    ago = ago(departed.head.time),
                )),
            ),
        }
        progress(app, ui, &entry.id, job);
        kit::sheet_buttons(
            ui,
            |ui| {
                if replace && departed.is_some() {
                    go = ui
                        .add_enabled_ui(!busy, |ui| kit::button(ui, "Replace", Style::Destructive))
                        .inner
                        .clicked();
                }
            },
            |ui| {
                if !replace && departed.is_some() {
                    take = ui
                        .add_enabled_ui(!busy, |ui| {
                            kit::button(ui, "Use This Copy", Style::Prominent)
                        })
                        .inner
                        .clicked();
                }
                let close = if departed.is_some() {
                    "Cancel"
                } else {
                    "Close"
                };
                cancel = kit::button(ui, close, Style::Bordered).clicked();
            },
        );
    });
    if go || take {
        // A fresh owner check for exactly this head and this choice; the answer of the
        // relay closes the sheet.
        app.relay_ask_departed(&entry.id, replace, Some(ctx));
    }
    if cancel {
        super::cancel_sheet(app, ctx);
    }
    response.escape
}

#[cfg(test)]
mod access_repair_tests {
    use super::*;
    #[test]
    fn re_pair_offers_same_name_or_any_iphone_in_team_without_removing_them() {
        use crate::vault::{TrustedDevice, TrustedDeviceKind};
        let make = |id: &str, name: &str, kind, team: &str, key: u8| TrustedDevice {
            uuid: id.into(),
            name: name.into(),
            kind,
            relay_devices: std::collections::BTreeMap::from([(team.into(), 1)]),
            sign_key: vec![key],
            answer_key: None,
            created_at: 1,
            updated_at: 1,
            updated_by: "synthetic".into(),
        };
        let rows = vec![
            make("old", "iPhone", TrustedDeviceKind::Iphone, "other", 1),
            make(
                "other",
                "Different name",
                TrustedDeviceKind::Iphone,
                "team",
                2,
            ),
            make(
                "keep",
                "Other phone",
                TrustedDeviceKind::Iphone,
                "elsewhere",
                3,
            ),
            make("mac", "iPhone", TrustedDeviceKind::Mac, "team", 4),
            make("new", "iPhone", TrustedDeviceKind::Iphone, "team", 5),
        ];
        let selected = older_devices(
            rows.clone(),
            &[5],
            "iPhone",
            "team",
            TrustedDeviceKind::Iphone,
        );
        assert_eq!(
            selected
                .iter()
                .map(|r| r.0.uuid.as_str())
                .collect::<Vec<_>>(),
            vec!["old", "other"]
        );
        assert_eq!(rows.len(), 5);
    }

    /// A new watch offers to remove an older watch only, and a new iPhone never offers
    /// a watch (ADR 0039).
    #[test]
    fn a_new_watch_and_a_new_iphone_offer_only_their_own_kind() {
        use crate::vault::TrustedDevice;
        let make = |id: &str, kind, key: u8| TrustedDevice {
            uuid: id.into(),
            name: "Test".into(),
            kind,
            relay_devices: std::collections::BTreeMap::from([("team".into(), 1)]),
            sign_key: vec![key],
            answer_key: None,
            created_at: 1,
            updated_at: 1,
            updated_by: "synthetic".into(),
        };
        let rows = vec![
            make("phone", TrustedDeviceKind::Iphone, 1),
            make("old-watch", TrustedDeviceKind::Watch, 2),
            make("mac", TrustedDeviceKind::Mac, 3),
            make("new-watch", TrustedDeviceKind::Watch, 4),
        ];
        let uuids = |kind, key: u8| {
            older_devices(rows.clone(), &[key], "Test", "team", kind)
                .into_iter()
                .map(|r| r.0.uuid)
                .collect::<Vec<_>>()
        };
        assert_eq!(uuids(TrustedDeviceKind::Watch, 4), ["old-watch"]);
        assert_eq!(uuids(TrustedDeviceKind::Iphone, 5), ["phone"]);
    }

    #[test]
    fn a_watch_link_shows_its_kind() {
        let key = crate::sync::DeviceKey::generate().unwrap();
        let watch =
            crate::questions::device_link::watch_link_device_name("Test Watch", key.public_key())
                .unwrap();
        let phone =
            crate::questions::device_link::link_device_name("Test iPhone", key.public_key())
                .unwrap();
        assert!(link_is_watch(&watch));
        assert!(!link_is_watch(&phone));
        assert!(!link_is_watch("Mac mini"));
        assert_eq!(link_device_label(&watch), "Test Watch (Apple Watch)");
        assert_eq!(link_device_label(&phone), "Test iPhone");
        assert_eq!(link_device_label("Mac mini"), "Mac mini");
        assert_eq!(
            watch_confirm_title("Test Watch"),
            "Connect Apple Watch “Test Watch”"
        );
    }

    /// The plan states of a vault store of Apassy Connect (plan s7 unit M3): the tag
    /// and the sentence name the state and its date, say when the changes made here go
    /// up, and never name a price or a purchase (plans section 5).
    #[test]
    fn the_connect_states_say_what_works_with_their_date() {
        use crate::sync::StorePlan;
        let read_only = ConnectState::refused(Some(StorePlan::ReadOnly {
            until: Some(1_799_020_800),
        }));
        assert_eq!(
            read_only,
            ConnectState::ReadOnly {
                until: Some(1_799_020_800)
            }
        );
        let words = connect_words(read_only);
        assert!(
            words.starts_with("Connect: read-only until 4 Jan 2027."),
            "{words}"
        );
        assert!(
            words.contains("Changes made here upload when the plan is active again."),
            "{words}"
        );
        assert_eq!(connect_tag(read_only).0, "Connect: read-only");
        assert_eq!(
            ConnectState::refused(None),
            ConnectState::ReadOnly { until: None },
            "a refusal before the plan is known is read-only too"
        );
        assert!(connect_words(ConnectState::refused(None)).starts_with("Connect: read-only."));
        let past_due = ConnectState::PastDue {
            last: None,
            grace_until: Some(1_796_860_800),
        };
        assert_eq!(connect_tag(past_due).0, "Connect: past due");
        assert!(
            connect_words(past_due).contains("Sync works until 10 Dec 2026"),
            "{}",
            connect_words(past_due)
        );
        assert!(
            connect_words(ConnectState::SignedOut).contains("Settings › Connect"),
            "the way on"
        );
        for state in [
            read_only,
            past_due,
            ConnectState::Suspended {
                delete_at: Some(1_805_000_000),
            },
            ConnectState::SignedOut,
        ] {
            let text = connect_words(state);
            for refused in ["€", "$", "Buy", "Subscribe", "Upgrade", "free"] {
                assert!(!text.contains(refused), "{refused}: {text}");
            }
            // The status of a store is a warning in every state.
            assert_eq!(connect_tag(state).1, Tone::Warning);
            assert_eq!(UiStatus::Connect(state).tag().0, connect_tag(state).0);
        }
        // The words of the setup and of the move follow the same rules.
        for text in [
            CONNECT_SETUP_WORDS,
            CONNECT_NEEDS_PLAN,
            MOVE_WORDS,
            MOVE_BOTH_COPIES,
            MOVE_OLD_DELETED,
        ] {
            for refused in ["€", "Buy", "Subscribe", "Upgrade", "paid"] {
                assert!(!text.contains(refused), "{refused}: {text}");
            }
        }
    }
}

#[cfg(test)]
mod departed_tests {
    use super::*;

    /// "Use the relay copy…" names a device of another account of a shared vault by its
    /// verified name and person, and a key that no list holds as unknown.
    #[test]
    fn the_copy_of_a_co_member_names_its_verified_device() {
        let mut app = DesktopApp::new();
        let key = vec![4; 65];
        app.sync.relay.shared_devices.insert(
            key.clone(),
            ("Synthetic MacBook".to_owned(), "“Ola”".to_owned()),
        );
        assert_eq!(
            app.relay_signed_name(&key).as_deref(),
            Some("“Synthetic MacBook” of “Ola”")
        );
        assert_eq!(app.relay_signed_name(&[5; 65]), None);
        let text = store_copy_text("Family", 7, app.relay_signed_name(&key).as_deref(), 0);
        assert!(
            text.contains("which “Synthetic MacBook” of “Ola” saved"),
            "{text}"
        );
        let text = store_copy_text("Family", 7, None, 0);
        assert!(text.contains("does not know"), "{text}");
    }

    fn head() -> DepartedHead {
        DepartedHead {
            key: vec![4; 65],
            device_id: 3,
            version: 7,
            head_hash: "ab".repeat(32),
            time: 1_700_000_000,
        }
    }

    fn collect(shape: &egui::Shape, out: &mut String) {
        match shape {
            egui::Shape::Text(text) => {
                out.push_str(text.galley.text());
                out.push('\n');
            }
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, out);
                }
            }
            _ => {}
        }
    }

    /// The text that the screen of a device that joins paints for `view`.
    fn painted(view: &JoinView) -> String {
        let ctx = egui::Context::default();
        let mut text = String::new();
        for _ in 0..2 {
            let output = ctx.run_ui(egui::RawInput::default(), |ui| join_progress(ui, view));
            text.clear();
            for clipped in &output.shapes {
                collect(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        text
    }

    /// A device that joins has no copy of the vault: it can take the copy that a removed
    /// device left, named by its signed name, and it is offered no "Replace…".
    #[test]
    fn a_new_device_is_offered_the_copy_that_a_removed_device_left_and_no_replace() {
        let departed = Departed {
            head: head(),
            name: Some("Synthetic Mac mini".to_owned()),
            person: None,
        };
        let text = painted(&JoinView::Departed {
            words: departed.words(),
            label: departed.use_label(),
        });
        assert!(
            text.contains("Use the Copy That “Synthetic Mac mini” Left…"),
            "{text}"
        );
        assert!(
            text.contains("“Synthetic Mac mini” saved the last copy"),
            "{text}"
        );
        assert!(!text.contains(REPLACE_DEPARTED), "{text}");
        assert!(!text.contains("Replace"), "{text}");
    }

    /// Without a verified device list in memory the steps use a neutral phrase.
    #[test]
    fn without_a_verified_list_the_device_is_not_named() {
        let departed = Departed {
            head: head(),
            name: None,
            person: None,
        };
        assert_eq!(
            departed.use_label(),
            "Use the Copy That a Removed Device Left…"
        );
        assert!(
            departed
                .words()
                .starts_with("A device that left the account saved the last copy"),
            "{}",
            departed.words()
        );
        assert_eq!(departed.who_in(), "a device that left the account");
    }

    /// A chain entry by a device that this computer has not learned yet is a wait for the
    /// device list, never the refused-copy offer; only a fresh list that still refuses it
    /// offers "Use the relay copy…".
    #[test]
    fn a_chain_entry_of_an_unknown_device_waits_for_the_list_before_the_offer() {
        let checking = UiStatus::from_error(SyncError::ChecksDeviceList);
        assert_eq!(tag(&checking), ("Checking the device list", Tone::Accent));
        assert!(!refused_copy(&checking));
        assert!(
            words(&checking, None).starts_with("Checking the device list of this account."),
            "{}",
            words(&checking, None)
        );
        let refused = UiStatus::from_error(SyncError::UnknownSigner);
        assert_eq!(tag(&refused), ("Relay copy refused", Tone::Warning));
        assert!(refused_copy(&refused));
        assert!(
            words(&refused, None).contains("“Use the relay copy…”"),
            "{}",
            words(&refused, None)
        );
        // A real fork stays the refused copy that it was.
        assert!(refused_copy(&UiStatus::from_error(SyncError::ForkedCopy)));
    }
}
