//! The questions through the relay behind Settings > Devices (ADR 0025 §3e, ADR 0027,
//! stage 5 plan §A6 and §A7, contracts relay-questions-v1 and relay-connect-v1).
//!
//! Turning them on opens a new channel that can approve runs, so it passes the owner
//! check (`OwnerAction::EnableRelayQuestions`) before anything changes:
//!
//! - A vault that syncs through the relay: the sync membership gets the purpose
//!   `questions` ([`enable_questions`]), with no relay call.
//! - Any other vault: the first "Add a device" makes an Apassy Connect team, with no
//!   code and no relay address (ADR 0027 §4). After the check, `POST /v1/connect` runs on
//!   its own thread ([`create_connect_team`], no vault), then the vault keeps the
//!   membership ([`adopt_questions_team`]). The team never gets a snapshot; iCloud Drive
//!   stays the sync. "Use another relay…" (a self-hosted relay) asks for the relay
//!   address and an operator team code instead (`POST /v1/teams`,
//!   [`new_questions_team`]). A vault that has a questions team already (another Mac
//!   made it) never gets a second one: this Mac joins that team with a device link from
//!   a Mac in it ([`join_questions_team`]), confirmed there with the safety words and
//!   that Mac's owner check, after the owner check of this Mac.
//!
//! Either way the vault gets its question key when it has none, and this Mac registers
//! as a trusted device. Only these steps write the row of this Mac. Off needs no check:
//! it takes authority away. It removes the purpose `questions` and never touches relay
//! sync.
//!
//! "Add a device" (`super::super::devices`) links a device to the questions team: through
//! the sync team for a vault on the relay, through the questions team for the others.
//! The confirmation writes the row of an iPhone from the keys of its link
//! (`register_linked_device`); a Mac writes its own. Settings > Devices lists each trusted
//! device of the vault, with when the relay last saw it (`GET /v1/devices`, every 30
//! seconds while the list shows), and "Remove…" for each other device
//! ([`SyncSheet::RemoveQuestionsDevice`]): no owner check, it takes authority away. The
//! removal keeps the row with `deleted_at`, writes a new question key, and revokes the
//! device on the relay when this Mac can.
//!
//! A Connect team that the relay deleted after 30 days without use answers `401` at the
//! sign-in (relay SPEC §26.5; a suspended team answers so too until a sign-in wakes it).
//! Each read of the device list is tagged with its vault and team, and an answer for
//! another vault or team is dropped. Settings > Devices says the team is gone and keeps
//! asking, less often, so a `401` that passes heals by itself; a lock or another vault
//! forgets it. Nothing is deleted on a `401`: "Add a device" asks the relay once more,
//! then asks the owner "Connect again?". Only after that and the owner check does the
//! vault get a new Connect team, which takes the place of the old one in one vault
//! transaction ([`reconnect_questions_team`]). The same question comes when no Mac is
//! left in the questions team of the vault ("Stop approvals here" on the only Mac): no
//! device could add this Mac back.
//!
//! The team code and a pasted link stay in memory only from "Turn On…" or "Join…" to the
//! relay call. A lock, another sync sheet, and the end of the try erase them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroizing;

use super::super::kit::{self, Style, Tone};
use super::super::{forget_secret_field, secure_input};
use super::SyncSheet;
use super::relay::{TEAM_CODE_CAPACITY, TEAM_CODE_FIELD, call_error};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
use crate::desktop::owner_store::Ephemeral;
use crate::questions::{QuestionsClient, TeamDevice};
use crate::relay::membership::{
    QuestionsAvailability, adopt_questions_team, create_connect_team, disable_questions,
    enable_questions, join_questions_team, mac_in_team, new_questions_team, questions_availability,
    questions_membership, questions_only, reconnect_questions_team, this_device,
};
use crate::sync::{
    DEFAULT_RELAY_URL, DeviceKey, JoinedDevice, LinkPayloadError, PendingJoin, RelayLinkPayload,
    RelayRefusal, RelayUrl, SyncError, device_name, link_code_team, valid_team_code,
};
use crate::vault::{MembershipPurpose, RelayMembership, TrustedDeviceKind, VaultErrorKind};
use crate::vaults::VaultEntry;

/// How often Devices asks the relay for the push state of the devices.
const DEVICES_EVERY: Duration = Duration::from_secs(30);
/// The longest wait between two reads of a team that the relay no longer knows.
const GONE_EVERY_MAX: Duration = Duration::from_secs(600);
/// How often a Mac that joins the questions team asks whether the other Mac confirmed.
const JOIN_POLL_EVERY: Duration = Duration::from_secs(2);
/// The note of a Mac whose relay sync key was removed from the questions.
pub(crate) const REMOVED_SYNC: &str = "This Mac was removed from the questions of this vault. To answer and ask through the relay again, turn relay sync off and join the vault again from another Mac: that gives this Mac a new key.";
/// A relay without `POST /v1/connect` (before relay-connect-v1).
pub(crate) const CONNECT_UNAVAILABLE: &str = "Apassy Connect is not available yet on this relay. On this Wi-Fi, pair on this network instead.";
/// `503 busy` of `POST /v1/connect`: the relay made as many teams today as it takes.
pub(crate) const CONNECT_BUSY: &str =
    "Apassy Connect takes no new vaults right now. Try again later, or pair on this network.";
/// The relay does not answer.
pub(crate) const CONNECT_UNREACHABLE: &str = "Can't reach Apassy Connect.";
/// The Connect team of the vault is gone: the relay deleted it after 30 days without use.
pub(crate) const CONNECT_GONE: &str = "Apassy Connect no longer knows this vault: it was not used for 30 days. Add a device to connect again.";
/// The question before a new Connect team takes the place of one that the relay forgot.
pub(crate) const CONNECT_AGAIN: &str =
    "Apassy Connect no longer knows this vault's team. Connect again?";
/// The same question when no Mac is left in the questions team of the vault.
pub(crate) const CONNECT_AGAIN_NO_MAC: &str = "No Mac of this vault is in its Apassy Connect team now, so no device can add this Mac back. Connect again?";
/// What connecting again does.
pub(crate) const CONNECT_AGAIN_NOTE: &str = "Apassy makes a new team for this vault. Your iPhones and your other Macs connect again with a new code from Add a device. Connecting needs Touch ID or your passphrase.";

/// A join of the questions team that waits for the owner check. Debug shows no link.
struct JoinRequest {
    vault: String,
    team_id: String,
    url: String,
    link: Zeroizing<String>,
    device: String,
}

/// A Mac that joins the questions team of the vault.
enum JoinPhase {
    /// `POST /v1/devices/link` with a new key.
    Requesting(Task<Result<PendingJoin, SyncError>>),
    /// The other Mac shows the same words; it confirms there.
    Waiting {
        pending: Arc<PendingJoin>,
        poll: Option<Task<Result<Option<JoinedDevice>, SyncError>>>,
        next: Instant,
    },
}

struct Joining {
    vault: String,
    team_id: String,
    device: String,
    phase: JoinPhase,
}

/// A removal of a trusted device whose relay devices this Mac revokes: in the questions
/// team, and in the relay sync team when that is another team.
struct Removing {
    name: String,
    task: Task<Revoked>,
}

/// What the relay said to each revocation of a removal; `None`: none was asked.
struct Revoked {
    questions: Option<Result<(), SyncError>>,
    sync: Option<Result<(), SyncError>>,
}

/// A team for the questions only that waits for the owner check. Debug shows no code.
struct NewTeam {
    /// The vault (list ID) and its name, the name of the team.
    vault: String,
    name: String,
    url: String,
    /// The operator team code of "Use another relay…"; `None`: an Apassy Connect team,
    /// with no code (`POST /v1/connect`).
    code: Option<Zeroizing<String>>,
    device: String,
    /// "Connect again": the questions team that the new team takes the place of.
    replaces: Option<String>,
}

/// The relay call that makes a team for the questions only.
struct Creating {
    vault: String,
    device: String,
    /// An Apassy Connect team of "Add a device".
    connect: bool,
    replaces: Option<String>,
    task: Task<Result<RelayMembership, SyncError>>,
}

/// A read of the devices of the questions team `team` of the vault `vault` (list ID).
/// Its answer counts only while that vault is open with that team.
struct DevicesRead {
    vault: String,
    team: String,
    task: Task<Result<Vec<TeamDevice>, SyncError>>,
}

/// A questions team that the relay no longer knows: the vault (list ID) and the team.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gone {
    vault: String,
    team: String,
}

/// The state of "Send questions through the relay" in the window.
#[derive(Default)]
pub(crate) struct QuestionsUi {
    pending: Option<NewTeam>,
    creating: Option<Creating>,
    /// Why the last try of the team sheet failed.
    pub(crate) error: Option<String>,
    /// The devices of the questions team on the relay, while the relay answers.
    devices: Option<DevicesRead>,
    devices_read: Option<Instant>,
    /// The wait before the next read while the team is gone: it doubles up to
    /// [`GONE_EVERY_MAX`], and a read that works sets it back.
    gone_every: Option<Duration>,
    /// "Add a device" asked the relay once more before "Connect again?".
    pub(crate) rechecking: bool,
    /// The devices of the team `push_team` as the relay said last, by relay device
    /// number: when it last saw each one, and its push state.
    team: BTreeMap<u64, TeamDevice>,
    push_team: Option<String>,
    /// The last answer of the relay about the devices failed: it does not answer.
    unreachable: bool,
    /// The relay answered `401` to the sign-in of a Connect team whose key was not
    /// removed: the relay deleted or suspended the team (relay SPEC §26.5).
    gone: Option<Gone>,
    /// The relay of Apassy Connect when it is not the Apassy relay: a fake relay on this
    /// computer, for the tests and the screenshot tour only.
    connect_url: Option<String>,
    repaint: Option<egui::Context>,
    /// A pasted link of the questions team that waits for the owner check.
    join_request: Option<JoinRequest>,
    /// This Mac joins the questions team: the safety words, then the confirmation.
    joining: Option<Joining>,
    /// The safety words of the join, for the sheet.
    pub(crate) join_words: Option<String>,
    /// The relay revokes a removed device.
    removing: Option<Removing>,
}

impl QuestionsUi {
    /// Whether an Apassy Connect team for the vault `id` waits for the owner check.
    pub(crate) fn connect_asked(&self, id: &str) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.vault == id && pending.code.is_none())
    }

    /// Give up an Apassy Connect team that waits for the owner check.
    pub(crate) fn forget_connect(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.code.is_none())
        {
            self.pending = None;
        }
    }

    /// Erase the team code and the link that wait for the owner check, and give up a
    /// join of the questions team: its key never reaches a vault.
    pub(crate) fn forget_codes(&mut self) {
        self.pending = None;
        self.join_request = None;
        self.join_words = None;
        if let Some(joining) = self.joining.take() {
            cancel_join(joining);
        }
    }

    /// Whether this Mac joins the questions team of the vault `id` now.
    pub(crate) fn joining(&self, id: &str) -> bool {
        self.joining
            .as_ref()
            .is_some_and(|joining| joining.vault == id)
    }

    /// Whether the relay makes the team of the vault `id` now.
    pub(crate) fn creating(&self, id: &str) -> bool {
        self.creating
            .as_ref()
            .is_some_and(|creating| creating.vault == id)
    }

    /// Whether the relay no longer knows the questions team `team` of the vault `id`.
    pub(crate) fn gone(&self, id: &str, team: &str) -> bool {
        self.gone
            .as_ref()
            .is_some_and(|gone| gone.vault == id && gone.team == team)
    }

    /// The open vault changed or locked: what the relay said of its team goes, and a read
    /// that runs no longer counts.
    pub(crate) fn forget_vault(&mut self) {
        self.team.clear();
        self.push_team = None;
        self.devices = None;
        self.devices_read = None;
        self.gone_every = None;
        self.rechecking = false;
        self.unreachable = false;
        self.gone = None;
    }
}

/// What Settings > Devices knows of the questions team of the open vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuestionsTeamView {
    pub(crate) team_id: String,
    /// A team of the questions only (Apassy Connect, or a notifications-only team): no
    /// snapshot goes through it.
    pub(crate) questions_only: bool,
    /// The trusted device UUID of this Mac in the team.
    pub(crate) me: Option<String>,
    /// The devices of the team as the relay said last, by relay device number.
    pub(crate) devices: BTreeMap<u64, TeamDevice>,
    /// The relay did not answer the last time.
    pub(crate) unreachable: bool,
    /// The relay deleted the team ([`CONNECT_GONE`]).
    pub(crate) gone: bool,
}

/// What the removal of a trusted device means, for its confirmation.
pub(crate) fn removal_words(kind: TrustedDeviceKind, icloud: bool) -> String {
    let device = match kind {
        TrustedDeviceKind::Mac => "this Mac",
        TrustedDeviceKind::Iphone => "this iPhone",
    };
    let mut words = format!(
        "It can no longer answer the questions of this vault, and Apassy makes a new question key, so {device} cannot read the next questions. Apassy also removes it from the relay when this Mac can, so it gets no more notifications. To answer again it needs a new link and your confirmation."
    );
    if icloud {
        words.push_str(
            " This vault syncs through iCloud Drive (a folder): the device keeps its copy of the vault until you remove the vault from it or from iCloud Drive. It can no longer answer.",
        );
    }
    words
}

impl DesktopApp {
    /// The relay where "Add a device" makes the Apassy Connect team of a vault with no
    /// team: the Apassy relay.
    pub(crate) fn connect_relay_url(&self) -> String {
        self.sync
            .relay
            .questions
            .connect_url
            .clone()
            .unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned())
    }

    /// Make Apassy Connect use the relay at `url` on this computer (`http://127.0.0.1:…`
    /// or `http://localhost:…`): the fake relay of the tests and of the screenshot tour
    /// (`examples/screenshots.rs`), its only callers. No path of the app calls it. Any
    /// other address is refused, so it cannot send the devices of a vault to another
    /// server. Returns whether it took the address.
    #[doc(hidden)]
    pub fn set_connect_relay_url(&mut self, url: &str) -> bool {
        let local = |url: &str| {
            ["http://127.0.0.1:", "http://localhost:"]
                .iter()
                .any(|prefix| url.starts_with(prefix))
        };
        // The address as the relay client reads it must be on this computer too.
        let Some(parsed) = RelayUrl::parse(url)
            .ok()
            .filter(|parsed| local(url) && local(parsed.as_str()))
        else {
            return false;
        };
        self.sync.relay.questions.connect_url = Some(parsed.as_str().to_owned());
        true
    }

    pub(crate) fn wake_questions(&self) {
        if let Some(questions) = &self.owner.questions {
            questions.wake();
        }
    }

    /// The questions go on for this Mac: the owner check for the relay sync team of the
    /// vault, or the sheet that joins the questions team of the vault. Nothing changes
    /// before the check passes.
    pub(crate) fn questions_turn_on(&mut self, ctx: Option<&egui::Context>) {
        let state = self.owner_ui.session.with_vault(|vault| {
            if vault.is_locked() {
                return None;
            }
            let availability = questions_availability(vault).ok()?;
            let url = vault
                .relay_device()
                .ok()
                .flatten()
                .map(|device| device.relay_url);
            // No Mac is left in the team to add this one back.
            let no_mac = match &availability {
                QuestionsAvailability::JoinTeam { team_id } => !mac_in_team(vault, team_id).ok()?,
                _ => false,
            };
            Some((availability, url, no_mac))
        });
        match state.flatten() {
            None => self.set_err("Unlock the vault first."),
            Some((QuestionsAvailability::JoinTeam { team_id }, _, true)) => {
                self.devices_offer_connect_again(&team_id, false);
            }
            Some((QuestionsAvailability::On { .. }, _, _)) => {}
            Some((QuestionsAvailability::Removed { sync: true, .. }, _, _)) => {
                self.set_err(REMOVED_SYNC);
            }
            Some((QuestionsAvailability::Removed { sync: false, .. }, _, _)) => {
                // The removed key goes; this Mac joins the team again with a new one.
                let dropped = self
                    .owner_ui
                    .session
                    .with_vault(|vault| disable_questions(vault).is_ok());
                if dropped != Some(true) {
                    return self.set_err("Unlock the vault first.");
                }
                self.wake_questions();
                self.questions_open_team_sheet(ctx);
            }
            Some((QuestionsAvailability::CanTurnOn { team_id }, Some(relay_url), _)) => self
                .ask_owner(
                    OwnerRequest::EnableRelayQuestions {
                        relay_url,
                        team_id: Some(team_id),
                    },
                    ctx,
                ),
            Some(_) => self.questions_open_team_sheet(ctx),
        }
    }

    /// The sheet of a notifications-only team: a new team, or a join of the team that
    /// the vault has.
    fn questions_open_team_sheet(&mut self, ctx: Option<&egui::Context>) {
        match self.vault_list.current.clone() {
            Some(id) => self.sync_open_sheet(SyncSheet::QuestionsTeam { id }, ctx),
            None => self.set_err("Open a vault of the list first."),
        }
    }

    /// "Stop approvals here": no check, it takes authority away. Relay sync never
    /// changes.
    pub(crate) fn questions_turn_off(&mut self) {
        let result = self.owner_ui.session.with_vault(|vault| {
            if vault.is_locked() {
                return Err("Unlock the vault first.".to_owned());
            }
            disable_questions(vault)
                .map(|_| ())
                .map_err(|error| format!("Apassy could not turn it off: {error}"))
        });
        match result.unwrap_or_else(|| Err("Unlock the vault first.".to_owned())) {
            Ok(()) => {
                self.wake_questions();
                self.sync.relay.questions.forget_vault();
                self.set_note(
                    "Approvals stop here. Questions stay on this Mac and the iPhones on this Wi-Fi.",
                );
            }
            Err(message) => self.set_err(message),
        }
    }

    /// Wait for the relay call of a new team and take its answer, for a test.
    #[cfg(test)]
    pub(crate) fn questions_settle_for_test(&mut self) {
        let ctx = egui::Context::default();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.questions_poll(&ctx);
            let busy = self.sync.relay.questions.creating.is_some()
                || self.sync.relay.questions.devices.is_some()
                || self.sync.relay.questions.removing.is_some();
            if !busy || Instant::now() > deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Take an answer of a read of the devices of the team `team` of the vault `vault`, as
    /// if the relay gave it, for a test.
    #[cfg(test)]
    pub(crate) fn questions_answer_for_test(
        &mut self,
        vault: &str,
        team: &str,
        answer: Result<Vec<TeamDevice>, SyncError>,
    ) {
        let read = DevicesRead {
            vault: vault.to_owned(),
            team: team.to_owned(),
            task: Task::spawn(None, || Ok(Vec::new())),
        };
        self.questions_devices_read(&read, Some(answer));
    }

    /// The message of a removal whose revocations ended with `questions` and `sync`, for
    /// a test.
    #[cfg(test)]
    pub(crate) fn questions_revoked_for_test(
        &mut self,
        name: &str,
        questions: Option<Result<(), SyncError>>,
        sync: Option<Result<(), SyncError>>,
    ) {
        self.questions_revoked(name, Some(Revoked { questions, sync }));
    }

    /// "Turn On…" of the team sheet: the fields are checked, then the owner check. The
    /// team code waits in memory for the check only.
    pub(crate) fn questions_ask_new_team(
        &mut self,
        entry: &VaultEntry,
        url: &str,
        code: Zeroizing<String>,
        device: &str,
        ctx: Option<&egui::Context>,
    ) -> Result<(), String> {
        let url = match url.trim() {
            "" => DEFAULT_RELAY_URL.to_owned(),
            typed => RelayUrl::parse(typed)
                .map_err(|error| format!("{error}."))?
                .as_str()
                .to_owned(),
        };
        let code = Zeroizing::new(code.trim().to_owned());
        if !valid_team_code(&code) {
            return Err(
                "Type the team code from the operator of the relay. It starts with apassy_tcd_."
                    .to_owned(),
            );
        }
        let device = match device.trim() {
            "" => device_name(),
            typed => typed.to_owned(),
        };
        self.sync.relay.questions.error = None;
        self.sync.relay.questions.pending = Some(NewTeam {
            vault: entry.id.clone(),
            name: entry.name.clone(),
            url: url.clone(),
            code: Some(code),
            device,
            replaces: None,
        });
        self.ask_owner(
            OwnerRequest::EnableRelayQuestions {
                relay_url: url,
                team_id: None,
            },
            ctx,
        );
        Ok(())
    }

    /// The first "Add a device" of a vault with no team: the owner check for a new Apassy
    /// Connect team on `relay_url`, with no code. After the check, `POST /v1/connect` runs
    /// on its own thread and the vault keeps the membership; then the sheet makes its
    /// link.
    pub(crate) fn questions_ask_connect(
        &mut self,
        entry: &VaultEntry,
        relay_url: &str,
        ctx: Option<&egui::Context>,
    ) {
        self.sync.relay.questions.error = None;
        self.sync.relay.questions.pending = Some(NewTeam {
            vault: entry.id.clone(),
            name: entry.name.clone(),
            url: relay_url.to_owned(),
            code: None,
            device: device_name(),
            replaces: None,
        });
        self.ask_owner(
            OwnerRequest::ConnectVault {
                relay_url: relay_url.to_owned(),
            },
            ctx,
        );
    }

    /// "Connect again" after its question: the owner check for a new Apassy Connect team
    /// that takes the place of the questions team `team_id`. Nothing changes before the
    /// check, and the old membership goes only when the vault keeps the new one.
    pub(crate) fn questions_ask_connect_again(
        &mut self,
        entry: &VaultEntry,
        team_id: &str,
        ctx: Option<&egui::Context>,
    ) {
        let relay_url = self.connect_relay_url();
        self.sync.relay.questions.error = None;
        self.sync.relay.questions.pending = Some(NewTeam {
            vault: entry.id.clone(),
            name: entry.name.clone(),
            url: relay_url.clone(),
            code: None,
            device: device_name(),
            replaces: Some(team_id.to_owned()),
        });
        self.ask_owner(OwnerRequest::ConnectVault { relay_url }, ctx);
    }

    /// Ask the relay once more for the devices of the questions team of the open vault:
    /// a fresh sign-in before "Connect again?".
    pub(crate) fn questions_recheck(&mut self) {
        let questions = &mut self.sync.relay.questions;
        questions.devices_read = None;
        questions.gone_every = None;
        questions.rechecking = true;
    }

    /// After the owner check of "Send questions through the relay": `proof` must name
    /// exactly this relay and team, in this vault session.
    pub(crate) fn questions_enable_with(
        &mut self,
        relay_url: String,
        team_id: Option<String>,
        proof: OwnerProof,
    ) {
        let expected = OwnerAction::EnableRelayQuestions {
            relay_url: relay_url.clone(),
            team_id: team_id.clone(),
        };
        let checked = self
            .owner_ui
            .session
            .with_vault(|vault| proof.check(&expected, &vault.epoch()));
        match checked {
            Some(Ok(())) => {}
            Some(Err(refusal)) => {
                self.sync.relay.questions.pending = None;
                return self.set_err(refusal.message());
            }
            None => {
                self.sync.relay.questions.pending = None;
                self.sync.relay.questions.join_request = None;
                return self.set_err("Unlock the vault first. Nothing changed.");
            }
        }
        let join = self
            .sync
            .relay
            .questions
            .join_request
            .as_ref()
            .is_some_and(|join| Some(&join.team_id) == team_id.as_ref() && join.url == relay_url);
        match team_id {
            Some(_) if join => self.questions_join_start(),
            Some(team_id) => self.questions_enable_sync_team(&relay_url, &team_id),
            None => self.questions_create_team(&relay_url),
        }
    }

    /// "Join…" of the team sheet: the pasted link must be of the questions team of the
    /// vault; then the owner check names the relay and that team. The link waits in
    /// memory for the check only.
    pub(crate) fn questions_ask_join(
        &mut self,
        entry: &VaultEntry,
        team_id: &str,
        link: Zeroizing<String>,
        device: &str,
        ctx: Option<&egui::Context>,
    ) -> Result<(), String> {
        let link = Zeroizing::new(link.trim().to_owned());
        if link.is_empty() {
            return Err("Paste the link from a Mac that has the questions on.".to_owned());
        }
        // The parameters of the link only word the screens; an `r` that this version does
        // not know refuses the link (contract relay-connect-v1 section 7.2).
        let (url, code) = match RelayLinkPayload::parse(&link, DEFAULT_RELAY_URL) {
            Ok(payload) => (payload.relay, payload.code),
            Err(LinkPayloadError::UnknownRoute) => {
                return Err(
                    "This link needs a newer version of Apassy. Update Apassy, then try again."
                        .to_owned(),
                );
            }
            Err(_) => return Err("This is not a device link of the Apassy relay.".to_owned()),
        };
        if link_code_team(&code) != Some(team_id) {
            return Err(
                "This link is of another team. Make the link on a Mac that has the questions of this vault on."
                    .to_owned(),
            );
        }
        let device = match device.trim() {
            "" => device_name(),
            typed => typed.to_owned(),
        };
        let questions = &mut self.sync.relay.questions;
        questions.error = None;
        questions.join_request = Some(JoinRequest {
            vault: entry.id.clone(),
            team_id: team_id.to_owned(),
            url: url.as_str().to_owned(),
            link,
            device,
        });
        self.ask_owner(
            OwnerRequest::EnableRelayQuestions {
                relay_url: url.as_str().to_owned(),
                team_id: Some(team_id.to_owned()),
            },
            ctx,
        );
        Ok(())
    }

    /// After the owner check: send the link with a new key of this Mac, on its own
    /// thread.
    fn questions_join_start(&mut self) {
        let Some(request) = self.sync.relay.questions.join_request.take() else {
            return self.set_err("The sheet is closed. Nothing changed.");
        };
        if self.vault_list.current.as_deref() != Some(request.vault.as_str()) {
            return self.set_err("The open vault changed. Nothing changed.");
        }
        if let Some(old) = self.sync.relay.questions.joining.take() {
            cancel_join(old);
        }
        let JoinRequest {
            vault,
            team_id,
            url,
            link,
            device,
        } = request;
        let name = device.clone();
        let task = Task::spawn(self.sync.relay.questions.repaint.clone(), move || {
            PendingJoin::request_with_key(&link, &url, &name, DeviceKey::generate()?)
        });
        self.sync.relay.questions.joining = Some(Joining {
            vault,
            team_id,
            device,
            phase: JoinPhase::Requesting(task),
        });
    }

    /// "Cancel" of a join: the other Mac no longer lists this Mac.
    pub(crate) fn questions_join_cancel(&mut self) {
        let questions = &mut self.sync.relay.questions;
        questions.join_request = None;
        questions.join_words = None;
        if let Some(joining) = questions.joining.take() {
            cancel_join(joining);
        }
    }

    /// Each frame: the steps of a join of the questions team.
    fn questions_join_poll(&mut self, ctx: &egui::Context) {
        let Some(joining) = self.sync.relay.questions.joining.take() else {
            return;
        };
        let Joining {
            vault,
            team_id,
            device,
            phase,
        } = joining;
        let fail = |app: &mut Self, text: String| {
            app.sync.relay.questions.join_words = None;
            app.sync.relay.questions.error = Some(text.clone());
            app.set_err(text);
        };
        let phase = match phase {
            JoinPhase::Requesting(task) => match task.poll() {
                TaskPoll::Waiting => JoinPhase::Requesting(task),
                TaskPoll::Lost => {
                    return fail(
                        self,
                        "The relay call ended without an answer. Try again.".to_owned(),
                    );
                }
                TaskPoll::Done(Err(error)) => {
                    return fail(self, format!("Nothing changed. {}", call_error(error)));
                }
                TaskPoll::Done(Ok(pending)) => {
                    self.sync.relay.questions.join_words = Some(pending.safety.clone());
                    JoinPhase::Waiting {
                        pending: Arc::new(pending),
                        poll: None,
                        next: Instant::now(),
                    }
                }
            },
            JoinPhase::Waiting {
                pending,
                poll,
                next,
            } => match poll.as_ref().map(Task::poll) {
                None if Instant::now() >= next => {
                    let asking = Arc::clone(&pending);
                    let task = Task::spawn(Some(ctx.clone()), move || asking.poll());
                    JoinPhase::Waiting {
                        pending,
                        poll: Some(task),
                        next,
                    }
                }
                None | Some(TaskPoll::Waiting) => JoinPhase::Waiting {
                    pending,
                    poll,
                    next,
                },
                Some(TaskPoll::Lost) | Some(TaskPoll::Done(Ok(None))) => JoinPhase::Waiting {
                    pending,
                    poll: None,
                    next: Instant::now() + JOIN_POLL_EVERY,
                },
                Some(TaskPoll::Done(Err(error))) => {
                    let text = match error {
                        SyncError::Relay(RelayRefusal::JoinRefused) => {
                            "The other Mac refused this Mac, or the link expired. Nothing changed."
                                .to_owned()
                        }
                        other => format!("Nothing changed. {}", call_error(other)),
                    };
                    return fail(self, text);
                }
                Some(TaskPoll::Done(Ok(Some(joined)))) => {
                    return self.questions_joined(&vault, &device, joined);
                }
            },
        };
        ctx.request_repaint_after(Duration::from_millis(200));
        self.sync.relay.questions.joining = Some(Joining {
            vault,
            team_id,
            device,
            phase,
        });
    }

    /// The other Mac confirmed: the vault keeps the new key for the questions only, and
    /// this Mac registers. A vault that does not keep it leaves the team again.
    fn questions_joined(&mut self, vault_id: &str, device: &str, joined: JoinedDevice) {
        self.sync.relay.questions.join_words = None;
        let member = joined.member();
        let membership = match (member.device_id(), joined.key_pkcs8()) {
            (Some(device_id), Some(key_pkcs8)) => RelayMembership {
                team_id: member.team_id().to_owned(),
                relay_url: member.relay_url().to_owned(),
                device_id,
                public_key: member.public_key().to_vec(),
                key_pkcs8,
                purposes: BTreeSet::from([MembershipPurpose::Questions]),
                created_at: 0,
            },
            _ => {
                std::thread::spawn(move || joined.cancel());
                return self.set_err("The relay gave no device number. Nothing changed.");
            }
        };
        let open = self.vault_list.current.as_deref() == Some(vault_id);
        let kept = if open {
            self.owner_ui
                .session
                .with_vault(|vault| join_questions_team(vault, &membership, device))
                .unwrap_or(Err(SyncError::Vault(VaultErrorKind::Locked)))
        } else {
            Err(SyncError::Vault(VaultErrorKind::Locked))
        };
        match kept {
            Ok(_) => {
                drop(joined);
                self.wake_questions();
                if let Some(super::super::Sheet::Vault(super::super::vaults::VaultSheet::Sync(
                    SyncSheet::QuestionsTeam { id },
                ))) = &self.ui.sheet
                    && id == vault_id
                {
                    self.ui.sheet = None;
                }
                self.set_ok("Questions now also go to your other devices through the relay.");
            }
            Err(error) => {
                std::thread::spawn(move || joined.cancel());
                let text = format!(
                    "The other Mac confirmed this Mac, but the vault did not keep the key: {}",
                    call_error(error)
                );
                self.sync.relay.questions.error = Some(text.clone());
                self.set_err(text);
            }
        }
    }

    /// On through the relay sync team `team_id` of the vault: no relay call.
    fn questions_enable_sync_team(&mut self, relay_url: &str, team_id: &str) {
        let name = device_name();
        let result = self.owner_ui.session.with_vault(|vault| {
            let sync = vault
                .relay_device()?
                .filter(|device| device.team_id == team_id && device.relay_url == relay_url);
            if sync.is_none() {
                return Err(SyncError::NotEnabled);
            }
            enable_questions(vault, &name)
        });
        match result {
            Some(Ok(_)) => {
                self.wake_questions();
                self.set_ok("Questions now also go to your other devices through the relay.");
            }
            Some(Err(SyncError::NotEnabled)) => self.set_err(
                "This vault no longer syncs through the same relay team. Nothing changed.",
            ),
            Some(Err(error)) => self.set_err(format!("Nothing changed. {}", call_error(error))),
            None => self.set_err("Unlock the vault first. Nothing changed."),
        }
    }

    /// On through a new notifications-only team: `POST /v1/teams` on its own thread with
    /// the team code of the sheet, which leaves the memory with the call.
    fn questions_create_team(&mut self, relay_url: &str) {
        let Some(new) = self.sync.relay.questions.pending.take() else {
            return self.set_err("The sheet is closed. Nothing changed.");
        };
        if new.url != relay_url || self.vault_list.current.as_deref() != Some(new.vault.as_str()) {
            return self.set_err("The open vault changed. Nothing changed.");
        }
        if self.sync.relay.questions.creating.is_some() {
            return;
        }
        let NewTeam {
            vault,
            name,
            url,
            code,
            device,
            replaces,
        } = new;
        let team_device = device.clone();
        let connect = code.is_none();
        let task = Task::spawn(
            self.sync.relay.questions.repaint.clone(),
            move || match code {
                Some(code) => new_questions_team(&url, &code, &name, &team_device),
                None => create_connect_team(&url, &name, &team_device),
            },
        );
        self.sync.relay.questions.creating = Some(Creating {
            vault,
            device,
            connect,
            replaces,
            task,
        });
    }

    /// Each frame: the answer of the relay for a new team, and the device list.
    pub(crate) fn questions_poll(&mut self, ctx: &egui::Context) {
        self.sync.relay.questions.repaint = Some(ctx.clone());
        self.questions_join_poll(ctx);
        let removed = match self
            .sync
            .relay
            .questions
            .removing
            .as_ref()
            .map(|removing| removing.task.poll())
        {
            Some(TaskPoll::Waiting) => {
                ctx.request_repaint_after(Duration::from_millis(200));
                None
            }
            Some(TaskPoll::Done(result)) => Some(Some(result)),
            Some(TaskPoll::Lost) => Some(None),
            None => None,
        };
        if let Some(result) = removed
            && let Some(removing) = self.sync.relay.questions.removing.take()
        {
            self.questions_revoked(&removing.name, result);
        }
        let done = match self
            .sync
            .relay
            .questions
            .creating
            .as_ref()
            .map(|c| c.task.poll())
        {
            Some(TaskPoll::Waiting) => {
                ctx.request_repaint_after(Duration::from_millis(200));
                None
            }
            Some(TaskPoll::Done(result)) => Some(Some(result)),
            Some(TaskPoll::Lost) => Some(None),
            None => None,
        };
        if let Some(result) = done
            && let Some(creating) = self.sync.relay.questions.creating.take()
        {
            self.questions_team_made(&creating, result);
        }
        let devices = match self
            .sync
            .relay
            .questions
            .devices
            .as_ref()
            .map(|read| read.task.poll())
        {
            Some(TaskPoll::Done(result)) => Some(Some(result)),
            Some(TaskPoll::Lost) => Some(None),
            _ => None,
        };
        if let Some(answer) = devices
            && let Some(read) = self.sync.relay.questions.devices.take()
        {
            self.questions_devices_read(&read, answer);
        }
    }

    /// The answer of a read of the devices: it counts only for the vault and the team that
    /// it was asked for, while that vault is open with that team.
    fn questions_devices_read(
        &mut self,
        read: &DevicesRead,
        answer: Option<Result<Vec<TeamDevice>, SyncError>>,
    ) {
        if self.questions_open_team().as_ref() != Some(&(read.vault.clone(), read.team.clone())) {
            return;
        }
        let gone = match &answer {
            Some(Err(SyncError::RemovedFromRelay)) => self.questions_team_forgotten(&read.team),
            _ => false,
        };
        let questions = &mut self.sync.relay.questions;
        questions.rechecking = false;
        questions.unreachable = false;
        match answer {
            Some(Ok(devices)) => {
                // A 401 that passed (a suspended team that a sign-in woke): the team is
                // back.
                questions.gone = None;
                questions.gone_every = None;
                questions.team = devices
                    .into_iter()
                    .map(|device| (device.id, device))
                    .collect();
            }
            Some(Err(SyncError::RemovedFromRelay)) if gone => {
                questions.gone = Some(Gone {
                    vault: read.vault.clone(),
                    team: read.team.clone(),
                });
                questions.gone_every = Some(
                    questions
                        .gone_every
                        .map_or(DEVICES_EVERY, |every| every * 2)
                        .min(GONE_EVERY_MAX),
                );
            }
            Some(Err(_)) | None => questions.unreachable = true,
        }
    }

    /// The list ID of the open, unlocked vault and its questions team.
    fn questions_open_team(&self) -> Option<(String, String)> {
        let vault = self.vault_list.current.clone()?;
        let team = self
            .owner_ui
            .session
            .with_vault(|vault| {
                if vault.is_locked() {
                    return None;
                }
                questions_membership(vault).ok()?.map(|team| team.team_id)
            })
            .flatten()?;
        Some((vault, team))
    }

    /// The answer of the revocations of a removed device, in one message: a failure of
    /// either one is never hidden by the success of the other.
    fn questions_revoked(&mut self, name: &str, result: Option<Revoked>) {
        let Some(Revoked { questions, sync }) = result else {
            return self.set_note(format!(
                "“{name}” can no longer answer. The relay did not answer about its device."
            ));
        };
        if sync.is_some() {
            self.relay_refresh_devices();
        }
        match (questions, sync) {
            (_, Some(Err(error))) => self.set_err(format!(
                "“{name}” can no longer answer, but it is not removed from the sync. {}",
                call_error(error)
            )),
            (Some(Err(error)), _) => self.set_note(format!(
                "“{name}” can no longer answer. The relay did not remove its device: {}",
                call_error(error)
            )),
            (Some(Ok(())), Some(Ok(()))) => self.set_ok(format!(
                "“{name}” is removed. It can no longer sync or answer, and the relay removed its devices."
            )),
            (None, Some(Ok(()))) => self.set_ok(format!(
                "“{name}” is removed. It can no longer sync or answer."
            )),
            (Some(Ok(())), None) => self.set_ok(format!(
                "“{name}” is removed. It can no longer answer, and the relay removed its device."
            )),
            (None, None) => self.set_ok(format!("“{name}” is removed. It can no longer answer.")),
        }
    }

    /// The relay made the team, or did not: keep the membership in the open vault.
    fn questions_team_made(
        &mut self,
        creating: &Creating,
        result: Option<Result<RelayMembership, SyncError>>,
    ) {
        let open = self.vault_list.current.as_deref() == Some(creating.vault.as_str());
        let outcome = match result {
            None => Err("The relay call ended without an answer. Try again.".to_owned()),
            Some(Err(SyncError::Relay(RelayRefusal::InviteInvalid))) => Err(
                "The team code is wrong, used, or expired. Ask the operator of the relay for a new one."
                    .to_owned(),
            ),
            Some(Err(error)) if creating.connect => Err(connect_error(error)),
            Some(Err(error)) => Err(call_error(error)),
            Some(Ok(membership)) if open => self
                .owner_ui
                .session
                .with_vault(|vault| match &creating.replaces {
                    Some(old_team) => {
                        reconnect_questions_team(vault, old_team, &membership, &creating.device)
                    }
                    None => adopt_questions_team(vault, &membership, &creating.device),
                })
                .unwrap_or(Err(SyncError::Vault(VaultErrorKind::Locked)))
                .map(|_| ())
                .map_err(|error| match error {
                    SyncError::AlreadyEnabled if creating.replaces.is_some() => {
                        "Another Mac connected this vault again. Add this Mac with a link from that Mac.".to_owned()
                    }
                    SyncError::AlreadyEnabled => {
                        "This vault sends its questions through the relay already.".to_owned()
                    }
                    other => format!(
                        "The relay made the team, but the vault did not keep it: {}",
                        call_error(other)
                    ),
                }),
            Some(Ok(_)) => Err("The open vault changed. The questions stay off.".to_owned()),
        };
        match outcome {
            Ok(()) => {
                self.wake_questions();
                self.sync.relay.questions.forget_vault();
                if let Some(super::super::Sheet::Vault(super::super::vaults::VaultSheet::Sync(
                    SyncSheet::QuestionsTeam { id },
                ))) = &self.ui.sheet
                    && *id == creating.vault
                {
                    self.ui.sheet = None;
                }
                // "Connect again" goes on as "Add a device", with the link of the new team.
                if super::super::devices::connecting_again(self) {
                    self.ui.sheet = Some(super::super::Sheet::Devices(
                        super::super::devices::DevicesSheet::AddDevice,
                    ));
                }
                // "Add a device" goes on with the link of the new team.
                if super::super::devices::adding(self) {
                    self.relay_add_device_start(&creating.vault, true);
                } else {
                    self.set_ok("This vault is connected. Add a device in Settings > Devices.");
                }
            }
            Err(text) => {
                self.sync.relay.questions.error = Some(text.clone());
                self.set_err(text);
            }
        }
    }

    /// The list of Settings > Devices asks the relay for the devices of the questions
    /// team at its next frame.
    pub(crate) fn questions_refresh_devices(&mut self) {
        self.sync.relay.questions.devices_read = None;
    }

    /// Whether a `401` at the sign-in of the questions team `team` means the relay forgot
    /// it: the team of the questions only, whose key the owner did not remove (relay SPEC
    /// §26.5: deleted after 30 days without use, or suspended until a sign-in).
    fn questions_team_forgotten(&self, team: &str) -> bool {
        self.owner_ui
            .session
            .with_vault(|vault| {
                let membership = questions_membership(vault).ok()??;
                let removed = vault
                    .trusted_key_removed(&membership.public_key)
                    .unwrap_or(true);
                Some(membership.team_id == team && questions_only(&membership) && !removed)
            })
            .flatten()
            .unwrap_or(false)
    }

    /// What Settings > Devices shows of the questions team of the open vault: its
    /// devices as the relay said last. Asks the relay every 30 seconds while it shows.
    /// `None`: the vault is locked or has no questions team on this Mac.
    pub(crate) fn questions_team_view(&mut self) -> Option<QuestionsTeamView> {
        let found = self.owner_ui.session.with_vault(|vault| {
            if vault.is_locked() {
                return None;
            }
            let membership = questions_membership(vault).ok()??;
            let me = this_device(vault, &membership).ok().flatten();
            Some((membership, me))
        });
        let Some((membership, me)) = found.flatten() else {
            // A lock forgets what the relay said.
            self.sync.relay.questions.gone = None;
            return None;
        };
        let vault_id = self.vault_list.current.clone().unwrap_or_default();
        let questions = &mut self.sync.relay.questions;
        if questions.push_team.as_deref() != Some(membership.team_id.as_str()) {
            questions.team.clear();
            questions.push_team = Some(membership.team_id.clone());
            questions.devices_read = None;
            questions.unreachable = false;
        }
        // A team that is gone for another vault or team counts no more.
        if questions
            .gone
            .as_ref()
            .is_some_and(|gone| gone.vault != vault_id || gone.team != membership.team_id)
        {
            questions.gone = None;
            questions.gone_every = None;
        }
        let gone = questions.gone(&vault_id, &membership.team_id);
        // A team that is gone is asked again, less often each time.
        let every = questions
            .gone_every
            .filter(|_| gone)
            .unwrap_or(DEVICES_EVERY);
        let due = questions.devices.is_none()
            && questions
                .devices_read
                .is_none_or(|at| at.elapsed() >= every);
        if due && let Ok(client) = QuestionsClient::from_membership(&membership) {
            questions.devices_read = Some(Instant::now());
            questions.devices = Some(DevicesRead {
                vault: vault_id,
                team: membership.team_id.clone(),
                task: Task::spawn(questions.repaint.clone(), move || client.devices()),
            });
        }
        Some(QuestionsTeamView {
            questions_only: questions_only(&membership),
            team_id: membership.team_id,
            me: me.map(|me| me.uuid),
            devices: questions.team.clone(),
            unreachable: questions.unreachable,
            gone,
        })
    }

    /// "Remove…" of a device in Settings > Devices: its confirmation first.
    pub(crate) fn questions_ask_remove(&mut self, uuid: &str, ctx: Option<&egui::Context>) {
        match self.vault_list.current.clone() {
            Some(id) => self.sync_open_sheet(
                SyncSheet::RemoveQuestionsDevice {
                    id,
                    uuid: uuid.to_owned(),
                },
                ctx,
            ),
            None => self.set_err("Open a vault of the list first."),
        }
    }

    /// Remove the trusted device `uuid` after its confirmation. No owner check: it takes
    /// authority away. The row stays with `deleted_at` (the removal syncs and wins), the
    /// vault gets a new question key, and the relay revokes the device on a thread of
    /// its own when this Mac is in the team.
    pub(crate) fn questions_remove_device(&mut self, uuid: &str) {
        let found = self.owner_ui.session.with_vault(|vault| {
            if vault.is_locked() {
                return Err(SyncError::Vault(VaultErrorKind::Locked));
            }
            let device = vault
                .trusted_device(uuid)?
                .ok_or(SyncError::Vault(VaultErrorKind::NotFound))?;
            let membership = questions_membership(vault)?;
            if membership
                .as_ref()
                .is_some_and(|membership| device.sign_key == membership.public_key)
            {
                // This Mac turns the questions off instead.
                return Err(SyncError::Vault(VaultErrorKind::InvalidInput));
            }
            vault.remove_trusted_device_and_rotate(uuid)?;
            let questions_team = membership
                .as_ref()
                .map(|membership| membership.team_id.clone());
            let revoke = membership.and_then(|membership| {
                let id = *device.relay_devices.get(&membership.team_id)?;
                Some((membership, id))
            });
            // A device of the relay sync team in another team than the questions also
            // leaves the sync team: a removed device neither approves nor syncs.
            let sync = vault
                .relay_device()?
                .filter(|sync| Some(&sync.team_id) != questions_team.as_ref())
                .and_then(|sync| device.relay_devices.get(&sync.team_id).copied());
            Ok((device.name, revoke, sync))
        });
        let (name, revoke, sync) = match found {
            Some(Ok(found)) => found,
            Some(Err(SyncError::Vault(VaultErrorKind::InvalidInput))) => {
                return self.set_err("To stop this Mac, select “Stop approvals here” in its row.");
            }
            Some(Err(SyncError::Vault(VaultErrorKind::NotFound))) => {
                return self.set_err("This device is not in the questions of this vault any more.");
            }
            Some(Err(error)) => {
                return self.set_err(format!("Nothing changed. {}", call_error(error)));
            }
            None => return self.set_err("Unlock the vault first. Nothing changed."),
        };
        self.wake_questions();
        self.sync.relay.questions.devices_read = None;
        // Both revocations run on one thread and end in one message.
        let questions = match revoke {
            Some((membership, device_id)) => match QuestionsClient::from_membership(&membership) {
                Ok(client) => Some(Ok((client, device_id))),
                Err(error) => Some(Err(error)),
            },
            None => None,
        };
        let sync = match (sync, self.vault_list.current.clone()) {
            (Some(device_id), Some(id)) => {
                Some(self.relay_sync_of_open(&id).map(|relay| (relay, device_id)))
            }
            _ => None,
        };
        if questions.is_none() && sync.is_none() {
            return self.set_ok(format!("“{name}” is removed. It can no longer answer."));
        }
        let task = Task::spawn(self.sync.relay.questions.repaint.clone(), move || Revoked {
            questions: questions
                .map(|asked| asked.and_then(|(client, device_id)| client.remove_device(device_id))),
            sync: sync.map(|asked| {
                asked.and_then(|(relay, device_id)| {
                    relay.remove_device(crate::sync::KeySource::Memory, device_id)
                })
            }),
        });
        self.sync.relay.questions.removing = Some(Removing { name, task });
    }

    /// Remove the device `device_id` of the questions team `team_id` of the open vault
    /// that has no trusted row: the relay revokes it, on a thread of its own. No owner
    /// check: it takes authority away. The vault gets a new question key, so the device
    /// cannot read the next questions.
    pub(crate) fn questions_revoke_device(&mut self, team_id: &str, device_id: u64, name: &str) {
        let membership = self
            .owner_ui
            .session
            .with_vault(|vault| {
                if vault.is_locked() {
                    return None;
                }
                let membership = questions_membership(vault).ok()??;
                (membership.team_id == team_id).then_some(())?;
                vault.rotate_question_key().ok()?;
                Some(membership)
            })
            .flatten();
        let Some(membership) = membership else {
            return self.set_err("Unlock the vault first. Nothing changed.");
        };
        self.wake_questions();
        self.sync.relay.questions.devices_read = None;
        let name = name.to_owned();
        match QuestionsClient::from_membership(&membership) {
            Ok(client) => {
                let task =
                    Task::spawn(self.sync.relay.questions.repaint.clone(), move || Revoked {
                        questions: Some(client.remove_device(device_id)),
                        sync: None,
                    });
                self.sync.relay.questions.removing = Some(Removing { name, task });
            }
            Err(error) => self.set_err(format!("“{name}” is not removed. {}", call_error(error))),
        }
    }

    /// "Remove" in "Devices…" of relay sync took the device `device_id` out of the sync
    /// team: its trusted device of that team goes too, with a new question key. Returns
    /// the name of the removed trusted device.
    pub(crate) fn questions_forget_relay_device(&mut self, device_id: u64) -> Option<String> {
        self.owner_ui
            .session
            .with_vault(|vault| {
                if vault.is_locked() {
                    return None;
                }
                let team = vault.relay_device().ok()??.team_id;
                let device = vault.trusted_device_by_relay_id(&team, device_id).ok()??;
                vault
                    .remove_trusted_device_and_rotate(&device.uuid)
                    .ok()
                    .filter(|removed| *removed)
                    .map(|_| device.name)
            })
            .flatten()
    }
}

/// The words of a failed `POST /v1/connect` (relay-connect-v1 section 2.1).
pub(crate) fn connect_error(error: SyncError) -> String {
    match error {
        SyncError::Relay(RelayRefusal::NotFound) => CONNECT_UNAVAILABLE.to_owned(),
        SyncError::Relay(RelayRefusal::Busy) => CONNECT_BUSY.to_owned(),
        SyncError::Relay(RelayRefusal::RateLimited) => {
            "Too many tries from this network. Wait a minute, then try again.".to_owned()
        }
        SyncError::RelayUnreachable => CONNECT_UNREACHABLE.to_owned(),
        other => format!(
            "Apassy Connect did not connect this vault: {}",
            call_error(other)
        ),
    }
}

/// "Use another relay…" of "Add a device" for a vault with no team (L3): the relay
/// address, the operator team code, and the name of this Mac, for a self-hosted relay.
/// "Connect…" runs the owner check, then makes a team for the questions only. A vault
/// whose questions team another Mac made joins it instead. Returns true on Escape.
pub(super) fn team_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    // A vault with a questions team never gets a second one: this Mac joins it.
    let join =
        app.owner_ui
            .session
            .with_vault(|vault| match questions_availability(vault).ok()? {
                QuestionsAvailability::JoinTeam { team_id } => Some(team_id),
                _ => None,
            });
    if let Some(Some(team_id)) = join {
        return join_sheet(app, ctx, entry, &team_id);
    }
    let busy = app.sync.relay.questions.creating(&entry.id);
    let mut turn_on = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "questions-relay-team", 520.0, |ui| {
        kit::sheet_title(
            ui,
            "Use another relay",
            Some(
                "For a relay that you or your company runs. Apassy makes a team on it for the questions of this vault only. The relay passes each question, end-to-end encrypted, to your other devices. It never gets the vault, a command, or a credential. Your vault keeps syncing as it does now.",
            ),
        );
        kit::section(
            ui,
            None,
            Some(
                "The operator of the relay gives you a team code. It works once. Apassy makes a key for this Mac and keeps it in the vault. Connecting needs Touch ID or your passphrase.",
            ),
            |s| {
                s.field("Relay address", |ui| {
                    kit::text_input(
                        ui,
                        &mut app.sync.relay.url_input,
                        "questions-relay-url",
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
                        "questions-relay-device",
                        "MacBook Pro",
                    )
                });
            },
        );
        if busy {
            kit::tone_note(ui, "Apassy makes the team on the relay…", Tone::Accent);
        }
        if let Some(error) = app.sync.relay.questions.error.clone() {
            kit::tone_note(ui, error, Tone::Critical);
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                ui.add_enabled_ui(!busy, |ui| {
                    turn_on = kit::button(ui, "Connect…", Style::Prominent).clicked();
                });
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if !busy && app.owner.check.is_none() && super::super::save_pressed(app, ctx) {
        turn_on = true;
    }
    if turn_on && !busy {
        let (url, device) = (
            app.sync.relay.url_input.clone(),
            app.sync.relay.device_input.clone(),
        );
        // The code works once: the field forgets it after each try.
        let code = Ephemeral::take(&mut app.sync.relay.team_code).into_zeroizing();
        forget_secret_field(ctx, TEAM_CODE_FIELD);
        if let Err(text) = app.questions_ask_new_team(entry, &url, code, &device, Some(ctx)) {
            app.sync.relay.questions.error = Some(text.clone());
            app.set_err(text);
        }
    }
    if cancel {
        app.sync.relay.questions.pending = None;
        super::cancel_sheet(app, ctx);
    }
    response.escape
}

/// Give up a join of the questions team: the other Mac no longer lists this Mac. Best
/// effort, on a thread of its own; a link that is still on its way just expires.
fn cancel_join(joining: Joining) {
    if let JoinPhase::Waiting { pending, poll, .. } = joining.phase {
        drop(poll);
        std::thread::spawn(move || {
            if let Ok(pending) = Arc::try_unwrap(pending) {
                let _ = pending.cancel();
            }
        });
    }
}

/// "Send questions through the relay" for a vault that has a questions team that this Mac
/// is not in: a link from a Mac in the team and the name of this Mac. "Join…" runs the
/// owner check, then sends the link; the other Mac confirms with the safety words and its
/// own owner check. Returns true on Escape.
fn join_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
    team_id: &str,
) -> bool {
    let joining = app.sync.relay.questions.joining(&entry.id);
    let words = app.sync.relay.questions.join_words.clone();
    let mut join = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "questions-relay-join", 520.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Connect this Mac to “{}”", entry.name),
            Some(
                "Your other devices of this vault are connected from another Mac. On that Mac, open Settings > Devices, select “Add a device…”, and paste its link here. Connecting needs Touch ID or your passphrase here, and a confirmation on the other Mac.",
            ),
        );
        if !joining {
            kit::section(ui, None, None, |s| {
                if super::relay::link_fields(app, s, false) {
                    join = true;
                }
            });
        }
        match &words {
            Some(words) => super::relay::safety_lines(
                ui,
                "Waiting for the other Mac… Both Macs show:",
                words,
                "Confirm on the other Mac only if it shows the same words.",
            ),
            None if joining => {
                kit::tone_note(ui, "Apassy sends the link to the relay…", Tone::Accent);
            }
            None => {}
        }
        if let Some(error) = app.sync.relay.questions.error.clone() {
            kit::tone_note(ui, error, Tone::Critical);
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                ui.add_enabled_ui(!joining, |ui| {
                    join |= kit::button(ui, "Join…", Style::Prominent).clicked();
                });
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if join && !joining {
        let device = app.sync.relay.device_input.clone();
        let link = Zeroizing::new(std::mem::take(&mut app.sync.relay.link_input));
        if let Err(text) = app.questions_ask_join(entry, team_id, link, &device, Some(ctx)) {
            app.sync.relay.questions.error = Some(text.clone());
            app.set_err(text);
        }
    }
    if cancel {
        app.questions_join_cancel();
        super::cancel_sheet(app, ctx);
    }
    response.escape
}

/// The confirmation of "Remove…" of a device in Devices. Returns true on Escape.
pub(super) fn remove_device_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    entry: &VaultEntry,
    uuid: &str,
) -> bool {
    let device = app
        .owner_ui
        .session
        .with_vault(|vault| vault.trusted_device(uuid).ok().flatten())
        .flatten();
    let Some(device) = device else {
        super::cancel_sheet(app, ctx);
        return false;
    };
    let icloud = entry.sync_relay().is_none() && entry.sync_file().is_some();
    let mut remove = false;
    let mut keep = false;
    let response = kit::sheet(ctx, "questions-remove-device", 440.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Remove “{}” from “{}”?", device.name, entry.name),
            Some(&removal_words(device.kind, icloud)),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                remove = kit::button(ui, "Remove", Style::DestructiveProminent).clicked();
                keep = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if remove {
        app.questions_remove_device(uuid);
        super::cancel_sheet(app, ctx);
    } else if keep {
        super::cancel_sheet(app, ctx);
    }
    response.escape
}
