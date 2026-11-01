//! "Send questions through the relay" in Settings > Devices (ADR 0025 §3e, stage 5 plan
//! §A6 and §A7, contract relay-questions-v1).
//!
//! On opens a new channel that can approve runs, so it passes the owner check
//! (`OwnerAction::EnableRelayQuestions`) before anything changes:
//!
//! - A vault that syncs through the relay: the sync membership gets the purpose
//!   `questions` ([`enable_questions`]), with no relay call.
//! - Any other vault: "Get approvals on your iPhone" prepares and persists a Connect
//!   key after the owner check, then signed `POST /v1/connect` runs on its own thread.
//!   The operator-code API stays available for existing callers. Then the vault
//!   keeps the membership ([`adopt_questions_team`]). The team never gets a snapshot;
//!   iCloud Drive stays the sync. A vault that has a questions team already (another Mac
//!   made it) never gets a second one: the sheet joins that team with a device link from
//!   a Mac in it ([`join_questions_team`]), confirmed there with the safety words and
//!   that Mac's owner check, after the owner check of this Mac.
//!
//! Either way the vault gets its question key when it has none, and this Mac registers
//! as a trusted device. Only these steps write the row of this Mac. Off needs no check:
//! it takes authority away. It removes the purpose `questions` and never touches relay
//! sync.
//!
//! "Add an iPhone or a Mac…" links a device to the questions team: the "Add a device…"
//! sheet of relay sync for a sync team, its questions mode ([`SyncSheet::AddIphone`])
//! for a notifications-only team. The confirmation writes the row of an iPhone from the
//! keys of its link (`register_linked_device`); a Mac writes its own. Devices lists each
//! trusted device of the vault, with the push state of an iPhone when the relay tells it
//! (`GET /v1/devices`, every 30 seconds while the tab shows), and "Remove…" for each
//! other device ([`SyncSheet::RemoveQuestionsDevice`]): no owner check, it takes
//! authority away. The removal keeps the row with `deleted_at`, writes a new question
//! key, and revokes the device on the relay when this Mac can.
//!
//! The team code and a pasted link stay in memory only from "Turn On…" or "Join…" to the
//! relay call. A lock, another sync sheet, and the end of the try erase them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroizing;

use super::super::kit::{self, Style, Tone};
use super::SyncSheet;
use super::relay::call_error;
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
use crate::questions::{QuestionsClient, TeamDevice};
use crate::relay::membership::{
    QuestionsAvailability, adopt_questions_team, disable_questions, enable_questions,
    join_questions_team, new_questions_team, questions_availability, questions_membership,
    questions_only, this_device,
};
use crate::sync::{
    DEFAULT_RELAY_URL, DeviceKey, JoinedDevice, PendingJoin, RelayRefusal, RelayUrl, SyncError,
    device_name, link_code_team, valid_team_code,
};
use crate::vault::{
    MembershipPurpose, RelayMembership, TrustedDevice, TrustedDeviceKind, VaultErrorKind,
};
use crate::vaults::VaultEntry;

/// How often Devices asks the relay for the push state of the devices.
const DEVICES_EVERY: Duration = Duration::from_secs(30);
/// How often a Mac that joins the questions team asks whether the other Mac confirmed.
const JOIN_POLL_EVERY: Duration = Duration::from_secs(2);
/// The note of a Mac whose relay sync key was removed from the questions.
pub(crate) const REMOVED_SYNC: &str = "This Mac was removed from the questions of this vault. To answer and ask through the relay again, turn relay sync off and join the vault again from another Mac: that gives this Mac a new key.";

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

/// A removal of a trusted device whose relay device this Mac revokes.
struct Removing {
    name: String,
    task: Task<Result<(), SyncError>>,
}

/// A notifications-only team that waits for the owner check. Debug shows no code.
struct NewTeam {
    /// The vault (list ID) and its name, the name of the team.
    vault: String,
    name: String,
    url: String,
    code: Zeroizing<String>,
    device: String,
}

/// The relay call that makes a notifications-only team.
struct Creating {
    vault: String,
    device: String,
    task: Task<Result<RelayMembership, String>>,
    connect: bool,
}

/// The state of "Send questions through the relay" in the window.
#[derive(Default)]
pub(crate) struct QuestionsUi {
    pending: Option<NewTeam>,
    creating: Option<Creating>,
    /// Why the last try of the team sheet failed.
    pub(crate) error: Option<String>,
    /// The devices of the questions team on the relay, while the relay answers.
    devices: Option<Task<Result<Vec<TeamDevice>, SyncError>>>,
    devices_read: Option<Instant>,
    /// The push state of each device of the team `push_team`, by relay device number,
    /// as the relay said last.
    push: BTreeMap<u64, bool>,
    push_team: Option<String>,
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
    fn creating(&self, id: &str) -> bool {
        self.creating
            .as_ref()
            .is_some_and(|creating| creating.vault == id)
    }
}

/// What Devices shows of one trusted device of the vault: its kind, how it answers, and
/// its push state when the relay tells it.
pub(crate) fn device_words(device: &TrustedDevice, this_mac: bool, push: Option<bool>) -> String {
    let mut words = match (device.kind, this_mac) {
        (TrustedDeviceKind::Mac, true) => "This Mac".to_owned(),
        (TrustedDeviceKind::Mac, false) => "Mac · answers after Touch ID".to_owned(),
        (TrustedDeviceKind::Iphone, _) if device.answer_key.is_some() => {
            "iPhone · answers with Face ID".to_owned()
        }
        (TrustedDeviceKind::Iphone, _) => "iPhone · its Face ID key has not synced yet".to_owned(),
    };
    match push {
        Some(true) => words.push_str(" · Push on"),
        Some(false) => words.push_str(" · Push off"),
        None => {}
    }
    words
}

/// One row of the devices of the questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceRow {
    pub(crate) name: String,
    pub(crate) words: String,
    /// The trusted device UUID, for "Remove…".
    pub(crate) uuid: String,
    /// Every device but this Mac can be removed here; this Mac turns the questions off.
    pub(crate) removable: bool,
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
    pub(crate) fn wake_questions(&self) {
        if let Some(questions) = &self.owner.questions {
            questions.wake();
        }
    }

    /// "Send questions through the relay" goes on: the owner check for the relay sync
    /// team of the vault, or the sheet of a notifications-only team. Nothing changes
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
            Some((availability, url))
        });
        match state.flatten() {
            None => self.set_err("Unlock the vault first."),
            Some((QuestionsAvailability::On { .. }, _)) => {}
            Some((QuestionsAvailability::Removed { sync: true, .. }, _)) => {
                self.set_err(REMOVED_SYNC);
            }
            Some((QuestionsAvailability::Removed { sync: false, .. }, _)) => {
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
            Some((QuestionsAvailability::CanTurnOn { team_id }, Some(relay_url))) => self
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

    /// "Send questions through the relay" goes off: no check, it takes authority away.
    /// Relay sync never changes.
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
                let questions = &mut self.sync.relay.questions;
                questions.push.clear();
                questions.push_team = None;
                questions.devices_read = None;
                self.set_note("Questions stay on this Mac and the paired iPhones on this network.");
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
        if !code.is_empty() && !valid_team_code(&code) {
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
            code,
            device,
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
        let (url, code) = PendingJoin::parse_link(&link, DEFAULT_RELAY_URL)
            .map_err(|_| "This is not a device link of the Apassy relay.".to_owned())?;
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
        } = new;
        let connect = code.is_empty();
        let staged = if connect {
            match self.owner_ui.session.with_vault(|open| {
                crate::relay::connect::prepare_connect(open, &url, &name, &device)
            }) {
                Some(Ok(pending)) => Some(pending),
                Some(Err(error)) => {
                    self.sync.relay.questions.error = Some(error.to_string());
                    return self.set_err(error.to_string());
                }
                None => return self.set_err("Unlock the vault first. Nothing changed."),
            }
        } else {
            None
        };
        let team_device = device.clone();
        let task = Task::spawn(
            self.sync.relay.questions.repaint.clone(),
            move || match staged {
                Some(pending) => {
                    crate::relay::connect::create_connect(&pending).map_err(|e| e.to_string())
                }
                None => new_questions_team(&url, &code, &name, &team_device).map_err(call_error),
            },
        );
        self.sync.relay.questions.creating = Some(Creating {
            vault,
            device,
            task,
            connect,
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
            let name = removing.name;
            match result {
                Some(Ok(())) => self.set_ok(format!(
                    "“{name}” is removed. It can no longer answer, and the relay removed its device."
                )),
                Some(Err(error)) => self.set_note(format!(
                    "“{name}” can no longer answer. The relay did not remove its device: {}",
                    call_error(error)
                )),
                None => self.set_note(format!(
                    "“{name}” can no longer answer. The relay did not answer about its device."
                )),
            }
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
        let devices = match self.sync.relay.questions.devices.as_ref().map(Task::poll) {
            Some(TaskPoll::Done(result)) => Some(result.ok()),
            Some(TaskPoll::Lost) => Some(None),
            _ => None,
        };
        if let Some(devices) = devices {
            let questions = &mut self.sync.relay.questions;
            questions.devices = None;
            if let Some(devices) = devices {
                questions.push = devices
                    .into_iter()
                    .filter_map(|device| device.push.map(|push| (device.id, push)))
                    .collect();
            }
        }
    }

    /// The relay made the team, or did not: keep the membership in the open vault.
    fn questions_team_made(
        &mut self,
        creating: &Creating,
        result: Option<Result<RelayMembership, String>>,
    ) {
        let open = self.vault_list.current.as_deref() == Some(creating.vault.as_str());
        let outcome = match result {
            None => Err("The relay call ended without an answer. Try again.".to_owned()),
            Some(Err(error)) => Err(error),
            Some(Ok(membership)) if open => self
                .owner_ui
                .session
                .with_vault(|vault| {
                    if creating.connect {
                        vault.keep_connect_result(&membership)?;
                    }
                    adopt_questions_team(vault, &membership, &creating.device)
                })
                .unwrap_or(Err(SyncError::Vault(VaultErrorKind::Locked)))
                .map(|_| ())
                .map_err(|error| match error {
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
                if let Some(super::super::Sheet::Vault(super::super::vaults::VaultSheet::Sync(
                    SyncSheet::QuestionsTeam { id },
                ))) = &self.ui.sheet
                    && *id == creating.vault
                {
                    self.ui.sheet = None;
                }
                if creating.connect {
                    self.set_ok("Connected. Scan the pairing code with Apassy on your iPhone.");
                    self.questions_add_iphone(None);
                } else {
                    self.set_ok("Questions now also go to your other devices through the relay. Add an iPhone in Devices to answer them there.");
                }
            }
            Err(text) => {
                self.sync.relay.questions.error = Some(text.clone());
                self.set_err(text);
            }
        }
    }

    /// The devices of the questions of the open vault, for Devices: each trusted device
    /// with its words. Asks the relay for the push state every 30 seconds while it shows.
    pub(crate) fn questions_devices(&mut self) -> Vec<DeviceRow> {
        let found = self.owner_ui.session.with_vault(|vault| {
            if vault.is_locked() {
                return None;
            }
            let membership = questions_membership(vault).ok()??;
            let me = this_device(vault, &membership).ok().flatten();
            let devices = vault.trusted_devices().ok()?;
            Some((membership, me, devices))
        });
        let Some((membership, me, devices)) = found.flatten() else {
            return Vec::new();
        };
        let questions = &mut self.sync.relay.questions;
        if questions.push_team.as_deref() != Some(membership.team_id.as_str()) {
            questions.push.clear();
            questions.push_team = Some(membership.team_id.clone());
            questions.devices_read = None;
        }
        let due = questions.devices.is_none()
            && questions
                .devices_read
                .is_none_or(|at| at.elapsed() >= DEVICES_EVERY);
        if due && let Ok(client) = QuestionsClient::from_membership(&membership) {
            questions.devices_read = Some(Instant::now());
            questions.devices = Some(Task::spawn(questions.repaint.clone(), move || {
                client.devices()
            }));
        }
        devices
            .iter()
            .map(|device| {
                let this_mac = me.as_ref().is_some_and(|me| me.uuid == device.uuid);
                let push = device
                    .relay_devices
                    .get(&membership.team_id)
                    .and_then(|id| questions.push.get(id).copied());
                DeviceRow {
                    name: device.name.clone(),
                    words: device_words(device, this_mac, push),
                    uuid: device.uuid.clone(),
                    removable: !this_mac,
                }
            })
            .collect()
    }

    /// "Remove…" of a device in Devices: its confirmation first.
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
            let revoke = membership.and_then(|membership| {
                let id = *device.relay_devices.get(&membership.team_id)?;
                Some((membership, id))
            });
            Ok((device.name, revoke))
        });
        let (name, revoke) = match found {
            Some(Ok(found)) => found,
            Some(Err(SyncError::Vault(VaultErrorKind::InvalidInput))) => {
                return self
                    .set_err("To stop this Mac, turn “Send questions through the relay” off.");
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
        let Some((membership, device_id)) = revoke else {
            return self.set_ok(format!("“{name}” is removed. It can no longer answer."));
        };
        match QuestionsClient::from_membership(&membership) {
            Ok(client) => {
                let task = Task::spawn(self.sync.relay.questions.repaint.clone(), move || {
                    client.remove_device(device_id)
                });
                self.sync.relay.questions.removing = Some(Removing { name, task });
            }
            Err(error) => self.set_note(format!(
                "“{name}” can no longer answer. The relay did not remove its device: {}",
                call_error(error)
            )),
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

    /// "Add an iPhone…": the link of the questions team as a QR code. A notifications-only
    /// team links through its own sheet; a sync team through "Add a device…".
    pub(crate) fn questions_add_iphone(&mut self, ctx: Option<&egui::Context>) {
        let Some(id) = self.vault_list.current.clone() else {
            return self.set_err("Open a vault of the list first.");
        };
        let only = self
            .owner_ui
            .session
            .with_vault(|vault| questions_membership(vault).ok().flatten())
            .flatten()
            .map(|membership| questions_only(&membership));
        match only {
            Some(true) => self.sync_open_sheet(SyncSheet::AddIphone { id }, ctx),
            Some(false) => self.sync_open_sheet(SyncSheet::AddMac { id }, ctx),
            None => self.questions_turn_on(ctx),
        }
    }
}

/// Account-free Connect setup for a vault that does not use relay sync. The owner
/// check precedes durable staging and creation. Returns true on Escape.
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
            "Get approvals on your iPhone",
            Some(
                "Connect your iPhone to approve requests from this vault on any network. No account or subscription is needed. Your vault keeps syncing as it does now.",
            ),
        );
        kit::section(
            ui,
            None,
            Some(
                "Apassy saves a connection key in this encrypted vault before connecting. Then scan the pairing code on your iPhone and compare the safety words. Connecting needs Touch ID or your passphrase.",
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
            kit::tone_note(ui, "Connecting…", Tone::Accent);
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
        let code = Zeroizing::new(String::new());
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
            &format!("Join the questions of “{}”", entry.name),
            Some(
                "This vault already sends its questions through a team on the relay, so this Mac joins that team. On a Mac that has “Send questions through the relay” on, open Settings > Devices, select “Add an iPhone or a Mac…”, and paste its link here. Joining needs Touch ID or your passphrase here, and a confirmation on the other Mac.",
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
            &format!(
                "Remove “{}” from the questions of “{}”?",
                device.name, entry.name
            ),
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
