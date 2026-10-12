//! "Send questions through the relay" in Settings > Devices (ADR 0025 §3e, stage 5 plan
//! §A6 and §A7, contract relay-questions-v1).
//!
//! On opens a new channel that can approve runs, so it passes the owner check
//! (`OwnerAction::EnableRelayQuestions`) before anything changes:
//!
//! - A vault that syncs through the relay: the sync membership gets the purpose
//!   `questions` ([`enable_questions`]), with no relay call.
//! - Any other vault: the "Questions through the relay" sheet asks for the relay address
//!   and an operator team code, as "Turn on" of relay sync does. After the check, `POST
//!   /v1/teams` runs on its own thread ([`new_questions_team`], no vault), then the vault
//!   keeps the membership ([`adopt_questions_team`]). The team never gets a snapshot;
//!   iCloud Drive stays the sync.
//!
//! Either way the vault gets its question key when it has none, and this Mac registers
//! as a trusted device. Off needs no check: it takes authority away. It removes the
//! purpose `questions` and never touches relay sync.
//!
//! "Add an iPhone…" links an iPhone to the questions team: the "Add a device…" sheet of
//! relay sync for a sync team, its questions mode ([`SyncSheet::AddIphone`]) for a
//! notifications-only team. Devices lists each trusted device of the vault, with the push
//! state of an iPhone when the relay tells it (`GET /v1/devices`, every 30 seconds while
//! the tab shows).
//!
//! The team code stays in memory only from "Turn On…" to the relay call. A lock, another
//! sync sheet, and the end of the try erase it.

use std::collections::BTreeMap;
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
    QuestionsAvailability, adopt_questions_team, disable_questions, enable_questions,
    new_questions_team, questions_availability, questions_membership, questions_only, this_device,
};
use crate::sync::{
    DEFAULT_RELAY_URL, RelayRefusal, RelayUrl, SyncError, device_name, valid_team_code,
};
use crate::vault::{RelayMembership, TrustedDevice, TrustedDeviceKind, VaultErrorKind};
use crate::vaults::VaultEntry;

/// How often Devices asks the relay for the push state of the devices.
const DEVICES_EVERY: Duration = Duration::from_secs(30);

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
    task: Task<Result<RelayMembership, SyncError>>,
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
}

impl QuestionsUi {
    /// Erase the team code that waits for the owner check.
    pub(crate) fn forget_codes(&mut self) {
        self.pending = None;
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
}

impl DesktopApp {
    fn wake_questions(&self) {
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
            Some((QuestionsAvailability::CanTurnOn { team_id }, Some(relay_url))) => self
                .ask_owner(
                    OwnerRequest::EnableRelayQuestions {
                        relay_url,
                        team_id: Some(team_id),
                    },
                    ctx,
                ),
            Some(_) => match self.vault_list.current.clone() {
                Some(id) => self.sync_open_sheet(SyncSheet::QuestionsTeam { id }, ctx),
                None => self.set_err("Open a vault of the list first."),
            },
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
                || self.sync.relay.questions.devices.is_some();
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
                return self.set_err("Unlock the vault first. Nothing changed.");
            }
        }
        match team_id {
            Some(team_id) => self.questions_enable_sync_team(&relay_url, &team_id),
            None => self.questions_create_team(&relay_url),
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
        let team_device = device.clone();
        let task = Task::spawn(self.sync.relay.questions.repaint.clone(), move || {
            new_questions_team(&url, &code, &name, &team_device)
        });
        self.sync.relay.questions.creating = Some(Creating {
            vault,
            device,
            task,
        });
    }

    /// Each frame: the answer of the relay for a new team, and the device list.
    pub(crate) fn questions_poll(&mut self, ctx: &egui::Context) {
        self.sync.relay.questions.repaint = Some(ctx.clone());
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
        result: Option<Result<RelayMembership, SyncError>>,
    ) {
        let open = self.vault_list.current.as_deref() == Some(creating.vault.as_str());
        let outcome = match result {
            None => Err("The relay call ended without an answer. Try again.".to_owned()),
            Some(Err(SyncError::Relay(RelayRefusal::InviteInvalid))) => Err(
                "The team code is wrong, used, or expired. Ask the operator of the relay for a new one."
                    .to_owned(),
            ),
            Some(Err(error)) => Err(call_error(error)),
            Some(Ok(membership)) if open => self
                .owner_ui
                .session
                .with_vault(|vault| adopt_questions_team(vault, &membership, &creating.device))
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
                self.set_ok(
                    "Questions now also go to your other devices through the relay. Add an iPhone in Devices to answer them there.",
                );
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
                }
            })
            .collect()
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
            None => self.set_err("Turn on “Send questions through the relay” first."),
        }
    }
}

/// "Send questions through the relay" for a vault that does not sync through the relay:
/// the relay address, the operator team code, and the name of this Mac. "Turn On…" runs
/// the owner check, then makes a notifications-only team. Returns true on Escape.
pub(super) fn team_sheet(app: &mut DesktopApp, ctx: &egui::Context, entry: &VaultEntry) -> bool {
    let busy = app.sync.relay.questions.creating(&entry.id);
    let mut turn_on = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "questions-relay-team", 520.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Questions of “{}” through the Apassy relay", entry.name),
            Some(
                "This vault does not sync through the relay, so Apassy makes a team on the relay for its questions only. The relay passes each question, end-to-end encrypted, to your other devices of this vault. It never gets the vault, a command, or a credential. Your vault keeps syncing as it does now.",
            ),
        );
        kit::section(
            ui,
            None,
            Some(
                "The operator of the relay gives you a team code. It works once. Apassy makes a key for this Mac and keeps it in the vault. Turning it on needs Touch ID or your passphrase.",
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
                    turn_on = kit::button(ui, "Turn On…", Style::Prominent).clicked();
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
