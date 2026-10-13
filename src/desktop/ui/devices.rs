//! Settings > Devices, the hub (flow spec M1), and its sheets: "Add a device" (M2), the
//! pairing on this network (L3), and the confirmations of "Remove…".
//!
//! The hub is one list of every device of the open vault:
//!
//! - this Mac, with the health of its macOS notifications (a warning only when they do
//!   not work), and "Stop approvals here" while it approves through the relay;
//! - the trusted devices of the vault (`TrustedDevice`), with when the relay last saw
//!   them (`GET /v1/devices` of the questions team, every 30 seconds while the list
//!   shows);
//! - the devices of the relay sync team that have no trusted row (a Mac that syncs but
//!   does not approve);
//! - the iPhones paired on this Wi-Fi (`CompanionDevice`): "Approves on this Wi-Fi only".
//!
//! "Add a device…" opens one sheet for an iPhone or a Mac. Its QR code and its link
//! carry the link of the team (contract relay-connect-v1 section 7): `r=connect` for a
//! team of the questions only, `r=sync` for the relay sync team, the name of this Mac,
//! the end of the code, and in the QR code only, the pairing link of this network as
//! the fallback. The fields after the code only word the screens of the device: trust
//! comes from the safety words on both screens and the owner check on this Mac
//! (`OwnerRequest::ConfirmQuestionsDevice` or `ConfirmSyncDevice`, by the purpose of
//! the team), and only that confirmation writes the row of a new device.
//!
//! A vault with no team gets an Apassy Connect team at its first "Add a device", with no
//! code and no relay address, after the owner check that turns approvals on here. The
//! relay address and an operator team code live only under "Use another relay…" (L3).

use std::collections::BTreeSet;

use eframe::egui::{self, Color32, Label};

use super::companion;
use super::kit::{self, Font, Icon, Style, Tone};
use super::settings::rows;
use super::sync::SyncSheet;
use super::sync::questions::{CONNECT_GONE, REMOVED_SYNC};
use super::{Sheet, close_sheet};
use crate::companion::pairing::PairingView;
use crate::desktop::DesktopApp;
use crate::desktop::notify::{self, Delivery};
use crate::relay::membership::{QuestionsAvailability, questions_availability};
use crate::sync::{LinkRoute, device_name};
use crate::vault::TrustedDeviceKind;

/// The width of the QR code of "Add a device" in points, about.
const QR_POINTS: f32 = 180.0;
/// The tile of a device in the list, in points.
const TILE: f32 = 28.0;
/// The gray of the device tiles: a device has no color of its own.
const TILE_GRAY: Color32 = Color32::from_rgb(142, 142, 147);
/// The primary action of the hub.
pub(crate) const ADD_DEVICE: &str = "Add a device…";
/// The trust line next to "Add a device…".
pub(crate) const TRUST_LINE: &str = "A new device needs your Touch ID here.";
/// The note under the list.
pub(crate) const HUB_NOTE: &str = "Each question goes to every device. The first answer counts. Apassy Connect sees no command and no credential.";
/// The empty state, while this Mac is the only device.
pub(crate) const EMPTY_TITLE: &str = "Approve your agents from your iPhone";
pub(crate) const EMPTY_MESSAGE: &str = "Add a device to get each question there too.";
/// The L3 fallback of the local network.
pub(crate) const PAIR_HERE: &str = "Pair on this network";
/// The memory of the window that keeps "Pair on this network" open.
pub(crate) const PAIR_HERE_ID: &str = "apassy-devices-pair-here";
/// What an iPhone paired on this Wi-Fi does.
pub(crate) const WIFI_ONLY: &str = "Approves on this Wi-Fi only";
/// "⋯" of this Mac while it approves through the relay.
pub(crate) const STOP_HERE: &str = "Stop approvals here";
/// "⋯" of this Mac while it does not, and can, with the owner check.
pub(crate) const APPROVE_HERE: &str = "Approve here…";
/// The error state of the hub.
pub(crate) const UNREACHABLE: &str = "Can't reach Apassy Connect.";

/// A sheet of the Devices hub (`Sheet::Devices`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DevicesSheet {
    /// "Add a device": one QR code and one link for an iPhone or a Mac (M2).
    AddDevice,
    /// "Pair on this network": the QR code of the listener on this Wi-Fi and the code
    /// that the iPhone shows (ADR 0020), the fallback of "Add a device".
    PairHere,
    /// "Remove…" of a device in a relay team that has no trusted row: its confirmation.
    RemoveTeamDevice {
        team_id: String,
        device_id: u64,
        name: String,
    },
    /// "Remove…" of an iPhone paired on this Wi-Fi: its confirmation.
    RemoveWifi { device_id: String, name: String },
}

/// The kind of a device, for its tile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    ThisMac,
    Mac,
    Iphone,
}

/// What "Remove…" of a row removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Removal {
    /// A trusted device: the row stays with `deleted_at`, the question key rotates, and
    /// the relay revokes it when this Mac can.
    Trusted { uuid: String },
    /// A device of a relay team with no trusted row.
    TeamDevice {
        team_id: String,
        device_id: u64,
        name: String,
    },
    /// An iPhone paired on this Wi-Fi.
    Wifi { device_id: String, name: String },
}

/// One row of the hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceRow {
    pub(crate) name: String,
    pub(crate) kind: DeviceKind,
    /// What it does, in the words of flow spec §2: "Approves with Face ID · Syncs
    /// through iCloud Drive", or "This Mac".
    pub(crate) does: String,
    /// When the relay or this Mac last saw it, Unix seconds.
    pub(crate) seen: Option<u64>,
    pub(crate) remove: Option<Removal>,
    /// "Stop approvals here": this Mac while it approves through the relay.
    pub(crate) stop_here: bool,
    /// "Approve here…": this Mac while it does not approve through the team of the
    /// vault, and can after the owner check.
    pub(crate) approve_here: bool,
}

/// A state of the hub that the owner should know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HubProblem {
    /// The relay did not answer: "Can't reach Apassy Connect."
    Unreachable,
    /// The relay deleted the Connect team of the vault ([`CONNECT_GONE`]).
    Gone,
    /// Another problem of the relay or of this Mac, in words.
    Other(String),
}

/// What the hub shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hub {
    pub(crate) rows: Vec<DeviceRow>,
    /// The questions of the vault go through the relay from this Mac.
    pub(crate) approvals: bool,
    pub(crate) problem: Option<HubProblem>,
}

/// Whether the "Add a device" sheet is open.
pub(crate) fn adding(app: &DesktopApp) -> bool {
    matches!(app.ui.sheet, Some(Sheet::Devices(DevicesSheet::AddDevice)))
}

/// The status line of Devices in the list of Settings: "Only this Mac", or "3 devices ·
/// approvals on all", after "Notifications off" while they do not work. It reads the
/// vault and asks the relay nothing.
pub(super) fn status_line(app: &DesktopApp) -> String {
    let mut parts = Vec::new();
    if notifications_broken(app) {
        parts.push("Notifications off".to_owned());
    }
    let wifi = app
        .owner_ui
        .session
        .companion_devices()
        .map_or(0, |devices| devices.len());
    let (others, approvals) = app
        .owner_ui
        .session
        .with_vault(|vault| {
            if vault.is_locked() {
                return (0, false);
            }
            let membership = crate::relay::membership::questions_membership(vault)
                .ok()
                .flatten();
            let me = membership.as_ref().and_then(|membership| {
                crate::relay::membership::this_device(vault, membership)
                    .ok()
                    .flatten()
            });
            let others = vault.trusted_devices().map_or(0, |devices| {
                devices
                    .iter()
                    .filter(|device| me.as_ref().is_none_or(|me| me.uuid != device.uuid))
                    .count()
            });
            (others, membership.is_some())
        })
        .unwrap_or((0, false));
    let count = 1 + others + wifi;
    parts.push(match count {
        1 => "Only this Mac".to_owned(),
        count if approvals && others > 0 => format!("{count} devices · approvals on all"),
        count => format!("{count} devices"),
    });
    parts.join(" · ")
}

fn notifications_broken(app: &DesktopApp) -> bool {
    app.owner
        .notifications
        .as_ref()
        .is_some_and(|center| !center.view().channel.can_deliver())
}

/// What the vault syncs through, for the line of a device: "Syncs through Apassy", or
/// through the synced folder. `None` while it does not sync.
fn sync_words(app: &DesktopApp) -> Option<String> {
    let others = super::sync::other_macs(app);
    if others.relay.is_some() {
        return Some("Syncs through Apassy".to_owned());
    }
    let entry = app.current_vault()?;
    if entry.sync_relay().is_some() || entry.sync_file().is_none() {
        return None;
    }
    // "Through iCloud Drive" → "Syncs through iCloud Drive".
    let place = others.words.strip_prefix("Through ")?;
    Some(format!("Syncs through {place}"))
}

impl DesktopApp {
    /// The hub of the open vault: every device with what it does. Asks the relay for the
    /// devices of the teams of the vault every 30 seconds while it shows.
    pub(crate) fn devices_hub(&mut self) -> Hub {
        let mac = Some(DeviceRow {
            name: device_name(),
            kind: DeviceKind::ThisMac,
            does: "This Mac".to_owned(),
            seen: None,
            remove: None,
            stop_here: false,
            approve_here: false,
        });
        let mut hub = Hub {
            rows: mac.into_iter().collect(),
            approvals: false,
            problem: None,
        };
        let unlocked = !self.owner_ui.session.is_locked();
        let syncs = sync_words(self);
        if unlocked {
            self.trusted_rows(&mut hub, syncs.as_deref());
            let availability = self
                .owner_ui
                .session
                .with_vault(|vault| questions_availability(vault).ok())
                .flatten();
            if let Some(mac) = hub.rows.first_mut() {
                mac.approve_here = matches!(
                    availability,
                    Some(
                        QuestionsAvailability::CanTurnOn { .. }
                            | QuestionsAvailability::JoinTeam { .. }
                            | QuestionsAvailability::Removed { sync: false, .. }
                    )
                );
            }
        }
        for device in self
            .owner_ui
            .session
            .companion_devices()
            .unwrap_or_default()
        {
            hub.rows.push(DeviceRow {
                name: device.name.clone(),
                kind: DeviceKind::Iphone,
                does: WIFI_ONLY.to_owned(),
                seen: device.last_seen_at,
                remove: Some(Removal::Wifi {
                    device_id: device.device_id,
                    name: device.name,
                }),
                stop_here: false,
                approve_here: false,
            });
        }
        if hub.problem.is_none()
            && let Some(view) = self
                .owner
                .questions
                .as_ref()
                .map(|questions| questions.view())
            && let Some(problem) = view.problem.filter(|_| view.unsupported || view.removed)
        {
            hub.problem = Some(HubProblem::Other(problem));
        }
        hub
    }

    /// The trusted devices and the relay devices of the open, unlocked vault.
    fn trusted_rows(&mut self, hub: &mut Hub, syncs: Option<&str>) {
        let team = self.questions_team_view();
        let sync_id = super::sync::other_macs(self).relay;
        let sync_team = sync_id.as_ref().and_then(|_| {
            self.owner_ui
                .session
                .with_vault(|vault| vault.relay_device().ok().flatten())
                .flatten()
                .map(|device| device.team_id)
        });
        let sync_list = sync_id.as_ref().and_then(|id| self.relay_team_devices(id));
        let trusted = self
            .owner_ui
            .session
            .with_vault(|vault| vault.trusted_devices().ok())
            .flatten()
            .unwrap_or_default();
        if let Some(team) = &team {
            hub.approvals = true;
            if team.gone {
                hub.problem = Some(HubProblem::Gone);
            } else if team.unreachable {
                hub.problem = Some(HubProblem::Unreachable);
            }
            if let Some(mac) = hub.rows.first_mut() {
                mac.stop_here = true;
            }
        }
        if matches!(
            sync_list,
            Some(Err(crate::sync::SyncError::RelayUnreachable))
        ) {
            hub.problem.get_or_insert(HubProblem::Unreachable);
        }
        let me = team.as_ref().and_then(|team| team.me.clone());
        // The relay numbers of the devices that have a row, by team.
        let mut known: BTreeSet<(String, u64)> = BTreeSet::new();
        for device in &trusted {
            for (team_id, id) in &device.relay_devices {
                known.insert((team_id.clone(), *id));
            }
            if me.as_deref() == Some(device.uuid.as_str()) {
                continue;
            }
            let seen_in_team = team.as_ref().and_then(|team| {
                let id = device.relay_devices.get(&team.team_id)?;
                team.devices.get(id)?.last_seen_at
            });
            let seen_in_sync = sync_team.as_ref().and_then(|sync_team| {
                let id = device.relay_devices.get(sync_team)?;
                let list = sync_list.as_ref()?.as_ref().ok()?;
                list.iter().find(|view| view.id == *id)?.last_seen_at
            });
            let push_off = team.as_ref().is_some_and(|team| {
                device
                    .relay_devices
                    .get(&team.team_id)
                    .and_then(|id| team.devices.get(id))
                    .is_some_and(|view| view.push == Some(false))
            });
            let (kind, mut does) = match device.kind {
                TrustedDeviceKind::Mac => (DeviceKind::Mac, "Approves with Touch ID".to_owned()),
                TrustedDeviceKind::Iphone if device.answer_key.is_some() => {
                    (DeviceKind::Iphone, "Approves with Face ID".to_owned())
                }
                TrustedDeviceKind::Iphone => (
                    DeviceKind::Iphone,
                    "Its Face ID key has not synced yet".to_owned(),
                ),
            };
            if let Some(syncs) = syncs {
                does.push_str(" · ");
                does.push_str(syncs);
            }
            if push_off {
                does.push_str(" · No notifications");
            }
            hub.rows.push(DeviceRow {
                name: device.name.clone(),
                kind,
                does,
                seen: seen_in_team.max(seen_in_sync),
                remove: Some(Removal::Trusted {
                    uuid: device.uuid.clone(),
                }),
                stop_here: false,
                approve_here: false,
            });
        }
        // A device of a team with no trusted row: a Mac that syncs but does not approve
        // here, or a device whose row has not synced yet. The owner can remove it.
        let mut extra = Vec::new();
        if let (Some(sync_team), Some(Ok(list))) = (&sync_team, &sync_list) {
            for view in list {
                if !view.current && known.insert((sync_team.clone(), view.id)) {
                    extra.push((
                        sync_team.clone(),
                        view.id,
                        view.name.clone(),
                        view.last_seen_at,
                        true,
                    ));
                }
            }
        }
        if let Some(team) = &team {
            for view in team.devices.values() {
                if !view.current && known.insert((team.team_id.clone(), view.id)) {
                    extra.push((
                        team.team_id.clone(),
                        view.id,
                        view.name.clone(),
                        view.last_seen_at,
                        false,
                    ));
                }
            }
        }
        for (team_id, device_id, name, seen, sync) in extra {
            let (shown, answer_key) = crate::questions::device_link::split_link_device_name(&name);
            let name = crate::sync::relay::clean_name(&shown, "Device");
            hub.rows.push(DeviceRow {
                name: name.clone(),
                kind: if answer_key.is_some() {
                    DeviceKind::Iphone
                } else {
                    DeviceKind::Mac
                },
                does: if sync {
                    "Syncs through Apassy".to_owned()
                } else {
                    "Connected · not set up to approve yet".to_owned()
                },
                seen,
                remove: Some(Removal::TeamDevice {
                    team_id,
                    device_id,
                    name,
                }),
                stop_here: false,
                approve_here: false,
            });
        }
    }

    /// "Add a device…": the sheet with the link of the team of the vault. A vault with no
    /// team gets an Apassy Connect team first, after the owner check; a vault whose team
    /// another Mac made joins it with a link from that Mac.
    pub(crate) fn devices_add(&mut self, ctx: Option<&egui::Context>) {
        let Some(entry) = self.current_vault().cloned() else {
            return self.set_err("Open a vault of the list first.");
        };
        if self.owner_ui.session.is_locked() {
            return self.set_err("Unlock the vault first.");
        }
        // A Connect team that the relay deleted: its membership goes, and a new team comes.
        self.questions_forget_gone_team();
        let state = self.owner_ui.session.with_vault(|vault| {
            let availability = questions_availability(vault).ok()?;
            let membership = crate::relay::membership::questions_membership(vault)
                .ok()
                .flatten();
            Some((availability, membership))
        });
        let Some(Some((availability, membership))) = state else {
            return self.set_err("Unlock the vault first.");
        };
        self.sync.relay.questions.error = None;
        match availability {
            QuestionsAvailability::On { team_id } => {
                let questions_only = membership
                    .as_ref()
                    .is_some_and(crate::relay::membership::questions_only);
                // The sync team links through relay sync; it must be the team of the
                // questions, else this Mac adds through the questions team.
                let sync = entry
                    .sync_relay()
                    .is_some_and(|link| link.team_id == team_id);
                self.relay_add_device_start(&entry.id, questions_only || !sync);
            }
            QuestionsAvailability::CanTurnOn { .. } => {
                // A new device approves by default: this Mac sends its questions through
                // the sync team too, after the owner check.
                self.relay_add_device_start(&entry.id, false);
                self.questions_turn_on(ctx);
            }
            QuestionsAvailability::NeedsTeam if entry.sync.is_none() => {
                // The vault stays on this Mac: a device can approve only on this Wi-Fi.
                return self.devices_pair_here(ctx);
            }
            QuestionsAvailability::NeedsTeam => {
                self.relay_sheet_closed();
                let url = self.connect_relay_url();
                self.questions_ask_connect(&entry, &url, ctx);
            }
            QuestionsAvailability::JoinTeam { .. }
            | QuestionsAvailability::Removed { sync: false, .. } => {
                return self.questions_turn_on(ctx);
            }
            QuestionsAvailability::Removed { sync: true, .. } => {
                return self.set_err(REMOVED_SYNC);
            }
        }
        self.ui.sheet = Some(Sheet::Devices(DevicesSheet::AddDevice));
        self.devices_open_fallback(ctx);
    }

    /// The pairing window of this network goes with the QR code of "Add a device" when
    /// the listener of this Mac runs, so that the iPhone can fall back to it. The
    /// listener is never turned on for it.
    fn devices_open_fallback(&mut self, ctx: Option<&egui::Context>) {
        let closed = self
            .companion_controller()
            .is_some_and(|controller| controller.view() == PairingView::Closed);
        if closed && let Some(ctx) = ctx {
            self.open_pairing(ctx);
        }
    }

    /// "Pair on this network": the listener goes on (the owner asked for it), and the
    /// pairing code shows in its sheet.
    pub(crate) fn devices_pair_here(&mut self, ctx: Option<&egui::Context>) {
        self.devices_close_add();
        self.ui.sheet = Some(Sheet::Devices(DevicesSheet::PairHere));
        if let Some(ctx) = ctx {
            let open = self
                .companion_controller()
                .is_some_and(|controller| controller.view() != PairingView::Closed);
            if !open {
                super::settings::add_an_iphone(self, ctx);
            }
        }
    }

    /// The "Add a device" sheet goes: the devices that wait are refused, the link and an
    /// Apassy Connect team that waits for the owner check are dropped. A pairing window
    /// that nobody used closes.
    fn devices_close_add(&mut self) {
        self.relay_sheet_closed();
        self.sync.relay.questions.forget_connect();
        self.sync.relay.questions.error = None;
    }

    /// "Remove…" of a row: its confirmation.
    pub(crate) fn devices_ask_remove(&mut self, removal: Removal, ctx: Option<&egui::Context>) {
        match removal {
            Removal::Trusted { uuid } => self.questions_ask_remove(&uuid, ctx),
            Removal::TeamDevice {
                team_id,
                device_id,
                name,
            } => {
                self.ui.sheet = Some(Sheet::Devices(DevicesSheet::RemoveTeamDevice {
                    team_id,
                    device_id,
                    name,
                }));
            }
            Removal::Wifi { device_id, name } => {
                self.ui.sheet = Some(Sheet::Devices(DevicesSheet::RemoveWifi { device_id, name }));
            }
        }
    }
}

/// Settings > Devices: the list, "Add a device…", and "Pair on this network" (L3).
pub(super) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let hub = app.devices_hub();
    let mut add = false;
    let mut pair_here = false;
    let mut action = None;
    match &hub.problem {
        Some(HubProblem::Unreachable) => {
            kit::notice(
                ui,
                Tone::Warning,
                UNREACHABLE,
                Some("Devices show when it is back."),
                |ui| {
                    pair_here =
                        kit::small_button(ui, "On this Wi-Fi? Pair on this network.", Style::Link)
                            .clicked();
                },
            );
        }
        Some(HubProblem::Gone) => {
            kit::notice(
                ui,
                Tone::Warning,
                "Connect this vault again",
                Some(CONNECT_GONE),
                |ui| {
                    add = kit::small_button(ui, ADD_DEVICE, Style::Bordered).clicked();
                },
            );
        }
        Some(HubProblem::Other(text)) => {
            kit::notice(
                ui,
                Tone::Warning,
                "Approvals on other devices stopped",
                Some(text),
                |_| {},
            );
        }
        None => {}
    }
    let alone = hub.rows.len() == 1;
    if alone {
        // The hero: only this Mac.
        ui.vertical_centered(|ui| {
            ui.add_space(28.0);
            kit::paint_icon_in(ui, Icon::Phone, 48.0, kit::SECONDARY);
            ui.add_space(10.0);
            ui.label(kit::text(EMPTY_TITLE, Font::Title3).color(kit::LABEL));
            ui.add_space(2.0);
            ui.label(kit::text(EMPTY_MESSAGE, Font::Callout).color(kit::SECONDARY));
            ui.add_space(12.0);
            add |= kit::button(ui, ADD_DEVICE, Style::Prominent).clicked();
            ui.add_space(6.0);
            ui.label(kit::text(TRUST_LINE, Font::Footnote).color(kit::SECONDARY));
            ui.add_space(12.0);
        });
    } else {
        ui.add_space(14.0);
        kit::sheet_buttons(
            ui,
            |ui| {
                ui.label(kit::text(TRUST_LINE, Font::Callout).color(kit::SECONDARY));
            },
            |ui| {
                add |= kit::button(ui, ADD_DEVICE, Style::Prominent).clicked();
            },
        );
    }
    let note = (!alone).then_some(HUB_NOTE);
    rows::section(ui, alone.then_some("This Mac"), note, |g| {
        for row in &hub.rows {
            if let Some(chosen) = device_row(app, g, row) {
                action = Some(chosen);
            }
        }
    });
    // L3: the fallback of this Wi-Fi, with the listener and its pairing.
    ui.add_space(14.0);
    let id = egui::Id::new(PAIR_HERE_ID);
    let pairing = app
        .companion_controller()
        .is_some_and(|controller| controller.view() != PairingView::Closed);
    let mut open = ui
        .ctx()
        .data(|data| data.get_temp::<bool>(id))
        .unwrap_or(false)
        || pairing;
    kit::disclosure(ui, &mut open, PAIR_HERE);
    ui.ctx().data_mut(|data| data.insert_temp(id, open));
    if open {
        companion::draw(app, ui);
    }
    let ctx = ui.ctx().clone();
    if add {
        app.devices_add(Some(&ctx));
    } else if pair_here {
        app.devices_pair_here(Some(&ctx));
    }
    match action {
        Some(RowAction::Remove(removal)) => app.devices_ask_remove(removal, Some(&ctx)),
        Some(RowAction::StopHere) => app.questions_turn_off(),
        Some(RowAction::ApproveHere) => app.questions_turn_on(Some(&ctx)),
        Some(RowAction::Notify(notify)) => notify_act(app, notify),
        None => {}
    }
}

/// What a row asked for.
enum RowAction {
    Remove(Removal),
    StopHere,
    ApproveHere,
    Notify(NotifyAction),
}

/// What the owner chose for the macOS notifications of this Mac.
enum NotifyAction {
    Allow,
    OpenSettings,
    Check,
}

/// One device: its tile, its name, what it does and when it was last seen, and "⋯".
/// This Mac also shows its notifications while they do not work.
fn device_row(app: &DesktopApp, g: &mut rows::Group<'_>, row: &DeviceRow) -> Option<RowAction> {
    let mut action = None;
    let now = kit::now();
    let mut line = row.does.clone();
    if let Some(seen) = row.seen {
        line.push_str(" · ");
        line.push_str(&kit::relative_time(seen, now));
    }
    let spoken = format!("{}, {}", row.name, line.to_lowercase());
    g.row(|ui| {
        egui::Sides::new().shrink_left().show(
            ui,
            |ui| {
                let icon = match row.kind {
                    DeviceKind::Iphone => Icon::Phone,
                    DeviceKind::ThisMac | DeviceKind::Mac => Icon::Laptop,
                };
                let tile = kit::Tile {
                    round: true,
                    ..kit::Tile::icon(TILE_GRAY, icon)
                };
                let response = kit::tile(ui, &tile, TILE);
                ui.ctx()
                    .accesskit_node_builder(response.id, |node| node.set_label(spoken.clone()));
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.add(Label::new(kit::row_title(&row.name)).truncate());
                    ui.add(Label::new(rows::note(&line)).wrap());
                });
            },
            |ui| {
                let menu = row.remove.is_some() || row.stop_here || row.approve_here;
                if menu {
                    let more = kit::icon_button(
                        ui,
                        Icon::More,
                        &format!("More actions for {}", row.name),
                        kit::Size::Small,
                    );
                    egui::Popup::menu(&more).show(|ui| {
                        ui.set_min_width(180.0);
                        if row.stop_here && ui.selectable_label(false, STOP_HERE).clicked() {
                            action = Some(RowAction::StopHere);
                        }
                        if row.approve_here && ui.selectable_label(false, APPROVE_HERE).clicked() {
                            action = Some(RowAction::ApproveHere);
                        }
                        if let Some(removal) = &row.remove
                            && ui
                                .selectable_label(
                                    false,
                                    kit::text("Remove…", Font::Body).color(Tone::Critical.text()),
                                )
                                .clicked()
                        {
                            action = Some(RowAction::Remove(removal.clone()));
                        }
                    });
                }
            },
        );
        if row.kind == DeviceKind::ThisMac
            && let Some(notify) = notifications_problem(app, ui)
        {
            action = Some(RowAction::Notify(notify));
        }
    });
    action
}

/// The notifications of this Mac under its row, only while they do not work (goal items
/// N1 to N4): what to do, and the buttons for it.
fn notifications_problem(app: &DesktopApp, ui: &mut egui::Ui) -> Option<NotifyAction> {
    let Some(view) = app.owner.notifications.as_ref().map(|center| center.view()) else {
        kit::tone_note(
            ui,
            "Notifications are not running. They start with the broker. Questions still wait in Decisions.",
            Tone::Warning,
        );
        return None;
    };
    let channel = &view.channel;
    let failed = view
        .deliveries
        .values()
        .filter(|delivery| matches!(delivery, Delivery::Failed(_)))
        .count();
    if channel.can_deliver() && failed == 0 {
        return None;
    }
    let mut action = None;
    if !channel.can_deliver() {
        kit::tone_note(ui, channel.summary(), Tone::Warning);
        ui.horizontal(|ui| {
            if channel.needs_permission()
                && kit::small_button(ui, "Allow…", Style::Prominent)
                    .on_hover_text(
                        "macOS shows a prompt for \"Apassy\" at the top right of the screen. Select \"Allow\".",
                    )
                    .clicked()
            {
                action = Some(NotifyAction::Allow);
            }
            if channel.needs_settings()
                && kit::small_button(ui, "Open System Settings…", Style::Bordered)
                    .on_hover_text(
                        "System Settings > Notifications > Apassy. Turn on \"Allow notifications\" and select \"Banners\".",
                    )
                    .clicked()
            {
                action = Some(NotifyAction::OpenSettings);
            }
            if kit::small_button(ui, "Check again", Style::Bordered).clicked() {
                action = Some(NotifyAction::Check);
            }
        });
    }
    if failed > 0 {
        kit::tone_note(
            ui,
            format!(
                "{failed} {} failed. Questions still wait in Decisions.",
                if failed == 1 {
                    "notification"
                } else {
                    "notifications"
                }
            ),
            Tone::Critical,
        );
    }
    action
}

fn notify_act(app: &mut DesktopApp, action: NotifyAction) {
    let Some(center) = &app.owner.notifications else {
        return;
    };
    match action {
        // The notifier (Contents/Helpers/ApassyNotify.app, display name "Apassy") asks
        // macOS. After a denial, macOS shows no new prompt.
        NotifyAction::Allow => center.request_permission(),
        NotifyAction::OpenSettings => match notify::open_notification_settings() {
            Ok(()) => center.refresh_status(),
            Err(err) => center.report_problem(format!(
                "Apassy cannot open System Settings ({err}). Open System Settings > Notifications > Apassy."
            )),
        },
        NotifyAction::Check => center.refresh_status(),
    }
}

/// Draw `sheet`. Returns whether Escape closes it, as each sheet.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, sheet: &DevicesSheet) -> bool {
    match sheet {
        DevicesSheet::AddDevice => add_device_sheet(app, ctx),
        DevicesSheet::PairHere => pair_here_sheet(app, ctx),
        DevicesSheet::RemoveTeamDevice {
            team_id,
            device_id,
            name,
        } => remove_team_device_sheet(app, ctx, team_id, *device_id, name),
        DevicesSheet::RemoveWifi { device_id, name } => {
            remove_wifi_sheet(app, ctx, device_id, name)
        }
    }
}

/// What the owner did in the "Add a device" sheet.
enum AddAction {
    Confirm(u64),
    Refuse(u64),
    NewCode,
    CheckAgain,
    Connect,
    PairHere,
    OtherRelay,
    PairCode,
    Done,
}

/// "Add a device" (M2): the QR code and the link, then each device that asks with the
/// safety words, "Confirm with Touch ID", and "Refuse"; the end with "Add another
/// device" and "Done". For a vault with no team, the Apassy Connect team comes first.
fn add_device_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let Some(entry) = app.current_vault().cloned() else {
        close_add(app, ctx);
        return false;
    };
    let questions = &app.sync.relay.questions;
    let asked = questions.connect_asked(&entry.id);
    let creating = questions.creating(&entry.id);
    let checking = app.owner.check.is_some();
    let started = app.relay_add_device_started(&entry.id);
    let connect_error = (!started).then(|| questions.error.clone()).flatten();
    // The pairing link of this network, while its window is open: the fallback in the
    // QR code.
    let fallback = app
        .companion_controller()
        .filter(|controller| matches!(controller.view(), PairingView::Open { .. }))
        .and(app.companion.invite_link.clone());
    let view = if started {
        app.relay_add_device_view(ctx, fallback.as_deref().map(|link| link.as_str()))
    } else {
        None
    };
    let local = companion::asking_to_pair(app);
    let mut action = None;
    let mut done = false;
    let response = kit::sheet(ctx, "devices-add", 520.0, |ui| {
        if let Some(added) = view.as_ref().and_then(|view| view.added.clone()) {
            success(ui, &added, &mut action);
            return;
        }
        kit::sheet_title(ui, "Add a device", None);
        if !started {
            // The first "Add a device" of a vault with no team.
            match &connect_error {
                Some(error) => {
                    kit::notice(
                        ui,
                        Tone::Critical,
                        "This vault is not connected yet",
                        Some(error),
                        |ui| {
                            ui.horizontal(|ui| {
                                if kit::small_button(ui, "Try again", Style::Bordered).clicked() {
                                    action = Some(AddAction::Connect);
                                }
                                if kit::small_button(
                                    ui,
                                    "Pair on this network instead",
                                    Style::Link,
                                )
                                .clicked()
                                {
                                    action = Some(AddAction::PairHere);
                                }
                            });
                        },
                    );
                }
                None if creating => {
                    waiting_line(ui, "Apassy connects this vault…");
                }
                None if asked && checking => {
                    waiting_line(ui, "Confirm with Touch ID to connect this vault…");
                }
                None => {
                    kit::paragraph(
                        ui,
                        "Apassy Connect links your devices to this vault, so each question reaches them. It sees no command and no credential. Turning it on needs Touch ID or your passphrase here.",
                        Font::Body,
                        kit::LABEL,
                    );
                    ui.add_space(8.0);
                    if kit::button(ui, "Connect with Touch ID", Style::Prominent).clicked() {
                        action = Some(AddAction::Connect);
                    }
                }
            }
        }
        if let Some(view) = &view {
            link_part(ui, view, &mut action);
        }
        if let Some((device, wrong)) = &local {
            ui.add_space(10.0);
            if companion::code_entry(app, ui, device, *wrong) {
                action = Some(AddAction::PairCode);
            }
        }
        kit::sheet_buttons(
            ui,
            |ui| {
                if kit::small_button(ui, "Pair on this network instead", Style::Link).clicked() {
                    action = Some(AddAction::PairHere);
                }
                if !started && kit::small_button(ui, "Use another relay…", Style::Link).clicked()
                {
                    action = Some(AddAction::OtherRelay);
                }
            },
            |ui| {
                done = kit::button(ui, "Done", Style::Bordered).clicked();
            },
        );
    });
    if done {
        action = Some(AddAction::Done);
    }
    match action {
        Some(AddAction::Confirm(link_id)) => app.relay_ask_confirm(link_id, Some(ctx)),
        Some(AddAction::Refuse(link_id)) => app.relay_refuse_link(link_id),
        Some(AddAction::NewCode) => app.relay_add_device_again(),
        Some(AddAction::CheckAgain) => app.relay_add_mac_poll(),
        Some(AddAction::Connect) => {
            app.sync.relay.questions.error = None;
            let url = app.connect_relay_url();
            app.questions_ask_connect(&entry, &url, Some(ctx));
        }
        Some(AddAction::PairHere) => app.devices_pair_here(Some(ctx)),
        Some(AddAction::OtherRelay) => {
            app.devices_close_add();
            app.sync_open_sheet(SyncSheet::QuestionsTeam { id: entry.id }, Some(ctx));
        }
        Some(AddAction::PairCode) => app.submit_pairing_code(ctx),
        Some(AddAction::Done) => close_add(app, ctx),
        None => {}
    }
    if response.escape {
        app.devices_close_add();
        cancel_unused_pairing(app);
    }
    response.escape
}

/// The QR code, the link, and the devices that ask.
fn link_part(
    ui: &mut egui::Ui,
    view: &super::sync::relay::AddDeviceView,
    action: &mut Option<AddAction>,
) {
    if let Some(progress) = view.progress {
        waiting_line(ui, progress);
    }
    if view.removed {
        kit::tone_note(
            ui,
            "This Mac was removed from the relay team of this vault, so it cannot add a device.",
            Tone::Critical,
        );
        return;
    }
    if let Some(link) = &view.link {
        if let Some(qr) = &view.qr {
            ui.vertical_centered(|ui| {
                super::companion::draw_qr(ui, qr, QR_POINTS, "Add a device QR code");
            });
            ui.add_space(8.0);
        }
        let how = match view.route {
            LinkRoute::Connect => {
                "On your iPhone, open Apassy and select Connect to your Mac. On another Mac with this vault, paste the link in Settings > Devices."
            }
            LinkRoute::Sync => {
                "On your iPhone, open Apassy and select Connect to your Mac. On another Mac, select Use a vault from another Mac and paste the link."
            }
        };
        kit::paragraph(ui, how, Font::Callout, kit::SECONDARY);
        ui.add_space(6.0);
        let heading = ui.label(kit::text("Link", Font::Headline).color(kit::LABEL));
        kit::code_block(ui, link, 1).labelled_by(heading.id);
        ui.horizontal(|ui| {
            if kit::small_button(ui, "Copy link", Style::Bordered).clicked() {
                ui.ctx().copy_text(link.to_string());
            }
            kit::note(
                ui,
                "Works once, for 10 minutes. Nothing is shared until you confirm here.",
            );
        });
        ui.add_space(8.0);
    }
    if let Some(error) = &view.error {
        kit::notice(ui, Tone::Critical, UNREACHABLE, Some(error), |ui| {
            ui.horizontal(|ui| {
                if kit::small_button(ui, "Try again", Style::Bordered).clicked() {
                    *action = Some(if view.link.is_some() {
                        AddAction::CheckAgain
                    } else {
                        AddAction::NewCode
                    });
                }
                if kit::small_button(ui, "Pair on this network instead", Style::Link).clicked() {
                    *action = Some(AddAction::PairHere);
                }
            });
        });
        return;
    }
    if view.expired {
        ui.horizontal(|ui| {
            kit::tone_note(ui, "This code expired.", Tone::Neutral);
            if kit::small_button(ui, "New code", Style::Bordered).clicked() {
                *action = Some(AddAction::NewCode);
            }
        });
    } else if view.asking.is_empty() && view.link.is_some() {
        waiting_line(ui, "Waiting for your device…");
    }
    for device in &view.asking {
        ui.add_space(8.0);
        match &device.words {
            Some(words) => {
                kit::paragraph(
                    ui,
                    format!("{} wants to connect. Both show:", device.name),
                    Font::Body,
                    kit::LABEL,
                );
                ui.add_space(4.0);
                ui.label(kit::text(words, Font::Title).color(kit::LABEL));
                ui.add_space(4.0);
                kit::paragraph(
                    ui,
                    "Confirm only if your device shows the same words. They prove that the code reached your device and no one else's.",
                    Font::Callout,
                    kit::SECONDARY,
                );
                ui.add_space(6.0);
                ui.add_enabled_ui(!view.deciding, |ui| {
                    ui.horizontal(|ui| {
                        if kit::button(ui, "Confirm with Touch ID", Style::Prominent).clicked() {
                            *action = Some(AddAction::Confirm(device.link_id));
                        }
                        if kit::button(ui, "Refuse", Style::Bordered).clicked() {
                            *action = Some(AddAction::Refuse(device.link_id));
                        }
                    });
                });
            }
            None => {
                kit::paragraph(
                    ui,
                    format!(
                        "{} asks with an older link. Refuse it, and make a new code.",
                        device.name
                    ),
                    Font::Body,
                    kit::LABEL,
                );
                if kit::small_button(ui, "Refuse", Style::Bordered).clicked() {
                    *action = Some(AddAction::Refuse(device.link_id));
                }
            }
        }
    }
}

/// The end of "Add a device": the device and what it does now, "Add another device",
/// and "Done".
fn success(ui: &mut egui::Ui, added: &str, action: &mut Option<AddAction>) {
    kit::sheet_title(ui, "Add a device", None);
    ui.horizontal(|ui| {
        kit::paint_icon_in(ui, Icon::Check, 18.0, Tone::Good.mark());
        ui.label(kit::text(added, Font::Headline).color(kit::LABEL));
    });
    ui.add_space(4.0);
    kit::paragraph(
        ui,
        "Each question now goes to every device. Remove a device in Settings > Devices.",
        Font::Callout,
        kit::SECONDARY,
    );
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if kit::button(ui, "Done", Style::Prominent).clicked() {
                *action = Some(AddAction::Done);
            }
            if kit::button(ui, "Add another device", Style::Bordered).clicked() {
                *action = Some(AddAction::NewCode);
            }
        },
    );
}

/// A line of what runs: the progress dot of the sync status and the words.
fn waiting_line(ui: &mut egui::Ui, words: &str) {
    ui.horizontal(|ui| {
        kit::dot(ui, Tone::Accent);
        ui.label(kit::text(words, Font::Callout).color(kit::SECONDARY));
    });
}

fn close_add(app: &mut DesktopApp, ctx: &egui::Context) {
    app.devices_close_add();
    cancel_unused_pairing(app);
    close_sheet(app, ctx);
}

/// A pairing window that "Add a device" opened and no iPhone used closes with the sheet.
fn cancel_unused_pairing(app: &mut DesktopApp) {
    let unused = app
        .companion_controller()
        .is_some_and(|controller| matches!(controller.view(), PairingView::Open { .. }));
    if unused {
        app.cancel_pairing();
    }
}

/// "Pair on this network": the QR code of the listener, the code that the iPhone shows,
/// and the end. An iPhone paired here approves only on this Wi-Fi.
fn pair_here_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let controller = app.companion_controller();
    let view = controller.as_ref().map(|controller| controller.view());
    let failed = match &app.companion.listener {
        crate::desktop::companion::Listener::Failed { message, .. } => Some(message.clone()),
        _ => None,
    };
    let local = companion::asking_to_pair(app);
    let qr = app.companion.invite.clone();
    let opening = app.companion.opening_window();
    let mut action = None;
    let mut make_code = false;
    let response = kit::sheet(ctx, "devices-pair-here", 480.0, |ui| {
        kit::sheet_title(
            ui,
            "Pair on this network",
            Some(
                "Without Apassy Connect, an iPhone on the same Wi-Fi as this Mac approves with Face ID. It approves only while it is on this Wi-Fi.",
            ),
        );
        if let Some(message) = &failed {
            kit::notice(
                ui,
                Tone::Critical,
                "The listener did not start",
                Some(message),
                |ui| {
                    if kit::small_button(ui, "Try again", Style::Bordered).clicked() {
                        action = Some(AddAction::CheckAgain);
                    }
                },
            );
        }
        match (&view, &local) {
            (_, Some((device, wrong))) => {
                if companion::code_entry(app, ui, device, *wrong) {
                    action = Some(AddAction::PairCode);
                }
            }
            (Some(PairingView::Open { expires_at }), None) => {
                if let Some(qr) = &qr {
                    ui.vertical_centered(|ui| {
                        super::companion::draw_qr(ui, qr, QR_POINTS, "Pairing QR code");
                    });
                }
                ui.add_space(8.0);
                kit::paragraph(
                    ui,
                    "On your iPhone, open Apassy, select Connect to your Mac, and scan this code. Then type here the 6-digit code that the iPhone shows.",
                    Font::Callout,
                    kit::SECONDARY,
                );
                let left = expires_at.saturating_sub(crate::desktop::companion::now());
                kit::note(
                    ui,
                    format!(
                        "The code works for {}. Do not photograph or share it.",
                        companion::countdown(left)
                    ),
                );
            }
            _ if opening => waiting_line(ui, "Apassy is making the pairing code…"),
            _ if failed.is_none() => {
                make_code = kit::button(ui, "Make a pairing code", Style::Prominent).clicked();
            }
            _ => {}
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if kit::button(ui, "Done", Style::Bordered).clicked() {
                    action = Some(AddAction::Done);
                }
            },
        );
    });
    if make_code {
        action = Some(AddAction::NewCode);
    }
    match action {
        Some(AddAction::PairCode) => app.submit_pairing_code(ctx),
        Some(AddAction::NewCode) => super::settings::add_an_iphone(app, ctx),
        Some(AddAction::CheckAgain) => app.retry_companion(),
        Some(AddAction::Done) => {
            cancel_unused_pairing(app);
            close_sheet(app, ctx);
        }
        _ => {}
    }
    if response.escape {
        cancel_unused_pairing(app);
    }
    response.escape
}

/// The confirmation of "Remove…" of a device of a relay team with no trusted row.
fn remove_team_device_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    team_id: &str,
    device_id: u64,
    name: &str,
) -> bool {
    let mut remove = false;
    let mut keep = false;
    let response = kit::sheet(ctx, "devices-remove-team-device", 440.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Remove “{name}”?"),
            Some(
                "It can no longer sync or approve through Apassy, and Apassy makes a new question key. It keeps the copy of the vault that it has: to lock a person out, also change the passphrase and rotate each credential. To add it again you need a new code and your confirmation.",
            ),
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
        app.devices_remove_team_device(team_id, device_id, name);
        close_sheet(app, ctx);
    } else if keep {
        close_sheet(app, ctx);
    }
    response.escape
}

/// The confirmation of "Remove…" of an iPhone paired on this Wi-Fi. It takes effect at
/// once and needs no owner check: it only takes authority away.
fn remove_wifi_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    device_id: &str,
    name: &str,
) -> bool {
    let mut remove = false;
    let mut keep = false;
    let response = kit::sheet(ctx, "devices-remove-wifi", 420.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Remove “{name}”?"),
            Some(
                "It can no longer reach this Mac or approve on this Wi-Fi. To add it again, pair it again.",
            ),
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
        app.remove_companion_device(device_id, name);
        close_sheet(app, ctx);
    } else if keep {
        close_sheet(app, ctx);
    }
    response.escape
}

impl DesktopApp {
    /// Remove a device of a relay team that has no trusted row: from the relay sync team
    /// as "Remove" of relay sync does, else from the questions team. No owner check.
    pub(crate) fn devices_remove_team_device(&mut self, team_id: &str, device_id: u64, name: &str) {
        let sync = self.current_vault().and_then(|entry| {
            entry
                .sync_relay()
                .map(|link| (entry.id.clone(), link.team_id.clone()))
        });
        match sync {
            Some((id, team)) if team == team_id => self.relay_remove_device(&id, device_id, name),
            _ => self.questions_revoke_device(team_id, device_id, name),
        }
    }
}
