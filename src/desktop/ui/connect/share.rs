//! Settings › Connect › Shared Vaults: a vault shared between the accounts of one family
//! or team (contract connect-account-v1 section 16, `crate::connect::share`).
//!
//! - **Share with…** on a store of this account: pick a member (the group view of Connect
//!   is only a list to pick from). For a member whose root this account pinned already,
//!   and whose verified list pins this account, the share needs one owner check and no
//!   words; else this Mac makes a share code, keeps it in memory, and shows it with a QR
//!   code: "Send this to <name>." (also again for a member who did not finish the words).
//!   When the member answers, both Macs show six words; Confirm runs the owner check, and
//!   this Mac signs the `peer` and the `share` and adds the member's verified devices to the
//!   store.
//! - **Accept a Shared Vault…**: paste the code. The Mac checks the account and the device
//!   that Connect names against the code ("The code does not match the account that
//!   answered." otherwise), shows the six words, and "The Words Match" runs the owner check
//!   and signs the `peer`. The stores that the other account shares with this one then
//!   show here: "<vault>, shared by <name>: Join". Join runs an owner check that names the
//!   vault and the person, signs the `join`, and opens the download of "Use a Vault from
//!   Another Mac" with the passphrase of the copy.
//! - **Stop Sharing with <name>…** and **Leave This Shared Vault…** sign `unshare` and
//!   `leave` after an owner check. Leave turns off the sync of that vault here and keeps the
//!   vault; the other devices of the account do the same when they read the `leave`. The
//!   ends that need no owner check (a member who left, a member outside the family or team)
//!   are signed by the account itself at a refresh, and show as notes.
//! - Each owner check names the vault by its name on this computer, the person by the name
//!   that their verified device list signed with the short fingerprint of the pinned root,
//!   and Connect's name for them only beside it.
//! - The states: "<name>: has not joined yet", "<name> reset the account. Share again.",
//!   "<name> must verify this account again.", and the sync lines "Checking who shares
//!   this vault…" (for a head whose signer is not verified yet, 10 minutes once for each
//!   head, while the lists are read again after 30 s, then after twice the wait, up to 10
//!   minutes) and "Waiting for a device that shares this vault".
//!
//! One step at a time runs on a worker with the account of the one session of the app
//! (`super::live`); the UI thread never waits on Connect. The signers of the vault stores
//! reach the sync after each step that wrote the account file, whether or not a call to
//! Connect worked (`super::live`, `AccountSession::signers_after`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Ui};
use zeroize::Zeroizing;

use super::super::devices::rows;
use super::super::kit::{self, Font, Style, Tone};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::connect::share::{ShareConfirmed, StoreStatus};
use crate::connect::{
    ConnectAccount, ConnectError, GroupMember, ShareLink, ShareNames, SharePeerJoin, ShareRequest,
    ShareStatus, VaultStoreView,
};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};

// ---- Texts (plain English, the style of the other Connect screens). ----

pub(crate) const SECTION: &str = "Shared Vaults";
pub(crate) const SECTION_NOTE: &str =
    "Share a vault with a person of your family or team. Each of you compares six words once.";
pub(crate) const SHARE_WITH: &str = "Share with…";
pub(crate) const ACCEPT: &str = "Accept a Shared Vault…";
pub(crate) const PICK_TITLE: &str = "Share a Vault";
pub(crate) const PICK_LEAD: &str =
    "Choose the person. They need the passphrase of the vault to open it.";
pub(crate) const NO_MEMBERS: &str =
    "Your family or team has no other active member. Invite someone first.";
pub(crate) const CODE_TITLE: &str = "Share Code";
pub(crate) const CODE_WAITING: &str = "Waiting for the other person…";
pub(crate) const CONFIRM_TITLE: &str = "Compare the Words";
pub(crate) const ACCEPT_TITLE: &str = "Accept a Shared Vault";
pub(crate) const ACCEPT_LEAD: &str = "Paste the code that the other person sent you.";
pub(crate) const WORDS_MATCH: &str = "The Words Match";
pub(crate) const WORDS_DIFFER: &str = "The Words Differ";
pub(crate) const DIFFERENT: &str =
    "Nothing was signed. Make a new code and compare the words again.";
pub(crate) const MISMATCH: &str = "The code does not match the account that answered.";
pub(crate) const EXPIRED: &str = "The code expired. Nothing was signed. Make a new code.";
pub(crate) const JOIN: &str = "Join";
pub(crate) const LEAVE: &str = "Leave This Shared Vault…";
pub(crate) const CHECKING: &str = "Checking who shares this vault…";
pub(crate) const WAITING_SHARED: &str = "Waiting for a device that shares this vault";
pub(crate) const ENDED: &str = "The share ended. The vault stays on this device.";
pub(crate) const LEAVE_LEAD: &str = "This device stops syncing the shared copy. The vault stays on this device, and the other person keeps theirs.";
pub(crate) const STOP_LEAD: &str =
    "Their devices leave the shared copy now. The vault stays on every device that has it.";
pub(crate) const ACCEPTED_LEAD: &str =
    "The vaults that they share with you show in Settings › Connect.";
pub(crate) const LEFT_HERE: &str =
    "You left this shared vault. It stays on this device and does not sync the shared copy.";
pub(crate) const UNPINNED: &str = "Some people who share a vault that you joined could not be verified on this device. Their devices sign nothing here.";
pub(crate) const DOWNLOAD: &str = "Download the Shared Copy…";
pub(crate) const VAULT_OFFERED: &str = "A vault";

/// Every fixed text of the section, for the wording tests.
#[cfg(test)]
pub(crate) const TEXTS: &[&str] = &[
    SECTION,
    SECTION_NOTE,
    SHARE_WITH,
    ACCEPT,
    PICK_TITLE,
    PICK_LEAD,
    NO_MEMBERS,
    CODE_TITLE,
    CODE_WAITING,
    CONFIRM_TITLE,
    ACCEPT_TITLE,
    ACCEPT_LEAD,
    WORDS_MATCH,
    WORDS_DIFFER,
    DIFFERENT,
    MISMATCH,
    EXPIRED,
    JOIN,
    LEAVE,
    CHECKING,
    WAITING_SHARED,
    ENDED,
    LEAVE_LEAD,
    STOP_LEAD,
    ACCEPTED_LEAD,
    LEFT_HERE,
    UNPINNED,
    DOWNLOAD,
    VAULT_OFFERED,
];

/// "Send this to <name>."
pub(crate) fn send_to(name: &str) -> String {
    format!("Send this to {name}.")
}

/// The words line on the device that made the code.
pub(crate) fn asks(name: &str, device: &str) -> String {
    format!("{name} ({device}) asks to share vaults with you.")
}

/// The words tail on the device that made the code.
pub(crate) fn confirm_tail(name: &str) -> String {
    format!("Confirm only if {name}'s screen shows the same words.")
}

/// The words tail on the device that answered the code.
pub(crate) fn match_tail(name: &str) -> String {
    format!("Go on only if {name}'s screen shows the same words.")
}

/// A member that has not joined yet.
pub(crate) fn not_joined(name: &str) -> String {
    format!("{name}: has not joined yet")
}

/// A member whose list does not pin this account yet: they did not finish the words.
pub(crate) fn not_accepted(name: &str) -> String {
    format!("{name}: has not finished comparing the words. Share with… shows a new code.")
}

/// The owner's line for a member that reset its account.
pub(crate) fn reset_owner(name: &str) -> String {
    format!("{name} reset the account. Share again.")
}

/// The member's line for an owner that reset its account.
pub(crate) fn reset_member(name: &str) -> String {
    format!("{name} must verify this account again.")
}

/// The button that ends a share for a member.
pub(crate) fn stop(name: &str) -> String {
    format!("Stop Sharing with {name}…")
}

/// An offer, or a store that this account joined.
pub(crate) fn shared_by(vault: &str, name: &str) -> String {
    format!("{vault}, shared by {name}")
}

/// The result of a share.
pub(crate) fn shared_with(name: &str) -> String {
    format!("Shared with {name}")
}

/// A note on another device of the account that left a shared vault.
pub(crate) fn left_on(device: &str) -> String {
    format!("You left this shared vault on {device}.")
}

/// A store that this account joined, whose owner ended the share (or shares it anew).
pub(crate) fn stopped(name: &str) -> String {
    format!("{name} stopped sharing this vault.")
}

/// A member of a store of this account whose list left the share.
pub(crate) fn left_vault(name: &str) -> String {
    format!("{name} left this vault.")
}

/// A member of a store of this account whose share ended otherwise.
pub(crate) fn sharing_ended(name: &str) -> String {
    format!("Sharing with {name} ended.")
}

/// The button that shares a store again with a member whose share ended.
pub(crate) fn share_again(name: &str) -> String {
    format!("Share with {name} Again…")
}

/// The name that Connect gives a store of another account: a hint beside it.
pub(crate) fn connect_calls(name: &str) -> String {
    format!("Apassy Connect calls it \u{201c}{name}\u{201d}.")
}

/// Join worked, and Connect does not list this device in the store yet.
pub(crate) fn not_listed(name: &str) -> String {
    format!(
        "This device is not in the shared copy yet. It is added when {name} opens Apassy on a device that syncs this vault. Then choose {DOWNLOAD}"
    )
}

// ---- The model of the section. ----

/// A store of this account and its members, as the section shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnStore {
    pub(crate) team_id: String,
    pub(crate) vault: String,
    /// The members: name, account, the line under it.
    pub(crate) members: Vec<(String, String, String)>,
    /// The members whose share ended: name, account, the line under it. Each row offers
    /// "Share with <name> Again…".
    pub(crate) ended: Vec<(String, String, String)>,
}

/// A store of another account: joined (with its state), offered, or left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtherStore {
    pub(crate) team_id: String,
    pub(crate) owner: String,
    pub(crate) title: String,
    /// `None`: offered, not joined; else the line of the joined store.
    pub(crate) joined: Option<String>,
    /// A line under an offer (the name that Connect gives the store), or of a left store.
    pub(crate) note: Option<String>,
    /// Joined, and no vault of this computer syncs it: the row offers the download.
    pub(crate) download: bool,
    /// This account left it: the row has no button.
    pub(crate) left: bool,
}

/// What the section shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ShareView {
    pub(crate) own: Vec<OwnStore>,
    pub(crate) others: Vec<OtherStore>,
    /// The account is in an active family or team: "Share with…" and "Accept…" work.
    pub(crate) in_group: bool,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
    /// What this device did by itself, or learned: shown as notes.
    pub(crate) notes: Vec<String>,
}

/// A press in the section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShareAction {
    ShareWith {
        team_id: String,
        vault: String,
    },
    Accept,
    Join {
        team_id: String,
        owner: String,
    },
    /// Download the copy of a store that this account joined.
    Download {
        team_id: String,
        owner: String,
    },
    /// Share a store of this account again with a member whose share ended.
    ShareAgain {
        team_id: String,
        account: String,
        name: String,
    },
    Stop {
        team_id: String,
        account: String,
        name: String,
    },
    Leave {
        team_id: String,
        owner: String,
        name: String,
    },
}

/// A sheet of the section.
#[derive(Debug)]
pub(crate) enum ShareSheet {
    /// Choose the member.
    Pick {
        team_id: String,
        vault: String,
        /// (account, name) of the active members other than this account.
        members: Vec<(String, String)>,
        chosen: Option<usize>,
    },
    /// "Send this to <name>.": the code as text and QR, while the answer waits.
    Code {
        name: String,
        code: Zeroizing<String>,
        expires_at: u64,
    },
    /// The words on the device that made the code.
    Confirm {
        join_id: u64,
        name: String,
        device: String,
        words: String,
    },
    /// "Accept a Shared Vault…": the pasted code.
    Paste { code: Zeroizing<String> },
    /// The words on the device that answered.
    Match {
        name: String,
        device: String,
        words: String,
    },
    /// A destructive confirmation of Stop Sharing or Leave.
    End {
        team_id: String,
        account: String,
        name: String,
        leave: bool,
    },
    /// A result.
    Done { title: String, line: String },
}

/// A choice in a sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ShareChoice {
    Cancel,
    Go,
    /// "The Words Differ" or "Refuse".
    Differ,
    Done,
    Copy(String),
}

// ---- Drawing (pure: the view in, a press out). ----

/// The "Shared Vaults" group.
pub(crate) fn draw(ui: &mut Ui, view: &ShareView) -> Option<ShareAction> {
    let mut action = None;
    if let Some(error) = &view.error {
        rows::footnote_colored(ui, error.as_str(), Tone::Critical.text());
    }
    for note in &view.notes {
        rows::footnote(ui, note.as_str());
    }
    ui.add_enabled_ui(!view.busy, |ui| {
        rows::group(ui, Some(SECTION), |g| {
            for store in &view.own {
                g.row(|ui| {
                    rows::one_line(ui, rows::label_text(&store.vault).into(), None, |ui| {
                        if view.in_group
                            && kit::small_button(ui, SHARE_WITH, Style::Bordered).clicked()
                        {
                            action = Some(ShareAction::ShareWith {
                                team_id: store.team_id.clone(),
                                vault: store.vault.clone(),
                            });
                        }
                    });
                    for (name, account, line) in &store.members {
                        ui.horizontal(|ui| {
                            ui.add(egui::Label::new(rows::note(line)).wrap());
                            if kit::small_button(ui, &stop(name), Style::Bordered).clicked() {
                                action = Some(ShareAction::Stop {
                                    team_id: store.team_id.clone(),
                                    account: account.clone(),
                                    name: name.clone(),
                                });
                            }
                        });
                    }
                    for (name, account, line) in &store.ended {
                        ui.horizontal(|ui| {
                            ui.add(egui::Label::new(rows::note(line)).wrap());
                            if view.in_group
                                && kit::small_button(ui, &share_again(name), Style::Bordered)
                                    .clicked()
                            {
                                action = Some(ShareAction::ShareAgain {
                                    team_id: store.team_id.clone(),
                                    account: account.clone(),
                                    name: name.clone(),
                                });
                            }
                        });
                    }
                });
            }
            for store in &view.others {
                g.row(|ui| {
                    rows::one_line(ui, rows::label_text(&store.title).into(), None, |ui| {
                        match &store.joined {
                            _ if store.left => {}
                            None => {
                                if kit::small_button(ui, JOIN, Style::Bordered).clicked() {
                                    action = Some(ShareAction::Join {
                                        team_id: store.team_id.clone(),
                                        owner: store.owner.clone(),
                                    });
                                }
                            }
                            Some(_) => {
                                if kit::small_button(ui, LEAVE, Style::Bordered).clicked() {
                                    action = Some(ShareAction::Leave {
                                        team_id: store.team_id.clone(),
                                        owner: store.owner.clone(),
                                        name: store.title.clone(),
                                    });
                                }
                                if store.download
                                    && kit::small_button(ui, DOWNLOAD, Style::Bordered).clicked()
                                {
                                    action = Some(ShareAction::Download {
                                        team_id: store.team_id.clone(),
                                        owner: store.owner.clone(),
                                    });
                                }
                            }
                        }
                    });
                    for line in store
                        .joined
                        .iter()
                        .chain(&store.note)
                        .filter(|line| !line.is_empty())
                    {
                        ui.add(egui::Label::new(rows::note(line)).wrap());
                    }
                });
            }
            g.row(|ui| {
                rows::one_line(ui, rows::label_text(SECTION_NOTE).into(), None, |ui| {
                    if view.in_group && kit::small_button(ui, ACCEPT, Style::Bordered).clicked() {
                        action = Some(ShareAction::Accept);
                    }
                });
            });
        });
    });
    action
}

fn big_words(ui: &mut Ui, words: &str) {
    ui.add_space(6.0);
    let list: Vec<&str> = words.split_whitespace().collect();
    for line in list.chunks(3) {
        ui.vertical_centered(|ui| {
            ui.label(
                kit::text(line.join("  "), Font::Title)
                    .variation(b"wght", 600.0)
                    .color(kit::palette().label),
            );
        });
        ui.add_space(4.0);
    }
    ui.add_space(6.0);
}

fn buttons(
    ui: &mut Ui,
    leading: Option<(&str, ShareChoice, Style)>,
    trailing: Option<(&str, ShareChoice)>,
    busy: bool,
) -> Option<ShareChoice> {
    let mut left = None;
    let mut right = None;
    kit::sheet_buttons(
        ui,
        |ui| {
            if busy {
                ui.add(egui::Spinner::new().size(14.0));
            }
            if let Some((label, pick, style)) = &leading
                && ui
                    .add_enabled_ui(!busy, |ui| kit::button(ui, label, *style))
                    .inner
                    .clicked()
            {
                left = Some(pick.clone());
            }
        },
        |ui| {
            if let Some((label, pick)) = &trailing
                && ui
                    .add_enabled_ui(!busy, |ui| kit::button(ui, label, Style::Prominent))
                    .inner
                    .clicked()
            {
                right = Some(pick.clone());
            }
            if kit::alert_cancel(ui).clicked() {
                right = Some(ShareChoice::Cancel);
            }
        },
    );
    left.or(right)
}

/// One sheet of the section.
pub(crate) fn sheet(
    ctx: &egui::Context,
    sheet: &mut ShareSheet,
    busy: bool,
    error: Option<&str>,
    now: u64,
    qr: &dyn Fn(&mut Ui, &str),
) -> Option<ShareChoice> {
    let mut choice = None;
    let response = kit::sheet(ctx, "connect-share-sheet", 420.0, |ui| {
        choice = sheet_body(ui, sheet, busy, now, qr);
        if let Some(error) = error {
            ui.add_space(4.0);
            kit::paragraph(ui, error, Font::Callout, Tone::Critical.text());
        }
    });
    if response.escape && choice.is_none() {
        choice = Some(ShareChoice::Cancel);
    }
    choice
}

fn continue_buttons(ui: &mut Ui, ready: bool, busy: bool) -> Option<ShareChoice> {
    let mut choice = None;
    kit::sheet_buttons(
        ui,
        |ui| {
            if busy {
                ui.add(egui::Spinner::new().size(14.0));
            }
        },
        |ui| {
            if ui
                .add_enabled_ui(ready && !busy, |ui| {
                    kit::button(ui, "Continue", Style::Prominent)
                })
                .inner
                .clicked()
            {
                choice = Some(ShareChoice::Go);
            }
            if kit::alert_cancel(ui).clicked() {
                choice = Some(ShareChoice::Cancel);
            }
        },
    );
    choice
}

fn sheet_body(
    ui: &mut Ui,
    sheet: &mut ShareSheet,
    busy: bool,
    now: u64,
    qr: &dyn Fn(&mut Ui, &str),
) -> Option<ShareChoice> {
    match sheet {
        ShareSheet::Pick {
            vault,
            members,
            chosen,
            ..
        } => {
            kit::sheet_title(ui, &format!("{PICK_TITLE}: {vault}"), Some(PICK_LEAD));
            if members.is_empty() {
                kit::paragraph(ui, NO_MEMBERS, Font::Callout, kit::palette().label);
            }
            rows::group_box(ui, |g| {
                for (index, (_, name)) in members.iter().enumerate() {
                    g.row(|ui| {
                        if ui.radio(*chosen == Some(index), name.as_str()).clicked() {
                            *chosen = Some(index);
                        }
                    });
                }
            });
            ui.add_space(8.0);
            continue_buttons(ui, chosen.is_some(), busy)
        }
        ShareSheet::Code {
            name,
            code,
            expires_at,
        } => {
            let mut choice = None;
            kit::sheet_title(ui, CODE_TITLE, Some(&send_to(name)));
            ui.vertical_centered(|ui| qr(ui, code.as_str()));
            ui.add_space(8.0);
            rows::group_box(ui, |g| {
                let shown = format!("{}…", &code[..code.len().min(26)]);
                g.line(
                    "Code",
                    Some(kit::text(shown, Font::Mono).color(kit::palette().label)),
                    |ui| {
                        if kit::small_button(ui, "Copy", Style::Bordered).clicked() {
                            choice = Some(ShareChoice::Copy(code.as_str().to_owned()));
                        }
                    },
                );
                let left = expires_at.saturating_sub(now);
                g.labeled(
                    "Expires In",
                    rows::value(format!("{}:{:02}", left / 60, left % 60)),
                );
            });
            ui.add_space(8.0);
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(12.0));
                    ui.label(rows::value(CODE_WAITING));
                });
            });
            ui.add_space(8.0);
            choice.or_else(|| buttons(ui, None, None, false))
        }
        ShareSheet::Confirm {
            name,
            device,
            words,
            ..
        } => {
            kit::sheet_title(
                ui,
                CONFIRM_TITLE,
                Some(&format!(
                    "{} Both devices show these words. {}",
                    asks(name, device),
                    confirm_tail(name)
                )),
            );
            big_words(ui, words);
            buttons(
                ui,
                Some(("Refuse", ShareChoice::Differ, Style::Destructive)),
                Some(("Confirm…", ShareChoice::Go)),
                busy,
            )
        }
        ShareSheet::Paste { code } => {
            kit::sheet_title(ui, ACCEPT_TITLE, Some(ACCEPT_LEAD));
            kit::mono_input(ui, code, "connect-share-code", "apassy_shr_…");
            ui.add_space(8.0);
            continue_buttons(ui, !code.trim().is_empty(), busy)
        }
        ShareSheet::Match {
            name,
            device,
            words,
        } => {
            kit::sheet_title(
                ui,
                CONFIRM_TITLE,
                Some(&format!(
                    "{name} ({device}) shares vaults with you. Both devices show these words. {}",
                    match_tail(name)
                )),
            );
            big_words(ui, words);
            buttons(
                ui,
                Some((WORDS_DIFFER, ShareChoice::Differ, Style::Destructive)),
                Some((&format!("{WORDS_MATCH}…"), ShareChoice::Go)),
                busy,
            )
        }
        ShareSheet::End { name, leave, .. } => {
            let (title, lead, button) = if *leave {
                ("Leave This Shared Vault?".to_owned(), LEAVE_LEAD, "Leave…")
            } else {
                (
                    format!("Stop Sharing with {name}?"),
                    STOP_LEAD,
                    "Stop Sharing…",
                )
            };
            let mut choice = None;
            kit::sheet_title(ui, &title, Some(lead));
            kit::sheet_buttons(
                ui,
                |ui| {
                    if busy {
                        ui.add(egui::Spinner::new().size(14.0));
                    }
                },
                |ui| {
                    if ui
                        .add_enabled_ui(!busy, |ui| kit::button(ui, button, Style::Destructive))
                        .inner
                        .clicked()
                    {
                        choice = Some(ShareChoice::Go);
                    }
                    if kit::alert_cancel(ui).clicked() {
                        choice = Some(ShareChoice::Cancel);
                    }
                },
            );
            choice
        }
        ShareSheet::Done { title, line } => {
            kit::sheet_title(ui, title, Some(line));
            let mut choice = None;
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| {
                    if kit::button(ui, "Done", Style::Prominent).clicked() {
                        choice = Some(ShareChoice::Done);
                    }
                },
            );
            choice
        }
    }
}

// ---- The model from what the account knows. ----

/// The view of the section from the last status, the stores, the names of the vaults on
/// this computer (`local`, by store), and whether the account is in a group. Every line
/// comes from the lists of the status, so the section says the same after a restart.
pub(crate) fn view_of(
    status: &ShareStatus,
    stores: &[VaultStoreView],
    local: &BTreeMap<String, String>,
    in_group: bool,
    checking: &[String],
) -> ShareView {
    let name_of = |team: &str| {
        local.get(team).cloned().unwrap_or_else(|| {
            stores
                .iter()
                .find(|store| store.team_id == team)
                .map_or_else(|| "A shared vault".to_owned(), |store| store.name.clone())
        })
    };
    // A store of another account: by its name on this computer, else as "a vault shared
    // by" the person, with Connect's name of it as a hint.
    let other_title = |team: &str, owner_name: &str| match local.get(team) {
        Some(vault) => (shared_by(vault, owner_name), None),
        None => (
            shared_by(VAULT_OFFERED, owner_name),
            stores
                .iter()
                .find(|store| store.team_id == team)
                .map(|store| connect_calls(&store.name)),
        ),
    };
    let theirs = |team: &str| {
        status.offers.iter().any(|offer| offer.team_id == team)
            || status.left.iter().any(|left| left.team_id == team)
            || status
                .stores
                .iter()
                .any(|store| store.team_id == team && store.owner.is_some())
    };
    let mut own: Vec<OwnStore> = stores
        .iter()
        .filter(|store| !theirs(&store.team_id))
        .map(|store| OwnStore {
            team_id: store.team_id.clone(),
            vault: name_of(&store.team_id),
            members: Vec::new(),
            ended: Vec::new(),
        })
        .collect();
    for shared in status.stores.iter().filter(|store| store.owner.is_none()) {
        let Some(store) = own.iter_mut().find(|own| own.team_id == shared.team_id) else {
            continue;
        };
        for member in &shared.members {
            let line = if member.suspended {
                reset_owner(&member.name)
            } else if member.joined {
                format!("{}: syncs this vault", member.name)
            } else if !member.accepted {
                not_accepted(&member.name)
            } else {
                not_joined(&member.name)
            };
            store
                .members
                .push((member.name.clone(), member.account_id.clone(), line));
        }
        for member in &shared.ended_members {
            let line = if member.left {
                left_vault(&member.name)
            } else {
                sharing_ended(&member.name)
            };
            store
                .ended
                .push((member.name.clone(), member.account_id.clone(), line));
        }
    }
    let mut others: Vec<OtherStore> = Vec::new();
    for offer in &status.offers {
        let (title, note) = other_title(&offer.team_id, &offer.owner_name);
        others.push(OtherStore {
            team_id: offer.team_id.clone(),
            owner: offer.owner.clone(),
            title,
            joined: None,
            note,
            download: false,
            left: false,
        });
    }
    for store in status.stores.iter().filter(|store| store.owner.is_some()) {
        if others.iter().any(|other| other.team_id == store.team_id) {
            // A newer share of a store that this account joined: the offer row.
            continue;
        }
        let owner_name = store.owner_name.clone().unwrap_or_default();
        let (title, note) = other_title(&store.team_id, &owner_name);
        others.push(OtherStore {
            download: !local.contains_key(&store.team_id) && !store.ended && !store.void,
            ..joined_store(store, title, note, checking)
        });
    }
    for left in &status.left {
        if others.iter().any(|other| other.team_id == left.team_id) {
            continue;
        }
        let (title, _) = other_title(&left.team_id, &status.name_of(&left.owner));
        others.push(OtherStore {
            team_id: left.team_id.clone(),
            owner: left.owner.clone(),
            title,
            joined: None,
            note: Some(if left.here {
                LEFT_HERE.to_owned()
            } else {
                left_on(&left.device)
            }),
            download: false,
            left: true,
        });
    }
    let mut notes = Vec::new();
    if !status.unpinned.is_empty() {
        notes.push(UNPINNED.to_owned());
    }
    ShareView {
        own,
        others,
        in_group,
        busy: false,
        error: None,
        notes,
    }
}

fn joined_store(
    store: &StoreStatus,
    title: String,
    note: Option<String>,
    checking: &[String],
) -> OtherStore {
    let owner_name = store.owner_name.clone().unwrap_or_default();
    let line = if store.owner_suspended {
        reset_member(&owner_name)
    } else if store.void {
        ENDED.to_owned()
    } else if store.ended {
        stopped(&owner_name)
    } else if checking.contains(&store.team_id) {
        CHECKING.to_owned()
    } else {
        String::new()
    };
    OtherStore {
        team_id: store.team_id.clone(),
        owner: store.owner.clone().unwrap_or_default(),
        title,
        joined: Some(line),
        note,
        download: false,
        left: false,
    }
}

// ---- The checks of heads whose signer is not verified yet (kept across locks). ----

/// The lists are read again this long after a head of a key not verified yet first came,
/// then after twice the last wait.
pub(crate) const CHECK_FIRST: Duration = Duration::from_secs(30);
/// The longest wait between two reads for one head, and the quiet time of one head: for
/// this long it shows "Checking who shares this vault…" and no error.
pub(crate) const CHECK_QUIET: Duration = Duration::from_secs(600);
/// The most heads that the checks keep (the oldest go first).
const MAX_CHECKS: usize = 64;

/// One head of a shared store whose signer this device has not verified yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeadCheck {
    pub(crate) team: String,
    /// The head hash (`RelaySync::unlisted_head`).
    pub(crate) head: String,
    /// When this device first met the head: the quiet time runs from it, once.
    pub(crate) since: Instant,
    /// When the lists were read for it last.
    pub(crate) read_at: Instant,
    /// The wait before the next read.
    pub(crate) wait: Duration,
}

/// The checks of the heads, which a lock does not reset.
#[derive(Debug, Default)]
pub(crate) struct HeadChecks {
    pub(crate) list: Vec<HeadCheck>,
}

impl HeadChecks {
    /// A sync of `team` met `head`, whose signer is not verified yet, at `now`. Returns
    /// whether the lists are due to be read again: at once for a new head, then after 30
    /// s, and after twice the last wait up to 10 minutes. A new head of the store starts
    /// its own quiet time; the same head keeps its first one.
    pub(crate) fn due(&mut self, team: &str, head: &str, now: Instant) -> bool {
        if let Some(check) = self
            .list
            .iter_mut()
            .find(|check| check.team == team && check.head == head)
        {
            if now.saturating_duration_since(check.read_at) < check.wait {
                return false;
            }
            check.read_at = now;
            check.wait = (check.wait * 2).min(CHECK_QUIET);
            return true;
        }
        self.list.retain(|check| check.team != team);
        if self.list.len() >= MAX_CHECKS {
            self.list.remove(0);
        }
        self.list.push(HeadCheck {
            team: team.to_owned(),
            head: head.to_owned(),
            since: now,
            read_at: now,
            wait: CHECK_FIRST,
        });
        true
    }

    /// Whether `team` is checking `head` within its quiet time at `now`.
    pub(crate) fn quiet(&self, team: &str, head: &str, now: Instant) -> bool {
        self.list.iter().any(|check| {
            check.team == team
                && check.head == head
                && now.saturating_duration_since(check.since) < CHECK_QUIET
        })
    }

    /// The stores within the quiet time of their head at `now`.
    pub(crate) fn quiet_teams(&self, now: Instant) -> Vec<String> {
        self.list
            .iter()
            .filter(|check| now.saturating_duration_since(check.since) < CHECK_QUIET)
            .map(|check| check.team.clone())
            .collect()
    }

    /// A head of `team` passed: its check goes.
    pub(crate) fn passed(&mut self, team: &str) {
        self.list.retain(|check| check.team != team);
    }
}

// ---- The vault build: the worker and the owner checks. ----

type Slot<T> = Arc<Mutex<Option<T>>>;

fn take<T>(slot: &Slot<T>) -> std::sync::MutexGuard<'_, Option<T>> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The section asks Connect again this long after the last answer while Settings shows it.
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(60);
/// The answer to a share code is asked every 5 s while the code sheet is open.
pub(crate) const POLL_EVERY: Duration = Duration::from_secs(5);
/// Without Settings › Connect on the screen the lists are read again this often (and when
/// a head of a key not verified yet comes).
pub(crate) const REFRESH_HIDDEN: Duration = Duration::from_secs(30 * 60);

/// A step that waits for the proof of its owner check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Guard {
    Confirm {
        join_id: u64,
    },
    Again {
        team_id: String,
        account: String,
    },
    Accept,
    Join {
        team_id: String,
        owner: String,
    },
    End {
        team_id: String,
        account: String,
        leave: bool,
    },
}

/// What "Continue" of the picker found.
#[allow(clippy::large_enum_variant)] // One message at a time on the channel; a box buys nothing.
pub(crate) enum Started {
    /// A code was made (in the slot).
    Code,
    /// The member is pinned and pins this account: one owner check, no words.
    Again(OwnerAction),
}

/// The result of one worker step.
#[allow(clippy::large_enum_variant)] // One message at a time on the channel; a box buys nothing.
pub(crate) enum Outcome {
    Refreshed(Result<Refreshed, ConnectError>),
    /// The lists read again for a head whose signer is not verified yet.
    Checked(Result<ShareStatus, ConnectError>),
    Started(Result<Started, ConnectError>),
    Requests(Result<Vec<(ShareRequest, OwnerAction)>, ConnectError>),
    Confirmed(Result<ShareConfirmed, ConnectError>),
    Answered(Result<(String, String, String, OwnerAction), ConnectError>),
    Accepted(Result<(), ConnectError>),
    /// The owner action of a step, made on the worker from the account.
    Ask(Guard, Result<OwnerAction, ConnectError>),
    Joined(Result<Joined, ConnectError>),
    Ended {
        team_id: String,
        leave: bool,
        result: Result<(), ConnectError>,
    },
    Differed,
}

/// What a join (or a download of a joined store) leads to.
pub(crate) enum Joined {
    /// Download the copy, as "Use a Vault from Another Mac" › Apassy Connect does.
    Download(VaultStoreView),
    /// A vault of this computer synced the store before: it syncs again.
    Again(String),
    /// Connect does not list this device in the store yet: the person who shares it adds
    /// it (named here).
    NotListed(String),
}

/// What a refresh of the section read.
pub(crate) struct Refreshed {
    status: ShareStatus,
    /// `None` when Connect did not list the stores: the last list stays.
    stores: Option<Vec<VaultStoreView>>,
}

/// The section state.
#[derive(Default)]
pub(crate) struct ShareUi {
    task: Option<Task<Outcome>>,
    status: Option<ShareStatus>,
    stores: Vec<VaultStoreView>,
    members: Vec<GroupMember>,
    refreshed_at: Option<Instant>,
    pub(crate) sheet: Option<ShareSheet>,
    link: Slot<ShareLink>,
    answer: Slot<SharePeerJoin>,
    /// The owner action of the answer in [`Self::answer`].
    answer_action: Option<OwnerAction>,
    requests: Vec<(ShareRequest, OwnerAction)>,
    polled_at: Option<Instant>,
    pub(crate) guarded: Option<Guard>,
    error: Option<String>,
    /// Notes of what the account did by itself, or learned (a leave on another device).
    notes: Vec<String>,
    /// The share that the next "Continue" of the picker starts: (store, account, name).
    pending: Option<(String, String, String)>,
    /// The heads whose signer is not verified yet; a lock keeps them.
    pub(crate) checks: HeadChecks,
    /// A read of the lists that a head made due while a step ran.
    check_due: bool,
    /// When [`watch_heads`] looked last.
    watched_at: Option<Instant>,
    /// When the section was on the screen last.
    shown_at: Option<Instant>,
}

impl ShareUi {
    fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// Forget what the section showed (a lock, another vault session). The checks of the
    /// heads stay: their quiet time runs once for each head.
    pub(crate) fn reset(&mut self) {
        let checks = std::mem::take(&mut self.checks);
        *self = Self {
            checks,
            ..Self::default()
        };
    }

    /// Read the lists again at the next frame.
    #[cfg(test)]
    pub(crate) fn refresh_now(&mut self) {
        self.refreshed_at = None;
    }

    /// Whether a step of the section runs.
    #[cfg(test)]
    pub(crate) fn is_busy(&self) -> bool {
        self.busy()
    }

    /// Whether `team_id` is a store shared between accounts, as the last status says.
    pub(crate) fn is_shared(&self, team_id: &str) -> bool {
        self.status
            .as_ref()
            .is_some_and(|status| status.stores.iter().any(|store| store.team_id == team_id))
    }

    /// The names that the owner checks show beside what the account verified: the vault
    /// names of this computer (`local`), else of Connect, and Connect's names of people.
    fn names(&self, local: &BTreeMap<String, String>) -> ShareNames {
        ShareNames {
            vaults: local.clone(),
            stores: self
                .stores
                .iter()
                .map(|store| (store.team_id.clone(), store.name.clone()))
                .collect(),
            people: self
                .status
                .as_ref()
                .map(ShareStatus::hints)
                .unwrap_or_default(),
        }
    }
}

/// The vault stores that this computer's vaults sync, with the name of each vault.
fn local_stores(app: &DesktopApp) -> BTreeMap<String, String> {
    app.vault_list
        .registry
        .entries()
        .iter()
        .filter_map(|entry| Some((app.store_team(&entry.id)?, entry.name.clone())))
        .collect()
}

/// Run `work` with the account of the session on a worker.
fn spawn(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    work: impl FnOnce(&mut ConnectAccount) -> Outcome + Send + 'static,
) {
    let session = app.connect_session();
    let share = &mut app.ui.connect.share;
    share.error = None;
    share.task = Some(Task::spawn(Some(ctx.clone()), move || {
        let mut done = None;
        let result = session.with_account(|account| {
            done = Some(work(account));
            Ok(())
        });
        match (done, result) {
            (Some(outcome), _) => outcome,
            (None, Err(error)) => Outcome::Refreshed(Err(error)),
            (None, Ok(())) => Outcome::Refreshed(Err(ConnectError::Local)),
        }
    }));
}

/// The steps of one frame: the worker's result, the owner proof, the heads of the shared
/// stores, the poll of the answer, and the refresh.
pub(crate) fn step(app: &mut DesktopApp, ctx: &egui::Context) {
    let share = &mut app.ui.connect.share;
    if let Some(task) = &share.task {
        match task.poll() {
            TaskPoll::Waiting => {}
            TaskPoll::Lost => {
                share.task = None;
                share.error = Some(ConnectError::Local.to_string());
            }
            TaskPoll::Done(outcome) => {
                share.task = None;
                app.ui.connect.live.file_changed();
                apply(app, ctx, outcome);
            }
        }
    }
    guarded(app, ctx);
    watch_heads(app, Instant::now());
    let session_open = app.connect_session().is_open();
    let share = &app.ui.connect.share;
    if !session_open || share.busy() {
        return;
    }
    let code_open = matches!(share.sheet, Some(ShareSheet::Code { .. }));
    if code_open && share.polled_at.is_none_or(|at| at.elapsed() >= POLL_EVERY) {
        app.ui.connect.share.polled_at = Some(Instant::now());
        let link = Arc::clone(&app.ui.connect.share.link);
        let names = app.ui.connect.share.names(&local_stores(app));
        spawn(app, ctx, move |account| {
            let link = take(&link);
            match link.as_ref() {
                Some(link) => {
                    Outcome::Requests(account.share_requests(link).and_then(|requests| {
                        requests
                            .into_iter()
                            .map(|request| {
                                let action = account.share_action(link, &request, &names)?;
                                Ok((request, action))
                            })
                            .collect()
                    }))
                }
                None => Outcome::Requests(Ok(Vec::new())),
            }
        });
        return;
    }
    if share.check_due && share.sheet.is_none() {
        check(app, ctx);
        return;
    }
    let shown = share
        .shown_at
        .is_some_and(|at| at.elapsed() < Duration::from_secs(2));
    let every = if shown { REFRESH_EVERY } else { REFRESH_HIDDEN };
    let due = share.refreshed_at.is_none_or(|at| at.elapsed() >= every);
    if due && share.sheet.is_none() {
        refresh(app, ctx);
    }
}

fn refresh(app: &mut DesktopApp, ctx: &egui::Context) {
    app.ui.connect.share.refreshed_at = Some(Instant::now());
    let local: Vec<String> = local_stores(app).into_keys().collect();
    spawn(app, ctx, move |account| {
        Outcome::Refreshed(account.refresh_shares(&local).map(|status| Refreshed {
            stores: status.vault_stores.clone(),
            status,
        }))
    });
}

/// The lists read again for a head whose signer is not verified yet: the refresh of the
/// shares alone (no list of stores, no registration of devices). The signers reach the
/// sync through the account file.
fn check(app: &mut DesktopApp, ctx: &egui::Context) {
    app.ui.connect.share.check_due = false;
    let local: Vec<String> = local_stores(app).into_keys().collect();
    spawn(app, ctx, move |account| {
        Outcome::Checked(account.refresh_shares(&local))
    });
}

/// Turn off the sync of each vault of this computer that syncs `team` (a shared vault that
/// this account left): the vault stays. Returns whether one was turned off.
fn stop_syncing(app: &mut DesktopApp, team: &str) -> bool {
    let ids: Vec<String> = app
        .vault_list
        .registry
        .entries()
        .iter()
        .map(|entry| entry.id.clone())
        .filter(|id| app.store_team(id).as_deref() == Some(team))
        .collect();
    for id in &ids {
        app.sync_disable(id);
    }
    !ids.is_empty()
}

/// A new status: the vaults of the stores that this account left stop syncing here (the
/// rows of the section say so from the lists, also after a restart).
fn take_status(app: &mut DesktopApp, status: ShareStatus) {
    for left in &status.left {
        stop_syncing(app, &left.team_id);
    }
    // The devices of the other accounts, for the steps on a copy that one of them left.
    app.sync.relay.shared_devices = status
        .devices
        .iter()
        .filter_map(|(key, (account, device))| {
            Some((
                crate::sync::decode_b64u(key)?,
                (device.clone(), status.name_of(account)),
            ))
        })
        .collect();
    let share = &mut app.ui.connect.share;
    if let Some(members) = status.group.clone() {
        share.members = members;
    }
    share.status = Some(status);
    lists_read(app, Instant::now());
}

/// The lists of the other accounts were read again: each vault of a shared store whose head
/// has a signer not verified yet syncs again, and one past the quiet time of its head notes
/// the read (`RelaySync::note_device_list`), so a signer that the lists still do not hold
/// is refused from then on. (Settings › Connect notes the account's own list for the other
/// stores.)
fn lists_read(app: &mut DesktopApp, now: Instant) {
    let ids: Vec<String> = app
        .vault_list
        .registry
        .entries()
        .iter()
        .map(|entry| entry.id.clone())
        .collect();
    for id in ids {
        let Some(team) = app.store_team(&id) else {
            continue;
        };
        let checking = app
            .sync
            .statuses
            .get(&id)
            .is_some_and(super::super::sync::relay::is_unlisted_signer);
        if !checking || !app.ui.connect.share.is_shared(&team) {
            continue;
        }
        let Some(relay) = app.relay_of(&id) else {
            continue;
        };
        let quiet = relay
            .unlisted_head()
            .is_some_and(|head| app.ui.connect.share.checks.quiet(&team, &head, now));
        if !quiet {
            relay.note_device_list(now);
        }
        app.relay_sync_now(&id);
    }
}

fn ask(app: &mut DesktopApp, ctx: &egui::Context, guard: Guard, action: OwnerAction) {
    match OwnerRequest::from_share_action(action) {
        Some(request) => {
            app.ui.connect.share.guarded = Some(guard);
            app.ask_owner(request, Some(ctx));
        }
        None => app.ui.connect.share.error = Some(ConnectError::Local.to_string()),
    }
}

#[allow(clippy::too_many_lines)]
fn apply(app: &mut DesktopApp, ctx: &egui::Context, outcome: Outcome) {
    let share = &mut app.ui.connect.share;
    match outcome {
        Outcome::Refreshed(Ok(refreshed)) => {
            if let Some(stores) = refreshed.stores {
                share.stores = stores;
            }
            take_status(app, refreshed.status);
            app.relay_share_connect();
        }
        Outcome::Checked(Ok(status)) => take_status(app, status),
        Outcome::Refreshed(Err(error))
        | Outcome::Checked(Err(error))
        | Outcome::Ask(_, Err(error)) => share.error = Some(error.to_string()),
        Outcome::Started(Ok(Started::Again(action))) => {
            if let Some((team_id, account, _)) = share.pending.clone() {
                ask(app, ctx, Guard::Again { team_id, account }, action);
            }
        }
        Outcome::Started(Ok(Started::Code)) => {
            let link = take(&share.link);
            if let (Some(link), Some((_, _, name))) = (link.as_ref(), share.pending.as_ref()) {
                share.sheet = Some(ShareSheet::Code {
                    name: name.clone(),
                    code: Zeroizing::new(link.code().to_owned()),
                    expires_at: link.expires_at(),
                });
            }
            drop(link);
            share.polled_at = Some(Instant::now());
        }
        Outcome::Started(Err(error)) | Outcome::Requests(Err(error)) => {
            share.sheet = None;
            share.error = Some(error.to_string());
        }
        Outcome::Requests(Ok(requests)) => {
            if let Some((first, _)) = requests.first() {
                share.sheet = Some(ShareSheet::Confirm {
                    join_id: first.join_id,
                    name: crate::connect::share::label(&first.root_name, &first.name),
                    device: first.device_name.clone(),
                    words: first.words.clone(),
                });
            }
            share.requests = requests;
        }
        Outcome::Confirmed(result) => match result {
            Ok(_) => {
                let name = share
                    .pending
                    .take()
                    .map(|(_, _, name)| name)
                    .unwrap_or_default();
                *take(&share.link) = None;
                share.requests.clear();
                share.sheet = Some(ShareSheet::Done {
                    title: shared_with(&name),
                    line: not_joined(&name),
                });
                share.refreshed_at = None;
            }
            Err(error) => {
                share.sheet = None;
                share.error = Some(error.to_string());
            }
        },
        Outcome::Answered(Ok((name, device, words, action))) => {
            share.answer_action = Some(action);
            share.sheet = Some(ShareSheet::Match {
                name,
                device,
                words,
            });
        }
        Outcome::Answered(Err(error)) => {
            share.sheet = Some(ShareSheet::Paste {
                code: Zeroizing::new(String::new()),
            });
            share.error = Some(match error {
                ConnectError::ShareMismatch => MISMATCH.to_owned(),
                ConnectError::Forbidden => EXPIRED.to_owned(),
                other => other.to_string(),
            });
        }
        Outcome::Accepted(result) => {
            *take(&share.answer) = None;
            share.answer_action = None;
            match result {
                Ok(()) => {
                    share.sheet = Some(ShareSheet::Done {
                        title: "Accepted".to_owned(),
                        line: ACCEPTED_LEAD.to_owned(),
                    });
                    share.refreshed_at = None;
                }
                Err(error) => {
                    share.sheet = None;
                    share.error = Some(error.to_string());
                }
            }
        }
        Outcome::Ask(guard, Ok(action)) => ask(app, ctx, guard, action),
        Outcome::Joined(result) => {
            share.refreshed_at = None;
            match result {
                // The download with the passphrase of the copy, as "Use a Vault from
                // Another Mac" › Apassy Connect does it.
                Ok(Joined::Download(store)) => app.relay_connect_use(store, Some(ctx)),
                Ok(Joined::Again(team)) => {
                    let ids: Vec<String> = app
                        .vault_list
                        .registry
                        .entries()
                        .iter()
                        .map(|entry| entry.id.clone())
                        .filter(|id| app.store_team(id).as_deref() == Some(team.as_str()))
                        .collect();
                    for id in ids {
                        app.relay_sync_now(&id);
                    }
                }
                Ok(Joined::NotListed(name)) => share.error = Some(not_listed(&name)),
                Err(error) => share.error = Some(error.to_string()),
            }
        }
        Outcome::Ended {
            team_id,
            leave,
            result,
        } => {
            share.sheet = None;
            share.refreshed_at = None;
            match result {
                Ok(()) if leave => {
                    stop_syncing(app, &team_id);
                }
                Ok(()) => {}
                Err(error) => share.error = Some(error.to_string()),
            }
        }
        Outcome::Differed => {
            share.sheet = None;
            share.error = Some(DIFFERENT.to_owned());
        }
    }
}

fn guarded(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(guard) = app.ui.connect.share.guarded.clone() else {
        return;
    };
    if app.ui.connect.share.busy() {
        return;
    }
    let Some(proof) = app.owner.take_connect_proof() else {
        if app.owner.check.is_none() {
            app.ui.connect.share.guarded = None;
        }
        return;
    };
    app.ui.connect.share.guarded = None;
    let Some(epoch) = app.owner_ui.session.epoch() else {
        app.ui.connect.share.error = Some(super::LOCKED.to_owned());
        return;
    };
    run_guarded(app, ctx, guard, proof, epoch);
}

fn run_guarded(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    guard: Guard,
    proof: OwnerProof,
    epoch: [u8; 32],
) {
    let local = local_stores(app);
    let names = app.ui.connect.share.names(&local);
    let local: Vec<String> = local.into_keys().collect();
    match guard {
        Guard::Confirm { join_id } => {
            let Some(request) = app
                .ui
                .connect
                .share
                .requests
                .iter()
                .find(|(request, _)| request.join_id == join_id)
                .map(|(request, _)| request.clone())
            else {
                return;
            };
            let link = Arc::clone(&app.ui.connect.share.link);
            spawn(app, ctx, move |account| {
                let link = take(&link);
                match link.as_ref() {
                    Some(link) => Outcome::Confirmed(
                        account.confirm_share(link, &request, &names, proof, &epoch),
                    ),
                    None => Outcome::Confirmed(Err(ConnectError::JoinRefused)),
                }
            });
        }
        Guard::Again {
            team_id,
            account: peer,
        } => spawn(app, ctx, move |account| {
            Outcome::Confirmed(account.share_again(&team_id, &peer, &names, proof, &epoch))
        }),
        Guard::Accept => {
            let answer = Arc::clone(&app.ui.connect.share.answer);
            spawn(app, ctx, move |account| {
                let answer = take(&answer);
                match answer.as_ref() {
                    Some(join) => {
                        Outcome::Accepted(account.accept_share(join, &names, proof, &epoch))
                    }
                    None => Outcome::Accepted(Err(ConnectError::JoinRefused)),
                }
            });
        }
        Guard::Join { team_id, owner } => spawn(app, ctx, move |account| {
            let rejoin = local.contains(&team_id);
            Outcome::Joined(
                account
                    .join_shared_store(&team_id, &owner, &local, &names, proof, &epoch)
                    .and_then(|()| {
                        if rejoin {
                            Ok(Joined::Again(team_id.clone()))
                        } else {
                            joined_copy(account, &team_id, &owner, &names)
                        }
                    }),
            )
        }),
        Guard::End {
            team_id,
            account: peer,
            leave,
        } => spawn(app, ctx, move |account| {
            let result = if leave {
                account.leave_shared_store(&team_id, &peer, &names, proof, &epoch)
            } else {
                account.stop_sharing(&team_id, &peer, &names, proof, &epoch)
            };
            Outcome::Ended {
                team_id,
                leave,
                result,
            }
        }),
    }
}

/// The copy of the store `team_id` that this account joined from `owner`, when Connect
/// lists this device in it; else who adds it.
fn joined_copy(
    account: &mut ConnectAccount,
    team_id: &str,
    owner: &str,
    names: &ShareNames,
) -> Result<Joined, ConnectError> {
    let me = account.state().device_id.clone();
    let store = account.vault_stores()?.into_iter().find(|store| {
        store.team_id == team_id && store.devices.iter().any(|device| device.device_id == me)
    });
    Ok(match store {
        Some(store) => Joined::Download(store),
        None => {
            let (name, _) = account.person_of(owner);
            Joined::NotListed(crate::connect::share::label(&name, &names.hint(owner)))
        }
    })
}

/// "Share with…" of `team_id` for `account` (`name` as the sheet shows it): one owner check
/// for a member who is pinned and pins this account, else a share code.
fn start_share_with(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    team_id: String,
    account: String,
    name: String,
) {
    let names = app.ui.connect.share.names(&local_stores(app));
    app.ui.connect.share.pending = Some((team_id.clone(), account.clone(), name));
    let link = Arc::clone(&app.ui.connect.share.link);
    spawn(app, ctx, move |connect| {
        // A pinned member whose list pins this account: no words. Else a code (also
        // again, for a member who did not finish the words).
        match connect.needs_share_code(&account) {
            Ok(false) => Outcome::Started(
                connect
                    .share_again_action(&team_id, &account, &names)
                    .map(Started::Again),
            ),
            Ok(true) | Err(ConnectError::NotVerified) => {
                Outcome::Started(connect.start_share(&account, &team_id).map(|made| {
                    *take(&link) = Some(made);
                    Started::Code
                }))
            }
            Err(error) => Outcome::Started(Err(error)),
        }
    });
}

/// A press in the section.
pub(crate) fn act(app: &mut DesktopApp, ctx: &egui::Context, action: ShareAction) {
    let share = &mut app.ui.connect.share;
    share.error = None;
    match action {
        ShareAction::ShareWith { team_id, vault } => {
            let me = app.ui.connect.share_account_id().unwrap_or_default();
            let status = app.ui.connect.share.status.clone().unwrap_or_default();
            let members = app
                .ui
                .connect
                .share
                .members
                .iter()
                .filter(|member| member.account_id != me && member.state == "active")
                .map(|member| {
                    let name = if status.people.contains_key(&member.account_id) {
                        status.name_of(&member.account_id)
                    } else {
                        member.name.clone()
                    };
                    (member.account_id.clone(), name)
                })
                .collect();
            app.ui.connect.share.sheet = Some(ShareSheet::Pick {
                team_id,
                vault,
                members,
                chosen: None,
            });
        }
        ShareAction::Accept => {
            share.sheet = Some(ShareSheet::Paste {
                code: Zeroizing::new(String::new()),
            });
        }
        ShareAction::Join { team_id, owner } => {
            let names = app.ui.connect.share.names(&local_stores(app));
            spawn(app, ctx, move |account| {
                let action = account.join_action(&team_id, &owner, &names);
                Outcome::Ask(Guard::Join { team_id, owner }, Ok(action))
            });
        }
        ShareAction::Download { team_id, owner } => {
            let names = app.ui.connect.share.names(&local_stores(app));
            spawn(app, ctx, move |account| {
                Outcome::Joined(joined_copy(account, &team_id, &owner, &names))
            });
        }
        ShareAction::ShareAgain {
            team_id,
            account,
            name,
        } => start_share_with(app, ctx, team_id, account, name),
        ShareAction::Stop {
            team_id,
            account,
            name,
        } => {
            share.sheet = Some(ShareSheet::End {
                team_id,
                account,
                name,
                leave: false,
            });
        }
        ShareAction::Leave {
            team_id,
            owner,
            name,
        } => {
            share.sheet = Some(ShareSheet::End {
                team_id,
                account: owner,
                name,
                leave: true,
            });
        }
    }
}

/// A choice in a sheet of the section.
#[allow(clippy::too_many_lines)]
pub(crate) fn choose(app: &mut DesktopApp, ctx: &egui::Context, choice: ShareChoice) {
    if let ShareChoice::Copy(text) = &choice {
        ctx.copy_text(text.clone());
        return;
    }
    let Some(sheet) = app.ui.connect.share.sheet.take() else {
        return;
    };
    let names = app.ui.connect.share.names(&local_stores(app));
    match (sheet, choice) {
        (
            ShareSheet::Pick {
                team_id,
                members,
                chosen: Some(index),
                ..
            },
            ShareChoice::Go,
        ) => {
            let Some((account, name)) = members.get(index).cloned() else {
                return;
            };
            start_share_with(app, ctx, team_id, account, name);
        }
        (
            ShareSheet::Confirm {
                join_id,
                name,
                words,
                device,
            },
            ShareChoice::Go,
        ) => {
            let action = app
                .ui
                .connect
                .share
                .requests
                .iter()
                .find(|(request, _)| request.join_id == join_id)
                .map(|(_, action)| action.clone());
            app.ui.connect.share.sheet = Some(ShareSheet::Confirm {
                join_id,
                name,
                words,
                device,
            });
            if let Some(action) = action {
                ask(app, ctx, Guard::Confirm { join_id }, action);
            }
        }
        (ShareSheet::Confirm { join_id, .. }, ShareChoice::Differ) => {
            let requests: Vec<ShareRequest> = app
                .ui
                .connect
                .share
                .requests
                .iter()
                .map(|(request, _)| request.clone())
                .collect();
            *take(&app.ui.connect.share.link) = None;
            spawn(app, ctx, move |account| {
                if let Some(request) = requests.iter().find(|request| request.join_id == join_id) {
                    let _ = account.refuse_share_request(request);
                }
                Outcome::Differed
            });
        }
        (ShareSheet::Paste { code }, ShareChoice::Go) => {
            let answer = Arc::clone(&app.ui.connect.share.answer);
            app.ui.connect.share.sheet = Some(ShareSheet::Paste { code: code.clone() });
            spawn(app, ctx, move |account| {
                Outcome::Answered(account.accept_code(code.as_str()).and_then(|join| {
                    let action = account.accept_action(&join, &names)?;
                    let shown = (
                        crate::connect::share::label(&join.root_name, &join.name),
                        join.device_name.clone(),
                        join.words.clone(),
                        action,
                    );
                    *take(&answer) = Some(join);
                    Ok(shown)
                }))
            });
        }
        (
            ShareSheet::Match {
                name,
                device,
                words,
            },
            ShareChoice::Go,
        ) => {
            let action = app.ui.connect.share.answer_action.clone();
            app.ui.connect.share.sheet = Some(ShareSheet::Match {
                name,
                device,
                words,
            });
            if let Some(action) = action {
                ask(app, ctx, Guard::Accept, action);
            }
        }
        (ShareSheet::Match { .. }, ShareChoice::Differ | ShareChoice::Cancel) => {
            let answer = Arc::clone(&app.ui.connect.share.answer);
            app.ui.connect.share.answer_action = None;
            spawn(app, ctx, move |account| {
                if let Some(join) = take(&answer).take() {
                    let _ = account.cancel_share_answer(join);
                }
                Outcome::Differed
            });
        }
        (
            ShareSheet::End {
                team_id,
                account,
                name,
                leave,
            },
            ShareChoice::Go,
        ) => {
            // Always with the owner check; the ends without one are the account's own
            // (a member who left, a member outside the group).
            app.ui.connect.share.sheet = Some(ShareSheet::End {
                team_id: team_id.clone(),
                account: account.clone(),
                name,
                leave,
            });
            spawn(app, ctx, move |connect| {
                let action = connect.end_share_action(&team_id, &account, &names, leave);
                Outcome::Ask(
                    Guard::End {
                        team_id,
                        account,
                        leave,
                    },
                    Ok(action),
                )
            });
        }
        (ShareSheet::Code { .. }, _) => {
            *take(&app.ui.connect.share.link) = None;
            app.ui.connect.share.pending = None;
        }
        _ => {}
    }
}

/// The section in Settings › Connect, under the account.
pub(crate) fn section(app: &mut DesktopApp, ui: &mut Ui) {
    let ctx = ui.ctx().clone();
    app.ui.connect.share.shown_at = Some(Instant::now());
    step(app, &ctx);
    let local = local_stores(app);
    let share = &app.ui.connect.share;
    let Some(status) = share.status.as_ref() else {
        return;
    };
    let checking = share.checks.quiet_teams(Instant::now());
    let me = app.ui.connect.share_account_id().unwrap_or_default();
    let in_group = share
        .members
        .iter()
        .any(|member| member.account_id == me && member.state == "active");
    let mut view = view_of(status, &share.stores, &local, in_group, &checking);
    view.busy = share.busy();
    view.error = share.error.clone();
    view.notes.extend(share.notes.iter().cloned());
    if let Some(action) = draw(ui, &view) {
        act(app, &ctx, action);
    }
    let busy = app.ui.connect.share.busy();
    let error = app.ui.connect.share.error.clone();
    let now = crate::desktop::companion::now();
    let choice = app.ui.connect.share.sheet.as_mut().and_then(|sheet| {
        self::sheet(&ctx, sheet, busy, error.as_deref(), now, &|ui, text| {
            if let Some(modules) = crate::desktop::companion::QrModules::new(text) {
                super::super::companion::draw_qr(ui, &modules, 150.0, "QR code of the share code");
            }
        })
    });
    if let Some(choice) = choice {
        choose(app, &ctx, choice);
    }
    if app.ui.connect.share.busy()
        || matches!(app.ui.connect.share.sheet, Some(ShareSheet::Code { .. }))
    {
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

/// The heads of the shared stores in the sync statuses, at most once a second: a store
/// whose newest copy has a signer not verified yet reads the lists again when its check is
/// due ([`HeadChecks::due`]), and one in sync clears its check.
fn watch_heads(app: &mut DesktopApp, now: Instant) {
    let share = &mut app.ui.connect.share;
    if share
        .status
        .as_ref()
        .is_none_or(|status| status.stores.is_empty())
        || share
            .watched_at
            .is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(1))
    {
        return;
    }
    share.watched_at = Some(now);
    let seen: Vec<(String, bool)> = app
        .sync
        .statuses
        .iter()
        .filter_map(|(id, status)| {
            if super::super::sync::relay::is_unlisted_signer(status) {
                Some((id.clone(), true))
            } else if matches!(status, crate::desktop::sync_worker::UiStatus::UpToDate(_)) {
                Some((id.clone(), false))
            } else {
                None
            }
        })
        .collect();
    for (id, unverified) in seen {
        let Some(team) = app.store_team(&id) else {
            continue;
        };
        let head = app.relay_of(&id).and_then(|relay| relay.unlisted_head());
        let share = &mut app.ui.connect.share;
        if !share.is_shared(&team) {
            continue;
        }
        match (unverified, head) {
            (true, Some(head)) => {
                if share.checks.due(&team, &head, now) {
                    share.check_due = true;
                }
            }
            (false, _) => share.checks.passed(&team),
            (true, None) => {}
        }
    }
}

impl DesktopApp {
    /// The vault store of the vault `id`, when it syncs through Apassy Connect.
    fn store_team(&self, id: &str) -> Option<String> {
        self.relay_of(id)?.state().ok()??.team_id
    }

    /// Whether the vault `id` syncs a store shared between accounts: Shared Vaults reads the
    /// lists of the other accounts for it and notes them itself ([`lists_read`]).
    pub(crate) fn share_reads_lists(&self, id: &str) -> bool {
        // Before Shared Vaults has a status (after an unlock), the account file says it:
        // the signers that the relay sync holds give the store signers of its own.
        self.store_team(id).is_some_and(|team| {
            self.ui.connect.share.is_shared(&team)
                || self
                    .relay_of(id)
                    .is_some_and(|relay| relay.shares_between_accounts(&team))
        })
    }

    /// The sync line of a vault whose store is shared between accounts: "Checking who
    /// shares this vault…" while a head whose signer is not verified yet waits for the
    /// lists (10 minutes once for that head; then the error shows), and "Waiting for a
    /// device that shares this vault" for a head of a device that left, after the anchor.
    /// `None` for every other vault and state.
    pub(crate) fn share_sync_line(
        &self,
        id: &str,
        status: &crate::desktop::sync_worker::UiStatus,
    ) -> Option<String> {
        let team = self.store_team(id)?;
        let share = &self.ui.connect.share;
        if !share.is_shared(&team) {
            return None;
        }
        match status {
            status if super::super::sync::relay::is_unlisted_signer(status) => {
                let head = self.relay_of(id)?.unlisted_head()?;
                share
                    .checks
                    .quiet(&team, &head, Instant::now())
                    .then(|| CHECKING.to_owned())
            }
            crate::desktop::sync_worker::UiStatus::Problem(text)
                if *text == crate::sync::SyncError::WaitsForAccountDevice.to_string() =>
            {
                Some(WAITING_SHARED.to_owned())
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "share_tests.rs"]
mod tests;
