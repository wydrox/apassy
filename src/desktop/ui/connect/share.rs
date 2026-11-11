//! Settings › Connect › Shared Vaults: a vault shared between the accounts of one family
//! or team (contract connect-account-v1 section 16, `crate::connect::share`).
//!
//! - **Share with…** on a store of this account: pick a member (the group view of Connect
//!   is only a list to pick from). For a member whose root this account pinned already
//!   the share needs one owner check and no words; else this Mac makes a share code, keeps
//!   it in memory, and shows it with a QR code: "Send this to <name>." When the member
//!   answers, both Macs show six words; Confirm runs the owner check, and this Mac signs
//!   the `peer` and the `share` and adds the member's verified devices to the store.
//! - **Accept a Shared Vault…**: paste the code. The Mac checks the account and the device
//!   that Connect names against the code ("The code does not match the account that
//!   answered." otherwise), shows the six words, and "The Words Match" runs the owner check
//!   and signs the `peer`. The stores that the other account shares with this one then
//!   show here: "<vault>, shared by <name>: Join". Join signs the `join` and opens the
//!   download of "Use a Vault from Another Mac" with the passphrase of the copy.
//! - **Stop Sharing with <name>…** and **Leave This Shared Vault…** sign `unshare` and
//!   `leave` after an owner check; while Connect shows the member outside the group, Stop
//!   Sharing needs none (ending a share gives no one access).
//! - The states: "<name>: has not joined yet", "<name> reset the account. Share again.",
//!   "<name> must verify this account again.", and the sync lines "Checking who shares
//!   this vault…" and "Waiting for a device that shares this vault".
//!
//! One step at a time runs on a worker with the account of the one session of the app
//! (`super::live`); the UI thread never waits on Connect.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Ui};
use zeroize::Zeroizing;

use super::super::devices::rows;
use super::super::kit::{self, Font, Style, Tone};
use crate::broker::approvals::OwnerProof;
use crate::connect::share::{ShareConfirmed, StoreStatus};
use crate::connect::{
    ConnectAccount, ConnectError, GroupMember, ShareLink, SharePeerJoin, ShareRequest, ShareStatus,
    VaultStoreView,
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
];

/// "Send this to <name>."
pub(crate) fn send_to(name: &str) -> String {
    format!("Send this to {name}.")
}

/// The words line on the device that made the code.
pub(crate) fn asks(name: &str, device: &str) -> String {
    format!("\"{name}\" ({device}) asks to share vaults with you.")
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

// ---- The model of the section. ----

/// A store of this account and its members, as the section shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnStore {
    pub(crate) team_id: String,
    pub(crate) vault: String,
    /// The members: name, account, the line under it.
    pub(crate) members: Vec<(String, String, String)>,
}

/// A store of another account: joined (with its state) or offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtherStore {
    pub(crate) team_id: String,
    pub(crate) owner: String,
    pub(crate) title: String,
    /// `None`: offered, not joined; else the line of the joined store.
    pub(crate) joined: Option<String>,
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
                });
            }
            for store in &view.others {
                g.row(|ui| {
                    rows::one_line(ui, rows::label_text(&store.title).into(), None, |ui| {
                        match &store.joined {
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
                            }
                        }
                    });
                    if let Some(line) = store.joined.as_deref().filter(|line| !line.is_empty()) {
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
            let ready = chosen.is_some();
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
            let ready = !code.trim().is_empty();
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
        ShareSheet::Match {
            name,
            device,
            words,
        } => {
            kit::sheet_title(
                ui,
                CONFIRM_TITLE,
                Some(&format!(
                    "\"{name}\" ({device}) shares vaults with you. Both devices show these words. {}",
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
                ("Leave This Shared Vault?".to_owned(), LEAVE_LEAD, "Leave")
            } else {
                (
                    format!("Stop Sharing with {name}?"),
                    STOP_LEAD,
                    "Stop Sharing",
                )
            };
            let mut choice = None;
            kit::sheet_title(ui, &title, Some(lead));
            kit::sheet_buttons(
                ui,
                |_| {},
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

/// The view of the section from the last status, the stores, and the group members.
pub(crate) fn view_of(
    status: &ShareStatus,
    stores: &[VaultStoreView],
    in_group: bool,
    checking: &[String],
) -> ShareView {
    let name_of = |team: &str| {
        stores
            .iter()
            .find(|store| store.team_id == team)
            .map_or_else(|| team.to_owned(), |store| store.name.clone())
    };
    let theirs = |team: &str| {
        status.offers.iter().any(|offer| offer.team_id == team)
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
            vault: store.name.clone(),
            members: Vec::new(),
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
            } else {
                not_joined(&member.name)
            };
            store
                .members
                .push((member.name.clone(), member.account_id.clone(), line));
        }
    }
    let mut others: Vec<OtherStore> = status
        .offers
        .iter()
        .map(|offer| OtherStore {
            team_id: offer.team_id.clone(),
            owner: offer.owner.clone(),
            title: shared_by(
                offer.vault_name.as_deref().unwrap_or(&offer.team_id),
                &offer.owner_name,
            ),
            joined: None,
        })
        .collect();
    for store in status.stores.iter().filter(|store| store.owner.is_some()) {
        others.push(joined_store(store, &name_of(&store.team_id), checking));
    }
    ShareView {
        own,
        others,
        in_group,
        busy: false,
        error: None,
    }
}

fn joined_store(store: &StoreStatus, vault: &str, checking: &[String]) -> OtherStore {
    let owner_name = store.owner_name.clone().unwrap_or_default();
    let line = if store.owner_suspended {
        reset_member(&owner_name)
    } else if store.ended {
        ENDED.to_owned()
    } else if checking.contains(&store.team_id) {
        CHECKING.to_owned()
    } else {
        String::new()
    };
    OtherStore {
        team_id: store.team_id.clone(),
        owner: store.owner.clone().unwrap_or_default(),
        title: shared_by(vault, &owner_name),
        joined: Some(line),
    }
}

// ---- The vault build: the worker and the owner checks. ----

type Slot<T> = Arc<Mutex<Option<T>>>;

/// The section asks Connect again this long after the last answer while Settings shows it.
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(60);
/// The answer to a share code is asked every 5 s while the code sheet is open.
pub(crate) const POLL_EVERY: Duration = Duration::from_secs(5);
/// A head of a key that this device has not verified yet: the lists are read again at
/// most this often for one store.
pub(crate) const CHECK_EVERY: Duration = Duration::from_secs(30);
/// For this long such a head shows "Checking who shares this vault…" and no error.
pub(crate) const CHECK_QUIET: Duration = Duration::from_secs(600);

/// A step that waits for the proof of its owner check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Guard {
    Confirm {
        join_id: u64,
    },
    Again {
        team_id: String,
        account: String,
        name: String,
    },
    Accept,
    End {
        team_id: String,
        account: String,
        name: String,
        leave: bool,
    },
}

/// The result of one worker step.
pub(crate) enum Outcome {
    Refreshed(Result<(ShareStatus, Vec<VaultStoreView>, Vec<GroupMember>), ConnectError>),
    /// A code was made (in the slot: `None`), or the member is pinned already (the short
    /// fingerprint of its pinned root, for the owner check of a share without words).
    Started(Result<Option<String>, ConnectError>),
    Requests(Result<Vec<ShareRequest>, ConnectError>),
    Confirmed(Result<ShareConfirmed, ConnectError>),
    Answered(Result<(String, String, String), ConnectError>),
    Accepted(Result<(), ConnectError>),
    Joined(Result<Option<VaultStoreView>, ConnectError>),
    Ended(Result<(), ConnectError>),
    Differed,
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
    requests: Vec<ShareRequest>,
    polled_at: Option<Instant>,
    pub(crate) guarded: Option<Guard>,
    error: Option<String>,
    /// The share that the next "Continue" of the picker starts: (store, account, name).
    pending: Option<(String, String, String)>,
    /// Stores whose newest head a key not verified yet signed: when this device first saw
    /// it, and when it read the lists last.
    checking: Vec<(String, Instant, Instant)>,
    /// When [`watch_heads`] looked last.
    watched_at: Option<Instant>,
}

impl ShareUi {
    fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// Forget what the section showed (a lock, another vault session).
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// Whether `team_id` is a store shared between accounts, as the last status says.
    pub(crate) fn is_shared(&self, team_id: &str) -> bool {
        self.status
            .as_ref()
            .is_some_and(|status| status.stores.iter().any(|store| store.team_id == team_id))
    }

    /// The sync line of a shared store whose newest head a key not verified yet signed:
    /// "Checking who shares this vault…" for [`CHECK_QUIET`], then `None` (the error of
    /// the sync shows).
    pub(crate) fn checking_line(&self, team_id: &str) -> Option<&'static str> {
        self.checking
            .iter()
            .find(|(team, since, _)| team == team_id && since.elapsed() < CHECK_QUIET)
            .map(|_| CHECKING)
    }

    /// A sync of the shared store `team_id` met a head of a key that this device has not
    /// verified: the lists are read again (at most every [`CHECK_EVERY`] for the store).
    pub(crate) fn note_unverified_head(&mut self, team_id: &str) {
        match self
            .checking
            .iter_mut()
            .find(|(team, _, _)| team == team_id)
        {
            Some((_, _, read)) if read.elapsed() >= CHECK_EVERY => {
                *read = Instant::now();
                self.refreshed_at = None;
            }
            Some(_) => {}
            None => {
                self.checking
                    .push((team_id.to_owned(), Instant::now(), Instant::now()));
                self.refreshed_at = None;
            }
        }
    }

    /// The head of `team_id` verified again: the line goes.
    pub(crate) fn head_verified(&mut self, team_id: &str) {
        self.checking.retain(|(team, _, _)| team != team_id);
    }
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

/// The steps of one frame: the worker's result, the owner proof, the poll of the answer,
/// and the refresh.
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
                apply(app, ctx, outcome);
            }
        }
    }
    guarded(app, ctx);
    watch_heads(app);
    let session_open = app.connect_session().is_open();
    let share = &app.ui.connect.share;
    if !session_open || share.busy() {
        return;
    }
    let code_open = matches!(share.sheet, Some(ShareSheet::Code { .. }));
    if code_open && share.polled_at.is_none_or(|at| at.elapsed() >= POLL_EVERY) {
        app.ui.connect.share.polled_at = Some(Instant::now());
        let link = Arc::clone(&app.ui.connect.share.link);
        spawn(app, ctx, move |account| {
            let link = link
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match link.as_ref() {
                Some(link) => Outcome::Requests(account.share_requests(link)),
                None => Outcome::Requests(Ok(Vec::new())),
            }
        });
        return;
    }
    let due = app
        .ui
        .connect
        .share
        .refreshed_at
        .is_none_or(|at| at.elapsed() >= REFRESH_EVERY);
    if due && app.ui.connect.share.sheet.is_none() {
        refresh(app, ctx);
    }
}

fn refresh(app: &mut DesktopApp, ctx: &egui::Context) {
    app.ui.connect.share.refreshed_at = Some(Instant::now());
    spawn(app, ctx, |account| {
        let result = account.refresh_shares().and_then(|status| {
            let stores = account.vault_stores()?;
            let members = account
                .group()?
                .map(|group| group.members)
                .unwrap_or_default();
            Ok((status, stores, members))
        });
        Outcome::Refreshed(result)
    });
}

fn apply(app: &mut DesktopApp, ctx: &egui::Context, outcome: Outcome) {
    let share = &mut app.ui.connect.share;
    match outcome {
        Outcome::Refreshed(Ok((status, stores, members))) => {
            share.status = Some(status);
            share.stores = stores;
            share.members = members;
            // The sessions that run take the new signers of the shared stores.
            app.relay_share_connect();
        }
        Outcome::Refreshed(Err(error)) | Outcome::Ended(Err(error)) => {
            share.error = Some(error.to_string())
        }
        Outcome::Started(Ok(Some(fingerprint))) => {
            // A pinned member: one owner check, no words.
            if let Some((team_id, account, name)) = share.pending.clone() {
                ask_again(app, ctx, (team_id, account, name), fingerprint);
            }
        }
        Outcome::Started(Ok(None)) => {
            let link = share
                .link
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            if let Some(first) = requests.first() {
                share.sheet = Some(ShareSheet::Confirm {
                    join_id: first.join_id,
                    name: first.name.clone(),
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
                *share
                    .link
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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
        Outcome::Answered(Ok((name, device, words))) => {
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
            *share
                .answer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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
        Outcome::Joined(result) => match result {
            Ok(store) => {
                share.refreshed_at = None;
                if let Some(store) = store {
                    // The download with the passphrase of the copy, as "Use a Vault from
                    // Another Mac" › Apassy Connect does it.
                    app.relay_connect_use(store, Some(ctx));
                }
            }
            Err(error) => share.error = Some(error.to_string()),
        },
        Outcome::Ended(Ok(())) => {
            share.sheet = None;
            share.refreshed_at = None;
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
    match guard {
        Guard::Confirm { join_id } => {
            let Some(request) = app
                .ui
                .connect
                .share
                .requests
                .iter()
                .find(|request| request.join_id == join_id)
                .cloned()
            else {
                return;
            };
            let link = Arc::clone(&app.ui.connect.share.link);
            spawn(app, ctx, move |account| {
                let link = link
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match link.as_ref() {
                    Some(link) => {
                        Outcome::Confirmed(account.confirm_share(link, &request, proof, &epoch))
                    }
                    None => Outcome::Confirmed(Err(ConnectError::JoinRefused)),
                }
            });
        }
        Guard::Again {
            team_id,
            account: peer,
            name,
        } => spawn(app, ctx, move |account| {
            Outcome::Confirmed(account.share_again(&team_id, &peer, &name, proof, &epoch))
        }),
        Guard::Accept => {
            let answer = Arc::clone(&app.ui.connect.share.answer);
            spawn(app, ctx, move |account| {
                let answer = answer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match answer.as_ref() {
                    Some(join) => Outcome::Accepted(account.accept_share(join, proof, &epoch)),
                    None => Outcome::Accepted(Err(ConnectError::JoinRefused)),
                }
            });
        }
        Guard::End {
            team_id,
            account: peer,
            name,
            leave,
        } => spawn(app, ctx, move |account| {
            Outcome::Ended(if leave {
                account.leave_shared_store(&team_id, &peer, &name, proof, &epoch)
            } else {
                account.stop_sharing(&team_id, &peer, &name, Some(proof), &epoch)
            })
        }),
    }
}

fn ask_again(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    (team_id, account, name): (String, String, String),
    fingerprint: String,
) {
    let Some(me) = app.ui.connect.share_account_id() else {
        return;
    };
    let request = OwnerRequest::ShareConnectVault {
        account_id: me,
        peer_account: account.clone(),
        peer_name: name.clone(),
        team_id: team_id.clone(),
        words: String::new(),
        fingerprint,
    };
    app.ui.connect.share.guarded = Some(Guard::Again {
        team_id,
        account,
        name,
    });
    app.ask_owner(request, Some(ctx));
}

/// A press in the section.
pub(crate) fn act(app: &mut DesktopApp, ctx: &egui::Context, action: ShareAction) {
    let share = &mut app.ui.connect.share;
    share.error = None;
    match action {
        ShareAction::ShareWith { team_id, vault } => {
            let me = app.ui.connect.share_account_id().unwrap_or_default();
            let members = app
                .ui
                .connect
                .share
                .members
                .iter()
                .filter(|member| member.account_id != me && member.state == "active")
                .map(|member| (member.account_id.clone(), member.name.clone()))
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
        ShareAction::Join { team_id, owner } => spawn(app, ctx, move |account| {
            Outcome::Joined(account.join_shared_store(&team_id, &owner).and_then(|()| {
                Ok(account
                    .vault_stores()?
                    .into_iter()
                    .find(|store| store.team_id == team_id))
            }))
        }),
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
pub(crate) fn choose(app: &mut DesktopApp, ctx: &egui::Context, choice: ShareChoice) {
    if let ShareChoice::Copy(text) = &choice {
        ctx.copy_text(text.clone());
        return;
    }
    let Some(sheet) = app.ui.connect.share.sheet.take() else {
        return;
    };
    let me = app.ui.connect.share_account_id().unwrap_or_default();
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
            app.ui.connect.share.pending = Some((team_id.clone(), account.clone(), name));
            let link = Arc::clone(&app.ui.connect.share.link);
            spawn(app, ctx, move |connect| {
                if connect.is_pinned_peer(&account) {
                    let fingerprint = match connect.share_again_action(&team_id, &account, "") {
                        crate::broker::approvals::OwnerAction::ShareConnectVault {
                            fingerprint,
                            ..
                        } => fingerprint,
                        _ => String::new(),
                    };
                    return Outcome::Started(Ok(Some(fingerprint)));
                }
                Outcome::Started(connect.start_share(&account, &team_id).map(|made| {
                    *link
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(made);
                    None
                }))
            });
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
            let Some((team_id, account, _)) = app.ui.connect.share.pending.clone() else {
                return;
            };
            let fingerprint = app
                .ui
                .connect
                .share
                .requests
                .iter()
                .find(|request| request.join_id == join_id)
                .map(|request| crate::connect::key_fingerprint(&request.root))
                .unwrap_or_default();
            let request = OwnerRequest::ShareConnectVault {
                account_id: me,
                peer_account: account,
                peer_name: name.clone(),
                team_id,
                words: words.clone(),
                fingerprint,
            };
            app.ui.connect.share.guarded = Some(Guard::Confirm { join_id });
            app.ui.connect.share.sheet = Some(ShareSheet::Confirm {
                join_id,
                name,
                words,
                device,
            });
            app.ask_owner(request, Some(ctx));
        }
        (ShareSheet::Confirm { join_id, .. }, ShareChoice::Differ) => {
            let requests = app.ui.connect.share.requests.clone();
            *app.ui
                .connect
                .share
                .link
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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
                Outcome::Answered(account.accept_code(code.as_str()).map(|join| {
                    let shown = (
                        join.name.clone(),
                        join.device_name.clone(),
                        join.words.clone(),
                    );
                    *answer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(join);
                    shown
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
            let (peer, fingerprint) = {
                let answer = app
                    .ui
                    .connect
                    .share
                    .answer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match answer.as_ref() {
                    Some(join) => (
                        join.account_id.clone(),
                        crate::connect::key_fingerprint(&join.root),
                    ),
                    None => return,
                }
            };
            let request = OwnerRequest::AcceptConnectShare {
                account_id: me,
                peer_account: peer,
                peer_name: name.clone(),
                words: words.clone(),
                fingerprint,
            };
            app.ui.connect.share.guarded = Some(Guard::Accept);
            app.ui.connect.share.sheet = Some(ShareSheet::Match {
                name,
                device,
                words,
            });
            app.ask_owner(request, Some(ctx));
        }
        (ShareSheet::Match { .. }, ShareChoice::Differ | ShareChoice::Cancel) => {
            let answer = Arc::clone(&app.ui.connect.share.answer);
            spawn(app, ctx, move |account| {
                let taken = answer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(join) = taken {
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
            let outside = !leave
                && app
                    .ui
                    .connect
                    .share
                    .status
                    .as_ref()
                    .is_some_and(|status| status.outside_group.contains(&account));
            if outside {
                // Connect shows the member outside the group: ending the share needs no
                // owner check (it gives no one access).
                spawn(app, ctx, move |connect| {
                    Outcome::Ended(
                        connect.stop_sharing(&team_id, &account, &name, None, &[0u8; 32]),
                    )
                });
                return;
            }
            let request = OwnerRequest::EndConnectShare {
                account_id: me,
                peer_account: account.clone(),
                peer_name: name.clone(),
                team_id: team_id.clone(),
                leave,
            };
            app.ui.connect.share.guarded = Some(Guard::End {
                team_id: team_id.clone(),
                account: account.clone(),
                name: name.clone(),
                leave,
            });
            app.ui.connect.share.sheet = Some(ShareSheet::End {
                team_id,
                account,
                name,
                leave,
            });
            app.ask_owner(request, Some(ctx));
        }
        (ShareSheet::Code { .. }, _) => {
            *app.ui
                .connect
                .share
                .link
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            app.ui.connect.share.pending = None;
        }
        _ => {}
    }
}

/// The section in Settings › Connect, under the account.
pub(crate) fn section(app: &mut DesktopApp, ui: &mut Ui) {
    let ctx = ui.ctx().clone();
    step(app, &ctx);
    let share = &app.ui.connect.share;
    let Some(status) = share.status.as_ref() else {
        return;
    };
    let checking: Vec<String> = share
        .checking
        .iter()
        .filter(|(_, since, _)| since.elapsed() < CHECK_QUIET)
        .map(|(team, _, _)| team.clone())
        .collect();
    let in_group = !share.members.is_empty();
    let mut view = view_of(status, &share.stores, in_group, &checking);
    view.busy = share.busy();
    view.error = share.error.clone();
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
/// whose newest copy fails the check of its signer reads the lists again
/// ([`ShareUi::note_unverified_head`]), and one in sync clears its line.
fn watch_heads(app: &mut DesktopApp) {
    let share = &mut app.ui.connect.share;
    if share
        .status
        .as_ref()
        .is_none_or(|status| status.stores.is_empty())
        || share
            .watched_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
    {
        return;
    }
    share.watched_at = Some(Instant::now());
    let seen: Vec<(String, bool)> = app
        .sync
        .statuses
        .iter()
        .filter_map(|(id, status)| match status {
            crate::desktop::sync_worker::UiStatus::Damaged => Some((id.clone(), true)),
            crate::desktop::sync_worker::UiStatus::UpToDate(_) => Some((id.clone(), false)),
            _ => None,
        })
        .collect();
    for (id, damaged) in seen {
        let Some(team) = app.store_team(&id) else {
            continue;
        };
        let share = &mut app.ui.connect.share;
        if !share.is_shared(&team) {
            continue;
        }
        if damaged {
            share.note_unverified_head(&team);
        } else {
            share.head_verified(&team);
        }
    }
}

impl DesktopApp {
    /// The vault store of the vault `id`, when it syncs through Apassy Connect.
    fn store_team(&self, id: &str) -> Option<String> {
        self.relay_of(id)?.state().ok()??.team_id
    }

    /// The sync line of a vault whose store is shared between accounts: "Checking who
    /// shares this vault…" while a head of a key not verified yet waits for the lists, and
    /// "Waiting for a device that shares this vault" for a head of a device that left,
    /// after the anchor. `None` for every other vault and state.
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
            crate::desktop::sync_worker::UiStatus::Damaged => {
                share.checking_line(&team).map(str::to_owned)
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
