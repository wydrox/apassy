//! Timelines: the change history of a credential, and the agent requests of a
//! credential or of an agent. Each shows the newest entries and folds the rest.

use eframe::egui::{self, Label};

use super::kit::{self, Font, Tone};
use crate::desktop::DesktopApp;
use crate::desktop::owner_store::{AgentActivityRow, field_label, format_utc};
use crate::vault::{ActivityDecision, EditChange, ItemEvent, ItemEventKind};

/// Rows before "Show all".
const FOLDED_ROWS: usize = 5;

pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// "just now", "5 min ago", "3 h ago", "yesterday", "4 days ago", or the date.
pub(super) fn relative_time(at: u64, now: u64) -> String {
    let age = now.saturating_sub(at);
    match age {
        0..60 => "just now".to_owned(),
        60..3_600 => format!("{} min ago", age / 60),
        3_600..86_400 => format!("{} h ago", age / 3_600),
        86_400..172_800 => "yesterday".to_owned(),
        172_800..604_800 => format!("{} days ago", age / 86_400),
        _ => format_utc(at)
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}

/// The owner-facing text of an edit: "name, Username, Token (secret)". The history
/// holds names only. A service or project change also changes the tags, so the tags
/// show only on their own.
fn edit_text(detail: &str) -> String {
    let changes = EditChange::parse_detail(detail);
    let labels_changed = changes.iter().any(|change| {
        matches!(change, EditChange::Field(name) if name == "service" || name == "project")
    });
    let parts: Vec<String> = changes
        .iter()
        .filter_map(|change| match change {
            EditChange::Title => Some("name".to_owned()),
            EditChange::Notes => Some("notes".to_owned()),
            EditChange::Tags if labels_changed => None,
            EditChange::Tags => Some("tags".to_owned()),
            EditChange::Field(name) => Some(field_label(name)),
            EditChange::Secret(name) => Some(format!("{} (secret)", field_label(name))),
        })
        .collect();
    if parts.is_empty() {
        "Edited".to_owned()
    } else {
        format!("Edited {}", parts.join(", "))
    }
}

/// The text, the detail line, and the tone of one history event.
fn event_text(event: &ItemEvent) -> (String, Option<String>, Tone) {
    let detail = || Some(event.detail.clone()).filter(|detail| !detail.is_empty());
    match event.kind {
        ItemEventKind::Created => ("Added".to_owned(), None, Tone::Accent),
        ItemEventKind::Tracked => (
            "History starts".to_owned(),
            Some("The credential was in the vault before Apassy kept a history.".to_owned()),
            Tone::Neutral,
        ),
        ItemEventKind::Edited => (edit_text(&event.detail), None, Tone::Neutral),
        ItemEventKind::Revealed => ("You showed the secret".to_owned(), None, Tone::Warning),
        ItemEventKind::Archived => (
            "Archived".to_owned(),
            Some("Agents cannot use it.".to_owned()),
            Tone::Neutral,
        ),
        ItemEventKind::Unarchived => ("Back from the archive".to_owned(), None, Tone::Accent),
        ItemEventKind::Declaration => ("Declaration saved".to_owned(), detail(), Tone::Accent),
        ItemEventKind::Variable => (
            "Environment variable set".to_owned(),
            detail(),
            Tone::Accent,
        ),
        ItemEventKind::VariableRemoved => (
            "Environment variable removed".to_owned(),
            None,
            Tone::Neutral,
        ),
        ItemEventKind::Connector => ("Connector set".to_owned(), detail(), Tone::Accent),
        ItemEventKind::ConnectorRemoved => ("Connector removed".to_owned(), None, Tone::Neutral),
        ItemEventKind::AccessGiven => ("Process access given".to_owned(), detail(), Tone::Accent),
        ItemEventKind::AccessRemoved => {
            ("Process access removed".to_owned(), detail(), Tone::Neutral)
        }
        ItemEventKind::RuleChanged => ("Rule changed".to_owned(), detail(), Tone::Accent),
        ItemEventKind::OperationAllowed => {
            ("API operation allowed".to_owned(), detail(), Tone::Accent)
        }
        ItemEventKind::OperationRemoved => {
            ("API operation removed".to_owned(), detail(), Tone::Neutral)
        }
        ItemEventKind::Restored => (
            "Restored from a backup".to_owned(),
            Some("Its agent settings wait for your review.".to_owned()),
            Tone::Warning,
        ),
        ItemEventKind::ReviewConfirmed => ("Agent settings confirmed".to_owned(), None, Tone::Good),
    }
}

/// One timeline row: a dot, the text, an optional detail line, and the time.
fn row(ui: &mut egui::Ui, tone: Tone, text: &str, detail: Option<&str>, at: u64, now: u64) {
    egui::Sides::new().shrink_left().wrap().show(
        ui,
        |ui| {
            kit::dot(ui, tone);
            ui.label(kit::text(text, Font::Body).color(kit::LABEL));
        },
        |ui| {
            ui.label(kit::text(relative_time(at, now), Font::Footnote).color(kit::SECONDARY))
                .on_hover_text(format_utc(at));
        },
    );
    if let Some(detail) = detail {
        ui.horizontal(|ui| {
            ui.add_space(18.0);
            ui.add(Label::new(kit::text(detail, Font::Footnote).color(kit::SECONDARY)).wrap());
        });
    }
}

/// "Show all" or "Show fewer" under a folded list.
fn fold_toggle(app: &mut DesktopApp, s: &mut kit::Section<'_>, key: &str, total: usize) {
    if total <= FOLDED_ROWS {
        return;
    }
    let open = app.ui.is_expanded(key);
    let label = if open {
        "Show fewer".to_owned()
    } else {
        format!("Show all {total}")
    };
    let clicked = s
        .clickable_row(|ui| {
            ui.label(kit::text(label, Font::Body).color(kit::ACCENT_TEXT));
        })
        .clicked();
    if clicked {
        app.ui.set_expanded(key, !open);
    }
}

/// The change history of one credential. It names changes, never values.
pub(super) fn change_timeline(app: &mut DesktopApp, ui: &mut egui::Ui, item_id: u64) {
    let events = app
        .owner_ui
        .session
        .item_events(item_id, crate::vault::MAX_ITEM_EVENTS)
        .unwrap_or_default();
    if events.is_empty() {
        return;
    }
    let key = format!("history-{item_id}");
    let shown = if app.ui.is_expanded(&key) {
        events.len()
    } else {
        FOLDED_ROWS
    };
    let now = now();
    kit::section(
        ui,
        Some("History"),
        Some(
            "Changes to this credential, newest first. The history names what changed and never keeps a value.",
        ),
        |s| {
            for event in events.iter().take(shown) {
                let (text, detail, tone) = event_text(event);
                s.row(|ui| row(ui, tone, &text, detail.as_deref(), event.at, now));
            }
            fold_toggle(app, s, &key, events.len());
        },
    );
}

fn decision(row: &AgentActivityRow) -> (&'static str, Tone) {
    match row.decision {
        ActivityDecision::Allow => ("Allowed", Tone::Good),
        ActivityDecision::Deny => ("Denied", Tone::Critical),
        ActivityDecision::Error => ("Failed", Tone::Warning),
    }
}

/// Agent requests, newest first. `by_agent` names the credential in each row; otherwise
/// the row names the agent.
pub(super) fn access_timeline(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    rows: &[AgentActivityRow],
    key: &str,
    title: &str,
    empty: &str,
    by_agent: bool,
) {
    let now = now();
    let shown = if app.ui.is_expanded(key) {
        rows.len()
    } else {
        FOLDED_ROWS
    };
    kit::section(
        ui,
        Some(title),
        Some(
            "Requests that Apassy allowed, denied, or ended, newest first. The log keeps the last 500 requests of all agents.",
        ),
        |s| {
            if rows.is_empty() {
                s.row(|ui| kit::note(ui, empty));
                return;
            }
            for entry in rows.iter().take(shown) {
                s.row(|ui| {
                    let (label, tone) = decision(entry);
                    egui::Sides::new().shrink_left().truncate().show(
                        ui,
                        |ui| {
                            kit::dot(ui, tone);
                            let who = if by_agent { &entry.item } else { &entry.agent };
                            ui.label(kit::medium(who, Font::Body).color(kit::LABEL));
                            ui.add(
                                Label::new(
                                    kit::text(&entry.operation, Font::MonoSmall)
                                        .color(kit::SECONDARY),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&entry.operation);
                        },
                        |ui| {
                            ui.label(
                                kit::text(relative_time(entry.at, now), Font::Footnote)
                                    .color(kit::SECONDARY),
                            )
                            .on_hover_text(&entry.when);
                            kit::tag(ui, label, tone);
                        },
                    );
                    if !entry.reason.is_empty() {
                        ui.horizontal(|ui| {
                            ui.add_space(18.0);
                            ui.add(
                                Label::new(
                                    kit::text(&entry.reason, Font::Footnote).color(kit::SECONDARY),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&entry.reason);
                        });
                    }
                });
            }
            fold_toggle(app, s, key, rows.len());
        },
    );
}
