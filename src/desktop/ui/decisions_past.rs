//! The detail of a past decision of this computer (ADR 0046): one sentence under "Why",
//! what can change under "Next time", and the facts behind "Details". Vault build only:
//! the History list itself (`decisions_bouncer.rs`) is in both builds.
//!
//! A button of "Next time" does only what the owner can already do elsewhere, plus one
//! entry point: saving the project answer that the question itself offered. A button
//! that loosens opens the owner check; one that tightens acts at once. A decision that a
//! check refused, or that the owner denied, has no button that loosens. The detail is
//! read once per status change, vault session, and two seconds ([`CacheKey`]); every
//! action checks again on click.

use eframe::egui::{self, Label, Ui};

use super::kit::{self, Font, Style};
use super::settings_rows as rows;
use crate::broker::approvals::action_words;
use crate::broker::next_time::{self, Change, NotOffered};
use crate::broker::reasons;
use crate::broker::route_diagnostics::ReasonKind;
use crate::broker::shell_risk::injection_entry;
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::OwnerRequest;
use crate::vault::answers::{AnswerScope, OwnerAnswer};
use crate::vault::exceptions::ExceptionKind;
use crate::vault::usage::ItemUse;
use crate::vault::{DecidedBy, DecisionEntry, DecisionWhy, LoggedDecision, Vault};

/// The key of the detail in the cache: the event, the status (each action sets one),
/// the vault session, and the time in steps of two seconds, so a change that the broker
/// makes on its own shows soon.
pub(crate) type CacheKey = (u64, u64, Option<[u8; 32]>, u64);

/// The cache key of the detail of `event_key` now.
pub(crate) fn cache_key(app: &DesktopApp, event_key: u64, now: u64) -> CacheKey {
    (
        event_key,
        app.status_seq,
        app.owner_ui.session.epoch(),
        now / 2,
    )
}

/// What a button of "Next time" does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Act {
    /// Open the owner check for this request: "Allow…", "Remove…", "Turn Off…".
    Ask(Box<OwnerRequest>),
    /// Remove a remembered answer. Stricter: no owner check.
    RemoveAnswer {
        id: u64,
        title: String,
    },
    /// Remove the remembered patterns of the command. Stricter: no owner check.
    Forget(Vec<u64>),
    /// "Always Ask" or "Never" for the agent. Stricter: no owner check.
    Except {
        agent_id: u64,
        agent: String,
        item_id: u64,
        item: String,
        kind: ExceptionKind,
    },
    OpenCredential(u64),
    OpenSettings,
}

/// One button of a row of "Next time".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextButton {
    pub(crate) label: &'static str,
    /// The name that VoiceOver reads: it names what the button acts on.
    pub(crate) spoken: String,
    pub(crate) style: Style,
    pub(crate) act: Act,
}

/// One row of "Next time": one sentence or a label, and at most two buttons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextRow {
    pub(crate) text: String,
    /// The hover text and the accessible description.
    pub(crate) detail: Option<String>,
    pub(crate) buttons: Vec<NextButton>,
}

impl NextRow {
    fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            detail: None,
            buttons: Vec::new(),
        }
    }

    fn with(text: impl Into<String>, label: &'static str, spoken: String, act: Act) -> Self {
        Self {
            text: text.into(),
            detail: None,
            buttons: vec![NextButton {
                label,
                spoken,
                style: Style::Bordered,
                act,
            }],
        }
    }

    fn open_credential(text: impl Into<String>, item_id: u64, item: &str) -> Self {
        Self::with(
            text,
            "Open Credential",
            format!("Open {item}"),
            Act::OpenCredential(item_id),
        )
    }

    fn turn_off(item_id: u64, item: &str) -> Self {
        Self::with(
            "Always ask me",
            "Turn Off…",
            "Turn off Always ask me".to_owned(),
            Act::Ask(Box::new(OwnerRequest::AlwaysAskOff {
                item_id,
                name: item.to_owned(),
            })),
        )
    }
}

/// The detail of one past decision of this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Past {
    /// The one sentence of "Why".
    pub(crate) reason: String,
    /// The stored note: the hover text of "Why". Empty when it says the same.
    pub(crate) note: String,
    pub(crate) next: Vec<NextRow>,
    /// The rows of "Details": `(label, value)`; an empty label is the note.
    pub(crate) details: Vec<(String, String)>,
    /// The masked command summary of its use.
    pub(crate) command: String,
}

/// Read the detail of decision `decision_id` from the vault. `None` when the vault is
/// locked or the decision is gone.
pub(crate) fn read(app: &DesktopApp, decision_id: u64) -> Option<Past> {
    app.owner_ui
        .session
        .with_vault(|vault| read_in(vault, decision_id))
        .flatten()
}

fn read_in(vault: &Vault, decision_id: u64) -> Option<Past> {
    let entry = vault.decision(decision_id).ok().flatten()?.entry;
    let why = entry.why();
    let kind = reasons::kind_of(&why, entry.decided_by.as_str(), &entry.rule_flags);
    let stored = entry.note.trim().to_owned();
    let line = reasons::words(kind, &entry.rule_flags, &why.code).line;
    let reason = if kind == ReasonKind::Other && !stored.is_empty() {
        stored.clone()
    } else if line == reasons::words(ReasonKind::HookFlags, &[INJECTION.to_owned()], "").line
        && let Some(phrase) = phrase(&why.inject)
    {
        // The owner's window names the phrase that the injection flag found.
        phrase
    } else {
        line.to_owned()
    };
    let uses = vault.uses_of_decision(decision_id).unwrap_or_default();
    let command = uses
        .iter()
        .map(|used| used.command_summary.clone())
        .find(|summary| !summary.is_empty())
        .unwrap_or_default();
    Some(Past {
        next: next_rows(vault, decision_id, &entry, &why, kind, &uses),
        details: details(&entry),
        note: if stored == reason {
            String::new()
        } else {
            stored
        },
        reason,
        command,
    })
}

/// The flag whose phrase the owner's window names.
const INJECTION: &str = crate::broker::shell_risk::INJECTION_FLAG;

/// The rows of "Details": the stored note, whether it asked, the task, the raw flag
/// names, and the answers of the bouncer brain.
fn details(entry: &DecisionEntry) -> Vec<(String, String)> {
    let past = super::decisions_activity::PastWhy::of(entry);
    let mut rows = Vec::new();
    if !past.note.is_empty() {
        rows.push((String::new(), past.note.clone()));
    }
    rows.push((
        "Asked you".to_owned(),
        if past.asked { "Yes" } else { "No" }.to_owned(),
    ));
    rows.push(("Task".to_owned(), past.task.clone()));
    if !past.flags.is_empty() {
        rows.push(("Rule flags".to_owned(), past.flags.join(", ")));
    }
    let brain = past.brain_line();
    if !brain.is_empty() {
        rows.push(("Bouncer brain".to_owned(), brain));
    }
    rows
}

/// "Your prompt mentions “bouncer”." from the stored word `prompt:1000` (ADR 0046). An
/// unknown source or a number outside the lists gives none.
fn phrase(word: &str) -> Option<String> {
    let (source, index) = word.split_once(':')?;
    let place = match source {
        "prompt" => "Your prompt",
        "task" => "The agent's task text",
        "purpose" => "The agent's purpose",
        "command" => "The command",
        _ => return None,
    };
    let entry = injection_entry(index.parse().ok()?)?;
    Some(format!("{place} mentions \u{201c}{entry}\u{201d}."))
}

/// "Allow changes in apassy", the title of a remembered answer.
fn answer_title(answer: &OwnerAnswer) -> String {
    format!(
        "Allow {} in {}",
        action_words(answer.action),
        answer.project.label
    )
}

/// The row of a remembered answer that is there: its title with Remove.
fn rule_row(answer: &OwnerAnswer) -> NextRow {
    let title = answer_title(answer);
    NextRow::with(
        format!("Rule: {title}"),
        "Remove",
        format!("Remove the rule: {title}"),
        Act::RemoveAnswer {
            id: answer.id,
            title,
        },
    )
}

/// The project answer that covers the use of a decision allowed by an answer.
fn covering_answer(vault: &Vault, item_id: u64, use_row: Option<&ItemUse>) -> Option<OwnerAnswer> {
    let used = use_row.filter(|used| !used.project_key.is_empty())?;
    [AnswerScope::Project, AnswerScope::Production]
        .into_iter()
        .find_map(|scope| {
            vault
                .answer_for(item_id, &used.project_key, used.action, scope)
                .ok()
                .flatten()
        })
}

/// The active remembered patterns of the command of `entry`: the same agent, project
/// (the key of its use, as the pattern keeps it), folder in it, credentials, and command.
/// A blocked pattern stays.
fn patterns_of(vault: &Vault, entry: &DecisionEntry, use_row: Option<&ItemUse>) -> Vec<u64> {
    let Some(project_key) = use_row
        .map(|used| used.project_key.as_str())
        .filter(|key| !key.is_empty())
    else {
        return Vec::new();
    };
    if entry.pattern.is_empty() {
        return Vec::new();
    }
    let mut items = entry.items.clone();
    items.sort_unstable();
    items.dedup();
    vault
        .patterns()
        .unwrap_or_default()
        .into_iter()
        .filter(|pattern| {
            !pattern.blocked
                && pattern.key.agent_id == entry.agent_id
                && pattern.key.project_dir == project_key
                && pattern.key.cwd_rel == entry.cwd_rel
                && pattern.key.items == items
                && pattern.display == entry.pattern
        })
        .map(|pattern| pattern.id)
        .collect()
}

/// The row of a credential whose environment is not confirmed now.
fn environment_row(item_id: u64, item: &str) -> NextRow {
    NextRow::open_credential("Environment not set", item_id, item)
}

/// The row of the project answer that the question offered (ADR 0046).
fn offer_row(
    vault: &Vault,
    decision_id: u64,
    entry: &DecisionEntry,
    item_id: u64,
    item: &str,
) -> Option<NextRow> {
    let why = entry.why();
    if why.offered.is_empty() {
        return None;
    }
    const TICK: &str = "Tick \u{201c}Remember for this project\u{201d} on its next question.";
    if !why.offered.starts_with("in_project:") {
        return Some(NextRow::text(TICK));
    }
    match next_time::later_answer(vault, decision_id) {
        Ok(answer) => {
            // An "Always ask" exception of the agent asks whatever the rule says: its row
            // with Remove… is the way.
            if vault
                .agent_view(entry.agent_id)
                .is_ok_and(|view| view.always_ask.contains(&item_id))
            {
                return None;
            }
            let text = format!(
                "Allow {}{} in {} without asking",
                action_words(answer.action),
                if answer.codes.is_some() {
                    " with one-time codes"
                } else {
                    ""
                },
                answer.project.label
            );
            let detail = format!(
                "For every agent, with {}. Safety rules still ask.",
                answer.item_name
            );
            let request = OwnerRequest::RememberAnswer {
                decision_id,
                item_id: answer.item_id,
                name: answer.item_name.clone(),
                project: answer.project.label.clone(),
                project_key: answer.project.key.clone(),
                action: answer.action,
                codes: answer.codes.is_some(),
            };
            let mut row = NextRow::with(text.clone(), "Allow…", text, Act::Ask(Box::new(request)));
            row.detail = Some(detail);
            Some(row)
        }
        Err(NotOffered::Covered(id)) => vault
            .answers_for_item(item_id)
            .ok()?
            .into_iter()
            .find(|answer| answer.id == id)
            .map(|answer| rule_row(&answer)),
        Err(NotOffered::Changed(Change::Environment)) => Some(environment_row(item_id, item)),
        Err(NotOffered::Changed(Change::AlwaysAsk)) => Some(NextRow::turn_off(item_id, item)),
        Err(NotOffered::Changed(Change::Production)) => Some(NextRow::text(PRODUCTION)),
        Err(NotOffered::Changed(Change::Other)) => Some(NextRow::text(TICK)),
        Err(NotOffered::NoOffer) => None,
    }
}

/// The sentence of a production credential that asks every time.
const PRODUCTION: &str = "This production credential asks every time.";

/// The rows of "Next time" of one decision.
fn next_rows(
    vault: &Vault,
    decision_id: u64,
    entry: &DecisionEntry,
    why: &DecisionWhy,
    kind: ReasonKind,
    uses: &[ItemUse],
) -> Vec<NextRow> {
    let every = reasons::every_time(kind, &entry.rule_flags);
    let item_id = match entry.items.as_slice() {
        [] => return Vec::new(),
        [item_id] => *item_id,
        items => {
            // A flagged run asks every time, whatever the rules of its credentials say.
            return vec![NextRow::text(every.map_or_else(
                || {
                    format!(
                        "This run used {} credentials. Change their rules in each credential.",
                        items.len()
                    )
                },
                str::to_owned,
            ))];
        }
    };
    let Ok(details) = vault.details(item_id) else {
        return Vec::new();
    };
    let item = details.summary.title;
    let refused = entry.decided_by == DecidedBy::Rule;
    let denied = entry.decided_by == DecidedBy::Owner && entry.decision == LoggedDecision::Deny;
    let may_loosen = !refused && !denied;
    let unconfirmed = next_time::environment_unconfirmed(vault, item_id);
    let use_row = uses.iter().find(|used| used.item_id == item_id);
    let mut rows = Vec::new();
    match kind {
        ReasonKind::RememberedAnswer => {
            rows.extend(covering_answer(vault, item_id, use_row).map(|answer| rule_row(&answer)));
        }
        ReasonKind::RememberedPattern => {
            let ids = patterns_of(vault, entry, use_row);
            if !ids.is_empty() {
                rows.push(NextRow::with(
                    "Remembered command",
                    "Forget",
                    "Forget the remembered command".to_owned(),
                    Act::Forget(ids),
                ));
            }
        }
        ReasonKind::MissingDeclaration => rows.push(NextRow::open_credential(
            "Apassy asks until its environment is set.",
            item_id,
            &item,
        )),
        // The Why line says it; the row is the label with its button.
        ReasonKind::AlwaysAsk if vault.always_ask(item_id).unwrap_or(false) => {
            rows.push(if may_loosen {
                NextRow::turn_off(item_id, &item)
            } else {
                NextRow::open_credential("Always ask me", item_id, &item)
            });
        }
        ReasonKind::ModelUnavailable => rows.push(NextRow::with(
            "Bouncer brain",
            "Open Settings",
            "Open the bouncer settings".to_owned(),
            Act::OpenSettings,
        )),
        ReasonKind::AccessCheck
            if matches!(
                why.code.as_str(),
                "item_archived" | "review_required" | "needs_field"
            ) =>
        {
            rows.push(NextRow::open_credential(item.clone(), item_id, &item));
        }
        _ => {}
    }
    if may_loosen && let Some(row) = offer_row(vault, decision_id, entry, item_id, &item) {
        rows.push(row);
    }
    if let Some(every) = every {
        rows.push(if kind == ReasonKind::Production {
            NextRow::open_credential(every, item_id, &item)
        } else {
            NextRow::text(every)
        });
    } else if rows.is_empty() {
        rows.extend(match why.noremember.as_str() {
            "uncertain" => {
                let text = "Apassy could not tell what this command changes, so it asks each time.";
                Some(if unconfirmed {
                    NextRow::open_credential(text, item_id, &item)
                } else {
                    NextRow::text(text)
                })
            }
            "brain" => Some(NextRow::text(
                "Nothing is remembered while the bouncer brain is off.",
            )),
            "dbhost" => Some(NextRow::text(
                "A database host that the credential does not know asks every time.",
            )),
            "production" if unconfirmed => Some(environment_row(item_id, &item)),
            "production" => Some(NextRow::text(PRODUCTION)),
            _ => None,
        });
    }
    rows.extend(standing_row(vault, entry, item_id, &item, may_loosen));
    // Two causes can give the same row; it shows once.
    let mut seen = Vec::new();
    rows.retain(|row| {
        let new = !seen.contains(&row.text);
        if new {
            seen.push(row.text.clone());
        }
        new
    });
    rows
}

/// The row of the agent and the credential: its exception, or the buttons that add one.
/// Only for a connected agent.
fn standing_row(
    vault: &Vault,
    entry: &DecisionEntry,
    item_id: u64,
    item: &str,
    may_loosen: bool,
) -> Option<NextRow> {
    let agent_id = entry.agent_id;
    let agent = entry.agent_name.as_str();
    let connected = vault
        .list_agents()
        .ok()?
        .iter()
        .any(|summary| summary.id == agent_id && !summary.revoked);
    if !connected {
        return None;
    }
    let view = vault.agent_view(agent_id).ok()?;
    let exception = if view.never.contains(&item_id) {
        Some((ExceptionKind::Never, format!("Never for {agent}"), "Never"))
    } else if view.always_ask.contains(&item_id) {
        Some((
            ExceptionKind::AlwaysAsk,
            format!("Always asks for {agent}"),
            "Always ask",
        ))
    } else {
        None
    };
    if let Some((kind, text, words)) = exception {
        // Removing an exception gives authority back: never from a refused or denied
        // decision, where the credential page has it.
        return Some(if may_loosen {
            NextRow::with(
                text,
                "Remove…",
                format!("Remove {words} for {agent}"),
                Act::Ask(Box::new(OwnerRequest::RemoveAgentException {
                    agent_id,
                    agent_name: agent.to_owned(),
                    item_id,
                    kind,
                })),
            )
        } else {
            NextRow::open_credential(format!("{text}."), item_id, item)
        });
    }
    if view.restricted && !view.listed.contains(&item_id) {
        return Some(NextRow::text(format!(
            "{agent} is limited to its listed credentials."
        )));
    }
    let except = |kind| Act::Except {
        agent_id,
        agent: agent.to_owned(),
        item_id,
        item: item.to_owned(),
        kind,
    };
    Some(NextRow {
        text: format!("Next uses by {agent}"),
        detail: None,
        buttons: vec![
            NextButton {
                label: "Always Ask",
                spoken: format!("Always ask {agent} for {item}"),
                style: Style::Bordered,
                act: except(ExceptionKind::AlwaysAsk),
            },
            NextButton {
                label: "Never",
                spoken: format!("Never give {item} to {agent}"),
                style: Style::DestructiveBordered,
                act: except(ExceptionKind::Never),
            },
        ],
    })
}

/// Draw "Why" and "Next time". Returns the action of a pressed button.
pub(crate) fn draw_top(ui: &mut Ui, past: &Past) -> Option<Act> {
    kit::section(ui, Some("Why"), None, |s| {
        s.row(|ui| {
            let _ = rows::text_buttons_detailed(
                ui,
                kit::text(&past.reason, Font::Body).color(kit::palette().label),
                (!past.note.is_empty()).then_some(past.note.as_str()),
                &[],
            );
        });
    });
    if past.next.is_empty() {
        return None;
    }
    let mut pressed = None;
    kit::section(ui, Some("Next time"), None, |s| {
        for row in &past.next {
            // The helper puts its first button at the trailing edge: the buttons of a row
            // go in from the last, so they read left to right as listed.
            let buttons: Vec<(&str, &str, Style)> = row
                .buttons
                .iter()
                .rev()
                .map(|button| (button.label, button.spoken.as_str(), button.style))
                .collect();
            let index = s.row(|ui| {
                rows::text_buttons_detailed(
                    ui,
                    kit::text(&row.text, Font::Body).color(kit::palette().label),
                    row.detail.as_deref(),
                    &buttons,
                )
            });
            if let Some(index) = index {
                pressed = row
                    .buttons
                    .iter()
                    .rev()
                    .nth(index)
                    .map(|button| button.act.clone());
            }
        }
    });
    pressed
}

/// Draw "Details", closed until the owner opens it: the "Decision" table (`facts`), the
/// facts of the decision, and the command of its use.
pub(crate) fn draw_details(ui: &mut Ui, past: &Past, open: &mut bool, facts: impl FnOnce(&mut Ui)) {
    ui.add_space(4.0);
    kit::disclosure(ui, open, "Details");
    if !*open {
        return;
    }
    facts(ui);
    kit::section(ui, None, None, |s| {
        for (label, value) in &past.details {
            if label.is_empty() {
                s.row(|ui| {
                    ui.add(
                        Label::new(kit::text(value, Font::Body).color(kit::palette().label)).wrap(),
                    );
                });
            } else {
                s.labeled(label, value.as_str());
            }
        }
    });
    if !past.command.is_empty() {
        kit::section(ui, Some("Command"), None, |s| {
            s.row(|ui| {
                ui.add(
                    Label::new(kit::text(&past.command, Font::Mono).color(kit::palette().label))
                        .wrap(),
                );
            });
        });
    }
}

/// Do what a button of "Next time" says.
pub(crate) fn act(app: &mut DesktopApp, ctx: &egui::Context, act: Act) {
    match act {
        Act::Ask(request) => app.ask_owner(*request, Some(ctx)),
        Act::RemoveAnswer { id, title } => {
            // Stricter: the bouncer asks again. No owner check (ADR 0025 §3b).
            match app
                .owner_ui
                .session
                .with_vault(|vault| vault.remove_answer(id))
            {
                Some(Ok(_)) => app.set_ok(format!(
                    "\u{201c}{title}\u{201d} is removed. The bouncer asks again."
                )),
                Some(Err(err)) => app.set_err(format!("The rule did not change: {err}.")),
                None => app.set_err("The vault is locked."),
            }
        }
        Act::Forget(ids) => {
            // The patterns are read again at the click: one blocked since the detail was
            // drawn stays as it is.
            let active: Vec<u64> = app
                .owner_ui
                .session
                .patterns()
                .unwrap_or_default()
                .into_iter()
                .filter(|pattern| ids.contains(&pattern.id) && !pattern.blocked)
                .map(|pattern| pattern.id)
                .collect();
            let removed = !active.is_empty()
                && active
                    .into_iter()
                    .all(|id| app.owner_ui.session.remove_pattern(id).is_ok());
            if removed {
                app.set_ok("Forgotten. Matching runs ask you again.");
            } else {
                app.set_err("The pattern was not removed.");
            }
        }
        Act::Except {
            agent_id,
            agent,
            item_id,
            item,
            kind,
        } => {
            match app
                .owner_ui
                .session
                .with_vault(|vault| vault.add_agent_exception(agent_id, item_id, kind))
            {
                Some(Ok(())) => app.set_ok(match kind {
                    ExceptionKind::Never => format!("{agent} never gets {item}."),
                    _ => format!("Each use of {item} by {agent} now asks you."),
                }),
                Some(Err(err)) => app.set_err(format!("The rule did not change: {err}.")),
                None => app.set_err("The vault is locked."),
            }
        }
        Act::OpenCredential(item_id) => app.select_item(item_id.to_string()),
        Act::OpenSettings => super::open_settings(app, super::SettingsSection::Bouncer),
    }
}

#[cfg(test)]
#[path = "decisions_past_tests.rs"]
mod tests;
