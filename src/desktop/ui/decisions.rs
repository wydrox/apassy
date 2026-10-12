//! Decisions (ADR 0026 §2, ADR 0025 §3): what waits for the owner.
//!
//! The list has the questions that wait ("Waiting"): the agent, the credential, the
//! project, a red dot for production, and the time left of the 5-minute wait. Credential
//! requests ("Requests") and corrections ("Suggestions") come with the agent tools: until
//! the vault keeps them, the list has no such section. The line under the title counts
//! the owner interactions and the automatic decisions of the week (ADR 0025 §1).
//!
//! The detail of a question has its facts, its command, why the owner is asked, and a bar
//! at the bottom: Deny, Allow Once, and the remembered answer that the question offers
//! ([`QuestionInfo::valid_answers`]). The "⋯" menu makes the agent stricter. Each answer
//! that gives authority passes the owner check; a stricter answer needs none. After an
//! answer, the next question is selected.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{
    self, Align, Frame, Label, Layout, Margin, Pos2, Rect, Sense, TextStyle, TextWrapMode, Vec2,
    WidgetInfo, WidgetText, WidgetType,
};

use super::columns::{self, Group};
use super::kit::{self, Font, Icon, Style, Tone};
use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::{
    AnswerKind, ApprovalQueue, PendingRun, QuestionInfo, QuestionItem, StricterAnswer, shown_path,
};
use crate::broker::server::QUESTION_WAIT;
use crate::contracts::CredentialKind;
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{BrokerState, DesktopApp};
use crate::vault::Environment;

/// The longest project name in a button. A longer name ends with "…".
const SHORT_PROJECT: usize = 28;
/// The longest folder path in the facts.
const SHOWN_PATH: usize = 80;

/// The state of the view.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The selected question, by run ID.
    selected: Option<u64>,
    /// Its place in the list in the last frame. When it goes (an answer, a time-out), the
    /// question that takes its place is selected.
    index: usize,
    /// "Disconnect AGENT…" waits for its confirmation: the run and the agent name.
    disconnect: Option<(u64, String)>,
}

/// One question that waits, with the time left of its wait.
#[derive(Debug, Clone)]
pub(super) struct Waiting {
    pub(super) run: PendingRun,
    pub(super) left: Duration,
}

/// The remembered answer that the bottom bar offers as its main button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Primary {
    /// "Allow ACTION in PROJECT".
    InProject(ActionKind),
    /// "Allow production: ACTION in PROJECT".
    Production(ActionKind),
    /// "Development" (and "Production") for a credential that is production only by
    /// default.
    Correct,
}

/// An answer of the owner on the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Answer {
    Deny,
    Once,
    InProject(ActionKind),
    Production(ActionKind),
    /// Mark the credential as development: the owner check first.
    Development {
        item_id: u64,
        name: String,
    },
    /// Mark the credential as production: stricter, no check.
    MarkProduction {
        item_id: u64,
        name: String,
    },
    Never,
    AlwaysAsk,
    Disconnect,
}

// ---- Pure parts, for the tests. ----

/// The time left of a wait of `timeout` that started `age` ago.
pub(super) fn time_left(timeout: Duration, age: Duration) -> Duration {
    timeout.saturating_sub(age)
}

/// "4:52": minutes and seconds, rounded up, so a wait shows "0:00" only at its end.
pub(super) fn clock(left: Duration) -> String {
    let seconds = left.as_millis().div_ceil(1000);
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

/// The kind of action in a button: "Read", "Change", "Deploy", "Delete".
pub(super) fn action_label(action: ActionKind) -> &'static str {
    match action {
        ActionKind::Read => "Read",
        ActionKind::Change => "Change",
        ActionKind::Deploy => "Deploy",
        ActionKind::Delete => "Delete",
    }
}

/// The main answer of a question from the answers that can take effect: production
/// first, then the project answer, then the correction of a default production value.
pub(super) fn primary(question: &QuestionInfo) -> Option<Primary> {
    let offered =
        |wanted: fn(&AnswerKind) -> Option<Primary>| question.valid_answers.iter().find_map(wanted);
    let in_project = question.project.is_some();
    offered(|answer| match answer {
        AnswerKind::Production(action) => Some(Primary::Production(*action)),
        _ => None,
    })
    .filter(|_| in_project)
    .or_else(|| {
        offered(|answer| match answer {
            AnswerKind::InProject(action) => Some(Primary::InProject(*action)),
            _ => None,
        })
        .filter(|_| in_project)
    })
    .or_else(|| {
        offered(|answer| match answer {
            AnswerKind::CorrectEnvironment => Some(Primary::Correct),
            _ => None,
        })
        .filter(|_| question.items.iter().any(|item| item.unconfirmed))
    })
}

/// A project name for a button, at most [`SHORT_PROJECT`] characters.
fn short(text: &str) -> String {
    let mut cut: String = text.chars().take(SHORT_PROJECT).collect();
    if cut.len() < text.len() {
        cut.pop();
        cut.push('…');
    }
    cut
}

/// The label of the main button, or `None` when the question offers no remembered
/// answer.
pub(super) fn primary_label(question: &QuestionInfo) -> Option<String> {
    let project = question
        .project
        .as_ref()
        .map(|project| short(&project.label));
    Some(match (primary(question)?, project) {
        (Primary::InProject(action), Some(project)) => {
            format!("Allow {} in {project}", action_label(action))
        }
        (Primary::Production(action), Some(project)) => {
            format!("Allow production: {} in {project}", action_label(action))
        }
        (Primary::Correct, _) => "Development".to_owned(),
        _ => return None,
    })
}

/// The question to select: the selected one while it waits, else the one at its place,
/// else the last one.
pub(super) fn next_selection(ids: &[u64], selected: Option<u64>, index: usize) -> Option<u64> {
    if selected.is_some_and(|id| ids.contains(&id)) {
        return selected;
    }
    ids.get(index.min(ids.len().saturating_sub(1))).copied()
}

/// A command as a shell would read it: an argument with a space or a quote is quoted.
pub(super) fn shell_words(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| {
            let plain = !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c));
            if plain {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The hosts that the command names, as the broker compares them.
fn command_hosts(command: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = crate::broker::shell_risk::command_hosts(command)
        .iter()
        .filter_map(|host| crate::vault::answers::normal_host(host))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The credentials of a question: "Stripe live", "A and B", or "A and 2 more".
fn item_names(run: &PendingRun) -> String {
    let names: Vec<&str> = if run.question.items.is_empty() {
        run.env_names.iter().map(String::as_str).collect()
    } else {
        run.question
            .items
            .iter()
            .map(|item| item.name.as_str())
            .collect()
    };
    match names.as_slice() {
        [] => "a credential".to_owned(),
        [one] => (*one).to_owned(),
        [one, two] => format!("{one} and {two}"),
        [one, rest @ ..] => format!("{one} and {} more", rest.len()),
    }
}

/// The project of a question for the facts and the list.
fn project_text(run: &PendingRun) -> String {
    match (&run.question.project, run.cwd.is_empty()) {
        (Some(project), _) => project.label.clone(),
        (None, true) => "No project".to_owned(),
        (None, false) => format!("No project ({})", shown_path(&run.cwd, SHOWN_PATH)),
    }
}

fn production(run: &PendingRun) -> bool {
    run.question.production || run.question.items.iter().any(|item| item.production)
}

// ---- The queue. ----

fn queue(app: &DesktopApp) -> Option<(Arc<ApprovalQueue>, Duration)> {
    match &app.broker {
        BrokerState::Running(handle) => {
            Some((Arc::clone(handle.approvals()), handle.approval_timeout()))
        }
        _ => None,
    }
}

/// The questions that wait, the least time left first.
pub(super) fn waiting(app: &DesktopApp, pending: &[PendingRun]) -> Vec<Waiting> {
    let (ages, timeout) = match queue(app) {
        Some((queue, timeout)) => (
            queue
                .pending_with_age()
                .into_iter()
                .map(|(run, age)| (run.id, age))
                .collect::<BTreeMap<_, _>>(),
            timeout,
        ),
        None => (BTreeMap::new(), QUESTION_WAIT),
    };
    let mut waiting: Vec<Waiting> = pending
        .iter()
        .map(|run| Waiting {
            left: time_left(timeout, ages.get(&run.id).copied().unwrap_or_default()),
            run: run.clone(),
        })
        .collect();
    waiting.sort_by_key(|waiting| waiting.left);
    waiting
}

/// The open credential requests of agents. The vault keeps them in `credential_request`
/// (schema 18), but it has no API for them until the agent tools (stream T2), so there is
/// none to show.
fn open_requests(_app: &DesktopApp) -> usize {
    0
}

/// The red count of Decisions in the sidebar: what blocks an agent, the waiting
/// questions and the open credential requests. Suggestions do not count.
pub(super) fn badge_count(app: &DesktopApp, pending: &[PendingRun]) -> usize {
    pending.len() + open_requests(app)
}

/// The selected question, by run ID.
#[cfg(test)]
pub(super) fn selected(app: &DesktopApp) -> Option<u64> {
    app.ui.decisions.selected
}

/// "Disconnect AGENT…" waits for its confirmation.
#[cfg(test)]
pub(super) fn disconnecting(app: &DesktopApp) -> bool {
    app.ui.decisions.disconnect.is_some()
}

/// Select a question, for example from the banner of another view.
pub(super) fn select(app: &mut DesktopApp, run_id: u64) {
    app.ui.decisions.selected = Some(run_id);
    app.ui.decisions.disconnect = None;
}

fn sync_selection(state: &mut State, waiting: &[Waiting]) {
    let ids: Vec<u64> = waiting.iter().map(|waiting| waiting.run.id).collect();
    state.selected = next_selection(&ids, state.selected, state.index);
    if let Some(selected) = state.selected {
        state.index = ids.iter().position(|id| *id == selected).unwrap_or(0);
    }
    if state
        .disconnect
        .as_ref()
        .is_some_and(|(run_id, _)| !ids.contains(run_id))
    {
        state.disconnect = None;
    }
}

// ---- The list column. ----

pub(super) fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    let waiting = waiting(app, pending);
    sync_selection(&mut app.ui.decisions, &waiting);
    let subtitle = app
        .owner_ui
        .session
        .week_counts()
        .map(|counts| counts.line())
        .unwrap_or_default();
    columns::list_toolbar(ui, "Decisions", &subtitle, |_| {});
    let mut groups = Vec::new();
    if !waiting.is_empty() {
        groups.push(Group {
            title: "Waiting".to_owned(),
            rows: waiting,
        });
    }
    let selected = app.ui.decisions.selected;
    let mut chosen = None;
    columns::grouped_rows(
        ui,
        "decisions-list",
        &groups,
        true,
        |ui, waiting| {
            let run = &waiting.run;
            let response = ui
                .push_id(("decision-row", run.id), |ui| {
                    decision_row(
                        ui,
                        &DecisionRow {
                            tile: kit::Tile::letter(
                                super::agents::agent_color(&run.agent),
                                &run.agent,
                            ),
                            title: &item_names(run),
                            subtitle: &format!("{} · {}", run.agent, project_text(run)),
                            production: production(run),
                            left: &clock(waiting.left),
                            selected: selected == Some(run.id),
                        },
                    )
                })
                .inner;
            if response.clicked() {
                chosen = Some(run.id);
            }
        },
        |ui| {
            if groups.is_empty() {
                columns::list_note(ui, "Nothing needs you");
            }
        },
    );
    if let Some(run_id) = chosen {
        select(app, run_id);
    }
}

/// One row of the list.
struct DecisionRow<'a> {
    tile: kit::Tile,
    title: &'a str,
    subtitle: &'a str,
    production: bool,
    /// The time left, in orange.
    left: &'a str,
    selected: bool,
}

/// A row of the list as [`kit::list_row`], with the time left in orange at the right
/// and the red dot of production before it.
fn decision_row(ui: &mut egui::Ui, row: &DecisionRow<'_>) -> egui::Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 48.0), Sense::click());
    let name = format!(
        "{}, {}{}, {} left",
        row.title,
        row.subtitle,
        if row.production { ", production" } else { "" },
        row.left
    );
    response.widget_info(|| {
        WidgetInfo::selected(WidgetType::SelectableLabel, true, row.selected, &name)
    });
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let painter = ui.painter();
    if row.selected {
        painter.rect_filled(rect, 8, kit::SELECTION);
    } else if response.hovered() {
        painter.rect_filled(rect, 8, egui::Color32::from_rgb(247, 247, 248));
    }
    if response.has_focus() {
        kit::inner_focus_ring(painter, rect, 8);
    }
    let tile_rect = Rect::from_min_size(
        Pos2::new(rect.left() + 8.0, rect.center().y - 16.0),
        Vec2::splat(32.0),
    );
    kit::paint_tile(ui, tile_rect, &row.tile);
    let (title_color, sub_color, time_color, dot) = if row.selected {
        let white = egui::Color32::WHITE;
        (white, egui::Color32::from_white_alpha(210), white, white)
    } else {
        (
            kit::LABEL,
            kit::SECONDARY,
            Tone::Warning.text(),
            kit::PRODUCTION,
        )
    };
    let galley = |value: egui::RichText, max: f32| {
        WidgetText::from(value).into_galley(ui, Some(TextWrapMode::Truncate), max, TextStyle::Body)
    };
    let time = galley(kit::text(row.left, Font::Callout).color(time_color), 60.0);
    let mut right = rect.right() - 8.0 - time.size().x;
    painter.galley(
        Pos2::new(right, rect.center().y - time.size().y / 2.0),
        time,
        time_color,
    );
    right -= 6.0;
    if row.production {
        painter.circle_filled(Pos2::new(right - 3.5, rect.center().y), 3.5, dot);
        right -= 13.0;
    }
    let left = tile_rect.right() + 10.0;
    let text_width = (right - left).max(10.0);
    let title = galley(
        kit::medium(row.title, Font::Body).color(title_color),
        text_width,
    );
    let subtitle = galley(
        kit::text(row.subtitle, Font::Callout).color(sub_color),
        text_width,
    );
    let top = rect.center().y - (title.size().y + subtitle.size().y) / 2.0;
    let title_height = title.size().y;
    painter.galley(Pos2::new(left, top), title, title_color);
    painter.galley(Pos2::new(left, top + title_height), subtitle, sub_color);
    response
}

// ---- The detail column. ----

pub(super) fn detail_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    let waiting = waiting(app, pending);
    sync_selection(&mut app.ui.decisions, &waiting);
    let current = app
        .ui
        .decisions
        .selected
        .and_then(|id| waiting.iter().find(|waiting| waiting.run.id == id))
        .cloned();
    let mut answer = None;
    columns::detail_toolbar(ui, |ui| {
        if let Some(current) = &current {
            more_menu(ui, &current.run, &mut answer);
        }
    });
    let Some(current) = current else {
        columns::detail_body(ui, ("decision", None::<u64>), |ui| {
            super::shell::banners(app, ui, pending);
            notifications_notice(app, ui);
            columns::nothing_selected(
                ui,
                Icon::CheckCircle,
                "All clear",
                "Nothing waits for you. A new question also shows as a macOS notification.",
            );
        });
        return;
    };
    egui::Panel::bottom(egui::Id::new(("decision-bar", current.run.id)))
        .resizable(false)
        .show_separator_line(true)
        .frame(
            Frame::NONE
                .fill(kit::SURFACE)
                .inner_margin(Margin::symmetric(16, 10)),
        )
        .show(ui, |ui| action_bar(ui, &current.run, &mut answer));
    columns::detail_body(ui, ("decision", Some(current.run.id)), |ui| {
        super::shell::banners(app, ui, pending);
        notifications_notice(app, ui);
        draw_question(app, ui, &current, &mut answer);
    });
    if let Some(answer) = answer {
        apply(app, ui.ctx(), &current.run, answer);
    }
    disconnect_sheet(app, ui.ctx());
}

/// A short banner when macOS cannot show a notification. The controls are in Settings.
fn notifications_notice(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(center) = &app.owner.notifications else {
        return;
    };
    let view = center.view();
    if view.channel.can_deliver() {
        return;
    }
    let summary = view.channel.summary();
    let open = kit::notice(
        ui,
        Tone::Warning,
        "macOS notifications are off",
        Some(&summary),
        |ui| kit::small_button(ui, "Open Settings", Style::Link).clicked(),
    );
    if open {
        app.open_settings_window();
        app.ui.settings_tab = super::settings::SettingsTab::Notifications;
    }
}

/// "⋯": the stricter answers that the question offers (ADR 0025 §3f).
fn more_menu(ui: &mut egui::Ui, run: &PendingRun, answer: &mut Option<Answer>) {
    let valid = &run.question.valid_answers;
    let offers = |kind: AnswerKind| valid.contains(&kind);
    if !offers(AnswerKind::NeverForAgent)
        && !offers(AnswerKind::AlwaysAskForAgent)
        && !offers(AnswerKind::Disconnect)
    {
        return;
    }
    let more = kit::toolbar_button(ui, Some(Icon::More), "", "More answers for this question");
    egui::Popup::menu(&more).show(|ui| {
        ui.set_min_width(200.0);
        if offers(AnswerKind::NeverForAgent)
            && ui
                .selectable_label(false, format!("Never for {}", run.agent))
                .clicked()
        {
            *answer = Some(Answer::Never);
        }
        if offers(AnswerKind::AlwaysAskForAgent)
            && ui
                .selectable_label(false, format!("Always Ask for {}", run.agent))
                .clicked()
        {
            *answer = Some(Answer::AlwaysAsk);
        }
        if offers(AnswerKind::Disconnect) {
            ui.separator();
            if ui
                .selectable_label(false, format!("Disconnect {}…", run.agent))
                .clicked()
            {
                *answer = Some(Answer::Disconnect);
            }
        }
    });
}

/// The first credential of a question that is production only by default.
fn unconfirmed(run: &PendingRun) -> Option<&QuestionItem> {
    run.question.items.iter().find(|item| item.unconfirmed)
}

/// The bar at the bottom: Deny on the left; a caption; Allow Once; the main answer.
fn action_bar(ui: &mut egui::Ui, run: &PendingRun, answer: &mut Option<Answer>) {
    let question = &run.question;
    let main = primary(question);
    let main_label = primary_label(question);
    let caption = match (main, &question.project) {
        (Some(Primary::InProject(_)), Some(project)) => format!(
            "Allow is remembered for all agents in {}.",
            short(&project.label)
        ),
        (Some(Primary::Production(action)), Some(project)) => format!(
            "Production stays allowed for {} in {} for all agents.",
            crate::broker::approvals::action_words(action),
            short(&project.label)
        ),
        (Some(Primary::Correct), _) => unconfirmed(run).map_or_else(String::new, |item| {
            format!("Is {} a development credential?", item.name)
        }),
        _ => "Allow Once allows this run only.".to_owned(),
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if kit::button(ui, "Deny", Style::Destructive).clicked() {
            *answer = Some(Answer::Deny);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            match (main, &main_label) {
                (Some(Primary::Correct), Some(label)) => {
                    let item = unconfirmed(run);
                    if kit::button(ui, label, Style::Prominent).clicked()
                        && let Some(item) = item
                    {
                        *answer = Some(Answer::Development {
                            item_id: item.item_id,
                            name: item.name.clone(),
                        });
                    }
                    if kit::button(ui, "Production", Style::Bordered).clicked()
                        && let Some(item) = item
                    {
                        *answer = Some(Answer::MarkProduction {
                            item_id: item.item_id,
                            name: item.name.clone(),
                        });
                    }
                    if kit::button(ui, "Allow Once", Style::Bordered).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
                (Some(remembered), Some(label)) => {
                    if kit::button(ui, label, Style::Prominent).clicked() {
                        *answer = Some(match remembered {
                            Primary::Production(action) => Answer::Production(action),
                            Primary::InProject(action) => Answer::InProject(action),
                            Primary::Correct => Answer::Once,
                        });
                    }
                    if kit::button(ui, "Allow Once", Style::Bordered).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
                _ => {
                    if kit::button(ui, "Allow Once", Style::Prominent).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
            }
            ui.add(Label::new(kit::text(caption, Font::Callout).color(kit::SECONDARY)).truncate());
        });
    });
}

/// A credential of the question with its provider tile and its production cap.
fn credential_row(app: &DesktopApp, section: &mut kit::Section<'_>, item: &QuestionItem) {
    let tile = item_tile(app, item.item_id, &item.name);
    section.row(|ui| {
        ui.horizontal(|ui| {
            ui.label(kit::text("Credential", Font::Body).color(kit::LABEL));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                if item.production {
                    kit::cap(ui, "Production", true);
                } else if item.unconfirmed {
                    kit::cap(ui, "Production by default", false);
                }
                if item.always_ask {
                    kit::cap(ui, "Always ask", false);
                }
                ui.add(Label::new(kit::text(&item.name, Font::Body).color(kit::LABEL)).truncate());
                kit::tile(ui, &tile, 20.0);
            });
        });
    });
}

/// The provider tile of a credential, or the tile of its kind.
fn item_tile(app: &DesktopApp, item_id: u64, name: &str) -> kit::Tile {
    let session = &app.owner_ui.session;
    let provider = session
        .with_vault(|vault| vault.declaration_provider(item_id))
        .and_then(Result::ok)
        .flatten()
        .and_then(|id| crate::vault::providers::find(&id))
        .map(|provider| provider.label.clone());
    let (kind, service) = session
        .details(item_id)
        .map_or((CredentialKind::Custom, String::new()), |details| {
            (details.kind, details.service)
        });
    super::credential_tile(kind, provider.as_deref().unwrap_or(&service), name)
}

fn draw_question(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    waiting: &Waiting,
    answer: &mut Option<Answer>,
) {
    let run = &waiting.run;
    let question = &run.question;
    ui.horizontal(|ui| {
        kit::tile(
            ui,
            &kit::Tile::letter(super::agents::agent_color(&run.agent), &run.agent),
            48.0,
        );
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(
                Label::new(
                    kit::text(
                        format!("{} wants to use {}", run.agent, item_names(run)),
                        Font::Title3,
                    )
                    .color(kit::LABEL),
                )
                .wrap(),
            );
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.label(
                    kit::text(format!("{} · ", project_text(run)), Font::Callout)
                        .color(kit::SECONDARY),
                );
                ui.label(
                    kit::text(
                        format!("{} left to answer", clock(waiting.left)),
                        Font::Callout,
                    )
                    .color(Tone::Warning.text()),
                );
            });
        });
    });
    ui.add_space(16.0);
    let hosts = command_hosts(&run.command);
    kit::section(ui, None, None, |s| {
        for item in &question.items {
            credential_row(app, s, item);
        }
        if question.items.is_empty() && !run.env_names.is_empty() {
            s.labeled(
                "Variables",
                kit::text(run.env_names.join(", "), Font::Mono).color(kit::LABEL),
            );
        }
        s.labeled(
            "Action",
            kit::text(action_label(question.action), Font::Body).color(kit::SECONDARY),
        );
        s.labeled(
            "Project",
            kit::text(project_text(run), Font::Body).color(kit::SECONDARY),
        );
        s.labeled(
            "Sends to",
            kit::text(
                if hosts.is_empty() {
                    "No host in the command".to_owned()
                } else {
                    hosts.join(", ")
                },
                Font::Body,
            )
            .color(kit::SECONDARY),
        );
    });
    if !run.user_request.is_empty() {
        let source = if run.request_source.is_empty() {
            "from the agent"
        } else {
            run.request_source.as_str()
        };
        kit::section(ui, Some("Request"), None, |s| {
            s.row(|ui| {
                kit::paragraph(
                    ui,
                    format!("\"{}\" ({source})", run.user_request),
                    Font::Body,
                    kit::LABEL,
                );
                // Goal item B6: the hook request replaced a different text of the agent.
                if !run.agent_request.is_empty() {
                    kit::tone_note(
                        ui,
                        format!(
                            "The agent sent a different request: \"{}\"",
                            run.agent_request
                        ),
                        Tone::Warning,
                    );
                }
            });
        });
    }
    kit::section(ui, Some("Command"), None, |s| {
        s.row(|ui| {
            ui.add(
                Label::new(kit::text(shell_words(&run.command), Font::Mono).color(kit::LABEL))
                    .wrap(),
            );
        });
    });
    let why = if !question.why.is_empty() {
        question.why.clone()
    } else if !run.risk.is_empty() {
        run.risk.clone()
    } else {
        "The bouncer did not decide this run, so it asks you.".to_owned()
    };
    kit::section(ui, Some("Why you are asked"), None, |s| {
        s.row(|ui| kit::paragraph(ui, why, Font::Body, kit::LABEL));
    });
    // The correction stays at hand when the bar offers a remembered answer.
    if question
        .valid_answers
        .contains(&AnswerKind::CorrectEnvironment)
        && primary(question) != Some(Primary::Correct)
    {
        kit::section(
            ui,
            Some("Environment"),
            Some("Until you answer, the bouncer treats it as production and asks more often."),
            |s| {
                for item in question.items.iter().filter(|item| item.unconfirmed) {
                    s.row(|ui| {
                        egui::Sides::new().shrink_left().show(
                            ui,
                            |ui| {
                                ui.add(
                                    Label::new(
                                        kit::text(
                                            format!("{} is production only by default.", item.name),
                                            Font::Body,
                                        )
                                        .color(kit::LABEL),
                                    )
                                    .wrap(),
                                );
                            },
                            |ui| {
                                if kit::small_button(ui, "Development", Style::Bordered).clicked() {
                                    *answer = Some(Answer::Development {
                                        item_id: item.item_id,
                                        name: item.name.clone(),
                                    });
                                }
                                if kit::small_button(ui, "Production", Style::Bordered).clicked() {
                                    *answer = Some(Answer::MarkProduction {
                                        item_id: item.item_id,
                                        name: item.name.clone(),
                                    });
                                }
                            },
                        );
                    });
                }
            },
        );
    }
    kit::note(
        ui,
        "The process can read these secrets. An allow needs Touch ID or the passphrase now. A notification is not an approval.",
    );
}

/// Do the answer of the owner. An answer that gives authority opens the owner check;
/// the run stays in the queue until it passes. A stricter answer acts at once.
pub(super) fn apply(app: &mut DesktopApp, ctx: &egui::Context, run: &PendingRun, answer: Answer) {
    let Some((queue, _)) = queue(app) else {
        app.set_err("The broker is not running. Nothing changed.");
        return;
    };
    let names = item_names(run);
    match answer {
        Answer::Deny => {
            if queue.deny(run.id) {
                app.set_ok(format!("Denied. {} gets a refusal.", run.agent));
            } else {
                app.set_err("The question no longer waits.");
            }
        }
        Answer::Once => app.ask_owner(OwnerRequest::ApproveRun(run.clone()), Some(ctx)),
        Answer::InProject(action) | Answer::Production(action) => {
            let Some(project) = run.question.project.clone() else {
                app.set_err("This question has no project. Use Allow Once.");
                return;
            };
            let request = if matches!(answer, Answer::Production(_)) {
                OwnerRequest::AllowProduction {
                    run: run.clone(),
                    project,
                    action,
                }
            } else {
                OwnerRequest::ApproveInProject {
                    run: run.clone(),
                    project,
                    action,
                }
            };
            app.ask_owner(request, Some(ctx));
        }
        Answer::Development { item_id, name } => app.ask_owner(
            OwnerRequest::CorrectEnvironment {
                run_id: run.id,
                agent: run.agent.clone(),
                item_id,
                name,
                environment: Environment::Development,
            },
            Some(ctx),
        ),
        Answer::MarkProduction { item_id, name } => {
            let result = app.owner_ui.session.mark_production(item_id);
            let _ = app.apply(
                result,
                &format!(
                    "{name} is marked as production. The question of {} still waits.",
                    run.agent
                ),
            );
        }
        Answer::Never | Answer::AlwaysAsk => {
            let (stricter, message) = if answer == Answer::Never {
                (
                    StricterAnswer::NeverForAgent,
                    format!("Denied. {} never gets {names}.", run.agent),
                )
            } else {
                (
                    StricterAnswer::AlwaysAskForAgent,
                    format!("Denied. Each use of {names} by {} asks you.", run.agent),
                )
            };
            stricter_answer(app, &queue, run.id, stricter, &message);
        }
        Answer::Disconnect => {
            app.ui.decisions.disconnect = Some((run.id, run.agent.clone()));
        }
    }
}

fn stricter_answer(
    app: &mut DesktopApp,
    queue: &ApprovalQueue,
    run_id: u64,
    stricter: StricterAnswer,
    message: &str,
) {
    match app.owner_ui.session.deny_stricter(queue, run_id, stricter) {
        Ok(true) => app.set_ok(message),
        Ok(false) => app.set_err("The question no longer waits. Nothing changed."),
        Err(err) => app.set_err(err.message),
    }
}

/// "Disconnect AGENT…" asks once. It denies the question and revokes the agent: it
/// takes authority away, so it needs no owner check.
fn disconnect_sheet(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some((run_id, agent)) = app.ui.decisions.disconnect.clone() else {
        return;
    };
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "disconnect-agent", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Disconnect {agent}?"),
            Some(
                "Apassy denies this question, and the token of the agent stops working at once. You can connect it again later in Agents.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = kit::button(ui, "Disconnect", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if cancel || response.escape {
        app.ui.decisions.disconnect = None;
    }
    if confirm {
        app.ui.decisions.disconnect = None;
        let Some((queue, _)) = queue(app) else {
            app.set_err("The broker is not running. Nothing changed.");
            return;
        };
        stricter_answer(
            app,
            &queue,
            run_id,
            StricterAnswer::Disconnect,
            &format!("{agent} is disconnected. Its token does not work."),
        );
    }
}
