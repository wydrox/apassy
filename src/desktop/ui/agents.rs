//! Agents (ADR 0026 §2, ADR 0025 §3f): the connected agents, read-only.
//!
//! The list shows each agent, where it runs, and its uses this week. The page of an agent
//! shows, it does not configure: its uses and projects, the kinds of action it used this
//! week, its newest uses, an optional note for the bouncer, its exceptions, and
//! "Disconnect…". An exception comes from an answer in Decisions;
//! removing one gives authority back, so it needs the owner check. Saving the note and
//! disconnecting take no authority, so they need none. "+" opens "Connect an Agent"
//! ([`super::agent_onboarding`]), the only setup, with one owner check.

use eframe::egui::{self, Align, Label, Layout};

use super::agent_onboarding::{self, ConnectHost};
use super::decisions::action_label;
use super::detail_rows as rows;
use super::kit::{self, Font, Icon, Style, Tone};
use super::{Sheet, close_sheet};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::{ActionUse, AgentOverview, ExceptionRow, RecentUse, format_utc};
use crate::desktop::{DesktopApp, Place};
use crate::vault::AgentSummary;
use crate::vault::exceptions::{ExceptionKind, MAX_AGENT_NOTE_BYTES};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The date part of a UTC time.
fn date(unix: u64) -> String {
    format_utc(unix)
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Where an agent runs. Agents reach the broker through its socket on this Mac.
const WHERE: &str = "This Mac";

/// The state of the view: the note that the owner edits.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The agent of the note field and its text.
    pub(super) note: Option<(u64, String)>,
}

/// The detail column of Agents: the selected agent, or with none, an empty state. As in
/// the mockup, the page has no banner of a waiting question: the red count of Decisions
/// in the sidebar shows it. A ready update and a sync note still show.
pub(super) fn detail_column(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    _pending: &super::shell::Pending,
) {
    let selected = app.owner_ui.selected_agent;
    let agent = selected.and_then(|agent_id| {
        app.owner_ui
            .session
            .agents()
            .ok()
            .and_then(|agents| agents.into_iter().find(|agent| agent.id == agent_id))
    });
    let mut reconnect = false;
    super::columns::detail_toolbar(ui, |ui| {
        if let Some(agent) = agent.as_ref().filter(|agent| !agent.revoked) {
            reconnect = more_menu(ui, agent);
        }
    });
    if let Some(agent) = agent.as_ref().filter(|_| reconnect) {
        let ctx = ui.ctx().clone();
        agent_onboarding::reconnect(app, &ctx, &agent.name);
    }
    super::columns::detail_body(ui, ("agent", selected), |ui| {
        ui.scope(|ui| super::updates::banner(app, ui));
        ui.scope(|ui| super::sync::banner(app, ui));
        match agent {
            Some(agent) => draw_agent(app, ui, &agent),
            None => {
                if selected.is_some() {
                    app.owner_ui.selected_agent = None;
                }
                draw_empty(app, ui);
            }
        }
    });
}

/// "⋯" in the toolbar: the rare actions of an agent, under the date its token ends.
/// Returns true on "Reconnect with a New Token…".
fn more_menu(ui: &mut egui::Ui, agent: &AgentSummary) -> bool {
    let mut reconnect = false;
    let more = kit::toolbar_button(ui, Some(Icon::More), "", "More actions for this agent");
    egui::Popup::menu(&more).show(|ui| {
        ui.set_min_width(200.0);
        ui.label(kit::text(token_words(agent, now()), Font::Callout).color(kit::SECONDARY));
        ui.separator();
        reconnect = ui
            .selectable_label(false, "Reconnect with a New Token…")
            .clicked();
    });
    reconnect
}

/// The token line of the "⋯" menu.
fn token_words(agent: &AgentSummary, now: u64) -> String {
    let day = short_date(agent.token_expires_at, now);
    if agent.token_expired_at(now) {
        format!("Token expired {day}")
    } else {
        format!("Token valid until {day}")
    }
}

/// No agent is selected. With no connected agent, the empty state has the one main
/// action, "Connect an Agent".
fn draw_empty(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let agents = app.owner_ui.session.agents().unwrap_or_default();
    let revoked = agents.iter().filter(|agent| agent.revoked).count();
    let active = agents.len() - revoked;
    if active > 0 {
        super::columns::nothing_selected(
            ui,
            Icon::Agent,
            "No agent selected",
            "Select an agent in the list.",
        );
        return;
    }
    // A restore disconnects every agent, so the owner connects them again here.
    let (title, message) = if revoked == 0 {
        (
            "No agents yet",
            "Connect Claude Code, Codex, or another agent. The bouncer decides each use of a credential, and asks you when it is not sure.",
        )
    } else {
        (
            "No connected agents",
            "Every agent of this vault is disconnected, for example after a restore. Connect each agent host again; it gets a new token.",
        )
    };
    if kit::empty_state(ui, Icon::Agent, title, message, Some("Connect an Agent")) {
        agent_onboarding::open(app);
    }
}

/// Continue after a synced vault opens. The caller ties panel visibility to the
/// vault identity. A host choice or Skip ends this panel; CLI keeps its steps open.
pub(super) fn next_steps_panel(app: &mut DesktopApp, ui: &mut egui::Ui) -> bool {
    if app.owner_ui.session.is_locked() {
        return false;
    }
    let intro = match (
        app.owner_ui.session.search(""),
        app.owner_ui.session.archived(),
    ) {
        (Ok(items), Ok(archived)) => {
            let count = items
                .iter()
                .filter(|item| !archived.contains_key(&item.id))
                .count();
            if count == 1 {
                "The vault is open. 1 active credential is available on this Mac.".to_owned()
            } else {
                format!("The vault is open. {count} active credentials are available on this Mac.")
            }
        }
        _ => "The vault is open. Check Credentials for the available items.".to_owned(),
    };
    let mut host = None;
    let mut skip = false;
    let mut cli = app.ui.is_expanded("next-step-cli");
    kit::section(ui, Some("Use this vault on this Mac"), Some(&intro), |s| {
        s.row(|ui| {
            kit::note(
                ui,
                "Agents stay on this Mac. Connect them here before an agent can use a credential.",
            );
        });
        s.row(|ui| {
            ui.horizontal_wrapped(|ui| {
                if kit::button(ui, "Claude Code", Style::Bordered).clicked() {
                    host = Some(0);
                }
                if kit::button(ui, "Codex", Style::Bordered).clicked() {
                    host = Some(1);
                }
                if kit::button(ui, "CLI", Style::Bordered).clicked() {
                    cli = !cli;
                }
                skip = kit::button(ui, "Skip", Style::Link).clicked();
            });
        });
        s.row(|ui| {
            kit::note(
                ui,
                "You can do these steps later in Agents or Settings > Agents > Command line.",
            );
        });
    });
    app.ui.set_expanded("next-step-cli", cli);
    if cli {
        connection_progress(app, ui, true);
        cli_guidance(app, ui);
    }
    if let Some(host) = host {
        let ctx = ui.ctx().clone();
        choose_host(app, &ctx, host);
        return true;
    }
    skip
}

/// "Claude Code" or "Codex" in the panel: connect that host, with one owner check.
fn choose_host(app: &mut DesktopApp, ctx: &egui::Context, host: usize) {
    let host = if host == 1 {
        ConnectHost::Codex
    } else {
        ConnectHost::Claude
    };
    agent_onboarding::connect(app, Some(ctx), host, host.agent_name());
}

/// The app knows the first three stages. A settings file or an allowed request
/// cannot prove the last two: access requests can wait and runs can fail.
fn connection_progress(app: &mut DesktopApp, ui: &mut egui::Ui, cli: bool) {
    let links = super::cli_tools::installed();
    let window = app.cli.socket_path().is_some();
    let unlocked = !app.owner_ui.session.is_locked();
    let session = cli && app.cli_sessions_open() > 0;
    kit::section(ui, Some("Setup checks"), None, |s| {
        for (label, complete, detail) in [
            (
                "CLI tools installed",
                links,
                "Check in Settings > Agents > Command line",
            ),
            (
                "App available to CLI",
                window,
                "Check the owner socket in Settings",
            ),
            ("Vault unlocked", unlocked, "Unlock the vault"),
            (
                if cli {
                    "CLI connected"
                } else {
                    "Host connected"
                },
                session,
                if cli {
                    "Run apassy login, then apassy status"
                } else if app.ui.setup_host == 1 {
                    "Restart Codex. Trust the hook with /hooks. Check Apassy with /mcp."
                } else {
                    "Check Apassy in the host's /mcp view"
                },
            ),
            (
                "First successful request",
                false,
                "Check the result of a test request and its entry in Decisions",
            ),
        ] {
            s.status(
                label,
                (!complete).then_some(detail),
                kit::text(if complete { "Checked" } else { "To check" }, Font::Callout).color(
                    if complete {
                        Tone::Good.text()
                    } else {
                        kit::SECONDARY
                    },
                ),
            );
        }
        s.row(|ui| kit::note(ui, "CLI links do not set PATH. Host settings do not prove a connection or a successful request."));
    });
}

fn cli_guidance(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut install = false;
    kit::section(ui, Some("Use the CLI"), None, |s| {
        s.row(|ui| {
            kit::note(ui, "Install the CLI tools. Then run these commands in Terminal.");
            install = kit::button(ui, "Install CLI tools", Style::Bordered).clicked();
            kit::code_block(ui, "export PATH=\"$HOME/.local/bin:$PATH\"\neval \"$(apassy login)\"\napassy status\napassy doctor", 4);
            kit::note(ui, "Confirm the login in Apassy. Keep the window open and the vault unlocked.");
            kit::note(ui, "The PATH command applies to this Terminal session. Add it to ~/.zshrc for new sessions.");
            kit::note(ui, "CLI login is separate from an agent token. It does not give an agent access to credentials.");
        });
    });
    if install {
        match super::cli_tools::install() {
            Ok(()) => app.set_ok("CLI tools are installed in ~/.local/bin. Run the Terminal commands to check the connection."),
            Err(error) => app.set_err(error),
        }
    }
}

/// The list column of Agents: the connected agents, then the disconnected ones, folded.
/// "+" connects an agent.
pub(super) fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let agents = app.owner_ui.session.agents();
    let count = agents.as_ref().map_or(0, |agents| {
        agents.iter().filter(|agent| !agent.revoked).count()
    });
    let mut connect = false;
    super::columns::list_toolbar(ui, "Agents", &format!("{count} connected"), |ui| {
        connect = kit::plain_icon_button(ui, Icon::Plus, "Connect an Agent").clicked();
    });
    if connect {
        agent_onboarding::open(app);
    }
    let agents = match agents {
        Ok(agents) => agents,
        Err(err) => {
            kit::tone_note(ui, err.message, Tone::Critical);
            return;
        }
    };
    let now = now();
    let (revoked, active): (Vec<_>, Vec<_>) = agents.into_iter().partition(|agent| agent.revoked);
    let rows: Vec<(u64, String, String, Option<&'static str>)> = active
        .iter()
        .map(|agent| {
            let uses = app
                .owner_ui
                .session
                .agent_uses_this_week(agent.id)
                .unwrap_or(0);
            let subtitle = format!(
                "{WHERE} · {}",
                super::columns::count_label(uses, "use this week", "uses this week")
            );
            let meta = agent.token_expired_at(now).then_some("Token expired");
            (agent.id, agent.name.clone(), subtitle, meta)
        })
        .collect();
    let groups = if rows.is_empty() {
        Vec::new()
    } else {
        vec![super::columns::Group {
            title: "Connected".to_owned(),
            rows,
        }]
    };
    let selected = app.owner_ui.selected_agent;
    let mut open = None;
    let mut expanded = app.ui.is_expanded("revoked-agents");
    super::columns::grouped_rows(
        ui,
        "agent-list",
        &groups,
        false,
        |ui, (id, name, subtitle, meta)| {
            let response = ui
                .push_id(("agent-row", id), |ui| {
                    kit::list_row(
                        ui,
                        &kit::ListRow {
                            tile: kit::Tile::agent(name),
                            title: name,
                            subtitle,
                            meta: *meta,
                            production: false,
                            selected: selected == Some(*id),
                        },
                    )
                })
                .inner;
            if response.clicked() {
                open = Some(*id);
            }
        },
        |ui| {
            if active.is_empty() && revoked.is_empty() {
                super::columns::list_note(ui, "No agents yet.");
            }
            if !revoked.is_empty() {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    kit::disclosure(
                        ui,
                        &mut expanded,
                        &format!("Disconnected agents ({})", revoked.len()),
                    );
                });
                if expanded {
                    ui.add_space(4.0);
                    kit::section(ui, None, Some("A disconnected token does not work."), |s| {
                        for agent in &revoked {
                            s.labeled(
                                &agent.name,
                                kit::text(
                                    format!("Connected {}", date(agent.created_at)),
                                    Font::Callout,
                                )
                                .color(kit::SECONDARY),
                            );
                        }
                    });
                }
            }
        },
    );
    app.ui.set_expanded("revoked-agents", expanded);
    if let Some(agent_id) = open {
        app.owner_ui.selected_agent = Some(agent_id);
    }
}

/// The words of an exception in its row.
fn exception_words(kind: ExceptionKind) -> &'static str {
    match kind {
        ExceptionKind::Never => "Never",
        ExceptionKind::AlwaysAsk => "Always ask",
        ExceptionKind::Only => "Only",
    }
}

fn draw_agent(app: &mut DesktopApp, ui: &mut egui::Ui, agent: &AgentSummary) {
    let agent_id = agent.id;
    let now = now();
    // The header sits lower than the toolbar, as in the mockup.
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        kit::tile(ui, &kit::Tile::agent(&agent.name), 56.0);
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(Label::new(kit::text(&agent.name, Font::Title).color(kit::LABEL)).wrap());
            ui.label(
                kit::text(
                    format!("{WHERE} · connected {}", short_date(agent.created_at, now)),
                    Font::Body,
                )
                .color(kit::SECONDARY),
            );
        });
    });
    ui.add_space(16.0);
    if agent.revoked {
        kit::notice(
            ui,
            Tone::Neutral,
            "Disconnected. The token does not work.",
            Some("Connect the agent again with \"+\" to give it a new token."),
            |_| {},
        );
        return;
    }
    let overview = match app.owner_ui.session.agent_overview(agent_id) {
        Ok(overview) => overview,
        Err(err) => {
            kit::tone_note(ui, err.message, Tone::Critical);
            return;
        }
    };
    // The credentials in the catalog of the agent: `None` when it sees each name.
    let visible = app
        .owner_ui
        .session
        .with_vault(|vault| vault.visible_items_for_agent(agent_id))
        .and_then(Result::ok)
        .map_or_else(
            || overview.restricted.then_some(0),
            |visible| visible.map(|items| items.len()),
        );
    let reconnect = stats_group(ui, agent, &overview, visible, now);
    actions_group(ui, &overview);
    recent_group(ui, &overview.recent, now);
    note_group(app, ui, agent_id, &overview);
    exceptions_group(app, ui, agent, &overview.exceptions);
    let mut disconnect = false;
    kit::section(ui, None, None, |s| {
        disconnect = s
            .clickable_row(&format!("Disconnect {}…", agent.name), |ui| {
                ui.label(
                    kit::text(format!("Disconnect {}…", agent.name), Font::Body)
                        .color(Tone::Critical.text()),
                );
            })
            .clicked();
    });
    if reconnect {
        let ctx = ui.ctx().clone();
        agent_onboarding::reconnect(app, &ctx, &agent.name);
    } else if disconnect {
        app.ui.sheet = Some(Sheet::RevokeAgent {
            agent_id,
            name: agent.name.clone(),
        });
    }
}

/// What the agent sees, for the "Sees" row. `visible`: the number of credentials of an
/// agent restricted to its listed ones ("only these items", ADR 0025 §3f), or `None`
/// for an agent that sees the name of each credential.
fn sees_words(visible: Option<usize>) -> String {
    match visible {
        None => "Credential names, never values".to_owned(),
        Some(0) => "No credentials yet".to_owned(),
        Some(count) => format!(
            "Only {}, never values",
            super::columns::count_label(count, "credential", "credentials")
        ),
    }
}

/// A day as in the mockup: "Oct 9", with the year when it is not this year.
pub(super) fn short_date(unix: u64, now: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day = date(unix);
    let parts: Vec<&str> = day.split('-').collect();
    let [year, month, day_of_month] = parts[..] else {
        return day;
    };
    let (Ok(month), Ok(day_of_month)) = (month.parse::<usize>(), day_of_month.parse::<u32>())
    else {
        return day;
    };
    let Some(name) = month.checked_sub(1).and_then(|index| MONTHS.get(index)) else {
        return day;
    };
    if date(now).starts_with(year) {
        format!("{name} {day_of_month}")
    } else {
        format!("{name} {day_of_month}, {year}")
    }
}

/// Uses, projects, and what the agent sees. An expired token adds its row with
/// "Reconnect…": the agent cannot work until then. Returns true on "Reconnect…".
fn stats_group(
    ui: &mut egui::Ui,
    agent: &AgentSummary,
    overview: &AgentOverview,
    visible: Option<usize>,
    now: u64,
) -> bool {
    let mut reconnect = false;
    kit::section(ui, None, None, |s| {
        s.labeled(
            "Uses this week",
            kit::text(overview.uses_this_week.to_string(), Font::Body).color(kit::SECONDARY),
        );
        s.labeled(
            "Projects",
            kit::text(
                if overview.projects.is_empty() {
                    "None yet".to_owned()
                } else {
                    overview.projects.join(", ")
                },
                Font::Body,
            )
            .color(kit::SECONDARY),
        );
        s.labeled(
            "Sees",
            kit::text(sees_words(visible), Font::Body).color(kit::SECONDARY),
        );
        if !agent.token_expired_at(now) {
            return;
        }
        s.row(|ui| {
            egui::Sides::new().shrink_left().show(
                ui,
                |ui| {
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(kit::text("Token", Font::Body).color(kit::LABEL));
                        ui.add(
                            Label::new(
                                kit::text(
                                    format!(
                                        "Expired {}. Reconnect to give it a new one.",
                                        short_date(agent.token_expires_at, now)
                                    ),
                                    Font::Callout,
                                )
                                .color(Tone::Critical.text()),
                            )
                            .wrap(),
                        );
                    });
                },
                |ui| {
                    reconnect = kit::small_button(ui, "Reconnect…", Style::Prominent).clicked();
                },
            );
        });
    });
    reconnect
}

/// At most this many projects follow the count of an action.
const ACTION_PROJECTS: usize = 3;

/// The value of an action row: the allowed uses and the projects in gray, then the uses
/// that were not allowed, for red. "3 · acme-billing, apassy", "1 not allowed".
fn action_value(action: &ActionUse) -> (String, Option<String>) {
    let mut parts = Vec::new();
    if action.allowed > 0 {
        parts.push(action.allowed.to_string());
    }
    if !action.projects.is_empty() {
        let shown = action.projects[..action.projects.len().min(ACTION_PROJECTS)].join(", ");
        let more = action.projects.len().saturating_sub(ACTION_PROJECTS);
        parts.push(if more > 0 {
            format!("{shown}, and {more} more")
        } else {
            shown
        });
    }
    let refused = (action.not_allowed > 0).then(|| format!("{} not allowed", action.not_allowed));
    (parts.join(" · "), refused)
}

/// "Actions this week": one row per kind of action, the most used first, with the
/// words of Decisions ("Read", "Change", "Deploy", "Delete"). Uses that were denied,
/// refused, or not answered in time show apart, in red.
fn actions_group(ui: &mut egui::Ui, overview: &AgentOverview) {
    group_label(ui, "Actions this week");
    let rows: Vec<(&str, egui::text::LayoutJob)> = overview
        .actions
        .iter()
        .map(|action| {
            let (used, refused) = action_value(action);
            let mut job = egui::text::LayoutJob::default();
            let mut add = |text: String, color| {
                kit::text(text, Font::Body).color(color).append_to(
                    &mut job,
                    ui.style(),
                    egui::FontSelection::Default,
                    Align::Center,
                );
            };
            match refused {
                Some(refused) if used.is_empty() => add(refused, Tone::Critical.text()),
                Some(refused) => {
                    add(format!("{used} · "), kit::SECONDARY);
                    add(refused, Tone::Critical.text());
                }
                None => add(used, kit::SECONDARY),
            }
            (action_label(action.action), job)
        })
        .collect();
    kit::section(ui, None, None, |s| {
        if rows.is_empty() {
            s.row(|ui| {
                kit::note(
                    ui,
                    if overview.recent.is_empty() {
                        "No actions yet."
                    } else {
                        "No actions this week."
                    },
                );
            });
        }
        for (label, job) in rows {
            s.labeled(label, job);
        }
    });
}

/// The second line of a recent use: "Deploy in apassy · Allowed automatically".
fn recent_words(recent: &RecentUse, outcome: &str) -> String {
    let item_use = &recent.item_use;
    let action = action_label(item_use.action);
    if item_use.project_label.is_empty() {
        format!("{action} · {outcome}")
    } else {
        format!("{action} in {} · {outcome}", item_use.project_label)
    }
}

/// "Recent": the newest uses, as the "Agent use" group of a credential: the round mark,
/// the credential, the action, the project, and its result, with the time at the right.
/// The command shows on hover, as on the credential page. With no use, no group.
fn recent_group(ui: &mut egui::Ui, recent: &[RecentUse], now: u64) {
    if recent.is_empty() {
        return;
    }
    group_label(ui, "Recent");
    kit::section(ui, None, None, |s| {
        for entry in recent {
            let (mark, outcome) = super::items::use_outcome(&entry.item_use);
            let words = recent_words(entry, &outcome);
            let when = kit::relative_time(entry.item_use.at, now);
            let command = &entry.item_use.command_summary;
            s.row(|ui| {
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    ui.vertical(|ui| {
                        ui.add_space(1.0);
                        rows::status_mark(ui, mark);
                    });
                    let when_width =
                        kit::galley(ui, kit::text(&when, Font::Callout)).size().x + 10.0;
                    ui.vertical(|ui| {
                        ui.set_width((ui.available_width() - when_width).max(80.0));
                        ui.spacing_mut().item_spacing.y = 3.0;
                        // The second line sits right under the first: no minimum
                        // control height.
                        ui.spacing_mut().interact_size.y = 0.0;
                        ui.add(
                            Label::new(kit::text(&entry.item_name, Font::Body).color(kit::LABEL))
                                .truncate(),
                        );
                        let line = ui.add(Label::new(rows::small(words)).truncate());
                        if !command.is_empty() {
                            line.on_hover_text(kit::text(command, Font::Mono));
                        }
                    });
                    ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                        ui.label(kit::text(&when, Font::Callout).color(kit::TERTIARY));
                    });
                });
            });
        }
    });
}

/// The title of a group of the agent page, as in the mockup: small, semibold, and
/// gray, close over its group. A group leaves 20 points under it; the mockup has about
/// 18 over a title, so the title moves up into that space.
fn group_label(ui: &mut egui::Ui, title: &str) {
    ui.add_space(-10.0);
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.label(
            kit::text(title, Font::Headline)
                .size(12.0)
                .color(kit::SECONDARY),
        );
    });
}

/// "Note for the bouncer": a hint, not a limit (ADR 0025 §3f). Saving it needs no check.
fn note_group(app: &mut DesktopApp, ui: &mut egui::Ui, agent_id: u64, overview: &AgentOverview) {
    let state = &mut app.ui.agents;
    if state.note.as_ref().is_none_or(|(id, _)| *id != agent_id) {
        state.note = Some((agent_id, overview.note.clone()));
    }
    let mut save = false;
    {
        let Some((_, text)) = state.note.as_mut() else {
            return;
        };
        group_label(ui, "Note for the bouncer");
        kit::text_area(
            ui,
            text,
            &format!("agent-note-{agent_id}"),
            "Optional. For example: CI agent for Acme, only the Stripe test key.",
            2,
        )
        .on_hover_text(format!(
            "The bouncer reads it as a hint, not as a limit. At most {MAX_AGENT_NOTE_BYTES} bytes."
        ));
        if text.trim() != overview.note.trim() {
            ui.add_space(6.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                save = kit::small_button(ui, "Save Note", Style::Prominent).clicked();
            });
        }
        ui.add_space(16.0);
    }
    if save {
        save_note(app, agent_id);
    }
}

/// Save the note of the field. It is a hint for the bouncer and moves no authority, so
/// it needs no owner check.
pub(super) fn save_note(app: &mut DesktopApp, agent_id: u64) {
    let Some((_, text)) = app.ui.agents.note.clone().filter(|(id, _)| *id == agent_id) else {
        return;
    };
    let result = app.owner_ui.session.set_agent_note(agent_id, &text);
    if app.apply(result, "The note is saved.").is_some() {
        app.ui.agents.note = None;
    }
}

/// The exceptions of the agent, each with Remove. Removing "Never" or "Always ask" gives
/// authority back: the owner check. Removing a listed item ("Only") takes it away: none.
fn exceptions_group(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    agent: &AgentSummary,
    exceptions: &[ExceptionRow],
) {
    let mut remove = None;
    group_label(ui, "Exceptions");
    kit::section(ui, None, None, |s| {
        if exceptions.is_empty() {
            s.row(|ui| {
                kit::note(ui, "None. Exceptions come from your answers in Decisions.");
            });
        }
        for row in exceptions {
            let name = row.item.as_ref().map_or_else(
                || format!("Credential {}", row.exception.item_id),
                |item| item.name.clone(),
            );
            let tile = row.item.as_ref().map_or_else(
                || kit::Tile::icon(Tone::Neutral.mark(), Icon::Key),
                |item| super::credential_tile(item.kind, &item.service, &item.name),
            );
            let words = exception_words(row.exception.kind);
            s.row(|ui| {
                egui::Sides::new().shrink_left().show(
                    ui,
                    |ui| {
                        ui.horizontal(|ui| {
                            kit::tile(ui, &tile, 20.0);
                            ui.add(
                                Label::new(
                                    kit::text(format!("{words}: {name}"), Font::Body)
                                        .color(kit::LABEL),
                                )
                                .truncate(),
                            );
                        });
                    },
                    |ui| {
                        let button = kit::small_button(ui, "Remove", Style::Bordered);
                        let label = format!("Remove the exception {words}: {name}");
                        ui.ctx()
                            .accesskit_node_builder(button.id, |node| node.set_label(label));
                        if button.clicked() {
                            remove = Some(row.exception.clone());
                        }
                    },
                );
            });
        }
    });
    if let Some(exception) = remove {
        let ctx = ui.ctx().clone();
        remove_exception(app, &ctx, agent, &exception);
    }
}

/// Remove an exception. "Never" and "Always ask" give authority back: the owner check
/// first. A listed item ("Only") goes at once: the agent then sees less.
pub(super) fn remove_exception(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    agent: &AgentSummary,
    exception: &crate::vault::exceptions::AgentException,
) {
    if exception.kind == ExceptionKind::Only {
        let result = app
            .owner_ui
            .session
            .remove_listed_item(agent.id, exception.item_id);
        let _ = app.apply(
            result,
            &format!("{} no longer sees this credential.", agent.name),
        );
        return;
    }
    app.ask_owner(
        OwnerRequest::RemoveAgentException {
            agent_id: agent.id,
            agent_name: agent.name.clone(),
            item_id: exception.item_id,
            kind: exception.kind,
        },
        Some(ctx),
    );
}

// ---- Sheets. ----

fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn cli_path() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "apassy".to_owned())
}

/// The manual steps for a host, in "Advanced setup" of the token sheet.
fn setup_guidance(state: &mut super::UiState, ui: &mut egui::Ui) {
    let selected = super::agent_setup::Host::from_index(state.setup_host);
    kit::picker(
        ui,
        "setup-host",
        &mut state.setup_host,
        &[(0, "Claude Code".to_owned()), (1, "Codex".to_owned())],
        selected.name(),
        200.0,
    );
    let host = selected.id();
    kit::note(
        ui,
        format!(
            "First, install {}. Make sure `{host} --version` works in Terminal.",
            selected.name()
        ),
    );
    kit::note(
        ui,
        "1. Open Terminal. Run this command. Paste the token when Terminal waits, then press Return. The token is hidden as you type.",
    );
    let command = format!(
        "read -r -s APASSY_SETUP_TOKEN\nprintf '%s' \"$APASSY_SETUP_TOKEN\" | {} setup {host} --token-stdin --write\nunset APASSY_SETUP_TOKEN",
        shell_word(&cli_path())
    );
    kit::code_block(ui, &command, 3);
    kit::note(
        ui,
        "This writes the MCP server and prompt hook settings. It does not check the connection. Apassy keeps a copy of changed settings.",
    );
    kit::note(
        ui,
        if host == "codex" {
            "2. Restart Codex. Use /hooks to trust the Apassy hook. Check the Apassy server with /mcp."
        } else {
            "2. Restart Claude Code. Use /mcp to check that Apassy is connected."
        },
    );
    kit::note(
        ui,
        "3. In your project folder, start the host with this command. A question waits up to 5 minutes for you, so the host waits at least 330 seconds for a tool.",
    );
    kit::code_block(ui, &agent_onboarding::launch_command(selected), 2);
    let sandbox = std::path::Path::new(&cli_path())
        .parent()
        .map(|p| p.join("apassy-sandbox").display().to_string())
        .unwrap_or_else(|| "apassy-sandbox".to_owned());
    let protected = if host == "claude" {
        format!(
            "{} {} -- claude --settings '{{\"sandbox\":{{\"enabled\":false}}}}'",
            agent_onboarding::CLAUDE_TOOL_TIMEOUT,
            shell_word(&sandbox)
        )
    } else {
        format!(
            "{} -- codex -c sandbox_mode=danger-full-access",
            shell_word(&sandbox)
        )
    };
    kit::note(
        ui,
        "Optional, more protection: start the host in the Apassy sandbox. It uses the Apassy sandbox instead of the host's inner sandbox. Your host approval prompts stay active.",
    );
    kit::code_block(ui, &protected, 2);
    kit::note(
        ui,
        "4. Ask the agent to use a credential. The bouncer decides; when it asks you, the question shows in Decisions.",
    );
}

/// The manual MCP configuration for another host, with the token.
fn manual_config(ui: &mut egui::Ui, token: &str) {
    let adapter = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("apassy-mcp")))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "apassy-mcp".to_owned());
    let config = zeroize::Zeroizing::new(
        serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": { "apassy": { "command": adapter, "env": { "APASSY_AGENT_TOKEN": token } } }
        }))
        .unwrap_or_default(),
    );
    kit::code_block(ui, &config, 7);
    kit::note(
        ui,
        "Add this server to your host. Keep the token private. Give the host a tool time-out of at least 330 seconds: a question waits up to 5 minutes for you. Manual MCP setup does not install the prompt hook.",
    );
}

/// The token after "Connect" or a new token: Apassy saves the host settings at once
/// (ADR 0025 §2). For Other, the sheet shows the token and the MCP configuration one
/// time. Escape does not discard the one-time token.
pub(super) fn draw_fresh_token(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(fresh) = &app.owner_ui.fresh_token else {
        return;
    };
    app.ui.agent_setup.prepare(
        fresh.token.expose(),
        if fresh.rotated { "" } else { &fresh.agent_name },
        &mut app.ui.setup_host,
    );
    let (host, start_now) = agent_onboarding::token_shown(app);
    let Some(fresh) = &app.owner_ui.fresh_token else {
        return;
    };
    let token = zeroize::Zeroizing::new(fresh.token.expose().to_owned());
    let rotated = fresh.rotated;
    let title = format!("Connect {}", fresh.agent_name);
    // The settings are saved at once after the check, in the app only: a test never
    // writes host settings.
    if start_now
        && !cfg!(test)
        && let Some(setup) = host.setup()
    {
        app.ui.setup_host = setup.index();
        app.ui.agent_setup.start(setup, &token, ctx);
    }
    app.ui.agent_setup.poll(ctx);
    let mut dismiss = false;
    let mut connect = false;
    let busy = app.ui.agent_setup.busy();
    let saved = app
        .ui
        .agent_setup
        .result
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .copied();
    let other = host == ConnectHost::Other;
    kit::sheet(ctx, "fresh-token", 480.0, |ui| {
        kit::sheet_title(
            ui,
            &title,
            Some(if other {
                "Use this token in the host. Apassy shows it one time."
            } else {
                "Apassy saves the settings of the host. There is nothing else to set."
            }),
        );
        kit::sheet_body(ui, |ui| {
            if rotated {
                kit::note(
                    ui,
                    "The old token does not work. Save the new settings for your host.",
                );
            }
            if other {
                let heading = ui.label(kit::text("Token", Font::Headline).color(kit::LABEL));
                kit::code_block(ui, &token, 1).labelled_by(heading.id);
                manual_config(ui, &token);
                kit::note(
                    ui,
                    "For the command line on another computer, set APASSY_AGENT_TOKEN to this token.",
                );
                return;
            }
            if saved.is_some() {
                kit::tone_note(ui, "Connection settings saved.", Tone::Good);
                agent_onboarding::after_setup_notes(ui, host);
                kit::note(
                    ui,
                    "Saved settings do not prove a connection. Check it in the host.",
                );
            } else {
                let setup = super::agent_setup::Host::from_index(app.ui.setup_host);
                ui.add_enabled_ui(!busy, |ui| {
                    kit::picker(
                        ui,
                        "fresh-setup-host",
                        &mut app.ui.setup_host,
                        &[(0, "Claude Code".to_owned()), (1, "Codex".to_owned())],
                        setup.name(),
                        200.0,
                    );
                });
                kit::note(
                    ui,
                    "Apassy keeps a copy of changed host settings. This step does not check the connection.",
                );
                if busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        kit::note(ui, "Please wait. Apassy saves the host settings.");
                    });
                }
                if let Some(Err(error)) = &app.ui.agent_setup.result {
                    kit::tone_note(ui, error, Tone::Critical);
                }
            }
            ui.add_space(12.0);
            kit::disclosure(ui, &mut app.ui.agent_setup.advanced, "Advanced setup");
            if app.ui.agent_setup.advanced {
                kit::note(ui, "Apassy shows this token one time. Keep it private.");
                let heading = ui.label(kit::text("Token", Font::Headline).color(kit::LABEL));
                kit::code_block(ui, &token, 1).labelled_by(heading.id);
                ui.add_enabled_ui(!busy, |ui| setup_guidance(&mut app.ui, ui));
                let mut manual = app.ui.is_expanded("manual-mcp-config");
                kit::disclosure(ui, &mut manual, "Other hosts: manual MCP configuration");
                app.ui.set_expanded("manual-mcp-config", manual);
                if manual {
                    manual_config(ui, &token);
                }
                if saved.is_none() {
                    ui.add_enabled_ui(!busy, |ui| {
                        dismiss = kit::button(ui, "I saved the token", Style::Link).clicked();
                    });
                }
            }
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if saved.is_some() || other {
                    dismiss = kit::button(ui, "Done", Style::Prominent).clicked();
                } else {
                    let setup = super::agent_setup::Host::from_index(app.ui.setup_host);
                    ui.add_enabled_ui(!busy, |ui| {
                        connect =
                            kit::button(ui, &format!("Connect {}", setup.name()), Style::Prominent)
                                .clicked();
                    });
                }
            },
        );
    });
    if connect {
        app.ui.agent_setup.start(
            super::agent_setup::Host::from_index(app.ui.setup_host),
            &token,
            ctx,
        );
    }
    if dismiss {
        app.owner_ui.fresh_token = None;
        app.ui.agent_setup = Default::default();
        app.ui.agent_onboarding.shown = None;
        app.place = Place::Agents;
        app.set_ok(if saved.is_some() || other {
            "The agent is connected. The bouncer decides each use; a question shows in Decisions."
        } else {
            "The token is hidden. Apassy cannot show it again."
        });
    }
}

/// "Disconnect AGENT…": its token stops working. It takes authority away, so it needs no
/// owner check.
pub(super) fn revoke_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    agent_id: u64,
    name: &str,
) -> bool {
    let mut revoke = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "revoke-agent", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Disconnect {name}?"),
            Some("Its token stops working at once. You can connect the agent again later."),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                revoke = kit::button(ui, "Disconnect", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if revoke {
        let message = format!("{name} is disconnected. Its token does not work.");
        let result = app.owner_ui.session.revoke_agent(agent_id);
        if app.apply(result, &message).is_some() {
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sees_tells_the_whole_catalog_from_a_list_of_credentials() {
        assert_eq!(sees_words(None), "Credential names, never values");
        assert_eq!(sees_words(Some(0)), "No credentials yet");
        assert_eq!(sees_words(Some(1)), "Only 1 credential, never values");
        assert_eq!(sees_words(Some(3)), "Only 3 credentials, never values");
    }

    #[test]
    fn an_action_row_shows_the_allowed_uses_the_projects_and_the_rest_apart() {
        use crate::broker::action_kind::ActionKind;
        let action = |allowed, not_allowed, projects: &[&str]| ActionUse {
            action: ActionKind::Deploy,
            allowed,
            not_allowed,
            projects: projects.iter().map(|p| (*p).to_owned()).collect(),
        };
        assert_eq!(
            action_value(&action(3, 0, &["acme-billing", "apassy"])),
            ("3 · acme-billing, apassy".to_owned(), None)
        );
        assert_eq!(
            action_value(&action(2, 1, &["apassy"])),
            ("2 · apassy".to_owned(), Some("1 not allowed".to_owned()))
        );
        assert_eq!(
            action_value(&action(0, 2, &[])),
            (String::new(), Some("2 not allowed".to_owned()))
        );
        assert_eq!(
            action_value(&action(5, 0, &["a", "b", "c", "d", "e"])).0,
            "5 · a, b, c, and 2 more"
        );
    }

    #[test]
    fn a_recent_use_names_its_action_and_project() {
        use crate::broker::action_kind::ActionKind;
        use crate::vault::usage::{ItemUse, UseDecidedBy, UseOutcome};
        let mut recent = RecentUse {
            item_use: ItemUse {
                id: 1,
                at: 0,
                item_id: 1,
                agent_id: Some(1),
                agent_name: "Claude Code".to_owned(),
                project_key: "/code/apassy".to_owned(),
                project_label: "apassy".to_owned(),
                action: ActionKind::Delete,
                command_summary: String::new(),
                hosts: Vec::new(),
                outcome: UseOutcome::Denied,
                decided_by: UseDecidedBy::Owner,
                answered_on: String::new(),
                decision_log_id: None,
            },
            item_name: "Billing database".to_owned(),
        };
        assert_eq!(
            recent_words(&recent, "You denied it"),
            "Delete in apassy · You denied it"
        );
        recent.item_use.project_label.clear();
        assert_eq!(recent_words(&recent, "Denied"), "Delete · Denied");
    }

    #[test]
    fn a_short_date_has_the_year_only_for_another_year() {
        // 2026-10-09 12:00 UTC and 2025-12-31 12:00 UTC.
        let oct_9 = 1_791_547_200;
        let new_year_eve = 1_767_182_400;
        assert_eq!(short_date(oct_9, oct_9 + 86_400), "Oct 9");
        assert_eq!(short_date(new_year_eve, oct_9), "Dec 31, 2025");
    }

    #[test]
    fn the_token_line_tells_valid_from_expired() {
        let oct_9 = 1_791_547_200;
        let agent = AgentSummary {
            id: 1,
            name: "Claude Code".to_owned(),
            created_at: 0,
            revoked: false,
            token_issued_at: 0,
            token_expires_at: oct_9,
        };
        assert_eq!(token_words(&agent, oct_9 - 60), "Token valid until Oct 9");
        assert_eq!(token_words(&agent, oct_9 + 60), "Token expired Oct 9");
    }

    #[test]
    fn the_known_hosts_have_the_colors_of_the_mockup() {
        let orange = egui::Color32::from_rgb(217, 119, 87);
        assert_eq!(kit::agent_color("Claude Code"), orange);
        assert_eq!(kit::agent_color("claude-code"), orange);
        assert_eq!(
            kit::agent_color("Codex"),
            egui::Color32::from_rgb(16, 163, 127)
        );
        assert_eq!(
            kit::agent_color("T3 Code"),
            egui::Color32::from_rgb(110, 90, 230)
        );
        assert_eq!(
            kit::agent_color("CI on GitHub"),
            egui::Color32::from_rgb(36, 41, 47)
        );
    }
}
