//! Agents (implementation-plan-bouncer-section §5; ADR 0026 §2, ADR 0025 §3f), the vault
//! build: one wide page with the agents of every Mac of the vault in the scope of the bar,
//! and the page of one agent ([`super::agents_page`] draws both).
//!
//! The page reads the Bouncer cache (`bouncer_load`, at most once per 2 seconds) and the
//! copy of the remote access block (`DesktopApp::poll_remote_access`, on a worker thread):
//! a frame reads no vault for the table and never runs the Tailscale command line. The
//! open agent page of this Mac reads its facts (what it can see, its note) once per
//! change of the window ([`FactsCache`]).
//!
//! - The remote access switch: on asks Touch ID (`OwnerRequest::TurnOnRemoteAccess`), off
//!   needs nothing. A problem has one line and one button: "Get Tailscale…", "Check
//!   Again", "Open Admin Console…", or "Use Port 10000".
//! - "Choose Credentials…" opens a sheet of the credentials: an added one gives access, so
//!   the owner check (`OwnerRequest::ChooseAgentItems`) comes first; a removed one goes at
//!   once. The node then sends the new list to a remote agent (`Node::sync_catalog`).
//! - "Disconnect…" opens one sheet for both kinds: a local agent is revoked in the vault,
//!   a remote one also on the node (`Node::revoke_agent`). No owner check: it takes
//!   authority away.
//! - "+" opens "Connect an Agent" ([`super::agent_onboarding`]), for agents of this Mac.
//!   Remote agents connect by themselves.

use eframe::egui::{self, Label};

use super::agent_onboarding::{self, ConnectHost};
use super::agents_page::{
    self, AccessProblem, AccessView, Action, AgentPage, AgentsView, CanSee, LocalFacts,
    ProblemButton, SeeKind, SeeRow,
};
use super::bouncer::{self, AgentRef, DeviceScope};
use super::kit::{self, Font, Icon, Style, Tone};
use super::{Sheet, close_sheet};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{DesktopApp, Place};
use crate::vault::AgentSummary;
use crate::vault::exceptions::{ExceptionKind, MAX_AGENT_NOTE_BYTES};

mod remote;

pub(super) use remote::connected as remote_connected;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The state of the vault build: the note that the owner edits, the facts of the open
/// agent page, and the choice of the "Choose Credentials…" sheet.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The agent of the note field and its text.
    pub(super) note: Option<(u64, String)>,
    pub(super) facts: FactsCache,
    /// "Choose Credentials…": the agent, the credentials it may use when the sheet
    /// opened, and the ones the owner chose.
    pub(super) choosing: Option<Choosing>,
}

/// The choice of the "Choose Credentials…" sheet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Choosing {
    pub(super) agent_id: u64,
    pub(super) before: std::collections::BTreeSet<u64>,
    pub(super) chosen: std::collections::BTreeSet<u64>,
    pub(super) search: String,
}

/// The facts of the open agent page of this Mac, read again only when the window
/// changed something (the status stamp) or another agent opens.
#[derive(Debug, Default)]
pub(crate) struct FactsCache {
    key: Option<(u64, u64)>,
    facts: Option<LocalFacts>,
    /// How many times the facts were read (a test counts them).
    pub(super) reads: u64,
}

/// The open agent page: the one of the page state, or an agent of this Mac that another
/// view selected (`owner_ui.selected_agent`, as "Connect an Agent" does).
pub(super) fn open_agent(app: &DesktopApp) -> Option<AgentRef> {
    app.ui
        .agent_page
        .open
        .clone()
        .or_else(|| app.owner_ui.selected_agent.map(AgentRef::Local))
}

/// Open the page of `agent`, or close the open page with `None`.
pub(super) fn set_open(app: &mut DesktopApp, agent: Option<AgentRef>) {
    app.owner_ui.selected_agent = match &agent {
        Some(AgentRef::Local(id)) => Some(*id),
        _ => None,
    };
    app.ui.agent_page.open = agent;
    app.ui.agent_page.note_open = None;
}

/// The wide pane of Agents: the page of the open agent, or the page of all agents.
pub(super) fn wide_pane(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &super::shell::Pending) {
    let ctx = ui.ctx().clone();
    app.poll_remote_access(&ctx);
    let now = now();
    let offset = bouncer::local_offset(now);
    if let Some(agent) = open_agent(app) {
        let facts = match &agent {
            AgentRef::Local(id) => local_facts(app, *id),
            AgentRef::Other { .. } => None,
        };
        let page = AgentPage::of(&app.ui.bouncer.data, &agent, facts.as_ref(), now, offset).map(
            |mut page| {
                page.note = other_note(app, &agent);
                page
            },
        );
        let Some(page) = page else {
            // The agent or its Mac is gone.
            set_open(app, None);
            ctx.request_repaint();
            return;
        };
        let mut action = None;
        super::columns::wide_toolbar(ui, "", "", |ui| {
            if let Some(chosen) = agent_menu(ui, &page, facts.as_ref()) {
                action = Some(chosen);
            }
        });
        let back = super::columns::wide_inset(ui, |ui| kit::back_link(ui, "Agents"));
        if back {
            action = Some(Action::Back);
        }
        super::columns::wide_body(ui, ("agent-page", &agent), |ui| {
            super::shell::banners(app, ui, pending);
            if let Some(chosen) = agents_page::draw_agent(ui, &page, now) {
                action = Some(chosen);
            }
            if let (Some(id), Some(open)) = (page_local(&agent), app.ui.agent_page.note_open)
                && id == open
                && let Some(facts) = &facts
            {
                note_group(app, ui, id, &facts.note);
            }
        });
        if let Some(action) = action {
            apply(app, &ctx, action);
        }
        return;
    }
    let access = access_view(app);
    let view = AgentsView::of(
        &app.ui.bouncer.data,
        &app.ui.activity_scope,
        access,
        now,
        offset,
    );
    let subtitle = if view.count == 0 {
        String::new()
    } else {
        super::columns::count_label(view.count, "agent", "agents")
    };
    let mut action = None;
    super::columns::wide_toolbar(ui, "Agents", &subtitle, |ui| {
        if kit::plain_icon_button(ui, Icon::Plus, "Connect an Agent…").clicked() {
            action = Some(Action::ConnectAgent);
        }
    });
    let changed = super::columns::wide_inset(ui, |ui| {
        super::scope_bar::bouncer_bar(
            ui,
            &mut app.ui.activity_scope,
            &app.ui.bouncer.data.environments,
            &app.ui.bouncer.data.projects,
            now,
            offset,
        )
    });
    if changed {
        ctx.request_repaint();
    }
    super::columns::wide_body(ui, "bouncer-agents", |ui| {
        super::shell::banners(app, ui, pending);
        if let Some(chosen) = agents_page::draw_page(ui, &view, &app.ui.agent_page) {
            action = Some(chosen);
        }
    });
    if let Some(action) = action {
        apply(app, &ctx, action);
    }
}

fn page_local(agent: &AgentRef) -> Option<u64> {
    match agent {
        AgentRef::Local(id) => Some(*id),
        AgentRef::Other { .. } => None,
    }
}

/// "⋯" of an agent page: "Show in Logs", and for an agent of this Mac "Edit Note…",
/// "Reconnect with a New Token…" (a local agent), and "Disconnect…". The token line of a
/// token agent comes first; an agent that connected by itself has no end to show.
fn agent_menu(ui: &mut egui::Ui, page: &AgentPage, facts: Option<&LocalFacts>) -> Option<Action> {
    let mut action = None;
    let more = kit::toolbar_button(ui, Some(Icon::More), "", "More actions for this agent");
    egui::Popup::menu(&more).show(|ui| {
        ui.set_min_width(200.0);
        if let Some(words) = facts.and_then(|facts| token_words(facts.token_end, now())) {
            ui.label(kit::text(words, Font::Callout).color(kit::palette().secondary));
            ui.separator();
        }
        if ui.selectable_label(false, "Show in Logs").clicked() {
            action = Some(Action::ShowInLogs {
                env: page.agent.env(),
                name: page.name.clone(),
            });
        }
        if let Some(facts) = facts.filter(|facts| !facts.revoked) {
            if ui.selectable_label(false, "Edit Note…").clicked() {
                action = Some(Action::EditNote(facts.id));
            }
            if !facts.remote
                && ui
                    .selectable_label(false, "Reconnect with a New Token…")
                    .clicked()
            {
                action = Some(Action::Reconnect(facts.id));
            }
            if ui.selectable_label(false, "Disconnect…").clicked() {
                action = Some(Action::Disconnect(facts.id));
            }
        }
    });
    action
}

/// The token line of the "⋯" menu. `None` for a token without an end to show (an agent
/// that connected by itself: never "9999").
fn token_words(token_end: Option<u64>, now: u64) -> Option<String> {
    let end = token_end?;
    Some(if now >= end {
        format!("Token expired {}", kit::relative_time(end, now))
    } else {
        format!("Token valid until {}", kit::day_month_year(end))
    })
}

/// The note of an agent of another Mac, from its feed (read-only).
fn other_note(app: &DesktopApp, agent: &AgentRef) -> String {
    let AgentRef::Other { device, id } = agent else {
        return String::new();
    };
    remote::find(&app.remote_macs, &(device.clone(), id.clone()))
        .map(|found| remote::plain(found.agent.note.trim()))
        .unwrap_or_default()
}

/// The facts of an agent of this Mac for its page, read once per change of the window.
fn local_facts(app: &mut DesktopApp, agent_id: u64) -> Option<LocalFacts> {
    let stamp = bouncer::stamp((app.owner_ui.session.epoch(), app.status_seq));
    let key = Some((agent_id, stamp));
    if app.ui.agents.facts.key == key {
        return app.ui.agents.facts.facts.clone();
    }
    let facts = read_facts(app, agent_id);
    let cache = &mut app.ui.agents.facts;
    cache.key = key;
    cache.facts = facts.clone();
    cache.reads += 1;
    facts
}

fn read_facts(app: &DesktopApp, agent_id: u64) -> Option<LocalFacts> {
    let agent = app
        .owner_ui
        .session
        .agents()
        .ok()?
        .into_iter()
        .find(|agent| agent.id == agent_id)?;
    app.owner_ui.session.with_vault(|vault| {
        let link = vault.cloud_agent_link(agent_id).ok().flatten();
        let remote = link.is_some()
            || vault
                .cloud_agent_ids()
                .is_ok_and(|ids| ids.contains(&agent_id));
        let oauth = link
            .as_ref()
            .is_some_and(|(_, with)| *with == crate::vault::ConnectedWith::OAuth);
        let titles = vault.item_refs().unwrap_or_default();
        let name = |item: u64| {
            titles.get(&item).map_or_else(
                || "A deleted credential".to_owned(),
                |item| bouncer::clip(&item.title),
            )
        };
        let visible = vault.visible_items_for_agent(agent_id).ok().flatten();
        let mut rows: Vec<SeeRow> = visible
            .iter()
            .flatten()
            .map(|item| SeeRow {
                item: *item,
                name: name(*item),
                kind: SeeKind::Only,
            })
            .collect();
        rows.sort_by_key(|row| row.name.to_lowercase());
        let mut stricter: Vec<SeeRow> = vault
            .agent_exceptions(agent_id)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|exception| {
                let kind = match exception.kind {
                    ExceptionKind::Never => SeeKind::Never,
                    ExceptionKind::AlwaysAsk => SeeKind::AlwaysAsk,
                    ExceptionKind::Only => return None,
                };
                Some(SeeRow {
                    item: exception.item_id,
                    name: name(exception.item_id),
                    kind,
                })
            })
            .collect();
        stricter.sort_by(|a, b| {
            (a.kind == SeeKind::AlwaysAsk)
                .cmp(&(b.kind == SeeKind::AlwaysAsk))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        rows.extend(stricter);
        LocalFacts {
            id: agent.id,
            name: agent.name.clone(),
            remote,
            revoked: agent.revoked,
            created_at: agent.created_at,
            token_end: bouncer::shown_token_end(agent.token_expires_at),
            oauth,
            can_see: CanSee {
                all: visible.is_none(),
                rows,
            },
            note: vault.agent_note(agent_id).unwrap_or_default(),
        }
    })
}

/// The remote access block of this Mac from the copy of the last read. `None`: this
/// build has no node.
fn access_view(app: &DesktopApp) -> Option<AccessView> {
    app.cloud_node()?;
    let Some(status) = app.remote_access_cached() else {
        return Some(AccessView {
            on: app.ui.bouncer.data.remote_access_on,
            address: None,
            problem: None,
            no_remote_agents: false,
            reading: true,
        });
    };
    Some(access_of(status, app.remote_agents_cached().is_empty()))
}

/// The block for a status of the node (the problems of frames 8a–8d).
pub(super) fn access_of(status: &crate::node::NodeStatus, no_remote_agents: bool) -> AccessView {
    use crate::node::RouteProblem;
    use crate::node::funnel::Tailscale;
    let problem = match &status.problem {
        Some(RouteProblem::NoTailscale) => Some(AccessProblem::NotInstalled),
        Some(RouteProblem::NotConnected) => Some(AccessProblem::NotConnected),
        Some(RouteProblem::Policy { link }) => Some(AccessProblem::Policy { link: link.clone() }),
        Some(RouteProblem::PortTaken { alternative }) => Some(AccessProblem::PortTaken {
            port: status.funnel_port,
            alternative: *alternative,
        }),
        Some(RouteProblem::HttpsPublic) => Some(AccessProblem::HttpsPublic),
        Some(RouteProblem::Failed(message)) => Some(AccessProblem::Failed(message.clone())),
        // Off: Tailscale must be there before the switch goes on.
        None if !status.route_on => match status.tailscale {
            Tailscale::Missing => Some(AccessProblem::NotInstalled),
            Tailscale::NotConnected { .. } => Some(AccessProblem::NotConnected),
            Tailscale::Connected { .. } => None,
        },
        None => None,
    };
    AccessView {
        on: status.route_on,
        address: status.url.clone().filter(|_| status.route_on),
        problem,
        no_remote_agents: status.route_on && no_remote_agents,
        reading: false,
    }
}

/// Do what the owner chose.
fn apply(app: &mut DesktopApp, ctx: &egui::Context, action: Action) {
    match action {
        Action::Open(agent) => set_open(app, Some(agent)),
        Action::Back => set_open(app, None),
        Action::ConnectAgent => agent_onboarding::open(app),
        Action::RemoteAccess(true) => app.ask_remote_access_on(Some(ctx)),
        Action::RemoteAccess(false) => {
            app.remote_access_off();
            app.node_changed();
        }
        Action::CopyAddress(address) => {
            // The address is no secret: it names this Mac, not a credential.
            ctx.copy_text(address);
            app.set_ok("The MCP address is copied. Give it to the remote agent.");
        }
        Action::Problem(ProblemButton::GetTailscale) => {
            open_link(app, agents_page::TAILSCALE_DOWNLOAD);
        }
        Action::Problem(ProblemButton::AdminConsole(link)) => open_link(app, &link),
        Action::Problem(ProblemButton::CheckAgain) => app.check_remote_access_again(),
        Action::Problem(ProblemButton::UsePort(port)) => app.use_funnel_port(port),
        Action::ToggleDisconnected(scope) => {
            let open = &mut app.ui.agent_page.disconnected;
            if !open.remove(&scope) {
                open.insert(scope);
            }
        }
        Action::ShowAllEnvironments => app.ui.activity_scope.device = DeviceScope::All,
        Action::ShowAllProjects => app.ui.activity_scope.project = None,
        Action::ChooseCredentials(agent_id) => open_choose(app, agent_id),
        Action::RemoveSee { agent, item, kind } => remove_see(app, ctx, agent, item, kind),
        Action::Disconnect(agent_id) => {
            let name = agent_name(app, agent_id);
            app.ui.sheet = Some(Sheet::RevokeAgent { agent_id, name });
        }
        Action::ShowInLogs { env, name } => {
            app.ui.activity_scope.device = env;
            super::logs::show_agent(app, Some(name));
            super::sidebar::navigate(app, Place::Logs);
        }
        Action::EditNote(agent_id) => app.ui.agent_page.note_open = Some(agent_id),
        Action::Reconnect(agent_id) => {
            let name = agent_name(app, agent_id);
            agent_onboarding::reconnect(app, ctx, &name);
        }
    }
}

fn agent_name(app: &DesktopApp, agent_id: u64) -> String {
    app.owner_ui
        .session
        .agents()
        .ok()
        .and_then(|agents| agents.into_iter().find(|agent| agent.id == agent_id))
        .map_or_else(|| "this agent".to_owned(), |agent| agent.name)
}

/// Open a page of Tailscale in the browser. Only these fixed `https` pages and the link
/// of Tailscale's own message.
fn open_link(app: &mut DesktopApp, url: &str) {
    if !url.starts_with("https://") {
        return;
    }
    #[cfg(test)]
    {
        OPENED.with(|opened| opened.borrow_mut().push(url.to_owned()));
        let _ = app;
    }
    #[cfg(not(test))]
    {
        let spawned = std::process::Command::new("/usr/bin/open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match spawned {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(_) => app.set_err("The page cannot be opened."),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The pages that the tests opened.
    pub(super) static OPENED: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Remove a row of "Can see". A listed item goes at once: the agent sees less. "Never"
/// and "Always ask" give authority back: the owner check first.
fn remove_see(app: &mut DesktopApp, ctx: &egui::Context, agent_id: u64, item: u64, kind: SeeKind) {
    let kind = match kind {
        SeeKind::Only => ExceptionKind::Only,
        SeeKind::Never => ExceptionKind::Never,
        SeeKind::AlwaysAsk => ExceptionKind::AlwaysAsk,
    };
    let Some(agent) = app
        .owner_ui
        .session
        .agents()
        .ok()
        .and_then(|agents| agents.into_iter().find(|agent| agent.id == agent_id))
    else {
        return;
    };
    let exception = crate::vault::exceptions::AgentException {
        agent_id,
        item_id: item,
        kind,
        created_at: 0,
    };
    remove_exception(app, ctx, &agent, &exception);
    if kind == ExceptionKind::Only {
        app.sync_remote_catalog();
    }
}

// ---- "Choose Credentials…". ----

/// Open the sheet with the credentials that the agent may use now.
fn open_choose(app: &mut DesktopApp, agent_id: u64) {
    let before: std::collections::BTreeSet<u64> = app
        .owner_ui
        .session
        .with_vault(|vault| vault.visible_items_for_agent(agent_id))
        .and_then(Result::ok)
        .flatten()
        .unwrap_or_default();
    app.ui.agents.choosing = Some(Choosing {
        agent_id,
        chosen: before.clone(),
        before,
        search: String::new(),
    });
    let name = agent_name(app, agent_id);
    app.ui.sheet = Some(Sheet::ChooseCredentials { agent_id, name });
}

/// What a save of the sheet changes: the credentials to add (the owner check) and to
/// remove (none).
pub(super) fn choose_changes(choosing: &Choosing) -> (Vec<u64>, Vec<u64>) {
    let add = choosing
        .chosen
        .difference(&choosing.before)
        .copied()
        .collect();
    let remove = choosing
        .before
        .difference(&choosing.chosen)
        .copied()
        .collect();
    (add, remove)
}

/// Save the choice: remove at once, then ask the owner for the added ones. With nothing
/// added the sheet closes now; else after the check.
pub(super) fn save_choice(app: &mut DesktopApp, ctx: &egui::Context, agent_id: u64, name: &str) {
    let Some(choosing) = app
        .ui
        .agents
        .choosing
        .clone()
        .filter(|c| c.agent_id == agent_id)
    else {
        return;
    };
    let (add, remove) = choose_changes(&choosing);
    for item in &remove {
        if let Err(error) = app.owner_ui.session.remove_listed_item(agent_id, *item) {
            app.set_err(error.message);
            return;
        }
    }
    if add.is_empty() {
        app.sync_remote_catalog();
        app.ui.agents.choosing = None;
        app.ui.sheet = None;
        app.set_ok(if remove.is_empty() {
            "Nothing changed.".to_owned()
        } else {
            format!("{name} no longer sees the removed credentials.")
        });
        return;
    }
    super::ask_owner_from_sheet(
        app,
        OwnerRequest::ChooseAgentItems {
            agent_id,
            agent_name: name.to_owned(),
            add,
        },
        ctx,
    );
}

/// The sheet of "Choose Credentials…": a search field and the active credentials, each
/// with a check box. The agent sees the names of the chosen ones, never their values.
pub(super) fn choose_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    agent_id: u64,
    name: &str,
) -> bool {
    if app
        .ui
        .agents
        .choosing
        .as_ref()
        .is_none_or(|choosing| choosing.agent_id != agent_id)
    {
        open_choose(app, agent_id);
    }
    let items = app.owner_ui.session.search("").unwrap_or_default();
    let archived = app.owner_ui.session.archived().unwrap_or_default();
    let mut save = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "choose-credentials", 460.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Choose What {name} Can See"),
            Some("It sees the names, never the values. Every use still asks the bouncer."),
        );
        kit::sheet_body(ui, |ui| {
            let Some(choosing) = app.ui.agents.choosing.as_mut() else {
                return;
            };
            kit::search_field(
                ui,
                &mut choosing.search,
                "choose-credentials-search",
                "Search",
            );
            ui.add_space(6.0);
            let needle = choosing.search.trim().to_lowercase();
            let shown: Vec<_> = items
                .iter()
                .filter(|item| !archived.contains_key(&item.id))
                .filter(|item| needle.is_empty() || item.name.to_lowercase().contains(&needle))
                .collect();
            egui::ScrollArea::vertical()
                .id_salt("choose-credentials-list")
                .max_height(320.0)
                .show(ui, |ui| {
                    kit::section(ui, None, None, |s| {
                        if shown.is_empty() {
                            s.row(|ui| kit::note(ui, "No credential matches."));
                        }
                        for item in &shown {
                            let mut on = choosing.chosen.contains(&item.id);
                            s.row(|ui| {
                                ui.horizontal(|ui| {
                                    kit::tile(
                                        ui,
                                        &super::credential_tile(
                                            item.kind,
                                            &item.service,
                                            &item.name,
                                        ),
                                        20.0,
                                    );
                                    ui.add(
                                        Label::new(
                                            kit::text(&item.name, Font::Body)
                                                .color(kit::palette().label),
                                        )
                                        .truncate(),
                                    );
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if kit::toggle(ui, &mut on, &item.name).changed() {
                                                if on {
                                                    choosing.chosen.insert(item.id);
                                                } else {
                                                    choosing.chosen.remove(&item.id);
                                                }
                                            }
                                        },
                                    );
                                });
                            });
                        }
                    });
                });
            let (add, _) = choose_changes(choosing);
            if !add.is_empty() {
                kit::note(ui, "Adding credentials asks for Touch ID.");
            }
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                save = kit::button(ui, "Save", Style::Prominent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if save {
        save_choice(app, ctx, agent_id, name);
    }
    if cancel {
        app.ui.agents.choosing = None;
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Edit Note…": the note for the bouncer, a hint, not a limit (ADR 0025 §3f). Saving it
/// needs no check.
fn note_group(app: &mut DesktopApp, ui: &mut egui::Ui, agent_id: u64, saved: &str) {
    let state = &mut app.ui.agents;
    if state.note.as_ref().is_none_or(|(id, _)| *id != agent_id) {
        state.note = Some((agent_id, saved.to_owned()));
    }
    let mut save = false;
    {
        let Some((_, text)) = state.note.as_mut() else {
            return;
        };
        kit::group_heading(ui, "Note for the bouncer", None, "");
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
        if text.trim() != saved.trim() {
            ui.add_space(6.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
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
                        kit::palette().secondary
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
                let heading =
                    ui.label(kit::text("Token", Font::Headline).color(kit::palette().label));
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
                let heading =
                    ui.label(kit::text("Token", Font::Headline).color(kit::palette().label));
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

/// Disconnect an agent after its sheet: a remote agent on the node too
/// (`Node::revoke_agent`: the vault, the relay agent, its refresh family, its open
/// requests), a local one in the vault. Returns true when it is disconnected.
pub(super) fn disconnect_agent(
    app: &mut DesktopApp,
    agent_id: u64,
    name: &str,
    remote: bool,
) -> bool {
    if remote && app.cloud_node().is_some() {
        app.disconnect_remote_agent(agent_id);
        return app.status_kind == crate::desktop::StatusKind::Ok;
    }
    let message = format!("{name} is disconnected. Its token does not work.");
    let result = app.owner_ui.session.revoke_agent(agent_id);
    app.apply(result, &message).is_some()
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
    // A remote agent is revoked on the node too: its access and its refresh end.
    let remote = app
        .owner_ui
        .session
        .with_vault(|vault| vault.cloud_agent_ids())
        .and_then(Result::ok)
        .is_some_and(|ids| ids.contains(&agent_id));
    let response = kit::sheet(ctx, "revoke-agent", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Disconnect {name}?"),
            Some(if remote {
                "Its access stops at once. To come back it must connect again and be allowed."
            } else {
                "Its token stops working at once. You can connect the agent again later."
            }),
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
    if revoke && disconnect_agent(app, agent_id, name, remote) {
        app.ui.sheet = None;
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
    fn the_token_line_tells_valid_from_expired_and_hides_the_far_end() {
        let oct_9 = 1_791_547_200;
        // The days of the page read as `kit::relative_time` does: "9 Oct 2026".
        assert_eq!(
            token_words(Some(oct_9), oct_9 - 60).as_deref(),
            Some("Token valid until 9 Oct 2026")
        );
        assert_eq!(
            token_words(Some(oct_9), oct_9 + 60).as_deref(),
            Some("Token expired 1 min ago")
        );
        assert_eq!(
            token_words(Some(oct_9), oct_9 + 8 * 86_400).as_deref(),
            Some("Token expired 9 Oct 2026")
        );
        // An agent that connected by itself has the far end of the vault: no line, never
        // "31 Dec 9999".
        let far = bouncer::shown_token_end(crate::node::NO_TOKEN_EXPIRY);
        assert_eq!(far, None);
        assert_eq!(token_words(far, oct_9), None);
        assert_eq!(bouncer::NO_TOKEN_END, crate::node::NO_TOKEN_EXPIRY);
    }

    #[test]
    fn a_choice_of_credentials_adds_with_the_check_and_removes_without() {
        let choosing = Choosing {
            agent_id: 7,
            before: [1, 2].into_iter().collect(),
            chosen: [2, 3, 4].into_iter().collect(),
            search: String::new(),
        };
        assert_eq!(choose_changes(&choosing), (vec![3, 4], vec![1]));
        let same = Choosing {
            chosen: choosing.before.clone(),
            ..choosing
        };
        assert_eq!(choose_changes(&same), (Vec::new(), Vec::new()));
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
