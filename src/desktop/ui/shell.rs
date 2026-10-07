//! The window frame: the sidebar, the page area, and the sheets.

use eframe::egui::{self, Align, Frame, Layout, Margin, Pos2, Rect, ScrollArea, Vec2};

use super::Sheet;
#[cfg(not(feature = "vault"))]
use super::close_sheet;
use super::kit::{self, Icon, Style, Tone};
use crate::desktop::{DesktopApp, OwnerView};

const SIDEBAR_WIDTH: f32 = 216.0;
/// The reading width of a page.
const PAGE_WIDTH: f32 = 760.0;

#[cfg(feature = "vault")]
type Pending = Vec<crate::broker::approvals::PendingRun>;
#[cfg(not(feature = "vault"))]
type Pending = ();

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    #[cfg(feature = "vault")]
    let pending = watch_approvals(app, ui.ctx());
    #[cfg(feature = "vault")]
    shortcuts(app, &ui.ctx().clone());
    #[cfg(not(feature = "vault"))]
    let pending = ();
    if !app.ui.sidebar_hidden {
        egui::Panel::left("apassy-sidebar")
            .resizable(false)
            .exact_size(SIDEBAR_WIDTH)
            .show_separator_line(true)
            .frame(Frame::NONE.fill(kit::SIDEBAR).inner_margin(Margin {
                left: 10,
                right: 10,
                top: 0,
                bottom: 12,
            }))
            .show(ui, |ui| sidebar(app, ui, &pending));
    }
    egui::CentralPanel::default()
        .frame(Frame::NONE.fill(kit::WINDOW))
        .show(ui, |ui| content(app, ui, &pending));
    sidebar_toggle(app, &ui.ctx().clone());
    sheets(app, &ui.ctx().clone());
}

/// The sidebar button in the title bar, right of the window buttons, as in a macOS
/// window. It stays at the same place when the sidebar hides, so the owner finds it
/// again. ⌃⌘S does the same.
fn sidebar_toggle(app: &mut DesktopApp, ctx: &egui::Context) {
    // The window buttons end at 70 points; the title bar is 38 points high.
    let name = if app.ui.sidebar_hidden {
        "Show sidebar  ⌃⌘S"
    } else {
        "Hide sidebar  ⌃⌘S"
    };
    let clicked = egui::Area::new(egui::Id::new("apassy-sidebar-toggle"))
        .fixed_pos(Pos2::new(80.0, 3.0))
        .show(ctx, |ui| {
            kit::title_bar_button(ui, Icon::Sidebar, name).clicked()
        })
        .inner;
    if clicked {
        app.ui.toggle_sidebar();
    }
}

/// Window shortcuts. They act only when no sheet, alert, token, or owner check is open,
/// except ⌘L.
///
/// - ⌘1 to ⌘4: Credentials, Agents, Activity, Learning. ⌘,: Settings.
/// - ⌘[: back from a credential or an agent to its list.
/// - ⌘N: a new credential.
/// - ⌘F: search the credentials.
/// - ⌘⇧H: show or hide the secret values of the open credential. ⌘H stays the macOS
///   shortcut for "Hide Apassy": the app menu takes it before the window.
/// - ⌘L: lock the vault, also with a sheet open, but not during an owner check.
/// - ⌃⌘S: hide or show the sidebar.
///
/// Tab and Shift-Tab move the focus, and the page scrolls to it. Space or Return
/// presses the focused control. Page Up, Page Down, Home, and End scroll the page.
#[cfg(feature = "vault")]
fn shortcuts(app: &mut DesktopApp, ctx: &egui::Context) {
    use eframe::egui::{Key, Modifiers};

    if app.owner.check.is_none() && kit::shortcut(ctx, Modifiers::COMMAND, Key::L) {
        app.lock_vault(Some(ctx));
        return;
    }
    let busy = app.ui.sheet.is_some()
        || app.pending_delete
        || app.owner_ui.fresh_token.is_some()
        || app.owner.check.is_some()
        || app.learning.inspected.is_some();
    if busy {
        return;
    }
    // Before ⌘ alone: ⌃⌘S must not reach a ⌘S handler.
    if kit::shortcut(ctx, Modifiers::COMMAND | Modifiers::CTRL, Key::S) {
        app.ui.toggle_sidebar();
        return;
    }
    let views = [
        (Key::Num1, OwnerView::Vault),
        (Key::Num2, OwnerView::Agents),
        (Key::Num3, OwnerView::Activity),
        (Key::Num4, OwnerView::Learning),
        (Key::Comma, OwnerView::Settings),
    ];
    for (key, view) in views {
        if kit::shortcut(ctx, Modifiers::COMMAND, key) {
            navigate(app, view);
            app.ui.focus.focus_page_start();
            return;
        }
    }
    if kit::shortcut(ctx, Modifiers::COMMAND | Modifiers::SHIFT, Key::H) {
        if app.view == OwnerView::Item {
            super::items::toggle_masking(app, ctx);
        }
    } else if kit::shortcut(ctx, Modifiers::COMMAND, Key::OpenBracket) {
        if app.view == OwnerView::Item {
            app.view = OwnerView::Vault;
            app.ui.focus.focus_page_start();
        } else if app.view == OwnerView::Agents && app.owner_ui.selected_agent.is_some() {
            app.owner_ui.selected_agent = None;
            app.ui.focus.focus_page_start();
        }
    } else if kit::shortcut(ctx, Modifiers::COMMAND, Key::N) {
        app.view = OwnerView::Vault;
        super::items::open_add(app);
    } else if kit::shortcut(ctx, Modifiers::COMMAND, Key::F) {
        app.view = OwnerView::Vault;
        app.ui.focus_search = true;
    }
}

/// Runs that wait for the owner. A new run asks macOS for attention. A broker thread
/// can add a run at any time, so the window checks again soon.
#[cfg(feature = "vault")]
fn watch_approvals(app: &mut DesktopApp, ctx: &egui::Context) -> Pending {
    let crate::desktop::BrokerState::Running(handle) = &app.broker else {
        return Vec::new();
    };
    ctx.request_repaint_after(std::time::Duration::from_millis(500));
    let pending = handle.approvals().pending();
    if pending
        .iter()
        .any(|run| !app.owner_ui.signaled_runs.contains(&run.id))
    {
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
            egui::UserAttentionType::Critical,
        ));
    }
    app.owner_ui.signaled_runs = pending.iter().map(|run| run.id).collect();
    pending
}

/// The views in the sidebar list, with their icons.
fn primary_views() -> &'static [(OwnerView, Icon)] {
    #[cfg(feature = "vault")]
    {
        &[
            (OwnerView::Vault, Icon::Key),
            (OwnerView::Agents, Icon::Person),
            (OwnerView::Activity, Icon::Tray),
            (OwnerView::Learning, Icon::Chart),
        ]
    }
    #[cfg(not(feature = "vault"))]
    {
        &[
            (OwnerView::Vault, Icon::Key),
            (OwnerView::Rules, Icon::List),
            (OwnerView::Agents, Icon::Person),
            (OwnerView::Activity, Icon::Tray),
        ]
    }
}

/// Go to a view from the sidebar. A click on the current view goes back to its root.
pub(super) fn navigate(app: &mut DesktopApp, view: OwnerView) {
    app.view = view;
    #[cfg(feature = "vault")]
    if view == OwnerView::Agents {
        app.owner_ui.selected_agent = None;
    }
}

fn sidebar(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    let full = ui.max_rect();
    kit::window_drag_region(
        ui,
        Rect::from_min_max(
            Pos2::new(full.left() - 10.0, full.top()),
            Pos2::new(full.right() + 10.0, full.top() + kit::TITLE_BAR),
        ),
    );
    ui.add_space(kit::TITLE_BAR + 10.0);
    #[cfg(feature = "vault")]
    super::vaults::sidebar_switcher(app, ui);
    ui.spacing_mut().item_spacing.y = 2.0;
    for (index, (view, icon)) in primary_views().iter().enumerate() {
        let selected =
            app.view == *view || (*view == OwnerView::Vault && app.view == OwnerView::Item);
        let badge = badge(app, *view, pending);
        // The shortcut shows on hover, as in the menus of a macOS app.
        let hint = format!("{}  ⌘{}", view.label(), index + 1);
        if kit::sidebar_item(ui, *icon, view.label(), selected, badge)
            .on_hover_text(hint)
            .clicked()
        {
            navigate(app, *view);
        }
    }
    ui.with_layout(Layout::bottom_up(Align::Min), |ui| sidebar_footer(app, ui));
}

#[cfg(feature = "vault")]
fn badge(app: &DesktopApp, view: OwnerView, pending: &Pending) -> Option<kit::Badge> {
    let session = &app.owner_ui.session;
    match view {
        OwnerView::Vault => {
            // The count leaves out archived credentials, as the list does.
            let archived = session.archived().map_or(0, |archived| archived.len());
            session.search("").ok().map(|items| kit::Badge {
                count: items.len().saturating_sub(archived),
                tone: Tone::Neutral,
                what: "",
            })
        }
        OwnerView::Agents => {
            let expired = session
                .agents()
                .map_or(0, |agents| expired_tokens(&agents, kit::now()));
            Some(kit::Badge {
                count: expired,
                tone: Tone::Warning,
                what: if expired == 1 {
                    "token expired"
                } else {
                    "tokens expired"
                },
            })
        }
        OwnerView::Activity => {
            // Runs that wait, and access requests of agents (ADR 0012).
            let requests = session
                .access_requests(true)
                .map_or(0, |requests| requests.len());
            Some(kit::Badge {
                count: pending.len() + requests,
                tone: Tone::Warning,
                what: "waiting",
            })
        }
        _ => None,
    }
}

/// Active agents whose token expired. An expired token stops the agent until the owner
/// rotates it; a revoked agent needs nothing.
#[cfg(feature = "vault")]
pub(super) fn expired_tokens(agents: &[crate::vault::AgentSummary], now: u64) -> usize {
    agents
        .iter()
        .filter(|agent| !agent.revoked && agent.token_expired_at(now))
        .count()
}

#[cfg(not(feature = "vault"))]
fn badge(app: &DesktopApp, view: OwnerView, _pending: &Pending) -> Option<kit::Badge> {
    match view {
        OwnerView::Vault if !app.model.is_locked() => Some(kit::Badge {
            count: app.model.list_items("").len(),
            tone: Tone::Neutral,
            what: "",
        }),
        OwnerView::Activity => {
            let waiting = app
                .model
                .list_requests()
                .iter()
                .filter(|request| request.status == crate::desktop::RequestStatus::Pending)
                .count();
            Some(kit::Badge {
                count: waiting,
                tone: Tone::Warning,
                what: "waiting",
            })
        }
        _ => None,
    }
}

/// Settings. The lock is at the top, with the open vault it locks.
#[cfg(feature = "vault")]
fn sidebar_footer(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let selected = app.view == OwnerView::Settings;
    if kit::sidebar_item(ui, Icon::Gear, OwnerView::Settings.label(), selected, None)
        .on_hover_text("Settings  ⌘,")
        .clicked()
    {
        navigate(app, OwnerView::Settings);
    }
}

/// The demo notice, the lock controls, and "Reset demo".
#[cfg(not(feature = "vault"))]
fn sidebar_footer(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if kit::small_button(ui, "Reset demo", Style::Link).clicked() {
        app.reset_demo();
    }
    let locked = app.model.is_locked();
    let (label, icon) = if locked {
        ("Open vault", Icon::Key)
    } else {
        ("Lock vault", Icon::Lock)
    };
    if kit::button_with(ui, Some(icon), label, Style::Bordered, kit::Size::Small).clicked() {
        if locked {
            let result = app.model.unlock();
            let _ = app.apply(
                result,
                "The vault is open. This control is not owner authentication.",
            );
        } else {
            let result = app.model.lock();
            if app
                .apply(result, "The vault is locked. Item details are hidden.")
                .is_some()
            {
                app.pending_delete = false;
            }
        }
    }
    ui.add_space(4.0);
    kit::note(ui, app.model.lock_state_label());
    ui.add_space(8.0);
    kit::note(ui, crate::desktop::DEMO_BANNER);
    kit::tag(ui, "Demo", Tone::Warning);
}

fn content(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    let full = ui.max_rect();
    kit::window_drag_region(
        ui,
        Rect::from_min_size(full.min, Vec2::new(full.width(), kit::TITLE_BAR)),
    );
    ui.add_space(kit::TITLE_BAR + 6.0);
    let ctx = ui.ctx().clone();
    ScrollArea::vertical()
        .id_salt(("page", app.view))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            kit::column(ui, PAGE_WIDTH, |ui| {
                super::focus::page_start(&mut app.ui.focus, &ctx);
                // The scope keeps the IDs of the page the same when the banner comes
                // or goes, so the focus stays on its control.
                #[cfg(feature = "vault")]
                ui.scope(|ui| {
                    if app.view != OwnerView::Activity {
                        approval_banner(app, ui, pending);
                    }
                });
                #[cfg(feature = "vault")]
                ui.scope(|ui| super::updates::banner(app, ui));
                #[cfg(feature = "vault")]
                ui.scope(|ui| super::sync::banner(app, ui));
                page(app, ui, pending);
            });
            kit::follow_focus(ui);
            kit::keyboard_scroll(ui);
        });
}

#[cfg(feature = "vault")]
fn page(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    match app.view {
        OwnerView::Vault => super::items::draw_list(app, ui),
        OwnerView::Item => super::items::draw_detail(app, ui),
        OwnerView::Agents => super::agents::draw(app, ui),
        OwnerView::Activity => super::activity::draw(app, ui, pending),
        OwnerView::Learning => crate::desktop::learning_ui::draw(app, ui),
        OwnerView::Settings => super::settings::draw(app, ui),
    }
}

#[cfg(not(feature = "vault"))]
fn page(app: &mut DesktopApp, ui: &mut egui::Ui, _pending: &Pending) {
    match app.view {
        OwnerView::Vault => super::demo::draw_list(app, ui),
        OwnerView::Item => super::demo::draw_detail(app, ui),
        OwnerView::Rules => super::demo::draw_rules(app, ui),
        OwnerView::Agents => super::demo::draw_agents(app, ui),
        OwnerView::Activity => super::demo::draw_activity(app, ui),
    }
}

/// A run that waits for the owner, on top of every view but Activity.
#[cfg(feature = "vault")]
fn approval_banner(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    let Some(run) = pending.first() else {
        return;
    };
    let title = format!("{} asks to run a command with secrets", run.agent);
    let more = pending.len() - 1;
    kit::notice(ui, Tone::Warning, &title, None, |ui| {
        ui.add(
            egui::Label::new(
                kit::text(super::activity::shell_words(&run.command), kit::Font::Mono)
                    .color(kit::LABEL),
            )
            .truncate(),
        );
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            if kit::small_button(ui, "Review", Style::Prominent).clicked() {
                app.ui.sheet = Some(Sheet::Approval(run.id));
            }
            if more > 0
                && kit::small_button(ui, &format!("{more} more waiting"), Style::Link).clicked()
            {
                navigate(app, OwnerView::Activity);
            }
        });
    });
}

fn sheets(app: &mut DesktopApp, ctx: &egui::Context) {
    #[cfg(feature = "vault")]
    {
        if app.owner_ui.fresh_token.is_some() {
            super::agents::draw_fresh_token(app, ctx);
            return;
        }
        if app.pending_delete && app.view == OwnerView::Item {
            super::items::draw_delete_alert(app, ctx);
        }
    }
    #[cfg(not(feature = "vault"))]
    if app.pending_delete && app.view == OwnerView::Item {
        super::demo::draw_delete_alert(app, ctx);
    }
    let Some(sheet) = app.ui.sheet.clone() else {
        return;
    };
    #[cfg(feature = "vault")]
    let confirming_discard = app.ui.discard_item_changes;
    let escape = match sheet {
        #[cfg(feature = "vault")]
        Sheet::AddItem { kind_chosen } => super::items::add_sheet(app, ctx, kind_chosen),
        #[cfg(feature = "vault")]
        Sheet::EditItem => super::items::edit_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::Declaration => super::items::declaration_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::Variable => super::items::variable_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::Connector => super::items::connector_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::ArchiveItem => super::items::archive_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::RegisterAgent => super::agents::register_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::RevokeAgent { agent_id, name } => {
            super::agents::revoke_sheet(app, ctx, agent_id, &name)
        }
        #[cfg(feature = "vault")]
        Sheet::ProcessAccess {
            agent_id,
            item_id,
            mode,
            any_folder,
        } => super::agents::access_sheet(app, ctx, agent_id, item_id, mode, any_folder),
        #[cfg(feature = "vault")]
        Sheet::GrantMany { agent_id } => super::agents::grant_many_sheet(app, ctx, agent_id),
        #[cfg(feature = "vault")]
        Sheet::AccessRequest { request_id } => {
            super::activity::access_request_sheet(app, ctx, request_id)
        }
        #[cfg(feature = "vault")]
        Sheet::Approval(run_id) => super::activity::approval_sheet(app, ctx, run_id),
        #[cfg(feature = "vault")]
        Sheet::ChangePassphrase => super::settings::passphrase_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::Backup => super::settings::backup_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::Restore => super::settings::restore_sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::Vault(sheet) => super::vaults::sheet(app, ctx, &sheet),
        #[cfg(feature = "vault")]
        Sheet::Import => super::import::sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::ResetCompanion => super::companion::reset_sheet(app, ctx),
        #[cfg(not(feature = "vault"))]
        Sheet::AddItem { kind_chosen } => super::demo::add_sheet(app, ctx, kind_chosen),
        #[cfg(not(feature = "vault"))]
        Sheet::EditItem => super::demo::edit_sheet(app, ctx),
    };
    // Escape closes the top sheet, but not while the owner check is open over it.
    #[cfg(feature = "vault")]
    let checking = app.owner.check.is_some();
    #[cfg(not(feature = "vault"))]
    let checking = false;
    #[cfg(feature = "vault")]
    if confirming_discard {
        super::items::discard_changes_alert(app, ctx);
        return;
    }
    if escape && !checking {
        #[cfg(feature = "vault")]
        super::items::request_close_form(app, ctx);
        #[cfg(not(feature = "vault"))]
        close_sheet(app, ctx);
    }
}

#[cfg(all(test, feature = "vault"))]
mod tests {
    #[test]
    fn the_agents_badge_counts_active_agents_with_an_expired_token() {
        use crate::vault::AgentSummary;
        let agent = |id, revoked, expires| AgentSummary {
            id,
            name: format!("Agent {id}"),
            created_at: 0,
            revoked,
            token_issued_at: 0,
            token_expires_at: expires,
        };
        let agents = [
            agent(1, false, 100),
            agent(2, false, 500),
            agent(3, true, 100),
        ];
        assert_eq!(super::expired_tokens(&agents, 99), 0);
        assert_eq!(super::expired_tokens(&agents, 100), 1);
        assert_eq!(super::expired_tokens(&agents, 600), 2);
    }
}
