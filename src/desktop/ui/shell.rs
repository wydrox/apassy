//! The window frame (ADR 0026 §1): the sidebar, the list column, the detail column, and
//! the sheets.

use eframe::egui::{self, Frame, Margin};

use super::Sheet;
#[cfg(not(feature = "vault"))]
use super::close_sheet;
use super::columns::{Columns, SidebarMode};
use super::kit;
#[cfg(feature = "vault")]
use super::kit::{Style, Tone};
use crate::desktop::{DesktopApp, Place};

#[cfg(feature = "vault")]
pub(super) type Pending = Vec<crate::broker::approvals::PendingRun>;
#[cfg(not(feature = "vault"))]
pub(super) type Pending = ();

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    #[cfg(feature = "vault")]
    let pending = watch_approvals(app, &ctx);
    #[cfg(not(feature = "vault"))]
    let pending = ();
    shortcuts(app, &ctx);
    let columns = Columns::of(app, ctx.content_rect().width());
    if !columns.narrow {
        app.ui.sidebar_float = false;
    }
    // The columns are split by a hairline, as in the mockup, not by the 1-point line
    // of egui.
    let sidebar = egui::Panel::left("apassy-sidebar")
        .resizable(false)
        .exact_size(columns.sidebar_width())
        .show_separator_line(false)
        .frame(Frame::NONE.fill(kit::SIDEBAR).inner_margin(Margin {
            left: side_margin(columns.sidebar),
            right: side_margin(columns.sidebar),
            top: 0,
            bottom: 10,
        }))
        .show(ui, |ui| {
            super::sidebar::draw(app, ui, &pending, columns.sidebar)
        })
        .response
        .rect;
    let list = egui::Panel::left("apassy-list")
        .resizable(false)
        .exact_size(columns.list_width)
        .show_separator_line(false)
        .frame(Frame::NONE.fill(kit::LIST))
        .show(ui, |ui| list_column(app, ui, &pending))
        .response
        .rect;
    for rect in [sidebar, list] {
        column_edge(ui, rect);
    }
    egui::CentralPanel::default()
        .frame(Frame::NONE.fill(kit::DETAIL))
        .show(ui, |ui| detail_column(app, ui, &pending));
    if columns.sidebar == SidebarMode::Float {
        super::sidebar::draw_float(app, &ctx, &pending);
    }
    // A sheet that opened in the Settings window shows there.
    if !(app.settings_open && app.ui.settings_sheet && !ctx.embed_viewports()) {
        sheets(app, &ctx);
    }
}

/// The margin at the sides of the sidebar. On the rail, wide enough for the traffic
/// lights ([`kit::RAIL_WIDTH`]), it keeps the icon rows 42 points wide, near the 40 of
/// the mockup.
fn side_margin(mode: SidebarMode) -> i8 {
    if mode == SidebarMode::Full { 10 } else { 18 }
}

/// The hairline at the right edge of a column, inside it.
fn column_edge(ui: &egui::Ui, rect: egui::Rect) {
    let width = 1.0 / ui.ctx().pixels_per_point();
    let x = rect.right() - width / 2.0;
    ui.painter().vline(
        x,
        rect.y_range(),
        egui::Stroke::new(width, kit::COLUMN_EDGE),
    );
}

/// The list column of the place. After a navigation with the keyboard, its first
/// control takes the focus.
fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    super::focus::page_start(&mut app.ui.focus, &ui.ctx().clone());
    #[cfg(feature = "vault")]
    match &app.place {
        Place::Folder(_) | Place::Shared(_) => super::items::list_column(app, ui),
        Place::Decisions => super::decisions::list_column(app, ui, pending),
        Place::Agents => super::agents::list_column(app, ui),
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = pending;
        match &app.place {
            Place::Folder(_) | Place::Shared(_) => super::demo::list_column(app, ui),
            Place::Decisions => super::demo::decisions_list(app, ui),
            Place::Agents => super::demo::agents_list(app, ui),
        }
    }
}

/// The detail column of the place.
fn detail_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    #[cfg(feature = "vault")]
    match &app.place {
        Place::Folder(_) | Place::Shared(_) => super::items::detail_column(app, ui, pending),
        Place::Decisions => super::decisions::detail_column(app, ui, pending),
        Place::Agents => super::agents::detail_column(app, ui, pending),
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = pending;
        match &app.place {
            Place::Folder(_) | Place::Shared(_) => super::demo::detail_column(app, ui),
            Place::Decisions => super::demo::decisions_detail(app, ui),
            Place::Agents => super::demo::agents_detail(app, ui),
        }
    }
}

/// The banners on top of a detail: a run that waits (but in Decisions), a ready update,
/// and a sync note. Each scope keeps the IDs below it the same when it comes or goes, so
/// the focus stays on its control.
#[cfg(feature = "vault")]
pub(super) fn banners(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    pending: &[crate::broker::approvals::PendingRun],
) {
    ui.scope(|ui| {
        if app.place != Place::Decisions {
            approval_banner(app, ui, pending);
        }
    });
    ui.scope(|ui| super::updates::banner(app, ui));
    ui.scope(|ui| super::sync::banner(app, ui));
}

/// Go to a place with the keyboard. The first control of its list takes the focus.
fn go(app: &mut DesktopApp, ctx: &egui::Context, place: Place) {
    super::sidebar::navigate(app, place);
    // Settings in place of the window gives way to the place.
    if ctx.embed_viewports() {
        app.settings_open = false;
    }
    app.ui.focus.focus_page_start();
}

/// Window shortcuts. They act only when no sheet, alert, token, or owner check is open,
/// except ⌘L.
///
/// - ⌘1, ⌘2, ⌘3: All credentials, Decisions, Agents. ⌘,: the Settings window.
/// - ⌘[: back from a credential or an agent to nothing selected.
/// - ⌘N: a new credential.
/// - ⌘F: search the credentials.
/// - ⌘⇧H: show or hide the secret values of the open credential. ⌘H stays the macOS
///   shortcut for "Hide Apassy": the app menu takes it before the window.
/// - ⌘L: lock the vault, also with a sheet open, but not during an owner check.
/// - ⌃⌘S: collapse or expand the sidebar; in a narrow window, open or close it over
///   the list.
///
/// Tab and Shift-Tab move the focus, and the page scrolls to it. Space or Return
/// presses the focused control. Page Up, Page Down, Home, and End scroll the page.
pub(super) fn shortcuts(app: &mut DesktopApp, ctx: &egui::Context) {
    use eframe::egui::{Key, Modifiers};

    #[cfg(feature = "vault")]
    if app.owner.check.is_none() && kit::shortcut(ctx, Modifiers::COMMAND, Key::L) {
        app.lock_vault(Some(ctx));
        return;
    }
    #[cfg(feature = "vault")]
    let busy = app.ui.sheet.is_some()
        || app.pending_delete
        || app.owner_ui.fresh_token.is_some()
        || app.owner.check.is_some()
        || app.learning.inspected.is_some();
    #[cfg(not(feature = "vault"))]
    let busy = app.ui.sheet.is_some() || app.pending_delete;
    if busy {
        return;
    }
    // Before ⌘ alone: ⌃⌘S must not reach a ⌘S handler.
    if kit::shortcut(ctx, Modifiers::COMMAND | Modifiers::CTRL, Key::S) {
        app.ui
            .toggle_sidebar_in(ctx.content_rect().width() < kit::NARROW_WINDOW);
        return;
    }
    let places = [
        (Key::Num1, Place::CREDENTIALS),
        (Key::Num2, Place::Decisions),
        (Key::Num3, Place::Agents),
    ];
    for (key, place) in places {
        if kit::shortcut(ctx, Modifiers::COMMAND, key) {
            go(app, ctx, place);
            return;
        }
    }
    if kit::shortcut(ctx, Modifiers::COMMAND, Key::Comma) {
        app.open_settings_window();
        return;
    }
    if kit::shortcut(ctx, Modifiers::COMMAND, Key::OpenBracket) {
        if app.place.is_credentials() && app.selected_item_id.is_some() {
            app.selected_item_id = None;
            app.ui.focus.focus_page_start();
        }
        #[cfg(feature = "vault")]
        if app.place == Place::Agents && app.owner_ui.selected_agent.is_some() {
            app.owner_ui.selected_agent = None;
            app.ui.focus.focus_page_start();
        }
        return;
    }
    #[cfg(feature = "vault")]
    if kit::shortcut(ctx, Modifiers::COMMAND | Modifiers::SHIFT, Key::H) {
        if app.place.is_credentials() && app.selected_item_id.is_some() {
            super::items::toggle_masking(app, ctx);
        }
    } else if kit::shortcut(ctx, Modifiers::COMMAND, Key::N) {
        app.show_credentials();
        app.ui.sheet = Some(Sheet::NewCredential);
    } else if kit::shortcut(ctx, Modifiers::COMMAND, Key::F) {
        app.show_credentials();
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

/// Active agents whose token expired. An expired token stops the agent until the owner
/// rotates it; a revoked agent needs nothing.
#[cfg(feature = "vault")]
pub(super) fn expired_tokens(agents: &[crate::vault::AgentSummary], now: u64) -> usize {
    agents
        .iter()
        .filter(|agent| !agent.revoked && agent.token_expired_at(now))
        .count()
}

/// A question that waits for the owner, on top of each detail but Decisions. "Review"
/// opens it in Decisions.
#[cfg(feature = "vault")]
fn approval_banner(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    pending: &[crate::broker::approvals::PendingRun],
) {
    let Some(run) = pending.first() else {
        return;
    };
    let title = format!("{} waits for your answer", run.agent);
    let more = pending.len() - 1;
    kit::notice(ui, Tone::Warning, &title, None, |ui| {
        ui.add(
            egui::Label::new(
                kit::text(super::decisions::shell_words(&run.command), kit::Font::Mono)
                    .color(kit::LABEL),
            )
            .truncate(),
        );
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            if kit::small_button(ui, "Review", Style::Prominent).clicked() {
                super::decisions::select(app, run.id);
                super::sidebar::navigate(app, Place::Decisions);
            }
            if more > 0
                && kit::small_button(ui, &format!("{more} more waiting"), Style::Link).clicked()
            {
                super::sidebar::navigate(app, Place::Decisions);
            }
        });
    });
}

/// The sheet over the window, the delete alert, and the token sheet.
pub(super) fn sheets(app: &mut DesktopApp, ctx: &egui::Context) {
    #[cfg(feature = "vault")]
    {
        if app.owner_ui.fresh_token.is_some() {
            super::agents::draw_fresh_token(app, ctx);
            return;
        }
        if app.pending_delete && app.selected_item_id.is_some() {
            super::items::draw_delete_alert(app, ctx);
        }
    }
    #[cfg(not(feature = "vault"))]
    if app.pending_delete && app.selected_item_id.is_some() {
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
        Sheet::RegisterAgent => super::agent_onboarding::sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::RevokeAgent { agent_id, name } => {
            super::agents::revoke_sheet(app, ctx, agent_id, &name)
        }
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
        #[cfg(feature = "vault")]
        Sheet::NewCredential => super::new_credential::sheet(app, ctx),
        #[cfg(feature = "vault")]
        Sheet::MoveToFolder { item_id } => super::folders::move_sheet(app, ctx, item_id),
        #[cfg(feature = "vault")]
        Sheet::NewFolder { parent } => {
            super::folders::new_folder_sheet(app, ctx, parent.as_deref())
        }
        #[cfg(feature = "vault")]
        Sheet::RenameFolder { uuid } => super::folders::rename_sheet(app, ctx, &uuid),
        #[cfg(feature = "vault")]
        Sheet::DeleteFolder { uuid } => super::folders::delete_sheet(app, ctx, &uuid),
        #[cfg(feature = "vault")]
        Sheet::Share { item_id } => super::items::share_sheet(app, ctx, item_id),
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
