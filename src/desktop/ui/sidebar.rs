//! The sidebar (ADR 0026 §1): Personal (all credentials and the folders), Shared (the
//! shared vaults), Agents (Decisions and Agents), and at the bottom the open vault with
//! its lock and the Settings button.
//!
//! The sidebar is full, a rail of icons, or, in a narrow window, a full sidebar that
//! floats over the list until a choice or a click outside it. The button in its top row
//! and ⌃⌘S switch it.

use eframe::egui::{self, Align, Color32, Frame, Layout, Margin, Pos2, Rect, ScrollArea, Vec2};

use super::columns::SidebarMode;
use super::kit::{self, Badge, Icon, Lead, SidebarClick, SidebarRow, Tone};
use crate::desktop::{DesktopApp, Place};

#[cfg(feature = "vault")]
type Pending = [crate::broker::approvals::PendingRun];
#[cfg(not(feature = "vault"))]
type Pending = ();

/// A shared vault in the sidebar: its UUID, its name, and the color of its square.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SharedVaultRow {
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) color: Color32,
}

/// The shared vaults of the open vault. Shared vaults come with ADR 0026 §6; until the
/// vault reads them, the list is empty.
pub(crate) fn shared_vaults(app: &DesktopApp) -> Vec<SharedVaultRow> {
    app.ui.shared_vaults.clone()
}

/// The shared vault `uuid`, or a stand-in when it is not on this Mac.
pub(crate) fn shared_vault(app: &DesktopApp, uuid: &str) -> SharedVaultRow {
    shared_vaults(app)
        .into_iter()
        .find(|vault| vault.uuid == uuid)
        .unwrap_or_else(|| SharedVaultRow {
            uuid: uuid.to_owned(),
            name: "Shared vault".to_owned(),
            color: Tone::Neutral.mark(),
        })
}

/// Go to a place. A credential that is not in the new list is no longer selected. In a
/// narrow window the floating sidebar closes.
pub(super) fn navigate(app: &mut DesktopApp, place: Place) {
    #[cfg(feature = "vault")]
    if let Place::Folder(_) = &place
        && let Some(id) = app
            .selected_item_id
            .as_deref()
            .and_then(|id| id.parse::<u64>().ok())
        && !super::folders::FolderTree::load(app).contains(&place, id)
    {
        app.selected_item_id = None;
    }
    if let Place::Shared(_) = &place {
        app.selected_item_id = None;
    }
    app.place = place;
    app.ui.sidebar_float = false;
}

/// The sidebar button: "Hide sidebar" or "Show sidebar" with ⌃⌘S. `shown`: the full
/// sidebar shows.
fn toggle_button(app: &mut DesktopApp, ui: &mut egui::Ui, rect: Rect, narrow: bool, shown: bool) {
    let name = if shown {
        "Hide sidebar  ⌃⌘S"
    } else {
        "Show sidebar  ⌃⌘S"
    };
    let clicked = ui
        .scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
            kit::title_bar_button(ui, Icon::Sidebar, name).clicked()
        })
        .inner;
    if clicked {
        app.ui.toggle_sidebar_in(narrow);
    }
}

/// The sidebar in its panel: full or as a rail.
pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending, mode: SidebarMode) {
    let full = ui.max_rect();
    let narrow = mode != SidebarMode::Full && ui.ctx().content_rect().width() < kit::NARROW_WINDOW;
    match mode {
        SidebarMode::Full => {
            kit::window_drag_region(
                ui,
                Rect::from_min_size(full.min, Vec2::new(full.width(), kit::TOOLBAR)),
            );
            // Right of the window buttons, at the end of the top row.
            let button = Rect::from_min_size(
                Pos2::new(full.right() - 18.0 - 26.0, full.top() + 13.0),
                Vec2::splat(26.0),
            );
            toggle_button(app, ui, button, narrow, true);
            ui.add_space(kit::TOOLBAR);
            full_content(app, ui, pending);
        }
        SidebarMode::Rail | SidebarMode::Float => {
            kit::window_drag_region(
                ui,
                Rect::from_min_size(full.min, Vec2::new(full.width(), kit::TITLE_BAR)),
            );
            // Under the window buttons, which take the top of the rail.
            let button = Rect::from_min_size(
                Pos2::new(full.center().x - 13.0, full.top() + kit::TITLE_BAR + 4.0),
                Vec2::splat(26.0),
            );
            // Under a floating sidebar, its own button is the one to use.
            if mode == SidebarMode::Rail {
                toggle_button(app, ui, button, narrow, false);
            }
            ui.add_space(kit::TITLE_BAR + 38.0);
            rail_content(app, ui, pending);
        }
    }
}

/// The full sidebar over the list, in a narrow window. A click outside closes it.
pub(super) fn draw_float(app: &mut DesktopApp, ctx: &egui::Context, pending: &Pending) {
    let screen = ctx.content_rect();
    egui::Area::new(egui::Id::new("apassy-sidebar-float"))
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            // The rest of the window: a click there closes the sidebar.
            let outside = Rect::from_min_max(
                Pos2::new(screen.left() + kit::SIDEBAR_WIDTH, screen.top()),
                screen.max,
            );
            let scrim = ui.interact(
                outside,
                egui::Id::new("apassy-sidebar-scrim"),
                egui::Sense::click(),
            );
            if scrim.clicked() {
                app.ui.sidebar_float = false;
            }
            let rect =
                Rect::from_min_size(screen.min, Vec2::new(kit::SIDEBAR_WIDTH, screen.height()));
            let painter = ui.painter();
            painter.rect_filled(
                rect.translate(Vec2::new(6.0, 0.0)),
                0,
                Color32::from_black_alpha(18),
            );
            painter.rect_filled(rect, 0, kit::SIDEBAR);
            ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                Frame::NONE
                    .inner_margin(Margin {
                        left: 10,
                        right: 10,
                        top: 0,
                        bottom: 10,
                    })
                    .show(ui, |ui| {
                        ui.set_min_size(Vec2::new(
                            kit::SIDEBAR_WIDTH - 20.0,
                            screen.height() - 10.0,
                        ));
                        let full = ui.max_rect();
                        let button = Rect::from_min_size(
                            Pos2::new(full.right() - 8.0 - 26.0, full.top() + 13.0),
                            Vec2::splat(26.0),
                        );
                        toggle_button(app, ui, button, true, true);
                        ui.add_space(kit::TOOLBAR);
                        full_content(app, ui, pending);
                    });
            });
        });
    if ctx.input(|input| input.key_pressed(egui::Key::Escape))
        && ctx.memory(|memory| memory.top_modal_layer()).is_none()
    {
        app.ui.sidebar_float = false;
    }
}

/// The rows and the footer of the full sidebar.
fn full_content(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    let footer_height = 56.0;
    let rows_height = (ui.available_height() - footer_height).max(60.0);
    ScrollArea::vertical()
        .id_salt("sidebar-rows")
        .max_height(rows_height)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            personal_section(app, ui);
            shared_section(app, ui, false);
            agents_section(app, ui, pending, false);
        });
    footer(app, ui, false);
}

/// The icons of the rail, and its footer.
fn rail_content(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending) {
    ui.spacing_mut().item_spacing.y = 2.0;
    let count = active_count(app);
    let selected = app.place == Place::CREDENTIALS;
    if kit::rail_row(
        ui,
        &Lead::Icon(Icon::Key),
        &format!("All credentials, {count}  ⌘1"),
        selected,
        None,
    )
    .clicked()
    {
        navigate(app, Place::CREDENTIALS);
    }
    let shared = shared_vaults(app);
    if !shared.is_empty() {
        ui.add_space(10.0);
    }
    shared_section(app, ui, true);
    ui.add_space(10.0);
    agents_section(app, ui, pending, true);
    ui.with_layout(Layout::bottom_up(Align::Center), |ui| footer(app, ui, true));
}

/// Credentials that are not archived, as the list counts them.
fn active_count(app: &DesktopApp) -> usize {
    #[cfg(feature = "vault")]
    {
        let session = &app.owner_ui.session;
        let archived = session.archived().unwrap_or_default();
        session
            .search("")
            .map(|items| {
                items
                    .iter()
                    .filter(|item| !archived.contains_key(&item.id))
                    .count()
            })
            .unwrap_or(0)
    }
    #[cfg(not(feature = "vault"))]
    {
        if app.model.is_locked() {
            0
        } else {
            app.model.list_items("").len()
        }
    }
}

/// "Personal": all credentials, then the folders, nested. "+" on the header makes a
/// folder at the top level.
fn personal_section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    #[cfg(feature = "vault")]
    let add = kit::sidebar_section(ui, "Personal", Some("New folder"));
    #[cfg(not(feature = "vault"))]
    kit::sidebar_section(ui, "Personal", None);
    #[cfg(feature = "vault")]
    if add.is_some_and(|add| add.clicked()) {
        super::folders::open_new(app, None);
    }
    let count = active_count(app);
    let (response, click) = kit::sidebar_row(
        ui,
        &SidebarRow {
            lead: Lead::Icon(Icon::Key),
            label: "All credentials",
            count: Some(count),
            badge: None,
            selected: app.place == Place::CREDENTIALS,
            level: 0,
            disclosure: None,
        },
    );
    response.on_hover_text("All credentials  ⌘1");
    if click == SidebarClick::Select {
        navigate(app, Place::CREDENTIALS);
    }
    #[cfg(feature = "vault")]
    folder_rows(app, ui);
}

/// The folder tree under "All credentials". A folder shows its subfolders when it is
/// open. A secondary click has New Folder, Rename, and Delete.
#[cfg(feature = "vault")]
fn folder_rows(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let tree = super::folders::FolderTree::load(app);
    if tree.folders.is_empty() {
        return;
    }
    let archived = app.owner_ui.session.archived().unwrap_or_default();
    let active: Vec<u64> = app
        .owner_ui
        .session
        .search("")
        .unwrap_or_default()
        .into_iter()
        .map(|item| item.id)
        .filter(|id| !archived.contains_key(id))
        .collect();
    enum Act {
        Select(String),
        Toggle(String),
        New(String),
        Rename(String),
        Delete(String),
    }
    let mut act = None;
    // Depth first: a folder shows when each folder above it is open.
    for folder in &tree.folders {
        let mut parent = folder.parent.as_deref();
        let mut visible = true;
        while let Some(above) = parent {
            if !app.ui.open_folders.contains(above) {
                visible = false;
                break;
            }
            parent = tree.get(above).and_then(|f| f.parent.as_deref());
        }
        if !visible {
            continue;
        }
        let subtree = tree.subtree(&folder.uuid);
        let count = active
            .iter()
            .filter(|id| tree.folder_of(**id).is_some_and(|f| subtree.contains(f)))
            .count();
        let disclosure = tree
            .has_children(&folder.uuid)
            .then(|| app.ui.open_folders.contains(&folder.uuid));
        let selected = app.place == Place::Folder(Some(folder.uuid.clone()));
        let (response, click) = ui
            .push_id(("folder", &folder.uuid), |ui| {
                kit::sidebar_row(
                    ui,
                    &SidebarRow {
                        lead: Lead::Icon(Icon::Folder),
                        label: &folder.name,
                        count: Some(count),
                        badge: None,
                        selected,
                        level: tree.level(&folder.uuid) + 1,
                        disclosure,
                    },
                )
            })
            .inner;
        match click {
            SidebarClick::Select => act = Some(Act::Select(folder.uuid.clone())),
            SidebarClick::Disclose => act = Some(Act::Toggle(folder.uuid.clone())),
            SidebarClick::None => {}
        }
        response.context_menu(|ui| {
            if ui.button("New Folder…").clicked() {
                act = Some(Act::New(folder.uuid.clone()));
            }
            if ui.button("Rename…").clicked() {
                act = Some(Act::Rename(folder.uuid.clone()));
            }
            ui.separator();
            if ui.button("Delete…").clicked() {
                act = Some(Act::Delete(folder.uuid.clone()));
            }
        });
    }
    match act {
        Some(Act::Select(uuid)) => navigate(app, Place::Folder(Some(uuid))),
        Some(Act::Toggle(uuid)) => app.ui.toggle_folder(&uuid),
        Some(Act::New(uuid)) => super::folders::open_new(app, Some(uuid)),
        Some(Act::Rename(uuid)) => super::folders::open_rename(app, &uuid),
        Some(Act::Delete(uuid)) => super::folders::open_delete(app, &uuid),
        None => {}
    }
}

/// "Shared": a square with the first letter of each shared vault. On the rail, the name
/// is in the tooltip.
fn shared_section(app: &mut DesktopApp, ui: &mut egui::Ui, rail: bool) {
    let shared = shared_vaults(app);
    if !rail {
        kit::sidebar_section(ui, "Shared", None);
        if shared.is_empty() {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(kit::text("No shared vaults", kit::Font::Callout).color(kit::TERTIARY));
            });
        }
    }
    let mut chosen = None;
    for vault in &shared {
        let selected = app.place == Place::Shared(vault.uuid.clone());
        let lead = Lead::Square(vault.color, vault.name.clone());
        let clicked = ui
            .push_id(("shared", &vault.uuid), |ui| {
                if rail {
                    kit::rail_row(ui, &lead, &vault.name, selected, None).clicked()
                } else {
                    kit::sidebar_row(
                        ui,
                        &SidebarRow {
                            lead: lead.clone(),
                            label: &vault.name,
                            count: None,
                            badge: None,
                            selected,
                            level: 0,
                            disclosure: None,
                        },
                    )
                    .1 == SidebarClick::Select
                }
            })
            .inner;
        if clicked {
            chosen = Some(vault.uuid.clone());
        }
    }
    if let Some(uuid) = chosen {
        navigate(app, Place::Shared(uuid));
    }
}

/// What waits for the owner: runs and open access requests of agents.
fn decisions_badge(app: &DesktopApp, pending: &Pending) -> Badge {
    #[cfg(feature = "vault")]
    let count = pending.len()
        + app
            .owner_ui
            .session
            .access_requests(true)
            .map_or(0, |requests| requests.len());
    #[cfg(not(feature = "vault"))]
    let count = {
        let _ = pending;
        app.model
            .list_requests()
            .iter()
            .filter(|request| request.status == crate::desktop::RequestStatus::Pending)
            .count()
    };
    Badge {
        count,
        tone: Tone::Critical,
        what: "waiting",
    }
}

/// The agents: a neutral count of the active ones, or an orange count of the expired
/// tokens.
fn agents_count(app: &DesktopApp) -> (Option<usize>, Option<Badge>) {
    #[cfg(feature = "vault")]
    {
        let agents = app.owner_ui.session.agents().unwrap_or_default();
        let expired = super::shell::expired_tokens(&agents, kit::now());
        let active = agents.iter().filter(|agent| !agent.revoked).count();
        let badge = (expired > 0).then_some(Badge {
            count: expired,
            tone: Tone::Warning,
            what: if expired == 1 {
                "token expired"
            } else {
                "tokens expired"
            },
        });
        (Some(active), badge)
    }
    #[cfg(not(feature = "vault"))]
    {
        (Some(app.model.list_agents().len()), None)
    }
}

/// "Agents": Decisions with the red count of what blocks agents, and Agents.
fn agents_section(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &Pending, rail: bool) {
    let badge = decisions_badge(app, pending);
    let (count, agents_badge) = agents_count(app);
    let mut chosen = None;
    let rows = [
        (
            Place::Decisions,
            Icon::CheckCircle,
            "Decisions",
            None,
            Some(badge),
            "⌘2",
        ),
        (
            Place::Agents,
            Icon::Agent,
            "Agents",
            count,
            agents_badge,
            "⌘3",
        ),
    ];
    if !rail {
        kit::sidebar_section(ui, "Agents", None);
    }
    for (place, icon, label, count, badge, keys) in rows {
        let selected = app.place == place;
        let clicked = if rail {
            kit::rail_row(
                ui,
                &Lead::Icon(icon),
                &format!("{label}  {keys}"),
                selected,
                badge,
            )
            .clicked()
        } else {
            let (response, click) = kit::sidebar_row(
                ui,
                &SidebarRow {
                    lead: Lead::Icon(icon),
                    label,
                    count,
                    badge,
                    selected,
                    level: 0,
                    disclosure: None,
                },
            );
            response.on_hover_text(format!("{label}  {keys}"));
            click == SidebarClick::Select
        };
        if clicked {
            chosen = Some(place);
        }
    }
    if let Some(place) = chosen {
        navigate(app, place);
    }
}

/// The bottom of the sidebar: the open vault with its lock state and its menu, and the
/// Settings button. On the rail: the lock and the Settings button.
fn footer(app: &mut DesktopApp, ui: &mut egui::Ui, rail: bool) {
    ui.add_space(6.0);
    if rail {
        if kit::plain_icon_button(ui, Icon::Gearshape, "Settings  ⌘,").clicked() {
            app.open_settings_window();
        }
        #[cfg(feature = "vault")]
        if kit::plain_icon_button(ui, Icon::Lock, "Lock the vault  ⌘L").clicked() {
            let ctx = ui.ctx().clone();
            app.lock_vault(Some(&ctx));
        }
        return;
    }
    let area = ui.max_rect();
    let rect = Rect::from_min_max(Pos2::new(area.left(), area.bottom() - 52.0), area.max);
    ui.painter().hline(
        (rect.left() - 10.0)..=(rect.right() + 10.0),
        rect.top(),
        egui::Stroke::new(1.0 / ui.ctx().pixels_per_point(), kit::SEPARATOR),
    );
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(Vec2::new(0.0, 6.0)))
            .layout(Layout::left_to_right(Align::Center)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            let switcher = (ui.available_width() - 30.0).max(40.0);
            ui.allocate_ui_with_layout(
                Vec2::new(switcher, 40.0),
                Layout::top_down(Align::Min),
                |ui| vault_footer(app, ui),
            );
            if kit::plain_icon_button(ui, Icon::Gearshape, "Settings  ⌘,").clicked() {
                app.open_settings_window();
            }
        },
    );
}

/// The open vault, its status, its lock, and its menu (ADR 0013).
#[cfg(feature = "vault")]
fn vault_footer(app: &mut DesktopApp, ui: &mut egui::Ui) {
    super::vaults::sidebar_switcher(app, ui);
}

/// The demo: the lock state, "Open vault" or "Lock vault", and "Reset demo".
#[cfg(not(feature = "vault"))]
fn vault_footer(app: &mut DesktopApp, ui: &mut egui::Ui) {
    use super::kit::Style;
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.horizontal(|ui| {
            let locked = app.model.is_locked();
            let label = if locked { "Open vault" } else { "Lock vault" };
            if kit::small_button(ui, label, Style::Bordered).clicked() {
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
            if kit::small_button(ui, "Reset demo", Style::Link).clicked() {
                app.reset_demo();
            }
        });
        ui.horizontal(|ui| {
            kit::tag(ui, "Demo", Tone::Warning);
            ui.add(
                egui::Label::new(
                    kit::text(crate::desktop::DEMO_BANNER, kit::Font::Footnote)
                        .color(kit::SECONDARY),
                )
                .truncate(),
            )
            .on_hover_text(app.model.lock_state_label());
        });
    });
}
