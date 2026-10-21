//! Credentials: the list, the detail page, and their sheets (vault build).
//!
//! The list shows each credential with its provider tile, its name, and one line: the
//! username or the kind (ADR 0026 §1). A production credential has a red dot. The list
//! sorts and filters, and it hides archived credentials unless the owner searches or
//! selects their archive filter. Sync conflict copies have a persistent review notice
//! and a separate filter.
//!
//! The detail page follows the approved mockup (ADR 0026 §2): the header with the tile,
//! the name, the provider and the kind, and the caps; the question "Is this a
//! development key?" while the environment is only a default; the secret (masked), the
//! variable, and the host; the folder and the shared vaults; the agent use; the rules
//! from the owner's answers and the exceptions of agents; "Always ask me", the
//! environment, and "Hosts and risk" with the declaration, the variable, and the
//! connector. A change that makes the bouncer less careful needs the owner check; a
//! stricter change does not (ADR 0025 §3b, §3f).

use std::collections::BTreeMap;

use eframe::egui::{self, Align, Label, Layout, Pos2, Rect, RichText, Sense, Vec2};

use super::columns;
use super::detail_rows as rows;
use super::folders::FolderTree;
use super::kit::{self, Font, Icon, Section, Size, Style, Tone};
use super::otp;
use super::timeline::{self, relative_time};
use super::{
    SECRET_VALUE_CAPACITY, Sheet, UiState, ask_owner_from_sheet, close_sheet, extra_label,
    forget_secret_field, forget_secret_form, kind_blurb, kind_icon, meta_line, secure_input,
};
use crate::broker::approvals::action_words;
use crate::broker::profile::REPORTING_API_V0;
use crate::contracts::CredentialKind;
use crate::desktop::model::{DesktopModel, DetailDraft, ExtraField, ItemDraft, MASKED_VALUE};
use crate::desktop::owner_check::{OwnerRequest, page_text};
use crate::desktop::owner_store::{
    DETAIL_PREFIX, DeclarationForm, DetailLine, MAX_DETAILS, OwnerDetails, OwnerSummary,
    PasskeyItem, SecretForm, field_label,
};
use crate::desktop::{DesktopApp, Place};
use crate::vault::answers::{AnswerScope, OwnerAnswer};
use crate::vault::exceptions::{AgentException, ExceptionKind};
use crate::vault::providers::{self, Suggested};
use crate::vault::usage::{ItemUse, UseDecidedBy, UseOutcome};
use crate::vault::{DeclarationSource, EnvDelivery, Environment, Reversibility, RiskLevel, Scope};

// ---- The list. ----

/// Which credentials the list shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Filter {
    #[default]
    All,
    /// Archived versions retained after concurrent sync changes.
    Conflicts,
    Archived,
}

impl Filter {
    fn label(self) -> &'static str {
        match self {
            Self::All => "All credentials",
            Self::Conflicts => "Conflicting changes",
            Self::Archived => "Archived",
        }
    }
}

/// Conflict copies have a separate review list and archive count. A search still
/// finds them with a distinct label. Restored copies follow the active filters.
fn matches_filter(filter: Filter, searching: bool, archived: bool, conflict: bool) -> bool {
    let conflict = archived && conflict;
    if filter == Filter::Conflicts {
        return conflict;
    }
    if filter == Filter::Archived {
        return archived && !conflict;
    }
    if archived && !searching {
        return false;
    }
    true
}

/// One row of the credential list, read before the list draws.
struct ListedItem {
    id: u64,
    name: String,
    subtitle: String,
    /// "Archived", "Conflict copy", or nothing.
    status: String,
    production: bool,
    /// In at least one shared vault.
    shared: bool,
    tile: kit::Tile,
}

/// The list column of a credentials place: the toolbar with the title, the count, and
/// "+", the search field, then the rows. By name, the rows
/// group by folder, and the header of a group stays at the top while its rows scroll.
pub(super) fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let title = columns::place_title(app);
    if let Place::Shared(_) = &app.place {
        shared_list(app, ui, &title);
        return;
    }
    let place = app.place.clone();
    let tree = FolderTree::load(app);
    let session = &app.owner_ui.session;
    let all = session.search("").unwrap_or_default();
    let archived = session.archived().unwrap_or_default();
    let conflicts = session.conflict_copies().unwrap_or_default();
    let vault_empty = all.is_empty();
    let in_place: Vec<OwnerSummary> = all
        .into_iter()
        .filter(|item| tree.contains(&place, item.id))
        .collect();
    let active = in_place
        .iter()
        .filter(|item| !archived.contains_key(&item.id))
        .count();
    let mut add = false;
    let mut folder_more = false;
    columns::list_toolbar(
        ui,
        &title,
        &columns::count_label(active, "item", "items"),
        |ui| {
            add = kit::plain_icon_button(ui, Icon::Plus, "New credential  ⌘N").clicked();
            if let Place::Folder(Some(uuid)) = &place {
                let uuid = uuid.clone();
                ui.menu_button("More", |ui| {
                    if ui.button("New Subfolder…").clicked() {
                        super::folders::open_new(app, Some(uuid.clone()));
                        ui.close();
                    }
                    if ui.button("Rename Folder…").clicked() {
                        super::folders::open_rename(app, &uuid);
                        ui.close();
                    }
                    if ui.button("Move Folder…").clicked() {
                        folder_more = true;
                        ui.close();
                    }
                    if ui.button("Delete Folder…").clicked() {
                        super::folders::open_delete(app, &uuid);
                        ui.close();
                    }
                });
            }
        },
    );
    if folder_more && let Place::Folder(Some(uuid)) = &place {
        super::folders::open_move_folder(app, uuid.clone());
    }
    if add {
        app.ui.sheet = Some(Sheet::NewCredential);
    }
    if vault_empty {
        // No search field without credentials. ⌘F must not focus it later by surprise.
        app.ui.focus_search = false;
        columns::list_note(ui, "No items");
        return;
    }
    columns::list_inset(ui, |ui| {
        toolbar(app, ui);
        if !app.ui.selected_items.is_empty() {
            ui.horizontal_wrapped(|ui| {
                kit::note(ui, format!("{} selected", app.ui.selected_items.len()));
                if kit::small_button(ui, "Move…", Style::Bordered)
                    .on_hover_text("Move selected credentials  ⇧⌘M")
                    .clicked()
                {
                    super::folders::open_move_many(app);
                }
                if kit::small_button(ui, "Clear Selection", Style::Link).clicked() {
                    app.ui.selected_items.clear();
                }
            });
        }
        if !app.ui.move_undo.is_empty() {
            ui.horizontal_wrapped(|ui| {
                kit::note(ui, format!("{} credentials moved", app.ui.move_undo.len()));
                if kit::small_button(ui, "Undo Move", Style::Bordered)
                    .on_hover_text("⌘Z")
                    .clicked()
                {
                    super::folders::undo_move(app);
                }
            });
        }
    });

    let session = &app.owner_ui.session;
    let query = app.search.trim().to_owned();
    let filter = app.ui.credential_filter;
    let archived_count = in_place
        .iter()
        .filter(|item| archived.contains_key(&item.id) && !conflicts.contains_key(&item.id))
        .count();
    let found: Vec<OwnerSummary> = if query.is_empty() && app.ui.search_all {
        session.search("").unwrap_or_default()
    } else if query.is_empty() {
        in_place
    } else {
        session
            .search(&query)
            .unwrap_or_default()
            .into_iter()
            .filter(|item| app.ui.search_all || tree.contains(&place, item.id))
            .collect()
    };
    let mut items: Vec<OwnerSummary> = found
        .into_iter()
        .filter(|item| {
            matches_filter(
                filter,
                !query.is_empty(),
                archived.contains_key(&item.id),
                conflicts.contains_key(&item.id),
            )
        })
        .collect();
    items.sort_by_key(|item| item.name.to_lowercase());
    let hidden_archived = if filter == Filter::Archived || !query.is_empty() {
        0
    } else {
        archived_count
    };
    let listed = |item: &OwnerSummary| {
        let status = if archived.contains_key(&item.id) && conflicts.contains_key(&item.id) {
            "Conflict copy".to_owned()
        } else if archived.contains_key(&item.id) {
            "Archived".to_owned()
        } else {
            String::new()
        };
        let looks = Looks::of(app, item.id, item.kind, &item.service, &item.name);
        let username = matches!(item.kind, CredentialKind::Login | CredentialKind::Database)
            .then(|| page_text(&plain_field(app, item.id, "username")))
            .unwrap_or_default();
        ListedItem {
            id: item.id,
            name: item.name.clone(),
            subtitle: if username.is_empty() {
                looks.kind_label.clone()
            } else {
                username
            },
            status,
            production: looks.environment == EnvState::Production,
            shared: !looks.shared.is_empty(),
            tile: looks.tile,
        }
    };
    let grouped = filter != Filter::Conflicts;
    let groups: Vec<columns::Group<ListedItem>> = if grouped {
        // The top level first, then each folder by its path.
        let mut by_folder: BTreeMap<(bool, String), Vec<ListedItem>> = BTreeMap::new();
        for item in &items {
            let folder = tree.folder_of(item.id);
            by_folder
                .entry((folder.is_some(), tree.path_label(folder)))
                .or_default()
                .push(listed(item));
        }
        by_folder
            .into_iter()
            .map(|((_, title), rows)| columns::Group { title, rows })
            .collect()
    } else if items.is_empty() {
        Vec::new()
    } else {
        let title = match filter {
            Filter::Conflicts => format!("Conflicting changes ({})", items.len()),
            _ => "Credentials".to_owned(),
        };
        vec![columns::Group {
            title,
            rows: items.iter().map(listed).collect(),
        }]
    };
    let headers = !grouped || groups.len() > 1;
    let empty_message = items.is_empty().then(|| match filter {
        _ if !query.is_empty() => format!("No credential matches “{query}”."),
        Filter::Archived => "No credential is archived.".to_owned(),
        Filter::Conflicts => "No archived conflict copy needs review.".to_owned(),
        _ if place != Place::CREDENTIALS && active == 0 => {
            "No credentials in this folder.".to_owned()
        }
        _ => "No credential matches the filter.".to_owned(),
    });
    let visible: Vec<u64> = groups
        .iter()
        .flat_map(|group| group.rows.iter().map(|item| item.id))
        .collect();
    app.ui.selected_items.retain(|id| visible.contains(id));
    let selected = selected_id(app);
    let mut open = None;
    let mut show_archived = false;
    let mut list_focused = false;
    columns::grouped_rows(
        ui,
        ("credential-list", &place),
        &groups,
        headers,
        |ui, item| {
            let response = ui
                .push_id(("credential-row", item.id), |ui| {
                    credential_row(
                        ui,
                        item,
                        app.ui.selected_items.contains(&item.id) || selected == Some(item.id),
                    )
                })
                .inner;
            if app.ui.reveal_item == Some(item.id) {
                response.scroll_to_me(Some(Align::Center));
                app.ui.reveal_item = None;
            }
            if response.clicked() {
                response.request_focus();
            }
            list_focused |= response.has_focus();
            let range_key = response.gained_focus()
                && ui.input(|input| {
                    input.modifiers.shift
                        && (input.key_pressed(egui::Key::ArrowUp)
                            || input.key_pressed(egui::Key::ArrowDown))
                });
            if response.clicked() || range_key {
                open = Some(item.id);
            }
        },
        |ui| {
            if let Some(message) = &empty_message {
                columns::list_note(ui, message);
            }
            if hidden_archived > 0 {
                ui.add_space(8.0);
                let noun = if hidden_archived == 1 {
                    "archived credential is hidden."
                } else {
                    "archived credentials are hidden."
                };
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(8.0);
                    kit::note(ui, format!("{hidden_archived} {noun}"));
                    show_archived = kit::small_button(ui, "Show archived", Style::Link).clicked();
                });
            }
        },
    );
    let list_can_select = list_focused
        && ui.is_enabled()
        && !ui.ctx().text_edit_focused()
        && app.ui.sheet.is_none()
        && app.owner.check.is_none()
        && !app.pending_delete
        && app.owner_ui.fresh_token.is_none()
        && app.learning.inspected.is_none()
        && ui.ctx().memory(|memory| memory.top_modal_layer()).is_none()
        && !egui::Popup::is_any_open(ui.ctx());
    app.ui.native_library_focus = if list_can_select {
        ui.ctx().memory(|memory| memory.focused())
    } else {
        None
    };
    if list_can_select && kit::shortcut(ui.ctx(), egui::Modifiers::COMMAND, egui::Key::A) {
        app.ui.selected_items = visible.iter().copied().collect();
        app.ui.selection_anchor = visible.first().copied();
    }
    if show_archived {
        app.ui.credential_filter = Filter::Archived;
    }
    if let Some(id) = open {
        let modifiers = ui.input(|input| input.modifiers);
        update_selection(
            &mut app.ui.selected_items,
            &mut app.ui.selection_anchor,
            &visible,
            id,
            modifiers.command,
            modifiers.shift,
        );
        let selection = app.ui.selected_items.clone();
        if selection.contains(&id) {
            app.select_item(id.to_string());
        } else if let Some(next) = selection.iter().next().copied() {
            app.select_item(next.to_string());
        } else {
            app.selected_item_id = None;
        }
        app.ui.selected_items = selection;
    }
}

/// Selection follows displayed order, including folder grouping.
fn update_selection(
    selected: &mut std::collections::BTreeSet<u64>,
    anchor: &mut Option<u64>,
    visible: &[u64],
    id: u64,
    command: bool,
    shift: bool,
) {
    if shift
        && let Some((start, end)) = anchor
            .and_then(|a| visible.iter().position(|v| *v == a))
            .zip(visible.iter().position(|v| *v == id))
    {
        if !command {
            selected.clear();
        }
        selected.extend(visible[start.min(end)..=start.max(end)].iter().copied());
        return;
    }
    if command {
        if !selected.remove(&id) {
            selected.insert(id);
        }
    } else {
        selected.clear();
        selected.insert(id);
    }
    *anchor = Some(id);
}

/// The list of a shared vault: "From you" and "From others" (ADR 0026 §6). Shared vaults
/// come later, so the list has no item yet.
fn shared_list(app: &mut DesktopApp, ui: &mut egui::Ui, title: &str) {
    columns::list_toolbar(ui, title, "0 items", |_| {});
    app.ui.focus_search = false;
    columns::list_note(ui, "No items yet.");
}

/// The search field. ⌘F puts the focus in it. The list has no filter or order menus,
/// as in the mockup: the rows group by folder. A list of archived credentials or of
/// conflict copies (from "Show archived" and from the review of conflicting changes)
/// says so under the field, with "Show All" to go back.
fn toolbar(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let field = kit::search_field(ui, &mut app.search, "credential-search", "Search")
        .on_hover_text("Search by name, username, website, host, project, service, or notes  ⌘F");
    ui.ctx()
        .accesskit_node_builder(field.id, |node| node.set_label("Search credentials"));
    app.ui.credential_search_focused = field.has_focus();
    if std::mem::take(&mut app.ui.focus_search) {
        field.request_focus();
    }
    if matches!(app.place, Place::Folder(Some(_))) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut app.ui.search_all, false, "This Folder");
            ui.selectable_value(&mut app.ui.search_all, true, "All Credentials");
        });
    }
    if app.ui.credential_filter != Filter::All {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            ui.label(
                kit::text(app.ui.credential_filter.label(), Font::Footnote).color(kit::SECONDARY),
            );
            if kit::small_button(ui, "Show All", Style::Link).clicked() {
                app.ui.credential_filter = Filter::All;
            }
        });
    }
}

/// A row of the credential list: [`kit::list_row`], with the shared mark at the right.
fn credential_row(ui: &mut egui::Ui, item: &ListedItem, selected: bool) -> egui::Response {
    // Room for the mark: the row keeps its text clear of it.
    const MARK: &str = "     ";
    let meta = match (item.shared, item.status.is_empty()) {
        (false, _) => item.status.clone(),
        (true, true) => MARK.to_owned(),
        (true, false) => format!("{}{MARK}", item.status),
    };
    let response = kit::list_row(
        ui,
        &kit::ListRow {
            tile: item.tile.clone(),
            title: &item.name,
            subtitle: &item.subtitle,
            meta: Some(&meta),
            production: item.production,
            selected,
        },
    );
    if item.shared && ui.is_rect_visible(response.rect) {
        let right = response.rect.right() - 8.0 - if item.production { 13.0 } else { 0.0 };
        let rect = Rect::from_center_size(
            Pos2::new(right - 8.0, response.rect.center().y),
            Vec2::splat(14.0),
        );
        let color = if selected {
            egui::Color32::WHITE
        } else {
            kit::SECONDARY
        };
        kit::paint_icon(ui.painter(), rect, Icon::People, color);
    }
    if item.shared || item.production {
        // VoiceOver hears the marks after the name and the line.
        let mut name = format!("{}, {}", item.name, item.subtitle);
        if item.production {
            name.push_str(", production");
        }
        if item.shared {
            name.push_str(", shared");
        }
        ui.ctx()
            .accesskit_node_builder(response.id, |node| node.set_label(name));
    }
    response
}

/// A plain (not secret) field of a credential, such as its username. Empty when the
/// credential has none.
fn plain_field(app: &DesktopApp, item_id: u64, name: &str) -> String {
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault
                .reveal(item_id, name)
                .ok()
                .map(|value| value.expose().to_owned())
        })
        .flatten()
        .unwrap_or_default()
}

/// What the owner knows of the environment of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnvState {
    /// No declaration: each run waits for the owner.
    None,
    /// Only a default or the usage found it (ADR 0025 §4). The bouncer treats the
    /// credential as production until the owner answers.
    Unconfirmed(Environment),
    /// The owner or a signal of the credential set it.
    Known(Environment),
    /// Production that the owner or a signal set: the one red mark.
    Production,
}

impl EnvState {
    pub(super) fn of(app: &DesktopApp, item_id: u64) -> Self {
        let session = &app.owner_ui.session;
        let Some(declaration) = session.declaration(item_id).ok().flatten() else {
            return Self::None;
        };
        let source = session
            .with_vault(|vault| vault.declaration_sources(item_id))
            .and_then(Result::ok)
            .map_or(DeclarationSource::Owner, |sources| sources.environment);
        match (source, declaration.environment) {
            (DeclarationSource::Default | DeclarationSource::Usage, environment) => {
                Self::Unconfirmed(environment)
            }
            (_, Environment::Production) => Self::Production,
            (_, environment) => Self::Known(environment),
        }
    }

    /// The cap of the header: "Production" in red, or the environment in gray.
    fn cap(self) -> Option<(&'static str, bool)> {
        match self {
            Self::Production => Some(("Production", true)),
            Self::Known(environment) => Some((environment_label(environment), false)),
            Self::None | Self::Unconfirmed(_) => None,
        }
    }
}

/// "Production", "Staging", "Development", "Local".
fn environment_label(environment: Environment) -> &'static str {
    match environment {
        Environment::Production => "Production",
        Environment::Staging => "Staging",
        Environment::Development => "Development",
        Environment::Local => "Local",
    }
}

/// How a credential looks in the list and in its header: its tile, its provider, its
/// environment, and its shared vaults.
struct Looks {
    tile: kit::Tile,
    /// The label of its provider, such as "Stripe": the provider of its declaration,
    /// else the provider that its service or its name names (the one of its tile).
    provider: Option<String>,
    /// Its kind as its provider names it, such as "Secret key" (see [`field_kind`]).
    kind_label: String,
    environment: EnvState,
    /// The names of the shared vaults that hold it. Empty until shared vaults land
    /// (ADR 0026 §6).
    shared: Vec<String>,
}

impl Looks {
    fn of(app: &DesktopApp, item_id: u64, kind: CredentialKind, service: &str, name: &str) -> Self {
        let session = &app.owner_ui.session;
        let declared = session
            .with_vault(|vault| vault.declaration_provider(item_id))
            .and_then(Result::ok)
            .flatten()
            .and_then(|id| providers::find(&id))
            .map(|provider| provider.label.clone());
        let tile_service = declared.as_deref().unwrap_or(service);
        let variable = session
            .env_binding(item_id)
            .ok()
            .flatten()
            .map(|binding| binding.env_name)
            .filter(|variable| variable != &format!("APASSY_ITEM_{item_id}"));
        let provider = declared
            .clone()
            .or_else(|| super::named_provider(service, name).map(|(label, _)| label.to_owned()));
        Self {
            tile: super::credential_tile(kind, tile_service, name),
            provider,
            kind_label: field_kind(kind, variable.as_deref()),
            environment: EnvState::of(app, item_id),
            shared: shared_vaults(app, item_id),
        }
    }
}

/// The kind of a key as its provider names it, from the end of its variable:
/// `STRIPE_SECRET_KEY` is a "Secret key", `CLOUDFLARE_API_TOKEN` an "API token", and
/// `GITHUB_TOKEN` a "Token", as in the mockup. Another variable or kind gives the label
/// of the kind.
fn field_kind(kind: CredentialKind, variable: Option<&str>) -> String {
    const ENDINGS: [(&str, &str); 7] = [
        ("_SECRET_KEY", "Secret key"),
        ("_API_TOKEN", "API token"),
        ("_AUTH_TOKEN", "Auth token"),
        ("_ACCESS_TOKEN", "Access token"),
        ("_API_KEY", "API key"),
        ("_ACCESS_KEY_ID", "Access key"),
        ("_TOKEN", "Token"),
    ];
    if kind == CredentialKind::ApiKey
        && let Some(variable) = variable
        && let Some((_, label)) = ENDINGS
            .iter()
            .find(|(ending, _)| variable.to_ascii_uppercase().ends_with(ending))
    {
        return (*label).to_owned();
    }
    kind.label().to_owned()
}

/// Open the add sheet with an empty form. ⌘N does the same.
pub(super) fn open_add(app: &mut DesktopApp) {
    app.add_form = ItemDraft::default();
    app.ui.create_folder = FolderTree::load(app).folder_of_place(&app.place);
    app.owner_ui.add_secrets.clear();
    app.ui.sheet = Some(Sheet::AddItem { kind_chosen: false });
}

/// Reveal the actual saved result, even after a search or archive filter.
pub(super) fn reveal_saved(app: &mut DesktopApp, id: u64, folder: Option<String>) {
    app.search.clear();
    app.ui.credential_filter = Filter::All;
    app.ui.search_all = false;
    let tree = FolderTree::load(app);
    let mut above = folder.as_deref();
    while let Some(uuid) = above {
        app.ui.open_folders.insert(uuid.to_owned());
        above = tree.get(uuid).and_then(|f| f.parent.as_deref());
    }
    app.place = Place::Folder(folder);
    app.select_item(id.to_string());
    app.ui.selected_items.clear();
    app.ui.selected_items.insert(id);
    app.ui.selection_anchor = Some(id);
    app.ui.reveal_item = Some(id);
}

/// Items from a restored backup that wait for the owner review (goal item V4).
fn review_notice(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let items = app
        .owner_ui
        .session
        .items_needing_review()
        .unwrap_or_default();
    if items.is_empty() {
        return;
    }
    let mut open = None;
    kit::notice(
        ui,
        Tone::Warning,
        "Review after restore",
        Some(
            "This vault came from a backup. Agents cannot use these credentials until you confirm their agent settings: the declaration, the environment variable, and the connector. The restore also revoked every agent. Connect the agents again.",
        ),
        |ui| {
            ui.horizontal_wrapped(|ui| {
                for (item_id, name) in &items {
                    if kit::small_button(ui, name, Style::Bordered).clicked() {
                        open = Some(*item_id);
                    }
                }
            });
        },
    );
    if let Some(item_id) = open {
        app.select_item(item_id.to_string());
    }
}

/// This notice comes from retained vault records, not the latest sync result.
fn conflict_notice(app: &mut DesktopApp, ui: &mut egui::Ui, count: usize) {
    if count == 0 {
        return;
    }
    let review = kit::notice(
        ui,
        Tone::Warning,
        &format!("Review conflicting changes ({count})"),
        Some(
            "Sync kept another version in an archived conflict copy. Agents cannot use that copy.",
        ),
        |ui| kit::small_button(ui, "Review conflicting changes", Style::Bordered).clicked(),
    );
    if review {
        app.search.clear();
        app.ui.credential_filter = Filter::Conflicts;
    }
}

/// Show the relationship without a secret value or a change to either version.
fn conflict_detail(app: &mut DesktopApp, ui: &mut egui::Ui, id: u64, archived: bool) {
    let conflicts = app.owner_ui.session.conflict_copies().unwrap_or_default();
    if conflicts.is_empty() {
        return;
    }
    let items = app.owner_ui.session.search("").unwrap_or_default();
    let archives = app.owner_ui.session.archived().unwrap_or_default();
    let mut open = None;
    if let Some(original) = conflicts.get(&id) {
        let current = original.and_then(|original| items.iter().find(|item| item.id == original));
        let description = match current {
            Some(current) if !archives.contains_key(&current.id) => format!(
                "The current version is active: {}. This copy keeps the other version from sync.",
                current.name
            ),
            Some(current) => format!(
                "The current version is archived: {}. This copy keeps the other version from sync.",
                current.name
            ),
            None => "The original credential is no longer in this vault. This copy keeps the other version from sync.".to_owned(),
        };
        kit::notice(
            ui,
            Tone::Warning,
            if archived {
                "Conflict copy"
            } else {
                "Restored conflict copy"
            },
            Some(&description),
            |ui| {
                if let Some(current) = current
                    && kit::small_button(ui, "Open current version", Style::Bordered).clicked()
                {
                    open = Some(current.id);
                }
            },
        );
    } else {
        let retained: Vec<_> = items
            .iter()
            .filter(|item| {
                conflicts.get(&item.id) == Some(&Some(id)) && archives.contains_key(&item.id)
            })
            .collect();
        if !retained.is_empty() {
            kit::notice(
                ui,
                Tone::Warning,
                if archived {
                    "Current version · Archived"
                } else {
                    "Current version · Active"
                },
                Some(
                    "Sync kept this version as the current version. The other versions stay in archived conflict copies.",
                ),
                |ui| {
                    for copy in &retained {
                        if kit::small_button(ui, &copy.name, Style::Bordered).clicked() {
                            open = Some(copy.id);
                        }
                    }
                },
            );
        }
    }
    if let Some(id) = open {
        app.select_item(id.to_string());
    }
}

// ---- The detail page. ----

fn selected_id(app: &DesktopApp) -> Option<u64> {
    app.selected_item_id.as_deref()?.parse().ok()
}

/// The detail column of a credentials place: the selected credential, or, with none,
/// the notices of the vault and its first steps.
pub(super) fn detail_column(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    pending: &super::shell::Pending,
) {
    let Some(id) = selected_id(app) else {
        overview(app, ui, pending);
        return;
    };
    let details = match app.owner_ui.session.details(id) {
        Ok(details) => details,
        Err(err) if err.code == "not_found" => {
            // The credential is gone, for example after "Delete login" for a passkey
            // without a password, or after a delete on another device.
            app.selected_item_id = None;
            overview(app, ui, pending);
            return;
        }
        Err(err) => {
            columns::detail_toolbar(ui, |_| {});
            kit::column(ui, columns::DETAIL_WIDTH, |ui| {
                kit::tone_note(ui, err.message, Tone::Critical);
            });
            return;
        }
    };
    if details.hidden {
        columns::detail_toolbar(ui, |_| {});
        kit::column(ui, columns::DETAIL_WIDTH, |ui| {
            kit::note(ui, &details.message)
        });
        return;
    }
    detail_toolbar(app, ui, &details);
    // The header scrolls with the body, as in the mockup. A credential has its own
    // scroll position: opening a different credential must not start at the bottom of
    // the details of the one before. A question of an agent waits in Decisions, not on
    // the page.
    columns::detail_body(ui, ("credential", id), |ui| {
        rows::reading_column(ui, |ui| {
            ui.scope(|ui| super::updates::banner(app, ui));
            ui.scope(|ui| super::sync::banner(app, ui));
            draw_detail_header(app, ui);
            draw_detail_body(app, ui);
        });
    });
}

/// The key of the history of a credential, shown from the "⋯" menu.
fn history_key(id: u64) -> String {
    format!("credential-history-{id}")
}

/// Edit and the More menu: Move to Folder, custom details, history, Archive, and Delete.
fn detail_toolbar(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails) {
    let id = details.id;
    let history_open = app.ui.is_expanded(&history_key(id));
    let mut edit = false;
    let mut move_to = false;
    let mut add_detail = false;
    let mut history = false;
    let mut archive = false;
    let mut delete = false;
    columns::detail_toolbar(ui, |ui| {
        let more =
            kit::toolbar_button(ui, Some(Icon::More), "", "More actions for this credential");
        egui::Popup::menu(&more).show(|ui| {
            ui.set_min_width(200.0);
            move_to = ui.selectable_label(false, "Move to Folder…").clicked();
            if details.details.len() < MAX_DETAILS {
                add_detail = ui.selectable_label(false, "Add Custom Detail…").clicked();
            }
            let label = if history_open {
                "Hide History"
            } else {
                "Show History"
            };
            history = ui.selectable_label(false, label).clicked();
            ui.separator();
            if !details.archived {
                archive = ui.selectable_label(false, "Archive…").clicked();
            }
            delete = ui.selectable_label(false, "Delete…").clicked();
            // A choice with Return or Space closes the menu, as a click does.
            if move_to || add_detail || history || archive || delete {
                ui.close();
            }
        });
        // A choice closes the menu. For a keyboard user the focus goes back to "⋯", so
        // a sheet or an alert that the choice opens gives it back there, not to an item
        // of the closed menu.
        let chosen = move_to || add_detail || history || archive || delete;
        if chosen && kit::keyboard_mode(ui.ctx()) {
            more.request_focus();
        }
        edit = kit::toolbar_button(ui, None, "Edit", "Edit").clicked();
    });
    if edit {
        open_edit(app, details, false);
    } else if move_to {
        super::folders::open_move(app, id);
    } else if add_detail {
        open_edit(app, details, true);
    } else if history {
        app.ui.set_expanded(&history_key(id), !history_open);
    } else if archive {
        app.ui.sheet = Some(Sheet::ArchiveItem);
    } else if delete {
        app.pending_delete = true;
    }
}

/// No credential is selected: the banners, the setup of a vault from another Mac, the
/// first steps, the review and conflict notices, and an empty state.
fn overview(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &super::shell::Pending) {
    // A passkey removal that waits for the owner does not outlive its credential page.
    forget_removal(ui.ctx());
    columns::detail_toolbar(ui, |_| {});
    let shared = matches!(app.place, Place::Shared(_));
    columns::detail_body(ui, ("credentials-overview", shared), |ui| {
        super::shell::banners(app, ui, pending);
        if shared {
            columns::nothing_selected(
                ui,
                Icon::People,
                "No items yet",
                "Use Share on a credential to add it to this shared vault.",
            );
            return;
        }
        // A vault from another Mac: its agents stay on that Mac, so this one sets them
        // up here.
        if app.ui.setup_vault.is_some() && super::agents::next_steps_panel(app, ui) {
            app.ui.setup_vault = None;
        }
        let session = &app.owner_ui.session;
        let all = session.search("").unwrap_or_default();
        let archived = session.archived().unwrap_or_default();
        let conflicts = session.conflict_copies().unwrap_or_default();
        let conflict_count = all
            .iter()
            .filter(|item| archived.contains_key(&item.id) && conflicts.contains_key(&item.id))
            .count();
        // The two first steps of a new vault. With no credential, they are the empty
        // state.
        let guided = super::first_steps::draw(app, ui);
        ui.scope(|ui| review_notice(app, ui));
        ui.scope(|ui| conflict_notice(app, ui, conflict_count));
        if all.is_empty() {
            if !guided
                && kit::empty_state(
                    ui,
                    Icon::Key,
                    "No credentials yet",
                    "Paste an API key, a .env file, or a database URL. Agents use a credential through Apassy and never see its value.",
                    Some("Add credential"),
                )
            {
                app.ui.sheet = Some(Sheet::NewCredential);
            }
        } else {
            columns::nothing_selected(
                ui,
                Icon::Key,
                "No credential selected",
                "Select a credential in the list.",
            );
        }
    });
}

/// The header of a credential, as in the mockup: its tile, its name at 20 points, its
/// provider and kind ("Stripe · Secret key"), and its caps (Production, the shared
/// vaults). It scrolls with the body.
pub(super) fn draw_detail_header(app: &mut DesktopApp, ui: &mut egui::Ui) {
    const TILE: f32 = 56.0;
    let Some(id) = selected_id(app) else {
        return;
    };
    let Ok(details) = app.owner_ui.session.details(id) else {
        return;
    };
    if details.hidden {
        return;
    }
    let looks = Looks::of(app, id, details.kind, &details.service, &details.name);
    // "Stripe · Secret key"; without a provider, the service or the project.
    let source = looks
        .provider
        .clone()
        .unwrap_or_else(|| meta_line(&details.project, &details.service));
    let subtitle = if source.is_empty() {
        looks.kind_label.clone()
    } else {
        format!("{source} · {}", looks.kind_label)
    };
    let title = kit::text(&details.name, Font::Title)
        .size(20.0)
        .color(kit::LABEL);
    let subtitle = kit::text(subtitle, Font::Body).color(kit::SECONDARY);
    let cap = looks.environment.cap();
    let caps = cap.is_some() || details.archived || !looks.shared.is_empty();
    let width = (ui.available_width() - TILE - 14.0).max(40.0);
    // The tile is centered on the text, as `align-items: center` of the mockup.
    let text_height = {
        let wrapped = |text: RichText| {
            let job = egui::WidgetText::from(text);
            job.into_galley(
                ui,
                Some(egui::TextWrapMode::Wrap),
                width,
                egui::TextStyle::Body,
            )
            .size()
            .y
        };
        wrapped(title.clone()) + 2.0 + wrapped(subtitle.clone()) + if caps { 24.0 } else { 0.0 }
    };
    ui.add_space(6.0);
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        ui.vertical(|ui| {
            ui.add_space(((text_height - TILE) / 2.0).max(0.0));
            kit::tile(ui, &looks.tile, TILE);
        });
        ui.vertical(|ui| {
            ui.set_max_width(width);
            ui.spacing_mut().item_spacing.y = 2.0;
            let top = ((TILE - text_height) / 2.0).max(0.0);
            ui.add_space(top);
            ui.add(Label::new(title).wrap());
            ui.add(Label::new(subtitle).wrap());
            if caps {
                ui.add_space(5.0);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if let Some((label, red)) = cap {
                        kit::cap(ui, label, red);
                    }
                    // The tag of each shared vault. None until shared vaults land
                    // (ADR 0026 §6).
                    for vault in &looks.shared {
                        kit::cap(ui, vault, false);
                    }
                    if details.archived {
                        kit::cap(ui, "Archived", false);
                    }
                });
            }
        });
    });
    ui.add_space(rows::HEADER_GAP);
}

#[cfg(test)]
fn draw_detail(app: &mut DesktopApp, ui: &mut egui::Ui) {
    draw_detail_header(app, ui);
    if app.selected_item_id.is_some() {
        draw_detail_body(app, ui);
    }
}

/// The Share sheet (ADR 0026 §6). Shared vaults come later, so it says so and closes.
/// Returns true on Escape.
pub(super) fn share_sheet(app: &mut DesktopApp, ctx: &egui::Context, item_id: u64) -> bool {
    let name = app
        .owner_ui
        .session
        .details(item_id)
        .map(|details| details.name)
        .unwrap_or_default();
    let mut done = false;
    let response = kit::sheet(ctx, "share-credential", 440.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Share “{name}”"),
            Some(
                "A shared vault gets the same credential, not a copy. This Mac has no shared vault yet.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| done = kit::button(ui, "Done", Style::Prominent).clicked(),
        );
    });
    if done || super::save_pressed(app, ctx) {
        close_sheet(app, ctx);
    }
    response.escape
}

pub(super) fn draw_detail_body(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(id) = selected_id(app) else {
        return;
    };
    let details = match app.owner_ui.session.details(id) {
        Ok(details) if !details.hidden => details,
        _ => return,
    };
    conflict_detail(app, ui, id, details.archived);
    if details.archived {
        let restore = kit::notice(
            ui,
            Tone::Neutral,
            "Archived",
            Some(
                "Agents cannot use this credential. It stays in the vault, and a search finds it.",
            ),
            |ui| kit::small_button(ui, "Restore from archive", Style::Prominent).clicked(),
        );
        if restore {
            // Agents can use the item again after this, so it needs an owner check (A4).
            let ctx = ui.ctx().clone();
            app.ask_owner(
                OwnerRequest::Unarchive {
                    item_id: id,
                    name: details.name.clone(),
                },
                Some(&ctx),
            );
        }
    }
    review_card(app, ui, id);
    if !details.archived {
        environment_question(app, ui, &details);
    }
    let passkey = passkey_of(app, &details);
    fields_group(app, ui, &details, passkey.is_some());
    otp::code_section(app, ui, &details);
    if let Some(passkey) = &passkey {
        passkey_section(ui, &details, passkey);
    }
    place_group(app, ui, &details);
    let agents_use_it = !app
        .owner_ui
        .session
        .secret_fields(id)
        .unwrap_or_default()
        .is_empty();
    if agents_use_it {
        agent_use_group(app, ui, id);
    }
    evaluation_scopes_group(app, ui, id);
    if agents_use_it {
        if !rules_of(app, id).is_empty() {
            rules_group(app, ui, &details);
        }
        let key = format!("credential-agent-settings-{id}");
        let mut open = app.ui.is_expanded(&key);
        if kit::disclosure(ui, &mut open, "Agent Access").changed() {
            app.ui.set_expanded(&key, open);
        }
        if open {
            agent_settings_group(app, ui, &details);
        }
    }
    // The history comes from "Show History" in the "⋯" menu: a rare look back.
    if app.ui.is_expanded(&history_key(id)) {
        if rows::group_label(ui, "History", Some(("Hide", "Hide the history"))) {
            app.ui.set_expanded(&history_key(id), false);
        }
        ui.spacing_mut().item_spacing.y = 6.0;
        timeline::change_timeline(app, ui, id);
        let requests = app
            .owner_ui
            .session
            .item_activity(id, crate::vault::MAX_ACTIVITY_ROWS)
            .unwrap_or_default();
        timeline::access_timeline(
            app,
            ui,
            &requests,
            &format!("access-{id}"),
            "Agent requests",
            "No agent asked for this credential yet.",
            false,
        );
        ui.spacing_mut().item_spacing.y = 0.0;
    }
    footer(app, ui, id);
    removal_sheet(app, ui.ctx(), &details, passkey.as_ref());
}

fn detail_disclosure(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    id: u64,
    section: &str,
    label: &str,
    add: impl FnOnce(&mut DesktopApp, &mut egui::Ui),
) {
    let key = format!("credential-{section}-{id}");
    let mut open = app.ui.is_expanded(&key);
    if kit::disclosure(ui, &mut open, label).changed() {
        app.ui.set_expanded(&key, open);
    }
    if open {
        ui.add_space(8.0);
        add(app, ui);
    }
    ui.add_space(14.0);
}

/// Open the edit sheet with the stored values. With `add_detail`, the form gets a new
/// empty custom detail.
fn open_edit(app: &mut DesktopApp, details: &OwnerDetails, add_detail: bool) {
    app.edit_form = details.to_draft();
    if add_detail && app.edit_form.details.len() < MAX_DETAILS {
        app.edit_form.details.push(DetailDraft::default());
    }
    app.owner_ui.edit_revision = details.revision;
    app.owner_ui.edit_secrets.clear();
    app.ui.sheet = Some(Sheet::EditItem);
}

/// Show or hide the secret values of the selected credential. Showing needs the owner
/// check (goal item A4). ⌘⇧H does the same.
pub(super) fn toggle_masking(app: &mut DesktopApp, ctx: &egui::Context) {
    toggle_with(app, ctx, true);
}

/// The Show and Hide of the secret and the details. A shown one-time password does not
/// change them: its Show and Hide are on its own row. Hide still hides every value of the
/// item, and Show asks for the check of the generic Reveal.
fn toggle_values(app: &mut DesktopApp, ctx: &egui::Context) {
    toggle_with(app, ctx, false);
}

/// `with_codes`: a shown code counts as a shown value, so the shortcut hides it.
fn toggle_with(app: &mut DesktopApp, ctx: &egui::Context, with_codes: bool) {
    let Some(id) = selected_id(app) else {
        return;
    };
    let Ok(details) = app.owner_ui.session.details(id) else {
        return;
    };
    if details.hidden || details.secret_lines.is_empty() {
        return;
    }
    let code_shown = with_codes
        && details.details.iter().any(|detail| {
            otp::is_otp_detail(detail) && app.owner_ui.session.code_seed(id, &detail.name).is_some()
        });
    if details.any_revealed() || code_shown {
        let result = app.owner_ui.session.hide(id);
        let _ = app.apply(result, "The values are hidden.");
    } else {
        app.ask_owner(OwnerRequest::Reveal { item_id: id }, Some(ctx));
    }
}

/// The masked value, or the revealed value that the view borrows from the session.
/// egui still copies it for the layout (key-memory review F10, §5).
fn secret_value(ui: &mut egui::Ui, app: &DesktopApp, id: u64, name: &str) {
    if let Some(value) = app.owner_ui.session.revealed_value(id, name) {
        // A key, recovery list, or imported source record must not stretch the
        // complete page when revealed. Its own value area remains scrollable.
        egui::ScrollArea::vertical()
            .id_salt(("secret-value", id, name))
            .max_height(180.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.add(
                    Label::new(kit::text(value, Font::Mono).size(14.0).color(kit::LABEL)).wrap(),
                );
            });
    } else {
        ui.label(
            kit::text(MASKED_VALUE, Font::Mono)
                .size(17.0)
                .color(kit::LABEL),
        );
    }
}

/// "Show" or "Hide" for the secret values. The value sits below its field label.
fn mask_button(ui: &mut egui::Ui, revealed: bool) -> bool {
    let label = if revealed { "Hide" } else { "Show" };
    let name = if revealed {
        "Hide the secret values"
    } else {
        "Show the secret values"
    };
    rows::pill_button(ui, label, name)
        .on_hover_text("Show or hide secret values  ⌘⇧H")
        .clicked()
}

/// A row of a group: the label at the left, the value at the right, as in System
/// Settings. A value that does not fit goes under the label.
fn pair_row(group: &mut rows::Group<'_>, label: &str, value: RichText) {
    group.pair(label, value);
}

/// A masked secret with Show/Hide and a separately authenticated field Copy action.
/// A shown value uses its own scroll area. Copy records only the field identity.
fn secret_row(
    app: &DesktopApp,
    group: &mut rows::Group<'_>,
    details: &OwnerDetails,
    label: &str,
    name: &str,
    revealed: bool,
    copy: &mut Option<String>,
) -> bool {
    let id = details.id;
    let shown = app.owner_ui.session.revealed_value(id, name).is_some();
    group.row(|ui| {
        let width = ui.available_width();
        let toggle = ui
            .allocate_ui_with_layout(
                Vec2::new(width, 24.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_min_size(Vec2::new(width, 24.0));
                    ui.label(kit::text(label, Font::Body).color(kit::LABEL));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 10.0;
                        let toggle = mask_button(ui, revealed);
                        if app.owner_ui.session.can_copy_field(id, name, details.revision)
                            && rows::pill_button(ui, "Copy", &format!("Copy {label}")).on_hover_text("Confirm with Touch ID or passphrase. Clipboard clears after 30 seconds if unchanged.").clicked() {
                            *copy = Some(name.to_owned());
                        }
                        if !shown {
                            ui.label(
                                kit::text(MASKED_VALUE, Font::Body)
                                    .size(15.0)
                                    .extra_letter_spacing(2.0)
                                    .color(kit::LABEL),
                            );
                        }
                        toggle
                    })
                    .inner
                },
            )
            .inner;
        if shown {
            ui.add_space(4.0);
            secret_value(ui, app, id, name);
        }
        toggle
    })
}

/// The first group: the username, the secret, the variable, the host or the website,
/// and the other details that are set, then the custom details. A hidden custom detail
/// is masked like the secret, and Show shows it with the secret.
///
/// `from_page`: the login has a passkey. A website or macOS gave its account name, and the
/// vault copied it to the username. The page cleans it like the passkey rows.
fn fields_group(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails, from_page: bool) {
    let id = details.id;
    let username = if from_page {
        page_text(&details.username)
    } else {
        details.username.clone()
    };
    let secrets: Vec<_> = details
        .secret_lines
        .iter()
        .filter(|line| !line.name.starts_with(DETAIL_PREFIX))
        .collect();
    let session = &app.owner_ui.session;
    let provider_known = session
        .with_vault(|vault| vault.declaration_provider(id))
        .and_then(Result::ok)
        .flatten()
        .is_some_and(|provider| providers::find(&provider).is_some());
    let variable = session
        .env_binding(id)
        .ok()
        .flatten()
        .map(|binding| binding.env_name)
        .filter(|name| name != &format!("APASSY_ITEM_{id}"));
    let other: Vec<(&str, &str)> = [
        ("Host", details.host.as_str()),
        ("Website", details.website.as_str()),
        ("Database", details.database_name.as_str()),
        ("Public key", details.public_label.as_str()),
        // Without a provider, the header shows the service and the project.
        (
            "Service",
            if provider_known {
                details.service.as_str()
            } else {
                ""
            },
        ),
        (
            "Project",
            if provider_known {
                details.project.as_str()
            } else {
                ""
            },
        ),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .collect();
    let revealed = details.any_revealed();
    let footer = revealed.then(|| details.reveal_warning());
    let mut toggle = false;
    let mut copy = None;
    rows::group(ui, |s| {
        if !username.is_empty() {
            pair_row(
                s,
                "Username",
                kit::text(&username, Font::Body).color(kit::SECONDARY),
            );
        }
        for (index, line) in secrets.iter().enumerate() {
            // A key or a token says "Secret", as in the mockup; a login says "Password".
            let label = match details.kind {
                CredentialKind::ApiKey | CredentialKind::Custom if index == 0 => {
                    "Secret".to_owned()
                }
                _ => field_label(&line.name),
            };
            toggle |= secret_row(app, s, details, &label, &line.name, revealed, &mut copy);
        }
        if let Some(variable) = &variable {
            pair_row(
                s,
                "Variable",
                kit::text(variable, Font::Mono).color(kit::SECONDARY),
            );
        }
        for (label, value) in other {
            pair_row(s, label, kit::text(value, Font::Body).color(kit::SECONDARY));
        }
        // A one-time password has its own section. Its seed is never a detail row. A
        // visible setup key is not drawn.
        for detail in details
            .details
            .iter()
            .filter(|detail| !is_import_data(detail) && !otp::is_otp_detail(detail))
        {
            if otp::exposes_setup_key(detail) {
                s.row(|ui| otp::exposed_content(ui, detail));
            } else {
                match &detail.value {
                    Some(value) => pair_row(
                        s,
                        &detail.label,
                        kit::text(value, Font::Body).color(kit::SECONDARY),
                    ),
                    None => {
                        toggle |= secret_row(
                            app,
                            s,
                            details,
                            &detail.label,
                            &detail.name,
                            revealed,
                            &mut copy,
                        );
                    }
                }
            }
        }
    });
    if let Some(footer) = footer {
        ui.add_space(6.0);
        egui::Frame::NONE
            .inner_margin(egui::Margin::symmetric(12, 0))
            .show(ui, |ui| kit::note(ui, footer));
    }
    ui.add_space(rows::GROUP_GAP);
    if details.details.iter().any(is_import_data) {
        detail_disclosure(app, ui, id, "import", "Import data", |app, ui| {
            kit::section(ui, None, None, |s| {
                for detail in details
                    .details
                    .iter()
                    .filter(|detail| is_import_data(detail))
                {
                    toggle |= custom_value_row(app, s, details, detail, revealed, &mut copy);
                }
            });
        });
    }
    if !details.notes.is_empty() {
        rows::group_label(ui, "Notes", None);
        rows::group(ui, |s| {
            s.row(|ui| kit::paragraph(ui, &details.notes, Font::Body, kit::LABEL));
        });
        ui.add_space(rows::GROUP_GAP);
    }
    if let Some(field) = copy {
        app.ask_owner(
            OwnerRequest::CopyField {
                item_id: id,
                field,
                revision: details.revision,
            },
            Some(ui.ctx()),
        );
    } else if toggle {
        toggle_values(app, ui.ctx());
    }
}

/// The names of the shared vaults that hold a credential. None until shared vaults
/// land (ADR 0026 §6).
fn shared_vaults(_app: &DesktopApp, _item_id: u64) -> Vec<String> {
    Vec::new()
}

/// The folder action and shared destinations when sharing is available.
fn place_group(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails) {
    let id = details.id;
    let tree = FolderTree::load(app);
    let folder = tree.path_label(tree.folder_of(id));
    let shared = shared_vaults(app, id);
    let shared = shared.join(", ");
    let mut move_to = false;
    let mut share = false;
    rows::group(ui, |s| {
        move_to = s.chevron("Folder", &folder).clicked();
        if !shared.is_empty() {
            share = s.chevron("Shared in", &shared).clicked();
        }
    });
    ui.add_space(rows::GROUP_GAP);
    if move_to {
        super::folders::open_move(app, id);
    } else if share {
        app.ui.sheet = Some(Sheet::Share { item_id: id });
    }
}

/// The uses that the "Agent use" group shows before "Show All".
const RECENT_USES: usize = 3;
/// The uses that "Show All" shows.
const ALL_USES: usize = 200;

/// What a use of a credential came to, for its row: the round mark and the words.
pub(super) fn use_outcome(item_use: &ItemUse) -> (rows::Mark, String) {
    use rows::Mark;
    let on = if item_use.answered_on.is_empty() {
        String::new()
    } else {
        format!(", on {}", item_use.answered_on)
    };
    match (item_use.outcome, item_use.decided_by) {
        (UseOutcome::Allowed, UseDecidedBy::Owner) => {
            (Mark::Owner, format!("You allowed once{on}"))
        }
        (UseOutcome::Allowed, UseDecidedBy::Answer) => {
            (Mark::Allowed, "Allowed by your answer".to_owned())
        }
        (UseOutcome::Allowed, UseDecidedBy::Pattern) => {
            (Mark::Allowed, "Allowed by a remembered pattern".to_owned())
        }
        (UseOutcome::Allowed, UseDecidedBy::Rule) => {
            (Mark::Allowed, "Allowed by a rule".to_owned())
        }
        (UseOutcome::Allowed, UseDecidedBy::Bouncer) => {
            (Mark::Allowed, "Allowed automatically".to_owned())
        }
        (UseOutcome::Denied, UseDecidedBy::Owner) => (Mark::Refused, format!("You denied it{on}")),
        (UseOutcome::Denied, _) => (Mark::Refused, "Denied".to_owned()),
        (UseOutcome::Refused, _) => (Mark::Refused, "Refused".to_owned()),
        (UseOutcome::TimedOut, _) => (Mark::TimedOut, "No answer in time".to_owned()),
    }
}

/// "Agent use", as in the mockup: the newest uses, each with its round mark, the agent
/// and the project, the command and its result, and the time at the right; "Show All"
/// on the label lists every use.
fn agent_use_group(app: &mut DesktopApp, ui: &mut egui::Ui, id: u64) {
    let key = format!("credential-uses-{id}");
    let all = app.ui.is_expanded(&key);
    let uses = app
        .owner_ui
        .session
        .with_vault(|vault| vault.item_uses(id, if all { ALL_USES } else { RECENT_USES + 1 }))
        .and_then(Result::ok)
        .unwrap_or_default();
    if uses.is_empty() {
        return;
    }
    let link = if all {
        Some(("Show Less", "Show fewer agent uses"))
    } else if !uses.is_empty() {
        Some(("Show All", "Show all agent uses"))
    } else {
        None
    };
    if rows::group_label(ui, "Agent use", link) {
        app.ui.set_expanded(&key, !all);
    }
    let now = timeline::now();
    let shown = if all { uses.len() } else { RECENT_USES };
    rows::group(ui, |s| {
        if uses.is_empty() {
            s.line(|ui| {
                ui.label(kit::text("No agent used it yet.", Font::Body).color(kit::SECONDARY))
            });
        }
        for item_use in uses.iter().take(shown) {
            let (mark, outcome) = use_outcome(item_use);
            let who = format!("{} in {}", item_use.agent_name, item_use.project_label);
            let when = relative_time(item_use.at, now);
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
                            Label::new(kit::text(&who, Font::Body).color(kit::LABEL)).truncate(),
                        );
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.add(
                                Label::new(
                                    kit::text(&item_use.command_summary, Font::Mono)
                                        .color(kit::SECONDARY),
                                )
                                .truncate(),
                            );
                            ui.add(Label::new(rows::small(format!(" · {outcome}"))).truncate());
                        });
                    });
                    ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                        ui.label(kit::text(&when, Font::Callout).color(kit::TERTIARY));
                    });
                });
            });
        }
    });
    ui.add_space(rows::GROUP_GAP);
}

/// Model-evaluation permission is separate from a remembered execution allowance.
fn evaluation_scopes_group(app: &mut DesktopApp, ui: &mut egui::Ui, item_id: u64) {
    let scopes = match app.owner_ui.session.evaluation_scopes(item_id) {
        Ok(scopes) if !scopes.is_empty() => scopes,
        _ => return,
    };
    let agents = app.owner_ui.session.agents().unwrap_or_default();
    let mut remove = None;
    rows::group_label(ui, "Bouncer decisions", None);
    rows::group(ui, |s| {
        for scope in &scopes {
            let agent = agents
                .iter()
                .find(|agent| agent.id == scope.agent_id)
                .map_or_else(
                    || format!("Agent {}", scope.agent_id),
                    |agent| agent.name.clone(),
                );
            let title = format!(
                "{agent} · {} in {}",
                action_words(scope.action),
                scope.project.label
            );
            let hosts = if scope.hosts.is_empty() {
                "No destination host".to_owned()
            } else {
                scope.hosts.join(", ")
            };
            s.line(|ui| {
                ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - 80.0).max(80.0));
                    ui.add(Label::new(kit::text(&title, Font::Body).color(kit::LABEL)).wrap());
                    ui.add(Label::new(rows::small(format!("{} · {hosts}", scope.project.key))).wrap());
                    if scope.command_binding.is_some() {
                        ui.add(Label::new(rows::small("Only this exact command, execution context and directly selected script version.")).wrap());
                    }
                    ui.add(Label::new(rows::small("Model evaluation only; production, always-ask, and hard checks still apply.")).wrap());
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if rows::pill_button(ui, "Remove", &format!("Remove bouncer permission: {title}")).clicked() {
                        remove = Some(scope.id);
                    }
                });
            });
        }
    });
    ui.add_space(rows::GROUP_GAP);
    if let Some(id) = remove {
        let result = app.owner_ui.session.remove_evaluation_scope(id);
        match result {
            Ok(true) => {
                app.set_ok("Bouncer permission removed. Matching uses require your decision again.")
            }
            Ok(false) => app.set_note("This bouncer permission was already removed."),
            Err(error) => app.set_err(error.message),
        }
    }
}

/// One rule of the "Rules from your answers" group.
enum Rule {
    /// "Allow ACTION in PROJECT". Removing it is stricter: no owner check (ADR 0025 §3b).
    Answer(OwnerAnswer),
    /// "Never for AGENT" or "Always ask for AGENT". Removing it gives authority back:
    /// the owner check first (ADR 0025 §3f).
    Exception(AgentException, String),
}

impl Rule {
    fn title(&self) -> String {
        match self {
            Self::Answer(answer) => format!(
                "Allow {} in {}",
                action_words(answer.action),
                answer.project.label
            ),
            Self::Exception(exception, agent) => match exception.kind {
                ExceptionKind::Never => format!("Never for {agent}"),
                ExceptionKind::AlwaysAsk => format!("Always ask for {agent}"),
                ExceptionKind::Only => format!("Only these credentials for {agent}"),
            },
        }
    }
}

/// The remembered answers of the owner for the credential and the exceptions of
/// agents. "Only these credentials" belongs to the agent page, not to one credential.
fn rules_of(app: &DesktopApp, id: u64) -> Vec<Rule> {
    let session = &app.owner_ui.session;
    let agents = session.agents().unwrap_or_default();
    let agent_name = |agent_id: u64| {
        agents
            .iter()
            .find(|agent| agent.id == agent_id)
            .map_or_else(|| format!("agent {agent_id}"), |agent| agent.name.clone())
    };
    let (answers, exceptions) = session
        .with_vault(|vault| {
            (
                vault.answers_for_item(id).unwrap_or_default(),
                vault.item_exceptions(id).unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    // The answers first, then "Never for" before "Always ask for", as in the mockup.
    let mut exceptions = exceptions;
    exceptions.sort_by_key(|exception| exception.kind != ExceptionKind::Never);
    answers
        .into_iter()
        .map(Rule::Answer)
        .chain(
            exceptions
                .into_iter()
                .filter(|exception| exception.kind != ExceptionKind::Only)
                .map(|exception| {
                    let name = agent_name(exception.agent_id);
                    Rule::Exception(exception, name)
                }),
        )
        .collect()
}

/// The line under a remembered answer, as in the mockup: "All agents · production ·
/// your answer on iPhone, Oct 10".
fn answer_line(answer: &OwnerAnswer, now: u64) -> String {
    let mut parts = vec!["All agents".to_owned()];
    if answer.scope == AnswerScope::Production {
        parts.push("production".to_owned());
    }
    let on = if answer.answered_on.is_empty() {
        String::new()
    } else {
        format!(" on {}", answer.answered_on)
    };
    parts.push(format!(
        "your answer{on}, {}",
        relative_time(answer.created_at, now)
    ));
    parts.join(" · ")
}

/// "Rules from your answers": each rule with Remove at the right.
fn rules_group(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails) {
    let rules = rules_of(app, details.id);
    let now = timeline::now();
    let mut remove = None;
    rows::group_label(ui, "Rules from your answers", None);
    rows::group(ui, |s| {
        if rules.is_empty() {
            s.line(|ui| {
                ui.label(
                    kit::text("None. The bouncer decides each use.", Font::Body)
                        .color(kit::SECONDARY),
                )
            });
        }
        for (index, rule) in rules.iter().enumerate() {
            let title = rule.title();
            let line = match rule {
                Rule::Answer(answer) => Some(answer_line(answer, now)),
                Rule::Exception(..) => None,
            };
            s.line(|ui| {
                let button_width = 80.0;
                let title_text = kit::text(&title, Font::Body).color(kit::LABEL);
                match &line {
                    // A title alone stays on the center line of the row, with Remove.
                    None => {
                        ui.add(Label::new(title_text).truncate());
                    }
                    Some(line) => {
                        ui.vertical(|ui| {
                            ui.set_width((ui.available_width() - button_width).max(80.0));
                            ui.spacing_mut().item_spacing.y = 3.0;
                            ui.add(Label::new(title_text).wrap());
                            ui.add(Label::new(rows::small(line)).wrap());
                        });
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let name = format!("Remove the rule: {title}");
                    if rows::pill_button(ui, "Remove", &name).clicked() {
                        remove = Some(index);
                    }
                });
            });
        }
    });
    ui.add_space(rows::GROUP_GAP);
    let Some(rule) = remove.and_then(|index| rules.into_iter().nth(index)) else {
        return;
    };
    match rule {
        Rule::Answer(answer) => {
            // Stricter: the bouncer asks again. No owner check (ADR 0025 §3b).
            let title = Rule::Answer(answer.clone()).title();
            let result = app
                .owner_ui
                .session
                .with_vault(|vault| vault.remove_answer(answer.id));
            match result {
                Some(Ok(_)) => app.set_ok(format!("“{title}” is removed. The bouncer asks again.")),
                Some(Err(err)) => app.set_err(format!("The rule did not change: {err}.")),
                None => app.set_err("The vault is locked."),
            }
        }
        Rule::Exception(exception, agent_name) => {
            let ctx = ui.ctx().clone();
            app.ask_owner(
                OwnerRequest::RemoveAgentException {
                    agent_id: exception.agent_id,
                    agent_name,
                    item_id: exception.item_id,
                    kind: exception.kind,
                },
                Some(&ctx),
            );
        }
    }
}

/// The third group: "Always ask me", the environment, and "Hosts and risk" with the
/// declaration, the variable, and the connector.
fn agent_settings_group(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails) {
    let id = details.id;
    let always_ask = app
        .owner_ui
        .session
        .with_vault(|vault| vault.always_ask(id))
        .and_then(Result::ok)
        .unwrap_or(false);
    let state = EnvState::of(app, id);
    let access_key = format!("credential-access-{id}");
    let access_open = app.ui.is_expanded(&access_key);
    let mut ask = always_ask;
    let mut environment = match state {
        EnvState::Production => Some(Environment::Production),
        EnvState::Known(environment) => Some(environment),
        EnvState::None | EnvState::Unconfirmed(_) => None,
    };
    let chosen = environment;
    let shown = match state {
        EnvState::None => "Not set".to_owned(),
        EnvState::Unconfirmed(_) => "Not confirmed".to_owned(),
        EnvState::Known(environment) => environment_label(environment).to_owned(),
        EnvState::Production => "Production".to_owned(),
    };
    let options: Vec<(Option<Environment>, String)> = [
        Environment::Production,
        Environment::Staging,
        Environment::Development,
        Environment::Local,
    ]
    .into_iter()
    .map(|environment| (Some(environment), environment_label(environment).to_owned()))
    .collect();
    // Each value set or confirmed by the owner, or found by Apassy.
    let by_owner = app
        .owner_ui
        .session
        .with_vault(|vault| vault.declaration_sources(id))
        .and_then(Result::ok)
        .is_some_and(|sources| sources == crate::vault::DeclarationSources::default());
    let hosts = match state {
        EnvState::None => "Not set",
        _ if by_owner => "Set by you",
        _ => "Set automatically",
    };
    let mut toggle_access = false;
    rows::group(ui, |s| {
        s.toggle("Always ask me", &mut ask)
            .on_hover_text("Each use by an agent waits for you.");
        s.line(|ui| {
            ui.label(kit::text("Environment", Font::Body).color(kit::LABEL));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.push_id(("credential-environment", id), |ui| {
                    rows::pop_menu(
                        ui,
                        &mut environment,
                        &options,
                        &shown,
                        &format!("Environment, {shown}"),
                    )
                });
            });
        });
        let access = s.chevron("Hosts and risk", hosts);
        ui_expanded(&access, access_open);
        toggle_access = access.clicked();
    });
    ui.add_space(rows::GROUP_GAP);
    if toggle_access {
        app.ui.set_expanded(&access_key, !access_open);
    }
    if access_open {
        ui.spacing_mut().item_spacing.y = 6.0;
        access_section(app, ui, id, details.kind);
        ui.spacing_mut().item_spacing.y = 0.0;
    }
    if ask != always_ask {
        set_always_ask(app, ui.ctx(), details, ask);
    }
    if environment != chosen
        && let Some(environment) = environment
    {
        set_environment(app, ui.ctx(), details, environment);
    }
}

/// A row that opens and closes a part says so to VoiceOver.
fn ui_expanded(response: &egui::Response, open: bool) {
    response
        .ctx
        .accesskit_node_builder(response.id, |node| node.set_expanded(open));
}

/// Turn "Always ask me" on at once; turning it off asks for the owner check first.
pub(super) fn set_always_ask(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    details: &OwnerDetails,
    on: bool,
) {
    let id = details.id;
    if on {
        // Stricter: each use waits for the owner. No check.
        match app
            .owner_ui
            .session
            .with_vault(|vault| vault.set_always_ask(id, true))
        {
            Some(Ok(())) => app.set_ok(format!(
                "Each use of {} by an agent now waits for you.",
                details.name
            )),
            Some(Err(err)) => app.set_err(format!("\"Always ask me\" did not change: {err}.")),
            None => app.set_err("The vault is locked."),
        }
    } else {
        app.ask_owner(
            OwnerRequest::AlwaysAskOff {
                item_id: id,
                name: details.name.clone(),
            },
            Some(ctx),
        );
    }
}

/// Set the environment as the answer of the owner. Production is stricter and needs no
/// check. Another environment makes the bouncer less careful: the owner check first.
pub(super) fn set_environment(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    details: &OwnerDetails,
    environment: Environment,
) {
    let id = details.id;
    if EnvState::of(app, id) == EnvState::None {
        // No declaration yet: the owner sees and saves each value in its sheet, with
        // the owner check, so no value from a suggestion counts as the owner's.
        prepare_sheet(app, id, &Sheet::Declaration);
        app.owner_ui.declaration_form.environment = environment;
        app.ui.sheet = Some(Sheet::Declaration);
        return;
    }
    if environment != Environment::Production {
        app.ask_owner(
            OwnerRequest::SetEnvironment {
                item_id: id,
                name: details.name.clone(),
                environment,
            },
            Some(ctx),
        );
        return;
    }
    let result = app
        .owner_ui
        .session
        .with_vault(|vault| vault.set_declaration_environment(id, environment));
    match result {
        Some(Ok(())) => {
            app.reload_declaration_form(id);
            app.set_ok(format!(
                "{} is marked as production. Each run with it waits for you.",
                details.name
            ));
        }
        Some(Err(err)) => app.set_err(format!("The environment did not change: {err}.")),
        None => app.set_err("The vault is locked."),
    }
}

/// The kinds that a "development key?" question fits: a key or a token.
fn asks_for_environment(details: &OwnerDetails) -> bool {
    match details.kind {
        CredentialKind::ApiKey => true,
        CredentialKind::Custom => {
            let name = details.name.to_lowercase();
            name.contains("key") || name.contains("token")
        }
        CredentialKind::Login | CredentialKind::SshKey | CredentialKind::Database => false,
    }
}

/// "Is this a development key?" (ADR 0025 §4): only a default found the environment, so
/// the bouncer treats the key as production until the owner answers.
fn environment_question(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails) {
    if !matches!(EnvState::of(app, details.id), EnvState::Unconfirmed(_))
        || !asks_for_environment(details)
    {
        return;
    }
    let hosts = app
        .owner_ui
        .session
        .with_vault(|vault| vault.declaration_provider(details.id))
        .and_then(Result::ok)
        .flatten()
        .and_then(|id| providers::find(&id))
        .map(|provider| provider.known_hosts.clone())
        .unwrap_or_default();
    let host = hosts
        .first()
        .cloned()
        .or_else(|| (!details.host.is_empty()).then(|| details.host.clone()));
    let message = match host {
        Some(host) => {
            format!("It goes to {host}. Until you answer, the bouncer treats it as production.")
        }
        None => "Until you answer, the bouncer treats it as production.".to_owned(),
    };
    // The banner of the mockup: an icon, the question and its line, and two buttons.
    let mut answer = None;
    rows::group(ui, |s| {
        s.line(|ui| {
            ui.spacing_mut().item_spacing.x = 12.0;
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
            ui.painter()
                .rect_filled(rect, 7, egui::Color32::from_rgb(255, 244, 229));
            kit::paint_icon(
                ui.painter(),
                Rect::from_center_size(rect.center(), Vec2::splat(16.0)),
                Icon::Warning,
                egui::Color32::from_rgb(200, 106, 0),
            );
            let buttons = 200.0;
            ui.vertical(|ui| {
                ui.set_width((ui.available_width() - buttons).max(80.0));
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(kit::medium("Is this a development key?", Font::Body).color(kit::LABEL));
                ui.add(Label::new(rows::small(&message)).wrap());
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                if rows::pill_button(ui, "Production", "Mark as a production key").clicked() {
                    answer = Some(Environment::Production);
                }
                if rows::pill_button(ui, "Development", "Mark as a development key").clicked() {
                    answer = Some(Environment::Development);
                }
            });
        });
    });
    ui.add_space(rows::GROUP_GAP);
    if let Some(environment) = answer {
        set_environment(app, ui.ctx(), details, environment);
    }
}

/// "Added … · Changed …". "Added by AGENT in PROJECT" comes with the API of
/// `item_origin` (stream T2).
fn footer(app: &DesktopApp, ui: &mut egui::Ui, id: u64) {
    let times = app
        .owner_ui
        .session
        .item_times()
        .ok()
        .and_then(|times| times.get(&id).copied())
        .unwrap_or_default();
    let now = timeline::now();
    let mut parts = Vec::new();
    if let Some(added) = times.added {
        parts.push(format!("Added {}", relative_time(added, now)));
    }
    if let Some(changed) = times
        .changed
        .filter(|changed| Some(*changed) != times.added)
    {
        parts.push(format!("Changed {}", relative_time(changed, now)));
    }
    if parts.is_empty() {
        return;
    }
    // Each group adds its gap under it; the footer sits 22 points under the last one.
    ui.add_space(rows::FOOTER_GAP - rows::GROUP_GAP);
    ui.vertical_centered(|ui| {
        ui.label(kit::text(parts.join(" · "), Font::Footnote).color(kit::TERTIARY));
    });
    ui.add_space(8.0);
}

/// Labels and values share one reading edge, including paths and long identifiers.
fn value_row(section: &mut Section<'_>, label: &str, value: &str) {
    section.row(|ui| {
        ui.label(kit::text(label, Font::Callout).color(kit::SECONDARY));
        ui.add(Label::new(kit::text(value, Font::Mono).size(14.0).color(kit::LABEL)).wrap());
    });
}

fn is_import_data(detail: &DetailLine) -> bool {
    matches!(
        detail.label.as_str(),
        "1Password item ID" | "1Password source JSON"
    )
}

fn custom_value_row(
    app: &DesktopApp,
    section: &mut Section<'_>,
    details: &OwnerDetails,
    detail: &DetailLine,
    revealed: bool,
    copy: &mut Option<String>,
) -> bool {
    let id = details.id;
    match &detail.value {
        Some(value) => {
            value_row(section, &detail.label, value);
            false
        }
        None => section.row(|ui| {
            let mut toggle = false;
            egui::Sides::new().show(
                ui,
                |ui| ui.label(kit::text(&detail.label, Font::Callout).color(kit::SECONDARY)),
                |ui| {
                    toggle = mask_button(ui, revealed);
                    if app.owner_ui.session.can_copy_field(id, &detail.name, details.revision)
                        && rows::pill_button(ui, "Copy", &format!("Copy {}", detail.label)).on_hover_text("Confirm with Touch ID or passphrase. Clipboard clears after 30 seconds if unchanged.").clicked() {
                        *copy = Some(detail.name.clone());
                    }
                },
            );
            secret_value(ui, app, id, &detail.name);
            toggle
        }),
    }
}

fn access_section(app: &mut DesktopApp, ui: &mut egui::Ui, id: u64, kind: CredentialKind) {
    let session = &app.owner_ui.session;
    let declaration = session.declaration(id).ok().flatten();
    let provider = session
        .declaration_form(id)
        .ok()
        .filter(|form| form.stored)
        .and_then(|form| form.provider)
        .and_then(|provider| providers::find(&provider))
        .map(|provider| provider.label.clone());
    let binding = session.env_binding(id).ok().flatten();
    let automatic_ready = session.process_binding(id).ok().flatten().is_some();
    let has_fields = !session.secret_fields(id).unwrap_or_default().is_empty();
    let connector = if kind == CredentialKind::ApiKey {
        session.connector(id).ok().flatten()
    } else {
        None
    };
    let mut open = None;
    kit::section(
        ui,
        None,
        Some(
            "Agents never receive a secret value. They ask Apassy to run a command or to call an API, and Apassy decides.",
        ),
        |s| {
            let (subtitle, detail) = match &declaration {
                Some(declaration) => (
                    match &provider {
                        Some(provider) => format!("{provider} · project {}", declaration.project),
                        None => format!("Project {}", declaration.project),
                    },
                    kit::text(
                        format!(
                            "{} · {} risk",
                            title_case(declaration.environment.as_str()),
                            declaration.risk.as_str()
                        ),
                        Font::Callout,
                    )
                    .color(kit::SECONDARY),
                ),
                None => (
                    "Every agent run with this credential waits for you.".to_owned(),
                    kit::medium("Not set", Font::Callout).color(Tone::Warning.text()),
                ),
            };
            let shield = (Icon::Shield, egui::Color32::from_rgb(52, 120, 246));
            if s.nav(Some(shield), "Declaration", Some(&subtitle), Some(detail))
                .clicked()
            {
                open = Some(Sheet::Declaration);
            }
            if has_fields {
                let detail = match &binding {
                    Some(binding) => {
                        let mode = match binding.delivery {
                            EnvDelivery::Value => "",
                            EnvDelivery::Placeholder(_) => " · placeholder",
                        };
                        let name = if binding.env_name == format!("APASSY_ITEM_{id}") {
                            "Automatic"
                        } else {
                            &binding.env_name
                        };
                        kit::text(format!("{name}{mode}"), Font::Mono).color(kit::SECONDARY)
                    }
                    None => kit::text(
                        if automatic_ready {
                            "Automatic"
                        } else {
                            "Choose field"
                        },
                        Font::Callout,
                    )
                    .color(kit::SECONDARY),
                };
                let terminal = (Icon::Terminal, egui::Color32::from_rgb(88, 86, 214));
                if s.nav(
                    Some(terminal),
                    "Command settings",
                    Some("Optional variable name, secret field, and delivery settings."),
                    Some(detail),
                )
                .clicked()
                {
                    open = Some(Sheet::Variable);
                }
            }
            if kind == CredentialKind::ApiKey {
                let detail = match &connector {
                    Some(destination) => {
                        kit::text(&destination.base_url, Font::Callout).color(kit::SECONDARY)
                    }
                    None => kit::text("None", Font::Callout).color(kit::SECONDARY),
                };
                let globe = (Icon::Globe, egui::Color32::from_rgb(48, 176, 199));
                if s.nav(
                    Some(globe),
                    "Connector",
                    Some("Agents can call an HTTP API. Apassy adds the token."),
                    Some(detail),
                )
                .clicked()
                {
                    open = Some(Sheet::Connector);
                }
            }
        },
    );
    if let Some(sheet) = open {
        prepare_sheet(app, id, &sheet);
        app.ui.sheet = Some(sheet);
    }
}

/// Fill the form of a sheet from the vault, so an old cancelled edit does not stay.
pub(super) fn prepare_sheet(app: &mut DesktopApp, id: u64, sheet: &Sheet) {
    let state = &mut app.owner_ui;
    match sheet {
        Sheet::Declaration => {
            state.declaration_form = state.session.declaration_form(id).unwrap_or_default();
        }
        Sheet::Variable => {
            let binding = state.session.env_binding(id).ok().flatten();
            state.env_name_input = binding
                .as_ref()
                .map(|binding| binding.env_name.clone())
                .filter(|name| name != &format!("APASSY_ITEM_{id}"))
                .unwrap_or_default();
            let suggested = state.session.suggested_placeholder_hosts(id);
            // The sheet starts with what a run delivers now (`process_binding`): a stored
            // binding, or the automatic one, which delivers the real value. Only an item
            // that has neither starts in placeholder mode when the provider hosts are known.
            let effective = binding
                .clone()
                .or_else(|| state.session.process_binding(id).ok().flatten());
            (state.env_placeholder_input, state.env_hosts_input) =
                match effective.as_ref().map(|binding| &binding.delivery) {
                    Some(EnvDelivery::Placeholder(hosts)) => (true, hosts.join(", ")),
                    Some(EnvDelivery::Value) => (false, suggested.join(", ")),
                    None => (!suggested.is_empty(), suggested.join(", ")),
                };
            state.env_field_input = effective.map(|binding| binding.field).unwrap_or_default();
        }
        Sheet::Connector => {
            state.connector_url = state
                .session
                .connector(id)
                .ok()
                .flatten()
                .map(|destination| destination.base_url)
                .unwrap_or_default();
        }
        _ => {}
    }
}

/// Review and confirm the agent settings of one restored item (goal item V4).
fn review_card(app: &mut DesktopApp, ui: &mut egui::Ui, item_id: u64) {
    let session = &app.owner_ui.session;
    if !session.needs_review(item_id).unwrap_or(false) {
        return;
    }
    // The provider gives known hosts to the command analysis, so the owner reviews it.
    let provider = session
        .declaration_form(item_id)
        .ok()
        .and_then(|form| form.provider)
        .and_then(|id| providers::find(&id))
        .map_or_else(String::new, |p| format!(", provider {}", p.label));
    let declaration = session.declaration(item_id).ok().flatten().map_or_else(
        || "None. Every run with this item waits for you.".to_owned(),
        |d| {
            format!(
                "{}, {} risk, {}, {}, project {}{provider}",
                d.environment.as_str(),
                d.risk.as_str(),
                d.scope.as_str(),
                d.reversibility.as_str(),
                d.project
            )
        },
    );
    let variable = session.env_binding(item_id).ok().flatten().map_or_else(
        || "None".to_owned(),
        |binding| format!("{} = field {}", binding.env_name, binding.field),
    );
    let connector = session
        .connector(item_id)
        .ok()
        .flatten()
        .map_or_else(|| "None".to_owned(), |destination| destination.base_url);
    let confirm = kit::notice(
        ui,
        Tone::Warning,
        "Review after restore",
        Some(
            "This credential came from a restored backup. An old or changed backup can have wrong agent settings, for example a connector to another host or a production credential with a lower declaration. Check the settings below and correct them. Agents cannot use this credential before you confirm.",
        ),
        |ui| {
            egui::Grid::new(("review", item_id))
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    for (term, value) in [
                        ("Declaration", &declaration),
                        ("Environment variable", &variable),
                        ("Connector", &connector),
                    ] {
                        ui.label(kit::medium(term, Font::Callout).color(kit::LABEL));
                        ui.label(kit::text(value, Font::Callout).color(kit::LABEL));
                        ui.end_row();
                    }
                });
            ui.add_space(4.0);
            kit::small_button(ui, "Confirm settings", Style::Prominent).clicked()
        },
    );
    if confirm {
        // Agents can use the item again after this, so it needs an owner check (A4).
        let ctx = ui.ctx().clone();
        app.ask_owner(OwnerRequest::ConfirmReview { item_id }, Some(&ctx));
    }
}

/// The delete confirmation alert.
pub(super) fn draw_delete_alert(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(id) = selected_id(app) else {
        app.pending_delete = false;
        return;
    };
    let name = app
        .owner_ui
        .session
        .details(id)
        .map(|details| details.name)
        .unwrap_or_default();
    let mut delete = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "delete-item", 380.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Delete “{name}”?"),
            Some(
                "Apassy removes the credential and its agent settings from the vault file. You cannot undo this.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                delete = kit::button(ui, "Delete", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if cancel || response.escape {
        app.pending_delete = false;
    }
    if delete {
        let revision = app.owner_ui.edit_revision;
        let result = app.owner_ui.session.delete(id, revision);
        app.pending_delete = false;
        if app.apply(result, "The credential is deleted.").is_some() {
            app.selected_item_id = None;
            app.show_credentials();
        }
    }
}

/// The archive confirmation. An archive only takes authority away, so it needs no
/// owner check. Bringing the credential back does.
pub(super) fn archive_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let Some(id) = selected_id(app) else {
        app.ui.sheet = None;
        return false;
    };
    let name = app
        .owner_ui
        .session
        .details(id)
        .map(|details| details.name)
        .unwrap_or_default();
    let mut archive = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "archive-item", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Archive “{name}”?"),
            Some(
                "Agents cannot use an archived credential. It stays in the vault with its history, and a search or the \"Archived\" filter finds it. Restoring it asks for your passphrase.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                archive = kit::button(ui, "Archive", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    archive |= super::save_pressed(app, ctx);
    if archive {
        let result = app.owner_ui.session.archive(id);
        if app
            .apply(
                result,
                &format!("{name} is archived. Agents cannot use it."),
            )
            .is_some()
        {
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

// ---- The add and edit sheets. ----

enum FormAction {
    None,
    Cancel,
    Back,
    Pick(CredentialKind),
    Save,
}

fn new_form_dirty(app: &DesktopApp) -> bool {
    let blank = ItemDraft {
        kind: app.add_form.kind,
        ..ItemDraft::default()
    };
    app.add_form != blank || !app.owner_ui.add_secrets.is_blank()
}

fn change_kind(app: &mut DesktopApp, ctx: &egui::Context) {
    app.owner_ui.add_secrets.clear();
    forget_secret_form(ctx, "add");
    app.add_form = ItemDraft::default();
    app.ui.sheet = Some(Sheet::AddItem { kind_chosen: false });
}

/// Cancel a credential form only after the owner confirms the loss of typed data.
/// The draft and secret buffers stay in place while the confirmation is open.
pub(super) fn request_close_form(app: &mut DesktopApp, ctx: &egui::Context) {
    let dirty = match app.ui.sheet {
        Some(Sheet::EditItem) => selected_id(app).is_some_and(|id| {
            !app.owner_ui
                .session
                .is_unchanged(id, &app.edit_form, &app.owner_ui.edit_secrets)
                .unwrap_or(false)
        }),
        Some(Sheet::AddItem { kind_chosen: true }) => new_form_dirty(app),
        Some(Sheet::NewCredential) => {
            // The paste is erased. A paste is quick to make again; no confirmation.
            super::new_credential::forget(app, ctx);
            false
        }
        _ => false,
    };
    if dirty {
        app.ui.focus.remember_modal_origin();
        app.ui.discard_item_kind_change = false;
        app.ui.discard_item_changes = true;
        ctx.request_repaint();
    } else {
        close_sheet(app, ctx);
    }
}

pub(super) fn discard_changes_alert(app: &mut DesktopApp, ctx: &egui::Context) {
    let mut discard = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "discard-item-changes", 380.0, |ui| {
        kit::sheet_title(
            ui,
            "Discard changes?",
            Some("The changes are not saved. Discard removes the text that you typed."),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                discard = kit::button(ui, "Discard", Style::DestructiveProminent).clicked();
                cancel = kit::alert_default_button(ui, "Keep editing").clicked();
            },
        );
    });
    if cancel || response.escape {
        app.ui.discard_item_changes = false;
        app.ui.discard_item_kind_change = false;
    }
    if discard {
        app.ui.discard_item_changes = false;
        if std::mem::take(&mut app.ui.discard_item_kind_change) {
            change_kind(app, ctx);
        } else {
            close_sheet(app, ctx);
        }
    }
}

pub(super) fn add_sheet(app: &mut DesktopApp, ctx: &egui::Context, kind_chosen: bool) -> bool {
    let mut action = FormAction::None;
    let response = kit::sheet(ctx, "add-item", 500.0, |ui| {
        if !kind_chosen {
            kit::sheet_title(ui, "Add a credential", Some("What kind of secret is it?"));
            let width = (ui.available_width() - 8.0) / 2.0;
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::splat(8.0);
                for kind in CredentialKind::ALL {
                    if kind_card(ui, kind, width).clicked() {
                        action = FormAction::Pick(kind);
                    }
                }
            });
            ui.add_space(10.0);
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| {
                    if kit::button(ui, "Cancel", Style::Bordered).clicked() {
                        action = FormAction::Cancel;
                    }
                },
            );
            return;
        }
        let kind = app.add_form.kind;
        ui.horizontal(|ui| {
            let (icon, color) = kind_icon(kind);
            kit::icon_tile(ui, icon, color);
            ui.label(kit::text(new_title(kind), Font::Title3).color(kit::LABEL));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if kit::small_button(ui, "Change kind", Style::Link).clicked() {
                    action = FormAction::Back;
                }
            });
        });
        ui.add_space(12.0);
        kit::sheet_body(ui, |ui| {
            item_form(
                ui,
                &mut app.add_form,
                &mut app.owner_ui.add_secrets,
                &mut app.ui,
                "add",
                false,
                false,
            );
        });
        let tree = FolderTree::load(app);
        let label = if app
            .ui
            .create_folder
            .as_deref()
            .is_some_and(|id| tree.get(id).is_none())
        {
            "Missing Folder".to_owned()
        } else {
            tree.path_label(app.ui.create_folder.as_deref())
        };
        let options = tree.choices();
        if app
            .ui
            .create_folder
            .as_deref()
            .is_some_and(|id| tree.get(id).is_none())
        {
            kit::tone_note(
                ui,
                "The selected folder is gone. Choose another folder before adding.",
                Tone::Warning,
            );
        }
        ui.horizontal(|ui| {
            ui.label("Folder");
            super::new_credential::folder_menu(ui, &mut app.ui.create_folder, &options, &label);
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if kit::button(ui, "Add", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked()
                {
                    action = FormAction::Save;
                }
                if kit::button(ui, "Cancel", Style::Bordered).clicked() {
                    action = FormAction::Cancel;
                }
            },
        );
    });
    if kind_chosen
        && !app.ui.discard_item_changes
        && matches!(action, FormAction::None)
        && super::save_pressed(app, ctx)
    {
        action = FormAction::Save;
    }
    match action {
        FormAction::None => {}
        FormAction::Cancel => request_close_form(app, ctx),
        FormAction::Back => {
            if new_form_dirty(app) {
                app.ui.focus.remember_modal_origin();
                app.ui.discard_item_kind_change = true;
                app.ui.discard_item_changes = true;
                ctx.request_repaint();
            } else {
                change_kind(app, ctx);
            }
        }
        FormAction::Pick(kind) => {
            app.add_form.kind = kind;
            app.owner_ui.add_secrets.clear();
            app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
            // The picked card goes away. The Name field takes the focus.
            app.ui.focus_form_name = true;
        }
        FormAction::Save => {
            let draft = app.add_form.clone();
            if let Err(message) = otp::check_form(&draft, &app.owner_ui.add_secrets) {
                app.set_err(message);
                return response.escape;
            }
            // Borrow the form. A clone would be one more copy of each secret (F3).
            let folder = app.ui.create_folder.clone();
            match app.owner_ui.session.add_in_folder(
                &draft,
                &app.owner_ui.add_secrets,
                folder.as_deref(),
            ) {
                Ok(item) => {
                    app.owner_ui.add_secrets.clear();
                    forget_secret_form(ctx, "add");
                    app.add_form = ItemDraft::default();
                    app.ui.sheet = None;
                    reveal_saved(app, item.id, folder.clone());
                    let place = FolderTree::load(app).path_label(folder.as_deref());
                    app.set_ok(format!("Added {} in {place}.", item.name));
                }
                Err(err) => app.set_err(err.message),
            }
        }
    }
    response.escape
}

fn new_title(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::ApiKey => "New API key",
        CredentialKind::Login => "New login",
        CredentialKind::SshKey => "New SSH key",
        CredentialKind::Database => "New database login",
        CredentialKind::Custom => "New custom secret",
    }
}

/// A card that picks a credential kind.
fn kind_card(ui: &mut egui::Ui, kind: CredentialKind, width: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 58.0), Sense::click());
    let label = kind.label();
    let name = format!("{label}: {}", kind_blurb(kind));
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &name));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let fill = if response.is_pointer_button_down_on() {
            kit::FILL_PRESSED
        } else if response.hovered() {
            kit::FILL
        } else {
            kit::SURFACE
        };
        painter.rect_filled(rect, 10, fill);
        painter.rect_stroke(
            rect,
            10,
            egui::Stroke::new(1.0, kit::SECTION_EDGE),
            egui::StrokeKind::Inside,
        );
        let (icon, color) = kind_icon(kind);
        let tile = Rect::from_min_size(
            Pos2::new(rect.left() + 12.0, rect.center().y - 14.0),
            Vec2::splat(28.0),
        );
        kit::paint_icon_tile(painter, tile, icon, color);
        let title = kit::galley(ui, kit::medium(label, Font::Body));
        let blurb = kit::galley(ui, kit::text(kind_blurb(kind), Font::Footnote));
        let x = tile.right() + 10.0;
        painter.galley(
            Pos2::new(x, rect.center().y - title.size().y + 1.0),
            title,
            kit::LABEL,
        );
        painter.galley(Pos2::new(x, rect.center().y + 2.0), blurb, kit::SECONDARY);
        if response.has_focus() {
            kit::focus_ring(painter, rect, 10);
        }
    }
    response
}

pub(super) fn edit_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let Some(id) = selected_id(app) else {
        app.ui.sheet = None;
        return false;
    };
    let mut action = FormAction::None;
    let kind = app.edit_form.kind;
    // A login that signs in with a passkey and has no password needs no password.
    let passkey_only = kind == CredentialKind::Login
        && app
            .owner_ui
            .session
            .passkey_item(id)
            .ok()
            .flatten()
            .is_some_and(|passkey| !passkey.has_password);
    let response = kit::sheet(ctx, "edit-item", 500.0, |ui| {
        kit::sheet_title(ui, "Edit credential", Some(kind.label()));
        kit::sheet_body(ui, |ui| {
            item_form(
                ui,
                &mut app.edit_form,
                &mut app.owner_ui.edit_secrets,
                &mut app.ui,
                "edit",
                true,
                passkey_only,
            );
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if kit::button(ui, "Save", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked()
                {
                    action = FormAction::Save;
                }
                if kit::button(ui, "Cancel", Style::Bordered).clicked() {
                    action = FormAction::Cancel;
                }
            },
        );
    });
    if !app.ui.discard_item_changes
        && matches!(action, FormAction::None)
        && super::save_pressed(app, ctx)
    {
        action = FormAction::Save;
    }
    match action {
        FormAction::Cancel => request_close_form(app, ctx),
        FormAction::Save => save_edit(app, ctx, id),
        _ => {}
    }
    response.escape
}

fn save_edit(app: &mut DesktopApp, ctx: &egui::Context, id: u64) {
    let draft = app.edit_form.clone();
    if let Err(message) = otp::check_form(&draft, &app.owner_ui.edit_secrets) {
        app.set_err(message);
        return;
    }
    let revision = app.owner_ui.edit_revision;
    let unchanged = app
        .owner_ui
        .session
        .is_unchanged(id, &draft, &app.owner_ui.edit_secrets)
        .unwrap_or(false);
    if unchanged {
        close_sheet(app, ctx);
        app.set_note("There are no changes to save.");
        return;
    }
    match app
        .owner_ui
        .session
        .update(id, revision, &draft, &app.owner_ui.edit_secrets)
    {
        Ok(summary) => {
            app.owner_ui.edit_secrets.clear();
            forget_secret_form(ctx, "edit");
            app.owner_ui.edit_revision = summary.revision;
            app.pending_delete = false;
            // The item changed, so the suggestion can change (goal item B4).
            app.owner_ui.declaration_form = app
                .owner_ui
                .session
                .declaration_form(id)
                .unwrap_or_default();
            app.ui.sheet = None;
            app.set_ok("The credential is updated.");
        }
        Err(err) => app.set_err(err.message),
    }
}

/// The fields of the add and edit sheets. The add sheet asks for the secret with the
/// name. The edit sheet keeps a blank secret. `passkey_only`: the stored login signs in
/// with a passkey and has no password, so a blank password is valid.
fn item_form(
    ui: &mut egui::Ui,
    form: &mut ItemDraft,
    secrets: &mut SecretForm,
    state: &mut UiState,
    salt: &str,
    editing: bool,
    passkey_only: bool,
) {
    let kind = form.kind;
    if !editing {
        kit::note(
            ui,
            match kind {
                CredentialKind::Login => {
                    "Required: Name, Username, Password. Website is needed for browser filling (https://example.com)."
                }
                CredentialKind::ApiKey => "Required: Name and API token.",
                CredentialKind::SshKey => "Required: Name and private key. Passphrase is optional.",
                CredentialKind::Database => "Required: Name, Host, Database, Username, Password.",
                CredentialKind::Custom => {
                    "Required: Name, field name (letters, digits, underscores), and value."
                }
            },
        );
    }
    let focus_name = std::mem::take(&mut state.focus_form_name);
    // A setup key is never a plain detail: hide it before the first draw.
    otp::protect_form(ui.ctx(), salt, form, secrets);
    kit::section(ui, None, None, |s| {
        s.field("Name", |ui| {
            let field = kit::text_input(
                ui,
                &mut form.name,
                &format!("{salt}-name"),
                name_placeholder(kind),
            );
            // Also for a pointer user: after the pick of a kind, the owner types the
            // name next.
            if focus_name {
                field.request_focus();
            }
            field
        });
        for field in DesktopModel::extra_fields(kind) {
            let (value, placeholder) = extra_value(form, *field);
            s.field(extra_label(*field), |ui| {
                kit::text_input(ui, value, &format!("{salt}-{field:?}"), placeholder)
            });
        }
        if !editing {
            secret_rows(s, salt, kind, secrets, "Required");
            otp::form_row(s, salt, form, secrets);
        }
    });
    if editing {
        let (footer, placeholder) = if passkey_only {
            (
                "This login signs in with a passkey. A password is optional. Apassy keeps the passkey when you save.",
                "Optional",
            )
        } else {
            ("Leave a field blank to keep the stored value.", "Unchanged")
        };
        kit::section(ui, Some("Secret"), Some(footer), |s| {
            secret_rows(s, salt, kind, secrets, placeholder);
            otp::form_row(s, salt, form, secrets);
        });
    }
    let agent_key = format!("{salt}-agent-fields");
    let mut agent_open =
        state.is_expanded(&agent_key) || !form.service.is_empty() || !form.project.is_empty();
    if kit::disclosure(ui, &mut agent_open, "Agent Settings (Optional)").changed() {
        state.set_expanded(&agent_key, agent_open);
    }
    if agent_open {
        kit::section(
            ui,
            Some("Where it is used"),
            Some("Apassy suggests safe agent settings from the service and the project."),
            |s| {
                s.field("Service", |ui| {
                    kit::text_input(
                        ui,
                        &mut form.service,
                        &format!("{salt}-service"),
                        "stripe, github, supabase…",
                    )
                });
                s.field("Project", |ui| {
                    kit::text_input(ui, &mut form.project, &format!("{salt}-project"), "shop")
                });
            },
        );
    }
    detail_rows(ui, form, secrets, salt);
    let key = format!("{salt}-notes");
    let mut open = state.is_expanded(&key) || !form.notes.is_empty();
    if kit::disclosure(ui, &mut open, "Notes").changed() {
        state.set_expanded(&key, open);
    }
    if open {
        ui.add_space(4.0);
        kit::text_area(
            ui,
            &mut form.notes,
            &format!("{salt}-notes"),
            "Anything you want to remember",
            3,
        );
    }
}

/// The custom details of a form. A hidden value goes in the secret form, with the same
/// fixed buffer and erase rules as the secret (key-memory review F1, F3, F4).
fn detail_rows(ui: &mut egui::Ui, form: &mut ItemDraft, secrets: &mut SecretForm, salt: &str) {
    let ctx = ui.ctx().clone();
    let mut remove = None;
    // The login form edits its one-time password in the secret rows.
    let dedicated = otp::dedicated_slot(form);
    if form.details.len() > usize::from(dedicated.is_some()) {
        kit::section(
            ui,
            Some("Custom details"),
            Some(
                "A hidden detail is masked, and showing it needs your passphrase. For a hidden detail that is stored, leave the value blank to keep it.",
            ),
            |s| {
                s.row(|ui| {
                    ui.horizontal(|ui| {
                        let caption =
                            |text: &str| kit::text(text, Font::Footnote).color(kit::SECONDARY);
                        ui.allocate_ui(Vec2::new(150.0, 14.0), |ui| {
                            ui.set_min_width(150.0);
                            ui.label(caption("Name"));
                        });
                        let width = (ui.available_width() - 92.0).max(120.0);
                        ui.allocate_ui(Vec2::new(width, 14.0), |ui| {
                            ui.set_min_width(width);
                            ui.label(caption("Value"));
                        });
                        ui.label(caption("Hidden"));
                    });
                });
                for (index, detail) in form.details.iter_mut().enumerate() {
                    if dedicated == Some(index) {
                        continue;
                    }
                    // VoiceOver names each field of the row, as the captions above do.
                    let row_name = if detail.label.trim().is_empty() {
                        format!("detail {}", index + 1)
                    } else {
                        format!("\"{}\"", detail.label.trim())
                    };
                    let name_label = |ctx: &egui::Context, id: egui::Id, text: String| {
                        ctx.accesskit_node_builder(id, |node| node.set_label(text));
                    };
                    s.row(|ui| {
                        ui.horizontal(|ui| {
                            let name_field = ui.allocate_ui(Vec2::new(150.0, 26.0), |ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut detail.label)
                                        .id_salt(format!("{salt}-detail-label-{index}"))
                                        .hint_text(
                                            kit::text("Name", Font::Body).color(kit::TERTIARY),
                                        )
                                        .char_limit(
                                            crate::desktop::owner_store::MAX_DETAIL_LABEL_BYTES,
                                        )
                                        .margin(kit::FIELD_MARGIN)
                                        .desired_width(f32::INFINITY),
                                )
                            });
                            name_label(
                                ui.ctx(),
                                name_field.inner.id,
                                format!("Name of {row_name}"),
                            );
                            // A label like "OTP" makes the detail hidden before its value is drawn.
                            let mut protected = otp::hide_setup_key(
                                ui.ctx(),
                                salt,
                                index,
                                detail,
                                &mut secrets.details[index],
                            );
                            let width = (ui.available_width() - 92.0).max(120.0);
                            let value_field = ui.allocate_ui(Vec2::new(width, 26.0), |ui| {
                                if detail.hidden {
                                    let placeholder = if detail.stored.is_some() {
                                        "Unchanged"
                                    } else {
                                        "Value"
                                    };
                                    secure_input(
                                        ui,
                                        &format!("{salt}-detail-{index}"),
                                        &mut secrets.details[index],
                                        SECRET_VALUE_CAPACITY,
                                        placeholder,
                                    )
                                } else {
                                    kit::text_input(
                                        ui,
                                        &mut detail.value,
                                        &format!("{salt}-detail-value-{index}"),
                                        "Value",
                                    )
                                }
                            });
                            name_label(
                                ui.ctx(),
                                value_field.inner.id,
                                format!("Value of {row_name}"),
                            );
                            // A pasted otpauth link hides the detail. The frame is drawn
                            // again, so the link is never painted.
                            protected |= otp::hide_setup_key(
                                ui.ctx(),
                                salt,
                                index,
                                detail,
                                &mut secrets.details[index],
                            );
                            if protected {
                                ui.ctx().request_discard("A setup key is hidden");
                                ui.ctx().request_repaint();
                            }
                            let mut hidden = detail.hidden;
                            let locked = otp::is_locked_hidden(detail);
                            let switch = ui
                                .add_enabled_ui(!locked, |ui| {
                                    kit::toggle(ui, &mut hidden, &format!("Hidden: {row_name}"))
                                        .on_hover_text(if locked {
                                            "A one-time password is always hidden"
                                        } else {
                                            "Hidden: masked, and showing it needs your passphrase"
                                        })
                                })
                                .inner;
                            if switch.changed() && !locked {
                                set_hidden(detail, &mut secrets.details[index], hidden);
                            }
                            if kit::icon_button(
                                ui,
                                Icon::Xmark,
                                &format!("Remove {row_name}"),
                                Size::Small,
                            )
                            .clicked()
                            {
                                remove = Some(index);
                            }
                        });
                    });
                }
            },
        );
    }
    if let Some(index) = remove {
        form.details.remove(index);
        secrets.remove_detail(index);
        // The rows moved, so no field keeps an undo history of another row (F1).
        for index in 0..MAX_DETAILS {
            forget_secret_field(&ctx, &format!("{salt}-detail-{index}"));
        }
    }
    if form.details.len() < MAX_DETAILS
        && kit::button_with(
            ui,
            Some(Icon::Plus),
            "Add custom detail",
            Style::Link,
            Size::Small,
        )
        .clicked()
    {
        form.details.push(DetailDraft::default());
    }
    ui.add_space(10.0);
}

/// Make a detail hidden or visible. A typed value moves with it, so the owner does not
/// type it again. A value that moves out of the secret buffer is erased there.
pub(super) fn set_hidden(detail: &mut DetailDraft, secret: &mut String, hidden: bool) {
    use zeroize::Zeroize;

    detail.hidden = hidden;
    if hidden {
        secret.push_str(detail.value.trim());
        detail.value.zeroize();
    } else {
        detail.value.push_str(secret);
        secret.zeroize();
        detail.stored = None;
    }
}

fn name_placeholder(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::ApiKey => "Stripe live key",
        CredentialKind::Login => "GitHub",
        CredentialKind::SshKey => "Deploy key",
        CredentialKind::Database => "Production Postgres",
        CredentialKind::Custom => "Webhook secret",
    }
}

fn extra_value(form: &mut ItemDraft, field: ExtraField) -> (&mut String, &'static str) {
    match field {
        ExtraField::Username => (&mut form.username, "name@example.com"),
        ExtraField::Website => (&mut form.website, "https://example.com/login"),
        ExtraField::Host => (&mut form.host, "db.example.com"),
        ExtraField::DatabaseName => (&mut form.database_name, "app"),
        ExtraField::FieldName => (&mut form.field_name, "webhook_secret"),
        ExtraField::PublicLabel => (&mut form.public_label, "Optional"),
    }
}

/// The secret fields of one credential kind, as form rows.
pub(super) fn secret_rows(
    s: &mut Section<'_>,
    salt: &str,
    kind: CredentialKind,
    secrets: &mut SecretForm,
    placeholder: &str,
) {
    let cap = SECRET_VALUE_CAPACITY;
    let row = |s: &mut Section<'_>, label: &str, field: &str, value: &mut String, hint: &str| {
        s.field(label, |ui| {
            secure_input(ui, &format!("{salt}-{field}"), value, cap, hint)
        });
    };
    match kind {
        CredentialKind::ApiKey => row(s, "Token", "token", &mut secrets.token, placeholder),
        CredentialKind::Login | CredentialKind::Database => {
            row(
                s,
                "Password",
                "password",
                &mut secrets.password,
                placeholder,
            );
        }
        CredentialKind::SshKey => {
            row(
                s,
                "Private key",
                "private",
                &mut secrets.private_key,
                placeholder,
            );
            let optional = if placeholder == "Required" {
                "Optional"
            } else {
                placeholder
            };
            row(
                s,
                "Key passphrase",
                "phrase",
                &mut secrets.key_passphrase,
                optional,
            );
        }
        CredentialKind::Custom => {
            row(
                s,
                "Secret value",
                "custom",
                &mut secrets.custom_value,
                placeholder,
            );
        }
    }
}

// ---- The passkey. ----

/// The label of the removal action. Without a password the vault deletes the whole login,
/// and the action says so.
const REMOVE_PASSKEY: &str = "Remove passkey";
const DELETE_LOGIN: &str = "Delete login";

/// The passkey of a login, for the page. `None` for another kind and for a login
/// without a passkey. It has no key: the vault gives only the metadata.
fn passkey_of(app: &DesktopApp, details: &OwnerDetails) -> Option<PasskeyItem> {
    if details.kind != CredentialKind::Login {
        return None;
    }
    app.owner_ui.session.passkey_item(details.id).ok().flatten()
}

/// The credential ID for the screen: the first characters of its base64url text.
fn short_credential_id(id: &[u8]) -> String {
    let text = crate::vault::passkey::b64url_encode(id);
    if text.chars().count() <= 16 {
        return text;
    }
    let head: String = text.chars().take(10).collect();
    let tail: String = text.chars().skip(text.chars().count() - 4).collect();
    format!("{head}…{tail}")
}

/// The metadata of the passkey and the one action. The page never shows the private key.
/// The generic Show and Hide of the credential do not touch it. The relying party, the
/// account, and the display name come from a website or from macOS, so the page cleans
/// them like the owner check dialog does.
fn passkey_section(ui: &mut egui::Ui, details: &OwnerDetails, passkey: &PasskeyItem) {
    let info = &passkey.info;
    let account = page_text(&info.user_name);
    let display = page_text(&info.user_display_name);
    let mut remove = false;
    kit::section(
        ui,
        Some("Passkey"),
        Some(
            "The private key stays in the vault. This page cannot show it, copy it, or set it up again.",
        ),
        |s| {
            value_row(s, "Website", &page_text(&info.rp_id));
            if !account.is_empty() {
                value_row(s, "Account", &account);
            }
            if !display.is_empty() && display != account {
                value_row(s, "Display name", &display);
            }
            value_row(
                s,
                "Credential ID",
                &short_credential_id(&info.credential_id),
            );
            let (label, note, color) = if passkey.has_password {
                (
                    format!("{REMOVE_PASSKEY}…"),
                    "Apassy keeps the password and the other fields.",
                    kit::LABEL,
                )
            } else {
                (
                    format!("{DELETE_LOGIN}…"),
                    "This login has no password. Apassy deletes the whole login.",
                    Tone::Critical.text(),
                )
            };
            remove = s
                .clickable_row(&label, |ui| {
                    ui.label(kit::text(&label, Font::Body).color(color));
                    kit::note(ui, note);
                })
                .clicked();
        },
    );
    if remove {
        remember_removal(
            ui.ctx(),
            Removal {
                item_id: details.id,
                revision: details.revision,
                name: details.name.clone(),
                delete_login: !passkey.has_password,
            },
        );
    }
}

/// What the owner saw when the removal sheet opened. The owner check asks for exactly this.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Removal {
    item_id: u64,
    revision: u64,
    name: String,
    /// The vault deletes the whole login: the login has no password.
    delete_login: bool,
}

fn removal_key() -> egui::Id {
    egui::Id::new("apassy-passkey-removal")
}

fn remember_removal(ctx: &egui::Context, removal: Removal) {
    ctx.data_mut(|data| data.insert_temp(removal_key(), removal));
}

fn forget_removal(ctx: &egui::Context) {
    ctx.data_mut(|data| data.remove::<Removal>(removal_key()));
}

/// The confirmation before the owner check. The sheet shows what the vault will do. A
/// change of the login while the sheet is open closes it: the owner must read the warning
/// again. The confirmation asks for the owner check with the revision and the name that
/// the sheet showed; the vault checks the revision again.
fn removal_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    details: &OwnerDetails,
    passkey: Option<&PasskeyItem>,
) {
    let Some(removal) = ctx.data(|data| data.get_temp::<Removal>(removal_key())) else {
        return;
    };
    let now = passkey.map(|passkey| (details.revision, !passkey.has_password));
    if removal.item_id != details.id {
        forget_removal(ctx);
        return;
    }
    if now != Some((removal.revision, removal.delete_login)) {
        forget_removal(ctx);
        app.set_err("The login changed. Select the action again and read the warning.");
        return;
    }
    let shown = page_text(&removal.name);
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "remove-passkey", 420.0, |ui| {
        if removal.delete_login {
            kit::sheet_title(ui, "Delete this login?", None);
            kit::paragraph(
                ui,
                format!(
                    "The login “{shown}” has a passkey and no password. Apassy cannot keep a login with neither. So Apassy deletes the whole login."
                ),
                Font::Callout,
                kit::LABEL,
            );
            ui.add_space(8.0);
            kit::paragraph(
                ui,
                "You lose the passkey and all other fields: notes, tags, website, one-time passwords, custom details, agent access, and history. Your other devices lose them too after sync. You cannot undo this.",
                Font::Callout,
                kit::SECONDARY,
            );
            ui.add_space(8.0);
            kit::paragraph(
                ui,
                "To keep the fields, press Cancel. Then add a password to the login, or archive the login.",
                Font::Callout,
                kit::SECONDARY,
            );
        } else {
            kit::sheet_title(ui, "Remove this passkey?", None);
            kit::paragraph(
                ui,
                format!(
                    "Apassy deletes the passkey of the login “{shown}”. The password and the other fields stay. You cannot undo this."
                ),
                Font::Callout,
                kit::LABEL,
            );
            ui.add_space(8.0);
            kit::paragraph(
                ui,
                "The website can still list the passkey. Remove it on the website too.",
                Font::Callout,
                kit::SECONDARY,
            );
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                let label = if removal.delete_login {
                    DELETE_LOGIN
                } else {
                    REMOVE_PASSKEY
                };
                confirm = kit::button(ui, label, Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if cancel || response.escape {
        forget_removal(ctx);
    } else if confirm {
        forget_removal(ctx);
        // The owner check names this item, this revision, and this branch. No vault call
        // happens here.
        app.ask_owner(
            OwnerRequest::RemovePasskey {
                item_id: removal.item_id,
                revision: removal.revision,
                name: removal.name,
                delete_login: removal.delete_login,
            },
            Some(ctx),
        );
    }
}

// ---- Agent settings sheets. ----

pub(super) fn declaration_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let Some(id) = selected_id(app) else {
        app.ui.sheet = None;
        return false;
    };
    let stats = app.owner_ui.session.suggestion_stats().ok();
    let mut save = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "declaration", 560.0, |ui| {
        kit::sheet_title(
            ui,
            "Declaration",
            Some(
                "How sensitive is this credential? The bouncer uses these values for each agent request. Production, high risk, or irreversible means that a command that changes state waits for you.",
            ),
        );
        kit::sheet_body(ui, |ui| {
            let form = &mut app.owner_ui.declaration_form;
            if !form.stored {
                let detail = if form.suggestion.is_some() {
                    "Apassy suggests the values below from the item. Confirm or change each value, then save."
                } else {
                    "Apassy found no signal in the item. The form starts with the most sensitive values."
                };
                kit::notice(
                    ui,
                    Tone::Warning,
                    "Not saved yet",
                    Some("No declaration. Every agent run with this item waits for you."),
                    |ui| kit::note(ui, detail),
                );
            }
            declaration_form(ui, form, id);
            let reasons = suggestion_reasons(form);
            if !reasons.is_empty() {
                let mut open = app.ui.is_expanded(WHY);
                if kit::disclosure(ui, &mut open, "Why these values?").changed() {
                    app.ui.set_expanded(WHY, open);
                }
                if open {
                    ui.add_space(4.0);
                    kit::section(ui, None, None, |s| {
                        for reason in &reasons {
                            s.row(|ui| kit::paragraph(ui, reason, Font::Callout, kit::LABEL));
                        }
                    });
                } else {
                    ui.add_space(10.0);
                }
            }
            kit::note(ui, acceptance_text(stats.as_ref()));
        });
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                save = kit::button(ui, "Save", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    save |= super::save_pressed(app, ctx);
    if save {
        let form = app.owner_ui.declaration_form.clone();
        if form.project.trim().is_empty() {
            app.set_err("Type the project name.");
        } else {
            // The declaration is a rule input for the bouncer (goal item A4).
            ask_owner_from_sheet(
                app,
                OwnerRequest::SaveDeclaration { item_id: id, form },
                ctx,
            );
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// The disclosure key of the suggestion reasons.
const WHY: &str = "declaration-why";

/// The distinct reasons of the suggestion, one per line.
fn suggestion_reasons(form: &DeclarationForm) -> Vec<String> {
    let Some(suggestion) = &form.suggestion else {
        return Vec::new();
    };
    let mut reasons: Vec<String> = Vec::new();
    let mut push = |reason: &str| {
        let reason = reason.trim();
        if !reason.is_empty() && !reasons.iter().any(|known| known == reason) {
            reasons.push(reason.to_owned());
        }
    };
    push(&suggestion.provider_reason);
    if let Some(value) = &suggestion.environment {
        push(&value.reason);
    }
    if let Some(value) = &suggestion.risk {
        push(&value.reason);
    }
    if let Some(value) = &suggestion.scope {
        push(&value.reason);
    }
    if let Some(value) = &suggestion.reversibility {
        push(&value.reason);
    }
    reasons
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

fn options<T: Copy>(values: &[T], text: fn(T) -> &'static str) -> Vec<(T, String)> {
    values
        .iter()
        .map(|value| (*value, title_case(text(*value))))
        .collect()
}

/// The declaration fields (goal item B4). A field shows a hint only when the owner
/// changed the suggested value or the signals disagree.
fn declaration_form(ui: &mut egui::Ui, form: &mut DeclarationForm, id: u64) {
    let provider_hint = provider_hint(form);
    let suggestion = form.suggestion.clone().unwrap_or_default();
    let hints = [
        value_hint(
            suggestion.environment.as_ref(),
            form.environment,
            Environment::as_str,
        ),
        value_hint(suggestion.risk.as_ref(), form.risk, RiskLevel::as_str),
        value_hint(suggestion.scope.as_ref(), form.scope, Scope::as_str),
        value_hint(
            suggestion.reversibility.as_ref(),
            form.reversibility,
            Reversibility::as_str,
        ),
    ];
    let hint = |index: usize| {
        hints[index]
            .as_ref()
            .map(|(text, tone)| (text.as_str(), *tone))
    };
    kit::section(
        ui,
        None,
        Some(
            "A command that sends the secret of this item to a host outside the known hosts of its provider and the global list waits for you.",
        ),
        |s| {
            s.field("Project", |ui| {
                kit::text_input(ui, &mut form.project, "decl-project", "odealo")
            });
            let provider_tone = if provider_hint.contains("You changed it.") {
                Tone::Warning
            } else {
                Tone::Neutral
            };
            s.field_with_hint("Provider", Some((&provider_hint, provider_tone)), |ui| {
                provider_picker(ui, form, id)
            });
            let environment = options(Environment::ALL, Environment::as_str);
            s.field_with_hint("Environment", hint(0), |ui| {
                segmented(ui, ("decl-env", id), &mut form.environment, &environment)
            });
            let risk = options(RiskLevel::ALL, RiskLevel::as_str);
            s.field_with_hint("Risk", hint(1), |ui| {
                segmented(ui, ("decl-risk", id), &mut form.risk, &risk)
            });
            let scope = options(Scope::ALL, Scope::as_str);
            s.field_with_hint("Scope", hint(2), |ui| {
                segmented(ui, ("decl-scope", id), &mut form.scope, &scope)
            });
            let reversibility = options(Reversibility::ALL, Reversibility::as_str);
            s.field_with_hint("Reversibility", hint(3), |ui| {
                segmented(
                    ui,
                    ("decl-rev", id),
                    &mut form.reversibility,
                    &reversibility,
                )
            });
        },
    );
}

fn segmented<T: PartialEq + Copy>(
    ui: &mut egui::Ui,
    salt: impl std::hash::Hash + std::fmt::Debug,
    value: &mut T,
    options: &[(T, String)],
) -> egui::Response {
    let options: Vec<(T, &str)> = options
        .iter()
        .map(|(value, label)| (*value, label.as_str()))
        .collect();
    kit::segmented(ui, salt, value, &options)
}

fn provider_picker(ui: &mut egui::Ui, form: &mut DeclarationForm, id: u64) -> egui::Response {
    let selected = form
        .provider
        .as_deref()
        .and_then(providers::find)
        .map_or("None", |provider| provider.label.as_str());
    let selected = selected.to_owned();
    let mut options = vec![(None, "None".to_owned())];
    if let Ok(catalog) = providers::builtin() {
        options.extend(
            catalog
                .providers()
                .iter()
                .map(|provider| (Some(provider.id.clone()), provider.label.clone())),
        );
    }
    kit::picker(
        ui,
        ("decl-provider", id),
        &mut form.provider,
        &options,
        selected,
        220.0,
    )
}

/// The known hosts of the chosen provider, and the suggested provider when the owner
/// chose another one.
fn provider_hint(form: &DeclarationForm) -> String {
    let provider = form.provider.as_deref().and_then(providers::find);
    let hosts = match provider {
        Some(provider) if !provider.known_hosts.is_empty() => format!(
            "Known hosts of {}: {}.",
            provider.label,
            provider.known_hosts.join(", ")
        ),
        Some(provider) => format!("{} has no known hosts.", provider.label),
        None => "No provider. Apassy uses the global known hosts only.".to_owned(),
    };
    let suggested = form
        .suggestion
        .as_ref()
        .and_then(|suggestion| suggestion.provider.as_ref())
        .filter(|id| form.provider.as_ref() != Some(*id));
    match suggested {
        Some(id) => {
            let label = providers::find(id).map_or(id.as_str(), |provider| provider.label.as_str());
            format!("{hosts} Apassy suggested {label}. You changed it.")
        }
        None => hosts,
    }
}

/// A hint when the value differs from the suggestion, or when signals disagree.
fn value_hint<T: Copy + PartialEq>(
    suggested: Option<&Suggested<T>>,
    current: T,
    text: fn(T) -> &'static str,
) -> Option<(String, Tone)> {
    let suggested = suggested?;
    if suggested.value != current {
        return Some((
            format!(
                "Apassy suggested {}. You changed it.",
                text(suggested.value)
            ),
            Tone::Warning,
        ));
    }
    suggested.conflict.then(|| {
        (
            format!("Signals disagree. {}", suggested.reason),
            Tone::Warning,
        )
    })
}

/// The share of suggested declarations that the owner saved without a change.
fn acceptance_text(stats: Option<&crate::vault::SuggestionStats>) -> String {
    let Some(stats) = stats.filter(|stats| stats.total > 0) else {
        return "No suggested declaration is saved yet. Apassy counts the first save of each item."
            .to_owned();
    };
    let changed: Vec<String> = stats
        .changed
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(field, count)| format!("{} {count}", field.as_str()))
        .collect();
    let mut text = format!(
        "Suggested declarations saved without a change: {} of {} ({:.0}%).",
        stats.accepted,
        stats.total,
        stats.share().unwrap_or_default() * 100.0
    );
    if !changed.is_empty() {
        text.push_str(&format!(" Changed fields: {}.", changed.join(", ")));
    }
    text
}

pub(super) fn variable_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let Some(id) = selected_id(app) else {
        app.ui.sheet = None;
        return false;
    };
    let fields = app.owner_ui.session.secret_fields(id).unwrap_or_default();
    if fields.is_empty() {
        app.ui.sheet = None;
        return false;
    }
    if !fields.contains(&app.owner_ui.env_field_input) {
        app.owner_ui.env_field_input = fields[0].clone();
    }
    let current = app.owner_ui.session.env_binding(id).ok().flatten();
    let mut save = false;
    let mut cancel = false;
    let mut remove = false;
    let response = kit::sheet(ctx, "variable", 480.0, |ui| {
        kit::sheet_title(
            ui,
            "Command settings",
            Some(
                "Choose the secret field and how commands use it. A variable name is optional. The agent never receives the value.",
            ),
        );
        kit::section(
            ui,
            None,
            Some(
                "Leave the variable name empty for automatic use. Set a name only when a command needs a specific one.",
            ),
            |s| {
                s.field("Variable name (optional)", |ui| {
                    kit::mono_input(
                        ui,
                        &mut app.owner_ui.env_name_input,
                        "env-name",
                        "Automatic",
                    )
                });
                if fields.len() > 1 {
                    s.field("Secret field", |ui| {
                        let options: Vec<(String, String)> = fields
                            .iter()
                            .map(|field| (field.clone(), field_label(field)))
                            .collect();
                        let selected = field_label(&app.owner_ui.env_field_input);
                        kit::picker(
                            ui,
                            ("env-field", id),
                            &mut app.owner_ui.env_field_input,
                            &options,
                            selected,
                            220.0,
                        )
                    });
                }
            },
        );
        let placeholder = app.owner_ui.env_placeholder_input;
        kit::section(
            ui,
            Some("What the program gets"),
            Some(if placeholder {
                PLACEHOLDER_HINT
            } else {
                REAL_VALUE_HINT
            }),
            |s| {
                s.field("Value", |ui| {
                    kit::segmented(
                        ui,
                        ("env-delivery", id),
                        &mut app.owner_ui.env_placeholder_input,
                        &[(true, "Placeholder"), (false, "Real value")],
                    )
                });
                if placeholder {
                    s.field("Hosts", |ui| {
                        kit::text_input(
                            ui,
                            &mut app.owner_ui.env_hosts_input,
                            "env-hosts",
                            "api.example.com",
                        )
                    });
                }
            },
        );
        kit::sheet_buttons(
            ui,
            |ui| {
                if current.is_some() {
                    remove = kit::button(ui, "Remove variable", Style::Destructive).clicked();
                }
            },
            |ui| {
                save = kit::button(ui, "Save", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    save |= super::save_pressed(app, ctx);
    if save {
        let env_name = app.owner_ui.env_name_input.trim().to_owned();
        let field = app.owner_ui.env_field_input.clone();
        let delivery = if app.owner_ui.env_placeholder_input {
            EnvDelivery::Placeholder(host_list(&app.owner_ui.env_hosts_input))
        } else {
            EnvDelivery::Value
        };
        let hosts_ok = match &delivery {
            EnvDelivery::Value => true,
            EnvDelivery::Placeholder(hosts) => {
                !hosts.is_empty()
                    && hosts.len() <= crate::vault::MAX_PLACEHOLDER_HOSTS
                    && hosts
                        .iter()
                        .all(|host| crate::vault::parse_placeholder_host(host).is_some())
            }
        };
        if !env_name.is_empty() && crate::vault::checked_env_name(&env_name).is_err() {
            app.set_err("Use A-Z, 0-9, and _ and start with a letter or _. System names such as PATH or DYLD_* are not permitted.");
        } else if !hosts_ok {
            app.set_err("Name 1 to 16 hosts, such as api.stripe.com or api.example.com:8443, separated by commas.");
        } else {
            // The variable decides which secret a process gets (goal item A4).
            ask_owner_from_sheet(
                app,
                OwnerRequest::SaveVariable {
                    item_id: id,
                    env_name,
                    field,
                    delivery,
                },
                ctx,
            );
        }
    }
    if remove {
        let result = app.owner_ui.session.clear_env_binding(id);
        if app
            .apply(result, "The variable and its process grants are removed.")
            .is_some()
        {
            app.owner_ui.env_name_input.clear();
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

const PLACEHOLDER_HINT: &str = "The program gets a placeholder with the form of the key. Apassy puts the real value into HTTPS requests to these hosts and their subdomains, and nowhere else. On macOS the program reaches the network only through Apassy. The program must read HTTPS_PROXY: curl, Python, Node, and most SDKs do. Go programs on macOS (gh, the Stripe CLI) do not trust Apassy yet, so use the real value for them.";

const REAL_VALUE_HINT: &str = "The program gets the real value. It can print it, save it, or send it to any host. The output shows [apassy:NAME] in place of the value.";

/// Hosts from the text of the owner: separated by commas, spaces, or lines.
pub(super) fn host_list(text: &str) -> Vec<String> {
    text.split([',', ' ', '\n'])
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

pub(super) fn connector_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let Some(id) = selected_id(app) else {
        app.ui.sheet = None;
        return false;
    };
    let current = app.owner_ui.session.connector(id).ok().flatten();
    let mut save = false;
    let mut cancel = false;
    let mut remove = false;
    let response = kit::sheet(ctx, "connector", 480.0, |ui| {
        kit::sheet_title(
            ui,
            "Connector",
            Some(
                "The broker adds this token to requests for permitted agents. The agent never receives the token.",
            ),
        );
        kit::section(
            ui,
            None,
            Some(
                "Use https://, or http:// on this computer only. The broker does not follow redirects. The app has no switch for an operation: let an agent use one with apassy grant operation AGENT ITEM OPERATION.",
            ),
            |s| {
                s.labeled(
                    "Profile",
                    kit::text(REPORTING_API_V0.label, Font::Body).color(kit::SECONDARY),
                );
                s.field("Address", |ui| {
                    kit::text_input(
                        ui,
                        &mut app.owner_ui.connector_url,
                        "connector-url",
                        "http://127.0.0.1:8787",
                    )
                });
            },
        );
        kit::sheet_buttons(
            ui,
            |ui| {
                if current.is_some() {
                    remove = kit::button(ui, "Remove connector", Style::Destructive).clicked();
                }
            },
            |ui| {
                save = kit::button(ui, "Save", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    save |= super::save_pressed(app, ctx);
    if save {
        let base_url = app.owner_ui.connector_url.trim().to_owned();
        match crate::broker::http::parse_destination(&base_url) {
            // The connector decides where the token goes (goal item A4).
            Ok(_) => ask_owner_from_sheet(
                app,
                OwnerRequest::SaveConnector {
                    item_id: id,
                    base_url,
                },
                ctx,
            ),
            Err(message) => app.set_err(message),
        }
    }
    if remove {
        let result = app.owner_ui.session.clear_connector(id);
        if app
            .apply(result, "The connector and its grants are removed.")
            .is_some()
        {
            app.owner_ui.connector_url.clear();
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

#[cfg(test)]
mod conflict_tests {
    use super::*;
    use crate::broker::approvals::OwnerCheck;
    use crate::desktop::owner_store::SecretForm;
    use crate::vault::{Field, ItemDraft as VaultDraft, SecretValue, SyncScope, Vault};

    const PASS: &str = "conflict-ui-test-pass";
    const CANARY: &str = "conflict-ui-secret-canary";

    #[test]
    fn command_and_shift_selection_follow_the_visible_order() {
        let visible = [8, 2, 14, 6, 9];
        let mut selected = std::collections::BTreeSet::new();
        let mut anchor = None;
        super::update_selection(&mut selected, &mut anchor, &visible, 2, false, false);
        super::update_selection(&mut selected, &mut anchor, &visible, 6, false, true);
        assert_eq!(selected, [2, 14, 6].into_iter().collect());
        super::update_selection(&mut selected, &mut anchor, &visible, 14, true, false);
        assert_eq!(selected, [2, 6].into_iter().collect());
        super::update_selection(&mut selected, &mut anchor, &visible, 9, true, false);
        assert_eq!(selected, [2, 6, 9].into_iter().collect());
    }

    #[test]
    fn conflict_filter_separates_verified_copies_and_preserves_search() {
        let matches = |filter, searching, archived, conflict| {
            matches_filter(filter, searching, archived, conflict)
        };
        // A user-selected name cannot make an ordinary archived item a conflict.
        assert!(matches(Filter::Archived, false, true, false));
        assert!(!matches(Filter::Conflicts, true, true, false));
        assert!(matches(Filter::Conflicts, false, true, true));
        assert!(!matches(Filter::Archived, true, true, true));
        assert!(!matches(Filter::All, false, true, true));
        assert!(matches(Filter::All, true, true, true));
        // A deliberate restore removes the copy from the archived review list.
        assert!(!matches(Filter::Conflicts, false, false, true));
        assert!(matches(Filter::All, false, false, true));
    }

    fn add(app: &mut DesktopApp, name: &str) -> u64 {
        let mut secrets = SecretForm::default();
        secrets.token = CANARY.to_owned();
        app.owner_ui
            .session
            .add(
                &ItemDraft {
                    name: name.to_owned(),
                    ..ItemDraft::default()
                },
                &secrets,
            )
            .expect("add synthetic credential")
            .id
    }

    fn text(app: &mut DesktopApp, detail: bool) -> String {
        fn collect(shape: &egui::Shape, text: &mut String) {
            match shape {
                egui::Shape::Text(shape) => {
                    text.push_str(shape.galley.text());
                    text.push('\n');
                }
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, text)),
                _ => {}
            }
        }
        let ctx = egui::Context::default();
        let mut text = String::new();
        for _ in 0..3 {
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(1280.0, 2400.0))),
                    ..Default::default()
                },
                |ui| {
                    if detail {
                        draw_detail(app, ui);
                    } else {
                        list_column(app, ui);
                        detail_column(app, ui, &Vec::new());
                    }
                },
            );
            text.clear();
            for shape in &output.shapes {
                collect(&shape.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        assert!(
            !text.contains(CANARY),
            "a secret entered the conflict summary"
        );
        text
    }

    #[test]
    fn retained_conflicts_stay_visible_after_reopen_and_show_both_versions() {
        let dir = tempfile::TempDir::new().expect("synthetic files only");
        let path = dir.path().join("owner.db");
        let baseline = dir.path().join("baseline.apassy");
        let remote_path = dir.path().join("remote.db");
        let incoming = dir.path().join("incoming.apassy");
        let mut app = DesktopApp::new();
        app.owner_ui
            .session
            .create_file(&path, PASS)
            .expect("create");
        app.owner_ui.session.unlock(PASS).expect("unlock");
        let original = add(&mut app, "Current credential");
        app.owner_ui
            .session
            .with_vault(|vault| {
                vault
                    .write_sync_copy(&baseline, "First Mac")
                    .expect("baseline");
            })
            .expect("open vault");
        let (mut remote, _) = Vault::adopt_sync_copy(&baseline, &remote_path, PASS).expect("adopt");
        remote.unlock(PASS).expect("unlock remote");
        let details = app.owner_ui.session.details(original).expect("details");
        let mut draft = details.to_draft();
        draft.notes = "First Mac edit".to_owned();
        app.owner_ui
            .session
            .update(original, details.revision, &draft, &SecretForm::default())
            .expect("local edit");
        let remote_item = remote.search("").expect("search").remove(0);
        remote
            .update(
                remote_item.id,
                remote_item.revision,
                VaultDraft {
                    title: "Current credential".to_owned(),
                    kind: CredentialKind::ApiKey,
                    notes: "Second Mac edit".to_owned(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: "token".to_owned(),
                        value: SecretValue::new(CANARY.to_owned()),
                        secret: true,
                    }],
                },
            )
            .expect("remote edit");
        remote
            .write_sync_copy(&incoming, "Second Mac")
            .expect("remote copy");
        app.owner_ui
            .session
            .with_vault(|vault| {
                let report = vault
                    .merge_from(&incoming, &SyncScope::vault())
                    .expect("merge");
                assert_eq!(report.conflicts.len(), 1);
            })
            .expect("open vault");
        let copies = app.owner_ui.session.conflict_copies().expect("metadata");
        assert_eq!(copies.len(), 1);
        let copy = *copies.keys().next().expect("copy ID");
        assert_eq!(copies[&copy], Some(original));
        let ordinary = add(&mut app, "Ordinary archive");
        let title_only = add(&mut app, "User name (conflict copy, Mac)");
        app.owner_ui.session.archive(ordinary).expect("archive");
        app.owner_ui
            .session
            .archive(title_only)
            .expect("archive user title");
        // No latest sync report is required. The notice uses retained vault metadata.
        drop(app);
        let mut app = DesktopApp::new();
        app.owner_ui.session.open_file(&path).expect("reopen");
        app.owner_ui
            .session
            .unlock(PASS)
            .expect("unlock after reopen");
        let list = text(&mut app, false);
        assert!(list.contains("Review conflicting changes (1)"), "{list}");
        assert!(
            list.contains("2 archived credentials are hidden."),
            "{list}"
        );
        app.search = "no matching credential".to_owned();
        let list = text(&mut app, false);
        assert!(list.contains("Review conflicting changes (1)"), "{list}");
        app.search.clear();
        app.ui.credential_filter = Filter::Archived;
        let list = text(&mut app, false);
        assert!(
            list.contains("Ordinary archive") && list.contains("User name (conflict copy, Mac)"),
            "{list}"
        );
        assert!(
            !list.contains("Current credential (conflict copy"),
            "{list}"
        );
        app.ui.credential_filter = Filter::Conflicts;
        let list = text(&mut app, false);
        assert!(
            list.contains("Conflict copy") && list.contains("Current credential (conflict copy"),
            "{list}"
        );
        assert!(!list.contains("Ordinary archive"), "{list}");
        app.select_item(copy.to_string());
        let detail = text(&mut app, true);
        assert!(
            detail.contains("The current version is active: Current credential."),
            "{detail}"
        );
        assert!(
            detail.contains("Open current version") && detail.contains("Restore from archive"),
            "{detail}"
        );
        assert!(
            app.owner_ui
                .session
                .is_archived(copy)
                .expect("still archived")
        );
        app.select_item(original.to_string());
        let detail = text(&mut app, true);
        assert!(
            detail.contains("Current version · Active")
                && detail.contains("Current credential (conflict copy"),
            "{detail}"
        );
        app.owner_ui
            .session
            .archive(original)
            .expect("archive current version");
        app.select_item(copy.to_string());
        let detail = text(&mut app, true);
        assert!(
            detail.contains("The current version is archived: Current credential."),
            "{detail}"
        );
        let revision = app
            .owner_ui
            .session
            .details(original)
            .expect("original details")
            .revision;
        app.owner_ui
            .session
            .delete(original, revision)
            .expect("delete original");
        let detail = text(&mut app, true);
        assert!(
            detail.contains("The original credential is no longer in this vault."),
            "{detail}"
        );
        assert!(!detail.contains("Open current version"), "{detail}");
        let name = app
            .owner_ui
            .session
            .details(copy)
            .expect("copy details")
            .name;
        app.ask_owner(
            OwnerRequest::Unarchive {
                item_id: copy,
                name: name.clone(),
            },
            None,
        );
        assert!(
            app.confirm_owner_now(OwnerCheck::passphrase("wrong-passphrase"))
                .is_err()
        );
        assert!(
            app.owner_ui
                .session
                .is_archived(copy)
                .expect("wrong passphrase preserves archive")
        );
        app.ask_owner(
            OwnerRequest::Unarchive {
                item_id: copy,
                name,
            },
            None,
        );
        app.confirm_owner_now(OwnerCheck::passphrase(PASS))
            .expect("restore needs the passphrase");
        assert!(!app.owner_ui.session.is_archived(copy).expect("restored"));
        assert!(
            app.owner_ui
                .session
                .declaration(copy)
                .expect("agent settings")
                .is_none()
        );
        app.ui.credential_filter = Filter::All;
        let list = text(&mut app, false);
        assert!(!list.contains("Review conflicting changes"), "{list}");
        assert!(list.contains("Current credential (conflict copy"), "{list}");
    }
}

#[cfg(test)]
#[path = "passkey_tests.rs"]
mod passkey_tests;

#[cfg(test)]
mod looks_tests {
    use super::*;

    /// The kind of a key comes from its variable, as in the mockup.
    #[test]
    fn a_key_is_named_by_the_end_of_its_variable() {
        let key = CredentialKind::ApiKey;
        assert_eq!(field_kind(key, Some("STRIPE_SECRET_KEY")), "Secret key");
        assert_eq!(field_kind(key, Some("CLOUDFLARE_API_TOKEN")), "API token");
        assert_eq!(field_kind(key, Some("GITHUB_TOKEN")), "Token");
        assert_eq!(field_kind(key, Some("OPENAI_API_KEY")), "API key");
        assert_eq!(field_kind(key, Some("STRIPE_TEST_KEY")), key.label());
        assert_eq!(field_kind(key, None), key.label());
        let database = CredentialKind::Database;
        assert_eq!(
            field_kind(database, Some("DATABASE_TOKEN")),
            database.label()
        );
    }

    /// The header names the provider of the tile; a database without one gets the
    /// blue database tile of the mockup, not a green kind tile.
    #[test]
    fn the_provider_and_the_tile_follow_one_rule() {
        let (label, tile) = super::super::named_provider("", "Stripe live").expect("Stripe");
        assert_eq!(label, "Stripe");
        assert_eq!(
            tile,
            super::super::credential_tile(CredentialKind::ApiKey, "", "Stripe live")
        );
        assert!(super::super::named_provider("", "Billing database").is_none());
        let tile = super::super::credential_tile(CredentialKind::Database, "", "Billing database");
        assert_eq!(tile.color, egui::Color32::from_rgb(51, 103, 145));
        assert_eq!(tile.mark, kit::Mark::Icon(Icon::Database));
    }
}
