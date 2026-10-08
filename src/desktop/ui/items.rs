//! Credentials: the list, the detail page, and their sheets (vault build).
//!
//! The list shows each credential with its agent status. It sorts and filters, and it
//! hides archived credentials unless the owner searches or selects their archive filter.
//! Sync conflict copies have a persistent review notice and a separate filter.
//! The detail page shows the secret (masked), the details that are set, the custom
//! details, three agent settings, the change history, and the agent requests. Each
//! change opens a sheet. A change that decides where a secret goes needs the owner check.

use std::collections::BTreeMap;

use eframe::egui::{self, Align, Label, Layout, Pos2, Rect, RichText, Sense, Vec2};

use super::kit::{self, Font, Icon, Section, Size, Style, Tone};
use super::timeline::{self, relative_time};
use super::{
    SECRET_VALUE_CAPACITY, Sheet, UiState, ask_owner_from_sheet, close_sheet, extra_label,
    forget_secret_field, forget_secret_form, kind_blurb, kind_icon, kind_plural, meta_line,
    secure_input,
};
use crate::broker::profile::REPORTING_API_V0;
use crate::contracts::CredentialKind;
use crate::desktop::model::{DesktopModel, DetailDraft, ExtraField, ItemDraft, MASKED_VALUE};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::{
    DETAIL_PREFIX, DeclarationForm, MAX_DETAILS, OwnerDetails, OwnerSummary, SecretForm,
    field_label,
};
use crate::desktop::{DesktopApp, OwnerView};
use crate::vault::providers::{self, Suggested};
use crate::vault::{EnvDelivery, Environment, ItemTimes, Reversibility, RiskLevel, Scope};

// ---- The list. ----

/// Which credentials the list shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Filter {
    #[default]
    All,
    Kind(CredentialKind),
    /// No declaration, or a review after a restore.
    NeedsSetup,
    /// Archived versions retained after concurrent sync changes.
    Conflicts,
    Archived,
}

impl Filter {
    const ALL: [Self; 9] = [
        Self::All,
        Self::Kind(CredentialKind::ApiKey),
        Self::Kind(CredentialKind::Login),
        Self::Kind(CredentialKind::SshKey),
        Self::Kind(CredentialKind::Database),
        Self::Kind(CredentialKind::Custom),
        Self::NeedsSetup,
        Self::Conflicts,
        Self::Archived,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::All => "All credentials",
            Self::Kind(kind) => kind_plural(kind),
            Self::NeedsSetup => "Needs setup",
            Self::Conflicts => "Conflicting changes",
            Self::Archived => "Archived",
        }
    }
}

/// Conflict copies have a separate review list and archive count. A search still
/// finds them with a distinct label. Restored copies follow the active filters.
fn matches_filter(
    item: &OwnerSummary,
    filter: Filter,
    searching: bool,
    archived: bool,
    conflict: bool,
    needs_setup: impl FnOnce(u64) -> bool,
) -> bool {
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
    match filter {
        Filter::Kind(kind) => item.kind == kind,
        Filter::NeedsSetup => needs_setup(item.id),
        Filter::All | Filter::Archived | Filter::Conflicts => true,
    }
}

/// The order of the list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Sort {
    #[default]
    Name,
    Changed,
    Used,
    Added,
}

impl Sort {
    const ALL: [Self; 4] = [Self::Name, Self::Changed, Self::Used, Self::Added];

    fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Changed => "Last changed",
            Self::Used => "Last used",
            Self::Added => "Date added",
        }
    }

    /// The title of the list in this order.
    fn title(self) -> &'static str {
        match self {
            Self::Name => "Credentials",
            Self::Changed => "Recently changed",
            Self::Used => "Recently used by agents",
            Self::Added => "Newest first",
        }
    }
}

pub(super) fn draw_list(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let all = app.owner_ui.session.search("").unwrap_or_default();
    let mut add = false;
    // With no credential, the empty state has the one main action (⌘N still works).
    kit::page_header(ui, "Credentials", None, |ui| {
        if !all.is_empty() {
            add = kit::button_with(ui, Some(Icon::Plus), "Add", Style::Prominent, Size::Regular)
                .on_hover_text("New credential  ⌘N")
                .clicked();
        }
    });
    // A vault from another Mac: its agents stay on that Mac, so this one sets them up
    // here. The panel is part of this page, under its title.
    if app.ui.setup_vault.is_some() && super::agents::next_steps_panel(app, ui) {
        app.ui.setup_vault = None;
    }
    // The steps of a new vault. With no credential, they replace the empty state:
    // "Add a credential" is then the one main action.
    let guided = super::get_started::draw(app, ui);
    if all.is_empty() && guided {
        if add {
            open_add(app);
        }
        app.ui.focus_search = false;
        return;
    }
    if all.is_empty() {
        add |= kit::empty_state(
            ui,
            Icon::Key,
            "No credentials yet",
            "Add an API key, a login, an SSH key, or a database password. Agents use a credential through Apassy and never see its value.",
            Some("Add credential"),
        );
        if add {
            open_add(app);
        }
        // No search field without credentials. ⌘F must not focus it later by surprise.
        app.ui.focus_search = false;
        return;
    }
    let archived = app.owner_ui.session.archived().unwrap_or_default();
    let conflicts = app.owner_ui.session.conflict_copies().unwrap_or_default();
    let conflict_count = all
        .iter()
        .filter(|item| archived.contains_key(&item.id) && conflicts.contains_key(&item.id))
        .count();
    let archived_count = all
        .iter()
        .filter(|item| archived.contains_key(&item.id) && !conflicts.contains_key(&item.id))
        .count();
    // Each scope keeps the IDs below a notice the same when it comes or goes.
    ui.scope(|ui| review_notice(app, ui));
    ui.scope(|ui| conflict_notice(app, ui, conflict_count));
    toolbar(app, ui);
    ui.add_space(18.0);

    let session = &app.owner_ui.session;
    let times = session.item_times().unwrap_or_default();
    let query = app.search.trim().to_owned();
    let filter = app.ui.credential_filter;
    let sort = app.ui.credential_sort;
    let found = if query.is_empty() {
        all
    } else {
        session.search(&query).unwrap_or_default()
    };
    let needs_setup = |id: u64| {
        session.needs_review(id).unwrap_or(false)
            || session.declaration(id).ok().flatten().is_none()
    };
    let mut items: Vec<OwnerSummary> = found
        .into_iter()
        .filter(|item| {
            matches_filter(
                item,
                filter,
                !query.is_empty(),
                archived.contains_key(&item.id),
                conflicts.contains_key(&item.id),
                needs_setup,
            )
        })
        .collect();
    sort_items(&mut items, sort, &times);
    let hidden_archived = if filter == Filter::Archived || !query.is_empty() {
        0
    } else {
        archived_count
    };

    if items.is_empty() {
        let message = match filter {
            _ if !query.is_empty() => format!("No credential matches “{query}”."),
            Filter::Archived => "No credential is archived.".to_owned(),
            Filter::Conflicts => "No archived conflict copy needs review.".to_owned(),
            Filter::NeedsSetup => "Every credential has a declaration.".to_owned(),
            _ => "No credential matches the filter.".to_owned(),
        };
        kit::note(ui, message);
        ui.add_space(12.0);
    }
    let mut open = None;
    let grouped = sort == Sort::Name && !matches!(filter, Filter::Kind(_) | Filter::Conflicts);
    let row = |s: &mut Section<'_>, item: &OwnerSummary, open: &mut Option<u64>| {
        let meta = meta_line(&item.project, &item.service);
        let subtitle = (!meta.is_empty()).then_some(meta.as_str());
        let detail = if archived.contains_key(&item.id) && conflicts.contains_key(&item.id) {
            kit::medium("Conflict copy", Font::Callout).color(Tone::Warning.text())
        } else if archived.contains_key(&item.id) {
            kit::medium("Archived", Font::Callout).color(kit::SECONDARY)
        } else {
            row_detail(app, item.id, sort, times.get(&item.id))
        };
        if s.nav(
            Some(kind_icon(item.kind)),
            &item.name,
            subtitle,
            Some(detail),
        )
        .clicked()
        {
            *open = Some(item.id);
        }
    };
    if grouped {
        for kind in CredentialKind::ALL {
            let group: Vec<_> = items.iter().filter(|item| item.kind == kind).collect();
            if group.is_empty() {
                continue;
            }
            kit::section(ui, Some(kind_plural(kind)), None, |s| {
                for item in group {
                    row(s, item, &mut open);
                }
            });
        }
    } else if !items.is_empty() {
        let title = match filter {
            Filter::Kind(kind) => kind_plural(kind).to_owned(),
            Filter::Conflicts => format!("Conflicting changes ({conflict_count})"),
            _ => sort.title().to_owned(),
        };
        kit::section(ui, Some(&title), None, |s| {
            for item in &items {
                row(s, item, &mut open);
            }
        });
    }
    if hidden_archived > 0 {
        ui.horizontal(|ui| {
            let noun = if hidden_archived == 1 {
                "archived credential is hidden."
            } else {
                "archived credentials are hidden."
            };
            kit::note(ui, format!("{hidden_archived} {noun}"));
            if kit::small_button(ui, "Show archived", Style::Link).clicked() {
                app.ui.credential_filter = Filter::Archived;
            }
        });
    }
    if let Some(id) = open {
        app.select_item(id.to_string());
    }
    if add {
        open_add(app);
    }
}

/// Search, filter, and sort in one row. ⌘F puts the focus in the search field. The
/// search field takes the width that the two menus leave. The controls draw from left
/// to right, so Tab visits them in the order that the owner sees.
fn toolbar(app: &mut DesktopApp, ui: &mut egui::Ui) {
    const MENU_WIDTH: f32 = 150.0;
    let width = ui.available_width();
    ui.allocate_ui_with_layout(
        Vec2::new(width, 28.0),
        Layout::left_to_right(Align::Center),
        |ui| {
            let gap = ui.spacing().item_spacing.x;
            // A menu button is exactly `MENU_WIDTH` wide, with its padding and chevron.
            // The search field takes the rest, so the toolbar ends at the page edge.
            let menus = 2.0 * (MENU_WIDTH + gap);
            let search_width = (width - menus).max(160.0);
            let field = ui
                .scope(|ui| {
                    ui.set_width(search_width);
                    kit::text_input(
                        ui,
                        &mut app.search,
                        "credential-search",
                        "Search by name, project, service, or notes",
                    )
                    .on_hover_text("Search  ⌘F")
                })
                .inner;
            ui.ctx()
                .accesskit_node_builder(field.id, |node| node.set_label("Search credentials"));
            if std::mem::take(&mut app.ui.focus_search) {
                field.request_focus();
            }
            let mut filter = app.ui.credential_filter;
            let filters: Vec<(Filter, String)> = Filter::ALL
                .into_iter()
                .map(|option| (option, option.label().to_owned()))
                .collect();
            let label = filter.label();
            kit::picker(
                ui,
                "credential-filter",
                &mut filter,
                &filters,
                label,
                MENU_WIDTH,
            );
            app.ui.credential_filter = filter;
            let mut sort = app.ui.credential_sort;
            let sorts: Vec<(Sort, String)> = Sort::ALL
                .into_iter()
                .map(|option| (option, option.label().to_owned()))
                .collect();
            let label = format!("Sort: {}", sort.label());
            kit::picker(ui, "credential-sort", &mut sort, &sorts, label, MENU_WIDTH);
            app.ui.credential_sort = sort;
        },
    );
}

/// Name order, or newest first by a time. An item without the time goes last.
fn sort_items(items: &mut [OwnerSummary], sort: Sort, times: &BTreeMap<u64, ItemTimes>) {
    let time = |item: &OwnerSummary| {
        let times = times.get(&item.id).copied().unwrap_or_default();
        match sort {
            Sort::Name => None,
            Sort::Changed => times.changed,
            Sort::Used => times.used,
            Sort::Added => times.added,
        }
    };
    items.sort_by(|a, b| {
        time(b)
            .cmp(&time(a))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

/// The right side of a list row: the time of the sort, or the agent status.
fn row_detail(app: &DesktopApp, item_id: u64, sort: Sort, times: Option<&ItemTimes>) -> RichText {
    let times = times.copied().unwrap_or_default();
    let now = timeline::now();
    let when = |at: Option<u64>, verb: &str, never: &str| match at {
        Some(at) => format!("{verb} {}", relative_time(at, now)),
        None => never.to_owned(),
    };
    match sort {
        Sort::Name => row_status(app, item_id),
        Sort::Changed => kit::text(when(times.changed, "Changed", "No change"), Font::Callout)
            .color(kit::SECONDARY),
        Sort::Used => {
            kit::text(when(times.used, "Used", "Not used yet"), Font::Callout).color(kit::SECONDARY)
        }
        Sort::Added => {
            kit::text(when(times.added, "Added", ""), Font::Callout).color(kit::SECONDARY)
        }
    }
}

/// The agent status of a list row: review, declaration, or variable.
fn row_status(app: &DesktopApp, item_id: u64) -> RichText {
    let session = &app.owner_ui.session;
    if session.needs_review(item_id).unwrap_or(false) {
        return kit::medium("Needs review", Font::Callout).color(Tone::Warning.text());
    }
    let Some(declaration) = session.declaration(item_id).ok().flatten() else {
        return kit::text("No declaration", Font::Callout).color(kit::SECONDARY);
    };
    match session.env_binding(item_id).ok().flatten() {
        Some(binding) => kit::text(binding.env_name, Font::Mono).color(kit::SECONDARY),
        None => kit::text(title_case(declaration.environment.as_str()), Font::Callout)
            .color(kit::SECONDARY),
    }
}

/// Open the add sheet with an empty form. ⌘N does the same.
pub(super) fn open_add(app: &mut DesktopApp) {
    app.add_form = ItemDraft::default();
    app.owner_ui.add_secrets.clear();
    app.ui.sheet = Some(Sheet::AddItem { kind_chosen: false });
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
            "This vault came from a backup. Agents cannot use these credentials until you confirm their agent settings: the declaration, the environment variable, and the connector. The restore also revoked every agent. Register the agents again.",
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

pub(super) fn draw_detail(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if kit::back_link(ui, "Credentials") {
        app.view = OwnerView::Vault;
        return;
    }
    let Some(id) = selected_id(app) else {
        kit::note(ui, "Select a credential in the list.");
        return;
    };
    let details = match app.owner_ui.session.details(id) {
        Ok(details) => details,
        Err(err) => {
            kit::tone_note(ui, err.message, Tone::Critical);
            return;
        }
    };
    if details.hidden {
        kit::note(ui, &details.message);
        return;
    }
    let mut edit = false;
    ui.horizontal(|ui| {
        let (icon, color) = kind_icon(details.kind);
        kit::icon_tile_sized(ui, icon, color, 40.0);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(kit::text(&details.name, Font::Title).color(kit::LABEL));
            let meta = meta_line(&details.project, &details.service);
            let subtitle = if meta.is_empty() {
                details.kind.label().to_owned()
            } else {
                format!("{} · {meta}", details.kind.label())
            };
            ui.label(kit::text(subtitle, Font::Callout).color(kit::SECONDARY));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            edit = kit::button(ui, "Edit", Style::Bordered).clicked();
            if details.archived {
                kit::tag(ui, "Archived", Tone::Neutral);
            }
        });
    });
    ui.add_space(20.0);
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
    secret_section(app, ui, &details);
    details_section(app, ui, &details);
    access_section(app, ui, id, details.kind);
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
    let mut archive = false;
    let mut delete = false;
    kit::section(ui, None, None, |s| {
        if !details.archived {
            archive = s
                .clickable_row("Archive credential…", |ui| {
                    ui.label(kit::text("Archive credential…", Font::Body).color(kit::LABEL));
                    kit::note(ui, "Agents cannot use it. Search still finds it.");
                })
                .clicked();
        }
        delete = s
            .clickable_row("Delete credential…", |ui| {
                ui.label(kit::text("Delete credential…", Font::Body).color(Tone::Critical.text()));
            })
            .clicked();
    });
    if edit {
        open_edit(app, &details, false);
    }
    if archive {
        app.ui.sheet = Some(Sheet::ArchiveItem);
    }
    if delete {
        app.pending_delete = true;
    }
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
    let Some(id) = selected_id(app) else {
        return;
    };
    let Ok(details) = app.owner_ui.session.details(id) else {
        return;
    };
    if details.hidden || details.secret_lines.is_empty() {
        return;
    }
    if details.any_revealed() {
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
        ui.add(Label::new(kit::text(value, Font::Mono).color(kit::LABEL)).wrap());
    }
}

/// "Show" or "Hide" for the secret values, with the masked value while hidden.
fn mask_button(ui: &mut egui::Ui, revealed: bool, masked: bool) -> bool {
    let label = if revealed { "Hide" } else { "Show" };
    let button = kit::button_with(ui, Some(Icon::Eye), label, Style::Link, Size::Small)
        .on_hover_text("Show or hide secret values  ⌘⇧H");
    let name = if revealed {
        "Hide the secret values"
    } else {
        "Show the secret values"
    };
    ui.ctx()
        .accesskit_node_builder(button.id, |node| node.set_label(name));
    let clicked = button.clicked();
    if masked {
        ui.label(kit::text(MASKED_VALUE, Font::Mono).color(kit::SECONDARY));
    }
    clicked
}

fn secret_section(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails) {
    let id = details.id;
    let revealed = details.any_revealed();
    let lines: Vec<_> = details
        .secret_lines
        .iter()
        .filter(|line| !line.name.starts_with(DETAIL_PREFIX))
        .collect();
    if lines.is_empty() {
        return;
    }
    let footer = if revealed {
        details.reveal_warning()
    } else {
        "Show asks for your passphrase. Apassy never copies a value to the clipboard."
    };
    let mut toggle = false;
    kit::section(ui, Some("Secret"), Some(footer), |s| {
        for line in lines {
            s.row(|ui| {
                egui::Sides::new().show(
                    ui,
                    |ui| ui.label(kit::text(field_label(&line.name), Font::Body).color(kit::LABEL)),
                    |ui| toggle |= mask_button(ui, revealed, !line.revealed),
                );
                secret_value(ui, app, id, &line.name);
            });
        }
    });
    if toggle {
        toggle_masking(app, ui.ctx());
    }
}

/// The details that are set, and the custom details. A hidden custom detail is masked
/// like the secret, and "Show" shows it with the secret.
fn details_section(app: &mut DesktopApp, ui: &mut egui::Ui, details: &OwnerDetails) {
    let id = details.id;
    let rows: Vec<(&str, &str)> = [
        ("Username", details.username.as_str()),
        ("Website", details.website.as_str()),
        ("Host", details.host.as_str()),
        ("Database", details.database_name.as_str()),
        ("Public key", details.public_label.as_str()),
        ("Service", details.service.as_str()),
        ("Project", details.project.as_str()),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .collect();
    let revealed = details.any_revealed();
    let mut toggle = false;
    let mut add_detail = false;
    kit::section(
        ui,
        Some("Details"),
        Some(
            "Custom details are yours: an account number, a region, recovery codes. A hidden detail is masked like the secret.",
        ),
        |s| {
            for (label, value) in rows {
                s.labeled(label, kit::text(value, Font::Body).color(kit::SECONDARY));
            }
            for detail in &details.details {
                match &detail.value {
                    Some(value) => {
                        s.labeled(
                            &detail.label,
                            kit::text(value, Font::Body).color(kit::SECONDARY),
                        );
                    }
                    None => s.row(|ui| {
                        let shown = app
                            .owner_ui
                            .session
                            .revealed_value(id, &detail.name)
                            .is_some();
                        egui::Sides::new().show(
                            ui,
                            |ui| ui.label(kit::text(&detail.label, Font::Body).color(kit::LABEL)),
                            |ui| toggle |= mask_button(ui, revealed, !shown),
                        );
                        secret_value(ui, app, id, &detail.name);
                    }),
                }
            }
            if details.details.len() < MAX_DETAILS {
                add_detail = s
                    .clickable_row("Add custom detail", |ui| {
                        ui.horizontal(|ui| {
                            kit::paint_icon_in(ui, Icon::Plus, 12.0, kit::ACCENT);
                            ui.label(
                                kit::text("Add custom detail", Font::Body).color(kit::ACCENT_TEXT),
                            );
                        });
                    })
                    .clicked();
            }
        },
    );
    if !details.notes.is_empty() {
        kit::section(ui, Some("Notes"), None, |s| {
            s.row(|ui| kit::paragraph(ui, &details.notes, Font::Body, kit::LABEL));
        });
    }
    if toggle {
        toggle_masking(app, ui.ctx());
    }
    if add_detail {
        open_edit(app, details, true);
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
    let has_fields = !session.secret_fields(id).unwrap_or_default().is_empty();
    let connector = if kind == CredentialKind::ApiKey {
        session.connector(id).ok().flatten()
    } else {
        None
    };
    let mut open = None;
    kit::section(
        ui,
        Some("Agent access"),
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
                        kit::text(format!("{}{mode}", binding.env_name), Font::Mono)
                            .color(kit::SECONDARY)
                    }
                    None => kit::text("Not set", Font::Callout).color(kit::SECONDARY),
                };
                let terminal = (Icon::Terminal, egui::Color32::from_rgb(88, 86, 214));
                if s.nav(
                    Some(terminal),
                    "Environment variable",
                    Some("Agents can run a command with this secret in its environment."),
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
                .unwrap_or_default();
            let suggested = state.session.suggested_placeholder_hosts(id);
            // A new variable starts in placeholder mode when the provider hosts are known.
            (state.env_placeholder_input, state.env_hosts_input) =
                match binding.as_ref().map(|binding| &binding.delivery) {
                    Some(EnvDelivery::Placeholder(hosts)) => (true, hosts.join(", ")),
                    Some(EnvDelivery::Value) => (false, suggested.join(", ")),
                    None => (!suggested.is_empty(), suggested.join(", ")),
                };
            state.env_field_input = binding.map(|binding| binding.field).unwrap_or_default();
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
            app.view = OwnerView::Vault;
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
            );
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
            // Borrow the form. A clone would be one more copy of each secret (F3).
            match app.owner_ui.session.add(&draft, &app.owner_ui.add_secrets) {
                Ok(item) => {
                    app.owner_ui.add_secrets.clear();
                    forget_secret_form(ctx, "add");
                    app.add_form = ItemDraft::default();
                    app.ui.sheet = None;
                    app.set_ok(format!(
                        "{} is stored. Next, set up agent access.",
                        item.name
                    ));
                    app.select_item(item.id.to_string());
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
/// name. The edit sheet keeps a blank secret.
fn item_form(
    ui: &mut egui::Ui,
    form: &mut ItemDraft,
    secrets: &mut SecretForm,
    state: &mut UiState,
    salt: &str,
    editing: bool,
) {
    let kind = form.kind;
    let focus_name = std::mem::take(&mut state.focus_form_name);
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
        }
    });
    if editing {
        kit::section(
            ui,
            Some("Secret"),
            Some("Leave a field blank to keep the stored value."),
            |s| secret_rows(s, salt, kind, secrets, "Unchanged"),
        );
    }
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
    if !form.details.is_empty() {
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
                            let mut hidden = detail.hidden;
                            if kit::toggle(ui, &mut hidden, &format!("Hidden: {row_name}"))
                                .on_hover_text(
                                    "Hidden: masked, and showing it needs your passphrase",
                                )
                                .changed()
                            {
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
fn set_hidden(detail: &mut DetailDraft, secret: &mut String, hidden: bool) {
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
            "Environment variable",
            Some(
                "An agent can ask Apassy to run a command with this secret in its environment. The agent never receives the value.",
            ),
        );
        kit::section(
            ui,
            None,
            Some(
                "Use A-Z, 0-9, and _, and start with a letter or _. System names such as PATH or DYLD_* are not permitted. You give each agent process access in Agents.",
            ),
            |s| {
                s.field("Name", |ui| {
                    kit::mono_input(
                        ui,
                        &mut app.owner_ui.env_name_input,
                        "env-name",
                        "SUPABASE_SERVICE_KEY",
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
        if crate::vault::checked_env_name(&env_name).is_err() {
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
                "Use https://, or http:// on this computer only. The broker does not follow redirects. You let each agent use an operation in Agents.",
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

    fn summary() -> OwnerSummary {
        OwnerSummary {
            id: 1,
            name: "User name (conflict copy, Mac)".to_owned(),
            kind: CredentialKind::ApiKey,
            service: String::new(),
            project: String::new(),
            revision: 1,
        }
    }

    #[test]
    fn conflict_filter_separates_verified_copies_and_preserves_search() {
        let item = summary();
        let matches = |filter, searching, archived, conflict| {
            matches_filter(&item, filter, searching, archived, conflict, |_| true)
        };
        // A user-selected name cannot make an ordinary archived item a conflict.
        assert!(matches(Filter::Archived, false, true, false));
        assert!(!matches(Filter::Conflicts, true, true, false));
        assert!(matches(Filter::Conflicts, false, true, true));
        assert!(!matches(Filter::Archived, true, true, true));
        assert!(!matches(Filter::All, false, true, true));
        assert!(matches(Filter::All, true, true, true));
        assert!(matches(
            Filter::Kind(CredentialKind::ApiKey),
            true,
            true,
            true
        ));
        assert!(!matches(
            Filter::Kind(CredentialKind::Login),
            true,
            true,
            true
        ));
        // A deliberate restore removes the copy from the archived review list.
        assert!(!matches(Filter::Conflicts, false, false, true));
        assert!(matches(Filter::All, false, false, true));
        assert!(matches(Filter::NeedsSetup, false, false, true));
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
                        draw_list(app, ui);
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
