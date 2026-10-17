//! "New Credential" (ADR 0025 §4, ADR 0026 §4): "+" in a list and ⌘N open it.
//!
//! The owner pastes a key, a `KEY=value` line, a `.env` file, a database URL, or an
//! `otpauth://` link. [`detect`] finds each credential on this Mac, and the sheet shows
//! one row for each: the provider tile, the title (the owner can change it), the
//! provider, the variable, the host, and the environment that a signal found. A paste
//! with several credentials has a checkbox on each row. "Add" saves the checked ones in
//! one transaction, in the folder of the menu (the folder that the sidebar shows), with
//! the variable and the declaration. No owner check: a new credential moves no
//! authority, and the bouncer decides each use of it.
//!
//! The paste is a secret. It lives in the secret buffer of the add form, so a lock
//! erases it, and its field has a global ID, so a close forgets its undo history. The
//! field shows the paste masked (`STRIPE_SECRET_KEY=sk_test_••••••••`) unless the owner
//! edits it. "Examples:" puts a synthetic example in the field, and the quiet "Fill in
//! by hand…" leads to the add form with its kinds (a login, an SSH key) for a
//! credential that a paste does not fit.

use eframe::egui::{self, Label, RichText, Sense, TextEdit, WidgetInfo, WidgetType};

use super::folders::FolderTree;
use super::kit::{self, Font, Style, Tone};
use super::{SECRET_VALUE_CAPACITY, close_sheet, forget_secret_field, save_pressed};
use crate::contracts::CredentialKind;
use crate::desktop::model::MASKED_VALUE;
use crate::desktop::{DesktopApp, Place};
use crate::vault::detect::{self, Detected, Source};
use crate::vault::{Environment, providers};

/// The content width of the sheet: 520 points with the margins of [`kit::sheet`], as
/// the mockup's sheet.
const SHEET_WIDTH: f32 = 476.0;
/// The inner margin and the corner radius of [`kit::sheet`].
const SHEET_MARGIN: f32 = 22.0;
const SHEET_RADIUS: u8 = 14;
/// The paste field: four lines of 12-point monospace, as the mockup's `rows="4"`.
const PASTE_HEIGHT: f32 = 80.0;
const PASTE_FONT: f32 = 12.0;
/// The summary line of a row.
const SUMMARY_FONT: f32 = 11.5;

/// The note when a paste has no credential.
const NOTHING_FOUND: &str = "Apassy found no credential in the text. Paste a secret, a KEY=value line, a .env file, a URL with a password, or an otpauth:// link.";

/// The salt of the paste field. It is the custom value field of the add form: both use
/// the secret buffer `add_secrets.custom_value`, and a lock erases both.
pub(super) const PASTE_FIELD: &str = "add-custom";

/// What the owner chose for the rows of a paste. It has no secret value.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct Choices {
    /// The place that the sheet opened in. Another place starts new choices.
    place: Option<Place>,
    /// The folder for the new credentials. `None`: the top level.
    pub(super) folder: Option<String>,
    /// For each row of the detection, by [`row_key`]: the title and whether it is added.
    rows: Vec<(String, String, bool)>,
}

impl Choices {
    fn id() -> egui::Id {
        egui::Id::new("apassy-new-credential")
    }

    pub(super) fn load(ctx: &egui::Context) -> Self {
        ctx.data(|data| data.get_temp::<Self>(Self::id()))
            .unwrap_or_default()
    }

    fn store(self, ctx: &egui::Context) {
        ctx.data_mut(|data| data.insert_temp(Self::id(), self));
    }

    /// Follow a new detection: a row that was there keeps its title and its checkbox.
    fn follow(&mut self, detected: &[Detected]) {
        let old = std::mem::take(&mut self.rows);
        self.rows = detected
            .iter()
            .map(|found| {
                let key = row_key(found);
                old.iter()
                    .find(|(old_key, _, _)| *old_key == key)
                    .cloned()
                    .unwrap_or_else(|| (key, found.title.clone(), true))
            })
            .collect();
    }

    /// The detected credentials that the owner keeps, with the typed titles.
    pub(super) fn kept(&self, mut detected: Vec<Detected>) -> Vec<Detected> {
        let mut kept = Vec::new();
        for (found, (_, title, keep)) in detected.drain(..).zip(&self.rows) {
            if !keep {
                continue;
            }
            let mut found = found;
            if !title.trim().is_empty() {
                found.title = title.trim().to_owned();
            }
            kept.push(found);
        }
        kept
    }

    /// Set the title of row `index`, as the field of the row does.
    #[cfg(test)]
    pub(super) fn set_title(ctx: &egui::Context, index: usize, title: &str) {
        let mut choices = Self::load(ctx);
        if let Some(row) = choices.rows.get_mut(index) {
            row.1 = title.to_owned();
        }
        choices.store(ctx);
    }

    /// Check or uncheck row `index`, as its checkbox does.
    #[cfg(test)]
    pub(super) fn set_kept(ctx: &egui::Context, index: usize, keep: bool) {
        let mut choices = Self::load(ctx);
        if let Some(row) = choices.rows.get_mut(index) {
            row.2 = keep;
        }
        choices.store(ctx);
    }

    /// Choose the folder, as the Folder menu does.
    #[cfg(test)]
    pub(super) fn set_folder(ctx: &egui::Context, folder: Option<String>) {
        let mut choices = Self::load(ctx);
        choices.folder = folder;
        choices.store(ctx);
    }
}

/// The identity of a detected row across frames: its line, its variable, and its
/// detected title. It has no secret value.
fn row_key(found: &Detected) -> String {
    format!(
        "{}|{}|{}",
        found.line.unwrap_or(0),
        found.env_name.as_deref().unwrap_or_default(),
        found.title
    )
}

/// The provider label of a detected credential, or its kind. A value without a provider
/// and without a kind is a "Secret", as in the mockup.
fn provider_label(found: &Detected) -> String {
    found
        .provider
        .as_deref()
        .and_then(providers::find)
        .map_or_else(
            || match found.kind {
                CredentialKind::Custom => "Secret".to_owned(),
                kind => kind.label().to_owned(),
            },
            |p| p.label.clone(),
        )
}

/// "Stripe · STRIPE_SECRET_KEY · api.stripe.com".
pub(super) fn row_line(found: &Detected) -> String {
    let mut parts = vec![provider_label(found)];
    if let Some(variable) = &found.env_name {
        parts.push(variable.clone());
    }
    if let Some(host) = found.hosts.first() {
        parts.push(host.clone());
    }
    parts.join(" · ")
}

/// The cap of a row: the environment that a signal found. A default shows none: the
/// bouncer treats it as production until the owner answers.
pub(super) fn row_cap(found: &Detected) -> Option<(&'static str, bool)> {
    if found.sources.environment != Source::Signal {
        return None;
    }
    match found.environment {
        Environment::Production => Some(("Production", true)),
        Environment::Development | Environment::Local => Some(("Development", false)),
        Environment::Staging => Some(("Staging", false)),
    }
}

/// Erase the paste and forget the choices and the undo history of the field. Each way
/// out of the sheet calls it.
pub(super) fn forget(app: &mut DesktopApp, ctx: &egui::Context) {
    use zeroize::Zeroize;
    app.owner_ui.add_secrets.custom_value.zeroize();
    forget_secret_field(ctx, PASTE_FIELD);
    ctx.data_mut(|data| data.remove::<Choices>(Choices::id()));
}

/// The sheet. Returns true on Escape.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let tree = FolderTree::load(app);
    let mut choices = Choices::load(ctx);
    if choices.place.as_ref() != Some(&app.place) {
        choices = Choices {
            place: Some(app.place.clone()),
            folder: tree.folder_of_place(&app.place),
            rows: Vec::new(),
        };
    }
    let detected = detect::detect(&app.owner_ui.add_secrets.custom_value);
    choices.follow(&detected);
    let kept = choices.rows.iter().filter(|(_, _, keep)| *keep).count();
    let typed = !app.owner_ui.add_secrets.custom_value.trim().is_empty();
    let folder_choices = tree.choices();
    let folder_label = if choices
        .folder
        .as_deref()
        .is_some_and(|id| tree.get(id).is_none())
    {
        "Missing Folder".to_owned()
    } else {
        tree.path_label(choices.folder.as_deref())
    };

    let mut add = false;
    let mut cancel = false;
    let mut by_hand = false;
    let mut login = false;
    let response = kit::sheet(ctx, "new-credential", SHEET_WIDTH, |ui| {
        // The mockup's sheet is gray (#f6f6f7) under its white field and group. The kit
        // sheet is white: paint the gray inside its edge, under the content.
        let backdrop = ui.painter().add(egui::Shape::Noop);
        ui.spacing_mut().item_spacing.y = 0.0;
        ui.label(kit::text("New Credential", Font::Body).variation(b"wght", 700.0));
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            login = push_button(ui, "Login").clicked();
            ui.label(kit::text("Paste", Font::Body).color(kit::LABEL));
            by_hand = push_button(ui, "Other…").clicked();
        });
        ui.add_space(3.0);
        kit::paragraph(
            ui,
            "Paste a key, a .env file, a database URL, or an otpauth:// link.",
            Font::Callout,
            kit::SECONDARY,
        );
        // 14 points to the field, as in the mockup. The body clips at its top, so 4 of
        // them are inside it: room for the edge and the focus ring of the field.
        ui.add_space(10.0);
        kit::sheet_body(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add_space(4.0);
            paste_field(ui, &mut app.owner_ui.add_secrets.custom_value, &detected);
            ui.add_space(8.0);
            by_hand |= examples(ui, &mut app.owner_ui.add_secrets.custom_value);
            if choices
                .folder
                .as_deref()
                .is_some_and(|id| tree.get(id).is_none())
            {
                kit::tone_note(
                    ui,
                    "The selected folder is gone. Choose another folder before adding.",
                    Tone::Warning,
                );
            }
            if typed && detected.is_empty() {
                ui.add_space(10.0);
                kit::tone_note(ui, NOTHING_FOUND, Tone::Warning);
            }
            if !detected.is_empty() {
                ui.add_space(12.0);
                rows(ui, &detected, &mut choices);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    kit::paragraph(
                        ui,
                        "Everything else is set automatically.",
                        Font::Callout,
                        kit::SECONDARY,
                    );
                });
            }
        });
        ui.add_space(18.0);
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(kit::text("Folder", Font::Callout).color(kit::SECONDARY));
                let mut folder = choices.folder.clone();
                let menu = folder_menu(ui, &mut folder, &folder_choices, &folder_label);
                ui.ctx().accesskit_node_builder(menu.id, |node| {
                    node.set_label(format!("Folder, {folder_label}"));
                });
                choices.folder = folder;
            },
            |ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let label = if kept > 1 {
                    format!("Add {kept}")
                } else {
                    "Add".to_owned()
                };
                add = ui
                    .add_enabled_ui(kept > 0, |ui| kit::button(ui, &label, Style::Prominent))
                    .inner
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = push_button(ui, "Cancel").clicked();
            },
        );
        let inside = ui.min_rect().expand(SHEET_MARGIN - 1.0);
        ui.painter().set(
            backdrop,
            egui::epaint::RectShape::filled(inside, SHEET_RADIUS - 1, kit::DETAIL),
        );
    });
    let ready = kept > 0;
    app.ui.create_folder = choices.folder.clone();
    choices.store(ctx);
    if ready && !add && save_pressed(app, ctx) {
        add = true;
    }
    if add {
        add_kept(app, ctx, detected);
    } else if by_hand || login {
        let folder = app.ui.create_folder.clone();
        forget(app, ctx);
        super::items::open_add(app);
        app.ui.create_folder = folder;
        if login {
            app.add_form.kind = CredentialKind::Login;
            app.ui.sheet = Some(super::Sheet::AddItem { kind_chosen: true });
            app.ui.focus_form_name = true;
        }
    } else if cancel {
        forget(app, ctx);
        close_sheet(app, ctx);
    }
    if response.escape {
        forget(app, ctx);
    }
    response.escape
}

/// The paste field. While the owner edits it, it is a plain multi-line field. Otherwise
/// it shows [`masked_paste`]: one line for each credential found, with the variable and
/// the public prefix of the value, never the value. A paste ends the editing at once, so
/// the pasted values show masked; a click, Return, or Space on the masked text edits it
/// again.
fn paste_field(ui: &mut egui::Ui, value: &mut String, detected: &[Detected]) {
    super::presize(value, SECRET_VALUE_CAPACITY);
    let id = super::secret_field_id(PASTE_FIELD);
    let width = ui.available_width();
    let editing = value.is_empty() || ui.memory(|memory| memory.has_focus(id));
    if editing {
        // The frame of a paste draws dots: the text shows masked from the next frame.
        let pasting = ui.input(|input| {
            input
                .events
                .iter()
                .any(|event| matches!(event, egui::Event::Paste(_)))
        });
        let response = ui.add(
            TextEdit::multiline(value)
                .password(pasting)
                .id(id)
                .char_limit(SECRET_VALUE_CAPACITY / 4)
                .font(egui::FontId::monospace(PASTE_FONT))
                .text_color(kit::LABEL)
                .hint_text(kit::text("⌘V", Font::Mono).color(kit::TERTIARY))
                .frame(field_frame(ui))
                .min_size(egui::Vec2::new(width, PASTE_HEIGHT))
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        if response.has_focus() {
            kit::focus_ring(ui.painter(), response.rect, 6);
        }
        ui.ctx().accesskit_node_builder(response.id, |node| {
            node.set_label("Paste a credential");
        });
        if pasting && response.changed() {
            response.surrender_focus();
        }
        // The owner pastes at once, also after a click on "+".
        kit::claim_first_field(&response);
        return;
    }
    let (rect, response) =
        ui.allocate_exact_size(egui::Vec2::new(width, PASTE_HEIGHT), Sense::click());
    response.widget_info(|| {
        WidgetInfo::labeled(WidgetType::Button, true, "The pasted text, hidden. Edit it")
    });
    let response = response.on_hover_cursor(egui::CursorIcon::Text);
    if response.clicked() {
        ui.memory_mut(|memory| memory.request_focus(id));
    }
    if ui.is_rect_visible(rect) {
        let frame = field_frame(ui);
        // `Frame::paint` takes the content rect and adds the inner margin around it.
        let inner = rect - frame.total_margin();
        let painter = ui.painter();
        painter.add(frame.paint(inner));
        let galley = kit::galley(
            ui,
            RichText::new(masked_paste(detected))
                .font(egui::FontId::monospace(PASTE_FONT))
                .color(kit::LABEL),
        );
        painter
            .with_clip_rect(inner.intersect(painter.clip_rect()))
            .galley(inner.min, galley, kit::LABEL);
        if response.has_focus() {
            kit::focus_ring(painter, rect, 6);
        }
    }
}

/// The white field of the mockup: a hairline edge, 6 points round, 7 by 9 points inside.
fn field_frame(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::NONE
        .fill(kit::SURFACE)
        .stroke(egui::Stroke::new(
            1.0 / ui.ctx().pixels_per_point(),
            egui::Color32::from_black_alpha(46),
        ))
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(9, 7))
}

/// The paste without a secret value: `STRIPE_SECRET_KEY=sk_test_••••••••` for each line
/// of a `.env` file, the masked value alone for one value, and the mask when Apassy found
/// nothing. A comment line can hold a value, so it does not show.
pub(super) fn masked_paste(detected: &[Detected]) -> String {
    if detected.is_empty() {
        return MASKED_VALUE.to_owned();
    }
    detected
        .iter()
        .map(|found| match (found.line, &found.env_name) {
            (Some(_), Some(variable)) => format!("{variable}={}", masked_value(found)),
            _ => masked_value(found),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The secret value of a detected credential as the paste shows it: the public value
/// prefix of its provider (`sk_test_`, `ghp_`) or the scheme of its URL, then the mask.
/// Nothing of the secret part of the value, as in the masks of the iPhone app.
fn masked_value(found: &Detected) -> String {
    let field = found
        .env_field
        .as_deref()
        .and_then(|name| found.field(name))
        .filter(|field| field.secret)
        .or_else(|| found.fields.iter().find(|field| field.secret));
    let Some(field) = field else {
        return MASKED_VALUE.to_owned();
    };
    let value = field.value.expose();
    if let Some((provider, prefix)) = providers::prefix_match(value)
        && found.provider.as_deref() == Some(provider.id.as_str())
    {
        return format!("{prefix}{MASKED_VALUE}");
    }
    if field.name == detect::URL_FIELD
        && let Some((scheme, _)) = value.split_once("://")
        && !scheme.is_empty()
        && scheme.len() <= 16
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return format!("{scheme}://{MASKED_VALUE}");
    }
    MASKED_VALUE.to_owned()
}

/// The examples of the mockup, with synthetic values that look fake.
const EXAMPLES: [(&str, &str); 3] = [
    ("API key", "sk-ant-api03-EXAMPLE0EXAMPLE0EXAMPLE0EXAMPLE0"),
    (
        ".env file",
        "# .env\nRESEND_API_KEY=re_EXAMPLE0EXAMPLE0\nSTRIPE_SECRET_KEY=sk_test_EXAMPLE0EXAMPLE0\nSENTRY_AUTH_TOKEN=sntrys_EXAMPLE0EXAMPLE0\nDATABASE_PASSWORD=example-pass\n",
    ),
    (
        "Database URL",
        "postgres://billing_rw:EXAMPLE0@db.example.com:5432/billing",
    ),
];

/// "Examples:" with one button for each kind of paste, as in the mockup: a button puts
/// a synthetic example in the field. On the right, the quiet "Fill in by hand…" link to
/// the add form, for a login, an SSH key, or another kind that a paste does not fit.
/// Returns true when the owner chose the link.
fn examples(ui: &mut egui::Ui, value: &mut String) -> bool {
    let mut by_hand = false;
    egui::Sides::new().show(
        ui,
        |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.label(kit::text("Examples:", Font::Footnote).color(kit::TERTIARY));
            for (label, example) in EXAMPLES {
                if chip(ui, label, &format!("Paste the {label} example")).clicked() {
                    use zeroize::Zeroize;
                    value.zeroize();
                    super::presize(value, SECRET_VALUE_CAPACITY);
                    value.push_str(example);
                    let id = super::secret_field_id(PASTE_FIELD);
                    ui.memory_mut(|memory| memory.surrender_focus(id));
                }
            }
        },
        |ui| {
            by_hand = link(ui, "Fill in by hand…")
                .on_hover_text("A login, an SSH key, or another kind, field by field")
                .clicked();
        },
    );
    by_hand
}

/// A small gray button of the "Examples:" row: 11 points, 5 points round.
fn chip(ui: &mut egui::Ui, label: &str, name: &str) -> egui::Response {
    let galley = kit::galley(ui, kit::text(label, Font::Footnote));
    let size = galley.size() + egui::Vec2::new(14.0, 4.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, ui.is_enabled(), name));
    if ui.is_rect_visible(rect) {
        let fill = if response.is_pointer_button_down_on() {
            kit::FILL_PRESSED
        } else if response.hovered() {
            kit::FILL_HOVER
        } else {
            kit::FILL
        };
        let painter = ui.painter();
        painter.rect_filled(rect, 5, fill);
        painter.galley(rect.center() - galley.size() / 2.0, galley, kit::SECONDARY);
        if response.has_focus() {
            kit::focus_ring(painter, rect, 5);
        }
    }
    response
}

/// A quiet link: accent text at 11 points, without a fill.
fn link(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let galley = kit::galley(ui, kit::text(label, Font::Footnote));
    let size = galley.size() + egui::Vec2::new(4.0, 4.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Link, ui.is_enabled(), label));
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    if ui.is_rect_visible(rect) {
        let color = if response.hovered() {
            kit::ACCENT
        } else {
            kit::ACCENT_TEXT
        };
        let painter = ui.painter();
        painter.galley(rect.center() - galley.size() / 2.0, galley, color);
        if response.has_focus() {
            kit::focus_ring(painter, rect, 4);
        }
    }
    response
}

/// The push button of a macOS sheet, as the mockup's `.btn`: white, a hairline edge,
/// 28 points high, 7 points round.
fn push_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let galley = kit::galley(ui, kit::text(label, Font::Body));
    let size = egui::Vec2::new(galley.size().x + 28.0, 28.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, ui.is_enabled(), label));
    if ui.is_rect_visible(rect) {
        let fill = if response.is_pointer_button_down_on() {
            kit::FILL_PRESSED
        } else if response.hovered() {
            kit::WINDOW
        } else {
            kit::SURFACE
        };
        let painter = ui.painter();
        painter.rect(
            rect,
            7,
            fill,
            egui::Stroke::new(
                1.0 / ui.ctx().pixels_per_point(),
                egui::Color32::from_black_alpha(52),
            ),
            egui::StrokeKind::Inside,
        );
        painter.galley(rect.center() - galley.size() / 2.0, galley, kit::LABEL);
        if response.has_focus() {
            kit::focus_ring(painter, rect, 7);
        }
    }
    response
}

/// The Folder pop-up of the footer, as the mockup's `.pop`: a gray fill without an
/// edge, 22 points high. A choice with Return or Space closes the menu, and the focus
/// goes back to the button after a choice or Escape, as with [`kit::picker`].
pub(super) fn folder_menu(
    ui: &mut egui::Ui,
    value: &mut Option<String>,
    options: &[(Option<String>, String)],
    selected: &str,
) -> egui::Response {
    let label = kit::text(selected, Font::Callout)
        .size(12.5)
        .color(kit::LABEL);
    let width = (kit::galley(ui, label.clone()).size().x + 34.0).clamp(90.0, 240.0);
    let response = ui
        .scope(|ui| {
            let widgets = &mut ui.style_mut().visuals.widgets;
            for (state, fill) in [
                (&mut widgets.inactive, kit::FILL),
                (&mut widgets.hovered, kit::FILL_HOVER),
                (&mut widgets.active, kit::FILL_PRESSED),
                (&mut widgets.open, kit::FILL_HOVER),
            ] {
                state.weak_bg_fill = fill;
                state.bg_fill = fill;
                state.bg_stroke = egui::Stroke::NONE;
                state.corner_radius = egui::CornerRadius::same(6);
                state.expansion = 0.0;
            }
            ui.spacing_mut().interact_size.y = 22.0;
            ui.spacing_mut().button_padding = egui::Vec2::new(8.0, 2.0);
            egui::ComboBox::from_id_salt("new-credential-folder")
                .width(width)
                .selected_text(label)
                .icon(|ui, rect, _visuals, _open| {
                    let center = rect.center();
                    ui.painter().line(
                        vec![
                            center + egui::Vec2::new(-3.2, -1.6),
                            center + egui::Vec2::new(0.0, 1.6),
                            center + egui::Vec2::new(3.2, -1.6),
                        ],
                        egui::Stroke::new(1.4, kit::SECONDARY),
                    );
                })
                .show_ui(ui, |ui| {
                    for (option, label) in options {
                        if ui.selectable_value(value, option.clone(), label).clicked() {
                            ui.close();
                        }
                    }
                })
                .response
        })
        .inner;
    let ctx = ui.ctx();
    let open = egui::ComboBox::is_open(ctx, response.id);
    let key = response.id.with("apassy-picker-open");
    let was_open = ctx.data(|data| data.get_temp::<bool>(key)).unwrap_or(false);
    ctx.data_mut(|data| data.insert_temp(key, open));
    if was_open && !open && kit::keyboard_mode(ctx) {
        response.request_focus();
    }
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    response
}

/// One row for each detected credential, in a white group as in the mockup: the
/// checkbox of a paste with several, the provider tile, the title (the owner edits it
/// in place, without a box), the summary line, and the environment cap.
fn rows(ui: &mut egui::Ui, detected: &[Detected], choices: &mut Choices) {
    let several = detected.len() > 1;
    let hairline = 1.0 / ui.ctx().pixels_per_point();
    egui::Frame::NONE
        .fill(kit::SURFACE)
        .stroke(egui::Stroke::new(
            hairline,
            egui::Color32::from_black_alpha(26),
        ))
        .corner_radius(10)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            for (index, found) in detected.iter().enumerate() {
                let Some((_, title, keep)) = choices.rows.get_mut(index) else {
                    continue;
                };
                if index > 0 {
                    let left = ui.min_rect().left() + 12.0;
                    let y = ui.cursor().top();
                    ui.painter().hline(
                        left..=ui.max_rect().right(),
                        y,
                        egui::Stroke::new(hairline, kit::SEPARATOR),
                    );
                }
                egui::Frame::NONE
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            if several {
                                let check = checkbox(ui, keep);
                                let name = format!("Add {}", found.title);
                                ui.ctx().accesskit_node_builder(check.id, |node| {
                                    node.set_label(name);
                                });
                            }
                            kit::tile(ui, &row_tile(found, title), 32.0);
                            let cap = row_cap(found);
                            let cap_width = cap.map_or(0.0, |(label, _)| {
                                kit::galley(ui, kit::medium(label, Font::Footnote)).size().x + 24.0
                            });
                            ui.vertical(|ui| {
                                ui.set_width((ui.available_width() - cap_width).max(80.0));
                                ui.spacing_mut().item_spacing.y = 2.0;
                                title_field(ui, title, index);
                                ui.add(Label::new(summary(ui, found)).truncate());
                            });
                            if let Some((label, red)) = cap {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| kit::cap(ui, label, red),
                                );
                            }
                        });
                    });
            }
        });
}

/// The title of a row: 13 points at weight 500, edited in place without a box. A light
/// fill shows on hover and while the owner edits it.
fn title_field(ui: &mut egui::Ui, title: &mut String, index: usize) {
    let background = ui.painter().add(egui::Shape::Noop);
    let mut layouter = |ui: &egui::Ui, text: &dyn egui::TextBuffer, _wrap_width: f32| {
        let mut job = egui::text::LayoutJob::default();
        kit::row_title(text.as_str()).color(kit::LABEL).append_to(
            &mut job,
            ui.style(),
            egui::FontSelection::Default,
            egui::Align::Center,
        );
        ui.fonts_mut(|fonts| fonts.layout_job(job))
    };
    let field = ui.add(
        TextEdit::singleline(title)
            .id_salt(("new-credential-title", index))
            .frame(egui::Frame::NONE)
            .margin(egui::Margin::ZERO)
            .layouter(&mut layouter)
            .desired_width(f32::INFINITY),
    );
    if field.hovered() || field.has_focus() {
        ui.painter().set(
            background,
            egui::epaint::RectShape::filled(
                field.rect.expand2(egui::Vec2::new(4.0, 1.0)),
                4,
                kit::FILL,
            ),
        );
    }
    ui.ctx().accesskit_node_builder(field.id, |node| {
        node.set_label(format!("Title of the credential on row {}", index + 1));
    });
}

/// "Stripe · `STRIPE_SECRET_KEY` · api.stripe.com" at 11.5 points, the variable in
/// monospace, as in the mockup.
fn summary(ui: &egui::Ui, found: &Detected) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mut append = |text: RichText| {
        text.color(kit::SECONDARY).append_to(
            &mut job,
            ui.style(),
            egui::FontSelection::Default,
            egui::Align::Center,
        );
    };
    append(kit::text(provider_label(found), Font::Footnote).size(SUMMARY_FONT));
    if let Some(variable) = &found.env_name {
        append(kit::text(" · ", Font::Footnote).size(SUMMARY_FONT));
        append(RichText::new(variable.as_str()).font(egui::FontId::monospace(SUMMARY_FONT)));
    }
    if let Some(host) = found.hosts.first() {
        append(kit::text(format!(" · {host}"), Font::Footnote).size(SUMMARY_FONT));
    }
    job
}

/// A macOS checkbox: 14 points, the accent fill with a white check when it is on.
fn checkbox(ui: &mut egui::Ui, on: &mut bool) -> egui::Response {
    let (rect, mut response) = ui.allocate_exact_size(egui::Vec2::splat(14.0), Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let checked = *on;
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::Checkbox, ui.is_enabled(), checked, ""));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if checked {
            painter.rect_filled(rect, 3, kit::ACCENT);
            let point = |x: f32, y: f32| rect.min + egui::Vec2::new(x, y);
            painter.line(
                vec![point(3.5, 7.2), point(6.0, 9.8), point(10.5, 4.2)],
                egui::Stroke::new(1.8, egui::Color32::WHITE),
            );
        } else {
            painter.rect(
                rect,
                3,
                kit::SURFACE,
                egui::Stroke::new(1.0, kit::BORDER),
                egui::StrokeKind::Inside,
            );
        }
        if response.has_focus() {
            kit::focus_ring(painter, rect, 3);
        }
    }
    response
}

/// The tile of a row: the provider tile, or a gray key for a secret without a provider,
/// as in the mockup.
fn row_tile(found: &Detected, title: &str) -> kit::Tile {
    if found.provider.is_none() && found.kind == CredentialKind::Custom {
        return kit::Tile::icon(egui::Color32::from_rgb(142, 142, 147), kit::Icon::Key);
    }
    super::credential_tile(found.kind, &provider_label(found), title)
}

/// Add the kept rows in the chosen folder, select the new credential (the first of
/// several), and say what was added.
fn add_kept(app: &mut DesktopApp, ctx: &egui::Context, detected: Vec<Detected>) {
    let choices = Choices::load(ctx);
    let kept = choices.kept(detected);
    if kept.is_empty() {
        return;
    }
    let folder = choices.folder.clone();
    let result = app
        .owner_ui
        .session
        .add_detected_items(&kept, folder.as_deref());
    drop(kept);
    let added = match result {
        Ok(added) => added,
        Err(err) => {
            app.set_err(err.message);
            return;
        }
    };
    let lines = app
        .owner_ui
        .session
        .added_credentials(&added)
        .unwrap_or_default();
    forget(app, ctx);
    close_sheet(app, ctx);
    if let Some(first) = added.first() {
        super::items::reveal_saved(app, first.id, folder.clone());
    }
    let place = FolderTree::load(app).path_label(folder.as_deref());
    match lines.as_slice() {
        [one] => app.set_ok(format!("Added {} in {place}.", one.line())),
        _ => app.set_ok(format!("Added {} credentials in {place}.", added.len())),
    }
}

#[cfg(test)]
#[path = "new_credential_tests.rs"]
mod tests;
