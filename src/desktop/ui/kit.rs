//! The Apassy design system: SwiftUI-style tokens and controls drawn with egui.
//!
//! Light appearance only. The kit loads SF Pro and SF Mono from macOS at start. It does
//! not bundle them. Without them, the default egui fonts stay.
//!
//! The controls follow macOS system conventions: grouped form sections, a sidebar list,
//! bordered-prominent buttons, switches, segmented pickers, sheets, and a toast for
//! results. Each control reports its label to AccessKit.
//!
//! The demo build (without `vault`) uses only part of the kit.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use std::sync::Arc;

use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId,
    Frame, Id, Key, Label, Layout, Margin, Modal, Order, Painter, PointerButton, Pos2, Rect,
    Response, RichText, ScrollArea, Sense, Shadow, Shape, Stroke, StrokeKind, TextEdit, TextStyle,
    TextWrapMode, Theme, ThemePreference, Ui, UiBuilder, Vec2, ViewportCommand, WidgetInfo,
    WidgetText, WidgetType, epaint,
};

// ---- Color tokens (macOS light appearance). ----

pub(crate) const WINDOW: Color32 = Color32::from_rgb(250, 250, 251);
pub(crate) const SIDEBAR: Color32 = Color32::from_rgb(236, 236, 239);
/// The list column (ADR 0026): white, as the content list of Mail.
pub(crate) const LIST: Color32 = Color32::WHITE;
/// The detail column, behind its white groups.
pub(crate) const DETAIL: Color32 = Color32::from_rgb(246, 246, 247);
/// The fill of the selected list row. White text on it passes 4.5:1.
pub(crate) const SELECTION: Color32 = Color32::from_rgb(10, 108, 255);
/// The one colored mark of the window: production, and what blocks an agent.
pub(crate) const PRODUCTION: Color32 = Color32::from_rgb(224, 53, 43);
pub(crate) const SURFACE: Color32 = Color32::WHITE;
/// Hairlines between rows.
pub(crate) const SEPARATOR: Color32 = Color32::from_rgb(232, 232, 236);
/// The outline of a grouped section.
pub(crate) const SECTION_EDGE: Color32 = Color32::from_rgb(228, 228, 233);
/// Text field borders.
pub(crate) const BORDER: Color32 = Color32::from_rgb(210, 210, 216);
pub(crate) const LABEL: Color32 = Color32::from_rgb(29, 29, 31);
pub(crate) const SECONDARY: Color32 = Color32::from_rgb(106, 106, 112);
/// Placeholders and decoration only. It is too light for text that carries meaning.
pub(crate) const TERTIARY: Color32 = Color32::from_rgb(160, 160, 166);
pub(crate) const FILL: Color32 = Color32::from_rgb(240, 240, 243);
pub(crate) const FILL_HOVER: Color32 = Color32::from_rgb(232, 232, 236);
pub(crate) const FILL_PRESSED: Color32 = Color32::from_rgb(222, 222, 227);
pub(crate) const ACCENT: Color32 = Color32::from_rgb(0, 122, 255);
const ACCENT_HOVER: Color32 = Color32::from_rgb(0, 108, 230);
const ACCENT_PRESSED: Color32 = Color32::from_rgb(0, 94, 204);
/// Accent for text on white. It passes 4.5:1.
pub(crate) const ACCENT_TEXT: Color32 = Color32::from_rgb(0, 102, 214);

/// The meaning of a color. Status colors always come with a label or an icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tone {
    Neutral,
    Accent,
    Good,
    Warning,
    Critical,
}

impl Tone {
    /// For dots, icons, bars, and fills.
    pub(crate) fn mark(self) -> Color32 {
        match self {
            Self::Neutral => Color32::from_rgb(142, 142, 147),
            Self::Accent => ACCENT,
            Self::Good => Color32::from_rgb(52, 199, 89),
            Self::Warning => Color32::from_rgb(255, 149, 0),
            Self::Critical => Color32::from_rgb(255, 59, 48),
        }
    }

    /// For text on white or on the tint. Each passes 4.5:1.
    pub(crate) fn text(self) -> Color32 {
        match self {
            Self::Neutral => SECONDARY,
            Self::Accent => ACCENT_TEXT,
            Self::Good => Color32::from_rgb(29, 128, 54),
            Self::Warning => Color32::from_rgb(166, 82, 0),
            Self::Critical => Color32::from_rgb(200, 30, 30),
        }
    }

    /// A light wash for banners and tags.
    pub(crate) fn tint(self) -> Color32 {
        match self {
            Self::Neutral => FILL,
            Self::Accent => Color32::from_rgb(232, 242, 255),
            Self::Good => Color32::from_rgb(233, 247, 237),
            Self::Warning => Color32::from_rgb(255, 245, 229),
            Self::Critical => Color32::from_rgb(255, 238, 237),
        }
    }
}

// ---- Typography. ----

/// SwiftUI text styles at macOS sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Font {
    LargeTitle,
    Title,
    Title3,
    Headline,
    Body,
    Callout,
    Footnote,
    Mono,
    MonoSmall,
}

impl Font {
    pub(crate) fn size(self) -> f32 {
        match self {
            Self::LargeTitle => 26.0,
            Self::Title => 22.0,
            Self::Title3 => 15.0,
            Self::Headline | Self::Body => 13.0,
            Self::Callout | Self::Mono => 12.0,
            Self::Footnote | Self::MonoSmall => 11.0,
        }
    }

    fn weight(self) -> f32 {
        match self {
            Self::LargeTitle | Self::Title => 700.0,
            Self::Title3 | Self::Headline => 600.0,
            _ => 400.0,
        }
    }

    fn mono(self) -> bool {
        matches!(self, Self::Mono | Self::MonoSmall)
    }
}

/// Text in a style. SF Pro gets the weight and the optical size of the style.
pub(crate) fn text(value: impl Into<String>, font: Font) -> RichText {
    let size = font.size();
    let text = RichText::new(value).size(size);
    if font.mono() {
        return text.family(FontFamily::Monospace);
    }
    let text = text
        .variation(b"wght", font.weight())
        .variation(b"opsz", size.clamp(17.0, 28.0));
    if size >= 20.0 {
        text.extra_letter_spacing(-0.3)
    } else {
        text
    }
}

/// Medium weight for emphasis inside body text.
pub(crate) fn medium(value: impl Into<String>, font: Font) -> RichText {
    text(value, font).variation(b"wght", 560.0)
}

/// The title of a list row: 13 points at weight 500, as in the mockup.
pub(crate) fn row_title(value: impl Into<String>) -> RichText {
    text(value, Font::Body).variation(b"wght", 500.0)
}

/// A wrapping label.
pub(crate) fn paragraph(ui: &mut Ui, value: impl Into<String>, font: Font, color: Color32) {
    ui.add(Label::new(text(value, font).color(color)).wrap());
}

/// A wrapping secondary note under a control or a section.
pub(crate) fn note(ui: &mut Ui, value: impl Into<String>) {
    paragraph(ui, value, Font::Footnote, SECONDARY);
}

/// A wrapping note in a status color.
pub(crate) fn tone_note(ui: &mut Ui, value: impl Into<String>, tone: Tone) {
    paragraph(ui, value, Font::Footnote, tone.text());
}

// ---- Time. ----

/// Seconds since the Unix epoch.
#[cfg(feature = "vault")]
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// "just now", "5 min ago", "3 h ago", "yesterday", "4 days ago", or the date. Lists
/// show this form; the exact UTC time goes in a tooltip or a detail sheet.
#[cfg(feature = "vault")]
pub(crate) fn relative_time(at: u64, now: u64) -> String {
    let age = now.saturating_sub(at);
    match age {
        0..60 => "just now".to_owned(),
        60..3_600 => format!("{} min ago", age / 60),
        3_600..86_400 => format!("{} h ago", age / 3_600),
        86_400..172_800 => "yesterday".to_owned(),
        172_800..604_800 => format!("{} days ago", age / 86_400),
        _ => crate::vault::format_utc(at)
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_owned(),
    }
}

// ---- Theme. ----

const SF_PRO: &str = "/System/Library/Fonts/SFNS.ttf";
const SF_MONO: &str = "/System/Library/Fonts/SFNSMono.ttf";

/// Apply the fonts, colors, and spacing of the kit.
pub(crate) fn apply_theme(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.options_mut(|options| options.theme_preference = ThemePreference::Light);
    ctx.set_visuals_of(Theme::Light, visuals());
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(22.0)),
            (TextStyle::Body, FontId::proportional(13.0)),
            (TextStyle::Button, FontId::proportional(13.0)),
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Monospace, FontId::monospace(12.0)),
        ]
        .into();
        let spacing = &mut style.spacing;
        spacing.item_spacing = Vec2::new(8.0, 6.0);
        spacing.button_padding = Vec2::new(10.0, 4.0);
        spacing.interact_size = Vec2::new(40.0, 24.0);
        spacing.combo_height = 320.0;
        spacing.menu_margin = Margin::same(6);
        spacing.window_margin = Margin::same(16);
    });
}

/// SF Pro and SF Mono from the system, in front of the egui fonts. The egui fonts stay
/// as fallbacks for symbols.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let tweak = |coords: &[(&[u8; 4], f32)]| epaint::text::FontTweak {
        coords: epaint::text::VariationCoords::new(coords.iter().copied()),
        ..Default::default()
    };
    if let Ok(bytes) = std::fs::read(SF_PRO) {
        let data = FontData::from_owned(bytes).tweak(tweak(&[(b"opsz", 17.0), (b"wght", 400.0)]));
        fonts.font_data.insert("sf-pro".to_owned(), Arc::new(data));
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "sf-pro".to_owned());
    }
    if let Ok(bytes) = std::fs::read(SF_MONO) {
        let data = FontData::from_owned(bytes).tweak(tweak(&[(b"wght", 400.0)]));
        fonts.font_data.insert("sf-mono".to_owned(), Arc::new(data));
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "sf-mono".to_owned());
    }
    ctx.set_fonts(fonts);
}

fn visuals() -> egui::Visuals {
    let mut v = egui::Visuals::light();
    v.panel_fill = WINDOW;
    v.window_fill = SURFACE;
    v.window_stroke = Stroke::new(1.0, SECTION_EDGE);
    v.window_corner_radius = CornerRadius::same(12);
    v.window_shadow = soft_shadow(28, 30);
    v.popup_shadow = soft_shadow(14, 34);
    v.menu_corner_radius = CornerRadius::same(8);
    v.extreme_bg_color = SURFACE;
    v.text_edit_bg_color = Some(SURFACE);
    v.faint_bg_color = Color32::from_rgb(248, 248, 250);
    v.code_bg_color = FILL;
    v.hyperlink_color = ACCENT_TEXT;
    v.warn_fg_color = Tone::Warning.text();
    v.error_fg_color = Tone::Critical.text();
    v.selection.bg_fill = Color32::from_rgb(196, 222, 255);
    // The focus ring of a text field. 2 points of solid accent pass 3:1 (WCAG 1.4.11).
    v.selection.stroke = Stroke::new(2.0, ACCENT);
    v.indent_has_left_vline = false;
    v.striped = false;
    v.button_frame = true;

    let radius = CornerRadius::same(6);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = SURFACE;
    w.noninteractive.weak_bg_fill = SURFACE;
    w.noninteractive.bg_stroke = Stroke::new(1.0, SEPARATOR);
    w.noninteractive.fg_stroke = Stroke::new(1.0, LABEL);
    w.noninteractive.corner_radius = radius;
    w.inactive.bg_fill = FILL;
    w.inactive.weak_bg_fill = FILL;
    w.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    w.inactive.fg_stroke = Stroke::new(1.0, LABEL);
    w.inactive.corner_radius = radius;
    w.inactive.expansion = 0.0;
    w.hovered.bg_fill = FILL_HOVER;
    w.hovered.weak_bg_fill = FILL_HOVER;
    w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(188, 188, 196));
    w.hovered.fg_stroke = Stroke::new(1.0, LABEL);
    w.hovered.corner_radius = radius;
    w.hovered.expansion = 0.0;
    w.active.bg_fill = FILL_PRESSED;
    w.active.weak_bg_fill = FILL_PRESSED;
    // egui draws a focused built-in widget, such as a menu button, as active.
    w.active.bg_stroke = Stroke::new(2.0, ACCENT);
    w.active.fg_stroke = Stroke::new(1.0, LABEL);
    w.active.corner_radius = radius;
    w.active.expansion = 0.0;
    w.open.bg_fill = FILL;
    w.open.weak_bg_fill = FILL;
    w.open.bg_stroke = Stroke::new(1.0, BORDER);
    w.open.fg_stroke = Stroke::new(1.0, LABEL);
    w.open.corner_radius = radius;
    v
}

fn soft_shadow(blur: u8, alpha: u8) -> Shadow {
    Shadow {
        offset: [0, (blur / 3) as i8],
        blur,
        spread: 0,
        color: Color32::from_black_alpha(alpha),
    }
}

/// One physical pixel, for hairlines.
fn hairline(ui: &Ui) -> f32 {
    1.0 / ui.ctx().pixels_per_point()
}

/// A text galley with a fallback color, for painted controls.
pub(crate) fn galley(ui: &Ui, value: RichText) -> Arc<epaint::Galley> {
    WidgetText::from(value).into_galley(
        ui,
        Some(TextWrapMode::Extend),
        f32::INFINITY,
        TextStyle::Body,
    )
}

// ---- Window. ----

/// The title bar is transparent and the content runs under it (macOS unified style).
/// A drag on this strip moves the window. A double click zooms it.
pub(crate) fn window_drag_region(ui: &Ui, rect: Rect) {
    let id = Id::new(("apassy-window-drag", rect.left().round() as i32));
    // Not focusable: the strip is not a stop in the Tab order.
    let response = ui.interact(rect, id, Sense::CLICK | Sense::DRAG);
    if response.drag_started_by(PointerButton::Primary) {
        ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
    }
    if response.double_clicked() {
        let zoomed = ui.input(|input| input.viewport().maximized.unwrap_or(false));
        ui.ctx()
            .send_viewport_cmd(ViewportCommand::Maximized(!zoomed));
    }
}

/// Height of the transparent title bar strip.
pub(crate) const TITLE_BAR: f32 = 38.0;

// ---- Page structure. ----

/// The smallest side margin of a page column.
const COLUMN_MIN_SIDE: f32 = 28.0;

/// A centered reading column at most `max_width` wide, with side margins of at least
/// 28 points.
///
/// The column is a child UI at a computed rect, not a frame margin: `Margin` holds
/// `i8`, so a side margin over 127 points would saturate and let the column grow
/// past `max_width` in a wide window.
pub(crate) fn column<R>(ui: &mut Ui, max_width: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    column_with_bottom_space(ui, max_width, 36.0, add)
}

/// A reading column with an explicit bottom inset, also used by fixed page headers.
pub(crate) fn column_with_bottom_space<R>(
    ui: &mut Ui,
    max_width: f32,
    bottom_space: f32,
    add: impl FnOnce(&mut Ui) -> R,
) -> R {
    let available = ui.available_rect_before_wrap();
    let width = (available.width() - 2.0 * COLUMN_MIN_SIDE)
        .min(max_width)
        .max(0.0)
        .floor();
    let left = (available.left() + (available.width() - width) / 2.0).round();
    let rect = Rect::from_min_size(
        Pos2::new(left, available.top()),
        Vec2::new(width, available.height()),
    );
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::top_down(Align::Min)),
        |ui| {
            ui.set_width(width);
            let inner = add(ui);
            ui.add_space(bottom_space);
            inner
        },
    )
    .inner
}

/// The large title of a page, with controls on the right and an optional subtitle.
pub(crate) fn page_header(
    ui: &mut Ui,
    title: &str,
    subtitle: Option<&str>,
    trailing: impl FnOnce(&mut Ui),
) {
    ui.horizontal(|ui| {
        ui.label(text(title, Font::Title).color(LABEL));
        ui.with_layout(Layout::right_to_left(Align::Center), trailing);
    });
    if let Some(subtitle) = subtitle {
        paragraph(ui, subtitle, Font::Callout, SECONDARY);
    }
    ui.add_space(18.0);
}

/// The indent of the text after a [`dot`]: the dot and the item spacing.
pub(crate) const DOT_INDENT: f32 = 18.0;

/// The lines under the first line of a list row, indented to its text (for example
/// past a status dot). Unlike `ui.horizontal`, this adds no minimum control height,
/// so a footnote sits close to the line above it.
pub(crate) fn indented<R>(ui: &mut Ui, indent: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::NONE
        .inner_margin(Margin {
            left: indent.clamp(0.0, 127.0) as i8,
            ..Margin::ZERO
        })
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            add(ui)
        })
        .inner
}

/// "‹ Title" above a page title. Returns true on a click.
pub(crate) fn back_link(ui: &mut Ui, label: &str) -> bool {
    let clicked =
        button_with(ui, Some(Icon::ChevronLeft), label, Style::Link, Size::Small).clicked();
    ui.add_space(2.0);
    clicked
}

// ---- Grouped sections (SwiftUI `Form` with `.formStyle(.grouped)`). ----

const ROW_PAD_X: f32 = 12.0;
const ROW_PAD_Y: f32 = 8.0;
/// Width of the label column in a form row.
const FIELD_LABEL_WIDTH: f32 = 148.0;

/// The rows of one section. Rows get a hairline between them.
pub(crate) struct Section<'u> {
    ui: &'u mut Ui,
    rows: usize,
}

/// A white rounded group with an optional header above and a footer below.
pub(crate) fn section<R>(
    ui: &mut Ui,
    header: Option<&str>,
    footer: Option<&str>,
    add: impl FnOnce(&mut Section<'_>) -> R,
) -> R {
    if let Some(header) = header {
        ui.horizontal(|ui| {
            ui.add_space(2.0);
            ui.label(text(header, Font::Headline).color(LABEL));
        });
        ui.add_space(2.0);
    }
    let inner = Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, SECTION_EDGE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(0, 2))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            add(&mut Section { ui, rows: 0 })
        })
        .inner;
    if let Some(footer) = footer {
        ui.add_space(4.0);
        Frame::NONE
            .inner_margin(Margin::symmetric(ROW_PAD_X as i8, 0))
            .show(ui, |ui| note(ui, footer));
    }
    ui.add_space(20.0);
    inner
}

impl Section<'_> {
    fn separator(&mut self) {
        if self.rows > 0 {
            let width = self.ui.available_width();
            let (rect, _) = self
                .ui
                .allocate_exact_size(Vec2::new(width, 1.0), Sense::hover());
            let stroke = Stroke::new(hairline(self.ui), SEPARATOR);
            self.ui.painter().hline(
                (rect.left() + ROW_PAD_X)..=rect.right(),
                rect.center().y,
                stroke,
            );
        }
        self.rows += 1;
    }

    /// A padded row with custom content.
    pub(crate) fn row<R>(&mut self, add: impl FnOnce(&mut Ui) -> R) -> R {
        self.separator();
        Frame::NONE
            .inner_margin(Margin::symmetric(ROW_PAD_X as i8, ROW_PAD_Y as i8))
            .show(self.ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing.y = 4.0;
                add(ui)
            })
            .inner
    }

    /// A whole-row button with a hover highlight. `label` is its name for VoiceOver.
    pub(crate) fn clickable_row(&mut self, label: &str, add: impl FnOnce(&mut Ui)) -> Response {
        self.separator();
        let background = self.ui.painter().add(Shape::Noop);
        let response = self
            .ui
            .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
                ui.style_mut().interaction.selectable_labels = false;
                Frame::NONE
                    .inner_margin(Margin::symmetric(ROW_PAD_X as i8, ROW_PAD_Y as i8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().item_spacing.y = 2.0;
                        add(ui);
                    });
            })
            .response;
        if response.hovered() || response.has_focus() {
            let fill = if response.is_pointer_button_down_on() {
                FILL_PRESSED
            } else {
                Color32::from_rgb(246, 246, 248)
            };
            let rect = response.rect.shrink2(Vec2::new(4.0, 1.0));
            self.ui
                .painter()
                .set(background, epaint::RectShape::filled(rect, 6, fill));
            if response.has_focus() {
                inner_focus_ring(self.ui.painter(), rect, 6);
            }
        }
        if response.gained_focus() {
            response.scroll_to_me(None);
        }
        let enabled = self.ui.is_enabled();
        response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, label));
        response
    }

    /// SwiftUI `LabeledContent`: a label on the left and a value on the right. A value
    /// that does not fit on the line goes under the label, left-aligned: a long
    /// sentence or path stays readable, and no line wraps flush right.
    pub(crate) fn labeled(&mut self, label: &str, value: impl Into<WidgetText>) {
        const GAP: f32 = 24.0;
        let value = value.into();
        self.row(|ui| {
            let label = text(label, Font::Body).color(LABEL);
            let one_line = galley(ui, label.clone()).size().x
                + GAP
                + value
                    .clone()
                    .into_galley(
                        ui,
                        Some(TextWrapMode::Extend),
                        f32::INFINITY,
                        TextStyle::Body,
                    )
                    .size()
                    .x;
            if one_line <= ui.available_width() {
                egui::Sides::new().spacing(GAP).show(
                    ui,
                    |ui| ui.label(label),
                    |ui| ui.label(value),
                );
            } else {
                ui.label(label);
                ui.add(Label::new(value).wrap());
            }
        });
    }

    /// A status row: a title with an optional note under it, and a short value on the
    /// right, centered on the row. The note belongs to its row, so it gets no row of
    /// its own with a separator above.
    pub(crate) fn status(&mut self, title: &str, note_text: Option<&str>, value: RichText) {
        self.row(|ui| {
            egui::Sides::new()
                .shrink_left()
                .wrap_mode(TextWrapMode::Wrap)
                .show(
                    ui,
                    |ui| match note_text {
                        Some(note_text) => {
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.label(text(title, Font::Body).color(LABEL));
                                note(ui, note_text);
                            });
                        }
                        // Alone, the title stays centered with the value.
                        None => {
                            ui.label(text(title, Font::Body).color(LABEL));
                        }
                    },
                    |ui| ui.label(value),
                );
        });
    }

    /// A `NavigationLink` row: icon tile, title, subtitle, a detail on the right, and a
    /// chevron.
    pub(crate) fn nav(
        &mut self,
        icon: Option<(Icon, Color32)>,
        title: &str,
        subtitle: Option<&str>,
        detail: Option<RichText>,
    ) -> Response {
        // VoiceOver reads the title with the status on the right, for example
        // "Touch ID unlock, Not set".
        let name = match &detail {
            Some(detail) if !detail.text().trim().is_empty() => {
                format!("{title}, {}", detail.text())
            }
            _ => title.to_owned(),
        };
        self.clickable_row(&name, |ui| {
            ui.horizontal(|ui| {
                if let Some((icon, color)) = icon {
                    icon_tile(ui, icon, color);
                    ui.add_space(4.0);
                }
                // A title alone sits in the row itself, so the row centers it with the
                // icon and the detail. In a vertical group it would sit at the top.
                match subtitle {
                    Some(subtitle) => {
                        ui.vertical(|ui| {
                            ui.label(text(title, Font::Body).color(LABEL));
                            ui.add(
                                Label::new(text(subtitle, Font::Footnote).color(SECONDARY))
                                    .truncate(),
                            );
                        });
                    }
                    None => {
                        ui.label(text(title, Font::Body).color(LABEL));
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    paint_icon_in(ui, Icon::ChevronRight, 12.0, TERTIARY);
                    if let Some(detail) = detail {
                        ui.add(Label::new(detail).truncate());
                    }
                });
            });
        })
    }

    /// A form row: a label on the left and a control that fills the rest.
    pub(crate) fn field(&mut self, label: &str, add: impl FnOnce(&mut Ui) -> Response) -> Response {
        self.row(|ui| {
            ui.horizontal(|ui| {
                let label = ui
                    .allocate_ui_with_layout(
                        Vec2::new(FIELD_LABEL_WIDTH, ui.spacing().interact_size.y),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.set_min_width(FIELD_LABEL_WIDTH);
                            ui.label(text(label, Font::Body).color(LABEL))
                        },
                    )
                    .inner;
                add(ui).labelled_by(label.id)
            })
            .inner
        })
    }

    /// A form row with a hint line under the control.
    pub(crate) fn field_with_hint(
        &mut self,
        label: &str,
        hint: Option<(&str, Tone)>,
        add: impl FnOnce(&mut Ui) -> Response,
    ) -> Response {
        self.row(|ui| {
            let response = ui
                .horizontal(|ui| {
                    let label = ui
                        .allocate_ui_with_layout(
                            Vec2::new(FIELD_LABEL_WIDTH, ui.spacing().interact_size.y),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.set_min_width(FIELD_LABEL_WIDTH);
                                ui.label(text(label, Font::Body).color(LABEL))
                            },
                        )
                        .inner;
                    add(ui).labelled_by(label.id)
                })
                .inner;
            if let Some((hint, tone)) = hint {
                ui.horizontal(|ui| {
                    ui.add_space(FIELD_LABEL_WIDTH + ui.spacing().item_spacing.x);
                    ui.vertical(|ui| tone_note(ui, hint, tone));
                });
            }
            response
        })
    }

    /// A form row with a switch on the right.
    pub(crate) fn toggle(
        &mut self,
        title: &str,
        subtitle: Option<&str>,
        on: &mut bool,
    ) -> Response {
        self.row(|ui| {
            egui::Sides::new()
                .shrink_left()
                .wrap_mode(TextWrapMode::Wrap)
                .show(
                    ui,
                    |ui| {
                        ui.vertical(|ui| {
                            ui.label(text(title, Font::Body).color(LABEL));
                            if let Some(subtitle) = subtitle {
                                note(ui, subtitle);
                            }
                        });
                    },
                    |ui| toggle(ui, on, title),
                )
                .1
        })
    }
}

// ---- Buttons. ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Style {
    /// `.borderedProminent`: the one main action of a view.
    Prominent,
    /// `.bordered`: a secondary action.
    Bordered,
    /// `.borderless`: an action in the accent color.
    Link,
    /// A borderless action that removes or ends something.
    Destructive,
    /// The confirm button of a destructive alert.
    DestructiveProminent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Size {
    Regular,
    Small,
    Large,
}

impl Size {
    fn height(self) -> f32 {
        match self {
            Self::Small => 22.0,
            Self::Regular => 28.0,
            Self::Large => 36.0,
        }
    }

    fn font(self) -> Font {
        match self {
            Self::Small => Font::Callout,
            Self::Regular | Self::Large => Font::Body,
        }
    }
}

pub(crate) fn button(ui: &mut Ui, label: &str, style: Style) -> Response {
    button_with(ui, None, label, style, Size::Regular)
}

pub(crate) fn small_button(ui: &mut Ui, label: &str, style: Style) -> Response {
    button_with(ui, None, label, style, Size::Small)
}

/// A full-width large button, for the start screens.
pub(crate) fn wide_button(ui: &mut Ui, label: &str, style: Style) -> Response {
    let width = ui.available_width();
    ui.scope(|ui| {
        ui.set_min_width(width);
        button_sized(ui, None, label, style, Size::Large, width)
    })
    .inner
}

pub(crate) fn button_with(
    ui: &mut Ui,
    icon: Option<Icon>,
    label: &str,
    style: Style,
    size: Size,
) -> Response {
    button_sized(ui, icon, label, style, size, 0.0)
}

/// A button with an icon and no text. `name` is its name for VoiceOver and its
/// tooltip.
pub(crate) fn icon_button(ui: &mut Ui, icon: Icon, name: &str, size: Size) -> Response {
    button_named(ui, Some(icon), "", Some(name), Style::Link, size, 0.0).on_hover_text(name)
}

fn button_sized(
    ui: &mut Ui,
    icon: Option<Icon>,
    label: &str,
    style: Style,
    size: Size,
    min_width: f32,
) -> Response {
    button_named(ui, icon, label, None, style, size, min_width)
}

#[allow(clippy::too_many_arguments)]
fn button_named(
    ui: &mut Ui,
    icon: Option<Icon>,
    label: &str,
    name: Option<&str>,
    style: Style,
    size: Size,
    min_width: f32,
) -> Response {
    let font = size.font();
    let strong = matches!(style, Style::Prominent | Style::DestructiveProminent);
    let label_text = if strong {
        medium(label, font)
    } else {
        text(label, font)
    };
    let galley = galley(ui, label_text);
    let icon_size = if size == Size::Small { 11.0 } else { 13.0 };
    let icon_space = if icon.is_some() {
        icon_size + if label.is_empty() { 0.0 } else { 5.0 }
    } else {
        0.0
    };
    let pad = match (style, size) {
        (Style::Link | Style::Destructive, Size::Small) => 4.0,
        (_, Size::Small) => 8.0,
        _ => 12.0,
    };
    let width = (galley.size().x + icon_space + 2.0 * pad).max(min_width);
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, size.height()), Sense::click());
    let enabled = ui.is_enabled();
    let name = name.unwrap_or(label);
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, name));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let pressed = response.is_pointer_button_down_on();
    let hovered = response.hovered();
    let (fill, fg) = match style {
        Style::Prominent => (
            if pressed {
                ACCENT_PRESSED
            } else if hovered {
                ACCENT_HOVER
            } else {
                ACCENT
            },
            Color32::WHITE,
        ),
        Style::DestructiveProminent => (
            if pressed || hovered {
                Color32::from_rgb(222, 44, 36)
            } else {
                Tone::Critical.mark()
            },
            Color32::WHITE,
        ),
        Style::Bordered => (
            if pressed {
                FILL_PRESSED
            } else if hovered {
                FILL_HOVER
            } else {
                FILL
            },
            LABEL,
        ),
        Style::Link | Style::Destructive => (
            if pressed {
                FILL_PRESSED
            } else if hovered {
                FILL
            } else {
                Color32::TRANSPARENT
            },
            if style == Style::Link {
                ACCENT_TEXT
            } else {
                Tone::Critical.text()
            },
        ),
    };
    let (fill, fg) = if enabled {
        (fill, fg)
    } else {
        (fill.gamma_multiply(0.5), fg.gamma_multiply(0.45))
    };
    let radius = if size == Size::Large { 8 } else { 6 };
    let painter = ui.painter();
    painter.rect_filled(rect, radius, fill);
    if response.has_focus() {
        focus_ring(painter, rect, radius);
    }
    let content = Vec2::new(icon_space + galley.size().x, galley.size().y);
    let start = rect.center() - content / 2.0;
    if let Some(icon) = icon {
        let icon_rect = Rect::from_center_size(
            Pos2::new(start.x + icon_size / 2.0, rect.center().y),
            Vec2::splat(icon_size),
        );
        paint_icon(painter, icon_rect, icon, fg);
    }
    painter.galley(Pos2::new(start.x + icon_space, start.y), galley, fg);
    response
}

// ---- Inputs. ----

/// Margins of a text field. The field is 26 points high with a 13-point font.
pub(crate) const FIELD_MARGIN: Margin = Margin {
    left: 8,
    right: 8,
    top: 5,
    bottom: 5,
};

/// A rounded text field that fills the width.
pub(crate) fn text_input(
    ui: &mut Ui,
    value: &mut String,
    salt: &str,
    placeholder: &str,
) -> Response {
    let response = ui.add(
        TextEdit::singleline(value)
            .id_salt(salt)
            .hint_text(text(placeholder, Font::Body).color(TERTIARY))
            .margin(FIELD_MARGIN)
            .desired_width(f32::INFINITY),
    );
    claim_first_field(&response);
    response
}

/// A monospace text field, for names such as `STRIPE_SECRET_KEY`.
pub(crate) fn mono_input(
    ui: &mut Ui,
    value: &mut String,
    salt: &str,
    placeholder: &str,
) -> Response {
    let response = ui.add(
        TextEdit::singleline(value)
            .id_salt(salt)
            .font(TextStyle::Monospace)
            .hint_text(text(placeholder, Font::Mono).color(TERTIARY))
            .margin(FIELD_MARGIN)
            .desired_width(f32::INFINITY),
    );
    claim_first_field(&response);
    response
}

/// A multi-line field.
pub(crate) fn text_area(
    ui: &mut Ui,
    value: &mut String,
    salt: &str,
    placeholder: &str,
    rows: usize,
) -> Response {
    ui.add(
        TextEdit::multiline(value)
            .id_salt(salt)
            .hint_text(text(placeholder, Font::Body).color(TERTIARY))
            .margin(FIELD_MARGIN)
            .desired_rows(rows)
            .desired_width(f32::INFINITY),
    )
}

/// Read-only monospace text that the owner can select, for a command or a token. The
/// keyboard can focus it and select the text with ⌘A.
pub(crate) fn code_block(ui: &mut Ui, value: &str, rows: usize) -> Response {
    let mut shown: &str = value;
    let response = ui.add(
        TextEdit::multiline(&mut shown)
            .font(TextStyle::Monospace)
            .frame(
                Frame::NONE
                    .fill(Color32::from_rgb(246, 246, 248))
                    .stroke(Stroke::new(1.0, SEPARATOR))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::symmetric(10, 8)),
            )
            .desired_rows(rows)
            .desired_width(f32::INFINITY),
    );
    if response.has_focus() {
        focus_ring(ui.painter(), response.rect, 8);
    }
    response
}

/// A macOS switch.
pub(crate) fn toggle(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    let size = Vec2::new(32.0, 18.0);
    let (rect, mut response) = ui.allocate_exact_size(size, Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    let enabled = ui.is_enabled();
    let value = *on;
    response.widget_info(|| WidgetInfo::selected(WidgetType::Checkbox, enabled, value, label));
    if ui.is_rect_visible(rect) {
        let t = ui.ctx().animate_bool_responsive(response.id, *on);
        let off = Color32::from_rgb(216, 216, 222);
        let track = Color32::from(egui::lerp(
            egui::Rgba::from(off)..=egui::Rgba::from(ACCENT),
            t,
        ));
        let track = if enabled {
            track
        } else {
            track.gamma_multiply(0.5)
        };
        let painter = ui.painter();
        painter.rect_filled(rect, 9, track);
        let radius = rect.height() / 2.0 - 2.0;
        let x = egui::lerp(
            (rect.left() + radius + 2.0)..=(rect.right() - radius - 2.0),
            t,
        );
        let center = Pos2::new(x, rect.center().y);
        painter.circle_filled(
            center + Vec2::new(0.0, 0.5),
            radius + 0.5,
            Color32::from_black_alpha(28),
        );
        painter.circle_filled(center, radius, Color32::WHITE);
        if response.has_focus() {
            focus_ring(painter, rect, 9);
        }
    }
    response
}

/// A segmented `Picker`. Equal segments, the selection on a white thumb.
///
/// The control is one stop in the Tab order. With the focus, Space or Enter selects the
/// next option, and the arrow keys move left and right.
pub(crate) fn segmented<T: PartialEq + Copy>(
    ui: &mut Ui,
    salt: impl std::hash::Hash + std::fmt::Debug,
    value: &mut T,
    options: &[(T, &str)],
) -> Response {
    let galleys: Vec<_> = options
        .iter()
        .map(|(_, label)| galley(ui, text(*label, Font::Callout)))
        .collect();
    let widest = galleys
        .iter()
        .map(|galley| galley.size().x)
        .fold(0.0, f32::max);
    let segment = widest + 20.0;
    let height = 24.0;
    let total = Vec2::new(segment * options.len() as f32 + 4.0, height);
    let (rect, _) = ui.allocate_exact_size(total, Sense::hover());
    let id = ui.id().with(salt);
    let mut response = ui.interact(rect, id, Sense::click());
    let enabled = ui.is_enabled();
    let count = options.len();
    let selected = options.iter().position(|(option, _)| option == value);
    let segment_at = |pos: Pos2| {
        let index = ((pos.x - rect.left() - 2.0) / segment).floor();
        (index >= 0.0)
            .then_some(index as usize)
            .filter(|index| *index < count)
    };
    let mut choose = None;
    if response.clicked() {
        choose = match response.interact_pointer_pos() {
            Some(pos) => segment_at(pos),
            // Space or Enter with the focus: the next option.
            None => Some(selected.map_or(0, |index| (index + 1) % count)),
        };
    }
    if response.has_focus() {
        // The arrow keys belong to the picker. Without this, egui also moves the focus.
        ui.memory_mut(|memory| {
            memory.set_focus_lock_filter(
                response.id,
                egui::EventFilter {
                    horizontal_arrows: true,
                    ..Default::default()
                },
            );
        });
    }
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if response.has_focus() && count > 0 {
        let (left, right) = ui.input(|input| {
            (
                input.key_pressed(Key::ArrowLeft),
                input.key_pressed(Key::ArrowRight),
            )
        });
        if right {
            choose = Some(selected.map_or(0, |index| (index + 1).min(count - 1)));
        } else if left {
            choose = Some(selected.map_or(0, |index| index.saturating_sub(1)));
        }
    }
    if let Some(index) = choose
        && selected != Some(index)
    {
        *value = options[index].0;
        response.mark_changed();
    }
    let current = options
        .iter()
        .find(|(option, _)| option == value)
        .map_or("", |(_, label)| *label)
        .to_owned();
    // No label here: a form row names the picker with `labelled_by`, and VoiceOver
    // reads the selected option as the value.
    response.widget_info(|| WidgetInfo {
        current_text_value: Some(current.clone()),
        ..WidgetInfo::new(WidgetType::ComboBox)
    });
    if !enabled {
        ui.ctx()
            .accesskit_node_builder(response.id, |node| node.set_disabled());
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let selected = options.iter().position(|(option, _)| option == value);
    let hovered = response.hover_pos().and_then(segment_at);
    let painter = ui.painter();
    painter.rect_filled(rect, 7, Color32::from_rgb(234, 234, 238));
    for (index, galley) in galleys.into_iter().enumerate() {
        let segment_rect = Rect::from_min_size(
            Pos2::new(rect.left() + 2.0 + segment * index as f32, rect.top() + 2.0),
            Vec2::new(segment, height - 4.0),
        );
        if selected == Some(index) {
            painter.rect_filled(
                segment_rect.translate(Vec2::new(0.0, 0.5)),
                5,
                Color32::from_black_alpha(18),
            );
            painter.rect_filled(segment_rect, 5, SURFACE);
        } else if hovered == Some(index) {
            painter.rect_filled(segment_rect, 5, Color32::from_rgb(224, 224, 229));
        } else if index > 0 && selected != Some(index - 1) {
            painter.vline(
                segment_rect.left(),
                (segment_rect.top() + 4.0)..=(segment_rect.bottom() - 4.0),
                Stroke::new(1.0, Color32::from_rgb(214, 214, 220)),
            );
        }
        let color = if enabled { LABEL } else { TERTIARY };
        painter.galley(segment_rect.center() - galley.size() / 2.0, galley, color);
    }
    if response.has_focus() {
        focus_ring(painter, rect, 7);
    }
    response
}

/// The keyboard focus ring: 2 points of solid accent. It passes 3:1 against the window
/// and the sidebar (WCAG 1.4.11).
pub(crate) const FOCUS_STROKE: Stroke = Stroke {
    width: 2.0,
    color: ACCENT,
};

/// The keyboard focus ring around a control.
pub(crate) fn focus_ring(painter: &Painter, rect: Rect, radius: u8) {
    painter.rect_stroke(
        rect.expand(2.0),
        radius + 2,
        FOCUS_STROKE,
        StrokeKind::Outside,
    );
}

/// The keyboard focus ring inside a full-width row.
pub(crate) fn inner_focus_ring(painter: &Painter, rect: Rect, radius: u8) {
    painter.rect_stroke(rect, radius, FOCUS_STROKE, StrokeKind::Inside);
}

/// True once when the owner presses `key` with `modifiers`. The key is consumed.
pub(crate) fn shortcut(ctx: &egui::Context, modifiers: egui::Modifiers, key: Key) -> bool {
    ctx.input_mut(|input| input.consume_shortcut(&egui::KeyboardShortcut::new(modifiers, key)))
}

/// The default action of a sheet: ⌘S, ⌘Return, or Return (see [`sheet`]).
pub(crate) fn save_shortcut(ctx: &egui::Context) -> bool {
    let command = shortcut(ctx, egui::Modifiers::COMMAND, Key::S)
        | shortcut(ctx, egui::Modifiers::COMMAND, Key::Enter);
    command | take_sheet_enter(ctx)
}

/// A menu `Picker`: a combo box with the macOS up and down chevrons.
pub(crate) fn menu(
    salt: impl std::hash::Hash + std::fmt::Debug,
    selected: impl Into<WidgetText>,
    width: f32,
) -> egui::ComboBox {
    egui::ComboBox::from_id_salt(salt)
        .width(width)
        .selected_text(selected)
        .icon(|ui, rect, _visuals, _open| {
            let center = rect.center();
            let stroke = Stroke::new(1.3, SECONDARY);
            let (w, h) = (3.2, 2.6);
            ui.painter().line(
                vec![
                    center + Vec2::new(-w, -1.6),
                    center + Vec2::new(0.0, -1.6 - h),
                    center + Vec2::new(w, -1.6),
                ],
                stroke,
            );
            ui.painter().line(
                vec![
                    center + Vec2::new(-w, 1.6),
                    center + Vec2::new(0.0, 1.6 + h),
                    center + Vec2::new(w, 1.6),
                ],
                stroke,
            );
        })
}

/// A menu `Picker` for a value. A choice with Return or Space closes the menu, as a
/// click does, and the focus goes back to the menu button after a choice or Escape.
pub(crate) fn picker<T: PartialEq + Clone>(
    ui: &mut Ui,
    salt: impl std::hash::Hash + std::fmt::Debug,
    value: &mut T,
    options: &[(T, String)],
    selected: impl Into<WidgetText>,
    width: f32,
) -> Response {
    let output = menu(salt, selected, width).show_ui(ui, |ui| {
        for (option, label) in options {
            if ui.selectable_value(value, option.clone(), label).clicked() {
                ui.close();
            }
        }
    });
    let response = output.response;
    let ctx = ui.ctx();
    let open = egui::ComboBox::is_open(ctx, response.id);
    let key = response.id.with("apassy-picker-open");
    let was_open = ctx.data(|data| data.get_temp::<bool>(key)).unwrap_or(false);
    ctx.data_mut(|data| data.insert_temp(key, open));
    if was_open && !open && keyboard_mode(ctx) {
        response.request_focus();
    }
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    response
}

/// A `DisclosureGroup` label with a chevron. Flips `open` on a click.
pub(crate) fn disclosure(ui: &mut Ui, open: &mut bool, label: &str) -> Response {
    let galley = galley(ui, medium(label, Font::Body));
    let size = Vec2::new(galley.size().x + 22.0, 24.0);
    let (rect, mut response) = ui.allocate_exact_size(size, Sense::click());
    if response.clicked() {
        *open = !*open;
        response.mark_changed();
    }
    let expanded = *open;
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::CollapsingHeader, true, expanded, label));
    ui.ctx()
        .accesskit_node_builder(response.id, |node| node.set_expanded(expanded));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if response.hovered() {
            painter.rect_filled(rect.expand2(Vec2::new(4.0, 0.0)), 6, FILL);
        }
        if response.has_focus() {
            focus_ring(painter, rect.expand2(Vec2::new(4.0, 0.0)), 6);
        }
        let icon = if *open {
            Icon::ChevronDown
        } else {
            Icon::ChevronRight
        };
        let icon_rect = Rect::from_center_size(
            Pos2::new(rect.left() + 6.0, rect.center().y),
            Vec2::splat(10.0),
        );
        paint_icon(painter, icon_rect, icon, SECONDARY);
        painter.galley(
            Pos2::new(rect.left() + 18.0, rect.center().y - galley.size().y / 2.0),
            galley,
            LABEL,
        );
    }
    response
}

// ---- Status marks. ----

/// A small capsule with a label, such as "Production" or "Active".
pub(crate) fn tag(ui: &mut Ui, label: &str, tone: Tone) -> Response {
    let galley = galley(ui, medium(label, Font::Footnote));
    let size = galley.size() + Vec2::new(14.0, 4.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Label, true, label));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        painter.rect_filled(rect, rect.height() / 2.0, tone.tint());
        painter.galley(rect.center() - galley.size() / 2.0, galley, tone.text());
    }
    response
}

/// A small dot in a status color.
pub(crate) fn dot(ui: &mut Ui, tone: Tone) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, tone.mark());
    response
}

// ---- Sidebar. ----

/// A count on a sidebar row. A neutral count is a total; another tone means that the
/// owner has something to do, and `what` names it for VoiceOver ("3 waiting").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Badge {
    pub(crate) count: usize,
    pub(crate) tone: Tone,
    pub(crate) what: &'static str,
}

const SIDEBAR_SELECTED: Color32 = Color32::from_rgb(222, 222, 228);
const SIDEBAR_HOVER: Color32 = Color32::from_rgb(232, 232, 236);

/// The open vault at the top of the sidebar: a tile with its initial, its name, and a
/// status line. A click opens the vault menu. `tone` colors the status line when sync
/// needs the owner.
#[cfg(feature = "vault")]
pub(crate) fn vault_header(
    ui: &mut Ui,
    width: f32,
    name: &str,
    status: &str,
    tone: Tone,
    tile: Color32,
) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 40.0), Sense::click());
    let label = format!("Vault {name}, {status}");
    response.widget_info(|| WidgetInfo::labeled(WidgetType::ComboBox, true, &label));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let open = egui::Popup::is_id_open(ui.ctx(), egui::Popup::default_response_id(&response));
        if open || response.is_pointer_button_down_on() {
            painter.rect_filled(rect, 8, SIDEBAR_SELECTED);
        } else if response.hovered() {
            painter.rect_filled(rect, 8, SIDEBAR_HOVER);
        }
        if response.has_focus() {
            inner_focus_ring(painter, rect, 8);
        }
        // The avatar: the initial of the vault in a 22-point circle of its color, as in
        // the mockup.
        let tile_rect = Rect::from_center_size(
            Pos2::new(rect.left() + 17.0, rect.center().y),
            Vec2::splat(22.0),
        );
        painter.circle_filled(tile_rect.center(), 11.0, tile);
        let initial: String = name
            .chars()
            .find(|c| c.is_alphanumeric())
            .map_or_else(|| "V".to_owned(), |c| c.to_uppercase().collect());
        let letter = galley(ui, text(initial, Font::Footnote).variation(b"wght", 600.0));
        painter.galley(
            tile_rect.center() - letter.size() / 2.0,
            letter,
            Color32::WHITE,
        );
        // The name and the status, cut to the room left of the chevrons.
        let text_left = tile_rect.right() + 8.0;
        let text_width = (rect.right() - 20.0 - text_left).max(0.0);
        let line = |value: RichText, color: Color32| {
            WidgetText::from(value.color(color)).into_galley(
                ui,
                Some(TextWrapMode::Truncate),
                text_width,
                TextStyle::Body,
            )
        };
        let title = line(text(name, Font::Body), LABEL);
        let status_color = match tone {
            Tone::Neutral => SECONDARY,
            other => other.text(),
        };
        let subtitle = line(text(status, Font::Footnote), status_color);
        let top = rect.center().y - (title.size().y + subtitle.size().y) / 2.0;
        let subtitle_top = top + title.size().y;
        painter.galley(Pos2::new(text_left, top), title, LABEL);
        painter.galley(Pos2::new(text_left, subtitle_top), subtitle, status_color);
        // Up and down chevrons, as on a macOS pop-up button.
        let center = Pos2::new(rect.right() - 10.0, rect.center().y);
        let stroke = Stroke::new(1.3, SECONDARY);
        let (w, h) = (3.2, 2.6);
        painter.line(
            vec![
                center + Vec2::new(-w, -1.6),
                center + Vec2::new(0.0, -1.6 - h),
                center + Vec2::new(w, -1.6),
            ],
            stroke,
        );
        painter.line(
            vec![
                center + Vec2::new(-w, 1.6),
                center + Vec2::new(0.0, 1.6 + h),
                center + Vec2::new(w, 1.6),
            ],
            stroke,
        );
    }
    response
}

/// A gray icon button for the title bar, as the sidebar button of a macOS window.
pub(crate) fn title_bar_button(ui: &mut Ui, icon: Icon, name: &str) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::click());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, true, name));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if response.is_pointer_button_down_on() {
            painter.rect_filled(rect, 6, SIDEBAR_SELECTED);
        } else if response.hovered() {
            painter.rect_filled(rect, 6, SIDEBAR_HOVER);
        }
        if response.has_focus() {
            inner_focus_ring(painter, rect, 6);
        }
        paint_icon(painter, rect.shrink(5.0), icon, SECONDARY);
    }
    response.on_hover_text(name)
}

// ---- The three-column window (ADR 0026, `docs/design/app-v2-mockup.html`). ----

/// The width of the full sidebar.
pub(crate) const SIDEBAR_WIDTH: f32 = 216.0;
/// The width of the sidebar as a rail of icons. The traffic lights of macOS take
/// [`LIGHTS_RIGHT`] points, wider than the 56 points of the mockup, where they are
/// smaller: the rail keeps them inside, with the margin of the red one at the right, so
/// they do not run into the list. Its icons center under the yellow light.
pub(crate) const RAIL_WIDTH: f32 = 78.0;
/// The width of the list column, and in a window narrower than [`WIDE_LIST_WINDOW`].
pub(crate) const LIST_WIDTH: f32 = 300.0;
pub(crate) const LIST_WIDTH_NARROW: f32 = 236.0;
/// From this window width on, the list column has its full width.
pub(crate) const WIDE_LIST_WINDOW: f32 = 1040.0;
/// Below this window width, the sidebar is a rail of icons. Opened, it floats over the
/// list.
pub(crate) const NARROW_WINDOW: f32 = 1000.0;
/// The vertical center of the traffic lights, from the top of the window. The window
/// has a transparent title bar and no toolbar (an NSToolbar would need unsafe code, which
/// the crate forbids), so macOS draws the lights at the height of a plain title bar. The
/// top row of each column centers on this line: the sidebar button, the title of the
/// list and its "+", and the buttons of the detail.
pub(crate) const LIGHTS_Y: f32 = 16.0;
/// The right edge of the traffic lights, from the left edge of the window. A title next
/// to the lights starts after it.
pub(crate) const LIGHTS_RIGHT: f32 = 69.0;
/// The height of the toolbar on top of the list: the title on the row of the traffic
/// lights, the count under it, and "+". It holds the title bar.
pub(crate) const TOOLBAR: f32 = 40.0;
/// The height of the toolbar on top of the detail: its buttons on the row of the traffic
/// lights.
pub(crate) const DETAIL_TOOLBAR: f32 = 34.0;
/// The top of the sidebar rows: right under the row of the traffic lights.
pub(crate) const SIDEBAR_TOP: f32 = 30.0;
/// The top of the rail icons: under the traffic lights and the sidebar button.
pub(crate) const RAIL_TOP: f32 = 66.0;
/// The hairline between the columns (the mockup: 0.5 px of black at 9 %).
pub(crate) const COLUMN_EDGE: Color32 = Color32::from_black_alpha(23);
/// The fill of a hovered sidebar row and of a pressed small button.
const FILL2: Color32 = Color32::from_rgb(235, 235, 237);
/// The leading edge of each row, as in the mockup.
const ROW_RADIUS: u8 = 6;

/// What a provider tile shows: a letter or an icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mark {
    Letter(String),
    Icon(Icon),
}

/// A provider tile (Stripe, GitHub, Postgres…), or a kind tile when the provider is not
/// known: a rounded square with a white letter or icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tile {
    pub(crate) color: Color32,
    pub(crate) mark: Mark,
    /// A circle instead of a rounded square: the avatar of an agent.
    pub(crate) round: bool,
}

impl Tile {
    pub(crate) fn letter(color: Color32, name: &str) -> Self {
        let letter: String = name
            .chars()
            .find(|c| c.is_alphanumeric())
            .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect());
        Self {
            color,
            mark: Mark::Letter(letter),
            round: false,
        }
    }

    pub(crate) fn icon(color: Color32, icon: Icon) -> Self {
        Self {
            color,
            mark: Mark::Icon(icon),
            round: false,
        }
    }

    /// The round avatar of an agent, in [`agent_color`], as in Decisions.
    pub(crate) fn agent(name: &str) -> Self {
        Self {
            round: true,
            ..Self::letter(agent_color(name), name)
        }
    }
}

/// Paint `tile` in `rect`: 8 of 32 points round, the letter in bold at 7/16 of the side.
pub(crate) fn paint_tile(ui: &Ui, rect: Rect, tile: &Tile) {
    let side = rect.width();
    let painter = ui.painter();
    if tile.round {
        painter.circle_filled(rect.center(), side / 2.0, tile.color);
    } else {
        painter.rect_filled(rect, (side * 0.25).round() as u8, tile.color);
    }
    match &tile.mark {
        Mark::Letter(letter) => {
            let galley = galley(
                ui,
                text(letter.clone(), Font::Body)
                    .size((side * 0.44).round())
                    .variation(b"wght", 700.0),
            );
            painter.galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
        }
        Mark::Icon(icon) => paint_icon(painter, rect.shrink(side * 0.25), *icon, Color32::WHITE),
    }
}

/// A tile of `side` points in the layout.
pub(crate) fn tile(ui: &mut Ui, tile: &Tile, side: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), Sense::hover());
    if ui.is_rect_visible(rect) {
        paint_tile(ui, rect, tile);
    }
    response
}

// ---- Agent avatars. ----

/// The color of an agent, as in the mockup and Connect an Agent: Claude Code orange,
/// Codex green, T3 Code purple, a CI agent of GitHub near black. Any other agent gets
/// a steady color from its name. The name is compared without case, spaces, or dashes,
/// so "claude-code" and "Ola's Claude Code" are Claude Code too.
pub(crate) fn agent_color(name: &str) -> Color32 {
    const OTHERS: [Color32; 6] = [
        Color32::from_rgb(0, 122, 255),
        Color32::from_rgb(88, 86, 214),
        Color32::from_rgb(191, 90, 242),
        Color32::from_rgb(48, 176, 199),
        Color32::from_rgb(255, 55, 95),
        Color32::from_rgb(142, 142, 147),
    ];
    let plain: String = name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    if plain.contains("claude") {
        Color32::from_rgb(217, 119, 87)
    } else if plain.contains("codex") {
        Color32::from_rgb(16, 163, 127)
    } else if plain.contains("t3code") {
        Color32::from_rgb(110, 90, 230)
    } else if plain.contains("github") {
        Color32::from_rgb(36, 41, 47)
    } else {
        let sum = plain
            .bytes()
            .fold(0usize, |sum, byte| sum.wrapping_add(byte as usize));
        OTHERS[sum % OTHERS.len()]
    }
}

/// Paint the round avatar of an agent in `rect`: its first letter in white, semibold,
/// on [`agent_color`].
pub(crate) fn paint_avatar(ui: &Ui, rect: Rect, name: &str) {
    let side = rect.width().min(rect.height());
    let painter = ui.painter();
    painter.circle_filled(rect.center(), side / 2.0, agent_color(name));
    let letter: String = name
        .chars()
        .find(|c| c.is_alphanumeric())
        .map_or_else(|| "?".to_owned(), |c| c.to_uppercase().collect());
    let galley = galley(
        ui,
        text(letter, Font::Body)
            .size((side * 0.42).round())
            .variation(b"wght", 600.0),
    );
    painter.galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
}

/// The round avatar of an agent, `side` points wide, in the layout: 28 in a list row,
/// 56 in the header of a detail, 20 in a fact row.
pub(crate) fn avatar(ui: &mut Ui, name: &str, side: f32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), Sense::hover());
    if ui.is_rect_visible(rect) {
        paint_avatar(ui, rect, name);
    }
    response
}

/// A cap: a small gray label in the header of a detail ("Development", the name of a
/// shared vault). `red` is the one red cap, "Production".
pub(crate) fn cap(ui: &mut Ui, label: &str, red: bool) -> Response {
    let color = if red {
        Color32::from_rgb(196, 43, 34)
    } else {
        SECONDARY
    };
    let galley = galley(ui, medium(label, Font::Footnote));
    let size = galley.size() + Vec2::new(12.0, 2.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Label, true, label));
    if ui.is_rect_visible(rect) {
        let fill = if red {
            PRODUCTION.gamma_multiply(0.1)
        } else {
            FILL2
        };
        let painter = ui.painter();
        painter.rect_filled(rect, 5, fill);
        painter.galley(rect.center() - galley.size() / 2.0, galley, color);
    }
    response
}

/// The title of a list toolbar with its first line centered on `center_y` (the row of
/// the traffic lights) and the line under it, from `left` to `right`.
pub(crate) fn toolbar_title_on_row(
    ui: &mut Ui,
    left: f32,
    right: f32,
    center_y: f32,
    title: &str,
    subtitle: &str,
) {
    let width = (right - left).max(10.0);
    let title_text = text(title, Font::Body)
        .variation(b"wght", 700.0)
        .color(LABEL);
    let height = galley(ui, title_text.clone()).size().y;
    let title_rect = Rect::from_min_size(
        Pos2::new(left, (center_y - height / 2.0).round()),
        Vec2::new(width, height),
    );
    put_left(
        ui,
        title_rect,
        Label::new(title_text).truncate().selectable(false),
    );
    if subtitle.is_empty() {
        return;
    }
    let sub_text = text(subtitle, Font::Footnote).color(SECONDARY);
    let sub_height = galley(ui, sub_text.clone()).size().y;
    put_left(
        ui,
        Rect::from_min_size(
            Pos2::new(left, title_rect.bottom()),
            Vec2::new(width, sub_height),
        ),
        Label::new(sub_text).truncate().selectable(false),
    );
}

/// A widget in `rect`, at its left edge and centered vertically.
fn put_left(ui: &mut Ui, rect: Rect, widget: impl egui::Widget) -> Response {
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::left_to_right(Align::Center)),
        |ui| ui.add(widget),
    )
    .inner
}

/// A borderless 28-point icon button of a toolbar or a footer. `name` is its name for
/// VoiceOver and its tooltip.
pub(crate) fn plain_icon_button(ui: &mut Ui, icon: Icon, name: &str) -> Response {
    plain_icon_toggle(ui, icon, name, false)
}

/// A [`plain_icon_button`] that can show as selected, as the gear of the sidebar while
/// Settings shows: the gray fill of a selected sidebar row, and the icon in the label
/// color.
pub(crate) fn plain_icon_toggle(ui: &mut Ui, icon: Icon, name: &str, selected: bool) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::click());
    let enabled = ui.is_enabled();
    if selected {
        response.widget_info(|| WidgetInfo::selected(WidgetType::Button, enabled, true, name));
    } else {
        response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, name));
    }
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if selected {
            painter.rect_filled(rect, ROW_RADIUS, Color32::from_black_alpha(23));
        } else if response.is_pointer_button_down_on() {
            painter.rect_filled(rect, ROW_RADIUS, FILL_PRESSED);
        } else if response.hovered() {
            painter.rect_filled(rect, ROW_RADIUS, FILL2);
        }
        if response.has_focus() {
            inner_focus_ring(painter, rect, ROW_RADIUS);
        }
        let color = if !enabled {
            SECONDARY.gamma_multiply(0.45)
        } else if selected {
            LABEL
        } else {
            SECONDARY
        };
        paint_icon(painter, rect.shrink(6.0), icon, color);
    }
    response.on_hover_text(name)
}

/// A toolbar button of the detail column: an optional gray icon and a label, no border.
pub(crate) fn toolbar_button(ui: &mut Ui, icon: Option<Icon>, label: &str, name: &str) -> Response {
    let galley = galley(ui, text(label, Font::Body));
    let icon_space = if icon.is_some() {
        if label.is_empty() { 16.0 } else { 21.0 }
    } else {
        0.0
    };
    let width = galley.size().x + icon_space + 18.0;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 28.0), Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, name));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if response.is_pointer_button_down_on() {
            painter.rect_filled(rect, ROW_RADIUS, FILL_PRESSED);
        } else if response.hovered() {
            painter.rect_filled(rect, ROW_RADIUS, FILL2);
        }
        if response.has_focus() {
            inner_focus_ring(painter, rect, ROW_RADIUS);
        }
        let mut x = rect.left() + 9.0;
        if let Some(icon) = icon {
            let icon_rect =
                Rect::from_center_size(Pos2::new(x + 8.0, rect.center().y), Vec2::splat(16.0));
            paint_icon(painter, icon_rect, icon, SECONDARY);
            x += icon_space;
        }
        let color = if enabled { LABEL } else { TERTIARY };
        painter.galley(
            Pos2::new(x, rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
    }
    response
}

/// A search field: a gray capsule, 28 points high, with a magnifier.
pub(crate) fn search_field(
    ui: &mut Ui,
    value: &mut String,
    salt: &str,
    placeholder: &str,
) -> Response {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 28.0), Sense::hover());
    ui.painter().rect_filled(rect, 7, FILL);
    paint_icon(
        ui.painter(),
        Rect::from_center_size(
            Pos2::new(rect.left() + 15.0, rect.center().y),
            Vec2::splat(13.0),
        ),
        Icon::Search,
        TERTIARY,
    );
    let field_rect = Rect::from_min_max(
        Pos2::new(rect.left() + 24.0, rect.top()),
        Pos2::new(rect.right() - 4.0, rect.bottom()),
    );
    // The margin goes in the frame: with a frame, a text edit has no margin of its own.
    // The row is centered on the magnifier.
    let response = ui
        .scope_builder(
            UiBuilder::new()
                .max_rect(field_rect)
                .layout(Layout::left_to_right(Align::Center)),
            |ui| {
                ui.add(
                    TextEdit::singleline(value)
                        .id_salt(salt)
                        .frame(Frame::NONE.inner_margin(Margin::symmetric(2, 6)))
                        .hint_text(text(placeholder, Font::Body).color(TERTIARY))
                        .desired_width(field_rect.width()),
                )
            },
        )
        .inner;
    if response.has_focus() {
        focus_ring(ui.painter(), rect, 7);
    }
    response
}

/// One row of a list column.
pub(crate) struct ListRow<'a> {
    pub(crate) tile: Tile,
    pub(crate) title: &'a str,
    pub(crate) subtitle: &'a str,
    /// A short text at the right, such as a status or a time.
    pub(crate) meta: Option<&'a str>,
    /// The red dot of a production credential.
    pub(crate) production: bool,
    pub(crate) selected: bool,
}

/// A row of a list column: the tile, the title, one line of detail, and a short meta on
/// the right. The selected row has the accent fill. It is one stop in the Tab order.
pub(crate) fn list_row(ui: &mut Ui, row: &ListRow<'_>) -> Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 48.0), Sense::click());
    let name = if row.subtitle.is_empty() {
        row.title.to_owned()
    } else {
        format!("{}, {}", row.title, row.subtitle)
    };
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
        painter.rect_filled(rect, 8, SELECTION);
    } else if response.hovered() {
        painter.rect_filled(rect, 8, Color32::from_rgb(247, 247, 248));
    }
    if response.has_focus() {
        inner_focus_ring(painter, rect, 8);
    }
    let tile_rect = Rect::from_min_size(
        Pos2::new(rect.left() + 8.0, rect.center().y - 16.0),
        Vec2::splat(32.0),
    );
    paint_tile(ui, tile_rect, &row.tile);
    let (title_color, sub_color) = if row.selected {
        (Color32::WHITE, Color32::from_white_alpha(210))
    } else {
        (LABEL, SECONDARY)
    };
    let mut right = rect.right() - 8.0;
    if row.production {
        let center = Pos2::new(right - 3.5, rect.center().y);
        let dot = if row.selected {
            Color32::WHITE
        } else {
            PRODUCTION
        };
        painter.circle_filled(center, 3.5, dot);
        right -= 13.0;
    }
    if let Some(meta) = row.meta.filter(|meta| !meta.is_empty()) {
        let galley = WidgetText::from(text(meta, Font::Callout).color(sub_color)).into_galley(
            ui,
            Some(TextWrapMode::Truncate),
            (width * 0.4).max(40.0),
            TextStyle::Body,
        );
        let pos = Pos2::new(
            right - galley.size().x,
            rect.center().y - galley.size().y / 2.0,
        );
        right = pos.x - 6.0;
        painter.galley(pos, galley, sub_color);
    }
    let left = tile_rect.right() + 10.0;
    let text_width = (right - left).max(10.0);
    let line = |value: RichText| {
        WidgetText::from(value).into_galley(
            ui,
            Some(TextWrapMode::Truncate),
            text_width,
            TextStyle::Body,
        )
    };
    let title = line(row_title(row.title).color(title_color));
    let subtitle = (!row.subtitle.is_empty())
        .then(|| line(text(row.subtitle, Font::Callout).color(sub_color)));
    let height = title.size().y + subtitle.as_ref().map_or(0.0, |sub| sub.size().y);
    let top = rect.center().y - height / 2.0;
    let title_height = title.size().y;
    painter.galley(Pos2::new(left, top), title, title_color);
    if let Some(subtitle) = subtitle {
        painter.galley(Pos2::new(left, top + title_height), subtitle, sub_color);
    }
    response
}

/// Paint the header of a group of list rows in `rect`: the name and an optional count
/// on the right, on an almost opaque white, so a header pinned at the top of the list
/// covers the rows under it.
pub(crate) fn paint_group_header(ui: &Ui, rect: Rect, title: &str, count: Option<usize>) {
    let painter = ui.painter();
    painter.rect_filled(rect, 0, Color32::from_white_alpha(240));
    let title = galley(ui, medium(title, Font::Footnote).variation(b"wght", 600.0));
    painter.galley(
        Pos2::new(rect.left() + 8.0, rect.bottom() - 4.0 - title.size().y),
        title,
        SECONDARY,
    );
    if let Some(count) = count {
        let count = galley(ui, text(count.to_string(), Font::Footnote));
        painter.galley(
            Pos2::new(
                rect.right() - 8.0 - count.size().x,
                rect.bottom() - 4.0 - count.size().y,
            ),
            count,
            SECONDARY,
        );
    }
}

/// The height of a group header in a list column.
pub(crate) const GROUP_HEADER: f32 = 28.0;

/// What a sidebar row leads with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lead {
    Icon(Icon),
    /// The letter square of a shared vault, in its color.
    Square(Color32, String),
}

/// One row of the sidebar.
pub(crate) struct SidebarRow<'a> {
    pub(crate) lead: Lead,
    pub(crate) label: &'a str,
    /// A neutral total, in gray.
    pub(crate) count: Option<usize>,
    /// A count that needs the owner, in a capsule.
    pub(crate) badge: Option<Badge>,
    pub(crate) selected: bool,
    /// The nesting level of a folder: 0 for a top row.
    pub(crate) level: usize,
    /// A disclosure triangle: `Some(open)` for a folder with subfolders.
    pub(crate) disclosure: Option<bool>,
}

/// What the owner did on a sidebar row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SidebarClick {
    None,
    Select,
    /// A click on the disclosure triangle.
    Disclose,
}

/// The name of a sidebar row for VoiceOver: the label with its count.
fn sidebar_name(label: &str, count: Option<usize>, badge: Option<Badge>) -> String {
    match (badge.filter(|badge| badge.count > 0), count) {
        (Some(Badge { count, what, .. }), _) => format!("{label}, {count} {what}"),
        (None, Some(count)) => format!("{label}, {count}"),
        (None, None) => label.to_owned(),
    }
}

fn paint_lead(ui: &Ui, center: Pos2, lead: &Lead, side: f32) {
    match lead {
        Lead::Icon(icon) => paint_icon(
            ui.painter(),
            Rect::from_center_size(center, Vec2::splat(side)),
            *icon,
            ACCENT,
        ),
        Lead::Square(color, name) => {
            let rect = Rect::from_center_size(center, Vec2::splat(side - 2.0));
            paint_tile(ui, rect, &Tile::letter(*color, name));
        }
    }
}

fn paint_badge(ui: &Ui, right: Pos2, badge: Badge, small: bool) {
    let painter = ui.painter();
    let label = badge.count.to_string();
    let galley = galley(
        ui,
        medium(label, Font::Footnote).size(if small { 9.0 } else { 11.0 }),
    );
    let height = if small { 14.0 } else { 16.0 };
    let size = Vec2::new((galley.size().x + 10.0).max(height + 2.0), height);
    let rect = Rect::from_min_size(Pos2::new(right.x - size.x, right.y - size.y / 2.0), size);
    let (fill, color) = match badge.tone {
        Tone::Neutral => (Color32::from_black_alpha(36), LABEL),
        Tone::Critical => (PRODUCTION, Color32::WHITE),
        other => (other.mark(), Color32::WHITE),
    };
    painter.rect_filled(rect, height / 2.0, fill);
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);
}

/// A row of the full sidebar: 28 points high, the icon in the accent color, the label,
/// and a count or a badge. A folder row has its level of indent and, with subfolders, a
/// disclosure triangle.
pub(crate) fn sidebar_row(ui: &mut Ui, row: &SidebarRow<'_>) -> (Response, SidebarClick) {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 28.0), Sense::click());
    let name = sidebar_name(row.label, row.count, row.badge);
    response.widget_info(|| {
        WidgetInfo::selected(WidgetType::SelectableLabel, true, row.selected, &name)
    });
    if let Some(open) = row.disclosure {
        ui.ctx()
            .accesskit_node_builder(response.id, |node| node.set_expanded(open));
    }
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    let indent = 8.0 + 16.0 * row.level as f32;
    let triangle = Rect::from_center_size(
        Pos2::new(rect.left() + indent - 1.0, rect.center().y),
        Vec2::new(14.0, 28.0),
    );
    let mut click = SidebarClick::None;
    if response.clicked() {
        let on_triangle = row.disclosure.is_some()
            && response
                .interact_pointer_pos()
                .is_some_and(|pos| triangle.contains(pos));
        click = if on_triangle {
            SidebarClick::Disclose
        } else {
            SidebarClick::Select
        };
    }
    // The keyboard opens and closes a folder with the arrows, as in Finder.
    if response.has_focus() && row.disclosure.is_some() {
        let (left, right) = ui.input(|input| {
            (
                input.key_pressed(Key::ArrowLeft),
                input.key_pressed(Key::ArrowRight),
            )
        });
        if (left && row.disclosure == Some(true)) || (right && row.disclosure == Some(false)) {
            click = SidebarClick::Disclose;
        }
        ui.memory_mut(|memory| {
            memory.set_focus_lock_filter(
                response.id,
                egui::EventFilter {
                    horizontal_arrows: true,
                    ..Default::default()
                },
            );
        });
    }
    if !ui.is_rect_visible(rect) {
        return (response, click);
    }
    let painter = ui.painter();
    if row.selected {
        painter.rect_filled(rect, ROW_RADIUS, Color32::from_black_alpha(23));
    } else if response.hovered() {
        painter.rect_filled(rect, ROW_RADIUS, Color32::from_black_alpha(10));
    }
    if response.has_focus() {
        inner_focus_ring(painter, rect, ROW_RADIUS);
    }
    if let Some(open) = row.disclosure {
        let center = Pos2::new(rect.left() + indent - 1.0, rect.center().y);
        let (w, h) = (3.0, 2.2);
        let points = if open {
            vec![
                center + Vec2::new(-w, -h / 1.4),
                center + Vec2::new(w, -h / 1.4),
                center + Vec2::new(0.0, h * 1.2),
            ]
        } else {
            vec![
                center + Vec2::new(-h / 1.4, -w),
                center + Vec2::new(h * 1.2, 0.0),
                center + Vec2::new(-h / 1.4, w),
            ]
        };
        painter.add(Shape::convex_polygon(points, SECONDARY, Stroke::NONE));
    }
    let lead_center = Pos2::new(rect.left() + indent + 14.0, rect.center().y);
    paint_lead(ui, lead_center, &row.lead, 15.0);
    let mut right = rect.right() - 8.0;
    if let Some(badge) = row.badge.filter(|badge| badge.count > 0) {
        paint_badge(ui, Pos2::new(right, rect.center().y), badge, false);
        right -= 30.0;
    } else if let Some(count) = row.count {
        let galley = galley(ui, text(count.to_string(), Font::Callout));
        let pos = Pos2::new(
            right - galley.size().x,
            rect.center().y - galley.size().y / 2.0,
        );
        right = pos.x - 6.0;
        ui.painter().galley(pos, galley, SECONDARY);
    }
    let left = lead_center.x + 15.0;
    let label = WidgetText::from(text(row.label, Font::Body).color(LABEL)).into_galley(
        ui,
        Some(TextWrapMode::Truncate),
        (right - left).max(10.0),
        TextStyle::Body,
    );
    ui.painter().galley(
        Pos2::new(left, rect.center().y - label.size().y / 2.0),
        label,
        LABEL,
    );
    (response, click)
}

/// A row of the sidebar rail: the icon or the letter square alone, centered, with the
/// name in a tooltip and the badge at its corner.
pub(crate) fn rail_row(
    ui: &mut Ui,
    lead: &Lead,
    name: &str,
    selected: bool,
    badge: Option<Badge>,
) -> Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::click());
    let spoken = sidebar_name(name, None, badge);
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, &spoken));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if selected {
            painter.rect_filled(rect, ROW_RADIUS, Color32::from_black_alpha(23));
        } else if response.hovered() {
            painter.rect_filled(rect, ROW_RADIUS, Color32::from_black_alpha(10));
        }
        if response.has_focus() {
            inner_focus_ring(painter, rect, ROW_RADIUS);
        }
        paint_lead(ui, rect.center(), lead, 18.0);
        if let Some(badge) = badge.filter(|badge| badge.count > 0) {
            paint_badge(
                ui,
                Pos2::new(rect.right() - 3.0, rect.top() + 9.0),
                badge,
                true,
            );
        }
    }
    response.on_hover_text(name)
}

/// The title of a sidebar section ("Personal", "Shared", "Agents"), with an optional
/// "+" that shows when the pointer is on the header. Returns the response of "+".
pub(crate) fn sidebar_section(ui: &mut Ui, title: &str, add: Option<&str>) -> Option<Response> {
    let (rect, header) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 30.0), Sense::hover());
    let galley = galley(ui, medium(title, Font::Footnote).variation(b"wght", 600.0));
    ui.painter().galley(
        Pos2::new(rect.left() + 8.0, rect.bottom() - 6.0 - galley.size().y),
        galley,
        SECONDARY,
    );
    let name = add?;
    let button_rect = Rect::from_center_size(
        Pos2::new(rect.right() - 13.0, rect.bottom() - 6.0 - 6.0),
        Vec2::splat(18.0),
    );
    let response = ui.interact(button_rect, header.id.with("add"), Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, name));
    let visible = header.hovered()
        || response.hovered()
        || response.has_focus()
        || ui.rect_contains_pointer(rect);
    if visible {
        let painter = ui.painter();
        if response.hovered() {
            painter.rect_filled(button_rect, 4, FILL2);
        }
        if response.has_focus() {
            inner_focus_ring(painter, button_rect, 4);
        }
        paint_icon(painter, button_rect.shrink(3.0), Icon::Plus, SECONDARY);
    }
    Some(response.on_hover_text(name))
}

// ---- Banners, empty states, figures. ----

/// A tinted banner for something that needs attention.
pub(crate) fn notice<R>(
    ui: &mut Ui,
    tone: Tone,
    title: &str,
    message: Option<&str>,
    add: impl FnOnce(&mut Ui) -> R,
) -> R {
    let icon = match tone {
        Tone::Good => Icon::Check,
        Tone::Warning | Tone::Critical => Icon::Warning,
        Tone::Neutral | Tone::Accent => Icon::Info,
    };
    let inner = Frame::NONE
        .fill(tone.tint())
        .stroke(Stroke::new(1.0, tone.mark().gamma_multiply(0.28)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                paint_icon_in(ui, icon, 16.0, tone.mark());
                ui.add_space(2.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    ui.label(text(title, Font::Headline).color(LABEL));
                    if let Some(message) = message {
                        paragraph(ui, message, Font::Callout, LABEL);
                    }
                    add(ui)
                })
                .inner
            })
            .inner
        })
        .inner;
    ui.add_space(16.0);
    inner
}

/// SwiftUI `ContentUnavailableView`. Returns true when the action is clicked.
pub(crate) fn empty_state(
    ui: &mut Ui,
    icon: Icon,
    title: &str,
    message: &str,
    action: Option<&str>,
) -> bool {
    let mut clicked = false;
    ui.vertical_centered(|ui| {
        ui.add_space(48.0);
        paint_icon_in(ui, icon, 34.0, TERTIARY);
        ui.add_space(10.0);
        ui.label(text(title, Font::Title3).color(LABEL));
        ui.add_space(2.0);
        ui.scope(|ui| {
            ui.set_max_width(380.0);
            ui.add(
                Label::new(text(message, Font::Callout).color(SECONDARY))
                    .wrap()
                    .halign(Align::Center),
            );
        });
        if let Some(action) = action {
            ui.add_space(12.0);
            clicked = button(ui, action, Style::Prominent).clicked();
        }
        ui.add_space(48.0);
    });
    clicked
}

/// A stat tile: a label, a large value, and a caption. `width` is the outer width,
/// with the margins and the border.
pub(crate) fn stat_tile(ui: &mut Ui, width: f32, label: &str, value: &str, caption: &str) {
    Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, SECTION_EDGE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            // 14 + 14 of margin and 1 + 1 of border: a frame draws its stroke inside
            // its size. Without the border the row of tiles is wider than the page.
            ui.set_width(width - 30.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(text(label, Font::Callout).color(SECONDARY));
                ui.label(text(value, Font::LargeTitle).color(LABEL));
                ui.add(Label::new(text(caption, Font::Footnote).color(SECONDARY)).truncate());
            });
        });
}

// ---- Sheets and the toast. ----

/// What a sheet reports.
pub(crate) struct SheetResponse {
    /// The owner pressed Escape on the top sheet.
    pub escape: bool,
}

/// The input of the last frame came from the keyboard, not the pointer. The focus
/// helpers move the focus only for a keyboard user, so a pointer user sees no focus
/// ring that they did not ask for.
pub(crate) fn keyboard_mode(ctx: &egui::Context) -> bool {
    ctx.data(|data| data.get_temp(Id::new("apassy-keyboard-mode")))
        .unwrap_or(false)
}

pub(crate) fn set_keyboard_mode(ctx: &egui::Context, on: bool) {
    ctx.data_mut(|data| data.insert_temp(Id::new("apassy-keyboard-mode"), on));
}

fn sheet_enter_id() -> Id {
    Id::new("apassy-sheet-enter")
}

/// True once when the owner pressed Return in the top sheet for its default action.
/// [`save_shortcut`] reads it. A destructive alert never calls it, so Return never
/// deletes or revokes.
fn take_sheet_enter(ctx: &egui::Context) -> bool {
    ctx.data_mut(|data| data.remove_temp::<bool>(sheet_enter_id()))
        .unwrap_or(false)
}

fn first_field_id() -> Id {
    Id::new("apassy-sheet-first-field")
}

/// Give `field` the focus once when a screen asks for it (`flag`): the first field of
/// a start step, or the field that a choice shows. A text field takes it also for a
/// pointer user, as in a macOS form: the owner types next. Not in a frame with a
/// pointer press or release: egui gives the focus up at the click that changed the
/// screen, so the field waits for the next frame.
pub(crate) fn claim_start_focus(flag: &mut bool, field: &Response) {
    let clicking = field
        .ctx
        .input(|input| input.pointer.any_pressed() || input.pointer.any_released());
    if *flag && !clicking {
        *flag = false;
        field.request_focus();
    }
}

/// As in a macOS sheet, the first single-line field of a sheet that just opened takes
/// the focus, also for a pointer user: the owner can type at once. A keyboard user
/// already gets the first control of the sheet. Buttons never take the focus for a
/// pointer user, so no focus ring shows that the owner did not ask for.
pub(crate) fn claim_first_field(response: &Response) {
    let ctx = &response.ctx;
    let pending = ctx.data(|data| data.get_temp::<egui::LayerId>(first_field_id()));
    if pending == Some(response.layer_id) {
        response.request_focus();
        ctx.data_mut(|data| data.remove::<egui::LayerId>(first_field_id()));
    }
}

fn sheet_takes_focus_id() -> Id {
    Id::new("apassy-sheet-takes-focus")
}

/// True in the frame where the sheet that is drawing moves the focus to its first
/// control, for a keyboard user: it became the top sheet, or the first key came after
/// the pointer opened it. A destructive alert uses it to put the focus on Cancel
/// instead. Not after the focus left a control of the sheet, as with Tab past the
/// last control: the focus then goes on to the first control.
pub(crate) fn sheet_takes_focus(ctx: &egui::Context) -> bool {
    ctx.data(|data| data.get_temp(sheet_takes_focus_id()))
        .unwrap_or(false)
}

/// The Cancel button of a destructive alert. See [`alert_default_button`].
pub(crate) fn alert_cancel(ui: &mut Ui) -> Response {
    alert_default_button(ui, "Cancel")
}

/// The safe button of a destructive alert, such as Cancel or "Keep editing". It is the
/// default button, so Return and Space never delete, revoke, or reset:
/// - It takes the focus when the sheet moves the focus (see [`sheet_takes_focus`]).
/// - When no control has the focus, for example in an alert opened with the pointer,
///   Return or Space presses it.
pub(crate) fn alert_default_button(ui: &mut Ui, label: &str) -> Response {
    let ctx = ui.ctx().clone();
    let layer = ui.layer_id();
    let pressed = ctx
        .memory(|memory| memory.top_modal_layer() == Some(layer) && memory.focused().is_none())
        && !egui::Popup::is_any_open(&ctx)
        && ctx.input(|input| {
            !input.modifiers.any()
                && (input.key_pressed(Key::Enter) || input.key_pressed(Key::Space))
        });
    // The button takes the focus before it registers, so egui turns the key into its
    // click in this frame.
    let id = ui.next_auto_id();
    if pressed {
        ctx.memory_mut(|memory| memory.request_focus(id));
    }
    let default = button(ui, label, Style::Bordered);
    debug_assert_eq!(default.id, id, "the button has the ID that took the focus");
    if pressed {
        // The key is used: the sheet does not take it as its default action too.
        ctx.input_mut(|input| {
            input.consume_key(egui::Modifiers::NONE, Key::Enter);
            input.consume_key(egui::Modifiers::NONE, Key::Space);
        });
    } else if sheet_takes_focus(&ctx) {
        default.request_focus();
    }
    default
}

/// A macOS sheet: a modal card over a dimmed window. A click outside does not close
/// it, so typed text is not lost. A sheet that opens over another sheet is drawn on
/// top of it.
///
/// The keyboard:
/// - When the sheet becomes the top sheet, the focus moves to its first control (for a
///   keyboard user). The page behind keeps its focus for the return.
/// - Return does the default action when no button has the focus: in a single-line
///   field, or with no focus. A focused button takes Return itself. A multi-line field
///   takes Return as a new line.
/// - The focus never moves in a frame with Return or Space: the control that took it
///   would take the key as a click too. In an alert opened with the pointer, that
///   control is the destructive button.
/// - Escape closes the sheet. The arrow keys do not move the focus out of the sheet.
pub(crate) fn sheet(
    ctx: &egui::Context,
    id: &str,
    width: f32,
    add: impl FnOnce(&mut Ui),
) -> SheetResponse {
    let modal_id = Id::new(("apassy-sheet", id));
    let layer = egui::LayerId::new(Order::Foreground, modal_id);
    // A sheet that would appear over another sheet in a frame with a pointer press waits
    // for the next frame. A quick click (press and release in one frame) on the sheet
    // behind brings that sheet to the front in this frame too, and egui keeps the old
    // order of the two: the new sheet, for example the owner check, would stay hidden
    // behind the sheet that opened it, without the focus.
    let appears = !ctx.memory(|memory| memory.areas().visible_last_frame(&layer));
    if appears
        && ctx.memory(|memory| memory.top_modal_layer()).is_some()
        && ctx.input(|input| input.pointer.any_pressed())
    {
        ctx.request_repaint();
        return SheetResponse { escape: false };
    }
    let top_key = modal_id.with("was-top");
    let top_now = ctx.memory(|memory| memory.top_modal_layer()) == Some(layer);
    let was_top = ctx
        .data(|data| data.get_temp::<bool>(top_key))
        .unwrap_or(false);
    let opened = top_now && !was_top;
    // A control of this sheet had the focus since the sheet became the top sheet.
    let had_key = modal_id.with("had-focus");
    let had_focus = !opened
        && ctx
            .data(|data| data.get_temp::<bool>(had_key))
            .unwrap_or(false);
    // Read before `data_mut`: the lock of the context data does not nest.
    let pointer_user = !keyboard_mode(ctx);
    ctx.data_mut(|data| {
        // Return belongs to the sheet that draws now, and to this frame only.
        data.remove_temp::<bool>(sheet_enter_id());
        // A pointer user: the first single-line field of the new sheet takes the
        // focus in this frame (see [`claim_first_field`]). Only in this frame.
        if opened && pointer_user {
            data.insert_temp(first_field_id(), layer);
        } else {
            data.remove::<egui::LayerId>(first_field_id());
        }
    });
    // A focused control in the sheet went away, for example after a failed save with
    // Return. The focus goes to the first control again, not behind the sheet.
    let lost = top_now
        && ctx.memory(|memory| memory.focused()).is_none()
        && !ctx.input(|input| input.key_pressed(Key::Escape));
    // Return or Space in this frame: a control that takes the focus now would also take
    // the key as a click. The focus moves in the next frame; the key does the default
    // action, or presses the safe button of an alert ([`alert_default_button`]).
    let click_key =
        ctx.input(|input| input.key_pressed(Key::Enter) || input.key_pressed(Key::Space));
    let move_focus = (opened || lost) && keyboard_mode(ctx);
    if move_focus {
        // The next control that registers takes the focus: the first one of the sheet.
        ctx.memory_mut(|memory| {
            if let Some(focused) = memory.focused() {
                memory.surrender_focus(focused);
            }
            if !click_key {
                memory.move_focus(egui::FocusDirection::Next);
            }
        });
    }
    let takes_focus = move_focus && !click_key && !had_focus;
    ctx.data_mut(|data| data.insert_temp(sheet_takes_focus_id(), takes_focus));
    let before = ctx.memory(|memory| memory.focused());
    let response = Modal::new(modal_id)
        .backdrop_color(Color32::from_black_alpha(46))
        .frame(
            Frame::NONE
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, Color32::from_black_alpha(16)))
                .corner_radius(CornerRadius::same(14))
                .inner_margin(Margin::same(22))
                .shadow(soft_shadow(40, 60)),
        )
        .show(ctx, |ui| {
            ui.set_width(width);
            ui.spacing_mut().item_spacing = Vec2::new(8.0, 6.0);
            add(ui)
        });
    let after = ctx.memory(|memory| memory.focused());
    ctx.data_mut(|data| {
        data.insert_temp(top_key, response.is_top_modal);
        data.insert_temp(sheet_takes_focus_id(), false);
        // A control behind the top sheet drops the focus, so a focus here is in it.
        let has_focus = response.is_top_modal && after.is_some();
        data.insert_temp(had_key, response.is_top_modal && (had_focus || has_focus));
    });
    let quiet = response.is_top_modal && !response.any_popup_open;
    let escape = quiet && ctx.input(|input| input.key_pressed(Key::Escape));
    let enter = quiet
        && ctx.input(|input| input.key_pressed(Key::Enter) && !input.modifiers.any())
        // No focus, or a single-line field that gave up the focus on Return.
        && (before.is_none() || after.is_none());
    if enter {
        ctx.data_mut(|data| data.insert_temp(sheet_enter_id(), true));
    }
    if quiet && let Some(focused) = after {
        // The arrow keys stay in the sheet. egui would move the focus to a control
        // behind it, and the control would drop the focus.
        ctx.memory_mut(|memory| {
            memory.set_focus_lock_filter(
                focused,
                egui::EventFilter {
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    ..Default::default()
                },
            );
        });
    }
    SheetResponse { escape }
}

/// The title of a sheet, with an optional line of explanation.
pub(crate) fn sheet_title(ui: &mut Ui, title: &str, subtitle: Option<&str>) {
    ui.label(text(title, Font::Title3).color(LABEL));
    if let Some(subtitle) = subtitle {
        paragraph(ui, subtitle, Font::Callout, SECONDARY);
    }
    ui.add_space(12.0);
}

/// The scrolling body of a sheet. It leaves room for the title and the buttons.
///
/// A sheet is bounded by its size in the last frame, so the body asks for the content
/// height of the last frame. The sheet then fits its content in two frames.
pub(crate) fn sheet_body<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let max = (ui.ctx().content_rect().height() - 220.0).max(160.0);
    let id = ui.id().with("apassy-sheet-body-height");
    let last: f32 = ui.ctx().data(|data| data.get_temp(id)).unwrap_or(0.0);
    let output = ScrollArea::vertical()
        .max_height(max)
        .min_scrolled_height(last.min(max))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            let inner = add(ui);
            follow_focus(ui);
            keyboard_scroll(ui);
            inner
        });
    let height = output.content_size.y;
    ui.ctx().data_mut(|data| data.insert_temp(id, height));
    output.inner
}

/// Scroll the focused control into view when the focus moves to it, also for a control
/// that does not do it itself, such as a text field. Call it at the end of the content
/// of a [`ScrollArea`].
pub(crate) fn follow_focus(ui: &Ui) {
    let ctx = ui.ctx();
    let Some(focused) = ctx.memory(|memory| memory.focused()) else {
        return;
    };
    let key = ui.id().with("apassy-follow-focus");
    if ctx.data(|data| data.get_temp::<Id>(key)) == Some(focused) {
        return;
    }
    let Some(response) = ctx.read_response(focused) else {
        return;
    };
    if response.layer_id != ui.layer_id() || !ui.min_rect().intersects(response.rect) {
        return;
    }
    ui.scroll_to_rect(response.rect.expand(16.0), None);
    ctx.data_mut(|data| data.insert_temp(key, focused));
}

/// Page Up, Page Down, Home, and End scroll the content of a [`ScrollArea`]. They do
/// nothing in a text field, in a menu, or behind a sheet.
pub(crate) fn keyboard_scroll(ui: &Ui) {
    let ctx = ui.ctx();
    if ctx.text_edit_focused()
        || egui::Popup::is_any_open(ctx)
        || !ctx.memory(|memory| memory.allows_interaction(ui.layer_id()))
    {
        return;
    }
    let (page_up, page_down, home, end) = ctx.input(|input| {
        let plain = !input.modifiers.any();
        (
            plain && input.key_pressed(Key::PageUp),
            plain && input.key_pressed(Key::PageDown),
            plain && input.key_pressed(Key::Home),
            plain && input.key_pressed(Key::End),
        )
    });
    let page = ui.clip_rect().height() * 0.9;
    let content = ui.min_rect();
    if page_down {
        ui.scroll_with_delta(Vec2::new(0.0, -page));
    } else if page_up {
        ui.scroll_with_delta(Vec2::new(0.0, page));
    } else if home {
        ui.scroll_to_rect(
            Rect::from_min_size(content.min, Vec2::new(content.width(), 1.0)),
            Some(Align::TOP),
        );
    } else if end {
        ui.scroll_to_rect(
            Rect::from_min_size(
                Pos2::new(content.left(), content.bottom() - 1.0),
                Vec2::new(content.width(), 1.0),
            ),
            Some(Align::BOTTOM),
        );
    }
}

/// The button row of a sheet: `leading` on the left (for a destructive action), and
/// `trailing` on the right, added right to left (the default action first).
pub(crate) fn sheet_buttons(
    ui: &mut Ui,
    leading: impl FnOnce(&mut Ui),
    trailing: impl FnOnce(&mut Ui),
) {
    ui.add_space(4.0);
    egui::Sides::new().show(ui, leading, |ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        trailing(ui);
    });
}

/// A short result message at the bottom of the window. Returns true when the owner
/// closes it.
pub(crate) fn toast(
    ctx: &egui::Context,
    message: &str,
    tone: Tone,
    opacity: f32,
    closable: bool,
) -> bool {
    let mut close = false;
    egui::Area::new(Id::new("apassy-toast"))
        .order(Order::Tooltip)
        .anchor(Align2::CENTER_BOTTOM, Vec2::new(0.0, -22.0))
        .interactable(true)
        .show(ctx, |ui| {
            Frame::NONE
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, Color32::from_black_alpha(20)))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::symmetric(14, 10))
                .shadow(soft_shadow(24, 40))
                .multiply_with_opacity(opacity)
                .show(ui, |ui| {
                    ui.set_max_width(540.0);
                    ui.horizontal(|ui| {
                        let icon = match tone {
                            Tone::Good => Icon::Check,
                            Tone::Critical | Tone::Warning => Icon::Warning,
                            _ => Icon::Info,
                        };
                        paint_icon_in(ui, icon, 15.0, tone.mark().gamma_multiply(opacity));
                        ui.add(
                            Label::new(
                                text(message, Font::Body).color(LABEL.gamma_multiply(opacity)),
                            )
                            .wrap(),
                        );
                        if closable {
                            close = icon_button(
                                ui,
                                Icon::Xmark,
                                "Close the message (Esc)",
                                Size::Small,
                            )
                            .clicked();
                        }
                    });
                });
        });
    close
}

// ---- Icons (SF Symbols style, drawn as strokes). ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Icon {
    Key,
    Person,
    Terminal,
    Database,
    Asterisk,
    Lock,
    Chart,
    Plus,
    ChevronRight,
    ChevronLeft,
    ChevronDown,
    Shield,
    Globe,
    Check,
    Warning,
    Info,
    Xmark,
    Clock,
    #[cfg(not(feature = "vault"))]
    List,
    Folder,
    Eye,
    /// A window with a sidebar, for "Hide sidebar" and "Show sidebar".
    Sidebar,
    /// The Settings gear with teeth, as SF Symbols `gearshape`.
    Gearshape,
    /// A check in a circle: Decisions.
    CheckCircle,
    /// A robot head: Agents.
    Agent,
    /// Two people: a shared vault.
    People,
    Search,
    /// Three dots: the menu of rare actions.
    More,
    /// An arrow out of a box.
    Share,
    /// A laptop: Settings > Devices.
    #[cfg(feature = "vault")]
    Laptop,
    /// An arrow down in a circle: Settings > Updates.
    #[cfg(feature = "vault")]
    Download,
}

/// An icon in a rounded color tile, as in System Settings.
pub(crate) fn icon_tile(ui: &mut Ui, icon: Icon, color: Color32) {
    icon_tile_sized(ui, icon, color, 22.0);
}

/// An icon tile of `size` points.
pub(crate) fn icon_tile_sized(ui: &mut Ui, icon: Icon, color: Color32, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint_icon_tile(ui.painter(), rect, icon, color);
}

/// Paint an icon tile in `rect`.
pub(crate) fn paint_icon_tile(painter: &Painter, rect: Rect, icon: Icon, color: Color32) {
    let size = rect.width();
    painter.rect_filled(rect, (size * 0.26).round() as u8, color);
    paint_icon(painter, rect.shrink(size * 0.21), icon, Color32::WHITE);
}

/// Allocate `size` and paint an icon.
pub(crate) fn paint_icon_in(ui: &mut Ui, icon: Icon, size: f32, color: Color32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint_icon(ui.painter(), rect, icon, color);
    response
}

/// Paint `icon` in `rect`. The drawing uses a unit square.
pub(crate) fn paint_icon(painter: &Painter, rect: Rect, icon: Icon, color: Color32) {
    let size = rect.width().min(rect.height());
    let origin = rect.center() - Vec2::splat(size / 2.0);
    let p = |x: f32, y: f32| origin + Vec2::new(x * size, y * size);
    let stroke = Stroke::new((size / 11.0).clamp(1.0, 2.6), color);
    let line = |points: &[(f32, f32)]| {
        painter.add(Shape::line(
            points.iter().map(|&(x, y)| p(x, y)).collect(),
            stroke,
        ));
    };
    let closed = |points: &[(f32, f32)]| {
        painter.add(Shape::closed_line(
            points.iter().map(|&(x, y)| p(x, y)).collect(),
            stroke,
        ));
    };
    let circle = |x: f32, y: f32, r: f32| {
        painter.circle_stroke(p(x, y), r * size, stroke);
    };
    let arc = |cx: f32, cy: f32, rx: f32, ry: f32, from: f32, to: f32| -> Vec<(f32, f32)> {
        (0..=16)
            .map(|step| {
                let t = from + (to - from) * step as f32 / 16.0;
                (cx + rx * t.cos(), cy + ry * t.sin())
            })
            .collect()
    };
    use std::f32::consts::{PI, TAU};
    match icon {
        Icon::Key => {
            circle(0.27, 0.5, 0.19);
            line(&[(0.46, 0.5), (0.92, 0.5), (0.92, 0.68)]);
            line(&[(0.76, 0.5), (0.76, 0.64)]);
        }
        Icon::Person => {
            circle(0.5, 0.3, 0.17);
            line(&arc(0.5, 0.92, 0.32, 0.34, PI, TAU));
        }
        Icon::Terminal => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.08, 0.16), p(0.92, 0.84)),
                size * 0.12,
                stroke,
                StrokeKind::Middle,
            );
            line(&[(0.26, 0.37), (0.42, 0.5), (0.26, 0.63)]);
            line(&[(0.5, 0.65), (0.72, 0.65)]);
        }
        Icon::Database => {
            closed(&arc(0.5, 0.22, 0.34, 0.11, 0.0, TAU));
            line(&[(0.16, 0.22), (0.16, 0.78)]);
            line(&[(0.84, 0.22), (0.84, 0.78)]);
            line(&arc(0.5, 0.5, 0.34, 0.11, 0.0, PI));
            line(&arc(0.5, 0.78, 0.34, 0.11, 0.0, PI));
        }
        Icon::Asterisk => {
            for angle in [0.0_f32, PI / 3.0, 2.0 * PI / 3.0] {
                let (dx, dy) = (0.36 * angle.sin(), 0.36 * angle.cos());
                line(&[(0.5 - dx, 0.5 - dy), (0.5 + dx, 0.5 + dy)]);
            }
        }
        Icon::Lock => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.18, 0.44), p(0.82, 0.9)),
                size * 0.1,
                stroke,
                StrokeKind::Middle,
            );
            let mut shackle = vec![(0.3, 0.44)];
            shackle.extend(arc(0.5, 0.32, 0.2, 0.2, PI, TAU));
            shackle.push((0.7, 0.44));
            line(&shackle);
        }
        Icon::Chart => {
            for (x, top) in [(0.2, 0.5), (0.5, 0.26), (0.8, 0.1)] {
                line(&[(x, 0.9), (x, top)]);
            }
        }
        Icon::Plus => {
            line(&[(0.5, 0.16), (0.5, 0.84)]);
            line(&[(0.16, 0.5), (0.84, 0.5)]);
        }
        Icon::ChevronRight => line(&[(0.36, 0.18), (0.66, 0.5), (0.36, 0.82)]),
        Icon::ChevronLeft => line(&[(0.64, 0.18), (0.34, 0.5), (0.64, 0.82)]),
        Icon::ChevronDown => line(&[(0.18, 0.36), (0.5, 0.66), (0.82, 0.36)]),
        Icon::Shield => closed(&[
            (0.5, 0.08),
            (0.84, 0.2),
            (0.84, 0.48),
            (0.78, 0.66),
            (0.66, 0.8),
            (0.5, 0.92),
            (0.34, 0.8),
            (0.22, 0.66),
            (0.16, 0.48),
            (0.16, 0.2),
        ]),
        Icon::Globe => {
            circle(0.5, 0.5, 0.38);
            closed(&arc(0.5, 0.5, 0.16, 0.38, 0.0, TAU));
            line(&[(0.12, 0.5), (0.88, 0.5)]);
        }
        Icon::Check => line(&[(0.18, 0.54), (0.4, 0.76), (0.84, 0.28)]),
        Icon::Warning => {
            closed(&[(0.5, 0.1), (0.92, 0.86), (0.08, 0.86)]);
            line(&[(0.5, 0.38), (0.5, 0.6)]);
            painter.circle_filled(p(0.5, 0.73), stroke.width * 0.7, color);
        }
        Icon::Info => {
            circle(0.5, 0.5, 0.4);
            line(&[(0.5, 0.46), (0.5, 0.72)]);
            painter.circle_filled(p(0.5, 0.32), stroke.width * 0.7, color);
        }
        Icon::Xmark => {
            line(&[(0.24, 0.24), (0.76, 0.76)]);
            line(&[(0.76, 0.24), (0.24, 0.76)]);
        }
        Icon::Clock => {
            circle(0.5, 0.5, 0.4);
            line(&[(0.5, 0.26), (0.5, 0.5), (0.68, 0.6)]);
        }
        #[cfg(not(feature = "vault"))]
        Icon::List => {
            for y in [0.26, 0.5, 0.74] {
                painter.circle_filled(p(0.16, y), stroke.width * 0.8, color);
                line(&[(0.32, y), (0.86, y)]);
            }
        }
        Icon::Folder => closed(&[
            (0.08, 0.24),
            (0.38, 0.24),
            (0.46, 0.34),
            (0.92, 0.34),
            (0.92, 0.82),
            (0.08, 0.82),
        ]),
        Icon::Eye => {
            closed(&arc(0.5, 0.5, 0.42, 0.26, 0.0, TAU));
            circle(0.5, 0.5, 0.12);
        }
        Icon::Sidebar => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.06, 0.16), p(0.94, 0.84)),
                size * 0.12,
                stroke,
                StrokeKind::Middle,
            );
            line(&[(0.38, 0.16), (0.38, 0.84)]);
        }
        Icon::Gearshape => {
            let step = TAU / 8.0;
            let mut outline = Vec::new();
            for tooth in 0..8 {
                let angle = tooth as f32 * step;
                for (offset, radius) in [(-0.36, 0.34), (-0.17, 0.45), (0.17, 0.45), (0.36, 0.34)] {
                    let at = angle + offset * step;
                    outline.push((0.5 + radius * at.cos(), 0.5 + radius * at.sin()));
                }
            }
            closed(&outline);
            circle(0.5, 0.5, 0.13);
        }
        Icon::CheckCircle => {
            circle(0.5, 0.5, 0.4);
            line(&[(0.33, 0.52), (0.45, 0.64), (0.68, 0.38)]);
        }
        Icon::Agent => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.18, 0.3), p(0.82, 0.8)),
                size * 0.13,
                stroke,
                StrokeKind::Middle,
            );
            line(&[(0.5, 0.14), (0.5, 0.3)]);
            line(&[(0.4, 0.5), (0.4, 0.58)]);
            line(&[(0.6, 0.5), (0.6, 0.58)]);
        }
        Icon::People => {
            circle(0.37, 0.36, 0.13);
            line(&arc(0.37, 0.86, 0.25, 0.3, PI, TAU));
            circle(0.72, 0.4, 0.1);
            line(&arc(0.72, 0.84, 0.18, 0.24, 1.25 * PI, TAU));
        }
        Icon::Search => {
            circle(0.44, 0.44, 0.26);
            line(&[(0.63, 0.63), (0.86, 0.86)]);
        }
        Icon::More => {
            for x in [0.22, 0.5, 0.78] {
                painter.circle_filled(p(x, 0.5), stroke.width * 1.1, color);
            }
        }
        Icon::Share => {
            line(&[(0.5, 0.62), (0.5, 0.1)]);
            line(&[(0.33, 0.26), (0.5, 0.1), (0.67, 0.26)]);
            line(&[
                (0.32, 0.42),
                (0.18, 0.42),
                (0.18, 0.9),
                (0.82, 0.9),
                (0.82, 0.42),
                (0.68, 0.42),
            ]);
        }
        #[cfg(feature = "vault")]
        Icon::Laptop => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.2, 0.22), p(0.8, 0.66)),
                size * 0.06,
                stroke,
                StrokeKind::Middle,
            );
            line(&[(0.06, 0.8), (0.94, 0.8)]);
        }
        #[cfg(feature = "vault")]
        Icon::Download => {
            circle(0.5, 0.5, 0.4);
            line(&[(0.5, 0.28), (0.5, 0.7)]);
            line(&[(0.33, 0.54), (0.5, 0.7), (0.67, 0.54)]);
        }
    }
}
