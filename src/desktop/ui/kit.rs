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
pub(crate) const SIDEBAR: Color32 = Color32::from_rgb(242, 242, 245);
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

/// A centered reading column with generous side margins.
pub(crate) fn column<R>(ui: &mut Ui, max_width: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    let side = ((ui.available_width() - max_width) / 2.0).max(28.0);
    Frame::NONE
        .inner_margin(Margin {
            left: side as i8,
            right: side as i8,
            top: 0,
            bottom: 36,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
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

    /// SwiftUI `LabeledContent`: a label on the left and a value on the right.
    pub(crate) fn labeled(&mut self, label: &str, value: impl Into<WidgetText>) {
        let value = value.into();
        self.row(|ui| {
            egui::Sides::new()
                .spacing(24.0)
                .shrink_right()
                .wrap_mode(TextWrapMode::Wrap)
                .show(
                    ui,
                    |ui| ui.label(text(label, Font::Body).color(LABEL)),
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
                ui.vertical(|ui| {
                    ui.label(text(title, Font::Body).color(LABEL));
                    if let Some(subtitle) = subtitle {
                        ui.add(
                            Label::new(text(subtitle, Font::Footnote).color(SECONDARY)).truncate(),
                        );
                    }
                });
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
    ui.add(
        TextEdit::singleline(value)
            .id_salt(salt)
            .hint_text(text(placeholder, Font::Body).color(TERTIARY))
            .margin(FIELD_MARGIN)
            .desired_width(f32::INFINITY),
    )
}

/// A monospace text field, for names such as `STRIPE_SECRET_KEY`.
pub(crate) fn mono_input(
    ui: &mut Ui,
    value: &mut String,
    salt: &str,
    placeholder: &str,
) -> Response {
    ui.add(
        TextEdit::singleline(value)
            .id_salt(salt)
            .font(TextStyle::Monospace)
            .hint_text(text(placeholder, Font::Mono).color(TERTIARY))
            .margin(FIELD_MARGIN)
            .desired_width(f32::INFINITY),
    )
}

/// A narrow field for a number.
pub(crate) fn number_input(
    ui: &mut Ui,
    value: &mut String,
    salt: &str,
    placeholder: &str,
) -> Response {
    ui.add(
        TextEdit::singleline(value)
            .id_salt(salt)
            .hint_text(text(placeholder, Font::Body).color(TERTIARY))
            .margin(FIELD_MARGIN)
            .desired_width(90.0),
    )
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

/// A count badge for the sidebar.
fn count_badge(painter: &Painter, ui: &Ui, right: Pos2, count: usize, tone: Tone) {
    let label = count.to_string();
    let color = if tone == Tone::Neutral {
        SECONDARY
    } else {
        Color32::WHITE
    };
    let galley = galley(ui, medium(label, Font::Footnote));
    let size = Vec2::new((galley.size().x + 10.0).max(18.0), 16.0);
    let rect = Rect::from_min_size(Pos2::new(right.x - size.x, right.y - size.y / 2.0), size);
    if tone != Tone::Neutral {
        painter.rect_filled(rect, 8, tone.mark());
    }
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);
}

// ---- Sidebar. ----

/// A sidebar `List` row: icon, label, and an optional count.
pub(crate) fn sidebar_item(
    ui: &mut Ui,
    icon: Icon,
    label: &str,
    selected: bool,
    badge: Option<(usize, Tone)>,
) -> Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 28.0), Sense::click());
    let name = match badge.filter(|(count, _)| *count > 0) {
        Some((count, Tone::Neutral)) => format!("{label}, {count}"),
        Some((count, _)) => format!("{label}, {count} waiting"),
        None => label.to_owned(),
    };
    response
        .widget_info(|| WidgetInfo::selected(WidgetType::SelectableLabel, true, selected, &name));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        if selected {
            painter.rect_filled(rect, 6, Color32::from_rgb(222, 222, 228));
        } else if response.hovered() {
            painter.rect_filled(rect, 6, Color32::from_rgb(232, 232, 236));
        }
        if response.has_focus() {
            inner_focus_ring(painter, rect, 6);
        }
        let icon_rect = Rect::from_center_size(
            Pos2::new(rect.left() + 18.0, rect.center().y),
            Vec2::splat(15.0),
        );
        paint_icon(painter, icon_rect, icon, ACCENT);
        let weight = if selected {
            medium(label, Font::Body)
        } else {
            text(label, Font::Body)
        };
        let galley = galley(ui, weight);
        painter.galley(
            Pos2::new(rect.left() + 34.0, rect.center().y - galley.size().y / 2.0),
            galley,
            LABEL,
        );
        if let Some((count, tone)) = badge.filter(|(count, _)| *count > 0) {
            count_badge(
                painter,
                ui,
                Pos2::new(rect.right() - 8.0, rect.center().y),
                count,
                tone,
            );
        }
    }
    response
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

/// A stat tile: a label, a large value, and a caption.
pub(crate) fn stat_tile(ui: &mut Ui, width: f32, label: &str, value: &str, caption: &str) {
    Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, SECTION_EDGE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(width - 28.0);
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

/// True in the frame where the sheet that is drawing became the top sheet. A
/// destructive alert uses it to put the focus on Cancel.
pub(crate) fn sheet_just_opened(ctx: &egui::Context) -> bool {
    ctx.data(|data| data.get_temp(Id::new("apassy-sheet-opened")))
        .unwrap_or(false)
}

/// The Cancel button of a destructive alert. It takes the focus when the alert opens,
/// so Return or Space on a new alert cancels: it never deletes, revokes, or resets.
pub(crate) fn alert_cancel(ui: &mut Ui) -> Response {
    let cancel = button(ui, "Cancel", Style::Bordered);
    if sheet_just_opened(ui.ctx()) && keyboard_mode(ui.ctx()) {
        cancel.request_focus();
    }
    cancel
}

/// A macOS sheet: a modal card over a dimmed window. A click outside does not close
/// it, so typed text is not lost.
///
/// The keyboard:
/// - When the sheet becomes the top sheet, the focus moves to its first control (for a
///   keyboard user). The page behind keeps its focus for the return.
/// - Return does the default action when no button has the focus: in a single-line
///   field, or with no focus. A focused button takes Return itself. A multi-line field
///   takes Return as a new line.
/// - Escape closes the sheet. The arrow keys do not move the focus out of the sheet.
pub(crate) fn sheet(
    ctx: &egui::Context,
    id: &str,
    width: f32,
    add: impl FnOnce(&mut Ui),
) -> SheetResponse {
    let modal_id = Id::new(("apassy-sheet", id));
    let layer = egui::LayerId::new(Order::Foreground, modal_id);
    let top_key = modal_id.with("was-top");
    let top_now = ctx.memory(|memory| memory.top_modal_layer()) == Some(layer);
    let was_top = ctx
        .data(|data| data.get_temp::<bool>(top_key))
        .unwrap_or(false);
    let opened = top_now && !was_top;
    ctx.data_mut(|data| {
        data.insert_temp(Id::new("apassy-sheet-opened"), opened);
        // Return belongs to the sheet that draws now, and to this frame only.
        data.remove_temp::<bool>(sheet_enter_id());
    });
    // A focused control in the sheet went away, for example after a failed save with
    // Return. The focus goes to the first control again, not behind the sheet.
    let lost = top_now
        && ctx.memory(|memory| memory.focused()).is_none()
        && !ctx.input(|input| input.key_pressed(Key::Escape));
    if (opened || lost) && keyboard_mode(ctx) {
        // The next control that registers takes the focus: the first one of the sheet.
        ctx.memory_mut(|memory| {
            if let Some(focused) = memory.focused() {
                memory.surrender_focus(focused);
            }
            memory.move_focus(egui::FocusDirection::Next);
        });
    }
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
    ctx.data_mut(|data| {
        data.insert_temp(top_key, response.is_top_modal);
        data.insert_temp(Id::new("apassy-sheet-opened"), false);
    });
    let quiet = response.is_top_modal && !response.any_popup_open;
    let escape = quiet && ctx.input(|input| input.key_pressed(Key::Escape));
    let after = ctx.memory(|memory| memory.focused());
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
    Tray,
    Chart,
    Gear,
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
    Phone,
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
        Icon::Tray => {
            closed(&[
                (0.1, 0.56),
                (0.26, 0.18),
                (0.74, 0.18),
                (0.9, 0.56),
                (0.9, 0.84),
                (0.1, 0.84),
            ]);
            line(&[
                (0.1, 0.56),
                (0.34, 0.56),
                (0.4, 0.66),
                (0.6, 0.66),
                (0.66, 0.56),
                (0.9, 0.56),
            ]);
        }
        Icon::Chart => {
            for (x, top) in [(0.2, 0.5), (0.5, 0.26), (0.8, 0.1)] {
                line(&[(x, 0.9), (x, top)]);
            }
        }
        Icon::Gear => {
            circle(0.5, 0.5, 0.14);
            circle(0.5, 0.5, 0.3);
            for step in 0..8 {
                let angle = step as f32 * TAU / 8.0;
                let (c, s) = (angle.cos(), angle.sin());
                line(&[
                    (0.5 + 0.3 * c, 0.5 + 0.3 * s),
                    (0.5 + 0.44 * c, 0.5 + 0.44 * s),
                ]);
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
        Icon::Phone => {
            painter.rect_stroke(
                Rect::from_min_max(p(0.27, 0.08), p(0.73, 0.92)),
                size * 0.12,
                stroke,
                StrokeKind::Middle,
            );
            line(&[(0.42, 0.79), (0.58, 0.79)]);
        }
    }
}
