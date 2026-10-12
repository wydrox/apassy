//! The grouped rows of the credential page, at the sizes of the approved mockup
//! (docs/design/app-v2-mockup.html, ADR 0026 §1): a reading column 584 points wide, white
//! groups with rows at least 38 points high, a hairline between rows, labels at the
//! left and values at the right, 13-point text, 12-point group labels, and small gray
//! buttons 24 points high.
//!
//! [`kit::section`] stays for the other pages; these rows follow the mockup more
//! closely (row height, spacing, and the gaps between groups).

use eframe::egui::{
    self, Align, Color32, CornerRadius, Frame, Label, Layout, Margin, Pos2, Rect, Response,
    RichText, Sense, Shadow, Stroke, TextWrapMode, Ui, UiBuilder, Vec2, WidgetInfo, WidgetText,
    WidgetType,
};

use super::kit::{self, Font, Icon};

/// The width of the content of the page: 640 points less the 28-point margins.
pub(super) const READING_WIDTH: f32 = 584.0;
/// The space between two groups without a label.
pub(super) const GROUP_GAP: f32 = 12.0;
/// The space under the header.
pub(super) const HEADER_GAP: f32 = 22.0;
/// The space above the footer.
pub(super) const FOOTER_GAP: f32 = 22.0;

const PAD_X: f32 = 12.0;
const PAD_Y: f32 = 7.0;
/// The smallest row: 38 points with its padding.
const ROW_MIN: f32 = 38.0 - 2.0 * PAD_Y;
/// The gap between a value and its button or chevron.
const GAP: f32 = 10.0;

/// The hairline between rows: rgba(0, 0, 0, 0.06) on white.
const LINE: Color32 = Color32::from_rgb(240, 240, 240);
/// The edge of a group: rgba(0, 0, 0, 0.08).
const EDGE: Color32 = Color32::from_black_alpha(22);
/// A gray button: rgba(0, 0, 0, 0.08) on white, and 0.12 under the pointer.
const BUTTON: Color32 = Color32::from_rgb(235, 235, 235);
const BUTTON_HOVER: Color32 = Color32::from_rgb(224, 224, 224);
/// A menu value: rgba(0, 0, 0, 0.05) on white.
const POP: Color32 = Color32::from_rgb(242, 242, 242);
/// The links of the page, as in the mockup.
pub(super) const LINK: Color32 = Color32::from_rgb(10, 108, 255);

/// The page column: at most [`READING_WIDTH`] wide and centered, with no item spacing,
/// so each gap of the page is explicit.
pub(super) fn reading_column<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let available = ui.available_rect_before_wrap();
    let width = available.width().min(READING_WIDTH).floor();
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
            ui.spacing_mut().item_spacing.y = 0.0;
            add(ui)
        },
    )
    .inner
}

/// The rows of one group.
pub(super) struct Group<'u> {
    ui: &'u mut Ui,
    rows: usize,
}

/// A white rounded group with a thin edge and a soft shadow, as `.grp` of the mockup.
/// It adds no space around it.
pub(super) fn group<R>(ui: &mut Ui, add: impl FnOnce(&mut Group<'_>) -> R) -> R {
    Frame::NONE
        .fill(kit::SURFACE)
        .stroke(Stroke::new(0.5, EDGE))
        .shadow(Shadow {
            offset: [0, 1],
            blur: 2,
            spread: 0,
            color: Color32::from_black_alpha(8),
        })
        .corner_radius(CornerRadius::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            add(&mut Group { ui, rows: 0 })
        })
        .inner
}

/// The label of a group, as `.gl` of the mockup: 12 points, semibold, gray, 18 points
/// under the group above (with its [`GROUP_GAP`]) and 6 above its group. A link at the
/// right, such as "Show All", returns true on a click; `link` is its text and its name
/// for VoiceOver.
pub(super) fn group_label(ui: &mut Ui, title: &str, link: Option<(&str, &str)>) -> bool {
    ui.add_space(18.0 - GROUP_GAP);
    let mut clicked = false;
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.label(
            kit::text(title, Font::Callout)
                .variation(b"wght", 600.0)
                .color(kit::SECONDARY),
        );
        if let Some((label, name)) = link {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(2.0);
                clicked = text_link(ui, label, name).clicked();
            });
        }
    });
    ui.add_space(6.0);
    clicked
}

/// A link in the accent color, 12 points.
fn text_link(ui: &mut Ui, label: &str, name: &str) -> Response {
    let galley = kit::galley(ui, kit::text(label, Font::Callout));
    let (rect, response) = ui.allocate_exact_size(galley.size(), Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Link, enabled, name));
    if ui.is_rect_visible(rect) {
        let color = if response.is_pointer_button_down_on() {
            kit::ACCENT_TEXT
        } else {
            LINK
        };
        ui.painter().galley(rect.min, galley, color);
        if response.has_focus() {
            kit::focus_ring(ui.painter(), rect.expand(1.0), 3);
        }
    }
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

impl Group<'_> {
    /// The hairline above each row but the first, inset 12 points at the left.
    fn separator(&mut self) {
        if self.rows > 0 {
            let rect = self.ui.available_rect_before_wrap();
            let y = rect.top();
            let width = 1.0 / self.ui.ctx().pixels_per_point();
            self.ui.painter().hline(
                (rect.left() + PAD_X)..=rect.right(),
                y,
                Stroke::new(width, LINE),
            );
        }
        self.rows += 1;
    }

    /// A row with custom content, at least 38 points high.
    pub(super) fn row<R>(&mut self, add: impl FnOnce(&mut Ui) -> R) -> R {
        self.separator();
        Frame::NONE
            .inner_margin(Margin::symmetric(PAD_X as i8, PAD_Y as i8))
            .show(self.ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(ROW_MIN);
                ui.spacing_mut().item_spacing.y = 2.0;
                add(ui)
            })
            .inner
    }

    /// A row on one line: `add` lays out left to right, centered on the row.
    pub(super) fn line<R>(&mut self, add: impl FnOnce(&mut Ui) -> R) -> R {
        self.row(|ui| {
            let width = ui.available_width();
            ui.allocate_ui_with_layout(
                Vec2::new(width, ROW_MIN),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_min_size(Vec2::new(width, ROW_MIN));
                    ui.spacing_mut().item_spacing.x = GAP;
                    add(ui)
                },
            )
            .inner
        })
    }

    /// A label at the left and a value at the right, as `LabeledContent`. A value that
    /// does not fit on the line goes under the label, left-aligned.
    pub(super) fn pair(&mut self, label: &str, value: impl Into<WidgetText>) {
        let value = value.into();
        let label = kit::text(label, Font::Body).color(kit::LABEL);
        let label_width = kit::galley(self.ui, label.clone()).size().x;
        let value_width = value
            .clone()
            .into_galley(
                self.ui,
                Some(TextWrapMode::Extend),
                f32::INFINITY,
                egui::TextStyle::Body,
            )
            .size()
            .x;
        let inner = self.ui.available_width() - 2.0 * PAD_X;
        if label_width.max(110.0) + 24.0 + value_width <= inner {
            self.line(|ui| {
                ui.label(label);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add(Label::new(value).truncate());
                });
            });
        } else {
            self.row(|ui| {
                ui.label(label);
                ui.add(Label::new(value).wrap());
            });
        }
    }

    /// A whole-row button with a hover highlight. `name` is its name for VoiceOver.
    pub(super) fn clickable_row(&mut self, name: &str, add: impl FnOnce(&mut Ui)) -> Response {
        self.separator();
        let background = self.ui.painter().add(egui::Shape::Noop);
        let response = self
            .ui
            .scope_builder(UiBuilder::new().sense(Sense::click()), |ui| {
                ui.style_mut().interaction.selectable_labels = false;
                Frame::NONE
                    .inner_margin(Margin::symmetric(PAD_X as i8, PAD_Y as i8))
                    .show(ui, |ui| {
                        let width = ui.available_width();
                        ui.set_width(width);
                        ui.allocate_ui_with_layout(
                            Vec2::new(width, ROW_MIN),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.set_min_size(Vec2::new(width, ROW_MIN));
                                ui.spacing_mut().item_spacing.x = GAP;
                                add(ui);
                            },
                        );
                    });
            })
            .response;
        if response.hovered() || response.has_focus() {
            let fill = if response.is_pointer_button_down_on() {
                kit::FILL_PRESSED
            } else {
                Color32::from_rgb(250, 250, 250)
            };
            let rect = response.rect.shrink2(Vec2::new(1.0, 1.0));
            self.ui
                .painter()
                .set(background, egui::epaint::RectShape::filled(rect, 8, fill));
            if response.has_focus() {
                kit::inner_focus_ring(self.ui.painter(), rect, 8);
            }
        }
        if response.gained_focus() {
            response.scroll_to_me(None);
        }
        let enabled = self.ui.is_enabled();
        response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, name));
        response
    }

    /// A row that opens something: the label, the value in gray, and a chevron.
    pub(super) fn chevron(&mut self, label: &str, value: &str) -> Response {
        self.clickable_row(&format!("{label}, {value}"), |ui| {
            ui.label(kit::text(label, Font::Body).color(kit::LABEL));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                kit::paint_icon_in(ui, Icon::ChevronRight, 10.0, kit::TERTIARY);
                ui.add(Label::new(kit::text(value, Font::Body).color(kit::SECONDARY)).truncate());
            });
        })
    }

    /// A row with a switch at the right.
    pub(super) fn toggle(&mut self, label: &str, on: &mut bool) -> Response {
        self.line(|ui| {
            ui.label(kit::text(label, Font::Body).color(kit::LABEL));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                kit::toggle(ui, on, label)
            })
            .inner
        })
    }
}

/// A small gray button, as `.pb` of the mockup: 24 points high, 12.5-point medium text.
/// `name` is its name for VoiceOver.
pub(super) fn pill_button(ui: &mut Ui, label: &str, name: &str) -> Response {
    let galley = kit::galley(
        ui,
        kit::text(label, Font::Callout)
            .size(12.5)
            .variation(b"wght", 500.0),
    );
    let size = Vec2::new(galley.size().x + 20.0, 24.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, name));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if ui.is_rect_visible(rect) {
        let fill = if response.is_pointer_button_down_on() {
            kit::FILL_PRESSED
        } else if response.hovered() {
            BUTTON_HOVER
        } else {
            BUTTON
        };
        let painter = ui.painter();
        painter.rect_filled(rect, 6, fill);
        if response.has_focus() {
            kit::focus_ring(painter, rect, 6);
        }
        let color = if enabled { kit::LABEL } else { kit::TERTIARY };
        painter.galley(rect.center() - galley.size() / 2.0, galley, color);
    }
    response
}

/// A menu value, as `.pop` of the mockup: the value on a light gray capsule with a
/// chevron down. A click opens a menu of `options`; a choice changes `value`. `name` is
/// its name for VoiceOver.
pub(super) fn pop_menu<T: PartialEq + Clone>(
    ui: &mut Ui,
    value: &mut T,
    options: &[(T, String)],
    shown: &str,
    name: &str,
) -> Response {
    let galley = kit::galley(ui, kit::text(shown, Font::Callout).size(12.5));
    let size = Vec2::new(galley.size().x + 31.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(WidgetType::ComboBox, enabled, name));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if ui.is_rect_visible(rect) {
        let fill = if response.is_pointer_button_down_on() {
            BUTTON_HOVER
        } else if response.hovered() {
            BUTTON
        } else {
            POP
        };
        let painter = ui.painter();
        painter.rect_filled(rect, 6, fill);
        if response.has_focus() {
            kit::focus_ring(painter, rect, 6);
        }
        let text_pos = Pos2::new(rect.left() + 8.0, rect.center().y - galley.size().y / 2.0);
        painter.galley(text_pos, galley, kit::LABEL);
        // A chevron down, 6 points wide.
        let center = Pos2::new(rect.right() - 12.0, rect.center().y - 0.5);
        painter.line(
            vec![
                center + Vec2::new(-3.5, -1.8),
                center + Vec2::new(0.0, 1.8),
                center + Vec2::new(3.5, -1.8),
            ],
            Stroke::new(1.4, kit::SECONDARY),
        );
    }
    egui::Popup::menu(&response).show(|ui| {
        ui.set_min_width(rect.width().max(140.0));
        for (option, label) in options {
            if ui
                .selectable_label(*value == *option, kit::text(label, Font::Body))
                .clicked()
            {
                *value = option.clone();
                // A choice with Return or Space closes the menu, as a click does.
                ui.close();
            }
        }
    });
    // After a choice or Escape with the keyboard, the focus goes back to the button, as
    // in `kit::picker`.
    let ctx = ui.ctx();
    let open = egui::Popup::is_id_open(ctx, egui::Popup::default_response_id(&response));
    let key = response.id.with("apassy-pop-open");
    let was_open = ctx.data(|data| data.get_temp::<bool>(key)).unwrap_or(false);
    ctx.data_mut(|data| data.insert_temp(key, open));
    if was_open && !open && kit::keyboard_mode(ctx) {
        response.request_focus();
    }
    response
}

/// How a use of a credential ended, for its round mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mark {
    /// Allowed without the owner: a green check.
    Allowed,
    /// The owner answered: a blue person.
    Owner,
    /// Refused or denied: a red cross.
    Refused,
    /// No answer in time: an orange clock.
    TimedOut,
}

/// The round mark of a use, as `.st` of the mockup: a 16-point circle with a white
/// glyph.
pub(super) fn status_mark(ui: &mut Ui, mark: Mark) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
    if ui.is_rect_visible(rect) {
        let (color, icon) = match mark {
            Mark::Allowed => (Color32::from_rgb(36, 161, 72), Icon::Check),
            Mark::Owner => (LINK, Icon::Person),
            Mark::Refused => (kit::PRODUCTION, Icon::Xmark),
            Mark::TimedOut => (Color32::from_rgb(200, 106, 0), Icon::Clock),
        };
        let painter = ui.painter();
        painter.circle_filled(rect.center(), 8.0, color);
        kit::paint_icon(
            painter,
            Rect::from_center_size(rect.center(), Vec2::splat(10.0)),
            icon,
            Color32::WHITE,
        );
    }
    response
}

/// Text at 12 points in gray, as the second line of a row.
pub(super) fn small(value: impl Into<String>) -> RichText {
    kit::text(value, Font::Callout).color(kit::SECONDARY)
}
