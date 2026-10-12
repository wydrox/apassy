//! The grouped rows of the Settings window, as in the mockup (ADR 0026 §3): a gray
//! group label, a white rounded group, and rows with the label on the left and the value
//! or the control on the right. A short footnote can follow a group.
//!
//! The API follows [`kit::Section`], so a section of Settings changes its look with one
//! call. The rows are 38 points high at least, with 13-point text.

use eframe::egui::{
    self, Align, Color32, CornerRadius, Frame, Label, Layout, Margin, Response, RichText, Sense,
    Shadow, Shape, Stroke, TextWrapMode, Ui, UiBuilder, Vec2, WidgetInfo, WidgetText, WidgetType,
    epaint,
};

use super::super::kit::{self, Font};

/// The side padding of a row.
pub(crate) const PAD_X: f32 = 12.0;
/// The top and bottom padding of a row.
const PAD_Y: f32 = 7.0;
/// The height of the content of a one-line row: 38 points with the padding.
pub(crate) const LINE: f32 = 24.0;
/// The smallest width of the label column.
const LABEL_MIN: f32 = 110.0;
/// The space between the label and the value.
const GAP: f32 = 10.0;
/// The space above a group label.
const LABEL_TOP: f32 = 18.0;

/// The hairline between two rows.
const SEPARATOR: Color32 = Color32::from_rgb(235, 235, 237);

/// The label of a group: 12 points, semibold, secondary.
pub(crate) fn group_label(ui: &mut Ui, title: &str) {
    ui.add_space(LABEL_TOP);
    // A frame, not a horizontal row: a row would be one control high.
    Frame::NONE
        .inner_margin(Margin {
            left: 2,
            ..Margin::ZERO
        })
        .show(ui, |ui| {
            ui.add(
                Label::new(
                    kit::text(title, Font::Callout)
                        .variation(b"wght", 600.0)
                        .color(kit::SECONDARY),
                )
                .selectable(false),
            );
        });
    ui.add_space(6.0);
}

/// A short footnote under a group: 12 points, secondary.
pub(crate) fn footnote(ui: &mut Ui, text: impl Into<String>) {
    footnote_colored(ui, text, kit::SECONDARY);
}

/// A footnote in a status color.
pub(crate) fn footnote_colored(ui: &mut Ui, text: impl Into<String>, color: Color32) {
    ui.add_space(6.0);
    Frame::NONE
        .inner_margin(Margin::symmetric(4, 0))
        .show(ui, |ui| {
            ui.add(Label::new(kit::text(text, Font::Callout).color(color)).wrap());
        });
}

/// The rows of one group. Rows get a hairline between them.
pub(crate) struct Group<'u> {
    ui: &'u mut Ui,
    rows: usize,
}

/// A group with an optional label above and a footnote below. Same use as
/// [`kit::section`].
pub(crate) fn section<R>(
    ui: &mut Ui,
    header: Option<&str>,
    footer: Option<&str>,
    add: impl FnOnce(&mut Group<'_>) -> R,
) -> R {
    let inner = group(ui, header, add);
    if let Some(footer) = footer {
        footnote(ui, footer);
    }
    inner
}

/// A group with an optional label above.
pub(crate) fn group<R>(
    ui: &mut Ui,
    header: Option<&str>,
    add: impl FnOnce(&mut Group<'_>) -> R,
) -> R {
    match header {
        Some(header) => group_label(ui, header),
        None => ui.add_space(LABEL_TOP),
    }
    Frame::NONE
        .fill(kit::SURFACE)
        .stroke(Stroke::new(0.5, Color32::from_black_alpha(22)))
        .shadow(Shadow {
            offset: [0, 1],
            blur: 2,
            spread: 0,
            color: Color32::from_black_alpha(10),
        })
        .corner_radius(CornerRadius::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            add(&mut Group { ui, rows: 0 })
        })
        .inner
}

impl Group<'_> {
    fn separator(&mut self) {
        if self.rows > 0 {
            let width = self.ui.available_width();
            let (rect, _) = self
                .ui
                .allocate_exact_size(Vec2::new(width, 0.0), Sense::hover());
            let stroke = Stroke::new(1.0 / self.ui.ctx().pixels_per_point(), SEPARATOR);
            self.ui
                .painter()
                .hline((rect.left() + PAD_X)..=rect.right(), rect.top(), stroke);
        }
        self.rows += 1;
    }

    /// A padded row with custom content, at least one line high.
    pub(crate) fn row<R>(&mut self, add: impl FnOnce(&mut Ui) -> R) -> R {
        self.separator();
        Frame::NONE
            .inner_margin(Margin::symmetric(PAD_X as i8, PAD_Y as i8))
            .show(self.ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(LINE);
                ui.spacing_mut().item_spacing.y = 3.0;
                add(ui)
            })
            .inner
    }

    /// A row with the label on the left, then the value and the controls on the right,
    /// all on one line. The value is cut with "…" when it does not fit, and shows whole
    /// on hover. The controls come right to left: the first is the rightmost.
    pub(crate) fn line(
        &mut self,
        label: &str,
        value: Option<RichText>,
        controls: impl FnOnce(&mut Ui),
    ) {
        let label = label_text(label).into();
        self.row(|ui| one_line(ui, label, value, controls));
    }

    /// A one-line row with a note under it: a hint, a state, or a warning.
    pub(crate) fn line_note(
        &mut self,
        label: &str,
        value: Option<RichText>,
        note: Option<RichText>,
        controls: impl FnOnce(&mut Ui),
    ) {
        let label = label_text(label).into();
        self.row(|ui| {
            one_line(ui, label, value, controls);
            if let Some(note) = note {
                ui.add(Label::new(note).wrap());
            }
        });
    }

    /// SwiftUI `LabeledContent`: a label on the left and a value on the right.
    pub(crate) fn labeled(&mut self, label: &str, value: impl Into<WidgetText>) {
        let value = value.into();
        self.row(|ui| {
            one_line_widget(ui, label_text(label).into(), value, |_| {});
        });
    }

    /// A form row with a switch on the right, and an optional note under the title.
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
                .height(LINE)
                .show(
                    ui,
                    |ui| {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(label_text(title));
                            if let Some(subtitle) = subtitle {
                                ui.add(Label::new(note(subtitle)).wrap());
                            }
                        });
                    },
                    |ui| kit::toggle(ui, on, title),
                )
                .1
        })
    }

    /// A form row: a label on the left and a control on the right.
    pub(crate) fn field(&mut self, label: &str, add: impl FnOnce(&mut Ui) -> Response) -> Response {
        self.row(|ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(ui.available_width(), LINE),
                Layout::left_to_right(Align::Center),
                |ui| {
                    let label = ui.label(label_text(label));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        add(ui).labelled_by(label.id)
                    })
                    .inner
                },
            )
            .inner
        })
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
                    .inner_margin(Margin::symmetric(PAD_X as i8, PAD_Y as i8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), LINE),
                            Layout::left_to_right(Align::Center),
                            add,
                        );
                    });
            })
            .response;
        if response.hovered() || response.has_focus() {
            let fill = if response.is_pointer_button_down_on() {
                kit::FILL_PRESSED
            } else {
                Color32::from_rgb(246, 246, 248)
            };
            let rect = response.rect.shrink2(Vec2::new(4.0, 1.0));
            self.ui
                .painter()
                .set(background, epaint::RectShape::filled(rect, 6, fill));
            if response.has_focus() {
                kit::inner_focus_ring(self.ui.painter(), rect, 6);
            }
        }
        if response.gained_focus() {
            response.scroll_to_me(None);
        }
        let enabled = self.ui.is_enabled();
        response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, label));
        response
    }

    /// A row that is a link in the accent color, as "Open a Synced Vault…".
    pub(crate) fn link(&mut self, label: &str) -> Response {
        self.clickable_row(label, |ui| {
            ui.label(kit::text(label, Font::Body).color(kit::ACCENT_TEXT));
        })
    }

    /// A row with free content under the others, for a note or a code block.
    pub(crate) fn note_row(&mut self, text: impl Into<String>) {
        let text = text.into();
        self.row(|ui| {
            ui.add(Label::new(note(&text)).wrap());
        });
    }

    /// A row with a note in a status color.
    pub(crate) fn tone_row(&mut self, text: impl Into<String>, color: Color32) {
        let text = text.into();
        self.row(|ui| {
            ui.add(Label::new(kit::text(text, Font::Callout).color(color)).wrap());
        });
    }
}

/// The text of a row label.
pub(crate) fn label_text(label: &str) -> RichText {
    kit::text(label, Font::Body).color(kit::LABEL)
}

/// A value on the right of a row: 13 points, secondary.
pub(crate) fn value(text: impl Into<String>) -> RichText {
    kit::text(text, Font::Body).color(kit::SECONDARY)
}

/// A note in a row: 12 points, secondary.
pub(crate) fn note(text: &str) -> RichText {
    kit::text(text, Font::Callout).color(kit::SECONDARY)
}

/// The content of a one-line row (see [`Group::line`]), for a custom row.
pub(crate) fn one_line(
    ui: &mut Ui,
    label: WidgetText,
    value: Option<RichText>,
    controls: impl FnOnce(&mut Ui),
) {
    let value = value.map_or_else(|| WidgetText::from(""), WidgetText::from);
    one_line_widget(ui, label, value, controls);
}

fn one_line_widget(
    ui: &mut Ui,
    label: WidgetText,
    value: WidgetText,
    controls: impl FnOnce(&mut Ui),
) {
    ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), LINE),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            let label_width = label
                .clone()
                .into_galley(
                    ui,
                    Some(TextWrapMode::Extend),
                    f32::INFINITY,
                    egui::TextStyle::Body,
                )
                .size()
                .x;
            // The label keeps its width up to the half of the row; a longer one is cut.
            let keep = label_width.min(ui.available_width() * 0.6).max(0.0);
            ui.allocate_ui_with_layout(
                Vec2::new(keep, LINE),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_min_width(keep.min(LABEL_MIN));
                    ui.add(Label::new(label).truncate().selectable(false));
                },
            );
            ui.add_space(GAP - 8.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                controls(ui);
                // A cut value shows the whole value on hover.
                if !value.text().is_empty() {
                    ui.add(Label::new(value).truncate());
                }
            });
        },
    );
}
