//! The colors of the Mac app, by role (implementation-plan-misc M13, D7).
//!
//! Every color of the window comes from a role of [`Palette`]: a background, a text, a
//! line, a fill, the accent, or a status. The UI reads the palette of the current
//! appearance with [`palette`]. [`Palette::LIGHT`] holds the exact values that `kit.rs`
//! had before the roles, so the light window does not change. The dark palette comes
//! with M14 (`docs/design/misc-mockup.html`, the palette table).
//!
//! Colors that stay the same in both appearances are in [`fixed`]: provider and kind
//! tiles, agent avatars, the icon tiles of Settings, the app logo, and the QR code.
//!
//! No other file of `src/desktop/ui` writes a color literal; a source scan test checks
//! it.

#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use eframe::egui::Color32;

/// The roles of the window, one color each. The names follow the CSS variables of the
/// mockup palette table; P1–P6 are the roles that the mockup proposes for colors that
/// were outside `kit.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Palette {
    // ---- Backgrounds. ----
    /// The window behind the columns.
    pub(crate) window: Color32,
    pub(crate) sidebar: Color32,
    /// The list column (ADR 0026), as the content list of Mail.
    pub(crate) list: Color32,
    /// The detail column, behind its groups; the bars at the bottom of a detail.
    pub(crate) detail: Color32,
    /// Grouped sections, stat cards, sheets, toasts.
    pub(crate) surface: Color32,
    /// The faint background of egui (striped rows).
    pub(crate) faint: Color32,

    // ---- Text. ----
    pub(crate) label: Color32,
    pub(crate) secondary: Color32,
    /// Placeholders and decoration only. It is too light for text that carries meaning.
    pub(crate) tertiary: Color32,
    /// Text and glyphs on a colored fill: the accent, the selection, a tile, a badge.
    pub(crate) on_accent: Color32,
    /// The second line of a selected list row, on the selection.
    pub(crate) on_selection_secondary: Color32,

    // ---- Lines. ----
    /// Hairlines between rows and columns.
    pub(crate) separator: Color32,
    /// The outline of a grouped section.
    pub(crate) section_edge: Color32,
    /// Text fields, bordered controls.
    pub(crate) border: Color32,
    /// A hovered egui widget.
    pub(crate) border_hover: Color32,
    /// The hairline between the columns (the mockup: 0.5 px of black at 9 %).
    pub(crate) column_edge: Color32,
    /// The edge of a settings or detail group: black at 8 %.
    pub(crate) group_edge: Color32,
    /// The hairline between two settings rows.
    pub(crate) settings_line: Color32,
    /// The hairline between two detail rows: black at 6 % on white.
    pub(crate) detail_line: Color32,
    /// The hairline of a text field of the new credential sheet.
    pub(crate) field_edge: Color32,
    /// The hairline of a push button of a sheet.
    pub(crate) button_edge: Color32,
    /// The hairline of a group of detected credentials.
    pub(crate) card_edge: Color32,
    /// The edge of a plain bar button at the bottom of a decision.
    pub(crate) bar_button_edge: Color32,
    /// The edge of a sheet.
    pub(crate) sheet_edge: Color32,
    /// The edge of a toast.
    pub(crate) toast_edge: Color32,
    /// The trailing edge of the floating sidebar.
    pub(crate) float_edge: Color32,

    // ---- Fills. ----
    /// The search field, the neutral tint, a bordered button.
    pub(crate) fill: Color32,
    /// Small buttons, tags, hover.
    pub(crate) fill_hover: Color32,
    /// Pressed, an open menu button.
    pub(crate) fill_pressed: Color32,
    /// A hovered row of a section or a table, and of a settings group.
    pub(crate) row_hover: Color32,
    /// A hovered list row.
    pub(crate) list_hover: Color32,
    /// A hovered row of a detail group.
    pub(crate) detail_row_hover: Color32,
    /// A gray cap, a hovered plain button.
    pub(crate) fill_soft: Color32,
    /// P1: a selected sidebar row, and the gear when Settings is open.
    pub(crate) sidebar_selected: Color32,
    /// A hovered sidebar row.
    pub(crate) sidebar_hover: Color32,
    /// A pressed control of the sidebar or the title bar: the vault header (also with
    /// its menu open), the sidebar button.
    pub(crate) sidebar_pressed: Color32,
    /// A hovered control of the sidebar or the title bar.
    pub(crate) sidebar_control_hover: Color32,
    /// The header of a group of list rows, almost opaque over the rows under it.
    pub(crate) list_header: Color32,
    /// The track of a switch that is off.
    pub(crate) switch_off: Color32,
    /// The knob of a switch.
    pub(crate) knob: Color32,
    /// The track of a segmented picker.
    pub(crate) segment_track: Color32,
    /// A hovered segment.
    pub(crate) segment_hover: Color32,
    /// The line between two segments.
    pub(crate) segment_divider: Color32,
    /// P2: push buttons, the plain bars of a decision, the selected segment.
    pub(crate) button: Color32,
    /// A hovered plain bar of a decision.
    pub(crate) button_hover: Color32,
    /// A gray button of a detail row.
    pub(crate) gray_button: Color32,
    /// A gray button of a detail row, hovered.
    pub(crate) gray_button_hover: Color32,
    /// A menu value of a detail row.
    pub(crate) menu_value: Color32,
    /// P3: command blocks.
    pub(crate) code: Color32,
    /// The selectable monospace text of a code block.
    pub(crate) code_field: Color32,
    /// P4: menus, popovers, and tooltips (the egui window fill).
    pub(crate) menu: Color32,
    /// P5: behind a sheet.
    pub(crate) scrim: Color32,
    /// The rest of the window under the floating sidebar.
    pub(crate) float_scrim: Color32,
    /// P6: the red count badge of the sidebar.
    pub(crate) badge: Color32,
    /// A neutral count badge: a total.
    pub(crate) badge_neutral: Color32,
    /// The disk of the cloud badge on an avatar.
    pub(crate) badge_disk: Color32,
    /// The edge of the disk of the cloud badge.
    pub(crate) badge_disk_edge: Color32,
    /// Selected text.
    pub(crate) text_selection: Color32,
    /// The base of every shadow; each shadow takes its own opacity of it.
    pub(crate) shadow: Color32,

    // ---- Accent. ----
    /// The primary button, sidebar icons, focus.
    pub(crate) accent: Color32,
    pub(crate) accent_hover: Color32,
    pub(crate) accent_pressed: Color32,
    /// Accent text and links on white.
    pub(crate) accent_text: Color32,
    /// The selected list row. White text on it passes 4.5:1.
    pub(crate) selection: Color32,
    /// The links of a detail page, and the owner mark of a detail.
    pub(crate) link: Color32,
    /// The main bar at the bottom of a decision.
    pub(crate) primary_bar: Color32,
    /// The main bar at the bottom of a decision, hovered or pressed.
    pub(crate) primary_bar_pressed: Color32,
    /// The red prominent button, hovered or pressed.
    pub(crate) critical_hover: Color32,
    /// The one colored mark of the window: production, and what blocks an agent.
    pub(crate) production: Color32,
    /// The text of the red "Production" cap.
    pub(crate) production_text: Color32,

    // ---- Status (`Tone`). ----
    pub(crate) mark_neutral: Color32,
    pub(crate) mark_good: Color32,
    pub(crate) mark_warning: Color32,
    pub(crate) mark_critical: Color32,
    pub(crate) text_good: Color32,
    pub(crate) text_warning: Color32,
    pub(crate) text_critical: Color32,
    pub(crate) tint_accent: Color32,
    pub(crate) tint_good: Color32,
    pub(crate) tint_warning: Color32,
    pub(crate) tint_critical: Color32,
    /// The time left of a decision, a timed-out mark, a warning glyph on its tile.
    pub(crate) countdown: Color32,
    /// The tile behind a warning glyph.
    pub(crate) warning_tile: Color32,
    /// The allowed mark of a detail.
    pub(crate) mark_allowed: Color32,
    /// "Allowed by bouncer" in charts (the mockup's `--s-auto`).
    pub(crate) chart_automatic: Color32,
    /// "Asked you" in charts and an ask rate of 25 % or more (`--s-ask`).
    pub(crate) chart_asked: Color32,
    /// The total above a bar of a chart.
    pub(crate) chart_value: Color32,
}

/// Black at `alpha` of 255, premultiplied: [`Color32::from_black_alpha`] as a const.
const fn black(alpha: u8) -> Color32 {
    Color32::from_rgba_premultiplied(0, 0, 0, alpha)
}

/// White at `alpha` of 255, premultiplied: `Color32::from_white_alpha` as a const.
const fn white(alpha: u8) -> Color32 {
    Color32::from_rgba_premultiplied(alpha, alpha, alpha, alpha)
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

impl Palette {
    /// The macOS light appearance: the values of `kit.rs` before M13.
    pub(crate) const LIGHT: Self = Self {
        window: rgb(250, 250, 251),
        sidebar: rgb(236, 236, 239),
        list: Color32::WHITE,
        detail: rgb(246, 246, 247),
        surface: Color32::WHITE,
        faint: rgb(248, 248, 250),

        label: rgb(29, 29, 31),
        secondary: rgb(106, 106, 112),
        tertiary: rgb(160, 160, 166),
        on_accent: Color32::WHITE,
        on_selection_secondary: white(210),

        separator: rgb(232, 232, 236),
        section_edge: rgb(228, 228, 233),
        border: rgb(210, 210, 216),
        border_hover: rgb(188, 188, 196),
        column_edge: black(23),
        group_edge: black(22),
        settings_line: rgb(235, 235, 237),
        detail_line: rgb(240, 240, 240),
        field_edge: black(46),
        button_edge: black(52),
        card_edge: black(26),
        bar_button_edge: black(48),
        sheet_edge: black(16),
        toast_edge: black(20),
        float_edge: black(51),

        fill: rgb(240, 240, 243),
        fill_hover: rgb(232, 232, 236),
        fill_pressed: rgb(222, 222, 227),
        row_hover: rgb(246, 246, 248),
        list_hover: rgb(247, 247, 248),
        detail_row_hover: rgb(250, 250, 250),
        fill_soft: rgb(235, 235, 237),
        sidebar_selected: black(23),
        sidebar_hover: black(10),
        sidebar_pressed: rgb(222, 222, 228),
        sidebar_control_hover: rgb(232, 232, 236),
        list_header: white(240),
        switch_off: rgb(216, 216, 222),
        knob: Color32::WHITE,
        segment_track: rgb(234, 234, 238),
        segment_hover: rgb(224, 224, 229),
        segment_divider: rgb(214, 214, 220),
        button: Color32::WHITE,
        button_hover: rgb(250, 250, 250),
        gray_button: rgb(235, 235, 235),
        gray_button_hover: rgb(224, 224, 224),
        menu_value: rgb(242, 242, 242),
        code: rgb(242, 242, 244),
        code_field: rgb(246, 246, 248),
        menu: Color32::WHITE,
        scrim: black(46),
        float_scrim: black(28),
        badge: rgb(224, 53, 43),
        badge_neutral: black(36),
        badge_disk: Color32::WHITE,
        badge_disk_edge: black(38),
        text_selection: rgb(196, 222, 255),
        shadow: Color32::BLACK,

        accent: rgb(0, 122, 255),
        accent_hover: rgb(0, 108, 230),
        accent_pressed: rgb(0, 94, 204),
        accent_text: rgb(0, 102, 214),
        selection: rgb(10, 108, 255),
        link: rgb(10, 108, 255),
        primary_bar: rgb(10, 108, 255),
        primary_bar_pressed: rgb(0, 94, 224),
        critical_hover: rgb(222, 44, 36),
        production: rgb(224, 53, 43),
        production_text: rgb(196, 43, 34),

        mark_neutral: rgb(142, 142, 147),
        mark_good: rgb(52, 199, 89),
        mark_warning: rgb(255, 149, 0),
        mark_critical: rgb(255, 59, 48),
        text_good: rgb(29, 128, 54),
        text_warning: rgb(166, 82, 0),
        text_critical: rgb(200, 30, 30),
        tint_accent: rgb(232, 242, 255),
        tint_good: rgb(233, 247, 237),
        tint_warning: rgb(255, 245, 229),
        tint_critical: rgb(255, 238, 237),
        countdown: rgb(200, 106, 0),
        warning_tile: rgb(255, 244, 229),
        mark_allowed: rgb(36, 161, 72),
        chart_automatic: rgb(10, 108, 255),
        chart_asked: rgb(232, 137, 12),
        chart_value: black(184),
    };
}

/// The palette of the current appearance. The app has only the light appearance until
/// M14 follows the system.
pub(crate) fn palette() -> &'static Palette {
    &Palette::LIGHT
}

/// Colors that stay the same in both appearances: brand and kind tiles, agent avatars,
/// the icon tiles of Settings, the app logo, and the QR code.
pub(crate) mod fixed {
    use eframe::egui::Color32;

    use super::rgb;

    // ---- Agents (`kit::agent_color`, the agent onboarding). ----
    pub(crate) const CLAUDE: Color32 = rgb(217, 119, 87);
    pub(crate) const CODEX: Color32 = rgb(16, 163, 127);
    pub(crate) const T3_CODE: Color32 = rgb(110, 90, 230);
    /// A CI agent of GitHub.
    pub(crate) const GITHUB_AGENT: Color32 = rgb(36, 41, 47);
    /// Any other agent: a steady color from its name.
    pub(crate) const OTHER_AGENTS: [Color32; 6] = [
        rgb(0, 122, 255),
        rgb(88, 86, 214),
        rgb(191, 90, 242),
        rgb(48, 176, 199),
        rgb(255, 55, 95),
        GRAY,
    ];

    // ---- Tiles. ----
    /// A gray tile: an agent of no known kind, a custom secret, the Updates settings.
    pub(crate) const GRAY: Color32 = rgb(142, 142, 147);
    /// The orange tile of an API key and of the Rules settings.
    pub(crate) const ORANGE: Color32 = rgb(255, 149, 0);
    /// The dark gray terminal tile of an SSH key.
    pub(crate) const SSH_KEY: Color32 = rgb(75, 79, 88);
    /// The blue Postgres tile. A database of an unknown engine gets it too.
    pub(crate) const DATABASE: Color32 = rgb(51, 103, 145);
    /// The lock tile of a vault file in a list of files.
    pub(crate) const VAULT_FILE: Color32 = rgb(99, 99, 104);
    /// The tiles of the declaration, command, and connector rows of a credential.
    pub(crate) const DECLARATION: Color32 = rgb(52, 120, 246);
    pub(crate) const COMMAND: Color32 = rgb(88, 86, 214);
    pub(crate) const CONNECTOR: Color32 = rgb(48, 176, 199);
    /// The colors of vault tiles, picked by the name of the vault.
    pub(crate) const VAULTS: [Color32; 6] = [
        rgb(0, 122, 255),
        rgb(52, 170, 90),
        rgb(255, 149, 0),
        rgb(88, 86, 214),
        rgb(255, 59, 48),
        rgb(48, 176, 199),
    ];

    // ---- Providers (`ui::named_provider`). ----
    pub(crate) const ANTHROPIC: Color32 = rgb(204, 120, 92);
    pub(crate) const GITHUB: Color32 = rgb(31, 35, 40);
    pub(crate) const STRIPE: Color32 = rgb(99, 91, 255);
    pub(crate) const CLOUDFLARE: Color32 = rgb(244, 129, 32);
    pub(crate) const FLY_IO: Color32 = rgb(123, 63, 228);
    pub(crate) const OPENAI: Color32 = rgb(16, 163, 127);
    pub(crate) const AWS: Color32 = rgb(35, 47, 62);
    pub(crate) const SLACK: Color32 = rgb(74, 21, 75);
    pub(crate) const SENTRY: Color32 = rgb(54, 45, 89);
    pub(crate) const RESEND: Color32 = rgb(17, 17, 17);
    pub(crate) const NETFLIX: Color32 = rgb(229, 9, 20);

    // ---- The icon tiles of Settings (`settings_view`), as in System Settings. ----
    pub(crate) const SETTINGS_VAULT: Color32 = rgb(0, 122, 255);
    pub(crate) const SETTINGS_SECURITY: Color32 = rgb(88, 86, 214);
    pub(crate) const SETTINGS_DEVICES: Color32 = rgb(48, 160, 200);
    pub(crate) const SETTINGS_BOUNCER: Color32 = rgb(175, 82, 222);
    pub(crate) const SETTINGS_TOOLS: Color32 = rgb(99, 99, 102);
    pub(crate) const SETTINGS_UPDATES: Color32 = rgb(142, 142, 147);
    #[cfg(not(feature = "vault"))]
    pub(crate) const SETTINGS_RULES: Color32 = rgb(255, 149, 0);

    // ---- The app logo and the QR code. ----
    pub(crate) const LOGO_TILE: Color32 = rgb(14, 24, 32);
    pub(crate) const LOGO_MARK: Color32 = Color32::WHITE;
    pub(crate) const LOGO_BLADE: Color32 = rgb(10, 119, 254);
    /// A QR code stays black on white, so every camera reads it.
    pub(crate) const QR_LIGHT: Color32 = Color32::WHITE;
    pub(crate) const QR_DARK: Color32 = Color32::BLACK;
}

#[cfg(test)]
mod tests {
    use eframe::egui::Color32;

    use super::{Palette, palette};
    use crate::desktop::ui::kit::Tone;

    /// Each role of the light palette next to the literal it replaced, as `kit.rs` and
    /// the UI files wrote it before M13. A change of the light window starts here.
    #[test]
    fn the_light_palette_keeps_every_color_of_before() {
        let p = Palette::LIGHT;
        let roles = [
            ("window", p.window, Color32::from_rgb(250, 250, 251)),
            ("sidebar", p.sidebar, Color32::from_rgb(236, 236, 239)),
            ("list", p.list, Color32::WHITE),
            ("detail", p.detail, Color32::from_rgb(246, 246, 247)),
            ("surface", p.surface, Color32::WHITE),
            ("faint", p.faint, Color32::from_rgb(248, 248, 250)),
            ("label", p.label, Color32::from_rgb(29, 29, 31)),
            ("secondary", p.secondary, Color32::from_rgb(106, 106, 112)),
            ("tertiary", p.tertiary, Color32::from_rgb(160, 160, 166)),
            ("on_accent", p.on_accent, Color32::WHITE),
            (
                "on_selection_secondary",
                p.on_selection_secondary,
                Color32::from_white_alpha(210),
            ),
            ("separator", p.separator, Color32::from_rgb(232, 232, 236)),
            (
                "section_edge",
                p.section_edge,
                Color32::from_rgb(228, 228, 233),
            ),
            ("border", p.border, Color32::from_rgb(210, 210, 216)),
            (
                "border_hover",
                p.border_hover,
                Color32::from_rgb(188, 188, 196),
            ),
            ("column_edge", p.column_edge, Color32::from_black_alpha(23)),
            ("group_edge", p.group_edge, Color32::from_black_alpha(22)),
            (
                "settings_line",
                p.settings_line,
                Color32::from_rgb(235, 235, 237),
            ),
            (
                "detail_line",
                p.detail_line,
                Color32::from_rgb(240, 240, 240),
            ),
            ("field_edge", p.field_edge, Color32::from_black_alpha(46)),
            ("button_edge", p.button_edge, Color32::from_black_alpha(52)),
            ("card_edge", p.card_edge, Color32::from_black_alpha(26)),
            (
                "bar_button_edge",
                p.bar_button_edge,
                Color32::from_black_alpha(48),
            ),
            ("sheet_edge", p.sheet_edge, Color32::from_black_alpha(16)),
            ("toast_edge", p.toast_edge, Color32::from_black_alpha(20)),
            ("float_edge", p.float_edge, Color32::from_black_alpha(51)),
            ("fill", p.fill, Color32::from_rgb(240, 240, 243)),
            ("fill_hover", p.fill_hover, Color32::from_rgb(232, 232, 236)),
            (
                "fill_pressed",
                p.fill_pressed,
                Color32::from_rgb(222, 222, 227),
            ),
            ("row_hover", p.row_hover, Color32::from_rgb(246, 246, 248)),
            ("list_hover", p.list_hover, Color32::from_rgb(247, 247, 248)),
            (
                "detail_row_hover",
                p.detail_row_hover,
                Color32::from_rgb(250, 250, 250),
            ),
            ("fill_soft", p.fill_soft, Color32::from_rgb(235, 235, 237)),
            (
                "sidebar_selected",
                p.sidebar_selected,
                Color32::from_black_alpha(23),
            ),
            (
                "sidebar_hover",
                p.sidebar_hover,
                Color32::from_black_alpha(10),
            ),
            (
                "sidebar_pressed",
                p.sidebar_pressed,
                Color32::from_rgb(222, 222, 228),
            ),
            (
                "sidebar_control_hover",
                p.sidebar_control_hover,
                Color32::from_rgb(232, 232, 236),
            ),
            ("list_header", p.list_header, Color32::from_white_alpha(240)),
            ("switch_off", p.switch_off, Color32::from_rgb(216, 216, 222)),
            ("knob", p.knob, Color32::WHITE),
            (
                "segment_track",
                p.segment_track,
                Color32::from_rgb(234, 234, 238),
            ),
            (
                "segment_hover",
                p.segment_hover,
                Color32::from_rgb(224, 224, 229),
            ),
            (
                "segment_divider",
                p.segment_divider,
                Color32::from_rgb(214, 214, 220),
            ),
            ("button", p.button, Color32::WHITE),
            (
                "button_hover",
                p.button_hover,
                Color32::from_rgb(250, 250, 250),
            ),
            (
                "gray_button",
                p.gray_button,
                Color32::from_rgb(235, 235, 235),
            ),
            (
                "gray_button_hover",
                p.gray_button_hover,
                Color32::from_rgb(224, 224, 224),
            ),
            ("menu_value", p.menu_value, Color32::from_rgb(242, 242, 242)),
            ("code", p.code, Color32::from_rgb(242, 242, 244)),
            ("code_field", p.code_field, Color32::from_rgb(246, 246, 248)),
            ("menu", p.menu, Color32::WHITE),
            ("scrim", p.scrim, Color32::from_black_alpha(46)),
            ("float_scrim", p.float_scrim, Color32::from_black_alpha(28)),
            ("badge", p.badge, Color32::from_rgb(224, 53, 43)),
            (
                "badge_neutral",
                p.badge_neutral,
                Color32::from_black_alpha(36),
            ),
            ("badge_disk", p.badge_disk, Color32::WHITE),
            (
                "badge_disk_edge",
                p.badge_disk_edge,
                Color32::from_black_alpha(38),
            ),
            (
                "text_selection",
                p.text_selection,
                Color32::from_rgb(196, 222, 255),
            ),
            ("shadow", p.shadow, Color32::BLACK),
            ("accent", p.accent, Color32::from_rgb(0, 122, 255)),
            (
                "accent_hover",
                p.accent_hover,
                Color32::from_rgb(0, 108, 230),
            ),
            (
                "accent_pressed",
                p.accent_pressed,
                Color32::from_rgb(0, 94, 204),
            ),
            ("accent_text", p.accent_text, Color32::from_rgb(0, 102, 214)),
            ("selection", p.selection, Color32::from_rgb(10, 108, 255)),
            ("link", p.link, Color32::from_rgb(10, 108, 255)),
            (
                "primary_bar",
                p.primary_bar,
                Color32::from_rgb(10, 108, 255),
            ),
            (
                "primary_bar_pressed",
                p.primary_bar_pressed,
                Color32::from_rgb(0, 94, 224),
            ),
            (
                "critical_hover",
                p.critical_hover,
                Color32::from_rgb(222, 44, 36),
            ),
            ("production", p.production, Color32::from_rgb(224, 53, 43)),
            (
                "production_text",
                p.production_text,
                Color32::from_rgb(196, 43, 34),
            ),
            (
                "mark_neutral",
                p.mark_neutral,
                Color32::from_rgb(142, 142, 147),
            ),
            ("mark_good", p.mark_good, Color32::from_rgb(52, 199, 89)),
            (
                "mark_warning",
                p.mark_warning,
                Color32::from_rgb(255, 149, 0),
            ),
            (
                "mark_critical",
                p.mark_critical,
                Color32::from_rgb(255, 59, 48),
            ),
            ("text_good", p.text_good, Color32::from_rgb(29, 128, 54)),
            (
                "text_warning",
                p.text_warning,
                Color32::from_rgb(166, 82, 0),
            ),
            (
                "text_critical",
                p.text_critical,
                Color32::from_rgb(200, 30, 30),
            ),
            (
                "tint_accent",
                p.tint_accent,
                Color32::from_rgb(232, 242, 255),
            ),
            ("tint_good", p.tint_good, Color32::from_rgb(233, 247, 237)),
            (
                "tint_warning",
                p.tint_warning,
                Color32::from_rgb(255, 245, 229),
            ),
            (
                "tint_critical",
                p.tint_critical,
                Color32::from_rgb(255, 238, 237),
            ),
            ("countdown", p.countdown, Color32::from_rgb(200, 106, 0)),
            (
                "warning_tile",
                p.warning_tile,
                Color32::from_rgb(255, 244, 229),
            ),
            (
                "mark_allowed",
                p.mark_allowed,
                Color32::from_rgb(36, 161, 72),
            ),
            (
                "chart_automatic",
                p.chart_automatic,
                Color32::from_rgb(10, 108, 255),
            ),
            (
                "chart_asked",
                p.chart_asked,
                Color32::from_rgb(232, 137, 12),
            ),
            ("chart_value", p.chart_value, Color32::from_black_alpha(184)),
            (
                "on_accent at 217",
                p.on_accent.gamma_multiply_u8(217),
                Color32::from_white_alpha(217),
            ),
        ];
        // Every role is in the table (Palette holds only colors), and one more line.
        assert_eq!(
            roles.len() - 1,
            std::mem::size_of::<Palette>() / std::mem::size_of::<Color32>()
        );
        let changed: Vec<String> = roles
            .iter()
            .filter(|(_, role, before)| role != before)
            .map(|(name, role, before)| format!("{name}: {role:?}, before {before:?}"))
            .collect();
        assert!(changed.is_empty(), "{changed:#?}");
        // Each shadow takes its opacity of the shadow role: the same as black at it.
        for alpha in [8, 10, 18, 22, 28, 30, 34, 40, 46, 60] {
            assert_eq!(
                p.shadow.gamma_multiply_u8(alpha),
                Color32::from_black_alpha(alpha)
            );
        }
        assert_eq!(*palette(), Palette::LIGHT);
    }

    /// The status colors of `Tone` read the palette and keep their colors of before.
    #[test]
    fn each_tone_keeps_its_light_colors() {
        let rgb = Color32::from_rgb;
        let tones = [
            (
                Tone::Neutral,
                rgb(142, 142, 147),
                rgb(106, 106, 112),
                rgb(240, 240, 243),
            ),
            (
                Tone::Accent,
                rgb(0, 122, 255),
                rgb(0, 102, 214),
                rgb(232, 242, 255),
            ),
            (
                Tone::Good,
                rgb(52, 199, 89),
                rgb(29, 128, 54),
                rgb(233, 247, 237),
            ),
            (
                Tone::Warning,
                rgb(255, 149, 0),
                rgb(166, 82, 0),
                rgb(255, 245, 229),
            ),
            (
                Tone::Critical,
                rgb(255, 59, 48),
                rgb(200, 30, 30),
                rgb(255, 238, 237),
            ),
        ];
        for (tone, mark, text, tint) in tones {
            assert_eq!(tone.mark(), mark, "{tone:?} mark");
            assert_eq!(tone.text(), text, "{tone:?} text");
            assert_eq!(tone.tint(), tint, "{tone:?} tint");
        }
    }

    /// The source without its inline test modules (`#[cfg(test)]` and a `mod … {` line
    /// at the start of a line, up to the `}` that closes it at the start of a line).
    fn without_test_modules(source: &str) -> String {
        let mut rest = source;
        let mut kept = String::new();
        while let Some(start) = rest.find("#[cfg(test)]\nmod ") {
            let line_end = rest[start..]
                .find('\n')
                .map_or(rest.len(), |i| start + i + 1);
            let header_end = rest[line_end..]
                .find('\n')
                .map_or(rest.len(), |i| line_end + i);
            if !rest[line_end..header_end].trim_end().ends_with('{') {
                // `mod name;`: a test file of its own, skipped by its name.
                kept.push_str(&rest[..header_end]);
                rest = &rest[header_end..];
                continue;
            }
            kept.push_str(&rest[..start]);
            rest = rest[header_end..]
                .find("\n}\n")
                .map_or("", |end| &rest[header_end + end + 3..]);
        }
        kept.push_str(rest);
        kept
    }

    fn rust_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }

    /// The color literals of the UI are in this file only (D7): every other file of
    /// `src/desktop/ui` names a role of the palette or a fixed color. Test modules and
    /// test files may write colors to check them. `Color32::TRANSPARENT` is no color.
    #[test]
    fn no_color_literal_outside_the_palette() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/desktop");
        let mut files = vec![root.join("ui.rs")];
        rust_files(&root.join("ui"), &mut files);
        assert!(files.len() > 40, "{} files", files.len());
        let mut found = Vec::new();
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name == "palette.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            let source = without_test_modules(&std::fs::read_to_string(&path).unwrap());
            for (number, line) in source.lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                let literal = code.match_indices("Color32::").any(|(at, _)| {
                    let after = &code[at + "Color32::".len()..];
                    after.starts_with("from_")
                        || (after.starts_with(|c: char| c.is_ascii_uppercase())
                            && !after.starts_with("TRANSPARENT"))
                }) || code.contains("Rgba::from_")
                    || code.contains("Color32([")
                    || code.contains("hex_color!");
                if literal {
                    found.push(format!("{name}:{}: {}", number + 1, line.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "color literals outside palette.rs: {found:#?}"
        );
    }
}
