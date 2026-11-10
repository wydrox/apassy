//! Settings > Devices (plan S2–S3, unit N7, decision D9; the approved mockup
//! `docs/design/devices-settings-mockup.html`, frames 1 and 3 to 7).
//!
//! The section has, in this order: the This Mac group with the node of this Mac on the
//! tailnet ("Reachable on Your Tailnet", its address, port, and Node Words, one line for
//! each problem, "Move Approvals to This Mac…" when the approvals still go through
//! Apassy relay, and the notifications), the Devices list with one row for each device of
//! each team (kind, roles, the route word, the last contact, and Revoke… or Details…),
//! the one add button, and the Wi-Fi Pairing group while a Wi-Fi iPhone is paired
//! (`companion.rs`, ADR 0028 stage 3).
//!
//! The drawing is pure: [`draw`] takes a [`DevicesView`] and returns the [`Action`] that
//! the owner chose. The vault build makes the view from the vault and from
//! [`NodeCache`], the copy of `Node::status` that a worker thread reads (a frame never
//! runs the Tailscale command line); the demo build makes it from the fixtures of each
//! mockup frame (`demo.rs`).
//!
//! The route switch and every Revoke… go through the owner check first
//! (`OwnerRequest::SetTailnetRoute`, `OwnerRequest::RevokeNodeDevice`); the node itself
//! checks nothing (plan unit N4).

// The demo build draws the fixtures only: the parts of the vault build stay unused there.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use eframe::egui::{self, Align, Label, Layout, Rect, Sense, Stroke, Ui, Vec2};

use super::kit::{self, Font, Icon, Style, Tone};

#[cfg(feature = "vault")]
pub(super) use super::settings::rows;
#[cfg(not(feature = "vault"))]
#[allow(dead_code)]
#[path = "settings_rows.rs"]
pub(super) mod rows;

/// The label of the route switch, and its name for VoiceOver.
pub(crate) const ROUTE_SWITCH: &str = "Reachable on Your Tailnet";
/// The subline of the switch while the route is on.
pub(crate) const ROUTE_ON: &str = "Your iPhone and Macs reach this Mac directly.";
/// The subline of the switch while the route is off or cannot be on.
pub(crate) const ROUTE_OFF: &str = "Approvals go through Apassy relay.";
/// The subline of the switch while the vault is locked.
pub(crate) const ROUTE_LOCKED: &str = "Stopped while the vault is locked.";
/// The one add button of the section.
pub(crate) const ADD_DEVICE: &str = "Add an iPhone or a Mac…";
/// The button of the move row (frame 4).
pub(crate) const MOVE_APPROVALS: &str = "Move Approvals to This Mac…";
/// The hint row of a list with only this Mac (frame 7).
pub(crate) const ONLY_THIS_MAC: &str = "Add an iPhone to approve runs with Face ID.";
/// The group of the Wi-Fi iPhones (ADR 0028 stage 3).
pub(crate) const WIFI_GROUP: &str = "Wi-Fi Pairing";
/// The switch of the Wi-Fi listener.
pub(crate) const WIFI_LISTEN: &str = "Listen on This Network";
/// The title of the once-only alert of the end of Wi-Fi pairing (frame 6a, 6b).
pub(crate) const WIFI_NOTICE_TITLE: &str = "Wi-Fi Pairing Is Ending";
/// Where "Get Tailscale…" goes.
pub(crate) const TAILSCALE_DOWNLOAD: &str = "https://tailscale.com/download";
/// After this long without a bound front, "Starting…" gives way to the problem.
pub(crate) const STARTING_FOR: std::time::Duration = std::time::Duration::from_secs(15);

/// The help of the route switch (frame 3e).
const ROUTE_HELP: [&str; 4] = [
    "Your iPhone and Macs reach this Mac over Tailscale.",
    "Only devices on your tailnet can connect. Nothing opens to the internet.",
    "Each device still signs in with its own key.",
    concat!(
        "Switching needs ",
        crate::touch_id!(),
        ". It stops when the vault locks."
    ),
];
/// The help of Node Words: safety words to compare, never proof of the node (N8-7).
const WORDS_HELP: [&str; 4] = [
    "Safety words to compare: six words from this Mac's certificate.",
    "Your iPhone shows them in Settings → Devices.",
    "Other words there: revoke that iPhone and pair again.",
    "The same words are not proof of this Mac. The iPhone checks the whole certificate.",
];
/// The help of the Devices list.
const DEVICES_HELP: [&str; 4] = [
    "via your Mac: straight to this Mac over your tailnet.",
    "via Apassy relay: through apassy-relay.wyderka.cc, end-to-end encrypted.",
    "Tailnet: your own Linux node.",
    "Wi-Fi: the old pairing. It ends soon.",
];
/// The help of the Wi-Fi Pairing group (frame 6c).
const WIFI_HELP: [&str; 4] = [
    "The iPhone app now uses your tailnet or Apassy relay.",
    "Both work away from home. Wi-Fi works only on one network.",
    "Paired iPhones keep working until the removal.",
    "New Wi-Fi pairing is no longer possible.",
];

/// The group of the questions through the relay, the feed, and the other Macs (the old
/// Relay and Other Macs groups, restored inside this layout).
pub(crate) const RELAY_GROUP: &str = "Relay";
/// The switch of the questions through the relay, and its name for VoiceOver (ADR 0025
/// §3e, contract relay-questions-v1). Off by default: only a relay membership with the
/// purpose `questions` turns it on.
pub(crate) const RELAY_QUESTIONS: &str = "Send Questions Through the Relay";
pub(crate) const RELAY_QUESTIONS_ON: &str =
    "End-to-end encrypted. The relay sees no command or credential.";
pub(crate) const RELAY_QUESTIONS_OFF: &str =
    "Off. Answer on your other devices away from this network.";
pub(crate) const RELAY_QUESTIONS_NEW_TEAM: &str =
    "Approve on your iPhone on any network. No account needed.";
pub(crate) const RELAY_QUESTIONS_JOIN: &str =
    "Off. Turning it on joins this vault's questions team.";
pub(crate) const RELAY_QUESTIONS_REMOVED: &str =
    "This Mac was removed. Turning it on needs a new link.";
pub(crate) const RELAY_QUESTIONS_REMOVED_SYNC: &str =
    "This Mac was removed from the questions of this vault.";
/// The line under a Mac whose relay sync key was removed from the questions.
pub(crate) const RELAY_QUESTIONS_REMOVED_SYNC_FIX: &str =
    "Turn relay sync off, then join the vault again from another Mac.";
pub(crate) const RELAY_QUESTIONS_LOCKED: &str = "Unlock the vault to change it.";
/// The switch of the feed of the agents for the other devices of the vault (relay-feed-v1
/// section 8), and its name for VoiceOver. On by default; `ui.json` keeps it.
pub(crate) const SHOW_AGENTS: &str = "Show Agents on My Other Devices";
pub(crate) const SHOW_AGENTS_NOTE: &str = "Only this Mac changes them.";
/// The row of the other Macs of a synced vault.
pub(crate) const OTHER_MACS: &str = "Other Macs";
/// Its buttons while the vault syncs through the relay.
pub(crate) const OTHER_MACS_DEVICES: &str = "Devices…";
pub(crate) const ADD_MAC: &str = "Add a Mac…";
/// The row of frame 4d after "Later": the hosted relay kept the old entry of a move.
pub(crate) const OLD_RELAY_ENTRY: &str = "Old entry still on Apassy relay";

/// The help of the relay switch.
const RELAY_HELP: [&str; 4] = [
    "Questions also reach your other devices of this vault.",
    "The relay sees no command and no credential.",
    concat!(
        "Turning it on needs ",
        crate::touch_id!(),
        ". Off needs none."
    ),
    "Relay sync of the vault does not change.",
];
/// The help of the feed switch.
const SHOW_AGENTS_HELP: [&str; 3] = [
    "Your iPhone and your other Macs of this vault show this Mac's agents.",
    "Only this Mac changes them.",
    "Off: Apassy deletes this Mac's feed from the relay.",
];
/// The help of the other Macs row.
const OTHER_MACS_HELP: [&str; 2] = [
    "The Macs that sync this vault.",
    "Devices… lists them; Add a Mac… links one more.",
];
/// The help of the old entry row (frame 4d).
const OLD_RELAY_ENTRY_HELP: [&str; 2] = [
    "Approvals already go through this Mac.",
    "Apassy relay did not answer the removal of the old devices.",
];

// ---- The view. ----

/// Where a device reaches the approvals of this Mac: one of four words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    /// Straight to this Mac's node over the tailnet.
    Mac,
    /// Through the hosted Apassy relay.
    Relay,
    /// Through the owner's own Linux node.
    Tailnet,
    /// The old Wi-Fi pairing (ADR 0020), until W2.
    Wifi,
}

impl Route {
    pub(crate) fn words(self) -> &'static str {
        match self {
            Self::Mac => "via your Mac",
            Self::Relay => "via Apassy relay",
            Self::Tailnet => "Tailnet",
            Self::Wifi => "Wi-Fi",
        }
    }

    /// Green, grey, blue, orange.
    fn tone(self) -> Tone {
        match self {
            Self::Mac => Tone::Good,
            Self::Relay => Tone::Neutral,
            Self::Tailnet => Tone::Accent,
            Self::Wifi => Tone::Warning,
        }
    }
}

/// The kind of a device row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Mac,
    Iphone,
    Watch,
    LinuxNode,
}

impl Kind {
    pub(crate) fn words(self) -> &'static str {
        match self {
            Self::Mac => "Mac",
            Self::Iphone => "iPhone",
            Self::Watch => "Apple Watch",
            Self::LinuxNode => "Linux node",
        }
    }
}

/// What Revoke… or Details… of a row acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// This Mac: no button.
    ThisMac,
    /// A device of the questions team of the vault on this Mac's node.
    Node {
        team_id: String,
        id: u64,
        uuid: Option<String>,
    },
    /// A trusted device of a team on another relay: today's removal.
    Hosted {
        team_id: String,
        id: Option<u64>,
        uuid: String,
    },
    /// A Linux node that the vault `vault` syncs through: this Mac leaves its team.
    Linux {
        vault: String,
        team_id: String,
        device_id: u64,
        origin: String,
    },
}

/// One row of the Devices list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceEntry {
    pub(crate) name: String,
    pub(crate) kind: Kind,
    /// "Hosts approvals", "Approves runs", "Syncs Personal".
    pub(crate) roles: Vec<String>,
    pub(crate) route: Option<Route>,
    /// Unix seconds of the last contact, when the relay knows it.
    pub(crate) last_contact: Option<u64>,
    pub(crate) target: Target,
    /// The last revoke of this device failed: "Not revoked. Try Again" under the name.
    pub(crate) failed: bool,
}

impl DeviceEntry {
    /// `<Kind> · <Role>[ · <Role>]`.
    pub(crate) fn subline(&self) -> String {
        std::iter::once(self.kind.words().to_owned())
            .chain(self.roles.iter().cloned())
            .collect::<Vec<_>>()
            .join(" · ")
    }

    /// The button of the row: Revoke… for node and relay devices, Details… for a Linux
    /// node, none for this Mac.
    pub(crate) fn button(&self) -> Option<&'static str> {
        match self.target {
            Target::ThisMac => None,
            Target::Linux { .. } => Some("Details…"),
            Target::Node { .. } | Target::Hosted { .. } if self.failed => Some("Try Again"),
            Target::Node { .. } | Target::Hosted { .. } => Some("Revoke…"),
        }
    }
}

/// The tailnet address of this Mac's node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Address {
    /// The Tailscale IPv4 only.
    pub(crate) ipv4: String,
    /// The node origin, `https://100.101.7.12:8444`, for Copy.
    pub(crate) origin: String,
    pub(crate) port: u16,
    /// Six words of the pin, once the front runs.
    pub(crate) words: Option<String>,
}

/// The state of the node of this Mac on the tailnet (frame 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodeState {
    /// 3a: no Tailscale command line.
    Missing,
    /// 3b: Tailscale is not running or not signed in.
    NotConnected,
    /// 3c: the route is off.
    Off,
    /// 3f: the vault is locked; the route was on.
    Locked,
    /// The route is on: 3d (`address` `None`, "Starting…"), 1, 3e, 3g, 3h.
    On { address: Option<Address> },
}

/// A problem of a route that is on: one line, at most one button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NodeProblem {
    /// 3g: another program listens on the port. Before the first pairing the route can
    /// take the next port.
    PortTaken { port: u16, before_pairing: bool },
    /// 3h: the tailnet address is not the one that the paired devices know.
    AddressChanged,
    /// Any other failure of the start, as the node said it.
    Failed(String),
}

/// A paired Wi-Fi iPhone (ADR 0020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WifiDevice {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) paired_at: u64,
    pub(crate) last_seen_at: Option<u64>,
}

/// Which release of the end of Wi-Fi pairing this is (ADR 0028 stage 3, plan D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WifiEnd {
    /// R1: "in two versions".
    TwoVersions,
    /// R2: "in the next version".
    #[allow(dead_code)]
    NextVersion,
}

impl WifiEnd {
    /// The release of this build.
    pub(crate) const NOW: Self = Self::TwoVersions;

    pub(crate) fn line(self) -> &'static str {
        match self {
            Self::TwoVersions => "Wi-Fi pairing ends in two versions.",
            Self::NextVersion => "Wi-Fi pairing ends in the next version.",
        }
    }
}

/// The Wi-Fi Pairing group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WifiView {
    pub(crate) listening: bool,
    /// The listener is on but not running yet.
    pub(crate) starting: bool,
    /// Why the listener failed.
    pub(crate) failed: Option<String>,
    pub(crate) devices: Vec<WifiDevice>,
    pub(crate) end: WifiEnd,
}

/// The state of "Send Questions Through the Relay" for the open vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Questions {
    On,
    CanTurnOn,
    NeedsTeam,
    JoinTeam,
    /// This Mac was removed; a new link turns it on again.
    Removed,
    /// The relay sync key of this Mac was removed: the switch cannot move.
    RemovedSync,
    /// The vault is locked or not open.
    Locked,
}

impl Questions {
    /// The subline of the switch, and whether the switch can move.
    pub(crate) fn subline(self) -> (&'static str, bool) {
        match self {
            Self::On => (RELAY_QUESTIONS_ON, true),
            Self::CanTurnOn => (RELAY_QUESTIONS_OFF, true),
            Self::NeedsTeam => (RELAY_QUESTIONS_NEW_TEAM, true),
            Self::JoinTeam => (RELAY_QUESTIONS_JOIN, true),
            Self::Removed => (RELAY_QUESTIONS_REMOVED, true),
            Self::RemovedSync => (RELAY_QUESTIONS_REMOVED_SYNC, false),
            Self::Locked => (RELAY_QUESTIONS_LOCKED, false),
        }
    }
}

/// The other Macs of a synced vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtherMacsRow {
    /// "Through the Apassy relay", "Through iCloud Drive", "Removed from the relay".
    pub(crate) words: String,
    /// The vault syncs through the relay and this Mac is in its team: Devices… and Add a
    /// Mac… work.
    pub(crate) relay: bool,
}

/// The Relay group: the questions through the relay, the feed of the agents, the other
/// Macs, and the end of the free approvals (ADR 0037 D14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayView {
    pub(crate) questions: Questions,
    /// "Show Agents on My Other Devices": shown only while the questions are on.
    pub(crate) feed_shown: bool,
    pub(crate) other_macs: Option<OtherMacsRow>,
    /// The version with which the free approvals through the hosted relay end, while the
    /// questions of the vault go through it.
    pub(crate) free_end: Option<String>,
}

/// Everything that Settings > Devices shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DevicesView {
    pub(crate) node: NodeState,
    pub(crate) problem: Option<NodeProblem>,
    /// The vault is locked or not open: the switch does not move.
    pub(crate) locked: bool,
    /// The approvals go through Apassy relay and the route runs: frame 4.
    pub(crate) can_move: bool,
    pub(crate) devices: Vec<DeviceEntry>,
    /// Problems of the approvals or of the feed, one line each.
    pub(crate) notes: Vec<(String, Tone)>,
    pub(crate) wifi: Option<WifiView>,
    /// The Relay group, while a vault is open.
    pub(crate) relay: Option<RelayView>,
    /// Frame 4d after "Later": the hosted relay kept the old entry of a move.
    pub(crate) old_relay_entry: bool,
    /// Unix seconds now, for the last contact.
    pub(crate) now: u64,
}

impl DevicesView {
    /// The route switch is on.
    pub(crate) fn route_on(&self) -> bool {
        matches!(self.node, NodeState::On { .. } | NodeState::Locked)
    }

    /// The status line of the section: "Tailnet on · 6 devices", "This Mac only".
    pub(crate) fn status_line(&self) -> String {
        let count = self.devices.len();
        let devices = match count {
            0 | 1 => None,
            count => Some(format!("{count} devices")),
        };
        match (self.route_on(), devices) {
            (true, Some(devices)) => format!("Tailnet on · {devices}"),
            (true, None) => "Tailnet on · This Mac only".to_owned(),
            (false, Some(devices)) => devices,
            (false, None) => "This Mac only".to_owned(),
        }
    }
}

/// What the owner chose in the section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// The route switch moved: the owner check first.
    SetRoute(bool),
    GetTailscale,
    CheckAgain,
    UsePort(u16),
    PairAgain,
    Copy(String),
    Move,
    Add,
    /// Revoke… or Try Again of the row with this index.
    Revoke(usize),
    /// Details… of the Linux node row with this index.
    Details(usize),
    Listen(bool),
    /// Remove… of a Wi-Fi iPhone: its ID and name.
    RemoveWifi(String, String),
    ResetWifi,
    RetryWifi,
    /// "Send Questions Through the Relay" moved: on runs the owner check first.
    SetQuestions(bool),
    /// "Show Agents on My Other Devices" moved.
    ShowAgents(bool),
    /// Devices… of the other Macs: the relay sync sheet of the Macs.
    OtherMacs,
    /// Add a Mac… of the other Macs: the relay sync link.
    AddMac,
}

// ---- Words. ----

/// The last contact: "Now" under a minute, then "4 min ago", "3 h ago", "Yesterday",
/// "12 Sep".
pub(crate) fn last_contact(at: u64, now: u64) -> String {
    let age = now.saturating_sub(at);
    match age {
        0..60 => "Now".to_owned(),
        60..3_600 => format!("{} min ago", age / 60),
        3_600..86_400 => format!("{} h ago", age / 3_600),
        86_400..172_800 => "Yesterday".to_owned(),
        _ => day_month(at),
    }
}

/// "12 Sep": the UTC day and the English month abbreviation.
pub(crate) fn day_month(at: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (_, month, day) = civil_day(at);
    format!("{day} {}", MONTHS[(month - 1) as usize])
}

/// The UTC year, month (1–12), and day (1–31) of `at` (H. Hinnant's algorithm).
fn civil_day(at: u64) -> (i64, u32, u32) {
    let days = (at / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The host of an `https://host:port` origin.
pub(crate) fn origin_host(origin: &str) -> String {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin);
    let host = rest.split('/').next().unwrap_or(rest);
    match host.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host.to_owned(),
        _ => host.to_owned(),
    }
}

// ---- Drawing. ----

/// The space above a group label, as `rows::group_label`.
const LABEL_TOP: f32 = 18.0;

/// Draw the section. `notifications` draws the notification rows of the This Mac group.
pub(crate) fn draw(
    ui: &mut Ui,
    view: &DevicesView,
    notifications: impl FnOnce(&mut rows::Group<'_>),
) -> Option<Action> {
    let mut action = None;
    this_mac_group(ui, view, notifications, &mut action);
    devices_group(ui, view, &mut action);
    if let Some(relay) = &view.relay {
        relay_group(ui, relay, &mut action);
    }
    if let Some(wifi) = &view.wifi {
        action = wifi_group(ui, wifi, view.now).or(action);
    }
    action
}

/// One problem line in the warning or critical tone, with a warning glyph, and at most
/// one button on the right.
fn problem_line(
    g: &mut rows::Group<'_>,
    text: &str,
    tone: Tone,
    button: Option<&str>,
    help: Option<(&str, &[&str])>,
) -> bool {
    let mut clicked = false;
    g.row(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), rows::LINE),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                kit::paint_icon_in(ui, Icon::Warning, 13.0, tone.text());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if let Some(label) = button {
                        clicked = kit::small_button(ui, label, Style::Bordered).clicked();
                    }
                    if let Some((title, lines)) = help {
                        kit::help_button(ui, title, lines);
                    }
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        ui.add(
                            Label::new(kit::text(text, Font::Callout).color(tone.text())).wrap(),
                        );
                    });
                });
            },
        );
    });
    clicked
}

/// A row with a value and an optional small button on the right.
fn value_row(
    g: &mut rows::Group<'_>,
    label: &str,
    value: egui::RichText,
    button: Option<&str>,
) -> bool {
    let mut clicked = false;
    g.line(label, Some(value), |ui| {
        if let Some(label) = button {
            clicked = kit::small_button(ui, label, Style::Bordered).clicked();
        }
    });
    clicked
}

/// The switch row: the label and its subline on the left, the ⓘ and the switch on the
/// right.
fn switch_row(
    g: &mut rows::Group<'_>,
    title: &str,
    subline: Option<&str>,
    on: &mut bool,
    enabled: bool,
    help: Option<&[&str]>,
) {
    g.row(|ui| {
        egui::Sides::new()
            .shrink_left()
            .wrap_mode(egui::TextWrapMode::Wrap)
            .height(rows::LINE)
            .show(
                ui,
                |ui| {
                    // A title alone is centered on the switch; with a subline, the two
                    // lines are a column.
                    if let Some(subline) = subline {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(rows::label_text(title));
                            ui.add(Label::new(rows::note(subline)).wrap());
                        });
                    } else {
                        ui.label(rows::label_text(title));
                    }
                },
                |ui| {
                    ui.add_enabled_ui(enabled, |ui| kit::toggle(ui, on, title));
                    if let Some(lines) = help {
                        kit::help_button(ui, title, lines);
                    }
                },
            );
    });
}

fn this_mac_group(
    ui: &mut Ui,
    view: &DevicesView,
    notifications: impl FnOnce(&mut rows::Group<'_>),
    action: &mut Option<Action>,
) {
    rows::group(ui, Some("This Mac"), |g| {
        let (subline, enabled) = match &view.node {
            NodeState::Missing | NodeState::NotConnected => (ROUTE_OFF, false),
            NodeState::Off => (ROUTE_OFF, !view.locked),
            NodeState::Locked => (ROUTE_LOCKED, false),
            NodeState::On { .. } => (ROUTE_ON, !view.locked),
        };
        let was = view.route_on();
        let mut on = was;
        switch_row(
            g,
            ROUTE_SWITCH,
            Some(subline),
            &mut on,
            enabled,
            Some(&ROUTE_HELP),
        );
        if on != was {
            *action = Some(Action::SetRoute(on));
        }
        match &view.node {
            NodeState::Missing => {
                if problem_line(
                    g,
                    "Tailscale is not installed.",
                    Tone::Warning,
                    Some("Get Tailscale…"),
                    None,
                ) {
                    *action = Some(Action::GetTailscale);
                }
            }
            NodeState::NotConnected => {
                if problem_line(
                    g,
                    "Tailscale is not connected.",
                    Tone::Warning,
                    Some("Check Again"),
                    None,
                ) {
                    *action = Some(Action::CheckAgain);
                }
            }
            NodeState::Off => {}
            NodeState::Locked => {
                value_row(g, "Address", rows::value("Off"), None);
            }
            NodeState::On { address } => on_rows(g, view, address.as_ref(), action),
        }
        if view.can_move && matches!(view.node, NodeState::On { address: Some(_) }) {
            move_row(g, action);
        }
        if view.old_relay_entry {
            problem_line(
                g,
                OLD_RELAY_ENTRY,
                Tone::Warning,
                None,
                Some((OLD_RELAY_ENTRY, &OLD_RELAY_ENTRY_HELP)),
            );
        }
        notifications(g);
    });
}

/// The rows of a route that is on.
fn on_rows(
    g: &mut rows::Group<'_>,
    view: &DevicesView,
    address: Option<&Address>,
    action: &mut Option<Action>,
) {
    match &view.problem {
        Some(NodeProblem::PortTaken {
            port,
            before_pairing,
        }) => {
            if *before_pairing {
                let next = port.saturating_add(1);
                if problem_line(
                    g,
                    &format!("Another app uses port {port}."),
                    Tone::Warning,
                    Some(&format!("Use Port {next}")),
                    None,
                ) {
                    *action = Some(Action::UsePort(next));
                }
            } else {
                problem_line(
                    g,
                    &format!("Another app uses port {port}. Quit it."),
                    Tone::Warning,
                    None,
                    None,
                );
            }
            return;
        }
        Some(NodeProblem::Failed(text)) => {
            if problem_line(g, text, Tone::Warning, Some("Check Again"), None) {
                *action = Some(Action::CheckAgain);
            }
            return;
        }
        Some(NodeProblem::AddressChanged) | None => {}
    }
    let Some(address) = address else {
        g.row(|ui| {
            rows::one_line(ui, rows::label_text("Address").into(), None, |ui| {
                ui.label(rows::value("Starting…"));
                ui.add(egui::Spinner::new().size(12.0));
            });
        });
        return;
    };
    let mono = kit::text(&address.ipv4, Font::Mono).color(kit::palette().label);
    if value_row(g, "Address", mono, Some("Copy")) {
        *action = Some(Action::Copy(address.origin.clone()));
    }
    if view.problem == Some(NodeProblem::AddressChanged) {
        if problem_line(
            g,
            "The address changed. Paired devices must pair again.",
            Tone::Critical,
            Some("Pair Again…"),
            None,
        ) {
            *action = Some(Action::PairAgain);
        }
        return;
    }
    value_row(g, "Port", rows::value(address.port.to_string()), None);
    if let Some(words) = &address.words {
        g.line(
            "Node Words",
            Some(kit::text(words, Font::Mono).color(kit::palette().label)),
            |ui| {
                kit::help_button(ui, "Node Words", &WORDS_HELP);
            },
        );
    }
}

/// Frame 4: the approvals still go through Apassy relay.
fn move_row(g: &mut rows::Group<'_>, action: &mut Option<Action>) {
    g.row(|ui| {
        egui::Sides::new()
            .shrink_left()
            .wrap_mode(egui::TextWrapMode::Wrap)
            .height(rows::LINE)
            .show(
                ui,
                |ui| {
                    ui.horizontal_top(|ui| {
                        kit::icon_tile_sized(ui, Icon::Globe, kit::palette().accent, 22.0);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(
                                kit::medium("Approvals go through Apassy relay", Font::Body)
                                    .color(kit::palette().label),
                            );
                            ui.add(
                                Label::new(rows::note(
                                    "Move them here to keep them on your tailnet.",
                                ))
                                .wrap(),
                            );
                        });
                    });
                },
                |ui| {
                    if kit::small_button(ui, MOVE_APPROVALS, Style::Prominent).clicked() {
                        *action = Some(Action::Move);
                    }
                },
            );
    });
}

/// A group label with an ⓘ and a count on the right: "Devices ⓘ 6".
fn devices_label(ui: &mut Ui, count: usize) {
    ui.add_space(LABEL_TOP);
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.add(
            Label::new(
                kit::text("Devices", Font::Callout)
                    .variation(b"wght", 600.0)
                    .color(kit::palette().secondary),
            )
            .selectable(false),
        );
        if count > 1 {
            kit::help_button(ui, "Devices", &DEVICES_HELP);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(2.0);
            ui.label(kit::text(count.to_string(), Font::Callout).color(kit::palette().secondary));
        });
    });
    ui.add_space(6.0);
}

fn devices_group(ui: &mut Ui, view: &DevicesView, action: &mut Option<Action>) {
    devices_label(ui, view.devices.len());
    rows::group_box(ui, |g| {
        for (index, device) in view.devices.iter().enumerate() {
            if let Some(clicked) = device_row(g, device, view.now)
                && clicked
            {
                *action = Some(match device.target {
                    Target::Linux { .. } => Action::Details(index),
                    _ => Action::Revoke(index),
                });
            }
        }
        if view.devices.len() <= 1 {
            g.row(|ui| {
                ui.add(Label::new(rows::label_text(ONLY_THIS_MAC)).wrap());
            });
        }
        for (note, tone) in &view.notes {
            g.tone_row(note.as_str(), tone.text());
        }
    });
    ui.add_space(12.0);
    // One blue button for each view: the move row has it in frame 4.
    let style = if view.can_move {
        Style::Bordered
    } else {
        Style::Prominent
    };
    ui.horizontal(|ui| {
        if kit::button(ui, ADD_DEVICE, style)
            .on_hover_text("An iPhone answers the questions with Face ID, also away from home.")
            .clicked()
        {
            *action = Some(Action::Add);
        }
    });
}

/// The small tile of a device kind: a gray rounded square with its glyph.
fn device_glyph(ui: &mut Ui, kind: Kind) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();
    painter.rect_filled(rect, 7, kit::palette().fill_hover);
    let inner = Rect::from_center_size(rect.center(), Vec2::splat(17.0));
    let stroke = Stroke::new(1.4, kit::palette().label);
    match kind {
        Kind::Mac => kit::paint_icon(painter, inner, Icon::Laptop, kit::palette().label),
        Kind::LinuxNode => kit::paint_icon(painter, inner, Icon::Terminal, kit::palette().label),
        Kind::Iphone => {
            let body = Rect::from_center_size(inner.center(), Vec2::new(9.0, 15.0));
            painter.rect_stroke(body, 2.5, stroke, egui::StrokeKind::Middle);
            painter.hline(
                (body.center().x - 1.5)..=(body.center().x + 1.5),
                body.bottom() - 2.2,
                Stroke::new(1.2, kit::palette().label),
            );
        }
        Kind::Watch => {
            let face = Rect::from_center_size(inner.center(), Vec2::new(10.0, 11.0));
            painter.rect_stroke(face, 3.0, stroke, egui::StrokeKind::Middle);
            let band = |top: f32, bottom: f32| {
                Rect::from_min_max(
                    egui::pos2(face.left() + 2.0, top),
                    egui::pos2(face.right() - 2.0, bottom),
                )
            };
            painter.rect_filled(band(inner.top(), face.top()), 1, kit::palette().label);
            painter.rect_filled(band(face.bottom(), inner.bottom()), 1, kit::palette().label);
        }
    }
}

/// A route chip: the route word in the tint of its tone.
fn route_chip(ui: &mut Ui, route: Route) -> egui::Response {
    kit::cap_toned(ui, route.words(), route.tone())
}

/// One device row. `Some(true)` when its button was pressed; `None` without a button.
fn device_row(g: &mut rows::Group<'_>, device: &DeviceEntry, now: u64) -> Option<bool> {
    let mut clicked = None;
    g.row(|ui| {
        egui::Sides::new()
            .shrink_left()
            .wrap_mode(egui::TextWrapMode::Truncate)
            .height(rows::LINE)
            .show(
                ui,
                |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    device_glyph(ui, device.kind);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            ui.add(Label::new(rows::label_text(&device.name)).truncate());
                            if device.target == Target::ThisMac {
                                kit::cap_toned(ui, "This Mac", Tone::Neutral);
                            }
                        });
                        if device.failed {
                            ui.label(
                                kit::text("Not revoked. Try Again", Font::Callout)
                                    .color(Tone::Critical.text()),
                            );
                        } else {
                            ui.add(Label::new(rows::note(&device.subline())).truncate());
                        }
                    });
                },
                |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    if let Some(label) = device.button() {
                        let button = kit::small_button(ui, label, Style::Bordered);
                        let spoken = format!("{label} {}", device.name);
                        ui.ctx()
                            .accesskit_node_builder(button.id, |node| node.set_label(spoken));
                        clicked = Some(button.clicked());
                    }
                    if let Some(at) = device.last_contact {
                        ui.label(rows::value(last_contact(at, now)).size(12.0));
                    }
                    if let Some(route) = device.route {
                        route_chip(ui, route);
                    }
                },
            );
    });
    clicked
}

/// The Relay group: "Send Questions Through the Relay" with its ⓘ, "Show Agents on My
/// Other Devices" while it is on, the other Macs of a synced vault, and the end of the
/// free approvals through Apassy relay.
fn relay_group(ui: &mut Ui, relay: &RelayView, action: &mut Option<Action>) {
    rows::group(ui, Some(RELAY_GROUP), |g| {
        let was = relay.questions == Questions::On;
        let (subline, enabled) = relay.questions.subline();
        let mut on = was;
        switch_row(
            g,
            RELAY_QUESTIONS,
            Some(subline),
            &mut on,
            enabled,
            Some(&RELAY_HELP),
        );
        if on != was {
            *action = Some(Action::SetQuestions(on));
        }
        if relay.questions == Questions::RemovedSync {
            g.note_row(RELAY_QUESTIONS_REMOVED_SYNC_FIX);
        }
        if was {
            let mut shown = relay.feed_shown;
            switch_row(
                g,
                SHOW_AGENTS,
                Some(SHOW_AGENTS_NOTE),
                &mut shown,
                true,
                Some(&SHOW_AGENTS_HELP),
            );
            if shown != relay.feed_shown {
                *action = Some(Action::ShowAgents(shown));
            }
        }
        if let Some(others) = &relay.other_macs {
            g.line(OTHER_MACS, Some(rows::value(&others.words)), |ui| {
                if others.relay {
                    if kit::small_button(ui, ADD_MAC, Style::Bordered).clicked() {
                        *action = Some(Action::AddMac);
                    }
                    if kit::small_button(ui, OTHER_MACS_DEVICES, Style::Bordered).clicked() {
                        *action = Some(Action::OtherMacs);
                    }
                }
                kit::help_button(ui, OTHER_MACS, &OTHER_MACS_HELP);
            });
        }
        if let Some(version) = &relay.free_end {
            let line = free_end_line(version);
            let help = free_end_help(version);
            let help: Vec<&str> = help.iter().map(String::as_str).collect();
            problem_line(g, &line, Tone::Warning, None, Some((RELAY_GROUP, &help)));
        }
    });
}

/// The warning line of the end of the free approvals (ADR 0037 D14).
pub(crate) fn free_end_line(version: &str) -> String {
    format!("Free approvals through Apassy relay end with Apassy {version}.")
}

/// Its help: the notice of plan s7 unit N1, a line each.
fn free_end_help(version: &str) -> [String; 3] {
    [
        format!("Free approvals through apassy-relay.wyderka.cc end with Apassy {version}."),
        "Keep them free over Tailscale with this Mac as the node.".to_owned(),
        "Or use Apassy Connect (paid).".to_owned(),
    ]
}

/// The Wi-Fi Pairing group (frame 6c, 6d). Shown only while a Wi-Fi iPhone is paired.
pub(crate) fn wifi_group(ui: &mut Ui, wifi: &WifiView, now: u64) -> Option<Action> {
    let mut action = None;
    rows::group(ui, Some(WIFI_GROUP), |g| {
        problem_line(
            g,
            wifi.end.line(),
            Tone::Warning,
            None,
            Some((WIFI_GROUP, &WIFI_HELP)),
        );
        let mut on = wifi.listening;
        let subline = wifi.starting.then_some("Starting");
        switch_row(g, WIFI_LISTEN, subline, &mut on, true, None);
        if on != wifi.listening {
            action = Some(Action::Listen(on));
        }
        if let Some(message) = &wifi.failed
            && problem_line(g, message, Tone::Critical, Some("Try Again"), None)
        {
            action = Some(Action::RetryWifi);
        }
        for device in &wifi.devices {
            let entry = DeviceEntry {
                name: device.name.clone(),
                kind: Kind::Iphone,
                roles: Vec::new(),
                route: Some(Route::Wifi),
                last_contact: device.last_seen_at,
                target: Target::ThisMac,
                failed: false,
            };
            g.row(|ui| {
                egui::Sides::new()
                    .shrink_left()
                    .wrap_mode(egui::TextWrapMode::Truncate)
                    .height(rows::LINE)
                    .show(
                        ui,
                        |ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            device_glyph(ui, Kind::Iphone);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 1.0;
                                ui.add(Label::new(rows::label_text(&entry.name)).truncate());
                                ui.label(rows::note(&format!(
                                    "Paired {}",
                                    day_month(device.paired_at)
                                )));
                            });
                        },
                        |ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            let button = kit::small_button(ui, "Remove…", Style::Bordered);
                            let spoken = format!("Remove {}", device.name);
                            ui.ctx()
                                .accesskit_node_builder(button.id, |node| node.set_label(spoken));
                            if button.clicked() {
                                action = Some(Action::RemoveWifi(
                                    device.id.clone(),
                                    device.name.clone(),
                                ));
                            }
                            if let Some(at) = entry.last_contact {
                                ui.label(rows::value(last_contact(at, now)).size(12.0));
                            }
                            route_chip(ui, Route::Wifi);
                        },
                    );
            });
        }
        let reset = g
            .clickable_row("Reset Pairing…", |ui| {
                ui.label(kit::text("Reset Pairing…", Font::Body).color(Tone::Critical.text()));
            })
            .on_hover_text(
                "Removes every iPhone and makes a new certificate, so an iPhone that pinned the old one cannot connect.",
            );
        if reset.clicked() {
            action = Some(Action::ResetWifi);
        }
    });
    action
}

// ---- Sheets. ----

/// What a confirmation sheet gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice {
    Cancel,
    Confirm,
    /// The second button of the Wi-Fi notice: "Open Devices".
    Open,
}

/// A watch of the iPhone in the revoke sheet, and whether it goes too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchChoice {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) revoke: bool,
}

/// A sheet of the section, over the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DevicesSheet {
    /// Frame 5a and 5b: "Revoke <Device>?".
    Revoke {
        device: DeviceEntry,
        /// The vault that the device syncs, for a Mac.
        vault: Option<String>,
        watches: Vec<WatchChoice>,
    },
    /// Details… of a Linux node, with Revoke.
    Linux { device: DeviceEntry, vault: String },
    /// Frame 6a and 6b, once: the end of Wi-Fi pairing.
    WifiNotice { tailnet: bool },
}

/// Frame 5a and 5b. Revoke is the destructive button (red text); Cancel is the default,
/// so Return never revokes.
pub(crate) fn revoke_sheet(
    ctx: &egui::Context,
    device: &DeviceEntry,
    vault: Option<&str>,
    watches: &mut [WatchChoice],
) -> (Option<Choice>, bool) {
    let mut choice = None;
    let response = kit::sheet(ctx, "devices-revoke", 400.0, |ui| {
        let title = format!("Revoke {}?", device.name);
        let (lead, note) = match (device.kind, vault) {
            (Kind::Mac, Some(vault)) => (
                format!("It stops syncing {vault} and seeing approvals."),
                "Its copy of the vault stays on that Mac.",
            ),
            _ => (
                "It can no longer see or answer questions.".to_owned(),
                "To use it again, pair it again.",
            ),
        };
        kit::sheet_title(ui, &title, Some(&lead));
        if !watches.is_empty() {
            rows::group(ui, None, |g| {
                for watch in watches.iter_mut() {
                    g.row(|ui| {
                        ui.checkbox(
                            &mut watch.revoke,
                            rows::label_text(&format!("Also revoke {}", watch.name)),
                        );
                    });
                }
            });
            ui.add_space(8.0);
        }
        kit::note(ui, note);
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if kit::button(ui, "Revoke", Style::Destructive).clicked() {
                    choice = Some(Choice::Confirm);
                }
                if kit::alert_cancel(ui).clicked() {
                    choice = Some(Choice::Cancel);
                }
            },
        );
    });
    (choice, response.escape)
}

/// Details… of a Linux node: what it is, and Revoke (this Mac leaves its team).
pub(crate) fn linux_sheet(
    ctx: &egui::Context,
    device: &DeviceEntry,
    vault: &str,
    origin: &str,
) -> (Option<Choice>, bool) {
    let mut choice = None;
    let response = kit::sheet(ctx, "devices-linux", 420.0, |ui| {
        kit::sheet_title(ui, &device.name, Some(&device.subline()));
        rows::group(ui, None, |g| {
            g.labeled("Kind", rows::value(Kind::LinuxNode.words()));
            g.line("Route", None, |ui| {
                route_chip(ui, Route::Tailnet);
            });
            g.labeled(
                "Address",
                kit::text(origin_host(origin), Font::Mono).color(kit::palette().label),
            );
        });
        ui.add_space(8.0);
        kit::note(
            ui,
            format!("Revoke: this Mac stops syncing {vault} through it. Its copy stays there."),
        );
        ui.add_space(8.0);
        let mut revoke = false;
        let mut done = false;
        kit::sheet_buttons(
            ui,
            |ui| revoke = kit::button(ui, "Revoke…", Style::Destructive).clicked(),
            |ui| done = kit::alert_default_button(ui, "Done").clicked(),
        );
        if revoke {
            choice = Some(Choice::Confirm);
        } else if done {
            choice = Some(Choice::Cancel);
        }
    });
    (choice, response.escape)
}

/// Frame 6a (the route on) and 6b (no route): once, after the update. Either button
/// dismisses it for good.
pub(crate) fn wifi_notice(ctx: &egui::Context, tailnet: bool) -> (Option<Choice>, bool) {
    let mut choice = None;
    let response = kit::sheet(ctx, "devices-wifi-notice", 340.0, |ui| {
        ui.vertical_centered(|ui| {
            kit::paint_icon_in(ui, Icon::Warning, 30.0, Tone::Warning.mark());
            ui.add_space(6.0);
            ui.label(kit::text(WIFI_NOTICE_TITLE, Font::Title3).color(kit::palette().label));
            ui.add_space(4.0);
            let way = if tailnet {
                "The iPhone app now reaches this Mac through your tailnet."
            } else {
                "The iPhone app now reaches this Mac through Apassy relay."
            };
            kit::paragraph(ui, way, Font::Callout, kit::palette().secondary);
            kit::paragraph(
                ui,
                WifiEnd::NOW.line(),
                Font::Callout,
                kit::palette().secondary,
            );
        });
        ui.add_space(10.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if kit::button(ui, "Open Devices", Style::Prominent).clicked() {
                    choice = Some(Choice::Open);
                }
                if kit::button(ui, "OK", Style::Bordered).clicked() {
                    choice = Some(Choice::Cancel);
                }
            },
        );
    });
    (choice, response.escape)
}

// ---- Frames 2 and 4b–4d: the add and move sheets. ----
//
// The sheet of "Add an iPhone or a Mac…" and of "Move Approvals to This Mac…" is the
// questions mode of "Add a device…" of relay sync (`sync/relay.rs`); these functions draw
// its steps inside it, with the exact texts of the mockup, and the demo build draws them
// from fixtures.

pub(crate) const ADD_TITLE: &str = "Add a Device";
pub(crate) const ADD_LEAD: &str = "Scan with the Apassy app on the iPhone.";
pub(crate) const LINK_EXPIRED: &str = "The link expired.";
pub(crate) const PASTE_ON_MAC: &str = "On a Mac, paste the link instead.";
pub(crate) const NEW_LINK: &str = "New Link";
pub(crate) const EXPIRES_IN: &str = "Expires In";
pub(crate) const ADDED_LEAD: &str = "It approves runs through this Mac.";
/// The lead of 2c for an Apple Watch: it cannot approve runs (ADR 0039).
pub(crate) const ADDED_WATCH_LEAD: &str = "It allows access requests once, on a wrist.";
pub(crate) const ADDED_TAILSCALE: &str = "The iPhone needs Tailscale on to reach this Mac.";
pub(crate) const MOVE_TITLE: &str = "Move Approvals to This Mac";
pub(crate) const MOVE_LEAD: &str = "Your iPhone pairs again, with this Mac.";
pub(crate) const MOVE_STEP_TEAM: &str = "Approvals team made here";
pub(crate) const MOVE_STEP_WORDS: &str = "Then check the words on both.";
pub(crate) const MOVE_STEP_REMOVE: &str = "Remove from Apassy relay";
pub(crate) const MOVED_TITLE: &str = "Approvals Moved";
pub(crate) const MOVED_LEAD: &str = "Questions now go through this Mac.";
pub(crate) const MOVED_REMOVED: &str = "Removed from Apassy relay";
pub(crate) const OLD_ENTRY_TITLE: &str = "Old Entry Still on Relay";
pub(crate) const OLD_ENTRY_LEAD: &str = "Approvals already use this Mac.";
pub(crate) const OLD_ENTRY_NOTE: &str = "Apassy relay did not answer the removal.";

/// "Rafal's iPhone Wants to Join".
pub(crate) fn join_title(name: &str) -> String {
    format!("{name} Wants to Join")
}

/// "Confirm only if the iPhone shows these words." ("the Mac" for a Mac; a watch pairs
/// from the iPhone).
pub(crate) fn join_lead(kind: Kind) -> String {
    let device = match kind {
        Kind::Mac | Kind::LinuxNode => "Mac",
        Kind::Iphone | Kind::Watch => "iPhone",
    };
    format!("Confirm only if the {device} shows these words.")
}

/// "Rafal's iPhone Added".
pub(crate) fn added_title(name: &str) -> String {
    format!("{name} Added")
}

/// "Scan with Rafal's iPhone".
pub(crate) fn move_scan(iphone: &str) -> String {
    format!("Scan with {iphone}")
}

/// "Pair Rafal's Apple Watch again from the iPhone."
pub(crate) fn pair_watch_again(watch: &str) -> String {
    format!("Pair {watch} again from the iPhone.")
}

/// The countdown of "Expires In": "9:41".
pub(crate) fn expires_in(seconds: u64) -> String {
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

/// The link field: the origin and "/link#…"; Copy copies the whole link.
pub(crate) fn shown_link(link: &str) -> String {
    match link.split_once('#') {
        Some((before, _)) => format!("{before}#…"),
        None => link.to_owned(),
    }
}

/// What the owner chose in a step of the add or move sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepChoice {
    Copy,
    NewLink,
    Cancel,
    Refuse,
    Confirm,
    Done,
    Later,
    TryAgain,
}

/// The link of frame 2a and of step 2 of 4b.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkStep {
    /// Where the device goes: "via your Mac" with the route on, else "via Apassy relay".
    pub(crate) route: Route,
    /// The link field, for a link that may go to the pasteboard (a node link). `None`:
    /// no field, no Copy, and no "On a Mac, paste the link instead." (hosted Connect
    /// never copies its capability).
    pub(crate) shown: Option<String>,
    /// Seconds until the link expires; `None` while the link is made.
    pub(crate) seconds_left: Option<u64>,
}

impl LinkStep {
    pub(crate) fn expired(&self) -> bool {
        self.seconds_left == Some(0)
    }
}

/// The step of the move sheet (frame 4b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MovePhase {
    /// Step 2: the iPhone scans; Cancel deletes the new node team.
    Scan,
    /// Step 3: the join was confirmed; the old devices leave Apassy relay. No Cancel.
    Removing,
}

/// The route chip, on its own line.
fn route_line(ui: &mut Ui, route: Route) {
    ui.horizontal(|ui| {
        route_chip(ui, route);
    });
}

/// Frame 2a: "Add a Device", the QR code, the link, "Expires In", and Cancel; expired,
/// "The link expired." and New Link only. `extra` draws the progress or the error of
/// the sheet above the buttons.
pub(crate) fn link_step(
    ui: &mut Ui,
    step: &LinkStep,
    qr: impl FnOnce(&mut Ui),
    extra: impl FnOnce(&mut Ui),
) -> Option<StepChoice> {
    let mut choice = None;
    let expired = step.expired();
    kit::sheet_title(
        ui,
        ADD_TITLE,
        Some(if expired { LINK_EXPIRED } else { ADD_LEAD }),
    );
    let shows_qr = !expired && step.seconds_left.is_some();
    if !shows_qr {
        route_line(ui, step.route);
    }
    ui.add_space(8.0);
    if shows_qr {
        // The route chip sits under the QR code, centered (frame 2a).
        ui.vertical_centered(|ui| {
            qr(ui);
            ui.add_space(6.0);
            route_chip(ui, step.route);
        });
        ui.add_space(10.0);
        rows::group(ui, None, |g| {
            if let Some(shown) = &step.shown {
                g.line(
                    "Link",
                    Some(kit::text(shown, Font::Mono).color(kit::palette().label)),
                    |ui| {
                        if kit::small_button(ui, "Copy", Style::Bordered).clicked() {
                            choice = Some(StepChoice::Copy);
                        }
                    },
                );
            }
            if let Some(seconds) = step.seconds_left {
                g.labeled(EXPIRES_IN, rows::value(expires_in(seconds)));
            }
        });
        if step.shown.is_some() {
            ui.add_space(6.0);
            kit::note(ui, PASTE_ON_MAC);
        }
    }
    extra(ui);
    ui.add_space(8.0);
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if expired {
                if kit::button(ui, NEW_LINK, Style::Prominent).clicked() {
                    choice = Some(StepChoice::NewLink);
                }
            } else if kit::alert_cancel(ui).clicked() {
                choice = Some(StepChoice::Cancel);
            }
        },
    );
    choice
}

/// The safety words, large, in a box. One text, so that VoiceOver reads them in order.
fn big_words(ui: &mut Ui, words: &str) {
    ui.add_space(6.0);
    ui.vertical_centered(|ui| {
        egui::Frame::new()
            .fill(kit::palette().window)
            .stroke(Stroke::new(0.5, kit::palette().border))
            .corner_radius(8)
            .inner_margin(egui::Margin::symmetric(14, 6))
            .show(ui, |ui| {
                ui.label(
                    kit::text(words, Font::Title)
                        .variation(b"wght", 600.0)
                        .color(kit::palette().label),
                );
            });
    });
    ui.add_space(10.0);
}

/// Frame 2b: "<Device> Wants to Join", the two safety words, Kind and Route, Refuse and
/// Confirm…. `extra` draws a note under the rows (the limits of an Apple Watch).
pub(crate) fn join_step(
    ui: &mut Ui,
    name: &str,
    kind: Kind,
    words: &str,
    route: Route,
    enabled: bool,
    extra: impl FnOnce(&mut Ui),
) -> Option<StepChoice> {
    kit::sheet_title(ui, &join_title(name), Some(&join_lead(kind)));
    big_words(ui, words);
    rows::group(ui, None, |g| {
        g.labeled("Kind", rows::value(kind.words()));
        g.line("Route", None, |ui| {
            route_chip(ui, route);
        });
    });
    extra(ui);
    ui.add_space(8.0);
    let mut refuse = false;
    let mut confirm = false;
    ui.add_enabled_ui(enabled, |ui| {
        kit::sheet_buttons(
            ui,
            |ui| refuse = kit::button(ui, "Refuse", Style::Destructive).clicked(),
            |ui| confirm = kit::button(ui, "Confirm…", Style::Prominent).clicked(),
        );
    });
    if confirm {
        Some(StepChoice::Confirm)
    } else if refuse {
        Some(StepChoice::Refuse)
    } else {
        None
    }
}

/// The centred head of a result: a glyph, the title, and its lines.
fn result_head(ui: &mut Ui, icon: Icon, tone: Tone, title: &str, lines: &[(&str, bool)]) {
    ui.vertical_centered(|ui| {
        ui.add_space(6.0);
        kit::paint_icon_in(ui, icon, 30.0, tone.mark());
        ui.add_space(6.0);
        ui.label(kit::text(title, Font::Title3).color(kit::palette().label));
        ui.add_space(4.0);
        for (line, secondary) in lines {
            let color = if *secondary {
                kit::palette().secondary
            } else {
                kit::palette().label
            };
            kit::paragraph(ui, *line, Font::Callout, color);
        }
    });
    ui.add_space(10.0);
}

/// Frame 2c: "<Device> Added", what it does, and for a device of this Mac's node that it
/// needs Tailscale. `extra` draws the question about an older device of the same kind.
pub(crate) fn added_step(
    ui: &mut Ui,
    name: &str,
    watch: bool,
    node: bool,
    extra: impl FnOnce(&mut Ui),
) -> Option<StepChoice> {
    let mut choice = None;
    let lead = if watch { ADDED_WATCH_LEAD } else { ADDED_LEAD };
    let mut lines = vec![(lead, false)];
    if node {
        lines.push((ADDED_TAILSCALE, true));
    }
    result_head(
        ui,
        Icon::CheckCircle,
        Tone::Good,
        &added_title(name),
        &lines,
    );
    extra(ui);
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if kit::button(ui, "Done", Style::Prominent).clicked() {
                choice = Some(StepChoice::Done);
            }
        },
    );
    choice
}

/// One step of the move: a numbered circle (a check when done), its title, its line.
fn move_step_row(g: &mut rows::Group<'_>, number: u8, title: &str, line: Option<&str>, state: i8) {
    g.row(|ui| {
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
            let painter = ui.painter();
            let fill = match state {
                ..0 => kit::palette().fill_hover,
                0 => kit::palette().accent,
                _ => Tone::Good.mark(),
            };
            painter.circle_filled(rect.center(), 9.0, fill);
            if state > 0 {
                let inner = Rect::from_center_size(rect.center(), Vec2::splat(10.0));
                kit::paint_icon(painter, inner, Icon::Check, kit::palette().on_accent);
            } else {
                let color = if state == 0 {
                    kit::palette().on_accent
                } else {
                    kit::palette().secondary
                };
                painter.text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    number.to_string(),
                    egui::FontId::proportional(10.5),
                    color,
                );
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                let text = if state < 0 {
                    kit::text(title, Font::Body).color(kit::palette().secondary)
                } else {
                    kit::medium(title, Font::Body).color(kit::palette().label)
                };
                ui.label(text);
                if let Some(line) = line {
                    ui.label(rows::note(line));
                }
            });
            if state == 0 && number == 3 {
                ui.add(egui::Spinner::new().size(12.0));
            }
        });
    });
}

/// Frame 4b: "Move Approvals to This Mac", the three steps, the QR code while the iPhone
/// scans, the route chip, and Cancel before the join (none after it). An expired link
/// shows "The link expired." and New Link.
pub(crate) fn move_step(
    ui: &mut Ui,
    iphone: &str,
    phase: MovePhase,
    link: Option<&LinkStep>,
    qr: impl FnOnce(&mut Ui),
    extra: impl FnOnce(&mut Ui),
) -> Option<StepChoice> {
    let mut choice = None;
    kit::sheet_title(ui, MOVE_TITLE, Some(MOVE_LEAD));
    let scanning = phase == MovePhase::Scan;
    rows::group(ui, None, |g| {
        move_step_row(g, 1, MOVE_STEP_TEAM, None, 1);
        move_step_row(
            g,
            2,
            &move_scan(iphone),
            scanning.then_some(MOVE_STEP_WORDS),
            if scanning { 0 } else { 1 },
        );
        move_step_row(g, 3, MOVE_STEP_REMOVE, None, if scanning { -1 } else { 0 });
    });
    ui.add_space(10.0);
    let expired = link.is_some_and(LinkStep::expired);
    let shows_qr = scanning && !expired && link.is_some_and(|link| link.seconds_left.is_some());
    if shows_qr {
        // The route chip sits under the QR code, centered (frame 4b).
        ui.vertical_centered(|ui| {
            qr(ui);
            ui.add_space(6.0);
            route_chip(ui, Route::Mac);
        });
        ui.add_space(8.0);
    }
    if expired {
        kit::note(ui, LINK_EXPIRED);
    }
    if !shows_qr {
        route_line(ui, Route::Mac);
    }
    extra(ui);
    ui.add_space(8.0);
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if !scanning {
                return;
            }
            if expired {
                if kit::button(ui, NEW_LINK, Style::Prominent).clicked() {
                    choice = Some(StepChoice::NewLink);
                }
            } else if kit::alert_cancel(ui).clicked() {
                choice = Some(StepChoice::Cancel);
            }
        },
    );
    choice
}

/// Frame 4c: "Approvals Moved", each device that joined with its route, "Removed from
/// Apassy relay" when the old devices left it, and a line for each watch that must pair
/// again.
pub(crate) fn moved_step(
    ui: &mut Ui,
    joined: &[String],
    removed: bool,
    watches: &[String],
) -> Option<StepChoice> {
    let mut choice = None;
    result_head(
        ui,
        Icon::CheckCircle,
        Tone::Good,
        MOVED_TITLE,
        &[(MOVED_LEAD, false)],
    );
    let ok = |ui: &mut Ui| {
        kit::paint_icon_in(ui, Icon::CheckCircle, 14.0, Tone::Good.mark());
    };
    rows::group(ui, None, |g| {
        for name in joined {
            g.row(|ui| {
                egui::Sides::new().height(rows::LINE).show(
                    ui,
                    |ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ok(ui);
                        ui.label(rows::label_text(name));
                    },
                    |ui| {
                        route_chip(ui, Route::Mac);
                    },
                );
            });
        }
        if removed {
            g.row(|ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ok(ui);
                    ui.label(rows::label_text(MOVED_REMOVED));
                });
            });
        }
    });
    for watch in watches {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            kit::paint_icon_in(ui, Icon::Info, 13.0, Tone::Accent.text());
            ui.add(
                Label::new(
                    kit::text(pair_watch_again(watch), Font::Callout).color(Tone::Accent.text()),
                )
                .wrap(),
            );
        });
    }
    ui.add_space(8.0);
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if kit::button(ui, "Done", Style::Prominent).clicked() {
                choice = Some(StepChoice::Done);
            }
        },
    );
    choice
}

/// Frame 4d: the hosted relay did not answer the removal of the old devices. Later keeps
/// the row "Old entry still on Apassy relay" in the This Mac group. Try Again shows only
/// with `retry`: a move that ended keeps no hosted team to ask again.
pub(crate) fn old_entry_step(ui: &mut Ui, retry: bool) -> Option<StepChoice> {
    let mut choice = None;
    result_head(
        ui,
        Icon::Warning,
        Tone::Warning,
        OLD_ENTRY_TITLE,
        &[(OLD_ENTRY_LEAD, false), (OLD_ENTRY_NOTE, true)],
    );
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if retry && kit::button(ui, "Try Again", Style::Prominent).clicked() {
                choice = Some(StepChoice::TryAgain);
            }
            let later = if retry {
                kit::button(ui, "Later", Style::Bordered)
            } else {
                kit::button(ui, "Later", Style::Prominent)
            };
            if later.clicked() {
                choice = Some(StepChoice::Later);
            }
        },
    );
    choice
}

/// The state of the section in the window.
#[derive(Default)]
pub(crate) struct State {
    /// The sheet of the section, over the window.
    pub(crate) sheet: Option<DevicesSheet>,
    /// The copy of the node status, read on a worker thread.
    #[cfg(feature = "vault")]
    pub(crate) cache: NodeCache,
    /// The vault session in which the Wi-Fi notice was considered last.
    #[cfg(feature = "vault")]
    pub(crate) notice_epoch: Option<[u8; 32]>,
    /// The names of devices whose last revoke failed.
    #[cfg(feature = "vault")]
    pub(crate) failed: std::collections::BTreeSet<String>,
    /// The demo build: the mockup frame that the section shows.
    #[cfg(not(feature = "vault"))]
    pub(crate) demo: super::demo::DevicesFrame,
}

/// Draw the sheets of the section and the once-only Wi-Fi notice. The window calls it
/// in each frame, after the page and before the other sheets.
pub(super) fn overlays(app: &mut crate::desktop::DesktopApp, ctx: &egui::Context) {
    #[cfg(feature = "vault")]
    live::overlays(app, ctx);
    #[cfg(not(feature = "vault"))]
    super::demo::devices_overlays(app, ctx);
}

#[cfg(feature = "vault")]
pub(super) use live::{NodeCache, section, status_line};

/// The vault build: the view from the vault, the node cache, and the owner check.
#[cfg(feature = "vault")]
mod live {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use eframe::egui;

    use super::super::sync::SyncSheet;
    use super::{
        Action, Address, Choice, DeviceEntry, DevicesSheet, DevicesView, Kind, NodeProblem,
        NodeState, Questions, Route, Target, WatchChoice,
    };
    use crate::broker::approvals::{OwnerAction, OwnerProof};
    use crate::desktop::DesktopApp;
    use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
    use crate::node::NodeStatus;
    use crate::node::funnel::Tailscale;
    use crate::relay::membership::{
        FREE_RELAY_PATHS_END_VERSION, QuestionsAvailability, questions_availability,
        questions_membership, this_device,
    };
    use crate::vault::TrustedDeviceKind;

    /// While Settings > Devices shows, the node status is read again this often (on a
    /// worker thread: it runs the Tailscale command line).
    pub(crate) const READ_EVERY: Duration = Duration::from_secs(10);
    /// The words of a start that failed because the port is taken (`tailnet_port_taken`).
    const PORT_TAKEN: &str = "on the tailnet address of this Mac is taken";

    /// The node status as the last read on a worker thread saw it. The section draws this
    /// copy; a frame never runs the Tailscale command line.
    #[derive(Default)]
    pub(crate) struct NodeCache {
        /// `None` until the first read ends.
        pub(crate) status: Option<NodeStatus>,
        reading: Option<Task<NodeStatus>>,
        read_at: Option<Instant>,
        /// A change of the owner: read again at once.
        pub(crate) stale: bool,
        /// How many reads started (a test counts them).
        pub(crate) reads: u64,
        /// Since when the route is on without a bound front.
        starting_since: Option<Instant>,
        /// The route switch was on in the last unlocked read.
        last_on: bool,
        /// A change of the route or a revoke on its way.
        call: Option<Task<Result<String, (String, String)>>>,
        /// Wakes the window when a read or a call ends.
        repaint: Option<egui::Context>,
    }

    impl NodeCache {
        /// Read again at the next frame.
        pub(crate) fn invalidate(&mut self) {
            self.stale = true;
        }
    }

    impl DesktopApp {
        /// Read the node status again when the copy is older than [`READ_EVERY`] or a
        /// change made it stale, on a worker thread; take the result of a read that
        /// ended. The section calls it each frame: a frame reads only memory.
        pub(crate) fn poll_devices(&mut self, ctx: &egui::Context) {
            self.poll_devices_call();
            let Some(node) = self.cloud_node() else {
                return;
            };
            let cache = &mut self.ui.devices.cache;
            if cache.repaint.is_none() {
                cache.repaint = Some(ctx.clone());
            }
            if let Some(task) = &cache.reading {
                match task.poll() {
                    TaskPoll::Waiting => return,
                    TaskPoll::Done(status) => {
                        if status.tailnet.on || status.route_on {
                            cache.last_on = status.tailnet.on;
                        } else if self.owner_ui.session.epoch().is_some() {
                            cache.last_on = false;
                        }
                        cache.status = Some(status);
                    }
                    TaskPoll::Lost => {}
                }
                cache.reading = None;
                cache.read_at = Some(Instant::now());
            }
            let due = cache.stale || cache.read_at.is_none_or(|at| at.elapsed() >= READ_EVERY);
            if !due {
                if let Some(at) = cache.read_at {
                    ctx.request_repaint_after(READ_EVERY.saturating_sub(at.elapsed()));
                }
                return;
            }
            cache.stale = false;
            cache.reads += 1;
            let vault = self.owner_ui.session.shared_vault();
            cache.reading = Some(Task::spawn(Some(ctx.clone()), move || node.status(&vault)));
        }

        /// The end of a change of the route or of a revoke.
        fn poll_devices_call(&mut self) {
            let cache = &mut self.ui.devices.cache;
            let Some(task) = &cache.call else {
                return;
            };
            let done = match task.poll() {
                TaskPoll::Waiting => return,
                TaskPoll::Done(done) => Some(done),
                TaskPoll::Lost => None,
            };
            cache.call = None;
            cache.stale = true;
            match done {
                Some(Ok(message)) => {
                    self.node_changed();
                    self.set_ok(message);
                }
                Some(Err((name, message))) => {
                    if !name.is_empty() {
                        self.ui.devices.failed.insert(name);
                    }
                    self.node_changed();
                    self.set_err(message);
                }
                None => self.set_err("The node did not answer. Nothing changed."),
            }
        }

        /// After the owner check of the route switch (`OwnerRequest::SetTailnetRoute`):
        /// the setting on its own thread, then the node starts or stops at the next
        /// comparison.
        pub(crate) fn devices_set_route(&mut self, on: bool, proof: OwnerProof) {
            let Some(epoch) = self.owner_ui.session.epoch() else {
                return self.set_err("Unlock the vault first.");
            };
            if proof
                .check(&OwnerAction::SetTailnetRoute { on }, &epoch)
                .is_err()
            {
                return self.set_err("The owner check did not match. Nothing changed.");
            }
            let Some(node) = self.cloud_node() else {
                return self.set_err("This build has no node. Nothing changed.");
            };
            let vault = self.owner_ui.session.shared_vault();
            let repaint = self.ui.devices.cache.repaint.clone();
            self.ui.devices.cache.call = Some(Task::spawn(repaint, move || {
                node.set_tailnet(&vault, on)
                    .map(|()| {
                        if on {
                            "This Mac is reachable on your tailnet.".to_owned()
                        } else {
                            "This Mac is off your tailnet. Approvals go through Apassy relay."
                                .to_owned()
                        }
                    })
                    .map_err(|error| (String::new(), error.message))
            }));
            self.ui.devices.cache.starting_since = on.then(Instant::now);
        }

        /// After the owner check of a revoke (`OwnerRequest::RevokeNodeDevice`): a device
        /// of the node team on its own thread, a device of another relay with today's
        /// removal, or this Mac leaves a Linux node.
        pub(crate) fn devices_revoke(&mut self, request: &RevokeRequest, proof: OwnerProof) {
            let Some(epoch) = self.owner_ui.session.epoch() else {
                return self.set_err("Unlock the vault first.");
            };
            if proof.check(&request.action(), &epoch).is_err() {
                return self.set_err("The owner check did not match. Nothing was revoked.");
            }
            drop(proof);
            self.ui.devices.failed.remove(&request.device_name);
            let name = request.device_name.clone();
            if let Some(vault_id) = &request.linux_vault {
                return match self.relay_turn_off(vault_id, false, None) {
                    Ok(()) => self.set_ok(format!("{name} revoked")),
                    Err(message) => {
                        self.ui.devices.failed.insert(name);
                        self.set_err(message);
                    }
                };
            }
            if !request.node {
                for (_, uuid) in &request.devices {
                    if !uuid.is_empty() {
                        self.questions_remove_device(uuid);
                    }
                }
                self.ui.devices.cache.stale = true;
                return self.set_ok(format!("{name} revoked"));
            }
            let Some(node) = self.cloud_node() else {
                return self.set_err("This build has no node. Nothing was revoked.");
            };
            let vault = self.owner_ui.session.shared_vault();
            let devices = request.devices.clone();
            let repaint = self.ui.devices.cache.repaint.clone();
            self.ui.devices.cache.call = Some(Task::spawn(repaint, move || {
                for (id, uuid) in devices {
                    node.revoke_device(&vault, id, &uuid)
                        .map_err(|error| (name.clone(), error.message))?;
                }
                Ok(format!("{name} revoked"))
            }));
        }
    }

    /// A revoke as the owner check names it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RevokeRequest {
        pub team_id: String,
        /// Each device: its relay number (0 when unknown) and its trusted device UUID
        /// (empty for none).
        pub devices: Vec<(u64, String)>,
        pub device_name: String,
        /// The devices are on this Mac's node.
        pub node: bool,
        /// A Linux node that the vault with this list ID syncs through.
        pub linux_vault: Option<String>,
    }

    impl RevokeRequest {
        pub fn action(&self) -> OwnerAction {
            OwnerAction::RevokeNodeDevice {
                team_id: self.team_id.clone(),
                device_ids: self.devices.iter().map(|(id, _)| *id).collect(),
                device_name: self.device_name.clone(),
            }
        }
    }

    /// The status line of Settings > Devices in the list of sections.
    pub(crate) fn status_line(app: &DesktopApp) -> String {
        let broken = app
            .owner
            .notifications
            .as_ref()
            .is_some_and(|center| !center.view().channel.can_deliver());
        let line = view(app).status_line();
        if broken {
            format!("Notifications off · {line}")
        } else {
            line
        }
    }

    /// The state of the route from the cache, the vault, and the failure of the start.
    fn node_state(app: &DesktopApp) -> (NodeState, Option<NodeProblem>, bool) {
        let locked = app
            .owner_ui
            .session
            .with_vault(|vault| vault.is_locked())
            .unwrap_or(true);
        let cache = &app.ui.devices.cache;
        if locked {
            let state = if cache.last_on {
                NodeState::Locked
            } else {
                NodeState::Off
            };
            return (state, None, true);
        }
        if app.cloud_node().is_none() {
            return (NodeState::Missing, None, false);
        }
        // Before the first read: the setting of the vault, without Tailscale.
        let setting_on = app
            .owner_ui
            .session
            .with_vault(|vault| vault.cloud_node_setting().ok().map(|s| s.tailnet_on))
            .flatten()
            .unwrap_or(false);
        let Some(status) = &cache.status else {
            let state = if setting_on {
                NodeState::On { address: None }
            } else {
                NodeState::Off
            };
            return (state, None, false);
        };
        let tailnet = &status.tailnet;
        let on = setting_on;
        match &status.tailscale {
            Tailscale::Missing => return (NodeState::Missing, None, false),
            Tailscale::NotConnected { .. } if !tailnet.running => {
                return (NodeState::NotConnected, None, false);
            }
            _ => {}
        }
        if !on {
            return (NodeState::Off, None, false);
        }
        let origin = tailnet.origin.clone().filter(|_| tailnet.running);
        let Some(origin) = origin else {
            // On, without a bound front: "Starting…", then the problem.
            let failure = app.node.failed.as_ref().map(|(_, message)| message.clone());
            let waited = cache
                .starting_since
                .is_none_or(|since| since.elapsed() >= super::STARTING_FOR);
            let problem = match failure {
                Some(message) if message.contains(PORT_TAKEN) => Some(NodeProblem::PortTaken {
                    port: tailnet.port,
                    before_pairing: before_pairing(app),
                }),
                Some(message) if waited => Some(NodeProblem::Failed(message)),
                _ => None,
            };
            return (NodeState::On { address: None }, problem, false);
        };
        let address = Address {
            ipv4: super::origin_host(&origin),
            origin: origin.clone(),
            port: tailnet.port,
            words: tailnet.pin_words.clone(),
        };
        // 3h: the paired devices know another address of this Mac.
        let changed = app
            .owner_ui
            .session
            .with_vault(|vault| questions_membership(vault).ok().flatten())
            .flatten()
            .is_some_and(|membership| membership.pin.is_some() && membership.relay_url != origin);
        let problem = changed.then_some(NodeProblem::AddressChanged);
        (
            NodeState::On {
                address: Some(address),
            },
            problem,
            false,
        )
    }

    /// No device paired with this Mac's node yet: the port may still change.
    fn before_pairing(app: &DesktopApp) -> bool {
        !app.owner_ui
            .session
            .with_vault(|vault| questions_membership(vault).ok().flatten())
            .flatten()
            .is_some_and(|membership| membership.pin.is_some())
    }

    /// The view of the section now.
    pub(crate) fn view(app: &DesktopApp) -> DevicesView {
        let (node, problem, locked) = node_state(app);
        let cache = &app.ui.devices.cache;
        let tailnet = cache.status.as_ref().map(|status| &status.tailnet);
        let on_node = matches!(node, NodeState::On { address: Some(_) });
        let can_move = on_node
            && problem.is_none()
            && tailnet.is_some_and(|tailnet| tailnet.questions_elsewhere.is_some())
            && app.questions_can_move();
        let mut devices = if locked { Vec::new() } else { device_rows(app) };
        if devices.is_empty() {
            devices.push(this_mac_row(false));
        }
        for device in &mut devices {
            device.failed = app.ui.devices.failed.contains(&device.name);
        }
        let notes = notes(app);
        DevicesView {
            node,
            problem,
            locked,
            can_move,
            devices,
            notes,
            wifi: None,
            relay: relay_view(app),
            old_relay_entry: !locked && app.questions_old_hosted_entry(),
            now: crate::desktop::companion::now(),
        }
    }

    /// The Relay group of the open vault: the state of its questions ("Unlock the vault
    /// to change it." while locked), the feed switch, the other Macs while it syncs, and
    /// the D14 notice while its questions go through the hosted relay.
    fn relay_view(app: &DesktopApp) -> Option<super::RelayView> {
        let questions = app
            .owner_ui
            .session
            .with_vault(|vault| {
                if vault.is_locked() {
                    return None;
                }
                questions_availability(vault).ok()
            })
            .flatten();
        let questions = match questions {
            Some(QuestionsAvailability::On { .. }) => Questions::On,
            Some(QuestionsAvailability::CanTurnOn { .. }) => Questions::CanTurnOn,
            Some(QuestionsAvailability::NeedsTeam) => Questions::NeedsTeam,
            Some(QuestionsAvailability::JoinTeam { .. }) => Questions::JoinTeam,
            Some(QuestionsAvailability::Removed { sync: false, .. }) => Questions::Removed,
            Some(QuestionsAvailability::Removed { sync: true, .. }) => Questions::RemovedSync,
            None => Questions::Locked,
        };
        let synced = app
            .current_vault()
            .is_some_and(|entry| entry.sync.is_some() && entry.sync_state().is_some());
        let other_macs = synced.then(|| {
            let others = super::super::sync::other_macs(app);
            super::OtherMacsRow {
                words: others.words,
                relay: others.relay.is_some(),
            }
        });
        let free_end = app
            .questions_free_notice()
            .map(|_| FREE_RELAY_PATHS_END_VERSION.to_owned());
        Some(super::RelayView {
            questions,
            feed_shown: !app.ui.feed_off,
            other_macs,
            free_end,
        })
    }

    /// "Show Agents on My Other Devices" on or off. Off: the questions waiter deletes the
    /// feed of this Mac from the relay on its own thread, and takes no action from the
    /// other devices.
    pub(crate) fn set_feed_shown(app: &mut DesktopApp, on: bool) {
        app.ui.set_feed_off(!on);
        if let Some(questions) = &app.owner.questions {
            questions.set_feed(on);
        }
    }

    /// The row of this Mac: it hosts the approvals on its node, or asks for them.
    fn this_mac_row(hosts: bool) -> DeviceEntry {
        DeviceEntry {
            name: crate::sync::device_name(),
            kind: Kind::Mac,
            roles: vec![if hosts {
                "Hosts approvals".to_owned()
            } else {
                "Asks for approvals".to_owned()
            }],
            route: None,
            last_contact: Some(crate::desktop::companion::now()),
            target: Target::ThisMac,
            failed: false,
        }
    }

    /// The problems of the questions waiter and of the feed, one line each.
    fn notes(app: &DesktopApp) -> Vec<(String, super::Tone)> {
        let mut notes = Vec::new();
        if app
            .node
            .node
            .as_ref()
            .is_some_and(|node| node.serve_without_peer_addresses())
        {
            notes.push((
                crate::net::tailnet::SERVE_WITHOUT_PEER_ADDRESSES.to_owned(),
                super::Tone::Warning,
            ));
        }
        let Some(view) = app
            .owner
            .questions
            .as_ref()
            .map(|questions| questions.view())
        else {
            return notes;
        };
        if view.unsupported
            && let Some(problem) = view.problem
        {
            notes.push((problem, super::Tone::Critical));
        }
        if !app.ui.feed_off
            && let Some(problem) = view.feed_problem
        {
            notes.push((problem, super::Tone::Warning));
        }
        notes
    }

    /// One row for each device of the vault: this Mac first, then the trusted devices
    /// of the questions team (through the node or another relay), then each Linux node
    /// that a vault of the list syncs through.
    fn device_rows(app: &DesktopApp) -> Vec<DeviceEntry> {
        let entry = app.current_vault();
        let vault_name = entry.map(|entry| entry.name.clone()).unwrap_or_default();
        let syncs = entry.is_some_and(|entry| entry.sync_relay().is_some());
        let found = app.owner_ui.session.with_vault(|vault| {
            let membership = questions_membership(vault).ok().flatten();
            let me = membership
                .as_ref()
                .and_then(|membership| this_device(vault, membership).ok().flatten());
            let devices = vault.trusted_devices().unwrap_or_default();
            (membership, me, devices)
        });
        let Some((membership, me, trusted)) = found else {
            return Vec::new();
        };
        let tailnet = app
            .ui
            .devices
            .cache
            .status
            .as_ref()
            .map(|status| &status.tailnet);
        let node_seen: BTreeMap<u64, Option<u64>> = tailnet
            .map(|tailnet| {
                tailnet
                    .devices
                    .iter()
                    .map(|device| (device.id, device.last_seen_at))
                    .collect()
            })
            .unwrap_or_default();
        let on_node = membership.as_ref().is_some_and(|membership| {
            membership.pin.is_some()
                && tailnet.is_some_and(|tailnet| tailnet.questions_team.is_some())
        });
        let mut rows = vec![this_mac_row(on_node)];
        let me_uuid = me.map(|me| me.uuid);
        for device in trusted {
            if me_uuid.as_deref() == Some(device.uuid.as_str()) {
                continue;
            }
            let team = membership
                .as_ref()
                .map(|membership| membership.team_id.clone());
            let relay_id = team
                .as_ref()
                .and_then(|team| device.relay_devices.get(team).copied());
            let kind = match device.kind {
                TrustedDeviceKind::Mac => Kind::Mac,
                TrustedDeviceKind::Iphone => Kind::Iphone,
                TrustedDeviceKind::Watch => Kind::Watch,
            };
            let role = match kind {
                Kind::Iphone => "Approves runs".to_owned(),
                Kind::Watch => "Sees requests".to_owned(),
                Kind::Mac if syncs => format!("Syncs {vault_name}"),
                _ => "Asks for approvals".to_owned(),
            };
            let route = membership.as_ref().map(|membership| {
                if membership.pin.is_some() {
                    Route::Mac
                } else {
                    Route::Relay
                }
            });
            let target = match (&team, on_node) {
                (Some(team_id), true) => Target::Node {
                    team_id: team_id.clone(),
                    id: relay_id.unwrap_or(0),
                    uuid: Some(device.uuid.clone()),
                },
                (Some(team_id), false) => Target::Hosted {
                    team_id: team_id.clone(),
                    id: relay_id,
                    uuid: device.uuid.clone(),
                },
                (None, _) => Target::Hosted {
                    team_id: String::new(),
                    id: None,
                    uuid: device.uuid.clone(),
                },
            };
            let last_contact = relay_id.and_then(|id| node_seen.get(&id).copied().flatten());
            rows.push(DeviceEntry {
                name: device.name.clone(),
                kind,
                roles: vec![role],
                route,
                last_contact,
                target,
                failed: false,
            });
        }
        // Devices of the node team that the vault has no row for.
        if on_node && let Some(tailnet) = tailnet {
            let known: Vec<u64> = rows
                .iter()
                .filter_map(|row| match &row.target {
                    Target::Node { id, .. } => Some(*id),
                    _ => None,
                })
                .collect();
            for device in &tailnet.devices {
                if device.this_mac || known.contains(&device.id) {
                    continue;
                }
                let kind = match device.kind {
                    Some(TrustedDeviceKind::Iphone) => Kind::Iphone,
                    Some(TrustedDeviceKind::Watch) => Kind::Watch,
                    _ => Kind::Mac,
                };
                rows.push(DeviceEntry {
                    name: device.name.clone(),
                    kind,
                    roles: Vec::new(),
                    route: Some(Route::Mac),
                    last_contact: device.last_seen_at,
                    target: Target::Node {
                        team_id: tailnet.questions_team.clone().unwrap_or_default(),
                        id: device.id,
                        uuid: None,
                    },
                    failed: false,
                });
            }
        }
        // The Linux nodes: a pinned sync link that is not this Mac's node.
        let own = tailnet.and_then(|tailnet| tailnet.origin.clone());
        for entry in app.vault_list.registry.entries() {
            let Some(link) = entry.sync_relay() else {
                continue;
            };
            if link.pin.is_none() || own.as_deref() == Some(link.url.as_str()) {
                continue;
            }
            rows.push(DeviceEntry {
                name: super::origin_host(&link.url),
                kind: Kind::LinuxNode,
                roles: vec![format!("Syncs {}", entry.name)],
                route: Some(Route::Tailnet),
                last_contact: None,
                target: Target::Linux {
                    vault: entry.id.clone(),
                    team_id: link.team_id.clone(),
                    device_id: link.device_id,
                    origin: link.url.clone(),
                },
                failed: false,
            });
        }
        rows
    }

    /// Settings > Devices.
    pub(crate) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        app.poll_devices(&ctx);
        let starting = matches!(node_state(app).0, NodeState::On { address: None });
        if starting {
            app.ui
                .devices
                .cache
                .starting_since
                .get_or_insert_with(Instant::now);
        } else {
            app.ui.devices.cache.starting_since = None;
        }
        let view = view(app);
        let mut notify = None;
        let action = super::draw(ui, &view, |g| {
            notify = super::super::settings::notification_rows(app, g);
        });
        super::super::companion::draw(app, ui);
        if let Some(notify) = notify {
            super::super::settings::notify(app, notify);
        }
        if let Some(action) = action {
            act(app, &ctx, &view, action);
        }
    }

    fn act(app: &mut DesktopApp, ctx: &egui::Context, view: &DevicesView, action: Action) {
        match action {
            Action::SetRoute(on) => {
                app.ask_owner(OwnerRequest::SetTailnetRoute { on }, Some(ctx));
            }
            Action::GetTailscale => {
                ctx.open_url(egui::OpenUrl::new_tab(super::TAILSCALE_DOWNLOAD));
            }
            Action::CheckAgain => {
                app.ui.devices.cache.invalidate();
                app.ui.devices.cache.starting_since = Some(Instant::now());
                app.retry_node();
            }
            Action::UsePort(port) => {
                let Some(node) = app.cloud_node() else {
                    return;
                };
                let vault = app.owner_ui.session.shared_vault();
                match node.set_tailnet_port(&vault, Some(port)) {
                    Ok(()) => {
                        app.ui.devices.cache.invalidate();
                        app.node_changed();
                        app.set_ok(format!("The node of this Mac uses port {port} now."));
                    }
                    Err(error) => app.set_err(error.message),
                }
            }
            Action::PairAgain | Action::Move => app.questions_move_to_node(Some(ctx)),
            Action::Copy(origin) => {
                ctx.copy_text(origin);
                app.set_ok("The address of this Mac is copied.");
            }
            Action::Add => app.questions_add_iphone(Some(ctx)),
            Action::Revoke(index) => {
                let Some(device) = view.devices.get(index) else {
                    return;
                };
                let watches = if device.kind == Kind::Iphone {
                    view.devices
                        .iter()
                        .enumerate()
                        .filter(|(_, other)| {
                            other.kind == Kind::Watch && other.route == device.route
                        })
                        .map(|(index, other)| WatchChoice {
                            index,
                            name: other.name.clone(),
                            revoke: true,
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let vault = device
                    .roles
                    .iter()
                    .find_map(|role| role.strip_prefix("Syncs ").map(str::to_owned));
                app.ui.devices.sheet = Some(DevicesSheet::Revoke {
                    device: device.clone(),
                    vault,
                    watches,
                });
            }
            Action::Details(index) => {
                let Some(device) = view.devices.get(index) else {
                    return;
                };
                let vault = device
                    .roles
                    .iter()
                    .find_map(|role| role.strip_prefix("Syncs ").map(str::to_owned))
                    .unwrap_or_default();
                app.ui.devices.sheet = Some(DevicesSheet::Linux {
                    device: device.clone(),
                    vault,
                });
            }
            // On is a new channel that can approve runs: the owner check first, for the
            // relay sync team of the vault, or the sheet of a new team. Off needs no
            // check and takes the purpose `questions` away; relay sync never changes.
            Action::SetQuestions(true) => app.questions_turn_on(Some(ctx)),
            Action::SetQuestions(false) => app.questions_turn_off(),
            Action::ShowAgents(on) => set_feed_shown(app, on),
            Action::OtherMacs | Action::AddMac => {
                let Some(id) = super::super::sync::other_macs(app).relay else {
                    return;
                };
                let sheet = if action == Action::AddMac {
                    SyncSheet::AddMac { id }
                } else {
                    SyncSheet::Devices { id }
                };
                app.sync_open_sheet(sheet, Some(ctx));
            }
            Action::Listen(_) | Action::RemoveWifi(..) | Action::ResetWifi | Action::RetryWifi => {}
        }
    }

    /// The owner check of a revoke for `device` (and the watches that go with it).
    fn ask_revoke(
        app: &mut DesktopApp,
        ctx: &egui::Context,
        device: &DeviceEntry,
        watches: &[DeviceEntry],
    ) {
        let mut request = match &device.target {
            Target::ThisMac => return,
            Target::Node { team_id, id, uuid } => RevokeRequest {
                team_id: team_id.clone(),
                devices: vec![(*id, uuid.clone().unwrap_or_default())],
                device_name: device.name.clone(),
                node: true,
                linux_vault: None,
            },
            Target::Hosted { team_id, id, uuid } => RevokeRequest {
                team_id: team_id.clone(),
                devices: vec![(id.unwrap_or(0), uuid.clone())],
                device_name: device.name.clone(),
                node: false,
                linux_vault: None,
            },
            Target::Linux {
                vault,
                team_id,
                device_id,
                ..
            } => RevokeRequest {
                team_id: team_id.clone(),
                devices: vec![(*device_id, String::new())],
                device_name: device.name.clone(),
                node: false,
                linux_vault: Some(vault.clone()),
            },
        };
        for watch in watches {
            match &watch.target {
                Target::Node { id, uuid, .. } => request
                    .devices
                    .push((*id, uuid.clone().unwrap_or_default())),
                Target::Hosted { id, uuid, .. } => {
                    request.devices.push((id.unwrap_or(0), uuid.clone()));
                }
                Target::ThisMac | Target::Linux { .. } => {}
            }
        }
        app.ask_owner(OwnerRequest::RevokeNodeDevice(request), Some(ctx));
    }

    /// The sheets of the section and the Wi-Fi notice.
    pub(crate) fn overlays(app: &mut DesktopApp, ctx: &egui::Context) {
        if app.ui.devices.sheet.is_none() {
            notice_due(app);
        }
        let Some(sheet) = app.ui.devices.sheet.clone() else {
            return;
        };
        let checking = app.owner.check.is_some();
        match sheet {
            DevicesSheet::Revoke {
                device,
                vault,
                mut watches,
            } => {
                let (choice, escape) =
                    super::revoke_sheet(ctx, &device, vault.as_deref(), &mut watches);
                match choice {
                    Some(Choice::Confirm) => {
                        app.ui.devices.sheet = None;
                        let view = view(app);
                        let chosen: Vec<DeviceEntry> = watches
                            .iter()
                            .filter(|watch| watch.revoke)
                            .filter_map(|watch| view.devices.get(watch.index).cloned())
                            .collect();
                        ask_revoke(app, ctx, &device, &chosen);
                    }
                    Some(_) => app.ui.devices.sheet = None,
                    None if escape && !checking => app.ui.devices.sheet = None,
                    None => {
                        app.ui.devices.sheet = Some(DevicesSheet::Revoke {
                            device,
                            vault,
                            watches,
                        });
                    }
                }
            }
            DevicesSheet::Linux { device, vault } => {
                let origin = match &device.target {
                    Target::Linux { origin, .. } => origin.clone(),
                    _ => String::new(),
                };
                let (choice, escape) = super::linux_sheet(ctx, &device, &vault, &origin);
                match choice {
                    Some(Choice::Confirm) => {
                        app.ui.devices.sheet = None;
                        ask_revoke(app, ctx, &device, &[]);
                    }
                    Some(_) => app.ui.devices.sheet = None,
                    None if escape && !checking => app.ui.devices.sheet = None,
                    None => {}
                }
            }
            DevicesSheet::WifiNotice { tailnet } => {
                let (choice, escape) = super::wifi_notice(ctx, tailnet);
                let choice = choice.or(escape.then_some(Choice::Cancel));
                if let Some(choice) = choice {
                    app.ui.devices.sheet = None;
                    app.ui.set_wifi_notice_seen();
                    if choice == Choice::Open {
                        super::super::settings_view::open(
                            app,
                            super::super::settings_view::SettingsSection::Devices,
                        );
                    }
                }
            }
        }
    }

    /// Frame 6a and 6b: once per Mac, at the first unlock after the update, only with
    /// a paired Wi-Fi iPhone. Considered once per vault session.
    fn notice_due(app: &mut DesktopApp) {
        if app.ui.wifi_notice_seen || app.ui.sheet.is_some() || app.owner.check.is_some() {
            return;
        }
        let Some(epoch) = app.owner_ui.session.epoch() else {
            return;
        };
        if app.ui.devices.notice_epoch == Some(epoch) {
            return;
        }
        app.ui.devices.notice_epoch = Some(epoch);
        let paired = !app
            .owner_ui
            .session
            .companion_devices()
            .unwrap_or_default()
            .is_empty();
        if !paired {
            return;
        }
        let tailnet = app
            .owner_ui
            .session
            .with_vault(|vault| vault.cloud_node_setting().ok().map(|s| s.tailnet_on))
            .flatten()
            .unwrap_or(false);
        app.ui.devices.sheet = Some(DevicesSheet::WifiNotice { tailnet });
    }
}

#[cfg(feature = "vault")]
pub(crate) use live::RevokeRequest;
