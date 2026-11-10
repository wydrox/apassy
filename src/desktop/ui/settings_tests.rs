//! Headless tests of Settings as a view of the window (ADR 0026 §3): the gear and ⌘,
//! open it, the list column names each section, a click selects one, a sidebar click
//! leaves; each section shows its groups at a tall and at the minimum window size;
//! Devices (plan S2–S3, unit N7): each frame of its mockup, the device list with Revoke…
//! and its owner check, and the route switch behind the owner check; and a sheet of
//! Settings over the window. Synthetic values only; the relay is the in-process fake
//! relay on 127.0.0.1.

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::devices::{
    self, ADD_DEVICE, Address, DeviceEntry, DevicesSheet, DevicesView, Kind, NodeProblem,
    NodeState, ONLY_THIS_MAC, OtherMacsRow, Questions, ROUTE_LOCKED, ROUTE_OFF, ROUTE_ON,
    ROUTE_SWITCH, RelayView, Route, Target, WIFI_GROUP, WIFI_LISTEN, WIFI_NOTICE_TITLE, WifiDevice,
    WifiEnd, WifiView,
};
use super::super::owner_tests::{PASS, WRONG, unlocked_app_with_item};
use super::super::settings_view::SettingsSection;
use crate::broker::approvals::{OwnerAction, OwnerAuthError, OwnerCheck};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{DesktopApp, Place};

use crate::desktop::fake_relay;

/// The default window, a tall one that shows each group of a section, and the smallest
/// window ([`super::super::MIN_WINDOW`]).
const DEFAULT: Vec2 = Vec2::new(1180.0, 800.0);
const TALL: Vec2 = Vec2::new(1180.0, 6000.0);
const MIN: Vec2 = Vec2::new(super::super::MIN_WINDOW.0, super::super::MIN_WINDOW.1);

/// One frame of the whole window at `size`. Returns the painted texts with their
/// rectangles.
fn frame(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    size: Vec2,
    events: Vec<Event>,
) -> Vec<(String, Rect)> {
    let input = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
        events,
        ..Default::default()
    };
    let output = ctx.run_ui(input, |ui| super::super::draw(app, ui));
    let mut texts = Vec::new();
    for clipped in &output.shapes {
        texts_of(&clipped.shape, clipped.clip_rect, &mut texts);
    }
    output.drop_without_applying_deltas();
    texts
}

/// Each painted text and its rectangle, cut to its clip rectangle.
fn texts_of(shape: &egui::Shape, clip: Rect, out: &mut Vec<(String, Rect)>) {
    match shape {
        egui::Shape::Text(text) => {
            let rect = text.visual_bounding_rect().intersect(clip);
            if rect.is_positive() {
                out.push((text.galley.text().to_owned(), rect));
            }
        }
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| texts_of(inner, clip, out)),
        _ => {}
    }
}

/// Three frames, so a new layout settles. Returns the painted texts of the last one.
fn frames(app: &mut DesktopApp, size: Vec2) -> (String, Vec<(String, Rect)>) {
    let ctx = egui::Context::default();
    let mut texts = Vec::new();
    for _ in 0..3 {
        texts = frame(&ctx, app, size, Vec::new());
    }
    let joined = texts
        .iter()
        .map(|(text, _)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    (joined, texts)
}

/// A click at `at`: the pointer moves there, presses, and releases.
fn click(ctx: &egui::Context, app: &mut DesktopApp, size: Vec2, at: Pos2) {
    let button = |pressed| Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Modifiers::NONE,
    };
    frame(ctx, app, size, vec![Event::PointerMoved(at)]);
    frame(ctx, app, size, vec![button(true)]);
    frame(ctx, app, size, vec![button(false)]);
}

/// A key press, after a frame that settles the window.
fn press(ctx: &egui::Context, app: &mut DesktopApp, key: Key, modifiers: Modifiers) {
    frame(ctx, app, DEFAULT, Vec::new());
    frame(
        ctx,
        app,
        DEFAULT,
        vec![Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers,
        }],
    );
    frame(ctx, app, DEFAULT, Vec::new());
}

/// The center of the first painted `text` left of `right`.
fn center_of(texts: &[(String, Rect)], text: &str, right: f32) -> Option<Pos2> {
    texts
        .iter()
        .find(|(painted, rect)| painted == text && rect.right() < right)
        .map(|(_, rect)| rect.center())
}

/// What each section shows, and what it never shows: the groups of another section.
/// The list column names every section, so no section name is in the second list.
fn cases() -> [(
    SettingsSection,
    &'static [&'static str],
    &'static [&'static str],
); 6] {
    [
        (
            SettingsSection::Vault,
            &[
                "Vault",
                "Backup",
                "Back up now…",
                "Restore…",
                "Import",
                "1Password",
            ],
            &["Change passphrase…", "Install tools…", "Pair…"],
        ),
        (
            SettingsSection::Security,
            if cfg!(target_os = "linux") {
                &[
                    "Unlock",
                    "Passphrase",
                    "Owner checks",
                    "How often to ask",
                    "Lock after inactivity",
                    "Never",
                    "Agents cannot use credentials while the vault is locked.",
                    "Every time",
                    "Change passphrase…",
                ]
            } else {
                &[
                    "Unlock",
                    "Touch ID",
                    "Owner checks use",
                    "Lock after inactivity",
                    "Never",
                    "Agents can't use your credentials while the vault is locked.",
                    "How often to ask for Touch ID",
                    "Every time",
                    "Change passphrase…",
                ]
            },
            if cfg!(target_os = "linux") {
                &[
                    "Back up now…",
                    "Install tools…",
                    "Touch ID",
                    "Owner checks use",
                ]
            } else {
                &["Back up now…", "Install tools…", "Owner confirmation"]
            },
        ),
        (
            SettingsSection::Devices,
            &[
                "This Mac",
                ROUTE_SWITCH,
                "Notifications",
                ADD_DEVICE,
                ONLY_THIS_MAC,
            ],
            &[
                "Back up now…",
                "Pair an iPhone",
                "Allow the iPhone app on this network",
                WIFI_GROUP,
                "Other Macs",
                "Questions reach every device.",
                "Get approvals on your iPhone",
                "None paired",
            ],
        ),
        (
            SettingsSection::Bouncer,
            &[
                "Bouncer brain",
                "Calibration and learning",
                "decided by the bouncer gate",
            ],
            &[
                "Back up now…",
                "Asked you",
                "Accepts agent requests",
                "Address",
            ],
        ),
        (
            SettingsSection::Tools,
            &[
                "Command line",
                "apassy",
                "Install tools…",
                "Browser extension",
            ],
            &["Back up now…", "Socket", "Sessions", "None open"],
        ),
        (
            SettingsSection::Updates,
            &["Updates", "Version", "Keyboard shortcuts"],
            &["Back up now…", "Contract", "Install tools…"],
        ),
    ]
}

/// Each section shows its groups and no group of another section. The list column names
/// every section. The settings of single agents are gone (ADR 0025 §3f), and Settings has
/// no "Done": it is no window. At the smallest window, with the sidebar full, as a rail,
/// and floating, each section draws its list and its first group, and no text goes past
/// the right edge.
#[test]
fn each_section_shows_its_groups() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    for (section, shown, hidden) in cases() {
        super::super::open_settings(&mut app, section);
        let (text, _) = frames(&mut app, TALL);
        for listed in SettingsSection::ALL {
            assert!(
                text.contains(listed.label()),
                "{section:?}: the list has {listed:?}: {text}"
            );
        }
        for expected in shown {
            assert!(
                text.contains(expected),
                "{section:?} shows {expected}: {text}"
            );
        }
        for unexpected in hidden {
            assert!(
                !text.contains(unexpected),
                "{section:?} hides {unexpected}: {text}"
            );
        }
        for gone in ["Token lifetime", "Current lifetime", "Done"] {
            assert!(!text.contains(gone), "{section:?}: {gone} is gone: {text}");
        }
    }

    // The smallest window.
    for (hidden, float) in [(false, false), (true, false), (false, true)] {
        app.ui.sidebar_hidden = hidden;
        for (section, shown, _) in cases() {
            super::super::open_settings(&mut app, section);
            app.ui.sidebar_float = float;
            let (text, texts) = frames(&mut app, MIN);
            assert!(
                text.contains("Settings"),
                "MIN {hidden} {float}: {section:?}: {text}"
            );
            assert!(
                text.contains(shown[0]),
                "MIN {hidden} {float}: {section:?}: {}: {text}",
                shown[0]
            );
            for (painted, rect) in &texts {
                assert!(
                    rect.right() <= MIN.x + 0.5 && rect.left() >= -0.5,
                    "MIN {hidden} {float}: {section:?}: \"{painted}\" at {rect:?} is outside the window"
                );
            }
        }
    }
}

/// The gear at the bottom of the sidebar and ⌘, open Settings, with the section that was
/// open last. A click on a section in the list selects it. A click on a sidebar row
/// leaves Settings for that place.
#[test]
fn the_gear_and_command_comma_open_settings_and_the_sidebar_leaves_it() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let texts = frame(&ctx, &mut app, DEFAULT, Vec::new());
    assert!(app.place.is_credentials());
    // The gear is the last control of the sidebar footer, at its right edge.
    let gear = Pos2::new(
        super::super::kit::SIDEBAR_WIDTH - 10.0 - 14.0,
        DEFAULT.y - 10.0 - 26.0,
    );
    drop(texts);
    click(&ctx, &mut app, DEFAULT, gear);
    assert_eq!(app.place, Place::Settings, "the gear opens Settings");
    assert_eq!(app.ui.settings_section, SettingsSection::Vault);

    // A click on each section in the list selects it.
    let list_right = super::super::kit::SIDEBAR_WIDTH + super::super::kit::LIST_WIDTH;
    for target in [
        SettingsSection::Devices,
        SettingsSection::Updates,
        SettingsSection::Security,
    ] {
        let texts = frame(&ctx, &mut app, DEFAULT, Vec::new());
        let at = center_of(&texts, target.label(), list_right)
            .unwrap_or_else(|| panic!("{} is in the list", target.label()));
        click(&ctx, &mut app, DEFAULT, at);
        assert_eq!(app.ui.settings_section, target);
        assert_eq!(app.place, Place::Settings);
    }

    // A sidebar row leaves Settings.
    let texts = frame(&ctx, &mut app, DEFAULT, Vec::new());
    let decisions = center_of(&texts, "Decisions", super::super::kit::SIDEBAR_WIDTH)
        .expect("the sidebar has Decisions");
    click(&ctx, &mut app, DEFAULT, decisions);
    assert_eq!(app.place, Place::Decisions, "the sidebar leaves Settings");

    // ⌘, comes back to the section that was open last; ⌘1 leaves.
    press(&ctx, &mut app, Key::Comma, Modifiers::COMMAND);
    assert_eq!(app.place, Place::Settings, "⌘, opens Settings");
    assert_eq!(app.ui.settings_section, SettingsSection::Security);
    press(&ctx, &mut app, Key::Num1, Modifiers::COMMAND);
    assert_eq!(app.place, Place::CREDENTIALS);
}

/// A sheet that a section opens shows over the main window, with Settings behind it.
/// Esc closes the sheet and Settings stays.
#[test]
fn a_sheet_of_settings_shows_over_the_window() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Vault);
    app.ui.sheet = Some(super::Sheet::Backup);
    let (text, _) = frames(&mut app, DEFAULT);
    assert!(text.contains("Back up the vault"), "{text}");
    assert!(text.contains("Settings"), "{text}");
    let ctx = egui::Context::default();
    press(&ctx, &mut app, Key::Escape, Modifiers::NONE);
    assert!(app.ui.sheet.is_none(), "Esc closes the sheet");
    assert_eq!(app.place, Place::Settings, "and Settings stays");
    press(&ctx, &mut app, Key::Escape, Modifiers::NONE);
    assert_eq!(app.place, Place::Settings, "Esc does not leave a view");
}

/// The painted texts of the Devices section for `view`, in a tall window, after three
/// frames.
fn view_texts(view: &DevicesView) -> String {
    joined(&view_rects(view))
}

/// The painted texts of the Devices section for `view`, with their rectangles.
fn view_rects(view: &DevicesView) -> Vec<(String, Rect)> {
    let ctx = egui::Context::default();
    let mut texts = Vec::new();
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(720.0, 2400.0))),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                devices::draw(ui, view, |g| {
                    g.labeled("Notifications", super::rows::value("On"));
                });
            });
        });
        texts.clear();
        for clipped in &output.shapes {
            texts_of(&clipped.shape, clipped.clip_rect, &mut texts);
        }
        output.drop_without_applying_deltas();
    }
    texts
}

fn joined(texts: &[(String, Rect)]) -> String {
    texts
        .iter()
        .map(|(text, _)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Tue 3 Nov 2026, 14:20 UTC, as the mockup.
const NOW: u64 = 1_793_715_600;
const MOVE: &str = devices::MOVE_APPROVALS;

fn entry(
    name: &str,
    kind: Kind,
    role: &str,
    route: Option<Route>,
    ago: u64,
    target: Target,
) -> DeviceEntry {
    DeviceEntry {
        name: name.to_owned(),
        kind,
        roles: vec![role.to_owned()],
        route,
        last_contact: Some(NOW - ago),
        target,
        failed: false,
    }
}

/// The view of frame 1 of the mockup: the route on, every kind of device, Wi-Fi Pairing.
fn frame_one() -> DevicesView {
    let node = |id| Target::Node {
        team_id: "t_node".to_owned(),
        id,
        uuid: None,
    };
    let hosted = |uuid: &str| Target::Hosted {
        team_id: "t_sync".to_owned(),
        id: None,
        uuid: uuid.to_owned(),
    };
    DevicesView {
        node: NodeState::On {
            address: Some(Address {
                ipv4: "100.101.7.12".to_owned(),
                origin: "https://100.101.7.12:8444".to_owned(),
                port: 8444,
                words: Some("harbor lemon quartz otter cedar mango".to_owned()),
            }),
        },
        problem: None,
        locked: false,
        can_move: false,
        devices: vec![
            entry(
                "Mac mini (office)",
                Kind::Mac,
                "Hosts approvals",
                None,
                0,
                Target::ThisMac,
            ),
            entry(
                "Rafal's iPhone",
                Kind::Iphone,
                "Approves runs",
                Some(Route::Mac),
                10,
                node(2),
            ),
            entry(
                "Rafal's Apple Watch",
                Kind::Watch,
                "Sees requests",
                Some(Route::Mac),
                240,
                node(3),
            ),
            entry(
                "MacBook Pro",
                Kind::Mac,
                "Syncs Personal",
                Some(Route::Relay),
                120,
                hosted("mbp"),
            ),
            entry(
                "Mac mini (studio)",
                Kind::Mac,
                "Syncs Personal",
                Some(Route::Relay),
                3_600,
                hosted("studio"),
            ),
            entry(
                "build-box",
                Kind::LinuxNode,
                "Syncs Acme team",
                Some(Route::Tailnet),
                300,
                Target::Linux {
                    vault: "acme".to_owned(),
                    team_id: "t_acme".to_owned(),
                    device_id: 7,
                    origin: "https://100.88.4.20:8444".to_owned(),
                },
            ),
        ],
        notes: Vec::new(),
        wifi: Some(WifiView {
            listening: true,
            starting: false,
            failed: None,
            devices: vec![WifiDevice {
                id: "wifi".to_owned(),
                name: "Rafal's iPhone".to_owned(),
                // 12 Sep 2026, 09:00 UTC.
                paired_at: 1_789_203_600,
                last_seen_at: Some(NOW - 3 * 3_600),
            }],
            end: WifiEnd::TwoVersions,
        }),
        relay: None,
        old_relay_entry: false,
        now: NOW,
    }
}

/// Frame 1 of the mockup: the texts of the node group, the device list with its route
/// words, last contacts, and buttons, the one add button, and the Wi-Fi group in its
/// notice state with no "Pair an iPhone".
#[test]
fn devices_frame_one_draws_the_mockup() {
    let view = frame_one();
    assert_eq!(view.status_line(), "Tailnet on · 6 devices");
    let text = view_texts(&view);
    for expected in [
        "This Mac",
        ROUTE_SWITCH,
        ROUTE_ON,
        "Address",
        "100.101.7.12",
        "Copy",
        "Port",
        "8444",
        "Node Words",
        "harbor lemon quartz otter cedar mango",
        "Notifications",
        "Devices",
        "6",
        "Mac mini (office)",
        "Mac · Hosts approvals",
        "iPhone · Approves runs",
        "Apple Watch · Sees requests",
        "Mac · Syncs Personal",
        "Linux node · Syncs Acme team",
        "via your Mac",
        "via Apassy relay",
        "Tailnet",
        "Now",
        "4 min ago",
        "2 min ago",
        "1 h ago",
        "5 min ago",
        "Revoke…",
        "Details…",
        ADD_DEVICE,
        WIFI_GROUP,
        "Wi-Fi pairing ends in two versions.",
        WIFI_LISTEN,
        "Paired 12 Sep",
        "Wi-Fi",
        "3 h ago",
        "Remove…",
        "Reset Pairing…",
    ] {
        assert!(text.contains(expected), "frame 1 shows {expected}: {text}");
    }
    for gone in [
        "Pair an iPhone",
        "Pair…",
        "Allow the iPhone app on this network",
        MOVE,
        ONLY_THIS_MAC,
        "Get approvals on your iPhone",
    ] {
        assert!(!text.contains(gone), "frame 1 has no {gone}: {text}");
    }
    // This Mac has no button; four node and relay devices have Revoke…, the Linux node
    // has Details….
    assert_eq!(text.matches("Revoke…").count(), 4, "{text}");
    assert_eq!(text.matches("Details…").count(), 1, "{text}");
}

/// Frame 3: the This Mac group in each state, one line and at most one button for each
/// problem; frame 4: the move row; frame 6d; and frame 7: only this Mac.
#[test]
fn devices_node_states_draw_the_mockup() {
    let with = |node: NodeState, problem: Option<NodeProblem>| DevicesView {
        node,
        problem,
        ..frame_one()
    };
    let address = |ipv4: &str| Address {
        ipv4: ipv4.to_owned(),
        origin: format!("https://{ipv4}:8444"),
        port: 8444,
        words: Some("harbor lemon quartz otter cedar mango".to_owned()),
    };
    let only_this_mac = || frame_one().devices.into_iter().take(1).collect::<Vec<_>>();
    let cases: Vec<(&str, DevicesView, Vec<&str>, Vec<&str>)> = vec![
        (
            "3a",
            with(NodeState::Missing, None),
            vec![ROUTE_OFF, "Tailscale is not installed.", "Get Tailscale…"],
            vec!["Address", "Node Words", ROUTE_ON],
        ),
        (
            "3b",
            with(NodeState::NotConnected, None),
            vec![ROUTE_OFF, "Tailscale is not connected.", "Check Again"],
            vec!["Address", "Get Tailscale…"],
        ),
        (
            "3c",
            with(NodeState::Off, None),
            vec![ROUTE_OFF, "Notifications", "via your Mac"],
            vec!["Address", "Port", "Node Words"],
        ),
        (
            "3d",
            with(NodeState::On { address: None }, None),
            vec![ROUTE_ON, "Address", "Starting…"],
            vec!["Node Words", "Copy"],
        ),
        (
            "3f",
            DevicesView {
                locked: true,
                ..with(NodeState::Locked, None)
            },
            vec![ROUTE_LOCKED, "Address", "Off"],
            vec!["Node Words", "Copy"],
        ),
        (
            "3g",
            with(
                NodeState::On { address: None },
                Some(NodeProblem::PortTaken {
                    port: 8444,
                    before_pairing: true,
                }),
            ),
            vec![ROUTE_ON, "Another app uses port 8444.", "Use Port 8445"],
            vec!["Starting…", "Address"],
        ),
        (
            "3g after the first pairing",
            with(
                NodeState::On { address: None },
                Some(NodeProblem::PortTaken {
                    port: 8444,
                    before_pairing: false,
                }),
            ),
            vec!["Another app uses port 8444. Quit it."],
            vec!["Use Port 8445"],
        ),
        (
            "3h",
            with(
                NodeState::On {
                    address: Some(address("100.77.20.5")),
                },
                Some(NodeProblem::AddressChanged),
            ),
            vec![
                "100.77.20.5",
                "The address changed. Paired devices must pair again.",
                "Pair Again…",
            ],
            vec!["Node Words", "Port"],
        ),
        (
            "4",
            DevicesView {
                can_move: true,
                ..frame_one()
            },
            vec![
                "Approvals go through Apassy relay",
                "Move them here to keep them on your tailnet.",
                MOVE,
                ADD_DEVICE,
            ],
            vec![],
        ),
        (
            "6d",
            DevicesView {
                wifi: frame_one().wifi.map(|wifi| WifiView {
                    end: WifiEnd::NextVersion,
                    ..wifi
                }),
                ..frame_one()
            },
            vec!["Wi-Fi pairing ends in the next version."],
            vec!["Wi-Fi pairing ends in two versions."],
        ),
        (
            "7",
            DevicesView {
                devices: only_this_mac(),
                wifi: None,
                ..with(NodeState::Missing, None)
            },
            vec![
                "Tailscale is not installed.",
                "Get Tailscale…",
                "Mac mini (office)",
                ONLY_THIS_MAC,
                ADD_DEVICE,
            ],
            vec![WIFI_GROUP, "Revoke…", "Details…"],
        ),
    ];
    for (frame, view, shown, hidden) in cases {
        let text = view_texts(&view);
        for expected in shown {
            assert!(text.contains(expected), "{frame} shows {expected}: {text}");
        }
        for unexpected in hidden {
            assert!(
                !text.contains(unexpected),
                "{frame} hides {unexpected}: {text}"
            );
        }
    }
    let first_run = DevicesView {
        devices: only_this_mac(),
        node: NodeState::Missing,
        ..frame_one()
    };
    assert_eq!(first_run.status_line(), "This Mac only");
    let off = DevicesView {
        node: NodeState::Off,
        ..frame_one()
    };
    assert_eq!(off.status_line(), "6 devices");
}

/// The last contact reads "Now" under a minute, then "4 min ago", "3 h ago",
/// "Yesterday", "12 Sep"; a device row says `<Kind> · <Role>[ · <Role>]`; the host of an
/// origin is its address.
#[test]
fn devices_words_follow_the_mockup() {
    use devices::{day_month, last_contact, origin_host};
    assert_eq!(last_contact(NOW - 59, NOW), "Now");
    assert_eq!(last_contact(NOW - 240, NOW), "4 min ago");
    assert_eq!(last_contact(NOW - 3 * 3_600, NOW), "3 h ago");
    assert_eq!(last_contact(NOW - 90_000, NOW), "Yesterday");
    assert_eq!(last_contact(1_789_203_600, NOW), "12 Sep");
    assert_eq!(day_month(0), "1 Jan");
    assert_eq!(day_month(1_767_225_599), "31 Dec");
    // 29 Feb 2028, 12:00 UTC.
    assert_eq!(day_month(1_835_438_400), "29 Feb");
    let mut device = entry(
        "MacBook Pro",
        Kind::Mac,
        "Syncs Personal",
        Some(Route::Relay),
        0,
        Target::ThisMac,
    );
    device.roles.push("Asks for approvals".to_owned());
    assert_eq!(
        device.subline(),
        "Mac · Syncs Personal · Asks for approvals"
    );
    assert_eq!(device.button(), None);
    assert_eq!(origin_host("https://100.101.7.12:8444"), "100.101.7.12");
    assert_eq!(
        origin_host("https://build-box.tail0.ts.net"),
        "build-box.tail0.ts.net"
    );
    assert_eq!(
        [Route::Mac, Route::Relay, Route::Tailnet, Route::Wifi].map(Route::words),
        ["via your Mac", "via Apassy relay", "Tailnet", "Wi-Fi"]
    );
}

/// The sheets of frame 5 and frame 6: Revoke of an iPhone with its watch and of another
/// Mac, Details… of a Linux node, and the once-only Wi-Fi notice with and without the
/// route.
#[test]
fn devices_sheets_draw_the_mockup() {
    let sheet_texts = |sheet: DevicesSheet| {
        let ctx = egui::Context::default();
        let mut texts = Vec::new();
        for _ in 0..3 {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, DEFAULT)),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| match &sheet {
                DevicesSheet::Revoke {
                    device,
                    vault,
                    watches,
                } => {
                    let mut watches = watches.clone();
                    devices::revoke_sheet(ui.ctx(), device, vault.as_deref(), &mut watches);
                }
                DevicesSheet::Linux { device, vault } => {
                    devices::linux_sheet(ui.ctx(), device, vault, "https://100.88.4.20:8444");
                }
                DevicesSheet::WifiNotice { tailnet } => {
                    devices::wifi_notice(ui.ctx(), *tailnet);
                }
            });
            texts.clear();
            for clipped in &output.shapes {
                texts_of(&clipped.shape, clipped.clip_rect, &mut texts);
            }
            output.drop_without_applying_deltas();
        }
        joined(&texts)
    };
    let view = frame_one();
    let text = sheet_texts(DevicesSheet::Revoke {
        device: view.devices[1].clone(),
        vault: None,
        watches: vec![devices::WatchChoice {
            index: 2,
            name: "Rafal's Apple Watch".to_owned(),
            revoke: true,
        }],
    });
    for expected in [
        "Revoke Rafal's iPhone?",
        "It can no longer see or answer questions.",
        "Also revoke Rafal's Apple Watch",
        "To use it again, pair it again.",
        "Cancel",
        "Revoke",
    ] {
        assert!(text.contains(expected), "5a shows {expected}: {text}");
    }
    let text = sheet_texts(DevicesSheet::Revoke {
        device: view.devices[3].clone(),
        vault: Some("Personal".to_owned()),
        watches: Vec::new(),
    });
    for expected in [
        "Revoke MacBook Pro?",
        "It stops syncing Personal and seeing approvals.",
        "Its copy of the vault stays on that Mac.",
    ] {
        assert!(text.contains(expected), "5b shows {expected}: {text}");
    }
    assert!(!text.contains("Also revoke"), "{text}");
    let text = sheet_texts(DevicesSheet::Linux {
        device: view.devices[5].clone(),
        vault: "Acme team".to_owned(),
    });
    for expected in [
        "build-box",
        "Linux node",
        "Tailnet",
        "100.88.4.20",
        "Revoke…",
        "Done",
    ] {
        assert!(text.contains(expected), "Details… shows {expected}: {text}");
    }
    for (tailnet, way) in [
        (
            true,
            "The iPhone app now reaches this Mac through your tailnet.",
        ),
        (
            false,
            "The iPhone app now reaches this Mac through Apassy relay.",
        ),
    ] {
        let text = sheet_texts(DevicesSheet::WifiNotice { tailnet });
        for expected in [
            WIFI_NOTICE_TITLE,
            way,
            "Wi-Fi pairing ends in two versions.",
            "OK",
            "Open Devices",
        ] {
            assert!(text.contains(expected), "6a/6b shows {expected}: {text}");
        }
    }
}

/// The Relay group restores what the old Relay and Other Macs groups did, in the layout
/// of the mockup: "Send Questions Through the Relay" in each state of the vault, "Show
/// Agents on My Other Devices" only while it is on, the other Macs of a synced vault with
/// Devices… and Add a Mac…, and the end of the free approvals (ADR 0037 D14). Frame 1 of
/// the mockup itself has no Relay group. Frame 4d after "Later" keeps its row.
#[test]
fn devices_relay_group_restores_the_relay_and_the_other_macs() {
    use devices::{
        ADD_MAC, OLD_RELAY_ENTRY, OTHER_MACS, OTHER_MACS_DEVICES, RELAY_GROUP, RELAY_QUESTIONS,
        RELAY_QUESTIONS_REMOVED_SYNC_FIX, SHOW_AGENTS, SHOW_AGENTS_NOTE,
    };
    let frame = view_texts(&frame_one());
    for gone in [
        RELAY_GROUP,
        RELAY_QUESTIONS,
        SHOW_AGENTS,
        OTHER_MACS,
        OLD_RELAY_ENTRY,
    ] {
        assert!(!frame.contains(gone), "frame 1 has no {gone}: {frame}");
    }
    let with = |questions: Questions, other_macs: Option<OtherMacsRow>, free: bool| DevicesView {
        relay: Some(RelayView {
            questions,
            feed_shown: true,
            other_macs,
            free_end: free.then(|| "0.5.20".to_owned()),
        }),
        ..frame_one()
    };
    for questions in [
        Questions::On,
        Questions::CanTurnOn,
        Questions::NeedsTeam,
        Questions::JoinTeam,
        Questions::Removed,
        Questions::RemovedSync,
        Questions::Locked,
    ] {
        let text = view_texts(&with(questions, None, false));
        let (subline, _) = questions.subline();
        for expected in [RELAY_GROUP, RELAY_QUESTIONS, subline] {
            assert!(text.contains(expected), "{questions:?}: {expected}: {text}");
        }
        assert_eq!(
            text.contains(SHOW_AGENTS) && text.contains(SHOW_AGENTS_NOTE),
            questions == Questions::On,
            "the feed switch only while the questions are on: {questions:?}: {text}"
        );
        assert_eq!(
            text.contains(RELAY_QUESTIONS_REMOVED_SYNC_FIX),
            questions == Questions::RemovedSync,
            "{text}"
        );
        assert!(!text.contains(OTHER_MACS), "{text}");
        // One add button and one blue button, as before.
        assert_eq!(text.matches(ADD_DEVICE).count(), 1, "{text}");
    }
    for words in ["End-to-end encrypted.", "Off.", "No account needed."] {
        assert!(
            [
                devices::RELAY_QUESTIONS_ON,
                devices::RELAY_QUESTIONS_OFF,
                devices::RELAY_QUESTIONS_NEW_TEAM,
            ]
            .iter()
            .any(|line| line.contains(words))
        );
    }
    // Each line of the group has 12 words or fewer.
    for line in [
        devices::RELAY_QUESTIONS_ON,
        devices::RELAY_QUESTIONS_OFF,
        devices::RELAY_QUESTIONS_NEW_TEAM,
        devices::RELAY_QUESTIONS_JOIN,
        devices::RELAY_QUESTIONS_REMOVED,
        devices::RELAY_QUESTIONS_REMOVED_SYNC,
        RELAY_QUESTIONS_REMOVED_SYNC_FIX,
        devices::RELAY_QUESTIONS_LOCKED,
        SHOW_AGENTS_NOTE,
    ] {
        assert!(line.split_whitespace().count() <= 12, "{line}");
    }

    // The other Macs of a vault that syncs through the relay, and the D14 notice.
    let text = view_texts(&with(
        Questions::On,
        Some(OtherMacsRow {
            words: "Through the Apassy relay".to_owned(),
            relay: true,
        }),
        true,
    ));
    for expected in [
        OTHER_MACS,
        "Through the Apassy relay",
        OTHER_MACS_DEVICES,
        ADD_MAC,
        devices::free_end_line("0.5.20").as_str(),
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // A folder sync names the folder and has no relay buttons.
    let text = view_texts(&with(
        Questions::CanTurnOn,
        Some(OtherMacsRow {
            words: "Through iCloud Drive".to_owned(),
            relay: false,
        }),
        false,
    ));
    assert!(text.contains("Through iCloud Drive"), "{text}");
    assert!(!text.contains(ADD_MAC), "{text}");
    assert!(!text.contains("Free approvals"), "{text}");

    // Frame 4d after "Later": the row in the This Mac group.
    let text = view_texts(&DevicesView {
        old_relay_entry: true,
        ..frame_one()
    });
    assert!(text.contains(OLD_RELAY_ENTRY), "{text}");
}

/// The texts of the steps of the add and move sheets, inside a sheet.
fn step_texts(draw: impl Fn(&mut egui::Ui)) -> String {
    joined(&step_rects(draw))
}

/// The painted texts of a sheet step, with their rectangles.
fn step_rects(draw: impl Fn(&mut egui::Ui)) -> Vec<(String, Rect)> {
    let ctx = egui::Context::default();
    let mut texts = Vec::new();
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, DEFAULT)),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| {
            super::super::kit::sheet(ui.ctx(), "test-step", 440.0, |ui| draw(ui));
        });
        texts.clear();
        for clipped in &output.shapes {
            texts_of(&clipped.shape, clipped.clip_rect, &mut texts);
        }
        output.drop_without_applying_deltas();
    }
    texts
}

/// The rectangle of the first painted text equal to `text`.
fn rect_of(texts: &[(String, Rect)], text: &str) -> Rect {
    texts
        .iter()
        .find(|(painted, _)| painted == text)
        .map(|(_, rect)| *rect)
        .unwrap_or_else(|| panic!("{text} not painted: {}", joined(texts)))
}

/// A stand-in for the QR code: a 120-point square with the text "QR" in its center.
fn fake_qr(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(120.0), egui::Sense::hover());
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        "QR",
        egui::FontId::proportional(12.0),
        egui::Color32::BLACK,
    );
}

/// Frames 2a and 4b: the route chip sits under the QR code, centered on it.
#[test]
fn devices_route_chip_sits_under_the_qr_code() {
    use devices::{LinkStep, MovePhase};
    let node = LinkStep {
        route: Route::Mac,
        shown: Some(devices::shown_link("https://100.101.7.12:8444/link#code")),
        seconds_left: Some(9 * 60 + 41),
    };
    let add = step_rects(|ui| {
        devices::link_step(ui, &node, fake_qr, |_| {});
    });
    let moving = step_rects(|ui| {
        devices::move_step(
            ui,
            "Rafal's iPhone",
            MovePhase::Scan,
            Some(&node),
            fake_qr,
            |_| {},
        );
    });
    for (frame, texts) in [("2a", &add), ("4b", &moving)] {
        let qr = rect_of(texts, "QR");
        let chip = rect_of(texts, "via your Mac");
        assert!(
            chip.top() > qr.bottom() + 40.0,
            "{frame}: the chip is under the QR code: {chip:?} {qr:?}"
        );
        assert!(
            (chip.center().x - qr.center().x).abs() < 2.0,
            "{frame}: the chip is centered on the QR code: {chip:?} {qr:?}"
        );
    }
    // Expired: no QR code, the chip stays under the lead.
    let expired = LinkStep {
        seconds_left: Some(0),
        ..node
    };
    let texts = step_rects(|ui| {
        devices::link_step(ui, &expired, fake_qr, |_| {});
    });
    assert!(!joined(&texts).contains("QR"), "{}", joined(&texts));
    assert!(
        joined(&texts).contains("via your Mac"),
        "{}",
        joined(&texts)
    );
}

/// "Devices ⓘ 6" has the space of a group label above it, and its rows follow at the
/// same distance as under "This Mac": no second space between the label and the rows.
#[test]
fn devices_rows_follow_their_label_as_under_this_mac() {
    let texts = view_rects(&frame_one());
    let this_mac = rect_of(&texts, "This Mac");
    let reachable = rect_of(&texts, devices::ROUTE_SWITCH);
    let first = rect_of(&texts, "Mac mini (office)");
    // The group label: the last "Devices" above the first row.
    let label = texts
        .iter()
        .rev()
        .find(|(text, rect)| text == "Devices" && rect.bottom() < first.top())
        .map(|(_, rect)| *rect)
        .expect("the Devices label");
    let under_this_mac = reachable.top() - this_mac.bottom();
    let under_devices = first.top() - label.bottom();
    assert!(
        (under_devices - under_this_mac).abs() < 6.0,
        "the rows follow the label: {under_devices} vs {under_this_mac}"
    );
}

/// Frames 2a–2c and 4b–4d use the exact texts of the mockup table.
#[test]
fn devices_add_and_move_sheets_use_the_mockup_texts() {
    use devices::{LinkStep, MovePhase};
    let node = LinkStep {
        route: Route::Mac,
        shown: Some(devices::shown_link(
            "https://100.101.7.12:8444/link#code&pin=x",
        )),
        seconds_left: Some(9 * 60 + 41),
    };
    // 2a.
    let text = step_texts(|ui| {
        devices::link_step(ui, &node, |_| {}, |_| {});
    });
    for expected in [
        "Add a Device",
        "Scan with the Apassy app on the iPhone.",
        "via your Mac",
        "Link",
        "https://100.101.7.12:8444/link#…",
        "Copy",
        "Expires In",
        "9:41",
        "On a Mac, paste the link instead.",
        "Cancel",
    ] {
        assert!(text.contains(expected), "2a: {expected}: {text}");
    }
    assert!(!text.contains("pin=x"), "the field shows no secret: {text}");
    // 2a through hosted Connect: the chip only changes, and nothing goes to the pasteboard.
    let hosted = LinkStep {
        route: Route::Relay,
        shown: None,
        ..node.clone()
    };
    let text = step_texts(|ui| {
        devices::link_step(ui, &hosted, |_| {}, |_| {});
    });
    assert!(text.contains("via Apassy relay"), "{text}");
    for gone in ["Copy", "On a Mac, paste the link instead."] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
    // 2a expired: "The link expired." and New Link only.
    let expired = LinkStep {
        seconds_left: Some(0),
        ..node.clone()
    };
    let text = step_texts(|ui| {
        devices::link_step(ui, &expired, |_| {}, |_| {});
    });
    assert!(text.contains("The link expired."), "{text}");
    assert!(text.contains("New Link"), "{text}");
    for gone in [
        "Cancel",
        "Expires In",
        "Scan with the Apassy app on the iPhone.",
    ] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
    // 2b, for an iPhone and for a Mac.
    let text = step_texts(|ui| {
        devices::join_step(
            ui,
            "Rafal's iPhone",
            Kind::Iphone,
            "amber falcon",
            Route::Mac,
            true,
            |_| {},
        );
    });
    for expected in [
        "Rafal's iPhone Wants to Join",
        "Confirm only if the iPhone shows these words.",
        "amber falcon",
        "Kind",
        "iPhone",
        "Route",
        "via your Mac",
        "Refuse",
        "Confirm…",
    ] {
        assert!(text.contains(expected), "2b: {expected}: {text}");
    }
    assert_eq!(
        devices::join_lead(Kind::Mac),
        "Confirm only if the Mac shows these words."
    );
    // 2c: the Tailscale line only for a node device.
    let text = step_texts(|ui| {
        devices::added_step(ui, "Rafal's iPhone", false, true, |_| {});
    });
    for expected in [
        "Rafal's iPhone Added",
        "It approves runs through this Mac.",
        "The iPhone needs Tailscale on to reach this Mac.",
        "Done",
    ] {
        assert!(text.contains(expected), "2c: {expected}: {text}");
    }
    let text = step_texts(|ui| {
        devices::added_step(ui, "Rafal's iPhone", false, false, |_| {});
    });
    assert!(!text.contains("Tailscale"), "{text}");
    // 4b while the iPhone scans, and after the join (no Cancel).
    let text = step_texts(|ui| {
        devices::move_step(
            ui,
            "Rafal's iPhone",
            MovePhase::Scan,
            Some(&node),
            |_| {},
            |_| {},
        );
    });
    for expected in [
        "Move Approvals to This Mac",
        "Your iPhone pairs again, with this Mac.",
        "Approvals team made here",
        "Scan with Rafal's iPhone",
        "Then check the words on both.",
        "Remove from Apassy relay",
        "via your Mac",
        "Cancel",
    ] {
        assert!(text.contains(expected), "4b: {expected}: {text}");
    }
    let text = step_texts(|ui| {
        devices::move_step(
            ui,
            "Rafal's iPhone",
            MovePhase::Removing,
            None,
            |_| {},
            |_| {},
        );
    });
    assert!(text.contains("Remove from Apassy relay"), "{text}");
    assert!(!text.contains("Cancel"), "no cancel after the join: {text}");
    // 4c.
    let text = step_texts(|ui| {
        devices::moved_step(
            ui,
            &["Rafal's iPhone".to_owned()],
            true,
            &["Rafal's Apple Watch".to_owned()],
        );
    });
    for expected in [
        "Approvals Moved",
        "Questions now go through this Mac.",
        "Rafal's iPhone",
        "via your Mac",
        "Removed from Apassy relay",
        "Pair Rafal's Apple Watch again from the iPhone.",
        "Done",
    ] {
        assert!(text.contains(expected), "4c: {expected}: {text}");
    }
    let text = step_texts(|ui| {
        devices::moved_step(ui, &["Rafal's iPhone".to_owned()], false, &[]);
    });
    for gone in ["Removed from Apassy relay", "Pair "] {
        assert!(
            !text.contains(gone),
            "4c without a removal or a watch: {gone}: {text}"
        );
    }
    // 4d.
    let text = step_texts(|ui| {
        devices::old_entry_step(ui, false);
    });
    for expected in [
        "Old Entry Still on Relay",
        "Approvals already use this Mac.",
        "Apassy relay did not answer the removal.",
        "Later",
    ] {
        assert!(text.contains(expected), "4d: {expected}: {text}");
    }
    assert!(
        !text.contains("Try Again"),
        "no hosted team to ask again: {text}"
    );
    let text = step_texts(|ui| {
        devices::old_entry_step(ui, true);
    });
    assert!(
        text.contains("Try Again") && text.contains("Later"),
        "{text}"
    );
}

/// The switch with `label` in the AccessKit tree of one frame: its center, whether it
/// is on, and whether it is disabled.
fn switch_in(ctx: &egui::Context, app: &mut DesktopApp, label: &str) -> Option<(Pos2, bool, bool)> {
    let input = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, TALL)),
        ..Default::default()
    };
    let output = ctx.run_ui(input, |ui| super::super::draw(app, ui));
    let mut found = None;
    if let Some(update) = &output.platform_output.accesskit_update {
        for (_, node) in &update.nodes {
            if node.label() == Some(label)
                && let Some(toggled) = node.toggled()
                && let Some(bounds) = node.bounds()
            {
                let center = Pos2::new(
                    ((bounds.x0 + bounds.x1) / 2.0) as f32,
                    ((bounds.y0 + bounds.y1) / 2.0) as f32,
                );
                found = Some((
                    center,
                    toggled == egui::accesskit::Toggled::True,
                    node.is_disabled(),
                ));
            }
        }
    }
    output.drop_without_applying_deltas();
    found
}

/// "Send Questions Through the Relay" in Settings > Devices: on opens the owner check
/// for exactly the relay sync team and changes nothing before it passes; then "Show
/// Agents on My Other Devices" shows and its switch keeps the choice; off needs no check
/// and keeps relay sync.
#[test]
fn the_relay_switch_needs_the_owner_check_and_off_needs_none() {
    use crate::relay::membership::{QuestionsAvailability, questions_availability};
    use devices::{RELAY_QUESTIONS, SHOW_AGENTS};
    let relay = fake_relay::FakeRelay::start();
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Devices);
    let vault = app.owner_ui.session.shared_vault();
    let key = crate::sync::DeviceKey::generate().expect("key");
    vault
        .lock()
        .unwrap()
        .as_mut()
        .expect("open vault")
        .set_relay_device(&crate::vault::RelayDevice {
            relay_url: relay.url.clone(),
            team_id: "t_7k2m5q4x3c".to_owned(),
            device_id: 2,
            public_key: key.public_key().to_vec(),
            key_pkcs8: key.pkcs8().expect("pkcs8").clone(),
            created_at: 0,
            account_key: false,
        })
        .expect("relay row");
    let availability = |app: &DesktopApp| {
        let shared = app.owner_ui.session.shared_vault();
        let guard = shared.lock().unwrap();
        questions_availability(guard.as_ref().expect("open vault")).unwrap()
    };
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    let mut switch = None;
    for _ in 0..3 {
        switch = switch_in(&ctx, &mut app, RELAY_QUESTIONS);
    }
    let (at, on, disabled) = switch.expect("the relay switch is in the AccessKit tree");
    assert!(!on && !disabled, "off, and it can move");
    assert!(
        switch_in(&ctx, &mut app, SHOW_AGENTS).is_none(),
        "no feed switch while off"
    );
    click(&ctx, &mut app, TALL, at);
    let request = app
        .owner
        .check
        .as_ref()
        .expect("on opens the owner check")
        .request
        .clone();
    assert_eq!(
        request.action(),
        OwnerAction::EnableRelayQuestions {
            relay_url: relay.url.clone(),
            team_id: Some("t_7k2m5q4x3c".to_owned()),
        }
    );
    assert!(
        matches!(availability(&app), QuestionsAvailability::CanTurnOn { .. }),
        "nothing changes before the check"
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(matches!(
        availability(&app),
        QuestionsAvailability::On { .. }
    ));

    // On: the feed switch shows, on by default; off keeps the choice.
    let mut feed = None;
    for _ in 0..3 {
        feed = switch_in(&ctx, &mut app, SHOW_AGENTS);
    }
    let (at, shown, _) = feed.expect("the feed switch shows while the questions are on");
    assert!(shown, "on by default");
    assert!(!app.ui.feed_off);
    click(&ctx, &mut app, TALL, at);
    assert!(app.ui.feed_off, "the switch turns the feed off");

    // Off needs no owner check and keeps relay sync.
    let mut switch = None;
    for _ in 0..3 {
        switch = switch_in(&ctx, &mut app, RELAY_QUESTIONS);
    }
    let (at, on, _) = switch.expect("the relay switch");
    assert!(on);
    click(&ctx, &mut app, TALL, at);
    assert!(app.owner.check.is_none(), "off needs no owner check");
    assert!(matches!(
        availability(&app),
        QuestionsAvailability::CanTurnOn { .. }
    ));
    let guard = vault.lock().unwrap();
    assert_eq!(
        guard
            .as_ref()
            .expect("open vault")
            .relay_device()
            .unwrap()
            .expect("relay sync stays")
            .team_id,
        "t_7k2m5q4x3c"
    );
}

/// The route switch and every revoke go through the owner check: the requests name
/// exactly what changes, and a proof of another action changes nothing.
#[test]
fn the_route_switch_and_revoke_name_their_owner_check() {
    let on = OwnerRequest::SetTailnetRoute { on: true };
    assert_eq!(on.action(), OwnerAction::SetTailnetRoute { on: true });
    assert!(
        on.describe()
            .starts_with("Make this Mac reachable on your tailnet."),
        "{}",
        on.describe()
    );
    assert_eq!(
        OwnerRequest::SetTailnetRoute { on: false }.action(),
        OwnerAction::SetTailnetRoute { on: false }
    );
    let revoke = OwnerRequest::RevokeNodeDevice(devices::RevokeRequest {
        team_id: "t_node".to_owned(),
        devices: vec![(2, String::new()), (3, String::new())],
        device_name: "Rafal's iPhone".to_owned(),
        node: true,
        linux_vault: None,
    });
    assert_eq!(
        revoke.action(),
        OwnerAction::RevokeNodeDevice {
            team_id: "t_node".to_owned(),
            device_ids: vec![2, 3],
            device_name: "Rafal's iPhone".to_owned(),
        }
    );
    assert!(
        revoke.describe().starts_with("Revoke \"Rafal's iPhone\"."),
        "{}",
        revoke.describe()
    );
    assert_eq!(
        OwnerAction::SetTailnetRoute { on: true }.touch_id_title(),
        "Reach this Mac on your tailnet"
    );
    assert!(
        !OwnerAction::SetTailnetRoute { on: true }
            .reason()
            .is_empty()
    );

    // The completion checks the proof: a proof of another action changes nothing.
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let other = app
        .owner_gate()
        .authorize(
            OwnerAction::SetTailnetRoute { on: false },
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    app.devices_set_route(true, other);
    assert!(
        app.status_text.contains("did not match"),
        "{}",
        app.status_text
    );
    let setting = app
        .owner_ui
        .session
        .with_vault(|vault| vault.cloud_node_setting().map(|s| s.tailnet_on).ok())
        .flatten();
    assert_ne!(setting, Some(true), "the route stays off");
}

/// Devices of a vault without a team: only this Mac, the hint row, and the one add
/// button. Without Tailscale the switch cannot move. A lock leaves Settings.
#[test]
fn devices_of_a_vault_without_a_team_show_this_mac_and_the_add_button() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Devices);
    let (text, _) = frames(&mut app, TALL);
    for expected in [
        ROUTE_SWITCH,
        ROUTE_OFF,
        "Tailscale is not installed.",
        ONLY_THIS_MAC,
        ADD_DEVICE,
    ] {
        assert!(text.contains(expected), "shows {expected}: {text}");
    }
    assert_eq!(
        super::status_line(&app, SettingsSection::Devices),
        "This Mac only"
    );
    // The switch is disabled: no Tailscale, no route.
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    let mut switch = None;
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, TALL)),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| super::super::draw(&mut app, ui));
        if let Some(update) = &output.platform_output.accesskit_update {
            for (_, node) in &update.nodes {
                if node.label() == Some(ROUTE_SWITCH) && node.toggled().is_some() {
                    switch = Some((node.is_disabled(), node.toggled()));
                }
            }
        }
        output.drop_without_applying_deltas();
    }
    let (disabled, toggled) = switch.expect("the route switch is in the AccessKit tree");
    assert!(disabled, "no Tailscale: the switch does not move");
    assert_eq!(toggled, Some(egui::accesskit::Toggled::False));

    // A lock leaves Settings.
    app.owner_ui.session.lock().expect("lock");
    frames(&mut app, TALL);
    assert!(app.place.is_credentials(), "a lock leaves Settings");
}

/// With relay sync, turning the approvals on is a new channel that can approve runs: it
/// opens the owner check for exactly the sync team, and nothing changes before it passes.
/// Then the devices of the vault show with their route, and Revoke… of an iPhone opens
/// its sheet; Revoke there asks the owner check, and only the right proof removes the
/// iPhone. Off needs no check and keeps relay sync.
#[test]
fn devices_list_the_team_and_revoke_needs_the_owner_check() {
    use crate::relay::membership::{QuestionsAvailability, questions_availability};
    // The device list of Devices goes to this relay on 127.0.0.1, never to the network.
    let relay = fake_relay::FakeRelay::start();
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Devices);
    let vault = app.owner_ui.session.shared_vault();
    let key = crate::sync::DeviceKey::generate().expect("key");
    vault
        .lock()
        .unwrap()
        .as_mut()
        .expect("open vault")
        .set_relay_device(&crate::vault::RelayDevice {
            relay_url: relay.url.clone(),
            team_id: "t_7k2m5q4x3c".to_owned(),
            device_id: 2,
            public_key: key.public_key().to_vec(),
            key_pkcs8: key.pkcs8().expect("pkcs8").clone(),
            created_at: 0,
            account_key: false,
        })
        .expect("relay row");

    let unchanged = |app: &DesktopApp| {
        let shared = app.owner_ui.session.shared_vault();
        let guard = shared.lock().unwrap();
        let open = guard.as_ref().expect("open vault");
        assert_eq!(
            questions_availability(open).unwrap(),
            QuestionsAvailability::CanTurnOn {
                team_id: "t_7k2m5q4x3c".to_owned()
            }
        );
        assert!(open.question_key().unwrap().is_none());
        assert!(open.trusted_devices().unwrap().is_empty());
    };
    app.questions_turn_on(None);
    let request = app
        .owner
        .check
        .as_ref()
        .expect("owner check")
        .request
        .clone();
    let expected = OwnerAction::EnableRelayQuestions {
        relay_url: relay.url.clone(),
        team_id: Some("t_7k2m5q4x3c".to_owned()),
    };
    assert_eq!(request.action(), expected);
    unchanged(&app);
    assert_eq!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG)),
        Err(OwnerAuthError::WrongPassphrase)
    );
    unchanged(&app);
    app.questions_turn_on(None);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    {
        let guard = vault.lock().unwrap();
        let open = guard.as_ref().expect("open vault");
        assert_eq!(
            questions_availability(open).unwrap(),
            QuestionsAvailability::On {
                team_id: "t_7k2m5q4x3c".to_owned()
            }
        );
    }
    let (text, _) = frames(&mut app, TALL);
    assert!(
        text.contains("This Mac") && text.contains(ADD_DEVICE),
        "{text}"
    );

    // An iPhone linked through the relay: a row with its route and Revoke….
    let sign = crate::sync::DeviceKey::generate().expect("key");
    let answer = crate::sync::DeviceKey::generate().expect("key");
    let uuid = "5d2c9e1a-7b3f-4c8d-9e0a-1b2c3d4e5f60";
    vault
        .lock()
        .unwrap()
        .as_mut()
        .expect("open vault")
        .register_trusted_device(
            uuid,
            "Synthetic iPhone",
            crate::vault::TrustedDeviceKind::Iphone,
            sign.public_key(),
            Some(answer.public_key()),
        )
        .expect("iPhone row");
    assert_eq!(
        super::status_line(&app, SettingsSection::Devices),
        "2 devices"
    );
    let ctx = egui::Context::default();
    let mut texts = Vec::new();
    for _ in 0..3 {
        texts = frame(&ctx, &mut app, TALL, Vec::new());
    }
    let text = joined(&texts);
    for expected in [
        "Synthetic iPhone",
        "iPhone · Approves runs",
        "via Apassy relay",
        "Revoke…",
    ] {
        assert!(text.contains(expected), "shows {expected}: {text}");
    }
    let at = center_of(&texts, "Revoke…", TALL.x).expect("Revoke… is painted");
    click(&ctx, &mut app, TALL, at);
    assert!(
        matches!(&app.ui.devices.sheet, Some(DevicesSheet::Revoke { device, .. }) if device.name == "Synthetic iPhone"),
        "Revoke… opens its sheet"
    );
    assert!(app.owner.check.is_none(), "no owner check before Revoke");
    let texts = frame(&ctx, &mut app, TALL, Vec::new());
    assert!(
        texts
            .iter()
            .any(|(text, _)| text == "Revoke Synthetic iPhone?"),
        "the sheet shows: {}",
        joined(&texts)
    );
    let revoke = texts
        .iter()
        .find(|(text, _)| text == "Revoke")
        .map(|(_, rect)| rect.center())
        .expect("the Revoke button is painted");
    click(&ctx, &mut app, TALL, revoke);
    assert!(app.ui.devices.sheet.is_none(), "the sheet closes");
    let request = app
        .owner
        .check
        .as_ref()
        .expect("the owner check opens")
        .request
        .clone();
    assert!(
        matches!(&request, OwnerRequest::RevokeNodeDevice(r) if r.device_name == "Synthetic iPhone" && !r.node),
        "{request:?}"
    );
    let present = |app: &DesktopApp| {
        let shared = app.owner_ui.session.shared_vault();
        let guard = shared.lock().unwrap();
        guard
            .as_ref()
            .expect("open vault")
            .trusted_devices()
            .unwrap()
            .iter()
            .any(|device| device.uuid == uuid)
    };
    assert_eq!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG)),
        Err(OwnerAuthError::WrongPassphrase)
    );
    assert!(present(&app), "a wrong passphrase revokes nothing");
    app.ask_owner(request.clone(), None);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(!present(&app), "the right proof revokes the iPhone");
    assert!(
        app.status_text.contains("Synthetic iPhone revoked"),
        "{}",
        app.status_text
    );

    // Off: stricter, no check; relay sync stays.
    app.questions_turn_off();
    assert!(app.owner.check.is_none(), "off needs no owner check");
    let guard = vault.lock().unwrap();
    let open = guard.as_ref().expect("open vault");
    assert_eq!(
        open.relay_device()
            .unwrap()
            .expect("relay sync stays")
            .team_id,
        "t_7k2m5q4x3c"
    );
}

/// What Devices says of each device of the questions: its kind, how it answers, and the
/// push state of an iPhone only when the relay tells it.
#[test]
fn device_rows_say_how_each_device_answers() {
    use super::super::sync::questions::device_words;
    use crate::vault::{TrustedDevice, TrustedDeviceKind};
    let device = |kind, answer_key: Option<Vec<u8>>| TrustedDevice {
        uuid: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d".to_owned(),
        name: "Synthetic device".to_owned(),
        kind,
        relay_devices: Default::default(),
        sign_key: vec![4; 65],
        answer_key,
        created_at: 0,
        updated_at: 0,
        updated_by: String::new(),
    };
    let mac = device(TrustedDeviceKind::Mac, None);
    assert_eq!(device_words(&mac, true, None), "This Mac");
    assert_eq!(
        device_words(&mac, false, None),
        "Mac · answers after Touch ID"
    );
    let phone = device(TrustedDeviceKind::Iphone, Some(vec![4; 65]));
    assert_eq!(
        device_words(&phone, false, None),
        "iPhone · answers with Face ID"
    );
    assert_eq!(
        device_words(&phone, false, Some(true)),
        "iPhone · answers with Face ID · Push on"
    );
    assert_eq!(
        device_words(&phone, false, Some(false)),
        "iPhone · answers with Face ID · Push off"
    );
    let waiting = device(TrustedDeviceKind::Iphone, None);
    assert_eq!(
        device_words(&waiting, false, None),
        "iPhone · its Face ID key has not synced yet"
    );
}

/// An Apple Watch in Devices (ADR 0039): "(Apple Watch)" after its name, what it can do,
/// no push state (it registers no push token in v1), and the words of its removal.
#[test]
fn a_watch_row_names_its_kind() {
    use super::super::sync::questions::{device_label, device_words, removal_words};
    use crate::vault::{TrustedDevice, TrustedDeviceKind};
    let device = |kind, answer_key: Option<Vec<u8>>| TrustedDevice {
        uuid: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d".to_owned(),
        name: "Test Watch".to_owned(),
        kind,
        relay_devices: Default::default(),
        sign_key: vec![4; 65],
        answer_key,
        created_at: 0,
        updated_at: 0,
        updated_by: String::new(),
    };
    let watch = device(TrustedDeviceKind::Watch, Some(vec![4; 65]));
    assert_eq!(device_label(&watch), "Test Watch (Apple Watch)");
    for push in [None, Some(true), Some(false)] {
        assert_eq!(
            device_words(&watch, false, push),
            "Apple Watch · allows access requests once, on a wrist"
        );
    }
    assert_eq!(
        device_words(&device(TrustedDeviceKind::Watch, None), false, None),
        "Apple Watch · its answer key is missing; connect it again"
    );
    assert_eq!(
        device_label(&device(TrustedDeviceKind::Iphone, None)),
        "Test Watch"
    );
    assert!(
        removal_words(TrustedDeviceKind::Watch, false)
            .contains("so this Apple Watch cannot read the next questions")
    );
}

#[test]
fn bouncer_status_requires_inference_readiness_including_external_mode() {
    use crate::broker::model_server::{Problem, ServerState};
    assert!(super::model_ready(&ServerState::Running {
        model: None,
        outside: false
    }));
    assert!(super::model_ready(&ServerState::External {
        up: Some(true),
        model: None
    }));
    for state in [
        ServerState::Off,
        ServerState::Stopped,
        ServerState::External {
            up: None,
            model: None,
        },
        ServerState::External {
            up: Some(false),
            model: None,
        },
        ServerState::Starting {
            since: std::time::Instant::now(),
        },
        ServerState::Failed {
            problem: Problem::Readiness("failed inference".into()),
            log_tail: vec![],
        },
    ] {
        assert!(!super::model_ready(&state), "{state:?}");
    }
}

#[test]
fn today_uses_local_calendar_boundaries_including_dst_and_skipped_midnight() {
    use time::{Date, Month, UtcOffset};
    let ts = |year, month, day, hour| {
        Date::from_calendar_date(year, Month::try_from(month).unwrap(), day)
            .unwrap()
            .with_hms(hour, 0, 0)
            .unwrap()
            .assume_utc()
            .unix_timestamp() as u64
    };
    for (offset, start, end) in [
        (-7 * 3600, ts(2026, 10, 31, 7), ts(2026, 11, 1, 7)),
        (
            5 * 3600 + 45 * 60,
            ts(2026, 10, 30, 18) + 900,
            ts(2026, 10, 31, 18) + 900,
        ),
    ] {
        assert_eq!(
            super::local_day_bounds_with(ts(2026, 10, 31, 12), |_| {
                UtcOffset::from_whole_seconds(offset).ok()
            }),
            Some((start, end))
        );
    }
    for (transition, before, after, now, start, end) in [
        (
            ts(2026, 3, 29, 1),
            1,
            2,
            ts(2026, 3, 29, 12),
            ts(2026, 3, 28, 23),
            ts(2026, 3, 29, 22),
        ),
        (
            ts(2026, 10, 25, 1),
            2,
            1,
            ts(2026, 10, 25, 12),
            ts(2026, 10, 24, 22),
            ts(2026, 10, 25, 23),
        ),
        (
            ts(2018, 11, 4, 3),
            -3,
            -2,
            ts(2018, 11, 4, 12),
            ts(2018, 11, 4, 3),
            ts(2018, 11, 5, 2),
        ),
    ] {
        assert_eq!(
            super::local_day_bounds_with(now, |at| {
                UtcOffset::from_whole_seconds(if at.unix_timestamp() < transition as i64 {
                    before * 3600
                } else {
                    after * 3600
                })
                .ok()
            }),
            Some((start, end))
        );
    }
    assert!(super::local_day_bounds_with(ts(2026, 10, 31, 12), |_| None).is_none());
}

#[test]
fn security_owner_frequency_defaults_every_time_and_names_covered_actions() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.place = Place::Settings;
    app.ui.settings_section = SettingsSection::Security;
    let (text, _) = frames(&mut app, TALL);
    for expected in ["Lock after inactivity", "Never", "Every time"] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    // Linux: with no observer (this test starts none) nothing is observed, so reuse is
    // off and the texts say why; macOS can reuse its owner window.
    let expected: &[&str] = if cfg!(target_os = "linux") {
        &[
            "How often to ask",
            "Each sensitive action requires fresh confirmation with the vault passphrase or optional system authentication.",
            "Approval reuse is off: Apassy cannot observe the screen lock here.",
            "Lock the vault manually when you finish.",
            "Screen lock is not observed here",
            "Inactivity counts only input in the Apassy window",
            "Agents cannot use credentials while the vault is locked.",
        ]
    } else {
        &[
            "Agents can't use your credentials while the vault is locked.",
            "How often to ask for Touch ID",
            "After you confirm with Touch ID or your passphrase",
            "Apassy doesn't ask again for anything until this time is up",
            "Mac locks or sleeps",
        ]
    };
    for expected in expected {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    if cfg!(target_os = "linux") {
        for unavailable in [
            "Touch ID",
            "Apassy doesn't ask again for anything until this time is up",
            "Mac locks or sleeps",
            "unavailable on Linux",
        ] {
            assert!(
                !text.contains(unavailable),
                "unexpected {unavailable}: {text}"
            );
        }
    }
}

/// The Security texts for full and partial observation (Linux renders them; the text
/// functions themselves are tested on every platform in `session_watch`).
#[test]
fn security_lock_texts_follow_the_observed_sources() {
    use crate::native::session_lock::Observation;
    if !cfg!(target_os = "linux") {
        return;
    }
    let full = Observation {
        session_bus: true,
        logind: true,
        logind_session: true,
        screen_saver: true,
        idle_hint: true,
        sleep_inhibitor: true,
    };
    let partial = Observation {
        screen_saver: false,
        idle_hint: false,
        ..full
    };
    for (obs, expected, absent) in [
        (
            full,
            &[
                "Apassy doesn't ask again for anything until this time is up",
                "The window ends when the screen locks, the computer sleeps, or you switch user.",
                "observed through systemd-logind and the screen saver service",
                "while the desktop reports the session idle",
            ][..],
            &["Approval reuse is off", "Not observed", "manually"][..],
        ),
        (
            partial,
            &[
                "The window ends at every lock and sleep that Apassy observes.",
                "Not observed: No screen saver service answers on the session bus",
                "Apassy observes only part of this session.",
                "Inactivity counts only input in the Apassy window",
            ][..],
            &["Approval reuse is off", "manually"][..],
        ),
    ] {
        let dir = TempDir::new().unwrap();
        let (mut app, _) = unlocked_app_with_item(&dir);
        app.place = Place::Settings;
        app.ui.settings_section = SettingsSection::Security;
        app.owner.session.fixed = Some(obs);
        let (text, _) = frames(&mut app, TALL);
        for expected in expected {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        for absent in absent {
            assert!(!text.contains(absent), "unexpected {absent}: {text}");
        }
    }
}

/// A fake signal source drives the real app: a screen lock ends the owner window and,
/// under "When the screen locks", locks the vault; a sleep locks it too.
#[test]
fn security_observed_lock_and_sleep_lock_the_vault_and_end_reuse() {
    use crate::broker::approvals::{CheckMethod, OwnerFrequency};
    use crate::desktop::auto_lock::LockPolicy;
    use crate::desktop::session_watch::Applier;
    use crate::native::session_lock::{Observation, SessionEvent};
    let full = Observation {
        session_bus: true,
        logind: true,
        logind_session: true,
        screen_saver: true,
        idle_hint: false,
        sleep_inhibitor: false,
    };
    for event in [SessionEvent::ScreenLocked, SessionEvent::Sleep] {
        let dir = TempDir::new().unwrap();
        let (mut app, _) = unlocked_app_with_item(&dir);
        let window = app.owner_ui.session.owner_window.clone();
        window.configure(OwnerFrequency::UntilLock);
        let applier = Applier::new(window.clone(), app.auto_lock.source.clone(), full);
        applier.apply(SessionEvent::ScreenUnlocked);
        applier.apply(SessionEvent::SessionActive);
        let epoch = app.owner_ui.session.epoch().unwrap();
        window.seed(epoch, CheckMethod::Passphrase, window.generation());
        let (proof, _) = window.ticket(epoch).expect("reuse while observed");
        app.auto_lock.policy = LockPolicy::Session;
        let ctx = egui::Context::default();
        app.poll_auto_lock(&ctx);
        assert!(!app.owner_ui.session.is_locked());
        applier.apply(event);
        assert!(!proof.valid(), "{event:?}");
        assert!(window.ticket(epoch).is_none(), "{event:?}");
        app.poll_auto_lock(&ctx);
        assert!(app.owner_ui.session.is_locked(), "{event:?}");
    }
}

// ---------------------------------------------------------------- bouncer brain host

/// The stored hosting choice of the open vault (plan 0035 J1).
fn stored_hosting(app: &DesktopApp) -> Option<crate::vault::BouncerHost> {
    let shared = app.owner_ui.session.shared_vault();
    let guard = shared.lock().unwrap();
    guard
        .as_ref()
        .expect("open vault")
        .bouncer_host(crate::vault::BouncerHostRole::Hosting)
        .expect("hosting row")
}

/// The generated token of the open "Use My Server" sheet.
fn draft_token(app: &DesktopApp) -> String {
    app.bouncer_host
        .draft
        .as_ref()
        .expect("draft")
        .token_copy()
        .to_string()
}

/// Settings > Bouncer starts on This Mac: one "Runs on" row, no note, no fallback, and
/// the start rows of the local bouncer brain stay.
#[test]
fn the_runs_on_row_starts_on_this_mac() {
    use crate::desktop::brain_hosting_ui::{FALLBACK_HEADLINE, GATE_STAYS, RUNS_ON};
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Bouncer);
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(RUNS_ON), "{text}");
    assert!(text.contains("This Mac"), "{text}");
    assert!(!text.contains(GATE_STAYS), "{text}");
    assert!(!text.contains(FALLBACK_HEADLINE), "{text}");
    assert_eq!(stored_hosting(&app), None);
}

/// "Use My Server" ends in the fresh owner check of exactly that change, whose text has
/// the trust warning (ADR 0035 section 5). Nothing is stored before the check passes; a
/// wrong passphrase stores nothing. After it, the vault has the server with the
/// generated token, and neither Settings nor the status message shows the token.
#[test]
fn the_hosting_picker_needs_the_owner_check_and_shows_the_trust_warning() {
    use crate::desktop::brain_hosting_ui::{
        self as hosting, GATE_STAYS, HostingStep, RunsOnAction,
    };
    use crate::vault::{BouncerHostKind, HOSTING_CONSENT_VERSION};
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Bouncer);
    hosting::apply(&mut app, RunsOnAction::MyServer, None);
    assert_eq!(app.ui.sheet, Some(super::super::Sheet::BrainHosting));
    assert!(app.owner.check.is_none(), "the sheet comes first");
    let token = draft_token(&app);
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(hosting::SERVER_TITLE), "{text}");
    assert!(text.contains(hosting::RUN_HEADER), "{text}");
    assert!(text.contains("docker run"), "{text}");
    assert!(text.contains("LAYA_API_KEY_FILE="), "{text}");
    assert!(text.contains(hosting::START_NOTE), "{text}");
    assert!(text.contains("Paste a Token"), "{text}");
    assert!(!text.contains(&token), "the token is masked: {text}");

    // A wrong address keeps step 1 and says why.
    {
        let draft = app.bouncer_host.draft.as_mut().expect("draft");
        draft.address = "http://brain.synthetic.ts.net".to_owned();
        assert!(draft.change().is_none());
    }
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(hosting::ADDRESS_HINT), "{text}");
    hosting::submit(&mut app, None);
    assert!(app.owner.check.is_none(), "no check without a valid change");

    {
        let draft = app.bouncer_host.draft.as_mut().expect("draft");
        draft.address = "https://brain.synthetic.ts.net/".to_owned();
        draft.step = HostingStep::Consent;
    }
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(hosting::TRUST_WARNING), "{text}");
    hosting::submit(&mut app, None);
    let request = app
        .owner
        .check
        .as_ref()
        .expect("owner check")
        .request
        .clone();
    let expected = OwnerAction::ChangeBouncerHosting {
        kind: BouncerHostKind::OwnServer,
        url: "https://brain.synthetic.ts.net".to_owned(),
        consent_version: HOSTING_CONSENT_VERSION,
    };
    assert_eq!(request.action(), expected);
    assert!(request.action().needs_fresh_local_check());
    let words = request.describe();
    assert!(words.contains("someone else controls"), "{words}");
    assert!(words.contains("https://brain.synthetic.ts.net"), "{words}");
    assert!(!words.contains(&token), "{words}");
    assert!(!format!("{request:?}").contains(&token));
    assert_eq!(stored_hosting(&app), None, "nothing before the check");

    assert_eq!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG)),
        Err(OwnerAuthError::WrongPassphrase)
    );
    assert_eq!(
        stored_hosting(&app),
        None,
        "nothing after a wrong passphrase"
    );

    hosting::submit(&mut app, None);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let host = stored_hosting(&app).expect("stored host");
    assert_eq!(host.kind, BouncerHostKind::OwnServer);
    assert_eq!(host.url, "https://brain.synthetic.ts.net");
    assert_eq!(host.consent_version, HOSTING_CONSENT_VERSION);
    {
        let shared = app.owner_ui.session.shared_vault();
        let guard = shared.lock().unwrap();
        let bearer = guard
            .as_ref()
            .expect("open vault")
            .bouncer_host_bearer(crate::vault::BouncerHostRole::Hosting)
            .expect("bearer")
            .expect("a bearer");
        assert_eq!(bearer.expose(), token, "the generated token is stored");
    }
    assert!(app.bouncer_host.draft.is_none(), "the draft ends");
    assert!(!app.status_text.contains(&token), "{}", app.status_text);
    let (text, _) = frames(&mut app, TALL);
    assert_eq!(app.ui.sheet, None, "the sheet closes after the check");
    assert!(text.contains("My Server"), "{text}");
    assert!(
        text.contains(&format!("brain.synthetic.ts.net · {GATE_STAYS}")),
        "{text}"
    );
    assert!(!text.contains(&token), "{text}");
}

/// The consent step lists what leaves this Mac and what never does, names the host,
/// the version of the words, and the Touch ID for each change. Back keeps the token.
#[test]
fn the_consent_sheet_lists_what_leaves_the_mac() {
    use crate::desktop::brain_hosting_ui::{self as hosting, HostingStep, RunsOnAction};
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Bouncer);
    hosting::apply(&mut app, RunsOnAction::MyServer, None);
    let token = draft_token(&app);
    {
        let draft = app.bouncer_host.draft.as_mut().expect("draft");
        draft.address = "https://brain.synthetic.ts.net".to_owned();
        draft.step = HostingStep::Consent;
    }
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(hosting::CONSENT_TITLE), "{text}");
    assert!(
        text.contains("Each bouncer request goes to brain.synthetic.ts.net."),
        "{text}"
    );
    for line in hosting::SENT.iter().chain(hosting::NEVER_SENT.iter()) {
        assert!(text.contains(line), "missing {line}: {text}");
    }
    assert!(text.contains(hosting::TRUST_WARNING), "{text}");
    assert!(text.contains(&hosting::consent_note()), "{text}");
    assert!(text.contains(hosting::USE_SERVER), "{text}");
    assert!(!text.contains(&token), "{text}");
    app.bouncer_host.draft.as_mut().expect("draft").step = HostingStep::Server;
    assert_eq!(draft_token(&app), token, "Back keeps the token");
    // Cancel erases the draft.
    let ctx = egui::Context::default();
    super::super::close_sheet(&mut app, &ctx);
    assert!(app.bouncer_host.draft.is_none());
}

/// A stored host that cannot be used shows the fallback: the brain runs on this Mac and
/// the row says why, once. The return to this Mac needs the owner check too.
#[test]
fn a_host_that_cannot_be_used_shows_the_fallback_and_the_return_needs_the_check() {
    use crate::desktop::brain_hosting_ui::{self as hosting, FALLBACK_HEADLINE, RunsOnAction};
    use crate::vault::{BouncerHostChange, BouncerHostKind, HOSTING_CONSENT_VERSION};
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Bouncer);
    {
        let shared = app.owner_ui.session.shared_vault();
        let mut guard = shared.lock().unwrap();
        guard
            .as_mut()
            .expect("open vault")
            .set_bouncer_host(
                crate::vault::BouncerHostRole::Hosting,
                &BouncerHostChange {
                    kind: BouncerHostKind::Connect,
                    url: "https://brain.connect.example".to_owned(),
                    bearer: None,
                    consent_version: HOSTING_CONSENT_VERSION,
                },
                1,
            )
            .expect("connect row");
    }
    app.bouncer_host.problem = Some(crate::broker::brain_host::CONNECT_UNAVAILABLE.to_owned());
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains("Apassy Connect"), "{text}");
    assert!(text.contains(FALLBACK_HEADLINE), "{text}");
    assert!(
        text.contains("needs the Connect sign-in, which this version does not have yet."),
        "{text}"
    );
    assert_eq!(text.matches("runs on this Mac").count(), 1, "{text}");

    hosting::apply(&mut app, RunsOnAction::ThisMac, None);
    let request = app
        .owner
        .check
        .as_ref()
        .expect("owner check")
        .request
        .clone();
    assert_eq!(
        request.action(),
        OwnerAction::ChangeBouncerHosting {
            kind: BouncerHostKind::ThisMac,
            url: String::new(),
            consent_version: 0,
        }
    );
    assert!(request.action().needs_fresh_local_check());
    assert!(stored_hosting(&app).is_some(), "nothing before the check");
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert_eq!(stored_hosting(&app), None);
}

/// A remote bouncer brain says whether the owner's server answers. No answer is not an
/// allowance: every run waits for the owner. The note names no address.
#[test]
fn a_remote_brain_state_waits_for_the_owner_and_names_no_address() {
    use super::super::kit::Tone;
    let (words, tone, note) = super::remote_server_words(Some(false), None);
    assert_eq!(words, "Not running");
    assert_eq!(tone, Tone::Warning);
    assert_eq!(note.as_deref(), Some(super::REMOTE_DOWN));
    let (words, tone, note) = super::remote_server_words(Some(true), Some("apassy-base-v1"));
    assert_eq!((words.as_str(), tone), ("Ready", Tone::Good));
    assert_eq!(
        note.as_deref(),
        Some("Brain: apassy-base-v1 on your server.")
    );
    let (words, _, _) = super::remote_server_words(None, None);
    assert_eq!(words, "Checking");
}
