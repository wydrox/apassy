//! Headless tests of the Settings window (ADR 0026 §3): the four tabs of the toolbar,
//! the sections of each tab at the minimum and a tall window size, the relay row of
//! Devices, and the keys that close the window. Synthetic values only.

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::owner_tests::unlocked_app_with_item;
use super::super::settings_window::{MIN_SIZE, content};
use super::{
    RELAY_QUESTIONS, RELAY_QUESTIONS_NEEDS_RELAY, RELAY_QUESTIONS_OFF, RELAY_QUESTIONS_ON,
    SettingsTab,
};
use crate::desktop::DesktopApp;

const TALL: Vec2 = Vec2::new(MIN_SIZE.x, 6000.0);

/// One frame of the Settings content at `size`. Returns the painted texts with their
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
    let output = ctx.run_ui(input, |ui| {
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE)
            .show(ui, |ui| content(app, ui));
    });
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

/// What each tab shows first, and what it never shows.
fn cases() -> [(
    SettingsTab,
    &'static [&'static str],
    &'static [&'static str],
); 4] {
    [
        (
            SettingsTab::General,
            &[
                "Vaults",
                "Lock now",
                "Import from 1Password…",
                "Browser extension",
            ],
            &[
                "Back up now",
                "Broker and bouncer",
                "Questions go to every device",
            ],
        ),
        (
            SettingsTab::Devices,
            &[
                "Questions go to every device",
                "This Mac",
                "Other Macs",
                "iPhones",
                RELAY_QUESTIONS,
                "Add a Device…",
                "Notifications",
                "iPhone companion",
                "Paired iPhones",
            ],
            &["Lock now", "Back up now", "Keyboard shortcuts"],
        ),
        (
            SettingsTab::Security,
            &[
                "Unlock",
                "Change passphrase",
                "Back up now",
                "Restore from a backup",
            ],
            &["Lock now", "Broker and bouncer", "Updates"],
        ),
        (
            SettingsTab::Advanced,
            &[
                "Broker and bouncer",
                "Calibration and learning",
                "Command line",
                "Updates",
                "Keyboard shortcuts",
                "Contract",
            ],
            &["Lock now", "Back up now", "iPhone companion"],
        ),
    ]
}

/// Each tab shows its sections and no section of another tab. The settings of single
/// agents are gone (ADR 0025 §3f).
#[test]
fn each_tab_shows_its_sections() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    for (tab, shown, hidden) in cases() {
        app.ui.settings_tab = tab;
        let (text, _) = frames(&mut app, TALL);
        for label in SettingsTab::ALL.map(SettingsTab::label) {
            assert!(
                text.contains(label),
                "{tab:?}: the tab bar has {label}: {text}"
            );
        }
        for expected in shown {
            assert!(text.contains(expected), "{tab:?} shows {expected}: {text}");
        }
        for unexpected in hidden {
            assert!(
                !text.contains(unexpected),
                "{tab:?} hides {unexpected}: {text}"
            );
        }
        for gone in ["Token lifetime", "Current lifetime"] {
            assert!(!text.contains(gone), "{tab:?}: {gone} is gone: {text}");
        }
    }
}

/// At the minimum size of the window, each tab draws its tab bar and its first section,
/// and no text goes past the right edge of the window.
#[test]
fn each_tab_draws_at_the_minimum_window_size() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    for (tab, shown, _) in cases() {
        app.ui.settings_tab = tab;
        let (text, texts) = frames(&mut app, MIN_SIZE);
        for label in SettingsTab::ALL.map(SettingsTab::label) {
            assert!(text.contains(label), "{tab:?}: {label}: {text}");
        }
        assert!(text.contains(shown[0]), "{tab:?}: {}: {text}", shown[0]);
        for (painted, rect) in &texts {
            assert!(
                rect.right() <= MIN_SIZE.x + 0.5 && rect.left() >= -0.5,
                "{tab:?}: \"{painted}\" at {rect:?} is outside the window"
            );
        }
    }
}

/// A click on a tab of the toolbar selects it.
#[test]
fn a_click_on_a_tab_selects_it() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    for target in [
        SettingsTab::Devices,
        SettingsTab::Security,
        SettingsTab::Advanced,
        SettingsTab::General,
    ] {
        let texts = frame(&ctx, &mut app, MIN_SIZE, Vec::new());
        let at = texts
            .iter()
            .find(|(text, _)| text == target.label())
            .map(|(_, rect)| rect.center())
            .unwrap_or_else(|| panic!("{} is on the tab bar", target.label()));
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        frame(&ctx, &mut app, MIN_SIZE, vec![Event::PointerMoved(at)]);
        frame(&ctx, &mut app, MIN_SIZE, vec![button(true)]);
        frame(&ctx, &mut app, MIN_SIZE, vec![button(false)]);
        assert_eq!(app.ui.settings_tab, target);
    }
}

/// The state of the relay switch in the AccessKit tree of three frames: disabled, and
/// toggled.
fn relay_switch(app: &mut DesktopApp) -> (bool, Option<egui::accesskit::Toggled>) {
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    let mut switch = None;
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, TALL)),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| content(app, ui));
        });
        if let Some(update) = &output.platform_output.accesskit_update {
            for (_, node) in &update.nodes {
                if node.label() == Some(RELAY_QUESTIONS) {
                    switch = Some((node.is_disabled(), node.toggled()));
                }
            }
        }
        output.drop_without_applying_deltas();
    }
    switch.expect("the relay switch is in the AccessKit tree")
}

/// "Send questions through the relay" is on the Devices tab and off by default. A vault
/// that is not on the relay cannot turn it on: the switch is disabled.
#[test]
fn the_relay_questions_switch_needs_the_relay() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.ui.settings_tab = SettingsTab::Devices;
    let (disabled, toggled) = relay_switch(&mut app);
    assert!(disabled, "the relay switch is disabled");
    assert_eq!(toggled, Some(egui::accesskit::Toggled::False), "and off");
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(RELAY_QUESTIONS_NEEDS_RELAY), "{text}");
}

/// With relay sync, the switch is enabled and still off by default. On adds the purpose
/// `questions` to the sync membership, makes the question key, and registers this Mac;
/// off takes the purpose away and keeps relay sync.
#[test]
fn the_relay_questions_switch_goes_on_and_off_with_relay_sync() {
    use crate::relay::membership::{QuestionsAvailability, questions_availability};
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    app.ui.settings_tab = SettingsTab::Devices;
    let vault = app.owner_ui.session.shared_vault();
    let key = crate::sync::DeviceKey::generate().expect("key");
    vault
        .lock()
        .unwrap()
        .as_mut()
        .expect("open vault")
        .set_relay_device(&crate::vault::RelayDevice {
            relay_url: "https://relay.example.test".to_owned(),
            team_id: "t_7k2m5q4x3c".to_owned(),
            device_id: 2,
            public_key: key.public_key().to_vec(),
            key_pkcs8: key.pkcs8().expect("pkcs8").clone(),
            created_at: 0,
        })
        .expect("relay row");
    let (disabled, toggled) = relay_switch(&mut app);
    assert!(!disabled, "the relay switch is enabled");
    assert_eq!(toggled, Some(egui::accesskit::Toggled::False), "and off");
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(RELAY_QUESTIONS_OFF), "{text}");

    super::set_relay_questions(&mut app, true);
    let (_, toggled) = relay_switch(&mut app);
    assert_eq!(toggled, Some(egui::accesskit::Toggled::True));
    {
        let guard = vault.lock().unwrap();
        let open = guard.as_ref().expect("open vault");
        assert_eq!(
            questions_availability(open).unwrap(),
            QuestionsAvailability::On {
                team_id: "t_7k2m5q4x3c".to_owned()
            }
        );
        assert!(open.question_key().unwrap().is_some());
        assert_eq!(open.trusted_devices().unwrap().len(), 1);
    }
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(RELAY_QUESTIONS_ON), "{text}");

    super::set_relay_questions(&mut app, false);
    let (_, toggled) = relay_switch(&mut app);
    assert_eq!(toggled, Some(egui::accesskit::Toggled::False));
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

/// Settings in place of the main window: Esc and ⌘W close it. Esc with a sheet open
/// closes the sheet only.
#[test]
fn escape_and_command_w_close_settings() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let run = |app: &mut DesktopApp, mut events: Vec<Event>| {
        for _ in 0..3 {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(1180.0, 760.0))),
                events: std::mem::take(&mut events),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| super::super::draw(app, ui));
            output.drop_without_applying_deltas();
        }
    };
    let press = |app: &mut DesktopApp, key: Key, modifiers: Modifiers| {
        // The window draws first: a new sheet is invisible in its first frame.
        run(app, Vec::new());
        run(
            app,
            vec![Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            }],
        );
    };
    super::open(&mut app, SettingsTab::Security);
    press(&mut app, Key::Escape, Modifiers::NONE);
    assert!(!app.settings_open, "Esc closes Settings");

    super::open(&mut app, SettingsTab::Security);
    press(&mut app, Key::W, Modifiers::COMMAND);
    assert!(!app.settings_open, "⌘W closes Settings");

    super::open(&mut app, SettingsTab::Security);
    app.ui.sheet = Some(super::Sheet::Backup);
    press(&mut app, Key::Escape, Modifiers::NONE);
    assert!(app.ui.sheet.is_none(), "Esc closes the sheet");
    assert!(app.settings_open, "and Settings stays");
    press(&mut app, Key::Escape, Modifiers::NONE);
    assert!(!app.settings_open, "the next Esc closes Settings");
}

/// The old Notifications tab opens Devices, which has its sections.
#[test]
fn the_old_notifications_tab_opens_devices() {
    assert_eq!(SettingsTab::Notifications, SettingsTab::Devices);
}
