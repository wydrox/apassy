//! Headless tests of Settings as a view of the window (ADR 0026 §3): the gear and ⌘,
//! open it, the list column names each section, a click selects one, a sidebar click
//! leaves; each section shows its groups at a tall and at the minimum window size; the
//! relay row of Devices with its owner check; and a sheet of Settings over the window.
//! Synthetic values only; the relay is the in-process fake relay on 127.0.0.1.

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::owner_tests::{PASS, WRONG, unlocked_app_with_item};
use super::super::settings_view::SettingsSection;
use super::{
    ADD_IPHONE, RELAY_QUESTIONS, RELAY_QUESTIONS_NEW_TEAM, RELAY_QUESTIONS_OFF, RELAY_QUESTIONS_ON,
    RELAY_ROW,
};
use crate::broker::approvals::{OwnerAction, OwnerAuthError, OwnerCheck};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{DesktopApp, Place};

/// The fake relay reads the app's sync module under this name.
use crate::sync as relay_api;
/// The sync tests load the same file for their own use.
#[allow(clippy::duplicate_mod)]
#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

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
            &[
                "Unlock",
                "Touch ID",
                "Owner checks use",
                "Change passphrase…",
            ],
            &["Back up now…", "Install tools…", "Owner checks\n"],
        ),
        (
            SettingsSection::Devices,
            &[
                "This Mac",
                "Notifications",
                "iPhone",
                "Allow the iPhone app on this network",
                "Pair an iPhone",
                RELAY_ROW,
                "Questions reach every device.",
            ],
            &[
                "Back up now…",
                "Questions go to every device",
                "Add device…",
                "None paired",
                "Not synced",
            ],
        ),
        (
            SettingsSection::Bouncer,
            &["Model", "Calibration and learning"],
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
/// no "Done": it is no window.
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
}

/// At the smallest window, with the sidebar full, as a rail, and floating, each section
/// draws its list and its first group, and no text goes past the right edge.
#[test]
fn each_section_draws_at_the_minimum_window_size() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    for (hidden, float) in [(false, false), (true, false), (false, true)] {
        app.ui.sidebar_hidden = hidden;
        for (section, shown, _) in cases() {
            super::super::open_settings(&mut app, section);
            app.ui.sidebar_float = float;
            let (text, texts) = frames(&mut app, MIN);
            assert!(text.contains("Settings"), "{section:?}: {text}");
            assert!(text.contains(shown[0]), "{section:?}: {}: {text}", shown[0]);
            for (painted, rect) in &texts {
                assert!(
                    rect.right() <= MIN.x + 0.5 && rect.left() >= -0.5,
                    "{section:?}: \"{painted}\" at {rect:?} is outside the window"
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
        let output = ctx.run_ui(input, |ui| super::super::draw(app, ui));
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

/// "Send questions through the relay" is in Settings > Devices and off by default. A vault
/// that is not on the relay can turn it on too: through a notifications-only team, so
/// the switch says so. A locked vault cannot change it.
#[test]
fn the_relay_questions_switch_offers_a_team_without_relay_sync() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Devices);
    let (disabled, toggled) = relay_switch(&mut app);
    assert!(!disabled, "the relay switch is enabled");
    assert_eq!(toggled, Some(egui::accesskit::Toggled::False), "and off");
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(RELAY_QUESTIONS_NEW_TEAM), "{text}");
    assert!(
        !text.contains(ADD_IPHONE),
        "no iPhone before it is on: {text}"
    );

    // A lock leaves Settings, and a locked vault has no relay state to change.
    app.owner_ui.session.lock().expect("lock");
    assert_eq!(super::relay_questions_state(&app), None);
    frames(&mut app, TALL);
    assert!(app.place.is_credentials(), "a lock leaves Settings");
}

/// With relay sync, the switch is enabled and still off by default. On is a new channel
/// that can approve runs: it opens the owner check for exactly the sync team, and nothing
/// changes before it passes. Then the sync membership has the purpose `questions`, the
/// vault has its question key, and this Mac is a trusted device. Off needs no check,
/// takes the purpose away, and keeps relay sync.
#[test]
fn the_relay_questions_switch_needs_the_owner_check_to_go_on() {
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
        })
        .expect("relay row");
    let (disabled, toggled) = relay_switch(&mut app);
    assert!(!disabled, "the relay switch is enabled");
    assert_eq!(toggled, Some(egui::accesskit::Toggled::False), "and off");
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(RELAY_QUESTIONS_OFF), "{text}");

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
    super::set_relay_questions(&mut app, true, None);
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
    assert!(matches!(request, OwnerRequest::EnableRelayQuestions { .. }));
    assert_eq!(
        expected.reason(),
        "send the questions of this vault through the relay"
    );
    assert!(
        request
            .describe()
            .starts_with("Send the questions of this vault through the Apassy relay"),
        "{}",
        request.describe()
    );
    unchanged(&app);
    assert_eq!(
        app.confirm_owner_now(OwnerCheck::passphrase(WRONG)),
        Err(OwnerAuthError::WrongPassphrase)
    );
    unchanged(&app);
    // A proof for another action changes nothing.
    let other = app
        .owner_gate()
        .authorize(
            OwnerAction::EnableRelayQuestions {
                relay_url: relay.url.clone(),
                team_id: None,
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    super::set_relay_questions(&mut app, true, None);
    app.finish_owner_check_with(other);
    unchanged(&app);

    super::set_relay_questions(&mut app, true, None);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
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
        let devices = open.trusted_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].sign_key, key.public_key());
    }
    let (text, _) = frames(&mut app, TALL);
    assert!(text.contains(RELAY_QUESTIONS_ON), "{text}");
    assert!(
        text.contains("This Mac") && text.contains(ADD_IPHONE),
        "{text}"
    );

    // Off: stricter, no check.
    super::set_relay_questions(&mut app, false, None);
    assert!(app.owner.check.is_none(), "off needs no owner check");
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
    assert_eq!(
        questions_availability(open).unwrap(),
        QuestionsAvailability::CanTurnOn {
            team_id: "t_7k2m5q4x3c".to_owned()
        }
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
