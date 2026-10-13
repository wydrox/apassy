//! Headless tests of Settings as a view of the window (ADR 0026 §3): the gear and ⌘,
//! open it, the list column names each section, a click selects one, a sidebar click
//! leaves; each section shows its groups at a tall and at the minimum window size; the
//! hub of Devices, "Approve here…" with its owner check, and the rows of each kind of
//! device; and a sheet of Settings over the window.
//! Synthetic values only; the relay is the in-process fake relay on 127.0.0.1.

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::devices::{
    ADD_DEVICE, DeviceKind, DevicesSheet, EMPTY_MESSAGE, EMPTY_TITLE, PAIR_HERE, Removal,
    TRUST_LINE, WIFI_ONLY,
};
use super::super::owner_tests::{PASS, WRONG, unlocked_app_with_item};
use super::super::settings_view::SettingsSection;
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
            &[EMPTY_TITLE, ADD_DEVICE, TRUST_LINE, "This Mac", PAIR_HERE],
            &[
                "Back up now…",
                "Questions go to every device",
                "Add device…",
                "None paired",
                "Not synced",
                "Questions through the relay",
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
        // Plan shows only with an offer, and this app has none.
        for listed in SettingsSection::listed_all(&app) {
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

/// Settings > Devices of a vault with no team: only this Mac, the hero with "Add a
/// device…" and its trust line, and the L3 fallback. No relay address, no team code,
/// and no switch: the relay is invisible (flow spec §2).
#[test]
fn the_devices_hub_starts_with_this_mac_and_add_a_device() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    super::super::open_settings(&mut app, SettingsSection::Devices);
    let hub = app.devices_hub();
    assert_eq!(hub.rows.len(), 1, "{hub:?}");
    assert_eq!(hub.rows[0].kind, DeviceKind::ThisMac);
    assert_eq!(hub.rows[0].does, "This Mac");
    assert!(!hub.rows[0].stop_here && !hub.rows[0].approve_here);
    assert!(
        hub.rows[0].remove.is_none(),
        "this Mac is never removed here"
    );
    assert!(!hub.approvals);
    assert_eq!(hub.problem, None);
    let (text, _) = frames(&mut app, TALL);
    for shown in [
        EMPTY_TITLE,
        EMPTY_MESSAGE,
        ADD_DEVICE,
        TRUST_LINE,
        "This Mac",
        PAIR_HERE,
    ] {
        assert!(text.contains(shown), "{shown}: {text}");
    }
    for gone in [
        "Relay address",
        "Team code",
        "Send questions through the relay",
        "Questions through the relay",
        "Other Macs",
        "Add an iPhone or a Mac…",
        "Devices…",
        "Allow the iPhone app on this network",
    ] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
    assert_eq!(
        super::status_line(&app, SettingsSection::Devices),
        "Only this Mac"
    );

    // "Pair on this network" opens the listener group (L3).
    app.ui.sheet = None;
    let ctx = egui::Context::default();
    let texts = frame(&ctx, &mut app, TALL, Vec::new());
    let at = center_of(&texts, PAIR_HERE, TALL.x).expect("the L3 link");
    click(&ctx, &mut app, TALL, at);
    let texts = frame(&ctx, &mut app, TALL, Vec::new());
    assert!(
        texts
            .iter()
            .any(|(text, _)| text == "Allow the iPhone app on this network"),
        "{texts:?}"
    );

    // A lock leaves Settings.
    app.owner_ui.session.lock().expect("lock");
    frames(&mut app, TALL);
    assert!(app.place.is_credentials(), "a lock leaves Settings");
}

/// "Approve here…" of this Mac in a vault that syncs through the relay: a new channel
/// that can approve runs, so it opens the owner check for exactly the sync team, and
/// nothing changes before it passes. Then the sync membership has the purpose
/// `questions`, the vault has its question key, and this Mac is a trusted device; its
/// row offers "Stop approvals here", which needs no check and keeps relay sync.
#[test]
fn approve_here_needs_the_owner_check_and_stop_approvals_does_not() {
    use crate::relay::membership::{QuestionsAvailability, questions_availability};
    // The device list goes to this relay on 127.0.0.1, never to the network.
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
    let hub = app.devices_hub();
    assert!(
        hub.rows[0].approve_here && !hub.rows[0].stop_here,
        "{hub:?}"
    );
    assert!(!hub.approvals);

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
    assert!(matches!(request, OwnerRequest::EnableRelayQuestions { .. }));
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
    app.questions_turn_on(None);
    app.finish_owner_check_with(other);
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
        assert!(open.question_key().unwrap().is_some());
        let devices = open.trusted_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].sign_key, key.public_key());
    }
    let hub = app.devices_hub();
    assert!(hub.approvals);
    assert_eq!(hub.rows.len(), 1, "this Mac is one row: {hub:?}");
    assert!(hub.rows[0].stop_here && !hub.rows[0].approve_here);

    // "Stop approvals here": stricter, no check.
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
    assert_eq!(
        questions_availability(open).unwrap(),
        QuestionsAvailability::CanTurnOn {
            team_id: "t_7k2m5q4x3c".to_owned()
        }
    );
}

/// One list: the trusted devices of the vault say how they approve, an iPhone paired on
/// this Wi-Fi says "Approves on this Wi-Fi only", and each other device offers
/// "Remove…". The status line counts them.
#[test]
fn device_rows_say_what_each_device_does() {
    use crate::vault::TrustedDeviceKind;
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = unlocked_app_with_item(&dir);
    let point = || {
        crate::sync::DeviceKey::generate()
            .expect("key")
            .public_key()
            .to_vec()
    };
    let (mac, phone, waiting) = (point(), point(), point());
    let answer = point();
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault
                .register_trusted_device(
                    "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
                    "Synthetic Mac mini",
                    TrustedDeviceKind::Mac,
                    &mac,
                    None,
                )
                .expect("mac");
            vault
                .register_trusted_device(
                    "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
                    "Synthetic iPhone",
                    TrustedDeviceKind::Iphone,
                    &phone,
                    Some(&answer),
                )
                .expect("iphone");
            vault
                .register_trusted_device(
                    "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                    "Synthetic iPad",
                    TrustedDeviceKind::Iphone,
                    &waiting,
                    None,
                )
                .expect("waiting iphone");
        })
        .expect("open vault");
    let (request_key, approval_key) = (point(), point());
    let device_id = "00112233445566778899aabbccddeeff";
    let proof = app
        .owner_gate()
        .authorize(
            OwnerAction::PairCompanion {
                device_id: device_id.to_owned(),
                device_name: "Synthetic Wi-Fi iPhone".to_owned(),
                request_key: request_key.clone(),
                approval_key: approval_key.clone(),
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault
                .add_companion_device(
                    proof,
                    device_id,
                    "Synthetic Wi-Fi iPhone",
                    &request_key,
                    &approval_key,
                )
                .expect("paired")
        })
        .expect("open vault");
    let hub = app.devices_hub();
    let row = |name: &str| {
        hub.rows
            .iter()
            .find(|row| row.name == name)
            .unwrap_or_else(|| panic!("{name}: {hub:?}"))
            .clone()
    };
    assert_eq!(hub.rows.len(), 5, "{hub:?}");
    assert_eq!(hub.rows[0].kind, DeviceKind::ThisMac);
    let mac = row("Synthetic Mac mini");
    assert_eq!(
        (mac.kind, mac.does.as_str()),
        (DeviceKind::Mac, "Approves with Touch ID")
    );
    assert!(matches!(mac.remove, Some(Removal::Trusted { .. })));
    let phone = row("Synthetic iPhone");
    assert_eq!(
        (phone.kind, phone.does.as_str()),
        (DeviceKind::Iphone, "Approves with Face ID")
    );
    assert_eq!(
        row("Synthetic iPad").does,
        "Its Face ID key has not synced yet"
    );
    let wifi = row("Synthetic Wi-Fi iPhone");
    assert_eq!(wifi.does, WIFI_ONLY);
    assert!(matches!(wifi.remove, Some(Removal::Wifi { .. })));
    assert_eq!(
        super::status_line(&app, SettingsSection::Devices),
        "5 devices"
    );

    // "Remove…" of the Wi-Fi iPhone asks first; Cancel keeps it.
    app.devices_ask_remove(wifi.remove.clone().expect("removal"), None);
    assert!(matches!(
        app.ui.sheet,
        Some(super::Sheet::Devices(DevicesSheet::RemoveWifi { .. }))
    ));
    let (text, _) = frames(&mut app, DEFAULT);
    assert!(text.contains("Remove “Synthetic Wi-Fi iPhone”?"), "{text}");
}
