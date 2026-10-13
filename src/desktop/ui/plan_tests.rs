//! Headless tests of the plan in the window (ADR 0027, flow spec M3 to M5, Flows B to
//! E): nothing about plans shows in the app as it ships (no offer); with the fake plan
//! of the tests, the Sync choice per plan, the Upgrade sheet with its wait and its end,
//! Settings > Plan in each state, Compare plans, the Shared empty state, the switch to
//! Apassy behind the owner check, and "Personal ended" once. Synthetic values only; the
//! relay is the in-process fake relay on 127.0.0.1, and no link opens a browser.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Event, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::plan::{
    APASSY_LINE, COMING_SOON, FREE_LINE, NOT_CONFIRMED, OFF_LINE, PlanSheet, REASSURANCE,
    SEE_PLANS, SHARED_LINE, TAG, WAITING_TITLE,
};
use super::settings_view::SettingsSection;
use super::sync::{Choice, SyncSheet};
use super::vaults::VaultSheet;
use super::{Sheet, draw, start};
use crate::broker::approvals::{OwnerAction, OwnerCheck, OwnerProof};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::OwnerRequest;
use crate::plan::{Entitlement, FakePlanProvider, Plan, PlanStatus, UpgradeFrom};

/// The fake relay reads the app's sync module under this name.
use crate::sync as relay_api;
/// The sync tests load the same file for their own use.
#[allow(clippy::duplicate_mod)]
#[path = "../../../tests/common/fake_relay.rs"]
mod fake_relay;

const PASS: &str = "plan-ui-pass-ok";
const SIZE: Vec2 = Vec2::new(1280.0, 1600.0);
const DAY: u64 = 24 * 60 * 60;

/// A Mac with a vault "Work", unlocked. `icloud`: this Mac has an iCloud Drive folder.
struct Mac {
    _dir: TempDir,
    app: DesktopApp,
    icloud: PathBuf,
}

fn mac(icloud: bool) -> Mac {
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("data"), true);
    app.sync.offered = true;
    let folder = dir
        .path()
        .join("Mobile Documents")
        .join("com~apple~CloudDocs")
        .join("Apassy");
    std::fs::create_dir_all(folder.parent().expect("parent")).expect("icloud drive");
    if icloud {
        app.sync.icloud = Some(folder.clone());
        app.sync.folders = vec![crate::sync::SyncFolder {
            label: "iCloud Drive".to_owned(),
            path: folder.clone(),
        }];
    }
    let ctx = egui::Context::default();
    app.vault_list.name_input = "Work".to_owned();
    app.owner_ui.passphrase.push_str(PASS);
    app.owner_ui.passphrase_confirm.push_str(PASS);
    start::create_vault(&mut app, &ctx);
    assert!(!app.owner_ui.session.is_locked(), "{}", app.status_text);
    Mac {
        _dir: dir,
        app,
        icloud: folder,
    }
}

/// The fake plan `name` with an offer, for the window.
fn fake(app: &mut DesktopApp, name: &str) -> Arc<FakePlanProvider> {
    let provider =
        Arc::new(FakePlanProvider::for_screenshots(name, super::kit::now()).expect("plan"));
    app.set_plan_provider(provider.clone());
    provider
}

/// One frame of the window. Returns the painted texts with their rectangles.
fn frame(ctx: &egui::Context, app: &mut DesktopApp, events: Vec<Event>) -> Vec<(String, Rect)> {
    let input = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
        events,
        ..Default::default()
    };
    let output = ctx.run_ui(input, |ui| draw(app, ui));
    let mut texts = Vec::new();
    for clipped in &output.shapes {
        texts_of(&clipped.shape, &mut texts);
    }
    output.drop_without_applying_deltas();
    texts
}

fn texts_of(shape: &egui::Shape, out: &mut Vec<(String, Rect)>) {
    match shape {
        egui::Shape::Text(text) => {
            out.push((text.galley.text().to_owned(), text.visual_bounding_rect()));
        }
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| texts_of(inner, out)),
        _ => {}
    }
}

/// A window that keeps its context, for clicks.
struct Window {
    ctx: egui::Context,
}

impl Window {
    fn new() -> Self {
        Self {
            ctx: egui::Context::default(),
        }
    }

    /// Three frames. Returns the painted text of the last one.
    fn text(&self, app: &mut DesktopApp) -> String {
        let mut texts = Vec::new();
        for _ in 0..3 {
            texts = frame(&self.ctx, app, Vec::new());
        }
        texts
            .iter()
            .map(|(text, _)| text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A click on the last painted `label` (a sheet draws over the window).
    fn click(&self, app: &mut DesktopApp, label: &str) {
        let mut texts = Vec::new();
        for _ in 0..3 {
            texts = frame(&self.ctx, app, Vec::new());
        }
        let at = texts
            .iter()
            .rev()
            .find(|(text, _)| text == label)
            .map(|(_, rect)| rect.center())
            .unwrap_or_else(|| panic!("no {label:?} in {texts:?}"));
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        frame(&self.ctx, app, vec![Event::PointerMoved(at)]);
        frame(&self.ctx, app, vec![button(true)]);
        frame(&self.ctx, app, vec![button(false)]);
    }
}

fn current_id(app: &DesktopApp) -> String {
    app.vault_list.current.clone().expect("open vault")
}

/// The vault gets an Apassy Connect team on `relay` with this Mac only, as the first
/// "Add a device" makes it: the owner check, then the relay call.
fn connect(app: &mut DesktopApp, relay: &fake_relay::FakeRelay) -> String {
    assert!(app.set_connect_relay_url(&relay.url));
    let entry = app.current_vault().cloned().expect("entry");
    app.questions_ask_connect(&entry, &relay.url, None);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    app.questions_settle_for_test();
    app.owner_ui
        .session
        .with_vault(|vault| crate::relay::membership::questions_membership(vault))
        .expect("open")
        .expect("read")
        .expect("a Connect team")
        .team_id
}

/// A proof of the owner check for `action` in this vault session.
fn proof(app: &DesktopApp, action: OwnerAction) -> OwnerProof {
    let epoch = app
        .owner_ui
        .session
        .with_vault(|vault| vault.epoch())
        .expect("open");
    OwnerProof::issue_for_test(action, epoch, Instant::now())
}

/// Wait until the switch to Apassy ended.
fn settle_switch(app: &mut DesktopApp) {
    let ctx = egui::Context::default();
    let deadline = Instant::now() + Duration::from_secs(20);
    while super::plan::switching(app, &current_id(app)) && Instant::now() < deadline {
        app.plan_poll(&ctx);
        std::thread::sleep(Duration::from_millis(10));
    }
    app.plan_poll(&ctx);
}

/// The request of the owner check that waits.
fn asked(app: &DesktopApp) -> Option<OwnerRequest> {
    app.owner.check.as_ref().map(|check| check.request.clone())
}

#[test]
fn the_app_as_it_ships_shows_nothing_about_plans() {
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(false);
    let window = Window::new();
    assert!(!app.plans_offered());
    super::open_settings(&mut app, SettingsSection::Vault);
    let text = window.text(&mut app);
    for shown in [
        "iCloud Drive",
        "Apassy",
        "Off",
        OFF_LINE,
        "No shared vaults",
    ] {
        assert!(text.contains(shown), "{shown}: {text}");
    }
    assert!(!text.contains(&format!("Apassy\n{TAG}")), "{text}");
    assert!(
        text.contains("iCloud Drive is off on this Mac. Turn it on in System Settings."),
        "{text}"
    );
    for hidden in [
        "Free",
        "or sync through Apassy",
        SEE_PLANS,
        SHARED_LINE,
        "Compare plans",
    ] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    assert!(!SettingsSection::listed_all(&app).contains(&SettingsSection::Plan));

    // "Apassy" opens "Use another relay…" with the relay address and the team code.
    app.sync_pick_for_test(Choice::Apassy);
    assert_eq!(
        app.ui.sheet,
        Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::RelaySetup {
            id: current_id(&app)
        })))
    );
    let text = window.text(&mut app);
    assert!(text.contains("Team code"), "{text}");
    app.ui.sheet = None;

    // No upgrade, and no "Personal ended", even when something asks for them.
    for sheet in [
        Sheet::Upgrade(UpgradeFrom::Sync),
        Sheet::Upgrade(UpgradeFrom::Shared),
        Sheet::PlanEnded,
    ] {
        app.ui.sheet = Some(sheet.clone());
        let _ = window.text(&mut app);
        assert_eq!(app.ui.sheet, None, "{sheet:?}");
    }
    assert!(app.ui.plan.opened.is_empty());
}

#[test]
fn free_shows_the_tag_and_apassy_opens_the_upgrade() {
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(false);
    fake(&mut app, "free");
    let window = Window::new();
    super::open_settings(&mut app, SettingsSection::Vault);
    let text = window.text(&mut app);
    assert!(text.contains(&format!("Apassy\n{TAG}")), "{text}");
    assert!(
        text.contains(
            "iCloud Drive is off on this Mac. Turn it on in System Settings, or sync through Apassy."
        ),
        "{text}"
    );

    window.click(&mut app, "Apassy");
    assert_eq!(app.ui.sheet, Some(Sheet::Upgrade(UpgradeFrom::Sync)));
    let text = window.text(&mut app);
    for shown in [
        "Sync through Apassy",
        "Changes on every device in seconds",
        "Works without iCloud",
        "End-to-end encrypted. Apassy can't read your vault.",
        "Personal · €X a month, or €X a year",
        "Continue to checkout",
        "Not now",
        "Compare plans",
        REASSURANCE,
    ] {
        assert!(text.contains(shown), "{shown}: {text}");
    }
    // "Not now" closes it, and nothing changed.
    window.click(&mut app, "Not now");
    assert_eq!(app.ui.sheet, None);
    assert!(app.ui.plan.opened.is_empty());
    assert_eq!(app.plan.current().plan, Plan::Free);
}

#[test]
fn each_pick_follows_the_plan() {
    let relay = fake_relay::FakeRelay::start();
    for name in ["free", "ended", "personal", "team", "operator"] {
        let Mac {
            mut app,
            _dir: _keep,
            ..
        } = mac(true);
        fake(&mut app, name);
        let id = current_id(&app);
        app.sync_pick_for_test(Choice::Apassy);
        let paid = matches!(name, "personal" | "team" | "operator");
        if paid {
            // No team yet: the owner check of a new device list comes first, then the
            // switch.
            assert_eq!(app.ui.sheet, None, "{name}");
            assert!(
                matches!(asked(&app), Some(OwnerRequest::ConnectVault { .. })),
                "{name}: {:?}",
                asked(&app)
            );
            assert!(super::plan::switching(&app, &id), "{name}");
        } else {
            assert_eq!(
                app.ui.sheet,
                Some(Sheet::Upgrade(UpgradeFrom::Sync)),
                "{name}"
            );
            assert!(asked(&app).is_none(), "{name}");
        }
        assert!(!app.is_relay(&id), "{name}");

        // With a team, a paid plan asks the owner check of the switch itself.
        if paid {
            let Mac {
                mut app,
                _dir: _team_dir,
                ..
            } = mac(true);
            fake(&mut app, name);
            let team = connect(&mut app, &relay);
            app.sync_pick_for_test(Choice::Apassy);
            match asked(&app) {
                Some(OwnerRequest::SyncThroughApassy {
                    team_id, devices, ..
                }) => {
                    assert_eq!(team_id, team, "{name}");
                    assert!(devices.is_empty(), "{name}: {devices:?}");
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }

    // iCloud Drive and Off follow the folder of this Mac, on every plan.
    let Mac {
        mut app,
        icloud,
        _dir: _keep,
    } = mac(true);
    fake(&mut app, "free");
    let id = current_id(&app);
    app.sync_pick_for_test(Choice::ICloud);
    assert!(icloud.join("Work.apassy").is_file());
    assert_eq!(
        app.vault_list
            .registry
            .get(&id)
            .and_then(|entry| entry.sync.as_ref())
            .map(|link| link.folder.clone()),
        Some(icloud)
    );
    app.sync_pick_for_test(Choice::Off);
    assert_eq!(
        app.ui.sheet,
        Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::TurnOff { id })))
    );
}

#[test]
fn the_switch_to_apassy_runs_only_with_the_owner_proof() {
    let relay = fake_relay::FakeRelay::start();
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "personal");
    let id = current_id(&app);
    let team = connect(&mut app, &relay);
    // A Mac that was added for the questions only.
    app.owner_ui
        .session
        .with_vault(|vault| {
            let mut key = vec![4u8];
            key.extend_from_slice(&[7u8; 64]);
            vault.register_trusted_device(
                "8b0c2f5e-3a1d-4c6b-9e7f-0a1b2c3d4e5f",
                "Mac mini",
                crate::vault::TrustedDeviceKind::Mac,
                &key,
                None,
            )
        })
        .expect("open")
        .expect("row");
    relay.lift_plan(&team);
    app.sync_pick_for_test(Choice::Apassy);
    let Some(OwnerRequest::SyncThroughApassy {
        vault,
        team_id,
        devices,
        ..
    }) = asked(&app)
    else {
        panic!("{:?}", asked(&app));
    };
    assert_eq!(
        (vault.as_str(), team_id.as_str()),
        (id.as_str(), team.as_str())
    );
    assert_eq!(devices, ["Mac mini"]);
    let request = asked(&app).expect("asked");
    assert!(
        request
            .describe()
            .contains("These devices will also sync the vault through Apassy: Mac mini."),
        "{}",
        request.describe()
    );
    // Without the proof of this switch, nothing runs.
    app.finish_owner_check_with(proof(&app, OwnerAction::OpenCliSession));
    settle_switch(&mut app);
    assert!(!app.is_relay(&id));
    assert_eq!(relay.version(), 0);
    // A proof that names fewer devices than the team has does not cover it.
    let fewer = OwnerAction::SyncThroughApassy {
        team_id: team.clone(),
        devices: Vec::new(),
    };
    app.plan_switch_with(&id, &team, Vec::new(), proof(&app, fewer));
    settle_switch(&mut app);
    assert!(!app.is_relay(&id));
    assert!(
        app.status_text.contains("devices of this vault changed"),
        "{}",
        app.status_text
    );
    assert_eq!(relay.version(), 0);

    // The owner check of the switch as the owner saw it.
    app.sync_pick_for_test(Choice::Apassy);
    assert!(matches!(
        asked(&app),
        Some(OwnerRequest::SyncThroughApassy { .. })
    ));
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    settle_switch(&mut app);
    assert!(app.is_relay(&id), "{}", app.status_text);
    assert_eq!(relay.team_ids(), vec![team], "never a second team");
    assert_eq!(relay.version(), 1);
    assert!(
        app.status_text.contains("syncs through Apassy"),
        "{}",
        app.status_text
    );
}

#[test]
fn a_relay_that_did_not_take_the_plan_changes_nothing() {
    let relay = fake_relay::FakeRelay::start();
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "personal");
    let id = current_id(&app);
    let team = connect(&mut app, &relay);
    let action = OwnerAction::SyncThroughApassy {
        team_id: team.clone(),
        devices: Vec::new(),
    };
    app.plan_switch_with(&id, &team, Vec::new(), proof(&app, action));
    assert!(super::plan::switching(&app, &id));
    settle_switch(&mut app);
    assert!(!app.is_relay(&id));
    assert!(
        app.status_text
            .contains("Apassy did not accept your plan yet"),
        "{}",
        app.status_text
    );
    // The membership keeps the questions only, and no state was written.
    let questions = app
        .owner_ui
        .session
        .with_vault(|vault| {
            (
                crate::relay::membership::questions_membership(vault)
                    .expect("read")
                    .map(|membership| membership.team_id),
                vault.relay_device().expect("read").is_none(),
            )
        })
        .expect("open");
    assert_eq!(questions, (Some(team), true));
    assert_eq!(relay.version(), 0);
}

#[test]
fn the_checkout_waits_in_the_browser_then_personal_is_on() {
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    let provider = fake(&mut app, "free");
    let window = Window::new();
    app.plan_open_upgrade(UpgradeFrom::Sync);
    window.click(&mut app, "Continue to checkout");
    assert_eq!(
        app.ui.plan.opened,
        ["https://accounts.example.test/checkout?from=sync"]
    );
    let text = window.text(&mut app);
    assert!(text.contains(WAITING_TITLE), "{text}");
    assert!(
        text.contains("Apassy turns Personal on when the payment is done."),
        "{text}"
    );
    assert!(text.contains("Check again"), "{text}");
    assert!(!text.contains(NOT_CONFIRMED), "{text}");

    // Two minutes and no payment: the sheet says so, and nothing changed.
    app.plan_age_checkout_for_test(Duration::from_secs(121));
    let text = window.text(&mut app);
    assert!(text.contains(NOT_CONFIRMED), "{text}");
    window.click(&mut app, "Check again");
    assert_eq!(app.plan.current().plan, Plan::Free);

    // The payment arrives: "Personal is on." and the switch of the vault.
    let now = super::kit::now();
    provider.set(Entitlement {
        plan: Plan::Personal,
        email: Some("owner@example.test".to_owned()),
        renews_at: Some(now + 30 * DAY),
        status: PlanStatus::Active,
        checked_at: now,
    });
    let text = window.text(&mut app);
    assert!(text.contains("Personal is on."), "{text}");
    assert!(text.contains("Switch “Work” to Apassy now?"), "{text}");
    assert!(text.contains("Switch to Apassy"), "{text}");
    window.click(&mut app, "Later");
    assert_eq!(app.ui.sheet, None);
    assert!(!app.is_relay(&current_id(&app)));
}

#[test]
fn cancel_in_the_wait_leaves_everything_as_it_was() {
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "free");
    let window = Window::new();
    app.plan_open_upgrade(UpgradeFrom::Sync);
    window.click(&mut app, "Continue to checkout");
    assert!(window.text(&mut app).contains(WAITING_TITLE));
    window.click(&mut app, "Cancel");
    assert_eq!(app.ui.sheet, None);
    // A new Upgrade starts from the offer again.
    app.plan_open_upgrade(UpgradeFrom::Sync);
    let text = window.text(&mut app);
    assert!(text.contains("Continue to checkout"), "{text}");
    assert!(!text.contains(WAITING_TITLE), "{text}");
    assert_eq!(app.plan.current().plan, Plan::Free);
}

#[test]
fn settings_plan_shows_each_state() {
    let window = Window::new();
    let cases: [(&str, &[&str], &[&str]); 5] = [
        (
            "free",
            &["Free", FREE_LINE, "Compare plans"],
            &["Manage subscription", "Sign out of this Mac"],
        ),
        (
            "personal",
            &[
                "Personal",
                "renews ",
                "owner@example.test",
                "Manage subscription",
                "Sign out of this Mac",
            ],
            &["Update payment", "Works offline"],
        ),
        (
            "past-due",
            &[
                "The last payment did not go through.",
                "Update payment",
                "Personal · payment failed",
            ],
            &["Works offline"],
        ),
        (
            "offline",
            &["Works offline for 14 days.", "Personal · checked "],
            &["Update payment"],
        ),
        (
            "ended",
            &["Personal ended", "Compare plans"],
            &["Manage subscription", "Sign out of this Mac"],
        ),
    ];
    for (name, shown, hidden) in cases {
        let Mac {
            mut app,
            _dir: _keep,
            ..
        } = mac(true);
        fake(&mut app, name);
        super::open_settings(&mut app, SettingsSection::Plan);
        let text = window.text(&mut app);
        for expected in shown {
            assert!(text.contains(expected), "{name}: {expected}: {text}");
        }
        for unexpected in hidden {
            assert!(!text.contains(unexpected), "{name}: {unexpected}: {text}");
        }
    }

    // "Manage subscription" opens the portal; "Sign out of this Mac" asks first.
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "personal");
    super::open_settings(&mut app, SettingsSection::Plan);
    window.click(&mut app, "Manage subscription");
    assert_eq!(app.ui.plan.opened, ["https://accounts.example.test/portal"]);
    window.click(&mut app, "Sign out of this Mac");
    assert_eq!(app.ui.sheet, Some(Sheet::Plan(PlanSheet::SignOut)));
    let text = window.text(&mut app);
    assert!(
        text.contains("Sync through Apassy stops on this Mac."),
        "{text}"
    );
    window.click(&mut app, "Sign out");
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.plan.current().plan != Plan::Free && Instant::now() < deadline {
        let _ = window.text(&mut app);
    }
    let _ = window.text(&mut app);
    assert_eq!(app.plan.current().plan, Plan::Free);
    assert_eq!(app.ui.sheet, None);
}

#[test]
fn compare_plans_has_three_honest_columns() {
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "free");
    let window = Window::new();
    super::open_settings(&mut app, SettingsSection::Plan);
    window.click(&mut app, "Compare plans");
    let text = window.text(&mut app);
    for shown in [
        "Free",
        "Personal",
        "Team",
        "Your plan",
        "Sync through iCloud Drive",
        "Approvals on all your devices",
        "€X a month, or €X a year",
        "Shared vaults with roles",
        "Choose Personal…",
    ] {
        assert!(text.contains(shown), "{shown}: {text}");
    }
    for hidden in ["Recommended", "Most popular", "Best value", "left"] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    window.click(&mut app, "Done");
    assert_eq!(app.ui.sheet, None);
}

#[test]
fn the_shared_empty_state_follows_the_plan() {
    let window = Window::new();
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "free");
    let text = window.text(&mut app);
    assert!(text.contains(SHARED_LINE), "{text}");
    assert!(!text.contains("No shared vaults"), "{text}");
    window.click(&mut app, SEE_PLANS);
    assert_eq!(app.ui.sheet, Some(Sheet::Upgrade(UpgradeFrom::Shared)));
    let text = window.text(&mut app);
    assert!(text.contains("Share vaults with people"), "{text}");

    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "personal");
    let text = window.text(&mut app);
    assert!(text.contains("New shared vault…"), "{text}");
    assert!(text.contains(COMING_SOON), "{text}");
    assert!(!text.contains(SEE_PLANS), "{text}");
}

#[test]
fn personal_ended_shows_once_and_keeps_the_approvals() {
    let relay = fake_relay::FakeRelay::start();
    let Mac {
        mut app,
        icloud,
        _dir: _keep,
    } = mac(true);
    let provider = fake(&mut app, "personal");
    let id = current_id(&app);
    let team = connect(&mut app, &relay);
    relay.lift_plan(&team);
    let action = OwnerAction::SyncThroughApassy {
        team_id: team.clone(),
        devices: Vec::new(),
    };
    app.plan_switch_with(&id, &team, Vec::new(), proof(&app, action));
    settle_switch(&mut app);
    assert!(app.is_relay(&id), "{}", app.status_text);
    let window = Window::new();
    let _ = window.text(&mut app);
    assert_eq!(app.ui.sheet, None, "no sheet while the plan works");

    let now = super::kit::now();
    provider.set(Entitlement {
        plan: Plan::Personal,
        email: Some("owner@example.test".to_owned()),
        renews_at: Some(now),
        status: PlanStatus::Ended,
        checked_at: now,
    });
    let text = window.text(&mut app);
    assert_eq!(app.ui.sheet, Some(Sheet::PlanEnded));
    for shown in [
        "Personal ended",
        "Your vault stays on all your devices. Sync moves to iCloud Drive.",
        "Move sync to iCloud Drive",
        "Turn sync off",
    ] {
        assert!(text.contains(shown), "{shown}: {text}");
    }
    // Closed, it does not come back in this session.
    app.ui.sheet = None;
    let _ = window.text(&mut app);
    assert_eq!(app.ui.sheet, None);

    // "Move sync to iCloud Drive": the vault syncs there, and this Mac stays in the
    // team, so the approvals stay.
    app.ui.sheet = Some(Sheet::PlanEnded);
    window.click(&mut app, "Move sync to iCloud Drive");
    assert!(!app.is_relay(&id), "{}", app.status_text);
    assert!(icloud.join("Work.apassy").is_file());
    let questions = app
        .owner_ui
        .session
        .with_vault(|vault| {
            crate::relay::membership::questions_membership(vault)
                .expect("read")
                .map(|membership| membership.team_id)
        })
        .expect("open");
    assert_eq!(questions, Some(team));
    assert!(
        app.status_text.contains("Approvals stay"),
        "{}",
        app.status_text
    );
}

/// A paid vault that picks iCloud Drive again, with the "Turn off" sheet: sync stops and
/// the copy stays, but this Mac stays in the vault's Apassy Connect team, so approvals
/// stay on every device (ADR 0027: a downgrade never removes them).
#[test]
fn turning_apassy_sync_off_keeps_the_connect_team() {
    let relay = fake_relay::FakeRelay::start();
    let Mac {
        mut app,
        icloud,
        _dir: _keep,
    } = mac(true);
    fake(&mut app, "personal");
    let id = current_id(&app);
    let team = connect(&mut app, &relay);
    relay.lift_plan(&team);
    let action = OwnerAction::SyncThroughApassy {
        team_id: team.clone(),
        devices: Vec::new(),
    };
    app.plan_switch_with(&id, &team, Vec::new(), proof(&app, action));
    settle_switch(&mut app);
    assert!(app.is_relay(&id), "{}", app.status_text);

    app.sync_pick_for_test(Choice::ICloud);
    assert!(
        matches!(
            app.ui.sheet,
            Some(Sheet::Vault(VaultSheet::Sync(SyncSheet::TurnOff { .. })))
        ),
        "{:?}",
        app.ui.sheet
    );
    app.relay_turn_off(&id, false, Some(icloud.clone()))
        .expect("turn off");
    assert!(!app.is_relay(&id), "{}", app.status_text);
    assert!(icloud.join("Work.apassy").is_file(), "{}", app.status_text);
    assert!(
        app.status_text
            .contains("approvals stay on all your devices"),
        "{}",
        app.status_text
    );
    let questions = app
        .owner_ui
        .session
        .with_vault(|vault| {
            crate::relay::membership::questions_membership(vault)
                .expect("read")
                .map(|membership| membership.team_id)
        })
        .expect("open");
    assert_eq!(questions, Some(team.clone()));
    assert_eq!(relay.team_ids(), vec![team], "the team stays on the relay");
}

#[test]
fn the_apassy_line_shows_under_the_choice() {
    let relay = fake_relay::FakeRelay::start();
    let Mac {
        mut app,
        _dir: _keep,
        ..
    } = mac(true);
    fake(&mut app, "personal");
    let id = current_id(&app);
    let team = connect(&mut app, &relay);
    relay.lift_plan(&team);
    let action = OwnerAction::SyncThroughApassy {
        team_id: team.clone(),
        devices: Vec::new(),
    };
    app.plan_switch_with(&id, &team, Vec::new(), proof(&app, action));
    settle_switch(&mut app);
    super::open_settings(&mut app, SettingsSection::Vault);
    let text = Window::new().text(&mut app);
    assert!(text.contains(APASSY_LINE), "{text}");
    assert!(
        !text.contains(&format!("Apassy\n{TAG}")),
        "no tag on a paid plan: {text}"
    );
}
