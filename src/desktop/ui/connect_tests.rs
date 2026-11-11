//! Headless tests of Settings > Connect (plan s7 unit M2): the totals of the plan picker
//! equal `tests/fixtures/connect-billing-v1/totals.json`, the browser gets exactly the
//! Checkout and Portal URLs that Connect returned (the recorded `OpenUrl` commands),
//! the checkout poll runs while the waiting sheet is open and stops on an entitled plan,
//! the portal needs no owner check and the deletion, a revoke, a device confirmation,
//! and every group change need one, the invite, confirm, and remove flows of a family,
//! every state of the plan row (`plan-states.json`), and the text rules of plans
//! section 5. Connect is the in-process fake of `tests/common/fake_connect.rs` on
//! 127.0.0.1 (a free port); every value is synthetic and every file is in a temporary
//! directory.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, OutputCommand};
use serde_json::Value;
use tempfile::TempDir;

use super::connect::live::{self, Guarded};
use super::connect::{
    Account, Action, CONTINUE_BROWSER, ConnectView, DELETE_TITLE, FORGET_THIS_MAC, LOADING_PRICES,
    MANAGE_BILLING, NOT_ON_CONNECT, NOT_VERIFIED, PRICES_FAILED, Plan, Plans, REMOVED, SELF_HOST,
    Sheet, SheetChoice, Shown, TEXTS, TRY_AGAIN, fallback_name, money, plan_note,
};
use super::owner_tests::{PASS, collect, confirm_with, input, unlocked_app_with_item};
use crate::connect::{
    ConnectAccount, ConnectClient, JoinPoll, JoinRequest, MemoryKeyStore, PlansView,
};
use crate::desktop::DesktopApp;

/// The fake Connect reads the app's sync module under this name.
use crate::sync as relay_api;
#[path = "../../../tests/common/fake_connect.rs"]
mod fake_connect;

use fake_connect::FakeConnect;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/connect-billing-v1"
);

fn fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join(name)).expect("fixture");
    serde_json::from_str(&text).expect("json")
}

/// The plans of the fixture, read as the app reads `GET /v1/plans`.
fn fixture_plans() -> Plans {
    let view: PlansView = serde_json::from_value(fixture("plans.json")).expect("PlansView");
    live::plans_from(&view)
}

// ---- The app under test. ----

/// An unlocked app whose Connect section uses `connect`, a key store in memory, and a
/// temporary data directory, with short polls.
fn connect_app(dir: &TempDir, connect: &FakeConnect) -> DesktopApp {
    let (mut app, _) = unlocked_app_with_item(dir);
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    let live = &mut app.ui.connect.live;
    live.store = Some(Arc::new(MemoryKeyStore::new()));
    live.dir = Some(data);
    live.origin = Some(connect.url.clone());
    live.poll_every = Some(Duration::from_millis(40));
    live.join_poll_every = Some(Duration::from_millis(40));
    super::open_settings(&mut app, super::SettingsSection::Connect);
    app
}

/// One pass of egui that runs `work` inside it; the output commands of the pass.
fn pass(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    work: impl FnOnce(&mut DesktopApp, &egui::Context),
) -> Vec<OutputCommand> {
    let mut work = Some(work);
    let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
        if let Some(work) = work.take() {
            work(app, ui.ctx());
        }
    });
    let commands = output.platform_output.commands.clone();
    output.drop_without_applying_deltas();
    commands
}

/// Run the steps of the section until `done` holds; the output commands on the way.
fn until(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    what: &str,
    done: impl Fn(&DesktopApp) -> bool,
) -> Vec<OutputCommand> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut commands = Vec::new();
    while !done(app) {
        assert!(Instant::now() < deadline, "timed out: {what}");
        commands.extend(pass(ctx, app, live::step));
        std::thread::sleep(Duration::from_millis(5));
    }
    commands
}

/// The step of the worker ends.
fn settle(ctx: &egui::Context, app: &mut DesktopApp) -> Vec<OutputCommand> {
    until(ctx, app, "the worker", |app| !live::view(app).busy)
}

fn act(ctx: &egui::Context, app: &mut DesktopApp, action: Action) -> Vec<OutputCommand> {
    pass(ctx, app, |app, ctx| live::act(app, ctx, action))
}

fn choose(ctx: &egui::Context, app: &mut DesktopApp, choice: SheetChoice) -> Vec<OutputCommand> {
    pass(ctx, app, |app, ctx| live::choose(app, ctx, choice))
}

/// The painted text of Settings > Connect after three frames of the whole window.
fn text(ctx: &egui::Context, app: &mut DesktopApp) -> String {
    super::open_settings(app, super::SettingsSection::Connect);
    let mut text = String::new();
    for _ in 0..3 {
        let output = ctx.run_ui(input(0.0, Vec::new()), |ui| super::draw(app, ui));
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn shown(app: &DesktopApp) -> Option<Account> {
    match live::view(app).shown {
        Shown::Account(account) => Some(account),
        _ => None,
    }
}

fn opened_urls(commands: &[OutputCommand]) -> Vec<String> {
    commands
        .iter()
        .filter_map(|command| match command {
            OutputCommand::OpenUrl(open) => Some(open.url.clone()),
            _ => None,
        })
        .collect()
}

/// Create the account of this Mac through the sheet, save the recovery code, and wait
/// for the first refresh.
fn create_account(ctx: &egui::Context, app: &mut DesktopApp, name: &str) -> String {
    act(ctx, app, Action::Create);
    if let Some(Sheet::Create { name: typed, .. }) = &mut app.ui.connect.sheet {
        typed.push_str(name);
    }
    choose(ctx, app, SheetChoice::Go);
    until(ctx, app, "the recovery code", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Recovery { .. }))
    });
    let Some(Sheet::Recovery { words }) = &app.ui.connect.sheet else {
        unreachable!();
    };
    assert_eq!(words.split_whitespace().count(), 16, "16 words, once");
    choose(ctx, app, SheetChoice::Done);
    until(ctx, app, "the account", |app| shown(app).is_some());
    shown(app).expect("account").account_id
}

/// Choose `plan` in the picker, continue in the browser, and complete the checkout at
/// the fake as its webhook would. Returns the URL that the browser got.
fn buy(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    connect: &FakeConnect,
    plan: &str,
    count: u64,
) -> String {
    act(ctx, app, Action::ChoosePlan);
    until(ctx, app, "the plans", |app| live::view(app).plans.is_some());
    app.ui.connect.sheet = Some(Sheet::Picker {
        plan: plan.to_owned(),
        interval: "month".to_owned(),
        count,
    });
    let mut commands = choose(ctx, app, SheetChoice::Go);
    commands.extend(until(ctx, app, "the waiting sheet", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Waiting { .. }))
    }));
    let (session, _) = connect.checkouts().pop().expect("a checkout");
    assert!(connect.complete_checkout(&session));
    until(ctx, app, "the plan", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Active { .. }))
    });
    choose(ctx, app, SheetChoice::Done);
    settle(ctx, app);
    opened_urls(&commands).pop().expect("the browser opened")
}

// ---- The plan picker. ----

/// The totals of the picker are those of `totals.json`, from the prices of
/// `plans.json` only: each count in range, and none outside it (`seat_limit`). A year
/// price is 10 times its month price in the default configuration.
#[test]
fn the_picker_totals_equal_the_fixture() {
    let plans = fixture_plans();
    let totals = fixture("totals.json");
    for case in totals["totals"].as_array().expect("totals") {
        let offer = plans
            .offer(case["plan"].as_str().expect("plan"))
            .expect("offer");
        let interval = case["interval"].as_str().expect("interval");
        let count = case["count"].as_u64().expect("count");
        assert_eq!(
            offer.total(interval, count),
            case["amount"].as_u64(),
            "{case}"
        );
    }
    for case in totals["seat_limit"].as_array().expect("seat_limit") {
        let offer = plans
            .offer(case["plan"].as_str().expect("plan"))
            .expect("offer");
        let total = offer.total(
            case["interval"].as_str().expect("interval"),
            case["count"].as_u64().expect("count"),
        );
        assert_eq!(total, None, "{case}");
    }
    for offer in &plans.offers {
        let month = offer.price("month").expect("month").amount;
        let year = offer.price("year").expect("year").amount;
        assert_eq!(year, 10 * month, "{}", offer.plan);
    }
    assert_eq!(money("eur", 700), "€7");
    assert_eq!(money("eur", 350), "€3.50");
    assert_eq!(money("chf", 300), "CHF 3");
}

/// The picker shows the prices and the total that Connect sent: a family of 6, yearly,
/// is €70 a year; a team of 5, monthly, €20 a month. Without the plans it shows no
/// price and Continue stays off.
#[test]
fn the_picker_shows_the_total_of_the_plans() {
    let ctx = egui::Context::default();
    let draw = |sheet: &mut Sheet, plans: Option<&Plans>| {
        let mut text = String::new();
        for _ in 0..3 {
            let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
                super::connect::sheet(ui.ctx(), sheet, plans, false, None, 0, &|_, _| {});
            });
            text.clear();
            for clipped in &output.shapes {
                collect(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        text
    };
    let plans = fixture_plans();
    let mut family = Sheet::Picker {
        plan: "family".to_owned(),
        interval: "year".to_owned(),
        count: 6,
    };
    let text = draw(&mut family, Some(&plans));
    for expected in [
        "Connect Personal",
        "Connect Family",
        "Connect Team",
        "€30",
        "€50",
        "€40",
        "€70 a year",
        "4 people; each further person €10 a year",
        CONTINUE_BROWSER,
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    let mut team = Sheet::Picker {
        plan: "team".to_owned(),
        interval: "month".to_owned(),
        count: 5,
    };
    assert!(draw(&mut team, Some(&plans)).contains("€20 a month"));
    let mut loading = Sheet::Picker {
        plan: "personal".to_owned(),
        interval: "month".to_owned(),
        count: 1,
    };
    let text = draw(&mut loading, None);
    assert!(text.contains("Loading prices…"), "{text}");
    assert!(!text.contains('€'), "no price without the plans: {text}");
}

/// When `GET /v1/plans` fails, the picker says so with the error and offers "Try
/// Again", which asks Connect again; then the prices show. Before the answer it shows no
/// price, and Continue stays off.
#[test]
fn a_failed_price_load_offers_try_again_and_asks_again() {
    let dir = TempDir::new().expect("dir");
    let connect = FakeConnect::start();
    let ctx = egui::Context::default();
    let mut app = connect_app(&dir, &connect);
    // The refresh after the creation loses the answer (it shows no error), then the
    // picker loses it too.
    connect.lose_next_answers("GET /v1/plans", 1);
    create_account(&ctx, &mut app, "Rafal");
    settle(&ctx, &mut app);
    assert!(live::view(&app).plans.is_none());
    connect.lose_next_answers("GET /v1/plans", 1);
    act(&ctx, &mut app, Action::ChoosePlan);
    settle(&ctx, &mut app);
    let view = live::view(&app);
    assert!(view.plans.is_none(), "no prices");
    // The sheet shows the error of the step under its buttons.
    let shown = text(&ctx, &mut app);
    let failure = crate::connect::ConnectError::Broken.to_string();
    let offline = crate::connect::ConnectError::Offline.to_string();
    assert!(
        shown.contains(&failure) || shown.contains(&offline),
        "the error shows: {shown}"
    );
    assert!(shown.contains(PRICES_FAILED), "{shown}");
    assert!(shown.contains(TRY_AGAIN), "{shown}");
    assert!(!shown.contains(LOADING_PRICES), "{shown}");
    assert!(!shown.contains('€'), "no price: {shown}");
    let asked = connect.count("GET /v1/plans");
    choose(&ctx, &mut app, SheetChoice::TryAgain);
    until(&ctx, &mut app, "the plans", |app| {
        live::view(app).plans.is_some()
    });
    assert!(
        connect.count("GET /v1/plans") > asked,
        "Try Again asked again"
    );
    assert!(matches!(app.ui.connect.sheet, Some(Sheet::Picker { .. })));
    let shown = text(&ctx, &mut app);
    assert!(
        !shown.contains(&failure) && !shown.contains(&offline),
        "{shown}"
    );
    assert!(shown.contains("Connect Personal"), "{shown}");
    assert!(!shown.contains(TRY_AGAIN), "{shown}");
}

/// The relay sheet offers "Apassy Connect" only while this Mac's account is signed in
/// with a plan that pushes (plan s7 unit M3): not for an account without a plan, then
/// after the checkout; the account key goes to the sync then.
#[test]
fn the_sync_offers_apassy_connect_only_with_a_plan_that_pushes() {
    let dir = TempDir::new().expect("dir");
    let connect = FakeConnect::start();
    let ctx = egui::Context::default();
    let mut app = connect_app(&dir, &connect);
    assert!(!app.connect_sync_available(), "no account");
    create_account(&ctx, &mut app, "Rafal");
    assert!(!app.connect_sync_available(), "no plan");
    buy(&ctx, &mut app, &connect, "personal", 1);
    until(&ctx, &mut app, "the refresh", |app| {
        app.connect_sync_available()
    });
    let account = app.ui.connect.live.sync_account().expect("account");
    assert!(account.signer.is_some(), "the key goes to the sync");
    assert_eq!(account.origin, connect.url);
}

/// No amount is written in the code of the section: every price comes from
/// `GET /v1/plans`.
#[test]
fn no_price_is_written_in_the_section() {
    for (name, source) in [
        ("connect.rs", include_str!("connect.rs")),
        ("connect/live.rs", include_str!("connect/live.rs")),
        ("connect/demo.rs", include_str!("connect/demo.rs")),
    ] {
        let chars: Vec<char> = source.chars().collect();
        for (index, pair) in chars.windows(2).enumerate() {
            assert!(
                !(['€', '$', '£'].contains(&pair[0]) && pair[1].is_ascii_digit()),
                "{name}: a price at character {index}"
            );
        }
        for amount in ["300", "3000", "500", "5000", "400", "4000"] {
            assert!(
                !source.contains(&format!("amount: {amount}")),
                "{name} holds the amount {amount}"
            );
        }
    }
}

// ---- Checkout and portal. ----

/// "Continue in the Browser…" asks Connect for a checkout with the exact body of
/// connect-billing-v1 section 4, and the browser opens the URL that Connect returned.
/// While the waiting sheet is open the app asks `GET /v1/account` again and again; it
/// stops when the plan is entitled, and shows the plan.
#[test]
fn checkout_opens_the_url_of_connect_and_polling_stops_on_active() {
    assert_eq!(super::connect::POLL_EVERY, Duration::from_secs(3));
    assert_eq!(super::connect::WAIT_AT_MOST, Duration::from_secs(30 * 60));
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    assert!(text(&ctx, &mut app).contains(NOT_ON_CONNECT));
    create_account(&ctx, &mut app, "Rafal");

    act(&ctx, &mut app, Action::ChoosePlan);
    until(&ctx, &mut app, "the plans", |app| {
        live::view(app).plans.is_some()
    });
    app.ui.connect.sheet = Some(Sheet::Picker {
        plan: "family".to_owned(),
        interval: "year".to_owned(),
        count: 6,
    });
    let mut commands = choose(&ctx, &mut app, SheetChoice::Go);
    commands.extend(until(&ctx, &mut app, "the waiting sheet", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Waiting { .. }))
    }));
    let (session, body) = connect.checkouts().pop().expect("a checkout");
    assert_eq!(
        body,
        serde_json::json!({"plan": "family", "interval": "year", "people": 6})
    );
    assert_eq!(
        opened_urls(&commands),
        vec![format!("https://checkout.stripe.com/c/pay/{session}")],
        "the browser opens exactly the URL of Connect"
    );
    // The browser's return changes nothing: the app keeps asking Connect.
    let before = connect.count("GET /v1/account");
    until(&ctx, &mut app, "two polls", |_| {
        connect.count("GET /v1/account") >= before + 2
    });
    assert!(matches!(app.ui.connect.sheet, Some(Sheet::Waiting { .. })));

    // "Open the Page Again" opens the same URL.
    let again = choose(&ctx, &mut app, SheetChoice::OpenAgain);
    assert_eq!(
        opened_urls(&again),
        vec![format!("https://checkout.stripe.com/c/pay/{session}")]
    );

    assert!(connect.complete_checkout(&session));
    until(&ctx, &mut app, "the plan is active", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Active { .. }))
    });
    let Some(Sheet::Active { title, .. }) = &app.ui.connect.sheet else {
        unreachable!();
    };
    assert_eq!(title, "Connect Family Is Active");
    settle(&ctx, &mut app);
    let stopped = connect.count("GET /v1/account");
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        pass(&ctx, &mut app, live::step);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        connect.count("GET /v1/account"),
        stopped,
        "no poll after the plan is entitled"
    );
    choose(&ctx, &mut app, SheetChoice::Done);
    settle(&ctx, &mut app);
    let text = text(&ctx, &mut app);
    assert!(text.contains("Connect Family"), "{text}");
    assert!(text.contains(MANAGE_BILLING), "{text}");
}

/// Cancel of the waiting sheet stops the poll at once.
#[test]
fn cancel_stops_the_checkout_poll() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    act(&ctx, &mut app, Action::ChoosePlan);
    until(&ctx, &mut app, "the plans", |app| {
        live::view(app).plans.is_some()
    });
    choose(&ctx, &mut app, SheetChoice::Go);
    until(&ctx, &mut app, "the waiting sheet", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Waiting { .. }))
    });
    choose(&ctx, &mut app, SheetChoice::Cancel);
    settle(&ctx, &mut app);
    let after = connect.count("GET /v1/account");
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        pass(&ctx, &mut app, live::step);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(connect.count("GET /v1/account"), after);
    assert!(app.ui.connect.sheet.is_none());
}

/// "Manage Billing…" opens the portal URL of Connect without an owner check; "Delete
/// Account…" asks for one, and Connect sees nothing until the owner confirms.
#[test]
fn the_portal_needs_no_owner_check_and_delete_needs_one() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    let account_id = create_account(&ctx, &mut app, "Rafal");
    buy(&ctx, &mut app, &connect, "personal", 1);

    let mut commands = act(&ctx, &mut app, Action::ManageBilling);
    assert!(
        app.owner.check.is_none(),
        "the portal asks for no owner check"
    );
    commands.extend(settle(&ctx, &mut app));
    let urls = opened_urls(&commands);
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert!(
        urls[0].starts_with("https://billing.stripe.com/p/session/test_Fake"),
        "{urls:?}"
    );
    assert_eq!(connect.count("POST /v1/account/portal"), 1);

    act(&ctx, &mut app, Action::Delete);
    assert!(text(&ctx, &mut app).contains(DELETE_TITLE));
    choose(&ctx, &mut app, SheetChoice::Go);
    assert!(
        app.owner.check.is_some(),
        "the deletion asks for the owner check"
    );
    assert_eq!(app.ui.connect.live.guarded, Some(Guarded::Delete));
    for _ in 0..5 {
        pass(&ctx, &mut app, live::step);
    }
    assert_eq!(
        connect.count("DELETE /v1/account"),
        0,
        "nothing before the check"
    );
    assert_eq!(connect.accounts(), vec![account_id]);

    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "the deletion", |app| {
        matches!(live::view(app).shown, Shown::None)
    });
    assert_eq!(connect.count("DELETE /v1/account"), 1);
    assert!(connect.accounts().is_empty());
    assert!(
        !dir.path().join("data/connect/account.json").exists(),
        "the account file is gone"
    );
}

/// A cancelled owner check drops the step: nothing reaches Connect.
#[test]
fn a_cancelled_owner_check_changes_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    act(&ctx, &mut app, Action::Delete);
    choose(&ctx, &mut app, SheetChoice::Go);
    assert!(app.owner.check.is_some());
    app.close_owner_check(Some(&ctx));
    for _ in 0..5 {
        pass(&ctx, &mut app, live::step);
    }
    assert_eq!(app.ui.connect.live.guarded, None);
    assert_eq!(connect.count("DELETE /v1/account"), 0);
    assert!(shown(&app).is_some());
}

// ---- Devices. ----

/// "Add a Device…": the new device joins with the code; both sides show the same six
/// words; Confirm… needs the owner check; then the device is in the account. "Forget…"
/// of this Mac needs the owner check too, and removes the account file.
#[test]
fn add_a_device_with_the_words_and_forget_this_mac() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    let account_id = create_account(&ctx, &mut app, "Rafal");

    act(&ctx, &mut app, Action::AddDevice);
    until(&ctx, &mut app, "the link", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::AddDevice { .. }))
    });
    let Some(Sheet::AddDevice { code, .. }) = &app.ui.connect.sheet else {
        unreachable!();
    };
    let code = code.as_str().to_owned();
    let phone_store = MemoryKeyStore::new();
    let phone_path = dir.path().join("phone/connect/account.json");
    let mut phone = JoinRequest::start(
        ConnectClient::new(&connect.url).expect("client"),
        &phone_store,
        &phone_path,
        &code,
        "Rafal's iPhone",
    )
    .expect("join");
    until(&ctx, &mut app, "the words", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Words { .. }))
    });
    let Some(Sheet::Words {
        words, device_name, ..
    }) = &app.ui.connect.sheet
    else {
        unreachable!();
    };
    assert_eq!(words, phone.words(), "both devices show the same words");
    assert_eq!(device_name, "Rafal's iPhone");

    choose(&ctx, &mut app, SheetChoice::Go);
    assert!(
        app.owner.check.is_some(),
        "Confirm… asks for the owner check"
    );
    for _ in 0..5 {
        pass(&ctx, &mut app, live::step);
    }
    assert_eq!(
        connect.live_devices(&account_id).len(),
        1,
        "nothing before the check"
    );
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "the device", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::DeviceAdded { .. }))
    });
    assert_eq!(connect.live_devices(&account_id).len(), 2);
    assert!(matches!(phone.poll(), Ok(JoinPoll::Confirmed(_))));
    choose(&ctx, &mut app, SheetChoice::Done);
    until(&ctx, &mut app, "two devices", |app| {
        shown(app).is_some_and(|account| account.devices.len() == 2)
    });
    let account = shown(&app).expect("account");
    assert!(account.devices[0].this, "this Mac comes first");

    // Forget this Mac: the owner check, then the revoke and the account file.
    act(&ctx, &mut app, Action::Revoke(0));
    assert!(matches!(
        app.ui.connect.sheet,
        Some(Sheet::Revoke { this: true, .. })
    ));
    choose(&ctx, &mut app, SheetChoice::Go);
    assert!(
        app.owner.check.is_some(),
        "Forget… asks for the owner check"
    );
    assert_eq!(connect.live_devices(&account_id).len(), 2);
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "this Mac forgotten", |app| {
        matches!(live::view(app).shown, Shown::None)
    });
    assert_eq!(connect.live_devices(&account_id).len(), 1);
    assert!(!dir.path().join("data/connect/account.json").exists());
}

/// Whether the key store of the section holds a key.
fn has_key(app: &DesktopApp) -> bool {
    app.ui
        .connect
        .live
        .store
        .as_ref()
        .is_some_and(|store| matches!(store.read(), Ok(Some(_))))
}

/// When Connect says this Mac was removed, the section shows it and deletes nothing;
/// only "Forget This Mac…" and its confirmation delete the key and the account file.
#[test]
fn a_removed_mac_keeps_its_key_until_the_owner_confirms_the_forget() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    let file = dir.path().join("data/connect/account.json");
    let this = shown(&app).expect("account").devices[0].clone();
    assert!(this.this && this.verified);

    connect.revoke(&this.id);
    act(&ctx, &mut app, Action::SignIn);
    until(&ctx, &mut app, "the removed state", |app| {
        matches!(live::view(app).shown, Shown::Removed { .. })
    });
    assert!(has_key(&app));
    assert!(file.exists());
    assert_eq!(live::view(&app).status_line(), REMOVED);
    let painted = text(&ctx, &mut app);
    assert!(painted.contains(REMOVED), "{painted}");
    assert!(painted.contains(FORGET_THIS_MAC), "{painted}");

    // Cancel changes nothing.
    act(&ctx, &mut app, Action::ForgetRemoved);
    assert!(matches!(app.ui.connect.sheet, Some(Sheet::ForgetRemoved)));
    choose(&ctx, &mut app, SheetChoice::Cancel);
    settle(&ctx, &mut app);
    assert!(app.ui.connect.sheet.is_none());
    assert!(has_key(&app) && file.exists());
    assert!(matches!(live::view(&app).shown, Shown::Removed { .. }));

    // The confirmed forget deletes the key and the account file.
    act(&ctx, &mut app, Action::ForgetRemoved);
    choose(&ctx, &mut app, SheetChoice::Go);
    until(&ctx, &mut app, "this Mac forgotten", |app| {
        matches!(live::view(app).shown, Shown::None)
    });
    assert!(!has_key(&app));
    assert!(!file.exists());
}

/// A device that this Mac cannot verify shows "Not verified" in its row.
#[test]
fn a_device_that_is_not_verified_says_so() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    let account_id = create_account(&ctx, &mut app, "Rafal");
    let stranger = crate::sync::DeviceKey::generate().expect("key");
    let inserted = connect.insert_device(&account_id, "Mac Studio", stranger.public_key());
    act(&ctx, &mut app, Action::SignIn);
    until(&ctx, &mut app, "two devices", |app| {
        shown(app).is_some_and(|account| account.devices.len() == 2)
    });
    let account = shown(&app).expect("account");
    let row = account
        .devices
        .iter()
        .find(|device| device.id == inserted)
        .expect("the inserted row");
    assert!(!row.verified);
    assert!(
        account
            .devices
            .iter()
            .any(|device| device.this && device.verified)
    );
    let painted = text(&ctx, &mut app);
    assert!(painted.contains(NOT_VERIFIED), "{painted}");
}

// ---- Families and teams. ----

/// The organizer invites: the link comes from Connect; the person joins with it and is
/// pending; Confirm… needs the owner check and makes them active; Remove… needs it too
/// and removes them. A member who joined sees who manages the group.
#[test]
fn invite_confirm_and_remove_a_family_member() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    let organizer = create_account(&ctx, &mut app, "Rafal");
    buy(&ctx, &mut app, &connect, "family", 4);
    until(&ctx, &mut app, "the family", |app| {
        shown(app).is_some_and(|account| account.group.is_some())
    });

    act(&ctx, &mut app, Action::Invite);
    until(&ctx, &mut app, "the invite link", |app| {
        matches!(
            app.ui.connect.sheet,
            Some(Sheet::Invite { link: Some(_), .. })
        )
    });
    let Some(Sheet::Invite {
        link: Some((url, _)),
        choose_role,
        ..
    }) = &app.ui.connect.sheet
    else {
        unreachable!();
    };
    assert!(!choose_role, "a family invites members only");
    assert!(url.starts_with("https://apassy.wyderka.cc/connect/join#apassy_gin_"));
    let url = url.clone();
    choose(&ctx, &mut app, SheetChoice::Done);

    // Ola's own Mac: a free account that joins with the link.
    let ola_store = MemoryKeyStore::new();
    let ola_path = dir.path().join("ola/connect/account.json");
    let (mut ola, _) = ConnectAccount::create(
        ConnectClient::new(&connect.url).expect("client"),
        &ola_store,
        &ola_path,
        "Ola",
        "MacBook Air",
    )
    .expect("Ola's account");
    let joined = ola.join_group(&url).expect("join");
    assert_eq!(joined.state, "pending");
    assert_eq!(joined.owner_name, "Rafal");
    let ola_id = ola.state().account_id.clone();
    assert!(!ola.view().expect("Ola's view").plan.entitled);

    act(&ctx, &mut app, Action::SignIn);
    until(&ctx, &mut app, "the pending member", |app| {
        shown(app)
            .and_then(|account| account.group)
            .is_some_and(|group| group.members.iter().any(|member| member.state == "pending"))
    });
    assert!(text(&ctx, &mut app).contains("Waits for your confirmation"));
    let index = shown(&app)
        .and_then(|account| account.group)
        .and_then(|group| {
            group
                .members
                .iter()
                .position(|member| member.account_id == ola_id)
        })
        .expect("Ola");

    act(&ctx, &mut app, Action::ConfirmMember(index));
    assert!(
        app.owner.check.is_some(),
        "Confirm… asks for the owner check"
    );
    for _ in 0..5 {
        pass(&ctx, &mut app, live::step);
    }
    assert!(
        connect
            .members(&organizer)
            .iter()
            .any(|(id, _, state)| *id == ola_id && state == "pending"),
        "nothing before the check"
    );
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "Ola is active", |_| {
        connect
            .members(&organizer)
            .iter()
            .any(|(id, _, state)| *id == ola_id && state == "active")
    });
    settle(&ctx, &mut app);
    assert!(ola.view().expect("Ola's view").plan.entitled);

    act(&ctx, &mut app, Action::RemoveMember(index));
    assert!(matches!(
        app.ui.connect.sheet,
        Some(Sheet::RemoveMember { leave: false, .. })
    ));
    choose(&ctx, &mut app, SheetChoice::Go);
    assert!(
        app.owner.check.is_some(),
        "Remove… asks for the owner check"
    );
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "Ola is removed", |_| {
        connect.members(&organizer).len() == 1
    });
    assert_eq!(connect.count("DELETE /v1/account/group/members/"), 1);
    assert!(!ola.view().expect("Ola's view").plan.entitled);
}

/// "Join a Family or Team": the pasted link joins as pending, with no owner check; a
/// link of a bad shape reaches nothing.
#[test]
fn join_a_group_with_the_pasted_link() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let ctx = egui::Context::default();
    // The organizer on another Mac.
    let store = MemoryKeyStore::new();
    let (mut organizer, _) = ConnectAccount::create(
        ConnectClient::new(&connect.url).expect("client"),
        &store,
        &dir.path().join("rafal/connect/account.json"),
        "Rafal",
        "Mac mini",
    )
    .expect("organizer");
    let request = crate::connect::CheckoutRequest::new("family", "month", 4);
    let checkout = organizer.checkout(&request).expect("checkout");
    assert!(connect.complete_checkout(&checkout.session_id));
    let invite = organizer.invite("member").expect("invite");

    let mut app = connect_app(&dir, &connect);
    create_account(&ctx, &mut app, "Ola");
    assert!(text(&ctx, &mut app).contains("Join a Family or Team"));
    act(&ctx, &mut app, Action::JoinGroup);
    if let Some(Sheet::JoinGroup { link, .. }) = &mut app.ui.connect.sheet {
        link.push_str("not a link");
    }
    choose(&ctx, &mut app, SheetChoice::Go);
    settle(&ctx, &mut app);
    assert_eq!(connect.count("POST /v1/account/group/join"), 0);
    assert!(live::view(&app).error.is_none() || app.ui.connect.sheet.is_some());

    app.ui.connect.sheet = Some(Sheet::JoinGroup {
        link: invite.url.clone(),
        refused: false,
    });
    choose(&ctx, &mut app, SheetChoice::Go);
    assert!(app.owner.check.is_none(), "joining asks for no owner check");
    until(&ctx, &mut app, "the request", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::JoinSent { .. }))
    });
    choose(&ctx, &mut app, SheetChoice::Done);
    until(&ctx, &mut app, "the pending group", |app| {
        shown(app)
            .and_then(|account| account.group)
            .is_some_and(|group| group.state == "pending")
    });
    let text = text(&ctx, &mut app);
    assert!(text.contains("Waiting for Rafal to confirm you."), "{text}");
    assert!(
        !text.contains(MANAGE_BILLING),
        "a member has no billing: {text}"
    );
}

// ---- The plan row. ----

/// The texts of the galleys of `shape` that egui cut with "…" (`Label::truncate`).
fn elided(shape: &egui::Shape, out: &mut Vec<String>) {
    match shape {
        egui::Shape::Text(text) if text.galley.elided => out.push(text.galley.text().to_owned()),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| elided(inner, out)),
        _ => {}
    }
}

/// At the width of the Settings column, the plan row shows its whole status, also the
/// longest ones beside two buttons: the status goes under the label and wraps, and no
/// text of the row is cut with "…" (leftover of unit M2, frame 6 of the mockup).
#[test]
fn the_plan_row_shows_its_whole_status_at_the_settings_width() {
    let ctx = egui::Context::default();
    let plan = |status: &str, renews: Option<u64>, read_only: Option<u64>| Plan {
        plan: Some("personal".to_owned()),
        status: status.to_owned(),
        entitled: status == "active",
        interval: Some("month".to_owned()),
        quantity: Some(1),
        renews_at: renews,
        ends_at: None,
        grace_until: None,
        read_only_until: read_only,
        delete_at: read_only.map(|at| at + 5_184_000),
    };
    for (plan, expected) in [
        (
            plan("active", Some(1_796_860_800), None),
            "Connect Personal · Renews 10 Dec 2026",
        ),
        (
            plan("read_only", None, Some(1_799_020_800)),
            "Read-only until 4 Jan 2027",
        ),
    ] {
        let view = ConnectView {
            shown: Shown::Account(Account {
                account_id: "acc_k7m2q4x3ca".to_owned(),
                name: "Rafal".to_owned(),
                email: Some("synthetic@example.test".to_owned()),
                plan,
                devices: Vec::new(),
                group: None,
            }),
            plans: Some(fixture_plans()),
            locked: false,
            busy: false,
            error: None,
            now: 1_795_000_000,
        };
        // The narrowest Settings detail column: the window at its smallest.
        for width in [380.0, 460.0] {
            let mut text = String::new();
            let mut cut = Vec::new();
            for _ in 0..2 {
                let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
                    ui.allocate_ui(egui::vec2(width, 900.0), |ui| {
                        ui.set_max_width(width);
                        super::connect::draw(ui, &view);
                    });
                });
                text.clear();
                cut.clear();
                for clipped in &output.shapes {
                    collect(&clipped.shape, &mut text);
                    elided(&clipped.shape, &mut cut);
                }
                output.drop_without_applying_deltas();
            }
            assert!(text.contains(expected), "{width}: {text}");
            assert!(
                cut.iter().all(|line| !line.contains(expected)),
                "{width}: the status is cut: {cut:?}"
            );
            assert!(text.contains(MANAGE_BILLING), "{width}: {text}");
        }
    }
}

/// Every case of `plan-states.json` shows its state: the plan row, the status line,
/// the line under the row, and the buttons of the account that pays.
#[test]
fn every_state_of_the_plan_row() {
    let states = fixture("plan-states.json");
    let ctx = egui::Context::default();
    for case in states["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        let expect = &case["expect"];
        let time = |key: &str| expect[key].as_u64();
        let status = expect["status"].as_str().expect("status").to_owned();
        let plan = Plan {
            plan: (status != "none").then(|| "personal".to_owned()),
            status: status.clone(),
            entitled: expect["entitled"].as_bool().expect("entitled"),
            interval: Some("month".to_owned()),
            quantity: Some(1),
            renews_at: time("renews_at"),
            ends_at: time("ends_at"),
            grace_until: time("grace_until"),
            read_only_until: time("read_only_until"),
            delete_at: time("delete_at"),
        };
        let view = ConnectView {
            shown: Shown::Account(Account {
                account_id: "acc_k7m2q4x3ca".to_owned(),
                name: "Rafal".to_owned(),
                email: None,
                plan: plan.clone(),
                devices: Vec::new(),
                group: None,
            }),
            plans: Some(fixture_plans()),
            locked: false,
            busy: false,
            error: None,
            now: case["input"]["now"].as_u64().expect("now"),
        };
        let (value, _) = view.plan_value(&plan);
        let expected_value = match name {
            "no_subscription" | "canceled_deleted" => "No plan".to_owned(),
            "incomplete" => "Waiting for the payment".to_owned(),
            "active" | "trialing" => "Connect Personal · Renews 21 Oct 2026".to_owned(),
            "active_cancel_at_period_end" => "Connect Personal · Ends 21 Oct 2026".to_owned(),
            "past_due_in_grace" | "past_due_last_second_of_grace" => {
                "Connect Personal · Past due".to_owned()
            }
            "canceled_suspended" | "canceled_last_second_before_deletion" => "Ended".to_owned(),
            _ => "Read-only until 4 Dec 2026".to_owned(),
        };
        assert_eq!(value, expected_value, "{name}");
        let note = plan_note(&plan).map(|(line, _)| line);
        match status.as_str() {
            "past_due" => assert!(
                note.as_deref()
                    .is_some_and(|line| line.contains("by 4 Nov 2026")),
                "{name}: {note:?}"
            ),
            "read_only" | "suspended" => assert!(
                note.as_deref()
                    .is_some_and(|line| line.contains("deleted on 2 Feb 2027")),
                "{name}: {note:?}"
            ),
            _ => assert_eq!(note, None, "{name}"),
        }
        let status_line = view.status_line();
        assert!(!status_line.is_empty(), "{name}");
        // Drawn: the row, and the buttons of the account that pays.
        let mut text = String::new();
        for _ in 0..2 {
            let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
                super::connect::draw(ui, &view);
            });
            text.clear();
            for clipped in &output.shapes {
                collect(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        assert!(text.contains(&expected_value), "{name}: {text}");
        assert_eq!(
            text.contains(MANAGE_BILLING),
            status != "none",
            "{name}: Manage Billing… for a plan with a customer: {text}"
        );
        assert_eq!(
            text.contains("Choose a Plan…"),
            matches!(status.as_str(), "none" | "read_only" | "suspended"),
            "{name}: Choose a Plan…: {text}"
        );
        assert!(
            !text.contains('€'),
            "{name}: no price outside the picker: {text}"
        );
    }
}

// ---- The text rules (plans section 5). ----

/// The texts of the section call the paid part Apassy Connect and use the plan names;
/// "free" is said only of what runs on your own hardware; relay sync and shared vaults
/// are never the paid feature; the hosted relay is never "for teams"; no text holds a
/// price.
#[test]
fn the_texts_follow_plans_section_5() {
    assert_eq!(fallback_name("personal"), "Connect Personal");
    assert_eq!(fallback_name("family"), "Connect Family");
    assert_eq!(fallback_name("team"), "Connect Team");
    let names: Vec<String> = fixture_plans()
        .offers
        .iter()
        .map(|offer| offer.name.clone())
        .collect();
    assert_eq!(
        names,
        ["Connect Personal", "Connect Family", "Connect Team"]
    );
    for text in TEXTS {
        let lower = text.to_lowercase();
        if lower
            .split(|c: char| !c.is_alphanumeric())
            .any(|word| word == "free")
        {
            assert_eq!(*text, SELF_HOST, "\"free\" only for self-hosting: {text}");
            assert!(lower.contains("your own hardware"));
        }
        for forbidden in [
            "relay sync",
            "shared vault",
            "for teams",
            "hosted relay",
            "upgrade",
            "subscribe",
            "trial",
            "premium",
            "pro plan",
        ] {
            if forbidden == "shared vault" && lower.contains("its shared vaults") {
                continue;
            }
            assert!(!lower.contains(forbidden), "{forbidden}: {text}");
        }
        assert!(!text.contains('€'), "no price in a text: {text}");
        assert!(
            !lower.contains(" a month") || lower.contains("each further"),
            "no amount per month in a text: {text}"
        );
    }
}
