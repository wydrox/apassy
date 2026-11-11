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
use zeroize::Zeroizing;

use super::connect::live::{self, Guarded};
use super::connect::{
    Account, Action, CONTINUE_BROWSER, ConnectView, DELETE_TITLE, FORGET_THIS_MAC, LOADING_PRICES,
    MANAGE_BILLING, NOT_ON_CONNECT, NOT_VERIFIED, PRICES_FAILED, Plan, Plans, REMOVED, SELF_HOST,
    Sheet, SheetChoice, Shown, TEXTS, TRY_AGAIN, fallback_name, money, plan_note,
};
use super::owner_tests::{PASS, collect, confirm_with, input, unlocked_app_with_item};
use crate::connect::{
    ConnectAccount, ConnectClient, ConnectError, DeviceKeyStore, JoinPoll, JoinRequest,
    MemoryKeyStore, PlansView, SessionState,
};
use crate::desktop::DesktopApp;
use crate::node::tunnel::{AccountAuth, Failure, TunnelAuth};

/// The fake Connect reads the app's sync module under this name.
use crate::sync as relay_api;
#[path = "../../../tests/common/fake_connect.rs"]
pub(super) mod fake_connect;

use fake_connect::FakeConnect;

/// The fake relay of the desktop keeps the vault stores of the fake Connect, as in the
/// integration tests (`tests/common/mod.rs`).
impl fake_connect::StoreRelay for crate::desktop::fake_relay::FakeRelay {
    fn url(&self) -> String {
        self.url.clone()
    }
    fn set_origin(&self, origin: &str) {
        crate::desktop::fake_relay::FakeRelay::set_origin(self, origin);
    }
    fn add_store_team(&self, name: &str, device_name: &str, public_key: &[u8]) -> (String, u64) {
        crate::desktop::fake_relay::FakeRelay::add_store_team(self, name, device_name, public_key)
    }
    fn add_store_device(&self, team_id: &str, device_name: &str, public_key: &[u8]) -> u64 {
        crate::desktop::fake_relay::FakeRelay::add_store_device(
            self,
            team_id,
            device_name,
            public_key,
        )
    }
    fn remove_team(&self, team_id: &str) {
        crate::desktop::fake_relay::FakeRelay::remove_team(self, team_id);
    }
    fn set_team_sync_bytes(&self, team_id: &str, bytes: u64) {
        crate::desktop::fake_relay::FakeRelay::set_team_sync_bytes(self, team_id, bytes);
    }
    fn set_store_guard(&self, guard: fake_connect::StoreGuard) {
        crate::desktop::fake_relay::FakeRelay::set_store_guard(self, guard);
    }
}

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
pub(super) fn connect_app(dir: &TempDir, connect: &FakeConnect) -> DesktopApp {
    connect_app_with(dir, connect, Arc::new(MemoryKeyStore::new()))
}

/// [`connect_app`] with the key store `store` (a counting fake).
pub(super) fn connect_app_with(
    dir: &TempDir,
    connect: &FakeConnect,
    store: Arc<dyn DeviceKeyStore>,
) -> DesktopApp {
    let (mut app, _) = unlocked_app_with_item(dir);
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    app.connect_configure(Some(store), Some(data));
    let live = &mut app.ui.connect.live;
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
pub(super) fn until(
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
pub(super) fn create_account(ctx: &egui::Context, app: &mut DesktopApp, name: &str) -> String {
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
    app.connect_session()
        .store()
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
                list_verified: true,
                list_nearly_full: false,
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
                list_verified: true,
                list_nearly_full: false,
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

// ---- One account session for the app (plan s7 unit M5b). ----

/// A key store whose every read the owner cancels (Touch ID cancelled on the Mac).
pub(super) struct CancelledStore;

impl DeviceKeyStore for CancelledStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, crate::connect::DeviceKeyError> {
        Err(crate::connect::DeviceKeyError::Cancelled)
    }
    fn store(&self, _pkcs8: &[u8]) -> Result<(), crate::connect::DeviceKeyError> {
        Err(crate::connect::DeviceKeyError::Cancelled)
    }
    fn delete(&self) -> Result<bool, crate::connect::DeviceKeyError> {
        Ok(false)
    }
}

/// A cancelled read at the unlock is the signed-out state, the vault stays open, and
/// "Sign In…" reads again.
#[test]
fn a_cancelled_read_at_the_unlock_is_signed_out_and_the_vault_stays_open() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    app.connect_configure(
        Some(Arc::new(CancelledStore)),
        Some(dir.path().join("data")),
    );
    until(&ctx, &mut app, "the signed-out state", |app| {
        matches!(app.connect_session().state(), SessionState::SignedOut(_))
    });
    assert!(matches!(live::view(&app).shown, Shown::SignedOut { .. }));
    assert!(!app.owner_ui.session.is_locked());
    assert_eq!(
        app.connect_session().state(),
        SessionState::SignedOut(ConnectError::Cancelled)
    );
    let painted = text(&ctx, &mut app);
    assert!(
        painted.contains(super::connect::SIGNED_OUT_NOTE),
        "{painted}"
    );
    assert!(painted.contains(super::connect::SIGN_IN), "{painted}");
}

/// Unlock the vault of `app` with the passphrase, as the unlock screen does, and run the
/// frames until the read of the key ended.
fn unlock(ctx: &egui::Context, app: &mut DesktopApp) {
    app.owner_ui
        .session
        .unlock(super::owner_tests::PASS)
        .expect("unlock");
    pass(ctx, app, live::step);
    until(ctx, app, "the read of the key", |app| {
        app.connect_session().state() != SessionState::Opening
    });
}

/// The session opens with the unlock with one read of the key store, and Settings, the
/// sync, and the tunnel use it without another read; a lock, the sleep that locks the
/// vault, and a quit close it; the next unlock reads once more.
#[test]
fn one_session_for_each_unlock_shared_by_settings_the_sync_and_the_tunnel() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let store = Arc::new(MemoryKeyStore::new());
    let mut app = connect_app_with(&dir, &connect, store.clone());
    let ctx = egui::Context::default();
    let account_id = create_account(&ctx, &mut app, "Rafal");
    connect.entitle(&account_id);

    // Lock, then unlock: one read of the store opens the session for all three.
    app.lock_vault(Some(&ctx));
    let session = app.connect_session();
    assert_eq!(session.state(), SessionState::Closed);
    assert!(session.signer().is_none());
    assert!(app.ui.connect.live.sync_account().is_none());
    let before = store.reads();
    unlock(&ctx, &mut app);
    until(&ctx, &mut app, "the account", |app| shown(app).is_some());
    assert_eq!(store.reads(), before + 1, "one read for the unlock");

    // The sync gets the key of the session, and the tunnel signs in with it.
    let sync = app
        .ui
        .connect
        .live
        .sync_account()
        .expect("the sync account");
    let signer = sync.signer.expect("the key goes to the sync");
    assert!(Arc::ptr_eq(&signer, &session.signer().expect("open")));
    assert!(Arc::ptr_eq(&sync.account, &session.slot()));
    let tunnel = AccountAuth::new(app.connect_session());
    assert!(tunnel.has_account());
    assert_eq!(tunnel.origin(), connect.url);
    let mut seen = None;
    tunnel
        .with_token(&mut |token| {
            seen = Some(token.to_owned());
            Ok(())
        })
        .expect("the tunnel signs in");
    assert!(seen.is_some_and(|token| token.starts_with("apassy_act_")));
    tunnel.entitled().expect("the tunnel is entitled");
    // Settings asks again: still no read.
    act(&ctx, &mut app, Action::SignIn);
    settle(&ctx, &mut app);
    tunnel.sign_out();
    assert!(session.is_open(), "the tunnel never closes the session");
    assert_eq!(store.reads(), before + 1, "no part reads the store again");

    // A lock closes it for every part.
    app.lock_vault(Some(&ctx));
    assert_eq!(session.state(), SessionState::Closed);
    assert!(session.signer().is_none());
    assert!(session.slot().lock().unwrap().is_none());
    assert!(matches!(
        tunnel.with_token(&mut |_| Ok(())),
        Err(Failure::Offline(_))
    ));
    assert!(matches!(live::view(&app).shown, Shown::SignedOut { .. }));

    // The sleep that locks the vault ("When the screen locks or the computer sleeps").
    unlock(&ctx, &mut app);
    assert!(session.is_open());
    assert_eq!(store.reads(), before + 2);
    app.auto_lock.policy = crate::desktop::auto_lock::LockPolicy::Session;
    app.auto_lock.source.record(Some(0.0), true);
    pass(&ctx, &mut app, |app, ctx| app.poll_auto_lock(ctx));
    assert!(
        app.owner_ui.session.is_locked(),
        "the sleep locked the vault"
    );
    assert_eq!(session.state(), SessionState::Closed);
    assert!(session.signer().is_none());

    // A lock that no `lock_vault` saw: the next frame closes the session.
    app.auto_lock.policy = crate::desktop::auto_lock::LockPolicy::Never;
    unlock(&ctx, &mut app);
    assert!(session.is_open());
    app.owner_ui.session.lock().expect("lock");
    pass(&ctx, &mut app, live::step);
    assert_eq!(session.state(), SessionState::Closed);

    // The quit.
    unlock(&ctx, &mut app);
    assert!(session.is_open());
    app.shut_down();
    assert_eq!(session.state(), SessionState::Closed);
    assert!(session.signer().is_none());
    assert_eq!(
        store.reads(),
        before + 4,
        "one read for each of the four unlocks"
    );
}

/// When Connect says this device was removed, the part that meets it (here the tunnel)
/// makes it the state of all three: Settings shows it with no call of its own, the sync
/// gets no key, and the tunnel and Settings get the removal. Nothing is deleted.
#[test]
fn a_removal_that_the_tunnel_meets_reaches_settings_and_the_sync() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    let this = shown(&app).expect("account").devices[0].clone();
    let session = app.connect_session();
    let tunnel = AccountAuth::new(app.connect_session());
    // A fresh sign-in is needed for Connect to say it.
    app.lock_vault(Some(&ctx));
    unlock(&ctx, &mut app);
    until(&ctx, &mut app, "the account", |app| shown(app).is_some());
    connect.revoke(&this.id);
    // The cached token of the refresh is refused at the next call, then the sign-in.
    let result = tunnel.with_token(&mut |_| Err(Failure::Unauthenticated));
    assert_eq!(result.unwrap_err(), Failure::NoAccount);
    assert_eq!(
        session.state(),
        SessionState::Removed(ConnectError::Revoked)
    );
    pass(&ctx, &mut app, live::step);
    assert!(matches!(live::view(&app).shown, Shown::Removed { .. }));
    assert!(app.ui.connect.live.sync_account().is_none());
    assert!(session.signer().is_none());
    assert_eq!(tunnel.entitled().unwrap_err(), Failure::NoAccount);
    assert!(has_key(&app), "nothing is deleted");
    assert!(dir.path().join("data/connect/account.json").exists());
}

/// A device that this Mac cannot verify is not among the signers of the sync's policy of
/// the shared session, as the section shows it "Not verified".
#[test]
fn an_unverified_device_is_refused_by_the_sync_of_the_session() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    let account_id = create_account(&ctx, &mut app, "Rafal");
    let stranger = crate::sync::DeviceKey::generate().expect("key");
    connect.insert_device(&account_id, "Mac Studio", stranger.public_key());
    act(&ctx, &mut app, Action::SignIn);
    until(&ctx, &mut app, "two devices", |app| {
        shown(app).is_some_and(|account| account.devices.len() == 2)
    });
    let sync = app.ui.connect.live.sync_account().expect("sync account");
    assert!(!sync.signers.allows(stranger.public_key(), 1, 9));
    assert!(
        !sync
            .signers
            .accepted
            .iter()
            .any(|key| key == stranger.public_key())
    );
}

/// A link for the origin of this Mac's Connect account is decided from the account file:
/// while the account session is not open, the join asks for the sign-in and sends nothing
/// (never a key of its own for a store of the account).
#[test]
fn a_link_for_the_account_origin_with_the_session_closed_asks_for_the_sign_in() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    app.ui.connect.live.session().close();
    assert!(app.ui.connect.live.sync_account().is_none());
    let before = connect.log().len();
    app.sync.relay.link_input = format!(
        "{}/link#apassy_lnk_t_7k2m5q4x3c_{}",
        connect.url,
        "ab".repeat(32)
    );
    app.sync.relay.device_input = "Synthetic Mac mini".to_owned();
    app.relay_join_request(None, None);
    app.relay_join_settle_for_test();
    assert!(app.sync.relay.join_view(None).is_none(), "no join runs");
    let error = app.sync.relay.join_error.clone().unwrap_or_default();
    assert!(error.contains("Sign In"), "asks for the sign-in: {error}");
    assert!(
        !connect.log()[before..]
            .iter()
            .any(|line| line.starts_with("POST /v1/devices/link")),
        "nothing was sent: {:?}",
        connect.log()
    );
}

/// A removal reaches the running sync of a vault store through the window: the app turns
/// on the sync through Apassy Connect, the owner revokes another device of the account in
/// Settings › Connect, and the refresh after it hands the new policy to the relay sync of
/// the vault (`relay_share_connect`). A later head of the revoked device, a copy that
/// merges, is not merged by the session that runs: the vault waits for a device of the
/// account instead.
#[test]
fn a_removal_reaches_the_running_store_session_through_the_window() {
    use crate::sync::{HeadFields, sha256_hex};
    let dir = TempDir::new().expect("temp dir");
    let relay = Arc::new(crate::desktop::fake_relay::FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    // A vault of the vault list, unlocked, and the Connect section of this test.
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("mac"), true);
    let ctx = egui::Context::default();
    app.vault_list.name_input = "Personal".to_owned();
    app.owner_ui.passphrase.push_str(PASS);
    app.owner_ui.passphrase_confirm.push_str(PASS);
    super::start::create_vault(&mut app, &ctx);
    assert!(!app.owner_ui.session.is_locked(), "{}", app.status_text);
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    app.connect_configure(Some(Arc::new(MemoryKeyStore::new())), Some(data));
    let live = &mut app.ui.connect.live;
    live.origin = Some(connect.url.clone());
    live.poll_every = Some(Duration::from_millis(40));
    live.join_poll_every = Some(Duration::from_millis(40));
    super::open_settings(&mut app, super::SettingsSection::Connect);
    let account_id = create_account(&ctx, &mut app, "Rafal");
    connect.entitle(&account_id);

    // The iMac joins with the words and the owner check.
    act(&ctx, &mut app, Action::AddDevice);
    until(&ctx, &mut app, "the link", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::AddDevice { .. }))
    });
    let Some(Sheet::AddDevice { code, .. }) = &app.ui.connect.sheet else {
        unreachable!();
    };
    let code = code.as_str().to_owned();
    let imac_store = MemoryKeyStore::new();
    let imac_path = dir.path().join("imac/connect/account.json");
    let mut request = JoinRequest::start(
        ConnectClient::new(&connect.url).expect("client"),
        &imac_store,
        &imac_path,
        &code,
        "Synthetic iMac",
    )
    .expect("join");
    until(&ctx, &mut app, "the words", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Words { .. }))
    });
    choose(&ctx, &mut app, SheetChoice::Go);
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "the device", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::DeviceAdded { .. }))
    });
    let imac = match request.poll() {
        Ok(JoinPoll::Confirmed(imac)) => *imac,
        other => panic!("not confirmed: {other:?}"),
    };
    choose(&ctx, &mut app, SheetChoice::Done);
    act(&ctx, &mut app, Action::SignIn);
    until(&ctx, &mut app, "two verified devices and the plan", |app| {
        shown(app).is_some_and(|account| {
            account.devices.len() == 2 && account.devices.iter().all(|device| device.verified)
        }) && app
            .ui
            .connect
            .live
            .sync_account()
            .is_some_and(|account| account.plan.is_some_and(crate::sync::StorePlan::entitled))
    });

    // The sync through Apassy Connect: the store with both devices.
    let entry = app.current_vault().expect("the open vault").clone();
    app.relay_enable_connect(&entry.id).expect("turn on");
    app.relay_settle_for_test();
    let sync = app.relay_of(&entry.id).expect("the relay sync");
    let team = sync
        .state()
        .expect("state")
        .and_then(|state| state.team_id)
        .expect("a store");
    let imac_key = imac.signer().expect("key").public_key().to_vec();
    let number = relay
        .team_devices(&team)
        .into_iter()
        .find(|(_, key)| *key == imac_key)
        .map(|(number, _)| number)
        .expect("the iMac is in the store");
    app.sync_now();
    app.relay_settle_for_test();
    assert!(sync.has_session(), "a session runs");

    // The owner revokes the iMac; the refresh after it reaches the relay sync.
    let index = shown(&app)
        .expect("account")
        .devices
        .iter()
        .position(|device| device.name == "Synthetic iMac")
        .expect("the iMac");
    act(&ctx, &mut app, Action::Revoke(index));
    choose(&ctx, &mut app, SheetChoice::Go);
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "one device", |app| {
        shown(app).is_some_and(|account| account.devices.len() == 1)
    });
    assert!(sync.has_session(), "the same session still runs");

    // A later head of the iMac with a copy of the vault that merges.
    let copy_path = dir.path().join("imac-copy.db");
    std::fs::copy(&entry.path, &copy_path).expect("copy");
    let mut copy = crate::vault::Vault::open(&copy_path).expect("open");
    copy.unlock(PASS).expect("unlock");
    copy.add(crate::vault::ItemDraft {
        title: "From the revoked iMac".to_owned(),
        kind: crate::contracts::CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![crate::vault::Field {
            name: "token".to_owned(),
            value: crate::vault::SecretValue::new("SYNTH-revoked".to_owned()),
            secret: true,
        }],
    })
    .expect("add");
    let synced = dir.path().join("imac-copy.sync");
    copy.write_sync_copy(&synced, "Synthetic iMac")
        .expect("sync copy");
    let bytes = std::fs::read(&synced).expect("bytes");
    let last = relay.heads_of(&team).last().cloned().expect("a head");
    let fields = HeadFields {
        version: last.version + 1,
        previous: last.hash(),
        snapshot_sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
        device_id: number,
        ..HeadFields::parse(&last.text).expect("head")
    };
    let signed = imac.signer().expect("key").sign_head(fields).expect("sign");
    relay.replace_store_from(
        &team,
        vec![(
            crate::desktop::fake_relay::StoredHead {
                version: last.version + 1,
                text: signed.text,
                signature: signed.signature,
                device_id: number,
            },
            bytes,
        )],
    );
    app.sync_now();
    app.relay_settle_for_test();
    let titles: Vec<String> = app
        .owner_ui
        .session
        .search("")
        .expect("search")
        .into_iter()
        .map(|summary| summary.name)
        .collect();
    assert!(
        !titles.iter().any(|title| title == "From the revoked iMac"),
        "not merged: {titles:?}"
    );
    assert!(
        matches!(
            app.sync.statuses.get(&entry.id),
            Some(super::sync::UiStatus::Problem(text))
                if text == &crate::sync::SyncError::WaitsForAccountDevice.to_string()
        ),
        "{:?}",
        app.sync.statuses.get(&entry.id)
    );
}

/// A Connect that cannot be reached never blocks the unlock: the vault is open, the
/// session is open, and the section says "Connect unreachable" and asks again.
#[test]
fn an_unreachable_connect_never_blocks_the_unlock() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let store = Arc::new(MemoryKeyStore::new());
    let mut app = connect_app_with(&dir, &connect, store.clone());
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    app.lock_vault(Some(&ctx));
    // The account file names a Connect that answers nothing now.
    let file = dir.path().join("data/connect/account.json");
    let saved = std::fs::read_to_string(&file).expect("account file");
    let dead = format!("http://127.0.0.1:{}", unused_port());
    std::fs::write(&file, saved.replace(&connect.url, &dead)).expect("account file");
    unlock(&ctx, &mut app);
    assert!(
        !app.owner_ui.session.is_locked(),
        "the vault is open at once"
    );
    until(&ctx, &mut app, "the unreachable state", |app| {
        matches!(live::view(app).shown, Shown::Unreachable { .. })
    });
    assert!(app.connect_session().is_open());
    assert_eq!(live::view(&app).status_line(), super::connect::UNREACHABLE);
    let painted = text(&ctx, &mut app);
    assert!(painted.contains(super::connect::UNREACHABLE), "{painted}");
}

/// A port that nothing listens on.
fn unused_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// "Sign In…" never reads the key while Apassy is locked.
#[test]
fn sign_in_reads_nothing_while_locked() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let store = Arc::new(MemoryKeyStore::new());
    let mut app = connect_app_with(&dir, &connect, store.clone());
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    app.lock_vault(Some(&ctx));
    let reads = store.reads();
    act(&ctx, &mut app, Action::SignIn);
    for _ in 0..5 {
        pass(&ctx, &mut app, live::step);
    }
    assert_eq!(store.reads(), reads);
    assert!(!app.connect_session().is_open());
}

/// macOS keeps the Connect texts that it had before the wording macros, byte for byte.
#[cfg(not(target_os = "linux"))]
#[test]
fn mac_connect_texts_are_unchanged() {
    use super::connect::*;
    for (text, before) in [
        (ADD_THIS_MAC, "Add This Mac to an Account…"),
        (
            KEY_NOTE,
            "No password and no email: the key of this Mac, in the Keychain, signs in.",
        ),
        (
            SIGNED_OUT_NOTE,
            "Touch ID reads the Connect key of this Mac.",
        ),
        (
            CREATE_LEAD,
            "No password and no email: the key of this Mac, in the Keychain, signs in. You choose a plan later.",
        ),
        (
            RECOVERY_NOTE,
            "If every device of the account is lost, this code gives the account to a new Mac. The vault copies at Connect are deleted then; your vaults stay on your devices.",
        ),
        (
            ADD_LEAD,
            "On the new device, choose Add This Mac to an Account (on a Mac) or scan this code (on the iPhone).",
        ),
        (FORGET_TITLE, "Forget This Mac?"),
        (
            REMOVED_NOTE,
            "Apassy Connect says this Mac was removed from its account. Its Connect key and its account file stay on this Mac until you forget the account here.",
        ),
        (FORGET_THIS_MAC, "Forget This Mac…"),
        (
            FORGET_REMOVED_LEAD,
            "The Connect key and the account file of this Mac are deleted, and the vault copies of the account stop syncing on this Mac. To use the account here again, add this Mac from another device of the account.",
        ),
        (
            FORGET_LEAD,
            "This Mac leaves your Connect account, and its Connect key is deleted. To use the account here again, add this Mac from another device of the account.",
        ),
        (JOIN_ACCOUNT_TITLE, "Add This Mac to an Account"),
        (JOINED_TITLE, "This Mac Is Added"),
        (THIS_DEVICE, "This Mac"),
        (LEFT, "This Mac left the Connect account."),
        (FORGOT, "This Mac forgot the Connect account."),
    ] {
        assert_eq!(text, before);
    }
    for (error, before) in [
        (
            ConnectError::Unauthenticated,
            "Apassy Connect did not accept this Mac's sign-in.",
        ),
        (
            ConnectError::TagRefused,
            "The account key of this Mac does not sign this.",
        ),
        (
            ConnectError::NoDeviceKey,
            "This Mac has no Apassy Connect key.",
        ),
        (
            ConnectError::SignedOut,
            "Apassy Connect is signed out on this Mac. Unlock Apassy and try again.",
        ),
        (
            ConnectError::KeyLost,
            "This Mac's Apassy Connect key is gone (the Touch ID fingerprints changed). Add this Mac again from another device, or recover the account.",
        ),
        (
            ConnectError::KeychainUnavailable,
            "The Keychain is not available to this build. Apassy Connect works only in Apassy.app.",
        ),
        (
            ConnectError::Cancelled,
            "Touch ID was cancelled. Nothing changed.",
        ),
        (
            ConnectError::AccountExists,
            "This Mac already has an Apassy Connect account.",
        ),
        (
            ConnectError::NoAccount,
            "This Mac has no Apassy Connect account.",
        ),
        (
            ConnectError::Local,
            "Apassy could not complete this step on this Mac.",
        ),
    ] {
        assert_eq!(error.to_string(), before);
    }
    assert_eq!(
        Failure::NoAccount.to_string(),
        "this Mac has no Apassy Connect account"
    );
    assert_eq!(
        Failure::NodeUnknown.to_string(),
        "Apassy Connect does not know this Mac's node"
    );
}

/// Linux names no Mac-only thing in the Connect texts and errors.
#[cfg(target_os = "linux")]
#[test]
fn linux_connect_texts_name_nothing_of_the_mac() {
    let errors: Vec<String> = [
        ConnectError::Unauthenticated,
        ConnectError::TagRefused,
        ConnectError::NoDeviceKey,
        ConnectError::SignedOut,
        ConnectError::KeyLost,
        ConnectError::KeychainUnavailable,
        ConnectError::Cancelled,
        ConnectError::AccountExists,
        ConnectError::NoAccount,
        ConnectError::Local,
        ConnectError::Revoked,
    ]
    .iter()
    .map(ToString::to_string)
    .chain([
        Failure::NoAccount.to_string(),
        Failure::NodeUnknown.to_string(),
    ])
    .collect();
    for text in TEXTS
        .iter()
        .copied()
        .chain(errors.iter().map(String::as_str))
    {
        for word in ["Touch ID", "Keychain", "keychain", "Apassy.app", "macOS"] {
            assert!(!text.contains(word), "{text}");
        }
        assert!(
            !text
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| word == "Mac"),
            "{text}"
        );
    }
    assert!(super::connect::KEY_NOTE.contains("in a private file of your user"));
}

/// A vault store of two devices whose removed device pushed the last head (an iMac that
/// left the account), as `a_removal_reaches_the_running_store_session_through_the_window`
/// sets it up: the open vault waits for another device of the account.
struct Departing {
    _dir: TempDir,
    _connect: FakeConnect,
    relay: Arc<crate::desktop::fake_relay::FakeRelay>,
    ctx: egui::Context,
    app: DesktopApp,
    id: String,
    team: String,
    /// The version and the time of the head that the iMac left.
    version: u64,
    time: u64,
}

fn departing() -> Departing {
    use crate::sync::{HeadFields, sha256_hex};
    let dir = TempDir::new().expect("temp dir");
    let relay = Arc::new(crate::desktop::fake_relay::FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    // A vault of the vault list, unlocked, and the Connect section of this test.
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("mac"), true);
    let ctx = egui::Context::default();
    app.vault_list.name_input = "Personal".to_owned();
    app.owner_ui.passphrase.push_str(PASS);
    app.owner_ui.passphrase_confirm.push_str(PASS);
    super::start::create_vault(&mut app, &ctx);
    assert!(!app.owner_ui.session.is_locked(), "{}", app.status_text);
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    app.connect_configure(Some(Arc::new(MemoryKeyStore::new())), Some(data));
    let live = &mut app.ui.connect.live;
    live.origin = Some(connect.url.clone());
    live.poll_every = Some(Duration::from_millis(40));
    live.join_poll_every = Some(Duration::from_millis(40));
    super::open_settings(&mut app, super::SettingsSection::Connect);
    let account_id = create_account(&ctx, &mut app, "Rafal");
    connect.entitle(&account_id);

    // The iMac joins with the words and the owner check.
    act(&ctx, &mut app, Action::AddDevice);
    until(&ctx, &mut app, "the link", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::AddDevice { .. }))
    });
    let Some(Sheet::AddDevice { code, .. }) = &app.ui.connect.sheet else {
        unreachable!();
    };
    let code = code.as_str().to_owned();
    let imac_store = MemoryKeyStore::new();
    let imac_path = dir.path().join("imac/connect/account.json");
    let mut request = JoinRequest::start(
        ConnectClient::new(&connect.url).expect("client"),
        &imac_store,
        &imac_path,
        &code,
        "Synthetic iMac",
    )
    .expect("join");
    until(&ctx, &mut app, "the words", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Words { .. }))
    });
    choose(&ctx, &mut app, SheetChoice::Go);
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "the device", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::DeviceAdded { .. }))
    });
    let imac = match request.poll() {
        Ok(JoinPoll::Confirmed(imac)) => *imac,
        other => panic!("not confirmed: {other:?}"),
    };
    choose(&ctx, &mut app, SheetChoice::Done);
    act(&ctx, &mut app, Action::SignIn);
    until(&ctx, &mut app, "two verified devices and the plan", |app| {
        shown(app).is_some_and(|account| {
            account.devices.len() == 2 && account.devices.iter().all(|device| device.verified)
        }) && app
            .ui
            .connect
            .live
            .sync_account()
            .is_some_and(|account| account.plan.is_some_and(crate::sync::StorePlan::entitled))
    });

    // The sync through Apassy Connect: the store with both devices.
    let entry = app.current_vault().expect("the open vault").clone();
    app.relay_enable_connect(&entry.id).expect("turn on");
    app.relay_settle_for_test();
    let sync = app.relay_of(&entry.id).expect("the relay sync");
    let team = sync
        .state()
        .expect("state")
        .and_then(|state| state.team_id)
        .expect("a store");
    let imac_key = imac.signer().expect("key").public_key().to_vec();
    let number = relay
        .team_devices(&team)
        .into_iter()
        .find(|(_, key)| *key == imac_key)
        .map(|(number, _)| number)
        .expect("the iMac is in the store");
    app.sync_now();
    app.relay_settle_for_test();
    assert!(sync.has_session(), "a session runs");

    // The owner revokes the iMac; the refresh after it reaches the relay sync.
    let index = shown(&app)
        .expect("account")
        .devices
        .iter()
        .position(|device| device.name == "Synthetic iMac")
        .expect("the iMac");
    act(&ctx, &mut app, Action::Revoke(index));
    choose(&ctx, &mut app, SheetChoice::Go);
    confirm_with(&mut app, &ctx, PASS);
    until(&ctx, &mut app, "one device", |app| {
        shown(app).is_some_and(|account| account.devices.len() == 1)
    });
    assert!(sync.has_session(), "the same session still runs");

    // A later head of the iMac with a copy of the vault that merges.
    let copy_path = dir.path().join("imac-copy.db");
    std::fs::copy(&entry.path, &copy_path).expect("copy");
    let mut copy = crate::vault::Vault::open(&copy_path).expect("open");
    copy.unlock(PASS).expect("unlock");
    copy.add(crate::vault::ItemDraft {
        title: "From the revoked iMac".to_owned(),
        kind: crate::contracts::CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![crate::vault::Field {
            name: "token".to_owned(),
            value: crate::vault::SecretValue::new("SYNTH-revoked".to_owned()),
            secret: true,
        }],
    })
    .expect("add");
    let synced = dir.path().join("imac-copy.sync");
    copy.write_sync_copy(&synced, "Synthetic iMac")
        .expect("sync copy");
    let bytes = std::fs::read(&synced).expect("bytes");
    let last = relay.heads_of(&team).last().cloned().expect("a head");
    let fields = HeadFields {
        version: last.version + 1,
        previous: last.hash(),
        snapshot_sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
        device_id: number,
        ..HeadFields::parse(&last.text).expect("head")
    };
    let head_time = fields.time;
    let version = fields.version;
    let signed = imac.signer().expect("key").sign_head(fields).expect("sign");
    relay.replace_store_from(
        &team,
        vec![(
            crate::desktop::fake_relay::StoredHead {
                version: last.version + 1,
                text: signed.text,
                signature: signed.signature,
                device_id: number,
            },
            bytes,
        )],
    );
    app.sync_now();
    app.relay_settle_for_test();
    assert!(
        matches!(
            app.sync.statuses.get(&entry.id),
            Some(super::sync::UiStatus::Problem(text))
                if text == &crate::sync::SyncError::WaitsForAccountDevice.to_string()
        ),
        "{:?}",
        app.sync.statuses.get(&entry.id)
    );
    Departing {
        _dir: dir,
        _connect: connect,
        relay,
        ctx,
        app,
        id: entry.id,
        team,
        version,
        time: head_time,
    }
}

/// The painted text of the window after three frames, with Settings › Vault open and its
/// sync section shown (a test turns it on without real synced folders).
fn vault_text(ctx: &egui::Context, app: &mut DesktopApp) -> String {
    app.sync.offered = true;
    super::open_settings(app, super::SettingsSection::Vault);
    painted(ctx, app)
}

/// The painted text of the window after three frames, on a screen tall enough for every
/// row of Settings › Vault.
fn painted(ctx: &egui::Context, app: &mut DesktopApp) -> String {
    let mut text = String::new();
    for _ in 0..3 {
        let tall = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 2400.0),
            )),
            ..input(0.0, Vec::new())
        };
        let output = ctx.run_ui(tall, |ui| super::draw(app, ui));
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn vault_titles(app: &DesktopApp) -> Vec<String> {
    app.owner_ui
        .session
        .search("")
        .expect("search")
        .into_iter()
        .map(|summary| summary.name)
        .collect()
}

/// The open vault waits on the head of a removed device: Settings › Vault › Sync names the
/// device by its signed name and the time of that head, and offers both steps. "Use the
/// Copy That … Left…" merges that copy once and signs over it; the next sync is a plain
/// one.
#[test]
fn a_store_that_waits_on_a_removed_device_offers_its_copy_by_name() {
    let mut d = departing();
    let departed = d.app.relay_departed(&d.id).expect("the waiting head");
    assert_eq!(departed.name.as_deref(), Some("Synthetic iMac"));
    assert_eq!(departed.head.version, d.version);
    assert_eq!(departed.head.time, d.time);
    let text = vault_text(&d.ctx, &mut d.app);
    assert!(
        text.contains("Use the Copy That “Synthetic iMac” Left…"),
        "{text}"
    );
    assert!(
        text.contains(super::sync::relay::REPLACE_DEPARTED),
        "{text}"
    );
    assert!(
        text.contains("“Synthetic iMac” saved the last copy"),
        "{text}"
    );
    assert!(!text.contains("Use the relay copy…"), "{text}");

    d.app.sync_open_sheet(
        super::sync::SyncSheet::UseDepartedCopy { id: d.id.clone() },
        None,
    );
    let text = painted(&d.ctx, &mut d.app);
    assert!(
        text.contains("Use the copy that “Synthetic iMac” left?"),
        "{text}"
    );
    d.app.relay_use_departed(&d.id);
    d.app.relay_settle_for_test();
    assert!(d.app.ui.sheet.is_none(), "{}", d.app.status_text);
    assert!(
        d.app
            .status_text
            .starts_with("Apassy merged the copy that “Synthetic iMac” left"),
        "{}",
        d.app.status_text
    );
    assert!(
        vault_titles(&d.app)
            .iter()
            .any(|title| title == "From the revoked iMac"),
        "merged once"
    );
    let heads = d.relay.heads_of(&d.team);
    assert_eq!(heads.last().map(|head| head.version), Some(d.version + 1));
    assert!(matches!(
        d.app.sync.statuses.get(&d.id),
        Some(super::sync::UiStatus::UpToDate(_))
    ));
    assert!(d.app.relay_departed(&d.id).is_none());
    // The next sync is a plain one: nothing more goes up.
    d.app.sync_now();
    d.app.relay_settle_for_test();
    assert_eq!(d.relay.heads_of(&d.team).len(), heads.len());
    assert!(matches!(
        d.app.sync.statuses.get(&d.id),
        Some(super::sync::UiStatus::UpToDate(_))
    ));
}

/// "Replace It with This Mac's Copy…" pushes the vault of this Mac over the head that the
/// removed device left, without its change; the next sync is a plain one.
#[test]
fn replace_it_with_this_macs_copy_ends_the_wait_without_the_change() {
    let mut d = departing();
    d.app.sync_open_sheet(
        super::sync::SyncSheet::ReplaceDepartedCopy { id: d.id.clone() },
        None,
    );
    let text = painted(&d.ctx, &mut d.app);
    assert!(
        text.contains("Replace the copy that “Synthetic iMac” left?"),
        "{text}"
    );
    d.app.relay_replace(&d.id);
    d.app.relay_settle_for_test();
    assert!(d.app.ui.sheet.is_none(), "{}", d.app.status_text);
    let heads = d.relay.heads_of(&d.team);
    assert_eq!(heads.last().map(|head| head.version), Some(d.version + 1));
    assert!(
        !vault_titles(&d.app)
            .iter()
            .any(|title| title == "From the revoked iMac"),
        "not merged"
    );
    d.app.sync_now();
    d.app.relay_settle_for_test();
    assert_eq!(d.relay.heads_of(&d.team).len(), heads.len());
    assert!(matches!(
        d.app.sync.statuses.get(&d.id),
        Some(super::sync::UiStatus::UpToDate(_))
    ));
    assert!(d.app.relay_departed(&d.id).is_none());
}

/// Each step on the copy of a device that left asks for a fresh owner check that names
/// exactly that head and the choice: nothing goes up before it, a cancelled check changes
/// nothing, and after the check the copy is taken.
#[test]
fn the_copy_that_a_removed_device_left_is_taken_only_after_the_owner_check() {
    let mut d = departing();
    let heads = d.relay.heads_of(&d.team).len();
    d.app.relay_ask_departed(&d.id, false, Some(&d.ctx));
    let request = d
        .app
        .owner
        .check
        .as_ref()
        .map(|check| check.request.action())
        .expect("an owner check");
    assert!(
        matches!(
            &request,
            crate::broker::approvals::OwnerAction::TakeDepartedCopy {
                version,
                replace: false,
                ..
            } if *version == d.version
        ),
        "{request:?}"
    );
    assert!(request.needs_fresh_local_check());
    d.app.relay_settle_for_test();
    assert_eq!(
        d.relay.heads_of(&d.team).len(),
        heads,
        "nothing before the check"
    );
    // A cancelled check drops the step.
    d.app.owner.check = None;
    d.app.relay_settle_for_test();
    assert_eq!(d.relay.heads_of(&d.team).len(), heads);
    assert!(d.app.relay_departed(&d.id).is_some(), "it still waits");
    // Asked again and confirmed: the copy is merged once and this device's head goes up.
    d.app.relay_ask_departed(&d.id, false, Some(&d.ctx));
    confirm_with(&mut d.app, &d.ctx, PASS);
    d.app.relay_settle_for_test();
    let after = d.relay.heads_of(&d.team);
    assert_eq!(after.last().map(|head| head.version), Some(d.version + 1));
    assert!(
        vault_titles(&d.app)
            .iter()
            .any(|title| title == "From the revoked iMac"),
        "merged once"
    );
    assert!(d.app.relay_departed(&d.id).is_none());
}

/// C3: the signers of a shared store reach the running sync of the vault after a step of
/// Shared Vaults that wrote the account file, also when a later call of that step failed:
/// the owner's Mac shares its vault with Ola, Ola adds a second device, and the refresh
/// that learns it meets a Connect that does not list the stores.
#[test]
fn the_signers_reach_the_sync_after_a_share_step_whose_later_call_failed() {
    use crate::broker::approvals::{OwnerCheck, OwnerGate};
    use crate::connect::{ShareNames, account_file};
    let dir = TempDir::new().expect("temp dir");
    let relay = Arc::new(crate::desktop::fake_relay::FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("mac"), true);
    let ctx = egui::Context::default();
    app.vault_list.name_input = "Family".to_owned();
    app.owner_ui.passphrase.push_str(PASS);
    app.owner_ui.passphrase_confirm.push_str(PASS);
    super::start::create_vault(&mut app, &ctx);
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    app.connect_configure(Some(Arc::new(MemoryKeyStore::new())), Some(data));
    let live = &mut app.ui.connect.live;
    live.origin = Some(connect.url.clone());
    live.poll_every = Some(Duration::from_millis(40));
    live.join_poll_every = Some(Duration::from_millis(40));
    super::open_settings(&mut app, super::SettingsSection::Connect);
    let a_id = create_account(&ctx, &mut app, "Rafal");
    connect.entitle(&a_id);
    connect.make_group(&a_id, "family");
    act(&ctx, &mut app, Action::SignIn);
    until(&ctx, &mut app, "the plan", |app| {
        app.ui
            .connect
            .live
            .sync_account()
            .is_some_and(|account| account.plan.is_some_and(crate::sync::StorePlan::entitled))
    });
    let entry = app.current_vault().expect("the open vault").clone();
    app.relay_enable_connect(&entry.id).expect("turn on");
    app.relay_settle_for_test();
    let sync = app.relay_of(&entry.id).expect("the relay sync");
    let team = sync
        .state()
        .expect("state")
        .and_then(|state| state.team_id)
        .expect("a store");
    // Ola's account, and the owner checks of both people (each with a vault of the test).
    let x_dir = dir.path().join("ola");
    let x_keys = MemoryKeyStore::new();
    let (mut ola, _) = ConnectAccount::create(
        ConnectClient::new(&connect.url).expect("client"),
        &x_keys,
        &account_file(&x_dir),
        "Ola",
        "Synthetic MacBook",
    )
    .expect("Ola");
    let x_id = ola.state().account_id.clone();
    connect.entitle(&x_id);
    connect.add_member(&a_id, &x_id);
    let gate_dir = TempDir::new().expect("dir");
    let mut gate_vault =
        crate::vault::Vault::create(&gate_dir.path().join("gate.db"), PASS).expect("vault");
    gate_vault.unlock(PASS).expect("unlock");
    let epoch = gate_vault.epoch();
    let shared: crate::broker::SharedVault = Arc::new(std::sync::Mutex::new(Some(gate_vault)));
    let gate = OwnerGate::new(Arc::clone(&shared), None);
    let proof = |action| {
        gate.authorize(action, OwnerCheck::passphrase(PASS))
            .expect("owner check")
    };
    let names = ShareNames::default();
    let session = app.connect_session();
    let link = session
        .with_account(|account| account.start_share(&x_id, &team))
        .expect("code");
    let answer = ola.accept_code(link.code()).expect("answer");
    session
        .with_account(|account| {
            let requests = account.share_requests(&link)?;
            let action = account.share_action(&link, &requests[0], &names);
            account.confirm_share(&link, &requests[0], &names, proof(action), &epoch)
        })
        .expect("share");
    ola.accept_share(
        &answer,
        &names,
        proof(ola.accept_action(&answer, &names)),
        &epoch,
    )
    .expect("Ola accepts");
    // Ola's second device joins her account.
    let x2_keys = MemoryKeyStore::new();
    let ola_link = ola.start_link().expect("link");
    let mut request = JoinRequest::start(
        ConnectClient::new(&connect.url).expect("client"),
        &x2_keys,
        &account_file(&dir.path().join("ola2")),
        ola_link.code(),
        "Synthetic iMac",
    )
    .expect("join");
    assert!(matches!(request.poll().expect("poll"), JoinPoll::Waiting));
    let pending = ola.pending_joins(&ola_link).expect("pending");
    ola.confirm_join(
        &ola_link,
        &pending[0],
        proof(pending[0].owner_action(&x_id)),
        &epoch,
    )
    .expect("confirm");
    let ola2 = match request.poll().expect("poll") {
        JoinPoll::Confirmed(joined) => *joined,
        other => panic!("not confirmed: {other:?}"),
    };
    let x2_key = ola2.signer().expect("key").public_key().to_vec();
    // The refresh of Shared Vaults learns the device; the list of the stores then fails.
    connect.answer_route_error("GET /v1/account/vaults", 500, "relay_error");
    app.ui.connect.share.refresh_now();
    until(
        &ctx,
        &mut app,
        "the new device in the signers of the sync",
        |app| {
            !app.ui.connect.share.is_busy()
                && sync
                    .account_signers()
                    .is_some_and(|policy| policy.for_team(&team).accepts(&x2_key))
        },
    );
    assert!(
        app.ui
            .connect
            .live
            .sync_account()
            .expect("account")
            .signers
            .for_team(&team)
            .accepts(&x2_key)
    );
}
