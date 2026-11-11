//! Headless tests of "Use a vault from another Mac" › "Apassy Connect" on the start
//! screen, where no vault is unlocked: a computer without an account file joins the
//! account with the code of another device of the account, the account session opens for
//! that step only, the vault stores of the account are listed at each visit, and the
//! chosen store becomes a vault with sync through Apassy Connect. Connect is the
//! in-process fake of `tests/common/fake_connect.rs` with the fake relay of the desktop,
//! both on 127.0.0.1 (free ports); every value is synthetic and every file is in a
//! temporary directory.

use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use tempfile::TempDir;

use super::connect::live;
use zeroize::Zeroizing;

use super::connect::{
    ADD_THIS_MAC, Action, FORGET_OLD_FILE, JOIN_ACCOUNT_TITLE, JOINED_TITLE, OLD_FILE,
    OLD_FILE_TITLE, REMOVED, SIGN_IN, Sheet, SheetChoice, Shown, TRY_AGAIN,
};
use super::connect_tests::fake_connect::FakeConnect;
use super::connect_tests::{connect_app, connect_app_with, create_account, until};
use super::owner_tests::{PASS, collect, confirm_with, input};
use super::sync::OpenSource;
use super::sync::relay::{
    CONNECT_OPEN_EMPTY, CONNECT_OPEN_JOIN, CONNECT_OPEN_USE, CONNECT_SIGN_IN, JoinView,
};
use crate::connect::{DeviceKeyError, DeviceKeyStore, MemoryKeyStore, SessionState};
use crate::desktop::DesktopApp;
use crate::desktop::fake_relay::FakeRelay;

/// One frame of the app: the steps of the window (`DesktopApp::logic` runs them before
/// the drawing), then the whole window. Returns the painted text.
fn frame(ctx: &egui::Context, app: &mut DesktopApp) -> String {
    let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
        live::step(app, ui.ctx());
        super::draw(app, ui);
    });
    let mut text = String::new();
    for clipped in &output.shapes {
        collect(&clipped.shape, &mut text);
    }
    output.drop_without_applying_deltas();
    text
}

/// Frames until the painted text holds `done`; the last text.
fn frames_until(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    what: &str,
    done: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let text = frame(ctx, app);
        if done(&text) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "timed out: {what}: {text}\n{:?} {:?} {:?} {:?} {:?}",
            live::start_account(app),
            app.connect_session().state(),
            app.ui.start,
            app.sync.relay.source,
            app.sync.relay.join_error,
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// One pass of egui that runs `work`.
fn pass(
    ctx: &egui::Context,
    app: &mut DesktopApp,
    work: impl FnOnce(&mut DesktopApp, &egui::Context),
) {
    let mut work = Some(work);
    let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
        if let Some(work) = work.take() {
            work(app, ui.ctx());
        }
    });
    output.drop_without_applying_deltas();
}

fn shown_devices(app: &DesktopApp) -> usize {
    match live::view(app).shown {
        Shown::Account(account) => account.devices.len(),
        _ => 0,
    }
}

/// Device A: the vault "Personal" with one credential, unlocked, its Connect account
/// (entitled), and the sync of the vault through Apassy Connect. Returns the app, its
/// context, and the team of the vault store.
fn device_a(
    dir: &TempDir,
    connect: &FakeConnect,
    relay: &FakeRelay,
) -> (DesktopApp, egui::Context, String) {
    let mut a = DesktopApp::new();
    a.load_vault_list(dir.path().join("mac-a"), true);
    let ctx = egui::Context::default();
    a.vault_list.name_input = "Personal".to_owned();
    a.owner_ui.passphrase.push_str(PASS);
    a.owner_ui.passphrase_confirm.push_str(PASS);
    super::start::create_vault(&mut a, &ctx);
    assert!(!a.owner_ui.session.is_locked(), "{}", a.status_text);
    let mut secrets = crate::desktop::owner_store::SecretForm::default();
    secrets.token = "SYNTH-start-token".to_owned();
    a.owner_ui
        .session
        .add(
            &crate::desktop::ItemDraft {
                name: "Synthetic token".to_owned(),
                kind: crate::contracts::CredentialKind::ApiKey,
                ..crate::desktop::ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    let data = dir.path().join("data-a");
    std::fs::create_dir_all(&data).expect("data dir");
    a.connect_configure(Some(Arc::new(MemoryKeyStore::new())), Some(data));
    let live = &mut a.ui.connect.live;
    live.origin = Some(connect.url.clone());
    live.poll_every = Some(Duration::from_millis(40));
    live.join_poll_every = Some(Duration::from_millis(40));
    super::open_settings(&mut a, super::SettingsSection::Connect);
    let account_id = create_account(&ctx, &mut a, "Rafal");
    connect.entitle(&account_id);
    pass(&ctx, &mut a, |app, ctx| live::act(app, ctx, Action::SignIn));
    until(&ctx, &mut a, "the plan", |app| {
        app.ui
            .connect
            .live
            .sync_account()
            .is_some_and(|account| account.plan.is_some_and(crate::sync::StorePlan::entitled))
    });
    let entry = a.current_vault().expect("the open vault").clone();
    a.relay_enable_connect(&entry.id).expect("turn on");
    a.relay_settle_for_test();
    let team = a
        .relay_of(&entry.id)
        .expect("the relay sync")
        .state()
        .expect("state")
        .and_then(|state| state.team_id)
        .expect("a store");
    assert_eq!(relay.team_devices(&team).len(), 1);
    a.sync_now();
    a.relay_settle_for_test();
    assert!(
        a.relay_of(&entry.id)
            .is_some_and(|relay| relay.uses_account_key()),
        "the store session of A runs"
    );
    (a, ctx, team)
}

/// Device B: no vault and no account file; the key store `store` and its own data
/// directory, with short polls.
fn device_b(dir: &TempDir, connect: &FakeConnect, store: Arc<MemoryKeyStore>) -> DesktopApp {
    let mut b = DesktopApp::new();
    b.load_vault_list(dir.path().join("mac-b"), true);
    b.sync.offered = true;
    let data = dir.path().join("data-b");
    std::fs::create_dir_all(&data).expect("data dir");
    b.connect_configure(Some(store), Some(data));
    let live = &mut b.ui.connect.live;
    live.origin = Some(connect.url.clone());
    live.poll_every = Some(Duration::from_millis(40));
    live.join_poll_every = Some(Duration::from_millis(40));
    b
}

/// The start screen's "Use a vault from another Mac" › "Apassy Connect".
fn open_connect_path(app: &mut DesktopApp) {
    super::sync::begin_open(app);
    app.sync.relay.source = OpenSource::Connect;
}

/// The whole path of a new computer: no vault and no account file, so the start screen
/// offers the join with the code of device A; both show the same words; A confirms; B
/// lists the vault store of the account, takes it with the passphrase of the vault, and
/// the vault opens with sync through Apassy Connect. Nothing asks for Settings.
#[test]
fn a_computer_without_a_vault_joins_the_account_and_gets_a_vault_from_connect() {
    let dir = TempDir::new().expect("temp dir");
    let relay = Arc::new(FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    let (mut a, a_ctx, team) = device_a(&dir, &connect, &relay);
    let b_store = Arc::new(MemoryKeyStore::new());
    let mut b = device_b(&dir, &connect, Arc::clone(&b_store));
    let ctx = egui::Context::default();

    // No account file: the join with a code, and no word of Settings.
    open_connect_path(&mut b);
    let text = frame(&ctx, &mut b);
    let text = text + &frame(&ctx, &mut b);
    assert!(text.contains(ADD_THIS_MAC), "the join is offered: {text}");
    assert!(text.contains(CONNECT_OPEN_JOIN), "{text}");
    assert!(!text.contains("Settings"), "{text}");
    let session = b.connect_session();
    let start = session.start_epoch().expect("the step of the start screen");
    assert_eq!(session.state(), SessionState::Closed, "no account yet");
    assert_eq!(b_store.reads(), 0, "nothing to read");
    pass(&ctx, &mut b, |app, ctx| {
        live::act(app, ctx, Action::AddThisMac)
    });
    let text = frame(&ctx, &mut b);
    assert!(text.contains(JOIN_ACCOUNT_TITLE), "the join sheet: {text}");

    // A makes the code; B pastes it and shows the words and the name of A.
    pass(&a_ctx, &mut a, |app, ctx| {
        live::act(app, ctx, Action::AddDevice)
    });
    until(&a_ctx, &mut a, "the code", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::AddDevice { .. }))
    });
    let Some(Sheet::AddDevice { code, .. }) = &a.ui.connect.sheet else {
        unreachable!();
    };
    let code = code.as_str().to_owned();
    if let Some(Sheet::JoinAccount { code: typed }) = &mut b.ui.connect.sheet {
        typed.push_str(&code);
    }
    pass(&ctx, &mut b, |app, ctx| {
        live::choose(app, ctx, SheetChoice::Go)
    });
    until(&ctx, &mut b, "the words", |app| {
        let error = live::error_for_test(app).filter(|_| !live::view(app).busy);
        assert!(error.is_none(), "the join failed: {error:?}");
        matches!(app.ui.connect.sheet, Some(Sheet::JoinWaiting { .. }))
    });
    let Some(Sheet::JoinWaiting { confirmer, words }) = &b.ui.connect.sheet else {
        unreachable!();
    };
    let (confirmer, words) = (confirmer.clone(), words.clone());
    let text = frame(&ctx, &mut b);
    assert!(
        text.contains(&format!("Waiting for {confirmer}…")),
        "{text}"
    );
    let a_name = match live::view(&a).shown {
        Shown::Account(account) => account.devices[0].name.clone(),
        _ => panic!("the account of A"),
    };
    assert_eq!(confirmer, a_name, "the name of the device that confirms");
    assert!(text.contains("Both devices show these words"), "{text}");
    for word in words.split_whitespace() {
        assert!(text.contains(word), "{word}: {text}");
    }

    // A shows the same words and confirms with the owner check.
    until(&a_ctx, &mut a, "the words on A", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Words { .. }))
    });
    let Some(Sheet::Words { words: a_words, .. }) = &a.ui.connect.sheet else {
        unreachable!();
    };
    let a_words = a_words.clone();
    assert_eq!(a_words, words, "both devices show the same words");
    pass(&a_ctx, &mut a, |app, ctx| {
        live::choose(app, ctx, SheetChoice::Go)
    });
    confirm_with(&mut a, &a_ctx, PASS);
    until(&a_ctx, &mut a, "the device", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::DeviceAdded { .. }))
    });
    pass(&a_ctx, &mut a, |app, ctx| {
        live::choose(app, ctx, SheetChoice::Done)
    });
    until(&a_ctx, &mut a, "two devices", |app| shown_devices(app) == 2);
    // The store of A takes the new device of the account.
    a.relay_settle_for_test();
    let verified = match live::view(&a).shown {
        Shown::Account(account) => account
            .devices
            .iter()
            .map(|device| (device.name.clone(), device.verified))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    assert_eq!(
        relay.team_devices(&team).len(),
        2,
        "B is in the store: {verified:?} {} {:?}",
        a.status_text,
        connect.log()
    );

    // B is in the account: the session of this step is open, and the list shows the store.
    let text = frames_until(&ctx, &mut b, "joined", |text| text.contains(JOINED_TITLE));
    assert!(session.is_open(), "{text}");
    assert_eq!(
        session.start_epoch(),
        Some(start),
        "the account of the step"
    );
    pass(&ctx, &mut b, |app, ctx| {
        live::choose(app, ctx, SheetChoice::Done)
    });
    let text = frames_until(&ctx, &mut b, "the store", |text| {
        text.contains(CONNECT_OPEN_USE) && text.contains("Personal")
    });
    assert!(!text.contains("Settings"), "{text}");
    let Some(Ok(stores)) = b.relay_connect_stores(&ctx).cloned() else {
        panic!("the stores are listed");
    };
    let store = stores
        .into_iter()
        .find(|store| store.team_id == team)
        .expect("the store of A");

    // "Use This Vault…", the passphrase, and the vault opens with Connect sync.
    b.relay_connect_use(store, None);
    b.relay_settle_for_test();
    assert_eq!(
        b.sync.relay.join_view(None),
        Some(JoinView::Ready {
            team: "Personal".to_owned()
        }),
        "{:?}",
        b.sync.relay.join_error
    );
    let text = frame(&ctx, &mut b);
    assert!(text.contains("Use this vault"), "{text}");
    b.owner_ui.passphrase.push_str(PASS);
    b.relay_open_vault(None);
    b.relay_settle_for_test();
    assert!(!b.owner_ui.session.is_locked(), "{}", b.status_text);
    assert!(
        b.status_text.contains("Relay sync is on"),
        "{}",
        b.status_text
    );
    let entry = b.current_vault().expect("the new vault").clone();
    assert_eq!(entry.name, "Personal");
    assert_eq!(
        b.relay_of(&entry.id)
            .and_then(|relay| relay.state().ok().flatten())
            .and_then(|state| state.team_id),
        Some(team.clone()),
        "the vault store of the account"
    );
    let names: Vec<String> = b
        .owner_ui
        .session
        .search("")
        .expect("search")
        .into_iter()
        .map(|summary| summary.name)
        .collect();
    assert_eq!(names, vec!["Synthetic token".to_owned()]);

    // The vault's own session takes over.
    pass(&ctx, &mut b, live::step);
    until(&ctx, &mut b, "the session of the vault", |app| {
        app.connect_session().state() != SessionState::Opening
    });
    assert!(session.is_open());
    assert!(session.start_epoch().is_none(), "the step ended");
    assert_eq!(session.epoch(), b.owner_ui.session.epoch());
    // The new vault syncs through Apassy Connect with the key of the account.
    b.sync_now();
    b.relay_settle_for_test();
    assert!(
        b.relay_of(&entry.id)
            .is_some_and(|relay| relay.uses_account_key()),
        "the vault syncs through Apassy Connect: {}",
        b.status_text
    );
}

/// From an unlocked vault, "Use a vault from Apassy Connect…" leaves the vault for the
/// start screen's Connect path: the session opens for that step (one read of the key) and
/// lists the stores; "Try Again" asks again at once; going back closes the session, and
/// the next visit asks Connect again without the error of the earlier one.
#[test]
fn the_connect_path_opens_the_session_for_the_step_and_lists_at_each_visit() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let store = Arc::new(MemoryKeyStore::new());
    let mut app = connect_app_with(&dir, &connect, Arc::clone(&store) as _);
    app.sync.offered = true;
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");

    // A visit with Connect failing: the error and "Try Again".
    connect.lose_next_answers("GET /v1/account/vaults", 1);
    let reads = store.reads();
    let asked = connect.count("GET /v1/account/vaults");
    app.leave_vault_for_connect(Some(&ctx));
    assert!(app.owner_ui.session.is_locked(), "the vault is left");
    assert_eq!(app.sync.relay.source, OpenSource::Connect);
    let session = app.connect_session();
    let text = frames_until(&ctx, &mut app, "the error", |text| text.contains(TRY_AGAIN));
    assert!(session.is_open(), "the step opened the session: {text}");
    assert!(session.start_epoch().is_some());
    assert_eq!(store.reads(), reads + 1, "one read for the step");
    assert_eq!(connect.count("GET /v1/account/vaults"), asked + 1);
    pass(&ctx, &mut app, |app, _| app.relay_connect_forget_stores());
    let text = frames_until(&ctx, &mut app, "the list", |text| {
        text.contains(CONNECT_OPEN_EMPTY)
    });
    assert!(!text.contains(TRY_AGAIN), "{text}");
    assert_eq!(connect.count("GET /v1/account/vaults"), asked + 2);

    // Back: the session closes, and nothing of the account stays in memory.
    app.ui.start = super::start::Step::Home;
    frame(&ctx, &mut app);
    assert_eq!(session.state(), SessionState::Closed);
    assert!(session.start_epoch().is_none());
    assert!(session.signer().is_none());
    assert!(session.slot().lock().unwrap().is_none());

    // The next visit reads the key once more and asks Connect again.
    open_connect_path(&mut app);
    frames_until(&ctx, &mut app, "the second visit", |text| {
        text.contains(CONNECT_OPEN_EMPTY)
    });
    assert_eq!(store.reads(), reads + 2);
    assert_eq!(connect.count("GET /v1/account/vaults"), asked + 3);
}

/// A cancelled read of the key in the step says so and offers "Sign In…", which reads
/// it again.
#[test]
fn a_cancelled_read_in_the_step_offers_sign_in() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let store = Arc::new(CancelOnce::default());
    let mut app = connect_app_with(&dir, &connect, Arc::clone(&store) as _);
    app.sync.offered = true;
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    app.lock_vault(Some(&ctx));
    *store.cancel.lock().unwrap() = true;
    open_connect_path(&mut app);
    let text = frames_until(&ctx, &mut app, "signed out", |text| {
        text.contains(CONNECT_SIGN_IN)
    });
    assert!(text.contains(SIGN_IN), "{text}");
    assert!(!app.connect_session().is_open());
    pass(&ctx, &mut app, |app, ctx| {
        live::start_sign_in(app, Some(ctx))
    });
    frames_until(&ctx, &mut app, "the list", |text| {
        text.contains(CONNECT_OPEN_EMPTY)
    });
    assert!(app.connect_session().is_open());
}

/// A key store in memory whose next read is cancelled once (the owner cancels Touch ID).
#[derive(Default)]
struct CancelOnce {
    keys: MemoryKeyStore,
    cancel: std::sync::Mutex<bool>,
}

impl DeviceKeyStore for CancelOnce {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError> {
        if std::mem::take(&mut *self.cancel.lock().unwrap()) {
            return Err(DeviceKeyError::Cancelled);
        }
        self.keys.read()
    }
    fn store(&self, pkcs8: &[u8]) -> Result<(), DeviceKeyError> {
        self.keys.store(pkcs8)
    }
    fn delete(&self) -> Result<bool, DeviceKeyError> {
        self.keys.delete()
    }
}

/// On the start screen, a relay-team link for the origin of the account opens the
/// session there and goes on: the stores of the account are asked, and the screen does
/// not send the owner to Settings.
#[test]
fn a_link_for_the_account_origin_on_the_start_screen_opens_the_session_there() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    app.sync.offered = true;
    let ctx = egui::Context::default();
    create_account(&ctx, &mut app, "Rafal");
    app.lock_vault(Some(&ctx));
    super::sync::begin_open(&mut app);
    app.sync.relay.source = OpenSource::Relay;
    frame(&ctx, &mut app);
    let asked = connect.count("GET /v1/account/vaults");
    app.sync.relay.link_input = format!(
        "{}/link#apassy_lnk_t_7k2m5q4x3c_{}",
        connect.url,
        "ab".repeat(32)
    );
    app.sync.relay.device_input = "Synthetic Mac mini".to_owned();
    pass(&ctx, &mut app, |app, ctx| {
        app.relay_join_request(None, Some(ctx))
    });
    let error = app.sync.relay.join_error.clone().unwrap_or_default();
    assert!(!error.contains("Settings"), "{error}");
    assert!(
        app.connect_session().start_epoch().is_some(),
        "the step opened"
    );
    frames_until(&ctx, &mut app, "the stores of the account", |_| {
        connect.count("GET /v1/account/vaults") > asked
    });
    assert!(app.connect_session().is_open());
}

/// An account file of an earlier version has its own title, not the removal's.
#[test]
fn an_old_account_file_says_join_the_account_again() {
    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let file = dir.path().join("data/connect/account.json");
    std::fs::create_dir_all(file.parent().expect("dir")).expect("dir");
    std::fs::write(&file, br#"{"v":1}"#).expect("old file");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
    app.ui
        .connect
        .live
        .configure(app.connect_session().store(), Some(dir.path().join("data")));
    let ctx = egui::Context::default();
    pass(&ctx, &mut app, live::step);
    assert!(matches!(live::view(&app).shown, Shown::OldFile));
    let title = OLD_FILE_TITLE;
    assert_eq!(live::view(&app).status_line(), title);
    super::open_settings(&mut app, super::SettingsSection::Connect);
    let text = frame(&ctx, &mut app) + &frame(&ctx, &mut app);
    assert!(text.contains(title), "{text}");
    assert!(text.contains(OLD_FILE), "{text}");
    assert!(text.contains(FORGET_OLD_FILE), "{text}");
    assert!(!text.contains(REMOVED), "{text}");
}
