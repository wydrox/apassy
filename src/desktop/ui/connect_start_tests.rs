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
    let Some(Sheet::JoinWaiting {
        confirmer, words, ..
    }) = &b.ui.connect.sheet
    else {
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

// ---- Round 5: the copy of a removed device, joins that outlive their step, and the
// ---- ways out of the Connect path.

/// Join the device of `store` and the account file `path` to the account of A with the
/// core join of `name`, confirmed in A's window with the words and the owner check; then
/// A's store takes the new device.
fn join_with_core(
    a: &mut DesktopApp,
    a_ctx: &egui::Context,
    connect: &FakeConnect,
    store: &MemoryKeyStore,
    path: &std::path::Path,
    name: &str,
) -> crate::connect::ConnectAccount {
    use crate::connect::{ConnectClient, JoinPoll, JoinRequest};
    let devices = shown_devices(a);
    pass(a_ctx, a, |app, ctx| live::act(app, ctx, Action::AddDevice));
    until(a_ctx, a, "the code", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::AddDevice { .. }))
    });
    let Some(Sheet::AddDevice { code, .. }) = &a.ui.connect.sheet else {
        unreachable!();
    };
    let code = code.as_str().to_owned();
    let mut request = JoinRequest::start(
        ConnectClient::new(&connect.url).expect("client"),
        store,
        path,
        &code,
        name,
    )
    .expect("join");
    until(a_ctx, a, "the words", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Words { .. }))
    });
    pass(a_ctx, a, |app, ctx| live::choose(app, ctx, SheetChoice::Go));
    confirm_with(a, a_ctx, PASS);
    until(a_ctx, a, "the device", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::DeviceAdded { .. }))
    });
    pass(a_ctx, a, |app, ctx| {
        live::choose(app, ctx, SheetChoice::Done)
    });
    until(a_ctx, a, "one more device", |app| {
        shown_devices(app) == devices + 1
    });
    a.relay_settle_for_test();
    match request.poll() {
        Ok(JoinPoll::Confirmed(account)) => *account,
        other => panic!("not confirmed: {other:?}"),
    }
}

/// A with its store; B (no vault) in the account through the core join, on the start
/// screen's Connect path with the store listed.
struct OnStart {
    _dir: TempDir,
    connect: FakeConnect,
    relay: Arc<FakeRelay>,
    /// Device A stays for the whole test.
    _a: DesktopApp,
    team: String,
    b: DesktopApp,
    ctx: egui::Context,
    store: crate::connect::VaultStoreView,
}

/// [`OnStart`]; `after_b` runs on A after B joined and before B opens the Connect path.
fn on_start(
    after_b: impl FnOnce(&mut DesktopApp, &egui::Context, &FakeConnect, &FakeRelay, &str),
) -> OnStart {
    let dir = TempDir::new().expect("temp dir");
    let relay = Arc::new(FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    let (mut a, a_ctx, team) = device_a(&dir, &connect, &relay);
    let b_store = Arc::new(MemoryKeyStore::new());
    let b_file = crate::connect::account_file(&dir.path().join("data-b"));
    drop(join_with_core(
        &mut a,
        &a_ctx,
        &connect,
        &b_store,
        &b_file,
        "Synthetic Mac mini",
    ));
    let b_key = crate::connect::AccountSigner::open(b_store.as_ref())
        .expect("key")
        .expect("B's key")
        .public_key()
        .to_vec();
    assert!(
        relay
            .team_devices(&team)
            .iter()
            .any(|(_, key)| *key == b_key),
        "B is in the store"
    );
    after_b(&mut a, &a_ctx, &connect, &relay, &team);
    let mut b = device_b(&dir, &connect, b_store);
    let ctx = egui::Context::default();
    open_connect_path(&mut b);
    // The session of the step read the account: its trust store is that of Connect now.
    frames_until(&ctx, &mut b, "a verified device list", |_| true);
    let deadline = Instant::now() + Duration::from_secs(20);
    while b
        .ui
        .connect
        .live
        .sync_account()
        .and_then(|account| account.verified_at)
        .is_none()
    {
        assert!(Instant::now() < deadline, "the step read the account");
        frame(&ctx, &mut b);
        std::thread::sleep(Duration::from_millis(5));
    }
    frames_until(&ctx, &mut b, "the store", |text| {
        text.contains(CONNECT_OPEN_USE) && text.contains("Personal")
    });
    let Some(Ok(stores)) = b.relay_connect_stores(&ctx).cloned() else {
        panic!("the stores are listed");
    };
    let store = stores
        .into_iter()
        .find(|store| store.team_id == team)
        .expect("the store of A");
    OnStart {
        _dir: dir,
        connect,
        relay,
        _a: a,
        team,
        b,
        ctx,
        store,
    }
}

/// A head over the last head of `team` signed by `signer` (its store device), with a copy
/// of A's vault that holds one more item, "From the removed iMac".
fn removed_device_push(
    s_a: &DesktopApp,
    relay: &FakeRelay,
    team: &str,
    signer: &crate::connect::AccountSigner,
    work: &std::path::Path,
) {
    use crate::sync::{HeadFields, sha256_hex};
    let number = relay
        .team_devices(team)
        .into_iter()
        .find(|(_, key)| key.as_slice() == signer.public_key())
        .map(|(number, _)| number)
        .expect("the device is in the store");
    let entry = s_a.current_vault().expect("A's vault").clone();
    let copy_path = work.join(format!("removed-copy-{}.db", relay.version_of(team)));
    std::fs::copy(&entry.path, &copy_path).expect("copy");
    let mut copy = crate::vault::Vault::open(&copy_path).expect("open");
    copy.unlock(PASS).expect("unlock");
    copy.add(crate::vault::ItemDraft {
        title: format!("From the removed iMac {}", relay.version_of(team)),
        kind: crate::contracts::CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![crate::vault::Field {
            name: "token".to_owned(),
            value: crate::vault::SecretValue::new("SYNTH-removed".to_owned()),
            secret: true,
        }],
    })
    .expect("add");
    let synced = work.join(format!("removed-copy-{}.sync", relay.version_of(team)));
    copy.write_sync_copy(&synced, "Synthetic iMac")
        .expect("sync copy");
    let bytes = std::fs::read(&synced).expect("bytes");
    let last = relay.heads_of(team).last().cloned().expect("a head");
    let fields = HeadFields {
        version: last.version + 1,
        previous: last.hash(),
        snapshot_sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
        device_id: number,
        ..HeadFields::parse(&last.text).expect("head")
    };
    let signed = signer.sign_head(fields).expect("sign");
    relay.replace_store_from(
        team,
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
}

/// On the start screen, the copy that a removed device left is taken only after an owner
/// check bound to the store, the version, the head, and the session of the step; the
/// screen names the device and warns not to use the copy of a lost or stolen device; a
/// vault passphrase cannot confirm with no vault unlocked; and after the copy is taken, a
/// later head of the same removed device waits again.
#[test]
fn the_start_screen_takes_the_copy_of_a_removed_device_only_after_an_owner_check() {
    let imac = Arc::new(std::sync::Mutex::new(None));
    let held = Arc::clone(&imac);
    let mut s = on_start(move |a, a_ctx, connect, relay, team| {
        let dir = TempDir::new().expect("dir");
        let store = MemoryKeyStore::new();
        let file = crate::connect::account_file(dir.path());
        let account = join_with_core(a, a_ctx, connect, &store, &file, "Synthetic iMac");
        let signer = account.signer().expect("the iMac's key");
        // The iMac pushes last, then A removes it.
        removed_device_push(a, relay, team, &signer, dir.path());
        let index = match live::view(a).shown {
            Shown::Account(account) => account
                .devices
                .iter()
                .position(|device| device.name == "Synthetic iMac")
                .expect("the iMac"),
            _ => panic!("the account of A"),
        };
        pass(a_ctx, a, |app, ctx| {
            live::act(app, ctx, Action::Revoke(index))
        });
        pass(a_ctx, a, |app, ctx| live::choose(app, ctx, SheetChoice::Go));
        confirm_with(a, a_ctx, PASS);
        until(a_ctx, a, "the iMac is removed", |app| {
            shown_devices(app) == 2
        });
        *held.lock().unwrap() = Some((dir, signer));
    });
    let (imac_dir, imac_signer) = imac.lock().unwrap().take().expect("the iMac");
    let version = s.relay.version_of(&s.team);
    let store = s.store.clone();
    s.b.relay_connect_use(store, None);
    s.b.relay_settle_for_test();
    assert!(
        matches!(
            s.b.sync.relay.join_view(None),
            Some(JoinView::Departed { .. })
        ),
        "{:?} {:?}",
        s.b.sync.relay.join_view(None),
        s.b.sync.relay.join_error
    );
    let ctx = s.ctx.clone();
    let text = frames_until(
        &ctx,
        &mut s.b,
        "the signed name of the removed device",
        |text| text.contains("“Synthetic iMac”"),
    );
    assert!(
        text.contains("Do not use it if that device was lost or stolen."),
        "{text}"
    );
    assert!(text.contains(super::sync::relay::DEPARTED_ADVICE), "{text}");

    // The click asks for the owner check; nothing is downloaded before it.
    s.b.relay_take_departed_for_test(&ctx);
    let action =
        s.b.owner
            .check
            .as_ref()
            .map(|check| check.request.action())
            .expect("an owner check");
    assert!(
        matches!(
            &action,
            crate::broker::approvals::OwnerAction::TakeDepartedCopy {
                team_id,
                version: v,
                replace: false,
                ..
            } if *team_id == s.team && *v == version
        ),
        "{action:?}"
    );
    assert!(action.allowed_without_vault());
    s.b.relay_settle_for_test();
    assert!(matches!(
        s.b.sync.relay.join_view(None),
        Some(JoinView::Departed { .. })
    ));
    // No vault is unlocked: the passphrase cannot confirm it.
    let refused =
        s.b.owner_gate()
            .authorize(
                action.clone(),
                crate::broker::approvals::OwnerCheck::passphrase(PASS),
            )
            .expect_err("no vault to confirm with");
    assert!(
        refused.message().contains("No vault is unlocked"),
        "{}",
        refused.message()
    );
    // A proof of another session changes nothing.
    s.b.finish_owner_check_with(crate::broker::approvals::OwnerProof::issue_for_test(
        action.clone(),
        [9; 32],
        Instant::now(),
    ));
    s.b.relay_settle_for_test();
    assert!(matches!(
        s.b.sync.relay.join_view(None),
        Some(JoinView::Departed { .. })
    ));
    // The proof of the step: the copy downloads.
    s.b.relay_take_departed_for_test(&ctx);
    let epoch = s.b.connect_session().start_epoch().expect("the step");
    s.b.finish_owner_check_with(crate::broker::approvals::OwnerProof::issue_for_test(
        action,
        epoch,
        Instant::now(),
    ));
    s.b.relay_settle_for_test();
    assert_eq!(
        s.b.sync.relay.join_view(None),
        Some(JoinView::Ready {
            team: "Personal".to_owned()
        }),
        "{:?}",
        s.b.sync.relay.join_error
    );
    s.b.owner_ui.passphrase.push_str(PASS);
    s.b.relay_open_vault(None);
    s.b.relay_settle_for_test();
    assert!(!s.b.owner_ui.session.is_locked(), "{}", s.b.status_text);
    let entry = s.b.current_vault().expect("the new vault").clone();
    pass(&ctx, &mut s.b, live::step);
    until(&ctx, &mut s.b, "the session of the vault", |app| {
        app.connect_session().is_open() && app.connect_session().start_epoch().is_none()
    });
    // A later head of the same device waits again: the engine test
    // `a_new_device_takes_the_copy_that_a_removed_device_left` (tests/relay_sync.rs).
    drop((imac_dir, imac_signer, entry));
    drop(s.connect);
}

/// K2: on the start screen, a copy whose head a live device of the account signed, while an
/// earlier version is by a key that no list holds, is taken only with "Take This Copy
/// Without Its Earlier History…": the screen names the version, the device by its signed
/// name, and its time; nothing downloads before the owner check, a proof of another
/// session changes nothing, and the proof of the step takes exactly that head.
#[test]
fn the_start_screen_takes_a_copy_without_its_earlier_history_only_after_an_owner_check() {
    let held = Arc::new(std::sync::Mutex::new(None));
    let keep = Arc::clone(&held);
    let mut s = on_start(move |a, a_ctx, connect, relay, team| {
        let dir = TempDir::new().expect("dir");
        // A key that no list holds pushes, then a live device of the account over it.
        let stranger_keys = MemoryKeyStore::new();
        let stranger =
            crate::connect::AccountSigner::open_or_create(&stranger_keys).expect("a key");
        relay.add_store_device(team, "Synthetic stranger", stranger.public_key());
        removed_device_push(a, relay, team, &stranger, dir.path());
        let store = MemoryKeyStore::new();
        let file = crate::connect::account_file(dir.path());
        let account = join_with_core(a, a_ctx, connect, &store, &file, "Synthetic iMac");
        let signer = account.signer().expect("the iMac's key");
        removed_device_push(a, relay, team, &signer, dir.path());
        *keep.lock().unwrap() = Some((dir, signer));
    });
    let (imac_dir, imac_signer) = held.lock().unwrap().take().expect("the iMac");
    let version = s.relay.version_of(&s.team);
    let store = s.store.clone();
    s.b.relay_connect_use(store, None);
    s.b.relay_settle_for_test();
    assert!(
        matches!(
            s.b.sync.relay.join_view(None),
            Some(JoinView::WithoutHistory { .. })
        ),
        "{:?} {:?}",
        s.b.sync.relay.join_view(None),
        s.b.sync.relay.join_error
    );
    let ctx = s.ctx.clone();
    let text = frames_until(&ctx, &mut s.b, "the step of the copy", |text| {
        text.contains(super::sync::relay::WITHOUT_HISTORY)
    });
    assert!(text.contains(&format!("Version {version}")), "{text}");
    assert!(text.contains("“Synthetic iMac”"), "{text}");
    s.b.relay_take_without_history_for_test(&ctx);
    let action =
        s.b.owner
            .check
            .as_ref()
            .map(|check| check.request.action())
            .expect("an owner check");
    assert!(
        matches!(
            &action,
            crate::broker::approvals::OwnerAction::TakeCopyWithoutHistory {
                team_id,
                version: v,
                ..
            } if *team_id == s.team && *v == version
        ),
        "{action:?}"
    );
    assert!(action.allowed_without_vault());
    s.b.relay_settle_for_test();
    assert!(matches!(
        s.b.sync.relay.join_view(None),
        Some(JoinView::WithoutHistory { .. })
    ));
    // A proof of another session changes nothing.
    s.b.finish_owner_check_with(crate::broker::approvals::OwnerProof::issue_for_test(
        action.clone(),
        [9; 32],
        Instant::now(),
    ));
    s.b.relay_settle_for_test();
    assert!(matches!(
        s.b.sync.relay.join_view(None),
        Some(JoinView::WithoutHistory { .. })
    ));
    // The proof of the step: the copy downloads.
    s.b.relay_take_without_history_for_test(&ctx);
    let epoch = s.b.connect_session().start_epoch().expect("the step");
    s.b.finish_owner_check_with(crate::broker::approvals::OwnerProof::issue_for_test(
        action,
        epoch,
        Instant::now(),
    ));
    s.b.relay_settle_for_test();
    assert_eq!(
        s.b.sync.relay.join_view(None),
        Some(JoinView::Ready {
            team: "Personal".to_owned()
        }),
        "{:?}",
        s.b.sync.relay.join_error
    );
    drop((imac_dir, imac_signer));
    drop(s.connect);
}

/// B on the start screen with the copy of the store downloaded (the account key held by
/// the join).
fn ready_on_start() -> OnStart {
    let mut s = on_start(|_, _, _, _, _| {});
    let store = s.store.clone();
    s.b.relay_connect_use(store, None);
    s.b.relay_settle_for_test();
    assert_eq!(
        s.b.sync.relay.join_view(None),
        Some(JoinView::Ready {
            team: "Personal".to_owned()
        })
    );
    assert!(s.b.sync.relay.join_with_account().is_some());
    s
}

/// What holds the account key on B after a way out of the Connect path: nothing.
fn assert_nothing_holds_the_key(s: &mut OnStart) {
    let ctx = s.ctx.clone();
    frame(&ctx, &mut s.b);
    frame(&ctx, &mut s.b);
    assert!(
        s.b.sync.relay.join_with_account().is_none(),
        "the join went"
    );
    assert!(s.b.sync.relay.join_view(None).is_none());
    let session = s.b.connect_session();
    assert!(session.start_epoch().is_none(), "the step ended");
    assert!(session.signer().is_none(), "no key in the session");
    assert!(session.slot().lock().unwrap().is_none());
}

/// The segment "Synced folder" ends the step and drops the store's join.
#[test]
fn the_folder_segment_drops_what_holds_the_account_key() {
    let mut s = ready_on_start();
    s.b.sync.relay.source = OpenSource::Folder;
    assert_nothing_holds_the_key(&mut s);
}

/// The segment "Apassy relay" ends the step too: a join from the Connect list goes, and
/// the relay segment keeps no session of its own.
#[test]
fn the_relay_segment_drops_what_holds_the_account_key() {
    let mut s = ready_on_start();
    s.b.sync.relay.source = OpenSource::Relay;
    assert_nothing_holds_the_key(&mut s);
}

/// Back to the start screen's home ends the step and drops the join.
#[test]
fn back_home_drops_what_holds_the_account_key() {
    let mut s = ready_on_start();
    s.b.ui.start = super::start::Step::Home;
    assert_nothing_holds_the_key(&mut s);
}

/// B joins the account on the start screen, and its step ends before the other device
/// confirms (a way out of the step, or a quit) while Connect does not take the cancel: the
/// join stays on disk, the other device confirms, and the next visit of the step resumes
/// the join, which ends with this device in the account.
fn a_join_outlives_its_step(quit: bool) {
    let dir = TempDir::new().expect("temp dir");
    let relay = Arc::new(FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    let (mut a, a_ctx, _team) = device_a(&dir, &connect, &relay);
    let b_store = Arc::new(MemoryKeyStore::new());
    let mut b = device_b(&dir, &connect, Arc::clone(&b_store));
    let ctx = egui::Context::default();
    open_connect_path(&mut b);
    frame(&ctx, &mut b);
    pass(&ctx, &mut b, |app, ctx| {
        live::act(app, ctx, Action::AddThisMac)
    });
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
        matches!(app.ui.connect.sheet, Some(Sheet::JoinWaiting { .. }))
    });
    let pending = dir.path().join("data-b/connect/pending-join.json");
    assert!(pending.exists(), "the join is on disk");
    // Connect does not take the cancel.
    connect.answer_route_error("POST /v1/account/devices/join/cancel", 503, "busy");
    let cancels = connect.count("POST /v1/account/devices/join/cancel");
    let kept = if quit {
        b.connect_quit();
        drop(b);
        None
    } else {
        b.sync.relay.source = OpenSource::Folder;
        frame(&ctx, &mut b);
        assert!(b.ui.connect.sheet.is_none(), "the sheet went with the step");
        Some(b)
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while connect.count("POST /v1/account/devices/join/cancel") == cancels {
        assert!(Instant::now() < deadline, "the cancel was sent");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        pending.exists(),
        "a cancel that Connect did not take keeps the join"
    );
    // The other device confirms meanwhile.
    until(&a_ctx, &mut a, "the words on A", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::Words { .. }))
    });
    pass(&a_ctx, &mut a, |app, ctx| {
        live::choose(app, ctx, SheetChoice::Go)
    });
    confirm_with(&mut a, &a_ctx, PASS);
    until(&a_ctx, &mut a, "the device", |app| {
        matches!(app.ui.connect.sheet, Some(Sheet::DeviceAdded { .. }))
    });
    // The next visit of the step (after a restart: a new app) resumes the join.
    let mut b = kept.unwrap_or_else(|| device_b(&dir, &connect, b_store));
    open_connect_path(&mut b);
    frames_until(&ctx, &mut b, "joined", |text| text.contains(JOINED_TITLE));
    assert!(!pending.exists(), "the join ended");
    assert!(
        crate::connect::AccountState::load(&dir.path().join("data-b/connect/account.json"))
            .expect("load")
            .is_some(),
        "this device is in the account"
    );
    assert!(b.connect_session().is_open());
}

#[test]
fn a_join_left_on_the_start_screen_ends_in_the_account_after_a_late_confirmation() {
    a_join_outlives_its_step(false);
}

#[test]
fn a_join_cut_by_a_quit_resumes_at_the_next_start() {
    a_join_outlives_its_step(true);
}

// ---- Round 6: a vault unlock ends the step; "Use the relay copy…" of a store. ----

/// A vault of this computer is unlocked while a copy of a store waits on the start screen:
/// the step ends, and the join that held the account key goes with it.
#[test]
fn an_unlock_drops_the_copy_that_waits_on_the_start_screen() {
    let mut s = ready_on_start();
    let other = TempDir::new().expect("dir");
    s.b.owner_ui
        .session
        .create_file(&other.path().join("other.db"), PASS)
        .expect("create");
    s.b.owner_ui.session.unlock(PASS).expect("unlock");
    assert!(s.b.owner_ui.session.epoch().is_some());
    let ctx = s.ctx.clone();
    frame(&ctx, &mut s.b);
    frame(&ctx, &mut s.b);
    assert!(
        s.b.sync.relay.join_with_account().is_none(),
        "the join of the store went"
    );
    assert!(s.b.sync.relay.join_view(None).is_none());
    assert!(
        s.b.connect_session().start_epoch().is_none(),
        "the step ended"
    );
    drop(other);
}

/// "Use the relay copy…" of a vault store of the account: the sheet names the copy (its
/// version, and that the record of what this computer merged is replaced), the plain step
/// takes nothing, and the copy is taken only after an owner check that names exactly that
/// head.
#[test]
fn the_relay_copy_of_a_store_is_taken_only_after_an_owner_check() {
    let dir = TempDir::new().expect("temp dir");
    let relay = Arc::new(FakeRelay::start());
    let connect = FakeConnect::with_relay(Arc::clone(&relay) as _);
    let (mut a, ctx, team) = device_a(&dir, &connect, &relay);
    let id = a.current_vault().expect("the open vault").id.clone();
    let mut secrets = crate::desktop::owner_store::SecretForm::default();
    secrets.token = "SYNTH-second".to_owned();
    a.owner_ui
        .session
        .add(
            &crate::desktop::ItemDraft {
                name: "Second token".to_owned(),
                kind: crate::contracts::CredentialKind::ApiKey,
                ..crate::desktop::ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    a.sync_now();
    a.relay_settle_for_test();
    assert_eq!(relay.version_of(&team), 2);
    // The relay comes back from a backup: this computer refuses the older copy.
    relay.roll_back_store(&team, 1);
    a.sync_now();
    a.relay_settle_for_test();
    let status = a.sync.statuses.get(&id).cloned().expect("status");
    assert!(super::sync::relay::refused_copy(&status), "{status:?}");
    let (served, _) = a.relay_served_copy(&id).expect("the copy on the relay");
    assert_eq!(served.version, 1);
    // The plain step takes nothing for a store of the account.
    a.relay_use_copy(&id);
    a.relay_settle_for_test();
    assert_eq!(relay.version_of(&team), 1, "nothing taken");
    assert!(
        a.status_text.contains("Confirm which copy to use first"),
        "{}",
        a.status_text
    );
    super::open_settings(&mut a, super::SettingsSection::Vault);
    a.sync_open_sheet(
        super::sync::SyncSheet::UseRelayCopy { id: id.clone() },
        None,
    );
    frame(&ctx, &mut a);
    let text = frame(&ctx, &mut a);
    assert!(text.contains("The relay holds version 1"), "{text}");
    assert!(
        text.contains("record of the copies it had merged is replaced"),
        "{text}"
    );
    a.relay_ask_use_copy(&id, Some(&ctx));
    let action = a
        .owner
        .check
        .as_ref()
        .map(|check| check.request.action())
        .expect("an owner check");
    assert_eq!(
        action,
        crate::broker::approvals::OwnerAction::UseRelayCopy {
            team_id: team.clone(),
            version: 1,
            head: served.head_hash.clone(),
        }
    );
    assert_eq!(relay.version_of(&team), 1, "nothing before the check");
    confirm_with(&mut a, &ctx, PASS);
    let deadline = Instant::now() + Duration::from_secs(20);
    while relay.version_of(&team) < 2 {
        assert!(
            Instant::now() < deadline,
            "the copy was taken: {}",
            a.status_text
        );
        frame(&ctx, &mut a);
        a.relay_settle_for_test();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        a.status_text.starts_with("Apassy merged the relay copy"),
        "{}",
        a.status_text
    );
}
