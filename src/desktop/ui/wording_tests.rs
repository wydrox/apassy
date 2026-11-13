//! The words of the window by platform (ADR 0041, unit L7). On Linux, every main view
//! and every Settings section, rendered with the fixture vault (Settings > Connect also
//! in each state and sheet of its account flows, against a fake Connect), names nothing that
//! exists only on a Mac: no Touch ID, Keychain, Finder, Dock, iCloud, Apassy.app,
//! System Settings, macOS, no ⌘ ⌥ ⌃ shortcut signs, and no "Mac" for this computer.
//! On macOS the same views keep their Mac words: [`mac_views_keep_their_mac_words`]
//! names them literally, without the macros of `src/wording.rs`.
//!
//! The text of a view is what it paints and the AccessKit names of its controls (where
//! the hover hints of the sidebar live).

use std::collections::HashMap;

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2, accesskit};
use tempfile::TempDir;

use super::owner_tests::{collect, locked_app, unlocked_app_with_item};
use super::settings_view::SettingsSection;
use super::{Sheet, draw};
#[cfg(target_os = "linux")]
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{DesktopApp, Place};

/// A tall window, so that each group of a section is on the screen.
const SIZE: Vec2 = Vec2::new(1180.0, 6000.0);

/// Words for a Mac-only thing. Any of them on a Linux screen fails the test.
#[cfg(target_os = "linux")]
const MAC_ONLY: [&str; 13] = [
    "Touch ID",
    "Keychain",
    "keychain",
    "Finder",
    "Dock",
    "iCloud",
    "Apassy.app",
    "System Settings",
    "macOS",
    "⌘",
    "⌥",
    "⌃",
    "Notification Center",
];

/// Where "Mac" may stay on a Linux screen: a device that really is a Mac or an Apple
/// device, never this computer (class c of the L7 inventory). Each entry is the whole
/// phrase around the word.
#[cfg(target_os = "linux")]
const MAC_ALLOWED: [&str; 0] = [];

/// The painted texts and the AccessKit names of one screen after a few frames.
struct Screen {
    // Only the Linux guard names the screen, in its failure message.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    name: String,
    text: String,
}

/// Draw `app` for a few frames, so that a new layout and its lazy loads settle.
fn render(name: &str, app: &mut DesktopApp, prepare: impl Fn(&egui::Context)) -> Screen {
    render_with(name, app, |_, ctx| prepare(ctx))
}

/// [`render`], with `prepare` given the app and the context before the first frame.
fn render_with(
    name: &str,
    app: &mut DesktopApp,
    prepare: impl FnOnce(&mut DesktopApp, &egui::Context),
) -> Screen {
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    prepare(app, &ctx);
    let mut names: HashMap<accesskit::NodeId, String> = HashMap::new();
    let mut text = String::new();
    for frame in 0..4 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            time: Some(f64::from(frame) * 0.1),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        if let Some(update) = &output.platform_output.accesskit_update {
            for (id, node) in &update.nodes {
                if let Some(label) = node.label() {
                    names.insert(*id, label.to_owned());
                }
            }
        }
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    let mut labels: Vec<_> = names.into_values().collect();
    labels.sort();
    text.push_str(&labels.join("\n"));
    Screen {
        name: name.to_owned(),
        text,
    }
}

/// Open the hidden rows of Settings > Updates (the keyboard shortcuts).
fn show_all_rows(ctx: &egui::Context) {
    ctx.data_mut(|data| {
        data.insert_temp(egui::Id::new(("apassy-settings-more", "shortcuts")), true);
    });
}

/// The owner-check dialogs of the guard: one request of each kind that a Linux owner
/// meets (agents, secrets, the browser, passkeys, devices and the relay), for `item`.
/// Linux only, like [`sync_screens`]: the macOS sibling keeps its own screen list.
#[cfg(target_os = "linux")]
fn owner_requests(item: u64) -> Vec<(&'static str, OwnerRequest)> {
    use crate::broker::approvals::OwnerFrequency;
    use crate::desktop::owner_check::{PasskeyAccount, PasskeyRequest};
    let page = |rp: &str| PasskeyRequest {
        origin: Some(format!("https://{rp}")),
        rid: "rid-1".to_owned(),
        rp_id: rp.to_owned(),
        client_data_hash: [7; 32],
    };
    let account = |name: &str, id: u8| PasskeyAccount {
        item_id: item,
        item_name: format!("{name} login"),
        user_name: format!("{name}@example.test"),
        user_display_name: name.to_owned(),
        credential_id: vec![id; 16],
        added: Some(1_762_783_385),
    };
    vec![
        (
            "connect an agent",
            OwnerRequest::RegisterAgent {
                name: "Claude Code".to_owned(),
            },
        ),
        ("owner command line", OwnerRequest::OpenCliSession),
        ("export decisions", OwnerRequest::ExportDecisions),
        (
            "back up",
            OwnerRequest::BackupVault {
                path: std::path::PathBuf::from("/home/owner/apassy-backup.apassy"),
            },
        ),
        (
            "how often to ask",
            OwnerRequest::ChangeOwnerFrequency {
                old: OwnerFrequency::EveryTime,
                new: OwnerFrequency::FiveMinutes,
            },
        ),
        ("show values", OwnerRequest::Reveal { item_id: item }),
        (
            "remember an answer",
            OwnerRequest::RememberAnswer {
                decision_id: 1,
                item_id: item,
                name: "Synthetic key".to_owned(),
                project: "apassy".to_owned(),
                action: crate::broker::action_kind::ActionKind::Change,
                codes: true,
            },
        ),
        (
            "copy a field",
            OwnerRequest::CopyField {
                item_id: item,
                field: "token".to_owned(),
                revision: 1,
            },
        ),
        (
            "fill a login",
            OwnerRequest::FillLogin {
                item_id: item,
                item_name: "Example login".to_owned(),
                username: "ada@example.test".to_owned(),
                origin: "https://example.test".to_owned(),
            },
        ),
        (
            "save a login",
            OwnerRequest::SaveLogin {
                title: "example.test".to_owned(),
                username: "ada@example.test".to_owned(),
                origin: "https://example.test".to_owned(),
            },
        ),
        (
            "fill a code",
            OwnerRequest::FillCode {
                item_id: item,
                item_name: "Example login".to_owned(),
                field: "otp".to_owned(),
                origin: "https://example.test".to_owned(),
            },
        ),
        (
            "sign in with a passkey, two accounts",
            OwnerRequest::SignPasskey {
                request: page("example.test"),
                accounts: vec![account("ada", 1), account("bob", 2)],
                chosen: crate::desktop::owner_check::NO_ACCOUNT,
                extensions: Default::default(),
            },
        ),
        (
            "sign in with a passkey without a page",
            OwnerRequest::SignPasskey {
                request: PasskeyRequest {
                    origin: None,
                    ..page("example.test")
                },
                accounts: vec![account("ada", 1), account("bob", 2)],
                chosen: crate::desktop::owner_check::NO_ACCOUNT,
                extensions: Default::default(),
            },
        ),
        (
            "create a passkey",
            OwnerRequest::CreatePasskey {
                request: page("example.test"),
                user_handle: vec![1; 16],
                user_name: "ada@example.test".to_owned(),
                user_display_name: "Ada".to_owned(),
                algorithms: vec![-7],
                excluded: Vec::new(),
                target: crate::vault::PasskeyTarget::NewItem {
                    title: "example.test".to_owned(),
                },
                attach_name: None,
            },
        ),
        (
            "remove a passkey",
            OwnerRequest::RemovePasskey {
                item_id: item,
                revision: 1,
                name: "Example login".to_owned(),
                delete_login: false,
            },
        ),
        (
            "pair an iPhone",
            OwnerRequest::PairCompanion {
                device_id: "device-1".to_owned(),
                device_name: "iPhone (test)".to_owned(),
                request_key: vec![4; 65],
                approval_key: vec![4; 65],
            },
        ),
        (
            "add a device to the relay sync",
            OwnerRequest::ConfirmSyncDevice {
                vault: "vault-1".to_owned(),
                link_id: 1,
                device_name: "Office computer".to_owned(),
                public_key: vec![4; 65],
            },
        ),
        (
            "add a device to the questions",
            OwnerRequest::ConfirmQuestionsDevice {
                vault: "vault-1".to_owned(),
                link_id: 1,
                device_name: "Office computer".to_owned(),
                public_key: vec![4; 65],
            },
        ),
        (
            "send questions through the relay",
            OwnerRequest::EnableRelayQuestions {
                relay_url: crate::sync::DEFAULT_RELAY_URL.to_owned(),
                team_id: None,
            },
        ),
    ]
}

/// A vault of the vault list, created on the Create screen, for the sheets of its sync:
/// the relay setup (new copy, join from another computer, your own node), "Add a
/// device…", "Add an iPhone…", the questions team and the devices.
#[cfg(target_os = "linux")]
fn sync_screens(screens: &mut Vec<Screen>) {
    use super::sync::SyncSheet;
    use super::sync::relay::SetupMode;
    let dir = TempDir::new().expect("temp dir");
    let mut app = DesktopApp::new();
    app.load_vault_list(dir.path().join("list"), true);
    app.sync.offered = true;
    let ctx = egui::Context::default();
    app.vault_list.name_input = "Personal".to_owned();
    app.owner_ui.passphrase.push_str(super::owner_tests::PASS);
    app.owner_ui
        .passphrase_confirm
        .push_str(super::owner_tests::PASS);
    super::start::create_vault(&mut app, &ctx);
    let id = app.vault_list.current.clone().expect("open vault");
    super::open_settings(&mut app, SettingsSection::Vault);
    for (name, mode) in [
        ("relay setup, new copy", SetupMode::NewCopy),
        ("relay setup, join from another computer", SetupMode::Join),
        ("relay setup, your own node", SetupMode::Node),
    ] {
        app.sync_open_sheet(SyncSheet::RelaySetup { id: id.clone() }, None);
        app.sync.relay.mode = mode;
        screens.push(render(name, &mut app, |_| {}));
    }
    for (name, sheet) in [
        ("add a device", SyncSheet::AddMac { id: id.clone() }),
        ("add an iPhone", SyncSheet::AddIphone { id: id.clone() }),
        (
            "questions team",
            SyncSheet::QuestionsTeam { id: id.clone() },
        ),
        ("relay devices", SyncSheet::Devices { id: id.clone() }),
        ("turn off sync", SyncSheet::TurnOff { id: id.clone() }),
    ] {
        app.sync_open_sheet(sheet, None);
        screens.push(render(name, &mut app, |_| {}));
    }
}

/// Every screen of the guard: the welcome screen, the open screen of a synced vault,
/// the locked vault, each place of the sidebar with the sidebar full and as a rail, a
/// credential, the new-credential and import sheets, the sheets of the relay sync and
/// of pairing, the owner-check dialogs, and each Settings section with its hidden rows
/// shown.
fn screens() -> Vec<Screen> {
    let dir = TempDir::new().expect("temp dir");
    let mut screens = Vec::new();

    let mut welcome = DesktopApp::new();
    welcome.sync.offered = true;
    screens.push(render("welcome", &mut welcome, |_| {}));
    super::sync::begin_open(&mut welcome);
    screens.push(render("open a synced vault", &mut welcome, |_| {}));
    // "Apassy Connect" on a computer without an account: the join of this computer.
    welcome.sync.relay.source = super::sync::OpenSource::Connect;
    screens.push(render("a vault from Apassy Connect", &mut welcome, |_| {}));
    welcome.ui.connect.sheet = Some(super::connect::Sheet::JoinAccount {
        code: zeroize::Zeroizing::new(String::new()),
    });
    screens.push(render("join from the start screen", &mut welcome, |_| {}));
    welcome.ui.connect.sheet = None;

    let locked_dir = TempDir::new().expect("temp dir");
    let mut locked = locked_app(&locked_dir, "locked.db");
    screens.push(render("locked", &mut locked, |_| {}));

    let (mut app, item) = unlocked_app_with_item(&dir);
    app.sync.offered = true;
    for (name, place) in [
        ("credentials", Place::CREDENTIALS),
        ("overview", Place::Overview),
        ("decisions", Place::Decisions),
        ("agents", Place::Agents),
        ("logs", Place::Logs),
    ] {
        app.place = place.clone();
        app.ui.sidebar_hidden = false;
        screens.push(render(name, &mut app, |_| {}));
        app.ui.sidebar_hidden = true;
        screens.push(render(&format!("{name}, sidebar rail"), &mut app, |_| {}));
    }
    app.ui.sidebar_hidden = false;
    app.place = Place::CREDENTIALS;
    app.select_item(item.to_string());
    screens.push(render("a credential", &mut app, |_| {}));
    app.ui.sheet = Some(Sheet::NewCredential);
    screens.push(render("new credential", &mut app, |_| {}));
    #[cfg(target_os = "linux")]
    {
        app.ui.sheet = Some(Sheet::Import);
        screens.push(render("import", &mut app, |_| {}));
        app.ui.sheet = Some(Sheet::RegisterAgent);
        screens.push(render("connect an agent", &mut app, |_| {}));
    }
    app.ui.sheet = None;
    #[cfg(target_os = "linux")]
    for (name, request) in owner_requests(item) {
        screens.push(render_with(
            &format!("owner check: {name}"),
            &mut app,
            |app, ctx| app.prepare_owner(request, Some(ctx), false),
        ));
        app.owner.check = None;
    }
    app.selected_item_id = None;
    for section in SettingsSection::ALL {
        super::open_settings(&mut app, section);
        screens.push(render(
            &format!("Settings > {}", section.label()),
            &mut app,
            show_all_rows,
        ));
    }
    connect_screens(&mut screens);
    #[cfg(target_os = "linux")]
    sync_screens(&mut screens);
    screens
}

/// Settings > Connect in each state and with each sheet of its account flows (plan s7
/// unit M5b): no account, the creation and the join sheets, an account with its device
/// list, the device link and the safety words, the forget and delete sheets, a device
/// that Connect removed, and a Connect that cannot be reached. Connect is the in-process
/// fake of `tests/common/fake_connect.rs`; every value is synthetic.
fn connect_screens(screens: &mut Vec<Screen>) {
    use super::connect::Sheet as ConnectSheet;
    use super::connect_tests::fake_connect::FakeConnect;
    use super::connect_tests::{connect_app, create_account, until};
    use zeroize::Zeroizing;

    let dir = TempDir::new().expect("temp dir");
    let connect = FakeConnect::start();
    let mut app = connect_app(&dir, &connect);
    let ctx = egui::Context::default();
    fn sheet(screens: &mut Vec<Screen>, app: &mut DesktopApp, name: &str, sheet: ConnectSheet) {
        app.ui.connect.sheet = Some(sheet);
        screens.push(render(&format!("Settings > Connect, {name}"), app, |_| {}));
        app.ui.connect.sheet = None;
    }
    let device_name = crate::sync::device_name();
    sheet(
        screens,
        &mut app,
        "create",
        ConnectSheet::Create {
            name: "Synthetic".to_owned(),
            device_name: device_name.clone(),
        },
    );
    sheet(
        screens,
        &mut app,
        "join an account",
        ConnectSheet::JoinAccount {
            code: Zeroizing::new(String::new()),
        },
    );
    sheet(
        screens,
        &mut app,
        "join waiting",
        ConnectSheet::JoinWaiting {
            confirmer: "Synthetic Phone".to_owned(),
            words: "blaze cable flute board seal tiger".to_owned(),
            note: None,
        },
    );
    sheet(screens, &mut app, "joined", ConnectSheet::Joined);
    sheet(
        screens,
        &mut app,
        "recovery code",
        ConnectSheet::Recovery {
            account_id: "acc_k7m2q4x3ca".to_owned(),
            words: Zeroizing::new("blaze cable flute board seal tiger maple orbit".to_owned()),
            unrecorded: false,
        },
    );
    sheet(
        screens,
        &mut app,
        "recover an account",
        ConnectSheet::Recover {
            account_id: "acc_k7m2q4x3c".to_owned(),
            code: Zeroizing::new("blaze cable orbitt".to_owned()),
            device_name: device_name.clone(),
        },
    );
    create_account(&ctx, &mut app, "Synthetic");
    screens.push(render("Settings > Connect, account", &mut app, |_| {}));
    for (name, value) in [
        (
            "add a device",
            ConnectSheet::AddDevice {
                code: Zeroizing::new("apassy_lnk_synthetic".to_owned()),
                expires_at: crate::desktop::companion::now() + 600,
            },
        ),
        (
            "safety words",
            ConnectSheet::Words {
                join_id: 1,
                device_name: "Synthetic Phone".to_owned(),
                platform: "iphone".to_owned(),
                words: "blaze cable flute board seal tiger".to_owned(),
            },
        ),
        (
            "forget this device",
            ConnectSheet::Revoke {
                index: 0,
                name: device_name.clone(),
                this: true,
                detail: String::new(),
            },
        ),
        ("forget after a removal", ConnectSheet::ForgetRemoved),
        ("delete", ConnectSheet::Delete),
        (
            "request sent",
            ConnectSheet::JoinSent {
                owner_name: "Synthetic".to_owned(),
            },
        ),
    ] {
        sheet(screens, &mut app, name, value);
    }
    // Connect removed this device: the removed state names this computer.
    let this = match super::connect::live::view(&app).shown {
        super::connect::Shown::Account(account) => account.devices[0].id.clone(),
        other => panic!("no account: {other:?}"),
    };
    connect.revoke(&this);
    super::connect::live::act(&mut app, &ctx, super::connect::Action::SignIn);
    until(&ctx, &mut app, "the removed state", |app| {
        matches!(
            super::connect::live::view(app).shown,
            super::connect::Shown::Removed { .. }
        )
    });
    screens.push(render("Settings > Connect, removed", &mut app, |_| {}));

    // A Connect that cannot be reached, and the signed-out state after a lock.
    let dir = TempDir::new().expect("temp dir");
    let mut app = connect_app(&dir, &connect);
    create_account(&ctx, &mut app, "Synthetic");
    app.lock_vault(None);
    let file = dir.path().join("data/connect/account.json");
    let text = std::fs::read_to_string(&file).expect("account file");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let dead = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("addr").port()
    );
    drop(listener);
    std::fs::write(&file, text.replace(&connect.url, &dead)).expect("account file");
    app.owner_ui
        .session
        .unlock(super::owner_tests::PASS)
        .expect("unlock");
    until(&ctx, &mut app, "the unreachable state", |app| {
        matches!(
            super::connect::live::view(app).shown,
            super::connect::Shown::Unreachable { .. }
        )
    });
    super::open_settings(&mut app, SettingsSection::Connect);
    screens.push(render("Settings > Connect, unreachable", &mut app, |_| {}));
    // Signed out: the read of the key did not work for this unlock.
    app.connect_configure(
        Some(std::sync::Arc::new(super::connect_tests::CancelledStore)),
        Some(dir.path().join("data")),
    );
    until(&ctx, &mut app, "the signed-out state", |app| {
        matches!(
            app.connect_session().state(),
            crate::connect::SessionState::SignedOut(_)
        )
    });
    screens.push(render("Settings > Connect, signed out", &mut app, |_| {}));
}

/// The words of `text` that name a Mac-only thing, and each "Mac" that is not in the
/// allow-list.
#[cfg(target_os = "linux")]
fn mac_words(text: &str) -> Vec<String> {
    let mut found: Vec<String> = MAC_ONLY
        .iter()
        .filter(|word| text.contains(*word))
        .map(|word| (*word).to_owned())
        .collect();
    for line in text.lines() {
        let mut rest = line;
        while let Some(at) = rest.find("Mac") {
            let before = rest[..at].chars().next_back();
            let after = rest[at + 3..].chars().next();
            let word_start = before.is_none_or(|c| !c.is_alphanumeric());
            let word_end = after.is_none_or(|c| !c.is_alphanumeric() || c == 's');
            let allowed = MAC_ALLOWED.iter().any(|phrase| line.contains(phrase));
            if word_start && word_end && !allowed {
                found.push(line.to_owned());
                break;
            }
            rest = &rest[at + 3..];
        }
    }
    found
}

/// The guard of L7: no Linux screen names a Mac-only thing or calls this computer a
/// Mac. It runs in the ubuntu `tests` job.
#[cfg(target_os = "linux")]
#[test]
fn linux_screens_name_nothing_of_the_mac() {
    let screens = screens();
    assert!(screens.len() > 40, "{} screens", screens.len());
    let mut failures = Vec::new();
    for screen in &screens {
        assert!(
            !screen.text.trim().is_empty(),
            "{} painted nothing",
            screen.name
        );
        let words = mac_words(&screen.text);
        if !words.is_empty() {
            failures.push(format!("{}: {words:?}", screen.name));
        }
    }
    // The browser rows of Settings > Tools need an installed package: their texts, for
    // each browser in each state, directly.
    let rows = super::browser_settings::every_row_text().join("\n");
    let words = mac_words(&rows);
    if !words.is_empty() {
        failures.push(format!("Settings > Tools > browser rows: {words:?}"));
    }
    assert!(
        failures.is_empty(),
        "Mac words on Linux:\n{}",
        failures.join("\n")
    );
}

/// The texts of syncing through Apassy Connect (the "Apassy Connect" choice of the setup
/// sheet, the status lines of a vault store, the results of turning it on) need an
/// account with a plan to show; on Linux they name no Mac, no Keychain, and no "Macs".
#[cfg(target_os = "linux")]
#[test]
fn the_connect_sync_texts_use_the_linux_words() {
    use super::sync::relay;
    use crate::desktop::sync_worker::{ConnectState, UiStatus};
    let mut texts = vec![
        relay::CONNECT_SETUP_LEAD.to_owned(),
        relay::CONNECT_SETUP_WORDS.to_owned(),
        relay::CONNECT_NEEDS_PLAN.to_owned(),
        relay::CONNECT_DEVICES_NOTE.to_owned(),
        relay::CONNECT_UNREACHABLE.to_owned(),
        relay::MOVE_OLD_DELETED.to_owned(),
        relay::CHECK_LIST_UNREACHABLE.to_owned(),
        relay::STORE_REFUSED_WORDS.to_owned(),
    ];
    for status in [
        UiStatus::UpToDate(None),
        UiStatus::Syncing,
        UiStatus::Damaged,
        UiStatus::Waiting,
        UiStatus::Connect(ConnectState::SignedOut),
        UiStatus::Connect(ConnectState::ReadOnly {
            until: Some(1_800_000_000),
        }),
        UiStatus::Connect(ConnectState::Suspended {
            delete_at: Some(1_800_000_000),
        }),
        UiStatus::Connect(ConnectState::Suspended { delete_at: None }),
    ] {
        texts.push(relay::words_of(&status, None, true));
    }
    let all = texts.join("\n");
    assert_eq!(mac_words(&all), Vec::<String>::new(), "{all}");
    assert!(
        all.contains("Changes stay on this computer until then."),
        "{all}"
    );
    assert!(all.contains("Saved to Apassy Connect."), "{all}");
}

/// The guard sees what it guards: the Linux words are on the screens, among them the
/// Linux shortcuts in Settings > Updates and in the sidebar names.
#[cfg(target_os = "linux")]
#[test]
fn linux_screens_use_the_linux_words() {
    let screens = screens();
    let all = screens
        .iter()
        .map(|screen| screen.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "Each vault is one encrypted file on this computer.",
        "Use a vault from another computer",
        "Hide sidebar  F9",
        "Show sidebar  F9",
        "Settings  Ctrl+,",
        "Lock the vault  Ctrl+L",
        "Ctrl+1 to Ctrl+5",
        "Alt+Left",
        "Ctrl+Shift+H",
        "Tab, Shift+Tab",
        "Quit Apassy",
        "Apassy does not update itself on Linux",
        "Add This Computer…",
        "Forget This Computer?",
        "This Computer",
        "Connect unreachable",
    ] {
        assert!(all.contains(expected), "no screen shows {expected:?}");
    }
}

/// The sibling of the guard on macOS: the same screens keep their Mac words, written
/// here literally, so a change of a macro in `src/wording.rs` cannot change them
/// unnoticed. It runs in the macOS `tests` job of a ready pull request.
#[cfg(not(target_os = "linux"))]
#[test]
fn mac_views_keep_their_mac_words() {
    let screens = screens();
    let all = screens
        .iter()
        .map(|screen| screen.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for expected in [
        "Credentials for you and your agents. Each vault is one encrypted file on this Mac. Agents use the secrets through Apassy and never see the values.",
        "Use a vault from another Mac",
        "macOS can ask for permission to use iCloud Drive before Apassy can read the file.",
        "Help with iCloud",
        "Hide sidebar  ⌃⌘S",
        "Show sidebar  ⌃⌘S",
        "Settings  ⌘,",
        "Lock the vault  ⌘L",
        "⌘1 to ⌘5",
        "⌘[",
        "⌘⇧H",
        "Tab, ⇧Tab",
        "⌘H stays the macOS shortcut for \"Hide Apassy\", so showing values uses ⌘⇧H.",
        "This Mac",
        "Add This Mac…",
        "Forget This Mac?",
    ] {
        assert!(all.contains(expected), "no screen shows {expected:?}");
    }
    for linux_only in ["Quit Apassy", "F9", "Ctrl+", "Alt+Left", "this computer"] {
        assert!(
            !all.contains(linux_only),
            "a Mac screen shows {linux_only:?}"
        );
    }
}
