//! Headless tests for several vaults, one open at a time (ADR 0013). Synthetic values
//! only. Each test keeps its vault list in a temporary data directory.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{self, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::start::{self, Step};
use super::vaults::VaultSheet;
use super::{SettingsTab, Sheet, draw};
use crate::agent::client;
use crate::agent::wire::Action;
use crate::broker::approvals::{ApprovalOutcome, OwnerAction, OwnerCheck, PendingRun};
use crate::desktop::inbox::EventKey;
use crate::desktop::owner_store::{ENDED_BY_SWITCH, FreshToken, SecretForm};
use crate::desktop::{BrokerState, DesktopApp, ItemDraft, OwnerView};
use crate::vault::{ActivityDecision, NewActivity};
use crate::vaults::Registry;

const PASS_A: &str = "vault-alpha-pass-ok";
const PASS_B: &str = "vault-beta-pass-ok";
const CANARY: &str = "vault-switch-token-canary";
const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

/// Three frames of the whole app. Returns the painted text of the last frame.
fn frames(app: &mut DesktopApp) -> String {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn collect(shape: &egui::Shape, out: &mut String) {
    match shape {
        egui::Shape::Text(text) => {
            out.push_str(text.galley.text());
            out.push('\n');
        }
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| collect(inner, out)),
        _ => {}
    }
}

fn data_dir(dir: &TempDir) -> PathBuf {
    dir.path().join("data")
}

/// An app that keeps its vault list in `<dir>/data`.
fn app_in(dir: &TempDir) -> DesktopApp {
    let mut app = DesktopApp::new();
    app.load_vault_list(data_dir(dir), true);
    app
}

/// Create a vault on the Create screen with `name` (blank for the default).
fn create(app: &mut DesktopApp, name: &str, pass: &str) {
    let ctx = egui::Context::default();
    app.vault_list.name_input = name.to_owned();
    app.owner_ui.passphrase.push_str(pass);
    app.owner_ui.passphrase_confirm.push_str(pass);
    start::create_vault(app, &ctx);
    assert!(
        !app.owner_ui.session.is_locked(),
        "create failed: {}",
        app.status_text
    );
}

/// The ID of the listed vault `name`.
fn id_of(app: &DesktopApp, name: &str) -> String {
    app.vault_list
        .registry
        .entries()
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.id.clone())
        .expect("listed vault")
}

fn path_of(app: &DesktopApp, name: &str) -> PathBuf {
    let id = id_of(app, name);
    app.vault_list
        .registry
        .get(&id)
        .map(|entry| entry.path.clone())
        .expect("path")
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

fn add_item(app: &mut DesktopApp, name: &str) -> u64 {
    let mut secrets = SecretForm::default();
    secrets.token = CANARY.to_owned();
    app.owner_ui
        .session
        .add(
            &ItemDraft {
                name: name.to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add")
        .id
}

fn unlock(app: &mut DesktopApp, pass: &str) {
    app.owner_ui.session.unlock(pass).expect("unlock");
}

/// Create asks for a name. New vaults go to `<data dir>/vaults/<name>.db`, and the
/// list on disk has mode 0600. A taken name refuses the create and keeps the typed
/// passphrases.
#[test]
fn create_asks_for_a_name_and_lists_the_vault() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    app.ui.start = Step::Create;
    let text = frames(&mut app);
    assert!(text.contains("Create your vault"), "{text}");
    assert!(text.contains("Name"), "{text}");
    assert!(
        text.contains("Personal"),
        "the first vault is Personal: {text}"
    );

    // A blank name gives the first vault the name "Personal".
    create(&mut app, "", PASS_A);
    let data = data_dir(&dir);
    let personal = path_of(&app, "Personal");
    assert_eq!(
        personal,
        std::fs::canonicalize(data.join("vaults").join("personal.db")).expect("file")
    );
    assert_eq!(mode(&data.join("vaults")), 0o700, "a private vault folder");
    assert_eq!(mode(&crate::vaults::registry_path(&data)), 0o600);

    // A second vault needs a name. A taken name does not create a file.
    app.leave_vault_for(Step::Create, None);
    app.owner_ui.passphrase.push_str(PASS_B);
    app.owner_ui.passphrase_confirm.push_str(PASS_B);
    let text = frames(&mut app);
    assert!(text.contains("Create a new vault"), "{text}");
    let ctx = egui::Context::default();
    start::create_vault(&mut app, &ctx);
    assert!(
        app.status_text.contains("Type a name"),
        "{}",
        app.status_text
    );
    app.vault_list.name_input = " PERSONAL ".to_owned();
    start::create_vault(&mut app, &ctx);
    assert!(
        app.status_text.contains("Another vault has the name"),
        "{}",
        app.status_text
    );
    assert_eq!(
        app.owner_ui.passphrase, PASS_B,
        "a refused name keeps the typed passphrase"
    );
    assert_eq!(app.vault_list.registry.entries().len(), 1);
    app.owner_ui.passphrase.clear();
    app.owner_ui.passphrase_confirm.clear();
    create(&mut app, "Client Work", PASS_B);
    let work = path_of(&app, "Client Work");
    assert!(work.ends_with("vaults/client-work.db"), "{work:?}");
    assert_eq!(app.current_vault_name().as_deref(), Some("Client Work"));

    // The list on disk has both, and the last used vault is the new one.
    let read = Registry::read(&data).expect("read").expect("list");
    assert_eq!(read.entries().len(), 2);
    assert_eq!(
        read.last_used().map(|entry| entry.name.as_str()),
        Some("Client Work")
    );

    // The sidebar shows the open vault. Settings lists each vault with its file.
    let text = frames(&mut app);
    assert!(text.contains("Client Work"), "{text}");
    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    for expected in [
        "Vaults",
        "Personal",
        "Client Work",
        "Open",
        "Rename…",
        "Remove from list…",
        "New vault…",
        "Open vault file…",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

/// Settings has five tabs. Only the sections of the selected tab show.
#[test]
fn settings_show_the_sections_of_the_selected_tab_only() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    app.view = OwnerView::Settings;
    let text = frames(&mut app);
    for tab in ["General", "Security", "Agents", "Notifications", "About"] {
        assert!(text.contains(tab), "tab {tab}: {text}");
    }
    let cases = [
        (
            SettingsTab::General,
            &["Vaults", "New vault…", "Import from 1Password…"][..],
            &["Keyboard shortcuts", "Back up now", "Broker and bouncer"][..],
        ),
        (
            SettingsTab::Security,
            &["Change passphrase", "Back up now"][..],
            &["Lock now", "Token lifetime", "Updates"][..],
        ),
        (
            SettingsTab::Agents,
            &["Token lifetime", "Broker and bouncer", "Command line"][..],
            &["Lock now", "Back up now", "Keyboard shortcuts"][..],
        ),
        (
            SettingsTab::Notifications,
            &["A waiting approval or a blocked request causes a macOS notification."][..],
            &["Lock now", "Token lifetime", "Keyboard shortcuts"][..],
        ),
        (
            SettingsTab::About,
            &["Updates", "Keyboard shortcuts", "Contract"][..],
            &["Lock now", "Back up now", "Token lifetime"][..],
        ),
    ];
    for (tab, shown, hidden) in cases {
        app.ui.settings_tab = tab;
        let text = frames(&mut app);
        for expected in shown {
            assert!(text.contains(expected), "{tab:?} shows {expected}: {text}");
        }
        for unexpected in hidden {
            assert!(
                !text.contains(unexpected),
                "{tab:?} hides {unexpected}: {text}"
            );
        }
    }
}

/// Settings > Agents: how the bouncer model starts. "Managed outside Apassy" is the
/// default and starts nothing. Each mode shows its label, its status, and its actions,
/// and a missing start script shows the install commands.
#[test]
fn settings_show_how_the_bouncer_model_starts() {
    use crate::broker::model_server::{
        BouncerSettings, Host, Layout, ModelServer, ServerState, StartMode,
    };

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let settings_path = dir.path().join("bouncer.json");
    // No uv and no LaunchAgent: the test does not read this Mac.
    let server = ModelServer::start_with_host(
        Some(settings_path.clone()),
        BouncerSettings::load(&settings_path),
        Layout {
            script: None,
            laya_dir: dir.path().join("laya"),
            checkpoints: Vec::new(),
            log: dir.path().join("Logs").join("bouncer.log"),
        },
        Host::none(),
    );
    app.model_server = Some(Arc::clone(&server));
    app.view = OwnerView::Settings;
    app.ui.settings_tab = SettingsTab::Agents;
    let text = frames(&mut app);
    for expected in [
        "Broker and bouncer",
        "Start the model",
        "Managed outside Apassy",
        "Status",
        "Open log",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for hidden in [
        "Stop after",
        "Start now",
        "Install the Laya environment",
        "Install the model",
    ] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    assert!(!settings_path.exists(), "the default is not written");

    let set = |mode| {
        server
            .set_settings(BouncerSettings {
                start: mode,
                ..BouncerSettings::default()
            })
            .expect("save");
    };
    set(StartMode::WhenNeeded);
    let text = frames(&mut app);
    for expected in [
        "When a run needs it",
        "Stop after",
        "30 minutes without a run",
        // The script is missing here, so the status does not promise a start.
        "Cannot start",
        "Something that the model needs is missing.",
        "Or install the Laya environment with these commands in Terminal:",
        // No uv here, so no install button.
        "Install uv first: brew install uv",
        "Until then, every run waits for you.",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(text.contains("laya[serve]==0.3.20"), "{text}");
    assert!(!text.contains("Install the model"), "{text}");
    // A start would fail, so there is no "Start now".
    assert!(!text.contains("Start now"), "{text}");

    // "With Apassy" starts at once. Here the script is missing, so the start fails.
    set(StartMode::WithApassy);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !matches!(server.state(), ServerState::Failed { .. }) {
        assert!(std::time::Instant::now() < deadline, "{:?}", server.state());
        std::thread::sleep(Duration::from_millis(20));
    }
    let text = frames(&mut app);
    for expected in ["With Apassy", "Not running", "start script"] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Stop after"), "{text}");
    assert!(
        !text.contains("Start now"),
        "the script is still missing: {text}"
    );

    set(StartMode::Off);
    let text = frames(&mut app);
    assert!(text.contains("Off"), "{text}");
    assert!(text.contains("Every run waits for you."), "{text}");
    assert!(!text.contains("Start now"), "{text}");
    assert_eq!(
        BouncerSettings::load(&settings_path).start,
        StartMode::Off,
        "a change persists"
    );
    server.shutdown();
}

/// Settings > Agents: "Install the model" shows only in a managed mode while the Laya
/// environment is missing. A LaunchAgent that runs start.sh with a missing model, or
/// in a mode where Apassy starts the server, gets a note with the commands that remove
/// it. The test does not run the install.
// macOS only: the LaunchAgent is read with `/usr/bin/plutil`.
#[cfg(target_os = "macos")]
#[test]
fn settings_offer_the_model_install_and_name_a_launch_agent() {
    use crate::broker::model_server::{BouncerSettings, Host, Layout, ModelServer, StartMode};

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let executable = |path: &Path| {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(path, "#!/bin/sh\n").expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("mode");
    };
    let script = dir.path().join("tools/basemodel/start.sh");
    executable(&script);
    let uv = dir.path().join("bin/uv");
    executable(&uv);
    let agents = dir.path().join("LaunchAgents");
    std::fs::create_dir_all(&agents).expect("dir");
    let model = dir.path().join("models/apassy-base-v1.safetensors");
    let plist = agents.join("com.example.bouncer.plist");
    std::fs::write(
        &plist,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>com.example.bouncer</string><key>ProgramArguments</key><array><string>/bin/bash</string><string>{}</string></array><key>EnvironmentVariables</key><dict><key>APASSY_BASE_MODEL</key><string>{}</string></dict></dict></plist>\n",
            script.display(),
            model.display()
        ),
    )
    .expect("write");
    let laya_dir = dir.path().join("laya");
    let server = ModelServer::start_with_host(
        None,
        BouncerSettings {
            start: StartMode::WhenNeeded,
            ..BouncerSettings::default()
        },
        Layout {
            script: Some(script),
            laya_dir: laya_dir.clone(),
            checkpoints: Vec::new(),
            log: dir.path().join("Logs").join("bouncer.log"),
        },
        Host {
            uv_dirs: vec![dir.path().join("bin")],
            launch_agents: Some(agents),
            hf_cache: None,
        },
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while server.status().launch_agents.is_empty() {
        assert!(std::time::Instant::now() < deadline, "no LaunchAgent");
        std::thread::sleep(Duration::from_millis(20));
    }
    app.model_server = Some(Arc::clone(&server));
    app.view = OwnerView::Settings;
    app.ui.settings_tab = SettingsTab::Agents;
    let remove = format!(
        "launchctl bootout gui/$(id -u)/com.example.bouncer\nrm {}",
        plist.display()
    );

    // The environment and the model are missing.
    let text = frames(&mut app);
    for expected in [
        "Install the model",
        "with these commands in Terminal:",
        "\nuv venv --python 3.12 .venv\n",
        // The last command downloads the base weights.
        &format!(
            "\n.venv/bin/python -B {}",
            dir.path()
                .join("tools/basemodel/fetch_weights.py")
                .display()
        ),
        "The LaunchAgent com.example.bouncer starts the bouncer with APASSY_BASE_MODEL",
        "That file does not exist, so the start fails.",
        "To remove it, run these commands in Terminal. Apassy does not change it.",
        &remove,
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Install uv first"), "{text}");

    // "Managed outside Apassy" offers no install. The missing model still shows.
    server
        .set_settings(BouncerSettings::default())
        .expect("settings");
    let text = frames(&mut app);
    assert!(!text.contains("Install the model"), "{text}");
    assert!(text.contains("That file does not exist"), "{text}");

    // With the model, "Managed outside Apassy" has no note.
    executable(&model);
    let text = frames(&mut app);
    assert!(!text.contains("com.example.bouncer"), "{text}");

    // "With Apassy" and a LaunchAgent both start the server.
    server
        .set_settings(BouncerSettings {
            start: StartMode::WithApassy,
            ..BouncerSettings::default()
        })
        .expect("settings");
    let text = frames(&mut app);
    for expected in [
        "The LaunchAgent com.example.bouncer also starts the bouncer.",
        "With \"With Apassy\", Apassy starts and stops the model itself.",
        &remove,
        "Install the model",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }

    // Without uv: the note instead of the button.
    std::fs::remove_file(&uv).expect("remove");
    let text = frames(&mut app);
    assert!(text.contains("Install uv first: brew install uv"), "{text}");
    assert!(!text.contains("Install the model"), "{text}");

    // A `.venv` whose Python is gone: the Terminal commands clear it, as the install.
    std::fs::create_dir_all(laya_dir.join(".venv/bin")).expect("dir");
    std::os::unix::fs::symlink(
        dir.path().join("gone/python3.12"),
        laya_dir.join(".venv/bin/python"),
    )
    .expect("symlink");
    let text = frames(&mut app);
    assert!(
        text.contains("\nuv venv --clear --python 3.12 .venv\n"),
        "{text}"
    );
    std::fs::remove_file(laya_dir.join(".venv/bin/python")).expect("remove");

    // An environment: no install button and no install commands.
    executable(&laya_dir.join(".venv/bin/python"));
    executable(&laya_dir.join(".venv/bin/laya-serve"));
    let text = frames(&mut app);
    for hidden in [
        "Install the model",
        "Install uv first",
        "with these commands in Terminal",
    ] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    server.shutdown();
}

/// Settings > Agents: "Start now" shows only when the server can start. A first start
/// without the base weights in the Hugging Face cache says that it downloads them.
#[test]
fn settings_show_start_now_and_the_first_start_download() {
    use crate::broker::model_server::{
        BouncerSettings, Host, Layout, ModelServer, ServerState, StartMode,
    };

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let executable = |path: &Path, text: &str| {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(path, text).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("mode");
    };
    let script = dir.path().join("tools/basemodel/start.sh");
    executable(&script, "sleep 60\n");
    let laya_dir = dir.path().join("laya");
    executable(&laya_dir.join(".venv/bin/python"), "#!/bin/sh\n");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    let server = ModelServer::start_for_test(
        BouncerSettings {
            start: StartMode::WhenNeeded,
            url: Some(format!("http://127.0.0.1:{port}")),
            ..BouncerSettings::default()
        },
        Layout {
            script: Some(script),
            laya_dir: laya_dir.clone(),
            checkpoints: Vec::new(),
            log: dir.path().join("Logs").join("bouncer.log"),
        },
        Host {
            uv_dirs: Vec::new(),
            launch_agents: None,
            hf_cache: Some(dir.path().join("hub")),
        },
        None,
        Duration::from_secs(1),
    );
    app.model_server = Some(Arc::clone(&server));
    app.view = OwnerView::Settings;
    app.ui.settings_tab = SettingsTab::Agents;

    // laya-serve is missing: "Cannot start" and no "Start now".
    let text = frames(&mut app);
    assert!(text.contains("Cannot start"), "{text}");
    assert!(!text.contains("Start now"), "{text}");

    // The environment is complete: "Start now".
    executable(&laya_dir.join(".venv/bin/laya-serve"), "#!/bin/sh\n");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while server.status().preflight.is_err() {
        assert!(std::time::Instant::now() < deadline, "the preflight");
        std::thread::sleep(Duration::from_millis(50));
    }
    let text = frames(&mut app);
    assert!(text.contains("Stopped"), "{text}");
    assert!(text.contains("Start now"), "{text}");

    // The weights are not in the cache: the start downloads them.
    server.start_now();
    assert!(matches!(server.state(), ServerState::Starting { .. }));
    let text = frames(&mut app);
    for expected in [
        "Starting (downloading the model weights, first start only)",
        "downloads the Laya base weights from Hugging Face",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Start now"), "{text}");
    server.shutdown();
}

/// Settings > Agents: when only the download of the weights failed, the environment is
/// there. The status does not say that it is missing, and "Install the model" tries the
/// download again.
#[test]
fn settings_offer_the_weights_download_again_after_it_failed() {
    use crate::broker::model_server::{
        BouncerSettings, FETCH_SCRIPT, Host, InstallState, Layout, ModelServer, ServerState,
        StartMode,
    };

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let executable = |path: &Path, text: &str| {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(path, text).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("mode");
    };
    let tools = dir.path().join("tools/basemodel");
    executable(&tools.join("start.sh"), "sleep 60\n");
    std::fs::write(tools.join(FETCH_SCRIPT), "# fake\n").expect("write");
    // A fake uv makes the environment. Its Python fails, so the download fails.
    executable(
        &dir.path().join("bin/uv"),
        "#!/bin/sh\ncase \"$1\" in\n  venv) mkdir -p .venv/bin; printf '#!/bin/sh\\necho fetch: 503\\nexit 1\\n' > .venv/bin/python; chmod 755 .venv/bin/python;;\n  pip) printf '#!/bin/sh\\n' > .venv/bin/laya-serve; chmod 755 .venv/bin/laya-serve;;\nesac\n",
    );
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    let laya_dir = dir.path().join("laya");
    let server = ModelServer::start_for_test(
        BouncerSettings {
            start: StartMode::WhenNeeded,
            url: Some(format!("http://127.0.0.1:{port}")),
            ..BouncerSettings::default()
        },
        Layout {
            script: Some(tools.join("start.sh")),
            laya_dir: laya_dir.clone(),
            checkpoints: Vec::new(),
            log: dir.path().join("Logs").join("bouncer.log"),
        },
        Host {
            uv_dirs: vec![dir.path().join("bin")],
            launch_agents: None,
            hf_cache: Some(dir.path().join("hub")),
        },
        None,
        Duration::from_secs(1),
    );
    app.model_server = Some(Arc::clone(&server));
    app.view = OwnerView::Settings;
    app.ui.settings_tab = SettingsTab::Agents;
    // A run finds no environment.
    assert!(crate::broker::model_server::ModelGate::before_model(&*server).is_err());
    assert!(matches!(server.state(), ServerState::Failed { .. }));

    server.install().expect("install");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while matches!(server.install_state(), InstallState::Installing { .. }) {
        assert!(std::time::Instant::now() < deadline, "the install");
        std::thread::sleep(Duration::from_millis(20));
    }
    let text = frames(&mut app);
    for expected in [
        "The install failed. Downloading the model weights failed",
        "The first start of the model server downloads the weights.",
        "Stopped",
        "Install the model",
        "Or download them with this command in Terminal:",
        &format!(".venv/bin/python -B {}", tools.join(FETCH_SCRIPT).display()),
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for hidden in ["The Laya environment is missing", "Cannot start"] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    server.shutdown();
}

/// Settings > General shows the file of the open vault one time, in Vaults. "Lock now"
/// is a row of Vaults, and About has no second version row.
#[test]
fn settings_show_the_vault_file_one_time() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let path = path_of(&app, "Personal").display().to_string();
    app.view = OwnerView::Settings;
    app.ui.settings_tab = SettingsTab::General;
    let text = frames(&mut app);
    assert_eq!(text.matches(path.as_str()).count(), 1, "{path}: {text}");
    assert!(text.contains("Lock now"), "{text}");
    assert!(
        text.contains("The broker refuses all agent requests while the vault is locked."),
        "{text}"
    );

    app.ui.settings_tab = SettingsTab::About;
    let text = frames(&mut app);
    assert_eq!(
        text.lines().filter(|line| *line == "Version").count(),
        1,
        "only Updates shows the version: {text}"
    );
}

/// A switch locks the open vault, ends its waiting runs with the switch text, clears
/// every piece of state of that vault, and puts the new vault locked in the slot that
/// the broker shares. A token of the other vault then gets a clear refusal.
#[test]
fn a_switch_ends_waiting_runs_and_clears_the_state_of_the_vault() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Alpha", PASS_A);
    let (_, alpha_token) = app
        .owner_ui
        .session
        .register_agent("Alpha agent")
        .expect("register");
    let alpha_token = alpha_token.expose().to_owned();
    app.leave_vault_for(Step::Create, None);
    create(&mut app, "Beta", PASS_B);
    let alpha = id_of(&app, "Alpha");
    let socket = dir.path().join("s").join("broker.sock");
    app.start_broker(&socket);
    let BrokerState::Running(handle) = &app.broker else {
        panic!("the broker did not start");
    };
    let approvals = Arc::clone(handle.approvals());

    // State of Beta: a selection, a search, a revealed value, forms, marks.
    let item = add_item(&mut app, "Beta key");
    app.select_item(item.to_string());
    let proof = app
        .owner_gate()
        .authorize(
            OwnerAction::Reveal { item_id: item },
            OwnerCheck::passphrase(PASS_B),
        )
        .expect("owner check");
    app.owner_ui.session.reveal(item, proof).expect("reveal");
    assert!(app.owner_ui.session.revealed_value(item, "token").is_some());
    let (agent, beta_token) = app
        .owner_ui
        .session
        .register_agent("Beta agent")
        .expect("register");
    let beta_secret = beta_token.expose().to_owned();
    app.ui.agent_setup.advanced = true;
    app.ui.agent_setup.result = Some(Err("Previous setup error".to_owned()));
    app.owner_ui.fresh_token = Some(FreshToken {
        agent_name: agent.name.clone(),
        token: beta_token,
        rotated: false,
    });
    app.search = "beta".to_owned();
    app.owner_ui.selected_agent = Some(agent.id);
    app.owner_ui
        .exec_dir_inputs
        .insert((agent.id, item), "/tmp".to_owned());
    app.owner_ui.edit_secrets.token.push_str(CANARY);
    app.owner.acknowledged.insert(EventKey::Activity(1));
    app.learning.inspected = Some(1);
    app.ui.sheet = Some(Sheet::EditItem);

    // A run waits in Beta: a wait record in the vault and a card in the queue.
    let ticket = {
        let shared = app.owner_ui.session.shared_vault();
        let mut guard = shared.lock().expect("vault");
        guard
            .as_mut()
            .expect("open")
            .start_wait(&NewActivity {
                agent_id: Some(agent.id),
                agent_name: agent.name.clone(),
                item_id: Some(item),
                operation: "run npm test".to_owned(),
                decision: ActivityDecision::Deny,
                reason: "Run the tests.".to_owned(),
            })
            .expect("wait record")
    };
    let waiter = {
        let approvals = Arc::clone(&approvals);
        std::thread::spawn(move || {
            approvals.wait_for(
                PendingRun {
                    id: 0,
                    agent: "Beta agent".to_owned(),
                    command: vec!["npm".to_owned(), "test".to_owned()],
                    cwd: "/tmp".to_owned(),
                    env_names: Vec::new(),
                    purpose: "Run the tests.".to_owned(),
                    risk: String::new(),
                    user_request: "Run the tests.".to_owned(),
                    request_source: String::new(),
                    agent_request: String::new(),
                    remember: None,
                },
                Duration::from_secs(20),
                || true,
            )
        })
    };
    while approvals.pending().is_empty() {
        std::thread::sleep(Duration::from_millis(5));
    }

    let ctx = egui::Context::default();
    app.switch_vault(&alpha, Some(&ctx));
    assert_eq!(
        waiter.join().expect("waiter"),
        ApprovalOutcome::Invalidated,
        "the waiting run ends"
    );
    drop(ticket);

    // Alpha is in the shared slot, locked.
    let alpha_path = path_of(&app, "Alpha");
    assert_eq!(app.owner_ui.session.vault_path(), Some(alpha_path.clone()));
    assert!(app.owner_ui.session.is_locked());
    {
        let shared = app.owner_ui.session.shared_vault();
        let guard = shared.lock().expect("vault");
        let open = guard.as_ref().expect("a vault in the slot");
        assert_eq!(open.path(), alpha_path);
        assert!(open.is_locked());
    }
    assert_eq!(app.vault_list.current.as_deref(), Some(alpha.as_str()));
    assert_eq!(
        Registry::read(&data_dir(&dir))
            .expect("read")
            .expect("list")
            .last_used_id(),
        Some(alpha.as_str())
    );

    // Nothing of Beta stays.
    assert!(!app.ui.agent_setup.advanced);
    assert!(app.ui.agent_setup.result.is_none());
    assert_eq!(app.view, OwnerView::Vault);
    assert!(app.selected_item_id.is_none());
    assert!(app.search.is_empty());
    assert!(app.owner_ui.session.revealed_value(item, "token").is_none());
    assert!(app.owner_ui.fresh_token.is_none());
    assert!(app.owner_ui.selected_agent.is_none());
    assert!(app.owner_ui.exec_dir_inputs.is_empty());
    assert!(app.owner_ui.edit_secrets.is_blank());
    assert!(app.owner.acknowledged.is_empty());
    assert!(app.learning.inspected.is_none());
    assert!(app.ui.sheet.is_none());
    assert_eq!(app.ui.start, Step::Home);
    assert!(
        app.status_text.contains("“Alpha” is open"),
        "{}",
        app.status_text
    );

    // The unlock screen names Alpha and offers Beta.
    let text = frames(&mut app);
    assert!(text.contains("Apassy is locked"), "{text}");
    assert!(
        text.contains("Type the passphrase of “Alpha” to unlock it."),
        "{text}"
    );
    assert!(!text.contains(&beta_secret), "{text}");
    assert!(!text.contains(CANARY), "{text}");

    // The broker serves Alpha now. A token of Beta gets a clear refusal that names no
    // vault.
    unlock(&mut app, PASS_A);
    let answer = client::send(&socket, &alpha_token, Action::ListAccess).expect("answer");
    assert!(answer.ok, "{answer:?}");
    let refused = client::send(&socket, &beta_secret, Action::ListAccess).expect("answer");
    let error = refused.error.expect("an error");
    assert_eq!(error.code, "unauthenticated");
    assert!(
        error
            .message
            .contains("not valid for the Apassy vault that is open now"),
        "{}",
        error.message
    );
    assert!(!error.message.contains("Beta") && !error.message.contains("Alpha"));

    // Back in Beta, the run that waited has its entry with the switch text.
    app.switch_vault(&id_of(&app, "Beta"), Some(&ctx));
    unlock(&mut app, PASS_B);
    let rows = app.owner_ui.session.activity(20).expect("activity");
    let ended: Vec<_> = rows
        .iter()
        .filter(|row| row.reason.starts_with(ENDED_BY_SWITCH))
        .collect();
    assert_eq!(ended.len(), 1, "{rows:?}");
    assert_eq!(ended[0].agent, "Beta agent");
}

/// At start, the last used vault opens locked. The unlock screen names it and lets
/// the owner pick another one.
#[test]
fn start_opens_the_last_used_vault_locked() {
    let dir = TempDir::new().expect("temp dir");
    {
        let mut app = app_in(&dir);
        create(&mut app, "Alpha", PASS_A);
        app.leave_vault_for(Step::Create, None);
        create(&mut app, "Beta", PASS_B);
        let alpha = id_of(&app, "Alpha");
        app.switch_vault(&alpha, None);
    }
    let mut app = app_in(&dir);
    app.open_last_vault(None);
    assert!(app.owner_ui.session.has_file());
    assert!(app.owner_ui.session.is_locked());
    assert_eq!(app.current_vault_name().as_deref(), Some("Alpha"));
    let text = frames(&mut app);
    assert!(text.contains("Apassy is locked"), "{text}");
    assert!(text.contains("“Alpha”"), "{text}");
    assert!(text.contains("New vault…"), "{text}");
    assert!(text.contains("Open vault file…"), "{text}");

    // The picker of the unlock screen switches to Beta.
    let beta = id_of(&app, "Beta");
    app.switch_vault(&beta, None);
    assert_eq!(app.current_vault_name().as_deref(), Some("Beta"));
    unlock(&mut app, PASS_B);
    assert!(
        app.owner_ui.session.unlock(PASS_A).is_err(),
        "each vault has its passphrase"
    );
}

/// "Remove from list" keeps the file and refuses the open vault. A rename checks the
/// name.
#[test]
fn remove_from_list_keeps_the_file_and_rename_checks_the_name() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Alpha", PASS_A);
    app.leave_vault_for(Step::Create, None);
    create(&mut app, "Beta", PASS_B);
    let alpha = id_of(&app, "Alpha");
    let beta = id_of(&app, "Beta");
    let alpha_path = path_of(&app, "Alpha");

    app.vault_list.name_input = "alpha".to_owned();
    assert!(!app.rename_vault(&beta));
    assert!(
        app.status_text.contains("Another vault"),
        "{}",
        app.status_text
    );
    app.vault_list.name_input = "Gamma".to_owned();
    assert!(app.rename_vault(&beta));
    assert_eq!(app.current_vault_name().as_deref(), Some("Gamma"));

    assert!(!app.remove_vault(&beta), "the open vault stays in the list");
    assert!(
        app.status_text.contains("open vault stays"),
        "{}",
        app.status_text
    );

    app.view = OwnerView::Settings;
    app.ui.sheet = Some(Sheet::Vault(VaultSheet::Remove { id: alpha.clone() }));
    let text = frames(&mut app);
    assert!(text.contains("Remove “Alpha” from the list?"), "{text}");
    assert!(text.contains("Apassy does not delete it"), "{text}");
    assert!(app.remove_vault(&alpha));
    assert!(alpha_path.is_file(), "the file stays");
    let read = Registry::read(&data_dir(&dir))
        .expect("read")
        .expect("list");
    let names: Vec<&str> = read
        .entries()
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    assert_eq!(names, ["Gamma"]);
}

/// A listed vault whose file is gone: a switch changes nothing and offers to remove
/// it; at start, the welcome screen says so.
#[test]
fn a_missing_vault_file_is_shown_and_can_be_removed() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Alpha", PASS_A);
    app.leave_vault_for(Step::Create, None);
    create(&mut app, "Beta", PASS_B);
    let alpha = id_of(&app, "Alpha");
    let beta = id_of(&app, "Beta");
    let beta_path = path_of(&app, "Beta");
    app.switch_vault(&alpha, None);
    std::fs::remove_file(&beta_path).expect("remove the file");
    unlock(&mut app, PASS_A);

    app.switch_vault(&beta, None);
    assert!(!app.owner_ui.session.is_locked(), "Alpha stays open");
    assert_eq!(
        app.ui.sheet,
        Some(Sheet::Vault(VaultSheet::Missing { id: beta.clone() }))
    );
    assert!(
        app.status_text.contains("cannot find"),
        "{}",
        app.status_text
    );
    let text = frames(&mut app);
    assert!(text.contains("The file of “Beta” is missing"), "{text}");
    assert!(text.contains("Remove from list"), "{text}");

    // At the next start the list names Beta last. The welcome screen shows the
    // problem and the list.
    let mut list = app.vault_list.registry.clone();
    list.mark_opened(&beta, crate::vaults::now()).expect("mark");
    list.save(&data_dir(&dir)).expect("save");
    drop(app);
    let mut app = app_in(&dir);
    app.open_last_vault(None);
    assert!(!app.owner_ui.session.has_file());
    assert_eq!(app.vault_list.missing.as_deref(), Some(beta.as_str()));
    let text = frames(&mut app);
    for expected in [
        "Welcome to Apassy",
        "The file of “Beta” is missing",
        "Remove from list",
        "Your vaults",
        "Alpha",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(app.remove_vault(&beta));
    assert!(app.vault_list.missing.is_none());
    let text = frames(&mut app);
    assert!(!text.contains("is missing"), "{text}");
}

/// Open adds a file to the list with a name from its file name. A listed file opens
/// as it is. Restore adds the restored file as a new vault.
#[test]
fn open_and_restore_add_the_file_to_the_list() {
    let dir = TempDir::new().expect("temp dir");
    let outside = dir.path().join("elsewhere").join("client-x.db");
    std::fs::create_dir_all(outside.parent().expect("parent")).expect("folder");
    drop(crate::vault::Vault::create(&outside, PASS_A).expect("create"));
    let mut app = app_in(&dir);
    app.ui.start = Step::Open;
    app.owner_ui.open_path = outside.display().to_string();
    let text = frames(&mut app);
    assert!(text.contains("client-x"), "the name from the file: {text}");
    app.open_vault_file(&outside.display().to_string(), None);
    assert!(app.owner_ui.session.is_locked());
    assert_eq!(app.current_vault_name().as_deref(), Some("client-x"));
    assert_eq!(app.ui.start, Step::Home);
    app.open_vault_file(&outside.display().to_string(), None);
    assert_eq!(
        app.vault_list.registry.entries().len(),
        1,
        "no second entry"
    );

    // A backup of client-x, restored as a new vault with a name.
    unlock(&mut app, PASS_A);
    let backup = dir.path().join("client-x.backup");
    app.owner_ui.session.backup(&backup).expect("backup");
    let ctx = egui::Context::default();
    app.owner_ui.restore_source = backup.display().to_string();
    app.vault_list.name_input = "Restored X".to_owned();
    app.owner_ui.passphrase.push_str(PASS_A);
    start::restore_now(&mut app, &ctx);
    assert!(app.owner_ui.passphrase.is_empty());
    assert_eq!(app.current_vault_name().as_deref(), Some("Restored X"));
    let restored = path_of(&app, "Restored X");
    assert!(restored.ends_with("vaults/restored-x.db"), "{restored:?}");
    assert!(app.owner_ui.session.is_locked());
    assert_eq!(app.vault_list.registry.entries().len(), 2);
}
