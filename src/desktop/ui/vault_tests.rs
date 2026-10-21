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
use super::{SettingsSection, Sheet, draw};
use crate::agent::client;
use crate::agent::wire::Action;
use crate::broker::approvals::{ApprovalOutcome, OwnerAction, OwnerCheck, PendingRun};
use crate::desktop::inbox::EventKey;
use crate::desktop::owner_store::{ENDED_BY_SWITCH, FreshToken, SecretForm};
use crate::desktop::{BrokerState, DesktopApp, ItemDraft};
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
    super::open_settings(&mut app, SettingsSection::Vault);
    let text = frames(&mut app);
    for expected in ["Vaults", "Personal", "Client Work", "Open"] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

/// Settings is a view with six sections (ADR 0026 §3). The list column names each one;
/// the detail column shows the groups of the selected section only.
#[test]
fn settings_show_the_groups_of_the_selected_section_only() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    super::open_settings(&mut app, SettingsSection::Vault);
    let text = frames(&mut app);
    for section in SettingsSection::ALL {
        assert!(text.contains(section.label()), "{section:?}: {text}");
    }
    let cases = [
        (
            SettingsSection::Vault,
            &["Personal", "Back up now…", "Restore…", "Import…"][..],
            &["Change passphrase…", "Install tools…", "Keyboard shortcuts"][..],
        ),
        (
            SettingsSection::Security,
            &["Touch ID", "Change passphrase…"][..],
            &["Back up now…", "Token lifetime", "Owner checks\n"][..],
        ),
        (
            SettingsSection::Devices,
            &["This Mac", "Allow the iPhone app on this network", "Relay"][..],
            &["Back up now…", "Change passphrase…", "Other Macs"][..],
        ),
        (
            SettingsSection::Bouncer,
            &["Calibration and learning"][..],
            &["Back up now…", "Asked you", "Address", "Install tools…"][..],
        ),
        (
            SettingsSection::Tools,
            &["Command line", "Install tools…", "Browser extension"][..],
            &["Back up now…", "Socket", "Sessions"][..],
        ),
        (
            SettingsSection::Updates,
            &["Version", "Keyboard shortcuts"][..],
            &["Back up now…", "Contract", "Install tools…"][..],
        ),
    ];
    for (section, shown, hidden) in cases {
        super::open_settings(&mut app, section);
        let text = frames(&mut app);
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
    }
}

/// Settings > Bouncer: how the bouncer model starts. "When a run needs it" is the
/// default (ADR 0024) and starts nothing before a run. Each mode shows its label, its
/// status, and its actions, and a missing start script shows the install commands.
#[test]
fn settings_show_how_the_bouncer_model_starts() {
    use crate::broker::model_server::{
        BouncerSettings, Host, Layout, ModelServer, ServerState, StartMode,
    };

    // The supervisor honors these variables. Remove them only in a child process,
    // so this fixture cannot probe the owner's model or use its API key.
    if std::env::var_os("APASSY_BOUNCER_URL").is_some()
        || std::env::var_os("APASSY_BOUNCER_KEY").is_some()
    {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("desktop::ui::vault_tests::settings_show_how_the_bouncer_model_starts")
            .env_remove("APASSY_BOUNCER_URL")
            .env_remove("APASSY_BOUNCER_KEY")
            .output()
            .expect("isolated model settings fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated model settings fixture must run and pass exactly one test: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let settings_path = dir.path().join("bouncer.json");
    // Keep a synthetic port reserved. The external-mode probe times out against this
    // listener instead of finding an installed bouncer and warming it for 60 seconds.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("synthetic listener");
    let fixture_url = format!(
        "http://{}",
        listener.local_addr().expect("synthetic address")
    );
    // No uv, no LaunchAgent, and no installed model.
    let server = ModelServer::start_with_host(
        Some(settings_path.clone()),
        BouncerSettings {
            url: Some(fixture_url.clone()),
            ..BouncerSettings::load(&settings_path)
        },
        Layout {
            script: None,
            laya_dir: dir.path().join("laya"),
            checkpoints: Vec::new(),
            log: dir.path().join("Logs").join("bouncer.log"),
        },
        Host::none(),
    );
    app.model_server = Some(Arc::clone(&server));
    super::open_settings(&mut app, SettingsSection::Bouncer);
    let text = frames(&mut app);
    for expected in ["Bouncer", "Model", "Start the model", "When a run needs it"] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Start now"), "{text}");
    assert!(!settings_path.exists(), "the default is not written");

    let set = |mode| {
        server
            .set_settings(BouncerSettings {
                start: mode,
                url: Some(fixture_url.clone()),
                ..BouncerSettings::default()
            })
            .expect("save");
    };
    set(StartMode::External);
    let text = frames(&mut app);
    assert!(text.contains("Managed outside Apassy"), "{text}");
    for hidden in ["Stop after", "Start now", "Install…"] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    set(StartMode::WhenNeeded);
    let text = frames(&mut app);
    for expected in [
        "When a run needs it",
        "Stop after",
        "30 minutes without a run",
        // The script is missing here, so the status does not promise a start.
        "Cannot start",
        "Apassy cannot find the start script tools/basemodel/start.sh.",
        // No uv here, so no install button.
        "Install uv first: brew install uv",
        "Until then, every run waits for you.",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    // The Terminal commands are in the menu of the row, not on the page.
    assert!(!text.contains("laya[serve]==0.3.20"), "{text}");
    assert!(
        super::settings::install_commands(&server.status()).contains("laya[serve]==0.3.20"),
        "the menu copies the install commands"
    );
    assert!(!text.contains("Install…"), "{text}");
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

/// Settings > Bouncer: "Install the model" shows only in a managed mode while the Laya
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
    super::open_settings(&mut app, SettingsSection::Bouncer);
    let remove = format!(
        "launchctl bootout gui/$(id -u)/com.example.bouncer\nrm {}",
        plist.display()
    );

    // The environment and the model are missing.
    let text = frames(&mut app);
    for expected in [
        "Install…",
        "The LaunchAgent com.example.bouncer starts the bouncer with APASSY_BASE_MODEL",
        "That file does not exist, so the start fails.",
        "Copy remove commands",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains("Install uv first"), "{text}");
    // The install commands are in the menu of the row; the last downloads the weights.
    let commands = super::settings::install_commands(&server.status());
    for expected in [
        "\nuv venv --python 3.12 .venv\n",
        &format!(
            "\n.venv/bin/python -B {}",
            dir.path()
                .join("tools/basemodel/fetch_weights.py")
                .display()
        ),
    ] {
        assert!(commands.contains(expected), "{expected}: {commands}");
    }
    // "Copy remove commands" copies the commands that remove the LaunchAgent.
    assert_eq!(server.status().launch_agents[0].remove_commands(), remove);

    // "Managed outside Apassy" offers no install. The missing model still shows.
    server
        .set_settings(BouncerSettings {
            start: StartMode::External,
            ..BouncerSettings::default()
        })
        .expect("settings");
    let text = frames(&mut app);
    assert!(!text.contains("Install…"), "{text}");
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
        "Copy remove commands",
        "Install…",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }

    // Without uv: the note instead of the button.
    std::fs::remove_file(&uv).expect("remove");
    let text = frames(&mut app);
    assert!(text.contains("Install uv first: brew install uv"), "{text}");
    assert!(!text.contains("Install…"), "{text}");

    // A `.venv` whose Python is gone: the Terminal commands clear it, as the install.
    std::fs::create_dir_all(laya_dir.join(".venv/bin")).expect("dir");
    std::os::unix::fs::symlink(
        dir.path().join("gone/python3.12"),
        laya_dir.join(".venv/bin/python"),
    )
    .expect("symlink");
    let commands = super::settings::install_commands(&server.status());
    assert!(
        commands.contains("\nuv venv --clear --python 3.12 .venv\n"),
        "{commands}"
    );
    std::fs::remove_file(laya_dir.join(".venv/bin/python")).expect("remove");

    // An environment: no install button and no install commands.
    executable(&laya_dir.join(".venv/bin/python"));
    executable(&laya_dir.join(".venv/bin/laya-serve"));
    let text = frames(&mut app);
    for hidden in ["Install…", "Install uv first"] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    server.shutdown();
}

/// Settings > Bouncer: "Start now" shows only when the server can start. A first start
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
    super::open_settings(&mut app, SettingsSection::Bouncer);

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

/// Settings > Bouncer: when only the download of the weights failed, the environment is
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
    super::open_settings(&mut app, SettingsSection::Bouncer);
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
        "Install…",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    for hidden in ["The Laya environment is missing", "Cannot start"] {
        assert!(!text.contains(hidden), "{hidden}: {text}");
    }
    server.shutdown();
}

/// Settings > Vault shows where the open vault lives in short words, not its whole
/// path (that is the hover text). "Lock now" is on its row, and About has no second
/// version row.
#[test]
fn settings_show_the_vault_file_one_time() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let path = path_of(&app, "Personal").display().to_string();
    super::open_settings(&mut app, SettingsSection::Vault);
    let text = frames(&mut app);
    assert_eq!(text.matches(path.as_str()).count(), 0, "{path}: {text}");
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let place = super::vaults::short_location(
        &path_of(&app, "Personal"),
        home.as_deref(),
        &app.vault_list.data_dir,
    );
    assert!(text.contains(&place), "{place}: {text}");

    super::open_settings(&mut app, SettingsSection::Updates);
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
                    question: Default::default(),
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
    assert!(app.place.is_credentials());
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

    super::open_settings(&mut app, SettingsSection::Vault);
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

/// Draw one frame with `events` and two without, at the tall size, in one context.
/// Returns the painted text and each text with its position, of the last frame.
fn frames_with(app: &mut DesktopApp, events: Vec<egui::Event>) -> (String, Vec<(String, Pos2)>) {
    let ctx = egui::Context::default();
    let mut text = String::new();
    let mut placed = Vec::new();
    for events in [events, Vec::new(), Vec::new()] {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            events,
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        text.clear();
        placed.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
            collect_placed(&clipped.shape, &mut placed);
        }
        output.drop_without_applying_deltas();
    }
    (text, placed)
}

fn collect_placed(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| collect_placed(inner, out)),
        _ => {}
    }
}

/// ⌘S: the default action of the open sheet.
fn command_s() -> egui::Event {
    egui::Event::Key {
        key: egui::Key::S,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::COMMAND,
    }
}

/// Click the last painted text `needle` (the top layer draws last) in one context.
fn click_text(app: &mut DesktopApp, needle: &str) {
    let ctx = egui::Context::default();
    let frame = |app: &mut DesktopApp, events: Vec<egui::Event>| {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            events,
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| draw(app, ui));
        let mut placed = Vec::new();
        for clipped in &output.shapes {
            collect_placed(&clipped.shape, &mut placed);
        }
        output.drop_without_applying_deltas();
        placed
    };
    frame(app, Vec::new());
    let placed = frame(app, Vec::new());
    let at = placed
        .iter()
        .rev()
        .find(|(text, _)| text == needle)
        .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
        .unwrap_or_else(|| panic!("{needle} is not on the screen"));
    let button = |pressed| egui::Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    frame(app, vec![egui::Event::PointerMoved(at)]);
    frame(app, vec![button(true)]);
    frame(app, vec![button(false)]);
    frame(app, Vec::new());
}

/// Folders (ADR 0026 §5): New Folder makes a folder and a nested one, a taken name is
/// refused, Rename renames, Move to Folder moves a credential and the list follows the
/// folder, and Delete moves the credentials of the folder up to its parent.
#[test]
fn folder_sheets_create_nested_rename_move_and_delete() {
    use super::folders::{self, FolderTree};
    use crate::desktop::Place;

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let filed = add_item(&mut app, "Filed key");
    add_item(&mut app, "Loose key");
    let folder_of = |app: &DesktopApp, id: u64| {
        app.owner_ui
            .session
            .with_vault(|vault| vault.item_folder(id))
            .expect("open")
            .expect("item")
    };

    // New Folder at the top level: "+" on the Personal header opens it.
    folders::open_new(&mut app, None);
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(
        text.contains("New Folder") && text.contains("In Personal."),
        "{text}"
    );
    app.ui.folder_name = "Work".to_owned();
    frames_with(&mut app, vec![command_s()]);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    let tree = FolderTree::load(&app);
    let work = tree.folders[0].uuid.clone();
    assert_eq!(
        app.place,
        Place::Folder(Some(work.clone())),
        "the new folder shows"
    );

    // A nested folder: its parent opens in the sidebar.
    folders::open_new(&mut app, Some(work.clone()));
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(text.contains("In Work."), "{text}");
    app.ui.folder_name = "Acme".to_owned();
    frames_with(&mut app, vec![command_s()]);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    let tree = FolderTree::load(&app);
    let acme = tree
        .children(Some(&work))
        .next()
        .expect("nested folder")
        .uuid
        .clone();
    assert_eq!(tree.path(&acme), ["Work", "Acme"]);
    assert!(app.ui.open_folders.contains(&work));
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(
        text.contains("Acme"),
        "the sidebar shows the nested folder: {text}"
    );

    // A taken name, in any case, is refused and the sheet stays.
    folders::open_new(&mut app, Some(work.clone()));
    app.ui.folder_name = "acme".to_owned();
    frames_with(&mut app, vec![command_s()]);
    assert!(app.ui.sheet.is_some(), "the sheet stays after an error");
    assert!(
        app.status_text.contains("already there"),
        "{}",
        app.status_text
    );
    app.ui.sheet = None;

    // Rename.
    folders::open_rename(&mut app, &acme);
    assert_eq!(app.ui.folder_name, "Acme", "Rename starts with the name");
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(text.contains("Rename “Acme”"), "{text}");
    app.ui.folder_name = "Acme Inc".to_owned();
    frames_with(&mut app, vec![command_s()]);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert_eq!(
        FolderTree::load(&app).name(&acme).as_deref(),
        Some("Acme Inc")
    );

    // Move to Folder: the credential goes to Acme Inc; the folder list holds it.
    app.place = Place::CREDENTIALS;
    app.select_item(filed.to_string());
    folders::open_move(&mut app, filed);
    assert_eq!(app.ui.move_target, None, "it starts at the top level");
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(
        text.contains("Move “Filed key”") && text.contains("Acme Inc"),
        "{text}"
    );
    app.ui.move_target = Some(acme.clone());
    frames_with(&mut app, vec![command_s()]);
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert_eq!(folder_of(&app, filed).as_deref(), Some(acme.as_str()));
    // "All credentials" groups by folder path.
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(text.contains("Work › Acme Inc"), "{text}");
    // The list of Work holds the credentials of its subfolders.
    app.place = Place::Folder(Some(work.clone()));
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(
        text.contains("Filed key") && !text.contains("Loose key"),
        "{text}"
    );

    // Delete Acme Inc: its credential moves up to Work. No credential is deleted.
    app.place = Place::Folder(Some(acme.clone()));
    folders::open_delete(&mut app, &acme);
    let (text, _) = frames_with(&mut app, Vec::new());
    assert!(text.contains("Delete “Acme Inc”?"), "{text}");
    assert!(
        text.contains("move to Work. No credential is deleted."),
        "{text}"
    );
    click_text(&mut app, "Delete");
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert!(FolderTree::load(&app).get(&acme).is_none());
    assert_eq!(folder_of(&app, filed).as_deref(), Some(work.as_str()));
    assert_eq!(
        app.place,
        Place::Folder(Some(work.clone())),
        "the list shows the parent"
    );
    assert!(
        app.status_text.contains("Its credential is in Work."),
        "{}",
        app.status_text
    );
    assert!(
        app.owner_ui.session.details(filed).is_ok(),
        "the credential stays"
    );

    // Delete Work: the credential goes to the top level.
    assert!(folders::delete(&mut app, &work));
    assert_eq!(folder_of(&app, filed), None);
    assert_eq!(app.place, Place::CREDENTIALS);
}

// ---- The credential page (ADR 0025, ADR 0026 §2). ----

/// Three frames of the whole app at `size`, in a new context. Returns the painted text
/// of the last frame.
fn frames_at(app: &mut DesktopApp, size: Vec2) -> String {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for _ in 0..3 {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
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

/// A synthetic value with a provider prefix, as in `tests/detect.rs`.
fn fake_key(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", &"EXAMPLE0".repeat(len / 8 + 1)[..len])
}

/// Paste `text` as the owner does in New Credential, at the top level.
fn paste(app: &mut DesktopApp, text: &str) -> u64 {
    app.owner_ui
        .session
        .add_detected(text, None)
        .expect("add pasted credential")[0]
        .id
}

fn register(app: &mut DesktopApp, name: &str) -> u64 {
    app.owner_ui
        .session
        .with_vault(|vault| vault.register_agent(name))
        .expect("open")
        .expect("register")
        .0
        .id
}

fn record_use(app: &mut DesktopApp, item_id: u64, agent_id: u64, command: &str) {
    use crate::broker::action_kind::ActionKind;
    use crate::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault.record_item_use(&NewItemUse {
                item_id,
                agent_id: Some(agent_id),
                agent_name: "Claude Code".to_owned(),
                project_key: "/synthetic/apassy".to_owned(),
                project_label: "apassy".to_owned(),
                action: ActionKind::Read,
                command_summary: command.to_owned(),
                hosts: vec!["api.example.com".to_owned()],
                outcome: UseOutcome::Allowed,
                decided_by: UseDecidedBy::Bouncer,
                answered_on: String::new(),
                decision_log_id: None,
            })
        })
        .expect("open")
        .expect("record use");
}

#[test]
fn a_credential_lists_and_revokes_bouncer_evaluation_permission_without_authentication() {
    use crate::broker::action_kind::ActionKind;
    use crate::vault::answers::ProjectRef;
    use crate::vault::bouncer_scopes::EvaluationConfirmation;
    use crate::vault::{Environment, RiskLevel};

    let dir = TempDir::new().expect("dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let item_id = add_item(&mut app, "Deploy key");
    let agent_id = register(&mut app, "Claude Code");
    app.owner_ui
        .session
        .with_vault(|vault| -> crate::vault::VaultResult<()> {
            let revision = vault.details(item_id)?.summary.revision;
            vault.authorize_evaluation(
                agent_id,
                &ProjectRef {
                    key: "/synthetic/apassy".to_owned(),
                    label: "apassy".to_owned(),
                },
                ActionKind::Read,
                &[EvaluationConfirmation {
                    item_id,
                    revision,
                    environment: Environment::Development,
                    risk: RiskLevel::Low,
                    hosts: vec!["api.example.com".to_owned()],
                }],
                Some("synthetic-script-binding"),
                "Synthetic Mac",
            )
        })
        .expect("open")
        .expect("authorize synthetic evaluation scope");
    app.select_item(item_id.to_string());
    let text = frames(&mut app);
    for expected in [
        "Bouncer decisions",
        "Claude Code",
        "reading in apassy",
        "api.example.com",
        "Only this exact command, execution context and directly selected script version.",
        "Model evaluation only",
        "Remove",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(!text.contains(CANARY), "the secret stays masked");
    assert!(!text.contains("synthetic-script-binding"), "{text}");
    let scopes = app
        .owner_ui
        .session
        .evaluation_scopes(item_id)
        .expect("scopes");
    assert_eq!(scopes.len(), 1);
    assert_eq!(
        scopes[0].command_binding.as_deref(),
        Some("synthetic-script-binding")
    );
    click_text(&mut app, "Remove");
    assert!(
        app.owner.check.is_none(),
        "revocation is stricter and starts no owner check"
    );
    assert!(
        app.owner_ui
            .session
            .evaluation_scopes(item_id)
            .expect("scopes")
            .is_empty()
    );
    assert!(!frames(&mut app).contains("Bouncer decisions"));
    assert!(
        !app.owner_ui
            .session
            .remove_evaluation_scope(scopes[0].id)
            .expect("idempotent removal")
    );
}

/// The rules of a credential: an answer of the owner and an exception of an agent. The
/// page lists both and the agent use. Removing the exception gives authority back, so
/// it asks for the owner check first; removing the answer makes the bouncer ask again,
/// so it needs no check (ADR 0025 §3b, §3f).
#[test]
fn the_credential_page_lists_rules_and_removing_an_exception_asks_for_the_owner() {
    use crate::broker::action_kind::ActionKind;
    use crate::desktop::owner_check::OwnerRequest;
    use crate::vault::answers::ProjectRef;
    use crate::vault::exceptions::ExceptionKind;

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let id = add_item(&mut app, "Deploy key");
    let agent = register(&mut app, "Claude Code");
    app.owner_ui
        .session
        .with_vault(|vault| -> crate::vault::VaultResult<()> {
            vault.add_agent_exception(agent, id, ExceptionKind::Never)?;
            let project = ProjectRef {
                key: "/synthetic/apassy".to_owned(),
                label: "apassy".to_owned(),
            };
            vault.remember_answer(id, &project, ActionKind::Change, "this Mac", &[])?;
            Ok(())
        })
        .expect("open")
        .expect("rules");
    for command in [
        "gh api user",
        "gh pr list",
        "gh run list",
        "gh release view",
    ] {
        record_use(&mut app, id, agent, command);
    }
    app.select_item(id.to_string());
    app.ui
        .set_expanded(&format!("credential-agent-settings-{id}"), true);
    let text = frames(&mut app);
    for expected in [
        "Agent use",
        "Show All",
        "Claude Code in apassy",
        "gh release view",
        " · Allowed automatically",
        "Rules from your answers",
        "Allow changes in apassy",
        "Never for Claude Code",
        "Always ask me",
        "Environment",
        "Hosts and risk",
        "Folder",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    assert!(
        !text.contains("gh api user"),
        "only the 3 newest uses: {text}"
    );
    assert!(!text.contains(CANARY), "the secret stays masked");

    // "Show All" lists every use.
    click_text(&mut app, "Show All");
    let text = frames(&mut app);
    assert!(
        text.contains("gh api user") && text.contains("Show Less"),
        "{text}"
    );

    // The exception row is the last Remove: the owner check first.
    click_text(&mut app, "Remove");
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        matches!(
            &check.request,
            OwnerRequest::RemoveAgentException { agent_id, item_id, kind: ExceptionKind::Never, .. }
                if *agent_id == agent && *item_id == id
        ),
        "{:?}",
        check.request
    );
    let still = app
        .owner_ui
        .session
        .with_vault(|vault| vault.item_exceptions(id))
        .expect("open")
        .expect("exceptions");
    assert_eq!(still.len(), 1, "nothing changes before the check");
    app.confirm_owner_now(OwnerCheck::passphrase(PASS_A))
        .expect("owner check");
    let left = app
        .owner_ui
        .session
        .with_vault(|vault| vault.item_exceptions(id))
        .expect("open")
        .expect("exceptions");
    assert!(left.is_empty(), "{left:?}");
    let text = frames(&mut app);
    assert!(!text.contains("Never for Claude Code"), "{text}");

    // The answer: removed at once, without a check.
    click_text(&mut app, "Remove");
    assert!(
        app.owner.check.is_none(),
        "a stricter change needs no check"
    );
    let answers = app
        .owner_ui
        .session
        .with_vault(|vault| vault.answers_for_item(id))
        .expect("open")
        .expect("answers");
    assert!(answers.is_empty(), "{answers:?}");
    let text = frames(&mut app);
    assert!(
        !text.contains("Rules from your answers"),
        "Empty rules stay hidden: {text}"
    );
}

/// "Always ask me": on at once (stricter), off only after the owner check.
#[test]
fn always_ask_turns_on_at_once_and_off_after_the_owner_check() {
    use crate::desktop::owner_check::OwnerRequest;

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let id = add_item(&mut app, "Careful key");
    app.select_item(id.to_string());
    let always_ask = |app: &DesktopApp| {
        app.owner_ui
            .session
            .with_vault(|vault| vault.always_ask(id))
            .expect("open")
            .expect("read")
    };
    let details = app.owner_ui.session.details(id).expect("details");
    let ctx = egui::Context::default();
    super::items::set_always_ask(&mut app, &ctx, &details, true);
    assert!(app.owner.check.is_none(), "turning it on needs no check");
    assert!(always_ask(&app));

    super::items::set_always_ask(&mut app, &ctx, &details, false);
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        matches!(&check.request, OwnerRequest::AlwaysAskOff { item_id, .. } if *item_id == id),
        "{:?}",
        check.request
    );
    assert!(always_ask(&app), "still on before the check");
    app.confirm_owner_now(OwnerCheck::passphrase(PASS_A))
        .expect("owner check");
    assert!(!always_ask(&app));
}

/// "Is this a development key?" shows while only a default found the environment.
/// "Production" is stricter: no check. "Development" waits for the owner check. Each
/// answer counts as the owner's (the source "owner"), and the question goes away.
#[test]
fn the_development_key_question_and_its_answers() {
    use crate::desktop::owner_check::OwnerRequest;
    use crate::vault::{DeclarationSource, Environment};

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let first = paste(&mut app, &fake_key("sk-ant-api03-", 40));
    let second = paste(&mut app, &fake_key("sk-ant-api03-", 41));
    let state = |app: &DesktopApp, id: u64| {
        let declaration = app
            .owner_ui
            .session
            .declaration(id)
            .expect("read")
            .expect("declaration");
        let sources = app
            .owner_ui
            .session
            .with_vault(|vault| vault.declaration_sources(id))
            .expect("open")
            .expect("sources");
        (declaration.environment, sources.environment, sources.risk)
    };
    let (_, _, risk_before) = state(&app, first);

    app.select_item(first.to_string());
    app.ui
        .set_expanded(&format!("credential-agent-settings-{first}"), true);
    let text = frames(&mut app);
    assert!(text.contains("Is this a development key?"), "{text}");
    assert!(text.contains("api.anthropic.com"), "{text}");
    assert!(text.contains("Not confirmed"), "{text}");
    click_text(&mut app, "Production");
    assert!(
        app.owner.check.is_none(),
        "production is stricter: no check"
    );
    assert_eq!(
        state(&app, first),
        (
            Environment::Production,
            DeclarationSource::Owner,
            risk_before
        )
    );
    let text = frames(&mut app);
    assert!(!text.contains("Is this a development key?"), "{text}");
    assert!(text.contains("Production"), "the red cap: {text}");

    app.select_item(second.to_string());
    let text = frames(&mut app);
    assert!(text.contains("Is this a development key?"), "{text}");
    click_text(&mut app, "Development");
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        matches!(
            &check.request,
            OwnerRequest::SetEnvironment { item_id, environment: Environment::Development, .. }
                if *item_id == second
        ),
        "{:?}",
        check.request
    );
    assert_eq!(state(&app, second).1, DeclarationSource::Default);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS_A))
        .expect("owner check");
    let (environment, source, risk) = state(&app, second);
    assert_eq!(environment, Environment::Development);
    assert_eq!(source, DeclarationSource::Owner);
    assert_eq!(risk, risk_before, "the other sources stay");
    let text = frames(&mut app);
    assert!(!text.contains("Is this a development key?"), "{text}");
    assert!(text.contains("Development"), "{text}");

    // A login is no key: no question.
    let mut secrets = SecretForm::default();
    secrets.password = CANARY.to_owned();
    let login = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                kind: crate::contracts::CredentialKind::Login,
                name: "Router".to_owned(),
                username: "admin".to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add login")
        .id;
    app.select_item(login.to_string());
    let text = frames(&mut app);
    assert!(!text.contains("Is this a development key?"), "{text}");
}

/// A pasted credential has an empty project on purpose (ADR 0025 §4). Changing the
/// environment on the detail page changes only the environment and its source: the
/// project stays empty, and the folder name or title never stands in for it.
#[test]
fn changing_the_environment_keeps_the_pasted_project_empty() {
    use crate::desktop::owner_check::OwnerRequest;
    use crate::vault::{DeclarationSource, Environment};

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let first = paste(&mut app, &fake_key("sk-ant-api03-", 42));
    let second = paste(&mut app, &fake_key("sk-ant-api03-", 43));
    let read = |app: &DesktopApp, id: u64| {
        let declaration = app
            .owner_ui
            .session
            .declaration(id)
            .expect("read")
            .expect("declaration");
        let sources = app
            .owner_ui
            .session
            .with_vault(|vault| vault.declaration_sources(id))
            .expect("open")
            .expect("sources");
        (declaration, sources.environment)
    };
    let (before, _) = read(&app, first);
    assert!(before.project.is_empty(), "a pasted item has no project");

    app.select_item(first.to_string());
    frames(&mut app);
    click_text(&mut app, "Development");
    assert!(matches!(
        app.owner.check.as_ref().map(|check| &check.request),
        Some(OwnerRequest::SetEnvironment { .. })
    ));
    app.confirm_owner_now(OwnerCheck::passphrase(PASS_A))
        .expect("owner check");
    let (after, source) = read(&app, first);
    assert_eq!(after.environment, Environment::Development);
    assert_eq!(source, DeclarationSource::Owner);
    assert!(after.project.is_empty(), "the project stays empty");
    assert_eq!(
        (after.risk, after.scope, after.reversibility),
        (before.risk, before.scope, before.reversibility)
    );

    // Production needs no check and keeps the project empty as well.
    app.select_item(second.to_string());
    frames(&mut app);
    click_text(&mut app, "Production");
    assert!(app.owner.check.is_none());
    let (after, source) = read(&app, second);
    assert_eq!(after.environment, Environment::Production);
    assert_eq!(source, DeclarationSource::Owner);
    assert!(after.project.is_empty(), "the project stays empty");
}

/// Every variant of the credential page draws at the default and the minimum window
/// size, with the sidebar full and collapsed: a plain key, a pasted key with the
/// question, a production key, a login, a one-time password, an archived credential, a
/// credential with rules, uses, "Always ask me", and "Hosts and risk" open. No value
/// shows.
#[test]
fn every_variant_of_the_credential_page_draws_at_default_and_minimum_sizes() {
    use crate::broker::action_kind::ActionKind;
    use crate::vault::answers::ProjectRef;
    use crate::vault::exceptions::ExceptionKind;

    let dir = TempDir::new().expect("temp dir");
    let mut app = app_in(&dir);
    create(&mut app, "Personal", PASS_A);
    let plain = add_item(&mut app, "Plain key");
    let question = paste(&mut app, &fake_key("sk-ant-api03-", 40));
    let production = paste(
        &mut app,
        &format!("STRIPE_SECRET_KEY={}", fake_key("sk_live_", 24)),
    );
    let mut secrets = SecretForm::default();
    secrets.password = CANARY.to_owned();
    let login = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                kind: crate::contracts::CredentialKind::Login,
                name: "Router login".to_owned(),
                username: "admin".to_owned(),
                website: "https://router.example".to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add login")
        .id;
    let code = paste(
        &mut app,
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
    );
    let archived = add_item(&mut app, "Old key");
    app.owner_ui.session.archive(archived).expect("archive");
    let ruled = add_item(&mut app, "Ruled key");
    let agent = register(&mut app, "Claude Code");
    app.owner_ui
        .session
        .with_vault(|vault| -> crate::vault::VaultResult<()> {
            vault.add_agent_exception(agent, ruled, ExceptionKind::AlwaysAsk)?;
            let project = ProjectRef {
                key: "/synthetic/a-very-long-project-name-for-the-narrow-window".to_owned(),
                label: "a-very-long-project-name-for-the-narrow-window".to_owned(),
            };
            vault.remember_answer(ruled, &project, ActionKind::Deploy, "this Mac", &[])?;
            vault.set_always_ask(ruled, true)?;
            Ok(())
        })
        .expect("open")
        .expect("rules");
    for index in 0..5 {
        record_use(
            &mut app,
            ruled,
            agent,
            &format!("curl --silent https://api.example.com/v1/items/{index}"),
        );
    }
    app.ui
        .set_expanded(&format!("credential-agent-settings-{ruled}"), true);
    app.ui
        .set_expanded(&format!("credential-access-{ruled}"), true);
    app.ui
        .set_expanded(&format!("credential-uses-{ruled}"), true);

    let pages = [
        (plain, "Plain key"),
        (question, "Anthropic API key"),
        (production, "Stripe live"),
        (login, "Router login"),
        (code, "Example"),
        (archived, "Old key"),
        (ruled, "Ruled key"),
    ];
    for (id, name) in pages {
        for size in [Vec2::new(1180.0, 800.0), Vec2::new(900.0, 600.0)] {
            for collapsed in [false, true] {
                app.ui.sidebar_hidden = collapsed;
                app.select_item(id.to_string());
                let text = frames_at(&mut app, size);
                assert!(text.contains(name), "{name} at {size:?}: {text}");
                assert!(!text.contains(CANARY), "{name}: a value is visible");
                assert!(!text.contains("EXAMPLE0"), "{name}: a value is visible");
                assert!(
                    !text.contains("JBSWY3DPEHPK3PXP"),
                    "{name}: the seed is visible"
                );
            }
        }
    }
    app.ui.sidebar_hidden = false;
    app.select_item(ruled.to_string());
    app.ui
        .set_expanded(&format!("credential-agent-settings-{ruled}"), true);
    let text = frames(&mut app);
    for expected in ["Always ask me", "Agent use"] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
    app.select_item(production.to_string());
    let text = frames_at(&mut app, Vec2::new(1180.0, 800.0));
    assert!(text.contains("Production"), "{text}");
    assert!(!text.contains("Is this a development key?"), "{text}");
}

/// Settings > Vault says where a vault lives in short words: the place, and the last
/// two folders under it.
#[test]
fn the_vault_place_reads_in_short_words() {
    use super::vaults::short_location;
    let home = Path::new("/Users/synthetic");
    let data = home.join("Library/Application Support/Apassy");
    let place = |path: &Path| short_location(path, Some(home), &data);
    assert_eq!(place(&data.join("vault.db")), "On this Mac");
    assert_eq!(
        place(&home.join("Library/Mobile Documents/com~apple~CloudDocs/Apassy/vault.db")),
        "iCloud Drive › Apassy"
    );
    assert_eq!(
        place(&home.join("Library/CloudStorage/GoogleDrive-a@example.com/My Drive/Vaults/w.db")),
        "Google Drive › My Drive › Vaults"
    );
    assert_eq!(
        place(&home.join("Documents/a/b/c/v.db")),
        "Home › … › b › c"
    );
    assert_eq!(
        place(Path::new("/Volumes/Backup/Apassy/v.db")),
        "Backup › Apassy"
    );
    assert_eq!(place(Path::new("/srv/vaults/v.db")), "/srv/vaults");
}
