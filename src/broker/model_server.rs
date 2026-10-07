//! The local model server of the bouncer (ADR 0007, `docs/operations/bouncer.md`).
//!
//! - [`BouncerSettings`] is `bouncer.json` in the data directory: how Apassy starts the
//!   model server on this Mac. It is not in the vault. The default is
//!   [`StartMode::External`]: Apassy starts nothing, as before this setting.
//! - [`ModelServer`] starts and stops `tools/basemodel/start.sh` by that setting. It runs
//!   the slow work (start, health checks, the idle stop) on its own thread.
//! - [`ModelGate`] is the hook of the broker. The broker calls it just before it asks
//!   the active model. It never changes the decision policy: a model that does not
//!   answer makes the run wait for the owner, as before.
//! - "Install the model" in Settings runs the `uv` commands of section 1 on its own
//!   thread ([`ModelServer::install`]). Each command is an argument vector, never a shell.
//!   The last step downloads the Laya base weights with `tools/basemodel/fetch_weights.py`.
//! - Without the base weights in the Hugging Face cache ([`weights_cached`]), the first
//!   start downloads them. That start gets more time ([`FIRST_START_WAIT`]).
//! - [`scan_launch_agents`] finds a LaunchAgent that runs `tools/basemodel/start.sh`.
//!   Settings shows how to remove it. Apassy never changes a LaunchAgent.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::bouncer::{self, BouncerClient, DEFAULT_URL, Health};

/// The settings file in the data directory.
pub const SETTINGS_FILE: &str = "bouncer.json";
/// The reason in the activity log and on the approval card when the bouncer is off.
pub const OFF_REASON: &str = "The bouncer is off in Settings.";
/// How long a run waits for a server that starts for it. The first decision loads the
/// model: about 8 seconds on an M1 Pro.
pub const NEEDED_WAIT: Duration = Duration::from_secs(25);
/// How long a run waits for a first start that downloads the base weights (about
/// 800 MB). After that, the run waits for the owner, and the download goes on. With the
/// 120 s owner wait, the run must end within the 180 s tool time-out of the hosts
/// (`MCP_TOOL_TIMEOUT`, `tool_timeout_sec` in `src/cli/setup.rs`).
pub const FIRST_START_WAIT: Duration = Duration::from_secs(45);
/// The reason of a run that stopped waiting for the download of the base weights.
pub const DOWNLOAD_REASON: &str = "The model server downloads the model weights (first start only). This run waits for you. Later runs use the model.";
/// The Hugging Face repository of the Laya base weights. As `BASE_REPO` in
/// `tools/basemodel/common.py`.
pub const BASE_REPO: &str = "convaiinnovations/laya";
/// The pinned revision of the base weights. As `BASE_REVISION` in
/// `tools/basemodel/common.py`.
pub const BASE_REVISION: &str = "55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851";
/// The script next to `start.sh` that downloads the base weights.
pub const FETCH_SCRIPT: &str = "fetch_weights.py";
/// The label of the install step that downloads the base weights.
pub const FETCH_LABEL: &str = "Downloading the model weights";
/// The choices of "Stop after".
pub const IDLE_CHOICES: [u32; 3] = [10, 30, 60];
/// The default of "Stop after".
pub const DEFAULT_IDLE_MINUTES: u32 = 30;
/// After SIGTERM, the server has this long to stop before SIGKILL.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

const MAX_FILE_BYTES: u64 = 64 * 1024;
const CHECKPOINT: &str = "apassy-base-v1.safetensors";
/// A started server must answer the health check within this time.
const START_LIMIT: Duration = Duration::from_secs(180);
/// The same limit for a first start that downloads the base weights.
const FIRST_START_LIMIT: Duration = Duration::from_secs(30 * 60);
/// The first answer loads the model.
const WARM_UP_LIMIT: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const START_POLL: Duration = Duration::from_millis(250);
/// The monitor thread looks at the server this often.
const TICK: Duration = Duration::from_secs(2);
/// A server that Apassy did not start gets a health check this often.
const PROBE_EVERY: Duration = Duration::from_secs(10);
/// After a crash or a time-out, a run does not start the server again for this long.
const RETRY_AFTER: Duration = Duration::from_secs(60);
/// The log starts again when it is larger than this.
const MAX_LOG_BYTES: u64 = 1024 * 1024;
const LOG_TAIL_LINES: usize = 6;
/// The install log, next to `bouncer.log`.
pub const INSTALL_LOG: &str = "bouncer-install.log";
/// The Laya package of `docs/operations/bouncer.md` section 1.
pub const LAYA_PACKAGE: &str = "laya[serve]==0.3.20";
/// The note when Apassy cannot find `uv`.
pub const UV_MISSING: &str = "Install uv first: brew install uv";
/// The install thread looks at `uv` this often.
const INSTALL_POLL: Duration = Duration::from_millis(200);
const INSTALL_TAIL_LINES: usize = 8;
/// Apassy reads the LaunchAgents again after this time.
const AGENT_SCAN_EVERY: Duration = Duration::from_secs(60);
const MAX_PLIST_BYTES: u64 = 256 * 1024;
/// A LaunchAgent with this text in its program arguments starts the bouncer.
const START_SCRIPT: &str = "tools/basemodel/start.sh";

/// How Apassy starts the model server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartMode {
    /// Start when Apassy starts, stop when Apassy quits.
    WithApassy,
    /// Start on the first run that needs the model, stop after the idle time.
    WhenNeeded,
    /// Apassy starts and stops nothing. It only uses the address.
    #[default]
    External,
    /// The broker asks no model. Every run that needs it waits for the owner.
    Off,
}

impl StartMode {
    pub const ALL: [Self; 4] = [
        Self::WithApassy,
        Self::WhenNeeded,
        Self::External,
        Self::Off,
    ];

    /// The label in Settings > Agents.
    pub fn label(self) -> &'static str {
        match self {
            Self::WithApassy => "With Apassy",
            Self::WhenNeeded => "When a run needs it",
            Self::External => "Managed outside Apassy",
            Self::Off => "Off",
        }
    }

    /// Apassy starts and stops the server in this mode.
    pub fn managed(self) -> bool {
        matches!(self, Self::WithApassy | Self::WhenNeeded)
    }
}

/// The content of `bouncer.json`. A missing field takes its default. A damaged file
/// gives the defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BouncerSettings {
    pub start: StartMode,
    /// Minutes without a run before the idle stop, in [`StartMode::WhenNeeded`].
    pub idle_minutes: u32,
    /// The address. `None` is [`DEFAULT_URL`]. `APASSY_BOUNCER_URL` wins over it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl Default for BouncerSettings {
    fn default() -> Self {
        Self {
            start: StartMode::External,
            idle_minutes: DEFAULT_IDLE_MINUTES,
            url: None,
        }
    }
}

/// Check an address for the bouncer: a loopback `http://` address, as the client
/// requires ([`BouncerClient::new`]).
pub fn validate_url(url: &str) -> Result<String, &'static str> {
    BouncerClient::new(url).map(|client| client.url().to_owned())
}

impl BouncerSettings {
    /// Read `path`. A missing, large, or damaged file gives the defaults. An idle time
    /// that is not a choice gives the default, and an address that is not a loopback
    /// `http://` address gives the default address.
    pub fn load(path: &Path) -> Self {
        let Ok(file) = fs::File::open(path) else {
            return Self::default();
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_FILE_BYTES
        {
            return Self::default();
        }
        let mut settings: Self = serde_json::from_slice(&bytes).unwrap_or_default();
        if !IDLE_CHOICES.contains(&settings.idle_minutes) {
            settings.idle_minutes = DEFAULT_IDLE_MINUTES;
        }
        settings.url = settings
            .url
            .as_deref()
            .filter(|url| !url.trim().is_empty())
            .and_then(|url| validate_url(url).ok());
        settings
    }

    /// Write `path` atomically with mode 0600: a temporary file in the same folder,
    /// synced, then renamed over the old file.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        private_dir(&dir)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let mut temp = tempfile::Builder::new()
            .prefix(".bouncer.json.")
            .tempfile_in(&dir)?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;
        temp.write_all(&bytes)?;
        temp.write_all(b"\n")?;
        temp.as_file().sync_all()?;
        temp.persist(path).map_err(|err| err.error)?;
        Ok(())
    }

    /// The address from the file, or the default address.
    pub fn file_url(&self) -> &str {
        self.url.as_deref().unwrap_or(DEFAULT_URL)
    }

    pub fn idle(&self) -> Duration {
        Duration::from_secs(u64::from(self.idle_minutes) * 60)
    }
}

/// Make `dir` with mode 0700 when it does not exist.
fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Where the start script, the Laya environment, the checkpoint, and the log are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// `tools/basemodel/start.sh`. `None` when Apassy cannot find it.
    pub script: Option<PathBuf>,
    /// `$APASSY_LAYA_DIR`, by default `<data dir>/laya`.
    pub laya_dir: PathBuf,
    /// The checkpoint candidates in the order of `start.sh`.
    pub checkpoints: Vec<PathBuf>,
    /// `~/Library/Logs/Apassy/bouncer.log`.
    pub log: PathBuf,
}

impl Layout {
    /// The layout of this Mac: the script next to the app, else in the repository when
    /// Apassy runs from `target/`.
    pub fn discover() -> Self {
        let exe = std::env::current_exe().ok();
        let laya_dir = std::env::var_os("APASSY_LAYA_DIR")
            .filter(|dir| !dir.is_empty())
            .map_or_else(|| crate::paths::data_dir().join("laya"), PathBuf::from);
        let mut checkpoints: Vec<PathBuf> = std::env::var_os("APASSY_BASE_MODEL")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .into_iter()
            .collect();
        checkpoints.push(laya_dir.join("models").join(CHECKPOINT));
        if let Some(resources) = exe.as_deref().and_then(bundle_resources) {
            checkpoints.push(resources.join("models").join(CHECKPOINT));
        }
        let installed =
            PathBuf::from("/Applications/Apassy.app/Contents/Resources/models").join(CHECKPOINT);
        if !checkpoints.contains(&installed) {
            checkpoints.push(installed);
        }
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
        Self {
            script: exe.as_deref().and_then(find_script),
            laya_dir,
            checkpoints,
            log: home
                .join("Library")
                .join("Logs")
                .join("Apassy")
                .join("bouncer.log"),
        }
    }

    pub fn python(&self) -> PathBuf {
        self.laya_dir.join(".venv").join("bin").join("python")
    }

    pub fn laya_serve(&self) -> PathBuf {
        self.laya_dir.join(".venv").join("bin").join("laya-serve")
    }

    /// The Laya environment has `python` and `laya-serve`.
    pub fn venv_ready(&self) -> bool {
        self.python().is_file() && self.laya_serve().is_file()
    }

    /// `~/Library/Logs/Apassy/bouncer-install.log`, next to the server log.
    pub fn install_log(&self) -> PathBuf {
        self.log.with_file_name(INSTALL_LOG)
    }

    /// `requirements.txt` next to the start script, when it exists.
    pub fn requirements(&self) -> Option<PathBuf> {
        self.script
            .as_deref()
            .and_then(Path::parent)
            .map(|dir| dir.join("requirements.txt"))
            .filter(|path| path.is_file())
    }

    /// `fetch_weights.py` next to the start script, when it exists.
    pub fn fetch_script(&self) -> Option<PathBuf> {
        self.script
            .as_deref()
            .and_then(Path::parent)
            .map(|dir| dir.join(FETCH_SCRIPT))
            .filter(|path| path.is_file())
    }

    /// A checkpoint exists, so `start.sh` runs the base model, not the zero-shot model.
    pub fn has_checkpoint(&self) -> bool {
        self.checkpoints.iter().any(|path| path.is_file())
    }
}

/// The Hugging Face hub cache that the server and `fetch_weights.py` use:
/// `HF_HUB_CACHE`, else `HF_HOME/hub`, else `~/.cache/huggingface/hub`. Both get only
/// `HOME` and the `HF_` variables of Apassy, so other variables do not count.
pub fn hf_hub_cache(
    home: Option<&Path>,
    hub_cache: Option<&OsStr>,
    hf_home: Option<&OsStr>,
) -> Option<PathBuf> {
    let set = |value: Option<&OsStr>| value.filter(|value| !value.is_empty()).map(PathBuf::from);
    set(hub_cache)
        .or_else(|| set(hf_home).map(|dir| dir.join("hub")))
        .or_else(|| home.map(|home| home.join(".cache").join("huggingface").join("hub")))
}

/// The base weights are in the hub cache `hub`: `model.safetensors` and
/// `rl_agent_config.json` of the pinned revision. The zero-shot `laya-serve` does not pin
/// a revision, so for it the snapshot of `refs/main` also counts.
pub fn weights_cached(hub: &Path, zero_shot: bool) -> bool {
    let repo = hub.join(format!("models--{}", BASE_REPO.replace('/', "--")));
    let complete = |revision: &str| {
        let snapshot = repo.join("snapshots").join(revision);
        snapshot.join("model.safetensors").is_file()
            && snapshot.join("rl_agent_config.json").is_file()
    };
    if complete(BASE_REVISION) {
        return true;
    }
    zero_shot
        && fs::read_to_string(repo.join("refs").join("main")).is_ok_and(|main| {
            let main = main.trim();
            !main.is_empty() && !main.contains(['/', '.']) && complete(main)
        })
}

/// Where the install looks for `uv`, and where the LaunchAgents are. Tests use
/// temporary folders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The folders that can have `uv`, in the order of the search.
    pub uv_dirs: Vec<PathBuf>,
    /// `~/Library/LaunchAgents`. `None`: Apassy checks no LaunchAgent.
    pub launch_agents: Option<PathBuf>,
    /// The Hugging Face hub cache ([`hf_hub_cache`]). `None`: Apassy does not check the
    /// base weights, and they count as there.
    pub hf_cache: Option<PathBuf>,
}

impl Host {
    /// The folders of this Mac.
    pub fn discover() -> Self {
        let home = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from);
        Self {
            uv_dirs: uv_dirs(home.as_deref(), std::env::var_os("PATH").as_deref()),
            hf_cache: hf_hub_cache(
                home.as_deref(),
                std::env::var_os("HF_HUB_CACHE").as_deref(),
                std::env::var_os("HF_HOME").as_deref(),
            ),
            launch_agents: home.map(|home| home.join("Library").join("LaunchAgents")),
        }
    }

    /// No `uv`, no LaunchAgent, and no check of the base weights.
    pub fn none() -> Self {
        Self {
            uv_dirs: Vec::new(),
            launch_agents: None,
            hf_cache: None,
        }
    }
}

/// The folders that can have `uv`: Homebrew, the uv installer, Cargo, then `PATH`. A
/// relative folder of `PATH` is skipped.
pub fn uv_dirs(home: Option<&Path>, path: Option<&OsStr>) -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ];
    if let Some(home) = home {
        dirs.push(home.join(".local").join("bin"));
        dirs.push(home.join(".cargo").join("bin"));
    }
    for dir in path.map(std::env::split_paths).into_iter().flatten() {
        if dir.is_absolute() && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// The first executable `uv` in `dirs`.
pub fn find_uv(dirs: &[PathBuf]) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    dirs.iter().map(|dir| dir.join("uv")).find(|uv| {
        fs::metadata(uv).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    })
}

/// `Contents/Resources` of the app bundle when `exe` is `Contents/MacOS/<name>`.
fn bundle_resources(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    if macos.file_name()? != "MacOS" {
        return None;
    }
    Some(macos.parent()?.join("Resources"))
}

/// The start script for `exe`: `Contents/Resources/tools/basemodel/start.sh` of the app
/// bundle, else `<repository>/tools/basemodel/start.sh` when `exe` is in `target/`.
pub fn find_script(exe: &Path) -> Option<PathBuf> {
    let relative = Path::new("tools").join("basemodel").join("start.sh");
    if let Some(resources) = bundle_resources(exe) {
        let script = resources.join(&relative);
        if script.is_file() {
            return Some(script);
        }
    }
    exe.ancestors()
        .find(|dir| dir.file_name().is_some_and(|name| name == "target"))
        .and_then(Path::parent)
        .map(|repo| repo.join(&relative))
        .filter(|script| script.is_file())
}

/// Why the server does not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// Apassy cannot find `tools/basemodel/start.sh`.
    NoScript,
    /// The Laya environment is missing: `program` does not exist.
    NoVenv { program: PathBuf },
    /// Another program uses the port and does not answer the health check.
    PortTaken { port: u16 },
    /// The address is not a loopback `http://` address.
    BadUrl(&'static str),
    /// Apassy could not start the script.
    Spawn(String),
    /// The server stopped by itself.
    Exited(String),
    /// The server did not answer in time.
    NoAnswer(Duration),
}

impl Problem {
    /// A missing file that the owner must install. A run does not wait for it.
    pub fn is_setup(&self) -> bool {
        matches!(self, Self::NoScript | Self::NoVenv { .. } | Self::BadUrl(_))
    }

    pub fn text(&self) -> String {
        match self {
            Self::NoScript => {
                "Apassy cannot find the start script tools/basemodel/start.sh.".to_owned()
            }
            Self::NoVenv { program } => format!(
                "The Laya environment is missing: {} does not exist.",
                program.display()
            ),
            Self::PortTaken { port } => {
                format!("Another program uses port {port} and does not answer as a bouncer.")
            }
            Self::BadUrl(reason) => (*reason).to_owned(),
            Self::Spawn(err) => format!("The model server did not start: {err}."),
            Self::Exited(status) => format!("The model server stopped ({status}). See the log."),
            Self::NoAnswer(limit) => format!(
                "The model server did not answer within {} seconds. See the log.",
                limit.as_secs()
            ),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

/// What `start.sh` runs, after the preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub script: PathBuf,
    pub laya_dir: PathBuf,
    /// `None`: no checkpoint, so `start.sh` runs the zero-shot `laya-serve`.
    pub checkpoint: Option<PathBuf>,
}

/// Check that the server can start: the script, the Laya environment, and the
/// checkpoint. No checkpoint is allowed: then the model is zero-shot.
pub fn preflight(layout: &Layout) -> Result<Ready, Problem> {
    let script = layout.script.clone().ok_or(Problem::NoScript)?;
    let checkpoint = layout
        .checkpoints
        .iter()
        .find(|path| path.is_file())
        .cloned();
    let program = if checkpoint.is_some() {
        layout.python()
    } else {
        layout.laya_serve()
    };
    for needed in [layout.python(), program] {
        if !needed.is_file() {
            return Err(Problem::NoVenv { program: needed });
        }
    }
    Ok(Ready {
        script,
        laya_dir: layout.laya_dir.clone(),
        checkpoint,
    })
}

/// The idle stop rule: only in [`StartMode::WhenNeeded`], only a running server that
/// Apassy started, and only after `idle` without a run.
pub fn idle_stop_due(
    mode: StartMode,
    started_by_apassy: bool,
    running: bool,
    last_use: Instant,
    now: Instant,
    idle: Duration,
) -> bool {
    mode == StartMode::WhenNeeded
        && started_by_apassy
        && running
        && now.saturating_duration_since(last_use) >= idle
}

/// The state of the model server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerState {
    /// The broker asks no model.
    Off,
    /// Managed outside Apassy. `up` is `None` before the first health check.
    External {
        up: Option<bool>,
        model: Option<String>,
    },
    Stopped,
    Starting {
        since: Instant,
    },
    Running {
        /// The model version from the `model` field of an answer.
        model: Option<String>,
        /// A server that already answered on the port, for example a LaunchAgent.
        /// Apassy does not stop it.
        outside: bool,
    },
    Failed {
        problem: Problem,
        /// The last lines of the log.
        log_tail: Vec<String>,
    },
}

/// What Settings shows.
#[derive(Debug, Clone)]
pub struct Status {
    pub settings: BouncerSettings,
    pub state: ServerState,
    pub preflight: Result<Ready, Problem>,
    /// The address that the broker uses.
    pub url: String,
    /// `APASSY_BOUNCER_URL` sets the address.
    pub url_from_env: bool,
    pub log: PathBuf,
    pub laya_dir: PathBuf,
    /// The folder of `start.sh`, for the install commands.
    pub script_dir: Option<PathBuf>,
    /// Apassy started the server that runs or starts now.
    pub owned: bool,
    /// The Laya environment has `python` and `laya-serve`.
    pub venv_ready: bool,
    /// `uv` for "Install the model". Apassy looks for it only while the environment is
    /// missing or after a failed install.
    pub uv: Option<PathBuf>,
    /// The arguments of `uv venv` for the Terminal commands. `None`: the environment
    /// has a Python.
    pub venv_args: Option<&'static [&'static str]>,
    pub install: InstallState,
    pub install_log: PathBuf,
    /// The LaunchAgents that run `tools/basemodel/start.sh`.
    pub launch_agents: Vec<LaunchAgent>,
    /// The base weights are in the Hugging Face cache, or Apassy does not check them.
    /// `false`: the next start downloads them.
    pub weights_cached: bool,
}

/// The hook of the broker before it asks the active model.
pub trait ModelGate: fmt::Debug + Send + Sync {
    /// `Ok`: ask the model. `Err(reason)`: do not ask it; the run waits for the owner
    /// with this reason.
    fn before_model(&self) -> Result<(), String>;
}

#[derive(Debug)]
struct Inner {
    settings: BouncerSettings,
    state: ServerState,
    /// The server that Apassy started.
    child: Option<Child>,
    preflight: Result<Ready, Problem>,
    last_use: Instant,
    last_failure: Option<Instant>,
    last_probe: Option<Instant>,
    /// A start waits for the monitor thread.
    launch: bool,
    /// A run already waited [`Timing::first_start_wait`] for the start in progress,
    /// which downloads the base weights. Later runs do not wait for it.
    first_start_waited: bool,
    /// Grows with each stop and each change of the mode. A start in progress for an
    /// older generation stops.
    generation: u64,
    quit: bool,
    /// The LaunchAgents that run `start.sh`, from the last scan.
    agents: Vec<LaunchAgent>,
    agents_scanned: Option<Instant>,
}

/// The install of the Laya environment. It has its own lock.
#[derive(Debug, Default)]
struct Installer {
    state: InstallState,
    /// The process of the current step: `uv` or the Python of the environment.
    child: Option<Child>,
    /// Grows with each install and each cancel. An older install thread stops.
    generation: u64,
}

enum Job {
    Launch(u64),
    Probe(u64),
    Stop(Child),
}

/// Time limits that tests make short.
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// `None`: "Stop after" of the settings.
    idle: Option<Duration>,
    /// How long a run waits for a first start that downloads the base weights.
    first_start_wait: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            idle: None,
            first_start_wait: FIRST_START_WAIT,
        }
    }
}

/// The supervisor of the model server. Share it with [`Arc`]. Each method takes the
/// lock only for a short time. No lock is held during a health check or a stop.
#[derive(Debug)]
pub struct ModelServer {
    inner: Mutex<Inner>,
    wake: Condvar,
    layout: Layout,
    settings_path: Option<PathBuf>,
    client: Result<BouncerClient, &'static str>,
    url_from_env: bool,
    host: Host,
    installer: Mutex<Installer>,
    timing: Timing,
}

impl ModelServer {
    /// The supervisor of this Mac: `<data dir>/bouncer.json` and [`Layout::discover`].
    pub fn start_default() -> Arc<Self> {
        Self::start(
            Some(crate::paths::data_dir().join(SETTINGS_FILE)),
            Layout::discover(),
        )
    }

    /// Read the settings at `settings_path` (`None`: the defaults, never saved) and start
    /// the monitor thread. In [`StartMode::WithApassy`] the server starts now.
    pub fn start(settings_path: Option<PathBuf>, layout: Layout) -> Arc<Self> {
        let settings = settings_path
            .as_deref()
            .map(BouncerSettings::load)
            .unwrap_or_default();
        Self::start_with(settings_path, settings, layout)
    }

    /// As [`ModelServer::start`] with the given settings.
    pub fn start_with(
        settings_path: Option<PathBuf>,
        settings: BouncerSettings,
        layout: Layout,
    ) -> Arc<Self> {
        Self::start_with_host(settings_path, settings, layout, Host::discover())
    }

    /// As [`ModelServer::start_with`] with the given folders for `uv` and the
    /// LaunchAgents.
    pub fn start_with_host(
        settings_path: Option<PathBuf>,
        settings: BouncerSettings,
        layout: Layout,
        host: Host,
    ) -> Arc<Self> {
        Self::start_timed(settings_path, settings, layout, host, Timing::default())
    }

    /// As [`ModelServer::start_with_host`] with a short idle stop (`idle`, instead of
    /// "Stop after") and a short wait for a start that downloads the base weights.
    #[cfg(test)]
    pub(crate) fn start_for_test(
        settings: BouncerSettings,
        layout: Layout,
        host: Host,
        idle: Option<Duration>,
        first_start_wait: Duration,
    ) -> Arc<Self> {
        Self::start_timed(
            None,
            settings,
            layout,
            host,
            Timing {
                idle,
                first_start_wait,
            },
        )
    }

    fn start_timed(
        settings_path: Option<PathBuf>,
        settings: BouncerSettings,
        layout: Layout,
        host: Host,
        timing: Timing,
    ) -> Arc<Self> {
        let client = BouncerClient::from_env_or(settings.file_url());
        let now = Instant::now();
        let preflight = preflight(&layout);
        let launch = settings.start == StartMode::WithApassy;
        let state = match settings.start {
            StartMode::WithApassy => ServerState::Starting { since: now },
            mode => base_state(mode),
        };
        let server = Arc::new(Self {
            inner: Mutex::new(Inner {
                settings,
                state,
                child: None,
                preflight,
                last_use: now,
                last_failure: None,
                last_probe: None,
                launch,
                first_start_waited: false,
                generation: 0,
                quit: false,
                agents: Vec::new(),
                agents_scanned: None,
            }),
            wake: Condvar::new(),
            layout,
            settings_path,
            client,
            url_from_env: bouncer::env_url().is_some(),
            host,
            installer: Mutex::new(Installer::default()),
            timing,
        });
        let monitor = Arc::clone(&server);
        let spawned = thread::Builder::new()
            .name("apassy-model-server".to_owned())
            .spawn(move || monitor.monitor());
        if let Err(err) = spawned {
            let mut inner = server.lock();
            inner.launch = false;
            inner.state = ServerState::Failed {
                problem: Problem::Spawn(err.to_string()),
                log_tail: Vec::new(),
            };
        }
        server
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn installer(&self) -> MutexGuard<'_, Installer> {
        self.installer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The client for the address of the settings (`APASSY_BOUNCER_URL` wins).
    pub fn client(&self) -> Result<BouncerClient, &'static str> {
        self.client.clone()
    }

    pub fn settings(&self) -> BouncerSettings {
        self.lock().settings.clone()
    }

    pub fn state(&self) -> ServerState {
        self.lock().state.clone()
    }

    pub fn status(&self) -> Status {
        let install = self.installer().state.clone();
        let venv_ready = self.layout.venv_ready();
        // A failed install can be tried again, also when only the weights failed.
        let uv = if venv_ready && !matches!(install, InstallState::Failed { .. }) {
            None
        } else {
            find_uv(&self.host.uv_dirs)
        };
        let venv = venv_args(&self.layout.laya_dir);
        let weights_cached = self.weights_ready();
        let inner = self.lock();
        Status {
            settings: inner.settings.clone(),
            state: inner.state.clone(),
            preflight: inner.preflight.clone(),
            url: self.client.as_ref().map_or_else(
                |_| inner.settings.file_url().to_owned(),
                |client| client.url().to_owned(),
            ),
            url_from_env: self.url_from_env,
            log: self.layout.log.clone(),
            laya_dir: self.layout.laya_dir.clone(),
            script_dir: self
                .layout
                .script
                .as_deref()
                .and_then(Path::parent)
                .map(Path::to_path_buf),
            owned: inner.child.is_some(),
            venv_ready,
            uv,
            venv_args: venv,
            install,
            install_log: self.layout.install_log(),
            launch_agents: inner.agents.clone(),
            weights_cached,
        }
    }

    /// The base weights are in the Hugging Face cache, or Apassy does not check them.
    fn weights_ready(&self) -> bool {
        self.host
            .hf_cache
            .as_deref()
            .is_none_or(|hub| weights_cached(hub, !self.layout.has_checkpoint()))
    }

    /// Save and apply new settings. A change to "Managed outside Apassy" or "Off" stops a
    /// server that Apassy started. The stop runs on its own thread.
    pub fn set_settings(&self, settings: BouncerSettings) -> io::Result<()> {
        if let Some(path) = &self.settings_path {
            settings.save(path)?;
        }
        let child = {
            let mut inner = self.lock();
            let old = inner.settings.start;
            inner.settings = settings;
            let mode = inner.settings.start;
            let child = if mode.managed() {
                None
            } else {
                let child = Self::take_for_stop(&mut inner);
                inner.state = base_state(mode);
                inner.last_probe = None;
                child
            };
            let active = matches!(
                inner.state,
                ServerState::Running { .. } | ServerState::Starting { .. }
            );
            if mode == StartMode::WithApassy && !active {
                Self::request_launch(&mut inner);
            } else if mode == StartMode::WhenNeeded && !old.managed() {
                inner.state = ServerState::Stopped;
            }
            inner.last_use = Instant::now();
            child
        };
        self.wake.notify_all();
        if let Some(child) = child {
            stop_in_background(child);
        }
        Ok(())
    }

    /// "Start now" in Settings. It returns at once.
    pub fn start_now(&self) {
        {
            let mut inner = self.lock();
            if !inner.settings.start.managed()
                || matches!(
                    inner.state,
                    ServerState::Running { .. } | ServerState::Starting { .. }
                )
            {
                return;
            }
            inner.last_use = Instant::now();
            inner.last_failure = None;
            Self::request_launch(&mut inner);
        }
        self.wake.notify_all();
    }

    /// "Stop" in Settings: stop the server that Apassy started. It returns at once.
    pub fn stop(&self) {
        let child = {
            let mut inner = self.lock();
            let child = Self::take_for_stop(&mut inner);
            inner.state = base_state(inner.settings.start);
            child
        };
        self.wake.notify_all();
        if let Some(child) = child {
            stop_in_background(child);
        }
    }

    /// Quit: stop the monitor and the server that Apassy started. This waits for the
    /// server to stop (at most [`STOP_GRACE`] and the SIGKILL).
    pub fn shutdown(&self) {
        let child = {
            let mut inner = self.lock();
            inner.quit = true;
            Self::take_for_stop(&mut inner)
        };
        self.wake.notify_all();
        let install = {
            let mut installer = self.installer();
            installer.generation += 1;
            installer.child.take()
        };
        for child in [child, install].into_iter().flatten() {
            terminate(child, STOP_GRACE);
        }
    }

    /// In [`StartMode::WhenNeeded`], start the server if it does not run, and wait up to
    /// `timeout` for it. No lock is held while the server starts.
    pub fn ensure_running(&self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut inner = self.lock();
        inner.last_use = Instant::now();
        match &inner.state {
            ServerState::Running { .. } => return Ok(()),
            ServerState::Off => return Err(OFF_REASON.to_owned()),
            ServerState::External { .. } => return Ok(()),
            ServerState::Starting { .. } => {}
            ServerState::Stopped | ServerState::Failed { .. } => {
                if !inner.settings.start.managed() {
                    return Ok(());
                }
                if let ServerState::Failed { problem, .. } = &inner.state
                    && !problem.is_setup()
                    && inner
                        .last_failure
                        .is_some_and(|at| at.elapsed() < RETRY_AFTER)
                {
                    return Err(problem.text());
                }
                Self::request_launch(&mut inner);
                self.wake.notify_all();
            }
        }
        loop {
            match &inner.state {
                ServerState::Running { .. } => return Ok(()),
                ServerState::Failed { problem, .. } => return Err(problem.text()),
                ServerState::Starting { .. } => {}
                _ => return Err("the model server stopped".to_owned()),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "the model server did not answer within {} seconds",
                    timeout.as_secs()
                ));
            }
            inner = self
                .wake
                .wait_timeout(inner, deadline - now)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    fn request_launch(inner: &mut Inner) {
        inner.launch = true;
        inner.first_start_waited = false;
        inner.state = ServerState::Starting {
            since: Instant::now(),
        };
    }

    /// Take the server that Apassy started, and end a start in progress.
    fn take_for_stop(inner: &mut Inner) -> Option<Child> {
        inner.generation += 1;
        inner.launch = false;
        inner.child.take()
    }

    fn fail(&self, inner: &mut Inner, problem: Problem) {
        inner.last_failure = Some(Instant::now());
        inner.state = ServerState::Failed {
            log_tail: if problem.is_setup() {
                Vec::new()
            } else {
                log_tail(&self.layout.log, LOG_TAIL_LINES)
            },
            problem,
        };
    }

    fn monitor(&self) {
        loop {
            self.scan_agents_when_due();
            let job = {
                let mut inner = self.lock();
                if inner.quit {
                    return;
                }
                self.next_job(&mut inner)
            };
            self.wake.notify_all();
            match job {
                Some(Job::Launch(generation)) => self.launch(generation),
                Some(Job::Probe(generation)) => self.probe(generation),
                Some(Job::Stop(child)) => terminate(child, STOP_GRACE),
                None => {}
            }
            // A run in `ensure_running` waits for the result of a start.
            self.wake.notify_all();
            let inner = self.lock();
            if inner.quit {
                return;
            }
            if !inner.launch {
                drop(
                    self.wake
                        .wait_timeout(inner, TICK)
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
            }
        }
    }

    fn next_job(&self, inner: &mut Inner) -> Option<Job> {
        let now = Instant::now();
        inner.preflight = preflight(&self.layout);
        if inner.launch {
            inner.launch = false;
            return Some(Job::Launch(inner.generation));
        }
        if let Some(child) = inner.child.as_mut()
            && let Ok(Some(status)) = child.try_wait()
        {
            inner.child = None;
            self.fail(inner, Problem::Exited(status.to_string()));
            return None;
        }
        let running = matches!(inner.state, ServerState::Running { outside: false, .. });
        if idle_stop_due(
            inner.settings.start,
            inner.child.is_some(),
            running,
            inner.last_use,
            now,
            self.timing.idle.unwrap_or_else(|| inner.settings.idle()),
        ) {
            let child = Self::take_for_stop(inner);
            inner.state = ServerState::Stopped;
            return child.map(Job::Stop);
        }
        let probe = matches!(
            inner.state,
            ServerState::External { .. } | ServerState::Running { outside: true, .. }
        );
        if probe
            && inner
                .last_probe
                .is_none_or(|at| now.saturating_duration_since(at) >= PROBE_EVERY)
        {
            inner.last_probe = Some(now);
            return Some(Job::Probe(inner.generation));
        }
        None
    }

    /// The health check of a server that Apassy did not start.
    fn probe(&self, generation: u64) {
        let Ok(client) = &self.client else {
            return;
        };
        let up = client.probe_health(PROBE_TIMEOUT) == Health::Healthy;
        let needs_model = {
            let inner = self.lock();
            matches!(inner.state, ServerState::External { model: None, .. })
        };
        // The version needs one answer. It also loads the model, so the first run is fast.
        let model = if up && needs_model {
            client.warm_up(WARM_UP_LIMIT).ok().flatten()
        } else {
            None
        };
        let mut inner = self.lock();
        if inner.generation != generation {
            return;
        }
        match &mut inner.state {
            ServerState::External {
                up: known,
                model: version,
            } => {
                *known = Some(up);
                if !up {
                    *version = None;
                } else if model.is_some() {
                    *version = model;
                }
            }
            ServerState::Running { outside: true, .. } if !up => {
                inner.state = ServerState::Stopped;
            }
            _ => {}
        }
    }

    /// Start the server: the preflight, the port, the script, the health check, and the
    /// first answer. It runs on the monitor thread.
    fn launch(&self, generation: u64) {
        let current = |inner: &Inner| inner.generation == generation && !inner.quit;
        let client = match &self.client {
            Ok(client) => client.clone(),
            Err(reason) => {
                let mut inner = self.lock();
                if current(&inner) {
                    self.fail(&mut inner, Problem::BadUrl(reason));
                }
                return;
            }
        };
        let ready = match preflight(&self.layout) {
            Ok(ready) => ready,
            Err(problem) => {
                let mut inner = self.lock();
                if current(&inner) {
                    self.fail(&mut inner, problem);
                }
                return;
            }
        };
        let port = client.port().unwrap_or(8770);
        match client.probe_health(PROBE_TIMEOUT) {
            Health::Healthy => {
                let model = client.warm_up(WARM_UP_LIMIT).ok().flatten();
                let mut inner = self.lock();
                if current(&inner) {
                    inner.state = ServerState::Running {
                        model,
                        outside: true,
                    };
                    inner.last_probe = Some(Instant::now());
                }
                return;
            }
            Health::NotBouncer => {
                let mut inner = self.lock();
                if current(&inner) {
                    self.fail(&mut inner, Problem::PortTaken { port });
                }
                return;
            }
            Health::NoServer => {}
        }
        // A first start downloads the base weights before it answers.
        let limit = if self.weights_ready() {
            START_LIMIT
        } else {
            FIRST_START_LIMIT
        };
        let child = match spawn_server(&ready, port, client.api_key(), &self.layout.log) {
            Ok(child) => child,
            Err(err) => {
                let mut inner = self.lock();
                if current(&inner) {
                    self.fail(&mut inner, Problem::Spawn(err.to_string()));
                }
                return;
            }
        };
        let since = Instant::now();
        {
            let mut inner = self.lock();
            if !current(&inner) {
                drop(inner);
                terminate(child, STOP_GRACE);
                return;
            }
            inner.child = Some(child);
            inner.state = ServerState::Starting { since };
        }
        self.wake.notify_all();
        loop {
            thread::sleep(START_POLL);
            {
                let mut inner = self.lock();
                if !current(&inner) {
                    return;
                }
                let exited = inner
                    .child
                    .as_mut()
                    .map(|child| child.try_wait().ok().flatten());
                match exited {
                    None => return,
                    Some(Some(status)) => {
                        inner.child = None;
                        self.fail(&mut inner, Problem::Exited(status.to_string()));
                        drop(inner);
                        self.wake.notify_all();
                        return;
                    }
                    Some(None) => {}
                }
                if since.elapsed() >= limit {
                    let child = Self::take_for_stop(&mut inner);
                    self.fail(&mut inner, Problem::NoAnswer(limit));
                    drop(inner);
                    self.wake.notify_all();
                    if let Some(child) = child {
                        terminate(child, STOP_GRACE);
                    }
                    return;
                }
            }
            if client.probe_health(PROBE_TIMEOUT) == Health::Healthy {
                break;
            }
        }
        let model = client.warm_up(WARM_UP_LIMIT).ok().flatten();
        let mut inner = self.lock();
        if current(&inner) && inner.child.is_some() {
            inner.state = ServerState::Running {
                model,
                outside: false,
            };
        }
    }
}

impl ModelGate for ModelServer {
    fn before_model(&self) -> Result<(), String> {
        let mode = {
            let mut inner = self.lock();
            inner.last_use = Instant::now();
            inner.settings.start
        };
        match mode {
            StartMode::Off => Err(OFF_REASON.to_owned()),
            StartMode::WhenNeeded if self.weights_ready() => self.ensure_running(NEEDED_WAIT),
            StartMode::WhenNeeded => self.ensure_first_start(),
            StartMode::WithApassy | StartMode::External => Ok(()),
        }
    }
}

impl ModelServer {
    /// "When a run needs it" without the base weights: the start downloads them. One
    /// run waits up to [`Timing::first_start_wait`]. If the server still starts, that
    /// run and the runs after it wait for the owner with [`DOWNLOAD_REASON`] until the
    /// download ends. The download goes on.
    fn ensure_first_start(&self) -> Result<(), String> {
        let downloading = |inner: &Inner| matches!(inner.state, ServerState::Starting { .. });
        {
            let inner = self.lock();
            if inner.first_start_waited && downloading(&inner) {
                return Err(DOWNLOAD_REASON.to_owned());
            }
        }
        let result = self.ensure_running(self.timing.first_start_wait);
        if result.is_err() {
            let mut inner = self.lock();
            if downloading(&inner) {
                inner.first_start_waited = true;
                return Err(DOWNLOAD_REASON.to_owned());
            }
        }
        result
    }
}

/// The install of the Laya environment from Settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InstallState {
    /// No install since Apassy started, or the owner stopped it.
    #[default]
    Idle,
    Installing {
        /// The current step, from 1.
        step: usize,
        /// The number of steps.
        of: usize,
        label: &'static str,
        since: Instant,
    },
    Done,
    Failed {
        reason: String,
        /// The last lines of the install log.
        log_tail: Vec<String>,
    },
}

/// One command of the install: `uv` or the Python of the environment with its
/// arguments, in the Laya folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallStep {
    pub label: &'static str,
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

impl InstallStep {
    /// The command as one line for the log. It is not for a shell.
    pub fn line(&self) -> String {
        let mut line = self.program.display().to_string();
        for arg in &self.args {
            line.push(' ');
            line.push_str(&arg.to_string_lossy());
        }
        line
    }
}

/// The arguments of `uv venv` in the Laya folder. `None`: `.venv/bin/python` exists, so
/// the install skips `uv venv`. A `.venv` without its Python gets `--clear`, because
/// `uv venv` does not replace a folder that exists. This happens when Homebrew removes
/// the Python of the environment. Apassy owns this folder.
pub fn venv_args(laya_dir: &Path) -> Option<&'static [&'static str]> {
    let venv = laya_dir.join(".venv");
    if venv.join("bin").join("python").is_file() {
        None
    } else if venv.symlink_metadata().is_ok() {
        Some(&["venv", "--clear", "--python", "3.12", ".venv"])
    } else {
        Some(&["venv", "--python", "3.12", ".venv"])
    }
}

/// The commands of `docs/operations/bouncer.md` section 1 as argument vectors. An
/// environment with a Python skips `uv venv` (see [`venv_args`]). Without
/// `requirements`, the packages of the base model are not installed: the model is then
/// zero-shot. With `fetch` (`tools/basemodel/fetch_weights.py`), the last step runs it
/// with the Python of the environment, so the first start does not download the base
/// weights.
pub fn install_steps(
    uv: &Path,
    laya_dir: &Path,
    requirements: Option<&Path>,
    fetch: Option<&Path>,
) -> Vec<InstallStep> {
    let step = |label, args: &[&OsStr]| InstallStep {
        label,
        program: uv.to_path_buf(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
    };
    let python = OsStr::new(".venv/bin/python");
    let mut steps = Vec::new();
    if let Some(args) = venv_args(laya_dir) {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        steps.push(step("Create the Python environment", &args));
    }
    steps.push(step(
        "Install Laya",
        &[
            "pip".as_ref(),
            "install".as_ref(),
            "--python".as_ref(),
            python,
            LAYA_PACKAGE.as_ref(),
        ],
    ));
    if let Some(requirements) = requirements {
        steps.push(step(
            "Install the base-model packages",
            &[
                "pip".as_ref(),
                "install".as_ref(),
                "--python".as_ref(),
                python,
                "-r".as_ref(),
                requirements.as_os_str(),
            ],
        ));
    }
    if let Some(fetch) = fetch {
        // `-B`: no `__pycache__` next to the script. In Apassy.app it would break the
        // code signature of the bundle.
        steps.push(InstallStep {
            label: FETCH_LABEL,
            program: laya_dir.join(".venv").join("bin").join("python"),
            args: vec![OsString::from("-B"), fetch.as_os_str().to_owned()],
        });
    }
    steps
}

/// Environment variables that `uv` keeps from Apassy, besides [`KEPT_ENV`].
const INSTALL_ENV: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];
/// Prefixes of variables for `uv`, its certificates, and Hugging Face. `HF_HOME` and
/// `HF_HUB_CACHE` put the base weights where the server looks for them.
const INSTALL_PREFIXES: [&str; 3] = ["UV_", "SSL_CERT_", "HF_"];

/// The command of an install step: no shell, in `laya_dir`, in its own process group.
pub fn install_command(step: &InstallStep, laya_dir: &Path) -> Command {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(&step.program);
    command.args(&step.args).current_dir(laya_dir).env_clear();
    for (name, value) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if KEPT_ENV.contains(&text.as_ref())
            || INSTALL_ENV.contains(&text.as_ref())
            || INSTALL_PREFIXES
                .iter()
                .any(|prefix| text.starts_with(prefix))
        {
            command.env(&name, value);
        }
    }
    if std::env::var_os("PATH").is_none() {
        command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }
    command.stdin(Stdio::null()).process_group(0);
    command
}

/// How an install thread ended without success.
enum InstallEnd {
    /// The owner stopped it, or Apassy quits.
    Cancelled,
    Failed(String),
    /// Only the download of the base weights failed. The environment can be complete.
    WeightsFailed(String),
}

/// The note after a failed download of the base weights with a complete environment.
pub const WEIGHTS_LATER: &str =
    "The Laya environment is installed. The first start of the model server downloads the weights.";

impl ModelServer {
    /// "Install the model" in Settings: run the install steps on their own thread. It
    /// returns at once. `Err` when `uv` is missing or an install runs.
    pub fn install(self: &Arc<Self>) -> Result<(), String> {
        let uv = find_uv(&self.host.uv_dirs).ok_or_else(|| UV_MISSING.to_owned())?;
        let generation = {
            let mut installer = self.installer();
            if matches!(installer.state, InstallState::Installing { .. }) {
                return Err("The install already runs.".to_owned());
            }
            installer.generation += 1;
            installer.state = InstallState::Installing {
                step: 0,
                of: 0,
                label: "Prepare",
                since: Instant::now(),
            };
            installer.generation
        };
        let server = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("apassy-model-install".to_owned())
            .spawn(move || server.run_install(generation, &uv));
        if let Err(err) = spawned {
            let mut installer = self.installer();
            installer.state = InstallState::Failed {
                reason: format!("Apassy cannot start the install ({err})."),
                log_tail: Vec::new(),
            };
            return Err(format!("Apassy cannot start the install ({err})."));
        }
        Ok(())
    }

    /// "Cancel install" in Settings: stop `uv` and its children. It returns at once.
    pub fn cancel_install(&self) {
        let child = {
            let mut installer = self.installer();
            if !matches!(installer.state, InstallState::Installing { .. }) {
                return;
            }
            installer.generation += 1;
            installer.state = InstallState::Idle;
            installer.child.take()
        };
        if let Some(child) = child {
            stop_in_background(child);
        }
    }

    pub fn install_state(&self) -> InstallState {
        self.installer().state.clone()
    }

    /// The install thread.
    fn run_install(&self, generation: u64, uv: &Path) {
        let log = self.layout.install_log();
        let result = self.install_steps_in_order(generation, uv, &log);
        // A failed download of the weights leaves a complete environment. The server
        // can start, and its first start downloads them.
        let result = match result {
            Err(InstallEnd::WeightsFailed(reason)) if self.layout.venv_ready() => Err(
                InstallEnd::WeightsFailed(format!("{reason} {WEIGHTS_LATER}")),
            ),
            Err(InstallEnd::WeightsFailed(reason)) => Err(InstallEnd::Failed(reason)),
            other => other,
        };
        let note = match &result {
            Ok(()) => "apassy: the install finished.".to_owned(),
            Err(InstallEnd::Cancelled) => "apassy: the install stopped.".to_owned(),
            Err(InstallEnd::Failed(reason) | InstallEnd::WeightsFailed(reason)) => {
                format!("apassy: {reason}")
            }
        };
        if let Ok(mut file) = open_log(&log) {
            let _ = writeln!(file, "{note}");
        }
        let environment_ready = matches!(result, Ok(()) | Err(InstallEnd::WeightsFailed(_)));
        {
            let mut installer = self.installer();
            if installer.generation != generation {
                return;
            }
            installer.child = None;
            installer.state = match result {
                Ok(()) => InstallState::Done,
                Err(InstallEnd::Cancelled) => InstallState::Idle,
                Err(InstallEnd::Failed(reason) | InstallEnd::WeightsFailed(reason)) => {
                    InstallState::Failed {
                        reason,
                        log_tail: log_tail(&log, INSTALL_TAIL_LINES),
                    }
                }
            };
        }
        if environment_ready {
            self.after_install();
        }
    }

    fn install_steps_in_order(
        &self,
        generation: u64,
        uv: &Path,
        log: &Path,
    ) -> Result<(), InstallEnd> {
        let laya_dir = &self.layout.laya_dir;
        private_dir(laya_dir).map_err(|err| {
            InstallEnd::Failed(format!(
                "Apassy cannot create {} ({err}).",
                laya_dir.display()
            ))
        })?;
        let requirements = self.layout.requirements();
        let fetch = self.layout.fetch_script();
        let steps = install_steps(uv, laya_dir, requirements.as_deref(), fetch.as_deref());
        let of = steps.len();
        for (index, step) in steps.iter().enumerate() {
            {
                let mut installer = self.installer();
                if installer.generation != generation {
                    return Err(InstallEnd::Cancelled);
                }
                installer.state = InstallState::Installing {
                    step: index + 1,
                    of,
                    label: step.label,
                    since: Instant::now(),
                };
            }
            let failed = |err: io::Error| {
                InstallEnd::Failed(format!("Apassy cannot write {} ({err}).", log.display()))
            };
            let step_failed = |reason: String| {
                if step.label == FETCH_LABEL {
                    InstallEnd::WeightsFailed(reason)
                } else {
                    InstallEnd::Failed(reason)
                }
            };
            let mut out = open_log(log).map_err(failed)?;
            writeln!(out, "apassy: step {} of {of}: {}", index + 1, step.line()).map_err(failed)?;
            let err = out.try_clone().map_err(failed)?;
            let child = install_command(step, laya_dir)
                .stdout(Stdio::from(out))
                .stderr(Stdio::from(err))
                .spawn()
                .map_err(|err| {
                    step_failed(format!("{} did not start ({err}).", step.program.display()))
                })?;
            {
                let mut installer = self.installer();
                if installer.generation != generation {
                    drop(installer);
                    terminate(child, STOP_GRACE);
                    return Err(InstallEnd::Cancelled);
                }
                installer.child = Some(child);
            }
            loop {
                thread::sleep(INSTALL_POLL);
                let mut installer = self.installer();
                if installer.generation != generation {
                    // The cancel took the process and stops it.
                    return Err(InstallEnd::Cancelled);
                }
                let Some(child) = installer.child.as_mut() else {
                    return Err(InstallEnd::Cancelled);
                };
                match child.try_wait() {
                    Ok(None) => {}
                    Ok(Some(status)) => {
                        installer.child = None;
                        if status.success() {
                            break;
                        }
                        return Err(step_failed(format!("{} failed ({status}).", step.label)));
                    }
                    Err(err) => {
                        let child = installer.child.take();
                        drop(installer);
                        if let Some(child) = child {
                            terminate(child, STOP_GRACE);
                        }
                        return Err(step_failed(format!("{} failed ({err}).", step.label)));
                    }
                }
            }
        }
        for needed in [self.layout.python(), self.layout.laya_serve()] {
            if !needed.is_file() {
                return Err(InstallEnd::Failed(format!(
                    "uv finished, but {} does not exist.",
                    needed.display()
                )));
            }
        }
        Ok(())
    }

    /// After an install, or a failed download of the weights with a complete
    /// environment: check again, clear a "missing environment" state, and start the
    /// server in "With Apassy". That start downloads the weights.
    fn after_install(&self) {
        {
            let mut inner = self.lock();
            inner.preflight = preflight(&self.layout);
            let setup_failed = matches!(
                &inner.state,
                ServerState::Failed { problem, .. } if problem.is_setup()
            );
            if setup_failed {
                inner.state = base_state(inner.settings.start);
            }
            if inner.settings.start == StartMode::WithApassy
                && inner.preflight.is_ok()
                && matches!(inner.state, ServerState::Stopped)
            {
                Self::request_launch(&mut inner);
            }
        }
        self.wake.notify_all();
    }

    /// Read the LaunchAgents at start and then each [`AGENT_SCAN_EVERY`].
    fn scan_agents_when_due(&self) {
        let Some(dir) = &self.host.launch_agents else {
            return;
        };
        {
            let mut inner = self.lock();
            if inner
                .agents_scanned
                .is_some_and(|at| at.elapsed() < AGENT_SCAN_EVERY)
            {
                return;
            }
            inner.agents_scanned = Some(Instant::now());
        }
        let agents = scan_launch_agents(dir);
        self.lock().agents = agents;
    }
}

/// A LaunchAgent that runs `tools/basemodel/start.sh`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchAgent {
    pub path: PathBuf,
    /// `Label`, or the file name without `.plist`.
    pub label: String,
    /// `APASSY_BASE_MODEL` of `EnvironmentVariables`.
    pub base_model: Option<PathBuf>,
}

/// Why Settings shows a LaunchAgent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentConflict {
    /// Its `APASSY_BASE_MODEL` does not exist, so `start.sh` stops at each start.
    MissingModel(PathBuf),
    /// Apassy starts the server itself in this mode.
    Mode(StartMode),
}

impl LaunchAgent {
    /// The conflict with the mode of Settings, if any.
    pub fn conflict(&self, mode: StartMode) -> Option<AgentConflict> {
        if let Some(model) = &self.base_model
            && !model.exists()
        {
            return Some(AgentConflict::MissingModel(model.clone()));
        }
        mode.managed().then_some(AgentConflict::Mode(mode))
    }

    /// The Terminal commands that remove it. Apassy never runs them.
    pub fn remove_commands(&self) -> String {
        format!(
            "launchctl bootout gui/$(id -u)/{}\nrm {}",
            shell_word(&self.label),
            shell_word(&self.path.to_string_lossy())
        )
    }
}

/// `text` as one word for a shell: as it is when it has only safe characters, else in
/// single quotes.
pub fn shell_word(text: &str) -> String {
    let safe = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/+:@%,=".contains(c));
    if safe {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The LaunchAgent in a plist converted to JSON. `None` when it does not run
/// `tools/basemodel/start.sh`.
pub fn parse_launch_agent(path: &Path, plist: &serde_json::Value) -> Option<LaunchAgent> {
    let runs_script =
        |value: &serde_json::Value| value.as_str().is_some_and(|arg| arg.contains(START_SCRIPT));
    let in_arguments = plist
        .get("ProgramArguments")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|args| args.iter().any(runs_script));
    if !in_arguments && !plist.get("Program").is_some_and(runs_script) {
        return None;
    }
    let label = plist
        .get("Label")
        .and_then(serde_json::Value::as_str)
        .filter(|label| !label.trim().is_empty())
        .map_or_else(
            || {
                path.file_stem()
                    .map_or_else(String::new, |stem| stem.to_string_lossy().into_owned())
            },
            str::to_owned,
        );
    let base_model = plist
        .get("EnvironmentVariables")
        .and_then(|env| env.get("APASSY_BASE_MODEL"))
        .and_then(serde_json::Value::as_str)
        .filter(|model| !model.is_empty())
        .map(PathBuf::from);
    Some(LaunchAgent {
        path: path.to_path_buf(),
        label,
        base_model,
    })
}

/// Read one LaunchAgent with `plutil -convert json`. A file without `start.sh` in its
/// bytes is skipped without `plutil`.
pub fn read_launch_agent(path: &Path) -> Option<LaunchAgent> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_PLIST_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_PLIST_BYTES
        || !bytes.windows(b"start.sh".len()).any(|w| w == b"start.sh")
    {
        return None;
    }
    let output = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let plist: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    parse_launch_agent(path, &plist)
}

/// The `.plist` files in `dir` that run `tools/basemodel/start.sh`, by file name.
pub fn scan_launch_agents(dir: &Path) -> Vec<LaunchAgent> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "plist") && path.is_file())
        .collect();
    paths.sort();
    paths
        .iter()
        .filter_map(|path| read_launch_agent(path))
        .collect()
}

/// The state of a mode without a server that Apassy runs.
fn base_state(mode: StartMode) -> ServerState {
    match mode {
        StartMode::Off => ServerState::Off,
        StartMode::External => ServerState::External {
            up: None,
            model: None,
        },
        StartMode::WithApassy | StartMode::WhenNeeded => ServerState::Stopped,
    }
}

/// Environment variables that the server keeps from Apassy. The server gets no other
/// variable of the Apassy process.
const KEPT_ENV: [&str; 7] = [
    "HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "USER", "LOGNAME",
];
/// Prefixes of variables for Laya, Hugging Face, and PyTorch.
const KEPT_PREFIXES: [&str; 3] = ["LAYA_", "HF_", "PYTORCH_"];

/// The command of the server: `/bin/bash start.sh` in its own process group.
pub fn server_command(ready: &Ready, port: u16, api_key: Option<&str>) -> Command {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new("/bin/bash");
    command.arg(&ready.script).env_clear();
    for (name, value) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if KEPT_ENV.contains(&text.as_ref())
            || KEPT_PREFIXES.iter().any(|prefix| text.starts_with(prefix))
        {
            command.env(&name, value);
        }
    }
    if std::env::var_os("PATH").is_none() {
        command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }
    command
        .env("LAYA_HOST", "127.0.0.1")
        .env("LAYA_PORT", port.to_string())
        .env("APASSY_LAYA_DIR", &ready.laya_dir)
        .stdin(Stdio::null())
        .process_group(0);
    if let Some(checkpoint) = &ready.checkpoint {
        command.env("APASSY_BASE_MODEL", checkpoint);
    }
    // The client sends `APASSY_BOUNCER_KEY`, so the server checks the same key.
    if let Some(key) = api_key {
        command.env("LAYA_API_KEY", key);
    }
    command
}

/// Start the server with its output in `log` (folder mode 0700, file mode 0600).
pub fn spawn_server(
    ready: &Ready,
    port: u16,
    api_key: Option<&str>,
    log: &Path,
) -> io::Result<Child> {
    let out = open_log(log)?;
    let err = out.try_clone()?;
    server_command(ready, port, api_key)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
}

fn open_log(log: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(dir) = log.parent() {
        private_dir(dir)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log)?;
    if file.metadata()?.len() > MAX_LOG_BYTES {
        file.set_len(0)?;
        file.rewind()?;
    }
    Ok(file)
}

/// The last `lines` lines of the log.
pub fn log_tail(log: &Path, lines: usize) -> Vec<String> {
    const TAIL_BYTES: u64 = 8 * 1024;
    let Ok(mut file) = fs::File::open(log) else {
        return Vec::new();
    };
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if file
        .seek(io::SeekFrom::Start(len.saturating_sub(TAIL_BYTES)))
        .is_err()
    {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if file.take(TAIL_BYTES).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let all: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    all[all.len().saturating_sub(lines)..]
        .iter()
        .map(|line| (*line).to_owned())
        .collect()
}

fn signal_group(pgid: u32, signal: &str) {
    let _ = Command::new("/bin/kill")
        .args([signal, "--", &format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Stop the process group of `child`: SIGTERM, then SIGKILL after `grace`.
pub fn terminate(mut child: Child, grace: Duration) {
    // The child leads its own process group (`process_group(0)`), so its PID is the
    // group ID. The group is signaled while the leader is not yet reaped.
    let pgid = child.id();
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    signal_group(pgid, "-TERM");
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Another process of the group can still run. Its group ID stays in use,
                // so this signal reaches only that group.
                signal_group(pgid, "-KILL");
                return;
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            _ => break,
        }
    }
    signal_group(pgid, "-KILL");
    let _ = child.wait();
}

fn stop_in_background(child: Child) {
    // Without a thread, the child is dropped and keeps running until the app quits.
    let _ = thread::Builder::new()
        .name("apassy-model-stop".to_owned())
        .spawn(move || terminate(child, STOP_GRACE));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn executable(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        fs::write(path, text).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("mode");
    }

    fn layout(dir: &Path) -> Layout {
        let laya_dir = dir.join("laya");
        Layout {
            script: Some(dir.join("tools/basemodel/start.sh")),
            checkpoints: vec![laya_dir.join("models").join(CHECKPOINT)],
            laya_dir,
            log: dir.join("Logs/Apassy/bouncer.log"),
        }
    }

    #[test]
    fn a_missing_or_damaged_file_gives_external_and_30_minutes() {
        let dir = TempDir::new().expect("temp dir");
        let defaults = BouncerSettings::default();
        assert_eq!(defaults.start, StartMode::External);
        assert_eq!(defaults.idle_minutes, 30);
        assert_eq!(defaults.url, None);
        let path = dir.path().join(SETTINGS_FILE);
        assert_eq!(BouncerSettings::load(&path), defaults);
        fs::write(&path, b"{ not json").expect("write");
        assert_eq!(BouncerSettings::load(&path), defaults);
        fs::write(&path, br#"{"start": "sometimes"}"#).expect("write");
        assert_eq!(BouncerSettings::load(&path), defaults, "an unknown mode");
        fs::write(&path, br#"{"start": "when_needed", "idle_minutes": 7}"#).expect("write");
        let read = BouncerSettings::load(&path);
        assert_eq!(read.start, StartMode::WhenNeeded);
        assert_eq!(read.idle_minutes, 30, "7 is not a choice");
        fs::write(&path, vec![b' '; 70 * 1024]).expect("write");
        assert_eq!(BouncerSettings::load(&path), defaults);
    }

    #[test]
    fn settings_persist_with_mode_0600() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("data").join(SETTINGS_FILE);
        let settings = BouncerSettings {
            start: StartMode::WhenNeeded,
            idle_minutes: 10,
            url: Some("http://127.0.0.1:8771".to_owned()),
        };
        settings.save(&path).expect("save");
        assert_eq!(BouncerSettings::load(&path), settings);
        let mode = fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(path.parent().expect("parent"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        let text = fs::read_to_string(&path).expect("read");
        assert!(text.contains("\"when_needed\""), "{text}");

        for mode in StartMode::ALL {
            let changed = BouncerSettings {
                start: mode,
                ..settings.clone()
            };
            changed.save(&path).expect("save again");
            assert_eq!(BouncerSettings::load(&path).start, mode);
        }
        let names: Vec<_> = fs::read_dir(path.parent().expect("parent"))
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(SETTINGS_FILE)]);
    }

    #[test]
    fn the_address_must_be_a_loopback_http_url() {
        assert_eq!(
            validate_url("http://127.0.0.1:8770/").as_deref(),
            Ok("http://127.0.0.1:8770")
        );
        assert!(validate_url("http://localhost:9000").is_ok());
        assert!(validate_url("https://127.0.0.1:8770").is_err());
        assert!(validate_url("http://example.com:8770").is_err());
        assert!(validate_url("http://10.0.0.2:8770").is_err());
        assert!(validate_url("not a url").is_err());

        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(SETTINGS_FILE);
        fs::write(&path, br#"{"url": "http://example.com:8770"}"#).expect("write");
        let read = BouncerSettings::load(&path);
        assert_eq!(read.url, None, "a remote address is dropped");
        assert_eq!(read.file_url(), DEFAULT_URL);
        fs::write(&path, br#"{"url": "http://127.0.0.1:8771"}"#).expect("write");
        assert_eq!(
            BouncerSettings::load(&path).file_url(),
            "http://127.0.0.1:8771"
        );
    }

    #[test]
    fn preflight_names_what_is_missing() {
        let dir = TempDir::new().expect("temp dir");
        let mut layout = layout(dir.path());

        layout.script = None;
        assert_eq!(preflight(&layout), Err(Problem::NoScript));

        let script = dir.path().join("tools/basemodel/start.sh");
        executable(&script, "#!/bin/bash\n");
        layout.script = Some(script.clone());
        assert_eq!(
            preflight(&layout),
            Err(Problem::NoVenv {
                program: layout.python()
            })
        );

        // A Python without laya-serve and without a checkpoint cannot start zero-shot.
        executable(&layout.python(), "#!/bin/sh\n");
        assert_eq!(
            preflight(&layout),
            Err(Problem::NoVenv {
                program: layout.laya_serve()
            })
        );

        // The venv but no checkpoint: zero-shot laya-serve.
        executable(&layout.laya_serve(), "#!/bin/sh\n");
        let ready = preflight(&layout).expect("ready");
        assert_eq!(ready.checkpoint, None);
        assert_eq!(ready.script, script);

        // A checkpoint: the base model.
        let checkpoint = layout.checkpoints[0].clone();
        fs::create_dir_all(checkpoint.parent().expect("parent")).expect("dir");
        fs::write(&checkpoint, b"weights").expect("write");
        assert_eq!(
            preflight(&layout).expect("ready").checkpoint,
            Some(checkpoint)
        );
    }

    #[test]
    fn the_script_is_in_the_bundle_or_in_the_repository() {
        let dir = TempDir::new().expect("temp dir");
        let app = dir.path().join("Apassy.app/Contents");
        let exe = app.join("MacOS/apassy");
        assert_eq!(find_script(&exe), None);
        let bundled = app.join("Resources/tools/basemodel/start.sh");
        executable(&bundled, "#!/bin/bash\n");
        assert_eq!(find_script(&exe), Some(bundled));

        let repo = dir.path().join("repo");
        let dev = repo.join("target/debug/apassy");
        assert_eq!(find_script(&dev), None);
        let script = repo.join("tools/basemodel/start.sh");
        executable(&script, "#!/bin/bash\n");
        assert_eq!(find_script(&dev), Some(script.clone()));
        assert_eq!(find_script(&repo.join("target/debug/deps/x")), Some(script));
    }

    #[test]
    fn the_idle_stop_needs_when_needed_an_own_server_and_the_idle_time() {
        let start = Instant::now();
        let idle = Duration::from_secs(30 * 60);
        let later = start + idle;
        let early = start + idle - Duration::from_secs(1);
        assert!(idle_stop_due(
            StartMode::WhenNeeded,
            true,
            true,
            start,
            later,
            idle
        ));
        assert!(!idle_stop_due(
            StartMode::WhenNeeded,
            true,
            true,
            start,
            early,
            idle
        ));
        assert!(!idle_stop_due(
            StartMode::WithApassy,
            true,
            true,
            start,
            later,
            idle
        ));
        assert!(!idle_stop_due(
            StartMode::External,
            true,
            true,
            start,
            later,
            idle
        ));
        assert!(!idle_stop_due(
            StartMode::WhenNeeded,
            false,
            true,
            start,
            later,
            idle
        ));
        assert!(!idle_stop_due(
            StartMode::WhenNeeded,
            true,
            false,
            start,
            later,
            idle
        ));
        // A use after `now` (a clock race) is not idle.
        assert!(!idle_stop_due(
            StartMode::WhenNeeded,
            true,
            true,
            later,
            start,
            idle
        ));
    }

    #[test]
    fn the_default_mode_starts_nothing() {
        let dir = TempDir::new().expect("temp dir");
        let server = ModelServer::start(Some(dir.path().join(SETTINGS_FILE)), layout(dir.path()));
        assert_eq!(server.settings().start, StartMode::External);
        assert!(matches!(server.state(), ServerState::External { .. }));
        assert_eq!(server.before_model(), Ok(()));
        server.start_now();
        thread::sleep(Duration::from_millis(100));
        let status = server.status();
        assert!(matches!(status.state, ServerState::External { .. }));
        assert!(!status.owned);
        assert!(
            !dir.path().join(SETTINGS_FILE).exists(),
            "nothing is written"
        );
        server.shutdown();
    }

    #[test]
    fn off_skips_the_model_and_when_needed_starts_the_server_first() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join(SETTINGS_FILE);
        let mut layout = layout(dir.path());
        layout.script = None;
        let server = ModelServer::start_with(
            Some(path.clone()),
            BouncerSettings {
                start: StartMode::Off,
                ..BouncerSettings::default()
            },
            layout,
        );
        assert_eq!(server.before_model(), Err(OFF_REASON.to_owned()));
        assert_eq!(server.state(), ServerState::Off);

        // "When a run needs it" starts the server before the model. Here the script is
        // missing, so the run does not wait 25 seconds.
        server
            .set_settings(BouncerSettings {
                start: StartMode::WhenNeeded,
                ..BouncerSettings::default()
            })
            .expect("save");
        assert_eq!(BouncerSettings::load(&path).start, StartMode::WhenNeeded);
        assert_eq!(server.state(), ServerState::Stopped);
        let began = Instant::now();
        let reason = server.before_model().expect_err("no script");
        assert!(began.elapsed() < Duration::from_secs(5));
        assert!(reason.contains("start script"), "{reason}");
        assert!(matches!(
            server.state(),
            ServerState::Failed {
                problem: Problem::NoScript,
                ..
            }
        ));
        server.shutdown();
    }

    #[test]
    fn the_command_sets_the_laya_environment() {
        let ready = Ready {
            script: PathBuf::from("/tmp/x/start.sh"),
            laya_dir: PathBuf::from("/tmp/x/laya"),
            checkpoint: None,
        };
        let command = server_command(&ready, 8771, None);
        assert_eq!(command.get_program(), "/bin/bash");
        let envs: Vec<_> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let get = |name: &str| {
            envs.iter()
                .find(|(key, _)| key == name)
                .and_then(|(_, value)| value.clone())
        };
        assert_eq!(get("LAYA_HOST").as_deref(), Some("127.0.0.1"));
        assert_eq!(get("LAYA_PORT").as_deref(), Some("8771"));
        assert_eq!(get("APASSY_LAYA_DIR").as_deref(), Some("/tmp/x/laya"));
        assert_eq!(get("APASSY_BASE_MODEL"), None, "no checkpoint, no variable");
        assert_eq!(get("LAYA_API_KEY"), None);

        let with_model = Ready {
            checkpoint: Some(PathBuf::from("/tmp/x/m.safetensors")),
            ..ready
        };
        let command = server_command(&with_model, 8770, Some("k"));
        let has = |name: &str, want: &str| {
            command
                .get_envs()
                .any(|(key, value)| key == name && value.is_some_and(|value| value == want))
        };
        assert!(has("APASSY_BASE_MODEL", "/tmp/x/m.safetensors"));
        assert!(has("LAYA_API_KEY", "k"));
    }

    /// A real start of `tools/basemodel/start.sh` with the Laya environment of this Mac,
    /// on port 8779. Ignored by default:
    /// `cargo test --features vault --lib model_server::tests::live -- --ignored`.
    #[test]
    #[ignore = "needs the Laya environment and loads the model"]
    fn live_start_answer_and_stop() {
        let layout = Layout::discover();
        preflight(&layout).expect("the Laya environment of this Mac");
        let server = ModelServer::start_with(
            None,
            BouncerSettings {
                start: StartMode::WhenNeeded,
                idle_minutes: 10,
                url: Some("http://127.0.0.1:8779".to_owned()),
            },
            layout,
        );
        let began = Instant::now();
        server
            .ensure_running(Duration::from_secs(170))
            .expect("the server starts");
        eprintln!("ready after {:?}: {:?}", began.elapsed(), server.state());
        assert!(matches!(
            server.state(),
            ServerState::Running {
                model: Some(_),
                outside: false
            }
        ));
        assert!(server.status().owned);
        let client = server.client().expect("client");
        server.shutdown();
        assert_eq!(client.probe_health(PROBE_TIMEOUT), Health::NoServer);
    }

    #[test]
    fn uv_is_found_in_the_known_folders_then_in_path() {
        let dir = TempDir::new().expect("temp dir");
        let home = dir.path().join("home");
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let path = std::env::join_paths([
            first.as_path(),
            Path::new("relative/bin"),
            second.as_path(),
            Path::new("/usr/local/bin"),
        ])
        .expect("path");
        let dirs = uv_dirs(Some(&home), Some(&path));
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/opt/homebrew/bin"),
                PathBuf::from("/usr/local/bin"),
                home.join(".local/bin"),
                home.join(".cargo/bin"),
                first.clone(),
                second.clone(),
            ],
            "a relative folder and a repeated folder are skipped"
        );

        let search = vec![first.clone(), home.join(".local/bin"), second.clone()];
        assert_eq!(find_uv(&search), None);
        // A file without the executable bit is not uv.
        fs::create_dir_all(&first).expect("dir");
        fs::write(first.join("uv"), "#!/bin/sh\n").expect("write");
        assert_eq!(find_uv(&search), None);
        executable(&second.join("uv"), "#!/bin/sh\n");
        assert_eq!(find_uv(&search), Some(second.join("uv")));
        executable(&home.join(".local/bin/uv"), "#!/bin/sh\n");
        assert_eq!(find_uv(&search), Some(home.join(".local/bin/uv")));
        assert_eq!(find_uv(&[]), None);
    }

    #[test]
    fn the_install_steps_are_the_commands_of_the_guide() {
        let dir = TempDir::new().expect("temp dir");
        let uv = PathBuf::from("/opt/homebrew/bin/uv");
        let laya = dir.path().join("Application Support/laya");
        let requirements = dir.path().join("tools/basemodel/requirements.txt");
        let fetch = dir.path().join("tools/basemodel").join(FETCH_SCRIPT);
        let steps = install_steps(&uv, &laya, Some(&requirements), Some(&fetch));
        // The last step downloads the base weights with the Python of the environment.
        // `-B`: no `__pycache__` in the signed app bundle.
        let (last, steps) = steps.split_last().expect("steps");
        assert_eq!(last.label, FETCH_LABEL);
        assert_eq!(last.program, laya.join(".venv/bin/python"));
        assert_eq!(
            last.args,
            vec![OsString::from("-B"), fetch.clone().into_os_string()]
        );
        let args: Vec<Vec<String>> = steps
            .iter()
            .map(|step| {
                assert_eq!(step.program, uv);
                step.args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect()
            })
            .collect();
        let python = ".venv/bin/python";
        assert_eq!(
            args,
            vec![
                vec!["venv", "--python", "3.12", ".venv"],
                vec!["pip", "install", "--python", python, "laya[serve]==0.3.20"],
                vec![
                    "pip",
                    "install",
                    "--python",
                    python,
                    "-r",
                    requirements.to_str().expect("utf-8"),
                ],
            ]
        );
        assert_eq!(steps[1].label, "Install Laya");

        // A `.venv` whose Python link points to a removed Python: `uv venv` needs
        // `--clear`, or it stops with "A virtual environment already exists".
        fs::create_dir_all(laya.join(".venv/bin")).expect("dir");
        fs::write(laya.join(".venv/pyvenv.cfg"), "home = /gone\n").expect("write");
        std::os::unix::fs::symlink(
            dir.path().join("gone/python3.12"),
            laya.join(".venv/bin/python"),
        )
        .expect("symlink");
        let steps = install_steps(&uv, &laya, None, None);
        assert_eq!(
            steps[0].args,
            ["venv", "--clear", "--python", "3.12", ".venv"].map(OsString::from)
        );
        assert_eq!(steps[0].label, "Create the Python environment");
        assert_eq!(steps.len(), 2);
        // An empty `.venv` folder needs `--clear` too.
        fs::remove_dir_all(laya.join(".venv")).expect("remove");
        fs::create_dir_all(laya.join(".venv")).expect("dir");
        assert_eq!(
            venv_args(&laya),
            Some(&["venv", "--clear", "--python", "3.12", ".venv"][..])
        );

        // An environment with a Python skips `uv venv`. No requirements: Laya only.
        fs::remove_dir_all(laya.join(".venv")).expect("remove");
        assert_eq!(
            venv_args(&laya),
            Some(&["venv", "--python", "3.12", ".venv"][..])
        );
        executable(&laya.join(".venv/bin/python"), "#!/bin/sh\n");
        assert_eq!(venv_args(&laya), None);
        let steps = install_steps(&uv, &laya, None, None);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].args[0], "pip");

        // No shell: the program is uv itself, in the Laya folder, with a small environment.
        let command = install_command(&steps[0], &laya);
        assert_eq!(command.get_program(), uv.as_os_str());
        assert_eq!(command.get_current_dir(), Some(laya.as_path()));
        assert!(
            command
                .get_envs()
                .all(|(name, _)| !name.to_string_lossy().starts_with("APASSY_")),
            "no Apassy variable reaches uv"
        );
    }

    /// The base-model block of `scripts/build-app.sh` in a scratch HOME. It returns
    /// the exit status, the output, and the error output.
    #[cfg(target_os = "macos")]
    fn build_app_model_block(
        home: &Path,
        root: &Path,
        app: &Path,
        env: &[(&str, &OsStr)],
    ) -> (bool, String, String) {
        let script =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build-app.sh"))
                .expect("read build-app.sh");
        let start = script
            .find("# Goal B8: the base-model checkpoint")
            .expect("the model block");
        let end = script
            .find("# The training and serving scripts")
            .expect("the end of the model block");
        let block = format!(
            "set -euo pipefail\nstep() {{ printf '\\n==> %s\\n' \"$*\"; }}\nfail() {{ printf 'FAILED: %s\\n' \"$*\" >&2; exit 1; }}\nwarn() {{ printf 'WARNING: %s\\n' \"$*\" >&2; }}\n{}",
            &script[start..end]
        );
        let mut command = Command::new("/bin/bash");
        command
            .arg("-c")
            .arg(block)
            .env_clear()
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("ROOT", root)
            .env("APP", app);
        for (name, value) in env {
            command.env(name, value);
        }
        let output = command.output().expect("bash");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// Without `APASSY_BASE_MODEL`, `scripts/build-app.sh` ships the checkpoint of this
    /// Mac only when it matches the manifest. An old or retrained one gives an app
    /// without a model, so `scripts/install.sh` does not fail. An explicit
    /// `APASSY_BASE_MODEL` that does not match stops the build.
    /// macOS only: `scripts/build-app.sh` reads the manifest with `plutil`.
    #[cfg(target_os = "macos")]
    #[test]
    fn build_app_ships_the_local_checkpoint_only_when_it_matches() {
        let dir = TempDir::new().expect("temp dir");
        let home = dir.path().join("home");
        let root = dir.path().join("repo");
        let app = dir.path().join("Apassy.app");
        let models = home.join("Library/Application Support/Apassy/laya/models");
        fs::create_dir_all(&models).expect("dir");
        fs::create_dir_all(root.join("tools/basemodel")).expect("dir");
        let local = models.join(CHECKPOINT);
        fs::write(&local, b"old checkpoint").expect("write");
        let manifest = |sha: &str, size: u64| {
            let text = format!(
                "{{\"version\":\"apassy-base-v1+{}\",\"checkpoint\":{{\"file\":\"{CHECKPOINT}\",\"sha256\":\"{sha}\",\"size_bytes\":{size}}}}}",
                &sha[..8]
            );
            fs::write(root.join("tools/basemodel/manifest.json"), text).expect("write");
        };
        manifest(&"8".repeat(64), 104_996_060);
        let shipped = app.join("Contents/Resources/models").join(CHECKPOINT);

        // A local checkpoint that does not match: no model, and the build goes on.
        let (ok, out, err) = build_app_model_block(&home, &root, &app, &[]);
        assert!(ok, "{out}{err}");
        assert!(
            err.contains("WARNING: checkpoint size 14 does not match"),
            "{err}"
        );
        assert!(out.contains("Base model: none."), "{out}");
        assert!(out.contains("does not match the manifest."), "{out}");
        assert!(!shipped.exists());

        // The same file in APASSY_BASE_MODEL stops the build.
        let (ok, out, err) = build_app_model_block(
            &home,
            &root,
            &app,
            &[("APASSY_BASE_MODEL", local.as_os_str())],
        );
        assert!(!ok, "{out}{err}");
        assert!(
            err.contains("FAILED: checkpoint size 14 does not match"),
            "{err}"
        );
        assert!(!shipped.exists());

        // An empty APASSY_BASE_MODEL, and GitHub Actions, ship no model.
        let (ok, out, _) =
            build_app_model_block(&home, &root, &app, &[("APASSY_BASE_MODEL", OsStr::new(""))]);
        assert!(
            ok && out.contains("Base model: none (APASSY_BASE_MODEL is empty)."),
            "{out}"
        );
        let (ok, out, _) = build_app_model_block(
            &home,
            &root,
            &app,
            &[("GITHUB_ACTIONS", OsStr::new("true"))],
        );
        assert!(ok && out.contains("in GitHub Actions"), "{out}");

        // A local checkpoint that matches ships, with the manifest.
        let sha = Command::new("/usr/bin/shasum")
            .args(["-a", "256"])
            .arg(&local)
            .output()
            .expect("shasum");
        let sha = String::from_utf8_lossy(&sha.stdout)[..64].to_owned();
        manifest(&sha, 14);
        let (ok, out, err) = build_app_model_block(&home, &root, &app, &[]);
        assert!(ok, "{out}{err}");
        assert!(
            out.contains(&format!("Base model: apassy-base-v1+{}", &sha[..8])),
            "{out}"
        );
        assert_eq!(fs::read(&shipped).expect("read"), b"old checkpoint");
        assert!(
            app.join("Contents/Resources/models/manifest.json")
                .is_file()
        );
    }

    /// A fake `uv` in a temporary folder. It prints its arguments. `venv` and `pip`
    /// make the files of the environment. `fail_pip` makes `pip` fail.
    fn fake_uv(dir: &Path, fail_pip: bool) -> Host {
        fake_uv_with_fetch(dir, fail_pip, true)
    }

    /// As [`fake_uv`]. Without `fetch_ok`, the Python of the environment fails, so the
    /// download of the weights fails.
    fn fake_uv_with_fetch(dir: &Path, fail_pip: bool, fetch_ok: bool) -> Host {
        let bin = dir.join("bin");
        let pip = if fail_pip {
            "echo 'error: no network'; exit 1"
        } else {
            "printf '#!/bin/sh\\n' > .venv/bin/laya-serve; chmod 755 .venv/bin/laya-serve"
        };
        let fetch = if fetch_ok {
            ""
        } else {
            "echo fetch: 503 Service Unavailable\\nexit 1\\n"
        };
        executable(
            &bin.join("uv"),
            &format!(
                "#!/bin/sh\necho \"fake uv $*\"\ncase \"$1\" in\n  venv) mkdir -p .venv/bin; printf '#!/bin/sh\\necho \"fake python $*\"\\n{fetch}' > .venv/bin/python; chmod 755 .venv/bin/python;;\n  pip) {pip};;\nesac\n"
            ),
        );
        Host {
            uv_dirs: vec![bin],
            launch_agents: None,
            hf_cache: None,
        }
    }

    fn wait_install(server: &ModelServer) -> InstallState {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let state = server.install_state();
            if !matches!(state, InstallState::Installing { .. }) {
                return state;
            }
            assert!(Instant::now() < deadline, "{state:?}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn the_install_runs_each_step_and_ends_done_or_failed() {
        let dir = TempDir::new().expect("temp dir");
        let layout = layout(dir.path());
        executable(layout.script.as_deref().expect("script"), "#!/bin/bash\n");
        let requirements = dir.path().join("tools/basemodel/requirements.txt");
        fs::write(&requirements, "torch==2.14.0\n").expect("write");
        let fetch = dir.path().join("tools/basemodel").join(FETCH_SCRIPT);
        fs::write(&fetch, "# fake\n").expect("write");

        // Without uv, nothing starts.
        let server = ModelServer::start_with_host(
            None,
            BouncerSettings::default(),
            layout.clone(),
            Host::none(),
        );
        assert_eq!(server.install(), Err(UV_MISSING.to_owned()));
        assert_eq!(server.install_state(), InstallState::Idle);
        assert!(!server.status().venv_ready);
        assert_eq!(server.status().uv, None);
        server.shutdown();

        let server = ModelServer::start_with_host(
            None,
            BouncerSettings::default(),
            layout.clone(),
            fake_uv(dir.path(), false),
        );
        assert_eq!(server.status().uv, Some(dir.path().join("bin/uv")));
        server.install().expect("install");
        assert_eq!(wait_install(&server), InstallState::Done);
        let status = server.status();
        assert!(status.venv_ready);
        assert_eq!(status.uv, None, "no search with an environment");
        assert_eq!(
            status.install_log,
            dir.path().join("Logs/Apassy/bouncer-install.log")
        );
        let mode = fs::metadata(&layout.laya_dir)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let text = fs::read_to_string(&status.install_log).expect("log");
        for expected in [
            "apassy: step 1 of 4:",
            "fake uv venv --python 3.12 .venv",
            "fake uv pip install --python .venv/bin/python laya[serve]==0.3.20",
            &format!("-r {}", requirements.display()),
            &format!(
                "apassy: step 4 of 4: {} -B {}",
                layout.python().display(),
                fetch.display()
            ),
            &format!("fake python -B {}", fetch.display()),
            "apassy: the install finished.",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        assert_eq!(
            fs::metadata(&status.install_log)
                .expect("meta")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        server.shutdown();

        // A failing step: Failed with the last lines of the log.
        let other = TempDir::new().expect("temp dir");
        let server = ModelServer::start_with_host(
            None,
            BouncerSettings::default(),
            layout_without_script(other.path()),
            fake_uv(other.path(), true),
        );
        server.install().expect("install");
        let InstallState::Failed { reason, log_tail } = wait_install(&server) else {
            panic!("{:?}", server.install_state());
        };
        assert!(reason.starts_with("Install Laya failed"), "{reason}");
        assert!(
            log_tail
                .iter()
                .any(|line| line.contains("error: no network")),
            "{log_tail:?}"
        );
        assert!(!server.status().venv_ready);
        // A second install runs again.
        server.install().expect("again");
        assert!(matches!(wait_install(&server), InstallState::Failed { .. }));
        server.shutdown();
    }

    fn layout_without_script(dir: &Path) -> Layout {
        Layout {
            script: None,
            ..layout(dir)
        }
    }

    #[test]
    fn cancel_stops_uv_and_its_children() {
        let dir = TempDir::new().expect("temp dir");
        let bin = dir.path().join("bin");
        let pids = dir.path().join("pids");
        executable(
            &bin.join("uv"),
            &format!(
                "#!/bin/sh\nsleep 30 &\necho \"$$ $!\" > '{}'\nwait\n",
                pids.display()
            ),
        );
        let server = ModelServer::start_with_host(
            None,
            BouncerSettings {
                start: StartMode::WhenNeeded,
                ..BouncerSettings::default()
            },
            layout_without_script(dir.path()),
            Host {
                uv_dirs: vec![bin],
                launch_agents: None,
                hf_cache: None,
            },
        );
        server.install().expect("install");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pids.is_file() {
            assert!(Instant::now() < deadline, "{:?}", server.install_state());
            thread::sleep(Duration::from_millis(20));
        }
        assert!(matches!(
            server.install_state(),
            InstallState::Installing {
                step: 1,
                of: 2,
                label: "Create the Python environment",
                ..
            }
        ));
        assert!(server.install().is_err(), "one install at a time");
        server.cancel_install();
        assert_eq!(server.install_state(), InstallState::Idle);
        thread::sleep(Duration::from_millis(600));
        let text = fs::read_to_string(&pids).expect("pids");
        for pid in text.split_whitespace() {
            let alive = Command::new("/bin/kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            assert!(!alive, "process {pid} stopped");
        }
        assert_eq!(server.install_state(), InstallState::Idle);
        let log = fs::read_to_string(server.status().install_log).expect("log");
        assert!(log.contains("apassy: the install stopped."), "{log}");
        server.shutdown();
    }

    #[cfg(target_os = "macos")]
    fn plist(label: &str, program: &str, model: Option<&str>) -> String {
        let env = model.map_or_else(String::new, |model| {
            format!(
                "<key>EnvironmentVariables</key><dict><key>APASSY_BASE_MODEL</key><string>{model}</string></dict>"
            )
        });
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>/bin/bash</string><string>{program}</string></array>{env}<key>RunAtLoad</key><true/></dict></plist>\n"
        )
    }

    /// macOS only: a LaunchAgent is read with `/usr/bin/plutil`.
    #[cfg(target_os = "macos")]
    #[test]
    fn launch_agents_that_run_start_sh_are_found_and_checked() {
        let dir = TempDir::new().expect("temp dir");
        let agents = dir.path().join("LaunchAgents");
        fs::create_dir_all(&agents).expect("dir");
        let script = "/Applications/Apassy.app/Contents/Resources/tools/basemodel/start.sh";
        let missing = dir.path().join("gone/apassy-base-v1.safetensors");
        let present = dir.path().join("models/apassy-base-v1.safetensors");
        fs::create_dir_all(present.parent().expect("parent")).expect("dir");
        fs::write(&present, b"weights").expect("write");
        let write = |name: &str, text: String| fs::write(agents.join(name), text).expect("write");
        write(
            "com.example.bouncer.plist",
            plist(
                "com.example.bouncer",
                script,
                Some(missing.to_str().expect("utf-8")),
            ),
        );
        write(
            "com.example.good.plist",
            plist(
                "com.example.good",
                script,
                Some(present.to_str().expect("utf-8")),
            ),
        );
        write(
            "com.example.plain.plist",
            plist("com.example.plain", script, None),
        );
        write(
            "com.example.other.plist",
            plist("com.example.other", "/usr/local/bin/other-start.sh", None),
        );
        write("broken.plist", "start.sh but not a plist".to_owned());
        write("notes.txt", plist("com.example.text", script, None));

        let found = scan_launch_agents(&agents);
        let labels: Vec<&str> = found.iter().map(|agent| agent.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "com.example.bouncer",
                "com.example.good",
                "com.example.plain"
            ],
            "an unrelated plist, a damaged plist, and a text file are ignored"
        );
        let [missing_model, good, plain] = &found[..] else {
            panic!("{found:?}");
        };
        assert_eq!(missing_model.base_model.as_deref(), Some(missing.as_path()));
        assert_eq!(missing_model.path, agents.join("com.example.bouncer.plist"));

        // A missing model is a problem in every mode.
        for mode in StartMode::ALL {
            assert_eq!(
                missing_model.conflict(mode),
                Some(AgentConflict::MissingModel(missing.clone()))
            );
        }
        // A working LaunchAgent conflicts only with the modes where Apassy starts the server.
        for agent in [good, plain] {
            assert_eq!(agent.conflict(StartMode::External), None);
            assert_eq!(agent.conflict(StartMode::Off), None);
            assert_eq!(
                agent.conflict(StartMode::WithApassy),
                Some(AgentConflict::Mode(StartMode::WithApassy))
            );
            assert_eq!(
                agent.conflict(StartMode::WhenNeeded),
                Some(AgentConflict::Mode(StartMode::WhenNeeded))
            );
        }
        assert_eq!(
            missing_model.remove_commands(),
            format!(
                "launchctl bootout gui/$(id -u)/com.example.bouncer\nrm {}",
                agents.join("com.example.bouncer.plist").display()
            )
        );
        assert_eq!(shell_word("a b'c"), "'a b'\\''c'");
        assert_eq!(scan_launch_agents(&dir.path().join("none")), Vec::new());

        // The supervisor reads them when it starts.
        let server = ModelServer::start_with_host(
            None,
            BouncerSettings::default(),
            layout(dir.path()),
            Host {
                uv_dirs: Vec::new(),
                launch_agents: Some(agents),
                hf_cache: None,
            },
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while server.status().launch_agents.len() != 3 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        server.shutdown();
    }

    fn group_alive(pgid: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", "--", &format!("-{pgid}")])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn spawn_and_stop_end_the_whole_process_group() {
        let dir = TempDir::new().expect("temp dir");
        let script = dir.path().join("start.sh");
        // A child in the background and the script itself. Both are in the group.
        executable(
            &script,
            "echo \"port $LAYA_PORT dir $APASSY_LAYA_DIR\"\nsleep 30 &\nsleep 30\n",
        );
        let ready = Ready {
            script,
            laya_dir: dir.path().join("laya"),
            checkpoint: None,
        };
        let log = dir.path().join("Logs/Apassy/bouncer.log");
        let child = spawn_server(&ready, 18_770, None, &log).expect("spawn");
        let pgid = child.id();
        thread::sleep(Duration::from_millis(300));
        assert!(group_alive(pgid));
        terminate(child, Duration::from_secs(5));
        thread::sleep(Duration::from_millis(100));
        assert!(!group_alive(pgid), "the background child also stopped");
        let text = fs::read_to_string(&log).expect("log");
        assert!(text.contains("port 18770 dir"), "{text}");
        let mode = fs::metadata(&log).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(log.parent().expect("parent"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        assert_eq!(log_tail(&log, 6).len(), 1);

        // A script that ignores SIGTERM gets SIGKILL after the grace time.
        let stubborn = dir.path().join("stubborn.sh");
        executable(&stubborn, "trap '' TERM\nsleep 30\n");
        let ready = Ready {
            script: stubborn,
            ..ready
        };
        let child = spawn_server(&ready, 18_770, None, &log).expect("spawn");
        let pgid = child.id();
        thread::sleep(Duration::from_millis(300));
        let began = Instant::now();
        terminate(child, Duration::from_millis(400));
        assert!(began.elapsed() < Duration::from_secs(4));
        thread::sleep(Duration::from_millis(100));
        assert!(!group_alive(pgid));
    }

    /// A port on 127.0.0.1 where nothing listens now.
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    /// Wait up to `limit` for `done`.
    fn wait_until(limit: Duration, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + limit;
        while !done() {
            assert!(Instant::now() < deadline, "{what}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// The process group of a fake server: the first PID in `pids`.
    fn first_pid(pids: &Path) -> u32 {
        fs::read_to_string(pids)
            .expect("pids")
            .split_whitespace()
            .next()
            .and_then(|pid| pid.parse().ok())
            .expect("pid")
    }

    /// A fake model server on `listener`: `GET /health` answers "ok", and a decision
    /// answers with the model `fake-base-v1`. It stops when `stop` is set.
    fn serve_fake_model(
        listener: std::net::TcpListener,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> thread::JoinHandle<()> {
        listener.set_nonblocking(true).expect("nonblocking");
        thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(20));
                    continue;
                };
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let end = loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                    if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(at + 4);
                    }
                };
                let Some(end) = end else { continue };
                let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while raw.len() < end + length {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let body = if head.starts_with("get /health") {
                    r#"{"status":"ok"}"#
                } else {
                    r#"{"model":"fake-base-v1","answers":{"ready":{"type":"noul","noul":0.5}}}"#
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        })
    }

    /// A layout whose `start.sh` writes the PIDs of its group to `pids` and waits, with a
    /// Laya environment for the zero-shot model.
    fn fake_server_layout(dir: &Path, pids: &Path) -> Layout {
        let layout = layout(dir);
        executable(
            layout.script.as_deref().expect("script"),
            &format!("sleep 60 &\necho \"$$ $!\" > '{}'\nwait\n", pids.display()),
        );
        executable(&layout.python(), "#!/bin/sh\n");
        executable(&layout.laya_serve(), "#!/bin/sh\n");
        layout
    }

    /// "When a run needs it" stops a server that Apassy started after "Stop after"
    /// without a run. The whole process group of the server stops.
    #[test]
    fn the_idle_stop_ends_the_process_group_of_its_own_server() {
        let dir = TempDir::new().expect("temp dir");
        let pids = dir.path().join("pids");
        let port = free_port();
        let server = ModelServer::start_for_test(
            BouncerSettings {
                start: StartMode::WhenNeeded,
                idle_minutes: 10,
                url: Some(format!("http://127.0.0.1:{port}")),
            },
            fake_server_layout(dir.path(), &pids),
            Host::none(),
            Some(Duration::from_secs(1)),
            FIRST_START_WAIT,
        );
        server.start_now();
        wait_until(Duration::from_secs(10), "the script starts", || {
            pids.is_file()
        });
        // The model answers only after Apassy started the script, so it is Apassy's.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).expect("bind");
        let fake = serve_fake_model(listener, Arc::clone(&stop));
        wait_until(Duration::from_secs(10), "the server runs", || {
            matches!(server.state(), ServerState::Running { .. })
        });
        assert_eq!(
            server.state(),
            ServerState::Running {
                model: Some("fake-base-v1".to_owned()),
                outside: false
            }
        );
        assert!(server.status().owned);
        let pgid = first_pid(&pids);
        assert!(group_alive(pgid));

        // No run for 1 second: the monitor (each 2 seconds) stops it.
        wait_until(Duration::from_secs(15), "the idle stop", || {
            server.state() == ServerState::Stopped && !server.status().owned
        });
        wait_until(Duration::from_secs(5), "the process group ends", || {
            !group_alive(pgid)
        });
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        fake.join().expect("fake server");
        server.shutdown();
    }

    /// Without the base weights in the Hugging Face cache, a start downloads them. The
    /// run waits longer for that start, then waits for the owner with a clear reason.
    /// Later runs do not wait again while the download goes on.
    #[test]
    fn a_first_start_without_the_weights_waits_longer_then_asks_the_owner() {
        let dir = TempDir::new().expect("temp dir");
        let pids = dir.path().join("pids");
        let hub = dir.path().join("hub");
        let port = free_port();
        let server = ModelServer::start_for_test(
            BouncerSettings {
                start: StartMode::WhenNeeded,
                idle_minutes: 10,
                url: Some(format!("http://127.0.0.1:{port}")),
            },
            fake_server_layout(dir.path(), &pids),
            Host {
                uv_dirs: Vec::new(),
                launch_agents: None,
                hf_cache: Some(hub.clone()),
            },
            None,
            Duration::from_millis(800),
        );
        assert!(!server.status().weights_cached);
        let began = Instant::now();
        assert_eq!(server.before_model(), Err(DOWNLOAD_REASON.to_owned()));
        let waited = began.elapsed();
        assert!(
            waited >= Duration::from_millis(800) && waited < Duration::from_secs(5),
            "{waited:?}"
        );
        assert!(matches!(server.state(), ServerState::Starting { .. }));
        assert!(server.status().owned, "the download goes on");

        let began = Instant::now();
        assert_eq!(server.before_model(), Err(DOWNLOAD_REASON.to_owned()));
        assert!(
            began.elapsed() < Duration::from_millis(300),
            "no second wait"
        );

        // The download ends: the weights are in the cache.
        let snapshot = hub
            .join("models--convaiinnovations--laya/snapshots")
            .join(BASE_REVISION);
        fs::create_dir_all(&snapshot).expect("dir");
        fs::write(snapshot.join("model.safetensors"), b"weights").expect("write");
        fs::write(snapshot.join("rl_agent_config.json"), b"{}").expect("write");
        assert!(server.status().weights_cached);

        wait_until(Duration::from_secs(5), "the script starts", || {
            pids.is_file()
        });
        let pgid = first_pid(&pids);

        // The server answers after the download: the next run uses the model at once.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener = std::net::TcpListener::bind(("127.0.0.1", port)).expect("bind");
        let fake = serve_fake_model(listener, Arc::clone(&stop));
        wait_until(Duration::from_secs(10), "the server runs", || {
            matches!(server.state(), ServerState::Running { outside: false, .. })
        });
        let began = Instant::now();
        assert_eq!(server.before_model(), Ok(()));
        assert!(began.elapsed() < Duration::from_secs(1), "no wait");

        // After a stop, a run takes the normal path: the weights are in the cache.
        server.stop();
        wait_until(Duration::from_secs(10), "the process group ends", || {
            !group_alive(pgid)
        });
        assert_eq!(server.before_model(), Ok(()));
        assert!(matches!(server.state(), ServerState::Running { .. }));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        fake.join().expect("fake server");
        server.shutdown();
    }

    /// A run that waits for a first start, then for the owner, ends before the hosts
    /// stop the tool call: 180 s in the commands of `apassy setup`.
    #[test]
    fn a_run_that_waits_for_a_first_start_ends_within_the_tool_time_out() {
        let setup =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/setup.rs"))
                .expect("setup.rs");
        assert!(setup.contains("MCP_TOOL_TIMEOUT=180000"), "Claude Code");
        assert!(setup.contains("tool_timeout_sec = 180"), "Codex");
        let host_limit = Duration::from_secs(180);
        let owner_wait = crate::broker::server::BrokerOptions::with_tls(
            crate::broker::http::TlsClient::platform().expect("tls"),
        )
        .approval_timeout;
        // Time for the hook, the request checks, and the answer of the model.
        let margin = Duration::from_secs(10);
        for gate in [NEEDED_WAIT, FIRST_START_WAIT] {
            assert!(
                gate + owner_wait + margin <= host_limit,
                "{gate:?} + {owner_wait:?} + {margin:?} > {host_limit:?}"
            );
        }
    }

    /// A failed download of the weights after a complete environment: the install
    /// fails with a note, the "missing environment" state goes, and "With Apassy"
    /// starts the server, which downloads the weights.
    #[test]
    fn a_failed_weights_download_still_starts_the_server_with_apassy() {
        let dir = TempDir::new().expect("temp dir");
        let pids = dir.path().join("pids");
        let layout = layout(dir.path());
        let script = layout.script.clone().expect("script");
        executable(
            &script,
            &format!("sleep 60 &\necho \"$$ $!\" > '{}'\nwait\n", pids.display()),
        );
        fs::write(script.with_file_name(FETCH_SCRIPT), "# fake\n").expect("write");
        let server = ModelServer::start_for_test(
            BouncerSettings {
                start: StartMode::WithApassy,
                url: Some(format!("http://127.0.0.1:{}", free_port())),
                ..BouncerSettings::default()
            },
            layout,
            Host {
                hf_cache: Some(dir.path().join("hub")),
                ..fake_uv_with_fetch(dir.path(), false, false)
            },
            None,
            FIRST_START_WAIT,
        );
        wait_until(Duration::from_secs(5), "the missing environment", || {
            matches!(
                server.state(),
                ServerState::Failed {
                    problem: Problem::NoVenv { .. },
                    ..
                }
            )
        });
        server.install().expect("install");
        let InstallState::Failed { reason, log_tail } = wait_install(&server) else {
            panic!("{:?}", server.install_state());
        };
        assert!(reason.starts_with(FETCH_LABEL), "{reason}");
        assert!(reason.ends_with(WEIGHTS_LATER), "{reason}");
        assert!(
            log_tail.iter().any(|line| line.contains("503")),
            "{log_tail:?}"
        );
        let status = server.status();
        assert!(status.venv_ready && status.preflight.is_ok());
        assert!(!status.weights_cached);
        assert!(status.uv.is_some(), "the install can run again");
        wait_until(Duration::from_secs(10), "the server starts", || {
            pids.is_file()
        });
        assert!(
            matches!(server.state(), ServerState::Starting { .. }),
            "{:?}",
            server.state()
        );
        let pgid = first_pid(&pids);
        server.shutdown();
        assert!(!group_alive(pgid));
    }

    /// The fetch script and the server import `common.py` without a `__pycache__` next
    /// to them: in Apassy.app it would break the code signature.
    #[test]
    fn the_python_scripts_write_no_bytecode_next_to_them() {
        let tools = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/basemodel");
        let serve = fs::read_to_string(tools.join("serve.py")).expect("serve.py");
        let at = |text: &str| serve.find(text).expect(text);
        assert!(at("sys.dont_write_bytecode = True") < at("import common"));

        // The Python of Apple keeps its bytecode in ~/Library/Caches, so Homebrew first.
        let Some(python) = [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
        ]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file()) else {
            eprintln!("skipped: no python3 on this Mac");
            return;
        };
        let run = |args: &[&OsStr], home: &Path, pythonpath: &Path| {
            Command::new(python)
                .args(args)
                .env_clear()
                .env("HOME", home)
                .env("PYTHONPATH", pythonpath)
                .current_dir(home)
                .output()
                .expect("python3")
        };
        // A control: this Python writes `__pycache__` next to an imported module.
        let control = TempDir::new().expect("temp dir");
        fs::write(control.path().join("control.py"), "X = 1\n").expect("write");
        run(
            &[OsStr::new("-c"), OsStr::new("import control")],
            control.path(),
            control.path(),
        );
        if !control.path().join("__pycache__").is_dir() {
            eprintln!("skipped: {} writes no __pycache__", python.display());
            return;
        }
        let dir = TempDir::new().expect("temp dir");
        let bundle = dir.path().join("Resources/tools/basemodel");
        fs::create_dir_all(&bundle).expect("dir");
        for name in [FETCH_SCRIPT, "common.py"] {
            fs::copy(tools.join(name), bundle.join(name)).expect("copy");
        }
        // A fake `huggingface_hub`: the download gives a folder with the weights.
        let fake = dir.path().join("fake");
        let snapshot = dir.path().join("snapshot");
        fs::create_dir_all(fake.join("huggingface_hub")).expect("dir");
        fs::create_dir_all(&snapshot).expect("dir");
        fs::write(snapshot.join("model.safetensors"), b"weights").expect("write");
        fs::write(
            fake.join("huggingface_hub/__init__.py"),
            format!(
                "def snapshot_download(repo, revision=None, allow_patterns=None, token=None):\n    return {:?}\n",
                snapshot.to_string_lossy()
            ),
        )
        .expect("write");
        // No `-B` here: the script itself keeps the bundle clean.
        let script = bundle.join(FETCH_SCRIPT);
        let output = run(&[script.as_os_str()], dir.path(), &fake);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(&format!("fetch: {BASE_REPO} at {BASE_REVISION}")),
            "{stdout}"
        );
        assert!(
            !bundle.join("__pycache__").exists(),
            "no bytecode in the bundle"
        );
    }

    #[test]
    fn the_base_weights_are_found_in_the_hugging_face_cache() {
        let home = Path::new("/Users/someone");
        let default = home.join(".cache/huggingface/hub");
        assert_eq!(hf_hub_cache(Some(home), None, None), Some(default.clone()));
        assert_eq!(
            hf_hub_cache(Some(home), Some(OsStr::new("")), Some(OsStr::new(""))),
            Some(default)
        );
        assert_eq!(
            hf_hub_cache(Some(home), None, Some(OsStr::new("/hf"))),
            Some(PathBuf::from("/hf/hub"))
        );
        assert_eq!(
            hf_hub_cache(
                Some(home),
                Some(OsStr::new("/hub")),
                Some(OsStr::new("/hf"))
            ),
            Some(PathBuf::from("/hub"))
        );
        assert_eq!(hf_hub_cache(None, None, None), None);

        let dir = TempDir::new().expect("temp dir");
        let hub = dir.path().join("hub");
        assert!(!weights_cached(&hub, false));
        assert!(!weights_cached(&hub, true));
        let repo = hub.join("models--convaiinnovations--laya");
        let snapshot = |revision: &str, files: &[&str]| {
            let dir = repo.join("snapshots").join(revision);
            fs::create_dir_all(&dir).expect("dir");
            for file in files {
                fs::write(dir.join(file), b"x").expect("write");
            }
        };
        // `laya-serve` downloads `main`. Only the zero-shot model uses it.
        snapshot("0123abcd", &["model.safetensors", "rl_agent_config.json"]);
        fs::create_dir_all(repo.join("refs")).expect("dir");
        fs::write(repo.join("refs/main"), "0123abcd\n").expect("write");
        assert!(weights_cached(&hub, true));
        assert!(!weights_cached(&hub, false));
        fs::write(repo.join("refs/main"), "../0123abcd").expect("write");
        assert!(!weights_cached(&hub, true), "a path is not a revision");
        // The pinned revision needs the weights and the config.
        snapshot(BASE_REVISION, &["model.safetensors"]);
        assert!(!weights_cached(&hub, false));
        snapshot(BASE_REVISION, &["rl_agent_config.json"]);
        assert!(weights_cached(&hub, false));
        assert!(weights_cached(&hub, true));

        // The server and the fetch script pin the same repository and revision.
        let tools = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/basemodel");
        let common = fs::read_to_string(tools.join("common.py")).expect("common.py");
        assert!(
            common.contains(&format!("BASE_REPO = \"{BASE_REPO}\"")),
            "{common}"
        );
        assert!(
            common.contains(&format!("BASE_REVISION = \"{BASE_REVISION}\"")),
            "{common}"
        );
        let fetch = fs::read_to_string(tools.join(FETCH_SCRIPT)).expect("fetch script");
        assert!(fetch.contains("common.base_dir()"), "{fetch}");
    }

    /// "Install the model" downloads the base weights as its own last step, with the
    /// Python of the environment. A failed download fails the install with the log.
    #[test]
    fn the_install_downloads_the_weights_as_its_own_step() {
        let dir = TempDir::new().expect("temp dir");
        let layout = layout(dir.path());
        let script = layout.script.clone().expect("script");
        executable(&script, "#!/bin/bash\n");
        let fetch = script.with_file_name(FETCH_SCRIPT);
        fs::write(&fetch, "# fake\n").expect("write");
        let started = dir.path().join("started");
        let go = dir.path().join("go");
        let fail = dir.path().join("fail");
        // An environment with a Python: the install skips `uv venv`. The fake Python
        // waits for `go`, so the test sees the step.
        executable(
            &layout.python(),
            &format!(
                "#!/bin/sh\necho \"fake python $*\"\ntouch '{}'\nwhile [ ! -f '{}' ]; do sleep 0.05; done\nif [ -f '{}' ]; then echo 'fetch: 401 Unauthorized'; exit 1; fi\n",
                started.display(),
                go.display(),
                fail.display()
            ),
        );
        let server = ModelServer::start_with_host(
            None,
            BouncerSettings::default(),
            layout.clone(),
            fake_uv(dir.path(), false),
        );
        server.install().expect("install");
        wait_until(Duration::from_secs(10), "the download starts", || {
            started.is_file()
        });
        assert!(
            matches!(
                server.install_state(),
                InstallState::Installing {
                    step: 2,
                    of: 2,
                    label: FETCH_LABEL,
                    ..
                }
            ),
            "{:?}",
            server.install_state()
        );
        fs::write(&go, b"").expect("write");
        assert_eq!(wait_install(&server), InstallState::Done);
        let log = fs::read_to_string(layout.install_log()).expect("log");
        assert!(
            log.contains(&format!("fake python -B {}", fetch.display())),
            "{log}"
        );

        fs::write(&fail, b"").expect("write");
        server.install().expect("again");
        let InstallState::Failed { reason, log_tail } = wait_install(&server) else {
            panic!("{:?}", server.install_state());
        };
        // The environment is complete, so the reason says that the server downloads
        // the weights.
        assert!(reason.starts_with(FETCH_LABEL), "{reason}");
        assert!(reason.ends_with(WEIGHTS_LATER), "{reason}");
        assert!(server.status().uv.is_some(), "the install can run again");
        assert!(
            log_tail
                .iter()
                .any(|line| line.contains("401 Unauthorized")),
            "{log_tail:?}"
        );
        server.shutdown();
    }
}
