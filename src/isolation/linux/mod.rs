//! The Linux sandbox: bubblewrap with new namespaces and a mount plan (decision D7 of
//! [the s5 plan](../../../docs/design/implementation-plan-s5-env-0011.md), unit X1).
//!
//! ```no_run
//! # use std::path::Path;
//! use apassy::isolation::linux::{HostPaths, HostRelay, NetPlan, Sandbox};
//! # fn run(proxy: std::net::SocketAddr, project: &Path, init: &Path) -> Result<(), Box<dyn std::error::Error>> {
//! // The run proxy listens on `proxy` (127.0.0.1). Inside the sandbox the run gets
//! // the same port, and nothing else.
//! let relay = HostRelay::start(proxy)?;
//! let sandbox = Sandbox::for_run(&HostPaths::from_env()?, project)?
//!     .net(NetPlan::Bridged(vec![relay.bridge(proxy.port())]))
//!     .init_program(init)
//!     .env("PATH", "/usr/bin:/bin")
//!     .build()?;
//! let status = sandbox.command("curl", ["-sS", "https://api.example.com/"]).status()?;
//! # let _ = status; Ok(()) }
//! ```
//!
//! - [`probe()`] says whether bubblewrap works here; [`Availability::report`] is the
//!   `network.rule` of a run (`netns`, or `none` with the reason and the fix).
//! - [`Sandbox::builder`] and [`Sandbox::for_run`] make the bubblewrap command.
//! - [`bridge_main`] is the init and bridge inside the sandbox; [`HostRelay`] is
//!   the host end of a bridge.
//!
//! Only `std`, `serde`, `serde_json`, and `rustix` (the real user id), and no
//! `unsafe`. The facts, the profile,
//! and the limits are in `docs/operations/isolation-linux.md`.

mod bridge;
mod bwrap;
mod probe;

pub use bridge::{
    BRIDGE_ARG, EXIT_CANNOT_RUN, EXIT_NOT_FOUND, EXIT_SETUP, HostRelay, bridge_main, is_bridge_call,
};
pub use bwrap::{INTERNAL_DIR, SYSTEM_SOCKETS};
pub use probe::{
    Availability, BWRAP_PATHS, MIN_VERSION, RULE_NETNS, RULE_NONE, RuleReport, Version, find_bwrap,
    probe, probe_with,
};

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Variables that point at services of the user's session outside the sandbox: the
/// session and system bus, the SSH and GPG agents, the keyring, the display, and
/// the owner's command-line session (ADR 0017). A sandbox never gets them, also
/// when the caller sets them.
pub const SESSION_VARIABLES: [&str; 13] = [
    "DBUS_SESSION_BUS_ADDRESS",
    "DBUS_SYSTEM_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "GNOME_KEYRING_CONTROL",
    "GNOME_KEYRING_PID",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "KRB5CCNAME",
    "APASSY_SESSION",
];

/// The temporary folder of every sandbox: its private `/tmp`.
pub const SANDBOX_TMPDIR: &str = "/tmp";

/// The network of a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetPlan {
    /// A new network namespace with only `lo`. Each bridge listens on
    /// `127.0.0.1:<inside>` in the namespace and leads to its Unix socket on the
    /// host. Without a bridge the sandbox has no network at all.
    Bridged(Vec<Bridge>),
    /// The network of the host: no network rule. For the agent-host launcher (X3),
    /// where the host keeps its network, as on macOS.
    Host,
}

/// One way out of a network namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge {
    /// The port on `127.0.0.1` inside the namespace.
    pub inside: u16,
    /// The Unix socket on the host (a [`HostRelay`]).
    pub outside: PathBuf,
}

/// What the sandbox sees of the user's home folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomePolicy {
    /// An empty, private, writable tmpfs at the same path. Allowed paths in the
    /// home (the project) are bound into it. The default of a run: what is not
    /// named is not there, so no list of credential stores can miss one.
    Hidden,
    /// The real home, read-only, with the deny list on top.
    ReadOnly,
}

/// Why a sandbox cannot be built. No variant holds a value of the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    /// bubblewrap cannot run here; see [`Availability::report`].
    Unavailable(Availability),
    /// No init program: the program that answers [`BRIDGE_ARG`].
    NoInitProgram,
    /// `HOME` is not set or not absolute.
    NoHome,
    NotAbsolute(PathBuf),
    Missing(PathBuf),
    NotAFile(PathBuf),
    NotASocket(PathBuf),
    /// An allowed path is in a denied one.
    InsideDenied {
        path: PathBuf,
        denied: PathBuf,
    },
    /// An allowed path or the home holds a hidden folder (`/`, `/home`, `/tmp`,
    /// `/var`, `/run`, `/root`): binding it would show what the plan hides.
    AboveHidden(PathBuf),
    /// A path in `/proc`, `/dev`, or the sandbox's own folder.
    NeverAllowed(PathBuf),
    /// A bridge port that is 0 or used twice.
    BadPort(u16),
    /// The working directory would not exist in the sandbox.
    CwdHidden(PathBuf),
    /// An environment variable name or value that a process cannot have.
    BadEnv(String),
    /// The vault list cannot be read, so a vault file may be unknown.
    VaultList(String),
    /// The working directory of a run is in a shared folder (`/tmp`, `/var/tmp`,
    /// `/run`, `/dev/shm`), is the home folder, or holds a denied path. The text
    /// names the folder to use instead.
    UnsafeWorkDir(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxError::Unavailable(found) => {
                let report = found.report();
                write!(
                    f,
                    "the Linux sandbox cannot run here: {}. {}",
                    report.detail.as_deref().unwrap_or("unknown"),
                    report.fix.unwrap_or("")
                )
            }
            SandboxError::NoInitProgram => write!(f, "the sandbox has no init program"),
            SandboxError::NoHome => write!(f, "HOME is not set to an absolute path"),
            SandboxError::NotAbsolute(path) => write!(f, "{} is not absolute", path.display()),
            SandboxError::Missing(path) => write!(f, "{} does not exist", path.display()),
            SandboxError::NotAFile(path) => write!(f, "{} is not a file", path.display()),
            SandboxError::NotASocket(path) => write!(f, "{} is not a socket", path.display()),
            SandboxError::InsideDenied { path, denied } => write!(
                f,
                "{} is inside the denied path {}",
                path.display(),
                denied.display()
            ),
            SandboxError::AboveHidden(path) => write!(
                f,
                "{} holds a folder that the sandbox hides (/home, /tmp, /run, /root, /var/tmp)",
                path.display()
            ),
            SandboxError::NeverAllowed(path) => {
                write!(f, "{} cannot be given to a sandbox", path.display())
            }
            SandboxError::BadPort(port) => write!(f, "bad or repeated bridge port {port}"),
            SandboxError::CwdHidden(path) => write!(
                f,
                "the working directory {} is not visible in the sandbox",
                path.display()
            ),
            SandboxError::BadEnv(name) => write!(f, "bad environment variable {name}"),
            SandboxError::VaultList(message) | SandboxError::UnsafeWorkDir(message) => {
                write!(f, "{message}")
            }
        }
    }
}

impl std::error::Error for SandboxError {}

/// The plan of a sandbox. Each path is absolute; the builder resolves symlinks.
#[derive(Default)]
pub struct Builder {
    bwrap: Option<PathBuf>,
    init: Option<PathBuf>,
    net: Option<NetPlan>,
    home: Option<(PathBuf, HomePolicy)>,
    deny: Vec<PathBuf>,
    read_only: Vec<PathBuf>,
    rw: Vec<PathBuf>,
    sockets: Vec<PathBuf>,
    cwd: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
}

impl fmt::Debug for Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Builder")
            .field("bwrap", &self.bwrap)
            .field("init", &self.init)
            .field("net", &self.net)
            .field("home", &self.home)
            .field("deny", &self.deny)
            .field("read_only", &self.read_only)
            .field("rw", &self.rw)
            .field("sockets", &self.sockets)
            .field("cwd", &self.cwd)
            .field("env", &EnvNames(&self.env))
            .finish()
    }
}

/// Prints the names of the variables only.
struct EnvNames<'a>(&'a [(OsString, OsString)]);

impl fmt::Debug for EnvNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

impl Builder {
    /// The bubblewrap program. Default: the one that [`probe`] found ready.
    pub fn bwrap(mut self, program: impl Into<PathBuf>) -> Self {
        self.bwrap = Some(program.into());
        self
    }

    /// The program that answers [`BRIDGE_ARG`] with [`bridge_main`]: PID 1 of the
    /// sandbox. It is bound read-only into the sandbox, so its own folder may be
    /// hidden. Required.
    pub fn init_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.init = Some(program.into());
        self
    }

    /// The network. Default: [`NetPlan::Bridged`] with no bridge, which is no
    /// network at all.
    pub fn net(mut self, plan: NetPlan) -> Self {
        self.net = Some(plan);
        self
    }

    /// The home folder and what the sandbox sees of it.
    pub fn home(mut self, dir: impl Into<PathBuf>, policy: HomePolicy) -> Self {
        self.home = Some((dir.into(), policy));
        self
    }

    /// Paths that the sandbox must not see. A path that does not exist when the
    /// sandbox is built is skipped.
    pub fn deny<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.deny.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Paths that the sandbox sees read-only, also in a hidden place.
    pub fn read_only<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.read_only.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Paths that the sandbox can change.
    pub fn rw<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.rw.extend(paths.into_iter().map(Into::into));
        self
    }

    /// A Unix socket that the sandbox may connect to, also inside a denied folder
    /// (the broker socket in the data folder, for the agent-host launcher).
    pub fn bind_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.sockets.push(path.into());
        self
    }

    /// The working directory in the sandbox. Default: `/`.
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// One environment variable of the program. The sandbox starts with an empty
    /// environment; [`SESSION_VARIABLES`] are dropped, and `TMPDIR` is always
    /// [`SANDBOX_TMPDIR`].
    pub fn env(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    /// More environment variables, as [`Builder::env`].
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        self.env.extend(
            vars.into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        self
    }

    /// Check the plan and make the sandbox.
    pub fn build(self) -> Result<Sandbox, SandboxError> {
        let bwrap = match self.bwrap {
            Some(program) => program,
            None => match probe() {
                Availability::Ready { program, .. } => program,
                other => return Err(SandboxError::Unavailable(other)),
            },
        };
        let init = self.init.ok_or(SandboxError::NoInitProgram)?;
        let net = self.net.unwrap_or(NetPlan::Bridged(Vec::new()));
        let cwd = self.cwd.unwrap_or_else(|| PathBuf::from("/"));
        let args = bwrap::arguments(&bwrap::Spec {
            init: &init,
            net: &net,
            home: self
                .home
                .as_ref()
                .map(|(dir, policy)| (dir.as_path(), *policy)),
            deny: &self.deny,
            read_only: &self.read_only,
            rw: &self.rw,
            sockets: &self.sockets,
            cwd: &cwd,
        })?;
        let env = sandbox_env(self.env)?;
        Ok(Sandbox {
            bwrap,
            args,
            env,
            rule: match net {
                NetPlan::Bridged(_) => RULE_NETNS,
                NetPlan::Host => RULE_NONE,
            },
        })
    }
}

/// SECURITY (judge panel): the environment goes to bubblewrap as its environment,
/// never as `--setenv` arguments: the arguments of a process are readable by every
/// user (`/proc/<pid>/cmdline`), its environment only by its user.
fn sandbox_env(vars: Vec<(OsString, OsString)>) -> Result<Vec<(OsString, OsString)>, SandboxError> {
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    for (name, value) in vars {
        let bytes = name.as_encoded_bytes();
        if bytes.is_empty() || bytes.contains(&b'=') || bytes.contains(&0) {
            return Err(SandboxError::BadEnv(name.to_string_lossy().into_owned()));
        }
        if value.as_encoded_bytes().contains(&0) {
            return Err(SandboxError::BadEnv(name.to_string_lossy().into_owned()));
        }
        if SESSION_VARIABLES.iter().any(|session| name == *session) || name == "TMPDIR" {
            continue;
        }
        // The last value of a name wins, as in `Command::env`.
        out.retain(|(seen, _)| *seen != name);
        out.push((name, value));
    }
    out.push(("TMPDIR".into(), SANDBOX_TMPDIR.into()));
    Ok(out)
}

/// A checked bubblewrap command line. Its `Debug` shows the variable names only.
#[derive(Clone)]
pub struct Sandbox {
    bwrap: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    rule: &'static str,
}

impl fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sandbox")
            .field("bwrap", &self.bwrap)
            .field("args", &self.args)
            .field("env", &EnvNames(&self.env))
            .field("rule", &self.rule)
            .finish()
    }
}

impl Sandbox {
    /// An empty plan.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// The default plan of a proxied run (ADR 0011 stage 2): `/` read-only, the
    /// home hidden ([`HomePolicy::Hidden`]), `project` writable and the working
    /// directory, a private `/tmp`, the deny list of `paths`
    /// ([`HostPaths::denied`]), no network until the caller adds a bridge. The
    /// caller adds the bridge, the init program, and the environment.
    ///
    /// SECURITY (judge panel, M1): a network namespace does not stop Unix sockets,
    /// so `project` must not be in `/tmp`, `/var/tmp`, `/run`, or `/dev/shm`, must
    /// not be the home folder, and must not hold a denied path
    /// ([`crate::isolation::run_paths::check_work_dir`]).
    pub fn for_run(paths: &HostPaths, project: &Path) -> Result<Builder, SandboxError> {
        let denied = paths.denied()?;
        check_run_dir(project, &paths.home, &denied)?;
        Ok(Sandbox::builder()
            .home(paths.home.clone(), HomePolicy::Hidden)
            .deny(denied)
            .rw([project])
            .cwd(project)
            .net(NetPlan::Bridged(Vec::new())))
    }

    /// The bubblewrap program.
    pub fn program(&self) -> &Path {
        &self.bwrap
    }

    /// The bubblewrap arguments before the program. They hold paths and ports only.
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// The `network.rule` of this sandbox: `netns`, or `none` with the host network.
    pub fn rule(&self) -> &'static str {
        self.rule
    }

    /// The bubblewrap command that runs `program` with `args` in the sandbox. The
    /// command has the sandbox environment and nothing else; the caller sets the
    /// standard streams. `program` is looked up with the sandbox `PATH`.
    pub fn command<I, S>(&self, program: impl AsRef<OsStr>, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(&self.bwrap);
        command.args(&self.args).arg(program).args(args).env_clear();
        for (name, value) in &self.env {
            command.env(name, value);
        }
        command
    }
}

/// The working directory of a run, checked with the resolved paths. A path that
/// cannot be resolved is checked as given; bubblewrap refuses a missing one later.
fn check_run_dir(project: &Path, home: &Path, denied: &[PathBuf]) -> Result<(), SandboxError> {
    use crate::isolation::run_paths;
    let real = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let cwd = real(project);
    let home = real(home);
    let denied: Vec<PathBuf> = denied
        .iter()
        .flat_map(|path| {
            let mut both = vec![path.clone()];
            both.extend(std::fs::canonicalize(path).ok());
            both
        })
        .collect();
    run_paths::check_work_dir(&cwd, &home, &run_paths::shared_roots(), &denied)
        .map_err(|refusal| SandboxError::UnsafeWorkDir(refusal.message(&cwd, &home)))
}

/// The paths of the user that a sandbox denies by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`, else `~/.config`.
    pub config_home: PathBuf,
    /// `$XDG_DATA_HOME`, else `~/.local/share`.
    pub data_home: PathBuf,
    /// `$XDG_RUNTIME_DIR`: the session bus, the keyring, the agent sockets.
    pub runtime_dir: Option<PathBuf>,
    /// The Apassy data folder ([`crate::paths::data_dir`]).
    pub data_dir: PathBuf,
}

impl HostPaths {
    /// The paths of this process's user.
    pub fn from_env() -> Result<HostPaths, SandboxError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_absolute())
            .ok_or(SandboxError::NoHome)?;
        let xdg = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|dir| dir.is_absolute())
        };
        Ok(HostPaths {
            config_home: xdg("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")),
            data_home: xdg("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local").join("share")),
            runtime_dir: xdg("XDG_RUNTIME_DIR"),
            data_dir: crate::paths::data_dir(),
            home,
        })
    }

    /// The default layout under `home`: `~/.config`, `~/.local/share`, the data
    /// folder `~/.local/share/apassy`, no runtime folder.
    pub fn under_home(home: &Path) -> HostPaths {
        let data_home = home.join(".local").join("share");
        HostPaths {
            home: home.to_owned(),
            config_home: home.join(".config"),
            data_dir: data_home.join("apassy"),
            data_home,
            runtime_dir: None,
        }
    }

    /// The Apassy configuration folder: `$XDG_CONFIG_HOME/apassy`.
    pub fn config_dir(&self) -> PathBuf {
        self.config_home.join("apassy")
    }

    /// The link file of a linked environment (decision D4 of the s5 plan).
    pub fn link_file(&self) -> PathBuf {
        self.config_dir().join("link.json")
    }

    /// The deny list: the Apassy data folder, its configuration with the link file,
    /// the runtime folder (`$XDG_RUNTIME_DIR` and always `/run/user/<real uid>`:
    /// the variable can point elsewhere), each vault of the vault list outside the data folder with
    /// its companion files, each synced vault file, the SSH and GPG keys, the
    /// cloud and container credentials, the keyrings, and the browser profiles. A vault list that cannot be read is an
    /// error: a vault file that the list names could then stay visible.
    pub fn denied(&self) -> Result<Vec<PathBuf>, SandboxError> {
        let mut paths = vec![self.data_dir.clone(), self.config_dir()];
        paths.extend(self.runtime_dir.clone());
        let own = crate::isolation::run_paths::runtime_dir_of(rustix::process::getuid().as_raw());
        if !paths.contains(&own) {
            paths.push(own);
        }
        paths.extend(listed_vault_files(&self.data_dir)?);
        for rel in HOME_DENIED {
            paths.push(self.home.join(rel));
        }
        for rel in DATA_HOME_DENIED {
            paths.push(self.data_home.join(rel));
        }
        for rel in CONFIG_HOME_DENIED {
            paths.push(self.config_home.join(rel));
        }
        Ok(paths)
    }
}

/// Keys, cloud and container credentials, keyrings, and browser and mail profiles
/// under the home folder.
const HOME_DENIED: [&str; 28] = [
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".config/gh",
    ".docker",
    ".kube",
    ".netrc",
    ".password-store",
    ".pki",
    ".kde/share/apps/kwallet",
    ".kde4/share/apps/kwallet",
    ".mozilla",
    ".librewolf",
    ".waterfox",
    ".thunderbird",
    "snap/firefox",
    "snap/chromium",
    "snap/thunderbird",
    ".var/app/org.mozilla.firefox",
    ".var/app/org.chromium.Chromium",
    ".var/app/com.google.Chrome",
    ".var/app/com.brave.Browser",
    ".var/app/com.microsoft.Edge",
    ".var/app/com.vivaldi.Vivaldi",
    ".var/app/io.gitlab.librewolf-community",
    ".var/app/org.mozilla.Thunderbird",
];

/// Keyrings under `$XDG_DATA_HOME`.
const DATA_HOME_DENIED: [&str; 2] = ["keyrings", "kwalletd"];

/// Credentials and browser profiles under `$XDG_CONFIG_HOME`.
const CONFIG_HOME_DENIED: [&str; 14] = [
    "gh",
    "gcloud",
    "google-chrome",
    "google-chrome-beta",
    "google-chrome-unstable",
    "chromium",
    "BraveSoftware",
    "microsoft-edge",
    "microsoft-edge-beta",
    "microsoft-edge-dev",
    "vivaldi",
    "opera",
    "net.imput.helium",
    "kwalletrc",
];

/// The files next to a vault or a synced file that hold its data.
const COMPANIONS: [&str; 6] = [
    "-wal",
    "-shm",
    "-journal",
    ".lock",
    ".backup",
    ".push.nosync",
];

/// The vault files of the vault list (ADR 0013) and the synced files (ADR 0014),
/// with their companions. A vault in the data folder is covered by the folder.
fn listed_vault_files(data_dir: &Path) -> Result<Vec<PathBuf>, SandboxError> {
    let registry = match crate::vaults::Registry::read(data_dir) {
        Ok(None) => return Ok(Vec::new()),
        Ok(Some(registry)) => registry,
        Err(err) => {
            return Err(SandboxError::VaultList(format!(
                "cannot use the vault list {}: {err}. The sandbox cannot hide a vault file that it does not know, so it does not start. Open Apassy once: it moves a damaged list aside and makes a new one.",
                crate::vaults::registry_path(data_dir).display()
            )));
        }
    };
    let mut files = Vec::new();
    for entry in registry.entries() {
        let mut bases = vec![entry.path.clone()];
        if entry.sync_state().is_some() {
            match entry.sync_file() {
                Some(file) => bases.push(file),
                None if entry.sync_relay().is_some() => {}
                None => {
                    return Err(SandboxError::VaultList(format!(
                        "the vault “{}” syncs, but the vault list has no valid synced file for it, so the sandbox does not start. In Apassy, turn its sync off and on again (Settings > Vault > Sync).",
                        entry.name
                    )));
                }
            }
        }
        for base in bases {
            if base.starts_with(data_dir) {
                continue;
            }
            for suffix in COMPANIONS {
                let mut name = base.clone().into_os_string();
                name.push(suffix);
                files.push(PathBuf::from(name));
            }
            files.push(base);
        }
    }
    Ok(files)
}

/// Temporary folders for the unit tests of this module, with `std` only.
#[cfg(test)]
pub(crate) mod test_dir {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new(name: &str) -> TestDir {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "apassy-isotest-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("test folder");
            TestDir(dir)
        }

        /// A test folder outside the shared folders (`/tmp`), for the working
        /// directory of a run: in the `target` folder of the crate.
        pub(crate) fn outside_tmp(name: &str) -> TestDir {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("tmp")
                .join(format!(
                    "apassy-isotest-{name}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("test folder");
            TestDir(fs::canonicalize(&dir).expect("canonical test folder"))
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        pub(crate) fn mkdir(&self, rel: &str) -> PathBuf {
            let dir = self.0.join(rel);
            fs::create_dir_all(&dir).expect("test sub-folder");
            dir
        }

        pub(crate) fn file(&self, rel: &str, text: &str) -> PathBuf {
            let path = self.0.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("test sub-folder");
            }
            fs::write(&path, text).expect("test file");
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_dir::TestDir;
    use super::*;
    use std::fs;

    const PLACEHOLDER: &str = "apassy-placeholder-SYNTHETIC-0001";

    fn base(dir: &TestDir) -> Builder {
        let project = dir.mkdir("project");
        Sandbox::builder()
            .bwrap("/usr/bin/bwrap")
            .init_program("/bin/sh")
            .rw([&project])
            .cwd(&project)
    }

    /// SECURITY (judge panel): values reach bubblewrap only through its environment.
    #[test]
    fn the_environment_is_never_in_the_arguments() {
        let dir = TestDir::new("env-args");
        let sandbox = base(&dir)
            .env("API_TOKEN", PLACEHOLDER)
            .env(
                "HTTPS_PROXY",
                "http://apassy:proxy-password-SYNTHETIC@127.0.0.1:9",
            )
            .build()
            .expect("sandbox");
        for arg in sandbox.args() {
            let arg = arg.to_string_lossy();
            assert!(!arg.contains(PLACEHOLDER), "{arg}");
            assert!(!arg.contains("proxy-password"), "{arg}");
            assert!(!arg.starts_with("--setenv"), "{arg}");
        }
        let command = sandbox.command("curl", ["https://api.example.com/"]);
        let envs: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(envs.contains(&("API_TOKEN".to_owned(), Some(PLACEHOLDER.to_owned()))));
        let shown = format!("{sandbox:?}");
        assert!(!shown.contains(PLACEHOLDER), "{shown}");
        assert!(!shown.contains("proxy-password"), "{shown}");
        assert!(shown.contains("API_TOKEN"));
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            &args[args.len() - 3..],
            &["--", "curl", "https://api.example.com/"]
        );
        assert_eq!(sandbox.rule(), RULE_NETNS);
    }

    #[test]
    fn session_variables_never_reach_the_sandbox_and_tmpdir_is_private() {
        let dir = TestDir::new("env-session");
        let sandbox = base(&dir)
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
            .env("SSH_AUTH_SOCK", "/run/user/1000/ssh")
            .env("XDG_RUNTIME_DIR", "/run/user/1000")
            .env("APASSY_SESSION", "owner-session")
            .env("TMPDIR", "/run/user/1000/tmp")
            .env("LANG", "C")
            .env("LANG", "C.UTF-8")
            .build()
            .expect("sandbox");
        let command = sandbox.command("true", Vec::<&str>::new());
        let names: Vec<String> = command
            .get_envs()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        for session in SESSION_VARIABLES {
            assert!(!names.iter().any(|name| name == session), "{session}");
        }
        let get = |wanted: &str| {
            command
                .get_envs()
                .find(|(name, _)| *name == wanted)
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned())
        };
        assert_eq!(get("TMPDIR").as_deref(), Some("/tmp"));
        assert_eq!(get("LANG").as_deref(), Some("C.UTF-8"));
        assert_eq!(names.iter().filter(|name| *name == "LANG").count(), 1);
    }

    #[test]
    fn bad_variables_and_a_missing_init_are_refused() {
        let dir = TestDir::new("env-bad");
        for (name, value) in [("", "x"), ("A=B", "x"), ("A\0", "x"), ("A", "x\0y")] {
            let err = base(&dir).env(name, value).build().expect_err(name);
            assert!(matches!(err, SandboxError::BadEnv(_)), "{err:?}");
        }
        let project = dir.mkdir("project");
        let err = Sandbox::builder()
            .bwrap("/usr/bin/bwrap")
            .rw([&project])
            .build()
            .expect_err("no init");
        assert_eq!(err, SandboxError::NoInitProgram);
        let host = base(&dir).net(NetPlan::Host).build().expect("host");
        assert_eq!(host.rule(), RULE_NONE);
    }

    #[test]
    fn host_paths_follow_xdg_and_name_the_link_file() {
        let paths = HostPaths::under_home(Path::new("/home/dev"));
        assert_eq!(paths.config_dir(), Path::new("/home/dev/.config/apassy"));
        assert_eq!(
            paths.link_file(),
            Path::new("/home/dev/.config/apassy/link.json")
        );
        assert_eq!(paths.data_dir, Path::new("/home/dev/.local/share/apassy"));
        let denied = paths.denied().expect("no vault list");
        for wanted in [
            "/home/dev/.local/share/apassy",
            "/home/dev/.config/apassy",
            "/home/dev/.ssh",
            "/home/dev/.gnupg",
            "/home/dev/.local/share/keyrings",
            "/home/dev/.mozilla",
            "/home/dev/.config/google-chrome",
            "/home/dev/.config/chromium",
            "/home/dev/.config/BraveSoftware",
            "/home/dev/.aws",
            "/home/dev/.azure",
            "/home/dev/.config/gh",
            "/home/dev/.config/gcloud",
            "/home/dev/.docker",
            "/home/dev/.kube",
            "/home/dev/.netrc",
        ] {
            assert!(denied.contains(&PathBuf::from(wanted)), "{wanted}");
        }
        // The runtime folder of the real user, also without XDG_RUNTIME_DIR.
        let own = PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()));
        assert!(denied.contains(&own), "{denied:?}");
        let with_runtime = HostPaths {
            runtime_dir: Some(PathBuf::from("/run/user/1000")),
            ..paths
        };
        assert!(
            with_runtime
                .denied()
                .expect("denied")
                .contains(&PathBuf::from("/run/user/1000"))
        );
    }

    /// SECURITY (judge panel, M1): a run never works in a shared folder, in the home
    /// folder itself, or above a denied path; the error names the folder to use.
    #[test]
    fn a_run_refuses_a_shared_folder_the_home_and_a_folder_above_a_denied_path() {
        let shared = TestDir::new("run-in-tmp");
        let outside = TestDir::outside_tmp("run-dirs");
        let home = outside.mkdir("home");
        let project = outside.mkdir("home/projects/app");
        outside.mkdir("home/.config/apassy");
        let paths = HostPaths::under_home(&home);
        let refused = |dir: &Path| match Sandbox::for_run(&paths, dir) {
            Err(SandboxError::UnsafeWorkDir(text)) => text,
            other => panic!(
                "expected UnsafeWorkDir for {}, got {other:?}",
                dir.display()
            ),
        };
        let text = refused(shared.path());
        assert!(text.contains("/tmp"), "{text}");
        assert!(text.contains("projects"), "{text}");
        let text = refused(&home);
        assert!(text.contains("home folder"), "{text}");
        let text = refused(&home.join(".config"));
        assert!(text.contains(".config/apassy"), "{text}");
        assert!(Sandbox::for_run(&paths, &project).is_ok());
    }

    /// ADR 0013 and 0014: a vault outside the data folder, its companions, and a
    /// synced file are denied; a damaged list fails closed.
    #[test]
    fn listed_vaults_outside_the_data_folder_are_denied_and_a_damaged_list_fails_closed() {
        let dir = TestDir::new("vault-list");
        let home = dir.mkdir("home");
        let paths = HostPaths::under_home(&home);
        fs::create_dir_all(&paths.data_dir).expect("data dir");
        let outside = dir.path().join("elsewhere").join("work.db");
        let inside = paths.data_dir.join("vaults").join("personal.db");
        let dropbox = dir.path().join("Dropbox");
        let mut registry = crate::vaults::Registry::new();
        registry.add("Personal", &inside, 1).expect("add");
        let id = registry.add("Work", &outside, 1).expect("add");
        registry.entry_mut(&id).expect("entry").sync =
            Some(crate::vaults::SyncLink::new(&id, &dropbox, "work.apassy"));
        registry.save(&paths.data_dir).expect("save");
        let denied = paths.denied().expect("denied");
        assert!(denied.contains(&outside));
        let mut wal = outside.clone().into_os_string();
        wal.push("-wal");
        assert!(denied.contains(&PathBuf::from(wal)));
        assert!(denied.contains(&dropbox.join("work.apassy")));
        let mut push = dropbox.join("work.apassy").into_os_string();
        push.push(".push.nosync");
        assert!(denied.contains(&PathBuf::from(push)));
        assert!(!denied.contains(&inside), "the data folder covers it");

        fs::write(paths.data_dir.join("vaults.json"), "{ not json").expect("damage");
        let err = paths.denied().expect_err("a damaged list");
        assert!(matches!(err, SandboxError::VaultList(_)), "{err:?}");
        let err = Sandbox::for_run(&paths, dir.path()).expect_err("for_run fails closed");
        assert!(err.to_string().contains("does not start"), "{err}");
    }

    #[test]
    fn an_unavailable_bubblewrap_names_the_fix() {
        let err = SandboxError::Unavailable(Availability::UsernsBlocked {
            program: PathBuf::from("/usr/bin/bwrap"),
            version: MIN_VERSION,
            detail: "bwrap: setting up uid map: Permission denied".to_owned(),
        });
        let text = err.to_string();
        assert!(text.contains("uid map"), "{text}");
        assert!(text.contains("AppArmor"), "{text}");
    }
}
