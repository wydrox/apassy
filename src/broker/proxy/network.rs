//! What the process of a proxied run needs (ADR 0011 §4): the proxy and trust
//! variables, the trust files, and the network rule of the system.
//!
//! On macOS, a Seatbelt rule lets the process connect only to the proxy port, so a
//! program that ignores `HTTPS_PROXY` has no network at all. On Linux the run starts
//! in a bubblewrap sandbox with its own network namespace (unit X2 of the s5 plan,
//! `crate::isolation::linux`): its only way out is a bridge to the proxy port. When
//! bubblewrap cannot run there, the run starts without a rule and its answer says
//! why ([`RunNetwork::report`]). On other systems the run has no rule. A program
//! that goes around the proxy still holds only placeholders.

use std::io;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::{Value, json};

/// The system trust stores that the bundle for the process starts with.
const SYSTEM_BUNDLES: [&str; 4] = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];
/// Variables that point a process at the proxy. Upper and lower case, because
/// tools read different ones.
const PROXY_VARIABLES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];
/// Variables that name a full trust bundle (system roots and the run authority).
const BUNDLE_VARIABLES: [&str; 4] = [
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

/// The rule that keeps a proxied run on the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRule {
    /// macOS: a Seatbelt profile allows only the connection to the proxy.
    Seatbelt,
    /// Linux: a network namespace whose only way out leads to the proxy.
    Netns,
    /// No rule: the process has the network of the user.
    None,
}

impl NetworkRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seatbelt => "seatbelt",
            Self::Netns => "netns",
            Self::None => "none",
        }
    }
}

/// Why a run that asked for the rule has none (Linux): the `reason`, `detail`, and
/// `fix` of the run answer. It holds no value and no placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoRule {
    /// `bwrap_missing`, `bwrap_too_old`, `userns_blocked`, or `sandbox_program_missing`.
    pub reason: &'static str,
    pub detail: String,
    pub fix: &'static str,
}

/// What the process needs: environment variables and, on macOS, a Seatbelt profile;
/// on Linux, the sandbox plan. The trust files live as long as this value.
pub struct RunNetwork {
    pub env: Vec<(String, String)>,
    /// The rule that the run gets. `Seatbelt` exactly when `sandbox_profile` is set;
    /// `Netns` exactly when `linux` is set.
    pub rule: NetworkRule,
    pub sandbox_profile: Option<String>,
    /// The bubblewrap sandbox of the run (Linux).
    pub linux: Option<LinuxNet>,
    /// Why the run has no rule although it asked for one (Linux).
    pub no_rule: Option<NoRule>,
    pub ca_file: PathBuf,
    _dir: tempfile::TempDir,
}

impl RunNetwork {
    /// The rule part of the run answer (broker-v0 `network.rule`): `{"rule":"netns"}`,
    /// or `{"rule":"none","reason":…,"detail":…,"fix":…}` when the run asked for the
    /// rule and this computer cannot give it.
    pub fn report(&self) -> Value {
        let mut report = json!({ "rule": self.rule.as_str() });
        if let Some(why) = &self.no_rule {
            report["reason"] = json!(why.reason);
            report["detail"] = json!(why.detail);
            report["fix"] = json!(why.fix);
        }
        report
    }
}

/// Writes the trust files of a run into a new 0700 folder and builds the variables
/// that point a process at `proxy_url`. With `enforce`, the run gets the network
/// rule of this system for the proxy `port`.
pub fn network_for(
    ca_pem: &str,
    proxy_url: &str,
    port: u16,
    enforce: bool,
) -> io::Result<RunNetwork> {
    // tempfile makes the folder with mode 0700.
    let dir = tempfile::Builder::new().prefix("apassy-run-").tempdir()?;
    let ca_file = dir.path().join("apassy-run-ca.pem");
    std::fs::write(&ca_file, ca_pem)?;
    let mut bundle = SYSTEM_BUNDLES
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default();
    if !bundle.ends_with('\n') && !bundle.is_empty() {
        bundle.push('\n');
    }
    bundle.push_str(ca_pem);
    let bundle_file = dir.path().join("trust-bundle.pem");
    std::fs::write(&bundle_file, bundle)?;

    let mut env: Vec<(String, String)> = PROXY_VARIABLES
        .iter()
        .map(|name| ((*name).to_owned(), proxy_url.to_owned()))
        .collect();
    env.push(("NO_PROXY".to_owned(), String::new()));
    env.push(("no_proxy".to_owned(), String::new()));
    // Node 22.21 and later read HTTPS_PROXY only with this switch.
    env.push(("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()));
    env.push((
        "NODE_EXTRA_CA_CERTS".to_owned(),
        ca_file.display().to_string(),
    ));
    for name in BUNDLE_VARIABLES {
        env.push((name.to_owned(), bundle_file.display().to_string()));
    }
    let sandbox_profile = enforce.then(|| sandbox_profile(port)).flatten();
    let (linux, no_rule) = if enforce {
        linux_rule(port, dir.path())?
    } else {
        (None, None)
    };
    let rule = if sandbox_profile.is_some() {
        NetworkRule::Seatbelt
    } else if linux.is_some() {
        NetworkRule::Netns
    } else {
        NetworkRule::None
    };
    Ok(RunNetwork {
        env,
        rule,
        sandbox_profile,
        linux,
        no_rule,
        ca_file,
        _dir: dir,
    })
}

#[cfg(target_os = "linux")]
fn linux_rule(
    port: u16,
    trust_dir: &std::path::Path,
) -> io::Result<(Option<LinuxNet>, Option<NoRule>)> {
    use crate::isolation::linux::probe;
    linux::plan(&probe(), linux::init_program(), port, trust_dir)
}

#[cfg(not(target_os = "linux"))]
fn linux_rule(
    _port: u16,
    _trust_dir: &std::path::Path,
) -> io::Result<(Option<LinuxNet>, Option<NoRule>)> {
    Ok((None, None))
}

/// The bubblewrap sandbox of a proxied run on Linux. On other systems it is never
/// made.
pub struct LinuxNet {
    #[cfg(target_os = "linux")]
    inner: linux::Plan,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for LinuxNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.inner, f)
    }
}

#[cfg(not(target_os = "linux"))]
impl std::fmt::Debug for LinuxNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinuxNet")
    }
}

impl LinuxNet {
    /// The bubblewrap command that runs `program` with `args` in the sandbox of the
    /// run, in `cwd` (writable), with `env` as its environment and `path` as its
    /// `PATH`. The caller sets the standard streams and the process group, and
    /// starts and waits for it from one thread: `--die-with-parent` follows the
    /// thread that started bubblewrap.
    pub(crate) fn command(
        &self,
        program: &str,
        args: &[String],
        cwd: &std::path::Path,
        path: &str,
        env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> io::Result<std::process::Command> {
        self.command_on_this_system(program, args, cwd, path, env)
    }

    #[cfg(target_os = "linux")]
    fn command_on_this_system(
        &self,
        program: &str,
        args: &[String],
        cwd: &std::path::Path,
        path: &str,
        env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> io::Result<std::process::Command> {
        self.inner.command(program, args, cwd, path, env)
    }

    #[cfg(not(target_os = "linux"))]
    fn command_on_this_system(
        &self,
        _program: &str,
        _args: &[String],
        _cwd: &std::path::Path,
        _path: &str,
        _env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> io::Result<std::process::Command> {
        Err(io::Error::other("the Linux sandbox runs only on Linux"))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    //! The Linux network rule of a proxied run (unit X2): the run gets
    //! [`Sandbox::for_run`] with one bridge, `127.0.0.1:<proxy port>` in its network
    //! namespace to the proxy on the host. `HTTPS_PROXY` does not change.

    use std::ffi::OsString;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::isolation::linux::{
        Availability, HostPaths, HostRelay, INTERNAL_DIR, NetPlan, Sandbox,
    };
    use crate::isolation::run_paths;

    use super::{LinuxNet, NoRule};

    /// The program that is PID 1 and the bridge of the sandbox (`__netns-bridge`).
    pub(super) const INIT_PROGRAM: &str = "apassy-sandbox";
    const INIT_MISSING_FIX: &str = "Install apassy-sandbox in the folder of the Apassy program that runs the broker. On Linux it is the init and the network bridge of the sandbox of a run.";
    /// Folders that the sandbox replaces with an empty tmpfs (`bwrap.rs`).
    const HIDDEN_ROOTS: [&str; 5] = ["/tmp", "/var/tmp", "/home", "/root", "/run"];

    pub(super) struct Plan {
        bwrap: PathBuf,
        init: PathBuf,
        port: u16,
        /// The folder of the trust files, bound read-only: it is in the hidden `/tmp`.
        trust_dir: PathBuf,
        /// The host end of the bridge. Dropping it closes the bridge.
        relay: HostRelay,
    }

    impl std::fmt::Debug for Plan {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxNet")
                .field("bwrap", &self.bwrap)
                .field("init", &self.init)
                .field("port", &self.port)
                .field("relay", &self.relay)
                .finish()
        }
    }

    /// `apassy-sandbox` next to this program. A test binary of Cargo is in
    /// `target/<profile>/deps`, and the programs of the package are one folder up.
    /// There is no environment override: the program becomes PID 1 of every run.
    pub(super) fn init_program() -> Result<PathBuf, String> {
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|err| format!("cannot find this program: {err}"))?;
        let dir = exe.parent().ok_or("this program has no folder")?;
        let mut candidates = vec![dir.join(INIT_PROGRAM)];
        if dir.file_name().is_some_and(|name| name == "deps")
            && let Some(up) = dir.parent()
        {
            candidates.push(up.join(INIT_PROGRAM));
        }
        candidates
            .iter()
            .find(|path| path.is_file())
            .cloned()
            .ok_or_else(|| {
                format!(
                    "{INIT_PROGRAM} is not in {}",
                    candidates
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" or ")
                )
            })
    }

    /// The rule of a run: a sandbox when bubblewrap is ready and the init program is
    /// there, else no rule with the reason.
    pub(super) fn plan(
        found: &Availability,
        init: Result<PathBuf, String>,
        port: u16,
        trust_dir: &Path,
    ) -> io::Result<(Option<LinuxNet>, Option<NoRule>)> {
        let Availability::Ready { program, .. } = found else {
            let report = found.report();
            return Ok((
                None,
                Some(NoRule {
                    reason: report.reason.unwrap_or("bwrap_missing"),
                    detail: report.detail.unwrap_or_default(),
                    fix: report.fix.unwrap_or(""),
                }),
            ));
        };
        let init = match init {
            Ok(init) => init,
            Err(detail) => {
                return Ok((
                    None,
                    Some(NoRule {
                        reason: "sandbox_program_missing",
                        detail,
                        fix: INIT_MISSING_FIX,
                    }),
                ));
            }
        };
        let relay = HostRelay::start(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
        Ok((
            Some(LinuxNet {
                inner: Plan {
                    bwrap: program.clone(),
                    init,
                    port,
                    trust_dir: trust_dir.to_owned(),
                    relay,
                },
            }),
            None,
        ))
    }

    impl Plan {
        pub(super) fn command(
            &self,
            program: &str,
            args: &[String],
            cwd: &Path,
            path: &str,
            env: Vec<(OsString, OsString)>,
        ) -> io::Result<Command> {
            let paths = HostPaths::from_env().map_err(refused)?;
            let denied = paths.denied().map_err(refused)?;
            let cwd = std::fs::canonicalize(cwd).map_err(|err| {
                refused(format!("the working directory {}: {err}", cwd.display()))
            })?;
            let extra = programs_to_show(path, program, &paths.home, &cwd, &denied);
            let sandbox = Sandbox::for_run(&paths, &cwd)
                .map_err(refused)?
                .bwrap(&self.bwrap)
                .init_program(&self.init)
                .net(NetPlan::Bridged(vec![self.relay.bridge(self.port)]))
                .read_only([&self.trust_dir])
                .read_only(extra)
                .envs(env)
                .build()
                .map_err(refused)?;
            Ok(sandbox.command(program, args))
        }
    }

    /// A sandbox that cannot be built stops the run; it does not run without the rule.
    fn refused(err: impl std::fmt::Display) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("The sandbox of the run cannot start: {err}. The command did not run."),
        )
    }

    /// The folders of `PATH`, and the program itself when its path is absolute, that
    /// the sandbox would hide (the home, `/tmp`, `/run`, …), so that the tools of
    /// the user (`~/.local/bin`, `~/.cargo/bin`, the NixOS wrappers) still start.
    /// They are bound read-only. Skipped: a path that does not exist, the home itself
    /// or a folder that holds a hidden folder, a path in a denied one, in the working
    /// directory (already writable), or in the folder of the sandbox.
    ///
    /// SECURITY (judge panel, M1): a `PATH` folder in `/tmp`, `/var/tmp`, `/run`, or
    /// `/dev/shm` is skipped too: it can hold the socket of another program, and a
    /// network namespace does not stop Unix sockets.
    pub(super) fn programs_to_show(
        path: &str,
        program: &str,
        home: &Path,
        cwd: &Path,
        denied: &[PathBuf],
    ) -> Vec<PathBuf> {
        let home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_owned());
        let mut hidden: Vec<PathBuf> = HIDDEN_ROOTS
            .iter()
            .filter_map(|root| std::fs::canonicalize(root).ok())
            .collect();
        hidden.push(home.clone());
        let shared = run_paths::shared_roots();
        let denied: Vec<PathBuf> = denied
            .iter()
            .flat_map(|path| {
                let mut both = vec![path.clone()];
                both.extend(std::fs::canonicalize(path).ok());
                both
            })
            .collect();
        let mut candidates: Vec<(PathBuf, bool)> = path
            .split(':')
            .filter(|dir| !dir.is_empty())
            .map(|dir| (PathBuf::from(dir), true))
            .collect();
        if program.starts_with('/') {
            candidates.push((PathBuf::from(program), false));
        }
        let mut out: Vec<PathBuf> = Vec::new();
        for (candidate, is_dir) in candidates {
            if !candidate.is_absolute() {
                continue;
            }
            let Ok(real) = std::fs::canonicalize(&candidate) else {
                continue;
            };
            let kind_ok = if is_dir {
                real.is_dir()
            } else {
                real.is_file()
            };
            let skip = !kind_ok
                || (is_dir && run_paths::in_shared_root(&real, &shared))
                || !hidden.iter().any(|root| real.starts_with(root))
                || real == Path::new("/")
                || hidden.iter().any(|root| root.starts_with(&real))
                || real.starts_with(cwd)
                || real.starts_with(INTERNAL_DIR)
                || denied
                    .iter()
                    .any(|deny| real.starts_with(deny) || candidate.starts_with(deny));
            if !skip && !out.contains(&real) {
                out.push(real);
            }
        }
        out
    }
}

/// The Seatbelt profile of a proxied run: each outgoing connection, also to a Unix
/// socket and to another loopback port, is denied, except the one to the proxy.
#[cfg(target_os = "macos")]
fn sandbox_profile(port: u16) -> Option<String> {
    Some(format!(
        "(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip \"localhost:{port}\"))\n"
    ))
}

#[cfg(not(target_os = "macos"))]
fn sandbox_profile(_port: u16) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";
    const URL: &str = "http://apassy:secret@127.0.0.1:4100";

    #[test]
    fn the_rule_follows_the_sandbox_profile() {
        let enforced = network_for(PEM, URL, 4100, true).expect("network");
        assert_eq!(
            enforced.rule == NetworkRule::Seatbelt,
            enforced.sandbox_profile.is_some()
        );
        assert_eq!(
            enforced.rule == NetworkRule::Netns,
            enforced.linux.is_some()
        );
        if cfg!(target_os = "macos") {
            assert_eq!(enforced.rule, NetworkRule::Seatbelt);
            assert_eq!(enforced.report(), json!({"rule": "seatbelt"}));
        } else if cfg!(target_os = "linux") {
            // netns where bubblewrap runs, else none with the reason.
            assert_eq!(
                enforced.rule == NetworkRule::None,
                enforced.no_rule.is_some()
            );
        } else {
            assert_eq!(enforced.rule, NetworkRule::None);
        }
        let open = network_for(PEM, URL, 4100, false).expect("network");
        assert_eq!(open.rule, NetworkRule::None);
        assert!(open.sandbox_profile.is_none());
        assert!(open.linux.is_none());
        assert!(open.no_rule.is_none());
        assert_eq!(open.report(), json!({"rule": "none"}));
        assert_eq!(std::fs::read_to_string(&open.ca_file).expect("ca"), PEM);
        assert_eq!(
            serde_json::to_value([NetworkRule::Seatbelt, NetworkRule::Netns, NetworkRule::None])
                .expect("json"),
            serde_json::json!(["seatbelt", "netns", "none"])
        );
        assert_eq!(NetworkRule::Netns.as_str(), "netns");
    }

    #[cfg(target_os = "linux")]
    mod on_linux {
        use super::super::linux::{plan, programs_to_show};
        use super::*;
        use crate::isolation::linux::test_dir::TestDir;
        use crate::isolation::linux::{Availability, MIN_VERSION};
        use std::path::{Path, PathBuf};

        fn with(rule: NetworkRule, linux: Option<LinuxNet>, no_rule: Option<NoRule>) -> RunNetwork {
            let dir = tempfile::tempdir().expect("dir");
            RunNetwork {
                env: Vec::new(),
                rule,
                sandbox_profile: None,
                linux,
                no_rule,
                ca_file: dir.path().join("ca.pem"),
                _dir: dir,
            }
        }

        /// D7: without user namespaces the run starts without the rule and says why.
        #[test]
        fn a_blocked_user_namespace_reports_none_with_the_reason_and_the_fix() {
            let dir = TestDir::new("x2-userns");
            let init = dir.file("apassy-sandbox", "");
            let blocked = Availability::UsernsBlocked {
                program: PathBuf::from("/usr/bin/bwrap"),
                version: MIN_VERSION,
                detail: "bwrap: setting up uid map: Permission denied".to_owned(),
            };
            let (linux, no_rule) = plan(&blocked, Ok(init), 4100, dir.path()).expect("plan");
            assert!(linux.is_none());
            let report = with(NetworkRule::None, None, no_rule).report();
            assert_eq!(report["rule"], "none");
            assert_eq!(report["reason"], "userns_blocked");
            assert_eq!(
                report["detail"],
                "bwrap: setting up uid map: Permission denied"
            );
            assert!(
                report["fix"]
                    .as_str()
                    .is_some_and(|fix| fix.contains("AppArmor")),
                "{report}"
            );
            let missing = Availability::Missing {
                detail: "bubblewrap is not installed".to_owned(),
            };
            let (linux, no_rule) =
                plan(&missing, Ok(dir.path().join("x")), 4100, dir.path()).expect("plan");
            assert!(linux.is_none());
            assert_eq!(no_rule.expect("why").reason, "bwrap_missing");
        }

        #[test]
        fn a_missing_init_program_reports_none() {
            let dir = TestDir::new("x2-init");
            let ready = Availability::Ready {
                program: PathBuf::from("/usr/bin/bwrap"),
                version: MIN_VERSION,
            };
            let (linux, no_rule) = plan(
                &ready,
                Err("apassy-sandbox is not in /opt/x".to_owned()),
                4100,
                dir.path(),
            )
            .expect("plan");
            assert!(linux.is_none());
            let why = no_rule.expect("why");
            assert_eq!(why.reason, "sandbox_program_missing");
            assert!(why.detail.contains("apassy-sandbox"));
        }

        /// The run gets one bridge, on the proxy port, so `HTTPS_PROXY` does not
        /// change; the trust files are bound read-only; no value is in the arguments.
        #[test]
        fn a_ready_sandbox_bridges_only_the_proxy_port() {
            // The working directory of a run is never in /tmp (M1).
            let dir = TestDir::outside_tmp("x2-ready");
            let init = dir.file("bin/apassy-sandbox", "");
            let trust = dir.mkdir("trust");
            let project = dir.mkdir("project");
            let ready = Availability::Ready {
                program: PathBuf::from("/usr/bin/bwrap"),
                version: MIN_VERSION,
            };
            let (linux, no_rule) = plan(&ready, Ok(init), 4100, &trust).expect("plan");
            assert!(no_rule.is_none());
            let linux = linux.expect("sandbox");
            let command = linux
                .command(
                    "curl",
                    &["https://api.example.com/".to_owned()],
                    &project,
                    "/usr/bin:/bin",
                    vec![("LANG".into(), "C.UTF-8".into())],
                )
                .expect("command");
            assert_eq!(
                Path::new(command.get_program()),
                Path::new("/usr/bin/bwrap")
            );
            let args: Vec<String> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert!(args.iter().any(|arg| arg == "--unshare-net"), "{args:?}");
            assert!(
                args.iter().any(|arg| arg == "--die-with-parent"),
                "{args:?}"
            );
            let listens: Vec<&String> = args
                .windows(2)
                .filter(|pair| pair[0] == "--listen")
                .map(|pair| &pair[1])
                .collect();
            assert_eq!(listens.len(), 1, "{args:?}");
            assert!(listens[0].starts_with("4100="), "{args:?}");
            let trust = std::fs::canonicalize(&trust).expect("trust");
            let trust = trust.to_string_lossy().into_owned();
            assert!(
                args.windows(3)
                    .any(|w| w[0] == "--ro-bind" && w[1] == trust && w[2] == trust),
                "{args:?}"
            );
            assert_eq!(
                &args[args.len() - 3..],
                &["--", "curl", "https://api.example.com/"]
            );
            let tmpdir = command
                .get_envs()
                .find(|(name, _)| *name == "TMPDIR")
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned());
            assert_eq!(tmpdir.as_deref(), Some("/tmp"));
            assert!(
                command
                    .get_envs()
                    .all(|(name, _)| name != "XDG_RUNTIME_DIR"),
                "session variables stay outside"
            );
            let shown = format!("{linux:?}");
            assert!(shown.contains("4100"), "{shown}");
        }

        #[test]
        fn hidden_tool_folders_are_shown_read_only_and_nothing_else() {
            let dir = TestDir::outside_tmp("x2-path");
            // A tool folder in /tmp can hold the socket of another program (M1).
            let shared = TestDir::new("x2-path-tmp");
            let in_tmp = shared.mkdir("bin");
            let home = dir.mkdir("home");
            let tools = dir.mkdir("home/.local/bin");
            let keys = dir.mkdir("home/.ssh/bin");
            let project = dir.mkdir("home/project");
            let in_project = dir.mkdir("home/project/bin");
            let program = dir.file("home/opt/tool", "");
            let denied = vec![home.join(".ssh")];
            let path = [
                tools.to_str().expect("utf-8"),
                keys.to_str().expect("utf-8"),
                in_project.to_str().expect("utf-8"),
                home.to_str().expect("utf-8"),
                "/usr/bin",
                "/tmp",
                in_tmp.to_str().expect("utf-8"),
                "/var/tmp",
                "/dev/shm",
                "relative/bin",
                "/nonexistent/apassy/bin",
            ]
            .join(":");
            let real = |path: &Path| std::fs::canonicalize(path).expect("real");
            let shown = programs_to_show(
                &path,
                program.to_str().expect("utf-8"),
                &home,
                &real(project.as_path()),
                &denied,
            );
            assert_eq!(shown, vec![real(tools.as_path()), real(program.as_path())]);
            assert!(programs_to_show("/usr/bin:/bin", "curl", &home, &project, &denied).is_empty());
        }
    }
}
