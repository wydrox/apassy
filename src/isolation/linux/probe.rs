//! Can bubblewrap make a sandbox on this computer?
//!
//! [`probe`] finds a root-owned `bwrap`, reads its version, and starts one empty
//! sandbox with the same namespace options as a real one. It caches a definite
//! answer for the life of the process; a transient failure (a timeout, or a
//! namespace limit that is full for a moment: `EAGAIN`, `ENOSPC`) is tried again
//! on the next run. [`Availability::report`] is the network rule of a run:
//! `netns` when the sandbox works, else `none` with the reason and the fix, so a run
//! that starts without the rule says so (decision D7 of the s5 plan).
//!
//! SECURITY (judge panel): bubblewrap is looked for only in fixed system folders and
//! only when root owns the file and its folder. There is no `PATH` search and no
//! environment override: an agent can set the environment of the program that
//! starts a run, and a `bwrap` of its own would report a sandbox that is not there.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::bwrap;

/// bubblewrap 0.8.0 added `--disable-userns`, which the sandbox needs.
pub const MIN_VERSION: Version = Version {
    major: 0,
    minor: 8,
    patch: 0,
};

/// The only places where Apassy looks for bubblewrap, in this order. The last one
/// is the system profile of NixOS.
pub const BWRAP_PATHS: [&str; 4] = [
    "/usr/bin/bwrap",
    "/bin/bwrap",
    "/usr/local/bin/bwrap",
    "/run/current-system/sw/bin/bwrap",
];

/// The `network.rule` of a run in its own network namespace (broker-v0, D14).
pub const RULE_NETNS: &str = "netns";
/// The `network.rule` of a run without a network rule.
pub const RULE_NONE: &str = "none";

const MISSING_FIX: &str = "Install bubblewrap 0.8 or later as root (Debian and Ubuntu: `sudo apt-get install bubblewrap`; Fedora: `sudo dnf install bubblewrap`; Arch: `sudo pacman -S bubblewrap`). Apassy uses only a bwrap that root owns in /usr/bin, /bin, /usr/local/bin, or /run/current-system/sw/bin.";
const TOO_OLD_FIX: &str =
    "Update bubblewrap to 0.8 or later. Apassy needs its --disable-userns option.";
const USERNS_FIX: &str = "Let bubblewrap make user namespaces. On Ubuntu 23.10 and later, add an AppArmor profile for /usr/bin/bwrap with the `userns,` rule, or set `kernel.apparmor_restrict_unprivileged_userns=0`. In a container, allow user namespaces in the container runtime. See docs/operations/isolation-linux.md.";

const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Output bytes kept from each stream of a probe.
const MAX_OUTPUT: usize = 16 * 1024;
/// The `PATH` of a probe. The probe sandbox runs `true`.
const PROBE_PATH: &str = "/usr/bin:/bin:/run/current-system/sw/bin";
/// Linux `ETXTBSY`: a program that another thread still has open for writing.
const ETXTBSY: i32 = 26;
/// Linux `EAGAIN` and `ENOSPC`: `fork` or `clone(CLONE_NEW*)` hit a limit that is
/// full for a moment (processes, `user.max_user_namespaces`).
const EAGAIN: i32 = 11;
const ENOSPC: i32 = 28;
/// The texts of `EAGAIN` and `ENOSPC` in the error line of bubblewrap.
const TRANSIENT_TEXTS: [&str; 2] = [
    "Resource temporarily unavailable",
    "No space left on device",
];

/// A bubblewrap version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    /// Read the output of `bwrap --version`: `bubblewrap 0.9.0`.
    pub fn parse(text: &str) -> Option<Version> {
        let rest = text.trim().strip_prefix("bubblewrap")?;
        let number = rest.split_whitespace().next()?;
        let mut parts = number.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = match parts.next() {
            Some(part) => part.parse().ok()?,
            None => 0,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Version {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What the probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// bubblewrap made a sandbox with every namespace of a real one.
    Ready { program: PathBuf, version: Version },
    /// No usable bubblewrap: none in the fixed folders, one that root does not own,
    /// a setuid one, or a program that is not bubblewrap.
    Missing { detail: String },
    /// bubblewrap is older than [`MIN_VERSION`].
    TooOld { program: PathBuf, version: Version },
    /// bubblewrap is there, but it cannot make the namespaces: user namespaces are
    /// off or restricted (Ubuntu's AppArmor rule), or a container forbids them.
    /// `detail` is the first line that bubblewrap wrote.
    UsernsBlocked {
        program: PathBuf,
        version: Version,
        detail: String,
    },
}

impl Availability {
    pub fn is_ready(&self) -> bool {
        matches!(self, Availability::Ready { .. })
    }

    /// The bubblewrap program when it is ready.
    pub fn program(&self) -> Option<&Path> {
        match self {
            Availability::Ready { program, .. } => Some(program),
            _ => None,
        }
    }

    /// The network rule of a run on this computer, with the reason and the fix
    /// when there is no rule.
    pub fn report(&self) -> RuleReport {
        match self {
            Availability::Ready { .. } => RuleReport {
                rule: RULE_NETNS,
                reason: None,
                detail: None,
                fix: None,
            },
            Availability::Missing { detail } => {
                RuleReport::none("bwrap_missing", detail, MISSING_FIX)
            }
            Availability::TooOld { program, version } => RuleReport::none(
                "bwrap_too_old",
                &format!("{} is bubblewrap {version}", program.display()),
                TOO_OLD_FIX,
            ),
            Availability::UsernsBlocked { detail, .. } => {
                RuleReport::none("userns_blocked", detail, USERNS_FIX)
            }
        }
    }
}

/// The network rule of a run: `{"rule":"netns"}`, or `{"rule":"none","reason":…,
/// "detail":…,"fix":…}`. It holds no value and no placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleReport {
    /// [`RULE_NETNS`] or [`RULE_NONE`].
    pub rule: &'static str,
    /// `bwrap_missing`, `bwrap_too_old`, or `userns_blocked`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<&'static str>,
}

impl RuleReport {
    fn none(reason: &'static str, detail: &str, fix: &'static str) -> RuleReport {
        RuleReport {
            rule: RULE_NONE,
            reason: Some(reason),
            detail: Some(detail.to_owned()),
            fix: Some(fix),
        }
    }
}

/// The availability of bubblewrap on this computer. A definite answer is found
/// once for the process; after a transient failure the next call probes again.
pub fn probe() -> Availability {
    static CACHE: Mutex<Option<Availability>> = Mutex::new(None);
    cached(&CACHE, || match find_bwrap() {
        Ok(program) => probe_once(&program),
        Err(detail) => Probed {
            found: Availability::Missing { detail },
            transient: false,
        },
    })
}

/// One probe and whether its answer may change on the next try.
struct Probed {
    found: Availability,
    /// A timeout or a full limit: not cached.
    transient: bool,
}

/// The cached answer, or a new probe. Only a definite answer is kept. The lock is
/// held during the probe, so two runs do not probe at once.
fn cached(cache: &Mutex<Option<Availability>>, run: impl FnOnce() -> Probed) -> Availability {
    let mut slot = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(found) = slot.as_ref() {
        return found.clone();
    }
    let probed = run();
    if !probed.transient {
        *slot = Some(probed.found.clone());
    }
    probed.found
}

/// An error that can go away on the next try.
fn transient_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::TimedOut || matches!(err.raw_os_error(), Some(EAGAIN | ENOSPC))
}

/// An error line of bubblewrap that can go away on the next try.
fn transient_text(line: &str) -> bool {
    TRANSIENT_TEXTS.iter().any(|text| line.contains(text))
}

/// The first trusted bubblewrap of [`BWRAP_PATHS`], resolved. The error names each
/// candidate that exists and why it is not used.
pub fn find_bwrap() -> Result<PathBuf, String> {
    let mut notes = Vec::new();
    for candidate in BWRAP_PATHS {
        let Ok(real) = fs::canonicalize(candidate) else {
            continue;
        };
        match trusted(&real) {
            Ok(()) => return Ok(real),
            Err(note) => notes.push(format!("{candidate}: {note}")),
        }
    }
    if notes.is_empty() {
        Err(format!(
            "bubblewrap is not installed (looked in {})",
            BWRAP_PATHS.join(", ")
        ))
    } else {
        Err(notes.join("; "))
    }
}

/// SECURITY (judge panel): only a program that root owns, in a folder that root owns,
/// that nobody else can change, and that is not setuid (`--disable-userns` does not
/// work in a setuid bubblewrap).
fn trusted(path: &Path) -> Result<(), String> {
    let meta = fs::metadata(path).map_err(|err| err.to_string())?;
    if !meta.is_file() {
        return Err("not a file".to_owned());
    }
    let mode = meta.mode();
    if meta.uid() != 0 {
        return Err("root does not own it".to_owned());
    }
    if mode & 0o022 != 0 {
        return Err("its group or other users can change it".to_owned());
    }
    if mode & 0o111 == 0 {
        return Err("not executable".to_owned());
    }
    if mode & 0o4000 != 0 {
        return Err("a setuid bubblewrap cannot disable user namespaces".to_owned());
    }
    let parent = path.parent().ok_or("no folder")?;
    let folder = fs::metadata(parent).map_err(|err| err.to_string())?;
    if folder.uid() != 0 || folder.mode() & 0o022 != 0 {
        return Err("root does not own its folder, or others can change it".to_owned());
    }
    Ok(())
}

/// Probe one bubblewrap program, without the cache and without the ownership check.
/// For tests and for `doctor`-style diagnostics of a given path.
pub fn probe_with(program: &Path) -> Availability {
    probe_once(program).found
}

fn probe_once(program: &Path) -> Probed {
    let definite = |found: Availability| Probed {
        found,
        transient: false,
    };
    let mut version_cmd = Command::new(program);
    version_cmd.arg("--version");
    let version = match run_bounded(&mut version_cmd, VERSION_TIMEOUT) {
        Ok(out) if out.success => match Version::parse(&out.stdout) {
            Some(version) => version,
            None => {
                return definite(Availability::Missing {
                    detail: format!(
                        "{} --version did not print a bubblewrap version",
                        program.display()
                    ),
                });
            }
        },
        Ok(out) => {
            let detail = out.first_error();
            return Probed {
                transient: transient_text(&detail),
                found: Availability::Missing {
                    detail: format!("{} --version failed: {detail}", program.display()),
                },
            };
        }
        Err(err) => {
            return Probed {
                transient: transient_error(&err),
                found: Availability::Missing {
                    detail: format!("cannot run {}: {err}", program.display()),
                },
            };
        }
    };
    if version < MIN_VERSION {
        return definite(Availability::TooOld {
            program: program.to_owned(),
            version,
        });
    }
    // The namespaces of a real sandbox with a network rule, and the base mounts.
    let mut sandbox = Command::new(program);
    sandbox
        .args(bwrap::namespace_args(true))
        .args(["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"])
        .arg("true");
    match run_bounded(&mut sandbox, PROBE_TIMEOUT) {
        Ok(out) if out.success => definite(Availability::Ready {
            program: program.to_owned(),
            version,
        }),
        Ok(out) => {
            let detail = out.first_error();
            Probed {
                transient: transient_text(&detail),
                found: Availability::UsernsBlocked {
                    program: program.to_owned(),
                    version,
                    detail,
                },
            }
        }
        Err(err) => Probed {
            transient: transient_error(&err),
            found: Availability::UsernsBlocked {
                program: program.to_owned(),
                version,
                detail: err.to_string(),
            },
        },
    }
}

struct Bounded {
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Bounded {
    /// The first line of standard error, or the exit code.
    fn first_error(&self) -> String {
        let line = self
            .stderr
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty());
        match (line, self.code) {
            (Some(line), _) => line.chars().take(300).collect(),
            (None, Some(code)) => format!("exit code {code}"),
            (None, None) => "stopped by a signal".to_owned(),
        }
    }
}

/// Run a short command with an empty environment and a deadline.
fn run_bounded(command: &mut Command, limit: Duration) -> io::Result<Bounded> {
    command
        .env_clear()
        .env("PATH", PROBE_PATH)
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_retrying(command)?;
    let stdout = reader(child.stdout.take());
    let stderr = reader(child.stderr.take());
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no answer in {} s", limit.as_secs()),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(Bounded {
        success: status.success(),
        code: status.code(),
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// A program written a moment ago can still be open for writing in a child that
/// another thread forks (`ETXTBSY`). Try again a few times.
fn spawn_retrying(command: &mut Command) -> io::Result<Child> {
    let mut tries = 0;
    loop {
        match command.spawn() {
            Err(err) if err.raw_os_error() == Some(ETXTBSY) && tries < 20 => {
                tries += 1;
                thread::sleep(Duration::from_millis(25));
            }
            other => return other,
        }
    }
}

fn reader<R: Read + Send + 'static>(pipe: Option<R>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        if let Some(pipe) = pipe {
            let _ = pipe.take(MAX_OUTPUT as u64).read_to_end(&mut kept);
        }
        String::from_utf8_lossy(&kept).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::linux::test_dir::TestDir;
    use std::os::unix::fs::PermissionsExt;

    /// A fake bwrap: `--version` prints `version_line`, anything else prints
    /// `error` to standard error and exits with `code`.
    fn fake_bwrap(dir: &TestDir, version_line: &str, error: &str, code: i32) -> PathBuf {
        let path = dir.path().join("bwrap");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{version_line}'; exit 0; fi\necho '{error}' >&2\nexit {code}\n"
        );
        fs::write(&path, script).expect("write the fake bwrap");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[test]
    fn versions_are_read_from_bwrap_version_output() {
        assert_eq!(
            Version::parse("bubblewrap 0.9.0\n"),
            Some(Version {
                major: 0,
                minor: 9,
                patch: 0
            })
        );
        assert_eq!(
            Version::parse("bubblewrap 0.10"),
            Some(Version {
                major: 0,
                minor: 10,
                patch: 0
            })
        );
        assert!(Version::parse("bubblewrap 0.11.0") > Version::parse("bubblewrap 0.8.0"));
        assert_eq!(Version::parse("firejail 0.9.0"), None);
        assert_eq!(Version::parse("bubblewrap"), None);
        assert_eq!(Version::parse("bubblewrap 1.2.3.4"), None);
    }

    /// Plan X1: `probe_reports_userns_blocked` (a fake `bwrap` script). The report is
    /// the explicit "no network rule" answer of a run.
    #[test]
    fn probe_reports_userns_blocked() {
        let dir = TestDir::new("probe-userns");
        let fake = fake_bwrap(
            &dir,
            "bubblewrap 0.9.0",
            "bwrap: setting up uid map: Permission denied",
            1,
        );
        let found = probe_with(&fake);
        match &found {
            Availability::UsernsBlocked {
                version, detail, ..
            } => {
                assert_eq!(version.to_string(), "0.9.0");
                assert_eq!(detail, "bwrap: setting up uid map: Permission denied");
            }
            other => panic!("expected UsernsBlocked, got {other:?}"),
        }
        assert!(!found.is_ready());
        assert_eq!(found.program(), None);
        let report = found.report();
        assert_eq!(report.rule, RULE_NONE);
        assert_eq!(report.reason, Some("userns_blocked"));
        assert!(
            report
                .fix
                .is_some_and(|fix| fix.contains("apparmor_restrict_unprivileged_userns"))
        );
        let json = serde_json::to_value(&report).expect("json");
        assert_eq!(
            json,
            serde_json::json!({
                "rule": "none",
                "reason": "userns_blocked",
                "detail": "bwrap: setting up uid map: Permission denied",
                "fix": USERNS_FIX,
            })
        );
    }

    #[test]
    fn probe_reports_an_old_a_missing_and_a_foreign_bwrap() {
        let dir = TestDir::new("probe-old");
        let old = fake_bwrap(&dir, "bubblewrap 0.6.1", "", 0);
        assert!(matches!(
            probe_with(&old),
            Availability::TooOld { version, .. } if version.to_string() == "0.6.1"
        ));
        assert_eq!(probe_with(&old).report().reason, Some("bwrap_too_old"));

        let absent = dir.path().join("no-such-bwrap");
        let missing = probe_with(&absent);
        assert!(
            matches!(missing, Availability::Missing { .. }),
            "{missing:?}"
        );
        assert_eq!(missing.report().rule, RULE_NONE);
        assert_eq!(missing.report().reason, Some("bwrap_missing"));

        let other_dir = TestDir::new("probe-foreign");
        let foreign = fake_bwrap(&other_dir, "firejail version 0.9.72", "", 0);
        assert!(matches!(probe_with(&foreign), Availability::Missing { .. }));
    }

    #[test]
    fn probe_is_ready_when_the_sandbox_starts_and_reports_netns() {
        let dir = TestDir::new("probe-ready");
        let fake = fake_bwrap(&dir, "bubblewrap 0.9.0", "", 0);
        let found = probe_with(&fake);
        assert_eq!(
            found,
            Availability::Ready {
                program: fake.clone(),
                version: V0_9_0,
            }
        );
        assert_eq!(found.program(), Some(fake.as_path()));
        let json = serde_json::to_value(found.report()).expect("json");
        assert_eq!(json, serde_json::json!({"rule": "netns"}));
    }

    const V0_9_0: Version = Version {
        major: 0,
        minor: 9,
        patch: 0,
    };

    #[test]
    fn a_hanging_bwrap_is_not_ready() {
        let dir = TestDir::new("probe-hang");
        let path = dir.path().join("bwrap");
        fs::write(
            &path,
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'bubblewrap 0.9.0'; exit 0; fi\nexec sleep 60\n",
        )
        .expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        let started = Instant::now();
        let probed = probe_once(&path);
        assert!(probed.transient, "a timeout is tried again on the next run");
        let found = probed.found;
        assert!(started.elapsed() < Duration::from_secs(30));
        assert!(
            matches!(&found, Availability::UsernsBlocked { detail, .. } if detail.contains("no answer")),
            "{found:?}"
        );
    }

    /// L3: a timeout or a full namespace limit is not cached; a definite answer is.
    #[test]
    fn only_a_definite_probe_is_cached() {
        let dir = TestDir::new("probe-transient");
        let full = fake_bwrap(
            &dir,
            "bubblewrap 0.9.0",
            "bwrap: Creating new namespace failed: No space left on device",
            1,
        );
        let probed = probe_once(&full);
        assert!(probed.transient, "ENOSPC is transient");
        assert!(matches!(probed.found, Availability::UsernsBlocked { .. }));
        let other_dir = TestDir::new("probe-definite");
        let denied = fake_bwrap(
            &other_dir,
            "bubblewrap 0.9.0",
            "bwrap: setting up uid map: Permission denied",
            1,
        );
        assert!(!probe_once(&denied).transient, "EPERM is definite");
        assert!(transient_text(
            "bwrap: clone: Resource temporarily unavailable"
        ));
        assert!(transient_error(&io::Error::new(
            io::ErrorKind::TimedOut,
            "x"
        )));
        assert!(transient_error(&io::Error::from_raw_os_error(EAGAIN)));
        assert!(!transient_error(&io::Error::from_raw_os_error(2)));

        let cache = Mutex::new(None);
        let mut calls = 0;
        for _ in 0..2 {
            cached(&cache, || {
                calls += 1;
                Probed {
                    found: Availability::Missing {
                        detail: "synthetic".to_owned(),
                    },
                    transient: true,
                }
            });
        }
        assert_eq!(calls, 2, "a transient answer is probed again");
        assert!(cache.lock().expect("cache").is_none());
        let ready = Availability::Ready {
            program: PathBuf::from("/usr/bin/bwrap"),
            version: V0_9_0,
        };
        let first = cached(&cache, || Probed {
            found: ready.clone(),
            transient: false,
        });
        assert_eq!(first, ready);
        let second = cached(&cache, || panic!("a definite answer is cached"));
        assert_eq!(second, ready);
    }

    /// SECURITY (judge panel): a bwrap that the user owns is never used.
    #[test]
    fn a_bwrap_that_root_does_not_own_is_not_trusted() {
        let dir = TestDir::new("probe-owner");
        let fake = fake_bwrap(&dir, "bubblewrap 0.9.0", "", 0);
        let owned_by_root = fs::metadata(&fake)
            .map(|meta| meta.uid() == 0)
            .unwrap_or(false);
        if owned_by_root {
            // A test run as root cannot make a file that root does not own.
            return;
        }
        let err = trusted(&fake).expect_err("a user-owned bwrap");
        assert!(err.contains("root does not own"), "{err}");
    }

    #[test]
    fn the_found_bwrap_is_in_a_fixed_folder() {
        if let Ok(path) = find_bwrap() {
            assert!(path.is_absolute());
            assert!(trusted(&path).is_ok());
        }
    }
}
