//! The installer: a constant shell script that replaces the app bundle after
//! Apassy quits.
//!
//! The app starts `/bin/sh -c <script> apassy-update PID STAGED INSTALLED TEAM LOG
//! RELAUNCH`. The paths are arguments only; the script text never contains them.
//! The script:
//!
//! 1. checks its arguments,
//! 2. waits for PID to exit (at most 2 minutes),
//! 3. checks the staged app with `codesign --verify --deep --strict -R` against the
//!    Developer ID requirement with TEAM,
//! 4. moves the installed bundle aside, moves the staged bundle into place (`ditto`
//!    when they are on different volumes), checks it again, and removes the old
//!    bundle. A failure puts the old bundle back.
//! 5. writes `result: ok` or `result: failed: <reason>` as the last line of LOG,
//! 6. opens the new app when RELAUNCH is 1.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::system::{is_team_id, requirement_prefix};

/// The tools of the real installer. `verify` uses `$TEAM` of the body.
const REAL_TOOLS: &str = concat!(
    "REQ_PREFIX='",
    requirement_prefix!(),
    "'\n",
    r#"verify() { /usr/bin/codesign --verify --deep --strict -R "=${REQ_PREFIX}\"${TEAM}\"" "$1"; }
copy_tree() { /usr/bin/ditto "$1" "$2"; }
launch() { /usr/bin/open "$1"; }
"#
);

/// The steps of the installer. [`REAL_TOOLS`] or a test double defines `verify`,
/// `copy_tree`, and `launch` before it.
const BODY: &str = r#"set -u
umask 077
PID="${1:-}"; STAGED="${2:-}"; INSTALLED="${3:-}"; TEAM="${4:-}"; LOG="${5:-}"; RELAUNCH="${6:-}"
case "$LOG" in /*) ;; *) exit 2 ;; esac
say() { printf '%s\n' "$*" >>"$LOG"; }
finish() { say "result: $1"; exit "$2"; }
case "$PID" in ''|*[!0-9]*) finish "failed: the process ID is not valid" 2 ;; esac
case "$TEAM" in *[!A-Z0-9]*) finish "failed: the team ID is not valid" 2 ;; esac
[ "${#TEAM}" -eq 10 ] || finish "failed: the team ID is not valid" 2
case "$STAGED" in /*.app) ;; *) finish "failed: the path of the new version is not valid" 2 ;; esac
case "$INSTALLED" in /*.app) ;; *) finish "failed: the path of the installed app is not valid" 2 ;; esac
case "$RELAUNCH" in 0|1) ;; *) finish "failed: the relaunch flag is not valid" 2 ;; esac
say "Installing $STAGED to $INSTALLED after process $PID quits."
n=0
while kill -0 "$PID" 2>/dev/null; do
  n=$((n + 1))
  [ "$n" -le 600 ] || finish "failed: Apassy did not quit" 1
  sleep 0.2
done
[ -d "$STAGED" ] && [ ! -L "$STAGED" ] || finish "failed: the new version is missing" 1
verify "$STAGED" >>"$LOG" 2>&1 || finish "failed: the new version did not pass the signature check" 1
PARENT="$(dirname "$INSTALLED")"
[ -d "$PARENT" ] || finish "failed: the folder of the app is missing" 1
OLD="$PARENT/.Apassy-previous-$$.app"
dev() { stat -c %d "$1" 2>/dev/null || stat -f %d "$1"; }
restore() {
  rm -rf "$INSTALLED"
  if [ -e "$OLD" ]; then mv "$OLD" "$INSTALLED"; fi
}
if [ -e "$INSTALLED" ] || [ -L "$INSTALLED" ]; then
  mv "$INSTALLED" "$OLD" || finish "failed: the installed app cannot be moved aside" 1
fi
if [ "$(dev "$STAGED")" = "$(dev "$PARENT")" ]; then
  mv "$STAGED" "$INSTALLED" || { restore; finish "failed: the new version cannot be moved into place" 1; }
else
  copy_tree "$STAGED" "$INSTALLED" >>"$LOG" 2>&1 || { restore; finish "failed: the new version cannot be copied into place" 1; }
  rm -rf "$STAGED"
fi
verify "$INSTALLED" >>"$LOG" 2>&1 || { restore; finish "failed: the installed copy did not pass the signature check" 1; }
rm -rf "$OLD"
say "result: ok"
if [ "$RELAUNCH" = 1 ]; then launch "$INSTALLED" >>"$LOG" 2>&1; fi
exit 0
"#;

/// The script of the real installer.
fn script() -> String {
    format!("{REAL_TOOLS}{BODY}")
}

/// The name of the log in the update folder.
pub(crate) fn log_path(dir: &Path) -> PathBuf {
    dir.join("install.log")
}

/// One install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Job {
    /// The process of the running app.
    pub(crate) pid: u32,
    pub(crate) staged: PathBuf,
    pub(crate) installed: PathBuf,
    pub(crate) team: String,
    pub(crate) log: PathBuf,
    /// Open the new app after the install ("Restart now"). An install at quit does
    /// not open it.
    pub(crate) relaunch: bool,
}

impl Job {
    /// Check the job before the start. The script checks the same again.
    fn check(&self) -> Result<(), String> {
        let is_app =
            |path: &Path| path.is_absolute() && path.extension().is_some_and(|ext| ext == "app");
        if !is_team_id(&self.team) {
            return Err("The team ID of this copy is not valid.".to_owned());
        }
        if !is_app(&self.staged) || !is_app(&self.installed) || !self.log.is_absolute() {
            return Err("The paths of the update are not valid.".to_owned());
        }
        Ok(())
    }

    fn command(&self, script: String) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(script)
            .arg("apassy-update")
            .arg(self.pid.to_string())
            .arg(&self.staged)
            .arg(&self.installed)
            .arg(&self.team)
            .arg(&self.log)
            .arg(if self.relaunch { "1" } else { "0" })
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
}

/// Start the installer in its own process group, so it outlives the app. A new
/// log replaces the old one.
pub(crate) fn spawn(job: &Job) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    job.check()?;
    let _ = std::fs::remove_file(&job.log);
    let mut child = job
        .command(script())
        .process_group(0)
        .spawn()
        .map_err(|err| format!("The installer did not start: {err}"))?;
    // Reap the installer if it ends while the app still runs.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// The result in a log: `Some(Ok(()))`, `Some(Err(reason))`, or `None` without a
/// result line.
pub(crate) fn read_result(log: &Path) -> Option<Result<(), String>> {
    let file = std::fs::File::open(log).ok()?;
    let mut bytes = Vec::new();
    file.take(256 * 1024).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let last = text
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("result: "))?;
    Some(match last.strip_prefix("failed: ") {
        None if last == "ok" => Ok(()),
        Some(reason) => Err(reason.chars().take(300).collect()),
        None => Err("the installer stopped without a result".to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Test doubles of the tools. `verify` accepts a bundle with the file
    /// `Contents/VALID`. The real script is never changed.
    const TEST_TOOLS: &str = r#"verify() { [ -f "$1/Contents/VALID" ]; }
copy_tree() { cp -R "$1" "$2"; }
launch() { : >"$1.launched"; }
"#;

    fn bundle(path: &Path, version: &str, valid: bool) {
        fs::create_dir_all(path.join("Contents").join("MacOS")).expect("bundle");
        fs::write(path.join("Contents").join("version"), version).expect("version");
        if valid {
            fs::write(path.join("Contents").join("VALID"), b"").expect("valid");
        }
    }

    fn version_of(path: &Path) -> Option<String> {
        fs::read_to_string(path.join("Contents").join("version")).ok()
    }

    struct Setup {
        _temp: tempfile::TempDir,
        staged: PathBuf,
        installed: PathBuf,
        log: PathBuf,
    }

    fn setup(staged_valid: bool) -> Setup {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let update = temp.path().join("data").join("update");
        let apps = temp.path().join("Applications");
        fs::create_dir_all(&update).expect("update");
        fs::create_dir_all(&apps).expect("apps");
        let staged = update.join("Apassy.app");
        let installed = apps.join("Apassy.app");
        bundle(&staged, "0.3.1", staged_valid);
        bundle(&installed, "0.3.0", true);
        Setup {
            staged,
            installed,
            log: update.join("install.log"),
            _temp: temp,
        }
    }

    /// Run the body with the test doubles and wait for it.
    fn run_with(job: &Job, args: Option<Vec<String>>) -> std::process::ExitStatus {
        run_in(job, args, Path::new("/"))
    }

    /// The same in the working folder `cwd`.
    fn run_in(job: &Job, args: Option<Vec<String>>, cwd: &Path) -> std::process::ExitStatus {
        let mut command = job.command(format!("{TEST_TOOLS}{BODY}"));
        command.current_dir(cwd);
        if let Some(args) = args {
            command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg(format!("{TEST_TOOLS}{BODY}"))
                .arg("apassy-update")
                .args(args)
                .stdin(Stdio::null());
        }
        command.status().expect("run the installer")
    }

    fn job(setup: &Setup, pid: u32, relaunch: bool) -> Job {
        Job {
            pid,
            staged: setup.staged.clone(),
            installed: setup.installed.clone(),
            team: "ABCDE12345".to_owned(),
            log: setup.log.clone(),
            relaunch,
        }
    }

    /// A process ID that has ended.
    fn ended_pid() -> u32 {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn");
        let pid = child.id();
        child.wait().expect("wait");
        pid
    }

    #[test]
    fn the_installer_waits_for_the_app_then_replaces_it() {
        let setup = setup(true);
        let mut app = Command::new("/bin/sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .expect("spawn");
        let started = std::time::Instant::now();
        let reaper = {
            let pid = app.id();
            let job = job(&setup, pid, true);
            std::thread::spawn(move || run_with(&job, None))
        };
        app.wait().expect("the app quits");
        let status = reaper.join().expect("installer");
        assert!(
            status.success(),
            "{}",
            fs::read_to_string(&setup.log).unwrap_or_default()
        );
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(900),
            "the installer waited for the app"
        );
        assert_eq!(version_of(&setup.installed).as_deref(), Some("0.3.1"));
        assert!(!setup.staged.exists(), "the staged app moved into place");
        let apps = setup.installed.parent().unwrap();
        let left: Vec<_> = fs::read_dir(apps)
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(left.len(), 2, "the app and the launch marker: {left:?}");
        assert!(PathBuf::from(format!("{}.launched", setup.installed.display())).exists());
        assert_eq!(read_result(&setup.log), Some(Ok(())));
    }

    #[test]
    fn an_install_at_quit_does_not_open_the_app() {
        let setup = setup(true);
        let status = run_with(&job(&setup, ended_pid(), false), None);
        assert!(status.success());
        assert_eq!(version_of(&setup.installed).as_deref(), Some("0.3.1"));
        assert!(!PathBuf::from(format!("{}.launched", setup.installed.display())).exists());
        assert_eq!(read_result(&setup.log), Some(Ok(())));
    }

    #[test]
    fn a_staged_app_that_fails_the_check_is_not_installed() {
        let setup = setup(false);
        let status = run_with(&job(&setup, ended_pid(), true), None);
        assert!(!status.success());
        assert_eq!(version_of(&setup.installed).as_deref(), Some("0.3.0"));
        assert!(setup.staged.exists());
        assert_eq!(
            read_result(&setup.log),
            Some(Err(
                "the new version did not pass the signature check".to_owned()
            ))
        );
        assert!(!PathBuf::from(format!("{}.launched", setup.installed.display())).exists());
    }

    #[test]
    fn a_missing_staged_app_leaves_the_installed_one() {
        let setup = setup(true);
        fs::remove_dir_all(&setup.staged).expect("remove");
        let status = run_with(&job(&setup, ended_pid(), true), None);
        assert!(!status.success());
        assert_eq!(version_of(&setup.installed).as_deref(), Some("0.3.0"));
        assert_eq!(
            read_result(&setup.log),
            Some(Err("the new version is missing".to_owned()))
        );
    }

    /// Arguments that are not in the expected form stop the script before it
    /// changes anything. A path with shell syntax stays one argument.
    #[test]
    fn the_installer_checks_its_arguments() {
        let setup = setup(true);
        let pid = ended_pid().to_string();
        let staged = setup.staged.display().to_string();
        let installed = setup.installed.display().to_string();
        let log = setup.log.display().to_string();
        let cases: Vec<([String; 6], &str)> = vec![
            (
                [
                    "12x".into(),
                    staged.clone(),
                    installed.clone(),
                    "ABCDE12345".into(),
                    log.clone(),
                    "1".into(),
                ],
                "the process ID is not valid",
            ),
            (
                [
                    pid.clone(),
                    staged.clone(),
                    installed.clone(),
                    "ABCDE1234\"".into(),
                    log.clone(),
                    "1".into(),
                ],
                "the team ID is not valid",
            ),
            (
                [
                    pid.clone(),
                    staged.clone(),
                    installed.clone(),
                    "ABCDE1234".into(),
                    log.clone(),
                    "1".into(),
                ],
                "the team ID is not valid",
            ),
            (
                [
                    pid.clone(),
                    "Apassy.app".into(),
                    installed.clone(),
                    "ABCDE12345".into(),
                    log.clone(),
                    "1".into(),
                ],
                "the path of the new version is not valid",
            ),
            (
                [
                    pid.clone(),
                    staged.clone(),
                    "/Applications/Apassy".into(),
                    "ABCDE12345".into(),
                    log.clone(),
                    "1".into(),
                ],
                "the path of the installed app is not valid",
            ),
            (
                [
                    pid.clone(),
                    staged.clone(),
                    installed.clone(),
                    "ABCDE12345".into(),
                    log.clone(),
                    "yes".into(),
                ],
                "the relaunch flag is not valid",
            ),
        ];
        for (args, expected) in cases {
            let _ = fs::remove_file(&setup.log);
            let status = run_with(&job(&setup, 0, false), Some(args.to_vec()));
            assert_eq!(status.code(), Some(2), "{expected}");
            assert_eq!(read_result(&setup.log), Some(Err(expected.to_owned())));
            assert_eq!(version_of(&setup.installed).as_deref(), Some("0.3.0"));
            assert!(setup.staged.exists());
        }
        // A relative log path: the script stops without writing anywhere.
        let status = run_with(
            &job(&setup, 0, false),
            Some(vec![
                pid.clone(),
                staged.clone(),
                installed.clone(),
                "ABCDE12345".into(),
                "install.log".into(),
                "0".into(),
            ]),
        );
        assert_eq!(status.code(), Some(2));

        // Shell syntax in a path is data, not code.
        let temp = tempfile::TempDir::new().expect("temp dir");
        let odd = temp
            .path()
            .join("$(touch pwned) `id`; x")
            .join("Apassy.app");
        bundle(&odd, "0.3.0", true);
        let marker = temp.path().join("pwned");
        let status = run_in(
            &Job {
                installed: odd.clone(),
                ..job(&setup, ended_pid(), false)
            },
            None,
            temp.path(),
        );
        assert!(
            status.success(),
            "{}",
            fs::read_to_string(&setup.log).unwrap_or_default()
        );
        assert_eq!(version_of(&odd).as_deref(), Some("0.3.1"));
        assert!(!marker.exists(), "a path ran as code");
    }

    #[test]
    fn a_job_with_invalid_values_does_not_start() {
        let setup = setup(true);
        let valid = job(&setup, 1, false);
        assert!(valid.check().is_ok());
        for bad in [
            Job {
                team: "not-a-team".into(),
                ..valid.clone()
            },
            Job {
                staged: "relative/Apassy.app".into(),
                ..valid.clone()
            },
            Job {
                installed: "/Applications/Apassy".into(),
                ..valid.clone()
            },
            Job {
                log: "install.log".into(),
                ..valid.clone()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
            assert!(spawn(&bad).is_err());
        }
    }

    #[test]
    fn the_real_script_checks_the_developer_id_requirement() {
        let script = script();
        assert!(
            script.starts_with(
                "REQ_PREFIX='identifier \"com.wydrox.apassy\" and anchor apple generic"
            )
        );
        assert!(script.contains(r#"-R "=${REQ_PREFIX}\"${TEAM}\"""#));
        assert!(script.contains("/usr/bin/ditto"));
        assert!(script.contains("/usr/bin/open"));
        assert!(script.ends_with(BODY));
        // The script parses.
        let status = Command::new("/bin/sh")
            .args(["-n", "-c", &script])
            .status()
            .expect("sh -n");
        assert!(status.success());
    }

    /// The real script with the real `codesign`, by hand on macOS (see
    /// `real_tools_check_a_disk_image` in `system.rs`). A notarized app of another
    /// developer, staged as Apassy.app, fails the Apassy requirement, and the
    /// installed bundle stays.
    #[test]
    #[ignore = "manual: needs macOS and APASSY_UPDATE_PROBE_APP"]
    fn real_script_refuses_an_app_of_another_developer() {
        let source = PathBuf::from(std::env::var("APASSY_UPDATE_PROBE_APP").expect("probe app"));
        let setup = setup(true);
        fs::remove_dir_all(&setup.staged).expect("remove");
        let status = Command::new("/usr/bin/ditto")
            .arg(&source)
            .arg(&setup.staged)
            .status()
            .expect("ditto");
        assert!(status.success());
        let output = Command::new("/usr/bin/codesign")
            .args(["-d", "--verbose=2"])
            .arg(&setup.staged)
            .output()
            .expect("codesign");
        let team =
            super::super::system::team_from_codesign(&String::from_utf8_lossy(&output.stderr))
                .expect("team");
        let job = Job {
            team,
            ..job(&setup, ended_pid(), false)
        };
        let status = job.command(script()).status().expect("installer");
        assert!(!status.success());
        assert_eq!(
            read_result(&setup.log),
            Some(Err(
                "the new version did not pass the signature check".to_owned()
            ))
        );
        assert_eq!(version_of(&setup.installed).as_deref(), Some("0.3.0"));
        let log = fs::read_to_string(&setup.log).expect("log");
        assert!(log.contains("failed to satisfy"), "{log}");
    }

    #[test]
    fn results_in_a_log() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let log = temp.path().join("install.log");
        assert_eq!(read_result(&log), None);
        fs::write(&log, "start\nresult: ok\n").expect("write");
        assert_eq!(read_result(&log), Some(Ok(())));
        fs::write(
            &log,
            "start\ncodesign: invalid\nresult: failed: synthetic reason\n",
        )
        .expect("write");
        assert_eq!(read_result(&log), Some(Err("synthetic reason".to_owned())));
        fs::write(&log, "start\n").expect("write");
        assert_eq!(read_result(&log), None);
        fs::write(&log, "result: odd\n").expect("write");
        assert!(matches!(read_result(&log), Some(Err(_))));
    }
}
