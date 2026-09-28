//! Automatic updates of the macOS app (ADR 0015, `docs/operations/updates.md`).
//!
//! A background thread reads `https://apassy.wyderka.cc/latest.json` shortly after
//! the start and then every 6 hours. For a newer build it downloads the disk image
//! into `<data dir>/update/`, checks its size and SHA-256, attaches it, and checks
//! the app in it: bundle ID, version, Developer ID signature of the same team as
//! the running app, and Gatekeeper (notarization). It copies the app to
//! `<data dir>/update/Apassy.app`. The agent profile denies the data directory.
//!
//! "Restart now", or the next quit when automatic install is on, locks the vault,
//! ends waiting runs, and starts the installer ([`install`]). The installer
//! replaces the bundle after the app quits and writes its result to
//! `<data dir>/update/install.log`. The next start shows the result.
//!
//! Linux has no published app: the thread does not start, and Settings says so.

mod install;
mod manifest;
mod pipeline;
mod store;
mod system;
mod version;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use eframe::egui;

use self::pipeline::{Check, Outcome, Urls};
use self::store::UpdateFile;
use self::system::{Commands, Location, UpdateSystem};
use super::owner_store::ENDED_BY_QUIT;
use super::{BrokerState, DesktopApp};

pub(crate) use self::manifest::BuildIdentity;
pub(crate) use self::pipeline::{CHANGELOG_URL, DOWNLOAD_PAGE_URL, Phase};
pub(crate) use self::store::{InstallReport, Staged, StagedKind};

/// Updates exist only for the published macOS app.
pub(crate) const SUPPORTED: bool = cfg!(target_os = "macos");
/// The first check waits for the start of the window.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(15);
/// The time between two automatic checks.
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// What the settings and the banner show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateView {
    /// False on Linux.
    pub(crate) supported: bool,
    /// The background thread runs. It does not run in tests and in the smoke test.
    pub(crate) running: bool,
    pub(crate) phase: Phase,
    pub(crate) auto_check: bool,
    pub(crate) auto_install: bool,
    pub(crate) last_check: Option<u64>,
    pub(crate) last_result: Option<String>,
    pub(crate) last_install: Option<InstallReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    Check,
    /// Check and download, also when automatic install is off.
    Download,
}

struct State {
    phase: Phase,
    file: UpdateFile,
    request: Option<Request>,
    stop: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The files of the updater in the data directory.
#[derive(Debug, Clone)]
struct Paths {
    /// `<data dir>/update`: downloads, the staged app, and the install log.
    dir: PathBuf,
    /// `<data dir>/update.json`.
    file: PathBuf,
}

impl Paths {
    fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join("update"),
            file: data_dir.join("update.json"),
        }
    }
}

type Repaint = Arc<dyn Fn() + Send + Sync>;

/// The updater of the desktop app.
pub(crate) struct Updater {
    shared: Arc<Shared>,
    /// `None` until [`Updater::start`]: tests and the smoke test keep it so.
    paths: Option<Paths>,
    sys: Arc<dyn UpdateSystem>,
    build: BuildIdentity,
    running: bool,
    /// The installer has started. A quit does not start it again.
    installer_started: bool,
    /// The commit of the version whose banner the owner hid ("Later"). A newer
    /// version shows the banner again.
    pub(crate) banner_hidden: Option<String>,
}

impl Default for Updater {
    fn default() -> Self {
        Self::idle()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Open a URL or a file with `/usr/bin/open` (`xdg-open` on Linux).
pub(crate) fn open(target: &std::ffi::OsStr) -> Result<(), String> {
    let program = if cfg!(target_os = "macos") {
        "/usr/bin/open"
    } else {
        "xdg-open"
    };
    let mut child = std::process::Command::new(program)
        .arg(target)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| format!("Apassy cannot open {}: {err}", target.to_string_lossy()))?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// True when `staged` is newer than the running build, so it is worth installing.
fn staged_is_newer(staged: &Staged, build: &BuildIdentity) -> bool {
    use std::cmp::Ordering;
    let (Ok(offered), Ok(running)) = (
        version::Version::parse(&staged.version),
        version::Version::parse(&build.version),
    ) else {
        return false;
    };
    match offered.cmp(&running) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => build
            .build
            .as_ref()
            .is_some_and(|(commit, _)| *commit != staged.commit),
    }
}

impl Updater {
    /// An updater without files and without a thread. Tests and the smoke test use
    /// it, so they never check for updates.
    pub(crate) fn idle() -> Self {
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    phase: Phase::Idle,
                    file: UpdateFile::default(),
                    request: None,
                    stop: false,
                }),
                wake: Condvar::new(),
            }),
            paths: None,
            sys: Arc::new(Commands),
            build: BuildIdentity::current(),
            running: false,
            installer_started: false,
            banner_hidden: None,
        }
    }

    /// Read the settings and the result of the last install, and start the thread
    /// on macOS. The returned note is the result of the last install, for a toast.
    pub(crate) fn start(
        data_dir: &Path,
        repaint: impl Fn() + Send + Sync + 'static,
    ) -> (Self, Option<Result<String, String>>) {
        let mut updater = Self::idle();
        let note = updater.load(data_dir);
        if SUPPORTED {
            updater.spawn_worker(Arc::new(repaint), Urls::current());
        }
        (updater, note)
    }

    /// Read `update.json` and `install.log`, and drop a staged version that is not
    /// newer than this build.
    fn load(&mut self, data_dir: &Path) -> Option<Result<String, String>> {
        let paths = Paths::new(data_dir);
        let mut file = UpdateFile::load(&paths.file);
        let before = file.clone();
        let log = install::log_path(&paths.dir);
        let note = install::read_result(&log).map(|result| {
            let (ok, message) = match result {
                Ok(()) => (
                    true,
                    format!("Apassy is updated to {}.", self.build.version),
                ),
                Err(reason) => (
                    false,
                    format!(
                        "The update did not install: {reason}. Apassy {} still runs. Details: {}",
                        self.build.version,
                        paths.dir.join("install-failed.log").display()
                    ),
                ),
            };
            file.last_install = Some(InstallReport {
                at: unix_now(),
                ok,
                message: message.clone(),
            });
            if ok {
                let _ = std::fs::remove_file(&log);
            } else {
                let _ = std::fs::rename(&log, paths.dir.join("install-failed.log"));
                // A new check downloads and checks the version again.
                file.staged = None;
            }
            if ok { Ok(message) } else { Err(message) }
        });
        let keep = file.staged.as_ref().is_some_and(|staged| {
            staged_is_newer(staged, &self.build) && pipeline::staged_present(&paths.dir, staged)
        });
        if !keep {
            file.staged = None;
            pipeline::clean(&paths.dir);
        }
        // Only the thread stages a version, and it runs only on macOS.
        let phase = file.staged.clone().map_or(Phase::Idle, Phase::Ready);
        if file != before {
            let _ = file.save(&paths.file);
        }
        {
            let mut state = self.shared.lock();
            state.file = file;
            state.phase = phase;
        }
        self.paths = Some(paths);
        note
    }

    fn spawn_worker(&mut self, repaint: Repaint, urls: Urls) {
        let (Some(paths), true) = (self.paths.clone(), SUPPORTED) else {
            return;
        };
        let shared = Arc::clone(&self.shared);
        let sys = Arc::clone(&self.sys);
        let build = self.build.clone();
        let spawned = std::thread::Builder::new()
            .name("apassy-update".to_owned())
            .spawn(move || worker(&shared, &paths, &build, sys.as_ref(), &urls, &repaint));
        self.running = spawned.is_ok();
    }

    pub(crate) fn view(&self) -> UpdateView {
        let state = self.shared.lock();
        UpdateView {
            supported: SUPPORTED,
            running: self.running,
            phase: state.phase.clone(),
            auto_check: state.file.auto_check,
            auto_install: state.file.auto_install,
            last_check: state.file.last_check,
            last_result: state.file.last_result.clone(),
            last_install: state.file.last_install.clone(),
        }
    }

    pub(crate) fn build(&self) -> &BuildIdentity {
        &self.build
    }

    fn change(&self, edit: impl FnOnce(&mut UpdateFile)) {
        let mut state = self.shared.lock();
        edit(&mut state.file);
        if let Some(paths) = &self.paths {
            let _ = state.file.save(&paths.file);
        }
        drop(state);
        self.shared.wake.notify_all();
    }

    pub(crate) fn set_auto_check(&self, on: bool) {
        self.change(|file| file.auto_check = on);
    }

    pub(crate) fn set_auto_install(&self, on: bool) {
        self.change(|file| file.auto_install = on);
    }

    fn request(&self, request: Request) {
        if !self.running {
            return;
        }
        self.shared.lock().request = Some(request);
        self.shared.wake.notify_all();
    }

    /// "Check now".
    pub(crate) fn check_now(&self) {
        self.request(Request::Check);
    }

    /// Download and check an available version, also with automatic install off.
    pub(crate) fn download_now(&self) {
        self.request(Request::Download);
    }

    /// Stop the thread. A download stops at its next progress report.
    pub(crate) fn stop(&self) {
        self.shared.lock().stop = true;
        self.shared.wake.notify_all();
    }

    /// Open the checked disk image in Finder, when Apassy cannot replace itself.
    pub(crate) fn open_image(&self) -> Result<(), String> {
        let paths = self.paths.as_ref().ok_or("Updates are not running.")?;
        open(pipeline::staged_image(&paths.dir).as_os_str())
    }

    /// The install job for the staged app, or why there is none.
    fn install_job(&self, relaunch: bool) -> Result<install::Job, String> {
        let paths = self
            .paths
            .as_ref()
            .ok_or("Updates are not running in this window.")?;
        let staged = self
            .shared
            .lock()
            .file
            .staged
            .clone()
            .ok_or("No new version is ready.")?;
        if staged.kind != StagedKind::App || !pipeline::staged_present(&paths.dir, &staged) {
            return Err("The new version is not ready to install. Check again.".to_owned());
        }
        let installed = match self.sys.location() {
            Location::Bundle {
                bundle,
                writable: true,
            } => bundle,
            Location::Bundle { bundle, .. } => {
                return Err(format!(
                    "Apassy cannot replace itself in {}. Download the new version from the site.",
                    bundle.parent().unwrap_or(&bundle).display()
                ));
            }
            Location::NotBundle => return Err(pipeline::NOT_A_BUNDLE.to_owned()),
        };
        Ok(install::Job {
            pid: std::process::id(),
            staged: pipeline::staged_app(&paths.dir),
            installed,
            team: staged.team,
            log: install::log_path(&paths.dir),
            relaunch,
        })
    }

    /// Stop the thread, and start the installer. The app must quit next. A check
    /// that runs now stops before it cleans the update folder.
    fn start_install(&mut self, job: &install::Job) -> Result<(), String> {
        if self.installer_started {
            return Ok(());
        }
        self.stop();
        install::spawn(job)?;
        self.installer_started = true;
        Ok(())
    }

    /// At quit: start the installer without a relaunch when automatic install is
    /// on and a version is ready. A failure goes to the log for the next start.
    fn install_at_quit(&mut self) {
        let Some(paths) = &self.paths else {
            return;
        };
        let (auto_install, staged) = {
            let state = self.shared.lock();
            (state.file.auto_install, state.file.staged.clone())
        };
        // A check that runs now does not stop the install of the staged app. A
        // download of a newer version removed it, so nothing installs then.
        let ready = staged.is_some_and(|staged| {
            staged.kind == StagedKind::App && pipeline::staged_present(&paths.dir, &staged)
        });
        if self.installer_started || !auto_install || !ready {
            return;
        }
        let result = self
            .install_job(false)
            .and_then(|job| self.start_install(&job));
        if let (Err(err), Some(paths)) = (result, &self.paths) {
            let _ = std::fs::write(
                install::log_path(&paths.dir),
                format!("result: failed: {err}\n"),
            );
        }
    }

    /// An updater with a fake system, for tests.
    #[cfg(test)]
    fn with_system(sys: Arc<dyn UpdateSystem>, build: BuildIdentity, data_dir: &Path) -> Self {
        let mut updater = Self::idle();
        updater.sys = sys;
        updater.build = build;
        let _ = updater.load(data_dir);
        updater
    }

    /// Set the phase, for UI tests.
    #[cfg(test)]
    pub(crate) fn set_phase_for_test(&self, phase: Phase) {
        self.shared.lock().phase = phase;
    }

    /// Set the last results, for UI tests.
    #[cfg(test)]
    pub(crate) fn set_results_for_test(
        &self,
        last_check: u64,
        last_result: &str,
        last_install: Option<InstallReport>,
    ) {
        let mut state = self.shared.lock();
        state.file.last_check = Some(last_check);
        state.file.last_result = Some(last_result.to_owned());
        state.file.last_install = last_install;
    }
}

/// The loop of the background thread.
fn worker(
    shared: &Shared,
    paths: &Paths,
    build: &BuildIdentity,
    sys: &dyn UpdateSystem,
    urls: &Urls,
    repaint: &Repaint,
) {
    let mut next = Instant::now() + FIRST_CHECK_DELAY;
    loop {
        let request = {
            let mut state = shared.lock();
            loop {
                if state.stop {
                    return;
                }
                if let Some(request) = state.request.take() {
                    break request;
                }
                let now = Instant::now();
                if state.file.auto_check && now >= next {
                    break Request::Check;
                }
                let wait = if state.file.auto_check {
                    next - now
                } else {
                    Duration::from_secs(3600)
                };
                state = shared
                    .wake
                    .wait_timeout(state, wait)
                    .map_or_else(|err| err.into_inner().0, |(state, _)| state);
            }
        };
        run_once(shared, paths, build, sys, urls, request, repaint.as_ref());
        next = Instant::now() + CHECK_INTERVAL;
    }
}

/// One check. The phase moves through checking, downloading, and verifying, and
/// ends idle, available, ready, or error. `update.json` gets the result.
fn run_once(
    shared: &Shared,
    paths: &Paths,
    build: &BuildIdentity,
    sys: &dyn UpdateSystem,
    urls: &Urls,
    request: Request,
    repaint: &(dyn Fn() + Send + Sync),
) {
    let (download, staged) = {
        let state = shared.lock();
        (
            request == Request::Download || state.file.auto_install,
            state.file.staged.clone(),
        )
    };
    let check = Check {
        sys,
        build,
        dir: &paths.dir,
        urls,
        download,
        staged: staged.as_ref(),
    };
    let result = pipeline::run(&check, &mut |phase| {
        let mut state = shared.lock();
        state.phase = phase;
        let go_on = !state.stop;
        drop(state);
        repaint();
        go_on
    });
    let mut state = shared.lock();
    if state.stop && result.is_err() {
        // The app quits during the check. The next check starts again.
        return;
    }
    state.file.last_check = Some(unix_now());
    match result {
        Ok(Outcome::UpToDate) => {
            // The server no longer offers a staged version: do not install it.
            state.file.staged = None;
            pipeline::clean(&paths.dir);
            state.phase = Phase::Idle;
            state.file.last_result = Some(format!("Apassy {} is up to date.", build.version));
        }
        Ok(Outcome::Available { manifest, blocked }) => {
            state.file.last_result = Some(format!("Apassy {} is available.", manifest.version));
            state.phase = Phase::Available {
                version: manifest.version,
                blocked,
            };
        }
        Ok(Outcome::Ready(staged)) => {
            state.file.last_result = Some(format!("Apassy {} is ready.", staged.version));
            state.file.staged = Some(staged.clone());
            state.phase = Phase::Ready(staged);
        }
        Err(err) => {
            let kept = state
                .file
                .staged
                .clone()
                .filter(|staged| pipeline::staged_present(&paths.dir, staged));
            state.file.last_result = Some(format!("The last check failed: {err}"));
            state.file.staged = kept.clone();
            state.phase = match kept {
                Some(staged) => Phase::Ready(staged),
                None => Phase::Error(err),
            };
        }
    }
    let _ = state.file.save(&paths.file);
    drop(state);
    repaint();
}

impl DesktopApp {
    /// Start the updater of the window. Tests and the smoke test do not call this.
    pub(crate) fn start_updates(&mut self, ctx: &egui::Context) {
        let repaint = ctx.clone();
        let (updater, note) = Updater::start(&crate::paths::data_dir(), move || {
            repaint.request_repaint();
        });
        self.updates = updater;
        match note {
            Some(Ok(message)) => self.set_ok(message),
            Some(Err(message)) => self.set_err(message),
            None => {}
        }
    }

    /// "Restart now": lock the vault and end waiting runs as a quit does, start the
    /// installer, and close the window. The installer opens the new version.
    pub(crate) fn restart_to_update(&mut self, ctx: &egui::Context) {
        let job = match self.updates.install_job(true) {
            Ok(job) => job,
            Err(err) => {
                self.set_err(err);
                return;
            }
        };
        let approvals = match &self.broker {
            BrokerState::Running(handle) => Some(Arc::clone(handle.approvals())),
            _ => None,
        };
        let _ = self
            .owner_ui
            .session
            .lock_ending_runs(approvals.as_deref(), ENDED_BY_QUIT);
        self.erase_typed_secrets(Some(ctx));
        match self.updates.start_install(&job) {
            Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(err) => self.set_err(format!(
                "{err}. The vault is locked. Unlock it to go on, or quit Apassy and install the new version from the site."
            )),
        }
    }

    /// At quit, after the vault is locked: install a ready version when automatic
    /// install is on, and stop the updater.
    pub(crate) fn finish_updates(&mut self) {
        self.updates.stop();
        self.updates.install_at_quit();
    }
}

#[cfg(test)]
mod tests {
    use super::manifest::tests::{COMMIT, manifest_json};
    use super::pipeline::tests::{Fake, TEAM, running};
    use super::*;

    fn run(updater: &Updater, fake: &Fake, request: Request) -> Vec<Phase> {
        let phases = Arc::new(Mutex::new(Vec::new()));
        let paths = updater.paths.clone().expect("paths");
        let seen = Arc::clone(&phases);
        let shared = Arc::clone(&updater.shared);
        let repaint = move || {
            let phase = shared.lock().phase.clone();
            let mut seen = seen.lock().expect("phases");
            if seen.last() != Some(&phase) {
                seen.push(phase);
            }
        };
        run_once(
            &updater.shared,
            &paths,
            &updater.build,
            fake,
            &Urls::for_base(pipeline::SITE),
            request,
            &repaint,
        );
        phases.lock().expect("phases").clone()
    }

    fn kinds(phases: &[Phase]) -> Vec<&'static str> {
        let mut names = Vec::new();
        for phase in phases {
            let name = match phase {
                Phase::Idle => "idle",
                Phase::Checking => "checking",
                Phase::Available { .. } => "available",
                Phase::Downloading { .. } => "downloading",
                Phase::Verifying { .. } => "verifying",
                Phase::Ready(_) => "ready",
                Phase::Error(_) => "error",
            };
            if names.last() != Some(&name) {
                names.push(name);
            }
        }
        names
    }

    fn make_updater(temp: &tempfile::TempDir, fake: Fake) -> (Updater, Arc<Fake>) {
        let fake = Arc::new(fake);
        let sys: Arc<dyn UpdateSystem> = fake.clone();
        let updater = Updater::with_system(sys, running(), &temp.path().join("data"));
        (updater, fake)
    }

    /// Idle, checking, downloading, verifying, ready. The result persists, and the
    /// next start shows the ready version again.
    #[test]
    fn the_state_moves_from_idle_to_ready() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let (updater, fake) = make_updater(&temp, Fake::new(temp.path()));
        assert_eq!(updater.view().phase, Phase::Idle);
        assert!(!updater.view().running, "no thread in tests");
        let phases = run(&updater, &fake, Request::Check);
        assert_eq!(
            kinds(&phases),
            ["checking", "downloading", "verifying", "ready"]
        );
        let view = updater.view();
        let Phase::Ready(staged) = &view.phase else {
            panic!("ready: {:?}", view.phase);
        };
        assert_eq!(staged.version, "0.3.1");
        assert_eq!(view.last_result.as_deref(), Some("Apassy 0.3.1 is ready."));
        assert!(view.last_check.is_some());

        let again = Updater::with_system(fake.clone(), running(), &temp.path().join("data"));
        assert_eq!(
            again.view().phase,
            view.phase,
            "the ready version survives a restart"
        );
        // A newer running build drops the staged version.
        let newer = BuildIdentity::from_parts("0.3.1", Some(COMMIT), Some("2026-10-03T00:00:00Z"));
        let after = Updater::with_system(fake, newer, &temp.path().join("data"));
        assert_eq!(after.view().phase, Phase::Idle);
        assert!(
            !temp
                .path()
                .join("data")
                .join("update")
                .join("Apassy.app")
                .exists()
        );
    }

    #[test]
    fn the_state_ends_in_an_error_after_a_sha_mismatch() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let mut fake = Fake::new(temp.path());
        fake.image = b"synthetic disk imagX".to_vec();
        let (updater, fake) = make_updater(&temp, fake);
        let phases = run(&updater, &fake, Request::Check);
        assert_eq!(kinds(&phases), ["checking", "downloading", "error"]);
        let view = updater.view();
        assert!(
            matches!(&view.phase, Phase::Error(err) if err.contains("SHA-256")),
            "{:?}",
            view.phase
        );
        assert!(
            view.last_result
                .unwrap_or_default()
                .starts_with("The last check failed")
        );
    }

    #[test]
    fn with_automatic_install_off_a_check_only_reports_the_version() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let (updater, fake) = make_updater(&temp, Fake::new(temp.path()));
        updater.set_auto_install(false);
        let phases = run(&updater, &fake, Request::Check);
        assert_eq!(kinds(&phases), ["checking", "available"]);
        assert_eq!(
            updater.view().phase,
            Phase::Available {
                version: "0.3.1".to_owned(),
                blocked: None
            }
        );
        // "Download and install" downloads it anyway.
        let phases = run(&updater, &fake, Request::Download);
        assert_eq!(
            kinds(&phases),
            ["checking", "downloading", "verifying", "ready"]
        );
        // The settings persist.
        let again = Updater::with_system(fake, running(), &temp.path().join("data"));
        assert!(!again.view().auto_install);
        assert!(again.view().auto_check);
    }

    #[test]
    fn an_up_to_date_check_drops_a_version_the_server_no_longer_offers() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let (updater, fake) = make_updater(&temp, Fake::new(temp.path()));
        run(&updater, &fake, Request::Check);
        assert!(matches!(updater.view().phase, Phase::Ready(_)));
        let mut rolled_back = Fake::new(temp.path());
        // The server names the running build again.
        let other = super::manifest::tests::OTHER_COMMIT;
        rolled_back.manifest = manifest_json(&[
            ("version", serde_json::json!("0.3.0")),
            ("commit", serde_json::json!(other)),
            ("build", serde_json::json!(&other[..7])),
        ]);
        let phases = run(&updater, &rolled_back, Request::Check);
        assert_eq!(kinds(&phases), ["checking", "idle"]);
        assert_eq!(
            updater.view().last_result.as_deref(),
            Some("Apassy 0.3.0 is up to date.")
        );
        assert!(
            !temp
                .path()
                .join("data")
                .join("update")
                .join("Apassy.app")
                .exists()
        );
    }

    #[test]
    fn a_failed_check_keeps_a_ready_version() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let (updater, fake) = make_updater(&temp, Fake::new(temp.path()));
        run(&updater, &fake, Request::Check);
        let mut offline = Fake::new(temp.path());
        offline.fetch_error = Some("offline (synthetic)".to_owned());
        run(&updater, &offline, Request::Check);
        assert!(matches!(updater.view().phase, Phase::Ready(_)));
        assert_eq!(
            updater.view().last_result.as_deref(),
            Some("The last check failed: offline (synthetic)")
        );
    }

    #[test]
    fn the_next_start_shows_the_result_of_the_installer() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let data = temp.path().join("data");
        let dir = data.join("update");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("install.log"), "Installing\nresult: ok\n").expect("log");
        let mut updater = Updater::idle();
        let note = updater.load(&data);
        assert_eq!(
            note,
            Some(Ok(format!(
                "Apassy is updated to {}.",
                env!("CARGO_PKG_VERSION")
            )))
        );
        assert!(!dir.join("install.log").exists());
        assert!(updater.view().last_install.is_some_and(|report| report.ok));

        std::fs::write(
            dir.join("install.log"),
            "Installing\nresult: failed: the installed app cannot be moved aside\n",
        )
        .expect("log");
        let mut updater = Updater::idle();
        let note = updater.load(&data).expect("note").expect_err("failed");
        assert!(
            note.contains("the installed app cannot be moved aside"),
            "{note}"
        );
        assert!(dir.join("install-failed.log").exists());
        assert!(!updater.view().last_install.is_some_and(|report| report.ok));
        // Nothing to show on the start after.
        let mut updater = Updater::idle();
        assert_eq!(updater.load(&data), None);
    }

    #[test]
    fn install_needs_a_ready_app_in_a_writable_bundle() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let (updater, fake) = make_updater(&temp, Fake::new(temp.path()));
        assert!(updater.install_job(true).is_err(), "nothing is ready");
        run(&updater, &fake, Request::Check);
        let job = updater.install_job(true).expect("job");
        assert_eq!(job.pid, std::process::id());
        assert_eq!(job.team, TEAM);
        assert!(job.relaunch);
        assert!(job.staged.ends_with("update/Apassy.app"));
        assert!(job.installed.ends_with("Applications/Apassy.app"));
        assert!(job.log.ends_with("update/install.log"));

        let mut blocked = Fake::new(temp.path());
        blocked.location = Location::Bundle {
            bundle: PathBuf::from("/Applications/Apassy.app"),
            writable: false,
        };
        let mut other =
            Updater::with_system(Arc::new(blocked), running(), &temp.path().join("data"));
        let err = other.install_job(false).expect_err("not writable");
        assert!(
            err.contains("cannot replace itself in /Applications"),
            "{err}"
        );
        // Automatic install at quit logs the failure for the next start.
        other.install_at_quit();
        assert!(!other.installer_started);
        let log = temp.path().join("data").join("update").join("install.log");
        assert!(
            matches!(install::read_result(&log), Some(Err(reason)) if reason.contains("cannot replace"))
        );

        // Automatic install off: a quit installs nothing and writes nothing.
        std::fs::remove_file(&log).expect("remove");
        other.set_auto_install(false);
        other.install_at_quit();
        assert!(!log.exists());

        // An idle updater (tests, the smoke test) never installs.
        let mut idle = Updater::idle();
        idle.install_at_quit();
        assert!(idle.install_job(true).is_err());
        assert!(!idle.installer_started);
    }

    #[test]
    fn a_staged_version_is_newer_only_when_it_is_a_later_build() {
        let staged = |version: &str, commit: &str| Staged {
            version: version.to_owned(),
            build: commit[..7].to_owned(),
            commit: commit.to_owned(),
            kind: StagedKind::App,
            team: TEAM.to_owned(),
        };
        let build = BuildIdentity::from_parts("0.3.0", Some(COMMIT), Some("2026-10-01T00:00:00Z"));
        let other = super::manifest::tests::OTHER_COMMIT;
        assert!(staged_is_newer(&staged("0.3.1", COMMIT), &build));
        assert!(staged_is_newer(&staged("0.3.0", other), &build));
        assert!(!staged_is_newer(&staged("0.3.0", COMMIT), &build));
        assert!(!staged_is_newer(&staged("0.2.9", other), &build));
        let dev = BuildIdentity::from_parts("0.3.0", None, None);
        assert!(!staged_is_newer(&staged("0.3.0", other), &dev));
    }
}
