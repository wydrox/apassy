//! One update check: read `latest.json`, compare it with the running build,
//! download the image, check it, and stage the new app.
//!
//! Phases: [`Phase::Checking`], then for a newer version [`Phase::Downloading`] and
//! [`Phase::Verifying`]. The caller turns the [`Outcome`] or the error into the last
//! phase: idle, available, ready, or error.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::manifest::{BuildIdentity, Manifest, is_newer};
use super::store::{Staged, StagedKind, private_dir};
use super::system::{BUNDLE_ID, Location, UpdateSystem};

/// The site of Apassy.
pub(crate) const SITE: &str = "https://apassy.wyderka.cc";
/// The changes of each version.
pub(crate) const CHANGELOG_URL: &str = "https://apassy.wyderka.cc/changelog";
/// The download buttons of the site.
pub(crate) const DOWNLOAD_PAGE_URL: &str = "https://apassy.wyderka.cc/#download";

/// The staged app in the update folder.
pub(crate) fn staged_app(dir: &Path) -> PathBuf {
    dir.join("Apassy.app")
}

/// The checked image in the update folder, when Apassy cannot replace itself.
pub(crate) fn staged_image(dir: &Path) -> PathBuf {
    dir.join("Apassy.dmg")
}

/// True when the files of `staged` are in `dir`.
pub(crate) fn staged_present(dir: &Path, staged: &Staged) -> bool {
    match staged.kind {
        StagedKind::App => fs::symlink_metadata(staged_app(dir)).is_ok_and(|meta| meta.is_dir()),
        StagedKind::Image => {
            fs::symlink_metadata(staged_image(dir)).is_ok_and(|meta| meta.is_file())
        }
    }
}

/// The addresses of `latest.json` and of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Urls {
    pub(crate) manifest: String,
    pub(crate) image: String,
}

impl Urls {
    pub(crate) fn for_base(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        Self {
            manifest: format!("{base}/latest.json"),
            image: format!("{base}/download/Apassy.dmg"),
        }
    }

    /// The release server. A debug build takes another HTTPS server from
    /// `APASSY_UPDATE_BASE`, for development. A release build does not contain
    /// this code. Either way, a new version must pass every check of the image.
    pub(crate) fn current() -> Self {
        #[cfg(debug_assertions)]
        if let Some(base) = std::env::var("APASSY_UPDATE_BASE")
            .ok()
            .filter(|base| valid_override(base))
        {
            return Self::for_base(&base);
        }
        Self::for_base(SITE)
    }
}

/// An HTTPS origin without a path, query, or space.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
fn valid_override(base: &str) -> bool {
    base.strip_prefix("https://").is_some_and(|rest| {
        let rest = rest.trim_end_matches('/');
        !rest.is_empty()
            && rest.len() <= 200
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    })
}

/// The phase of the updater.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Phase {
    Idle,
    Checking,
    /// A newer version. `blocked` says why this copy cannot install it: the owner
    /// then downloads it from the site. Without `blocked`, the owner can start the
    /// download (automatic install is off).
    Available {
        version: String,
        blocked: Option<String>,
    },
    Downloading {
        version: String,
        received: u64,
        total: u64,
    },
    Verifying {
        version: String,
    },
    Ready(Staged),
    Error(String),
}

/// The end of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    UpToDate,
    Available {
        manifest: Manifest,
        blocked: Option<String>,
    },
    Ready(Staged),
}

/// Why this copy cannot install a new version.
pub(crate) const NOT_A_BUNDLE: &str = "This copy of Apassy does not run from an app bundle, so it cannot install a new version. Download it from the site.";
pub(crate) const NO_TEAM: &str = "This copy of Apassy has no Developer ID signature, so it cannot check that a new version comes from the same developer. Download it from the site.";

/// The input of one check.
pub(crate) struct Check<'a> {
    pub(crate) sys: &'a dyn UpdateSystem,
    pub(crate) build: &'a BuildIdentity,
    /// The update folder, `<data dir>/update`.
    pub(crate) dir: &'a Path,
    pub(crate) urls: &'a Urls,
    /// Download a newer version. When false, the check only reports it.
    pub(crate) download: bool,
    /// The version that is staged already, if any.
    pub(crate) staged: Option<&'a Staged>,
}

/// Run one check. `report` gets each phase. It returns false to stop a download:
/// the app quits.
pub(crate) fn run(
    check: &Check<'_>,
    report: &mut dyn FnMut(Phase) -> bool,
) -> Result<Outcome, String> {
    let _ = report(Phase::Checking);
    let bytes = check.sys.fetch(&check.urls.manifest)?;
    let macos = check.sys.macos_version()?;
    let manifest = Manifest::parse(&bytes, &macos).map_err(|err| err.to_string())?;
    if !is_newer(&manifest, check.build) {
        return Ok(Outcome::UpToDate);
    }
    if let Some(staged) = check.staged
        && staged.version == manifest.version
        && staged.commit == manifest.commit
        && staged_present(check.dir, staged)
    {
        return Ok(Outcome::Ready(staged.clone()));
    }
    let writable = match check.sys.location() {
        Location::NotBundle => {
            return Ok(Outcome::Available {
                manifest,
                blocked: Some(NOT_A_BUNDLE.to_owned()),
            });
        }
        Location::Bundle { writable, .. } => writable,
    };
    let Some(team) = check.sys.running_team()? else {
        return Ok(Outcome::Available {
            manifest,
            blocked: Some(NO_TEAM.to_owned()),
        });
    };
    if !check.download {
        return Ok(Outcome::Available {
            manifest,
            blocked: None,
        });
    }
    let kind = download_and_verify(check, &manifest, &team, writable, report)?;
    Ok(Outcome::Ready(Staged {
        version: manifest.version,
        build: manifest.build,
        commit: manifest.commit,
        kind,
        team,
    }))
}

/// Remove what an earlier check left in the update folder. A mount folder is
/// removed only when it is empty, so a volume that is still attached stays.
pub(crate) fn clean(dir: &Path) {
    let _ = fs::remove_file(dir.join("Apassy.dmg.part"));
    let _ = fs::remove_file(staged_image(dir));
    let _ = fs::remove_dir_all(dir.join("Apassy.app.part"));
    let _ = fs::remove_dir_all(staged_app(dir));
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("mount-") {
                let _ = fs::remove_dir(entry.path());
            }
        }
    }
}

/// The SHA-256 of a file, in lowercase hex.
pub(crate) fn sha256_file(path: &Path) -> io::Result<String> {
    use std::fmt::Write as _;

    let mut file = fs::File::open(path)?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0_u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    let mut hex = String::with_capacity(64);
    for byte in context.finish().as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

fn download_and_verify(
    check: &Check<'_>,
    manifest: &Manifest,
    team: &str,
    writable: bool,
    report: &mut dyn FnMut(Phase) -> bool,
) -> Result<StagedKind, String> {
    let dir = check.dir;
    let version = manifest.version.clone();
    let total = manifest.size;
    // The app quits, maybe to install the staged version: keep it.
    if !report(Phase::Downloading {
        version: version.clone(),
        received: 0,
        total,
    }) {
        return Err("The download stopped.".to_owned());
    }
    private_dir(dir).map_err(|err| format!("Apassy cannot make {}: {err}", dir.display()))?;
    clean(dir);
    let part = dir.join("Apassy.dmg.part");
    let downloaded = check
        .sys
        .download(&check.urls.image, &part, total, &mut |received| {
            report(Phase::Downloading {
                version: version.clone(),
                received,
                total,
            })
        });
    let checked = downloaded.and_then(|()| {
        let size = fs::metadata(&part)
            .map_err(|err| format!("The download is missing: {err}"))?
            .len();
        if size != total {
            return Err(format!(
                "The download has {size} bytes, but the update information says {total}. Apassy deleted it."
            ));
        }
        let digest =
            sha256_file(&part).map_err(|err| format!("Apassy cannot read the download: {err}"))?;
        if digest != manifest.sha256 {
            return Err(
                "The SHA-256 of the download does not match the update information. Apassy deleted it."
                    .to_owned(),
            );
        }
        Ok(())
    });
    if let Err(err) = checked {
        let _ = fs::remove_file(&part);
        return Err(err);
    }
    let image = staged_image(dir);
    fs::rename(&part, &image).map_err(|err| format!("Apassy cannot keep the download: {err}"))?;
    let _ = report(Phase::Verifying {
        version: version.clone(),
    });
    let result = verify_image(check, manifest, team, &image, writable);
    match &result {
        Ok(StagedKind::App) | Err(_) => {
            let _ = fs::remove_file(&image);
        }
        Ok(StagedKind::Image) => {}
    }
    result
}

/// Attach the image at a private folder in the update folder, check the app in it,
/// and detach it. The image stays attached only while the check runs.
fn verify_image(
    check: &Check<'_>,
    manifest: &Manifest,
    team: &str,
    image: &Path,
    writable: bool,
) -> Result<StagedKind, String> {
    let mount = tempfile::Builder::new()
        .prefix("mount-")
        .tempdir_in(check.dir)
        .map_err(|err| format!("Apassy cannot make a folder for the disk image: {err}"))?;
    check.sys.attach(image, mount.path())?;
    let result = check_app(
        check,
        manifest,
        team,
        &mount.path().join("Apassy.app"),
        writable,
    );
    let detached = check.sys.detach(mount.path());
    if detached.is_err() {
        // Never remove files under a volume that is still attached.
        let _ = mount.keep();
    }
    let kind = result?;
    detached?;
    Ok(kind)
}

/// The build identity in the signed `Info.plist` of the new app must be the build
/// of `latest.json`. The version is checked apart: only a higher version gets this
/// far (ADR 0015).
fn check_build(manifest: &Manifest, info: &super::system::BundleInfo) -> Result<(), String> {
    if let Some(commit) = &info.build_commit
        && *commit != manifest.commit
    {
        return Err(format!(
            "The app in the disk image is build {}, but the update information says {}.",
            commit.get(..7).unwrap_or(commit),
            manifest.build
        ));
    }
    Ok(())
}

fn check_app(
    check: &Check<'_>,
    manifest: &Manifest,
    team: &str,
    app: &Path,
    writable: bool,
) -> Result<StagedKind, String> {
    let sys = check.sys;
    let is_dir = fs::symlink_metadata(app).is_ok_and(|meta| meta.is_dir());
    if !is_dir {
        return Err("The disk image has no Apassy.app.".to_owned());
    }
    let info = sys.bundle_info(app)?;
    if info.identifier != BUNDLE_ID {
        return Err(format!(
            "The app in the disk image has the bundle ID {}, not {BUNDLE_ID}.",
            info.identifier
        ));
    }
    if info.version != manifest.version {
        return Err(format!(
            "The app in the disk image has version {}, but the update information says {}.",
            info.version, manifest.version
        ));
    }
    check_build(manifest, &info)?;
    match sys.signing_team(app)? {
        Some(signed) if signed == team => {}
        Some(signed) => {
            return Err(format!(
                "The new version is signed by team {signed}, not by team {team} of this copy. Apassy does not install it."
            ));
        }
        None => {
            return Err("The new version has no Developer ID signature.".to_owned());
        }
    }
    sys.verify_signature(app, team)?;
    sys.assess(app)?;
    if !writable {
        return Ok(StagedKind::Image);
    }
    let part = check.dir.join("Apassy.app.part");
    let _ = fs::remove_dir_all(&part);
    sys.copy_app(app, &part)?;
    if let Err(err) = sys.verify_signature(&part, team) {
        let _ = fs::remove_dir_all(&part);
        return Err(err);
    }
    let staged = staged_app(check.dir);
    let _ = fs::remove_dir_all(&staged);
    fs::rename(&part, &staged).map_err(|err| {
        let _ = fs::remove_dir_all(&part);
        format!("Apassy cannot keep the new version: {err}")
    })?;
    Ok(StagedKind::App)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::manifest::tests::{COMMIT, OTHER_COMMIT, manifest_json};
    use super::super::system::BundleInfo;
    use super::*;
    use std::sync::Mutex;

    pub(crate) const TEAM: &str = "ABCDE12345";

    /// A fake system. Its disk image is a folder; `attach` copies it to the mount
    /// point.
    pub(crate) struct Fake {
        pub(crate) manifest: Vec<u8>,
        pub(crate) image: Vec<u8>,
        pub(crate) location: Location,
        pub(crate) running_team: Option<String>,
        pub(crate) app_id: String,
        pub(crate) app_version: String,
        pub(crate) app_commit: Option<String>,
        pub(crate) app_team: Option<String>,
        pub(crate) signature_ok: bool,
        pub(crate) gatekeeper_ok: bool,
        pub(crate) fetch_error: Option<String>,
        pub(crate) calls: Mutex<Vec<String>>,
    }

    impl Fake {
        pub(crate) fn new(dir: &Path) -> Self {
            let image = b"synthetic disk image".to_vec();
            let digest = {
                let path = dir.join("digest-probe");
                fs::write(&path, &image).expect("write");
                let digest = sha256_file(&path).expect("hash");
                fs::remove_file(&path).expect("remove");
                digest
            };
            Self {
                manifest: manifest_json(&[
                    ("size", serde_json::json!(image.len())),
                    ("sha256", serde_json::json!(digest)),
                ]),
                image,
                location: Location::Bundle {
                    bundle: dir.join("Applications").join("Apassy.app"),
                    writable: true,
                },
                running_team: Some(TEAM.to_owned()),
                app_id: BUNDLE_ID.to_owned(),
                app_version: "0.3.1".to_owned(),
                app_commit: Some(COMMIT.to_owned()),
                app_team: Some(TEAM.to_owned()),
                signature_ok: true,
                gatekeeper_ok: true,
                fetch_error: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn call(&self, name: &str) {
            self.calls.lock().expect("calls").push(name.to_owned());
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls").clone()
        }
    }

    impl UpdateSystem for Fake {
        fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
            self.call("fetch");
            assert!(url.starts_with("https://"));
            match &self.fetch_error {
                Some(err) => Err(err.clone()),
                None => Ok(self.manifest.clone()),
            }
        }

        fn download(
            &self,
            url: &str,
            dest: &Path,
            max_bytes: u64,
            progress: &mut dyn FnMut(u64) -> bool,
        ) -> Result<(), String> {
            self.call("download");
            assert!(url.ends_with("/download/Apassy.dmg"));
            let bytes = &self.image[..self.image.len().min(max_bytes as usize + 1)];
            let half = bytes.len() / 2;
            fs::write(dest, &bytes[..half]).expect("write");
            if !progress(half as u64) {
                return Err("The download stopped.".to_owned());
            }
            fs::write(dest, bytes).expect("write");
            let _ = progress(bytes.len() as u64);
            Ok(())
        }

        fn macos_version(&self) -> Result<String, String> {
            Ok("15.4".to_owned())
        }

        fn running_team(&self) -> Result<Option<String>, String> {
            self.call("running_team");
            Ok(self.running_team.clone())
        }

        fn location(&self) -> Location {
            self.location.clone()
        }

        fn attach(&self, image: &Path, mountpoint: &Path) -> Result<(), String> {
            self.call("attach");
            assert_eq!(fs::read(image).expect("image"), self.image);
            let app = mountpoint.join("Apassy.app").join("Contents");
            fs::create_dir_all(&app).expect("app");
            fs::write(app.join("Info.plist"), b"synthetic").expect("plist");
            Ok(())
        }

        fn detach(&self, mountpoint: &Path) -> Result<(), String> {
            self.call("detach");
            fs::remove_dir_all(mountpoint.join("Apassy.app")).expect("detach");
            Ok(())
        }

        fn bundle_info(&self, _app: &Path) -> Result<BundleInfo, String> {
            Ok(BundleInfo {
                identifier: self.app_id.clone(),
                version: self.app_version.clone(),
                build_commit: self.app_commit.clone(),
            })
        }

        fn signing_team(&self, _app: &Path) -> Result<Option<String>, String> {
            Ok(self.app_team.clone())
        }

        fn verify_signature(&self, _app: &Path, team: &str) -> Result<(), String> {
            self.call("verify");
            if self.signature_ok && self.app_team.as_deref() == Some(team) {
                Ok(())
            } else {
                Err("The signature of the new version is not valid (synthetic).".to_owned())
            }
        }

        fn assess(&self, _app: &Path) -> Result<(), String> {
            self.call("assess");
            if self.gatekeeper_ok {
                Ok(())
            } else {
                Err("Gatekeeper does not accept the new version (synthetic).".to_owned())
            }
        }

        fn copy_app(&self, from: &Path, to: &Path) -> Result<(), String> {
            self.call("copy");
            fs::create_dir_all(to.join("Contents")).expect("copy");
            fs::copy(
                from.join("Contents").join("Info.plist"),
                to.join("Contents").join("Info.plist"),
            )
            .expect("copy");
            Ok(())
        }
    }

    pub(crate) fn running() -> BuildIdentity {
        BuildIdentity::from_parts("0.3.0", Some(OTHER_COMMIT), Some("2026-10-01T00:00:00Z"))
    }

    fn check_with(
        fake: &Fake,
        dir: &Path,
        download: bool,
        staged: Option<&Staged>,
    ) -> (Result<Outcome, String>, Vec<Phase>) {
        let build = running();
        let urls = Urls::for_base(SITE);
        let check = Check {
            sys: fake,
            build: &build,
            dir,
            urls: &urls,
            download,
            staged,
        };
        let mut phases = Vec::new();
        let result = run(&check, &mut |phase| {
            phases.push(phase);
            true
        });
        (result, phases)
    }

    /// The names of the phases, with repeated download progress folded.
    fn names(phases: &[Phase]) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = Vec::new();
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

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[test]
    fn a_newer_version_is_downloaded_checked_and_staged() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let fake = Fake::new(temp.path());
        let (result, phases) = check_with(&fake, &dir, true, None);
        let Ok(Outcome::Ready(staged)) = result else {
            panic!("ready: {result:?}");
        };
        assert_eq!(names(&phases), ["checking", "downloading", "verifying"]);
        let progress: Vec<u64> = phases
            .iter()
            .filter_map(|phase| match phase {
                Phase::Downloading { received, .. } => Some(*received),
                _ => None,
            })
            .collect();
        assert_eq!(progress, [0, 10, 20], "progress of the download");
        assert_eq!(staged.version, "0.3.1");
        assert_eq!(staged.commit, COMMIT);
        assert_eq!(staged.kind, StagedKind::App);
        assert_eq!(staged.team, TEAM);
        // The app is staged; the image and the mount folder are gone.
        assert_eq!(files(&dir), ["Apassy.app"]);
        assert!(staged_present(&dir, &staged));
        assert_eq!(
            fake.calls(),
            [
                "fetch",
                "running_team",
                "download",
                "attach",
                "verify",
                "assess",
                "copy",
                "verify",
                "detach"
            ]
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&dir).expect("dir").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the update folder is private");

        // A second check finds the same version staged and downloads nothing.
        let (result, phases) = check_with(&fake, &dir, true, Some(&staged));
        assert_eq!(result, Ok(Outcome::Ready(staged)));
        assert_eq!(names(&phases), ["checking"]);
        assert_eq!(fake.calls().iter().filter(|c| *c == "download").count(), 1);
    }

    /// A quit during a check stops it before it touches the update folder.
    #[test]
    fn a_stop_keeps_the_update_folder() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        fs::create_dir_all(staged_app(&dir)).expect("staged");
        let fake = Fake::new(temp.path());
        let build = running();
        let urls = Urls::for_base(SITE);
        let check = Check {
            sys: &fake,
            build: &build,
            dir: &dir,
            urls: &urls,
            download: true,
            staged: None,
        };
        let result = run(&check, &mut |phase| {
            !matches!(phase, Phase::Downloading { .. })
        });
        assert_eq!(result, Err("The download stopped.".to_owned()));
        assert_eq!(files(&dir), ["Apassy.app"]);
        assert!(!fake.calls().contains(&"download".to_owned()));
    }

    #[test]
    fn the_same_or_an_older_build_is_up_to_date() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        for version in ["0.3.0", "0.2.9", "0.3.0-rc.1"] {
            fake.manifest = manifest_json(&[
                ("version", serde_json::json!(version)),
                ("date", serde_json::json!("2026-09-30T00:00:00Z")),
            ]);
            let (result, phases) = check_with(&fake, &dir, true, None);
            assert_eq!(result, Ok(Outcome::UpToDate), "{version}");
            assert_eq!(names(&phases), ["checking"]);
        }
        assert!(!fake.calls().contains(&"download".to_owned()));
        assert!(!dir.exists(), "nothing is written for an up-to-date check");
    }

    #[test]
    fn a_sha_mismatch_deletes_the_download() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        fake.image = b"synthetic disk imagE".to_vec();
        let (result, phases) = check_with(&fake, &dir, true, None);
        let err = result.expect_err("mismatch");
        assert!(err.contains("SHA-256"), "{err}");
        assert_eq!(names(&phases), ["checking", "downloading"]);
        assert!(files(&dir).is_empty(), "{:?}", files(&dir));
        assert!(!fake.calls().contains(&"attach".to_owned()));
    }

    #[test]
    fn a_size_mismatch_deletes_the_download() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        fake.image = b"short".to_vec();
        let (result, _) = check_with(&fake, &dir, true, None);
        let err = result.expect_err("mismatch");
        assert!(err.contains("5 bytes") && err.contains("says 20"), "{err}");
        assert!(files(&dir).is_empty());

        // A longer download stops at the size of the manifest plus one byte.
        fake.image = b"synthetic disk image and more".to_vec();
        let (result, _) = check_with(&fake, &dir, true, None);
        let err = result.expect_err("mismatch");
        assert!(err.contains("21 bytes"), "{err}");
        assert!(files(&dir).is_empty());
    }

    /// Each failed check of the app in the image ends in an error, detaches the
    /// image, and deletes it.
    #[test]
    fn an_app_that_fails_a_check_is_refused() {
        type Change = fn(&mut Fake);
        let cases: [(Change, &str); 7] = [
            (
                |fake| fake.app_id = "com.example.other".to_owned(),
                "bundle ID",
            ),
            (
                |fake| fake.app_version = "0.3.2".to_owned(),
                "version 0.3.2",
            ),
            (
                |fake| fake.app_commit = Some(OTHER_COMMIT.to_owned()),
                "build 0123456",
            ),
            (
                |fake| fake.app_team = Some("ZZZZZ99999".to_owned()),
                "team ZZZZZ99999",
            ),
            (|fake| fake.app_team = None, "no Developer ID"),
            (|fake| fake.signature_ok = false, "signature"),
            (|fake| fake.gatekeeper_ok = false, "Gatekeeper"),
        ];
        for (change, expected) in cases {
            let temp = tempfile::TempDir::new().expect("temp dir");
            let dir = temp.path().join("update");
            let mut fake = Fake::new(temp.path());
            change(&mut fake);
            let (result, phases) = check_with(&fake, &dir, true, None);
            let err = result.expect_err(expected);
            assert!(err.contains(expected), "{expected}: {err}");
            assert_eq!(names(&phases), ["checking", "downloading", "verifying"]);
            assert!(files(&dir).is_empty(), "{expected}: {:?}", files(&dir));
            let calls = fake.calls();
            assert_eq!(
                calls.last().map(String::as_str),
                Some("detach"),
                "{expected}"
            );
            assert!(!calls.contains(&"copy".to_owned()), "{expected}");
        }
    }

    /// Another build of the same version is up to date: nothing downloads. A higher
    /// version installs also from an app without the build identity keys.
    #[test]
    fn only_a_higher_version_downloads() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        fake.manifest = manifest_json(&[
            ("version", serde_json::json!("0.3.0")),
            ("size", serde_json::json!(fake.image.len())),
            ("sha256", serde_json::json!(digest_of(&fake.image))),
        ]);
        fake.app_version = "0.3.0".to_owned();
        let (result, _) = check_with(&fake, &dir, true, None);
        assert!(matches!(result, Ok(Outcome::UpToDate)), "{result:?}");
        assert!(!fake.calls().contains(&"download".to_owned()));
        assert!(files(&dir).is_empty());

        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        fake.app_commit = None;
        let (result, _) = check_with(&fake, &dir, true, None);
        assert!(matches!(result, Ok(Outcome::Ready(_))), "{result:?}");
    }

    fn digest_of(bytes: &[u8]) -> String {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let path = temp.path().join("bytes");
        fs::write(&path, bytes).expect("write");
        sha256_file(&path).expect("hash")
    }

    #[test]
    fn a_copy_that_cannot_install_only_reports_the_version() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        fake.running_team = None;
        let (result, _) = check_with(&fake, &dir, true, None);
        let Ok(Outcome::Available { manifest, blocked }) = result else {
            panic!("available: {result:?}");
        };
        assert_eq!(manifest.version, "0.3.1");
        assert_eq!(blocked.as_deref(), Some(NO_TEAM));

        fake.location = Location::NotBundle;
        let (result, _) = check_with(&fake, &dir, true, None);
        assert!(
            matches!(&result, Ok(Outcome::Available { blocked: Some(text), .. }) if text == NOT_A_BUNDLE),
            "{result:?}"
        );
        assert!(!fake.calls().contains(&"download".to_owned()));

        // Automatic install off: the check reports the version and downloads nothing.
        let fake = Fake::new(temp.path());
        let (result, _) = check_with(&fake, &dir, false, None);
        assert!(
            matches!(&result, Ok(Outcome::Available { blocked: None, .. })),
            "{result:?}"
        );
        assert!(!fake.calls().contains(&"download".to_owned()));
    }

    #[test]
    fn a_folder_that_apassy_cannot_write_keeps_the_checked_image() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        fake.location = Location::Bundle {
            bundle: PathBuf::from("/Applications/Apassy.app"),
            writable: false,
        };
        let (result, _) = check_with(&fake, &dir, true, None);
        let Ok(Outcome::Ready(staged)) = result else {
            panic!("ready: {result:?}");
        };
        assert_eq!(staged.kind, StagedKind::Image);
        assert_eq!(files(&dir), ["Apassy.dmg"]);
        assert_eq!(fs::read(staged_image(&dir)).expect("image"), fake.image);
        assert!(!fake.calls().contains(&"copy".to_owned()));
        assert!(fake.calls().contains(&"assess".to_owned()), "checked first");
    }

    #[test]
    fn errors_of_the_check_are_reported() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        let mut fake = Fake::new(temp.path());
        fake.fetch_error = Some("Apassy cannot reach the update server (synthetic).".to_owned());
        let (result, _) = check_with(&fake, &dir, true, None);
        assert_eq!(
            result,
            Err("Apassy cannot reach the update server (synthetic).".to_owned())
        );
        fake.fetch_error = None;
        fake.manifest = manifest_json(&[("arch", serde_json::json!("x86_64"))]);
        let (result, _) = check_with(&fake, &dir, true, None);
        assert!(result.expect_err("arch").contains("\"arch\""));
    }

    #[test]
    fn stale_files_are_cleaned_before_a_download() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let dir = temp.path().join("update");
        fs::create_dir_all(dir.join("mount-old")).expect("mount");
        fs::create_dir_all(dir.join("mount-busy").join("Apassy.app")).expect("busy");
        fs::create_dir_all(dir.join("Apassy.app.part")).expect("part");
        fs::write(dir.join("Apassy.dmg.part"), b"old").expect("part");
        fs::write(dir.join("install.log"), b"result: ok\n").expect("log");
        clean(&dir);
        assert_eq!(files(&dir), ["install.log", "mount-busy"]);
    }

    #[test]
    fn sha256_of_a_file() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let path = temp.path().join("abc");
        fs::write(&path, b"abc").expect("write");
        assert_eq!(
            sha256_file(&path).expect("hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn only_https_origins_override_the_server() {
        assert!(valid_override("https://localhost:8443"));
        assert!(valid_override("https://updates.example.com/"));
        for bad in [
            "http://localhost:8787",
            "https://",
            "https://host/path",
            "https://host?x",
            "https://user@host",
            "file:///tmp",
        ] {
            assert!(!valid_override(bad), "{bad}");
        }
        let urls = Urls::for_base("https://apassy.wyderka.cc/");
        assert_eq!(urls.manifest, "https://apassy.wyderka.cc/latest.json");
        assert_eq!(urls.image, "https://apassy.wyderka.cc/download/Apassy.dmg");
    }
}
