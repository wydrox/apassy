//! The system calls of an update, behind [`UpdateSystem`], so tests run the whole
//! check with a fake and no network.
//!
//! [`Commands`] is the real one. It runs the tools of macOS by their full path, with
//! an empty environment, a time limit, and a limit on the output:
//!
//! - `/usr/bin/curl` for HTTPS. It uses the macOS trust store, streams a large image
//!   to a file, and keeps redirects on HTTPS. The rustls client of the broker
//!   (`src/broker/http.rs`) reads at most 64 KiB and has no streaming, so it does not
//!   fit a download of about 110 MB.
//! - `hdiutil`, `plutil`, `codesign`, `spctl`, `ditto`, and `sw_vers` for the checks.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::manifest::MAX_MANIFEST_BYTES;

/// The bundle ID of the app, and the signing identifier of its main program.
pub(crate) const BUNDLE_ID: &str = "com.wydrox.apassy";

/// The start of the code requirement for a new version, up to the team. The
/// installer script uses the same text (`install.rs`).
///
/// - `identifier`: the signing identifier of the Apassy app.
/// - `anchor apple generic`: a certificate chain to the Apple root.
/// - `certificate 1[field.1.2.840.113635.100.6.2.6]`: the Developer ID
///   intermediate.
/// - `certificate leaf[field.1.2.840.113635.100.6.1.13]`: a Developer ID
///   Application certificate.
/// - `certificate leaf[subject.OU]`: the team, added by [`requirement`].
macro_rules! requirement_prefix {
    () => {
        r#"identifier "com.wydrox.apassy" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "#
    };
}
pub(crate) use requirement_prefix;

/// The code requirement for a new version signed by `team`.
pub(crate) fn requirement(team: &str) -> String {
    format!("{}\"{team}\"", requirement_prefix!())
}

/// A team ID: 10 characters, uppercase letters and digits.
pub(crate) fn is_team_id(text: &str) -> bool {
    text.len() == 10
        && text
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// The key of the build commit in `Contents/Info.plist`. `scripts/build-app.sh` adds
/// it, and `ApassyBuildDate`, before the signature, so the signature covers them.
pub(crate) const PLIST_BUILD_COMMIT: &str = "ApassyBuildCommit";

/// The fields of `Contents/Info.plist` that the check reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleInfo {
    pub(crate) identifier: String,
    pub(crate) version: String,
    /// [`PLIST_BUILD_COMMIT`], when the app has it.
    pub(crate) build_commit: Option<String>,
}

/// Where the running app is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Location {
    /// The app runs from `bundle` (`<bundle>/Contents/MacOS/<program>`).
    /// `writable` is true when Apassy can replace the bundle in its folder.
    Bundle { bundle: PathBuf, writable: bool },
    /// The program is not in an app bundle, for example `cargo run`.
    NotBundle,
}

/// The system calls of a check, a download, and the checks of an image.
pub(crate) trait UpdateSystem: Send + Sync {
    /// GET `url` over HTTPS. At most [`MAX_MANIFEST_BYTES`].
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String>;
    /// GET `url` over HTTPS into `dest`. Stop after `max_bytes`. `progress` gets
    /// the bytes so far, and returns false to stop the download.
    fn download(
        &self,
        url: &str,
        dest: &Path,
        max_bytes: u64,
        progress: &mut dyn FnMut(u64) -> bool,
    ) -> Result<(), String>;
    /// The macOS version, for example `15.4.1`.
    fn macos_version(&self) -> Result<String, String>;
    /// The team of the signature of the running app. `None` when the running
    /// program is not the signed Apassy app, or when its signature is not a
    /// Developer ID Application signature (ad hoc, or Apple Development for a
    /// build from source).
    fn running_team(&self) -> Result<Option<String>, String>;
    fn location(&self) -> Location;
    /// Attach `image` read-only at `mountpoint`, with no Finder window.
    fn attach(&self, image: &Path, mountpoint: &Path) -> Result<(), String>;
    fn detach(&self, mountpoint: &Path) -> Result<(), String>;
    fn bundle_info(&self, app: &Path) -> Result<BundleInfo, String>;
    /// The team of the signature of `app`, if any.
    fn signing_team(&self, app: &Path) -> Result<Option<String>, String>;
    /// `codesign --verify --deep --strict` against [`requirement`] for `team`.
    fn verify_signature(&self, app: &Path, team: &str) -> Result<(), String>;
    /// Gatekeeper: `spctl --assess --type exec`. It passes only for a notarized
    /// Developer ID app.
    fn assess(&self, app: &Path) -> Result<(), String>;
    /// Copy a bundle with `ditto`.
    fn copy_app(&self, from: &Path, to: &Path) -> Result<(), String>;
}

/// The real system calls.
pub(crate) struct Commands;

/// A command with an empty environment and a fixed `PATH`.
fn tool(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .current_dir("/")
        .stdin(Stdio::null());
    command
}

/// The output of a finished command.
struct Output {
    ok: bool,
    stdout: Vec<u8>,
    stderr: String,
}

/// Read at most `limit` bytes from `reader` on a new thread.
fn read_limited(
    reader: Option<impl Read + Send + 'static>,
    limit: u64,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(reader) = reader {
            let mut limited = reader.take(limit + 1);
            let _ = limited.read_to_end(&mut bytes);
            // Drain the rest, so the child does not block on a full pipe.
            let _ = std::io::copy(&mut limited.into_inner(), &mut std::io::sink());
        }
        bytes
    })
}

/// Run `command` for at most `timeout`. Stdout over `limit` bytes is an error.
fn run(mut command: Command, timeout: Duration, limit: u64) -> Result<Output, String> {
    let name = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{name} did not start: {err}"))?;
    let stdout = read_limited(child.stdout.take(), limit);
    let stderr = read_limited(child.stderr.take(), 16 * 1024);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{name} did not finish in time"));
            }
            Err(err) => return Err(format!("{name} failed: {err}")),
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = String::from_utf8_lossy(&stderr.join().unwrap_or_default())
        .trim()
        .to_owned();
    if stdout.len() as u64 > limit {
        return Err(format!("{name} wrote more than {limit} bytes"));
    }
    Ok(Output {
        ok: status.success(),
        stdout,
        stderr,
    })
}

/// Run `command`, and fail with its error output when it fails.
fn run_ok(command: Command, timeout: Duration, what: &str) -> Result<Vec<u8>, String> {
    let output = run(command, timeout, 64 * 1024)?;
    if output.ok {
        Ok(output.stdout)
    } else {
        let detail = output
            .stderr
            .lines()
            .last()
            .unwrap_or("no details")
            .to_owned();
        Err(format!("{what} ({detail})"))
    }
}

/// `/usr/bin/curl` for one HTTPS URL. `-q` skips `~/.curlrc`.
fn curl(url: &str) -> Result<Command, String> {
    if !url.starts_with("https://") {
        return Err("Apassy downloads updates over HTTPS only.".to_owned());
    }
    let mut command = tool("/usr/bin/curl");
    command.args([
        "-q",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "3",
        "--connect-timeout",
        "20",
        "--user-agent",
        concat!("Apassy/", env!("CARGO_PKG_VERSION")),
    ]);
    Ok(command)
}

/// The `TeamIdentifier=` line of `codesign -d --verbose=2`.
pub(crate) fn team_from_codesign(output: &str) -> Option<String> {
    let team = output
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))?
        .trim();
    is_team_id(team).then(|| team.to_owned())
}

/// The team of `codesign -d --verbose=2` output when the leaf certificate (the first
/// `Authority=` line) is a Developer ID Application certificate. A build from
/// source, signed with an "Apple Development" certificate, has a team but no
/// Developer ID. Such a copy does not download updates: a release of another team
/// can never pass [`requirement`] for it, and its owner updates it with the
/// installer (docs/operations/updates.md).
pub(crate) fn developer_id_team_from_codesign(output: &str) -> Option<String> {
    let leaf = output
        .lines()
        .find_map(|line| line.strip_prefix("Authority="))?;
    if leaf.trim().starts_with("Developer ID Application: ") {
        team_from_codesign(output)
    } else {
        None
    }
}

/// The `Identifier=` line of `codesign -d --verbose=2`.
fn identifier_from_codesign(output: &str) -> Option<&str> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("Identifier="))
        .map(str::trim)
}

fn plist_value(app: &Path, key: &str) -> Result<String, String> {
    let mut command = tool("/usr/bin/plutil");
    command
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(app.join("Contents").join("Info.plist"));
    let bytes = run_ok(
        command,
        Duration::from_secs(20),
        "The app has no Info.plist",
    )?;
    Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
}

/// `<bundle>` when `exe` is `<bundle>.app/Contents/MacOS/<program>`.
pub(crate) fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    let is_bundle = macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app";
    is_bundle.then(|| bundle.to_path_buf())
}

/// True when this user can replace `bundle`: a file can be made in its folder, and
/// the user owns the bundle, so the old copy can be removed.
pub(crate) fn can_replace(bundle: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Some(parent) = bundle.parent() else {
        return false;
    };
    let probe = tempfile::Builder::new()
        .prefix(".apassy-update-probe.")
        .tempfile_in(parent);
    let owned = std::fs::symlink_metadata(bundle)
        .is_ok_and(|meta| meta.uid() == rustix::process::getuid().as_raw());
    probe.is_ok() && owned
}

impl UpdateSystem for Commands {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut command = curl(url)?;
        command.args([
            "--max-time",
            "60",
            "--max-filesize",
            &MAX_MANIFEST_BYTES.to_string(),
            "--header",
            "Cache-Control: no-cache",
            "--header",
            "Accept: application/json",
            url,
        ]);
        let output = run(command, Duration::from_secs(90), MAX_MANIFEST_BYTES)?;
        if !output.ok && output.stderr.contains("error: 404") {
            return Err("The update server has no published version yet.".to_owned());
        }
        if !output.ok {
            return Err(format!(
                "Apassy cannot reach the update server ({}).",
                output.stderr.lines().last().unwrap_or("no details")
            ));
        }
        Ok(output.stdout)
    }

    fn download(
        &self,
        url: &str,
        dest: &Path,
        max_bytes: u64,
        progress: &mut dyn FnMut(u64) -> bool,
    ) -> Result<(), String> {
        let mut command = curl(url)?;
        command
            .args([
                "--max-time",
                "3600",
                // Stop when the transfer is slower than 1 KB/s for a minute.
                "--speed-limit",
                "1024",
                "--speed-time",
                "60",
                "--max-filesize",
                &max_bytes.to_string(),
                "--output",
            ])
            .arg(dest)
            .arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|err| format!("curl did not start: {err}"))?;
        let stderr = read_limited(child.stderr.take(), 16 * 1024);
        let deadline = Instant::now() + Duration::from_secs(3700);
        let status = loop {
            let size = std::fs::metadata(dest).map_or(0, |meta| meta.len());
            let go_on = progress(size.min(max_bytes));
            let stop = if !go_on {
                Some("The download stopped.")
            } else if size > max_bytes {
                Some("The download is larger than the update information says.")
            } else if Instant::now() > deadline {
                Some("The download did not finish in time.")
            } else {
                None
            };
            if let Some(reason) = stop {
                let _ = child.kill();
                let _ = child.wait();
                return Err(reason.to_owned());
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => std::thread::sleep(Duration::from_millis(250)),
                Err(err) => return Err(format!("curl failed: {err}")),
            }
        };
        let stderr = String::from_utf8_lossy(&stderr.join().unwrap_or_default()).into_owned();
        if !status.success() {
            return Err(format!(
                "The download failed ({}).",
                stderr.trim().lines().last().unwrap_or("no details")
            ));
        }
        let _ = progress(std::fs::metadata(dest).map_or(0, |meta| meta.len()));
        Ok(())
    }

    fn macos_version(&self) -> Result<String, String> {
        let mut command = tool("/usr/bin/sw_vers");
        command.arg("-productVersion");
        let bytes = run_ok(
            command,
            Duration::from_secs(20),
            "Apassy cannot read the macOS version",
        )?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_owned())
    }

    fn running_team(&self) -> Result<Option<String>, String> {
        // The signature of the running process, not of a file that can change.
        let mut command = tool("/usr/bin/codesign");
        command
            .args(["-d", "--verbose=2"])
            .arg(std::process::id().to_string());
        let output = run(command, Duration::from_secs(20), 64 * 1024)?;
        if !output.ok {
            return Ok(None);
        }
        if identifier_from_codesign(&output.stderr) != Some(BUNDLE_ID) {
            return Ok(None);
        }
        Ok(developer_id_team_from_codesign(&output.stderr))
    }

    fn location(&self) -> Location {
        let bundle = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .ok()
            .and_then(|exe| bundle_of(&exe));
        match bundle {
            Some(bundle) => Location::Bundle {
                writable: can_replace(&bundle),
                bundle,
            },
            None => Location::NotBundle,
        }
    }

    fn attach(&self, image: &Path, mountpoint: &Path) -> Result<(), String> {
        let mut command = tool("/usr/bin/hdiutil");
        command
            .args([
                "attach",
                "-nobrowse",
                "-readonly",
                "-noautoopen",
                "-mountpoint",
            ])
            .arg(mountpoint)
            .arg(image);
        run_ok(
            command,
            Duration::from_secs(300),
            "macOS cannot open the disk image",
        )
        .map(drop)
    }

    fn detach(&self, mountpoint: &Path) -> Result<(), String> {
        let mut command = tool("/usr/bin/hdiutil");
        command.arg("detach").arg(mountpoint);
        if run_ok(command, Duration::from_secs(60), "detach").is_ok() {
            return Ok(());
        }
        let mut command = tool("/usr/bin/hdiutil");
        command.args(["detach", "-force"]).arg(mountpoint);
        run_ok(
            command,
            Duration::from_secs(60),
            "macOS cannot close the disk image",
        )
        .map(drop)
    }

    fn bundle_info(&self, app: &Path) -> Result<BundleInfo, String> {
        Ok(BundleInfo {
            identifier: plist_value(app, "CFBundleIdentifier")?,
            version: plist_value(app, "CFBundleShortVersionString")?,
            build_commit: plist_value(app, PLIST_BUILD_COMMIT).ok(),
        })
    }

    fn signing_team(&self, app: &Path) -> Result<Option<String>, String> {
        let mut command = tool("/usr/bin/codesign");
        command.args(["-d", "--verbose=2"]).arg(app);
        let output = run(command, Duration::from_secs(60), 64 * 1024)?;
        Ok(if output.ok {
            team_from_codesign(&output.stderr)
        } else {
            None
        })
    }

    fn verify_signature(&self, app: &Path, team: &str) -> Result<(), String> {
        if !is_team_id(team) {
            return Err("The team ID is not valid.".to_owned());
        }
        let mut command = tool("/usr/bin/codesign");
        command
            .args(["--verify", "--deep", "--strict", "-R"])
            .arg(format!("={}", requirement(team)))
            .arg(app);
        run_ok(
            command,
            Duration::from_secs(300),
            "The signature of the new version is not valid",
        )
        .map(drop)
    }

    fn assess(&self, app: &Path) -> Result<(), String> {
        let mut command = tool("/usr/sbin/spctl");
        command.args(["--assess", "--type", "exec"]).arg(app);
        run_ok(
            command,
            Duration::from_secs(120),
            "Gatekeeper does not accept the new version",
        )
        .map(drop)
    }

    fn copy_app(&self, from: &Path, to: &Path) -> Result<(), String> {
        let mut command = tool("/usr/bin/ditto");
        command.arg(from).arg(to);
        run_ok(
            command,
            Duration::from_secs(600),
            "Apassy cannot copy the new version",
        )
        .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_requirement_names_the_app_developer_id_and_team() {
        let text = requirement("ABCDE12345");
        assert!(text.starts_with(r#"identifier "com.wydrox.apassy" and anchor apple generic"#));
        assert!(text.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
        assert!(text.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
        assert!(text.ends_with(r#"certificate leaf[subject.OU] = "ABCDE12345""#));
        assert!(
            !requirement_prefix!().contains('\''),
            "the installer puts the prefix in single quotes"
        );
    }

    #[test]
    fn team_ids() {
        assert!(is_team_id("ABCDE12345"));
        for bad in [
            "",
            "abcde12345",
            "ABCDE1234",
            "ABCDE123456",
            "ABCDE 1234",
            "ABCDE\"1234",
        ] {
            assert!(!is_team_id(bad), "{bad:?}");
        }
        let output = "Executable=/Applications/Apassy.app/Contents/MacOS/apassy\nIdentifier=com.wydrox.apassy\nTeamIdentifier=7S3F9767BM\n";
        assert_eq!(team_from_codesign(output).as_deref(), Some("7S3F9767BM"));
        assert_eq!(identifier_from_codesign(output), Some(BUNDLE_ID));
        assert_eq!(
            team_from_codesign("Identifier=x\nTeamIdentifier=not set\n"),
            None
        );
        assert_eq!(team_from_codesign("Identifier=x\n"), None);
    }

    /// Only a Developer ID signature gives the team for updates. A build from
    /// source (Apple Development) and an ad hoc build do not.
    #[test]
    fn only_a_developer_id_signature_gives_the_update_team() {
        let signed = |authority: &str, team: &str| {
            format!(
                "Executable=/Applications/Apassy.app/Contents/MacOS/apassy\nIdentifier=com.wydrox.apassy\n{authority}Authority=Apple Root CA\nTeamIdentifier={team}\n"
            )
        };
        let developer_id = signed(
            "Authority=Developer ID Application: Example Inc. (ABCDE12345)\nAuthority=Developer ID Certification Authority\n",
            "ABCDE12345",
        );
        assert_eq!(
            developer_id_team_from_codesign(&developer_id).as_deref(),
            Some("ABCDE12345")
        );
        let from_source = signed(
            "Authority=Apple Development: Jane Doe (XYZ9876543)\nAuthority=Apple Worldwide Developer Relations Certification Authority\n",
            "ABCDE12345",
        );
        assert_eq!(
            team_from_codesign(&from_source).as_deref(),
            Some("ABCDE12345")
        );
        assert_eq!(developer_id_team_from_codesign(&from_source), None);
        let ad_hoc = "Identifier=com.wydrox.apassy\nSignature=adhoc\nTeamIdentifier=not set\n";
        assert_eq!(developer_id_team_from_codesign(ad_hoc), None);
        // The leaf is the first Authority line; a later one does not count.
        let wrong_leaf = signed(
            "Authority=Apple Development: Jane Doe (XYZ9876543)\nAuthority=Developer ID Application: Example Inc. (ABCDE12345)\n",
            "ABCDE12345",
        );
        assert_eq!(developer_id_team_from_codesign(&wrong_leaf), None);
    }

    #[test]
    fn a_program_in_contents_macos_of_an_app_is_in_a_bundle() {
        assert_eq!(
            bundle_of(Path::new("/Applications/Apassy.app/Contents/MacOS/apassy")),
            Some(PathBuf::from("/Applications/Apassy.app"))
        );
        for exe in [
            "/Users/me/apassy/target/debug/apassy",
            "/Applications/Apassy/Contents/MacOS/apassy",
            "/Applications/Apassy.app/Contents/Helpers/apassy",
            "/apassy",
        ] {
            assert_eq!(bundle_of(Path::new(exe)), None, "{exe}");
        }
    }

    #[test]
    fn a_bundle_in_a_folder_of_the_user_can_be_replaced() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let bundle = dir.path().join("Apassy.app");
        std::fs::create_dir_all(bundle.join("Contents")).expect("bundle");
        assert!(can_replace(&bundle));
        assert!(!can_replace(&dir.path().join("missing").join("Apassy.app")));
        // No temporary file stays.
        let names: Vec<_> = std::fs::read_dir(dir.path()).expect("list").collect();
        assert_eq!(names.len(), 1);
    }

    /// The real tools with a throwaway disk image, on macOS only and by hand:
    ///
    /// ```text
    /// APASSY_UPDATE_PROBE_APP=/Applications/<a notarized Developer ID app>.app \
    ///   cargo test --features desktop,vault --lib real_tools -- --ignored
    /// ```
    ///
    /// The probe copies the app as `Apassy.app` into an image. Its signature and
    /// Gatekeeper pass; the Apassy requirement refuses it (another identifier and
    /// team).
    #[test]
    #[ignore = "manual: needs macOS and APASSY_UPDATE_PROBE_APP"]
    fn real_tools_check_a_disk_image() {
        let source = PathBuf::from(std::env::var("APASSY_UPDATE_PROBE_APP").expect("probe app"));
        let sys = Commands;
        let temp = tempfile::TempDir::new().expect("temp dir");
        let stage = temp.path().join("stage");
        std::fs::create_dir_all(&stage).expect("stage");
        sys.copy_app(&source, &stage.join("Apassy.app"))
            .expect("ditto");
        let image = temp.path().join("probe.dmg");
        let mut create = tool("/usr/bin/hdiutil");
        create
            .args([
                "create",
                "-volname",
                "ApassyProbe",
                "-fs",
                "HFS+",
                "-format",
                "UDZO",
                "-srcfolder",
            ])
            .arg(&stage)
            .arg(&image);
        run_ok(create, Duration::from_secs(300), "hdiutil create").expect("image");

        let macos = sys.macos_version().expect("sw_vers");
        assert!(
            super::super::version::parse_macos(&macos).is_some(),
            "{macos}"
        );
        assert_eq!(
            sys.running_team().expect("codesign"),
            None,
            "a test binary is not Apassy"
        );

        let mount = temp.path().join("mount");
        std::fs::create_dir(&mount).expect("mount");
        sys.attach(&image, &mount).expect("attach");
        let app = mount.join("Apassy.app");
        let info = sys.bundle_info(&app).expect("plist");
        assert_ne!(info.identifier, BUNDLE_ID);
        assert!(!info.version.is_empty());
        assert_eq!(
            info.build_commit, None,
            "another app has no Apassy build identity"
        );
        let team = sys.signing_team(&app).expect("codesign").expect("team");
        assert!(is_team_id(&team));
        let refused = sys
            .verify_signature(&app, &team)
            .expect_err("another identifier");
        assert!(refused.contains("signature"), "{refused}");
        sys.assess(&app)
            .expect("Gatekeeper accepts a notarized app");
        let copy = temp.path().join("Copy.app");
        sys.copy_app(&app, &copy).expect("ditto");
        let mut verify = tool("/usr/bin/codesign");
        verify.args(["--verify", "--deep", "--strict"]).arg(&copy);
        run_ok(verify, Duration::from_secs(120), "codesign").expect("the copy keeps its signature");
        sys.detach(&mount).expect("detach");
        assert!(!app.exists(), "detached");
        eprintln!(
            "probe: macOS {macos}, {} {} team {team}",
            info.identifier, info.version
        );
    }

    #[test]
    fn curl_refuses_plain_http() {
        assert!(curl("http://apassy.wyderka.cc/latest.json").is_err());
        assert!(curl("file:///etc/passwd").is_err());
        assert!(curl("https://apassy.wyderka.cc/latest.json").is_ok());
    }

    #[test]
    fn a_command_that_writes_too_much_or_runs_too_long_fails() {
        let mut command = tool("/bin/sh");
        command.args(["-c", "yes | head -c 5000"]);
        assert!(run(command, Duration::from_secs(20), 100).is_err());
        let mut command = tool("/bin/sh");
        command.args(["-c", "printf abc"]);
        let output = run(command, Duration::from_secs(20), 100).expect("run");
        assert!(output.ok);
        assert_eq!(output.stdout, b"abc");
        let mut command = tool("/bin/sh");
        command.args(["-c", "sleep 5"]);
        let started = Instant::now();
        assert!(run(command, Duration::from_millis(300), 100).is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}
