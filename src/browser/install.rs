//! Connect a browser to Apassy (ADR 0021, contract section 7).
//!
//! The extension comes from the Chrome Web Store ([`STORE_URL`]), or from the folder in
//! Apassy.app with Developer mode. A browser finds the native messaging host through the
//! manifest
//! `com.wydrox.apassy.json` in its `NativeMessagingHosts` folder. Settings > Tools >
//! Browser extension in the app and `apassy setup browser` write it. The manifest names
//! `apassy-browser-host` of the running Apassy.app and allows only the Apassy extension.
//!
//! On Linux the root-owned installed host is required. On macOS only an app bundle
//! can connect a browser: the agent profile protects the bundle, not a
//! source tree. From a source build the manifest would name `target/debug`, which an
//! agent can rebuild, and the browser would run it outside the sandbox.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;

use super::wire::{EXTENSION_ORIGIN, HOST_NAME};

/// A Chromium browser: its folder under `~/Library/Application Support` and its bundle
/// ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Browser {
    /// The name for `apassy setup browser --browser`.
    pub id: &'static str,
    pub name: &'static str,
    pub dir: &'static str,
    pub bundle_id: &'static str,
}

#[cfg(not(target_os = "linux"))]
pub const BROWSERS: &[Browser] = &[
    Browser {
        id: "helium",
        name: "Helium",
        dir: "net.imput.helium",
        bundle_id: "net.imput.helium",
    },
    Browser {
        id: "chrome",
        name: "Google Chrome",
        dir: "Google/Chrome",
        bundle_id: "com.google.Chrome",
    },
    Browser {
        id: "chromium",
        name: "Chromium",
        dir: "Chromium",
        bundle_id: "org.chromium.Chromium",
    },
    Browser {
        id: "brave",
        name: "Brave",
        dir: "BraveSoftware/Brave-Browser",
        bundle_id: "com.brave.Browser",
    },
    Browser {
        id: "edge",
        name: "Microsoft Edge",
        dir: "Microsoft Edge",
        bundle_id: "com.microsoft.edgemac",
    },
    Browser {
        id: "arc",
        name: "Arc",
        dir: "Arc/User Data",
        bundle_id: "company.thebrowser.Browser",
    },
    Browser {
        id: "vivaldi",
        name: "Vivaldi",
        dir: "Vivaldi",
        bundle_id: "com.vivaldi.Vivaldi",
    },
];

/// Linux desktop support starts with packaged Google Chrome stable and Chromium.
#[cfg(target_os = "linux")]
pub const BROWSERS: &[Browser] = &[
    Browser {
        id: "chrome",
        name: "Google Chrome",
        dir: "google-chrome",
        bundle_id: "com.google.Chrome",
    },
    Browser {
        id: "chromium",
        name: "Chromium",
        dir: "chromium",
        bundle_id: "org.chromium.Chromium",
    },
];

/// The browser with the ID `id`.
pub fn find(id: &str) -> Option<&'static Browser> {
    BROWSERS.iter().find(|browser| browser.id == id)
}

/// The name of the manifest file.
pub fn manifest_name() -> String {
    format!("{HOST_NAME}.json")
}

/// The manifest for the host at `host`.
pub fn manifest(host: &Path) -> String {
    let value = serde_json::json!({
        "name": HOST_NAME,
        "description": "Apassy: fill logins from your Apassy vault",
        "path": host.display().to_string(),
        "type": "stdio",
        "allowed_origins": [EXTENSION_ORIGIN],
    });
    let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
    text.push('\n');
    text
}

/// The home folder of the owner.
pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// The folder of the running program.
pub fn program_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| fs::canonicalize(exe).ok())
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

/// The `Contents` folder of the app bundle that holds the programs in `program_dir`.
/// `None` for a source build.
pub fn bundle_contents(program_dir: &Path) -> Option<PathBuf> {
    let contents = program_dir
        .ends_with("Contents/MacOS")
        .then(|| program_dir.parent())??;
    let bundle = contents.parent()?;
    (bundle.extension().is_some_and(|ext| ext == "app")).then(|| contents.to_path_buf())
}

/// The installed Apassy package that connects the browsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    contents: PathBuf,
}

impl Install {
    /// The app bundle of the running program. `None` for a source build.
    pub fn current() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let executable = fs::canonicalize(std::env::current_exe().ok()?).ok()?;
            if ![
                Path::new("/usr/bin/apassy"),
                Path::new(super::caller::linux::HOST),
            ]
            .contains(&executable.as_path())
            {
                return None;
            }
            super::caller::linux::trusted_binary(&executable).ok()?;
        }
        Self::at(&program_dir()?)
    }

    /// The app bundle of the programs in `program_dir`.
    pub fn at(program_dir: &Path) -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let host = Path::new(super::caller::linux::HOST);
            (linux_program_dir(program_dir) && super::caller::linux::trusted_binary(host).is_ok())
                .then(|| Self {
                    contents: PathBuf::from("/usr/lib/apassy"),
                })
        }
        #[cfg(not(target_os = "linux"))]
        {
            bundle_contents(program_dir).map(|contents| Self { contents })
        }
    }

    /// The native messaging host of this app.
    pub fn host(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            self.contents.join("apassy-browser-host")
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.contents.join("MacOS").join("apassy-browser-host")
        }
    }

    /// The folder of the extension, for "Load unpacked".
    pub fn extension_dir(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/usr/share/apassy/browser-extension")
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.contents.join("Resources").join("browser-extension")
        }
    }

    /// True when this app is `/Applications/Apassy.app`, which the agent profile always
    /// protects.
    pub fn is_installed_app(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.contents == Path::new("/usr/lib/apassy")
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.contents == Path::new("/Applications/Apassy.app/Contents")
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_program_dir(dir: &Path) -> bool {
    matches!(dir.to_str(), Some("/usr/bin" | "/usr/lib/apassy"))
}

/// How one browser is connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// The folder of the browser is not there, so the browser is not on this Mac.
    Missing,
    NotConnected,
    /// The manifest names the host of this app.
    Connected,
    /// The manifest names another program, for example another copy of Apassy.app.
    Other(String),
    /// Linux: the browser is on this computer, but it cannot reach the native host or
    /// the browser check refuses it, so a manifest would not make it work.
    Unsupported(Unsupported),
}

/// Why a browser cannot use Apassy (Linux).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// A snap. Its confinement hides `/usr/lib/apassy` and `/usr/share/apassy`, it
    /// reads its manifests from `~/snap`, and it runs from a `/snap` path.
    Snap,
    /// A Flatpak. Its sandbox cannot start a program of the host system.
    Flatpak,
    /// A profile folder without the packaged executable that the browser check knows:
    /// another build, or a browser that was removed.
    UnknownBuild,
}

/// What to use instead of a browser that is not supported.
pub const UNSUPPORTED_ALTERNATIVE: &str = "Use Google Chrome, or Chromium from a .deb.";

impl Unsupported {
    /// One sentence: why `browser` does not work with Apassy.
    pub fn reason(self, browser: &Browser) -> String {
        match self {
            Self::Snap => format!(
                "The {} snap cannot start Apassy's browser host: its confinement hides /usr/lib/apassy.",
                browser.name
            ),
            Self::Flatpak => format!(
                "The Flatpak of {} cannot start Apassy's browser host: its sandbox hides the programs of this computer.",
                browser.name
            ),
            Self::UnknownBuild => format!(
                "Apassy finds no packaged {} that its browser check can verify.",
                browser.name
            ),
        }
    }

    /// The reason and the alternative, for a row or a line of `apassy setup browser`.
    pub fn explain(self, browser: &Browser) -> String {
        format!("{} {UNSUPPORTED_ALTERNATIVE}", self.reason(browser))
    }

    /// The JSON name of the reason.
    pub fn code(self) -> &'static str {
        match self {
            Self::Snap => "snap",
            Self::Flatpak => "flatpak",
            Self::UnknownBuild => "unknown_build",
        }
    }
}

/// Linux: the packaged executables of `browser` that the browser check accepts, its
/// snap name and its Flatpak application ID.
#[cfg(target_os = "linux")]
fn linux_package(
    browser: &Browser,
) -> (&'static [&'static str], Option<&'static str>, &'static str) {
    match browser.id {
        "chrome" => (
            &super::caller::linux::BROWSERS[..1],
            None,
            "com.google.Chrome",
        ),
        _ => (
            &super::caller::linux::BROWSERS[1..],
            Some("chromium"),
            "org.chromium.Chromium",
        ),
    }
}

/// Linux: is `browser` installed as a package that Apassy supports, as a snap or
/// Flatpak, or not at all? System paths are under `root` (`/`; a folder in tests).
/// `None` when the packaged executable is there: then the manifest decides.
#[cfg(target_os = "linux")]
fn linux_presence(root: &Path, home: &Path, browser: &Browser) -> Option<State> {
    let (executables, snap, flatpak) = linux_package(browser);
    let system = |path: &str| root.join(path.trim_start_matches('/'));
    if executables.iter().any(|path| system(path).is_file()) {
        return None;
    }
    if let Some(name) = snap
        && [
            system("/snap").join(name),
            system("/var/lib/snapd/snap").join(name),
            home.join("snap").join(name),
        ]
        .iter()
        .any(|path| path.exists())
    {
        return Some(State::Unsupported(Unsupported::Snap));
    }
    if [
        system("/var/lib/flatpak/app").join(flatpak),
        home.join(".local/share/flatpak/app").join(flatpak),
        home.join(".var/app").join(flatpak),
    ]
    .iter()
    .any(|path| path.exists())
    {
        return Some(State::Unsupported(Unsupported::Flatpak));
    }
    Some(if support(home).join(browser.dir).is_dir() {
        State::Unsupported(Unsupported::UnknownBuild)
    } else {
        State::Missing
    })
}

fn support(home: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if self::home().as_deref() == Some(home)
            && let Some(config) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from)
            && config.is_absolute()
        {
            return config;
        }
        home.join(".config")
    }
    #[cfg(not(target_os = "linux"))]
    {
        home.join("Library").join("Application Support")
    }
}

/// The manifest file of `browser` under `home`.
pub fn manifest_path(home: &Path, browser: &Browser) -> PathBuf {
    support(home)
        .join(browser.dir)
        .join("NativeMessagingHosts")
        .join(manifest_name())
}

/// How `browser` is connected to the host at `host`. On Linux a snap, a Flatpak or an
/// unknown build is [`State::Unsupported`] whatever its manifest says.
pub fn state(home: &Path, browser: &Browser, host: &Path) -> State {
    #[cfg(target_os = "linux")]
    if let Some(state) = linux_presence(Path::new("/"), home, browser) {
        return state;
    }
    manifest_state(home, browser, host)
}

/// [`state`] with the system paths of Linux under `root`.
#[cfg(all(test, feature = "vault", target_os = "linux"))]
fn state_at(root: &Path, home: &Path, browser: &Browser, host: &Path) -> State {
    linux_presence(root, home, browser).unwrap_or_else(|| manifest_state(home, browser, host))
}

/// The state that the manifest file of `browser` gives.
fn manifest_state(home: &Path, browser: &Browser, host: &Path) -> State {
    let file = manifest_path(home, browser);
    match fs::read_to_string(&file) {
        Ok(text) => {
            let named = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|value| value["path"].as_str().map(str::to_owned))
                .unwrap_or_default();
            if Path::new(&named) == host {
                State::Connected
            } else {
                State::Other(named)
            }
        }
        Err(_) if !support(home).join(browser.dir).is_dir() => State::Missing,
        Err(_) => State::NotConnected,
    }
}

/// Write the manifest of `browser` for the host at `host`. The write is atomic.
pub fn connect(home: &Path, browser: &Browser, host: &Path) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    if host != Path::new(super::caller::linux::HOST) {
        return Err(io::Error::other(
            "Linux browser integration requires the installed Apassy host",
        ));
    }
    #[cfg(target_os = "linux")]
    super::caller::linux::trusted_binary(host)?;
    #[cfg(target_os = "linux")]
    if let Some(State::Unsupported(kind)) = linux_presence(Path::new("/"), home, browser) {
        return Err(io::Error::other(kind.explain(browser)));
    }
    write_manifest(home, browser, host)
}

fn write_manifest(home: &Path, browser: &Browser, host: &Path) -> io::Result<PathBuf> {
    let file = manifest_path(home, browser);
    let folder = file
        .parent()
        .ok_or_else(|| io::Error::other("the manifest has no folder"))?;
    fs::create_dir_all(folder)?;
    let temp = folder.join(format!("{}.tmp", manifest_name()));
    let _ = fs::remove_file(&temp);
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    out.write_all(manifest(host).as_bytes())?;
    out.sync_all()?;
    fs::rename(&temp, &file)?;
    Ok(file)
}

/// Delete the manifest of `browser`. False when there was none.
pub fn disconnect(home: &Path, browser: &Browser) -> io::Result<bool> {
    match fs::remove_file(manifest_path(home, browser)) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// The page of the extension in the Chrome Web Store (ADR 0021, D5). Its item ID is
/// [`super::wire::EXTENSION_ID`].
pub const STORE_URL: &str =
    "https://chromewebstore.google.com/detail/apassy/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";

/// Open the page of the extension in the Chrome Web Store in `browser`, for "Add to
/// Chrome". The browser starts when it does not run.
pub fn open_store_page(browser: &Browser) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let executable = match browser.id {
            "chrome" => "/usr/bin/google-chrome-stable",
            "chromium" => "/usr/bin/chromium",
            _ => return Err(io::Error::other("Unsupported Linux browser")),
        };
        let mut child = Command::new(executable)
            .arg(STORE_URL)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        // A first browser launch can live for hours. Reap it off the UI thread.
        std::thread::Builder::new()
            .name("apassy-browser-launch".into())
            .spawn(move || {
                let _ = child.wait();
            })?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        run_open(&["-b", browser.bundle_id, STORE_URL])
    }
}

#[cfg(not(target_os = "linux"))]
fn run_open(args: &[&str]) -> io::Result<()> {
    let status = Command::new("/usr/bin/open").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("open ended with {status}")))
    }
}

#[cfg(all(test, feature = "vault"))]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn only_an_app_bundle_can_connect() {
        let installed = Install::at(Path::new("/Applications/Apassy.app/Contents/MacOS")).unwrap();
        assert!(installed.is_installed_app());
        assert_eq!(
            installed.host(),
            Path::new("/Applications/Apassy.app/Contents/MacOS/apassy-browser-host")
        );
        assert_eq!(
            installed.extension_dir(),
            Path::new("/Applications/Apassy.app/Contents/Resources/browser-extension")
        );
        let build = Install::at(Path::new(
            "/Users/me/src/apassy/target/Apassy.app/Contents/MacOS",
        ))
        .unwrap();
        assert!(!build.is_installed_app());
        assert_eq!(
            Install::at(Path::new("/Users/me/src/apassy/target/debug")),
            None
        );
        assert_eq!(
            Install::at(Path::new("/Users/me/Contents/MacOS")),
            None,
            "a Contents/MacOS folder outside a bundle"
        );
    }

    #[test]
    fn the_manifest_allows_only_the_extension() {
        let text = manifest(Path::new(
            "/Applications/Apassy.app/Contents/MacOS/apassy-browser-host",
        ));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["name"], "com.wydrox.apassy");
        assert_eq!(value["type"], "stdio");
        assert_eq!(
            value["path"],
            "/Applications/Apassy.app/Contents/MacOS/apassy-browser-host"
        );
        assert_eq!(
            value["allowed_origins"],
            serde_json::json!(["chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/"])
        );
        // The store page is the page of the extension ID.
        assert!(STORE_URL.starts_with("https://chromewebstore.google.com/detail/"));
        assert!(STORE_URL.ends_with(super::super::wire::EXTENSION_ID));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn connect_and_disconnect_follow_the_state() {
        let home = tempfile::tempdir().unwrap();
        let helium = find("helium").unwrap();
        let chrome = find("chrome").unwrap();
        let host = Path::new("/Applications/Apassy.app/Contents/MacOS/apassy-browser-host");
        assert_eq!(state(home.path(), helium, host), State::Missing);
        fs::create_dir_all(support(home.path()).join("net.imput.helium")).unwrap();
        assert_eq!(state(home.path(), helium, host), State::NotConnected);

        let file = connect(home.path(), helium, host).unwrap();
        assert_eq!(file, manifest_path(home.path(), helium));
        assert_eq!(state(home.path(), helium, host), State::Connected);
        assert_eq!(
            state(home.path(), helium, Path::new("/other/apassy-browser-host")),
            State::Other(host.display().to_string())
        );
        assert_eq!(state(home.path(), chrome, host), State::Missing);

        assert!(disconnect(home.path(), helium).unwrap());
        assert!(!disconnect(home.path(), helium).unwrap());
        assert_eq!(state(home.path(), helium, host), State::NotConnected);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_registration_uses_only_packaged_hosts_and_supported_profiles() {
        let home = tempfile::tempdir().unwrap();
        let chrome = find("chrome").unwrap();
        let chromium = find("chromium").unwrap();
        assert!(find("helium").is_none());
        let host = Path::new(super::super::caller::linux::HOST);
        assert_eq!(
            manifest_path(home.path(), chrome),
            home.path()
                .join(".config/google-chrome/NativeMessagingHosts/com.wydrox.apassy.json")
        );
        assert_eq!(
            manifest_path(home.path(), chromium),
            home.path()
                .join(".config/chromium/NativeMessagingHosts/com.wydrox.apassy.json")
        );
        // The state does not depend on the browsers of the test machine: the system
        // paths are under a private root with a packaged Chrome.
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("opt/google/chrome")).unwrap();
        fs::write(root.path().join("opt/google/chrome/chrome"), b"").unwrap();
        let at = |browser| state_at(root.path(), home.path(), browser, host);
        assert_eq!(at(chrome), State::Missing);
        fs::create_dir_all(support(home.path()).join(chrome.dir)).unwrap();
        assert_eq!(at(chrome), State::NotConnected);
        // Exercise file registration separately from installed-image validation;
        // this test does not install or pretend to own a root-owned executable.
        write_manifest(home.path(), chrome, host).unwrap();
        assert_eq!(at(chrome), State::Connected);
        assert!(connect(home.path(), chrome, Path::new("/tmp/apassy-browser-host")).is_err());
        assert!(disconnect(home.path(), chrome).unwrap());
        assert!(!disconnect(home.path(), chrome).unwrap());
        assert_eq!(Install::at(Path::new("/tmp/apassy")), None);
        assert!(
            linux_program_dir(Path::new("/usr/bin")),
            "the desktop package installs /usr/bin/apassy"
        );
        assert!(linux_program_dir(Path::new("/usr/lib/apassy")));
        assert!(!linux_program_dir(Path::new("/usr/local/bin")));
    }

    /// Ubuntu's Chromium is a snap and a Flatpak browser runs in its sandbox: neither
    /// can start the host, so neither is shown as connected or offered Connect, also
    /// with a manifest in `~/.config` (found in the Linux acceptance, 2026-11-10).
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_snaps_flatpaks_and_unknown_builds_are_not_supported() {
        let host = Path::new(super::super::caller::linux::HOST);
        let chrome = find("chrome").unwrap();
        let chromium = find("chromium").unwrap();
        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let at = |browser| state_at(root.path(), home.path(), browser, host);
        assert_eq!(at(chromium), State::Missing);
        assert_eq!(at(chrome), State::Missing);
        // Ubuntu 24.04: /snap/chromium, with the manifest that setup wrote in ~/.config.
        fs::create_dir_all(root.path().join("snap/chromium/3590")).unwrap();
        write_manifest(home.path(), chromium, host).unwrap();
        assert_eq!(at(chromium), State::Unsupported(Unsupported::Snap));
        // A Chromium .deb next to it is the browser that connects.
        fs::create_dir_all(root.path().join("usr/lib/chromium")).unwrap();
        fs::write(root.path().join("usr/lib/chromium/chromium"), b"").unwrap();
        assert_eq!(at(chromium), State::Connected);
        fs::remove_file(root.path().join("usr/lib/chromium/chromium")).unwrap();
        fs::remove_dir_all(root.path().join("snap")).unwrap();
        // The snap's own data folder alone also tells.
        fs::create_dir_all(home.path().join("snap/chromium/common")).unwrap();
        assert_eq!(at(chromium), State::Unsupported(Unsupported::Snap));
        fs::remove_dir_all(home.path().join("snap")).unwrap();
        // A profile without a packaged executable: another build, or a removed one.
        assert_eq!(at(chromium), State::Unsupported(Unsupported::UnknownBuild));
        // Flatpak, system-wide or per user, or only its data folder.
        for flatpak in [
            root.path().join("var/lib/flatpak/app/com.google.Chrome"),
            home.path()
                .join(".local/share/flatpak/app/com.google.Chrome"),
            home.path().join(".var/app/com.google.Chrome"),
        ] {
            fs::create_dir_all(&flatpak).unwrap();
            assert_eq!(at(chrome), State::Unsupported(Unsupported::Flatpak));
            fs::remove_dir_all(&flatpak).unwrap();
        }
        fs::create_dir_all(home.path().join(".var/app/org.chromium.Chromium")).unwrap();
        assert_eq!(at(chromium), State::Unsupported(Unsupported::Flatpak));
        // The text names the reason and the alternative.
        for kind in [
            Unsupported::Snap,
            Unsupported::Flatpak,
            Unsupported::UnknownBuild,
        ] {
            let text = kind.explain(chromium);
            assert!(text.contains("Chromium"), "{text}");
            assert!(
                text.ends_with("Use Google Chrome, or Chromium from a .deb."),
                "{text}"
            );
        }
        assert!(Unsupported::Snap.reason(chromium).contains("snap"));
        assert!(Unsupported::Flatpak.reason(chrome).contains("Flatpak"));
    }

    /// The executables that tell a supported package are the ones that the browser
    /// check accepts.
    #[cfg(target_os = "linux")]
    #[test]
    fn supported_packages_are_the_executables_of_the_browser_check() {
        let mut named: Vec<&str> = BROWSERS
            .iter()
            .flat_map(|browser| linux_package(browser).0.iter().copied())
            .collect();
        named.sort_unstable();
        let mut checked = super::super::caller::linux::BROWSERS.to_vec();
        checked.sort_unstable();
        assert_eq!(named, checked);
    }
}
