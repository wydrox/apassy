//! Connect a browser to Apassy (ADR 0021, contract section 7).
//!
//! A browser finds the native messaging host through the manifest
//! `com.wydrox.apassy.json` in its `NativeMessagingHosts` folder. Settings > General >
//! Browser extension in the app and `apassy setup browser` write it. The manifest names
//! `apassy-browser-host` of the running Apassy.app and allows only the Apassy extension.
//!
//! Only an app bundle can connect a browser: the agent profile protects the bundle, not a
//! source tree. From a source build the manifest would name `target/debug`, which an
//! agent can rebuild, and the browser would run it outside the sandbox.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// The Apassy.app that connects the browsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    contents: PathBuf,
}

impl Install {
    /// The app bundle of the running program. `None` for a source build.
    pub fn current() -> Option<Self> {
        Self::at(&program_dir()?)
    }

    /// The app bundle of the programs in `program_dir`.
    pub fn at(program_dir: &Path) -> Option<Self> {
        bundle_contents(program_dir).map(|contents| Self { contents })
    }

    /// The native messaging host of this app.
    pub fn host(&self) -> PathBuf {
        self.contents.join("MacOS").join("apassy-browser-host")
    }

    /// The folder of the extension, for "Load unpacked".
    pub fn extension_dir(&self) -> PathBuf {
        self.contents.join("Resources").join("browser-extension")
    }

    /// True when this app is `/Applications/Apassy.app`, which the agent profile always
    /// protects.
    pub fn is_installed_app(&self) -> bool {
        self.contents == Path::new("/Applications/Apassy.app/Contents")
    }
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
}

fn support(home: &Path) -> PathBuf {
    home.join("Library").join("Application Support")
}

/// The manifest file of `browser` under `home`.
pub fn manifest_path(home: &Path, browser: &Browser) -> PathBuf {
    support(home)
        .join(browser.dir)
        .join("NativeMessagingHosts")
        .join(manifest_name())
}

/// How `browser` is connected to the host at `host`.
pub fn state(home: &Path, browser: &Browser, host: &Path) -> State {
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

/// Open the extensions page in `browser`. The browser starts when it does not run.
pub fn open_extensions_page(browser: &Browser) -> io::Result<()> {
    run_open(&["-b", browser.bundle_id, "chrome://extensions"])
}

/// Show `path` in the Finder, selected.
pub fn reveal(path: &Path) -> io::Result<()> {
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::other("the path is not UTF-8"))?;
    run_open(&["-R", path])
}

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
            serde_json::json!(["chrome-extension://clopaaapnilhoeplaenolhdmjpompeeh/"])
        );
    }

    #[test]
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
}
