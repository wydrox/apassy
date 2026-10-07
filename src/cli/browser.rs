//! `apassy setup browser`: connect the browser extension to Apassy (ADR 0021).
//!
//! The command writes the native messaging host manifest `com.wydrox.apassy.json` into
//! the `NativeMessagingHosts` folder of each Chromium browser that it finds
//! ([`crate::browser::install`]). Settings > General > Browser extension in the app does the same.
//! It needs no session: it gives no access to the vault.

use std::path::Path;

use super::args::{Args, usage};
use super::{Failure, Outcome};
use crate::browser::install::{self, BROWSERS, Browser, Install, State};

pub const HELP: &str = "\
apassy setup browser [--browser NAME] [--remove]

Connect the Apassy browser extension. Settings > General > Browser extension in the app does the
same with one click for each browser.
  1. Write the native messaging host manifest com.wydrox.apassy.json for each browser
     that is on this Mac: helium, chrome, chromium, brave, edge, arc, vivaldi.
     --browser NAME selects one, also when its folder does not exist yet.
     The manifest names apassy-browser-host of this Apassy.app, and it allows only the
     Apassy extension.
  2. Print the folder of the extension. Load it once in each browser:
     open chrome://extensions, turn on Developer mode, and drag the folder onto the page.

--remove deletes the manifests.

Each fill asks for Touch ID or the passphrase in Apassy. The extension gets no
password without it.
";

/// What happened in one browser.
#[derive(Debug, PartialEq, Eq)]
enum Change {
    Wrote(std::path::PathBuf),
    Removed(std::path::PathBuf),
    /// The browser folder is not there, so the browser is not on this Mac.
    Missing,
    /// `--remove` found no manifest.
    Absent,
}

/// Write or remove the manifest in each selected browser under `home`.
fn apply(
    home: &Path,
    host: &Path,
    only: Option<&Browser>,
    remove: bool,
) -> Result<Vec<(&'static str, Change)>, Failure> {
    let mut changes = Vec::new();
    for browser in BROWSERS
        .iter()
        .filter(|browser| only.is_none_or(|selected| selected.id == browser.id))
    {
        if remove {
            let file = install::manifest_path(home, browser);
            let change = if install::disconnect(home, browser)? {
                Change::Removed(file)
            } else {
                Change::Absent
            };
            changes.push((browser.name, change));
            continue;
        }
        if only.is_none() && install::state(home, browser, host) == State::Missing {
            changes.push((browser.name, Change::Missing));
            continue;
        }
        let file = install::connect(home, browser, host)?;
        changes.push((browser.name, Change::Wrote(file)));
    }
    Ok(changes)
}

pub fn run(mut args: Args) -> Outcome {
    let only = args.value(&["--browser"])?;
    let remove = args.flag(&["--remove"]);
    args.finish()?;
    let only = match only.as_deref() {
        None => None,
        Some(id) => Some(install::find(id).ok_or_else(|| {
            Failure::Usage(usage(format!(
                "Unknown browser \"{id}\". Use one of: {}.",
                BROWSERS
                    .iter()
                    .map(|browser| browser.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        })?),
    };
    let home = install::home().ok_or_else(|| Failure::Other("HOME is not set.".to_owned()))?;
    // The agent profile denies a change in the app bundle, not in a source tree.
    let Some(app) = Install::current() else {
        return Err(Failure::Other(
            "Use the apassy program inside Apassy.app: /Applications/Apassy.app/Contents/MacOS/apassy setup browser. A source build is not protected from agents: an agent could change target/debug/apassy-browser-host or extension/, and the browser runs them outside the sandbox."
                .to_owned(),
        ));
    };
    if !app.host().is_file() {
        return Err(Failure::Other(
            "apassy-browser-host is not in this Apassy.app. Install the current Apassy.app."
                .to_owned(),
        ));
    }
    let changes = apply(&home, &app.host(), only, remove)?;
    let mut wrote = false;
    for (name, change) in &changes {
        match change {
            Change::Wrote(file) => {
                wrote = true;
                println!("{name}: wrote {}", file.display());
            }
            Change::Removed(file) => println!("{name}: removed {}", file.display()),
            Change::Missing => println!("{name}: not on this Mac"),
            Change::Absent => println!("{name}: no manifest"),
        }
    }
    if remove {
        println!("Remove the Apassy extension in each browser too: chrome://extensions.");
        return Ok(());
    }
    if !wrote {
        return Err(Failure::Other(
            "No browser was found. Use --browser NAME to select one.".to_owned(),
        ));
    }
    let extension = app.extension_dir();
    if extension.join("manifest.json").is_file() {
        println!("The extension folder: {}", extension.display());
    } else {
        println!(
            "The extension folder is missing in this Apassy.app. Install the current Apassy.app."
        );
    }
    if !app.is_installed_app() {
        println!(
            "This Apassy.app is not /Applications/Apassy.app. The agent profile protects it only when agents start with the apassy-sandbox of this app, or with --app-build."
        );
    }
    println!(
        "Load it once in each browser: open chrome://extensions, turn on Developer mode, and drag the folder onto the page."
    );
    println!("Each fill asks for Touch ID or the passphrase in Apassy.");
    Ok(())
}

#[cfg(all(test, feature = "vault"))]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn setup_writes_only_for_browsers_on_this_mac_and_removes() {
        let home = tempfile::tempdir().unwrap();
        let support = home.path().join("Library/Application Support");
        fs::create_dir_all(support.join("net.imput.helium")).unwrap();
        fs::create_dir_all(support.join("Arc/User Data")).unwrap();
        let host = Path::new("/x/apassy-browser-host");

        let changes = apply(home.path(), host, None, false).unwrap();
        let helium = support.join("net.imput.helium/NativeMessagingHosts/com.wydrox.apassy.json");
        let arc = support.join("Arc/User Data/NativeMessagingHosts/com.wydrox.apassy.json");
        assert!(changes.contains(&("Helium", Change::Wrote(helium.clone()))));
        assert!(changes.contains(&("Arc", Change::Wrote(arc.clone()))));
        assert!(changes.contains(&("Google Chrome", Change::Missing)));
        assert!(
            !support.join("Google").exists(),
            "no folder for a missing browser"
        );
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&helium).unwrap()).unwrap();
        assert_eq!(value["path"], "/x/apassy-browser-host");

        // A selected browser gets its folder.
        let changes = apply(home.path(), host, install::find("chrome"), false).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(
            support
                .join("Google/Chrome/NativeMessagingHosts/com.wydrox.apassy.json")
                .is_file()
        );

        let changes = apply(home.path(), host, None, true).unwrap();
        assert!(changes.contains(&("Helium", Change::Removed(helium.clone()))));
        assert!(changes.contains(&("Brave", Change::Absent)));
        assert!(!helium.exists() && !arc.exists());
    }
}
