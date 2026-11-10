//! `apassy setup browser`: connect the browser extension to Apassy (ADR 0021).
//!
//! The command writes the native messaging host manifest `com.wydrox.apassy.json` into
//! the `NativeMessagingHosts` folder of each Chromium browser that it finds
//! ([`crate::browser::install`]). Settings > Tools > Browser extension in the app does the same.
//! It needs no session: it gives no access to the vault.

use std::path::Path;

use super::args::{Args, usage};
use super::{Failure, Outcome};
use crate::browser::install::{self, BROWSERS, Browser, Install, State};

#[cfg(not(target_os = "linux"))]
pub const HELP: &str = "\
apassy setup browser [--browser NAME] [--remove]

Connect the Apassy browser extension. Settings > Tools > Browser extension in the app does the
same with one click for each browser.
  1. Write the native messaging host manifest com.wydrox.apassy.json for each browser
     that is on this Mac: helium, chrome, chromium, brave, edge, arc, vivaldi.
     --browser NAME selects one, also when its folder does not exist yet.
     The manifest names apassy-browser-host of this Apassy.app, and it allows only the
     Apassy extension.
  2. Print the page of the extension in the Chrome Web Store. Open it in each browser
     and click Add to Chrome. The folder in Apassy.app also works with Developer mode.

--remove deletes the manifests.

Each fill asks for Touch ID or the passphrase in Apassy. The extension gets no
password without it.
";

#[cfg(target_os = "linux")]
pub const HELP: &str = "apassy setup browser [--browser chrome|chromium] [--remove]

Connect Chrome stable or Chromium to the installed Apassy browser host.
The root-owned host is /usr/lib/apassy/apassy-browser-host; the extension is in
/usr/share/apassy/browser-extension. --browser selects one browser even before its
profile exists. Load that extension folder from the browser extensions page.
Each fill and passkey request requires owner confirmation in the Apassy window.
The vault passphrase works without a keyring, screen lock or biometric reader.
--remove deletes native messaging manifests; remove the extension in the browser too.
";

/// What happened in one browser.
#[derive(Debug, PartialEq, Eq)]
enum Change {
    Wrote(std::path::PathBuf),
    Removed(std::path::PathBuf),
    /// The browser folder is not there, so the browser is no browser profile found.
    Missing,
    /// `--remove` found no manifest.
    Absent,
    /// Linux: a snap, a Flatpak or an unknown build. Nothing was written. The text
    /// gives the reason and the alternative; the code names the reason for JSON.
    Unsupported(String, &'static str),
}

/// Write or remove the manifest in each selected browser under `home`.
fn apply(
    home: &Path,
    host: &Path,
    only: Option<&Browser>,
    remove: bool,
) -> Result<Vec<(&'static str, Change)>, Failure> {
    apply_with(home, host, only, remove, |browser| {
        install::state(home, browser, host)
    })
}

/// [`apply`] with the state of each browser from `state`.
fn apply_with(
    home: &Path,
    host: &Path,
    only: Option<&Browser>,
    remove: bool,
    state: impl Fn(&Browser) -> State,
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
        match state(browser) {
            State::Missing if only.is_none() => {
                changes.push((browser.name, Change::Missing));
                continue;
            }
            State::Unsupported(kind) => {
                changes.push((
                    browser.name,
                    Change::Unsupported(kind.explain(browser), kind.code()),
                ));
                continue;
            }
            _ => {}
        }
        let file = install::connect(home, browser, host)?;
        changes.push((browser.name, Change::Wrote(file)));
    }
    Ok(changes)
}

fn changes_json(changes: &[(&str, Change)]) -> Vec<serde_json::Value> {
    changes
        .iter()
        .map(|(name, change)| {
            let (state, path) = match change {
                Change::Wrote(path) => ("written", Some(path)),
                Change::Removed(path) => ("removed", Some(path)),
                Change::Missing => ("browser_missing", None),
                Change::Absent => ("manifest_absent", None),
                Change::Unsupported(message, reason) => {
                    return serde_json::json!({"browser": name, "state": "unsupported", "reason": reason, "message": message});
                }
            };
            serde_json::json!({"browser": name, "state": state, "path": path})
        })
        .collect()
}

pub fn run(args: Args) -> Outcome {
    run_with_json(args, false)
}

pub fn run_with_json(mut args: Args, json: bool) -> Outcome {
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
            if cfg!(target_os = "linux") {
                "Install the Linux vault package with its root-owned host at /usr/lib/apassy/apassy-browser-host. Source builds are not accepted browser hosts."
            } else {
                "Use the apassy program inside Apassy.app: /Applications/Apassy.app/Contents/MacOS/apassy setup browser. Source builds are not protected browser hosts."
            }.to_owned(),
        ));
    };
    if !app.host().is_file() {
        return Err(Failure::Other(
            "apassy-browser-host is missing. Reinstall the Apassy package.".to_owned(),
        ));
    }
    let changes = if json {
        let mut completed = Vec::new();
        for browser in BROWSERS
            .iter()
            .filter(|browser| only.is_none_or(|selected| selected.id == browser.id))
        {
            if !remove
                && only.is_none()
                && install::state(&home, browser, &app.host()) == State::Missing
            {
                completed.push((browser.name, Change::Missing));
                continue;
            }
            match apply(&home, &app.host(), Some(browser), remove) {
                Ok(changes) => completed.extend(changes),
                Err(_) => {
                    super::print_json(
                        &serde_json::json!({"ok": false, "code": "browser_write", "stage": "manifests", "message": "A manifest could not be changed. Check browser directory permissions.", "partial_state": {"changes": changes_json(&completed)}, "data": {"failed_browser": browser.name}}),
                    );
                    return Err(Failure::Printed);
                }
            }
        }
        let ok = remove
            || completed
                .iter()
                .any(|(_, change)| matches!(change, Change::Wrote(_)));
        super::print_json(
            &serde_json::json!({"ok": ok, "code": if ok {"ok"} else {"no_browser"}, "stage": "browser", "partial_state": {"changes": changes_json(&completed)}, "data": {"extension_url": install::STORE_URL, "remove_extension_manually": remove}}),
        );
        return if ok { Ok(()) } else { Err(Failure::Printed) };
    } else {
        apply(&home, &app.host(), only, remove)?
    };
    let mut wrote = false;
    let mut unsupported = false;
    for (name, change) in &changes {
        match change {
            Change::Wrote(file) => {
                wrote = true;
                println!("{name}: wrote {}", file.display());
            }
            Change::Removed(file) => println!("{name}: removed {}", file.display()),
            Change::Missing => println!("{name}: no browser profile found"),
            Change::Absent => println!("{name}: no manifest"),
            Change::Unsupported(message, _) => {
                unsupported = true;
                println!("{name}: not supported. {message}");
            }
        }
    }
    if remove {
        println!("Remove the Apassy extension in each browser too: chrome://extensions.");
        return Ok(());
    }
    if !wrote {
        return Err(Failure::Other(if unsupported {
            format!(
                "No supported browser was found. {}",
                install::UNSUPPORTED_ALTERNATIVE
            )
        } else {
            "No browser was found. Use --browser NAME to select one.".to_owned()
        }));
    }
    let extension = app.extension_dir();
    if extension.join("manifest.json").is_file() {
        println!("The extension folder: {}", extension.display());
    } else {
        println!("The extension folder is missing. Reinstall the Apassy package.");
    }
    if !cfg!(target_os = "linux") && !app.is_installed_app() {
        println!(
            "This Apassy.app is not /Applications/Apassy.app. The agent profile protects it only when agents start with the apassy-sandbox of this app, or with --app-build."
        );
    }
    println!(
        "Add the extension in each browser: open {} and click Add to Chrome.",
        install::STORE_URL
    );
    println!("Or load the folder above with Developer mode on the extensions page of the browser.");
    println!(
        "Each fill requires owner confirmation in Apassy. The vault passphrase is always available."
    );
    Ok(())
}

#[cfg(all(test, feature = "vault"))]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn setup_writes_only_for_existing_profiles_and_removes() {
        let home = tempfile::tempdir().unwrap();
        let first = &BROWSERS[0];
        let second = &BROWSERS[1];
        let first_file = install::manifest_path(home.path(), first);
        let second_file = install::manifest_path(home.path(), second);
        fs::create_dir_all(first_file.parent().unwrap().parent().unwrap()).unwrap();
        let host = Path::new("/x/apassy-browser-host");
        let changes = apply(home.path(), host, None, false).unwrap();
        assert!(changes.contains(&(first.name, Change::Wrote(first_file.clone()))));
        assert!(changes.contains(&(second.name, Change::Missing)));
        assert!(!second_file.exists());
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&first_file).unwrap()).unwrap();
        assert_eq!(value["path"], "/x/apassy-browser-host");
        let changes = apply(home.path(), host, Some(second), false).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(second_file.is_file());
        let changes = apply(home.path(), host, None, true).unwrap();
        assert!(changes.contains(&(first.name, Change::Removed(first_file.clone()))));
        assert!(!first_file.exists() && !second_file.exists());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn setup_refuses_uninstalled_hosts_and_can_remove_existing_manifests() {
        let home = tempfile::tempdir().unwrap();
        let chrome = install::find("chrome").unwrap();
        let file = install::manifest_path(home.path(), chrome);
        let host = Path::new("/tmp/apassy-browser-host");
        let error = apply(home.path(), host, Some(chrome), false).unwrap_err();
        assert!(format!("{error:?}").contains("installed Apassy host"));
        assert!(!file.exists());
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, install::manifest(host)).unwrap();
        let changes = apply(home.path(), host, Some(chrome), true).unwrap();
        assert_eq!(changes, vec![(chrome.name, Change::Removed(file.clone()))]);
        assert!(!file.exists());
    }

    /// A snap or Flatpak browser is reported with its reason and the alternative, and
    /// gets no manifest, also when `--browser` names it.
    #[test]
    #[cfg(target_os = "linux")]
    fn setup_reports_unsupported_browsers_and_writes_nothing_for_them() {
        use crate::browser::install::Unsupported;
        let home = tempfile::tempdir().unwrap();
        let chromium = install::find("chromium").unwrap();
        let host = Path::new("/usr/lib/apassy/apassy-browser-host");
        let snap = |_: &Browser| State::Unsupported(Unsupported::Snap);
        for only in [None, Some(chromium)] {
            let changes = apply_with(home.path(), host, only, false, snap).unwrap();
            assert!(changes.iter().all(|(_, change)| matches!(
                change,
                Change::Unsupported(message, "snap")
                    if message.ends_with("Use Google Chrome, or Chromium from a .deb.")
            )));
        }
        assert!(!install::manifest_path(home.path(), chromium).exists());
        let json = changes_json(&[(
            chromium.name,
            Change::Unsupported(Unsupported::Flatpak.explain(chromium), "flatpak"),
        )]);
        assert_eq!(json[0]["state"], "unsupported");
        assert_eq!(json[0]["reason"], "flatpak");
        // --remove still deletes a stale manifest of an unsupported browser.
        let file = install::manifest_path(home.path(), chromium);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, install::manifest(host)).unwrap();
        let changes = apply_with(home.path(), host, Some(chromium), true, snap).unwrap();
        assert_eq!(
            changes,
            vec![(chromium.name, Change::Removed(file.clone()))]
        );
    }
}
