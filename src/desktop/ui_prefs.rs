//! `ui.json` in the data directory: the view settings that the app keeps across
//! restarts. It holds no secret. The app writes it atomically with mode 0600, like
//! `update.json`.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The largest `ui.json` that the app reads.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// The content of `ui.json`. A missing field takes its default; an unknown field, like
/// `get_started_hidden` of the "Get started" list before 0.5.0, is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct UiPrefs {
    /// The owner collapsed the sidebar to its icons.
    pub(crate) sidebar_hidden: bool,
    /// The folders whose subfolders the sidebar shows, by UUID. A folder UUID is
    /// random and the same on each Mac that syncs the vault.
    pub(crate) open_folders: BTreeSet<String>,
    /// The owner turned "Show agents on the iPhone" off (relay-feed-v1 section 8). On by
    /// default.
    pub(crate) feed_off: bool,
}

impl UiPrefs {
    /// `<data dir>/ui.json`.
    pub(crate) fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("ui.json")
    }

    /// Read `path`. A missing, large, or damaged file gives the defaults.
    pub(crate) fn load(path: &Path) -> Self {
        let Ok(file) = fs::File::open(path) else {
            return Self::default();
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_FILE_BYTES
        {
            return Self::default();
        }
        serde_json::from_slice(&bytes).unwrap_or_default()
    }

    /// Write `path` atomically with mode 0600: a temporary file in the same folder,
    /// synced, then renamed over the old file.
    pub(crate) fn save(&self, path: &Path) -> io::Result<()> {
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        if !dir.is_dir() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let mut temp = tempfile::Builder::new()
            .prefix(".ui.json.")
            .tempfile_in(&dir)?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;
        temp.write_all(&bytes)?;
        temp.write_all(b"\n")?;
        temp.as_file().sync_all()?;
        temp.persist(path).map_err(|err| err.error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_broken_file_gives_the_defaults() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = UiPrefs::path(dir.path());
        assert_eq!(UiPrefs::load(&path), UiPrefs::default());
        assert!(!UiPrefs::default().sidebar_hidden);
        fs::write(&path, b"{ not json").expect("write");
        assert_eq!(UiPrefs::load(&path), UiPrefs::default());
        fs::write(&path, vec![b' '; MAX_FILE_BYTES as usize + 1]).expect("write");
        assert_eq!(UiPrefs::load(&path), UiPrefs::default());
        // A missing field takes its default.
        fs::write(&path, br#"{"sidebar_hidden": true}"#).expect("write");
        let prefs = UiPrefs::load(&path);
        assert!(prefs.sidebar_hidden && prefs.open_folders.is_empty());
    }

    /// A file from before 0.5.0 has the vaults where the owner hid "Get started". It
    /// still loads, and the next save drops that field.
    #[test]
    fn a_file_with_the_old_get_started_field_still_loads() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = UiPrefs::path(dir.path());
        fs::write(
            &path,
            br#"{"sidebar_hidden": true, "get_started_hidden": ["vault-a", "vault-b"], "open_folders": ["folder-1"]}"#,
        )
        .expect("write");
        let prefs = UiPrefs::load(&path);
        assert_eq!(
            prefs,
            UiPrefs {
                sidebar_hidden: true,
                open_folders: ["folder-1".to_owned()].into(),
                feed_off: false,
            }
        );
        prefs.save(&path).expect("save");
        let saved = fs::read_to_string(&path).expect("read");
        assert!(!saved.contains("get_started_hidden"), "{saved}");
        assert_eq!(UiPrefs::load(&path), prefs);
    }

    #[test]
    fn the_settings_round_trip_with_mode_0600() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("data").join("ui.json");
        let prefs = UiPrefs {
            sidebar_hidden: true,
            open_folders: ["folder-1".to_owned()].into(),
            feed_off: true,
        };
        prefs.save(&path).expect("save");
        assert_eq!(UiPrefs::load(&path), prefs);
        let mode = fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(path.parent().expect("parent"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        // A second save replaces the file and leaves no temporary file.
        UiPrefs::default().save(&path).expect("save again");
        assert_eq!(UiPrefs::load(&path), UiPrefs::default());
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn the_sidebar_toggle_writes_the_file_and_a_new_app_reads_it() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = UiPrefs::path(dir.path());
        let mut app = crate::desktop::DesktopApp::new();
        app.ui.load_prefs(dir.path().to_path_buf());
        assert!(!app.ui.sidebar_hidden);
        assert!(!path.exists(), "loading does not write");

        app.ui.toggle_sidebar();
        assert!(app.ui.sidebar_hidden);
        assert!(UiPrefs::load(&path).sidebar_hidden);

        let mut next = crate::desktop::DesktopApp::new();
        assert!(!next.ui.sidebar_hidden);
        next.ui.load_prefs(dir.path().to_path_buf());
        assert!(
            next.ui.sidebar_hidden,
            "a new app starts with the sidebar hidden"
        );

        next.ui.toggle_sidebar();
        assert!(!UiPrefs::load(&path).sidebar_hidden);

        // An open folder stays open after a restart; the narrow-window float does not
        // touch the file.
        next.ui.toggle_folder("folder-a");
        assert!(UiPrefs::load(&path).open_folders.contains("folder-a"));
        next.ui.toggle_sidebar_in(true);
        assert!(next.ui.sidebar_float);
        assert!(!UiPrefs::load(&path).sidebar_hidden);
        let mut third = crate::desktop::DesktopApp::new();
        third.ui.load_prefs(dir.path().to_path_buf());
        assert!(third.ui.open_folders.contains("folder-a"));
        third.ui.toggle_folder("folder-a");
        assert!(UiPrefs::load(&path).open_folders.is_empty());
    }

    /// "Show agents on the iPhone" is on by default, and off stays off after a restart.
    #[test]
    fn the_feed_setting_is_on_by_default_and_kept() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = UiPrefs::path(dir.path());
        let mut app = crate::desktop::DesktopApp::new();
        app.ui.load_prefs(dir.path().to_path_buf());
        assert!(!app.ui.feed_off, "on by default");
        app.ui.set_feed_off(true);
        assert!(UiPrefs::load(&path).feed_off);
        let mut next = crate::desktop::DesktopApp::new();
        next.ui.load_prefs(dir.path().to_path_buf());
        assert!(next.ui.feed_off, "off after a restart");
        next.ui.set_feed_off(false);
        assert!(!UiPrefs::load(&path).feed_off);
    }

    #[test]
    fn an_app_without_a_loaded_file_writes_nothing() {
        let mut app = crate::desktop::DesktopApp::new();
        app.ui.toggle_sidebar();
        assert!(app.ui.sidebar_hidden);
    }
}
