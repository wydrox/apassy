//! `update.json` in the data directory: the update settings and the last results.
//! It holds no secret. The app writes it atomically with mode 0600.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The largest `update.json` that the app reads.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// What is ready to install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum StagedKind {
    /// The checked app in `update/Apassy.app`. The installer moves it into place.
    App,
    /// The checked disk image in `update/Apassy.dmg`. Apassy cannot replace itself
    /// in its folder, so the owner copies the app from the image in Finder.
    Image,
}

/// A checked new version in the update folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Staged {
    pub(crate) version: String,
    pub(crate) build: String,
    pub(crate) commit: String,
    pub(crate) kind: StagedKind,
    /// The team of the signature, the same as the team of the running app.
    pub(crate) team: String,
}

/// The result of the last install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InstallReport {
    /// Seconds since 1970, when the app read the result.
    pub(crate) at: u64,
    pub(crate) ok: bool,
    pub(crate) message: String,
}

/// The content of `update.json`. A missing field takes its default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct UpdateFile {
    /// Check at start and every 6 hours.
    pub(crate) auto_check: bool,
    /// Download a new version after a check, and install it at the next quit.
    pub(crate) auto_install: bool,
    /// Seconds since 1970.
    pub(crate) last_check: Option<u64>,
    pub(crate) last_result: Option<String>,
    pub(crate) staged: Option<Staged>,
    pub(crate) last_install: Option<InstallReport>,
}

impl Default for UpdateFile {
    fn default() -> Self {
        Self {
            auto_check: true,
            auto_install: true,
            last_check: None,
            last_result: None,
            staged: None,
            last_install: None,
        }
    }
}

impl UpdateFile {
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
        private_dir(&dir)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let mut temp = tempfile::Builder::new()
            .prefix(".update.json.")
            .tempfile_in(&dir)?;
        set_mode(temp.path(), 0o600)?;
        temp.write_all(&bytes)?;
        temp.write_all(b"\n")?;
        temp.as_file().sync_all()?;
        temp.persist(path).map_err(|err| err.error)?;
        Ok(())
    }
}

/// Make `dir` with mode 0700 when it does not exist.
pub(crate) fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

pub(crate) fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn defaults_turn_both_settings_on() {
        let file = UpdateFile::default();
        assert!(file.auto_check);
        assert!(file.auto_install);
        assert_eq!(file.staged, None);
        let dir = tempfile::TempDir::new().expect("temp dir");
        assert_eq!(UpdateFile::load(&dir.path().join("none.json")), file);
    }

    #[test]
    fn settings_and_results_persist_with_mode_0600() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("data").join("update.json");
        let file = UpdateFile {
            auto_check: false,
            auto_install: false,
            last_check: Some(1_790_593_085),
            last_result: Some("Apassy is up to date.".to_owned()),
            staged: Some(Staged {
                version: "0.3.1".to_owned(),
                build: "e710914".to_owned(),
                commit: super::super::manifest::tests::COMMIT.to_owned(),
                kind: StagedKind::App,
                team: "ABCDE12345".to_owned(),
            }),
            last_install: Some(InstallReport {
                at: 1_790_593_100,
                ok: false,
                message: "Synthetic failure.".to_owned(),
            }),
        };
        file.save(&path).expect("save");
        assert_eq!(UpdateFile::load(&path), file);
        let mode = fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(path.parent().unwrap())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "a new data folder is private");

        // A second save replaces the file and leaves no temporary file.
        let mut changed = file.clone();
        changed.auto_check = true;
        changed.save(&path).expect("save again");
        assert_eq!(UpdateFile::load(&path), changed);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .expect("list")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("update.json")]);
    }

    #[test]
    fn a_damaged_or_partial_file_gives_defaults_for_what_is_missing() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("update.json");
        fs::write(&path, b"{ not json").expect("write");
        assert_eq!(UpdateFile::load(&path), UpdateFile::default());
        fs::write(&path, br#"{"auto_install": false}"#).expect("write");
        let file = UpdateFile::load(&path);
        assert!(file.auto_check, "a missing field takes its default");
        assert!(!file.auto_install);
        fs::write(&path, vec![b' '; 70 * 1024]).expect("write");
        assert_eq!(UpdateFile::load(&path), UpdateFile::default());
    }
}
