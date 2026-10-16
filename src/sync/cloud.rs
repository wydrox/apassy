//! What iCloud Drive says about the synced file (docs/operations/sync.md, section 7).
//!
//! A file that iCloud evicted is easy to see: its flags or its placeholder name say so
//! ([`super::folder::Probe::Evicted`]). A file that is on this Mac can still be an old
//! version: iCloud knows of a newer one and has not downloaded it yet. Only iCloud can
//! tell (`NSURLUbiquitousItemDownloadingStatusKey`). The crate has no unsafe code, so
//! the native helper reads the key ([`crate::native::NativeHelper::ubiquity_status`]).
//!
//! While iCloud says that the copy on this Mac is not the newest one, the engine reports
//! [`super::FileStatus::NotDownloaded`], a sync stops with
//! [`super::SyncError::NotDownloaded`] before it merges or pushes, and a download
//! request asks iCloud for the newest version. A folder outside iCloud Drive, a file
//! that iCloud does not manage, a system without the helper, and a helper that does not
//! answer keep the plain rule: a file on this Mac is the copy to read.
//!
//! [`CloudProbe`] is a trait, so a test can stand in for iCloud
//! ([`super::FolderSync::with_cloud`]).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::native::{NativeHelper, Timeouts, UbiquityDownload};

/// The longest wait for an answer of the helper about one file.
const HELPER_WAIT: Duration = Duration::from_secs(5);
/// An answer of the helper counts this long. One look of the sync worker reads the
/// status of the open vault twice; the helper then runs once.
const STATUS_FOR: Duration = Duration::from_secs(1);

/// What iCloud says about the copy of a file on this Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudDownload {
    /// The copy on this Mac is the newest version.
    Current,
    /// A copy is on this Mac, but iCloud has a newer version.
    Downloaded,
    /// iCloud has not downloaded the file. A copy on this Mac can still be an old
    /// version of it.
    NotDownloaded,
}

/// The iCloud status of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudFileStatus {
    pub download: CloudDownload,
    /// iCloud downloads the file now.
    pub downloading: bool,
    /// The last download of iCloud failed.
    pub download_error: bool,
}

impl CloudFileStatus {
    /// The copy on this Mac is the newest version.
    pub fn is_current(&self) -> bool {
        self.download == CloudDownload::Current
    }
}

/// iCloud for the engine.
pub trait CloudProbe: fmt::Debug + Send + Sync {
    /// The iCloud status of the file at `path`. `None` when the file is not in iCloud
    /// Drive or the status is not known: the engine then reads the file on this Mac as
    /// before.
    fn status(&self, path: &Path) -> Option<CloudFileStatus>;

    /// Ask for the newest version of the file at `path`. Returns whether a request
    /// runs.
    fn request_download(&self, path: &Path) -> bool;
}

/// The iCloud of this Mac: the native helper for a file in `~/Library/Mobile Documents`,
/// and `brctl download` ([`super::start_download`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCloud;

impl SystemCloud {
    /// The shared probe of [`super::FolderSync::new`].
    pub fn shared() -> Arc<dyn CloudProbe> {
        static SHARED: OnceLock<Arc<dyn CloudProbe>> = OnceLock::new();
        Arc::clone(SHARED.get_or_init(|| Arc::new(Self)))
    }
}

/// The last answers of the helper, by path, and when they came.
type Answers = BTreeMap<PathBuf, (Instant, Option<CloudFileStatus>)>;

fn answers() -> MutexGuard<'static, Answers> {
    static ANSWERS: Mutex<Answers> = Mutex::new(BTreeMap::new());
    ANSWERS.lock().unwrap_or_else(PoisonError::into_inner)
}

impl CloudProbe for SystemCloud {
    fn status(&self, path: &Path) -> Option<CloudFileStatus> {
        if !in_icloud_drive(path) {
            return None;
        }
        let now = Instant::now();
        {
            let mut answers = answers();
            answers.retain(|_, (at, _)| now.saturating_duration_since(*at) < STATUS_FOR);
            if let Some((_, status)) = answers.get(path) {
                return *status;
            }
        }
        let status = helper()
            .and_then(|helper| helper.ubiquity_status(path, false).ok())
            .and_then(|status| {
                cloud_status(status.ubiquitous, status.download).map(|download| CloudFileStatus {
                    download,
                    downloading: status.downloading,
                    download_error: status.download_error,
                })
            });
        answers().insert(path.to_owned(), (now, status));
        status
    }

    fn request_download(&self, path: &Path) -> bool {
        answers().remove(path);
        // Foundation asks for the newest version also when an old copy is on this Mac.
        let asked = in_icloud_drive(path)
            && helper().is_some_and(|helper| {
                helper
                    .ubiquity_status(path, true)
                    .is_ok_and(|status| status.download_requested)
            });
        super::start_download(path) || asked
    }
}

/// The status for the engine. `None` for a file that iCloud does not manage, or an
/// unknown status.
fn cloud_status(ubiquitous: bool, download: UbiquityDownload) -> Option<CloudDownload> {
    if !ubiquitous {
        return None;
    }
    match download {
        UbiquityDownload::Current => Some(CloudDownload::Current),
        UbiquityDownload::Downloaded => Some(CloudDownload::Downloaded),
        UbiquityDownload::NotDownloaded => Some(CloudDownload::NotDownloaded),
        UbiquityDownload::Unknown => None,
    }
}

/// Whether `path` is in iCloud Drive (`~/Library/Mobile Documents`). Only there does
/// the engine ask iCloud.
#[cfg(target_os = "macos")]
fn in_icloud_drive(path: &Path) -> bool {
    super::home()
        .is_some_and(|home| path.starts_with(home.join("Library").join("Mobile Documents")))
}

/// There is no iCloud Drive on this system.
#[cfg(not(target_os = "macos"))]
fn in_icloud_drive(_path: &Path) -> bool {
    false
}

/// The native helper of the app, when its file is there. An app without the helper
/// (a test, the command line) asks iCloud nothing.
fn helper() -> Option<&'static NativeHelper> {
    static HELPER: OnceLock<Option<NativeHelper>> = OnceLock::new();
    HELPER
        .get_or_init(|| {
            NativeHelper::locate()
                .ok()
                .filter(|helper| helper.helper_path().is_file())
                .map(|helper| {
                    helper.with_timeouts(Timeouts {
                        quick: HELPER_WAIT,
                        ..Timeouts::default()
                    })
                })
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_known_status_of_an_icloud_file_counts() {
        assert_eq!(cloud_status(false, UbiquityDownload::Current), None);
        assert_eq!(cloud_status(true, UbiquityDownload::Unknown), None);
        assert_eq!(
            cloud_status(true, UbiquityDownload::Current),
            Some(CloudDownload::Current)
        );
        assert_eq!(
            cloud_status(true, UbiquityDownload::Downloaded),
            Some(CloudDownload::Downloaded)
        );
        assert_eq!(
            cloud_status(true, UbiquityDownload::NotDownloaded),
            Some(CloudDownload::NotDownloaded)
        );
    }

    /// A folder outside iCloud Drive asks iCloud nothing: Dropbox and the test folders
    /// keep the plain rule.
    #[test]
    fn a_folder_outside_icloud_drive_is_not_asked() {
        let dir = tempfile::tempdir().expect("dir");
        let file = dir.path().join("Synthetic.apassy");
        std::fs::write(&file, b"synthetic").expect("file");
        assert!(!in_icloud_drive(&file));
        assert_eq!(SystemCloud.status(&file), None);
        assert!(!in_icloud_drive(Path::new(
            "/Users/x/Dropbox/Apassy/a.apassy"
        )));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_mobile_documents_folder_is_icloud_drive() {
        let home = super::super::home().expect("HOME");
        let file = home
            .join("Library")
            .join("Mobile Documents")
            .join("com~apple~CloudDocs")
            .join("Apassy")
            .join("Synthetic.apassy");
        assert!(in_icloud_drive(&file));
    }
}
