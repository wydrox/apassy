//! The synced folder: file names, the folders on this Mac, files that iCloud evicted,
//! duplicates that a sync service made, and the download request.

use std::fs::{self, Metadata};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::SyncError;

/// The extension of a synced vault file.
pub const SYNC_FILE_EXTENSION: &str = ".apassy";
/// The suffix of the file that a push writes before the rename. iCloud Drive does not
/// sync a name that ends in `.nosync`. The Seatbelt profile denies it with the file.
pub const PUSH_SUFFIX: &str = ".push.nosync";
/// The name of the Apassy folder inside a synced folder (iCloud Drive, Dropbox, ...).
pub const FOLDER_NAME: &str = "Apassy";
/// The stem of a synced file name has at most this many bytes.
const MAX_STEM_BYTES: usize = 64;
/// iCloud Drive shows a file that is only in iCloud as `.<name>.icloud` (before
/// macOS 14).
const PLACEHOLDER_SUFFIX: &str = ".icloud";
/// `SF_DATALESS` from `<sys/stat.h>`: since macOS 14 a file that is only in iCloud keeps
/// its name and has this flag. A read of such a file waits for the download.
#[cfg(target_os = "macos")]
const SF_DATALESS: u32 = 0x4000_0000;

/// What the synced folder has for one file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Probe {
    /// The file is on this Mac.
    Present(PathBuf),
    /// The file is in iCloud but not on this Mac. The path is the real file name.
    Evicted(PathBuf),
    /// The folder has no such file.
    Missing,
    /// The folder is not there, but its parent is: a push makes it.
    NoFolder,
    /// The folder and its parent are not there: the drive, the share, or the sync
    /// service is not available.
    Unavailable,
}

/// Whether the folder exists: `None` when it does, else `NoFolder` or `Unavailable`.
pub(super) fn folder_missing(folder: &Path) -> Result<Option<Probe>, SyncError> {
    match fs::metadata(folder) {
        Ok(meta) if meta.is_dir() => Ok(None),
        Ok(_) => Err(SyncError::FolderUnavailable),
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            let parent_exists = folder.parent().is_some_and(Path::is_dir);
            Ok(Some(if parent_exists {
                Probe::NoFolder
            } else {
                Probe::Unavailable
            }))
        }
        Err(_) => Ok(Some(Probe::Unavailable)),
    }
}

/// Look up `name` in `folder`.
pub(super) fn probe(folder: &Path, name: &str) -> Result<Probe, SyncError> {
    if let Some(missing) = folder_missing(folder)? {
        return Ok(missing);
    }
    let path = folder.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(if is_evicted(&meta) {
            Probe::Evicted(path)
        } else {
            Probe::Present(path)
        }),
        Ok(_) => Err(SyncError::Io),
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            match fs::symlink_metadata(folder.join(placeholder_name(name))) {
                Ok(_) => Ok(Probe::Evicted(path)),
                Err(io_err) if io_err.kind() == ErrorKind::NotFound => Ok(Probe::Missing),
                Err(_) => Err(SyncError::Io),
            }
        }
        Err(_) => Err(SyncError::Io),
    }
}

/// Whether the file content is only in iCloud (a dataless file, macOS 14 and later).
#[cfg(target_os = "macos")]
fn is_evicted(meta: &Metadata) -> bool {
    use std::os::macos::fs::MetadataExt;
    meta.st_flags() & SF_DATALESS != 0
}

#[cfg(not(target_os = "macos"))]
fn is_evicted(_meta: &Metadata) -> bool {
    false
}

/// The placeholder name of an evicted file before macOS 14: `.<name>.icloud`.
pub(super) fn placeholder_name(name: &str) -> String {
    format!(".{name}{PLACEHOLDER_SUFFIX}")
}

/// Whether `name` can be the name of a vault file in the iCloud Apassy folder.
pub(super) fn valid_file_name(name: &str) -> bool {
    name.len() > SYNC_FILE_EXTENSION.len()
        && name.len() <= 255
        && name.ends_with(SYNC_FILE_EXTENSION)
        && !name.starts_with('.')
        && !name.contains(['/', '\0'])
        && !name.chars().any(char::is_control)
}

/// The synced file name for a vault name: `<name>.apassy`.
///
/// A `/`, `\`, `:`, or control character becomes `-`. A leading dot goes. The stem has
/// at most 64 bytes. A name that ends in a space and a number, like iCloud duplicates
/// (`Work 2`), gets a `-` instead of the space (`Work-2`). An empty name becomes `Vault`.
pub fn file_name_for(vault_name: &str) -> String {
    let base = vault_name.trim();
    let base = base.strip_suffix(SYNC_FILE_EXTENSION).unwrap_or(base);
    let mut stem = String::new();
    for ch in base.chars() {
        let ch = if ch.is_control() || matches!(ch, '/' | '\\' | ':') {
            '-'
        } else {
            ch
        };
        if stem.len() + ch.len_utf8() > MAX_STEM_BYTES {
            break;
        }
        stem.push(ch);
    }
    let mut stem = stem.trim_start_matches('.').trim().to_owned();
    if let Some((head, tail)) = stem.rsplit_once(' ')
        && !head.is_empty()
        && !tail.is_empty()
        && tail.bytes().all(|byte| byte.is_ascii_digit())
    {
        stem = format!("{head}-{tail}");
    }
    if stem.is_empty() {
        stem.push_str("Vault");
    }
    format!("{stem}{SYNC_FILE_EXTENSION}")
}

/// The name that enable tries at step `n` (1, 2, ...): `<stem>.apassy`, then
/// `<stem>-2.apassy`, and so on.
pub(super) fn candidate_name(first: &str, n: u32) -> String {
    if n <= 1 {
        return first.to_owned();
    }
    let stem = first.strip_suffix(SYNC_FILE_EXTENSION).unwrap_or(first);
    format!("{stem}-{n}{SYNC_FILE_EXTENSION}")
}

/// For a duplicate name `<base> <n>.apassy` (n at least 2) that iCloud Drive makes, the
/// original name `<base>.apassy`.
pub(super) fn duplicate_base(name: &str) -> Option<String> {
    let stem = name.strip_suffix(SYNC_FILE_EXTENSION)?;
    let (head, tail) = stem.rsplit_once(' ')?;
    let number: u32 = tail.parse().ok()?;
    let digits_only = tail.bytes().all(|byte| byte.is_ascii_digit());
    (digits_only && number >= 2 && !head.is_empty()).then(|| format!("{head}{SYNC_FILE_EXTENSION}"))
}

/// One vault file in a synced folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntry {
    /// The file name, for example `Personal.apassy`.
    pub name: String,
    /// The path of the file (also for a file that is not downloaded).
    pub path: PathBuf,
    /// Whether the content is on this Mac. A file that is only in iCloud needs a download
    /// first (`start_download`).
    pub downloaded: bool,
    /// For a duplicate that iCloud made (`Personal 2.apassy`), the name of the original
    /// file in the same folder.
    pub duplicate_of: Option<String>,
}

/// List the vault files (`*.apassy`) in a synced folder, sorted by name. An evicted file
/// is listed with `downloaded: false`. A missing folder whose parent exists gives an
/// empty list; a folder that is not available gives `FolderUnavailable`.
pub fn list_folder_vaults(folder: &Path) -> Result<Vec<FolderEntry>, SyncError> {
    match folder_missing(folder)? {
        Some(Probe::Unavailable) => return Err(SyncError::FolderUnavailable),
        Some(_) => return Ok(Vec::new()),
        None => {}
    }
    let mut entries: Vec<FolderEntry> = Vec::new();
    for dir_entry in fs::read_dir(folder).map_err(|_| SyncError::Io)? {
        let dir_entry = dir_entry.map_err(|_| SyncError::Io)?;
        let Ok(file_name) = dir_entry.file_name().into_string() else {
            continue;
        };
        let (name, downloaded) = if let Some(real) = file_name
            .strip_prefix('.')
            .and_then(|rest| rest.strip_suffix(PLACEHOLDER_SUFFIX))
        {
            (real.to_owned(), false)
        } else {
            let Ok(meta) = dir_entry.path().symlink_metadata() else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            (file_name, !is_evicted(&meta))
        };
        if !valid_file_name(&name) || entries.iter().any(|entry| entry.name == name) {
            continue;
        }
        entries.push(FolderEntry {
            path: folder.join(&name),
            name,
            downloaded,
            duplicate_of: None,
        });
    }
    let names: Vec<String> = entries.iter().map(|entry| entry.name.clone()).collect();
    for entry in &mut entries {
        entry.duplicate_of = duplicate_base(&entry.name).filter(|base| names.contains(base));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// The iCloud duplicates of `name` in `folder` (`<stem> 2.apassy`, ...), sorted.
pub(super) fn duplicates_of(folder: &Path, name: &str) -> Result<Vec<String>, SyncError> {
    let Ok(read) = fs::read_dir(folder) else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for dir_entry in read {
        let dir_entry = dir_entry.map_err(|_| SyncError::Io)?;
        let Ok(file_name) = dir_entry.file_name().into_string() else {
            continue;
        };
        let real = file_name
            .strip_prefix('.')
            .and_then(|rest| rest.strip_suffix(PLACEHOLDER_SUFFIX))
            .map_or(file_name.as_str(), |real| real);
        if duplicate_base(real).as_deref() == Some(name) && !found.iter().any(|seen| seen == real) {
            found.push(real.to_owned());
        }
    }
    found.sort();
    Ok(found)
}

/// Ask iCloud Drive to download the file at `path` (`/usr/bin/brctl download`). The
/// request runs in the background. Returns whether the request started. Always `false`
/// on a system without iCloud Drive. For a file outside iCloud Drive it does nothing.
#[cfg(target_os = "macos")]
pub fn start_download(path: &Path) -> bool {
    use std::process::{Command, Stdio};
    let child = Command::new("/usr/bin/brctl")
        .arg("download")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(mut child) => {
            // Reap the child, so it does not stay as a zombie in a long-running app.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            true
        }
        Err(_) => false,
    }
}

/// Ask iCloud Drive to download the file at `path`. There is no iCloud Drive here.
#[cfg(not(target_os = "macos"))]
pub fn start_download(_path: &Path) -> bool {
    false
}

/// A folder on this Mac that a sync service keeps in step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncFolder {
    /// For the owner: "iCloud Drive", "Dropbox", "Google Drive (me@example.com)".
    pub label: String,
    /// The Apassy folder in it. It may not exist yet; the first push makes it.
    pub path: PathBuf,
}

/// The iCloud Drive folder of `home`: `Library/Mobile Documents/com~apple~CloudDocs`.
pub(super) fn icloud_drive(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Mobile Documents")
        .join("com~apple~CloudDocs")
}

/// The synced folders under `home`, in this order: iCloud Drive, the folders of
/// `~/Library/CloudStorage` (Dropbox, Google Drive, OneDrive, and other File Provider
/// services), and `~/Dropbox`. Only folders that exist count. Each result is the Apassy
/// folder inside.
pub fn detect_folders_in(home: &Path) -> Vec<SyncFolder> {
    let mut found = Vec::new();
    let icloud = icloud_drive(home);
    if icloud.is_dir() {
        found.push(SyncFolder {
            label: "iCloud Drive".to_owned(),
            path: icloud.join(FOLDER_NAME),
        });
    }
    let storage = home.join("Library").join("CloudStorage");
    let mut providers: Vec<PathBuf> = fs::read_dir(&storage)
        .map(|dir| {
            dir.filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default();
    providers.sort();
    for root in providers {
        let Some(name) = root.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let (label, base) = provider_label(name);
        // Google Drive syncs "My Drive"; the root holds only the drives.
        let my_drive = root.join("My Drive");
        let base_dir = if base == "Google Drive" && my_drive.is_dir() {
            my_drive
        } else {
            root.clone()
        };
        found.push(SyncFolder {
            label,
            path: base_dir.join(FOLDER_NAME),
        });
    }
    let dropbox = home.join("Dropbox");
    let dropbox_listed = found
        .iter()
        .any(|folder| folder.label.starts_with("Dropbox"));
    if dropbox.is_dir() && !dropbox_listed {
        found.push(SyncFolder {
            label: "Dropbox".to_owned(),
            path: dropbox.join(FOLDER_NAME),
        });
    }
    found
}

/// The owner label and the service of a `~/Library/CloudStorage` folder name.
fn provider_label(name: &str) -> (String, &'static str) {
    let with_account = |service: &'static str, rest: &str| {
        let account = rest.trim_start_matches('-').trim();
        if account.is_empty() {
            (service.to_owned(), service)
        } else {
            (format!("{service} ({account})"), service)
        }
    };
    if let Some(rest) = name.strip_prefix("GoogleDrive") {
        with_account("Google Drive", rest)
    } else if let Some(rest) = name.strip_prefix("OneDrive") {
        with_account("OneDrive", rest)
    } else if let Some(rest) = name.strip_prefix("Dropbox") {
        with_account("Dropbox", rest)
    } else if let Some(rest) = name.strip_prefix("Box") {
        with_account("Box", rest)
    } else {
        (name.to_owned(), "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_file_names_are_safe_and_do_not_look_like_duplicates() {
        assert_eq!(file_name_for("Personal"), "Personal.apassy");
        assert_eq!(file_name_for("  Służbowy  "), "Służbowy.apassy");
        assert_eq!(file_name_for("Work 2"), "Work-2.apassy");
        assert_eq!(file_name_for("a/b:c\\d"), "a-b-c-d.apassy");
        assert_eq!(file_name_for("..hidden"), "hidden.apassy");
        assert_eq!(file_name_for(""), "Vault.apassy");
        assert_eq!(file_name_for("Team.apassy"), "Team.apassy");
        let long = file_name_for(&"ż".repeat(100));
        assert!(long.len() <= MAX_STEM_BYTES + SYNC_FILE_EXTENSION.len());
        assert!(valid_file_name(&long));
    }

    #[test]
    fn duplicates_have_a_space_and_a_number_of_at_least_two() {
        assert_eq!(
            duplicate_base("Personal 2.apassy").as_deref(),
            Some("Personal.apassy")
        );
        assert_eq!(
            duplicate_base("My vault 13.apassy").as_deref(),
            Some("My vault.apassy")
        );
        assert_eq!(duplicate_base("Personal 1.apassy"), None);
        assert_eq!(duplicate_base("Personal-2.apassy"), None);
        assert_eq!(duplicate_base("Personal 2x.apassy"), None);
        assert_eq!(duplicate_base(" 2.apassy"), None);
        assert_eq!(duplicate_base("Personal.apassy"), None);
    }

    #[test]
    fn detected_folders_name_each_service() {
        let home = tempfile::TempDir::new().unwrap();
        assert!(detect_folders_in(home.path()).is_empty());
        fs::create_dir_all(icloud_drive(home.path())).unwrap();
        let storage = home.path().join("Library").join("CloudStorage");
        fs::create_dir_all(storage.join("Dropbox")).unwrap();
        fs::create_dir_all(storage.join("GoogleDrive-me@example.com").join("My Drive")).unwrap();
        fs::create_dir_all(storage.join("OneDrive-Personal")).unwrap();
        fs::create_dir_all(home.path().join("Dropbox")).unwrap();
        let found = detect_folders_in(home.path());
        let labels: Vec<&str> = found.iter().map(|folder| folder.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "iCloud Drive",
                "Dropbox",
                "Google Drive (me@example.com)",
                "OneDrive (Personal)"
            ]
        );
        assert_eq!(found[0].path, icloud_drive(home.path()).join(FOLDER_NAME));
        assert_eq!(
            found[2].path,
            storage
                .join("GoogleDrive-me@example.com")
                .join("My Drive")
                .join(FOLDER_NAME)
        );
    }

    #[test]
    fn candidate_names_use_a_hyphen() {
        assert_eq!(candidate_name("Personal.apassy", 1), "Personal.apassy");
        assert_eq!(candidate_name("Personal.apassy", 3), "Personal-3.apassy");
    }

    #[test]
    fn cloud_file_name_rules() {
        assert!(valid_file_name("Personal.apassy"));
        assert!(valid_file_name("Personal 2.apassy"));
        assert!(!valid_file_name(".apassy"));
        assert!(!valid_file_name(".Personal.apassy"));
        assert!(!valid_file_name("a/b.apassy"));
        assert!(!valid_file_name("Personal.db"));
        assert!(!valid_file_name("Per\nsonal.apassy"));
    }
}
