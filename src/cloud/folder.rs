//! The Apassy folder in iCloud Drive: file names, evicted files, iCloud duplicates,
//! and the download request.

use std::fs::{self, Metadata};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::CloudError;

/// The extension of a vault file in the iCloud Apassy folder.
pub const CLOUD_FILE_EXTENSION: &str = ".apassy";
/// The stem of a cloud file name has at most this many bytes.
const MAX_STEM_BYTES: usize = 64;
/// iCloud Drive shows a file that is only in iCloud as `.<name>.icloud` (before
/// macOS 14).
const PLACEHOLDER_SUFFIX: &str = ".icloud";
/// `SF_DATALESS` from `<sys/stat.h>`: since macOS 14 a file that is only in iCloud keeps
/// its name and has this flag. A read of such a file waits for the download.
#[cfg(target_os = "macos")]
const SF_DATALESS: u32 = 0x4000_0000;

/// What the Apassy folder has for one cloud file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Probe {
    /// The file is on this Mac.
    Present(PathBuf),
    /// The file is in iCloud but not on this Mac. The path is the real file name.
    Evicted(PathBuf),
    /// The Apassy folder has no such file.
    Missing,
    /// iCloud Drive is there, but the Apassy folder is not.
    NoFolder,
    /// There is no iCloud Drive folder.
    NoICloud,
}

/// Whether the Apassy folder exists: `None` when it does, else `NoFolder` or `NoICloud`.
/// The parent of `cloud_dir` is the iCloud Drive folder.
pub(super) fn folder_missing(cloud_dir: &Path) -> Result<Option<Probe>, CloudError> {
    match fs::metadata(cloud_dir) {
        Ok(meta) if meta.is_dir() => Ok(None),
        Ok(_) => Err(CloudError::Io),
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            let root_exists = cloud_dir.parent().is_some_and(Path::is_dir);
            Ok(Some(if root_exists {
                Probe::NoFolder
            } else {
                Probe::NoICloud
            }))
        }
        Err(_) => Err(CloudError::Io),
    }
}

/// Look up `name` in `cloud_dir`.
pub(super) fn probe(cloud_dir: &Path, name: &str) -> Result<Probe, CloudError> {
    if let Some(missing) = folder_missing(cloud_dir)? {
        return Ok(missing);
    }
    let path = cloud_dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(if is_evicted(&meta) {
            Probe::Evicted(path)
        } else {
            Probe::Present(path)
        }),
        Ok(_) => Err(CloudError::Io),
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            match fs::symlink_metadata(cloud_dir.join(placeholder_name(name))) {
                Ok(_) => Ok(Probe::Evicted(path)),
                Err(io_err) if io_err.kind() == ErrorKind::NotFound => Ok(Probe::Missing),
                Err(_) => Err(CloudError::Io),
            }
        }
        Err(_) => Err(CloudError::Io),
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
pub(super) fn valid_cloud_file_name(name: &str) -> bool {
    name.len() > CLOUD_FILE_EXTENSION.len()
        && name.len() <= 255
        && name.ends_with(CLOUD_FILE_EXTENSION)
        && !name.starts_with('.')
        && !name.contains(['/', '\0'])
        && !name.chars().any(char::is_control)
}

/// The cloud file name for a vault name: `<name>.apassy`.
///
/// A `/`, `\`, `:`, or control character becomes `-`. A leading dot goes. The stem has
/// at most 64 bytes. A name that ends in a space and a number, like iCloud duplicates
/// (`Work 2`), gets a `-` instead of the space (`Work-2`). An empty name becomes `Vault`.
pub fn cloud_file_name_for(vault_name: &str) -> String {
    let base = vault_name.trim();
    let base = base.strip_suffix(CLOUD_FILE_EXTENSION).unwrap_or(base);
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
    format!("{stem}{CLOUD_FILE_EXTENSION}")
}

/// The name that enable tries at step `n` (1, 2, ...): `<stem>.apassy`, then
/// `<stem>-2.apassy`, and so on.
pub(super) fn candidate_name(first: &str, n: u32) -> String {
    if n <= 1 {
        return first.to_owned();
    }
    let stem = first.strip_suffix(CLOUD_FILE_EXTENSION).unwrap_or(first);
    format!("{stem}-{n}{CLOUD_FILE_EXTENSION}")
}

/// For an iCloud duplicate name `<base> <n>.apassy` (n at least 2), the original name
/// `<base>.apassy`.
pub(super) fn duplicate_base(name: &str) -> Option<String> {
    let stem = name.strip_suffix(CLOUD_FILE_EXTENSION)?;
    let (head, tail) = stem.rsplit_once(' ')?;
    let number: u32 = tail.parse().ok()?;
    let digits_only = tail.bytes().all(|byte| byte.is_ascii_digit());
    (digits_only && number >= 2 && !head.is_empty())
        .then(|| format!("{head}{CLOUD_FILE_EXTENSION}"))
}

/// One vault file in the iCloud Apassy folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudEntry {
    /// The file name, for example `Personal.apassy`.
    pub name: String,
    /// The path of the file (also for a file that is not downloaded).
    pub path: PathBuf,
    /// Whether the content is on this Mac. A file that is only in iCloud needs a download
    /// first (`start_download`).
    pub downloaded: bool,
    /// For an iCloud conflict duplicate (`Personal 2.apassy`), the name of the original
    /// file in the same folder.
    pub duplicate_of: Option<String>,
}

/// List the vault files (`*.apassy`) in the iCloud Apassy folder, sorted by name. An
/// evicted file is listed with `downloaded: false`. A missing Apassy folder gives an
/// empty list. No iCloud Drive gives `Unavailable`.
pub fn list_cloud_vaults(cloud_dir: &Path) -> Result<Vec<CloudEntry>, CloudError> {
    match folder_missing(cloud_dir)? {
        Some(Probe::NoICloud) => return Err(CloudError::Unavailable),
        Some(_) => return Ok(Vec::new()),
        None => {}
    }
    let mut entries: Vec<CloudEntry> = Vec::new();
    for dir_entry in fs::read_dir(cloud_dir).map_err(|_| CloudError::Io)? {
        let dir_entry = dir_entry.map_err(|_| CloudError::Io)?;
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
        if !valid_cloud_file_name(&name) || entries.iter().any(|entry| entry.name == name) {
            continue;
        }
        entries.push(CloudEntry {
            path: cloud_dir.join(&name),
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

/// The iCloud duplicates of `name` in `cloud_dir` (`<stem> 2.apassy`, ...), sorted.
pub(super) fn duplicates_of(cloud_dir: &Path, name: &str) -> Result<Vec<String>, CloudError> {
    let Ok(read) = fs::read_dir(cloud_dir) else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for dir_entry in read {
        let dir_entry = dir_entry.map_err(|_| CloudError::Io)?;
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
/// on a system without iCloud Drive.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_file_names_are_safe_and_do_not_look_like_duplicates() {
        assert_eq!(cloud_file_name_for("Personal"), "Personal.apassy");
        assert_eq!(cloud_file_name_for("  Służbowy  "), "Służbowy.apassy");
        assert_eq!(cloud_file_name_for("Work 2"), "Work-2.apassy");
        assert_eq!(cloud_file_name_for("a/b:c\\d"), "a-b-c-d.apassy");
        assert_eq!(cloud_file_name_for("..hidden"), "hidden.apassy");
        assert_eq!(cloud_file_name_for(""), "Vault.apassy");
        assert_eq!(cloud_file_name_for("Team.apassy"), "Team.apassy");
        let long = cloud_file_name_for(&"ż".repeat(100));
        assert!(long.len() <= MAX_STEM_BYTES + CLOUD_FILE_EXTENSION.len());
        assert!(valid_cloud_file_name(&long));
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
    fn candidate_names_use_a_hyphen() {
        assert_eq!(candidate_name("Personal.apassy", 1), "Personal.apassy");
        assert_eq!(candidate_name("Personal.apassy", 3), "Personal-3.apassy");
    }

    #[test]
    fn cloud_file_name_rules() {
        assert!(valid_cloud_file_name("Personal.apassy"));
        assert!(valid_cloud_file_name("Personal 2.apassy"));
        assert!(!valid_cloud_file_name(".apassy"));
        assert!(!valid_cloud_file_name(".Personal.apassy"));
        assert!(!valid_cloud_file_name("a/b.apassy"));
        assert!(!valid_cloud_file_name("Personal.db"));
        assert!(!valid_cloud_file_name("Per\nsonal.apassy"));
    }
}
