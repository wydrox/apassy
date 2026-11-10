//! The device settings "How often to ask" and "Lock after inactivity" on Linux.
//!
//! macOS keeps them in the keychain through the signed helper. Linux has no such
//! boundary (ADR 0045: same-user processes are outside the software vault), so they live
//! in a private file of the data directory: `device-policy.json`, mode 0600, owned by
//! this user, never a symlink. The synced vault and `ui.json` never carry them.
//! A damaged, foreign or too-open file fails closed: the callers then use "Every time"
//! and "Never". A missing file is the default (the same values).
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The file name in the data directory.
pub const FILE: &str = "device-policy.json";
const MAX_BYTES: u64 = 4096;

/// The stored codes. The callers parse them (`OwnerFrequency::parse`, `LockRule::parse`)
/// and treat an unknown code as damage.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicy {
    pub owner_frequency: String,
    pub auto_lock: String,
}

impl Default for DevicePolicy {
    fn default() -> Self {
        Self {
            owner_frequency: "every_time".into(),
            auto_lock: "never".into(),
        }
    }
}

pub fn path_in(dir: &Path) -> PathBuf {
    dir.join(FILE)
}

/// The file in Apassy's data directory.
pub fn default_path() -> PathBuf {
    path_in(&crate::paths::data_dir())
}

/// Read the settings. `Ok(default)` when the file does not exist.
pub fn read(path: &Path) -> Result<DevicePolicy, String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DevicePolicy::default()),
        Err(_) => return Err("The device settings cannot be read.".into()),
    };
    if !meta.file_type().is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || meta.len() > MAX_BYTES
    {
        return Err("The device settings file is not a private file of this user.".into());
    }
    let mut bytes = Vec::new();
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .and_then(|f| f.take(MAX_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| "The device settings cannot be read.".to_owned())?;
    serde_json::from_slice(&bytes).map_err(|_| "The device settings file is damaged.".into())
}

/// Write the settings atomically (a private temporary file, then a rename).
pub fn write(path: &Path, policy: &DevicePolicy) -> Result<(), String> {
    let fail = |_| "The device settings cannot be saved.".to_owned();
    let dir = path.parent().ok_or("The device settings have no folder.")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(fail)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| "The device settings cannot be saved.")?;
    let temp = dir.join(format!(".{FILE}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temp);
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(fail)?;
    if read(path)? != *policy {
        return Err("The device settings readback failed.".into());
    }
    Ok(())
}

/// Change one value and keep the other: read, edit, write. A damaged file is replaced
/// only by an explicit change, starting from the strict defaults.
pub fn update(path: &Path, edit: impl FnOnce(&mut DevicePolicy)) -> Result<DevicePolicy, String> {
    let mut policy = read(path).unwrap_or_default();
    edit(&mut policy);
    write(path, &policy)?;
    Ok(policy)
}

#[cfg(all(test, feature = "vault"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn device_policy_missing_file_is_strict_default_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(&dir.path().join("apassy"));
        assert_eq!(read(&path).unwrap(), DevicePolicy::default());
        let saved = update(&path, |p| p.owner_frequency = "5m".into()).unwrap();
        assert_eq!(saved.auto_lock, "never");
        let saved = update(&path, |p| p.auto_lock = "session".into()).unwrap();
        assert_eq!(saved.owner_frequency, "5m");
        assert_eq!(read(&path).unwrap(), saved);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn device_policy_open_damaged_or_linked_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        write(&path, &DevicePolicy::default()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"{\"owner_frequency\":\"1h\"}").unwrap();
        assert!(read(&path).is_err());
        let other = dir.path().join("other.json");
        fs::write(&other, b"{}").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(read(&path).is_err());
    }
}
