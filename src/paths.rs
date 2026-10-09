//! Where Apassy keeps its files on each system.
//!
//! - macOS: `~/Library/Application Support/Apassy`.
//! - Linux: `$XDG_DATA_HOME/apassy`, or `~/.local/share/apassy`.

use std::path::PathBuf;

fn home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// The Apassy data directory: the vault, the broker socket, rule packs, and models.
#[cfg(target_os = "macos")]
pub fn data_dir() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(path) = debug_data_dir() {
        return path;
    }
    home()
        .join("Library")
        .join("Application Support")
        .join("Apassy")
}

/// The Apassy data directory: the vault, the broker socket, rule packs, and models.
#[cfg(not(target_os = "macos"))]
pub fn data_dir() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(path) = debug_data_dir() {
        return path;
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .unwrap_or_else(|| home().join(".local").join("share"));
    base.join("apassy")
}

/// Isolate a debug app's complete data directory for native acceptance tests.
/// Release builds contain no override. An invalid explicit path stops the app
/// instead of falling back to the owner's real vault directory.
#[cfg(debug_assertions)]
fn debug_data_dir() -> Option<PathBuf> {
    std::env::var_os("APASSY_DEBUG_DATA_DIR").map(|path| {
        let path = PathBuf::from(path);
        assert!(
            path.is_absolute(),
            "APASSY_DEBUG_DATA_DIR must be an absolute path."
        );
        path
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn data_dir_is_absolute_under_home() {
        let dir = super::data_dir();
        assert!(
            dir.ends_with("Apassy") || dir.ends_with("apassy"),
            "{dir:?}"
        );
    }
}
