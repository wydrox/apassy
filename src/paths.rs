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
    home()
        .join("Library")
        .join("Application Support")
        .join("Apassy")
}

/// The Apassy data directory: the vault, the broker socket, rule packs, and models.
#[cfg(not(target_os = "macos"))]
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .unwrap_or_else(|| home().join(".local").join("share"));
    base.join("apassy")
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
