//! The project of a working directory (ADR 0025 §3a).
//!
//! A project is one git repository with all its worktrees: the folders that share
//! the git common directory. A folder without git is its own project. The root, the
//! home folder, its parents, and the filesystem aliases of them are never a project
//! (ADR 0024). The code reads only `.git` entries, with no `git` binary and no
//! library, so the answer is the same on every machine and in tests.

use std::fs;
use std::path::{Path, PathBuf};

use super::approvals::folder_is_broad_with;

/// One project. Answers of the owner (ADR 0025 §3) are remembered under its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    /// The canonical path of the git common directory. All worktrees of one
    /// repository share it. For a folder without git, it is the canonical folder.
    pub key: String,
    /// A name for a card: the name of the folder that contains the common directory
    /// (the repository folder for a normal repository), or the folder name.
    pub label: String,
    /// The folder where the search ended: the worktree that holds `.git`, or the
    /// working directory itself when there is no `.git`.
    pub root: PathBuf,
}

/// The project of `cwd`, or `None` when the folder is too wide to be one.
///
/// The search walks up from `cwd` to the nearest folder with `.git` and never goes
/// to `home` or above. `.git` is either the common directory itself, or a file
/// `gitdir: PATH` of a linked worktree (the path may be relative to the folder). The
/// gitdir of a linked worktree has a `commondir` file (relative to the gitdir) that
/// names the common directory. Without `.git`, the project is `cwd` itself. The
/// root, `home`, its parents, and aliases of them give `None`, by
/// [`folder_is_broad_with`]. Without `home`, only the root is known to be broad.
pub fn project_of(cwd: &Path, home: Option<&Path>) -> Option<Project> {
    let cwd = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    if folder_is_broad_with(&cwd, home) {
        return None;
    }
    for folder in cwd.ancestors() {
        if folder_is_broad_with(folder, home) {
            break;
        }
        if let Some(common) = git_common_dir(folder) {
            return Some(Project {
                key: common.to_string_lossy().into_owned(),
                label: label_of(&common),
                root: folder.to_path_buf(),
            });
        }
    }
    Some(Project {
        key: cwd.to_string_lossy().into_owned(),
        label: label_of_folder(&cwd),
        root: cwd,
    })
}

/// The canonical git common directory for the `.git` entry of `folder`. `None`
/// when there is no usable `.git`: the search then goes on to the parent.
fn git_common_dir(folder: &Path) -> Option<PathBuf> {
    let dot_git = folder.join(".git");
    let metadata = fs::symlink_metadata(&dot_git).ok()?;
    let common = if metadata.is_dir() {
        dot_git
    } else if metadata.is_file() || metadata.file_type().is_symlink() {
        let gitdir = resolve(folder, &gitdir_line(&dot_git)?);
        match fs::read_to_string(gitdir.join("commondir")) {
            Ok(text) => resolve(&gitdir, text.lines().next()?.trim()),
            Err(_) => gitdir,
        }
    } else {
        return None;
    };
    fs::canonicalize(common)
        .ok()
        .filter(|common| common.is_dir())
}

/// The path after `gitdir:` in a `.git` file.
fn gitdir_line(dot_git: &Path) -> Option<String> {
    let text = fs::read_to_string(dot_git).ok()?;
    let path = text.lines().find_map(|line| line.strip_prefix("gitdir:"))?;
    let path = path.trim();
    (!path.is_empty()).then(|| path.to_owned())
}

/// `path` as an absolute path: a relative one starts at `base`.
fn resolve(base: &Path, path: &str) -> PathBuf {
    base.join(path)
}

/// The name of the folder that contains the common directory.
fn label_of(common: &Path) -> String {
    common
        .parent()
        .map(label_of_folder)
        .unwrap_or_else(|| common.to_string_lossy().into_owned())
}

fn label_of_folder(folder: &Path) -> String {
    folder.file_name().map_or_else(
        || folder.to_string_lossy().into_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}
