//! The project of a working directory (ADR 0025 §3a).
//!
//! A project is one git repository with all its worktrees: the folders that share
//! the git common directory. A folder without git is its own project. The root, the
//! home folder, its parents, and the filesystem aliases of them are never a project
//! (ADR 0024). The code reads only `.git` entries, with no `git` binary and no
//! library, so the answer is the same on every machine and in tests.
//!
//! The agent can write files in its working directory, so a `.git` entry is not
//! trusted: only a real directory or a regular file counts (never a symlink, a FIFO, or
//! a device), a file is read up to 4096 bytes, and a common directory that is the root,
//! the home folder, or one of their parents makes the entry broken, never a project key.
//!
//! A project key carries the owner's answers and production allowances (ADR 0025
//! §3b), so a folder must never claim the key of another repository (Gate 1 review).
//! A `.git` file is only a pointer that anyone can write (`gitdir: ~/Dev/acme/.git` in
//! `/tmp/x`), so it counts only with a back-link that git keeps inside the repository:
//!
//! - a linked worktree: the gitdir is `COMMON/worktrees/NAME`, and the file
//!   `COMMON/worktrees/NAME/gitdir` names this folder's `.git` file;
//! - a submodule: the gitdir is `SUPER/.git/modules/NAME` (also nested), and this folder
//!   is inside the working tree `SUPER`.
//!
//! A `.git` file without such a back-link is ignored, as if the folder had no git.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use super::approvals::folder_is_broad_with;

/// One project. Answers of the owner (ADR 0025 §3) are remembered under its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    /// The canonical path of the git common directory. All worktrees of one
    /// repository share it. For a folder without git, it is the canonical folder.
    pub key: String,
    /// A name for a card: the repository folder for a normal repository, the folder of
    /// a bare repository without `.git` (`repo.git` is `repo`), the name of a submodule
    /// (`.git/modules/NAME`), or the folder name.
    pub label: String,
    /// The folder where the search ended: the worktree that holds `.git`, or the
    /// working directory itself when there is no `.git`.
    pub root: PathBuf,
}

/// The project of `cwd`, or `None` when the folder is too wide to be one.
///
/// The search walks up from `cwd` to the nearest folder with a usable `.git` and never
/// goes to `home` or above. `.git` is either the common directory itself (a real
/// directory, not a symlink), or a regular file `gitdir: PATH` of a linked worktree or a
/// submodule (the path may be relative to the folder) with a back-link (see the module
/// documentation). The gitdir of a linked worktree has a regular file `commondir`
/// (relative to the gitdir) that names the common directory, and a regular file
/// `gitdir` that names the `.git` file of its worktree. The resolution reads at most
/// these three files, so it has no loop. A `.git` entry of another type, a `.git` file
/// without a back-link, an unreadable or missing target, or a common directory that is
/// broad is skipped, and the search goes on to the parent. Without `.git`, the project
/// is `cwd` itself. The root, `home`, its parents, and aliases of them give `None`, by
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
        if let Some(common) = git_common_dir(folder, home) {
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

/// The most that is read of a `.git` file or a `commondir` file.
const MAX_GIT_FILE: u64 = 4096;

/// Open a file without a wait on a FIFO that replaced it after the type check.
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(not(target_os = "macos"))]
const O_NONBLOCK: i32 = 0o4000;

/// The canonical git common directory for the `.git` entry of `folder`. `None`
/// when there is no usable `.git`: the search then goes on to the parent. `folder` is
/// canonical (an ancestor of the canonical working directory).
fn git_common_dir(folder: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let dot_git = folder.join(".git");
    // `symlink_metadata` does not follow a symlink: a `.git` symlink to the `.git` of
    // another repository (a directory or a worktree's file) is a pointer that the agent
    // can write, as a `.git` file is, and it has no back-link.
    let metadata = fs::symlink_metadata(&dot_git).ok()?;
    let common = if metadata.is_dir() {
        dot_git
    } else if metadata.is_file() {
        let gitdir = canonical_dir(&folder.join(gitdir_line(&dot_git)?))?;
        let commondir = gitdir.join("commondir");
        match fs::symlink_metadata(&commondir) {
            Err(error) if error.kind() == ErrorKind::NotFound => {
                // Without `commondir`, only a submodule is its own common directory.
                if !submodule_contains(&gitdir, folder) {
                    return None;
                }
                gitdir
            }
            Err(_) => return None,
            Ok(_) => {
                let text = read_small(&commondir)?;
                let line = text.lines().next()?.trim();
                if line.is_empty() {
                    return None;
                }
                let common = canonical_dir(&gitdir.join(line))?;
                if !worktree_links_back(&gitdir, &common, &dot_git) {
                    return None;
                }
                common
            }
        }
    } else {
        return None;
    };
    let common = canonical_dir(&common)?;
    let broad = folder_is_broad_with(&common, home)
        || folder_is_broad_with(&repository_folder(&common), home);
    (!broad).then_some(common)
}

/// The gitdir of a linked worktree is `COMMON/worktrees/NAME`, and its file `gitdir`
/// names `dot_git` (the `.git` file of the folder). Both sides are canonical: a path
/// with a symlink in the back-link still names the same file.
fn worktree_links_back(gitdir: &Path, common: &Path, dot_git: &Path) -> bool {
    if gitdir.parent() != Some(common.join("worktrees").as_path()) {
        return false;
    }
    let Some(text) = read_small(&gitdir.join("gitdir")) else {
        return false;
    };
    let Some(line) = text.lines().next().map(str::trim).filter(|l| !l.is_empty()) else {
        return false;
    };
    // Git writes an absolute path. A relative one (`worktree.useRelativePaths`) starts
    // at the gitdir.
    let Ok(target) = fs::canonicalize(gitdir.join(line)) else {
        return false;
    };
    let Ok(own) = fs::canonicalize(dot_git) else {
        return false;
    };
    target == own
}

/// The gitdir is `SUPER/.git/modules/NAME` (or a nested `.../modules/A/modules/B`) and
/// `folder` is inside the working tree `SUPER`, below it.
fn submodule_contains(gitdir: &Path, folder: &Path) -> bool {
    let parts: Vec<Component<'_>> = gitdir.components().collect();
    let Some(git) = parts.iter().position(|part| part.as_os_str() == ".git") else {
        return false;
    };
    if parts.get(git + 1).map(|part| part.as_os_str()) != Some(OsStr::new("modules"))
        || parts.len() <= git + 2
    {
        return false;
    }
    let superproject: PathBuf = parts[..git].iter().collect();
    // The superproject is a working tree: its `.git` is a real directory.
    let real_git = fs::symlink_metadata(superproject.join(".git")).is_ok_and(|m| m.is_dir());
    real_git && folder != superproject && folder.starts_with(&superproject)
}

/// The canonical form of `path` when it is a directory.
fn canonical_dir(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok().filter(|path| path.is_dir())
}

/// The path after `gitdir:` in a `.git` file.
fn gitdir_line(dot_git: &Path) -> Option<String> {
    let text = read_small(dot_git)?;
    let path = text.lines().find_map(|line| line.strip_prefix("gitdir:"))?;
    let path = path.trim();
    (!path.is_empty()).then(|| path.to_owned())
}

/// The first [`MAX_GIT_FILE`] bytes of a regular file, as text. `None` for a FIFO, a
/// device, a folder, or a file that cannot be read.
fn read_small(path: &Path) -> Option<String> {
    if !fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)
        .ok()?;
    // The type again on the open file: the path may have changed after the check.
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_GIT_FILE).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The folder that the repository is named after: the folder that holds `.git`, or
/// the common directory of a bare repository or a submodule.
fn repository_folder(common: &Path) -> PathBuf {
    match (common.file_name(), common.parent()) {
        (Some(name), Some(parent)) if name == ".git" => parent.to_path_buf(),
        _ => common.to_path_buf(),
    }
}

/// The name for the card of a common directory: the submodule name for
/// `.git/modules/NAME` (the innermost one of nested submodules), else the name of
/// [`repository_folder`] without a `.git` suffix.
fn label_of(common: &Path) -> String {
    if let Some(name) = submodule_name(common) {
        return name;
    }
    let name = label_of_folder(&repository_folder(common));
    match name.strip_suffix(".git") {
        Some(stem) if !stem.is_empty() => stem.to_owned(),
        _ => name,
    }
}

/// `NAME` of `.../.git/modules/NAME`, and of `.../.git/modules/A/modules/NAME` for a
/// nested submodule. A name may have several parts (`libs/foo`).
fn submodule_name(common: &Path) -> Option<String> {
    let parts: Vec<String> = common
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    let git = parts.iter().rposition(|part| part == ".git")?;
    if parts.get(git + 1).map(String::as_str) != Some("modules") {
        return None;
    }
    let rest = &parts[git + 2..];
    rest.split(|part| part == "modules")
        .rfind(|group| !group.is_empty())
        .map(|group| group.join("/"))
        .or_else(|| rest.last().cloned())
}

fn label_of_folder(folder: &Path) -> String {
    folder.file_name().map_or_else(
        || folder.to_string_lossy().into_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}
