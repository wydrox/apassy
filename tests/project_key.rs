#![cfg(feature = "vault")]

//! The project of a working directory (ADR 0025 §3a). Temporary folders only; the
//! git layout is written by hand, so no `git` binary is needed.

use std::fs;
use std::path::{Path, PathBuf};

use apassy::broker::project::{Project, project_of};
use tempfile::TempDir;

/// A fake home folder inside a temporary folder. Its parents are broad, as a real
/// home's are.
struct Fixture {
    _tmp: TempDir,
    home: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = fs::canonicalize(tmp.path())
        .expect("canonical")
        .join("home");
    fs::create_dir_all(&home).expect("home");
    Fixture { _tmp: tmp, home }
}

fn mkdir(path: &Path) -> PathBuf {
    fs::create_dir_all(path).expect("mkdir");
    path.to_path_buf()
}

fn repo(parent: &Path, name: &str) -> PathBuf {
    let root = mkdir(&parent.join(name));
    mkdir(&root.join(".git"));
    root
}

/// A linked worktree of `main`, as `git worktree add` writes it.
fn worktree(main: &Path, folder: &Path, name: &str, relative: bool) {
    let gitdir = mkdir(&main.join(".git").join("worktrees").join(name));
    fs::write(gitdir.join("commondir"), "../..\n").expect("commondir");
    fs::write(gitdir.join("HEAD"), "ref: refs/heads/x\n").expect("head");
    mkdir(folder);
    let target = if relative {
        let up = folder
            .strip_prefix(main.parent().unwrap())
            .unwrap()
            .components()
            .count();
        let mut path = PathBuf::new();
        for _ in 0..up {
            path.push("..");
        }
        path.join(main.file_name().unwrap())
            .join(".git/worktrees")
            .join(name)
    } else {
        gitdir
    };
    fs::write(
        folder.join(".git"),
        format!("gitdir: {}\n", target.display()),
    )
    .expect(".git");
}

fn project(cwd: &Path, home: &Path) -> Project {
    project_of(cwd, Some(home)).unwrap_or_else(|| panic!("no project for {}", cwd.display()))
}

#[test]
fn a_normal_repository_is_a_project_with_its_folder_name() {
    let f = fixture();
    let root = repo(&f.home, "shop");
    let p = project(&root, &f.home);
    assert_eq!(p.key, root.join(".git").to_string_lossy());
    assert_eq!(p.label, "shop");
    assert_eq!(p.root, root);
}

#[test]
fn a_subfolder_has_the_key_of_the_repository_root() {
    let f = fixture();
    let root = repo(&f.home, "shop");
    let deep = mkdir(&root.join("src/a/b"));
    let p = project(&deep, &f.home);
    assert_eq!(p, project(&root, &f.home));
    assert_eq!(p.root, root);
}

#[test]
fn worktrees_share_one_key_with_the_main_folder() {
    let f = fixture();
    let main = repo(&f.home, "shop");
    let wt1 = f.home.join("shop-feature");
    let wt2 = f.home.join("elsewhere/shop-fix");
    worktree(&main, &wt1, "feature", false);
    worktree(&main, &wt2, "fix", true);
    let base = project(&main, &f.home);
    for wt in [&wt1, &wt2] {
        let p = project(wt, &f.home);
        assert_eq!(p.key, base.key, "{}", wt.display());
        assert_eq!(p.label, "shop");
        assert_eq!(p.root, *wt);
        let sub = mkdir(&wt.join("src"));
        assert_eq!(project(&sub, &f.home), p);
    }
    assert_ne!(project(&wt1, &f.home).root, project(&wt2, &f.home).root);
}

#[test]
fn two_repositories_have_two_keys() {
    let f = fixture();
    let a = repo(&f.home, "a");
    let b = repo(&f.home, "b");
    assert_ne!(project(&a, &f.home).key, project(&b, &f.home).key);
}

#[test]
fn a_gitdir_without_commondir_is_its_own_common_directory() {
    let f = fixture();
    let gitdir = mkdir(&f.home.join("super/.git/modules/lib"));
    let folder = mkdir(&f.home.join("super/lib"));
    fs::write(folder.join(".git"), format!("gitdir: {}", gitdir.display())).unwrap();
    let p = project(&folder, &f.home);
    assert_eq!(p.key, gitdir.to_string_lossy());
    assert_eq!(p.label, "modules");
    assert_eq!(p.root, folder);
}

#[test]
fn a_folder_without_git_is_its_own_project() {
    let f = fixture();
    let plain = mkdir(&f.home.join("notes/draft"));
    let p = project(&plain, &f.home);
    assert_eq!(p.key, plain.to_string_lossy());
    assert_eq!(p.label, "draft");
    assert_eq!(p.root, plain);
    // A subfolder of a folder without git is a project of its own.
    let sub = mkdir(&plain.join("deeper"));
    assert_eq!(project(&sub, &f.home).root, sub);
}

#[test]
fn a_broken_git_entry_is_skipped() {
    let f = fixture();
    let root = repo(&f.home, "shop");
    let inner = mkdir(&root.join("inner"));
    fs::write(inner.join(".git"), "not a gitdir line\n").unwrap();
    let missing = mkdir(&root.join("missing"));
    fs::write(missing.join(".git"), "gitdir: /nonexistent/apassy-test\n").unwrap();
    let base = project(&root, &f.home);
    assert_eq!(project(&inner, &f.home), base);
    assert_eq!(project(&missing, &f.home), base);
}

#[test]
fn the_search_never_goes_to_home_or_above() {
    let f = fixture();
    // A repository at HOME (dotfiles) does not make HOME a project, and a folder
    // below it is not part of that repository.
    mkdir(&f.home.join(".git"));
    let plain = mkdir(&f.home.join("notes"));
    let p = project(&plain, &f.home);
    assert_eq!(p.root, plain);
    assert_eq!(p.key, plain.to_string_lossy());
    assert_eq!(project_of(&f.home, Some(&f.home)), None);
}

#[test]
fn the_root_home_and_its_parents_are_not_projects() {
    let f = fixture();
    assert_eq!(project_of(Path::new("/"), None), None);
    assert_eq!(project_of(Path::new("/"), Some(&f.home)), None);
    assert_eq!(project_of(&f.home, Some(&f.home)), None);
    let parent = f.home.parent().unwrap();
    assert_eq!(project_of(parent, Some(&f.home)), None);
    assert_eq!(project_of(parent.parent().unwrap(), Some(&f.home)), None);
    // A symlink to HOME is HOME.
    let link = parent.join("home-link");
    std::os::unix::fs::symlink(&f.home, &link).unwrap();
    assert_eq!(project_of(&link, Some(&f.home)), None);
}

#[test]
fn a_filesystem_alias_of_home_follows_the_broad_folder_rules() {
    // macOS firmlink: /System/Volumes/Data/<path> is the same directory as /<path>.
    let data = Path::new("/System/Volumes/Data");
    if !data.is_dir() {
        return;
    }
    let f = fixture();
    let alias = |path: &Path| PathBuf::from(format!("{}{}", data.display(), path.display()));
    let alias_home = alias(&f.home);
    if !alias_home.is_dir() {
        return;
    }
    assert_eq!(project_of(&alias_home, Some(&f.home)), None);
    assert_eq!(
        project_of(&alias(f.home.parent().unwrap()), Some(&f.home)),
        None
    );
    // A repository below the aliased HOME is still a project.
    let root = repo(&f.home, "shop");
    let p = project_of(&alias(&root), Some(&f.home)).expect("project below the alias");
    assert_eq!(p.label, "shop");
}
