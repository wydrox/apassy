#![cfg(feature = "vault")]

//! The project of a working directory (ADR 0025 §3a). Temporary folders only; the
//! git layout is written by hand, so no `git` binary is needed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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
    // A submodule has the name of the submodule.
    assert_eq!(p.label, "lib");
    assert_eq!(p.root, folder);
}

#[test]
fn submodule_labels_are_the_submodule_names() {
    let f = fixture();
    for (modules, name) in [
        ("super/.git/modules/libs/foo", "libs/foo"),
        ("super/.git/modules/outer/modules/inner", "inner"),
    ] {
        let gitdir = mkdir(&f.home.join(modules));
        let folder = mkdir(&f.home.join("checkouts").join(name));
        // A relative gitdir starts at the folder of `.git`.
        let up = folder.strip_prefix(&f.home).unwrap().components().count();
        let relative = (0..up)
            .fold(PathBuf::new(), |p, _| p.join(".."))
            .join(modules);
        fs::write(
            folder.join(".git"),
            format!("gitdir: {}\n", relative.display()),
        )
        .unwrap();
        let p = project(&folder, &f.home);
        assert_eq!(p.key, gitdir.to_string_lossy());
        assert_eq!(p.label, name);
    }
}

#[test]
fn a_bare_repository_is_labelled_without_dot_git() {
    let f = fixture();
    let bare = mkdir(&f.home.join("dev/repo.git"));
    fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    let gitdir = mkdir(&bare.join("worktrees/main"));
    fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    let wt = mkdir(&f.home.join("dev/repo"));
    fs::write(wt.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
    let p = project(&wt, &f.home);
    assert_eq!(p.key, bare.to_string_lossy());
    assert_eq!(p.label, "repo");
    assert_eq!(p.root, wt);
    // A normal repository named `x.git` loses the suffix too.
    let dotted = repo(&f.home, "site.git");
    assert_eq!(project(&dotted, &f.home).label, "site");
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

/// `project_of` in a thread with a time limit: a `.git` entry written by the agent
/// must never make it wait (a FIFO) or read without end (a device).
fn guarded(cwd: &Path, home: &Path) -> Project {
    let (cwd, home) = (cwd.to_path_buf(), home.to_path_buf());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(project_of(&cwd, Some(&home)));
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("project_of finished in time")
        .expect("a project")
}

/// A FIFO at `path`, or `false` where `mkfifo` is not available.
fn fifo(path: &Path) -> bool {
    Command::new("mkfifo")
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

/// A folder below `root` whose `.git` file names `gitdir`.
fn gitdir_file(root: &Path, name: &str, gitdir: &str) -> PathBuf {
    let folder = mkdir(&root.join(name));
    fs::write(folder.join(".git"), format!("gitdir: {gitdir}\n")).unwrap();
    folder
}

#[test]
fn a_fifo_git_entry_is_skipped_without_a_wait() {
    let f = fixture();
    let root = repo(&f.home, "shop");
    let base = project(&root, &f.home);
    let inner = mkdir(&root.join("inner"));
    if !fifo(&inner.join(".git")) {
        return;
    }
    assert_eq!(guarded(&inner, &f.home), base);
    // A symlink to a FIFO.
    let pipe = root.join("pipe");
    assert!(fifo(&pipe));
    let linked = mkdir(&root.join("linked"));
    std::os::unix::fs::symlink(&pipe, linked.join(".git")).unwrap();
    assert_eq!(guarded(&linked, &f.home), base);
    // A FIFO as `commondir` of a gitdir.
    let gitdir = mkdir(&f.home.join("meta/wt"));
    assert!(fifo(&gitdir.join("commondir")));
    let wt = gitdir_file(&root, "wt", &gitdir.to_string_lossy());
    assert_eq!(guarded(&wt, &f.home), base);
}

#[test]
fn a_device_git_entry_is_skipped() {
    let f = fixture();
    let root = repo(&f.home, "shop");
    let base = project(&root, &f.home);
    let zero = Path::new("/dev/zero");
    if !zero.exists() {
        return;
    }
    let inner = mkdir(&root.join("inner"));
    std::os::unix::fs::symlink(zero, inner.join(".git")).unwrap();
    assert_eq!(guarded(&inner, &f.home), base);
    // A gitdir that is a device, and a `commondir` that is a device.
    let device = gitdir_file(&root, "device", "/dev/zero");
    assert_eq!(guarded(&device, &f.home), base);
    let gitdir = mkdir(&f.home.join("meta/wt"));
    std::os::unix::fs::symlink(zero, gitdir.join("commondir")).unwrap();
    let wt = gitdir_file(&root, "wt", &gitdir.to_string_lossy());
    assert_eq!(guarded(&wt, &f.home), base);
}

#[test]
fn only_the_start_of_a_git_file_is_read() {
    let f = fixture();
    let main = repo(&f.home, "shop");
    let other = repo(&f.home, "outer");
    let base = project(&other, &f.home);
    let line = format!("gitdir: {}\n", main.join(".git").display());
    // The line after 4096 bytes is not seen: the entry is broken.
    let late = mkdir(&other.join("late"));
    fs::write(
        late.join(".git"),
        format!("{}\n{line}", "x".repeat(1 << 20)),
    )
    .unwrap();
    assert_eq!(guarded(&late, &f.home), base);
    // The line at the start of a large file is seen.
    let early = mkdir(&other.join("early"));
    fs::write(early.join(".git"), format!("{line}{}", "x".repeat(1 << 20))).unwrap();
    let p = guarded(&early, &f.home);
    assert_eq!(p.key, project(&main, &f.home).key);
    assert_eq!(p.label, "shop");
}

#[test]
fn a_gitdir_to_root_or_home_is_never_a_key() {
    let f = fixture();
    // Dotfiles: HOME has a repository. Its common directory names HOME.
    mkdir(&f.home.join(".git"));
    let work = mkdir(&f.home.join("work"));
    let above = f.home.parent().unwrap().to_string_lossy().into_owned();
    for (name, gitdir) in [
        ("root", "/".to_owned()),
        ("home", f.home.to_string_lossy().into_owned()),
        (
            "dotfiles",
            f.home.join(".git").to_string_lossy().into_owned(),
        ),
        ("above", above),
        ("relative", "../../..".to_owned()),
    ] {
        let folder = gitdir_file(&work, name, &gitdir);
        let p = guarded(&folder, &f.home);
        assert_eq!(p.key, folder.to_string_lossy(), "gitdir {gitdir}");
        assert_eq!(p.root, folder, "gitdir {gitdir}");
    }
    // A `.git` symlink to the root or to HOME.
    for (name, target) in [("link-root", Path::new("/")), ("link-home", &f.home)] {
        let folder = mkdir(&work.join(name));
        std::os::unix::fs::symlink(target, folder.join(".git")).unwrap();
        let p = guarded(&folder, &f.home);
        assert_eq!(p.key, folder.to_string_lossy(), "{name}");
    }
}

#[test]
fn a_commondir_at_or_above_home_is_never_a_key() {
    let f = fixture();
    let root = repo(&f.home, "shop");
    let base = project(&root, &f.home);
    // home/meta/NAME/commondir: `../..` is HOME, `../../..` is above HOME, and an
    // absolute `/` is the root.
    for (name, commondir) in [("home", "../.."), ("above", "../../.."), ("root", "/")] {
        let gitdir = mkdir(&f.home.join("meta").join(name));
        fs::write(gitdir.join("commondir"), format!("{commondir}\n")).unwrap();
        let wt = gitdir_file(&root, name, &gitdir.to_string_lossy());
        assert_eq!(guarded(&wt, &f.home), base, "commondir {commondir}");
        // Without a repository above, the folder is its own project.
        let alone = gitdir_file(&f.home.join("alone"), name, &gitdir.to_string_lossy());
        let p = guarded(&alone, &f.home);
        assert_eq!(p.key, alone.to_string_lossy(), "commondir {commondir}");
    }
}

#[test]
fn a_git_symlink_to_a_repository_is_followed() {
    let f = fixture();
    let main = repo(&f.home, "shop");
    let folder = mkdir(&f.home.join("mirror"));
    std::os::unix::fs::symlink(main.join(".git"), folder.join(".git")).unwrap();
    let p = guarded(&folder, &f.home);
    assert_eq!(p.key, project(&main, &f.home).key);
    assert_eq!(p.label, "shop");
    assert_eq!(p.root, folder);
}
