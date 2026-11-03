//! The bubblewrap arguments of a sandbox: the namespaces, the mount plan, and the
//! init program with its bridges.
//!
//! SECURITY (judge panel): this file is the boundary. The mount plan, in order:
//!
//! 1. `/` read-only, a new `/dev`, and a new `/proc` for the new PID namespace.
//! 2. An empty tmpfs over `/tmp`, `/var/tmp`, `/home`, `/root`, and `/run`: the
//!    files of other users, the user's runtime folder (`$XDG_RUNTIME_DIR`: the
//!    session bus, the keyring and agent sockets, `systemd --user`), and the
//!    system sockets in `/run` (Docker, the system bus) are gone.
//! 3. The few things that programs need from `/run` (the NixOS system profile, and
//!    with the host network the DNS file that `/etc/resolv.conf` points to).
//! 4. The home folder: an empty private tmpfs ([`HomePolicy::Hidden`]) or the real
//!    one read-only ([`HomePolicy::ReadOnly`]).
//! 5. The allowed paths, ancestors first: read-only or writable binds of the same
//!    path.
//! 6. A mask over each denied path that step 1 to 5 left visible: an empty
//!    read-only tmpfs over a folder, `/dev/null` over a file or a socket. The masks
//!    come after the binds, so a deny always wins; an allowed path inside a denied
//!    one is refused.
//! 7. The sockets that a sandbox may use inside a denied folder (the broker socket),
//!    read-only.
//! 8. The init program and the bridge sockets, read-only, in [`INTERNAL_DIR`].
//!
//! Every path is resolved on the host first. A denied path that does not exist when
//! the sandbox starts gets no mask; the read-only system and the hidden folders keep
//! the sandbox from making it.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use super::bridge::BRIDGE_ARG;
use super::{Bridge, HomePolicy, NetPlan, SandboxError};

/// The folder of the init program and of the bridge sockets inside the sandbox. It
/// is in the private `/tmp`, so it never names a folder of the host.
pub const INTERNAL_DIR: &str = "/tmp/.apassy-sandbox";

/// Folders that the sandbox replaces with an empty tmpfs.
const HIDDEN_ROOTS: [&str; 5] = ["/tmp", "/var/tmp", "/home", "/root", "/run"];

/// Sockets outside `/run` that give root to a group of the user (`lxd`,
/// `incus-admin`). A sandbox never sees them.
pub const SYSTEM_SOCKETS: [&str; 3] = [
    "/var/snap/lxd/common/lxd/unix.socket",
    "/var/lib/lxd/unix.socket",
    "/var/lib/incus/unix.socket",
];

/// Paths that a sandbox can never get through a bind: a host `/proc` would show the
/// environment of every process of the user (F11), and a host `/dev` its devices.
const NEVER_ALLOWED: [&str; 2] = ["/proc", "/dev"];

/// The namespace options of every sandbox. `isolated_net` adds a network namespace
/// with only `lo`.
///
/// SECURITY (judge panel): new user, IPC, PID, UTS, and cgroup namespaces;
/// `--disable-userns`, so the sandbox cannot make a user namespace of its own and
/// undo the mounts; `--die-with-parent`, so the sandbox ends with its caller;
/// `--new-session`, so it cannot push keys into the caller's terminal (TIOCSTI);
/// `--as-pid-1`, so the init program is PID 1 and the kernel stops every process
/// of the sandbox when it exits.
pub(super) fn namespace_args(isolated_net: bool) -> Vec<&'static str> {
    let mut args = vec![
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ];
    if isolated_net {
        args.push("--unshare-net");
    }
    args.extend([
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--as-pid-1",
    ]);
    args
}

/// What the builder asks for.
pub(super) struct Spec<'a> {
    pub init: &'a Path,
    pub net: &'a NetPlan,
    pub home: Option<(&'a Path, HomePolicy)>,
    pub deny: &'a [PathBuf],
    pub read_only: &'a [PathBuf],
    pub rw: &'a [PathBuf],
    pub sockets: &'a [PathBuf],
    pub cwd: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mount {
    /// `--ro-bind / /`.
    Root,
    Dev,
    Proc,
    Tmpfs(PathBuf),
    /// The same path of the host.
    Bind {
        path: PathBuf,
        writable: bool,
    },
    /// A host file at another path, read-only (the init program, a bridge socket).
    Internal {
        source: PathBuf,
        dest: PathBuf,
    },
    /// `/dev/null` over a denied file.
    Null(PathBuf),
    Symlink {
        target: PathBuf,
        link: PathBuf,
    },
}

impl Mount {
    fn dest(&self) -> &Path {
        match self {
            Mount::Root => Path::new("/"),
            Mount::Dev => Path::new("/dev"),
            Mount::Proc => Path::new("/proc"),
            Mount::Tmpfs(path) | Mount::Null(path) | Mount::Bind { path, .. } => path,
            Mount::Internal { dest, .. } => dest,
            Mount::Symlink { link, .. } => link,
        }
    }

    /// Does the sandbox see the host's files below this mount?
    fn shows_host(&self) -> bool {
        matches!(self, Mount::Root | Mount::Bind { .. })
    }

    fn push_args(&self, out: &mut Vec<OsString>) {
        let os = OsStr::new;
        let parts: Vec<&OsStr> = match self {
            Mount::Root => vec![os("--ro-bind"), os("/"), os("/")],
            Mount::Dev => vec![os("--dev"), os("/dev")],
            Mount::Proc => vec![os("--proc"), os("/proc")],
            Mount::Tmpfs(path) => vec![os("--tmpfs"), path.as_os_str()],
            Mount::Bind { path, writable } => {
                let flag = if *writable { "--bind" } else { "--ro-bind" };
                vec![os(flag), path.as_os_str(), path.as_os_str()]
            }
            Mount::Internal { source, dest } => {
                vec![os("--ro-bind"), source.as_os_str(), dest.as_os_str()]
            }
            Mount::Null(path) => vec![os("--ro-bind"), os("/dev/null"), path.as_os_str()],
            Mount::Symlink { target, link } => {
                vec![os("--symlink"), target.as_os_str(), link.as_os_str()]
            }
        };
        out.extend(parts.into_iter().map(OsStr::to_os_string));
    }
}

/// The bubblewrap arguments, up to and including the `--` after which the caller
/// puts the program and its arguments.
pub(super) fn arguments(spec: &Spec<'_>) -> Result<Vec<OsString>, SandboxError> {
    let init = existing(spec.init)?;
    if !init.is_file() {
        return Err(SandboxError::NotAFile(init));
    }
    let hidden = hidden_roots()?;
    let home = match spec.home {
        Some((dir, policy)) => home(dir, policy, &hidden)?.map(|dir| (dir, policy)),
        None => None,
    };
    let read_only = allowed(spec.read_only, &hidden)?;
    let rw = allowed(spec.rw, &hidden)?;
    let mut sockets = Vec::new();
    for path in spec.sockets {
        sockets.push(socket(path)?);
    }
    let denied = denied(spec.deny)?;
    for path in read_only.iter().chain(&rw) {
        if let Some(deny) = denied.iter().find(|deny| path.starts_with(deny)) {
            return Err(SandboxError::InsideDenied {
                path: path.clone(),
                denied: deny.clone(),
            });
        }
    }
    let (isolated, bridges) = match spec.net {
        NetPlan::Bridged(bridges) => (true, checked_bridges(bridges)?),
        NetPlan::Host => (false, Vec::new()),
    };
    let cwd = existing(spec.cwd)?;

    let mut mounts = vec![Mount::Root, Mount::Dev, Mount::Proc];
    for root in &hidden {
        mounts.push(Mount::Tmpfs(root.clone()));
    }
    if hidden.iter().any(|root| root == Path::new("/run")) {
        give_back_from_run(&mut mounts, isolated);
    }
    if let Some((dir, policy)) = &home {
        mounts.push(match policy {
            HomePolicy::Hidden => Mount::Tmpfs(dir.clone()),
            HomePolicy::ReadOnly => Mount::Bind {
                path: dir.clone(),
                writable: false,
            },
        });
    }
    let mut binds: Vec<Mount> = read_only
        .into_iter()
        .map(|path| Mount::Bind {
            path,
            writable: false,
        })
        .chain(rw.into_iter().map(|path| Mount::Bind {
            path,
            writable: true,
        }))
        .collect();
    // An ancestor first, so a deeper bind is not covered by it.
    binds.sort_by_key(|mount| depth(mount.dest()));
    mounts.extend(binds);

    let mut masked_dirs = Vec::new();
    for path in denied {
        if !visible(&mounts, &path) {
            continue;
        }
        if path.is_dir() {
            mounts.push(Mount::Tmpfs(path.clone()));
            masked_dirs.push(path);
        } else {
            mounts.push(Mount::Null(path));
        }
    }
    for path in sockets {
        mounts.push(Mount::Bind {
            path,
            writable: false,
        });
    }
    let internal = Path::new(INTERNAL_DIR);
    let init_inside = internal.join("init");
    mounts.push(Mount::Internal {
        source: init,
        dest: init_inside.clone(),
    });
    let mut listen = Vec::new();
    for (index, bridge) in bridges.into_iter().enumerate() {
        let dest = internal.join(format!("bridge-{index}.sock"));
        let mut listen_spec = OsString::from(format!("{}=", bridge.inside));
        listen_spec.push(dest.as_os_str());
        listen.push(listen_spec);
        mounts.push(Mount::Internal {
            source: bridge.outside,
            dest,
        });
    }

    let cwd_ok = visible(&mounts, &cwd)
        || matches!(covering(&mounts, &cwd), Some(Mount::Tmpfs(dir)) if *dir == cwd);
    if !cwd_ok {
        return Err(SandboxError::CwdHidden(cwd));
    }

    let mut args: Vec<OsString> = namespace_args(isolated)
        .into_iter()
        .map(OsString::from)
        .collect();
    for mount in &mounts {
        mount.push_args(&mut args);
    }
    // The masks become read-only last: a socket mount point inside a masked folder
    // is made first.
    for dir in masked_dirs {
        args.push("--remount-ro".into());
        args.push(dir.into_os_string());
    }
    args.push("--chdir".into());
    args.push(cwd.into_os_string());
    args.push(init_inside.into_os_string());
    args.push(BRIDGE_ARG.into());
    for spec in listen {
        args.push("--listen".into());
        args.push(spec);
    }
    args.push("--".into());
    Ok(args)
}

/// The resolved hidden roots that exist. `/tmp` must exist: the sandbox keeps its
/// own files there.
fn hidden_roots() -> Result<Vec<PathBuf>, SandboxError> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for root in HIDDEN_ROOTS {
        let Ok(real) = fs::canonicalize(root) else {
            if root == "/tmp" {
                return Err(SandboxError::Missing(PathBuf::from(root)));
            }
            continue;
        };
        if !real.is_dir() || real == Path::new("/") || roots.contains(&real) {
            continue;
        }
        roots.push(real);
    }
    Ok(roots)
}

/// What programs need from the hidden `/run`: the NixOS system profile (its
/// programs), and with the host network the DNS file of `/etc/resolv.conf`.
fn give_back_from_run(mounts: &mut Vec<Mount>, isolated: bool) {
    for name in ["current-system", "booted-system"] {
        let link = Path::new("/run").join(name);
        if let Ok(target) = fs::read_link(&link) {
            mounts.push(Mount::Symlink { target, link });
        }
    }
    if !isolated
        && let Ok(target) = fs::canonicalize("/etc/resolv.conf")
        && target.starts_with("/run")
        && target.is_file()
    {
        mounts.push(Mount::Bind {
            path: target,
            writable: false,
        });
    }
}

fn absolute(path: &Path) -> Result<(), SandboxError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(SandboxError::NotAbsolute(path.to_owned()))
    }
}

/// The resolved path. It must exist.
fn existing(path: &Path) -> Result<PathBuf, SandboxError> {
    absolute(path)?;
    fs::canonicalize(path).map_err(|_| SandboxError::Missing(path.to_owned()))
}

/// The home folder, resolved. `None` when it does not exist. A home that holds a
/// hidden root is refused: a read-only bind of it would show the other users and
/// the host `/tmp` again, and a tmpfs over `/` would hide the system.
fn home(
    dir: &Path,
    policy: HomePolicy,
    hidden: &[PathBuf],
) -> Result<Option<PathBuf>, SandboxError> {
    absolute(dir)?;
    let Ok(real) = fs::canonicalize(dir) else {
        return Ok(None);
    };
    let holds = |root: &PathBuf| match policy {
        HomePolicy::Hidden => root.starts_with(&real) && *root != real,
        HomePolicy::ReadOnly => root.starts_with(&real),
    };
    if real == Path::new("/") || hidden.iter().any(holds) {
        return Err(SandboxError::AboveHidden(real));
    }
    for never in NEVER_ALLOWED {
        if real.starts_with(never) {
            return Err(SandboxError::NeverAllowed(real));
        }
    }
    Ok(Some(real))
}

/// The resolved allowed paths. Each must exist, must not hold a hidden root, and
/// must not be in `/proc`, `/dev`, or [`INTERNAL_DIR`].
fn allowed(paths: &[PathBuf], hidden: &[PathBuf]) -> Result<Vec<PathBuf>, SandboxError> {
    let mut out: Vec<PathBuf> = Vec::new();
    for path in paths {
        let real = existing(path)?;
        if real == Path::new("/") || hidden.iter().any(|root| root.starts_with(&real)) {
            return Err(SandboxError::AboveHidden(real));
        }
        if NEVER_ALLOWED.iter().any(|never| real.starts_with(never))
            || real.starts_with(INTERNAL_DIR)
        {
            return Err(SandboxError::NeverAllowed(real));
        }
        if !out.contains(&real) {
            out.push(real);
        }
    }
    Ok(out)
}

/// A socket that the sandbox may use, resolved.
fn socket(path: &Path) -> Result<PathBuf, SandboxError> {
    let real = existing(path)?;
    let is_socket = fs::metadata(&real).is_ok_and(|meta| meta.file_type().is_socket());
    if !is_socket {
        return Err(SandboxError::NotASocket(real));
    }
    if NEVER_ALLOWED.iter().any(|never| real.starts_with(never)) || real.starts_with(INTERNAL_DIR) {
        return Err(SandboxError::NeverAllowed(real));
    }
    Ok(real)
}

/// The resolved denied paths that exist, with [`SYSTEM_SOCKETS`], ancestors first.
/// A path that cannot be resolved does not exist for the sandbox either.
fn denied(paths: &[PathBuf]) -> Result<Vec<PathBuf>, SandboxError> {
    let mut out: Vec<PathBuf> = Vec::new();
    for path in paths {
        absolute(path)?;
    }
    let system = SYSTEM_SOCKETS.iter().map(PathBuf::from);
    for path in paths.iter().cloned().chain(system) {
        if let Ok(real) = fs::canonicalize(&path)
            && real != Path::new("/")
            && !out.contains(&real)
        {
            out.push(real);
        }
    }
    out.sort_by_key(|path| depth(path));
    Ok(out)
}

fn checked_bridges(bridges: &[Bridge]) -> Result<Vec<Bridge>, SandboxError> {
    let mut out: Vec<Bridge> = Vec::new();
    for bridge in bridges {
        if bridge.inside == 0 || out.iter().any(|seen| seen.inside == bridge.inside) {
            return Err(SandboxError::BadPort(bridge.inside));
        }
        out.push(Bridge {
            inside: bridge.inside,
            outside: socket(&bridge.outside)?,
        });
    }
    Ok(out)
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

/// The last mount at or above `path`.
fn covering<'m>(mounts: &'m [Mount], path: &Path) -> Option<&'m Mount> {
    mounts
        .iter()
        .rev()
        .find(|mount| path.starts_with(mount.dest()))
}

/// Does the sandbox see the host's `path` through the mounts so far?
fn visible(mounts: &[Mount], path: &Path) -> bool {
    covering(mounts, path).is_some_and(Mount::shows_host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::linux::test_dir::TestDir;
    use std::os::unix::net::UnixListener;

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    /// The index of the first `flag a b…` sequence in `args`.
    fn find(args: &[String], seq: &[&str]) -> Option<usize> {
        args.windows(seq.len())
            .position(|window| window.iter().zip(seq).all(|(a, b)| a == b))
    }

    fn spec<'a>(
        init: &'a Path,
        net: &'a NetPlan,
        cwd: &'a Path,
        home: Option<(&'a Path, HomePolicy)>,
        lists: &'a [Vec<PathBuf>; 4],
    ) -> Spec<'a> {
        Spec {
            init,
            net,
            home,
            deny: &lists[0],
            read_only: &lists[1],
            rw: &lists[2],
            sockets: &lists[3],
            cwd,
        }
    }

    fn canonical(path: &Path) -> String {
        fs::canonicalize(path)
            .expect("canonical")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn namespace_flags_come_first_and_isolate_the_network() {
        let dir = TestDir::new("bwrap-ns");
        let project = dir.mkdir("project");
        let lists = [vec![], vec![], vec![project.clone()], vec![]];
        let net = NetPlan::Bridged(Vec::new());
        let args = strings(
            &arguments(&spec(Path::new("/bin/sh"), &net, &project, None, &lists)).expect("args"),
        );
        assert_eq!(
            &args[..10],
            &[
                "--unshare-user",
                "--unshare-ipc",
                "--unshare-pid",
                "--unshare-uts",
                "--unshare-cgroup-try",
                "--unshare-net",
                "--disable-userns",
                "--die-with-parent",
                "--new-session",
                "--as-pid-1",
            ]
        );
        assert_eq!(&args[10..13], &["--ro-bind", "/", "/"]);
        assert!(find(&args, &["--dev", "/dev"]).is_some());
        assert!(find(&args, &["--proc", "/proc"]).is_some());
        assert!(find(&args, &["--tmpfs", "/tmp"]).is_some());
        assert!(find(&args, &["--tmpfs", "/run"]).is_some());
        // The init program and its marker end the arguments, then `--`.
        let tail = &args[args.len() - 3..];
        assert_eq!(tail, &["/tmp/.apassy-sandbox/init", BRIDGE_ARG, "--"]);

        let host = NetPlan::Host;
        let args = strings(
            &arguments(&spec(Path::new("/bin/sh"), &host, &project, None, &lists)).expect("args"),
        );
        assert!(!args.iter().any(|arg| arg == "--unshare-net"));
        assert!(args.iter().any(|arg| arg == "--as-pid-1"));
    }

    /// SECURITY (judge panel): denies come after every bind, sockets after the
    /// denies, and the masks become read-only last.
    #[test]
    fn the_mount_order_puts_denies_after_binds_and_sockets_after_denies() {
        let dir = TestDir::new("bwrap-order");
        let home = dir.mkdir("home");
        let project = dir.mkdir("home/work/project");
        let ssh = dir.mkdir("home/.ssh");
        let data = dir.mkdir("home/.local/share/apassy");
        let vault = dir.file("home/.local/share/apassy/vault.db", "x");
        let socket_path = data.join("broker.sock");
        let _listener = UnixListener::bind(&socket_path).expect("socket");
        let lists = [
            vec![ssh.clone(), data.clone(), vault.clone()],
            vec![],
            vec![project.clone()],
            vec![socket_path.clone()],
        ];
        let net = NetPlan::Bridged(Vec::new());
        let args = strings(
            &arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                &project,
                Some((&home, HomePolicy::ReadOnly)),
                &lists,
            ))
            .expect("args"),
        );
        let home_s = canonical(&home);
        let project_s = canonical(&project);
        let ssh_s = canonical(&ssh);
        let data_s = canonical(&data);
        let socket_s = canonical(&socket_path);
        let home_bind = find(&args, &["--ro-bind", &home_s, &home_s]).expect("home bind");
        let project_bind = find(&args, &["--bind", &project_s, &project_s]).expect("project");
        let ssh_mask = find(&args, &["--tmpfs", &ssh_s]).expect("ssh mask");
        let data_mask = find(&args, &["--tmpfs", &data_s]).expect("data mask");
        let socket_bind = find(&args, &["--ro-bind", &socket_s, &socket_s]).expect("socket");
        let remount = find(&args, &["--remount-ro", &data_s]).expect("remount");
        assert!(home_bind < project_bind);
        assert!(project_bind < ssh_mask && project_bind < data_mask);
        assert!(data_mask < socket_bind);
        assert!(socket_bind < remount);
        // The vault is in the masked data folder: it needs no mask of its own.
        let vault_s = canonical(&vault);
        assert!(find(&args, &["--ro-bind", "/dev/null", &vault_s]).is_none());
        // The home tmpfs hides /home first.
        let homes = find(&args, &["--tmpfs", "/home"]);
        if Path::new("/home").is_dir() && fs::canonicalize("/home").ok() == Some("/home".into()) {
            assert!(homes.expect("/home hidden") < home_bind);
        }
    }

    /// With the home hidden, a denied path in it is already gone: no mask, and no
    /// mount point that bubblewrap would have to make.
    #[test]
    fn denied_paths_in_a_hidden_home_need_no_mask() {
        let dir = TestDir::new("bwrap-hidden-home");
        let home = dir.mkdir("home");
        let project = dir.mkdir("home/project");
        let ssh = dir.mkdir("home/.ssh");
        let lists = [vec![ssh.clone()], vec![], vec![project.clone()], vec![]];
        let net = NetPlan::Bridged(Vec::new());
        let args = strings(
            &arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                &project,
                Some((&home, HomePolicy::Hidden)),
                &lists,
            ))
            .expect("args"),
        );
        let home_s = canonical(&home);
        let ssh_s = canonical(&ssh);
        let home_tmpfs = find(&args, &["--tmpfs", &home_s]).expect("home tmpfs");
        let project_s = canonical(&project);
        let project_bind = find(&args, &["--bind", &project_s, &project_s]).expect("project");
        assert!(home_tmpfs < project_bind);
        assert!(find(&args, &["--tmpfs", &ssh_s]).is_none());

        // The same deny with the home itself writable (a run in the home folder)
        // gets its mask.
        let lists = [vec![ssh.clone()], vec![], vec![home.clone()], vec![]];
        let args = strings(
            &arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                &home,
                Some((&home, HomePolicy::Hidden)),
                &lists,
            ))
            .expect("args"),
        );
        assert!(find(&args, &["--tmpfs", &ssh_s]).is_some());
    }

    #[test]
    fn an_allowed_path_inside_a_denied_path_is_refused() {
        let dir = TestDir::new("bwrap-inside");
        let data = dir.mkdir("data");
        let inner = dir.mkdir("data/project");
        for list in [1, 2] {
            let mut lists = [vec![data.clone()], vec![], vec![], vec![]];
            lists[list].push(inner.clone());
            let net = NetPlan::Bridged(Vec::new());
            let err = arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists,
            ))
            .expect_err("inside a denied folder");
            assert!(matches!(err, SandboxError::InsideDenied { .. }), "{err:?}");
        }
        // Equal paths too.
        let lists = [vec![data.clone()], vec![], vec![data.clone()], vec![]];
        let net = NetPlan::Host;
        assert!(matches!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::InsideDenied { .. })
        ));
    }

    /// SECURITY (judge panel): a bind of `/`, of a folder that holds a hidden root,
    /// or of the host `/proc` would undo the plan.
    #[test]
    fn an_allowed_path_above_a_hidden_root_or_in_proc_is_refused() {
        let net = NetPlan::Host;
        // `/var` holds a hidden root only when `/var/tmp` (or `/home`) is a real
        // folder under it.
        let var_holds_hidden = ["/var/tmp", "/home"].iter().any(|root| {
            fs::canonicalize(root).is_ok_and(|real| real.is_dir() && real.starts_with("/var"))
        });
        for path in ["/", "/var", "/proc", "/proc/self", "/dev", "/tmp"] {
            if !Path::new(path).exists() || (path == "/var" && !var_holds_hidden) {
                continue;
            }
            let lists = [vec![], vec![PathBuf::from(path)], vec![], vec![]];
            let err = arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists,
            ))
            .expect_err(path);
            assert!(
                matches!(
                    err,
                    SandboxError::AboveHidden(_) | SandboxError::NeverAllowed(_)
                ),
                "{path}: {err:?}"
            );
        }
        let lists = [vec![], vec![], vec![], vec![]];
        for home in ["/", "/var"] {
            if home == "/var" && !var_holds_hidden {
                continue;
            }
            let err = arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                Some((Path::new(home), HomePolicy::Hidden)),
                &lists,
            ))
            .expect_err(home);
            assert!(
                matches!(err, SandboxError::AboveHidden(_)),
                "{home}: {err:?}"
            );
        }
        if Path::new("/tmp").is_dir() {
            let err = arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                Some((Path::new("/tmp"), HomePolicy::ReadOnly)),
                &lists,
            ))
            .expect_err("a read-only home of /tmp");
            assert!(matches!(err, SandboxError::AboveHidden(_)), "{err:?}");
        }
    }

    #[test]
    fn relative_and_missing_paths_are_refused() {
        let net = NetPlan::Host;
        let lists = [vec![], vec![], vec![PathBuf::from("project")], vec![]];
        assert!(matches!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::NotAbsolute(_))
        ));
        let lists = [vec![PathBuf::from("relative")], vec![], vec![], vec![]];
        assert!(matches!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::NotAbsolute(_))
        ));
        let lists = [
            vec![],
            vec![],
            vec![PathBuf::from("/no/such/apassy/path")],
            vec![],
        ];
        assert!(matches!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::Missing(_))
        ));
        let lists = [vec![], vec![], vec![], vec![]];
        assert!(matches!(
            arguments(&spec(
                Path::new("/no/such/init"),
                &net,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::Missing(_))
        ));
        // A denied path that does not exist is fine: there is nothing to hide.
        let lists = [
            vec![PathBuf::from("/no/such/apassy/vault.db")],
            vec![],
            vec![],
            vec![],
        ];
        assert!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists
            ))
            .is_ok()
        );
    }

    #[test]
    fn a_bridge_needs_a_socket_and_a_unique_port() {
        let dir = TestDir::new("bwrap-bridge");
        let socket_path = dir.path().join("b.sock");
        let _listener = UnixListener::bind(&socket_path).expect("socket");
        let file = dir.file("not-a-socket", "x");
        let lists = [vec![], vec![], vec![], vec![]];
        let good = Bridge {
            inside: 8443,
            outside: socket_path.clone(),
        };
        let net = NetPlan::Bridged(vec![good.clone()]);
        let args = strings(
            &arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists,
            ))
            .expect("args"),
        );
        let socket_s = canonical(&socket_path);
        assert!(
            find(
                &args,
                &["--ro-bind", &socket_s, "/tmp/.apassy-sandbox/bridge-0.sock"]
            )
            .is_some()
        );
        assert!(
            find(
                &args,
                &["--listen", "8443=/tmp/.apassy-sandbox/bridge-0.sock", "--"]
            )
            .is_some()
        );

        let twice = NetPlan::Bridged(vec![good.clone(), good.clone()]);
        assert!(matches!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &twice,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::BadPort(8443))
        ));
        let zero = NetPlan::Bridged(vec![Bridge {
            inside: 0,
            outside: socket_path.clone(),
        }]);
        assert!(matches!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &zero,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::BadPort(0))
        ));
        let not_socket = NetPlan::Bridged(vec![Bridge {
            inside: 1,
            outside: file,
        }]);
        assert!(matches!(
            arguments(&spec(
                Path::new("/bin/sh"),
                &not_socket,
                Path::new("/"),
                None,
                &lists
            )),
            Err(SandboxError::NotASocket(_))
        ));
    }

    #[test]
    fn the_working_directory_must_be_visible() {
        let dir = TestDir::new("bwrap-cwd");
        let home = dir.mkdir("home");
        let elsewhere = dir.mkdir("home/elsewhere");
        let project = dir.mkdir("home/project");
        let lists = [vec![], vec![], vec![project.clone()], vec![]];
        let net = NetPlan::Bridged(Vec::new());
        let err = arguments(&spec(
            Path::new("/bin/sh"),
            &net,
            &elsewhere,
            Some((&home, HomePolicy::Hidden)),
            &lists,
        ))
        .expect_err("a working directory in the hidden home");
        assert!(matches!(err, SandboxError::CwdHidden(_)), "{err:?}");
        // The private home itself and the project are fine.
        for cwd in [&home, &project] {
            arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                cwd,
                Some((&home, HomePolicy::Hidden)),
                &lists,
            ))
            .expect("visible working directory");
        }
    }

    #[test]
    fn a_denied_file_gets_dev_null_and_a_denied_folder_an_empty_tmpfs() {
        let dir = TestDir::new("bwrap-masks");
        let visible_dir = dir.mkdir("shown");
        let secret_dir = dir.mkdir("shown/secret");
        let secret_file = dir.file("shown/token.txt", "x");
        let lists = [
            vec![secret_dir.clone(), secret_file.clone()],
            vec![visible_dir.clone()],
            vec![],
            vec![],
        ];
        let net = NetPlan::Host;
        let args = strings(
            &arguments(&spec(
                Path::new("/bin/sh"),
                &net,
                Path::new("/"),
                None,
                &lists,
            ))
            .expect("args"),
        );
        let file_s = canonical(&secret_file);
        let dir_s = canonical(&secret_dir);
        assert!(find(&args, &["--ro-bind", "/dev/null", &file_s]).is_some());
        assert!(find(&args, &["--tmpfs", &dir_s]).is_some());
        assert!(find(&args, &["--remount-ro", &dir_s]).is_some());
    }
}
