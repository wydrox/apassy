//! Scope a remembered permission to evaluate an uncertain command again.
//!
//! This binds argv, the working directory, executable resolution, and directly named
//! project script bytes. It does not bind transitive imports, sourced files, other
//! external dependencies, or an executable's future behavior. It authorizes evaluation
//! only; it is not permission to execute the command.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ring::digest::{Context, SHA256};

const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Certain action kinds use action and host scope only when the resolved program
/// is a trusted system native executable. Other commands need an exact binding,
/// or a fresh permission if their source cannot be identified conservatively.
///
/// `path` is the PATH snapshot used to resolve the command; no shell is invoked.
pub(super) fn command_binding(
    command: &[String],
    cwd: &Path,
    project: &Path,
    certain: bool,
    path: Option<&str>,
) -> Result<Option<String>, String> {
    let program = command
        .first()
        .filter(|arg| !arg.is_empty())
        .ok_or_else(|| {
            "An empty command cannot have a remembered evaluation permission.".to_owned()
        })?;
    let cwd = canonical_directory(cwd)?;
    let project = canonical_directory(project)?;
    let executable = resolve_program(program, &cwd, path)?;
    let requested = cwd.join(program);
    if program.contains('/') && requested.starts_with(&project) && !executable.starts_with(&project)
    {
        return Err(
            "A project executable escapes the project through its path or a symlink.".to_owned(),
        );
    }
    let name = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("The executable name cannot be bound.")?;
    let resolved_name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("The resolved executable name cannot be bound.")?;
    if project_runner(name)
        || project_runner(resolved_name)
        || [name, resolved_name]
            .iter()
            .any(|name| name.starts_with("python") && interpreter(name).is_none())
    {
        return Err("A project runner needs a fresh evaluation permission.".to_owned());
    }
    let selected_interpreter = interpreter(name).or_else(|| interpreter(resolved_name));
    let project_local = executable.starts_with(&project);
    if project_local {
        // A native executable can be a renamed interpreter whose argument is its
        // real source. Hashing only that binary would omit the selected script.
        if selected_interpreter.is_some() || native_executable(&executable)? {
            return Err("A project-local native program or interpreter needs a fresh evaluation permission.".to_owned());
        }
    } else if selected_interpreter.is_none()
        && (!known_native_tool(name) || !known_native_tool(resolved_name))
    {
        return Err(
            "Unknown native command semantics need a fresh evaluation permission.".to_owned(),
        );
    }

    // Classification by the command's spelling cannot vouch for PATH wrappers.
    // Resolve first, and never let a project executable inherit a generic action
    // permission merely because it is named git, curl, or another known command.
    if certain
        && !project_local
        && name == resolved_name
        && selected_interpreter.is_none()
        && trusted_system_location(&executable)
        && native_executable(&executable)?
    {
        return Ok(None);
    }

    let mut digest = Context::new(&SHA256);
    field(&mut digest, b"apassy-evaluation-binding-v1");
    field(&mut digest, &(command.len() as u64).to_le_bytes());
    for arg in command {
        field(&mut digest, arg.as_bytes());
    }
    path_field(&mut digest, &cwd);
    path_field(&mut digest, &project);
    field(
        &mut digest,
        if path.is_some() {
            b"PATH=set"
        } else {
            b"PATH=default"
        },
    );
    field(&mut digest, path.unwrap_or(DEFAULT_PATH).as_bytes());
    path_field(&mut digest, &executable);

    if project_local {
        bind_script(&mut digest, &executable, &project)?;
    } else {
        if !normal_program_location(&executable) {
            return Err(
                "An executable outside the project or a normal program directory cannot be bound."
                    .to_owned(),
            );
        }
        if script_extension(&executable) || !native_executable(&executable)? {
            return Err(
                "An external script cannot have a remembered evaluation permission.".to_owned(),
            );
        }
        if let Some(kind) = selected_interpreter {
            bind_interpreter(&mut digest, kind, &command[1..], &cwd, &project)?;
        }
    }

    let result = digest.finish();
    let hex: String = result
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(Some(format!("sha256:{hex}")))
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|_| "The evaluation directory cannot be resolved.".to_owned())?;
    if !canonical.is_dir() {
        return Err("The evaluation directory is not a directory.".to_owned());
    }
    Ok(canonical)
}

fn resolve_program(program: &str, cwd: &Path, path: Option<&str>) -> Result<PathBuf, String> {
    let given = Path::new(program);
    let candidate = if program.contains('/') {
        if given.is_absolute() {
            given.to_owned()
        } else {
            cwd.join(given)
        }
    } else {
        let dirs: Vec<_> = std::env::split_paths(path.unwrap_or(DEFAULT_PATH)).collect();
        // Empty/relative entries depend on working-directory lookup rules. Refuse
        // them even when an earlier entry happens to contain this program.
        if dirs.iter().any(|dir| !dir.is_absolute()) {
            return Err(
                "A relative PATH entry cannot have a remembered evaluation permission.".to_owned(),
            );
        }
        dirs.iter()
            .map(|dir| dir.join(given))
            .find(|candidate| {
                fs::metadata(candidate)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
            .ok_or("The command cannot be resolved in PATH.")?
    };
    let canonical =
        fs::canonicalize(candidate).map_err(|_| "The executable cannot be resolved.".to_owned())?;
    let metadata =
        fs::metadata(&canonical).map_err(|_| "The executable cannot be inspected.".to_owned())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("The command is not a regular executable file.".to_owned());
    }
    Ok(canonical)
}

fn normal_program_location(path: &Path) -> bool {
    [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local",
        "/opt/homebrew",
    ]
    .iter()
    .any(|root| path.starts_with(root))
}

fn trusted_system_location(path: &Path) -> bool {
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        .iter()
        .any(|root| path.parent() == Some(Path::new(root)))
}

/// These tools do not treat a positional argument as a local source script.
/// Exclude language processors (awk, jq, sed), SQL clients and generic runners:
/// accepting an unknown native executable could accept a renamed interpreter.
/// Tool configuration, plugins and hooks remain transitive dependencies, which
/// this evaluation-only binding deliberately does not attest.
fn known_native_tool(name: &str) -> bool {
    matches!(
        name,
        "echo"
            | "printf"
            | "true"
            | "false"
            | "cat"
            | "head"
            | "tail"
            | "wc"
            | "sort"
            | "uniq"
            | "cut"
            | "tr"
            | "tee"
            | "cp"
            | "mv"
            | "mkdir"
            | "rmdir"
            | "rm"
            | "touch"
            | "chmod"
            | "chown"
            | "ls"
            | "git"
            | "gh"
            | "glab"
            | "curl"
            | "wget"
            | "kubectl"
            | "helm"
            | "aws"
            | "gcloud"
            | "az"
            | "terraform"
            | "tofu"
            | "docker"
            | "podman"
    )
}

#[derive(Clone, Copy)]
enum Interpreter {
    Shell,
    Python,
    Node,
}

fn interpreter(name: &str) -> Option<Interpreter> {
    match name {
        "sh" | "bash" | "dash" => Some(Interpreter::Shell),
        "python" | "python3" => Some(Interpreter::Python),
        name if name.strip_prefix("python3.").is_some_and(|version| {
            !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
        }) =>
        {
            Some(Interpreter::Python)
        }
        "pypy" | "pypy3" => Some(Interpreter::Python),
        "node" | "nodejs" => Some(Interpreter::Node),
        _ => None,
    }
}

/// Read only the directly invoked executable's magic, never its argument paths.
/// Extensionless external scripts and unknown formats need a fresh permission.
fn native_executable(path: &Path) -> Result<bool, String> {
    let mut file = File::open(path).map_err(|_| "The executable cannot be read.".to_owned())?;
    let mut magic = [0; 4];
    file.read_exact(&mut magic)
        .map_err(|_| "The executable format cannot be identified.".to_owned())?;
    Ok(matches!(
        magic,
        [0x7f, b'E', b'L', b'F'] // ELF
        | [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] // Mach-O 32
        | [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] // Mach-O 64
        | [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] // universal
        | [0xca, 0xfe, 0xba, 0xbf] | [0xbf, 0xba, 0xfe, 0xca]
    ))
}

fn bind_interpreter(
    digest: &mut Context,
    kind: Interpreter,
    arguments: &[String],
    cwd: &Path,
    project: &Path,
) -> Result<(), String> {
    let first = arguments
        .first()
        .ok_or("An interactive interpreter cannot be bound.")?;
    let inline = match kind {
        Interpreter::Shell | Interpreter::Python => first == "-c",
        Interpreter::Node => matches!(first.as_str(), "-e" | "--eval"),
    };
    if inline {
        if arguments.get(1).is_none() {
            return Err("The inline source is missing.".to_owned());
        }
        // All inline source and arguments were included in argv. Deliberately do
        // not inspect paths mentioned inside source, imports, or shell expressions.
        return Ok(());
    }
    let script = if first == "--" {
        arguments.get(1).ok_or("The script path is missing.")?
    } else {
        first
    };
    if script.starts_with('-') || script.is_empty() {
        return Err("Interpreter options, modules, and stdin sources cannot be bound.".to_owned());
    }
    bind_script(digest, &cwd.join(script), project)
}

fn bind_script(digest: &mut Context, path: &Path, project: &Path) -> Result<(), String> {
    let canonical =
        fs::canonicalize(path).map_err(|_| "The project script cannot be resolved.".to_owned())?;
    if !canonical.starts_with(project) {
        return Err("The script is outside the project, possibly through a symlink.".to_owned());
    }
    let metadata = fs::metadata(&canonical)
        .map_err(|_| "The project script cannot be inspected.".to_owned())?;
    if !metadata.is_file() || metadata.len() > MAX_SCRIPT_BYTES {
        return Err("The project script must be a regular file of at most 1 MiB.".to_owned());
    }
    if metadata.permissions().mode() & 0o444 == 0 {
        return Err("The project script is unreadable.".to_owned());
    }
    let file =
        File::open(&canonical).map_err(|_| "The project script cannot be read.".to_owned())?;
    let mut bytes = Vec::new();
    file.take(MAX_SCRIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "The project script cannot be read.".to_owned())?;
    if bytes.len() as u64 > MAX_SCRIPT_BYTES {
        return Err("The project script exceeds 1 MiB.".to_owned());
    }
    path_field(digest, &canonical);
    field(digest, &bytes);
    Ok(())
}

fn script_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("sh" | "bash" | "zsh" | "py" | "js" | "mjs" | "cjs")
    )
}

fn project_runner(name: &str) -> bool {
    matches!(
        name,
        "npm"
            | "npx"
            | "pnpm"
            | "yarn"
            | "bun"
            | "deno"
            | "make"
            | "gmake"
            | "cmake"
            | "ninja"
            | "cargo"
            | "rustc"
            | "go"
            | "gradle"
            | "gradlew"
            | "mvn"
            | "dotnet"
            | "just"
            | "task"
            | "rake"
            | "uv"
            | "poetry"
            | "pipenv"
            | "composer"
            | "ruby"
            | "perl"
            | "php"
            | "zsh"
            | "fish"
            | "env"
            | "ash"
            | "ksh"
            | "csh"
            | "tcsh"
    )
}

fn field(digest: &mut Context, bytes: &[u8]) {
    digest.update(&(bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn path_field(digest: &mut Context, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    field(digest, path.as_os_str().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn args(command: &[&str]) -> Vec<String> {
        command.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn bind(command: &[&str], root: &Path) -> Result<Option<String>, String> {
        command_binding(&args(command), root, root, false, Some(DEFAULT_PATH))
    }

    fn script(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn certain_system_native_commands_use_action_scope_after_resolution() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            command_binding(
                &args(&["echo", "status"]),
                root.path(),
                root.path(),
                true,
                Some(DEFAULT_PATH)
            ),
            Ok(None)
        );
        assert!(command_binding(&[], root.path(), root.path(), true, None).is_err());
    }

    #[test]
    fn certain_project_git_binds_bytes_and_does_not_inherit_system_scope() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        let file = root.path().join("bin/git");
        script(&file, "#!/bin/sh\necho first\n");
        let path = format!("{}:{DEFAULT_PATH}", root.path().join("bin").display());
        let command = args(&["git", "status"]);
        let first = command_binding(&command, root.path(), root.path(), true, Some(&path)).unwrap();
        assert!(first.is_some());
        script(&file, "#!/bin/sh\necho second\n");
        let edited =
            command_binding(&command, root.path(), root.path(), true, Some(&path)).unwrap();
        assert_ne!(first, edited);

        // Same command spelling and certainty, but normal PATH must not match
        // either project script's exact binding.
        let system =
            command_binding(&command, root.path(), root.path(), true, Some(DEFAULT_PATH)).unwrap();
        assert_eq!(system, None);
        assert_ne!(system, first);
        assert_ne!(system, edited);
    }

    #[test]
    fn certain_project_git_path_and_symlink_changes_invalidate_binding() {
        let root = tempfile::tempdir().unwrap();
        let first_dir = root.path().join("first");
        let second_dir = root.path().join("second");
        fs::create_dir(&first_dir).unwrap();
        fs::create_dir(&second_dir).unwrap();
        script(&first_dir.join("git"), "#!/bin/sh\necho same\n");
        script(&second_dir.join("git"), "#!/bin/sh\necho same\n");
        let command = args(&["git", "status"]);
        let binding = |path: &str| {
            command_binding(&command, root.path(), root.path(), true, Some(path)).unwrap()
        };
        let first_path = first_dir.to_str().unwrap();
        let second_path = second_dir.to_str().unwrap();
        assert_ne!(binding(first_path), binding(second_path));

        let link = root.path().join("current");
        symlink(&first_dir, &link).unwrap();
        let linked_path = link.to_str().unwrap();
        let first = binding(linked_path);
        fs::remove_file(&link).unwrap();
        symlink(&second_dir, &link).unwrap();
        assert_ne!(first, binding(linked_path));
    }

    #[test]
    fn copied_or_renamed_native_interpreters_do_not_omit_script_source() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        script(&root.path().join("source.sh"), "echo first\n");
        for directory in [root.path(), outside.path()] {
            let runner = directory.join("script-runner");
            fs::copy("/bin/sh", &runner).unwrap();
            fs::set_permissions(&runner, fs::Permissions::from_mode(0o700)).unwrap();
            let command = args(&[runner.to_str().unwrap(), "source.sh"]);
            // The result is refusal, rather than a binary-only binding that
            // would survive a change to source.sh.
            assert!(command_binding(&command, root.path(), root.path(), false, None).is_err());
            assert!(command_binding(&command, root.path(), root.path(), true, None).is_err());
        }
    }

    #[test]
    fn project_native_interpreter_names_and_unknown_versions_are_refused() {
        let root = tempfile::tempdir().unwrap();
        script(&root.path().join("source.py"), "print(1)\n");
        for name in ["python3", "python3.14t", "python4.0"] {
            let program = root.path().join(name);
            fs::copy("/bin/sh", &program).unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(bind(&[program.to_str().unwrap(), "source.py"], root.path()).is_err());
        }
    }

    #[test]
    fn exact_argument_boundaries_cwd_and_path_affect_binding() {
        let root = tempfile::tempdir().unwrap();
        let first = bind(&["/bin/echo", "one", "two"], root.path()).unwrap();
        assert_ne!(first, bind(&["/bin/echo", "one two"], root.path()).unwrap());
        assert_eq!(
            first,
            bind(&["/bin/echo", "one", "two"], root.path()).unwrap()
        );
        let second = tempfile::tempdir().unwrap();
        assert_ne!(
            first,
            bind(&["/bin/echo", "one", "two"], second.path()).unwrap()
        );
        assert_ne!(
            first,
            command_binding(
                &args(&["/bin/echo", "one", "two"]),
                root.path(),
                root.path(),
                false,
                Some("/bin:/usr/bin")
            )
            .unwrap()
        );
    }

    #[test]
    fn direct_script_edits_invalidate_the_binding() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("scripts")).unwrap();
        let file = root.path().join("scripts/a.sh");
        script(&file, "#!/bin/sh\necho first\n");
        let first = bind(&["./scripts/a.sh"], root.path()).unwrap();
        script(&file, "#!/bin/sh\necho second\n");
        assert_ne!(first, bind(&["./scripts/a.sh"], root.path()).unwrap());
    }

    #[test]
    fn interpreter_script_edits_invalidate_the_binding() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("a.sh");
        script(&file, "echo first\n");
        let first = bind(&["/bin/sh", "a.sh"], root.path()).unwrap();
        script(&file, "echo second\n");
        assert_ne!(first, bind(&["/bin/sh", "a.sh"], root.path()).unwrap());
    }

    #[test]
    fn data_arguments_are_not_opened_or_hashed() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data.json");
        fs::write(&data, "first").unwrap();
        let first = bind(&["/bin/echo", "data.json"], root.path()).unwrap();
        fs::write(&data, "second").unwrap();
        assert_eq!(
            first,
            bind(&["/bin/echo", "data.json"], root.path()).unwrap()
        );
    }

    #[test]
    fn scripts_outside_project_or_through_escaping_symlinks_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let outside = external.path().join("a.sh");
        script(&outside, "echo outside\n");
        assert!(bind(&["/bin/sh", outside.to_str().unwrap()], root.path()).is_err());
        symlink(&outside, root.path().join("linked.sh")).unwrap();
        assert!(bind(&["./linked.sh"], root.path()).is_err());
        assert!(bind(&["/bin/sh", "linked.sh"], root.path()).is_err());
        symlink("/bin/echo", root.path().join("escaped-executable")).unwrap();
        assert!(bind(&["./escaped-executable"], root.path()).is_err());
    }

    #[test]
    fn unreadable_nonregular_and_large_scripts_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("a.sh");
        script(&file, "echo hidden\n");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o100)).unwrap();
        assert!(bind(&["/bin/sh", "a.sh"], root.path()).is_err());
        fs::create_dir(root.path().join("directory")).unwrap();
        assert!(bind(&["/bin/sh", "directory"], root.path()).is_err());
        fs::write(
            root.path().join("large.sh"),
            vec![0; MAX_SCRIPT_BYTES as usize + 1],
        )
        .unwrap();
        assert!(bind(&["/bin/sh", "large.sh"], root.path()).is_err());
    }

    #[test]
    fn inline_source_binds_argv_but_modules_and_runners_are_refused() {
        let root = tempfile::tempdir().unwrap();
        assert!(bind(&["/bin/sh", "-c", "echo first"], root.path()).is_ok());
        assert_ne!(
            bind(&["/bin/sh", "-c", "echo first"], root.path()).unwrap(),
            bind(&["/bin/sh", "-c", "echo second"], root.path()).unwrap()
        );
        // Use the pure interpreter helper so tests need neither Python nor Node.
        for (kind, inline) in [(Interpreter::Python, "-c"), (Interpreter::Node, "-e")] {
            assert!(
                bind_interpreter(
                    &mut Context::new(&SHA256),
                    kind,
                    &args(&[inline, "print(1)"]),
                    root.path(),
                    root.path()
                )
                .is_ok()
            );
            assert!(
                bind_interpreter(
                    &mut Context::new(&SHA256),
                    kind,
                    &args(&["-m", "package"]),
                    root.path(),
                    root.path()
                )
                .is_err()
            );
        }
        assert!(project_runner("npm"));
        assert!(project_runner("make"));
        assert!(project_runner("cargo"));
        assert!(
            command_binding(
                &args(&["echo", "hi"]),
                root.path(),
                root.path(),
                false,
                Some(".:/bin")
            )
            .is_err()
        );
    }
}
