//! ADR 0011 stage 6 (plan P6): every binary that holds a secret value or a token calls
//! `harden_process` first in its `main`. A new binary has to be listed here, either as
//! a hardened one or as one that never holds a secret, so it is a decision and not an
//! accident.

use std::path::{Path, PathBuf};

/// Binaries that hold a secret value or a token: source file, and the call that must
/// be the first statement of `main`.
const HARDENED: &[(&str, &str)] = &[
    ("src/main.rs", "harden_process_or_exit("),
    ("crates/apassy-app/src/main.rs", "harden_process_or_exit("),
    ("src/bin/apassy-mcp.rs", "harden_process_or_exit("),
    // The hook always exits with 0, so a failure is a warning (see its `main`).
    ("src/bin/apassy-hook.rs", "harden_process()"),
    ("src/bin/apassy-sandbox.rs", "harden_process_or_exit("),
    ("src/bin/apassy-browser-host.rs", "harden_process_or_exit("),
    (
        "crates/apassy-relay/src/bin/apassy-relay.rs",
        "harden_process_or_exit(",
    ),
    (
        "crates/apassy-relay/src/bin/apassy-team.rs",
        "harden_process_or_exit(",
    ),
];

/// Binaries that never hold a secret: developer tools with synthetic data only.
const NOT_HARDENED: &[(&str, &str)] = &[
    (
        "src/bin/apassy-dev-reporting.rs",
        "sends a synthetic token to a mock service",
    ),
    (
        "src/bin/apassy-eval.rs",
        "runs a synthetic vault against a model; no command executes",
    ),
    (
        "src/bin/apassy-packs.rs",
        "checks rule packs; reads no credentials",
    ),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The first code line of `fn main` (comments and blank lines skipped), with the
/// lines of its statement up to the first line that ends with `;` or `{`.
fn first_statement_of_main(source: &str) -> String {
    let mut lines = source.lines();
    let found = lines.by_ref().any(|line| {
        let line = line.trim_start();
        line.starts_with("fn main(") && line.trim_end().ends_with('{')
    });
    assert!(found, "no one-line `fn main(...) {{` found");
    let mut statement = String::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        statement.push_str(line);
        statement.push(' ');
        if line.ends_with(';') || line.ends_with('{') {
            break;
        }
    }
    statement
}

#[test]
fn every_secret_handling_binary_hardens_the_process_first() {
    for (file, call) in HARDENED {
        let source = std::fs::read_to_string(root().join(file)).expect("read the binary source");
        let first = first_statement_of_main(&source);
        assert!(
            first.contains("apassy::harden::") && first.contains(call),
            "{file}: the first statement of `main` must call `apassy::harden::{call}` \
             (ADR 0011 stage 6), but it is: {first}"
        );
    }
}

/// Every `[[bin]]` of the root package and of the workspace crates is either hardened
/// or listed with the reason it holds no secret.
#[test]
fn every_binary_is_hardened_or_listed_as_without_secrets() {
    let mut manifests = vec![root().join("Cargo.toml")];
    for entry in std::fs::read_dir(root().join("crates")).expect("read crates/") {
        let manifest = entry.expect("crates/ entry").path().join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(manifest);
        }
    }
    let mut seen = 0;
    for manifest in manifests {
        let text = std::fs::read_to_string(&manifest).expect("read Cargo.toml");
        let base: &Path = manifest.parent().expect("manifest directory");
        let mut in_bin = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                in_bin = line == "[[bin]]";
                continue;
            }
            let Some(path) = line
                .strip_prefix("path = \"")
                .and_then(|rest| rest.strip_suffix('"'))
            else {
                continue;
            };
            if !in_bin {
                continue;
            }
            let relative = base
                .join(path)
                .strip_prefix(root())
                .expect("a binary inside the repository")
                .to_string_lossy()
                .replace('\\', "/");
            let listed = HARDENED.iter().any(|(file, _)| *file == relative)
                || NOT_HARDENED.iter().any(|(file, _)| *file == relative);
            assert!(
                listed,
                "{relative} is a binary that tests/harden.rs does not list: call \
                 `apassy::harden::harden_process` first in its `main`, or list it \
                 as a binary without secrets"
            );
            seen += 1;
        }
    }
    assert_eq!(seen, HARDENED.len() + NOT_HARDENED.len());
}

#[test]
fn the_list_of_binaries_without_secrets_has_no_stale_entry() {
    for (file, reason) in NOT_HARDENED {
        assert!(!reason.is_empty());
        assert!(
            root().join(file).is_file(),
            "{file} is gone: update the list"
        );
    }
}
