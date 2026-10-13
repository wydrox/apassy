//! All integration tests in one test program.
//!
//! Each `tests/<name>.rs` file is a module here, so one program links the crate and
//! its dependencies once (a separate program per file filled target/ with copies).
//! Run one area with a module filter: `cargo test --test it companion::`.
//! `Cargo.toml` sets `autotests = false`: a new file under `tests/` runs only after
//! a `mod` line here (`layout::every_test_file_is_a_module` checks it).
//!
//! Each module keeps the feature gate of its file (`#![cfg(...)]` in the file, or on
//! the `mod` line below). The tests run in parallel threads of one process: a test
//! that changes process-wide state runs in a child process of this program
//! (`rule_packs::a_rejected_local_directory_fails_closed`).

mod common;

/// Helpers that several modules share.
mod support {
    #[cfg(feature = "vault")]
    pub mod companion;
    pub mod fake_native;
    #[cfg(feature = "vault")]
    pub mod zip_fixture;
}

mod access_model;
mod action_kind;
mod add_detected;
mod agent_items;
mod agent_path;
mod agent_run;
mod analysis_replay;
mod automatic_access;
mod bouncer_eval;
mod bouncer_rules;
mod browser_passkeys;
mod cli_ux;
mod companion;
mod companion_activity;
mod companion_owner;
mod companion_store;
mod contracts;
mod corrections;
mod declaration_suggestions;
mod desktop_model;
mod detect;
mod exceptions;
mod first_use;
mod folder_sync;
mod host_coverage;
mod host_hook;
#[path = "isolation/product_profile.rs"]
mod isolation_profile;
mod item_history;
mod learning;
mod learning_replay;
mod local_finetune;
mod native_auth_cancel;
mod native_helper;
mod notifications;
#[cfg(feature = "vault")]
mod onepassword_import;
mod otp_agent_boundary;
mod owner_answers;
mod owner_auth;
mod owner_vault;
mod passkey_conflict_recovery;
mod passkey_export;
mod passkeys;
mod project_key;
mod provider_hosts;
mod relay_feed;
mod relay_questions;
mod relay_sync;
mod rule_packs;
mod run_proxy;
mod shadow_mode;
#[cfg(feature = "storage-probe")]
mod sqlcipher_probe;
mod sync_schema_upgrade;
mod trusted_devices;
mod vault_lifecycle;
mod vault_migration;
#[cfg(feature = "vault")]
mod vault_passphrase;
mod waiting_restart;

mod layout {
    use std::path::Path;

    /// With `autotests = false`, a `tests/*.rs` file without a `mod` line in this
    /// program would not build and would not run.
    #[test]
    fn every_test_file_is_a_module() {
        let root = include_str!("it.rs");
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("read tests/") {
            let path = entry.expect("tests/ entry").path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .expect("file name");
            if stem == "it" {
                continue;
            }
            assert!(
                root.lines().any(|line| line == format!("mod {stem};")),
                "tests/{stem}.rs is not a module of tests/it.rs, so it does not run"
            );
            checked += 1;
        }
        assert!(checked > 0, "no test files in {}", dir.display());
    }
}
