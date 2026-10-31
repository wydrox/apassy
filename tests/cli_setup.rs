//! Terminal setup contracts, with a scratch HOME and synthetic tokens only.
#![cfg(all(feature = "desktop", feature = "vault"))]
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn setup(home: &Path, args: &[&str], token: Option<&str>, exit: i32) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_apassy"))
        .args(["--json", "setup", "codex"])
        .args(args)
        .env("HOME", home)
        .env("CODEX_HOME", home.join(".codex"))
        .env("APASSY_OWNER_SOCKET", home.join("absent.sock"))
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("APASSY_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(token) = token {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(token.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(exit),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], exit == 0);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("apassy_agt_synthetic_contract"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("apassy_agt_synthetic_contract"));
    result
}

#[test]
fn preview_preflight_and_retry_do_not_register_or_replace_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    setup(home, &[], None, 0);
    assert!(std::fs::read_dir(home).unwrap().next().is_none());
    std::fs::create_dir(home.join(".codex")).unwrap();
    let hooks = home.join(".codex/hooks.json");
    std::fs::write(&hooks, r#"{"disableAllHooks":true}"#).unwrap();
    let failure = setup(
        home,
        &["--write", "--token-stdin"],
        Some("apassy_agt_synthetic_contract"),
        1,
    );
    assert_eq!(failure["partial_state"]["partial"], false);
    assert!(!home.join(".config").exists());
    std::fs::write(&hooks, "{}").unwrap();
    setup(
        home,
        &["--write", "--token-stdin"],
        Some("apassy_agt_synthetic_contract"),
        0,
    );
    let wrapper = home.join(".config/apassy/apassy-mcp-codex.sh");
    let original = std::fs::read(&wrapper).unwrap();
    setup(home, &["--write"], None, 0);
    assert_eq!(std::fs::read(&wrapper).unwrap(), original);
    std::fs::write(&hooks, "not JSON").unwrap();
    setup(home, &["--write"], None, 1);
    assert_eq!(std::fs::read(&wrapper).unwrap(), original);
    std::fs::write(&hooks, "{}").unwrap();
    setup(home, &["--write"], None, 0);
    assert_eq!(std::fs::read(&wrapper).unwrap(), original);
}

#[test]
fn missing_app_is_one_json_document_with_exit_three_and_no_files_written() {
    let dir = tempfile::tempdir().unwrap();
    let failure = setup(dir.path(), &["--write"], None, 3);
    assert_eq!(failure["code"], "not_running");
    assert_eq!(failure["partial_state"]["partial"], false);
    assert_eq!(failure["partial_state"]["changes_unknown"], false);
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
}
