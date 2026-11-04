//! The main executable of Apassy, built as `apassy-app` and installed as `apassy`.
//!
//! - macOS (feature `window`, the app bundle's `Contents/MacOS/apassy`): without
//!   arguments, it opens the window; with a command, it is the `apassy` owner command
//!   line (ADR 0017) and talks to the running window over the owner socket. It never
//!   prints a secret value of an item. The window runs the Mac's own node for cloud
//!   agents (ADR 0037): this binary passes the embedded relay of this workspace in.
//! - Linux (feature `node`; the package builds `--no-default-features --features node`):
//!   the node without a window, `apassy serve`, `up`, `pair`, `status`, `doctor`, and
//!   `team` (plan S2-S3, D8; `apassy_relay::node`).
//!
//! `serve`, `up`, `pair`, and `team` are node commands everywhere. `status` and `doctor`
//! are node commands on Linux and in a build without the window; on macOS they stay the
//! owner commands.

#[cfg(feature = "window")]
use std::sync::Arc;

#[cfg(feature = "window")]
use apassy::node::backend::NodeBackend;

// The same narrow diagnostics sink as the root `apassy` target.
#[cfg(feature = "window")]
#[path = "../../../src/owner_diagnostics.rs"]
mod owner_diagnostics;

/// True when `args` name a command of the node (`apassy_relay::node::main`).
fn is_node_command(args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("serve" | "up" | "pair" | "team") => true,
        Some("status" | "doctor") => cfg!(target_os = "linux") || !cfg!(feature = "window"),
        // Without the window there is no owner command line: the node prints its usage.
        _ => !cfg!(feature = "window"),
    }
}

fn main() {
    // Key-memory review F6 and ADR 0011 stage 6: no core file (it would contain the
    // vault memory; the hard limit is 0 too). First, before anything reads a secret.
    apassy::harden::harden_process_or_exit("apassy");
    let args: Vec<String> = std::env::args().skip(1).collect();
    if is_node_command(&args) {
        std::process::exit(apassy_relay::node::main(args));
    }
    #[cfg(feature = "window")]
    window_main(args);
}

#[cfg(feature = "window")]
fn window_main(args: Vec<String>) {
    owner_diagnostics::install();
    if args.is_empty() {
        if let Err(error) = apassy::desktop::run_with(desktop_options()) {
            eprintln!("apassy: the window stopped: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() == 1 && args[0] == "--smoke-test" {
        match apassy::desktop::smoke_test() {
            Ok(()) => {
                eprintln!(
                    "smoke-test: desktop model check passed. This check does not open a window."
                );
                eprintln!(
                    "smoke-test: owner vault round trip passed. No real credentials were used."
                );
                return;
            }
            Err(err) => {
                eprintln!("smoke-test failed: {err}");
                std::process::exit(1);
            }
        }
    }
    // Goal item N1: scripts/n1-check.sh runs the notifier through the signed app.
    if args.len() == 2 && args[0] == "--notify-check" {
        std::process::exit(apassy::native::check::run_notify_check(&args[1]));
    }
    // Every other argument list is a command of the owner command line.
    std::process::exit(apassy::cli::run(args));
}

/// The window with the Mac's own node: the relay of this workspace, in this process
/// (ADR 0037, cloud slice, decision 1).
#[cfg(feature = "window")]
fn desktop_options() -> apassy::desktop::RunOptions {
    let node: Arc<dyn NodeBackend> = Arc::new(apassy_relay::embedded::EmbeddedRelay::default());
    apassy::desktop::RunOptions { node: Some(node) }
}

// The shipped main executable hardens itself: its own copy of the check.
#[cfg(test)]
mod tests {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    use super::is_node_command;

    #[test]
    fn core_dump_limit_is_zero_and_cannot_be_raised() {
        apassy::harden::harden_process().expect("set the core limit");
        let limit = getrlimit(Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
        let raise = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(4096),
                maximum: Some(4096),
            },
        );
        assert!(raise.is_err());
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "ulimit -c; ulimit -H -c"])
            .output()
            .expect("run sh");
        assert_eq!(String::from_utf8_lossy(&child.stdout), "0\n0\n");
    }

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn node_commands_go_to_the_node() {
        for command in ["serve", "up --port 8444", "pair --json", "team me"] {
            assert!(is_node_command(&words(command)), "{command}");
        }
        let linux_or_headless = cfg!(target_os = "linux") || !cfg!(feature = "window");
        assert_eq!(is_node_command(&words("status --json")), linux_or_headless);
        assert_eq!(is_node_command(&words("doctor")), linux_or_headless);
        // The owner command line keeps its commands when the window is built in.
        assert_eq!(
            is_node_command(&words("items list")),
            !cfg!(feature = "window")
        );
        assert_eq!(is_node_command(&[]), !cfg!(feature = "window"));
    }
}
