//! Process hardening for every Apassy binary that holds a secret value or a token
//! (ADR 0011 stage 6, plan P6).
//!
//! [`harden_process`] is the first call in the `main` of each such binary.
//! `tests/harden.rs` fails when one of them does not call it.
//!
//! - macOS and Linux: the core file size limit, soft and hard, is 0. A core file
//!   would contain the vault memory, and a parent shell or a later call cannot raise
//!   a hard limit of 0. Child processes, such as agent commands with secrets, get the
//!   same limit.
//! - Linux: `prctl(PR_SET_DUMPABLE, 0)`. A process that is not dumpable has its
//!   `/proc/<pid>/environ`, `mem`, and `ptrace` closed to the same user.
//! - macOS: the hardened runtime is already on for every binary (`scripts/build-app.sh`
//!   signs with `--options runtime` and fails when a binary has `get-task-allow`),
//!   so no further call is needed.

use std::io;

use rustix::process::{Resource, Rlimit, setrlimit};

/// Turn off core dumps, and on Linux turn off the dumpable attribute. Call it first
/// in `main`. On an error the caller must not go on: the binary handles secrets.
pub fn harden_process() -> io::Result<()> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    Ok(())
}

/// [`harden_process`] for a `main` that has nothing else to do on an error: print the
/// reason and exit with 1.
pub fn harden_process_or_exit(program: &str) {
    if let Err(err) = harden_process() {
        eprintln!("{program}: cannot harden the process ({err}), so it does not start.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::getrlimit;

    #[test]
    fn the_core_limit_is_zero() {
        harden_process().expect("harden the process");
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
        assert!(raise.is_err(), "a hard limit of 0 cannot be raised");
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "ulimit -c; ulimit -H -c"])
            .output()
            .expect("run sh");
        assert_eq!(String::from_utf8_lossy(&child.stdout), "0\n0\n");
    }

    #[test]
    fn hardening_twice_is_fine() {
        harden_process().expect("first call");
        harden_process().expect("second call");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_process_is_not_dumpable_on_linux() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};
        harden_process().expect("harden the process");
        assert_eq!(
            dumpable_behavior().expect("PR_GET_DUMPABLE"),
            DumpableBehavior::NotDumpable
        );
    }
}
