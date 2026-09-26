//! Native desktop entry for Apassy.
//!
//! This binary is a demo shell. It does not read or print secrets.

use rustix::process::{Resource, Rlimit, setrlimit};

fn main() -> eframe::Result {
    // Key-memory review F6: a core file would contain the vault memory. The hard
    // limit is 0 too, so a parent shell or a later call cannot raise it.
    if disable_core_dumps().is_err() {
        eprintln!("Apassy cannot turn off core dumps, so it does not start.");
        std::process::exit(1);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return apassy::desktop::run();
    }
    if args.len() == 1 && args[0] == "--smoke-test" {
        match apassy::desktop::smoke_test() {
            Ok(()) => {
                eprintln!(
                    "smoke-test: desktop model check passed. This check does not open a window."
                );
                #[cfg(feature = "vault")]
                eprintln!(
                    "smoke-test: owner vault round trip passed. No real credentials were used."
                );
                return Ok(());
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
    eprintln!("Unknown option. Permitted options: --smoke-test, --notify-check STEP");
    std::process::exit(2);
}

/// Set the soft and the hard core file size limit to 0. Child processes, such as
/// agent commands with secrets, get the same limit.
fn disable_core_dumps() -> rustix::io::Result<()> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::getrlimit;

    #[test]
    fn core_dump_limit_is_zero_and_cannot_be_raised() {
        disable_core_dumps().expect("set the core limit");
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
}
