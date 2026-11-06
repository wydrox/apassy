//! Native desktop entry for Apassy, and the `apassy` owner command line (ADR 0017).
//!
//! Without arguments, it opens the window. With a command, it talks to the running
//! window over the owner socket. It never prints a secret value of an item.

mod owner_diagnostics;

fn main() -> eframe::Result {
    // Key-memory review F6 and ADR 0011 stage 6: no core file (it would contain the
    // vault memory; the hard limit is 0 too) and, on Linux, not dumpable. First.
    apassy::harden::harden_process_or_exit("apassy");
    owner_diagnostics::install();
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
    // Every other argument list is a command of the owner command line.
    std::process::exit(apassy::cli::run(args));
}
