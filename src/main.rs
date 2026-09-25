//! Native desktop entry for Apassy.
//!
//! This binary is a demo shell. It does not read or print secrets.

fn main() -> eframe::Result {
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
    eprintln!("Unknown option. Permitted option: --smoke-test");
    std::process::exit(2);
}
