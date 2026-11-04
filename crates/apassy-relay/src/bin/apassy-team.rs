//! The team CLI and the stdio MCP adapter of the relay.
//!
//! On Linux this name is an alias of `apassy team` for one release (plan S2-S3, D8): it
//! runs the same commands and prints one deprecation line to stderr when stderr is a
//! terminal (or `APASSY_TEAM_DEPRECATION=1`), so scripts, services, and MCP clients
//! that read stderr see no change.
#![forbid(unsafe_code)]

use std::io::IsTerminal;

fn main() {
    // ADR 0011 stage 6: first, before anything reads a secret.
    apassy::harden::harden_process_or_exit("apassy-team");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let forced = std::env::var_os(apassy_relay::node::team::DEPRECATION_ENV)
        .is_some_and(|value| value == "1");
    if forced || (cfg!(target_os = "linux") && std::io::stderr().is_terminal()) {
        eprintln!("{}", apassy_relay::node::team::DEPRECATION_LINE);
    }
    std::process::exit(apassy_relay::cli::main(args));
}
