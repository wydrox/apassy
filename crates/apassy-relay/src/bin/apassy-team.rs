//! The team CLI and the stdio MCP adapter of the relay.
#![forbid(unsafe_code)]

fn main() {
    // ADR 0011 stage 6: first, before anything reads a secret.
    apassy::harden::harden_process_or_exit("apassy-team");
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(apassy_relay::cli::main(args));
}
