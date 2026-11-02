//! The team CLI and the stdio MCP adapter of the relay.
#![forbid(unsafe_code)]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(apassy_relay::cli::main(args));
}
