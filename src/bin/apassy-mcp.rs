//! MCP stdio adapter for Apassy agents.
//!
//! Configure the agent host to start this program. Set `APASSY_AGENT_TOKEN` to
//! the token from the Apassy Agents view. `APASSY_BROKER_SOCKET` can change the
//! socket path. The adapter does not accept the token as an argument, because
//! other local processes can read process arguments.

fn main() {
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        if arg == "--version" {
            println!("apassy-mcp {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        eprintln!(
            "apassy-mcp takes no arguments. Use the APASSY_AGENT_TOKEN environment variable."
        );
        std::process::exit(2);
    }
    let config = apassy::agent::mcp::AdapterConfig::from_env();
    if config.token.is_none() {
        eprintln!("apassy-mcp: APASSY_AGENT_TOKEN is not set. Tool calls will fail.");
    }
    if let Err(err) = apassy::agent::mcp::run_stdio(&config) {
        eprintln!("apassy-mcp: stdio error: {err}");
        std::process::exit(1);
    }
}
