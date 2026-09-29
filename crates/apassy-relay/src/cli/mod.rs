//! Track client: the `apassy-team` command (docs/SPEC.md, "CLI").
//!
//! Admin commands for owners and managers, `join` and `agent create` for members,
//! `run -- <cmd>` for agents, and `mcp`, the stdio MCP adapter that forwards each
//! JSON-RPC message to the relay's `/mcp`.
//!
//! The public interface below is fixed by the skeleton: `src/bin/apassy-team.rs`
//! calls `main`.

pub mod client;
pub mod commands;
pub mod exec;
pub mod mcp_stdio;
pub mod settings;

/// Runs the command line `args` (without the program name) and returns the exit code.
pub fn main(args: Vec<String>) -> i32 {
    let _ = args;
    eprintln!("apassy-team: not built yet");
    2
}
