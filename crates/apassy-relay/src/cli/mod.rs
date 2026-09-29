//! The `apassy-team` command (docs/SPEC.md, "CLI").
//!
//! Admin commands for owners and managers, `join` and `agent create` for members,
//! `run -- <cmd>` for agents, and `mcp`, the stdio MCP adapter that forwards each
//! JSON-RPC message to the relay's `/mcp`.
//!
//! The public interface below is fixed by the skeleton: `src/bin/apassy-team.rs`
//! calls `main`.
//!
//! Exit codes: 0 success (or the child's code for `run`), 2 usage error,
//! 3 run denied or timed out, 4 relay or network error.

pub mod args;
pub mod client;
pub mod commands;
pub mod exec;
pub mod mcp_stdio;
pub mod settings;

/// An error that ends the command with an exit code and one line on stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub code: i32,
    pub message: String,
}

impl CliError {
    /// Exit 2: the command line or the local setup is wrong.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }

    /// Exit 3: the run was denied or timed out.
    pub fn denied(message: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: message.into(),
        }
    }

    /// Exit 4: the relay or the network failed.
    pub fn relay(message: impl Into<String>) -> Self {
        Self {
            code: 4,
            message: message.into(),
        }
    }
}

/// Runs the command line `args` (without the program name) and returns the exit code.
pub fn main(args: Vec<String>) -> i32 {
    let command = match args::parse(&args) {
        Ok(command) => command,
        Err(err) => return fail(&err, true),
    };
    match commands::execute(command) {
        Ok(code) => code,
        Err(err) => fail(&err, false),
    }
}

fn fail(err: &CliError, show_help_hint: bool) -> i32 {
    eprintln!("apassy-team: {}", err.message);
    if show_help_hint {
        eprintln!("Run `apassy-team help` for the commands.");
    }
    err.code
}
