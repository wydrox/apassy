//! The `apassy-team` command (docs/SPEC.md, "CLI").
//!
//! Admin commands for owners and managers, `join` and `agent create` for members,
//! `run -- <cmd>` for agents, `host` for the owner's machine (it holds the item keys
//! and releases them run by run), and `mcp`, the stdio MCP adapter that forwards each
//! JSON-RPC message to the relay's `/mcp`.
//!
//! The public interface below is fixed by the skeleton: `src/bin/apassy-team.rs`
//! calls `main`.
//!
//! Exit codes: 0 success (or the child's code for `run`), 2 usage error,
//! 3 run denied or timed out, 4 relay or network error.

// Route human output through one place; explicit secret output bypasses progress.
macro_rules! println {
    ($($arg:tt)*) => { crate::cli::output::line(format_args!($($arg)*)) };
}
macro_rules! print {
    ($($arg:tt)*) => { crate::cli::output::text(format_args!($($arg)*)) };
}

pub mod args;
pub mod client;
pub mod commands;
pub mod devicekey;
pub mod devices;
pub mod exec;
pub mod host;
pub mod keystore;
pub mod mcp_stdio;
pub mod onboarding;
pub mod output;
pub mod service;
pub mod settings;
pub mod signin;

/// An error that ends the command with an exit code and one line on stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub code: i32,
    pub message: String,
    pub kind: String,
    pub status: Option<u16>,
    pub retryable: bool,
    pub retry_after: Option<u64>,
}

impl CliError {
    /// Exit 2: the command line or the local setup is wrong.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
            kind: "usage".into(),
            status: None,
            retryable: false,
            retry_after: None,
        }
    }

    /// Exit 3: the run was denied or timed out.
    pub fn denied(message: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: message.into(),
            kind: "run_denied".into(),
            status: None,
            retryable: false,
            retry_after: None,
        }
    }

    /// Exit 4: the relay or the network failed.
    pub fn relay(message: impl Into<String>) -> Self {
        Self {
            code: 4,
            message: message.into(),
            kind: "relay_error".into(),
            status: None,
            retryable: false,
            retry_after: None,
        }
    }
}

/// Runs the command line `args` (without the program name) and returns the exit code.
pub fn main(args: Vec<String>) -> i32 {
    // Never consume flags after the child's delimiter.
    let boundary = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let json = args[..boundary].iter().any(|arg| arg == "--json");
    output::begin(json);
    let repeats = args[..boundary]
        .iter()
        .filter(|arg| *arg == "--json")
        .count();
    let filtered: Vec<_> = args
        .iter()
        .enumerate()
        .filter(|(index, arg)| *index >= boundary || *arg != "--json")
        .map(|(_, arg)| arg.clone())
        .collect();
    let mut show_help_hint = true;
    let result = if repeats > 1 {
        Err(CliError::usage("Option --json is given twice."))
    } else {
        args::parse(&filtered).and_then(|command| {
            show_help_hint = false;
            fn streaming(command: &args::Command) -> bool {
                match command {
                    args::Command::Selected { command, .. } => streaming(command),
                    args::Command::Mcp | args::Command::Host { .. } => true,
                    _ => false,
                }
            }
            if json && streaming(&command) {
                return Err(CliError::usage("--json wraps finite commands. MCP and foreground host use their own streaming protocols."));
            }
            commands::execute(command)
        })
    };
    let code = match &result {
        Ok(code) => *code,
        Err(error) => error.code,
    };
    if json {
        let envelope = match result {
            Ok(_) => serde_json::json!({"ok":true,"result":output::finish(),"exit_code":code}),
            Err(error) => serde_json::json!({"ok":false,"exit_code":code,"error":{
                "code":error.kind,"message":error.message,"status":error.status,
                "retryable":error.retryable,"retry_after":error.retry_after}}),
        };
        std::println!("{envelope}");
    } else if let Err(error) = result {
        eprintln!("apassy-team: {}", error.message);
        if show_help_hint {
            eprintln!("Run `apassy-team help` for the commands.");
        }
    }
    code
}
