//! The `apassy-team` command (docs/SPEC.md, "CLI").
//!
//! Admin commands for owners and managers, `join` and `agent create` for members,
//! `run -- <cmd>` for agents, `host` for the owner's machine (it holds the item keys
//! and releases them run by run), and `mcp`, the stdio MCP adapter that forwards each
//! JSON-RPC message to the relay's `/mcp`.
//!
//! The public interface below is fixed by the skeleton: `src/bin/apassy-team.rs`
//! calls `main`. `apassy team ...` (the node binary, `crate::node::team`) calls
//! `main_as(Program::NodeTeam, ...)`: the same commands, with `apassy team` in its
//! messages and in the host services it writes.
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

/// Which binary runs the team command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// `apassy-team ...`.
    Team,
    /// `apassy team ...`, the node binary (plan S2-S3, D8).
    NodeTeam,
}

impl Program {
    /// The command as a person types it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Team => "apassy-team",
            Self::NodeTeam => "apassy team",
        }
    }

    /// The words between the executable and the team command line in a service file.
    pub fn service_prefix(self) -> &'static [&'static str] {
        match self {
            Self::Team => &[],
            Self::NodeTeam => &["team"],
        }
    }
}

static PROGRAM: std::sync::OnceLock<Program> = std::sync::OnceLock::new();

/// The program of this process: `Program::Team` unless `main_as` said otherwise.
pub fn program() -> Program {
    PROGRAM.get().copied().unwrap_or(Program::Team)
}

/// Runs the command line `args` (without the program name) and returns the exit code.
pub fn main(args: Vec<String>) -> i32 {
    main_as(Program::Team, args)
}

/// `main` for `program`. The first call of a process sets the program.
pub fn main_as(program_name: Program, args: Vec<String>) -> i32 {
    let _ = PROGRAM.set(program_name);
    let name = program().name();
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
            fn issues_secret(command: &args::Command) -> bool {
                match command {
                    args::Command::Selected { command, .. } => issues_secret(command),
                    args::Command::Invite { .. } | args::Command::AgentCreate { .. }
                        | args::Command::DeviceAdd => true,
                    _ => false,
                }
            }
            if json && issues_secret(&command) {
                return Err(CliError::usage("This command issues a one-time secret and cannot use --json. Run it without --json and save stdout privately."));
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
        let mut envelope = match result {
            Ok(_) => serde_json::json!({"ok":true,"result":output::finish(),"exit_code":code}),
            Err(error) => serde_json::json!({"ok":false,"exit_code":code,"error":{
                "code":error.kind,"message":error.message,"status":error.status,
                "retryable":error.retryable,"retry_after":error.retry_after}}),
        };
        output::redact(&mut envelope);
        std::println!("{envelope}");
    } else if let Err(error) = result {
        eprintln!("{name}: {}", error.message);
        if show_help_hint {
            eprintln!("Run `{name} help` for the commands.");
        }
    }
    code
}
