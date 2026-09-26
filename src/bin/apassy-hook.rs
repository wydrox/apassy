//! `UserPromptSubmit` hook for Claude Code and Codex (goal item B6).
//!
//! The host starts this program for each user prompt and writes the hook JSON to
//! stdin. The program sends the prompt to the Apassy broker with the agent token in
//! `APASSY_AGENT_TOKEN`. `APASSY_BROKER_SOCKET` can change the socket path, as for
//! `apassy-mcp`. The program does not accept the token as an argument, because other
//! local processes can read process arguments.
//!
//! The program never writes to stdout, and it always exits with code 0. So it does not
//! change or block the user prompt. A failure goes to stderr without the prompt text.

use std::io::Read;

use apassy::agent::{client, hook};

fn main() {
    if let Some(arg) = std::env::args().nth(1) {
        if arg == "--version" {
            // A manual check, not a hook run. The host does not pass arguments.
            println!("apassy-hook {}", env!("CARGO_PKG_VERSION"));
        } else {
            eprintln!("apassy-hook: takes no arguments. The host writes the hook JSON to stdin.");
        }
        return;
    }
    if let Err(message) = run() {
        eprintln!("apassy-hook: {message}. The prompt continues without Apassy.");
    }
}

fn run() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(hook::MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|err| format!("cannot read the hook input ({})", err.kind()))?;
    let Some(prompt) = hook::parse(&input)? else {
        return Ok(());
    };
    input.fill(0);
    let token = std::env::var(client::TOKEN_ENV)
        .ok()
        .filter(|token| !token.trim().is_empty())
        .ok_or("APASSY_AGENT_TOKEN is not set")?;
    hook::submit(&client::default_socket_path(), &token, prompt)
}
