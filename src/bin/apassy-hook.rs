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
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        match args.as_slice() {
            [arg] if arg == "--version" => println!("apassy-hook {}", env!("CARGO_PKG_VERSION")),
            [arg] if arg == "--help" || arg == "-h" => println!(
                "Usage: apassy-hook\nReads host hook JSON from stdin. Runtime failures allow the prompt to continue (exit 0).\n--help  --version; invalid arguments exit 2."
            ),
            _ => {
                eprintln!("Usage: apassy-hook [--help|--version]");
                std::process::exit(2);
            }
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
    let host = prompt.host;
    hook::submit(&client::default_socket_path(), &token, prompt)?;
    // Non-secret acknowledgement only: no prompt, token, credential or path.
    if let Some(home) = std::env::var_os("HOME") {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = std::path::PathBuf::from(home).join(".config/apassy");
        if dir.is_dir() {
            let path = dir.join(format!("hook-health-{host}.json"));
            let temp = dir.join(format!(".hook-health-{}-{}.tmp", host, std::process::id()));
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
            {
                use std::io::Write;
                let seen = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let bytes =
                    serde_json::json!({"version":env!("CARGO_PKG_VERSION"), "broker_ack_at":seen})
                        .to_string();
                if file
                    .write_all(bytes.as_bytes())
                    .and_then(|()| file.sync_all())
                    .is_ok()
                {
                    let _ = std::fs::rename(&temp, path);
                }
                let _ = std::fs::remove_file(temp);
            }
        }
    }
    Ok(())
}
