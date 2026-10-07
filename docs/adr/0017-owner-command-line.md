# ADR 0017 — The owner command line

Date: 2026-10-01. Release 0.3.1.
Status: ACCEPTED by the owner on 2026-10-01 ("dodaj wszystko": add every owner function to the command line). It changes the role of the CLI in [product infrastructure](../product-infra-v1.md), section 2.

## Context

- The `apassy` program opened the window. Its only options were `--smoke-test` and `--notify-check`. Every owner function was in the window only: adding a credential, importing, agents, grants, approvals, backups.
- The product documents gave the CLI to agents only: "CLI and MCP connect agents and support diagnostics. They are not the primary way the owner manages credentials and rules" ([MVP plan](../mvp-plan.md)). No document asked for an owner command line, but none ruled it out.
- The vault is open only in the app process. SQLCipher holds an exclusive lock on the file, and the passphrase is in the memory of the app. A second process cannot open the vault while the app runs.
- An agent runs as the same Mac user as the owner. A program that the owner can run, an agent can run too, unless the agent profile stops it.

## Decision

### 1. The owner socket

The app listens on `owner.sock` in the data directory (`APASSY_OWNER_SOCKET` changes the path). The `apassy` program, started with a command, sends one JSON request on a new connection and reads one response. A thread of the app hands the request to the UI thread, which uses the same vault session calls and the same owner check dialog as the views. eframe calls the app each frame also while the window is hidden ([`eframe::App::logic`]), so the command line works without a visible window.

The wire is in [owner-cli-v1](../contracts/owner-cli-v1.md).

### 2. Three levels of authority

| Level | Commands | What protects them |
| --- | --- | --- |
| No session | `status`, `login`, `lock`, `unlock` (brings the window to the front) | They show no vault content and give no authority. |
| Session | read and change credentials, import, agents, revoke, deny, history, backup, passphrase change, restore (opens the sheet) | A session token from `apassy login`. |
| Session and owner check | grants, rules, connector operations, variables, declarations, connectors, unarchive, review, "see all", token rotation and lifetime, approve a run, give an access request | Touch ID or the passphrase in the window, for each action, exactly as in the views. |

- `apassy login` asks for the owner check (`OwnerAction::OpenCliSession`) in the window. The app then makes a random token (`apassy_cli_` and 64 hex digits) and keeps only its SHA-256 digest. The command prints a shell line for `eval`. A session ends after 30 idle minutes, after 12 hours, at a lock or an unlock and when another vault opens (the vault epoch changes, [ADR 0013](0013-multiple-vaults.md)), at a backup or a passphrase change, at `apassy logout`, and when the app quits. At most 8 sessions are open.
- The owner check dialog says "The command line asked for this". The window comes to the front. One dialog at a time: a request while a dialog is open gets `busy`, so a program cannot replace a dialog that the owner reads.
- A change from the command line shows in the app too, as a message that starts with "Command line:".

### 3. What the command line never does

- It never shows a secret value of an item. There is no reveal command. A response has a token only when the owner just made one: a session after `login`, or an agent token after `agent add` or `agent rotate`.
- It never takes a secret as a program argument, because other local processes can read process arguments. It asks on the terminal with the echo off, or reads stdin or a file.
- It never sends the master passphrase to unlock. The owner unlocks in the window (`apassy unlock` brings it to the front). `vault change-passphrase` sends the current and the new passphrase, because the current passphrase is the authority for that change.
- A restore does not run from the command line. `vault restore` opens the restore sheet in the window, and the owner types the backup passphrase there. A restore replaces the open vault, so a program with a session must not do it.

### 4. The agent profile

The profile denies the data directory, so the owner socket was thought to be closed to agents. A measurement on 2026-10-01 showed that it was not: `(deny file-read* file-write* (subpath DATA_DIR))` does not stop a `connect()` to a Unix socket in that directory. The profile now also has `(deny network-outbound (remote unix-socket (subpath DATA_DIR)))`, and the broker socket is re-allowed after it. The test `profile_denies_the_owner_socket_and_keeps_the_broker_socket` connects with `nc -U` from inside the profile: the owner socket is denied, and the broker socket works.

`apassy-sandbox` removes `APASSY_SESSION` from the environment of the host, so a session of the owner never reaches a sandboxed agent (`launcher_removes_the_owner_session_from_the_host_environment`).

### 5. Owner commands that are local

- `apassy import` reads a `.env` file, or a CSV export of 1Password or Bitwarden, in the command line, and sends one add request for each entry. It never prints a value. A name that exists is left out unless `--allow-duplicates`.
- `apassy import --bind` binds the variables of the added credentials with one owner check (decided 2026-10-06). A `.env` key is the variable of its credential. A CSV row has a variable only when its title is a variable name already, such as `STRIPE_API_KEY`. The command sends one `item_bind_variables` request. The app refuses an invalid name, a name that another credential uses, and a credential without a secret value before the check, and reports each one. It asks for `OwnerAction::BindVariables`, which names each item and its variable. The dialog lists each credential and its variable, with the count, and the list scrolls when it is long. The Touch ID text names the count. The proof is checked once for the whole list, and each variable then binds on its own, with the real value. A cancel binds nothing. Without `--bind`, the import binds nothing.
- `apassy setup claude|codex` registers an agent and writes two wrapper scripts with mode 0700 in `~/.config/apassy`: one for `apassy-mcp`, one for `apassy-hook`. The host configuration names the wrappers, so no host file holds the token. Apassy.app does not ship `apassy-hook`; `--hook PATH` takes the one of a source build, and without it setup connects only the MCP server. With `--write`, it adds the MCP server (`claude mcp add` or `[mcp_servers.apassy]` in the Codex configuration) and the prompt hook, and keeps a copy of each file that it changes.
- `apassy doctor` checks the window, the vault, the broker, the session, the programs, the data directory, and the host configurations.
- `apassy completions zsh|bash|fish` prints a completion script (decided 2026-10-06). The scripts are made from the command tables of `apassy help`, so a new command or subcommand appears in them without a second list. They complete the commands, the subcommands, and the main options. A test checks every command and subcommand of the tables in each script, and checks the syntax with `zsh -n`, `bash -n`, and `fish --no-execute`. Only bash is required: the check skips zsh or fish when the shell is not installed, as on the Linux runners of CI. Where no subcommand fits, the scripts leave the word to file-name completion. The command does not need the window, and Apassy does not install the script.

## Consequences

- The owner can do from a terminal what the window does, except a reveal and a restore. The window stays the place of every owner check.
- A same-user process outside the profile can connect to the owner socket. Without a session it can lock the vault, bring the window to the front, read the status, and ask for a login check that the owner sees and can cancel.
- A session token is in the environment of the shell that ran `eval "$(apassy login)"`, and of each program that the shell starts. A same-user process can read the environment of a running process ([ADR 0006](0006-process-secrets.md), F11). The idle time and the lock limit the exposure. Do not start an agent outside `apassy-sandbox` from a shell with a session; `apassy doctor` warns when it runs inside Claude Code with a session.
- A same-user process outside the profile can replace the socket file before the app starts, and read what the command line sends: a session token, item secrets of an add, or the passphrases of a change. This is the limit of every local command line of a password manager. The profile stops it for sandboxed agents.
- The CLI adds `rustix` `termios` (already a dependency) to turn off the echo. No new crate.

## Open decisions

None. D1 (`apassy import --bind`) and D2 (shell completions) are decided in section 5.
