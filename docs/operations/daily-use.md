# Daily use with real credentials

Date: 2026-09-27. Goal items P3 and B12 in [goal.md](../goal.md). Decisions: [ADR 0010](../adr/0010-closing-open-decisions.md).

This page is the first-day checklist. The other pages have the details.

## 1. Build and install once

1. Build the signed app with the base model:

   ```
   APASSY_BASE_MODEL="$HOME/Library/Application Support/Apassy/laya/models/apassy-base-v1.safetensors" \
     scripts/build-app.sh
   cargo build --release --locked --features vault --bin apassy-sandbox --bin apassy-hook
   ```

2. Copy `target/Apassy.app` to `/Applications`. The agent profile protects `/Applications/Apassy.app` by default.
3. Make sure that the data directory has mode `0700`: `chmod 700 "$HOME/Library/Application Support/Apassy"`. The broker does not start in a directory with a wider mode.
4. Start the bouncer with the base model: [bouncer](bouncer.md), "Start command with the base model". Keep it on `127.0.0.1`.
5. To start the bouncer at login, use a LaunchAgent. On 2026-09-27 this Mac got `~/Library/LaunchAgents/com.wydrox.apassy.bouncer.plist`. It runs `/Applications/Apassy.app/Contents/Resources/tools/basemodel/start.sh` with the base model on `127.0.0.1:8770`. The log is `~/Library/Logs/Apassy/bouncer.log`. To remove it: `launchctl bootout gui/$(id -u)/com.wydrox.apassy.bouncer`, then delete the file.

## 2. Set up the vault

1. Open `Apassy.app`. Create the vault. Use a strong passphrase that you can remember. A lost passphrase can make the data unrecoverable (ADR 0003).
2. Make an encrypted backup and keep it in a safe place: [backup and restore](backup-restore.md).
3. Add each credential. Apassy suggests a declaration from the item. Confirm or change each field: [declarations](declarations.md). An item without a declaration makes every run wait for you.
4. For each credential that a command needs, set the environment variable name and the secret field: [agent path](agent-path.md), section 8.

## 3. Connect Claude Code and Codex

1. In Agents, register one agent for each host. The app shows the token one time. The token expires after 30 days. Rotate it in the app.
2. Add the MCP server to the host with the path `/Applications/Apassy.app/Contents/MacOS/apassy-mcp`: [agent path](agent-path.md), section 4. For Claude Code, set `MCP_TOOL_TIMEOUT` higher than `120000`.
3. Install the prompt hook for each host: [host hooks](host-hooks.md), section 6.
4. Give process access for each project directory: [agent path](agent-path.md), section 8. Start with "ask" mode for a new project. Use "bouncer" mode when the declarations are correct.
5. Log in to each host (`claude /login`, `codex login`, `gh auth login`) before you start it in the profile. The profile blocks browser logins.
6. Start each host in the profile, with its own sandbox off: [isolation](isolation.md), section 3.
7. In a project that agents edit, open your own terminal in the profile too: `apassy-sandbox -- zsh` (ADR 0010, second round).

## 4. Every day

- A card shows each run that waits for you. Click "Approve once", "Approve and remember", or "Deny". Each approval needs your passphrase.
- A production run always waits for you.
- "Approve and remember" makes a pattern. A pattern runs without a prompt after 3 approvals. One denial blocks it.
- The Learning tab shows how often Apassy asks you. Goal item B12: after two weeks, you are asked on 10% or fewer of the runs, over the last seven days.
- Until goal item N1 is done, check the inbox in the app. A native notification is not available yet.

## 5. What Apassy does not protect

Read these limits before you add a production credential:

- A running command can read, print in encoded form, write, or send its secrets ([ADR 0006](../adr/0006-process-secrets.md)).
- A process of the same user can read the environment of a running secret command (F11, accepted in ADR 0010).
- Code that an agent writes runs with full access when you run it outside the profile ([isolation](isolation.md), section 7).
