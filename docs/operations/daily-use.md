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
5. Prefer Settings > Bouncer > "Start the model": "With Apassy" or "When a run needs it" ([bouncer](bouncer.md), "Start from Apassy"). If the Laya environment is missing, click "Install the model". Apassy runs the `uv` commands of step 4 for you and shows each step ([bouncer](bouncer.md), "Install from Apassy"). It needs `uv`: `brew install uv`. A LaunchAgent is now optional. If one already answers on the port, Apassy uses it and starts no second server. To start the bouncer at login without Apassy, use a LaunchAgent. On 2026-09-27 this Mac got `~/Library/LaunchAgents/com.wydrox.apassy.bouncer.plist`. It runs `/Applications/Apassy.app/Contents/Resources/tools/basemodel/start.sh` with the base model on `127.0.0.1:8770`. The log is `~/Library/Logs/Apassy/bouncer.log`. Settings shows a note when such a LaunchAgent names a missing model, or when "Start the model" is "With Apassy" or "When a run needs it". The note has the commands that remove it: `launchctl bootout gui/$(id -u)/com.wydrox.apassy.bouncer`, then delete the file. Apassy does not remove it.

## 2. Set up the vault

1. Open `Apassy.app`. Click "Create a new vault". Type a name, or leave "Personal". Type a strong passphrase that you can remember, two times. A lost passphrase can make the data unrecoverable (ADR 0003). The vault file is `~/Library/Application Support/Apassy/vaults/personal.db`. A vault from Apassy 0.2 stays at `~/Library/Application Support/Apassy/vault.db` with the name "Personal". At the next start, Apassy opens the last used vault and shows the unlock screen.
   To keep credentials apart, for example for one client, make another vault with its own passphrase: [several vaults](multiple-vaults.md). One vault is open at a time. An agent works only with the vault where you registered it.
2. Make an encrypted backup and keep it in a safe place: Settings > Vault > "Back up now", and [backup and restore](backup-restore.md).
3. Click "+" and paste a credential, a `.env` file, or a database URL, then "Add". Apassy finds the kind, the provider, the variable, the hosts, and the declaration ([ADR 0025](../adr/0025-low-friction-access.md) §4). Or import from 1Password with Settings > Vault > Import: [import from 1Password](import-1password.md).
4. Optional: open a credential to check its environment ("Is this a development key?") or to set "Always ask me": [declarations](declarations.md).

The app layout is in [desktop UI](desktop-ui.md).

## 3. Connect Claude Code and Codex

1. In Agents, click "+" ("Connect an Agent") for each host, pick it, and confirm once. Apassy saves the settings of Claude Code, Codex, and T3 Code. The token expires after 30 days. "Reconnect…" on the page of the agent gives a new one.
2. For another host ("Other"), add the MCP server with the path `/Applications/Apassy.app/Contents/MacOS/apassy-mcp`: [agent path](agent-path.md), section 4. Give the host a tool time-out of at least 330 seconds (`MCP_TOOL_TIMEOUT=330000` for Claude Code): a question waits up to 5 minutes.
3. Install the prompt hook for each host: [host hooks](host-hooks.md), section 6.
4. There is no access to give. The bouncer decides each use and asks you in Decisions when it is not sure ([agent path](agent-path.md), section 8).
5. Log in to each host (`claude /login`, `codex login`, `gh auth login`) before you start it in the profile. The profile blocks browser logins.
6. Start each host in the profile, with its own sandbox off: [isolation](isolation.md), section 3. The profile denies each vault in the vault list. After you add a vault outside `~/Library/Application Support/Apassy`, start the host again.
7. In a project that agents edit, open your own terminal in the profile too: `apassy-sandbox -- zsh` (ADR 0010, second round).

## 4. Every day

- A banner on every view shows a question that waits for you, and Decisions lists it, with the time left of its 5 minutes. Answer "Deny", "Allow Once", or "Allow ACTION in PROJECT", for example "Allow Read in shop". Apassy remembers "Allow ACTION in PROJECT" for the credential, the project, and the kind of action, for all agents. An answer that allows needs Touch ID or the passphrase.
- A production run waits for you, unless you allowed production for that project and kind of action. A question about a production credential offers "Allow production: ACTION in PROJECT" instead. A credential that is production only by default offers "Development" and "Production".
- The "⋯" menu of a question has the stricter answers "Never for AGENT", "Always Ask for AGENT", and "Disconnect AGENT…". They need no owner check. The credential page lists your remembered answers under "Rules from your answers"; "Remove" takes one away.
- Decisions also shows Requests (an agent asks you to paste a credential) and Suggestions (corrections from how agents use a credential).
- The line under the Decisions title shows how often Apassy asked you this week. Goal item B12: after two weeks, you are asked on 10% or fewer of the runs, over the last seven days.
- Settings > Devices > This Mac has the "Allow notifications" button.

## 5. What Apassy does not protect

Read these limits before you add a production credential:

- A running command can read, print in encoded form, write, or send its secrets ([ADR 0006](../adr/0006-process-secrets.md)).
- A process of the same user can read the environment of a running secret command (F11, accepted in ADR 0010).
- Code that an agent writes runs with full access when you run it outside the profile ([isolation](isolation.md), section 7).
