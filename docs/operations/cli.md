# The apassy command line

Date: 2026-10-03. Decision: [ADR 0017](../adr/0017-owner-command-line.md). Wire: [owner-cli-v1](../contracts/owner-cli-v1.md).

The `apassy` program opens the window when it runs without arguments. With a command, it talks to the running window. Every change uses the same checks as the window: approvals, new tokens, connector operations, and agent settings ask for Touch ID or the passphrase in the window, for each change.

The command line never shows a secret value, and never takes one as an argument. It asks on the terminal with the echo off, or reads stdin or a file.

## Fresh checks for backup, export and tokens (2026-10-31)

[ADR 0030](../adr/0030-owner-check-window.md) requires a fresh local owner
check for an encrypted backup (from Settings or the CLI), CLI decision export,
and registering an agent/issuing its token. A command-line session and the new
owner-check window cannot replace those checks. Restore still verifies the typed
backup passphrase and opens the restored vault locked. This supersedes earlier
wording below that allowed these commands using only an open CLI session.


## 1. Install

The app contains `apassy`, `apassy-mcp`, `apassy-hook`, and `apassy-sandbox`. It also contains the Seatbelt profile for `apassy-sandbox`.

In Apassy, open Settings > Tools > Command line. Use Install CLI tools to put links in `~/.local/bin`.

You can also install the links from Terminal:

```sh
mkdir -p "$HOME/.local/bin"
for tool in apassy apassy-mcp apassy-hook apassy-sandbox; do
  ln -s "/Applications/Apassy.app/Contents/MacOS/$tool" "$HOME/.local/bin/$tool"
done
```

If a link or file exists, `ln` reports an error. It does not replace that file. Keep the program files in the app. Do not copy the programs out of the app. The programs need the other tools and the profile in the app.

If `~/.local/bin` is not on your `PATH`, set it for this Terminal session:

```sh
export PATH="$HOME/.local/bin:$PATH"  # zsh or bash
# For fish: fish_add_path --path "$HOME/.local/bin"
```

For new Terminal sessions in zsh, add the `export` line to `~/.zprofile`. For bash, use `~/.bash_profile`. For fish, use `fish_add_path "$HOME/.local/bin"`. Apassy and the source installer do not change shell files.

Check the installation:

```sh
command -v apassy apassy-mcp apassy-hook apassy-sandbox
apassy doctor
apassy-sandbox --print -- /usr/bin/true
```

The app must run for owner commands. `apassy` without arguments, or Apassy.app, starts it. You can also use the full path without links:

```sh
/Applications/Apassy.app/Contents/MacOS/apassy doctor
```

### Shell completions

`apassy completions zsh|bash|fish` prints a completion script. The scripts complete the commands, the subcommands, and the main options (`--json`, `--socket`, `--help`, `--version`). They come from the same tables as `apassy help`, so a new command appears in them. They do not need the window.

For zsh, write the script to a folder on `fpath`, then start a new shell:

```sh
mkdir -p ~/.zfunc
apassy completions zsh > ~/.zfunc/_apassy
# In ~/.zshrc, before compinit:
#   fpath=(~/.zfunc $fpath)
#   autoload -Uz compinit && compinit
```

For bash, add this line to `~/.bash_profile`. Terminal on macOS starts login shells, which read `~/.bash_profile` and not `~/.bashrc`. Use `eval`: the bash 3.2 of macOS reads nothing from `source <(...)`.

```sh
eval "$(apassy completions bash)"
```

For fish, write the script to the completions folder:

```sh
apassy completions fish > ~/.config/fish/completions/apassy.fish
```

Where no subcommand fits, as for the file of `apassy import`, zsh and bash complete file names. Fish does too.

Apassy and the installer do not change shell files. Write the script again after an update, so it lists the new commands.

## 2. A session

`status`, `login`, `lock`, and `unlock` contact the app without a session. Local help, version, completions, doctor, and browser setup also need no session. Logout without a session prints local cleanup instructions.

```sh
apassy unlock                 # brings the window to the front; unlock it there
eval "$(apassy login)"        # confirm with Touch ID or the passphrase in the window
apassy status
apassy logout                 # or: eval "$(apassy logout)"
```

`login` prints `export APASSY_SESSION='apassy_cli_…'` (`set -gx …` in fish). It refuses to print the token on a terminal: use it with `eval`, or add `--raw` for the token only. A session belongs to the open vault. It ends after 30 idle minutes, after 12 hours, at a lock, when another vault opens, after a backup or a passphrase change, and when Apassy quits. Settings > Tools > Command line shows the open sessions and ends them.

Do not start an agent from a shell that has `APASSY_SESSION`. `apassy-sandbox` removes it from the agent environment; an agent started without the sandbox would inherit it.

## 3. Credentials

The quickest way is to paste (ADR 0025 §4, "two steps to add"):

```sh
apassy add                                # a hidden prompt: paste one secret or KEY=value line
apassy add < .env                         # every line of a .env file
pbpaste | apassy add --folder Work/Acme   # into a folder that exists
op read op://dev/db/url | apassy add --folder Work/Acme --create-folder
```

`apassy add` reads the text from stdin when it is not a terminal, else from a hidden prompt (one line, at most 64 KiB). The text is a secret, a `KEY=value` line, a whole `.env` file, a URL with a password (`postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://`), or an `otpauth://` link. The app finds the rest on this Mac, without sending the value anywhere, and adds every credential in one transaction: all of them or none. It prints one line for each, such as `Anthropic API key · ANTHROPIC_API_KEY · production`, and never a value.

- The kind, the name, the provider, the variable, and the provider hosts come from the provider catalog (the value prefix, the variable name, the host). A URL is split into fields; its password is the secret, and the variable gets the whole URL.
- A name that another credential has gets ` 2`, ` 3`, … A variable that another credential uses is not taken: the new credential gets the automatic name `APASSY_ITEM_<id>`. A reserved name such as `PATH` is not used.
- A known provider starts in placeholder mode for its hosts (ADR 0011), as a new variable does in the window, when the value is long enough for a placeholder. Else programs get the real value. Change it with `apassy item env`. A one-time password setup key is never bound.
- The declaration is saved with the credential, with the source of each value: `signal` (the catalog found it) or `default` (nothing did, so the most sensitive value).
- `--folder PATH` names a folder by its names from the top level, such as `Work/Acme`, exactly or without regard to case. A folder that does not exist is an error unless `--create-folder`.
- A session is needed and no owner check, as for `apassy item add`: a new credential gives no agent anything that the bouncer does not decide (ADR 0025 §3). Binding a variable of an existing credential still asks for the owner check.

Each field by hand:

```sh
apassy item list                          # or: apassy item list stripe --archived
apassy item show "Stripe test"            # an ID or the exact name
apassy item add "Stripe test" --kind api-key --service stripe.com --project billing
                                          # asks for the token with the echo off
op read op://dev/stripe/key | apassy item add "Stripe test" --kind api-key
apassy item add "Deploy key" --kind ssh-key --secret-file ~/.ssh/deploy_key --key-passphrase
apassy item add "Prod DB" --kind database --host db.example.com --database app --username app
apassy item add "Webhook" --kind custom --field signing_secret --detail Region=eu --secret-detail "Backup code"
apassy item edit "Stripe test" --notes "rotated 2026-10" --secret      # --secret asks for a new value
apassy item edit 7 --remove-detail Region
apassy item archive "Stripe test"         # agents cannot use it
apassy item unarchive "Stripe test"       # owner check
apassy item history "Stripe test"
apassy item delete "Stripe test"          # asks to confirm; --yes without a terminal
```

Agent settings of a credential (each asks for the owner check):

```sh
apassy item env "Stripe test" STRIPE_SECRET_KEY
apassy item env "Stripe test" STRIPE_SECRET_KEY --placeholder-host api.stripe.com
apassy item env "Stripe test" --clear     # also removes its process grants
apassy item declare "Stripe test" --project billing --environment staging --risk medium \
    --scope read-write --reversibility partial --provider stripe
apassy item connector "Reporting" https://reports.example.com
apassy item review "Stripe test"          # after a restore
```

## 4. Import

```sh
apassy import .env --project billing --dry-run
apassy import .env --project billing
apassy import .env --project billing --bind   # one owner check for every variable
apassy import ~/Downloads/1Password.csv
apassy import ~/Downloads/bitwarden_export.csv
```

| Format | Each entry becomes |
| --- | --- |
| `.env` | One credential named after the key, an API key by default. `--kind custom` stores the value in a field named after the key. Quotes, `export`, comments, and quoted values on more than one line work. |
| 1Password CSV | A login (username and password), an API key (a password alone), or a custom credential (a note alone). The website gives the service, and a one-time code secret is a hidden detail. |
| Bitwarden CSV | The same. Custom fields are hidden details. |

The format comes from the file name and the header. `--format` overrides it. A name that exists is left out unless `--allow-duplicates`. Then bind the variables with `apassy item env`, and delete the export file: it holds every password in plain text.

`--bind` binds the variables in the same command, with one owner check for all of them:

- A `.env` key is the variable of its credential. A 1Password or Bitwarden row has a variable only when its title is a variable name already, such as `STRIPE_API_KEY`. Other rows get no variable.
- Only the credentials that this import adds are bound, at most 200 in one import. The main secret is the value, and programs get the real value. A placeholder needs `apassy item env --placeholder-host`.
- The app refuses a name that is not valid (`A-Z`, `0-9`, and `_`; no system name such as `PATH`), a name that another credential uses, and a credential without a secret value. The window lists the others with their count, and Touch ID says how many variables it binds.
- The table shows the result of each credential. Under it, one line for each variable that is not bound says why. A cancel adds the credentials and binds nothing. The exit code is 1 when a variable is not bound.
- With `--json`, the answer is one document. An entry that is not bound has a `reason`. When something was not done, `ok` is false and the document has a `code` and a `message`.
- With `--dry-run`, the table shows the variable that each credential would get.
- Without `--bind`, the import binds nothing.

## 5. Agents and access

```sh
apassy setup claude --write               # registers "Claude Code", writes the wrappers,
                                          # the MCP server, and the prompt hook
apassy setup codex --write
apassy agent list
apassy agent show "Claude Code"
apassy agent add "CI bot"                 # prints the token once
apassy agent rotate "Claude Code"         # owner check; prints the new token once
apassy agent revoke "CI bot"
apassy agent see-all "Claude Code" on     # owner check; removes "Only these items"
apassy agent lifetime 30                  # owner check
apassy grant operation "Claude Code" Reporting get_sales_summary   # owner check
```

Since 0.5.0 a connected agent needs no process grant ([ADR 0025](../adr/0025-low-friction-access.md)). A new terminal setup connection asks for catalog consent in its fresh owner approval, as GUI onboarding does. Raw registration with `agent add` stays restricted. Existing agents keep their visibility and token; the bouncer decides each use of each visible credential.

- `apassy grant operation` allows one connector operation for `apassy_use_credential`. The app has no switch for it.
- `apassy grant set`, `grant rule`, and `grant remove` still save or remove a process grant with its folder, mode, and rule. The broker does not read them for a run. A process grant only adds the credential to the list of an agent with "Only these items", and shows in `process_access` of `apassy_list_access`.
- `apassy agent see-all AGENT off` gives the agent "Only these items" (no owner check). `on` removes it.
- The command line has no command for exceptions. Answer a question in Decisions with "Never for AGENT" or "Always Ask for AGENT", and remove an exception on the page of the agent.

`setup --write` writes `~/.config/apassy/apassy-mcp-HOST.sh` and `~/.config/apassy/apassy-hook-HOST.sh` with mode 0700. These wrapper scripts hold the token. The host configuration files do not hold the token.

The app contains both programs. `setup` uses them without a source build or `--hook PATH` ([host hooks](host-hooks.md)). For an older app without `apassy-hook`, install the current app first.

Without `--write`, Claude/Codex setup validates and previews configuration only: it creates no agent or files and needs no session. With `--write`, setup checks helpers, host/hook configuration, and destinations before connecting. A retry reuses complete managed wrappers and their existing token. Incomplete wrappers require explicit repair with the existing token through `--token-stdin`; setup does not rotate or broaden an existing agent. With `--write`, it adds the MCP server and the prompt hook:

- Claude Code gets the MCP server through `claude mcp add --scope user`. It gets the prompt hook in `~/.claude/settings.json`.
- Codex gets `[mcp_servers.apassy]` in `~/.codex/config.toml`. It gets the prompt hook in `~/.codex/hooks.json`.

The default paths above honor `CLAUDE_CONFIG_DIR` and `CODEX_HOME`. Managed setup uses 660 seconds for Codex and `MCP_TOOL_TIMEOUT=660000` for Claude Code, above the default 300-second owner wait plus 300-second run budget. It migrates the recognized legacy 330-second value once and preserves other custom timeout values. A copy of an existing changed host/hook file stays next to it (`.before-apassy`). Trust the hook in Codex with `/hooks`.

`apassy setup browser` connects the browser extension: it writes the native messaging host manifest for each browser on this Mac and prints the folder of the extension. It registers no agent and needs no session. `--browser NAME` selects one browser, and `--remove` deletes the manifests ([browser](browser.md)).

## 6. Requests, runs, and history

```sh
apassy request list                       # --all for the decided ones too
apassy request deny 12
apassy runs                               # questions that wait for you
apassy runs approve 41                    # owner check; the window shows the run
apassy runs approve 41 --remember         # owner check; also one approval for its pattern
apassy runs deny 41
apassy pattern list
apassy pattern remove 3
apassy activity --agent "Claude Code" --limit 20
apassy decisions export --output decisions.jsonl     # mode 0600
```

- `apassy request` lists and closes the notes of `apassy_request_access`. An agent does not need them, and the app does not show them. `apassy request grant ID` still saves a process grant and closes the request; like `grant set`, it gives the agent nothing that the bouncer does not decide.
- `apassy runs approve` is "Allow Once". The command line cannot give "Allow ACTION in PROJECT" or a production allowance: answer in Decisions.
- `--remember` is the only way left to teach a pattern ([learning](learning.md), section 2). The app shows only the number of patterns (Settings > Bouncer > Calibration and learning). `apassy pattern list` shows each pattern, and `apassy pattern remove` removes one.

## 7. Vault

```sh
apassy lock
apassy vault backup /Volumes/Backup/apassy-2026-10-01.backup   # the vault locks after it
apassy vault change-passphrase            # asks for the current and the new one
apassy vault restore /Volumes/Backup/apassy.backup   # opens the restore sheet in the window
```

## 8. Scripts

`--json` prints one response document on stdout, with progress on stderr. The exit code is 0 for done, 1 when Apassy refused or a diagnostic failed, 2 for a usage error, and 3 when an app request cannot connect. Doctor reports a missing app as a failed diagnostic with exit 1. See the JSON output contract below for command data and partial changes.

```sh
apassy --json item list | jq -r '.data.items[] | select(.variable == null) | .name'
```

## 9. Limits

- A process of the same user outside the agent profile can connect to the owner socket. Without a session, it can only read the status, lock, bring the window to the front, and ask for a login that you see in the window and can cancel.
- The session token is in the environment of the shell and of each program that it starts. A process of the same user can read the environment of a running process (F11).
- A process of the same user outside the profile can replace the socket before Apassy starts and read what the command line sends. Inside the profile, the socket is denied ([isolation](isolation.md)).


## Installed-app first use

1. Open and unlock Apassy. In Settings > Tools install the command links; follow the PATH instructions above.
2. Connect the host in Agents, or run `eval "$(apassy login)"` and `apassy setup claude --write` (use `codex` for Codex). Setup selects the bundled MCP and hook programs automatically.
3. Start the copied `apassy-sandbox` command in your project. For Codex, accept hook trust through `/hooks`.
4. Check `/mcp`, list the catalog, and make a first request using a synthetic credential. Inspect the result and Decisions. A saved config or doctor result does not prove this connection works.

## JSON output contract

For doctor, setup (Claude, Codex, and browser), logout, and decisions export, `--json` writes exactly one JSON document to stdout. Progress and human instructions belong on stderr. Parse the whole document, then inspect `ok` and the exit status. These results share `ok`, `code`, `stage`, and `partial_state`; command data is in `data`, or `checks` for doctor. A `message` may explain the result. Failures before command work starts use the standard `ok`, `code`, `message`, `data` error envelope with `stage: "request"` and empty `partial_state`. Partial browser changes are reported and are not rolled back.

Claude/Codex setup returns `data.type: "setup"` and `data.connection_verified: false`. Its top-level `stage` is the last marker reached (or `preflight` before any marker). `partial_state.stages` lists the ordered markers reached; `partial_state.partial` means a failed setup made confirmed changes, and `partial_state.changes_unknown` means a connection request lost its response and may have created an agent. Check both flags before recovery. Without `--write`, a successful preview has `stage: "preview"` and neither flag set. Setup usage errors exit 2, a missing app during connection exits 3, and other failures exit 1.

Doctor includes `checks`; a failed report exits 1 without a second error document. `unverified` means the diagnostic cannot prove connection, hook execution, or enforcement. Doctor reads configuration and never launches referenced commands.

Logout returns `data.shell_command` for clearing the local environment; JSON itself is not shell code. Decisions export returns `data.jsonl` as a JSON string, or `data.output` and `data.bytes` after a mode-0600 create-new file write. Without `--json`, export remains JSON Lines.

No stored secret values or wrapper contents belong in diagnostics. Issued session/agent tokens are exceptions only for commands deliberately requesting issuance. Help, version, and completions are text-only even with `--json`.

MCP errors expose `structuredContent.code`, `message`, `next_step`, and `retryable`. Error codes and messages are allowlisted; raw broker text and caller-controlled parameter names are not copied into diagnostics. Unknown broker refusal codes become `broker_error`. `question_waiting` means another owner question must finish. Supplied literal secrets are masked in the original run output; transformed, fragmented, or unrelated secrets may remain. Request only needed non-secret fields.

### Concurrent MCP calls and recovery

The stdio adapter admits at most four tool calls: at most three mutating/run calls, with one slot reserved for `apassy_list_access` (catalog or operation status). Initialize, ping, tool descriptions (`tools/list`), and cancellation remain available while calls wait. Responses can arrive out of order and retain the original JSON-RPC ID. Admission has no waiting queue: a full adapter returns `busy` without submitting an operation. Duplicate active request IDs are rejected.

Every mutating/run call has a random 32-character hexadecimal `operation_id`. It appears immediately in `notifications/progress` when `params._meta.progressToken` is supplied, and in `structuredContent.operation_id` on the result or error. Progress repeats every 15 seconds while the broker works, including owner/bouncer waits. Progress contains the token, a monotonic counter, the operation ID, and fixed text; no command, argument, credential value, or broker error text.

On a lost response, reconnect and call:

```json
{"name":"apassy_list_access","arguments":{"operation_id":"0123456789abcdef0123456789abcdef"}}
```

With this argument the tool returns a receipt instead of the catalog: `state` (`checking`, `waiting_for_owner`, `executing`, or `completed`), `cancellation_requested`, `may_have_run`, and `outcome`. Check `outcome.ok` and `outcome.code`; a successful status lookup does not mean the original operation succeeded. Run outcomes include `exit_code`, `timed_out`, and `truncated`. Credential outcomes can include `item_id` and `created`. Other operations retain success/refusal only. `may_have_run` is conservative: it can be true even when a later authorization/spawn check refused execution.

Receipts retain no output or free text: stdout/stderr, names, notes, paths, arguments, network data, secret values, and raw errors are omitted. The original caller alone receives the ordinary full result. Completed receipts and idempotency bindings stay in broker memory for 15 minutes after completion, scoped to the authenticated agent and the current unlocked vault session. The broker admits at most eight active tracked operations and 256 total records, including cancellation tombstones. It refuses new work with `busy` rather than evicting an unexpired receipt. Expiry is checked on subsequent requests. A broker restart or vault session change makes earlier receipts unavailable. `operation_not_found` never proves that a call did not run.

All mutating/run tools accept optional `idempotency_key` (1–128 bytes). Choose one unique key before the first call. Within retention, the same key and identical effective arguments return the original operation receipt, including its original ID, without executing again or taking over its owner question. Completed retries return the same outcome metadata as status lookup; they do not repeat stdout/stderr. Reusing a key with different arguments returns `idempotency_conflict`. Comparison includes the action, default working directory and adapter PATH where applicable, but excludes the MCP request ID, progress token, and host session. Keys and argument fingerprints are retained as keyed digests, never as plain argument copies. A key is not durable across expiry, a broker restart, or a new vault session: verify activity and the external target with the owner before submitting again. The adapter never automatically replays a mutation.

MCP `notifications/cancelled` identifies the original JSON-RPC request with `params.requestId`. A pending question is withdrawn; cancellation before a side effect returns `cancelled`. Once execution or a mutation starts, the adapter returns `cancellation_requested`: the effect may already have happened, and status retrieval supplies its final outcome. Cancellation does not kill or undo an executing command. Closing stdin cancels all outstanding adapter calls and withdraws their waiting questions; already executing broker work can finish under its existing time limit and remains retrievable. A timeout, protocol failure, or lost response includes the operation ID and recovery instructions. Upgrade the app and adapter together; an older broker refuses the new operation envelope without executing it.
