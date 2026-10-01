# The apassy command line

Date: 2026-10-01. Decision: [ADR 0017](../adr/0017-owner-command-line.md). Wire: [owner-cli-v1](../contracts/owner-cli-v1.md).

The `apassy` program opens the window when it runs without arguments. With a command, it talks to the running window. Every change uses the same checks as the window: grants, approvals, new tokens, and agent settings ask for Touch ID or the passphrase in the window, for each change.

The command line never shows a secret value, and never takes one as an argument. It asks on the terminal with the echo off, or reads stdin or a file.

## 1. Install

The program is inside the app. Put a link on your `PATH`:

```sh
ln -s /Applications/Apassy.app/Contents/MacOS/apassy /usr/local/bin/apassy
apassy doctor
```

The app must run. `apassy` without arguments, or Apassy.app, starts it.

## 2. A session

Only `status`, `login`, `lock`, and `unlock` work without a session.

```sh
apassy unlock                 # brings the window to the front; unlock it there
eval "$(apassy login)"        # confirm with Touch ID or the passphrase in the window
apassy status
apassy logout                 # or: eval "$(apassy logout)"
```

`login` prints `export APASSY_SESSION='apassy_cli_…'` (`set -gx …` in fish). It refuses to print the token on a terminal: use it with `eval`, or add `--raw` for the token only. A session belongs to the open vault. It ends after 30 idle minutes, after 12 hours, at a lock, when another vault opens, after a backup or a passphrase change, and when Apassy quits. Settings > Command line shows the open sessions and ends them.

Do not start an agent from a shell that has `APASSY_SESSION`. `apassy-sandbox` removes it from the agent environment; an agent started without the sandbox would inherit it.

## 3. Credentials

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
apassy import ~/Downloads/1Password.csv
apassy import ~/Downloads/bitwarden_export.csv
```

| Format | Each entry becomes |
| --- | --- |
| `.env` | One credential named after the key, an API key by default. `--kind custom` stores the value in a field named after the key. Quotes, `export`, comments, and quoted values on more than one line work. |
| 1Password CSV | A login (username and password), an API key (a password alone), or a custom credential (a note alone). The website gives the service, and a one-time code secret is a hidden detail. |
| Bitwarden CSV | The same. Custom fields are hidden details. |

The format comes from the file name and the header. `--format` overrides it. A name that exists is left out unless `--allow-duplicates`. Then bind the variables with `apassy item env`, and delete the export file: it holds every password in plain text.

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
apassy agent see-all "Claude Code" on     # owner check
apassy agent lifetime 30                  # owner check

apassy grant set "Claude Code" "Stripe test" "Prod DB"            # this folder, you approve each run
apassy grant set "Claude Code" "Stripe test" --folder ~/src/billing --mode bouncer
apassy grant set "Claude Code" "Stripe test" --any-folder
apassy grant rule "Claude Code" "Stripe test" --allow "npm test" --allow "npm run migrate" \
    --forbid prod --max-runs 20 --expires 24 --instruction "Staging only."
apassy grant remove "Claude Code" "Stripe test"
apassy grant operation "Claude Code" Reporting get_sales_summary
```

`setup` writes `~/.config/apassy/apassy-mcp-HOST.sh` and `~/.config/apassy/apassy-hook-HOST.sh` with mode 0700. Apassy.app ships `apassy-mcp` but not `apassy-hook`: from the app, `setup` connects the MCP server and leaves out the prompt hook, unless `--hook PATH` names an `apassy-hook` from a source build ([host hooks](host-hooks.md)). They hold the token, so no host file does. Without `--write`, it prints the configuration. With `--write`, Claude Code gets the server through `claude mcp add --scope user` and the hook in `~/.claude/settings.json`; Codex gets `[mcp_servers.apassy]` in `~/.codex/config.toml` and the hook in `~/.codex/hooks.json`. A copy of each changed file stays next to it (`.before-apassy`). Trust the hook in Codex with `/hooks`.

## 6. Requests, runs, and history

```sh
apassy request list                       # --all for the decided ones too
apassy request grant 12 --folder ~/src/billing      # owner check
apassy request deny 12
apassy runs                               # runs that wait for you
apassy runs approve 41                    # owner check; the window shows the run
apassy runs approve 41 --remember
apassy runs deny 41
apassy pattern list
apassy pattern remove 3
apassy activity --agent "Claude Code" --limit 20
apassy decisions export --output decisions.jsonl     # mode 0600
```

## 7. Vault

```sh
apassy lock
apassy vault backup /Volumes/Backup/apassy-2026-10-01.backup   # the vault locks after it
apassy vault change-passphrase            # asks for the current and the new one
apassy vault restore /Volumes/Backup/apassy.backup   # opens the restore sheet in the window
```

## 8. Scripts

`--json` prints the full response. A failure prints `{"ok": false, "code": …, "message": …}`. The exit code is 0 for done, 1 when Apassy refused, 2 for a usage error, and 3 when Apassy is not running.

```sh
apassy --json item list | jq -r '.data.items[] | select(.variable == null) | .name'
```

## 9. Limits

- A process of the same user outside the agent profile can connect to the owner socket. Without a session, it can only read the status, lock, bring the window to the front, and ask for a login that you see in the window and can cancel.
- The session token is in the environment of the shell and of each program that it starts. A process of the same user can read the environment of a running process (F11).
- A process of the same user outside the profile can replace the socket before Apassy starts and read what the command line sends. Inside the profile, the socket is denied ([isolation](isolation.md)).
