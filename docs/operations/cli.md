# The apassy command line

Date: 2026-10-03. Decision: [ADR 0017](../adr/0017-owner-command-line.md). Wire: [owner-cli-v1](../contracts/owner-cli-v1.md).

The `apassy` program opens the window when it runs without arguments. With a command, it talks to the running window. Every change uses the same checks as the window: grants, approvals, new tokens, and agent settings ask for Touch ID or the passphrase in the window, for each change.

The command line never shows a secret value, and never takes one as an argument. It asks on the terminal with the echo off, or reads stdin or a file.

## 1. Install

The app contains `apassy`, `apassy-mcp`, `apassy-hook`, and `apassy-sandbox`. It also contains the Seatbelt profile for `apassy-sandbox`.

In Apassy, open Settings > Agents > Command line. Use Install CLI tools to put links in `~/.local/bin`.

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

Only `status`, `login`, `lock`, and `unlock` work without a session.

```sh
apassy unlock                 # brings the window to the front; unlock it there
eval "$(apassy login)"        # confirm with Touch ID or the passphrase in the window
apassy status
apassy logout                 # or: eval "$(apassy logout)"
```

`login` prints `export APASSY_SESSION='apassy_cli_…'` (`set -gx …` in fish). It refuses to print the token on a terminal: use it with `eval`, or add `--raw` for the token only. A session belongs to the open vault. It ends after 30 idle minutes, after 12 hours, at a lock, when another vault opens, after a backup or a passphrase change, and when Apassy quits. Settings > Agents > Command line shows the open sessions and ends them.

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

`setup` writes `~/.config/apassy/apassy-mcp-HOST.sh` and `~/.config/apassy/apassy-hook-HOST.sh` with mode 0700. These wrapper scripts hold the token. The host configuration files do not hold the token.

The app contains both programs. `setup` uses them without a source build or `--hook PATH` ([host hooks](host-hooks.md)). For an older app without `apassy-hook`, install the current app first.

Without `--write`, `setup` prints the configuration. With `--write`, it adds the MCP server and the prompt hook:

- Claude Code gets the MCP server through `claude mcp add --scope user`. It gets the prompt hook in `~/.claude/settings.json`.
- Codex gets `[mcp_servers.apassy]` in `~/.codex/config.toml`. It gets the prompt hook in `~/.codex/hooks.json`.

A copy of each changed file stays next to it (`.before-apassy`). Trust the hook in Codex with `/hooks`.

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
