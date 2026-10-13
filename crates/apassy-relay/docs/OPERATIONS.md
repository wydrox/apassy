# Running apassy-relay

Plain steps to run the alpha. The design is in [SPEC.md](SPEC.md). Names such as `apassy-relay.wyderka.cc` are the ones of the first deployment. Change them for yours.

## 1. What runs where

Since 2026-10-01 the relay runs on a Linux VPS, behind a named tunnel and a Workers VPC binding. See section 16. The layout below, with a quick tunnel to a container on the owner's Mac, is the first setup. It still works as a fallback.

```
agent (cloud session, CI, laptop)
   │ HTTPS
   ▼
Cloudflare Worker  apassy-relay.wyderka.cc   adds X-Apassy-Edge: <edge secret>
   │ HTTPS, fetch()
   ▼
cloudflared quick tunnel  https://<random>.trycloudflare.com   (URL in the Worker var RELAY_ORIGIN)
   │ HTTP
   ▼
container apassy-relay  0.0.0.0:8080 plain HTTP, /data volume   (Docker in colima on the owner's Mac, aarch64)
   │ HTTPS (rustls, ring, system roots)
   ▼
upstream API hosts (api.stripe.com, api.openai.com, ...)
```

- The relay refuses every request without the right `X-Apassy-Edge`, except `GET /healthz`. The tunnel URL alone gives no access.
- The Worker forwards everything and streams bodies. It checks nothing else.
- The image is portable: one binary, one port, one volume, config from variables. It can move to Cloudflare Containers later. That needs an amd64 image and persistent storage.
- The relay holds no readable item value. The keys of the items are on the owner's Mac, in `keys.json`. `apassy-team host` runs there and talks to the relay through the same Worker and tunnel. See section 11.

## 2. Secrets

The relay needs two secrets: the master key and the edge secret. Make them with `openssl rand -hex 32`, into files that only you can read:

```sh
mkdir -p ~/.apassy-relay && chmod 700 ~/.apassy-relay
openssl rand -hex 32 > ~/.apassy-relay/master_key
openssl rand -hex 32 > ~/.apassy-relay/edge_secret
chmod 600 ~/.apassy-relay/master_key ~/.apassy-relay/edge_secret
```

The examples below use `master_key` as the file name.

- Never put a secret in a shell history, a repo, or an image.
- The master key opens `relay.db`, which holds the random key of each team file (section 17). If you lose it, every team is lost. Back it up somewhere apart from the vault backup.
- The edge secret must be the same text in the relay and in the Worker.
- Keep the folder under your home folder. Colima shares only the home folder with its VM. A folder in `/tmp` shows up empty in the container, and the relay then says it cannot read the file.
- Every secret the CLI needs (a member token, an invite code, an item value) is read from stdin. The CLI refuses to read it from a terminal.
- The vault holds only sealed item values, so the master key protects less than before: a stolen vault or backup gives only ciphertext. The item keys are in `keys.json` on each owner's machine (section 9). Back that file up apart from the vault.

## 3. Build the image

```sh
docker build -t apassy-relay:alpha .
```

The build is native (arm64 on colima). For Cloudflare Containers later, build for amd64:

```sh
docker buildx build --platform linux/amd64 -t apassy-relay:alpha-amd64 .
```

The image holds two programs: `apassy-relay` (the entry point) and `apassy-team`. It runs as user 10001 and keeps its data in the volume `/data`.

## 4. Create the relay and the first team

Run this once. It creates the directory `relay.db`, the first team, and its owner. It prints the owner token once. Copy the token into `~/.apassy-relay/owner_token.txt` at once (mode 0600). The file must hold only the token. More teams come later from team codes (section 17). Without `--team` and `--owner`, `init` makes a relay with no team.

```sh
docker run --rm -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/master_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=https://apassy-relay.wyderka.cc \
  apassy-relay:alpha init --team <name> --owner <name>
```

`APASSY_RELAY_PUBLIC_URL` is the URL that agents use. The relay puts it in the base URLs of a session. If it is wrong, agents get wrong base URLs.

If the volume already holds a relay, or a `team.db` from before teams, `init` refuses.

## 5. Start

The same command, with `-d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080` and `serve`:

```sh
docker run -d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/master_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=https://apassy-relay.wyderka.cc \
  apassy-relay:alpha serve
```

The port is bound to the loopback address only. Only the tunnel reaches it.

Optional variables:

| Variable | Meaning | Default |
| --- | --- | --- |
| `APASSY_RELAY_SESSION_TTL` | session lifetime, 60 to 3600 s | 900 |
| `APASSY_RELAY_APPROVAL_TIMEOUT` | wait for the owner's host to decide a run, 30 to 86400 s | 600 |

A restart ends every session. Runs that are still pending stay in the vault, but they lose their one-time keys: the host never sees them, and they time out.

A vault from the first alpha (it held plaintext values) is refused at start. There is no migration: start with a new data volume and add the items again.

## 6. Tunnel

Start a quick tunnel to the container:

```sh
cloudflared tunnel --url http://127.0.0.1:8080
```

Copy the `https://<random>.trycloudflare.com` URL from its output into the Worker var `RELAY_ORIGIN`.

- The URL changes at each cloudflared restart. Then the Worker needs the new URL and a deploy.
- Errors 1016 and 530 from Cloudflare mean that the tunnel is down or that the URL in the Worker is old.
- A quick tunnel has no SLA. It does not carry server-sent events.
- Keep cloudflared running. A launchd job or a `tmux` session works for the alpha.

## 7. Worker

The Worker lives in `deploy/worker/`. It has three settings:

- The var `RELAY_ORIGIN`, in `wrangler.jsonc`: the tunnel URL.
- The secret `EDGE_SECRET`: the same text as the edge secret file. Set it with `wrangler secret put EDGE_SECRET`.
- The custom domain `apassy-relay.wyderka.cc`, in `wrangler.jsonc`. The zone must be in the same Cloudflare account.

A fourth setting, the Workers VPC binding `RELAY`, replaces `RELAY_ORIGIN` when it is set (section 16).

Without the edge secret, or without both `RELAY` and `RELAY_ORIGIN`, the Worker answers 503 "relay not configured". If the relay is not reachable, it answers 502.

The Worker makes the target URL by string concatenation: origin, path, query. It does not use `new URL(path, origin)`, so a path like `//evil.example/x` cannot send the edge secret to another host. It deletes any `X-Apassy-Edge` from the client and sets its own. It does not log URLs, because paths hold session keys.

Who deploys: the owner of the Cloudflare account. The repository holds the code only. Deploy with `wrangler deploy` from `deploy/worker/`, after `npm install`. Test the Worker before that with:

```sh
node --test 'deploy/worker/test/*.test.ts'
```

This needs Node 22.18 or later. It needs no npm install.

## 8. Check

```sh
curl https://apassy-relay.wyderka.cc/healthz
```

The command prints `ok`. For a team from `apassy-relay init`, the owner can use the bootstrap token:

```sh
apassy-team init --relay https://apassy-relay.wyderka.cc < ~/.apassy-relay/owner_token.txt
apassy-team me
```

`init` checks the token with the relay. It saves legacy member-token settings, not a device key.
Legacy member tokens expire 14 days after team creation or migration to server schema version 3.
Enroll a device before this period ends. See section 9.

Settings version 2 keeps several teams in `settings.json`.
The path is `$XDG_CONFIG_HOME/apassy-team/settings.json` or `~/.config/apassy-team/settings.json`.
The directory has mode 0700. The file has mode 0600.
The file contains the current team and each team's relay URL, member name, and device ID.
The CLI reads old settings and writes version 2 at the next save.

```sh
apassy-team team list
apassy-team team use TEAM_ID
apassy-team --team TEAM_ID me
APASSY_TEAM=TEAM_ID apassy-team me
```

`--team ID` selects a team for a member command. Otherwise, `APASSY_TEAM` selects it, then the current team.
In `create --team NAME`, `--team` gives the new team's name.

The CLI stores each device private key separately.
On macOS, it uses the login Keychain: service `apassy-team`, account `<relay host> <team id>`.
On other systems, it uses `device-<team id>.key` next to `settings.json`, with mode 0600.
It never prints the private key or puts it in `settings.json`.
`APASSY_TEAM_KEY_STORE=file` selects the file store for tests only.
Tests must not use the real login Keychain.

Each member command signs in with its device key.
Its access token lasts 15 minutes and stays only in process memory.
A 401 causes one new sign-in and one retry. A second 401 fails.
If the relay's sign-in origin differs from the saved URL, the CLI stops.

For direct access to the container, set the edge secret and the local URL:

```sh
export APASSY_EDGE_SECRET="$(cat ~/.apassy-relay/edge_secret)"
apassy-team init --relay http://127.0.0.1:8080 < ~/.apassy-relay/owner_token.txt
```

The CLI accepts plain `http://` only for `127.0.0.1`, `::1`, and `localhost`.

| Variable | Meaning |
| --- | --- |
| `APASSY_RELAY_URL` | The relay origin. |
| `APASSY_TEAM` | The team ID for a member command. |
| `APASSY_TEAM_TOKEN` | A legacy member token, before its expiry. |
| `APASSY_TOKEN` | An agent token for `access`, `run`, and `mcp`. |
| `APASSY_EDGE_SECRET` | An optional secret for `X-Apassy-Edge`. |

## 9. Team setup walkthrough

For a new team, get a one-time team code from the operator.
Read the code from stdin:

```sh
apassy-team create --relay https://apassy-relay.wyderka.cc --team myteam \
  --name olga --device "Olga Mac" < team-code-file
```

`create` always makes an owner device. This device is the team's key holder.
The CLI saves the team as current. It does not save a new owner token.

For an existing team, use `device enroll` with its legacy member token.
`create`, `join`, `device link`, and `device enroll` refuse an existing key or settings entry for that team.
Thus, do not enroll in the directory where `init` saved the legacy settings.
Use an unused configuration directory and the token in the environment:

```sh
export XDG_CONFIG_HOME="$HOME/.config/apassy-device"
export APASSY_RELAY_URL=https://apassy-relay.wyderka.cc
export APASSY_TEAM_TOKEN="$(cat ~/.apassy-relay/owner_token.txt)"
apassy-team device enroll --name "Olga Mac"
unset APASSY_TEAM_TOKEN
apassy-team me
```

Enrollment removes the member token from the settings. The relay invalidates that member's old token.
The first device becomes the key holder only for the sole live owner when no key holder exists.
If the host already has item keys, copy `keys.json` into the new configuration directory before you start it.
Keep the new `XDG_CONFIG_HOME` for later commands and the host service.
On macOS, another configuration directory still uses the same Keychain account for that relay and team.
Use another machine for a second member of the same team on macOS.

The owner makes a collection, adds an item, and makes an invite link:

```sh
apassy-team collection create payments --mode bouncer
apassy-team item add --collection 1 --name "Stripe test" --env STRIPE_API_KEY \
  --environment staging --provider stripe < stripe-test-key-file
apassy-team invite --role member --hours 72 --name bob --grant 1 > invite-link-file
```

`item add` reads the value from stdin. It checks the value on this machine.
It seals the value and saves the item key in `keys.json` next to `settings.json`.
The directory has mode 0700. The file has mode 0600.
Only the sealed value goes to the relay.
Add items on the key-holder machine that runs `apassy-team host`.
A key on another machine cannot release an item from this host.

Back up `keys.json`. Item keys remain plain text in this file.
Without the keys, add the items again. Keep this backup separate from the relay's vault backup.

A known provider, such as `stripe`, supplies API hosts.
For another API, use `--host api.example.com` with the exact API host.
A host also covers its subdomains.
The relay refuses public suffixes and whole domains.
Use `--allow-broad-host` only if you own every subdomain. The audit records this choice.
Use `--environment production` for a production credential. The host asks for every run with it.

`invite` prints a link once: `<relay URL>/join#<code>`.
Use `--name NAME` to set the member name and repeat `--grant ID` for collection grants.
Use `--shared` only for role `member` on a shared device.
Only an owner can invite a manager or another owner.
Send the invite link through a private channel. The code works once.

The member reads the link or raw invite code from stdin:

```sh
apassy-team join --relay https://apassy-relay.wyderka.cc --device "Bob laptop" < invite-link-file
```

If the invite has no name, add `--name bob`.
The CLI saves the device key before it sends the request.
It prints two safety words and checks them against words it computes locally.
If the words differ, it stops. Tell the inviter the words through a trusted channel.

The inviter lists requests and confirms with the words from the member:

```sh
apassy-team joins
apassy-team confirm JOIN_ID --words "W1 W2"
```

Replace `W1 W2` with the member's words. `--words` is mandatory.
`joins` does not print safety words. Never confirm from a list or from the invite code alone.
Use `apassy-team refuse JOIN_ID` to refuse the request.

`join` waits up to 10 minutes. A pending join can remain open for 72 hours.
Use `--no-wait` to return immediately, then `apassy-team join --resume` to wait again.
The CLI uses the same saved key after an uncertain request result.
Do not remove the key or make another join request with a new key.

For a join or device link, settings can contain `safety_verified`.
It starts as `false` and becomes `true` only after the local safety-word check.
The nonsecret `recovery-<team id>.json` file saves the pending name, device name, request kind, and blocked state.
It contains no code, private key, or token.

If a network error or `busy` leaves the request result unknown, supply the original code or link on stdin.
For a join, use `apassy-team join --resume < original-code-file`.
For a device link, use `apassy-team device link --resume < original-code-file`.
The CLI repeats the request with the same saved key, checks the safety words, then waits.
After a successful `--no-wait`, resume needs no stdin.

A safety-word mismatch blocks resume.
Stop and tell the person who supplied the code.
Do not remove the saved key or change the recovery file.

Shared members cannot make device links.
To add another device for the same person, use the existing device:

```sh
apassy-team device add > device-link-code-file
```

On the new machine:

```sh
apassy-team device link --relay https://apassy-relay.wyderka.cc \
  --device "Second laptop" < device-link-code-file
```

On the existing device, get the words from the new device and confirm:

```sh
apassy-team device pending
apassy-team device confirm LINK_ID --words "W1 W2"
```

`device pending` does not print safety words. Device links expire after 10 minutes.
Use `--no-wait` with `device link`, then `apassy-team device link --resume` to wait again.
Use `device refuse LINK_ID` to refuse a link and `device revoke DEVICE_ID` to revoke a device.
A new device does not become the key holder automatically.

```sh
apassy-team device list
apassy-team device key-holder DEVICE_ID
```

Before you move the key-holder flag, copy `keys.json` to the new owner's device.
Protect the copy with mode 0600. The command moves the flag, not the item keys.
Only the current key-holder device can move the flag when one exists.

The member can make an agent token. The CLI prints it once:

```sh
apassy-team agent create ci --days 30 > agent-token-file
APASSY_TOKEN="$(cat agent-token-file)" apassy-team access
```

An owner can change a member role with `member role MEMBER_ID ROLE`.
Use `member`, `manager`, or `owner` for `ROLE`.
Move the key-holder flag before you change its member's owner role.
Use `leave` to leave a team. The last live owner cannot leave or lose the owner role.

Policy flags for `collection create` and `collection policy ID`:

| Flag | Meaning |
| --- | --- |
| `--mode ask\|bouncer` | `ask` suggests a question for every run. `bouncer` suggests release for a known safe command. The host checks each run. |
| `--allow-prefix P` | The command must start with a permitted prefix. Repeat for more prefixes. |
| `--forbid WORD` | The relay denies a command with this word. Repeat for more words. |
| `--max-runs-per-hour N` | At most N runs per hour. |
| `--instruction TEXT` | A note for the owner. |
| `--rule-expires-at UNIX` | The rule stops at this time. |

`collection policy` replaces the whole policy. Omitted flags return to their defaults.
Secrets enter input commands through stdin, never command arguments.
This includes team codes, invite codes, device-link codes, item values, and legacy tokens for `init`.
The CLI refuses a secret from a terminal. Agent tokens use `APASSY_TOKEN`.

## 10. Agents

The agent uses an agent token. Device access tokens stay in member processes.
There are three ways to run an agent.

The CLI requests a run, waits for the key-holder host, and starts the command with the session environment:

```sh
export APASSY_RELAY_URL=https://apassy-relay.wyderka.cc
export APASSY_TOKEN="$(cat agent-token-file)"
apassy-team run --items 1 --purpose "Check the balance" \
  --request "Show me the Stripe balance" -- stripe balance retrieve
```

The command does not inherit `APASSY_TOKEN`, `APASSY_TEAM_TOKEN`, or `APASSY_EDGE_SECRET`.
`run` returns the command's exit code, or 128 plus its signal number.
It returns 3 for a denied run or timeout, 4 for a relay or network error, and 2 for usage errors.
Use `--wait SECONDS` to limit the wait. The default is 900 seconds.

For remote MCP with Claude Code, put this configuration in `.mcp.json`:

```json
{"mcpServers": {"apassy": {"type": "http", "url": "https://apassy-relay.wyderka.cc/mcp",
  "headers": {"Authorization": "Bearer ${APASSY_TOKEN}"}}}}
```

For stdio MCP, use this configuration:

```json
{"mcpServers": {"apassy": {"command": "apassy-team", "args": ["mcp"]}}}
```

The adapter needs `APASSY_RELAY_URL` and `APASSY_TOKEN` in its environment.
With MCP, the agent starts its own command with `session.env`.
Thus, placeholders can enter its transcript. A placeholder needs the relay to work.
The CLI keeps the session environment outside the agent's transcript.

Cloud sessions need `apassy-relay.wyderka.cc` in their network allowlist and `APASSY_TOKEN` in their environment.
Use that exact token variable name for Claude Code MCP headers.

Each item supplies a placeholder variable and `APASSY_BASE_<NAME>`, a relay base URL.
Known providers also supply `STRIPE_API_BASE`, `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, or `GITHUB_API_URL`.
The command must send API requests to the relay base URL.
The relay inserts the real value only in a permitted authentication position.
It refuses placeholders in other positions.

The host signs in as the selected team's key-holder device. One host serves one team.
Other owner devices cannot release the item keys.
Terminal prompts, desktop dialogs, and the host service still work. See section 11 for service commands and logs.

## 11. Runs and the host

Each run that passes the hard rules waits for the host of the owner. A run cannot start without a release. The relay cannot approve a run because it does not hold the keys.

Use the key-holder device of the selected team on the machine that holds `keys.json`.
For a legacy team, enroll the device with the procedure in section 9.
Use `apassy-team team use TEAM_ID` to select the enrolled team.
Replace `TEAM_ID` with the team ID from the enrollment output.
After enrollment, make a new agent token:

```sh
apassy-team agent create NAME --days 30 > agent-token-file
```

Replace `NAME` with the name of the agent.
Use the new token for the agent.
Legacy `apassy_agt_` tokens without a team ID stop at the member-token deadline of the team.
Enrollment does not extend this deadline.

To start the host on a terminal, use:

```sh
apassy-team host
```

To use desktop dialogs in the foreground, use:

```sh
apassy-team host --dialog
```

After an update to `apassy-team`, macOS can show one Keychain prompt for access to the device key.
Before you start the background host, run `apassy-team me` in a terminal.
If macOS shows this Keychain prompt, select **Always Allow**.
The background host cannot run before you select **Always Allow**.

To use file storage on macOS, set `APASSY_TEAM_KEY_STORE=file` before you make or enroll the device.
The CLI saves the key in `device-<team id>.key` next to `settings.json`, with mode 0600.
Use this variable for all foreground commands with the device.
The CLI does not copy a key from the Keychain to the file store.

The foreground host can also use file storage.
For a host service with file storage, set `APASSY_TEAM_KEY_STORE=file` in the service environment before the host starts.
A shell setting does not set the service environment.

To install and start the host as a user service, use:

```sh
apassy-team host install
apassy-team host status
```

The service must use the same saved relay URL and selected team as the shell.
The service must also use the key-holder device key.
Installation stops with different shell settings. The service file contains no token.
A service cannot use `APASSY_EDGE_SECRET` from the shell. Use a relay endpoint that operates without this variable.

The service starts at login and uses desktop dialogs. On macOS, it uses a LaunchAgent. On Linux, it uses a systemd user service. Keep the desktop session open for approval dialogs.

After installation, the host starts at each login until you remove the service. `--ask-all` and `--auto-limit N` also apply to `host install`:

```sh
apassy-team host install --ask-all --auto-limit 0
```

On Linux, the user service needs the environment of the desktop session. If dialogs cannot open, import the applicable variables:

```sh
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
systemctl --user restart apassy-team-host.service
```

To stop and remove the user service, use:

```sh
apassy-team host uninstall
```

The host must be online for each run. Without the host, a run expires after `APASSY_RELAY_APPROVAL_TIMEOUT` seconds (600 by default). The agent sees `timed_out`.

The host checks one run at a time, oldest first. It uses the metadata in `keys.json` and its own command analysis:

Each item must exist in `keys.json` for this relay. Otherwise, the host denies the run with "Unknown item on this host."

Automatic release requires all conditions below:

- `--ask-all` is absent.
- The relay suggests release without flags.
- No item has the `production` environment in `keys.json`.
- The host analysis identifies a known safe command without flags.
- Each item stays below the automatic release limit (30 per hour by default). `--auto-limit N` changes this limit.

`git status`, `ls -la`, `cargo test`, and `stripe balance retrieve` with a staging item are known safe commands.

Other runs need a decision from the owner. The host shows the agent, member, command, purpose, user request, working directory, items, environments, and flags. It also shows the relay note and the reason for approval.

On the terminal, the host asks `Release the keys for run 7? [y/N]`. Only `y` or `yes` releases the keys. All other answers deny the run. Without a terminal, the terminal mode denies the run with "No one at the host."

In dialog mode, only an explicit click on `Release` releases the keys. `Deny` is the default button. Return, Escape, a closed dialog, or a dialog error denies the run. A dialog timeout expires the request without a release. If fewer than five seconds remain, the host records an expired request without a dialog. A dialog never stays open beyond the expiry time of the run.

The host holds `host.lock` next to `keys.json` while it runs. A second host for the same key store cannot start. This lock also prevents a foreground host and the user service from running together.

Each request adds one line to `host.log` next to `keys.json`. The line gives the time, run id, agent, member, item uids, item names, and decision. Decisions are `auto`, `approved`, `denied`, `unknown_item`, `expired`, or `error`. The log contains no key.

The service writes process output to `~/Library/Logs/apassy-team-host.log` on macOS. On Linux, it writes process output to `service.log` next to `host.log`. Use `host.log` to check decisions and the process log to check service errors.

`--ask-all` requires approval for each run. `--auto-limit 0` prevents automatic release. Neither option permits an automatic approval of an unknown command.

The owner or a manager can examine and deny waiting runs from another machine:

```sh
apassy-team pending
apassy-team deny 7 --reason "Not this key"
```

`apassy-team approve` cannot release keys. The relay answers `approve_on_host`. The CLI says "The keys are on the owner's host. Approve there with apassy-team host."

- A run without a decision expires. The agent sees `timed_out`.
- If a member revokes an agent, grant, member, or item, the relay denies its waiting run with `approval_invalidated`.
- A wrong run, changed text, or wrong item set causes `release_invalid`. Each run key works once.
- The owner decides on the host terminal or in its desktop dialog.
- The host can release a run of the agent of the owner.

## 12. Audit

```sh
apassy-team audit --limit 50
apassy-team audit --after 120 --json
```

The audit records team changes, runs, decisions, sessions, and proxy requests. It never holds a value, a placeholder, a token, or a session key. Only the owner and managers can read it. No endpoint changes or deletes a row.

## 13. Backup

`apassy-relay admin backup` copies `relay.db`, every team file, and the vault sync snapshots of each team (`teams/<id>.sync/`, the current and the previous version) while the relay runs. Each file is copied while its connection is locked, so the copy is whole. A snapshot is copied while no push of its team can commit. The copy goes to a new folder `<APASSY_RELAY_BACKUP_DIR>/<UTC time>` (default `/backups`; mode 0700, files 0600), with `MANIFEST.json`: the name, size, and SHA-256 of each file, and the number of teams.

```sh
docker compose exec -T relay apassy-relay admin backup
```

- The files stay encrypted. `relay.db` opens with the master key; each team file opens with its own key, which is in `relay.db`. Keep the master key apart from the backups: a backup with the master key opens every team's metadata (never an item value).
- A suspended team is copied too.
- On the VPS the folder is `/opt/apassy/backups/relay`. `deploy/vps/backup/` has a daily timer (03:30 UTC, 14 days kept, at least the 3 newest), a weekly restore test, and a pull to the owner's Mac (see its README).
- To restore: stop the relay; put `relay.db` and `teams/` of one backup into an empty data volume (owner 10001, mode 0700, files 0600); start with the same master key. A team deleted after the backup comes back with it.
- A restored relay can hold an older vault snapshot than the Macs saw. The Macs then refuse it ("The relay has an older copy than this Mac saw") and keep their vaults; the owner turns relay sync off and on again on one Mac, and that Mac pushes again.
- Snapshots are each vault's SQLCipher file: encrypted with the vault's passphrase, which is not on the relay. They add up to about 128 MiB per team to a backup.

Also back up `keys.json` on each owner's machine (`~/.config/apassy-team/keys.json`, or under `$XDG_CONFIG_HOME`). It is plain text in the alpha, so keep the copy private and apart from the relay backups. Losing it means adding the items again. With a relay backup alone nobody can read a value, and with `keys.json` alone nobody can open anything.

## 14. Revocation

```sh
apassy-team agent revoke 2      # an agent token
apassy-team revoke --grant 5    # a grant
apassy-team member revoke 3     # a member (owner only)
apassy-team item archive 4      # an item
```

A revocation works at the next request. The relay looks up each token every time. Revoking an agent, a grant, a member, or an item ends the live sessions that depend on it at once, and denies the runs that are pending on it (`approval_invalidated`) and drops their keys.

To rotate a credential, archive the item and add a new one (`item add` makes a new key). There is no edit in the alpha.

To rotate the edge secret, change the file, restart the container, and run `wrangler secret put EDGE_SECRET` with the new text. The master key cannot be rotated in the alpha.

## 15. Limits and what this does not protect

What this does not protect:

- The relay does not store a readable value, but it sees a value in memory while its session lives. Root on the Mac or the VM, or a taken-over relay while it runs, can read the values of the sessions of that time. A stolen vault or backup gives only ciphertext.
- A relay that is taken over can make up a run. The host releases a known-safe command with a non-production item by itself, and one release is enough to learn a value, so such a relay can get the values of those items. Read `host.log`. Start the host with `--ask-all` (or `--auto-limit 0`) if you want to be asked every time. Production items always ask.
- `keys.json` on the owner's Mac is plain text in the alpha. Whoever reads it holds the item keys. Back it up, and protect it like the vault key.
- The host must be online for every run. Only the owner's host holds keys: a manager can deny a run but cannot release one, and there is no sharing of keys to another machine yet.
- A session key and a placeholder together work as a credential for the hosts of that item, in auth positions only, until the session ends. They can end up in an agent transcript if the agent runs the command itself.
- The relay and the host approve a stated command. They cannot check what the agent really runs with the session. The relay controls which hosts get the value, where the value goes in a request, and for how long.
- Cloudflare sees all traffic in clear, including session keys in paths and placeholders in headers. It no longer sees a value when an item is added: the CLI seals it first.
- The quick tunnel has no SLA and a changing URL.

What the alpha does not do:

- Way A (the member's Mac app gets a value for one run), and the model sidecar. With no model, only known-safe commands are released by the host by itself. Every other command asks the owner at the host.
- `CONNECT` and a run certificate. Workers cannot do `CONNECT`, so the relay rewrites base URLs.
- Team rule packs, grants to one agent, item edit, access requests from agents.
- Approvals in an app, on the web, or in Slack. The owner decides at the terminal of the host.
- Keep-alive to upstream hosts, HTTP/2, WebSocket, `Upgrade`, server-sent events through the tunnel.
- Rewriting of redirects. A `Location` header passes through. A client that follows it goes to the real host with a placeholder and fails.
- Compressed upstream responses (a 502), request bodies over 8 MiB (a 413), AWS SigV4 and other signed requests.
- Items that are not HTTP API keys, such as a Postgres URL.
- The `gh` CLI. Only `GITHUB_API_URL` is set.
- Sessions that survive a restart.
- TLS in the relay, several teams per relay, a key typed at start.

The full list is in section 2 of [SPEC.md](SPEC.md). The threat notes are in sections 20 and 21.

## 16. On a VPS

The live relay runs on a Linux VPS since 2026-10-01: `ssh ottervibe`, Debian 12, x86_64. Nothing on the VPS is public. The Worker reaches the relay through a Workers VPC binding and a named tunnel. The tunnel URL never changes, so a restart needs no Worker deploy.

```
agent ──HTTPS──▶ Worker apassy-relay.wyderka.cc   adds X-Apassy-Edge
   ──Workers VPC binding RELAY──▶ VPC service apassy-relay ──▶ tunnel apassy-relay
   ──▶ container apassy-relay-tunnel (cloudflared, outbound only)
   ──HTTP──▶ container apassy-relay  relay:8080, volume apassy-relay-data
```

| What | Where |
| --- | --- |
| Compose project | `apassy` in `/opt/apassy`, a copy of `deploy/vps/compose.yaml` |
| Image | `apassy-relay:host-keys-<commit>`, built on the VPS from `git archive` of that commit |
| Data | the volume `apassy-relay-data`: `relay.db` and `teams/` (owner 10001, mode 0600 and 0700) |
| Relay secrets | `/opt/apassy/secrets/relay/master_key` and `edge_secret`, owner 10001, mode 0400. `vault_key` is the key of the old `team.db.pre-teams` only |
| Tunnel token | `/opt/apassy/secrets/tunnel/token`, owner 65532 (cloudflared), mode 0400 |
| Tunnel | `apassy-relay`, id `044bd7e2-2257-4927-925b-f1f8c0796700` |
| VPC service | `apassy-relay`, id `01a0f70c-70ec-7882-9121-853d63b9eece`: host `relay`, HTTP port 8080 |
| Owner's check port | `127.0.0.1:8787` on the VPS only |

- The VPC service names the relay by the host name `relay`. Cloudflared looks it up with the DNS of its own container, which is Docker's DNS. Keep both containers in the same Compose project.
- The Worker uses the binding `RELAY` when it is set, and `RELAY_ORIGIN` only when it is not.
- `/opt/apassy/secrets` is root's, mode 0711. The user `otter` cannot read the files in it. Change them with `sudo`.
- The VPS also runs other services (Pretix, mail). The relay has its own limits: 2 CPUs, 512 MiB, 512 processes.

Check it:

```sh
curl https://apassy-relay.wyderka.cc/healthz
ssh ottervibe 'cd /opt/apassy && docker compose ps && docker compose logs --tail 20'
apassy-team me
```

Deploy a new commit:

```sh
git archive --format=tar HEAD | ssh ottervibe 'rm -rf /opt/apassy/build && mkdir -p /opt/apassy/build && tar -x -C /opt/apassy/build'
ssh ottervibe 'cd /opt/apassy/build && docker build -t apassy-relay:host-keys-<commit> .'
# Set the new tag in /opt/apassy/compose.yaml, then:
ssh ottervibe 'cd /opt/apassy && docker compose up -d --wait'
```

A restart ends every session (section 5).

Back up the vault as in section 13: `docker compose exec -T relay apassy-relay admin backup` writes to `/opt/apassy/backups/relay` on the VPS. The timer of `deploy/vps/backup/` does it every day.

The operator commands of section 17 run in the container:

```sh
ssh ottervibe 'cd /opt/apassy && docker compose exec relay apassy-relay admin teams'
```

Go back to the Mac:

1. On the VPS: `docker compose stop relay`. Copy `team.db` to the Mac volume if the VPS changed it.
2. On the Mac: start the container and a quick tunnel (sections 5 and 6).
3. In `deploy/worker/wrangler.jsonc`, remove `vpc_services` and set `RELAY_ORIGIN` to the tunnel URL. Then `wrangler deploy`.

## 17. Teams

One relay holds several teams (ADR 0019 of the core). Each team is its own file in `teams/`, with its own key, its own audit, and its own sessions. A token, an invite code, and a session key name their team (`apassy_mbr_t_7k2m5q4x3c_...`), and the relay looks a token up only in that team. People in one team cannot see another team, and the same person in two teams is two members.

The operator works on the server, with `apassy-relay admin` in the container. It talks to the running relay through `admin.sock` in the data directory. There is no operator page or endpoint.

**A new team.** The operator makes a one-time team code and gives it to the future owner, like a password:

```sh
docker compose exec relay apassy-relay admin team-code --hours 72 > team-code-file
```

The code is printed once. The future owner creates the team. It becomes the owner, and the settings are saved like `init` does:

```sh
apassy-team create --relay https://apassy-relay.wyderka.cc --team "Family" --name rafal < team-code-file
apassy-team me          # team Family (t_...): member rafal (id 1, owner)
```

A code works once. A typo in a name does not use it. The owner then invites members (section 9) and runs `apassy-team host` for the team's items (section 11). A host serves the team of its owner token.

**The teams.** `admin teams` shows the id, name, state, and effective limits of each team. For an active team, it also shows the member, item, and agent counts, the time of the last audit row, the vault sync version and the size of its snapshot (`sync_version`, `sync_size`; 0 without a snapshot), and the counts of open questions and push tokens (`open_questions`, `push_tokens`). It shows no names of people or items, no runs, and no audit.

**Team limits.** Each team starts with these limits:

| Field | Default |
| --- | --- |
| `members` | 50 |
| `items` | 500 |
| `agents` | 100 |
| `runs_per_hour` | 1000 |
| `pending_runs` | 50 |
| `agent_requests` | 56 |
| `sync_bytes` | 67108864 (64 MiB) |
| `sync_pushes_per_hour` | 600 |
| `sync_transfers` | 2 |
| `open_questions` | 20 |
| `questions_per_hour` | 300 |
| `member_open_questions` | 15 |
| `member_questions_per_hour` | 225 |
| `device_open_questions` | 10 |
| `device_questions_per_hour` | 150 |
| `question_bytes` | 8388608 (8 MiB) |

Read all effective values:

```sh
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c
```

Change only the necessary fields:

```sh
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --members 25 --items 200
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --agents 40 --runs-per-hour 500 --pending-runs 20 --agent-requests 28
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --sync-bytes 33554432 --sync-pushes-per-hour 300 --sync-transfers 4
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --open-questions 40 --questions-per-hour 600
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --device-open-questions 20 --member-open-questions 30 --question-bytes 16777216
```

The command prints all sixteen effective values. If a field has no flag, its value stays the same. Values must be integers from 1 to 1000000; `items` and `agents` may also be 0 (none, as in a Connect team, section 20). The `agent_requests` range is 1 to 224. The `sync_bytes` range is 0 (no vault sync: a push answers 403 `plan_required`) or 1048576 to 67108864 (the largest vault snapshot, in bytes; 64 MiB is also the most that the app and the head grammar allow), and the `sync_transfers` range is 1 to 8 (snapshot uploads and downloads of the team at once; over it, 503 `busy`). The relay also allows at most 16 snapshot transfers of all teams at once. The `open_questions` range is 1 to 1000 (questions that wait for an answer; over it, 403 `too_many_questions`, see section 19); `questions_per_hour` is 1 to 1000000. `member_open_questions` and `device_open_questions` (1 to 1000) and `member_questions_per_hour` and `device_questions_per_hour` (1 to 1000000) are the shares of one member and of one asking device, so one Mac cannot use the team's whole quota. `question_bytes` (1048576 to 268435456) bounds the sealed questions and answers that the team file holds at once.

A question limit changed away from its default is stored in `relay.db` in a form the image before questions cannot read: a rollback to it then needs the backup of `relay.db` (section 19.3). Change question limits only when no rollback is planned, or note the change.

Use the command for active or suspended teams. A change adds `limits_changed` with actor `operator` to the team audit and relay audit.

Members without revocation use member slots. Items without archive status use item slots. Agents without revocation or expiry use agent slots. Agents of revoked members do not use slots. The hourly limit counts all run rows from the last 3600 seconds. It also counts denials.

The pending limit counts runs with status `pending`.

A count limit returns HTTP 403 `team_limit`. A full agent request limit returns HTTP 503 `busy`, with `Retry-After: 2`. Member requests and the host of the owner keep the global member reserve. The team audit records a limit refusal at most once per field per ten seconds.

New limits apply immediately. A lower limit does not remove existing data or stop existing runs. New operations can start only if the applicable limit permits them. Limits stay in `relay.db` after a restart.

The relay automatically changes directory version 1001 to 1002 at start. The new nullable `limits TEXT` column holds JSON. A null column or an absent JSON field uses the default. The column change and version change use one transaction. Unknown versions stop the relay.

**Vault sync.** A team can hold one vault snapshot of the Apassy app (docs/SPEC.md section 24): the encrypted SQLCipher file of the vault, with a head signed by the device that pushed it. The relay keeps the current and the previous version in `teams/<id>.sync/` and never opens them. A team made by the app for its vault has one owner and the owner's Macs as devices. The audit of the team records `sync_pushed`, `sync_fetched`, `sync_received`, and `sync_deleted`, with versions, device ids, and sizes only.

The first start of this version moves each team file to schema version 4: it copies the file to `teams/<id>.db.pre-v4` (the way back for an older image), then adds the two sync tables. A team whose copy cannot be made stays at version 3 and does not open; free disk space and start again. Delete `.pre-v4` files when you no longer need the older image.

**Suspend, resume, delete.**

```sh
docker compose exec relay apassy-relay admin suspend t_7k2m5q4x3c
docker compose exec relay apassy-relay admin resume t_7k2m5q4x3c
docker compose exec relay apassy-relay admin delete t_7k2m5q4x3c   # only a suspended team; no undo
```

A suspended team's tokens fail at the next request; its sessions and waiting runs end. Each action is a row in the audit of the team (actor `operator`) and of the relay. Delete waits for the requests that started before the suspension, then removes the team's key from `relay.db`, its file, and its vault snapshots. Old backups still hold them (section 13).

**A team that does not open.** If a team file is missing or damaged, the relay still starts and serves the other teams. It logs the team, and `admin teams` shows it with `"open": false`. Suspend and delete it, or put the file back, then suspend and resume it.

**One relay per data directory.** `serve`, `init`, and `migrate` hold `relay.lock` in the data directory. A second relay on the same volume (for example `docker compose run relay` while the relay runs) refuses to start.

**The relay's own addresses.** The proxy refuses private addresses by itself. Add the public addresses of the VPS so that a team cannot reach its other services through the proxy: `APASSY_RELAY_BLOCKED_ADDRESSES=9.9.9.117,2620:fe:0:7491::/64` (in `deploy/vps/compose.yaml`).

**What the operator can see.** The master key and every team file are on the same machine. The operator, root on the VPS, or a disk snapshot can open the names, members, hosts, commands, and audit of every team. Item values stay sealed: their keys are on each owner's machine. Tell the owners this.

**From a relay before teams.** A data volume with one `team.db` must be migrated once. With the relay stopped:

```sh
openssl rand -hex 32 > master_key                 # the new master key
docker compose run --rm \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/relay/master_key \
  -e APASSY_RELAY_OLD_KEY_FILE=/run/secrets/relay/vault_key \
  relay migrate                                     # prints the new team id
```

`migrate` copies `team.db` into `teams/<id>.db` with a new random key, makes `relay.db` with the master key, and renames the old file to `team.db.pre-teams` (it opens with the old key only). The master key must be new: `migrate` refuses the old vault key. A failure before `relay.db` is written leaves `team.db` as it was, and a new `migrate` starts over. A stop after it is finished by the next start. The old owner token, member tokens, agent tokens, and `keys.json` keep working for the migrated team. New tokens of that team name it. An invite code made before the migration stops working: make a new one. Delete `team.db.pre-teams` and the old vault key when you no longer need a way back.

## 18. Install, guide, and limits at the edge

The Worker serves three things itself, without the relay and without the edge secret:

| Path | What |
| --- | --- |
| `/install.sh` | installs `apassy-team` into `~/.local/bin` after a SHA-256 check (`deploy/worker/public/install.sh`) |
| `/guide` | the alpha guide for owners and members (`deploy/worker/public/guide.html`; source `docs/ONBOARDING.md`) |
| `/dl/*` | the CLI binaries and `SHA256SUMS` |

Users install with:

```sh
curl -fsSL https://apassy-relay.wyderka.cc/install.sh -o install.sh && sh install.sh
```

The binaries are not in git (`deploy/worker/public/dl/` is ignored). Before `wrangler deploy`, put them there:

- `apassy-team-darwin-arm64`: `cargo build --release --locked --bin apassy-team` on an Apple silicon Mac.
- `apassy-team-linux-x86_64`: the same in a `rust:1.97.0-bullseye` container (glibc 2.31, so it runs on Debian 11 and Ubuntu 20.04 or later), then `strip`.
- `SHA256SUMS`: `shasum -a 256 apassy-team-* > SHA256SUMS` in that folder.

The installer refuses a binary whose checksum is not in `SHA256SUMS`. A missing platform is a clear error.

`POST /v1/join`, `POST /v1/teams`, `POST /v1/devices/link`, and `POST /v1/devices/link/cancel` have a limit per IP address at the Worker: about 10 a minute (Workers Rate Limiting, binding `CREATE_LIMITER`). `POST /v1/connect` has its own, 1 a minute per IPv4 address or IPv6 /64 (`CONNECT_LIMITER`, section 20). Device sign-in (`POST /v1/auth/challenge` and `/v1/auth/token`) has a looser one, about 60 a minute (`AUTH_LIMITER`), because a waiting CLI asks every 5 seconds and several people can share one address. Vault snapshot pushes (`PUT /v1/sync/snapshot`) have their own, about 60 a minute (`SYNC_LIMITER`). Over it, the Worker answers 429 `rate_limited` and the request does not reach the relay. The count is kept in each Cloudflare location and is approximate, so a burst can pass a few more. If the limiter fails, or its binding is missing, requests go on: the relay checks every code itself. The four bindings are in `wrangler.jsonc`; a deploy creates them.

The Worker also checks the declared length of every request body before it forwards it, because the relay reads every declared byte of a body even when it answers early, on any path (docs/SPEC.md section 24.10). A snapshot push (exactly `PUT /v1/sync/snapshot`) with `Transfer-Encoding` or with a missing or non-numeric `Content-Length` gets 400 `invalid_request`; one that declares more than 64 MiB plus 64 KiB gets 413 `payload_too_large`. A body under `/p/` (the agent proxy) may declare up to 8 MiB plus 64 KiB; every other body, on any other path or method (`PUT /v1/sync/snapshot/` or `POST /v1/sync/snapshot` included), up to 128 KiB. Above that: 413; a non-numeric length: 400. The relay keeps its own checks. This bounds bytes, not time: a client that sends a body slowly still holds a relay thread until the connection ends, and only pushes are rate-limited.

A workflow in `.github/workflows/health.yml` checks `/healthz` and `/v1/me` (401) every hour. A failed run is the alert: GitHub notifies the owner of the repository.

## 19. Questions and push (team schema 5)

The relay carries the questions of an agent broker from the asking Mac to the other devices of the vault, and wakes iPhones with a push notification without content (docs/SPEC.md section 25; the app's contract is `docs/contracts/relay-questions-v1.md` of the core). It stores sealed envelopes for at most 24 hours and never reads them. The Worker sends the Apple pushes; the relay asks it to, with its own push secret.

What changes at the first start of this version:

- Each team file moves to schema version 5: the relay copies it to `teams/<id>.db.pre-v5` (the way back for an older image, mode 0600), then adds the tables `question`, `question_answer`, `push_token`, `device_wrapped_key`, and the column `team.question_seq` in one transaction. The change is additive: no table is rebuilt, sync rows stay. A team whose copy cannot be made stays at version 4 and does not open; free disk space and start again. The previous image (`sync-*`, schema 4) refuses a version 5 file.
- New routes in the member lane: `/v1/questions`, `/v1/questions/{qid}/answers`, `/v1/questions/{qid}/settle`, `/v1/push/token`. Question long polls have their own 128 threads, apart from the 256 of section 15, so they never take the member reserve.
- New team limits, section 17: `open_questions` (20) and `questions_per_hour` (300) of the team, the shares of one member (15, 225) and of one asking device (10, 150), and `question_bytes` (8 MiB of sealed questions and answers at once). Over any: 403 `too_many_questions` (for an answer over `question_bytes`: 403 `too_many_answers`), and the question stays on the asking Mac. A question has at most 20 answers.
- Ten minutes after a question is settled or expired, the relay deletes its answers and its sealed card and settle; the row (devices, times, state) goes 24 hours after the post.
- One team holds at most 32 of the 128 question long-poll threads; more polls of that team return at once. A long poll of a device that is revoked, or whose member's role changes, ends with 401 at once.
- `to: "approvers"` questions are refused (403 `not_routed`) until shared vaults. `APASSY_RELAY_QUESTIONS_TO_APPROVERS=1` turns them on; leave it unset.
- The audit gets `question_*` and `push_*` rows with device ids and counts only.

### 19.1 Push: what is where

| What | Where | Kind |
| --- | --- | --- |
| `APNS_KEY` | Worker | secret: the text of the Apple `.p8` key (APNs, team `7S3F9767BM`) |
| `PUSH_SECRET` | Worker | secret: 64 hex characters, the same as the relay's push secret |
| `APNS_KEY_ID` | Worker, `wrangler.jsonc` `vars` | the Key ID of the `.p8` key (empty in git: set it before the deploy) |
| `APNS_TEAM_ID`, `APNS_TOPIC` | Worker, `wrangler.jsonc` `vars` | `7S3F9767BM`, `com.wydrox.apassy.companion` |
| `/opt/apassy/secrets/relay/push_secret` | VPS | the push secret, owner 10001, mode 0400 |
| `APASSY_RELAY_PUSH_URL`, `APASSY_RELAY_PUSH_TOPIC`, `APASSY_RELAY_PUSH_SECRET_FILE` | `/opt/apassy/compose.yaml`, service `relay`, `environment` | `https://apassy-relay.wyderka.cc/internal/push`, `com.wydrox.apassy.companion`, `/run/secrets/relay/push_secret` |

- The relay needs all three push variables or none. None: push is off and the relay logs `push is off` once at start; questions still reach the devices by their long polls, and `PUT /v1/push/token` answers 409 `push_unavailable`. Some but not all: the relay does not start.
- The `.p8` key never goes on the VPS, into git, or into an image. It is only a Worker secret.
- The push secret goes only from the relay to the Worker (`X-Apassy-Push`); the edge secret only from the Worker to the relay. Rotate it like the edge secret (section 14): a new file on the VPS, a restart, and `wrangler secret put PUSH_SECRET` with the same text.

### 19.2 Owner steps for the deploy

Run them in this order. Steps 1 to 4 change nothing on the live relay.

1. **The A4 spike.** Can a Worker reach APNs over HTTP/2? From `deploy/worker/`:

   ```sh
   npx wrangler dev --remote -c spike/wrangler.jsonc     # runs on Cloudflare's network, deploys nothing
   curl -s http://127.0.0.1:8787/                        # in another terminal
   ```

   Expect `"status":403`, `MissingProviderToken`, and `"ok":true`. Stop wrangler with Ctrl-C. Anything else: stop here; push needs the fallback of SPEC 25.7 (the APNs key on the VPS), which is the owner's decision and is not built. Write the result in this section.

2. **The APNs key.** In the Apple Developer account (team `7S3F9767BM`), Certificates, Identifiers & Profiles, Keys: make a key with Apple Push Notifications service (APNs), environment Sandbox & Production. Download the `.p8` once and put its text into an Apassy item (for example "APNs key"). Note its Key ID. Set `APNS_KEY_ID` in `deploy/worker/wrangler.jsonc` to it.

3. **The secrets.** Make the push secret on the Mac and copy it to the VPS and the Worker without typing or echoing it:

   ```sh
   umask 077; openssl rand -hex 32 > ~/.apassy-relay/push_secret
   ssh ottervibe 'sudo sh -c "umask 077; cat > /opt/apassy/secrets/relay/push_secret && chown 10001:10001 /opt/apassy/secrets/relay/push_secret && chmod 0400 /opt/apassy/secrets/relay/push_secret"' < ~/.apassy-relay/push_secret
   cd deploy/worker
   npx wrangler secret put PUSH_SECRET < ~/.apassy-relay/push_secret
   ```

   Put the key through Apassy (`apassy_run_with_secrets` with the item of step 2, from `deploy/worker/`):

   ```sh
   printf '%s' "$APNS_KEY" | npx wrangler secret put APNS_KEY
   ```

4. **The Worker.** It must serve `/internal/push` before the relay calls it. Test and deploy (section 7):

   ```sh
   cd deploy/worker && npm test && npm run typecheck && npx wrangler deploy
   curl -s -o /dev/null -w '%{http_code}\n' -X POST https://apassy-relay.wyderka.cc/internal/push   # 404: no secret
   curl -s https://apassy-relay.wyderka.cc/healthz                                                # ok
   ```

   Optional: a call with the secret and a token of 64 zeros (through Apassy, never on the command line) answers `{"results":[{"token":"00…","status":400,"reason":"BadDeviceToken"}]}`: Apple took the provider token. `403` with `InvalidProviderToken` means a wrong key, Key ID, or team id.

5. **The backup.** Note the image the relay runs now (the rollback target), then back up:

   ```sh
   ssh ottervibe 'grep "image: apassy-relay" /opt/apassy/compose.yaml'     # for example apassy-relay:sync-4208643
   ssh ottervibe 'cd /opt/apassy && docker compose exec -T relay apassy-relay admin backup'
   ```

   Keep the folder name it prints (`/opt/apassy/backups/relay/<UTC time>`).

6. **The relay.** Build the image of the commit, as in section 16, with the tag `apassy-relay:questions-<commit>`:

   ```sh
   git archive --format=tar <commit> | ssh ottervibe 'rm -rf /opt/apassy/build && mkdir -p /opt/apassy/build && tar -x -C /opt/apassy/build'
   ssh ottervibe 'cd /opt/apassy/build && docker build -t apassy-relay:questions-<commit> .'
   ```

   In `/opt/apassy/compose.yaml` (and in `deploy/vps/compose.yaml`, committed with the deploy) set `image: apassy-relay:questions-<commit>` and add to `environment` of `relay`:

   ```yaml
      APASSY_RELAY_PUSH_URL: https://apassy-relay.wyderka.cc/internal/push
      APASSY_RELAY_PUSH_TOPIC: com.wydrox.apassy.companion
      APASSY_RELAY_PUSH_SECRET_FILE: /run/secrets/relay/push_secret
   ```

   Then:

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose up -d --wait'
   ```

7. **Checks.**

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose logs --tail 20 relay'            # no "cannot be moved to schema version 5", no "push is off"
   ssh ottervibe 'cd /opt/apassy && docker compose exec relay ls -l /data/teams'     # a .db.pre-v5 next to each .db
   ssh ottervibe 'cd /opt/apassy && docker compose exec relay apassy-relay admin teams'   # every team "open": true, with open_questions and push_tokens
   curl -s https://apassy-relay.wyderka.cc/healthz
   apassy-team me
   ```

   A Mac with relay sync still syncs (its sync rows are untouched). The first push shows as `push_sent` in the team audit; a `push_failed` with `reason: "worker"` means the relay could not reach the Worker or the secrets differ.

8. **Later.** Delete the `.pre-v5` files when no rollback to schema 4 is needed any more (they hold the team as it was at the migration).

### 19.3 Rollback

- **Push only.** Remove the three `APASSY_RELAY_PUSH_*` lines from `compose.yaml` and `docker compose up -d --wait`: push is off, questions still work. Or leave the relay and remove `PUSH_SECRET` from the Worker (`npx wrangler secret delete PUSH_SECRET`): `/internal/push` answers 404 and the relay records `push_failed`.
- **The Worker.** The new Worker serves every old route as before. To go back: `npx wrangler rollback` (to the previous version), or deploy the previous commit of `deploy/worker/`.
- **The relay image.** The previous image refuses the version 5 team files, so a rollback puts the version 4 copies back. It also refuses a `limits` column in `relay.db` with a field it does not know: the new relay writes the question limits there only when one differs from its default (section 17). If any `admin limits` call changed a question limit after the deploy, restore `relay.db` from the backup of step 5 too (below), or set every question limit back to its default with the new image still running before you stop it:

  ```sh
  docker compose exec relay apassy-relay admin limits <team id> --open-questions 20 --questions-per-hour 300 \
    --member-open-questions 15 --member-questions-per-hour 225 --device-open-questions 10 \
    --device-questions-per-hour 150 --question-bytes 8388608
  ```

  Restoring `relay.db` from the backup also undoes every other change of the directory since step 5 (teams made, suspended, or deleted, other limits).

  Putting the version 4 copies back loses every change of the teams since the migration: questions and push tokens (the iPhones send their tokens again), and also members, devices, and vault sync heads made after it. A Mac that pushed a snapshot after the migration then sees an older copy on the relay (section 13). Prefer a fix forward when the problem is not the migration itself.

  On the VPS (`ssh ottervibe`, then `cd /opt/apassy`):

  ```sh
  docker compose stop relay
  docker compose run --rm --no-deps --entrypoint bash relay -c '
    set -e
    for j in /data/teams/*.db-journal /data/relay.db-journal; do
      if [ -e "$j" ]; then echo "$j is left: the relay did not stop cleanly. Stop here." >&2; exit 1; fi
    done
    for f in /data/teams/*.db.pre-v5; do cp -p "$f" "${f%.pre-v5}"; done
    ls -l /data/teams'
  ```

  A `*.db-journal` next to a file means a write was cut off (the relay uses `journal_mode=DELETE`). SQLite would replay it into the copied version 4 file at the next open and break it. Do not delete it and do not copy over it: start the new image once (`docker compose up -d --wait`), let it open and close the files cleanly, stop it, and run the step again. If the journal stays, restore the backup of step 5 instead.

  When a question limit was changed after the deploy (above), also put `relay.db` of the step 5 backup into the volume now, with the relay stopped (section 13).

  Then set the image noted in step 5 (for example `apassy-relay:sync-4208643`) in `/opt/apassy/compose.yaml`, remove the three `APASSY_RELAY_PUSH_*` lines, and start:

  ```sh
  ssh ottervibe 'cd /opt/apassy && docker compose up -d --wait && docker compose exec relay apassy-relay admin teams'
  ```

  Every team must be `"open": true`. If the relay does not start and the log names the directory or a team's limits, `relay.db` holds a question limit (above): restore it from the backup of step 5. A team made after the migration has no `.pre-v5` and is version 5 from the start: the old image cannot open it; suspend it, or restore the backup of step 5 instead (section 13: put `relay.db` and `teams/` of that folder into the volume with the relay stopped). The backup of step 5 is the same state as the `.pre-v5` files, plus `relay.db` and the snapshots.

## 20. Connect teams (directory 1003)

On the Free plan the Mac app makes its own team, without a team code, the first time its owner adds a device: a Connect team (docs/SPEC.md section 26). It is an ordinary team with one member, `owner`, whose devices are the Mac that made it and the devices it confirmed with safety words. It carries questions (section 19) and no vault sync. Nobody gives out a code, so the bounds below are what keeps the relay small: every write path and long poll that such a team can reach has a count, a rate, or a byte cap.

What changes at the first start of this version:

- `relay.db` moves from version 1002 to 1003 in one transaction: the column `team.kind` (every existing team becomes `operator`), the column `team.suspend_reason`, and the table `connect_key` (the SHA-256 of each public key that made a Connect team, with the id of its team while the team exists). The change is additive. A failure leaves 1002 and the relay does not start. The image before (`questions-*`, directory 1002) refuses a 1003 file: see 20.3. Team files do not change.
- A new edge route, `POST /v1/connect`. Its body carries a signature of the device key (SPEC 26.3), so only the holder of a key can make a team with it. `POST /v1/teams` and team codes work as before.
- Two settings:
  - `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` (default 200, 0 to 100000): the Connect teams of the whole relay in any 24 hours. Over it, 503 `busy` with `Retry-After: 3600`.
  - `APASSY_RELAY_CONNECT_TEAMS_MAX` (default 1000, 0 to 1000000): the Connect teams the relay holds at once, active or suspended. At it, 503 `busy` ("no room") with `Retry-After: 3600`. A deleted team frees its place.

  Either at `0` turns Connect off without a deploy. Each refusal writes a `connect_refused` row to the relay audit (at most one per reason and ten seconds).
- One device key makes at most one Connect team, ever; the same key again gets 409 `connect_key_used`.
- One client network (an IPv6 /48 or an IPv4 /24, which the Worker sends in `X-Apassy-Client-Prefix`) makes at most 5 Connect teams per UTC day, and never more than a tenth of the daily cap; over it 429 `rate_limited` until the next UTC day. The relay counts this **in memory only**: it keeps an HMAC of the prefix under a random salt that it makes at the first call of each UTC day and forgets with the counts at the next. No file, log line, or audit row of the relay holds an address or a prefix, and a restart forgets the counts. Calls without the header (a Worker from before this version) all share one count.
- A Connect team starts with these limits, and every other limit at its default (section 17):

  | Field | Connect | Why |
  | --- | --- | --- |
  | `members` | 1 | one person; more devices come by device links (10 per member). Invites are refused |
  | `items`, `agents` | 0 | no runs and no use of the agent proxy: a free team must not be an open HTTP proxy. Collections, policies, and grants are refused |
  | `sync_bytes` | 0 | no vault sync on the relay: a snapshot push and a receipt answer 403 `plan_required` |
  | `question_bytes` | 2097152 (2 MiB) | about 60 waiting questions |

- A Connect team's file is capped at `question_bytes` + 8 MiB (10 MiB at the preset; more when `admin limits` gives it items or members). A write past the cap is 403 `team_limit` for that team only. Near the cap, the maintenance pass drops the oldest quarter of that team's audit and writes one `audit_trimmed` row. Operator teams have no file cap and keep their whole audit.
- A Connect team makes at most 300 authenticated requests a minute (429 `rate_limited` over it); all Connect teams together hold at most 64 long polls and at most half of the push queue (2 jobs per team), so they can take neither the threads of members nor the pushes of operator teams. Long polls that can get nothing (`GET /v1/sync/head` with `sync_bytes` 0, `GET /v1/host/requests` with `agents` 0) answer at once.
- For every team: a repeated sync receipt or push token writes no new audit row; expired or refused device links go after 7 days (at most 100 stay); a public key must be a point on P-256 (`/v1/teams`, `/v1/join`, `/v1/devices/link`, and sign-in refuse others).
- The maintenance pass of every team runs on its own thread; a Connect team without requests is passed every 60 seconds instead of every 5. At start the team files open on up to 8 threads (20.5).
- The ranges of three limits change for every team: `--items 0` and `--agents 0` are allowed (none), and `--sync-bytes 0` is allowed (no vault sync). To give one Connect team vault sync by hand: `apassy-relay admin limits <id> --sync-bytes 67108864`. `--sync-bytes 0` later blocks pushes and receipts only: snapshots pushed before can still be downloaded until `DELETE /v1/sync` or the team's deletion.
- `admin teams` shows `kind` (`operator` or `connect`) and `suspend_reason` for each team. The sign-in answer and `GET /v1/me` carry `team_kind`.
- A new admin command, `connect-sweep` (20.4). It does not run by itself.
- The Worker has two new rate limit bindings for `POST /v1/connect`: `CONNECT_LIMITER` (namespace `1004`, 1 a minute per IPv4 address or IPv6 /64) and `CONNECT_PREFIX_LIMITER` (namespace `1005`, 3 a minute per IPv4 /24 or IPv6 /48). Workers Rate Limiting counts only per 10 or 60 seconds, so the daily bounds are the relay's. Like the others, the bindings fail open. The Worker also sets `X-Apassy-Client-Prefix` on that route and removes a client's copy of it everywhere.

### 20.1 What to watch

- `admin teams`: the number of `connect` teams against `APASSY_RELAY_CONNECT_TEAMS_MAX`.
- The relay audit (`relay.db`, section 12): `team_created` rows with `"kind":"connect"`, and `connect_refused` rows with their `reason`: `busy` (the daily cap is full), `full` (the room is full), `rate_limited` (one network made its teams of the day), `prefixes_full` (more than 65536 networks in a day). Many `busy` or `full` refusals mean someone makes teams in bulk, or the app grew: raise or lower the caps, set either to 0 and restart the relay, or run the sweep. Many `rate_limited` refusals right after a deploy mean the Worker does not send the prefix header (20.2 step 2).
- Disk: Connect teams take at most `APASSY_RELAY_CONNECT_TEAMS_MAX` × 10 MiB (about 10 GiB at the defaults), plus one journal while a transaction runs. The backup copies each file (section 13), so a backup can be as large.
- A team's audit with `audit_trimmed` rows: a Connect team that writes a lot (or tries to fill its file).
- The start time of the relay (20.5).

### 20.2 Owner steps for the deploy

This version is built on the questions image of section 19 (team schema 5). Deploy section 19 first, or both together: the backup of 19.2 step 5 then serves both.

1. **The backup.** Note the image the relay runs now (the rollback target), then back up, as in 19.2 step 5. Keep the folder name: its `relay.db` is the way back to directory 1002.
2. **The Worker, first.** It must have `CONNECT_LIMITER`, `CONNECT_PREFIX_LIMITER`, and the prefix header before the app calls `/v1/connect`: without the header the relay counts every call as one network, so the whole relay makes at most 5 Connect teams a day. Test and deploy (section 7):

   ```sh
   cd deploy/worker && npm test && npm run typecheck && npx wrangler deploy
   ```

   A Worker with the bindings in front of the old relay is harmless: `POST /v1/connect` gets 404 from the relay, and the old relay ignores the new header.
3. **The relay.** Build and set the image of the commit as in 19.2 step 6, with the tag `apassy-relay:connect-<commit>`. Keep the caps at their defaults, or set them in `environment` of `relay` in `/opt/apassy/compose.yaml` (and `deploy/vps/compose.yaml`):

   ```yaml
      APASSY_RELAY_CONNECT_TEAMS_PER_DAY: "200"
      APASSY_RELAY_CONNECT_TEAMS_MAX: "1000"
   ```

   Size `APASSY_RELAY_CONNECT_TEAMS_MAX` to the free disk of the volume: 10 MiB a team, twice that with backups. Then `docker compose up -d --wait`.
4. **Checks.**

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose logs --tail 20 relay'                   # no "unknown version"
   ssh ottervibe 'cd /opt/apassy && docker compose exec relay apassy-relay admin teams'   # every team "open": true, "kind": "operator"
   curl -s -o /dev/null -w '%{http_code}\n' https://apassy-relay.wyderka.cc/v1/connect          # 405: the route exists (GET)
   curl -s -X POST -H 'content-type: application/json' -d '{}' https://apassy-relay.wyderka.cc/v1/connect   # 400 invalid_request
   apassy-team me
   ```

   The first Connect team made by the app shows in `admin teams` as `"kind": "connect"` with the limits above, and its first `admin teams` after a restart still `"open": true`.

### 20.3 Rollback

1. **First, stop new Connect teams.** Set `APASSY_RELAY_CONNECT_TEAMS_PER_DAY: "0"` (or `APASSY_RELAY_CONNECT_TEAMS_MAX: "0"`) and `docker compose up -d --wait`. Existing Connect teams keep working; new calls get 503. This needs no rollback of anything, and it is the step to take before either rollback below.
2. **The Worker.** The new Worker serves every old route as before; `npx wrangler rollback` goes back. **After a Worker rollback, `POST /v1/connect` has no edge limiter (or only the first one) while the relay stays on the new image**, and no prefix header: the relay then counts every call as the one network `unknown` (at most 5 new teams a day for the whole relay) and still applies its daily cap and room. That is why step 1 comes first: keep the cap at 0 until the Worker with both bindings is back.
3. **The relay image.** The image before (directory 1002) refuses a 1003 `relay.db`, and the limits of a Connect team (`sync_bytes` 0, `items` 0, `agents` 0) are out of its ranges. So a rollback to it restores `relay.db` from the backup of 20.2 step 1. The team files stay as they are (they do not change in this version). With the relay stopped (section 13):

   ```sh
   docker compose stop relay
   # put relay.db of the step 1 backup into the volume, as in section 13
   ```

   Then set the old image in `/opt/apassy/compose.yaml`, remove `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` and `APASSY_RELAY_CONNECT_TEAMS_MAX`, and `docker compose up -d --wait`. Every team must be `"open": true` in `admin teams`.

   What the restore loses: every team made after the backup, Connect or operator (its file stays in `teams/` with no key anywhere; the old relay ignores it; delete those files when you are sure), and every change of `relay.db` since the backup (limits set, teams suspended, resumed, or deleted, team codes made). Members, devices, questions, and sync heads of the teams that existed before stay, because they are in the team files. Every Mac with a Connect team then gets 401 at sign-in and makes a new team when the app calls `/v1/connect` again: that also fails on the old image (404), so Free users have relay questions again only after a fix forward. Prefer step 1 and a fix forward.

### 20.4 Idle Connect teams

A Connect team whose devices have not signed in for 30 days is most likely abandoned, however many devices it linked. The sweep suspends such teams, then deletes them 30 days after their suspension. It touches only Connect teams whose limits are still the Connect preset and that have no vault sync head: never operator teams, teams a plan or `admin limits` lifted, teams that synced a vault, or teams the operator suspended:

```sh
docker compose exec relay apassy-relay admin connect-sweep --dry-run       # names the teams, changes nothing
docker compose exec relay apassy-relay admin connect-sweep                 # --idle-days 30 --delete-days 30
```

The answer lists `suspended`, `deleted`, and `failed` team ids. A suspended team gets `"suspend_reason": "idle"` in `admin teams` and `team_suspended {"reason":"idle"}` in the team and relay audit. Its devices get 401 at the next sign-in, and the app connects again with a new key. During the suspension, `admin resume <id>` brings a team back (and clears the reason). A deleted team's key stays used, and no longer names the team. Suspended teams still count against `APASSY_RELAY_CONNECT_TEAMS_MAX` until they are deleted. Take a backup before the first real run.

The relay does not schedule it. To run it once a day, the owner can add a cron line on the VPS after the first manual runs, for example `17 4 * * * cd /opt/apassy && docker compose exec -T relay apassy-relay admin connect-sweep >> /opt/apassy/logs/connect-sweep.log 2>&1`; that is not set up.

### 20.5 Start time and open files

Every active team is opened at start, and each open derives the key of its file with PBKDF2-HMAC-SHA512 at 256 000 rounds: about 0.11 s of one core (measured on the build Mac; a shared VPS core is slower, about 0.15 to 0.25 s). The relay opens the files on up to 8 threads (no more than the cores), and it does not listen until all are open, so `/healthz` is down meanwhile. At the defaults (1000 Connect teams) that is about 110 to 250 s of CPU, so about 30 to 60 s on 4 cores. The healthcheck of `deploy/vps/compose.yaml` (10 s start period, then 3 tries 30 s apart) allows about 100 s; with more teams, raise its `start_period` or lower `APASSY_RELAY_CONNECT_TEAMS_MAX`. Each open team also holds one SQLite connection (one file descriptor and its page cache) for as long as the relay runs; suspended teams hold none.

Opening Connect teams only when they are first used, and closing idle ones, would remove this cost. It is not built: `Hub::team` is how every request, the sweep, `admin teams`, and the backup find a team, and an open on first use would let an unauthenticated sign-in call with a known team id start a key derivation. Lower the room, or run the sweep, if the start grows too long.
