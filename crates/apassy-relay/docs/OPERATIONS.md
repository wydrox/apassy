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

It prints `ok`. Then log in as the owner:

```sh
apassy-team init --relay https://apassy-relay.wyderka.cc < ~/.apassy-relay/owner_token.txt
apassy-team me
```

`init` checks the token with the relay and saves the settings in `~/.config/apassy-team/settings.json` (or under `$XDG_CONFIG_HOME`). The directory has mode 0700 and the file 0600. The token is plain text in that file in the alpha.

To talk to the container directly, without the Worker, set the edge secret and use the local URL:

```sh
export APASSY_EDGE_SECRET="$(cat ~/.apassy-relay/edge_secret)"
apassy-team init --relay http://127.0.0.1:8080 < ~/.apassy-relay/owner_token.txt
```

The CLI accepts plain `http://` only for `127.0.0.1`, `::1`, and `localhost`.

Settings come from these variables first, then from the file:

| Variable | Meaning |
| --- | --- |
| `APASSY_RELAY_URL` | the relay origin |
| `APASSY_TEAM_TOKEN` | a member token |
| `APASSY_TOKEN` | an agent token (for `access`, `run`, `mcp`) |
| `APASSY_EDGE_SECRET` | optional; adds `X-Apassy-Edge` |

## 9. Team setup walkthrough

The owner makes a collection, adds an item, and invites a member:

```sh
apassy-team collection create payments --mode bouncer
apassy-team item add --collection 1 --name "Stripe test" --env STRIPE_API_KEY \
  --environment staging --provider stripe < stripe-test-key-file
apassy-team invite --role member --hours 72 > invite-code-file
```

`item add` reads the value from stdin and checks it on this machine (1 to 4096 bytes of printable ASCII, no `"` and no `\`, long and varied enough for a placeholder). It makes a uid and a key, seals the value, writes the key to `keys.json` next to `settings.json` (directory 0700, file 0600), and sends only the uid and the sealed text to the relay. Run `item add` as the owner, on the machine where `apassy-team host` runs: only that machine holds the keys. A manager can add an item too, but its key is on the manager's machine, so every run with it is denied at the owner's host ("Unknown item on this host.").

**Back up `keys.json`.** It is plain text in the alpha. Without it the items on the relay cannot be used, and you add them again. With it, and a copy of the vault, anyone can read the items: keep the two apart.

An item needs at least one host. A provider that the core knows, such as `stripe`, brings its hosts. For another API, give `--host api.example.com`. A host covers every subdomain too, so give the exact API host. The relay refuses a public suffix (`herokuapp.com`, `github.io`, `supabase.co`) and a whole domain (`example.com`): someone else may own a subdomain of it. Add `--allow-broad-host` only when you own every subdomain; the audit records it. Add `--environment production` for a production credential: the host asks you for every run with it.

The member joins with the code. The code works once:

```sh
apassy-team join --relay https://apassy-relay.wyderka.cc --name bob < invite-code-file
apassy-team me
```

The owner finds the member id and grants the collection:

```sh
apassy-team members
apassy-team grant --collection 1 --member 2
```

The member makes an agent token. It is printed once:

```sh
apassy-team agent create ci --days 30 > agent-token-file
```

The agent then sees what it may use:

```sh
APASSY_TOKEN="$(cat agent-token-file)" apassy-team access
```

Policy flags for `collection create` and `collection policy ID`:

| Flag | Meaning |
| --- | --- |
| `--mode ask\|bouncer` | `ask`: the relay suggests asking for every run. `bouncer`: the relay suggests a release for a known-safe command, and asking for the rest. (The host runs its own check either way.) |
| `--allow-prefix P` | the command must start with one of these (repeat) |
| `--forbid WORD` | a command with this word is denied (repeat) |
| `--max-runs-per-hour N` | at most N runs per hour |
| `--instruction TEXT` | a note for the owner |
| `--rule-expires-at UNIX` | the rule stops working at this time |

`collection policy` replaces the whole policy. Flags you leave out go back to their defaults.

## 10. Agents

There are three ways.

**The CLI.** It asks for a run, waits for the owner's host, then runs the command with the session environment. The variables never reach the transcript of the agent.

```sh
export APASSY_RELAY_URL=https://apassy-relay.wyderka.cc
export APASSY_TOKEN=...
apassy-team run --items 1 --purpose "Check the balance" \
  --request "Show me the Stripe balance" -- stripe balance retrieve
```

`run` exits with the code of the command (128 plus the signal number when it dies from a signal). It exits 3 if the run is denied (by a hard rule, by the host, or for lack of access) or times out, 4 on a relay or network error, and 2 on a usage error. The command does not inherit `APASSY_TOKEN`, `APASSY_TEAM_TOKEN`, or `APASSY_EDGE_SECRET`. Use `--wait SECONDS` to limit how long it waits for the host (the default is 900).

**Remote MCP, for Claude Code.** Put this in `.mcp.json` in a repo:

```json
{"mcpServers": {"apassy": {"type": "http", "url": "https://apassy-relay.wyderka.cc/mcp",
  "headers": {"Authorization": "Bearer ${APASSY_TOKEN}"}}}}
```

**Stdio MCP.** The adapter forwards each line to the relay:

```json
{"mcpServers": {"apassy": {"command": "apassy-team", "args": ["mcp"]}}}
```

It needs `APASSY_RELAY_URL` and `APASSY_TOKEN` in the environment.

With MCP, the agent must run the command itself with `session.env` set. Then the placeholders can end up in its transcript. A placeholder alone is useless without the relay, but the CLI is the better way.

**Cloud sessions.** A cloud session needs `apassy-relay.wyderka.cc` in the network allowlist of its environment (Custom access). It needs `APASSY_TOKEN` in its environment. Use the name `APASSY_TOKEN`: Claude Code reads some credential names as empty in MCP headers.

What the session gives the command: for each item, a variable with the item's name that holds a placeholder, and `APASSY_BASE_<NAME>`, a base URL on the relay. Some providers also get a standard variable: `STRIPE_API_BASE`, `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `GITHUB_API_URL`. The command must send its requests to that base URL. The relay puts the real value only in an auth position: the `Authorization` header, a known API key header, or a known key query parameter. A placeholder anywhere else is refused.

## 11. Runs and the host

Each run that passes the hard rules waits for the host of the owner. A run cannot start without a release. The relay cannot approve a run because it does not hold the keys.

Use the owner token on the machine that holds `keys.json`. Save the token with `apassy-team init`. To start the host on a terminal, use:

```sh
apassy-team host
```

To use desktop dialogs in the foreground, use:

```sh
apassy-team host --dialog
```

To install and start the host as a user service, use:

```sh
apassy-team host install
apassy-team host status
```

The service needs the same relay URL and owner token in `settings.json` as the shell. Installation refuses different shell settings. The service file contains no token. A service cannot use `APASSY_EDGE_SECRET` from the shell. Use a relay endpoint that does not need this variable.

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

`apassy-relay admin backup` copies `relay.db` and every team file while the relay runs. Each file is copied while its connection is locked, so the copy is whole. The copy goes to a new folder `<APASSY_RELAY_BACKUP_DIR>/<UTC time>` (default `/backups`; mode 0700, files 0600), with `MANIFEST.json`: the name, size, and SHA-256 of each file, and the number of teams.

```sh
docker compose exec -T relay apassy-relay admin backup
```

- The files stay encrypted. `relay.db` opens with the master key; each team file opens with its own key, which is in `relay.db`. Keep the master key apart from the backups: a backup with the master key opens every team's metadata (never an item value).
- A suspended team is copied too.
- On the VPS the folder is `/opt/apassy/backups/relay`. `deploy/vps/backup/` has a daily timer (03:30 UTC, 14 days kept, at least the 3 newest), a weekly restore test, and a pull to the owner's Mac (see its README).
- To restore: stop the relay; put `relay.db` and `teams/` of one backup into an empty data volume (owner 10001, mode 0700, files 0600); start with the same master key. A team deleted after the backup comes back with it.

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

One relay holds several teams (ADR 0019 of the core). Each team is its own file in `teams/`, with its own key, its own audit, and its own sessions. A token, an invite code, and a session key name their team (`apassy_mbr_t_7k2m9q4x8c_...`), and the relay looks a token up only in that team. People in one team cannot see another team, and the same person in two teams is two members.

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

**The teams.** `admin teams` lists each team: id, name, state, and for an active team the number of members, items, and agents, and the time of its last audit row. It shows no names of people or items, no runs, and no audit.

**Suspend, resume, delete.**

```sh
docker compose exec relay apassy-relay admin suspend t_7k2m9q4x8c
docker compose exec relay apassy-relay admin resume t_7k2m9q4x8c
docker compose exec relay apassy-relay admin delete t_7k2m9q4x8c   # only a suspended team; no undo
```

A suspended team's tokens fail at the next request; its sessions and waiting runs end. Each action is a row in the audit of the team (actor `operator`) and of the relay. Delete waits for the requests that started before the suspension, then removes the team's key from `relay.db` and its file. Old backups still hold both (section 13).

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

`POST /v1/join` and `POST /v1/teams` have a limit per IP address at the Worker: about 10 a minute (Workers Rate Limiting). Over it, the Worker answers 429 `rate_limited` and the request does not reach the relay. The count is kept in each Cloudflare location and is approximate, so a burst can pass a few more. If the limiter fails, requests go on: the relay checks every code itself.

A workflow in `.github/workflows/health.yml` checks `/healthz` and `/v1/me` (401) every hour. A failed run is the alert: GitHub notifies the owner of the repository.
