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

The relay needs two secrets: the vault key and the edge secret. Make them with `openssl rand -hex 32`, into files that only you can read:

```sh
mkdir -p ~/.apassy-relay && chmod 700 ~/.apassy-relay
openssl rand -hex 32 > ~/.apassy-relay/vault_key
openssl rand -hex 32 > ~/.apassy-relay/edge_secret
chmod 600 ~/.apassy-relay/vault_key ~/.apassy-relay/edge_secret
```

- Never put a secret in a shell history, a repo, or an image.
- The vault key opens the vault. If you lose it, the vault is lost. Back it up somewhere apart from the vault backup.
- The edge secret must be the same text in the relay and in the Worker.
- Keep the folder under your home folder. Colima shares only the home folder with its VM. A folder in `/tmp` shows up empty in the container, and the relay then says it cannot read the file.
- Every secret the CLI needs (a member token, an invite code, an item value) is read from stdin. The CLI refuses to read it from a terminal.
- The vault holds only sealed item values, so the vault key protects less than before: a stolen vault or backup gives only ciphertext. The item keys are in `keys.json` on the owner's Mac (section 9). Back that file up apart from the vault.

## 3. Build the image

```sh
docker build -t apassy-relay:alpha .
```

The build is native (arm64 on colima). For Cloudflare Containers later, build for amd64:

```sh
docker buildx build --platform linux/amd64 -t apassy-relay:alpha-amd64 .
```

The image holds two programs: `apassy-relay` (the entry point) and `apassy-team`. It runs as user 10001 and keeps its data in the volume `/data`.

## 4. Create the team

Run this once. It creates the vault, the team, and the owner. It prints the owner token once. Copy the token into `~/.apassy-relay/owner_token.txt` at once (mode 0600). The file must hold only the token.

```sh
docker run --rm -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/vault_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=https://apassy-relay.wyderka.cc \
  apassy-relay:alpha init --team <name> --owner <name>
```

`APASSY_RELAY_PUBLIC_URL` is the URL that agents use. The relay puts it in the base URLs of a session. If it is wrong, agents get wrong base URLs.

If the volume already holds a team, `init` refuses.

## 5. Start

The same command, with `-d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080` and `serve`:

```sh
docker run -d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/vault_key \
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

Every run that passes the hard rules waits for the owner's host. Nothing starts without a release, and the relay cannot approve a run on its own: it does not hold the keys.

On the owner's Mac, where `keys.json` is, run:

```sh
apassy-team host
```

Use the owner token (`apassy-team init` with it). Keep it running, in `tmux` or a launchd job that has a terminal for questions. The host must be online for every run. A run with no host times out after `APASSY_RELAY_APPROVAL_TIMEOUT` seconds (600 by default), and the agent sees `timed_out`.

The host handles the runs one at a time, oldest first. For each run it checks, on its own, with the metadata in `keys.json` and its own run of the core analysis (not with what the relay says):

- Every item must be in `keys.json` for this relay, else the run is denied ("Unknown item on this host.").
- It releases the keys by itself only if all of these are true: you did not start it with `--ask-all`; the relay suggests a release and flags nothing; no item is `production` in `keys.json`; the host's own analysis says known safe with no flag; and the item was not released automatically 30 times in the last hour (`--auto-limit N` changes the number). `git status`, `ls -la`, `cargo test`, and `stripe balance retrieve` with a staging item are known safe.
- Otherwise it shows you the run: the agent, the member, the command, the purpose, the user's request, the working directory, the items with their environment from `keys.json`, the flags, the relay's note, and why it asks. Then it asks `Release the keys for run 7? [y/N]` on the terminal. Only `y` or `yes` releases. Anything else denies. With no terminal it denies ("No one at the host."). If the run expires while it waits, it moves on.

Every request is one line in `host.log` next to `keys.json`: the time, the run id, the agent, the member, the item uids and names, and the decision (`auto`, `approved`, `denied`, `unknown_item`, `expired`, `error`). It holds no key.

There is no flag or variable that makes the host say yes by itself. `--ask-all` only asks more.

To see and deny waiting runs from anywhere, the owner or a manager can use the CLI. This is for looking, and for saying no:

```sh
apassy-team pending
apassy-team deny 7 --reason "Not this key"
```

`apassy-team approve` does not approve: the relay answers `approve_on_host`, and the CLI says "The keys are on the owner's host. Approve there with apassy-team host."

- A run that no one decides times out. The agent sees `timed_out`.
- If the agent, the grant, the member, or the item is revoked while a run waits, the run is denied at once with `approval_invalidated`, and its key is dropped.
- A release that does not check (a wrong run, a changed text, a wrong set of items) denies the run with `release_invalid`. Each run key works once.
- There is no web page or app in the alpha. The owner decides at the terminal of the host.
- The owner's host may release a run of the owner's own agent.

## 12. Audit

```sh
apassy-team audit --limit 50
apassy-team audit --after 120 --json
```

The audit records team changes, runs, decisions, sessions, and proxy requests. It never holds a value, a placeholder, a token, or a session key. Only the owner and managers can read it. No endpoint changes or deletes a row.

## 13. Backup

The vault is one file, `team.db`, in the volume `/data`. To back it up:

```sh
docker stop apassy-relay
docker run --rm -v apassy-relay-data:/data:ro -v "$PWD":/backup debian:trixie-slim \
  cp /data/team.db /backup/team.db
docker start apassy-relay
```

The file is encrypted with the vault key, and it holds no readable value: each item is sealed, and its key is not on the relay. Keep the vault key apart from the backup. To restore, copy the file into a fresh volume with the same key.

Also back up `keys.json` on the owner's Mac (`~/.config/apassy-team/keys.json`, or under `$XDG_CONFIG_HOME`). It is plain text in the alpha, so keep the copy private and apart from the vault backup. Losing it means adding the items again. With the vault backup alone nobody can read a value, and with `keys.json` alone nobody can open anything.

## 14. Revocation

```sh
apassy-team agent revoke 2      # an agent token
apassy-team revoke --grant 5    # a grant
apassy-team member revoke 3     # a member (owner only)
apassy-team item archive 4      # an item
```

A revocation works at the next request. The relay looks up each token every time. Revoking an agent, a grant, a member, or an item ends the live sessions that depend on it at once, and denies the runs that are pending on it (`approval_invalidated`) and drops their keys.

To rotate a credential, archive the item and add a new one (`item add` makes a new key). There is no edit in the alpha.

To rotate the edge secret, change the file, restart the container, and run `wrangler secret put EDGE_SECRET` with the new text. The vault key cannot be rotated in the alpha.

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
| Data | the volume `apassy-relay-data`, file `team.db` (owner 10001, mode 0600) |
| Relay secrets | `/opt/apassy/secrets/relay/vault_key` and `edge_secret`, owner 10001, mode 0400 |
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

Back up the vault as in section 13, with the project stopped: `docker compose stop relay`, then copy `team.db` out of `apassy-relay-data`, then `docker compose start relay`.

Go back to the Mac:

1. On the VPS: `docker compose stop relay`. Copy `team.db` to the Mac volume if the VPS changed it.
2. On the Mac: start the container and a quick tunnel (sections 5 and 6).
3. In `deploy/worker/wrangler.jsonc`, remove `vpc_services` and set `RELAY_ORIGIN` to the tunnel URL. Then `wrangler deploy`.
