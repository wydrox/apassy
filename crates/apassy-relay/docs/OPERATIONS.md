# Running apassy-relay

Plain steps to run the alpha. The design is in [SPEC.md](SPEC.md). Names such as `apassy-relay.wyderka.cc` are the ones of the first deployment. Change them for yours.

## 1. What runs where

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
| `APASSY_RELAY_APPROVAL_TIMEOUT` | wait for an approver, 30 to 86400 s | 600 |

A restart ends every session. Runs that are still pending stay in the vault.

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

Without both values, the Worker answers 503 "relay not configured". If the tunnel is not reachable, it answers 502.

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

An item needs at least one host. A provider that the core knows, such as `stripe`, brings its hosts. For another API, give `--host api.example.com`. Add `--environment production` for a production credential: every run with it waits for an approver.

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
| `--mode ask\|bouncer` | `ask`: every run waits. `bouncer`: a known-safe command runs, the rest waits. |
| `--allow-prefix P` | the command must start with one of these (repeat) |
| `--forbid WORD` | a command with this word is denied (repeat) |
| `--max-runs-per-hour N` | at most N runs per hour |
| `--instruction TEXT` | a note for the approver |
| `--rule-expires-at UNIX` | the rule stops working at this time |

`collection policy` replaces the whole policy. Flags you leave out go back to their defaults.

## 10. Agents

There are three ways.

**The CLI.** It asks for a run, waits for an approver if needed, then runs the command with the session environment. The variables never reach the transcript of the agent.

```sh
export APASSY_RELAY_URL=https://apassy-relay.wyderka.cc
export APASSY_TOKEN=...
apassy-team run --items 1 --purpose "Check the balance" \
  --request "Show me the Stripe balance" -- stripe balance retrieve
```

`run` exits with the code of the command (128 plus the signal number when it dies from a signal). It exits 3 if the run is denied (by a hard rule, by an approver, or for lack of access) or times out, 4 on a relay or network error, and 2 on a usage error. The command does not inherit `APASSY_TOKEN`, `APASSY_TEAM_TOKEN`, or `APASSY_EDGE_SECRET`. Use `--wait SECONDS` to limit how long it waits for an approver (the default is 900).

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

## 11. Approvals

The owner or a manager sees the waiting runs:

```sh
apassy-team pending
```

It shows the command, the purpose, the user's request, the items, the flags, and the note. Read it before you decide:

```sh
apassy-team approve 7 --reason "Fine, I asked for it"
apassy-team deny 7 --reason "Not this key"
```

- A run that no one decides times out after `APASSY_RELAY_APPROVAL_TIMEOUT` seconds (600 by default). The agent sees `timed_out`.
- An approval fails with `run_not_pending` if the run is not pending any more.
- If the agent, the grant, or the item was revoked while the run waited, the approval fails and the run is denied with `approval_invalidated`.
- Approvals happen only in the CLI. There is no web page or app in the alpha.
- An owner may approve a run of their own agent.

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

The file is encrypted with the vault key. Keep the key apart from the backup. To restore, copy the file into a fresh volume with the same key.

## 14. Revocation

```sh
apassy-team agent revoke 2      # an agent token
apassy-team revoke --grant 5    # a grant
apassy-team member revoke 3     # a member (owner only)
apassy-team item archive 4      # an item
```

A revocation works at the next request. The relay looks up each token every time. Revoking an agent, a grant, a member, or an item ends the live sessions that depend on it at once. A run that is still pending fails when someone tries to approve it.

To rotate a credential, archive the item and add a new one. There is no edit in the alpha.

To rotate the edge secret, change the file, restart the container, and run `wrangler secret put EDGE_SECRET` with the new text. The vault key cannot be rotated in the alpha.

## 15. Limits and what this does not protect

What this does not protect:

- The relay holds the vault key and every value in memory while it runs. Root on the Mac or the VM can read them.
- A session key and a placeholder together work as a credential for the hosts of that item, in auth positions only, until the session ends. They can end up in an agent transcript if the agent runs the command itself.
- The relay approves a stated command. It cannot check what the agent really runs with the session. It controls which hosts get the value, where the value goes in a request, and for how long.
- Cloudflare sees all traffic in clear, including session keys in paths and placeholders in headers.
- The quick tunnel has no SLA and a changing URL.

What the alpha does not do:

- Way A (the member's Mac app gets a value for one run), and the model sidecar. With no model, only known-safe commands run at once. Every other command waits for an approver.
- `CONNECT` and a run certificate. Workers cannot do `CONNECT`, so the relay rewrites base URLs.
- Team rule packs, grants to one agent, item edit, access requests from agents.
- Approvals in an app, on the web, or in Slack.
- Keep-alive to upstream hosts, HTTP/2, WebSocket, `Upgrade`, server-sent events through the tunnel.
- Rewriting of redirects. A `Location` header passes through. A client that follows it goes to the real host with a placeholder and fails.
- Compressed upstream responses (a 502), request bodies over 8 MiB (a 413), AWS SigV4 and other signed requests.
- Items that are not HTTP API keys, such as a Postgres URL.
- The `gh` CLI. Only `GITHUB_API_URL` is set.
- Sessions that survive a restart.
- TLS in the relay, several teams per relay, a key typed at start.

The full list is in section 2 of [SPEC.md](SPEC.md). The threat notes are in section 20.
