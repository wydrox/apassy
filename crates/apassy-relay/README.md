# apassy-relay

The team relay of Apassy. It is a credential manager with a bouncer for AI agents, for a small team.

A team keeps shared credentials on the relay, but the relay never stores a readable value. Each value is sealed on the owner's machine, and its key stays there. An agent asks for a run. The owner's machine (`apassy-team host`) decides, and for a run that it agrees to, it sends the relay the keys of that run's items, sealed to a one-time key of that run. The relay opens the values in memory for that session only. The agent gets placeholders and base URLs that point at the relay. The relay proxies the agent's requests to the real API host. It puts the real value only in an auth position, only for the hosts of that item. The agent never holds a real value.

This is an alpha. The design is in [docs/SPEC.md](docs/SPEC.md). It follows ADR 0013 of the [core](https://github.com/wydrox/apassy), way B.

## What it does

- Several teams on one relay, each in its own encrypted file with its own state. The operator gives a one-time team code; its holder creates a team (`apassy-team create`). See section 22 of the spec.
- Owner, managers, and members in each team. Members join with one-time invite codes.
- Collections of items. Each collection has a policy. A grant gives one member the use of one collection.
- Each member makes agent tokens.
- Host-held item keys. A stolen vault or backup gives only ciphertext. A relay that is taken over gets only the values of the runs that the host released while it ran.
- The owner's host releases a known safe command with a non-production item at once. Other runs need approval on the terminal or in a desktop dialog. Production credentials always need approval. The relay denies a hard-rule failure. Nobody approves on the relay.
- An audit log with no values, no placeholders, no tokens, no keys.
- Agents use a remote MCP endpoint, a stdio MCP adapter, or `apassy-team run`.

## Two modes: the relay, and Apassy Connect

The same binary runs in one of two modes (`APASSY_RELAY_MODE`, SPEC section 37):

- **`relay`** (the default): every route above, the files encrypted with the master key. A
  relay that you run for yourself, and the hosted relay until its cutover.
- **`connect`**: Apassy Connect only (ADR 0037 stage 7): accounts and their devices, vault
  stores (relay sync of a vault, ciphertext only), billing through Stripe, Family and Team
  groups, and the tunnel between devices and nodes. No master key, no proxy, no push, no
  team vault; every other route answers 410 `hosted_retired`; `relay.db` and the stores are
  plain SQLite files, because nothing in them is secret. Everything Connect does can be
  self-hosted from this repository.

A relay moves from `relay` to `connect` once, with the relay stopped:
`apassy-relay backup` (a byte-for-byte copy of the stopped data directory), then
`apassy-relay connect-cutover` (a dry run that checks that backup and prints the plan), then
`apassy-relay connect-cutover --confirm-delete-teams` (keeps the vault stores of the accounts
as plain files and deletes every other team with its files and keys). Before it, the
transition switch `APASSY_RELAY_FREE_CONNECT=0` ends the free questions-only Connect path.
The owner's runbook is [docs/operations/connect.md](../../docs/operations/connect.md); the
operator reference is section 29 of [docs/OPERATIONS.md](docs/OPERATIONS.md).

## License

The relay is Apache-2.0, like the rest of this repository (see the [LICENSE](../../LICENSE) at the root). Versions up to 0.5.13 were published under FSL-1.1-ALv2 in the private `wydrox/apassy-relay` repository; on 2026-11-02 the copyright holder relicensed the whole history under Apache-2.0 and moved it here ([ADR 0037](../../docs/adr/0037-own-relay-open-source.md)).

## Quick start

You need Rust 1.97 and Docker. The relay runs as a Linux container. Cloudflare terminates TLS, so the relay itself serves plain HTTP.

Obtain the relay image and both CLI downloads from GitHub Actions, using the
[CI-only release runbook](docs/OPERATIONS.md#current-release-runbook-github-artifacts-only).
Load a verified image archive on the approved runtime; no production or local-VM
image builds are part of this procedure. The examples below use `apassy-relay:alpha`
as a placeholder for that verified image.

Make a master key and an edge secret. Keep them in files, never in a shell history:

```sh
mkdir -p ~/.apassy-relay && chmod 700 ~/.apassy-relay
openssl rand -hex 32 > ~/.apassy-relay/master_key
openssl rand -hex 32 > ~/.apassy-relay/edge_secret
chmod 600 ~/.apassy-relay/*
```

Create the relay and its first team. This prints the owner token once:

```sh
docker run --rm -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/master_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=http://127.0.0.1:8080 \
  apassy-relay:alpha init --team myteam --owner olga
```

Start it on the loopback address:

```sh
docker run -d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/master_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=http://127.0.0.1:8080 \
  apassy-relay:alpha serve
```

Save the owner token in `owner-token-file`. Enroll the bootstrap owner as a device before the legacy token expires.
Use an unused configuration directory. `device enroll` refuses an existing key or team settings entry.
For direct access to the container, set the edge secret:

```sh
export XDG_CONFIG_HOME="$HOME/.config/apassy-device"
export APASSY_RELAY_URL=http://127.0.0.1:8080
export APASSY_EDGE_SECRET="$(cat ~/.apassy-relay/edge_secret)"
export APASSY_TEAM_TOKEN="$(cat owner-token-file)"
apassy-team device enroll --name "Owner laptop"
unset APASSY_TEAM_TOKEN
apassy-team me
```

The sole bootstrap owner's first device becomes the key holder. Enrollment invalidates the old member token.
For an operator-issued team code, use `apassy-team create` instead. It always creates an owner device:

```sh
apassy-team create --relay https://apassy-relay.wyderka.cc --team myteam \
  --name olga --device "Owner laptop" < team-code-file
```

Settings version 2 keeps several teams in `settings.json`, with directory mode 0700 and file mode 0600.
Use `team list` and `team use TEAM_ID` to see and select teams.
Use `--team TEAM_ID` or `APASSY_TEAM=TEAM_ID` for a member command. Otherwise, the current team applies.
In `create --team NAME`, `--team` gives the new team's name.
The CLI stores device private keys in the login Keychain on macOS.
The Keychain service is `apassy-team`, and the account is `<relay host> <team id>`.
On other systems, `device-<team id>.key` next to settings has mode 0600.
Private keys never enter settings or command output. Device access tokens stay only in process memory for 15 minutes.

`create`, `join`, `device link`, and `device enroll` refuse an existing device key or settings entry for that team.
On macOS, separate configuration directories still share the same Keychain account for a relay and team.
Use another machine for a second member of the same team.

Add credentials on the key-holder machine. `item add` seals the value and keeps its key in `keys.json` next to settings.
Back up this file separately from the relay's vault backup. Without the item keys, add the items again.

```sh
apassy-team collection create payments
apassy-team item add --collection 1 --name "Stripe test" --env STRIPE_API_KEY \
  --environment staging --provider stripe < stripe-key-file
apassy-team invite --role member --name bob --grant 1 > invite-link-file
```

`invite` prints `<relay URL>/join#<code>` once. Repeat `--grant ID` for more collections.
Use `--shared` only for role `member` on a shared device.
Send the link through a private channel. On the member's machine, read the link or raw code from stdin:

```sh
apassy-team join --relay http://127.0.0.1:8080 --device "Bob laptop" < invite-link-file
```

For this loopback example, use the same machine with a separate configuration directory on Linux.
Set `APASSY_EDGE_SECRET` there too. A remote member needs the HTTPS relay URL from the full setup.
For a second member on macOS, use another machine with that HTTPS URL.
If the invite has no member name, add `--name bob`.
The member's CLI saves its key before the request and checks the safety words locally.
The member gives these words to the inviter through a trusted channel. The inviter confirms:

```sh
apassy-team joins
apassy-team confirm JOIN_ID --words "W1 W2"
```

Replace `W1 W2` with the member's words. `--words` is mandatory. `joins` does not print safety words.
`join` waits up to 10 minutes. Use `--no-wait` to return immediately and `join --resume` to wait again.
The CLI retains the same key after an uncertain request result.

To add a device for the same member, use `device add > device-link-code-file` on an existing device.
On the new device, use `device link --relay URL < device-link-code-file`.
Get its words through a trusted channel, then use `device pending` and `device confirm LINK_ID --words "W1 W2"`.
`device pending` does not print safety words. Device links expire after 10 minutes.
Before `device key-holder DEVICE_ID`, copy `keys.json` to the new owner's device. The command does not copy item keys.

On the member's device, make an agent token:

```sh
apassy-team agent create ci > agent-token-file
```

On the key-holder machine, install the host:

```sh
apassy-team host install
```

In the agent's environment, use its token:

```sh
export APASSY_TOKEN="$(cat agent-token-file)"
apassy-team run --items 1 --purpose "Check the balance" \
  --request "Show me the Stripe balance" -- stripe balance retrieve
```

Input commands read team codes, invite codes, device-link codes, item values, and legacy `init` tokens only from stdin.
Never put these secrets in command arguments. Agent tokens use `APASSY_TOKEN`.

Each run waits for `apassy-team host`. A known safe command with a staging item starts automatically (the `stripe balance retrieve` example). Other runs show a desktop dialog. Only a click on `Release` releases the keys. `Deny` is the default button. Return, Escape, a closed dialog, or a dialog error denies the run. A timeout expires the request without a release.

Use `apassy-team host status` to check the user service. Use `apassy-team host uninstall` to stop and remove it. For a foreground host, use `apassy-team host` on a terminal or `apassy-team host --dialog` for desktop dialogs. The host must be online for each run. See [section 11 of the operations guide](docs/OPERATIONS.md#11-runs-and-the-host) for service options and logs.

The full setup, with the Cloudflare Worker and the tunnel, is in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Layout

| Path | What |
| --- | --- |
| `src/server/` | the relay server: vault (sealed values), decisions, run keys, host endpoints, sessions, audit, MCP |
| `src/proxy/` | the reverse proxy that swaps placeholders |
| `src/cli/` | the `apassy-team` CLI, the owner's host (`host.rs`), the key store (`keystore.rs`), and the stdio MCP adapter |
| `src/hostkeys.rs` | the crypto of host-held item keys: seal, open, release |
| `src/decision.rs` | the pure part of the decision per run, used by the relay and by the host |
| `deploy/worker/` | the Cloudflare Worker at the edge |
| `scripts/e2e.sh` | the end-to-end check with the real binaries |
| `examples/e2e_relay.rs` | the relay with a mock upstream, for `scripts/e2e.sh` only |
| `Dockerfile` | the image: one binary, one port, one volume |
| `docs/SPEC.md` | the specification of the alpha |
| `docs/OPERATIONS.md` | how to run it |

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
node --test 'deploy/worker/test/*.test.ts'    # Node 22.18 or later, no npm install
scripts/e2e.sh                                # the binaries end to end, on 127.0.0.1
```

`tests/e2e.rs` runs the whole flow in process: `apassy-team item add` with a key store in a temp dir, the real host loop with a scripted person, an agent, and the mock upstream. `scripts/e2e.sh` runs it with the real
binaries: `apassy-relay init` and `serve`, then the same server code with a mock
upstream (`examples/e2e_relay.rs`), `apassy-team host` cut off from any terminal, and `apassy-team` for every step. The release
binary cannot trust a test root on purpose, so the script needs the example for the
upstream. All values are synthetic.

## What it does not protect

Read sections 20 and 21 of [docs/SPEC.md](docs/SPEC.md). In short: the relay still sees a value while a session lives, `keys.json` is plain text on the owner's disk in this alpha (back it up), the host must be online for every run, only the owner's host holds keys, and Cloudflare sees all traffic in clear (but no longer a value when an item is added).
