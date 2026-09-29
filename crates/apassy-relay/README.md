# apassy-relay

The team relay of Apassy. It is a credential manager with a bouncer for AI agents, for a small team.

A team keeps shared credentials in one encrypted vault on the relay. An agent asks for a run. The relay decides. If the run may go, the agent gets placeholders and base URLs that point at the relay. The relay proxies the agent's requests to the real API host. It puts the real value only in an auth position, only for the hosts of that item. The agent never holds a real value.

This is an alpha. The design is in [docs/SPEC.md](docs/SPEC.md). It follows ADR 0013 of the [core](https://github.com/wydrox/apassy), way B.

## What it does

- Owner, managers, and members. Members join with one-time invite codes.
- Collections of items. Each collection has a policy. A grant gives one member the use of one collection.
- Each member makes agent tokens.
- A known-safe command runs at once. Every other command waits for an approver. A production credential always waits. A hard-rule failure is denied.
- Approvals are done with the CLI.
- An audit log with no values, no placeholders, no tokens.
- Agents use a remote MCP endpoint, a stdio MCP adapter, or `apassy-team run`.

## License

The relay is under the Functional Source License, Version 1.1, with the Apache-2.0 future license (FSL-1.1-ALv2). Each version becomes Apache-2.0 two years after its release. See [LICENSE](LICENSE). The core crate, `apassy`, is Apache-2.0.

## Quick start

You need Rust 1.97 and Docker. The relay runs as a Linux container. Cloudflare terminates TLS, so the relay itself serves plain HTTP.

Build the CLI and the image:

```sh
cargo build --release --bin apassy-team
docker build -t apassy-relay:alpha .
```

Make a vault key and an edge secret. Keep them in files, never in a shell history:

```sh
mkdir -p ~/.apassy-relay && chmod 700 ~/.apassy-relay
openssl rand -hex 32 > ~/.apassy-relay/vault_key
openssl rand -hex 32 > ~/.apassy-relay/edge_secret
chmod 600 ~/.apassy-relay/*
```

Create the team. This prints the owner token once:

```sh
docker run --rm -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/vault_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=http://127.0.0.1:8080 \
  apassy-relay:alpha init --team myteam --owner olga
```

Start it on the loopback address:

```sh
docker run -d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/vault_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=http://127.0.0.1:8080 \
  apassy-relay:alpha serve
```

Save the owner token in a file, then log in. A secret always comes from stdin, never from an argument. Talking to the container directly needs the edge secret:

```sh
export APASSY_EDGE_SECRET="$(cat ~/.apassy-relay/edge_secret)"
apassy-team init --relay http://127.0.0.1:8080 < owner-token-file
apassy-team me
```

Add a credential and let an agent use it:

```sh
apassy-team collection create payments
apassy-team item add --collection 1 --name "Stripe test" --env STRIPE_API_KEY \
  --environment staging --provider stripe < stripe-key-file
apassy-team invite                       # send the code to the member
apassy-team grant --collection 1 --member 2
apassy-team agent create ci              # the member runs this; it prints the token once

export APASSY_TOKEN=...                  # in the agent's environment
apassy-team run --items 1 --purpose "Check the balance" \
  --request "Show me the Stripe balance" -- stripe balance retrieve
```

The full setup, with the Cloudflare Worker and the tunnel, is in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Layout

| Path | What |
| --- | --- |
| `src/server/` | the relay server: vault, decisions, sessions, audit, MCP |
| `src/proxy/` | the reverse proxy that swaps placeholders |
| `src/cli/` | the `apassy-team` CLI and the stdio MCP adapter |
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

`tests/e2e.rs` runs the whole flow in process. `scripts/e2e.sh` runs it with the real
binaries: `apassy-relay init` and `serve`, then the same server code with a mock
upstream (`examples/e2e_relay.rs`), and `apassy-team` for every step. The release
binary cannot trust a test root on purpose, so the script needs the example for the
upstream. All values are synthetic.

## What it does not protect

Read section 20 of [docs/SPEC.md](docs/SPEC.md). In short: the relay holds every value in memory while it runs, and Cloudflare sees all traffic in clear.
