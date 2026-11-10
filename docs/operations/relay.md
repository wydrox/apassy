# The hosted service: Apassy Connect

Date: 2026-11-10 (rewritten for ADR 0037 stage 7; the relay of 2026-10-01 is in "Until the cutover").
Scope: what runs at `apassy-relay.wyderka.cc`, what it stores, and what it never holds. Decisions: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 7, D2, D3, D7, D8, D14; [ADR 0019](../adr/0019-relay-teams-and-accounts.md). The owner's runbook, with the cutover and the rollback: [connect.md](connect.md).

The relay is the crate `crates/apassy-relay` of this repository (Apache-2.0, ADR 0037 stage 1). Its specification is `crates/apassy-relay/docs/SPEC.md` and its operator reference `crates/apassy-relay/docs/OPERATIONS.md`. The production deployment files and the health monitor stay in the archived private repository `wydrox/apassy-relay`, with the server addresses.

**Status.** The code of Connect is built (plan s7, units C1 to C5, not yet released). The hosted service runs in `relay` mode until the owner runs the cutover of release R3 ([connect.md](connect.md), section 9); this page describes it after that step, and "Until the cutover" keeps the facts of the hosted relay before it.

## What runs

- **The edge Worker** at `https://apassy-relay.wyderka.cc` (`crates/apassy-relay/deploy/worker`): TLS ends here for the API; it adds the edge secret, bounds every body, limits the creation and dial routes per client, and serves the downloads (`/dl/`), the guide, and `install.sh` from its own assets. Its var `RELAY_MODE` is `connect` after the cutover: no APNs route, and `/v1/connect` answers 410 `hosted_retired` at the edge. A deploy refuses a `RELAY_MODE` that is not the mode the relay reports on `/healthz`.
- **The relay** in `APASSY_RELAY_MODE=connect`, behind the Worker through a Workers VPC binding and a named tunnel, with no public port for the API. It serves accounts and their devices, vault stores (one relay-sync-v1 team for each vault), billing through Stripe Checkout and the Customer Portal, Family and Team groups, and the tunnel between devices and nodes. Every other route of the relay answers 410 `hosted_retired`. It builds no proxy, sends no push, and has no master key.
- **The ingress** on ports 443 and 80 of the Connect host (`*.node.apassy.wyderka.cc`, DNS-only): it reads only the server name of a cloud agent's TLS and forwards the raw stream to the node through its tunnel. TLS for cloud agents ends on the user's node.
- **Push** is not Connect: the nodes push through the free push gateway `push.apassy.wyderka.cc` (D7, [push-gateway.md](push-gateway.md)).

## What it stores

Plain SQLite files, with no key, because nothing in them is secret ([connect.md](connect.md) section 11, the trust model):

- `relay.db`: accounts, their devices (public keys, names, platforms), groups and invite hashes, the Stripe ids and plan states, the tunnel nodes, grants, and usage counts, the vault store list, the entitlement key ids, and the relay audit (ids, actions, times).
- `teams/<id>.db` for each vault store: its devices (public keys), the signed heads, and the receipts; `teams/<id>.sync/` its current and previous snapshot, which are the vault's SQLCipher file under the user's passphrase.
- `cutover.json`: the record of the cutover (ids, counts, file hashes).

Backups are the same plain files (`admin backup` daily, `apassy-relay backup` with the service stopped); restore and checks: [connect.md](connect.md) section 8.

## What it never holds

A master key or the key of any file; a vault passphrase or vault key; an item value or a team vault of items; a proxy session or way B (D8); a question, an answer, or a feed; an APNs token or the APNs key; a link code, a recovery code, or an account token on disk (tokens live 15 minutes in memory); a client address on disk. The hosted bouncer brain (ADR 0035) is a separate service with its own consent and gets only an entitlement token.

## Inspect

```sh
curl -s -D - -o /dev/null https://apassy-relay.wyderka.cc/healthz   # x-apassy-relay-version, -commit, -mode (GET: no HEAD)
curl -s https://apassy-relay.wyderka.cc/.well-known/apassy-connect.json
```

On the host, in the compose directory: `docker compose ps`, `docker compose exec -T relay apassy-relay admin teams` (vault stores only, `"kind": "account"`), `docker compose exec -T relay apassy-relay admin readiness`.

## The free paths end with 0.5.20 (ADR 0037 D14)

From Apassy 0.5.17 the apps say that the free approvals without a team code (the questions-only Connect path of [ADR 0032](../adr/0032-connect-onboarding.md)) and free relay sync on `apassy-relay.wyderka.cc` end with Apassy 0.5.20, moved from 0.5.19 by the owner on 2026-11-06 (`FREE_RELAY_PATHS_END_VERSION` in `src/relay/membership.rs`; the iPhone has the same number in `VaultText.swift`). The choices that the apps name: Tailscale with the user's Mac as the node (free), an own sync home on a Mac or Linux node (free, stage 4), or Apassy Connect (paid). Until 0.5.20 the hosted relay keeps relay sync, questions, feed, and push as they are. A slip of the date changes the constant and needs the owner's word ([implementation plan s7](../design/implementation-plan-s7-connect.md), section 5).

The end itself has two steps on the hosted relay, both the owner's ([connect.md](connect.md)): the transition switches `APASSY_RELAY_FREE_CONNECT=0` and `APASSY_RELAY_CONNECT_SYNC_BYTES=0` (free approvals answer 410 `free_connect_ended`, free relay sync is read-only), and a week later the cutover, which keeps only the vault stores of accounts and deletes every other team.

## Until the cutover

The hosted relay as it runs today (2026-11-10), for operations before release R3's cutover:

- Public URL `https://apassy-relay.wyderka.cc`, the same Worker in `RELAY_MODE=relay` (or unset), with the APNs sender `/internal/push` that the relay's push thread calls.
- The relay in `relay` mode: `relay.db` and each team file encrypted with SQLCipher; the master key opens `relay.db`, which holds the random key of each team file. Shared team vaults and way B are off (D8, `APASSY_RELAY_TEAM_VAULTS=0`); devices, relay sync, questions, feed, and push work; the account routes are on once the owner sets `APASSY_RELAY_CONNECT_ACCOUNTS=1` (relay OPERATIONS.md 26.2).
- Teams of three kinds: operator teams made with a team code (the alpha team migrated on 2026-10-01 among them), free Connect teams of ADR 0032 (`POST /v1/connect`; with relay sync when `APASSY_RELAY_CONNECT_SYNC_BYTES` is set), and the vault stores of Connect accounts (with the account routes on).
- Backups: daily, 14 days kept, a weekly restore test, and a daily pull to the owner's Mac; the master key is not in them and is kept apart.
- The operator, or root on the host, can open every team's metadata (not item values) with the master key. The cutover ends that: after it no key exists on the host.

A new team with a team code is an operator step of the alpha (`admin team-code`, then `apassy-team create`): it works until the cutover and is refused after it; teams run on their own nodes (ADR 0037 stage 4).
