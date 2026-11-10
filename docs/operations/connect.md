# Apassy Connect: the hosted service, and the cutover from the hosted relay

Date: 2026-11-10. Status: runbook for release R3 of [implementation plan s7](../design/implementation-plan-s7-connect.md) (units C5 and O2). Nothing here has run against production: every step marked **Owner** changes the hosted service and runs only after the owner's go.
Decisions: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 7, D7, D8, D14, "Migration". Relay reference: `crates/apassy-relay/docs/SPEC.md` sections 33 to 37 and `docs/OPERATIONS.md` sections 26 to 29. The page of the service: [relay.md](relay.md).

Run the commands on the Connect host, in the compose directory of the deployment (the private deploy notes name both; production addresses stay out of this repository). `docker compose run --rm --no-deps -T relay <command>` runs a relay command on the data volume with the compose settings while the service is stopped; `docker compose exec -T relay apassy-relay <command>` runs one in the running service.

## 1. What runs

| Part | Before the cutover (`relay` mode) | After it (`connect` mode) |
| --- | --- | --- |
| Edge Worker `apassy-relay.wyderka.cc` | `RELAY_MODE=relay`: forwards to the relay with the edge secret, sends APNs pushes for the relay (`/internal/push`), limits the free Connect teams | `RELAY_MODE=connect`: forwards to the relay; `/internal/push` is off (404); the free Connect guards are off. `/dl/`, `/guide`, `/install.sh` as before |
| Relay container | every route; `relay.db` and the team files encrypted with the master key | Connect only: accounts, vault stores, billing, groups, the tunnel; every other route 410 `hosted_retired`; plain files, no master key, no proxy, no push |
| Tunnel container (cloudflared) | as before | as before |
| Ingress | `APASSY_CONNECT_INGRESS_LISTEN` and `_ACME_LISTEN` when R2 set them | the same: ports 443 and 80 of the host for cloud agents to nodes |
| Push | the relay's push thread through the Worker | none in Connect: nodes push through the push gateway `push.apassy.wyderka.cc` (D7, [push-gateway.md](push-gateway.md)) |

## 2. Settings of the two phases

The relay reads its settings from the environment of its container; secrets are files mounted read-only (section 3). A value that is not here keeps its default.

| Setting | Transition (R3, before the cutover) | Connect (after the cutover) |
| --- | --- | --- |
| `APASSY_RELAY_MODE` | unset (`relay`) | `connect` |
| `APASSY_RELAY_KEY_FILE` | the master key file | **unset**, and the master key not mounted (the start refuses it) |
| `APASSY_RELAY_EDGE_SECRET_FILE` | the edge secret file | the same |
| `APASSY_RELAY_PUBLIC_URL` | `https://apassy-relay.wyderka.cc` | the same |
| `APASSY_RELAY_DATA`, `APASSY_RELAY_BACKUP_DIR` | `/data`, `/backups` | the same |
| `APASSY_RELAY_TEAM_VAULTS` | `0` | unset (forced off) |
| `APASSY_RELAY_CONNECT_ACCOUNTS` | `1` | unset (forced on; `0` is refused) |
| `APASSY_RELAY_FREE_CONNECT` | `0` (section 6) | unset (forced off) |
| `APASSY_RELAY_CONNECT_SYNC_BYTES` | `0`, or unset (section 6) | unset |
| `APASSY_RELAY_PUSH_URL`, `_PUSH_TOPIC`, `_PUSH_SECRET_FILE` | as before (operator teams may still ask questions) | **unset** (the start refuses any of them) |
| `APASSY_CONNECT_SIGNING_KEY_FILE` | the signing key file (section 4) | the same |
| `STRIPE_SECRET_KEY_FILE`, `STRIPE_WEBHOOK_SECRET_FILE` | the two Stripe files (section 5) | the same |
| `APASSY_CONNECT_SITE_URL` | unset (`https://apassy.wyderka.cc`) | the same |
| `APASSY_CONNECT_INGRESS_LISTEN`, `APASSY_CONNECT_ACME_LISTEN` | `0.0.0.0:443`, `0.0.0.0:80` (section 7) | the same |
| `APASSY_CONNECT_NODE_ZONE` | unset (`node.apassy.wyderka.cc`) | the same |
| Billing durations and the Family extra price | as R2 set them (OPERATIONS.md 27.6) | the same |
| Worker var `RELAY_MODE` | `relay` | `connect` |
| Worker secrets | `EDGE_SECRET`, `PUSH_SECRET`, `APNS_KEY` | `EDGE_SECRET`; `PUSH_SECRET` and `APNS_KEY` unused (section 9, step 14) |

A sketch of the relay service in `connect` mode (the image tag and the published ports are those of the deployment):

```yaml
services:
  relay:
    image: apassy-relay:sha-<full SHA of R3>
    environment:
      APASSY_RELAY_MODE: connect
      APASSY_RELAY_PUBLIC_URL: https://apassy-relay.wyderka.cc
      APASSY_RELAY_EDGE_SECRET_FILE: /run/secrets/relay/edge_secret
      APASSY_CONNECT_SIGNING_KEY_FILE: /run/secrets/relay/connect_signing_key.pem
      STRIPE_SECRET_KEY_FILE: /run/secrets/relay/stripe-key
      STRIPE_WEBHOOK_SECRET_FILE: /run/secrets/relay/stripe-webhook-secret
      APASSY_CONNECT_INGRESS_LISTEN: 0.0.0.0:443
      APASSY_CONNECT_ACME_LISTEN: 0.0.0.0:80
    volumes:
      - apassy-relay-data:/data
      - <backup folder>:/backups
      - <secrets folder without master_key>:/run/secrets/relay:ro
    ports:
      - "443:443"
      - "80:80"
```

## 3. Secrets as files

Each secret is its own file, owner 10001 (the relay user), mode 0400, in the secrets folder of the host (root's, mode 0711); never in the compose file, the environment, a shell history, or this repository. Each is also kept in Apassy, so it reaches the host only through `apassy_run_with_secrets`.

| File | Content | Needed |
| --- | --- | --- |
| `edge_secret` | the text of the Worker secret `EDGE_SECRET` | both phases |
| `master_key` | the key of the keyed `relay.db` | until the cutover; then kept **only** with the stopped backup of the cutover for the retention the owner chooses (section 10) |
| `connect_signing_key.pem` | the Ed25519 key of the entitlement token (section 4) | Connect |
| `stripe-key` | the restricted Stripe key (`rk_live_…`) | Connect |
| `stripe-webhook-secret` | the signing secret of the webhook endpoint (`whsec_…`) | Connect |
| `push_secret` | the Worker's `PUSH_SECRET` | until the cutover |

To change a secret: replace the file, `docker compose up -d relay` (the relay reads it at start). Undo: put the old file back and start again.

## 4. The signing key

- **Owner, once (R2):** on the owner's Mac, `openssl genpkey -algorithm ed25519 -out connect_signing_key.pem`; save it in Apassy; put it on the host as in section 3; set `APASSY_CONNECT_SIGNING_KEY_FILE`; restart. Effect: `GET /.well-known/apassy-connect.json` lists the key id `ek_<16 hex>`, and entitled accounts get entitlement tokens. Undo: unset the setting and restart (`GET /v1/account/entitlement` answers 503 `busy`; the brain then refuses new tokens).
- **Rotate:** a new key file and a restart. The relay keeps listing the old key for 24 hours after its last token (SPEC 33.9), so services that hold a token keep verifying it. No step of the cutover touches it.

## 5. Stripe keys and the webhook

R2 sets them up (OPERATIONS.md 27.1 to 27.4): a restricted key with the permissions listed there, the webhook endpoint `https://apassy-relay.wyderka.cc/v1/stripe/webhook` (API version `2025-03-31.basil`, the six events), the Customer Portal settings, and the prices by lookup key. The cutover keeps them as they are: `relay.db` keeps every Stripe row, and the endpoint URL does not change. During the stop of section 9, Stripe retries the webhooks it could not deliver (the relay is down for minutes); check in the Stripe dashboard after the start that the endpoint shows no failing deliveries.

## 6. The transition switches (R3, at least a week before the cutover)

**Owner, step T1:** deploy the R3 image in `relay` mode with the settings as they are (the release runbook of OPERATIONS.md). Effect: no change of behaviour (directory 1006, team schema 8 stay). Undo: the previous image.

**Owner, step T2:** in the compose file set `APASSY_RELAY_FREE_CONNECT=0` and `APASSY_RELAY_CONNECT_SYNC_BYTES=0` (replacing `67108864`), then `docker compose up -d --wait relay`.
Effect: `POST /v1/connect` and its challenge answer 410 `free_connect_ended`; every free Connect team's questions, feed, and push answer 410 `free_connect_ended`; their snapshot pushes and receipts answer 403 `plan_required`; their pulls and downloads still work, and their devices can leave. Operator teams and vault stores do not change. The apps show the notice of N1 already; this makes it the fact.
Undo: remove both lines (or `APASSY_RELAY_FREE_CONNECT=1` and `APASSY_RELAY_CONNECT_SYNC_BYTES=67108864`), `docker compose up -d --wait relay`.
A staged end: `APASSY_RELAY_FREE_CONNECT=0` alone ends the free approvals and keeps free relay sync for existing teams; the second line ends the sync too.

**Owner, step T3, during the week:** `docker compose exec -T relay apassy-relay admin teams` shows the free Connect teams that remain (`"kind": "connect"`) and their last sign-in. A Mac that moved to Connect or to its own node deletes its free team itself; the rest go with the cutover.

## 7. The ingress ports and the DNS record

R2 set them (OPERATIONS.md 28.1): the DNS-only (grey cloud) wildcard record `*.node.apassy.wyderka.cc` to the host's public address, ports 443 and 80 open in the host firewall and published by the container, and `APASSY_CONNECT_INGRESS_LISTEN` and `_ACME_LISTEN`. The cutover does not change them; the stop of section 9 makes them answer nothing for its minutes (nodes reconnect with backoff). Undo of the ingress alone: unset the two listen settings and restart.

## 8. Backups of plain files, and the restore

After the cutover every file of the relay is plain SQLite (no key), and the snapshots stay ciphertext under each vault's passphrase. A backup holds no secret, so nothing has to be kept apart from it, but it holds public keys, device names, account and Stripe ids, vault ids, and the email copied from Stripe: keep it private like the volume itself.

- The daily backup of the running service stays `docker compose exec -T relay apassy-relay admin backup` (the timer of the deploy notes). In `connect` mode it copies plain files and its `MANIFEST.json` says `"mode": "connect"`.
- A backup of the stopped service: `docker compose stop relay`, then `docker compose run --rm --no-deps -T relay backup` (a byte-for-byte copy of the data directory, `"stopped": true`), then `docker compose start relay`.
- **The restore** (either kind): stop the service; put the backup's `relay.db`, `teams/`, and (from a stopped backup) its other files into an empty data volume, owner 10001, mode 0700, files 0600 (the restore procedure of the deploy notes does this); check it with `docker compose run --rm --no-deps -T relay snapshot-check`; start. A backup of `connect` mode starts with the Connect settings and no key; a backup without `"mode": "connect"` needs the `relay` settings and the master key of its time. A restored relay can hold an older snapshot than a Mac saw: that Mac refuses it, keeps its vault, and pushes again after the owner turns relay sync off and on (OPERATIONS.md 13).

## 9. The cutover

### 9.1 Preconditions

All of them, checked by the owner before step 1:

1. R1 and R2 are live at their versions (all six components), and R3 is the version that `FREE_RELAY_PATHS_END_VERSION` names in the apps (the notice of two releases).
2. The push gateway (2F) is live, and nodes push through it (`push.apassy.wyderka.cc/healthz`).
3. The transition switches of section 6 ran for at least a week.
4. The free disk of the host is at least twice the data volume (`du -sh` of the volume, `df -h` of the backup folder): the stopped backup is a full copy, and the cutover writes plain copies of the stores beside them.
5. The owner has confirmed the deletion of every team file on the hosted relay (plan s7, owner step 6), and chosen how long the stopped backup and the master key are kept.

### 9.2 The backup check

`connect-cutover` refuses to change anything unless **the backup check** passes: the stopped backup (the newest folder of the backup folder whose `MANIFEST.json` says `"stopped": true`, or the one named with `--backup <folder>`) holds a byte-identical copy, by size and SHA-256, of every file that the cutover keeps or deletes, and each of its own files still matches its manifest. Only `apassy-relay backup` with the service stopped makes such a backup; any write after it (a start of the relay included) makes the check fail. So the backup of step 4 must come right after step 3, and nothing may start the relay between step 4 and step 8.

### 9.3 The order

Each step: the command, what it changes, and how to undo it. Keep the outputs; they are the record.

1. **Owner. The state before.** `curl -sI https://apassy-relay.wyderka.cc/healthz` (version R3, `x-apassy-relay-mode: relay`); `docker compose exec -T relay apassy-relay admin teams > teams-before.json`; `docker inspect` of the running image (its id) and a copy of the compose file as `compose.yaml.pre-cutover`. Changes nothing.
2. **Owner. Announce the stop** (minutes): the API of the hosted relay answers 502 meanwhile; the downloads keep working from the Worker. Changes nothing.
3. **Owner. Stop the service:** `docker compose stop relay`. Changes: the relay stops; nodes and apps retry. Undo: `docker compose start relay`.
4. **Owner. The stopped backup:** `docker compose run --rm --no-deps -T relay backup > pre-cutover-backup.json`. Changes: a new folder in the backup folder (its name is `dir` in the JSON). Undo: none needed; it is the rollback point.
5. **Owner. Keep it off the host:** copy that folder and `pre-cutover-backup.json` to the owner's Mac (the pull of the deploy notes, or `rsync` now), and keep the master key file apart from it (it stays in Apassy too). Exclude the folder from the 14-day pruning of the backup timer until the retention of precondition 5 ends. Changes nothing on the relay.
6. **Owner. The dry run:** `docker compose run --rm --no-deps -T relay connect-cutover > cutover-plan.json`. Changes nothing (every file opened read-only, no file written). Check: `kept` is every team of `teams-before.json` with `"kind": "account"`; `deleted` is every other team; `backup.dir` is the folder of step 4; exit 0. A failed check exits 1 with the reason: fix it (a new stopped backup, a store to restore or delete), never skip it.
7. **Owner. The confirmation:** the owner reads `cutover-plan.json` (the counts of `before`, `kept`, `deleted`) and gives the explicit go for the deletion. Changes nothing.
8. **Owner. The cutover:** `docker compose run --rm --no-deps -T relay connect-cutover --confirm-delete-teams > cutover-result.json`. Changes, one way: `relay.db` and each vault store become plain files without keys; every other team file, snapshot folder, `.pre-v*` copy, `team.db.pre-teams`, and audit archive is deleted; the team codes, free Connect keys, and OAuth rows leave `relay.db`; `cutover.json` is written in the data volume. Undo: section 10. If it stops (an error, a kill, a reboot), run the same command again: section 9.5.
9. **Owner. The Connect settings:** edit the compose file to the "Connect" column of section 2: `APASSY_RELAY_MODE=connect`; remove `APASSY_RELAY_KEY_FILE` and the mount of `master_key`; remove the push settings, `APASSY_RELAY_FREE_CONNECT`, `APASSY_RELAY_CONNECT_SYNC_BYTES`, `APASSY_RELAY_TEAM_VAULTS`, and `APASSY_RELAY_CONNECT_ACCOUNTS`. Changes nothing until the start. Undo: `cp compose.yaml.pre-cutover compose.yaml`.
10. **Owner. Start Connect:** `docker compose up -d --wait relay`. Changes: the hosted service is Apassy Connect. A start that fails names the setting (a master key or a push value left is refused): fix the compose file and start again. Undo: section 10.
11. **Owner. The read-back** of section 9.4. If any check fails: section 10.
12. **Owner. The Worker:** in `crates/apassy-relay/deploy/worker/wrangler.jsonc` set the var `RELAY_MODE` to `connect` and deploy it with the Worker steps of the release runbook (tests, preflight, `npm run deploy`, the public delivery gate). Changes: `/internal/push` answers 404; `POST /v1/connect` loses its own guards (the relay answers 410). Undo: `RELAY_MODE` back to `relay`, deploy again.
13. **Owner. The record:** copy `cutover.json` from the volume (`docker compose cp relay:/data/cutover.json ./cutover.json`) to the backup of step 5. Changes nothing.
14. **Owner, after the retention of precondition 5:** remove the Worker secrets that Connect does not use (`npx wrangler secret delete PUSH_SECRET`, `npx wrangler secret delete APNS_KEY` in `deploy/worker`; the push gateway keeps its own `APNS_KEY`) and the files `master_key` and `push_secret` from the host's secrets folder, and then destroy the stopped backup and the master key in Apassy. Changes, one way: from then on no rollback to the hosted relay exists. Undo: none.

### 9.4 The read-back

- `curl -sI https://apassy-relay.wyderka.cc/healthz`: HTTP 200, `x-apassy-relay-version` the R3 version, `x-apassy-relay-commit` the commit of the image, `x-apassy-relay-mode: connect`.
- `curl -s -X POST https://apassy-relay.wyderka.cc/v1/connect -H 'content-type: application/json' -d '{}'`: HTTP 410, `"code":"hosted_retired"`. The same for `POST /v1/questions` and `POST /mcp`.
- `curl -s https://apassy-relay.wyderka.cc/.well-known/apassy-connect.json` lists the signing key; `curl -s https://apassy-relay.wyderka.cc/v1/plans` lists the prices.
- `docker compose exec -T relay apassy-relay admin teams`: only `"kind": "account"`, the same ids as `kept` of `cutover-result.json`.
- `docker compose exec -T relay ls -la /data`: `relay.db`, `cutover.json`, `teams/`, `relay.lock`, `admin.sock`; no `relay.db.keyed`. The container has no `APASSY_RELAY_KEY_FILE` (`docker compose exec -T relay env | grep -c APASSY_RELAY_KEY` answers 0) and no `master_key` under `/run/secrets`.
- `docker compose exec -T relay apassy-relay admin backup`: a backup with `"mode": "connect"`.
- On the owner's Mac (an account on a plan): Settings › Connect shows the plan; a vault synced through Connect pushes and pulls (Sync now); an iPhone without Tailscale, on cellular, approves a question through the tunnel; a cloud agent reaches `https://<node>.node.apassy.wyderka.cc/mcp`.
- The downloads: the public delivery gate of the release runbook (`check-public-assets.py`) passes as before.
- The Stripe dashboard: the webhook endpoint shows the deliveries after the start as answered 200.

### 9.5 If the cutover stops

Run step 8 again. Before its commit point (`relay.db` still keyed) the second run removes its side files (`*.plain`, `relay.db.keyed`, `cutover.json`) and starts over: the backup check must still pass, so the relay must not have started in between. After it (`relay.db` plain, `relay.db.keyed` present), the second run finishes the deletions and the record; it needs the configuration before the cutover (the master key), because a store that lost its plain copy is exported again with its key from `relay.db.keyed`. The dry run of step 6 says which case it is (`pending` in its JSON). Do not start the relay in `connect` mode before a run ends with `"state": "done"`: a team that is not a vault store would stay out of service. When the second run fails too: section 10.

## 10. Rollback

- **Before step 8:** nothing was changed. `cp compose.yaml.pre-cutover compose.yaml` if it was edited, `docker compose start relay`, and the Worker as it was.
- **After step 8 (the cutover ran, or stopped halfway):** stop the service (`docker compose stop relay`); keep the cut-over volume aside (do not delete it until the rollback is read back); restore the stopped backup of step 4 into an empty data volume with the restore procedure of the deploy notes (section 8); select the previous image and `compose.yaml.pre-cutover` (the master key mounted, the transition settings of section 2); `docker compose run --rm --no-deps -T relay snapshot-check`; `docker compose up -d --wait relay`; the Worker with `RELAY_MODE=relay`. Read back `/healthz` (`x-apassy-relay-mode: relay`) and `admin teams` (`teams-before.json`). Every change to accounts since the backup is lost with it: the vault stores of accounts get the snapshots of the backup (Macs that pushed since refuse the older copy and push again), and Stripe does not send again an event that Connect already answered: resend the events of the subscriptions that changed since the backup from the Stripe dashboard (Developers › Events › the event › Resend).
- **After step 14:** no rollback exists. The service rolls forward only (a fix in a new release).

`relay.db` in `connect` mode refuses every in-place downgrade (`downgrade-*`, `rollback-check`): the way back is only the stopped backup and the previous image.

## 11. What Connect stores, and what it never holds

It stores, as plain files: accounts (names, the recovery hash, the email copied from Stripe), account devices (names, platforms, public keys, times rounded to the hour), the SHA-256 of every key that ever was a device, link and join hashes, vault stores (one relay-sync team per vault: devices, signed heads, receipts, and the snapshots, which are ciphertext under the vault's passphrase), groups, invites as hashes, Stripe customer and subscription ids and states, event ids, tunnel nodes, grants, and monthly usage counts, entitlement key ids and public keys, and the relay audit (ids, actions, times). It never holds: a master key or any key of a file, a vault passphrase or vault key, an item value, a team vault of items, a question or an answer, a feed, an APNs token, a push secret, a proxy session, a token in a file (account tokens live in memory for 15 minutes), a link code, a recovery code, the signing key in a file other than its secret, or a client address on disk. The trust model ([docs/security/trust-model.md](../security/trust-model.md)) is the full list.
