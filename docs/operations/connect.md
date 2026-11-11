# Apassy Connect: the hosted service, and the cutover from the hosted relay

Date: 2026-11-10. Status: runbook for release R3 of [implementation plan s7](../design/implementation-plan-s7-connect.md) (units C5 and O2). Nothing here has run against production: every step marked **Owner** changes the hosted service and runs only after the owner's go.
Decisions: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 7, D7, D8, D14, "Migration". Relay reference: `crates/apassy-relay/docs/SPEC.md` sections 33 to 37 and `docs/OPERATIONS.md` sections 26 to 29. The page of the service: [relay.md](relay.md).

Run the commands on the Connect host, in the compose directory of the deployment (the private deploy notes name both; production addresses stay out of this repository). `docker compose run --rm --no-deps -T relay <command>` runs a relay command on the data volume with the compose settings while the service is stopped; `docker compose exec -T relay apassy-relay <command>` runs one in the running service.

## 1. What runs

| Part | Before the cutover (`relay` mode) | After it (`connect` mode) |
| --- | --- | --- |
| Edge Worker `apassy-relay.wyderka.cc` | `RELAY_MODE=relay`: forwards to the relay with the edge secret, sends APNs pushes for the relay (`/internal/push`), limits the free Connect teams | `RELAY_MODE=connect`: forwards to the relay; `/internal/push` is off (404); `/v1/connect` and its challenge answer 410 `hosted_retired` at the edge. `/dl/`, `/guide`, `/install.sh` as before. A deploy refuses a `RELAY_MODE` that is not the relay's (step 12) |
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

**Owner, step T2:** first write down the two values as they are (`docker compose config | grep -E 'APASSY_RELAY_(FREE_CONNECT|CONNECT_SYNC_BYTES)'`; on the hosted relay `APASSY_RELAY_FREE_CONNECT` is unset, which is `1`, and `APASSY_RELAY_CONNECT_SYNC_BYTES` is `67108864`). Then in the compose file set `APASSY_RELAY_FREE_CONNECT=0` and `APASSY_RELAY_CONNECT_SYNC_BYTES=0` (replacing `67108864`), then `docker compose up -d --wait relay`.
Effect: `POST /v1/connect` and its challenge answer 410 `free_connect_ended`; every free Connect team's questions, feed, and push answer 410 `free_connect_ended`; their snapshot pushes and receipts answer 403 `plan_required`; their pulls and downloads still work, and their devices can leave. Operator teams and vault stores do not change. The apps show the notice of N1 already; this makes it the fact.
Undo: put back the two values written down: remove the line `APASSY_RELAY_FREE_CONNECT=0` (or set `1`), and set `APASSY_RELAY_CONNECT_SYNC_BYTES` back to its value before (`67108864` on the hosted relay; do not remove that line: unset is `0`, which gives new free Connect teams no relay sync), then `docker compose up -d --wait relay`. Check with the same `docker compose config` line.
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
4. The free disk of the host is enough for three things at once (`du -sh` of the volume and of `relay.db`, `df -h` of the volume and of the backup folder): the stopped backup, a full copy of the volume (on the disk of the backup folder); and, beside the volume, two copies of `relay.db` (the cutover copies it three times, `relay.db.work`, `relay.db.plain`, and `relay.db.keyed`, and at most two of them exist at once) plus one plain copy of each file of `converted` (each vault store's database and its keyed copies, all written before the commit point). When the backup folder is on the disk of the volume, three times the size of the volume always covers it.
5. The owner has confirmed the deletion of every team file on the hosted relay (plan s7, owner step 6), and chosen how long the stopped backup and the master key are kept.

### 9.2 The backup check

`connect-cutover` refuses to change anything unless **the backup check** passes: the stopped backup (the newest folder of the backup folder whose `MANIFEST.json` says `"stopped": true`, or the one named with `--backup <folder>`) holds a byte-identical copy, by size and SHA-256, of every file that the cutover changes or deletes and of every file under `teams/` (`relay.db`; under `teams/` each team file, `.pre-v*` copy, snapshot folder, file of a team id that `relay.db` does not name, and file of no team; `team.db` and its journal, `team.db.pre-teams`, the files of a migration that stopped, and `audit-archive/`), and each of its own files still matches its manifest. The backup leaves out only the side files of a cutover that stopped (`relay.db.work`, `relay.db.plain`, `relay.db.keyed` beside a keyed `relay.db`, `cutover.json`, and a `<file>.plain` or `<file>.plain-journal` beside a file of a vault store), which are not data, and the entries at the top of the volume that the relay does not know, which the cutover neither changes nor deletes (it names them in `left`). Only `apassy-relay backup` with the service stopped makes such a backup; any write after it (a start of the relay included) makes the check fail. So the backup of step 4 must come right after step 3, and nothing may start the relay between step 4 and step 8.

The confirmed run checks it again, against the hashes in `cutover.json`, before each step that deletes, also when it finishes a run that stopped: leave the backup folder of step 4 where it is, unchanged, until the cutover is done. Each file that the cutover deletes must also be in that backup, byte for byte.

### 9.3 The order

Each step: the command, what it changes, and how to undo it. Keep the outputs; they are the record.

1. **Owner. The state before.** `curl -s -D - -o /dev/null https://apassy-relay.wyderka.cc/healthz` (the headers of a `GET`: `/healthz` answers no `HEAD`; HTTP 200, version R3, `x-apassy-relay-mode: relay`); `docker compose exec -T relay apassy-relay admin teams > teams-before.json`; `docker inspect` of the running image (its id) and a copy of the compose file as `compose.yaml.pre-cutover`. Changes nothing.
2. **Owner. Announce the stop** (minutes): the API of the hosted relay answers 502 meanwhile; the downloads keep working from the Worker. Changes nothing.
3. **Owner. Stop the service:** `docker compose stop relay`. Changes: the relay stops; nodes and apps retry. Undo: `docker compose start relay`.
4. **Owner. The stopped backup:** `docker compose run --rm --no-deps -T relay backup > pre-cutover-backup.json`. Changes: a new folder in the backup folder (its name is `dir` in the JSON). Undo: none needed; it is the rollback point.
5. **Owner. Keep it off the host:** copy that folder and `pre-cutover-backup.json` to the owner's Mac (the pull of the deploy notes, or `rsync` now), and keep the master key file apart from it (it stays in Apassy too). Exclude the folder from the 14-day pruning of the backup timer until the retention of precondition 5 ends. Changes nothing on the relay.
6. **Owner. The dry run:** `docker compose run --rm --no-deps -T relay connect-cutover > cutover-plan.json`. Changes nothing (every file opened read-only, no file written). Check: `kept` is every team of `teams-before.json` with `"kind": "account"`; `deleted` is every other team; `orphans` (when there) names team ids that have files in `teams/` but no row in `relay.db`, whose files go too; `converted` is the database of each kept store (and any keyed copy of it); `left` names what stays untouched; `side_files` (when there) names files of an earlier run that stopped, which the confirmed run removes first; `backup.dir` is the folder of step 4; exit 0. The plan has a SHA-256, `plan_sha256` (`jq -r .plan_sha256 cutover-plan.json`), over what it keeps, converts, and deletes, the file hashes, the backup it checked, and the relay's version and commit: run steps 6 and 8 with the same image (a new image needs a new dry run). A failed check exits 1 with the reason: fix it (a new stopped backup, a vault store restored from a backup), never skip it. A file of a vault store that does not open with the store's key (a damaged `.pre-v*` copy) is refused here: no key would open it after the cutover. It is in the backup of step 4; restore it, or move it out of the volume (beside that backup), then steps 4 to 6 again. Never delete a vault store (`admin delete` refuses one in any case).
7. **Owner. The confirmation:** the owner reads `cutover-plan.json` (the counts of `before`, `kept`, `deleted`) and gives the explicit go for the deletion of exactly that plan, by its `plan_sha256`. Changes nothing.
8. **Owner. The cutover:** `docker compose run --rm --no-deps -T relay connect-cutover --confirm-delete-teams <plan_sha256 of step 6> > cutover-result.json`. It goes on only if the data directory and the backup still give that plan: any change since step 6 (a newer backup, a file changed) refuses it, and then steps 6 and 7 come again. Changes, one way: `relay.db` and each vault store become plain files without keys (a keyed `.pre-v*` copy of a vault store becomes plain too); every other team's files (its database, journal, `.pre-v*` copies, snapshot folder, and any other entry with its team id, `.plain` names included), the files of the team ids of `orphans`, `team.db` and its journal, `team.db.pre-teams`, the files of a stopped migration, and the audit archives are deleted, each a file of the backup of step 4 (`files_deleted` in `cutover-result.json` lists them); the side files of `side_files` are removed; the team codes, free Connect keys, and OAuth rows leave `relay.db`; `cutover.json` is written in the data volume. A file of `teams/` with no team id and the entries of `left` stay as they are. Undo: section 10. If it stops (an error, a kill, a reboot), run the same command again: section 9.5.
9. **Owner. The Connect settings:** edit the compose file to the "Connect" column of section 2: `APASSY_RELAY_MODE=connect`; remove `APASSY_RELAY_KEY_FILE` and the mount of `master_key`; remove the push settings, `APASSY_RELAY_FREE_CONNECT`, `APASSY_RELAY_CONNECT_SYNC_BYTES`, `APASSY_RELAY_TEAM_VAULTS`, and `APASSY_RELAY_CONNECT_ACCOUNTS`. Changes nothing until the start. Undo: `cp compose.yaml.pre-cutover compose.yaml`.
10. **Owner. Start Connect:** first `docker compose run --rm --no-deps -T relay snapshot-check` with the Connect settings (it reads the plain files read-only: exit 0 and `Verified snapshots of <n> teams`, `<n>` the number of `kept`); then `docker compose up -d --wait relay`. Changes: the hosted service is Apassy Connect. A start that fails names the setting (a master key or a push value left is refused) or the cutover (one that is not finished is refused: section 9.5): fix it and start again. Undo: section 10.
11. **Owner. The read-back** of section 9.4. If any check fails: section 10.
12. **Owner. The Worker:** in `crates/apassy-relay/deploy/worker/wrangler.jsonc` set the var `RELAY_MODE` to `connect`, commit it to the repository (so every later checkout has it), and deploy it with the Worker steps of the release runbook (tests, preflight, `npm run deploy`, the public delivery gate). The preflight and the Wrangler build hook read `x-apassy-relay-mode` from `GET https://apassy-relay.wyderka.cc/healthz` and refuse a `RELAY_MODE` that is not the relay's (`scripts/check-relay-mode.mjs`): so no later deploy, from any checkout of R3 or newer, can turn `/internal/push` and the free Connect guards back on in front of Connect. A relay that answers 200 without that header is a relay before it (0.5.19 and older), in `relay` mode: it passes `RELAY_MODE` `relay` and refuses `connect`. `APASSY_EDGE_MODE_CHECK=skip` is honoured only when the relay cannot be reached (the request fails or times out, or the edge answers a gateway error such as the Worker's 502 "relay unreachable" without the mode header), and the deploy says so on the console; when the relay answers, the check runs and the skip is ignored. Set the mode only in `wrangler.jsonc`, never with `wrangler deploy --var`. **What the check cannot cover:** it runs only in a build from a checkout, so it does not see a change of `RELAY_MODE` in the Cloudflare dashboard, a deploy that skips the build hook, or a rollback to an older version of the Worker (the dashboard's version history or `wrangler rollback`, including any version older than R3, which has no `connect` mode). Do none of them after the cutover. If one happens anyway, the relay itself still protects Connect: in `connect` mode it answers 410 `hosted_retired` on every retired route (`/v1/connect`, `/v1/questions`, `/v1/feed`, `/mcp`, `/p/`, and the rest of SPEC section 37.2) before its body is read, so the free paths stay off; what such a Worker turns back on is only its own `/internal/push`, the APNs sender, until step 14 removes `PUSH_SECRET` and `APNS_KEY`. Undo it by deploying from the repository again. Changes: `/internal/push` answers 404; `/v1/connect` and `/v1/connect/challenge` answer 410 `hosted_retired` at the edge. Undo: `RELAY_MODE` back to `relay` after the relay is back in `relay` mode (section 10), deploy again.
13. **Owner. The record:** copy `cutover.json` from the volume (`docker compose cp relay:/data/cutover.json ./cutover.json`) to the backup of step 5. Changes nothing.
14. **Owner, after the retention of precondition 5:** remove the Worker secrets that Connect does not use (`npx wrangler secret delete PUSH_SECRET`, `npx wrangler secret delete APNS_KEY` in `deploy/worker`; the push gateway keeps its own `APNS_KEY`) and the files `master_key` and `push_secret` from the host's secrets folder, and then destroy the stopped backup and the master key in Apassy. Changes, one way: from then on no rollback to the hosted relay exists. Undo: none.

### 9.4 The read-back

- `curl -s -D - -o /dev/null https://apassy-relay.wyderka.cc/healthz`: HTTP 200, `x-apassy-relay-version` the R3 version, `x-apassy-relay-commit` the commit of the image, `x-apassy-relay-mode: connect`.
- `curl -s -X POST https://apassy-relay.wyderka.cc/v1/connect -H 'content-type: application/json' -d '{}'`: HTTP 410, `"code":"hosted_retired"`. The same for `POST /v1/questions` and `POST /mcp`.
- `curl -s https://apassy-relay.wyderka.cc/.well-known/apassy-connect.json` lists the signing key; `curl -s https://apassy-relay.wyderka.cc/v1/plans` lists the prices.
- `docker compose exec -T relay apassy-relay admin teams`: only `"kind": "account"`, the same ids as `kept` of `cutover-result.json`.
- `docker compose exec -T relay ls -la /data`: `relay.db`, `cutover.json`, `teams/`, `relay.lock`, `admin.sock`; no `relay.db.keyed`, `relay.db.work`, or `*.plain`. The container has no `APASSY_RELAY_KEY_FILE` (`docker compose exec -T relay env | grep -c APASSY_RELAY_KEY` answers 0) and no `master_key` under `/run/secrets`.
- `docker compose exec -T relay apassy-relay admin backup`: a backup with `"mode": "connect"`.
- On the owner's Mac (an account on a plan): Settings › Connect shows the plan; a vault synced through Connect pushes and pulls (Sync now); an iPhone without Tailscale, on cellular, approves a question through the tunnel; a cloud agent reaches `https://<node>.node.apassy.wyderka.cc/mcp`.
- The downloads: the public delivery gate of the release runbook (`check-public-assets.py`) passes as before.
- The Stripe dashboard: the webhook endpoint shows the deliveries after the start as answered 200.

### 9.5 If the cutover stops

Run step 8 again, with the same `plan_sha256`; the dry run of step 6 says which case it is (`state` and `pending` in its JSON) and names the plan. After the commit point that dry run makes every check of the confirmed run, read-only (the backup again, `relay.db.keyed`, each file that goes against the backup, each store's key, and `cutover.json` against its own `plan_sha256`, so a record changed by hand is refused), and lists what the confirmed run does: `to_convert` (the files made plain) and `to_delete` (the files deleted); a check that fails there fails the confirmed run the same way. Before its commit point (`relay.db` still keyed) an error removes the side files at once (`relay.db.work`, `*.plain`, `relay.db.keyed`, `cutover.json`); after a kill or a reboot the next run removes them first and starts over: the backup check must still pass, so the relay must not have started in between (if it did, the side files block nothing: make a new stopped backup and go back to step 6). After the commit point (`relay.db` plain, `relay.db.keyed` present), the second run finishes the deletions and the record; it needs the configuration before the cutover (the master key), because each file that is still keyed is exported again with its key from `relay.db.keyed` (a plain copy of the run that stopped, whole or partial, is removed and written again), and it checks the backup of step 4 again first. Neither mode of the relay starts while a cutover is not finished: `relay` mode refuses a plain `relay.db` beside `relay.db.keyed`, and `connect` mode refuses an encrypted `relay.db` and a `relay.db.keyed`, each before it opens or changes a file, with a message that says to run the cutover again. A `cutover.json` that cannot be read or whose `state` is not `done` stops `connect` mode only when the files are not those of a finished cutover (a plain `relay.db`, no `relay.db.keyed` and no other side file, no old file or audit archive, every team file plain, and only vault stores of accounts): then the message says to restore the backup (section 10). On the files of a finished cutover the relay starts, logs that the record is not readable, and never rewrites it; put back the copy of step 13 for the record. When the second run fails too: section 10.

### 9.6 What "deleted" means on the disk

The cutover deletes files: the filesystem frees their blocks and does not overwrite them, so until those blocks are used again, someone with the raw volume (root on the host, or the hosting provider) can read the bytes the files had. What those bytes are:

- The deleted team files, `.pre-v*` copies, audit archives, and `relay.db.keyed` were SQLCipher files: their freed blocks hold ciphertext. The keys of the team files were only in the keyed `relay.db`, itself ciphertext under the master key; the audit archives open with the master key. The cutover never writes a team key or a deleted row to the disk in plain: it edits and vacuums a keyed working copy of `relay.db` (`relay.db.work`) and exports only the result.
- `team.db.pre-teams` (and an old `team.db`) is the file of the single team from before teams: SQLCipher too, under the old single-team key (the key of the old `team.db` that `apassy-relay migrate` read from `APASSY_RELAY_OLD_KEY`), not under the master key or a key of `relay.db`. Its freed blocks open only with that old key, if it is still kept anywhere.
- The snapshots of deleted teams were ciphertext under each vault's passphrase.
- So the freed blocks open only with the master key (or, for `team.db.pre-teams`, the old single-team key), which never was on the data volume (it is a mounted secret file). The stopped backup of step 4 opens with it too. Destroying the master key and the backup (step 14) makes both unreadable. The key file itself is on the host's disk, in its secrets folder: removing it at step 14 frees its blocks there in the same way.

If that is not enough (for example, the master key may have leaked, or no ciphertext of the old teams may stay on the provider's disk), move the data to a new volume and destroy the old one: after step 11, stop the service, make a stopped backup (section 8; it holds only the plain files of Connect), restore it into a new, empty volume, start on it, and then delete the old volume (and, with disk encryption of the host, its key). For the blocks of the key file on the host's own disk, the same remedy is a new disk (a new server) rather than a new volume. The owner does not control the provider's reuse of the underlying storage; deleting the volume or the server is the last step that is in their hands.

## 10. Rollback

- **Before step 8:** nothing was changed. `cp compose.yaml.pre-cutover compose.yaml` if it was edited, `docker compose start relay`, and the Worker as it was.
- **After step 8 (the cutover ran, or stopped halfway):** stop the service (`docker compose stop relay`); keep the cut-over volume aside (do not delete it until the rollback is read back); restore the stopped backup of step 4 into an empty data volume with the restore procedure of the deploy notes (section 8); select the previous image and `compose.yaml.pre-cutover` (the master key mounted, the transition settings of section 2); `docker compose run --rm --no-deps -T relay snapshot-check`; `docker compose up -d --wait relay`; the Worker with `RELAY_MODE=relay`. Read back `/healthz` (`x-apassy-relay-mode: relay`) and `admin teams` (`teams-before.json`). Every change to accounts since the backup is lost with it: the vault stores of accounts get the snapshots of the backup (Macs that pushed since refuse the older copy and push again), and Stripe does not send again an event that Connect already answered: resend the events of the subscriptions that changed since the backup from the Stripe dashboard (Developers › Events › the event › Resend).
- **After step 14:** no rollback exists. The service rolls forward only (a fix in a new release).

`relay.db` in `connect` mode refuses every in-place downgrade (`downgrade-*`, `rollback-check`): the way back is only the stopped backup and the previous image.

## 11. What Connect stores, and what it never holds

It stores, as plain files: accounts (names, the recovery hash, the email copied from Stripe), account devices (names, platforms, public keys, times rounded to the hour), the SHA-256 of every key that ever was a device, link and join hashes, vault stores (one relay-sync team per vault: devices, signed heads, receipts, and the snapshots, which are ciphertext under the vault's passphrase), groups, invites as hashes, Stripe customer and subscription ids and states, event ids, tunnel nodes, grants, and monthly usage counts, entitlement key ids and public keys, and the relay audit (ids, actions, times). It never holds: a master key or any key of a file, a vault passphrase or vault key, an item value, a team vault of items, a question or an answer, a feed, an APNs token, a push secret, a proxy session, a token in a file (account tokens live in memory for 15 minutes), a link code, a recovery code, the signing key in a file other than its secret, or a client address on disk. The trust model ([docs/security/trust-model.md](../security/trust-model.md)) is the full list.
