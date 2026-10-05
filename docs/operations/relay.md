# Relay server

Date: 2026-10-01.
Scope: where the team relay runs. Decisions: [ADR 0016](../adr/0016-team-alpha-relay.md) and [ADR 0018](../adr/0018-local-bouncer-shared-vault-relay.md).

The relay is a separate private repository, `wydrox/apassy-relay` (FSL-1.1-ALv2). Its full runbook is `docs/OPERATIONS.md` in that repository: section 16 covers the VPS, 17 the teams, 18 the installer and the edge limits, and 13 the backups.

## What runs

- Public URL: `https://apassy-relay.wyderka.cc`, a Cloudflare Worker.
- The Worker reaches the relay through a Workers VPC binding and the named tunnel `apassy-relay`. No port on the VPS is public.
- VPS: SSH alias `ottervibe`, Debian 12, x86_64. Compose project `apassy` in `/opt/apassy`: containers `apassy-relay` and `apassy-relay-tunnel`, volume `apassy-relay-data`.
- Version: image `apassy-relay:teams-748f72e`: host-held item keys, several teams on one relay with per-team limits, and device keys with confirmed joins ([ADR 0019](../adr/0019-relay-teams-and-accounts.md), stages 1 to 4). Each team is its own encrypted file with its own key; `relay.db` holds the teams and is opened with the master key. The relay stores only sealed values. The item keys stay in `keys.json` on each owner's machine, and `apassy-team host` must run there for any run to start.
- Teams: `apassy-alpha` was migrated on 2026-10-01 to team `t_pmqboidksp` (schema version 3; the version 2 copy is `t_pmqboidksp.db.pre-v3`). The owner's Mac (`rafal-mac`, device 1) holds the item keys and signs in with a key in the login Keychain. Member tokens and old-form agent tokens of that team end on 2026-10-15.
- People join with an invite link, and an owner or manager confirms with the two safety words that the joiner reads out. A new team needs a one-time team code from the operator and `apassy-team create`.

The relay moved from a container on the owner's Mac on 2026-10-01. The Mac container `apassy-relay` and its volume `apassy-relay-data-v2` are stopped and kept for a rollback.

## Inspect

```sh
curl https://apassy-relay.wyderka.cc/healthz
ssh ottervibe 'cd /opt/apassy && docker compose ps'
apassy-team me
ssh ottervibe 'cd /opt/apassy && docker compose exec -T relay apassy-relay admin teams'
```

Users install the CLI and read the guide from the relay itself:

```sh
curl -fsSL https://apassy-relay.wyderka.cc/install.sh -o install.sh && sh install.sh
open https://apassy-relay.wyderka.cc/guide
```

New team (the code is shown once; give it to the future owner like a password):

```sh
ssh ottervibe 'cd /opt/apassy && docker compose exec -T relay apassy-relay admin team-code --hours 72' > team-code-file
apassy-team create --relay https://apassy-relay.wyderka.cc --team "Family" --name rafal < team-code-file
```

## What this setup does not do yet

- Backups: daily at 03:30 UTC to `/opt/apassy/backups/relay` (14 days kept), a weekly restore test, and a daily pull to the owner's Mac (`~/Backups/apassy-relay`). The master key is not in the backups: keep it apart.
- Monitoring: an hourly GitHub Actions check of `/healthz`; a failed run notifies the repository owner.
- The app has no Team source. Multiple active vaults and relay policy checks for a local bouncer (ADR 0018) are not built.
- One `apassy-team host` serves one team. The app has no team view yet (ADR 0019 stage 5).
- The owner's host runs in a terminal until `apassy-team host install` is run on the Mac (a background service that asks in a dialog).
- The operator, or root on the VPS, can open every team's metadata (not item values). Tell team owners.
