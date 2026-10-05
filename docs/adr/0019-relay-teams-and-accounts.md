# ADR 0019 — Teams and accounts on the relay

Date: 2026-10-01.
Status: ACCEPTED by the owner on 2026-10-01: several teams on one relay, with proper separation, simple onboarding, and the defaults below (identity per team, device keys, a confirmed join, one key holder, team codes from the operator). Implemented in `apassy-relay` on 2026-10-01 (stages 1 to 4; the details and the rules that two reviews added are in its `docs/SPEC.md` sections 22 and 23) and live. Not done yet: one host process for all teams of a machine (section 9; a host serves one team), the Secure Enclave key in the app (stage 5), and notifications beyond the audit.

## Context

The relay alpha ([ADR 0016](0016-team-alpha-relay.md), repository `apassy-relay`) holds one team. It runs on the VPS ([relay server](../operations/relay.md)).

- One SQLCipher file, `team.db`, with a `team` table of one row. One state in memory for the whole relay: sessions, run keys, long polls, host polls, and the audit with its masks. Run, agent, and member ids are the keys of these maps.
- People are members with a role: owner (one), manager, or member. A member joins with a one-time invite code and gets a member token. The token never expires and is plain text in `settings.json`. There are no devices.
- A member makes agent tokens (1 to 365 days).
- Only the owner's host holds item keys (`keys.json`). It must be online for every run. If `keys.json` is lost, the items are lost.
- A new member needs three steps from the owner: invite, find the member id, and grant each collection.

[ADR 0018](0018-local-bouncer-shared-vault-relay.md) makes a team a shared vault in the app, next to the personal vault, with several vaults active at once.

This record replaces two points of ADR 0016: the cut "a hosted multi-tenant relay" (section 8), and the reason given for trusting the operator ("the relay is self-hosted"). With several teams, the teams must trust the operator. The section "What this does not protect" says how far.

## Decision

### 1. Words

| Word | Meaning |
| --- | --- |
| Operator | The person who runs the relay. Works on the server only. Is not in any team by that role. |
| Team | One shared vault: members, devices, collections, items, grants, agents, runs, and audit. |
| Member | A person in one team, or a shared device of that team. Has a role. |
| Device | One key pair of one member. A Mac, an iPhone, or a CLI on a server. |
| Key holder | The one device of a team that holds the item keys and runs `apassy-team host`. |
| Agent | A token that a device makes for an AI agent. Acts for that member. |

### 2. Separation: one file and one state per team

- The relay keeps a small directory, `relay.db`: the teams (public id, name, state, limits, wrapped team key), team codes, and the operator audit. It holds no people, no items, and no runs.
- Each team is one SQLCipher file, `teams/<team id>.db`, with its own random 256-bit key. The directory keeps that key wrapped with the relay master key.
- The master key is a file on the VPS: `/opt/apassy/secrets/relay/master_key`. A snapshot of the VPS disk holds the master key and every team file. It is a full copy of all teams.
- Each team has its own state in memory: sessions, run keys, agent and host long polls, notifier, the audit with its masks, the limiter of refused requests, the counters, and the hashes of its live tokens. Every map key that could repeat between teams is local to that team's state. No map spans teams.
- A team id is random and public, for example `t_7k2m9q4x8c`. Ids inside a team file (member 1, item 1) are local to that team.
- The upstream proxy refuses loopback, private, link-local, CGNAT, and unique-local addresses after name resolution. A team cannot reach the VPS, its Docker networks, or other services on them.

### 3. Every credential names its team

| Credential | Form |
| --- | --- |
| Access token (device) | `apassy_acc_<team id>_<64 hex>` |
| Agent token | `apassy_tagt_<team id>_<64 hex>` (not `apassy_agt_`, which the core uses for local vault tokens) |
| Session key | `apassy_ses_<team id>_<64 hex>` |
| Invite | link `https://<relay>/join#<team id>.<code>` |
| Device link code | `apassy_lnk_<team id>_<64 hex>` |

- The relay reads the team id first. It checks the token hash against that team's set of live hashes in memory, and only then opens that team. A request handler, the proxy (`/p/`), MCP, and the host endpoints get one team and have no way to reach another.
- No endpoint takes a team id in the path. A user cannot point a request at another team.
- A token of team A at team B, a token of an unknown team, and an unknown token get the same `unauthenticated` answer.
- The audit masks every form above, with the team id. Tests cover each one.
- An invite code is never in a URL that a browser sends, a log, a process list, or a shell history. It does reach the relay, in the body of the join request, and Cloudflare sees it there (TLS ends at Cloudflare). The CLI reads a link from stdin. The join page only opens the app and never sends the fragment.

### 4. Identity is per team

There is no global user account. A person in two teams is two members, one in each team, with separate device keys. The app keeps the list of teams on the device and shows each as a shared vault.

- Why: no table links people across teams, so no bug and no operator query can show who is in which teams. Deleting a team deletes its people.
- Joining a second team is one more link.
- Cost: a device is added to, or revoked from, each team separately. The app does it in one step for all teams of the person. A person who loses their only device must be invited again in each team.

### 5. Devices sign in with a key pair

- A device makes a P-256 key pair when it joins a team. Where the private key is kept:
  - App on macOS and iOS: the Secure Enclave.
  - CLI on macOS, including the key holder's `apassy-team host`: the login Keychain (a binary built from source cannot use the Secure Enclave).
  - CLI on Linux: a file with mode 0600.
- A device id is `<team id>/<number>`. The relay stores only the public key.
- Sign-in: `POST /v1/auth/challenge` returns a nonce. The nonce is valid for 60 seconds and works once. `POST /v1/auth/token` takes the device id, the nonce, and an ECDSA signature over `"apassy-relay sign-in v1\0" || relay origin || "\0" || device id || "\0" || nonce`. It returns an access token that lasts 15 minutes. The token is held in memory only. The client renews it without the user.
- Revoking a device or a member drops its access tokens at once.
- A restart of the relay ends all access tokens. Clients sign in again by themselves.
- There are no passwords, no email, and no member tokens. The device private key (a file on Linux) and agent tokens are still secrets. Protect them like the tokens of today.
- An agent token belongs to the device that made it. Revoking the device revokes its agents.

### 6. Onboarding

The goal: the owner sends one link and confirms once, the person taps the link, and the person can work. No member ids and no separate grant step.

1. **Create a team.** The owner pipes a team code from the operator to `apassy-team create --relay URL --team NAME --name NAME`, or uses "New shared vault" in the app. The device key is made. The owner is in the team, and this device is its key holder.
2. **Invite.** `apassy-team invite --name ola --grant payments,family` (or the app: "Invite", pick the collections). The result is a link and a QR code. One use. 72 hours by default, at most 7 days. The invite carries the role, the collections to grant, and an optional name.
3. **Join.** The person opens the link in the app, or pipes it to `apassy-team join`. The device key is made. The join screen shows the team name, the inviter, and the team id. If two teams on the device have the same name, the app warns. Then the app shows two safety words and "Waiting for Rafal".
4. **Confirm.** An owner or a manager sees "Ola wants to join from MacBook Air" with the same two safety words, and taps Confirm. CLI: `apassy-team joins` and `apassy-team confirm ID`. The grants of the invite apply only now. A join that is not confirmed in 72 hours ends.
5. **Add a device.** On a device that is already in, "Add a device" shows a QR code. The code is valid for 10 minutes and works once, with one code for each team of the person. The new device scans it. The old device shows the new device's name and two safety words, and the person confirms there. An owner device that is added is reported to the other owners.
6. **Shared device.** The owner invites a shared device with `--shared`, for example the family computer. It is a member of kind `shared`: it has its own grants and agents, and no person behind it. It cannot add devices or invite.

- If the person who was invited finds the link already used, the app and the CLI say so plainly, and the owner is told.
- The owner sees each join in the app and in the audit, and can remove the member at once.

### 7. Roles

| Role | Can |
| --- | --- |
| Owner (one or more) | everything in the team; invite and confirm managers and owners; remove any member; delete the team |
| Manager | collections, items, grants; invite and confirm members; deny a waiting run |
| Member | use granted collections; make agents; add own devices |
| Shared device | as member, without devices and invites |

A team must keep at least one owner. A second owner can run the team when the first is away, but does not hold the item keys (section 9).

### 8. Leaving, removal, and deletion

- A member leaves the team, or an owner removes them. Their devices, agents, grants, sessions, and waiting runs end at once (as revocation does today).
- A device is revoked by its member or by an owner. Its agents end with it.
- An owner can hand ownership to another member and then leave.
- An owner deletes the team in two steps. First the team is suspended: every token stops at the next request, and sessions and waiting runs end. Any owner can undo this for 7 days. Then the relay deletes the file and its wrapped key.

### 9. Item keys and the key holder

- The item keys of a team are on one device, the key holder. It is the device that created the team, or a device that an owner names later with the keys moved to it. The host endpoints (`/v1/host/...`) require the key holder's access token. The role "owner" alone is not enough. A second owner that runs `apassy-team host` gets 403, not random denials.
- The key store finds an entry by relay URL and item uid, as today. The host's own check uses the team id, not the team name. One `apassy-team host` process serves every team in which this machine is the key holder.
- A second owner gives no protection for the items. If the key holder is lost, the items are added again. More key holders (more owner devices, or member devices for ADR 0018) are a separate decision.

### 10. Operator

- The operator works only on the server. `docker compose exec relay apassy-relay admin ...` talks to a Unix socket of the running relay process. The socket is in the container, and only the relay user can use it. There is no operator endpoint on HTTP.
- Commands: make a team code (one use), list teams (name, created, counts, last activity), suspend, resume, delete, and set limits. Delete is suspend, then drain (sessions and waiting runs end, the file is closed), then the file and the wrapped key are deleted.
- No operator command shows members, items, runs, or the team audit.
- Each operator action on a team is also a row in that team's audit, with the actor `operator`.
- Team creation needs a code from the operator in this stage. Open sign-up waits for abuse limits and billing.
- Master key rotation: make a new master key, wrap every team key again, then destroy the old key. A backup of `relay.db` from before can be opened until every master key in force at that time is destroyed. Keep backups for a limited time.

### 11. Limits

Per-team limits must fit inside the relay limits (256 requests at once; 224 on the agent lane; 32 for members).

| Limit | Default per team |
| --- | --- |
| Members, items, live agents | 50, 500, 100 |
| Runs per hour, waiting runs | 1000, 50 |
| Requests at once on the agent lane | 1/4 of the lane (56) |
| Host long polls | 1, on a separate lane for key holders |

- Unauthenticated endpoints (join, challenge, device link, create) have a limit per IP address at the Worker, and a limit for the whole relay.
- A request with a token that is not in the team's set of live hashes is refused before the team's database is used. A flood of false tokens does not hold the team's connection.
- A team over a limit gets 503 `busy` or 403 `team_limit`. Other teams see no change.

### 12. Migration of `apassy-alpha`

1. Back up `team.db`, the vault key, and `keys.json`.
2. Migrate the schema from version 2 to version 3: devices, joins, the member kind, and the key holder. Names become unique among live members only, so a removed name can be invited again. Member tokens stay valid for an enrollment period of 14 days.
3. Give the file a new key with `PRAGMA rekey`. Wrap the new key with a new master key. The old vault key then opens only the backups. Delete the Mac rollback volume `apassy-relay-data-v2` after the check in step 6, because the old key opens it.
4. Each member runs `apassy-team device enroll` once, with their old member token on stdin. The relay registers the device key. The owner's Mac becomes the key holder.
5. After the enrollment period, the relay refuses member tokens. Agent tokens of the old form stop at once. The members make new ones.
6. Check: collections, items, grants, and audit are as before. A run passes through the key holder.

Rollback until step 6: stop the relay, put back the version 2 file with the old vault key and the alpha image.

## What this protects

- A request of one team cannot read, change, or wait on data of another team. A failure would need a bug in the code that reads the team id, not in a handler.
- A stolen team file without the master key gives nothing. With the master key, it gives the metadata of that team, never an item value (host-held keys).
- A leaked invite link gives nothing without a confirmation by an owner or a manager. A leaked device link code works once, for 10 minutes, and needs a confirmation on the old device.
- A copied `settings.json` gives no long-lived secret. The device key of the CLI on Linux and the agent tokens still do.

## What this does not protect

- The operator, or root on the VPS, holds the master key and can open every team file: names, members, hosts, commands, and audit. A snapshot of the VPS disk is a full copy of all teams. Item values stay sealed. Metadata that the operator cannot read needs encryption on the clients. That is not in this record.
- Cloudflare sees all traffic in clear, including invite codes in join requests, as before.
- All teams share one process. A crash or a restart affects every team.
- A device that is taken over acts as its member until it is revoked. An owner or a manager who confirms a join without checking the safety words lets the wrong person in.

## Required checks

- For every endpoint, `/p/`, and MCP: a token or session key of team A gets no data of team B, and gets the same error as an unknown token.
- A run id, an agent id, or a member id that exists in two teams never mixes their sessions, run keys, polls, or audit masks.
- A host of team A cannot see or release a run of team B. An owner that is not the key holder gets 403 on the host endpoints.
- The proxy refuses an item host that resolves to a private or loopback address.
- A team at its limits slows only itself. A flood of false tokens does not lock the team's database.
- A suspended team's tokens fail at the next request. A deleted team's file and wrapped key are gone.
- A join that is not confirmed gets no grant. A device link code works once. A revoked device's access token fails at once.
- The audit masks every new credential form.
- The migrated `apassy-alpha` keeps its collections, items, grants, and audit.

## Stages

1. The directory, a file and a state per team, team ids in credentials, the proxy address block, the operator socket, and the migration.
2. Device keys, sign-in, device link, device revocation, and the key holder in the CLI.
3. Invite links with grants, joins with confirmation, `create` and `join` from stdin, and a join page that opens the app.
4. The separation tests, the limits, and a backup of each team.
5. The app: the Secure Enclave key, and teams as shared vaults (with ADR 0018).

## Open decisions

1. Open sign-up instead of team codes from the operator, and billing.
2. More key holders per team (section 9).
3. Sign in with Apple or Google as a second way, beside device keys.
4. Metadata that the operator cannot read.
