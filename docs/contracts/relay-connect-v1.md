# Relay connect wire contract v1

Date: 2026-10-13.
Status: proposed, for [ADR 0027](../adr/0027-plans-and-connect.md) (Apassy Connect). The app side (`src/sync/relay_link.rs`, `src/sync/relay.rs`, `src/relay/membership.rs`, and the iPhone core `ios/ApassyCore`) and the relay side (`apassy-relay`, branch `feat/connect`, `docs/SPEC.md` section 26) implement it. A change to this document changes both sides, one pull request on each; a change to the link grammar or to a check bumps `v1`. The app implements the client itself and does not depend on the relay crate (FSL license).

This document adds to [relay-sync-v1](relay-sync-v1.md) and [relay-questions-v1](relay-questions-v1.md). It repeats nothing from them: the encodings (sync section 2), the envelope and the errors (sync section 4), the Worker and the transport (sync section 3), and the question key (questions section 5.1) are the same here.

A name that this document uses and the [build plan](../product/sync-plans/build-plan.md) does not fix is marked "(name to confirm with the relay stream)".

## 1. Purpose

A Connect team is a relay team that anyone can make without an operator code. It carries questions and answers (relay-questions-v1), not vault snapshots. Plan Free uses it. Plan Personal and Plan Team lift its limits (section 6) and add the purpose `sync` to the same team.

An operator team (`POST /v1/teams` with `apassy_tcd_<64 hex>`, relay-sync-v1 section 6) is unchanged. A relay that an operator runs may refuse `POST /v1/connect` or leave it off (name of the switch to confirm with the relay stream).

## 2. `POST /v1/connect`

Edge endpoint, no `Authorization` header (the relay refuses a bearer here, as on the other edge endpoints). Only the Mac calls it. The Mac decides the plan; the iPhone never creates a team. App Attest is not part of v1.

Request:

```json
{"v":1,"team":"Personal","device_name":"MacBook Pro","public_key":"<b64u>"}
```

- `v`: the number `1`.
- `team`: the vault name, trimmed and cut to 64 bytes at a character boundary (as relay-sync-v1 section 6).
- `device_name`: this Mac's name, control characters removed, cut to 64 bytes.
- `public_key`: the new device key, P-256 X9.63 uncompressed, b64u (relay-sync-v1 section 2).
- No `code` and no `owner`. The member is the fixed name `owner`, as in a personal team.
- The relay refuses unknown fields (`400 invalid_request`).

Answer: the `TeamCreated` result of `POST /v1/teams` plus `kind`:

```json
{"team_id":"t_7k2m5q4x3c","member_id":1,"device_id":1,"kind":"connect"}
```

The device is the owner's and holds the key-holder flag, as in a personal team. The Mac then signs in (relay-sync-v1 section 5). The sign-in answer carries `team_kind` (`operator` or `connect`) (name to confirm with the relay stream).

The relay stores the kind of a team as `team.kind` (`operator` or `connect`) in `relay.db`. It also stores `connect_key(key_hash, team_id)` (section 4).

### 2.1 Errors

The envelope and the codes are those of relay-sync-v1 section 4.

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, an unknown field, `v` not `1`, a bad key encoding, a body over 64 KiB. |
| 403 | `plan_required` | A snapshot push (`PUT /v1/sync/snapshot`) to a team of kind `connect` whose limits are not lifted (section 5). Not an answer of `POST /v1/connect`. |
| 409 | `conflict` (code name to confirm with the relay stream) | This public key already made a Connect team (section 4), even if that team is deleted. |
| 429 | `rate_limited` | The per-IP limit of the Worker (section 3). `Retry-After: 60`. |
| 503 | `busy` | The relay-wide cap `connect_teams_per_day` is reached (section 3). `Retry-After: 2`. |

A refused call makes no team and leaves no `connect_key` row.

## 3. Limits on creating

The Worker binding fails open. So every limit that matters is also in the relay.

| Limit | Value | Where |
| --- | --- | --- |
| Calls per IP address | 3 per hour and 20 per day, by `cf-connecting-ip` (`CONNECT_LIMITER`) | Worker: `429 rate_limited` |
| Calls per IP address, again | the same values | relay: `429 rate_limited` |
| Connect teams per public key | 1, ever | relay: `409` |
| Connect teams per day on the whole relay (`connect_teams_per_day`) | 200 by default; a config value | relay: `503 busy` |

The relay keeps an IP address only as a hash (to confirm with the relay stream).

## 4. One team per public key

The relay keeps the SHA-256 of the public key in `connect_key(key_hash, team_id)`. The row stays after the team is deleted, so a key cannot make a second Connect team, and a deleted team cannot be made again with the same key. A Mac that lost its team makes a new device key and a new team.

## 5. The `connect` preset

A team of kind `connect` starts with these `TeamLimits`:

| Limit | Value |
| --- | --- |
| Members | 1 |
| Devices per member | 10 (as relay-sync-v1 section 12) |
| `sync_bytes` | 0 |
| `question_bytes` | 2 MiB |

With `sync_bytes` 0, `PUT /v1/sync/snapshot` answers `403 plan_required`. The error message tells the owner that sync needs a paid plan. Nothing is stored. Every other endpoint of the team works as in a personal team: sign-in, device links, questions, answers, and push tokens.

`POST /v1/teams/entitlement` lifts the preset to the limits of the plan. The call needs a signed-in device of the team and an `apassy_ent_` token. The relay verifies the token with the public key of the accounts service and checks `exp` again on each push. The token carries no device claim, and the call never adds a device or signs in. The body and the answer are in the relay stream's section 26 (name and shape to confirm with the relay stream).

The order of the checks on a push (relay-sync-v1 section 4): where `plan_required` stands among them is to confirm with the relay stream.

## 6. Idle cleanup

A Connect team with one device that has not been used for 30 days is suspended, and then deleted. "Used" means a sign-in, a question, an answer, or a push token call (definition to confirm with the relay stream). The length of the suspension is to confirm with the relay stream.

A suspended team answers `403 forbidden` to every call except a sign-in (rule to confirm with the relay stream). A device that signs in to a suspended team makes it live again. The job is in the relay's `OPERATIONS` file, section 20. A deleted team is gone, as with `DELETE /v1/sync`; the `connect_key` row stays (section 4).

## 7. The link payload

A device link is the text that the first Mac shows as a QR code and as a pasteable string. They are the same string. The iPhone has no URL scheme.

### 7.1 Grammar

```
link     = [ origin "/link#" ] code *( "&" param )
origin   = "https://" host [ ":" port ]
code     = "apassy_lnk_" team-id "_" 64HEXLC
team-id  = "t_" 10( a-z / 2-7 )
param    = key "=" value
```

Known parameters:

| Key | Value | Meaning |
| --- | --- | --- |
| `r` | `sync` or `connect` | What the join does. Missing means `sync`. |
| `n` | percent-encoded UTF-8 | The name of the Mac that made the link. |
| `e` | Unix seconds, decimal | When the link expires. |
| `p` | b64u, no padding | An `apassy://pair?…` link ([companion-v1](companion-v1.md)), for the "Pair on this network" fallback. |

### 7.2 Parse rules

1. Trim the text.
2. If it contains `/link#`, the part before it is the relay origin (parsed as in relay-sync-v1 section 3) and the part after it is the fragment. Else the text is the fragment and the relay address comes from the field above it, as today.
3. The code is the fragment up to the first `&`. It must match the `code` rule. Else the link is invalid (`forbidden`, as today).
4. The rest, if any, is split on `&` into `key=value`. A parameter without `=`, and a repeated key after its first use, are ignored. Unknown keys are ignored.
5. `r` missing means `sync`. An `r` with a value other than `sync` or `connect` makes the link invalid (rule to confirm with the relay stream).
6. `n` is percent-decoded as UTF-8, with control characters removed and a cut to 64 bytes. A bad escape drops `n` only.
7. `e` is a decimal number. A bad value drops `e` only. The relay, not the parser, decides whether a code has expired.
8. `p` is b64u with no padding. A value that does not decode, or does not start with `apassy://pair?`, drops `p` only.
9. A parameter never changes the code, the relay address, or the team. The relay address comes only from the part before `/link#`.
10. The parser never fails on parameters alone, except rule 5.

The Mac sets `r` from `PlanProvider::current()`: `connect` on Free, `sync` on a paid plan. `r=sync` runs `join_finish`. `r=connect` runs `join_attach`, then the iCloud card. A second Mac that pastes `r=connect` runs `join_questions_team`. The code is one-use and lives 10 minutes (relay-sync-v1 section 12). The fallback `p` is open on the Mac for 300 s while the relay link lives 600 s; the two windows are to align (open item of the build plan).

### 7.3 Test vectors

All values are made up. The hex part is `0123456789abcdef` four times. Each vector is the literal string and the fields it parses to.

**Vector 1: an old form (no parameters).**

```
https://apassy-relay.wyderka.cc/link#apassy_lnk_t_7k2m5q4x3c_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

| Field | Value |
| --- | --- |
| relay | `https://apassy-relay.wyderka.cc` |
| code | `apassy_lnk_t_7k2m5q4x3c_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |
| team | `t_7k2m5q4x3c` |
| `r` | `sync` (missing) |
| `n`, `e`, `p` | none |

**Vector 2: a new form with `r=connect`.**

```
https://apassy-relay.wyderka.cc/link#apassy_lnk_t_7k2m5q4x3c_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&r=connect&n=Mac%20mini&e=1790000600&p=YXBhc3N5Oi8vcGFpcj92PTEmaD0xOTIuMC4yLjEwJnA9NDg2MjAmYz1BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBJnM9QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQSZuPU1hYyUyMG1pbmkmZT0xNzkwMDAwMzAw
```

| Field | Value |
| --- | --- |
| relay | `https://apassy-relay.wyderka.cc` |
| code | `apassy_lnk_t_7k2m5q4x3c_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |
| team | `t_7k2m5q4x3c` |
| `r` | `connect` |
| `n` | `Mac mini` |
| `e` | `1790000600` |
| `p` | `apassy://pair?v=1&h=192.0.2.10&p=48620&c=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&s=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA&n=Mac%20mini&e=1790000300` |

**Vector 3: a bare code.** The relay address comes from the field above the paste box; here it is `https://apassy-relay.wyderka.cc`.

```
apassy_lnk_t_7k2m5q4x3c_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

| Field | Value |
| --- | --- |
| relay | `https://apassy-relay.wyderka.cc` (from the field) |
| code | the same string |
| team | `t_7k2m5q4x3c` |
| `r` | `sync` (missing) |
| `n`, `e`, `p` | none |

The vectors go to `tests/contracts.rs` and to the iPhone parser's tests.

## 8. What this does not protect

- The relay sees that a Connect team exists, its device count, and the sizes and times of its questions. It cannot read a question or an answer (relay-questions-v1 section 18).
- The per-key and per-IP limits make mass creation costly. They do not stop a determined person with many keys and many addresses until the daily cap (`connect_teams_per_day`) is reached; then everyone gets `503 busy` until the next day.
- A link with `r=connect` gives a join, not an approval. The new device still needs the safety words and an owner check on an existing device (ADR 0027 section 8).
- A link that the owner did not make. Anyone can make a Connect team, its link, and any `n`. A device that joins such a link joins the team of whoever made it, and that person confirms it on their own Mac with the same safety words. The words prove that the code reached this device, not whose Mac made it. So: a device that holds a vault refuses a link whose team is not the questions team that the vault names (`questions-team-v1`), before any relay call; `n` is shown only as "Code from “n”", never as the owner's Mac; and an iPhone can leave its team at any time ("Disconnect from Apassy Connect", no Face ID). A vault that names no team yet takes any link. A device in the wrong team gets no question of the owner's vault: the questions are sealed with the vault's question key (relay-questions-v1 section 5.1) and go to the vault's own team.
