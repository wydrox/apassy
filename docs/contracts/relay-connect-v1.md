# Relay connect wire contract v1

Date: 2026-10-13.
Status: proposed, for [ADR 0027](../adr/0027-plans-and-connect.md) (Apassy Connect). The app side (`src/sync/relay_link.rs`, `src/sync/relay.rs`, `src/relay/membership.rs`, and the iPhone core `ios/ApassyCore`) and the relay side (`apassy-relay`, branch `feat/connect`, `docs/SPEC.md` section 26) implement it. A change to this document changes both sides, one pull request on each; a change to the link grammar or to a check bumps `v1`. The app implements the client itself and does not depend on the relay crate (FSL license).

This document adds to [relay-sync-v1](relay-sync-v1.md) and [relay-questions-v1](relay-questions-v1.md). It repeats nothing from them: the encodings (sync section 2), the envelope and the errors (sync section 4), the Worker and the transport (sync section 3), and the question key (questions section 5.1) are the same here.

The names here match the relay branch `feat/connect` (commits through 93ddc93, after the security review of 2026-10-13).

## 1. Purpose

A Connect team is a relay team that anyone can make without an operator code. It carries questions and answers (relay-questions-v1), not vault snapshots. Plan Free uses it. Plan Personal and Plan Team lift its limits (section 6) and add the purpose `sync` to the same team.

An operator team (`POST /v1/teams` with `apassy_tcd_<64 hex>`, relay-sync-v1 section 6) is unchanged. A relay that an operator runs turns `POST /v1/connect` off with `APASSY_RELAY_CONNECT_TEAMS_PER_DAY=0`.

## 2. `POST /v1/connect`

Edge endpoint, no `Authorization` header (the relay refuses a bearer here, as on the other edge endpoints). Only the Mac calls it. The Mac decides the plan; the iPhone never creates a team. App Attest is not part of v1.

Request:

```json
{"v":1,"team":"Personal","device_name":"MacBook Pro","public_key":"<b64u>","signature":"<b64u>"}
```

- `v`: the number `1`.
- `team`: the vault name, trimmed and cut to 64 bytes at a character boundary (as relay-sync-v1 section 6).
- `device_name`: this Mac's name, control characters removed, cut to 64 bytes.
- `public_key`: the new device key, P-256 X9.63 uncompressed, b64u (relay-sync-v1 section 2). It must be a point on the curve.
- `signature`: proof that the caller holds the key. ECDSA P-256 with SHA-256, DER, b64u, over the bytes `"apassy-relay connect v1" 0x00 origin 0x00 public_key`, where `origin` is the relay origin without a trailing slash and `public_key` is the exact b64u text of the field above.
- The body has exactly these five fields. No `code` and no `owner`. The member is the fixed name `owner`, as in a personal team.
- The relay refuses unknown fields (`400 invalid_request`).

Answer: the `TeamCreated` result of `POST /v1/teams` plus `kind`:

```json
{"team_id":"t_7k2m5q4x3c","member_id":1,"device_id":1,"kind":"connect"}
```

The device is the owner's and holds the key-holder flag, as in a personal team. The Mac then signs in (relay-sync-v1 section 5). The sign-in answer and `GET /v1/me` carry `team_kind` (`operator` or `connect`).

The relay stores the kind of a team as `team.kind` (`operator` or `connect`) in `relay.db`. It also stores `connect_key(key_hash, team_id)` (section 4).

### 2.1 Errors

The envelope and the codes are those of relay-sync-v1 section 4.

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, an unknown or missing field, `v` not `1`, a bad key encoding, a key that is not on the curve, a bad or missing signature, a body over 64 KiB. |
| 409 | `connect_key_used` | This public key already made a Connect team (section 4), even if that team is deleted. The app makes a new device key and calls again once. |
| 429 | `rate_limited` | The Worker's limit per address (`Retry-After: 60`), or the relay's limit per network prefix (`Retry-After`: the seconds until the next UTC day). Section 3. |
| 503 | `busy` | The daily cap or the cap on live Connect teams is reached (section 3). `Retry-After: 3600`. The app does not retry at once. |

A refused call makes no team and leaves no `connect_key` row.

## 3. Limits on creating

The Worker bindings fail open and count only over 10 or 60 seconds. So every limit that matters is also in the relay.

| Limit | Value | Where |
| --- | --- | --- |
| Calls per address | 1 per minute per IPv4 address or IPv6 /64 (`CONNECT_LIMITER`) | Worker: `429 rate_limited` |
| Calls per network prefix | 3 per minute per IPv4 /24 or IPv6 /48 | Worker: `429 rate_limited` |
| Calls per network prefix, per day | 5 per UTC day per /24 or /48, and never more than a tenth of the daily cap | relay: `429 rate_limited` |
| Connect teams per public key | 1, ever | relay: `409 connect_key_used` |
| Connect teams per day on the whole relay | `APASSY_RELAY_CONNECT_TEAMS_PER_DAY`, 50 by default; 0 turns Connect off | relay: `503 busy` |
| Live Connect teams on the whole relay | `APASSY_RELAY_CONNECT_TEAMS_MAX`, 100 by default | relay: `503 busy` |

The Worker passes the network prefix to the relay in `X-Apassy-Client-Prefix`, on `POST /v1/connect` only, and drops any copy that a client sends. The relay takes the prefix only with the Worker's proof of it, an HMAC under the edge secret in a second header; without the proof the request counts as the one shared prefix. The relay counts per prefix in memory only, keyed by an HMAC under a random salt that changes each UTC day. Nothing about an IP address is written to disk. A restart resets the counts. A request without the header counts as one shared prefix.

## 4. One team per public key

The relay keeps the SHA-256 of the public key in `connect_key(key_hash, team_id)`. The row stays after the team is deleted (its `team_id` becomes empty), so a key cannot make a second Connect team, and a deleted team cannot be made again with the same key. A Mac that lost its team makes a new device key and a new team.

## 5. The `connect` preset

A team of kind `connect` starts with these `TeamLimits`:

| Limit | Value |
| --- | --- |
| Members | 1 |
| Items | 0 |
| Agents | 0 |
| Devices per member | 10 (as relay-sync-v1 section 12) |
| `sync_bytes` | 0 |
| `question_bytes` | 2 MiB |

A Connect team answers differently from an operator team on these routes:

- `PUT /v1/sync/snapshot` and `POST /v1/sync/receipt`: `403 plan_required`. On a push it comes after the header checks (400) and the token check (401), before the size checks. Nothing is stored. Downloads of an old snapshot still work.
- `GET /v1/sync/head?wait=…` and `GET /v1/host/requests?wait=…` answer at once. The app must not loop on them.
- Invites, collections, policies, and grants: `403 team_limit`.
- Any route: `429 rate_limited` above 300 requests per minute per member.
- A team file that is full (its page cap, about `question_bytes` plus 8 MiB): `403 team_limit` on every write that needs room, including a sign-in when it writes its hourly row, until the operator raises the team's limits (owner decision, 2026-10-13). The relay never deletes audit rows. Refusals that someone outside the team can cause (a forged or expired token, a failed sign-in) are not written into the team's file, so they cannot fill it. Old questions are still deleted on time.
- `GET /v1/questions?wait=…` and `GET /v1/questions/{qid}/answers?wait=…` can answer early with nothing new: a Connect team holds at most 2 waiting question polls (list and answer polls together), and all Connect teams share a bound. After an early empty answer the app waits before it polls again (for example 5 s, doubling to 60 s, with jitter), and keeps one question poll per device.
- Its pushes share a budget: at most 2 queued push jobs per Connect team, and half the queue for all Connect teams together.

Questions, answers, device links, sign-in, and push tokens work as in a personal team.

`POST /v1/teams/entitlement` will lift the preset to the limits of a paid plan. It is not built yet. It will need a signed-in device of the team and an `apassy_ent_` token; the token carries no device claim and never adds a device or signs in.

## 6. Idle cleanup

The operator runs `apassy-relay admin connect-sweep`; nothing runs it on its own. It suspends a Connect team whose newest sign-in of any device (`last_seen_at`, set by a sign-in or a sync call) is 30 days old, and deletes it 30 days after the suspension. It skips a team whose limits a plan lifted, a team with snapshot heads, and a team that the operator suspended.

A suspended team answers `401` to every call, including a sign-in. A sign-in does not revive it; only `admin resume` does. The app reads a `401` as "maybe gone": it signs in once more, then asks the owner before it connects again with a new team (ADR 0027). A deleted team is gone, as with `DELETE /v1/sync`; the `connect_key` row stays (section 4).

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
5. `r` missing means `sync`. An `r` with a value other than `sync` or `connect` makes the link invalid ("needs a newer version of Apassy").
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
- The per-key and per-prefix limits make mass creation costly. A determined person with many keys and many networks can still use up the daily cap; then new Free connections get `503 busy` until the window moves. Teams that exist keep working.
- A Connect team that uses its file fully stops taking writes until the operator raises its cap; nothing of its audit is deleted.
- A link with `r=connect` gives a join, not an approval. The new device still needs the safety words and an owner check on an existing device (ADR 0027 section 8).
- A link that the owner did not make. Anyone can make a Connect team, its link, and any `n`. A device that joins such a link joins the team of whoever made it, and that person confirms it on their own Mac with the same safety words. The words prove that the code reached this device, not whose Mac made it. So: a device that holds a vault refuses a link whose team is not the questions team that the vault names (`questions-team-v1`), before any relay call; `n` is shown only as "Code from “n”", never as the owner's Mac; and an iPhone can leave its team at any time ("Disconnect from Apassy Connect", no Face ID). A vault that names no team yet takes any link. A device in the wrong team gets no question of the owner's vault: the questions are sealed with the vault's question key (relay-questions-v1 section 5.1) and go to the vault's own team.
