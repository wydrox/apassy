# Push gateway (`apassy-push`)

Date: 2026-11-03. Contract: [push-gateway-v1](../contracts/push-gateway-v1.md). Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) §7 and D7. Source: `crates/apassy-relay/deploy/push-gateway/`.

The push gateway is a Cloudflare Worker that holds the APNs key and nothing else. A node (the relay inside the Mac app, or `apassy serve` on Linux) never holds the APNs key or a device token:

1. The iPhone (later the watch) gives its APNs token to the gateway once and gets a **handle** (the token sealed under the gateway key) and a **secret** (`POST /v1/handles`).
2. The device gives the handle and the secret to its node (`PUT /v1/push/handle`), never the token.
3. For each new question the node asks the gateway to push to the handle, with a proof made from the secret (`POST /v1/push`). The gateway opens the handle, checks the proof, and sends the fixed notification.

The gateway stores nothing but its limit counters: one Durable Object class, `LimitCounter` (binding `LIMITS`), holds one window of counts per limit and key, keyed by SHA-256, and deletes it when the window ends. It has no KV, D1, R2, Queue, or log binding, and `observability` is off. It cannot revoke a handle; a handle ends after 180 days, when APNs refuses its token, or when its key is retired (section "Rotate the gateway key").

The hosted relay (`apassy-relay.wyderka.cc`) does not use the gateway: it keeps the push of its edge Worker (relay `docs/OPERATIONS.md` section 19) until ADR 0037 stage 7.

## What is where

| Name | Kind | Value |
| --- | --- | --- |
| `GATEWAY_KEY` | Worker secret | 32 random bytes as b64u (43 characters): the AES-256-GCM key of the handles. Kept in Apassy as "push gateway key <id>" |
| `GATEWAY_KEY_ID` | var (`wrangler.jsonc`) | `1` to `255`: the key id written into each new handle |
| `GATEWAY_KEY_PREVIOUS`, `GATEWAY_KEY_PREVIOUS_ID` | Worker secret, var | Only during a rotation: the key before, so its handles open until they expire |
| `APNS_KEY` | Worker secret | The text of the Apple `.p8` key (team `7S3F9767BM`), the same key as the relay Worker's `APNS_KEY` |
| `APNS_KEY_ID`, `APNS_TEAM_ID` | vars | The Key ID of the `.p8` key; `7S3F9767BM` |
| `APNS_TOPIC` | var | `com.wydrox.apassy.companion` (device kind `iphone`) |
| `APNS_WATCH_TOPIC` | var | `com.wydrox.apassy.companion.watchkitapp` (device kind `watch`). Remove it to refuse watch handles (409 `kind_unavailable`) |
| `LIMITS` | Durable Object binding, class `LimitCounter` (SQLite, migration `v1-limits`) | The limit counters. See "Limits" |

The `.p8` key and the gateway key go only through Apassy into `wrangler secret put`: never typed, echoed, written to a file, or committed.

## Limits

The contract (section 13) gives hourly limits: 60 pushes per handle, 600 pushes per node address, 30 handle creations per address, and per APNs token 30 pushes an hour over all its handles and 10 handle creations a day (N8-3). A Workers Rate Limiting binding counts per 10 or 60 seconds only, so the gateway keeps these numbers with the Durable Object counter that section 13 allows (`src/limits.ts`): one object per limit and key, a fixed window from the first request. The keys are SHA-256 of the handle text, of `CF-Connecting-IP`, or of the token, so the counters hold no handle, address, or token; an alarm deletes a window when it ends. A request over a limit gets 429 `rate_limited` with `Retry-After` set to the rest of the window; the node drops that push (the next question pushes again). A refused request is not counted.

The gateway answers 503 `push_unavailable` when the `LIMITS` binding is missing or a counter fails, so a deploy without the counters fails closed. Each limited request costs one Durable Object request per limit (two for a handle, three for a push).

## Deploy (Apassy project, `push.apassy.wyderka.cc`)

These steps change the Cloudflare account (a new Worker and a custom domain in the zone `wyderka.cc`) and set secrets. They need the owner's approval; an agent prepares them and does not run them on its own.

Before the first deploy:

1. **The route.** `wrangler.jsonc` has `routes: [{ pattern: "push.apassy.wyderka.cc", custom_domain: true }]`. The first `wrangler deploy` creates the DNS record and the certificate of the custom domain in the zone `wyderka.cc`. No other DNS change is needed. Check that no record `push.apassy` exists yet (a custom domain refuses an existing record).
2. **The limit counters.** The first deploy with `durable_objects` and the migration `v1-limits` creates the class `LimitCounter` (SQLite storage, also on the Workers Free plan). An earlier deploy with the per-minute `ratelimits` bindings (`1101` to `1103`) loses them at this deploy; nothing else needs a change.
3. **The vars.** `APNS_KEY_ID` must be the Key ID of the `.p8` key (the same value as in `crates/apassy-relay/deploy/worker/wrangler.jsonc`). `GATEWAY_KEY_ID` is `1` for the first key.
4. **The gateway key.** Make it once and keep it in the vault, so a rotation can pass it on as `GATEWAY_KEY_PREVIOUS`. With `apassy_capture_credential`, name "push gateway key 1", command:

   ```sh
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
   ```

   The output is 43 characters. It goes into the vault; it is not shown.

Deploy, from `crates/apassy-relay/deploy/push-gateway/`, with the Cloudflare credentials of the relay Worker deploy:

5. Install the tools (the gateway has no lockfile; use the Worker's pinned versions): `npm ci --prefix ../worker --no-audit --no-fund` (through `~/.local/bin/heavy-check` on the Mac). Then `../worker/node_modules/.bin/wrangler` is the pinned wrangler.
6. Tests and types (CI runs the same): `node --test 'test/*.test.ts'` and `../worker/node_modules/.bin/tsc -p tsconfig.json`.
7. Deploy the code first, without secrets: `../worker/node_modules/.bin/wrangler deploy`. Until the secrets are set, `/v1/handles` and `/v1/push` answer 503 `push_unavailable`; `/healthz` answers.
8. The secrets, each with `apassy_run_with_secrets` (the value reaches only the standard input of wrangler):

   - item "push gateway key 1", env `GATEWAY_KEY`: `printf %s "$GATEWAY_KEY" | ../worker/node_modules/.bin/wrangler secret put GATEWAY_KEY`
   - the vault item of the `.p8` key (the one used for the relay Worker), env `APNS_KEY`: `printf %s "$APNS_KEY" | ../worker/node_modules/.bin/wrangler secret put APNS_KEY`

9. Check:

   ```sh
   curl -sS -D - https://push.apassy.wyderka.cc/healthz          # 200 {"v":1,"ok":true} and a Date header
   curl -sS -X POST https://push.apassy.wyderka.cc/v1/push -d '{}' # 400 invalid_request
   curl -sS https://push.apassy.wyderka.cc/v1/anything             # 404 not_found
   ```

   Then the end-to-end check: an iPhone of a node team turns notifications on (Settings → Notifications), the Mac asks a question with the iPhone app closed, and the fixed notification "A question is waiting" arrives. The node's audit shows `push_handle_set {device_id}` once and no `push_failed`.

10. `wrangler.jsonc` has no secret; nothing in git changes after the deploy.

## Rotate the gateway key

The handles of the old key keep working until they expire, so a rotation never stops pushes:

1. Make "push gateway key 2" as in step 4.
2. Set the old key as the previous one: with item "push gateway key 1", env `GATEWAY_KEY`: `printf %s "$GATEWAY_KEY" | wrangler secret put GATEWAY_KEY_PREVIOUS`; in `wrangler.jsonc` set `"GATEWAY_KEY_PREVIOUS_ID": "1"` and `"GATEWAY_KEY_ID": "2"`.
3. Set the new key: with item "push gateway key 2": `printf %s "$GATEWAY_KEY" | wrangler secret put GATEWAY_KEY`, then `wrangler deploy`.
4. New handles carry key id 2. Devices renew a handle when it expires within 30 days, so after 180 days no handle of key 1 is left: delete `GATEWAY_KEY_PREVIOUS` (`wrangler secret delete GATEWAY_KEY_PREVIOUS`) and remove `GATEWAY_KEY_PREVIOUS_ID`.

To retire a key at once (a leak), skip step 2: every handle of the old key answers 403 `handle_invalid`, the nodes mark them failed, and each device makes a new handle at its next launch with notifications on.

## Rollback

- `wrangler rollback` goes back to the previous version of the Worker. The handles stay valid as long as the gateway key is the same.
- To stop all pushes through the gateway: `wrangler secret delete APNS_KEY`. `/v1/push` then answers 503 and the nodes drop the pushes (no handle is marked failed). Questions still reach the devices by their long polls while the app is open.
- The relay's edge Worker and the hosted relay do not depend on the gateway.

## Self-hosting

A self-hoster runs the same source with their own app build:

- The bundle ids of their build go into `APNS_TOPIC` and `APNS_WATCH_TOPIC`; their `.p8` key (of the Apple team that signs the build) into `APNS_KEY`, its Key ID and team into `APNS_KEY_ID` and `APNS_TEAM_ID`. A handle request with another bundle id is 409 `wrong_bundle`: each build needs its own gateway.
- Change `name` and the route in `wrangler.jsonc`. The counters come with the Worker.
- Each node lists the gateways its devices may name (a node setting, default `["https://push.apassy.wyderka.cc"]`); add the own gateway's origin there. A device that names another gateway gets 409 `push_gateway_refused`.

## Who sees what

| Party | Sees | Does not see |
| --- | --- | --- |
| The gateway | Handles (and inside its own key: tokens, kinds, environments), node and device IP addresses, times, the summary's ciphertext | Which team or vault, any question data, the summary's text |
| The node | Handles and secrets of its devices | Tokens |
| Apple | Token, topic, time, the fixed payload (with a summary: 720 characters of ciphertext) | Question data |

A node that held a handle can push the fixed notification to that device until the handle expires, within the limits, also after the device left its team (contract section 17).
