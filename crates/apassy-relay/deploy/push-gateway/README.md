# apassy-push: the push gateway

A stateless Cloudflare Worker that holds the APNs key and nothing else
([push-gateway-v1](../../../../docs/contracts/push-gateway-v1.md)):

- `POST /v1/handles`: a device exchanges its APNs token for a handle (the token sealed
  under the gateway key with AES-256-GCM) and a secret.
- `POST /v1/push`: a node pushes to a handle with a proof (HMAC-SHA256 under the secret).
  The gateway checks the shape, the clock (±300 s), the limits, the handle, the proof,
  and the topic, in this order, and sends one APNs request with the fixed text.
- `GET /healthz`: `{"v":1,"ok":true}` with a `Date` header for the node's clock check.

It has no storage or log binding. The APNs sender is `../worker/src/apns.ts`, shared with
the relay's edge Worker.

Files: `src/handles.ts` (b64u, strict JSON, sealing, the proof), `src/gateway.ts` (the
routes), `src/index.ts` (the Worker's entry), `test/` (the contract's vectors and the
routes; `node --test 'test/*.test.ts'`, Node 22.18 or later).

Types: `../worker/node_modules/.bin/tsc -p tsconfig.json` after `npm ci` in `../worker`
(the gateway has no lockfile of its own and uses the Worker's pinned tools).

Deploy, secrets, rotation, and self-hosting: [docs/operations/push-gateway.md](../../../../docs/operations/push-gateway.md).
