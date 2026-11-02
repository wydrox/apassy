# APNs connectivity spike

A throwaway Worker that checks whether Cloudflare's network can reach APNs
(`api.sandbox.push.apple.com`). It sends one request without a provider token. A
reachable APNs answers `403` with `MissingProviderToken`. No key and no device token
are used, and nothing is deployed.

## Steps

1. Start it on Cloudflare's network:

   ```
   cd deploy/worker && npx wrangler dev --remote -c spike/wrangler.jsonc
   ```

   `--remote` runs the Worker on Cloudflare's network. A local `wrangler dev` does not
   test Cloudflare's outbound HTTP/2, which is what this check is about.

2. In another terminal:

   ```
   curl -s http://127.0.0.1:8787/
   ```

   Expect `"status":403` and `MissingProviderToken` in the answer (`"ok":true`).

3. Stop wrangler with Ctrl-C.

## A failure

An `error` answer (status 502), or any status other than 403 with `MissingProviderToken`,
means the Worker cannot talk to APNs directly. Use the fallback in docs/SPEC.md section
25.7.
