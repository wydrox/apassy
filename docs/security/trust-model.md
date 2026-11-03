# Trust model

Date: 2026-11-02. Updated 2026-11-03: cloud agents through Tailscale Funnel; the node over the tailnet and the push gateway (planned, contracts [node-pairing-v1](../contracts/node-pairing-v1.md) and [push-gateway-v1](../contracts/push-gateway-v1.md)). Decision:
[ADR 0037](../adr/0037-own-relay-open-source.md). This page says who can see what. Update it in the
same change as any code that changes an answer here.

## The rule

No Apassy-run server holds a key that opens a credential, a vault, a question, or an answer. A value
is opened only on a device of the user, or of the user's team. Every part that touches a value is
Apache-2.0 and builds from this repository.

## Parties

| Party | Holds | Sees | Cannot see |
| --- | --- | --- | --- |
| Your Mac or Linux node | Your vaults, the broker, the bouncer, your relay server, item keys of the teams it hosts | Everything of your vaults while they are unlocked; the values of runs it releases | — |
| Your iPhone | A vault opened from iCloud Drive or a node; its device and answer keys (Secure Enclave or Keychain) | Questions, feed, and access requests, after it opens them | Values in a question (a card never carries one) |
| A team host node | The team file and its item keys | The values of runs that it releases. In way B, the members' requests to the upstream API and the answers | Members' personal vaults |
| A team member's node | Its device key; in way A, a value for one run | Its own runs; in way A, the value (it can keep a copy) | In way B, the value |
| Tailscale control server (or Headscale) | Node keys and names | Which nodes exist and their addresses | Traffic |
| Tailscale DERP relays | — | WireGuard ciphertext, sizes, times | Traffic |
| Push gateway (Apassy project) | The APNs key and its own handle key | Push handles (inside its key: device tokens, device kinds), node IP addresses, device IP addresses when a handle is made, times, the ciphertext of a sealed summary | Which team or vault a push is for, any question data, the text of a summary. It stores and logs nothing ([push-gateway-v1](../contracts/push-gateway-v1.md)) |
| Apple (APNs, iCloud) | Push delivery; iCloud copies if folder sync is on | Push metadata; SQLCipher ciphertext of iCloud copies | Vault contents |
| Apassy Connect (paid, optional) | Sealed envelopes and sync snapshots | TLS records, ciphertext, sizes, times | Values, vault contents, questions, answers |
| Apassy project | Release signing keys | Nothing at run time | Anything of a user |
| Upstream API (Stripe, OpenAI, …) | — | The requests made with its credential | Other credentials |

## Not covered

- A device administrator can read what that device opens: the vault while unlocked, and in way A the
  value of a run.
- A team host operator (or root on that host) can read the members' way B traffic. The enterprise
  track (a confidential VM, ADR 0037 section 11) is for teams whose members must not trust the host.
- Physical attacks on a confidential VM's memory are out of scope of SEV-SNP and TDX (TEE.fail,
  2025).
- Tailscale Funnel, when a user turns it on, exposes the node's agent endpoints to the internet,
  behind agent tokens (next section).

## Cloud agents through Tailscale Funnel

A hosted cloud agent (first: Grok Bot) reaches the Mac's node at
`https://<Mac>.<tailnet>.ts.net:8443`, only `POST /mcp` and `/p/`
([contract](../contracts/cloud-agents-v1.md)). The route is off by default.

| Part | Holds | Sees | Cannot see or do |
| --- | --- | --- | --- |
| Tailscale Funnel relays (ingress servers of Tailscale) | — | TLS records, the server name (SNI), client addresses, sizes, times. TLS ends on the Mac, not here | Requests, tokens, session keys, placeholders, values |
| `tailscaled` on your Mac | The Funnel certificate and its key | Each cloud request and answer in clear, on the Mac: the token, session keys, placeholders. It ends TLS and connects to the public listener from the loopback | Values: the proxy sends them upstream on its own TLS connection, and the answers come back with placeholders. The vault |
| Certificate Transparency logs | The Funnel certificate | The machine name and the tailnet name (`<Mac>.<tailnet>.ts.net`), for ever, once the route is on | Whether the route is on now, any traffic |
| The public listener (`127.0.0.1:<port>`) | Nothing of its own | The cloud requests from `tailscaled` | It serves no other route: `/v1/...`, the host lane, `/healthz`, and everything else are 404. It trusts no header. After 20 failed authentications in 60 s, 429 for the rest of the window |
| The cloud agent token (`apassy_tagt_…`) | The cloud agent's vendor holds it, in its MCP server setting | The items that the owner picked for that agent (names, variables, hosts) and the agent's own runs | A value, another agent's items, the owner API. It lives 30, 90, or 365 days; a revocation counts at the next request |
| The cloud agent's vendor (xAI, …) | The token; for a ready run, the session key, placeholders, and base URLs, until the session ends (at most 600 s) | Its runs, and the API answers with the placeholders back in them | A value. The node puts a placeholder back where the API echoes the value |
| The node's store at rest (`<data dir>/node`, SQLCipher under a Keychain key) | Team and item metadata (names, variables, hosts, declarations), agent token hashes, run rows (masked command, purpose, user request), the audit | — | It never holds a value or an item key: the value stays in the vault and goes into a session only in memory |

The owner decides every cloud run in this release, on the Mac or the iPhone. The node trusts the app
process: code that runs in it can release any run, but it can read the vault anyway.

## The node over the tailnet (planned: plan S2–S3)

A device reaches the Mac's node, or a Linux node, at the **node origin** `https://<Tailscale IPv4>:8444`
behind a pinned self-signed certificate ([node-pairing-v1](../contracts/node-pairing-v1.md)). The
questions, the feed, the access requests, and relay sync use their contracts unchanged at that origin.

| Part | Holds | Sees | Cannot see or do |
| --- | --- | --- | --- |
| The node origin and its pin | The pairing link holds both (QR or pasted text); each device stores them with its membership, never in synced data | — | A link with another pin gives other safety words (the pin is in the handoff transcript); a stored pin changes only by a new pairing. Tailscale identity is never authorization |
| The TLS front (tailnet addresses, port 8444) | The node certificate; its key sealed under the node master key (`node/front/key.sealed`) | TLS records of the devices; peer addresses; it ends TLS and forwards bytes to the relay's tailnet-scope listener on the loopback | It binds only `100.64.0.0/10` and `fd7a:115c:a1e0::/48`, never `0.0.0.0` or `::`; it refuses other peers before the handshake; it parses no HTTP. It runs only while a vault is unlocked (Mac) or the service runs (Linux) |
| The relay's tailnet-scope listener (loopback) | The node's team files (SQLCipher) | Device-signed requests: sealed envelopes, ciphertext, ids, push handles and their secrets | Operator routes, `/v1/connect`, OAuth; on the Mac also the team and agent routes: 404. It trusts no header |
| A device with a pinned membership | Its device key, the pin, the alternatives | The node's answers | It never accepts another certificate for that origin and never falls back to system trust |
| `tailscaled` and the tailnet | WireGuard keys | Which devices talk to the node, sizes, times | Traffic: TLS runs end to end between the device and the node |
| Push gateway | The APNs key and its handle key | Handles, node addresses, times | Tokens are sealed under the gateway's key; the node never sees them. A node that held a handle can push the fixed notification within the limits until the handle expires (180 days) |

## The hosted relay today (until ADR 0037 stage 7)

| Function | State on 2026-11-02 | Sees |
| --- | --- | --- |
| Shared team vaults and way B | Off: the only team vault (`apassy-alpha`, the owner's alpha team) is suspended (D8) | Nothing new; its file stays encrypted for the stage 4 export |
| Relay sync | On | SQLCipher ciphertext and salt, sizes, times |
| Questions, feed, access requests | On | Sealed envelopes, ids, routing bit, expiry, sizes, times |
| Push | On, through the Cloudflare Worker | Device tokens, times |
| Edge | Cloudflare ends TLS | Request metadata and bodies of the above (all sealed or ciphertext) |
