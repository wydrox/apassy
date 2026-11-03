# Trust model

Date: 2026-11-02. Updated 2026-11-03: cloud agents through Tailscale Funnel; Apassy Connect as planned for stage 7; the node over the tailnet and the push gateway (built on `release/0.5.17`, not released yet; contracts [node-pairing-v1](../contracts/node-pairing-v1.md) and [push-gateway-v1](../contracts/push-gateway-v1.md); security panel [N8](../reviews/node-tailnet-2026-11/n8-panel.md)). Decision:
[ADR 0037](../adr/0037-own-relay-open-source.md). This page says who can see what. Update it in the
same change as any code that changes an answer here.

## The rule

No Apassy-run server holds a key that opens a credential, a vault, a question, or an answer. A value
is opened only on a device of the user, or of the user's team. Every part that touches a value is
Apache-2.0 and builds from this repository.

## Parties

| Party | Holds | Sees | Cannot see |
| --- | --- | --- | --- |
| Your Mac | Your vaults, the broker, the bouncer, your relay server (the node), item keys of the teams it hosts | Everything of your vaults while they are unlocked; the values of runs it releases | — |
| Your Linux node (`apassy serve`) | The relay directory and team files, SQLCipher under the node master key (a systemd credential, an encrypted `master.key.cred`, or a 0600 `master.key`); the sealed key of the node certificate; with `apassy team host`, the item keys of its teams (`keys.json`) | Sealed envelopes, relay sync ciphertext, team metadata, push handles and their secrets; the values of team runs that it releases | Your vaults: it needs no vault and no unlock. Who can act as its user (or root) can be the node |
| Your iPhone | A vault opened from iCloud Drive or a node; its device and answer keys (Secure Enclave or Keychain) | Questions, feed, and access requests, after it opens them | Values in a question (a card never carries one) |
| A team host node | The team file and its item keys | The values of runs that it releases. In way B, the members' requests to the upstream API and the answers | Members' personal vaults |
| A team member's node | Its device key; in way A, a value for one run | Its own runs; in way A, the value (it can keep a copy) | In way B, the value |
| Tailscale control server (or Headscale) | Node keys and names | Which nodes exist and their addresses | Traffic |
| Tailscale DERP relays | — | WireGuard ciphertext, sizes, times | Traffic |
| Push gateway (Apassy project) | The APNs key and its own handle key | Push handles (inside its key: device tokens, device kinds), node IP addresses, device IP addresses when a handle is made, times, the ciphertext of a sealed summary | Which team or vault a push is for, any question data, the text of a summary. It has no storage binding and logs nothing; Cloudflare's rate-limit counters (60 s) are keyed by the SHA-256 of the handle or of the client address ([push-gateway-v1](../contracts/push-gateway-v1.md)) |
| Apple (APNs, iCloud) | Push delivery; iCloud copies if folder sync is on | Push metadata; SQLCipher ciphertext of iCloud copies | Vault contents |
| Apassy Connect (paid, optional) | Sealed envelopes and sync snapshots; at stage 7 the account directory, the vault stores, and the Stripe ids (section "Apassy Connect") | TLS records, ciphertext, sizes, times, device names and public keys, the account's email and plan, vault ids, node names, client addresses in memory only | Values, vault contents, questions, answers, except the opt-in bouncer brain service below, which sees the bouncer state |
| Bouncer brain service of Apassy Connect (paid, opt-in, ADR 0035) | The shared encoder; the owner's head sets while Apassy hosting is on; the examples of a training job for at most 24 h | The state of each bouncer request (user request, command, relative directory, purpose, variable names, owner rule), in memory for one request; the examples of a training job | Values, the vault, the vault path, absolute project paths. It cannot allow a run: the bouncer gate on the Mac decides |
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

## The node over the tailnet (plan S2–S3; built on `release/0.5.17`, not released yet)

A device reaches the Mac's node, or a Linux node, at the **node origin** `https://<Tailscale IPv4>:8444`
behind a pinned self-signed certificate ([node-pairing-v1](../contracts/node-pairing-v1.md)). The
questions, the feed, the access requests, and relay sync use their contracts unchanged at that origin.

| Part | Holds | Sees | Cannot see or do |
| --- | --- | --- | --- |
| The node origin and its pin | The pairing link holds both (QR or pasted text); each device stores them with its membership, never in synced data | — | A link with another pin gives other safety words (the pin is in the handoff transcript); a stored pin changes only by a new pairing. Tailscale identity is never authorization |
| The TLS front (tailnet addresses, port 8444) | The node certificate; its key sealed under the node master key (`node/front/key.sealed`) | TLS records of the devices; peer addresses; it ends TLS and forwards bytes to the relay's tailnet-scope listener on the loopback | It binds only the addresses that Tailscale names for this machine in `100.64.0.0/10` and `fd7a:115c:a1e0::/48`, never `0.0.0.0` or `::`; it closes peers outside those ranges before the handshake; it parses no HTTP. In the Serve fallback (no interface has the Tailscale address) it binds `127.0.0.1` and Tailscale Serve forwards the tailnet port in TCP mode. Then the front **cannot tell a local process from a tailnet peer**: any process on this machine, of any local user on a Linux host, can connect to it and reaches the relay as a peer would (it still needs a device key to sign in). Serve is asked for a PROXY protocol v1 line (`--proxy-protocol=1`); with it the front reads the tailnet peer and gives each peer at most 16 of the 64 connections and 60 new ones a minute. A local process can write such a line too, so it can choose which peer's share it uses. A Tailscale without the PROXY protocol gives no peer address, and all peers share one pool. At each start the front first turns off a forward to its earlier local port that a crash left, so no process that took that port gets the tailnet traffic ([N8-5](../reviews/node-tailnet-2026-11/n8-panel.md)). It runs only while a vault is unlocked (Mac) or the service runs (Linux) |
| The relay's tailnet-scope listener (loopback) | The node's team files (SQLCipher) | Device-signed requests: sealed envelopes, ciphertext, ids, push handles and their secrets. Also requests without a key from any tailnet peer that the Tailscale ACLs let reach the front (sign-in challenges, link, join, and team codes); the Mac's own clients, plain over the loopback (the local route, on its own listener); on the Linux node, the member and agent requests of the team routes. Every request comes from the front's loopback address; the front names the tailnet peer of each connection in process memory (no header), and the listener counts failed authentications per peer, so one peer with bad tokens cannot lock out another. A connection that the front did not make (a local process) is counted as the loopback. The Mac's own clients use a separate loopback listener with the same routes that the front never forwards to, so no tailnet peer can limit them ([N8-1](../reviews/node-tailnet-2026-11/n8-panel.md)) | Operator routes, `/v1/connect`, OAuth; on the Mac also the team and agent routes: 404. It trusts no header |
| A device with a pinned membership | Its device key, the pin, the alternatives | The node's answers | It never accepts another certificate for that origin and never falls back to system trust |
| `tailscaled` and the tailnet | WireGuard keys | Which devices talk to the node, sizes, times | Traffic: TLS runs end to end between the device and the node |
| Push gateway | The APNs key and its handle key | Handles, node addresses, times | Tokens are sealed under the gateway's key; the node never sees them. A node that held a handle can push the fixed notification within the limits until the handle expires (180 days). Making a handle needs no proof of the device: whoever knows a device's APNs token can make handles for it and push the fixed notification, but at most 10 handles a day and 30 pushes an hour per token, over all its handles and addresses ([N8-3](../reviews/node-tailnet-2026-11/n8-panel.md)) |

## Apassy Connect (ADR 0037 stage 7, planned)

The paid hosted service of stage 7 ([plan](../design/implementation-plan-s7-connect.md); contracts
[connect-account-v1](../contracts/connect-account-v1.md),
[connect-billing-v1](../contracts/connect-billing-v1.md),
[connect-tunnel-v1](../contracts/connect-tunnel-v1.md)). Not implemented yet: this section says what
the contracts allow, and it becomes true when units C1 to C5 ship. The security review Q1 updates it.

| Part | Holds | Sees | Cannot see or do |
| --- | --- | --- | --- |
| Account directory (`relay.db`) | Account ids, person names, device names, platforms, device public keys, the hashes of link and recovery codes, the last-seen hour of each device, groups and roles, vault store ids and vault names, nodes (names, certificate pins, public names), tunnel grants, the public keys of the entitlement signing key | — | Private keys, link codes, recovery codes, tokens (memory only), passphrases, vault keys |
| Plain files at rest | In `APASSY_RELAY_MODE=connect` there is no master key: `relay.db` and the vault store files are plain SQLite. They hold the directory above and, in the stores, SQLCipher snapshots under the user's passphrase, signed heads, and receipts | — | Nothing in them opens a vault. Disk encryption of the host is the owner's choice; backups go through the encrypted pull of today |
| Vault stores (blind sync store) | One relay-sync-v1 team for each vault: the current and the previous snapshot | Ciphertext, sizes, times, which device pushed | Vault contents. The passphrase never reaches Connect |
| Account sign-in and the safety words | Public keys and signed challenges; a 15-minute account token in memory | Which device signs in, and when | It cannot add a device: a new device needs the confirmation of a live device with six safety words and an owner check. Connect never sees the link code, so it cannot compute the words or make a key that matches them |
| The email | A copy of the Stripe customer's email, for the devices list and support | — | Connect sends no mail in stage 7. Account deletion deletes the copy |
| Stripe (payment processor) | The customer: email, billing address, payment method, tax id; subscriptions and invoices (kept for legal retention) | The checkout and portal sessions, and the account id in `client_reference_id` and metadata | A device key, a token, a vault id, a device name, a value. Connect never sees card data or the address |
| The webhook | Event ids for 30 days | Stripe events, checked with the endpoint secret | A forged or replayed event changes nothing: signature, 300 s tolerance, idempotency by event id |
| The tunnel (byte relay) | Nodes and grants; for each account and month the counts of dials and streams and the bytes | TLS records, sizes, times; the client address of a WebSocket in memory | Requests, tokens, values: TLS ends on the node, pinned for devices. It logs no stream content |
| The SNI ingress (ports 443 and 80 of the Connect host, DNS-only, not through Cloudflare) | — | The server name `<node>.node.apassy.wyderka.cc`, the client address in memory only (never logged), the TLS records, and the plain ACME HTTP-01 challenge requests on port 80 | The cloud agent's requests, its token, session keys, placeholders, values: TLS ends on the node with its own Let's Encrypt certificate, whose key never leaves the node |
| Certificate Transparency logs | The node certificates | The public node names, for ever, once a node gets a certificate | Traffic |
| The Cloudflare Worker (edge) | — | The account and billing requests (public keys, names, signed messages, Stripe events) and the WebSocket upgrades; after an upgrade, the tunnel's TLS records | Values, vault contents |
| The entitlement token | The Mac keeps it in memory (24 hours) | Account id, plan, group, features, times; it is signed by Connect | It is not a credential for Connect. A service accepts it only for the account of the device that signed in to that service |
| Bouncer brain service, through Connect (ADR 0035; the row above) | Its own token after the device sign-in `apassy-bouncer sign-in v1`; the entitlement token | What the row above says; from Connect only `account`, the two entitlements, and `revoked` for a device (I-3), and `revoke` and `forget` events (I-4) | The account token: the Mac never sends it to the brain (I-2). Connect does not call the brain for a request |
| Fallback F1 (not chosen) | — | If the owner chose it, Cloudflare and Connect would end the cloud agent's TLS and see its requests (the bearer token, placeholders, session keys), never values | Not in effect. Choosing it changes this table and the Funnel parity of the ingress row |

The iPhone shows the plan only; it has no purchase, link, or price (connect-billing-v1 section 10).

## The hosted relay today (until ADR 0037 stage 7)

| Function | State on 2026-11-02 | Sees |
| --- | --- | --- |
| Shared team vaults and way B | Off: the only team vault (`apassy-alpha`, the owner's alpha team) is suspended (D8) | Nothing new; its file stays encrypted for the stage 4 export |
| Relay sync | On | SQLCipher ciphertext and salt, sizes, times |
| Questions, feed, access requests | On | Sealed envelopes, ids, routing bit, expiry, sizes, times |
| Push | On, through the Cloudflare Worker | Device tokens, times |
| Edge | Cloudflare ends TLS | Request metadata and bodies of the above (all sealed or ciphertext) |
