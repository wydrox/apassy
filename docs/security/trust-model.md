# Trust model

Date: 2026-11-02. Updated 2026-11-03: way C without leases in runs (0.5.17), the accepted risk of a synced way C switch, the account device key, and the codeless relay copies; cloud agents through Tailscale Funnel; Apassy Connect as planned for stage 7; the node over the tailnet and the push gateway (built on `release/0.5.17`, not released yet; contracts [node-pairing-v1](../contracts/node-pairing-v1.md) and [push-gateway-v1](../contracts/push-gateway-v1.md); security panel [N8](../reviews/node-tailnet-2026-11/n8-panel.md)). Decision:
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
| Push gateway (Apassy project) | The APNs key and its own handle key | Push handles (inside its key: device tokens, device kinds), node IP addresses, device IP addresses when a handle is made, times, the ciphertext of a sealed summary | Which team or vault a push is for, any question data, the text of a summary. It logs nothing. Its only storage is its limit counters: Durable Objects that hold one window of counts (an hour, or a day for handle creations per token), keyed by the SHA-256 of the handle, the client address, or the APNs token, deleted when the window ends ([push-gateway-v1](../contracts/push-gateway-v1.md) section 13) |
| Apple (APNs, iCloud) | Push delivery; iCloud copies if folder sync is on | Push metadata; SQLCipher ciphertext of iCloud copies | Vault contents |
| Apassy Connect (paid, optional) | Sealed envelopes and sync snapshots; at stage 7 the account directory, the vault stores, and the Stripe ids (section "Apassy Connect") | TLS records, ciphertext, sizes, times, device names and public keys, the account's email and plan, vault ids, node names, client addresses in memory only | Values, vault contents, questions, answers, except the opt-in bouncer brain service below, which sees the bouncer state |
| Bouncer brain service of Apassy Connect (paid, opt-in, ADR 0035) | The shared encoder; the owner's head sets while Apassy hosting is on; the examples of a training job for at most 24 h | The state of each bouncer request (user request, command, relative directory, purpose, variable names, owner rule), in memory for one request; the examples of a training job | Values, the vault, the vault path, absolute project paths. A server someone else controls can make the bouncer run development and staging commands without asking the owner. It can never allow production, a hard check failure, secret output, or another host |
| The bouncer brain on your own server | The shared encoder and your trained heads | User request, purpose, and shell command with paths shortened and values masked; trained heads | The vault and values. Whoever controls this server can make the bouncer run development and staging commands without asking the owner. It can never allow production, a hard check failure, secret output, or another host |
| Apassy project | Release signing keys | Nothing at run time | Anything of a user |
| Upstream API (Stripe, OpenAI, …) | — | The requests made with its credential | Other credentials |

## Not covered

- A device administrator can read what that device opens: the vault while unlocked, and in way A the
  value of a run.
- A team host operator (or root on that host) can read the members' way B traffic. The enterprise
  track (a confidential VM, ADR 0037 section 11) is for teams whose members must not trust the host.
- Physical attacks on a confidential VM's memory are out of scope of SEV-SNP and TDX (TEE.fail,
  2025).
- Tailscale Funnel, when a user turns it on, exposes the node's agent endpoints and its connect
  endpoints (the MCP authorization flow) to the internet, behind agent tokens and the owner's Allow
  (next section).
- **Accepted: a synced copy can switch temporary credentials (way C).** A device that has the vault
  key (it opened the vault with the passphrase) can push a copy that turns way C of a source item on
  or off, or changes its settings (the role, the scopes, the token and revoke URLs), and this Mac
  merges it without an owner check here. That is the same power as replacing the long-lived secret
  of the item, which such a device already has. The owner checks `ChangeDelivery` and
  `ChangeShortLivedSettings` guard the changes made on this Mac. A merge conflict keeps way C on.

## Temporary credentials (way C) in 0.5.17

Runs make no lease yet (plan s6 unit F; `LEASES_IN_RUNS` is false). A pasted AWS pair or Google
service-account key becomes an item with a `short_lived` row that is off: runs get the long-lived
key itself, AWS as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, Google as the key JSON in
`GOOGLE_API_KEY` (never in `CLOUDSDK_AUTH_ACCESS_TOKEN`). A run of an item whose way C is on fails
with `lease_failed` before the owner is asked; no run path gives the long-lived key, a placeholder of
it, or an older lease instead. Turning way C off needs a fresh owner check on this Mac; making an
existing item a source needs the owner check of its exact settings.

## Cloud agents through Tailscale Funnel

A hosted cloud agent (first: Grok Bot) reaches the Mac's node at
`https://<Mac>.<tailnet>.ts.net:8443`: `POST /mcp`, `/p/`, and the endpoints of the MCP authorization
flow (OAuth 2.1: the metadata, `/oauth/register`, `/oauth/authorize`, `/oauth/wait/<id>`,
`/oauth/token`, `/oauth/revoke`) ([contract](../contracts/cloud-agents-v1.md)). Remote access is off by
default. The owner gives an agent only the MCP address; the agent connects by itself and the owner
allows it on the Mac (Touch ID) or the iPhone (Face ID) after comparing the code of the connect page.

| Part | Holds | Sees | Cannot see or do |
| --- | --- | --- | --- |
| Tailscale Funnel relays (ingress servers of Tailscale) | — | TLS records, the server name (SNI), client addresses, sizes, times. TLS ends on the Mac, not here | Requests, tokens, session keys, placeholders, values |
| `tailscaled` on your Mac | The Funnel certificate and its key | Each cloud request and answer in clear, on the Mac: the token, session keys, placeholders. It ends TLS and connects to the public listener from the loopback | Values: the proxy sends them upstream on its own TLS connection, and the answers come back with placeholders. The vault |
| Certificate Transparency logs | The Funnel certificate | The machine name and the tailnet name (`<Mac>.<tailnet>.ts.net`), for ever, once the route is on | Whether the route is on now, any traffic |
| The public listener (`127.0.0.1:<port>`) | Nothing of its own | The cloud requests from `tailscaled`, and any request of a program on the Mac: the loopback bind keeps other computers away, not the programs of the Mac (review 0.5.16) | It serves no other route: `/v1/...`, the host lane, `/healthz`, and everything else are 404. It trusts no header for identity or authority. Failed authentications on `/mcp` and `/p/` count for each source address that Funnel forwards (`X-Forwarded-For`): after 20 in 60 s, 429 for that address only; requests without an address share a limit of 600. The flow is in neither count: bad codes and refresh tokens count for their client only; clients that the owner never allowed fill no limit of the flow |
| The connect page (`/oauth/wait/<id>`) | Nothing | The client name that the agent registered (not verified), "your Mac" (never the computer name: anyone with the address reads the page), the match code, and the state of the request | It has no script, form, cookie, or button: nothing on it can allow a connection. Never an item, an agent list, or the owner's name. Strict CSP, no framing, no referrer, no cache |
| A connect request | The node: its id, the OAuth client, the PKCE challenge, the match code, 300 s | — | It allows nothing by itself. Only the owner's Allow (Touch ID on the Mac, Face ID on the iPhone) connects it, always to a new agent with no credential: a client id is public, so a connect never takes over an agent that exists. At most 3 open per node and 1 per client: a new request of the client ends its waiting one, so the browser shows the code of its own request. The owner allows only when the browser page shows the same code |
| The access and refresh tokens of the flow | The cloud agent's vendor; the node keeps only their hashes | The items that the owner chose for that agent (names, variables, hosts) and the agent's own runs | A value, another agent's items, the owner API. An access token lives 24 h; a refresh token 90 days, rotated at each use, and a reused one revokes the family. A disconnect revokes the agent, its family, and the open requests of its client at the next request |
| The fallback agent token (`apassy_tagt_…`, `apassy agent add-remote`) | The cloud agent's vendor holds it, in its MCP server setting | As the tokens of the flow | As the tokens of the flow. It lives 1 to 365 days (default 90); a disconnect counts at the next request |
| The cloud agent's vendor (xAI, …) | The token; for a ready run, the session key, placeholders, and base URLs, until the session ends (at most 600 s) | Its runs, and the API answers with the placeholders back in them | A value. The node puts a placeholder back where the API echoes the value |
| The node's store at rest (`<data dir>/node`, SQLCipher under a Keychain key) | Team and item metadata (names, variables, hosts, declarations), agent token hashes, run rows (masked command, purpose, user request), the audit | — | It never holds a value or an item key: the value stays in the vault and goes into a session only in memory |

Known limits of the connect flow. Each is a denial of service only: none gives a token, an agent, or a
credential.

- A leaked authorize URL (or the address of its waiting page) can burn the code. Its holder opens the
  same request; after the owner's Allow, the code goes to whichever browser loads the page first. Without
  the client's PKCE verifier it gives no token, but the client's own browser then gets no code, and a
  redemption with a wrong verifier uses the code up and revokes its family. The same URL with other
  parameters ends the client's waiting request, since a new request of a client replaces it. The client
  connects again; the owner allows only a request whose code its own browser shows.
- A stranger can hold the 3 open connect requests of the node until the owner denies them, or they end
  after 300 s.
- A stranger who sends 20 bad codes or refresh tokens with the public id of a client holds that client's
  token requests at 429 for the rest of each 60 s window. Its access token keeps working until it ends.
- A flood of registrations can drop a client that registered and was not allowed yet; it registers again.
- A program on this Mac (a coding agent too) can connect to the public listener on the loopback and run
  the whole flow as any client name ("Grok Bot"), so its card looks like a real one (review 0.5.16).
  The owner's prompts and the iPhone card name where the code goes back: "Returns to <host of the
  redirect URI>", or "Returns to a program on a computer (localhost)" for a loopback redirect, and the
  Mac adds "A program on this Mac can start this request." Allow only a request that you started, whose
  code your browser shows, and that returns to your agent's site. A program that registers an
  `https://` redirect of a site it controls is not told apart by this line. An Allow gives a new agent
  with no credential. Planned for 0.5.17: the listener accepts only connections of the Tailscale
  process (a peer-process check).
- A program on this Mac can forge `X-Forwarded-For` and so hold the shared failed-auth count, or a
  guessed source address, at 429. A stranger with thousands of addresses can fill the source table
  (4096) and then the shared count.

The owner decides every cloud run in this release, on the Mac or the iPhone, one question of an agent
at a time. A remote agent starts with no credential. A node has at most 20 agents that are not
revoked, also those of the flow without a live token. The node trusts the app process: code that runs
in it can release any run, but it can read the vault anyway. The embedded node serves no operator
socket (`admin.sock`): its directory belongs to the Mac user, as the coding agents do, so no local
program can suspend or delete the personal team or make team codes through it (review 0.5.16).

The catalog mirror (`src/node/catalog.rs`) reads the value of each item that it mirrors with
`Vault::reveal`, without an owner check, when the item is new to the mirror or its revision changed. It
does this in the app process, only to run the node's `check_value` (`hostkeys::check_value`: a value
that the proxy could not swap, such as an empty one, one over the size limit, one with a byte outside
printable ASCII or a `"` or `\`, or one of no placeholder shape, keeps the item out of the mirror). The
value is held in zeroizing memory (`NodeSecret`) for that check only: it is not stored in the node, not
sent anywhere, and not logged; the node stores the marker `VALUE_ON_HOST` instead (SPEC 30.6). The owner check guards
values that leave the vault: a release of a run, a reveal or copy in the app. This read leaves nothing
outside the process (review 0.5.16).

## The node over the tailnet (plan S2–S3; built on `release/0.5.17`, not released yet)

A device reaches the Mac's node, or a Linux node, at the **node origin** `https://<Tailscale IPv4>:8444`
behind a pinned self-signed certificate ([node-pairing-v1](../contracts/node-pairing-v1.md)). The
questions, the feed, the access requests, and relay sync use their contracts unchanged at that origin.

| Part | Holds | Sees | Cannot see or do |
| --- | --- | --- | --- |
| The node origin and its pin | The pairing link holds both (QR or pasted text); each device stores them with its membership, never in synced data | — | A link with another pin gives other safety words (the pin is in the handoff transcript); a stored pin changes only by a new pairing. Tailscale identity is never authorization |
| The TLS front (tailnet addresses, port 8444) | The node certificate; its key sealed under the node master key (`node/front/key.sealed`) | TLS records of the devices; peer addresses; it ends TLS and forwards bytes to the relay's tailnet-scope listener on the loopback | It binds only the addresses that Tailscale names for this machine in `100.64.0.0/10` and `fd7a:115c:a1e0::/48`, never `0.0.0.0` or `::`; it closes peers outside those ranges before the handshake; it parses no HTTP. In the Serve fallback (no interface has the Tailscale address) it binds `127.0.0.1` and Tailscale Serve forwards the tailnet port in TCP mode. Then the front **cannot tell a local process from a tailnet peer**: any process on this machine, of any local user on a Linux host, can connect to it and reaches the relay as a peer would (it still needs a device key to sign in). Serve is asked for a PROXY protocol v1 line (`--proxy-protocol=1`); with it the front reads the tailnet peer and gives each peer at most 16 of the 64 connections and 60 new ones a minute. A local process can write such a line too, so it can choose which peer's share it uses. A Tailscale without the PROXY protocol gives no peer address, and all peers share one pool. At each start the front first turns off a forward to its earlier local port that a crash left, so no process that took that port gets the tailnet traffic ([N8-5](../reviews/node-tailnet-2026-11/n8-panel.md)). It runs only while a vault is unlocked (Mac) or the service runs (Linux) |
| The relay's tailnet-scope listener (loopback) | The node's team files (SQLCipher) | Device-signed requests: sealed envelopes, ciphertext, ids, push handles and their secrets. Also requests without a key from any tailnet peer that the Tailscale ACLs let reach the front (sign-in challenges, link, join, and team codes); the Mac's own clients, plain over the loopback (the local route, on its own listener); on the Linux node, the member and agent requests of the team routes. Every request comes from the front's loopback address; the front names the tailnet peer of each connection in process memory (no header), and the listener counts failed authentications per peer (20 in 60 s), so one peer with bad tokens cannot lock out another. Without PROXY peer addresses, tailnet peers share a listener-wide limit of 200 failures in 60 s; one peer can still exhaust it, but needs ten times as many failures. Node status flags this mode; Devices and `apassy doctor` show "Tailscale Serve without peer addresses: update Tailscale". A connection that the front did not make (a local process) is counted as the loopback. The Mac's own clients use a separate loopback listener with the same routes that the front never forwards to, so no tailnet peer can limit them ([N8-1](../reviews/node-tailnet-2026-11/n8-panel.md)) | Operator routes, `/v1/connect`, OAuth; on the Mac also the team and agent routes: 404. It trusts no header |
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

**The account device key** (connect-account-v1 section 5) is a software P-256 key in the Keychain of
each device (this device only, not synchronizable, behind Touch ID), not a Secure Enclave key yet.
Apassy reads it into memory only to sign the seven messages of section 5, and drops it from memory
when the vault locks and at a sign-out. A change of the Touch ID fingerprints deletes it: the device
is then no longer a device of its account, and the owner adds it again from another device or
recovers the account with the recovery code. The vault rows that sign with it go only after the
device forgot the account (a revoke of it, a deletion, "Forget this device") or Connect answered
`401` to a fresh sign-in; a missing or unreadable account file removes nothing. Adding a device to a
vault store and deleting a vault store need a fresh owner check on this Mac, as adding or revoking
an account device does.

**Relay copies without a code (plan s7 S0).** The hosted relay gets the team name `Vault` and the
device name `Mac` (or `iPhone`) of a codeless relay copy, never the names that the owner gave them;
the vault keeps its own names. A Connect team pushes at most 30 snapshots and 512 MiB of them an
hour.

## The hosted relay today (until ADR 0037 stage 7)

| Function | State on 2026-11-02 | Sees |
| --- | --- | --- |
| Shared team vaults and way B | Off: the only team vault (`apassy-alpha`, the owner's alpha team) is suspended (D8) | Nothing new; its file stays encrypted for the stage 4 export |
| Relay sync | On | SQLCipher ciphertext and salt, sizes, times |
| Questions, feed, access requests | On | Sealed envelopes, ids, routing bit, expiry, sizes, times |
| Push | On, through the Cloudflare Worker | Device tokens, times |
| Edge | Cloudflare ends TLS | Request metadata and bodies of the above (all sealed or ciphertext) |
