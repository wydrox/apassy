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
| Account directory (`relay.db`) | Account ids (every id that Connect ever made, kept so that an id is used once: a new account never meets the Stripe customer or other records of a deleted account of that id), person names, device names, platforms, device public keys, the signed device list of each account (each change signed by a device of the list), the hashes of link codes, the public recovery key of each account, the last-seen hour of each device, groups and roles, vault store ids and vault names, nodes (names, certificate pins, public names), tunnel grants, the public keys of the entitlement signing key | — | Private keys, link codes, recovery codes, tokens (memory only), passphrases, vault keys |
| Plain files at rest | In `APASSY_RELAY_MODE=connect` there is no master key: `relay.db` and the vault store files are plain SQLite. They hold the directory above and, in the stores, SQLCipher snapshots under the user's passphrase, signed heads, and receipts | — | Nothing in them opens a vault. Disk encryption of the host is the owner's choice; backups go through the encrypted pull of today |
| Vault stores (blind sync store) | One relay-sync-v1 team for each vault: the current and the previous snapshot | Ciphertext, sizes, times, which device pushed | Vault contents. The passphrase never reaches Connect |
| Account sign-in, the device list, and the safety words | Public keys, signed challenges, and the signed device list; a 15-minute account token in memory | Which device signs in, and when | It cannot add or remove a device for an Apassy client, or rename one: each change of the device list is an entry signed by a device of the list over the hash of the entry before (an `add` also over the new device's name), back to the account's first key, which each client pinned when it made or joined the account and which signed its own name, and each client pins the highest version it verified that holds its own key. A row that Connect adds, a key it swaps, or a removed device it lists again is not in the list: the client shows it as "Not verified" and never uses it as an account device (no store, no sync head, no later confirmation). A list older than the pinned one, or another history, verifies no device. A device that Connect only hides stays a device until a device of the list signs its removal. The joining device chooses its own name and signs it in its join request (one canonical form on both sides: trimmed, 1 to 64 bytes, no control character, never `-`); the confirming device shows, and signs into the list, only a name whose join signature verifies, and the joining device pins only a list whose `add` names it as it asked, so Connect can neither choose nor change the name of a device. A new device needs the confirmation of a verified device with six safety words and an owner check; the link code names the confirming device's key and the account's first key, and Connect never sees the code, so it can neither compute the words nor answer with other keys. Connect can refuse a sign-in, but a refusal never removes a device: the device forgets its key only when its owner confirms on it |
| The email | A copy of the Stripe customer's email, for the devices list and support | — | Connect sends no mail in stage 7. Account deletion deletes the copy |
| Stripe (payment processor) | The customer: email, billing address, payment method, tax id; subscriptions and invoices (kept for legal retention) | The checkout and portal sessions, and the account id in `client_reference_id` and metadata | A device key, a token, a vault id, a device name, a value. Connect never sees card data or the address |
| The webhook | Event ids for 30 days | Stripe events, checked with the endpoint secret | A forged or replayed event changes nothing: signature, 300 s tolerance, idempotency by event id |
| The tunnel (byte relay) | Nodes and grants; for each account and month the counts of dials and streams and the bytes (also apart for the ingress and for each other account that dials its nodes), 13 months | TLS records, sizes, times; the client address of a WebSocket in memory | A device's requests, tokens, values: its TLS ends on the node and is pinned to the node's own certificate, which no CA issues. It logs no stream content |
| The SNI ingress (ports 443 and 80 of the Connect host, DNS-only, not through Cloudflare) | — | The server name `<node>.node.apassy.wyderka.cc`, the client address in memory only (never logged), the TLS records, and the plain ACME HTTP-01 challenge requests on port 80 | Run as specified, the cloud agent's requests, its token, session keys, placeholders, values: TLS ends on the node with its own Let's Encrypt certificate, whose key never leaves the node. This holds only as long as nobody else gets a certificate for the node's public name (below) |
| Certificate Transparency logs | The node certificates | The public node names, for ever, once a node gets a certificate | Traffic |
| The Cloudflare Worker (edge) | — | The account and billing requests (public keys, names, signed messages, Stripe events) and the WebSocket upgrades; after an upgrade, the tunnel's TLS records | Values, vault contents |
| The entitlement token | The Mac keeps it in memory (24 hours) | Account id, plan, group, features, times; it is signed by Connect | It is not a credential for Connect. A service accepts it only for the account of the device that signed in to that service |
| Bouncer brain service, through Connect (ADR 0035; the row above) | Its own token after the device sign-in `apassy-bouncer sign-in v1`; the entitlement token | What the row above says; from Connect only `account`, the two entitlements, and `revoked` for a device (I-3), and `revoke` and `forget` events (I-4) | The account token: the Mac never sends it to the brain (I-2). Connect does not call the brain for a request |
| Fallback F1 (not chosen) | — | If the owner chose it, Cloudflare and Connect would end the cloud agent's TLS and see its requests (the bearer token, placeholders, session keys), never values | Not in effect. Choosing it changes this table and the Funnel parity of the ingress row |

**The public name of a node is Web PKI trust, as a Tailscale Funnel name.** A cloud agent checks the
node's public certificate as any HTTPS client checks a name. A CA issues a certificate for
`<node>.node.apassy.wyderka.cc` to whoever passes its challenge for that name. Whoever operates
Connect (it answers port 80 of those names and runs the zone's records), or whoever controls the DNS
of the zone or that port 80, can therefore obtain a certificate of their own for a node's public name,
end a cloud agent's TLS with it, and see that agent's requests, its token, session keys, and the
placeholders. It is the same trust that Tailscale Funnel needs for a Funnel name. Such a certificate is
visible in the Certificate Transparency logs. The device route is different: a device dials the node
through Connect with TLS pinned to the node's own certificate (the pin of the pairing), so neither
Connect nor a CA can stand in for the node there.

**What a `device` stream reaches.** A dial reaches the node's device routes (`Scope::Tailnet`, relay
SPEC 32.1 and 35.3), the same routes as the tailnet. Every device of the node's account, every device
of an account with a grant, and Connect itself (which can open any stream on a node's WebSocket) can
open one. TLS has no client authentication there, so each route's own token decides: without one only
the sign-in steps, a device link (a one-use link code and the owner's confirmation with the safety
words), and the health check answer. Through a stream of the tunnel the node refuses the routes of team
codes, invites, and joins (`404`), which no device needs through Connect.

The iPhone shows the plan only; it has no purchase, link, or price (connect-billing-v1 section 10).

**The account device key** (connect-account-v1 section 5) is a software P-256 key in the Keychain of
each Mac and iPhone (this device only, not synchronizable, behind Touch ID), not a Secure Enclave key yet.
On Linux it is a private file of the user (`connect/device-key` in the data directory, 0600, never a
symlink, outside every vault; ADR 0045, "The Apassy Connect key on Linux"): another program of the
same user can read it there and act at Connect as that computer without the app's owner checks, which
run in Apassy (for example confirm a device of its own, change the vault stores, or delete the
account), but it gains no vault content: the vault stores hold ciphertext under the passphrase. Apassy reads it into memory only to sign the eleven messages of sections 5 and 16, and drops it from memory
when the vault locks and at a sign-out. **One account session for the app** (plan s7 unit M5b): the
vault unlock opens it, and Settings › Connect, the sync of the vault stores, and the node's tunnel use
its one key and token; no part reads the key store on its own. It closes at a lock, at a quit, at another
vault session, and when the auto-lock rule locks the vault at a screen lock or sleep. One step opens
it without a vault: "Use a vault from another Mac › Apassy Connect" on the start screen, which the owner
starts, and only while no vault is unlocked. The key is read once for that step, to join the account or
list its vault stores: with Touch ID on the Mac; on Linux from the private file, with no prompt (ADR 0045:
the mode of the file protects it, not a check of Apassy, so another program of the same user can read it
whether or not this step runs). Every way out of the step (another source of that screen, the start
screen's home, a lock, a quit, or the first vault session, also of another vault than the one that the
step downloads) closes the session and drops what holds the key, also a download from a vault store
that is under way and a copy that waits for its passphrase; only a copy that its passphrase opens
already finishes opening. The one owner check of that step, taking the
copy that a removed device left on a vault store, is Touch ID, or system authentication on Linux, bound
to the session of the step: no unlocked vault holds a passphrase to check. A join of this device that
waits keeps public values on disk (`connect/pending-join.json`, mode 0600: ids, names, keys, the link
hash, the safety words; never the link code), so a restart can finish it after a late confirmation. On the Mac the Touch ID
unlock reads the key with the vault's unlock key under one Touch ID (both items have the same access
control); a passphrase unlock reads it with a Touch ID of its own. A Connect that cannot be reached never
blocks the unlock: the session needs only the account file and the key, and each part shows its own
"Connect unreachable". `apassy owner serve` opens no account session. A change of the Touch ID fingerprints deletes it: the device
is then no longer a device of its account, and the owner adds it again from another device or
recovers the account with the recovery code. The key and the vault rows that sign with it go only
when the owner confirms "Forget This Mac" (or iPhone, or Computer on Linux) on that device, after a revoke of it, a
deletion, or Connect's signed-in answer that the device was removed. A refused sign-in, a missing
answer, or a missing or unreadable account file removes nothing. Adding a device to a vault store
by hand and deleting a vault store need a fresh owner check on this Mac, as adding or revoking an
account device does; the sync through Apassy Connect adds the other verified devices of the same
account to a store that it turned on without one (each still needs the vault passphrase). Only a
verified device can be added to a store. A vault store has no device link: a device of the account
gets the copy from the store that lists it, with the passphrase of the copy. A store that holds
devices of another account opens only with a share of it that the device verified (below), else it
is refused before any request. That early refusal relies on Connect's `shared` mark; against a
Connect that hides the mark, the signer policy alone refuses: no head of a device of another account
that no verified share names is accepted, and nothing is merged. Sharing a vault, accepting a share, ending a share, and leaving a
shared vault each need a fresh owner check, and so does joining a vault that another account
shares; the owner's checks name the vault by its name on this computer, and Join names a vault that
no vault of this computer syncs as "a vault shared by" the person, with Connect's name of the store
beside it as a hint only (the other account chose it); each check names the person by the name that
their verified device list signed with the short fingerprint of their pinned root (Connect's name
for them shows beside it as a hint only), the step, and the exact entries that the step signs: the
device reads its own list just before it builds the check and signs exactly those entries or
nothing. A device of the owner ends a share by itself, without an owner check, only when the
member's verified list left that share, when Connect's group answer shows this account as an active
member and does not show the member (or names it as removed), or when Connect marks the share void
after a removal from the group, since an end gives no one access; an error or an unclear group
answer ends nothing. A re-pin after a reset has an owner check of its own that names the shares
that end.

**The device list** (connect-account-v1 section 7.5) is a signed list with a cryptographic root:
version 1 is the first device of the account (after a recovery, the recovering device), signed by
its own key over its name, and each later version is one change, an `add` or a `remove`, signed by
a device of the list over the hash of the entry before. An `add` signs the name of the new device,
so a name stays with the key that it was confirmed for, and a key that was in the list is never
added again. Each client keeps in its account file the root key, the version and the hash of the
newest list it verified, the devices of that list, and the keys it knew that left; it takes a list
only while the list holds its own key as a device. A confirmation and a revoke are entries that the
client signs itself after an owner check: the revoke names the key that the client's own verified
list holds for the row, with that list's name and a short fingerprint of the key, and a row whose
key is the client's own while its id is not (or the reverse) is refused. A new device pins only a
list that holds its own `add`, signed by the confirming device that the code named. A device that a
device confirmed before it left stays a device: its `add` precedes the `remove`. An entry that adds
something (a device, a peer, a share, a join, a store) comes only while every device, peer, share,
and join can still be ended before the list is full (1024 entries, adds up to version 822; a store
entry never needs an end), so a removal, the end of a share, and a recovery always remain possible.

The heads of a vault store are accepted from the devices of the verified list; from a device that
left, as the current head only for the versions of that store that the client had merged when it
learned of the removal (a key that the verified list removed, also one that left before the client joined), and below a head that a device of the list signed (that device had taken
it). A live device whose own last head is one of a device that left signs a head of its own over it
at its next sync, so a device that is behind takes the copy again; until then that device waits and
says so. When no live device will sign over that head (the device that left pushed last), the owner
ends the wait on the waiting device behind a fresh owner check that names that head, with the device that left named by its
signed name and the time of its head: take exactly that head once ("Use the Copy That … Left…",
only for a key that the verified list removed), or replace it with the device's own copy. A head or
a chain entry of a signer that the client does not know yet makes it read the device list again
before it calls the copy refused or damaged. A key that was never a device of the verified list signs nothing; the decision never comes from
Connect's answers (a group, a store marked shared, a device it lists). What a client cannot detect: a
newer list that Connect withholds (the client keeps the last list it verified, so a removal it has
not seen yet does not reach it); entries after its own `add` that Connect withholds at a join (the
new device starts from the list that holds its `add`); and the same for an account file restored
from a backup, which learns the removals from the list at its next view only while Connect serves
them. The cost of the rule below the head: a device from which a removal was withheld can still take
a push of the device that left, and its own later head carries that push into a head that the other
devices take. A recovery starts a new root; a device of the old root learns
it only by joining again with a link from the recovered device, never from Connect.

**A vault shared between accounts** (connect-account-v1 section 16). The account that made a vault
store is the only authority for who signs its heads, and which account that is can be checked: the
device that makes a store signs a `store` entry of it in its account's list, in the step that makes
the store (a store made before the entry gets it only from a device that syncs it with the account's
key and that Connect's store view names as its maker, and, when the list shared it already, only
after an owner check that names the shares that count again), and a share of a store counts only in
a list that holds its `store` entry; a list that
holds it never joins that store, so no device of that account takes it as another account's store,
also a device that does not sync it. What the owner says of other accounts are entries of its own
device list (`peer`, `share`, `join`, and their ends), in the chain of its device entries, so they
have one order with the device changes and a removed device signs none of them. A `join` names the
`share` that it answers: it counts only while that share is active, and a new share of the same
store is joined anew. No role in a group carries
trust; the group view, a store's `shared` flag, and a store's device rows are hints only. A `peer`
pins the root of another account once for each pair of accounts, after six words that both devices
compute from a share code that Connect never sees, both roots, and both devices' keys; the code
carries the fingerprint of the sharing account's root and device, so the answering device checks the
account that Connect names. A device of another account signs in a store only when the signed
`share` entries of the store's owner name its account, through a root that the client pinned (a
co-member's root comes from the owner's `peer` entry and counts only in that owner's stores; the
client keeps one pin for each pair of an account and the list that named it, so two owners that name
different roots for one person stay apart, and a re-pin keeps the old keys as keys that left). A
list of a peer from another root suspends that pin: its keys sign nothing new until the people
compare new words, which a recovery of either account needs. When the owner's list ends a share, or
a peer's list removes a device, those keys sign only what the client had merged and below an
accepted head; the ended members of a store come from the verified lists, so every device computes
the same, also one that reads a share and its end at once; Connect serves the lists of the accounts
that joined a store with a device (a share that was never answered gives no read), so a device that
was offline while a member wrote still reads that member's keys after the member left the group.
A share that ends on a device (an `unshare`, a newer share not joined yet, a void mark of Connect)
only ends there: the pins of the other accounts stay with their list pins, so a later share goes on
from them and never takes an older list again. A client takes a store as another
account's only through its own signed `join` of a share that the owner's verified list holds for a
store that the owner's list made, and never offers or joins a store that its own list made, shares,
or joins from another account, or that a vault of the same computer syncs as its own. A join reads
the lists of the store's co-members before its first download. Connect also refuses a device of
another account in a store without the owner's active share, the member's join of it, and one active
group (a second line), and a removal from the group voids at Connect the shares that name the
removed account and the shares that it made, until a newer share.

What a client cannot detect here: a suffix of a list that Connect withholds (a removal or an
`unshare`), or an old prefix that it gives to a new device or member, until Connect serves it the
newer list (no head carries a list; until then that client takes the heads of the ended keys, and
the other devices take them below its later head); a permanent partition, in which Connect keeps the
devices of a share apart; and the time between an admin's removal of a member at Connect, which
ends the member's sign-in to the store, and the next refresh of a device of the owner, which then
signs the `unshare` by itself, until which the member's earlier heads still count; and the old keys
of an account that reset, on a device that learns that account only after the reset when Connect
withholds that account's last list before the reset (Connect keeps it while a store names the
account, and a device takes it only from an earlier root that its naming list pinned, as keys that
left): their chain entries after that device's anchor are refused, and at a first download a copy
whose head a verified device signed is taken only after the owner's own choice, "Take This Copy
Without Its Earlier History…", which names that head, its device, and its time.

**The recovery code** is the seed of an Ed25519 key pair. Connect stores only the public key; a
recovery is a signature by that key over the new device key and the next recovery key, so the code
never leaves the device where it is typed. A new code of a live device (connect-account-v1 section 9.1)
is written first as a pending rotation of public values (the old and the new public key and the signed
statement), so a lost answer or a quit never leaves the owner with a code that stopped working
unannounced: the device shows the code only when Connect names its key, and keeps the mark of a code
that nobody saw until the owner closes its sheet. Each device pins the public key that it saw last, so
a new code of another device shows on every other device with the name of that device and its day.
A Connect that lies about the key can make a device say that the code changed, or that it did not;
it cannot learn or use a code.

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
